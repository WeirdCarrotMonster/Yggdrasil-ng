//! Tor Pluggable Transport (PT) subprocess management and SOCKS5 dialer.
//!
//! Implements PT spec v1: subprocess IPC via env vars + stdout line protocol.
//! Client side: PT exposes a SOCKS5 proxy; we dial peers through it with PT
//! args encoded in the SOCKS5 username field.  Server side: PT forwards
//! plaintext connections to a loopback ORPORT that Yggdrasil binds.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, ChildStdin, Command};
use tokio::time::timeout;
use tracing::{debug, info};

use crate::config::PluggableTransportConfig;

// ---------------------------------------------------------------------------
// Client-side PT process
// ---------------------------------------------------------------------------

pub(crate) struct PtClientProcess {
    pub child: Child,
    /// Held open for the life of the process. The PT was started with
    /// `TOR_PT_EXIT_ON_STDIN_CLOSE`, and tokio's `Child::wait()` drops
    /// `child.stdin` — so if we left stdin inside `child`, the very first
    /// `wait()` used to monitor the process would signal it to exit. Keeping
    /// the handle here means `wait()` has nothing to close; dropping it (see
    /// `shutdown_pt_client`) is what triggers a graceful shutdown.
    _stdin: Option<ChildStdin>,
    pub socks_addr: SocketAddr,
}

/// Spawn a PT client subprocess and wait for it to report its SOCKS5 proxy
/// address.  Returns `Err` on spawn failure, startup timeout (30 s), or if the
/// PT reports `CMETHOD-ERROR` / `VERSION-ERROR`.
pub(crate) async fn spawn_pt_client(cfg: &PluggableTransportConfig) -> Result<PtClientProcess, String> {
    let mut child = Command::new(&cfg.binary)
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_CLIENT_TRANSPORTS", &cfg.protocol)
        .env("TOR_PT_STATE_LOCATION", &cfg.workdir)
        // Ask the PT to exit when its stdin closes so a graceful shutdown (or an
        // abnormal exit that still runs destructors) doesn't orphan the child.
        .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("PT client '{}': spawn failed: {}", cfg.protocol, e))?;

    // Take stdin out of `child` so tokio's wait() can't close it (see
    // PtClientProcess::_stdin), and grab stderr for logging.
    let stdin = child.stdin.take();
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut lines = BufReader::new(stdout).lines();
    let protocol = cfg.protocol.clone();

    let socks_addr = timeout(Duration::from_secs(30), async {
        let mut found: Option<SocketAddr> = None;
        loop {
            let line = lines.next_line().await
                .map_err(|e| format!("PT client '{}': read error: {}", protocol, e))?
                .ok_or_else(|| format!("PT client '{}': stdout closed before CMETHODS DONE", protocol))?;
            debug!(pt = %protocol, line = %line, "pt client stdout");

            if line.starts_with("VERSION-ERROR") {
                return Err(format!("PT client '{}': {}", protocol, line));
            }
            if line.starts_with("CMETHOD-ERROR") {
                return Err(format!("PT client '{}': {}", protocol, line));
            }
            if line == "CMETHODS DONE" {
                break;
            }
            // CMETHOD <transport> socks5 <addr>:<port> [OPT-ARGS...]
            if let Some(rest) = line.strip_prefix("CMETHOD ") {
                let parts: Vec<&str> = rest.splitn(3, ' ').collect();
                if parts.len() == 3 && parts[0] == protocol && parts[1] == "socks5" {
                    // Take only the first token — optional ARGS may follow after a space
                    let addr_str = parts[2].split_ascii_whitespace().next().unwrap_or("");
                    found = addr_str.parse::<SocketAddr>().ok();
                }
            }
        }
        found.ok_or_else(|| format!("PT client '{}': no CMETHOD line seen before CMETHODS DONE", protocol))
    })
    .await
    .map_err(|_| format!("PT client '{}': timed out waiting for CMETHODS DONE", cfg.protocol))??;

    // Keep draining PT output for the life of the process: dropping the stdout
    // reader would SIGPIPE a PT that logs to stdout, and an undrained pipe would
    // eventually block the PT once its buffer fills.
    spawn_output_logger(lines, protocol.clone(), "stdout");
    spawn_output_logger(BufReader::new(stderr).lines(), protocol, "stderr");

    Ok(PtClientProcess { child, _stdin: stdin, socks_addr })
}

/// Gracefully shut down a PT client: close stdin, wait up to 5 s, then kill.
pub(crate) async fn shutdown_pt_client(mut proc: PtClientProcess) {
    drop(proc._stdin.take());
    if timeout(Duration::from_secs(5), proc.child.wait()).await.is_err() {
        let _ = proc.child.kill().await;
    }
}

/// Continuously read newline-delimited PT output and forward each line to the
/// tracing log at debug level.  Runs until the pipe closes (process exit).
fn spawn_output_logger<R>(mut lines: tokio::io::Lines<R>, protocol: String, stream: &'static str)
where
    R: AsyncBufRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => debug!(pt = %protocol, stream, line = %line, "pt output"),
                Ok(None) => break,
                Err(e) => {
                    debug!(pt = %protocol, stream, "pt output read error: {}", e);
                    break;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Server-side PT process
// ---------------------------------------------------------------------------

pub(crate) struct PtServerProcess {
    pub child: Child,
    /// Held open for the life of the process; see `PtClientProcess::_stdin`.
    /// tokio's `Child::wait()` (used to detect PT crashes) drops `child.stdin`,
    /// which under `TOR_PT_EXIT_ON_STDIN_CLOSE` would immediately kill the PT.
    _stdin: Option<ChildStdin>,
    /// The public-facing address that the PT binary actually bound.
    pub bound_addr: SocketAddr,
}

/// Spawn a PT server subprocess.
///
/// * `bind_addr`  — public address the PT should listen on (from the listen URL)
/// * `orport_addr` — loopback address where Yggdrasil accepts forwarded conns
/// * `server_options` — per-transport options from the listen URL's query
///   parameters (e.g. obfs4's `iat-mode`), passed via
///   `TOR_PT_SERVER_TRANSPORT_OPTIONS`
pub(crate) async fn spawn_pt_server(
    cfg: &PluggableTransportConfig,
    bind_addr: SocketAddr,
    orport_addr: SocketAddr,
    server_options: &[(String, String)],
) -> Result<PtServerProcess, String> {
    let bindaddr_env = format!("{}-{}", cfg.protocol, bind_addr);

    let mut command = Command::new(&cfg.binary);
    command
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_SERVER_TRANSPORTS", &cfg.protocol)
        .env("TOR_PT_SERVER_BINDADDR", &bindaddr_env)
        .env("TOR_PT_ORPORT", orport_addr.to_string())
        .env("TOR_PT_STATE_LOCATION", &cfg.workdir)
        // Exit when stdin closes so the public listener socket is released on
        // shutdown rather than being held by an orphaned child (which would
        // then block a restarted PT from re-binding the same address).
        .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if !server_options.is_empty() {
        command.env(
            "TOR_PT_SERVER_TRANSPORT_OPTIONS",
            encode_server_transport_options(&cfg.protocol, server_options),
        );
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("PT server '{}': spawn failed: {}", cfg.protocol, e))?;

    // Take stdin out of `child` so tokio's wait() can't close it (see
    // PtServerProcess::_stdin), and grab stderr for logging.
    let stdin = child.stdin.take();
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut lines = BufReader::new(stdout).lines();
    let protocol = cfg.protocol.clone();

    let (bound_addr, client_args) = timeout(Duration::from_secs(30), async {
        let mut found: Option<SocketAddr> = None;
        let mut client_args: Option<String> = None;
        loop {
            let line = lines.next_line().await
                .map_err(|e| format!("PT server '{}': read error: {}", protocol, e))?
                .ok_or_else(|| format!("PT server '{}': stdout closed before SMETHODS DONE", protocol))?;
            debug!(pt = %protocol, line = %line, "pt server stdout");

            if line.starts_with("VERSION-ERROR") {
                return Err(format!("PT server '{}': {}", protocol, line));
            }
            if line.starts_with("SMETHOD-ERROR") {
                return Err(format!("PT server '{}': {}", protocol, line));
            }
            if line == "SMETHODS DONE" {
                break;
            }
            // SMETHOD <transport> <addr>:<port> [OPT-ARGS...]
            // obfs4proxy appends "ARGS:cert=...,iat-mode=0" after the address;
            // take only the first whitespace-separated token as the address.
            if let Some(rest) = line.strip_prefix("SMETHOD ") {
                let parts: Vec<&str> = rest.splitn(2, ' ').collect();
                if parts.len() == 2 && parts[0] == protocol {
                    let mut tokens = parts[1].split_ascii_whitespace();
                    found = tokens.next().unwrap_or("").parse::<SocketAddr>().ok();
                    client_args = tokens
                        .find_map(|t| t.strip_prefix("ARGS:"))
                        .map(str::to_string);
                }
            }
        }
        found
            .map(|addr| (addr, client_args))
            .ok_or_else(|| format!("PT server '{}': no SMETHOD line seen before SMETHODS DONE", protocol))
    })
    .await
    .map_err(|_| format!("PT server '{}': timed out waiting for SMETHODS DONE", cfg.protocol))??;

    // The ARGS values are what clients must put in their peer URL query — for
    // obfs4 that includes the cert, which otherwise only exists in the state
    // dir. Surface them at info so a bridge operator doesn't have to go
    // digging (comma-separated k=v here maps to &-separated k=v in the URL).
    if let Some(args) = &client_args {
        info!("PT server '{}' client connection args: {}", protocol, args);
    }

    // Keep draining PT output for the life of the process (see spawn_pt_client).
    spawn_output_logger(lines, protocol.clone(), "stdout");
    spawn_output_logger(BufReader::new(stderr).lines(), protocol, "stderr");

    Ok(PtServerProcess { child, _stdin: stdin, bound_addr })
}

/// Gracefully shut down a PT server: close stdin, wait up to 5 s, then kill.
pub(crate) async fn shutdown_pt_server(mut proc: PtServerProcess) {
    drop(proc._stdin.take());
    if timeout(Duration::from_secs(5), proc.child.wait()).await.is_err() {
        let _ = proc.child.kill().await;
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 client with username/password sub-negotiation (RFC 1929)
// ---------------------------------------------------------------------------

/// Connect through a SOCKS5 proxy (PT client) to `target_host:target_port`,
/// passing `pt_args` encoded in the SOCKS5 username field.
///
/// Returns the `TcpStream` after CONNECT succeeds; the stream is ready to
/// carry the Yggdrasil link protocol.
pub(crate) async fn pt_socks5_connect(
    socks_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
    pt_args: &[(String, String)],
) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(socks_addr)
        .await
        .map_err(|e| format!("SOCKS5 connect to {}: {}", socks_addr, e))?;
    // Match the other dial paths: disable Nagle so the link protocol isn't
    // held back behind small writes.
    stream.set_nodelay(true).ok();

    // --- Greeting ---
    // Username/password (0x02) is how PT args are delivered (pt-spec §3.5).
    // With no args to deliver, also offer no-auth (0x00) — like Tor does —
    // for PT SOCKS servers that skip auth when they need no arguments.
    let encoded_args = encode_pt_args(pt_args);
    let greeting: &[u8] = if encoded_args.is_empty() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x02]
    };
    stream.write_all(greeting).await
        .map_err(|e| format!("SOCKS5 greeting write: {}", e))?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await
        .map_err(|e| format!("SOCKS5 greeting read: {}", e))?;
    if resp[0] != 0x05 {
        return Err(format!("SOCKS5: bad greeting version 0x{:02x}", resp[0]));
    }
    match resp[1] {
        // No-auth chosen (only offered when there are no args): skip sub-negotiation.
        0x00 if encoded_args.is_empty() => {}
        0x02 => {
            // --- Sub-negotiation (RFC 1929) ---
            // PT args ride in the username field; if they overflow 255 bytes the
            // remainder spills into the password field (pt-spec §3.5).
            let (username_bytes, password_bytes) = split_socks5_auth(&encoded_args)?;

            let mut subneg = Vec::with_capacity(3 + username_bytes.len() + password_bytes.len());
            subneg.push(0x01);
            subneg.push(username_bytes.len() as u8);
            subneg.extend_from_slice(&username_bytes);
            subneg.push(password_bytes.len() as u8);
            subneg.extend_from_slice(&password_bytes);
            stream.write_all(&subneg).await
                .map_err(|e| format!("SOCKS5 sub-neg write: {}", e))?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await
                .map_err(|e| format!("SOCKS5 sub-neg read: {}", e))?;
            if auth_resp[1] != 0x00 {
                return Err(format!("SOCKS5 sub-neg rejected (status 0x{:02x})", auth_resp[1]));
            }
        }
        m => return Err(format!("SOCKS5: server chose unsupported method 0x{:02x}", m)),
    }

    // --- CONNECT request ---
    let addr = encode_socks5_addr(target_host)?;
    let mut req = Vec::with_capacity(5 + addr.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    req.extend_from_slice(&addr);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xff) as u8);
    stream.write_all(&req).await
        .map_err(|e| format!("SOCKS5 CONNECT write: {}", e))?;

    // --- Response: drain variable-length bound address ---
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await
        .map_err(|e| format!("SOCKS5 response header: {}", e))?;
    if hdr[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT failed: reply 0x{:02x}", hdr[1]));
    }
    let addr_len: usize = match hdr[3] {
        0x01 => 4,          // IPv4
        0x04 => 16,         // IPv6
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await
                .map_err(|e| format!("SOCKS5 domain len: {}", e))?;
            l[0] as usize
        }
        t => return Err(format!("SOCKS5: unknown address type 0x{:02x}", t)),
    };
    let mut drain = vec![0u8; addr_len + 2]; // addr + 2-byte port
    stream.read_exact(&mut drain).await
        .map_err(|e| format!("SOCKS5 bound addr drain: {}", e))?;

    Ok(stream)
}

/// Encode a SOCKS5 destination address (ATYP + address bytes, RFC 1928 §4).
///
/// IP literals — including the bracketed IPv6 form that `Url::host_str()`
/// produces — use the native ATYP 0x01/0x04 encodings. Sending a literal as a
/// "domain name" instead breaks in practice: Go-based PTs (lyrebird, Snowflake)
/// feed the domain string through `net.JoinHostPort`, which double-brackets a
/// bracketed IPv6 address into an undialable `[[::1]]:port`, and Tor itself
/// never exercises the domain path for bridge IPs. Genuine hostnames keep
/// ATYP 0x03 so the PT resolves them inside the obfuscated channel.
fn encode_socks5_addr(host: &str) -> Result<Vec<u8>, String> {
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(v4) => {
                let mut out = Vec::with_capacity(5);
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
                out
            }
            std::net::IpAddr::V6(v6) => {
                let mut out = Vec::with_capacity(17);
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
                out
            }
        });
    }

    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(format!("target hostname too long: {}", host));
    }
    let mut out = Vec::with_capacity(2 + host_bytes.len());
    out.push(0x03);
    out.push(host_bytes.len() as u8);
    out.extend_from_slice(host_bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// PT args encoding
// ---------------------------------------------------------------------------

/// Encode PT connection args as `key=val;key=val` with backslash-escaping
/// of `\`, `;`, and `=` in both keys and values (pt-spec §3.5), suitable
/// for the SOCKS5 username field.
pub(crate) fn encode_pt_args(args: &[(String, String)]) -> String {
    fn escape_into(s: &str, out: &mut String) {
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str(r"\\"),
                ';'  => out.push_str(r"\;"),
                '='  => out.push_str(r"\="),
                c    => out.push(c),
            }
        }
    }

    let mut out = String::new();
    for (i, (k, v)) in args.iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        escape_into(k, &mut out);
        out.push('=');
        escape_into(v, &mut out);
    }
    out
}

/// Encode server-side transport options for `TOR_PT_SERVER_TRANSPORT_OPTIONS`
/// (pt-spec §3.2.3): a semicolon-separated list of `<transport>:<key>=<value>`
/// entries, with `\`, `:`, and `;` backslash-escaped.
pub(crate) fn encode_server_transport_options(
    protocol: &str,
    options: &[(String, String)],
) -> String {
    fn escape_into(s: &str, out: &mut String) {
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str(r"\\"),
                ':'  => out.push_str(r"\:"),
                ';'  => out.push_str(r"\;"),
                c    => out.push(c),
            }
        }
    }

    let mut out = String::new();
    for (i, (k, v)) in options.iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        escape_into(protocol, &mut out);
        out.push(':');
        escape_into(k, &mut out);
        out.push('=');
        escape_into(v, &mut out);
    }
    out
}

/// Split an encoded PT arg string into SOCKS5 username/password fields
/// (RFC 1929, as used by pt-spec §3.5).
///
/// * empty          → a single NUL username, NUL password (RFC 1929 forbids
///                    zero-length fields, and PTs expect a NUL placeholder)
/// * `len <= 255`   → all in username, NUL password
/// * `len <= 510`   → first 255 bytes username, remainder password
/// * `len > 510`    → error (cannot be represented in two 255-byte fields)
fn split_socks5_auth(encoded: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let bytes = encoded.as_bytes();
    match bytes.len() {
        0 => Ok((vec![0x00], vec![0x00])),
        1..=255 => Ok((bytes.to_vec(), vec![0x00])),
        256..=510 => Ok((bytes[..255].to_vec(), bytes[255..].to_vec())),
        n => Err(format!("PT args too long to encode in SOCKS5 auth: {} bytes (max 510)", n)),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_pt_args_basic() {
        let args = vec![
            ("cert".to_string(), "ABC123".to_string()),
            ("iat-mode".to_string(), "0".to_string()),
        ];
        assert_eq!(encode_pt_args(&args), "cert=ABC123;iat-mode=0");
    }

    #[test]
    fn encode_pt_args_escaping() {
        let args = vec![
            ("a".to_string(), r"semi;equal=back\slash".to_string()),
        ];
        assert_eq!(encode_pt_args(&args), r"a=semi\;equal\=back\\slash");
    }

    #[test]
    fn encode_pt_args_escapes_keys_too() {
        // pt-spec §3.5 requires escaping in keys as well as values; an
        // unescaped key would corrupt the whole arg string.
        let args = vec![
            (r"we;ird=k\ey".to_string(), "val".to_string()),
        ];
        assert_eq!(encode_pt_args(&args), r"we\;ird\=k\\ey=val");
    }

    #[test]
    fn encode_pt_args_empty() {
        assert_eq!(encode_pt_args(&[]), "");
    }

    #[test]
    fn encode_pt_args_single() {
        let args = vec![("key".to_string(), "val".to_string())];
        assert_eq!(encode_pt_args(&args), "key=val");
    }

    #[test]
    fn encode_server_transport_options_basic() {
        let opts = vec![
            ("iat-mode".to_string(), "1".to_string()),
            ("drain".to_string(), "yes".to_string()),
        ];
        assert_eq!(
            encode_server_transport_options("obfs4", &opts),
            "obfs4:iat-mode=1;obfs4:drain=yes"
        );
    }

    #[test]
    fn encode_server_transport_options_escaping() {
        let opts = vec![
            (r"k:ey".to_string(), r"semi;colon:back\slash".to_string()),
        ];
        assert_eq!(
            encode_server_transport_options("obfs4", &opts),
            r"obfs4:k\:ey=semi\;colon\:back\\slash"
        );
    }

    #[test]
    fn encode_server_transport_options_empty() {
        assert_eq!(encode_server_transport_options("obfs4", &[]), "");
    }

    #[test]
    fn split_socks5_auth_empty() {
        // RFC 1929 forbids zero-length fields; empty args become NUL placeholders.
        assert_eq!(split_socks5_auth("").unwrap(), (vec![0x00], vec![0x00]));
    }

    #[test]
    fn split_socks5_auth_short() {
        let (u, p) = split_socks5_auth("cert=abc").unwrap();
        assert_eq!(u, b"cert=abc");
        assert_eq!(p, vec![0x00]);
    }

    #[test]
    fn split_socks5_auth_boundary_255() {
        let s = "a".repeat(255);
        let (u, p) = split_socks5_auth(&s).unwrap();
        assert_eq!(u.len(), 255);
        assert_eq!(p, vec![0x00]);
    }

    #[test]
    fn split_socks5_auth_spills_to_password() {
        let s = "b".repeat(300);
        let (u, p) = split_socks5_auth(&s).unwrap();
        assert_eq!(u.len(), 255);
        assert_eq!(p.len(), 45);
        assert_eq!(u.len() + p.len(), 300);
    }

    #[test]
    fn split_socks5_auth_boundary_510() {
        let s = "c".repeat(510);
        let (u, p) = split_socks5_auth(&s).unwrap();
        assert_eq!(u.len(), 255);
        assert_eq!(p.len(), 255);
    }

    #[test]
    fn split_socks5_auth_too_long() {
        let s = "d".repeat(511);
        assert!(split_socks5_auth(&s).is_err());
    }

    #[test]
    fn encode_socks5_addr_ipv4_literal() {
        assert_eq!(
            encode_socks5_addr("192.0.2.1").unwrap(),
            vec![0x01, 192, 0, 2, 1]
        );
    }

    #[test]
    fn encode_socks5_addr_ipv6_bracketed() {
        // Url::host_str() keeps the brackets; they must not leak into the
        // encoded address.
        let mut expected = vec![0x04];
        expected.extend_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(encode_socks5_addr("[2001:db8::1]").unwrap(), expected);
    }

    #[test]
    fn encode_socks5_addr_ipv6_bare() {
        let mut expected = vec![0x04];
        expected.extend_from_slice(&"::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(encode_socks5_addr("::1").unwrap(), expected);
    }

    #[test]
    fn encode_socks5_addr_hostname() {
        let host = "bridge.example.com";
        let mut expected = vec![0x03, host.len() as u8];
        expected.extend_from_slice(host.as_bytes());
        assert_eq!(encode_socks5_addr(host).unwrap(), expected);
    }

    #[test]
    fn encode_socks5_addr_hostname_too_long() {
        let host = "a".repeat(256);
        assert!(encode_socks5_addr(&host).is_err());
    }

    /// Simulate parsing a well-formed CMETHOD + CMETHODS DONE sequence.
    #[test]
    fn parse_cmethod_line() {
        let line = "CMETHOD obfs4 socks5 127.0.0.1:54321";
        let rest = line.strip_prefix("CMETHOD ").unwrap();
        let parts: Vec<&str> = rest.splitn(3, ' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "obfs4");
        assert_eq!(parts[1], "socks5");
        let addr: SocketAddr = parts[2].parse().unwrap();
        assert_eq!(addr.port(), 54321);
    }

    /// spawn_pt_client with a nonexistent binary must return Err quickly.
    #[tokio::test]
    async fn spawn_nonexistent_binary_errors() {
        let cfg = PluggableTransportConfig {
            protocol: "obfs4".to_string(),
            binary: "/nonexistent/binary/path".to_string(),
            workdir: "/tmp".to_string(),
        };
        let result = spawn_pt_client(&cfg).await;
        assert!(result.is_err(), "expected Err for missing binary");
    }
}
