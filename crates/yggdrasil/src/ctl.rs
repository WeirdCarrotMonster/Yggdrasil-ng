use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Send one request to the admin socket and return the full response
/// envelope, whatever its status. Exits on an empty response.
async fn admin_call(
    endpoint: &str,
    command: &str,
    arguments: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let request = serde_json::json!({
        "request": command,
        "arguments": arguments,
        "keepalive": false,
    });

    let addr = endpoint.strip_prefix("tcp://").unwrap_or(endpoint);

    let stream = TcpStream::connect(addr).await.map_err(|e| {
        format!("Failed to connect to admin socket at {}: {}", endpoint, e)
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Send request
    let req_json = serde_json::to_string(&request)?;
    writer.write_all(req_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    // Read response
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    if line.trim().is_empty() {
        eprintln!("Empty response from admin socket");
        std::process::exit(1);
    }

    Ok(serde_json::from_str(line.trim())?)
}

/// The `response` member of a successful envelope. On any other status,
/// prints the error and exits 1.
fn success_response(resp: &serde_json::Value) -> &serde_json::Value {
    let status = resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if status != "success" {
        let error = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }

    &resp["response"]
}

/// Run a control command against the admin socket.
pub async fn run_ctl(
    endpoint: &str,
    json_output: bool,
    command: &str,
    arguments: serde_json::Map<String, serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = admin_call(endpoint, command, arguments).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    let response = success_response(&resp);

    // Pretty-print based on command
    match command.to_lowercase().as_str() {
        "list" => {
            if let Some(list) = response.get("list").and_then(|v| v.as_array()) {
                println!("Available commands:");
                for cmd in list {
                    if let Some(s) = cmd.as_str() {
                        println!("  {}", s);
                    }
                }
            }
        }

        "getself" => {
            print_kv(response, &[
                ("Build name", "build_name"),
                ("Build version", "build_version"),
                ("Public key", "key"),
                ("IPv6 address", "address"),
                ("IPv6 subnet", "subnet"),
                ("Coordinates", "coordinates"),
                ("Routing entries", "routing_entries"),
            ]);
        }

        "getpeers" => {
            if let Some(peers) = response.get("peers").and_then(|v| v.as_array()) {
                if peers.is_empty() {
                    println!("No peers connected.");
                } else {
                    let header = vec![
                        "URI", "State", "Dir", "IP Address", "Latency", "Cost",
                        "Uptime", "RX", "TX", "RX Rate", "TX Rate", "Pr", "Last Error",
                    ];
                    let rows: Vec<Vec<String>> = peers.iter().map(|peer| {
                        let uri = json_str(peer, "uri");
                        let up = peer.get("up").and_then(|v| v.as_bool()).unwrap_or(false);
                        let state = if up { "Up" } else { "Down" }.into();
                        let inbound = peer.get("inbound").and_then(|v| v.as_bool()).unwrap_or(false);
                        let dir: String = if inbound { "In" } else { "Out" }.into();
                        let address = json_str(peer, "address");
                        let latency = peer.get("latency")
                            .and_then(|v| v.as_f64())
                            .map(|ms| if ms > 0.0 { format!("{:.1}ms", ms) } else { "-".into() })
                            .unwrap_or_else(|| "-".into());
                        let cost = peer.get("cost")
                            .and_then(|v| v.as_u64())
                            .map(|c| if c > 0 { c.to_string() } else { "-".into() })
                            .unwrap_or_else(|| "-".into());
                        let uptime = peer.get("uptime")
                            .and_then(|v| v.as_f64())
                            .map(format_uptime)
                            .unwrap_or_else(|| "-".into());
                        let rx_bytes = peer.get("bytes_recvd")
                            .and_then(|v| v.as_u64())
                            .map(format_bytes)
                            .unwrap_or_else(|| "-".into());
                        let tx_bytes = peer.get("bytes_sent")
                            .and_then(|v| v.as_u64())
                            .map(format_bytes)
                            .unwrap_or_else(|| "-".into());
                        let rx_rate = peer.get("rx_rate")
                            .and_then(|v| v.as_u64())
                            .map(|r| if r > 0 { format!("{}/s", format_bytes(r)) } else { "-".into() })
                            .unwrap_or_else(|| "-".into());
                        let tx_rate = peer.get("tx_rate")
                            .and_then(|v| v.as_u64())
                            .map(|r| if r > 0 { format!("{}/s", format_bytes(r)) } else { "-".into() })
                            .unwrap_or_else(|| "-".into());
                        let priority = peer.get("priority")
                            .and_then(|v| v.as_u64())
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".into());
                        let last_error = json_str(peer, "last_error");
                        let last_error = if last_error.is_empty() { "-".into() } else { last_error };
                        vec![uri, state, dir, address, latency, cost, uptime,
                             rx_bytes, tx_bytes, rx_rate, tx_rate, priority, last_error]
                    }).collect();
                    // URI is the flexible column: it gets truncated to fit the terminal
                    print_table_flex(&header, &rows, 0);
                }
            }
        }

        "gettree" => {
            if let Some(tree) = response.get("tree").and_then(|v| v.as_array()) {
                if tree.is_empty() {
                    println!("No tree entries.");
                } else {
                    let header = vec!["Public Key", "IP Address", "Parent", "Sequence"];
                    let rows: Vec<Vec<String>> = tree.iter().map(|entry| {
                        vec![
                            json_str(entry, "key"),
                            json_str(entry, "address"),
                            json_str(entry, "parent"),
                            json_u64(entry, "sequence"),
                        ]
                    }).collect();
                    print_table(&header, &rows);
                }
            }
        }

        "getpaths" => {
            if let Some(paths) = response.get("paths").and_then(|v| v.as_array()) {
                if paths.is_empty() {
                    println!("No cached paths.");
                } else {
                    let header = vec!["Public Key", "IP Address", "Path", "Sequence"];
                    let rows: Vec<Vec<String>> = paths.iter().map(|entry| {
                        let path = entry.get("path")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_u64())
                                    .map(|n| n.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            })
                            .unwrap_or_else(|| "-".into());
                        vec![
                            json_str(entry, "key"),
                            json_str(entry, "address"),
                            path,
                            json_u64(entry, "sequence"),
                        ]
                    }).collect();
                    print_table(&header, &rows);
                }
            }
        }

        "getsessions" => {
            if let Some(sessions) = response.get("sessions").and_then(|v| v.as_array()) {
                if sessions.is_empty() {
                    println!("No active sessions.");
                } else {
                    let header = vec!["Public Key", "IP Address", "Uptime", "RX", "TX"];
                    print_table(&header, &session_rows(sessions));
                }
            }
        }

        "gettun" => {
            print_kv(response, &[
                ("TUN enabled", "enabled"),
                ("Interface name", "name"),
                ("Interface MTU", "mtu"),
            ]);
        }

        "getdebug" => {
            print_kv(response, &[
                ("Tree nodes known",      "tree_node_count"),
                ("Routing peers",         "routing_peer_count"),
                ("Tree root key",         "tree_root"),
                ("Our coordinates",       "our_coords"),
                ("Path cache total",      "path_cache_count"),
                ("Broken paths",          "broken_path_count"),
                ("Pending lookups",       "pending_lookup_count"),
                ("Pending sig requests",  "pending_sig_requests"),
                ("RX queue bytes",        "delivery_queue_bytes"),
            ]);

            if let Some(down) = response.get("peers_down").and_then(|v| v.as_array()) {
                if !down.is_empty() {
                    println!("\n  Down peers:");
                    for p in down {
                        let uri = json_str(p, "uri");
                        let err = json_str(p, "last_error");
                        println!("    {} ({})", uri, err);
                    }
                }
            }

            if let Some(lats) = response.get("peer_latencies").and_then(|v| v.as_array()) {
                if !lats.is_empty() {
                    println!("\n  Peer latencies:");
                    let header = vec!["Key", "IP Address", "Latency"];
                    let rows: Vec<Vec<String>> = lats.iter().map(|p| {
                        let ms = p.get("latency_ms").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let lat = if ms > 0.0 { format!("{:.1} ms", ms) } else { "n/a".into() };
                        vec![json_str(p, "key"), json_str(p, "address"), lat]
                    }).collect();
                    print_table(&header, &rows);
                }
            }

            if let Some(sessions) = response.get("sessions").and_then(|v| v.as_array()) {
                if !sessions.is_empty() {
                    println!("\n  Active sessions:");
                    let header = vec!["Key", "IP Address", "Uptime", "RX", "TX"];
                    print_table(&header, &session_rows(sessions));
                } else {
                    println!("\n  No active sessions.");
                }
            }
        }

        _ => {
            println!("{}", serde_json::to_string_pretty(response)?);
        }
    }

    Ok(())
}

/// The `ckr` verbs, one per line, for the usage error and the command list.
#[cfg(feature = "ckr")]
pub const CKR_VERBS: &str = "\
ckr list                  show the live route set
ckr export                print it as a [tunnel_routing.remote_subnets] TOML section
ckr check <file|->        validate a route set and show what would change
ckr set <file|->          replace the live route set";

/// Run a `yggdrasil ckr <verb>` subcommand against the admin socket.
#[cfg(feature = "ckr")]
pub async fn run_ckr(endpoint: &str, json_output: bool, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ckr::{CkrApplyReport, CkrKeySubnets};
    use serde::Deserialize;

    let verb = args.first().map(|s| s.to_ascii_lowercase());
    let (command, arguments) = match (verb.as_deref(), args.get(1)) {
        (Some("list" | "export"), None) => ("getckrroutes", serde_json::Map::new()),
        (Some(verb @ ("check" | "set")), Some(source)) if args.len() == 2 => {
            let mut arguments = serde_json::Map::new();
            arguments.insert("remote_subnets".to_string(), serde_json::to_value(read_route_file(source))?);
            arguments.insert("dry_run".to_string(), serde_json::Value::Bool(verb == "check"));
            ("setckrroutes", arguments)
        }
        _ => {
            eprintln!("Usage: yggdrasil [options] ckr <verb>");
            for line in CKR_VERBS.lines() {
                eprintln!("  {}", line);
            }
            std::process::exit(1);
        }
    };

    let resp = admin_call(endpoint, command, arguments).await?;
    let verb = verb.unwrap_or_default();
    // `export --json` prints the bare map, which `ckr set` accepts back.
    if json_output && verb != "export" {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        // Unlike other commands, exit 1 on an error, so that scripts can
        // trust the status.
        if resp.get("status").and_then(|v| v.as_str()) != Some("success") {
            std::process::exit(1);
        }
        return Ok(());
    }
    let r = success_response(&resp);

    if verb == "check" || verb == "set" {
        let report = CkrApplyReport::deserialize(r)?;
        if report.applied {
            println!(
                "Applied: {} IPv4, {} IPv6 routes; system routes +{} -{}",
                report.ipv4_routes,
                report.ipv6_routes,
                report.system_routes_added.len(),
                report.system_routes_removed.len()
            );
        } else {
            println!("Dry run: nothing changed.");
            println!("  Table routes:  {} IPv4, {} IPv6", report.ipv4_routes, report.ipv6_routes);
            println!("  System routes: +{} -{}", report.system_routes_added.len(), report.system_routes_removed.len());
            for prefix in &report.system_routes_added {
                println!("    + {}", prefix);
            }
            for prefix in &report.system_routes_removed {
                println!("    - {}", prefix);
            }
        }
        // The table was applied either way, so this is not an error exit.
        for failure in &report.system_route_failures {
            eprintln!("Warning: failed to install system route {}: {}", failure.prefix, failure.error);
        }
        return Ok(());
    }

    if r.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
        if verb == "export" {
            eprintln!("CKR is not enabled on this node.");
            std::process::exit(1);
        }
        println!("CKR is not enabled on this node.");
        return Ok(());
    }
    let entries = Vec::<CkrKeySubnets>::deserialize(&r["remote_subnets"])?;

    if verb == "export" {
        let map: SubnetMap = entries.into_iter().map(|e| (e.key, e.subnets)).collect();
        if json_output {
            println!("{}", serde_json::to_string_pretty(&map)?);
        } else {
            print!("{}", export_toml(&map)?);
        }
        return Ok(());
    }

    print_kv(r, &[
        ("TUN", "tun"),
        ("Yggdrasil routing", "yggdrasil_routing"),
        ("Install system routes", "install_system_routes"),
        ("IPv4 table routes", "ipv4_routes"),
        ("IPv6 table routes", "ipv6_routes"),
        ("System routes", "system_routes"),
    ]);
    let rows: Vec<Vec<String>> = entries
        .iter()
        .flat_map(|e| {
            let address = if e.is_self {
                "(self, ignored)".to_string()
            } else {
                e.address.clone().unwrap_or_else(|| "-".to_string())
            };
            e.subnets.iter().map(move |s| vec![s.clone(), e.key.clone(), address.clone()])
        })
        .collect();
    println!();
    if rows.is_empty() {
        println!("  No remote subnets.");
    } else {
        print_table(&["Subnet", "Public Key", "IP Address"], &rows);
    }
    let failed = Vec::<String>::deserialize(&r["failed_system_routes"])?;
    if !failed.is_empty() {
        println!("\nSystem routes that failed to install (retried on the next 'ckr set'):");
        for prefix in failed {
            println!("  {}", prefix);
        }
    }
    Ok(())
}

/// Read and parse a route file for `ckr check`/`ckr set`, exiting on error.
/// The file is read here, on the client side: the daemon never opens files
/// on request, so the admin socket cannot make a root process read
/// arbitrary paths.
#[cfg(feature = "ckr")]
fn read_route_file(source: &str) -> SubnetMap {
    let text = if source == "-" {
        std::io::read_to_string(std::io::stdin())
    } else {
        std::fs::read_to_string(source)
    };
    let text = text.unwrap_or_else(|e| {
        eprintln!("Error: failed to read {}: {}", source, e);
        std::process::exit(1);
    });
    parse_remote_subnets_doc(&text).unwrap_or_else(|e| {
        eprintln!("Error: {}: {}", source, e);
        std::process::exit(1);
    })
}

/// Public key hex -> raw subnet entries, as in `tunnel_routing.remote_subnets`.
#[cfg(feature = "ckr")]
type SubnetMap = std::collections::BTreeMap<String, Vec<String>>;

/// Render a route set as a `[tunnel_routing.remote_subnets]` TOML section
/// that can be pasted into the config or fed back to `ckr set`.
#[cfg(feature = "ckr")]
fn export_toml(map: &SubnetMap) -> Result<String, toml::ser::Error> {
    let section = std::collections::BTreeMap::from([("remote_subnets", map)]);
    toml::to_string(&std::collections::BTreeMap::from([("tunnel_routing", section)]))
}

/// Extract a `remote_subnets` map from a JSON or TOML document. Accepted
/// shapes, checked in order:
///  1. a full config: `tunnel_routing.remote_subnets`
///  2. `{ remote_subnets = {...} }`
///  3. the bare map `{ "<hex>" = [...] }`
///
/// Only the map is read; other `tunnel_routing` settings are ignored. An
/// empty document, or a `tunnel_routing` table without `remote_subnets`, is
/// an error rather than the empty set, so that a misspelt key cannot clear
/// every live route. Keys and subnets are validated by the daemon.
#[cfg(feature = "ckr")]
fn parse_remote_subnets_doc(text: &str) -> Result<SubnetMap, String> {
    const SHAPES: &str = "expected a [tunnel_routing.remote_subnets] section, a [remote_subnets] table, \
                          or a bare map of \"<public key hex>\" = [\"<subnet>\", ...]";
    // TOML cannot start with `{`, so that settles the format.
    let doc: serde_json::Value = if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|e| format!("invalid JSON: {}", e))?
    } else {
        let doc: toml::Value = toml::from_str(text).map_err(|e| format!("invalid TOML: {}", e))?;
        serde_json::to_value(doc).map_err(|e| e.to_string())?
    };
    let decode = |v: &serde_json::Value, what: &str| {
        serde_json::from_value::<SubnetMap>(v.clone()).map_err(|e| format!("{}: {}", what, e))
    };
    match doc.as_object() {
        Some(root) if root.is_empty() && !text.trim_start().starts_with('{') => {
            Err(format!("document is empty; {}", SHAPES))
        }
        Some(root) => match (root.get("tunnel_routing"), root.get("remote_subnets")) {
            (Some(tr), _) => match tr.get("remote_subnets") {
                Some(v) => decode(v, "tunnel_routing.remote_subnets"),
                None => Err("tunnel_routing has no remote_subnets; to clear every route, \
                             pass an empty [tunnel_routing.remote_subnets] section"
                    .to_string()),
            },
            (None, Some(v)) => decode(v, "remote_subnets"),
            (None, None) => decode(&doc, "document").map_err(|e| format!("{}; {}", e, SHAPES)),
        },
        None => Err(SHAPES.to_string()),
    }
}

fn session_rows(sessions: &[serde_json::Value]) -> Vec<Vec<String>> {
    sessions.iter().map(|s| {
        let uptime = s.get("uptime").and_then(|v| v.as_f64())
            .map(format_uptime).unwrap_or_else(|| "-".into());
        let rx = s.get("bytes_recvd").and_then(|v| v.as_u64())
            .map(format_bytes).unwrap_or_else(|| "-".into());
        let tx = s.get("bytes_sent").and_then(|v| v.as_u64())
            .map(format_bytes).unwrap_or_else(|| "-".into());
        vec![json_str(s, "key"), json_str(s, "address"), uptime, rx, tx]
    }).collect()
}

/// Smallest width the flexible column may be shrunk to.
const MIN_FLEX_WIDTH: usize = 20;

/// Print rows as space-aligned columns with no borders or padding.
fn print_table(header: &[&str], rows: &[Vec<String>]) {
    print_table_inner(header, rows, None);
}

/// Like [`print_table`], but if the table is wider than the terminal, column
/// `flex_col` is narrowed (its cells truncated with an ellipsis) until the
/// table fits, down to [`MIN_FLEX_WIDTH`].
fn print_table_flex(header: &[&str], rows: &[Vec<String>], flex_col: usize) {
    print_table_inner(header, rows, Some(flex_col));
}

fn print_table_inner(header: &[&str], rows: &[Vec<String>], flex_col: Option<usize>) {
    for line in format_table(header, rows, flex_col, terminal_width()) {
        println!("{}", line);
    }
}

fn format_table(
    header: &[&str],
    rows: &[Vec<String>],
    flex_col: Option<usize>,
    term_width: Option<usize>,
) -> Vec<String> {
    let cols = header.len();
    // Compute max width per column
    let mut widths = vec![0usize; cols];
    for (i, h) in header.iter().enumerate() {
        widths[i] = h.chars().count();
    }
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < cols {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }
    // Narrow the flexible column if the table overflows the terminal
    let flex_col = flex_col.filter(|&i| i < cols);
    if let (Some(flex), Some(term)) = (flex_col, term_width) {
        let total: usize = widths.iter().sum::<usize>() + 2 * cols.saturating_sub(1);
        if total > term {
            let shrunk = widths[flex].saturating_sub(total - term).max(MIN_FLEX_WIDTH);
            widths[flex] = shrunk.min(widths[flex]);
        }
    }

    let render = |cells: &mut dyn Iterator<Item = &str>| -> String {
        let mut line = String::new();
        for (i, cell) in cells.enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            let cell = fit_cell(cell, widths[i], flex_col == Some(i));
            if i < cols - 1 {
                line.push_str(&format!("{:<width$}", cell, width = widths[i]));
            } else {
                line.push_str(&cell); // last column: no trailing spaces
            }
        }
        line
    };

    let mut out = vec![render(&mut header.iter().copied())];
    for row in rows {
        out.push(render(&mut row.iter().map(|s| s.as_str())));
    }
    out
}

/// Cut `s` down to `width` characters, marking the cut with an ellipsis.
/// Returns it unchanged when `truncate` is false or it already fits.
fn fit_cell(s: &str, width: usize, truncate: bool) -> String {
    if !truncate || width == 0 || s.chars().count() <= width {
        return s.to_string();
    }
    let mut out: String = s.chars().take(width - 1).collect();
    out.push('…');
    out
}

/// Terminal width in columns, or `None` when stdout isn't a terminal
/// (redirected to a file or a pipe — leave the output untruncated there).
fn terminal_width() -> Option<usize> {
    terminal_size::terminal_size().map(|(terminal_size::Width(w), _)| w as usize)
}

fn json_str(obj: &serde_json::Value, key: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

fn json_u64(obj: &serde_json::Value, key: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".into())
}

fn print_kv(obj: &serde_json::Value, fields: &[(&str, &str)]) {
    let max_label = fields.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    for (label, key) in fields {
        if let Some(val) = obj.get(key) {
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "n/a".to_string(),
                other => other.to_string(),
            };
            println!("  {:width$}  {}", format!("{}:", label), val_str, width = max_label + 1);
        }
    }
}

/// Format bytes as human-readable string (KB, MB, GB, etc.)
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Vec<&'static str>, Vec<Vec<String>>) {
        let header = vec!["URI", "State", "Latency"];
        let rows = vec![
            vec!["tls://[201:23b0:9e11:2a7c:4d5f::1]:7743".into(), "Up".into(), "21.0ms".into()],
            vec!["tcp://192.168.44.125:7743".into(), "Up".into(), "1.1ms".into()],
        ];
        (header, rows)
    }

    /// Every line of a fitted table has the same width, and it's within the terminal.
    fn assert_fits(lines: &[String], term: usize) {
        for line in lines {
            assert!(line.chars().count() <= term, "line over {} cols: {:?}", term, line);
        }
    }

    #[test]
    fn table_untruncated_when_it_fits() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, Some(0), Some(200));
        assert!(lines[1].starts_with("tls://[201:23b0:9e11:2a7c:4d5f::1]:7743"));
        assert!(!lines.iter().any(|l| l.contains('…')));
    }

    #[test]
    fn table_untruncated_when_not_a_terminal() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, Some(0), None);
        assert!(lines[1].starts_with("tls://[201:23b0:9e11:2a7c:4d5f::1]:7743"));
    }

    #[test]
    fn flex_column_shrinks_to_terminal_width() {
        let (header, rows) = sample();
        let term = 45;
        let lines = format_table(&header, &rows, Some(0), Some(term));
        assert_fits(&lines, term);
        // Widest line uses the full terminal width, i.e. we shrank by exactly the overflow
        assert_eq!(lines.iter().map(|l| l.chars().count()).max().unwrap(), term);
        assert!(lines[1].starts_with("tls://[201:23b0"));
        assert!(lines[1].contains('…'));
        // The short URI still fits, so it keeps its tail
        assert!(lines[2].starts_with("tcp://192.168.44.125:7743"));
    }

    #[test]
    fn flex_column_never_shrinks_below_minimum() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, Some(0), Some(10));
        let uri: String = lines[1].chars().take(MIN_FLEX_WIDTH).collect();
        assert_eq!(uri.chars().count(), MIN_FLEX_WIDTH);
        assert!(uri.ends_with('…'));
    }

    #[test]
    fn other_columns_are_never_truncated() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, Some(0), Some(30));
        for line in &lines[1..] {
            assert!(line.ends_with("ms"), "latency column was cut: {:?}", line);
        }
    }

    #[test]
    fn plain_table_ignores_terminal_width() {
        let (header, rows) = sample();
        let lines = format_table(&header, &rows, None, Some(20));
        assert!(lines[1].starts_with("tls://[201:23b0:9e11:2a7c:4d5f::1]:7743"));
    }
    #[cfg(feature = "ckr")]
    mod ckr_doc {
        use super::super::*;

        const K1: &str = "0101010101010101010101010101010101010101010101010101010101010101";
        const K2: &str = "0202020202020202020202020202020202020202020202020202020202020202";

        fn expected() -> SubnetMap {
            SubnetMap::from([
                (K1.to_string(), vec!["10.0.0.0/24".to_string(), "~10.1.0.0/16".to_string()]),
                (K2.to_string(), vec!["!10.0.0.5".to_string(), "inetv6".to_string()]),
            ])
        }

        #[test]
        fn all_shapes_toml_and_json() {
            let toml = format!("\"{K1}\" = [\"10.0.0.0/24\", \"~10.1.0.0/16\"]\n\"{K2}\" = [\"!10.0.0.5\", \"inetv6\"]\n");
            let json = format!("{{\"{K1}\": [\"10.0.0.0/24\", \"~10.1.0.0/16\"], \"{K2}\": [\"!10.0.0.5\", \"inetv6\"]}}");
            for doc in [
                format!("[tunnel_routing.remote_subnets]\n{toml}"),
                format!("[remote_subnets]\n{toml}"),
                toml.clone(),
                format!("{{\"tunnel_routing\": {{\"remote_subnets\": {json}}}}}"),
                format!("{{\"remote_subnets\": {json}}}"),
                json.clone(),
            ] {
                assert_eq!(parse_remote_subnets_doc(&doc).unwrap(), expected(), "{}", doc);
            }
        }

        #[test]
        fn full_config_file() {
            let text = format!(
                "{}\n[tunnel_routing]\nenable = true\n[tunnel_routing.remote_subnets]\n\
                 \"{K1}\" = [\"10.0.0.0/24\", \"~10.1.0.0/16\"]\n\"{K2}\" = [\"!10.0.0.5\", \"inetv6\"]\n",
                crate::config::Config::generate_config_text()
            );
            assert!(text.contains("[firewall]"));
            assert_eq!(parse_remote_subnets_doc(&text).unwrap(), expected());
        }

        #[test]
        fn rejects_documents_that_would_clear_by_accident() {
            for doc in ["", "# only a comment\n", "[tunnel_routing]\nenable = true\n", "{\"tunnel_routing\": {}}"] {
                assert!(parse_remote_subnets_doc(doc).is_err(), "accepted {:?}", doc);
            }
            // Clearing stays possible, explicitly.
            assert!(parse_remote_subnets_doc("[tunnel_routing.remote_subnets]\n").unwrap().is_empty());
            assert!(parse_remote_subnets_doc("{}").unwrap().is_empty());
        }

        #[test]
        fn rejects_bad_documents() {
            let err = parse_remote_subnets_doc(&format!("[remote_subnets]\n\"{K1}\" = [\"10.0.0.0/24\", 5]\n"))
                .unwrap_err();
            assert!(err.contains("remote_subnets"), "{}", err);
            // A misspelt section name falls through to the bare map and gets the shapes.
            let err = parse_remote_subnets_doc("[tunnel_route.remote_subnets]\n\"aa\" = [\"10.0.0.0/24\"]\n")
                .unwrap_err();
            assert!(err.contains("expected"), "{}", err);
            for garbage in ["this is = = not toml", "{not json", "[1, 2]"] {
                assert!(parse_remote_subnets_doc(garbage).is_err(), "accepted {:?}", garbage);
            }
        }

        #[test]
        fn export_round_trips() {
            let text = export_toml(&expected()).unwrap();
            assert!(text.starts_with("[tunnel_routing.remote_subnets]"), "{}", text);
            assert_eq!(parse_remote_subnets_doc(&text).unwrap(), expected());
            let empty = export_toml(&SubnetMap::new()).unwrap();
            assert!(parse_remote_subnets_doc(&empty).unwrap().is_empty());
        }
    }
}

/// Format uptime in seconds as human-readable string (e.g., "1h23m45s")
fn format_uptime(seconds: f64) -> String {
    let total_secs = seconds as u64;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if hours > 0 {
        format!("{}h{}m{}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m{}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}
