use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{ AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use url::Url;

use rustls::pki_types::CertificateDer;

use crate::core::Core;
use crate::transport::tls::extract_ed25519_pubkey_from_cert;
use crate::version::Metadata;

#[cfg(feature = "quic")]
use crate::transport::quic;
#[cfg(feature = "ws")]
use crate::transport::ws;
#[cfg(feature = "pt")]
use crate::transport::pt;

/// Enum to handle TCP, TLS, WebSocket and QUIC streams uniformly.
pub(crate) enum Stream {
    Tcp(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
    TlsClient(tokio_rustls::client::TlsStream<TcpStream>),
    #[cfg(feature = "ws")]
    Ws(ws::WsStream),
    #[cfg(feature = "quic")]
    Quic(quic::QuicStream),
    /// A plain TCP stream tunnelled through a Pluggable Transport SOCKS5 proxy.
    /// The second field carries the logical peer address so the rest of the
    /// stack has a meaningful remote addr without relying on the actual socket
    /// peer (which is the loopback SOCKS proxy). `None` for hostname bridges:
    /// the name is resolved inside the PT (resolving it locally would leak
    /// DNS), so no honest address exists.
    #[cfg(feature = "pt")]
    Pt(TcpStream, Option<SocketAddr>),
}

impl Stream {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Stream::Tcp(s) => s.peer_addr(),
            Stream::Tls(s) => s.get_ref().0.peer_addr(),
            Stream::TlsClient(s) => s.get_ref().0.peer_addr(),
            #[cfg(feature = "ws")]
            Stream::Ws(s) => Ok(s.peer_addr()),
            #[cfg(feature = "quic")]
            Stream::Quic(s) => Ok(s.peer_addr()),
            #[cfg(feature = "pt")]
            Stream::Pt(_, addr) => addr.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "PT bridge address is a hostname (resolved inside the PT)",
                )
            }),
        }
    }

    /// Extract the first peer certificate from a TLS-carrying connection
    /// (tls, wss, quic). Returns `None` for plain TCP/ws or if no peer
    /// certificate is available.
    fn peer_tls_cert(&self) -> Option<&CertificateDer<'static>> {
        match self {
            Stream::Tcp(_) => None,
            Stream::Tls(s) => {
                // Server-side: client cert available if client sent one (optional)
                s.get_ref().1.peer_certificates()?.first()
            }
            Stream::TlsClient(s) => {
                // Client-side: server's certificate
                s.get_ref().1.peer_certificates()?.first()
            }
            #[cfg(feature = "ws")]
            Stream::Ws(s) => s.peer_cert(),
            #[cfg(feature = "quic")]
            Stream::Quic(s) => s.peer_cert(),
            #[cfg(feature = "pt")]
            Stream::Pt(_, _) => None,
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            Stream::TlsClient(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "ws")]
            Stream::Ws(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "quic")]
            Stream::Quic(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "pt")]
            Stream::Pt(s, _) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            Stream::TlsClient(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "ws")]
            Stream::Ws(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "quic")]
            Stream::Quic(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "pt")]
            Stream::Pt(s, _) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s).poll_flush(cx),
            Stream::TlsClient(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "ws")]
            Stream::Ws(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "quic")]
            Stream::Quic(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "pt")]
            Stream::Pt(s, _) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Stream::TlsClient(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "ws")]
            Stream::Ws(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "quic")]
            Stream::Quic(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "pt")]
            Stream::Pt(s, _) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Format a peer URI for display, resolving numeric IPv6 scope IDs to interface names.
fn format_peer_uri(scheme: &str, addr: &SocketAddr) -> String {
    if let SocketAddr::V6(v6) = addr {
        let scope_id = v6.scope_id();
        if scope_id != 0 {
            if let Some(name) = scope_id_to_name(scope_id) {
                return format!("{}://[{}%{}]:{}", scheme, v6.ip(), name, v6.port());
            }
        }
    }
    format!("{}://{}", scheme, addr)
}

fn scope_id_to_name(scope_id: u32) -> Option<String> {
    let ifaces = getifaddrs::getifaddrs().ok()?;
    for iface in ifaces {
        if iface.index == Some(scope_id) {
            return Some(iface.name);
        }
    }
    None
}

const DEFAULT_BACKOFF_LIMIT: Duration = Duration::from_secs(4096);
const MINIMUM_BACKOFF_LIMIT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(6);
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
// Dialling through a Pluggable Transport is deliberately slow — obfuscation
// handshakes and rendezvous (e.g. Snowflake) can take tens of seconds — so it
// gets its own, much larger budget than a plain TCP connect. Without any cap a
// blackholed bridge would wedge the reconnect loop forever.
#[cfg(feature = "pt")]
const PT_DIAL_TIMEOUT: Duration = Duration::from_secs(60);

// Maximum shift for exponential backoff (dial wait = 1 << shift seconds),
// further clamped by options.max_backoff.
const BACKOFF_SHIFT_MAX: u32 = 16;

// If a peering stayed up at least this long, treat the disconnect as a
// network-jitter event and reset backoff — not a broken peer we should
// back off from.
const BACKOFF_RESET_UPTIME: Duration = Duration::from_secs(30);

// Maximum concurrent incoming connections being processed
const MAX_CONCURRENT_INCOMING: usize = 350;

// Connection throttling settings
const MAX_FAILED_ATTEMPTS: usize = 3; // Ban after this many failed handshakes
const BAN_DURATION: Duration = Duration::from_secs(900); // 15 minutes
const FAILED_ATTEMPT_WINDOW: Duration = Duration::from_secs(60); // Track failures within 1 minute

/// Type of link connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    Persistent,
    Ephemeral,
    Incoming,
}

/// Options parsed from a peer URI.
#[derive(Clone, Debug)]
pub struct LinkOptions {
    pub pinned_keys: Vec<[u8; 32]>,
    pub priority: u8,
    pub password: Vec<u8>,
    pub max_backoff: Duration,
    pub tls_sni: Option<String>,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            pinned_keys: Vec::new(),
            priority: 0,
            password: Vec::new(),
            max_backoff: DEFAULT_BACKOFF_LIMIT,
            tls_sni: None,
        }
    }
}

/// Track failed connection attempts for throttling/banning.
struct FailedAttempt {
    count: usize,
    last_attempt: Instant,
    banned_until: Option<Instant>,
}

/// IP-based connection throttling and banning.
#[derive(Clone)]
pub struct BanList(Arc<Mutex<HashMap<IpAddr, FailedAttempt>>>);

impl BanList {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    /// Check if an IP is currently banned.
    pub async fn is_banned(&self, ip: IpAddr) -> bool {
        let mut map = self.0.lock().await;
        if let Some(entry) = map.get_mut(&ip) {
            if let Some(banned_until) = entry.banned_until {
                if Instant::now() < banned_until {
                    return true;
                } else {
                    // Ban expired, clear it
                    entry.banned_until = None;
                    entry.count = 0;
                    return false;
                }
            }
        }
        false
    }

    /// Record a failed handshake attempt. Returns true if the IP should now be banned.
    pub async fn record_failure(&self, ip: IpAddr, reason: &str) -> bool {
        let mut map = self.0.lock().await;
        let now = Instant::now();

        let entry = map.entry(ip).or_insert(FailedAttempt {
            count: 0,
            last_attempt: now,
            banned_until: None,
        });

        // Reset count if last attempt was outside the window
        if now.duration_since(entry.last_attempt) > FAILED_ATTEMPT_WINDOW {
            entry.count = 0;
        }

        entry.count += 1;
        entry.last_attempt = now;

        if entry.count >= MAX_FAILED_ATTEMPTS {
            entry.banned_until = Some(now + BAN_DURATION);
            tracing::warn!(
                "Banned {} for {} seconds after {} failed attempts (reason: {})",
                ip,
                BAN_DURATION.as_secs(),
                entry.count,
                reason
            );
            true
        } else {
            false
        }
    }

    /// Clean up old entries (call periodically).
    pub async fn cleanup(&self) {
        let mut map = self.0.lock().await;
        let now = Instant::now();
        map.retain(|_, entry| {
            // Keep if banned or if recent failure
            if let Some(banned_until) = entry.banned_until {
                now < banned_until + Duration::from_secs(60)
            } else {
                now.duration_since(entry.last_attempt) < FAILED_ATTEMPT_WINDOW * 2
            }
        });
    }
}

/// Wrapper that counts bytes read/written from a stream.
/// Uses local buffering to minimize atomic operations.
struct CountingStream {
    inner: Stream,
    rx_counter: Arc<AtomicUsize>,
    tx_counter: Arc<AtomicUsize>,
    rx_buffer: usize,
    tx_buffer: usize,
}

const FLUSH_THRESHOLD: usize = 65536; // Flush to atomic counters every 64KB

impl CountingStream {
    fn new(stream: Stream, rx_counter: Arc<AtomicUsize>, tx_counter: Arc<AtomicUsize>) -> Self {
        Self {
            inner: stream,
            rx_counter,
            tx_counter,
            rx_buffer: 0,
            tx_buffer: 0,
        }
    }

    fn flush_rx(&mut self) {
        if self.rx_buffer > 0 {
            self.rx_counter.fetch_add(self.rx_buffer, Ordering::Relaxed);
            self.rx_buffer = 0;
        }
    }

    fn flush_tx(&mut self) {
        if self.tx_buffer > 0 {
            self.tx_counter.fetch_add(self.tx_buffer, Ordering::Relaxed);
            self.tx_buffer = 0;
        }
    }
}

impl AsyncRead for CountingStream {
    fn poll_read(mut self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let bytes_read = buf.filled().len() - before;
            self.rx_buffer += bytes_read;
            if self.rx_buffer >= FLUSH_THRESHOLD {
                self.flush_rx();
            }
        }
        result
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(mut self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.tx_buffer += *n;
            if self.tx_buffer >= FLUSH_THRESHOLD {
                self.flush_tx();
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if let Poll::Ready(Ok(())) = &result {
            self.flush_tx(); // Flush buffered counts on stream flush
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.flush_rx(); // Flush all buffered counts on shutdown
        self.flush_tx();
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for CountingStream {
    fn drop(&mut self) {
        // Ensure any buffered counts are flushed when stream is dropped
        self.flush_rx();
        self.flush_tx();
    }
}

/// Snapshot of a link's current state (for admin API).
#[derive(Clone, Debug)]
pub struct LinkPeerInfo {
    pub uri: String,
    pub up: bool,
    pub inbound: bool,
    pub key: [u8; 32],
    pub priority: u8,
    pub rx_bytes: usize,
    pub tx_bytes: usize,
    pub rx_rate: usize,
    pub tx_rate: usize,
    pub uptime_secs: f64,
    pub latency_ms: f64,
    pub cost: u64,
    pub last_error: Option<String>,
}

/// Fired when a peer connection is established or lost.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    Connected    { key: [u8; 32], uri: String, inbound: bool },
    Disconnected { key: [u8; 32] },
}

/// Shared registry of active link connections.
/// This is separate from `Links` so spawned tasks can update it.
#[derive(Clone)]
pub struct ActiveLinks {
    inner: Arc<Mutex<ActiveLinksInner>>,
    pub ban_list: BanList,
    peer_tx: broadcast::Sender<PeerEvent>,
}

pub struct ActiveLinksInner {
    next_id: u64,
    connections: HashMap<u64, ActiveConn>,
}

struct ActiveConn {
    uri: String,
    inbound: bool,
    key: [u8; 32],
    priority: u8,
    rx: Arc<AtomicUsize>,
    tx: Arc<AtomicUsize>,
    rx_rate: Arc<AtomicUsize>,
    tx_rate: Arc<AtomicUsize>,
    last_rx: usize,
    last_tx: usize,
    up: Instant,
}

impl ActiveLinks {
    pub fn new() -> Self {
        let (peer_tx, _) = broadcast::channel(16);
        Self {
            inner: Arc::new(Mutex::new(ActiveLinksInner {
                next_id: 0,
                connections: HashMap::new(),
            })),
            ban_list: BanList::new(),
            peer_tx,
        }
    }

    async fn register(&self, uri: String, inbound: bool, key: [u8; 32], priority: u8) -> Option<(u64, Arc<AtomicUsize>, Arc<AtomicUsize>)> {
        let mut inner = self.inner.lock().await;
        // Reject duplicate: same key + same direction
        if inner.connections.values().any(|c| c.key == key && c.inbound == inbound) {
            return None;
        }
        let id = inner.next_id;
        inner.next_id += 1;
        let rx = Arc::new(AtomicUsize::new(0));
        let tx = Arc::new(AtomicUsize::new(0));
        inner.connections.insert(
            id,
            ActiveConn {
                uri: uri.clone(),
                inbound,
                key,
                priority,
                rx: rx.clone(),
                tx: tx.clone(),
                rx_rate: Arc::new(AtomicUsize::new(0)),
                tx_rate: Arc::new(AtomicUsize::new(0)),
                last_rx: 0,
                last_tx: 0,
                up: Instant::now(),
            },
        );
        drop(inner);
        let _ = self.peer_tx.send(PeerEvent::Connected { key, uri, inbound });
        Some((id, rx, tx))
    }

    async fn unregister(&self, id: u64) {
        let key = {
            let inner = self.inner.lock().await;
            inner.connections.get(&id).map(|c| c.key)
        };
        {
            let mut inner = self.inner.lock().await;
            inner.connections.remove(&id);
        }
        if let Some(key) = key {
            let _ = self.peer_tx.send(PeerEvent::Disconnected { key });
        }
    }

    /// Remove all active connections whose URI matches `uri`.
    /// Called by `remove_peer` to clean up entries that the aborted reconnect
    /// task can no longer clean up itself (task abort skips the `unregister` call).
    pub async fn unregister_by_uri(&self, uri: &str) {
        let ids_and_keys: Vec<(u64, [u8; 32])> = {
            let inner = self.inner.lock().await;
            inner.connections.iter()
                .filter(|(_, c)| c.uri == uri)
                .map(|(id, c)| (*id, c.key))
                .collect()
        };
        {
            let mut inner = self.inner.lock().await;
            for (id, _) in &ids_and_keys {
                inner.connections.remove(id);
            }
        }
        for (_, key) in ids_and_keys {
            let _ = self.peer_tx.send(PeerEvent::Disconnected { key });
        }
    }

    /// Update rate counters for all connections (call every ~1 second).
    pub async fn update_rates(&self) {
        let mut inner = self.inner.lock().await;
        for conn in inner.connections.values_mut() {
            let rx = conn.rx.load(Ordering::Relaxed);
            let tx = conn.tx.load(Ordering::Relaxed);
            conn.rx_rate.store(rx.saturating_sub(conn.last_rx), Ordering::Relaxed);
            conn.tx_rate.store(tx.saturating_sub(conn.last_tx), Ordering::Relaxed);
            conn.last_rx = rx;
            conn.last_tx = tx;
        }
    }

    /// Subscribe to peer connect/disconnect events.
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.peer_tx.subscribe()
    }

    /// Check if there is an active connection to the given public key.
    pub async fn has_key(&self, key: &[u8; 32]) -> bool {
        let inner = self.inner.lock().await;
        inner.connections.values().any(|c| &c.key == key)
    }

    /// Get a snapshot of all active connections for the admin API.
    pub async fn get_peers(&self) -> Vec<LinkPeerInfo> {
        let inner = self.inner.lock().await;
        inner
            .connections
            .values()
            .map(|c| LinkPeerInfo {
                uri: c.uri.clone(),
                up: true,
                inbound: c.inbound,
                key: c.key,
                priority: c.priority,
                rx_bytes: c.rx.load(Ordering::Relaxed),
                tx_bytes: c.tx.load(Ordering::Relaxed),
                rx_rate: c.rx_rate.load(Ordering::Relaxed),
                tx_rate: c.tx_rate.load(Ordering::Relaxed),
                uptime_secs: c.up.elapsed().as_secs_f64(),
                latency_ms: 0.0,
                cost: 0,
                last_error: None,
            })
            .collect()
    }
}

struct PeerEntry {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// Manages TCP peer connections and listeners.
pub struct Links {
    core: Option<Arc<Core>>,
    active: ActiveLinks,
    peers: HashMap<String, PeerEntry>,
    /// Track resolved IP:port to detect duplicate peers (e.g., same host via IP and domain)
    peer_addrs: HashMap<String, String>, // "IP:port" -> original URI
    listeners: HashMap<String, (CancellationToken, JoinHandle<()>)>,
    rate_handle: Option<JoinHandle<()>>,
    /// Notifier to wake all sleeping reconnect loops immediately.
    retry_notify: Arc<Notify>,
    /// Global semaphore shared across ALL listeners — enforces total incoming connection limit.
    connection_limiter: Arc<Semaphore>,
    /// Last error per configured peer URI (shared with reconnect tasks).
    peer_errors: Arc<Mutex<HashMap<String, Option<String>>>>,

    /// PT protocol name → config (used when routing peer/listen schemes).
    #[cfg(feature = "pt")]
    pt_configs: HashMap<String, crate::config::PluggableTransportConfig>,
    /// PT protocol name → watch receiver broadcasting the current SOCKS5 proxy addr.
    /// `None` means the PT client process is not yet ready or has crashed.
    #[cfg(feature = "pt")]
    pt_client_rxs: HashMap<String, tokio::sync::watch::Receiver<Option<std::net::SocketAddr>>>,
    /// Manager task handles — kept alive for the lifetime of Links.
    #[cfg(feature = "pt")]
    pt_client_tasks: Vec<(CancellationToken, JoinHandle<()>)>,
}

impl Links {
    pub fn new(active: ActiveLinks) -> Self {
        Self {
            core: None,
            active,
            peers: HashMap::new(),
            peer_addrs: HashMap::new(),
            listeners: HashMap::new(),
            rate_handle: None,
            retry_notify: Arc::new(Notify::new()),
            connection_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_INCOMING)),
            peer_errors: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "pt")]
            pt_configs: HashMap::new(),
            #[cfg(feature = "pt")]
            pt_client_rxs: HashMap::new(),
            #[cfg(feature = "pt")]
            pt_client_tasks: Vec::new(),
        }
    }

    /// Wake all sleeping peer reconnect loops so they retry immediately.
    pub fn retry_peers_now(&self) {
        self.retry_notify.notify_waiters();
    }

    /// Get the list of all configured (outbound) peer URIs with their last errors.
    pub async fn get_configured_peers(&self) -> Vec<(String, Option<String>)> {
        let errors = self.peer_errors.lock().await;
        self.peers
            .keys()
            .map(|uri| {
                let err = errors.get(uri).cloned().flatten();
                (uri.clone(), err)
            })
            .collect()
    }

    /// Set the core reference. Must be called before listen/add_peer.
    pub fn set_core(&mut self, core: Arc<Core>) {
        self.core = Some(core);
        // Start rate update and ban list cleanup tasks
        let active = self.active.clone();
        self.rate_handle = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            let mut cleanup_counter = 0u32;
            loop {
                interval.tick().await;
                active.update_rates().await;

                // Clean up ban list every 60 seconds
                cleanup_counter += 1;
                if cleanup_counter >= 60 {
                    cleanup_counter = 0;
                    active.ban_list.cleanup().await;
                }
            }
        }));
    }

    fn core(&self) -> Result<Arc<Core>, String> {
        self.core.clone().ok_or_else(|| "core not initialized".to_string())
    }

    /// Register Pluggable Transport configs so peers/listeners can reference
    /// them by URL scheme.
    ///
    /// This only records the configs; the client subprocess for a protocol is
    /// started lazily by [`ensure_pt_client`](Self::ensure_pt_client) the first
    /// time a peer actually uses that scheme, so a bridge-server-only node never
    /// runs an idle PT client. Server-side PTs are spawned by `listen()`.
    #[cfg(feature = "pt")]
    pub fn load_pluggable_transports(
        &mut self,
        configs: &[crate::config::PluggableTransportConfig],
    ) {
        // Schemes handled by built-in transports; a PT may not shadow them or
        // it would resolve inconsistently between listen() and add_peer().
        const RESERVED_SCHEMES: &[&str] = &["tcp", "tls", "ws", "wss", "quic"];

        for cfg in configs {
            // The `url` crate lowercases schemes on parse, so peer/listen URLs
            // always arrive lowercased. Normalise the configured protocol the
            // same way, or an entry like `protocol = "Obfs4"` would register but
            // never match any URL (and could even sneak past RESERVED_SCHEMES).
            let protocol = cfg.protocol.to_ascii_lowercase();

            if RESERVED_SCHEMES.contains(&protocol.as_str()) {
                tracing::error!("PT protocol '{}' collides with a built-in transport scheme, ignoring", cfg.protocol);
                continue;
            }
            // The protocol name is used verbatim as a URL scheme, so it must be a
            // valid one: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) per RFC 3986.
            if !is_valid_url_scheme(&protocol) {
                tracing::error!("PT protocol '{}' is not a valid URL scheme, ignoring", cfg.protocol);
                continue;
            }
            if self.pt_configs.contains_key(&protocol) {
                tracing::warn!("PT protocol '{}' configured more than once, ignoring duplicate", cfg.protocol);
                continue;
            }
            let mut cfg = cfg.clone();
            cfg.protocol = protocol.clone();
            self.pt_configs.insert(protocol, cfg);
        }
    }

    /// Ensure a PT client manager is running for `protocol`, starting it on
    /// first use. Idempotent: a second call for the same protocol is a no-op.
    ///
    /// The manager task owns the PT child process, restarts it on crash with
    /// exponential backoff, and broadcasts the current SOCKS5 proxy address via
    /// a watch channel. Peer reconnect tasks clone the receiver and check it
    /// before dialling — `None` means the PT is not yet ready.
    #[cfg(feature = "pt")]
    fn ensure_pt_client(&mut self, protocol: &str) {
        // A receiver already exists → the manager is running for this protocol.
        if self.pt_client_rxs.contains_key(protocol) {
            return;
        }
        let cfg = match self.pt_configs.get(protocol) {
            Some(cfg) => cfg.clone(),
            None => return, // not a registered PT scheme; callers guard this
        };

        let (tx, rx) = tokio::sync::watch::channel::<Option<std::net::SocketAddr>>(None);
        self.pt_client_rxs.insert(protocol.to_string(), rx);

        let cancel = CancellationToken::new();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                let mut backoff: u32 = 0;
                loop {
                    if cancel.is_cancelled() { break; }

                    match pt::spawn_pt_client(&cfg).await {
                        Ok(mut proc) => {
                            // Peers that failed to dial while the PT was starting
                            // are asleep on their backoff timers; this send wakes
                            // them (they select on the watch channel) so they retry
                            // against the ready proxy instead of drifting toward
                            // maxbackoff.
                            let _ = tx.send(Some(proc.socks_addr));
                            tracing::info!(
                                "PT client '{}' ready on {}",
                                cfg.protocol, proc.socks_addr
                            );
                            let started = Instant::now();
                            tokio::select! {
                                _ = cancel.cancelled() => {
                                    pt::shutdown_pt_client(proc).await;
                                    break;
                                }
                                _ = proc.child.wait() => {
                                    let _ = tx.send(None);
                                    tracing::warn!(
                                        "PT client '{}' exited unexpectedly, restarting",
                                        cfg.protocol
                                    );
                                    // Only clear backoff if the process stayed up
                                    // long enough to be considered healthy;
                                    // otherwise a fast crash-loop would retry every
                                    // second forever.
                                    if started.elapsed() >= BACKOFF_RESET_UPTIME {
                                        backoff = 0;
                                    } else if backoff < 6 {
                                        backoff += 1;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(None);
                            tracing::error!("PT client '{}' failed to start: {}", cfg.protocol, e);
                            if backoff < 6 { backoff += 1; }
                        }
                    }

                    let wait = Duration::from_secs(1u64 << backoff);
                    tracing::debug!("PT client '{}' retrying in {:?}", cfg.protocol, wait);
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(wait) => {}
                    }
                }
                tracing::debug!("PT client manager '{}' stopped", cfg.protocol);
            }
        });
        self.pt_client_tasks.push((cancel, handle));
    }

    /// Start listening on an address (e.g. "tcp://0.0.0.0:1234", "tls://0.0.0.0:2345",
    /// "ws://0.0.0.0:80", "wss://0.0.0.0:443" or "quic://0.0.0.0:4567").
    pub async fn listen(&mut self, addr: &str) -> Result<(), String> {
        let url = Url::parse(addr).map_err(|e| format!("invalid URL: {}", e))?;
        let scheme = url.scheme().to_string();

        let host_port = url
            .socket_addrs(|| Some(0))
            .map_err(|e| format!("invalid address: {}", e))?
            .first()
            .ok_or("no address resolved")?
            .to_string();

        let options = parse_link_options(&url)?;
        let core = self.core()?;
        let active = self.active.clone();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let addr_str = addr.to_string();

        // QUIC listens on a UDP endpoint with its own channel-based accept loop.
        #[cfg(feature = "quic")]
        if scheme == "quic" {
            let bind_addr: SocketAddr = host_port
                .parse()
                .map_err(|e| format!("invalid bind address {}: {}", host_port, e))?;
            let server_config = core.tls_server_config.read().await.clone();
            let listener =
                quic::quic_listen(bind_addr, server_config, self.connection_limiter.clone())
                    .await?;
            tracing::info!("Listening on quic://{}", listener.local_addr());

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => {
                            listener.close();
                            break;
                        }
                        result = listener.accept() => {
                            let Ok(qs) = result else { break }; // listener closed
                            let remote = qs.peer_addr();
                            tracing::debug!("Accepted quic connection from {}", remote);
                            let core = core.clone();
                            let opts = options.clone();
                            let active = active.clone();
                            let remote_str = format_peer_uri("quic", &remote);
                            tokio::spawn(async move {
                                // The connection-limiter permit rides inside the
                                // QuicStream and is released when it drops.
                                let _ = handle_connection(
                                    LinkType::Incoming,
                                    opts,
                                    Stream::Quic(qs),
                                    &core,
                                    &active,
                                    &remote_str,
                                ).await;
                            });
                        }
                    }
                }
            });

            self.listeners.insert(addr_str, (cancel, handle));
            return Ok(());
        }

        // PT server: bind a loopback ORPORT, start the PT binary, accept forwarded conns.
        #[cfg(feature = "pt")]
        if let Some(pt_cfg) = self.pt_configs.get(&scheme).cloned() {
            let bind_addr: SocketAddr = host_port
                .parse()
                .map_err(|e| format!("invalid PT bind address: {}", e))?;

            // Yggdrasil owns the ORPORT socket; the PT binary forwards decrypted
            // connections to it.  We bind on loopback with a random port.
            let orport_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("PT ORPORT bind: {}", e))?;
            let orport_addr = orport_listener
                .local_addr()
                .map_err(|e| format!("PT ORPORT local_addr: {}", e))?;

            let mut pt_server = pt::spawn_pt_server(&pt_cfg, bind_addr, orport_addr)
                .await
                .map_err(|e| {
                    tracing::error!("PT server '{}' failed to start: {}", pt_cfg.protocol, e);
                    e
                })?;
            tracing::info!(
                "PT '{}' listening on {} (ORPORT {})",
                pt_cfg.protocol, pt_server.bound_addr, orport_addr
            );

            let connection_limiter = self.connection_limiter.clone();

            let handle = tokio::spawn(async move {
                let mut restart_backoff: u32 = 0;
                let mut started = Instant::now();
                loop {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => {
                            drop(pt_server);
                            break;
                        }
                        // The PT process exiting is otherwise invisible: the ORPORT
                        // socket stays bound (Yggdrasil owns it), so accept() never
                        // errors on a PT crash. Watch the child directly and restart
                        // it with exponential backoff.
                        _ = pt_server.child.wait() => {
                            tracing::warn!("PT server '{}' process exited, restarting", pt_cfg.protocol);
                            // Backoff applies to a spawn that *succeeds* but dies
                            // young too, not just to spawn failures — otherwise a PT
                            // that reports SMETHODS DONE and then exits (bad state
                            // dir, stolen port, ...) would restart in a tight loop.
                            // Same policy as the client manager above.
                            if started.elapsed() >= BACKOFF_RESET_UPTIME {
                                restart_backoff = 0;
                            } else if restart_backoff < 6 {
                                restart_backoff += 1;
                            }
                            loop {
                                let wait = Duration::from_secs(1u64 << restart_backoff);
                                tracing::debug!("PT server '{}' restarting in {:?}", pt_cfg.protocol, wait);
                                tokio::select! {
                                    _ = cancel_clone.cancelled() => return,
                                    _ = tokio::time::sleep(wait) => {}
                                }
                                match pt::spawn_pt_server(&pt_cfg, bind_addr, orport_addr).await {
                                    Ok(p) => {
                                        tracing::info!(
                                            "PT server '{}' restarted on {}",
                                            pt_cfg.protocol, p.bound_addr
                                        );
                                        pt_server = p;
                                        started = Instant::now();
                                        break;
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "PT server '{}' restart failed: {}",
                                            pt_cfg.protocol, e
                                        );
                                        if restart_backoff < 6 { restart_backoff += 1; }
                                    }
                                }
                            }
                        }
                        result = orport_listener.accept() => {
                            match result {
                                Ok((stream, remote)) => {
                                    let permit = match connection_limiter.clone().try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            tracing::warn!(
                                                "PT: too many concurrent connections, rejecting from {}",
                                                remote
                                            );
                                            continue;
                                        }
                                    };
                                    stream.set_nodelay(true).ok();
                                    let core = core.clone();
                                    let opts = options.clone();
                                    let active = active.clone();
                                    let remote_str = format!("{}://{}", pt_cfg.protocol, remote);
                                    tokio::spawn(async move {
                                        let _ = handle_connection(
                                            LinkType::Incoming,
                                            opts,
                                            Stream::Pt(stream, Some(remote)),
                                            &core,
                                            &active,
                                            &remote_str,
                                        ).await;
                                        drop(permit);
                                    });
                                }
                                Err(e) => {
                                    tracing::error!("PT ORPORT accept error: {}", e);
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            }
                        }
                    }
                }
            });

            self.listeners.insert(addr_str, (cancel, handle));
            return Ok(());
        }

        // tcp / tls / ws / wss all listen on a TCP socket; tls/wss add a TLS
        // handshake and ws/wss add a WebSocket handshake on top.
        let (use_tls, use_ws) = match scheme.as_str() {
            "tcp" => (false, false),
            "tls" => (true, false),
            #[cfg(feature = "ws")]
            "ws" => (false, true),
            #[cfg(feature = "ws")]
            "wss" => (true, true),
            #[cfg(not(feature = "ws"))]
            "ws" | "wss" => {
                return Err("ws/wss support not compiled in (enable the `ws` feature)".to_string())
            }
            #[cfg(not(feature = "quic"))]
            "quic" => {
                return Err("quic support not compiled in (enable the `quic` feature)".to_string())
            }
            _ => return Err(format!("unsupported scheme: {}", scheme)),
        };

        let listener = TcpListener::bind(&host_port)
            .await
            .map_err(|e| format!("bind failed: {}", e))?;

        let actual_addr = listener
            .local_addr()
            .map_err(|e| format!("local_addr failed: {}", e))?;
        tracing::info!("Listening on {}://{}", scheme, actual_addr);

        let tls_acceptor = if use_tls {
            let server_config = core.tls_server_config.read().await.clone();
            Some(TlsAcceptor::from(server_config))
        } else {
            None
        };

        // Shared semaphore — global limit across all listeners
        let connection_limiter = self.connection_limiter.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, remote)) => {
                                // Try to acquire permit for new connection
                                let permit = match connection_limiter.clone().try_acquire_owned() {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        // Too many concurrent connections, reject immediately
                                        tracing::warn!(
                                            "Rejected connection from {} (too many concurrent connections: {}/{})",
                                            remote,
                                            MAX_CONCURRENT_INCOMING,
                                            MAX_CONCURRENT_INCOMING
                                        );
                                        drop(stream);  // Explicit close
                                        continue;
                                    }
                                };

                                stream.set_nodelay(true).ok();
                                tracing::debug!("Accepted connection from {}", remote);
                                let core = core.clone();
                                let opts = options.clone();
                                let active = active.clone();
                                let acceptor = tls_acceptor.clone();
                                let remote_str = format_peer_uri(&scheme, &remote);

                                tokio::spawn(async move {
                                    // Permit is held for the duration of this task

                                    // Perform TLS and/or WebSocket handshakes as needed
                                    let wrapped_stream = match wrap_incoming(stream, acceptor, use_ws, remote).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::debug!("{} from {}", e, remote);
                                            drop(permit);
                                            return;
                                        }
                                    };

                                    let _ = handle_connection(
                                        LinkType::Incoming,
                                        opts,
                                        wrapped_stream,
                                        &core,
                                        &active,
                                        &remote_str,
                                    ).await;
                                    // Permit automatically released when dropped
                                    drop(permit);
                                });
                            }
                            Err(e) => {
                                tracing::error!("Accept error: {}", e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });

        self.listeners.insert(addr_str, (cancel, handle));
        Ok(())
    }

    /// Add a persistent peer to connect to.
    pub async fn add_peer(&mut self, uri: &str) -> Result<(), String> {
        if self.peers.contains_key(uri) {
            return Err("peer already exists".to_string());
        }

        let url = Url::parse(uri).map_err(|e| format!("invalid URI: {}", e))?;
        let scheme = url.scheme().to_string();
        // `use_quic` is only read when the quic feature is enabled.
        #[cfg_attr(not(feature = "quic"), allow(unused_variables))]
        let (use_tls, use_ws, use_quic) = match scheme.as_str() {
            "tcp" => (false, false, false),
            "tls" => (true, false, false),
            #[cfg(feature = "ws")]
            "ws" => (false, true, false),
            #[cfg(feature = "ws")]
            "wss" => (true, true, false),
            #[cfg(feature = "quic")]
            "quic" => (false, false, true),
            #[cfg(not(feature = "ws"))]
            "ws" | "wss" => {
                return Err("ws/wss support not compiled in (enable the `ws` feature)".to_string())
            }
            #[cfg(not(feature = "quic"))]
            "quic" => {
                return Err("quic support not compiled in (enable the `quic` feature)".to_string())
            }
            #[cfg(feature = "pt")]
            s if self.pt_configs.contains_key(s) => (false, false, false),
            _ => return Err(format!("unsupported scheme: {}", scheme)),
        };

        #[cfg(feature = "pt")]
        let use_pt = self.pt_configs.contains_key(scheme.as_str());
        // Start the PT client subprocess on first use of this scheme.
        #[cfg(feature = "pt")]
        if use_pt {
            self.ensure_pt_client(&scheme);
        }

        let host = url.host_str().ok_or("missing host")?.to_string();
        // `port_or_known_default()` so `ws://host` / `wss://host` infer 80/443.
        // (The `url` crate omits a port equal to the scheme's known default, so
        // even an explicit `wss://host:443` reports `port() == None`.)
        let port = url.port_or_known_default().ok_or("missing port")?;
        let target = format!("{}:{}", host, port);

        // PT peers connect through the SOCKS proxy, which resolves the hostname
        // itself inside the obfuscated channel. Resolving here would leak a
        // plaintext DNS query for the bridge hostname — a metadata leak in the
        // censorship-circumvention setting PTs exist for — and the result is
        // meaningless anyway, since the real connection never uses it.
        #[cfg(feature = "pt")]
        let resolve_for_dedup = !use_pt;
        #[cfg(not(feature = "pt"))]
        let resolve_for_dedup = true;

        // Attempt DNS resolution for duplicate detection.
        // If DNS fails (e.g. device is offline), skip the check and let the
        // reconnect loop retry DNS + connect with its own backoff.
        let addr_key: Option<String> = if !resolve_for_dedup {
            None
        } else {
            match tokio::net::lookup_host(&target).await {
                Ok(addrs) => {
                    let mut resolved: Vec<_> = addrs.collect();
                    resolved.sort();

                    // Check if any resolved IP:port is already connected
                    for addr in &resolved {
                        let ak = addr.to_string();
                        if let Some(existing_uri) = self.peer_addrs.get(&ak) {
                            return Err(format!("peer {} already connected as {} (resolves to same address {})", uri, existing_uri, ak));
                        }
                    }
                    resolved.first().map(|a| a.to_string())
                }
                Err(e) => {
                    tracing::warn!("DNS lookup failed for {} ({}), skipping duplicate check — will retry in reconnect loop", target, e);
                    None
                }
            }
        };

        let options = parse_link_options(&url)?;
        let core = self.core()?;
        let active = self.active.clone();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let uri_str = uri.to_string();
        let retry_notify = self.retry_notify.clone();

        // tls/wss use a TLS connector; quic needs the raw rustls client config.
        let tls_connector = if use_tls {
            let client_config = core.tls_client_config.read().await.clone();
            Some(TlsConnector::from(client_config))
        } else {
            None
        };
        #[cfg(feature = "quic")]
        let quic_client_config = if use_quic {
            Some(core.tls_client_config.read().await.clone())
        } else {
            None
        };

        let peer_errors = self.peer_errors.clone();
        // Initialize error entry for this peer
        peer_errors.lock().await.insert(uri.to_string(), None);

        // PT: clone the watch receiver for this protocol and collect per-connection args.
        #[cfg(feature = "pt")]
        let mut pt_socks_rx = if use_pt {
            match self.pt_client_rxs.get(scheme.as_str()) {
                Some(rx) => rx.clone(),
                None => return Err(format!("PT protocol '{}' has no watch receiver (internal error)", scheme)),
            }
        } else {
            tokio::sync::watch::channel(None).1
        };
        #[cfg(feature = "pt")]
        let pt_args = if use_pt { extract_pt_args(&url) } else { Vec::new() };

        let handle = tokio::spawn(async move {
            let mut backoff: u32 = 0;
            loop {
                if cancel_clone.is_cancelled() {
                    break;
                }

                // Dial according to scheme. PT goes through the SOCKS5 proxy exposed
                // by the PT client process; quic uses its own UDP dialer; everything
                // else goes through dial_stream (TCP + optional TLS + optional WS).
                let dial_result: Result<Stream, String> = async {
                    #[cfg(feature = "pt")]
                    if use_pt {
                        // borrow_and_update (not borrow) marks this value as seen,
                        // so the pt_client_became_ready arm of the backoff select
                        // below fires exactly for values sent *after* this read —
                        // including one sent before we reach the select. A plain
                        // borrow would leave that window open and the peer would
                        // sleep its full accumulated backoff.
                        let socks_addr = match *pt_socks_rx.borrow_and_update() {
                            Some(a) => a,
                            None => return Err("PT client not ready (process starting or crashed)".to_string()),
                        };
                        let tcp = tokio::time::timeout(
                            PT_DIAL_TIMEOUT,
                            pt::pt_socks5_connect(socks_addr, &host, port, &pt_args),
                        )
                        .await
                        .map_err(|_| "PT dial timed out".to_string())??;
                        // Report the bridge's address only when the URL carried an
                        // IP literal. A hostname stays unresolved (see the DNS-leak
                        // note above), and falling back to the socket's real peer
                        // would misreport the loopback SOCKS proxy as the remote.
                        let peer_addr: Option<std::net::SocketAddr> =
                            format!("{}:{}", host, port).parse().ok();
                        return Ok(Stream::Pt(tcp, peer_addr));
                    }
                    #[cfg(feature = "quic")]
                    if use_quic {
                        return quic::quic_connect(
                            &url,
                            quic_client_config.clone().expect("quic client config"),
                        )
                        .await
                        .map(Stream::Quic);
                    }
                    dial_stream(
                        &target,
                        &host,
                        port,
                        url.path(),
                        options.tls_sni.as_deref(),
                        tls_connector.as_ref(),
                        use_ws,
                    )
                    .await
                }
                .await;

                match dial_result {
                    Ok(wrapped_stream) => {
                        // Connected successfully — clear error
                        peer_errors.lock().await.insert(uri_str.clone(), None);

                        let conn_start = Instant::now();
                        let result = handle_connection(LinkType::Persistent, options.clone(), wrapped_stream, &core, &active, &uri_str).await;

                        // Reset backoff on clean shutdown OR if the peering stayed
                        // up long enough that the disconnect was almost certainly a
                        // transient network event, not a broken peer.
                        if result.is_ok() || conn_start.elapsed() >= BACKOFF_RESET_UPTIME {
                            backoff = 0;
                        }

                        match result {
                            Ok(()) => {
                                peer_errors.lock().await.insert(uri_str.clone(), None);
                            }
                            Err(e) => {
                                peer_errors.lock().await.insert(uri_str.clone(), Some(e.to_string()));
                            }
                        }
                    }
                    Err(err_msg) => {
                        tracing::info!("{} to {}", err_msg, target);
                        peer_errors.lock().await.insert(uri_str.clone(), Some(err_msg));
                    }
                }

                if backoff < 32 {
                    backoff += 1;
                }
                let wait = Duration::from_secs(1u64 << backoff.min(BACKOFF_SHIFT_MAX))
                    .min(options.max_backoff);

                // For PT peers, also wake as soon as the PT client becomes ready:
                // the watch channel's version counter makes this race-free, unlike
                // retry_notify (notify_waiters only reaches tasks already parked).
                // For non-PT peers the future never resolves.
                #[cfg(feature = "pt")]
                let pt_ready = pt_client_became_ready(&mut pt_socks_rx);
                #[cfg(not(feature = "pt"))]
                let pt_ready = std::future::pending::<()>();

                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    _ = tokio::time::sleep(wait) => {}
                    _ = retry_notify.notified() => {
                        // Reset backoff after the network change
                        backoff = 0;
                    }
                    _ = pt_ready => {}
                }
            }
        });

        self.peers.insert(uri.to_string(), PeerEntry { cancel, handle });
        if let Some(ak) = addr_key {
            self.peer_addrs.insert(ak, uri.to_string());
        }
        Ok(())
    }

    /// Remove a peer by URI.
    pub async fn remove_peer(&mut self, uri: &str) -> Result<(), String> {
        if let Some(entry) = self.peers.remove(uri) {
            entry.cancel.cancel();
            entry.handle.abort();

            // The reconnect task is cancelled at `handle_conn().await`, which means
            // the `active.unregister(conn_id)` line after it never runs.  Clean up
            // the active_links entry here so the peer disappears from get_peers_json.
            self.active.unregister_by_uri(uri).await;

            // Also remove from peer_addrs map
            self.peer_addrs.retain(|_, v| v != uri);
            // Remove error tracking entry
            self.peer_errors.lock().await.remove(uri);

            Ok(())
        } else {
            Err("peer not found".to_string())
        }
    }

    /// Stop all listeners and peers.
    pub async fn close(&mut self) {
        if let Some(h) = self.rate_handle.take() {
            h.abort();
        }
        for (_, (cancel, handle)) in self.listeners.drain() {
            cancel.cancel();
            handle.abort();
        }
        for (_, entry) in self.peers.drain() {
            entry.cancel.cancel();
            entry.handle.abort();
        }
        self.peer_addrs.clear();

        // Tear down PT client managers. Without this they keep running — and
        // keep restarting crashed PTs — after the core has been closed.
        //
        // Cancel everything first so all managers begin their graceful shutdown
        // (close the PT's stdin, give it up to 5 s to exit — see
        // shutdown_pt_client) concurrently, then wait for each to finish.
        // Aborting immediately after cancelling would drop the manager future
        // before it could observe the cancellation, SIGKILLing the PT via
        // kill_on_drop and making the graceful path dead code. The timeout
        // back-stops a wedged manager: aborting it drops the Child, whose
        // kill_on_drop reaps the process. Total wall time stays ~6 s because
        // the shutdowns run in parallel.
        #[cfg(feature = "pt")]
        {
            for (cancel, _) in &self.pt_client_tasks {
                cancel.cancel();
            }
            for (_, mut handle) in self.pt_client_tasks.drain(..) {
                if tokio::time::timeout(Duration::from_secs(6), &mut handle).await.is_err() {
                    handle.abort();
                }
            }
            self.pt_configs.clear();
            self.pt_client_rxs.clear();
        }
    }
}

/// Perform the Yggdrasil handshake over a stream (TCP or TLS), then hand off to ironwood.
pub(crate) async fn handle_connection(
    link_type: LinkType,
    options: LinkOptions,
    mut stream: Stream,
    core: &Arc<Core>,
    active: &ActiveLinks,
    uri: &str,
) -> Result<(), String> {
    // Get peer IP address for ban checking
    let peer_ip = match stream.peer_addr() {
        Ok(addr) => Some(addr.ip()),
        Err(_) => None,
    };

    // Check if IP is banned (loopback is never banned: PT server connections arrive from 127.0.0.1)
    if let Some(ip) = peer_ip {
        if !ip.is_loopback() && active.ban_list.is_banned(ip).await {
            return Err(format!("IP {} is temporarily banned", ip));
        }
    }

    // 6 second handshake timeout
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let meta = Metadata::new(core.public_key, options.priority);
        let encoded = meta.encode(&core.signing_key, &options.password);
        stream
            .write_all(&encoded)
            .await
            .map_err(|e| format!("write handshake: {}", e))?;
        // Flush is mandatory for buffered transports (WebSocket): `write_all`
        // only queues into the sink, so without this the metadata frame never
        // reaches the peer and both sides stall until the handshake times out.
        // No-op for raw TCP.
        stream
            .flush()
            .await
            .map_err(|e| format!("flush handshake: {}", e))?;

        // Read directly from stream without BufReader to avoid consuming
        // ironwood protocol data that arrives right after the handshake.
        let mut header = [0u8; 6];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| format!("read header: {}", e))?;

        if &header[..4] != b"meta" {
            return Err("invalid preamble".to_string());
        }

        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if length < 64 {
            return Err("metadata too short".to_string());
        }

        let mut body = vec![0u8; length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("read body: {}", e))?;

        let mut full = Vec::with_capacity(6 + length);
        full.extend_from_slice(&header);
        full.extend_from_slice(&body);

        let mut cursor = std::io::Cursor::new(&full);
        let remote_meta = Metadata::decode(&mut cursor, &options.password)
            .map_err(|e| format!("decode handshake: {}", e))?;

        Ok(remote_meta)
    })
    .await
    .map_err(|_| "handshake timed out".to_string())?;

    let remote_meta = result?;

    // Verify TLS certificate matches meta handshake pubkey (outbound/client-side only)
    if let Some(peer_cert) = stream.peer_tls_cert() {
        match extract_ed25519_pubkey_from_cert(peer_cert.as_ref()) {
            Some(tls_pubkey) if tls_pubkey != remote_meta.public_key => {
                let err_msg = "TLS certificate pubkey does not match meta handshake pubkey";
                tracing::warn!("{} from {}", err_msg, uri);
                if let Some(ip) = peer_ip {
                    if !ip.is_loopback() { active.ban_list.record_failure(ip, err_msg).await; }
                }
                return Err(err_msg.to_string());
            }
            Some(_) => {
                tracing::debug!("TLS certificate pubkey verified for {}", uri);
            }
            None => {
                // Peer is using a non-ed25519 cert (e.g., older node). Allow for backwards compat.
                tracing::debug!(
                    "Peer {} TLS cert does not contain ed25519 key, skipping TLS verification",
                    uri
                );
            }
        }
    }

    if !remote_meta.check() {
        let err_msg = format!(
            "incompatible version {}.{} (local {}.{})",
            remote_meta.major_ver,
            remote_meta.minor_ver,
            crate::version::PROTOCOL_VERSION_MAJOR,
            crate::version::PROTOCOL_VERSION_MINOR
        );

        // Log incompatible version
        if let Some(ip) = peer_ip {
            tracing::info!("Rejected connection from {}: {}", ip, err_msg);
            if !ip.is_loopback() { active.ban_list.record_failure(ip, "incompatible version").await; }
        } else {
            tracing::info!("Rejected connection: {}", err_msg);
        }

        return Err(err_msg);
    }

    // Log if version is newer than ours (but still compatible)
    if !remote_meta.is_exact_match() {
        tracing::debug!(
            "Connected with newer version {}.{} (local {}.{})",
            remote_meta.major_ver,
            remote_meta.minor_ver,
            crate::version::PROTOCOL_VERSION_MAJOR,
            crate::version::PROTOCOL_VERSION_MINOR
        );
    }

    if remote_meta.public_key == core.public_key {
        if let Some(ip) = peer_ip {
            tracing::debug!("Rejected connection from {}: connected to self", ip);
            // Don't ban for self-connection, it's usually a configuration issue
        }
        return Err("connected to self".to_string());
    }

    if !options.pinned_keys.is_empty()
        && !options.pinned_keys.contains(&remote_meta.public_key)
    {
        if let Some(ip) = peer_ip {
            tracing::debug!("Rejected connection from {}: key not in pinned keys", ip);
            // Don't ban for wrong pinned key - could be legitimate peering config mismatch
        }
        return Err("remote key not in pinned keys".to_string());
    }

    if link_type == LinkType::Incoming && !core.is_key_allowed(&remote_meta.public_key) {
        if let Some(ip) = peer_ip {
            tracing::debug!("Rejected connection from {}: key not in allowed list", ip);
            if !ip.is_loopback() { active.ban_list.record_failure(ip, "key not allowed").await; }
        }
        return Err("remote key not allowed".to_string());
    }

    let priority = options.priority.max(remote_meta.priority);

    let remote_addr = crate::address::addr_for_key(&remote_meta.public_key);
    let direction = if link_type == LinkType::Incoming {
        "inbound"
    } else {
        "outbound"
    };
    // No socket address (e.g. a PT hostname bridge): fall back to the URI.
    let peer_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| uri.to_string());
    tracing::info!(
        "Connected {}: {} @ {} (v{}.{})",
        direction,
        remote_addr,
        peer_addr,
        remote_meta.major_ver,
        remote_meta.minor_ver
    );

    // Register in active links (rejects duplicate key+direction)
    let inbound = link_type == LinkType::Incoming;
    let (conn_id, rx_counter, tx_counter) = match active
        .register(uri.to_string(), inbound, remote_meta.public_key, priority)
        .await
    {
        Some(r) => r,
        None => return Err("duplicate connection".to_string()),
    };

    let conn_start = Instant::now();

    // Wrap stream to count bytes
    let counting_stream = CountingStream::new(stream, rx_counter, tx_counter);

    // Hand off to ironwood (blocks until peer disconnects)
    let result = core
        .handle_conn(remote_meta.public_key, Box::new(counting_stream), priority)
        .await
        .map_err(|e| format!("ironwood: {}", e));

    // Unregister when done
    active.unregister(conn_id).await;

    // Log disconnection
    let uptime = conn_start.elapsed();
    match &result {
        Ok(()) => {
            tracing::info!(
                "Disconnected {}: {} @ {} (uptime: {:.1}s)",
                direction,
                remote_addr,
                peer_addr,
                uptime.as_secs_f64()
            );
        }
        Err(e) => {
            tracing::info!(
                "Disconnected {}: {} @ {} (uptime: {:.1}s, error: {})",
                direction,
                remote_addr,
                peer_addr,
                uptime.as_secs_f64(),
                e
            );
        }
    }

    result
}

/// Wrap an accepted TCP connection according to the listener's scheme:
/// optional TLS handshake (tls/wss), then optional WebSocket handshake (ws/wss).
async fn wrap_incoming(
    stream: TcpStream,
    acceptor: Option<TlsAcceptor>,
    use_ws: bool,
    remote: SocketAddr,
) -> Result<Stream, String> {
    #[cfg(not(feature = "ws"))]
    let _ = (use_ws, remote); // ws:// and wss:// are rejected at listen() time

    #[cfg(feature = "ws")]
    if use_ws {
        return match acceptor {
            Some(acceptor) => {
                let tls_stream = acceptor
                    .accept(stream)
                    .await
                    .map_err(|e| format!("TLS handshake failed: {}", e))?;
                // Client cert (if presented) for cert/identity binding in
                // handle_connection.
                let peer_cert = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first().cloned());
                let ws = ws::ws_server_handshake(Box::new(tls_stream), remote, peer_cert).await?;
                Ok(Stream::Ws(ws))
            }
            None => {
                let ws = ws::ws_server_handshake(Box::new(stream), remote, None).await?;
                Ok(Stream::Ws(ws))
            }
        };
    }

    match acceptor {
        Some(acceptor) => {
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| format!("TLS handshake failed: {}", e))?;
            Ok(Stream::Tls(tls_stream))
        }
        None => Ok(Stream::Tcp(stream)),
    }
}

/// Dial a TCP-based peer (tcp/tls/ws/wss): TCP connect, then an optional TLS
/// handshake (tls/wss) and an optional WebSocket handshake (ws/wss), producing
/// a ready `Stream`.
async fn dial_stream(
    target: &str,
    host: &str,
    port: u16,
    path: &str,
    sni: Option<&str>,
    tls_connector: Option<&TlsConnector>,
    use_ws: bool,
) -> Result<Stream, String> {
    #[cfg(not(feature = "ws"))]
    let _ = (port, path, use_ws); // ws:// and wss:// are rejected at add_peer() time

    let stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| "Connection timed out".to_string())?
        .map_err(|e| format!("Failed to connect: {}", e))?;
    stream.set_nodelay(true).ok();
    #[cfg(feature = "ws")]
    let remote_addr = stream
        .peer_addr()
        .map_err(|e| format!("peer_addr: {}", e))?;

    if let Some(connector) = tls_connector {
        // Use SNI from options (explicit ?sni= or hostname fallback), else raw host
        let sni_host = sni.map(str::to_string).unwrap_or_else(|| host.to_string());
        let server_name = rustls::pki_types::ServerName::try_from(sni_host)
            .unwrap_or_else(|_| {
                // Fallback to using IP address as server name if hostname parsing fails
                rustls::pki_types::ServerName::IpAddress(
                    rustls::pki_types::IpAddr::try_from(host).expect("invalid hostname"),
                )
            });
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;
        #[cfg(feature = "ws")]
        if use_ws {
            // Server cert for cert/identity binding in handle_connection.
            let peer_cert = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first().cloned());
            let ws =
                ws::ws_client_handshake(Box::new(tls_stream), host, port, path, remote_addr, peer_cert)
                    .await?;
            return Ok(Stream::Ws(ws));
        }
        Ok(Stream::TlsClient(tls_stream))
    } else {
        #[cfg(feature = "ws")]
        if use_ws {
            let ws = ws::ws_client_handshake(Box::new(stream), host, port, path, remote_addr, None)
                .await?;
            return Ok(Stream::Ws(ws));
        }
        Ok(Stream::Tcp(stream))
    }
}

/// Parse a duration string that accepts either plain seconds ("300") or
/// Go-style duration components ("5m", "1h30m", "2h30m15s").
fn parse_duration_string(s: &str) -> Result<Duration, String> {
    // Try plain integer seconds first (backwards compatibility)
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    let mut total_secs: u64 = 0;
    let mut current_num = String::new();
    let mut has_unit = false;

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            let n: u64 = current_num
                .parse()
                .map_err(|_| format!("invalid duration: {}", s))?;
            current_num.clear();
            match ch {
                'h' => total_secs += n * 3600,
                'm' => total_secs += n * 60,
                's' => total_secs += n,
                _ => return Err(format!("invalid duration unit '{}' in: {}", ch, s)),
            }
            has_unit = true;
        }
    }

    if !current_num.is_empty() && !has_unit {
        return Err(format!("invalid duration: {}", s));
    }
    // Trailing number without unit (e.g., "5m30") is an error
    if !current_num.is_empty() {
        return Err(format!("trailing number without unit in duration: {}", s));
    }

    Ok(Duration::from_secs(total_secs))
}

/// Resolve when the PT client for this peer's protocol becomes ready — i.e.
/// the watch value transitions to `Some` after the last `borrow_and_update`.
/// Never resolves for non-PT peers (their dummy receiver's sender is already
/// dropped) or after the PT managers are torn down; cancellation wins instead.
#[cfg(feature = "pt")]
async fn pt_client_became_ready(rx: &mut tokio::sync::watch::Receiver<Option<SocketAddr>>) {
    loop {
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
        if rx.borrow_and_update().is_some() {
            return;
        }
    }
}

/// Whether `s` is a syntactically valid URL scheme per RFC 3986:
/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
#[cfg(feature = "pt")]
fn is_valid_url_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Parse link options from a URL's query parameters.
/// Collect all query parameters that are NOT standard Yggdrasil link options.
/// These are forwarded as PT connection arguments via the SOCKS5 username field.
///
/// Uses raw percent-decoding (not form-encoding) so that `+` characters in
/// base64 cert values are preserved as `+`, not corrupted to spaces.
#[cfg(feature = "pt")]
fn extract_pt_args(url: &Url) -> Vec<(String, String)> {
    const STANDARD_KEYS: &[&str] = &["key", "priority", "password", "maxbackoff", "sni"];
    let query = match url.query() {
        Some(q) => q,
        None => return Vec::new(),
    };
    query.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let key = pct_decode(k);
            let val = pct_decode(v);
            if STANDARD_KEYS.contains(&key.as_str()) { None } else { Some((key, val)) }
        })
        .collect()
}

/// Percent-decode a URL component WITHOUT the form-encoding `+`→space
/// substitution.  Used for PT args where `+` is a valid base64 character.
#[cfg(feature = "pt")]
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hi) = std::str::from_utf8(&bytes[i+1..i+3]) {
                if let Ok(b) = u8::from_str_radix(hi, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_link_options(url: &Url) -> Result<LinkOptions, String> {
    let mut opts = LinkOptions::default();

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "key" => {
                let bytes =
                    hex::decode(value.as_ref()).map_err(|e| format!("invalid key hex: {}", e))?;
                if bytes.len() != 32 {
                    return Err("pinned key must be 32 bytes".to_string());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                opts.pinned_keys.push(arr);
            }
            "priority" => {
                opts.priority = value
                    .parse()
                    .map_err(|e| format!("invalid priority: {}", e))?;
            }
            "password" => {
                if value.len() > 64 {
                    return Err("password too long (max 64 chars)".to_string());
                }
                opts.password = value.as_bytes().to_vec();
            }
            "maxbackoff" => {
                let dur = parse_duration_string(value.as_ref())
                    .map_err(|e| format!("invalid maxbackoff: {}", e))?;
                if dur < MINIMUM_BACKOFF_LIMIT {
                    return Err(format!(
                        "maxbackoff must be at least {} seconds",
                        MINIMUM_BACKOFF_LIMIT.as_secs()
                    ));
                }
                opts.max_backoff = dur;
            }
            "sni" => {
                let sni = value.as_ref();
                // SNI must be a hostname, not an IP address
                if !sni.is_empty() && sni.parse::<std::net::IpAddr>().is_err() {
                    opts.tls_sni = Some(sni.to_string());
                }
            }
            _ => {}
        }
    }

    // If no explicit SNI was set, fall back to URI hostname (if not an IP)
    if opts.tls_sni.is_none() {
        if let Some(host) = url.host_str() {
            if host.parse::<std::net::IpAddr>().is_err() {
                opts.tls_sni = Some(host.to_string());
            }
        }
    }

    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_string_plain_seconds() {
        assert_eq!(parse_duration_string("300").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration_string("0").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration_string("4096").unwrap(), Duration::from_secs(4096));
    }

    #[test]
    fn test_parse_duration_string_units() {
        assert_eq!(parse_duration_string("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration_string("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration_string("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration_string("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration_string("2h30m15s").unwrap(), Duration::from_secs(9015));
    }

    #[test]
    fn test_parse_duration_string_invalid() {
        assert!(parse_duration_string("abc").is_err());
        assert!(parse_duration_string("5x").is_err());
        assert!(parse_duration_string("5m30").is_err()); // trailing number without unit
    }

    #[test]
    fn test_parse_link_options_sni_hostname() {
        let url = Url::parse("tls://example.com:12345?sni=custom.host.com").unwrap();
        let opts = parse_link_options(&url).unwrap();
        assert_eq!(opts.tls_sni, Some("custom.host.com".to_string()));
    }

    #[test]
    fn test_parse_link_options_sni_ip_rejected() {
        let url = Url::parse("tls://example.com:12345?sni=1.2.3.4").unwrap();
        let opts = parse_link_options(&url).unwrap();
        // Explicit IP in sni is rejected, falls back to URI hostname
        assert_eq!(opts.tls_sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_link_options_sni_fallback_to_hostname() {
        let url = Url::parse("tls://peer.example.com:12345").unwrap();
        let opts = parse_link_options(&url).unwrap();
        assert_eq!(opts.tls_sni, Some("peer.example.com".to_string()));
    }

    #[test]
    fn test_parse_link_options_sni_no_fallback_for_ip() {
        let url = Url::parse("tls://192.168.1.1:12345").unwrap();
        let opts = parse_link_options(&url).unwrap();
        assert_eq!(opts.tls_sni, None);
    }

    #[test]
    fn test_parse_link_options_maxbackoff_duration_string() {
        let url = Url::parse("tcp://example.com:12345?maxbackoff=5m").unwrap();
        let opts = parse_link_options(&url).unwrap();
        assert_eq!(opts.max_backoff, Duration::from_secs(300));
    }

    #[test]
    fn test_parse_link_options_maxbackoff_seconds() {
        let url = Url::parse("tcp://example.com:12345?maxbackoff=600").unwrap();
        let opts = parse_link_options(&url).unwrap();
        assert_eq!(opts.max_backoff, Duration::from_secs(600));
    }

    #[test]
    fn test_parse_link_options_maxbackoff_too_small() {
        let url = Url::parse("tcp://example.com:12345?maxbackoff=3s").unwrap();
        assert!(parse_link_options(&url).is_err());
    }
}
