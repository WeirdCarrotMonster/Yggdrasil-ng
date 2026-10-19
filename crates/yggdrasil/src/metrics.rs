use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::address::addr_for_key;
use crate::core::Core;

pub struct MetricsSocket {
    cancel: CancellationToken,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl MetricsSocket {
    pub async fn new(listen_addr: &str, core: Arc<Core>) -> Result<Self, String> {
        if listen_addr.is_empty() || listen_addr == "none" {
            return Ok(Self {
                cancel: CancellationToken::new(),
                handle: None,
            });
        }

        let addr = listen_addr
            .strip_prefix("tcp://")
            .ok_or_else(|| format!("metrics_listen must start with tcp://, got: {}", listen_addr))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("metrics socket bind failed: {}", e))?;

        let actual_addr = listener
            .local_addr()
            .map_err(|e| format!("metrics local_addr: {}", e))?;
        tracing::info!("Metrics endpoint listening on tcp://{}", actual_addr);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let core = core.clone();
                                tokio::spawn(async move {
                                    handle_metrics_conn(stream, core).await;
                                });
                            }
                            Err(e) => {
                                tracing::error!("Metrics accept error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            cancel,
            handle: Some(handle),
        })
    }

    pub fn close(&self) {
        self.cancel.cancel();
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

async fn handle_metrics_conn(mut stream: tokio::net::TcpStream, core: Arc<Core>) {
    // Drain the HTTP request headers (read until \r\n\r\n or connection closes).
    let mut buf = [0u8; 4096];
    let mut header_end = false;
    let mut total = 0usize;
    while !header_end && total < buf.len() {
        match stream.read(&mut buf[total..]).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    header_end = true;
                }
            }
        }
    }

    let body = collect_metrics(&core).await;
    let response = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn collect_metrics(core: &Arc<Core>) -> String {
    let peers = core.get_peers().await;
    let sessions = core.get_sessions().await;
    let debug = core.get_debug_snapshot().await;

    let mut out = String::with_capacity(4096);

    // --- peer metrics: outbound-only, labeled by uri + key ---
    //
    // Inbound peers are excluded: their URIs contain ephemeral ports (unstable
    // across reconnects) and a peer may have multiple simultaneous inbound
    // connections from different source ports, producing duplicate series.
    // Outbound URIs are stable configured addresses; key is included for
    // cross-metric aggregation (e.g. joining with session metrics by key).
    // For down peers key is empty — the connection was never established.

    let outbound: Vec<_> = peers.iter().filter(|p| !p.inbound).collect();
    let outbound_up: Vec<_> = outbound.iter().filter(|p| p.up).collect();

    out.push_str("# HELP yggdrasil_peer_up Whether a configured outbound peer is currently connected (1=up, 0=down)\n");
    out.push_str("# TYPE yggdrasil_peer_up gauge\n");
    for p in &outbound {
        let key = if p.up { hex::encode(p.key) } else { String::new() };
        out.push_str(&format!(
            "yggdrasil_peer_up{{uri=\"{}\",key=\"{}\"}} {}\n",
            p.uri, key, if p.up { 1 } else { 0 }
        ));
    }

    out.push_str("# HELP yggdrasil_peer_bytes_total Cumulative bytes transferred on an outbound peer link\n");
    out.push_str("# TYPE yggdrasil_peer_bytes_total counter\n");
    for p in &outbound_up {
        let key = hex::encode(p.key);
        out.push_str(&format!(
            "yggdrasil_peer_bytes_total{{direction=\"rx\",uri=\"{}\",key=\"{}\"}} {}\n",
            p.uri, key, p.rx_bytes
        ));
        out.push_str(&format!(
            "yggdrasil_peer_bytes_total{{direction=\"tx\",uri=\"{}\",key=\"{}\"}} {}\n",
            p.uri, key, p.tx_bytes
        ));
    }

    out.push_str("# HELP yggdrasil_peer_rate_bytes_per_second Current transfer rate on an outbound peer link\n");
    out.push_str("# TYPE yggdrasil_peer_rate_bytes_per_second gauge\n");
    for p in &outbound_up {
        let key = hex::encode(p.key);
        out.push_str(&format!(
            "yggdrasil_peer_rate_bytes_per_second{{direction=\"rx\",uri=\"{}\",key=\"{}\"}} {}\n",
            p.uri, key, p.rx_rate
        ));
        out.push_str(&format!(
            "yggdrasil_peer_rate_bytes_per_second{{direction=\"tx\",uri=\"{}\",key=\"{}\"}} {}\n",
            p.uri, key, p.tx_rate
        ));
    }

    out.push_str("# HELP yggdrasil_peer_uptime_seconds Seconds since the outbound peer link was established\n");
    out.push_str("# TYPE yggdrasil_peer_uptime_seconds gauge\n");
    for p in &outbound_up {
        let key = hex::encode(p.key);
        out.push_str(&format!(
            "yggdrasil_peer_uptime_seconds{{uri=\"{}\",key=\"{}\"}} {:.3}\n",
            p.uri, key, p.uptime_secs
        ));
    }

    out.push_str("# HELP yggdrasil_peer_latency_ms Measured RTT latency to outbound peer in milliseconds\n");
    out.push_str("# TYPE yggdrasil_peer_latency_ms gauge\n");
    for p in &outbound_up {
        let key = hex::encode(p.key);
        out.push_str(&format!(
            "yggdrasil_peer_latency_ms{{uri=\"{}\",key=\"{}\"}} {:.3}\n",
            p.uri, key, p.latency_ms
        ));
    }

    // --- session metrics: labeled by key ---
    out.push_str("# HELP yggdrasil_session_bytes_total Cumulative bytes transferred in an encrypted session\n");
    out.push_str("# TYPE yggdrasil_session_bytes_total counter\n");
    for s in &sessions {
        let key = hex::encode(s.key);
        let addr = addr_for_key(&s.key).to_string();
        out.push_str(&format!(
            "yggdrasil_session_bytes_total{{direction=\"rx\",key=\"{}\",address=\"{}\"}} {}\n",
            key, addr, s.bytes_recvd
        ));
        out.push_str(&format!(
            "yggdrasil_session_bytes_total{{direction=\"tx\",key=\"{}\",address=\"{}\"}} {}\n",
            key, addr, s.bytes_sent
        ));
    }

    out.push_str("# HELP yggdrasil_session_uptime_seconds Seconds since the encrypted session was established\n");
    out.push_str("# TYPE yggdrasil_session_uptime_seconds gauge\n");
    for s in &sessions {
        let key = hex::encode(s.key);
        let addr = addr_for_key(&s.key).to_string();
        out.push_str(&format!(
            "yggdrasil_session_uptime_seconds{{key=\"{}\",address=\"{}\"}} {:.3}\n",
            key, addr, s.uptime_seconds
        ));
    }

    out.push_str("# HELP yggdrasil_session_count Number of active encrypted sessions\n");
    out.push_str("# TYPE yggdrasil_session_count gauge\n");
    out.push_str(&format!("yggdrasil_session_count {}\n", sessions.len()));

    // --- routing / tree metrics ---
    out.push_str("# HELP yggdrasil_routing_entries Number of peers known to the routing layer\n");
    out.push_str("# TYPE yggdrasil_routing_entries gauge\n");
    out.push_str(&format!("yggdrasil_routing_entries {}\n", debug.routing_peer_count));

    out.push_str("# HELP yggdrasil_tree_node_count Number of nodes known in the spanning tree\n");
    out.push_str("# TYPE yggdrasil_tree_node_count gauge\n");
    out.push_str(&format!("yggdrasil_tree_node_count {}\n", debug.tree_node_count));

    out.push_str("# HELP yggdrasil_path_cache_count Number of cached paths to remote nodes\n");
    out.push_str("# TYPE yggdrasil_path_cache_count gauge\n");
    out.push_str(&format!("yggdrasil_path_cache_count {}\n", debug.path_cache_count));

    out.push_str("# HELP yggdrasil_delivery_queue_bytes Bytes currently buffered in the packet delivery queue\n");
    out.push_str("# TYPE yggdrasil_delivery_queue_bytes gauge\n");
    out.push_str(&format!("yggdrasil_delivery_queue_bytes {}\n", debug.delivery_queue_bytes));

    out
}
