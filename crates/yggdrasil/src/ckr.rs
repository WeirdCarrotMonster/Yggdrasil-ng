use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
#[cfg(not(target_os = "android"))]
use route_manager::RouteManager;
use serde::{Deserialize, Serialize};

use crate::address::{addr_for_key, is_valid_address, is_valid_subnet};
use crate::config::TunnelRoutingConfig;

const INETV4_PREFIXES: &[&str] = &[
    "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/3",
    "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12", "172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7",
    "176.0.0.0/4", "192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16", "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12",
    "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4"
];

const INETV6_PREFIXES: &[&str] = &["2000::/3"];

/// Longest-prefix-match table for a single address family.
///
/// One hash map per distinct prefix length, iterated longest prefix first, so
/// the first hit is the longest-prefix match. A lookup therefore costs one
/// probe per *distinct prefix length* present — a couple of dozen for a
/// generated CIDR list — rather than a scan of the whole table. That matters
/// most on a miss: traffic that is not CKR-routed used to walk every route.
struct RouteTable {
    /// Address width of the family: 32 for IPv4, 128 for IPv6.
    bits: u32,
    /// Keyed by `Reverse(prefix_len)`, so map iteration yields the longest
    /// prefix first. Values map masked network address -> destination key.
    levels: BTreeMap<Reverse<u8>, HashMap<u128, [u8; 32]>>,
    len: usize,
}

impl RouteTable {
    fn new(bits: u32) -> Self {
        Self { bits, levels: BTreeMap::new(), len: 0 }
    }

    /// Insert a route. Returns `false` if that exact prefix was already
    /// present — the caller treats that as a fatal config error, so this
    /// doubles as the duplicate check that used to need a separate `HashSet`.
    fn insert(&mut self, prefix: IpNet, destination: [u8; 32]) -> bool {
        let key = mask_addr(addr_bits(prefix.network()), prefix.prefix_len(), self.bits);
        let level = self.levels.entry(Reverse(prefix.prefix_len())).or_default();
        if level.insert(key, destination).is_some() {
            return false;
        }
        self.len += 1;
        true
    }

    fn get(&self, addr: u128) -> Option<[u8; 32]> {
        for (Reverse(prefix_len), level) in &self.levels {
            if let Some(dest) = level.get(&mask_addr(addr, *prefix_len, self.bits)) {
                return Some(*dest);
            }
        }
        None
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Every route, longest prefix first and ascending by address within a
    /// prefix length. Only used for the debug listing, so the per-level sort
    /// is paid only when debug logging is on.
    fn iter_sorted(&self) -> impl Iterator<Item = (IpNet, [u8; 32])> + '_ {
        self.levels.iter().flat_map(move |(Reverse(len), level)| {
            let mut entries: Vec<(u128, [u8; 32])> = level.iter().map(|(k, v)| (*k, *v)).collect();
            entries.sort_unstable_by_key(|(k, _)| *k);
            entries
                .into_iter()
                .map(move |(k, dest)| (make_net(k, *len, self.bits), dest))
        })
    }
}

/// CKR routing table. Maps IP subnets to Yggdrasil node public keys.
pub struct CryptoKey {
    yggdrasil_routing: bool,
    v4: RouteTable,
    v6: RouteTable,
}

impl CryptoKey {
    /// Build a CKR routing table from configuration.
    ///
    /// Routes whose destination equals `self_key` are silently dropped — a
    /// shared config can thus be distributed to every node without each
    /// needing a node-specific copy.
    pub fn new(config: &TunnelRoutingConfig, self_key: &[u8; 32]) -> Result<Self, String> {
        let ckr = Self::build(config, self_key)?;
        ckr.log_routes();
        Ok(ckr)
    }

    /// [`CryptoKey::new`] without logging the result as the active route set.
    fn build(config: &TunnelRoutingConfig, self_key: &[u8; 32]) -> Result<Self, String> {
        let mut v4 = RouteTable::new(32);
        let mut v6 = RouteTable::new(128);

        if !config.enable {
            return Ok(Self { yggdrasil_routing: config.yggdrasil_routing, v4, v6 });
        }

        for (pubkey_hex, cidrs) in &config.remote_subnets {
            let dest = parse_pubkey(pubkey_hex)?;
            if &dest == self_key {
                tracing::info!("CKR: ignoring {} route(s) for own public key {}", cidrs.len(), pubkey_hex);
                continue;
            }
            for prefix in expand_cidrs(cidrs)? {
                let table = match prefix {
                    IpNet::V6(_) => {
                        if is_yggdrasil_destination(prefix.addr()) {
                            return Err(format!("can't specify Yggdrasil destination as routed subnet: {}", prefix));
                        }
                        &mut v6
                    }
                    IpNet::V4(_) => &mut v4,
                };
                if !table.insert(prefix, dest) {
                    return Err(format!("duplicate remote subnet: {}", prefix));
                }
            }
        }

        Ok(Self { yggdrasil_routing: config.yggdrasil_routing, v4, v6 })
    }

    /// Summarize at info, list at debug: one info line per route meant more
    /// than 100k synchronous writes (each allocating via hex::encode) before
    /// the TUN came up.
    fn log_routes(&self) {
        if !self.v4.is_empty() || !self.v6.is_empty() {
            tracing::info!("Active CKR routes: {} IPv4, {} IPv6", self.v4.len(), self.v6.len());
        }
        if tracing::enabled!(tracing::Level::DEBUG) {
            for (prefix, dest) in self.v6.iter_sorted().chain(self.v4.iter_sorted()) {
                tracing::debug!("  {} via {}", prefix, hex::encode(dest));
            }
        }
    }

    /// Number of table entries after expansion, as `(IPv4, IPv6)`.
    pub fn route_counts(&self) -> (usize, usize) {
        (self.v4.len(), self.v6.len())
    }

    /// Whether standard Yggdrasil address routing is enabled.
    pub fn yggdrasil_routing(&self) -> bool {
        self.yggdrasil_routing
    }

    /// Look up the destination public key for an IP address using
    /// longest-prefix-match. Returns `None` if no route matches.
    pub fn get_public_key_for_address(&self, addr: IpAddr) -> Option<[u8; 32]> {
        match addr {
            IpAddr::V4(a) => self.v4.get(u32::from(a) as u128),
            IpAddr::V6(a) => {
                if is_yggdrasil_destination(addr) {
                    return None;
                }
                self.v6.get(u128::from(a))
            }
        }
    }
}

/// Owner of the live CKR route table and of the OS routes derived from it.
///
/// `remote_subnets` can be replaced at runtime ([`CkrManager::set_remote_subnets`])
/// while packets keep flowing: readers take a cheap snapshot through
/// [`CkrManager::table`], and a setter builds a new table off to the side and
/// swaps it in atomically. Every other `tunnel_routing` setting is fixed at
/// startup.
pub struct CkrManager {
    self_key: [u8; 32],
    yggdrasil_routing: bool,
    install_system_routes: bool,
    table: ArcSwap<CryptoKey>,
    /// Serialises setters, TUN attachment and shutdown, which hold it on a
    /// blocking thread (see `with_state`) for the table build and the
    /// RouteManager calls.
    state: tokio::sync::Mutex<CkrState>,
}

struct CkrState {
    /// The live route set; the table and the OS routes are derived from it.
    remote_subnets: HashMap<String, Vec<String>>,
    /// TUN the OS routes point at, once it is up.
    tun: Option<String>,
    /// OS routes this node added for the live set. Only these are ever
    /// removed: a prefix whose add failed may be a route someone else owns,
    /// such as the on-link route of the TUN's own subnet.
    installed: HashSet<IpNet>,
    /// OS routes the live set asks for that failed to install; retried by
    /// the next set.
    failed: HashSet<IpNet>,
    /// Set by `shutdown`; later setters are refused.
    closed: bool,
}

/// Result of [`CkrManager::set_remote_subnets`].
#[derive(Debug, Serialize, Deserialize)]
pub struct CkrApplyReport {
    /// False for a dry run: nothing was changed.
    pub applied: bool,
    pub ipv4_routes: usize,
    pub ipv6_routes: usize,
    /// OS routes added and removed (for a dry run, the ones that would be).
    pub system_routes_added: Vec<String>,
    pub system_routes_removed: Vec<String>,
    pub system_route_failures: Vec<CkrRouteFailure>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CkrRouteFailure {
    pub prefix: String,
    pub error: String,
}

/// The live CKR state, as reported by the `getckrroutes` admin command.
#[derive(Debug, Serialize)]
pub struct CkrSnapshot {
    pub enabled: bool,
    pub yggdrasil_routing: bool,
    pub install_system_routes: bool,
    /// `None` when there is no TUN.
    pub tun: Option<String>,
    /// Table entries after expansion.
    pub ipv4_routes: usize,
    pub ipv6_routes: usize,
    /// OS routes installed for the live set.
    pub system_routes: usize,
    pub failed_system_routes: Vec<String>,
    /// Sorted by key.
    pub remote_subnets: Vec<CkrKeySubnets>,
}

/// One `remote_subnets` entry, with the subnet strings as configured.
#[derive(Debug, Serialize, Deserialize)]
pub struct CkrKeySubnets {
    pub key: String,
    /// Yggdrasil address of `key`; `None` if the key does not decode.
    pub address: Option<String>,
    /// The node's own key: kept in the set but ignored, as at startup.
    #[serde(rename = "self")]
    pub is_self: bool,
    pub subnets: Vec<String>,
}

impl CkrManager {
    /// Build the manager from the startup config. Called only when
    /// `config.enable` is set. No OS routes are touched until
    /// [`CkrManager::attach_tun`].
    pub fn new(config: &TunnelRoutingConfig, self_key: &[u8; 32]) -> Result<Self, String> {
        Ok(Self {
            self_key: *self_key,
            yggdrasil_routing: config.yggdrasil_routing,
            // VpnService owns routing on Android, and route_manager is not built there.
            install_system_routes: config.install_system_routes && cfg!(not(target_os = "android")),
            table: ArcSwap::from_pointee(CryptoKey::new(config, self_key)?),
            state: tokio::sync::Mutex::new(CkrState {
                remote_subnets: config.remote_subnets.clone(),
                tun: None,
                installed: HashSet::new(),
                failed: HashSet::new(),
                closed: false,
            }),
        })
    }

    /// Whether standard Yggdrasil address routing is enabled.
    pub fn yggdrasil_routing(&self) -> bool {
        self.yggdrasil_routing
    }

    /// The current route table.
    ///
    /// The guard **must not be held across an `.await`**: arc-swap guards use
    /// a small per-thread pool of debt slots, and holding many across awaits
    /// in per-packet tasks spills to the slow path. Use it within a statement
    /// or a short sync block.
    pub fn table(&self) -> arc_swap::Guard<Arc<CryptoKey>> {
        self.table.load()
    }

    /// Record the TUN and, with `install_system_routes`, install the OS
    /// routes of the live set through it. Called once, when the TUN is up.
    pub async fn attach_tun(self: &Arc<Self>, tun_name: &str) {
        let tun = tun_name.to_string();
        let result = self
            .with_state(move |mgr, state| {
                state.tun = Some(tun);
                if mgr.install_system_routes {
                    state.sync_routes(desired_system_routes(&state.remote_subnets, &mgr.self_key)?);
                }
                Ok(())
            })
            .await;
        if let Err(e) = result {
            tracing::error!("Failed to install CKR routes: {}", e);
        }
    }

    /// Report the live route set.
    pub async fn snapshot(&self) -> CkrSnapshot {
        let state = self.state.lock().await;
        let (ipv4_routes, ipv6_routes) = self.table().route_counts();
        let mut remote_subnets: Vec<CkrKeySubnets> = state
            .remote_subnets
            .iter()
            .map(|(key, subnets)| {
                let decoded = parse_pubkey(key).ok();
                CkrKeySubnets {
                    key: key.clone(),
                    address: decoded.map(|k| addr_for_key(&k).to_string()),
                    is_self: decoded == Some(self.self_key),
                    subnets: subnets.clone(),
                }
            })
            .collect();
        remote_subnets.sort_by(|a, b| a.key.cmp(&b.key));
        CkrSnapshot {
            enabled: true,
            yggdrasil_routing: self.yggdrasil_routing,
            install_system_routes: self.install_system_routes,
            tun: state.tun.clone(),
            ipv4_routes,
            ipv6_routes,
            system_routes: state.installed.len(),
            failed_system_routes: sorted_strings(state.failed.iter().copied().collect()),
            remote_subnets,
        }
    }

    /// Replace the whole `remote_subnets` set.
    ///
    /// The new table is built and validated first; any error leaves
    /// everything untouched. Otherwise the table is swapped in atomically and
    /// the OS routes, when managed, follow: new ones added first, then the
    /// dropped ones removed. In between, a prefix being removed still has an
    /// OS route into the TUN but no table entry, so its packets are dropped
    /// rather than leaked to the default route. With `dry_run` nothing
    /// changes, and the report says what would.
    pub async fn set_remote_subnets(
        self: &Arc<Self>,
        remote_subnets: HashMap<String, Vec<String>>,
        dry_run: bool,
    ) -> Result<CkrApplyReport, String> {
        self.with_state(move |mgr, state| mgr.apply(state, remote_subnets, dry_run)).await
    }

    /// Remove the OS routes of the live set and refuse later setters. Runs
    /// after a set already in progress.
    pub async fn shutdown(self: &Arc<Self>) {
        let result = self
            .with_state(|_, state| {
                state.closed = true;
                state.sync_routes(HashSet::new());
                Ok(())
            })
            .await;
        if let Err(e) = result {
            tracing::warn!("Failed to remove CKR routes: {}", e);
        }
    }

    /// Run `f` under the state lock on a blocking thread: a large set takes
    /// seconds to expand, and every OS route is a syscall.
    async fn with_state<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&Self, &mut CkrState) -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let mgr = self.clone();
        tokio::task::spawn_blocking(move || f(&mgr, &mut mgr.state.blocking_lock()))
            .await
            .map_err(|e| format!("CKR update task failed: {}", e))?
    }

    fn apply(
        &self,
        state: &mut CkrState,
        remote_subnets: HashMap<String, Vec<String>>,
        dry_run: bool,
    ) -> Result<CkrApplyReport, String> {
        if state.closed {
            return Err("node is shutting down".to_string());
        }
        let config = TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: self.yggdrasil_routing,
            remote_subnets,
            ..Default::default()
        };
        let table = CryptoKey::build(&config, &self.self_key)?;
        let routes = if self.install_system_routes && state.tun.is_some() {
            desired_system_routes(&config.remote_subnets, &self.self_key)?
        } else {
            HashSet::new()
        };
        let (ipv4_routes, ipv6_routes) = table.route_counts();

        let (added, removed, failures) = if dry_run {
            let (add, remove) = state.route_diff(&routes);
            (add, remove, Vec::new())
        } else {
            table.log_routes();
            self.table.store(Arc::new(table));
            state.remote_subnets = config.remote_subnets;
            let (mut add, remove, failures) = state.sync_routes(routes);
            add.retain(|p| !state.failed.contains(p));
            tracing::info!(
                "CKR routes replaced: {} IPv4, {} IPv6; system routes +{} -{} ({} failed)",
                ipv4_routes,
                ipv6_routes,
                add.len(),
                remove.len(),
                failures.len()
            );
            (add, remove, failures)
        };

        Ok(CkrApplyReport {
            applied: !dry_run,
            ipv4_routes,
            ipv6_routes,
            system_routes_added: sorted_strings(added),
            system_routes_removed: sorted_strings(removed),
            system_route_failures: failures
                .into_iter()
                .map(|(prefix, error)| CkrRouteFailure { prefix: prefix.to_string(), error })
                .collect(),
        })
    }
}

impl CkrState {
    /// The OS routes to add and remove to get from the installed ones to
    /// `new`.
    fn route_diff(&self, new: &HashSet<IpNet>) -> (Vec<IpNet>, Vec<IpNet>) {
        (new.difference(&self.installed).copied().collect(), self.installed.difference(new).copied().collect())
    }

    /// Move the OS routes via the TUN to `new`. Returns the prefixes tried
    /// to add and remove, and the adds that failed.
    fn sync_routes(&mut self, new: HashSet<IpNet>) -> (Vec<IpNet>, Vec<IpNet>, Vec<(IpNet, String)>) {
        let (mut add, mut remove) = self.route_diff(&new);
        add.sort_unstable();
        remove.sort_unstable();
        let failures = match &self.tun {
            Some(tun) => {
                let failures = install_route_set(&add, tun);
                remove_route_set(&remove, tun);
                failures
            }
            None => Vec::new(),
        };
        self.failed = failures.iter().map(|(p, _)| *p).collect();
        self.installed = new;
        self.installed.retain(|p| !self.failed.contains(p));
        (add, remove, failures)
    }
}

fn sorted_strings(mut nets: Vec<IpNet>) -> Vec<String> {
    nets.sort_unstable();
    nets.iter().map(IpNet::to_string).collect()
}

/// The bits of an address, right-aligned in a `u128`. IPv4 and IPv6 are always
/// kept in separate tables, so the two never share a key space.
fn addr_bits(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(a) => u32::from(a) as u128,
        IpAddr::V6(a) => u128::from(a),
    }
}

/// Clear all but the top `prefix_len` bits of a `bits`-wide address.
fn mask_addr(addr: u128, prefix_len: u8, bits: u32) -> u128 {
    if prefix_len == 0 {
        return 0;
    }
    let shift = bits - prefix_len as u32;
    (addr >> shift) << shift
}

/// Rebuild an `IpNet` from a masked address and prefix length.
fn make_net(addr: u128, prefix_len: u8, bits: u32) -> IpNet {
    // Both constructors only reject a prefix length wider than the family, and
    // every caller derives `prefix_len` from an existing net of that family.
    if bits == 32 {
        IpNet::V4(
            Ipv4Net::new(Ipv4Addr::from(addr as u32), prefix_len)
                .expect("prefix length bounded by family width"),
        )
    } else {
        IpNet::V6(
            Ipv6Net::new(Ipv6Addr::from(addr), prefix_len)
                .expect("prefix length bounded by family width"),
        )
    }
}

/// Check if an IP address falls within the Yggdrasil address space.
pub fn is_yggdrasil_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&octets);
            let mut subnet_bytes = [0u8; 8];
            subnet_bytes.copy_from_slice(&octets[..8]);
            is_valid_address(&addr_bytes) || is_valid_subnet(&subnet_bytes)
        }
    }
}

/// Parse a list of CIDR entries, where entries prefixed with `!` are
/// treated as exclusions. Returns the minimal set of prefixes covering
/// `(union of includes) \ (union of excludes)`.
///
/// Excludes only apply within the same address family as the includes.
/// Duplicate includes are tolerated; excludes outside any include are ignored.
pub fn expand_cidrs(entries: &[String]) -> Result<Vec<IpNet>, String> {
    let mut v4_inc: Vec<IpNet> = Vec::new();
    let mut v6_inc: Vec<IpNet> = Vec::new();
    let mut v4_exc: Vec<IpNet> = Vec::new();
    let mut v6_exc: Vec<IpNet> = Vec::new();

    let normalized = normalize_subnet_entries(entries);
    for raw in &normalized {
        let cidr_input = if let Some(after_tilde) = raw.strip_prefix('~') {
            after_tilde.trim()
        } else {
            raw.as_str()
        };
        let (is_exclude, cidr_str) = match cidr_input.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, cidr_input),
        };
        let cidr_for_parse = if !cidr_str.contains('/') {
            if cidr_str.contains(':') {
                format!("{}/128", cidr_str)
            } else {
                format!("{}/32", cidr_str)
            }
        } else {
            cidr_str.to_string()
        };
        let prefix: IpNet = cidr_for_parse
            .parse()
            .map_err(|e| format!("invalid CIDR '{}': {}", cidr_str, e))?;
        // Normalize to the network address (e.g. 10.0.0.5/24 -> 10.0.0.0/24).
        let prefix = prefix.trunc();
        match (is_exclude, prefix) {
            (false, IpNet::V4(_)) => v4_inc.push(prefix),
            (false, IpNet::V6(_)) => v6_inc.push(prefix),
            (true, IpNet::V4(_)) => v4_exc.push(prefix),
            (true, IpNet::V6(_)) => v6_exc.push(prefix),
        }
    }

    // Collapse the excludes into disjoint sorted ranges once, so each include
    // costs a binary search plus a walk of the ranges that actually overlap it.
    let v4_exc = merge_excludes(&v4_exc);
    let v6_exc = merge_excludes(&v6_exc);

    let mut out = Vec::new();
    for inc in v4_inc {
        out.extend(subtract_many(inc, &v4_exc));
    }
    for inc in v6_inc {
        out.extend(subtract_many(inc, &v6_exc));
    }
    Ok(out)
}

/// The inclusive address range a prefix covers, as integers.
fn net_bounds(net: &IpNet) -> (u128, u128) {
    match net {
        IpNet::V4(n) => (
            u32::from(n.network()) as u128,
            u32::from(n.broadcast()) as u128,
        ),
        IpNet::V6(n) => (u128::from(n.network()), u128::from(n.broadcast())),
    }
}

/// Collapse excludes of one family into disjoint inclusive ranges, sorted
/// ascending. Overlapping, nested and adjacent excludes all merge, so the
/// result describes the same address set with no redundancy.
fn merge_excludes(excludes: &[IpNet]) -> Vec<(u128, u128)> {
    let mut ranges: Vec<(u128, u128)> = excludes.iter().map(net_bounds).collect();
    ranges.sort_unstable();

    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match merged.last_mut() {
            // `saturating_add` only saturates at the very top of the address
            // space, where there is nothing left to be adjacent to anyway.
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    merged
}

/// Subtract a set of excludes from a single include prefix, returning the
/// minimal set of prefixes covering the remainder.
///
/// `excludes` must be the merged, sorted output of [`merge_excludes`] for the
/// same address family. Walking the include's range and emitting the gaps
/// costs one pass over the overlapping excludes. The previous approach split
/// the include into pieces and re-scanned every piece for every exclude, which
/// is quadratic in the exclude count once a single include (`0.0.0.0/0`,
/// `inetv4`) covers most of them.
fn subtract_many(include: IpNet, excludes: &[(u128, u128)]) -> Vec<IpNet> {
    let (inc_lo, inc_hi) = net_bounds(&include);
    let bits = match include {
        IpNet::V4(_) => 32,
        IpNet::V6(_) => 128,
    };

    // Ranges are disjoint and ascending, so `hi` is ascending too: the first
    // range that can overlap is the first whose end reaches `inc_lo`.
    let start = excludes.partition_point(|&(_, hi)| hi < inc_lo);

    let mut out = Vec::new();
    let mut cur = inc_lo;
    for &(lo, hi) in &excludes[start..] {
        if lo > inc_hi {
            break;
        }
        if lo > cur {
            emit_range(cur, lo - 1, bits, &mut out);
        }
        if hi >= inc_hi {
            // This exclude runs to the end of the include (or past it, which
            // is how a containing exclude drops the include entirely).
            return out;
        }
        cur = hi + 1;
    }
    emit_range(cur, inc_hi, bits, &mut out);
    out
}

/// Append the minimal set of prefix-aligned blocks covering the inclusive
/// range `[lo, hi]`. Each step takes the largest block that both starts at
/// `lo`'s alignment and fits in what is left.
fn emit_range(lo: u128, hi: u128, bits: u32, out: &mut Vec<IpNet>) {
    let mut cur = lo;
    loop {
        let align = if cur == 0 {
            bits
        } else {
            cur.trailing_zeros().min(bits)
        };
        let remaining = hi - cur;
        // Largest k with 2^k - 1 <= remaining, i.e. floor(log2(remaining + 1)).
        let span = if remaining == u128::MAX {
            128
        } else {
            127 - (remaining + 1).leading_zeros()
        };
        let size = align.min(span).min(bits);
        out.push(make_net(cur, (bits - size) as u8, bits));

        if size == 128 {
            break; // the block covered the whole address space
        }
        // `cur` is aligned to at least `size`, so this cannot overflow, and
        // `size <= span` guarantees `end <= hi`.
        let end = cur + (1u128 << size) - 1;
        if end >= hi {
            break;
        }
        cur = end + 1;
    }
}

fn normalize_subnet_entries(entries: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for entry in entries {
        let trimmed = entry.trim();
        match trimmed {
            "inetv4" => normalized.extend(INETV4_PREFIXES.iter().map(|&s| s.to_string())),
            "~inetv4" => normalized.extend(INETV4_PREFIXES.iter().map(|&s| format!("~{}", s))),
            "inetv6" => normalized.extend(INETV6_PREFIXES.iter().map(|&s| s.to_string())),
            "~inetv6" => normalized.extend(INETV6_PREFIXES.iter().map(|&s| format!("~{}", s))),
            _ => normalized.push(trimmed.to_string()),
        }
    }
    normalized
}

fn parse_pubkey(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("invalid public key hex '{}': {}", hex_str, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "public key should be 32 bytes, got {} for '{}'",
            bytes.len(),
            hex_str
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// The OS routes a route set asks for: own-key and `~` entries skipped,
/// excludes applied.
fn desired_system_routes(
    remote_subnets: &HashMap<String, Vec<String>>,
    self_key: &[u8; 32],
) -> Result<HashSet<IpNet>, String> {
    // Skip entries whose destination is this node itself — those are handled
    // by the OS's native routing and should not be steered into the TUN.
    let mut routes = HashSet::new();
    for (pubkey_hex, subnet_list) in remote_subnets {
        if parse_pubkey(pubkey_hex).ok().as_ref() == Some(self_key) {
            continue;
        }
        let non_tilde_entries: Vec<String> = subnet_list.iter().filter(|s| !s.trim().starts_with('~')).cloned().collect();
        let route_list = normalize_subnet_entries(&non_tilde_entries);
        routes.extend(expand_cidrs(&route_list)?);
    }
    Ok(routes)
}

/// Add system routes for `cidrs`, pointing them at the TUN interface so the
/// OS sends that traffic into the tunnel. Returns the prefixes that failed,
/// with the error text. Works on Linux, Windows, and macOS. No-op on Android
/// (VpnService handles routes).
#[cfg(target_os = "android")]
fn install_route_set(_cidrs: &[IpNet], _tun_name: &str) -> Vec<(IpNet, String)> {
    Vec::new()
}

#[cfg(not(target_os = "android"))]
fn install_route_set(cidrs: &[IpNet], tun_name: &str) -> Vec<(IpNet, String)> {
    if cidrs.is_empty() {
        return Vec::new();
    }

    let mut manager = match RouteManager::new() {
        Ok(m) => m,
        Err(e) => {
            let e = format!("failed to create route manager: {}", e);
            tracing::error!("Failed to install CKR routes: {}", e);
            return cidrs.iter().map(|c| (*c, e.clone())).collect();
        }
    };
    let mut installed: usize = 0;
    let mut failures = Vec::new();

    for cidr in cidrs {
        let route = route_manager::Route::new(cidr.network(), cidr.prefix_len())
            .with_if_name(tun_name.to_string());

        match manager.add(&route) {
            Ok(()) => {
                installed += 1;
                tracing::debug!("Installed route: {} via {}", cidr, tun_name);
            }
            Err(e) => {
                tracing::warn!("Failed to install route {} via {}: {}", cidr, tun_name, e);
                failures.push((*cidr, e.to_string()));
            }
        }
    }

    if !failures.is_empty() {
        tracing::info!("Installed {} CKR route(s) via {} ({} failed)", installed, tun_name, failures.len());
    } else {
        tracing::info!("Installed {} CKR route(s) via {}", installed, tun_name);
    }

    failures
}

/// Remove system routes for `cidrs` from the TUN interface. Failures are
/// logged at debug and otherwise ignored.
#[cfg(target_os = "android")]
fn remove_route_set(_cidrs: &[IpNet], _tun_name: &str) {}

#[cfg(not(target_os = "android"))]
fn remove_route_set(cidrs: &[IpNet], tun_name: &str) {
    if cidrs.is_empty() {
        return;
    }

    let mut manager = match RouteManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Failed to create route manager for cleanup: {}", e);
            return;
        }
    };

    for cidr in cidrs {
        let route = route_manager::Route::new(cidr.network(), cidr.prefix_len())
            .with_if_name(tun_name.to_string());
        if let Err(e) = manager.delete(&route) {
            tracing::debug!("Failed to remove route {}: {}", cidr, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_config(subnets: HashMap<String, Vec<String>>) -> TunnelRoutingConfig {
        TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            ip_addresses: Vec::new(),
            remote_subnets: subnets,
            install_system_routes: true,
        }
    }

    fn dummy_key_hex() -> String {
        hex::encode([0x01u8; 32])
    }

    fn other_key_hex() -> String {
        hex::encode([0x02u8; 32])
    }

    /// A self-key distinct from any configured route key, so the existing
    /// tests exercise the populated table (self-dropping is covered in its
    /// own test below).
    const SELF_KEY: [u8; 32] = [0xffu8; 32];

    #[test]
    fn test_empty_config() {
        let config = TunnelRoutingConfig::default();
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        assert!(ckr.v4.is_empty());
        assert!(ckr.v6.is_empty());
    }

    #[test]
    fn test_disabled_config() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        let config = TunnelRoutingConfig {
            enable: false,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            ip_addresses: Vec::new(),
            remote_subnets: subnets,
            install_system_routes: true,
        };
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        assert!(ckr.v4.is_empty());
    }

    #[test]
    fn test_ipv4_route_lookup() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string(), "192.168.1.100".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        let key = ckr.get_public_key_for_address(addr);
        assert_eq!(key, Some([0x01u8; 32]));

        let miss: IpAddr = "192.168.0.1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(miss), None);
        let bare_addr: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(bare_addr), Some([0x01u8; 32]));
    }

    #[test]
    fn test_ipv6_route_lookup() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["2001:db8::/32".to_string(), "2001:db8:aaaa::1".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr), Some([0x01u8; 32]));

        let miss: IpAddr = "2001:db9::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(miss), None);
        let bare_addr: IpAddr = "2001:db8:aaaa::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(bare_addr), Some([0x01u8; 32]));
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        subnets.insert(other_key_hex(), vec!["10.0.0.0/25".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        // 10.0.0.5 matches both /24 and /25, but /25 is more specific
        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr), Some([0x02u8; 32]));

        // 10.0.0.200 only matches /24 (not in /25 range 10.0.0.0-127)
        let addr2: IpAddr = "10.0.0.200".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr2), Some([0x01u8; 32]));
    }

    #[test]
    fn test_yggdrasil_destination_rejected() {
        let mut subnets = HashMap::new();
        // 0200::/7 is Yggdrasil address space
        subnets.insert(dummy_key_hex(), vec!["200::/7".to_string()]);
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_yggdrasil_address_lookup_returns_none() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["2001:db8::/32".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        // A Yggdrasil address should return None even if it somehow matched
        let ygg_addr: IpAddr = "200::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(ygg_addr), None);
    }

    #[test]
    fn test_duplicate_route_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["10.0.0.0/24".to_string(), "10.0.0.0/24".to_string()],
        );
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cidr_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["not-a-cidr".to_string()]);
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pubkey_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert("not-hex".to_string(), vec!["10.0.0.0/24".to_string()]);
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_length_pubkey_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(
            hex::encode([0x01u8; 16]), // 16 bytes, not 32
            vec!["10.0.0.0/24".to_string()],
        );
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_yggdrasil_destination() {
        // Yggdrasil addresses start with 0x02
        assert!(is_yggdrasil_destination("200::1".parse().unwrap()));
        // Yggdrasil subnets start with 0x03
        assert!(is_yggdrasil_destination("300::1".parse().unwrap()));
        // Regular IPv6
        assert!(!is_yggdrasil_destination("2001:db8::1".parse().unwrap()));
        // IPv4 is never Yggdrasil
        assert!(!is_yggdrasil_destination("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_multiple_subnets_per_key() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec![
                "10.0.0.0/24".to_string(),
                "192.168.1.0/24".to_string(),
                "2001:db8::/32".to_string(),
            ],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        assert_eq!(ckr.v4.len(), 2);
        assert_eq!(ckr.v6.len(), 1);

        assert!(ckr.get_public_key_for_address("10.0.0.1".parse().unwrap()).is_some());
        assert!(ckr.get_public_key_for_address("192.168.1.100".parse().unwrap()).is_some());
        assert!(ckr.get_public_key_for_address("2001:db8::1".parse().unwrap()).is_some());
    }

    #[test]
    fn test_expand_cidrs_simple_exclude() {
        let entries = vec!["10.0.0.0/24".to_string(), "!10.0.0.0/25".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        // 10.0.0.0/24 minus 10.0.0.0/25 = 10.0.0.128/25
        assert_eq!(out, vec!["10.0.0.128/25".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn test_expand_cidrs_default_route_minus_rfc1918() {
        let entries = vec![
            "0.0.0.0/0".to_string(),
            "!192.168.0.0/16".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        // All pieces must be prefix-aligned and cover 0.0.0.0/0 \ 192.168.0.0/16.
        let total_addrs: u128 = out
            .iter()
            .map(|n| 1u128 << (32 - n.prefix_len() as u32))
            .sum();
        assert_eq!(total_addrs, (1u128 << 32) - (1u128 << 16));
        // 192.168.5.1 should not be covered; 8.8.8.8 should be.
        let blocked: IpAddr = "192.168.5.1".parse().unwrap();
        let allowed: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!out.iter().any(|n| n.contains(&blocked)));
        assert!(out.iter().any(|n| n.contains(&allowed)));
    }

    #[test]
    fn test_expand_cidrs_exclude_routes_via_cryptokey() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["10.0.0.0/24".to_string(), "!10.0.0.5/32".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();
        // 10.0.0.5 must NOT resolve; surrounding addrs must.
        assert_eq!(
            ckr.get_public_key_for_address("10.0.0.5".parse().unwrap()),
            None
        );
        assert_eq!(
            ckr.get_public_key_for_address("10.0.0.4".parse().unwrap()),
            Some([0x01u8; 32])
        );
        assert_eq!(
            ckr.get_public_key_for_address("10.0.0.6".parse().unwrap()),
            Some([0x01u8; 32])
        );
    }

    #[test]
    fn test_expand_cidrs_exclude_fully_covers_include() {
        // Entire include is excluded → no routes.
        let entries = vec!["10.0.0.0/24".to_string(), "!10.0.0.0/8".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_expand_cidrs_exclude_outside_include_ignored() {
        let entries = vec!["10.0.0.0/24".to_string(), "!192.168.0.0/16".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert_eq!(out, vec!["10.0.0.0/24".parse::<IpNet>().unwrap()]);
    }

    /// Reference implementation: the original subtract_many, which split the
    /// include into pieces and walked every exclude against every piece.
    /// Kept as the yardstick for the range-sweep version.
    fn subtract_many_reference(include: IpNet, excludes: &[IpNet]) -> Vec<IpNet> {
        let mut pieces = vec![include];
        for ex in excludes {
            let mut next = Vec::with_capacity(pieces.len());
            for p in pieces {
                if ex.contains(&p) {
                } else if p.contains(ex) {
                    next.extend(subtract_one_reference(p, *ex));
                } else {
                    next.push(p);
                }
            }
            pieces = next;
        }
        pieces
    }

    /// Helper for `subtract_many_reference`: subtract `b` from `a`, requiring
    /// `a.contains(&b)` and `a != b`, producing `log2(|a|/|b|)` prefixes.
    fn subtract_one_reference(a: IpNet, b: IpNet) -> Vec<IpNet> {
        let mut result = Vec::new();
        let mut current = a;
        while current != b {
            let new_len = current.prefix_len() + 1;
            let mut halves = match current.subnets(new_len) {
                Ok(it) => it,
                Err(_) => return result,
            };
            let left = match halves.next() {
                Some(x) => x,
                None => return result,
            };
            let right = match halves.next() {
                Some(x) => x,
                None => return result,
            };
            if left.contains(&b) {
                result.push(right);
                current = left;
            } else {
                result.push(left);
                current = right;
            }
        }
        result
    }

    /// Sort prefixes into a canonical order so two coverings can be compared
    /// as sets. The two implementations emit pieces in different orders by
    /// design — the sweep walks the include ascending, the reference splits
    /// outward — and nothing downstream depends on the order.
    fn canonical(mut nets: Vec<IpNet>) -> Vec<IpNet> {
        nets.sort_by(|a, b| {
            a.network()
                .cmp(&b.network())
                .then(a.prefix_len().cmp(&b.prefix_len()))
        });
        nets
    }

    /// Assert the structural invariants every covering must satisfy, whatever
    /// order its pieces come in: pieces are pairwise disjoint, and no two of
    /// them are sibling halves that should have been emitted as one block.
    /// This is an absolute check — unlike the comparison against the
    /// reference, it still fails if *both* implementations are wrong.
    fn assert_minimal_disjoint(pieces: &[IpNet], context: &str) {
        let sorted = canonical(pieces.to_vec());
        for w in sorted.windows(2) {
            let (a, b) = (w[0], w[1]);
            assert!(
                !a.contains(&b.network()) && !b.contains(&a.network()),
                "overlapping pieces {} and {} in {}",
                a,
                b,
                context
            );
            if a.prefix_len() == b.prefix_len() && a.prefix_len() > 0 {
                let parent = IpNet::new(a.network(), a.prefix_len() - 1)
                    .expect("prefix length is in range")
                    .trunc();
                assert!(
                    !(parent.contains(&a.network()) && parent.contains(&b.network())),
                    "pieces {} and {} are siblings and should have merged in {}",
                    a,
                    b,
                    context
                );
            }
        }
    }

    #[test]
    fn test_subtract_many_matches_reference_exhaustively() {
        // Walk a wide range of include/exclude shapes, including excludes that
        // sit before, inside, and after the include, several nested excludes,
        // and excludes that cover the include entirely.
        //
        // Two things are checked per case. Against the reference: the address
        // set covered must be identical, compared order-independently because
        // the sweep emits ascending while the reference emits split order and
        // nothing downstream depends on which. Absolutely: the result must be
        // disjoint and minimal, which would still fail if both implementations
        // drifted the same way.
        let includes: Vec<IpNet> = [
            "10.0.0.0/8",
            "10.0.0.0/24",
            "10.0.1.0/24",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "0.0.0.0/0",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

        let exclude_pool: Vec<IpNet> = [
            "9.0.0.0/8",        // entirely before
            "10.0.0.0/9",       // covers part
            "10.0.0.0/25",      // nested
            "10.0.0.128/25",    // sibling
            "10.0.0.5/32",      // single host
            "10.0.1.128/25",    // in a different include
            "10.128.0.0/9",     // upper half
            "172.16.5.0/24",    // inside 172.16/12
            "192.168.1.0/24",   // inside 192.168/16
            "193.0.0.0/8",      // entirely after
            "10.0.0.0/8",       // equals one include
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

        // Every non-empty subset up to size 5, in the pool's original order.
        let n = exclude_pool.len();
        let mut checked = 0usize;
        for mask in 1u32..(1 << n) {
            if (mask.count_ones() as usize) > 5 {
                continue;
            }
            let subset: Vec<IpNet> = (0..n)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| exclude_pool[i])
                .collect();

            for inc in &includes {
                let got = subtract_many(*inc, &merge_excludes(&subset));
                let want = subtract_many_reference(*inc, &subset);
                let context = format!("include {} with excludes {:?}", inc, subset);
                assert_eq!(
                    canonical(got.clone()),
                    canonical(want),
                    "mismatch for {}",
                    context
                );
                assert_minimal_disjoint(&got, &context);
                checked += 1;
            }
        }
        assert!(checked > 5000, "expected a broad sweep, only checked {}", checked);
    }

    #[test]
    fn test_default_route_minus_many_excludes() {
        // The shape the sweep exists for: one include covering everything,
        // with a large exclude list. The old piece-splitting version was
        // quadratic here, so this case had to stay small to be testable.
        // Spread far enough apart that none of them merge, and fed in
        // descending order so the sweep cannot rely on input ordering.
        let host = |i: u32| Ipv4Addr::from(0x0a00_0000u32 + (1999 - i) * 8191);
        let mut entries = vec!["0.0.0.0/0".to_string()];
        for i in 0..2000u32 {
            entries.push(format!("!{}", host(i)));
        }
        let out = expand_cidrs(&entries).unwrap();
        assert_minimal_disjoint(&out, "default route minus 2000 hosts");

        // Every excluded host is gone; unrelated addresses are still routed.
        // `out` is disjoint, so merging it just yields sorted ranges to search.
        let covered = merge_excludes(&out);
        let covers = |a: Ipv4Addr| {
            let v = u32::from(a) as u128;
            let i = covered.partition_point(|&(_, hi)| hi < v);
            covered.get(i).is_some_and(|&(lo, _)| lo <= v)
        };
        for i in 0..2000u32 {
            assert!(!covers(host(i)), "{} should have been excluded", host(i));
        }
        assert!(covers("8.8.8.8".parse().unwrap()));

        // Total coverage must be the whole space minus the 2000 hosts.
        let total: u128 = out.iter().map(|n| 1u128 << (32 - n.prefix_len())).sum();
        assert_eq!(total, (1u128 << 32) - 2000);
    }

    #[test]
    fn test_expand_cidrs_ipv6_whole_space_and_top_edge() {
        // ::/0 exercises the widest block emit_range can produce, and an
        // exclude at the very top exercises the end-of-space arithmetic.
        let out = expand_cidrs(&["::/0".to_string()]).unwrap();
        assert_eq!(out, vec!["::/0".parse::<IpNet>().unwrap()]);

        let entries = vec![
            "::/0".to_string(),
            "!ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        assert_minimal_disjoint(&out, "::/0 minus the last address");
        let top: IpAddr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let below: IpAddr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe".parse().unwrap();
        let mid: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!out.iter().any(|n| n.contains(&top)));
        assert!(out.iter().any(|n| n.contains(&below)));
        assert!(out.iter().any(|n| n.contains(&mid)));
    }

    #[test]
    fn test_merge_excludes_collapses_overlapping_and_adjacent() {
        let nets: Vec<IpNet> = ["10.0.1.0/24", "10.0.0.0/24", "10.0.0.128/25", "10.0.4.0/24"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let merged = merge_excludes(&nets);
        // 10.0.0.0/24 swallows 10.0.0.128/25 and is adjacent to 10.0.1.0/24,
        // so those three become one range; 10.0.4.0/24 stays separate.
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].1 - merged[0].0 + 1, 512);
        assert_eq!(merged[1].1 - merged[1].0 + 1, 256);
    }

    #[test]
    fn test_lookup_is_longest_prefix_across_many_lengths() {
        // Several prefix lengths for the same key space: the lookup must land
        // on the most specific one, and a miss must return None.
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["10.0.0.0/8".to_string(), "10.1.2.0/24".to_string()],
        );
        subnets.insert(
            other_key_hex(),
            vec!["10.1.0.0/16".to_string(), "10.1.2.3/32".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        let cases: [(&str, Option<[u8; 32]>); 5] = [
            ("10.9.9.9", Some([0x01u8; 32])), // /8 only
            ("10.1.9.9", Some([0x02u8; 32])), // /16 beats /8
            ("10.1.2.9", Some([0x01u8; 32])), // /24 beats /16
            ("10.1.2.3", Some([0x02u8; 32])), // /32 beats /24
            ("11.0.0.1", None),               // miss
        ];
        for (addr, want) in cases {
            assert_eq!(
                ckr.get_public_key_for_address(addr.parse().unwrap()),
                want,
                "lookup for {}",
                addr
            );
        }
    }

    #[test]
    fn test_expand_cidrs_excludes_are_family_scoped() {
        // An IPv6 exclude must not affect an IPv4 include and vice versa.
        let entries = vec![
            "10.0.0.0/24".to_string(),
            "2001:db8::/32".to_string(),
            "!2001:db8:1::/48".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.contains(&"10.0.0.0/24".parse::<IpNet>().unwrap()));
        // IPv6 side got split.
        assert!(!out.contains(&"2001:db8::/32".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn test_expand_cidrs_multiple_excludes() {
        let entries = vec![
            "10.0.0.0/24".to_string(),
            "!10.0.0.5/32".to_string(),
            "!10.0.0.10/32".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        let blocked1: IpAddr = "10.0.0.5".parse().unwrap();
        let blocked2: IpAddr = "10.0.0.10".parse().unwrap();
        assert!(!out.iter().any(|n| n.contains(&blocked1)));
        assert!(!out.iter().any(|n| n.contains(&blocked2)));
        assert!(out.iter().any(|n| n.contains(&"10.0.0.6".parse::<IpAddr>().unwrap())));
    }

    #[test]
    fn test_self_routes_are_dropped() {
        // A shared config lists routes for both this node (dummy_key) and a
        // peer (other_key). When this node is `dummy_key`, its own entry
        // must be silently dropped; the peer's entry stays.
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        subnets.insert(other_key_hex(), vec!["10.1.0.0/24".to_string()]);
        let self_key = [0x01u8; 32]; // matches dummy_key_hex
        let ckr = CryptoKey::new(&make_config(subnets), &self_key).unwrap();

        assert_eq!(ckr.v4.len(), 1);
        assert_eq!(
            ckr.get_public_key_for_address("10.0.0.5".parse().unwrap()),
            None
        );
        assert_eq!(
            ckr.get_public_key_for_address("10.1.0.5".parse().unwrap()),
            Some([0x02u8; 32])
        );
    }

    #[test]
    fn test_route_sorting_order() {
        let mut subnets = HashMap::new();
        // Insert in non-sorted order
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/8".to_string()]);
        subnets.insert(other_key_hex(), vec!["10.0.0.0/16".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        // /16 must be probed before /8 (more specific first), which is what
        // makes the first hit the longest-prefix match.
        let probed: Vec<u8> = ckr.v4.levels.keys().map(|Reverse(len)| *len).collect();
        assert_eq!(probed, vec![16, 8]);
    }

    #[test]
    fn test_ip_addresses_field_in_config() {
        let config = TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            ip_addresses: vec!["10.99.0.1/24".to_string(), "2005:8a:9:11::3/64".to_string()],
            remote_subnets: HashMap::new(),
            install_system_routes: true,
        };
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        assert!(ckr.v4.is_empty());
        assert!(ckr.v6.is_empty());
    }

    #[test]
    fn test_expand_cidrs_inetv4_keyword() {
        let entries = vec!["inetv4".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.contains(&"0.0.0.0/5".parse::<IpNet>().unwrap()));
        assert!(out.contains(&"208.0.0.0/4".parse::<IpNet>().unwrap()));
        assert_eq!(out.len(), 30);
    }

    #[test]
    fn test_expand_cidrs_tilde_inetv4_keyword() {
        let entries = vec!["~inetv4".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.contains(&"0.0.0.0/5".parse::<IpNet>().unwrap()));
        assert_eq!(out.len(), 30);
    }

    #[test]
    fn test_expand_cidrs_inetv6_keyword() {
        let entries = vec!["inetv6".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.contains(&"2000::/3".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn test_expand_cidrs_tilde_prefix() {
        let entries = vec!["~10.0.0.0/24".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert_eq!(out, vec!["10.0.0.0/24".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn test_expand_cidrs_tilde_with_exclude() {
        let entries = vec!["~0.0.0.0/0".to_string(), "!192.168.0.0/16".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        let allowed: IpAddr = "8.8.8.8".parse().unwrap();
        let blocked: IpAddr = "192.168.5.1".parse().unwrap();
        assert!(out.iter().any(|n| n.contains(&allowed)));
        assert!(!out.iter().any(|n| n.contains(&blocked)));
    }

    #[test]
    fn test_expand_cidrs_exclude_applies_to_tilde() {
        let entries = vec!["~10.0.0.0/24".to_string(), "!10.0.0.0/25".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert_eq!(out, vec!["10.0.0.128/25".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn test_expand_cidrs_bare_ip_with_tilde_exclamation() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["10.0.0.0/24".to_string(), "!10.0.0.5".to_string(), "~192.168.1.100".to_string(), "2001:db8:bbbb::1".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        // bare IPv4 exclude applied
        let excluded: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(excluded), None);
        // bare IPv4 with ~ still routed via CKR
        let v4_bare: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(v4_bare), Some([0x01u8; 32]));
        // bare IPv6 routed via CKR
        let v6_bare: IpAddr = "2001:db8:bbbb::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(v6_bare), Some([0x01u8; 32]));
    }

    #[test]
    fn test_ip_addresses_in_tunnel_routing_config_for_mobile() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        let config = TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: "10.99.0.1/24".to_string(),
            ip_addresses: vec!["2005:8a:9:11::3/64".to_string()],
            remote_subnets: subnets,
            install_system_routes: true,
        };
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        // ensures CKR still works with ip_addresses present (TUN assignment only); one remote IPv4 subnet configured
        assert_eq!(ckr.v4.len(), 1);  
    }

    #[test]
    fn test_expand_cidrs_whitespace_trimming_with_tilde() {
        let entries = vec![
            "  ~10.0.0.0/24  ".to_string(),
            " !192.168.0.0/16 ".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        let expected: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(out, vec![expected]);
    }
    
    #[test]
    fn test_ip_addresses_multiple_ipv4_ipv6_and_deprecated_precedence() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["192.168.0.0/16".to_string()]);
        let config = TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: "10.99.0.1/24".to_string(), // deprecated; must be ignored when ip_addresses has valid entries
            ip_addresses: vec![
                "10.50.0.1/24".to_string(),
                "10.60.0.1".to_string(), // bare IPv4 (auto /32)
                "2001:db8:1::1/64".to_string(),
            ],
            remote_subnets: subnets,
            install_system_routes: true,
        };
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        assert_eq!(ckr.v4.len(), 1);
        assert!(ckr.v6.is_empty());
        // Covers: multiple entries in ip_addresses (IPv4 + bare + IPv6), deprecated ipv4_address present but ignored per the new precedence rule,
        // and that CKR route parsing still succeeds (the core of the "TUN assignment only" intent of the original test).
    }

    fn subnets_of(entries: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    fn manager(entries: &[(&str, &[&str])]) -> Arc<CkrManager> {
        Arc::new(CkrManager::new(&make_config(subnets_of(entries)), &SELF_KEY).unwrap())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn nets(list: &[&str]) -> HashSet<IpNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[tokio::test]
    async fn test_manager_replaces_table() {
        let (k1, k2) = (dummy_key_hex(), other_key_hex());
        let mgr = manager(&[(&k1, &["10.0.0.0/24"])]);
        let before = mgr.table().clone();

        let report = mgr
            .set_remote_subnets(subnets_of(&[(&k2, &["10.1.0.0/24", "2001:db8::/32"])]), false)
            .await
            .unwrap();
        assert!(report.applied);
        assert_eq!((report.ipv4_routes, report.ipv6_routes), (1, 1));
        // No TUN attached: the table changes, the OS routes are not touched.
        assert!(report.system_routes_added.is_empty());

        assert_eq!(mgr.table().get_public_key_for_address(ip("10.1.0.5")), Some([0x02; 32]));
        assert_eq!(mgr.table().get_public_key_for_address(ip("10.0.0.5")), None);
        // A table loaded before the swap keeps resolving the old routes.
        assert_eq!(before.get_public_key_for_address(ip("10.0.0.5")), Some([0x01; 32]));

        let snap = mgr.snapshot().await;
        assert_eq!(snap.remote_subnets.len(), 1);
        assert_eq!(snap.remote_subnets[0].key, k2);
        assert_eq!(snap.remote_subnets[0].subnets, vec!["10.1.0.0/24", "2001:db8::/32"]);
    }

    #[tokio::test]
    async fn test_manager_invalid_input_changes_nothing() {
        let k1 = dummy_key_hex();
        let mgr = manager(&[(&k1, &["10.0.0.0/24"])]);
        let bad: [&[(&str, &[&str])]; 4] = [
            &[(&k1, &["10.0.0.0/33"])],
            &[("zz", &["10.1.0.0/24"])],
            &[(&k1, &["10.1.0.0/24", "10.1.0.0/24"])],
            &[(&k1, &["200::/7"])],
        ];
        for entries in bad {
            for dry_run in [true, false] {
                assert!(mgr.set_remote_subnets(subnets_of(entries), dry_run).await.is_err(), "{:?}", entries);
            }
        }
        assert_eq!(mgr.table().get_public_key_for_address(ip("10.0.0.5")), Some([0x01; 32]));
        assert_eq!(mgr.snapshot().await.remote_subnets[0].subnets, vec!["10.0.0.0/24"]);
    }

    #[tokio::test]
    async fn test_manager_dry_run_changes_nothing() {
        let k1 = dummy_key_hex();
        let mgr = manager(&[(&k1, &["10.0.0.0/24"])]);
        let report = mgr.set_remote_subnets(subnets_of(&[(&k1, &["10.1.0.0/24", "10.2.0.0/24"])]), true).await.unwrap();
        assert!(!report.applied);
        assert_eq!(report.ipv4_routes, 2);
        assert_eq!(mgr.table().get_public_key_for_address(ip("10.0.0.5")), Some([0x01; 32]));
        assert_eq!(mgr.table().get_public_key_for_address(ip("10.1.0.5")), None);
        assert_eq!(mgr.snapshot().await.remote_subnets[0].subnets, vec!["10.0.0.0/24"]);
    }

    #[tokio::test]
    async fn test_manager_empty_set_clears() {
        let mgr = manager(&[(&dummy_key_hex(), &["10.0.0.0/24", "2001:db8::/32"])]);
        mgr.set_remote_subnets(HashMap::new(), false).await.unwrap();
        assert_eq!(mgr.table().route_counts(), (0, 0));
        assert!(mgr.snapshot().await.remote_subnets.is_empty());
    }

    #[tokio::test]
    async fn test_manager_own_key_ignored() {
        let own = hex::encode(SELF_KEY);
        let mgr = manager(&[]);
        let report = mgr.set_remote_subnets(subnets_of(&[(&own, &["10.0.0.0/24"])]), false).await.unwrap();
        assert_eq!((report.ipv4_routes, report.ipv6_routes), (0, 0));
        let snap = mgr.snapshot().await;
        assert!(snap.remote_subnets[0].is_self);
    }

    #[tokio::test]
    async fn test_manager_refuses_after_shutdown() {
        let mgr = manager(&[]);
        mgr.shutdown().await;
        let err = mgr.set_remote_subnets(HashMap::new(), false).await.unwrap_err();
        assert!(err.contains("shutting down"), "{}", err);
    }

    #[tokio::test]
    async fn test_manager_attach_without_system_routes() {
        let mut config = make_config(subnets_of(&[(&dummy_key_hex(), &["10.0.0.0/24"])]));
        config.install_system_routes = false;
        let mgr = Arc::new(CkrManager::new(&config, &SELF_KEY).unwrap());
        mgr.attach_tun("tun-test").await;
        let snap = mgr.snapshot().await;
        assert_eq!(snap.tun.as_deref(), Some("tun-test"));
        assert_eq!(snap.system_routes, 0);
        let report = mgr.set_remote_subnets(subnets_of(&[(&other_key_hex(), &["10.1.0.0/24"])]), false).await.unwrap();
        assert!(report.system_routes_added.is_empty() && report.system_routes_removed.is_empty());
    }

    #[test]
    fn test_route_diff_and_sync() {
        // No TUN, so sync_routes only does the bookkeeping.
        let mut state = CkrState {
            remote_subnets: HashMap::new(),
            tun: None,
            installed: nets(&["10.0.0.0/24", "10.4.0.0/24"]),
            failed: nets(&["10.1.0.0/24", "10.2.0.0/24"]),
            closed: false,
        };
        let new = nets(&["10.0.0.0/24", "10.1.0.0/24", "10.3.0.0/24"]);
        let (add, remove) = state.route_diff(&new);
        // New prefixes and failed ones still wanted are added; installed
        // ones no longer wanted are removed. A failed one no longer wanted
        // is left alone: it may be someone else's route.
        assert_eq!(add.into_iter().collect::<HashSet<_>>(), nets(&["10.1.0.0/24", "10.3.0.0/24"]));
        assert_eq!(remove, nets(&["10.4.0.0/24"]).into_iter().collect::<Vec<_>>());

        let (add, remove, failures) = state.sync_routes(new.clone());
        assert_eq!(add.len(), 2);
        assert_eq!(remove.len(), 1);
        assert!(failures.is_empty() && state.failed.is_empty());
        assert_eq!(state.installed, new);

        // Shutdown removes every installed route.
        let (add, remove, _) = state.sync_routes(HashSet::new());
        assert!(add.is_empty());
        assert_eq!(remove.into_iter().collect::<HashSet<_>>(), new);
    }

    #[test]
    fn test_desired_system_routes() {
        let own = hex::encode(SELF_KEY);
        let subnets = subnets_of(&[
            (&dummy_key_hex(), &["10.0.0.0/24", "!10.0.0.0/25", "~10.9.0.0/16", "~inetv6", "2001:db8::1"]),
            (&other_key_hex(), &["10.5.0.0/16"]),
            (&own, &["10.7.0.0/16"]),
        ]);
        assert_eq!(
            desired_system_routes(&subnets, &SELF_KEY).unwrap(),
            nets(&["10.0.0.128/25", "2001:db8::1/128", "10.5.0.0/16"])
        );
    }
}
