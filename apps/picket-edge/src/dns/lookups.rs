//! Sync lookup clients (edge.md §10, providers.md §4–§5): one picket-lookup [`LookupClient`] per
//! configured lookup provider, updated in place on activation (keeping its RAM tier, breaker,
//! pause and token bucket), dropped when no profile attaches it `sync` any more.
//!
//! - Each provider gets its own connections ([`EdgeConnections`]): an HTTP client (hyper +
//!   rustls, no redirects, bounded) whose host names resolve through the edge's own upstreams,
//!   unfiltered, and a DNS server client over the upstream transports (servers by IP, never an
//!   upstream group; answers never enter the DNS cache).
//! - Late answers become `lookup` records, per profile that waited, under that profile's `log`.
//! - Heartbeat metrics: each client's running totals, plus those of clients dropped earlier in
//!   this process, so a provider dropped and attached again never counts backwards.
//! - The verdict-set tier is attached by [`crate::bundles`] (edge.md §10); a new client starts
//!   without one. Until the wall clock is synchronised the tier answers nothing (README §2
//!   Clocks: a record's expiry can't be judged), see [`crate::bundles::verdicts`].

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;

use picket_api::edge_config::{EdgeConfig, LogLevel};
use picket_api::histogram::Histogram;
use picket_api::logs::LogRecord;
use picket_api::session::LookupMetrics;
use picket_lookup::{
    ClientOptions, ConnectionFactory, Connections, DnsClientError, DnsServer, DnsServerClient, LateAnswer,
    LookupClient, ProviderSpec, Registry, Role,
};

use super::resolve::Resolver;
use super::upstream::transport::{Endpoint, Transport, TxError};
use crate::logs::{LogProducer, placeholder_header};

/// Most DNS servers one provider keeps transports for (providers.md §5: 1–8 servers).
const MAX_SERVERS: usize = 16;

/// A provider's DNS server client: the upstream transports, one per server it names.
#[derive(Default)]
pub struct EdgeDnsClient {
    transports: Mutex<HashMap<Endpoint, Arc<Transport>>>,
}

impl EdgeDnsClient {
    fn transport(&self, server: &DnsServer) -> Result<Arc<Transport>, DnsClientError> {
        let ep = Endpoint {
            protocol: server.transport,
            ip: server.ip,
            port: server.port,
            tls_host: server.tls_host.clone(),
            trust_store: server.trust_store.clone(),
            path: server.path.clone(),
        };
        let mut g = self.transports.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(t) = g.get(&ep) {
            return Ok(Arc::clone(t));
        }
        let t = Transport::new(&ep).map_err(|e| DnsClientError::Connect(crate::diag::cap_chain(&e)))?;
        if g.len() < MAX_SERVERS {
            g.insert(ep, Arc::clone(&t));
        }
        Ok(t)
    }
}

#[async_trait]
impl DnsServerClient for EdgeDnsClient {
    async fn query(
        &self,
        server: &DnsServer,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsClientError> {
        let t = self.transport(server)?;
        t.query(query, timeout, None).await.map_err(|e| match e {
            TxError::Timeout => DnsClientError::Timeout,
            TxError::Connect(m) => DnsClientError::Connect(m),
            TxError::Transport(m) => DnsClientError::Transport(m),
            TxError::TooLarge => DnsClientError::TooLarge,
            TxError::Mismatch => DnsClientError::Transport("answer for another question".into()),
        })
    }
}

/// Resolves provider host names through the edge's own upstreams, unfiltered (edge.md §10).
pub struct UpstreamNames {
    resolver: Weak<Resolver>,
    group: ArcSwap<Option<Arc<str>>>,
}

impl UpstreamNames {
    /// Names that resolve nothing (tests that use IP literals only).
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self {
            resolver: Weak::new(),
            group: ArcSwap::from_pointee(None),
        }
    }

    /// The A and AAAA addresses of `host` (A first).
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        let resolver = self.resolver.upgrade().ok_or("shutting down")?;
        let group = self
            .group
            .load_full()
            .as_ref()
            .clone()
            .ok_or("no upstream group to resolve with")?;
        let name = picket_wire::WireName::from_text(host).map_err(|_| format!("bad host name {host:?}"))?;
        let (encrypted, generation) = resolver
            .pool
            .group(&group)
            .map_or((false, 0), |g| (g.encrypted, g.generation));
        let mut out = vec![];
        let mut last_err = None;
        for qtype in [picket_wire::types::rtype::A, picket_wire::types::rtype::AAAA] {
            let key = super::cache::KeyRef::new(
                name.as_name(),
                qtype,
                picket_wire::types::class::IN,
                super::upstream::upstream_do(encrypted, false, false),
                false,
                &group,
                generation,
            );
            let entry = match resolver.cache.get(&key, std::time::Instant::now()) {
                super::cache::Lookup::Fresh { entry, .. } => Ok(entry),
                _ => resolver.fetch(&key).await.map(|f| Arc::clone(&f.entry)),
            };
            match entry {
                Ok(e) => out.extend(
                    e.value
                        .facts()
                        .addrs
                        .iter()
                        .filter(|a| !a.source.is_hint())
                        .map(|a| a.ip),
                ),
                Err(f) => last_err = Some(f.cause.as_str()),
            }
        }
        if out.is_empty() {
            return Err(format!(
                "{host} has no address{}",
                last_err.map(|c| format!(" (upstream {c})")).unwrap_or_default()
            ));
        }
        Ok(out)
    }
}

/// Builds each provider's own connections.
pub struct EdgeConnections {
    pub names: Arc<UpstreamNames>,
    /// Extra roots for HTTPS APIs (tests; production uses the Mozilla roots).
    pub http_roots: Option<String>,
}

impl EdgeConnections {
    pub fn factory(self: &Arc<Self>) -> ConnectionFactory {
        let me = Arc::clone(self);
        Arc::new(move |_provider: &str| Connections {
            http: Arc::new(super::http_client::EdgeHttpClient::new(
                Arc::clone(&me.names),
                me.http_roots.as_deref(),
            )),
            dns: Arc::new(EdgeDnsClient::default()),
        })
    }
}

/// The lookup clients.
pub struct Lookups {
    clients: ArcSwap<HashMap<String, Arc<LookupClient>>>,
    registry: Arc<Registry>,
    connections: Arc<EdgeConnections>,
    levels: Arc<ArcSwap<HashMap<String, LogLevel>>>,
    retired: Mutex<HashMap<String, LookupMetrics>>,
    logs: LogProducer,
    configure_lock: Mutex<()>,
}

impl Lookups {
    pub fn new(resolver: Weak<Resolver>, logs: LogProducer) -> Arc<Self> {
        Self::with_registry(resolver, logs, Arc::new(Registry::builtin()), None)
    }

    /// With another module registry (tests use scripted modules) and extra HTTPS roots.
    pub fn with_registry(
        resolver: Weak<Resolver>,
        logs: LogProducer,
        registry: Arc<Registry>,
        http_roots: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            clients: ArcSwap::from_pointee(HashMap::new()),
            registry,
            connections: Arc::new(EdgeConnections {
                names: Arc::new(UpstreamNames {
                    resolver,
                    group: ArcSwap::from_pointee(None),
                }),
                http_roots,
            }),
            levels: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            retired: Mutex::new(HashMap::new()),
            logs,
            configure_lock: Mutex::new(()),
        })
    }

    fn late_sink(&self) -> picket_lookup::LateSink {
        let logs = self.logs.clone();
        let levels = Arc::clone(&self.levels);
        Arc::new(move |late: LateAnswer| {
            let lv = levels.load();
            for tag in &late.tags {
                let level = lv.get(&**tag).copied().unwrap_or(LogLevel::Full);
                if crate::logs::lookup_admitted(level) {
                    logs.emit(LogRecord::Lookup(
                        late.to_record(placeholder_header(), Some(tag.to_string())),
                    ));
                }
            }
        })
    }

    /// Applies a config (edge.md §13 "Lookup clients survive config activations").
    pub fn configure(&self, cfg: &EdgeConfig) {
        let _g = self.configure_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.levels.store(Arc::new(
            cfg.profiles.iter().map(|(k, p)| (k.clone(), p.log)).collect(),
        ));
        let group = cfg
            .default_profile
            .as_ref()
            .and_then(|d| cfg.profiles.get(d))
            .map(|p| p.upstream.clone())
            .filter(|g| cfg.upstream_groups.contains_key(g))
            .or_else(|| {
                cfg.upstream_groups
                    .contains_key("cloudflare")
                    .then(|| "cloudflare".to_owned())
            })
            .or_else(|| cfg.upstream_groups.keys().next().cloned());
        self.connections
            .names
            .group
            .store(Arc::new(group.map(|g| g.as_str().into())));
        let old = self.clients.load_full();
        let mut next = HashMap::new();
        for (id, pc) in &cfg.lookup_providers {
            let spec = ProviderSpec::from_edge(id, pc);
            match old.get(id) {
                Some(c) => {
                    c.update(spec, &cfg.secrets);
                    next.insert(id.clone(), Arc::clone(c));
                }
                None => {
                    let opts = ClientOptions::new(
                        Role::Edge,
                        Arc::clone(&self.registry),
                        self.connections.factory(),
                    );
                    let c = Arc::new(LookupClient::new(spec, &cfg.secrets, opts));
                    c.set_late_sink(Some(self.late_sink()));
                    // The verdict-set tier is attached by the activator (edge.md §10).
                    c.set_verdict_set(None);
                    // A provider attached again: its earlier totals carry on.
                    next.insert(id.clone(), c);
                }
            }
        }
        // Dropped providers: keep their running totals (api.md §3 running totals).
        let mut retired = self.retired.lock().unwrap_or_else(|p| p.into_inner());
        for (id, c) in old.iter() {
            if !next.contains_key(id) {
                let m = c.metrics();
                let e = retired.entry(id.clone()).or_default();
                add_counters(e, &m);
            }
        }
        self.clients.store(Arc::new(next));
    }

    pub fn get(&self, id: &str) -> Option<Arc<LookupClient>> {
        self.clients.load().get(id).cloned()
    }

    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.clients.load().keys().cloned().collect();
        v.sort();
        v
    }

    /// `flush.lookups.<provider>`: empties that provider's RAM tier. Unknown providers are fine
    /// (nothing to flush).
    pub fn flush(&self, id: &str) {
        if let Some(c) = self.get(id) {
            c.flush();
        }
    }

    pub fn flush_all(&self) {
        for c in self.clients.load().values() {
            c.flush();
        }
    }

    /// The heartbeat's `lookups` (api.md §3): running totals per provider.
    pub fn metrics(&self) -> BTreeMap<String, LookupMetrics> {
        let mut out: BTreeMap<String, LookupMetrics> = BTreeMap::new();
        let retired = self.retired.lock().unwrap_or_else(|p| p.into_inner());
        for (id, m) in retired.iter() {
            out.insert(id.clone(), m.clone());
        }
        drop(retired);
        for (id, c) in self.clients.load().iter() {
            let m = c.metrics();
            let e = out.entry(id.clone()).or_default();
            add_counters(e, &m);
            // Gauges are the live client's.
            e.breaker_open = m.breaker_open;
            e.entries = m.entries;
            e.bytes = m.bytes;
        }
        out
    }
}

fn add_hist(a: &mut Histogram, b: &Histogram) {
    if a.buckets.len() < b.buckets.len() {
        a.buckets.resize(b.buckets.len(), 0);
    }
    for (x, y) in a.buckets.iter_mut().zip(&b.buckets) {
        *x = x.saturating_add(*y);
    }
    a.sum = a.sum.saturating_add(b.sum);
    a.count = a.count.saturating_add(b.count);
}

fn add_counters(a: &mut LookupMetrics, b: &LookupMetrics) {
    a.calls = a.calls.saturating_add(b.calls);
    add_hist(&mut a.call_ms, &b.call_ms);
    a.timeouts = a.timeouts.saturating_add(b.timeouts);
    a.late = a.late.saturating_add(b.late);
    a.errors = a.errors.saturating_add(b.errors);
    a.rejected = a.rejected.saturating_add(b.rejected);
    a.paused = a.paused.saturating_add(b.paused);
    a.cache_hits = a.cache_hits.saturating_add(b.cache_hits);
    a.set_hits = a.set_hits.saturating_add(b.set_hits);
    a.cache_misses = a.cache_misses.saturating_add(b.cache_misses);
    a.evictions = a.evictions.saturating_add(b.evictions);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_totals_are_added() {
        let mut a = LookupMetrics {
            calls: 2,
            ..Default::default()
        };
        let mut b = LookupMetrics {
            calls: 3,
            breaker_open: 1,
            ..Default::default()
        };
        b.call_ms.buckets = vec![1, 2];
        b.call_ms.count = 3;
        add_counters(&mut a, &b);
        assert_eq!(a.calls, 5);
        assert_eq!(a.call_ms.count, 3);
        assert_eq!(a.breaker_open, 0, "gauges aren't summed");
    }
}
