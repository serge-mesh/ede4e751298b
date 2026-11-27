//! The DNS data path (edge.md §4–§10, §16): listeners, profile choice and devices, the query
//! pipeline, filtering over the active bundles, sync lookups, the cache and the upstream pool.
//!
//! - [`Dns`] holds what survives config activations: the cache, the upstream pool (one actor per
//!   upstream, kept while its settings don't change), the lookup clients (updated in place), the
//!   per-device limiter, the listener manager and the listener certificates. It is created before
//!   the [`Edge`] and lives in it (`edge.dns`).
//! - [`runtime::DnsRuntime`] is one config compiled for the data path, published in the active
//!   state with the bundles and `versions`, so a query reads all three from one load.
//! - [`activation`] holds the data path's foundation hooks: the config-only activator (the full
//!   one is [`crate::bundles::EdgeActivator`]), the request handler (`flush_dns`, `flush_lookups`,
//!   `revoked_allows`), the `listeners` firmware self-check, and the `versions` block.
//! - [`spawn`] starts the tasks: the listener manager, certificate renewal and reloads, the
//!   upstream health pass and the watchdog's internal test query.
//!
//! Seams (each a trait with a no-op default in [`DnsHooks`]): the firewall ensure point
//! (edge.md §9; [`crate::firewall::FwHook`]) and the extension's recent-blocks ring (edge.md §12;
//! [`crate::bypass::RingHook`]), both installed by [`crate::service::start`].

pub mod activation;
pub mod cache;
pub mod certs;
pub mod explain;
pub mod filter;
pub mod http_client;
pub mod interfaces;
pub mod limits;
pub mod listeners;
pub mod lookups;
pub mod pipeline;
pub mod profiles;
pub mod resolve;
pub mod runtime;
pub mod upstream;
pub mod zones;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;

use picket_api::edge_config::{BlockResponse, CacheSettings, ProfileFirewall};
use picket_api::logs::Stage;
use picket_wire::{NameRef, Query};

use crate::conditions::Conditions;
use crate::core_client::CoreClient;
use crate::edge::Edge;
use crate::logs::LogProducer;
use crate::metrics::Metrics;
use crate::supervisor::Kind;

use cache::DnsCache;
use filter::{AllowIndex, TempAllows};
use limits::DeviceLimiter;
use profiles::DeviceKey;
use resolve::Resolver;
use upstream::UpstreamPool;

/// One address of an answer with the TTL the client got for it (edge-firewall.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FwAddr {
    pub ip: IpAddr,
    /// `client_ttl`: the TTL of the record carrying the address in the reply the client got
    /// (its A or AAAA record, or the HTTPS/SVCB record holding the hint), aged and clamped to the
    /// profile's `ttl` as served, or `stale_ttl` for a stale answer. Where the reply carries the
    /// address more than once, the longest.
    pub client_ttl: u32,
}

/// What the firewall needs from an answer before it leaves (edge.md §9, edge-firewall.md §3).
#[derive(Debug)]
pub struct FwRequest<'a> {
    pub client: IpAddr,
    pub device: &'a DeviceKey,
    pub profile: &'a str,
    pub firewall: &'a ProfileFirewall,
    /// The answer's addresses (A, AAAA, HTTPS/SVCB hints; a rewrite's addresses), each with its
    /// own `client_ttl`.
    pub addrs: &'a [FwAddr],
}

/// The firewall's verdict on an answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FwOutcome {
    /// Entries newly added (`fw.added` in the log).
    pub added: u32,
    /// The helper's ack didn't come within `ack_wait_ms` (`fw_ack_late`).
    pub late: bool,
    /// The set is full and the profile says `on_full: servfail`.
    pub servfail: bool,
}

/// The firewall ensure point (edge.md §4 diagram, §9): called before an allowed or rewritten answer
/// carrying addresses leaves. The pipeline calls it only for profiles with `firewall.add_entries`.
#[async_trait]
pub trait FirewallEnsure: Send + Sync {
    async fn ensure(&self, req: &FwRequest<'_>) -> FwOutcome;
    /// False when nothing is ever added (no firewall client): the pipeline then skips the call
    /// and its boxed future (build-and-test.md §4).
    fn enabled(&self) -> bool {
        true
    }
}

/// No firewall client: nothing is added (the real one is [`crate::firewall::FwHook`]).
pub struct NoFirewall;

#[async_trait]
impl FirewallEnsure for NoFirewall {
    async fn ensure(&self, _req: &FwRequest<'_>) -> FwOutcome {
        FwOutcome::default()
    }
    fn enabled(&self) -> bool {
        false
    }
}

/// What decided a block, for its EDE (edge.md §4 EDE table). The ids are the active config's,
/// shared (`Arc`), so recording a block copies no text.
#[derive(Clone, Copy, Debug)]
pub enum BlockSource<'a> {
    /// A bundle rule: the bundle and the full id of the head its deciding part came from.
    Bundle {
        bundle: &'a Arc<str>,
        head: &'a Arc<str>,
    },
    /// A sync lookup: the first blocking provider and its verdict text.
    Lookup {
        provider: &'a Arc<str>,
        verdict: &'static str,
    },
}

/// A DNS block, as the recent-blocks ring records it (edge.md §12).
#[derive(Debug)]
pub struct BlockNote<'a> {
    pub block_id: &'a str,
    pub name: NameRef<'a>,
    pub stage: Stage,
    /// The response-phase target that blocked (log text), if any.
    pub target: Option<&'a str>,
    pub source: BlockSource<'a>,
    /// The block response the query was answered with (its `ttl` is the block TTL).
    pub response: &'a BlockResponse,
    pub profile: &'a Arc<str>,
}

/// The extension's recent-blocks ring (edge.md §12).
pub trait RecentBlocks: Send + Sync {
    /// A DoH query with `X-Picket-Client: extension` from `client`, checked against the device's
    /// ring first. `Some(reply)` answers it (a hit as its block did, a miss with NOERROR and no
    /// records); `None` lets it through the pipeline.
    fn extension_probe(
        &self,
        device: &DeviceKey,
        client: IpAddr,
        query: &Query,
        msg: &[u8],
    ) -> Option<Vec<u8>>;
    /// Records a DNS block for the device.
    fn record_block(&self, device: &DeviceKey, note: &BlockNote<'_>);
}

/// No ring: nothing kept, no probe handled (the real one is [`crate::bypass::RingHook`]).
pub struct NoRing;

impl RecentBlocks for NoRing {
    fn extension_probe(&self, _: &DeviceKey, _: IpAddr, _: &Query, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn record_block(&self, _: &DeviceKey, _: &BlockNote<'_>) {}
}

/// The data path's seams.
pub struct DnsHooks {
    pub firewall: ArcSwap<Box<dyn FirewallEnsure>>,
    pub recent_blocks: ArcSwap<Box<dyn RecentBlocks>>,
}

impl Default for DnsHooks {
    fn default() -> Self {
        Self {
            firewall: ArcSwap::from_pointee(Box::new(NoFirewall)),
            recent_blocks: ArcSwap::from_pointee(Box::new(NoRing)),
        }
    }
}

/// Knobs tests shorten.
#[derive(Clone, Debug)]
pub struct DnsTuning {
    /// How often the watchdog's internal test query runs once listeners are bound.
    pub watchdog_every: Duration,
    /// How often a failed listener bind is retried.
    pub rebind_every: Duration,
    /// How often certificates are checked (renewal, file changes).
    pub certs_every: Duration,
    /// One upstream attempt's timeout and one resolution's budget.
    pub attempt_timeout: Duration,
    pub resolve_budget: Duration,
    /// Backoff bounds for failed CSRs (the session's: edge.md §5).
    pub csr_backoff: (Duration, Duration),
    /// Extra PEM roots lookup providers' HTTPS clients trust besides the Mozilla roots (tests).
    pub http_roots: Option<String>,
    /// How long a group stays all-unhealthy before `upstream_down` (edge.md §6: 30 s).
    pub down_after: Duration,
    /// A listener loop whose liveness mark is older than this fails the watchdog's test
    /// (edge.md §16); idle loops stamp theirs five times as often.
    pub listener_stale: Duration,
    /// Most client queries in flight per UDP socket ([`listeners::udp::MAX_INFLIGHT`]; tests
    /// lower it to fill every slot).
    pub udp_inflight: usize,
}

impl Default for DnsTuning {
    fn default() -> Self {
        Self {
            watchdog_every: Duration::from_secs(5),
            rebind_every: Duration::from_secs(15),
            certs_every: Duration::from_secs(60),
            attempt_timeout: upstream::ATTEMPT_TIMEOUT,
            resolve_budget: upstream::RESOLVE_BUDGET,
            csr_backoff: (Duration::from_secs(1), Duration::from_secs(60)),
            http_roots: None,
            down_after: upstream::DOWN_AFTER,
            listener_stale: Duration::from_secs(10),
            udp_inflight: listeners::udp::MAX_INFLIGHT,
        }
    }
}

/// The DNS data path's long-lived state.
pub struct Dns {
    pub resolver: Arc<Resolver>,
    pub pool: Arc<UpstreamPool>,
    pub lookups: Arc<lookups::Lookups>,
    pub limiter: Arc<DeviceLimiter>,
    pub listeners: Arc<listeners::ListenerManager>,
    pub certs: Arc<certs::Certs>,
    pub interfaces: Arc<interfaces::Interfaces>,
    pub hooks: DnsHooks,
    pub tuning: DnsTuning,
    allow_index: ArcSwap<AllowCache>,
}

/// The temporary-allow index and the `allows.json` snapshot it was built from. Holding the
/// snapshot keeps its address from being reused, so [`Arc::ptr_eq`] can't mistake a later
/// snapshot for it (edge.md §12).
struct AllowCache {
    snap: Arc<crate::allows::AllowsFile>,
    index: Arc<AllowIndex>,
}

impl Dns {
    /// Builds the state (no task runs yet; see [`spawn`]).
    pub fn new(
        metrics: Arc<Metrics>,
        conditions: Arc<Conditions>,
        logs: LogProducer,
        tuning: DnsTuning,
        registry: Option<Arc<picket_lookup::Registry>>,
    ) -> Arc<Self> {
        let pool = {
            let mut p = UpstreamPool::new(Arc::clone(&metrics), Arc::clone(&conditions));
            if let Some(m) = Arc::get_mut(&mut p) {
                m.attempt_timeout = tuning.attempt_timeout;
                m.budget = tuning.resolve_budget;
                m.down_after = tuning.down_after;
            }
            p
        };
        let resolver = Resolver::new(DnsCache::new(CacheSettings::default()), Arc::clone(&pool));
        let registry = registry.unwrap_or_else(|| Arc::new(picket_lookup::Registry::builtin()));
        let lookups = lookups::Lookups::with_registry(
            Arc::downgrade(&resolver),
            logs,
            registry,
            tuning.http_roots.clone(),
        );
        Arc::new(Self {
            resolver,
            pool,
            lookups,
            limiter: DeviceLimiter::new(),
            listeners: listeners::ListenerManager::new(),
            certs: certs::Certs::new(),
            interfaces: interfaces::Interfaces::new(),
            hooks: DnsHooks::default(),
            tuning,
            allow_index: ArcSwap::from_pointee(AllowCache {
                snap: Arc::default(),
                index: Arc::new(AllowIndex::build(&Default::default(), None)),
            }),
        })
    }

    /// The temporary-allow index for ladder step 1, rebuilt when `allows.json` changed.
    pub fn temp_allows(&self, edge: &Edge) -> Arc<dyn TempAllows> {
        let snap = edge.allows.snapshot();
        let cur = self.allow_index.load();
        if Arc::ptr_eq(&cur.snap, &snap) {
            return Arc::clone(&cur.index) as Arc<dyn TempAllows>;
        }
        let index = Arc::new(AllowIndex::build(&snap, Some(Arc::clone(&edge.clock))));
        self.allow_index.store(Arc::new(AllowCache {
            snap,
            index: Arc::clone(&index),
        }));
        index
    }
}

/// Starts the data path's tasks under the supervisor.
pub fn spawn(edge: &Arc<Edge>, core: Option<Arc<CoreClient>>) {
    let sup = Arc::clone(&edge.supervisor);
    {
        let e = Arc::clone(edge);
        sup.spawn("dns-listeners", Kind::Background, move || {
            listeners::run(Arc::clone(&e))
        });
    }
    {
        let e = Arc::clone(edge);
        let c = core.clone();
        sup.spawn("dns-certs", Kind::Background, move || {
            certs::run(Arc::clone(&e), c.clone())
        });
    }
    {
        let e = Arc::clone(edge);
        sup.spawn("dns-upstream-health", Kind::Background, move || {
            let e = Arc::clone(&e);
            async move {
                let mut t = tokio::time::interval(Duration::from_secs(1));
                loop {
                    t.tick().await;
                    e.dns.pool.check_health();
                }
            }
        });
    }
    {
        // Pending `tls_version_refused` counts whose hour is over (listeners::handshake).
        let e = Arc::clone(edge);
        sup.spawn("dns-tls-refusals", Kind::Background, move || {
            let e = Arc::clone(&e);
            async move {
                let mut t = tokio::time::interval(listeners::handshake::SWEEP_EVERY);
                loop {
                    t.tick().await;
                    e.dns.listeners.tls_refusals.sweep_and_log(&e);
                }
            }
        });
    }
    {
        let e = Arc::clone(edge);
        sup.spawn("dns-watchdog-query", Kind::Background, move || {
            pipeline::watchdog_loop(Arc::clone(&e))
        });
    }
    {
        let e = Arc::clone(edge);
        sup.spawn("dns-interfaces", Kind::Background, move || {
            Arc::clone(&e.dns.interfaces).run()
        });
    }
}
