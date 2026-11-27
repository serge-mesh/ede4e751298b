//! `LookupClient` (providers.md §4): one per lookup provider, the same code on edge and core.
//!
//! It applies the provider's settings around the module's `lookup()`: the name label check, the
//! cache tiers, single-flight per (provider, name), `max_inflight`, the token bucket, the circuit
//! breaker, the rejection pause and the timeouts, and counts what happens for the heartbeat.
//!
//! - **Tiers** (edge.md §10): the RAM tier (edge only, [`Role::Edge`]), then the verdict-set hook
//!   ([`VerdictSet`], the edge's page files; core may plug in its `lookup_verdicts` table or
//!   nothing), then a call. An error cached in the RAM tier doesn't stop the set read; it
//!   suppresses the call only when the set misses too.
//! - **Generations** (providers.md §4 "Cache generation"): every entry and call carries the
//!   `cache_generation` current when it started; an entry from another generation is a miss and
//!   is dropped, and a call's result isn't stored if the generation moved on or the cache was
//!   flushed after the call started. A lookup never decides with the result of a call whose
//!   generation is no longer current: it starts again under the new one.
//! - **Settings** (edge.md §13): a call starts under the settings current when it is admitted
//!   (limits, config, connections), not those of when its lookup began.
//! - **Verdict-set activation** (edge.md §10, [`LookupClient::activate_set_delta`],
//!   [`LookupClient::activate_set_base`]): superseded RAM-tier entries are dropped, checked with no
//!   RAM-tier lock held, before the set is swapped in; a call in flight across an activation
//!   doesn't fill the RAM tier, so nothing older than the new set can appear behind it.
//! - **Sync** ([`LookupClient::lookup_sync`], the edge): waits until the caller's deadline, then
//!   returns a timeout while the call goes on up to `async_timeout_ms`; its answer is stored in
//!   the RAM tier and handed to the [`LateSink`] (edge.md §10 "Late answers").
//! - **Async** ([`LookupClient::lookup_async`], core): waits for an inflight slot and a token,
//!   then for the call, up to `async_timeout_ms` each; a pause or an open breaker returns at once
//!   so core's queue can wait (core.md §7).
//! - **Settings updates** ([`LookupClient::update`]) apply in place, keeping the RAM tier,
//!   breaker, pause and token bucket (edge.md §13); a config change replaces the provider's
//!   connections.

mod admission;
mod metrics;
mod outcome;
mod ram;

use std::collections::{BTreeMap, HashMap};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use futures_util::FutureExt as _;
use picket_api::edge_config::{LookupProviderConfig, LookupSettings};
use picket_api::session::LookupMetrics;
use picket_api::time::{Timestamp, clamp_to_now};
use serde_json::Value;
use tokio::sync::{Notify, watch};
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::ctx::{Clock, ConnectionFactory, LookupCtx, SystemClock};
use crate::module::{LookupError, LookupModule, detail_fits};
use crate::name::check_name;
use crate::registry::Registry;
use crate::secrets::{self, Redactor};
use crate::selftest::{SelfTestResult, SelfTestRun};

pub use admission::{FIRST_PAUSE, MAX_INFLIGHT_CAP, MAX_PAUSE, PAUSE_JITTER};
pub use outcome::{
    AsyncOutcome, AsyncResult, ErrorKind, LateAnswer, LateSink, Source, StoredVerdict, SyncOutcome,
    SyncResult,
};
pub use ram::{MAX_RAM_MIB, RamResult, TTL_CAP, ttl_for};

use admission::{Admission, Finish, Refusal, Ticket};
use metrics::Metrics;
use ram::{RamEntry, RamLookup, RamTier};

/// The longest Block reason kept (bytes); a longer one is cut at a character boundary.
pub const MAX_REASON: usize = 256;
/// The longest error message kept (bytes).
pub const MAX_MESSAGE: usize = 512;
/// The most distinct tags a call keeps for its late answer.
pub const MAX_LATE_TAGS: usize = 64;
/// `async_timeout_ms` is clamped to at most this.
pub const MAX_ASYNC_TIMEOUT: Duration = Duration::from_secs(600);
/// `sync_timeout_ms` is clamped to at most this.
pub const MAX_SYNC_TIMEOUT: Duration = Duration::from_secs(60);
/// How many times one lookup starts again because the generation moved on while it ran. Each
/// restart takes a save or flush, and every wait ends at the lookup's deadline, so this is only
/// a backstop.
const MAX_RESTARTS: usize = 3;

/// Which side runs the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// picket-edge: a RAM tier (`cache.max_mib`) that also caches errors for `error_ttl_s`.
    Edge,
    /// picket-core: no RAM tier and no error cache; its verdict store is `lookup_verdicts`
    /// (core.md §7), which core may plug in as the [`VerdictSet`] tier or check itself.
    Core,
}

/// One lookup provider's definition: its id, module, config (with `${secret:name}`
/// references), `cache_generation` and settings.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderSpec {
    /// The lookup provider id (not the module id).
    pub id: String,
    /// The module id (`http_json`, `dns`, …).
    pub module: String,
    pub config: Value,
    pub generation: String,
    pub settings: LookupSettings,
}

impl ProviderSpec {
    /// From an `EdgeConfig.lookup_providers` entry (api.md §4).
    pub fn from_edge(id: &str, c: &LookupProviderConfig) -> Self {
        Self {
            id: id.to_owned(),
            module: c.module.clone(),
            config: c.config.clone(),
            generation: c.cache_generation.clone(),
            settings: c.settings.clone(),
        }
    }
}

/// A record the verdict-set tier holds for a name.
#[derive(Clone, Debug, PartialEq)]
pub struct SetRecord {
    pub verdict: StoredVerdict,
    /// When the provider answered.
    pub obtained_at: Timestamp,
    /// The `cache_generation` of the set the record is in.
    pub generation: Arc<str>,
}

/// The tier between the RAM tier and a call (edge.md §10): on the edge, the provider's verdict
/// set from core (its RAM overlay, then one page read in a blocking thread). An error or a page
/// that fails its checks is a miss. The client checks the record's generation and expiry.
#[async_trait::async_trait]
pub trait VerdictSet: Send + Sync {
    async fn get(&self, name: &str) -> anyhow::Result<Option<SetRecord>>;
}

/// What a client needs besides the provider's definition.
#[derive(Clone)]
pub struct ClientOptions {
    pub role: Role,
    pub registry: Arc<Registry>,
    pub connections: ConnectionFactory,
    pub clock: Arc<dyn Clock>,
}

impl ClientOptions {
    pub fn new(role: Role, registry: Arc<Registry>, connections: ConnectionFactory) -> Self {
        Self {
            role,
            registry,
            connections,
            clock: Arc::new(SystemClock),
        }
    }
}

/// One sync lookup (edge.md §10).
#[derive(Clone, Debug)]
pub struct SyncRequest<'a> {
    pub name: &'a str,
    /// When the reply stops waiting: [`LookupClient::sync_deadline`].
    pub deadline: Instant,
    /// False for a cache-only lookup: the RAM tier and the verdict set, never a call (a query
    /// type outside `scope.qtypes`, or `ANY`: a live Block still blocks it, edge.md §10). It
    /// returns a live Block or [`SyncResult::Miss`], never a fail-mode result.
    pub call: bool,
    /// Returned with a late answer (e.g. the query's profile id), so the edge can log it.
    pub tag: Option<Arc<str>>,
}

/// One async lookup (core.md §7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AsyncOptions {
    /// Skip the cache tiers and single-flight and always call (a re-check: its result replaces
    /// the entry).
    pub skip_cache: bool,
    /// At most one call: a generation that moves on during the lookup ends it with
    /// [`AsyncResult::GenerationMoved`] instead of starting it again under the new one, so the
    /// caller decides about every call it makes (core reserves a re-check's share of
    /// `max_per_day` per call, core.md §7).
    pub one_attempt: bool,
}

/// What [`LookupClient::update`] changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpdateEffect {
    /// The `cache_generation` moved on: the RAM tier was emptied.
    pub generation_changed: bool,
    /// The module or its config changed: the provider got new connections.
    pub config_changed: bool,
}

/// The settings snapshot every lookup reads.
struct Spec {
    settings: LookupSettings,
    generation: Arc<str>,
    gen_key: u64,
    module_id: String,
    module: Option<Arc<dyn LookupModule>>,
    raw_config: Value,
    /// The config with secrets resolved, or why it couldn't be (no call is made then).
    resolved: Result<Arc<Value>, Arc<str>>,
    redactor: Arc<Redactor>,
    ctx: Arc<LookupCtx>,
}

/// A call in flight: single-flight joins it, and its result is broadcast to every waiter.
struct Flight {
    gen_key: u64,
    epoch: u64,
    /// The verdict-set activation count when the call started: a call that spans an activation
    /// doesn't fill the RAM tier.
    activation: u64,
    /// The call's own `async_timeout_ms`.
    limit: Duration,
    generation: Arc<str>,
    tx: watch::Sender<Option<Arc<CallDone>>>,
    late: Mutex<LateWaiters>,
}

#[derive(Default)]
struct LateWaiters {
    done: bool,
    timed_out: bool,
    tags: Vec<Arc<str>>,
}

#[derive(Debug)]
struct CallDone {
    result: CallResult,
    elapsed: Duration,
    /// The call ran out of `async_timeout_ms`.
    timed_out: bool,
    storable: bool,
}

#[derive(Clone, Debug)]
enum CallResult {
    Answer {
        verdict: StoredVerdict,
        detail: Option<Arc<Value>>,
        obtained_at: Timestamp,
    },
    Error {
        kind: ErrorKind,
        message: Arc<str>,
    },
    Rejected {
        retry_after: Option<Duration>,
    },
    Cancelled,
}

struct SetHook(Arc<dyn VerdictSet>);

/// What a verdict-set read found ([`LookupClient::read_set`]).
enum SetRead {
    /// A live record of the current generation, from the active set.
    Hit(StoredVerdict, Timestamp),
    Miss,
    /// The generation moved on, or another set became active, while the read ran: start again.
    Stale,
}
struct LateHook(LateSink);

struct Inner {
    id: Arc<str>,
    role: Role,
    registry: Arc<Registry>,
    connections: ConnectionFactory,
    clock: Arc<dyn Clock>,
    cancel: CancellationToken,
    spec: ArcSwap<Spec>,
    update_lock: Mutex<()>,
    ram: Option<RamTier>,
    set: ArcSwapOption<SetHook>,
    late: ArcSwapOption<LateHook>,
    flights: Mutex<HashMap<Arc<str>, Arc<Flight>>>,
    adm: Mutex<Admission>,
    adm_notify: Notify,
    /// Moves on with every flush of the RAM tier.
    epoch: AtomicU64,
    /// The current generation's key, so waiters learn at once that their call's generation is
    /// no longer current.
    gen_tx: watch::Sender<u64>,
    /// Verdict-set activations so far. A call stores into the RAM tier only under this lock and
    /// only if no activation began since it started.
    activation: Mutex<u64>,
    metrics: Metrics,
}

/// How waiting for a call ended.
enum Waited {
    /// Its result (`None` if the call ended without one).
    Done(Option<Arc<CallDone>>),
    /// Its generation is no longer current.
    Stale,
}

/// The client of one lookup provider. Cloning shares it; dropping the last handle cancels its
/// calls.
#[derive(Clone)]
pub struct LookupClient {
    inner: Arc<Inner>,
    _cancel_on_drop: Arc<DropGuard>,
}

impl std::fmt::Debug for LookupClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LookupClient")
            .field("id", &self.inner.id)
            .field("role", &self.inner.role)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A generation as a number for cheap per-entry checks: the 16-hex-character id itself, or a
/// hash of anything else.
fn generation_key(g: &str) -> u64 {
    if picket_api::ids::is_id64(g)
        && let Ok(v) = u64::from_str_radix(g, 16)
    {
        return v;
    }
    // FNV-1a.
    g.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn async_timeout(s: &LookupSettings) -> Duration {
    Duration::from_millis(u64::from(s.async_timeout_ms.max(1))).min(MAX_ASYNC_TIMEOUT)
}

fn sync_timeout(s: &LookupSettings) -> Duration {
    Duration::from_millis(u64::from(s.sync_timeout_ms.max(1))).min(MAX_SYNC_TIMEOUT)
}

/// `s` cut to at most `max` bytes at a character boundary.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut n = max;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s.get(..n).unwrap_or("")
}

impl LookupClient {
    /// Builds the client of one lookup provider. A module the registry doesn't know, or a
    /// config whose secrets can't be resolved, still makes a client: its cache tiers answer and
    /// every call fails with an `Other` error naming the problem.
    pub fn new(spec: ProviderSpec, secrets: &BTreeMap<String, String>, opts: ClientOptions) -> Self {
        let cancel = CancellationToken::new();
        let now = Instant::now();
        let ram = (opts.role == Role::Edge).then(|| RamTier::new(&spec.settings.cache));
        let adm = Admission::new(&spec.settings, now);
        let id: Arc<str> = spec.id.as_str().into();
        let built = build_spec(&spec, secrets, &opts, &cancel, None);
        let gen_key = built.gen_key;
        let inner = Arc::new(Inner {
            id,
            role: opts.role,
            registry: opts.registry,
            connections: opts.connections,
            clock: opts.clock,
            cancel: cancel.clone(),
            spec: ArcSwap::from_pointee(built),
            update_lock: Mutex::new(()),
            ram,
            set: ArcSwapOption::empty(),
            late: ArcSwapOption::empty(),
            flights: Mutex::new(HashMap::new()),
            adm: Mutex::new(adm),
            adm_notify: Notify::new(),
            epoch: AtomicU64::new(0),
            gen_tx: watch::Sender::new(gen_key),
            activation: Mutex::new(0),
            metrics: Metrics::default(),
        });
        Self {
            inner,
            _cancel_on_drop: Arc::new(cancel.drop_guard()),
        }
    }

    /// The lookup provider id.
    pub fn id(&self) -> &str {
        &self.inner.id
    }

    pub fn role(&self) -> Role {
        self.inner.role
    }

    /// The current `cache_generation`.
    pub fn generation(&self) -> Arc<str> {
        self.inner.spec.load().generation.clone()
    }

    /// The current settings.
    pub fn settings(&self) -> LookupSettings {
        self.inner.spec.load().settings.clone()
    }

    /// The module id.
    pub fn module_id(&self) -> String {
        self.inner.spec.load().module_id.clone()
    }

    /// The reply's deadline for a query that started at `query_start` (edge.md §10
    /// "Execution"): `min(sync_timeout_ms, lookup_budget_ms)` after it.
    pub fn sync_deadline(&self, query_start: Instant, lookup_budget_ms: u32) -> Instant {
        let s = self.inner.spec.load();
        let budget = Duration::from_millis(u64::from(lookup_budget_ms));
        query_start + sync_timeout(&s.settings).min(budget)
    }

    /// Applies a new definition in place (edge.md §13 "Lookup clients survive config
    /// activations"): the RAM tier, breaker, pause and token bucket stay. A new
    /// `cache_generation` empties the RAM tier (its entries would be misses anyway); a new
    /// module or config replaces the provider's connections; a new secret value re-resolves the
    /// config and keeps the cached verdicts.
    pub fn update(&self, spec: ProviderSpec, secrets: &BTreeMap<String, String>) -> UpdateEffect {
        let _serial = lock(&self.inner.update_lock);
        let old = self.inner.spec.load_full();
        let config_changed = old.module_id != spec.module || old.raw_config != spec.config;
        let generation_changed = *old.generation != *spec.generation;
        let opts = ClientOptions {
            role: self.inner.role,
            registry: self.inner.registry.clone(),
            connections: self.inner.connections.clone(),
            clock: self.inner.clock.clone(),
        };
        let keep_ctx = (!config_changed).then(|| old.ctx.clone());
        let built = build_spec(&spec, secrets, &opts, &self.inner.cancel, keep_ctx);
        let gen_key = built.gen_key;
        self.inner.spec.store(Arc::new(built));
        if generation_changed {
            // Waiters on calls of the old generation start again under this one.
            self.inner.gen_tx.send_replace(gen_key);
        }
        if let Some(ram) = &self.inner.ram {
            ram.set_capacity(&spec.settings.cache);
            if generation_changed {
                ram.clear();
            }
        }
        // A larger max_inflight or a refilled bucket may admit waiters now.
        self.inner.adm_notify.notify_waiters();
        UpdateEffect {
            generation_changed,
            config_changed,
        }
    }

    /// Sets (or removes) the verdict-set tier, leaving the RAM tier as it is. A new head is
    /// activated with [`Self::activate_set_delta`] or [`Self::activate_set_base`].
    pub fn set_verdict_set(&self, set: Option<Arc<dyn VerdictSet>>) {
        self.inner.set.store(set.map(|s| Arc::new(SetHook(s))));
    }

    /// Sets (or removes) the receiver of late answers.
    pub fn set_late_sink(&self, sink: Option<LateSink>) {
        self.inner.late.store(sink.map(|s| Arc::new(LateHook(s))));
    }

    /// Empties the RAM tier (providers.md §4 "Flush": `flush.lookups.<provider>`,
    /// `picket-edge flush-cache --lookups`); the verdict set still answers. Calls in flight
    /// aren't stored when they end.
    pub fn flush(&self) {
        self.inner.epoch.fetch_add(1, Ordering::AcqRel);
        if let Some(ram) = &self.inner.ram {
            ram.clear();
        }
    }

    /// Activates a verdict-set head that is a delta (edge.md §10): drops the RAM-tier entries
    /// the delta supersedes, then swaps the set in, so no query sees the new set behind an older
    /// RAM entry. `changed` holds each record the delta adds or replaces, by the name's 128-bit
    /// hash with its `obtained_at`, and `hash` computes that hash for a name (`xxh3_128` with
    /// the set's `hash_seed`, providers.md §4 "Verdict sets"). A RAM entry obtained after the
    /// record stays. Returns how many entries were dropped.
    pub fn activate_set_delta(
        &self,
        set: Arc<dyn VerdictSet>,
        hash: impl Fn(&str) -> u128,
        changed: impl IntoIterator<Item = (u128, Timestamp)>,
    ) -> usize {
        let mut records: HashMap<u128, Timestamp> = HashMap::new();
        for (h, at) in changed {
            let e = records.entry(h).or_insert(at);
            *e = (*e).max(at);
        }
        if records.is_empty() {
            self.set_verdict_set(Some(set));
            return 0;
        }
        self.activate(set, |name| records.get(&hash(name)).copied())
    }

    /// Activates a verdict-set head with a new base (edge.md §10): `held_at` gives, for a name
    /// in the RAM tier, the `obtained_at` of the new head's record for it, if it holds one (a
    /// page read, say); every entry the head holds a record for with an equal or later
    /// `obtained_at` is dropped, then the set is swapped in. `held_at` runs with no RAM-tier
    /// lock held, so lookups go on meanwhile; call this off the hot path (e.g. in a blocking
    /// thread). Returns how many entries were dropped.
    pub fn activate_set_base(
        &self,
        set: Arc<dyn VerdictSet>,
        held_at: impl FnMut(&str) -> Option<Timestamp>,
    ) -> usize {
        self.activate(set, held_at)
    }

    /// The drop is part of the activation (edge.md §10): calls that started before it don't
    /// fill the RAM tier when they end ([`CallGuard::complete`]), so none can put back an entry
    /// the new set supersedes after its name was checked; the entries already there are checked
    /// and dropped; then the set is swapped in. A call that starts after this point answers
    /// later than any record the head holds, and its entry stays, as a newer one should.
    fn activate(
        &self,
        set: Arc<dyn VerdictSet>,
        mut held_at: impl FnMut(&str) -> Option<Timestamp>,
    ) -> usize {
        {
            let mut n = lock(&self.inner.activation);
            *n = n.wrapping_add(1);
        }
        let dropped = self.inner.ram.as_ref().map_or(0, |ram| {
            let now = self.inner.clock.now();
            // Timestamps are clamped to the receiver's clock (README §2).
            ram.drop_superseded(|name| held_at(name).map(|at| clamp_to_now(at, now)))
        });
        self.set_verdict_set(Some(set));
        dropped
    }

    /// The heartbeat's `lookups.<provider>` (api.md §3).
    pub fn metrics(&self) -> LookupMetrics {
        let breaker_open = lock(&self.inner.adm).breaker_open(Instant::now());
        let ram = self
            .inner
            .ram
            .as_ref()
            .map(|r| (r.evictions(), r.len(), r.bytes()));
        self.inner.metrics.snapshot(breaker_open, ram)
    }

    /// Until when the provider is paused after a rejection (providers.md §4 "Rejections"), while
    /// it is: what the client's own calls and lookups see, without making one (core's
    /// `lookup_provider_down`, core.md §9). `None` while not paused, its probe call included.
    pub fn paused_until(&self) -> Option<Instant> {
        lock(&self.inner.adm).paused_until(Instant::now())
    }

    /// Provider calls in flight now.
    pub fn inflight(&self) -> u32 {
        lock(&self.inner.adm).inflight()
    }

    // -----------------------------------------------------------------------------------------
    // Sync (edge)

    /// One sync lookup (edge.md §10): the RAM tier, then the verdict set, then a call (joining
    /// one in flight for the name), waiting until `req.deadline`. Never waits past it.
    pub async fn lookup_sync(&self, req: SyncRequest<'_>) -> SyncOutcome {
        let start = Instant::now();
        let done = |result: SyncResult, generation: Arc<str>| SyncOutcome {
            result,
            generation,
            elapsed: start.elapsed(),
        };
        let Some(name) = check_name(req.name) else {
            return done(
                SyncResult::Verdict {
                    verdict: StoredVerdict::Unknown,
                    source: Source::NameCheck,
                    obtained_at: None,
                    detail: None,
                },
                self.generation(),
            );
        };
        // A generation that moves on during the lookup starts it again under the new one
        // (providers.md §4 "Cache generation": in-flight results from an old generation are
        // never used). Every wait ends at the deadline; past it, a new attempt only starts the
        // new generation's call, whose late answer is then logged.
        for _ in 0..=MAX_RESTARTS {
            if let Some((result, generation)) = self.sync_attempt(&name, &req).await {
                return done(result, generation);
            }
        }
        Metrics::inc(&self.inner.metrics.timeouts);
        done(SyncResult::Timeout, self.generation())
    }

    /// One pass of [`Self::lookup_sync`]; `None` when the generation moved on before it could
    /// decide.
    async fn sync_attempt(&self, name: &str, req: &SyncRequest<'_>) -> Option<(SyncResult, Arc<str>)> {
        let tiers = self.inner.spec.load_full();
        let m = &self.inner.metrics;
        let decided = |result: SyncResult| Some((cache_only(req.call, result), tiers.generation.clone()));

        let mut cached_error = None;
        if let Some(ram) = &self.inner.ram {
            let epoch = self.inner.epoch.load(Ordering::Acquire);
            match ram.get(name, &tiers.settings.cache, tiers.gen_key, epoch, Instant::now()) {
                RamLookup::Verdict { verdict, obtained_at } => {
                    Metrics::inc(&m.cache_hits);
                    return decided(SyncResult::Verdict {
                        verdict,
                        source: Source::Ram,
                        obtained_at: Some(obtained_at),
                        detail: None,
                    });
                }
                RamLookup::Error(kind) => cached_error = Some(kind),
                RamLookup::Miss => {}
            }
        }
        match self.read_set(name, &tiers, req.deadline).await {
            SetRead::Hit(verdict, obtained_at) => {
                Metrics::inc(&m.set_hits);
                return decided(SyncResult::Verdict {
                    verdict,
                    source: Source::Set,
                    obtained_at: Some(obtained_at),
                    detail: None,
                });
            }
            SetRead::Stale => return None,
            SetRead::Miss => {}
        }
        if let Some(kind) = cached_error {
            Metrics::inc(&m.cache_hits);
            return decided(SyncResult::Error {
                kind,
                message: "an error cached in the RAM tier".into(),
                cached: true,
            });
        }
        Metrics::inc(&m.cache_misses);
        if !req.call {
            return Some((SyncResult::Miss, tiers.generation.clone()));
        }

        // The call starts under the settings current now, not those from before the set read
        // (edge.md §13); if the generation moved on meanwhile, the tiers were read for the old
        // one, so start again.
        let spec = self.inner.spec.load_full();
        if spec.gen_key != tiers.gen_key {
            return None;
        }
        let name: Arc<str> = Arc::from(name);
        let generation = spec.generation.clone();
        match self.sync_flight(&name, &spec) {
            Err(Refusal::Paused { .. }) => {
                Metrics::inc(&m.paused);
                Some((SyncResult::Rejected { paused: true }, generation))
            }
            Err(Refusal::BreakerOpen { .. }) => Some((SyncResult::BreakerOpen, generation)),
            Err(Refusal::Limits { .. }) => Some((SyncResult::LimitsExhausted, generation)),
            Ok((flight, joined)) => {
                let r = self
                    .wait_sync(&flight, joined, req.deadline, req.tag.clone())
                    .await?;
                Some((r, flight.generation.clone()))
            }
        }
    }

    /// Joins the call in flight for `name`, or admits and starts one under `spec`.
    fn sync_flight(&self, name: &Arc<str>, spec: &Arc<Spec>) -> Result<(Arc<Flight>, bool), Refusal> {
        let now = Instant::now();
        let epoch = self.inner.epoch.load(Ordering::Acquire);
        let mut flights = lock(&self.inner.flights);
        // While paused, sync lookups apply the fail mode at once (providers.md §4), even ones
        // that would join the probe.
        if let Some(until) = lock(&self.inner.adm).paused_until(now) {
            return Err(Refusal::Paused { until });
        }
        if let Some(f) = flights.get(name)
            && f.gen_key == spec.gen_key
            && f.epoch == epoch
        {
            return Ok((f.clone(), true));
        }
        let ticket = lock(&self.inner.adm).try_admit(now, &spec.settings)?;
        let flight = Arc::new(Flight::new(spec, epoch, *lock(&self.inner.activation)));
        flights.insert(name.clone(), flight.clone());
        drop(flights);
        self.spawn_call(flight.clone(), ticket, spec.clone(), name.clone(), true, true);
        Ok((flight, false))
    }

    /// True while the flight's generation is the current one.
    fn is_current(&self, flight: &Flight) -> bool {
        flight.gen_key == self.inner.spec.load().gen_key
    }

    /// Waits for the flight's result, or until its generation stops being current.
    async fn wait_flight(&self, flight: &Flight) -> Waited {
        let mut rx = flight.tx.subscribe();
        let mut gen_rx = self.inner.gen_tx.subscribe();
        tokio::select! {
            r = rx.wait_for(Option::is_some) => Waited::Done(r.ok().and_then(|v| v.clone())),
            Ok(_) = gen_rx.wait_for(|k| *k != flight.gen_key) => Waited::Stale,
            else => Waited::Done(None),
        }
    }

    /// Waits for the flight until `deadline`. `None` once its generation is no longer current
    /// (providers.md §4 "Cache generation": in-flight results from an old generation are never
    /// used): the caller starts again under the new one.
    async fn wait_sync(
        &self,
        flight: &Arc<Flight>,
        joined: bool,
        deadline: Instant,
        tag: Option<Arc<str>>,
    ) -> Option<SyncResult> {
        let waited = tokio::time::timeout_at(deadline, self.wait_flight(flight)).await;
        let done = match waited {
            Ok(Waited::Done(d)) => d,
            Ok(Waited::Stale) => return None,
            Err(_) => {
                if !self.is_current(flight) {
                    return None;
                }
                let mut late = lock(&flight.late);
                if late.done {
                    // The answer came just as the deadline passed.
                    drop(late);
                    flight.tx.borrow().clone()
                } else {
                    late.timed_out = true;
                    if let Some(tag) = tag
                        && late.tags.len() < MAX_LATE_TAGS
                        && !late.tags.contains(&tag)
                    {
                        late.tags.push(tag);
                    }
                    drop(late);
                    Metrics::inc(&self.inner.metrics.timeouts);
                    return Some(SyncResult::Timeout);
                }
            }
        };
        if !self.is_current(flight) {
            return None;
        }
        let Some(done) = done else {
            return Some(SyncResult::Error {
                kind: ErrorKind::Other,
                message: "the call ended without a result".into(),
                cached: false,
            });
        };
        Some(match &done.result {
            CallResult::Answer {
                verdict,
                detail,
                obtained_at,
            } => SyncResult::Verdict {
                verdict: verdict.clone(),
                source: if joined { Source::Joined } else { Source::Call },
                obtained_at: Some(*obtained_at),
                detail: detail.clone(),
            },
            CallResult::Error { .. } if done.timed_out => {
                Metrics::inc(&self.inner.metrics.timeouts);
                SyncResult::Timeout
            }
            CallResult::Error { kind, message } => SyncResult::Error {
                kind: *kind,
                message: message.clone(),
                cached: false,
            },
            CallResult::Rejected { .. } => SyncResult::Rejected { paused: false },
            CallResult::Cancelled => SyncResult::Error {
                kind: ErrorKind::Other,
                message: "cancelled".into(),
                cached: false,
            },
        })
    }

    /// The verdict set's live record for `name`, if any (generation and expiry checked).
    ///
    /// The read can span an update or an activation (it may wait on a page read): its record is
    /// used only if, once it completes, the provider's generation is still `spec`'s and the set it
    /// came from is still the active one. Otherwise it is [`SetRead::Stale`] and the lookup starts
    /// again under the current ones, so an old generation's Block never decides, and its Clean
    /// never skips the fail mode (providers.md §4 "Cache generation"; edge.md §10; review round
    /// 2, CR6).
    async fn read_set(&self, name: &str, spec: &Spec, deadline: Instant) -> SetRead {
        let Some(hook) = self.inner.set.load_full() else {
            return SetRead::Miss;
        };
        let read = tokio::time::timeout_at(deadline, hook.0.get(name)).await;
        let same_set = self
            .inner
            .set
            .load()
            .as_ref()
            .is_some_and(|now| Arc::ptr_eq(now, &hook));
        if !same_set || self.inner.spec.load().gen_key != spec.gen_key {
            return SetRead::Stale;
        }
        let Some(rec) = read.ok().and_then(Result::ok).flatten() else {
            return SetRead::Miss;
        };
        if *rec.generation != *spec.generation {
            return SetRead::Miss;
        }
        let now = self.inner.clock.now();
        // Timestamps are clamped to the receiver's clock (README §2).
        let obtained_at = clamp_to_now(rec.obtained_at, now);
        let ttl = ttl_for(&spec.settings.cache, &RamResult::Verdict(rec.verdict.clone()));
        // A TTL reaching past the end of jiff's range never expires.
        if now < obtained_at.checked_add(ttl).unwrap_or(Timestamp::MAX) {
            SetRead::Hit(rec.verdict, obtained_at)
        } else {
            SetRead::Miss
        }
    }

    // -----------------------------------------------------------------------------------------
    // Async (core)

    /// One async lookup (core.md §7).
    pub async fn lookup_async(&self, name: &str, opts: AsyncOptions) -> AsyncOutcome {
        let store = true;
        let register = !opts.skip_cache;
        self.lookup_async_inner(name, opts.skip_cache, store, register, opts.one_attempt)
            .await
    }

    /// Runs the provider's self-test once (providers.md §4 "Self-tests"): it skips the verdict
    /// cache, and its result is never cached; limits, the breaker and pauses still apply. `None`
    /// when the module names no self-test for this config.
    pub async fn run_self_test(&self) -> Option<SelfTestRun> {
        let spec = self.inner.spec.load_full();
        let module = spec.module.as_ref()?;
        // A test's name and schedule don't depend on secrets: with one missing, the test still
        // runs (and its call fails, which isn't a failed test).
        let cfg = spec.resolved.as_deref().unwrap_or(&spec.raw_config);
        let test = module.self_test(cfg)?;
        let outcome = self
            .lookup_async_inner(&test.name, true, false, false, false)
            .await;
        let result = SelfTestResult::judge(test.expect, &outcome);
        Some(SelfTestRun { test, result })
    }

    async fn lookup_async_inner(
        &self,
        name: &str,
        skip_cache: bool,
        store: bool,
        register: bool,
        one_attempt: bool,
    ) -> AsyncOutcome {
        let start = Instant::now();
        let done = |result: AsyncResult, generation: Arc<str>| AsyncOutcome {
            result,
            generation,
            elapsed: start.elapsed(),
        };
        let Some(name) = check_name(name) else {
            return done(AsyncResult::NameCheck, self.generation());
        };
        let name: Arc<str> = Arc::from(&*name);
        // The wait for a slot and a token ends async_timeout_ms after the lookup started.
        let deadline = start + async_timeout(&self.inner.spec.load().settings);
        let call = AsyncCall {
            skip_cache,
            store,
            register,
            deadline,
            one_attempt,
        };
        // A generation that moves on during the lookup starts it again under the new one
        // (providers.md §4 "Cache generation"), unless the caller asked for one attempt.
        let tries = if one_attempt { 1 } else { MAX_RESTARTS + 1 };
        for _ in 0..tries {
            if let Some((result, generation)) = self.async_attempt(&name, call).await {
                return done(result, generation);
            }
        }
        if one_attempt {
            // It moved on before a call was made.
            return done(AsyncResult::GenerationMoved { called: false }, self.generation());
        }
        done(
            AsyncResult::Error {
                kind: ErrorKind::Other,
                message: "the cache generation kept moving on during the lookup".into(),
                timed_out: false,
            },
            self.generation(),
        )
    }

    /// One pass of an async lookup; `None` when the generation moved on before it could
    /// decide (with `one_attempt`, after its call: [`AsyncResult::GenerationMoved`]).
    async fn async_attempt(&self, name: &Arc<str>, call: AsyncCall) -> Option<(AsyncResult, Arc<str>)> {
        let m = &self.inner.metrics;
        let tiers = self.inner.spec.load_full();
        if !call.skip_cache {
            if let Some(ram) = &self.inner.ram {
                let epoch = self.inner.epoch.load(Ordering::Acquire);
                if let RamLookup::Verdict { verdict, obtained_at } =
                    ram.get(name, &tiers.settings.cache, tiers.gen_key, epoch, Instant::now())
                {
                    Metrics::inc(&m.cache_hits);
                    let result = AsyncResult::Cached {
                        verdict,
                        obtained_at,
                        source: Source::Ram,
                    };
                    return Some((result, tiers.generation.clone()));
                }
            }
            match self.read_set(name, &tiers, call.deadline).await {
                SetRead::Hit(verdict, obtained_at) => {
                    Metrics::inc(&m.set_hits);
                    let result = AsyncResult::Cached {
                        verdict,
                        obtained_at,
                        source: Source::Set,
                    };
                    return Some((result, tiers.generation.clone()));
                }
                SetRead::Stale => return None,
                SetRead::Miss => {}
            }
            Metrics::inc(&m.cache_misses);
        }

        let epoch = self.inner.epoch.load(Ordering::Acquire);
        // Wait for an inflight slot and a token (core's queue is paced by the bucket), joining a
        // call that starts meanwhile. Each try reads the settings current then (edge.md §13), so
        // a call admitted after an update runs with its limits, config and connections.
        let (flight, joined) = loop {
            let notified = self.inner.adm_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let retry_in = {
                let spec = self.inner.spec.load_full();
                if spec.gen_key != tiers.gen_key {
                    // The tiers were read for the old generation: start again.
                    return None;
                }
                let mut flights = lock(&self.inner.flights);
                if !call.skip_cache
                    && let Some(f) = flights.get(name)
                    && f.gen_key == spec.gen_key
                    && f.epoch == epoch
                {
                    break (f.clone(), true);
                }
                // Right before the call, after any wait for a slot or a token: no call on a clock
                // that can't stamp its answer (README §2 Clocks; joining another's call makes
                // none).
                if !self.inner.clock.synced() {
                    return Some((AsyncResult::ClockUnsynced, spec.generation.clone()));
                }
                let now = Instant::now();
                let admitted = lock(&self.inner.adm).try_admit(now, &spec.settings);
                match admitted {
                    Ok(ticket) => {
                        let flight = Arc::new(Flight::new(&spec, epoch, *lock(&self.inner.activation)));
                        if call.register {
                            flights.insert(name.clone(), flight.clone());
                        }
                        drop(flights);
                        self.spawn_call(
                            flight.clone(),
                            ticket,
                            spec.clone(),
                            name.clone(),
                            call.register,
                            call.store,
                        );
                        break (flight, false);
                    }
                    Err(Refusal::Paused { until }) => {
                        Metrics::inc(&m.paused);
                        return Some((AsyncResult::Paused { until }, spec.generation.clone()));
                    }
                    Err(Refusal::BreakerOpen { until }) => {
                        return Some((AsyncResult::BreakerOpen { until }, spec.generation.clone()));
                    }
                    Err(Refusal::Limits { retry_in }) => retry_in,
                }
            };
            let nap = retry_in.unwrap_or(Duration::from_secs(1));
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep(nap) => {}
                _ = tokio::time::sleep_until(call.deadline) => {
                    return Some((AsyncResult::LimitsExhausted, tiers.generation.clone()));
                }
                _ = self.inner.cancel.cancelled() => {
                    return Some((AsyncResult::Cancelled, tiers.generation.clone()));
                }
            }
        };

        // The call ends by itself within its async_timeout_ms; the margin only guards against a
        // waiter outliving a lost task.
        let waited =
            tokio::time::timeout(flight.limit + Duration::from_secs(1), self.wait_flight(&flight)).await;
        // Past this point the lookup made its call (or joined one).
        let moved = || {
            call.one_attempt.then(|| {
                (
                    AsyncResult::GenerationMoved { called: !joined },
                    self.generation(),
                )
            })
        };
        let finished = match waited {
            Ok(Waited::Done(d)) => d,
            Ok(Waited::Stale) => return moved(),
            Err(_) => None,
        };
        // In-flight results from an old generation are never used (providers.md §4).
        if !self.is_current(&flight) {
            return moved();
        }
        let generation = flight.generation.clone();
        let Some(done) = finished else {
            Metrics::inc(&m.timeouts);
            let result = AsyncResult::Error {
                kind: ErrorKind::Failed,
                message: "no result within async_timeout_ms".into(),
                timed_out: true,
            };
            return Some((result, generation));
        };
        let result = match &done.result {
            CallResult::Answer {
                verdict,
                detail,
                obtained_at,
            } => AsyncResult::Answer {
                verdict: verdict.clone(),
                obtained_at: *obtained_at,
                detail: detail.clone(),
                source: if joined { Source::Joined } else { Source::Call },
                storable: done.storable,
            },
            CallResult::Error { kind, message } => {
                if done.timed_out {
                    Metrics::inc(&m.timeouts);
                }
                AsyncResult::Error {
                    kind: *kind,
                    message: message.clone(),
                    timed_out: done.timed_out,
                }
            }
            CallResult::Rejected { retry_after } => AsyncResult::Rejected {
                retry_after: *retry_after,
            },
            CallResult::Cancelled => AsyncResult::Cancelled,
        };
        Some((result, generation))
    }

    // -----------------------------------------------------------------------------------------
    // Calls

    fn spawn_call(
        &self,
        flight: Arc<Flight>,
        ticket: Ticket,
        spec: Arc<Spec>,
        name: Arc<str>,
        registered: bool,
        store: bool,
    ) {
        let inner = self.inner.clone();
        Metrics::inc(&inner.metrics.calls);
        tokio::spawn(async move {
            let mut guard = CallGuard {
                inner,
                flight,
                ticket,
                name,
                registered,
                finished: false,
            };
            let started = Instant::now();
            let (result, timed_out) = run_module(&guard.inner, &spec, &guard.name).await;
            guard.complete(result, started.elapsed(), timed_out, store);
        });
    }
}

/// How an async lookup runs: see [`LookupClient::lookup_async`] and
/// [`LookupClient::run_self_test`].
#[derive(Clone, Copy)]
struct AsyncCall {
    skip_cache: bool,
    store: bool,
    register: bool,
    /// When the wait for a slot and a token gives up.
    deadline: Instant,
    /// See [`AsyncOptions::one_attempt`].
    one_attempt: bool,
}

impl Flight {
    fn new(spec: &Spec, epoch: u64, activation: u64) -> Self {
        Self {
            gen_key: spec.gen_key,
            epoch,
            activation,
            limit: async_timeout(&spec.settings),
            generation: spec.generation.clone(),
            tx: watch::Sender::new(None),
            late: Mutex::new(LateWaiters::default()),
        }
    }
}

/// A cache-only lookup (a query type outside `scope.qtypes`, or `ANY`) is decided only by a
/// live Block (edge.md §10): anything else is a miss, so no fail mode applies to it.
fn cache_only(call: bool, result: SyncResult) -> SyncResult {
    match result {
        SyncResult::Verdict {
            verdict: StoredVerdict::Block { .. },
            ..
        } => result,
        _ if !call => SyncResult::Miss,
        _ => result,
    }
}

/// Builds a settings snapshot; `keep_ctx` reuses the connections when the config is unchanged.
fn build_spec(
    spec: &ProviderSpec,
    secrets: &BTreeMap<String, String>,
    opts: &ClientOptions,
    cancel: &CancellationToken,
    keep_ctx: Option<Arc<LookupCtx>>,
) -> Spec {
    let module = opts.registry.get(&spec.module);
    let (resolved, redactor) = match secrets::resolve(&spec.config, secrets) {
        Ok(r) => (Ok(Arc::new(r.config)), Arc::new(r.redactor)),
        Err(e) => (Err(Arc::from(e.to_string())), Arc::new(Redactor::default())),
    };
    let resolved = match (&module, resolved) {
        (None, _) => Err(Arc::from(format!(
            "unknown lookup module {:?}",
            cut(&spec.module, 64)
        ))),
        (Some(_), r) => r,
    };
    let ctx = keep_ctx.unwrap_or_else(|| {
        Arc::new(LookupCtx::new(
            &spec.id,
            (opts.connections)(&spec.id),
            opts.clock.clone(),
            cancel.child_token(),
        ))
    });
    Spec {
        settings: spec.settings.clone(),
        generation: spec.generation.as_str().into(),
        gen_key: generation_key(&spec.generation),
        module_id: spec.module.clone(),
        module,
        raw_config: spec.config.clone(),
        resolved,
        redactor,
        ctx,
    }
}

/// Runs the module once, within `async_timeout_ms`, catching a panic. Returns the result and
/// whether the call ran out of time.
async fn run_module(inner: &Inner, spec: &Spec, name: &str) -> (CallResult, bool) {
    let other = |m: &str| CallResult::Error {
        kind: ErrorKind::Other,
        message: m.into(),
    };
    let (module, cfg) = match (&spec.module, &spec.resolved) {
        (Some(m), Ok(c)) => (m, c),
        (_, Err(msg)) => return (other(msg), false),
        (None, Ok(_)) => return (other("unknown lookup module"), false),
    };
    let limit = async_timeout(&spec.settings);
    // The module learns when this call is dropped, to fit its own timeouts into it.
    let ctx = spec.ctx.with_deadline(Instant::now() + limit);
    let call = AssertUnwindSafe(module.lookup(&ctx, cfg, name)).catch_unwind();
    tokio::select! {
        biased;
        _ = inner.cancel.cancelled() => (CallResult::Cancelled, false),
        r = tokio::time::timeout(limit, call) => match r {
            Err(_) => (
                CallResult::Error {
                    kind: ErrorKind::Failed,
                    message: format!("no answer within {} ms", limit.as_millis()).into(),
                },
                true,
            ),
            Ok(Err(_panic)) => (other("the lookup module panicked"), false),
            Ok(Ok(Ok(answer))) => {
                let verdict = sanitize_verdict(&answer.verdict, &spec.redactor);
                let detail = answer
                    .detail
                    .and_then(|d| sanitize_detail(d, &spec.redactor))
                    .map(Arc::new);
                let obtained_at = inner.clock.now();
                (CallResult::Answer { verdict, detail, obtained_at }, false)
            }
            Ok(Ok(Err(e))) => (error_result(e, &spec.redactor), false),
        },
    }
}

fn error_result(e: LookupError, redactor: &Redactor) -> CallResult {
    let message = |e: &anyhow::Error| -> Arc<str> {
        let text = redactor.redact(&format!("{e:#}"));
        cut(&text, MAX_MESSAGE).into()
    };
    match e {
        LookupError::Rejected { retry_after } => CallResult::Rejected { retry_after },
        LookupError::Failed(e) => CallResult::Error {
            kind: ErrorKind::Failed,
            message: message(&e),
        },
        LookupError::Other(e) => CallResult::Error {
            kind: ErrorKind::Other,
            message: message(&e),
        },
    }
}

/// A Block's reason redacted and cut to [`MAX_REASON`]; a score that isn't finite dropped.
fn sanitize_verdict(v: &crate::module::Verdict, redactor: &Redactor) -> StoredVerdict {
    match v {
        crate::module::Verdict::Block { score, reason } => {
            let reason = if redactor.is_empty() {
                cut(reason, MAX_REASON).to_owned()
            } else {
                cut(&redactor.redact(reason), MAX_REASON).to_owned()
            };
            StoredVerdict::Block {
                score: score.filter(|s| s.is_finite()),
                reason: reason.into(),
            }
        }
        other => StoredVerdict::from(other),
    }
}

/// The detail if it is a JSON object under [`DETAIL_MAX`] bytes serialised (providers.md §4
/// "Detail": a small JSON object; core drops a log record carrying anything else) and holds no
/// secret value; otherwise none.
fn sanitize_detail(d: Value, redactor: &Redactor) -> Option<Value> {
    if !d.is_object() {
        return None;
    }
    let text = serde_json::to_string(&d).ok()?;
    if !detail_fits(text.len()) {
        return None;
    }
    if !redactor.is_empty() && redactor.redact(&text) != text {
        return None;
    }
    Some(d)
}

/// Ends a call: settles admission, stores the result, wakes the waiters, hands a late answer
/// on and leaves the flight map. If the task ends without completing (runtime shutdown), its
/// drop does the bookkeeping with a cancelled result.
struct CallGuard {
    inner: Arc<Inner>,
    flight: Arc<Flight>,
    ticket: Ticket,
    name: Arc<str>,
    registered: bool,
    finished: bool,
}

impl CallGuard {
    fn complete(&mut self, result: CallResult, elapsed: Duration, timed_out: bool, store: bool) {
        self.finished = true;
        let inner = &self.inner;
        let m = &inner.metrics;
        let finish = match &result {
            CallResult::Answer { .. } => Finish::Answer,
            CallResult::Error {
                kind: ErrorKind::Failed,
                ..
            } => Finish::Failed,
            CallResult::Error {
                kind: ErrorKind::Other,
                ..
            }
            | CallResult::Cancelled => Finish::Other,
            CallResult::Rejected { retry_after } => Finish::Rejected(*retry_after),
        };
        if !matches!(result, CallResult::Cancelled) {
            m.record_call(elapsed);
        }
        match &result {
            CallResult::Error { .. } => Metrics::inc(&m.errors),
            CallResult::Rejected { .. } => Metrics::inc(&m.rejected),
            CallResult::Answer { .. } | CallResult::Cancelled => {}
        }
        let current = inner.spec.load_full();
        lock(&inner.adm).finish(self.ticket, finish, Instant::now(), &current.settings);
        inner.adm_notify.notify_waiters();

        // A verdict carries the generation current when its call started, and isn't stored if
        // the generation moved on or the cache was emptied after the call started.
        let gen_current = self.flight.gen_key == current.gen_key;
        let storable = gen_current && self.flight.epoch == inner.epoch.load(Ordering::Acquire);
        // Nor does a call that spans a verdict-set activation fill the RAM tier (edge.md §10):
        // the check and the insert hold the activation lock, so an activation either sees the
        // entry when it checks the tier or keeps it out.
        let activation = lock(&inner.activation);
        if store
            && storable
            && *activation == self.flight.activation
            && let Some(ram) = &inner.ram
        {
            let entry = match &result {
                CallResult::Answer {
                    verdict, obtained_at, ..
                } => Some((RamResult::Verdict(verdict.clone()), *obtained_at)),
                // Errors are cached on the edge only (providers.md §4), for error_ttl_s.
                CallResult::Error { kind, .. } => Some((RamResult::Error(*kind), inner.clock.now())),
                CallResult::Rejected { .. } | CallResult::Cancelled => None,
            };
            if let Some((result, obtained_at)) = entry {
                ram.insert(
                    &self.name,
                    RamEntry {
                        result,
                        obtained_at,
                        obtained_mono: Instant::now(),
                        gen_key: self.flight.gen_key,
                        epoch: self.flight.epoch,
                    },
                    &current.settings.cache,
                );
            }
        }
        drop(activation);

        let done = Arc::new(CallDone {
            result,
            elapsed,
            timed_out,
            storable,
        });
        self.flight.tx.send_replace(Some(done.clone()));
        let late_tags = {
            let mut late = lock(&self.flight.late);
            late.done = true;
            late.timed_out.then(|| std::mem::take(&mut late.tags))
        };
        self.leave_map();

        // Late answers (edge.md §10): logged so core's retry finds them; never from an old
        // generation.
        if let (Some(tags), true) = (late_tags, gen_current)
            && let CallResult::Answer {
                verdict,
                detail,
                obtained_at,
            } = &done.result
        {
            Metrics::inc(&m.late);
            if let Some(sink) = inner.late.load_full() {
                (sink.0)(LateAnswer {
                    provider: inner.id.clone(),
                    name: self.name.clone(),
                    verdict: verdict.clone(),
                    obtained_at: *obtained_at,
                    generation: self.flight.generation.clone(),
                    ms: u32::try_from(done.elapsed.as_millis()).unwrap_or(u32::MAX),
                    detail: detail.clone(),
                    tags,
                });
            }
        }
    }

    fn leave_map(&self) {
        if !self.registered {
            return;
        }
        let mut flights = lock(&self.inner.flights);
        if flights
            .get(&self.name)
            .is_some_and(|f| Arc::ptr_eq(f, &self.flight))
        {
            flights.remove(&self.name);
        }
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let current = self.inner.spec.load_full();
        lock(&self.inner.adm).finish(self.ticket, Finish::Other, Instant::now(), &current.settings);
        self.inner.adm_notify.notify_waiters();
        self.flight.tx.send_replace(Some(Arc::new(CallDone {
            result: CallResult::Cancelled,
            elapsed: Duration::ZERO,
            timed_out: false,
            storable: false,
        })));
        lock(&self.flight.late).done = true;
        self.leave_map();
    }
}

#[cfg(test)]
mod tests;
