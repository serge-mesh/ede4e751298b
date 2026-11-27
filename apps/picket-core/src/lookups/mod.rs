//! Async lookups, retries of failed sync lookups, re-checks and verdict sets (core.md §7;
//! providers.md §4 as core applies it).
//!
//! | Module | Job |
//! |---|---|
//! | [`store`] | `lookup_verdicts` (core's one verdict store: later `obtained_at` wins, tombstones, generations) and `lookup_blocks` |
//! | [`ingest`] | what the edges log: verdicts (`lookups[]` with `obtained_at`, `lookup` records), retries, async attachments, re-check deadlines, answers checked against Blocks |
//! | [`queue`] | `lookup_queue`: admission (dedup, live-entry settling, first-attempt delay), order, re-checks, execution in the light lane, backoff, drops |
//! | [`scope`] | a name against a profile's allow bundles, forward zones and a provider's or attachment's scope bundles |
//! | [`verdict_sets`] | publishing each `sync` provider's live rows as a verdict set (base + deltas), compaction, retention |
//! | [`answered`] | `category_answered` from provider Blocks |
//! | [`selftest`] | self-tests on core, `lookup_self_test_failed` |
//! | [`clients`] | core's HTTP and DNS server clients for lookup modules |
//! | [`api`] | the UI endpoints: modules and presets, flush, test, status, temporary allows |
//!
//! **Runtime** ([`Lookups`]): one [`picket_lookup::LookupClient`] per provider (role `Core`: no
//! RAM tier, no error cache; `lookup_verdicts` is checked by the queue itself), rebuilt or updated
//! in place on every configuration change, with the model snapshot the workers read. Every
//! client's connections follow core's current options (a new `resolver` reaches existing clients,
//! [`clients::LiveOptions`]). Any save of a provider (its config, settings, category, name or
//! preset) runs its self-test (providers.md §4). Workers: the queue dispatcher, the verdict-set
//! publisher, the self-test scheduler, the Block checker and a 30 s status sampler (queue
//! depths, breaker and pause, `lookup_provider_down`, core's call durations `lookup_call_ms`).

pub mod answered;
pub mod api;
pub mod clients;
pub mod ingest;
pub mod queue;
pub mod scope;
pub mod selftest;
pub mod store;
pub mod verdict_sets;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use jiff::Timestamp;
use picket_lookup::{ClientOptions, LookupClient, ProviderSpec, Registry, Role};
use tokio::sync::Notify;

use crate::config::Model;
use crate::config::model::LookupProviderDef;
use crate::state::{AppState, SharedState};

/// The compiled-in lookup modules (providers.md §1).
pub fn registry() -> &'static Registry {
    static R: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
    R.get_or_init(Registry::builtin)
}

/// The light-lane key of a provider's lookup jobs (its share of the lane, core.md §3).
pub fn lane_key(provider: &str) -> String {
    format!("lookup:{provider}")
}

/// What core observed of a provider's pause after a rejection (providers.md §4 "Rejections") and
/// its breaker, for the status, the gauges and `lookup_provider_down`.
#[derive(Clone, Debug, Default)]
pub struct ProviderRuntime {
    /// Paused (or breaker open) until about this wall time, as the last refused attempt said.
    pub paused_until: Option<Timestamp>,
    pub breaker_until: Option<Timestamp>,
    /// Since when the provider has been down (breaker open or paused, on core or an edge),
    /// monotonic; kept across gaps shorter than [`UP_GRACE`].
    pub down_since: Option<tokio::time::Instant>,
    /// The last sample that found it down.
    pub last_down: Option<tokio::time::Instant>,
    /// Core's client's call durations at the last sample (running totals), for `lookup_call_ms`,
    /// with the build of the client that counted them ([`Lookups::client_build`]).
    pub last_call_ms: Option<(u64, picket_api::Histogram)>,
}

/// Core's calls since the previous sample: the client's running totals less those of the
/// previous sample (`prev`). A rebuilt client counts from 0, so another build's totals are never
/// subtracted: then the totals are all new.
pub fn calls_since(
    prev: Option<&(u64, picket_api::Histogram)>,
    build: u64,
    now: &picket_api::Histogram,
) -> picket_api::Histogram {
    match prev {
        Some((b, p)) if *b == build && p.count <= now.count => now.delta(p),
        _ => now.clone(),
    }
}

/// How long a provider must look up before `lookup_provider_down`'s 15 minutes start again
/// (core.md §9): a rejection pause ends with one probe call, and the breaker half-opens between
/// open periods, so a sample can fall between two pauses of a provider that is still refusing.
/// Policy choice: four samples.
pub const UP_GRACE: Duration = Duration::from_secs(120);
/// An edge reports a provider paused while its heartbeats' `paused` or `rejected` totals moved
/// this recently (three heartbeats): the edge answers lookups at once while paused (api.md §3).
pub const EDGE_PAUSE_FRESH: Duration = Duration::from_secs(90);

/// One edge's last `lookups.<provider>` totals as the sampler saw them.
#[derive(Clone, Debug)]
struct EdgePause {
    boot: String,
    paused: u64,
    rejected: u64,
    /// When the totals last moved (monotonic).
    moved: Option<tokio::time::Instant>,
}

/// One built client and the definition it was built from.
struct Built {
    client: LookupClient,
    /// Which build of the provider's client this is: its running totals start from 0.
    build: u64,
    spec: ProviderSpec,
    secrets: BTreeMap<String, String>,
}

/// The lookups runtime (module docs).
pub struct Lookups {
    registry: ArcSwap<Registry>,
    clients: Mutex<HashMap<String, Built>>,
    /// The last client build handed out ([`Built::build`]).
    builds: std::sync::atomic::AtomicU64,
    model: ArcSwap<Model>,
    runtime: Mutex<HashMap<String, ProviderRuntime>>,
    /// Core's connection options every client follows (module docs).
    http: Arc<clients::LiveOptions>,
    /// The wall clock every client stamps `obtained_at` with.
    wall: Arc<clients::WallClock>,
    /// What each edge last reported of each provider's pause: (edge, provider).
    edge_pauses: Mutex<HashMap<(String, String), EdgePause>>,
    pub(crate) queue: queue::QueueState,
    pub(crate) sets: verdict_sets::SetsState,
    pub(crate) selftests: selftest::SelfTests,
    /// Wakes the Block checker ([`answered`]).
    pub(crate) blocks_wake: Notify,
    /// The counted answers running Block scans hold ([`answered::ScanHolds`]).
    pub(crate) scan_holds: Arc<answered::ScanHolds>,
    /// One reload at a time, so the model and the generation below only move forward.
    reload_lock: tokio::sync::Mutex<()>,
    /// The configuration generation ([`crate::config::ConfigStore::subscribe`]) the last good
    /// reload read core.db at or after; `None` before the first. "Test now" waits for it.
    loaded: tokio::sync::watch::Sender<Option<u64>>,
}

impl Default for Lookups {
    fn default() -> Self {
        Self::new()
    }
}

impl Lookups {
    pub fn new() -> Self {
        Self {
            registry: ArcSwap::from_pointee(registry().clone()),
            clients: Mutex::new(HashMap::new()),
            builds: std::sync::atomic::AtomicU64::new(0),
            model: ArcSwap::from_pointee(Model::default()),
            runtime: Mutex::new(HashMap::new()),
            http: Arc::new(clients::LiveOptions::default()),
            wall: Arc::new(clients::WallClock::default()),
            edge_pauses: Mutex::new(HashMap::new()),
            queue: queue::QueueState::default(),
            sets: verdict_sets::SetsState::default(),
            selftests: selftest::SelfTests::default(),
            blocks_wake: Notify::new(),
            scan_holds: Arc::default(),
            reload_lock: tokio::sync::Mutex::new(()),
            loaded: tokio::sync::watch::channel(None).0,
        }
    }

    /// Waits (at most `wait`) until the runtime has reloaded every configuration commit published
    /// before this call (a reload that fails leaves it waiting); false when it hasn't by then.
    pub async fn reloaded(&self, state: &AppState, wait: Duration) -> bool {
        let target = *state.config.subscribe().borrow();
        let mut rx = self.loaded.subscribe();
        tokio::time::timeout(wait, rx.wait_for(|g| g.is_some_and(|g| g >= target)))
            .await
            .is_ok_and(|r| r.is_ok())
    }

    /// The modules lookup providers are built from.
    pub fn modules(&self) -> Arc<Registry> {
        self.registry.load_full()
    }

    /// Replaces the module registry (tests add scripted modules) and rebuilds every client.
    pub async fn set_registry(&self, state: &AppState, registry: Registry) {
        self.registry.store(Arc::new(registry));
        if let Ok(mut c) = self.clients.lock() {
            c.clear();
        }
        let _ = self.reload(state).await;
    }

    /// The model snapshot the workers read (refreshed on every configuration change).
    pub fn model(&self) -> Arc<Model> {
        self.model.load_full()
    }

    /// Tests: shifts the wall clock core's lookup clients stamp `obtained_at` with by `offset`,
    /// simulating a boot clock that is wrong until NTP corrects it (README §2 Clocks); zero is
    /// the system clock.
    pub fn simulate_clock_offset(&self, offset: jiff::SignedDuration) {
        self.wall.set_offset(offset);
    }

    /// The wall clock the lookups read: the system clock (plus a test's simulated offset).
    pub fn now(&self) -> Timestamp {
        picket_lookup::Clock::now(&*self.wall)
    }

    /// The connection options the lookup clients use now (core's `resolver`, core.md §11).
    pub fn http_options(&self) -> Arc<crate::modules::download::client::HttpOptions> {
        self.http.get().1
    }

    /// The provider's client, if it exists.
    pub fn client(&self, provider: &str) -> Option<LookupClient> {
        self.clients
            .lock()
            .ok()
            .and_then(|c| c.get(provider).map(|b| b.client.clone()))
    }

    /// The provider's client with its build ([`Built::build`]).
    pub fn client_build(&self, provider: &str) -> Option<(u64, LookupClient)> {
        self.clients
            .lock()
            .ok()
            .and_then(|c| c.get(provider).map(|b| (b.build, b.client.clone())))
    }

    /// What core observed of a provider's pause and breaker.
    pub fn runtime(&self, provider: &str) -> ProviderRuntime {
        self.runtime
            .lock()
            .ok()
            .and_then(|m| m.get(provider).cloned())
            .unwrap_or_default()
    }

    pub(crate) fn update_runtime(&self, provider: &str, f: impl FnOnce(&mut ProviderRuntime)) {
        if let Ok(mut m) = self.runtime.lock() {
            f(m.entry(provider.to_string()).or_default());
        }
    }

    /// Reloads the model and reconciles the clients with it: new providers get a client, changed
    /// ones are updated in place (keeping breaker, pause and token bucket; a new config gets new
    /// connections, providers.md §4), deleted ones are dropped; core's current connection options
    /// reach every client (a new `resolver` rebuilds their connections in place). Returns the
    /// providers that are new or were saved (anything but their generation or last self-test
    /// changed): their self-tests run (providers.md §4 "when the provider is saved").
    pub async fn reload(&self, state: &AppState) -> anyhow::Result<Vec<String>> {
        let _one = self.reload_lock.lock().await;
        // Read before the model: every commit published by now is in what it loads (a commit's
        // generation moves on after it committed).
        let generation = *state.config.subscribe().borrow();
        let model = state.config.model().await?;
        let names: Vec<String> = model
            .lookup_providers
            .values()
            .flat_map(LookupProviderDef::secret_refs)
            .collect();
        let secrets = state.config.secret_values(names).await?;
        let registry = self.registry.load_full();
        if self.http.set(lookup_http_options(state)) {
            tracing::info!("lookup providers' connections follow core's new connection options");
        }
        let mut opts = ClientOptions::new(Role::Core, registry, clients::factory(self.http.clone()));
        // Calls wait for a synchronised clock (README §2 Clocks; clients::WallClock).
        self.wall.follow(&state.clock);
        opts.clock = self.wall.clone();
        let before = self.model.load_full();
        let mut saved: Vec<String> = model
            .lookup_providers
            .iter()
            .filter(|(id, p)| {
                before
                    .lookup_providers
                    .get(*id)
                    .is_none_or(|b| saved_view(b) != saved_view(p))
            })
            .map(|(id, _)| id.clone())
            .collect();
        if let Ok(mut clients) = self.clients.lock() {
            clients.retain(|id, _| model.lookup_providers.contains_key(id));
            for (id, p) in &model.lookup_providers {
                let spec = ProviderSpec {
                    id: id.clone(),
                    module: p.module.clone(),
                    config: p.config.clone(),
                    generation: p.cache_generation.clone(),
                    settings: p.settings.clone(),
                };
                let mine: BTreeMap<String, String> = p
                    .secret_refs()
                    .into_iter()
                    .filter_map(|n| secrets.get(&n).map(|v| (n, v.clone())))
                    .collect();
                let limit_changed = clients
                    .get(id)
                    .is_none_or(|b| b.spec.settings.limits.max_inflight != spec.settings.limits.max_inflight);
                if limit_changed {
                    state.scheduler.light.set_limit(&lane_key(id), lane_limit(p));
                }
                match clients.get_mut(id) {
                    Some(b) if b.spec == spec && b.secrets == mine => {}
                    Some(b) => {
                        let effect = b.client.update(spec.clone(), &mine);
                        if effect.config_changed && !saved.contains(id) {
                            saved.push(id.clone());
                        }
                        b.spec = spec;
                        b.secrets = mine;
                    }
                    None => {
                        let client = LookupClient::new(spec.clone(), &mine, opts.clone());
                        clients.insert(
                            id.clone(),
                            Built {
                                client,
                                build: self.builds.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
                                spec,
                                secrets: mine,
                            },
                        );
                        if !saved.contains(id) {
                            saved.push(id.clone());
                        }
                    }
                }
            }
        }
        if let Ok(mut rt) = self.runtime.lock() {
            rt.retain(|id, _| model.lookup_providers.contains_key(id));
        }
        self.model.store(Arc::new(model));
        self.loaded.send_replace(Some(generation));
        Ok(saved)
    }
}

/// What a save of a provider changes (providers.md §4 Self-tests "when the provider is saved"):
/// the definition without its generation (a flush isn't a save) and its last self-test (the
/// test's own result).
fn saved_view(p: &LookupProviderDef) -> LookupProviderDef {
    LookupProviderDef {
        cache_generation: String::new(),
        last_self_test: None,
        ..p.clone()
    }
}

/// A provider's share of the light lane: its `max_inflight`, at most the lane's own size.
fn lane_limit(p: &LookupProviderDef) -> usize {
    (p.settings.limits.max_inflight as usize).clamp(1, crate::scheduler::LightLane::CONCURRENCY)
}

/// The HTTP options lookup clients use: the feed client's (test roots and host overrides) with
/// core's current `resolver` (core.md §11), no redirects.
fn lookup_http_options(state: &AppState) -> crate::modules::download::client::HttpOptions {
    let settings = state.settings();
    let mut o = state
        .feeds
        .http(&settings.resolver)
        .map(|h| h.options().clone())
        .unwrap_or_default();
    o.resolver = match &settings.resolver {
        crate::settings::Resolver::Upstream(u) => Some(u.clone()),
        crate::settings::Resolver::Named(_) => None,
    };
    o.max_redirects = 0;
    o
}

/// The providers some profile attaches `sync` (every edge renders every profile, so each edge's
/// config names a verdict set for each of them; core.md §4).
pub fn sync_providers(model: &Model) -> Vec<String> {
    let mut v: Vec<String> = model
        .profiles
        .values()
        .flat_map(|p| p.edge.lookup_providers.iter())
        .filter(|a| a.mode == picket_api::edge_config::LookupMode::Sync)
        .map(|a| a.provider.clone())
        .filter(|p| model.lookup_providers.contains_key(p))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// A profile's `alert_lookup_providers`, resolved: unset means every lookup provider whose category
/// is `security` (core.md §9).
pub fn alert_lookup_providers(model: &Model, profile: &crate::config::model::ProfileDef) -> Vec<String> {
    match &profile.alert_lookup_providers {
        Some(v) => v.clone(),
        None => model
            .lookup_providers
            .iter()
            .filter(|(_, p)| p.category == crate::config::model::Category::Security)
            .map(|(id, _)| id.clone())
            .collect(),
    }
}

/// Flushes a provider on every edge and core (providers.md §4 "Flush"): its `cache_generation`
/// moves on, so the flush reaches an offline edge when it reconnects; core's verdicts,
/// tombstones and Blocks of the old generation are deleted in the same transaction, and the
/// verdict set starts again from a new base. Other providers' verdicts stay. Returns the new
/// generation.
pub async fn flush(
    state: &AppState,
    provider: &str,
    actor: crate::config::Actor,
) -> crate::error::CoreResult<String> {
    use rusqlite::OptionalExtension as _;
    let id = provider.to_string();
    let generation = picket_api::ids::new_id64();
    let g2 = generation.clone();
    state
        .config
        .change(move |tx| {
            let old: Option<String> = tx
                .query_row(
                    "SELECT cache_generation FROM lookup_providers WHERE id = ?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(old) = old else {
                return Err(crate::error::CoreError::NotFound(
                    "no such lookup provider".into(),
                ));
            };
            tx.execute(
                "UPDATE lookup_providers SET cache_generation = ?2 WHERE id = ?1",
                rusqlite::params![id, g2],
            )?;
            store::discard_generation(tx, &id)?;
            crate::config::journal::record(
                tx,
                actor.ip.as_deref(),
                &actor.source,
                crate::config::EntityKind::LookupProvider,
                &id,
                &serde_json::json!({"op": "flush", "changed": {"cache_generation": {"from": old, "to": g2}}}),
            )?;
            Ok(())
        })
        .await?;
    state.lookups.sets.wake.notify_one();
    Ok(generation)
}

/// Starts the lookups runtime: loads the providers, then the workers.
pub async fn start(state: &SharedState) -> anyhow::Result<()> {
    state.lookups.reload(state).await?;
    queue::recover(state).await?;
    answered::recover(state).await?;
    state.retention.register(Arc::new(verdict_sets::SetRetention));
    state.retention.register(Arc::new(VerdictRetention));
    // Configuration changes: clients, verdict sets, self-tests on save.
    {
        let state = state.clone();
        let mut rx = state.config.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = state.shutdown.cancelled() => return,
                    r = rx.changed() => if r.is_err() { return; },
                }
                match state.lookups.reload(&state).await {
                    Ok(saved) => {
                        for p in saved {
                            state.lookups.selftests.due_now(&p);
                        }
                    }
                    Err(e) => tracing::warn!(error = %format!("{e:#}"), "reloading lookup providers failed"),
                }
                state.lookups.sets.wake.notify_one();
                state.lookups.selftests.wake.notify_one();
                state.lookups.queue.wake.notify_one();
            }
        });
    }
    // Self-tests: the next scheduled run, or a suspect test's retest, survive a restart.
    for id in state.lookups.model().lookup_providers.keys() {
        state.lookups.selftests.schedule_initial(state, id);
    }
    tokio::spawn(queue::run(state.clone()));
    tokio::spawn(verdict_sets::run(state.clone()));
    tokio::spawn(selftest::run(state.clone()));
    tokio::spawn(answered::run(state.clone()));
    tokio::spawn(sample(state.clone()));
    Ok(())
}

/// Every 30 s: per-provider gauges (queue depth, breaker, pause), core's call durations
/// (`lookup_call_ms`) and `lookup_provider_down` (breaker open, or paused by rejections, for
/// 15 min; core.md §9): core's own client's breaker and pause (read from the client, whether or
/// not core made a call), and what online edges' heartbeats report: an open breaker, or a pause
/// (their `paused` or `rejected` totals moved within [`EDGE_PAUSE_FRESH`]). A sample between two
/// pauses, or between two open periods of the breaker, doesn't restart the 15 minutes: the
/// provider must look up for [`UP_GRACE`] first.
async fn sample(state: SharedState) {
    let mut t = tokio::time::interval(Duration::from_secs(30));
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => return,
            _ = t.tick() => {}
        }
        if let Err(e) = sample_once(&state).await {
            tracing::debug!(error = %format!("{e:#}"), "lookup status sample failed");
        }
    }
}

/// One status sample (see [`sample`]).
pub async fn sample_once(state: &AppState) -> anyhow::Result<()> {
    sample_at(state, tokio::time::Instant::now()).await
}

/// [`sample_once`] as of the monotonic instant `mono` (tests pass a later one to see what the
/// 15-minute timer, [`EDGE_PAUSE_FRESH`] and [`UP_GRACE`] do as time passes).
pub async fn sample_at(state: &AppState, mono: tokio::time::Instant) -> anyhow::Result<()> {
    let model = state.lookups.model();
    let depths: HashMap<String, i64> = state
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT provider_id, count(*) FROM lookup_queue GROUP BY provider_id")?;
            let m = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<rusqlite::Result<HashMap<_, _>>>()?;
            Ok::<_, anyhow::Error>(m)
        })
        .await?;
    let now = crate::util::now();
    let live = state.edges.hub.all_live();
    let mut gauges = Vec::new();
    let mut histograms = Vec::new();
    let total: i64 = depths.values().sum();
    gauges.push((
        "queue_depth".to_string(),
        crate::metrics::labels("", &[("queue", "lookup")]),
        total as f64,
    ));
    // Edges' pauses: their totals compared with the previous heartbeat of the same boot.
    if let Ok(mut ep) = state.lookups.edge_pauses.lock() {
        ep.retain(|(e, p), _| live.iter().any(|(id, _)| id == e) && model.lookup_providers.contains_key(p));
        for (e, l) in &live {
            let Some(hb) = l.heartbeat.as_ref().filter(|_| {
                l.heartbeat_at
                    .is_some_and(|t| now - t < jiff::SignedDuration::from_secs(90))
            }) else {
                continue;
            };
            for (p, m) in &hb.metrics.lookups {
                if !model.lookup_providers.contains_key(p) {
                    continue;
                }
                let key = (e.clone(), p.clone());
                let moved = match ep.get(&key) {
                    Some(prev) if prev.boot == hb.boot => {
                        if m.paused > prev.paused || m.rejected > prev.rejected {
                            Some(mono)
                        } else {
                            prev.moved
                        }
                    }
                    // A new boot, or the first heartbeat seen: its totals since start are the
                    // baseline (a boot's first totals don't say when they moved).
                    _ => None,
                };
                ep.insert(
                    key,
                    EdgePause {
                        boot: hb.boot.clone(),
                        paused: m.paused,
                        rejected: m.rejected,
                        moved,
                    },
                );
            }
        }
    }
    let edge_pauses: HashMap<(String, String), EdgePause> = state
        .lookups
        .edge_pauses
        .lock()
        .map(|m| m.clone())
        .unwrap_or_default();
    for id in model.lookup_providers.keys() {
        let built = state.lookups.client_build(id);
        let build = built.as_ref().map_or(0, |b| b.0);
        let client = built.map(|b| b.1);
        let metrics = client.as_ref().map(LookupClient::metrics);
        let core_breaker = metrics.as_ref().is_some_and(|m| m.breaker_open != 0);
        // Core's own pause, from its client (the pause a call met is kept too, for the status).
        let core_paused = client.as_ref().is_some_and(|c| c.paused_until().is_some());
        // Edges that heard from the provider recently report its breaker in their heartbeats.
        let edges_open: Vec<String> = live
            .iter()
            .filter(|(_, l)| {
                l.heartbeat_at
                    .is_some_and(|t| now - t < jiff::SignedDuration::from_secs(90))
                    && l.heartbeat
                        .as_ref()
                        .and_then(|h| h.metrics.lookups.get(id))
                        .is_some_and(|m| m.breaker_open != 0)
            })
            .map(|(e, _)| e.clone())
            .collect();
        let mut edges_paused: Vec<String> = edge_pauses
            .iter()
            .filter(|((_, p), ep)| {
                p == id
                    && ep
                        .moved
                        .is_some_and(|t| mono.duration_since(t) <= EDGE_PAUSE_FRESH)
            })
            .map(|((e, _), _)| e.clone())
            .collect();
        edges_paused.sort();
        let breaker = core_breaker || !edges_open.is_empty();
        let rt = state.lookups.runtime(id);
        let paused = core_paused || rt.paused_until.is_some_and(|u| u > now) || !edges_paused.is_empty();
        let down = breaker || paused;
        let mut since = None;
        let mut calls_since: Option<picket_api::Histogram> = None;
        state.lookups.update_runtime(id, |r| {
            if down {
                r.down_since = r.down_since.or(Some(mono));
                r.last_down = Some(mono);
            } else if r.last_down.is_none_or(|t| mono.duration_since(t) >= UP_GRACE) {
                r.down_since = None;
                r.last_down = None;
            }
            since = r.down_since;
            // Core's calls since the last sample (the client's totals restart when it is rebuilt).
            if let Some(m) = &metrics {
                let d = self::calls_since(r.last_call_ms.as_ref(), build, &m.call_ms);
                if d.count > 0 {
                    calls_since = Some(d);
                }
                r.last_call_ms = Some((build, m.call_ms.clone()));
            }
        });
        let l = crate::metrics::labels("", &[("provider", id)]);
        if let Some(mut h) = calls_since {
            h.trim();
            histograms.push(("lookup_call_ms".to_string(), l.clone(), now.as_millisecond(), h));
        }
        gauges.push((
            "lookup_queue".into(),
            l.clone(),
            depths.get(id).copied().unwrap_or(0) as f64,
        ));
        gauges.push((
            "lookup_breaker_open".into(),
            l.clone(),
            f64::from(u8::from(breaker)),
        ));
        gauges.push(("lookup_paused".into(), l, f64::from(u8::from(paused))));
        let held = crate::clock::held_since(since, mono, now);
        let spec = crate::alerts::RaiseSpec::new(
            "lookup_provider_down",
            crate::alerts::Severity::Warning,
            format!("lookup_provider_down:{id}"),
            format!("Lookup provider {id} is down"),
            serde_json::json!({
                "provider": id,
                "breaker_open": breaker,
                "breaker_open_on_core": core_breaker,
                "breaker_open_on_edges": edges_open,
                "paused": paused,
                "paused_on_core": core_paused,
                "paused_on_edges": edges_paused,
                "paused_until": rt.paused_until.map(|t| crate::util::ts(&t)),
            }),
        );
        let threshold = state.settings().alerts.threshold("lookup_provider_down");
        if let Err(e) = state.alerts.condition(spec, held, threshold, now).await {
            tracing::debug!(error = %e, "lookup_provider_down check failed");
        }
    }
    state.metrics.gauges(&state.metrics_db, gauges).await;
    // Charted per sample and exported as totals since core started (api.md §7).
    state.metrics.histograms(&state.metrics_db, histograms).await;
    Ok(())
}

/// Retention of `lookup_verdicts` (storage.md §4 "Lookup verdicts"): verdicts until their TTL
/// ends, tombstones for the log retention window ([`store::sweep`]); re-check day counters older
/// than two days; `lookup_ingested` rows and the answers provider alerts counted
/// (`lookup_answers_counted`, [`answered`]) older than the log retention window; change counters
/// of providers that are gone. Which providers exist, and their generations and TTLs, are read in
/// the sweeping transaction, never from a snapshot taken before it: a flush, save or new provider
/// committing in between never loses the rows written under it (providers.md §4 Cache
/// generation).
pub struct VerdictRetention;

impl crate::retention::RetentionHook for VerdictRetention {
    fn name(&self) -> &str {
        "lookup_verdicts"
    }

    fn step<'a>(
        &'a self,
        state: &'a AppState,
    ) -> crate::scheduler::BoxFuture<'a, anyhow::Result<crate::scheduler::Step>> {
        Box::pin(async move {
            let window = state.settings().retention.query_logs.as_duration();
            let now = crate::util::now();
            let cutoff = crate::util::window_start(now, window);
            let day_cut = crate::util::day_key(&(now - jiff::SignedDuration::from_hours(24 * 2)));
            let cut_s = crate::util::ts(&cutoff);
            let holds = state.lookups.scan_holds.clone();
            let n = state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    let n = store::sweep(&tx, now, cutoff, crate::retention::CHUNK)?;
                    tx.execute("DELETE FROM lookup_recheck_days WHERE day < ?1", [day_cut])?;
                    // Records older than the window are never resent (log ingest drops them).
                    tx.execute("DELETE FROM lookup_ingested WHERE updated_at < ?1", [&cut_s])?;
                    // A Block's scan never reads answers older than the window, except a scan
                    // running now: what it holds stays until it commits (answered module docs).
                    answered::forget_counted_in(&tx, &cut_s, &holds)?;
                    tx.execute(
                        "DELETE FROM lookup_verdict_seq WHERE provider_id NOT IN (SELECT id FROM lookup_providers)",
                        [],
                    )?;
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(n)
                })
                .await?;
            Ok(if crate::util::sat_i64(n) >= crate::retention::CHUNK {
                crate::scheduler::Step::More
            } else {
                crate::scheduler::Step::Done
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rebuilt_clients_calls_never_subtract_the_old_clients() {
        let hist = |us: &[u64]| {
            let mut h = picket_api::Histogram::default();
            for u in us {
                h.record(*u, *u / 1000);
            }
            h
        };
        let old = hist(&[1_000, 1_000]);
        // The same build: what was counted since.
        let same = hist(&[1_000, 1_000, 50_000]);
        assert_eq!(calls_since(Some(&(1, old.clone())), 1, &same), same.delta(&old));
        // A rebuilt client (set_registry) that already counted as many calls, in other buckets:
        // all of them are new, and the buckets add up to the count (+Inf = _count).
        let rebuilt = hist(&[50_000, 50_000, 900_000]);
        let d = calls_since(Some(&(1, old)), 2, &rebuilt);
        assert_eq!(d, rebuilt);
        assert_eq!(
            (0..picket_api::histogram::BUCKETS)
                .map(|i| d.bucket(i))
                .sum::<u64>(),
            d.count
        );
    }
}
