//! Metrics (core.md §10, storage.md §3 `metrics.db`).
//!
//! - **Heartbeats** ([`store`]): each heartbeat is stored as received: one `samples` row (edge,
//!   ts, boot, up_ms), one `points` row per counter and gauge (a counter as the running total
//!   received) and one `histograms` row per histogram, so charts take differences only within a
//!   boot and a lost heartbeat loses nothing (api.md §3 Running totals).
//! - **The registry** ([`HEARTBEAT_SERIES`], [`CORE_SERIES`]): every series with its kind and
//!   label keys. The export, the charts and the OpenAPI document's `MetricSeries` catalog (which
//!   the UI checks it renders) read it.
//! - **Core's own series** ([`CoreCounters`]): the log pipeline counts (`log_records`,
//!   `log_dropped`, `log_answer_missing`, `queries_by_transport`), activation failures,
//!   firewall repairs and drift, TLS refusals an edge couldn't attribute
//!   (`tls_refused_unlogged`), and `convergence_lag_s`. Counters and histograms are totals
//!   since core started for the export, and increments (histogram rows) stored at their event
//!   (sample) time for charts; core writes a sample every 30 s so charts tell "core counted
//!   nothing" (zero) from "core was down" (a gap).
//! - **Export** ([`export`]): `GET /metrics` in the Prometheus text format: core's counters,
//!   histograms and gauges and each edge's last heartbeat, labelled `edge` (api.md §7).
//! - **Charts** ([`query`]): `GET /api/ui/v1/metrics` (api.md §7, core.md §10 Charts).
//! - **Retention** ([`MetricsRetention`]): points, histogram rows and samples older than the
//!   window go, except the newest older value of each series, the baseline of the window's first
//!   interval, with the heartbeat sample it came with (its boot), and each edge's newest older
//!   sample (storage.md §4). A series with no value left in the window goes entirely, freeing
//!   its room in its edge's share ([`store::MAX_SERIES_PER_EDGE`]).
//!
//! - **Feeds** (`feeds::metrics`): checks, records added, deleted and total per type, parse
//!   errors and held runs (feeds.md §6).
//!
//! - **Logs** (`logs::analysis`): `feed_hits`, `trial_would_block`, `retro_hits`,
//!   `wire_mismatch`, `cold_missed_blocks`, `queue_depth{queue=attribution}`,
//!   `evidence_bytes` and `analysis_skipped{work}`; `/api/ui/v1/top` is `logs::api`.
//! - **Lookups** (`lookups`): `lookup_*`, `rechecks`, `recheck_blocks` and `verdict_set_*`,
//!   per provider, and `queue_depth{queue=lookup}`.
//!
//! - **Core's resources and work** ([`resources`]): `core_rss`, `core_cpu_ms`, `core_disk_used`,
//!   `core_disk_free`, `db_bytes{db}`, `queue_depth{queue=light|heavy}` and `job_ms{kind}`.
//! - **DNSSEC and the cross-check** (`dnssec`): `dnssec_results`, `dnssec_fallback`,
//!   `dnssec_answers`, `dnssec_coverage`, `dnssec_dropped`, `crosscheck`, and
//!   `queue_depth{queue=dnssec|crosscheck}`.

pub mod export;
pub mod outbox;
pub mod query;
pub mod resources;
pub mod store;

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use picket_api::Histogram as Hist;
use serde::Serialize;

use self::Kind::{CoreCounter, CoreGauge, CoreHistogram, Counter, Gauge, Histogram};
use crate::retention::RetentionHook;
use crate::scheduler::{BoxFuture, Step};
use crate::state::AppState;

/// How a value adds up (api.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A running total since the process started; charts take differences within a boot.
    Counter,
    /// A value at `ts`.
    Gauge,
    /// Bucket running totals on the fixed layout.
    Histogram,
    /// A counter core keeps itself, stored as increments at their event time.
    CoreCounter,
    /// A gauge core samples itself, never summed across edges (`convergence_lag_s`).
    CoreGauge,
    /// A histogram core samples itself: one row per sample holding what ended since the
    /// previous one (`job_ms`).
    CoreHistogram,
}

/// A series core records or receives (core.md §10): its name, its kind and its label keys. A
/// heartbeat series is named by its field path with map keys taken out (api.md §7); a core
/// series by its own name. The export (`GET /metrics`), the charts (`GET /api/ui/v1/metrics`)
/// and the OpenAPI document's `MetricSeries` catalog all read these lists, so a series missing
/// here is neither exported nor charted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Series {
    pub name: &'static str,
    pub kind: Kind,
    /// The label keys every value of the series carries (`edge` included where it has one).
    pub labels: &'static [&'static str],
}

const fn s(name: &'static str, kind: Kind, labels: &'static [&'static str]) -> Series {
    Series { name, kind, labels }
}

const E: &[&str] = &["edge"];
const E_UPSTREAM: &[&str] = &["edge", "upstream"];
const E_UPSTREAM_REASON: &[&str] = &["edge", "upstream", "reason"];
const E_PROVIDER: &[&str] = &["edge", "provider"];
const E_BUNDLE: &[&str] = &["edge", "bundle"];
const E_REASON: &[&str] = &["edge", "reason"];
const E_KIND: &[&str] = &["edge", "kind"];
const PROVIDER: &[&str] = &["provider"];
const PROVIDER_RESULT: &[&str] = &["provider", "result"];
const FEED: &[&str] = &["feed"];
const FEED_TYPE: &[&str] = &["feed", "type"];
const NONE: &[&str] = &[];

/// Every heartbeat series (api.md §3): counters, gauges and histograms, map keys as labels.
pub const HEARTBEAT_SERIES: &[Series] = &[
    s("queries", Counter, E),
    s("by_decision.allow", Counter, E),
    s("by_decision.block", Counter, E),
    s("by_decision.rewrite", Counter, E),
    s("by_decision.refused", Counter, E),
    s("by_decision.servfail", Counter, E),
    s("rejected", Counter, E),
    s("refused", Counter, E),
    s("cache_hits", Counter, E),
    s("cache_misses", Counter, E),
    s("stale_served", Counter, E),
    s("latency_us", Histogram, E),
    s("panics", Counter, E),
    s("fw_ack_late", Counter, E),
    s("upstream.queries", Counter, E_UPSTREAM),
    s("upstream.hedges", Counter, E_UPSTREAM),
    s("upstream.rtt_ms", Histogram, E_UPSTREAM),
    s("upstream.errors", Counter, E_UPSTREAM),
    s("upstream.invalid", Counter, E_UPSTREAM_REASON),
    // edge.md §7 Scrub: records the scrub removed from valid answers, by reason (in picket-api's
    // heartbeat and sent by the edge; not yet in api.md §3)
    s("upstream.scrubbed", Counter, E_UPSTREAM_REASON),
    s("lookups.calls", Counter, E_PROVIDER),
    s("lookups.call_ms", Histogram, E_PROVIDER),
    s("lookups.timeouts", Counter, E_PROVIDER),
    s("lookups.late", Counter, E_PROVIDER),
    s("lookups.errors", Counter, E_PROVIDER),
    s("lookups.rejected", Counter, E_PROVIDER),
    s("lookups.breaker_open", Gauge, E_PROVIDER),
    s("lookups.paused", Counter, E_PROVIDER),
    s("lookups.cache_hits", Counter, E_PROVIDER),
    s("lookups.set_hits", Counter, E_PROVIDER),
    s("lookups.cache_misses", Counter, E_PROVIDER),
    s("lookups.evictions", Counter, E_PROVIDER),
    s("lookups.entries", Gauge, E_PROVIDER),
    s("lookups.bytes", Gauge, E_PROVIDER),
    s("cold.blocks", Counter, E_BUNDLE),
    s("cold.unchecked", Counter, E_BUNDLE),
    s("cold.page_reads", Counter, E_BUNDLE),
    s("spool.bytes", Gauge, E),
    s("spool.oldest_ts", Gauge, E),
    s("logs.dropped", Counter, E_REASON),
    s("rss", Gauge, E),
    s("mem_available", Gauge, E),
    s("cpu_ms.edge", Counter, E),
    s("cpu_ms.helper", Counter, E),
    s("cgroup_mem.unit", Gauge, E),
    s("cgroup_mem.helper_rss", Gauge, E),
    s("disk.data_dir.used", Gauge, E),
    s("disk.data_dir.free", Gauge, E),
    s("disk.ssd_dir.used", Gauge, E),
    s("disk.ssd_dir.free", Gauge, E),
    s("fw.entries", Gauge, E),
    s("fw.max", Gauge, E),
    s("fw.rejects", Counter, E),
    s("fw.mon_rejects", Counter, E),
];

/// Core's own series (core.md §10).
pub const CORE_SERIES: &[Series] = &[
    s("log_records", CoreCounter, E),
    s("log_dropped", CoreCounter, E_REASON),
    s("log_answer_missing", CoreCounter, E),
    s("queries_by_transport", CoreCounter, &["edge", "transport"]),
    s("activations_failed", CoreCounter, E_KIND),
    s("fw_repairs", CoreCounter, E),
    // TLS refusals an edge's table had no room for (`tls_version_refused`'s `unlogged`, api.md §5)
    s("tls_refused_unlogged", CoreCounter, E),
    s("fw_drift", CoreGauge, E_KIND),
    s("convergence_lag_s", CoreGauge, E_KIND),
    // feeds.md §6
    s("feed_checks", CoreCounter, &["feed", "result"]),
    s("feed_records_added", CoreCounter, FEED_TYPE),
    s("feed_records_deleted", CoreCounter, FEED_TYPE),
    // A gauge, so exported without `_total` (`picket_feed_records`), which Prometheus keeps for
    // counters.
    s("feed_records", CoreGauge, FEED_TYPE),
    s("feed_parse_errors", CoreCounter, FEED),
    s("feed_held_runs", CoreCounter, FEED),
    // core.md §7, §10: async lookups on core, per provider
    s("lookup_calls", CoreCounter, PROVIDER),
    s("lookup_timeouts", CoreCounter, PROVIDER),
    s("lookup_errors", CoreCounter, PROVIDER),
    s("lookup_rejected", CoreCounter, PROVIDER),
    s("lookup_verdicts", CoreCounter, PROVIDER_RESULT),
    s("lookup_dropped", CoreCounter, &["provider", "reason"]),
    s("lookup_queue", CoreGauge, PROVIDER),
    s("lookup_breaker_open", CoreGauge, PROVIDER),
    s("lookup_paused", CoreGauge, PROVIDER),
    s("rechecks", CoreCounter, PROVIDER_RESULT),
    s("recheck_blocks", CoreCounter, PROVIDER),
    // core.md §10, §12: core's own call durations per provider (`lookup_call_ms{provider}`), a
    // histogram of the calls since the previous 30 s sample, charted as `lookup_call_ms.p50`/`.p99`
    s("lookup_call_ms", CoreHistogram, PROVIDER),
    s("queue_depth", CoreGauge, &["queue"]),
    // core.md §7: verdict sets, per provider
    s("verdict_set_deltas", CoreCounter, PROVIDER),
    s("verdict_set_bases", CoreCounter, PROVIDER),
    s("verdict_set_records", CoreGauge, PROVIDER),
    s("verdict_set_overlay_bytes", CoreGauge, PROVIDER),
    // core.md §6, §10: attribution, trial checks, retro-match, the wire check, cold checks,
    // alert evidence (queue_depth{queue=attribution} is the attribution backlog)
    s("feed_hits", CoreCounter, &["feed", "role"]),
    s("trial_would_block", CoreCounter, &["edge", "profile", "bundle"]),
    s("retro_hits", CoreCounter, FEED),
    s("wire_mismatch", CoreCounter, E_KIND),
    s("cold_missed_blocks", CoreCounter, E_BUNDLE),
    s("evidence_bytes", CoreGauge, NONE),
    // Work core skipped to stay within its bounds (README §2 Bounded), by kind: records past the
    // analysis budget, evidence copies not captured, retro-match and trial work given up, and
    // queued metric increments dropped while metrics.db refused them (`logs::analysis`,
    // `metrics::outbox`)
    s("analysis_skipped", CoreCounter, &["work"]),
    // core.md §8, §10: DNSSEC validation and the cross-check
    s("dnssec_results", CoreCounter, &["outcome"]),
    s("dnssec_fallback", CoreCounter, NONE),
    s("dnssec_answers", CoreCounter, E),
    s("dnssec_coverage", CoreCounter, &["edge", "class", "outcome"]),
    s("dnssec_dropped", CoreCounter, &["reason"]),
    s("crosscheck", CoreCounter, &["check", "result"]),
    // core.md §10: core's resources and work
    s("core_rss", CoreGauge, NONE),
    s("core_cpu_ms", CoreCounter, NONE),
    s("core_disk_used", CoreGauge, NONE),
    s("core_disk_free", CoreGauge, NONE),
    s("db_bytes", CoreGauge, &["db"]),
    s("job_ms", CoreHistogram, &["kind"]),
];

/// Every series, heartbeat series first.
pub fn all_series() -> impl Iterator<Item = &'static Series> {
    HEARTBEAT_SERIES.iter().chain(CORE_SERIES.iter())
}

/// A series by name.
pub fn series(name: &str) -> Option<&'static Series> {
    static BY_NAME: std::sync::OnceLock<HashMap<&'static str, &'static Series>> = std::sync::OnceLock::new();
    BY_NAME
        .get_or_init(|| all_series().map(|s| (s.name, s)).collect())
        .get(name)
        .copied()
}

/// Checks a value's labels against the registry where core records it: a call site that drops
/// or adds a label would split or merge series and export a family with mixed label sets. Debug
/// builds (the tests) stop; release builds record the value and say so once.
fn check_labels(name: &str, l: &Labels) {
    let want = series(name).map(|s| s.labels);
    if want.is_some_and(|w| w.len() == l.len() && w.iter().all(|k| l.contains_key(*k))) {
        return;
    }
    let got: Vec<&String> = l.keys().collect();
    if cfg!(debug_assertions) {
        panic!("series {name} recorded with labels {got:?}, registered with labels {want:?}");
    }
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::error!(series = name, labels = ?got, registered = ?want, "a core series recorded with unregistered labels");
    }
}

/// Ids of the entities core's series name in their `provider`, `feed`, `bundle` and `profile`
/// labels. Series of entities that no longer exist leave the export (README §2 Bounded: a
/// deleted provider's breaker gauge must not stay 1 forever).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entities {
    pub providers: std::collections::HashSet<String>,
    pub feeds: std::collections::HashSet<String>,
    pub bundles: std::collections::HashSet<String>,
    pub profiles: std::collections::HashSet<String>,
}

impl Entities {
    pub fn of(m: &crate::config::model::Model) -> Self {
        Self {
            providers: m.lookup_providers.keys().cloned().collect(),
            feeds: m.feeds.keys().cloned().collect(),
            bundles: m.bundles.keys().cloned().collect(),
            profiles: m.profiles.keys().cloned().collect(),
        }
    }

    /// Whether `l` names only entities that exist (an empty value names none).
    pub fn keeps(&self, l: &Labels) -> bool {
        [
            ("provider", &self.providers),
            ("feed", &self.feeds),
            ("bundle", &self.bundles),
            ("profile", &self.profiles),
        ]
        .iter()
        .all(|(k, ids)| l.get(*k).is_none_or(|v| v.is_empty() || ids.contains(v)))
    }
}

/// A series' kind by name.
pub fn kind_of(name: &str) -> Option<Kind> {
    series(name).map(|s| s.kind)
}

/// The label a map family's keys become.
pub fn map_label(family: &str) -> Option<&'static str> {
    match family {
        "upstream" => Some("upstream"),
        "lookups" => Some("provider"),
        "cold" => Some("bundle"),
        _ => None,
    }
}

/// Series labels: always sorted (`BTreeMap`), stored as JSON.
pub type Labels = BTreeMap<String, String>;

/// Labels with `edge` and the given pairs.
pub fn labels(edge: &str, extra: &[(&str, &str)]) -> Labels {
    let mut l = Labels::new();
    if !edge.is_empty() {
        l.insert("edge".into(), edge.into());
    }
    for (k, v) in extra {
        l.insert((*k).into(), (*v).into());
    }
    l
}

/// Core's counters and histograms since it started and its gauges' last values, by series and
/// labels, for the export (api.md §7). Bounded: labels come from registered edges, providers and
/// feeds and from fixed reason, kind and transport sets.
#[derive(Default)]
pub struct CoreCounters {
    totals: Mutex<BTreeMap<(String, Labels), f64>>,
    gauges: Mutex<BTreeMap<(String, Labels), f64>>,
    hists: Mutex<BTreeMap<(String, Labels), Hist>>,
    /// Values refused at the caps: counters, gauges, histograms.
    dropped: [std::sync::atomic::AtomicU64; 3],
    /// The entities that exist, once the configuration was read ([`CoreCounters::set_entities`]).
    entities: Mutex<Option<Entities>>,
}

/// Values refused because their map was at its cap, by map (the export's `metrics_dropped`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    pub counters: u64,
    pub gauges: u64,
    pub histograms: u64,
}

/// Most distinct core series held in memory (README §2, Bounded).
const MAX_CORE_SERIES: usize = 20_000;
/// Most distinct core histograms held in memory (README §2, Bounded): one per lookup provider
/// (`lookup_call_ms`); 47 buckets each.
const MAX_CORE_HISTOGRAMS: usize = 1_024;

/// The maps' names in the export (`metrics_dropped{map}`), by [`CoreCounters::dropped`] index.
pub const DROPPED_MAPS: [&str; 3] = ["counters", "gauges", "histograms"];

impl CoreCounters {
    /// Counts a value refused at map `i`'s cap; the first refusal of each map is logged.
    fn refused(&self, i: usize, name: &str) {
        if self.dropped[i].fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
            tracing::warn!(
                map = DROPPED_MAPS[i],
                series = name,
                "core's metric series are at their cap: new series are dropped (counted in picket_metrics_dropped_total)"
            );
        }
    }

    pub fn add(&self, name: &str, labels: Labels, n: f64) {
        check_labels(name, &labels);
        if let Ok(mut t) = self.totals.lock() {
            let key = (name.to_string(), labels);
            if t.len() >= MAX_CORE_SERIES && !t.contains_key(&key) {
                drop(t);
                self.refused(0, name);
                return;
            }
            *t.entry(key).or_insert(0.0) += n;
        }
    }

    pub fn set_gauge(&self, name: &str, labels: Labels, v: f64) {
        check_labels(name, &labels);
        if let Ok(mut g) = self.gauges.lock() {
            let key = (name.to_string(), labels);
            if g.len() >= MAX_CORE_SERIES && !g.contains_key(&key) {
                drop(g);
                self.refused(1, name);
                return;
            }
            g.insert(key, v);
        }
    }

    /// Adds `h` to the histogram's total since core started.
    pub fn add_histogram(&self, name: &str, labels: Labels, h: &Hist) {
        check_labels(name, &labels);
        if let Ok(mut m) = self.hists.lock() {
            let key = (name.to_string(), labels);
            if m.len() >= MAX_CORE_HISTOGRAMS && !m.contains_key(&key) {
                drop(m);
                self.refused(2, name);
                return;
            }
            m.entry(key).or_default().add(h);
        }
    }

    /// Takes the entities that exist now and drops every series naming one that doesn't.
    pub fn set_entities(&self, e: Entities) {
        if let Ok(mut g) = self.entities.lock() {
            *g = Some(e);
        }
        self.prune();
    }

    /// Drops the series of entities that no longer exist (values a late writer recorded after
    /// the entity's deletion go at the next prune: every 30 s and at each configuration change).
    pub fn prune(&self) {
        let Some(e) = self.entities.lock().ok().and_then(|g| g.clone()) else {
            return;
        };
        if let Ok(mut t) = self.totals.lock() {
            t.retain(|(_, l), _| e.keeps(l));
        }
        if let Ok(mut g) = self.gauges.lock() {
            g.retain(|(_, l), _| e.keeps(l));
        }
        if let Ok(mut h) = self.hists.lock() {
            h.retain(|(_, l), _| e.keeps(l));
        }
    }

    /// Whether bundle `id` exists (unknown before the configuration was first read: then yes).
    pub fn bundle_exists(&self, id: &str) -> bool {
        self.entities
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|e| e.bundles.contains(id)))
            .unwrap_or(true)
    }

    /// The histograms since core started.
    pub fn histograms(&self) -> Vec<((String, Labels), Hist)> {
        self.hists
            .lock()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }

    pub fn totals(&self) -> Vec<((String, Labels), f64)> {
        self.totals
            .lock()
            .map(|t| t.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default()
    }

    pub fn gauges(&self) -> Vec<((String, Labels), f64)> {
        self.gauges
            .lock()
            .map(|t| t.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default()
    }

    /// Values refused at the caps since core started.
    pub fn dropped(&self) -> Dropped {
        let n = |i: usize| self.dropped[i].load(std::sync::atomic::Ordering::Relaxed);
        Dropped {
            counters: n(0),
            gauges: n(1),
            histograms: n(2),
        }
    }

    /// Drops the series of edges that no longer exist.
    pub fn retain_edges(&self, edges: &[String]) {
        let keep = |l: &Labels| l.get("edge").is_none_or(|e| edges.contains(e));
        if let Ok(mut t) = self.totals.lock() {
            t.retain(|(_, l), _| keep(l));
        }
        if let Ok(mut g) = self.gauges.lock() {
            g.retain(|(_, l), _| keep(l));
        }
        if let Ok(mut h) = self.hists.lock() {
            h.retain(|(_, l), _| keep(l));
        }
    }
}

/// Metrics state shared by the process.
pub struct Metrics {
    pub series: store::SeriesCache,
    pub counters: CoreCounters,
    /// This core process's sample boot (core's own `samples` rows use edge id `""`).
    pub core_boot: String,
    pub started: tokio::time::Instant,
    /// Job durations since the last sample (`job_ms`, [`resources`]).
    pub jobs: resources::JobTimes,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            series: store::SeriesCache::default(),
            counters: CoreCounters::default(),
            core_boot: picket_api::ids::new_boot_id(),
            started: tokio::time::Instant::now(),
            jobs: resources::JobTimes::default(),
        }
    }
}

impl Metrics {
    /// Counts core events at their event time: totals for the export, and increments in
    /// `metrics.db` for charts. `items` are `(series, labels, event time ms, n)`.
    pub async fn count(&self, db: &crate::db::Db, items: Vec<(String, Labels, i64, f64)>) {
        self.count_if(db, items, None).await;
    }

    /// [`Metrics::count`], unless `guard` says no on the `metrics.db` writer (a log batch that a
    /// config restore overtook, [`crate::logs::ingest`]): then neither the chart increments nor
    /// the export totals count anything, and it returns false.
    pub async fn count_if(
        &self,
        db: &crate::db::Db,
        items: Vec<(String, Labels, i64, f64)>,
        guard: Option<store::WriteGuard>,
    ) -> bool {
        if items.is_empty() {
            return guard.is_none_or(|g| g());
        }
        let mut binned: HashMap<(String, Labels, i64), f64> = HashMap::new();
        let mut totals: Vec<(String, Labels, f64)> = Vec::with_capacity(items.len());
        for (name, l, ts, n) in items {
            let bin = ts - ts.rem_euclid(store::CORE_BIN_MS);
            *binned.entry((name.clone(), l.clone(), bin)).or_insert(0.0) += n;
            totals.push((name, l, n));
        }
        let points = binned.into_iter().map(|((n, l, ts), v)| (n, l, ts, v)).collect();
        let counted = match store::write_points_if(db, &self.series, points, guard).await {
            Ok(written) => written,
            Err(e) => {
                tracing::warn!(error = %e, "cannot store core metrics");
                true
            }
        };
        if counted {
            for (name, l, n) in totals {
                self.counters.add(&name, l, n);
            }
        }
        counted
    }

    /// Sets a core gauge now (export) and stores its sample (charts).
    pub async fn gauge(&self, db: &crate::db::Db, name: &str, l: Labels, v: f64) {
        self.gauges(db, vec![(name.to_string(), l, v)]).await;
    }

    /// Sets core gauges now (export) and stores their samples in one write (charts).
    pub async fn gauges(&self, db: &crate::db::Db, items: Vec<(String, Labels, f64)>) {
        if items.is_empty() {
            return;
        }
        let now = jiff::Timestamp::now().as_millisecond();
        let mut points = Vec::with_capacity(items.len());
        for (name, l, v) in items {
            self.counters.set_gauge(&name, l.clone(), v);
            points.push((name, l, now, v));
        }
        if let Err(e) = store::write_points(db, &self.series, points).await {
            tracing::warn!(error = %e, "cannot store a core gauge");
        }
    }

    /// Stores rows of core's own histograms, each holding what ended since the previous sample
    /// (charts), and adds them to the totals since core started (export). `items` are
    /// `(series, labels, sample time ms, histogram)`. `job_ms` keeps its totals as jobs end
    /// ([`resources::JobTimes`]) and stores its rows with [`store::write_histograms`].
    pub async fn histograms(&self, db: &crate::db::Db, items: Vec<(String, Labels, i64, Hist)>) {
        if items.is_empty() {
            return;
        }
        for (name, l, _, h) in &items {
            self.counters.add_histogram(name, l.clone(), h);
        }
        if let Err(e) = store::write_histograms(db, &self.series, items).await {
            tracing::warn!(error = %format!("{e:#}"), "cannot store core histograms");
        }
    }
}

/// Samples core's presence every 30 s (a `samples` row with edge id `""`), so a chart step in
/// which core ran and counted nothing is zero, and one without core is a gap (core.md §10).
pub fn spawn_core_sampler(state: crate::state::SharedState) {
    spawn_pruner(state.clone());
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_millis(store::CORE_BIN_MS as u64));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let cpu = resources::CpuBase::default();
        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                _ = t.tick() => {}
            }
            let boot = state.metrics.core_boot.clone();
            let up = picket_api::duration::as_millis_i64(state.metrics.started.elapsed());
            let now = jiff::Timestamp::now().as_millisecond();
            let r = state
                .metrics_db
                .write(move |c| {
                    c.execute(
                        "INSERT INTO samples(edge_id, ts, boot, up_ms) VALUES ('', ?1, ?2, ?3)",
                        rusqlite::params![now, boot, up],
                    )?;
                    Ok::<_, anyhow::Error>(())
                })
                .await;
            if let Err(e) = r {
                tracing::warn!(error = %e, "cannot store core's metrics sample");
            }
            // Core's resources, lane depths and job durations (core.md §10).
            resources::write(&state, &cpu).await;
            // Series a late writer recorded for an entity already deleted.
            state.metrics.counters.prune();
        }
    });
}

/// Follows the configuration: after each change, the series of deleted lookup providers, feeds,
/// bundles and profiles leave core's totals and gauges ([`CoreCounters::set_entities`]).
fn spawn_pruner(state: crate::state::SharedState) {
    tokio::spawn(async move {
        let mut rx = state.config.subscribe();
        loop {
            match state.config.model().await {
                Ok(m) => state.metrics.counters.set_entities(Entities::of(&m)),
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "cannot read the configuration for the metric series")
                }
            }
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                r = rx.changed() => if r.is_err() { return },
            }
        }
    });
}

/// Deletes metrics older than `retention.metrics`, keeping each series' newest older row (with
/// the sample it was stored with, and each edge's newest older sample) as the baseline of the
/// window's first interval (storage.md §4). A series with no value left in the window has no
/// first interval to need a baseline for: it goes with its rows, which frees its room in its
/// edge's share (README §2, capped shares; a later value creates it again). Clock-gated like
/// every retention delete (it runs inside the retention job).
pub struct MetricsRetention;

const METRICS_CHUNK: i64 = 5_000;
/// Series aged out per step.
const SERIES_CHUNK: i64 = 1_000;

impl RetentionHook for MetricsRetention {
    fn name(&self) -> &str {
        "metrics"
    }

    fn step<'a>(&'a self, state: &'a AppState) -> BoxFuture<'a, anyhow::Result<Step>> {
        Box::pin(async move {
            let window = state.settings().retention.metrics.as_duration();
            let cutoff = crate::util::window_start(jiff::Timestamp::now(), window).as_millisecond();
            let cache = state.metrics.series.clone();
            let n = state
                .metrics_db
                .write(move |c| {
                    let mut n = 0usize;
                    // Series with no value in the window, with their remaining rows; the cache
                    // forgets them right after the commit, on this writer, so no heartbeat
                    // reuses a deleted id.
                    let tx = c.transaction()?;
                    let gone: Vec<(i64, String, String)> = tx
                        .prepare(&format!(
                            "SELECT s.id, s.name, s.labels_json FROM series s
                             WHERE NOT EXISTS (SELECT 1 FROM points p WHERE p.series_id = s.id AND p.ts >= ?1)
                               AND NOT EXISTS (SELECT 1 FROM histograms h WHERE h.series_id = s.id AND h.ts >= ?1)
                             LIMIT {SERIES_CHUNK}"
                        ))?
                        .query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                        .collect::<rusqlite::Result<_>>()?;
                    let mut removed = Vec::with_capacity(gone.len());
                    for (id, name, lj) in gone {
                        n += tx.execute("DELETE FROM points WHERE series_id = ?1", [id])?;
                        n += tx.execute("DELETE FROM histograms WHERE series_id = ?1", [id])?;
                        n += tx.execute("DELETE FROM series WHERE id = ?1", [id])?;
                        let edge = serde_json::from_str::<Labels>(&lj)
                            .ok()
                            .and_then(|l| l.get("edge").cloned());
                        removed.push((name, lj, edge));
                    }
                    let aged = crate::util::sat_i64(removed.len());
                    tx.commit()?;
                    cache.forget(removed);
                    for table in ["points", "histograms"] {
                        n += c.execute(
                            &format!(
                                "DELETE FROM {table} WHERE rowid IN (
                                   SELECT t.rowid FROM {table} t WHERE t.ts < ?1
                                     AND t.ts < (SELECT max(o.ts) FROM {table} o WHERE o.series_id = t.series_id AND o.ts < ?1)
                                   LIMIT {METRICS_CHUNK})"
                            ),
                            [cutoff],
                        )?;
                    }
                    // A sample goes unless it is its edge's newest before the cutoff or a kept
                    // value was sampled with it: each series' baseline needs its boot, and an
                    // optional value's baseline can be older than the edge's last sample.
                    n += c.execute(
                        &format!(
                            "DELETE FROM samples WHERE rowid IN (
                               SELECT t.rowid FROM samples t WHERE t.ts < ?1
                                 AND t.ts < (SELECT max(o.ts) FROM samples o WHERE o.edge_id = t.edge_id AND o.ts < ?1)
                                 AND NOT EXISTS (SELECT 1 FROM points p JOIN series s ON s.id = p.series_id
                                                 WHERE p.ts = t.ts AND json_extract(s.labels_json, '$.edge') = t.edge_id)
                                 AND NOT EXISTS (SELECT 1 FROM histograms h JOIN series s ON s.id = h.series_id
                                                 WHERE h.ts = t.ts AND json_extract(s.labels_json, '$.edge') = t.edge_id)
                               LIMIT {METRICS_CHUNK})"
                        ),
                        [cutoff],
                    )?;
                    Ok::<_, anyhow::Error>((n, aged))
                })
                .await?;
            let (n, aged) = n;
            Ok(
                if crate::util::sat_i64(n) >= METRICS_CHUNK || aged >= SERIES_CHUNK {
                    Step::More
                } else {
                    Step::Done
                },
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_records_is_one_name_and_exports_without_total() {
        // Issue 74: stored rows, the UI's chart and the Prometheus family share the gauge's name;
        // a gauge's family has no `_total`, which Prometheus keeps for counters.
        let s = series("feed_records").expect("registered");
        assert_eq!(s.kind, Kind::CoreGauge);
        assert_eq!(export::family(s), "picket_feed_records");
        assert!(series("feed_records_total").is_none());
        // Counters still end in `_total`.
        assert_eq!(export::family(series("feed_records_added").unwrap()), "picket_feed_records_added_total");
    }

    /// A call site that records a series with other label keys than the registry's would split
    /// or merge series (and export a family with mixed label sets): debug builds stop.
    #[test]
    #[cfg(debug_assertions)]
    fn a_label_missing_at_a_call_site_stops_debug_builds() {
        let c = CoreCounters::default();
        // Registered labels pass, with or without an edge where the series has none.
        c.add("log_dropped", labels("e-1", &[("reason", "invalid")]), 1.0);
        c.set_gauge("core_rss", labels("", &[]), 1.0);
        c.add_histogram("job_ms", labels("", &[("kind", "compile")]), &Hist::default());
        let refused = |f: Box<dyn FnOnce() + std::panic::UnwindSafe>| std::panic::catch_unwind(f).is_err();
        assert!(refused(Box::new(|| {
            CoreCounters::default().add("log_dropped", labels("e-1", &[]), 1.0)
        })));
        assert!(refused(Box::new(|| {
            CoreCounters::default().set_gauge("lookup_queue", labels("", &[]), 1.0)
        })));
        assert!(refused(Box::new(|| {
            CoreCounters::default().add_histogram(
                "lookup_call_ms",
                labels("e-1", &[("provider", "p")]),
                &Hist::default(),
            )
        })));
        assert!(refused(Box::new(|| {
            CoreCounters::default().add("not_a_series", labels("", &[]), 1.0)
        })));
    }

    #[test]
    fn values_past_the_caps_are_counted() {
        let c = CoreCounters::default();
        let p = |i: usize| labels("", &[("provider", &format!("p{i}"))]);
        for i in 0..MAX_CORE_SERIES + 3 {
            c.add("lookup_calls", p(i), 1.0);
            c.set_gauge("lookup_queue", p(i), 1.0);
        }
        for i in 0..MAX_CORE_HISTOGRAMS + 2 {
            c.add_histogram("lookup_call_ms", p(i), &Hist::default());
        }
        // A series already held is never refused.
        c.add("lookup_calls", p(0), 1.0);
        assert_eq!(
            c.dropped(),
            Dropped {
                counters: 3,
                gauges: 3,
                histograms: 2
            }
        );
    }
}
