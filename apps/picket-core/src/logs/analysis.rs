//! The analysis of logged queries (core.md §6): one light-lane pass per batch of new records,
//! after ingest and never delaying it or the ack, plus retro-match and alert evidence.
//!
//! - **Progress** (README §2 Restarts; build-and-test.md §5 "a restart mid-batch loses nothing
//!   and duplicates nothing"): each partition's progress is the highest `events` rowid whose
//!   analysis effects are committed, kept in `core.db`'s `log_progress` (kind `analysis`).
//!   Rowids only grow in a partition, so the records after it are the work left. Partitions are
//!   never migrated (storage.md §5): the progress lives in `core.db`, so records of every log
//!   schema are analysed alike, including those appended to an older partition after an upgrade.
//! - **One pass per batch** ([`run_batch`]): attribution ([`super::attribution`]), the trial check
//!   ([`super::trial`]), the check of unchecked cold lookups ([`super::cold`]) and the wire check
//!   ([`super::wire`]), and `category_blocked` for blocks by a sync lookup, read from the record
//!   itself (core.md §9). First the records' results (`attribution`, `would_blocks`) and markers
//!   (`wire_check`, `trial_check`, `cold_check`) go into the partition, idempotently (a repeat
//!   rewrites the same rows; a record already trial-checked keeps its result, core.md §6 "checked
//!   once"). Then one `core.db` transaction holds the batch's every effect (alert raises,
//!   `bundle_key_hits`, wire examples, evidence copies, trial records awaiting a head, the metric
//!   increments as an outbox, [`crate::metrics::outbox`]) and moves the progress past the batch.
//!   A stop before that commit repeats the batch with no effect applied yet; a stop after it
//!   repeats nothing.
//! - **Failures stay local** (README §2: a bad item never stalls the receiver): a record whose
//!   analysis fails is retried in later turns, and after [`MAX_ATTEMPTS`] it is skipped and
//!   counted (`analysis_skipped{work}`); so is a record whose effects keep failing inside the
//!   `core.db` transaction, where each record's writes run in a savepoint of their own
//!   ([`isolated`]), and so is its evidence capture, which runs (a savepoint per record) after
//!   all the batch's effects, so a rule any record of the batch raises takes every record of it
//!   (core.md §9). Each of the three counts its own attempts ([`Work`]): a record whose effects
//!   used theirs still has its capture's. A partition that can't be read backs off while the
//!   others go on.
//! - **Progress outlives no partition it could belong to:** a partition's progress rows go with it
//!   when retention deletes it ([`forget_hour`]), and [`prune_progress`] drops only rows of hours
//!   past the retention window that have no file, never those of an hour that may still get one.
//! - **Retro-match and hour closes** ([`super::retro`]) and the **evidence budget**
//!   ([`super::evidence`]) run from the same loop.
//!
//! Bounded: a batch reads at most [`BATCH`] records; each loop turn runs at most [`TURN_BATCHES`]
//! batches and [`TURN_RETRO_STEPS`] retro steps before it looks at the clock and shutdown again.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;

use super::attribution::{self, Effects as AttrEffects, Env};
use super::cold::{ColdCache, ColdOutcome};
use super::evidence::{self, Capture, EvidenceRule};
use super::partition::hour_key;
use super::record::{self, Rec};
use super::replay::ReplayCaches;
use super::trial::{self, TrialOutcome};
use super::wire;
use crate::alerts::{self as alerts_mod, Changes, RaiseSpec, Severity};
use crate::config::model::Model;
use crate::metrics::outbox::{self, Item};
use crate::state::{AppState, SharedState};

/// Records one batch reads.
pub const BATCH: usize = 256;
/// Batches one loop turn runs.
const TURN_BATCHES: usize = 32;
/// Retro steps one loop turn runs.
const TURN_RETRO_STEPS: usize = 64;
/// How often every partition in the window is queued again.
const RESCAN_EVERY: Duration = Duration::from_secs(300);
/// How often the attribution backlog is counted (`queue_depth{queue=attribution}`).
const BACKLOG_EVERY: Duration = Duration::from_secs(30);
/// The loop's idle tick (hour closes, new feed runs, the backlog gauge).
const TICK: Duration = Duration::from_secs(15);
/// How often the evidence budget is recounted.
const BUDGET_EVERY: Duration = Duration::from_secs(300);
/// How often the proposed splits of block bundles are compared with their last dry run.
const DRY_RUN_EVERY: Duration = Duration::from_secs(60);
/// `wire_mismatch` examples kept per alert (core.md §6).
pub const MAX_WIRE_EXAMPLES: i64 = 20;
/// Turns a record's analysis may fail before it is skipped (README §2: a bad item is counted and
/// never stalls the receiver). A policy choice: three tries across separate turns ride out a
/// passing failure (a busy database) without letting one record hold its partition for long.
pub const MAX_ATTEMPTS: u32 = 3;
/// Records with failed attempts remembered at once (bounded; forgetting one only restarts its
/// count).
const MAX_TRACKED_FAILURES: usize = 10_000;
/// The longest a partition that can't be read waits before its next try.
const MAX_BACKOFF: Duration = Duration::from_secs(600);
/// The `log_progress` kind of the analysis.
pub const PROGRESS: &str = "analysis";

/// A record's work that counts its own failed attempts (README §2: a bad item is skipped and
/// counted after [`MAX_ATTEMPTS`]), so one work using its attempts never takes another's: a
/// record whose effects were skipped still gets its evidence copied unless its capture fails
/// [`MAX_ATTEMPTS`] times itself (core.md §9 Evidence: every ingested record related to an alert).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Work {
    /// Its analysis (replay, attribution, checks).
    Analysis,
    /// Its `core.db` effects.
    Effects,
    /// Its evidence capture.
    Evidence,
}

/// A record (its partition's hour, its rowid) and one of its works.
type Attempt = (Timestamp, i64, Work);

/// A point where tests stop a pass as a crash would ([`Analysis::fail_at`]), or hold it
/// ([`Analysis::pause_at`]).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailPoint {
    /// After the partition's results and markers, before the `core.db` effects commit.
    AnalysisBeforeEffects,
    /// After the `core.db` effects commit, before the metric outbox is flushed.
    AnalysisAfterEffects,
    /// Retro-match: before the `core.db` commit of a step with matches.
    RetroBeforeEffects,
    /// Inside the metrics flush, after `metrics.db` committed and before the outbox rows go.
    OutboxAfterMetrics,
    /// Inside the metrics flush, after the outbox rows were read, before `metrics.db` is written.
    OutboxAfterRead,
}

/// Tests: a held pass ([`Analysis::pause_at`]) signals `reached` and waits for `resume`.
#[doc(hidden)]
#[derive(Default)]
pub struct Pause {
    pub reached: tokio::sync::Notify,
    pub resume: tokio::sync::Notify,
}

/// The analysis state shared by the loop, the API and other modules.
pub struct Analysis {
    pub caches: ReplayCaches,
    pub cold: ColdCache,
    pub capture: Capture,
    retro_locks: Mutex<HashMap<Timestamp, Arc<tokio::sync::Mutex<()>>>>,
    batch_locks: Mutex<HashMap<Timestamp, Arc<tokio::sync::Mutex<()>>>>,
    model: Mutex<Option<(u64, Arc<Model>)>>,
    pending: Mutex<BTreeSet<Timestamp>>,
    wake: tokio::sync::Notify,
    /// Records awaiting analysis, as last counted (`queue_depth{queue=attribution}`).
    backlog: AtomicU64,
    /// Records analysed since start.
    analysed: AtomicU64,
    /// Turns of the analysis loop since start (tests: an idle core waits, README §2 Bounded).
    turns: AtomicU64,
    /// Turned off by tests that drive batches themselves.
    paused: std::sync::atomic::AtomicBool,
    /// Failed attempts per record and work.
    attempts: Mutex<HashMap<Attempt, u32>>,
    /// Partitions whose analysis failed as a whole.
    backoff: Backoff,
    /// Partitions whose retry of records awaiting a trial head failed as a whole
    /// ([`super::trial::retry_pending`]).
    pub(crate) trial_backoff: Backoff,
    /// Retro-match's compiled view of the run in progress (see [`super::retro`]).
    pub(crate) retro_run: Mutex<Option<Arc<super::retro::RunMatcher>>>,
    fail: Mutex<Option<FailPoint>>,
    pauses: Mutex<HashMap<FailPoint, Arc<Pause>>>,
    /// Tests: records with this query name fail their analysis.
    poison: Mutex<Option<String>>,
    /// Tests: retro-match's step sizes (records, values) in place of its defaults.
    retro_steps: Mutex<Option<(usize, usize)>>,
    /// Tests: retro-match's work per step in place of [`super::retro::STEP_WORK`].
    retro_work: Mutex<Option<usize>>,
    /// Failed attempts of retro-match and trial-retry items per partition: a retro record
    /// (`r:<rowid>`), an alert key's raise (`k:<key>`) or a record awaiting a trial head
    /// (`t:<rowid>`).
    item_attempts: Mutex<HashMap<(Timestamp, String), u32>>,
    /// Tests: records with this query name fail in the named work (`retro`, `retro_effects`,
    /// `effects`, `evidence`, `trial`).
    poison_in: Mutex<Vec<(String, String)>>,
}

impl Default for Analysis {
    fn default() -> Self {
        Self {
            caches: ReplayCaches::default(),
            cold: ColdCache::default(),
            capture: Capture::default(),
            retro_locks: Mutex::new(HashMap::new()),
            batch_locks: Mutex::new(HashMap::new()),
            model: Mutex::new(None),
            pending: Mutex::new(BTreeSet::new()),
            wake: tokio::sync::Notify::new(),
            backlog: AtomicU64::new(0),
            analysed: AtomicU64::new(0),
            turns: AtomicU64::new(0),
            paused: std::sync::atomic::AtomicBool::new(false),
            attempts: Mutex::new(HashMap::new()),
            backoff: Backoff::default(),
            trial_backoff: Backoff::default(),
            retro_run: Mutex::new(None),
            fail: Mutex::new(None),
            pauses: Mutex::new(HashMap::new()),
            poison: Mutex::new(None),
            retro_steps: Mutex::new(None),
            retro_work: Mutex::new(None),
            item_attempts: Mutex::new(HashMap::new()),
            poison_in: Mutex::new(Vec::new()),
        }
    }
}

fn lock_of(
    m: &Mutex<HashMap<Timestamp, Arc<tokio::sync::Mutex<()>>>>,
    hour: Timestamp,
) -> Arc<tokio::sync::Mutex<()>> {
    let mut m = m.lock().unwrap_or_else(|p| p.into_inner());
    if m.len() > 512 {
        m.retain(|_, l| Arc::strong_count(l) > 1);
    }
    m.entry(hour).or_default().clone()
}

impl Analysis {
    /// The retro lock of one partition (see [`super::retro`]).
    pub fn retro_lock(&self, hour: Timestamp) -> Arc<tokio::sync::Mutex<()>> {
        lock_of(&self.retro_locks, hour)
    }

    /// The analysis lock of one partition: one batch at a time per partition.
    fn batch_lock(&self, hour: Timestamp) -> Arc<tokio::sync::Mutex<()>> {
        lock_of(&self.batch_locks, hour)
    }

    /// The configuration model, reloaded after each configuration change.
    pub async fn model(&self, state: &AppState) -> anyhow::Result<Arc<Model>> {
        let generation = *state.config.subscribe().borrow();
        if let Ok(g) = self.model.lock()
            && let Some((gen_, m)) = g.as_ref()
            && *gen_ == generation
        {
            return Ok(m.clone());
        }
        let m = Arc::new(state.config.model().await?);
        if let Ok(mut g) = self.model.lock() {
            *g = Some((generation, m.clone()));
        }
        Ok(m)
    }

    /// Queues hours whose partitions may hold records awaiting analysis, and wakes the loop.
    pub fn wake(&self, hours: impl IntoIterator<Item = Timestamp>) {
        self.queue(hours);
        self.wake.notify_one();
    }

    /// Queues hours without waking the loop: for the loop's own turn, which analyses them now.
    /// Waking itself would leave a stored permit, so the next wait would return at once and an
    /// idle core would spin (README §2 Bounded).
    fn queue(&self, hours: impl IntoIterator<Item = Timestamp>) {
        if let Ok(mut p) = self.pending.lock() {
            for h in hours {
                if p.len() < 10_000 {
                    p.insert(h);
                }
            }
        }
    }

    /// Turns of the analysis loop since start.
    pub fn turns(&self) -> u64 {
        self.turns.load(Ordering::Relaxed)
    }

    pub fn backlog(&self) -> u64 {
        self.backlog.load(Ordering::Relaxed)
    }

    pub fn analysed(&self) -> u64 {
        self.analysed.load(Ordering::Relaxed)
    }

    /// Stops (or resumes) the background loop's batches (tests drive [`drain`] themselves).
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
        if !paused {
            self.wake.notify_one();
        }
    }

    /// Tests: the next pass that reaches `point` fails there, as a stop would cut it off.
    #[doc(hidden)]
    pub fn fail_at(&self, point: FailPoint) {
        if let Ok(mut f) = self.fail.lock() {
            *f = Some(point);
        }
    }

    /// Tests: the next pass that reaches `point` waits there until the test resumes it.
    #[doc(hidden)]
    pub fn pause_at(&self, point: FailPoint) -> Arc<Pause> {
        let p = Arc::new(Pause::default());
        if let Ok(mut m) = self.pauses.lock() {
            m.insert(point, p.clone());
        }
        p
    }

    /// Waits at `point` when a test holds it (once).
    pub(crate) async fn paused_at(&self, point: FailPoint) {
        let p = self.pauses.lock().ok().and_then(|mut m| m.remove(&point));
        if let Some(p) = p {
            p.reached.notify_one();
            p.resume.notified().await;
        }
    }

    /// Tests: records whose query name is `qname` fail their analysis (None: none do).
    #[doc(hidden)]
    pub fn poison_qname(&self, qname: Option<&str>) {
        if let Ok(mut p) = self.poison.lock() {
            *p = qname.map(str::to_string);
        }
    }

    fn poisoned(&self, qname: &str) -> bool {
        self.poison
            .lock()
            .map(|p| p.as_deref() == Some(qname))
            .unwrap_or(false)
    }

    /// Tests: retro-match's step sizes (records per close, late or record step; values per
    /// value step).
    #[doc(hidden)]
    pub fn set_retro_steps(&self, records: usize, values: usize) {
        if let Ok(mut s) = self.retro_steps.lock() {
            *s = Some((records.max(1), values.max(1)));
        }
    }

    pub(crate) fn retro_steps(&self) -> Option<(usize, usize)> {
        self.retro_steps.lock().ok().and_then(|s| *s)
    }

    /// Tests: retro-match's work per step ([`super::retro::STEP_WORK`]).
    #[doc(hidden)]
    pub fn set_retro_work(&self, work: usize) {
        if let Ok(mut s) = self.retro_work.lock() {
            *s = Some(work.max(1));
        }
    }

    pub(crate) fn retro_work(&self) -> Option<usize> {
        self.retro_work.lock().ok().and_then(|s| *s)
    }

    /// Tests: records whose query name is `qname` fail in `work` (`retro`: retro-match's
    /// matching; `retro_effects`: raising their `category_answered`; `effects`: the analysis's
    /// `core.db` effects; `evidence`: their evidence capture; `trial`: the retry of their trial
    /// check once a waiting bundle has a head). None: none do.
    #[doc(hidden)]
    pub fn poison_in(&self, work: &str, qname: Option<&str>) {
        if let Ok(mut p) = self.poison_in.lock() {
            *p = qname
                .map(|q| vec![(work.to_string(), q.to_string())])
                .unwrap_or_default();
        }
    }

    /// Tests: [`Analysis::poison_in`], keeping the poisons already set.
    #[doc(hidden)]
    pub fn poison_also(&self, work: &str, qname: &str) {
        if let Ok(mut p) = self.poison_in.lock() {
            p.push((work.to_string(), qname.to_string()));
        }
    }

    pub(crate) fn poisoned_in(&self, work: &str, qname: &str) -> bool {
        self.poison_in
            .lock()
            .map(|p| p.iter().any(|(w, q)| w == work && q == qname))
            .unwrap_or(false)
    }

    /// Counts a failed attempt of retro-match or trial-retry item `item` in `hour`; true when it
    /// has used them all (README §2: then it is skipped and counted).
    pub(crate) fn failed_item_attempt(&self, hour: Timestamp, item: &str) -> bool {
        let Ok(mut m) = self.item_attempts.lock() else {
            return false;
        };
        let k = (hour, item.to_string());
        if m.len() >= MAX_TRACKED_FAILURES && !m.contains_key(&k) {
            m.clear();
        }
        let n = m.entry(k).or_insert(0);
        *n += 1;
        *n >= MAX_ATTEMPTS
    }

    /// True (once) when a test asked to fail at `point`.
    pub(crate) fn failing(&self, point: FailPoint) -> bool {
        self.fail
            .lock()
            .map(|mut f| {
                if *f == Some(point) {
                    *f = None;
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false)
    }

    /// Counts a failed attempt of `work` for record `rowid` in `hour`; true when that work has
    /// used them all.
    fn failed_attempt(&self, hour: Timestamp, rowid: i64, work: Work) -> bool {
        let Ok(mut m) = self.attempts.lock() else {
            return false;
        };
        let k = (hour, rowid, work);
        if m.len() >= MAX_TRACKED_FAILURES && !m.contains_key(&k) {
            m.clear();
        }
        let n = m.entry(k).or_insert(0);
        *n += 1;
        *n >= MAX_ATTEMPTS
    }

    fn forget_attempts(&self, hour: Timestamp, upto: i64) {
        if let Ok(mut m) = self.attempts.lock() {
            m.retain(|(h, r, _), _| *h != hour || *r > upto);
        }
    }

    /// Tests: every partition's back-off ends, as if its wait had passed.
    #[doc(hidden)]
    pub fn end_backoffs(&self) {
        self.backoff.clear();
        self.trial_backoff.clear();
    }

    /// True while `hour` backs off after failing as a whole.
    pub(crate) fn backing_off(&self, hour: Timestamp) -> bool {
        self.backoff.active(hour)
    }

    /// Records that work on `hour` failed as a whole: it backs off ([`Backoff`]) while the other
    /// partitions go on.
    pub(crate) fn partition_failed(&self, hour: Timestamp) {
        self.backoff.failed(hour);
    }

    pub(crate) fn partition_ok(&self, hour: Timestamp) {
        self.backoff.ok(hour);
    }
}

/// Partitions whose work failed as a whole, each waiting before its next try (README §2: a bad
/// item never stalls the receiver): 5 s, doubling with each failure in a row up to
/// [`MAX_BACKOFF`], while the other partitions go on. Bounded: at most 4,096 partitions (more
/// forget them all, which only shortens their waits).
#[derive(Default)]
pub(crate) struct Backoff(Mutex<HashMap<Timestamp, (u32, tokio::time::Instant)>>);

impl Backoff {
    /// True while `hour` waits.
    pub(crate) fn active(&self, hour: Timestamp) -> bool {
        self.0
            .lock()
            .ok()
            .and_then(|m| m.get(&hour).map(|(_, at)| tokio::time::Instant::now() < *at))
            .unwrap_or(false)
    }

    /// The partitions waiting now.
    pub(crate) fn waiting(&self) -> Vec<Timestamp> {
        let now = tokio::time::Instant::now();
        self.0
            .lock()
            .map(|m| {
                m.iter()
                    .filter(|(_, (_, at))| now < *at)
                    .map(|(h, _)| *h)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Work on `hour` failed as a whole: it waits.
    pub(crate) fn failed(&self, hour: Timestamp) {
        if let Ok(mut m) = self.0.lock() {
            if m.len() > 4096 {
                m.clear();
            }
            let e = m.entry(hour).or_insert((0, tokio::time::Instant::now()));
            e.0 = e.0.saturating_add(1);
            let wait = Duration::from_secs(5)
                .saturating_mul(1u32 << e.0.min(10))
                .min(MAX_BACKOFF);
            e.1 = tokio::time::Instant::now() + wait;
        }
    }

    /// Work on `hour` went through: it no longer waits.
    pub(crate) fn ok(&self, hour: Timestamp) {
        if let Ok(mut m) = self.0.lock() {
            m.remove(&hour);
        }
    }

    fn clear(&self) {
        if let Ok(mut m) = self.0.lock() {
            m.clear();
        }
    }
}

/// What the pass found for one record.
#[derive(Default)]
struct RecResult {
    attribution: Option<AttrEffects>,
    trial: TrialOutcome,
    cold: Option<ColdOutcome>,
    wire: Option<(String, Option<wire::Outcome>)>,
    /// The record's analysis failed for good: skipped and counted, no effects.
    skipped: bool,
}

/// `log_progress` value of `hour_key` and `kind` (0 when none).
pub fn progress_get(c: &Connection, hour_key: &str, kind: &str) -> rusqlite::Result<i64> {
    Ok(c.query_row(
        "SELECT value FROM log_progress WHERE hour = ?1 AND kind = ?2",
        params![hour_key, kind],
        |r| r.get(0),
    )
    .optional()?
    .unwrap_or(0))
}

/// Sets `log_progress` of `hour_key` and `kind`.
pub fn progress_set(c: &Connection, hour_key: &str, kind: &str, value: i64) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO log_progress(hour, kind, value) VALUES (?1, ?2, ?3)
         ON CONFLICT(hour, kind) DO UPDATE SET value = excluded.value",
        params![hour_key, kind, value],
    )?;
    Ok(())
}

/// The `core.db` tables that keep per-partition progress, keyed by the partition's `hour`.
const PROGRESS_TABLES: [&str; 4] = ["log_progress", "retro_progress", "retro_values", "trial_pending"];

/// Drops the progress rows of partition `hour`, deleted just now (retention, storage.md §4).
pub async fn forget_hour(state: &AppState, hour: Timestamp) -> anyhow::Result<()> {
    let hk = hour_key(&hour);
    state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            for t in PROGRESS_TABLES {
                tx.execute(&format!("DELETE FROM {t} WHERE hour = ?1"), [&hk])?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
}

/// Drops the progress rows of hours that ended before the retention window and have no partition
/// file (deleted by retention before a stop let it drop them; a restore empties these tables in
/// its own transaction). Only such hours: ingest stores no record older than the window
/// (core.md §6), so no partition can appear for them again, while an hour inside the window may
/// get its file at any moment — the progress of a partition made right after a listing, whose
/// first batch committed before this write, is never taken (README §2 Restarts: nothing analysed
/// twice). The file is looked for inside the write, so a progress commit (always after its file
/// exists) can't fall between the look and the delete.
pub async fn prune_progress(state: &AppState) -> anyhow::Result<()> {
    let window = state.settings().retention.query_logs.as_duration();
    let cutoff = crate::util::window_start(Timestamp::now(), window);
    let store = state.logs.writer().store().clone();
    state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            for t in PROGRESS_TABLES {
                let hours: Vec<String> = {
                    let mut st = tx.prepare(&format!("SELECT DISTINCT hour FROM {t}"))?;
                    st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
                };
                for h in hours {
                    let gone = match super::partition::parse_hour_key(&h) {
                        Some(hour) => {
                            picket_api::time::saturating_add(hour, jiff::SignedDuration::from_hours(1))
                                <= cutoff
                                && !store.path_for(&hour).exists()
                        }
                        None => true,
                    };
                    if gone {
                        tx.execute(&format!("DELETE FROM {t} WHERE hour = ?1"), [&h])?;
                    }
                }
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
}

/// Starts the analysis loop.
pub fn start(state: &SharedState) {
    let st = state.clone();
    tokio::spawn(async move {
        let an = st.analysis.clone();
        let mut stored = st.logs.seams.stored.subscribe();
        let mut feed_runs = st.events.subscribe();
        let mut last_rescan: Option<tokio::time::Instant> = None;
        let mut last_retro: Option<tokio::time::Instant> = None;
        let mut last_budget: Option<tokio::time::Instant> = None;
        let mut last_dry: Option<tokio::time::Instant> = None;
        let mut last_backlog: Option<tokio::time::Instant> = None;
        // Evidence backfills, resumed where a stop left them (README §2 Restarts).
        evidence::start_backfills(&st);
        // At start: increments a stop left in the outbox, and progress of deleted partitions.
        if let Err(e) = outbox::flush(&st).await {
            tracing::warn!(error = %format!("{e:#}"), "cannot move queued metrics");
        }
        if let Err(e) = prune_progress(&st).await {
            tracing::warn!(error = %format!("{e:#}"), "cannot prune log progress");
        }
        // A turn that left work ready (a partition with more records, or more pending hours than
        // one turn's batches) starts the next turn at once; otherwise the loop waits for a wake,
        // a feed run or the tick.
        let mut again = false;
        loop {
            let mut retro_due = false;
            tokio::select! {
                _ = st.shutdown.cancelled() => return,
                _ = std::future::ready(()), if again => {}
                r = stored.changed() => {
                    if r.is_ok() {
                        let hours = stored.borrow_and_update().clone();
                        an.queue(hours);
                    }
                }
                _ = an.wake.notified() => {}
                ev = feed_runs.recv() => match ev {
                    // A feed run may have added entries: retro-match runs this turn. A bundle
                    // build may give a waiting trial bundle its head.
                    Ok(e) if e.kind == "feed_run" || e.kind == "bundle_version" => retro_due = true,
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => retro_due = true,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        feed_runs = st.events.subscribe();
                        continue;
                    }
                },
                _ = tokio::time::sleep(TICK) => {}
            }
            an.turns.fetch_add(1, Ordering::Relaxed);
            if an.paused.load(Ordering::Relaxed) {
                // Paused, nothing is ready: the loop waits (keeping `again` would spin it).
                again = false;
                continue;
            }
            // The ingest seam keeps only the latest hours it stored in: every partition is
            // queued at start and every RESCAN_EVERY, the current and previous hour every turn,
            // so no record waits for analysis longer than that (README §2 Restarts).
            if last_rescan.is_none_or(|t| t.elapsed() >= RESCAN_EVERY) {
                last_rescan = Some(tokio::time::Instant::now());
                let store = st.logs.writer().store().clone();
                if let Ok(Ok(list)) = tokio::task::spawn_blocking(move || store.list()).await {
                    an.queue(list.into_iter().map(|(h, _)| h));
                }
            } else {
                let now = super::partition::hour_start(&Timestamp::now());
                an.queue([now, now - jiff::SignedDuration::from_hours(1)]);
            }
            again = match batches(&st).await {
                Ok(more) => more,
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "log analysis failed");
                    false
                }
            };
            if let Err(e) = outbox::flush(&st).await {
                tracing::warn!(error = %format!("{e:#}"), "cannot move queued metrics");
            }
            if retro_due || last_retro.is_none_or(|t| t.elapsed() >= TICK) {
                last_retro = Some(tokio::time::Instant::now());
                if let Err(e) = retro_turn(&st, false).await {
                    tracing::warn!(error = %format!("{e:#}"), "retro-match failed");
                }
                if let Err(e) = trial::retry_pending(&st).await {
                    tracing::warn!(error = %format!("{e:#}"), "trial checks awaiting a head failed");
                }
                if let Err(e) = outbox::flush(&st).await {
                    tracing::warn!(error = %format!("{e:#}"), "cannot move queued metrics");
                }
            }
            if last_backlog.is_none_or(|t| t.elapsed() >= BACKLOG_EVERY) {
                last_backlog = Some(tokio::time::Instant::now());
                sample_backlog(&st).await;
            }
            if last_dry.is_none_or(|t| t.elapsed() >= DRY_RUN_EVERY) {
                last_dry = Some(tokio::time::Instant::now());
                submit_dry_runs(&st).await;
            }
            if last_budget.is_none_or(|t| t.elapsed() >= BUDGET_EVERY) {
                last_budget = Some(tokio::time::Instant::now());
                match evidence::check_budget(&st, &st.alerts).await {
                    Ok(used) => {
                        st.metrics
                            .gauge(
                                &st.metrics_db,
                                "evidence_bytes",
                                crate::metrics::labels("", &[]),
                                used as f64,
                            )
                            .await
                    }
                    Err(e) => tracing::warn!(error = %format!("{e:#}"), "evidence budget check failed"),
                }
            }
        }
    });
}

/// The backstop of the tiering dry runs (bundles.md §2 Tiering; the compiler submits them as soon
/// as it sees a proposal): submits those due or interrupted, and builds a split whose dry run has
/// reported or no longer holds it ([`crate::compiler::tier::submit_dry_runs`]).
pub async fn submit_dry_runs(state: &SharedState) {
    crate::compiler::tier::submit_dry_runs(state).await;
}

/// One loop turn's batches: the pending hours, newest first, at most [`TURN_BATCHES`]. A
/// partition whose batch fails backs off and the others go on (README §2). True when more work is
/// ready now, so the loop's next turn needn't wait; false when it's done, or when the light lane
/// is full (the next turn waits rather than spins).
pub async fn batches(state: &SharedState) -> anyhow::Result<bool> {
    let an = state.analysis.clone();
    if state.restore.logs_pending() {
        return Ok(false);
    }
    let mut ran = 0;
    let mut tried: BTreeSet<Timestamp> = BTreeSet::new();
    while ran < TURN_BATCHES {
        let next = an.pending.lock().ok().and_then(|p| {
            p.iter()
                .rev()
                .find(|h| !tried.contains(*h) && !an.backing_off(**h))
                .copied()
        });
        let Some(hour) = next else { break };
        let st = state.clone();
        let job = state
            .scheduler
            .light
            .spawn(Some("log_analysis"), async move { run_batch(&st, hour).await });
        let Some(job) = job else {
            // The light lane is at its admission cap: try again next turn, after a wait.
            return Ok(false);
        };
        ran += 1;
        match job.await {
            Ok(Ok((_, more))) => {
                an.partition_ok(hour);
                if !more && let Ok(mut p) = an.pending.lock() {
                    p.remove(&hour);
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %format!("{e:#}"), hour = %hour, "log analysis of a partition failed; it backs off");
                an.partition_failed(hour);
                tried.insert(hour);
            }
            Err(e) => {
                tracing::warn!(error = %e, hour = %hour, "log analysis of a partition panicked; it backs off");
                an.partition_failed(hour);
                tried.insert(hour);
            }
        }
    }
    // Work is ready now when an hour still pending isn't backing off or failed this turn: a
    // partition with more records than one batch, or hours past this turn's TURN_BATCHES.
    let ready = an
        .pending
        .lock()
        .map(|p| p.iter().any(|h| !tried.contains(h) && !an.backing_off(*h)))
        .unwrap_or(false);
    Ok(ready)
}

/// Runs batches until nothing awaits analysis (tests, and `turn`'s first pass).
pub async fn drain(state: &SharedState) -> anyhow::Result<usize> {
    let store = state.logs.writer().store().clone();
    let list = tokio::task::spawn_blocking(move || store.list()).await??;
    let mut total = 0;
    for (hour, _) in list.into_iter().rev() {
        loop {
            let (n, more) = run_batch(state, hour).await?;
            total += n;
            if !more {
                break;
            }
        }
    }
    outbox::flush(state).await?;
    Ok(total)
}

/// Runs every retro step due (tests): no partition backs off, and a failing step is an error.
pub async fn drain_retro(state: &SharedState) -> anyhow::Result<usize> {
    let mut hits = 0;
    loop {
        let n = retro_turn(state, true).await?;
        hits += n.0;
        if !n.1 {
            break;
        }
    }
    outbox::flush(state).await?;
    Ok(hits)
}

async fn sample_backlog(state: &SharedState) {
    let store = state.logs.writer().store().clone();
    let cursors: HashMap<String, i64> = match state
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT hour, value FROM log_progress WHERE kind = ?1")?;
            let v = st
                .query_map([PROGRESS], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<HashMap<String, i64>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let n = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
        let mut n = 0u64;
        for (hour, _) in store.list()? {
            let Some(p) = store.open(&hour, false)? else {
                continue;
            };
            let after = cursors.get(&hour_key(&hour)).copied().unwrap_or(0);
            let c: i64 = p
                .conn
                .query_row("SELECT count(*) FROM events WHERE rowid > ?1", [after], |r| {
                    r.get(0)
                })?;
            n += u64::try_from(c).unwrap_or(0);
        }
        Ok(n)
    })
    .await;
    if let Ok(Ok(n)) = n {
        state.analysis.backlog.store(n, Ordering::Relaxed);
        state
            .metrics
            .gauge(
                &state.metrics_db,
                "queue_depth",
                crate::metrics::labels("", &[("queue", "attribution")]),
                n as f64,
            )
            .await;
    }
}

/// The wire check of one record: `(wire_check, outcome)`; `None` when the record references no
/// answer.
fn wire_check(r: &Rec) -> Option<(String, Option<wire::Outcome>)> {
    r.answer_id.as_ref()?;
    // Only the preview is known: skipped (core.md §6).
    if r.truncated || r.answer_missing {
        return Some(("skipped".into(), None));
    }
    let Some(w) = r.answer_wire.as_ref() else {
        return Some(("skipped".into(), None));
    };
    let deciding = r.reason.as_ref().and_then(|reason| {
        (reason.step == 5 && r.decision() == Some(picket_api::logs::Decision::Block))
            .then(|| reason.value.clone().map(|v| (reason.stage, v)))
            .flatten()
    });
    let logged = wire::Logged {
        cname: &r.cname,
        answers: &r.answers,
        targets: &r.targets,
        cname_rewrite: r.decision() == Some(picket_api::logs::Decision::Rewrite),
        deciding,
    };
    let o = wire::check(w, &logged);
    let mark = if o.kinds.is_empty() { "ok" } else { "mismatch" };
    Some((mark.into(), Some(o)))
}

/// The feeds' categories, for `category_blocked`.
pub(crate) fn feed_category(model: &Model, feed: &str) -> Option<&'static str> {
    model.feeds.get(feed).map(|f| f.category.as_str())
}

/// One record's pass (see the module docs).
fn analyse_one(
    env: &Env<'_>,
    data_dir: &std::path::Path,
    cold: &ColdCache,
    r: &Rec,
    stored_trial: Option<&Vec<trial::WouldBlock>>,
) -> anyhow::Result<RecResult> {
    // Would-blocks a pass stored before a stop cut the batch off stand as they are (core.md §6:
    // each record is checked once): all of them once its check finished (`trial_check`), else
    // for their bundles, the others checked now.
    let stored = stored_trial.map(Vec::as_slice).unwrap_or(&[]);
    let trial = if r.trial_check.is_some() {
        TrialOutcome::stored(stored.to_vec())
    } else {
        trial::check(env, r, stored)?
    };
    Ok(RecResult {
        attribution: attribution::attribute(env, r)?,
        trial,
        cold: super::cold::check(env, data_dir, cold, r)?,
        wire: wire_check(r),
        skipped: false,
    })
}

/// The records of `hour` after rowid `after` (at most [`BATCH`]), with the would-blocks already
/// stored for them (a batch a stop cut off after its partition commit).
type Loaded = (Vec<Rec>, HashMap<i64, Vec<trial::WouldBlock>>);

fn load_batch(store: &super::LogStore, hour: Timestamp, after: i64) -> anyhow::Result<Loaded> {
    let Some(p) = store.open(&hour, false)? else {
        return Ok((Vec::new(), HashMap::new()));
    };
    let recs = record::load(
        &p,
        "WHERE e.rowid > ?1 ORDER BY e.rowid LIMIT ?2",
        &[&after, &BATCH],
    )?;
    let mut stored: HashMap<i64, Vec<trial::WouldBlock>> = HashMap::new();
    for r in recs.iter().filter(|r| trial::eligible(r)) {
        let wbs = trial::stored_would_blocks(&p, &r.edge, &r.boot, r.seq)?;
        if !wbs.is_empty() {
            stored.insert(r.rowid, wbs);
        }
    }
    Ok((recs, stored))
}

/// One batch of `hour`'s records awaiting analysis; returns (records analysed, more left).
pub async fn run_batch(state: &SharedState, hour: Timestamp) -> anyhow::Result<(usize, bool)> {
    let an = state.analysis.clone();
    let lock = an.batch_lock(hour);
    let _g = lock.lock().await;
    if state.restore.logs_pending() {
        return Ok((0, false));
    }
    let generation = state.restore.generation();
    let hk = hour_key(&hour);
    let after = {
        let hk = hk.clone();
        state
            .db
            .read(move |c| Ok::<_, anyhow::Error>(progress_get(c, &hk, PROGRESS)?))
            .await?
    };
    let store = state.logs.writer().store().clone();
    let (mut recs, stored_trials) =
        tokio::task::spawn_blocking(move || load_batch(&store, hour, after)).await??;
    if recs.is_empty() {
        return Ok((0, false));
    }
    let mut more = recs.len() >= BATCH;
    let model = an.model(state).await?;
    let data_dir = state.data_dir.clone();
    // The pass, on a read connection; each record on its own, so one that fails holds up only
    // itself (README §2).
    let outcomes: Vec<Result<RecResult, String>> = {
        let an = an.clone();
        let model = model.clone();
        let recs = recs.clone();
        state
            .db
            .read(move |c| {
                let env = Env {
                    c,
                    caches: &an.caches,
                    model: &model,
                };
                let mut out = Vec::with_capacity(recs.len());
                for r in &recs {
                    let one = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if an.poisoned(&r.qname) {
                            anyhow::bail!("a poisoned record (test)");
                        }
                        analyse_one(&env, &data_dir, &an.cold, r, stored_trials.get(&r.rowid))
                    }));
                    out.push(match one {
                        Ok(Ok(res)) => Ok(res),
                        Ok(Err(e)) => Err(format!("{e:#}")),
                        Err(_) => Err("the analysis panicked".to_string()),
                    });
                }
                Ok::<_, anyhow::Error>(out)
            })
            .await?
    };
    // A record that failed: retried in a later turn (the batch stops before it), or skipped and
    // counted once it has used its attempts.
    let mut results: Vec<RecResult> = Vec::with_capacity(outcomes.len());
    let mut skipped = 0usize;
    for (i, o) in outcomes.into_iter().enumerate() {
        match o {
            Ok(res) => results.push(res),
            Err(e) => {
                let r = &recs[i];
                if an.failed_attempt(hour, r.rowid, Work::Analysis) {
                    tracing::warn!(error = %e, hour = %hour, edge = %r.edge, boot = %r.boot, seq = r.seq,
                        "log record skipped: its analysis keeps failing");
                    skipped += 1;
                    results.push(RecResult {
                        skipped: true,
                        ..Default::default()
                    });
                } else {
                    tracing::warn!(error = %e, hour = %hour, edge = %r.edge, boot = %r.boot, seq = r.seq,
                        "log record analysis failed; retried later");
                    recs.truncate(i);
                    more = true;
                    break;
                }
            }
        }
    }
    if recs.is_empty() {
        // The first record failed: the partition backs off, the others go on.
        anyhow::bail!("the first record awaiting analysis failed");
    }
    let upto = recs.last().map(|r| r.rowid).unwrap_or(after);
    // 1. The partition: results and markers, idempotent.
    let now = crate::util::now_ts();
    let rows: Arc<Vec<(Rec, RecResult)>> = Arc::new(recs.into_iter().zip(results).collect());
    {
        let rows = rows.clone();
        let now = now.clone();
        state
            .logs
            .writer()
            .with_partition(hour, move |p| write_results(p, &rows, &now))
            .await?;
    }
    if an.failing(FailPoint::AnalysisBeforeEffects) {
        anyhow::bail!("stopped before the effects (test)");
    }
    // 2. DNSSEC and cross-check candidates (core.md §8), once per record.
    let plain: Vec<Rec> = rows
        .iter()
        .filter(|(_, x)| !x.skipped)
        .map(|(r, _)| r.clone())
        .collect();
    let admission = crate::dnssec::admit(state, &plain, generation).await?;
    // 3. core.db: every effect and the progress, in one transaction.
    let settings = state.settings();
    let per_alert = settings.alerts.evidence_per_alert;
    let total_bytes = u64::from(settings.alerts.evidence_total_mib) * 1024 * 1024;
    let names: HashMap<String, String> = rows
        .iter()
        .map(|(r, _)| {
            (
                r.edge.clone(),
                state.edges.hub.name_of(&r.edge).unwrap_or_else(|| r.edge.clone()),
            )
        })
        .collect();
    let alerts = state.alerts.clone();
    let gate = state.restore.clone();
    let clock = state.clock.clone();
    let committed = {
        let an = an.clone();
        let model = model.clone();
        let rows = rows.clone();
        let hk = hk.clone();
        state
            .db
            .write(move |c| {
                if !gate.is_current(generation) {
                    return Ok(None);
                }
                let tx = c.transaction()?;
                // One pass at a time moves a partition's progress (the batch lock); a restore or
                // a repeat that got here first leaves nothing to do.
                if progress_get(&tx, &hk, PROGRESS)? != after {
                    return Ok(None);
                }
                // The budget is recounted before anything is admitted after a start (core.md §9).
                an.capture.ensure_counted(&tx)?;
                // Room for records awaiting a trial head, counted once per batch.
                let mut room = if rows.iter().any(|(_, x)| !x.trial.pending.is_empty()) {
                    trial::pending_room(&tx)?
                } else {
                    0
                };
                let mut ch = Changes::default();
                let mut new: Vec<(i64, EvidenceRule)> = Vec::new();
                let mut metrics: Vec<Item> = Vec::new();
                let mut freed = 0u64;
                let mut skipped = skipped;
                // Each record's effects on their own (a savepoint): one whose writes keep failing
                // is skipped and counted after its attempts; while it has some left, the batch is
                // tried again later (README §2).
                for (r, res) in rows.iter().filter(|(_, x)| !x.skipped) {
                    let edge_name = names.get(&r.edge).cloned().unwrap_or_else(|| r.edge.clone());
                    let mut one_ch = Changes::default();
                    let mut one_new: Vec<(i64, EvidenceRule)> = Vec::new();
                    let mut one_room = room;
                    let applied = isolated(
                        &tx,
                        || an.failed_attempt(hour, r.rowid, Work::Effects),
                        || {
                            if an.poisoned_in("effects", &r.qname) {
                                anyhow::bail!("a poisoned record (test)");
                            }
                            if let Some(fx) = &res.attribution {
                                apply_attribution_in(
                                    &alerts,
                                    &tx,
                                    &model,
                                    r,
                                    fx,
                                    &edge_name,
                                    &mut one_ch,
                                    &mut one_new,
                                )?;
                            }
                            lookup_blocked_in(&alerts, &tx, &model, r, &mut one_ch, &mut one_new)?;
                            if let Some(co) = &res.cold {
                                for (bundle, key) in &co.missed {
                                    key_hit_in(&tx, bundle, key, &r.ts)?;
                                }
                            }
                            if let Some((_, Some(o))) = &res.wire
                                && !o.kinds.is_empty()
                            {
                                wire_mismatch_in(
                                    &alerts,
                                    &an.capture,
                                    &tx,
                                    r,
                                    o,
                                    &edge_name,
                                    total_bytes,
                                    &mut one_ch,
                                )?;
                            }
                            if !res.trial.pending.is_empty() {
                                trial::pend_in(&tx, &hk, r.rowid, &res.trial.pending, &mut one_room, &clock)?;
                            }
                            Ok(())
                        },
                    )?;
                    match applied {
                        Some(()) => {
                            ch.extend(one_ch);
                            new.extend(one_new);
                            room = one_room;
                            metrics.extend(record_items(r, res));
                        }
                        None => {
                            tracing::warn!(hour = %hour, edge = %r.edge, boot = %r.boot, seq = r.seq,
                                "log record's effects skipped: writing them keeps failing");
                            skipped += 1;
                        }
                    }
                }
                if skipped > 0 {
                    metrics.push(skipped_item("analysis", skipped));
                }
                // Evidence (core.md §9: each related record "as it is ingested"), once every
                // record's effects are in: a rule raised by any record of the batch then takes
                // every record of it, the earlier ones included (its backfill stops at the
                // progress before the batch). Every record of the batch is copied, those whose
                // analysis or effects were skipped too: they are ingested records all the same.
                // Each record's capture runs in a savepoint of its own with attempts of its own (a
                // record whose capture keeps failing is skipped and counted, whatever its effects
                // used), and what its copies evicted is given back only after the commit (a
                // rollback restores it).
                let capturing = evidence::Capturing::prepare(&an.capture, &tx)?;
                let mut uncaptured = 0usize;
                // The alerts whose evidence the batch changed (their `alert` UI event once it
                // commits; a skipped record's savepoint changed nothing).
                let mut touched = evidence::Touched::default();
                for (r, _) in rows.iter() {
                    let captured = isolated(
                        &tx,
                        || an.failed_attempt(hour, r.rowid, Work::Evidence),
                        || {
                            if an.poisoned_in("evidence", &r.qname) {
                                anyhow::bail!("a poisoned record (test)");
                            }
                            let mut one = evidence::Touched::default();
                            let (_, f) =
                                capturing.record(&an.capture, &tx, r, per_alert, total_bytes, &mut one)?;
                            Ok((f, one))
                        },
                    )?;
                    match captured {
                        Some((f, one)) => {
                            freed = freed.saturating_add(f);
                            touched.extend(one);
                        }
                        None => {
                            tracing::warn!(hour = %hour, edge = %r.edge, boot = %r.boot, seq = r.seq,
                                "log record's evidence capture skipped: it keeps failing");
                            uncaptured += 1;
                        }
                    }
                }
                if uncaptured > 0 {
                    metrics.push(skipped_item("evidence", uncaptured));
                }
                outbox::queue_in(&tx, &metrics, &clock)?;
                progress_set(&tx, &hk, PROGRESS, upto)?;
                tx.commit()?;
                // What the copies evicted is gone for good only now (core.md §9).
                an.capture.release(freed);
                alerts.committed(&ch);
                alerts.evidence_changed(c, &touched);
                Ok::<_, anyhow::Error>(Some((ch, new)))
            })
            .await
    };
    let Some((ch, new_security)) = committed? else {
        return Ok((0, true));
    };
    state.alerts.announce(ch);
    crate::dnssec::admitted(state, admission).await;
    let n = rows.len();
    an.analysed.fetch_add(n as u64, Ordering::Relaxed);
    an.forget_attempts(hour, upto);
    if an.failing(FailPoint::AnalysisAfterEffects) {
        anyhow::bail!("stopped after the effects (test)");
    }
    outbox::flush(state).await?;
    // Evidence for the security alerts this batch raised.
    for (id, rule) in new_security {
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = evidence::start_since(&st, generation, id, rule).await {
                tracing::warn!(error = %format!("{e:#}"), alert = id, "evidence capture failed to start");
            }
        });
    }
    Ok((n, more))
}

/// The partition side of a batch: results and markers in one transaction (idempotent).
fn write_results(p: &mut super::Partition, rows: &[(Rec, RecResult)], now: &str) -> anyhow::Result<()> {
    let tx = p.conn.unchecked_transaction()?;
    let has_attr = p.has_table("attribution");
    let has_wb = p.has_table("would_blocks");
    // The markers this partition has (an older one lacks some, storage.md §5), numbered after
    // the key's three parameters.
    let marks: Vec<(&str, &str)> = [
        ("wire_check", "wire_check = coalesce(?{}, wire_check)"),
        ("trial_check", "trial_check = coalesce(trial_check, ?{})"),
        ("cold_check", "cold_check = coalesce(?{}, cold_check)"),
    ]
    .into_iter()
    .filter(|(c, _)| p.has_column("events", c))
    .collect();
    let update = (!marks.is_empty()).then(|| {
        let sets: Vec<String> = marks
            .iter()
            .enumerate()
            .map(|(i, (_, f))| f.replace("{}", &(i + 4).to_string()))
            .collect();
        format!(
            "UPDATE events SET {} WHERE edge_id = ?1 AND boot = ?2 AND seq = ?3",
            sets.join(", ")
        )
    });
    for (r, res) in rows {
        if res.skipped {
            continue;
        }
        if has_attr
            && let Some(fx) = &res.attribution
            && let Some(status) = fx.status
        {
            let j = serde_json::to_string(&fx.attribution)?;
            tx.prepare_cached(
                "INSERT OR REPLACE INTO attribution(edge_id, boot, seq, matches_json, status) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![r.edge, r.boot, r.seq, j, status.as_str()])?;
        }
        if has_wb {
            for wb in res.trial.would_blocks.iter().filter(|wb| !wb.stored) {
                let j = serde_json::to_string(&wb.matches)?;
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO would_blocks(edge_id, boot, seq, bundle_id, head_id, key, stage, matches_json, status)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )?
                .execute(params![r.edge, r.boot, r.seq, wb.bundle, wb.head, wb.key, wb.stage, j, wb.status.as_str()])?;
            }
        }
        let Some(sql) = &update else { continue };
        let wire_mark = res.wire.as_ref().map(|w| w.0.clone());
        // Set once all the record's trial bundles are checked; one still waiting for its head
        // leaves it null (core.md §6).
        let trial_mark = (res.trial.checked && res.trial.pending.is_empty()).then(|| now.to_string());
        let cold_mark = res.cold.as_ref().map(|c| c.result.clone());
        if wire_mark.is_none() && trial_mark.is_none() && cold_mark.is_none() {
            continue;
        }
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&r.edge, &r.boot, &r.seq];
        for (c, _) in &marks {
            args.push(match *c {
                "wire_check" => &wire_mark,
                "trial_check" => &trial_mark,
                _ => &cold_mark,
            });
        }
        tx.prepare_cached(sql)?.execute(args.as_slice())?;
    }
    tx.commit()?;
    Ok(())
}

/// One record's metric increments (core.md §10), at its event time.
fn record_items(r: &Rec, res: &RecResult) -> Vec<Item> {
    let mut metrics: Vec<Item> = Vec::new();
    {
        let ms = r.time().map(|t| t.as_millisecond()).unwrap_or(0);
        if let Some(fx) = &res.attribution {
            for (feed, role) in &fx.feed_hits {
                metrics.push((
                    "feed_hits".into(),
                    crate::metrics::labels("", &[("feed", feed), ("role", role)]),
                    ms,
                    1.0,
                ));
            }
        }
        // `trial_would_block` carries the record's edge, so a trial bundle's view charts one edge
        // (`edge=<id>`) or all of them (`edge=all` sums the edges, core.md §10).
        for wb in &res.trial.would_blocks {
            metrics.push((
                "trial_would_block".into(),
                crate::metrics::labels(
                    &r.edge,
                    &[
                        ("profile", r.profile.as_deref().unwrap_or("")),
                        ("bundle", &wb.bundle),
                    ],
                ),
                ms,
                1.0,
            ));
        }
        if let Some((_, Some(o))) = &res.wire {
            for k in &o.kinds {
                metrics.push((
                    "wire_mismatch".into(),
                    crate::metrics::labels(&r.edge, &[("kind", k.as_str())]),
                    ms,
                    1.0,
                ));
            }
        }
        if let Some(co) = &res.cold {
            for (bundle, _) in &co.missed {
                metrics.push((
                    "cold_missed_blocks".into(),
                    crate::metrics::labels(&r.edge, &[("bundle", bundle)]),
                    ms,
                    1.0,
                ));
            }
        }
    }
    metrics
}

/// Runs `f` (one item's writes) inside a savepoint of `tx` (README §2: a bad item never stalls
/// the receiver): `Some` when it applied; when it fails (an error or a panic) its writes are
/// rolled back and `exhausted` counts the failed attempt: `None` once the item has used its
/// attempts (the caller skips it and counts it), else the error, which abandons the caller's
/// transaction so the work is tried again later.
pub(crate) fn isolated<T>(
    tx: &rusqlite::Transaction<'_>,
    exhausted: impl FnOnce() -> bool,
    f: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<Option<T>> {
    tx.execute_batch("SAVEPOINT picket_item")?;
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let err = match out {
        Ok(Ok(v)) => {
            tx.execute_batch("RELEASE picket_item")?;
            return Ok(Some(v));
        }
        Ok(Err(e)) => e,
        Err(_) => anyhow::anyhow!("the item's writes panicked"),
    };
    tx.execute_batch("ROLLBACK TO picket_item; RELEASE picket_item")?;
    if exhausted() {
        tracing::warn!(error = %format!("{err:#}"), "an item's writes keep failing; skipped");
        Ok(None)
    } else {
        Err(err)
    }
}

/// `analysis_skipped{work}`: items a pass gave up on (README §2: dropped and counted).
pub(crate) fn skipped_item(work: &str, n: usize) -> Item {
    (
        "analysis_skipped".into(),
        crate::metrics::labels("", &[("work", work)]),
        Timestamp::now().as_millisecond(),
        n as f64,
    )
}

/// `bundle_key_hits`: the later of the stored and `at` (bundles.md §2 Tiering), with the key, so
/// retention finds hits whose key left the bundle (`compiler::retention::KeyHitRetention`).
fn key_hit_in(tx: &rusqlite::Transaction<'_>, bundle: &str, key: &str, at: &str) -> rusqlite::Result<()> {
    let seed = picket_bundle::hash::bundle_hash_seed(bundle);
    let h = picket_bundle::hash::KeyHash::of(seed, key.as_bytes());
    tx.execute(
        "INSERT INTO bundle_key_hits(bundle_id, hash128, last_hit_at, key) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(bundle_id, hash128) DO UPDATE SET last_hit_at = max(last_hit_at, excluded.last_hit_at),
            key = excluded.key",
        params![bundle, &h.0.to_be_bytes()[..], at, key],
    )?;
    Ok(())
}

/// True when an alert with `key` exists in any state.
fn alert_exists(tx: &rusqlite::Transaction<'_>, key: &str) -> rusqlite::Result<bool> {
    Ok(tx
        .query_row("SELECT 1 FROM alerts WHERE dedupe_key = ?1", [key], |_| Ok(()))
        .optional()?
        .is_some())
}

/// Raises security alert `spec` in `tx` with its evidence rule (stored with its backfill in the
/// same transaction); a new rule's alert goes into `new`, whose backfill is woken after the
/// commit ([`evidence::start_since`] only resumes it).
pub(crate) fn raise_security(
    alerts: &crate::alerts::Alerts,
    tx: &rusqlite::Transaction<'_>,
    spec: &RaiseSpec,
    rule: EvidenceRule,
    ch: &mut Changes,
    new: &mut Vec<(i64, EvidenceRule)>,
) -> rusqlite::Result<()> {
    // The rule and its backfill go in with the raise (README §2 Restarts); the capture of this
    // transaction's records sees it.
    if let Some(id) = evidence::raise_security_with_rule_in(alerts, tx, spec, &rule, ch)? {
        new.push((id, rule));
    }
    Ok(())
}

/// The alert effects of one record's attribution.
#[expect(
    clippy::too_many_arguments,
    reason = "one record's attribution effects, applied in the caller's transaction"
)]
fn apply_attribution_in(
    alerts: &crate::alerts::Alerts,
    tx: &rusqlite::Transaction<'_>,
    model: &Model,
    r: &Rec,
    fx: &AttrEffects,
    edge_name: &str,
    ch: &mut Changes,
    new: &mut Vec<(i64, EvidenceRule)>,
) -> anyhow::Result<()> {
    // attribution_unavailable: once per edge and bundle version (core.md §6 step 1).
    for u in &fx.unavailable {
        let key = format!("attribution_unavailable:{}:{}:{}", r.edge, u.bundle, u.head);
        if !alert_exists(tx, &key)? {
            let spec = RaiseSpec::new(
                "attribution_unavailable",
                Severity::Warning,
                key,
                format!(
                    "Edge {}: logs name bundle version {} of {} whose feed history is gone",
                    crate::util::sanitize_for_message(edge_name, 64),
                    crate::util::sanitize_for_message(&u.head, 64),
                    crate::util::sanitize_for_message(&u.bundle, 128),
                ),
                json!({"edge": r.edge, "bundle": u.bundle, "head": u.head, "reason": u.reason}),
            )
            .edge(&r.edge)
            .bundle(&u.bundle);
            alerts.raise_in(tx, &spec, ch)?;
        }
    }
    if let Some(cfg) = &fx.config_gone {
        let key = format!("attribution_unavailable:{}:config:{}", r.edge, cfg);
        if !alert_exists(tx, &key)? {
            let spec = RaiseSpec::new(
                "attribution_unavailable",
                Severity::Warning,
                key,
                format!(
                    "Edge {}: logs name config version {} that core no longer keeps",
                    crate::util::sanitize_for_message(edge_name, 64),
                    crate::util::sanitize_for_message(cfg, 64)
                ),
                json!({"edge": r.edge, "config": cfg}),
            )
            .edge(&r.edge);
            alerts.raise_in(tx, &spec, ch)?;
        }
    }
    // attribution_mismatch (step 4), per edge and logged bundle.
    if let Some((step, bundle, replayed)) = &fx.mismatch {
        let b = bundle.clone().unwrap_or_default();
        let spec = RaiseSpec::new(
            "attribution_mismatch",
            Severity::Warning,
            format!("attribution_mismatch:{}:{}", r.edge, b),
            format!(
                "Edge {}: replay of a query decided by {} doesn't find the logged decision",
                crate::util::sanitize_for_message(edge_name, 64),
                crate::util::sanitize_for_message(&b, 128)
            ),
            json!({
                "edge": r.edge, "boot": r.boot, "seq": r.seq, "qname": r.qname, "qtype": r.qtype,
                "logged": {"step": step, "bundle": bundle, "key": r.reason.as_ref().and_then(|x| x.key.clone())},
                "replayed": replayed.as_ref().map(|(s, b)| json!({"step": s, "bundle": b})),
                "record": record::record_id(&r.ts, &r.edge, &r.boot, r.seq),
            }),
        )
        .edge(&r.edge);
        let spec = if b.is_empty() { spec } else { spec.bundle(&b) };
        alerts.raise_in(tx, &spec, ch)?;
    }
    if let Some((bundle, key)) = &fx.key_hit {
        key_hit_in(tx, bundle, key, &r.ts)?;
    }
    // category_blocked (core.md §9): a block by a rule attribution finds (decisive or also
    // matched) in a feed whose category the profile alerts on.
    if r.decision() == Some(picket_api::logs::Decision::Block)
        && let Some(profile) = r.profile.as_deref().and_then(|p| model.profiles.get(p))
        && !matches!(profile.edge.log, picket_api::edge_config::LogLevel::Off)
    {
        let mut feeds: BTreeMap<String, &'static str> = BTreeMap::new();
        for m in &fx.attribution.matches {
            if (m.role == "decisive" || m.role == "also_matched")
                && let Some(cat) = feed_category(model, &m.feed)
                && profile.alert_categories.iter().any(|c| c == cat)
            {
                feeds.insert(m.feed.clone(), cat);
            }
        }
        if !feeds.is_empty() {
            let security = feeds.values().any(|c| *c == "security");
            let feeds = feeds
                .iter()
                .map(|(f, c)| json!({"feed": f, "category": c}))
                .collect::<Vec<_>>();
            raise_category_blocked_in(alerts, tx, r, security, "a feed", ("feeds", feeds), ch, new)?;
        }
    }
    Ok(())
}

/// Lookup Blocks one `category_blocked` raise names at most (README §2 Bounded; a profile
/// attaches few providers).
const MAX_ALERT_LOOKUPS: usize = 8;
/// The largest provider `detail` an alert keeps (serialized bytes); a larger one is replaced by
/// `{"truncated": true}`, so the alert's details stay within the engine's cap.
const MAX_ALERT_LOOKUP_DETAIL: usize = 4 * 1024;

/// `category_blocked` for a block by a sync lookup (core.md §9 "Block alerts per profile": "a
/// query in the profile blocked by a sync lookup whose provider is in `alert_providers`"): the
/// record's `lookups[]` Blocks (api.md §5) from providers in the profile's effective
/// `alert_providers` (unset: every provider whose category is `security`; `[]`: none). Warning
/// when one of them is a `security` provider, info otherwise (core.md §9 table); keyed, grouped
/// and given evidence as a feed's block is, with each provider's reason and detail. Attribution
/// never replays these records (core.md §6 attributes rule decisions only), so this check reads
/// the record itself; it runs in the record's effects savepoint, once, like the others.
fn lookup_blocked_in(
    alerts: &crate::alerts::Alerts,
    tx: &rusqlite::Transaction<'_>,
    model: &Model,
    r: &Rec,
    ch: &mut Changes,
    new: &mut Vec<(i64, EvidenceRule)>,
) -> anyhow::Result<()> {
    use picket_api::logs::{Decision, LookupItem, LookupVerdict, MatchKind};
    if r.decision() != Some(Decision::Block) || r.reason.as_ref().is_none_or(|x| x.kind != MatchKind::Lookup)
    {
        return Ok(());
    }
    let Some(profile) = r.profile.as_deref().and_then(|p| model.profiles.get(p)) else {
        return Ok(());
    };
    if matches!(profile.edge.log, picket_api::edge_config::LogLevel::Off) {
        return Ok(());
    }
    let alerting = crate::lookups::alert_providers(model, profile);
    if alerting.is_empty() {
        return Ok(());
    }
    // Stored by ingest from the decoded record; one that no longer parses names nothing.
    let items: Vec<LookupItem> = r
        .lookups_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let mut security = false;
    let mut providers: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    for it in items
        .iter()
        .filter(|i| i.verdict == LookupVerdict::Block && alerting.contains(&i.provider))
    {
        if providers.len() >= MAX_ALERT_LOOKUPS || providers.contains_key(it.provider.as_str()) {
            continue;
        }
        let category = model
            .lookup_providers
            .get(&it.provider)
            .map(|p| p.category.as_str());
        security |= category == Some("security");
        let detail = it.detail.as_ref().map(|d| {
            if serde_json::to_string(d).map_or(usize::MAX, |s| s.len()) > MAX_ALERT_LOOKUP_DETAIL {
                json!({"truncated": true})
            } else {
                d.clone()
            }
        });
        providers.insert(
            &it.provider,
            json!({
                "provider": it.provider, "category": category,
                "score": it.score.and_then(crate::lookups::store::score_f64),
                "reason": it.reason.as_deref().map(|x| crate::util::sanitize_for_message(x, 256)),
                "detail": detail, "cached": it.cached,
            }),
        );
    }
    if providers.is_empty() {
        return Ok(());
    }
    let providers = providers.into_values().collect::<Vec<_>>();
    raise_category_blocked_in(
        alerts,
        tx,
        r,
        security,
        "a lookup provider",
        ("providers", providers),
        ch,
        new,
    )?;
    Ok(())
}

/// Raises `category_blocked` for record `r` (core.md §9): keyed on (device, registrable domain)
/// (Grouping), warning when a `security` feed or provider blocked it, else info; `by` names the
/// source in the title and `source` lists them in the details. The evidence rule copies that
/// device's records under the domain; the alert's `edge` is the record's (core.md §9 record).
#[expect(
    clippy::too_many_arguments,
    reason = "one record's alert, raised in the caller's transaction"
)]
fn raise_category_blocked_in(
    alerts: &crate::alerts::Alerts,
    tx: &rusqlite::Transaction<'_>,
    r: &Rec,
    security: bool,
    by: &str,
    source: (&str, Vec<serde_json::Value>),
    ch: &mut Changes,
    new: &mut Vec<(i64, EvidenceRule)>,
) -> rusqlite::Result<()> {
    let device = evidence::device_of(r);
    let domain = crate::psl::grouping_key(&r.qname);
    let mut details = json!({
        "device": device, "client": r.client_ip, "domain": domain, "name": r.qname,
        "profile": r.profile, "edge": r.edge,
        "record": record::record_id(&r.ts, &r.edge, &r.boot, r.seq),
    });
    details[source.0] = serde_json::Value::Array(source.1);
    let spec = RaiseSpec::new(
        "category_blocked",
        if security {
            Severity::Warning
        } else {
            Severity::Info
        },
        alerts_mod::category_blocked_key(&device, &r.qname),
        format!(
            "{} was blocked from {} by {by} its profile alerts on",
            crate::util::sanitize_for_message(&device, 128),
            crate::util::sanitize_for_message(&domain, 256)
        ),
        details,
    )
    // The alert's `edge` (core.md §9 record): the edge whose record raised it.
    .seen_on_edge(&r.edge);
    let rule = EvidenceRule {
        domain,
        device: Some(device),
        ..Default::default()
    };
    raise_security(alerts, tx, &spec, rule, ch, new)
}

/// `wire_mismatch` (core.md §6): keyed on the edge and the release that logged the record (the
/// `edge_version` its `boot` reported in `hello`; `unknown` for a boot core never heard a
/// `hello` from), with up to [`MAX_WIRE_EXAMPLES`] examples, each charged to the evidence budget
/// when it is stored (core.md §9).
#[expect(
    clippy::too_many_arguments,
    reason = "one record's wire check, raised in the caller's transaction"
)]
fn wire_mismatch_in(
    alerts: &crate::alerts::Alerts,
    cap: &Capture,
    tx: &rusqlite::Transaction<'_>,
    r: &Rec,
    o: &wire::Outcome,
    edge_name: &str,
    total_bytes: u64,
    ch: &mut Changes,
) -> anyhow::Result<()> {
    let release: String = tx
        .query_row(
            "SELECT edge_version FROM edge_boots WHERE edge_id = ?1 AND boot = ?2",
            params![r.edge, r.boot],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .unwrap_or_else(|| "unknown".into());
    let kinds: Vec<&str> = o.kinds.iter().map(|k| k.as_str()).collect();
    let spec = RaiseSpec::new(
        "wire_mismatch",
        Severity::Warning,
        format!("wire_mismatch:{}:{}", r.edge, release),
        format!(
            "Edge {} ({}): core's decode of a logged answer disagrees with what the edge logged",
            crate::util::sanitize_for_message(edge_name, 64),
            crate::util::sanitize_for_message(&release, 64)
        ),
        json!({"edge": r.edge, "release": release, "kinds": kinds, "qname": r.qname, "answer_id": r.answer_id}),
    )
    .edge(&r.edge);
    let Some(a) = alerts.raise_in(tx, &spec, ch)? else {
        return Ok(());
    };
    let (n, dup): (i64, bool) = tx.query_row(
        "SELECT count(*), coalesce(max(edge_id = ?2 AND boot = ?3 AND seq = ?4), 0) FROM wire_examples WHERE alert_id = ?1",
        params![a.id, r.edge, r.boot, r.seq],
        |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
    )?;
    if n >= MAX_WIRE_EXAMPLES || dup {
        return Ok(());
    }
    let logged = json!({
        "edge": r.edge, "boot": r.boot, "seq": r.seq, "ts": r.ts, "qname": r.qname, "qtype": r.qtype,
        "decision": r.decision, "reason": r.reason, "answers": r.answers, "targets": r.targets, "cname": r.cname,
        "answer_id": r.answer_id, "received_at": r.received_at,
    });
    let decoded = match &o.decoded {
        Ok(d) => json!({"decoded": d}),
        Err(e) => json!({"error": e}),
    };
    let rj = serde_json::to_string(&logged)?;
    let dj = serde_json::to_string(&decoded)?;
    let wire = r.answer_wire.clone().unwrap_or_default();
    let need = (rj.len() + dj.len() + wire.len()) as u64;
    if !cap.charge(need, total_bytes) {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO wire_examples(alert_id, edge_id, boot, seq, kind, record_json, wire, decoded_json, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            a.id,
            r.edge,
            r.boot,
            r.seq,
            kinds.first().copied().unwrap_or("rejected"),
            rj,
            wire,
            dj,
            crate::util::now_ts()
        ],
    )?;
    Ok(())
}

/// One retro turn: new runs, then the due steps on every partition in the window, oldest first;
/// returns (hits, more work left). A partition whose step fails backs off and the others go on
/// (README §2); `strict` (tests) ignores back-offs and returns the first failure.
async fn retro_turn(state: &SharedState, strict: bool) -> anyhow::Result<(usize, bool)> {
    if state.restore.logs_pending() {
        return Ok((0, false));
    }
    state
        .db
        .write(|c| Ok::<_, anyhow::Error>(super::retro::record_new_runs(c)?))
        .await?;
    let store = state.logs.writer().store().clone();
    let list = tokio::task::spawn_blocking(move || store.list()).await??;
    let model = state.analysis.model(state).await?;
    let an = state.analysis.clone();
    let mut steps = 0;
    let mut hits_total = 0;
    for (hour, _) in list {
        if !strict && an.backing_off(hour) {
            continue;
        }
        loop {
            if steps >= TURN_RETRO_STEPS {
                return Ok((hits_total, true));
            }
            steps += 1;
            let st = state.clone();
            let m = model.clone();
            let job = state.scheduler.light.spawn(Some("retro_match"), async move {
                super::retro::step(&st, hour, m).await
            });
            let Some(job) = job else {
                return Ok((hits_total, true));
            };
            match job.await {
                Ok(Ok(out)) => {
                    an.partition_ok(hour);
                    hits_total += out.hits;
                    if !out.more {
                        break;
                    }
                }
                Ok(Err(e)) if strict => return Err(e),
                Ok(Err(e)) => {
                    tracing::warn!(error = %format!("{e:#}"), hour = %hour, "retro-match of a partition failed; it backs off");
                    an.partition_failed(hour);
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, hour = %hour, "retro-match of a partition panicked; it backs off");
                    an.partition_failed(hour);
                    break;
                }
            }
        }
    }
    Ok((hits_total, false))
}
