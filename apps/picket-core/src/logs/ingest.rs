//! Log ingest (`POST /v1/logs`; core.md §6, api.md §2, §5, storage.md §3–§4).
//!
//! 1. **Admission:** each edge gets one batch in progress at a time, taken before its body is
//!    read, so an edge holds at most one body in memory however many connections or HTTP/2
//!    streams it opens; the edges share a few decode-and-store slots (README §2, Bounded: a
//!    capped share each). A batch that waits too long for a slot gets `503` and the edge
//!    retries. The request's key is checked when it starts (the edge port) and again in the
//!    transactions that store the batch: a key replaced (or an edge deleted) while the body
//!    arrived stores nothing more and gets `403` (api.md §1 Key change).
//! 2. **Decode** ([`super::decode`]): a batch core can't read gets `400`/`413`; records it can't
//!    parse or validate, or older than the log retention window, are dropped and counted.
//! 3. **Boots:** records from a boot core never heard a `hello` from are kept under release
//!    `unknown` (an `edge_boots` row without a version, superseded at once when the edge already
//!    has a current boot, so it ages out). Each edge may hold a capped number of such rows; past
//!    it a boot isn't registered, but its records are still stored (release `unknown` either
//!    way), so a long crash loop during an outage never costs the current boot's records.
//! 4. **Query records** go to the hourly partition of their event time, deduplicated on (edge,
//!    boot, seq), each with its answer stored once per partition by `id` (core.md §6), in the
//!    partition of each record that references it, never by the answer's own time. A record whose
//!    answer neither its batch nor its partition holds is stored with `answer_missing`. A record
//!    whose `ts` was clamped from a later hour goes, on every attempt, to the hour of its first
//!    attempt (`log_clamped`, runs of seqs per boot: about one per hour for an edge whose clock
//!    runs ahead, a capped number per edge), so a retry after the hour turns is still a
//!    duplicate.
//! 5. **Other records** go to `core.db`: `event` and `condition` records to `edge_events`
//!    (deduplicated on (edge, boot, seq), update events also on their `result_id`), `allow`
//!    records to `temp_allows` (never undoing a newer record; a capped number of rows per edge),
//!    with their alert effects (update outcomes, activation failures for targets core offered,
//!    listener rejections, panics, page-file refetches, TLS version refusals and firewall
//!    repairs; an allow is history, never an alert) and the condition changes in the matching
//!    alerts' history, all in the same transaction (core.md §9; README §2 Restarts). The edge's live update record follows right after the commit.
//! 6. **Ack** only after every write above is durable (`synchronous=FULL`). A failure that isn't
//!    a record's own gets `503`.
//!
//! **Config restores.** A batch takes the restore generation when it starts
//! ([`crate::config::export::RestoreGate`]) and each step that commits checks it again inside its
//! serialized writer operation, ordered with the restore's commit and cleanup there: the boots,
//! events and lookup transactions on the `core.db` writer, each partition write on the log
//! writer (with `logs_pending`), the metric increments on the `metrics.db` writer. Once a restore
//! committed since the batch started, the step commits nothing and the batch gets the usual
//! retryable `503` ([`RestoreOvertook`]), never an ack, so no pre-restore work lands in restored
//! state and reports success. What a batch committed before the restore is pre-restore state,
//! kept or dropped by the restore like any; the edge's retry, under the new generation, stores
//! the batch again, deduplicated on (edge, boot, seq) against whatever the restore kept. Analysis never delays the ack: the wire check, attribution,
//!    retro-match, trial checks and lookups find their work in the partitions (`wire_check` and
//!    `trial_check` null, no `attribution` row) and are woken through [`IngestSeams`].
//!
//! `lookup` records and the sync lookups on `q` records feed `lookup_verdicts`, `lookup_blocks`
//! and `lookup_queue` in step 5b, before the ack ([`crate::lookups::ingest`], core.md §7).
//! Retro-match's `answered_names`/`answered_ips` and alert evidence copies are written by the
//! analysis that follows ingest ([`super::analysis`], [`super::retro`], [`super::evidence`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use jiff::Timestamp;
use picket_api::logs::{AckPoint, AllowAction, ConditionChange, EventRecord, LookupRecord, event_kind};
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::json;
use tokio::sync::{Semaphore, watch};

use super::decode::{self, Batch, BatchError, DropReason, Record};
use super::writer::{EventRow, LogWriter, StoreError, StoreJob};
use crate::alerts::{Alerts, Changes, RaiseSpec, Severity};
use crate::edges::hub::{Hub, UpdateRecord};
use crate::state::AppState;

/// Batches being decoded and stored at once, across edges.
pub const SLOTS: usize = 4;
/// How long a batch waits for its edge's slot and a shared slot before `503`.
pub const ADMIT_WAIT: Duration = Duration::from_secs(10);
/// Unknown boots (no `hello` heard) one edge may hold in `edge_boots` (README §2, Bounded).
pub const MAX_UNKNOWN_BOOTS: i64 = 256;
/// `temp_allows` rows one edge may hold (README §2, Bounded: allow ids come from the edge). A
/// record for a new allow past it is dropped and counted (`store_failed`); rows leave with
/// retention (storage.md §4). A household's allows are capped per device by the profile's
/// `max_active` and `rate_per_hour`, so this is far above real use. Policy choice: the spec
/// gives no number.
pub const MAX_TEMP_ALLOWS_PER_EDGE: i64 = 20_000;
/// Runs of clamped records one edge may hold in `log_clamped` (README §2, Bounded: seqs come
/// from the edge). An edge sends its records in seq order, so a clock running an hour or more
/// ahead costs about one run per boot and hour. A record that would need a new run past the
/// share is stored at its clamped time without a pin (logged), so a retry of it after the hour
/// turns may be stored twice. Policy choice: the spec gives no number.
pub const MAX_CLAMPED_RUNS_PER_EDGE: i64 = 4096;
/// Most lookup records offered to the lookups seam per batch.
const MAX_LOOKUPS_PER_BATCH: usize = 1000;

/// Why a batch wasn't acked.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// The batch can't be read at all (`400`/`413`): the edge splits it.
    #[error("{0}")]
    Batch(#[from] BatchError),
    /// Storage failed for a reason that isn't a record's (`503`): the edge retries.
    #[error("{0}")]
    Unavailable(String),
    /// The edge's share of ingest is busy (`503`).
    #[error("ingest is busy")]
    Busy,
    /// The request's key is no longer the edge's (`403`): replaced, or the edge deleted, after
    /// the request began (api.md §1 Key change). Nothing more of the batch is stored.
    #[error("this key is no longer registered for the edge")]
    KeyGone,
}

/// What analysis modules wait on (core.md §6: never delaying ingest or the ack).
pub struct IngestSeams {
    /// The newest partition hours with new `q` records: the wire check, attribution, retro-match
    /// and trial checks scan them for unchecked records (`wire_check`/`trial_check` null).
    pub stored: watch::Sender<Vec<Timestamp>>,
    /// Late lookup answers (`lookup` records), bounded per batch, for core.md §7 (NOT
    /// IMPLEMENTED: their consumer).
    pub lookups: watch::Sender<Vec<(String, LookupRecord)>>,
}

impl Default for IngestSeams {
    fn default() -> Self {
        Self {
            stored: watch::channel(Vec::new()).0,
            lookups: watch::channel(Vec::new()).0,
        }
    }
}

/// A config restore committed after the batch started (module docs): the step refused, nothing
/// of it committed; the edge retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a config restore replaced the configuration while the batch was stored; retry")]
pub struct RestoreOvertook;

/// Tests: the places a batch can be held ([`Ingest::pause_at`]), each after one step committed.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IngestPoint {
    /// After the boots' transaction.
    AfterBoots,
    /// After every partition write.
    AfterPartitions,
    /// After the events' transaction.
    AfterEvents,
    /// After the lookups' transaction, before the metrics.
    AfterLookups,
}

/// The ingest service.
pub struct Ingest {
    writer: LogWriter,
    per_edge: std::sync::Mutex<HashMap<String, Arc<Semaphore>>>,
    slots: Arc<Semaphore>,
    admit_wait_ms: std::sync::atomic::AtomicU64,
    pub seams: IngestSeams,
    pauses: std::sync::Mutex<HashMap<IngestPoint, Arc<super::analysis::Pause>>>,
}

/// An edge's one batch in progress ([`Ingest::admit`]), held from before its body is read
/// until the batch is acked or refused.
pub struct EdgeSlot(
    #[expect(dead_code, reason = "held for its drop, which frees the edge's batch slot")]
    tokio::sync::OwnedSemaphorePermit,
);

/// What one batch did, for tests and metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestReport {
    pub ack: AckPoint,
    pub stored: usize,
    pub duplicates: usize,
    pub dropped: BTreeMap<String, u64>,
    pub answer_missing: usize,
    pub events: usize,
}

impl Ingest {
    pub fn new(writer: LogWriter) -> Self {
        Self {
            writer,
            per_edge: Default::default(),
            slots: Arc::new(Semaphore::new(SLOTS)),
            admit_wait_ms: std::sync::atomic::AtomicU64::new(picket_api::duration::as_millis_u64(ADMIT_WAIT)),
            seams: IngestSeams::default(),
            pauses: Default::default(),
        }
    }

    /// Tests: the next batch to reach `point` signals `reached` and waits for `resume`.
    #[doc(hidden)]
    pub fn pause_at(&self, point: IngestPoint) -> Arc<super::analysis::Pause> {
        let p = Arc::new(super::analysis::Pause::default());
        if let Ok(mut m) = self.pauses.lock() {
            m.insert(point, p.clone());
        }
        p
    }

    async fn paused_at(&self, point: IngestPoint) {
        let p = self.pauses.lock().ok().and_then(|mut m| m.remove(&point));
        if let Some(p) = p {
            p.reached.notify_one();
            p.resume.notified().await;
        }
    }

    /// Sets how long a batch waits for a slot (tests).
    pub fn set_admit_wait(&self, d: Duration) {
        self.admit_wait_ms.store(
            picket_api::duration::as_millis_u64(d),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn admit_wait(&self) -> Duration {
        Duration::from_millis(self.admit_wait_ms.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Takes `edge`'s one batch in progress, before its body is read (README §2, Bounded: one
    /// body per edge in memory, whatever it opens); `Busy` after the admission wait.
    pub async fn admit(&self, edge: &str) -> Result<EdgeSlot, IngestError> {
        let mine = self.edge_slot(edge);
        let permit = tokio::time::timeout(self.admit_wait(), mine.acquire_owned())
            .await
            .map_err(|_| IngestError::Busy)?
            .map_err(|_| IngestError::Busy)?;
        Ok(EdgeSlot(permit))
    }

    pub fn writer(&self) -> &LogWriter {
        &self.writer
    }

    fn edge_slot(&self, edge: &str) -> Arc<Semaphore> {
        let mut m = self.per_edge.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() > 4096 {
            m.retain(|_, s| s.available_permits() == 0);
        }
        m.entry(edge.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone()
    }

    /// Ingests one `POST /v1/logs` body from `edge`, sent with the key whose fingerprint is
    /// `key`, admitted with `_slot` ([`Ingest::admit`]).
    pub async fn ingest(
        &self,
        state: &AppState,
        _slot: EdgeSlot,
        edge: &str,
        key: &str,
        body: Bytes,
        gzip: bool,
    ) -> Result<IngestReport, IngestError> {
        // The restore generation, before the slot wait and the settings the decode reads: a
        // restore committing meanwhile then refuses every write of this batch (module docs).
        let generation = state.restore.generation();
        let _shared = tokio::time::timeout(self.admit_wait(), self.slots.clone().acquire_owned())
            .await
            .map_err(|_| IngestError::Busy)?
            .map_err(|_| IngestError::Busy)?;

        let now = Timestamp::now();
        let window = state.settings().retention.query_logs.as_duration();
        let ctx = decode::Context {
            now,
            oldest: crate::util::window_start(now, window),
        };
        let batch =
            tokio::task::spawn_blocking(move || decode::decode_body(&body, gzip, &ctx, &decode::LIMITS))
                .await
                .map_err(|e| IngestError::Unavailable(format!("decode task: {e}")))??;
        self.store_batch_under(state, edge, key, batch, generation).await
    }

    /// Stores a decoded batch (steps 3–6 of the module docs) from `edge`, sent with the key
    /// whose fingerprint is `key`. The key is checked again in the transactions that store the
    /// batch (api.md §1 Key change: a request that began before a replacement, its body still
    /// arriving, stores nothing once the replacement committed).
    pub async fn store_batch(
        &self,
        state: &AppState,
        edge: &str,
        key: &str,
        batch: Batch,
    ) -> Result<IngestReport, IngestError> {
        let generation = state.restore.generation();
        self.store_batch_under(state, edge, key, batch, generation).await
    }

    /// [`Self::store_batch`] for a batch that began under restore generation `generation`.
    async fn store_batch_under(
        &self,
        state: &AppState,
        edge: &str,
        key: &str,
        mut batch: Batch,
        generation: u64,
    ) -> Result<IngestReport, IngestError> {
        let ack = batch.ack();
        let mut report = IngestReport {
            ack,
            ..Default::default()
        };
        // The restore generation the batch works under, checked again in each step's writer
        // together with `logs_pending` (module docs): `stale` is true once a restore committed
        // since, or while one empties the logs.
        let gate = state.restore.clone();
        let stale: crate::lookups::ingest::Stale = {
            let g = gate.clone();
            Arc::new(move || g.logs_pending() || !g.is_current(generation))
        };
        let overtook = || IngestError::Unavailable(RestoreOvertook.to_string());

        // 3. Boots: register those core never heard a hello from, up to the edge's share. Past
        // it, records are stored anyway (release `unknown` either way).
        let boots: BTreeSet<String> = batch.records.iter().map(|r| r.header().boot.clone()).collect();
        let (edge_s, key_s) = (edge.to_string(), key.to_string());
        let st = Arc::clone(&stale);
        let unregistered = state
            .db
            .write(move |c| {
                if st() {
                    return Ok(Err(RestoreOvertook));
                }
                register_boots(c, &edge_s, &key_s, &boots).map(Ok)
            })
            .await
            .map_err(|e| unavailable(&e))?
            .map_err(|_| overtook())?
            .ok_or(IngestError::KeyGone)?;
        if unregistered > 0 {
            tracing::debug!(
                edge,
                unregistered,
                "unknown boots over the edge's share; their records are kept as release unknown"
            );
        }

        self.paused_at(IngestPoint::AfterBoots).await;

        // 4a. Records clamped from a later hour keep their first attempt's hour (core.md §6:
        // dedupe on (edge, boot, seq), whatever the clamp).
        pin_clamped_hours(state, edge, &mut batch, Arc::clone(&stale)).await?;

        // 4. Query records into their partitions, with their answers.
        let mut answers: HashMap<String, Vec<u8>> = HashMap::new();
        let mut by_hour: BTreeMap<Timestamp, Vec<EventRow>> = BTreeMap::new();
        let mut transports: BTreeMap<(String, i64), u64> = BTreeMap::new();
        let mut others: Vec<Record> = Vec::new();
        let mut lookups: Vec<(String, LookupRecord)> = Vec::new();
        // Async lookups' view of each q record, per hour in row order (core.md §7).
        let mut lookup_q: BTreeMap<Timestamp, Vec<crate::lookups::ingest::QueryInfo>> = BTreeMap::new();
        let mut q_meta: BTreeMap<Timestamp, Vec<(String, i64)>> = BTreeMap::new();
        for r in std::mem::take(&mut batch.records) {
            match r {
                Record::Answer(a) => {
                    answers.insert(a.id, a.wire);
                }
                Record::Query(q) => {
                    let hour = super::partition::hour_start(&q.q.h.ts);
                    let transport = match q.q.proto {
                        picket_api::logs::Proto::Udp | picket_api::logs::Proto::Tcp => "dns",
                        picket_api::logs::Proto::Dot => "dot",
                        picket_api::logs::Proto::Doh => "doh",
                    };
                    q_meta
                        .entry(hour)
                        .or_default()
                        .push((transport.to_string(), q.q.h.ts.as_millisecond()));
                    lookup_q
                        .entry(hour)
                        .or_default()
                        .push(crate::lookups::ingest::QueryInfo::of(&q.q, q.response.is_some()));
                    by_hour.entry(hour).or_default().push(event_row(edge, q));
                }
                Record::Lookup(l) => {
                    if lookups.len() < MAX_LOOKUPS_PER_BATCH {
                        lookups.push((edge.to_string(), l));
                    }
                }
                other => others.push(other),
            }
        }
        let answers = Arc::new(answers);
        let mut stored_hours = Vec::new();
        // While a config restore empties the partitions of pre-restore records, or once one
        // committed after the batch started, the log writer refuses each write (`503`, the edge
        // retries): checked on the writer thread, so it is ordered with the restore's deletions
        // (core.md §2; `config::export::RestoreGate`).
        let st = Arc::clone(&stale);
        let refuse: super::writer::Refuse = Arc::new(move || st());
        for (hour, rows) in by_hour {
            let n = rows.len();
            let out = self
                .writer
                .write_unless(
                    StoreJob {
                        hour,
                        rows,
                        answers: answers.clone(),
                    },
                    refuse.clone(),
                )
                .await
                .map_err(|e| match e {
                    StoreError::System(e) => IngestError::Unavailable(e),
                    e @ StoreError::Refused => IngestError::Unavailable(e.to_string()),
                })?;
            report.stored += out.stored.len();
            report.duplicates += out.duplicates;
            report.answer_missing += out.answer_missing;
            if out.failed > 0 {
                *batch.dropped.entry(DropReason::StoreFailed).or_insert(0) += out.failed as u64;
            }
            if !out.stored.is_empty() {
                stored_hours.push(hour);
            }
            if let Some(qs) = lookup_q.get_mut(&hour) {
                for i in &out.stored {
                    if let Some(q) = qs.get_mut(*i) {
                        q.stored = true;
                    }
                }
            }
            if let Some(meta) = q_meta.get(&hour) {
                for i in &out.stored {
                    if let Some((t, ms)) = meta.get(*i).filter(|_| *i < n) {
                        *transports.entry((t.clone(), *ms)).or_insert(0) += 1;
                    }
                }
            }
        }

        self.paused_at(IngestPoint::AfterPartitions).await;

        // 5. Events, conditions and allows into core.db, with their alert effects.
        let ctx = OthersCtx::new(state, edge, key, &others).await;
        let st = Arc::clone(&stale);
        let mut effects = state
            .db
            .write(move |c| {
                if st() {
                    return Ok(Err(RestoreOvertook));
                }
                store_others(c, &ctx, others).map(Ok)
            })
            .await
            .map_err(|e| unavailable(&e))?
            .map_err(|_| overtook())?
            .ok_or(IngestError::KeyGone)?;
        report.events = effects.stored;
        if effects.failed > 0 {
            *batch.dropped.entry(DropReason::StoreFailed).or_insert(0) += effects.failed as u64;
        }
        state.alerts.announce(std::mem::take(&mut effects.alerts));
        if effects.revoke_list_changed {
            state.edges.publisher.trigger(Some(edge));
        }

        self.paused_at(IngestPoint::AfterEvents).await;

        // 5b. Async lookups (core.md §7): verdicts, Blocks, retries, async attachments, re-check
        // deadlines and answers checked against Blocks, in core.db before the ack.
        let lookup_records: Vec<LookupRecord> = lookups.iter().map(|(_, l)| l.clone()).collect();
        crate::lookups::ingest::apply_within(
            state,
            edge,
            lookup_q.into_values().flatten().collect(),
            lookup_records,
            Some(Arc::clone(&stale)),
        )
        .await
        .map_err(|e| match e.downcast_ref::<RestoreOvertook>() {
            Some(_) => overtook(),
            None => unavailable(&e),
        })?;

        self.paused_at(IngestPoint::AfterLookups).await;

        // Metrics (core.md §10): at each record's event time.
        let now_ms = Timestamp::now().as_millisecond();
        let mut items = Vec::new();
        let total_records = report.stored + effects.stored;
        if total_records > 0 {
            items.push((
                "log_records".to_string(),
                crate::metrics::labels(edge, &[]),
                now_ms,
                total_records as f64,
            ));
        }
        for (reason, n) in &batch.dropped {
            items.push((
                "log_dropped".to_string(),
                crate::metrics::labels(edge, &[("reason", reason.as_str())]),
                now_ms,
                *n as f64,
            ));
        }
        if report.answer_missing > 0 {
            items.push((
                "log_answer_missing".to_string(),
                crate::metrics::labels(edge, &[]),
                now_ms,
                report.answer_missing as f64,
            ));
        }
        for ((t, ms), n) in transports {
            items.push((
                "queries_by_transport".to_string(),
                crate::metrics::labels(edge, &[("transport", &t)]),
                ms,
                n as f64,
            ));
        }
        for (kind, ms) in &effects.activation_failures {
            items.push((
                "activations_failed".to_string(),
                crate::metrics::labels(edge, &[("kind", kind)]),
                *ms,
                1.0,
            ));
        }
        if effects.repairs > 0 {
            items.push((
                "fw_repairs".to_string(),
                crate::metrics::labels(edge, &[]),
                now_ms,
                effects.repairs as f64,
            ));
        }
        if effects.tls_unlogged > 0 {
            items.push((
                "tls_refused_unlogged".to_string(),
                crate::metrics::labels(edge, &[]),
                now_ms,
                effects.tls_unlogged as f64,
            ));
        }
        let st = Arc::clone(&stale);
        let current: crate::metrics::store::WriteGuard = Arc::new(move || !st());
        if !state
            .metrics
            .count_if(&state.metrics_db, items, Some(current))
            .await
        {
            return Err(overtook());
        }
        report.dropped = batch
            .dropped
            .iter()
            .map(|(r, n)| (r.as_str().to_string(), *n))
            .collect();

        // 6. Wake analysis; never waited on.
        if !stored_hours.is_empty() {
            self.seams.stored.send_replace(stored_hours);
        }
        if !lookups.is_empty() {
            self.seams.lookups.send_replace(lookups);
        }
        Ok(report)
    }
}

fn unavailable(e: &anyhow::Error) -> IngestError {
    IngestError::Unavailable(format!("{e:#}"))
}

/// Registers boots core never heard a hello from (release `unknown`), up to the edge's share;
/// returns how many weren't registered, or `None` when `key` is no longer `edge`'s (nothing of
/// the batch is stored then; api.md §1). A boot first seen in spooled records while the edge
/// already has a current boot (a hello) is older than it, or will be superseded by its own
/// hello: it is registered as superseded now, so it ages out (storage.md §4); a hello of that
/// boot makes it current again.
fn register_boots(
    c: &mut rusqlite::Connection,
    edge: &str,
    key: &str,
    boots: &BTreeSet<String>,
) -> anyhow::Result<Option<usize>> {
    let tx = c.transaction()?;
    if !crate::edges::status::key_holds(&tx, edge, key)? {
        return Ok(None);
    }
    let now = crate::util::now_ts();
    let mut unknown: i64 = tx.query_row(
        "SELECT count(*) FROM edge_boots WHERE edge_id = ?1 AND edge_version IS NULL",
        [edge],
        |r| r.get(0),
    )?;
    let current = tx
        .query_row(
            "SELECT 1 FROM edge_boots WHERE edge_id = ?1 AND edge_version IS NOT NULL AND superseded_at IS NULL LIMIT 1",
            [edge],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let mut unregistered = 0;
    for b in boots {
        let known = tx
            .query_row(
                "SELECT 1 FROM edge_boots WHERE edge_id = ?1 AND boot = ?2",
                params![edge, b],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if known {
            continue;
        }
        if unknown >= MAX_UNKNOWN_BOOTS {
            unregistered += 1;
            continue;
        }
        // Release `unknown` until a hello names it (core.md §6).
        tx.execute(
            "INSERT INTO edge_boots(edge_id, boot, edge_version, first_seen, superseded_at) VALUES (?1, ?2, NULL, ?3, ?4)",
            params![edge, b, now, current.then_some(&now)],
        )?;
        unknown += 1;
    }
    tx.commit()?;
    Ok(Some(unregistered))
}

/// A run of clamped records' seqs in `log_clamped`: every `q` record of its boot with a seq in
/// `lo..=hi` whose `ts` is in a later hour than `hour` goes to `hour`.
#[derive(Clone, Debug)]
struct Run {
    lo: i64,
    hi: i64,
    hour: String,
}

fn run_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Run> {
    Ok(Run {
        lo: r.get(0)?,
        hi: r.get(1)?,
        hour: r.get(2)?,
    })
}

/// The run holding `seq`, else the nearest run below it.
fn run_at_or_below(
    c: &rusqlite::Connection,
    edge: &str,
    boot: &str,
    seq: i64,
) -> rusqlite::Result<Option<Run>> {
    c.prepare_cached(
        "SELECT lo, hi, hour FROM log_clamped WHERE edge_id = ?1 AND boot = ?2 AND lo <= ?3 ORDER BY lo DESC LIMIT 1",
    )?
    .query_row(params![edge, boot, seq], run_row)
    .optional()
}

/// The nearest run above `seq`.
fn run_above(c: &rusqlite::Connection, edge: &str, boot: &str, seq: i64) -> rusqlite::Result<Option<Run>> {
    c.prepare_cached(
        "SELECT lo, hi, hour FROM log_clamped WHERE edge_id = ?1 AND boot = ?2 AND lo > ?3 ORDER BY lo LIMIT 1",
    )?
    .query_row(params![edge, boot, seq], run_row)
    .optional()
}

/// The pinned hour of each of the batch's own `(boot, seq)` pairs that a run holds: one index
/// read per distinct seq at most (README §2, Bounded: never more than the batch's records,
/// whatever seqs the edge sends).
fn pinned_hours(
    c: &rusqlite::Connection,
    edge: &str,
    wanted: &BTreeMap<String, BTreeSet<i64>>,
) -> rusqlite::Result<HashMap<(String, i64), String>> {
    let mut out = HashMap::new();
    for (boot, seqs) in wanted {
        let mut run: Option<Run> = None;
        for &seq in seqs {
            if run.as_ref().is_none_or(|r| seq > r.hi) {
                run = run_at_or_below(c, edge, boot, seq)?;
            }
            if let Some(r) = run.as_ref().filter(|r| r.lo <= seq && seq <= r.hi) {
                out.insert((boot.clone(), seq), r.hour.clone());
            }
        }
    }
    Ok(out)
}

/// Pins the records clamped from a later hour that no run holds yet to the hour they go to now
/// (`fresh`: per boot and hour, their seqs), extending or joining a neighbouring run of the same
/// hour, else starting one within the edge's share ([`MAX_CLAMPED_RUNS_PER_EDGE`]). Returns how
/// many couldn't be pinned (over the share).
///
/// Runs stay disjoint, and a run of hour H is only made or grown by a batch core decodes during
/// H (an edge's batches are stored one at a time, [`Ingest::admit`]). So a seq a run comes to
/// cover without its record having been pinned belongs to a record that was never clamped from
/// a later hour, stored at a `ts` no later than H, which the pin then leaves alone (it moves only
/// records whose `ts` is in a later hour): every attempt of a record still lands in one
/// partition (core.md §6).
fn pin_fresh(
    tx: &Transaction<'_>,
    edge: &str,
    fresh: &BTreeMap<(String, String), BTreeSet<i64>>,
    pinned: &mut HashMap<(String, i64), String>,
) -> rusqlite::Result<usize> {
    let mut runs: Option<i64> = None;
    let mut unpinned = 0;
    for ((boot, hour), seqs) in fresh {
        for &seq in seqs {
            let key = (boot.clone(), seq);
            if pinned.contains_key(&key) {
                continue;
            }
            let below = run_at_or_below(tx, edge, boot, seq)?;
            if let Some(r) = below.as_ref().filter(|r| r.hi >= seq) {
                pinned.insert(key, r.hour.clone());
                continue;
            }
            let above = run_above(tx, edge, boot, seq)?;
            let join_below = below.filter(|r| r.hour == *hour);
            let join_above = above.filter(|r| r.hour == *hour);
            match (join_below, join_above) {
                (Some(b), Some(a)) => {
                    tx.execute(
                        "DELETE FROM log_clamped WHERE edge_id = ?1 AND boot = ?2 AND lo = ?3",
                        params![edge, boot, a.lo],
                    )?;
                    tx.execute(
                        "UPDATE log_clamped SET hi = ?4 WHERE edge_id = ?1 AND boot = ?2 AND lo = ?3",
                        params![edge, boot, b.lo, a.hi],
                    )?;
                    if let Some(n) = runs.as_mut() {
                        *n -= 1;
                    }
                }
                (Some(b), None) => {
                    tx.execute(
                        "UPDATE log_clamped SET hi = ?4 WHERE edge_id = ?1 AND boot = ?2 AND lo = ?3",
                        params![edge, boot, b.lo, seq],
                    )?;
                }
                (None, Some(a)) => {
                    tx.execute(
                        "UPDATE log_clamped SET lo = ?4 WHERE edge_id = ?1 AND boot = ?2 AND lo = ?3",
                        params![edge, boot, a.lo, seq],
                    )?;
                }
                (None, None) => {
                    let n = match runs {
                        Some(n) => n,
                        None => tx.query_row(
                            "SELECT count(*) FROM log_clamped WHERE edge_id = ?1",
                            [edge],
                            |r| r.get(0),
                        )?,
                    };
                    if n >= MAX_CLAMPED_RUNS_PER_EDGE {
                        runs = Some(n);
                        unpinned += 1;
                        continue;
                    }
                    tx.execute(
                        "INSERT INTO log_clamped(edge_id, boot, lo, hi, hour) VALUES (?1, ?2, ?3, ?3, ?4)",
                        params![edge, boot, seq, hour],
                    )?;
                    runs = Some(n + 1);
                }
            }
            pinned.insert(key, hour.clone());
        }
    }
    Ok(unpinned)
}

/// A decoded record's `seq` as stored and keyed: decode refuses one above i64::MAX
/// (`decode::check_header_ids`), so it always fits.
#[expect(
    clippy::cast_possible_wrap,
    reason = "decode refuses a seq above i64::MAX (decode::check_header_ids)"
)]
fn seq_i64(seq: u64) -> i64 {
    seq as i64
}

/// Pins every `q` record whose `ts` was clamped from a later hour to its first attempt's hour
/// (`log_clamped` runs, written before the partitions), and moves the records a run holds
/// whose `ts` is in a later hour than the run's back to it, `ts` at the end of that hour: a
/// retry after the hour turns lands in the same partition, where (edge, boot, seq) dedupes it
/// (core.md §6). Only the batch's own seqs are looked up.
async fn pin_clamped_hours(
    state: &AppState,
    edge: &str,
    batch: &mut Batch,
    stale: crate::lookups::ingest::Stale,
) -> Result<(), IngestError> {
    let mut wanted: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    let mut fresh: BTreeMap<(String, String), BTreeSet<i64>> = BTreeMap::new();
    for r in &batch.records {
        if let Record::Query(q) = r {
            let (boot, seq) = (q.q.h.boot.clone(), seq_i64(q.q.h.seq));
            wanted.entry(boot.clone()).or_default().insert(seq);
            if q.from_later_hour {
                let hour = crate::util::ts(&super::partition::hour_start(&q.q.h.ts));
                fresh.entry((boot, hour)).or_default().insert(seq);
            }
        }
    }
    if wanted.is_empty() {
        return Ok(());
    }
    let edge_s = edge.to_string();
    let (pinned, unpinned): (HashMap<(String, i64), String>, usize) = if fresh.is_empty() {
        state
            .db
            .read(move |c| {
                let any = c
                    .query_row(
                        "SELECT 1 FROM log_clamped WHERE edge_id = ?1 LIMIT 1",
                        [&edge_s],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !any {
                    return Ok((HashMap::new(), 0));
                }
                Ok::<_, anyhow::Error>((pinned_hours(c, &edge_s, &wanted)?, 0))
            })
            .await
    } else {
        state
            .db
            .write(move |c| {
                // A restore since the batch began clears `log_clamped`: pin nothing into it.
                if stale() {
                    return Err(RestoreOvertook.into());
                }
                let tx = c.transaction()?;
                let mut pinned = pinned_hours(&tx, &edge_s, &wanted)?;
                let unpinned = pin_fresh(&tx, &edge_s, &fresh, &mut pinned)?;
                tx.commit()?;
                Ok::<_, anyhow::Error>((pinned, unpinned))
            })
            .await
    }
    .map_err(|e| {
        if e.downcast_ref::<RestoreOvertook>().is_some() {
            IngestError::Unavailable(RestoreOvertook.to_string())
        } else {
            unavailable(&e)
        }
    })?;
    if unpinned > 0 {
        tracing::warn!(
            edge,
            unpinned,
            "records clamped from a later hour past the edge's share of log_clamped runs; stored unpinned"
        );
    }
    if pinned.is_empty() {
        return Ok(());
    }
    for r in &mut batch.records {
        if let Record::Query(q) = r
            && let Some(hour) = pinned
                .get(&(q.q.h.boot.clone(), seq_i64(q.q.h.seq)))
                .and_then(|h| crate::util::parse_ts(h))
            && super::partition::hour_start(&q.q.h.ts) > hour
        {
            let last_micro = jiff::SignedDuration::from_hours(1) - jiff::SignedDuration::from_micros(1);
            q.q.h.ts = picket_api::time::saturating_add(hour, last_micro);
        }
    }
    Ok(())
}

fn json_opt<T: serde::Serialize>(v: &Option<T>) -> Option<String> {
    v.as_ref().and_then(|x| serde_json::to_string(x).ok())
}

fn json_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".into())
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// The `events` row of a checked `q` record.
pub fn event_row(edge: &str, q: decode::Query) -> EventRow {
    let decode::Query {
        q,
        response,
        versions_json,
        versions_blake3,
        ..
    } = q;
    let r = q.reason.as_ref();
    EventRow {
        edge_id: edge.to_string(),
        boot: q.h.boot.clone(),
        seq: seq_i64(q.h.seq),
        ts: crate::util::ts(&q.h.ts),
        versions_json,
        versions_blake3,
        listener: q.listener.clone(),
        proto: enum_str(&q.proto),
        client_ip: q.client.clone(),
        device: q.device.clone(),
        profile: q.profile.clone(),
        qname: q.qname.clone(),
        qtype: q.qtype.clone(),
        rcode: q.rcode.clone(),
        decision: enum_str(&q.decision),
        step: r.map(|r| r.step as i64),
        bundle: r.and_then(|r| r.bundle.clone()),
        rule_key: r.and_then(|r| r.key.clone()),
        match_kind: r.map(|r| enum_str(&r.kind)),
        stage: r.map(|r| enum_str(&r.stage)),
        block_id: r.and_then(|r| r.block_id.clone()),
        reason_json: json_opt(&q.reason),
        answers_json: json_str(&q.answers),
        targets_json: json_str(&q.targets),
        truncated: q.truncated,
        response,
        tc: q.tc,
        answer_id: q.answer_id.clone(),
        received_at: q.received_at.map(|t| crate::util::ts(&t)),
        age_s: q.age_s.map(i64::from),
        client_do: q.dnssec_ok,
        cname_json: json_str(&q.cname),
        lookups_json: json_str(&q.lookups),
        cold_unchecked_json: (!q.cold_unchecked.is_empty()).then(|| json_str(&q.cold_unchecked)),
        upstream_json: json_opt(&q.upstream),
        fw_json: json_opt(&q.fw),
        timings_json: json_str(&q.us),
        edns_json: json_opt(&q.edns),
    }
}

/// What storing the non-query records did.
#[derive(Default)]
pub struct Effects {
    pub stored: usize,
    pub failed: usize,
    /// Update outcomes that replaced the edge's update record, oldest first.
    pub updates: Vec<UpdateRecord>,
    /// `(kind, event time ms)` of each new `activation_failed`.
    pub activation_failures: Vec<(String, i64)>,
    pub repairs: usize,
    /// Refusals `tls_version_refused` events say the edge couldn't attribute (`unlogged`).
    pub tls_unlogged: u64,
    /// The revoke list changed (an allow it held ended).
    pub revoke_list_changed: bool,
    /// Allow records stored (a `temp_allow` UI event, api.md §7).
    pub allows: u64,
    /// The alert changes committed with these records.
    pub alerts: Changes,
}

impl Effects {
    fn merge(&mut self, other: Effects) {
        self.stored += other.stored;
        self.failed += other.failed;
        self.updates.extend(other.updates);
        self.activation_failures.extend(other.activation_failures);
        self.repairs += other.repairs;
        self.tls_unlogged += other.tls_unlogged;
        self.revoke_list_changed |= other.revoke_list_changed;
        self.allows += other.allows;
        self.alerts.extend(other.alerts);
    }
}

/// What the alert effects of a batch's non-query records need, gathered before the writer
/// transaction.
pub struct OthersCtx {
    edge: String,
    /// The fingerprint of the key the batch came with, checked in each transaction.
    key: String,
    name: String,
    alerts: Alerts,
    hub: Arc<Hub>,
    /// Where the UI's coalesced notes wait (`web::events`).
    coalesced: Arc<crate::web::events::Coalesced>,
    /// After a completed config activation (core.md §9 `edge_listener_rejected`): per listener,
    /// whether it still asks this edge for its bind, the bind, and whether the edge's
    /// `allowed_binds` admits it.
    listeners: Option<HashMap<String, (bool, String, bool)>>,
}

impl OthersCtx {
    async fn new(state: &AppState, edge: &str, key: &str, records: &[Record]) -> Self {
        let activates_config = records.iter().any(|r| {
            matches!(r, Record::Event(e) if e.kind == event_kind::ACTIVATED
                && !e.fields.contains_key("part")
                && !e.fields.contains_key("bundle")
                && !e.fields.contains_key("verdict_set"))
        });
        let listeners = if activates_config {
            let hello = state.edges.hub.live(edge).hello;
            state.config.model().await.ok().map(|m| {
                m.listeners
                    .values()
                    .map(|l| {
                        let admitted = hello.as_ref().is_some_and(|h| h.bind_allowed(&l.bind));
                        (
                            l.id.clone(),
                            (l.edges.iter().any(|e| e == edge), l.bind.clone(), admitted),
                        )
                    })
                    .collect()
            })
        } else {
            None
        };
        Self {
            edge: edge.to_string(),
            key: key.to_string(),
            name: state.edges.hub.name_of(edge).unwrap_or_else(|| edge.to_string()),
            alerts: state.alerts.clone(),
            hub: state.edges.hub.clone(),
            coalesced: state.events.coalesced().clone(),
            listeners,
        }
    }
}

/// Event kinds core stores (api.md §5); others are ignored.
fn known_event(kind: &str) -> bool {
    matches!(
        kind,
        event_kind::ACTIVATED
            | event_kind::ACTIVATION_FAILED
            | event_kind::UPDATE_OK
            | event_kind::UPDATE_FAILED
            | event_kind::LISTENER_REJECTED
            | event_kind::RULES_REPAIRED
            | event_kind::PANIC
            | event_kind::PAGE_FILE_REFETCHED
            | event_kind::TLS_VERSION_REFUSED
            | event_kind::HELPER_PROTOCOL_MISMATCH
    )
}

/// The `edge_tls_version_refused` alert a `tls_version_refused` event raises (api.md §5; core.md
/// §9 style): one per edge and device, keyed on the device's MAC when the edge knows it (several
/// devices may share a client's name), else its name (from `clients`), else the client address.
/// Its details are the latest event's listener, transport, client, device, MAC, SNI and what the
/// client offered; its count goes up by the handshakes the event stands for (`refused`, at least
/// 1), so it counts refusals, not records. Warning: a device set up for DoT or DoH can't use it,
/// so depending on its fallback it has no DNS at all or quietly uses unencrypted DNS, and only
/// the admin can fix that (update the client, or point it at plain DNS); nothing beyond that
/// device is affected, so not critical. It resolves after
/// [`crate::edges::status::TLS_REFUSED_QUIET`] without a new event (`edges::status::watch_once`).
/// The fields come from the edge: each is checked for type and size (a device name as config
/// checks one: up to 128 characters), the client must be an address and the MAC one in the
/// edge's form (`aa:bb:cc:dd:ee:ff`).
fn tls_version_refused_spec(edge: &str, edge_name: &str, e: &EventRecord) -> RaiseSpec {
    let field = |k: &str, max: usize| {
        decode::event_str(e, k)
            .filter(|s| !s.is_empty() && s.len() <= max)
            .map(str::to_string)
    };
    let client = decode::event_str(e, "client")
        .and_then(|c| c.parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_canonical().to_string());
    let device = decode::event_str(e, "device")
        .filter(|s| crate::config::validate::is_display_name(s))
        .map(str::to_string);
    let mac = decode::event_str(e, "mac")
        .filter(|m| is_mac(m))
        .map(str::to_string);
    let listener = field("listener", 128);
    let who = mac
        .clone()
        .or_else(|| device.clone())
        .or_else(|| client.clone())
        .unwrap_or_else(|| "unknown".into());
    let refused = e
        .fields
        .get("refused")
        .and_then(serde_json::Value::as_u64)
        .map_or(1, |n| u32::try_from(n).unwrap_or(u32::MAX));
    let shown = device.as_deref().unwrap_or(&who);
    RaiseSpec::new(
        "edge_tls_version_refused",
        Severity::Warning,
        format!("edge_tls_version_refused:{edge}:{who}"),
        format!(
            "Edge {edge_name}: {} offers no TLS 1.3, so listener {} refuses it",
            crate::util::sanitize_for_message(shown, 128),
            crate::util::sanitize_for_message(listener.as_deref().unwrap_or("?"), 128)
        ),
        json!({"edge": edge, "device": device, "mac": mac, "client": client, "listener": listener,
               "transport": field("transport", 16), "sni": field("sni", 253),
               "offered": field("offered", 32)}),
    )
    .edge(edge)
    .occurrences(refused)
}

/// A MAC as the edge writes one: six lowercase hex pairs joined by `:`.
fn is_mac(s: &str) -> bool {
    s.len() == 17
        && s.split(':').count() == 6
        && s.split(':').all(|p| {
            p.len() == 2
                && p.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// The refusals a `tls_version_refused` event says the edge couldn't attribute (`unlogged`).
fn tls_unlogged(e: &EventRecord) -> u64 {
    e.fields
        .get("unlogged")
        .and_then(serde_json::Value::as_u64)
        .map_or(0, |n| n.min(u64::from(u32::MAX)))
}

/// What storing one record did.
enum Stored {
    New,
    /// Already stored, or older than what is (nothing changed).
    Old,
    /// Over the edge's share (`temp_allows`): dropped and counted.
    OverShare,
}

/// Stores one non-query record in `tx`, with its alert effects; `allows` is the edge's
/// `temp_allows` row count so far.
fn store_one(
    tx: &Transaction<'_>,
    ctx: &OthersCtx,
    r: &Record,
    fx: &mut Effects,
    allows: &mut i64,
) -> rusqlite::Result<Stored> {
    let edge = ctx.edge.as_str();
    match r {
        Record::Event(e) => {
            if !known_event(&e.kind) {
                return Ok(Stored::Old); // core ignores an unknown kind (api.md §5)
            }
            let result_id = matches!(e.kind.as_str(), event_kind::UPDATE_OK | event_kind::UPDATE_FAILED)
                .then(|| decode::event_str(e, "result_id").map(str::to_string))
                .flatten()
                .filter(|s| !s.is_empty() && s.len() <= 64);
            let detail = serde_json::to_string(&e.fields).unwrap_or_else(|_| "{}".into());
            let n = tx.execute(
                "INSERT OR IGNORE INTO edge_events(edge_id, boot, seq, at, kind, result_id, detail_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    edge,
                    e.h.boot,
                    e.h.seq,
                    crate::util::ts(&e.h.ts),
                    e.kind,
                    result_id,
                    detail
                ],
            )?;
            if n == 0 {
                return Ok(Stored::Old);
            }
            match e.kind.as_str() {
                event_kind::UPDATE_OK | event_kind::UPDATE_FAILED => {
                    if let Some(id) = result_id {
                        let rec = UpdateRecord {
                            result_id: id,
                            outcome: if e.kind == event_kind::UPDATE_OK {
                                "ok"
                            } else {
                                "failed"
                            }
                            .into(),
                            version: decode::event_str(e, "version")
                                .unwrap_or_default()
                                .chars()
                                .take(64)
                                .collect(),
                            at: crate::util::ts(&e.h.ts),
                            stage: decode::event_str(e, "stage").map(|s| s.chars().take(64).collect()),
                        };
                        if let Some(r) = crate::edges::status::reconcile_update(tx, edge, rec)? {
                            crate::edges::status::update_alert_in(&ctx.alerts, tx, edge, &r, &mut fx.alerts)?;
                            fx.updates.push(r);
                        }
                    }
                }
                event_kind::ACTIVATION_FAILED => {
                    let kind = if e.fields.contains_key("bundle") {
                        "bundle"
                    } else if e.fields.contains_key("verdict_set") {
                        "verdict_set"
                    } else {
                        "config"
                    };
                    fx.activation_failures
                        .push((kind.into(), e.h.ts.as_millisecond()));
                    let (target, t) = activation_target_in(tx, edge, e)?;
                    let spec = RaiseSpec::new(
                        "edge_activation_failed",
                        Severity::Warning,
                        format!("edge_activation_failed:{edge}:{target}"),
                        format!(
                            "Edge {}: an activation failed ({})",
                            ctx.name,
                            crate::util::sanitize_for_message(&target, 160)
                        ),
                        json!({"edge": edge, "target": t, "part": e.fields.get("part"), "stage": e.fields.get("stage"),
                               "reason": e.fields.get("reason")}),
                    )
                    .edge(edge);
                    ctx.alerts.raise_in(tx, &spec, &mut fx.alerts)?;
                }
                event_kind::ACTIVATED if !e.fields.contains_key("part") => {
                    // The completion event: every part the target needs is active. A target core
                    // never offered resolves nothing (its failures share the "other" alert).
                    let (target, _) = activation_target_in(tx, edge, e)?;
                    if target != OTHER_TARGET {
                        ctx.alerts.resolve_in(
                            tx,
                            &format!("edge_activation_failed:{edge}:{target}"),
                            Some(&json!({"by": "activated"})),
                            &mut fx.alerts,
                        )?;
                    }
                    if target.starts_with("config:")
                        && let Some(listeners) = &ctx.listeners
                    {
                        resolve_listener_rejections_in(tx, ctx, listeners, &mut fx.alerts)?;
                    }
                }
                event_kind::RULES_REPAIRED => fx.repairs += 1,
                event_kind::LISTENER_REJECTED => {
                    let listener = decode::event_str(e, "listener").unwrap_or_default().to_string();
                    let bind = decode::event_str(e, "bind").map(str::to_string);
                    let spec = RaiseSpec::new(
                        "edge_listener_rejected",
                        Severity::Warning,
                        format!("edge_listener_rejected:{edge}:{listener}"),
                        format!(
                            "Edge {}: listener {} isn't in the edge's allowed_binds",
                            ctx.name,
                            crate::util::sanitize_for_message(&listener, 128)
                        ),
                        json!({"edge": edge, "listener": listener, "bind": bind}),
                    )
                    .edge(edge);
                    ctx.alerts.raise_in(tx, &spec, &mut fx.alerts)?;
                }
                event_kind::PANIC => {
                    let spec = RaiseSpec::new(
                        "edge_panic",
                        Severity::Warning,
                        format!("edge_panic:{edge}"),
                        format!("Edge {}: a task panicked", ctx.name),
                        json!({"edge": edge, "event": e.fields}),
                    )
                    .edge(edge);
                    ctx.alerts.raise_in(tx, &spec, &mut fx.alerts)?;
                }
                event_kind::PAGE_FILE_REFETCHED => {
                    let what = decode::event_str(e, "bundle")
                        .or_else(|| decode::event_str(e, "provider"))
                        .unwrap_or_default()
                        .to_string();
                    let spec = RaiseSpec::new(
                        "edge_page_file_refetched",
                        Severity::Warning,
                        format!("edge_page_file_refetched:{edge}:{what}"),
                        format!(
                            "Edge {}: a page file of {} failed its checks and was refetched",
                            ctx.name,
                            crate::util::sanitize_for_message(&what, 128)
                        ),
                        json!({"edge": edge, "event": e.fields}),
                    )
                    .edge(edge);
                    ctx.alerts.raise_in(tx, &spec, &mut fx.alerts)?;
                }
                event_kind::TLS_VERSION_REFUSED => {
                    fx.tls_unlogged += tls_unlogged(e);
                    ctx.alerts
                        .raise_in(tx, &tls_version_refused_spec(edge, &ctx.name, e), &mut fx.alerts)?;
                }
                _ => {}
            }
            Ok(Stored::New)
        }
        Record::Condition(c) => {
            let detail = json!({"kind": c.kind, "key": c.key, "change": c.change, "time": crate::util::ts(&c.time), "detail": c.detail});
            let n = tx.execute(
                "INSERT OR IGNORE INTO edge_events(edge_id, boot, seq, at, kind, detail_json) VALUES (?1, ?2, ?3, ?4, 'condition', ?5)",
                params![edge, c.h.boot, c.h.seq, crate::util::ts(&c.time), detail.to_string()],
            )?;
            if n == 0 {
                return Ok(Stored::Old);
            }
            // The change goes into the alert's history; alerts are raised and resolved only
            // from the snapshots (core.md §9).
            if let Some((alert, _)) = crate::edges::status::condition_alert(&c.kind) {
                let dk = crate::edges::status::condition_key(alert, edge, c.key.as_deref());
                let change = match c.change {
                    ConditionChange::Appeared => "condition_appeared",
                    ConditionChange::Cleared => "condition_cleared",
                };
                ctx.alerts
                    .note_in(tx, &dk, change, &json!({"time": crate::util::ts(&c.time)}))?;
            }
            Ok(Stored::New)
        }
        Record::Allow(a) => {
            let ts = crate::util::ts(&a.h.ts);
            let updated: Option<Option<String>> = tx
                .query_row(
                    "SELECT updated_at FROM temp_allows WHERE edge_id = ?1 AND allow_id = ?2",
                    params![edge, a.allow_id],
                    |r| r.get(0),
                )
                .optional()?;
            // Delivery is at-least-once: a record older than the one applied changes nothing.
            if let Some(Some(u)) = &updated
                && u.as_str() > ts.as_str()
            {
                return Ok(Stored::Old);
            }
            if updated.is_none() {
                // A new allow id: within the edge's share of the table (README §2, Bounded).
                if *allows >= MAX_TEMP_ALLOWS_PER_EDGE {
                    return Ok(Stored::OverShare);
                }
                *allows += 1;
            }
            let kind = enum_str(&a.kind);
            let expires = a.expires_at.map(|t| crate::util::ts(&t));
            match a.action {
                AllowAction::Created | AllowAction::Changed => {
                    tx.execute(
                        "INSERT INTO temp_allows(edge_id, allow_id, client, device, kind, target, created_at, expires_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?7)
                         ON CONFLICT(edge_id, allow_id) DO UPDATE SET client = excluded.client, device = excluded.device,
                            kind = excluded.kind, target = excluded.target, expires_at = excluded.expires_at,
                            created_at = coalesce(temp_allows.created_at, excluded.created_at),
                            updated_at = excluded.updated_at",
                        params![edge, a.allow_id, a.client, a.device, kind, a.target, ts, expires],
                    )?;
                }
                AllowAction::Revoked | AllowAction::Expired => {
                    tx.execute(
                        "INSERT INTO temp_allows(edge_id, allow_id, client, device, kind, target, expires_at, ended_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                         ON CONFLICT(edge_id, allow_id) DO UPDATE SET ended_at = coalesce(temp_allows.ended_at, excluded.ended_at),
                            updated_at = excluded.updated_at",
                        params![edge, a.allow_id, a.client, a.device, kind, a.target, expires, ts],
                    )?;
                    // The edge's log shows the allow ended: it leaves the revoke list (api.md §4).
                    if crate::edges::requests::refresh_revoke_list(tx, edge)? {
                        fx.revoke_list_changed = true;
                    }
                }
            }
            fx.allows += 1;
            Ok(Stored::New)
        }
        _ => Ok(Stored::Old),
    }
}

/// The edge's `temp_allows` row count.
fn allow_rows(tx: &Transaction<'_>, edge: &str) -> rusqlite::Result<i64> {
    tx.query_row(
        "SELECT count(*) FROM temp_allows WHERE edge_id = ?1",
        [edge],
        |r| r.get(0),
    )
}

/// Effects of a whole batch's records, after them in the same transaction: `edge_fw_repairs`
/// (more than 10 `rules_repaired` in the last hour).
fn batch_effects_in(tx: &Transaction<'_>, ctx: &OthersCtx, fx: &mut Effects) -> rusqlite::Result<()> {
    if fx.repairs == 0 {
        return Ok(());
    }
    let now = Timestamp::now();
    let hour_ago = crate::util::ts(&(now - jiff::SignedDuration::from_hours(1)));
    let n: i64 = tx.query_row(
        "SELECT count(*) FROM edge_events WHERE edge_id = ?1 AND kind = 'rules_repaired' AND at >= ?2",
        params![ctx.edge, hour_ago],
        |r| r.get(0),
    )?;
    let spec = crate::edges::status::fw_repairs_spec(&ctx.edge, &ctx.name, n);
    let since = (n > crate::edges::status::FW_REPAIRS_PER_HOUR).then_some(now);
    ctx.alerts
        .condition_in(tx, &spec, since, Duration::ZERO, now, &mut fx.alerts)?;
    Ok(())
}

/// Stores the non-query records of a batch in one transaction with their alert effects; a
/// failure that isn't the system's is retried record by record (core.md §6), each record with
/// its own effects. Runs on the writer: the alert cache and the edge's live update record follow
/// each commit.
fn store_others(
    c: &mut rusqlite::Connection,
    ctx: &OthersCtx,
    records: Vec<Record>,
) -> anyhow::Result<Option<Effects>> {
    let whole = (|| -> rusqlite::Result<Option<Effects>> {
        let tx = c.transaction()?;
        if !crate::edges::status::key_holds(&tx, &ctx.edge, &ctx.key)? {
            return Ok(None);
        }
        let mut fx = Effects::default();
        let mut allows = allow_rows(&tx, &ctx.edge)?;
        for r in &records {
            match store_one(&tx, ctx, r, &mut fx, &mut allows)? {
                Stored::New => fx.stored += 1,
                Stored::OverShare => fx.failed += 1,
                Stored::Old => {}
            }
        }
        batch_effects_in(&tx, ctx, &mut fx)?;
        tx.commit()?;
        Ok(Some(fx))
    })();
    let fx = match whole {
        Ok(None) => return Ok(None),
        Ok(Some(fx)) => {
            committed(ctx, &fx);
            fx
        }
        Err(e) if super::writer::is_system_error(&e) => return Err(e.into()),
        Err(_) => {
            let mut fx = Effects::default();
            for r in &records {
                let one = (|| -> rusqlite::Result<Option<Effects>> {
                    let tx = c.transaction()?;
                    if !crate::edges::status::key_holds(&tx, &ctx.edge, &ctx.key)? {
                        return Ok(None);
                    }
                    let mut f = Effects::default();
                    let mut allows = allow_rows(&tx, &ctx.edge)?;
                    match store_one(&tx, ctx, r, &mut f, &mut allows)? {
                        Stored::New => f.stored += 1,
                        Stored::OverShare => f.failed += 1,
                        Stored::Old => {}
                    }
                    batch_effects_in(&tx, ctx, &mut f)?;
                    tx.commit()?;
                    Ok(Some(f))
                })();
                match one {
                    Ok(None) => return Ok(None),
                    Ok(Some(f)) => {
                        committed(ctx, &f);
                        fx.merge(f);
                    }
                    Err(e) if super::writer::is_system_error(&e) => return Err(e.into()),
                    Err(_) => fx.failed += 1,
                }
            }
            fx
        }
    };
    Ok(Some(fx))
}

/// Right after a commit, on the writer: the alert cache, the edge's live update record (core.md
/// §4–§5: the status the UI reads follows the stored record), and the `temp_allow` UI note for
/// the allow records stored (`web::events` module docs: notes follow commit order).
fn committed(ctx: &OthersCtx, fx: &Effects) {
    ctx.alerts.committed(&fx.alerts);
    if fx.allows > 0 {
        ctx.coalesced
            .temp_allow(&ctx.edge, crate::web::events::AllowChange::Ingested(fx.allows));
    }
    if let Some(u) = fx.updates.last().cloned() {
        ctx.hub.update_live(&ctx.edge, move |l| l.update = Some(u));
    }
}

/// The key suffix of activation failures for targets core never offered (README §2, Bounded:
/// targets come from the edge, so unknown ones share one alert per edge).
pub const OTHER_TARGET: &str = "other";

/// The target an `activated`/`activation_failed` event names, as its alert keys it, checked
/// against what core offered (README §2 Untrusted input): a config core published for this edge,
/// or a bundle head or verdict-set head core built, by its full id or its 16-character short
/// form, keyed by the full id. Anything else is [`OTHER_TARGET`], with the claimed target in the
/// details.
pub fn activation_target_in(
    tx: &Transaction<'_>,
    edge: &str,
    e: &EventRecord,
) -> rusqlite::Result<(String, serde_json::Value)> {
    let s = |k: &str| decode::event_str(e, k).unwrap_or_default().to_string();
    let id_like = |v: &str| (16..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_hexdigit());
    let full = |sql: &str, a: &str, b: &str| -> rusqlite::Result<Option<String>> {
        if !id_like(b) {
            return Ok(None);
        }
        tx.query_row(sql, params![a, b.to_ascii_lowercase()], |r| r.get(0))
            .optional()
    };
    let found = if let Some(b) = decode::event_str(e, "bundle") {
        full(
            "SELECT head_id FROM bundle_versions WHERE bundle_id = ?1 AND substr(head_id, 1, length(?2)) = ?2 LIMIT 1",
            b,
            &s("head"),
        )?
        .map(|head| (format!("bundle:{b}:{head}"), json!({"bundle": b, "head": head})))
    } else if let Some(p) = decode::event_str(e, "verdict_set") {
        full(
            "SELECT head_id FROM verdict_sets WHERE provider_id = ?1 AND substr(head_id, 1, length(?2)) = ?2 LIMIT 1",
            p,
            &s("head"),
        )?
        .map(|head| (format!("verdict_set:{p}:{head}"), json!({"verdict_set": p, "head": head})))
    } else {
        full(
            "SELECT config_id FROM edge_configs WHERE edge_id = ?1 AND substr(config_id, 1, length(?2)) = ?2 LIMIT 1",
            edge,
            &s("config"),
        )?
        .map(|cfg| (format!("config:{cfg}"), json!({"config": cfg})))
    };
    Ok(found.unwrap_or_else(|| {
        let claimed: serde_json::Map<String, serde_json::Value> = ["bundle", "verdict_set", "head", "config"]
            .iter()
            .filter_map(|k| {
                decode::event_str(e, k)
                    .map(|v| ((*k).to_string(), json!(crate::util::sanitize_for_message(v, 128))))
            })
            .collect();
        (
            OTHER_TARGET.to_string(),
            json!({"other": true, "claimed": claimed}),
        )
    }))
}

/// Resolves, in `tx`, the edge's `edge_listener_rejected` alerts whose listener no longer asks
/// it for that bind, or whose bind its `allowed_binds` now admits, after a completed config
/// activation (core.md §9).
fn resolve_listener_rejections_in(
    tx: &Transaction<'_>,
    ctx: &OthersCtx,
    listeners: &HashMap<String, (bool, String, bool)>,
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    let open: Vec<(String, String)> = {
        let mut st = tx.prepare_cached(
            "SELECT dedupe_key, details_json FROM alerts
             WHERE kind = 'edge_listener_rejected' AND edge_id = ?1 AND state = 'open'",
        )?;
        st.query_map([&ctx.edge], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (key, details) in open {
        let d: serde_json::Value = serde_json::from_str(&details).unwrap_or_default();
        let listener = d["listener"].as_str().unwrap_or_default();
        let bind = d["bind"].as_str();
        let (asks, admitted) = match listeners.get(listener) {
            Some((assigned, l_bind, admitted)) => (*assigned && bind.is_none_or(|b| b == l_bind), *admitted),
            None => (false, false),
        };
        if !asks || admitted {
            ctx.alerts.resolve_in(
                tx,
                &key,
                Some(&json!({"by": if asks { "activation" } else { "listener changed" }})),
                ch,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> rusqlite::Connection {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE log_clamped (edge_id TEXT NOT NULL, boot TEXT NOT NULL, lo INTEGER NOT NULL,
               hi INTEGER NOT NULL, hour TEXT NOT NULL, PRIMARY KEY (edge_id, boot, lo)) STRICT, WITHOUT ROWID;",
        )
        .unwrap();
        c
    }

    fn runs(c: &rusqlite::Connection) -> Vec<(String, i64, i64, String)> {
        let mut st = c
            .prepare("SELECT boot, lo, hi, hour FROM log_clamped ORDER BY boot, lo")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    /// Pins `seqs` of boot `b` at `hour` as one batch would; returns (pinned, unpinned).
    fn pin(
        c: &mut rusqlite::Connection,
        hour: &str,
        seqs: &[i64],
    ) -> (HashMap<(String, i64), String>, usize) {
        let wanted = BTreeMap::from([("b".to_string(), seqs.iter().copied().collect::<BTreeSet<i64>>())]);
        let fresh = BTreeMap::from([(("b".to_string(), hour.to_string()), wanted["b"].clone())]);
        let tx = c.transaction().unwrap();
        let mut pinned = pinned_hours(&tx, "e", &wanted).unwrap();
        let n = pin_fresh(&tx, "e", &fresh, &mut pinned).unwrap();
        tx.commit().unwrap();
        (pinned, n)
    }

    #[test]
    fn clamped_records_are_kept_as_disjoint_runs() {
        // core.md §6, README §2 Bounded (review round 2, CC3).
        let mut c = db();
        // In seq order, with gaps: one run.
        pin(&mut c, "H1", &[10, 13, 16]);
        pin(&mut c, "H1", &[19, 22]);
        assert_eq!(runs(&c), vec![("b".into(), 10, 22, "H1".into())]);
        // Out of order: the run grows downwards.
        pin(&mut c, "H1", &[4, 7]);
        assert_eq!(runs(&c), vec![("b".into(), 4, 22, "H1".into())]);
        // A later hour starts its own run; one already held keeps its hour.
        let (p, _) = pin(&mut c, "H2", &[16, 30, 33]);
        assert_eq!(p[&("b".to_string(), 16)], "H1");
        assert_eq!(p[&("b".to_string(), 30)], "H2");
        assert_eq!(
            runs(&c),
            vec![
                ("b".into(), 4, 22, "H1".into()),
                ("b".into(), 30, 33, "H2".into())
            ]
        );
        // Between runs of other hours: a new run, never overlapping them.
        pin(&mut c, "H3", &[25]);
        pin(&mut c, "H3", &[40]);
        pin(&mut c, "H3", &[28, 36]);
        assert_eq!(
            runs(&c),
            vec![
                ("b".into(), 4, 22, "H1".into()),
                ("b".into(), 25, 28, "H3".into()),
                ("b".into(), 30, 33, "H2".into()),
                ("b".into(), 36, 40, "H3".into()),
            ]
        );
        // Two runs of the same hour join over the seqs between them.
        c.execute(
            "INSERT INTO log_clamped(edge_id, boot, lo, hi, hour) VALUES ('e', 'b', 60, 62, 'H4'), ('e', 'b', 70, 72, 'H4')",
            [],
        )
        .unwrap();
        pin(&mut c, "H4", &[66]);
        assert_eq!(runs(&c)[4..], [("b".into(), 60, 72, "H4".into())]);
        // Only the batch's own seqs are looked up, whatever their range.
        let wanted = BTreeMap::from([("b".to_string(), BTreeSet::from([0, 5, 26, 29, i64::MAX]))]);
        let got = pinned_hours(&c, "e", &wanted).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[&("b".to_string(), 5)], "H1");
        assert_eq!(got[&("b".to_string(), 26)], "H3");
    }

    #[test]
    fn an_edges_runs_stay_within_its_share() {
        let mut c = db();
        {
            let tx = c.transaction().unwrap();
            for i in 0..MAX_CLAMPED_RUNS_PER_EDGE {
                tx.execute(
                    "INSERT INTO log_clamped(edge_id, boot, lo, hi, hour) VALUES ('e', 'other', ?1, ?1, 'H0')",
                    [i * 10],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        // A new run doesn't fit: unpinned. Growing an existing run of the hour needs no room.
        let (p, n) = pin(&mut c, "H1", &[7]);
        assert_eq!((p.len(), n), (0, 1));
        c.execute(
            "UPDATE log_clamped SET boot = 'b', hour = 'H1' WHERE edge_id = 'e' AND lo = 0",
            [],
        )
        .unwrap();
        let (p, n) = pin(&mut c, "H1", &[3, 5]);
        assert_eq!((p.len(), n), (2, 0));
        let count: i64 = c
            .query_row("SELECT count(*) FROM log_clamped WHERE edge_id = 'e'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, MAX_CLAMPED_RUNS_PER_EDGE);
    }
}
