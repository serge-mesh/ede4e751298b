//! The partition writer: one thread owns every write to the hourly log partitions
//! (`logs/YYYY-MM-DDTHH.db`, storage.md §2–§3), so batches from several edges never contend for
//! a partition's lock, and retention deletes a partition only through the same thread, after
//! closing it.
//!
//! - **Durability:** partitions run `synchronous=FULL`, so a store returns only once the batch is
//!   durable; the ack follows (core.md §6).
//! - **Dedupe:** `events` is keyed on (edge, boot, seq) (`INSERT OR IGNORE`); `answers` on `id`,
//!   stored in the partition of each record that references it ([`StoreJob`]).
//! - **Failures:** a batch that fails to store is retried record by record; a record that still
//!   fails is dropped and counted. A failure that isn't the record's (disk full, I/O, a locked or
//!   unreadable file) is returned as [`StoreError::System`], and the edge retries the batch.
//! - Bounded: a few partitions are kept open (an LRU), and the job queue is bounded.

use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use jiff::Timestamp;
use rusqlite::{ErrorCode, ToSql};
use tokio::sync::{mpsc, oneshot};

use super::partition::{LogStore, Partition};

/// Partitions kept open at once.
const OPEN_PARTITIONS: usize = 4;
/// Jobs queued for the writer; senders wait when it is full.
const QUEUE: usize = 64;
/// Version-set ids cached per partition.
const VERSION_SET_CACHE: usize = 10_000;

/// One `q` record ready for its partition's `events` row.
#[derive(Clone, Debug, PartialEq)]
pub struct EventRow {
    pub edge_id: String,
    pub boot: String,
    pub seq: i64,
    pub ts: String,
    pub versions_json: String,
    pub versions_blake3: String,
    pub listener: String,
    pub proto: String,
    pub client_ip: String,
    pub device: Option<String>,
    pub profile: Option<String>,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub decision: String,
    pub step: Option<i64>,
    pub bundle: Option<String>,
    pub rule_key: Option<String>,
    pub match_kind: Option<String>,
    pub stage: Option<String>,
    pub block_id: Option<String>,
    pub reason_json: Option<String>,
    pub answers_json: String,
    pub targets_json: String,
    pub truncated: bool,
    pub response: Option<Vec<u8>>,
    pub tc: bool,
    pub answer_id: Option<String>,
    pub received_at: Option<String>,
    pub age_s: Option<i64>,
    pub client_do: bool,
    pub cname_json: String,
    pub lookups_json: String,
    pub cold_unchecked_json: Option<String>,
    pub upstream_json: Option<String>,
    pub fw_json: Option<String>,
    pub timings_json: String,
    pub edns_json: Option<String>,
}

/// One partition's share of a batch.
pub struct StoreJob {
    pub hour: Timestamp,
    pub rows: Vec<EventRow>,
    /// The batch's answers by id (decoded wire), shared by every partition of the batch.
    pub answers: Arc<HashMap<String, Vec<u8>>>,
}

/// What storing one partition's share did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreOutcome {
    /// Rows written now, by index into the job's rows.
    pub stored: Vec<usize>,
    /// Rows already there (a repeated batch).
    pub duplicates: usize,
    /// Rows that failed for a reason of their own.
    pub failed: usize,
    /// Stored rows whose answer neither the batch nor the partition holds.
    pub answer_missing: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Not the records' fault (disk full, I/O, …): the batch is retried by the edge.
    #[error("log storage unavailable: {0}")]
    System(String),
    /// The job's refusal flag was set when the writer came to it ([`LogWriter::write_unless`]):
    /// nothing was stored; the edge retries the batch.
    #[error("a config restore is emptying the logs; retry later")]
    Refused,
}

/// Work on one existing partition, run on the writer thread ([`LogWriter::with_partition`]):
/// `None` when the partition doesn't exist (retention deleted it, or nothing was stored there).
type PartitionFn = Box<dyn FnOnce(Option<&mut Partition>) + Send>;

/// A flag that, set when the writer comes to a store job, refuses it ([`LogWriter::write_unless`]).
type Refusal = Option<Arc<std::sync::atomic::AtomicBool>>;

enum Job {
    Store(
        StoreJob,
        Refusal,
        oneshot::Sender<Result<StoreOutcome, StoreError>>,
    ),
    Delete(Timestamp, oneshot::Sender<anyhow::Result<()>>),
    Exec(Timestamp, PartitionFn),
}

/// The handle to the writer thread.
#[derive(Clone)]
pub struct LogWriter {
    tx: mpsc::Sender<Job>,
    store: LogStore,
}

/// True when an SQLite error is the system's, not the record's.
pub fn is_system_error(e: &rusqlite::Error) -> bool {
    match e {
        rusqlite::Error::SqliteFailure(f, _) => matches!(
            f.code,
            ErrorCode::DiskFull
                | ErrorCode::SystemIoFailure
                | ErrorCode::CannotOpen
                | ErrorCode::DatabaseBusy
                | ErrorCode::DatabaseLocked
                | ErrorCode::ReadOnly
                | ErrorCode::OutOfMemory
                | ErrorCode::NotADatabase
                | ErrorCode::DatabaseCorrupt
                | ErrorCode::FileLockingProtocolFailed
                | ErrorCode::PermissionDenied
        ),
        rusqlite::Error::SqliteSingleThreadedMode | rusqlite::Error::InvalidPath(_) => true,
        _ => false,
    }
}

struct Open {
    hour: Timestamp,
    part: Partition,
    version_sets: HashMap<String, i64>,
}

impl LogWriter {
    /// Starts the writer thread for the partitions under `store`.
    pub fn start(store: LogStore) -> anyhow::Result<Self> {
        let (tx, mut rx) = mpsc::channel::<Job>(QUEUE);
        let s2 = store.clone();
        std::thread::Builder::new()
            .name("log-writer".into())
            .spawn(move || {
                let mut open: VecDeque<Open> = VecDeque::new();
                while let Some(job) = rx.blocking_recv() {
                    match job {
                        Job::Store(_, Some(refuse), reply)
                            if refuse.load(std::sync::atomic::Ordering::SeqCst) =>
                        {
                            let _ = reply.send(Err(StoreError::Refused));
                        }
                        Job::Store(j, _, reply) => {
                            let r =
                                std::panic::catch_unwind(AssertUnwindSafe(|| store_job(&s2, &mut open, j)))
                                    .unwrap_or_else(|_| {
                                        Err(StoreError::System("the log writer panicked".into()))
                                    });
                            let _ = reply.send(r);
                        }
                        Job::Delete(hour, reply) => {
                            open.retain(|o| o.hour != hour);
                            let _ = reply.send(s2.delete(&hour));
                        }
                        Job::Exec(hour, f) => {
                            // A panic in `f` drops its reply sender: the caller sees an error.
                            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                match open_existing(&s2, &mut open, hour) {
                                    Some(o) => f(Some(&mut o.part)),
                                    None => f(None),
                                }
                            }));
                        }
                    }
                }
            })?;
        Ok(Self { tx, store })
    }

    pub fn store(&self) -> &LogStore {
        &self.store
    }

    /// Stores one partition's share of a batch; returns once it is durable.
    pub async fn write(&self, job: StoreJob) -> Result<StoreOutcome, StoreError> {
        self.send_store(job, None).await
    }

    /// [`LogWriter::write`], unless `refuse` is set when the writer thread comes to the job:
    /// then nothing is stored ([`StoreError::Refused`]). The flag is read on the thread that also
    /// runs [`LogWriter::delete`], so the check is ordered with partition deletions: a config
    /// restore's flag (core.md §2), set before it empties the partitions and cleared after,
    /// keeps every write that reaches the writer in between out of the partitions it empties.
    pub async fn write_unless(
        &self,
        job: StoreJob,
        refuse: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<StoreOutcome, StoreError> {
        self.send_store(job, Some(refuse)).await
    }

    async fn send_store(&self, job: StoreJob, refuse: Refusal) -> Result<StoreOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Store(job, refuse, tx))
            .await
            .map_err(|_| StoreError::System("the log writer stopped".into()))?;
        rx.await
            .map_err(|_| StoreError::System("the log writer stopped".into()))?
    }

    /// Runs `f` on the writer thread with the partition of `hour`, if it exists (`Ok(None)`
    /// otherwise; never creates one): the analysis writes its results and markers through the
    /// same thread that stores batches, so they never contend for a partition's lock (core.md §6:
    /// analysis never delays ingest beyond its turn on the writer). `f` should be short: one
    /// transaction of one batch's results.
    pub async fn with_partition<T, F>(&self, hour: Timestamp, f: F) -> anyhow::Result<Option<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut Partition) -> anyhow::Result<T> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel::<anyhow::Result<Option<T>>>();
        let job: PartitionFn = Box::new(move |p| {
            let r = match p {
                Some(p) => f(p).map(Some),
                None => Ok(None),
            };
            let _ = tx.send(r);
        });
        self.tx
            .send(Job::Exec(hour, job))
            .await
            .map_err(|_| anyhow::anyhow!("the log writer stopped"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("the log writer failed the job"))?
    }

    /// Deletes a whole partition (retention), closing it first.
    pub async fn delete(&self, hour: Timestamp) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Delete(hour, tx))
            .await
            .map_err(|_| anyhow::anyhow!("the log writer stopped"))?;
        rx.await.map_err(|_| anyhow::anyhow!("the log writer stopped"))?
    }
}

fn open_partition<'a>(
    store: &LogStore,
    open: &'a mut VecDeque<Open>,
    hour: Timestamp,
) -> Result<&'a mut Open, StoreError> {
    if let Some(o) = take_open(open, hour) {
        return Ok(open.push_front_mut(o));
    }
    let part = store
        .open(&hour, true)
        .map_err(|e| StoreError::System(format!("{e:#}")))?
        .ok_or_else(|| StoreError::System("partition missing".into()))?;
    Ok(push_open(open, hour, part))
}

/// Takes `hour`'s partition out of the open ones, if it is open.
fn take_open(open: &mut VecDeque<Open>, hour: Timestamp) -> Option<Open> {
    let i = open.iter().position(|o| o.hour == hour)?;
    open.remove(i)
}

/// Makes `part` the most recently used open partition, closing the least recently used one
/// beyond [`OPEN_PARTITIONS`].
fn push_open(open: &mut VecDeque<Open>, hour: Timestamp, part: Partition) -> &mut Open {
    open.truncate(OPEN_PARTITIONS.saturating_sub(1));
    open.push_front_mut(Open {
        hour,
        part,
        version_sets: HashMap::new(),
    })
}

/// The open partition of `hour`, opening it if its file exists; `None` when there is none.
fn open_existing<'a>(
    store: &LogStore,
    open: &'a mut VecDeque<Open>,
    hour: Timestamp,
) -> Option<&'a mut Open> {
    if let Some(o) = take_open(open, hour) {
        return Some(open.push_front_mut(o));
    }
    let part = match store.open(&hour, false) {
        Ok(Some(p)) => p,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!(hour = %hour, error = %format!("{e:#}"), "cannot open a log partition");
            return None;
        }
    };
    Some(push_open(open, hour, part))
}

fn sys(e: rusqlite::Error) -> StoreError {
    StoreError::System(e.to_string())
}

/// Inserts one row; `Ok(Some(answer_missing))` when it was new, `Ok(None)` for a duplicate.
fn insert_row(
    o: &mut Open,
    row: &EventRow,
    answers: &HashMap<String, Vec<u8>>,
) -> rusqlite::Result<Option<bool>> {
    let p = &o.part;
    let exists = p
        .conn
        .prepare_cached("SELECT 1 FROM events WHERE edge_id = ?1 AND boot = ?2 AND seq = ?3")?
        .exists(rusqlite::params![row.edge_id, row.boot, row.seq])?;
    if exists {
        return Ok(None);
    }
    let vs_id = match o.version_sets.get(&row.versions_blake3) {
        Some(id) => *id,
        None => {
            p.insert(
                "version_sets",
                &[
                    ("blake3", &row.versions_blake3),
                    ("versions_json", &row.versions_json),
                ],
                true,
            )?;
            let id: i64 = p.conn.query_row(
                "SELECT id FROM version_sets WHERE blake3 = ?1",
                [&row.versions_blake3],
                |r| r.get(0),
            )?;
            if o.version_sets.len() >= VERSION_SET_CACHE {
                o.version_sets.clear();
            }
            o.version_sets.insert(row.versions_blake3.clone(), id);
            id
        }
    };
    let p = &o.part;
    // The answer goes into this record's partition, whatever its own time (core.md §6).
    let mut answer_missing = false;
    if let Some(aid) = &row.answer_id {
        match answers.get(aid) {
            Some(wire) => {
                p.insert("answers", &[("id", aid), ("wire", wire)], true)?;
            }
            None => {
                answer_missing = !p
                    .conn
                    .prepare_cached("SELECT 1 FROM answers WHERE id = ?1")?
                    .exists([aid])?;
            }
        }
    }
    let truncated = row.truncated as i64;
    let tc = row.tc as i64;
    let do_ = row.client_do as i64;
    let missing = answer_missing as i64;
    let values: Vec<(&str, &dyn ToSql)> = vec![
        ("edge_id", &row.edge_id),
        ("boot", &row.boot),
        ("seq", &row.seq),
        ("ts", &row.ts),
        ("version_set", &vs_id),
        ("listener", &row.listener),
        ("proto", &row.proto),
        ("client_ip", &row.client_ip),
        ("device", &row.device),
        ("profile", &row.profile),
        ("qname", &row.qname),
        ("qtype", &row.qtype),
        ("rcode", &row.rcode),
        ("decision", &row.decision),
        ("step", &row.step),
        ("bundle", &row.bundle),
        ("rule_key", &row.rule_key),
        ("match_kind", &row.match_kind),
        ("stage", &row.stage),
        ("block_id", &row.block_id),
        ("reason_json", &row.reason_json),
        ("answers_json", &row.answers_json),
        ("targets_json", &row.targets_json),
        ("truncated", &truncated),
        ("response", &row.response),
        ("tc", &tc),
        ("answer_id", &row.answer_id),
        ("received_at", &row.received_at),
        ("age_s", &row.age_s),
        ("answer_missing", &missing),
        ("client_do", &do_),
        ("cname_json", &row.cname_json),
        ("lookups_json", &row.lookups_json),
        ("cold_unchecked_json", &row.cold_unchecked_json),
        ("upstream_json", &row.upstream_json),
        ("fw_json", &row.fw_json),
        ("timings_json", &row.timings_json),
        ("edns_json", &row.edns_json),
    ];
    p.insert("events", &values, false)?;
    Ok(Some(answer_missing))
}

/// Runs `f` in one transaction on the partition (explicit `BEGIN`/`COMMIT`, so `f` may borrow
/// the partition mutably), rolling back on error.
fn in_tx<T>(o: &mut Open, f: impl FnOnce(&mut Open) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
    o.part.conn.execute_batch("BEGIN IMMEDIATE")?;
    match f(o) {
        Ok(v) => match o.part.conn.execute_batch("COMMIT") {
            Ok(()) => Ok(v),
            Err(e) => {
                let _ = o.part.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        },
        Err(e) => {
            let _ = o.part.conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn store_job(store: &LogStore, open: &mut VecDeque<Open>, job: StoreJob) -> Result<StoreOutcome, StoreError> {
    let o = open_partition(store, open, job.hour)?;
    // First the whole share in one transaction.
    let whole = in_tx(o, |o| {
        let mut out = StoreOutcome::default();
        for (i, row) in job.rows.iter().enumerate() {
            match insert_row(o, row, &job.answers)? {
                Some(missing) => {
                    out.stored.push(i);
                    out.answer_missing += missing as usize;
                }
                None => out.duplicates += 1,
            }
        }
        Ok(out)
    });
    match whole {
        Ok(out) => Ok(out),
        Err(e) if is_system_error(&e) => {
            // A cached handle may be broken; reopen next time.
            open.retain(|x| x.hour != job.hour);
            Err(sys(e))
        }
        Err(_) => {
            // core.md §6: retried record by record; one that still fails is dropped and counted.
            o.version_sets.clear();
            let mut out = StoreOutcome::default();
            for (i, row) in job.rows.iter().enumerate() {
                match in_tx(o, |o| insert_row(o, row, &job.answers)) {
                    Ok(Some(missing)) => {
                        out.stored.push(i);
                        out.answer_missing += missing as usize;
                    }
                    Ok(None) => out.duplicates += 1,
                    Err(e) if is_system_error(&e) => {
                        open.retain(|x| x.hour != job.hour);
                        return Err(sys(e));
                    }
                    Err(e) => {
                        o.version_sets.clear();
                        tracing::debug!(error = %e, "a log record failed to store; dropped");
                        out.failed += 1;
                    }
                }
            }
            Ok(out)
        }
    }
}
