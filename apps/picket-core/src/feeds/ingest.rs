//! Ingest (feeds.md §3 step 4, §2, §5, §8): a heavy-lane P1 job per run.
//!
//! 1. **Setup:** the feed's definition and ingest parameters, a new run id (from
//!    `feed_run_ids`, so ids are never reused), the run marked open (`feed_runs_open`), and two
//!    staging tables on the writer connection (`TEMP`: spilled to `tmp/`, never journaled, gone
//!    after a crash). Every run takes a new id, a confirmation or re-gate of a waiting run too,
//!    so run ids follow the order runs change the feed's entries: replay (`first_run ≤ r <
//!    removed_run`, storage.md §3), "the latest applied run" and retention all order by id. The
//!    same transaction ends the job with nothing when a purge of a deleted feed with its id
//!    waits, or when the check whose result it carries saw an older source generation (a
//!    deletion, re-creation or source edit since).
//! 2. **Parse** (steps of ≈ 50k staged rows or [`STEP_BYTES`] read, whichever comes first, so
//!    lines that stage nothing still end a step): a parser thread streams the blob through
//!    `picket_rules::formats::parse_feed` → normalised, classified rules → the `drop` types and
//!    the rules `rule_policy` drops (counted per option, kept for `policy_drops`) are left out →
//!    the staging table, where duplicate lines collapse and the earliest `picket-first-seen`
//!    wins.
//! 3. **Gates** (feeds.md §5): parse errors, entry counts, then the change ratio per type
//!    against the applied entries, and for a feed with a held run, against the held run's
//!    entries (its blob parsed again with the current parameters). The counts and the held
//!    parse run in bounded steps (a few ≈ 50k-row chunks each), so a P0 delta runs between them
//!    (core.md §3). A confirmation skips only the change-ratio gate, the one confirmation is
//!    for; the parse-error and entry-count gates judge it again with the current parameters.
//! 4. **Diff** (one heavy step of ≈ 50k-row transactions, back to back): per rule type and mode,
//!    insert new entries, refresh or re-date existing ones, close missing ones (`replace`),
//!    mark them dropped (`aggregate`, for `expire_after`), or close every open entry (`drop`).
//!    Each chunk journals the rows it changes (`feed_entry_undo`) under the run's id.
//! 5. **Finalize** (one transaction): the `feed_runs` row with its counts (a waiting run that
//!    is applied moves to the new id, keeping its old one in `source_run`; one that stays held
//!    or is rejected is updated where it is), the journal and the open mark deleted,
//!    `policy_drops`, the provider's `last` (only while the check's source generation is still
//!    current: a source edit meanwhile keeps its cleared `last`), and the feed alerts. A feed
//!    deleted since setup fails the step, so the run is undone. After the commit: the
//!    `feed_run` UI event (with the source's `version`, and a manual feed's `saved_at`), the
//!    dirty bundles, metrics.
//!
//! **Imports** into a provider feed (feeds.md §4, [`Work::Import`]) are runs too: applied
//! without the entry-count and change-ratio gates, inserting or refreshing only the entries of
//! the rule types the feed keeps in `aggregate` mode (with their first-seen dates, earliest
//! wins) and skipping and counting the rest; an import run is never the provider's `last`, never
//! confirmed, compared with a download or re-ingested, closes nothing, and leaves a held run
//! waiting. An import's run reads its record in `feed_imports` (the import's blob and what it was
//! checked against) and deletes it in its final transaction, so an accepted import survives a
//! full heavy lane and a restart; a feed deleted, created again or retargeted since gets nothing
//! (the record goes), and one whose format, `format_options` or MISP list type changed since gets
//! a rejected run (gate `import_stale`) instead of input checked under other settings. An import
//! whose run keeps failing, or can't be queued, is dropped after [`MAX_IMPORT_ATTEMPTS`] (a run
//! the heavy lane refuses counts too, [`super::Feeds::submit`]) as a rejected run (gate
//! `import_dropped`) whose reason counts the runs started and the refusals; deleting its feed
//! deletes it. Every cleanup of an import names its id, feed and source generation, and ids are
//! never reused, so a job that outlived its feed never removes another feed's import.
//!
//! **Format edits:** after a `format` or `format_options` edit, or a `misp-warninglist` run whose
//! list `type` differs from that of the feed's latest applied run, the run's entries replace the
//! open ones in every mode (feeds.md §3). A `misp-warninglist` file's
//! `picket_first_seen` map dates its values (read by [`super::misp`]): a date that can't be
//! parsed is a parse error of its value.
//!
//! A job whose step fails undoes its run in that same step (`undo::undo_run`), so no other heavy
//! job sees a partial set; one dropped or panicking before it finalizes has its run undone by an
//! [`super::undo::UndoJob`] before the feed takes its next check.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use jiff::Timestamp;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use super::gates::{self, Changes, Verdict};
use super::store::{self, RunRow};
use super::types::{IngestParams, ParseSummary, PolicyCounts, RunKind, RunStatus, TypeCounts, option_name};
use crate::alerts::{Changes as AlertChanges, RaiseSpec, Severity};
use crate::config::model::{FeedDef, Mode};
use crate::modules::download::LastRun;
use crate::scheduler::{BoxFuture, HeavyJob, Step};
use crate::state::SharedState;
use crate::util::ts;

/// Rows per staging insert and per diff transaction (core.md §3: ≈ 50k).
pub const CHUNK: usize = crate::db::CHUNK_ROWS;
/// Parser batches sent to the job.
const BATCH: usize = 5_000;
/// Distinct dropped rules kept per run for `policy_drops` (counts stay exact).
pub const MAX_DROPS_PER_RUN: usize = 10_000;
/// Rule samples an alert carries.
const SAMPLES: usize = 5;
/// `policy_drops` rows kept per feed (README §2 Bounded): the open rows of the latest run (at
/// most [`MAX_DROPS_PER_RUN`]) plus as many resolved ones, the oldest resolved going first.
/// Resolved rows also age out with the resolved-warnings window (storage.md §4).
#[expect(
    clippy::cast_possible_wrap,
    reason = "a const (no TryFrom): MAX_DROPS_PER_RUN (10 000) fits an i64"
)]
pub const MAX_DROPS_PER_FEED: i64 = 2 * MAX_DROPS_PER_RUN as i64;
/// Chunk queries per gate-counting step.
const COUNT_CHUNKS_PER_STEP: usize = 4;
/// The most bytes of the file one parse step reads (≈ 50k lines of a typical list): a step ends
/// after [`CHUNK`] staged rows or this many bytes read, whichever comes first, so a file whose
/// lines are mostly parse errors, `drop` types or rules `rule_policy` drops (none of them staged)
/// is still read in bounded steps (core.md §3 preemption by splitting; build-and-test.md §6).
pub const STEP_BYTES: u64 = 2 * 1024 * 1024;
/// How many bytes the parser reads between two progress reports.
const PROGRESS_BYTES: u64 = 256 * 1024;
/// Runs a pending import may start before it is rejected (README §2: every retry is bounded).
pub const MAX_IMPORT_ATTEMPTS: i64 = 10;

/// Why a pending import is dropped once its attempts are spent, from what they were: the runs of
/// it that started without storing their run, and the times the full heavy lane refused its run.
pub(crate) fn dropped_reason(started: i64, refused: i64) -> String {
    let times = |n: i64| {
        if n == 1 {
            "once".to_string()
        } else {
            format!("{n} times")
        }
    };
    let runs = (started > 0).then(|| format!("its run started {} without finishing", times(started)));
    let lane = (refused > 0).then(|| {
        format!(
            "the heavy lane was full {} when its run was queued",
            times(refused)
        )
    });
    match (runs, lane) {
        (Some(r), Some(l)) => format!("the import was dropped after its attempts: {r}, and {l}"),
        (Some(x), None) | (None, Some(x)) => format!("the import was dropped after its attempts: {x}"),
        (None, None) => "the import was dropped after its attempts".into(),
    }
}

/// Records a pending import dropped before a run of it could start, its attempts spent (README §2
/// Bounded: "dropped and counted"; feeds.md §4), in the caller's transaction: its record goes and,
/// while the feed is still the one it was accepted for, a rejected import run (gate
/// `import_dropped`, changing nothing) says why, with `feed_held` raised as for an import run
/// rejected at its start. Returns that run's `feed_run` event item.
pub(crate) fn record_dropped_import(
    tx: &rusqlite::Transaction<'_>,
    alerts: &crate::alerts::Alerts,
    def: &FeedDef,
    import: i64,
    source_gen: Option<i64>,
    reason: &str,
    ch: &mut AlertChanges,
) -> Result<Option<crate::web::events::FeedRunItem>> {
    let feed = def.id.as_str();
    store::delete_import(tx, import, feed, source_gen)?;
    if store::purge_pending(tx, feed)? || !store::source_current(tx, feed, source_gen)? {
        // Deleted, created again or retargeted since: the import went with its feed.
        return Ok(None);
    }
    let now = ts(&crate::util::now());
    tx.execute(
        "INSERT INTO feed_run_ids(feed_id, at) VALUES (?1, ?2)",
        params![feed, now],
    )?;
    let run_id = tx.last_insert_rowid();
    let zero = serde_json::to_string(&TypeCounts::default())?;
    let parse = ParseSummary {
        import_skipped: Some(TypeCounts::default()),
        ..Default::default()
    };
    tx.execute(
        "INSERT INTO feed_runs(id, feed_id, version, updated_at, downloaded_at, confirmed_at, blob, status, added_json,
            removed_json, total_json, policy_dropped_json, error, kind, params_json, parse_json, gate)
         VALUES (?1, ?2, NULL, NULL, ?3, NULL, NULL, ?4, ?5, ?5, ?5, ?6, ?7, ?8, ?9, ?10, 'import_dropped')",
        params![
            run_id,
            feed,
            now,
            RunStatus::Rejected.as_str(),
            zero,
            serde_json::to_string(&PolicyCounts::new())?,
            reason,
            RunKind::Import.as_str(),
            serde_json::to_string(&IngestParams::of(def))?,
            serde_json::to_string(&parse)?
        ],
    )?;
    tx.execute("DELETE FROM feed_run_ids WHERE id = ?1", [run_id])?;
    let spec = RaiseSpec::new(
        "feed_held",
        Severity::Warning,
        format!("feed_held:{feed}"),
        format!("Feed {}: a run was rejected by a sanity gate", def.name),
        json!({"run": run_id, "status": "rejected", "gate": "import_dropped", "reason": reason}),
    )
    .feed(feed.to_string());
    alerts.raise_in(tx, &spec, ch)?;
    Ok(Some(crate::web::events::FeedRunItem {
        feed: feed.to_string(),
        run: run_id,
        kind: RunKind::Import.as_str().into(),
        status: RunStatus::Rejected.as_str().into(),
        gate: Some("import_dropped".into()),
        version: None,
        saved_at: None,
        source_run: None,
    }))
}

/// What the run is.
#[derive(Debug)]
pub enum Work {
    /// A new download (a manual save among them).
    Download(DownloadInput),
    /// The latest applied blob, read with the current parameters, without the change-ratio gate
    /// (feeds.md §3 "Editing a feed", §8).
    Reingest,
    /// A held run confirmed by a check (feeds.md §5): applied without the change-ratio gate, but
    /// still counted for the drop gate (an extreme drop is never confirmed). `source_gen`: the source generation the confirming check observed for.
    Confirm {
        run_id: i64,
        at: Timestamp,
        source_gen: Option<i64>,
    },
    /// The newest held or rejected run judged again after a `sanity` edit.
    Regate { run_id: i64 },
    /// The `aggregate` expiry sweep (feeds.md §2).
    Expire,
    /// An import merged into a provider feed (feeds.md §4): its record in `feed_imports`, by id,
    /// feed and the source generation it was accepted at (every cleanup names all three).
    Import { import: i64, source_gen: Option<i64> },
}

impl Work {
    fn kind(&self) -> &'static str {
        match self {
            Self::Download(_) => "feed_ingest",
            Self::Reingest => "feed_reingest",
            Self::Confirm { .. } => "feed_confirm",
            Self::Regate { .. } => "feed_regate",
            Self::Expire => "feed_expire",
            Self::Import { .. } => "feed_import",
        }
    }

    /// The source generation of the check this run carries the result of (a download, a
    /// confirmation); `None` for runs that read only stored data.
    fn source_gen(&self) -> Option<Option<i64>> {
        match self {
            Self::Download(d) => Some(d.source_gen),
            Self::Confirm { source_gen, .. } => Some(*source_gen),
            Self::Reingest | Self::Regate { .. } | Self::Expire | Self::Import { .. } => None,
        }
    }
}

/// A download waiting for its run.
#[derive(Clone, Debug)]
pub struct DownloadInput {
    pub blob: String,
    pub version: String,
    pub updated_at: Timestamp,
    pub downloaded_at: Timestamp,
    /// The provider's new state (stored in `last` with the run, whatever its status).
    pub state: Value,
    /// The feed's source generation the check observed for (`feeds::store::source_current`): a
    /// deletion or a source edit since makes the run end with nothing (before it starts) or
    /// keeps `last` as the edit left it (after).
    pub source_gen: Option<i64>,
    /// The provider's trigger is `cron`: the list's `! Expires:` floors its next full download
    /// (feeds.md §5).
    pub trigger_cron: bool,
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Applied,
    Held(String),
    Rejected {
        gate: &'static str,
        reason: String,
    },
    /// Nothing to do (no blob to re-ingest, nothing expired, the feed is gone).
    Nothing,
}

/// One staged rule.
#[derive(Debug)]
struct Row {
    rule_type: &'static str,
    key: String,
    kind: &'static str,
    flags: u16,
    value_json: String,
    raw: String,
    line_no: i64,
    first_seen_at: String,
    ip: Option<([u8; 16], [u8; 16])>,
    redirect: bool,
}

enum Msg {
    Rows(Vec<Row>),
    Drops(Vec<(String, String)>),
    /// A `misp-warninglist` file's `picket_first_seen` entries: value → its date (`None`: a
    /// date that can't be parsed), after every row.
    Dates(Vec<(String, Option<String>)>),
    /// A `misp-warninglist` file's list `type`.
    MispType(Option<String>),
    /// Bytes of the file read since the last report.
    Progress(u64),
    /// Boxed: the stats are far larger than the other messages.
    Done(Box<std::result::Result<(picket_rules::formats::ParseStats, PolicyCounts), String>>),
}

/// The file as the parser reads it, reporting the bytes read to the job ([`Msg::Progress`]),
/// which ends a parse step after [`STEP_BYTES`]. The bounded channel makes the parser wait
/// while the job is between steps.
struct Progress {
    inner: std::fs::File,
    tx: tokio::sync::mpsc::Sender<Msg>,
    unreported: u64,
}

impl std::io::Read for Progress {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = std::io::Read::read(&mut self.inner, buf)?;
        self.unreported += n as u64;
        if self.unreported >= PROGRESS_BYTES || (n == 0 && self.unreported > 0) {
            let bytes = std::mem::take(&mut self.unreported);
            self.tx
                .blocking_send(Msg::Progress(bytes))
                .map_err(|_| std::io::Error::other("the ingest stopped"))?;
        }
        Ok(n)
    }
}

/// A parser thread feeding a staging table.
struct Parser {
    rx: tokio::sync::mpsc::Receiver<Msg>,
    table: String,
    drops_table: Option<String>,
    /// `picket_first_seen` dates of staged values that can't be parsed (parse errors).
    bad_dates: u64,
    misp_type: Option<String>,
    raw_index: bool,
}

fn spawn_parser(
    path: PathBuf,
    params: IngestParams,
    run_time: Timestamp,
    table: String,
    drops_table: Option<String>,
) -> Parser {
    let (tx, rx) = tokio::sync::mpsc::channel::<Msg>(8);
    std::thread::Builder::new()
        .name("feed-parse".into())
        .spawn(move || {
            let r = parse_thread(&path, &params, run_time, &tx);
            let _ = tx.blocking_send(Msg::Done(Box::new(r)));
        })
        .ok();
    Parser {
        rx,
        table,
        drops_table,
        bad_dates: 0,
        misp_type: None,
        raw_index: false,
    }
}

fn parse_thread(
    path: &std::path::Path,
    params: &IngestParams,
    run_time: Timestamp,
    tx: &tokio::sync::mpsc::Sender<Msg>,
) -> std::result::Result<(picket_rules::formats::ParseStats, PolicyCounts), String> {
    let cfg =
        picket_rules::formats::ParseConfig::new(params.rules_format(), params.rules_domains_as(), run_time);
    let policy = params.policy();
    let run_ts = ts(&run_time);
    let mut rows: Vec<Row> = Vec::with_capacity(BATCH);
    let mut drops: Vec<(String, String)> = Vec::new();
    let mut counts: PolicyCounts = BTreeMap::new();
    let mut drops_sent = 0usize;
    let mut stopped = false;
    // Every pass over the file goes through `Progress`, so each parse step stays bounded by the
    // bytes it reads (core.md §3 preemption by splitting), the MISP metadata passes included.
    let open = || -> std::io::Result<std::io::BufReader<Progress>> {
        Ok(std::io::BufReader::with_capacity(
            64 * 1024,
            Progress {
                inner: std::fs::File::open(path)?,
                tx: tx.clone(),
                unreported: 0,
            },
        ))
    };
    let stats = picket_rules::formats::parse_feed(&open, &cfg, |e: picket_rules::Entry| {
        if stopped {
            return;
        }
        let rule = &e.rule;
        if params.mode(rule.rule_type) == Mode::Drop {
            return; // counted by the parser, never stored (feeds.md §2)
        }
        let dropping = policy.dropping(rule);
        if !dropping.is_empty() {
            for o in &dropping {
                *counts.entry(option_name(*o).to_string()).or_insert(0) += 1;
            }
            if drops_sent < MAX_DROPS_PER_RUN {
                drops_sent += 1;
                let opts: Vec<&str> = dropping.iter().map(|o| option_name(*o)).collect();
                drops.push((cut(&e.raw, 4096), opts.join(",")));
                if drops.len() >= BATCH && tx.blocking_send(Msg::Drops(std::mem::take(&mut drops))).is_err() {
                    stopped = true;
                }
            }
            return; // whole rules only (feeds.md §8)
        }
        let ip = rule.ip_range().map(|r| (r.first_bytes(), r.last_bytes()));
        let redirect =
            picket_rules::policy::covering(rule).contains(&picket_rules::policy::PolicyOption::Redirects);
        rows.push(Row {
            rule_type: rule.rule_type.as_str(),
            key: rule.key.clone(),
            kind: rule.kind.as_str(),
            flags: rule.flags.0,
            value_json: rule.value_json(),
            raw: cut(&e.raw, 64 * 1024),
            line_no: crate::util::sat_i64(e.line_no),
            first_seen_at: e
                .first_seen
                .map(|t| ts(&t.min(run_time)))
                .unwrap_or_else(|| run_ts.clone()),
            ip,
            redirect,
        });
        if rows.len() >= BATCH && tx.blocking_send(Msg::Rows(std::mem::take(&mut rows))).is_err() {
            stopped = true;
        }
    })
    .map_err(|e| format!("cannot read the file: {e}"))?;
    if stopped {
        return Err("the ingest stopped".into());
    }
    if !rows.is_empty() && tx.blocking_send(Msg::Rows(rows)).is_err() {
        return Err("the ingest stopped".into());
    }
    if !drops.is_empty() && tx.blocking_send(Msg::Drops(drops)).is_err() {
        return Err("the ingest stopped".into());
    }
    if params.format == crate::config::model::FeedFormat::MispWarninglist {
        // The list's type, and its `picket_first_seen` dates (feeds.md §4), once every row is
        // staged. A document the rule parser couldn't read has no rows to date.
        let ty = open().and_then(super::misp::list_type).ok().flatten();
        if tx.blocking_send(Msg::MispType(ty)).is_err() {
            return Err("the ingest stopped".into());
        }
        let mut batch: Vec<(String, Option<String>)> = Vec::new();
        let mut stop = false;
        let r = open().and_then(|f| {
            super::misp::first_seen(f, |k, d| {
                let date = picket_rules::formats::parse_rfc3339(d.trim()).map(|t| ts(&t.min(run_time)));
                batch.push((k, date));
                if batch.len() >= BATCH && tx.blocking_send(Msg::Dates(std::mem::take(&mut batch))).is_err() {
                    stop = true;
                    return Err(std::io::Error::other("the ingest stopped"));
                }
                Ok(())
            })
        });
        if stop {
            return Err("the ingest stopped".into());
        }
        if r.is_ok() && !batch.is_empty() && tx.blocking_send(Msg::Dates(batch)).is_err() {
            return Err("the ingest stopped".into());
        }
    }
    Ok((stats, counts))
}

fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// The identity of a `feed_entries` row against a staging row `s` (storage.md §3).
const ID_JOIN: &str = "e.rule_type = s.rule_type AND e.key = s.key AND e.kind = s.kind AND e.flags = s.flags AND e.value_json = s.value_json";

fn create_stage_sql(t: &str) -> String {
    format!(
        "CREATE TEMP TABLE IF NOT EXISTS {t} (rule_type TEXT NOT NULL, key TEXT NOT NULL, kind TEXT NOT NULL,
            flags INTEGER NOT NULL, value_json TEXT NOT NULL, raw TEXT NOT NULL, line_no INTEGER,
            first_seen_at TEXT NOT NULL, ip_first BLOB, ip_last BLOB, redirect INTEGER NOT NULL DEFAULT 0);
         CREATE UNIQUE INDEX IF NOT EXISTS temp.{t}_id ON {t}(rule_type, key, kind, flags, value_json);"
    )
}

/// Drops staging tables on the writer connection: one run's (`Some(run)`: its job ended or
/// failed), or every one (`None`: start-up, before any job runs).
pub async fn drop_temp(db: &crate::db::Db, only: Option<i64>) {
    let _ = db
        .write(move |c| {
            let names: Vec<String> = {
                let mut st = c.prepare(
                    "SELECT name FROM sqlite_temp_master WHERE type = 'table' AND (name LIKE 'fstage_%' OR name LIKE 'fdrops_%' OR name LIKE 'fheld_%')",
                )?;
                st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
            };
            for n in names {
                let wanted = only.is_none_or(|run| n.rsplit('_').next() == Some(run.to_string().as_str()));
                if wanted && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                    c.execute_batch(&format!("DROP TABLE IF EXISTS temp.{n};"))?;
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
}

/// What setup found.
struct Run {
    def: FeedDef,
    params: IngestParams,
    run_id: i64,
    blob: Option<String>,
    run_time: Timestamp,
    stage: String,
    drops: String,
    held_table: String,
    prev_totals: TypeCounts,
    /// The change ratio's previous total: the latest applied source run's (feeds.md §5).
    ratio_base: TypeCounts,
    first_run: bool,
    manual: bool,
    /// Staged entries of types an import skips (not `aggregate`), per type.
    import_skipped: TypeCounts,
    /// The held run a download may supersede or be compared with.
    held: Option<RunRow>,
    held_since: Option<Timestamp>,
    /// The run row being judged again or applied (Confirm, Regate).
    existing: Option<RunRow>,
    parse: ParseSummary,
    policy_counts: PolicyCounts,
    staged_totals: TypeCounts,
    held_totals: TypeCounts,
    vs_applied: Changes,
    vs_held: Option<Changes>,
    outcome: Option<Outcome>,
    /// The change-ratio failure against the applied entries, while the held comparison runs.
    ratio_reason: Option<String>,
    /// An import whose feed changed since it was accepted (gate `import_stale`), or whose
    /// attempts are spent (`import_dropped`): rejected with this gate and reason, unread.
    stale_import: Option<(&'static str, String)>,
    /// The held run this one replaces (status → rejected).
    supersede: Option<i64>,
    new_held_since: Option<Timestamp>,
    added: TypeCounts,
    removed: TypeCounts,
    redirects_added: u64,
    redirect_samples: Vec<String>,
}

enum Phase {
    Setup,
    Parse(Parser),
    Gates,
    /// The change counts against the applied entries.
    CountApplied(Count),
    /// The held run's blob, parsed again for the comparison with it.
    ParseHeld(Parser),
    /// The change counts against the held run's entries.
    CountHeld(Count),
    Apply,
    Finalize,
    Done,
}

/// A change count in progress (one pass after the other, a few chunks per step).
struct Count {
    ch: Changes,
    pass: Pass,
}

enum Pass {
    /// Staged rows `(lo, max]` the reference set lacks.
    Added {
        lo: i64,
        max: i64,
    },
    /// Open entries of the `replace` type at index `t` the stage lacks, after `cursor`.
    Removed {
        t: usize,
        cursor: Cursor,
    },
    /// Held rows `(lo, max]` the stage lacks.
    HeldRemoved {
        lo: i64,
        max: i64,
    },
    Done,
}

/// The heavy job of one run.
pub struct IngestJob {
    state: SharedState,
    feed: String,
    work: Work,
    phase: Phase,
    run: Option<Run>,
    guard: super::JobGuard,
}

impl IngestJob {
    /// A job for `feed`; `guard` keeps the feed busy and undoes an unfinished run when dropped.
    pub fn new(state: SharedState, feed: &str, work: Work, guard: super::JobGuard) -> Self {
        Self {
            state,
            feed: feed.to_string(),
            work,
            phase: Phase::Setup,
            run: None,
            guard,
        }
    }

    async fn setup(&mut self) -> Result<bool> {
        let model = self
            .state
            .config
            .model_of(crate::config::EntityKind::Feed)
            .await?;
        let Some(def) = model.feeds.get(&self.feed).cloned() else {
            self.drop_import().await;
            return Ok(false); // deleted meanwhile
        };
        let params = IngestParams::of(&def);
        let feed = self.feed.clone();
        let now = crate::util::now();
        // An import's record, and whether the feed's settings are still those it was checked
        // against (feeds.md §4).
        let mut import_blob: Option<String> = None;
        let mut import_gen: Option<Option<i64>> = None;
        let mut stale_import: Option<(&'static str, String)> = None;
        if let Work::Import { import, source_gen } = &self.work {
            let (id, f2, sgen) = (*import, feed.clone(), *source_gen);
            let (row, applied_type) = self
                .state
                .db
                .read(move |c| {
                    Ok::<_, anyhow::Error>((store::import_by_id(c, id)?, store::applied_misp_type(c, &f2)?))
                })
                .await?;
            let Some(row) = row.filter(|r| r.feed == self.feed && r.source_gen == sgen) else {
                return Ok(false); // stored or dropped already
            };
            let b = &row.binding;
            if b.format != def.format || b.format_options != def.format_options {
                stale_import = Some((
                    "import_stale",
                    "the feed's format or format_options changed after the import was accepted".into(),
                ));
            } else if def.format == crate::config::model::FeedFormat::MispWarninglist
                && b.misp_type != applied_type
            {
                stale_import = Some((
                    "import_stale",
                    "the feed's MISP list type changed after the import was accepted".into(),
                ));
            }
            import_blob = Some(row.blob);
            import_gen = Some(row.source_gen);
        }
        let mut ratio_base = TypeCounts::default();
        // What the run reads.
        let (blob, existing, held, held_since, first_run, prev_totals) = {
            let feed = feed.clone();
            self.state
                .db
                .read(move |c| {
                    let st = store::load_state(c, &feed)?;
                    let newest = store::newest_download(c, &feed)?;
                    let applied = store::has_applied(c, &feed)?;
                    let totals = store::open_totals(c, &feed)?;
                    let latest_blob = store::latest_applied_blob(c, &feed)?;
                    let base = store::latest_applied_source(c, &feed)?.map(|r| r.total);
                    Ok::<_, anyhow::Error>((st, newest, applied, totals, latest_blob, base))
                })
                .await
                .map(|(st, newest, applied, totals, latest_blob, base)| {
                    ratio_base = base.unwrap_or(totals);
                    let held = newest.clone().filter(|r| r.status == Some(RunStatus::Held));
                    match &self.work {
                        Work::Download(d) => {
                            (Some(d.blob.clone()), None, held, st.held_since, !applied, totals)
                        }
                        Work::Import { .. } => (
                            import_blob.clone().filter(|_| stale_import.is_none()),
                            None,
                            held,
                            st.held_since,
                            !applied,
                            totals,
                        ),
                        Work::Reingest => (
                            latest_blob.and_then(|r| r.blob),
                            None,
                            None,
                            st.held_since,
                            !applied,
                            totals,
                        ),
                        Work::Confirm { run_id, .. } | Work::Regate { run_id } => {
                            let ex = newest.filter(|r| r.id == *run_id);
                            (
                                ex.as_ref().and_then(|r| r.blob.clone()),
                                ex,
                                None,
                                st.held_since,
                                !applied,
                                totals,
                            )
                        }
                        Work::Expire => (None, None, None, st.held_since, !applied, totals),
                    }
                })?
        };
        match &self.work {
            Work::Reingest if blob.is_none() => return Ok(false),
            Work::Confirm { .. }
                if existing
                    .as_ref()
                    .is_none_or(|r| r.status != Some(RunStatus::Held)) =>
            {
                return Ok(false);
            }
            Work::Regate { .. }
                if existing
                    .as_ref()
                    .is_none_or(|r| !matches!(r.status, Some(RunStatus::Held | RunStatus::Rejected))) =>
            {
                return Ok(false);
            }
            Work::Expire => {
                let any = self.expiry_candidates(&params, now).await?;
                if !any {
                    return Ok(false);
                }
            }
            _ => {}
        }
        // A new id for every run, a confirmation or re-gate of a waiting run too: ids follow the
        // order runs change entries (storage.md §3 replay, "the latest applied run").
        //
        // In the same transaction, the feed is still the one the job was queued for: no purge of
        // a deleted feed with its id waits (a feed created again waits behind it, so a run set
        // up now would be the deleted feed's), and a check's result (a download, a confirmation)
        // is still for the current source generation (no deletion, re-creation or source edit
        // since the check began). Otherwise the job ends with nothing (storage.md §4: a feed
        // created again starts clean; feeds.md §3 "Editing a feed").
        let feed2 = feed.clone();
        let check_gen = match &self.work {
            Work::Import { .. } => import_gen,
            w => w.source_gen(),
        };
        let import_id = match &self.work {
            Work::Import { import, source_gen } => Some((*import, *source_gen)),
            _ => None,
        };
        let run_id = self
            .state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let current = !store::purge_pending(&tx, &feed2)?
                    && match check_gen {
                        Some(source_gen) => store::source_current(&tx, &feed2, source_gen)?,
                        None => true,
                    };
                if !current {
                    // An import into a feed deleted, created again or retargeted since it was
                    // accepted goes with it (feeds.md §4: bound to the feed it was checked for).
                    if let Some((id, sgen)) = import_id {
                        store::delete_import(&tx, id, &feed2, sgen)?;
                        tx.commit()?;
                    }
                    return Ok::<_, anyhow::Error>(None);
                }
                let attempts = match import_id {
                    Some((id, sgen)) => match store::import_attempt(&tx, id, &feed2, sgen, false)? {
                        Some(a) => Some(a),
                        // Stored or dropped meanwhile: nothing to do.
                        None => return Ok(None),
                    },
                    None => None,
                };
                tx.execute(
                    "INSERT INTO feed_run_ids(feed_id, at) VALUES (?1, ?2)",
                    params![feed2, crate::util::now_ts()],
                )?;
                let id = tx.last_insert_rowid();
                tx.execute(
                    "INSERT OR REPLACE INTO feed_runs_open(run_id, feed_id, started_at) VALUES (?1, ?2, ?3)",
                    params![id, feed2, crate::util::now_ts()],
                )?;
                tx.commit()?;
                Ok(Some((id, attempts)))
            })
            .await?;
        let Some((run_id, attempts)) = run_id else {
            tracing::info!(feed = %self.feed, kind = self.work.kind(),
                "the feed was deleted or its source changed since this run was queued; nothing to do");
            return Ok(false);
        };
        self.guard.set_run(run_id);
        if let Some(a) = attempts.filter(|a| stale_import.is_none() && a.attempts > MAX_IMPORT_ATTEMPTS) {
            // This run started only to reject it: the reason counts the earlier ones.
            stale_import = Some((
                "import_dropped",
                dropped_reason(a.started().saturating_sub(1), a.refused),
            ));
        }
        let blob = if stale_import.is_some() { None } else { blob };
        let stage = format!("fstage_{run_id}");
        let drops = format!("fdrops_{run_id}");
        let held_table = format!("fheld_{run_id}");
        let (s1, d1) = (
            create_stage_sql(&stage),
            format!("CREATE TEMP TABLE IF NOT EXISTS {drops} (raw TEXT PRIMARY KEY, option TEXT NOT NULL);"),
        );
        self.state
            .db
            .write(move |c| {
                c.execute_batch(&s1)?;
                c.execute_batch(&d1)?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        let run_time = match &self.work {
            Work::Download(d) => d.downloaded_at,
            _ => now,
        };
        let _ = &ratio_base;
        self.run = Some(Run {
            manual: def.is_manual(),
            def,
            params,
            run_id,
            blob,
            run_time,
            stage,
            drops,
            held_table,
            prev_totals,
            ratio_base,
            first_run,
            import_skipped: TypeCounts::default(),
            held,
            held_since,
            existing,
            parse: ParseSummary::default(),
            policy_counts: PolicyCounts::new(),
            staged_totals: TypeCounts::default(),
            held_totals: TypeCounts::default(),
            vs_applied: Changes::default(),
            vs_held: None,
            outcome: None,
            ratio_reason: None,
            stale_import,
            supersede: None,
            new_held_since: None,
            added: TypeCounts::default(),
            removed: TypeCounts::default(),
            redirects_added: 0,
            redirect_samples: vec![],
        });
        Ok(true)
    }

    /// Deletes this job's import record (its feed is gone), and only that record.
    async fn drop_import(&self) {
        if let Work::Import { import, source_gen } = &self.work {
            let (id, sgen, feed) = (*import, *source_gen, self.feed.clone());
            let _ = self
                .state
                .db
                .write(move |c| Ok::<_, anyhow::Error>(store::delete_import(c, id, &feed, sgen)?))
                .await;
        }
    }

    async fn expiry_candidates(&self, params: &IngestParams, now: Timestamp) -> Result<bool> {
        let mut cutoffs = Vec::new();
        for t in picket_rules::RuleType::ALL {
            if let Some(d) = params.expire_after(t) {
                let cutoff = crate::util::window_start(now, d);
                cutoffs.push((t.as_str(), ts(&cutoff)));
            }
        }
        if cutoffs.is_empty() {
            return Ok(false);
        }
        let feed = self.feed.clone();
        self.state
            .db
            .read(move |c| {
                for (t, cut) in &cutoffs {
                    let any = c
                        .query_row(
                            "SELECT 1 FROM feed_entries WHERE feed_id = ?1 AND rule_type = ?2 AND removed_run IS NULL
                               AND dropped_at IS NOT NULL AND dropped_at <= ?3 LIMIT 1",
                            params![feed, t, cut],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some();
                    if any {
                        return Ok::<_, anyhow::Error>(true);
                    }
                }
                Ok(false)
            })
            .await
    }

    fn blob_path(&self, b3: &str) -> Result<PathBuf> {
        crate::blobs::path(&self.state.data_dir, b3)
    }

    /// Receives up to one chunk of parsed rows into the parser's table, reading at most about
    /// [`STEP_BYTES`] of the file; `Ok(true)` when done.
    async fn parse_step(&mut self, held: bool) -> Result<bool> {
        let parser = match &mut self.phase {
            Phase::Parse(p) | Phase::ParseHeld(p) => p,
            _ => return Err(anyhow!("not parsing")),
        };
        let mut rows: Vec<Row> = Vec::new();
        let mut drops: Vec<(String, String)> = Vec::new();
        let mut dates: Vec<(String, Option<String>)> = Vec::new();
        let mut done = None;
        let mut read = 0u64;
        while rows.len() < CHUNK && read < STEP_BYTES && dates.len() < CHUNK {
            match parser.rx.recv().await {
                Some(Msg::Rows(r)) => rows.extend(r),
                Some(Msg::Drops(d)) => drops.extend(d),
                Some(Msg::Dates(d)) => dates.extend(d),
                Some(Msg::MispType(t)) => parser.misp_type = t,
                Some(Msg::Progress(n)) => read = read.saturating_add(n),
                Some(Msg::Done(r)) => {
                    done = Some(*r);
                    break;
                }
                None => {
                    done = Some(Err("the parser stopped".into()));
                    break;
                }
            }
        }
        let table = parser.table.clone();
        let drops_table = parser.drops_table.clone();
        let index = !dates.is_empty() && !std::mem::replace(&mut parser.raw_index, true);
        let dates_table = table.clone();
        if !rows.is_empty() || !drops.is_empty() {
            self.state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    {
                        let mut st = tx.prepare_cached(&format!(
                            "INSERT INTO {table}(rule_type, key, kind, flags, value_json, raw, line_no, first_seen_at, ip_first, ip_last, redirect)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                             ON CONFLICT(rule_type, key, kind, flags, value_json)
                             DO UPDATE SET first_seen_at = min(first_seen_at, excluded.first_seen_at)"
                        ))?;
                        for r in &rows {
                            st.execute(params![
                                r.rule_type,
                                r.key,
                                r.kind,
                                i64::from(r.flags),
                                r.value_json,
                                r.raw,
                                r.line_no,
                                r.first_seen_at,
                                r.ip.map(|(a, _)| a.to_vec()),
                                r.ip.map(|(_, b)| b.to_vec()),
                                r.redirect as i64
                            ])?;
                        }
                    }
                    if let Some(dt) = &drops_table {
                        let mut st = tx.prepare_cached(&format!("INSERT OR IGNORE INTO {dt}(raw, option) VALUES (?1, ?2)"))?;
                        for (raw, opt) in &drops {
                            st.execute(params![raw, opt])?;
                        }
                    }
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(())
                })
                .await?;
        }
        // Dates after the rows they date (the parser sends them after every row).
        if !dates.is_empty() {
            // Each date applies to its value alone, earliest wins; a key not in `list` is
            // ignored; a date that can't be parsed is an error of a staged value (feeds.md §4).
            let t = dates_table;
            let bad = self
                .state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    if index {
                        tx.execute_batch(&format!("CREATE INDEX IF NOT EXISTS temp.{t}_raw ON {t}(raw);"))?;
                    }
                    let mut bad = 0u64;
                    {
                        let mut up = tx.prepare_cached(&format!(
                            "UPDATE {t} SET first_seen_at = min(first_seen_at, ?2) WHERE raw = ?1"
                        ))?;
                        let mut has =
                            tx.prepare_cached(&format!("SELECT EXISTS (SELECT 1 FROM {t} WHERE raw = ?1)"))?;
                        for (raw, d) in &dates {
                            match d {
                                Some(d) => {
                                    up.execute(params![raw, d])?;
                                }
                                None => {
                                    if has.query_row([raw], |r| r.get::<_, bool>(0))? {
                                        bad += 1;
                                    }
                                }
                            }
                        }
                    }
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(bad)
                })
                .await?;
            if let Phase::Parse(p) | Phase::ParseHeld(p) = &mut self.phase {
                p.bad_dates += bad;
            }
        }
        let (bad_dates, misp_type) = match &self.phase {
            Phase::Parse(p) | Phase::ParseHeld(p) => (p.bad_dates, p.misp_type.clone()),
            _ => (0, None),
        };
        match done {
            None => Ok(false),
            Some(Err(e)) => Err(anyhow!(e)),
            Some(Ok((stats, counts))) => {
                let run = self.run.as_mut().context("no run")?;
                if !held {
                    run.parse = ParseSummary::from_stats(&stats);
                    // Notices are about browser rules kept: none are while the mode drops them.
                    if run.params.mode(picket_rules::RuleType::Browser) == Mode::Drop {
                        run.parse.notices.clear();
                        run.parse.notice_samples.clear();
                    }
                    run.parse.errors = run.parse.errors.saturating_add(bad_dates);
                    run.parse.misp_type = misp_type;
                    run.policy_counts = counts;
                }
                Ok(true)
            }
        }
    }

    /// Per-type row counts of a staging table.
    async fn table_totals(&self, table: &str) -> Result<TypeCounts> {
        let sql = format!("SELECT rule_type, count(*) FROM {table} GROUP BY rule_type");
        self.state
            .db
            .write(move |c| {
                let mut out = TypeCounts::default();
                let mut st = c.prepare(&sql)?;
                let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
                for row in rows {
                    let (t, n) = row?;
                    if let Some(t) = picket_rules::RuleType::parse(&t) {
                        out.add(t, crate::util::nonneg(n));
                    }
                }
                Ok::<_, anyhow::Error>(out)
            })
            .await
    }

    async fn max_rowid(&self, table: &str) -> Result<i64> {
        let sql = format!("SELECT coalesce(max(rowid), 0) FROM {table}");
        self.state
            .db
            .write(move |c| Ok::<_, anyhow::Error>(c.query_row(&sql, [], |r| r.get::<_, i64>(0))?))
            .await
    }

    /// Staged rows in `(lo, hi]` of `from` that `against` lacks, per type: `against` is the
    /// feed's open entries (`None`) or another staging table.
    async fn count_missing(
        &self,
        from: &str,
        against: Option<&str>,
        lo: i64,
        hi: i64,
    ) -> Result<Vec<(String, i64)>> {
        let cond = match against {
            None => format!(
                "NOT EXISTS (SELECT 1 FROM feed_entries e WHERE e.feed_id = ?3 AND {ID_JOIN} AND e.removed_run IS NULL)"
            ),
            Some(t) => format!("NOT EXISTS (SELECT 1 FROM {t} e WHERE {ID_JOIN}) AND ?3 = ?3"),
        };
        let sql = format!(
            "SELECT s.rule_type, count(*) FROM {from} s WHERE s.rowid > ?1 AND s.rowid <= ?2 AND {cond} GROUP BY s.rule_type"
        );
        let feed = self.feed.clone();
        self.state
            .db
            .write(move |c| {
                let mut st = c.prepare_cached(&sql)?;
                let v = st
                    .query_map(params![lo, hi, feed], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
    }

    /// Runs up to [`COUNT_CHUNKS_PER_STEP`] chunks of a change count; `Ok(true)` when it is done.
    /// Against the applied entries (`held` false): staged rows not open, then open entries of
    /// `replace` types not staged. Against the held run: staged rows the held table lacks, then
    /// held rows the stage lacks (`replace` types only; an `aggregate` type removes none).
    async fn count_step(&self, run: &Run, count: &mut Count, held: bool) -> Result<bool> {
        for _ in 0..COUNT_CHUNKS_PER_STEP {
            match &mut count.pass {
                Pass::Added { lo, max } => {
                    if *lo >= *max {
                        count.pass = if held {
                            Pass::HeldRemoved {
                                lo: 0,
                                max: self.max_rowid(&run.held_table).await?,
                            }
                        } else {
                            Pass::Removed {
                                t: 0,
                                cursor: Cursor::start(),
                            }
                        };
                        continue;
                    }
                    let hi = *lo + crate::util::sat_i64(CHUNK);
                    let against = held.then_some(run.held_table.as_str());
                    for (t, n) in self.count_missing(&run.stage, against, *lo, hi).await? {
                        if let Some(t) = picket_rules::RuleType::parse(&t) {
                            count.ch.added.add(t, crate::util::nonneg(n));
                        }
                    }
                    *lo = hi;
                }
                Pass::Removed { t, cursor } => {
                    let Some(rt) = picket_rules::RuleType::ALL.get(*t).copied() else {
                        count.pass = Pass::Done;
                        continue;
                    };
                    if run.params.mode(rt) != Mode::Replace {
                        // aggregate removes none; drop is not stored
                        *t += 1;
                        *cursor = Cursor::start();
                        continue;
                    }
                    let page = self.page_open(run, rt, cursor).await?;
                    for p in &page {
                        if !p.present {
                            count.ch.removed.add(rt, 1);
                        }
                    }
                    match page.last() {
                        Some(p) if page.len() >= CHUNK => *cursor = p.cursor(),
                        _ => {
                            *t += 1;
                            *cursor = Cursor::start();
                        }
                    }
                }
                Pass::HeldRemoved { lo, max } => {
                    if *lo >= *max {
                        count.pass = Pass::Done;
                        continue;
                    }
                    let hi = *lo + crate::util::sat_i64(CHUNK);
                    for (t, n) in self
                        .count_missing(&run.held_table, Some(&run.stage), *lo, hi)
                        .await?
                    {
                        if let Some(t) = picket_rules::RuleType::parse(&t)
                            && run.params.mode(t) == Mode::Replace
                        {
                            count.ch.removed.add(t, crate::util::nonneg(n));
                        }
                    }
                    *lo = hi;
                }
                Pass::Done => return Ok(true),
            }
        }
        Ok(matches!(count.pass, Pass::Done))
    }

    /// One page of the feed's open entries of type `t` after `cursor`, with whether `stage`
    /// holds each.
    async fn page_open(&self, run: &Run, t: picket_rules::RuleType, cursor: &Cursor) -> Result<Vec<OpenRow>> {
        let (feed, stage, c0) = (self.feed.clone(), run.stage.clone(), cursor.clone());
        self.state
            .db
            .write(move |c| {
                let mut st = c.prepare_cached(&format!(
                    "SELECT e.id, e.key, e.kind, e.flags, e.value_json, e.dropped_at IS NOT NULL,
                            EXISTS (SELECT 1 FROM {stage} s WHERE {ID_JOIN})
                     FROM feed_entries e
                     WHERE e.feed_id = ?1 AND e.rule_type = ?2 AND e.removed_run IS NULL
                       AND (e.key, e.kind, e.flags, e.value_json) > (?3, ?4, ?5, ?6)
                     ORDER BY e.key, e.kind, e.flags, e.value_json LIMIT ?7"
                ))?;
                let v = st
                    .query_map(
                        params![feed, t.as_str(), c0.key, c0.kind, c0.flags, c0.value_json, CHUNK],
                        |r| {
                            Ok(OpenRow {
                                id: r.get(0)?,
                                key: r.get(1)?,
                                kind: r.get(2)?,
                                flags: r.get(3)?,
                                value_json: r.get(4)?,
                                dropped: r.get(5)?,
                                present: r.get(6)?,
                            })
                        },
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
    }

    /// The first gates (feeds.md §5): parse errors and entry counts, which a confirmation
    /// doesn't skip either; then, where the drop or change-ratio gate applies, the count against
    /// the applied entries starts (`Phase::CountApplied`). Otherwise the outcome is decided here.
    async fn gates(&mut self) -> Result<Phase> {
        let mut run = self.run.take().context("no run")?;
        run.staged_totals = self.table_totals(&run.stage).await?;
        run.parse.kept = run.staged_totals.total();
        let sanity = run.params.sanity.clone();
        // An import is applied without the entry-count and change-ratio gates (feeds.md §4).
        let import = matches!(self.work, Work::Import { .. });
        let outcome = match &self.work {
            Work::Expire => Some(Outcome::Applied),
            Work::Import { .. } if run.stale_import.is_some() => {
                let (gate, reason) = run.stale_import.clone().unwrap_or_default();
                Some(Outcome::Rejected { gate, reason })
            }
            _ => match gates::reject_gates(
                &sanity,
                run.manual || import,
                &run.parse,
                run.staged_totals.total(),
            ) {
                Verdict::Reject { gate, reason } => Some(Outcome::Rejected { gate, reason }),
                Verdict::Hold { reason } => Some(Outcome::Held(reason)),
                Verdict::Pass => {
                    // A confirmation is counted too, for the drop gate only: it applies without
                    // the change-ratio gate, the gate it confirms (feeds.md §5).
                    let count = !run.manual
                        && !import
                        && !run.first_run
                        && matches!(
                            self.work,
                            Work::Download(_) | Work::Regate { .. } | Work::Confirm { .. }
                        );
                    if count { None } else { Some(Outcome::Applied) }
                }
            },
        };
        let next = match outcome {
            Some(o) => {
                self.decided(&mut run, o);
                self.after_gates(&run)
            }
            None => {
                let max = self.max_rowid(&run.stage).await?;
                Phase::CountApplied(Count {
                    ch: Changes::default(),
                    pass: Pass::Added { lo: 0, max },
                })
            }
        };
        self.run = Some(run);
        Ok(next)
    }

    /// The count against the applied entries is done: an extreme drop → rejected (never applied,
    /// whatever `confirm_after`); a confirmation → applied; within the limit → applied; else the
    /// run holds, unless a held run is waiting and this one is within *its* limit (the held blob
    /// is parsed again for that, `Phase::ParseHeld`).
    async fn after_count_applied(&mut self, ch: Changes) -> Result<Phase> {
        let mut run = self.run.take().context("no run")?;
        run.vs_applied = ch;
        if let Some(reason) = gates::drop_gate(&run.params.sanity, &run.vs_applied, &run.ratio_base) {
            self.decided(&mut run, Outcome::Rejected { gate: "drop", reason });
            let next = self.after_gates(&run);
            self.run = Some(run);
            return Ok(next);
        }
        if matches!(self.work, Work::Confirm { .. }) {
            self.decided(&mut run, Outcome::Applied);
            let next = self.after_gates(&run);
            self.run = Some(run);
            return Ok(next);
        }
        let next = match gates::change_gate(&run.params.sanity, &run.vs_applied, &run.ratio_base) {
            None => {
                self.decided(&mut run, Outcome::Applied);
                self.after_gates(&run)
            }
            Some(reason) => {
                let held_blob = match (&self.work, &run.held) {
                    (Work::Download(_), Some(h)) => h.blob.clone(),
                    _ => None,
                };
                match held_blob {
                    Some(b) => {
                        run.ratio_reason = Some(reason);
                        let path = self.blob_path(&b)?;
                        let sql = create_stage_sql(&run.held_table);
                        self.state
                            .db
                            .write(move |c| Ok::<_, anyhow::Error>(c.execute_batch(&sql)?))
                            .await?;
                        // Read with the current parameters: what applying the held run would
                        // give now, the same reading as this run's.
                        Phase::ParseHeld(spawn_parser(
                            path,
                            run.params.clone(),
                            run.run_time,
                            run.held_table.clone(),
                            None,
                        ))
                    }
                    None => {
                        let o = self.hold_outcome(&mut run, reason, false);
                        self.decided(&mut run, o);
                        self.after_gates(&run)
                    }
                }
            }
        };
        self.run = Some(run);
        Ok(next)
    }

    /// The count against the held run's entries is done: decide.
    fn after_count_held(&mut self, ch: Changes) -> Result<Phase> {
        let mut run = self.run.take().context("no run")?;
        let within_held = gates::change_gate(&run.params.sanity, &ch, &run.held_totals).is_none();
        run.vs_held = Some(ch);
        let reason = run.ratio_reason.take().unwrap_or_default();
        let o = self.hold_outcome(&mut run, reason, within_held);
        self.decided(&mut run, o);
        let next = self.after_gates(&run);
        self.run = Some(run);
        Ok(next)
    }

    /// A change-ratio failure against the applied entries (feeds.md §5): a run within the limit
    /// of a held run that has waited `confirm_after` confirms it (applied); otherwise it holds,
    /// keeping the hold's start when it is within the held run's limit.
    fn hold_outcome(&self, run: &mut Run, reason: String, within_held: bool) -> Outcome {
        let now = crate::util::now();
        let since = run.held_since.or(run
            .held
            .as_ref()
            .and_then(|h| h.downloaded_at.as_deref().and_then(crate::util::parse_ts)));
        let waited = since.is_some_and(|s| {
            now - s
                >= jiff::SignedDuration::try_from(run.params.sanity.confirm_after.as_duration())
                    .unwrap_or_default()
        });
        if run.held.is_some() && within_held && waited {
            return Outcome::Applied;
        }
        run.new_held_since = if run.held.is_some() && within_held {
            since.or(Some(now))
        } else {
            Some(now)
        };
        Outcome::Held(reason)
    }

    /// Records the outcome, with what it implies for a waiting held run.
    fn decided(&self, run: &mut Run, outcome: Outcome) {
        // A download supersedes a waiting held run, whatever its own outcome.
        if let (Work::Download(_), Some(h)) = (&self.work, &run.held) {
            run.supersede = Some(h.id);
        }
        if let (Work::Regate { .. }, Outcome::Held(_)) = (&self.work, &outcome) {
            run.new_held_since = run.held_since.or(Some(crate::util::now()));
        }
        run.outcome = Some(outcome);
    }

    /// The phase after the gates: the diff for an applied run, else the final transaction.
    fn after_gates(&self, run: &Run) -> Phase {
        if run.outcome == Some(Outcome::Applied) {
            Phase::Apply
        } else {
            Phase::Finalize
        }
    }

    /// The diff, chunk after chunk (one heavy step, feeds.md §3).
    async fn apply(&mut self) -> Result<()> {
        let mut run = self.run.take().context("no run")?;
        if matches!(self.work, Work::Expire) {
            self.expire(&mut run).await?;
            self.run = Some(run);
            return Ok(());
        }
        let max = self.max_rowid(&run.stage).await?;
        let now_ts = ts(&run.run_time);
        let import = matches!(self.work, Work::Import { .. });
        let replace_all = !import && self.replaces_all(&run).await?;
        for t in picket_rules::RuleType::ALL {
            let mode = run.params.mode(t);
            if import && mode != Mode::Aggregate {
                // An import touches only the types the feed aggregates; the rest are skipped and
                // counted (the next download would close them, feeds.md §4).
                let (stage, tt) = (run.stage.clone(), t.as_str());
                let n: i64 = self
                    .state
                    .db
                    .write(move |c| {
                        Ok::<_, anyhow::Error>(c.query_row(
                            &format!("SELECT count(*) FROM {stage} WHERE rule_type = ?1"),
                            [tt],
                            |r| r.get(0),
                        )?)
                    })
                    .await?;
                run.import_skipped.add(t, crate::util::nonneg(n));
                continue;
            }
            if mode != Mode::Drop {
                let aggregate = mode == Mode::Aggregate;
                let mut lo = 0i64;
                while lo < max {
                    let hi = lo + crate::util::sat_i64(CHUNK);
                    let (feed, stage, run_id, now_ts2) =
                        (self.feed.clone(), run.stage.clone(), run.run_id, now_ts.clone());
                    let (added, redirects, samples) = self
                        .state
                        .db
                        .write(move |c| {
                            let tx = c.transaction()?;
                            let r = upsert_chunk(
                                &tx,
                                &feed,
                                &stage,
                                run_id,
                                t.as_str(),
                                lo,
                                hi,
                                aggregate,
                                &now_ts2,
                            )?;
                            tx.commit()?;
                            Ok::<_, anyhow::Error>(r)
                        })
                        .await?;
                    run.added.add(t, added);
                    run.redirects_added += redirects;
                    for s in samples {
                        if run.redirect_samples.len() < SAMPLES {
                            run.redirect_samples.push(s);
                        }
                    }
                    lo = hi;
                }
            }
            if import {
                // An import closes nothing and marks nothing dropped: it isn't the whole set.
                continue;
            }
            // Open entries the download doesn't hold.
            let policy = run.params.policy();
            let mut cursor = Cursor::start();
            loop {
                let page = self.page_open(&run, t, &cursor).await?;
                let n = page.len();
                let mut close: Vec<i64> = Vec::new();
                let mut mark: Vec<i64> = Vec::new();
                for p in &page {
                    if p.present {
                        continue;
                    }
                    match mode {
                        Mode::Replace | Mode::Drop => close.push(p.id),
                        // Entries collected under other settings close (feeds.md §3).
                        Mode::Aggregate if replace_all => close.push(p.id),
                        Mode::Aggregate => {
                            // A rule the policy now drops goes whatever its mode (feeds.md §8).
                            let dropped_by_policy = crate::compiler::source::stored_rule(
                                t.as_str(),
                                &p.kind,
                                &p.key,
                                p.flags,
                                &p.value_json,
                            )
                            .is_some_and(|(_, r)| !policy.dropping(&r).is_empty());
                            if dropped_by_policy {
                                close.push(p.id);
                            } else if !p.dropped {
                                mark.push(p.id);
                            }
                        }
                    }
                }
                if !close.is_empty() || !mark.is_empty() {
                    let (run_id, now_ts2) = (run.run_id, now_ts.clone());
                    let closed = close.len() as u64;
                    self.state
                        .db
                        .write(move |c| {
                            let tx = c.transaction()?;
                            {
                                let mut cl = tx.prepare_cached("UPDATE feed_entries SET removed_run = ?1 WHERE id = ?2 AND removed_run IS NULL")?;
                                for id in &close {
                                    cl.execute(params![run_id, id])?;
                                }
                                let mut j = tx.prepare_cached(
                                    "INSERT OR IGNORE INTO feed_entry_undo(run_id, entry_id, prior_json)
                                     SELECT ?1, id, json_object('last_seen_run', last_seen_run, 'last_seen_at', last_seen_at,
                                        'first_seen_at', first_seen_at, 'dropped_at', dropped_at) FROM feed_entries WHERE id = ?2",
                                )?;
                                let mut m = tx.prepare_cached("UPDATE feed_entries SET dropped_at = ?2 WHERE id = ?1 AND dropped_at IS NULL")?;
                                for id in &mark {
                                    j.execute(params![run_id, id])?;
                                    m.execute(params![id, now_ts2])?;
                                }
                            }
                            tx.commit()?;
                            Ok::<_, anyhow::Error>(())
                        })
                        .await?;
                    run.removed.add(t, closed);
                }
                match page.last() {
                    Some(p) if n >= CHUNK => cursor = p.cursor(),
                    _ => break,
                }
            }
        }
        self.run = Some(run);
        Ok(())
    }

    /// True when this run's entries replace the open ones in every mode (feeds.md §3): its
    /// `format` or `format_options` differ from those of the feed's latest applied run, or a
    /// `misp-warninglist` list `type` differs from that run's.
    async fn replaces_all(&self, run: &Run) -> Result<bool> {
        let feed = self.feed.clone();
        let latest = self
            .state
            .db
            .read(move |c| {
                Ok::<_, anyhow::Error>(c
                    .query_row(
                        &format!(
                            "SELECT {} FROM feed_runs WHERE feed_id = ?1 AND status = 'applied' ORDER BY id DESC LIMIT 1",
                            store::RUN_COLUMNS
                        ),
                        [&feed],
                        store::row_to_run,
                    )
                    .optional()?)
            })
            .await?;
        let Some(prev) = latest else { return Ok(false) };
        let format_changed = prev
            .params
            .as_ref()
            .is_some_and(|p| p.format != run.params.format || p.domains_as != run.params.domains_as);
        let type_changed = run.params.format == crate::config::model::FeedFormat::MispWarninglist
            && match (
                prev.parse.as_ref().and_then(|p| p.misp_type.as_deref()),
                run.parse.misp_type.as_deref(),
            ) {
                (Some(a), Some(b)) => a != b,
                _ => false,
            };
        Ok(format_changed || type_changed)
    }

    /// The expiry sweep: closes `aggregate` entries dropped for longer than `expire_after`.
    async fn expire(&self, run: &mut Run) -> Result<()> {
        for t in picket_rules::RuleType::ALL {
            let Some(d) = run.params.expire_after(t) else {
                continue;
            };
            let cutoff = ts(&crate::util::window_start(crate::util::now(), d));
            loop {
                let (feed, run_id, cut) = (self.feed.clone(), run.run_id, cutoff.clone());
                let n = self
                    .state
                    .db
                    .write(move |c| {
                        let tx = c.transaction()?;
                        let n = tx.execute(
                            "UPDATE feed_entries SET removed_run = ?1 WHERE id IN (SELECT id FROM feed_entries
                               WHERE feed_id = ?2 AND rule_type = ?3 AND removed_run IS NULL AND dropped_at IS NOT NULL
                                 AND dropped_at <= ?4 LIMIT ?5)",
                            params![run_id, feed, t.as_str(), cut, CHUNK],
                        )?;
                        tx.commit()?;
                        Ok::<_, anyhow::Error>(n)
                    })
                    .await?;
                run.removed.add(t, n as u64);
                if n < CHUNK {
                    break;
                }
            }
        }
        Ok(())
    }

    /// The final transaction, then the announcements (feeds.md §3 step 4).
    async fn finalize(&mut self) -> Result<()> {
        let run = self.run.take().context("no run")?;
        let outcome = run.outcome.clone().unwrap_or(Outcome::Nothing);
        let state = self.state.clone();
        let feed = self.feed.clone();
        let (status, gate, error) = match (&outcome, &self.work) {
            (Outcome::Applied, Work::Expire) => (RunStatus::Expired, None, None),
            (Outcome::Applied, _) => (RunStatus::Applied, None, None),
            (Outcome::Held(r), _) => (RunStatus::Held, Some("change_ratio"), Some(r.clone())),
            (Outcome::Rejected { gate, reason }, _) => {
                (RunStatus::Rejected, Some(*gate), Some(reason.clone()))
            }
            (Outcome::Nothing, _) => return Ok(()),
        };
        let applied = matches!(status, RunStatus::Applied | RunStatus::Expired);
        let totals = if applied {
            let mut t = run.prev_totals;
            for rt in picket_rules::RuleType::ALL {
                *t.get_mut(rt) = t
                    .get(rt)
                    .saturating_add(run.added.get(rt))
                    .saturating_sub(run.removed.get(rt));
            }
            t
        } else {
            run.staged_totals
        };
        let (added, removed) = if applied {
            (run.added, run.removed)
        } else {
            (run.vs_applied.added, run.vs_applied.removed)
        };
        let kind = match &self.work {
            Work::Download(_) => RunKind::Download,
            Work::Reingest => RunKind::Reingest,
            Work::Expire => RunKind::Expire,
            Work::Import { .. } => RunKind::Import,
            Work::Confirm { .. } | Work::Regate { .. } => run
                .existing
                .as_ref()
                .and_then(|r| r.kind)
                .unwrap_or(RunKind::Download),
        };
        let now = crate::util::now();
        let (version, updated_at, downloaded_at, confirmed_at, new_last) = match &self.work {
            Work::Download(d) => (
                Some(d.version.clone()),
                Some(ts(&d.updated_at)),
                Some(ts(&d.downloaded_at)),
                applied.then(|| ts(&d.downloaded_at)),
                Some(LastRun {
                    updated_at: d.updated_at,
                    version: d.version.clone(),
                    state: d.state.clone(),
                }),
            ),
            Work::Confirm { at, .. } => (None, None, None, Some(ts(at)), None),
            Work::Regate { .. } => (None, None, None, None, None),
            // An import is never the provider's `last` nor confirmed (feeds.md §4).
            Work::Import { .. } => (None, None, Some(ts(&now)), None, None),
            Work::Reingest | Work::Expire => {
                let v = self.reingest_source_version(&run).await?;
                (v.0, v.1, Some(ts(&now)), Some(ts(&now)), None)
            }
        };
        // The row the event names: the new id, unless a waiting run judged again stays where it is.
        let event_run = match (&run.existing, applied) {
            (Some(r), false) => r.id,
            _ => run.run_id,
        };
        // The version of the source the run read (a confirmation or re-gate: the waiting run's),
        // and for a manual feed its save time, as the save returned it (feeds.md §1).
        let event_version = version
            .clone()
            .or_else(|| run.existing.as_ref().and_then(|r| r.version.clone()));
        let event_saved_at = run
            .manual
            .then(|| {
                updated_at
                    .clone()
                    .or_else(|| run.existing.as_ref().and_then(|r| r.updated_at.clone()))
            })
            .flatten();
        // The run's item in the coalesced `feed_run` event (api.md §7; `web::events`): what
        // places it; its counts and errors are in its row.
        let event = crate::web::events::FeedRunItem {
            feed: feed.clone(),
            run: event_run,
            kind: kind.as_str().into(),
            status: status.as_str().into(),
            gate: gate.map(str::to_string),
            version: event_version,
            saved_at: event_saved_at,
            source_run: run.existing.as_ref().filter(|_| applied).map(|r| r.id),
        };
        let params_json = serde_json::to_string(&run.params)?;
        let mut parse = run.parse.clone();
        if matches!(self.work, Work::Import { .. }) {
            parse.import_skipped = Some(run.import_skipped);
        }
        let parse_json = serde_json::to_string(&parse)?;
        let policy_json = serde_json::to_string(&run.policy_counts)?;
        let blob = run.blob.clone();
        let feed_name = run.def.name.clone();
        let alerts = state.alerts.clone();
        let is_download_feed = !run.manual;
        let keeps_redirects = run.params.policy().redirects == picket_rules::policy::Choice::Keep;
        let expires = run.parse.expires_secs;
        // The waiting run a confirmation or re-gate judged: applied, it moves to the new id
        // (`source_run` keeps the old one); held or rejected, it is updated where it is and the
        // new id is forgotten.
        let source = run.existing.as_ref().map(|r| r.id);
        let run_snapshot = (
            run.run_id,
            source,
            run.supersede,
            run.new_held_since,
            run.drops.clone(),
            run.redirects_added,
            run.redirect_samples.clone(),
        );
        let work_is_download = matches!(self.work, Work::Download(_));
        let work_is_expire = matches!(self.work, Work::Expire);
        let work_is_import = matches!(self.work, Work::Import { .. });
        let import_id = match &self.work {
            Work::Import { import, source_gen } => Some((*import, *source_gen)),
            _ => None,
        };
        // Only a run that takes a new version of the source ends a hold and resolves `feed_held`
        // (core.md §9 "on the feed's next accepted version"): a download, or the held or rejected
        // download a confirmation or re-gate applies; a re-ingest or sweep leaves a hold waiting.
        let accepts_version = matches!(
            self.work,
            Work::Download(_) | Work::Confirm { .. } | Work::Regate { .. }
        );
        let judged_waiting = matches!(self.work, Work::Confirm { .. } | Work::Regate { .. });
        let downloaded_dt = match &self.work {
            Work::Download(d) => Some(d.downloaded_at),
            _ => None,
        };
        // On cron triggers, a list's `! Expires:` is the minimum interval between full downloads
        // of its file (feeds.md §5): the check that downloaded it chose its next time before the
        // file was parsed, so the floor is applied now.
        let cron = matches!(&self.work, Work::Download(d) if d.trigger_cron);
        let expires_floor = match (cron, downloaded_dt, expires) {
            (true, Some(at), Some(e)) if !run.manual => Some(picket_api::time::saturating_add(
                at,
                jiff::SignedDuration::from_secs(crate::util::sat_i64(e.min(super::schedule::MAX_EXPIRES_S))),
            )),
            _ => None,
        };
        let check_gen = self.work.source_gen();
        let coalesced = state.events.coalesced().clone();
        let (ch, bundles, source_ok) = state
            .db
            .write(move |c| {
                let (run_id, source, supersede, held_since, drops_table, redirects_added, redirect_samples) = run_snapshot;
                let tx = c.transaction()?;
                if !super::undo::is_open(&tx, run_id)? {
                    // An undo already reverted this run (it can't be finalized any more).
                    anyhow::bail!("run {run_id} is no longer open");
                }
                if store::purge_pending(&tx, &feed)? {
                    // The feed was deleted while the run was in progress: the run is undone (its
                    // step fails), and the purge retires what the feed had (storage.md §4).
                    anyhow::bail!("the feed was deleted while run {run_id} was in progress");
                }
                // A source edit since the check that downloaded this file: the run is stored (the
                // file was the feed's when it was fetched), but the edit's cleared `last` and its
                // first check stay as they are (feeds.md §3 "Editing a feed").
                let source_ok = match check_gen {
                    Some(source_gen) => store::source_current(&tx, &feed, source_gen)?,
                    None => true,
                };
                let mut ch = AlertChanges::default();
                let reported_id = match source {
                    Some(old) if !applied => old,
                    _ => run_id,
                };
                if let Some(old) = source {
                    let n = if applied {
                        tx.execute(
                            "UPDATE feed_runs SET id = ?2, source_run = ?1, status = ?3, confirmed_at = coalesce(?4, confirmed_at),
                                added_json = ?5, removed_json = ?6, total_json = ?7, policy_dropped_json = ?8, error = ?9,
                                params_json = ?10, parse_json = ?11, gate = ?12
                             WHERE id = ?1",
                            params![
                                old,
                                run_id,
                                status.as_str(),
                                confirmed_at,
                                serde_json::to_string(&added)?,
                                serde_json::to_string(&removed)?,
                                serde_json::to_string(&totals)?,
                                policy_json,
                                error,
                                params_json,
                                parse_json,
                                gate
                            ],
                        )?
                    } else {
                        tx.execute(
                            "UPDATE feed_runs SET status = ?2, added_json = ?3, removed_json = ?4,
                                total_json = ?5, policy_dropped_json = ?6, error = ?7, params_json = ?8, parse_json = ?9, gate = ?10
                             WHERE id = ?1",
                            params![
                                old,
                                status.as_str(),
                                serde_json::to_string(&added)?,
                                serde_json::to_string(&removed)?,
                                serde_json::to_string(&totals)?,
                                policy_json,
                                error,
                                params_json,
                                parse_json,
                                gate
                            ],
                        )?
                    };
                    if n != 1 {
                        // Its row is gone: the run can't be stored (its job undoes it).
                        anyhow::bail!("the waiting run {old} is gone");
                    }
                } else {
                    tx.execute(
                        "INSERT INTO feed_runs(id, feed_id, version, updated_at, downloaded_at, confirmed_at, blob, status, added_json,
                            removed_json, total_json, policy_dropped_json, error, kind, params_json, parse_json, gate)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                        params![
                            run_id,
                            feed,
                            version,
                            updated_at,
                            downloaded_at,
                            confirmed_at,
                            blob,
                            status.as_str(),
                            serde_json::to_string(&added)?,
                            serde_json::to_string(&removed)?,
                            serde_json::to_string(&totals)?,
                            policy_json,
                            error,
                            kind.as_str(),
                            params_json,
                            parse_json,
                            gate
                        ],
                    )?;
                }
                tx.execute("DELETE FROM feed_entry_undo WHERE run_id = ?1", [run_id])?;
                tx.execute("DELETE FROM feed_runs_open WHERE run_id = ?1", [run_id])?;
                tx.execute("DELETE FROM feed_run_ids WHERE id = ?1", [run_id])?;
                // The import is stored (or rejected): its record goes with the run's commit.
                if let Some((id, sgen)) = import_id {
                    store::delete_import(&tx, id, &feed, sgen)?;
                }
                if let Some(old) = supersede
                    && old != run_id
                {
                    tx.execute(
                        "UPDATE feed_runs SET status = 'rejected', gate = 'superseded', error = ?2 WHERE id = ?1 AND status = 'held'",
                        params![old, format!("superseded by run {run_id}")],
                    )?;
                }
                if let Some(last) = new_last.as_ref().filter(|_| source_ok) {
                    store::set_last(&tx, &feed, Some(last))?;
                }
                if let Some(at) = downloaded_dt.filter(|_| source_ok) {
                    store::set_download(&tx, &feed, at, expires)?;
                }
                let _ = expires_floor;
                let held_key = format!("feed_held:{feed}");
                match status {
                    RunStatus::Applied => {
                        if accepts_version {
                            store::set_held_since(&tx, &feed, None)?;
                            alerts.resolve_in(&tx, &held_key, Some(&json!({"run": run_id})), &mut ch)?;
                        }
                        // policy_drops (feeds.md §8); an import isn't the feed's set of rules.
                        let (new_counts, samples) = if work_is_import {
                            (BTreeMap::new(), vec![])
                        } else {
                            update_policy_drops(&tx, &feed, run_id, &drops_table)?
                        };
                        if new_counts.values().sum::<u64>() > 0 {
                            let spec = RaiseSpec::new(
                                "feed_rules_dropped",
                                Severity::Warning,
                                format!("feed_rules_dropped:{feed}"),
                                format!("Feed {feed_name}: rules its rule_policy drops"),
                                json!({"run": run_id, "new_by_option": new_counts, "samples": samples}),
                            )
                            .feed(feed.clone());
                            alerts.raise_in(&tx, &spec, &mut ch)?;
                        }
                        if is_download_feed && !work_is_import && keeps_redirects && redirects_added > 0 {
                            let spec = RaiseSpec::new(
                                "feed_redirect_added",
                                Severity::Warning,
                                format!("feed_redirect_added:{feed}"),
                                format!("Feed {feed_name} added redirects"),
                                json!({"run": run_id, "added": redirects_added, "samples": redirect_samples}),
                            )
                            .feed(feed.clone());
                            alerts.raise_in(&tx, &spec, &mut ch)?;
                        }
                    }
                    RunStatus::Expired => {}
                    RunStatus::Held | RunStatus::Rejected => {
                        if status == RunStatus::Held {
                            store::set_held_since(&tx, &feed, held_since)?;
                        } else if supersede.is_some() || judged_waiting {
                            // The waiting held run is gone with it (superseded, or itself
                            // rejected on confirmation or re-gate): no hold runs any more.
                            store::set_held_since(&tx, &feed, None)?;
                        }
                        let spec = RaiseSpec::new(
                            "feed_held",
                            Severity::Warning,
                            held_key,
                            format!(
                                "Feed {feed_name}: a run was {} by a sanity gate",
                                if status == RunStatus::Held { "held" } else { "rejected" }
                            ),
                            json!({"run": reported_id, "status": status.as_str(), "gate": gate, "reason": error}),
                        )
                        .feed(feed.clone());
                        alerts.raise_in(&tx, &spec, &mut ch)?;
                    }
                }
                let bundles = if applied { store::bundles_of(&tx, &feed)? } else { vec![] };
                tx.commit()?;
                alerts.committed(&ch);
                // On the writer, right after the commit: the UI's `feed_run` notes follow commit
                // order, so a run stored before a config restore goes out before its `restore`
                // event (`web::events` module docs; core.md §2).
                coalesced.feed_run(event);
                Ok::<_, anyhow::Error>((ch, bundles, source_ok))
            })
            .await?;
        self.guard.finished();
        drop_temp(&state.db, Some(run.run_id)).await;
        if source_ok && downloaded_dt.is_some() && !work_is_import {
            state
                .feeds
                .set_floor(&self.feed, super::schedule::expires_floor(downloaded_dt, expires));
        }
        state.alerts.announce(ch);
        if applied && (added.total() > 0 || removed.total() > 0 || work_is_expire) {
            state.feeds.dirty().mark(&bundles, &self.feed);
        }
        tracing::info!(feed = %self.feed, run = event_run, status = status.as_str(), kind = kind.as_str(),
            added = added.total(), removed = removed.total(), "feed run stored");
        super::metrics::run_stored(
            &state,
            &self.feed,
            status,
            &added,
            &removed,
            &totals,
            run.parse.errors,
            work_is_download,
        )
        .await;
        Ok(())
    }

    /// A re-ingest or sweep keeps the source's version and time from the latest applied run.
    async fn reingest_source_version(&self, run: &Run) -> Result<(Option<String>, Option<String>)> {
        let feed = self.feed.clone();
        let blob = run.blob.clone();
        self.state
            .db
            .read(move |c| {
                let r = match &blob {
                    Some(_) => store::latest_applied_blob(c, &feed)?,
                    None => store::latest_change(c, &feed)?,
                };
                Ok::<_, anyhow::Error>(r.map(|r| (r.version, r.updated_at)).unwrap_or((None, None)))
            })
            .await
    }
}

/// One chunk of the insert-and-refresh pass (feeds.md §2, §4 first-seen): returns the rows
/// inserted, the redirects among them, and samples of those.
#[expect(
    clippy::too_many_arguments,
    reason = "one chunk's bounds and flags, written by one upsert"
)]
fn upsert_chunk(
    tx: &rusqlite::Transaction<'_>,
    feed: &str,
    stage: &str,
    run: i64,
    t: &str,
    lo: i64,
    hi: i64,
    aggregate: bool,
    now_ts: &str,
) -> rusqlite::Result<(u64, u64, Vec<String>)> {
    // Journal the rows this chunk changes, then change them.
    let changed_cond = if aggregate {
        "1"
    } else {
        "s.first_seen_at < e.first_seen_at"
    };
    tx.execute(
        &format!(
            "INSERT OR IGNORE INTO feed_entry_undo(run_id, entry_id, prior_json)
             SELECT ?1, e.id, json_object('last_seen_run', e.last_seen_run, 'last_seen_at', e.last_seen_at,
                 'first_seen_at', e.first_seen_at, 'dropped_at', e.dropped_at)
             FROM {stage} s JOIN feed_entries e ON e.feed_id = ?2 AND {ID_JOIN} AND e.removed_run IS NULL
             WHERE s.rowid > ?3 AND s.rowid <= ?4 AND s.rule_type = ?5 AND {changed_cond}"
        ),
        params![run, feed, lo, hi, t],
    )?;
    let target_join = "feed_entries.feed_id = ?2 AND feed_entries.rule_type = s.rule_type AND feed_entries.key = s.key
        AND feed_entries.kind = s.kind AND feed_entries.flags = s.flags AND feed_entries.value_json = s.value_json
        AND feed_entries.removed_run IS NULL AND s.rowid > ?3 AND s.rowid <= ?4 AND s.rule_type = ?5";
    if aggregate {
        tx.execute(
            &format!(
                "UPDATE feed_entries SET last_seen_run = ?1, last_seen_at = ?6,
                    first_seen_at = min(feed_entries.first_seen_at, s.first_seen_at), dropped_at = NULL
                 FROM {stage} s WHERE {target_join}"
            ),
            params![run, feed, lo, hi, t, now_ts],
        )?;
    } else {
        // Earliest wins (feeds.md §4): only an earlier first-seen date changes a row.
        tx.execute(
            &format!(
                "UPDATE feed_entries SET first_seen_at = s.first_seen_at
                 FROM {stage} s WHERE {target_join} AND s.first_seen_at < feed_entries.first_seen_at AND ?1 = ?1 AND ?6 = ?6"
            ),
            params![run, feed, lo, hi, t, now_ts],
        )?;
    }
    let new_cond = format!(
        "NOT EXISTS (SELECT 1 FROM feed_entries e WHERE e.feed_id = ?2 AND {ID_JOIN} AND e.removed_run IS NULL)"
    );
    let (redirects, samples) = {
        let mut st = tx.prepare_cached(&format!(
            "SELECT s.raw FROM {stage} s WHERE s.rowid > ?1 AND s.rowid <= ?3 AND s.rule_type = ?4 AND s.redirect = 1
               AND NOT EXISTS (SELECT 1 FROM feed_entries e WHERE e.feed_id = ?2 AND {ID_JOIN} AND e.removed_run IS NULL)"
        ))?;
        let mut n = 0u64;
        let mut samples = Vec::new();
        let mut rows = st.query(params![lo, feed, hi, t])?;
        while let Some(r) = rows.next()? {
            n += 1;
            if samples.len() < SAMPLES {
                samples.push(crate::util::sanitize_for_message(&r.get::<_, String>(0)?, 300));
            }
        }
        (n, samples)
    };
    let added = tx.execute(
        &format!(
            "INSERT INTO feed_entries(feed_id, rule_type, key, kind, flags, value_json, raw, line_no, first_run, last_seen_run,
                 last_seen_at, first_seen_at, ip_first, ip_last)
             SELECT ?2, s.rule_type, s.key, s.kind, s.flags, s.value_json, s.raw, s.line_no, ?1, ?1, ?6, s.first_seen_at,
                 s.ip_first, s.ip_last
             FROM {stage} s WHERE s.rowid > ?3 AND s.rowid <= ?4 AND s.rule_type = ?5 AND {new_cond}"
        ),
        params![run, feed, lo, hi, t, now_ts],
    )?;
    Ok((added as u64, redirects, samples))
}

/// Records the run's dropped rules in `policy_drops` (keyed on feed and rule): new rows, rows
/// seen again, and rows of rules the feed no longer has (resolved). Returns the new rows' count
/// per option and a few samples.
fn update_policy_drops(
    tx: &rusqlite::Transaction<'_>,
    feed: &str,
    run: i64,
    drops_table: &str,
) -> rusqlite::Result<(BTreeMap<String, u64>, Vec<String>)> {
    let exists: bool = tx
        .query_row(
            "SELECT 1 FROM sqlite_temp_master WHERE type = 'table' AND name = ?1",
            [drops_table],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let mut new_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut samples = Vec::new();
    if exists {
        let rows: Vec<(String, String)> = {
            let mut st = tx.prepare(&format!(
                "SELECT d.raw, d.option FROM {drops_table} d WHERE NOT EXISTS
                   (SELECT 1 FROM policy_drops p WHERE p.feed_id = ?1 AND p.raw = d.raw)"
            ))?;
            st.query_map([feed], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (raw, opt) in &rows {
            for o in opt.split(',') {
                *new_counts.entry(o.to_string()).or_insert(0) += 1;
            }
            if samples.len() < SAMPLES {
                samples.push(crate::util::sanitize_for_message(raw, 300));
            }
        }
        tx.execute(
            &format!(
                "INSERT INTO policy_drops(feed_id, option, raw, first_run, last_seen_run, status)
                 SELECT ?1, d.option, d.raw, ?2, ?2, 'open' FROM {drops_table} d WHERE true
                 ON CONFLICT(feed_id, raw) DO UPDATE SET option = excluded.option, last_seen_run = excluded.last_seen_run,
                    status = 'open', resolved_at = NULL"
            ),
            params![feed, run],
        )?;
    }
    // A rule that left the feed resolves its row (and ages out from then, storage.md §4).
    tx.execute(
        "UPDATE policy_drops SET status = 'resolved', resolved_at = ?3
         WHERE feed_id = ?1 AND status = 'open' AND last_seen_run < ?2",
        params![feed, run, crate::util::now_ts()],
    )?;
    // At most MAX_DROPS_PER_FEED rows per feed: the oldest resolved ones go first.
    let n: i64 = tx.query_row(
        "SELECT count(*) FROM policy_drops WHERE feed_id = ?1",
        [feed],
        |r| r.get(0),
    )?;
    if n > MAX_DROPS_PER_FEED {
        tx.execute(
            "DELETE FROM policy_drops WHERE id IN (SELECT id FROM policy_drops WHERE feed_id = ?1 AND status = 'resolved'
               ORDER BY coalesce(resolved_at, ''), id LIMIT ?2)",
            params![feed, n - MAX_DROPS_PER_FEED],
        )?;
    }
    Ok((new_counts, samples))
}

/// Where the open-entries pass is: the last identity tuple seen.
#[derive(Clone, Debug)]
struct Cursor {
    key: String,
    kind: String,
    flags: i64,
    value_json: String,
}

impl Cursor {
    fn start() -> Self {
        Self {
            key: String::new(),
            kind: String::new(),
            flags: -1,
            value_json: String::new(),
        }
    }
}

#[derive(Debug)]
struct OpenRow {
    id: i64,
    key: String,
    kind: String,
    flags: i64,
    value_json: String,
    dropped: bool,
    present: bool,
}

impl OpenRow {
    fn cursor(&self) -> Cursor {
        Cursor {
            key: self.key.clone(),
            kind: self.kind.clone(),
            flags: self.flags,
            value_json: self.value_json.clone(),
        }
    }
}

impl HeavyJob for IngestJob {
    fn kind(&self) -> &str {
        self.work.kind()
    }

    fn target(&self) -> &str {
        &self.feed
    }

    fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
        Box::pin(async move {
            match self.step_inner().await {
                Ok(s) => Ok(s),
                Err(e) => {
                    // Undo the run in this same step, so no other heavy job sees a partial set;
                    // if that fails too, the guard's undo job tries again (feeds.md §3 step 4).
                    if let Some(run) = self.guard.run() {
                        match super::undo::undo_run(&self.state.db, run).await {
                            Ok(s) => {
                                if let Some(s) = s {
                                    tracing::warn!(feed = %self.feed, run, deleted = s.deleted, reopened = s.reopened,
                                        restored = s.restored, "a feed run failed; its changes were undone");
                                }
                                drop_temp(&self.state.db, Some(run)).await;
                                self.guard.undone();
                            }
                            Err(u) => tracing::error!(feed = %self.feed, run, error = %format!("{u:#}"),
                                "cannot undo a failed feed run here; an undo job tries again"),
                        }
                    }
                    Err(e)
                }
            }
        })
    }
}

impl IngestJob {
    async fn step_inner(&mut self) -> anyhow::Result<Step> {
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Setup => {
                if !self.setup().await? {
                    self.guard.finished();
                    return Ok(Step::Done);
                }
                let run = self.run.as_ref().context("no run")?;
                self.phase = match &run.blob {
                    Some(b) => {
                        let path = self.blob_path(b)?;
                        Phase::Parse(spawn_parser(
                            path,
                            run.params.clone(),
                            run.run_time,
                            run.stage.clone(),
                            Some(run.drops.clone()),
                        ))
                    }
                    None => Phase::Gates,
                };
                Ok(Step::More)
            }
            p @ Phase::Parse(_) => {
                self.phase = p;
                if self.parse_step(false).await? {
                    self.phase = Phase::Gates;
                }
                Ok(Step::More)
            }
            Phase::Gates => {
                self.phase = self.gates().await?;
                Ok(Step::More)
            }
            Phase::CountApplied(mut count) => {
                let run = self.run.take().context("no run")?;
                let done = self.count_step(&run, &mut count, false).await;
                self.run = Some(run);
                self.phase = if done? {
                    self.after_count_applied(count.ch).await?
                } else {
                    Phase::CountApplied(count)
                };
                Ok(Step::More)
            }
            p @ Phase::ParseHeld(_) => {
                self.phase = p;
                if self.parse_step(true).await? {
                    let run = self.run.as_mut().context("no run")?;
                    let held_table = run.held_table.clone();
                    let totals = self.table_totals(&held_table).await?;
                    let stage = self.run.as_ref().context("no run")?.stage.clone();
                    self.run.as_mut().context("no run")?.held_totals = totals;
                    let max = self.max_rowid(&stage).await?;
                    self.phase = Phase::CountHeld(Count {
                        ch: Changes::default(),
                        pass: Pass::Added { lo: 0, max },
                    });
                }
                Ok(Step::More)
            }
            Phase::CountHeld(mut count) => {
                let run = self.run.take().context("no run")?;
                let done = self.count_step(&run, &mut count, true).await;
                self.run = Some(run);
                self.phase = if done? {
                    self.after_count_held(count.ch)?
                } else {
                    Phase::CountHeld(count)
                };
                Ok(Step::More)
            }
            Phase::Apply => {
                self.apply().await?;
                self.phase = Phase::Finalize;
                Ok(Step::More)
            }
            Phase::Finalize => {
                self.finalize().await?;
                Ok(Step::Done)
            }
            Phase::Done => Ok(Step::Done),
        }
    }
}
