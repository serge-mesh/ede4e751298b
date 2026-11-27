//! Feed state in `core.db` (storage.md §3): `feed_state`, `feed_provider_state`, `feed_runs`,
//! `feed_provider_checks`, `feed_checks`, `feed_changes`, module pauses. Plain functions over a
//! connection or a transaction, so the callers decide what commits together.

use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use super::types::{IngestParams, ParseSummary, PolicyCounts, RunKind, RunStatus, TypeCounts};
use crate::modules::download::{ChangeTime, LastRun, Listing};
use crate::util::{parse_ts, ts};

/// One feed's scheduler state.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FeedState {
    pub last: Option<LastRun>,
    pub next_check_at: Option<Timestamp>,
    pub last_check_at: Option<Timestamp>,
    pub last_ok_at: Option<Timestamp>,
    pub failures: u32,
    pub failing_since: Option<Timestamp>,
    pub held_since: Option<Timestamp>,
    pub expires_s: Option<u64>,
    pub last_download_at: Option<Timestamp>,
    /// The feed model's ask (feed-scheduling.md §5).
    pub next_ask_at: Option<Timestamp>,
    /// The current model epoch's start (feed-scheduling.md §4).
    pub epoch_at: Option<Timestamp>,
    /// The content hash of its last download in the epoch (feed-scheduling.md §3).
    pub seen_blake3: Option<String>,
    /// The staleness reference frozen at its last change (feed-scheduling.md §8).
    pub stale_ref: Option<String>,
    /// When the epoch's warm start was read (feed-scheduling.md §6).
    pub warm_started_at: Option<Timestamp>,
    /// The start of the span that warm start read (its first `bootstrap` check).
    pub warm_span_at: Option<Timestamp>,
}

fn t(s: Option<String>) -> Option<Timestamp> {
    s.as_deref().and_then(parse_ts)
}

pub fn load_state(c: &Connection, feed: &str) -> rusqlite::Result<FeedState> {
    Ok(c.query_row(
        "SELECT last_json, next_check_at, last_check_at, last_ok_at, failures, failing_since, held_since,
                expires_s, last_download_at, next_ask_at, epoch_at, seen_blake3, stale_ref_json, warm_started_at,
                warm_span_at
         FROM feed_state WHERE feed_id = ?1",
        [feed],
        |r| {
            Ok(FeedState {
                last: r
                    .get::<_, Option<String>>(0)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                next_check_at: t(r.get(1)?),
                last_check_at: t(r.get(2)?),
                last_ok_at: t(r.get(3)?),
                failures: u32::try_from(r.get::<_, i64>(4)?.clamp(0, i64::from(u32::MAX))).unwrap_or(u32::MAX),
                failing_since: t(r.get(5)?),
                held_since: t(r.get(6)?),
                expires_s: r.get::<_, Option<i64>>(7)?.map(crate::util::nonneg),
                last_download_at: t(r.get(8)?),
                next_ask_at: t(r.get(9)?),
                epoch_at: t(r.get(10)?),
                seen_blake3: r.get(11)?,
                stale_ref: r.get(12)?,
                warm_started_at: t(r.get(13)?),
                warm_span_at: t(r.get(14)?),
            })
        },
    )
    .optional()?
    .unwrap_or_default())
}

/// The start of a feed's history the learner uses: the later of 60 days ago and its epoch's
/// start (feed-scheduling.md §4).
pub fn history_since(c: &Connection, feed: &str, now: Timestamp) -> rusqlite::Result<Timestamp> {
    let epoch: Option<String> = c
        .query_row(
            "SELECT epoch_at FROM feed_state WHERE feed_id = ?1",
            [feed],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let floor = now - jiff::SignedDuration::from_hours(24 * 60);
    Ok(epoch
        .as_deref()
        .and_then(parse_ts)
        .map_or(floor, |e| e.max(floor)))
}

pub fn set_ask(c: &Connection, feed: &str, at: Option<Timestamp>) -> rusqlite::Result<()> {
    set_state_column(c, feed, "next_ask_at", at.as_ref().map(ts))
}

pub fn set_seen_blake3(c: &Connection, feed: &str, b3: &str) -> rusqlite::Result<()> {
    set_state_column(c, feed, "seen_blake3", b3)
}

pub fn set_stale_ref(c: &Connection, feed: &str, r: Option<&str>) -> rusqlite::Result<()> {
    set_state_column(c, feed, "stale_ref_json", r)
}

pub fn set_warm_started(c: &Connection, feed: &str, at: Timestamp) -> rusqlite::Result<()> {
    set_state_column(c, feed, "warm_started_at", ts(&at))
}

/// Records where the epoch's warm start began (feed-scheduling.md §6), so rebuilds and backtests
/// replay its span ([`super::schedule::epoch_observations`]).
pub fn set_warm_span(c: &Connection, feed: &str, at: Option<Timestamp>) -> rusqlite::Result<()> {
    set_state_column(c, feed, "warm_span_at", at.as_ref().map(ts))
}

/// One feed provider's durable state (storage.md §3 `feed_provider_state`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProviderState {
    pub state: Option<serde_json::Value>,
    pub listing: Option<Listing>,
    pub next_check_at: Option<Timestamp>,
    pub due_cause: Option<String>,
    pub nudged_at: Option<Timestamp>,
    pub k: Option<f64>,
    pub trigger_state: Option<serde_json::Value>,
    pub source_gen: Option<i64>,
    pub last_check_at: Option<Timestamp>,
    pub last_ok_at: Option<Timestamp>,
    pub failing_since: Option<Timestamp>,
    pub check_started_at: Option<Timestamp>,
}

/// A stored listing (`feed_provider_state.listing_json`) without any empty or blank path: no file
/// name is either, so none shows, counts or is selected.
pub fn parse_listing(json: &str) -> Option<Listing> {
    let mut l: Listing = serde_json::from_str(json).ok()?;
    l.files.retain(|f| !f.trim().is_empty());
    Some(l)
}

pub fn load_provider_state(c: &Connection, provider: &str) -> rusqlite::Result<ProviderState> {
    Ok(c.query_row(
        "SELECT state_json, listing_json, next_check_at, due_cause, nudged_at, k, trigger_state_json, source_gen,
                last_check_at, last_ok_at, failing_since, check_started_at
         FROM feed_provider_state WHERE provider_id = ?1",
        [provider],
        |r| {
            Ok(ProviderState {
                state: r
                    .get::<_, Option<String>>(0)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                listing: r.get::<_, Option<String>>(1)?.and_then(|s| parse_listing(&s)),
                next_check_at: t(r.get(2)?),
                due_cause: r.get(3)?,
                nudged_at: t(r.get(4)?),
                k: r.get(5)?,
                trigger_state: r
                    .get::<_, Option<String>>(6)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                source_gen: r.get(7)?,
                last_check_at: t(r.get(8)?),
                last_ok_at: t(r.get(9)?),
                failing_since: t(r.get(10)?),
                check_started_at: t(r.get(11)?),
            })
        },
    )
    .optional()?
    .unwrap_or_default())
}

/// Every provider's state (start-up).
pub fn load_provider_states(c: &Connection) -> rusqlite::Result<Vec<(String, ProviderState)>> {
    let mut st = c.prepare("SELECT provider_id FROM feed_provider_state")?;
    let ids: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    ids.into_iter()
        .map(|id| load_provider_state(c, &id).map(|s| (id, s)))
        .collect()
}

pub fn ensure_provider_state(c: &Connection, provider: &str) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO feed_provider_state(provider_id) VALUES (?1) ON CONFLICT(provider_id) DO NOTHING",
        [provider],
    )?;
    Ok(())
}

/// Gives a provider a new source generation (its `module` or `config` changed), in the caller's
/// transaction, as [`new_source_gen`] does for a feed.
pub fn new_provider_source_gen(c: &Connection, provider: &str) -> rusqlite::Result<i64> {
    let g = next_generation(c, &format!("provider:{provider}"))?;
    ensure_provider_state(c, provider)?;
    c.execute(
        "UPDATE feed_provider_state SET source_gen = ?2 WHERE provider_id = ?1",
        params![provider, g],
    )?;
    Ok(g)
}

/// Gives a provider a new selection generation (its `module`, `config`, `files` or `exclude`
/// changed), in the caller's transaction: a check that read an older one stores no provider
/// state or listing and adds no feeds (feeds.md §3 "Editing a feed provider", providers.md §2
/// Listing).
pub fn new_provider_list_gen(c: &Connection, provider: &str) -> rusqlite::Result<i64> {
    let g = next_generation(c, &format!("provider-list:{provider}"))?;
    ensure_provider_state(c, provider)?;
    c.execute(
        "UPDATE feed_provider_state SET list_gen = ?2 WHERE provider_id = ?1",
        params![provider, g],
    )?;
    Ok(g)
}

/// True while `list_gen` is the provider's current selection generation.
pub fn provider_list_current(
    c: &Connection,
    provider: &str,
    list_gen: Option<i64>,
) -> rusqlite::Result<bool> {
    c.query_row(
        "SELECT EXISTS (SELECT 1 FROM feed_providers WHERE id = ?1)
            AND (SELECT list_gen FROM feed_provider_state WHERE provider_id = ?1) IS ?2",
        params![provider, list_gen],
        |r| r.get(0),
    )
}

/// True while `source_gen` is the provider's current one and the provider exists.
pub fn provider_source_current(
    c: &Connection,
    provider: &str,
    source_gen: Option<i64>,
) -> rusqlite::Result<bool> {
    c.query_row(
        "SELECT EXISTS (SELECT 1 FROM feed_providers WHERE id = ?1)
            AND (SELECT source_gen FROM feed_provider_state WHERE provider_id = ?1) IS ?2",
        params![provider, source_gen],
        |r| r.get(0),
    )
}

/// A provider as stored, with its generations, read in one statement so they agree.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredProvider {
    pub module: String,
    pub config: serde_json::Value,
    pub files: serde_json::Value,
    pub exclude: serde_json::Value,
    pub source_gen: Option<i64>,
    pub list_gen: Option<i64>,
}

impl StoredProvider {
    /// True when the stored provider is the one `d` describes, as far as what a check reads and
    /// lists goes (`module`, `config`, `files`, `exclude`).
    pub fn is(&self, d: &crate::config::model::FeedProviderDef) -> bool {
        fn json<T: Serialize>(v: &T) -> serde_json::Value {
            serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
        }
        self.module == d.module
            && self.config == d.config
            && self.files == json(&d.files)
            && self.exclude == json(&d.exclude)
    }
}

pub fn stored_provider(c: &Connection, provider: &str) -> rusqlite::Result<Option<StoredProvider>> {
    let parse = |s: String| serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
    c.query_row(
        "SELECT p.module, p.config_json, p.files_json, p.exclude_json, s.source_gen, s.list_gen FROM feed_providers p
         LEFT JOIN feed_provider_state s ON s.provider_id = p.id WHERE p.id = ?1",
        [provider],
        |r| {
            Ok(StoredProvider {
                module: r.get(0)?,
                config: parse(r.get(1)?),
                files: parse(r.get(2)?),
                exclude: parse(r.get(3)?),
                source_gen: r.get(4)?,
                list_gen: r.get(5)?,
            })
        },
    )
    .optional()
}

pub fn set_provider_next(
    c: &Connection,
    provider: &str,
    next: Option<Timestamp>,
    cause: Option<&str>,
) -> rusqlite::Result<()> {
    ensure_provider_state(c, provider)?;
    c.execute(
        "UPDATE feed_provider_state SET next_check_at = ?2, due_cause = ?3 WHERE provider_id = ?1",
        params![provider, next.as_ref().map(ts), cause],
    )?;
    Ok(())
}

/// One check of a feed provider (`feed_provider_checks`); returns its id.
pub fn record_provider_check(
    c: &Connection,
    provider: &str,
    at: Timestamp,
    cause: &str,
    duration_ms: u64,
    ok: bool,
    error: Option<&str>,
) -> rusqlite::Result<i64> {
    c.execute(
        "INSERT INTO feed_provider_checks(provider_id, t, cause, duration_ms, ok, error) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![provider, ts(&at), cause, crate::util::sat_i64(duration_ms), ok, error],
    )?;
    let id = c.last_insert_rowid();
    ensure_provider_state(c, provider)?;
    if ok {
        c.execute(
            "UPDATE feed_provider_state SET last_check_at = ?2, last_ok_at = ?2 WHERE provider_id = ?1",
            params![provider, ts(&at)],
        )?;
    } else {
        c.execute(
            "UPDATE feed_provider_state SET last_check_at = ?2 WHERE provider_id = ?1",
            params![provider, ts(&at)],
        )?;
    }
    Ok(id)
}

/// Every feed's state (start-up).
pub fn load_states(c: &Connection) -> rusqlite::Result<Vec<(String, FeedState)>> {
    let mut st = c.prepare("SELECT feed_id FROM feed_state")?;
    let ids: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    ids.into_iter()
        .map(|id| load_state(c, &id).map(|s| (id, s)))
        .collect()
}

pub fn ensure_state(c: &Connection, feed: &str) -> rusqlite::Result<()> {
    c.execute("INSERT OR IGNORE INTO feed_state(feed_id) VALUES (?1)", [feed])?;
    Ok(())
}

/// Sets one `feed_state` column of `feed`, creating the feed's row first. `column` is one of this
/// module's literals, never input.
fn set_state_column(
    c: &Connection,
    feed: &str,
    column: &'static str,
    value: impl rusqlite::ToSql,
) -> rusqlite::Result<()> {
    ensure_state(c, feed)?;
    c.execute(
        &format!("UPDATE feed_state SET {column} = ?2 WHERE feed_id = ?1"),
        params![feed, value],
    )?;
    Ok(())
}

/// A new generation id for `key` from `feed_run_ids`, whose AUTOINCREMENT never hands out an id
/// twice; the id row is deleted at once, only the sequence moves ([`new_source_gen`]).
fn next_generation(c: &Connection, key: &str) -> rusqlite::Result<i64> {
    c.execute(
        "INSERT INTO feed_run_ids(feed_id, at) VALUES (?1, ?2)",
        params![key, crate::util::now_ts()],
    )?;
    let g = c.last_insert_rowid();
    c.execute("DELETE FROM feed_run_ids WHERE id = ?1", [g])?;
    Ok(g)
}

pub fn set_last(c: &Connection, feed: &str, last: Option<&LastRun>) -> rusqlite::Result<()> {
    let j = last.and_then(|l| serde_json::to_string(l).ok());
    set_state_column(c, feed, "last_json", j)
}

/// A feed's source as stored, with its source generation: a check compares it with the
/// definitions it runs (the feed's provider and file, the provider's module and config).
#[derive(Clone, Debug, PartialEq)]
pub struct StoredSource {
    pub source_gen: Option<i64>,
    pub provider: Option<String>,
    pub file: Option<String>,
}

/// The feed's [`StoredSource`], read in one statement so the source and its generation agree;
/// `None` when the feed doesn't exist.
pub fn stored_source(c: &Connection, feed: &str) -> rusqlite::Result<Option<StoredSource>> {
    c.query_row(
        "SELECT s.source_gen, f.provider_id, f.file
         FROM feeds f LEFT JOIN feed_state s ON s.feed_id = f.id WHERE f.id = ?1",
        [feed],
        |r| {
            Ok(StoredSource {
                source_gen: r.get(0)?,
                provider: r.get(1)?,
                file: r.get(2)?,
            })
        },
    )
    .optional()
}

/// The feed's source generation (`None` for a feed stored before generations, or none yet).
pub fn source_gen(c: &Connection, feed: &str) -> rusqlite::Result<Option<i64>> {
    Ok(c.query_row(
        "SELECT source_gen FROM feed_state WHERE feed_id = ?1",
        [feed],
        |r| r.get(0),
    )
    .optional()?
    .flatten())
}

/// Gives the feed a new source generation (it was created, or its provider's `module` or
/// `config` changed), in the caller's transaction: an id from `feed_run_ids`, whose
/// AUTOINCREMENT never hands out an id twice, so a feed created again with a deleted feed's id
/// never has that feed's generation (its id row is deleted at once; only the sequence moves).
pub fn new_source_gen(c: &Connection, feed: &str) -> rusqlite::Result<i64> {
    let source_gen = next_generation(c, feed)?;
    set_state_column(c, feed, "source_gen", source_gen)?;
    Ok(source_gen)
}

/// True while `source_gen` is the feed's current source generation: the feed exists, no purge
/// of a deleted feed with its id waits, and neither a deletion nor an edit of its provider's
/// `module` or `config` happened since `source_gen` was read. Called inside the writer's
/// transaction by every check and run that stores what it observed of the source (`last`, check
/// history, a download's run), so the answer holds for the whole transaction (feeds.md §3
/// "Editing a feed"; storage.md §4: a feed created again starts clean).
pub fn source_current(c: &Connection, feed: &str, source_gen: Option<i64>) -> rusqlite::Result<bool> {
    c.query_row(
        "SELECT EXISTS (SELECT 1 FROM feeds WHERE id = ?1)
            AND NOT EXISTS (SELECT 1 FROM feed_purges WHERE feed_id = ?1)
            AND (SELECT source_gen FROM feed_state WHERE feed_id = ?1) IS ?2",
        params![feed, source_gen],
        |r| r.get(0),
    )
}

/// True while a purge of a deleted feed with this id waits (a run set up for the feed before the
/// deletion must not store anything).
pub fn purge_pending(c: &Connection, feed: &str) -> rusqlite::Result<bool> {
    c.query_row(
        "SELECT EXISTS (SELECT 1 FROM feed_purges WHERE feed_id = ?1)",
        [feed],
        |r| r.get(0),
    )
}

/// What an import into a provider feed was checked against (feeds.md §4: the same format,
/// `format_options` and MISP list `type`).
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImportBinding {
    pub format: crate::config::model::FeedFormat,
    pub format_options: crate::config::model::FormatOptions,
    /// The list `type` of the feed's applied run when the import was accepted.
    #[serde(default)]
    pub misp_type: Option<String>,
}

/// An accepted import into a provider feed, not yet stored as a run (`feed_imports`).
#[derive(Clone, Debug, PartialEq)]
pub struct PendingImport {
    pub id: i64,
    pub feed: String,
    pub blob: String,
    pub source_gen: Option<i64>,
    pub binding: ImportBinding,
}

/// Records an accepted import, in the caller's transaction (with its blob's registration).
pub fn add_import(
    c: &Connection,
    feed: &str,
    blob: &str,
    source_gen: Option<i64>,
    binding: &ImportBinding,
) -> rusqlite::Result<i64> {
    c.execute(
        "INSERT INTO feed_imports(feed_id, blob, source_gen, params_json, at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            feed,
            blob,
            source_gen,
            serde_json::to_string(binding).unwrap_or_else(|_| "{}".into()),
            crate::util::now_ts()
        ],
    )?;
    Ok(c.last_insert_rowid())
}

fn row_to_import(r: &rusqlite::Row<'_>) -> rusqlite::Result<PendingImport> {
    Ok(PendingImport {
        id: r.get(0)?,
        feed: r.get(1)?,
        blob: r.get(2)?,
        source_gen: r.get(3)?,
        binding: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
    })
}

/// A pending import by id.
pub fn import_by_id(c: &Connection, id: i64) -> rusqlite::Result<Option<PendingImport>> {
    c.query_row(
        "SELECT id, feed_id, blob, source_gen, params_json FROM feed_imports WHERE id = ?1",
        [id],
        row_to_import,
    )
    .optional()
}

/// The feed's oldest pending import (imports run in the order they were accepted).
pub fn oldest_import(c: &Connection, feed: &str) -> rusqlite::Result<Option<PendingImport>> {
    c.query_row(
        "SELECT id, feed_id, blob, source_gen, params_json FROM feed_imports WHERE feed_id = ?1 ORDER BY id LIMIT 1",
        [feed],
        row_to_import,
    )
    .optional()
}

/// The feeds with pending imports (start-up).
pub fn feeds_with_imports(c: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut st = c.prepare("SELECT DISTINCT feed_id FROM feed_imports ORDER BY feed_id")?;
    st.query_map([], |r| r.get(0))?.collect()
}

/// A pending import's counts: its attempts (runs started and refusals of its run by the heavy
/// lane, together the bound) and the refusals alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportAttempts {
    pub attempts: i64,
    pub refused: i64,
}

impl ImportAttempts {
    /// The runs of it that started (and didn't store their run).
    pub fn started(&self) -> i64 {
        (self.attempts - self.refused).max(0)
    }
}

/// Counts an attempt of the pending import `id` of `feed` at `source_gen` (a run started, or
/// `refused` by the heavy lane); returns its counts with this one, or `None` when no such record
/// is left (it was stored or dropped, or is another feed's).
pub fn import_attempt(
    c: &Connection,
    id: i64,
    feed: &str,
    source_gen: Option<i64>,
    refused: bool,
) -> rusqlite::Result<Option<ImportAttempts>> {
    c.query_row(
        "UPDATE feed_imports SET attempts = attempts + 1, refused = refused + ?4
         WHERE id = ?1 AND feed_id = ?2 AND source_gen IS ?3 RETURNING attempts, refused",
        params![id, feed, source_gen, i64::from(refused)],
        |r| {
            Ok(ImportAttempts {
                attempts: r.get(0)?,
                refused: r.get(1)?,
            })
        },
    )
    .optional()
}

/// The list `type` of the feed's latest applied run (feeds.md §3, §4).
pub fn applied_misp_type(c: &Connection, feed: &str) -> rusqlite::Result<Option<String>> {
    Ok(one_run(c, "status = 'applied'", feed)?.and_then(|r| r.parse.and_then(|p| p.misp_type)))
}

/// Deletes the pending import `id` of `feed` accepted at `source_gen`, and nothing else: a job
/// that outlived its feed never removes another feed's import (ids are never reused either).
pub fn delete_import(c: &Connection, id: i64, feed: &str, source_gen: Option<i64>) -> rusqlite::Result<()> {
    c.execute(
        "DELETE FROM feed_imports WHERE id = ?1 AND feed_id = ?2 AND source_gen IS ?3",
        params![id, feed, source_gen],
    )?;
    Ok(())
}

pub fn set_next_check(c: &Connection, feed: &str, next: Option<Timestamp>) -> rusqlite::Result<()> {
    set_state_column(c, feed, "next_check_at", next.as_ref().map(ts))
}

pub fn set_held_since(c: &Connection, feed: &str, at: Option<Timestamp>) -> rusqlite::Result<()> {
    set_state_column(c, feed, "held_since", at.as_ref().map(ts))
}

pub fn set_download(
    c: &Connection,
    feed: &str,
    at: Timestamp,
    expires_s: Option<u64>,
) -> rusqlite::Result<()> {
    ensure_state(c, feed)?;
    c.execute(
        "UPDATE feed_state SET last_download_at = ?2, expires_s = ?3 WHERE feed_id = ?1",
        params![feed, ts(&at), expires_s.map(crate::util::sat_i64)],
    )?;
    Ok(())
}

/// A check's record (`feed_checks`) and what it changes in `feed_state`.
#[derive(Clone, Debug)]
pub struct CheckRecord {
    pub feed: String,
    pub at: Timestamp,
    pub duration_ms: u64,
    pub method: String,
    pub ok: bool,
    pub changed: bool,
    pub bytes: u64,
    pub version: Option<String>,
    pub predicted_rate: Option<f64>,
    pub error: Option<String>,
    /// Change times to record (`feed_changes`), already checked against this check's interval.
    pub changes: Vec<ChangeTime>,
    pub origin: &'static str,
    /// The provider check it was part of (`feed_provider_checks`; none for warm-start rows and
    /// manual feeds' saves).
    pub provider_check_id: Option<i64>,
}

/// Inserts the check (and its changes) and updates the streak and times in `feed_state`.
/// Returns the check's id.
pub fn record_check(c: &Connection, r: &CheckRecord) -> rusqlite::Result<i64> {
    ensure_state(c, &r.feed)?;
    c.execute(
        "INSERT INTO feed_checks(feed_id, t, duration_ms, method, ok, changed, bytes, ref, predicted_rate, error, provider_check_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            r.feed,
            ts(&r.at),
            crate::util::sat_i64(r.duration_ms),
            r.method,
            r.ok as i64,
            r.changed as i64,
            crate::util::sat_i64(r.bytes),
            r.version,
            r.predicted_rate,
            r.error,
            r.provider_check_id
        ],
    )?;
    let id = c.last_insert_rowid();
    for ch in &r.changes {
        let (t_change, exact, t_lo) = match ch {
            ChangeTime::Exact(t) => (Some(ts(t)), 1i64, None),
            ChangeTime::Interval { lo, .. } => (None, 0i64, Some(ts(lo))),
        };
        c.execute(
            "INSERT INTO feed_changes(feed_id, check_id, t_change, exact, t_lo, t_seen, origin) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![r.feed, id, t_change, exact, t_lo, ts(&r.at), r.origin],
        )?;
    }
    if r.ok {
        c.execute(
            "UPDATE feed_state SET last_check_at = ?2, last_ok_at = ?2, failures = 0, failing_since = NULL WHERE feed_id = ?1",
            params![r.feed, ts(&r.at)],
        )?;
    } else {
        c.execute(
            "UPDATE feed_state SET last_check_at = ?2, failures = failures + 1, failing_since = coalesce(failing_since, ?2)
             WHERE feed_id = ?1",
            params![r.feed, ts(&r.at)],
        )?;
    }
    Ok(id)
}

/// One stored run.
#[derive(Clone, Debug, Default, Serialize, schemars::JsonSchema)]
pub struct RunRow {
    pub id: i64,
    pub feed_id: String,
    pub version: Option<String>,
    pub updated_at: Option<String>,
    pub downloaded_at: Option<String>,
    pub confirmed_at: Option<String>,
    pub blob: Option<String>,
    pub status: Option<RunStatus>,
    pub kind: Option<RunKind>,
    pub added: TypeCounts,
    pub removed: TypeCounts,
    pub total: TypeCounts,
    pub policy_dropped: PolicyCounts,
    pub error: Option<String>,
    pub gate: Option<String>,
    /// For a run that applied a held or rejected download (a confirmation or a re-gate): the id
    /// that download had while it waited.
    pub source_run: Option<i64>,
    #[serde(skip)]
    pub params: Option<IngestParams>,
    pub parse: Option<ParseSummary>,
}

pub const RUN_COLUMNS: &str =
    "id, feed_id, version, updated_at, downloaded_at, confirmed_at, blob, status, added_json, removed_json,
     total_json, policy_dropped_json, error, kind, params_json, parse_json, gate, source_run";

fn json_or_default<T: serde::de::DeserializeOwned + Default>(s: Option<String>) -> T {
    s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn row_to_run(r: &rusqlite::Row<'_>) -> rusqlite::Result<RunRow> {
    Ok(RunRow {
        id: r.get(0)?,
        feed_id: r.get(1)?,
        version: r.get(2)?,
        updated_at: r.get(3)?,
        downloaded_at: r.get(4)?,
        confirmed_at: r.get(5)?,
        blob: r.get(6)?,
        status: r.get::<_, Option<String>>(7)?.map(|s| RunStatus::parse(&s)),
        added: json_or_default(r.get(8)?),
        removed: json_or_default(r.get(9)?),
        total: json_or_default(r.get(10)?),
        policy_dropped: json_or_default(r.get(11)?),
        error: r.get(12)?,
        kind: r.get::<_, Option<String>>(13)?.map(|s| RunKind::parse(&s)),
        params: r
            .get::<_, Option<String>>(14)?
            .and_then(|s| serde_json::from_str(&s).ok()),
        parse: r
            .get::<_, Option<String>>(15)?
            .and_then(|s| serde_json::from_str(&s).ok()),
        gate: r.get(16)?,
        source_run: r.get(17)?,
    })
}

fn one_run(c: &Connection, where_: &str, feed: &str) -> rusqlite::Result<Option<RunRow>> {
    c.query_row(
        &format!(
            "SELECT {RUN_COLUMNS} FROM feed_runs WHERE feed_id = ?1 AND {where_} ORDER BY id DESC LIMIT 1"
        ),
        [feed],
        row_to_run,
    )
    .optional()
}

pub fn run_by_id(c: &Connection, id: i64) -> rusqlite::Result<Option<RunRow>> {
    c.query_row(
        &format!("SELECT {RUN_COLUMNS} FROM feed_runs WHERE id = ?1"),
        [id],
        row_to_run,
    )
    .optional()
}

/// The newest downloaded run (never a sweep or a re-ingest): the run a held or rejected state
/// belongs to (feeds.md §3 step 2, §5; a download supersedes a waiting held run).
pub fn newest_download(c: &Connection, feed: &str) -> rusqlite::Result<Option<RunRow>> {
    one_run(c, "coalesce(kind, 'download') = 'download'", feed)
}

/// The newest run (a download or a re-ingest, never a sweep) that read what a check observed:
/// the same blob (a full download identical to a stored one) or the same provider version (an
/// `Unchanged` reply against `last`). This is the run an unchanged check confirms (feeds.md §3
/// step 2, §5).
pub fn newest_matching(
    c: &Connection,
    feed: &str,
    blob: Option<&str>,
    version: Option<&str>,
) -> rusqlite::Result<Option<RunRow>> {
    if blob.is_none() && version.is_none() {
        return Ok(None);
    }
    c.query_row(
        &format!(
            "SELECT {RUN_COLUMNS} FROM feed_runs WHERE feed_id = ?1 AND blob IS NOT NULL
               AND coalesce(kind, 'download') NOT IN ('expire', 'import')
               AND ((?2 IS NOT NULL AND blob = ?2) OR (?3 IS NOT NULL AND version = ?3))
             ORDER BY id DESC LIMIT 1"
        ),
        params![feed, blob, version],
        row_to_run,
    )
    .optional()
}

/// The newest source run that has a blob (a download or a re-ingest of any status; never an
/// import).
pub fn newest_with_blob(c: &Connection, feed: &str) -> rusqlite::Result<Option<RunRow>> {
    one_run(
        c,
        "blob IS NOT NULL AND coalesce(kind, 'download') <> 'import'",
        feed,
    )
}

/// The latest applied source run with a blob (what a re-ingest reads: a download's or a save's
/// blob, or a re-ingest of either; never an import's, feeds.md §3).
pub fn latest_applied_blob(c: &Connection, feed: &str) -> rusqlite::Result<Option<RunRow>> {
    one_run(
        c,
        "status = 'applied' AND blob IS NOT NULL AND coalesce(kind, 'download') <> 'import'",
        feed,
    )
}

/// The latest applied source run (feeds.md §5: the change ratio's previous total; never an
/// import's or a sweep's).
pub fn latest_applied_source(c: &Connection, feed: &str) -> rusqlite::Result<Option<RunRow>> {
    one_run(
        c,
        "status = 'applied' AND coalesce(kind, 'download') IN ('download', 'reingest')",
        feed,
    )
}

/// The newest run that changed entries (applied or expired).
pub fn latest_change(c: &Connection, feed: &str) -> rusqlite::Result<Option<RunRow>> {
    one_run(c, "status IN ('applied', 'expired')", feed)
}

/// True when the feed has an applied source run (until then the change-ratio gate is skipped;
/// an import doesn't count, feeds.md §5).
pub fn has_applied(c: &Connection, feed: &str) -> rusqlite::Result<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM feed_runs WHERE feed_id = ?1 AND status = 'applied'
           AND coalesce(kind, 'download') IN ('download', 'reingest') LIMIT 1",
        [feed],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

/// Sets `confirmed_at` on a run (a check found the source unchanged since it).
pub fn confirm_run(c: &Connection, run: i64, at: Timestamp) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE feed_runs SET confirmed_at = ?2 WHERE id = ?1",
        params![run, ts(&at)],
    )?;
    Ok(())
}

/// Open entries per rule type.
pub fn open_totals(c: &Connection, feed: &str) -> rusqlite::Result<TypeCounts> {
    let mut st = c.prepare_cached(
        "SELECT rule_type, count(*) FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NULL GROUP BY rule_type",
    )?;
    let mut out = TypeCounts::default();
    let rows = st.query_map([feed], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows {
        let (t, n) = row?;
        if let Some(t) = picket_rules::RuleType::parse(&t) {
            out.add(t, crate::util::nonneg(n));
        }
    }
    Ok(out)
}

/// The pause after a `RateLimited` reply, per module (providers.md §2).
pub fn load_pauses(c: &Connection) -> rusqlite::Result<Vec<(String, Timestamp)>> {
    let mut st = c.prepare("SELECT module, until FROM module_pauses")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (p, u) = row?;
        if let Some(u) = parse_ts(&u) {
            out.push((p, u));
        }
    }
    Ok(out)
}

pub fn set_pause(c: &Connection, module: &str, until: Timestamp) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO module_pauses(module, until) VALUES (?1, ?2)
         ON CONFLICT(module) DO UPDATE SET until = max(until, excluded.until)",
        params![module, ts(&until)],
    )?;
    Ok(())
}

/// Bundles a feed is a member of.
pub fn bundles_of(c: &Connection, feed: &str) -> rusqlite::Result<Vec<String>> {
    let mut st =
        c.prepare_cached("SELECT bundle_id FROM bundle_feeds WHERE feed_id = ?1 ORDER BY bundle_id")?;
    st.query_map([feed], |r| r.get(0))?.collect()
}

/// A manual feed's current file (`manual_files`): blob, version, save time.
pub fn manual_file(c: &Connection, feed: &str) -> rusqlite::Result<Option<(String, String, Timestamp)>> {
    c.query_row(
        "SELECT blob, version, saved_at FROM manual_files WHERE feed_id = ?1",
        [feed],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        },
    )
    .optional()
    .map(|o| o.map(|(b, v, s)| (b, v, parse_ts(&s).unwrap_or_else(Timestamp::now))))
}
