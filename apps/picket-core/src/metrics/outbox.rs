//! Metric increments committed with the effects that produced them (README §2 Restarts;
//! build-and-test.md §5: "a restart mid-batch loses nothing and duplicates nothing").
//!
//! Log analysis and retro-match commit their alert effects and progress in one `core.db`
//! transaction; their metric increments (`feed_hits`, `trial_would_block`, `wire_mismatch`,
//! `cold_missed_blocks`, `retro_hits`, core.md §10) go into `core.db`'s `metric_outbox` in that
//! same transaction ([`queue_in`]). [`flush`] then moves them to `metrics.db` in id order: one
//! `metrics.db` transaction writes the points and the last outbox id applied
//! (`outbox_applied`), and only then are the rows deleted from `core.db`. A stop between the two
//! commits leaves rows the next flush recognises as applied, so each increment counts once.
//!
//! - **Restores** (core.md §2: the old state until a restore completes, then only the new one): a
//!   flush takes the restore generation ([`crate::config::export::RestoreGate`]) before it reads
//!   the outbox and writes `metrics.db` only while it is current, inside that write; a restore
//!   bumps it right after its commit (which empties the outbox) and before it empties
//!   `metrics.db`, so increments read before a restore never land in the restored metrics.
//! - **Bounded** (README §2): a row holds one batch's increments summed per series and
//!   `metrics.db` bin; while `metrics.db` can't take them the outbox keeps at most
//!   [`MAX_ROWS`] rows and [`MAX_BYTES`] bytes, none older than [`MAX_AGE_MS`]: past that the
//!   oldest go, counted (`analysis_skipped{work="metric_outbox"}`, itself queued, and logged).
//!   Age is a wall-clock decision (README §2 Clocks): a row queued before the clock is
//!   synchronised has no queue time (0) and the age bound waits for the clock; the first queue
//!   after it stamps those rows, so their age counts from then (a boot clock far behind never
//!   makes them look a week old, nor one far ahead new).

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Transaction, params};

use super::Labels;
use crate::state::AppState;

/// One increment: (series, labels, event time in Unix ms, n).
pub type Item = (String, Labels, i64, f64);

/// Outbox rows one flush moves (each holds one batch's increments).
const FLUSH_ROWS: i64 = 256;
/// The `outbox_applied.source` of core.db's outbox.
const SOURCE: &str = "core";
/// Rows the outbox keeps at most (README §2 Bounded). A policy choice: about five hours of a
/// busy instance's batches with `metrics.db` refusing every write.
pub const MAX_ROWS: i64 = 10_000;
/// Bytes of increments the outbox keeps at most.
pub const MAX_BYTES: i64 = 32 * 1024 * 1024;
/// The oldest row the outbox keeps: an outbox that hasn't moved for a week means `metrics.db`
/// can't take writes; its oldest increments give way.
pub const MAX_AGE_MS: i64 = 7 * 24 * 3600 * 1000;

/// Queues `items` in core.db transaction `tx`, with the effects that produced them: summed per
/// series and `metrics.db` bin (as the flush bins them), then the outbox's bounds kept (the age
/// bound only once `clock` is synchronised, module docs).
pub fn queue_in(tx: &Transaction<'_>, items: &[Item], clock: &crate::clock::Clock) -> rusqlite::Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let mut summed: BTreeMap<(String, String, i64), (Labels, f64)> = BTreeMap::new();
    for (name, l, ts, v) in items {
        let bin = ts - ts.rem_euclid(super::store::CORE_BIN_MS);
        let lk = serde_json::to_string(l).unwrap_or_default();
        summed
            .entry((name.clone(), lk, bin))
            .or_insert_with(|| (l.clone(), 0.0))
            .1 += v;
    }
    let rows: Vec<Item> = summed
        .into_iter()
        .map(|((name, _, bin), (l, v))| (name, l, bin, v))
        .collect();
    let j = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into());
    // README §2 Clocks: the queue time only from a synchronised clock (0: none yet).
    let now = clock.synced().then(|| jiff::Timestamp::now().as_millisecond());
    tx.prepare_cached("INSERT INTO metric_outbox(bytes, queued_at, items_json) VALUES (?1, ?2, ?3)")?
        .execute(params![j.len(), now.unwrap_or(0), j])?;
    bound_in(tx, now)
}

/// Keeps the outbox within [`MAX_ROWS`], [`MAX_BYTES`] and [`MAX_AGE_MS`], dropping the oldest
/// rows and counting them in one more row (room for which is kept). Every queue checks all three
/// bounds, however few rows the outbox holds (one aggregate over at most [`MAX_ROWS`] rows, a
/// single row while `metrics.db` takes the increments); rows go only when one is passed. `now`:
/// the wall-clock time once synchronised (README §2 Clocks), else none: then rows have no age, and
/// the first call with a time stamps the rows queued without one.
fn bound_in(tx: &Transaction<'_>, now: Option<i64>) -> rusqlite::Result<()> {
    let (n, bytes, lo, oldest_at, unstamped): (i64, i64, Option<i64>, Option<i64>, i64) = tx
        .prepare_cached(
            "SELECT count(*), coalesce(sum(bytes), 0), min(id), min(CASE WHEN queued_at > 0 THEN queued_at END),
                    count(CASE WHEN queued_at <= 0 THEN 1 END)
             FROM metric_outbox",
        )?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
    let Some(lo) = lo else {
        return Ok(());
    };
    if let Some(now) = now
        && unstamped > 0
    {
        // Queued before the clock was synchronised: their age counts from now.
        tx.prepare_cached("UPDATE metric_outbox SET queued_at = ?1 WHERE queued_at <= 0")?
            .execute([now])?;
    }
    // Without a synchronised clock no row is too old (`i64::MIN`: none queued before it).
    let stale = now.map_or(i64::MIN, |now| now.saturating_sub(MAX_AGE_MS));
    if n <= MAX_ROWS && bytes <= MAX_BYTES && oldest_at.is_none_or(|t| t >= stale) {
        return Ok(());
    }
    // Rows go: the newest that fit every bound stay, leaving room for the row that counts them.
    let counted = |dropped: usize| {
        let item = crate::logs::analysis::skipped_item("metric_outbox", dropped);
        serde_json::to_string(&[item]).unwrap_or_else(|_| "[]".into())
    };
    let reserve = crate::util::sat_i64(counted(usize::MAX).len());
    // Rows: the newest MAX_ROWS − 1.
    let mut cut: i64 = tx
        .prepare_cached("SELECT id FROM metric_outbox ORDER BY id DESC LIMIT 1 OFFSET ?1")?
        .query_row([MAX_ROWS - 2], |r| r.get(0))
        .optional()?
        .unwrap_or(lo);
    // Age: none queued before `stale`.
    let old: Option<i64> = tx
        .prepare_cached(
            "SELECT id FROM metric_outbox WHERE id >= ?1 AND queued_at > 0 AND queued_at < ?2 ORDER BY id DESC LIMIT 1",
        )?
        .query_row(params![cut, stale], |r| r.get(0))
        .optional()?;
    if let Some(id) = old {
        cut = cut.max(id + 1);
    }
    {
        // Bytes: the newest rows that fit MAX_BYTES with the counting row.
        let mut st =
            tx.prepare_cached("SELECT id, bytes FROM metric_outbox WHERE id >= ?1 ORDER BY id DESC")?;
        let mut rows = st.query([cut])?;
        let mut total = reserve;
        while let Some(r) = rows.next()? {
            let (id, b): (i64, i64) = (r.get(0)?, r.get(1)?);
            total = total.saturating_add(b);
            if total > MAX_BYTES {
                cut = cut.max(id + 1);
                break;
            }
        }
    }
    if cut <= lo {
        return Ok(());
    }
    let dropped = tx.execute("DELETE FROM metric_outbox WHERE id < ?1", [cut])?;
    if dropped > 0 {
        tracing::warn!(
            rows = dropped,
            "queued metric increments dropped: metrics.db hasn't taken them"
        );
        let j = counted(dropped);
        tx.prepare_cached("INSERT INTO metric_outbox(bytes, queued_at, items_json) VALUES (?1, ?2, ?3)")?
            .execute(params![j.len(), now.unwrap_or(0), j])?;
    }
    Ok(())
}

/// Moves queued increments to metrics.db, oldest first, until the outbox is empty (each round
/// at most [`FLUSH_ROWS`] rows). Returns the rows moved.
pub async fn flush(state: &AppState) -> anyhow::Result<usize> {
    let mut moved = 0usize;
    loop {
        // Taken before the outbox is read: a restore after it makes this round write nothing.
        let generation = state.restore.generation();
        let rows: Vec<(i64, String)> = state
            .db
            .read(|c| {
                let mut st =
                    c.prepare_cached("SELECT id, items_json FROM metric_outbox ORDER BY id LIMIT ?1")?;
                let v = st
                    .query_map([FLUSH_ROWS], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await?;
        let Some(last) = rows.last().map(|r| r.0) else {
            return Ok(moved);
        };
        let n = rows.len();
        state
            .analysis
            .paused_at(crate::logs::analysis::FailPoint::OutboxAfterRead)
            .await;
        let cache = state.metrics.series.clone();
        let gate = state.restore.clone();
        let applied: Option<Vec<Item>> = state
            .metrics_db
            .write(move |c| {
                if !gate.is_current(generation) {
                    return Ok(None);
                }
                let tx = c.transaction()?;
                let done: i64 = tx.query_row(
                    "SELECT coalesce((SELECT last_id FROM outbox_applied WHERE source = ?1), 0)",
                    [SOURCE],
                    |r| r.get(0),
                )?;
                let mut binned: std::collections::HashMap<(String, Labels, i64), f64> =
                    std::collections::HashMap::new();
                let mut applied: Vec<Item> = Vec::new();
                for (id, j) in &rows {
                    if *id <= done {
                        continue;
                    }
                    let items: Vec<Item> = serde_json::from_str(j).unwrap_or_default();
                    for (name, l, ts, v) in items {
                        let bin = ts - ts.rem_euclid(super::store::CORE_BIN_MS);
                        *binned.entry((name.clone(), l.clone(), bin)).or_insert(0.0) += v;
                        applied.push((name, l, ts, v));
                    }
                }
                let mut pending = super::store::Pending::default();
                for ((name, l, ts), v) in &binned {
                    if let Some(id) = cache.resolve(&tx, name, l, false, &mut pending)? {
                        tx.prepare_cached("INSERT INTO points(series_id, ts, value) VALUES (?1, ?2, ?3)")?
                            .execute(params![id, ts, v])?;
                    }
                }
                tx.execute(
                    "INSERT INTO outbox_applied(source, last_id) VALUES (?1, ?2)
                     ON CONFLICT(source) DO UPDATE SET last_id = max(last_id, excluded.last_id)",
                    params![SOURCE, last],
                )?;
                tx.commit()?;
                cache.publish(pending);
                Ok::<_, anyhow::Error>(Some(applied))
            })
            .await?;
        // A restore came between: what was read is gone with the old state.
        let Some(applied) = applied else {
            return Ok(moved);
        };
        // The export's totals (core.md §10) count what this process applied.
        for (name, l, _, v) in applied {
            state.metrics.counters.add(&name, l, v);
        }
        if state
            .analysis
            .failing(crate::logs::analysis::FailPoint::OutboxAfterMetrics)
        {
            anyhow::bail!("stopped between the metrics and the outbox (test)");
        }
        let gate = state.restore.clone();
        state
            .db
            .write(move |c| {
                if gate.is_current(generation) {
                    c.execute("DELETE FROM metric_outbox WHERE id <= ?1", [last])?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        moved += n;
        if crate::util::sat_i64(n) < FLUSH_ROWS {
            return Ok(moved);
        }
    }
}
