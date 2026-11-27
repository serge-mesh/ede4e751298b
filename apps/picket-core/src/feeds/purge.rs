//! Retiring a deleted feed's data (storage.md §4; feeds.md §5 "skipped on a feed's first run"),
//! so a feed created again with the same id (a preset installed again, a restore) starts clean.
//!
//! Deleting a feed writes, in the same transaction, a `feed_purges` row with a new run id *D*
//! from `feed_run_ids` (newer than every run of the deleted feed). This heavy job then:
//!
//! 1. closes every open entry of the feed older than *D* (`first_run < D`; a feed created again
//!    later has newer ids and is never touched) under *D* (`removed_run = D`), a few ≈ 50k-row chunks
//!    per step, so the partial unique index on open rows admits the new feed's entries and the
//!    new feed's diffs, gates and totals see none of the old ones. Closed, not deleted: a
//!    retained bundle version that records an old run *r* still replays the rows open at *r*
//!    (`first_run ≤ r < removed_run`), and retention deletes them once no version needs them;
//! 2. in one transaction, moves the deleted feed's runs to a tombstone feed id (`<id>#<D>`, `#`
//!    is never in a feed id), so "the feed's first run", the latest applied blob, a held run and
//!    the newest download of the new feed are its own; deletes its policy drops, check history
//!    and scheduler state; and forgets the purge.
//!
//! The feed id stays busy from the deletion until the purge is done: a feed created again
//! meanwhile waits (its checks and runs queue behind the purge), so it never sees a partly
//! retired set. A check or run of the deleted feed still in flight at the deletion stores nothing
//! (its source generation is gone, and a purge waits: `feeds::store::source_current`, the
//! ingest's setup and final transaction), so nothing of it survives the purge either. The purge is durable: a stop resumes it at the next start. Closing is
//! idempotent, so a purge interrupted between chunks just continues.

use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::db::CHUNK_ROWS;
use crate::scheduler::{BoxFuture, HeavyJob, Step};
use crate::state::SharedState;

/// Chunks per purge step (a P0 delta runs between steps, core.md §3).
const CHUNKS_PER_STEP: usize = 4;

/// The feed ids with a purge waiting, and its run id.
pub async fn pending(db: &crate::db::Db) -> Result<Vec<(String, i64)>> {
    db.read(|c| {
        let mut st = c.prepare("SELECT feed_id, run_id FROM feed_purges ORDER BY feed_id")?;
        let v = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, anyhow::Error>(v)
    })
    .await
}

/// Records, in the transaction that deletes `feed`, that its data must be retired.
pub fn schedule_in(tx: &rusqlite::Transaction<'_>, feed: &str) -> rusqlite::Result<()> {
    let now = crate::util::now_ts();
    tx.execute(
        "INSERT INTO feed_run_ids(feed_id, at) VALUES (?1, ?2)",
        params![feed, now],
    )?;
    let run = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO feed_purges(feed_id, run_id, at) VALUES (?1, ?2, ?3)
         ON CONFLICT(feed_id) DO UPDATE SET run_id = max(run_id, excluded.run_id), at = excluded.at",
        params![feed, run, now],
    )?;
    Ok(())
}

/// The purge of one deleted feed's data; it holds the feed id busy and frees it when done.
pub struct PurgeJob {
    state: SharedState,
    feed: String,
    run: i64,
    done: bool,
}

/// How long a failed purge waits before it is tried again (the feed id stays busy meanwhile).
const RETRY: std::time::Duration = std::time::Duration::from_secs(60);

impl PurgeJob {
    pub fn new(state: SharedState, feed: &str, run: i64) -> Self {
        Self {
            state,
            feed: feed.to_string(),
            run,
            done: false,
        }
    }

    /// Closes up to [`CHUNKS_PER_STEP`] chunks of the feed's open entries; `Ok(true)` when none
    /// is left.
    async fn close_step(&self) -> Result<bool> {
        for _ in 0..CHUNKS_PER_STEP {
            let (feed, run) = (self.feed.clone(), self.run);
            let n = self
                .state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    let n = tx.execute(
                        "UPDATE feed_entries SET removed_run = ?2 WHERE id IN
                           (SELECT id FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NULL AND first_run < ?2 LIMIT ?3)",
                        params![feed, run, CHUNK_ROWS],
                    )?;
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(n)
                })
                .await?;
            if n < CHUNK_ROWS {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The final transaction: runs to the tombstone, the rest of the feed's data, the purge row.
    async fn finish(&self) -> Result<()> {
        let (feed, run) = (self.feed.clone(), self.run);
        let tomb = super::retention::tombstone(&feed, run);
        self.state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "UPDATE feed_runs SET feed_id = ?2 WHERE feed_id = ?1 AND id < ?3",
                    params![feed, tomb, run],
                )?;
                // Only what the deleted feed left (a feed created again later is never touched).
                let at: Option<String> = tx
                    .query_row(
                        "SELECT at FROM feed_purges WHERE feed_id = ?1 AND run_id = ?2",
                        params![feed, run],
                        |r| r.get(0),
                    )
                    .optional()?;
                tx.execute(
                    "DELETE FROM policy_drops WHERE feed_id = ?1 AND first_run < ?2",
                    params![feed, run],
                )?;
                if let Some(at) = &at {
                    tx.execute(
                        "DELETE FROM feed_checks WHERE feed_id = ?1 AND t < ?2",
                        params![feed, at],
                    )?;
                    tx.execute(
                        "DELETE FROM feed_changes WHERE feed_id = ?1 AND t_seen < ?2",
                        params![feed, at],
                    )?;
                }
                // The deletion deleted the feed's state; a row now is the new feed's (its source
                // generation is newer than D: checks and runs of the deleted feed store nothing
                // once it is deleted, `feeds::store::source_current`). Anything else goes.
                tx.execute(
                    "DELETE FROM feed_state WHERE feed_id = ?1 AND coalesce(source_gen, 0) < ?2",
                    params![feed, run],
                )?;
                tx.execute(
                    "DELETE FROM feed_purges WHERE feed_id = ?1 AND run_id = ?2",
                    params![feed, run],
                )?;
                tx.execute("DELETE FROM feed_run_ids WHERE id = ?1", [run])?;
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await
    }
}

impl Drop for PurgeJob {
    fn drop(&mut self) {
        let (state, feed, run, done) = (
            self.state.clone(),
            std::mem::take(&mut self.feed),
            self.run,
            self.done,
        );
        let Ok(h) = tokio::runtime::Handle::try_current() else {
            return; // shutting down: the next start resumes the purge
        };
        h.spawn(async move {
            if done {
                state.feeds.purge_done(&state, &feed);
                // The bundles naming the id read it at the purge from now on (its old entries
                // closed): they build again (bundles.md §2; `compiler::spec::snapshot`).
                if let Ok(model) = state.config.model().await {
                    let bundles: Vec<String> = model
                        .bundles
                        .values()
                        .filter(|b| b.feeds.iter().any(|f| f.feed == feed))
                        .map(|b| b.id.clone())
                        .collect();
                    if !bundles.is_empty() {
                        state.feeds.dirty().mark(&bundles, &feed);
                    }
                }
                return;
            }
            // Failed (or dropped by a full queue): the feed id stays busy and the purge is tried
            // again, never skipped (a feed created again must not inherit a partial set).
            tokio::select! {
                _ = state.shutdown.cancelled() => {}
                _ = tokio::time::sleep(RETRY) => super::queue_purge(&state, &feed, run),
            }
        });
    }
}

impl HeavyJob for PurgeJob {
    fn kind(&self) -> &str {
        "feed_purge"
    }

    fn target(&self) -> &str {
        &self.feed
    }

    fn step(&mut self) -> BoxFuture<'_, Result<Step>> {
        Box::pin(async move {
            if !self.close_step().await? {
                return Ok(Step::More);
            }
            self.finish().await?;
            self.done = true;
            tracing::info!(feed = %self.feed, run = self.run, "retired a deleted feed's data");
            Ok(Step::Done)
        })
    }
}
