//! Reverting a run that didn't finish (feeds.md §3 step 4): each chunk of a run's diff journals,
//! in its own transaction and under the run's id, the prior `last_seen_run`, `last_seen_at`,
//! `first_seen_at` and `dropped_at` of the `feed_entries` rows it changes (`feed_entry_undo`).
//! A run that writes entries is *open* (`feed_runs_open`) until the transaction that makes its
//! `feed_runs` row final, which also deletes its journal.
//!
//! At start (and when a run's job fails), each open run is undone: rows it inserted
//! (`first_run`) are deleted, rows it closed (`removed_run`) reopened, and journaled rows get
//! their prior values back, in bounded chunks. The applied set is then exactly what the last
//! finished run left: never a partial one.
//!
//! - **Only open runs:** every undo transaction first checks, inside the writer, that the run is
//!   still listed open. A job cancelled while its final transaction was already queued (shutdown)
//!   commits that transaction first (the writer runs in order), and the undo then finds the run
//!   finished and changes nothing (README §2 Restarts: a committed run is never undone).
//! - **In the heavy lane:** a failed job's undo runs as one heavy step ([`UndoJob`], P0), chunk
//!   after chunk, like the diff it reverts, so no other heavy job (a bundle build, retention)
//!   sees a half-undone set (core.md §3). It is admitted to the lane's reserved places when the
//!   queue is full, and never runs outside the lane. The feed stays busy until the undo is done; an undo
//!   that fails is tried again a minute later, never skipped, because the next run of the feed
//!   would diff against a partial set.

use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

/// Rows per undo step.
const CHUNK: i64 = 20_000;

/// The runs left open (by a crash or a failed job).
pub async fn open_runs(db: &Db) -> Result<Vec<(i64, String)>> {
    db.read(|c| {
        let mut st = c.prepare("SELECT run_id, feed_id FROM feed_runs_open ORDER BY run_id")?;
        let v = st
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, anyhow::Error>(v)
    })
    .await
}

/// Undoes one open run's entry changes, chunk by chunk, then forgets it. `Ok(None)` when the
/// run isn't open (it finished): nothing is changed.
pub async fn undo_run(db: &Db, run: i64) -> Result<Option<UndoStats>> {
    let mut stats = UndoStats::default();
    loop {
        let n = db
            .write(move |c| {
                let tx = c.transaction()?;
                if !is_open(&tx, run)? {
                    return Ok::<_, anyhow::Error>(None);
                }
                let n = tx.execute(
                    "DELETE FROM feed_entries WHERE id IN (SELECT id FROM feed_entries WHERE first_run = ?1 LIMIT ?2)",
                    params![run, CHUNK],
                )?;
                tx.commit()?;
                Ok(Some(n))
            })
            .await?;
        let Some(n) = n else { return Ok(None) };
        stats.deleted += n as u64;
        if crate::util::sat_i64(n) < CHUNK {
            break;
        }
    }
    loop {
        let n = db
            .write(move |c| {
                let tx = c.transaction()?;
                if !is_open(&tx, run)? {
                    return Ok::<_, anyhow::Error>(None);
                }
                let n = tx.execute(
                    "UPDATE feed_entries SET removed_run = NULL WHERE id IN
                       (SELECT id FROM feed_entries WHERE removed_run = ?1 LIMIT ?2)",
                    params![run, CHUNK],
                )?;
                tx.commit()?;
                Ok(Some(n))
            })
            .await?;
        let Some(n) = n else { return Ok(None) };
        stats.reopened += n as u64;
        if crate::util::sat_i64(n) < CHUNK {
            break;
        }
    }
    loop {
        let n = db
            .write(move |c| {
                let tx = c.transaction()?;
                if !is_open(&tx, run)? {
                    return Ok::<_, anyhow::Error>(None);
                }
                let ids: Vec<(i64, String)> = {
                    let mut st = tx.prepare(
                        "SELECT entry_id, prior_json FROM feed_entry_undo WHERE run_id = ?1 LIMIT ?2",
                    )?;
                    st.query_map(params![run, CHUNK], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect::<rusqlite::Result<_>>()?
                };
                for (id, prior) in &ids {
                    tx.execute(
                        "UPDATE feed_entries SET last_seen_run = json_extract(?2, '$.last_seen_run'),
                            last_seen_at = json_extract(?2, '$.last_seen_at'),
                            first_seen_at = json_extract(?2, '$.first_seen_at'),
                            dropped_at = json_extract(?2, '$.dropped_at')
                         WHERE id = ?1",
                        params![id, prior],
                    )?;
                    tx.execute(
                        "DELETE FROM feed_entry_undo WHERE run_id = ?1 AND entry_id = ?2",
                        params![run, id],
                    )?;
                }
                tx.commit()?;
                Ok(Some(ids.len()))
            })
            .await?;
        let Some(n) = n else { return Ok(None) };
        stats.restored += n as u64;
        if crate::util::sat_i64(n) < CHUNK {
            break;
        }
    }
    let done = db
        .write(move |c| {
            let tx = c.transaction()?;
            if !is_open(&tx, run)? {
                return Ok::<_, anyhow::Error>(false);
            }
            // A run id that never got its row: forget the id too. A held or rejected run that was
            // being applied (under this new id) keeps its own row as it was.
            tx.execute("DELETE FROM feed_runs_open WHERE run_id = ?1", [run])?;
            tx.execute("DELETE FROM feed_run_ids WHERE id = ?1", [run])?;
            tx.commit()?;
            Ok(true)
        })
        .await?;
    Ok(done.then_some(stats))
}

/// What an undo changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UndoStats {
    pub deleted: u64,
    pub reopened: u64,
    pub restored: u64,
}

/// Undoes every open run (start-up, before any check or ingest runs).
pub async fn undo_open_runs(db: &Db) -> Result<usize> {
    let runs = open_runs(db).await?;
    for (run, feed) in &runs {
        if let Some(s) = undo_run(db, *run).await? {
            tracing::warn!(feed = %feed, run, deleted = s.deleted, reopened = s.reopened, restored = s.restored,
                "undid a feed run that didn't finish");
        }
    }
    Ok(runs.len())
}

/// How long a failed undo waits before it is tried again.
const RETRY: std::time::Duration = std::time::Duration::from_secs(60);
/// How long an undo the heavy lane refused (queue and reserve full) waits to ask again.
const ADMIT_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

/// The undo of a run whose job failed, was dropped or panicked: one heavy step (P0) that reverts
/// the run chunk after chunk, then frees the feed. Dropped without running (shutdown), it leaves
/// the run open for the next start.
pub struct UndoJob {
    state: crate::state::SharedState,
    feed: String,
    run: i64,
    /// Frees the feed when the job ends or is dropped, unless a retry took it over.
    release: bool,
}

impl UndoJob {
    pub fn new(state: crate::state::SharedState, feed: &str, run: i64) -> Self {
        Self {
            state,
            feed: feed.to_string(),
            run,
            release: true,
        }
    }

    /// Queues the undo in the heavy lane, in its reserved places when the queue is full
    /// ([`crate::scheduler::HeavyLane::try_submit_reserved`]): it always runs in the lane, never
    /// next to another heavy job (core.md §3). If even the reserve is full, admission is tried
    /// again every [`ADMIT_RETRY`] (the feed stays busy meanwhile); at shutdown (the lane closed)
    /// the run stays open for the next start.
    pub fn submit(self) {
        let state = self.state.clone();
        let Err(job) = state
            .scheduler
            .heavy
            .try_submit_reserved(crate::scheduler::Priority::P0, Box::new(self))
        else {
            return;
        };
        if state.scheduler.heavy.is_closed() {
            // Shutting down: the next start undoes the run.
            return;
        }
        tracing::warn!("the heavy lane is full; a failed feed run's undo waits for a place in it");
        tokio::spawn(async move {
            let mut job = job;
            loop {
                tokio::select! {
                    _ = state.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(ADMIT_RETRY) => {}
                }
                match state
                    .scheduler
                    .heavy
                    .try_submit_reserved(crate::scheduler::Priority::P0, job)
                {
                    Ok(_) => return,
                    Err(j) => job = j,
                }
            }
        });
    }

    async fn run_once(&mut self) {
        match undo_run(&self.state.db, self.run).await {
            Ok(Some(s)) => tracing::warn!(feed = %self.feed, run = self.run, deleted = s.deleted,
                reopened = s.reopened, restored = s.restored, "a feed run failed; its changes were undone"),
            Ok(None) => {
                tracing::debug!(feed = %self.feed, run = self.run, "the run had finished; nothing to undo")
            }
            Err(e) => {
                tracing::error!(feed = %self.feed, run = self.run, error = %format!("{e:#}"),
                    "cannot undo a failed feed run; trying again in a minute");
                // The feed stays busy: a retry takes over (and frees it when it is done).
                self.release = false;
                let (state, feed, run) = (self.state.clone(), self.feed.clone(), self.run);
                tokio::spawn(async move {
                    tokio::select! {
                        _ = state.shutdown.cancelled() => {}
                        _ = tokio::time::sleep(RETRY) => UndoJob::new(state.clone(), &feed, run).submit(),
                    }
                });
                return;
            }
        }
        super::ingest::drop_temp(&self.state.db, Some(self.run)).await;
    }
}

impl Drop for UndoJob {
    fn drop(&mut self) {
        if !self.release {
            return;
        }
        let (state, feed) = (self.state.clone(), std::mem::take(&mut self.feed));
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(async move { state.feeds.release(&state, &feed) });
        }
    }
}

impl crate::scheduler::HeavyJob for UndoJob {
    fn kind(&self) -> &str {
        "feed_undo"
    }

    fn target(&self) -> &str {
        &self.feed
    }

    fn step(&mut self) -> crate::scheduler::BoxFuture<'_, Result<crate::scheduler::Step>> {
        Box::pin(async move {
            self.run_once().await;
            Ok(crate::scheduler::Step::Done)
        })
    }
}

/// True while `run` is open.
pub fn is_open(c: &rusqlite::Connection, run: i64) -> rusqlite::Result<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM feed_runs_open WHERE run_id = ?1",
        [run],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}
