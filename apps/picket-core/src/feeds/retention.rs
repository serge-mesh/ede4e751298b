//! Feed retention (storage.md §4), a hook of the hourly retention job (heavy lane, P3; clock
//! gated there), one bounded step at a time:
//!
//! - **Closed `feed_entries` rows** older than `retention.feed_entries` (by the time of the run
//!   that closed them), except rows a still-retained bundle version needs for replay: a version
//!   that records run *r* of a feed needs the rows open at *r* (`first_run ≤ r < removed_run`),
//!   so only rows closed at or before the oldest run any version records go. Rows closed by a
//!   run still open (an ingest or sweep between its diff and its row, feeds.md §3) are never
//!   candidates: its undo may have to reopen them. Pins are applied inside the query, so rows
//!   kept for replay never crowd out rows that may go.
//! - **`feed_runs`** older than `retention.feed_runs`, keeping per feed the newest, the latest
//!   applied, the run the provider's `last` names (its newest download, held included) and the
//!   latest applied source run (a download, a save, or a re-ingest of either; never an import),
//!   held runs still waiting, open runs, and every run a bundle version records (run ids follow
//!   the order runs changed entries).
//! - **Raw downloads** (`download` and `manual_file` blobs) older than `retention.raw_downloads`
//!   that no retained `feed_runs` row, no `manual_files` row, no pending import
//!   (`feed_imports`), no restored applied blob waiting for its run (`restore_applied`,
//!   core.md §2) and no row of another kind naming the same bytes names
//!   (`crate::blobs::unreferenced`).
//! - **Resolved `policy_drops`** past the resolved-warnings window (`retention.warnings`; a
//!   dropped rule is kept "like warninglist warnings", feeds.md §8).
//! - **Deleted feeds:** once a deleted feed's purge has run (`feeds::purge`: its open entries
//!   closed, its runs moved to a tombstone id), its entries go once no bundle version records the
//!   feed, its runs (tombstoned) once no version records them, with its policy drops and state.
//!
//! Bundle versions record their feed runs in `bundle_versions.feed_runs_json` as an object of
//! feed id → run id (the head's `feed_runs`, bundles.md §4), and each bundle's last build in
//! `bundle_builds.feed_runs_json` (its next incremental build replays from it); the compiler
//! writes both, and both pin. Run ids are unique across feeds, so a recorded run is found by its
//! id alone.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use jiff::Timestamp;
use rusqlite::params;

use crate::retention::{CHUNK, RetentionHook};
use crate::scheduler::{BoxFuture, Step};
use crate::state::AppState;

/// The feed retention hook (stateless: each step finds its own work).
pub struct FeedRetention;

/// What retained bundle versions record, and what each bundle's last build recorded (the run an
/// incremental build replays from: warn and browser-only bundles publish no version, and any
/// bundle's builds may fail for longer than the window): each feed's oldest recorded run (its
/// pin), and every recorded run id.
fn recorded_runs(c: &rusqlite::Connection) -> rusqlite::Result<(BTreeMap<String, i64>, BTreeSet<i64>)> {
    let mut pins: BTreeMap<String, i64> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut st = c.prepare(
        "SELECT feed_runs_json FROM bundle_versions UNION ALL SELECT feed_runs_json FROM bundle_builds",
    )?;
    let rows = st.query_map([], |r| r.get::<_, String>(0))?;
    for row in rows {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&row?) else {
            continue;
        };
        let Some(m) = v.as_object() else { continue };
        for (feed, run) in m {
            if let Some(r) = run.as_i64() {
                let e = pins.entry(feed.clone()).or_insert(r);
                *e = (*e).min(r);
                ids.insert(r);
            }
        }
    }
    Ok((pins, ids))
}

/// The tombstone id a deleted feed's runs move to (`#` is never in a feed id).
pub fn tombstone(feed: &str, purge_run: i64) -> String {
    format!("{feed}#{purge_run}")
}

impl RetentionHook for FeedRetention {
    fn name(&self) -> &str {
        "feeds"
    }

    fn step<'a>(&'a self, state: &'a AppState) -> BoxFuture<'a, Result<Step>> {
        Box::pin(async move {
            let s = state.settings();
            let now = Timestamp::now();
            let cut = |d: std::time::Duration| crate::util::ts(&crate::util::window_start(now, d));
            let entries_cut = cut(s.retention.feed_entries.as_duration());
            let runs_cut = cut(s.retention.feed_runs.as_duration());
            let blobs_cut = cut(s.retention.raw_downloads.as_duration());
            let drops_cut = cut(s.retention.warnings.as_duration());
            let data_dir = state.data_dir.clone();
            let more = state
                .db
                .write(move |c| {
                    let (pins, recorded) = recorded_runs(c)?;
                    let pins_json = serde_json::to_string(&pins)?;
                    let recorded_json = serde_json::to_string(&recorded)?;
                    let tx = c.transaction()?;
                    // Closed entries: by the closing run's time; not closed by an open run; not
                    // needed by any version (closed at or before the feed's oldest pin).
                    let deleted = tx.execute(
                        "DELETE FROM feed_entries WHERE id IN (
                           SELECT e.id FROM feed_entries e
                           LEFT JOIN feed_runs r ON r.id = e.removed_run
                           WHERE e.removed_run IS NOT NULL
                             AND coalesce(r.confirmed_at, r.downloaded_at, r.updated_at, '') < ?1
                             AND NOT EXISTS (SELECT 1 FROM feed_runs_open o WHERE o.run_id = e.removed_run)
                             AND e.removed_run <= coalesce(
                                   (SELECT p.value FROM json_each(?3) p WHERE p.key = e.feed_id), e.removed_run)
                           LIMIT ?2)",
                        params![entries_cut, CHUNK, pins_json],
                    )?;
                    // Old runs, keeping what is still needed.
                    let runs_deleted = tx.execute(
                        "DELETE FROM feed_runs WHERE id IN (
                           SELECT r.id FROM feed_runs r
                           WHERE coalesce(r.downloaded_at, r.confirmed_at, r.updated_at, '') < ?1
                             AND r.id <> (SELECT max(id) FROM feed_runs x WHERE x.feed_id = r.feed_id)
                             AND r.id <> coalesce((SELECT max(id) FROM feed_runs x WHERE x.feed_id = r.feed_id AND x.status = 'applied'), -1)
                             AND r.id <> coalesce((SELECT max(id) FROM feed_runs x WHERE x.feed_id = r.feed_id
                                   AND coalesce(x.kind, 'download') = 'download'), -1)
                             AND r.id <> coalesce((SELECT max(id) FROM feed_runs x WHERE x.feed_id = r.feed_id AND x.status = 'applied'
                                   AND coalesce(x.kind, 'download') IN ('download', 'reingest')), -1)
                             AND r.status <> 'held'
                             AND NOT EXISTS (SELECT 1 FROM feed_runs_open o WHERE o.run_id = r.id)
                             AND r.id NOT IN (SELECT value FROM json_each(?3))
                           LIMIT ?2)",
                        params![runs_cut, CHUNK, recorded_json],
                    )?;
                    // Raw downloads and manual files nothing names: no retained run, manual
                    // file, import or restore, nor a row of another kind naming the same bytes
                    // (`crate::blobs` Collection).
                    let blobs = crate::blobs::unreferenced(
                        &tx,
                        &[crate::blobs::kind::DOWNLOAD, crate::blobs::kind::MANUAL_FILE],
                        Some(&blobs_cut),
                        CHUNK,
                    )?;
                    for b in &blobs {
                        tx.execute("DELETE FROM blobs WHERE blake3 = ?1", [b])?;
                    }
                    // Resolved policy drops past their window (README §2 Bounded).
                    let drops_deleted = tx.execute(
                        "DELETE FROM policy_drops WHERE id IN (SELECT id FROM policy_drops
                           WHERE status = 'resolved' AND coalesce(resolved_at, '') < ?1 LIMIT ?2)",
                        params![drops_cut, CHUNK],
                    )?;
                    // Deleted feeds' data (entries first, in chunks), once their purge has run.
                    let gone: Vec<String> = {
                        let mut st = tx.prepare(
                            "SELECT feed_id FROM (
                               SELECT DISTINCT feed_id FROM feed_runs WHERE feed_id NOT IN (SELECT id FROM feeds)
                               UNION SELECT DISTINCT feed_id FROM feed_entries WHERE feed_id NOT IN (SELECT id FROM feeds)
                               UNION SELECT DISTINCT feed_id FROM policy_drops WHERE feed_id NOT IN (SELECT id FROM feeds))
                             WHERE feed_id NOT IN (SELECT feed_id FROM feed_purges) LIMIT 16",
                        )?;
                        st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
                    };
                    let mut gone_rows = 0usize;
                    for feed in &gone {
                        if !pins.contains_key(feed) {
                            gone_rows += tx.execute(
                                "DELETE FROM feed_entries WHERE id IN (SELECT id FROM feed_entries WHERE feed_id = ?1 LIMIT ?2)",
                                params![feed, CHUNK],
                            )?;
                        }
                        gone_rows += tx.execute(
                            "DELETE FROM feed_runs WHERE feed_id = ?1
                               AND NOT EXISTS (SELECT 1 FROM feed_runs_open o WHERE o.run_id = feed_runs.id)
                               AND id NOT IN (SELECT value FROM json_each(?2))",
                            params![feed, recorded_json],
                        )?;
                        if crate::util::sat_i64(gone_rows) < CHUNK {
                            for t in ["policy_drops", "feed_state"] {
                                tx.execute(&format!("DELETE FROM {t} WHERE feed_id = ?1"), [feed])?;
                            }
                        }
                    }
                    tx.commit()?;
                    // The blob files go after their rows (a file without a row is harmless).
                    for b in &blobs {
                        if let Ok(p) = crate::blobs::path(&data_dir, b) {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                    let more = crate::util::sat_i64(deleted) >= CHUNK
                        || crate::util::sat_i64(runs_deleted) >= CHUNK
                        || crate::util::sat_i64(blobs.len()) >= CHUNK
                        || crate::util::sat_i64(drops_deleted) >= CHUNK
                        || crate::util::sat_i64(gone_rows) >= CHUNK;
                    Ok::<_, anyhow::Error>(more)
                })
                .await?;
            Ok(if more { Step::More } else { Step::Done })
        })
    }
}
