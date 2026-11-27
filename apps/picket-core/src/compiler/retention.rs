//! Retention of bundle versions and their blobs, and of key hits (storage.md §4), hooks of the
//! hourly retention job (heavy lane, P3; clock gated there).
//!
//! A version is **in use** while it is a bundle's current head, pinned (`edge_pins`: core served
//! an edge an object naming it), named in an edge's current config object, or listed by an edge
//! as active or previous (`edge_status`, short ids, any part of a head). Each run stamps the
//! versions in use with `last_used_at`; a version not in use goes once `last_used_at` (or, for one
//! no edge ran, the time it stopped being current) is older than `retention.bundle_versions`.
//! Its `bundle_version_blobs` rows go with it, and a bundle blob nothing names
//! (`crate::blobs::unreferenced`: no retained version, nor a row of another kind) is deleted
//! (its row, then its file) once it is an hour old and no build in progress names it
//! (`bundle_build_blobs`: a build registers its blobs there before writing their files and marks
//! the older ones its head reuses, so a build between writing its files and its commit never
//! loses one; a failed or interrupted build's mark goes and its files are collected like any).
//! The files go in the same writer turn as their rows, right after the commit: a build that
//! registers the same content meanwhile (its registration is a write) comes after the file is
//! gone, so it writes the file again rather than finding it present and then losing it.
//!
//! **Key hits** ([`KeyHitRetention`]): a `bundle_key_hits` row is kept while its key is in its
//! bundle (storage.md §4). Each run walks the hits in primary-key order, [`CHUNK`] a step, and
//! deletes those whose key is no longer among the bundle's `bundle_keys` (found through
//! `bundle_keys_key`), a deleted bundle's with them. A hit stored without its key can't be
//! matched and goes too; the next block on that key stores it again, with its key.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use jiff::Timestamp;
use rusqlite::params;

use crate::retention::{CHUNK, RetentionHook};
use crate::scheduler::{BoxFuture, Step};
use crate::state::AppState;

/// The retention hook for bundle versions.
pub struct BundleRetention;

/// The retention hook for `bundle_key_hits` (module docs).
#[derive(Default)]
pub struct KeyHitRetention {
    /// The last hit a step checked; the next step starts after it. A run cut short resumes there,
    /// and a finished run starts the next from the beginning.
    after: std::sync::Mutex<Option<(String, Vec<u8>)>>,
}

impl RetentionHook for KeyHitRetention {
    fn name(&self) -> &str {
        "bundle_key_hits"
    }

    fn step<'a>(&'a self, state: &'a AppState) -> BoxFuture<'a, Result<Step>> {
        Box::pin(async move {
            let after = self.after.lock().map(|g| g.clone()).unwrap_or_default();
            let next = state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    let (bundle, hash) = after.unwrap_or_default();
                    let mut rows: Vec<(String, Vec<u8>, bool)> = {
                        let mut st = tx.prepare_cached(
                            "SELECT h.bundle_id, h.hash128,
                                    EXISTS (SELECT 1 FROM bundle_keys k WHERE k.bundle_id = h.bundle_id AND k.key = h.key)
                             FROM bundle_key_hits h WHERE (h.bundle_id, h.hash128) > (?1, ?2)
                             ORDER BY h.bundle_id, h.hash128 LIMIT ?3",
                        )?;
                        st.query_map(params![bundle, hash, CHUNK], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                            .collect::<rusqlite::Result<_>>()?
                    };
                    {
                        let mut del =
                            tx.prepare_cached("DELETE FROM bundle_key_hits WHERE bundle_id = ?1 AND hash128 = ?2")?;
                        for (b, h, _) in rows.iter().filter(|r| !r.2) {
                            del.execute(params![b, h])?;
                        }
                    }
                    tx.commit()?;
                    let full = crate::util::sat_i64(rows.len()) >= CHUNK;
                    Ok::<_, anyhow::Error>(rows.pop().filter(|_| full).map(|(b, h, _)| (b, h)))
                })
                .await?;
            let more = next.is_some();
            if let Ok(mut g) = self.after.lock() {
                *g = next;
            }
            Ok(if more { Step::More } else { Step::Done })
        })
    }
}

/// Unreferenced bundle blobs younger than this stay (a build between writing and committing).
const BLOB_GRACE: jiff::SignedDuration = jiff::SignedDuration::from_hours(1);
/// Blobs one step deletes: their files go inside the writer's turn, so few at a time.
const BLOB_CHUNK: i64 = 1_000;

/// The short head ids a `versions` block names per bundle (every part).
fn versions_heads(v: &picket_api::logs::Versions, out: &mut BTreeMap<String, BTreeSet<String>>) {
    for (b, bv) in &v.bundles {
        let e = out.entry(b.clone()).or_default();
        match bv {
            picket_api::logs::BundleVersion::Plain(h) => {
                e.insert(h.clone());
            }
            picket_api::logs::BundleVersion::Parts(p) => {
                e.insert(p.head.clone());
                e.extend(p.shards.values().cloned());
                e.extend(p.ip_shards.values().cloned());
                e.extend(p.segments.values().cloned());
                for c in p.cold_shards.values() {
                    match c {
                        picket_api::logs::ColdShardVersion::One(h) => {
                            e.insert(h.clone());
                        }
                        picket_api::logs::ColdShardVersion::Moving(hs) => e.extend(hs.iter().cloned()),
                    }
                }
            }
        }
    }
}

impl RetentionHook for BundleRetention {
    fn name(&self) -> &str {
        "bundles"
    }

    fn step<'a>(&'a self, state: &'a AppState) -> BoxFuture<'a, Result<Step>> {
        Box::pin(async move {
            let window = state.settings().retention.bundle_versions.as_duration();
            let now = Timestamp::now();
            let cutoff = crate::util::ts(&crate::util::window_start(now, window));
            let grace = crate::util::ts(&(now - BLOB_GRACE));
            let now_s = crate::util::ts(&now);
            // Heads named in the configs core serves now.
            let mut named: Vec<(String, String)> = Vec::new();
            for e in state.edges.hub.edge_ids() {
                if let Some(p) = state.edges.publisher.current(&e) {
                    named.extend(p.config.bundles.iter().map(|(b, h)| (b.clone(), h.clone())));
                }
            }
            let data_dir = state.data_dir.clone();
            let more = state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    // Short ids edges report active or previous.
                    let mut reported: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
                    {
                        let mut st =
                            tx.prepare("SELECT versions_json, previous_versions_json FROM edge_status")?;
                        let mut rows = st.query([])?;
                        while let Some(r) = rows.next()? {
                            for i in 0..2 {
                                if let Some(s) = r.get::<_, Option<String>>(i)?
                                    && let Ok(v) = serde_json::from_str::<picket_api::logs::Versions>(&s)
                                {
                                    versions_heads(&v, &mut reported);
                                }
                            }
                        }
                    }
                    let mut stamp = tx.prepare_cached(
                        "UPDATE bundle_versions SET last_used_at = ?3 WHERE bundle_id = ?1 AND head_id = ?2",
                    )?;
                    let mut stamp_short = tx.prepare_cached(
                        "UPDATE bundle_versions SET last_used_at = ?3 WHERE bundle_id = ?1 AND substr(head_id, 1, length(?2)) = ?2",
                    )?;
                    tx.execute(
                        "UPDATE bundle_versions SET last_used_at = ?1 WHERE EXISTS (SELECT 1 FROM bundle_builds b
                           WHERE b.bundle_id = bundle_versions.bundle_id AND b.head_id = bundle_versions.head_id)",
                        [&now_s],
                    )?;
                    tx.execute(
                        "UPDATE bundle_versions SET last_used_at = ?1 WHERE EXISTS (SELECT 1 FROM edge_pins p
                           WHERE p.kind = 'bundle' AND p.target = bundle_versions.bundle_id AND p.id = bundle_versions.head_id)",
                        [&now_s],
                    )?;
                    for (b, h) in &named {
                        stamp.execute(params![b, h, now_s])?;
                    }
                    for (b, hs) in &reported {
                        for h in hs {
                            if h.len() >= 8 {
                                stamp_short.execute(params![b, h, now_s])?;
                            }
                        }
                    }
                    drop(stamp);
                    drop(stamp_short);
                    // Versions out of use past the window.
                    let gone: Vec<(String, String)> = {
                        let mut st = tx.prepare(
                            "SELECT bundle_id, head_id FROM bundle_versions
                             WHERE coalesce(last_used_at, superseded_at, published_at) < ?1
                               AND NOT EXISTS (SELECT 1 FROM bundle_builds b WHERE b.bundle_id = bundle_versions.bundle_id
                                                 AND b.head_id = bundle_versions.head_id)
                               AND NOT EXISTS (SELECT 1 FROM edge_pins p WHERE p.kind = 'bundle'
                                                 AND p.target = bundle_versions.bundle_id AND p.id = bundle_versions.head_id)
                             LIMIT ?2",
                        )?;
                        st.query_map(params![cutoff, CHUNK], |r| Ok((r.get(0)?, r.get(1)?)))?
                            .collect::<rusqlite::Result<_>>()?
                    };
                    for (b, h) in &gone {
                        tx.execute(
                            "UPDATE blobs SET refcount = max(refcount - 1, 0) WHERE blake3 IN
                               (SELECT blake3 FROM bundle_version_blobs WHERE bundle_id = ?1 AND head_id = ?2)",
                            params![b, h],
                        )?;
                        tx.execute(
                            "DELETE FROM bundle_version_blobs WHERE bundle_id = ?1 AND head_id = ?2",
                            params![b, h],
                        )?;
                        tx.execute(
                            "DELETE FROM bundle_versions WHERE bundle_id = ?1 AND head_id = ?2",
                            params![b, h],
                        )?;
                    }
                    // Bundle blobs nothing names: no retained version or build in progress, nor
                    // a row of another kind naming the same bytes (`crate::blobs` Collection).
                    let blobs = crate::blobs::unreferenced(
                        &tx,
                        &[crate::blobs::kind::BUNDLE],
                        Some(&grace),
                        BLOB_CHUNK,
                    )?;
                    for b in &blobs {
                        tx.execute("DELETE FROM blobs WHERE blake3 = ?1", [b])?;
                    }
                    tx.commit()?;
                    // Still in the writer's turn (module docs): no build can register one of
                    // these between the commit and the removal.
                    for b in &blobs {
                        if let Ok(p) = crate::blobs::path(&data_dir, b) {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                    let more = crate::util::sat_i64(gone.len()) >= CHUNK || crate::util::sat_i64(blobs.len()) >= BLOB_CHUNK;
                    Ok::<_, anyhow::Error>(more)
                })
                .await?;
            Ok(if more { Step::More } else { Step::Done })
        })
    }
}
