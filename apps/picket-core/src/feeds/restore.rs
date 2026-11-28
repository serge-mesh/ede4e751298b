//! The feed side of the config export and restore (core.md §2 "Export and restore",
//! feed-scheduling.md §3, §8).
//!
//! [`export`] gives, beside the configuration (feed providers with their `files` and `exclude`,
//! and every feed, which the config document carries): each feed's model epoch, content hash
//! (`seen_blake3`) and staleness reference; each provider's `k`; and the retained check history
//! (`feed_provider_checks`, `feed_checks`, `feed_changes`). A provider's listing isn't carried:
//! core.md §2 doesn't name it among what the document holds, it can be larger than any part cap
//! a restore could read in memory (a GitHub tree of up to 200,000 paths, for each of up to 256
//! providers), and the restore clears every provider's module state, so its first check lists
//! again (providers.md §2 Listing). A listing in an older document is still restored.
//!
//! [`restore_in`] writes them back in the restore's transaction, after the configuration: every
//! provider's and feed's `last` is cleared (each provider's next check, due at once, is a first
//! check), each gets a new source generation (nothing in flight stores into the restored state),
//! no feed is added or raised again, and since `seen_blake3` comes back, a restored feed whose
//! source serves the same bytes (under another ETag too) records no change (feed-scheduling.md
//! §3). The check history streams through [`export_checks`] and [`restore_check_in`], one entry
//! at a time (core.md §3: bounded memory). Every provider and feed the parts name must be one
//! the document restores: one bad reference rejects the whole document (core.md §2), and an
//! export holds only the history of the providers and feeds it holds.
//!
//! The document itself, `GET/PUT config/export` and the parts of a restore outside feeds
//! (alerts, `config_changes`, secrets by name, lookup caches, the heads edges keep) are
//! `config::export`'s; this module is what the document's feed parts read and write.

use anyhow::{Context, Result};
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One feed's state that travels with the export.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FeedPart {
    pub feed: String,
    pub epoch_at: Option<String>,
    pub seen_blake3: Option<String>,
    pub stale_ref: Option<Value>,
    pub warm_started_at: Option<String>,
    /// The start of the span the warm start read (absent from older exports).
    #[serde(default)]
    pub warm_span_at: Option<String>,
}

/// One provider's state that travels with the export.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProviderPart {
    pub provider: String,
    /// The provider's listing: only in older documents (module docs: the export leaves it out,
    /// and the first check after a restore lists again).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing: Option<Value>,
    pub k: Option<f64>,
}

/// A provider check with its feeds' checks and their changes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CheckPart {
    pub provider: Option<String>,
    pub t: String,
    pub cause: Option<String>,
    pub duration_ms: Option<i64>,
    pub ok: bool,
    pub error: Option<String>,
    pub feeds: Vec<FeedCheckPart>,
}

/// One recorded change: `(t_change, exact, t_lo, t_seen, origin)`.
pub type ChangePart = (
    Option<String>,
    Option<i64>,
    Option<String>,
    String,
    Option<String>,
);

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FeedCheckPart {
    pub feed: String,
    pub t: String,
    pub duration_ms: Option<i64>,
    pub method: Option<String>,
    pub ok: bool,
    pub changed: Option<bool>,
    pub bytes: Option<i64>,
    #[serde(rename = "ref")]
    pub version: Option<String>,
    pub predicted_rate: Option<f64>,
    pub error: Option<String>,
    /// `(t_change, exact, t_lo, t_seen, origin)`.
    pub changes: Vec<ChangePart>,
}

/// The feed parts of a config export.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FeedSide {
    pub feeds: Vec<FeedPart>,
    pub providers: Vec<ProviderPart>,
    pub checks: Vec<CheckPart>,
}

/// Reads the feed parts of a config export (core.md §2), without the check history
/// ([`export_checks`]).
pub fn export(c: &Connection) -> Result<FeedSide> {
    let mut out = FeedSide::default();
    {
        let mut st = c.prepare(
            "SELECT s.feed_id, s.epoch_at, s.seen_blake3, s.stale_ref_json, s.warm_started_at, s.warm_span_at
             FROM feed_state s JOIN feeds f ON f.id = s.feed_id ORDER BY s.feed_id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(FeedPart {
                feed: r.get(0)?,
                epoch_at: r.get(1)?,
                seen_blake3: r.get(2)?,
                stale_ref: r
                    .get::<_, Option<String>>(3)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                warm_started_at: r.get(4)?,
                warm_span_at: r.get(5)?,
            })
        })?;
        for r in rows {
            out.feeds.push(r?);
        }
    }
    {
        // Without the listing (module docs).
        let mut st = c.prepare(
            "SELECT s.provider_id, s.k FROM feed_provider_state s
             JOIN feed_providers p ON p.id = s.provider_id ORDER BY s.provider_id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(ProviderPart {
                provider: r.get(0)?,
                listing: None,
                k: r.get(1)?,
            })
        })?;
        for r in rows {
            out.providers.push(r?);
        }
    }
    Ok(out)
}

/// The retained check history of the providers and feeds the configuration holds (a deleted
/// one's history stays until retention, but it isn't the document's), one entry at a time:
/// provider checks with their feeds' checks, by time; then feed checks without a provider check
/// of the document (warm-start rows), each under a provider-less entry.
pub fn export_checks(c: &Connection, mut emit: impl FnMut(CheckPart) -> Result<()>) -> Result<()> {
    // The recorded changes, by check (few: one per change a check saw).
    let mut changes: std::collections::HashMap<i64, Vec<ChangePart>> = std::collections::HashMap::new();
    {
        let mut st = c.prepare(
            "SELECT check_id, t_change, exact, t_lo, t_seen, origin FROM feed_changes
             WHERE check_id IS NOT NULL AND feed_id IN (SELECT id FROM feeds) ORDER BY id",
        )?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            changes.entry(r.get(0)?).or_default().push((
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ));
        }
    }
    let feed_check = |r: &rusqlite::Row<'_>,
                      at: usize,
                      changes: &mut std::collections::HashMap<i64, Vec<ChangePart>>|
     -> rusqlite::Result<FeedCheckPart> {
        let id: i64 = r.get(at)?;
        Ok(FeedCheckPart {
            feed: r.get(at + 1)?,
            t: r.get(at + 2)?,
            duration_ms: r.get(at + 3)?,
            method: r.get(at + 4)?,
            ok: r.get::<_, i64>(at + 5)? != 0,
            changed: r.get::<_, Option<i64>>(at + 6)?.map(|v| v != 0),
            bytes: r.get(at + 7)?,
            version: r.get(at + 8)?,
            predicted_rate: r.get(at + 9)?,
            error: r.get(at + 10)?,
            changes: changes.remove(&id).unwrap_or_default(),
        })
    };
    const FC: &str = "fc.id, fc.feed_id, fc.t, fc.duration_ms, fc.method, fc.ok, fc.changed, fc.bytes, fc.ref, fc.predicted_rate, fc.error";
    {
        let mut st = c.prepare(&format!(
            "SELECT pc.id, pc.provider_id, pc.t, pc.cause, pc.duration_ms, pc.ok, pc.error, {FC}
             FROM feed_provider_checks pc
             LEFT JOIN feed_checks fc ON fc.provider_check_id = pc.id AND fc.feed_id IN (SELECT id FROM feeds)
             WHERE pc.provider_id IN (SELECT id FROM feed_providers)
             ORDER BY pc.t, pc.id, fc.t, fc.id"
        ))?;
        let mut rows = st.query([])?;
        let mut cur: Option<(i64, CheckPart)> = None;
        while let Some(r) = rows.next()? {
            let pid: i64 = r.get(0)?;
            if cur.as_ref().is_none_or(|(id, _)| *id != pid) {
                if let Some((_, done)) = cur.take() {
                    emit(done)?;
                }
                cur = Some((
                    pid,
                    CheckPart {
                        provider: Some(r.get(1)?),
                        t: r.get(2)?,
                        cause: r.get(3)?,
                        duration_ms: r.get(4)?,
                        ok: r.get::<_, i64>(5)? != 0,
                        error: r.get(6)?,
                        feeds: vec![],
                    },
                ));
            }
            if r.get::<_, Option<i64>>(7)?.is_some()
                && let Some((_, c)) = cur.as_mut()
            {
                c.feeds.push(feed_check(r, 7, &mut changes)?);
            }
        }
        if let Some((_, done)) = cur.take() {
            emit(done)?;
        }
    }
    let mut st = c.prepare(&format!(
        "SELECT {FC} FROM feed_checks fc
         WHERE fc.feed_id IN (SELECT id FROM feeds)
           AND (fc.provider_check_id IS NULL OR NOT EXISTS (SELECT 1 FROM feed_provider_checks pc
                WHERE pc.id = fc.provider_check_id AND pc.provider_id IN (SELECT id FROM feed_providers)))
         ORDER BY fc.t, fc.id"
    ))?;
    let mut rows = st.query([])?;
    while let Some(r) = rows.next()? {
        let fc = feed_check(r, 0, &mut changes)?;
        emit(CheckPart {
            provider: None,
            t: fc.t.clone(),
            ok: fc.ok,
            feeds: vec![fc],
            ..CheckPart::default()
        })?;
    }
    Ok(())
}

/// Writes the feed parts of a restored export (core.md §2), in the restore's transaction, after
/// its configuration: the providers and feeds it names must exist. The check history follows,
/// one entry at a time ([`restore_check_in`]).
pub fn restore_in(
    tx: &Transaction<'_>,
    feeds_part: &[FeedPart],
    providers_part: &[ProviderPart],
) -> Result<()> {
    // Every provider and feed starts with a first check; nothing in flight stores into them.
    let providers: Vec<String> = {
        let mut st = tx.prepare("SELECT id FROM feed_providers")?;
        st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
    };
    for p in &providers {
        super::store::new_provider_source_gen(tx, p)?;
        tx.execute(
            "UPDATE feed_provider_state SET state_json = NULL, next_check_at = NULL, due_cause = 'first',
                nudged_at = NULL, failing_since = NULL, check_started_at = NULL, skipped_json = NULL, capacity_skipped_json = NULL,
                last_check_at = NULL, last_ok_at = NULL
             WHERE provider_id = ?1",
            [p],
        )?;
    }
    let feeds: Vec<String> = {
        let mut st = tx.prepare("SELECT id FROM feeds")?;
        st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
    };
    for f in &feeds {
        super::store::new_source_gen(tx, f)?;
        // Feeds come back with their providers: none is added or raised again.
        tx.execute(
            "UPDATE feed_state SET last_json = NULL, next_check_at = NULL, next_ask_at = NULL, added_pending = 0
             WHERE feed_id = ?1",
            [f],
        )?;
    }
    for p in providers_part {
        if !providers.contains(&p.provider) {
            anyhow::bail!(
                "the export's feed state names an unknown feed provider {:?}",
                p.provider
            );
        }
        tx.execute(
            "UPDATE feed_provider_state SET listing_json = ?2, k = ?3 WHERE provider_id = ?1",
            params![
                p.provider,
                p.listing.as_ref().map(Value::to_string),
                p.k.filter(|k| (0.1..=50.0).contains(k))
            ],
        )?;
    }
    for f in feeds_part {
        if !feeds.contains(&f.feed) {
            anyhow::bail!("the export's feed state names an unknown feed {:?}", f.feed);
        }
        if let Some(b) = &f.seen_blake3
            && !picket_api::ids::is_object_id(b)
        {
            anyhow::bail!("feed {:?}: seen_blake3 isn't a content hash", f.feed);
        }
        tx.execute(
            "UPDATE feed_state SET epoch_at = ?2, seen_blake3 = ?3, stale_ref_json = ?4, warm_started_at = ?5,
                warm_span_at = ?6
             WHERE feed_id = ?1",
            params![
                f.feed,
                f.epoch_at,
                f.seen_blake3,
                f.stale_ref.as_ref().map(Value::to_string),
                f.warm_started_at,
                f.warm_span_at
            ],
        )?;
    }
    Ok(())
}

/// Checks the providers and feeds the check history names against the document's: one unknown
/// rejects the whole document (core.md §2).
pub fn check_refs<'a>(
    providers: impl IntoIterator<Item = &'a String>,
    feeds: impl IntoIterator<Item = &'a String>,
    model: &crate::config::Model,
) -> std::result::Result<(), String> {
    for p in providers {
        if !model.feed_providers.contains_key(p) {
            return Err(format!(
                "the export's check history names an unknown feed provider {p:?}"
            ));
        }
    }
    for f in feeds {
        if !model.feeds.contains_key(f) {
            return Err(format!("the export's check history names an unknown feed {f:?}"));
        }
    }
    Ok(())
}

/// Writes one check-history entry (after [`restore_in`]); its provider and feeds must exist.
pub fn restore_check_in(tx: &Transaction<'_>, c: &CheckPart) -> Result<()> {
    let exists = |sql: &str, id: &str| -> Result<bool> { Ok(tx.prepare_cached(sql)?.exists([id])?) };
    let pc = match &c.provider {
        Some(p) => {
            if !exists("SELECT 1 FROM feed_providers WHERE id = ?1", p)? {
                anyhow::bail!("the export's check history names an unknown feed provider {p:?}");
            }
            tx.execute(
                "INSERT INTO feed_provider_checks(provider_id, t, cause, duration_ms, ok, error) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![p, c.t, c.cause.as_deref().unwrap_or("trigger"), c.duration_ms, c.ok as i64, c.error],
            )
            .context("restore a provider check")?;
            Some(tx.last_insert_rowid())
        }
        None => None,
    };
    for fc in &c.feeds {
        if !exists("SELECT 1 FROM feeds WHERE id = ?1", &fc.feed)? {
            anyhow::bail!("the export's check history names an unknown feed {:?}", fc.feed);
        }
        tx.execute(
            "INSERT INTO feed_checks(provider_check_id, feed_id, t, duration_ms, method, ok, changed, bytes, ref, predicted_rate, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                pc,
                fc.feed,
                fc.t,
                fc.duration_ms,
                fc.method,
                fc.ok as i64,
                fc.changed.map(|v| v as i64),
                fc.bytes,
                fc.version,
                fc.predicted_rate,
                fc.error
            ],
        )?;
        let id = tx.last_insert_rowid();
        for (t_change, exact, t_lo, t_seen, origin) in &fc.changes {
            tx.execute(
                "INSERT INTO feed_changes(feed_id, check_id, t_change, exact, t_lo, t_seen, origin) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![fc.feed, id, t_change, exact, t_lo, t_seen, origin],
            )?;
        }
    }
    Ok(())
}
