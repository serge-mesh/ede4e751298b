//! The one verdict store, `lookup_verdicts`, and the Block log, `lookup_blocks` (core.md §7;
//! providers.md §4 "Verdict cache"; storage.md §3).
//!
//! - **What it holds:** core's own results and every verdict the edges log (`lookups[]` items with
//!   `obtained_at`, and `lookup` records), whose `gen` is the provider's current
//!   `cache_generation`, read from `lookup_providers` inside the writer transaction (so a verdict
//!   of the old generation is dropped from the moment a flush or save commits, whatever any
//!   snapshot of the configuration says; providers.md §4 Cache generation). A verdict from another
//!   generation is dropped (never used).
//! - **Later wins:** of two verdicts for a name, the later `obtained_at` wins; an equal one changes
//!   nothing (two edges' cache hits of one answer).
//! - **Tombstones:** a row whose TTL ended holds only `obtained_at` (verdict null) until the log
//!   retention window has passed, so a late, older verdict can't come back; a result with TTL 0, or
//!   one already expired when it arrives, leaves the same tombstone. Expiry is `obtained_at` plus the
//!   provider's *current* TTL for the result, read at each use (an edited TTL applies at once).
//! - **Ordering for verdict sets:** every write gives the row the provider's next `changed_seq`
//!   from `lookup_verdict_seq`, a per-provider counter that only increases, assigned inside the
//!   writer transaction, so in commit order; the verdict-set publisher sends the rows past its
//!   head's `published_seq` ([`super::verdict_sets`]). Retention deleting the rows with the
//!   newest numbers never makes a later write reuse a published number.
//! - **Blocks:** every Block of the current generation is also kept, with that generation, in
//!   `lookup_blocks` for the retention window (a TTL of 0 or a later Clean doesn't hide it from
//!   `category_answered`); one already seen (same provider, name and `obtained_at`, such as an
//!   edge's cache hit) is ignored, so it is checked only once. A generation change deletes the
//!   provider's Blocks with its verdicts.
//! - **Clocks** (README §2): with the wall clock not yet synchronised, nothing is discarded for
//!   its age: a verdict that looks expired is stored as it came (expiry is judged at each use),
//!   and every Block is kept (the caller passes no cutoff); retention decides once it is. Core's
//!   own results ([`Source::Core`], told apart from an edge's by the type, never by the id: an
//!   edge may be named `core`) carry core's clock as `obtained_at`, so they are stored only on a
//!   synchronised clock (the queue makes no call before one): a boot clock days ahead would leave
//!   a verdict that, after the correction, stays live and beats accurately dated later ones. An
//!   edge's verdict carries the edge's clock, clamped to core's at receipt.

use std::time::Duration;

use jiff::Timestamp;
use picket_api::edge_config::VerdictCacheSettings;
use picket_bundle::verdict::VerdictKind;
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::Value;

/// The stored `source` of core's own results (an edge's verdict has the edge's id).
pub const CORE: &str = "core";

/// Who obtained a verdict (module docs, Clocks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source<'a> {
    /// Core's own lookup: `obtained_at` is core's clock.
    Core,
    /// An edge's log, by the edge's id: `obtained_at` is the edge's clock, clamped to core's.
    Edge(&'a str),
}

impl Source<'_> {
    /// The stored `source` column: [`CORE`], or the edge's id.
    pub fn id(&self) -> &str {
        match self {
            Source::Core => CORE,
            Source::Edge(e) => e,
        }
    }
}
/// The longest TTL any verdict gets (providers.md §4 "TTL cap": 30 days).
pub const TTL_CAP: Duration = Duration::from_secs(30 * 86_400);
/// The longest Block reason core keeps (bytes), cut at a character boundary (the verdict-set
/// record holds at most 512; the `LookupClient` keeps 256).
pub const MAX_REASON: usize = 256;
/// The largest detail core keeps (serialised bytes; providers.md §4 "Detail": under 512).
pub const MAX_DETAIL: usize = 511;

/// The verdict a stored row holds, as text.
pub fn verdict_text(v: VerdictKind) -> &'static str {
    match v {
        VerdictKind::Block => "block",
        VerdictKind::Clean => "clean",
        VerdictKind::Unknown => "unknown",
    }
}

/// Parses a stored verdict.
pub fn parse_verdict(s: &str) -> Option<VerdictKind> {
    match s {
        "block" => Some(VerdictKind::Block),
        "clean" => Some(VerdictKind::Clean),
        "unknown" => Some(VerdictKind::Unknown),
        _ => None,
    }
}

/// The provider's current TTL for a verdict, capped at 30 days.
pub fn ttl(cache: &VerdictCacheSettings, v: VerdictKind) -> Duration {
    let s = match v {
        VerdictKind::Block => cache.block_ttl_s,
        VerdictKind::Clean => cache.clean_ttl_s,
        VerdictKind::Unknown => cache.unknown_ttl_s,
    };
    Duration::from_secs(u64::from(s)).min(TTL_CAP)
}

/// True while a verdict obtained at `at` is live under `cache` at `now`.
pub fn is_live(cache: &VerdictCacheSettings, v: VerdictKind, at: Timestamp, now: Timestamp) -> bool {
    let t = ttl(cache, v);
    if t.is_zero() {
        return false;
    }
    jiff::SignedDuration::try_from(t).is_ok_and(|d| picket_api::time::saturating_add(at, d) > now)
}

/// `s` cut to at most `max` bytes at a character boundary.
pub fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut n = max;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s.get(..n).unwrap_or("")
}

/// What core knows of a provider when it stores one of its verdicts.
#[derive(Clone, Debug)]
pub struct ProviderView<'a> {
    pub id: &'a str,
    pub generation: &'a str,
    pub cache: &'a VerdictCacheSettings,
}

/// A lookup score as core stores and shows it (providers.md §4: a Block's `score` is an `f32` in
/// the module trait, in the edge's records, api.md §5 `lookups[]`, and in verdict sets; storage.md
/// §3 `lookup_verdicts.score` is a SQLite REAL, and the UI API's views use `f64`). Widened at that
/// boundary through the `f32`'s shortest decimal form, so the `0.97` a provider gave stays `0.97`
/// (a plain cast gives `0.9700000286102296`). Narrowing it back (`as f32`, verdict sets) gives the
/// same `f32` except in rare double-rounding cases, where it gives a neighbouring one (e.g.
/// `7.038531e-26` comes back as `7.0385313e-26`). `None` for a non-finite score.
pub fn score_f64(score: f32) -> Option<f64> {
    if !score.is_finite() {
        return None;
    }
    // Rust prints an f32 as the shortest decimal that reads back as the same f32.
    score.to_string().parse().ok()
}

/// One verdict to store.
#[derive(Clone, Debug)]
pub struct Incoming<'a> {
    pub name: &'a str,
    pub verdict: VerdictKind,
    pub score: Option<f32>,
    pub reason: Option<&'a str>,
    pub detail: Option<&'a Value>,
    /// When the provider answered (clamped to the receiver's clock by the caller).
    pub obtained_at: Timestamp,
    /// The `cache_generation` it was obtained under.
    pub generation: &'a str,
    /// Core's own result, or an edge's.
    pub source: Source<'a>,
}

/// What storing a verdict did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    /// The row changed: a live verdict, or a tombstone (TTL 0 or already expired).
    pub changed: bool,
    /// The row now holds a live verdict.
    pub live: bool,
    /// Another generation's verdict: dropped.
    pub wrong_generation: bool,
    /// A Block core hadn't seen (same provider, name and `obtained_at`), now in `lookup_blocks`.
    pub new_block: bool,
    /// Core's own result on an unsynchronised clock: not stored (module docs).
    pub unsynced: bool,
}

/// The provider's next `changed_seq`, inside the writer transaction (so in commit order), from
/// its counter in `lookup_verdict_seq`, which only increases (module docs). A provider without a
/// counter yet starts past its rows' numbers.
pub fn next_seq(tx: &Transaction<'_>, provider: &str) -> rusqlite::Result<i64> {
    tx.query_row(
        "INSERT INTO lookup_verdict_seq(provider_id, seq)
           SELECT ?1, coalesce(max(changed_seq), 0) + 1 FROM lookup_verdicts WHERE provider_id = ?1
         ON CONFLICT(provider_id) DO UPDATE SET seq = max(lookup_verdict_seq.seq + 1, excluded.seq)
         RETURNING seq",
        [provider],
        |r| r.get(0),
    )
}

/// The provider's last `changed_seq` handed out (0 for none): what a verdict set built now
/// includes at most.
pub fn last_seq(c: &rusqlite::Connection, provider: &str) -> rusqlite::Result<i64> {
    c.query_row(
        "SELECT max(coalesce((SELECT seq FROM lookup_verdict_seq WHERE provider_id = ?1), 0),
                    coalesce((SELECT max(changed_seq) FROM lookup_verdicts WHERE provider_id = ?1), 0))",
        [provider],
        |r| r.get(0),
    )
}

/// The provider's `cache_generation` as `lookup_providers` holds it now (inside the caller's
/// transaction), if the provider exists.
pub fn current_generation(c: &rusqlite::Connection, provider: &str) -> rusqlite::Result<Option<String>> {
    c.query_row(
        "SELECT cache_generation FROM lookup_providers WHERE id = ?1",
        [provider],
        |r| r.get(0),
    )
    .optional()
}

/// Deletes what a provider's old generation left in core's lookup tables (providers.md §4 Cache
/// generation: "a generation change deletes rows and tombstones alike"; the Blocks kept for
/// alerts go with them), inside the transaction that moves the generation on.
pub fn discard_generation(tx: &Transaction<'_>, provider: &str) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM lookup_verdicts WHERE provider_id = ?1", [provider])?;
    tx.execute("DELETE FROM lookup_blocks WHERE provider_id = ?1", [provider])?;
    Ok(())
}

/// The wall clock as [`record`] may use it (README §2 Clocks).
#[derive(Clone, Copy, Debug)]
pub struct RecordClock {
    pub now: Timestamp,
    /// Blocks obtained before this (older than the `lookup_blocks` window) aren't kept; `None`
    /// while the clock isn't synchronised (every Block is kept).
    pub block_cutoff: Option<Timestamp>,
    /// The clock is synchronised: a verdict already expired when it arrives leaves a tombstone.
    /// Unsynchronised, it is stored as it came, and its expiry is judged at each use.
    pub synced: bool,
}

impl RecordClock {
    /// The clock now: `block_window` back from now is the Block cutoff once synchronised.
    pub fn now(synced: bool, block_window: Duration) -> Self {
        let now = crate::util::now();
        Self {
            now,
            block_cutoff: synced.then(|| crate::util::window_start(now, block_window)),
            synced,
        }
    }
}

/// Stores one verdict (module docs). The generation is checked against the provider's row in
/// this transaction, never against `p.generation`.
pub fn record(
    tx: &Transaction<'_>,
    p: &ProviderView<'_>,
    v: &Incoming<'_>,
    clock: &RecordClock,
) -> rusqlite::Result<Recorded> {
    let mut out = Recorded::default();
    if v.source == Source::Core && !clock.synced {
        out.unsynced = true;
        return Ok(out);
    }
    if current_generation(tx, p.id)?.as_deref() != Some(v.generation) {
        out.wrong_generation = true;
        return Ok(out);
    }
    let now = clock.now;
    let at = crate::util::ts(&v.obtained_at);
    let reason = v.reason.map(|r| cut(r, MAX_REASON).to_string());
    let detail = v
        .detail
        .and_then(|d| serde_json::to_string(d).ok())
        .filter(|s| s.len() <= MAX_DETAIL);
    if v.verdict == VerdictKind::Block && clock.block_cutoff.is_none_or(|cut| v.obtained_at >= cut) {
        let n = tx.execute(
            "INSERT OR IGNORE INTO lookup_blocks(provider_id, name, obtained_at, source, reason, detail_json,
                 generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![p.id, v.name, at, v.source.id(), reason, detail, v.generation],
        )?;
        out.new_block = n > 0;
    }
    let existing: Option<String> = tx
        .query_row(
            "SELECT obtained_at FROM lookup_verdicts WHERE provider_id = ?1 AND name = ?2",
            params![p.id, v.name],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(e) = existing.as_deref().and_then(crate::util::parse_ts)
        && e >= v.obtained_at
    {
        return Ok(out);
    }
    let live = if clock.synced {
        is_live(p.cache, v.verdict, v.obtained_at, now)
    } else {
        // Expiry needs a synchronised clock: only a TTL of 0 decides now.
        !ttl(p.cache, v.verdict).is_zero()
    };
    let seq = next_seq(tx, p.id)?;
    if live {
        tx.execute(
            "INSERT INTO lookup_verdicts(provider_id, name, verdict, score, reason, detail_json, obtained_at,
                 generation, source, changed_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(provider_id, name) DO UPDATE SET verdict = excluded.verdict, score = excluded.score,
                 reason = excluded.reason, detail_json = excluded.detail_json, obtained_at = excluded.obtained_at,
                 generation = excluded.generation, source = excluded.source, changed_seq = excluded.changed_seq",
            params![
                p.id,
                v.name,
                verdict_text(v.verdict),
                v.score.and_then(score_f64),
                if v.verdict == VerdictKind::Block { reason } else { None },
                detail,
                at,
                v.generation,
                v.source.id(),
                seq
            ],
        )?;
    } else {
        tombstone(tx, p.id, v.name, &at, v.generation, v.source.id(), seq)?;
    }
    out.changed = true;
    out.live = live;
    Ok(out)
}

/// Writes a tombstone: only `obtained_at` (and the generation it belongs to).
fn tombstone(
    tx: &Transaction<'_>,
    provider: &str,
    name: &str,
    at: &str,
    generation: &str,
    source: &str,
    seq: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO lookup_verdicts(provider_id, name, verdict, score, reason, detail_json, obtained_at,
             generation, source, changed_seq)
         VALUES (?1, ?2, NULL, NULL, NULL, NULL, ?3, ?4, ?5, ?6)
         ON CONFLICT(provider_id, name) DO UPDATE SET verdict = NULL, score = NULL, reason = NULL,
             detail_json = NULL, obtained_at = excluded.obtained_at, generation = excluded.generation,
             source = excluded.source, changed_seq = excluded.changed_seq",
        params![provider, name, at, generation, source, seq],
    )?;
    Ok(())
}

/// A live verdict of the current generation for a name, if any: `(verdict, obtained_at)`.
pub fn live_entry(
    c: &rusqlite::Connection,
    p: &ProviderView<'_>,
    name: &str,
    now: Timestamp,
) -> rusqlite::Result<Option<(VerdictKind, Timestamp)>> {
    let row: Option<(Option<String>, String, String)> = c
        .query_row(
            "SELECT verdict, obtained_at, generation FROM lookup_verdicts WHERE provider_id = ?1 AND name = ?2",
            params![p.id, name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    Ok(row.and_then(|(v, at, g)| {
        let v = parse_verdict(v.as_deref()?)?;
        let at = crate::util::parse_ts(&at)?;
        (g == p.generation && is_live(p.cache, v, at, now)).then_some((v, at))
    }))
}

/// A stored verdict as the UI shows it.
#[derive(Clone, Debug, PartialEq, serde::Serialize, schemars::JsonSchema)]
pub struct VerdictRow {
    pub name: String,
    /// `block`, `clean` or `unknown`; null for a tombstone.
    pub verdict: Option<String>,
    pub score: Option<f64>,
    pub reason: Option<String>,
    pub detail: Option<Value>,
    pub obtained_at: String,
    pub generation: String,
    /// `core`, or the edge whose log carried it.
    pub source: String,
}

/// One stored row, if any.
pub fn get(c: &rusqlite::Connection, provider: &str, name: &str) -> rusqlite::Result<Option<VerdictRow>> {
    c.query_row(
        "SELECT name, verdict, score, reason, detail_json, obtained_at, generation, source
         FROM lookup_verdicts WHERE provider_id = ?1 AND name = ?2",
        params![provider, name],
        |r| {
            Ok(VerdictRow {
                name: r.get(0)?,
                verdict: r.get(1)?,
                score: r.get(2)?,
                reason: r.get(3)?,
                detail: r
                    .get::<_, Option<String>>(4)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                obtained_at: r.get(5)?,
                generation: r.get(6)?,
                source: r.get(7)?,
            })
        },
    )
    .optional()
}

/// Deletes the rows that can go (storage.md §4 "Lookup verdicts"): another generation's or an
/// unknown provider's at once; a tombstone, or a verdict whose TTL ended, once its `obtained_at`
/// is older than the log retention window (`window_cutoff`), so no late, older verdict can come
/// back while it matters. The providers, their generations and TTLs are read from
/// `lookup_providers` in `tx` (a snapshot taken before it could name an old generation and delete
/// the rows a flush just let in). At most `limit` rows per call; returns how many went.
pub fn sweep(
    tx: &Transaction<'_>,
    now: Timestamp,
    window_cutoff: Timestamp,
    limit: i64,
) -> rusqlite::Result<usize> {
    let mut gone = 0usize;
    // Rows of providers that no longer exist.
    gone += tx.execute(
        "DELETE FROM lookup_verdicts WHERE (provider_id, name) IN (SELECT provider_id, name FROM lookup_verdicts
           WHERE provider_id NOT IN (SELECT id FROM lookup_providers) LIMIT ?1)",
        [limit],
    )?;
    let providers: Vec<(String, String, Option<VerdictCacheSettings>)> = {
        let mut st =
            tx.prepare("SELECT id, cache_generation, cache_json FROM lookup_providers ORDER BY id")?;
        st.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                serde_json::from_str(&r.get::<_, String>(2)?).ok(),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    let cut = crate::util::ts(&window_cutoff);
    for (id, generation, cache) in &providers {
        let left = limit - crate::util::sat_i64(gone);
        if left <= 0 {
            break;
        }
        // Rows of another generation (left by nothing in practice: a generation change deletes
        // them in its own transaction).
        gone += tx.execute(
            "DELETE FROM lookup_verdicts WHERE (provider_id, name) IN (SELECT provider_id, name FROM lookup_verdicts
               WHERE provider_id = ?1 AND generation <> ?2 LIMIT ?3)",
            params![id, generation, left],
        )?;
        // TTLs that can't be read decide nothing.
        let Some(cache) = cache else { continue };
        let left = limit - crate::util::sat_i64(gone);
        if left <= 0 {
            break;
        }
        let ttl_cut = |v: VerdictKind| {
            jiff::SignedDuration::try_from(ttl(cache, v))
                .map(|d| crate::util::ts(&picket_api::time::saturating_sub(now, d)))
                .unwrap_or_else(|_| crate::util::ts(&now))
        };
        gone += tx.execute(
            "DELETE FROM lookup_verdicts WHERE (provider_id, name) IN (SELECT provider_id, name FROM lookup_verdicts
               WHERE provider_id = ?1 AND generation = ?2 AND obtained_at < ?3 AND (verdict IS NULL
                 OR (verdict = 'block' AND obtained_at <= ?4)
                 OR (verdict = 'clean' AND obtained_at <= ?5)
                 OR (verdict = 'unknown' AND obtained_at <= ?6))
               LIMIT ?7)",
            params![
                id,
                generation,
                cut,
                ttl_cut(VerdictKind::Block),
                ttl_cut(VerdictKind::Clean),
                ttl_cut(VerdictKind::Unknown),
                left
            ],
        )?;
    }
    Ok(gone)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A core.db with provider `q9` of generation `b71e4d09a2c63f58`.
    fn db() -> (tempfile::TempDir, rusqlite::Connection) {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let c = crate::db::open_connection(&opts, 1024).unwrap();
        provider(&c, "q9", "b71e4d09a2c63f58");
        (d, c)
    }

    pub(crate) fn provider(c: &rusqlite::Connection, id: &str, generation: &str) {
        c.execute(
            "INSERT INTO lookup_providers(id, name, module, config_json, sync_timeout_ms, async_timeout_ms,
                 fail_mode, retries, recheck_json, scope_json, cache_json, limits_json, breaker_json,
                 async_max_attempts, category, cache_generation)
             VALUES (?1, ?1, 'http_json', '{}', 150, 10000, 'open', 1, '{}', '{}', '{}', '{}', '{}', 5,
                 'security', ?2)
             ON CONFLICT(id) DO UPDATE SET cache_generation = excluded.cache_generation",
            params![id, generation],
        )
        .unwrap();
    }

    fn clock(now: Timestamp, cutoff: Timestamp) -> RecordClock {
        RecordClock {
            now,
            block_cutoff: Some(cutoff),
            synced: true,
        }
    }

    fn t(s: i64) -> Timestamp {
        Timestamp::new(1_763_700_000 + s, 0).unwrap()
    }

    fn inc<'a>(v: VerdictKind, at: Timestamp, generation: &'a str) -> Incoming<'a> {
        Incoming {
            name: "bad.example.org",
            verdict: v,
            score: Some(9.0),
            reason: Some("malware"),
            detail: None,
            obtained_at: at,
            generation,
            source: Source::Edge("edge-1"),
        }
    }

    /// F3 (providers.md §4 `score: Option<f32>`; storage.md §3 `lookup_verdicts.score`): a
    /// provider's score is stored and shown as the decimal it gave (0.97, not the f32 widened to
    /// 0.9700000286102296) and narrows back to the same f32 for verdict sets; a non-finite one is
    /// stored as none.
    #[test]
    fn scores_keep_their_decimal_form() {
        for (f, d) in [
            (0.97f32, 0.97f64),
            (9.0, 9.0),
            (7.5, 7.5),
            (0.1, 0.1),
            (123.456, 123.456),
        ] {
            assert_eq!(score_f64(f), Some(d), "{f}");
            assert_eq!(score_f64(f).map(|x| x as f32), Some(f), "{f}");
        }
        assert_eq!(score_f64(f32::NAN), None);
        assert_eq!(score_f64(f32::INFINITY), None);
        let (_d, mut c) = db();
        let cache = VerdictCacheSettings::default();
        let p = ProviderView {
            id: "q9",
            generation: "b71e4d09a2c63f58",
            cache: &cache,
        };
        let tx = c.transaction().unwrap();
        let v = Incoming {
            score: Some(0.97),
            ..inc(VerdictKind::Block, t(10), "b71e4d09a2c63f58")
        };
        record(&tx, &p, &v, &clock(t(100), t(-72 * 3600))).unwrap();
        let row = get(&tx, "q9", "bad.example.org").unwrap().unwrap();
        assert_eq!(row.score, Some(0.97));
        let text = serde_json::to_string(&row).unwrap();
        assert!(text.contains(r#""score":0.97,"#), "{text}");
    }

    /// core.md §7: the later `obtained_at` wins; another generation is dropped; TTL 0 and an
    /// expired verdict leave a tombstone that keeps an older verdict out; Blocks are kept apart and
    /// seen once.
    #[test]
    fn later_wins_tombstones_and_generations() {
        let (_d, mut c) = db();
        let cache = VerdictCacheSettings::default();
        let p = ProviderView {
            id: "q9",
            generation: "b71e4d09a2c63f58",
            cache: &cache,
        };
        let now = t(100);
        let cutoff = t(-72 * 3600);
        let tx = c.transaction().unwrap();
        let r = record(
            &tx,
            &p,
            &inc(VerdictKind::Block, t(10), "b71e4d09a2c63f58"),
            &clock(now, cutoff),
        )
        .unwrap();
        assert!(r.changed && r.live && r.new_block);
        // The same Block again (an edge's cache hit): nothing new.
        let r = record(
            &tx,
            &p,
            &inc(VerdictKind::Block, t(10), "b71e4d09a2c63f58"),
            &clock(now, cutoff),
        )
        .unwrap();
        assert!(!r.changed && !r.new_block);
        // An older Clean doesn't win.
        let r = record(
            &tx,
            &p,
            &inc(VerdictKind::Clean, t(5), "b71e4d09a2c63f58"),
            &clock(now, cutoff),
        )
        .unwrap();
        assert!(!r.changed);
        assert_eq!(
            live_entry(&tx, &p, "bad.example.org", now).unwrap().unwrap().0,
            VerdictKind::Block
        );
        // Another generation's verdict is dropped.
        let r = record(
            &tx,
            &p,
            &inc(VerdictKind::Clean, t(50), "0000000000000001"),
            &clock(now, cutoff),
        )
        .unwrap();
        assert!(r.wrong_generation && !r.changed);
        // A later Clean wins; with clean_ttl_s 0 it leaves a tombstone.
        let zero = VerdictCacheSettings {
            clean_ttl_s: 0,
            ..cache
        };
        let p0 = ProviderView {
            cache: &zero,
            ..p.clone()
        };
        let r = record(
            &tx,
            &p0,
            &inc(VerdictKind::Clean, t(60), "b71e4d09a2c63f58"),
            &clock(now, cutoff),
        )
        .unwrap();
        assert!(r.changed && !r.live);
        let row = get(&tx, "q9", "bad.example.org").unwrap().unwrap();
        assert_eq!(row.verdict, None);
        assert_eq!(live_entry(&tx, &p, "bad.example.org", now).unwrap(), None);
        // The tombstone keeps a late, older Block out of the verdicts, but the Block is kept.
        let r = record(
            &tx,
            &p,
            &inc(VerdictKind::Block, t(20), "b71e4d09a2c63f58"),
            &clock(now, cutoff),
        )
        .unwrap();
        assert!(!r.changed && r.new_block);
        // A verdict already expired when it arrives is a tombstone too.
        let r = record(
            &tx,
            &p,
            &Incoming {
                name: "old.example",
                ..inc(VerdictKind::Unknown, t(-3600), "b71e4d09a2c63f58")
            },
            &clock(now, cutoff),
        )
        .unwrap();
        assert!(r.changed && !r.live);
        // changed_seq increases with every write.
        let seqs: Vec<i64> = {
            let mut st = tx
                .prepare(
                    "SELECT changed_seq FROM lookup_verdicts WHERE provider_id = 'q9' ORDER BY changed_seq",
                )
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(seqs, vec![2, 3]);
        tx.commit().unwrap();
    }

    /// L1 (core.md §7 Verdict sets): change numbers only increase, even when the rows holding
    /// the newest ones are deleted (retention) or every row goes (a flush).
    #[test]
    fn change_numbers_never_go_back() {
        let (_d, mut c) = db();
        let cache = VerdictCacheSettings::default();
        let p = ProviderView {
            id: "q9",
            generation: "b71e4d09a2c63f58",
            cache: &cache,
        };
        let now = t(100);
        let tx = c.transaction().unwrap();
        for (i, name) in ["a.example", "b.example", "c.example"].into_iter().enumerate() {
            let r = record(
                &tx,
                &p,
                &Incoming {
                    name,
                    ..inc(VerdictKind::Clean, t(i as i64), "b71e4d09a2c63f58")
                },
                &clock(now, t(-1000)),
            )
            .unwrap();
            assert!(r.changed);
        }
        assert_eq!(last_seq(&tx, "q9").unwrap(), 3);
        // Retention deletes the newest row: the next number still passes it.
        tx.execute("DELETE FROM lookup_verdicts WHERE name = 'c.example'", [])
            .unwrap();
        assert_eq!(next_seq(&tx, "q9").unwrap(), 4);
        discard_generation(&tx, "q9").unwrap();
        assert_eq!(next_seq(&tx, "q9").unwrap(), 5);
        // A provider without a counter starts past its rows (rows written before one existed).
        tx.execute(
            "INSERT INTO lookup_verdicts(provider_id, name, verdict, obtained_at, generation, source, changed_seq)
             VALUES ('q2', 'x.example', 'clean', ?1, 'g', 'core', 41)",
            [crate::util::ts(&now)],
        )
        .unwrap();
        assert_eq!(next_seq(&tx, "q2").unwrap(), 42);
        tx.commit().unwrap();
    }

    /// L4 (providers.md §4 Cache generation): the generation is the provider row's in the
    /// writer's transaction, not the caller's snapshot: right after a flush an old-generation
    /// verdict is dropped and a new-generation one is stored, whatever the snapshot says.
    #[test]
    fn the_generation_is_read_in_the_transaction() {
        let (_d, mut c) = db();
        let cache = VerdictCacheSettings::default();
        // A snapshot from before the flush.
        let stale = ProviderView {
            id: "q9",
            generation: "b71e4d09a2c63f58",
            cache: &cache,
        };
        provider(&c, "q9", "00000000000000f2");
        let tx = c.transaction().unwrap();
        let ck = clock(t(100), t(-1000));
        let r = record(
            &tx,
            &stale,
            &inc(VerdictKind::Block, t(10), "b71e4d09a2c63f58"),
            &ck,
        )
        .unwrap();
        assert!(r.wrong_generation && !r.changed && !r.new_block);
        let r = record(
            &tx,
            &stale,
            &inc(VerdictKind::Block, t(10), "00000000000000f2"),
            &ck,
        )
        .unwrap();
        assert!(r.changed && r.new_block);
        let g: String = tx
            .query_row("SELECT generation FROM lookup_blocks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(g, "00000000000000f2", "a Block carries its generation");
        tx.commit().unwrap();
    }

    /// L8 (README §2 Clocks): unsynchronised, a verdict that looks expired is stored as it came
    /// and a Block that looks older than the window is kept.
    #[test]
    fn nothing_is_discarded_for_its_age_on_an_unsynchronised_clock() {
        let (_d, mut c) = db();
        let cache = VerdictCacheSettings::default();
        let p = ProviderView {
            id: "q9",
            generation: "b71e4d09a2c63f58",
            cache: &cache,
        };
        let unsynced = RecordClock {
            now: t(10 * 86_400),
            block_cutoff: None,
            synced: false,
        };
        let tx = c.transaction().unwrap();
        let r = record(
            &tx,
            &p,
            &inc(VerdictKind::Block, t(0), "b71e4d09a2c63f58"),
            &unsynced,
        )
        .unwrap();
        assert!(r.changed && r.new_block);
        let row = get(&tx, "q9", "bad.example.org").unwrap().unwrap();
        assert_eq!(row.verdict.as_deref(), Some("block"), "not a tombstone");
        // Synchronised, the same verdict is a tombstone and the Block is too old to keep.
        tx.execute("DELETE FROM lookup_verdicts", []).unwrap();
        tx.execute("DELETE FROM lookup_blocks", []).unwrap();
        let synced = RecordClock {
            block_cutoff: Some(t(10 * 86_400 - 72 * 3600)),
            synced: true,
            ..unsynced
        };
        let r = record(
            &tx,
            &p,
            &inc(VerdictKind::Block, t(0), "b71e4d09a2c63f58"),
            &synced,
        )
        .unwrap();
        assert!(r.changed && !r.live && !r.new_block);
        assert_eq!(get(&tx, "q9", "bad.example.org").unwrap().unwrap().verdict, None);
        tx.commit().unwrap();
    }

    /// storage.md §4: tombstones and expired verdicts go once their `obtained_at` is past the
    /// window; live ones stay; another generation's and unknown providers' go at once.
    #[test]
    fn sweep_keeps_live_rows_and_recent_tombstones() {
        let (_d, mut c) = db();
        let cache = VerdictCacheSettings::default();
        let p = ProviderView {
            id: "q9",
            generation: "b71e4d09a2c63f58",
            cache: &cache,
        };
        let now = t(10 * 86_400);
        let tx = c.transaction().unwrap();
        let mk = |name: &'static str, v: VerdictKind, at: Timestamp| Incoming {
            name,
            ..inc(v, at, "b71e4d09a2c63f58")
        };
        // A Block obtained 5 days ago with a 30-day TTL stays live.
        let long = VerdictCacheSettings {
            block_ttl_s: 30 * 86_400,
            ..cache
        };
        let pl = ProviderView {
            cache: &long,
            ..p.clone()
        };
        record(
            &tx,
            &pl,
            &mk(
                "live.example",
                VerdictKind::Block,
                now - jiff::SignedDuration::from_hours(24 * 5),
            ),
            &clock(now, now),
        )
        .unwrap();
        // A Clean obtained 5 days ago expired 6 h later: gone (past the 72 h window).
        record(
            &tx,
            &p,
            &mk(
                "old.example",
                VerdictKind::Clean,
                now - jiff::SignedDuration::from_hours(24 * 5),
            ),
            &clock(now, now),
        )
        .unwrap();
        // A tombstone from an hour ago stays.
        let zero = VerdictCacheSettings {
            unknown_ttl_s: 0,
            ..cache
        };
        let pz = ProviderView {
            cache: &zero,
            ..p.clone()
        };
        record(
            &tx,
            &pz,
            &mk(
                "tomb.example",
                VerdictKind::Unknown,
                now - jiff::SignedDuration::from_hours(1),
            ),
            &clock(now, now),
        )
        .unwrap();
        tx.execute(
            "INSERT INTO lookup_verdicts(provider_id, name, verdict, obtained_at, generation, source)
             VALUES ('gone', 'x.example', 'clean', ?1, 'g', 'core')",
            [crate::util::ts(&now)],
        )
        .unwrap();
        // The provider's TTLs as its row holds them.
        tx.execute(
            "UPDATE lookup_providers SET cache_json = ?1 WHERE id = 'q9'",
            [serde_json::to_string(&long).unwrap()],
        )
        .unwrap();
        let n = sweep(&tx, now, now - jiff::SignedDuration::from_hours(72), 1000).unwrap();
        assert_eq!(n, 2);
        let left: Vec<String> = {
            let mut st = tx
                .prepare("SELECT name FROM lookup_verdicts ORDER BY name")
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(left, vec!["live.example", "tomb.example"]);
        tx.commit().unwrap();
    }

    /// U8 (providers.md §4 Cache generation; storage.md §4): the sweep reads the providers and
    /// their generations in its own transaction: rows of the generation a flush just made, and of
    /// a provider just created, stay; the old generation's go.
    #[test]
    fn the_sweep_reads_providers_in_its_transaction() {
        let (_d, mut c) = db();
        let now = t(10 * 86_400);
        let at = crate::util::ts(&now);
        // A flush: the row's generation moved on; one row of each generation.
        provider(&c, "q9", "00000000000000f2");
        provider(&c, "q2", "00000000000000a1");
        for (p, name, generation) in [
            ("q9", "new.example", "00000000000000f2"),
            ("q9", "old.example", "b71e4d09a2c63f58"),
            ("q2", "fresh.example", "00000000000000a1"),
        ] {
            c.execute(
                "INSERT INTO lookup_verdicts(provider_id, name, verdict, obtained_at, generation, source)
                 VALUES (?1, ?2, 'clean', ?3, ?4, 'core')",
                params![p, name, at, generation],
            )
            .unwrap();
        }
        let tx = c.transaction().unwrap();
        assert_eq!(
            sweep(&tx, now, now - jiff::SignedDuration::from_hours(72), 1000).unwrap(),
            1
        );
        let left: Vec<String> = {
            let mut st = tx
                .prepare("SELECT name FROM lookup_verdicts ORDER BY name")
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(left, vec!["fresh.example", "new.example"]);
        tx.commit().unwrap();
    }

    /// U1 (README §2 Clocks): core's own result carries core's clock as `obtained_at`; with the
    /// clock unsynchronised it isn't stored, so a boot clock days ahead never leaves a verdict
    /// that outlives the correction and beats accurately dated later ones. An edge's verdict
    /// (the edge's clock, clamped to core's at receipt) is stored.
    #[test]
    fn core_results_wait_for_a_synchronised_clock() {
        let (_d, mut c) = db();
        let cache = VerdictCacheSettings::default();
        let p = ProviderView {
            id: "q9",
            generation: "b71e4d09a2c63f58",
            cache: &cache,
        };
        let real = t(0);
        let ahead = real + jiff::SignedDuration::from_hours(24 * 4);
        let tx = c.transaction().unwrap();
        // A call completed while the boot clock was four days ahead.
        let unsynced = RecordClock {
            now: ahead,
            block_cutoff: None,
            synced: false,
        };
        let r = record(
            &tx,
            &p,
            &Incoming {
                source: Source::Core,
                ..inc(VerdictKind::Clean, ahead, "b71e4d09a2c63f58")
            },
            &unsynced,
        )
        .unwrap();
        assert!(r.unsynced && !r.changed, "{r:?}");
        assert_eq!(get(&tx, "q9", "bad.example.org").unwrap(), None);
        // After NTP corrected the clock, an accurately dated Block is the verdict.
        let r = record(
            &tx,
            &p,
            &inc(VerdictKind::Block, real, "b71e4d09a2c63f58"),
            &clock(real, real - jiff::SignedDuration::from_hours(72)),
        )
        .unwrap();
        assert!(r.changed && r.live);
        assert_eq!(
            live_entry(&tx, &p, "bad.example.org", real).unwrap().map(|e| e.0),
            Some(VerdictKind::Block)
        );
        // An edge's verdict received while unsynchronised is stored, whatever the edge's id
        // (W4: an edge named `core` is an edge).
        for (name, edge) in [("edge.example", "edge-1"), ("core-edge.example", CORE)] {
            let r = record(
                &tx,
                &p,
                &Incoming {
                    name,
                    source: Source::Edge(edge),
                    ..inc(VerdictKind::Clean, real, "b71e4d09a2c63f58")
                },
                &unsynced,
            )
            .unwrap();
            assert!(r.changed && !r.unsynced, "{edge}: {r:?}");
        }
        tx.commit().unwrap();
    }
}
