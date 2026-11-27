//! Verdict sets (core.md §7; providers.md §4 "Verdict cache"; bundles.md §4 page file, §5 deltas
//! and compaction; storage.md §3–§4).
//!
//! For each provider an edge's profiles attach `sync` (every edge renders every profile, so every
//! edge's config names one per such provider), core publishes the provider's live rows (no
//! tombstones) of the current `cache_generation` as a read-only verdict set: a base page file of
//! records keyed by `xxh3_128(hash_seed, name)` with `{verdict, obtained_at, score?, reason?}`, and
//! deltas in the bundle delta line format keyed by that hash, under content-hash heads
//! (`{provider, format, generation, hash_seed, base, deltas, seq, checksum, issued_at}`), written
//! with picket-bundle's verdict writer so the edge's reader reads exactly what core wrote.
//!
//! - **State** (`verdict_set_state`): the provider's current head, base, chain, checksum and
//!   `published_seq`, the newest `lookup_verdicts.changed_seq` the head includes; the chain's
//!   records by hash in `verdict_set_overlay` (what the edge's overlay holds), so a delta knows
//!   each name's old record (the overlay's, else the base page's) and the set checksum moves in
//!   O(delta).
//! - **Deltas** (heavy lane, P0): every `lookups.verdict_delta_s` (default 300) while rows changed,
//!   and at once when core records a Block. A delta upserts the names whose live record changed and
//!   deletes the names whose live record went (replaced by a tombstone); a record that only expired
//!   stays until the base is rebuilt (the edge judges expiry itself). It reads the rows of the
//!   current generation past `published_seq` (change numbers only increase, [`super::store`]) and
//!   diffs them in bounded steps ([`DeltaBuild`], linear in the rows) off the async runtime.
//! - **Clocks** (README §2): nothing is published while the wall clock isn't synchronised (what a
//!   set holds depends on expiry); edges keep their current sets.
//! - **Bases** (heavy lane, P2): for a new provider, a new generation (a flush or a save that moves
//!   it on: the old set's rows are gone and edges drop the old set), and when the base is
//!   rebuilt: expired records are dropped. Backstops: more than 1,000 deltas, a base older than 30
//!   days, more changed rows than one delta carries ([`MAX_DELTA_ROWS`]), or an overlay past the
//!   overlay entry bound.
//! - **Compaction** (bundles.md §5): before publishing, when the delta would push an edge's
//!   overlays (its bundle heads' plus every verdict set's) past its `overlay_budget_mib`, core first
//!   rebuilds the part with the largest overlay on that edge: this set's base (published instead of
//!   the delta), another set's base, or a bundle part (its compaction build); the delta waits for
//!   it.
//! - **Retention** ([`SetRetention`]): versions and their blobs go 72 h (`retention.bundle_versions`)
//!   after the last edge stopped using them, kept while pinned, named in a config core serves,
//!   reported by an online edge (`have`), or current; a blob goes once nothing names it
//!   (`crate::blobs::unreferenced`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::os::unix::fs::FileExt as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use jiff::Timestamp;
use picket_bundle::checksum::SetChecksum;
use picket_bundle::hash::{KeyHash, verdict_hash_seed};
use picket_bundle::head::DeltaRef;
use picket_bundle::overlay::{Entry, HashOverlay};
use picket_bundle::page::{self, PAGE_SIZE, PageFileHeader, PageReader};
use picket_bundle::verdict::{self, VerdictChange, VerdictHead, VerdictKind, VerdictRecord};
use rusqlite::{OptionalExtension, params};
use tokio::sync::Notify;

use super::store;
use crate::config::Model;
use crate::scheduler::Priority;
use crate::state::{AppState, SharedState};

/// Most changed rows one delta carries; a larger backlog rebuilds the base instead (the edge reads
/// at most 512 Ki ops per delta).
pub const MAX_DELTA_ROWS: i64 = 100_000;
/// Most records one base holds (README §2 Bounded: a base is written in memory, about 90 MB at
/// the cap); past it the newest are kept and the rest counted.
pub const MAX_SET_RECORDS: i64 = 1_000_000;
/// Deltas before the base is rebuilt (bundles.md §5 backstop).
pub const MAX_DELTAS: usize = 1000;
/// A base this old is rebuilt (bundles.md §5 backstop).
pub const MAX_BASE_AGE: Duration = Duration::from_secs(30 * 86_400);
/// Unreferenced verdict-set blobs younger than this stay (a publish between writing its files and
/// its commit).
const BLOB_GRACE: jiff::SignedDuration = jiff::SignedDuration::from_hours(1);
/// How long a delta deferred for a compaction waits before it is tried again.
const DEFER: Duration = Duration::from_secs(30);

/// The publisher's state.
#[derive(Default)]
pub struct SetsState {
    pub wake: Notify,
    /// Providers that recorded a Block since their last delta (a delta at once).
    urgent: Mutex<HashSet<String>>,
    /// When each provider's last delta was planned.
    last_delta: Mutex<HashMap<String, tokio::time::Instant>>,
    /// Deltas deferred for a compaction, until.
    deferred: Mutex<HashMap<String, tokio::time::Instant>>,
}

impl SetsState {
    /// Core recorded a Block for `provider`: its next delta is built at once.
    pub fn block_recorded(&self, provider: &str) {
        if let Ok(mut u) = self.urgent.lock() {
            u.insert(provider.to_string());
        }
        self.wake.notify_one();
    }

    fn take_urgent(&self, provider: &str) -> bool {
        self.urgent
            .lock()
            .map(|mut u| u.remove(provider))
            .unwrap_or(false)
    }

    fn defer(&self, provider: &str) {
        if let Ok(mut d) = self.deferred.lock() {
            d.insert(provider.to_string(), tokio::time::Instant::now() + DEFER);
        }
    }

    fn deferred(&self, provider: &str) -> bool {
        self.deferred
            .lock()
            .ok()
            .and_then(|d| d.get(provider).copied())
            .is_some_and(|t| t > tokio::time::Instant::now())
    }
}

/// A provider's `verdict_set_state` row.
#[derive(Clone, Debug, PartialEq)]
pub struct SetState {
    pub provider: String,
    pub generation: String,
    pub head_id: String,
    pub base_id: String,
    pub seq: u64,
    pub checksum: SetChecksum,
    pub deltas: Vec<DeltaRef>,
    pub published_seq: i64,
    pub base_records: i64,
    pub overlay_entries: i64,
    pub overlay_bytes: i64,
    pub base_at: String,
    pub published_at: String,
}

fn read_state(c: &rusqlite::Connection, provider: &str) -> rusqlite::Result<Option<SetState>> {
    c.query_row(
        "SELECT provider_id, generation, head_id, base_id, seq, checksum, deltas_json, published_seq, base_records,
                overlay_entries, overlay_bytes, base_at, published_at
         FROM verdict_set_state WHERE provider_id = ?1",
        [provider],
        |r| {
            Ok(SetState {
                provider: r.get(0)?,
                generation: r.get(1)?,
                head_id: r.get(2)?,
                base_id: r.get(3)?,
                seq: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                checksum: SetChecksum::from_hex(&r.get::<_, String>(5)?).unwrap_or(SetChecksum::ZERO),
                deltas: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
                published_seq: r.get(7)?,
                base_records: r.get(8)?,
                overlay_entries: r.get(9)?,
                overlay_bytes: r.get(10)?,
                base_at: r.get(11)?,
                published_at: r.get(12)?,
            })
        },
    )
    .optional()
}

/// Every provider's state row.
pub fn states(c: &rusqlite::Connection) -> rusqlite::Result<BTreeMap<String, SetState>> {
    let ids: Vec<String> = {
        let mut st = c.prepare("SELECT provider_id FROM verdict_set_state")?;
        st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
    };
    let mut out = BTreeMap::new();
    for id in ids {
        if let Some(s) = read_state(c, &id)? {
            out.insert(id, s);
        }
    }
    Ok(out)
}

/// The verdict-set heads core names (`EdgeConfig.verdict_sets`): each provider's current head
/// under its current `cache_generation`.
pub fn current_heads(c: &rusqlite::Connection) -> rusqlite::Result<BTreeMap<String, String>> {
    let mut st = c.prepare(
        "SELECT s.provider_id, s.head_id FROM verdict_set_state s
         JOIN lookup_providers p ON p.id = s.provider_id AND p.cache_generation = s.generation",
    )?;
    st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect()
}

/// The overlay bytes each provider's current head costs an edge (edge.md §17).
pub fn overlay_bytes(c: &rusqlite::Connection) -> rusqlite::Result<BTreeMap<String, u64>> {
    let mut st = c.prepare(
        "SELECT s.provider_id, s.overlay_bytes FROM verdict_set_state s
         JOIN lookup_providers p ON p.id = s.provider_id AND p.cache_generation = s.generation",
    )?;
    st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
        ))
    })?
    .collect()
}

/// Reads pages of verdict-set bases from core's blob store (`pread`).
struct BlobPages {
    data_dir: PathBuf,
}

impl PageReader for BlobPages {
    fn read_page(&self, file: &str, file_page: u64, buf: &mut [u8; PAGE_SIZE]) -> std::io::Result<()> {
        let p = crate::blobs::path(&self.data_dir, file).map_err(|e| std::io::Error::other(e.to_string()))?;
        let f = std::fs::File::open(p)?;
        let at = file_page
            .checked_mul(PAGE_SIZE as u64)
            .ok_or_else(|| std::io::Error::other("page out of range"))?;
        f.read_exact_at(buf, at)
    }
}

/// A record as the set holds it for a stored row: `None` unless live now.
fn live_record(
    cache: &picket_api::edge_config::VerdictCacheSettings,
    verdict: Option<&str>,
    score: Option<f64>,
    reason: Option<String>,
    obtained_at: &str,
    now: Timestamp,
) -> Option<VerdictRecord> {
    let v = store::parse_verdict(verdict?)?;
    let at = crate::util::parse_ts(obtained_at)?;
    if !store::is_live(cache, v, at, now) {
        return None;
    }
    let rec = VerdictRecord {
        verdict: v,
        obtained_at: at,
        score: if v == VerdictKind::Block {
            score.map(crate::util::f64_to_f32).filter(|s| s.is_finite())
        } else {
            None
        },
        reason: if v == VerdictKind::Block {
            reason.map(|r| store::cut(&r, verdict::MAX_REASON).to_string())
        } else {
            None
        },
    };
    rec.canonical().ok()
}

/// The overlay bytes an edge holds for a chain's records (edge.md §17), measured on the same
/// table the edge builds, plus a tenth for the edge's own merges.
pub fn measure_overlay(entries: &HashMap<u128, Option<Vec<u8>>>) -> u64 {
    let it = entries.iter().map(|(h, v)| {
        let e = match v.as_deref().and_then(|b| VerdictRecord::decode(b).ok()) {
            Some(r) => Entry::Upsert(r),
            None => Entry::Tombstone,
        };
        (*h, e)
    });
    match HashOverlay::<VerdictRecord>::from_entries(it) {
        Ok(o) => {
            let b = o.memory_usage() as u64;
            b.saturating_add(b / 10)
        }
        Err(_) => u64::MAX,
    }
}

/// The publisher's loop: plans base rebuilds and deltas, submitted to the heavy lane.
pub async fn run(state: SharedState) {
    loop {
        if let Err(e) = plan(&state).await {
            tracing::warn!(error = %format!("{e:#}"), "planning verdict sets failed");
        }
        tokio::select! {
            _ = state.shutdown.cancelled() => return,
            _ = state.lookups.sets.wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

/// One planning pass (module docs).
pub async fn plan(state: &SharedState) -> Result<()> {
    let model = state.lookups.model();
    let sync = super::sync_providers(&model);
    let sync2 = sync.clone();
    let (rows, maxes) = state
        .db
        .read(move |c| {
            let rows = states(c)?;
            let mut maxes = BTreeMap::new();
            for p in &sync2 {
                let m: i64 = c.query_row(
                    "SELECT coalesce(max(changed_seq), 0) FROM lookup_verdicts WHERE provider_id = ?1",
                    [p],
                    |r| r.get(0),
                )?;
                maxes.insert(p.clone(), m);
            }
            Ok::<_, anyhow::Error>((rows, maxes))
        })
        .await?;
    // Providers no longer attached `sync` (or deleted): their state goes, their versions age out.
    let gone: Vec<String> = rows.keys().filter(|p| !sync.contains(p)).cloned().collect();
    if !gone.is_empty() {
        state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let now = crate::util::now_ts();
                for p in &gone {
                    tx.execute(
                        "UPDATE verdict_sets SET superseded_at = coalesce(superseded_at, ?2) WHERE provider_id = ?1",
                        params![p, now],
                    )?;
                    tx.execute("DELETE FROM verdict_set_state WHERE provider_id = ?1", [p])?;
                    tx.execute("DELETE FROM verdict_set_overlay WHERE provider_id = ?1", [p])?;
                }
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        state.edges.publisher.trigger(None);
    }
    // What a set holds depends on expiry, and its base on its age: both wait for a synchronised
    // wall clock (README §2 Clocks); edges keep their current sets meanwhile.
    if !state.clock.synced() {
        return Ok(());
    }
    let interval = Duration::from_secs(u64::from(state.settings().lookups.verdict_delta_s.max(1)));
    let now = crate::util::now();
    for p in sync {
        let Some(def) = model.lookup_providers.get(&p) else {
            continue;
        };
        let st = rows.get(&p);
        let base_due = match st {
            None => true,
            Some(s) => {
                s.generation != def.cache_generation
                    || s.deltas.len() >= MAX_DELTAS
                    || crate::util::parse_ts(&s.base_at).is_none_or(|t| {
                        std::time::Duration::try_from(now - t).unwrap_or(Duration::ZERO) >= MAX_BASE_AGE
                    })
                    || maxes.get(&p).copied().unwrap_or(0) - s.published_seq > MAX_DELTA_ROWS
            }
        };
        if base_due {
            submit_base(state, &p);
            continue;
        }
        let Some(s) = st else { continue };
        if maxes.get(&p).copied().unwrap_or(0) <= s.published_seq || state.lookups.sets.deferred(&p) {
            continue;
        }
        let urgent = state.lookups.sets.take_urgent(&p);
        let elapsed = state
            .lookups
            .sets
            .last_delta
            .lock()
            .ok()
            .and_then(|m| m.get(&p).map(|t| t.elapsed()))
            .is_none_or(|e| e >= interval);
        if urgent || elapsed {
            if let Ok(mut m) = state.lookups.sets.last_delta.lock() {
                m.insert(p.clone(), tokio::time::Instant::now());
            }
            submit_delta(state, &p);
        }
    }
    Ok(())
}

fn submit_base(state: &SharedState, provider: &str) {
    let st = state.clone();
    let p = provider.to_string();
    state
        .scheduler
        .heavy
        .submit_fn("verdict_base", provider, Priority::P2, move || async move {
            rebuild_base(&st, &p).await.map(|_| ())
        });
}

fn submit_delta(state: &SharedState, provider: &str) {
    state.scheduler.heavy.submit(
        Priority::P0,
        Box::new(DeltaJob(DeltaBuild::new(state.clone(), provider))),
    );
}

/// Asks for a rebuild of `provider`'s base (an overlay budget's compaction choosing this set,
/// bundles.md §5; [`crate::compiler::budget`]), in the heavy lane at P2 (coalesced per provider).
pub fn request_base(state: &SharedState, provider: &str) {
    submit_base(state, provider);
}

/// What a publish did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Published {
    /// A new head (its id).
    Head(String),
    /// Nothing changed in the set (only `published_seq` moved on).
    Unchanged,
    /// The provider isn't attached `sync`, or its generation moved on meanwhile.
    Skipped,
    /// Waiting for a compaction (bundles.md §5).
    Deferred,
    /// Waiting for a synchronised wall clock (README §2 Clocks: expiry decides what a set holds).
    ClockUnsynced,
}

/// Rebuilds a provider's base from its live rows (module docs).
pub async fn rebuild_base(state: &SharedState, provider: &str) -> Result<Published> {
    if !state.clock.synced() {
        return Ok(Published::ClockUnsynced);
    }
    let model = state.lookups.model();
    if !super::sync_providers(&model).iter().any(|p| p == provider) {
        return Ok(Published::Skipped);
    }
    let Some(def) = model.lookup_providers.get(provider).cloned() else {
        return Ok(Published::Skipped);
    };
    let generation = def.cache_generation.clone();
    let cache = def.settings.cache;
    let (pid, g) = (provider.to_string(), generation.clone());
    let now = crate::util::now();
    let (records, published_seq, total) = state
        .db
        .read(move |c| {
            // Every change numbered so far is in this snapshot (the counter only increases).
            let seq = store::last_seq(c, &pid)?;
            let seed = verdict_hash_seed(&pid, &g);
            let mut st = c.prepare(
                "SELECT name, verdict, score, reason, obtained_at FROM lookup_verdicts
                 WHERE provider_id = ?1 AND generation = ?2 AND verdict IS NOT NULL ORDER BY obtained_at DESC",
            )?;
            let mut rows = st.query(params![pid, g])?;
            let mut out: Vec<(KeyHash, VerdictRecord)> = Vec::new();
            let mut total = 0i64;
            while let Some(r) = rows.next()? {
                let name: String = r.get(0)?;
                let rec = live_record(&cache, r.get::<_, Option<String>>(1)?.as_deref(), r.get(2)?, r.get(3)?, &r.get::<_, String>(4)?, now);
                let Some(rec) = rec else { continue };
                total += 1;
                if crate::util::sat_i64(out.len()) < MAX_SET_RECORDS {
                    out.push((verdict::name_hash(seed, &name), rec));
                }
            }
            Ok::<_, anyhow::Error>((out, seq, total))
        })
        .await?;
    if total > MAX_SET_RECORDS {
        tracing::warn!(
            provider,
            total,
            kept = MAX_SET_RECORDS,
            "a verdict set holds only its newest records"
        );
    }
    let n = crate::util::sat_i64(records.len());
    let (p2, g2) = (provider.to_string(), generation.clone());
    let base = tokio::task::spawn_blocking(move || verdict::write_base(&p2, &g2, &records))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("write the verdict-set base")?;
    let head = VerdictHead {
        provider: provider.to_string(),
        format: picket_bundle::FORMAT,
        generation: generation.clone(),
        hash_seed: verdict_hash_seed(provider, &generation),
        base: base.blob.id.clone(),
        deltas: vec![],
        seq: 0,
        checksum: base.checksum,
        issued_at: crate::util::now_ts(),
    };
    let head_blob = head.to_blob();
    let data_dir = state.data_dir.clone();
    let (bb, hb) = (base.blob.bytes.clone(), head_blob.bytes.clone());
    tokio::task::spawn_blocking(move || -> Result<()> {
        crate::blobs::write_file(&data_dir, &bb)?;
        crate::blobs::write_file(&data_dir, &hb)?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))??;
    let st = SetState {
        provider: provider.to_string(),
        generation: generation.clone(),
        head_id: head_blob.id.clone(),
        base_id: base.blob.id.clone(),
        seq: 0,
        checksum: base.checksum,
        deltas: vec![],
        published_seq,
        base_records: n,
        overlay_entries: 0,
        overlay_bytes: 0,
        base_at: crate::util::now_ts(),
        published_at: crate::util::now_ts(),
    };
    let blobs = vec![
        (base.blob.id.clone(), base.blob.bytes.len() as u64),
        (head_blob.id.clone(), head_blob.bytes.len() as u64),
    ];
    let committed = commit(state, st, None, blobs, Some(HashMap::new()), &generation).await?;
    if !committed {
        return Ok(Published::Skipped);
    }
    metric(state, "verdict_set_bases", provider).await;
    state
        .metrics
        .gauge(
            &state.metrics_db,
            "verdict_set_records",
            crate::metrics::labels("", &[("provider", provider)]),
            n as f64,
        )
        .await;
    tracing::info!(provider, head = %picket_api::ids::short_id(&head_blob.id), records = n, "verdict-set base published");
    state.edges.publisher.trigger(None);
    Ok(Published::Head(head_blob.id))
}

async fn metric(state: &AppState, name: &str, provider: &str) {
    state
        .metrics
        .count(
            &state.metrics_db,
            vec![(
                name.to_string(),
                crate::metrics::labels("", &[("provider", provider)]),
                crate::util::now().as_millisecond(),
                1.0,
            )],
        )
        .await;
}

/// Stores a new head in one writer transaction: its blobs registered, the version row, the
/// blobs it names, the state, and the overlay rows (`overlay`: the whole overlay after a base
/// (empty), else the changes to merge). Only while the provider's state is still `expect` (or
/// absent, for a base) and its generation is still `generation`; returns false otherwise.
async fn commit(
    state: &AppState,
    st: SetState,
    expect_head: Option<String>,
    new_blobs: Vec<(String, u64)>,
    overlay: Option<HashMap<u128, Option<Vec<u8>>>>,
    generation: &str,
) -> Result<bool> {
    let generation = generation.to_string();
    let changes = overlay;
    state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let current_gen: Option<String> = tx
                .query_row(
                    "SELECT cache_generation FROM lookup_providers WHERE id = ?1",
                    [&st.provider],
                    |r| r.get(0),
                )
                .optional()?;
            if current_gen.as_deref() != Some(generation.as_str()) {
                return Ok::<_, anyhow::Error>(false);
            }
            let prev = read_state(&tx, &st.provider)?;
            if let Some(h) = &expect_head
                && prev.as_ref().map(|p| &p.head_id) != Some(h)
            {
                return Ok(false);
            }
            for (b3, size) in &new_blobs {
                crate::blobs::register_named(&tx, b3, crate::blobs::kind::VERDICT_SET, *size)?;
            }
            let now = crate::util::now_ts();
            tx.execute(
                "INSERT OR IGNORE INTO verdict_sets(provider_id, head_id, generation, published_at) VALUES (?1, ?2, ?3, ?4)",
                params![st.provider, st.head_id, st.generation, now],
            )?;
            // The blobs the version names: its head, base and every delta.
            let mut named: BTreeSet<String> = BTreeSet::from([st.head_id.clone(), st.base_id.clone()]);
            named.extend(st.deltas.iter().map(|d| d.blake3.clone()));
            for b in &named {
                tx.execute(
                    "INSERT OR IGNORE INTO verdict_set_blobs(provider_id, head_id, blake3) VALUES (?1, ?2, ?3)",
                    params![st.provider, st.head_id, b],
                )?;
            }
            if let Some(p) = &prev
                && p.head_id != st.head_id
            {
                tx.execute(
                    "UPDATE verdict_sets SET superseded_at = coalesce(superseded_at, ?3) WHERE provider_id = ?1 AND head_id = ?2",
                    params![st.provider, p.head_id, now],
                )?;
            }
            if st.deltas.is_empty() {
                tx.execute("DELETE FROM verdict_set_overlay WHERE provider_id = ?1", [&st.provider])?;
            }
            if let Some(ch) = &changes {
                for (h, v) in ch {
                    tx.execute(
                        "INSERT INTO verdict_set_overlay(provider_id, hash, value) VALUES (?1, ?2, ?3)
                         ON CONFLICT(provider_id, hash) DO UPDATE SET value = excluded.value",
                        params![st.provider, h.to_be_bytes().to_vec(), v],
                    )?;
                }
            }
            tx.execute(
                "INSERT INTO verdict_set_state(provider_id, generation, head_id, base_id, seq, checksum, deltas_json,
                     published_seq, base_records, overlay_entries, overlay_bytes, base_at, published_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(provider_id) DO UPDATE SET generation = excluded.generation, head_id = excluded.head_id,
                     base_id = excluded.base_id, seq = excluded.seq, checksum = excluded.checksum,
                     deltas_json = excluded.deltas_json, published_seq = excluded.published_seq,
                     base_records = excluded.base_records, overlay_entries = excluded.overlay_entries,
                     overlay_bytes = excluded.overlay_bytes, base_at = excluded.base_at,
                     published_at = excluded.published_at",
                params![
                    st.provider,
                    st.generation,
                    st.head_id,
                    st.base_id,
                    i64::try_from(st.seq).unwrap_or(i64::MAX),
                    st.checksum.to_hex(),
                    serde_json::to_string(&st.deltas)?,
                    st.published_seq,
                    st.base_records,
                    st.overlay_entries,
                    st.overlay_bytes,
                    st.base_at,
                    now
                ],
            )?;
            tx.commit()?;
            Ok(true)
        })
        .await
}

/// Publishes the rows changed since the head as a delta (module docs), running every step of
/// [`DeltaBuild`] at once (the publisher runs them as a stepped heavy job, [`DeltaJob`]).
pub async fn publish_delta(state: &SharedState, provider: &str) -> Result<Published> {
    let mut b = DeltaBuild::new(state.clone(), provider);
    loop {
        if let Some(p) = b.step().await? {
            return Ok(p);
        }
    }
}

/// A changed row as the delta reads it: name, verdict, score, reason, `obtained_at`,
/// `changed_seq`.
type ChangedRow = (String, Option<String>, Option<f64>, Option<String>, String, i64);

/// What a delta changes so far: one change per name hash (its first old record, its last new
/// one), found through `index` in O(1), and each touched name's record after the delta.
#[derive(Default)]
struct Diff {
    newest: i64,
    changes: Vec<VerdictChange>,
    index: HashMap<u128, usize>,
    touched: HashMap<u128, Option<Vec<u8>>>,
}

/// The parts of a set a delta's rows are diffed against.
struct DiffBase {
    pages: BlobPages,
    base_id: String,
    hdr: PageFileHeader,
    seed: u64,
    cache: picket_api::edge_config::VerdictCacheSettings,
    now: Timestamp,
}

/// Diffs `rows` (in `changed_seq` order) into `diff` against `overlay` and the base's pages
/// (blocking: page reads). Linear in the rows: repeats of a name collapse through the index.
/// `Err` when a base page can't be read.
fn diff_rows(
    diff: &mut Diff,
    rows: &[ChangedRow],
    overlay: &HashMap<u128, Option<Vec<u8>>>,
    b: &DiffBase,
) -> std::result::Result<(), String> {
    let mut buf = [0u8; PAGE_SIZE];
    for (name, v, score, reason, at, seq) in rows {
        diff.newest = diff.newest.max(*seq);
        let h = verdict::name_hash(b.seed, name);
        let new = live_record(&b.cache, v.as_deref(), *score, reason.clone(), at, b.now);
        let old: Option<VerdictRecord> = match diff.touched.get(&h.0).or_else(|| overlay.get(&h.0)) {
            Some(Some(bytes)) => VerdictRecord::decode(bytes).ok(),
            Some(None) => None,
            None => match page::read_record(
                &b.pages,
                &b.base_id,
                b.hdr.identity,
                b.hdr.page_count,
                h.0,
                &mut buf,
            ) {
                Ok(Some(bytes)) => VerdictRecord::decode(&bytes).ok(),
                Ok(None) => None,
                Err(e) => return Err(e.to_string()),
            },
        };
        if old == new {
            continue;
        }
        let bytes = match &new {
            Some(r) => Some(r.encode().map_err(|e| format!("encode a verdict record: {e}"))?),
            None => None,
        };
        diff.touched.insert(h.0, bytes);
        // Collapse repeats of one name within the delta: the first old, the last new.
        match diff.index.get(&h.0) {
            Some(&i) => diff.changes[i].new = new,
            None => {
                diff.index.insert(h.0, diff.changes.len());
                diff.changes.push(VerdictChange { hash: h, old, new });
            }
        }
    }
    Ok(())
}

/// Rows one step of a delta diffs (core.md §3 "Preemption by splitting": a delta of up to
/// [`MAX_DELTA_ROWS`] rows runs in bounded steps, each off the async runtime).
pub const DELTA_STEP_ROWS: usize = 10_000;

enum DeltaPhase {
    Load,
    Diff,
    Publish,
}

/// One delta, built in steps (module docs): load the head's state, overlay and changed rows;
/// diff them [`DELTA_STEP_ROWS`] at a time; then check the overlay budgets and publish.
pub struct DeltaBuild {
    state: SharedState,
    provider: String,
    phase: DeltaPhase,
    model: Option<std::sync::Arc<Model>>,
    generation: String,
    st: Option<SetState>,
    overlay: HashMap<u128, Option<Vec<u8>>>,
    rows: Vec<ChangedRow>,
    pos: usize,
    base: Option<DiffBase>,
    diff: Diff,
}

impl DeltaBuild {
    pub fn new(state: SharedState, provider: &str) -> Self {
        Self {
            state,
            provider: provider.to_string(),
            phase: DeltaPhase::Load,
            model: None,
            generation: String::new(),
            st: None,
            overlay: HashMap::new(),
            rows: Vec::new(),
            pos: 0,
            base: None,
            diff: Diff::default(),
        }
    }

    /// Runs one step; `Some` once the delta is done.
    pub async fn step(&mut self) -> Result<Option<Published>> {
        match self.phase {
            DeltaPhase::Load => self.load().await,
            DeltaPhase::Diff => self.diff_step().await,
            DeltaPhase::Publish => self.publish().await.map(Some),
        }
    }

    async fn load(&mut self) -> Result<Option<Published>> {
        let state = &self.state;
        let provider = self.provider.as_str();
        if !state.clock.synced() {
            return Ok(Some(Published::ClockUnsynced));
        }
        let model = state.lookups.model();
        if !super::sync_providers(&model).iter().any(|p| p == provider) {
            return Ok(Some(Published::Skipped));
        }
        let Some(def) = model.lookup_providers.get(provider).cloned() else {
            return Ok(Some(Published::Skipped));
        };
        let generation = def.cache_generation.clone();
        let cache = def.settings.cache;
        let (pid, g) = (provider.to_string(), generation.clone());
        let read = state
            .db
            .read(move |c| {
                let Some(st) = read_state(c, &pid)? else {
                    return Ok::<_, anyhow::Error>(None);
                };
                let mut overlay: HashMap<u128, Option<Vec<u8>>> = HashMap::new();
                {
                    let mut q =
                        c.prepare("SELECT hash, value FROM verdict_set_overlay WHERE provider_id = ?1")?;
                    let mut rows = q.query([&pid])?;
                    while let Some(r) = rows.next()? {
                        let h: Vec<u8> = r.get(0)?;
                        if let Ok(b) = <[u8; 16]>::try_from(h.as_slice()) {
                            overlay.insert(u128::from_be_bytes(b), r.get(1)?);
                        }
                    }
                }
                let mut q = c.prepare(
                    "SELECT name, verdict, score, reason, obtained_at, changed_seq FROM lookup_verdicts
                     WHERE provider_id = ?1 AND generation = ?2 AND changed_seq > ?3 ORDER BY changed_seq LIMIT ?4",
                )?;
                let rows: Vec<ChangedRow> = q
                    .query_map(params![pid, g, st.published_seq, MAX_DELTA_ROWS], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
                    })?
                    .collect::<rusqlite::Result<_>>()?;
                Ok(Some((st, overlay, rows)))
            })
            .await?;
        let Some((st, overlay, rows)) = read else {
            return rebuild_base(state, provider).await.map(Some);
        };
        if st.generation != generation {
            return rebuild_base(state, provider).await.map(Some);
        }
        // The base's header, for page reads of old records.
        let hdr = {
            let pages = BlobPages {
                data_dir: state.data_dir.clone(),
            };
            let id = st.base_id.clone();
            tokio::task::spawn_blocking(move || -> Result<PageFileHeader> {
                let mut buf = [0u8; PAGE_SIZE];
                pages.read_page(&id, 0, &mut buf)?;
                PageFileHeader::parse(&buf).map_err(|e| anyhow::anyhow!("verdict-set base header: {e}"))
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        };
        let hdr = match hdr {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(provider, error = %format!("{e:#}"), "the verdict-set base can't be read; rebuilding it");
                return rebuild_base(state, provider).await.map(Some);
            }
        };
        self.base = Some(DiffBase {
            pages: BlobPages {
                data_dir: state.data_dir.clone(),
            },
            base_id: st.base_id.clone(),
            hdr,
            seed: verdict_hash_seed(provider, &generation),
            cache,
            now: crate::util::now(),
        });
        self.diff.newest = st.published_seq;
        self.model = Some(model);
        self.generation = generation;
        self.st = Some(st);
        self.overlay = overlay;
        self.rows = rows;
        self.phase = DeltaPhase::Diff;
        Ok(None)
    }

    async fn diff_step(&mut self) -> Result<Option<Published>> {
        let end = (self.pos + DELTA_STEP_ROWS).min(self.rows.len());
        let chunk: Vec<ChangedRow> = self.rows[self.pos..end].to_vec();
        let (mut diff, overlay, base) = (
            std::mem::take(&mut self.diff),
            std::mem::take(&mut self.overlay),
            self.base.take().context("a delta diffed before it loaded")?,
        );
        let (diff, overlay, base, r) = tokio::task::spawn_blocking(move || {
            let r = diff_rows(&mut diff, &chunk, &overlay, &base);
            (diff, overlay, base, r)
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.diff = diff;
        self.overlay = overlay;
        self.base = Some(base);
        if let Err(e) = r {
            tracing::warn!(provider = %self.provider, error = %e, "a verdict-set base page can't be read; rebuilding it");
            return rebuild_base(&self.state, &self.provider).await.map(Some);
        }
        self.pos = end;
        if self.pos >= self.rows.len() {
            self.rows = Vec::new();
            self.phase = DeltaPhase::Publish;
        }
        Ok(None)
    }

    async fn publish(&mut self) -> Result<Published> {
        let state = &self.state;
        let provider = self.provider.as_str();
        let st = self.st.take().context("a delta published before it loaded")?;
        let model = self.model.take().context("a delta published before it loaded")?;
        let generation = self.generation.clone();
        let mut diff = std::mem::take(&mut self.diff);
        let mut overlay = std::mem::take(&mut self.overlay);
        let newest = diff.newest;
        diff.changes.retain(|c| c.old != c.new);
        let changes = diff.changes;
        let touched = diff.touched;
        if changes.is_empty() {
            let (pid, head) = (provider.to_string(), st.head_id.clone());
            state
                .db
                .write(move |c| {
                    c.execute(
                        "UPDATE verdict_set_state SET published_seq = max(published_seq, ?3) WHERE provider_id = ?1 AND head_id = ?2",
                        params![pid, head, newest],
                    )?;
                    Ok::<_, anyhow::Error>(())
                })
                .await?;
            return Ok(Published::Unchanged);
        }
        // The overlay after this delta, and what it costs an edge.
        for (h, v) in &touched {
            overlay.insert(*h, v.clone());
        }
        if overlay.len() > picket_bundle::overlay::MAX_OVERLAY_ENTRIES / 2 {
            return rebuild_base(state, provider).await;
        }
        let bytes = measure_overlay(&overlay);
        match compaction(state, &model, provider, bytes).await? {
            Compaction::Fits => {}
            Compaction::RebuildThis => return rebuild_base(state, provider).await,
            Compaction::Wait => {
                state.lookups.sets.defer(provider);
                return Ok(Published::Deferred);
            }
        }
        let seed = verdict_hash_seed(provider, &generation);
        let seq = st.seq + 1;
        let created = crate::util::now_ts();
        let (blob, header) = verdict::write_delta(
            provider,
            &generation,
            &st.base_id,
            seq,
            st.checksum,
            &changes,
            &created,
        )
        .context("write the verdict-set delta")?;
        let mut deltas = st.deltas.clone();
        deltas.push(DeltaRef {
            seq,
            blake3: blob.id.clone(),
            size: blob.size(),
        });
        let head = VerdictHead {
            provider: provider.to_string(),
            format: picket_bundle::FORMAT,
            generation: generation.clone(),
            hash_seed: seed,
            base: st.base_id.clone(),
            deltas: deltas.clone(),
            seq,
            checksum: header.new_checksum,
            issued_at: created.clone(),
        };
        let head_blob = head.to_blob();
        let data_dir = state.data_dir.clone();
        let (db, hb) = (blob.bytes.clone(), head_blob.bytes.clone());
        tokio::task::spawn_blocking(move || -> Result<()> {
            crate::blobs::write_file(&data_dir, &db)?;
            crate::blobs::write_file(&data_dir, &hb)?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))??;
        let new_st = SetState {
            head_id: head_blob.id.clone(),
            seq,
            checksum: header.new_checksum,
            deltas,
            published_seq: newest,
            overlay_entries: crate::util::sat_i64(overlay.len()),
            overlay_bytes: i64::try_from(bytes).unwrap_or(i64::MAX),
            ..st.clone()
        };
        let blobs = vec![
            (blob.id.clone(), blob.bytes.len() as u64),
            (head_blob.id.clone(), head_blob.bytes.len() as u64),
        ];
        let ok = commit(
            state,
            new_st,
            Some(st.head_id.clone()),
            blobs,
            Some(touched),
            &generation,
        )
        .await?;
        if !ok {
            return Ok(Published::Skipped);
        }
        metric(state, "verdict_set_deltas", provider).await;
        state
            .metrics
            .gauge(
                &state.metrics_db,
                "verdict_set_overlay_bytes",
                crate::metrics::labels("", &[("provider", provider)]),
                bytes as f64,
            )
            .await;
        tracing::debug!(provider, head = %picket_api::ids::short_id(&head_blob.id), seq, changes = changes.len(), "verdict-set delta published");
        state.edges.publisher.trigger(None);
        Ok(Published::Head(head_blob.id))
    }
}

/// A delta as the heavy lane runs it: one [`DeltaBuild`] step per scheduler step.
struct DeltaJob(DeltaBuild);

impl crate::scheduler::HeavyJob for DeltaJob {
    fn kind(&self) -> &str {
        "verdict_delta"
    }

    fn target(&self) -> &str {
        &self.0.provider
    }

    fn step(&mut self) -> crate::scheduler::BoxFuture<'_, Result<crate::scheduler::Step>> {
        Box::pin(async move {
            Ok(match self.0.step().await? {
                Some(_) => crate::scheduler::Step::Done,
                None => crate::scheduler::Step::More,
            })
        })
    }
}

/// What the overlay budgets ask before a delta.
enum Compaction {
    Fits,
    /// This set's overlay is the largest part on an edge it would push over: rebuild its base.
    RebuildThis,
    /// Another part was asked to compact first; the delta waits.
    Wait,
}

/// Checks every edge's overlay budget against the delta (bundles.md §5; module docs).
/// An edge as compaction sees it: its name, overlay budget (bytes) and the bundle heads its
/// config names.
type EdgeHeads = (String, u64, Vec<(String, String)>);

async fn compaction(
    state: &SharedState,
    model: &Model,
    provider: &str,
    new_bytes: u64,
) -> Result<Compaction> {
    let mut edges: Vec<EdgeHeads> = Vec::new();
    for (id, e) in &model.edges {
        let Some(p) = state.edges.publisher.current(id) else {
            continue;
        };
        let budget = u64::from(e.settings.overlay_budget(e.platform)).saturating_mul(1 << 20);
        let heads: Vec<(String, String)> = p
            .config
            .bundles
            .iter()
            .map(|(b, h)| (b.clone(), h.clone()))
            .collect();
        edges.push((e.name.clone(), budget, heads));
    }
    if edges.is_empty() {
        return Ok(Compaction::Fits);
    }
    let all: Vec<(String, String)> = edges.iter().flat_map(|(_, _, h)| h.iter().cloned()).collect();
    let (sizes, sets, current, parts) = state
        .db
        .read(move |c| {
            let sizes = crate::compiler::store::head_sizes(c, &all)?;
            let sets = overlay_bytes(c)?;
            let current = crate::compiler::store::current_heads(c)?;
            let bundles: BTreeSet<&String> = all.iter().map(|(b, _)| b).collect();
            let parts = crate::compiler::store::overlay_parts(c, bundles.into_iter())?;
            Ok::<_, anyhow::Error>((sizes, sets, current, parts))
        })
        .await?;
    let mut wait = false;
    for (edge, budget, heads) in edges {
        let mut total = 0u64;
        // (bytes, which): a bundle part ("b", bundle, part), a set ("s", provider, "").
        let mut largest: Option<(u64, &'static str, String, String)> = None;
        let mut consider = |b: u64, kind: &'static str, x: String, y: String| {
            if largest.as_ref().is_none_or(|l| b > l.0) {
                largest = Some((b, kind, x, y));
            }
        };
        for (b, h) in &heads {
            let ov = sizes.get(h).map_or(0, |s| s.overlay_bytes);
            total = total.saturating_add(ov);
            if current.get(b) == Some(h) {
                for (part, bytes) in parts.get(b).cloned().unwrap_or_default() {
                    consider(bytes, "b", b.clone(), part);
                }
            }
        }
        for (p, b) in &sets {
            if p != provider {
                total = total.saturating_add(*b);
                consider(*b, "s", p.clone(), String::new());
            }
        }
        total = total.saturating_add(new_bytes);
        consider(new_bytes, "s", provider.to_string(), String::new());
        if total <= budget {
            continue;
        }
        match largest {
            Some((_, "s", p, _)) if p == provider => return Ok(Compaction::RebuildThis),
            Some((_, "s", p, _)) => {
                submit_base(state, &p);
                wait = true;
            }
            Some((_, _, bundle, part)) => {
                state.compiler.request(
                    state,
                    &bundle,
                    crate::compiler::Request {
                        reasons: BTreeSet::from([format!(
                            "overlay budget of edge {edge} (verdict set {provider})"
                        )]),
                        compact: BTreeSet::from([part]),
                        ..crate::compiler::Request::default()
                    },
                    Priority::P2,
                );
                wait = true;
            }
            None => return Ok(Compaction::RebuildThis),
        }
    }
    Ok(if wait { Compaction::Wait } else { Compaction::Fits })
}

/// Retention of verdict-set versions and their blobs (module docs; as `compiler::retention` for
/// bundle versions).
pub struct SetRetention;

impl crate::retention::RetentionHook for SetRetention {
    fn name(&self) -> &str {
        "verdict_sets"
    }

    fn step<'a>(
        &'a self,
        state: &'a AppState,
    ) -> crate::scheduler::BoxFuture<'a, Result<crate::scheduler::Step>> {
        Box::pin(async move {
            let window = state.settings().retention.bundle_versions.as_duration();
            let now = Timestamp::now();
            let cutoff = crate::util::ts(&crate::util::window_start(now, window));
            let grace = crate::util::ts(&(now - BLOB_GRACE));
            let now_s = crate::util::ts(&now);
            // Heads in configs core serves now, and those online edges report keeping.
            let mut used: Vec<(String, String)> = Vec::new();
            for e in state.edges.hub.edge_ids() {
                if let Some(p) = state.edges.publisher.current(&e) {
                    used.extend(p.config.verdict_sets.iter().map(|(p, h)| (p.clone(), h.clone())));
                }
                let live = state.edges.hub.live(&e);
                for (p, hs) in live
                    .have
                    .verdict_sets
                    .iter()
                    .chain(live.have.in_progress.verdict_sets.iter())
                {
                    used.extend(hs.iter().map(|h| (p.clone(), h.clone())));
                }
            }
            let data_dir = state.data_dir.clone();
            let more = state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    tx.execute(
                        "UPDATE verdict_sets SET last_used_at = ?1 WHERE EXISTS (SELECT 1 FROM verdict_set_state s
                           WHERE s.provider_id = verdict_sets.provider_id AND s.head_id = verdict_sets.head_id)",
                        [&now_s],
                    )?;
                    tx.execute(
                        "UPDATE verdict_sets SET last_used_at = ?1 WHERE EXISTS (SELECT 1 FROM edge_pins p
                           WHERE p.kind = 'verdict_set' AND p.target = verdict_sets.provider_id AND p.id = verdict_sets.head_id)",
                        [&now_s],
                    )?;
                    {
                        let mut stamp = tx.prepare_cached(
                            "UPDATE verdict_sets SET last_used_at = ?3 WHERE provider_id = ?1 AND head_id = ?2",
                        )?;
                        for (p, h) in &used {
                            stamp.execute(params![p, h, now_s])?;
                        }
                    }
                    let gone: Vec<(String, String)> = {
                        let mut st = tx.prepare(
                            "SELECT provider_id, head_id FROM verdict_sets
                             WHERE coalesce(last_used_at, superseded_at, published_at) < ?1
                               AND NOT EXISTS (SELECT 1 FROM verdict_set_state s WHERE s.provider_id = verdict_sets.provider_id
                                                 AND s.head_id = verdict_sets.head_id)
                               AND NOT EXISTS (SELECT 1 FROM edge_pins p WHERE p.kind = 'verdict_set'
                                                 AND p.target = verdict_sets.provider_id AND p.id = verdict_sets.head_id)
                             LIMIT ?2",
                        )?;
                        st.query_map(params![cutoff, crate::retention::CHUNK], |r| Ok((r.get(0)?, r.get(1)?)))?
                            .collect::<rusqlite::Result<_>>()?
                    };
                    for (p, h) in &gone {
                        tx.execute(
                            "UPDATE blobs SET refcount = max(refcount - 1, 0) WHERE blake3 IN
                               (SELECT blake3 FROM verdict_set_blobs WHERE provider_id = ?1 AND head_id = ?2)",
                            params![p, h],
                        )?;
                        tx.execute(
                            "DELETE FROM verdict_set_blobs WHERE provider_id = ?1 AND head_id = ?2",
                            params![p, h],
                        )?;
                        tx.execute(
                            "DELETE FROM verdict_sets WHERE provider_id = ?1 AND head_id = ?2",
                            params![p, h],
                        )?;
                    }
                    // Verdict-set blobs nothing names: no retained version, nor a row of another
                    // kind naming the same bytes (`crate::blobs` Collection).
                    let blobs = crate::blobs::unreferenced(
                        &tx,
                        &[crate::blobs::kind::VERDICT_SET],
                        Some(&grace),
                        1000,
                    )?;
                    for b in &blobs {
                        tx.execute("DELETE FROM blobs WHERE blake3 = ?1", [b])?;
                    }
                    tx.commit()?;
                    // In the writer's turn: no publish can register one of these between the
                    // commit and the removal (as for bundle blobs).
                    for b in &blobs {
                        if let Ok(p) = crate::blobs::path(&data_dir, b) {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                    Ok::<_, anyhow::Error>(crate::util::sat_i64(gone.len()) >= crate::retention::CHUNK || blobs.len() >= 1000)
                })
                .await?;
            Ok(if more {
                crate::scheduler::Step::More
            } else {
                crate::scheduler::Step::Done
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_records_are_canonical_and_drop_expired_and_tombstones() {
        let cache = picket_api::edge_config::VerdictCacheSettings::default();
        let now = crate::util::now();
        let at = crate::util::ts(&(now - jiff::SignedDuration::from_mins(5)));
        let r = live_record(&cache, Some("block"), Some(7.5), Some("malware".into()), &at, now).unwrap();
        assert_eq!(r.verdict, VerdictKind::Block);
        assert_eq!(r.score, Some(7.5));
        assert_eq!(r.reason.as_deref(), Some("malware"));
        // A Clean keeps no score or reason.
        let r = live_record(&cache, Some("clean"), Some(1.0), Some("x".into()), &at, now).unwrap();
        assert_eq!((r.score, r.reason), (None, None));
        // Unknown expires after 60 s; tombstones are never records.
        assert!(live_record(&cache, Some("unknown"), None, None, &at, now).is_none());
        assert!(live_record(&cache, None, None, None, &at, now).is_none());
    }

    /// L10 (core.md §3): a delta's diff is linear in its rows: one change per name, its first
    /// old record and its last new one; a name back to its old record drops out.
    #[test]
    fn deltas_diff_in_one_pass_and_collapse_repeats() {
        let dir = tempfile::tempdir().unwrap();
        let seed = verdict_hash_seed("q9", "b71e4d09a2c63f58");
        let now = crate::util::now();
        let at = |m: i64| now - jiff::SignedDuration::from_mins(m);
        let rec = |v: VerdictKind, a: Timestamp| {
            VerdictRecord {
                verdict: v,
                obtained_at: a,
                score: None,
                reason: (v == VerdictKind::Block).then(|| "risk".to_string()),
            }
            .canonical()
            .unwrap()
        };
        // The base holds one Block.
        let base = verdict::write_base(
            "q9",
            "b71e4d09a2c63f58",
            &[(
                verdict::name_hash(seed, "kept.example"),
                rec(VerdictKind::Block, at(50)),
            )],
        )
        .unwrap();
        crate::blobs::write_file(dir.path(), &base.blob.bytes).unwrap();
        let pages = BlobPages {
            data_dir: dir.path().to_path_buf(),
        };
        let mut buf = [0u8; PAGE_SIZE];
        pages.read_page(&base.blob.id, 0, &mut buf).unwrap();
        let b = DiffBase {
            pages,
            base_id: base.blob.id.clone(),
            hdr: PageFileHeader::parse(&buf).unwrap(),
            seed,
            cache: picket_api::edge_config::VerdictCacheSettings::default(),
            now,
        };
        let row = |name: &str, v: Option<&str>, m: i64, seq: i64| -> ChangedRow {
            (
                name.to_string(),
                v.map(str::to_string),
                None,
                v.filter(|v| *v == "block").map(|_| "risk".to_string()),
                crate::util::ts(&at(m)),
                seq,
            )
        };
        let mut rows: Vec<ChangedRow> = Vec::new();
        // 20,000 distinct new names, each written twice (Clean, then Block).
        for i in 0..20_000 {
            rows.push(row(&format!("n{i}.example"), Some("clean"), 40, 2 * i + 1));
        }
        for i in 0..20_000 {
            rows.push(row(&format!("n{i}.example"), Some("block"), 30, 40_000 + i));
        }
        // The base's Block replaced, then back to an equal record: no change.
        rows.push(row("kept.example", Some("clean"), 20, 70_000));
        rows.push(row("kept.example", Some("block"), 50, 70_001));
        let mut diff = Diff::default();
        let overlay = HashMap::new();
        for chunk in rows.chunks(DELTA_STEP_ROWS) {
            diff_rows(&mut diff, chunk, &overlay, &b).unwrap();
        }
        assert_eq!(diff.newest, 70_001);
        diff.changes.retain(|c| c.old != c.new);
        assert_eq!(diff.changes.len(), 20_000);
        let c = &diff.changes[7];
        assert_eq!(c.old, None, "the first old record");
        assert_eq!(
            c.new.as_ref().map(|r| r.verdict),
            Some(VerdictKind::Block),
            "the last new one"
        );
    }

    #[test]
    fn overlay_measure_grows_with_entries() {
        let mut m: HashMap<u128, Option<Vec<u8>>> = HashMap::new();
        assert_eq!(measure_overlay(&m), 0);
        let rec = VerdictRecord {
            verdict: VerdictKind::Block,
            obtained_at: crate::util::now(),
            score: None,
            reason: Some("x".repeat(40)),
        };
        for i in 0..1000u128 {
            m.insert(i, Some(rec.encode().unwrap()));
        }
        let a = measure_overlay(&m);
        assert!(a > 1000 * 40, "{a}");
        m.insert(5000, None);
        assert!(measure_overlay(&m) >= a);
    }
}
