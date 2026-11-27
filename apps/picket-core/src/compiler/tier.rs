//! Hot/cold tiering (bundles.md §1 Tiers, §2 Tiering).
//!
//! - **Placement** ([`place`]): only plain block keys (`B_EXACT` and/or `B_SUBS` alone, no rich
//!   rules) may go cold; the key takes the hottest tier of the feeds listing it (hot >
//!   intelligent-tiering > cold). An intelligent-tiering key is hot without `hot_max_mib`;
//!   with it, the last re-rank's cutoffs decide: a cold key becomes hot when it ranks within
//!   `hot_max_mib` less 5 % (`enter`), a hot one stays while it ranks within `hot_max_mib`
//!   (`stay`). Until the first re-rank every intelligent-tiering key is hot.
//! - **Rank:** the later of the key's `last_hit_at` (`bundle_key_hits`, keyed by the key's
//!   128-bit hash, big-endian, as `bundle_keys.hash128`) and its `first_seen` (the earliest
//!   `first_seen_at` among its intelligent-tiering feeds), most recent first; ties by hash.
//! - **Re-rank** ([`Rerank`], bounded steps): the hot-tier keys (and the keys that always stay hot) count first,
//!   then intelligent-tiering keys fill the hot part in rank order up to `hot_max_mib`; if the
//!   hot-tier keys alone exceed it every intelligent-tiering key goes cold and
//!   `bundle_over_budget` reports it (the version is still published). The build that applies new
//!   cutoffs recomputes every intelligent-tiering key, so moves (both sides in one head) and their
//!   descendants follow.
//! - **Promotions:** a hit on a cold intelligent-tiering key after the last build makes it a
//!   changed key of the next build, which ranks it at the top ([`insert_promotions`]).
//!
//! - **Dry run** ([`DryRunJob`], [`dry_runs_due`]): before the first split, and whenever
//!   `hot_max_mib` or a feed's `tier` changes, core replays the last 72 h of logs (or the log
//!   window, if shorter) against the proposed split and reports how many of the bundle's blocks
//!   would have come from cold (`tier_dry_runs`, shown with the bundle's status). Each block
//!   logged from a key (`reason.key`) is placed as the proposed definition would place that key:
//!   only a plain block key may go cold, it takes the hottest proposed tier of the member feeds
//!   that list it, and an `intelligent-tiering` key is ranked against the proposed `hot_max_mib`
//!   by the same rank the re-rank uses (most recent first, ties by hash: [`Cutoff`]), as it stood
//!   when the window began (hits inside the window don't count for the key itself). The keys that
//!   always stay hot are counted from the bundle's current keys.
//!   - **When:** a proposal is dry run as soon as core sees it (a configuration change, a start;
//!     the analysis loop re-checks every minute as a backstop), on the heavy lane at P2 in bounded
//!     steps (a partition's block total, then its logged keys a page at a time, read through the
//!     partition's `bundle` index where it has one) that persist their position and counts, so a
//!     P0 delta runs between steps and a restart resumes.
//!   - **The split waits for the report** ([`effective_spec`]): until the dry run of a proposal has
//!     finished, or [`DRY_RUN_HOLD`] has passed since core first saw it, builds apply the split the
//!     bundle's builds last applied (none: every key hot), so feed updates keep going out; the
//!     report (or the end of the hold) builds the split. A proposal that moves every feed back to
//!     hot waits too when the split last applied had cold keys (it is a tier change). The split
//!     last applied survives a config restore (`config::export::TABLES`); rows of bundles no
//!     longer configured go ([`submit_dry_runs`]).
//!
//! `last_hit_at` is written by attribution and core's check of unchecked cold lookups
//! (`logs::analysis`).

use std::collections::HashMap;

use anyhow::Result;
use picket_bundle::hash::KeyHash;
use picket_rules::compile::{KeyValue, Part};
use rusqlite::{Connection, OptionalExtension, params};

use super::source::Row;
use super::spec::Spec;
use super::store::{BuildState, KeyState, Rank, TierCutoffs};
use crate::config::model::Tier;
use crate::state::SharedState;

/// Bytes one hot key costs on the edge (filter 1.13 B + FST 12–14 B, edge.md §17), for
/// `hot_max_mib` accounting.
pub const HOT_BYTES_PER_KEY: u64 = 15;

/// The hex a rank compares hashes by.
pub fn hash_hex(h: KeyHash) -> String {
    format!("{:032X}", h.0)
}

fn tier_rank(t: Tier) -> u8 {
    match t {
        Tier::Cold => 0,
        Tier::IntelligentTiering => 1,
        Tier::Hot => 2,
    }
}

/// A key's part, its tier (for cold-eligible keys) and its rank time (intelligent-tiering).
#[expect(
    clippy::too_many_arguments,
    reason = "one key's placement over the caller's tier state"
)]
pub fn place(
    c: &Connection,
    bundle: &str,
    spec: &Spec,
    cutoffs: Option<&TierCutoffs>,
    kv: &KeyValue,
    rows: &[Row],
    tiers: &HashMap<&str, Tier>,
    old: Option<&KeyState>,
    hash: KeyHash,
) -> Result<(Part, Option<String>, Option<String>)> {
    if !spec.cold_capable() || !kv.flags.is_plain_block() || !kv.rich.is_empty() {
        return Ok((Part::Hot, None, None));
    }
    let hottest = rows
        .iter()
        .filter_map(|r| tiers.get(r.feed.as_str()).copied())
        .max_by_key(|t| tier_rank(*t))
        .unwrap_or(Tier::Hot);
    match hottest {
        Tier::Hot => Ok((Part::Hot, Some(Tier::Hot.as_str().into()), None)),
        Tier::Cold => Ok((Part::Cold, Some(Tier::Cold.as_str().into()), None)),
        Tier::IntelligentTiering => {
            let rank_at = rows
                .iter()
                .filter(|r| tiers.get(r.feed.as_str()) == Some(&Tier::IntelligentTiering))
                .map(|r| r.first_seen_at.clone())
                .min();
            let name = Some(Tier::IntelligentTiering.as_str().to_string());
            if spec.hot_max_mib.is_none() {
                return Ok((Part::Hot, name, rank_at));
            }
            let Some(cut) = cutoffs else {
                return Ok((Part::Hot, name, rank_at));
            };
            if cut.hot_tier_over {
                return Ok((Part::Cold, name, rank_at));
            }
            let hit: Option<String> = c
                .query_row(
                    "SELECT last_hit_at FROM bundle_key_hits WHERE bundle_id = ?1 AND hash128 = ?2",
                    params![bundle, &hash.0.to_be_bytes()[..]],
                    |r| r.get(0),
                )
                .optional()?;
            let at = match (rank_at.as_deref(), hit.as_deref()) {
                (Some(a), Some(b)) => a.max(b).to_string(),
                (Some(a), None) => a.to_string(),
                (None, Some(b)) => b.to_string(),
                (None, None) => String::new(),
            };
            let rank = Rank {
                at,
                hash: hash_hex(hash),
            };
            let within = |r: &Option<Rank>| r.as_ref().is_some_and(|cut| rank.at_or_above(cut));
            let hot = match old {
                Some(o) if o.part == Part::Hot => within(&cut.stay),
                _ => within(&cut.enter),
            };
            Ok((if hot { Part::Hot } else { Part::Cold }, name, rank_at))
        }
    }
}

/// True when a cold intelligent-tiering key of the bundle was hit after the last build.
pub async fn pending_promotions(state: &SharedState, bundle: &str, st: &BuildState) -> Result<bool> {
    let (b, last) = (bundle.to_string(), st.last_build_at.clone().unwrap_or_default());
    state
        .db
        .read(move |c| {
            Ok::<_, anyhow::Error>(
                c.query_row(
                    "SELECT 1 FROM bundle_key_hits h JOIN bundle_keys k
                       ON k.bundle_id = h.bundle_id AND k.hash128 = h.hash128 AND k.tier = 'intelligent-tiering'
                     WHERE h.bundle_id = ?1 AND k.part = 'cold' AND h.last_hit_at > ?2 LIMIT 1",
                    params![b, last],
                    |_| Ok(()),
                )
                .optional()?
                .is_some(),
            )
        })
        .await
}

/// Adds the cold intelligent-tiering keys hit since `last` to the build's keys.
pub fn insert_promotions(
    tx: &rusqlite::Transaction<'_>,
    bundle: &str,
    last: Option<&str>,
) -> rusqlite::Result<usize> {
    tx.execute(
        "INSERT OR IGNORE INTO bundle_build_keys(bundle_id, key)
         SELECT k.bundle_id, k.key FROM bundle_key_hits h JOIN bundle_keys k
           ON k.bundle_id = h.bundle_id AND k.hash128 = h.hash128 AND k.tier = 'intelligent-tiering'
         WHERE h.bundle_id = ?1 AND k.part = 'cold' AND h.last_hit_at > ?2",
        params![bundle, last.unwrap_or("")],
    )
}

/// Keys one re-rank step reads (core.md §3: bounded steps).
pub const RANK_ROWS_PER_STEP: usize = 50_000;

/// The re-rank (bundles.md §2 Tiering) in bounded steps: a pass over the bundle's keys counts the
/// keys that are always hot and files each intelligent-tiering key in `bundle_build_rank` by its
/// rank (most recent first, ties by hash), a page per step; then a walk in rank order fills the
/// hot part up to `hot_max_mib`, a page per step. The cutoffs equal a sort of every key at once.
pub struct Rerank {
    budget: u64,
    cursor: String,
    /// Hot keys that aren't intelligent-tiering (they count first).
    base: u64,
    filled: bool,
    after: Option<(Vec<u8>, Vec<u8>)>,
    bytes: u64,
    enter: Option<Rank>,
    stay: Option<Rank>,
    ranked: u64,
}

impl Rerank {
    /// A re-rank of a bundle with `hot_max_mib` (`None`: nothing to rank).
    pub fn new(spec: &Spec) -> Option<Rerank> {
        let mib = spec.hot_max_mib?;
        Some(Rerank {
            budget: u64::from(mib).saturating_mul(1024 * 1024),
            cursor: String::new(),
            base: 0,
            filled: false,
            after: None,
            bytes: 0,
            enter: None,
            stay: None,
            ranked: 0,
        })
    }
}

/// A rank time as a key that sorts most recent first: every byte inverted, then 0xFF (so a
/// shorter time that is a prefix of a longer one sorts after it).
fn rank_key(r: &str) -> Vec<u8> {
    let mut v: Vec<u8> = r.bytes().map(|b| !b).collect();
    v.push(0xFF);
    v
}

/// One re-rank step; `Some(cutoffs)` when done (`None` inside: nothing to rank yet, every key
/// starts hot).
pub async fn rerank_step(
    state: &SharedState,
    bundle: &str,
    rr: &mut Rerank,
) -> Result<Option<Option<TierCutoffs>>> {
    let b = bundle.to_string();
    let per_step = state.compiler.step_rows(RANK_ROWS_PER_STEP);
    if !rr.filled {
        let cursor = rr.cursor.clone();
        let (rows, base, last) = state
            .db
            .read(move |c| {
                let mut st = c.prepare_cached(
                    "SELECT k.key, k.part, k.tier, k.hash128,
                        max(coalesce(h.last_hit_at, ''), coalesce(k.rank_at, ''))
                     FROM bundle_keys k LEFT JOIN bundle_key_hits h ON h.bundle_id = k.bundle_id AND h.hash128 = k.hash128
                     WHERE k.bundle_id = ?1 AND k.key > ?2 ORDER BY k.key LIMIT ?3",
                )?;
                let mut rows = st.query(params![b, cursor, per_step])?;
                let (mut out, mut base, mut last, mut n) = (Vec::new(), 0u64, None, 0usize);
                while let Some(r) = rows.next()? {
                    n += 1;
                    let key: String = r.get(0)?;
                    let part: String = r.get(1)?;
                    let tier: Option<String> = r.get(2)?;
                    let it = tier.as_deref() == Some(Tier::IntelligentTiering.as_str());
                    if it {
                        let rank: String = r.get(4)?;
                        out.push((rank_key(&rank), r.get::<_, Vec<u8>>(3)?, rank));
                    } else if part == "hot" {
                        base += 1;
                    }
                    last = Some(key);
                }
                let last = if n >= per_step { last } else { None };
                Ok::<_, anyhow::Error>((out, base, last))
            })
            .await?;
        rr.base += base;
        if !rows.is_empty() {
            let b = bundle.to_string();
            state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    {
                        let mut st = tx.prepare_cached(
                            "INSERT OR REPLACE INTO bundle_build_rank(bundle_id, rkey, hash128, r) VALUES (?1, ?2, ?3, ?4)",
                        )?;
                        for (k, h, r) in &rows {
                            st.execute(params![b, k, h, r])?;
                        }
                    }
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(())
                })
                .await?;
        }
        match last {
            Some(k) => rr.cursor = k,
            None => {
                rr.filled = true;
                rr.bytes = rr.base.saturating_mul(HOT_BYTES_PER_KEY);
                if rr.bytes >= rr.budget {
                    return Ok(Some(Some(TierCutoffs {
                        enter: None,
                        stay: None,
                        hot_tier_over: true,
                    })));
                }
            }
        }
        return Ok(None);
    }
    let after = rr.after.clone();
    let rows: Vec<(Vec<u8>, Vec<u8>, String)> = state
        .db
        .read(move |c| {
            let (k, h) = after.unwrap_or_default();
            let mut st = c.prepare_cached(
                "SELECT rkey, hash128, r FROM bundle_build_rank WHERE bundle_id = ?1 AND (rkey, hash128) > (?2, ?3)
                 ORDER BY rkey, hash128 LIMIT ?4",
            )?;
            let v = st
                .query_map(params![b, k, h, per_step], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    let enter_budget = rr.budget.saturating_sub(rr.budget / 20);
    let n = rows.len();
    let mut over = false;
    for (k, h, at) in rows {
        rr.ranked += 1;
        rr.bytes = rr.bytes.saturating_add(HOT_BYTES_PER_KEY);
        if rr.bytes > rr.budget {
            over = true;
            break;
        }
        let rank = Rank {
            at,
            hash: hash_hex(KeyHash(
                <[u8; 16]>::try_from(h.as_slice())
                    .map(u128::from_be_bytes)
                    .unwrap_or(0),
            )),
        };
        if rr.bytes <= enter_budget {
            rr.enter = Some(rank.clone());
        }
        rr.stay = Some(rank);
        rr.after = Some((k, h));
    }
    if !over && n >= per_step {
        return Ok(None);
    }
    if rr.ranked == 0 {
        // Nothing to rank yet (a bundle's first build): every key starts hot.
        return Ok(Some(None));
    }
    Ok(Some(Some(TierCutoffs {
        enter: rr.enter.take(),
        stay: rr.stay.take(),
        hot_tier_over: false,
    })))
}

/// How long a proposed split waits for its dry run (bundles.md §2 Tiering: the dry run reports
/// "before the first split, and whenever `hot_max_mib` or a feed's `tier` changes"). Policy
/// choice: a dry run that hasn't reported this long after core first saw the proposal (a busy
/// heavy lane, a failing partition) no longer holds the split, so a tier change always takes
/// effect within this bound.
pub const DRY_RUN_HOLD: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// The dry run's heavy-lane job kind (coalesced per bundle).
pub const DRY_RUN_JOB: &str = "tier_dry_run";
/// Distinct logged keys one dry-run step places (core.md §3: bounded steps).
pub const DRY_RUN_KEYS_PER_STEP: usize = 5_000;
/// Cold keys a dry run keeps counts for; the report shows the top 20.
const TOP_COLD_KEEP: usize = 1_000;

/// What a dry run reports (`tier_dry_runs`).
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct DryRun {
    /// The definition hash the proposed split was taken from.
    pub definition_hash: String,
    /// `hot_max_mib` and each member feed's tier, as proposed.
    pub proposed: serde_json::Value,
    /// `running`, `done` or `failed`.
    pub status: String,
    /// When core first saw the proposal (the split waits for the report until then plus
    /// 30 minutes).
    // The hold: DRY_RUN_HOLD (a test checks the number above).
    pub started_at: String,
    pub finished_at: Option<String>,
    /// The log window replayed.
    pub window_from: Option<String>,
    pub window_to: Option<String>,
    /// Blocks the bundle answered in the window (from any key, pattern or rule).
    pub blocks: Option<i64>,
    /// Of those, blocks from keys the proposed split would place cold.
    pub cold_blocks: Option<i64>,
    /// Per proposed tier, the blocks from keys of that tier; the most-blocked cold keys.
    pub detail: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// The proposed split of a block bundle: `hot_max_mib` and each member feed's tier.
pub fn proposed(spec: &Spec) -> serde_json::Value {
    serde_json::json!({
        "hot_max_mib": spec.hot_max_mib,
        "tiers": spec.members.iter().map(|m| (m.feed.clone(), m.tier.as_str())).collect::<std::collections::BTreeMap<_, _>>(),
    })
}

fn parse_tier(s: &str) -> Tier {
    match s {
        "cold" => Tier::Cold,
        "intelligent-tiering" => Tier::IntelligentTiering,
        _ => Tier::Hot,
    }
}

/// A bundle's `tier_dry_runs` row, as the hold reads it.
struct HoldRow {
    proposed: String,
    status: String,
    started_at: String,
    released: Option<String>,
}

fn hold_row(c: &Connection, bundle: &str) -> rusqlite::Result<Option<HoldRow>> {
    c.query_row(
        "SELECT proposed_json, status, started_at, released_json FROM tier_dry_runs WHERE bundle_id = ?1",
        [bundle],
        |r| {
            Ok(HoldRow {
                proposed: r.get(0)?,
                status: r.get(1)?,
                started_at: r.get(2)?,
                released: r.get(3)?,
            })
        },
    )
    .optional()
}

impl HoldRow {
    /// The dry run of `proposal` reported, or stopped holding it ([`DRY_RUN_HOLD`]).
    fn releases(&self, proposal: &str, now: jiff::Timestamp) -> bool {
        self.proposed == proposal
            && (self.status == "done"
                || self.status == "failed"
                || crate::util::parse_ts(&self.started_at).is_none_or(|t| {
                    let hold = jiff::SignedDuration::try_from(DRY_RUN_HOLD)
                        .unwrap_or(jiff::SignedDuration::from_mins(30));
                    picket_api::time::saturating_add(t, hold) <= now
                }))
    }
}

/// True when split `released` (a `released_json`) places anything cold: a cold feed, or an
/// intelligent-tiering one under a `hot_max_mib`.
fn released_cold(released: Option<&str>) -> bool {
    let Some(rel) = released.and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()) else {
        return false;
    };
    let hot_max = rel.get("hot_max_mib").is_some_and(|v| !v.is_null());
    rel.get("tiers").and_then(|t| t.as_object()).is_some_and(|t| {
        t.values().any(|v| match v.as_str().map(parse_tier) {
            Some(Tier::Cold) => true,
            Some(Tier::IntelligentTiering) => hot_max,
            _ => false,
        })
    })
}

/// True when a build of `spec` may change what goes cold: `spec` can place keys cold, or the
/// split its builds last applied did (moving the last cold feed back to hot is a tier change too,
/// bundles.md §2 Tiering).
fn splits(spec: &Spec, released: Option<&str>) -> bool {
    spec.cold_capable() || released_cold(released)
}

/// `spec` with the split its bundle's builds last applied (`released`; none: never split, every
/// feed hot).
fn held(spec: &Spec, released: Option<&str>) -> Spec {
    let rel: Option<serde_json::Value> = released.and_then(|s| serde_json::from_str(s).ok());
    let tiers = rel
        .as_ref()
        .and_then(|r| r.get("tiers"))
        .and_then(|t| t.as_object());
    let hot_max = rel
        .as_ref()
        .and_then(|r| r.get("hot_max_mib"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok());
    spec.with_tiering(
        |feed| {
            tiers
                .and_then(|t| t.get(feed))
                .and_then(|v| v.as_str())
                .map_or(Tier::Hot, parse_tier)
        },
        hot_max,
    )
}

/// The spec a build of `spec` applies at `now` (bundles.md §2 Tiering: the dry run reports before
/// the split): `spec` itself once the dry run of its proposed split has reported (or
/// [`DRY_RUN_HOLD`] has passed since core first saw the proposal), or when nothing in it can go
/// cold; until then `spec` with the split the bundle's builds last applied, so feed updates keep
/// going out while the proposal waits. The flag is true when `spec`'s proposal becomes the one
/// applied (`released_json`).
pub fn effective_in(c: &Connection, spec: &Spec, now: jiff::Timestamp) -> Result<(Spec, bool)> {
    if spec.action != crate::config::model::BundleAction::Block {
        return Ok((spec.clone(), false));
    }
    let p = proposed(spec).to_string();
    let row = hold_row(c, &spec.id)?;
    let released_already = row
        .as_ref()
        .is_some_and(|r| r.released.as_deref() == Some(p.as_str()));
    if released_already {
        return Ok((spec.clone(), false));
    }
    if !splits(spec, row.as_ref().and_then(|r| r.released.as_deref())) {
        // Every key hot, as the split last applied: nothing to hold. Remembered, so a later
        // proposal waits on this split.
        return Ok((spec.clone(), row.is_some()));
    }
    match row {
        Some(r) if r.releases(&p, now) => Ok((spec.clone(), true)),
        r => Ok((held(spec, r.as_ref().and_then(|r| r.released.as_deref())), false)),
    }
}

/// [`effective_in`] for a build that starts now; records a proposal it applies.
pub async fn effective_spec(state: &SharedState, spec: Spec) -> Result<Spec> {
    let s = spec.clone();
    let (eff, release) = state
        .db
        .read(move |c| effective_in(c, &s, jiff::Timestamp::now()))
        .await?;
    if release {
        let (b, p) = (spec.id.clone(), proposed(&spec).to_string());
        state
            .db
            .write(move |c| {
                c.execute(
                    "UPDATE tier_dry_runs SET released_json = ?2 WHERE bundle_id = ?1",
                    params![b, p],
                )?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
    }
    if eff.def_hash != spec.def_hash {
        tracing::info!(bundle = %spec.id, "a proposed split waits for its tiering dry run");
    }
    Ok(eff)
}

/// The block bundles whose proposed split has no finished dry run: a cold-capable bundle never dry
/// run (before the first split), one whose `hot_max_mib` or tiers differ from its last dry run,
/// and one whose dry run a stop interrupted (it resumes).
pub async fn dry_runs_due(state: &SharedState) -> Result<Vec<Spec>> {
    let model = state.config.model().await?;
    let mut due = Vec::new();
    let last: HashMap<String, (String, String)> = state
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT bundle_id, proposed_json, status FROM tier_dry_runs")?;
            let rows = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        (r.get::<_, String>(1)?, r.get::<_, String>(2)?),
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(rows.into_iter().collect())
        })
        .await?;
    for def in model.bundles.values() {
        if def.action != crate::config::model::BundleAction::Block {
            continue;
        }
        let spec = Spec::of(def, &model);
        let p = proposed(&spec).to_string();
        match last.get(&spec.id) {
            Some((prev, status)) if *prev == p && status != "running" => {}
            Some(_) => due.push(spec),
            None if spec.cold_capable() => due.push(spec),
            None => {}
        }
    }
    Ok(due)
}

/// Submits the dry runs due ([`dry_runs_due`]) to the heavy lane at P2, beside the re-rank they
/// inform, and asks for the build that applies a proposal whose dry run has reported or no longer
/// holds it ([`DRY_RUN_HOLD`]).
pub async fn submit_dry_runs(state: &SharedState) {
    if state.compiler.dry_runs_paused() {
        return;
    }
    if let Err(e) = forget_unconfigured(state).await {
        tracing::warn!(error = %format!("{e:#}"), "cannot drop dry runs of removed bundles");
    }
    match dry_runs_due(state).await {
        // Paused while it read what's due (tests): nothing is registered, run or released. A
        // call already past the check above at the pause would otherwise act on rows written
        // after it.
        Ok(_) if state.compiler.dry_runs_paused() => return,
        Ok(due) => {
            for spec in due {
                if let Some(p) = state.compiler.take_dry_run_register_pause() {
                    p.await;
                }
                // Seen now: the split's wait counts from here, not from when the lane gets to it.
                match register(state, &spec).await {
                    Ok(true) => {}
                    // Paused (tests): nothing more is registered or submitted.
                    Ok(false) => return,
                    Err(e) => {
                        tracing::warn!(error = %format!("{e:#}"), bundle = %spec.id, "cannot record a proposed split");
                        continue;
                    }
                }
                if state.compiler.dry_runs_paused() {
                    return;
                }
                state.scheduler.heavy.submit(
                    crate::scheduler::Priority::P2,
                    Box::new(DryRunJob::new(state.clone(), spec)),
                );
            }
        }
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "cannot check tiering dry runs"),
    }
    if state.compiler.dry_runs_paused() {
        return;
    }
    if let Err(e) = release_reported(state).await {
        tracing::warn!(error = %format!("{e:#}"), "cannot check held tier splits");
    }
}

/// Drops the `tier_dry_runs` rows of bundles the configuration no longer has as block bundles
/// (deleted, or gone in a restore, which keeps the table for the bundles it restores).
async fn forget_unconfigured(state: &SharedState) -> Result<()> {
    let model = state.config.model().await?;
    let keep: std::collections::HashSet<String> = model
        .bundles
        .values()
        .filter(|d| d.action == crate::config::model::BundleAction::Block)
        .map(|d| d.id.clone())
        .collect();
    state
        .db
        .write(move |c| {
            let ids: Vec<String> = {
                let mut st = c.prepare("SELECT bundle_id FROM tier_dry_runs")?;
                st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
            };
            for id in ids.iter().filter(|id| !keep.contains(*id)) {
                c.execute("DELETE FROM tier_dry_runs WHERE bundle_id = ?1", [id])?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
}

/// Records `spec`'s proposal as seen (a `running` row from now), unless its dry run is already
/// recorded; the split last applied stays. False, with nothing written, while dry runs are paused
/// (checked on the writer, right before the write).
async fn register(state: &SharedState, spec: &Spec) -> Result<bool> {
    let (id, hash, p, now) = (
        spec.id.clone(),
        spec.def_hash.clone(),
        proposed(spec).to_string(),
        crate::util::now_ts(),
    );
    let st = state.clone();
    state
        .db
        .write(move |c| {
            if st.compiler.dry_runs_paused() {
                return Ok::<_, anyhow::Error>(false);
            }
            c.execute(
                "INSERT INTO tier_dry_runs(bundle_id, definition_hash, proposed_json, status, started_at)
                 VALUES (?1, ?2, ?3, 'running', ?4)
                 ON CONFLICT(bundle_id) DO UPDATE SET definition_hash = excluded.definition_hash,
                    proposed_json = excluded.proposed_json, status = 'running', started_at = excluded.started_at,
                    finished_at = NULL, window_from = NULL, window_to = NULL, blocks = NULL, cold_blocks = NULL,
                    detail_json = NULL, error = NULL, progress_json = NULL
                 WHERE tier_dry_runs.proposed_json <> excluded.proposed_json",
                params![id, hash, p, now],
            )?;
            Ok(true)
        })
        .await
}

/// Asks for a build of every bundle whose current proposal waits no more but isn't applied yet.
async fn release_reported(state: &SharedState) -> Result<()> {
    let model = state.config.model().await?;
    let specs: Vec<Spec> = model
        .bundles
        .values()
        .filter(|d| d.action == crate::config::model::BundleAction::Block)
        .map(|d| Spec::of(d, &model))
        .collect();
    let now = jiff::Timestamp::now();
    let ready: Vec<Spec> = state
        .db
        .read(move |c| {
            let mut out = Vec::new();
            for s in specs {
                let p = proposed(&s).to_string();
                if let Some(r) = hold_row(c, &s.id)?
                    && r.released.as_deref() != Some(p.as_str())
                    && splits(&s, r.released.as_deref())
                    && r.releases(&p, now)
                {
                    out.push(s);
                }
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await?;
    for s in ready {
        request_split(state, &s);
    }
    Ok(())
}

/// [`splits`] for `spec` and the split its builds last applied.
async fn needs_split(state: &SharedState, spec: &Spec) -> bool {
    if spec.cold_capable() {
        return true;
    }
    let id = spec.id.clone();
    let released = state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(hold_row(c, &id)?.and_then(|r| r.released)))
        .await
        .ok()
        .flatten();
    released_cold(released.as_deref())
}

/// The build that applies `spec`'s split (its definition changed, so it recomputes every key; a
/// hot part it pushes past `hot_max_mib` re-ranks, as any build's does).
fn request_split(state: &SharedState, spec: &Spec) {
    // Paused (tests): no build is asked for, whichever caller got here.
    if state.compiler.dry_runs_paused() {
        return;
    }
    state.compiler.request(
        state,
        &spec.id,
        super::Request {
            reasons: ["tiering dry run reported".to_string()].into(),
            ..super::Request::default()
        },
        crate::scheduler::Priority::P0,
    );
}

/// Bytes a 1 MiB of `hot_max_mib` holds in hot keys.
fn hot_keys_for(mib: u32) -> i64 {
    i64::try_from(u64::from(mib).saturating_mul(1024 * 1024) / HOT_BYTES_PER_KEY).unwrap_or(i64::MAX)
}

/// Where an intelligent-tiering key goes under a proposed `hot_max_mib`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cutoff {
    /// No `hot_max_mib`, or every such key fits.
    AllHot,
    /// The keys that always stay hot fill it.
    AllCold,
    /// Hot when the key ranks at or above this one, the last that fits (most recent first, ties
    /// by hash, as the re-rank's [`Rank::at_or_above`]).
    Rank(Rank),
}

impl Cutoff {
    /// True when a key of rank time `at` and hash `hash` goes cold.
    pub fn cold(&self, at: &str, hash: KeyHash) -> bool {
        match self {
            Cutoff::AllHot => false,
            Cutoff::AllCold => true,
            Cutoff::Rank(cut) => !Rank {
                at: at.to_string(),
                hash: hash_hex(hash),
            }
            .at_or_above(cut),
        }
    }
}

/// The intelligent-tiering cutoff of `bundle` under `hot_max_mib`, by rank as of `from` (hits
/// inside the dry run's window don't count for the key itself): after the keys that always stay
/// hot (the bundle's current hot keys of other tiers), as many keys as fit, in the re-rank's
/// order (most recent first, ties by hash).
pub fn it_cutoff(
    c: &Connection,
    bundle: &str,
    hot_max_mib: Option<u32>,
    from: &str,
) -> rusqlite::Result<Cutoff> {
    let Some(mib) = hot_max_mib else {
        return Ok(Cutoff::AllHot);
    };
    let base: i64 = c.query_row(
        "SELECT count(*) FROM bundle_keys WHERE bundle_id = ?1 AND part = 'hot'
           AND coalesce(tier, 'hot') <> 'intelligent-tiering'",
        [bundle],
        |r| r.get(0),
    )?;
    let room = hot_keys_for(mib).saturating_sub(base);
    if room <= 0 {
        return Ok(Cutoff::AllCold);
    }
    let last: Option<(String, Vec<u8>)> = c
        .query_row(
            "SELECT max(coalesce(CASE WHEN h.last_hit_at < ?2 THEN h.last_hit_at END, ''), coalesce(k.rank_at, '')) AS r,
                    k.hash128
             FROM bundle_keys k LEFT JOIN bundle_key_hits h ON h.bundle_id = k.bundle_id AND h.hash128 = k.hash128
             WHERE k.bundle_id = ?1 AND k.tier = 'intelligent-tiering'
             GROUP BY k.hash128
             ORDER BY r DESC, k.hash128 LIMIT 1 OFFSET ?3",
            params![bundle, from, room - 1],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    // Fewer keys than fit: every one is hot.
    let Some((at, h)) = last else {
        return Ok(Cutoff::AllHot);
    };
    let hash = KeyHash(
        <[u8; 16]>::try_from(h.as_slice())
            .map(u128::from_be_bytes)
            .unwrap_or(0),
    );
    Ok(Cutoff::Rank(Rank {
        at,
        hash: hash_hex(hash),
    }))
}

/// A running dry run's position and counts (`tier_dry_runs.progress_json`), so a restart resumes.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct Progress {
    /// The last partition (hour key) fully replayed.
    #[serde(default)]
    done_through: Option<String>,
    /// The partition being replayed, and the last key placed in it.
    #[serde(default)]
    hour: Option<String>,
    #[serde(default)]
    key_after: Option<String>,
    #[serde(default)]
    blocks: i64,
    #[serde(default)]
    cold: i64,
    #[serde(default)]
    by_tier: BTreeMapCounts,
    /// Blocks per cold key (at most [`TOP_COLD_KEEP`]; past it the least blocked go).
    #[serde(default)]
    top_cold: BTreeMapCounts,
    cutoff: Option<Cutoff>,
}

/// One dry run of a proposed split on the heavy lane (bundles.md §2 Tiering; core.md §3): a step
/// replays at most [`DRY_RUN_KEYS_PER_STEP`] of one partition's logged block keys (read through
/// the partition's `bundle` index where it has one) and persists its position and counts, so a P0
/// delta runs between steps and a restart resumes. A newer proposal replaces a queued or running
/// one between steps.
pub struct DryRunJob {
    state: SharedState,
    spec: Spec,
    started: bool,
}

impl DryRunJob {
    pub fn new(state: SharedState, spec: Spec) -> Self {
        Self {
            state,
            spec,
            started: false,
        }
    }
}

impl crate::scheduler::HeavyJob for DryRunJob {
    fn kind(&self) -> &str {
        DRY_RUN_JOB
    }

    fn target(&self) -> &str {
        &self.spec.id
    }

    fn step(&mut self) -> crate::scheduler::BoxFuture<'_, Result<crate::scheduler::Step>> {
        Box::pin(async move {
            let first = !self.started;
            self.started = true;
            if first {
                // A proposal changed again since this job was queued: the newer one's job runs.
                let model = self.state.config.model().await?;
                let current = model
                    .bundles
                    .get(&self.spec.id)
                    .map(|d| proposed(&Spec::of(d, &model)));
                if current.as_ref() != Some(&proposed(&self.spec)) {
                    return Ok(crate::scheduler::Step::Done);
                }
            }
            let done = dry_run_step(&self.state, &self.spec, jiff::Timestamp::now(), first).await?;
            Ok(if done.is_some() {
                crate::scheduler::Step::Done
            } else {
                crate::scheduler::Step::More
            })
        })
    }

    fn supersedable(&self) -> bool {
        true
    }
}

/// Runs the dry run of `spec`'s proposed split over the log window ending `now` to its end (or
/// returns the finished one), and stores it.
pub async fn dry_run(state: &SharedState, spec: &Spec, now: jiff::Timestamp) -> Result<DryRun> {
    let mut first = true;
    loop {
        if let Some(r) = dry_run_step(state, spec, now, first).await? {
            return Ok(r);
        }
        first = false;
    }
}

/// One step of `spec`'s dry run; `Some(report)` once it has finished. A first step that finds a
/// finished dry run of the same proposal returns it; one that finds a running one resumes it;
/// otherwise it starts a new one over the window ending `now` (when core first saw the proposal
/// stays as recorded).
async fn dry_run_step(
    state: &SharedState,
    spec: &Spec,
    now: jiff::Timestamp,
    first: bool,
) -> Result<Option<DryRun>> {
    let lock = state.compiler.dry_run_lock(&spec.id);
    let _g = lock.lock().await;
    let id = spec.id.clone();
    let p = proposed(spec).to_string();
    // The run's row.
    let row: Option<(DryRun, Option<String>)> = {
        let id = id.clone();
        state
            .db
            .read(move |c| {
                let d = last_dry_run(c, &id)?;
                let prog: Option<String> = c
                    .query_row(
                        "SELECT progress_json FROM tier_dry_runs WHERE bundle_id = ?1",
                        [&id],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                Ok::<_, anyhow::Error>(d.map(|d| (d, prog)))
            })
            .await?
    };
    let running = row
        .as_ref()
        .filter(|(d, _)| d.proposed == proposed(spec))
        .map(|(d, prog)| (d.clone(), prog.clone()));
    let (run, mut prog) = match running {
        Some((d, _)) if d.status == "done" || d.status == "failed" => return Ok(Some(d)),
        Some((d, Some(prog))) => (d, serde_json::from_str::<Progress>(&prog).unwrap_or_default()),
        other => {
            if !first && other.is_none() {
                // Replaced by a newer proposal's run: this one stops.
                return Ok(Some(DryRun::default()));
            }
            start_run(state, spec, now, other.map(|(d, _)| d)).await?
        }
    };
    let from = run
        .window_from
        .as_deref()
        .and_then(crate::util::parse_ts)
        .unwrap_or(now);
    let to = run
        .window_to
        .as_deref()
        .and_then(crate::util::parse_ts)
        .unwrap_or(now);
    let finished = match replay_chunk(state, spec, &mut prog, from, to).await {
        Ok(f) => f,
        Err(e) => {
            let mut out = run.clone();
            out.status = "failed".into();
            out.error = Some(format!("{e:#}"));
            out.finished_at = Some(crate::util::now_ts());
            store_run(state, &id, &out, None).await?;
            // A failed dry run holds the split no longer.
            if needs_split(state, spec).await {
                request_split(state, spec);
            }
            return Ok(Some(out));
        }
    };
    if !finished {
        store_progress(state, &id, &p, &prog).await?;
        return Ok(None);
    }
    let mut out = run;
    out.status = "done".into();
    out.blocks = Some(prog.blocks);
    out.cold_blocks = Some(prog.cold);
    let mut top: Vec<(String, i64)> = prog.top_cold.iter().map(|(k, n)| (k.clone(), *n)).collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top.truncate(20);
    out.detail = Some(serde_json::json!({
        "by_tier": prog.by_tier,
        "top_cold_keys": top.iter().map(|(k, n)| serde_json::json!({"key": k, "blocks": n})).collect::<Vec<_>>(),
    }));
    out.finished_at = Some(crate::util::now_ts());
    store_run(state, &id, &out, None).await?;
    tracing::info!(bundle = %id, blocks = ?out.blocks, cold = ?out.cold_blocks, "tiering dry run");
    // The split waited for this report: build it now.
    if needs_split(state, spec).await {
        request_split(state, spec);
    }
    Ok(Some(out))
}

/// Starts a dry run of `spec`'s proposal: the window, the cutoff, a `running` row (keeping when core
/// first saw this proposal, and the split last applied).
async fn start_run(
    state: &SharedState,
    spec: &Spec,
    now: jiff::Timestamp,
    same: Option<DryRun>,
) -> Result<(DryRun, Progress)> {
    let window = state
        .settings()
        .retention
        .query_logs
        .as_duration()
        .min(std::time::Duration::from_secs(72 * 3600));
    let from = crate::util::window_start(now, window);
    let (id, mib, from_s) = (spec.id.clone(), spec.hot_max_mib, crate::util::ts(&from));
    let cutoff = state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(it_cutoff(c, &id, mib, &from_s)?))
        .await?;
    let run = DryRun {
        definition_hash: spec.def_hash.clone(),
        proposed: proposed(spec),
        status: "running".into(),
        started_at: same.map(|d| d.started_at).unwrap_or_else(crate::util::now_ts),
        window_from: Some(crate::util::ts(&from)),
        window_to: Some(crate::util::ts(&now)),
        ..Default::default()
    };
    let prog = Progress {
        cutoff: Some(cutoff),
        ..Default::default()
    };
    store_run(state, &spec.id, &run, Some(&prog)).await?;
    Ok((run, prog))
}

async fn store_run(state: &SharedState, bundle: &str, o: &DryRun, prog: Option<&Progress>) -> Result<()> {
    let o = o.clone();
    let id = bundle.to_string();
    let prog = prog.map(serde_json::to_string).transpose()?;
    state
        .db
        .write(move |c| {
            c.execute(
                "INSERT INTO tier_dry_runs(bundle_id, definition_hash, proposed_json, status, started_at, finished_at,
                    window_from, window_to, blocks, cold_blocks, detail_json, error, progress_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(bundle_id) DO UPDATE SET definition_hash = excluded.definition_hash,
                    proposed_json = excluded.proposed_json, status = excluded.status, started_at = excluded.started_at,
                    finished_at = excluded.finished_at, window_from = excluded.window_from, window_to = excluded.window_to,
                    blocks = excluded.blocks, cold_blocks = excluded.cold_blocks, detail_json = excluded.detail_json,
                    error = excluded.error, progress_json = excluded.progress_json",
                params![
                    id,
                    o.definition_hash,
                    o.proposed.to_string(),
                    o.status,
                    o.started_at,
                    o.finished_at,
                    o.window_from,
                    o.window_to,
                    o.blocks,
                    o.cold_blocks,
                    o.detail.as_ref().map(|d| d.to_string()),
                    o.error,
                    prog
                ],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
}

async fn store_progress(state: &SharedState, bundle: &str, proposal: &str, prog: &Progress) -> Result<()> {
    let (id, p, j) = (
        bundle.to_string(),
        proposal.to_string(),
        serde_json::to_string(prog)?,
    );
    state
        .db
        .write(move |c| {
            c.execute(
                "UPDATE tier_dry_runs SET progress_json = ?3 WHERE bundle_id = ?1 AND proposed_json = ?2 AND status = 'running'",
                params![id, p, j],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
}

/// Replays the next chunk of the window's logged blocks: the next partition's block total, then up
/// to [`DRY_RUN_KEYS_PER_STEP`] of its keys, each placed as the proposed definition would place it
/// (only a plain block key may go cold, it takes the hottest proposed tier of the member feeds that
/// list it, an `intelligent-tiering` key goes by [`Cutoff`]). True when the window is done.
async fn replay_chunk(
    state: &SharedState,
    spec: &Spec,
    prog: &mut Progress,
    from: jiff::Timestamp,
    to: jiff::Timestamp,
) -> Result<bool> {
    let per_step = state.compiler.step_rows(DRY_RUN_KEYS_PER_STEP);
    let store = state.logs.writer().store().clone();
    let bundle = spec.id.clone();
    let (from_s, to_s) = (crate::util::ts(&from), crate::util::ts(&to));
    let cur = prog.clone();
    // The partition and its next keys.
    type Chunk = Option<(String, Option<i64>, Vec<(String, i64)>, bool)>;
    let chunk: Chunk = tokio::task::spawn_blocking(move || -> Result<Chunk> {
        let lo = crate::logs::partition::hour_key(&crate::logs::partition::hour_start(&from));
        let mut hour = cur.hour.clone();
        let mut total = None;
        let list = store.list()?;
        let open_hour = |key: &str| -> Result<Option<crate::logs::Partition>> {
            match crate::logs::partition::parse_hour_key(key) {
                Some(h) => store.open(&h, false),
                None => Ok(None),
            }
        };
        if hour.is_none() {
            // The next partition in the window after the last one done.
            let next = list
                .iter()
                .map(|(h, _)| crate::logs::partition::hour_key(h))
                .filter(|k| *k >= lo && *k <= to_s && cur.done_through.as_ref().is_none_or(|d| k > d))
                .min();
            let Some(next) = next else {
                return Ok(None);
            };
            let n: i64 = match open_hour(&next)? {
                Some(p) if p.has_column("events", "bundle") => p.conn.query_row(
                    "SELECT count(*) FROM events WHERE bundle = ?1 AND decision = 'block' AND ts >= ?2 AND ts <= ?3",
                    params![bundle, from_s, to_s],
                    |r| r.get(0),
                )?,
                _ => 0,
            };
            total = Some(n);
            hour = Some(next);
        }
        let Some(h) = hour else { return Ok(None) };
        let mut keys = Vec::new();
        let mut more = false;
        if let Some(p) = open_hour(&h)?
            && p.has_column("events", "rule_key")
            && p.has_column("events", "bundle")
        {
            let kind_ok = if p.has_column("events", "match_kind") {
                "AND match_kind IN ('exact', 'subs')"
            } else {
                "AND 0"
            };
            let mut st = p.conn.prepare(&format!(
                "SELECT rule_key, count(*) FROM events
                 WHERE bundle = ?1 AND decision = 'block' AND ts >= ?2 AND ts <= ?3 {kind_ok}
                   AND rule_key IS NOT NULL AND rule_key > ?4
                 GROUP BY rule_key ORDER BY rule_key LIMIT ?5"
            ))?;
            let after = cur.key_after.clone().unwrap_or_default();
            let mut rows = st.query(params![bundle, from_s, to_s, after, per_step + 1])?;
            while let Some(r) = rows.next()? {
                if keys.len() >= per_step {
                    more = true;
                    break;
                }
                keys.push((r.get::<_, String>(0)?, r.get::<_, i64>(1)?));
            }
        }
        Ok(Some((h, total, keys, more)))
    })
    .await??;
    let Some((hour, total, keys, more)) = chunk else {
        return Ok(true);
    };
    if let Some(n) = total {
        prog.blocks = prog.blocks.saturating_add(n);
        prog.hour = Some(hour.clone());
        prog.key_after = None;
    }
    let last_key = keys.last().map(|(k, _)| k.clone());
    // Place the keys.
    let spec2 = spec.clone();
    let cutoff = prog.cutoff.clone().unwrap_or(Cutoff::AllHot);
    let from_s = crate::util::ts(&from);
    // (key, blocks, its proposed tier (none: no member feed lists it now), cold).
    type Placed = Vec<(String, i64, Option<Tier>, bool)>;
    let placed: Placed = state
        .db
        .read(move |c| -> Result<Placed> {
            let tiers: HashMap<&str, Tier> = spec2.members.iter().map(|m| (m.feed.as_str(), m.tier)).collect();
            let runs = super::spec::snapshot(c, &spec2)?;
            let seed = picket_bundle::hash::bundle_hash_seed(&spec2.id);
            let view = super::source::View::new(&spec2, &runs);
            let mut out = Vec::with_capacity(keys.len());
            for (name, n) in keys {
                let mut labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
                labels.reverse();
                let rev = labels.join(".");
                let mut bad = 0u64;
                let rows = view.key_rules(c, &rev, &mut bad)?;
                if rows.is_empty() {
                    out.push((name, n, None, false));
                    continue;
                }
                let plain = rows
                    .iter()
                    .all(|r| r.rule.flags.is_plain_block() && r.rule.rich().is_none() && !r.rule.is_badfilter());
                let hottest = rows
                    .iter()
                    .filter_map(|r| tiers.get(r.feed.as_str()).copied())
                    .max_by_key(|t| tier_rank(*t))
                    .unwrap_or(Tier::Hot);
                let tier = if plain { hottest } else { Tier::Hot };
                let is_cold = match tier {
                    Tier::Hot => false,
                    Tier::Cold => true,
                    Tier::IntelligentTiering => {
                        let h = KeyHash::of(seed, rev.as_bytes());
                        let rank: String = c
                            .query_row(
                                "SELECT max(coalesce(CASE WHEN h.last_hit_at < ?3 THEN h.last_hit_at END, ''), coalesce(k.rank_at, ''))
                                 FROM bundle_keys k LEFT JOIN bundle_key_hits h ON h.bundle_id = k.bundle_id AND h.hash128 = k.hash128
                                 WHERE k.bundle_id = ?1 AND k.hash128 = ?2",
                                params![spec2.id, &h.0.to_be_bytes()[..], from_s],
                                |r| r.get::<_, Option<String>>(0),
                            )
                            .optional()?
                            .flatten()
                            .unwrap_or_default();
                        cutoff.cold(&rank, h)
                    }
                };
                out.push((name, n, Some(tier), is_cold));
            }
            Ok(out)
        })
        .await?;
    for (name, n, tier, is_cold) in placed {
        let t = tier.map_or("unknown", Tier::as_str);
        *prog.by_tier.entry(t.into()).or_insert(0) += n;
        if is_cold {
            prog.cold = prog.cold.saturating_add(n);
            *prog.top_cold.entry(name).or_insert(0) += n;
        }
    }
    while prog.top_cold.len() > TOP_COLD_KEEP {
        let Some(min) = prog
            .top_cold
            .iter()
            .min_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        prog.top_cold.remove(&min);
    }
    if more {
        prog.key_after = last_key;
    } else {
        prog.done_through = prog.hour.take();
        prog.key_after = None;
    }
    Ok(false)
}

type BTreeMapCounts = std::collections::BTreeMap<String, i64>;

/// The last dry run of a bundle.
pub fn last_dry_run(c: &Connection, bundle: &str) -> rusqlite::Result<Option<DryRun>> {
    c.query_row(
        "SELECT definition_hash, proposed_json, status, started_at, finished_at, window_from, window_to, blocks,
                cold_blocks, detail_json, error FROM tier_dry_runs WHERE bundle_id = ?1",
        [bundle],
        |r| {
            Ok(DryRun {
                definition_hash: r.get(0)?,
                proposed: serde_json::from_str(&r.get::<_, String>(1)?).unwrap_or_default(),
                status: r.get(2)?,
                started_at: r.get(3)?,
                finished_at: r.get(4)?,
                window_from: r.get(5)?,
                window_to: r.get(6)?,
                blocks: r.get(7)?,
                cold_blocks: r.get(8)?,
                detail: r.get::<_, Option<String>>(9)?.and_then(|s| serde_json::from_str(&s).ok()),
                error: r.get(10)?,
            })
        },
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE bundle_keys(bundle_id TEXT, part TEXT, shard INTEGER, hash128 BLOB, key TEXT, value ANY,
                                      tier TEXT, rank_at TEXT);
             CREATE TABLE bundle_key_hits(bundle_id TEXT, hash128 BLOB, last_hit_at TEXT,
                                          PRIMARY KEY (bundle_id, hash128));",
        )
        .unwrap();
        c
    }

    /// bundles.md §2 Tiering: ranks tie by key hash. With room for one intelligent-tiering key
    /// and three of the same rank, only the smallest hash is hot, as the re-rank decides.
    #[test]
    fn the_dry_run_cutoff_breaks_rank_ties_by_hash() {
        let mut c = keys_db();
        let room_for_one = hot_keys_for(1) - 1;
        let tx = c.transaction().unwrap();
        for i in 0..room_for_one {
            tx.execute(
                "INSERT INTO bundle_keys VALUES ('b', 'hot', 0, ?1, ?2, 1, 'hot', NULL)",
                params![&(u128::MAX - i as u128).to_be_bytes()[..], format!("h{i}")],
            )
            .unwrap();
        }
        let at = "2026-11-01T00:00:00.000000Z";
        for h in [3u128, 1, 2] {
            tx.execute(
                "INSERT INTO bundle_keys VALUES ('b', 'hot', 0, ?1, ?2, 1, 'intelligent-tiering', ?3)",
                params![&h.to_be_bytes()[..], format!("it{h}"), at],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        let cut = it_cutoff(&c, "b", Some(1), "2026-11-20T00:00:00Z").unwrap();
        assert_eq!(
            cut,
            Cutoff::Rank(Rank {
                at: at.into(),
                hash: hash_hex(KeyHash(1)),
            })
        );
        assert!(!cut.cold(at, KeyHash(1)), "the smallest hash fits");
        assert!(cut.cold(at, KeyHash(2)), "a tie with a larger hash doesn't");
        assert!(cut.cold(at, KeyHash(3)));
        assert!(
            !cut.cold("2026-11-02T00:00:00.000000Z", KeyHash(9)),
            "more recent"
        );
        assert!(cut.cold("2026-10-31T00:00:00.000000Z", KeyHash(0)), "older");
        // Room for all three: every one is hot; none at all: every one is cold.
        assert_eq!(it_cutoff(&c, "b", Some(2), "z").unwrap(), Cutoff::AllHot);
        assert_eq!(it_cutoff(&c, "b", None, "z").unwrap(), Cutoff::AllHot);
        c.execute(
            "INSERT INTO bundle_keys VALUES ('b', 'hot', 0, x'00', 'extra', 1, NULL, NULL)",
            [],
        )
        .unwrap();
        assert_eq!(it_cutoff(&c, "b", Some(1), "z").unwrap(), Cutoff::AllCold);
    }
}
