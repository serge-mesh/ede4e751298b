//! The compiler's tables (storage.md §3): `bundle_builds` (each bundle's build state),
//! `bundle_keys` / `bundle_ip_ranges` (the materialised compiled state), `bundle_shards` /
//! `bundle_ip_shards` (per-shard bookkeeping), `bundle_versions` and the work tables of a build in
//! progress (`bundle_build_keys`, `bundle_build_ops`).

use std::collections::BTreeMap;

use picket_bundle::Head;
use picket_bundle::head::PartKind;
use picket_bundle::ips::IpShardId;
use picket_rules::compile::Part;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

/// The text of a part (`bundle_keys.part`).
pub fn part_text(p: Part) -> &'static str {
    match p {
        Part::Hot => "hot",
        Part::Cold => "cold",
    }
}

pub fn parse_part(s: &str) -> Option<Part> {
    match s {
        "hot" => Some(Part::Hot),
        "cold" => Some(Part::Cold),
        _ => None,
    }
}

pub fn part_kind(p: Part) -> PartKind {
    match p {
        Part::Hot => PartKind::Hot,
        Part::Cold => PartKind::Cold,
    }
}

/// What a build continues from besides the head (`bundle_builds.state_json`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BuildState {
    /// BLAKE3 of the last patterns segment's inputs, and that segment and its edge memory (a
    /// build whose inputs are the same reuses it).
    pub patterns_digest: Option<String>,
    pub patterns_blob: Option<String>,
    pub patterns_edge_memory: u64,
    /// Intelligent-tiering cutoffs (bundles.md §2 Tiering): a key enters the hot part when its
    /// rank is at or above `enter`, and stays while at or above `stay`. `None`: not ranked yet
    /// (every intelligent-tiering key hot).
    pub tier: Option<TierCutoffs>,
    /// When the build that set the cutoffs ran (hit promotions after it join the next build).
    pub last_build_at: Option<String>,
}

/// A rank: the later of a key's last hit and first seen (RFC 3339), then its hash (hex), most
/// recent first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rank {
    pub at: String,
    pub hash: String,
}

impl Rank {
    /// True when `self` ranks at or above `other` (more recent, or as recent with a smaller hash).
    pub fn at_or_above(&self, other: &Rank) -> bool {
        match self.at.cmp(&other.at) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => self.hash <= other.hash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierCutoffs {
    /// `None`: nothing fits (every intelligent-tiering key cold).
    pub enter: Option<Rank>,
    pub stay: Option<Rank>,
    /// The hot-tier keys alone exceed `hot_max_mib` (`bundle_over_budget`).
    #[serde(default)]
    pub hot_tier_over: bool,
}

/// A bundle's `bundle_builds` row.
#[derive(Clone, Debug, Default)]
pub struct BuildRow {
    pub feed_runs: super::spec::Runs,
    pub definition_hash: String,
    pub head_id: Option<String>,
    pub built_at: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub stats: Option<serde_json::Value>,
    pub state: BuildState,
}

pub fn build_row(c: &Connection, bundle: &str) -> rusqlite::Result<Option<BuildRow>> {
    c.query_row(
        "SELECT feed_runs_json, definition_hash, head_id, built_at, status, error, stats_json, state_json
         FROM bundle_builds WHERE bundle_id = ?1",
        [bundle],
        |r| {
            Ok(BuildRow {
                feed_runs: super::spec::parse_runs(&r.get::<_, String>(0)?),
                definition_hash: r.get(1)?,
                head_id: r.get(2)?,
                built_at: r.get(3)?,
                status: r.get(4)?,
                error: r.get(5)?,
                stats: r
                    .get::<_, Option<String>>(6)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                state: r
                    .get::<_, Option<String>>(7)?
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
            })
        },
    )
    .optional()
}

/// Every bundle's build row.
pub fn build_rows(c: &Connection) -> rusqlite::Result<BTreeMap<String, BuildRow>> {
    let ids: Vec<String> = {
        let mut st = c.prepare("SELECT bundle_id FROM bundle_builds")?;
        st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
    };
    let mut out = BTreeMap::new();
    for id in ids {
        if let Some(r) = build_row(c, &id)? {
            out.insert(id, r);
        }
    }
    Ok(out)
}

/// Records a failed build: the previous version stays (bundles.md §2; core.md §9
/// `bundle_build_failed`).
pub fn record_failure(tx: &Transaction<'_>, bundle: &str, error: &str, now: &str) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO bundle_builds(bundle_id, status, error, failed_at) VALUES (?1, 'failed', ?2, ?3)
         ON CONFLICT(bundle_id) DO UPDATE SET status = 'failed', error = ?2, failed_at = ?3",
        params![bundle, error, now],
    )?;
    Ok(())
}

/// The work tables of a build in progress (scratch: emptied when a build ends and at start).
pub const WORK_TABLES: &[&str] = &[
    "bundle_build_keys",
    "bundle_build_ops",
    "bundle_build_fresh",
    "bundle_build_blobs",
    "bundle_build_ip_rules",
    "bundle_build_ip_runs",
    "bundle_build_rank",
];

/// Empties a bundle's work tables. The blobs it registered as pending lose their protection:
/// retention collects those no version names (storage.md §4).
pub fn clear_work(c: &Connection, bundle: &str) -> rusqlite::Result<()> {
    for t in WORK_TABLES {
        c.execute(&format!("DELETE FROM {t} WHERE bundle_id = ?1"), [bundle])?;
    }
    Ok(())
}

/// Registers blobs a build is about to write (`kind` bundle, no reference yet) and marks them as
/// the build's, before their files move into the store: a file is never in the store without a
/// row retention can collect, and retention never collects a blob a build in progress names
/// (storage.md §4; README §2 Restarts).
pub fn pending_blobs(tx: &Transaction<'_>, bundle: &str, blobs: &[(String, u64)]) -> rusqlite::Result<()> {
    let now = crate::util::now_ts();
    let mut reg = tx.prepare_cached(
        "INSERT INTO blobs(blake3, kind, size, created_at, refcount) VALUES (?1, 'bundle', ?2, ?3, 0)
         ON CONFLICT(blake3) DO NOTHING",
    )?;
    let mut mark =
        tx.prepare_cached("INSERT OR IGNORE INTO bundle_build_blobs(bundle_id, blake3) VALUES (?1, ?2)")?;
    for (id, size) in blobs {
        reg.execute(params![id, *size, now])?;
        mark.execute(params![bundle, id])?;
    }
    Ok(())
}

/// Marks blobs a build's head names but didn't write (unchanged bases, earlier deltas) as the
/// build's, so retention keeps them until its commit names them in the version.
pub fn protect_blobs<'a>(
    tx: &Transaction<'_>,
    bundle: &str,
    ids: impl Iterator<Item = &'a String>,
) -> rusqlite::Result<()> {
    let mut mark =
        tx.prepare_cached("INSERT OR IGNORE INTO bundle_build_blobs(bundle_id, blake3) VALUES (?1, ?2)")?;
    for id in ids {
        mark.execute(params![bundle, id])?;
    }
    Ok(())
}

/// The table a build's keys live in while it runs: a fresh build stages them in
/// `bundle_build_fresh` until its commit swaps them in; other builds diff against `bundle_keys`.
pub fn keys_table(fresh: bool) -> &'static str {
    if fresh {
        "bundle_build_fresh"
    } else {
        "bundle_keys"
    }
}

/// A key's materialised state (`bundle_keys`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyState {
    pub part: Part,
    pub shard: u32,
    pub value: u64,
    pub tier: Option<String>,
    pub rank_at: Option<String>,
}

pub fn key_state(c: &Connection, bundle: &str, key: &str) -> rusqlite::Result<Option<KeyState>> {
    key_state_in(c, "bundle_keys", bundle, key)
}

/// A key's state in `table` (`bundle_keys`, or a fresh build's staging table).
pub fn key_state_in(
    c: &Connection,
    table: &str,
    bundle: &str,
    key: &str,
) -> rusqlite::Result<Option<KeyState>> {
    let mut st = c.prepare_cached(&format!(
        "SELECT part, shard, value, tier, rank_at FROM {table} WHERE bundle_id = ?1 AND key = ?2 LIMIT 1"
    ))?;
    st.query_row(params![bundle, key], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    })
    .optional()
    .map(|o| {
        o.and_then(|(p, s, v, t, ra)| {
            Some(KeyState {
                part: parse_part(&p)?,
                shard: u32::try_from(s).unwrap_or(0),
                value: v.cast_unsigned(),
                tier: t,
                rank_at: ra,
            })
        })
    })
}

/// A key's new (part, value) a build in progress computed, if any: `Some(None)` for a key that
/// goes (or is pruned), `None` when the build has no op for it.
pub fn op_new(c: &Connection, bundle: &str, key: &str) -> rusqlite::Result<Option<Option<(Part, u64)>>> {
    let mut st = c.prepare_cached(
        "SELECT new_part, new_value FROM bundle_build_ops WHERE bundle_id = ?1 AND key = ?2",
    )?;
    st.query_row(params![bundle, key], |r| {
        Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<i64>>(1)?))
    })
    .optional()
    .map(|o| {
        o.map(|(p, v)| match (p.as_deref().and_then(parse_part), v) {
            (Some(p), Some(v)) => Some((p, v.cast_unsigned())),
            _ => None,
        })
    })
}

/// One op of a build: a key whose compiled (part, shard, value), tier or rank changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub key: String,
    pub hash128: [u8; 16],
    pub old: Option<(Part, u32, u64)>,
    pub new: Option<(Part, u32, u64)>,
    pub tier: Option<String>,
    pub rank_at: Option<String>,
}

pub fn insert_ops(tx: &Transaction<'_>, bundle: &str, ops: &[Op]) -> rusqlite::Result<()> {
    let mut st = tx.prepare_cached(
        "INSERT INTO bundle_build_ops(bundle_id, key, hash128, old_part, old_shard, old_value, new_part, new_shard,
            new_value, tier, rank_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(bundle_id, key) DO UPDATE SET new_part = excluded.new_part, new_shard = excluded.new_shard,
            new_value = excluded.new_value, tier = excluded.tier, rank_at = excluded.rank_at",
    )?;
    for o in ops {
        st.execute(params![
            bundle,
            o.key,
            &o.hash128[..],
            o.old.map(|x| part_text(x.0)),
            o.old.map(|x| x.1 as i64),
            o.old.map(|x| x.2.cast_signed()),
            o.new.map(|x| part_text(x.0)),
            o.new.map(|x| x.1 as i64),
            o.new.map(|x| x.2.cast_signed()),
            o.tier,
            o.rank_at,
        ])?;
    }
    Ok(())
}

/// Writes a fresh build's keys into its staging table (swapped into `bundle_keys` at its commit,
/// so readers never see a partial table).
pub fn insert_keys_direct(tx: &Transaction<'_>, bundle: &str, ops: &[Op]) -> rusqlite::Result<()> {
    let mut st = tx.prepare_cached(
        "INSERT INTO bundle_build_fresh(bundle_id, part, shard, hash128, key, value, tier, rank_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for o in ops {
        if let Some((p, s, v)) = o.new {
            st.execute(params![
                bundle,
                part_text(p),
                s as i64,
                &o.hash128[..],
                o.key,
                v.cast_signed(),
                o.tier,
                o.rank_at
            ])?;
        }
    }
    Ok(())
}

/// Per-shard bookkeeping (`bundle_shards`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardRow {
    pub keys: u64,
    pub mem_bytes: u64,
    pub disk_bytes: u64,
    pub overlay_entries: u64,
    pub deltas: u64,
    pub created_at: String,
}

pub fn shard_rows(
    c: &Connection,
    bundle: &str,
) -> rusqlite::Result<std::collections::HashMap<(Part, u32), ShardRow>> {
    let mut st = c.prepare(
        "SELECT part, shard, keys, mem_bytes, disk_bytes, overlay_entries, deltas, coalesce(created_at, '')
         FROM bundle_shards WHERE bundle_id = ?1",
    )?;
    let mut out = std::collections::HashMap::new();
    let mut rows = st.query([bundle])?;
    while let Some(r) = rows.next()? {
        let Some(p) = parse_part(&r.get::<_, String>(0)?) else {
            continue;
        };
        out.insert(
            (p, u32::try_from(r.get::<_, i64>(1)?).unwrap_or(0)),
            ShardRow {
                keys: crate::util::nonneg(r.get(2)?),
                mem_bytes: crate::util::nonneg(r.get(3)?),
                disk_bytes: crate::util::nonneg(r.get(4)?),
                overlay_entries: crate::util::nonneg(r.get(5)?),
                deltas: crate::util::nonneg(r.get(6)?),
                created_at: r.get(7)?,
            },
        );
    }
    Ok(out)
}

/// Per-IP-shard bookkeeping (`bundle_ip_shards`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpShardRow {
    pub runs: u64,
    pub mem_bytes: u64,
    pub overlay_entries: u64,
    pub deltas: u64,
    pub created_at: String,
}

pub fn ip_shard_rows(c: &Connection, bundle: &str) -> rusqlite::Result<BTreeMap<IpShardId, IpShardRow>> {
    let mut st = c.prepare(
        "SELECT ip_shard, runs, mem_bytes, overlay_entries, deltas, coalesce(created_at, '')
         FROM bundle_ip_shards WHERE bundle_id = ?1",
    )?;
    let mut out = BTreeMap::new();
    let mut rows = st.query([bundle])?;
    while let Some(r) = rows.next()? {
        let Ok(id) = r.get::<_, String>(0)?.parse::<IpShardId>() else {
            continue;
        };
        out.insert(
            id,
            IpShardRow {
                runs: crate::util::nonneg(r.get(1)?),
                mem_bytes: crate::util::nonneg(r.get(2)?),
                overlay_entries: crate::util::nonneg(r.get(3)?),
                deltas: crate::util::nonneg(r.get(4)?),
                created_at: r.get(5)?,
            },
        );
    }
    Ok(out)
}

/// The runs of one IP shard (`bundle_ip_ranges`), sorted.
pub fn ip_runs(
    c: &Connection,
    bundle: &str,
    shard: IpShardId,
) -> rusqlite::Result<Vec<picket_bundle::ips::Run>> {
    runs_from(c, "bundle_ip_ranges", bundle, shard)
}

/// The new runs a build computed for an IP shard it changes (`bundle_build_ip_runs`).
pub fn build_ip_runs(
    c: &Connection,
    bundle: &str,
    shard: IpShardId,
) -> rusqlite::Result<Vec<picket_bundle::ips::Run>> {
    runs_from(c, "bundle_build_ip_runs", bundle, shard)
}

fn runs_from(
    c: &Connection,
    table: &str,
    bundle: &str,
    shard: IpShardId,
) -> rusqlite::Result<Vec<picket_bundle::ips::Run>> {
    let mut st = c.prepare_cached(&format!(
        "SELECT \"first\", \"last\", value FROM {table} WHERE bundle_id = ?1 AND ip_shard = ?2 ORDER BY \"first\""
    ))?;
    let mut out = Vec::new();
    let mut rows = st.query(params![bundle, shard.to_string()])?;
    while let Some(r) = rows.next()? {
        let f: Vec<u8> = r.get(0)?;
        let l: Vec<u8> = r.get(1)?;
        let v: i64 = r.get(2)?;
        let (Ok(f), Ok(l)) = (
            <[u8; 16]>::try_from(f.as_slice()),
            <[u8; 16]>::try_from(l.as_slice()),
        ) else {
            continue;
        };
        out.push(picket_bundle::ips::Run {
            first: u128::from_be_bytes(f),
            last: u128::from_be_bytes(l),
            value: picket_bundle::Value::from_stored(v.cast_unsigned()),
        });
    }
    Ok(out)
}

/// The head a bundle's build row names, read from the blob store and checked.
pub fn read_head(
    c: &Connection,
    data_dir: &std::path::Path,
    head_id: &str,
) -> anyhow::Result<Option<(Head, Vec<u8>)>> {
    let Some(bytes) = crate::blobs::read(c, data_dir, head_id)? else {
        return Ok(None);
    };
    let head = Head::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("head {head_id}: {e}"))?;
    Ok(Some((head, bytes)))
}

/// Every bundle's current head (`bundle_builds.head_id`): what core names for each bundle before
/// per-edge budgets (bundles.md §7).
pub fn current_heads(c: &Connection) -> rusqlite::Result<BTreeMap<String, String>> {
    let mut st = c.prepare(
        "SELECT b.bundle_id, b.head_id FROM bundle_builds b
         JOIN bundle_versions v ON v.bundle_id = b.bundle_id AND v.head_id = b.head_id
         WHERE b.head_id IS NOT NULL",
    )?;
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
}

/// A version's in-memory size on an edge and its overlays (edge.md §17), from its stats.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadSize {
    /// The hot part (filters, FSTs, IP shards, segments) plus the cold filters, without overlays.
    pub mem_bytes: u64,
    pub overlay_bytes: u64,
}

impl HeadSize {
    pub fn total(&self) -> u64 {
        self.mem_bytes.saturating_add(self.overlay_bytes)
    }
}

/// The parts of the bundles' current heads with an overlay (`bundle_shards`, `bundle_ip_shards`):
/// bundle → (part id as [`super::assemble::part_id`] writes it, overlay bytes).
pub fn overlay_parts<'a>(
    c: &Connection,
    bundles: impl Iterator<Item = &'a String>,
) -> rusqlite::Result<BTreeMap<String, Vec<(String, u64)>>> {
    let mut st = c.prepare_cached(
        "SELECT part, shard, overlay_bytes FROM bundle_shards WHERE bundle_id = ?1 AND overlay_bytes > 0",
    )?;
    let mut ip = c.prepare_cached(
        "SELECT ip_shard, overlay_bytes FROM bundle_ip_shards WHERE bundle_id = ?1 AND overlay_bytes > 0",
    )?;
    let mut out = BTreeMap::new();
    for b in bundles {
        let mut v = Vec::new();
        let mut rows = st.query([b])?;
        while let Some(r) = rows.next()? {
            v.push((
                format!("{}/{}", r.get::<_, String>(0)?, r.get::<_, i64>(1)?),
                crate::util::nonneg(r.get(2)?),
            ));
        }
        let mut rows = ip.query([b])?;
        while let Some(r) = rows.next()? {
            v.push((
                format!("ip/{}", r.get::<_, String>(0)?),
                crate::util::nonneg(r.get(1)?),
            ));
        }
        if !v.is_empty() {
            out.insert(b.clone(), v);
        }
    }
    Ok(out)
}

/// The sizes of the given heads (`bundle_versions.stats_json`).
pub fn head_sizes(
    c: &Connection,
    heads: &[(String, String)],
) -> rusqlite::Result<BTreeMap<String, HeadSize>> {
    let mut st =
        c.prepare_cached("SELECT stats_json FROM bundle_versions WHERE bundle_id = ?1 AND head_id = ?2")?;
    let mut out = BTreeMap::new();
    for (b, h) in heads {
        let s: Option<Option<String>> = st.query_row(params![b, h], |r| r.get(0)).optional()?;
        let size = s
            .flatten()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .map(|v| HeadSize {
                mem_bytes: v["edge_mem_bytes"].as_u64().unwrap_or(0),
                overlay_bytes: v["overlay_bytes"].as_u64().unwrap_or(0),
            })
            .unwrap_or_default();
        out.insert(h.clone(), size);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_order_most_recent_first_then_hash() {
        let a = Rank {
            at: "2026-11-21T10:00:00Z".into(),
            hash: "aa".into(),
        };
        let b = Rank {
            at: "2026-11-20T10:00:00Z".into(),
            hash: "00".into(),
        };
        assert!(a.at_or_above(&b) && !b.at_or_above(&a));
        let c = Rank {
            at: a.at.clone(),
            hash: "ab".into(),
        };
        assert!(a.at_or_above(&c) && !c.at_or_above(&a) && a.at_or_above(&a));
    }
}
