//! Unchecked cold lookups (core.md §6; bundles.md §6): a query whose cold check the edge
//! couldn't make (`cold_unchecked`: a page failed to read, or the cold part wasn't loaded) is
//! checked by core against the cold shards of the head the record's `versions` names for each
//! such bundle, both heads while a cold shard is mid-move (`[previous, new]`). Core reads the
//! shards from its blob store with picket-bundle's reader, exactly as the edge would have.
//!
//! The names checked: the query name, and, where the profile's response checks ran, the CNAME and
//! HTTPS/SVCB target names (from the referenced answer, else `response`, else the preview), each
//! only against the bundles whose cold stage the edge reached for it. Core finds those by
//! replaying the record's ladder for each name, at its published config and `versions`, as the
//! edge's filter ran it (rules.md §5; bundles.md §6 "Cold lookup"): an allow bundle that allows
//! the name ends it with no cold stage; in each block bundle in order, an exception (hot: only
//! plain block keys go cold, bundles.md §1) passes the name to the next bundle without its cold
//! stage, a rewrite ends the ladder, and otherwise the bundle's cold stage was reached (a block
//! the edge didn't make, or a host-IP mapping, then ends it). The response checks ran on an
//! allowed answer unless the profile skips them after an allow at steps 1–2 or an exception
//! (`skip_after_allow`, the record's `reason` or the replay saying so) or the query was
//! temporarily allowed (`all`), and on a step-5 block up to its deciding value. The record's
//! deciding bundle and everything after a decision weren't reached. Not replayed: a temporary
//! allow of a response-check name (core keeps no `subdomains` for them); such a name is checked.
//!
//! A hit is a missed block: core counts it (`cold_missed_blocks{edge, bundle}`), sets the key's
//! `last_hit_at`, which promotes an intelligent-tiering key at the bundle's next build
//! (bundles.md §2 Tiering), and records `cold_check = missed` on the record.

use std::path::Path;
use std::sync::{Arc, Mutex};

use picket_api::edge_config::ResponseChecks;
use picket_api::logs::{BundleVersion, ColdShardVersion, Decision, Stage};
use picket_bundle::hash::KeyHash;
use picket_bundle::head::{COLD_BF8, COLD_PAGES, Head, Manifest};
use picket_bundle::page::{PAGE_SIZE, PageReader};
use picket_bundle::reader::{ColdBaseBlobs, ColdProbe, ColdShard};
use picket_rules::{Flags, Outcome};
use rusqlite::Connection;

use super::attribution::{self, Env, value_qtype};
use super::record::Rec;
use super::replay::{self, BundleAt, CandKey, ClientCtx, Lru, Value};

/// Cold shards kept loaded (each holds its filter, ~1.13 B per key, and its overlay).
const SHARD_CACHE: usize = 16;

/// Reads page-file pages from core's blob store.
struct BlobPages {
    data_dir: std::path::PathBuf,
}

impl PageReader for BlobPages {
    fn read_page(&self, file: &str, file_page: u64, buf: &mut [u8; PAGE_SIZE]) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;
        let path = crate::blobs::path(&self.data_dir, file).map_err(std::io::Error::other)?;
        let f = std::fs::File::open(path)?;
        let off = file_page
            .checked_mul(PAGE_SIZE as u64)
            .ok_or_else(|| std::io::Error::other("page offset overflows"))?;
        f.read_exact_at(buf, off)
    }
}

/// A loaded cold shard's key: (bundle, head, shard).
type ShardKey = (String, String, u32);
type ShardLru = Lru<ShardKey, Option<Arc<ColdShard>>>;

/// Loaded cold shards by (bundle, head, shard).
#[derive(Default)]
pub struct ColdCache {
    shards: Mutex<Option<ShardLru>>,
}

impl ColdCache {
    fn get(&self, k: &(String, String, u32)) -> Option<Option<Arc<ColdShard>>> {
        self.shards
            .lock()
            .ok()?
            .get_or_insert_with(|| Lru::new(SHARD_CACHE, usize::MAX))
            .get(k)
    }

    fn put(&self, k: (String, String, u32), v: Option<Arc<ColdShard>>) {
        if let Ok(mut g) = self.shards.lock() {
            g.get_or_insert_with(|| Lru::new(SHARD_CACHE, usize::MAX))
                .insert(k, v, 1);
        }
    }
}

fn read_blob(c: &Connection, data_dir: &Path, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
    crate::blobs::read(c, data_dir, id)
}

/// Loads cold shard `n` of `head` with its delta chain; `None` when a blob is missing or fails
/// its checks.
fn load_shard(
    c: &Connection,
    data_dir: &Path,
    bundle: &str,
    head_id: &str,
    head: &Head,
    n: u32,
) -> Option<ColdShard> {
    let sref = head.cold_shard(n)?;
    let manifest = read_blob(c, data_dir, &sref.base).ok()??;
    let m = Manifest::from_bytes(&manifest).ok()?;
    let bf8 = read_blob(c, data_dir, &m.file(COLD_BF8)?.blake3).ok()??;
    let pages = m.file(COLD_PAGES)?;
    let reader = BlobPages {
        data_dir: data_dir.to_path_buf(),
    };
    let mut header = [0u8; PAGE_SIZE];
    reader.read_page(&pages.blake3, 0, &mut header).ok()?;
    let shard = ColdShard::load(
        bundle,
        Arc::from(head_id),
        head.hash_seed,
        sref.base_seq,
        ColdBaseBlobs {
            base_id: &sref.base,
            manifest: &manifest,
            bf8: &bf8,
        },
        &header,
    )
    .ok()?;
    let mut deltas = Vec::new();
    for d in &sref.deltas {
        deltas.push(read_blob(c, data_dir, &d.blake3).ok()??);
    }
    if deltas.is_empty() {
        return Some(shard);
    }
    let refs: Vec<&[u8]> = deltas.iter().map(Vec::as_slice).collect();
    shard.apply_deltas(&refs, &reader).ok()
}

/// The result of one record's check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColdOutcome {
    /// `ok`, `missed` or `unavailable` (a head, blob or published config core no longer has).
    pub result: String,
    /// Missed blocks: (bundle, reversed key). At most one: the first block the edge would have
    /// made, in its order (the query name, then the response checks' names), after which it
    /// would have checked nothing more.
    pub missed: Vec<(String, String)>,
}

/// Unchecked bundles one record is checked against (README §2 Bounded; a profile lists far
/// fewer block bundles).
const MAX_UNCHECKED: usize = 64;

/// How a name's ladder ended (rules.md §5 steps 2–3, as the edge's filter runs them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ladder {
    /// An allow bundle allowed it.
    Allowed,
    /// A block bundle decided (a block, rewrite or host-IP mapping), or the record's deciding
    /// bundle was reached.
    Ended,
    /// No step decided; `exception`: a block bundle's exception let it through.
    Passed { exception: bool },
}

/// Replays the record's profile ladder (at its published config and `versions`) for one name, to
/// learn which block bundles' cold stage the edge reached for it (bundles.md §6: a cold lookup
/// runs only when the bundle's hot part found no rewrite, block or exception; a cold key is a
/// plain block, so a replayed exception or rewrite is a hot one).
struct Walk<'a> {
    env: &'a Env<'a>,
    client: ClientCtx,
    qtype: u16,
    vkey: String,
    profile: String,
    ladder: Vec<(u8, BundleAt)>,
}

impl Walk<'_> {
    /// Walks `v`'s ladder, pushing each block bundle whose cold stage it reached onto `reached`.
    /// `stop_at`: the bundle that decided the record for this name (its own stage isn't an
    /// unchecked cold lookup: the edge decided there, hot or from a cold part it read).
    fn walk(
        &self,
        stage: Stage,
        v: &Value,
        stop_at: Option<&str>,
        reached: &mut Vec<String>,
    ) -> anyhow::Result<Ladder> {
        let mut exception = false;
        for (step, at) in &self.ladder {
            if *step == 3 && stop_at == Some(at.bundle.as_str()) {
                return Ok(Ladder::Ended);
            }
            let key = CandKey {
                versions: self.vkey.clone(),
                value: v.text(),
                qtype: self.qtype,
                profile: self.profile.clone(),
                bundle: at.bundle.clone(),
            };
            let cands = replay::candidates(self.env.c, self.env.caches, at, key, v)?;
            let res = self.client.eval(&cands, v, value_qtype(stage, v, self.qtype));
            match (*step, &res.outcome) {
                (2, Outcome::Allow) => return Ok(Ladder::Allowed),
                (2, _) => {}
                (_, Outcome::Exception) => exception = true,
                (_, Outcome::Rewrite(_)) => return Ok(Ladder::Ended),
                // The edge let the name through, so a replayed block is a cold key it couldn't
                // read; a host-IP mapping runs the cold stage too. Either ends the ladder.
                (_, Outcome::Block | Outcome::HostMapping(_)) => {
                    reached.push(at.bundle.clone());
                    return Ok(Ladder::Ended);
                }
                _ => reached.push(at.bundle.clone()),
            }
        }
        Ok(Ladder::Passed { exception })
    }
}

/// One cold probe's result.
enum Probe {
    Hit(String),
    Miss,
    Unavailable,
}

/// Probes `bundle`'s cold shards at the head(s) the record's `versions` names for `labels`: the
/// most specific matching key whose flags apply (`B_EXACT` at the name, `B_SUBS` above it).
fn probe(
    env: &Env<'_>,
    data_dir: &Path,
    cache: &ColdCache,
    reader: &BlobPages,
    bundle: &str,
    v: &BundleVersion,
    labels: &[Vec<u8>],
) -> anyhow::Result<Probe> {
    // The heads to read: per cold shard number, the head(s) its part came from.
    let mut parts: Vec<(Option<u32>, String)> = Vec::new();
    match v {
        BundleVersion::Plain(h) => parts.push((None, h.clone())),
        BundleVersion::Parts(p) => {
            if p.cold_shards.is_empty() {
                parts.push((None, p.head.clone()));
            }
            for (n, h) in p.cold_shards.iter().take(replay::MAX_PARTS) {
                let Ok(n) = n.parse::<u32>() else { continue };
                match h {
                    ColdShardVersion::One(h) => parts.push((Some(n), h.clone())),
                    ColdShardVersion::Moving([a, b]) => {
                        parts.push((Some(n), a.clone()));
                        parts.push((Some(n), b.clone()));
                    }
                }
            }
        }
    }
    let mut unavailable = false;
    for (only, short) in &parts {
        let vi = env.caches.version(env.c, bundle, short, env.model)?;
        let Ok(vi) = vi.as_ref() else {
            unavailable = true;
            continue;
        };
        let Ok(Some(dir)) = vi.head.cold_dir() else {
            continue;
        };
        // Most specific first; a suffix including a label with a `.` byte matches no key.
        let first_ok = labels
            .iter()
            .rposition(|l| l.contains(&b'.'))
            .map_or(0, |j| j + 1);
        for start in first_ok..labels.len() {
            let key: Vec<String> = labels[start..]
                .iter()
                .rev()
                .map(|l| String::from_utf8_lossy(&l.to_ascii_lowercase()).into_owned())
                .collect();
            let key = key.join(".");
            let h = KeyHash::of(vi.head.hash_seed, key.as_bytes());
            let n = dir.shard_of(h);
            if only.is_some_and(|o| o != n) {
                continue;
            }
            let ck = (bundle.to_string(), vi.head_id.clone(), n);
            let shard = match cache.get(&ck) {
                Some(s) => s,
                None => {
                    let s = load_shard(env.c, data_dir, bundle, &vi.head_id, &vi.head, n).map(Arc::new);
                    cache.put(ck, s.clone());
                    s
                }
            };
            let Some(shard) = shard else {
                unavailable = true;
                continue;
            };
            if let ColdProbe::Hit(value) = shard.probe(h, reader) {
                let flags = value.flags();
                let applies = if start == 0 {
                    flags.intersects(Flags::B_EXACT)
                } else {
                    flags.intersects(Flags::B_SUBS)
                };
                if applies {
                    return Ok(Probe::Hit(key));
                }
            }
        }
    }
    Ok(if unavailable {
        Probe::Unavailable
    } else {
        Probe::Miss
    })
}

/// Checks one record's unchecked cold lookups (see the module docs).
pub fn check(
    env: &Env<'_>,
    data_dir: &Path,
    cache: &ColdCache,
    r: &Rec,
) -> anyhow::Result<Option<ColdOutcome>> {
    if r.cold_unchecked.is_empty() {
        return Ok(None);
    }
    let unavailable = || {
        Ok(Some(ColdOutcome {
            result: "unavailable".into(),
            missed: Vec::new(),
        }))
    };
    let Some(versions) = replay::parse_versions(&r.versions_json) else {
        return unavailable();
    };
    // The ladder is replayed from the record's published config; without it (or with a bundle
    // version gone) core can't tell which names reached a cold stage, so it claims no miss.
    let Some(cfg) = env.caches.config(env.c, &r.edge, &versions.config)? else {
        return unavailable();
    };
    let profile_id = r.profile.clone().unwrap_or_default();
    let Some(profile) = cfg.profiles.get(&profile_id) else {
        return unavailable();
    };
    let ladder = attribution::ladder(env, &cfg, &profile_id, &versions)?;
    if ladder.iter().any(|(_, b)| b.unavailable().is_some()) {
        return unavailable();
    }
    let unchecked: Vec<&String> = r.cold_unchecked.iter().take(MAX_UNCHECKED).collect();
    // A bundle the record names as unchecked but its profile's block list (in that config)
    // doesn't hold has no place in the ladder: it is checked for each name that passed it.
    let outside: Vec<String> = unchecked
        .iter()
        .filter(|b| !profile.block.iter().any(|x| x == **b))
        .map(|b| (*b).clone())
        .collect();
    let walk = Walk {
        env,
        client: ClientCtx::of(Some(&cfg), &r.client_ip, r.device.as_deref()),
        qtype: r.qtype_num(),
        vkey: if r.versions_blake3.is_empty() {
            blake3::hash(r.versions_json.as_bytes()).to_hex().to_string()
        } else {
            r.versions_blake3.clone()
        },
        profile: profile_id.clone(),
        ladder,
    };
    let reason = r.reason.as_ref();
    let step = r.step();
    let decision = r.decision();
    let deciding_bundle = reason.and_then(|x| x.bundle.as_deref());
    // The names in the edge's order, each with the block bundles whose cold stage it reached.
    let mut names: Vec<(Vec<Vec<u8>>, Vec<String>)> = Vec::new();
    let mut push = |labels: Vec<Vec<u8>>, mut reached: Vec<String>, passed: bool| {
        if passed {
            reached.extend(outside.iter().cloned());
        }
        names.push((labels, reached));
    };
    // The query name: no ladder for a forwarded or temporarily allowed query (steps 0–1); a
    // block or rewrite at step 3 stopped at its bundle.
    let mut q_ladder = Ladder::Passed { exception: false };
    if let Some(q) = r.qname_value()
        && let Value::Name(labels) = &q
        && step >= 2
    {
        let stop = match decision {
            Some(Decision::Block | Decision::Rewrite) if step == 3 => deciding_bundle,
            _ => None,
        };
        let mut reached = Vec::new();
        q_ladder = walk.walk(Stage::Query, &q, stop, &mut reached)?;
        push(labels.clone(), reached, matches!(q_ladder, Ladder::Passed { .. }));
    }
    // The response checks (rules.md §5 step 5): run on an allowed answer, unless the profile
    // skips them after an allow at steps 1–2 or an exception (`skip_after_allow`), or on every
    // answer but a temporary allow's (`all`); a step-5 block ran them up to its deciding value.
    let allowed = matches!(step, 1 | 2) || q_ladder == Ladder::Allowed;
    let exception = matches!(q_ladder, Ladder::Passed { exception: true })
        || (step == 3 && decision == Some(Decision::Allow) && deciding_bundle.is_some());
    let checks = match decision {
        Some(Decision::Block) => step == 5,
        Some(Decision::Allow) if step >= 1 => match profile.response_checks {
            ResponseChecks::All => step != 1,
            ResponseChecks::SkipAfterAllow => !allowed && !exception,
        },
        _ => false,
    };
    if checks {
        let av = r.answer_values();
        // A step-5 block stopped at its deciding value: names after it weren't checked.
        let deciding = (step == 5)
            .then(|| reason.and_then(|x| x.value.as_deref()))
            .flatten()
            .and_then(|v| match v.parse::<std::net::IpAddr>() {
                Ok(ip) => Some(Value::Ip(ip)),
                Err(_) => Value::name_from_log(v),
            });
        let order: Vec<(Stage, &Value)> = av.staged();
        let stop_index = deciding
            .as_ref()
            .and_then(|d| order.iter().position(|(_, v)| *v == d));
        for (i, (stage, v)) in order.iter().enumerate() {
            if stop_index.is_some_and(|s| i > s) {
                break;
            }
            let Value::Name(labels) = v else { continue };
            let stop = (stop_index == Some(i)).then_some(deciding_bundle).flatten();
            let mut reached = Vec::new();
            let l = walk.walk(*stage, v, stop, &mut reached)?;
            push(labels.clone(), reached, matches!(l, Ladder::Passed { .. }));
        }
    }
    let mut out = ColdOutcome {
        result: "ok".into(),
        missed: Vec::new(),
    };
    let reader = BlobPages {
        data_dir: data_dir.to_path_buf(),
    };
    'names: for (labels, reached) in &names {
        for bundle in reached {
            if !unchecked.contains(&bundle) {
                continue;
            }
            let Some(v) = versions.bundles.get(bundle) else {
                continue;
            };
            match probe(env, data_dir, cache, &reader, bundle, v, labels)? {
                Probe::Hit(key) => {
                    out.missed.push((bundle.clone(), key));
                    break 'names;
                }
                Probe::Miss => {}
                Probe::Unavailable => out.result = "unavailable".into(),
            }
        }
    }
    if !out.missed.is_empty() {
        out.result = "missed".into();
    }
    Ok(Some(out))
}
