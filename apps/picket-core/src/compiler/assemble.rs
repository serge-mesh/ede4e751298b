//! Turning a build's computed state into a bundle version (bundles.md §2 steps 4–6, §4, §5):
//! IP runs, the patterns segment, shard plans (splits, merges, compaction), bases, deltas, the
//! segments and `head.json`, and the blobs written before the commit.
//!
//! - **IP shards** ([`ips`]): every IP rule is read and folded into runs ([`fold_runs`]) when IP
//!   rules may have changed; a shard whose runs' set checksum equals its head's is unchanged, the
//!   others get a delta of the runs that changed ([`diff_runs`]) or a new base.
//! - **Shard plans** (stage `Plan`): each part's directory is planned with picket-bundle's
//!   [`plan`] from per-shard key counts (an over-cap shard's hashes read in detail), so shards
//!   split past `max_shard_keys` and siblings merge below 75 % of it; new shards take numbers the
//!   bundle never used.
//! - **Compaction** (bundles.md §5): a touched shard (hot, cold or IP) gets a new base instead of a
//!   delta when its chain would pass 1,000 deltas, its overlay the reader's entry cap, the delta
//!   the reader's op cap, or its base is 30 days old; and, before publishing, while the overlays on
//!   an edge carrying the bundle would pass its `overlay_budget_mib` after this build, the part
//!   with the largest overlay is rebuilt first ([`overlay_compaction`]: this bundle's parts in the
//!   build, another bundle's as its compaction build, `Request::compact`). The daily compaction
//!   build applies the base-age backstop to untouched shards.
//! - **Bases** (stage `Base`, one per step): streamed from the shard's state, sorted by reversed
//!   name: the materialised rows merged with the build's ops, or a fresh build's staged keys
//!   (bundles.md §2 "Full shard build"). Its files go to the blob store in the same step; only
//!   their ids stay in RAM ([`BaseMeta`]).
//! - **Deltas** (stage `Delta`, one per step), then **Finish**: IP shards, segments (`rich.json`
//!   keeps every live index stable, [`RichBuilder::retain_sets`] reclaims the rest;
//!   `patterns.bin` is rebuilt only when its inputs changed), the head.
//! - **Blobs** ([`store_blobs`]): registered as pending, as the build's (`bundle_build_blobs`),
//!   before their files move into the store; the head's other blobs are marked too, so retention
//!   never collects what a build in progress names (storage.md §4).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Result, anyhow, bail};
use picket_bundle::checksum::SetChecksum;
use picket_bundle::hash::KeyHash;
use picket_bundle::head::{
    COLD_BF8, COLD_PAGES, DOMAINS_BF8, DOMAINS_FST, DeltaRef, Head, IpPatternClass, IpShardRef, PATTERNS,
    RICH, ShardRef,
};
use picket_bundle::ips::{IpShardId, Run};
use picket_bundle::patterns::PatternInput;
use picket_bundle::runs::diff_runs;
use picket_bundle::shard_dir::{Histogram, ShardDir, ShardEntry, plan};
use picket_bundle::writer::{
    Blob, ColdBaseWriter, DeltaTarget, HotBaseWriter, KeyChange, ShardBase, ip_base, ip_delta, key_delta,
};
use picket_bundle::{FORMAT, Value};
use picket_rules::compile::Part;
use rusqlite::{Connection, params_from_iter};
use serde_json::json;

use super::build::{Ctx, MAX_PATTERN_RULES, Mode, PROVISIONAL};
use super::source::View;
use super::store::{self, IpShardRow, ShardRow, parse_part, part_kind, part_text};
use crate::state::SharedState;

/// Deltas a shard's chain may hold before its base is rebuilt (bundles.md §5).
pub const MAX_CHAIN_DELTAS: u64 = 1000;
/// A base this old is rebuilt (bundles.md §5).
pub const MAX_BASE_AGE_DAYS: i64 = 30;
/// Bytes an IPv4 / IPv6 overlay entry takes on the edge (bundles.md §6).
pub const IP4_OVERLAY_BYTES: u64 = 24;
pub const IP6_OVERLAY_BYTES: u64 = 40;

/// What the IP pass computed ([`super::ipfold`]).
#[derive(Clone, Debug, Default)]
pub struct IpOutcome {
    /// How many runs each IP shard whose runs changed holds now (0: the shard goes); the runs
    /// themselves are in `bundle_build_ip_runs`.
    pub changed: BTreeMap<IpShardId, u64>,
    /// IP rules folded (when recomputed).
    pub rules: u64,
    pub recomputed: bool,
    /// The ops a delta of each changed IP shard with a previous chain would hold (its overlay
    /// growth on the edge, bundles.md §5).
    pub ops: BTreeMap<IpShardId, u64>,
}

/// What the patterns pass computed.
#[derive(Clone, Debug, Default)]
pub struct PatternOutcome {
    pub inputs: Vec<PatternInput>,
    pub digest: String,
    pub classes: Vec<IpPatternClass>,
    pub count: usize,
}

/// Where assembly stands.
#[derive(Clone, Debug)]
pub enum Stage {
    Plan,
    /// One rebuilt base per step.
    Base(usize),
    /// One shard's delta per step.
    Delta(usize),
    /// One IP shard's base or delta per step.
    Ip(usize),
    /// `rich.json` and `patterns.bin`.
    Segments,
    /// The head.
    Finish,
}

/// One part's plan.
#[derive(Clone, Debug)]
pub struct PartPlan {
    pub part: Part,
    pub dir: ShardDir,
    pub next: u32,
    /// New shard → the old shard numbers its base streams from.
    pub bases: BTreeMap<u32, Vec<u32>>,
    /// Shards keeping their base that get a delta.
    pub deltas: BTreeSet<u32>,
    /// Key counts per shard after the build.
    pub counts: BTreeMap<u32, u64>,
    pub cant_split: Vec<u32>,
    /// Old shard → its rows' new shard numbers come from `dir` (split or merged; renumbered at
    /// commit).
    pub renumber: Vec<u32>,
}

/// A rebuilt base whose files are already in the blob store: only its metadata stays in RAM, so a
/// build holds one shard's files at a time (bundles.md §2 "Full shard build"; core.md §3).
#[derive(Clone, Debug)]
pub struct BaseMeta {
    /// The base id (BLAKE3 of its manifest).
    pub id: String,
    pub checksum: SetChecksum,
    pub keys: u64,
    /// Its files: (name, BLAKE3, size).
    pub files: Vec<(String, String, u64)>,
}

/// The assembled version.
#[derive(Default)]
pub struct Assembly {
    pub hot: Option<PartPlan>,
    pub cold: Option<PartPlan>,
    /// Bases to build, one per step.
    pub tasks: Vec<(Part, u32)>,
    /// Shards keeping their base that may get a delta, one per step.
    pub delta_tasks: Vec<(Part, u32)>,
    pub bases: HashMap<(Part, u32), BaseMeta>,
    /// Refs of the shards the delta steps handled.
    pub delta_refs: HashMap<(Part, u32), ShardRef>,
    /// IP shards whose base is rebuilt (no previous chain, a backstop, the overlay budget or a
    /// compaction request); the other changed ones get a delta.
    pub ip_bases: BTreeSet<IpShardId>,
    /// The version's seq (one past the previous head's highest).
    pub seq: u64,
    pub prev_rows: HashMap<(Part, u32), ShardRow>,
    pub prev_ip_rows: BTreeMap<IpShardId, IpShardRow>,
    /// Other bundles' parts the overlay budget wants rebuilt (bundle → part ids), requested as
    /// their compaction builds after this build's commit.
    pub compact_requests: BTreeMap<String, BTreeSet<String>>,
    pub head: Option<Head>,
    pub head_blob: Option<Blob>,
    /// Blobs this build wrote.
    pub written: Vec<(String, u64)>,
    /// Every blob the new head names.
    pub named: BTreeSet<String>,
    pub shard_rows: HashMap<(Part, u32), ShardRow>,
    pub ip_rows: BTreeMap<IpShardId, IpShardRow>,
    /// Keys moved between parts or values changed, for stats.
    pub delta_bytes: u64,
    pub base_bytes: u64,
    pub edge_mem_bytes: u64,
    pub overlay_bytes: u64,
    pub patterns_blob: Option<String>,
    pub patterns_edge_memory: u64,
    pub rich_rules: usize,
    /// The IP shards' refs as the IP steps leave them (from the previous head's).
    pub ip_refs: BTreeMap<IpShardId, IpShardRef>,
    /// The IP shards to write, one per step: changed ones (their runs in `bundle_build_ip_runs`)
    /// and unchanged ones whose base is rebuilt (the overlay budget, a compaction request).
    pub ip_work: Vec<(IpShardId, bool)>,
    /// `rich.json`'s id and size.
    pub rich_blob: Option<(String, u64)>,
}

/// True when the build must recompute its IP runs: a full or fresh build, changed IP rules, or
/// changed bundle-wide inputs (rewrite orders, entities).
pub fn ips_needed(ctx: &Ctx) -> bool {
    ctx.spec.has_edge_bundle() && (ctx.mode != Mode::Incremental || ctx.touched.ip || ctx.wide_changed)
}

/// The set checksum of an IP shard's runs.
pub fn runs_checksum(id: IpShardId, runs: &[Run]) -> SetChecksum {
    runs.iter().fold(SetChecksum::ZERO, |cs, r| {
        cs.plus(SetChecksum::ip_entry(id.is_v4(), r.first, r.last, r.value.0))
    })
}

/// Patterns one admission step costs (each compiles its regex; core.md §3).
pub const ADMIT_PER_STEP: usize = 256;

/// The patterns pass while it runs: the rules read (at most [`MAX_PATTERN_RULES`]), the digest of
/// what decides their admission, and the admission as it is computed a few patterns per step
/// when the cached one doesn't match ([`Admitting`]).
pub struct PatternPass {
    rows: Vec<super::source::Row>,
    digest: String,
    admission: Option<picket_rules::matcher::PatternAdmission>,
    admitting: Option<Admitting>,
}

/// The reference matcher's pattern admission ([`picket_rules::matcher::pattern_admission`])
/// computed a bounded number of patterns per step, with the same result: in bundle order,
/// patterns that match everything or have no regex cost nothing; each other one is costed
/// (compiled) and kept while the total fits the limit; one that doesn't build is too large; at the
/// first that doesn't fit, it and every later one are over the budget.
pub struct Admitting {
    action: picket_rules::BundleAction,
    limit: usize,
    next: usize,
    used: usize,
    full: bool,
    adm: picket_rules::matcher::PatternAdmission,
}

impl Admitting {
    pub fn new(action: picket_rules::BundleAction, budget: usize) -> Admitting {
        Admitting {
            action,
            limit: picket_rules::matcher::pattern_admission_limit(budget),
            next: 0,
            used: 0,
            full: false,
            adm: picket_rules::matcher::PatternAdmission {
                resident: Vec::new(),
                over_budget: Vec::new(),
                too_large: Vec::new(),
            },
        }
    }

    /// Admits up to `n` more patterns of `rules`; `true` when every rule is looked at.
    pub fn step(&mut self, rules: &[picket_rules::Rule], n: usize) -> bool {
        self.step_by(rules.len(), |i| &rules[i], n)
    }

    /// [`Self::step`] over `len` rules that `get` reads.
    pub fn step_by<'r>(
        &mut self,
        len: usize,
        get: impl Fn(usize) -> &'r picket_rules::Rule,
        n: usize,
    ) -> bool {
        use picket_rules::{Kind, RuleType};
        let mut costed = 0usize;
        while costed < n {
            if self.next >= len {
                return true;
            }
            let r = get(self.next);
            let i = self.next;
            self.next += 1;
            // The reference's own pattern list (picket-rules' `pattern_entry`).
            if r.kind.is_browser()
                || r.rule_type == RuleType::Browser
                || (self.action == picket_rules::BundleAction::Scope && r.rule_type != RuleType::Dns)
                || (r.is_badfilter() && !r.is_rewrite())
                || !matches!(r.key_kind(), Kind::Pattern | Kind::Regex)
            {
                continue;
            }
            let Some(spec) = r.pattern_spec() else { continue };
            if spec.matches_all {
                continue;
            }
            if self.full {
                self.adm.over_budget.push(i);
                continue;
            }
            let Some(source) = spec.regex.as_deref() else {
                continue;
            };
            costed += 1;
            let Some(cost) = picket_rules::matcher::pattern_cost(source) else {
                self.adm.too_large.push(i);
                continue;
            };
            if self.used.saturating_add(cost) > self.limit {
                self.full = true;
                self.adm.over_budget.push(i);
                continue;
            }
            self.used = self.used.saturating_add(cost);
            self.adm.resident.push((i, cost));
        }
        self.next >= len
    }

    pub fn finish(self) -> picket_rules::matcher::PatternAdmission {
        self.adm
    }
}

/// One step of the patterns pass; `true` when it is done: the first reads the rules and looks up
/// the cached admission, the next ones admit a few patterns each when it misses, the last
/// compiles them with the pattern guardrails and the IP-text classes.
pub async fn patterns_step(state: &SharedState, ctx: &mut Ctx) -> Result<bool> {
    if !ctx.spec.compiles() {
        return Ok(true);
    }
    let budget = picket_bundle::patterns::DEFAULT_BUDGET;
    let Some(mut pass) = ctx.pattern_pass.take() else {
        let (spec, runs, action) = (ctx.spec.clone(), ctx.runs.clone(), ctx.wide.action.0);
        let (rows, bad) = state
            .db
            .read(move |c| {
                let view = View::new(&spec, &runs);
                let mut bad = 0u64;
                let rows = view
                    .patterns(c, MAX_PATTERN_RULES, &mut bad)?
                    .map_err(|n| anyhow!("more than {n} pattern rules; the build is refused"))?;
                Ok::<_, anyhow::Error>((rows, bad))
            })
            .await?;
        ctx.bad_rows += bad;
        let digest = super::compile::admission_digest(action, &rows, budget);
        let admission = state.compiler.admission(&ctx.spec.id, &digest);
        let admitting = admission.is_none().then(|| Admitting::new(action, budget));
        ctx.pattern_pass = Some(PatternPass {
            rows,
            digest,
            admission,
            admitting,
        });
        return Ok(false);
    };
    if let Some(mut a) = pass.admitting.take() {
        let rows = &pass.rows;
        if a.step_by(
            rows.len(),
            |i| &rows[i].rule,
            state.compiler.step_rows(ADMIT_PER_STEP),
        ) {
            pass.admission = Some(a.finish());
        } else {
            pass.admitting = Some(a);
        }
        ctx.pattern_pass = Some(pass);
        return Ok(false);
    }
    patterns_finish(state, ctx, pass).await?;
    Ok(true)
}

/// The patterns pass's last step: every pattern compiled with its admission, the pattern
/// guardrails, the IP-text classes.
async fn patterns_finish(state: &SharedState, ctx: &mut Ctx, pass: PatternPass) -> Result<()> {
    let (spec, runs, wide) = (ctx.spec.clone(), ctx.runs.clone(), ctx.wide.clone());
    let mut rich = ctx.rich.take().ok_or_else(|| anyhow!("rich builder missing"))?;
    let st2 = state.clone();
    let bundle = ctx.spec.id.clone();
    let PatternPass {
        rows,
        digest: adm_digest,
        admission,
        ..
    } = pass;
    let (res, rich) = state
        .db
        .read(move |c| {
            let r = (|| -> Result<_> {
                let view = View::new(&spec, &runs);
                let mut bad = 0u64;
                let budget = picket_bundle::patterns::DEFAULT_BUDGET;
                // More numeric keys than the cap: every class counts (over-approximating only
                // turns the edge's IPv4 fast path off).
                let numeric = view.numeric_keys(c, MAX_PATTERN_RULES, &mut bad)?;
                let mut classes = super::compile::ip_pattern_classes(rows.iter().chain(numeric.iter().flatten()));
                if numeric.is_err() {
                    classes = super::compile::all_ip_pattern_classes();
                }
                let mut counts = super::compile::CompileCounts::default();
                let compiled = super::compile::compile_patterns(&wide, rows, budget, &mut counts, admission);
                st2.compiler
                    .remember_admission(&bundle, adm_digest, compiled.admission.clone());
                let inputs: Vec<PatternInput> = compiled
                    .patterns
                    .iter()
                    .map(|p| PatternInput {
                        rich_set: p.spec.rich.as_ref().map(|r| rich.set(std::slice::from_ref(r))),
                        spec: p.spec.clone(),
                        admit: p.admit,
                    })
                    .collect();
                let mappings: i64 = {
                    let mut n = 0i64;
                    for (feed, run) in view.feeds() {
                        n += c.query_row(
                            "SELECT count(*) FROM feed_entries WHERE kind <> 'name' AND feed_id = ?1 AND kind = 'host_mapping'
                               AND first_run <= ?2 AND (removed_run IS NULL OR removed_run > ?2)",
                            rusqlite::params![feed, run],
                            |r| r.get::<_, i64>(0),
                        )?;
                    }
                    n
                };
                let over: Vec<String> = compiled
                    .admission
                    .over_budget
                    .iter()
                    .filter_map(|i| compiled.rows.get(*i))
                    .take(5)
                    .map(|r| r.order.key.clone())
                    .collect();
                let large: Vec<String> = compiled
                    .admission
                    .too_large
                    .iter()
                    .filter_map(|i| compiled.rows.get(*i))
                    .take(5)
                    .map(|r| r.order.key.clone())
                    .collect();
                Ok((
                    inputs,
                    classes,
                    compiled.patterns.len(),
                    counts,
                    bad,
                    mappings,
                    (compiled.admission.over_budget.len(), over),
                    (compiled.admission.too_large.len(), large),
                ))
            })();
            Ok::<_, anyhow::Error>((r, rich))
        })
        .await?;
    ctx.rich = Some(rich);
    let (inputs, classes, count, counts, bad, mappings, over, large) = res?;
    ctx.counts.badfiltered += counts.badfiltered;
    ctx.counts.entity_refused += counts.entity_refused;
    ctx.bad_rows += bad;
    let digest = {
        let mut s = String::new();
        for p in &inputs {
            s.push_str(&serde_json::to_string(&p.spec).unwrap_or_default());
            s.push_str(&format!("|{:?}|{:?}\n", p.rich_set, p.admit));
        }
        picket_api::ids::object_id(s.as_bytes())
    };
    let b = ctx.spec.id.clone();
    let f = &mut ctx.findings;
    let (k, s) = super::guard::aggregate(
        &b,
        "too_many_patterns",
        count > super::guard::MANY,
        format!(
            "Bundle {b} has {count} patterns (more than {})",
            super::guard::MANY
        ),
        json!({"patterns": count}),
    );
    f.condition(k, s);
    let (k, s) = super::guard::aggregate(
        &b,
        "too_many_mappings",
        crate::util::nonneg_usize(mappings) > super::guard::MANY,
        format!(
            "Bundle {b} has {mappings} host-IP mappings (more than {})",
            super::guard::MANY
        ),
        json!({"mappings": mappings}),
    );
    f.condition(k, s);
    let (k, s) = super::guard::aggregate(
        &b,
        "patterns_over_budget",
        over.0 > 0,
        format!(
            "Bundle {b}: {} pattern(s) past the memory budget are dropped",
            over.0
        ),
        json!({"count": over.0, "sample": over.1}),
    );
    f.condition(k, s);
    let (k, s) = super::guard::aggregate(
        &b,
        "patterns_too_large",
        large.0 > 0,
        format!(
            "Bundle {b}: {} pattern(s) too large to build are dropped",
            large.0
        ),
        json!({"count": large.0, "sample": large.1}),
    );
    f.condition(k, s);
    let refused = ctx.wide.refused.len();
    let (k, s) = super::guard::aggregate(
        &b,
        "entities",
        refused > 0,
        format!("Bundle {b}: {refused} rule(s) left out, their $denyallow entities past the cap"),
        json!({"count": refused, "cap": picket_rules::entity::MAX_ENTITIES_PER_BUNDLE}),
    );
    f.condition(k, s);
    ctx.patterns = Some(PatternOutcome {
        inputs,
        digest,
        classes,
        count,
    });
    Ok(())
}

/// One assembly step.
pub async fn step(state: &SharedState, ctx: &mut Ctx, stage: Stage) -> Result<Option<Stage>> {
    match stage {
        Stage::Ip(usize::MAX) => Ok(Some(ip_start(ctx)?)),
        Stage::Plan => {
            plan_parts(state, ctx).await?;
            let a = ctx.assembly.as_ref().ok_or_else(|| anyhow!("no plan"))?;
            Ok(Some(if a.tasks.is_empty() {
                after_bases(a)
            } else {
                Stage::Base(0)
            }))
        }
        Stage::Base(i) => {
            let a = ctx.assembly.as_ref().ok_or_else(|| anyhow!("no plan"))?;
            let Some(&(part, shard)) = a.tasks.get(i) else {
                return Ok(Some(after_bases(a)));
            };
            let pp = match part {
                Part::Hot => a.hot.as_ref(),
                Part::Cold => a.cold.as_ref(),
            }
            .ok_or_else(|| anyhow!("no plan for the part"))?
            .clone();
            let sources = pp.bases.get(&shard).cloned().unwrap_or_default();
            let base = build_base(state, ctx, part, shard, &pp.dir, &sources).await?;
            // Its files go to the blob store now; only the metadata stays (CP7).
            let mut blobs = vec![base.manifest.clone()];
            blobs.extend(base.files.iter().map(|(_, f)| f.clone()));
            let meta = BaseMeta {
                id: base.id().to_string(),
                checksum: base.checksum,
                keys: base.keys,
                files: base
                    .files
                    .iter()
                    .map(|(n, f)| (n.clone(), f.id.clone(), f.size()))
                    .collect(),
            };
            drop(base);
            let written = store_blobs(state, &ctx.spec.id, blobs).await?;
            let a = ctx.assembly.as_mut().ok_or_else(|| anyhow!("no plan"))?;
            a.written.extend(written);
            a.bases.insert((part, shard), meta);
            Ok(Some(if i + 1 < a.tasks.len() {
                Stage::Base(i + 1)
            } else {
                after_bases(a)
            }))
        }
        Stage::Delta(i) => {
            delta_step(state, ctx, i).await?;
            let a = ctx.assembly.as_ref().ok_or_else(|| anyhow!("no plan"))?;
            Ok(Some(if i + 1 < a.delta_tasks.len() {
                Stage::Delta(i + 1)
            } else {
                ip_start(ctx)?
            }))
        }
        Stage::Ip(i) => {
            ip_step(state, ctx, i).await?;
            let a = ctx.assembly.as_ref().ok_or_else(|| anyhow!("no plan"))?;
            Ok(Some(if i + 1 < a.ip_work.len() {
                Stage::Ip(i + 1)
            } else {
                Stage::Segments
            }))
        }
        Stage::Segments => {
            segments(state, ctx).await?;
            Ok(Some(Stage::Finish))
        }
        Stage::Finish => {
            finish(state, ctx).await?;
            Ok(None)
        }
    }
}

/// The stage after the bases: the deltas, if any.
fn after_bases(a: &Assembly) -> Stage {
    if a.delta_tasks.is_empty() {
        Stage::Ip(usize::MAX)
    } else {
        Stage::Delta(0)
    }
}

/// Sets up the IP steps (the previous head's IP shard refs, the shards to write) and returns
/// the first stage after the deltas.
fn ip_start(ctx: &mut Ctx) -> Result<Stage> {
    let prev_head = ctx
        .prev
        .as_ref()
        .filter(|_| ctx.mode != Mode::Fresh)
        .map(|p| p.head.clone());
    let ip = ctx.ips.clone().unwrap_or_default();
    let a = ctx.assembly.as_mut().ok_or_else(|| anyhow!("no plan"))?;
    if let Some(h) = &prev_head {
        for r in &h.ip_shards {
            a.ip_refs.insert(r.ip_shard, r.clone());
            a.ip_rows.insert(
                r.ip_shard,
                a.prev_ip_rows.get(&r.ip_shard).cloned().unwrap_or_default(),
            );
        }
    }
    let mut work: Vec<(IpShardId, bool)> = ip.changed.keys().map(|id| (*id, true)).collect();
    work.extend(
        a.ip_bases
            .iter()
            .filter(|id| !ip.changed.contains_key(id) && a.ip_refs.contains_key(id))
            .map(|id| (*id, false)),
    );
    a.ip_work = work;
    Ok(if a.ip_work.is_empty() {
        Stage::Segments
    } else {
        Stage::Ip(0)
    })
}

/// Batches of blob bytes a build writes per transaction while finishing.
const BLOB_BATCH_BYTES: u64 = 16 * 1024 * 1024;

/// Writes blobs into the store for `bundle`'s build: each is registered (pending, as the build's)
/// before its file moves into place (bundles.md §2 step 6; storage.md §4; README §2 Restarts: a
/// file the build leaves behind has a row retention collects, and retention never collects a blob
/// a build in progress names). Returns their ids and sizes.
pub(crate) async fn store_blobs(
    state: &SharedState,
    bundle: &str,
    blobs: Vec<Blob>,
) -> Result<Vec<(String, u64)>> {
    if blobs.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<(String, u64)> = blobs.iter().map(|b| (b.id.clone(), b.size())).collect();
    let (b, r2) = (bundle.to_string(), rows.clone());
    state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            store::pending_blobs(&tx, &b, &r2)?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    let dd = state.data_dir.clone();
    tokio::task::spawn_blocking(move || {
        let mut seen = BTreeSet::new();
        for b in &blobs {
            if seen.insert(b.id.as_str()) {
                crate::blobs::write_file(&dd, &b.bytes)?;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|e| anyhow!("blob writer: {e}"))??;
    Ok(rows)
}

/// Blobs a finishing build produces, written in batches.
struct BlobSink {
    bundle: String,
    pending: Vec<Blob>,
    bytes: u64,
    written: Vec<(String, u64)>,
}

impl BlobSink {
    fn new(bundle: &str) -> Self {
        Self {
            bundle: bundle.to_string(),
            pending: Vec::new(),
            bytes: 0,
            written: Vec::new(),
        }
    }

    async fn push(&mut self, state: &SharedState, b: Blob) -> Result<()> {
        self.bytes += b.size();
        self.pending.push(b);
        if self.bytes >= BLOB_BATCH_BYTES {
            self.flush(state).await?;
        }
        Ok(())
    }

    async fn flush(&mut self, state: &SharedState) -> Result<()> {
        let blobs = std::mem::take(&mut self.pending);
        self.bytes = 0;
        let w = store_blobs(state, &self.bundle, blobs).await?;
        self.written.extend(w);
        Ok(())
    }
}

/// The effective per-shard cap (picket-bundle's planning rule).
fn effective_cap(max: u64, total: u64) -> u64 {
    let reader = picket_bundle::domains::MAX_SHARD_KEYS;
    match max {
        0 if total > reader => reader,
        0 => u64::MAX,
        m => m.min(reader),
    }
}

/// Plans both parts.
async fn plan_parts(state: &SharedState, ctx: &mut Ctx) -> Result<()> {
    let mut a = Assembly::default();
    let bundle = ctx.spec.id.clone();
    let max = ctx.spec.max_shard_keys;
    let fresh = ctx.mode == Mode::Fresh;
    let prev_rows = {
        let b = bundle.clone();
        state
            .db
            .read(move |c| Ok::<_, anyhow::Error>(store::shard_rows(c, &b)?))
            .await?
    };
    let now = jiff::Timestamp::now();
    let old_cutoff = crate::util::ts(&(now - jiff::SignedDuration::from_hours(24 * (MAX_BASE_AGE_DAYS))));
    for part in [Part::Hot, Part::Cold] {
        let (old_dir, next0) = match part {
            Part::Hot => (
                ctx.hot_dir.clone(),
                ctx.prev
                    .as_ref()
                    .filter(|_| !fresh)
                    .map_or(1, |p| p.head.next_shard.max(1)),
            ),
            Part::Cold => match &ctx.cold_dir {
                Some(d) => (d.clone(), if fresh { 1 } else { ctx.next_cold_shard }),
                None => continue,
            },
        };
        let b = bundle.clone();
        let pt = part_text(part);
        let prev_rows2 = prev_rows.clone();
        let od = old_dir.clone();
        // Counts per shard after the build, and the detailed histogram of over-cap shards.
        let (hist, touched, ops_per_shard) = state
            .db
            .read(move |c| {
                let mut counts: BTreeMap<u32, i64> = BTreeMap::new();
                let mut hist = Histogram::default();
                let mut touched: BTreeSet<u32> = BTreeSet::new();
                let mut ops: BTreeMap<u32, u64> = BTreeMap::new();
                if fresh {
                    let mut st = c.prepare(
                        "SELECT shard, count(*) FROM bundle_build_fresh WHERE bundle_id = ?1 AND part = ?2 GROUP BY shard",
                    )?;
                    let mut rows = st.query(rusqlite::params![b, pt])?;
                    while let Some(r) = rows.next()? {
                        let s: i64 = r.get(0)?;
                        let n: i64 = r.get(1)?;
                        let idx = crate::util::nonneg_usize((s - i64::from(PROVISIONAL)).clamp(0, 255));
                        if let Some(h) = hist.0.get_mut(idx) {
                            *h = h.saturating_add(crate::util::nonneg(n));
                        }
                    }
                    return Ok::<_, anyhow::Error>((hist, touched, ops));
                }
                for ((p, s), row) in &prev_rows2 {
                    if part_text(*p) == pt && od.entry(*s).is_some() {
                        counts.insert(*s, crate::util::sat_i64(row.keys));
                    }
                }
                for e in od.entries() {
                    counts.entry(e.shard).or_insert(0);
                }
                let mut st = c.prepare(
                    "SELECT new_shard, count(*) FROM bundle_build_ops WHERE bundle_id = ?1 AND new_part = ?2
                       AND NOT (old_part IS ?2 AND old_shard IS new_shard AND old_value IS new_value) GROUP BY new_shard",
                )?;
                let mut rows = st.query(rusqlite::params![b, pt])?;
                while let Some(r) = rows.next()? {
                    let s = u32::try_from(r.get::<_, i64>(0)?).unwrap_or(0);
                    let n: i64 = r.get(1)?;
                    *ops.entry(s).or_default() += crate::util::nonneg(n);
                    touched.insert(s);
                }
                let mut st = c.prepare(
                    "SELECT new_shard, count(*) FROM bundle_build_ops WHERE bundle_id = ?1 AND new_part = ?2
                       AND old_part IS NULL GROUP BY new_shard",
                )?;
                let mut rows = st.query(rusqlite::params![b, pt])?;
                while let Some(r) = rows.next()? {
                    let s = u32::try_from(r.get::<_, i64>(0)?).unwrap_or(0);
                    *counts.entry(s).or_default() += r.get::<_, i64>(1)?;
                }
                let mut st = c.prepare(
                    "SELECT new_shard, count(*) FROM bundle_build_ops WHERE bundle_id = ?1 AND new_part = ?2
                       AND old_part IS NOT NULL AND (old_part <> ?2 OR old_shard <> new_shard) GROUP BY new_shard",
                )?;
                let mut rows = st.query(rusqlite::params![b, pt])?;
                while let Some(r) = rows.next()? {
                    let s = u32::try_from(r.get::<_, i64>(0)?).unwrap_or(0);
                    *counts.entry(s).or_default() += r.get::<_, i64>(1)?;
                }
                let mut st = c.prepare(
                    "SELECT old_shard, count(*) FROM bundle_build_ops WHERE bundle_id = ?1 AND old_part = ?2
                       AND (new_part IS NULL OR new_part <> ?2 OR new_shard <> old_shard) GROUP BY old_shard",
                )?;
                let mut rows = st.query(rusqlite::params![b, pt])?;
                while let Some(r) = rows.next()? {
                    let s = u32::try_from(r.get::<_, i64>(0)?).unwrap_or(0);
                    let n: i64 = r.get(1)?;
                    *counts.entry(s).or_default() -= n;
                    *ops.entry(s).or_default() += crate::util::nonneg(n);
                    touched.insert(s);
                }
                let total: i64 = counts.values().copied().map(|v| v.max(0)).sum();
                let cap = effective_cap(max, crate::util::nonneg(total));
                // Totals at each shard's first index; over-cap shards in detail.
                for e in od.entries() {
                    let n = crate::util::nonneg(counts.get(&e.shard).copied().unwrap_or(0));
                    if n > cap {
                        let mut st = c.prepare_cached(
                            "SELECT k.hash128 FROM bundle_keys k WHERE k.bundle_id = ?1 AND k.part = ?2 AND k.shard = ?3
                               AND NOT EXISTS (SELECT 1 FROM bundle_build_ops o WHERE o.bundle_id = k.bundle_id AND o.key = k.key)",
                        )?;
                        let mut rows = st.query(rusqlite::params![b, pt, e.shard as i64])?;
                        while let Some(r) = rows.next()? {
                            hist.add(hash_of(&r.get::<_, Vec<u8>>(0)?));
                        }
                        let mut st = c.prepare_cached(
                            "SELECT hash128 FROM bundle_build_ops WHERE bundle_id = ?1 AND new_part = ?2 AND new_shard = ?3",
                        )?;
                        let mut rows = st.query(rusqlite::params![b, pt, e.shard as i64])?;
                        while let Some(r) = rows.next()? {
                            hist.add(hash_of(&r.get::<_, Vec<u8>>(0)?));
                        }
                    } else if let Some((lo, _)) = e.index_range()
                        && let Some(h) = hist.0.get_mut(lo)
                    {
                        *h = h.saturating_add(n);
                    }
                }
                Ok((hist, touched, ops))
            })
            .await?;
        let total: u64 = hist.0.iter().sum();
        if part == Part::Cold && total == 0 {
            // No cold part (any more): its shards leave the head.
            continue;
        }
        let start = if fresh {
            ShardDir::single(0)
        } else {
            old_dir.clone()
        };
        let p = plan(&start, &hist, max, next0).map_err(|e| anyhow!("shard plan: {e}"))?;
        let mut pp = PartPlan {
            part,
            dir: p.dir.clone(),
            next: p.next,
            bases: BTreeMap::new(),
            deltas: BTreeSet::new(),
            counts: BTreeMap::new(),
            cant_split: p.cant_split.clone(),
            renumber: Vec::new(),
        };
        for e in p.dir.entries() {
            pp.counts.insert(e.shard, hist.count(e));
        }
        if fresh {
            // Every shard is new; rows move from provisional numbers to the planned ones.
            let entries: Vec<ShardEntry> = p.dir.entries().to_vec();
            let b = bundle.clone();
            let pt = part_text(part);
            state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    for e in &entries {
                        if let Some((lo, hi)) = e.index_range() {
                            tx.execute(
                                "UPDATE bundle_build_fresh SET shard = ?1 WHERE bundle_id = ?2 AND part = ?3 AND shard >= ?4 AND shard < ?5",
                                rusqlite::params![
                                    e.shard as i64,
                                    b,
                                    pt,
                                    i64::from(PROVISIONAL) + crate::util::sat_i64(lo),
                                    i64::from(PROVISIONAL) + crate::util::sat_i64(hi)
                                ],
                            )?;
                        }
                    }
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(())
                })
                .await?;
            for e in p.dir.entries() {
                pp.bases.insert(e.shard, vec![e.shard]);
            }
        } else {
            let mut resharded: BTreeSet<u32> = BTreeSet::new();
            for step in &p.steps {
                for r in &step.remove {
                    resharded.insert(*r);
                }
            }
            // Old shards whose rows move: those any step removed (ultimately).
            let old_shards: BTreeSet<u32> = old_dir.entries().iter().map(|e| e.shard).collect();
            for e in p.dir.entries() {
                if old_shards.contains(&e.shard) && !resharded.contains(&e.shard) {
                    continue;
                }
                // A new shard: its sources are the old shards whose ranges overlap it.
                let (lo, hi) = e.index_range().unwrap_or((0, 0));
                let src: Vec<u32> = old_dir
                    .entries()
                    .iter()
                    .filter(|o| o.index_range().is_some_and(|(a, b)| a < hi && lo < b))
                    .map(|o| o.shard)
                    .collect();
                pp.bases.insert(e.shard, src);
            }
            pp.renumber = old_shards
                .iter()
                .copied()
                .filter(|s| p.dir.entry(*s).is_none())
                .collect();
            let prev_head = ctx.prev.as_ref().map(|p| &p.head);
            let shards: Vec<u32> = p.dir.entries().iter().map(|e| e.shard).collect();
            for s in &shards {
                if pp.bases.contains_key(s) {
                    continue;
                }
                let row = prev_rows.get(&(part, *s)).cloned().unwrap_or_default();
                let ops = ops_per_shard.get(s).copied().unwrap_or(0);
                // An untouched shard needs nothing unless a backstop applies (bundles.md §5).
                let old_base = !row.created_at.is_empty() && row.created_at < old_cutoff;
                if !touched.contains(s) && !old_base && row.deltas < MAX_CHAIN_DELTAS {
                    continue;
                }
                let shard_ref = prev_head.and_then(|h| match part {
                    Part::Hot => h.shard(*s),
                    Part::Cold => h.cold_shard(*s),
                });
                let compact = shard_ref.is_none()
                    || row.deltas.saturating_add(1) > MAX_CHAIN_DELTAS
                    || ops > picket_bundle::delta::MAX_OPS as u64
                    || row.overlay_entries.saturating_add(ops)
                        > picket_bundle::overlay::MAX_OVERLAY_ENTRIES as u64
                    || (!row.created_at.is_empty() && row.created_at < old_cutoff);
                if compact {
                    pp.bases.insert(*s, vec![*s]);
                } else {
                    pp.deltas.insert(*s);
                }
            }
            // Shards a fresh cold part needs (no previous cold head).
            for e in p.dir.entries() {
                let has_ref = prev_head.is_some_and(|h| match part {
                    Part::Hot => h.shard(e.shard).is_some(),
                    Part::Cold => h.cold_shard(e.shard).is_some(),
                });
                if !has_ref && !pp.bases.contains_key(&e.shard) {
                    pp.bases.insert(e.shard, vec![e.shard]);
                    pp.deltas.remove(&e.shard);
                }
            }
        }
        if !pp.cant_split.is_empty() {
            let (k, s) = super::guard::aggregate(
                &bundle,
                "cant_split",
                true,
                format!("Bundle {bundle}: a shard holds more than max_shard_keys and can't split again"),
                json!({"shards": pp.cant_split, "part": part_text(part)}),
            );
            ctx.findings.condition(k, s);
        }
        match part {
            Part::Hot => a.hot = Some(pp),
            Part::Cold => a.cold = Some(pp),
        }
    }
    if !ctx
        .findings
        .conditions
        .contains_key(&format!("bundle_warning:{bundle}:cant_split"))
    {
        ctx.findings
            .condition(format!("bundle_warning:{bundle}:cant_split"), None);
    }
    let prev_ip_rows = {
        let b = bundle.clone();
        state
            .db
            .read(move |c| Ok::<_, anyhow::Error>(store::ip_shard_rows(c, &b)?))
            .await?
    };
    let prev_head = ctx.prev.as_ref().filter(|_| !fresh).map(|p| p.head.clone());
    a.seq = prev_head.as_ref().map_or(1, |h| max_seq(h).saturating_add(1));
    // IP shards: a changed shard without a previous chain, or past a backstop, gets a base.
    let ip = ctx.ips.clone().unwrap_or_default();
    for (id, runs) in &ip.changed {
        if *runs == 0 {
            continue;
        }
        let has_prev = prev_head
            .as_ref()
            .is_some_and(|h| h.ip_shards.iter().any(|r| r.ip_shard == *id));
        let row = prev_ip_rows.get(id).cloned().unwrap_or_default();
        let ops = ip.ops.get(id).copied().unwrap_or(0);
        if !has_prev
            || row.deltas.saturating_add(1) > MAX_CHAIN_DELTAS
            || ops > picket_bundle::delta::MAX_OPS as u64
            || row.overlay_entries.saturating_add(ops) > picket_bundle::overlay::MAX_OVERLAY_ENTRIES as u64
        {
            a.ip_bases.insert(*id);
        }
    }
    // Parts another bundle's build asked this one to rebuild (the overlay budget, below).
    for target in &ctx.request.compact {
        match parse_part_id(target) {
            Some(PartId::Shard(part, s)) => {
                let pp = match part {
                    Part::Hot => a.hot.as_mut(),
                    Part::Cold => a.cold.as_mut(),
                };
                if let Some(pp) = pp
                    && pp.dir.entry(s).is_some()
                    && !pp.bases.contains_key(&s)
                {
                    pp.deltas.remove(&s);
                    pp.bases.insert(s, vec![s]);
                }
            }
            Some(PartId::Ip(id)) => {
                let live = prev_head
                    .as_ref()
                    .is_some_and(|h| h.ip_shards.iter().any(|r| r.ip_shard == id))
                    && ip.changed.get(&id).is_none_or(|r| *r > 0);
                if live {
                    a.ip_bases.insert(id);
                }
            }
            None => {}
        }
    }
    a.prev_rows = prev_rows;
    a.prev_ip_rows = prev_ip_rows;
    // The overlay budget of the edges that carry the bundle (bundles.md §5).
    if !fresh {
        overlay_compaction(state, ctx, &mut a, prev_head.as_ref()).await?;
    }
    for pp in [a.hot.as_ref(), a.cold.as_ref()].into_iter().flatten() {
        for s in pp.bases.keys() {
            a.tasks.push((pp.part, *s));
        }
        for s in &pp.deltas {
            if !pp.bases.contains_key(s) {
                a.delta_tasks.push((pp.part, *s));
            }
        }
    }
    ctx.assembly = Some(a);
    Ok(())
}

/// A part of a bundle as overlay compaction names it: `hot/<shard>`, `cold/<shard>` or
/// `ip/<ip shard>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartId {
    Shard(Part, u32),
    Ip(IpShardId),
}

pub fn part_id(p: &PartId) -> String {
    match p {
        PartId::Shard(part, s) => format!("{}/{s}", part_text(*part)),
        PartId::Ip(id) => format!("ip/{id}"),
    }
}

pub fn parse_part_id(s: &str) -> Option<PartId> {
    let (kind, rest) = s.split_once('/')?;
    match kind {
        "hot" | "cold" => Some(PartId::Shard(parse_part(kind)?, rest.parse().ok()?)),
        "ip" => rest.parse().ok().map(PartId::Ip),
        _ => None,
    }
}

/// Keeps this build's head within the `overlay_budget_mib` of every edge carrying the bundle
/// (bundles.md §5): while the edge's overlays after this build (the other heads its config names,
/// verdict sets as far as core knows them, and this bundle's hot, cold and IP shards after their
/// deltas) would pass its budget, the part with the largest overlay is rebuilt first. A part of
/// this bundle becomes a base in this build; a larger part of another bundle is requested as that
/// bundle's compaction build (a build can only publish its own bundle), and a larger verdict set
/// as a new base of that set (core.md §7), and this build goes on rebuilding its own parts until
/// the edge fits, so it never publishes a head that pushes an edge past its budget. With every
/// part of this bundle rebuilt it adds no overlay at all.
async fn overlay_compaction(
    state: &SharedState,
    ctx: &mut Ctx,
    a: &mut Assembly,
    prev_head: Option<&Head>,
) -> Result<()> {
    let edges = super::budget::overlay_edges(state, &ctx.spec.id).await?;
    if edges.is_empty() {
        return Ok(());
    }
    let per = picket_bundle::overlay::KEY_OVERLAY_BYTES_PER_ENTRY as u64;
    // Keys each shard's delta would touch (an upper bound of its overlay growth).
    let b = ctx.spec.id.clone();
    let ops: HashMap<(Part, u32), u64> = state
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT part, shard, count(*) FROM (
                   SELECT old_part AS part, old_shard AS shard, key FROM bundle_build_ops WHERE bundle_id = ?1 AND old_part IS NOT NULL
                   UNION SELECT new_part, new_shard, key FROM bundle_build_ops WHERE bundle_id = ?1 AND new_part IS NOT NULL)
                 GROUP BY part, shard",
            )?;
            let mut out = HashMap::new();
            let mut rows = st.query([&b])?;
            while let Some(r) = rows.next()? {
                if let Some(p) = parse_part(&r.get::<_, String>(0)?) {
                    out.insert(
                        (p, u32::try_from(r.get::<_, i64>(1)?).unwrap_or(0)),
                        crate::util::nonneg(r.get(2)?),
                    );
                }
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await?;
    // This bundle's parts and their overlays after the build.
    let ip = ctx.ips.clone().unwrap_or_default();
    let mut mine: BTreeMap<String, u64> = BTreeMap::new();
    for pp in [a.hot.as_ref(), a.cold.as_ref()].into_iter().flatten() {
        for e in pp.dir.entries() {
            if pp.bases.contains_key(&e.shard) {
                continue;
            }
            let row = a.prev_rows.get(&(pp.part, e.shard)).cloned().unwrap_or_default();
            let grow = if pp.deltas.contains(&e.shard) {
                ops.get(&(pp.part, e.shard)).copied().unwrap_or(0)
            } else {
                0
            };
            let bytes = row.overlay_entries.saturating_add(grow).saturating_mul(per);
            if bytes > 0 {
                mine.insert(part_id(&PartId::Shard(pp.part, e.shard)), bytes);
            }
        }
    }
    for r in prev_head.map(|h| h.ip_shards.as_slice()).unwrap_or_default() {
        let id = r.ip_shard;
        if a.ip_bases.contains(&id) || ip.changed.get(&id).is_some_and(|runs| *runs == 0) {
            continue;
        }
        let row = a.prev_ip_rows.get(&id).cloned().unwrap_or_default();
        let grow = ip.ops.get(&id).copied().unwrap_or(0);
        let unit = if id.is_v4() {
            IP4_OVERLAY_BYTES
        } else {
            IP6_OVERLAY_BYTES
        };
        let bytes = row.overlay_entries.saturating_add(grow).saturating_mul(unit);
        if bytes > 0 {
            mine.insert(part_id(&PartId::Ip(id)), bytes);
        }
    }
    // The tightest edge first.
    let mut edges = edges;
    edges.sort_by_key(|e| {
        e.budget.saturating_sub(
            e.fixed + e.parts.iter().map(|p| p.2).sum::<u64>() + e.sets.iter().map(|s| s.1).sum::<u64>(),
        )
    });
    for e in &edges {
        let others: u64 =
            e.fixed + e.parts.iter().map(|p| p.2).sum::<u64>() + e.sets.iter().map(|s| s.1).sum::<u64>();
        let mut total = others + mine.values().sum::<u64>();
        if total <= e.budget {
            continue;
        }
        // Largest overlay first, this bundle's and the other bundles' parts and the verdict sets
        // alike (a set's owner is `None` with an empty part id: its provider is the part).
        let mut cands: Vec<(u64, Option<String>, String)> =
            mine.iter().map(|(p, b)| (*b, None, p.clone())).collect();
        cands.extend(e.parts.iter().map(|(b, p, n)| (*n, Some(b.clone()), p.clone())));
        let sets: BTreeMap<String, u64> = e.sets.iter().cloned().collect();
        cands.extend(e.sets.iter().map(|(p, n)| (*n, Some(String::new()), p.clone())));
        cands.sort_by(|x, y| {
            y.0.cmp(&x.0)
                .then_with(|| x.1.cmp(&y.1))
                .then_with(|| x.2.cmp(&y.2))
        });
        for (bytes, owner, pid) in cands {
            if total <= e.budget {
                break;
            }
            match owner {
                None => {
                    match parse_part_id(&pid) {
                        Some(PartId::Shard(part, s)) => {
                            let pp = match part {
                                Part::Hot => a.hot.as_mut(),
                                Part::Cold => a.cold.as_mut(),
                            };
                            if let Some(pp) = pp {
                                pp.deltas.remove(&s);
                                pp.bases.insert(s, vec![s]);
                            }
                        }
                        Some(PartId::Ip(id)) => {
                            a.ip_bases.insert(id);
                        }
                        None => continue,
                    }
                    mine.remove(&pid);
                    total = total.saturating_sub(bytes);
                }
                Some(other) if other.is_empty() && sets.contains_key(&pid) => {
                    // A verdict set: its publisher rebuilds the base (P2), as for another bundle.
                    crate::lookups::verdict_sets::request_base(state, &pid);
                }
                Some(other) => {
                    a.compact_requests.entry(other).or_default().insert(pid);
                }
            }
        }
        if total > e.budget {
            tracing::warn!(bundle = %ctx.spec.id, edge = %e.edge, total, budget = e.budget,
                "the other heads' overlays alone pass the edge's overlay budget; their compaction is requested");
        }
    }
    Ok(())
}

fn hash_of(b: &[u8]) -> KeyHash {
    KeyHash(<[u8; 16]>::try_from(b).map(u128::from_be_bytes).unwrap_or(0))
}

fn placeholders(n: usize, from: usize) -> String {
    (0..n)
        .map(|i| format!("?{}", from + i))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Streams one new shard's keys (sorted by reversed name) from the old shards `sources`: the
/// materialised rows merged with the build's ops, routed to `shard` by the new directory.
/// A fresh build streams its staged keys (it has no ops).
#[expect(
    clippy::too_many_arguments,
    reason = "one shard's stream: its place in the bundle and the caller's sink"
)]
fn shard_stream(
    c: &Connection,
    bundle: &str,
    fresh: bool,
    part: Part,
    shard: u32,
    dir: &ShardDir,
    seed: u64,
    sources: &[u32],
    mut f: impl FnMut(&str, Value) -> Result<()>,
) -> Result<()> {
    let pt = part_text(part);
    let src: Vec<i64> = sources.iter().map(|s| *s as i64).collect();
    let mut args: Vec<rusqlite::types::Value> = vec![bundle.to_string().into(), pt.to_string().into()];
    args.extend(src.iter().map(|s| rusqlite::types::Value::Integer(*s)));
    let mut st = c.prepare(&format!(
        "SELECT key, value FROM {} WHERE bundle_id = ?1 AND part = ?2 AND shard IN ({}) ORDER BY key",
        store::keys_table(fresh),
        placeholders(src.len(), 3)
    ))?;
    let mut ops_st = c.prepare(&format!(
        "SELECT key, new_part, new_shard, new_value FROM bundle_build_ops WHERE bundle_id = ?1
           AND ((old_part = ?2 AND old_shard IN ({p})) OR (new_part = ?2 AND new_shard IN ({p}))) ORDER BY key",
        p = placeholders(src.len(), 3)
    ))?;
    let mut rows = st.query(params_from_iter(args.iter()))?;
    let mut ops = ops_st.query(params_from_iter(args.iter()))?;
    let mut row = next_row(&mut rows)?;
    let mut op = next_op(&mut ops)?;
    let emit = |key: &str, v: u64, f: &mut dyn FnMut(&str, Value) -> Result<()>| -> Result<()> {
        if dir.shard_of(KeyHash::of(seed, key.as_bytes())) == shard {
            f(key, Value::from_stored(v))?;
        }
        Ok(())
    };
    loop {
        match (&row, &op) {
            (None, None) => break,
            (Some((rk, rv)), None) => {
                emit(rk, *rv, &mut f)?;
                row = next_row(&mut rows)?;
            }
            (None, Some((ok, onew))) => {
                if let Some((p, s, v)) = onew
                    && *p == part
                    && sources.contains(s)
                {
                    emit(ok, *v, &mut f)?;
                }
                op = next_op(&mut ops)?;
            }
            (Some((rk, rv)), Some((ok, onew))) => {
                if rk < ok {
                    emit(rk, *rv, &mut f)?;
                    row = next_row(&mut rows)?;
                } else {
                    if let Some((p, s, v)) = onew
                        && *p == part
                        && sources.contains(s)
                    {
                        emit(ok, *v, &mut f)?;
                    }
                    if rk == ok {
                        row = next_row(&mut rows)?;
                    }
                    op = next_op(&mut ops)?;
                }
            }
        }
    }
    Ok(())
}

fn next_row(rows: &mut rusqlite::Rows<'_>) -> Result<Option<(String, u64)>> {
    Ok(match rows.next()? {
        Some(r) => Some((r.get(0)?, r.get::<_, i64>(1)?.cast_unsigned())),
        None => None,
    })
}

#[expect(
    clippy::type_complexity,
    reason = "one row's op, taken apart at once by its caller"
)]
fn next_op(rows: &mut rusqlite::Rows<'_>) -> Result<Option<(String, Option<(Part, u32, u64)>)>> {
    Ok(match rows.next()? {
        Some(r) => {
            let key: String = r.get(0)?;
            let p: Option<String> = r.get(1)?;
            let s: Option<i64> = r.get(2)?;
            let v: Option<i64> = r.get(3)?;
            let new = match (p.as_deref().and_then(parse_part), s, v) {
                (Some(p), Some(s), Some(v)) => Some((p, u32::try_from(s).unwrap_or(0), v.cast_unsigned())),
                _ => None,
            };
            Some((key, new))
        }
        None => None,
    })
}

/// Builds one shard's base (bundles.md §2 "Full shard build").
async fn build_base(
    state: &SharedState,
    ctx: &Ctx,
    part: Part,
    shard: u32,
    dir: &ShardDir,
    sources: &[u32],
) -> Result<ShardBase> {
    let (bundle, seed, dir, sources) = (ctx.spec.id.clone(), ctx.seed, dir.clone(), sources.to_vec());
    let fresh = ctx.mode == Mode::Fresh;
    state
        .db
        .read(move |c| {
            let base = match part {
                Part::Hot => {
                    let mut w = HotBaseWriter::new(&bundle, shard, seed);
                    shard_stream(c, &bundle, fresh, part, shard, &dir, seed, &sources, |k, v| {
                        w.insert(k.as_bytes(), v).map_err(|e| anyhow!("{e}"))
                    })?;
                    w.finish().map_err(|e| anyhow!("hot shard {shard}: {e}"))?
                }
                Part::Cold => {
                    let mut w = ColdBaseWriter::new(&bundle, shard, seed);
                    shard_stream(c, &bundle, fresh, part, shard, &dir, seed, &sources, |k, v| {
                        w.insert(k.as_bytes(), v).map_err(|e| anyhow!("{e}"))
                    })?;
                    w.finish().map_err(|e| anyhow!("cold shard {shard}: {e}"))?
                }
            };
            Ok::<_, anyhow::Error>(base)
        })
        .await
}

/// One shard's delta (bundles.md §2 step 6): the ops that touch it, against its previous chain.
async fn delta_step(state: &SharedState, ctx: &mut Ctx, i: usize) -> Result<()> {
    let bundle = ctx.spec.id.clone();
    let now = ctx.now.clone();
    let prev_head = ctx
        .prev
        .as_ref()
        .filter(|_| ctx.mode != Mode::Fresh)
        .map(|p| &p.head);
    let a = ctx.assembly.as_ref().ok_or_else(|| anyhow!("no plan"))?;
    let Some(&(part, s)) = a.delta_tasks.get(i) else {
        return Ok(());
    };
    let seq = a.seq;
    let Some(mut r) = prev_head.and_then(|h| match part {
        Part::Hot => h.shard(s).cloned(),
        Part::Cold => h.cold_shard(s).cloned(),
    }) else {
        bail!(
            "{} shard {s} has neither a base nor a previous chain",
            part_text(part)
        );
    };
    let mut row = a.prev_rows.get(&(part, s)).cloned().unwrap_or_default();
    let (b2, pt) = (bundle.clone(), part_text(part));
    let changes: Vec<KeyChange> = state
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT key, old_part, old_shard, old_value, new_part, new_shard, new_value FROM bundle_build_ops
                 WHERE bundle_id = ?1 AND ((old_part = ?2 AND old_shard = ?3) OR (new_part = ?2 AND new_shard = ?3))
                 ORDER BY key",
            )?;
            let mut out = Vec::new();
            let mut rows = st.query(rusqlite::params![b2, pt, s as i64])?;
            while let Some(r) = rows.next()? {
                let key: String = r.get(0)?;
                let side = |p: Option<String>, sh: Option<i64>, v: Option<i64>| {
                    (p.as_deref() == Some(pt) && sh == Some(i64::from(s))).then(|| Value::from_stored(v.unwrap_or(0).cast_unsigned()))
                };
                let old = side(r.get(1)?, r.get(2)?, r.get(3)?);
                let new = side(r.get(4)?, r.get(5)?, r.get(6)?);
                if old != new {
                    out.push(KeyChange {
                        key: key.into_bytes(),
                        old,
                        new,
                    });
                }
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await?;
    let mut written = Vec::new();
    let mut delta_bytes = 0;
    if !changes.is_empty() {
        let d = key_delta(
            &DeltaTarget {
                bundle: &bundle,
                base: &r.base,
                seq,
                prev: r.checksum,
                created_at: &now,
            },
            part_kind(part),
            s,
            &changes,
        );
        drop(changes);
        delta_bytes = d.blob.size();
        r.deltas.push(DeltaRef {
            seq,
            blake3: d.blob.id.clone(),
            size: d.blob.size(),
        });
        r.seq = seq;
        r.checksum = d.header.new_checksum;
        row.deltas += 1;
        row.overlay_entries += d.ops as u64;
        written = store_blobs(state, &bundle, vec![d.blob]).await?;
    }
    let a = ctx.assembly.as_mut().ok_or_else(|| anyhow!("no plan"))?;
    let pp = match part {
        Part::Hot => a.hot.as_ref(),
        Part::Cold => a.cold.as_ref(),
    };
    row.keys = pp.and_then(|pp| pp.counts.get(&s).copied()).unwrap_or(row.keys);
    a.delta_bytes += delta_bytes;
    a.written.extend(written);
    a.shard_rows.insert((part, s), row);
    a.delta_refs.insert((part, s), r);
    Ok(())
}

/// One IP shard's base or delta (bundles.md §2 step 4, §5): a changed shard's runs from
/// `bundle_build_ip_runs`, or an unchanged shard's stored runs for a rebuilt base.
async fn ip_step(state: &SharedState, ctx: &mut Ctx, i: usize) -> Result<()> {
    let bundle = ctx.spec.id.clone();
    let now = ctx.now.clone();
    let a = ctx.assembly.as_ref().ok_or_else(|| anyhow!("no plan"))?;
    let Some(&(id, changed)) = a.ip_work.get(i) else {
        return Ok(());
    };
    let seq = a.seq;
    let prev_ref = a.ip_refs.get(&id).cloned();
    let row = a.ip_rows.get(&id).cloned().unwrap_or_default();
    let delta = prev_ref.is_some() && !a.ip_bases.contains(&id);
    let b2 = bundle.clone();
    let (runs, old_runs) = state
        .db
        .read(move |c| {
            let runs = if changed {
                store::build_ip_runs(c, &b2, id)?
            } else {
                store::ip_runs(c, &b2, id)?
            };
            let old = if delta {
                store::ip_runs(c, &b2, id)?
            } else {
                Vec::new()
            };
            Ok::<_, anyhow::Error>((runs, old))
        })
        .await?;
    let a = ctx.assembly.as_mut().ok_or_else(|| anyhow!("no plan"))?;
    if runs.is_empty() {
        a.ip_refs.remove(&id);
        a.ip_rows.remove(&id);
        return Ok(());
    }
    let blob = match prev_ref {
        Some(mut r) if delta => {
            let (dels, ups) = diff_runs(&old_runs, &runs);
            let ops = (dels.len() + ups.len()) as u64;
            let d = ip_delta(
                &DeltaTarget {
                    bundle: &bundle,
                    base: &r.base,
                    seq,
                    prev: r.checksum,
                    created_at: &now,
                },
                id,
                &dels,
                &ups,
            );
            a.delta_bytes += d.blob.size();
            r.deltas.push(DeltaRef {
                seq,
                blake3: d.blob.id.clone(),
                size: d.blob.size(),
            });
            r.seq = seq;
            r.checksum = d.header.new_checksum;
            let mut row = row;
            row.runs = runs.len() as u64;
            row.deltas += 1;
            row.overlay_entries += ops;
            a.ip_rows.insert(id, row);
            a.ip_refs.insert(id, r);
            d.blob
        }
        _ => {
            let b = ip_base(id, &runs).map_err(|e| anyhow!("IP shard {id}: {e}"))?;
            a.base_bytes += b.blob.size();
            a.ip_refs.insert(
                id,
                IpShardRef {
                    ip_shard: id,
                    base: b.blob.id.clone(),
                    seq,
                    checksum: b.checksum,
                    deltas: Vec::new(),
                    base_seq: seq,
                },
            );
            a.ip_rows.insert(
                id,
                IpShardRow {
                    runs: runs.len() as u64,
                    mem_bytes: b.blob.size(),
                    overlay_entries: 0,
                    deltas: 0,
                    created_at: now.clone(),
                },
            );
            b.blob
        }
    };
    let written = store_blobs(state, &bundle, vec![blob]).await?;
    if let Some(a) = ctx.assembly.as_mut() {
        a.written.extend(written);
    }
    Ok(())
}

/// The segments (bundles.md §2 step 5): live rich indices, then `rich.json`, and `patterns.bin`
/// when its inputs changed (its DFA build is this step's work: picket-bundle builds the segment
/// whole, bounded by the patterns' regex budget).
async fn segments(state: &SharedState, ctx: &mut Ctx) -> Result<()> {
    let bundle = ctx.spec.id.clone();
    let ip = ctx.ips.clone().unwrap_or_default();
    let pats = ctx.patterns.clone().unwrap_or_default();
    let live = live_sets(state, &bundle, ctx.mode == Mode::Fresh, &ip, &pats).await?;
    let mut rich = ctx.rich.take().ok_or_else(|| anyhow!("rich builder missing"))?;
    rich.retain_sets(&live);
    let rich_bytes = rich.to_bytes().map_err(|e| anyhow!("rich.json: {e}"))?;
    let rich_rules = rich.rule_count();
    ctx.rich = Some(rich);
    let rich_blob = Blob::new(rich_bytes);
    let reuse = ctx.mode != Mode::Fresh
        && ctx.state.patterns_digest.as_deref() == Some(pats.digest.as_str())
        && ctx.state.patterns_blob.is_some();
    let mut blobs = Vec::new();
    let (patterns_id, patterns_mem) = if reuse {
        (
            ctx.state.patterns_blob.clone().unwrap_or_default(),
            ctx.state.patterns_edge_memory,
        )
    } else {
        let built = picket_bundle::patterns::build(&pats.inputs, picket_bundle::patterns::DEFAULT_BUDGET)
            .map_err(|e| anyhow!("patterns.bin: {e}"))?;
        let b = Blob::new(built.bytes);
        let id = b.id.clone();
        blobs.push(b);
        (id, built.edge_memory as u64)
    };
    let rich_meta = (rich_blob.id.clone(), rich_blob.size());
    blobs.push(rich_blob);
    let written = store_blobs(state, &bundle, blobs).await?;
    let a = ctx.assembly.as_mut().ok_or_else(|| anyhow!("no plan"))?;
    a.written.extend(written);
    a.rich_rules = rich_rules;
    a.patterns_blob = Some(patterns_id);
    a.patterns_edge_memory = patterns_mem;
    a.rich_blob = Some(rich_meta);
    Ok(())
}

/// The head, every blob it names, and the sizes on the edge.
async fn finish(state: &SharedState, ctx: &mut Ctx) -> Result<()> {
    let bundle = ctx.spec.id.clone();
    let mut a = ctx.assembly.take().ok_or_else(|| anyhow!("no plan"))?;
    let prev_head = ctx
        .prev
        .as_ref()
        .filter(|_| ctx.mode != Mode::Fresh)
        .map(|p| p.head.clone());
    let seq = a.seq;
    let now = ctx.now.clone();
    let mut sink = BlobSink::new(&bundle);
    // Hot and cold shard refs: rebuilt bases, the delta steps' chains, untouched chains.
    let mut shard_refs: HashMap<(Part, u32), ShardRef> = HashMap::new();
    for pp in [a.hot.clone(), a.cold.clone()].into_iter().flatten() {
        for e in pp.dir.entries() {
            let s = e.shard;
            if let Some(base) = a.bases.get(&(pp.part, s)) {
                let mut mem = 0u64;
                let mut disk = 0u64;
                for (name, _, size) in &base.files {
                    match name.as_str() {
                        DOMAINS_FST | DOMAINS_BF8 | COLD_BF8 => mem += size,
                        COLD_PAGES => disk += size,
                        _ => {}
                    }
                    a.base_bytes += size;
                }
                shard_refs.insert(
                    (pp.part, s),
                    ShardRef {
                        shard: s,
                        base: base.id.clone(),
                        seq,
                        checksum: base.checksum,
                        deltas: Vec::new(),
                        base_seq: seq,
                    },
                );
                a.shard_rows.insert(
                    (pp.part, s),
                    ShardRow {
                        keys: base.keys,
                        mem_bytes: mem,
                        disk_bytes: disk,
                        overlay_entries: 0,
                        deltas: 0,
                        created_at: now.clone(),
                    },
                );
                continue;
            }
            if let Some(r) = a.delta_refs.get(&(pp.part, s)) {
                shard_refs.insert((pp.part, s), r.clone());
                continue;
            }
            let Some(r) = prev_head.as_ref().and_then(|h| match pp.part {
                Part::Hot => h.shard(s).cloned(),
                Part::Cold => h.cold_shard(s).cloned(),
            }) else {
                bail!(
                    "{} shard {s} has neither a base nor a previous chain",
                    part_text(pp.part)
                );
            };
            let mut row = a.prev_rows.get(&(pp.part, s)).cloned().unwrap_or_default();
            row.keys = pp.counts.get(&s).copied().unwrap_or(row.keys);
            a.shard_rows.insert((pp.part, s), row);
            shard_refs.insert((pp.part, s), r);
        }
    }
    let ip_refs = std::mem::take(&mut a.ip_refs);
    let patterns_id = a.patterns_blob.clone().unwrap_or_default();
    let patterns_mem = a.patterns_edge_memory;
    let (rich_id, rich_size) = a.rich_blob.clone().ok_or_else(|| anyhow!("no rich.json"))?;
    let pats = ctx.patterns.clone().unwrap_or_default();
    // The head.
    let hot = a.hot.clone().ok_or_else(|| anyhow!("no hot part"))?;
    let cold = a.cold.clone();
    let head = Head {
        bundle: bundle.clone(),
        format: FORMAT,
        hash_seed: ctx.seed,
        shard_dir: hot.dir.entries().to_vec(),
        shards: hot
            .dir
            .entries()
            .iter()
            .filter_map(|e| shard_refs.get(&(Part::Hot, e.shard)).cloned())
            .collect(),
        cold_shard_dir: cold
            .as_ref()
            .map(|c| c.dir.entries().to_vec())
            .unwrap_or_default(),
        cold_shards: cold
            .as_ref()
            .map(|c| {
                c.dir
                    .entries()
                    .iter()
                    .filter_map(|e| shard_refs.get(&(Part::Cold, e.shard)).cloned())
                    .collect()
            })
            .unwrap_or_default(),
        ip_shards: ip_refs.values().cloned().collect(),
        segments: [
            (PATTERNS.to_string(), patterns_id.clone()),
            (RICH.to_string(), rich_id.clone()),
        ]
        .into_iter()
        .collect(),
        ip_pattern_classes: pats.classes.clone(),
        feed_runs: ctx
            .runs
            .iter()
            .map(|(f, r)| (f.clone(), u64::try_from(*r).unwrap_or(0)))
            .collect(),
        issued_at: now.clone(),
        action: ctx.spec.rules_action(),
        max_shard_keys: ctx.spec.max_shard_keys,
        next_shard: hot.next,
        // A cold shard number is used only by a cold part: without one, the previous head's
        // counter stands (numbers are never reused, bundles.md §4), so a build that changes
        // nothing gives the previous head back (§2 Determinism).
        next_cold_shard: match &cold {
            Some(c) => c.next.max(ctx.next_cold_shard),
            None => prev_head
                .as_ref()
                .map_or(ctx.next_cold_shard, |h| h.next_cold_shard),
        },
    };
    // Nothing changed but the time: the previous head stands (no new version to publish).
    let head = match &prev_head {
        Some(p) if same_but_time(p, &head) => p.clone(),
        _ => head,
    };
    let (hb, _) = head.to_blob();
    let head_blob = Blob::new(hb);
    // Every blob the head names (unchanged bases' files from their manifests).
    let mut named: BTreeSet<String> = BTreeSet::new();
    named.insert(head_blob.id.clone());
    named.insert(patterns_id);
    named.insert(rich_id);
    let fresh_files: BTreeMap<String, Vec<String>> = a
        .bases
        .values()
        .map(|b| {
            (
                b.id.clone(),
                b.files.iter().map(|(_, id, _)| id.clone()).collect(),
            )
        })
        .collect();
    let mut manifests: Vec<String> = Vec::new();
    for r in head.shards.iter().chain(head.cold_shards.iter()) {
        named.insert(r.base.clone());
        for d in &r.deltas {
            named.insert(d.blake3.clone());
        }
        match fresh_files.get(&r.base) {
            Some(files) => named.extend(files.iter().cloned()),
            None => manifests.push(r.base.clone()),
        }
    }
    for r in &head.ip_shards {
        named.insert(r.base.clone());
        for d in &r.deltas {
            named.insert(d.blake3.clone());
        }
    }
    let dd = state.data_dir.clone();
    let files: Vec<String> = state
        .db
        .read(move |c| {
            let mut out = Vec::new();
            for m in manifests {
                let bytes = crate::blobs::read(c, &dd, &m)?.ok_or_else(|| anyhow!("missing manifest {m}"))?;
                let man =
                    picket_bundle::Manifest::from_bytes(&bytes).map_err(|e| anyhow!("manifest {m}: {e}"))?;
                out.extend(man.files.values().map(|f| f.blake3.clone()));
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await?;
    named.extend(files);
    // Sizes on the edge (edge.md §17).
    let per = picket_bundle::overlay::KEY_OVERLAY_BYTES_PER_ENTRY as u64;
    let mut mem = patterns_mem + (rich_size * 2);
    let mut overlay = 0u64;
    for row in a.shard_rows.values() {
        mem += row.mem_bytes;
        overlay += row.overlay_entries * per;
    }
    for (id, row) in &a.ip_rows {
        mem += row.mem_bytes;
        overlay += row.overlay_entries
            * if id.is_v4() {
                IP4_OVERLAY_BYTES
            } else {
                IP6_OVERLAY_BYTES
            };
    }
    a.edge_mem_bytes = mem;
    a.overlay_bytes = overlay;
    // The rest of the files, and every blob the head names marked as this build's until its
    // commit names them in the version (storage.md §4).
    sink.push(state, head_blob.clone()).await?;
    sink.flush(state).await?;
    a.written.extend(std::mem::take(&mut sink.written));
    let (b2, ids) = (bundle.clone(), named.clone());
    state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            store::protect_blobs(&tx, &b2, ids.iter())?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    a.named = named;
    a.head = Some(head);
    a.head_blob = Some(head_blob);
    ctx.assembly = Some(a);
    Ok(())
}

/// True when two heads differ only in `issued_at`.
fn same_but_time(a: &Head, b: &Head) -> bool {
    let mut b2 = b.clone();
    b2.issued_at = a.issued_at.clone();
    *a == b2
}

/// The highest seq in a head.
fn max_seq(h: &Head) -> u64 {
    h.shards
        .iter()
        .chain(h.cold_shards.iter())
        .map(|s| s.seq)
        .chain(h.ip_shards.iter().map(|s| s.seq))
        .max()
        .unwrap_or(0)
}

/// Every rich set the new head references: keys (unchanged and changed), runs and patterns.
async fn live_sets(
    state: &SharedState,
    bundle: &str,
    fresh: bool,
    ip: &IpOutcome,
    pats: &PatternOutcome,
) -> Result<BTreeSet<u32>> {
    let b = bundle.to_string();
    let changed: Vec<String> = ip.changed.keys().map(|k| k.to_string()).collect();
    let mut live: BTreeSet<u32> = state
        .db
        .read(move |c| {
            let mut out = BTreeSet::new();
            let mut st = c.prepare(&format!(
                "SELECT DISTINCT k.value FROM {} k WHERE k.bundle_id = ?1 AND (k.value & 256) <> 0
                   AND NOT EXISTS (SELECT 1 FROM bundle_build_ops o WHERE o.bundle_id = k.bundle_id AND o.key = k.key)",
                store::keys_table(fresh)
            ))?;
            let mut rows = st.query([&b])?;
            while let Some(r) = rows.next()? {
                if let Some(i) = Value::from_stored(r.get::<_, i64>(0)?.cast_unsigned()).rich_idx() {
                    out.insert(i);
                }
            }
            let mut st = c.prepare(
                "SELECT DISTINCT new_value FROM bundle_build_ops WHERE bundle_id = ?1 AND new_value IS NOT NULL
                   AND (new_value & 256) <> 0",
            )?;
            let mut rows = st.query([&b])?;
            while let Some(r) = rows.next()? {
                if let Some(i) = Value::from_stored(r.get::<_, i64>(0)?.cast_unsigned()).rich_idx() {
                    out.insert(i);
                }
            }
            // A fresh build's runs are all in `changed`; the rows left are the old format's.
            let mut st = c.prepare(
                "SELECT DISTINCT value, ip_shard FROM bundle_ip_ranges WHERE bundle_id = ?1 AND (value & 256) <> 0
                   AND NOT ?2",
            )?;
            let mut rows = st.query(rusqlite::params![b, fresh])?;
            while let Some(r) = rows.next()? {
                let shard: String = r.get(1)?;
                if changed.contains(&shard) {
                    continue;
                }
                if let Some(i) = Value::from_stored(r.get::<_, i64>(0)?.cast_unsigned()).rich_idx() {
                    out.insert(i);
                }
            }
            // The changed shards' new runs.
            let mut st = c.prepare(
                "SELECT DISTINCT value FROM bundle_build_ip_runs WHERE bundle_id = ?1 AND (value & 256) <> 0",
            )?;
            let mut rows = st.query([&b])?;
            while let Some(r) = rows.next()? {
                if let Some(i) = Value::from_stored(r.get::<_, i64>(0)?.cast_unsigned()).rich_idx() {
                    out.insert(i);
                }
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await?;
    live.extend(pats.inputs.iter().filter_map(|p| p.rich_set));
    Ok(live)
}
