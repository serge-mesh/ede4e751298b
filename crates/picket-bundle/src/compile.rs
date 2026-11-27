//! Rules → a compiled bundle, mirroring what core's compiler does (bundles.md §2 "Every build
//! applies"), and a from-scratch build of every blob of a bundle version.
//!
//! [`compile_rules`] takes a bundle's rules in bundle order (feed order, then line order; browser
//! rules included, since they take slots in urlfilter's matched-rule order) and applies, with
//! picket-rules' helpers:
//! - `$badfilter` bundle-wide ([`picket_rules::badfilter::resolve`]): removed rules are left out;
//!   conditionally removed ones become rich rules carrying their suppressors;
//! - folding rule forms into key flags ([`picket_rules::compile::KeyValue`]); rules with
//!   conditions or answers become rich rules, `$dnsrewrite` ones with urlfilter's matched-rule
//!   order ([`picket_rules::order::urlfilter_order`]);
//! - `$denyallow` entities, expanded once per bundle within the entity cap
//!   ([`picket_rules::entity::EntityExpander`]); a rule past the cap is refused (core counts it and
//!   raises `bundle_warning`);
//! - the IP-text pattern classes (`ip_pattern_classes`, [`picket_rules::compile::can_match_ip_text`]);
//! - pattern admission: the reference matcher's ([`picket_rules::matcher::pattern_admission`]),
//!   so the bundle drops exactly the patterns core's reference drops (past the budget, or over the
//!   NFA limit), listed for `bundle_warning` (review round 1, B3).
//!
//! [`build`] then assigns parts (only plain blocks may go cold), prunes subsumed keys
//! ([`picket_rules::compile::is_subsumed`], a hot parent covering hot and cold keys, a cold parent
//! only cold ones), shards the keys ([`crate::shard_dir::plan`]), folds IP rules into runs and
//! writes every base, the segments and `head.json`. Core's incremental build uses the same pieces
//! through [`crate::writer`]; this path is its from-scratch equivalent (and the parity tests').

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use picket_rules::Flags;
use picket_rules::badfilter::{BadfilterEffect, effective_rich, resolve};
use picket_rules::compile::{KeyValue, Part, can_match_ip_text, covering_subs, is_subsumed};
use picket_rules::entity::{EntityExpander, EntityTable, MAX_ENTITIES_PER_BUNDLE};
use picket_rules::flags::Level;
use picket_rules::matcher::{BundleAction, PatternAdmission, pattern_admission};
use picket_rules::name::reverse_dotted;
use picket_rules::order::{MatchOrder, urlfilter_order};
use picket_rules::psl::PublicSuffixList;
use picket_rules::rule::{Folded, Kind, PatternSpec, RichRule, Rule, RuleType};

use crate::FORMAT;
use crate::hash::{KeyHash, bundle_hash_seed};
use crate::head::{DeltaRef, Head, IpPatternClass, IpShardRef, PATTERNS, RICH, ShardRef};
use crate::ips::{IpShardId, Run};
use crate::matcher::{Bundle, Cold, ColdPart, LoadedParts};
use crate::page::{PAGE_SIZE, PageReader};
use crate::patterns::{PatternAdmit, PatternFate, PatternInput};
use crate::reader::{
    ColdBaseBlobs, ColdShard, HotBaseBlobs, HotShard, IpShard, LoadError, PatternsPart, load_rich,
};
use crate::rich::RichBuilder;
use crate::runs::{IpRuleInput, fold_runs};
use crate::shard_dir::{Histogram, ShardDir, plan};
use crate::value::Value;
use crate::writer::{Blob, ColdBaseWriter, HotBaseWriter, Segments, WriteError, ip_base, segments};

/// How [`compile_rules`] runs.
#[derive(Clone, Copy, Debug)]
pub struct CompileOptions<'a> {
    pub action: BundleAction,
    /// The public suffix list `$denyallow` entities expand against; without it a block or rewrite
    /// naming an entity applies to nothing (fail safe).
    pub psl: Option<&'a PublicSuffixList>,
    pub max_entities: usize,
    /// The pattern budget: the reference matcher's ([`crate::patterns::DEFAULT_BUDGET`]); the edge
    /// loads `patterns.bin` with the same budget.
    pub pattern_budget: usize,
}

impl<'a> CompileOptions<'a> {
    pub fn new(action: BundleAction, psl: Option<&'a PublicSuffixList>) -> Self {
        CompileOptions {
            action,
            psl,
            max_entities: MAX_ENTITIES_PER_BUNDLE,
            pattern_budget: crate::patterns::DEFAULT_BUDGET,
        }
    }
}

/// A compiled pattern: the rule it came from, its spec and the reference's admission of it.
#[derive(Clone, Debug)]
pub struct CompiledPattern {
    pub rule: usize,
    pub spec: PatternSpec,
    pub admit: PatternAdmit,
}

/// A bundle's rules, compiled.
#[derive(Clone, Debug)]
pub struct Compiled {
    /// Reversed name → merged value (rich rules with entities expanded and orders set).
    pub keys: BTreeMap<String, KeyValue>,
    /// Patterns in bundle order, with the rule each came from and its admission.
    pub patterns: Vec<CompiledPattern>,
    /// The reference matcher's pattern admission over the bundle's rules (rule indices): what
    /// core raises `bundle_warning` for.
    pub pattern_admission: PatternAdmission,
    /// The pattern budget the admission used (the edge loads with the same).
    pub pattern_budget: usize,
    /// IP rules with the index of the rule each came from.
    pub ip_rules: Vec<(usize, IpRuleInput)>,
    /// The expanded entities `rich.json` carries.
    pub entities: EntityTable,
    pub ip_pattern_classes: Vec<IpPatternClass>,
    /// Rules refused because their entities didn't fit the cap.
    pub refused: Vec<usize>,
}

impl Default for Compiled {
    fn default() -> Self {
        Compiled {
            keys: BTreeMap::new(),
            patterns: Vec::new(),
            pattern_admission: PatternAdmission::default(),
            pattern_budget: crate::patterns::DEFAULT_BUDGET,
            ip_rules: Vec::new(),
            entities: EntityTable::default(),
            ip_pattern_classes: Vec::new(),
            refused: Vec::new(),
        }
    }
}

fn class_of(r: &Rule) -> IpPatternClass {
    if r.is_rewrite() {
        return IpPatternClass::Rewrite;
    }
    if r.is_mapping() {
        return IpPatternClass::Mapping;
    }
    match r.level() {
        Some(Level::ImportantAllow) => IpPatternClass::ImportantAllow,
        Some(Level::ImportantBlock) => IpPatternClass::Important,
        Some(Level::Allow) => IpPatternClass::Allow,
        _ => IpPatternClass::Block,
    }
}

fn has_entities(r: &RichRule) -> bool {
    !r.denyallow_entities.is_empty() || r.unless.iter().any(|s| !s.denyallow_entities.is_empty())
}

/// Compiles a bundle's rules (see the module docs).
pub fn compile_rules(rules: &[Rule], opts: &CompileOptions<'_>) -> Compiled {
    let effects = resolve(rules);
    let orders = urlfilter_order(rules);
    let mut expander = opts.psl.map(|l| EntityExpander::new(l, opts.max_entities));
    let mut out = Compiled::default();
    let mut classes: BTreeSet<IpPatternClass> = BTreeSet::new();
    for (i, r) in rules.iter().enumerate() {
        if r.kind.is_browser() || r.rule_type == RuleType::Browser {
            continue;
        }
        if opts.action == BundleAction::Scope && r.rule_type != RuleType::Dns {
            continue;
        }
        let effect = effects.get(i).cloned().unwrap_or(BadfilterEffect::Kept);
        // A `$badfilter` rule takes part only as a rewrite (AdGuard computes rewrites without it).
        let rich = if r.is_badfilter() {
            if !r.is_rewrite() {
                continue;
            }
            r.rich()
        } else {
            match effective_rich(r, &effect) {
                Some(x) => x,
                None => continue,
            }
        };
        let mut rich = rich;
        if let Some(rr) = rich.as_mut() {
            if r.is_rewrite() {
                rr.order = Some(orders.get(i).copied().flatten().unwrap_or(MatchOrder {
                    gram: None,
                    seq: u32::try_from(i).unwrap_or(u32::MAX),
                }));
            }
            if has_entities(rr)
                && let Some(x) = expander.as_mut()
                && !x.expand(rr)
            {
                out.refused.push(i);
                continue;
            }
        }
        if can_match_ip_text(r) {
            classes.insert(class_of(r));
        }
        match r.key_kind() {
            Kind::Name | Kind::HostMapping | Kind::IpLiteral => {
                let key = if r.key_kind() == Kind::IpLiteral {
                    reverse_dotted(&r.key)
                } else {
                    r.key.clone()
                };
                let folded = match &rich {
                    Some(rr) => Folded {
                        key: key.clone(),
                        flags: Flags::HAS_RICH,
                        rich: Some(rr.clone()),
                    },
                    None => Folded {
                        key: key.clone(),
                        flags: r.flags.and(Flags::ALL_LEVELS),
                        rich: None,
                    },
                };
                out.keys.entry(key).or_default().add(folded);
                if r.key_kind() == Kind::IpLiteral {
                    push_ip(&mut out, i, r, rich.as_ref());
                }
            }
            Kind::IpRange => push_ip(&mut out, i, r, rich.as_ref()),
            Kind::Pattern | Kind::Regex => {
                let Some(mut spec) = r.pattern_spec() else {
                    continue;
                };
                let exact = r.flags.exact().union(r.flags.subs_as_exact());
                match rich {
                    Some(mut rr) => {
                        rr.flags = exact;
                        spec.flags = Flags::HAS_RICH;
                        spec.rich = Some(rr);
                    }
                    None => {
                        spec.flags = exact;
                        spec.rich = None;
                    }
                }
                out.patterns.push(CompiledPattern {
                    rule: i,
                    spec,
                    admit: PatternAdmit::Free,
                });
            }
            _ => {}
        }
    }
    if let Some(x) = &expander {
        out.entities = x.table();
    }
    out.ip_pattern_classes = classes.into_iter().collect();
    // The reference's admission, over its own pattern list (badfiltered and entity-refused rules
    // included, as it holds them), applied to the patterns kept here.
    let adm = pattern_admission(opts.action, rules, opts.pattern_budget);
    let resident: BTreeMap<usize, usize> = adm.resident.iter().copied().collect();
    let over: BTreeSet<usize> = adm.over_budget.iter().copied().collect();
    let large: BTreeSet<usize> = adm.too_large.iter().copied().collect();
    for p in out.patterns.iter_mut() {
        p.admit = if let Some(&cost) = resident.get(&p.rule) {
            PatternAdmit::Resident { cost }
        } else if over.contains(&p.rule) {
            PatternAdmit::OverBudget
        } else if large.contains(&p.rule) {
            PatternAdmit::TooLarge
        } else {
            PatternAdmit::Free
        };
    }
    out.pattern_admission = adm;
    out.pattern_budget = opts.pattern_budget;
    out
}

fn push_ip(out: &mut Compiled, i: usize, r: &Rule, rich: Option<&RichRule>) {
    let Some(range) = r.ip_range() else { return };
    let exact = r.flags.exact().union(r.flags.subs_as_exact());
    let input = match rich {
        Some(rr) => {
            let mut rr = rr.clone();
            rr.flags = exact;
            IpRuleInput {
                range,
                flags: Flags::NONE,
                rich: Some(rr),
            }
        }
        None => IpRuleInput {
            range,
            flags: exact,
            rich: None,
        },
    };
    out.ip_rules.push((i, input));
}

/// Which part a key goes in, given its reversed name and flags (core's tiering).
pub type PartOf<'a> = &'a dyn Fn(&str, Flags) -> Part;

/// How [`build`] writes a bundle version.
pub struct BuildOptions<'a> {
    pub bundle: &'a str,
    pub action: BundleAction,
    /// 0 = one shard.
    pub max_shard_keys: u64,
    /// Which part a key goes in (block bundles; only plain blocks may go cold). `None`: all hot.
    pub part_of: Option<PartOf<'a>>,
    /// Subsumption pruning (default on).
    pub prune: bool,
    pub issued_at: &'a str,
    pub feed_runs: BTreeMap<String, u64>,
}

impl<'a> BuildOptions<'a> {
    pub fn new(bundle: &'a str, action: BundleAction) -> Self {
        BuildOptions {
            bundle,
            action,
            max_shard_keys: 1_000_000,
            part_of: None,
            prune: true,
            issued_at: "2026-11-21T00:00:00Z",
            feed_runs: BTreeMap::new(),
        }
    }
}

/// A from-scratch bundle version: its head and every blob it names.
#[derive(Clone, Debug)]
pub struct BuiltBundle {
    pub head: Head,
    pub head_blob: Blob,
    /// Every blob by id (manifests, FSTs, filters, page files, `ips.bin`, segments).
    pub blobs: BTreeMap<String, Vec<u8>>,
    /// The keys by part after pruning (reversed name → value).
    pub hot_keys: BTreeMap<String, Value>,
    pub cold_keys: BTreeMap<String, Value>,
    pub runs: BTreeMap<IpShardId, Vec<Run>>,
    pub pattern_fates: Vec<PatternFate>,
    /// Keys left out by subsumption pruning.
    pub pruned: usize,
}

/// Assigns parts and prunes subsumed keys (bundles.md §1 Tiers, §2).
pub fn place_and_prune(
    keys: &BTreeMap<String, KeyValue>,
    part_of: Option<PartOf<'_>>,
    prune: bool,
) -> (BTreeMap<String, (Part, KeyValue)>, usize) {
    let placed: BTreeMap<&str, (Part, &KeyValue)> = keys
        .iter()
        .map(|(k, v)| {
            let part = match part_of {
                Some(f) if v.flags.is_plain_block() && v.rich.is_empty() => f(k, v.flags),
                _ => Part::Hot,
            };
            (k.as_str(), (part, v))
        })
        .collect();
    let mut out = BTreeMap::new();
    let mut pruned = 0usize;
    for (k, (part, v)) in &placed {
        if prune && !v.flags.contains(Flags::HAS_RICH) {
            let mut ancestors: Vec<(Flags, Part)> = Vec::new();
            let mut s: &str = k;
            while let Some(i) = s.rfind('.') {
                s = s.get(..i).unwrap_or("");
                if let Some((p, a)) = placed.get(s) {
                    ancestors.push((a.flags, *p));
                }
            }
            if is_subsumed(v.flags, covering_subs(*part, &ancestors)) {
                pruned = pruned.saturating_add(1);
                continue;
            }
        }
        out.insert((*k).to_string(), (*part, (*v).clone()));
    }
    (out, pruned)
}

/// Builds every blob of a bundle version from compiled rules.
pub fn build(c: &Compiled, opts: &BuildOptions<'_>) -> Result<BuiltBundle, WriteError> {
    let seed = bundle_hash_seed(opts.bundle);
    let part_of = if opts.action == BundleAction::Block {
        opts.part_of
    } else {
        None
    };
    let (placed, pruned) = place_and_prune(&c.keys, part_of, opts.prune);
    let mut rich = RichBuilder::new();
    rich.set_entities(c.entities.clone());
    let mut hot_keys: BTreeMap<String, Value> = BTreeMap::new();
    let mut cold_keys: BTreeMap<String, Value> = BTreeMap::new();
    for (k, (part, v)) in &placed {
        let value = if v.rich.is_empty() {
            Value::flags_only(v.flags)
        } else {
            let set = rich.set(&v.rich);
            Value::new(v.flags | Flags::HAS_RICH, set)
        };
        match part {
            Part::Hot => hot_keys.insert(k.clone(), value),
            Part::Cold => cold_keys.insert(k.clone(), value),
        };
    }
    let mut blobs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let put = |b: &Blob, blobs: &mut BTreeMap<String, Vec<u8>>| {
        blobs.insert(b.id.clone(), b.bytes.clone());
    };
    // Hot shards.
    let (hot_dir, next_shard) = shard_dir_for(hot_keys.keys(), seed, opts.max_shard_keys);
    let mut shards = Vec::new();
    {
        let mut writers: BTreeMap<u32, HotBaseWriter> = hot_dir
            .entries()
            .iter()
            .map(|e| (e.shard, HotBaseWriter::new(opts.bundle, e.shard, seed)))
            .collect();
        for (k, v) in &hot_keys {
            let s = hot_dir.shard_of(KeyHash::of(seed, k.as_bytes()));
            if let Some(w) = writers.get_mut(&s) {
                w.insert(k.as_bytes(), *v)?;
            }
        }
        for (n, w) in writers {
            let base = w.finish()?;
            put(&base.manifest, &mut blobs);
            for (_, f) in &base.files {
                put(f, &mut blobs);
            }
            shards.push(ShardRef {
                shard: n,
                base: base.id().to_string(),
                seq: 0,
                checksum: base.checksum,
                deltas: Vec::<DeltaRef>::new(),
                base_seq: 0,
            });
        }
    }
    // Cold shards.
    let mut cold_shards = Vec::new();
    let mut cold_dir_entries = Vec::new();
    let mut next_cold_shard = 0;
    if !cold_keys.is_empty() {
        let (cold_dir, next) = shard_dir_for(cold_keys.keys(), seed, opts.max_shard_keys);
        next_cold_shard = next;
        cold_dir_entries = cold_dir.entries().to_vec();
        let mut writers: BTreeMap<u32, ColdBaseWriter> = cold_dir
            .entries()
            .iter()
            .map(|e| (e.shard, ColdBaseWriter::new(opts.bundle, e.shard, seed)))
            .collect();
        for (k, v) in &cold_keys {
            let s = cold_dir.shard_of(KeyHash::of(seed, k.as_bytes()));
            if let Some(w) = writers.get_mut(&s) {
                w.insert(k.as_bytes(), *v)?;
            }
        }
        for (n, w) in writers {
            let base = w.finish()?;
            put(&base.manifest, &mut blobs);
            for (_, f) in &base.files {
                put(f, &mut blobs);
            }
            cold_shards.push(ShardRef {
                shard: n,
                base: base.id().to_string(),
                seq: 0,
                checksum: base.checksum,
                deltas: Vec::new(),
                base_seq: 0,
            });
        }
    }
    // IP shards.
    let ip_inputs: Vec<IpRuleInput> = c.ip_rules.iter().map(|(_, r)| r.clone()).collect();
    let runs = fold_runs(&ip_inputs, &mut rich);
    let mut ip_shards = Vec::new();
    for (id, rs) in &runs {
        let b = ip_base(*id, rs)?;
        put(&b.blob, &mut blobs);
        ip_shards.push(IpShardRef {
            ip_shard: *id,
            base: b.blob.id.clone(),
            seq: 0,
            checksum: b.checksum,
            deltas: Vec::new(),
            base_seq: 0,
        });
    }
    // Segments (patterns intern their rich rules first, so rich.json holds every set).
    let inputs: Vec<PatternInput> = c
        .patterns
        .iter()
        .map(|p| PatternInput {
            rich_set: p.spec.rich.as_ref().map(|r| rich.set(std::slice::from_ref(r))),
            spec: p.spec.clone(),
            admit: p.admit,
        })
        .collect();
    let Segments {
        patterns,
        rich: rich_blob,
        fates,
        ..
    } = segments(&inputs, c.pattern_budget, &rich)?;
    put(&patterns, &mut blobs);
    put(&rich_blob, &mut blobs);
    let head = Head {
        bundle: opts.bundle.to_string(),
        format: FORMAT,
        hash_seed: seed,
        shard_dir: hot_dir.entries().to_vec(),
        shards,
        cold_shard_dir: cold_dir_entries,
        cold_shards,
        ip_shards,
        segments: [
            (PATTERNS.to_string(), patterns.id.clone()),
            (RICH.to_string(), rich_blob.id.clone()),
        ]
        .into_iter()
        .collect(),
        ip_pattern_classes: c.ip_pattern_classes.clone(),
        feed_runs: opts.feed_runs.clone(),
        issued_at: opts.issued_at.to_string(),
        action: opts.action,
        max_shard_keys: opts.max_shard_keys,
        next_shard,
        next_cold_shard,
    };
    let (hb, _) = head.to_blob();
    Ok(BuiltBundle {
        head,
        head_blob: Blob::new(hb),
        blobs,
        hot_keys,
        cold_keys,
        runs,
        pattern_fates: fates,
        pruned,
    })
}

/// A directory sized for these keys, and the next unused shard number.
pub fn shard_dir_for<'k>(
    keys: impl Iterator<Item = &'k String>,
    seed: u64,
    max_shard_keys: u64,
) -> (ShardDir, u32) {
    let mut hist = Histogram::default();
    for k in keys {
        hist.add(KeyHash::of(seed, k.as_bytes()));
    }
    let start = ShardDir::single(0);
    match plan(&start, &hist, max_shard_keys, 1) {
        Ok(p) => (p.dir, p.next),
        Err(_) => (start, 1),
    }
}

/// Where blobs come from when loading a whole head.
pub trait BlobSource {
    /// The verified-or-not bytes of blob `id` (the loader verifies them).
    fn blob(&self, id: &str) -> Option<Vec<u8>>;
}

impl BlobSource for BTreeMap<String, Vec<u8>> {
    fn blob(&self, id: &str) -> Option<Vec<u8>> {
        self.get(id).cloned()
    }
}

fn need(store: &dyn BlobSource, id: &str) -> Result<Vec<u8>, LoadError> {
    store
        .blob(id)
        .ok_or_else(|| LoadError::Mismatch(format!("missing blob {id}")))
}

/// A shard's delta blobs, verified, in chain order.
fn chain(store: &dyn BlobSource, deltas: &[DeltaRef]) -> Result<Vec<Vec<u8>>, LoadError> {
    let mut out = Vec::with_capacity(deltas.len());
    for d in deltas {
        let bytes = need(store, &d.blake3)?;
        crate::head::verify_blob(&bytes, &d.blake3)?;
        out.push(bytes);
    }
    Ok(out)
}

fn refs(v: &[Vec<u8>]) -> Vec<&[u8]> {
    v.iter().map(Vec::as_slice).collect()
}

/// Loads a whole head: every shard (base plus its delta chain), cold part (when `pages` reads its
/// page files; otherwise not loaded), IP shard and segment. The edge's boot path: each shard's chain
/// is applied with one overlay rebuild. Activation of a later head swaps parts one at a time
/// instead ([`Bundle::with_hot`] and friends).
pub fn load_bundle(
    head_bytes: &[u8],
    store: &dyn BlobSource,
    pages: Option<&dyn PageReader>,
    pattern_budget: usize,
) -> Result<Bundle, LoadError> {
    let head = Head::from_bytes(head_bytes)?;
    let head_id: Arc<str> = crate::bytes::object_id(head_bytes).into();
    let rich_id = head
        .segment(RICH)
        .ok_or_else(|| LoadError::Mismatch("no rich.json".into()))?;
    let rich = load_rich(rich_id, &need(store, rich_id)?)?;
    let pat_id = head
        .segment(PATTERNS)
        .ok_or_else(|| LoadError::Mismatch("no patterns.bin".into()))?;
    let patterns = PatternsPart::load(
        head_id.clone(),
        pat_id,
        &need(store, pat_id)?,
        pattern_budget,
        rich.clone(),
    )?;
    let mut hot = Vec::new();
    for s in &head.shards {
        let manifest = need(store, &s.base)?;
        let m = crate::head::Manifest::from_bytes(&manifest)?;
        let fst = need(
            store,
            &m.file(crate::head::DOMAINS_FST)
                .map(|f| f.blake3.clone())
                .unwrap_or_default(),
        )?;
        let bf8 = need(
            store,
            &m.file(crate::head::DOMAINS_BF8)
                .map(|f| f.blake3.clone())
                .unwrap_or_default(),
        )?;
        let mut shard = HotShard::load(
            &head.bundle,
            head_id.clone(),
            head.hash_seed,
            s.base_seq,
            HotBaseBlobs {
                base_id: &s.base,
                manifest: &manifest,
                fst,
                bf8: &bf8,
            },
            rich.clone(),
        )?;
        let chain = chain(store, &s.deltas)?;
        if !chain.is_empty() {
            // The deltas' rich indices name sets of this head's segment.
            shard = shard.apply_deltas(&refs(&chain), head_id.clone(), rich.clone())?;
        }
        if shard.checksum() != s.checksum {
            return Err(LoadError::NeedBase(format!("shard {} checksum", s.shard)));
        }
        hot.push(Arc::new(shard));
    }
    let cold = match (head.has_cold(), pages) {
        (false, _) => Cold::None,
        (true, None) => Cold::NotLoaded,
        (true, Some(reader)) => {
            let mut shards = Vec::new();
            for s in &head.cold_shards {
                let manifest = need(store, &s.base)?;
                let m = crate::head::Manifest::from_bytes(&manifest)?;
                let bf8 = need(
                    store,
                    &m.file(crate::head::COLD_BF8)
                        .map(|f| f.blake3.clone())
                        .unwrap_or_default(),
                )?;
                let pages_id = m
                    .file(crate::head::COLD_PAGES)
                    .map(|f| f.blake3.clone())
                    .unwrap_or_default();
                let mut hdr = [0u8; PAGE_SIZE];
                reader
                    .read_page(&pages_id, 0, &mut hdr)
                    .map_err(|e| LoadError::Page(crate::page::PageError::Io(e.to_string())))?;
                let mut shard = ColdShard::load(
                    &head.bundle,
                    head_id.clone(),
                    head.hash_seed,
                    s.base_seq,
                    ColdBaseBlobs {
                        base_id: &s.base,
                        manifest: &manifest,
                        bf8: &bf8,
                    },
                    &hdr,
                )?;
                let chain = chain(store, &s.deltas)?;
                if !chain.is_empty() {
                    shard = shard.apply_deltas(&refs(&chain), reader)?;
                }
                if shard.checksum() != s.checksum {
                    return Err(LoadError::NeedBase(format!("cold shard {} checksum", s.shard)));
                }
                shards.push(Arc::new(shard));
            }
            Cold::Loaded(Arc::new(ColdPart::new(&head.cold_shard_dir, shards, None)?))
        }
    };
    let mut ip = Vec::new();
    for s in &head.ip_shards {
        let bytes = need(store, &s.base)?;
        let mut shard = IpShard::load(
            &head.bundle,
            head_id.clone(),
            &s.base,
            s.base_seq,
            &bytes,
            rich.clone(),
        )?;
        if shard.id != s.ip_shard {
            return Err(LoadError::Mismatch("ips.bin is for another shard".into()));
        }
        let chain = chain(store, &s.deltas)?;
        if !chain.is_empty() {
            shard = shard.apply_deltas(&refs(&chain), head_id.clone(), rich.clone())?;
        }
        if shard.checksum() != s.checksum {
            return Err(LoadError::NeedBase(format!("ip shard {} checksum", s.ip_shard)));
        }
        ip.push(Arc::new(shard));
    }
    Bundle::assemble(
        &head,
        head_id,
        LoadedParts {
            hot,
            cold,
            ip,
            patterns,
        },
    )
}
