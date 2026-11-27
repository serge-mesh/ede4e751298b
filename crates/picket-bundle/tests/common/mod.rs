//! Shared helpers: parse rules, compile and load a bundle through the real writer and reader, and
//! compare decisions with picket-rules' reference matcher.

#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use picket_api::time::Timestamp;
use std::collections::BTreeSet;

use picket_bundle::compile::{
    BuildOptions, BuiltBundle, CompileOptions, Compiled, build, compile_rules, load_bundle, place_and_prune,
};
use picket_bundle::hash::KeyHash;
use picket_bundle::head::{DeltaRef, Head, IpShardRef, PATTERNS, PartKind, RICH};
use picket_bundle::ips::{IpShardId, Run};
use picket_bundle::matcher::{Bundle, ColdCheck, Decision};
use picket_bundle::page::MemPages;
use picket_bundle::patterns::{DEFAULT_BUDGET, PatternInput};
use picket_bundle::rich::RichBuilder;
use picket_bundle::runs::{IpRuleInput, diff_runs, fold_runs};
use picket_bundle::value::Value;
use picket_bundle::writer::{DeltaTarget, KeyChange, ip_base, ip_delta, key_delta, segments};
use picket_rules::compile::Part;
use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};
use picket_rules::ip::netip_string;
use picket_rules::matcher::{BundleAction, BundleMatcher, Outcome};
use picket_rules::psl::PublicSuffixList;
use picket_rules::rewrite::RewriteAnswer;
use picket_rules::{Flags, QueryCtx, Rule};

pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures");

pub fn psl() -> &'static PublicSuffixList {
    static P: OnceLock<PublicSuffixList> = OnceLock::new();
    P.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/picket-core/data/public_suffix_list.dat"
        );
        PublicSuffixList::parse(&std::fs::read_to_string(path).expect("bundled PSL"))
    })
}

/// Parses adblock-format lines into rules, in order.
pub fn parse_rules(lines: &[String]) -> Vec<Rule> {
    let text = lines.join("\n");
    let cfg = ParseConfig::new(Format::Adblock, DomainsAs::Exact, Timestamp::now());
    let mut rules = Vec::new();
    parse_lines(text.as_bytes(), &cfg, |e| rules.push(e.rule)).unwrap();
    rules
}

/// The reference matcher (with the bundled public suffix list).
pub fn reference(action: BundleAction, rules: Vec<Rule>) -> BundleMatcher {
    BundleMatcher::new(action, rules).with_public_suffix_list(psl())
}

/// A compiled, written and loaded bundle, with the page files its cold part reads.
pub struct Loaded {
    pub built: BuiltBundle,
    pub bundle: Bundle,
    pub pages: MemPages,
}

/// How the test build places keys.
#[derive(Clone, Copy, Debug)]
pub enum Tiering {
    AllHot,
    /// Plain blocks go cold when their key hash is odd.
    Mixed,
    /// Every plain block goes cold.
    AllCold,
}

pub fn compile_and_load(
    action: BundleAction,
    rules: &[Rule],
    max_shard_keys: u64,
    tiering: Tiering,
) -> Loaded {
    let compiled = compile_rules(rules, &CompileOptions::new(action, Some(psl())));
    let mixed = |k: &str, _f: Flags| {
        if xxhash_rust::xxh3::xxh3_64(k.as_bytes()) & 1 == 1 {
            Part::Cold
        } else {
            Part::Hot
        }
    };
    let cold = |_k: &str, _f: Flags| Part::Cold;
    let mut opts = BuildOptions::new("test-bundle", action);
    opts.max_shard_keys = max_shard_keys;
    opts.part_of = match tiering {
        Tiering::AllHot => None,
        Tiering::Mixed => Some(&mixed),
        Tiering::AllCold => Some(&cold),
    };
    let built = build(&compiled, &opts).expect("build");
    let mut pages = MemPages::default();
    for s in &built.head.cold_shards {
        let m = picket_bundle::head::Manifest::from_bytes(&built.blobs[&s.base]).unwrap();
        let id = &m.file(picket_bundle::head::COLD_PAGES).unwrap().blake3;
        pages.files.insert(id.clone(), built.blobs[id].clone());
    }
    let bundle = load_bundle(
        &built.head_blob.bytes,
        &built.blobs,
        Some(&pages),
        picket_bundle::patterns::DEFAULT_BUDGET,
    )
    .expect("load");
    Loaded { built, bundle, pages }
}

/// A query: name labels or an address, with its context.
#[derive(Clone, Debug)]
pub enum Target {
    Name(Vec<Vec<u8>>),
    Ip(IpAddr),
}

#[derive(Clone, Debug)]
pub struct Query {
    pub target: Target,
    pub qtype: u16,
    pub client_ip: Option<IpAddr>,
    pub client_name: Option<String>,
    pub tags: Vec<String>,
}

impl Query {
    pub fn name(n: &str) -> Query {
        Query {
            target: Target::Name(dotted(n)),
            qtype: 1,
            client_ip: None,
            client_name: None,
            tags: vec![],
        }
    }

    pub fn ip(ip: IpAddr) -> Query {
        Query {
            target: Target::Ip(ip),
            qtype: 1,
            client_ip: None,
            client_name: None,
            tags: vec![],
        }
    }
}

pub fn dotted(n: &str) -> Vec<Vec<u8>> {
    if n.is_empty() {
        return vec![];
    }
    n.split('.').map(|l| l.as_bytes().to_vec()).collect()
}

/// The decision in the parity tables' syntax (picket-rules' tests use the same), exact for every
/// action: an allow bundle's match is `allowed` and a scope bundle's `in-scope`, never `none`, so
/// allow and scope parity can fail.
pub fn decision(o: &Outcome) -> String {
    match o {
        Outcome::None => "none".into(),
        Outcome::Allow => "allowed".into(),
        Outcome::InScope => "in-scope".into(),
        Outcome::Exception => "allow".into(),
        Outcome::Block => "block".into(),
        Outcome::HostMapping(ips) => {
            let mut v: Vec<String> = ips.iter().map(|ip| netip_string(*ip)).collect();
            v.sort();
            format!("hosts {}", v.join(","))
        }
        Outcome::Rewrite(RewriteAnswer::Cname(c)) => format!("rewrite cname {c}"),
        Outcome::Rewrite(RewriteAnswer::Rcode(r)) => format!("rewrite rcode {r}"),
        Outcome::Rewrite(RewriteAnswer::Records(recs)) => {
            let mut v: Vec<String> = recs
                .iter()
                .map(|(t, val)| format!("{t}={}", val.to_text()))
                .collect();
            v.sort();
            v.dedup();
            format!("rewrite records {}", v.join("|")).trim().to_string()
        }
    }
}

fn with_ctx<R>(q: &Query, f: impl FnOnce(&QueryCtx<'_>) -> R) -> R {
    let names: Vec<&str> = q.client_name.iter().map(String::as_str).collect();
    let tags: Vec<&str> = q.tags.iter().map(String::as_str).collect();
    let ctx = QueryCtx {
        qtype: q.qtype,
        client_ip: q.client_ip,
        client_names: &names,
        client_tags: &tags,
    };
    f(&ctx)
}

/// The reference matcher's outcome.
pub fn reference_outcome(m: &BundleMatcher, q: &Query) -> Outcome {
    with_ctx(q, |ctx| match &q.target {
        Target::Name(l) => {
            let labels: Vec<&[u8]> = l.iter().map(Vec::as_slice).collect();
            m.match_name(&labels, ctx).outcome
        }
        Target::Ip(ip) => m.match_ip(*ip, ctx).outcome,
    })
}

/// The compiled bundle's decision, cold stage included.
pub fn compiled_decision(l: &Loaded, q: &Query) -> Decision {
    bundle_decision(&l.bundle, &l.pages, q)
}

/// A bundle's decision, cold stage included.
pub fn bundle_decision(b: &Bundle, pages: &MemPages, q: &Query) -> Decision {
    with_ctx(q, |ctx| match &q.target {
        Target::Name(n) => {
            let labels: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
            b.lookup_labels_full(&labels, ctx, pages)
        }
        Target::Ip(ip) => {
            let d = b.lookup_ip(*ip, ctx);
            if d.cold == ColdCheck::Needed {
                let c = b.lookup_ip_cold(*ip, pages);
                d.with_cold(c)
            } else {
                d
            }
        }
    })
}

pub fn compiled_outcome(l: &Loaded, q: &Query) -> Outcome {
    compiled_decision(l, q).outcome
}

/// Tiny deterministic PRNG (splitmix64) for randomized cases.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

/// Blobs by id, for loaders.
pub type Store = BTreeMap<String, Vec<u8>>;

pub const CREATED: &str = "2026-11-21T01:00:00Z";

pub type PartOf<'a> = &'a dyn Fn(&str, Flags) -> Part;

/// The next version as base + deltas over `prev` (same shard directories).
pub fn incremental(
    prev: &BuiltBundle,
    c2: &Compiled,
    part_of: Option<PartOf<'_>>,
    seq: u64,
) -> (Head, Store, BTreeMap<String, Value>, BTreeMap<String, Value>) {
    let mut store: Store = prev.blobs.clone();
    // Indices stay stable (bundles.md §6; RichBuilder::from_previous); the entity table is the one
    // for the current rules (review round 1, B5).
    let mut rich = RichBuilder::from_previous(&prev.blobs[prev.head.segment(RICH).unwrap()]).unwrap();
    rich.set_entities(c2.entities.clone());
    let (placed, _) = place_and_prune(&c2.keys, part_of, true);
    let mut hot2 = BTreeMap::new();
    let mut cold2 = BTreeMap::new();
    for (k, (part, v)) in &placed {
        let value = if v.rich.is_empty() {
            Value::flags_only(v.flags)
        } else {
            Value::new(v.flags | Flags::HAS_RICH, rich.set(&v.rich))
        };
        match part {
            Part::Hot => hot2.insert(k.clone(), value),
            Part::Cold => cold2.insert(k.clone(), value),
        };
    }
    let seed = prev.head.hash_seed;
    let mut head = prev.head.clone();
    let diff_part = |shards: &mut Vec<picket_bundle::head::ShardRef>,
                     dir: &picket_bundle::shard_dir::ShardDir,
                     old: &BTreeMap<String, Value>,
                     new: &BTreeMap<String, Value>,
                     part: PartKind,
                     store: &mut Store| {
        let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
        for s in shards.iter_mut() {
            let changes: Vec<KeyChange> = keys
                .iter()
                .filter(|k| dir.shard_of(KeyHash::of(seed, k.as_bytes())) == s.shard)
                .map(|k| KeyChange {
                    key: k.as_bytes().to_vec(),
                    old: old.get(*k).copied(),
                    new: new.get(*k).copied(),
                })
                .filter(|c| c.old != c.new)
                .collect();
            if changes.is_empty() {
                continue;
            }
            let d = key_delta(
                &DeltaTarget {
                    bundle: prev.head.bundle.as_str(),
                    base: &s.base,
                    seq,
                    prev: s.checksum,
                    created_at: CREATED,
                },
                part,
                s.shard,
                &changes,
            );
            store.insert(d.blob.id.clone(), d.blob.bytes.clone());
            s.deltas.push(DeltaRef {
                seq,
                blake3: d.blob.id.clone(),
                size: d.blob.size(),
            });
            s.seq = seq;
            s.checksum = d.header.new_checksum;
        }
    };
    let hot_dir = prev.head.dir().unwrap();
    diff_part(
        &mut head.shards,
        &hot_dir,
        &prev.hot_keys,
        &hot2,
        PartKind::Hot,
        &mut store,
    );
    if let Some(cd) = prev.head.cold_dir().unwrap() {
        diff_part(
            &mut head.cold_shards,
            &cd,
            &prev.cold_keys,
            &cold2,
            PartKind::Cold,
            &mut store,
        );
    } else {
        assert!(cold2.is_empty(), "the test keeps a cold part in both versions");
    }
    // IP shards: diff runs per shard; new shards get a base, emptied ones leave the head.
    let ip_inputs: Vec<IpRuleInput> = c2.ip_rules.iter().map(|(_, r)| r.clone()).collect();
    let runs2 = fold_runs(&ip_inputs, &mut rich);
    let mut ip_shards = Vec::new();
    let ids: BTreeSet<IpShardId> = prev.runs.keys().chain(runs2.keys()).copied().collect();
    for id in ids {
        let empty: Vec<Run> = Vec::new();
        let old = prev.runs.get(&id).unwrap_or(&empty);
        let new = runs2.get(&id).unwrap_or(&empty);
        match (prev.head.ip_shard(id), new.is_empty()) {
            (_, true) => {}
            (None, false) => {
                let b = ip_base(id, new).unwrap();
                store.insert(b.blob.id.clone(), b.blob.bytes.clone());
                ip_shards.push(IpShardRef {
                    ip_shard: id,
                    base: b.blob.id.clone(),
                    seq: 0,
                    checksum: b.checksum,
                    deltas: vec![],
                    base_seq: 0,
                });
            }
            (Some(r), false) => {
                let mut r = r.clone();
                let (dels, ups) = diff_runs(old, new);
                if !dels.is_empty() || !ups.is_empty() {
                    let d = ip_delta(
                        &DeltaTarget {
                            bundle: prev.head.bundle.as_str(),
                            base: &r.base,
                            seq,
                            prev: r.checksum,
                            created_at: CREATED,
                        },
                        id,
                        &dels,
                        &ups,
                    );
                    store.insert(d.blob.id.clone(), d.blob.bytes.clone());
                    r.deltas.push(DeltaRef {
                        seq,
                        blake3: d.blob.id.clone(),
                        size: d.blob.size(),
                    });
                    r.seq = seq;
                    r.checksum = d.header.new_checksum;
                }
                ip_shards.push(r);
            }
        }
    }
    head.ip_shards = ip_shards;
    let inputs: Vec<PatternInput> = c2
        .patterns
        .iter()
        .map(|p| PatternInput {
            rich_set: p.spec.rich.as_ref().map(|r| rich.set(std::slice::from_ref(r))),
            spec: p.spec.clone(),
            admit: p.admit,
        })
        .collect();
    // Reclaim what the new head no longer references (review round 1, B6): every set its keys,
    // runs and patterns name.
    let live: BTreeSet<u32> = hot2
        .values()
        .chain(cold2.values())
        .copied()
        .chain(runs2.values().flatten().map(|r| r.value))
        .filter_map(Value::rich_idx)
        .chain(inputs.iter().filter_map(|p| p.rich_set))
        .collect();
    rich.retain_sets(&live);
    let seg = segments(&inputs, c2.pattern_budget, &rich).unwrap();
    for b in [&seg.patterns, &seg.rich] {
        store.insert(b.id.clone(), b.bytes.clone());
    }
    head.segments.insert(PATTERNS.into(), seg.patterns.id.clone());
    head.segments.insert(RICH.into(), seg.rich.id.clone());
    head.ip_pattern_classes = c2.ip_pattern_classes.clone();
    (head, store, hot2, cold2)
}

pub fn pages_for(head: &Head, store: &Store) -> MemPages {
    let mut pages = MemPages::default();
    for s in &head.cold_shards {
        let m = picket_bundle::head::Manifest::from_bytes(&store[&s.base]).unwrap();
        let id = &m.file(picket_bundle::head::COLD_PAGES).unwrap().blake3;
        pages.files.insert(id.clone(), store[id].clone());
    }
    pages
}

pub fn load(head: &Head, store: &Store) -> (Bundle, MemPages) {
    let pages = pages_for(head, store);
    let b = load_bundle(&head.to_bytes(), store, Some(&pages), DEFAULT_BUDGET).unwrap();
    (b, pages)
}
