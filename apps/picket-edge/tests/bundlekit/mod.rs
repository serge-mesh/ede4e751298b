//! Real bundles and verdict sets for the activation tests, built with picket-bundle's writer as
//! core would (bundles.md §2, §4–§5; providers.md §4): a from-scratch build, the next version as
//! deltas over a previous one (hot and cold moves included), and publishing every blob in the
//! mock core's objects bucket (api.md §2).

#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;

use picket_bundle::compile::{
    BuildOptions, BuiltBundle, CompileOptions, Compiled, build, compile_rules, place_and_prune,
};
use picket_bundle::hash::KeyHash;
use picket_bundle::head::{COLD_PAGES, DeltaRef, Head, Manifest, PATTERNS, PartKind, RICH};
use picket_bundle::patterns::PatternInput;
use picket_bundle::rich::RichBuilder;
use picket_bundle::value::Value;
use picket_bundle::verdict::{VerdictHead, VerdictKind, VerdictRecord, name_hash, write_base};
use picket_bundle::writer::{DeltaTarget, KeyChange, key_delta, segments};
use picket_rules::compile::Part;
use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};
use picket_rules::matcher::BundleAction;
use picket_rules::{Flags, Rule};

use crate::support::MockCore;

pub type Store = BTreeMap<String, Vec<u8>>;
/// Which part a key goes in.
pub type PartOf<'a> = &'a dyn Fn(&str, Flags) -> Part;
pub const CREATED: &str = "2026-11-21T01:00:00Z";

/// Parses adblock-format lines into rules, in order.
pub fn parse_rules(lines: &[&str]) -> Vec<Rule> {
    let text = lines.join("\n");
    let cfg = ParseConfig::new(Format::Adblock, DomainsAs::Exact, Timestamp::now());
    let mut rules = Vec::new();
    parse_lines(text.as_bytes(), &cfg, |e| rules.push(e.rule)).unwrap();
    rules
}

pub fn compile(lines: &[&str]) -> Compiled {
    compile_rules(
        &parse_rules(lines),
        &CompileOptions::new(BundleAction::Block, None),
    )
}

/// Keys whose reversed name contains one of `cold` go to the cold part.
pub fn cold_if(cold: &'static [&'static str]) -> impl Fn(&str, Flags) -> Part {
    move |k: &str, _f: Flags| {
        if cold.iter().any(|c| k.contains(c)) {
            Part::Cold
        } else {
            Part::Hot
        }
    }
}

/// A from-scratch block bundle.
pub fn build_bundle(name: &str, lines: &[&str], part_of: Option<PartOf<'_>>) -> BuiltBundle {
    build_sharded(
        name,
        lines,
        part_of,
        BuildOptions::new(name, BundleAction::Block).max_shard_keys,
    )
}

/// A from-scratch block bundle whose hot shards hold at most `max_shard_keys` keys each.
pub fn build_sharded(
    name: &str,
    lines: &[&str],
    part_of: Option<PartOf<'_>>,
    max_shard_keys: u64,
) -> BuiltBundle {
    let c = compile(lines);
    let mut o = BuildOptions::new(name, BundleAction::Block);
    o.part_of = part_of;
    o.max_shard_keys = max_shard_keys;
    build(&c, &o).unwrap()
}

/// The next version as deltas over `prev` (same shard directories; hot and cold keys diffed per
/// part, so a key moving between the parts gets both sides of the move). Returns the head, every
/// blob it names (with `prev`'s), and its hot and cold keys.
pub fn incremental(
    prev_head: &Head,
    prev_blobs: &Store,
    prev_hot: &BTreeMap<String, Value>,
    prev_cold: &BTreeMap<String, Value>,
    lines: &[&str],
    part_of: Option<PartOf<'_>>,
    seq: u64,
) -> (Head, Store, BTreeMap<String, Value>, BTreeMap<String, Value>) {
    let c2 = compile(lines);
    let mut store = prev_blobs.clone();
    let mut rich = RichBuilder::from_previous(&prev_blobs[prev_head.segment(RICH).unwrap()]).unwrap();
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
    let seed = prev_head.hash_seed;
    let mut head = prev_head.clone();
    let diff = |shards: &mut Vec<picket_bundle::head::ShardRef>,
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
                    bundle: prev_head.bundle.as_str(),
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
    let hot_dir = prev_head.dir().unwrap();
    diff(
        &mut head.shards,
        &hot_dir,
        prev_hot,
        &hot2,
        PartKind::Hot,
        &mut store,
    );
    if let Some(cd) = prev_head.cold_dir().unwrap() {
        diff(
            &mut head.cold_shards,
            &cd,
            prev_cold,
            &cold2,
            PartKind::Cold,
            &mut store,
        );
    } else {
        assert!(cold2.is_empty(), "the test keeps a cold part in both versions");
    }
    let inputs: Vec<PatternInput> = c2
        .patterns
        .iter()
        .map(|p| PatternInput {
            rich_set: p.spec.rich.as_ref().map(|r| rich.set(std::slice::from_ref(r))),
            spec: p.spec.clone(),
            admit: p.admit,
        })
        .collect();
    let seg = segments(&inputs, c2.pattern_budget, &rich).unwrap();
    for b in [&seg.patterns, &seg.rich] {
        store.insert(b.id.clone(), b.bytes.clone());
    }
    head.segments.insert(PATTERNS.into(), seg.patterns.id.clone());
    head.segments.insert(RICH.into(), seg.rich.id.clone());
    head.ip_pattern_classes = c2.ip_pattern_classes.clone();
    (head, store, hot2, cold2)
}

/// Publishes a head and its blobs in the mock core's objects bucket; returns the head id.
pub fn publish(core: &MockCore, head: &Head, store: &Store) -> String {
    let (bytes, id) = head.to_blob();
    core.with(|s| {
        s.objects
            .insert(format!("bundles/{}/heads/{id}.json", head.bundle), bytes.clone());
        for (k, v) in store {
            s.objects.insert(format!("blobs/{k}"), v.clone());
        }
    });
    id
}

/// The page files a head's cold part reads, by id.
pub fn page_files(head: &Head, store: &Store) -> Vec<String> {
    head.cold_shards
        .iter()
        .map(|s| {
            let m = Manifest::from_bytes(&store[&s.base]).unwrap();
            m.file(COLD_PAGES).unwrap().blake3.clone()
        })
        .collect()
}

/// A verdict set's head and blobs: one record per (name, verdict).
pub fn verdict_set(
    provider: &str,
    generation: &str,
    records: &[(&str, VerdictKind)],
) -> (VerdictHead, Store) {
    let seed = picket_bundle::hash::verdict_hash_seed(provider, generation);
    let at = Timestamp::from_microsecond(Timestamp::now().as_microsecond() - 1_000_000).unwrap();
    let recs: Vec<(KeyHash, VerdictRecord)> = records
        .iter()
        .map(|(n, v)| {
            (
                name_hash(seed, n),
                VerdictRecord {
                    verdict: *v,
                    obtained_at: at,
                    score: None,
                    reason: (*v == VerdictKind::Block).then(|| "listed".to_owned()),
                },
            )
        })
        .collect();
    let base = write_base(provider, generation, &recs).unwrap();
    let head = VerdictHead {
        provider: provider.into(),
        format: picket_bundle::FORMAT,
        generation: generation.into(),
        hash_seed: seed,
        base: base.blob.id.clone(),
        deltas: vec![],
        seq: 0,
        checksum: base.checksum,
        issued_at: CREATED.into(),
    };
    let mut store = Store::new();
    store.insert(base.blob.id.clone(), base.blob.bytes.clone());
    (head, store)
}

/// Publishes a verdict-set head and its blobs; returns the head id.
pub fn publish_set(core: &MockCore, head: &VerdictHead, store: &Store) -> String {
    let b = head.to_blob();
    core.with(|s| {
        s.objects.insert(
            format!("verdict-sets/{}/heads/{}.json", head.provider, b.id),
            b.bytes.clone(),
        );
        for (k, v) in store {
            s.objects.insert(format!("blobs/{k}"), v.clone());
        }
    });
    b.id
}
