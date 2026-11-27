//! Shards (build-and-test.md §5 "Bundles"; bundles.md §4 "Shards", §6 "Activation"): splits and
//! merges keep every key in exactly one shard, new shards take numbers never used before, and a
//! split swapped into a loaded bundle keeps every key matching.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use common::*;
use picket_bundle::hash::{KeyHash, bundle_hash_seed};
use picket_bundle::reader::{HotBaseBlobs, HotShard};
use picket_bundle::rich::RichSegment;
use picket_bundle::shard_dir::{Histogram, ShardDir, ShardEntry, plan};
use picket_bundle::value::Value;
use picket_bundle::writer::HotBaseWriter;
use picket_rules::Flags;
use picket_rules::matcher::BundleAction;

fn keys(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("com.example.k{i:05}")).collect()
}

fn hist(seed: u64, keys: &[String]) -> Histogram {
    let mut h = Histogram::default();
    for k in keys {
        h.add(KeyHash::of(seed, k.as_bytes()));
    }
    h
}

fn owners(dir: &ShardDir, seed: u64, keys: &[String]) -> BTreeMap<u32, usize> {
    let mut m = BTreeMap::new();
    for k in keys {
        let h = KeyHash::of(seed, k.as_bytes());
        // Exactly one entry owns the key's directory index.
        let n = dir
            .entries()
            .iter()
            .filter(|e| {
                let (s, t) = e.index_range().unwrap();
                (s..t).contains(&usize::from(h.dir_index()))
            })
            .count();
        assert_eq!(n, 1, "{k}");
        *m.entry(dir.shard_of(h)).or_default() += 1;
    }
    m
}

#[test]
fn splits_and_merges_keep_keys_in_one_shard() {
    let seed = bundle_hash_seed("shards");
    let ks = keys(5000);
    let mut used: BTreeSet<u32> = BTreeSet::from([0]);
    let start = ShardDir::single(0);
    let p = plan(&start, &hist(seed, &ks), 600, 1).unwrap();
    assert!(p.dir.entries().len() >= 8, "{}", p.dir.entries().len());
    for step in &p.steps {
        for e in &step.add {
            assert!(used.insert(e.shard), "shard number {} reused", e.shard);
        }
    }
    let counts = owners(&p.dir, seed, &ks);
    assert!(counts.values().all(|&c| c <= 600), "{counts:?}");
    assert_eq!(counts.values().sum::<usize>(), ks.len());
    // Most keys deleted: siblings merge below 75 % of the cap, again with new numbers.
    let few = &ks[..300];
    let p2 = plan(&p.dir, &hist(seed, few), 600, p.next).unwrap();
    assert!(p2.steps.iter().any(|s| s.remove.len() == 2), "merges happen");
    for step in &p2.steps {
        for e in &step.add {
            assert!(used.insert(e.shard), "shard number {} reused", e.shard);
        }
    }
    let counts = owners(&p2.dir, seed, few);
    assert_eq!(counts.values().sum::<usize>(), few.len());
    // max_shard_keys 0: one shard.
    let p3 = plan(&p.dir, &hist(seed, &ks), 0, p2.next).unwrap();
    assert_eq!(p3.dir.entries().len(), 1);
    assert!(used.insert(p3.dir.entries()[0].shard));
    // A shard that can't split again is reported, not split.
    let p4 = plan(&start, &hist(seed, &ks), 1, 1).unwrap();
    assert!(p4.dir.entries().iter().all(|e| e.prefix_bits <= 8));
    assert!(!p4.cant_split.is_empty());
}

#[test]
fn split_swaps_in_as_one_step() {
    // A loaded single-shard bundle; core splits shard 0 into two new shards; the edge swaps both
    // and the new directory in at once, and every key still matches.
    let rules: Vec<String> = (0..200).map(|i| format!("||k{i}.example^")).collect();
    let l = compile_and_load(BundleAction::Block, &parse_rules(&rules), 0, Tiering::AllHot);
    let seed = l.built.head.hash_seed;
    let dir = l.built.head.dir().unwrap();
    let mut next = 1;
    let (new_dir, halves) = dir.split(0, &mut next).unwrap();
    let rich = Arc::new(RichSegment::empty());
    let mut shards = Vec::new();
    for e in halves {
        let mut w = HotBaseWriter::new("test-bundle", e.shard, seed);
        for (k, v) in &l.built.hot_keys {
            if new_dir.shard_of(KeyHash::of(seed, k.as_bytes())) == e.shard {
                w.insert(k.as_bytes(), *v).unwrap();
            }
        }
        let base = w.finish().unwrap();
        let s = HotShard::load(
            "test-bundle",
            l.bundle.head().into(),
            seed,
            0,
            HotBaseBlobs {
                base_id: base.id(),
                manifest: &base.manifest.bytes,
                fst: base.file("domains.fst").unwrap().bytes.clone(),
                bf8: &base.file("domains.bf8").unwrap().bytes,
            },
            rich.clone(),
        )
        .unwrap();
        shards.push(Arc::new(s));
    }
    // A partial swap (one half only) is refused: each key stays covered by exactly one shard.
    assert!(
        l.bundle
            .with_hot(new_dir.entries(), vec![shards[0].clone()])
            .is_err()
    );
    let b = l.bundle.with_hot(new_dir.entries(), shards).unwrap();
    assert_eq!(b.hot_shards().len(), 2);
    for i in 0..200 {
        let q = Query::name(&format!("x.k{i}.example"));
        assert_eq!(
            decision(&bundle_decision(&b, &l.pages, &q).outcome),
            "block",
            "{i}"
        );
    }
    // `versions` lists the parts (the shard numbers changed from the head's layout).
    assert!(matches!(b.versions(), picket_api::logs::BundleVersion::Parts(_)));
    assert!(matches!(
        l.bundle.versions(),
        picket_api::logs::BundleVersion::Plain(_)
    ));
    let _ = (
        ShardEntry {
            prefix: 0,
            prefix_bits: 0,
            shard: 0,
        },
        Value::flags_only(Flags::B_EXACT),
    );
}

/// Review round 2, CR3: the planner never leaves a shard over the reader's
/// [`MAX_SHARD_KEYS`], whatever `max_shard_keys` says (0, "one shard", included): a bundle too
/// big for one shard splits rather than build a base no edge would load.
#[test]
fn planner_keeps_every_shard_within_the_reader_cap() {
    use picket_bundle::domains::MAX_SHARD_KEYS;
    let uniform = |total: u64| {
        let mut h = Histogram::default();
        for c in h.0.iter_mut() {
            *c = total / 256;
        }
        h
    };
    let start = ShardDir::single(0);
    for (total, max) in [
        (3 * MAX_SHARD_KEYS, 0),
        (3 * MAX_SHARD_KEYS, 10 * MAX_SHARD_KEYS),
        (MAX_SHARD_KEYS + 256 * 4, 0),
    ] {
        let h = uniform(total);
        let p = plan(&start, &h, max, 1).unwrap();
        assert!(p.dir.entries().len() > 1, "{total} keys, max {max}");
        for e in p.dir.entries() {
            assert!(h.count(e) <= MAX_SHARD_KEYS, "{e:?}: {}", h.count(e));
        }
        assert!(p.cant_split.is_empty());
    }
    // Within the cap, 0 still means one shard, and a directory collapses back to one.
    let h = uniform(MAX_SHARD_KEYS);
    let p = plan(&start, &h, 0, 1).unwrap();
    assert_eq!(p.dir.entries().len(), 1);
    let split = plan(&start, &uniform(3 * MAX_SHARD_KEYS), 0, 1).unwrap();
    let back = plan(&split.dir, &h, 0, split.next).unwrap();
    assert_eq!(back.dir.entries().len(), 1);
}

/// … and the writer refuses a hot shard base past it, instead of publishing one the edge refuses.
#[test]
fn writer_refuses_a_hot_shard_past_the_reader_cap() {
    use picket_bundle::domains::{FstWriter, MAX_SHARD_KEYS};
    let mut w = FstWriter::new();
    let v = Value::flags_only(Flags::B_EXACT);
    let key = |i: u64| format!("a{i:08}");
    for i in 0..MAX_SHARD_KEYS {
        w.insert(key(i).as_bytes(), v).unwrap();
    }
    assert!(w.insert(key(MAX_SHARD_KEYS).as_bytes(), v).is_err());
    let mut hw = HotBaseWriter::new("b", 0, 1);
    hw.insert(b"com.example", v).unwrap();
    assert!(hw.finish().is_ok());
}
