//! Activation steps (bundles.md §2 "Moves", §6 "Activation"; edge.md §13 "Order"): a new head's
//! first step keeps every part it doesn't swap yet deciding as before, so a key moving between the
//! parts is never in neither, and the IPv4 fast path follows the parts actually active.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::sync::Arc;

use common::*;
use picket_bundle::compile::{BuildOptions, BuiltBundle, CompileOptions, build, compile_rules};
use picket_bundle::head::{DOMAINS_BF8, DOMAINS_FST, Manifest, PATTERNS, RICH};
use picket_bundle::matcher::{Bundle, Cold};
use picket_bundle::patterns::DEFAULT_BUDGET;
use picket_bundle::reader::{HotBaseBlobs, HotShard, PatternsPart, load_rich};
use picket_rules::Flags;
use picket_rules::compile::Part;
use picket_rules::matcher::{BundleAction, Outcome};

fn built(lines: &[&str], part_of: Option<PartOf<'_>>) -> BuiltBundle {
    let rules = parse_rules(&lines.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let c = compile_rules(&rules, &CompileOptions::new(BundleAction::Block, Some(psl())));
    let mut o = BuildOptions::new("act", BundleAction::Block);
    o.part_of = part_of;
    build(&c, &o).unwrap()
}

fn id(b: &BuiltBundle) -> Arc<str> {
    b.head_blob.id.as_str().into()
}

/// Hot shard `n` of a built head, loaded as that head's part.
fn hot_shard(b: &BuiltBundle, n: u32) -> Arc<HotShard> {
    let s = b.head.shard(n).unwrap();
    let manifest = &b.blobs[&s.base];
    let m = Manifest::from_bytes(manifest).unwrap();
    let rich = load_rich(
        b.head.segment(RICH).unwrap(),
        &b.blobs[b.head.segment(RICH).unwrap()],
    )
    .unwrap();
    Arc::new(
        HotShard::load(
            &b.head.bundle,
            id(b),
            b.head.hash_seed,
            0,
            HotBaseBlobs {
                base_id: &s.base,
                manifest,
                fst: b.blobs[&m.file(DOMAINS_FST).unwrap().blake3].clone(),
                bf8: &b.blobs[&m.file(DOMAINS_BF8).unwrap().blake3],
            },
            rich,
        )
        .unwrap(),
    )
}

fn patterns_part(b: &BuiltBundle) -> PatternsPart {
    let rich_id = b.head.segment(RICH).unwrap();
    let rich = load_rich(rich_id, &b.blobs[rich_id]).unwrap();
    let pid = b.head.segment(PATTERNS).unwrap();
    PatternsPart::load(id(b), pid, &b.blobs[pid], DEFAULT_BUDGET, rich).unwrap()
}

fn outcome(b: &Bundle, pages: &picket_bundle::page::MemPages, n: &str) -> Outcome {
    bundle_decision(b, pages, &Query::name(n)).outcome
}

/// Review round 1, B1: a head with no cold part keeps the previous cold part until its hot swaps
/// are done; between its first step and the swap (or forever, if the swap fails) a key moving
/// cold → hot still blocks from the cold part.
#[test]
fn head_without_cold_part_keeps_the_old_one_until_the_hot_swaps() {
    let cold_moved = |k: &str, _f: Flags| {
        if k == "example.moved" {
            Part::Cold
        } else {
            Part::Hot
        }
    };
    let lines = ["||moved.example^", "||stay.example^"];
    let v1 = built(&lines, Some(&cold_moved));
    assert!(!v1.head.cold_shards.is_empty());
    let v2 = built(&lines, None);
    assert!(v2.head.cold_shards.is_empty(), "v2 has no cold part");
    let (b1, pages) = load(&v1.head, &v1.blobs);
    assert_eq!(outcome(&b1, &pages, "moved.example"), Outcome::Block);
    // Step 1: the head itself.
    let step1 = b1.with_head(&v2.head, id(&v2)).unwrap();
    assert!(
        matches!(step1.cold(), Cold::Loaded(_)),
        "the previous cold part stays"
    );
    for n in ["moved.example", "x.moved.example", "stay.example"] {
        assert_eq!(
            outcome(&step1, &pages, n),
            Outcome::Block,
            "after the head step: {n}"
        );
    }
    // `versions` lists the parts, the cold shard with the head it came from.
    match step1.versions() {
        picket_api::logs::BundleVersion::Parts(p) => {
            assert_eq!(p.cold_shards.len(), 1);
        }
        other => panic!("mid-activation versions must list parts: {other:?}"),
    }
    // Step 2: the hot swap (v2's shard is a new base).
    let step2 = step1
        .with_hot(&v2.head.shard_dir, vec![hot_shard(&v2, v2.head.shards[0].shard)])
        .unwrap();
    assert_eq!(outcome(&step2, &pages, "moved.example"), Outcome::Block);
    // Step 3: the cold part goes once the hot swaps are done.
    let step3 = step2.drop_previous_cold();
    assert!(matches!(step3.cold(), Cold::None));
    for n in ["moved.example", "x.moved.example", "stay.example"] {
        assert_eq!(outcome(&step3, &pages, n), Outcome::Block, "after the swap: {n}");
        let d = bundle_decision(&step3, &pages, &Query::name(n));
        assert!(!d.reason.unwrap().cold, "{n} now blocks from the hot part");
    }
    assert!(step3.ip_shards().count() == 0);
    // A head that still has a cold part keeps it through `drop_previous_cold`.
    assert!(matches!(b1.drop_previous_cold().cold(), Cold::Loaded(_)));
    // Without a usable SSD the previous head's cold part was never loaded: the head step keeps
    // marking cold-stage lookups unchecked (fail open, logged) until the hot swaps are done.
    let nl = b1
        .with_cold(Cold::NotLoaded)
        .with_head(&v2.head, id(&v2))
        .unwrap();
    assert!(nl.cold_not_loaded());
    let d = bundle_decision(&nl, &pages, &Query::name("moved.example"));
    assert_eq!(d.cold, picket_bundle::ColdCheck::Unchecked { refetch: vec![] });
    assert!(!nl.drop_previous_cold().cold_not_loaded());
}

/// Review round 1, B2: the IPv4 fast path follows the parts actually active. A head removing the
/// only `@@` IP-text pattern doesn't turn the fast path on while the previous patterns segment,
/// which still holds that exception, is active.
#[test]
fn ip_fast_path_waits_for_the_parts_that_carried_the_exception() {
    let v1 = built(&["||1.2.3.4^", r"@@/^1\.2\.3\./"], None);
    let v2 = built(&["||1.2.3.4^"], None);
    let (b1, pages) = load(&v1.head, &v1.blobs);
    let ip = Query::ip("1.2.3.4".parse().unwrap());
    assert_eq!(bundle_decision(&b1, &pages, &ip).outcome, Outcome::Exception);
    let step1 = b1.with_head(&v2.head, id(&v2)).unwrap();
    assert_eq!(
        bundle_decision(&step1, &pages, &ip).outcome,
        Outcome::Exception,
        "the old patterns segment (with the exception) is still active"
    );
    let step2 = step1.with_patterns(patterns_part(&v2));
    assert_eq!(bundle_decision(&step2, &pages, &ip).outcome, Outcome::Block);
    // The other way: a head adding an exception takes effect only with the part that carries it,
    // and the fast path never hides it once that part is active.
    let (b2, _) = load(&v2.head, &v2.blobs);
    let up = b2.with_head(&v1.head, id(&v1)).unwrap();
    assert_eq!(bundle_decision(&up, &pages, &ip).outcome, Outcome::Block);
    let up = up.with_patterns(patterns_part(&v1));
    assert_eq!(bundle_decision(&up, &pages, &ip).outcome, Outcome::Exception);
    // An exception carried by a key: `@@||2.3.4^` is a partial-IP key matching the address's
    // text, so the hot shard's head counts too.
    let v3 = built(&["||1.2.3.4^", "@@||2.3.4^"], None);
    let (b3, _) = load(&v3.head, &v3.blobs);
    assert_eq!(bundle_decision(&b3, &pages, &ip).outcome, Outcome::Exception);
    let step = b3.with_head(&v2.head, id(&v2)).unwrap();
    assert_eq!(
        bundle_decision(&step, &pages, &ip).outcome,
        Outcome::Exception,
        "until v3's hot shard is swapped out, its exception still decides"
    );
    let step = step
        .with_hot(&v2.head.shard_dir, vec![hot_shard(&v2, v2.head.shards[0].shard)])
        .unwrap();
    assert_eq!(bundle_decision(&step, &pages, &ip).outcome, Outcome::Block);
}

/// Review round 1, B8 (b): mid-activation, hot shards and the patterns part can read different
/// heads' `rich.json`; the bundle's memory counts each segment held, once.
#[test]
fn memory_counts_every_rich_segment_held() {
    let v1 = built(&["||a.example^$dnstype=AAAA", "||b.example^"], None);
    let many: Vec<String> = (0..300)
        .map(|i| format!("||r{i}.example^$dnsrewrite=10.0.{}.{}", i / 250, i % 250))
        .collect();
    let v2 = built(&many.iter().map(String::as_str).collect::<Vec<_>>(), None);
    let (b1, _) = load(&v1.head, &v1.blobs);
    let p2 = patterns_part(&v2);
    let v2_rich = p2.rich.memory_usage();
    assert!(v2_rich > 10_000);
    let mid = b1.with_head(&v2.head, id(&v2)).unwrap().with_patterns(p2);
    // v1's hot shard still reads v1's segment; the patterns part reads v2's.
    assert_eq!(mid.memory_usage(), b1.memory_usage() + v2_rich);
    // Once every part reads v2's segment it counts once.
    let (b2, _) = load(&v2.head, &v2.blobs);
    let hot_and_patterns: usize = b2.hot_shards().iter().map(|s| s.memory_usage()).sum::<usize>()
        + b2.patterns().patterns.memory_usage();
    assert_eq!(b2.memory_usage(), hot_and_patterns + v2_rich);
}
