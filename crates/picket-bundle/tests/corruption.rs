//! Integrity (build-and-test.md §5 "Bundles", "Verdict caches"; bundles.md §4–§6): checksum
//! mismatches after a delta mean "need base"; a corrupted page is a failed, unchecked cold lookup
//! naming the file to refetch; a cold part that isn't loaded fails open; corrupted blobs are
//! refused when loading.

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
use picket_bundle::ColdCheck;
use picket_bundle::checksum::SetChecksum;
use picket_bundle::compile::load_bundle;
use picket_bundle::head::{Head, Manifest, PartKind};
use picket_bundle::matcher::Cold;
use picket_bundle::page::{MemPages, PAGE_SIZE};
use picket_bundle::patterns::DEFAULT_BUDGET;
use picket_bundle::reader::LoadError;
use picket_bundle::value::Value;
use picket_bundle::writer::{DeltaTarget, KeyChange, key_delta};
use picket_rules::matcher::BundleAction;

fn rules(v: &[&str]) -> Vec<picket_rules::Rule> {
    parse_rules(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

#[test]
fn delta_checksum_mismatch_needs_base() {
    let l = compile_and_load(
        BundleAction::Block,
        &rules(&["||a.example^", "||b.example^"]),
        0,
        Tiering::AllHot,
    );
    let shard = &l.bundle.hot_shards()[0];
    let (h, r) = (shard.head.clone(), shard.rich_arc().clone());
    let s = &l.built.head.shards[0];
    let good = key_delta(
        &DeltaTarget {
            bundle: "test-bundle",
            base: &s.base,
            seq: 1,
            prev: s.checksum,
            created_at: "t",
        },
        PartKind::Hot,
        s.shard,
        &[KeyChange {
            key: b"example.c".to_vec(),
            old: None,
            new: Some(Value(3)),
        }],
    );
    let applied = shard.apply_delta(&good.blob.bytes, h.clone(), r.clone()).unwrap();
    assert_eq!(applied.checksum(), good.header.new_checksum);
    // The edge's state diverged from core's: core thinks `a` has another value.
    let bad = key_delta(
        &DeltaTarget {
            bundle: "test-bundle",
            base: &s.base,
            seq: 1,
            prev: s.checksum,
            created_at: "t",
        },
        PartKind::Hot,
        s.shard,
        &[KeyChange {
            key: b"example.a".to_vec(),
            old: Some(Value(1)),
            new: None,
        }],
    );
    assert!(matches!(
        shard.apply_delta(&bad.blob.bytes, h.clone(), r.clone()),
        Err(LoadError::NeedBase(_))
    ));
    // A gap in the chain (prev checksum isn't ours) and a replayed delta.
    let gap = key_delta(
        &DeltaTarget {
            bundle: "test-bundle",
            base: &s.base,
            seq: 2,
            prev: SetChecksum(7),
            created_at: "t",
        },
        PartKind::Hot,
        s.shard,
        &[KeyChange {
            key: b"example.d".to_vec(),
            old: None,
            new: Some(Value(1)),
        }],
    );
    assert!(matches!(
        applied.apply_delta(&gap.blob.bytes, h.clone(), r.clone()),
        Err(LoadError::NeedBase(_))
    ));
    assert!(matches!(
        applied.apply_delta(&good.blob.bytes, h.clone(), r.clone()),
        Err(LoadError::NeedBase(_))
    ));
    // A delta for another base.
    let other = key_delta(
        &DeltaTarget {
            bundle: "test-bundle",
            base: &"0".repeat(64),
            seq: 1,
            prev: s.checksum,
            created_at: "t",
        },
        PartKind::Hot,
        s.shard,
        &[],
    );
    assert!(matches!(
        shard.apply_delta(&other.blob.bytes, h.clone(), r.clone()),
        Err(LoadError::NeedBase(_))
    ));
}

#[test]
fn corrupted_page_is_unchecked_and_refetched() {
    let l = compile_and_load(
        BundleAction::Block,
        &rules(&["||cold.example^", "||hot.example^$important"]),
        0,
        Tiering::AllCold,
    );
    assert!(!l.built.head.cold_shards.is_empty());
    let q = Query::name("x.cold.example");
    assert_eq!(compiled_decision(&l, &q).cold, ColdCheck::Matched);
    // Flip a byte in every record page.
    let mut bad = MemPages::default();
    let mut file_id = String::new();
    for (id, bytes) in &l.pages.files {
        let mut b = bytes.clone();
        for p in (PAGE_SIZE..b.len()).step_by(PAGE_SIZE) {
            b[p + 3] ^= 0x40;
        }
        bad.files.insert(id.clone(), b);
        file_id = id.clone();
    }
    let d = bundle_decision(&l.bundle, &bad, &q);
    assert_eq!(d.outcome, picket_rules::matcher::Outcome::None, "fails open");
    assert_eq!(
        d.cold,
        ColdCheck::Unchecked {
            refetch: vec![file_id.clone()]
        }
    );
    // A read error (file gone) is unchecked without a refetch.
    let d = bundle_decision(&l.bundle, &MemPages::default(), &q);
    assert_eq!(d.cold, ColdCheck::Unchecked { refetch: vec![] });
    // The hot part still decides without the cold stage.
    let d = bundle_decision(&l.bundle, &bad, &Query::name("hot.example"));
    assert_eq!(d.cold, ColdCheck::NotApplicable);
    assert_eq!(d.outcome, picket_rules::matcher::Outcome::Block);
    // A cold part that isn't loaded (no SSD): every query reaching the cold stage is unchecked.
    let b = l.bundle.with_cold(Cold::NotLoaded);
    assert!(b.cold_not_loaded());
    let d = bundle_decision(&b, &l.pages, &q);
    assert_eq!(d.cold, ColdCheck::Unchecked { refetch: vec![] });
    let nl = load_bundle(&l.built.head_blob.bytes, &l.built.blobs, None, DEFAULT_BUDGET).unwrap();
    assert!(nl.cold_not_loaded());
}

/// Review round 1, B7 (c): a run of a shard's chain applies with one overlay rebuild, giving what
/// applying each delta in turn gives, and a bad delta in the middle still means "need base".
#[test]
fn a_chain_applies_at_once() {
    let l = compile_and_load(
        BundleAction::Block,
        &rules(&["||a.example^", "||b.example^"]),
        0,
        Tiering::AllHot,
    );
    let shard = &l.bundle.hot_shards()[0];
    let (h, r) = (shard.head.clone(), shard.rich_arc().clone());
    let s = &l.built.head.shards[0];
    let mut cs = s.checksum;
    let mut chain = Vec::new();
    let steps: [(&[u8], Option<Value>, Option<Value>); 3] = [
        (b"example.c", None, Some(Value(3))),
        (b"example.a", Some(Value(3)), None),
        (b"example.c", Some(Value(3)), Some(Value(1))),
    ];
    for (i, (k, old, new)) in steps.iter().enumerate() {
        let d = key_delta(
            &DeltaTarget {
                bundle: "test-bundle",
                base: &s.base,
                seq: i as u64 + 1,
                prev: cs,
                created_at: "t",
            },
            PartKind::Hot,
            s.shard,
            &[KeyChange {
                key: k.to_vec(),
                old: *old,
                new: *new,
            }],
        );
        cs = d.header.new_checksum;
        chain.push(d.blob.bytes);
    }
    let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    let at_once = shard.apply_deltas(&refs, h.clone(), r.clone()).unwrap();
    let mut one_by_one = (**shard).clone();
    for d in &refs {
        one_by_one = one_by_one.apply_delta(d, h.clone(), r.clone()).unwrap();
    }
    assert_eq!(at_once.checksum(), cs);
    assert_eq!(at_once.checksum(), one_by_one.checksum());
    assert_eq!(at_once.seq(), 3);
    for k in [&b"example.a"[..], b"example.b", b"example.c"] {
        let h = picket_bundle::hash::KeyHash::of(l.built.head.hash_seed, k);
        assert_eq!(
            at_once.get(k, h),
            one_by_one.get(k, h),
            "{}",
            String::from_utf8_lossy(k)
        );
    }
    // The middle delta out of place (applied twice): the chain is refused.
    let broken: Vec<&[u8]> = vec![refs[0], refs[1], refs[1], refs[2]];
    assert!(matches!(
        shard.apply_deltas(&broken, h.clone(), r.clone()),
        Err(LoadError::NeedBase(_))
    ));
}

/// Review round 1, B11: a corrupt cold page hit while applying a cold delta keeps its meaning (a
/// page error the edge answers by deleting and refetching the page file, bundles.md §4 "Reading"),
/// rather than becoming a generic mismatch.
#[test]
fn corrupted_page_while_applying_a_cold_delta_is_a_refetch() {
    let l = compile_and_load(
        BundleAction::Block,
        &rules(&["||cold.example^", "||other.example^"]),
        0,
        Tiering::AllCold,
    );
    let Cold::Loaded(part) = l.bundle.cold() else {
        panic!("cold part")
    };
    let shard = &part.shards()[0];
    let cref = &l.built.head.cold_shards[0];
    let d = key_delta(
        &DeltaTarget {
            bundle: &l.built.head.bundle,
            base: &cref.base,
            seq: 1,
            prev: cref.checksum,
            created_at: CREATED,
        },
        PartKind::Cold,
        cref.shard,
        &[
            // An upsert of a key the base holds reads its page (for the checksum) ...
            KeyChange {
                key: b"example.cold".to_vec(),
                old: Some(Value::flags_only(
                    picket_rules::Flags::B_EXACT | picket_rules::Flags::B_SUBS,
                )),
                new: Some(Value::flags_only(picket_rules::Flags::B_EXACT)),
            },
            // ... and so does a delete.
            KeyChange {
                key: b"example.other".to_vec(),
                old: Some(Value::flags_only(
                    picket_rules::Flags::B_EXACT | picket_rules::Flags::B_SUBS,
                )),
                new: None,
            },
        ],
    );
    let mut bad = MemPages::default();
    for (id, bytes) in &l.pages.files {
        let mut b = bytes.clone();
        for p in (PAGE_SIZE..b.len()).step_by(PAGE_SIZE) {
            b[p + 3] ^= 0x40;
        }
        bad.files.insert(id.clone(), b);
    }
    for r in [
        shard.apply_upserts(&d.blob.bytes, "h2".into(), &bad).map(|_| ()),
        shard.apply_delta(&d.blob.bytes, &bad).map(|_| ()),
    ] {
        match r {
            Err(LoadError::Page(e)) => assert!(e.needs_refetch(), "{e:?}"),
            other => panic!("expected a page error to refetch: {other:?}"),
        }
    }
    // A read error (the file is gone) is a page error that doesn't ask for a refetch.
    match shard.apply_delta(&d.blob.bytes, &MemPages::default()) {
        Err(LoadError::Page(e)) => assert!(!e.needs_refetch(), "{e:?}"),
        other => panic!("expected a read error: {other:?}"),
    }
    // With the good page file the delta applies.
    let done = shard.apply_delta(&d.blob.bytes, &l.pages).unwrap();
    assert_eq!(done.checksum(), d.header.new_checksum);
}

#[test]
fn corrupted_blobs_are_refused() {
    let l = compile_and_load(
        BundleAction::Block,
        &rules(&[
            "||a.example^",
            "||ads*.example^",
            "||1.2.3.4^",
            "||b.example^$dnstype=A",
        ]),
        0,
        Tiering::AllHot,
    );
    let head = &l.built.head;
    let corrupt = |id: &str| {
        let mut store = l.built.blobs.clone();
        let b = store.get_mut(id).unwrap();
        let n = b.len();
        b[n / 2] ^= 0x01;
        load_bundle(&l.built.head_blob.bytes, &store, None, DEFAULT_BUDGET).map(|_| ())
    };
    let m = Manifest::from_bytes(&l.built.blobs[&head.shards[0].base]).unwrap();
    for id in [
        head.shards[0].base.clone(),
        m.file("domains.fst").unwrap().blake3.clone(),
        m.file("domains.bf8").unwrap().blake3.clone(),
        head.ip_shards[0].base.clone(),
        head.segment("patterns.bin").unwrap().to_string(),
        head.segment("rich.json").unwrap().to_string(),
    ] {
        assert!(corrupt(&id).is_err(), "{id}");
    }
    // A head whose checksum disagrees with its chain is refused (need base).
    let mut h: Head = head.clone();
    h.shards[0].checksum = SetChecksum(1);
    let r = load_bundle(&h.to_bytes(), &l.built.blobs, None, DEFAULT_BUDGET);
    assert!(matches!(r, Err(LoadError::NeedBase(_))));
    let _ = Arc::new(());
}

#[test]
fn verdict_set_page_failing_its_checks_is_a_refetch() {
    use picket_bundle::hash::verdict_hash_seed;
    use picket_bundle::verdict::{
        VerdictHead, VerdictKind, VerdictRecord, load_verdict_set, name_hash, write_base,
    };
    let seed = verdict_hash_seed("p", "0123456789abcdef");
    let rec = VerdictRecord {
        verdict: VerdictKind::Block,
        obtained_at: picket_api::time::Timestamp::from_second(1_763_686_921).unwrap(),
        score: None,
        reason: Some("x".into()),
    };
    let base = write_base("p", "0123456789abcdef", &[(name_hash(seed, "a.example"), rec)]).unwrap();
    let head = VerdictHead {
        provider: "p".into(),
        format: picket_bundle::FORMAT,
        generation: "0123456789abcdef".into(),
        hash_seed: seed,
        base: base.blob.id.clone(),
        deltas: vec![],
        seq: 0,
        checksum: base.checksum,
        issued_at: String::new(),
    };
    let mut bytes = base.blob.bytes.clone();
    let pages = MemPages {
        files: [(base.blob.id.clone(), bytes.clone())].into_iter().collect(),
    };
    let set = load_verdict_set(&head.to_blob().bytes, &|_| None, &pages).unwrap();
    assert!(set.lookup("a.example", &pages).unwrap().is_some());
    bytes[PAGE_SIZE + 20] ^= 1;
    let bad = MemPages {
        files: [(base.blob.id.clone(), bytes)].into_iter().collect(),
    };
    let e = set.lookup("a.example", &bad).unwrap_err();
    assert!(e.needs_refetch(), "{e}");
}
