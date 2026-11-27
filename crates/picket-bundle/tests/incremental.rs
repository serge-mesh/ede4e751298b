//! Incremental builds (build-and-test.md §5 "Bundles", "Hot and cold parts"; bundles.md §2, §5,
//! §6): a head built as base + deltas (hot, cold and IP shards) gives the same lookups as a build
//! from scratch over the same rules, including tier moves and pruned parent/child pairs; a move
//! never leaves a key in neither part, even interrupted after the cold upserts.
//!
//! The incremental head is built the way core's incremental build does it, with the writer API:
//! diff each key's (part, value) per shard into deltas, diff IP runs per IP shard, keep `rich.json`
//! indices stable ([`RichBuilder::from_previous`]) and write new segments.

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
use picket_bundle::compile::{BuildOptions, BuiltBundle, CompileOptions, Compiled, build, compile_rules};
use picket_bundle::head::RICH;
use picket_bundle::ips::IpShardId;
use picket_bundle::matcher::{Bundle, Cold, ColdPart};
use picket_bundle::page::MemPages;
use picket_bundle::rich::RichBuilder;
use picket_bundle::runs::{IpRuleInput, fold_runs};
use picket_bundle::writer::Blob;
use picket_rules::Flags;
use picket_rules::compile::Part;
use picket_rules::matcher::BundleAction;

fn compiled(rules: &[&str]) -> Compiled {
    let rules: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
    compile_rules(
        &parse_rules(&rules),
        &CompileOptions::new(BundleAction::Block, Some(psl())),
    )
}

fn full(c: &Compiled, part_of: Option<PartOf<'_>>, cap: u64) -> BuiltBundle {
    let mut o = BuildOptions::new("inc", BundleAction::Block);
    o.part_of = part_of;
    o.max_shard_keys = cap;
    build(c, &o).unwrap()
}

fn probe_queries() -> Vec<Query> {
    let mut qs = Vec::new();
    for n in [
        "d.example",
        "sub.d.example",
        "a.sub.d.example",
        "other.example",
        "ads.example",
        "x.ads.example",
        "keep.example",
        "gone.example",
        "moved.example",
        "cold.example",
        "x.cold.example",
        "rw.example",
        "ip.example",
        "1.2.3.4",
        "tracker.example",
        "a.tracker.example",
        "new.example",
        "back.example",
    ] {
        let mut q = Query::name(n);
        qs.push(q.clone());
        q.qtype = 28;
        qs.push(q);
    }
    for ip in [
        "1.2.3.4",
        "1.2.3.5",
        "10.0.0.1",
        "10.1.0.1",
        "10.2.0.9",
        "45.12.3.4",
        "2001:db8::1",
        "2001:db8::5",
    ] {
        qs.push(Query::ip(ip.parse().unwrap()));
    }
    qs
}

fn decide(b: &Bundle, pages: &MemPages, q: &Query) -> String {
    decision(&bundle_decision(b, pages, q).outcome)
}

fn cold_if(names: &'static [&'static str]) -> impl Fn(&str, Flags) -> Part {
    move |k: &str, _f| {
        if names.iter().any(|n| picket_rules::name::reverse_dotted(n) == k) {
            Part::Cold
        } else {
            Part::Hot
        }
    }
}

#[test]
fn incremental_equals_full() {
    let v1 = compiled(&[
        "||d.example^",
        "||sub.d.example^",
        "||keep.example^",
        "||gone.example^",
        "||moved.example^",
        "||back.example^",
        "||cold.example^",
        "||rw.example^$dnsrewrite=1.2.3.4",
        "||tracker.example^$dnstype=AAAA",
        "||1.2.3.4^",
        "||10.0.0.0^",
        "@@||10.0.0.1^",
        "||ads*.example^",
    ]);
    // v2: removes ||d^ (sub.d still blocks: its pruned key comes back), drops gone, moves
    // `moved` to cold and `back` to hot, changes a rewrite and the IP rules, adds a pattern and
    // a new IP shard.
    let v2 = compiled(&[
        "||sub.d.example^",
        "||keep.example^",
        "||moved.example^",
        "||back.example^",
        "||cold.example^",
        "||new.example^",
        "||rw.example^$dnsrewrite=1.2.3.5",
        "||tracker.example^$dnstype=AAAA",
        "@@||1.2.3.4^",
        "||10.0.0.0^",
        "||45.12.3.4^",
        "||2001:db8::1^",
        "||ads*.example^",
        "/^x\\./",
    ]);
    let p1 = cold_if(&["cold.example", "back.example", "gone.example"]);
    let p2 = cold_if(&["cold.example", "moved.example"]);
    for cap in [0u64, 2] {
        let b1 = full(&v1, Some(&p1), cap);
        assert!(b1.pruned >= 1, "sub.d.example is pruned under d.example");
        let (h2, store2, hot2, cold2) = incremental(&b1, &v2, Some(&p2), 1);
        let fresh = full(&v2, Some(&p2), cap);
        assert_eq!(
            hot2.keys().collect::<Vec<_>>(),
            fresh.hot_keys.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            cold2.keys().collect::<Vec<_>>(),
            fresh.cold_keys.keys().collect::<Vec<_>>()
        );
        let (inc, inc_pages) = load(&h2, &store2);
        let (fr, fr_pages) = load(&fresh.head, &fresh.blobs);
        let mut checked = 0;
        for q in probe_queries() {
            let a = decide(&inc, &inc_pages, &q);
            let b = decide(&fr, &fr_pages, &q);
            assert_eq!(a, b, "cap {cap}: {q:?}");
            checked += usize::from(a != "none");
        }
        assert!(checked > 10);
        // The bundles.md row: after ||d^ and ||sub.d^, a run removing ||d^ still blocks sub.d.
        assert_eq!(decide(&inc, &inc_pages, &Query::name("sub.d.example")), "block");
        assert_eq!(decide(&inc, &inc_pages, &Query::name("d.example")), "none");
        // A chain of two: v2 → v3 on top of the incremental head.
        let v3 = compiled(&["||keep.example^", "||cold.example^", "||1.2.3.5^"]);
        let built2 = BuiltBundle {
            head: h2.clone(),
            head_blob: Blob::new(h2.to_bytes()),
            blobs: store2.clone(),
            hot_keys: hot2.clone(),
            cold_keys: cold2.clone(),
            runs: {
                let mut rich = RichBuilder::from_previous(&b1.blobs[b1.head.segment(RICH).unwrap()]).unwrap();
                let ip: Vec<IpRuleInput> = v2.ip_rules.iter().map(|(_, r)| r.clone()).collect();
                fold_runs(&ip, &mut rich)
            },
            pattern_fates: vec![],
            pruned: 0,
        };
        let (h3, store3, _, _) = incremental(&built2, &v3, Some(&p2), 2);
        assert!(
            h3.shards.iter().any(|s| s.deltas.len() == 2)
                || h3.cold_shards.iter().any(|s| s.deltas.len() == 2)
        );
        let fresh3 = full(&v3, Some(&p2), cap);
        let (inc3, p3) = load(&h3, &store3);
        let (fr3, pf3) = load(&fresh3.head, &fresh3.blobs);
        for q in probe_queries() {
            assert_eq!(
                decide(&inc3, &p3, &q),
                decide(&fr3, &pf3, &q),
                "v3 cap {cap}: {q:?}"
            );
        }
    }
}

#[test]
fn moves_never_leave_a_key_in_neither_part() {
    // `moved` goes hot → cold and `back` cold → hot, in one cold shard (cap 0: one shard).
    let v1 = compiled(&["||moved.example^", "||back.example^", "||stay.example^"]);
    let p1 = cold_if(&["back.example", "stay.example"]);
    let p2 = cold_if(&["moved.example", "stay.example"]);
    let b1 = full(&v1, Some(&p1), 0);
    let (h2, store2, _, _) = incremental(&b1, &v1, Some(&p2), 1);
    let h1_id: Arc<str> = b1.head_blob.id.as_str().into();
    let h2_id: Arc<str> = Blob::new(h2.to_bytes()).id.as_str().into();
    let pages = pages_for(&h2, &store2);
    let (start, _) = load(&b1.head, &b1.blobs);
    let names = ["moved.example", "back.example", "stay.example", "x.moved.example"];
    let all_block = |b: &Bundle, step: &str| {
        for n in names {
            assert_eq!(decide(b, &pages, &Query::name(n)), "block", "{step}: {n}");
        }
    };
    all_block(&start, "start");
    // Step 0: the new head's first step moves unchanged parts (none here).
    let b = start.with_head(&h2, h2_id.clone()).unwrap();
    // Step 1: cold upserts.
    let Cold::Loaded(cp) = b.cold() else {
        panic!("cold part")
    };
    let cs = &cp.shards()[0];
    let cref = &h2.cold_shards[0];
    let cdelta = &store2[&cref.deltas[0].blake3];
    let (mid, pending) = cs.apply_upserts(cdelta, h2_id.clone(), &pages).unwrap();
    let b = b.with_cold(Cold::Loaded(Arc::new(
        ColdPart::new(&h2.cold_shard_dir, vec![Arc::new(mid.clone())], None).unwrap(),
    )));
    all_block(&b, "after cold upserts");
    // Interrupted here: `versions` logs the cold shard as [previous, new].
    match b.versions() {
        picket_api::logs::BundleVersion::Parts(p) => {
            let v = &p.cold_shards[&cref.shard.to_string()];
            assert_eq!(
                v,
                &picket_api::logs::ColdShardVersion::Moving([
                    picket_api::ids::short_id(&h1_id).to_string(),
                    picket_api::ids::short_id(&h2_id).to_string()
                ])
            );
        }
        other => panic!("mid-move versions must list parts: {other:?}"),
    }
    // Step 2: the hot swap.
    let hs = &b.hot_shards()[0];
    let href = &h2.shards[0];
    let hot2 = hs
        .apply_delta(
            &store2[&href.deltas[0].blake3],
            h2_id.clone(),
            b.patterns().rich.clone(),
        )
        .unwrap();
    let b = b.with_hot(&h2.shard_dir, vec![Arc::new(hot2)]).unwrap();
    all_block(&b, "after hot swap");
    // Step 3: cold deletes.
    let done = mid.apply_deletes(pending, &pages).unwrap();
    assert_eq!(done.checksum(), cref.checksum);
    let b = b.with_cold(Cold::Loaded(Arc::new(
        ColdPart::new(&h2.cold_shard_dir, vec![Arc::new(done)], None).unwrap(),
    )));
    all_block(&b, "after cold deletes");
    // `back` is now hot only, `moved` cold only.
    let back = decide_detail(&b, &pages, "back.example");
    assert!(!back.reason.unwrap().cold);
    let moved = decide_detail(&b, &pages, "moved.example");
    assert!(moved.reason.unwrap().cold);
}

fn decide_detail(b: &Bundle, pages: &MemPages, n: &str) -> picket_bundle::Decision {
    let labels: Vec<&[u8]> = n.split('.').map(str::as_bytes).collect();
    b.lookup_labels_full(
        &labels,
        &picket_rules::QueryCtx {
            qtype: 1,
            ..Default::default()
        },
        pages,
    )
}

#[test]
fn moving_union_with_a_new_cold_base() {
    // A cold shard whose new head has a new base (a rebuilt or split shard): until the hot swap,
    // the previous part stays and a lookup checks both, the new value winning.
    let v1 = compiled(&["||a.example^", "||b.example^"]);
    let p1 = cold_if(&["a.example"]);
    let p2 = cold_if(&["b.example"]);
    let b1 = full(&v1, Some(&p1), 0);
    let b2 = full(&v1, Some(&p2), 0);
    let (start, pages1) = load(&b1.head, &b1.blobs);
    let (next, pages2) = load(&b2.head, &b2.blobs);
    let mut pages = pages1.clone();
    pages.files.extend(pages2.files.clone());
    let Cold::Loaded(prev) = start.cold() else {
        panic!()
    };
    let Cold::Loaded(new) = next.cold() else { panic!() };
    let union = ColdPart::new(new.dir().entries(), new.shards().to_vec(), Some(prev.clone())).unwrap();
    // Before the hot swap: old hot part (b), union cold (a from previous, b from new).
    let b = start.with_cold(Cold::Loaded(Arc::new(union)));
    for n in ["a.example", "b.example"] {
        assert_eq!(decide(&b, &pages, &Query::name(n)), "block", "{n}");
    }
    assert!(matches!(b.versions(), picket_api::logs::BundleVersion::Parts(_)));
}

#[test]
fn ip_runs_split_merge_and_deltas() {
    // A rule inside a run splits it; removing it merges the run back (maximal runs); deltas
    // delete the old runs and upsert the new ones, and lookups follow.
    let c1 = compiled(&["||10.0.0.0^"]);
    let mut c1b = c1.clone();
    c1b.ip_rules.push((
        99,
        IpRuleInput {
            range: picket_rules::ip::IpRange::parse("10.0.0.0/8").unwrap(),
            flags: Flags::B_EXACT,
            rich: None,
        },
    ));
    let mut c2 = c1b.clone();
    c2.ip_rules.push((
        100,
        IpRuleInput {
            range: picket_rules::ip::IpRange::parse("10.1.0.0/16").unwrap(),
            flags: Flags::A_EXACT,
            rich: None,
        },
    ));
    let b1 = full(&c1b, None, 0);
    assert_eq!(b1.runs[&IpShardId::V4(10)].len(), 1);
    let (h2, s2, _, _) = incremental(&b1, &c2, None, 1);
    let fresh = full(&c2, None, 0);
    assert_eq!(fresh.runs[&IpShardId::V4(10)].len(), 3);
    let (inc, pi) = load(&h2, &s2);
    let (fr, pf) = load(&fresh.head, &fresh.blobs);
    for ip in ["10.0.0.1", "10.1.0.1", "10.2.0.9", "10.255.255.255", "11.0.0.0"] {
        let q = Query::ip(ip.parse().unwrap());
        assert_eq!(decide(&inc, &pi, &q), decide(&fr, &pf, &q), "{ip}");
    }
    assert_eq!(
        decide(&inc, &pi, &Query::ip("10.1.0.1".parse().unwrap())),
        "allow"
    );
}

/// Review round 1, B5: `$denyallow` entity churn. Eight distinct entities fill the cap; replacing
/// one entity's rule with a ninth entity's must build incrementally (the removed entity isn't
/// carried), as a fresh build does, with the same lookups.
#[test]
fn entity_churn_builds_incrementally() {
    let lines = |ents: &[usize]| -> Vec<String> {
        ents.iter()
            .map(|i| format!("||site{i}.example^$denyallow=ent{i}.*"))
            .chain(["||plain.example^".to_string()])
            .collect()
    };
    let v1: Vec<String> = lines(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let v2: Vec<String> = lines(&[0, 1, 2, 3, 4, 5, 6, 8]);
    fn refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }
    let c1 = compiled(&refs(&v1));
    let c2 = compiled(&refs(&v2));
    assert!(
        c1.refused.is_empty() && c2.refused.is_empty(),
        "each version fits the cap"
    );
    let n_entities = |c: &Compiled| {
        serde_json::to_value(&c.entities)
            .unwrap()
            .as_array()
            .unwrap()
            .len()
    };
    assert_eq!(
        (n_entities(&c1), n_entities(&c2)),
        (8, 8),
        "eight entities each: the cap"
    );
    let b1 = full(&c1, None, 0);
    let fresh = full(&c2, None, 0);
    let (h2, s2, _, _) = incremental(&b1, &c2, None, 1);
    let (inc, pi) = load(&h2, &s2);
    let (fr, pf) = load(&fresh.head, &fresh.blobs);
    for n in [
        "site7.example",
        "site8.example",
        "x.site0.example",
        "plain.example",
        "ent8.co.uk",
    ] {
        let q = Query::name(n);
        assert_eq!(decide(&inc, &pi, &q), decide(&fr, &pf, &q), "{n}");
    }
    assert_eq!(decide(&inc, &pi, &Query::name("site8.example")), "block");
    assert_eq!(
        inc.patterns().rich.unlinked(),
        0,
        "no rule names a missing entity"
    );
}

/// Review round 1, B6: rich indices stay valid across heads, dead rules and sets are reclaimed
/// (the segment doesn't grow over a long run of incremental builds), and a part never reads an
/// index its `rich.json` lacks.
#[test]
fn rich_indices_stable_and_reclaimed_across_builds() {
    let mut prev = full(
        &compiled(&["||keep.example^$dnstype=AAAA", "||rw.example^$dnsrewrite=1.2.3.0"]),
        None,
        0,
    );
    let mut slots = Vec::new();
    for i in 1..=12u64 {
        let rw = format!("||rw.example^$dnsrewrite=1.2.3.{i}");
        let c = compiled(&["||keep.example^$dnstype=AAAA", &rw]);
        let (h, store, hot, cold) = incremental(&prev, &c, None, i);
        let (b, pages) = load(&h, &store);
        let fresh = full(&c, None, 0);
        let (fb, fp) = load(&fresh.head, &fresh.blobs);
        for n in ["keep.example", "rw.example", "x.rw.example"] {
            for qt in [1u16, 28] {
                let mut q = Query::name(n);
                q.qtype = qt;
                assert_eq!(
                    decide(&b, &pages, &q),
                    decide(&fb, &fp, &q),
                    "build {i}: {n}/{qt}"
                );
            }
        }
        let rich = picket_bundle::rich::RichBuilder::from_previous(&store[h.segment(RICH).unwrap()]).unwrap();
        slots.push(rich.slots());
        let runs = {
            let mut r =
                picket_bundle::rich::RichBuilder::from_previous(&store[h.segment(RICH).unwrap()]).unwrap();
            let ip: Vec<IpRuleInput> = c.ip_rules.iter().map(|(_, r)| r.clone()).collect();
            fold_runs(&ip, &mut r)
        };
        prev = BuiltBundle {
            head: h.clone(),
            head_blob: Blob::new(h.to_bytes()),
            blobs: store,
            hot_keys: hot,
            cold_keys: cold,
            runs,
            pattern_fates: vec![],
            pruned: 0,
        };
    }
    // Two live rules and sets; each build frees the previous rewrite and reuses its slot a build
    // later, so the arrays stay small.
    let (rules, sets) = *slots.last().unwrap();
    assert!(rules <= 4 && sets <= 4, "{slots:?}");
}

/// Review round 1, B6: an index past the end of the part's `rich.json` is an error when the part
/// loads, takes a delta or moves to a head, never a silent "no rules".
#[test]
fn rich_index_out_of_range_is_an_error() {
    use picket_bundle::head::{DOMAINS_BF8, DOMAINS_FST, Manifest, PartKind};
    use picket_bundle::reader::{HotBaseBlobs, HotShard, IpShard, LoadError};
    use picket_bundle::rich::RichSegment;
    use picket_bundle::value::Value;
    use picket_bundle::writer::{DeltaTarget, HotBaseWriter, KeyChange, ip_base, key_delta};
    let rich3 = Arc::new(
        RichSegment::from_bytes(br#"{"format":1,"rules":[{"flags":1}],"sets":[[0],[0],[0]]}"#).unwrap(),
    );
    let rich1 =
        Arc::new(RichSegment::from_bytes(br#"{"format":1,"rules":[{"flags":1}],"sets":[[0]]}"#).unwrap());
    let mut w = HotBaseWriter::new("b", 0, 7);
    w.insert(b"com.a", Value::new(Flags::B_EXACT | Flags::HAS_RICH, 2))
        .unwrap();
    let base = w.finish().unwrap();
    let m = Manifest::from_bytes(&base.manifest.bytes).unwrap();
    let blobs = || HotBaseBlobs {
        base_id: base.id(),
        manifest: &base.manifest.bytes,
        fst: base.file(DOMAINS_FST).unwrap().bytes.clone(),
        bf8: &base.file(DOMAINS_BF8).unwrap().bytes,
    };
    assert_eq!(m.keys, 1);
    assert!(matches!(
        HotShard::load("b", "h".into(), 7, 0, blobs(), rich1.clone()),
        Err(LoadError::Mismatch(_))
    ));
    let s = HotShard::load("b", "h".into(), 7, 0, blobs(), rich3.clone()).unwrap();
    assert!(matches!(
        s.in_head("h2".into(), rich1.clone()),
        Err(LoadError::Mismatch(_))
    ));
    assert!(s.in_head("h2".into(), rich3.clone()).is_ok());
    // A delta upserting an index the shard's segment lacks.
    let d = key_delta(
        &DeltaTarget {
            bundle: "b",
            base: base.id(),
            seq: 1,
            prev: base.checksum,
            created_at: CREATED,
        },
        PartKind::Hot,
        0,
        &[KeyChange {
            key: b"com.b".to_vec(),
            old: None,
            new: Some(Value::new(Flags::B_EXACT | Flags::HAS_RICH, 9)),
        }],
    );
    // Applying it with a head whose segment lacks the set is refused.
    assert!(matches!(
        s.apply_delta(&d.blob.bytes, "h2".into(), rich3.clone()),
        Err(LoadError::Mismatch(_))
    ));
    // IP shards too.
    let run = picket_bundle::ips::Run {
        first: u128::from(u32::from_be_bytes([10, 0, 0, 1])),
        last: u128::from(u32::from_be_bytes([10, 0, 0, 1])),
        value: Value::new(Flags::B_EXACT | Flags::HAS_RICH, 2),
    };
    let ib = ip_base(IpShardId::V4(10), &[run]).unwrap();
    assert!(IpShard::load("b", "h".into(), &ib.blob.id, 0, &ib.blob.bytes, rich1.clone()).is_err());
    let ips = IpShard::load("b", "h".into(), &ib.blob.id, 0, &ib.blob.bytes, rich3.clone()).unwrap();
    assert!(ips.in_head("h2".into(), rich1).is_err());
}

/// A head's deltas reference that head's `rich.json` (which may append sets, or reuse a
/// reclaimed slot for another rule): applying them takes that head and its segment, and the shard
/// comes back already part of it, checked against it (review round 2, CR4). A shard holding the
/// new indices never reads the previous segment, so none can be swapped in that way.
#[test]
fn deltas_adding_rich_sets_activate() {
    let v1 = compiled(&["||a.example^$dnstype=AAAA", "||p.example^"]);
    let v2 = compiled(&[
        "||a.example^$dnstype=AAAA",
        "||b.example^$dnstype=MX",
        "||p.example^",
    ]);
    let b1 = full(&v1, None, 0);
    let (h2, s2, _, _) = incremental(&b1, &v2, None, 1);
    let (start, pages) = load(&b1.head, &b1.blobs);
    let h2_id: Arc<str> = Blob::new(h2.to_bytes()).id.as_str().into();
    let rich2 =
        picket_bundle::reader::load_rich(h2.segment(RICH).unwrap(), &s2[h2.segment(RICH).unwrap()]).unwrap();
    let b = start.with_head(&h2, h2_id.clone()).unwrap();
    let href = &h2.shards[0];
    let delta = &s2[&href.deltas[0].blake3];
    // Given v1's segment, which lacks the new set: refused.
    assert!(
        b.hot_shards()[0]
            .apply_delta(delta, h2_id.clone(), start.patterns().rich.clone())
            .is_err()
    );
    let moved = b.hot_shards()[0]
        .apply_delta(delta, h2_id.clone(), rich2.clone())
        .unwrap();
    assert_eq!(moved.head, h2_id);
    assert!(
        Arc::ptr_eq(moved.rich_arc(), &rich2),
        "reads the deltas' head's segment"
    );
    let b = b.with_hot(&h2.shard_dir, vec![Arc::new(moved)]).unwrap();
    let mut q = Query::name("b.example");
    q.qtype = 15;
    assert_eq!(decide(&b, &pages, &q), "block");
}
