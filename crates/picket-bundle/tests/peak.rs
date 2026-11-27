//! Peak memory while loading untrusted input (README §2 "Bounded", "Untrusted input"; edge.md
//! §17): live heap bytes are counted by a global allocator and sampled by a second thread while
//! the work runs. One test in this binary, so no other test allocates meanwhile.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

use std::alloc::System;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use picket_bundle::delta::{DeltaHeader, RangeOp, write_range_delta};
use picket_bundle::ips::{IpShardId, Run};
use picket_bundle::reader::{IpShard, LoadError};
use picket_bundle::rich::RichSegment;
use picket_bundle::value::Value;
use picket_bundle::writer::{DeltaTarget, ip_base, ip_delta};
use picket_rules::Flags;
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const MIB: isize = 1024 * 1024;

/// Live heap bytes (`stats_alloc` counts a realloc's growth or shrink in these two already).
fn live() -> isize {
    let s = GLOBAL.stats();
    (s.bytes_allocated as isize).wrapping_sub(s.bytes_deallocated as isize)
}

/// Runs `f` and returns its result and the most live heap it added at any point (sampled).
fn peak<T>(f: impl FnOnce() -> T) -> (T, isize) {
    let start = live();
    let done = Arc::new(AtomicBool::new(false));
    let top = Arc::new(AtomicIsize::new(start));
    let sampler = {
        let (done, top) = (done.clone(), top.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                top.fetch_max(live(), Ordering::Relaxed);
                std::hint::spin_loop();
            }
        })
    };
    let out = f();
    top.fetch_max(live(), Ordering::Relaxed);
    done.store(true, Ordering::Relaxed);
    sampler.join().unwrap();
    (out, top.load(Ordering::Relaxed) - start)
}

/// Runs `f` and returns its result with the heap it still holds afterwards, as a range: glibc's
/// malloc adds 8 to 31 bytes to each allocation (header and rounding; `stats_alloc` counts only
/// the bytes requested).
fn held<T>(f: impl FnOnce() -> T) -> (T, std::ops::RangeInclusive<isize>) {
    let s0 = GLOBAL.stats();
    let out = f();
    let s1 = GLOBAL.stats();
    let bytes = (s1.bytes_allocated as isize - s1.bytes_deallocated as isize)
        - (s0.bytes_allocated as isize - s0.bytes_deallocated as isize);
    let allocs = (s1.allocations as isize - s1.deallocations as isize)
        - (s0.allocations as isize - s0.deallocations as isize);
    (out, bytes + 8 * allocs..=bytes + 31 * allocs)
}

/// True when `reported` is within 10 % of the range.
fn close(reported: usize, r: &std::ops::RangeInclusive<isize>) -> bool {
    let x = reported as isize;
    x >= r.start() - r.start() / 10 && x <= r.end() + r.end() / 10
}

fn addr(i: u32) -> u128 {
    u128::from(u32::from_be_bytes([10, 1, 0, 0]) + i)
}

/// Review round 2, CR2: an IP shard's chain is parsed and staged one delta at a time, so a run of
/// deltas costs one delta plus the staged changes, not every delta parsed at once.
fn ip_chain_is_staged_one_delta_at_a_time() {
    let shard = IpShardId::V4(10);
    let v = |k: u64| {
        Value::flags_only(if k.is_multiple_of(2) {
            Flags::B_EXACT
        } else {
            Flags::B_SUBS
        })
    };
    let base_run = Run {
        first: addr(0),
        last: addr(0),
        value: v(0),
    };
    let base = ip_base(shard, &[base_run]).unwrap();
    let rich = Arc::new(RichSegment::empty());
    let s = IpShard::load("b", "h".into(), &base.blob.id, 0, &base.blob.bytes, rich.clone()).unwrap();

    // (a) Deltas that continue the chain by their headers but whose checksums are wrong: the first
    // one's mismatch is found before the rest are parsed.
    const OPS: u32 = 100_000;
    let ops: Vec<RangeOp> = (1..=OPS)
        .map(|i| RangeOp::Upsert {
            first: addr(i),
            last: addr(i),
            value: v(1),
        })
        .collect();
    let bad: Vec<Vec<u8>> = (1..=8u64)
        .map(|seq| {
            let h = DeltaHeader {
                bundle: "b".into(),
                shard: None,
                cold_shard: None,
                ip_shard: Some(shard),
                base: base.blob.id.clone(),
                seq,
                prev_checksum: s.checksum(),
                mid_checksum: None,
                new_checksum: s.checksum(),
                created_at: "2026-11-21T00:00:00Z".into(),
            };
            write_range_delta(&h, &ops)
        })
        .collect();
    drop(ops);
    let refs: Vec<&[u8]> = bad.iter().map(Vec::as_slice).collect();
    let (r, used) = peak(|| s.apply_deltas(&refs, "h".into(), rich.clone()));
    assert!(matches!(r, Err(LoadError::NeedBase(_))), "{r:?}");
    // One parsed delta is ~6 MiB (48-byte ops), its staged changes a few more; all eight parsed
    // at once were ~50 MiB (review round 2: the old code peaked there).
    assert!(used < 24 * MIB, "a bad chain peaked at {} MiB", used / MIB);

    // (b) A valid chain rewriting the same runs again and again: the staged changes stay at one
    // delta's worth, whatever the chain's length.
    const RUNS: u32 = 20_000;
    let runs = |k: u64| -> Vec<Run> {
        (1..=RUNS)
            .map(|i| Run {
                first: addr(i),
                last: addr(i),
                value: v(k),
            })
            .collect()
    };
    let mut prev = s.checksum();
    let mut chain = Vec::new();
    for seq in 1..=24u64 {
        let deletes = if seq == 1 { Vec::new() } else { runs(seq - 1) };
        let d = ip_delta(
            &DeltaTarget {
                bundle: "b",
                base: &base.blob.id,
                seq,
                prev,
                created_at: "2026-11-21T00:00:00Z",
            },
            shard,
            &deletes,
            &runs(seq),
        );
        prev = d.header.new_checksum;
        chain.push(d.blob.bytes);
    }
    let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    let (r, used) = peak(|| s.apply_deltas(&refs, "h".into(), rich.clone()));
    let applied = r.unwrap();
    assert_eq!(applied.checksum(), prev);
    assert_eq!(applied.seq(), 24);
    assert_eq!(applied.get(addr(7)), Some((v(24), false)));
    // 24 deltas of 40k ops parsed at once were ~72 MiB (each ~3 MiB); staged one at a time,
    // ~4 MiB.
    assert!(used < 16 * MIB, "a valid chain peaked at {} MiB", used / MIB);
}

/// A `rich.json` with one rule holding `inner` (its JSON fields).
fn one_rule(inner: &str) -> Vec<u8> {
    format!("{{\"format\":1,\"rules\":[{{\"flags\":1,{inner}}}],\"sets\":[[0]]}}").into_bytes()
}

fn list(item: &str, n: usize) -> String {
    let mut s = String::with_capacity(n * (item.len() + 1) + 2);
    s.push('[');
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        s.push_str(item);
    }
    s.push(']');
    s
}

/// Review round 2, CR1: every nested list of a rich rule is bounded while it is parsed, and the
/// segment reports what it really holds.
fn rich_nested_lists_are_bounded_and_counted() {
    use picket_bundle::rich::{MAX_RICH_MEMORY, RichError};
    // (a) 50,000 empty `unless` entries: 150 KB of JSON, megabytes parsed. The reported memory is
    // within a quarter of the heap the segment holds.
    let doc = one_rule(&format!("\"unless\":{}", list("{}", 50_000)));
    let (seg, h) = held(|| RichSegment::from_bytes(&doc).unwrap());
    assert!(
        close(seg.memory_usage(), &h),
        "unless: reported {}, held {h:?}",
        seg.memory_usage()
    );
    drop(seg);
    // (b) A `$denyallow` list of one-letter names whose parsed form passes the memory cap (a
    // 24-byte name plus its allocation each): refused while parsing, its peak near the cap.
    let n = MAX_RICH_MEMORY / 48;
    let doc = one_rule(&format!("\"denyallow\":{}", list("\"a\"", n)));
    let (r, used) = peak(|| RichSegment::from_bytes(&doc));
    assert!(matches!(r, Err(RichError::Limits)), "{r:?}");
    assert!(
        used < (MAX_RICH_MEMORY as isize) * 3 / 2,
        "denyallow peaked at {} MiB",
        used / MIB
    );
    // … and a smaller one loads, reported as what it holds.
    let doc = one_rule(&format!("\"denyallow\":{}", list("\"a\"", 100_000)));
    let (seg, h) = held(|| RichSegment::from_bytes(&doc).unwrap());
    assert!(
        close(seg.memory_usage(), &h),
        "denyallow: reported {}, held {h:?}",
        seg.memory_usage()
    );
    drop(seg);
    // (c) One entity with a million tiny suffix rules: refused at the per-entity cap while
    // parsing, before the rest is read.
    let doc = format!(
        "{{\"format\":1,\"entities\":[{{\"prefix\":\"x\",\"rules\":{}}}],\"rules\":[],\"sets\":[]}}",
        list("{\"rule\":\"a\"}", 1_000_000)
    )
    .into_bytes();
    let (r, used) = peak(|| RichSegment::from_bytes(&doc));
    assert!(r.is_err());
    assert!(used < 8 * MIB, "entities peaked at {} MiB", used / MIB);
    // … as are more entities than the cap.
    let entity =
        |i: usize| format!("{{\"prefix\":\"e{i}\",\"rules\":[{{\"rule\":\"com\",\"icann\":true}}]}}");
    let many: Vec<String> = (0..9).map(entity).collect();
    let doc = format!("{{\"format\":1,\"entities\":[{}]}}", many.join(","));
    assert!(RichSegment::from_bytes(doc.as_bytes()).is_err());
    let doc = format!("{{\"format\":1,\"entities\":[{}]}}", many[..8].join(","));
    let (seg, h) = held(|| RichSegment::from_bytes(doc.as_bytes()).unwrap());
    assert!(
        close(seg.memory_usage(), &h),
        "entities: reported {}, held {h:?}",
        seg.memory_usage()
    );
    drop(seg);
    // A realistic entity: a few thousand suffix rules of one to three labels, several entities
    // and rules linking them.
    let rules: Vec<String> = (0..3_000)
        .map(|i| match i % 3 {
            0 => format!("{{\"rule\":\"t{i}\",\"icann\":true}}"),
            1 => format!("{{\"rule\":\"co.t{i}\",\"icann\":true}}"),
            _ => format!("{{\"rule\":\"*.x.t{i}\"}}"),
        })
        .collect();
    let ents: Vec<String> = (0..3)
        .map(|e| format!("{{\"prefix\":\"tracker{e}\",\"rules\":[{}]}}", rules.join(",")))
        .collect();
    let linked: Vec<String> = (0..200)
        .map(|i| {
            format!(
                "{{\"flags\":1,\"denyallow\":[\"n{i}.example\"],\"denyallow_entities\":[{{\"prefix\":\"tracker{}\"}}]}}",
                i % 3
            )
        })
        .collect();
    let doc = format!(
        "{{\"format\":1,\"entities\":[{}],\"rules\":[{}],\"sets\":[[0,1,2]]}}",
        ents.join(","),
        linked.join(",")
    );
    let (seg, h) = held(|| RichSegment::from_bytes(doc.as_bytes()).unwrap());
    assert_eq!(seg.unlinked(), 0);
    assert!(
        close(seg.memory_usage(), &h),
        "realistic: reported {}, held {h:?}",
        seg.memory_usage()
    );
}

#[test]
fn peak_memory_is_bounded() {
    ip_chain_is_staged_one_delta_at_a_time();
    rich_nested_lists_are_bounded_and_counted();
}
