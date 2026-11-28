//! Allocation budget: a filter evaluation makes zero heap allocation operations (allocations
//! and reallocations both count, as in the edge's and the wire's budgets) — the per-bundle name
//! lookup over hot keys (hit and miss, 2–5 suffix probes) and plain patterns (including a name
//! where more than 16 shortcuts occur), and address checks in the response phase (an IPv4 set
//! hit, IPv4 and IPv6 misses, IPv6 hits). Counted by a global allocator after a warm-up pass;
//! this binary holds one test so no other thread allocates meanwhile.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::alloc::System;

use common::*;
use picket_rules::QueryCtx;
use picket_rules::matcher::BundleAction;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn filter_evaluation_allocates_nothing() {
    let rules: Vec<String> = [
        "||ads.example.com^",
        "|exact.example.org^",
        "@@||ok.ads.example.com^",
        "||imp.example^$important",
        "||ad*.tracker.net^",
        "/^banner[0-9]+\\./",
        "||1.2.3.4^",
        "||2001:db8::1^",
        "||2001:db8:1::77^",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain((0..2000).map(|i| format!("||filler{i}.example^")))
    // Review round 1, B9 (a): 20 patterns whose shortcuts are consecutive 3-letter substrings of
    // one name, so more than 16 shortcuts occur in it.
    .chain((0..20u8).map(|i| {
        let s: String = (0..3u8).map(|k| char::from(b'a' + i + k)).collect();
        format!("/{s}/")
    }))
    .collect();
    let l = compile_and_load(BundleAction::Block, &parse_rules(&rules), 500, Tiering::AllHot);
    let names: Vec<Vec<&[u8]>> = [
        "x.y.ads.example.com",
        "ok.ads.example.com",
        "exact.example.org",
        "www.nothing.example.net",
        "a.b.c.d.miss.example",
        "adserver.tracker.net",
        "banner42.example.com",
        "abcdefghijklmnopqrstuvwxy.example",
    ]
    .iter()
    .map(|n| n.split('.').map(str::as_bytes).collect())
    .collect();
    let qnames: Vec<picket_wire::QName> = ["x.y.ads.example.com", "www.nothing.example.net"]
        .iter()
        .map(|n| picket_wire::QName::from_text(n).unwrap())
        .collect();
    let ctx = QueryCtx {
        qtype: 1,
        ..Default::default()
    };
    let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    // Review round 1, B9 (b): IPv6 checks (hits and misses) and an IPv4 miss, which take the
    // address's text form.
    let other_ips: Vec<std::net::IpAddr> = [
        "2001:db8::1",
        "2001:db8:1::77",
        "2001:db8:ffff::1:0:0:1",
        "fe80::1",
        "::",
        "9.9.9.9",
        "::ffff:9.9.9.9",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    // Warm up (first-use initialisation inside dependencies).
    for n in &names {
        let _ = l.bundle.lookup_labels(n, &ctx);
    }
    let _ = l.bundle.lookup_ip(ip, &ctx);
    for a in &other_ips {
        let _ = l.bundle.lookup_ip(*a, &ctx);
    }
    let region = Region::new(GLOBAL);
    let mut blocks = 0;
    for _ in 0..100 {
        for n in &names {
            let d = l.bundle.lookup_labels(n, &ctx);
            blocks += usize::from(d.outcome == picket_rules::matcher::Outcome::Block);
        }
        for q in &qnames {
            let _ = l.bundle.lookup_name(q, &ctx);
        }
        let d = l.bundle.lookup_ip(ip, &ctx);
        blocks += usize::from(d.outcome == picket_rules::matcher::Outcome::Block);
        for a in &other_ips {
            let d = l.bundle.lookup_ip(*a, &ctx);
            blocks += usize::from(d.outcome == picket_rules::matcher::Outcome::Block);
        }
    }
    let stats = region.change();
    assert_eq!(
        stats.allocations + stats.reallocations,
        0,
        "allocations and reallocations: {stats:?}"
    );
    // Per round: x.y.ads, exact, adserver.tracker, banner42, the 20-shortcut name, 1.2.3.4,
    // 2001:db8::1 and 2001:db8:1::77.
    assert_eq!(blocks, 100 * 8, "the lookups did match");
}
