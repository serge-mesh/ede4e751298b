//! Bounds (README §2 "Bounded", "Untrusted input"): pattern → regex translation is linear in the
//! rule length, long lines are refused without being held, and pathological rules don't stall
//! classification or matching.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

use std::time::{Duration, Instant};

use picket_rules::adguard::{pattern_rust_regex, pattern_to_go_regex, shortcut};
use picket_rules::classify::{Line, classify_adblock_line};
use picket_rules::goregex::translate;
use picket_rules::matcher::{BundleAction, BundleMatcher};
use picket_rules::{QueryCtx, Rule};

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let t = Instant::now();
    let v = f();
    (v, t.elapsed())
}

fn rules(lines: &[String]) -> Vec<Rule> {
    lines
        .iter()
        .flat_map(|l| match classify_adblock_line(l, false) {
            Line::Items(v) => v
                .into_iter()
                .filter_map(|i| {
                    if let picket_rules::classify::Item::Rule(r) = i {
                        Some(r)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>(),
            Line::Skipped => vec![],
        })
        .collect()
}

#[test]
fn translation_is_linear() {
    // Doubling the input must not much more than double the time or the output.
    let unit = "a*^|b.c$*(?i)";
    let small: String = unit.repeat(2_000);
    let large: String = unit.repeat(4_000);
    let (rs, ts) = timed(|| pattern_rust_regex(&small).map(|s| s.len()).unwrap_or(0));
    let (rl, tl) = timed(|| pattern_rust_regex(&large).map(|s| s.len()).unwrap_or(0));
    assert!(rl <= rs * 2 + 64, "output grows linearly: {rs} -> {rl}");
    assert!(
        tl < ts * 4 + Duration::from_millis(50),
        "time grows linearly: {ts:?} -> {tl:?}"
    );
    assert!(pattern_to_go_regex(&large).len() <= large.len() * 24);
}

#[test]
fn regex_rules_with_many_flag_groups_and_stars() {
    let inner = "(?i)a.*".repeat(10_000);
    let (r, t) = timed(|| translate(&inner));
    assert!(r.is_ok());
    assert!(t < Duration::from_secs(1), "{t:?}");
    let (s, t) = timed(|| shortcut(&format!("/{}/", "{(".repeat(20_000))));
    assert!(t < Duration::from_secs(1), "{t:?}");
    drop(s);
}

#[test]
fn long_and_pathological_lines() {
    let long = format!("||{}.example^", "a".repeat(60_000));
    let (_, t) = timed(|| classify_adblock_line(&long, false));
    assert!(t < Duration::from_secs(1), "{t:?}");
    let stars = format!("{}x", "*".repeat(30_000));
    let (_, t) = timed(|| classify_adblock_line(&stars, false));
    assert!(t < Duration::from_secs(1), "{t:?}");
    // A huge pattern either builds within the NFA limit or matches nothing; matching stays fast.
    let m = BundleMatcher::new(
        BundleAction::Block,
        rules(&[stars, "/(a|b|c)*d{100}/".to_string()]),
    );
    let ctx = QueryCtx {
        qtype: 1,
        ..QueryCtx::default()
    };
    let name = "x".repeat(60) + "." + &"y".repeat(60);
    let (_, t) = timed(|| m.match_dotted(&name, &ctx));
    assert!(t < Duration::from_secs(2), "{t:?}");
}

#[test]
fn cross_feed_scan_on_a_large_bundle() {
    // bundles.md §2 guardrail: with an exception pattern in the bundle, every keyed block is
    // walked once through each exception pattern's automaton; that stays fast for a big list.
    let mut lines: Vec<String> = (0..50_000).map(|i| format!("||host{i}.example^")).collect();
    lines.push("@@/^host1234\\./".to_string());
    lines.push("@@||host7.example^".to_string());
    let rs = rules(&lines);
    let feeds: Vec<usize> = (0..rs.len()).map(|i| usize::from(i >= 50_000)).collect();
    let (c, t) = timed(|| picket_rules::badfilter::cross_feed_cancellations(&rs, &feeds));
    // `@@/^host1234\./` matches `host1234.host<i>.example`, below every key, so it cancels each
    // block somewhere (sound, review round 1 R11); `@@||host7.example^` cancels its own key. One
    // entry per canceller (review round 2, CC3).
    assert!(!c.capped);
    assert_eq!(c.cancellers.len(), 2);
    assert_eq!(c.get(50_000).map(|x| x.count), Some(50_000));
    assert_eq!(c.get(50_001).map(|x| x.count), Some(1));
    assert!(t < Duration::from_secs(20), "{t:?}");
    eprintln!("cross-feed scan over 50k keys: {t:?}");
}

/// The heavy patterns of review round 1, R7: `/(?:\w|-){900}N/` and variants (no shortcut, so
/// every one runs on every query).
fn heavy(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("/(?:\\w|-){{900}}{}{}/", char::from(b'a' + (i % 26) as u8), i))
        .collect()
}

#[test]
fn pattern_proofs_are_bounded() {
    // The compiler's proofs walk the NFA (linear) instead of building dense DFAs (0.16 s and
    // 0.32 s per pattern, in release, before).
    let rs = rules(&heavy(40));
    let (_, t) = timed(|| {
        for r in &rs {
            let spec = r.pattern_spec().unwrap();
            assert!(picket_rules::analysis::pattern_can_match(&spec));
            // Over-approximated (any string of IP-text bytes): true for hex-letter variants.
            let _ = picket_rules::compile::can_match_ip_text(r);
        }
    });
    assert!(t < Duration::from_secs(20), "{t:?}");
}

#[test]
fn regex_cache_respects_its_budget() {
    // core.md §6, README §2 Bounded (review round 2, CC5): compiled patterns stay under a memory
    // cap without thrashing. Patterns are admitted in bundle order while they fit; the rest are
    // dropped and reported (the compiler drops them with bundle_warning), never rebuilt per query.
    let budget = 8 * 1024 * 1024;
    let lines = heavy(60);
    let m = BundleMatcher::new(BundleAction::Block, rules(&lines)).with_regex_budget(budget);
    let ctx = QueryCtx {
        qtype: 1,
        ..QueryCtx::default()
    };
    let dropped = m.patterns_over_budget();
    assert!(
        !dropped.is_empty() && dropped.len() < 60,
        "{} dropped",
        dropped.len()
    );
    let admitted = 60 - dropped.len();
    // Bundle order: the first patterns are the resident ones.
    assert!(dropped.iter().all(|&i| i >= admitted), "{dropped:?}");
    let miss = "x.example".to_string();
    for round in 0..3 {
        let r = m.match_dotted(&miss, &ctx);
        assert_eq!(r.outcome, picket_rules::Outcome::None);
        let (used, _) = m.regex_cache_stats();
        assert!(used <= budget, "round {round}: {used} bytes");
    }
    // A name with 900 word characters and then `a0` matches the first pattern (resident).
    let long = format!("{}a0", "w".repeat(900));
    let r = m.match_name(&[long.as_bytes(), b"example"], &ctx);
    assert_eq!(r.outcome, picket_rules::Outcome::Block);
    // The last pattern was dropped: it matches nothing.
    let last = format!("{}{}59", "w".repeat(900), char::from(b'a' + (59 % 26) as u8));
    let r = m.match_name(&[last.as_bytes(), b"example"], &ctx);
    assert_eq!(r.outcome, picket_rules::Outcome::None);
    let (used, builds) = m.regex_cache_stats();
    assert!(used <= budget, "{used} bytes");
    assert!(
        builds <= admitted as u64 + 1,
        "no rebuilds: {builds} builds for {admitted} resident"
    );
}

#[test]
fn shared_pattern_admission_matches_the_reference() {
    // Review round 1, B3: picket-bundle's compiler admits patterns with `pattern_admission`, which
    // must decide exactly as the reference matcher's regex cache (same costs, same order, same
    // stop), with badfiltered and browser rules in the list as the matcher has them.
    let budget = 8 * 1024 * 1024;
    let mut lines = heavy(60);
    lines.insert(3, "/(?:a|b)*a(?:a|b){12}/$badfilter".to_string());
    lines.insert(5, "||ads*.example^$badfilter".to_string());
    lines.insert(7, "||ads*.example^".to_string());
    let rs = rules(&lines);
    let m = BundleMatcher::new(BundleAction::Block, rs.clone()).with_regex_budget(budget);
    let a = picket_rules::matcher::pattern_admission(BundleAction::Block, &rs, budget);
    assert_eq!(a.over_budget, m.patterns_over_budget());
    assert_eq!(a.too_large, m.patterns_too_large());
    assert!(!a.over_budget.is_empty() && !a.resident.is_empty());
    let used: usize = a.resident.iter().map(|(_, c)| c).sum();
    assert!(used <= picket_rules::matcher::pattern_admission_limit(budget));
    let (resident_bytes, _) = m.regex_cache_stats();
    assert_eq!(
        resident_bytes, used,
        "the matcher's resident regexes cost what the admission says"
    );
    for (r, c) in &a.resident {
        let spec = rs[*r].pattern_spec().unwrap();
        assert_eq!(
            picket_rules::matcher::pattern_cost(spec.regex.as_deref().unwrap()),
            Some(*c)
        );
    }
}

#[test]
fn per_query_time_is_bounded_past_the_budget() {
    // CC5: 2,000 shortcut-less patterns used to cost every query a rebuild of each (seconds per
    // query); past the budget they are dropped, so a query runs only the resident set.
    let lines = heavy(200);
    let (m, t_build) =
        timed(|| BundleMatcher::new(BundleAction::Block, rules(&lines)).with_regex_budget(4 * 1024 * 1024));
    eprintln!("matcher with 200 heavy patterns built in {t_build:?}");
    let ctx = QueryCtx {
        qtype: 1,
        ..QueryCtx::default()
    };
    let mut worst = Duration::ZERO;
    for q in 0..20 {
        let name = format!("q{q}.example");
        let (r, t) = timed(|| m.match_dotted(&name, &ctx));
        assert_eq!(r.outcome, picket_rules::Outcome::None);
        worst = worst.max(t);
    }
    eprintln!("worst query: {worst:?}");
    assert!(worst < Duration::from_millis(100), "{worst:?}");
    let (_, builds) = m.regex_cache_stats();
    assert!(builds < 40, "{builds} builds");
}

#[test]
fn a_regex_provider_replaces_the_matchers_own_cache() {
    // core.md §6 (review fix-w5a N12): a caller keeping one budget for every compiled pattern
    // gives its matchers a provider; such a matcher compiles nothing of its own and decides as
    // one with its own cache.
    use picket_rules::matcher::{PatternRegex, RegexProvider};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Shared {
        built: Mutex<HashMap<String, Option<PatternRegex>>>,
        asked: Mutex<u64>,
    }
    impl RegexProvider for Shared {
        fn is_match(&self, source: &str, haystack: &str) -> bool {
            *self.asked.lock().unwrap() += 1;
            let mut b = self.built.lock().unwrap();
            b.entry(source.to_string())
                .or_insert_with(|| PatternRegex::build(source))
                .as_ref()
                .is_some_and(|r| r.is_match(haystack))
        }
    }
    let lines: Vec<String> = [
        "/^ad[0-9]+\\.example$/",
        "||track*.example^",
        "@@/^ad7\\.example$/",
        "||plain.example^",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let rs = rules(&lines);
    let shared = Arc::new(Shared::default());
    let with = BundleMatcher::new(BundleAction::Block, rs.clone()).with_regex_provider(shared.clone());
    let own = BundleMatcher::new(BundleAction::Block, rs);
    let ctx = QueryCtx {
        qtype: 1,
        ..QueryCtx::default()
    };
    for name in [
        "ad1.example",
        "ad7.example",
        "trackers.example",
        "plain.example",
        "x.example",
    ] {
        let a = with.match_dotted(name, &ctx);
        let b = own.match_dotted(name, &ctx);
        assert_eq!(a.outcome, b.outcome, "{name}");
        assert_eq!(a.matches, b.matches, "{name}");
    }
    assert_eq!(
        with.regex_cache_stats(),
        (0, 0),
        "the matcher compiled nothing itself"
    );
    assert!(with.patterns_over_budget().is_empty() && with.patterns_too_large().is_empty());
    assert!(*shared.asked.lock().unwrap() > 0, "the provider was asked");
    assert!(own.regex_cache_stats().1 > 0);
    // A pattern regex's cache stays within its cost.
    let r = PatternRegex::build("(?:a|b)*a(?:a|b){12}").unwrap();
    let cost = r.cost();
    for i in 0..200 {
        let hay: String = (0..64)
            .map(|j| if (i * 7 + j) % 3 == 0 { 'a' } else { 'b' })
            .collect();
        r.is_match(&hay);
    }
    assert!(cost > picket_rules::matcher::PATTERN_CACHE_GROWTH);
    assert_eq!(
        r.cost(),
        cost,
        "the cost is fixed: growth past it resets the cache"
    );
}
