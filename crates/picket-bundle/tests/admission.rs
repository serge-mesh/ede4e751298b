//! Pattern admission (review round 1, B3; bundles.md §2 "Determinism", §6; rules.md §3–§4): the
//! compiler, the edge reader and picket-rules' reference matcher keep the same patterns under the
//! same budget, with one cost model, so a name is never blocked on the edge by a pattern the
//! reference dropped, nor the reverse.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use common::*;
use picket_bundle::compile::{BuildOptions, CompileOptions, build, compile_rules, load_bundle};
use picket_bundle::page::MemPages;
use picket_bundle::patterns::{DEFAULT_BUDGET, PatternFate};
use picket_rules::matcher::{BundleAction, BundleMatcher, Outcome};

fn lines(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("/^ad{i:05}[a-z]+\\./")).collect()
}

/// Compiles and loads with one budget for compiler, reader and reference; returns the loaded
/// bundle, the reference and the compile.
fn at_budget(
    lines: &[String],
    budget: usize,
) -> (
    picket_bundle::Bundle,
    BundleMatcher,
    picket_bundle::compile::Compiled,
) {
    let rules = parse_rules(lines);
    let mut co = CompileOptions::new(BundleAction::Block, Some(psl()));
    co.pattern_budget = budget;
    let c = compile_rules(&rules, &co);
    let built = build(&c, &BuildOptions::new("adm", BundleAction::Block)).unwrap();
    let b = load_bundle(
        &built.head_blob.bytes,
        &built.blobs,
        Some(&MemPages::default()),
        budget,
    )
    .unwrap();
    let r = reference(BundleAction::Block, rules).with_regex_budget(budget);
    (b, r, c)
}

fn outcome_both(b: &picket_bundle::Bundle, r: &BundleMatcher, name: &str) -> (Outcome, Outcome) {
    let q = Query::name(name);
    (
        bundle_decision(b, &MemPages::default(), &q).outcome,
        reference_outcome(r, &q),
    )
}

/// The reviewers' case at the default budget: 18,000 small regexes. The reference keeps the first
/// few thousand; the bundle must keep exactly those, so `ad10000x.example` is no result on both.
#[test]
fn many_patterns_at_the_default_budget() {
    let ls = lines(18_000);
    let (b, r, c) = at_budget(&ls, DEFAULT_BUDGET);
    let dropped = r.patterns_over_budget();
    assert!(
        !dropped.is_empty() && dropped.len() < 18_000,
        "{} dropped",
        dropped.len()
    );
    assert_eq!(c.pattern_admission.over_budget, dropped);
    let kept = 18_000 - dropped.len();
    assert_eq!(
        b.patterns().patterns.len(),
        kept,
        "the edge holds the reference's set"
    );
    assert_eq!(
        b.patterns().patterns.over_budget(),
        0,
        "nothing more is cut on the edge"
    );
    for name in ["ad00000x.example", "ad10000x.example", "ad17999x.example"] {
        let (got, want) = outcome_both(&b, &r, name);
        assert_eq!(got, want, "{name}");
    }
    let last = format!("ad{:05}x.example", kept - 1);
    assert_eq!(outcome_both(&b, &r, &last), (Outcome::Block, Outcome::Block));
    let first_dropped = format!("ad{:05}x.example", kept);
    assert_eq!(
        outcome_both(&b, &r, &first_dropped),
        (Outcome::None, Outcome::None)
    );
}

/// Budgets that cut at assorted points, with badfiltered and catch-all patterns in the list (they
/// take places in the reference's order): every path agrees on every name, and the fates list
/// what was dropped.
#[test]
fn agreement_across_budgets() {
    let mut ls = lines(120);
    ls.insert(10, "/^ad00011[a-z]+\\./$badfilter".to_string());
    ls.insert(20, "||*^$dnstype=MX".to_string());
    ls.insert(30, "/(?:a|b)*a(?:a|b){12}/".to_string());
    let one = picket_rules::matcher::pattern_cost("^ad00000[a-z]+\\.").unwrap();
    for budget in [1, one * 2, one * 30, one * 61, one * 100, DEFAULT_BUDGET] {
        let (b, r, c) = at_budget(&ls, budget);
        assert_eq!(
            c.pattern_admission.over_budget,
            r.patterns_over_budget(),
            "budget {budget}"
        );
        assert_eq!(b.patterns().patterns.over_budget(), 0, "budget {budget}");
        let over = c
            .patterns
            .iter()
            .filter(|p| p.admit == picket_bundle::patterns::PatternAdmit::OverBudget)
            .count();
        assert!(over <= c.pattern_admission.over_budget.len());
        for i in (0..120).step_by(7).chain([11, 119]) {
            let name = format!("ad{i:05}q.example");
            let (got, want) = outcome_both(&b, &r, &name);
            assert_eq!(got, want, "budget {budget}: {name}");
        }
        let (got, want) = outcome_both(&b, &r, "abbbbbbbbbbbb.example");
        assert_eq!(got, want, "budget {budget}: the lazy pattern");
    }
    // The fates of a cut compile list the drops for core's bundle_warning.
    let rules = parse_rules(&ls);
    let mut co = CompileOptions::new(BundleAction::Block, Some(psl()));
    co.pattern_budget = one * 30;
    let c = compile_rules(&rules, &co);
    let built = build(&c, &BuildOptions::new("adm", BundleAction::Block)).unwrap();
    assert!(built.pattern_fates.contains(&PatternFate::OverBudget));
    assert_eq!(built.pattern_fates.len(), c.patterns.len());
}
