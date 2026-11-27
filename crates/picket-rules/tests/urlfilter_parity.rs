//! The urlfilter differential test (build-and-test.md §4–§5 "AdGuard parity", rules.md §3):
//! ≥ 99.99 % decision agreement with AdGuard Home's use of urlfilter v0.23 on a deterministic
//! rules × names corpus, with every `rule_policy` option at `keep`.
//!
//! Only rules.md §3's deliberate exceptions leave the metric, decided per decision: a disagreement
//! is excluded as the protocol/port extension's when the case without its extension rules agrees,
//! and as unusual bytes' when the name has unusual bytes and the case with its keyed rules read as
//! AdGuard's text patterns agrees. Response-check differences don't arise here (each query is one
//! name or address decision; tests/response_parity.rs compares response phases) and `rule_policy`
//! is all `keep`. Everything else counts.
//!
//! Three deviations wait for the owner (PARITY.md): rules.md §1's normalisation, several
//! `$badfilter` rules on one request, and browser path rules on names holding `/` bytes (review
//! round 1, R10). Each is reported in its own group and asserted against the explicit list of
//! expected deviations below, so a new deviation fails the test.
//!
//! Runs when `PICKET_URLFILTER_ORACLE` names the built `tools/urlfilter-oracle` binary; skipped
//! with a message otherwise. See PARITY.md.

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
use std::fmt::Write as _;

use common::{
    Case, Group, Query, block_matcher, build, decision, evaluate, normalise_oracle, parse_rules, run_oracle,
};
use picket_rules::Rule;
use picket_rules::classify::path_rule_as_pattern;

const MAIN: &str = "main (the metric)";
const NORMALISATION: &str = "normalisation (rules.md §1; owner decision)";
const MULTI_BADFILTER: &str = "several $badfilter rules on one request (owner decision)";
const PATH_NAMES: &str = "browser path rules × names with `/` bytes (R10; owner decision)";

/// The deviations the owner decides on: (group, case id, host text, qtype).
const EXPECTED_DEVIATIONS: &[(&str, &str, &str, u16)] = &[
    // rules.md §1: rule names are normalised (ASCII lowercase, IDN → A-labels, trailing dot
    // stripped); AdGuard compares host rules as written and keeps a key's trailing dot.
    (NORMALISATION, "n0", "example.com", 1),
    (NORMALISATION, "n0", "example.com", 28),
    (NORMALISATION, "n1", "example.com", 1),
    (NORMALISATION, "n1", "example.com", 28),
    (NORMALISATION, "n2", "xn--e1afmkfd.xn--p1ai", 1),
    (NORMALISATION, "n2", "xn--e1afmkfd.xn--p1ai", 28),
    (NORMALISATION, "n4", "example.com", 1),
    (NORMALISATION, "n4", "example.com", 28),
    (NORMALISATION, "n4", "ads.example.com", 1),
    (NORMALISATION, "n4", "ads.example.com", 28),
    (NORMALISATION, "n5", "xn--e1afmkfd.xn--p1ai", 1),
    (NORMALISATION, "n5", "xn--e1afmkfd.xn--p1ai", 28),
    (NORMALISATION, "n5", "sub.xn--e1afmkfd.xn--p1ai", 1),
    (NORMALISATION, "n5", "sub.xn--e1afmkfd.xn--p1ai", 28),
    (NORMALISATION, "n6", "ads.example.com", 1),
    (NORMALISATION, "n6", "ads.example.com", 28),
    (NORMALISATION, "n7", "tracker.de", 1),
    (NORMALISATION, "n7", "tracker.de", 28),
    // The corpus's `(picket)` groups (IDN rules, a key's trailing dot).
    (NORMALISATION, "c41", "xn--e1afmkfd.xn--p1ai", 1),
    (NORMALISATION, "c41", "sub.xn--e1afmkfd.xn--p1ai", 1),
    (NORMALISATION, "c42", "dotted.example", 1),
    // urlfilter's filterNegatedRules keeps a rule unless every $badfilter matching the request
    // negates it; Picket resolves each $badfilter on its own (rules.md §4).
    (MULTI_BADFILTER, "b0", "www.example.com", 1),
    (MULTI_BADFILTER, "b0", "www.example.com", 28),
    (MULTI_BADFILTER, "b0", "a.www.example.com", 1),
    (MULTI_BADFILTER, "b0", "a.www.example.com", 28),
    (MULTI_BADFILTER, "b1", "example.com", 1),
    (MULTI_BADFILTER, "b1", "example.com", 28),
    (MULTI_BADFILTER, "b1", "www.example.com", 1),
    (MULTI_BADFILTER, "b1", "www.example.com", 28),
    (MULTI_BADFILTER, "b1", "a.www.example.com", 1),
    (MULTI_BADFILTER, "b1", "a.www.example.com", 28),
];

#[derive(Default)]
struct Tally {
    total: u64,
    agree: u64,
    excluded_extension: u64,
    excluded_unusual: u64,
    unusual_total: u64,
    unusual_agree: u64,
    classes: BTreeMap<String, Vec<String>>,
    mix: BTreeMap<String, u64>,
}

#[test]
fn urlfilter_differential() {
    let Ok(bin) = std::env::var("PICKET_URLFILTER_ORACLE") else {
        eprintln!(
            "skipped: set PICKET_URLFILTER_ORACLE to the built tools/urlfilter-oracle binary (see PARITY.md)"
        );
        return;
    };
    let cases = build();
    let oracle = run_oracle(&bin, &cases);
    // The hand-written corpus's expectations must be urlfilter's own (parity_corpus.rs checks
    // Picket against them without Go); `(picket)` groups check spec'd deviations instead.
    let mut corpus_wrong = Vec::new();
    for g in common::corpus().iter().filter(|g| !g.picket) {
        let ci = cases.iter().position(|c| c.id == g.case.id).expect("corpus case");
        for (qi, (q, e)) in g.case.queries.iter().zip(&g.expects).enumerate() {
            let theirs = normalise_oracle(&oracle[ci][qi]);
            if !common::meets(&theirs, &e.want, q.qtype) {
                corpus_wrong.push(format!(
                    "parity-corpus.txt line {} [{}] {}: written {}, urlfilter {theirs}",
                    e.line,
                    g.title,
                    q.host_text(),
                    e.want
                ));
            }
        }
    }
    assert!(
        corpus_wrong.is_empty(),
        "{} corpus expectations aren't urlfilter's:\n{}",
        corpus_wrong.len(),
        corpus_wrong.join("\n")
    );
    let mut tallies: BTreeMap<&'static str, Tally> = BTreeMap::new();
    let mut deviations: BTreeSet<(&'static str, String, String, u16)> = BTreeSet::new();
    for (ci, case) in cases.iter().enumerate() {
        let m = block_matcher(parse_rules(&case.rules));
        let mut alt: Option<common::Alternatives> = None;
        let group = match case.group {
            Group::Main => MAIN,
            Group::Normalisation => NORMALISATION,
            Group::MultiBadfilter => MULTI_BADFILTER,
        };
        for (qi, q) in case.queries.iter().enumerate() {
            let ours = decision(&evaluate(&m, q).outcome);
            let theirs = normalise_oracle(&oracle[ci][qi]);
            let agree = ours == theirs;
            let mut target = group;
            let mut exclusion = None;
            if !agree && group == MAIN {
                let a = alt.get_or_insert_with(|| common::Alternatives::new(&case.rules));
                match a.explain(q, &theirs) {
                    common::Explained::Extension => exclusion = Some("extension"),
                    common::Explained::UnusualBytes => exclusion = Some("unusual"),
                    common::Explained::PathNames => target = PATH_NAMES,
                    common::Explained::No => {}
                }
            }
            let t = tallies.entry(target).or_default();
            if q.unusual() {
                t.unusual_total += 1;
                if agree {
                    t.unusual_agree += 1;
                }
            }
            match exclusion {
                Some("extension") => {
                    t.excluded_extension += 1;
                    continue;
                }
                Some(_) => {
                    t.excluded_unusual += 1;
                    record(
                        t,
                        "excluded: unusual bytes (keyed rules match whole labels)",
                        case,
                        q,
                        &ours,
                        &theirs,
                    );
                    continue;
                }
                None => {}
            }
            t.total += 1;
            let kind = if theirs.starts_with("hosts") {
                "hosts".to_string()
            } else {
                theirs.split(' ').take(2).collect::<Vec<_>>().join(" ")
            };
            *t.mix.entry(kind).or_default() += 1;
            if agree {
                t.agree += 1;
            } else {
                if target != MAIN {
                    deviations.insert((target, case.id.clone(), q.host_text(), q.qtype));
                }
                record(t, "disagreement", case, q, &ours, &theirs);
            }
        }
    }
    let mut report = String::new();
    for (group, t) in &tallies {
        let pct = if t.total == 0 {
            100.0
        } else {
            t.agree as f64 * 100.0 / t.total as f64
        };
        let _ = writeln!(
            report,
            "[{group}] {}/{} decisions agree ({pct:.4} %); excluded: {} extension-rule decisions, {} unusual-name decisions; unusual-name queries {} ({} agree)",
            t.agree, t.total, t.excluded_extension, t.excluded_unusual, t.unusual_total, t.unusual_agree
        );
        let _ = writeln!(report, "  decision mix (adguard): {:?}", t.mix);
        for (class, examples) in &t.classes {
            let _ = writeln!(report, "  {class}: {}", examples.len());
            let shown = if *group == MAIN { 8 } else { 40 };
            for e in examples.iter().take(shown) {
                let _ = writeln!(report, "    {e}");
            }
        }
    }
    eprintln!("{report}");
    // Cargo sets CARGO_TARGET_TMPDIR for integration tests at compile time, not at run time.
    let _ = std::fs::write(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("urlfilter-parity-report.txt"),
        &report,
    );
    // The owner's groups: exactly the expected deviations, no new ones and no stale entries.
    let expected: BTreeSet<(&'static str, String, String, u16)> = EXPECTED_DEVIATIONS
        .iter()
        .map(|(g, c, h, t)| (*g, c.to_string(), h.to_string(), *t))
        .collect();
    let path_expected = path_deviations(&cases);
    let mut all_expected = expected.clone();
    all_expected.extend(path_expected);
    let new: Vec<_> = deviations.difference(&all_expected).collect();
    let stale: Vec<_> = all_expected.difference(&deviations).collect();
    assert!(new.is_empty(), "new deviations:\n{new:#?}\n{report}");
    assert!(
        stale.is_empty(),
        "expected deviations that no longer occur:\n{stale:#?}"
    );
    let main = &tallies[MAIN];
    let pct = main.agree as f64 * 100.0 / main.total as f64;
    assert!(main.total > 50_000, "corpus too small: {}", main.total);
    assert!(pct >= 99.99, "agreement {pct:.4} % below 99.99 %\n{report}");
    for kind in [
        "none",
        "allow",
        "block",
        "hosts",
        "rewrite cname",
        "rewrite rcode",
        "rewrite records",
    ] {
        assert!(
            main.mix.get(kind).copied().unwrap_or(0) > 50,
            "the corpus has too few `{kind}` decisions\n{report}"
        );
    }
}

/// The R10 deviations: every decision on a name with a `/` byte that a browser path rule makes in
/// AdGuard (rules.md §2 sends path rules to browser lists). Listed from the corpus definition, not
/// from the run: a path rule (one [`path_rule_as_pattern`] reads) matching such a name's text.
fn path_deviations(cases: &[Case]) -> BTreeSet<(&'static str, String, String, u16)> {
    let mut out = BTreeSet::new();
    for case in cases.iter().filter(|c| c.group == Group::Main) {
        let paths: Vec<Rule> = case
            .rules
            .iter()
            .filter_map(|l| path_rule_as_pattern(l.trim()))
            .collect();
        if paths.is_empty() {
            continue;
        }
        let base = block_matcher(parse_rules(&case.rules));
        let mut with = parse_rules(&case.rules);
        with.extend(paths);
        let with = block_matcher(with);
        for q in case.queries.iter().filter(|q| q.host_text().contains('/')) {
            let a = decision(&evaluate(&base, q).outcome);
            let b = decision(&evaluate(&with, q).outcome);
            if a != b {
                out.insert((PATH_NAMES, case.id.clone(), q.host_text(), q.qtype));
            }
        }
    }
    out
}

fn record(t: &mut Tally, class: &str, case: &Case, q: &Query, ours: &str, theirs: &str) {
    let rules: Vec<&str> = case.rules.iter().map(String::as_str).take(4).collect();
    let e = format!(
        "{} {:?} qtype={} host={:?}: picket={ours:?} adguard={theirs:?}",
        case.id,
        rules,
        q.qtype,
        q.host_text()
    );
    t.classes.entry(class.to_string()).or_default().push(e);
}
