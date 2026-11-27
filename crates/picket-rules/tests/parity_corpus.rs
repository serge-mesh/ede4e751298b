//! The hand-written AdGuard parity corpus (`fixtures/rules/parity-corpus.txt`, PARITY.md §2): rule
//! groups with the decision urlfilter v0.23 and AdGuard Home's `matchHost` give for each name or
//! answer address, checked without Go. The differential test checks the same expectations against
//! the oracle (`urlfilter_parity.rs`), so the file stays true to urlfilter. Groups marked
//! `(picket)` check a deviation the spec names (rules.md §1–§3) instead.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use common::{corpus, decision, evaluate, meets, parse_rules_raw};

#[test]
fn corpus_expectations() {
    let groups = corpus();
    assert!(groups.len() >= 90, "corpus has {} groups", groups.len());
    let mut checked = 0usize;
    let mut failures = Vec::new();
    for g in &groups {
        let parsed = parse_rules_raw(&g.case.rules);
        let raws: Vec<String> = parsed.iter().map(|(_, raw)| raw.clone()).collect();
        let m = common::block_matcher(parsed.into_iter().map(|(r, _)| r).collect());
        for (q, e) in g.case.queries.iter().zip(&g.expects) {
            checked += 1;
            let res = evaluate(&m, q);
            let got = decision(&res.outcome);
            let mut ok = meets(&got, &e.want, q.qtype);
            if let Some(d) = &e.decisive {
                let decided = res.decisive().next().and_then(|mm| raws.get(mm.rule));
                ok &= decided == Some(d);
            }
            if !ok {
                failures.push(format!(
                    "line {} [{}] {}: want {}{}, got {got}",
                    e.line,
                    g.title,
                    q.host_text(),
                    e.want,
                    e.decisive
                        .as_deref()
                        .map(|d| format!(" by {d:?}"))
                        .unwrap_or_default()
                ));
            }
        }
    }
    assert!(checked >= 300, "corpus has {checked} expectations");
    assert!(
        failures.is_empty(),
        "{} of {checked} expectations failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
