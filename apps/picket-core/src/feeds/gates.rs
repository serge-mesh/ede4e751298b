//! Sanity gates (feeds.md §5), as pure decisions over a run's counts.
//!
//! - **Parse errors** ≤ `max_parse_error_ratio` (errors ÷ non-empty, non-comment lines).
//! - `min_entries` ≤ total ≤ `max_entries` (per feed, across types).
//! - **Change ratio** per type: `|added| + |removed| ≤ max(max_change_ratio × previous total,
//!   min_change_allowance)`; skipped on a feed's first run; an `aggregate` type removes none.
//! - A parse-error or entry-count failure **rejects** the run; a change-ratio failure **holds**
//!   it. Manual feeds skip the entry-count and change-ratio gates.

use super::types::{ParseSummary, TypeCounts};
use crate::config::model::Sanity;

/// A gate's verdict.
#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    Pass,
    /// Never applied (`rejected`).
    Reject {
        gate: &'static str,
        reason: String,
    },
    /// Waits for confirmation (`held`).
    Hold {
        reason: String,
    },
}

/// The change counts of one run against a reference set (the applied entries, or a held run's).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: TypeCounts,
    pub removed: TypeCounts,
}

/// The parse-error and entry-count gates.
pub fn reject_gates(s: &Sanity, manual: bool, parse: &ParseSummary, total: u64) -> Verdict {
    let ratio = parse.error_ratio();
    if ratio > s.max_parse_error_ratio {
        return Verdict::Reject {
            gate: "parse_errors",
            reason: format!(
                "{} of {} rule lines can't be read ({:.2} % > {:.2} %)",
                parse.errors,
                parse.rule_lines,
                ratio * 100.0,
                s.max_parse_error_ratio * 100.0
            ),
        };
    }
    if manual {
        return Verdict::Pass;
    }
    if let Some(min) = s.min_entries
        && total < min
    {
        return Verdict::Reject {
            gate: "entries",
            reason: format!("{total} entries, fewer than min_entries {min}"),
        };
    }
    if let Some(max) = s.max_entries
        && total > max
    {
        return Verdict::Reject {
            gate: "entries",
            reason: format!("{total} entries, more than max_entries {max}"),
        };
    }
    Verdict::Pass
}

/// The most changes a type may make against `prev_total` entries.
pub fn allowance(s: &Sanity, prev_total: u64) -> u64 {
    let by_ratio = (s.max_change_ratio * prev_total as f64).floor();
    let by_ratio = if by_ratio.is_finite() && by_ratio > 0.0 {
        crate::util::f64_to_u64(by_ratio)
    } else {
        0
    };
    by_ratio.max(s.min_change_allowance)
}

/// The change-ratio gate, per type: `None` when every type is within its limit, else which
/// type passed it and by how much.
pub fn change_gate(s: &Sanity, changes: &Changes, prev: &TypeCounts) -> Option<String> {
    for t in picket_rules::RuleType::ALL {
        let n = changes.added.get(t).saturating_add(changes.removed.get(t));
        let limit = allowance(s, prev.get(t));
        if n > limit {
            return Some(format!(
                "{} {} changes (+{} −{}) against {} entries, over the limit of {limit}",
                n,
                t.as_str(),
                changes.added.get(t),
                changes.removed.get(t),
                prev.get(t)
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(errors: u64, rule_lines: u64) -> ParseSummary {
        ParseSummary {
            errors,
            rule_lines,
            ..ParseSummary::default()
        }
    }

    #[test]
    fn each_gate() {
        let s = Sanity {
            min_entries: Some(10),
            max_entries: Some(100),
            ..Sanity::default()
        };
        assert_eq!(reject_gates(&s, false, &parse(0, 50), 50), Verdict::Pass);
        assert!(matches!(
            reject_gates(&s, false, &parse(2, 100), 50),
            Verdict::Reject {
                gate: "parse_errors",
                ..
            }
        ));
        assert_eq!(
            reject_gates(&s, false, &parse(1, 100), 50),
            Verdict::Pass,
            "1 % is allowed"
        );
        assert!(matches!(
            reject_gates(&s, false, &parse(0, 5), 5),
            Verdict::Reject { gate: "entries", .. }
        ));
        assert!(matches!(
            reject_gates(&s, false, &parse(0, 500), 500),
            Verdict::Reject { gate: "entries", .. }
        ));
        // Manual feeds keep the parse-error gate only.
        assert_eq!(reject_gates(&s, true, &parse(0, 5), 5), Verdict::Pass);
        assert!(matches!(
            reject_gates(&s, true, &parse(5, 5), 5),
            Verdict::Reject { .. }
        ));
    }

    #[test]
    fn change_ratio() {
        let s = Sanity::default(); // 0.20, allowance 100
        assert_eq!(allowance(&s, 10_000), 2_000);
        assert_eq!(allowance(&s, 10), 100);
        let prev = TypeCounts {
            dns: 10_000,
            ip: 0,
            browser: 0,
        };
        let mut c = Changes::default();
        c.added.dns = 1_500;
        c.removed.dns = 500;
        assert_eq!(change_gate(&s, &c, &prev), None);
        c.removed.dns = 501;
        assert!(change_gate(&s, &c, &prev).unwrap().contains("dns"));
        // allowance 0 leaves only the ratio
        let s0 = Sanity {
            min_change_allowance: 0,
            ..Sanity::default()
        };
        let mut c = Changes::default();
        c.added.ip = 1;
        assert!(change_gate(&s0, &c, &TypeCounts::default()).is_some());
    }
}
