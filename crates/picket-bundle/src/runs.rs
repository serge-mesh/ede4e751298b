//! Folding IP rules into runs (bundles.md §2 step 4, §4 "IP shards").
//!
//! An address's value folds every IP rule covering it, as a domain key folds its rule forms: the
//! union of the rules' `_EXACT` level bits, plus `HAS_RICH` and the `rich.json` set of the rules
//! with conditions or answers. A run is a maximal range of addresses with one value; a run
//! crossing an IPv4 /8 is split at the shard boundary. Core's incremental build folds the rules
//! overlapping a changed range ([`fold_runs`] over them, clipped with [`clip`]) and diffs the result
//! against the stored runs ([`diff_runs`]) into `upsert` / `delete` ops per IP shard.

use std::collections::BTreeMap;

use picket_rules::Flags;
use picket_rules::ip::IpRange;
use picket_rules::rule::RichRule;

use crate::ips::{IpShardId, Run};
use crate::rich::RichBuilder;
use crate::value::Value;

/// One IP rule as the compiler folds it ([`picket_rules::rule::Rule::ip_spec`], with its
/// `$badfilter` resolution applied).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpRuleInput {
    pub range: IpRange,
    /// `_EXACT` level bits (none for a rich rule).
    pub flags: Flags,
    pub rich: Option<RichRule>,
}

/// Folds IP rules into runs per IP shard. Rich rules are interned into `rich`.
pub fn fold_runs(rules: &[IpRuleInput], rich: &mut RichBuilder) -> BTreeMap<IpShardId, Vec<Run>> {
    let mut out: BTreeMap<IpShardId, Vec<Run>> = BTreeMap::new();
    for v4 in [true, false] {
        let fam: Vec<&IpRuleInput> = rules.iter().filter(|r| r.range.v4 == v4).collect();
        if fam.is_empty() {
            continue;
        }
        // Boundaries: every first, and every last + 1.
        let mut points: Vec<u128> = Vec::with_capacity(fam.len().saturating_mul(2));
        for r in &fam {
            points.push(r.range.first);
            if let Some(n) = r.range.last.checked_add(1) {
                points.push(n);
            }
        }
        points.sort_unstable();
        points.dedup();
        // Rules by first address, swept.
        let mut by_first: Vec<usize> = (0..fam.len()).collect();
        by_first.sort_unstable_by_key(|&i| fam.get(i).map_or(0, |r| r.range.first));
        let mut next_rule = 0usize;
        let mut active: Vec<usize> = Vec::new();
        let mut runs: Vec<Run> = Vec::new();
        for (k, &p) in points.iter().enumerate() {
            while let Some(&i) = by_first.get(next_rule) {
                if fam.get(i).is_some_and(|r| r.range.first <= p) {
                    active.push(i);
                    next_rule = next_rule.saturating_add(1);
                } else {
                    break;
                }
            }
            active.retain(|&i| fam.get(i).is_some_and(|r| r.range.last >= p));
            if active.is_empty() {
                continue;
            }
            let end = match points.get(k.saturating_add(1)) {
                Some(&n) => n.saturating_sub(1),
                None => fam.iter().map(|r| r.range.last).max().unwrap_or(p),
            };
            active.sort_unstable();
            let mut flags = Flags::NONE;
            let mut rich_rules: Vec<RichRule> = Vec::new();
            for &i in &active {
                let Some(r) = fam.get(i) else { continue };
                flags |= r.flags.and(Flags::ALL_LEVELS);
                if let Some(rr) = &r.rich {
                    rich_rules.push(rr.clone());
                }
            }
            let value = if rich_rules.is_empty() {
                Value::flags_only(flags)
            } else {
                let set = rich.set(&rich_rules);
                Value::new(flags | Flags::HAS_RICH, set)
            };
            if value.flags().is_empty() {
                continue;
            }
            match runs.last_mut() {
                Some(l) if l.value == value && l.last.checked_add(1) == Some(p) => l.last = end,
                _ => runs.push(Run {
                    first: p,
                    last: end,
                    value,
                }),
            }
        }
        for run in runs {
            split_into(&mut out, v4, run);
        }
    }
    out
}

/// Adds a run to its shard(s), splitting it at IPv4 /8 boundaries.
fn split_into(out: &mut BTreeMap<IpShardId, Vec<Run>>, v4: bool, run: Run) {
    if !v4 {
        out.entry(IpShardId::V6).or_default().push(run);
        return;
    }
    let mut s = run.first;
    loop {
        let shard = IpShardId::of(true, s);
        let (_, hi) = shard.bounds();
        let e = run.last.min(hi);
        out.entry(shard).or_default().push(Run {
            first: s,
            last: e,
            value: run.value,
        });
        if e >= run.last {
            break;
        }
        s = e.saturating_add(1);
    }
}

/// The parts of `runs` inside `first..=last`.
pub fn clip(runs: &[Run], first: u128, last: u128) -> Vec<Run> {
    runs.iter()
        .filter(|r| r.last >= first && r.first <= last)
        .map(|r| Run {
            first: r.first.max(first),
            last: r.last.min(last),
            value: r.value,
        })
        .collect()
}

/// The ops turning `old` runs into `new` ones (both sorted, of one shard): runs only in `old` are
/// deleted, runs only in `new` upserted (bundles.md §5 "IP deltas work on runs").
pub fn diff_runs(old: &[Run], new: &[Run]) -> (Vec<Run>, Vec<Run>) {
    let deletes = old
        .iter()
        .filter(|r| new.binary_search(r).is_err())
        .copied()
        .collect();
    let upserts = new
        .iter()
        .filter(|r| old.binary_search(r).is_err())
        .copied()
        .collect();
    (deletes, upserts)
}

/// The value at an address from a run list.
pub fn value_at(runs: &[Run], addr: u128) -> Option<Value> {
    let i = runs.partition_point(|r| r.first <= addr);
    let r = runs.get(i.checked_sub(1)?)?;
    (addr <= r.last).then_some(r.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str, flags: Flags) -> IpRuleInput {
        IpRuleInput {
            range: IpRange::parse(s).unwrap(),
            flags,
            rich: None,
        }
    }

    #[test]
    fn folds_and_splits() {
        let mut rb = RichBuilder::new();
        let runs = fold_runs(
            &[
                rule("10.0.0.0/8", Flags::B_EXACT),
                rule("10.1.2.0/24", Flags::A_EXACT),
                rule("11.0.0.0/7", Flags::B_EXACT), // 10.0.0.0/7 normalised: 10–11
                rule("2001:db8::/32", Flags::B_EXACT),
            ],
            &mut rb,
        );
        let v10 = &runs[&IpShardId::V4(10)];
        assert_eq!(v10.len(), 3, "{v10:?}");
        assert_eq!(v10[1].value, Value::flags_only(Flags::B_EXACT | Flags::A_EXACT));
        assert_eq!(runs[&IpShardId::V4(11)].len(), 1);
        assert_eq!(runs[&IpShardId::V6].len(), 1);
        let a = IpRange::parse("10.1.2.3").unwrap().first;
        assert_eq!(value_at(v10, a).unwrap().flags(), Flags::B_EXACT | Flags::A_EXACT);
    }

    #[test]
    fn diff() {
        let r = |f, l, v| Run {
            first: f,
            last: l,
            value: Value(v),
        };
        let old = vec![r(0, 9, 1), r(10, 19, 2)];
        let new = vec![r(0, 9, 1), r(10, 14, 2), r(15, 19, 3)];
        let (d, u) = diff_runs(&old, &new);
        assert_eq!(d, vec![r(10, 19, 2)]);
        assert_eq!(u, vec![r(10, 14, 2), r(15, 19, 3)]);
        assert_eq!(clip(&old, 5, 12), vec![r(5, 9, 1), r(10, 12, 2)]);
    }
}
