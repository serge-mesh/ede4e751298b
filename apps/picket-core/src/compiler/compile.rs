//! Compiling a bundle's rules (bundles.md §2 "Every build applies"; rules.md §3–§4), the way
//! picket-bundle's [`picket_bundle::compile::compile_rules`] does for a whole rule list, but per
//! part so a build holds only what it needs:
//!
//! - **One key** ([`compile_key`]): the rules folding into a domain key, with `$badfilter`
//!   resolved among them (a `$badfilter` targets rules with its own pattern text, which name the
//!   same key), folded into flags and rich rules ([`KeyValue`]).
//! - **Patterns** ([`compile_patterns`]) and **IP rules** ([`compile_ips`]): every one of the
//!   bundle's, read in full each build that needs them; the pattern admission is the reference
//!   matcher's ([`pattern_admission`]), so the edge drops exactly what core's reference drops.
//! - **Bundle-wide inputs** ([`BundleWide`]): urlfilter's matched-rule order of `$dnsrewrite`
//!   rules ([`rank_orders`]) and the `$denyallow` entity table within the per-bundle cap
//!   ([`expand_entities`]), both functions of the current rules alone, so an incremental build
//!   and a build from scratch agree.
//!
//! **Rewrite order.** urlfilter orders a query's matching rewrites by where it files each rule,
//! which depends on every network rule before it in the bundle. When no two of the bundle's
//! rewrite rules can match one query, the order can't change a decision, and each rewrite takes
//! its rank among the rewrites (cheap: no bundle-wide pass). Otherwise the compiler streams the
//! whole bundle in bundle order through [`picket_rules::order::OrderFiler`] and takes urlfilter's
//! exact filing.

use std::collections::{BTreeSet, HashMap, HashSet};

use picket_bundle::compile::CompiledPattern;
use picket_bundle::head::IpPatternClass;
use picket_bundle::patterns::PatternAdmit;
use picket_bundle::runs::IpRuleInput;
use picket_rules::badfilter::{BadfilterEffect, effective_rich, resolve};
use picket_rules::compile::{KeyValue, can_match_ip_text};
use picket_rules::entity::{EntityExpander, EntityTable, MAX_ENTITIES_PER_BUNDLE};
use picket_rules::flags::Level;
use picket_rules::matcher::{BundleAction, PatternAdmission, pattern_admission};
use picket_rules::order::MatchOrder;
use picket_rules::rule::{Folded, RichRule};
use picket_rules::{Flags, Kind, Rule, RuleType};

use super::source::{OrderKey, Row, domain_key};

/// What every part of one build compiles against.
#[derive(Clone, Debug, Default)]
pub struct BundleWide {
    pub action: Action,
    /// The `$dnsrewrite` rules' orders, by their place in bundle order.
    pub orders: HashMap<OrderKey, MatchOrder>,
    /// True when the orders are urlfilter's exact filing (two rewrites can match one query).
    pub exact_orders: bool,
    /// The expanded entities `rich.json` carries.
    pub entities: EntityTable,
    /// Rules whose entities didn't fit the cap: left out (core counts them and raises
    /// `bundle_warning`).
    pub refused: HashSet<OrderKey>,
    /// The domain keys of the entity rules (recomputed by every build).
    pub entity_keys: Vec<String>,
}

/// picket-rules' action, wrapped so [`BundleWide`] can default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action(pub BundleAction);

impl Default for Action {
    fn default() -> Self {
        Action(BundleAction::Block)
    }
}

/// Counters a compile adds to a build's stats.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompileCounts {
    /// Rules removed by `$badfilter`.
    pub badfiltered: u64,
    /// Rules left out because their entities didn't fit.
    pub entity_refused: u64,
    /// Rich rules naming an entity the table lacks (they apply to nothing).
    pub unlinked: u64,
}

fn has_entities(r: &RichRule) -> bool {
    !r.denyallow_entities.is_empty() || r.unless.iter().any(|s| !s.denyallow_entities.is_empty())
}

/// A rule's effective rich rule after `$badfilter`, rewrite order and entities: `None` when it
/// doesn't take part, `Some(None)` for a plain rule, `Some(Some(rich))` for a rich one.
fn effective(
    wide: &BundleWide,
    row: &Row,
    effect: &BadfilterEffect,
    counts: &mut CompileCounts,
) -> Option<Option<RichRule>> {
    let r = &row.rule;
    if r.kind.is_browser() || r.rule_type == RuleType::Browser {
        return None;
    }
    if wide.action.0 == BundleAction::Scope && r.rule_type != RuleType::Dns {
        return None;
    }
    // A `$badfilter` rule takes part only as a rewrite (AdGuard computes rewrites without it).
    let mut rich = if r.is_badfilter() {
        if !r.is_rewrite() {
            return None;
        }
        r.rich()
    } else {
        match effective_rich(r, effect) {
            Some(x) => x,
            None => {
                counts.badfiltered += 1;
                return None;
            }
        }
    };
    if let Some(rr) = rich.as_mut() {
        if r.is_rewrite() {
            rr.order = Some(wide.orders.get(&row.order).copied().unwrap_or(MatchOrder {
                gram: None,
                seq: u32::MAX,
            }));
        }
        if has_entities(rr) {
            if wide.refused.contains(&row.order) {
                counts.entity_refused += 1;
                return None;
            }
            if !wide.entities.link(rr) {
                counts.unlinked += 1;
            }
        }
    }
    Some(rich)
}

/// Folds one domain key's rules (in bundle order) into its value; `None` when no rule takes
/// part (every one removed or none left).
pub fn compile_key(wide: &BundleWide, rows: &[Row], counts: &mut CompileCounts) -> Option<KeyValue> {
    let rules: Vec<Rule> = rows.iter().map(|r| r.rule.clone()).collect();
    let effects = resolve(&rules);
    let mut kv = KeyValue::default();
    let mut any = false;
    for (i, row) in rows.iter().enumerate() {
        let effect = effects.get(i).cloned().unwrap_or(BadfilterEffect::Kept);
        let Some(rich) = effective(wide, row, &effect, counts) else {
            continue;
        };
        let Some(key) = domain_key(&row.rule) else {
            continue;
        };
        let folded = match rich {
            Some(rr) => Folded {
                key,
                flags: Flags::HAS_RICH,
                rich: Some(rr),
            },
            None => Folded {
                key,
                flags: row.rule.flags.and(Flags::ALL_LEVELS),
                rich: None,
            },
        };
        kv.add(folded);
        any = true;
    }
    any.then_some(kv)
}

/// The bundle's patterns, compiled with the reference's admission.
pub struct Patterns {
    pub patterns: Vec<CompiledPattern>,
    pub admission: PatternAdmission,
    /// Indices into the rows given (for alerts).
    pub rows: Vec<Row>,
}

/// The digest a pattern admission is cached under: the pattern rows in bundle order, the action
/// and the budget.
pub fn admission_digest(action: BundleAction, rows: &[Row], budget: usize) -> String {
    let mut s = format!("{action:?}|{budget}\n");
    for r in rows {
        s.push_str(&format!("{:?}\n", r.order));
    }
    picket_api::ids::object_id(s.as_bytes())
}

/// Compiles every pattern rule (rows in bundle order) as picket-bundle's compiler does; `cached`
/// is the reference's admission of exactly these rows, if known.
pub fn compile_patterns(
    wide: &BundleWide,
    rows: Vec<Row>,
    budget: usize,
    counts: &mut CompileCounts,
    cached: Option<PatternAdmission>,
) -> Patterns {
    let rules: Vec<Rule> = rows.iter().map(|r| r.rule.clone()).collect();
    let effects = resolve(&rules);
    let mut patterns = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let effect = effects.get(i).cloned().unwrap_or(BadfilterEffect::Kept);
        let Some(rich) = effective(wide, row, &effect, counts) else {
            continue;
        };
        let r = &row.rule;
        if !matches!(r.key_kind(), Kind::Pattern | Kind::Regex) {
            continue;
        }
        let Some(mut spec) = r.pattern_spec() else {
            continue;
        };
        let exact = r.flags.exact().union(r.flags.subs_as_exact());
        match rich {
            Some(mut rr) => {
                rr.flags = exact;
                spec.flags = Flags::HAS_RICH;
                spec.rich = Some(rr);
            }
            None => {
                spec.flags = exact;
                spec.rich = None;
            }
        }
        patterns.push(CompiledPattern {
            rule: i,
            spec,
            admit: PatternAdmit::Free,
        });
    }
    // The reference's admission over its own pattern list (badfiltered and entity-refused rules
    // included, as it holds them).
    let adm = cached.unwrap_or_else(|| pattern_admission(wide.action.0, &rules, budget));
    let resident: HashMap<usize, usize> = adm.resident.iter().copied().collect();
    let over: HashSet<usize> = adm.over_budget.iter().copied().collect();
    let large: HashSet<usize> = adm.too_large.iter().copied().collect();
    for p in patterns.iter_mut() {
        p.admit = if let Some(&cost) = resident.get(&p.rule) {
            PatternAdmit::Resident { cost }
        } else if over.contains(&p.rule) {
            PatternAdmit::OverBudget
        } else if large.contains(&p.rule) {
            PatternAdmit::TooLarge
        } else {
            PatternAdmit::Free
        };
    }
    Patterns {
        patterns,
        admission: adm,
        rows,
    }
}

/// Compiles every IP rule (rows in bundle order) into the inputs runs fold from.
pub fn compile_ips(wide: &BundleWide, rows: &[Row], counts: &mut CompileCounts) -> Vec<IpRuleInput> {
    compile_ips_ordered(wide, rows, counts)
        .into_iter()
        .map(|(_, i)| i)
        .collect()
}

/// [`compile_ips`] with each input's place in bundle order. `$badfilter` only relates rules with
/// one identity (one range), so a group holding every rule of its ranges compiles as the whole
/// bundle would ([`super::ipfold`] compiles one range group at a time).
pub fn compile_ips_ordered(
    wide: &BundleWide,
    rows: &[Row],
    counts: &mut CompileCounts,
) -> Vec<(OrderKey, IpRuleInput)> {
    let rules: Vec<Rule> = rows.iter().map(|r| r.rule.clone()).collect();
    let effects = resolve(&rules);
    let mut out = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let effect = effects.get(i).cloned().unwrap_or(BadfilterEffect::Kept);
        let Some(rich) = effective(wide, row, &effect, counts) else {
            continue;
        };
        let r = &row.rule;
        if !matches!(r.key_kind(), Kind::IpLiteral | Kind::IpRange) {
            continue;
        }
        let Some(range) = r.ip_range() else { continue };
        let exact = r.flags.exact().union(r.flags.subs_as_exact());
        out.push((
            row.order.clone(),
            match rich {
                Some(mut rr) => {
                    rr.flags = exact;
                    IpRuleInput {
                        range,
                        flags: Flags::NONE,
                        rich: Some(rr),
                    }
                }
                None => IpRuleInput {
                    range,
                    flags: exact,
                    rich: None,
                },
            },
        ));
    }
    out
}

/// The IP-text pattern classes of the rules given (rules.md §6; bundles.md §6
/// `ip_pattern_classes`). Over-approximating (a removed rule may still count) only turns the
/// edge's IPv4 fast path off.
pub fn ip_pattern_classes<'a>(rows: impl Iterator<Item = &'a Row>) -> Vec<IpPatternClass> {
    let mut classes = BTreeSet::new();
    for row in rows {
        let r = &row.rule;
        if r.kind.is_browser() || (r.is_badfilter() && !r.is_rewrite()) {
            continue;
        }
        if !can_match_ip_text(r) {
            continue;
        }
        classes.insert(if r.is_rewrite() {
            IpPatternClass::Rewrite
        } else if r.is_mapping() {
            IpPatternClass::Mapping
        } else {
            match r.level() {
                Some(Level::ImportantAllow) => IpPatternClass::ImportantAllow,
                Some(Level::ImportantBlock) => IpPatternClass::Important,
                Some(Level::Allow) => IpPatternClass::Allow,
                _ => IpPatternClass::Block,
            }
        });
    }
    classes.into_iter().collect()
}

/// Every IP-text pattern class (over-approximating: the edge's IPv4 fast path stays off).
pub fn all_ip_pattern_classes() -> Vec<IpPatternClass> {
    vec![
        IpPatternClass::ImportantAllow,
        IpPatternClass::Important,
        IpPatternClass::Allow,
        IpPatternClass::Block,
        IpPatternClass::Rewrite,
        IpPatternClass::Mapping,
    ]
}

/// True when two of the bundle's rewrite rules may match one query, so their order can change a
/// decision: two at one key, one at a key and one below it with a subdomain flag, or any pattern
/// or IP rewrite next to another rewrite (not analysed: assumed to overlap).
pub fn rewrites_may_overlap(rewrites: &[Row]) -> bool {
    if rewrites.len() < 2 {
        return false;
    }
    let mut keyed: Vec<(String, bool)> = Vec::new();
    for r in rewrites {
        match r.rule.key_kind() {
            Kind::Name | Kind::HostMapping => {
                keyed.push((r.rule.key.clone(), r.rule.flags.intersects(Flags::ALL_SUBS)))
            }
            _ => return true,
        }
    }
    keyed.sort();
    let subs: HashSet<&str> = keyed
        .iter()
        .filter(|(_, s)| *s)
        .map(|(k, _)| k.as_str())
        .collect();
    let mut seen: HashSet<&str> = HashSet::new();
    for (k, _) in &keyed {
        if !seen.insert(k.as_str()) {
            return true;
        }
        let mut s: &str = k;
        while let Some(i) = s.rfind('.') {
            s = &s[..i];
            if subs.contains(s) {
                return true;
            }
        }
    }
    false
}

/// The rank orders: each rewrite rule's place among the bundle's rewrites, unindexed (used when
/// no two can match one query, [`rewrites_may_overlap`]).
pub fn rank_orders(rewrites: &[Row]) -> HashMap<OrderKey, MatchOrder> {
    rewrites
        .iter()
        .enumerate()
        .map(|(i, r)| {
            (
                r.order.clone(),
                MatchOrder {
                    gram: None,
                    seq: u32::try_from(i).unwrap_or(u32::MAX),
                },
            )
        })
        .collect()
}

/// Expands the `$denyallow` entities of `candidates` (the rules whose effective rich rule names
/// one, in bundle order) within the per-bundle cap: the table and the refused rules.
pub fn expand_entities(
    psl: &picket_rules::psl::PublicSuffixList,
    candidates: &mut [(OrderKey, RichRule)],
) -> (EntityTable, HashSet<OrderKey>) {
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    let mut x = EntityExpander::new(psl, MAX_ENTITIES_PER_BUNDLE);
    let mut refused = HashSet::new();
    for (k, rr) in candidates.iter_mut() {
        if !x.expand(rr) {
            refused.insert(k.clone());
        }
    }
    (x.table(), refused)
}

/// The rules of a group whose effective rich rule names an entity (with orders not yet set:
/// entities don't depend on them).
pub fn entity_candidates(action: BundleAction, rows: &[Row]) -> Vec<(OrderKey, RichRule)> {
    let rules: Vec<Rule> = rows.iter().map(|r| r.rule.clone()).collect();
    let effects = resolve(&rules);
    let mut out = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let r = &row.rule;
        if r.kind.is_browser() || r.rule_type == RuleType::Browser {
            continue;
        }
        if action == BundleAction::Scope && r.rule_type != RuleType::Dns {
            continue;
        }
        let effect = effects.get(i).cloned().unwrap_or(BadfilterEffect::Kept);
        let rich = if r.is_badfilter() {
            if !r.is_rewrite() {
                continue;
            }
            r.rich()
        } else {
            match effective_rich(r, &effect) {
                Some(x) => x,
                None => continue,
            }
        };
        if let Some(rr) = rich
            && has_entities(&rr)
        {
            out.push((row.order.clone(), rr));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_rules::classify::{Item, Line, classify_adblock_line};

    fn rows(lines: &[&str]) -> Vec<Row> {
        let mut out = Vec::new();
        for (n, l) in lines.iter().enumerate() {
            if let Line::Items(v) = classify_adblock_line(l, false) {
                for it in v {
                    if let Item::Rule(r) = it {
                        out.push(Row {
                            order: OrderKey {
                                position: 0,
                                line_no: n as i64 + 1,
                                rule_type: r.rule_type.as_str(),
                                kind: r.kind.as_str(),
                                key: r.key.clone(),
                                flags: r.flags.bits(),
                                value_json: r.value_json(),
                            },
                            feed: "f".into(),
                            rule: r,
                            first_seen_at: String::new(),
                            entry_id: n as i64,
                        });
                    }
                }
            }
        }
        out
    }

    #[test]
    fn key_folds_forms_and_resolves_badfilter() {
        let wide = BundleWide::default();
        let mut c = CompileCounts::default();
        let kv = compile_key(
            &wide,
            &rows(&["||example.org^", "|example.org^$important"]),
            &mut c,
        )
        .unwrap();
        assert!(
            kv.flags
                .contains(Flags::B_EXACT | Flags::B_SUBS | Flags::IMP_B_EXACT)
        );
        assert!(
            compile_key(
                &wide,
                &rows(&["||example.org^", "||example.org^$badfilter"]),
                &mut c
            )
            .is_none()
        );
        assert_eq!(c.badfiltered, 1);
        let kv = compile_key(&wide, &rows(&["||rw.example^$dnsrewrite=1.2.3.4"]), &mut c).unwrap();
        assert!(kv.flags.contains(Flags::HAS_RICH));
    }

    /// The stepped admission (`super::assemble::Admitting`) gives the reference's
    /// `pattern_admission`, a few patterns per step, past the budget too (CR2).
    #[test]
    fn stepped_admission_equals_the_reference() {
        let mut lines: Vec<String> = vec![
            "||ads*.example^".into(),
            "/track[0-9]+/".into(),
            "||*^".into(),
            "||x*.example^$badfilter".into(),
            "@@||ok*.example^".into(),
            "||plain.example^".into(),
            "/(a|b|c|d|e|f|g){5,40}z{2,30}/".into(),
        ];
        for i in 0..300 {
            lines.push(format!("/[a-z]{{{}}}x[0-9]{{1,{}}}/", 3 + i % 50, 2 + i % 40));
            lines.push(format!("||ad{i}*.example^"));
        }
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let r = rows(&refs);
        let rules: Vec<Rule> = r.iter().map(|x| x.rule.clone()).collect();
        for (budget, per) in [(1 << 20, 3usize), (64 << 10, 7), (32 << 20, 1000), (4 << 10, 1)] {
            let want = pattern_admission(BundleAction::Block, &rules, budget);
            let mut a = super::super::assemble::Admitting::new(BundleAction::Block, budget);
            while !a.step(&rules, per) {}
            let got = a.finish();
            assert_eq!(got.resident, want.resident, "budget {budget}");
            assert_eq!(got.over_budget, want.over_budget, "budget {budget}");
            assert_eq!(got.too_large, want.too_large, "budget {budget}");
        }
    }

    #[test]
    fn rewrite_overlap() {
        assert!(!rewrites_may_overlap(&rows(&[
            "||use-application-dns.net^$dnsrewrite=NXDOMAIN;;",
            "||mask.icloud.com^$dnsrewrite=NXDOMAIN;;",
            "||mask-h2.icloud.com^$dnsrewrite=NXDOMAIN;;",
        ])));
        assert!(rewrites_may_overlap(&rows(&[
            "||example.org^$dnsrewrite=1.2.3.4",
            "||a.example.org^$dnsrewrite=NXDOMAIN;;",
        ])));
        assert!(rewrites_may_overlap(&rows(&[
            "|example.org^$dnsrewrite=1.2.3.4",
            "|example.org^$dnsrewrite=1.2.3.5",
        ])));
        assert!(!rewrites_may_overlap(&rows(&[
            "|example.org^$dnsrewrite=1.2.3.4",
            "|a.example.org^$dnsrewrite=1.2.3.5",
        ])));
    }
}
