//! Per-edge bundle heads within the edge's memory budgets (bundles.md §2 "Budget", §5; edge.md
//! §17), the seam [`crate::edges::publish`] renders through. Both budgets are checked at every
//! publish against what the edge would run ([`resolve`]):
//!
//! - **`bundle_budget_mib`** is a per-edge total across all bundles: each head's in-memory size
//!   (hot part, IP shards, segments, cold filters) plus its overlays, from the version's stats.
//! - **`overlay_budget_mib`** is the per-edge total of the heads' overlays (hot, cold and IP) plus
//!   the verdict sets' (core.md §7: every edge names every `sync` provider's set; their overlay
//!   bytes come from `crate::lookups::verdict_sets`, which compacts its own sets the same way when
//!   it publishes a delta).
//! - A head that would push the edge past either isn't named: the edge keeps the head its current
//!   config names (the bundles whose new head grew most go first), and `bundle_over_budget` names
//!   the edge and the bundle.
//! - When that isn't enough (a config change added a bundle, or the edge's budgets were lowered
//!   below what it runs), the whole object holds: the edge keeps its current config, later config
//!   changes for it wait too, and the alert says changes are waiting ([`Resolved::hold`]). An edge
//!   with no config yet gets one without the bundles that don't fit (largest first).
//! - **Compaction** (bundles.md §5): while the heads the edge should run pass its overlay budget,
//!   the parts with the largest overlays are requested until they would fit: a bundle part as its
//!   bundle's compaction build ([`Resolved::compact`]), a verdict set as a new base of that set
//!   ([`Resolved::rebase_sets`]), chosen by size like any part; the rebuilt heads carry no
//!   overlay there.
//! - Before publishing, a build also rebuilds the largest overlays first while the edge's overlays
//!   after it would pass the budget: its own parts in the build, another bundle's as that
//!   bundle's compaction build ([`overlay_edges`], `super::assemble`).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use super::store::HeadSize;
use crate::state::SharedState;

const MIB: u64 = 1024 * 1024;

/// One edge's budgets, in bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Budgets {
    /// `bundle_budget_mib`.
    pub bundle: u64,
    /// `overlay_budget_mib`.
    pub overlay: u64,
    /// Overlay bytes on the edge besides the bundles' and the verdict sets'.
    pub fixed_overlay: u64,
    /// Each verdict set's overlay on the edge (provider → bytes, as far as core knows them): part
    /// of the overlay total, and a compaction candidate like a bundle part (a new base).
    pub sets: BTreeMap<String, u64>,
}

impl Budgets {
    pub fn of_mib(bundle_mib: u32, overlay_mib: u32) -> Budgets {
        Budgets {
            bundle: u64::from(bundle_mib).saturating_mul(MIB),
            overlay: u64::from(overlay_mib).saturating_mul(MIB),
            fixed_overlay: 0,
            sets: BTreeMap::new(),
        }
    }
}

/// One edge's bundle heads after its budgets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    pub heads: BTreeMap<String, String>,
    /// Bundles kept on the edge's current head, or (with `hold`, or with no config yet) kept out:
    /// (bundle, kept head or "", wanted head).
    pub kept: Vec<(String, String, String)>,
    /// The edge keeps its whole current config: a bundle new to it doesn't fit, or its budgets
    /// were lowered below what it runs (the bundle named first in the alert).
    pub hold: Option<String>,
    /// The total the named heads take, and the budget.
    pub total: u64,
    pub budget: u64,
    /// The overlays the named heads (and the fixed share) take, and the overlay budget.
    pub overlay: u64,
    pub overlay_budget: u64,
    /// Parts of the current heads to rebuild as bases so the heads the edge should run fit its
    /// overlay budget (bundle → part ids, `super::assemble::part_id`), largest overlay first.
    pub compact: BTreeMap<String, BTreeSet<String>>,
    /// Verdict sets whose base to rebuild for the same reason (providers), chosen with the parts.
    pub rebase_sets: BTreeSet<String>,
}

/// Picks `edge`'s heads: the current head of each bundle it needs, unless that would pass one of
/// its budgets (see the module docs). `named` is what its current config names; `parts` holds the
/// current heads' parts with an overlay (bundle → (part id, bytes)).
pub fn resolve(
    budgets: &Budgets,
    needed: &BTreeSet<String>,
    current: &BTreeMap<String, String>,
    named: Option<&BTreeMap<String, String>>,
    sizes: &BTreeMap<String, HeadSize>,
    parts: &BTreeMap<String, Vec<(String, u64)>>,
) -> Resolved {
    let size = |h: &str| sizes.get(h).map_or(0, HeadSize::total);
    let ov = |h: &str| sizes.get(h).map_or(0, |s| s.overlay_bytes);
    let total = |heads: &BTreeMap<String, String>| heads.values().map(|h| size(h)).sum::<u64>();
    let overlay = |heads: &BTreeMap<String, String>| {
        heads
            .values()
            .map(|h| ov(h))
            .sum::<u64>()
            .saturating_add(budgets.fixed_overlay)
            .saturating_add(budgets.sets.values().fold(0u64, |a, b| a.saturating_add(*b)))
    };
    let bundle_over = |heads: &BTreeMap<String, String>| total(heads) > budgets.bundle;
    let overlay_over = |heads: &BTreeMap<String, String>| overlay(heads) > budgets.overlay;
    let fits = |heads: &BTreeMap<String, String>| !bundle_over(heads) && !overlay_over(heads);
    let mut heads: BTreeMap<String, String> = needed
        .iter()
        .filter_map(|b| current.get(b).map(|h| (b.clone(), h.clone())))
        .collect();
    let mut out = Resolved {
        budget: budgets.bundle,
        overlay_budget: budgets.overlay,
        ..Resolved::default()
    };
    // The heads the edge should run pass its overlay budget: compact the largest overlays first
    // until they would fit (bundles.md §5), bundle parts and verdict sets alike.
    if overlay_over(&heads) {
        // (bytes, the bundle or None for a verdict set, the part id or the provider)
        let mut cands: Vec<(u64, Option<&String>, &String)> = heads
            .keys()
            .flat_map(|b| {
                parts
                    .get(b)
                    .into_iter()
                    .flatten()
                    .filter(|(_, n)| *n > 0)
                    .map(move |(p, n)| (*n, Some(b), p))
            })
            .collect();
        cands.extend(
            budgets
                .sets
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(p, n)| (*n, None, p)),
        );
        cands.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)).then(x.2.cmp(y.2)));
        let mut left = overlay(&heads);
        for (n, b, p) in cands {
            if left <= budgets.overlay {
                break;
            }
            match b {
                Some(b) => {
                    out.compact.entry(b.clone()).or_default().insert(p.clone());
                }
                None => {
                    out.rebase_sets.insert(p.clone());
                }
            }
            left = left.saturating_sub(n);
        }
    }
    let finish = |mut out: Resolved, heads: BTreeMap<String, String>| {
        out.total = total(&heads);
        out.overlay = overlay(&heads);
        out.heads = heads;
        out
    };
    if fits(&heads) {
        return finish(out, heads);
    }
    // How much a bundle's head adds in the dimensions that are over.
    let excess = |heads: &BTreeMap<String, String>, h: &str, was: Option<&str>| {
        let mut d = 0u64;
        if bundle_over(heads) {
            d = d.saturating_add(size(h).saturating_sub(was.map_or(0, &size)));
        }
        if overlay_over(heads) {
            d = d.saturating_add(ov(h).saturating_sub(was.map_or(0, &ov)));
        }
        d
    };
    // Keep the edge's current head for the bundles that grew most, until it fits.
    if let Some(n) = named {
        let mut grown: Vec<(u64, String)> = heads
            .iter()
            .filter_map(|(b, h)| {
                let old = n.get(b).filter(|o| *o != h)?;
                Some((excess(&heads, h, Some(old)), b.clone()))
            })
            .filter(|(d, _)| *d > 0)
            .collect();
        grown.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        for (_, b) in grown {
            if fits(&heads) {
                break;
            }
            let (Some(old), Some(wanted)) = (n.get(&b), heads.get(&b).cloned()) else {
                continue;
            };
            heads.insert(b.clone(), old.clone());
            out.kept.push((b, old.clone(), wanted));
        }
        if fits(&heads) {
            return finish(out, heads);
        }
        // Still over: a bundle new to the edge, or budgets lowered below what it runs. The edge
        // keeps its whole current config; the alert names the bundles that don't fit, a new one
        // first, then the largest.
        let mut blame: Vec<(bool, u64, String)> = heads
            .iter()
            .map(|(b, h)| (n.contains_key(b), excess(&heads, h, None), b.clone()))
            .collect();
        blame.sort_by(|x, y| x.0.cmp(&y.0).then(y.1.cmp(&x.1)).then(x.2.cmp(&y.2)));
        let mut probe = heads.clone();
        for (_, _, b) in blame {
            if fits(&probe) {
                break;
            }
            let wanted = current.get(&b).cloned().unwrap_or_default();
            let kept = n.get(&b).cloned().unwrap_or_default();
            probe.remove(&b);
            if !out.kept.iter().any(|k| k.0 == b) {
                out.kept.push((b.clone(), kept, wanted));
            }
            out.hold.get_or_insert(b);
        }
        if out.hold.is_none() {
            // Nothing to blame (only a fixed share passes the overlay budget): hold anyway.
            out.hold = heads.keys().next().cloned();
        }
        return finish(out, heads);
    }
    // No config yet: leave out the bundles that add most, until it fits.
    loop {
        if fits(&heads) {
            break;
        }
        let worst = heads
            .iter()
            .map(|(b, h)| (excess(&heads, h, None), b.clone()))
            .max_by(|x, y| x.0.cmp(&y.0).then(y.1.cmp(&x.1)));
        let Some((_, b)) = worst else { break };
        if let Some(h) = heads.remove(&b) {
            out.kept.push((b, String::new(), h));
        }
    }
    finish(out, heads)
}

/// One edge carrying a bundle, as its build's overlay compaction sees it (bundles.md §5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OverlayEdge {
    pub edge: String,
    /// `overlay_budget_mib` in bytes.
    pub budget: u64,
    /// Overlay bytes on the edge no part-by-part rebuild can lower: other heads the edge is kept
    /// on (not their bundle's current head).
    pub fixed: u64,
    /// The verdict sets' overlays (provider, bytes; core.md §7): compaction candidates like the
    /// other bundles' parts, rebuilt as new bases by the verdict-set publisher.
    pub sets: Vec<(String, u64)>,
    /// The other bundles' parts with an overlay, of heads that are their bundle's current one:
    /// (bundle, part id as [`super::assemble::part_id`] writes it, bytes).
    pub parts: Vec<(String, String, u64)>,
}

/// Every edge with a config that carries `bundle`, with its overlay budget and the overlays of
/// the other heads its config names (none when no edge carries it).
pub async fn overlay_edges(state: &SharedState, bundle: &str) -> Result<Vec<OverlayEdge>> {
    let model = state.config.model().await?;
    if !crate::edges::render::edge_bundles(&model).contains(bundle) {
        return Ok(Vec::new());
    }
    /// (edge, budget, the other heads its config names as (bundle, head)).
    type Named = (String, u64, Vec<(String, String)>);
    let mut named: Vec<Named> = Vec::new();
    for (id, edge) in &model.edges {
        let Some(p) = state.edges.publisher.current(id) else {
            continue;
        };
        let others: Vec<(String, String)> = p
            .config
            .bundles
            .iter()
            .filter(|(b, _)| b.as_str() != bundle)
            .map(|(b, h)| (b.clone(), h.clone()))
            .collect();
        let budget = u64::from(edge.settings.overlay_budget(edge.platform)).saturating_mul(MIB);
        named.push((id.clone(), budget, others));
    }
    if named.is_empty() {
        return Ok(Vec::new());
    }
    let all: Vec<(String, String)> = named.iter().flat_map(|(_, _, v)| v.iter().cloned()).collect();
    let (sizes, current, parts, sets) = state
        .db
        .read(move |c| {
            let sizes = super::store::head_sizes(c, &all)?;
            let current = super::store::current_heads(c)?;
            let bundles: BTreeSet<&String> = all.iter().map(|(b, _)| b).collect();
            let parts = super::store::overlay_parts(c, bundles.into_iter())?;
            let sets: Vec<(String, u64)> = crate::lookups::verdict_sets::overlay_bytes(c)?
                .into_iter()
                .filter(|(_, b)| *b > 0)
                .collect();
            Ok::<_, anyhow::Error>((sizes, current, parts, sets))
        })
        .await?;
    Ok(named
        .into_iter()
        .map(|(edge, budget, others)| {
            let mut e = OverlayEdge {
                edge,
                budget,
                sets: sets.clone(),
                ..OverlayEdge::default()
            };
            for (b, h) in others {
                if current.get(&b) == Some(&h) {
                    for (pid, bytes) in parts.get(&b).cloned().unwrap_or_default() {
                        e.parts.push((b.clone(), pid, bytes));
                    }
                } else {
                    e.fixed += sizes.get(&h).map_or(0, |s| s.overlay_bytes);
                }
            }
            e
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sz(m: u64) -> HeadSize {
        HeadSize {
            mem_bytes: m * MIB,
            overlay_bytes: 0,
        }
    }

    fn ovl(m: u64, o: u64) -> HeadSize {
        HeadSize {
            mem_bytes: m * MIB,
            overlay_bytes: o * MIB,
        }
    }

    fn b(mib: u32) -> Budgets {
        Budgets::of_mib(mib, 4)
    }

    #[test]
    fn keeps_the_current_head_or_holds_a_new_bundle() {
        let none = BTreeMap::new();
        let needed: BTreeSet<String> = ["a".into(), "b".into()].into();
        let current: BTreeMap<String, String> = [("a".into(), "a2".into()), ("b".into(), "b1".into())].into();
        let sizes: BTreeMap<String, HeadSize> =
            [("a1".into(), sz(10)), ("a2".into(), sz(30)), ("b1".into(), sz(5))].into();
        // Fits.
        let r = resolve(&b(64), &needed, &current, None, &sizes, &none);
        assert_eq!(r.heads, current);
        assert!(r.kept.is_empty() && r.hold.is_none());
        // a2 doesn't fit: the edge keeps a1.
        let named: BTreeMap<String, String> = [("a".into(), "a1".into()), ("b".into(), "b1".into())].into();
        let r = resolve(&b(20), &needed, &current, Some(&named), &sizes, &none);
        assert_eq!(r.heads.get("a").map(String::as_str), Some("a1"));
        assert_eq!(r.kept, vec![("a".into(), "a1".into(), "a2".into())]);
        assert!(r.hold.is_none());
        // b is new to the edge and doesn't fit: the whole object holds.
        let named: BTreeMap<String, String> = [("a".into(), "a2".into())].into();
        let r = resolve(&b(32), &needed, &current, Some(&named), &sizes, &none);
        assert_eq!(r.hold.as_deref(), Some("b"));
        // An edge with no config yet gets one without the bundle that adds most.
        let r = resolve(&b(32), &needed, &current, None, &sizes, &none);
        assert!(r.hold.is_none() && !r.heads.contains_key("a") && r.heads.contains_key("b"));
        // A budget lowered below what the edge runs: the whole object holds, naming the largest.
        let named: BTreeMap<String, String> = [("a".into(), "a2".into()), ("b".into(), "b1".into())].into();
        let r = resolve(&b(16), &needed, &current, Some(&named), &sizes, &none);
        assert_eq!(r.hold.as_deref(), Some("a"));
        assert_eq!(r.kept, vec![("a".into(), "a2".into(), "a2".into())]);
    }

    #[test]
    fn the_overlay_budget_holds_and_asks_for_compaction() {
        let needed: BTreeSet<String> = ["a".into(), "b".into()].into();
        let current: BTreeMap<String, String> = [("a".into(), "a2".into()), ("b".into(), "b1".into())].into();
        let sizes: BTreeMap<String, HeadSize> = [
            ("a1".into(), ovl(10, 1)),
            ("a2".into(), ovl(10, 3)),
            ("b1".into(), ovl(5, 2)),
        ]
        .into();
        let parts: BTreeMap<String, Vec<(String, u64)>> = [
            ("a".into(), vec![("hot/0".into(), 2 * MIB), ("hot/1".into(), MIB)]),
            ("b".into(), vec![("ip/v4/1".into(), 2 * MIB)]),
        ]
        .into();
        // 5 MiB of overlays against 4: a2 grew by 2 MiB over a1, so the edge keeps a1; the
        // largest part is asked for compaction.
        let named: BTreeMap<String, String> = [("a".into(), "a1".into()), ("b".into(), "b1".into())].into();
        let r = resolve(&b(64), &needed, &current, Some(&named), &sizes, &parts);
        assert_eq!(r.heads.get("a").map(String::as_str), Some("a1"));
        assert!(r.hold.is_none());
        assert_eq!(r.overlay, 3 * MIB);
        assert_eq!(
            r.compact,
            [("a".to_string(), ["hot/0".to_string()].into())].into(),
            "largest first, until it fits"
        );
        // A new edge: the bundle that adds most overlay stays out until compacted.
        let r = resolve(&b(64), &needed, &current, None, &sizes, &parts);
        assert!(!r.heads.contains_key("a") && r.heads.contains_key("b"));
        assert!(!r.compact.is_empty());
        // Fits once compacted.
        let sizes: BTreeMap<String, HeadSize> = [("a2".into(), ovl(10, 0)), ("b1".into(), ovl(5, 2))].into();
        let r = resolve(&b(64), &needed, &current, Some(&named), &sizes, &BTreeMap::new());
        assert_eq!(r.heads, current);
        assert!(r.kept.is_empty() && r.compact.is_empty());
    }

    /// L7 (bundles.md §5; core.md §7): a verdict set's overlay is a compaction candidate like any
    /// part, chosen by size: verdict sets alone past the budget ask for the largest set's new
    /// base (not a hold with nothing to compact), and a set larger than every bundle part goes
    /// first.
    #[test]
    fn verdict_sets_are_compacted_like_any_part() {
        let needed: BTreeSet<String> = ["a".into()].into();
        let current: BTreeMap<String, String> = [("a".into(), "a1".into())].into();
        let named = current.clone();
        let sizes: BTreeMap<String, HeadSize> = [("a1".into(), ovl(10, 1))].into();
        let parts: BTreeMap<String, Vec<(String, u64)>> = [("a".into(), vec![("hot/0".into(), MIB)])].into();
        let budgets = |sets: &[(&str, u64)]| Budgets {
            sets: sets.iter().map(|(p, n)| ((*p).to_string(), n * MIB)).collect(),
            ..b(64)
        };
        // 1 MiB of bundle overlay and 5 MiB of verdict sets against 4: the 4 MiB set goes first,
        // and is enough.
        let r = resolve(
            &budgets(&[("q9", 4), ("q2", 1)]),
            &needed,
            &current,
            Some(&named),
            &sizes,
            &parts,
        );
        assert_eq!(r.rebase_sets, ["q9".to_string()].into());
        assert!(r.compact.is_empty(), "{:?}", r.compact);
        // Sets alone past the budget, with no bundle overlay to compact.
        let sizes0: BTreeMap<String, HeadSize> = [("a1".into(), ovl(10, 0))].into();
        let r = resolve(
            &budgets(&[("q9", 3), ("q2", 3)]),
            &needed,
            &current,
            Some(&named),
            &sizes0,
            &BTreeMap::new(),
        );
        assert_eq!(
            r.rebase_sets.len(),
            1,
            "one rebase is enough: {:?}",
            r.rebase_sets
        );
        // Within the budget: nothing asked.
        let r = resolve(
            &budgets(&[("q9", 1)]),
            &needed,
            &current,
            Some(&named),
            &sizes,
            &parts,
        );
        assert!(r.rebase_sets.is_empty() && r.compact.is_empty());
    }
}
