//! `$badfilter` (rules.md §4: resolved at compile time across the whole bundle, removing only the
//! rules it targets) and the cross-feed cancellations core reports as `bundle_warning`
//! (bundles.md §2).
//!
//! A `$badfilter` rule targets rules as urlfilter's `negatesBadfilter` does: same exception-ness,
//! same pattern text (as urlfilter keeps it), same negated request types, same `$important`, and
//! equal `$client` and `$ctag` sets. urlfilter doesn't compare `$dnstype`, `$denyallow` or
//! `$dnsrewrite`, so `||d^$badfilter` also removes `||d^$dnstype=A`. Host rules, hosts lines and
//! `plain` names are never targets (they aren't network rules), and neither are `$dnsrewrite`
//! rules: AdGuard computes rewrites without `$badfilter`.
//!
//! urlfilter applies a `$badfilter` only to requests it matches itself. Its pattern, `$client` and
//! `$ctag` equal the target's, so the only difference is its own `$dnstype` and `$denyallow`: a
//! `$badfilter` with neither removes its targets; one with them suppresses its targets only for
//! the queries it matches ([`crate::rule::Suppressor`]).
//!
//! Deliberate difference: with two or more `$badfilter` rules matching one request, urlfilter's
//! `filterNegatedRules` keeps a rule unless *every* one of them negates it (a quirk that depends on
//! unrelated rules). Picket resolves each `$badfilter` on its own, as the spec says.

use std::collections::{BTreeMap, HashMap};

use crate::analysis::{Budget, Exhausted, KeyMatcher, Overlap, patterns_overlap};
use crate::flags::Flags;
use crate::modifiers::{ClientCond, TagCond};
use crate::rewrite::{RewriteCandidate, apply_rewrite_exceptions_by};
use crate::rule::{Kind, PatternSpec, Rule, Suppressor};

/// What `$badfilter` does to one rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BadfilterEffect {
    /// Untouched.
    Kept,
    /// Removed by these `$badfilter` rules (indices).
    Removed { by: Vec<usize> },
    /// Removed only for queries one of `unless` matches.
    Suppressed { by: Vec<usize>, unless: Vec<Suppressor> },
}

#[derive(Hash, PartialEq, Eq)]
struct Identity<'a> {
    exception: bool,
    important: bool,
    pattern: &'a str,
    not_types: &'a [String],
    client: Option<&'a ClientCond>,
    ctag: Option<&'a TagCond>,
}

fn identity(r: &Rule) -> Option<Identity<'_>> {
    Some(Identity {
        exception: r.is_exception(),
        important: r.is_important(),
        pattern: r.adguard_pattern()?,
        not_types: &r.spec.not_types,
        client: r.spec.client.as_ref(),
        ctag: r.spec.ctag.as_ref(),
    })
}

/// True when `rule` can be a `$badfilter` target.
pub fn is_target(rule: &Rule) -> bool {
    !rule.is_badfilter()
        && !rule.is_rewrite()
        && !rule.kind.is_browser()
        && !rule.spec.matches_nothing
        && !rule.spec.host_rule
        && rule.adguard_pattern().is_some()
}

/// Resolves every `$badfilter` rule of a bundle against the others. Index i of the result is the
/// effect on `rules[i]` (`Kept` for the `$badfilter` rules themselves).
pub fn resolve(rules: &[Rule]) -> Vec<BadfilterEffect> {
    let mut by_identity: HashMap<Identity<'_>, Vec<usize>> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        // A `$badfilter` applies only to requests it matches itself; a bare `^` never does.
        if r.is_badfilter()
            && !r.spec.matches_nothing
            && let Some(id) = identity(r)
        {
            by_identity.entry(id).or_default().push(i);
        }
    }
    rules
        .iter()
        .map(|r| {
            if !is_target(r) {
                return BadfilterEffect::Kept;
            }
            let Some(bs) = identity(r).and_then(|id| by_identity.get(&id)) else {
                return BadfilterEffect::Kept;
            };
            let sups: Vec<Suppressor> = bs
                .iter()
                .filter_map(|&b| rules.get(b))
                .map(Suppressor::of)
                .collect();
            if sups.iter().any(Suppressor::is_unconditional) {
                BadfilterEffect::Removed { by: bs.clone() }
            } else {
                BadfilterEffect::Suppressed {
                    by: bs.clone(),
                    unless: sups,
                }
            }
        })
        .collect()
}

/// Applies a resolution for the compiler: `None` for a removed rule; a rule whose removal is
/// conditional comes back with its [`crate::rule::RichRule`] carrying the suppressors (it then
/// folds as a rich rule).
pub fn effective_rich(rule: &Rule, effect: &BadfilterEffect) -> Option<Option<crate::rule::RichRule>> {
    match effect {
        BadfilterEffect::Kept => Some(rule.rich()),
        BadfilterEffect::Removed { .. } => None,
        BadfilterEffect::Suppressed { unless, .. } => {
            let mut rich = rule.rich().unwrap_or_else(|| crate::rule::RichRule {
                flags: rule.flags.and(Flags::ALL_LEVELS),
                ..crate::rule::RichRule::default()
            });
            rich.unless = unless.clone();
            Some(Some(rich))
        }
    }
}

/// How one rule cancels another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CancelKind {
    /// A `$badfilter` removes (or suppresses) the rule.
    Badfilter,
    /// An exception overrides the block for some name.
    Exception,
    /// `@@…$dnsrewrite` cancels the rewrite.
    RewriteException,
}

/// Cancelled rules a report names per canceller.
pub const CANCELLATION_SAMPLE: usize = 5;

/// The default work cap of one scan ([`Budget`] units: automaton transitions, keys and rule pairs
/// visited, and an automaton's NFA states for each one built and each DFA state a proof expands):
/// at most about two seconds of CPU on core; the AdGuard DNS filter with HaGeZi Pro takes ~1 %
/// of it. The spec leaves it open.
pub const DEFAULT_SCAN_WORK: u64 = 2_000_000_000;

/// The default bytes of pattern automata a scan keeps at once.
pub const DEFAULT_KEPT_BYTES: usize = 32 * 1024 * 1024;

/// Bounds of one cross-feed scan (README §2 "Bounded"; review round 2, CC3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanLimits {
    /// Work for the whole scan; past it the scan stops and reports what it couldn't check.
    pub work: u64,
    /// Bytes of pattern automata (lazy DFAs, each at most its NFA plus
    /// [`crate::analysis::OVERLAP_CACHE_BYTES`]) kept at once; patterns past it are taken in
    /// further passes.
    pub kept_bytes: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        ScanLimits {
            work: DEFAULT_SCAN_WORK,
            kept_bytes: DEFAULT_KEPT_BYTES,
        }
    }
}

/// One rule that cancels rules of other feeds of its bundle, aggregated (one `bundle_warning`
/// each, bundles.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancellerReport {
    pub kind: CancelKind,
    /// Index of the exception or `$badfilter` rule.
    pub canceller: usize,
    /// Rules of other feeds it was found to cancel (all of them unless the report is `capped`).
    pub count: u64,
    /// The first of them found, at most [`CANCELLATION_SAMPLE`].
    pub sample: Vec<usize>,
    /// False when the work cap stopped the scan before this rule was checked: it may cancel
    /// rules of other feeds, so it is reported rather than missed.
    pub proven: bool,
}

/// What [`cross_feed_cancellations`] found: at most one entry per exception or `$badfilter` rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CrossFeedReport {
    /// By canceller index.
    pub cancellers: Vec<CancellerReport>,
    /// The work cap stopped the scan: counts may be low, and the exceptions and `$badfilter`
    /// rules it didn't get to are listed unproven.
    pub capped: bool,
    /// Work spent.
    pub work: u64,
}

impl CrossFeedReport {
    /// The entry for `canceller`.
    pub fn get(&self, canceller: usize) -> Option<&CancellerReport> {
        self.cancellers
            .binary_search_by_key(&canceller, |c| c.canceller)
            .ok()
            .and_then(|i| self.cancellers.get(i))
    }

    /// True when `canceller` was found cancelling `cancelled` (as one of its sampled rules).
    pub fn sampled(&self, canceller: usize, cancelled: usize) -> bool {
        self.get(canceller).is_some_and(|c| c.sample.contains(&cancelled))
    }
}

#[derive(Default)]
struct Collector {
    by: BTreeMap<usize, CancellerReport>,
}

impl Collector {
    fn add(&mut self, kind: CancelKind, canceller: usize, cancelled: usize) {
        let e = self.by.entry(canceller).or_insert(CancellerReport {
            kind,
            canceller,
            count: 0,
            sample: Vec::new(),
            proven: true,
        });
        e.count = e.count.saturating_add(1);
        if e.sample.len() < CANCELLATION_SAMPLE {
            e.sample.push(cancelled);
        }
    }
}

/// Finds cancellations across feeds in one bundle (bundles.md §2 guardrail: "a cross-feed `@@` /
/// `$badfilter` cancellation"), within [`ScanLimits::default`]. `feeds[i]` is the feed of
/// `rules[i]`. See [`cross_feed_cancellations_within`].
pub fn cross_feed_cancellations<F: PartialEq>(rules: &[Rule], feeds: &[F]) -> CrossFeedReport {
    cross_feed_cancellations_within(rules, feeds, ScanLimits::default())
}

/// Finds cancellations across feeds in one bundle, aggregated per canceller (count and sample:
/// the output is bounded by the number of exception and `$badfilter` rules, not by keys ×
/// exceptions; review round 2, CC3).
///
/// Reported: every `$badfilter` target in another feed; keyed exceptions whose scope (the key, and
/// below it with a `_SUBS` flag) overlaps a lower-level block of another feed; a keyed exception
/// and a block pattern, or an exception pattern and a keyed block, of different feeds when the
/// pattern matches the key's name (`_EXACT`) or some name below it (`_SUBS`); an exception pattern
/// and a block pattern of different feeds that can both match one name; `@@…$dnsrewrite` rules
/// that cancel a rewrite of another feed at the same key or pattern.
///
/// The pattern tests are sound over ordinary names (rules.md §3 lists names with other bytes as an
/// exception): "the key's name" is decided without the patterns' conditions (a `$dnstype` or
/// `$client` exception cancels the block for the queries it matches; review round 2, CC6), "some
/// name below the key" and "one name" on the patterns' lazy automata over every ordinary text,
/// and a proof over its limits counts as an overlap. So nothing is missed, and a reported
/// cancellation may apply only to some names or queries (`@@/^foo\./` reaches every subtree:
/// `foo.<key>` is below any key).
///
/// Bounded: work is capped by `limits.work` (past it the scan stops, sets `capped` and lists the
/// rest of the exceptions and `$badfilter` rules unproven), and at most `limits.kept_bytes` of
/// pattern automata are held at once.
pub fn cross_feed_cancellations_within<F: PartialEq>(
    rules: &[Rule],
    feeds: &[F],
    limits: ScanLimits,
) -> CrossFeedReport {
    let mut c = Collector::default();
    let mut budget = Budget::new(limits.work);
    let mut done = Done::default();
    let capped = scan(rules, feeds, &limits, &mut c, &mut budget, &mut done).is_err();
    if capped {
        let several_feeds = feeds.first().is_some_and(|f0| feeds.iter().any(|f| f != f0));
        for (i, r) in rules.iter().enumerate() {
            if !several_feeds || r.kind.is_browser() || !(r.is_exception() || r.is_badfilter()) {
                continue;
            }
            // Kinds whose phase finished were checked in full.
            if (r.is_badfilter() && done.badfilter) || (r.is_rewrite() && done.rewrites) {
                continue;
            }
            c.by.entry(i).or_insert(CancellerReport {
                kind: if r.is_badfilter() {
                    CancelKind::Badfilter
                } else if r.is_rewrite() {
                    CancelKind::RewriteException
                } else {
                    CancelKind::Exception
                },
                canceller: i,
                count: 0,
                sample: Vec::new(),
                proven: false,
            });
        }
    }
    CrossFeedReport {
        cancellers: c.by.into_values().collect(),
        capped,
        work: budget.spent(),
    }
}

/// The scan's phases that finished.
#[derive(Default)]
struct Done {
    badfilter: bool,
    rewrites: bool,
}

fn scan<F: PartialEq>(
    rules: &[Rule],
    feeds: &[F],
    limits: &ScanLimits,
    c: &mut Collector,
    budget: &mut Budget,
    done: &mut Done,
) -> Result<(), Exhausted> {
    let feed = |i: usize| feeds.get(i);
    for (i, eff) in resolve(rules).iter().enumerate() {
        budget.spend(1)?;
        let by = match eff {
            BadfilterEffect::Removed { by } | BadfilterEffect::Suppressed { by, .. } => by,
            BadfilterEffect::Kept => continue,
        };
        for &b in by {
            if feed(b) != feed(i) {
                c.add(CancelKind::Badfilter, b, i);
            }
        }
    }
    done.badfilter = true;
    // Patterns that stand for a key on ordinary names.
    let eff: Vec<Option<(crate::name::RuleName, Flags)>> = rules.iter().map(keyed_equivalent).collect();
    let eff_keys: Vec<Option<String>> = eff
        .iter()
        .map(|e| e.as_ref().map(|(n, _)| n.reversed()))
        .collect();
    let flags_of = |i: usize| match eff.get(i) {
        Some(Some((_, f))) => *f,
        _ => rules.get(i).map_or(Flags::NONE, |r| r.flags),
    };
    // Keyed exceptions and blocks, by reversed key.
    let mut exceptions: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut keyed: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut rewrites_by_key: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        if r.is_badfilter() || r.kind.is_browser() {
            continue;
        }
        let key = match (eff_keys.get(i), r.kind) {
            (Some(Some(k)), _) => k.as_str(),
            (_, Kind::Name | Kind::HostMapping) => r.key.as_str(),
            (_, Kind::Pattern | Kind::Regex | Kind::IpLiteral) => r.key.as_str(),
            _ => continue,
        };
        if r.is_rewrite() {
            rewrites_by_key.entry(key).or_default().push(i);
            continue;
        }
        if r.is_exception() {
            exceptions.entry(key).or_default().push(i);
        } else {
            keyed.entry(key).or_default().push(i);
        }
    }
    // `@@…$dnsrewrite` against rewrites at the same key or pattern.
    for idx in rewrites_by_key.values() {
        budget.spend(u64::try_from(idx.len()).unwrap_or(u64::MAX))?;
        let cands: Vec<RewriteCandidate<'_>> = idx
            .iter()
            .filter_map(|&i| rules.get(i))
            .filter_map(|r| {
                r.spec.dnsrewrite.as_ref().map(|rw| RewriteCandidate {
                    rewrite: rw,
                    important: r.is_important(),
                    exception: r.is_exception(),
                })
            })
            .collect();
        if !cands.iter().any(|c| c.exception) {
            continue;
        }
        let (_, removed) = apply_rewrite_exceptions_by(&cands);
        for (rm, by) in removed {
            let (Some(&cancelled), Some(&canceller)) = (idx.get(rm), idx.get(by)) else {
                continue;
            };
            if feed(canceller) != feed(cancelled) {
                c.add(CancelKind::RewriteException, canceller, cancelled);
            }
        }
    }
    done.rewrites = true;
    for (key, eidx) in &exceptions {
        for &e in eidx {
            let Some(er) = rules.get(e) else { continue };
            let Some(elevel) = er.level() else { continue };
            let keyed_kind =
                matches!(er.kind, Kind::Name | Kind::IpLiteral) || eff.get(e).is_some_and(Option::is_some);
            let ef = flags_of(e);
            let mut check = |bidx: &Vec<usize>, overlap: &dyn Fn(Flags) -> bool| -> Result<(), Exhausted> {
                budget.spend(u64::try_from(bidx.len()).unwrap_or(u64::MAX))?;
                for &b in bidx {
                    let Some(br) = rules.get(b) else { continue };
                    if feed(b) == feed(e) || br.is_exception() {
                        continue;
                    }
                    if br.level().is_some_and(|bl| bl > elevel) && overlap(flags_of(b)) {
                        c.add(CancelKind::Exception, e, b);
                    }
                }
                Ok(())
            };
            // Same key (or same pattern).
            if let Some(bidx) = keyed.get(key) {
                let same = move |bf: Flags| {
                    !keyed_kind
                        || (ef.intersects(Flags::ALL_EXACT) && bf.intersects(Flags::ALL_EXACT))
                        || (ef.intersects(Flags::ALL_SUBS) && bf.intersects(Flags::ALL_SUBS))
                };
                check(bidx, &same)?;
            }
            if !keyed_kind {
                continue;
            }
            // Blocks at a parent with a subdomain flag cover the exception's key.
            let mut parent = *key;
            while let Some(i) = parent.rfind('.') {
                parent = parent.get(..i).unwrap_or("");
                if let Some(bidx) = keyed.get(parent) {
                    check(bidx, &|bf: Flags| bf.intersects(Flags::ALL_SUBS))?;
                }
            }
            // Blocks below the key, when the exception covers subdomains.
            if ef.intersects(Flags::ALL_SUBS) {
                let prefix = format!("{key}.");
                for (_, bidx) in keyed
                    .range::<str, _>((
                        std::ops::Bound::Excluded(prefix.as_str()),
                        std::ops::Bound::Unbounded,
                    ))
                    .take_while(|(k, _)| k.starts_with(&prefix))
                {
                    check(bidx, &|_| true)?;
                }
            }
        }
    }
    // Keyed rules against patterns, and patterns against patterns.
    keyed_pattern_cancellations(rules, &eff, feeds, limits, c, budget)
}

/// True when the cross-feed scan takes `r` as an exception pattern: an exception no key stands
/// for ([`keyed_equivalent_key`]), which cancels a keyed block of another feed by matching the
/// block's name or some name below it. It meets a keyed block only when the block is among the
/// rules scanned, so a caller scanning part of a bundle must give it every keyed block (or say
/// that it couldn't).
pub fn is_pattern_exception(r: &Rule) -> bool {
    r.is_exception()
        && !r.is_badfilter()
        && !r.is_rewrite()
        && !r.kind.is_browser()
        && matches!(r.kind, Kind::Pattern | Kind::Regex)
        && keyed_equivalent(r).is_none()
}

/// The reversed key a pattern rule stands for on ordinary names, with its forms (see
/// [`keyed_equivalent`]): the scan decides such a pattern as that key, so it meets the rules at
/// the key, above it and (with a `_SUBS` form) below it.
pub fn keyed_equivalent_key(r: &Rule) -> Option<(String, Flags)> {
    keyed_equivalent(r).map(|(n, f)| (n.reversed(), f))
}

/// The key a pattern rule stands for on ordinary names, with its forms: `||name^` and
/// `||name^|` match the name and its subdomains, `|name^` and `|name^|` the name alone (a
/// separator can't be an ordinary name byte). The scan takes such a pattern as that key (AdGuard
/// DNS filter writes most of its exceptions as `@@||name^|`), which is exact for its proofs and
/// spares an automaton walk over every key: the `||` prefix's `([a-z0-9-_.]+\.)?` never lets a
/// walk die before a key's end (review round 2, CC3).
fn keyed_equivalent(r: &Rule) -> Option<(crate::name::RuleName, Flags)> {
    if r.kind != Kind::Pattern || r.is_rewrite() || r.is_mapping() || r.spec.matches_nothing {
        return None;
    }
    let t = r.key.as_str();
    let (body, subs) = match t.strip_prefix("||") {
        Some(b) => (b, true),
        None => (t.strip_prefix('|')?, false),
    };
    let body = body.strip_suffix("^|").or_else(|| body.strip_suffix('^'))?;
    let name = crate::name::RuleName::parse(body).ok()?;
    if name.as_str() != body
        || name
            .labels()
            .any(|l| !picket_api::names::is_ordinary_label(l.as_bytes()))
    {
        return None;
    }
    let exact = r.flags.and(Flags::ALL_EXACT);
    // Each level's `_SUBS` bit is its `_EXACT` bit shifted by one (crate::flags).
    let flags = if subs {
        exact.union(Flags(exact.bits() << 1))
    } else {
        exact
    };
    Some((name, flags))
}

/// The literal every ordinary name a pattern matches ends with: the trailing `[a-z0-9._-]` run of
/// a pattern ending in `^`, `|` or `^|` (a separator can't be an ordinary name byte, so the match
/// ends at the name's end). A prefilter for the walks below a key: `w.K` can end with it only if
/// `K` does, or it ends with `.K`.
fn end_literal(r: &Rule) -> Option<String> {
    if r.kind != Kind::Pattern {
        return None;
    }
    let t = r.key.as_str();
    let body = t
        .strip_suffix("^|")
        .or_else(|| t.strip_suffix('^'))
        .or_else(|| t.strip_suffix('|'))?;
    let ordinary = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-');
    let start = body
        .bytes()
        .rposition(|b| !ordinary(b))
        .map_or(0, |i| i.saturating_add(1));
    let lit = body.get(start..)?;
    (!lit.is_empty()).then(|| lit.to_string())
}

/// A pattern rule without its conditions: the exact-name check asks whether it matches the name
/// for some query (CC6), so `$dnstype`, `$client`, `$ctag` and `$denyallow` are left out
/// (over-approximating `$denyallow`, which only raises a warning).
fn unconditional(r: &Rule) -> Rule {
    let mut r = r.clone();
    r.spec.dnstype = None;
    r.spec.client = None;
    r.spec.ctag = None;
    r.spec.denyallow.clear();
    r.spec.denyallow_entities.clear();
    r
}

/// The patterns of `pats` in passes whose automata fit in `kept_bytes` (at least one per pass).
fn passes(
    rules: &[Rule],
    pats: &[usize],
    kept_bytes: usize,
    anchored: bool,
    budget: &mut Budget,
    mut f: impl FnMut(&[usize], &mut Vec<Overlap>, &mut Budget) -> Result<(), Exhausted>,
) -> Result<(), Exhausted> {
    let mut start = 0;
    while start < pats.len() {
        let mut chunk = Vec::new();
        let mut auto = Vec::new();
        let mut bytes = 0usize;
        while let Some(&p) = pats.get(start) {
            let o = match rules.get(p).and_then(Rule::pattern_spec) {
                Some(spec) if anchored => Overlap::anchored(&spec, budget)?,
                Some(spec) => Overlap::of(&spec, budget)?,
                None => Overlap::Never,
            };
            if !chunk.is_empty() && bytes.saturating_add(o.bytes()) > kept_bytes {
                break;
            }
            bytes = bytes.saturating_add(o.bytes());
            chunk.push(p);
            auto.push(o);
            start = start.saturating_add(1);
        }
        f(&chunk, &mut auto, budget)?;
    }
    Ok(())
}

fn keyed_pattern_cancellations<F: PartialEq>(
    rules: &[Rule],
    eff: &[Option<(crate::name::RuleName, Flags)>],
    feeds: &[F],
    limits: &ScanLimits,
    c: &mut Collector,
    budget: &mut Budget,
) -> Result<(), Exhausted> {
    let usable = |r: &Rule| !r.is_badfilter() && !r.is_rewrite() && !r.kind.is_browser();
    let as_key = |i: usize| eff.get(i).and_then(Option::as_ref);
    let is_keyed = |i: usize, r: &Rule| {
        as_key(i).is_some() || matches!(r.kind, Kind::Name | Kind::HostMapping | Kind::IpLiteral)
    };
    let is_pattern =
        |i: usize, r: &Rule| as_key(i).is_none() && matches!(r.kind, Kind::Pattern | Kind::Regex);
    // A key's name and forms (a keyed-equivalent pattern's own).
    let key_of = |i: usize| -> Option<(crate::name::RuleName, Flags)> {
        match as_key(i) {
            Some((n, f)) => Some((n.clone(), *f)),
            None => rules.get(i).and_then(|r| r.name().map(|n| (n, r.flags))),
        }
    };
    let mut keyed_exc = Vec::new();
    let mut keyed_block = Vec::new();
    let mut pat_exc = Vec::new();
    let mut pat_block = Vec::new();
    for (i, r) in rules.iter().enumerate() {
        if !usable(r) {
            continue;
        }
        match (is_keyed(i, r), is_pattern(i, r), r.is_exception()) {
            (true, _, true) => keyed_exc.push(i),
            (true, _, false) => keyed_block.push(i),
            (_, true, true) => pat_exc.push(i),
            (_, true, false) => pat_block.push(i),
            _ => {}
        }
    }
    let wins = |exc: &Rule, blk: &Rule| exc.level().zip(blk.level()).is_some_and(|(el, bl)| bl > el);
    // `keys` are the keyed side, `patterns` the other polarity, taken in passes.
    let scan = |keys: &[usize],
                patterns: &[usize],
                keys_are_exceptions: bool,
                c: &mut Collector,
                budget: &mut Budget| {
        if keys.is_empty() || patterns.is_empty() {
            return Ok(());
        }
        // The keys' names (ordinary text) and forms.
        let names: Vec<Option<(crate::name::RuleName, Flags)>> = keys.iter().map(|&k| key_of(k)).collect();
        passes(
            rules,
            patterns,
            limits.kept_bytes,
            true,
            budget,
            |chunk, auto, budget| {
                // Building the matcher and the multi-pattern search compiles the chunk's patterns again.
                let chunk_cost: u64 = auto.iter().map(Overlap::nfa_states).sum();
                budget.spend(chunk_cost)?;
                // Exact names, conditions left out, through the matcher's shortcut index.
                let sub: Vec<Rule> = chunk
                    .iter()
                    .filter_map(|&i| rules.get(i))
                    .map(unconditional)
                    .collect();
                let m = crate::matcher::BundleMatcher::new(crate::matcher::BundleAction::Block, sub);
                // A pattern the matcher can't run (over its budget or the NFA limit) may match any name.
                let unrun: Vec<usize> = m
                    .patterns_over_budget()
                    .into_iter()
                    .chain(m.patterns_too_large())
                    .collect();
                let lits: Vec<Option<String>> = chunk
                    .iter()
                    .map(|&i| rules.get(i).and_then(end_literal))
                    .collect();
                // Below a key, a match starting inside it: one multi-pattern search over `.K`.
                let specs: Vec<Option<PatternSpec>> = chunk
                    .iter()
                    .map(|&i| rules.get(i).and_then(Rule::pattern_spec))
                    .collect();
                let mut inside = KeyMatcher::new(&specs, chunk_cost, budget)?;
                // Below a key, a match starting before it: each pattern's entry into a subtree, and
                // the first bytes it survives.
                let mut entries = Vec::with_capacity(chunk.len());
                let mut by_byte: Vec<Vec<usize>> = vec![Vec::new(); 256];
                for (ci, o) in auto.iter_mut().enumerate() {
                    let entry = o.subtree_entry(budget)?;
                    for b in o.live_first_bytes(&entry, budget)? {
                        if let Some(v) = by_byte.get_mut(usize::from(b)) {
                            v.push(ci);
                        }
                    }
                    entries.push(entry);
                }
                for (ki, &k) in keys.iter().enumerate() {
                    let (Some(kr), Some(Some((name, kflags)))) = (rules.get(k), names.get(ki)) else {
                        continue;
                    };
                    budget.spend(1)?;
                    let mut hits: Vec<usize> = Vec::new();
                    if kflags.intersects(Flags::ALL_EXACT) {
                        let r = m.match_key_any(name);
                        budget.spend(u64::try_from(r.matches.len()).unwrap_or(u64::MAX))?;
                        hits.extend(r.matches.iter().map(|h| h.rule));
                        hits.extend(&unrun);
                    }
                    if kflags.intersects(Flags::ALL_SUBS) {
                        hits.extend(inside.starting_inside(&format!(".{}", name.as_str()), budget)?);
                        let text = name.as_str().as_bytes();
                        let first = text.first().copied().unwrap_or(b'.');
                        for &ci in by_byte.get(usize::from(first)).map_or(&[][..], Vec::as_slice) {
                            let (Some(o), Some(e)) = (auto.get_mut(ci), entries.get(ci)) else {
                                continue;
                            };
                            if let Some(Some(lit)) = lits.get(ci) {
                                let k = name.as_str();
                                let fits = k.ends_with(lit.as_str())
                                    || (lit.len() > k.len()
                                        && lit.ends_with(k)
                                        && lit
                                            .as_bytes()
                                            .get(lit.len().saturating_sub(k.len()).saturating_sub(1))
                                            == Some(&b'.'));
                                if !fits {
                                    continue;
                                }
                            }
                            if o.matches_below(e, text, budget)? {
                                hits.push(ci);
                            }
                        }
                    }
                    hits.sort_unstable();
                    hits.dedup();
                    for ci in hits {
                        let Some(&p) = chunk.get(ci) else { continue };
                        let Some(pr) = rules.get(p) else { continue };
                        if feeds.get(p) == feeds.get(k) {
                            continue;
                        }
                        let (exc, blk) = if keys_are_exceptions { (kr, pr) } else { (pr, kr) };
                        let (canceller, cancelled) = if keys_are_exceptions { (k, p) } else { (p, k) };
                        if wins(exc, blk) {
                            c.add(CancelKind::Exception, canceller, cancelled);
                        }
                    }
                }
                Ok(())
            },
        )
    };
    scan(&keyed_exc, &pat_block, true, c, budget)?;
    scan(&keyed_block, &pat_exc, false, c, budget)?;
    // Exception patterns against block patterns of other feeds: both can match one name. The
    // exception side is kept in passes; each block pattern is built once per pass.
    let cross = |e: usize, b: usize| {
        let (Some(er), Some(br)) = (rules.get(e), rules.get(b)) else {
            return false;
        };
        feeds.get(e) != feeds.get(b) && wins(er, br)
    };
    if pat_exc.iter().any(|&e| pat_block.iter().any(|&b| cross(e, b))) {
        passes(
            rules,
            &pat_exc,
            limits.kept_bytes,
            false,
            budget,
            |chunk, auto, budget| {
                for &b in &pat_block {
                    if !chunk.iter().any(|&e| cross(e, b)) {
                        continue;
                    }
                    let mut ob = match rules.get(b).and_then(Rule::pattern_spec) {
                        Some(spec) => Overlap::of(&spec, budget)?,
                        None => Overlap::Never,
                    };
                    for (ci, &e) in chunk.iter().enumerate() {
                        if !cross(e, b) {
                            continue;
                        }
                        let Some(oe) = auto.get_mut(ci) else { continue };
                        if patterns_overlap(oe, &mut ob, budget)? {
                            c.add(CancelKind::Exception, e, b);
                        }
                    }
                }
                Ok(())
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Item, Line, classify_adblock_line};

    fn rules(lines: &[&str]) -> Vec<Rule> {
        lines
            .iter()
            .flat_map(|l| match classify_adblock_line(l, false) {
                Line::Items(v) => v
                    .into_iter()
                    .filter_map(|i| if let Item::Rule(r) = i { Some(r) } else { None })
                    .collect::<Vec<_>>(),
                Line::Skipped => vec![],
            })
            .collect()
    }

    #[test]
    fn targets_as_urlfilter() {
        let r = rules(&[
            "||d.example^",                                 // 0 removed
            "||d.example^$dnstype=A",                       // 1 removed (dnstype not compared)
            "||d.example^$important",                       // 2 kept (important differs)
            "@@||d.example^",                               // 3 kept (exception differs)
            "d.example",                                    // 4 kept (host rule)
            "||d.example^$dnsrewrite=1.2.3.4",              // 5 kept (rewrites are immune)
            "||d.example^$client=kid",                      // 6 kept (client differs)
            "||d.example^$badfilter",                       // 7
            "||e.example^$client=kid|10.0.0.0/8",           // 8 removed by 9 (sets equal)
            "||e.example^$client=10.1.2.3/8|kid,badfilter", // 9
            "||f.example^",                                 // 10 suppressed
            "||f.example^$badfilter,dnstype=AAAA",          // 11
            "||g.example^$~image",                          // 12 kept (request types differ)
            "||g.example^$badfilter",                       // 13
        ]);
        let eff = resolve(&r);
        assert_eq!(eff[0], BadfilterEffect::Removed { by: vec![7] });
        assert_eq!(eff[1], BadfilterEffect::Removed { by: vec![7] });
        for i in [2, 3, 4, 5, 6, 12] {
            assert_eq!(eff[i], BadfilterEffect::Kept, "{i}");
        }
        assert_eq!(eff[8], BadfilterEffect::Removed { by: vec![9] });
        assert!(
            matches!(&eff[10], BadfilterEffect::Suppressed { by, unless } if by == &vec![11] && unless.len() == 1)
        );
        let rich = effective_rich(&r[10], &eff[10]).unwrap().unwrap();
        assert_eq!(rich.unless.len(), 1);
        assert!(effective_rich(&r[0], &eff[0]).is_none());
    }

    #[test]
    fn cross_feed() {
        let r = rules(&[
            "||a.example^",
            "||a.example^$badfilter",
            "@@||sub.a.example^",
            "||b.example^",
            "@@|b.example^",
            "||c.example^$dnsrewrite=1.2.3.4",
            "@@||c.example^$dnsrewrite",
            "@@||ads*.x^",
            "||ads*.x^",
        ]);
        let feeds = [1, 2, 2, 1, 1, 1, 2, 1, 2];
        let c = cross_feed_cancellations(&r, &feeds);
        let kind = |i: usize| c.get(i).map(|x| x.kind);
        assert!(c.sampled(1, 0) && kind(1) == Some(CancelKind::Badfilter));
        assert!(c.sampled(2, 0) && kind(2) == Some(CancelKind::Exception));
        assert!(c.get(4).is_none(), "same feed");
        assert!(c.sampled(6, 5) && kind(6) == Some(CancelKind::RewriteException));
        assert!(c.sampled(7, 8) && kind(7) == Some(CancelKind::Exception));
        assert!(!c.capped && c.cancellers.iter().all(|x| x.proven && x.count >= 1));
    }

    #[test]
    fn keyed_equivalent_patterns_decide_as_their_keys() {
        // CC3: the scan takes `||name^|`-style patterns as keys; on ordinary names the matcher
        // decides them as it decides the keyed rule.
        use crate::matcher::{BundleAction, BundleMatcher};
        let names = [
            "a.example",
            "x.a.example",
            "y.x.a.example",
            "a.example.com",
            "xa.example",
            "example",
            "b.example",
            "a-example",
        ];
        let ctx = crate::modifiers::QueryCtx {
            qtype: 1,
            ..Default::default()
        };
        for (pattern, keyed) in [
            ("||a.example^|", "||a.example^"),
            ("|a.example^|", "|a.example^"),
            ("@@||a.example^|", "@@||a.example^"),
            ("||a.example^|$important", "||a.example^$important"),
        ] {
            let p = rules(&[pattern]);
            let k = rules(&[keyed]);
            let (n, f) = keyed_equivalent(&p[0]).unwrap_or_else(|| panic!("{pattern}"));
            assert_eq!((n.reversed(), f), (k[0].key.clone(), k[0].flags), "{pattern}");
            let mp = BundleMatcher::new(BundleAction::Block, p);
            let mk = BundleMatcher::new(BundleAction::Block, k);
            for name in names {
                assert_eq!(
                    mp.match_dotted(name, &ctx).outcome,
                    mk.match_dotted(name, &ctx).outcome,
                    "{pattern} {name}"
                );
            }
        }
        for not in [
            "||a*.example^|",
            "||A.example^|",
            "||a.example^x",
            "/a.example/",
            "||a.example/",
        ] {
            let r = rules(&[not]);
            assert!(r.first().is_none_or(|r| keyed_equivalent(r).is_none()), "{not}");
        }
        // AdGuard DNS filter's form against a keyed block of another feed: one entry, as keys.
        let r = rules(&[
            "||ad.example.com^",
            "||x.ad.example.com^",
            "@@||ad.example.com^|",
            "||other.com^",
        ]);
        let c = cross_feed_cancellations(&r, &[1, 1, 2, 1]);
        let e = c.get(2).unwrap();
        assert_eq!((e.count, e.sample.clone()), (2, vec![0, 1]));
    }

    #[test]
    fn end_literals_prefilter_only_what_cannot_match() {
        let lit = |l: &str| end_literal(&rules(&[l])[0]);
        assert_eq!(lit("||ad*.example.com^|").as_deref(), Some(".example.com"));
        assert_eq!(lit("||ad*.example.com^").as_deref(), Some(".example.com"));
        assert_eq!(lit("ads*tracker|").as_deref(), Some("tracker"));
        assert_eq!(lit("||ad*.example.com"), None, "not end-anchored");
        assert_eq!(lit("/ads$/"), None, "a regex");
        assert_eq!(lit("||ad*^|"), None);
        // The walks it skips can't match: a wildcard exception still finds its keys.
        let r = rules(&[
            "||example.com^",
            "||tracker.example.com^",
            "||x.org^",
            "@@||ad*.example.com^|",
            "@@||ad*.tracker.example.com^|",
        ]);
        let c = cross_feed_cancellations(&r, &[1, 1, 1, 2, 2]);
        assert_eq!(c.get(3).map(|x| x.sample.clone()), Some(vec![0, 1]));
        assert_eq!(c.get(4).map(|x| x.sample.clone()), Some(vec![0, 1]));
    }

    #[test]
    fn output_is_one_entry_per_canceller() {
        // CC3: one exception reaching 20,000 keys of another feed is one entry with a count
        // and a sample, not 20,000 cancellations.
        let mut lines: Vec<String> = (0..20_000).map(|i| format!("||host{i}.example^")).collect();
        lines.push("@@/^foo\\./".to_string());
        lines.push("@@||com^".to_string());
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let r = rules(&refs);
        let feeds: Vec<usize> = (0..r.len()).map(|i| usize::from(i >= 20_000)).collect();
        let c = cross_feed_cancellations(&r, &feeds);
        assert_eq!(c.cancellers.len(), 1, "{:?}", c.cancellers);
        let e = c.get(20_000).unwrap();
        assert_eq!(
            (e.count, e.sample.len(), e.proven),
            (20_000, CANCELLATION_SAMPLE, true)
        );
        assert!(c.get(20_001).is_none(), "||com^ covers none of the .example keys");
    }

    #[test]
    fn patterns_only_unusual_names_trigger_cancel_nothing() {
        // CC3: the proofs run over ordinary-name bytes (unusual names are rules.md §3's listed
        // exception), so AdGuard DNS filter's `@@/\.(gif|jpe?g|png|webp)#(\/?.+)?(\/(ad)s?\/|\/ad-)/`
        // isn't a canceller of every key.
        let mut lines: Vec<String> = (0..2_000).map(|i| format!("||a{i}.com^")).collect();
        lines.push("@@/\\.(gif|jpe?g|png|webp)#(\\/?.+)?(\\/(ad)s?\\/|\\/ad-)/".to_string());
        lines.push("/x[#!]z/".to_string());
        lines.push("@@/x[#!]y/".to_string());
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let r = rules(&refs);
        assert_eq!(r.len(), 2_003);
        let feeds: Vec<usize> = (0..r.len())
            .map(|i| usize::from(i == 2_000 || i == 2_002))
            .collect();
        let c = cross_feed_cancellations(&r, &feeds);
        assert!(c.cancellers.is_empty(), "{:?}", c.cancellers);
    }

    #[test]
    fn conditional_exception_patterns_cancel_exact_keys() {
        // CC6: `@@/^example\.com$/$dnstype=A` (or `$client=…`) cancels another feed's
        // `example.com` for the queries it matches: a warning, though match_key_any leaves
        // conditional rules out.
        for exc in [
            "@@/^example\\.com$/$dnstype=A",
            "@@/^example\\.com$/$client=10.0.0.1",
            "@@/^example\\.com$/$ctag=device_phone",
            "@@/^example\\.com$/$denyallow=x.org",
            "@@/^example\\.com$/",
        ] {
            let r = rules(&["example.com", exc]);
            assert_eq!(r.len(), 2, "{exc}");
            let c = cross_feed_cancellations(&r, &[1, 2]);
            assert!(c.sampled(1, 0), "{exc}: {:?}", c.cancellers);
        }
        // A conditional keyed exception against a block pattern, likewise.
        let r = rules(&["/^example\\.com$/", "@@||example.com^$dnstype=AAAA"]);
        assert!(cross_feed_cancellations(&r, &[1, 2]).sampled(1, 0));
    }

    #[test]
    fn the_work_cap_reports_what_it_could_not_check() {
        // CC3: past its work cap the scan stops; exceptions it didn't get to are listed
        // unproven (sound: reported rather than missed).
        let mut lines: Vec<String> = (0..1_000).map(|i| format!("||k{i}.example^")).collect();
        lines.extend((0..50).map(|i| format!("@@/^z{i}\\.k[0-9]+\\.example$/")));
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let r = rules(&refs);
        let feeds: Vec<usize> = (0..r.len()).map(|i| usize::from(i >= 1_000)).collect();
        let full = cross_feed_cancellations(&r, &feeds);
        assert!(!full.capped);
        assert_eq!(full.cancellers.len(), 50);
        let limits = ScanLimits {
            work: full.work / 4,
            ..ScanLimits::default()
        };
        let part = cross_feed_cancellations_within(&r, &feeds, limits);
        assert!(part.capped && part.work <= full.work / 4);
        assert_eq!(part.cancellers.len(), 50, "every exception is listed");
        let total = |c: &CrossFeedReport| c.cancellers.iter().map(|x| x.count).sum::<u64>();
        assert!(total(&part) < total(&full), "counts stop at the cap");
        // Stopped before any proof: all listed, unproven.
        let none = cross_feed_cancellations_within(
            &r,
            &feeds,
            ScanLimits {
                work: 10,
                ..ScanLimits::default()
            },
        );
        assert!(none.capped);
        assert_eq!(none.cancellers.len(), 50);
        assert!(none.cancellers.iter().all(|x| !x.proven && x.count == 0));
    }

    #[test]
    fn automata_stay_within_their_bytes() {
        // CC3: 1,024 heavy block patterns and one keyed exception of another feed: the scan
        // keeps at most `kept_bytes` of automata at once and finishes within its work.
        let mut lines: Vec<String> = (0..1_024).map(|i| format!("/^[ab]{{900}}x{i}$/")).collect();
        lines.push("@@||ab.example^".to_string());
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let r = rules(&refs);
        let feeds: Vec<usize> = (0..r.len()).map(|i| usize::from(i >= 1_024)).collect();
        let limits = ScanLimits {
            kept_bytes: 4 * 1024 * 1024,
            ..ScanLimits::default()
        };
        let t = std::time::Instant::now();
        let c = cross_feed_cancellations_within(&r, &feeds, limits);
        assert!(!c.capped);
        assert!(c.cancellers.is_empty(), "{:?}", c.cancellers);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(30),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn cross_feed_keys_and_patterns() {
        let r = rules(&[
            "||ads.example^",           // 0 feed 1: cancelled by 3
            "/^ads\\./",                // 1 feed 1: cancelled by 2 (pattern matches the key)
            "@@||ads.example^",         // 2 feed 2
            "@@/ads/",                  // 3 feed 2
            "|tracker.example^",        // 4 feed 1: an exact key; @@/x\.tracker/ needs a subdomain
            "@@/x\\.tracker/",          // 5 feed 2
            "@@|y.example^",            // 6 feed 2: exact exception
            "/^sub\\.y\\.example$/",    // 7 feed 1: matches only below y.example
            "||imp.example^$important", // 8 feed 1: $important beats a plain exception
            "@@/imp/",                  // 9 feed 2
            "/same-feed/",              // 10 feed 2
            "@@||same-feed.example^",   // 11 feed 2
        ]);
        let feeds = [1, 1, 2, 2, 1, 2, 2, 1, 1, 2, 2, 2];
        let c = cross_feed_cancellations(&r, &feeds);
        let has = |canceller, cancelled| c.sampled(canceller, cancelled);
        assert!(has(3, 0), "an exception pattern matching a key of another feed");
        assert!(has(2, 1), "a keyed exception whose name a block pattern matches");
        assert!(!has(5, 4), "the pattern matches no name an exact key blocks");
        assert!(!has(6, 7), "an exact exception doesn't reach sub.y.example");
        assert!(!has(9, 8), "@@ doesn't beat $important");
        assert!(
            c.cancellers
                .iter()
                .all(|x| x.sample.iter().all(|&b| feeds[x.canceller] != feeds[b])),
            "same feed"
        );
        assert!(!c.cancellers.iter().any(|x| x.sample.contains(&10)), "same feed");
        assert!(
            has(11, 1),
            "ads.same-feed.example is below the key and matches /^ads\\./"
        );
    }

    #[test]
    fn pattern_exceptions_are_those_no_key_stands_for() {
        let r = rules(&[
            "@@/^ads\\./",              // 0 an exception pattern
            "@@||ads*.example^",        // 1 a wildcard: no key
            "@@||ads.example^|",        // 2 stands for its key
            "/^ads\\./",                // 3 a block pattern
            "@@||ads.example^",         // 4 a keyed exception
            "@@||x.example^$badfilter", // 5 a $badfilter
        ]);
        let got: Vec<bool> = r.iter().map(is_pattern_exception).collect();
        assert_eq!(got, [true, true, false, false, false, false], "{r:#?}");
        let (key, flags) = keyed_equivalent_key(&r[2]).expect("||name^ stands for its key");
        assert_eq!(key, "example.ads");
        assert!(flags.intersects(Flags::ALL_SUBS));
        assert!(keyed_equivalent_key(&r[0]).is_none());
    }

    #[test]
    fn cross_feed_patterns_below_keys_are_found() {
        // Review round 1, R11: an exception pattern matching some name below a key cancels the
        // key's block there, whatever the name; and two patterns that share a name.
        let r = rules(&[
            "||example.com^",            // 0 feed 1
            "@@/^foo\\.example\\.com/",  // 1 feed 2: foo.example.com
            "||other.net^",              // 2 feed 1
            "@@/\\.org$/",               // 3 feed 2: names ending in .org only
            "/^ads\\./",                 // 4 feed 1
            "@@/^ads\\.tracker/",        // 5 feed 2: overlaps 4 (ads.tracker…)
            "/\\.de$/",                  // 6 feed 1
            "@@||x.example.com^",        // 7 feed 2: a keyed exception below a key
            "/^a\\.x\\.example\\.com$/", // 8 feed 1: a name below 7's key
        ]);
        let feeds = [1, 2, 1, 2, 1, 2, 1, 2, 1];
        let c = cross_feed_cancellations(&r, &feeds);
        let has = |canceller, cancelled| c.sampled(canceller, cancelled);
        assert!(has(1, 0), "foo.example.com is below example.com");
        assert!(has(1, 2), "foo.example.com.other.net is below other.net");
        assert!(!has(3, 0), "nothing below example.com ends in .org");
        assert!(has(5, 4), "two patterns matching ads.tracker…");
        assert!(!has(3, 6), ".org and .de never end one name");
        assert!(
            has(7, 8),
            "a block pattern matching a name below a keyed exception"
        );
    }
}
