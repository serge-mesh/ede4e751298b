//! The reference matcher for one bundle (rules.md §4, §6; bundles.md §6), over parsed rules rather
//! than the compiled format. Core uses it for attribution replay, trial checks and warnings
//! (core.md §6); picket-bundle's tests use it as their oracle.
//!
//! Names are wire labels (most specific first). Keyed rules match whole labels; patterns run on
//! AdGuard's text form (rules.md §3). An address is matched as AdGuard Home matches answer
//! addresses: its Go text as a name, plus Picket's IP rules by range (IPv4-mapped IPv6 as IPv4).
//!
//! Order for one name (AdGuard Home `matchHost`):
//! 1. `$dnsrewrite` rules left after `@@…$dnsrewrite` cancellations → REWRITE (the first CNAME or
//!    rcode rewrite in bundle order answers alone, otherwise values merge; a CNAME to the name
//!    itself is ignored, as in AdGuard Home);
//! 2. the top remaining network rule by level (`@@…$important` > `$important` > `@@` > block) →
//!    BLOCK, or no result for an exception;
//! 3. host-IP mappings → their addresses;
//! 4. nothing.
//!
//! Rule order matters only where AdGuard's does (rewrites): pass rules in bundle order (feed
//! order, then line order). Rewrites and `@@…$dnsrewrite` exceptions are taken in urlfilter's
//! matched-rule order ([`crate::order`]), not list order; the compiler stores each rewrite rule's
//! [`crate::order::MatchOrder`] (from [`BundleMatcher::match_orders`]) in `rich.json`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use aho_corasick::{AhoCorasick, MatchKind};
use serde::{Deserialize, Serialize};

use crate::adguard::{MatchTarget, URL_PREFIX, shortcut_present};
use crate::analysis::build_regex;
use crate::badfilter::{BadfilterEffect, resolve};
use crate::entity::EntityExpansion;
use crate::flags::{Flags, Level};
use crate::ip::{canonical_ip, go_ip_string};
use crate::modifiers::{NameSemantics, QueryCtx};
use crate::name::reverse_dotted;
use crate::order::{MatchOrder, sequence, urlfilter_order};
use crate::psl::PublicSuffixList;
use crate::rewrite::{RewriteAnswer, RewriteCandidate, apply_rewrite_exceptions_by, merge_rewrites};
use crate::rule::{Kind, PatternSpec, RichRule, Rule, RuleType, Suppressor};

/// A bundle's action (bundles.md §1); `warn` bundles match as `allow` bundles do (bundles.md §3:
/// "matches a key as it would a query for the key's name").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BundleAction {
    Block,
    /// Every rule allows, `@@` or not (rules.md §4).
    Allow,
    /// A match puts the name in scope; exceptions and `$badfilter` cancel; only `dns` rules count.
    Scope,
}

/// The result for one name or address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// No rule decided.
    None,
    /// Block bundle: the winning rule is an exception (no result; the next bundle is checked).
    Exception,
    /// Block bundle: BLOCK.
    Block,
    /// Block bundle: REWRITE with these values.
    Rewrite(RewriteAnswer),
    /// Block bundle: host-IP mapping answer with these addresses (sorted).
    HostMapping(Vec<IpAddr>),
    /// Allow bundle: ALLOW.
    Allow,
    /// Scope bundle: the name is in scope.
    InScope,
}

/// The step of rules.md §4 that decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Rewrite,
    Network,
    Hosts,
}

/// Why a rule that matched didn't count (core.md §6 role `overridden`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverriddenBy {
    /// A higher-level exception won.
    Exception,
    /// A `$badfilter` removed it.
    Badfilter,
    /// `@@…$dnsrewrite` cancelled the rewrite.
    RewriteException,
}

/// A matching rule's role (core.md §6 attribution step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// It decided (every rewrite that shaped a merged answer, and every mapping that answered).
    Decisive,
    /// It matched and didn't decide.
    AlsoMatched,
    /// Cancelled.
    Overridden(OverriddenBy),
}

/// How a rule met the name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchHow {
    /// A key with this many labels: the name itself (`_EXACT` flags) or a parent (`_SUBS`).
    Key { labels: u8, at_name: bool },
    /// A wildcard or regex pattern on the text form.
    Pattern,
    /// An IP rule's range.
    IpRange,
}

/// One matching rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Index into the rules the matcher was built from.
    pub rule: usize,
    pub role: Role,
    /// The level its applying flags give (rules.md §4).
    pub level: Option<Level>,
    /// Ranks rules within a level for attribution (rules.md §4 "the more specific rule wins"):
    /// 1000 × urlfilter's specifier count + labels of the matched key (or prefix bits of a range).
    pub specificity: u32,
    pub how: MatchHow,
    /// For [`Role::Overridden`]: the rule that cancelled it (the deciding exception, the
    /// `$badfilter` rule, or the `@@…$dnsrewrite` rule), so attribution can name it too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<usize>,
}

/// The outcome and every matching rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResult {
    pub outcome: Outcome,
    pub step: Option<Step>,
    /// The deciding level for a network-rule decision.
    pub level: Option<Level>,
    pub matches: Vec<RuleMatch>,
}

impl MatchResult {
    /// The decisive rules.
    pub fn decisive(&self) -> impl Iterator<Item = &RuleMatch> {
        self.matches.iter().filter(|m| m.role == Role::Decisive)
    }
}

struct PatternEntry {
    rule: usize,
    spec: PatternSpec,
}

/// The default memory budget for compiled pattern regexes (core.md §6: patterns compiled lazily,
/// cached, 32 MB cap).
pub const REGEX_CACHE_BUDGET: usize = 32 * 1024 * 1024;

/// The share of the budget (1/n) kept for lazy-DFA caches growing past their fresh size; the
/// rest holds the resident regexes with fresh caches.
const CACHE_GROWTH_SHARE: usize = 4;

/// The part of a pattern budget that holds resident patterns ([`pattern_cost`] each): the budget
/// less the share kept for cache growth. Shared with picket-bundle, whose compiler and edge reader
/// admit patterns by the same rule (bundles.md §4, §6; review round 1, B3).
pub fn pattern_admission_limit(budget: usize) -> usize {
    budget.saturating_sub(budget / CACHE_GROWTH_SHARE)
}

/// A pattern regex's resident cost: its compiled regex's heap plus a fresh search cache. The one
/// cost model for pattern admission, here and in picket-bundle's compiler and edge reader.
pub fn regex_cost(regex: &regex_automata::meta::Regex, cache: &regex_automata::meta::Cache) -> usize {
    regex.memory_usage().saturating_add(cache.memory_usage())
}

/// [`regex_cost`] of a pattern's regex, building it as the reference matcher does
/// ([`crate::analysis::build_regex`]); `None` when it doesn't build (over the NFA limit).
pub fn pattern_cost(regex: &str) -> Option<usize> {
    let re = build_regex(regex).ok()?;
    let cache = re.create_cache();
    Some(regex_cost(&re, &cache))
}

/// Which of a bundle's patterns its reference matcher holds, under `budget` (the resident set of
/// [`BundleMatcher`]'s regex cache, without keeping the regexes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PatternAdmission {
    /// Resident patterns, in bundle order: (rule index, [`pattern_cost`]).
    pub resident: Vec<(usize, usize)>,
    /// Patterns past the budget: they match nothing (rule indices, bundle order).
    pub over_budget: Vec<usize>,
    /// Patterns whose regex doesn't build (over the NFA limit), among those tried: they match
    /// nothing (rule indices, bundle order).
    pub too_large: Vec<usize>,
}

/// The reference matcher's pattern admission for `rules` (in bundle order) under `budget`: what
/// [`BundleMatcher::patterns_over_budget`] and [`BundleMatcher::patterns_too_large`] report, plus
/// each resident pattern's cost. picket-bundle's compiler drops exactly the patterns this drops,
/// so the edge never holds a pattern core doesn't run, nor the reverse.
pub fn pattern_admission(action: BundleAction, rules: &[Rule], budget: usize) -> PatternAdmission {
    let patterns: Vec<PatternEntry> = rules
        .iter()
        .enumerate()
        .filter_map(|(i, r)| pattern_entry(action, i, r))
        .collect();
    let mut failed = HashSet::new();
    let (resident, over) = admit_in_order(
        &patterns,
        pattern_admission_limit(budget),
        &mut failed,
        |_, source| pattern_cost(source).map(|c| ((), c)),
    );
    let rule = |pi: usize| patterns.get(pi).map(|p| p.rule);
    let mut too_large: Vec<usize> = failed.into_iter().filter_map(rule).collect();
    too_large.sort_unstable();
    PatternAdmission {
        resident: resident
            .into_iter()
            .filter_map(|(pi, (), c)| rule(pi).map(|r| (r, c)))
            .collect(),
        over_budget: over.into_iter().filter_map(rule).collect(),
        too_large,
    }
}

/// The pattern a rule gives the reference matcher, if any (the filter [`BundleMatcher::new`]
/// applies).
fn pattern_entry(action: BundleAction, i: usize, r: &Rule) -> Option<PatternEntry> {
    if r.kind.is_browser() || r.rule_type == RuleType::Browser {
        return None;
    }
    if action == BundleAction::Scope && r.rule_type != RuleType::Dns {
        return None;
    }
    if r.is_badfilter() && !r.is_rewrite() {
        return None;
    }
    if !matches!(r.key_kind(), Kind::Pattern | Kind::Regex) {
        return None;
    }
    r.pattern_spec().map(|spec| PatternEntry { rule: i, spec })
}

/// The resident-set rule ([`RegexCache`]): in bundle order, patterns that match everything, have
/// no regex or failed to build cost nothing and are skipped; each other one is built (`build`
/// gives it and its cost, or `None` when it doesn't build, which records it in `failed`) and kept
/// while the total fits `limit`; at the first that doesn't, it and every later pattern are over
/// the budget (not built). Returns the resident patterns (index, built value, cost) and those over
/// the budget.
fn admit_in_order<T>(
    patterns: &[PatternEntry],
    limit: usize,
    failed: &mut HashSet<usize>,
    mut build: impl FnMut(usize, &str) -> Option<(T, usize)>,
) -> (Vec<(usize, T, usize)>, Vec<usize>) {
    let mut resident = Vec::new();
    let mut over = Vec::new();
    let mut used = 0usize;
    let mut full = false;
    for (pi, p) in patterns.iter().enumerate() {
        if p.spec.matches_all || failed.contains(&pi) {
            continue;
        }
        if full {
            over.push(pi);
            continue;
        }
        // A pattern without a regex (Go refuses it) matches nothing, as in AdGuard.
        let Some(source) = p.spec.regex.as_deref() else {
            continue;
        };
        let Some((t, cost)) = build(pi, source) else {
            failed.insert(pi);
            continue;
        };
        if used.saturating_add(cost) > limit {
            full = true;
            over.push(pi);
            continue;
        }
        used = used.saturating_add(cost);
        resident.push((pi, t, cost));
    }
    (resident, over)
}

/// The growth a [`PatternRegex`]'s lazy-DFA cache may take past its fresh size before it is
/// reset, so its memory stays within [`PatternRegex::cost`].
pub const PATTERN_CACHE_GROWTH: usize = 64 * 1024;

/// One pattern regex, built as the reference matcher builds it, with its own lazy-DFA cache whose
/// growth is capped ([`PATTERN_CACHE_GROWTH`]): its memory never passes [`PatternRegex::cost`].
/// For a caller that keeps compiled patterns under one budget of its own ([`RegexProvider`]).
pub struct PatternRegex {
    regex: regex_automata::meta::Regex,
    cache: Mutex<regex_automata::meta::Cache>,
    heap: usize,
    fresh: usize,
    /// The cache's growth past `fresh` as last measured (at most [`PATTERN_CACHE_GROWTH`]).
    growth: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for PatternRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternRegex")
            .field("heap", &self.heap)
            .field("fresh", &self.fresh)
            .finish()
    }
}

impl PatternRegex {
    /// Builds `source` ([`crate::analysis::build_regex`]); `None` when it doesn't build (over the
    /// NFA limit): such a pattern matches nothing.
    pub fn build(source: &str) -> Option<PatternRegex> {
        let regex = build_regex(source).ok()?;
        let cache = regex.create_cache();
        Some(PatternRegex {
            heap: regex.memory_usage(),
            fresh: cache.memory_usage(),
            cache: Mutex::new(cache),
            regex,
            growth: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// The most memory it takes: the regex's heap, a fresh cache and the growth allowed past it.
    pub fn cost(&self) -> usize {
        self.heap
            .saturating_add(self.fresh)
            .saturating_add(PATTERN_CACHE_GROWTH)
    }

    /// Its resident cost: the regex's heap and a fresh cache, [`pattern_cost`]'s measure (the one
    /// pattern admission uses). A caller keeping many under one budget charges this per regex and
    /// bounds their caches' growth ([`PatternRegex::growth`]) in a pool of its own.
    pub fn resident_cost(&self) -> usize {
        self.heap.saturating_add(self.fresh)
    }

    /// Its cache's growth past a fresh cache, as measured after the last search (at most
    /// [`PATTERN_CACHE_GROWTH`]).
    pub fn growth(&self) -> usize {
        self.growth.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Resets its cache to a fresh one (its growth goes to 0); returns the growth given back.
    pub fn reset_cache(&self) -> usize {
        let Ok(mut c) = self.cache.lock() else {
            return 0;
        };
        *c = self.regex.create_cache();
        self.growth.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// True when the regex matches `haystack` (searching with the earliest match, as the matcher
    /// does); a cache grown past its allowance is reset afterwards.
    pub fn is_match(&self, haystack: &str) -> bool {
        let Ok(mut c) = self.cache.lock() else {
            return self.regex.is_match(haystack);
        };
        let hit = self
            .regex
            .search_with(&mut c, &regex_automata::Input::new(haystack).earliest(true))
            .is_some();
        if c.memory_usage() > self.fresh.saturating_add(PATTERN_CACHE_GROWTH) {
            *c = self.regex.create_cache();
        }
        self.growth.store(
            c.memory_usage().saturating_sub(self.fresh),
            std::sync::atomic::Ordering::Relaxed,
        );
        hit
    }
}

/// A shared source of compiled pattern regexes: a matcher given one
/// ([`BundleMatcher::with_regex_provider`]) compiles nothing itself and asks it instead, so a
/// caller building many matchers (core's replay, core.md §6: "compiled lazily, LRU-cached …, 32 MB
/// cap") keeps every compiled pattern under one budget.
pub trait RegexProvider: Send + Sync {
    /// True when the regex built from `source` ([`crate::analysis::build_regex`]) matches
    /// `haystack`; false when it doesn't build.
    fn is_match(&self, source: &str, haystack: &str) -> bool;
}

/// One compiled regex and the lazy-DFA cache it searches with.
struct CompiledPattern {
    regex: Arc<regex_automata::meta::Regex>,
    cache: Arc<Mutex<regex_automata::meta::Cache>>,
    /// The regex's heap.
    heap: usize,
    /// A fresh cache's size.
    fresh: usize,
    /// The cache's size as last measured.
    cache_bytes: usize,
    last_use: u64,
}

impl CompiledPattern {
    fn growth(&self) -> usize {
        self.cache_bytes.saturating_sub(self.fresh)
    }
}

/// Compiled pattern regexes under a memory budget (README §2 "Bounded"; core.md §6; review
/// rounds 1–2, R7 and CC5). A fixed resident set: on first use, patterns are built in bundle
/// order and kept while their regexes with fresh caches fit in 3/4 of the budget; at the first
/// one that doesn't fit, it and every later pattern are dropped (they match nothing, and
/// [`BundleMatcher::patterns_over_budget`] lists them so the compiler drops them from the bundle
/// with a counted `bundle_warning`, as for a regex over the NFA limit, rules.md §3). Stopping
/// there bounds the build work by the budget too. Resident regexes are never evicted, so a cyclic
/// scan can't make every query rebuild every pattern (an LRU over a scan misses every time). The
/// last quarter bounds the lazy-DFA caches' growth past their fresh size: past it, the least
/// recently used caches are reset (their regexes stay). The admission depends only on the
/// patterns and the budget, never on query order, so a compile and a replay agree.
#[derive(Default)]
struct RegexCache {
    budget: usize,
    admitted: bool,
    /// Resident regexes plus fresh caches.
    resident: usize,
    /// Cache growth past fresh sizes.
    growth: usize,
    tick: u64,
    entries: HashMap<usize, CompiledPattern>,
    /// Patterns whose regex didn't build (over the NFA limit): they match nothing.
    failed: HashSet<usize>,
    /// Patterns past the budget, in bundle order: they match nothing.
    over_budget: Vec<usize>,
    builds: u64,
    resets: u64,
}

impl RegexCache {
    fn growth_budget(&self) -> usize {
        self.budget / CACHE_GROWTH_SHARE
    }

    /// Decides the resident set (once, or again after a budget change); see the type's docs.
    fn admit(&mut self, patterns: &[PatternEntry]) {
        if self.admitted {
            return;
        }
        self.admitted = true;
        let limit = pattern_admission_limit(self.budget);
        let mut old = std::mem::take(&mut self.entries);
        let mut builds = 0u64;
        let (resident, over) = admit_in_order(patterns, limit, &mut self.failed, |pi, source| {
            if let Some(e) = old.remove(&pi) {
                let cost = e.heap.saturating_add(e.fresh);
                return Some((e, cost));
            }
            let regex = build_regex(source).ok()?;
            builds = builds.saturating_add(1);
            let cache = regex.create_cache();
            let cost = regex_cost(&regex, &cache);
            let fresh = cache.memory_usage();
            Some((
                CompiledPattern {
                    heap: regex.memory_usage(),
                    regex: Arc::new(regex),
                    cache: Arc::new(Mutex::new(cache)),
                    fresh,
                    cache_bytes: fresh,
                    last_use: 0,
                },
                cost,
            ))
        });
        self.builds = self.builds.saturating_add(builds);
        self.over_budget = over;
        let mut used = 0usize;
        for (pi, e, cost) in resident {
            used = used.saturating_add(cost);
            self.entries.insert(pi, e);
        }
        self.resident = used;
        self.growth = self.entries.values().map(CompiledPattern::growth).sum();
        self.trim(usize::MAX);
    }

    /// The regex and cache for resident pattern `pi`; `None` when it isn't resident (over the
    /// NFA limit or past the budget: it matches nothing).
    fn get(
        &mut self,
        pi: usize,
        patterns: &[PatternEntry],
    ) -> Option<(
        Arc<regex_automata::meta::Regex>,
        Arc<Mutex<regex_automata::meta::Cache>>,
    )> {
        self.admit(patterns);
        self.tick = self.tick.saturating_add(1);
        let e = self.entries.get_mut(&pi)?;
        e.last_use = self.tick;
        Some((e.regex.clone(), e.cache.clone()))
    }

    /// Records a cache's size after a search and resets caches past the growth budget.
    fn measured(&mut self, pi: usize, cache_bytes: usize) {
        if let Some(e) = self.entries.get_mut(&pi) {
            self.growth = self.growth.saturating_sub(e.growth());
            e.cache_bytes = cache_bytes;
            self.growth = self.growth.saturating_add(e.growth());
        }
        self.trim(pi);
    }

    /// Resets least recently used caches that grew (`keep`'s last) until the growth fits.
    fn trim(&mut self, keep: usize) {
        while self.growth > self.growth_budget() {
            let victim = self
                .entries
                .iter()
                .filter(|(_, e)| e.growth() > 0)
                .min_by_key(|(k, e)| (**k == keep, e.last_use))
                .map(|(k, _)| *k);
            let Some(v) = victim else { break };
            let Some(e) = self.entries.get_mut(&v) else { break };
            if let Ok(mut c) = e.cache.lock() {
                *c = e.regex.create_cache();
                e.fresh = c.memory_usage();
            }
            self.growth = self.growth.saturating_sub(e.growth());
            e.cache_bytes = e.fresh;
            self.resets = self.resets.saturating_add(1);
        }
    }

    fn used(&self) -> usize {
        self.resident.saturating_add(self.growth)
    }
}

/// The reference matcher over one bundle's rules.
pub struct BundleMatcher {
    action: BundleAction,
    rules: Vec<Rule>,
    effects: Vec<BadfilterEffect>,
    orders: Vec<Option<MatchOrder>>,
    /// Each rule's conditions and answer (entities expanded when a public suffix list is given).
    rich: Vec<Option<RichRule>>,
    /// Each `$badfilter` rule's own conditions.
    suppressors: Vec<Option<Suppressor>>,
    keyed: HashMap<String, Vec<usize>>,
    patterns: Vec<PatternEntry>,
    ip_rules: IpIndex,
    ac: Option<AhoCorasick>,
    ac_targets: Vec<Vec<usize>>,
    unshortcut: Vec<usize>,
    regexes: Mutex<RegexCache>,
    /// Compiled patterns come from here instead of `regexes` when set.
    provider: Option<Arc<dyn RegexProvider>>,
    /// Rules (indices) whose pattern matches nothing here: the patterns a compile of the whole
    /// bundle left out ([`BundleMatcher::with_patterns_dropped`]).
    dropped: HashSet<usize>,
}

/// A candidate before roles.
#[derive(Clone, Copy)]
struct Cand {
    rule: usize,
    applying: Flags,
    how: MatchHow,
    depth: u32,
    /// The `$badfilter` rule that removes it for this query.
    removed: Option<usize>,
}

/// How rule conditions are evaluated.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// For this query.
    Query,
    /// For some query of any type from any client (bundles.md §3, [`BundleMatcher::match_key_any`]).
    AnyQuery,
}

impl BundleMatcher {
    /// Builds a matcher. `rules` are in bundle order. Browser rules are ignored; a scope bundle
    /// keeps only `dns` rules (bundles.md §1).
    pub fn new(action: BundleAction, rules: Vec<Rule>) -> BundleMatcher {
        let effects = resolve(&rules);
        let orders = urlfilter_order(&rules);
        let rich: Vec<Option<RichRule>> = rules.iter().map(Rule::rich).collect();
        let suppressors: Vec<Option<Suppressor>> = rules
            .iter()
            .map(|r| r.is_badfilter().then(|| Suppressor::of(r)))
            .collect();
        let mut keyed: HashMap<String, Vec<usize>> = HashMap::new();
        let mut patterns = Vec::new();
        let mut ip_rules = Vec::new();
        for (i, r) in rules.iter().enumerate() {
            if r.kind.is_browser() || r.rule_type == RuleType::Browser {
                continue;
            }
            if action == BundleAction::Scope && r.rule_type != RuleType::Dns {
                continue;
            }
            // A `$badfilter` rule takes part only as a rewrite (AdGuard).
            if r.is_badfilter() && !r.is_rewrite() {
                continue;
            }
            match r.key_kind() {
                Kind::Name | Kind::HostMapping => keyed.entry(r.key.clone()).or_default().push(i),
                Kind::IpLiteral => {
                    keyed.entry(reverse_dotted(&r.key)).or_default().push(i);
                    ip_rules.push(i);
                }
                Kind::IpRange => ip_rules.push(i),
                Kind::Pattern | Kind::Regex => {
                    // The same filter as `pattern_admission`, so both see one pattern list.
                    if let Some(p) = pattern_entry(action, i, r) {
                        patterns.push(p);
                    }
                }
                _ => {}
            }
        }
        let mut by_shortcut: HashMap<String, Vec<usize>> = HashMap::new();
        let mut unshortcut = Vec::new();
        for (pi, p) in patterns.iter().enumerate() {
            match &p.spec.shortcut {
                Some(s) => by_shortcut.entry(s.clone()).or_default().push(pi),
                None => unshortcut.push(pi),
            }
        }
        let mut shortcuts: Vec<String> = by_shortcut.keys().cloned().collect();
        shortcuts.sort();
        let ac_targets: Vec<Vec<usize>> = shortcuts
            .iter()
            .map(|s| by_shortcut.get(s).cloned().unwrap_or_default())
            .collect();
        let ac = if shortcuts.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .build(&shortcuts)
                .ok()
        };
        // Without an automaton (build failure), every pattern is checked directly.
        if ac.is_none() {
            unshortcut = (0..patterns.len()).collect();
        }
        let ip_rules = IpIndex::new(&rules, ip_rules);
        BundleMatcher {
            action,
            rules,
            effects,
            orders,
            rich,
            suppressors,
            keyed,
            patterns,
            ip_rules,
            ac,
            ac_targets,
            unshortcut,
            regexes: Mutex::new(RegexCache {
                budget: REGEX_CACHE_BUDGET,
                ..RegexCache::default()
            }),
            provider: None,
            dropped: HashSet::new(),
        }
    }

    /// Takes compiled patterns from `provider` instead of compiling its own: every pattern whose
    /// regex builds matches as its regex says (no resident set of its own, so
    /// [`BundleMatcher::patterns_over_budget`] and [`BundleMatcher::patterns_too_large`] report
    /// nothing, and [`BundleMatcher::regex_cache_stats`] stays at zero). The provider owns the
    /// memory budget.
    pub fn with_regex_provider(mut self, provider: Arc<dyn RegexProvider>) -> BundleMatcher {
        self.provider = Some(provider);
        self
    }

    /// Makes the patterns of `rules` (indices into this matcher's rules) match nothing, as the
    /// patterns past the budget or over the NFA limit do in a compile: for a matcher over part of
    /// a bundle (core's replay of one value's candidates), whose own admission would differ from
    /// the whole bundle's (bundles.md §2 Determinism). The rules stay otherwise (a `$badfilter`
    /// among them still cancels what it names).
    pub fn with_patterns_dropped(mut self, rules: impl IntoIterator<Item = usize>) -> BundleMatcher {
        self.dropped.extend(rules);
        self
    }

    /// Sets the memory budget for compiled pattern regexes (default [`REGEX_CACHE_BUDGET`]); the
    /// resident set is decided again on next use.
    pub fn with_regex_budget(self, bytes: usize) -> BundleMatcher {
        if let Ok(mut c) = self.regexes.lock() {
            c.budget = bytes;
            c.admitted = false;
        }
        self
    }

    /// The rules (indices into the matcher's rules, in bundle order) whose pattern doesn't fit in
    /// the regex memory budget: they match nothing here. The compiler drops them from the bundle
    /// and raises a counted `bundle_warning` (rules.md §3 "regex too large", bundles.md §2), so
    /// the edge never has a pattern core doesn't run. Deterministic: bundle order and sizes only.
    pub fn patterns_over_budget(&self) -> Vec<usize> {
        self.dropped(|c| c.over_budget.clone())
    }

    /// The rules whose regex is over the NFA limit ([`crate::analysis::NFA_SIZE_LIMIT`]) among
    /// those built (patterns past the budget aren't built): they match nothing either.
    pub fn patterns_too_large(&self) -> Vec<usize> {
        self.dropped(|c| {
            let mut v: Vec<usize> = c.failed.iter().copied().collect();
            v.sort_unstable();
            v
        })
    }

    fn dropped(&self, f: impl Fn(&RegexCache) -> Vec<usize>) -> Vec<usize> {
        if self.provider.is_some() {
            return Vec::new();
        }
        let Ok(mut c) = self.regexes.lock() else {
            return Vec::new();
        };
        c.admit(&self.patterns);
        f(&c)
            .into_iter()
            .filter_map(|pi| self.patterns.get(pi).map(|p| p.rule))
            .collect()
    }

    /// The compiled regexes' memory now (regex heaps plus lazy-DFA caches, at most the budget
    /// once caches are trimmed), and how many regexes have been built so far.
    pub fn regex_cache_stats(&self) -> (usize, u64) {
        self.regexes
            .lock()
            .map(|c| (c.used(), c.builds))
            .unwrap_or((0, 0))
    }

    /// Gives the matcher the public suffix list, so `$denyallow` entities (`tracker.*`) decide as
    /// in urlfilter ([`crate::entity`]); each entity is expanded once, as the compiler expands it
    /// for the edge, and shared by every rule naming it. Without it a block or rewrite rule naming
    /// an entity doesn't apply ([`BundleMatcher::rules_with_unexpanded_entities`]). Core passes
    /// its bundled list.
    pub fn with_public_suffix_list(mut self, list: &PublicSuffixList) -> BundleMatcher {
        let mut cache: HashMap<String, EntityExpansion> = HashMap::new();
        let mut expand = |ents: &mut Vec<EntityExpansion>| {
            for e in ents.iter_mut() {
                let x = cache
                    .entry(e.prefix.clone())
                    .or_insert_with(|| EntityExpansion::expand(&e.prefix, list));
                *e = x.clone();
            }
        };
        for r in self.rich.iter_mut().flatten() {
            expand(&mut r.denyallow_entities);
        }
        for s in self.suppressors.iter_mut().flatten() {
            expand(&mut s.denyallow_entities);
        }
        self
    }

    /// The rules naming a `$denyallow` entity that isn't expanded (no public suffix list given):
    /// a block or rewrite among them doesn't apply rather than block every name (fail safe,
    /// review round 2, CC4); the caller counts them.
    pub fn rules_with_unexpanded_entities(&self) -> Vec<usize> {
        let own = self
            .rich
            .iter()
            .enumerate()
            .filter(|(_, r)| r.as_ref().is_some_and(RichRule::has_unexpanded_entity))
            .map(|(i, _)| i);
        let suppressors = self
            .suppressors
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.as_ref()
                    .is_some_and(|s| s.denyallow_entities.iter().any(|e| !e.is_expanded()))
            })
            .map(|(i, _)| i);
        let mut v: Vec<usize> = own.chain(suppressors).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// The rules the matcher was built from.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// urlfilter's filing of each rule (index-aligned with [`BundleMatcher::rules`]): what the
    /// compiler stores with each `$dnsrewrite` rich rule ([`crate::order`]).
    pub fn match_orders(&self) -> &[Option<MatchOrder>] {
        &self.orders
    }

    /// The `$badfilter` resolution of the bundle (index-aligned with [`BundleMatcher::rules`]).
    pub fn badfilter_effects(&self) -> &[BadfilterEffect] {
        &self.effects
    }

    /// Matches a query or response-target name given as wire labels, most specific first.
    pub fn match_name(&self, labels: &[&[u8]], ctx: &QueryCtx<'_>) -> MatchResult {
        self.match_labels(labels, ctx, Mode::Query)
    }

    fn match_labels(&self, labels: &[&[u8]], ctx: &QueryCtx<'_>, mode: Mode) -> MatchResult {
        // The root: urlfilter's DNS engine matches nothing for an empty hostname.
        if labels.is_empty() {
            return MatchResult {
                outcome: Outcome::None,
                step: None,
                level: None,
                matches: Vec::new(),
            };
        }
        let text = picket_api::names::adguard_text(labels.iter().copied());
        let mut cands = Vec::new();
        self.keyed_cands(labels, &mut cands);
        self.pattern_cands(&text, &mut cands);
        self.decide(labels, &text, cands, ctx, mode)
    }

    /// Matches ordinary dotted text (convenience for names without `.` bytes in labels).
    pub fn match_dotted(&self, name: &str, ctx: &QueryCtx<'_>) -> MatchResult {
        let owned = crate::name::OwnedName::from_dotted(name);
        self.match_name(&owned.as_labels(), ctx)
    }

    /// Matches a compiled key's name, as a warn or allow bundle checks a block-bundle key
    /// (bundles.md §3: "as it would a query for the key's name").
    pub fn match_key(&self, name: &crate::name::RuleName, ctx: &QueryCtx<'_>) -> MatchResult {
        let labels: Vec<&[u8]> = name.labels().map(str::as_bytes).collect();
        self.match_name(&labels, ctx)
    }

    /// Matches a compiled key's name as some query for it would, of any type and from any client
    /// (bundles.md §3), the check warn and allow bundles make where no single query is meant:
    /// `$dnstype`, `$client` and `$ctag` are taken as met, so a rule limited by them still counts;
    /// an exception limited by them doesn't cancel (in a block or scope bundle), nor does a
    /// `$badfilter` limited by `$dnstype`. `$denyallow` depends only on the name and is exact.
    pub fn match_key_any(&self, name: &crate::name::RuleName) -> MatchResult {
        let labels: Vec<&[u8]> = name.labels().map(str::as_bytes).collect();
        self.match_labels(&labels, &QueryCtx::default(), Mode::AnyQuery)
    }

    /// The IP rules (not removed by `$badfilter`) whose ranges overlap `range`: how a warn or allow
    /// bundle matches a block bundle's IP rule (bundles.md §3).
    pub fn overlapping_ip_rules(&self, range: &crate::ip::IpRange) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .ip_rules
            .overlapping(range)
            .filter(|&i| !matches!(self.effects.get(i), Some(BadfilterEffect::Removed { .. })))
            .collect();
        out.sort_unstable();
        out
    }

    /// Matches an address (an answer IP or HTTPS/SVCB hint, rules.md §6): IP rules by range, plus
    /// every rule that matches its Go text as AdGuard matches it.
    pub fn match_ip(&self, ip: IpAddr, ctx: &QueryCtx<'_>) -> MatchResult {
        let ip = canonical_ip(ip);
        let text = go_ip_string(ip);
        let label_strs: Vec<&str> = if ip.is_ipv4() {
            text.split('.').collect()
        } else {
            vec![text.as_str()]
        };
        let labels: Vec<&[u8]> = label_strs.iter().map(|s| s.as_bytes()).collect();
        let mut cands = Vec::new();
        let mut covering: Vec<(usize, crate::ip::IpRange)> = self
            .ip_rules
            .overlapping_entries(&crate::ip::IpRange::single(ip))
            .collect();
        covering.sort_unstable_by_key(|&(i, _)| i);
        for (i, range) in covering {
            let Some(r) = self.rules.get(i) else { continue };
            let applying = r.flags.exact().union(r.flags.subs_as_exact());
            let depth = u32::from(range.prefix_len().unwrap_or(0));
            cands.push(Cand {
                rule: i,
                applying,
                how: MatchHow::IpRange,
                depth,
                removed: None,
            });
        }
        let mut keyed = Vec::new();
        self.keyed_cands(&labels, &mut keyed);
        for c in keyed {
            if !cands.iter().any(|x| x.rule == c.rule) {
                cands.push(c);
            }
        }
        self.pattern_cands(&text, &mut cands);
        self.decide(&labels, &text, cands, ctx, Mode::Query)
    }

    fn keyed_cands(&self, labels: &[&[u8]], out: &mut Vec<Cand>) {
        if self.keyed.is_empty() || labels.is_empty() {
            return;
        }
        // Suffixes that include a label holding a `.` byte match no key (rules.md §3).
        let first_ok = labels
            .iter()
            .rposition(|l| l.contains(&b'.'))
            .map_or(0, |j| j.saturating_add(1));
        let n = labels.len();
        let mut key = String::new();
        for start in first_ok..n {
            key.clear();
            for (k, l) in labels.get(start..).unwrap_or(&[]).iter().rev().enumerate() {
                if k > 0 {
                    key.push('.');
                }
                for &b in l.iter() {
                    key.push(char::from(b.to_ascii_lowercase()));
                }
            }
            let Some(ids) = self.keyed.get(&key) else { continue };
            let at_name = start == 0;
            let depth = u32::try_from(n.saturating_sub(start)).unwrap_or(u32::MAX);
            for &i in ids {
                let Some(r) = self.rules.get(i) else { continue };
                let applying = r.flags.applying(at_name);
                if applying.is_empty() {
                    continue;
                }
                let how = MatchHow::Key {
                    labels: u8::try_from(depth).unwrap_or(u8::MAX),
                    at_name,
                };
                out.push(Cand {
                    rule: i,
                    applying,
                    how,
                    depth,
                    removed: None,
                });
            }
        }
    }

    fn pattern_cands(&self, text: &str, out: &mut Vec<Cand>) {
        if self.patterns.is_empty() {
            return;
        }
        let mut url = String::with_capacity(URL_PREFIX.len().saturating_add(text.len()));
        url.push_str(URL_PREFIX);
        url.push_str(text);
        let mut todo: HashSet<usize> = self.unshortcut.iter().copied().collect();
        if let Some(ac) = &self.ac {
            for m in ac.find_overlapping_iter(url.as_str()) {
                if let Some(t) = self.ac_targets.get(m.pattern().as_usize()) {
                    todo.extend(t.iter().copied());
                }
            }
        }
        let mut todo: Vec<usize> = todo.into_iter().collect();
        todo.sort_unstable();
        for pi in todo {
            let Some(p) = self.patterns.get(pi) else { continue };
            if !shortcut_present(p.spec.shortcut.as_deref(), text) || self.dropped.contains(&p.rule) {
                continue;
            }
            let hit = if p.spec.matches_all {
                true
            } else if let Some(provider) = &self.provider {
                let hay = match p.spec.target {
                    MatchTarget::Host => text,
                    MatchTarget::HttpHost => url.as_str(),
                };
                p.spec
                    .regex
                    .as_deref()
                    .is_some_and(|src| provider.is_match(src, hay))
            } else {
                let compiled = match self.regexes.lock() {
                    Ok(mut c) => c.get(pi, &self.patterns),
                    Err(_) => None,
                };
                match compiled {
                    Some((re, cache)) => {
                        let hay = match p.spec.target {
                            MatchTarget::Host => text,
                            MatchTarget::HttpHost => url.as_str(),
                        };
                        let (hit, bytes) = match cache.lock() {
                            Ok(mut c) => {
                                let hit = re
                                    .search_with(&mut c, &regex_automata::Input::new(hay).earliest(true))
                                    .is_some();
                                (hit, c.memory_usage())
                            }
                            Err(_) => (re.is_match(hay), 0),
                        };
                        if let Ok(mut c) = self.regexes.lock() {
                            c.measured(pi, bytes);
                        }
                        hit
                    }
                    None => false,
                }
            };
            if hit {
                let Some(r) = self.rules.get(p.rule) else { continue };
                let applying = r.flags.exact().union(r.flags.subs_as_exact());
                out.push(Cand {
                    rule: p.rule,
                    applying,
                    how: MatchHow::Pattern,
                    depth: 0,
                    removed: None,
                });
            }
        }
    }

    /// The `$badfilter` rule (if any) that removes `rule` for this query.
    fn removed_by(
        &self,
        rule: usize,
        labels: &[&[u8]],
        text: &str,
        ctx: &QueryCtx<'_>,
        sem: NameSemantics,
        mode: Mode,
    ) -> Option<usize> {
        let by = match self.effects.get(rule) {
            Some(BadfilterEffect::Removed { by } | BadfilterEffect::Suppressed { by, .. }) => by,
            _ => return None,
        };
        by.iter().copied().find(|&b| {
            let Some(Some(s)) = self.suppressors.get(b) else {
                return false;
            };
            match mode {
                Mode::Query => s.suppresses(labels, text, ctx, sem),
                // Some query of another type keeps the rule: only a context-free one removes it.
                Mode::AnyQuery => s.dnstype.is_none() && s.suppresses(labels, text, ctx, sem),
            }
        })
    }

    fn decide(
        &self,
        labels: &[&[u8]],
        text: &str,
        cands: Vec<Cand>,
        ctx: &QueryCtx<'_>,
        mode: Mode,
    ) -> MatchResult {
        // Conditions, then `$badfilter`.
        let mut live: Vec<Cand> = Vec::new();
        for mut c in cands {
            let Some(r) = self.rules.get(c.rule) else { continue };
            let sem = match c.how {
                MatchHow::Pattern => NameSemantics::Text,
                _ => NameSemantics::Labels,
            };
            if let Some(Some(rich)) = self.rich.get(c.rule) {
                let ok = match mode {
                    Mode::Query => rich.conditions_match(labels, text, ctx, sem),
                    Mode::AnyQuery => {
                        let cancels_only_some =
                            rich.depends_on_query() && r.is_exception() && self.action != BundleAction::Allow;
                        !cancels_only_some && rich.conditions_match_any_query(labels, text, sem)
                    }
                };
                if !ok {
                    continue;
                }
            }
            c.removed = self.removed_by(c.rule, labels, text, ctx, sem, mode);
            live.push(c);
        }
        live.sort_by_key(|c| c.rule);
        live.dedup_by_key(|c| c.rule);
        let rules = &self.rules;
        let spec_of = |c: &Cand| -> u32 {
            let n = rules.get(c.rule).map_or(0, |r| r.spec.specifier_count(r.flags));
            n.saturating_mul(1000).saturating_add(c.depth)
        };
        let rank_of = |c: &Cand| -> (u8, u32) {
            let host = rules
                .get(c.rule)
                .is_some_and(|r| (r.kind == Kind::Name && r.spec.pattern.is_none()) || r.spec.host_rule);
            (u8::from(host), spec_of(c))
        };
        let mk_by = |c: &Cand, role: Role, by: Option<usize>| RuleMatch {
            rule: c.rule,
            role,
            level: c.applying.top_level(),
            specificity: spec_of(c),
            how: c.how,
            by,
        };
        let mk = |c: &Cand, role: Role| mk_by(c, role, None);
        let mut matches: Vec<RuleMatch> = live
            .iter()
            .filter(|c| c.removed.is_some())
            .map(|c| mk_by(c, Role::Overridden(OverriddenBy::Badfilter), c.removed))
            .collect();
        let active: Vec<Cand> = live.into_iter().filter(|c| c.removed.is_none()).collect();
        let is_rewrite = |c: &Cand| rules.get(c.rule).is_some_and(Rule::is_rewrite);
        let is_mapping = |c: &Cand| rules.get(c.rule).is_some_and(Rule::is_mapping);

        if self.action == BundleAction::Allow {
            if active.is_empty() {
                return MatchResult {
                    outcome: Outcome::None,
                    step: None,
                    level: None,
                    matches,
                };
            }
            let best = best_of(&active, &rank_of);
            for c in &active {
                matches.push(mk(
                    c,
                    if Some(c.rule) == best.map(|b| b.rule) {
                        Role::Decisive
                    } else {
                        Role::AlsoMatched
                    },
                ));
            }
            return MatchResult {
                outcome: Outcome::Allow,
                step: Some(Step::Network),
                level: best.and_then(|b| b.applying.top_level()),
                matches,
            };
        }

        // 1. Rewrites, in urlfilter's matched-rule order (a rule once per listing).
        let rw_matched: Vec<&Cand> = active.iter().filter(|c| is_rewrite(c)).collect();
        let orders: Vec<MatchOrder> = rw_matched
            .iter()
            .map(|c| {
                self.orders.get(c.rule).copied().flatten().unwrap_or(MatchOrder {
                    gram: None,
                    seq: u32::try_from(c.rule).unwrap_or(u32::MAX),
                })
            })
            .collect();
        let rw: Vec<&Cand> = sequence(text, &orders)
            .into_iter()
            .filter_map(|k| rw_matched.get(k).copied())
            .collect();
        let mut handled: HashSet<usize> = HashSet::new();
        if !rw.is_empty() {
            let cands: Vec<RewriteCandidate<'_>> = rw
                .iter()
                .filter_map(|c| {
                    let r = rules.get(c.rule)?;
                    Some(RewriteCandidate {
                        rewrite: r.spec.dnsrewrite.as_ref()?,
                        important: r.is_important(),
                        exception: r.is_exception(),
                    })
                })
                .collect();
            let (left, removed) = apply_rewrite_exceptions_by(&cands);
            let left_rules: HashSet<usize> = left.iter().filter_map(|&i| rw.get(i)).map(|c| c.rule).collect();
            for &(ri, by) in &removed {
                if let Some(c) = rw.get(ri) {
                    // A rule listed twice can be removed once and still answer.
                    if left_rules.contains(&c.rule) || !handled.insert(c.rule) {
                        continue;
                    }
                    let by = rw.get(by).map(|e| e.rule);
                    matches.push(mk_by(c, Role::Overridden(OverriddenBy::RewriteException), by));
                }
            }
            let left_rw: Vec<&crate::rewrite::DnsRewrite> = left
                .iter()
                .filter_map(|&i| cands.get(i).map(|c| c.rewrite))
                .collect();
            if let Some((answer, used)) = merge_rewrites(&left_rw) {
                let self_cname = matches!(&answer, RewriteAnswer::Cname(c) if c.as_str() == text);
                if !self_cname {
                    let used_rules: HashSet<usize> = used
                        .iter()
                        .filter_map(|&u| left.get(u))
                        .filter_map(|&i| rw.get(i))
                        .map(|c| c.rule)
                        .collect();
                    for c in &active {
                        if handled.contains(&c.rule) {
                            continue;
                        }
                        matches.push(mk(
                            c,
                            if used_rules.contains(&c.rule) {
                                Role::Decisive
                            } else {
                                Role::AlsoMatched
                            },
                        ));
                    }
                    return MatchResult {
                        outcome: self.finish(Outcome::Rewrite(answer)),
                        step: Some(Step::Rewrite),
                        level: None,
                        matches,
                    };
                }
            }
        }

        // 2. Network rules (host rules fold in as level-4 blocks; they rank last within it).
        let basic: Vec<&Cand> = active
            .iter()
            .filter(|c| !is_rewrite(c) && !is_mapping(c))
            .collect();
        if let Some(best) = best_of_refs(&basic, &rank_of) {
            let level = best.applying.top_level();
            let exception = level.is_some_and(Level::is_allow);
            for c in &active {
                if handled.contains(&c.rule) {
                    continue;
                }
                let role = if c.rule == best.rule {
                    Role::Decisive
                } else if exception
                    && (is_mapping(c)
                        || is_rewrite(c)
                        || c.applying
                            .top_level()
                            .zip(level)
                            .is_some_and(|(cl, bl)| cl > bl && !cl.is_allow()))
                {
                    if is_rewrite(c) {
                        Role::AlsoMatched
                    } else {
                        Role::Overridden(OverriddenBy::Exception)
                    }
                } else {
                    Role::AlsoMatched
                };
                let by = matches!(role, Role::Overridden(_)).then_some(best.rule);
                matches.push(mk_by(c, role, by));
            }
            let outcome = if exception {
                Outcome::Exception
            } else {
                Outcome::Block
            };
            return MatchResult {
                outcome: self.finish(outcome),
                step: Some(Step::Network),
                level,
                matches,
            };
        }

        // 3. Host-IP mappings.
        let maps: Vec<&Cand> = active.iter().filter(|c| is_mapping(c)).collect();
        for c in &active {
            if handled.contains(&c.rule) {
                continue;
            }
            matches.push(mk(
                c,
                if is_mapping(c) {
                    Role::Decisive
                } else {
                    Role::AlsoMatched
                },
            ));
        }
        if !maps.is_empty() {
            let mut ips: Vec<IpAddr> = maps
                .iter()
                .filter_map(|c| rules.get(c.rule))
                .filter_map(|r| r.spec.hosts_ip)
                .collect();
            ips.sort();
            ips.dedup();
            return MatchResult {
                outcome: self.finish(Outcome::HostMapping(ips)),
                step: Some(Step::Hosts),
                level: Some(Level::Block),
                matches,
            };
        }
        MatchResult {
            outcome: Outcome::None,
            step: None,
            level: None,
            matches,
        }
    }

    /// Maps a block-bundle outcome to a scope bundle's.
    fn finish(&self, o: Outcome) -> Outcome {
        if self.action != BundleAction::Scope {
            return o;
        }
        match o {
            Outcome::Block | Outcome::Rewrite(_) | Outcome::HostMapping(_) => Outcome::InScope,
            _ => Outcome::None,
        }
    }
}

/// The bundle's IP rules sorted by family and first address, with the running maximum of their
/// last addresses, so the rules covering an address (or overlapping a range) are found by a binary
/// search and a walk back over the ones that can still reach it, not a scan of every rule.
struct IpIndex {
    /// (range, rule index), IPv4 first, then by first address.
    entries: Vec<(crate::ip::IpRange, usize)>,
    /// `max_last[i]`: the greatest `last` among `entries[family start..=i]`.
    max_last: Vec<u128>,
    /// Where the IPv6 entries start.
    v6_start: usize,
}

impl IpIndex {
    fn new(rules: &[Rule], ids: Vec<usize>) -> IpIndex {
        let mut entries: Vec<(crate::ip::IpRange, usize)> = ids
            .into_iter()
            .filter_map(|i| rules.get(i).and_then(Rule::ip_range).map(|r| (r, i)))
            .collect();
        entries.sort_unstable_by_key(|(r, i)| (!r.v4, r.first, r.last, *i));
        let v6_start = entries.partition_point(|(r, _)| r.v4);
        let mut max_last = Vec::with_capacity(entries.len());
        let mut max = 0u128;
        for (k, (r, _)) in entries.iter().enumerate() {
            if k == v6_start {
                max = 0;
            }
            max = max.max(r.last);
            max_last.push(max);
        }
        IpIndex {
            entries,
            max_last,
            v6_start,
        }
    }

    /// The entries whose range overlaps `range`, in no particular order.
    fn overlapping_entries<'a>(
        &'a self,
        range: &'a crate::ip::IpRange,
    ) -> impl Iterator<Item = (usize, crate::ip::IpRange)> + 'a {
        let (lo, hi) = if range.v4 {
            (0, self.v6_start)
        } else {
            (self.v6_start, self.entries.len())
        };
        let family = self.entries.get(lo..hi).unwrap_or(&[]);
        let end = lo.saturating_add(family.partition_point(|(r, _)| r.first <= range.last));
        (lo..end)
            .rev()
            .take_while(move |&k| self.max_last.get(k).is_some_and(|&m| m >= range.first))
            .filter_map(move |k| self.entries.get(k))
            .filter(move |(r, _)| r.last >= range.first)
            .map(|&(r, i)| (i, r))
    }

    /// The rule indices whose range overlaps `range`.
    fn overlapping<'a>(&'a self, range: &'a crate::ip::IpRange) -> impl Iterator<Item = usize> + 'a {
        self.overlapping_entries(range).map(|(i, _)| i)
    }
}

/// The top candidate: highest level, then network rules before host rules (AdGuard Home consults
/// host rules only when no network rule matched), then most specific, then first in bundle order.
/// `spec` gives (host-rule rank, specificity).
fn best_of<'a>(cands: &'a [Cand], spec: &dyn Fn(&Cand) -> (u8, u32)) -> Option<&'a Cand> {
    let refs: Vec<&Cand> = cands.iter().collect();
    best_of_refs(&refs, spec)
}

fn best_of_refs<'a>(cands: &[&'a Cand], spec: &dyn Fn(&Cand) -> (u8, u32)) -> Option<&'a Cand> {
    cands
        .iter()
        .filter(|c| c.applying.top_level().is_some())
        .min_by_key(|c| {
            let (host, sp) = spec(c);
            (
                c.applying.top_level().map_or(u8::MAX, Level::number),
                host,
                std::cmp::Reverse(sp),
                c.rule,
            )
        })
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Item, Line, classify_adblock_line};
    use crate::name::OwnedName;
    use crate::rewrite::RewriteValue;
    use crate::rrtype::types;

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

    fn m(lines: &[&str]) -> BundleMatcher {
        BundleMatcher::new(BundleAction::Block, rules(lines))
    }

    const A: QueryCtx<'static> = QueryCtx {
        qtype: types::A,
        client_ip: None,
        client_names: &[],
        client_tags: &[],
    };

    fn out(mm: &BundleMatcher, name: &str) -> Outcome {
        mm.match_dotted(name, &A).outcome
    }

    #[test]
    fn dropped_patterns_match_nothing_and_badfilters_still_apply() {
        // Core's replay of part of a bundle drops the patterns the whole bundle's compile left out
        // (bundles.md §2 Determinism), with or without a provider.
        let lines = ["/block\\.example/", "@@/block\\.example/"];
        assert_eq!(out(&m(&lines), "block.example"), Outcome::Exception);
        let dropped = m(&lines).with_patterns_dropped([1]);
        assert_eq!(out(&dropped, "block.example"), Outcome::Block);
        assert_eq!(
            out(&m(&lines).with_patterns_dropped([0, 1]), "block.example"),
            Outcome::None
        );
        // A `$badfilter` among the rules still cancels what it names.
        let bf = ["/block\\.example/", "/block\\.example/$badfilter"];
        assert_eq!(
            out(&m(&bf).with_patterns_dropped([1]), "block.example"),
            Outcome::None
        );
    }

    fn bundled_psl() -> PublicSuffixList {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/picket-core/data/public_suffix_list.dat"
        );
        PublicSuffixList::parse(&std::fs::read_to_string(path).expect("bundled PSL"))
    }

    #[test]
    fn entity_expansions_are_shared_and_fail_safe() {
        // CC4: every rule naming `tracker.*` shares one expansion (7k suffix rules each before),
        // and a rule whose entity wasn't expanded (no public suffix list) never blocks: it is
        // listed, not turned into a block of every name.
        let lines: Vec<String> = (0..200)
            .map(|i| format!("||a{i}.com^$denyallow=tracker.*"))
            .chain([
                "*$denyallow=tracker.*".to_string(),
                "@@||x.a1.com^$denyallow=tracker.*".to_string(),
            ])
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let bare = m(&refs);
        assert_eq!(out(&bare, "example.com"), Outcome::None, "unexpanded: fail safe");
        assert_eq!(out(&bare, "a5.com"), Outcome::None);
        assert_eq!(bare.rules_with_unexpanded_entities().len(), 202);
        let psl = bundled_psl();
        let full = m(&refs).with_public_suffix_list(&psl);
        assert!(full.rules_with_unexpanded_entities().is_empty());
        assert_eq!(out(&full, "example.com"), Outcome::Block);
        assert_eq!(out(&full, "tracker.co.uk"), Outcome::None);
        assert_eq!(out(&full, "tracker.a5.com"), Outcome::Block);
        assert_eq!(out(&full, "x.a1.com"), Outcome::Exception);
        let first = full.rich[0].as_ref().unwrap().denyallow_entities[0].clone();
        for r in full.rich.iter().flatten() {
            for e in &r.denyallow_entities {
                assert!(e.shares_expansion_with(&first), "one shared expansion");
            }
        }
    }

    #[test]
    fn parity_examples() {
        // build-and-test.md §5 "AdGuard parity".
        let b = m(&["||d.example^", "|d.example^$important", "@@||d.example^"]);
        assert_eq!(out(&b, "d.example"), Outcome::Block);
        assert_eq!(out(&b, "sub.d.example"), Outcome::Exception);
        let b = m(&["||d.example^$important", "|d.example^", "@@||d.example^"]);
        assert_eq!(out(&b, "d.example"), Outcome::Block);
        assert_eq!(out(&b, "sub.d.example"), Outcome::Block);
        let b = m(&["192.0.2.10 d.example", "@@||d.example^"]);
        assert_eq!(out(&b, "d.example"), Outcome::Exception);
        let b = m(&["192.0.2.10 d.example"]);
        assert_eq!(
            out(&b, "d.example"),
            Outcome::HostMapping(vec!["192.0.2.10".parse().unwrap()])
        );
    }

    #[test]
    fn unusual_bytes() {
        // rules.md §3.
        let b = m(&["||evil.example^"]);
        let n = |l: Vec<&[u8]>| b.match_name(&l, &A).outcome;
        assert_eq!(n(vec![b"a!b", b"evil", b"example"]), Outcome::Block);
        assert_eq!(n(vec![b"evil", b"example!x"]), Outcome::None);
        assert_eq!(n(vec![b"evil", b"example!x", b"attacker", b"net"]), Outcome::None);
        assert_eq!(
            n(vec![b"x", b"evil.example"]),
            Outcome::None,
            "a suffix with a `.` byte label matches no key"
        );
        assert_eq!(n(vec![b"evil.example"]), Outcome::None);
        assert_eq!(
            n(vec![b"a.b", b"evil", b"example"]),
            Outcome::Block,
            "the label with a dot is below the key"
        );
        let p = m(&["/[!]/"]);
        assert_eq!(p.match_name(&[b"a!b", b"example"], &A).outcome, Outcome::Block);
        assert_eq!(p.match_name(&[b"ab", b"example"], &A).outcome, Outcome::None);
        let d = m(&["||example^$denyallow=evil.example"]);
        assert_eq!(
            d.match_name(&[b"a!b", b"evil", b"example"], &A).outcome,
            Outcome::None,
            "denyallow by whole labels"
        );
        assert_eq!(d.match_name(&[b"x", b"example"], &A).outcome, Outcome::Block);
        assert_eq!(
            d.match_name(&[b"evil", b"example!x", b"example"], &A).outcome,
            Outcome::Block
        );
        // A pattern keeps AdGuard's text form: `.` inside a label is `\.`.
        let t = m(&["/a\\\\\\.b\\.example/"]);
        assert_eq!(t.match_name(&[b"a.b", b"example"], &A).outcome, Outcome::Block);
        let o = OwnedName::from_labels(vec![b"A.B".to_vec(), b"example".to_vec()]);
        assert_eq!(t.match_name(&o.as_labels(), &A).outcome, Outcome::Block);
    }

    #[test]
    fn rewrites() {
        let b = m(&[
            "||r.example^$dnsrewrite=1.2.3.4",
            "||r.example^$dnsrewrite=1.2.3.5",
            "@@||r.example^$dnsrewrite=1.2.3.4",
            "||r.example^",
        ]);
        let res = b.match_dotted("r.example", &A);
        assert_eq!(
            res.outcome,
            Outcome::Rewrite(RewriteAnswer::Records(vec![(
                1,
                RewriteValue::Ip("1.2.3.5".parse().unwrap())
            )]))
        );
        let cancelled: Vec<(usize, Option<usize>)> = res
            .matches
            .iter()
            .filter(|m| m.role == Role::Overridden(OverriddenBy::RewriteException))
            .map(|m| (m.rule, m.by))
            .collect();
        assert_eq!(cancelled, vec![(0, Some(2))], "the @@…$dnsrewrite rule is named");
        let b = m(&[
            "||c.example^$dnsrewrite=1.2.3.4",
            "||c.example^$dnsrewrite=target.example",
        ]);
        assert_eq!(
            out(&b, "c.example"),
            Outcome::Rewrite(RewriteAnswer::Cname("target.example".into()))
        );
        let b = m(&["||n.example^$dnsrewrite=NXDOMAIN;;"]);
        assert_eq!(out(&b, "n.example"), Outcome::Rewrite(RewriteAnswer::Rcode(3)));
        let b = m(&[
            "||s.example^$dnsrewrite=s.example",
            "||s.example^$dnsrewrite=1.2.3.4",
            "||s.example^",
        ]);
        assert_eq!(
            out(&b, "s.example"),
            Outcome::Block,
            "a CNAME to itself is ignored"
        );
        let b = m(&[
            "||x.example^$dnsrewrite=1.2.3.4",
            "@@||x.example^$dnsrewrite",
            "||x.example^",
        ]);
        assert_eq!(
            out(&b, "x.example"),
            Outcome::Block,
            "@@…$dnsrewrite cancels rewrites only"
        );
        let b = m(&[
            "192.0.2.1 h.example",
            "||h.example^$dnsrewrite=1.2.3.4",
            "@@||h.example^$dnsrewrite",
        ]);
        assert_eq!(
            out(&b, "h.example"),
            Outcome::HostMapping(vec!["192.0.2.1".parse().unwrap()]),
            "@@…$dnsrewrite doesn't stop a mapping"
        );
        let b = m(&[
            "||b.example^$dnsrewrite=1.2.3.4",
            "||b.example^$dnsrewrite=1.2.3.4,badfilter",
        ]);
        assert!(
            matches!(out(&b, "b.example"), Outcome::Rewrite(_)),
            "AdGuard: $badfilter doesn't touch rewrites"
        );
    }

    #[test]
    fn modifiers() {
        let b = m(&[
            "||t.example^$dnstype=AAAA",
            "||c.example^$client=192.168.1.0/24",
            "||g.example^$ctag=device_phone",
            "||k.example^$client='Frank\\'s laptop'",
        ]);
        assert_eq!(b.match_dotted("t.example", &A).outcome, Outcome::None);
        assert_eq!(
            b.match_dotted(
                "t.example",
                &QueryCtx {
                    qtype: types::AAAA,
                    ..A
                }
            )
            .outcome,
            Outcome::Block
        );
        let ip: IpAddr = "192.168.1.9".parse().unwrap();
        assert_eq!(
            b.match_dotted(
                "c.example",
                &QueryCtx {
                    client_ip: Some(ip),
                    ..A
                }
            )
            .outcome,
            Outcome::Block
        );
        assert_eq!(b.match_dotted("c.example", &A).outcome, Outcome::None);
        assert_eq!(
            b.match_dotted(
                "g.example",
                &QueryCtx {
                    client_tags: &["device_phone"],
                    ..A
                }
            )
            .outcome,
            Outcome::Block
        );
        assert_eq!(
            b.match_dotted(
                "k.example",
                &QueryCtx {
                    client_names: &["Frank's laptop"],
                    ..A
                }
            )
            .outcome,
            Outcome::Block
        );
    }

    #[test]
    fn badfilter_conditional() {
        let b = m(&["||f.example^", "||f.example^$badfilter,dnstype=AAAA"]);
        assert_eq!(b.match_dotted("f.example", &A).outcome, Outcome::Block);
        let r = b.match_dotted(
            "f.example",
            &QueryCtx {
                qtype: types::AAAA,
                ..A
            },
        );
        assert_eq!(r.outcome, Outcome::None);
        assert_eq!(r.matches[0].role, Role::Overridden(OverriddenBy::Badfilter));
        assert_eq!(r.matches[0].by, Some(1), "the $badfilter rule is named");
        let b = m(&[
            "||g.example^",
            "||g.example^$badfilter,dnstype=AAAA",
            "||g.example^$badfilter",
        ]);
        let r = b.match_dotted("g.example", &A);
        assert_eq!(
            (r.outcome, r.matches[0].by),
            (Outcome::None, Some(2)),
            "the $badfilter that applies to this query"
        );
    }

    #[test]
    fn any_query_key_matching() {
        // bundles.md §3: a warn or allow bundle matches a key "as it would a query for the key's
        // name", whatever its type or client.
        let key = |mm: &BundleMatcher, n: &str| {
            mm.match_key_any(&crate::name::RuleName::parse(n).unwrap())
                .outcome
        };
        let warn = BundleMatcher::new(
            BundleAction::Allow,
            rules(&[
                "||cond.example^$dnstype=AAAA",
                "||kid.example^$client=kid",
                "@@||tagged.example^$ctag=device_tv",
                "||d.example^$denyallow=ok.d.example",
            ]),
        );
        for n in ["cond.example", "x.kid.example", "tagged.example", "d.example"] {
            assert_eq!(key(&warn, n), Outcome::Allow, "{n}");
        }
        assert_eq!(key(&warn, "ok.d.example"), Outcome::None, "$denyallow is exact");
        assert_eq!(
            warn.match_key(&crate::name::RuleName::parse("cond.example").unwrap(), &A)
                .outcome,
            Outcome::None,
            "a single A query doesn't meet $dnstype=AAAA"
        );
        let block = m(&[
            "||x.example^",
            "@@||x.example^$client=kid",
            "||y.example^",
            "@@||y.example^",
            "||f.example^",
            "||f.example^$badfilter,dnstype=AAAA",
            "||g.example^",
            "||g.example^$badfilter",
        ]);
        assert_eq!(
            key(&block, "x.example"),
            Outcome::Block,
            "a conditional exception doesn't cancel"
        );
        assert_eq!(key(&block, "y.example"), Outcome::Exception);
        assert_eq!(
            key(&block, "f.example"),
            Outcome::Block,
            "nor does a conditional $badfilter"
        );
        assert_eq!(key(&block, "g.example"), Outcome::None);
        let scope = BundleMatcher::new(
            BundleAction::Scope,
            rules(&["||s.example^", "@@||s.example^$dnstype=A"]),
        );
        assert_eq!(key(&scope, "s.example"), Outcome::InScope);
    }

    #[test]
    fn ip_matching() {
        let b = m(&["||1.2.3.4^", "||10.0.0^", "0.0.0.0 5.6.7.8"]);
        let ip = |s: &str| b.match_ip(s.parse().unwrap(), &A).outcome;
        assert_eq!(ip("1.2.3.4"), Outcome::Block);
        assert_eq!(ip("::ffff:1.2.3.4"), Outcome::Block);
        assert_eq!(ip("1.2.3.5"), Outcome::None);
        // A partial-IP key matches the address text's last labels, as AdGuard's regex does.
        assert_eq!(ip("1.10.0.0"), Outcome::Block, "partial-IP key");
        assert_eq!(
            ip("10.0.0.7"),
            Outcome::None,
            "`.7` follows: no separator in AdGuard either"
        );
        assert_eq!(ip("5.6.7.8"), Outcome::Block, "hosts line naming an address");
        // The name `1.2.3.4` is decided exactly as urlfilter does.
        assert_eq!(out(&b, "1.2.3.4"), Outcome::Block);
        assert_eq!(out(&b, "x.1.2.3.4"), Outcome::Block);
        let b = m(&["|1.2.3.4^", "@@||1.2.3.4^$important", "||2001:db8::1^"]);
        assert_eq!(
            b.match_ip("1.2.3.4".parse().unwrap(), &A).outcome,
            Outcome::Exception
        );
        assert_eq!(
            b.match_ip("2001:db8::1".parse().unwrap(), &A).outcome,
            Outcome::Block
        );
        assert_eq!(
            b.match_ip("2001:db8::2".parse().unwrap(), &A).outcome,
            Outcome::None
        );
        let ranges = BundleMatcher::new(
            BundleAction::Block,
            vec![crate::formats::ip_indicator(
                crate::ip::IpRange::parse("10.0.0.0/8").unwrap(),
            )],
        );
        assert_eq!(
            ranges.match_ip("10.9.9.9".parse().unwrap(), &A).outcome,
            Outcome::Block
        );
        assert_eq!(
            ranges.match_dotted("10.9.9.9", &A).outcome,
            Outcome::None,
            "an indicator is never a pattern"
        );
        // The IP index finds every covering rule, nested and overlapping ranges included.
        let nested = BundleMatcher::new(
            BundleAction::Block,
            [
                "10.0.0.0/8",
                "10.1.0.0/16",
                "10.1.2.0/24",
                "11.0.0.0/8",
                "10.200.0.0/16",
                "2001:db8::/32",
            ]
            .iter()
            .map(|s| crate::formats::ip_indicator(crate::ip::IpRange::parse(s).unwrap()))
            .collect(),
        );
        let hits = |s: &str| {
            let mut v: Vec<usize> = nested
                .match_ip(s.parse().unwrap(), &A)
                .matches
                .iter()
                .map(|mm| mm.rule)
                .collect();
            v.sort_unstable();
            v
        };
        assert_eq!(hits("10.1.2.3"), vec![0, 1, 2]);
        assert_eq!(hits("10.200.1.1"), vec![0, 4]);
        assert_eq!(hits("10.2.0.1"), vec![0]);
        assert_eq!(hits("12.0.0.1"), Vec::<usize>::new());
        assert_eq!(hits("2001:db8::5"), vec![5]);
        assert_eq!(hits("::ffff:10.1.2.3"), vec![0, 1, 2]);
        assert_eq!(
            nested.overlapping_ip_rules(&crate::ip::IpRange::parse("10.1.0.0/20").unwrap()),
            vec![0, 1, 2]
        );
        assert_eq!(
            nested.overlapping_ip_rules(&crate::ip::IpRange::parse("0.0.0.0/0").unwrap()),
            vec![0, 1, 2, 3, 4]
        );
        let da = m(&["||10.0.0^$denyallow=example.com"]);
        assert_eq!(
            da.match_ip("1.10.0.0".parse().unwrap(), &A).outcome,
            Outcome::None,
            "$denyallow never matches IP text"
        );
    }

    #[test]
    fn allow_and_scope_bundles() {
        let a = BundleMatcher::new(
            BundleAction::Allow,
            rules(&[
                "||a.example^",
                "||r.example^$dnsrewrite=1.2.3.4",
                "192.0.2.1 h.example",
                "@@||e.example^",
            ]),
        );
        for n in ["a.example", "x.a.example", "r.example", "h.example", "e.example"] {
            assert_eq!(a.match_dotted(n, &A).outcome, Outcome::Allow, "{n}");
        }
        assert_eq!(a.match_dotted("z.example", &A).outcome, Outcome::None);
        let all = BundleMatcher::new(BundleAction::Block, rules(&["||*^"]));
        assert_eq!(
            all.match_name(&[], &A).outcome,
            Outcome::None,
            "the root matches nothing"
        );
        let s = BundleMatcher::new(
            BundleAction::Scope,
            rules(&["||s.example^", "@@||ok.s.example^", "||1.2.3.4^"]),
        );
        assert_eq!(s.match_dotted("x.s.example", &A).outcome, Outcome::InScope);
        assert_eq!(s.match_dotted("ok.s.example", &A).outcome, Outcome::None);
        assert_eq!(
            s.match_dotted("1.2.3.4", &A).outcome,
            Outcome::None,
            "only dns rules count"
        );
    }

    #[test]
    fn roles() {
        let b = m(&[
            "||d.example^",
            "|d.example^$important",
            "@@||d.example^",
            "d.example",
        ]);
        let r = b.match_dotted("sub.d.example", &A);
        let role = |i: usize| r.matches.iter().find(|m| m.rule == i).map(|m| m.role);
        assert_eq!(role(2), Some(Role::Decisive));
        assert_eq!(role(0), Some(Role::Overridden(OverriddenBy::Exception)));
        assert_eq!(r.matches.iter().find(|m| m.rule == 0).and_then(|m| m.by), Some(2));
        assert_eq!(role(1), None);
        let r = b.match_dotted("d.example", &A);
        let role = |i: usize| r.matches.iter().find(|m| m.rule == i).map(|m| m.role);
        assert_eq!(role(1), Some(Role::Decisive));
        assert_eq!(role(0), Some(Role::AlsoMatched));
        assert_eq!(role(2), Some(Role::AlsoMatched));
        assert_eq!(role(3), Some(Role::AlsoMatched));
        assert_eq!(r.level, Some(Level::ImportantBlock));
    }
}
