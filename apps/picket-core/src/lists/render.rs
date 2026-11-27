//! Building browser list text (bundles.md §8), pure functions over rule texts in order, so they
//! are tested (and fuzzed) without storage.
//!
//! - **Bundle lists** ([`bundle_list`]): the bundle's `browser` rules, deduplicated, an allow
//!   bundle's written as exceptions ([`allow_conversion`]: `$redirect` / `$redirect-rule` rules
//!   dropped and counted).
//! - **Profile lists** ([`profile_lists`]): the allow bundles' rules as exceptions, then the block
//!   bundles' rules in profile order (a rule two bundles share under the first); blocks an allow
//!   cancels exactly left out (the exception stays); in the **pruned** list, the rules DNS makes
//!   useless left out ([`DnsOracle`]): network rules anchored on a DNS-blocked host (`$redirect`
//!   kept; an anchored `$redirect-rule=X` kept as `$redirect=X`), network rules whose `$domain=`
//!   names are all DNS-blocked, cosmetic rules whose domains all are; `$popup` and `$all` never.
//! - **Warnings** ([`ListWarning`]): an exception or `$badfilter` from one feed exactly cancelling
//!   a rule of another feed of the bundle; in a profile list, one block bundle's cancelling
//!   another's; an allow-bundle rule whose host or every `$domain=` name DNS blocks.
//! - **Exact cancellation** goes through an index ([`CancelIndex`]): each rule is filed under what
//!   an exception that exactly cancels it must share with it (a network rule's pattern and option
//!   values, a cosmetic rule's kind, selector and domains), so an exception meets only those
//!   candidates, never its whole selector group ([`cancellations`] equals the plain scan,
//!   [`cancellations_naive`], which the fuzz target checks).
//! - **Steps** (core.md §3): both lists build through resumable builders ([`BundleListBuild`],
//!   [`ProfileListBuild`]) that do at most a given amount of work per step (a DNS-oracle call
//!   counts [`ORACLE_WORK`]), so a list job is a bounded step at a time.

use std::collections::{BTreeSet, HashMap, HashSet};

use picket_rules::Kind;
use picket_rules::browser::{
    AllowConversion, CosmeticDomain, CosmeticRule, NetworkRule, allow_conversion, exactly_cancels,
    redirect_rule_to_redirect,
};
pub use picket_rules::browser::{BrowserRule, parse_browser};

/// Work one builder step does (rules converted, filed or scanned; candidates compared).
pub const STEP_WORK: usize = 20_000;
/// What one DNS-oracle call counts as (it may read storage).
pub const ORACLE_WORK: usize = 10;

/// One `browser` rule as a list reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub bundle: String,
    pub feed: String,
    pub text: String,
}

/// A browser-list warning (bundles.md §8 "Browser list warnings").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListWarning {
    /// `between_feeds`, `between_bundles` or `allow_defeated`.
    pub kind: &'static str,
    /// The cancelling (or defeated allow) rule, and its bundle and feed.
    pub rule: String,
    pub bundle: String,
    pub feed: String,
    /// What it cancels (a sample) or the block bundle that defeats it.
    pub detail: Vec<String>,
}

/// What a bundle list holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleList {
    pub lines: Vec<String>,
    /// `$redirect` rules an allow bundle dropped.
    pub dropped: u64,
    pub warnings: Vec<ListWarning>,
}

/// Rules a cancellation group keys on: exactly cancelling rules share it.
fn group_key(r: &BrowserRule) -> String {
    match r {
        BrowserRule::Network(n) => format!("n\u{0}{}", n.pattern),
        BrowserRule::Cosmetic(c) => {
            let body = match c.scriptlet() {
                Some((name, _)) => format!("+js\u{0}{}", name.strip_suffix(".js").unwrap_or(&name)),
                None => c.body.clone(),
            };
            format!("c\u{0}{:?}\u{0}{body}", c.kind)
        }
    }
}

/// The rules (indices) each canceller exactly cancels, among those `scope` admits: the plain scan
/// of each canceller's group (the reference [`cancellations`] must equal; fuzz target and tests).
pub fn cancellations_naive(
    rules: &[BrowserRule],
    mut scope: impl FnMut(usize, usize) -> bool,
) -> Vec<(usize, Vec<usize>)> {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        groups.entry(group_key(r)).or_default().push(i);
    }
    let mut out = Vec::new();
    for (i, c) in rules.iter().enumerate() {
        if !c.is_exception_or_badfilter() {
            continue;
        }
        let Some(g) = groups.get(&group_key(c)) else {
            continue;
        };
        let hit: Vec<usize> = g
            .iter()
            .copied()
            .filter(|&j| j != i && scope(i, j) && exactly_cancels(c, &rules[j]))
            .collect();
        if !hit.is_empty() {
            out.push((i, hit));
        }
    }
    out
}

/// The rules (indices) each canceller exactly cancels, among those `scope` admits, through a
/// [`CancelIndex`]; the same result as [`cancellations_naive`].
pub fn cancellations(
    rules: &[BrowserRule],
    mut scope: impl FnMut(usize, usize) -> bool,
) -> Vec<(usize, Vec<usize>)> {
    let mut index = CancelIndex::default();
    for (j, r) in rules.iter().enumerate() {
        index.add(j, r);
    }
    let mut out = Vec::new();
    for (i, c) in rules.iter().enumerate() {
        let hit: Vec<usize> = index
            .candidates(c)
            .iter()
            .copied()
            .filter(|&j| j != i && scope(i, j) && exactly_cancels(c, &rules[j]))
            .collect();
        if !hit.is_empty() {
            out.push((i, hit));
        }
    }
    out
}

/// A network rule's option values as a set of `|`-separated, lowercased tokens. Two rules whose
/// option sets [`exactly_cancels`] finds equal (aliases resolved, list values sorted and
/// lowercased, `important` / `badfilter` aside: none has a value) have the same tokens, whatever
/// their written order or case, so the tokens may file the rule; they never decide alone.
fn value_tokens(n: &NetworkRule) -> Vec<String> {
    let mut v: Vec<String> = n
        .options
        .iter()
        .filter_map(|o| o.value.as_deref())
        .flat_map(|val| val.split('|'))
        .map(str::to_ascii_lowercase)
        .collect();
    v.sort();
    v.dedup();
    v
}

/// A cosmetic rule's selector as exact cancellation compares it: for a scriptlet, its name
/// (without `.js`) and its arguments.
fn comparable_body(c: &CosmeticRule) -> String {
    match c.scriptlet() {
        Some((name, args)) => {
            let name = name.strip_suffix(".js").unwrap_or(&name);
            let mut s = format!("+js\u{0}{name}");
            for a in args {
                s.push('\u{0}');
                s.push_str(&a);
            }
            s
        }
        None => c.body.clone(),
    }
}

/// Network candidate key: pattern and option tokens.
type NetKey = (String, Vec<String>);
/// Cosmetic candidate key: kind and comparable selector.
type CosKey = (Kind, String);

/// Rules filed by what an exception that exactly cancels them shares with them (bundles.md §8
/// "Exact cancellation"): an exception looks up only its candidates. Index lists stay in rule
/// order, so results come in the order a plain scan gives.
#[derive(Default)]
pub struct CancelIndex {
    /// Network blocks (neither exception nor `$badfilter`): what a network exception cancels.
    net_blocks: HashMap<NetKey, Vec<usize>>,
    /// Network rules other than `$badfilter`, by exception flag: what a `$badfilter` names.
    net_any: HashMap<(bool, NetKey), Vec<usize>>,
    /// Cosmetic blocks: what a generic cosmetic exception cancels.
    cos_any: HashMap<CosKey, Vec<usize>>,
    /// Cosmetic blocks with their domains: what a cosmetic exception listing domains cancels.
    cos_domains: HashMap<(CosKey, Vec<CosmeticDomain>), Vec<usize>>,
}

impl CancelIndex {
    /// Files rule `j`.
    pub fn add(&mut self, j: usize, r: &BrowserRule) {
        match r {
            BrowserRule::Network(n) => {
                if n.is_badfilter() {
                    return;
                }
                let key = (n.pattern.clone(), value_tokens(n));
                if !n.exception {
                    self.net_blocks.entry(key.clone()).or_default().push(j);
                }
                self.net_any.entry((n.exception, key)).or_default().push(j);
            }
            BrowserRule::Cosmetic(c) => {
                if c.exception {
                    return;
                }
                let key = (c.kind, comparable_body(c));
                self.cos_domains
                    .entry((key.clone(), c.domains.clone()))
                    .or_default()
                    .push(j);
                self.cos_any.entry(key).or_default().push(j);
            }
        }
    }

    /// The rules `c` may cancel exactly (none unless it is an exception or a `$badfilter`).
    pub fn candidates(&self, c: &BrowserRule) -> &[usize] {
        let v = match c {
            BrowserRule::Network(n) if n.is_badfilter() => self
                .net_any
                .get(&(n.exception, (n.pattern.clone(), value_tokens(n)))),
            BrowserRule::Network(n) if n.exception => {
                self.net_blocks.get(&(n.pattern.clone(), value_tokens(n)))
            }
            BrowserRule::Cosmetic(k) if k.exception => {
                let key = (k.kind, comparable_body(k));
                if k.domains.is_empty() {
                    self.cos_any.get(&key)
                } else {
                    self.cos_domains.get(&(key, k.domains.clone()))
                }
            }
            _ => None,
        };
        v.map_or(&[], Vec::as_slice)
    }
}

/// A bundle's list (see the module docs).
pub fn bundle_list(allow: bool, sources: &[Source]) -> BundleList {
    let mut b = BundleListBuild::new(allow, sources.to_vec());
    while !b.step(usize::MAX) {}
    b.finish()
}

/// A bundle's list built a bounded step at a time ([`BundleListBuild::step`]).
pub struct BundleListBuild {
    allow: bool,
    sources: Vec<Source>,
    stage: u8,
    at: usize,
    seen: HashSet<String>,
    /// Kept rules: the rule and its source.
    kept: Vec<(BrowserRule, usize)>,
    index: CancelIndex,
    out: BundleList,
}

impl BundleListBuild {
    pub fn new(allow: bool, sources: Vec<Source>) -> Self {
        Self {
            allow,
            sources,
            stage: 0,
            at: 0,
            seen: HashSet::new(),
            kept: Vec::new(),
            index: CancelIndex::default(),
            out: BundleList::default(),
        }
    }

    /// Does up to `work` of the build; `true` when it is done.
    pub fn step(&mut self, work: usize) -> bool {
        let mut done = 0usize;
        while done < work {
            match self.stage {
                // Convert (allow bundles) and deduplicate.
                0 => {
                    let Some(s) = self.sources.get(self.at) else {
                        // Between feeds (allow bundles' rules all allow: only block bundles can
                        // cancel their own).
                        self.stage = if self.allow { 3 } else { 1 };
                        self.at = 0;
                        continue;
                    };
                    let text = if self.allow {
                        match allow_conversion(&parse_browser(&s.text)) {
                            AllowConversion::Written(t) | AllowConversion::Unchanged(t) => t,
                            AllowConversion::Dropped => {
                                self.out.dropped += 1;
                                self.at += 1;
                                done += 1;
                                continue;
                            }
                        }
                    } else {
                        s.text.clone()
                    };
                    if self.seen.insert(text.clone()) {
                        self.kept.push((parse_browser(&text), self.at));
                        self.out.lines.push(text);
                    }
                    self.at += 1;
                    done += 1;
                }
                1 => {
                    let Some((r, _)) = self.kept.get(self.at) else {
                        self.stage = 2;
                        self.at = 0;
                        continue;
                    };
                    self.index.add(self.at, r);
                    self.at += 1;
                    done += 1;
                }
                2 => {
                    let i = self.at;
                    let Some((c, si)) = self.kept.get(i) else {
                        self.stage = 3;
                        continue;
                    };
                    let feed = &self.sources[*si].feed;
                    let cands = self.index.candidates(c);
                    done += 1 + cands.len();
                    let hit: Vec<usize> = cands
                        .iter()
                        .copied()
                        .filter(|&j| j != i && self.sources[self.kept[j].1].feed != *feed)
                        .filter(|&j| exactly_cancels(c, &self.kept[j].0))
                        .collect();
                    if !hit.is_empty() {
                        let src = &self.sources[*si];
                        self.out.warnings.push(ListWarning {
                            kind: "between_feeds",
                            rule: src.text.clone(),
                            bundle: src.bundle.clone(),
                            feed: src.feed.clone(),
                            detail: hit
                                .iter()
                                .take(5)
                                .map(|j| {
                                    let s = &self.sources[self.kept[*j].1];
                                    format!("{} ({})", s.text, s.feed)
                                })
                                .collect(),
                        });
                    }
                    self.at += 1;
                }
                _ => return true,
            }
        }
        self.stage >= 3
    }

    pub fn finish(self) -> BundleList {
        self.out
    }
}

/// Whether DNS blocks a name's scope in a profile (bundles.md §8 "DNS-blocked names").
pub trait DnsOracle {
    /// The block bundle that blocks the whole scope of `name` (conditions 1–4), if any.
    fn scope_blocked(&mut self, name: &str) -> Option<String>;
    /// The block bundle that blocks `name` itself (condition 1 alone), if any.
    fn name_blocked(&mut self, name: &str) -> Option<String>;
}

/// No DNS information: nothing is left out.
pub struct NoDns;

impl DnsOracle for NoDns {
    fn scope_blocked(&mut self, _: &str) -> Option<String> {
        None
    }
    fn name_blocked(&mut self, _: &str) -> Option<String> {
        None
    }
}

/// Both profile lists and what building them found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileLists {
    pub full: Vec<String>,
    pub pruned: Vec<String>,
    /// Blocks left out because an allow cancels them exactly.
    pub cancelled: u64,
    /// Rules dropped in the allow conversion.
    pub dropped: u64,
    /// Rules the pruned list leaves out as DNS-blocked.
    pub dns_blocked: u64,
    pub warnings: Vec<ListWarning>,
    /// The names the rules refer to (hosts, `$domain=` entries, cosmetic domains), for tracking
    /// DNS changes (bundles.md §8 Builds).
    pub names: BTreeSet<String>,
}

/// The names a rule refers to, and whether its whole scope must be DNS-blocked for it to go.
enum Prunable {
    /// Never left out (`$popup`, `$all`, generic, negated or entity domains, unanchored).
    Never,
    /// Left out when this host's scope is DNS-blocked; `redirect` when kept as `$redirect=X`.
    Host {
        host: String,
        redirect: Option<String>,
        keep: bool,
    },
    /// Left out when every one of these names has a DNS-blocked scope.
    All(Vec<String>),
}

fn prunable(r: &BrowserRule) -> Prunable {
    match r {
        BrowserRule::Network(n) => {
            if n.is_popup_or_all() {
                return Prunable::Never;
            }
            if let Some(host) = n.host_anchor() {
                // `$redirect` rules stay; an anchored `$redirect-rule=X` becomes `$redirect=X`.
                let keep = n.option("redirect").is_some();
                return Prunable::Host {
                    host,
                    redirect: redirect_rule_to_redirect(n),
                    keep,
                };
            }
            match n.page_domains() {
                Some(names) => Prunable::All(names),
                None => Prunable::Never,
            }
        }
        BrowserRule::Cosmetic(c) => match c.plain_domains() {
            Some(names) => Prunable::All(names),
            None => Prunable::Never,
        },
    }
}

fn names_of(r: &BrowserRule) -> Vec<String> {
    match r {
        BrowserRule::Network(n) => {
            let mut v: Vec<String> = n.host_anchor().into_iter().collect();
            v.extend(n.page_domains().unwrap_or_default());
            v
        }
        BrowserRule::Cosmetic(c) => c.plain_domains().unwrap_or_default(),
    }
}

/// The names a rule's allow-defeated check looks at (its host, or every `$domain=` name, or its
/// cosmetic domains).
fn defeat_names(rule: &BrowserRule) -> Vec<String> {
    match rule {
        BrowserRule::Network(n) => match n.host_anchor() {
            Some(h) => vec![h],
            None => n.page_domains().unwrap_or_default(),
        },
        BrowserRule::Cosmetic(c) => c.plain_domains().unwrap_or_default(),
    }
}

/// A profile's lists (see the module docs). `allow` and `block` are the allow bundles' and the
/// block bundles' rules, each in the profile's bundle order.
pub fn profile_lists(allow: &[Source], block: &[Source], dns: &mut dyn DnsOracle) -> ProfileLists {
    let mut b = ProfileListBuild::new(allow.to_vec(), block.to_vec());
    while !b.step(dns, usize::MAX) {}
    b.finish()
}

/// Where a [`ProfileListBuild`] stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PStage {
    /// The allow bundles' rules as exceptions, deduplicated.
    Allows,
    /// The block bundles' rules, a rule two bundles share under the first.
    Blocks,
    /// Every kept rule filed in the cancellation index (allows, then blocks).
    Index,
    /// Blocks an allow cancels exactly.
    AllowCancels,
    /// One block bundle's exception cancelling another's (warnings).
    BetweenBundles,
    /// Allows that DNS defeats.
    Defeated,
    /// The allows written to both lists.
    WriteAllows,
    /// The blocks written to both lists.
    WriteBlocks,
    Done,
}

/// A profile's lists built a bounded step at a time ([`ProfileListBuild::step`]); the DNS oracle
/// is handed in at each step (it may read storage).
pub struct ProfileListBuild {
    allow_src: Vec<Source>,
    block_src: Vec<Source>,
    stage: PStage,
    at: usize,
    seen: HashSet<String>,
    /// Kept allows: the rule as written (an exception), its source and its text.
    allows: Vec<(BrowserRule, usize, String)>,
    /// Kept blocks: the rule and its source.
    blocks: Vec<(BrowserRule, usize)>,
    /// Over allows then blocks (block `k` is entry `allows.len() + k`).
    index: CancelIndex,
    cancelled: Vec<bool>,
    pruned_seen: HashSet<String>,
    out: ProfileLists,
}

impl ProfileListBuild {
    pub fn new(allow: Vec<Source>, block: Vec<Source>) -> Self {
        Self {
            allow_src: allow,
            block_src: block,
            stage: PStage::Allows,
            at: 0,
            seen: HashSet::new(),
            allows: Vec::new(),
            blocks: Vec::new(),
            index: CancelIndex::default(),
            cancelled: Vec::new(),
            pruned_seen: HashSet::new(),
            out: ProfileLists::default(),
        }
    }

    fn next(&mut self, stage: PStage) {
        self.stage = stage;
        self.at = 0;
    }

    fn keep_pruned(&mut self, line: String) {
        // A `$redirect-rule` written as `$redirect` may equal a rule already kept: each line once.
        if self.pruned_seen.insert(line.clone()) {
            self.out.pruned.push(line);
        }
    }

    /// Does up to `work` of the build (an oracle call counts [`ORACLE_WORK`]); `true` when done.
    pub fn step(&mut self, dns: &mut dyn DnsOracle, work: usize) -> bool {
        let mut done = 0usize;
        while done < work {
            match self.stage {
                PStage::Allows => {
                    let Some(s) = self.allow_src.get(self.at) else {
                        self.next(PStage::Blocks);
                        continue;
                    };
                    match allow_conversion(&parse_browser(&s.text)) {
                        AllowConversion::Written(t) | AllowConversion::Unchanged(t) => {
                            if self.seen.insert(t.clone()) {
                                self.allows.push((parse_browser(&t), self.at, t));
                            }
                        }
                        AllowConversion::Dropped => self.out.dropped += 1,
                    }
                    self.at += 1;
                    done += 1;
                }
                PStage::Blocks => {
                    let Some(s) = self.block_src.get(self.at) else {
                        self.cancelled = vec![false; self.blocks.len()];
                        self.next(PStage::Index);
                        continue;
                    };
                    if self.seen.insert(s.text.clone()) {
                        self.blocks.push((parse_browser(&s.text), self.at));
                    }
                    self.at += 1;
                    done += 1;
                }
                PStage::Index => {
                    let j = self.at;
                    let r = if j < self.allows.len() {
                        &self.allows[j].0
                    } else if let Some(b) = self.blocks.get(j - self.allows.len()) {
                        &b.0
                    } else {
                        self.next(PStage::AllowCancels);
                        continue;
                    };
                    self.index.add(j, r);
                    self.at += 1;
                    done += 1;
                }
                PStage::AllowCancels => {
                    // Blocks an allow cancels exactly are left out.
                    let Some((c, _, _)) = self.allows.get(self.at) else {
                        self.next(PStage::BetweenBundles);
                        continue;
                    };
                    let cands = self.index.candidates(c);
                    done += 1 + cands.len();
                    let na = self.allows.len();
                    for &j in cands {
                        if j >= na && exactly_cancels(c, &self.blocks[j - na].0) {
                            self.cancelled[j - na] = true;
                        }
                    }
                    self.at += 1;
                }
                PStage::BetweenBundles => {
                    // Between block bundles (an exception applies to every list in the browser).
                    let i = self.at;
                    let Some((c, si)) = self.blocks.get(i) else {
                        self.next(PStage::Defeated);
                        continue;
                    };
                    let na = self.allows.len();
                    let bundle = &self.block_src[*si].bundle;
                    let cands = self.index.candidates(c);
                    done += 1 + cands.len();
                    let hit: Vec<usize> = cands
                        .iter()
                        .filter(|&&j| j >= na && j - na != i)
                        .map(|&j| j - na)
                        .filter(|&k| self.block_src[self.blocks[k].1].bundle != *bundle)
                        .filter(|&k| exactly_cancels(c, &self.blocks[k].0))
                        .collect();
                    if !hit.is_empty() {
                        let src = &self.block_src[*si];
                        self.out.warnings.push(ListWarning {
                            kind: "between_bundles",
                            rule: src.text.clone(),
                            bundle: src.bundle.clone(),
                            feed: src.feed.clone(),
                            detail: hit
                                .iter()
                                .take(5)
                                .map(|k| {
                                    let s = &self.block_src[self.blocks[*k].1];
                                    format!("{} ({})", s.text, s.bundle)
                                })
                                .collect(),
                        });
                    }
                    self.at += 1;
                }
                PStage::Defeated => {
                    // Allows that DNS defeats (condition 1 on the host or every $domain= name).
                    let Some((rule, si, _)) = self.allows.get(self.at) else {
                        self.next(PStage::WriteAllows);
                        continue;
                    };
                    let names = defeat_names(rule);
                    done += 1 + names.len() * ORACLE_WORK;
                    if !names.is_empty() {
                        let by: Vec<Option<String>> = names.iter().map(|n| dns.name_blocked(n)).collect();
                        if by.iter().all(Option::is_some) {
                            let src = &self.allow_src[*si];
                            self.out.warnings.push(ListWarning {
                                kind: "allow_defeated",
                                rule: src.text.clone(),
                                bundle: src.bundle.clone(),
                                feed: src.feed.clone(),
                                detail: by
                                    .into_iter()
                                    .flatten()
                                    .collect::<BTreeSet<_>>()
                                    .into_iter()
                                    .collect(),
                            });
                        }
                    }
                    self.at += 1;
                }
                PStage::WriteAllows => {
                    let Some((rule, _, text)) = self.allows.get(self.at) else {
                        self.next(PStage::WriteBlocks);
                        continue;
                    };
                    let (text, names, p) = (text.clone(), names_of(rule), prunable(rule));
                    self.out.full.push(text.clone());
                    self.out.names.extend(names);
                    let keep = match p {
                        Prunable::Never => true,
                        Prunable::Host { host, keep, .. } => {
                            done += ORACLE_WORK;
                            keep || dns.scope_blocked(&host).is_none()
                        }
                        Prunable::All(names) => {
                            done += names.len() * ORACLE_WORK;
                            !names.iter().all(|n| dns.scope_blocked(n).is_some())
                        }
                    };
                    if keep {
                        self.keep_pruned(text);
                    } else {
                        self.out.dns_blocked += 1;
                    }
                    self.at += 1;
                    done += 1;
                }
                PStage::WriteBlocks => {
                    let i = self.at;
                    let Some((rule, si)) = self.blocks.get(i) else {
                        self.next(PStage::Done);
                        continue;
                    };
                    self.at += 1;
                    done += 1;
                    if self.cancelled.get(i).copied().unwrap_or(false) {
                        self.out.cancelled += 1;
                        continue;
                    }
                    let text = self.block_src[*si].text.clone();
                    let (names, p) = (names_of(rule), prunable(rule));
                    self.out.full.push(text.clone());
                    self.out.names.extend(names);
                    match p {
                        Prunable::Never => self.keep_pruned(text),
                        Prunable::Host { host, redirect, keep } => {
                            done += ORACLE_WORK;
                            if keep || dns.scope_blocked(&host).is_none() {
                                self.keep_pruned(text);
                            } else if let Some(r) = redirect {
                                // The blockers are left out; the redirect fires on its own.
                                self.keep_pruned(r);
                            } else {
                                self.out.dns_blocked += 1;
                            }
                        }
                        Prunable::All(names) => {
                            done += names.len() * ORACLE_WORK;
                            if names.iter().all(|n| dns.scope_blocked(n).is_some()) {
                                self.out.dns_blocked += 1;
                            } else {
                                self.keep_pruned(text);
                            }
                        }
                    }
                }
                PStage::Done => return true,
            }
        }
        self.stage == PStage::Done
    }

    pub fn finish(self) -> ProfileLists {
        self.out
    }
}

/// A list's version (bundles.md §8): its build time as `YYYYMMDDHHMM` UTC.
pub fn version(at: &jiff::Timestamp) -> String {
    at.strftime("%Y%m%d%H%M").to_string()
}

/// A list's header (bundles.md §8): title, version ([`version`]), last modified, expires.
pub fn header(title: &str, at: jiff::Timestamp) -> String {
    format!(
        "! Title: {title}\n! Version: {}\n! Last modified: {}\n! Expires: 1 hours\n",
        version(&at),
        at.strftime("%d %b %Y %H:%M UTC"),
    )
}

/// The whole list text.
pub fn text(title: &str, at: jiff::Timestamp, lines: &[String]) -> String {
    let mut s = header(title, at);
    for l in lines {
        // A rule text never holds a line break (feed lines are lines); guard anyway.
        if l.contains(['\n', '\r']) {
            continue;
        }
        s.push_str(l);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden (F7, F8: a list's version and `Last modified`; plan §5 step 1, unchanged after the
    /// move to jiff).
    #[test]
    fn golden_header() {
        use picket_api::time::golden::{ROWS, ts_from_nanos};
        for r in ROWS {
            let t = ts_from_nanos(r.nanos);
            assert_eq!(version(&t), r.list_version, "{}", r.name);
            let want = format!(
                "! Title: T\n! Version: {}\n! Last modified: {}\n! Expires: 1 hours\n",
                r.list_version, r.list_date
            );
            assert_eq!(header("T", t), want, "{}", r.name);
        }
    }

    fn src(bundle: &str, feed: &str, text: &str) -> Source {
        Source {
            bundle: bundle.into(),
            feed: feed.into(),
            text: text.into(),
        }
    }

    /// Every row of the allow-bundle conversion table (bundles.md §8; build-and-test.md §5
    /// "Browser lists": one fixture per row, fixtures/rules/browser-allow-conversion.tsv).
    #[test]
    fn allow_conversion_table() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/rules/browser-allow-conversion.tsv"
        );
        let text = std::fs::read_to_string(path).unwrap();
        let mut n = 0;
        for line in text.lines() {
            if line.starts_with("//") || line.trim().is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            let (rule, want) = (cols[0], cols[1]);
            let out = bundle_list(true, &[src("a", "f", rule)]);
            if want == "DROPPED" {
                assert!(out.lines.is_empty(), "{rule}");
                assert_eq!(out.dropped, 1, "{rule}");
            } else {
                assert_eq!(out.lines, vec![want.to_string()], "{rule}");
            }
            n += 1;
        }
        assert!(n >= 7, "one fixture per conversion row");
    }

    #[test]
    fn bundle_lists_dedupe_and_warn_between_feeds() {
        let out = bundle_list(
            false,
            &[
                src("b", "f1", "||ads.example/x.js"),
                src("b", "f1", "example.com##.ad"),
                src("b", "f2", "||ads.example/x.js"),
                src("b", "f2", "@@||ads.example/x.js"),
                src("b", "f2", "example.com#@#.ad"),
            ],
        );
        assert_eq!(out.lines.len(), 4, "the shared rule once");
        let kinds: Vec<&str> = out.warnings.iter().map(|w| w.kind).collect();
        assert_eq!(kinds, vec!["between_feeds", "between_feeds"]);
        // Same feed: no warning.
        let out = bundle_list(
            false,
            &[src("b", "f1", "||x.example/a"), src("b", "f1", "@@||x.example/a")],
        );
        assert!(out.warnings.is_empty());
    }

    struct Fake {
        blocked: Vec<&'static str>,
        exact_only: Vec<&'static str>,
    }

    impl DnsOracle for Fake {
        fn scope_blocked(&mut self, n: &str) -> Option<String> {
            self.blocked.contains(&n).then(|| "block-common".to_string())
        }
        fn name_blocked(&mut self, n: &str) -> Option<String> {
            (self.blocked.contains(&n) || self.exact_only.contains(&n)).then(|| "block-common".to_string())
        }
    }

    #[test]
    fn profile_lists_prune_cancel_and_keep_redirects_and_popups() {
        let allow = [
            src("allow-common", "ma", "||good.example/ads.js"),
            src("allow-common", "ma", "||tracker.example^$redirect=noop.js"),
        ];
        let block = [
            src("block-common", "f", "||good.example/ads.js"),
            src("block-common", "f", "||tracker.example/pixel.gif"),
            src("block-common", "f", "||tracker.example^$redirect=noopjs"),
            src("block-common", "f", "||tracker.example^$redirect-rule=noopjs"),
            src("block-common", "f", "||tracker.example^$popup"),
            src("block-common", "f", "*$script,domain=tracker.example"),
            src("block-common", "f", "tracker.example##.banner"),
            src("block-common", "f", "other.example##.banner"),
            src("block-common", "f", "##.generic"),
            src("block-common", "f", "||cdn.example/x.js"),
            src("other", "g", "@@||cdn.example/x.js"),
        ];
        let mut dns = Fake {
            blocked: vec!["tracker.example"],
            exact_only: vec![],
        };
        let out = profile_lists(&allow, &block, &mut dns);
        // The allow's exception is written; the block it cancels exactly isn't.
        assert!(out.full.contains(&"@@||good.example/ads.js".to_string()));
        assert!(!out.full.contains(&"||good.example/ads.js".to_string()));
        assert_eq!(out.cancelled, 1);
        assert_eq!(out.dropped, 1, "an allow's $redirect is dropped");
        // Pruned: DNS-blocked host rules go, $redirect stays, $redirect-rule becomes $redirect,
        // $popup stays, $domain= and cosmetic rules on blocked names go, others stay.
        let p = &out.pruned;
        assert!(!p.contains(&"||tracker.example/pixel.gif".to_string()));
        assert!(p.contains(&"||tracker.example^$redirect=noopjs".to_string()));
        assert!(
            p.contains(&"||tracker.example^$redirect=noopjs".to_string())
                && !p.iter().any(|l| l.contains("redirect-rule"))
        );
        assert!(p.contains(&"||tracker.example^$popup".to_string()));
        assert!(!p.contains(&"*$script,domain=tracker.example".to_string()));
        assert!(!p.contains(&"tracker.example##.banner".to_string()));
        assert!(p.contains(&"other.example##.banner".to_string()));
        assert!(p.contains(&"##.generic".to_string()));
        // The full list keeps them all, the $redirect-rule as written.
        assert!(
            out.full
                .contains(&"||tracker.example^$redirect-rule=noopjs".to_string())
        );
        assert!(out.full.contains(&"tracker.example##.banner".to_string()));
        assert!(out.dns_blocked >= 3);
        // Between bundles: `other`'s exception cancels block-common's rule.
        assert!(
            out.warnings
                .iter()
                .any(|w| w.kind == "between_bundles" && w.bundle == "other")
        );
        assert!(out.names.contains("tracker.example"));
    }

    /// A `$redirect-rule=X` written as `$redirect=X` beside the same `$redirect=X` rule: the
    /// pruned list holds the line once (review round 1, CP14).
    #[test]
    fn a_converted_redirect_rule_is_written_once() {
        let block = [
            src("block-common", "f", "||tracker.example^$redirect=noopjs"),
            src("block-common", "f", "||tracker.example^$redirect-rule=noopjs"),
        ];
        let mut dns = Fake {
            blocked: vec!["tracker.example"],
            exact_only: vec![],
        };
        let out = profile_lists(&[], &block, &mut dns);
        assert_eq!(out.pruned, vec!["||tracker.example^$redirect=noopjs".to_string()]);
        assert_eq!(out.full.len(), 2);
    }

    #[test]
    fn an_allow_dns_defeats_warns() {
        let allow = [src("allow-common", "ma", "||blocked.example/a.js")];
        let mut dns = Fake {
            blocked: vec![],
            exact_only: vec!["blocked.example"],
        };
        let out = profile_lists(&allow, &[], &mut dns);
        assert_eq!(out.warnings.len(), 1);
        assert_eq!(out.warnings[0].kind, "allow_defeated");
        assert_eq!(out.warnings[0].detail, vec!["block-common".to_string()]);
    }

    /// The index gives the plain scan's result (review round 2, CR3), on rules that differ in
    /// option order and case, aliases, `important`, `$badfilter`, generic and listed cosmetic
    /// domains, and scriptlet arguments.
    #[test]
    fn indexed_cancellation_equals_the_plain_scan() {
        let texts = [
            "||a.example/x.js$script,domain=B.com|a.com",
            "@@||a.example/x.js$domain=a.com|b.com,script",
            "@@||a.example/x.js$domain=a.com|b.com,script,important",
            "||a.example/x.js$script,domain=a.com|b.com$badfilter",
            "||a.example/x.js$xhr",
            "@@||a.example/x.js$xmlhttprequest",
            "||a.example/x.js$script,domain=a.com|b.com,badfilter",
            "@@||a.example/x.js$script,domain=a.com|b.com,badfilter",
            "a.com,b.com##.ad",
            "a.com,b.com#@#.ad",
            "b.com,a.com#@#.ad",
            "#@#.ad",
            "~a.com#@#.ad",
            "x.com##+js(set, a, 1)",
            "x.com#@#+js(set.js, a, 1)",
            "#@#+js(set, a, 2)",
            "#@#+js(set)",
            "x.com#?#.ad:has(b)",
            "x.com#@?#.ad:has(b)",
            "x.com##^script",
            "x.com#@#^script",
        ];
        let rules: Vec<BrowserRule> = texts.iter().map(|t| parse_browser(t)).collect();
        for scope in [0, 1, 2] {
            let f = |i: usize, j: usize| match scope {
                0 => true,
                1 => i % 2 != j % 2,
                _ => i < j,
            };
            assert_eq!(
                cancellations(&rules, f),
                cancellations_naive(&rules, f),
                "scope {scope}"
            );
        }
        assert!(!cancellations(&rules, |_, _| true).is_empty());
    }

    /// An exception meets only its candidates: 20,000 cosmetic rules and as many exceptions on
    /// other domains are linear work (the plain scan was quadratic, CR3).
    #[test]
    fn many_exceptions_of_one_selector_are_linear() {
        let mut v = Vec::new();
        for i in 0..20_000 {
            v.push(src("b", "f1", &format!("d{i}.example##.ad")));
        }
        for i in 0..20_000 {
            v.push(src("b", "f2", &format!("e{i}.example#@#.ad")));
        }
        let t = std::time::Instant::now();
        let out = bundle_list(false, &v);
        let p = profile_lists(&[], &v, &mut NoDns);
        assert!(out.warnings.is_empty() && p.full.len() == 40_000);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(20),
            "{:?}",
            t.elapsed()
        );
    }

    /// Building a step at a time gives what one go gives.
    #[test]
    fn steps_give_the_same_lists() {
        let allow = [
            src("allow-common", "ma", "||good.example/ads.js"),
            src("allow-common", "ma", "||blocked.example/a.js"),
        ];
        let block = [
            src("block-common", "f", "||good.example/ads.js"),
            src("block-common", "f", "||tracker.example/pixel.gif"),
            src("block-common", "f", "||tracker.example^$redirect-rule=noopjs"),
            src("block-common", "f", "tracker.example##.banner"),
            src("other", "g", "@@||tracker.example/pixel.gif"),
        ];
        let mut dns = Fake {
            blocked: vec!["tracker.example"],
            exact_only: vec!["blocked.example"],
        };
        let whole = profile_lists(&allow, &block, &mut dns);
        let mut b = ProfileListBuild::new(allow.to_vec(), block.to_vec());
        let mut steps = 0;
        while !b.step(&mut dns, 1) {
            steps += 1;
        }
        assert!(steps > 10);
        assert_eq!(b.finish(), whole);
        let whole = bundle_list(false, &block);
        let mut b = BundleListBuild::new(false, block.to_vec());
        while !b.step(1) {}
        assert_eq!(b.finish(), whole);
    }

    #[test]
    fn headers() {
        let at = "2026-11-21T09:05:00Z".parse::<jiff::Timestamp>().unwrap();
        let t = text(
            "Picket block-common",
            at,
            &["||a.example/x".into(), "bad\nline".into()],
        );
        assert!(t.starts_with("! Title: Picket block-common\n! Version: 202611210905\n"));
        assert!(t.contains("! Expires: 1 hours\n"));
        assert!(t.ends_with("||a.example/x\n"));
    }
}
