//! urlfilter's matched-rule order (rules.md §3–§4; review round 1, R5).
//!
//! AdGuard Home answers with the first CNAME or rcode `$dnsrewrite` in the order urlfilter's
//! `NetworkEngine.AppendAllMatching` returns the matching rules, and `@@…$dnsrewrite` exceptions
//! are applied in that order too (`DNSResult.DNSRewrites`). That order isn't the list order:
//!
//! 1. **Shortcut-indexed rules** (`ShortcutIndex`): a rule whose shortcut has at least 6 bytes (and
//!    isn't a bare scheme) is filed under one 5-byte slice of its shortcut: the first slice no
//!    earlier rule took, or else the least used one (the first of those). A query walks the 5-byte
//!    slices of `"http://" + host` from the left (all but the last) and lists each slice's rules in
//!    filing order, so a rule appears once per occurrence of its slice.
//! 2. **Unindexed rules** (`noIndex`), in list order (a repeated rule text is filed once).
//!
//! The filing depends on every network rule AdGuard's DNS engine indexes, in bundle order: `dns`
//! and `ip` rules written in network syntax, `$badfilter` rules, and `browser` network rules it
//! reads as host-level (no `$domain`, no options other than `$important`/`$badfilter` and the DNS
//! modifiers, and not both positive and negated request types), which never match a name but take
//! slots. Host rules, hosts lines and `plain`/MISP names aren't network rules.
//!
//! [`urlfilter_order`] computes each rule's [`MatchOrder`] for a bundle; the compiler stores it with
//! each `$dnsrewrite` rich rule, and the edge orders a query's matching rewrites with
//! [`sequence`], as [`crate::matcher::BundleMatcher`] does.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::adguard::{self, URL_PREFIX};
use crate::modifiers::{ClientCond, DnsTypeCond, TagCond};
use crate::rewrite::parse_dnsrewrite;
use crate::rule::{Kind, Rule};

/// urlfilter's `shortcutLength`.
pub const GRAM: usize = 5;

/// Where urlfilter files a network rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MatchOrder {
    /// The 5-byte slice of the shortcut the rule is filed under; `None` for an unindexed rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gram: Option<[u8; GRAM]>,
    /// The rule's place in bundle order (filing order within a slice, list order unindexed).
    pub seq: u32,
}

/// Each rule's [`MatchOrder`] (`None` for rules that aren't network rules in AdGuard's DNS engine),
/// index-aligned with `rules`, which must be in bundle order (feed order, then line order).
pub fn urlfilter_order(rules: &[Rule]) -> Vec<Option<MatchOrder>> {
    let mut filer = OrderFiler::default();
    rules.iter().map(|r| filer.push(r)).collect()
}

/// [`urlfilter_order`] one rule at a time, for a bundle too large to hold as one slice (core's
/// compiler streams its rules from storage in bundle order). Each [`OrderFiler::push`] gives the
/// pushed rule's order, exactly as `urlfilter_order` gives it at that index. Memory: one counter
/// per distinct 5-byte slice filed, plus the texts of unindexed rules.
#[derive(Debug, Default)]
pub struct OrderFiler {
    filed: HashMap<[u8; GRAM], u32>,
    unindexed_texts: std::collections::HashSet<String>,
    next: u32,
}

impl OrderFiler {
    /// Files the next rule of the bundle and returns its order (`None` for a rule that isn't a
    /// network rule AdGuard's DNS engine indexes). Every rule takes a `seq`, filed or not.
    pub fn push(&mut self, r: &Rule) -> Option<MatchOrder> {
        let seq = self.next;
        self.next = self.next.saturating_add(1);
        let (shortcut, text) = network_rule(r)?;
        match pick_gram(&shortcut, &self.filed) {
            Some(g) => {
                let c = self.filed.entry(g).or_default();
                *c = c.saturating_add(1);
                Some(MatchOrder { gram: Some(g), seq })
            }
            None => {
                // `noIndex` keeps one rule per text.
                if self.unindexed_texts.insert(text) {
                    Some(MatchOrder { gram: None, seq })
                } else {
                    None
                }
            }
        }
    }

    /// Rules pushed so far.
    pub fn pushed(&self) -> u32 {
        self.next
    }
}

/// urlfilter `ShortcutIndex.Add`'s choice of slice, or `None` when the rule isn't indexed by it.
fn pick_gram(shortcut: &str, filed: &HashMap<[u8; GRAM], u32>) -> Option<[u8; GRAM]> {
    let sc = shortcut.as_bytes();
    if sc.len() < GRAM || is_any_url_shortcut(sc) {
        return None;
    }
    let mut best: Option<([u8; GRAM], u32)> = None;
    // `for i := range len(r.Shortcut) - shortcutLength`: the last slice isn't a candidate.
    for i in 0..sc.len().saturating_sub(GRAM) {
        let Some(g) = sc
            .get(i..i.saturating_add(GRAM))
            .and_then(|s| <[u8; GRAM]>::try_from(s).ok())
        else {
            continue;
        };
        match filed.get(&g) {
            None => return Some(g),
            Some(&n) => {
                if best.is_none_or(|(_, m)| n < m) {
                    best = Some((g, n));
                }
            }
        }
    }
    best.map(|(g, _)| g)
}

/// urlfilter `isAnyURLShortcut`.
fn is_any_url_shortcut(sc: &[u8]) -> bool {
    let n = sc.len();
    (n < 6 && sc.starts_with(b"ws:"))
        || (n < 7 && sc.starts_with(b"wss:"))
        || (n < 8 && sc.starts_with(b"|ws"))
        || (n < 9 && sc.starts_with(b"http"))
        || (n < 10 && sc.starts_with(b"|http"))
}

/// A rule's urlfilter shortcut and rule text when it is a network rule AdGuard's DNS engine
/// indexes.
fn network_rule(r: &Rule) -> Option<(String, String)> {
    if r.kind.is_browser() {
        if r.kind != Kind::Network {
            return None;
        }
        let t = adguard::split_network(&r.key)?;
        if !host_level(&t.options, t.has_options) {
            return None;
        }
        let pattern = adguard::normalize_pattern(&t.pattern);
        return Some((shortcut_text(&pattern), r.key.clone()));
    }
    if r.spec.host_rule {
        return None;
    }
    let pattern = r.adguard_pattern()?;
    // Picket's own forms that AdGuard never sees: `plain`/MISP names and IP indicators carry no
    // pattern; MISP substrings and regexes are listed as the patterns they stand for.
    Some((shortcut_text(pattern), pattern.to_string()))
}

/// urlfilter `setShortcut` (lowercased; empty when shorter than 2 bytes).
fn shortcut_text(pattern: &str) -> String {
    adguard::shortcut(pattern).unwrap_or_default()
}

/// urlfilter's request types (for the host-level test).
const TYPES: &[&str] = &[
    "script",
    "stylesheet",
    "subdocument",
    "object",
    "image",
    "xmlhttprequest",
    "media",
    "font",
    "websocket",
    "ping",
    "other",
];

/// True when urlfilter parses a network rule with these options and its DNS engine indexes it
/// (`NewNetworkRule` accepts every option and `IsHostLevelNetworkRule` holds).
fn host_level(options: &str, has_options: bool) -> bool {
    if !has_options || options.is_empty() {
        return true;
    }
    let (mut permitted, mut restricted) = (false, false);
    for opt in adguard::split_escaped(options, ',', '\\') {
        let (name, value) = match opt.find('=') {
            Some(i) if i > 0 => (
                opt.get(..i).unwrap_or(""),
                opt.get(i.saturating_add(1)..).unwrap_or(""),
            ),
            _ => (opt.as_str(), ""),
        };
        match name {
            "important" | "badfilter" => {}
            "dnstype" if DnsTypeCond::parse(value).is_some() => {}
            "dnsrewrite" if parse_dnsrewrite(value).is_some() => {}
            "client" if ClientCond::parse(value).is_some() => {}
            "ctag" if TagCond::parse(value).is_some() => {}
            "denyallow" if !value.is_empty() && !value.split('|').any(|d| d.starts_with('~')) => {}
            n if TYPES.contains(&n) => permitted = true,
            n if n.strip_prefix('~').is_some_and(|t| TYPES.contains(&t)) => restricted = true,
            // `$domain`, page-level options (enabled or disabled), `$match-case`, `$document`,
            // `$popup`, …, an invalid value, or an option urlfilter doesn't know (the rule is then
            // refused): not indexed by the DNS engine.
            _ => return false,
        }
    }
    !(permitted && restricted)
}

/// The order urlfilter lists a query's matching network rules in: indices into `cands`, a rule
/// once per occurrence of its slice in `"http://" + text` (left to right, all slices but the
/// last), then the unindexed rules by `seq`. A rule filed under a slice the text doesn't hold (a
/// key matched by labels across escapes, rules.md §3) comes last, by `seq`.
pub fn sequence(text: &str, cands: &[MatchOrder]) -> Vec<usize> {
    let mut by_gram: HashMap<[u8; GRAM], Vec<usize>> = HashMap::new();
    let mut unindexed: Vec<usize> = Vec::new();
    for (k, c) in cands.iter().enumerate() {
        match c.gram {
            Some(g) => by_gram.entry(g).or_default().push(k),
            None => unindexed.push(k),
        }
    }
    let seq_of = |k: &usize| cands.get(*k).map_or(u32::MAX, |c| c.seq);
    for v in by_gram.values_mut() {
        v.sort_by_key(seq_of);
    }
    unindexed.sort_by_key(seq_of);
    let mut url = Vec::with_capacity(URL_PREFIX.len().saturating_add(text.len()));
    url.extend_from_slice(URL_PREFIX.as_bytes());
    url.extend(text.bytes().map(|b| b.to_ascii_lowercase()));
    let mut out = Vec::new();
    let mut seen_gram: std::collections::HashSet<[u8; GRAM]> = std::collections::HashSet::new();
    if !by_gram.is_empty() {
        for i in 0..url.len().saturating_sub(GRAM) {
            let Some(g) = url
                .get(i..i.saturating_add(GRAM))
                .and_then(|s| <[u8; GRAM]>::try_from(s).ok())
            else {
                continue;
            };
            if let Some(ks) = by_gram.get(&g) {
                out.extend(ks.iter().copied());
                seen_gram.insert(g);
            }
        }
    }
    out.extend(unindexed);
    let mut missed: Vec<usize> = by_gram
        .iter()
        .filter(|(g, _)| !seen_gram.contains(*g))
        .flat_map(|(_, ks)| ks.iter().copied())
        .collect();
    missed.sort_by_key(seq_of);
    out.extend(missed);
    out
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
    fn filing() {
        let rs = rules(&[
            "||ex*^$dnsrewrite=NXDOMAIN;;",             // shortcut "ex": unindexed
            "||example.com^$dnsrewrite=target.example", // "examp"
            "||example.com^$dnsrewrite=1.2.3.4",        // "examp" taken → "xampl"
            "example.org",                              // host rule: not a network rule
            "||example.com/ads/*",                      // browser, host-level: "examp"? taken twice
            "||example.com^$third-party",               // browser, not host-level
            "||http^",                                  // shortcut "http": unindexed
            "|https://x^",                              // extension: "https"
        ]);
        let o = urlfilter_order(&rs);
        assert_eq!(o[0], Some(MatchOrder { gram: None, seq: 0 }));
        assert_eq!(o[1].unwrap().gram, Some(*b"examp"));
        assert_eq!(o[2].unwrap().gram, Some(*b"xampl"));
        assert_eq!(o[3], None);
        assert_eq!(o[4].unwrap().gram, Some(*b"ample"));
        assert_eq!(o[5], None);
        assert_eq!(o[6].unwrap().gram, None);
        assert_eq!(o[7].unwrap().gram, Some(*b"https"));
        // A query lists slice by slice, then the unindexed rules.
        let cands = [o[0].unwrap(), o[2].unwrap(), o[1].unwrap()];
        assert_eq!(sequence("example.com", &cands), vec![2, 1, 0]);
        // A slice that occurs twice lists its rules twice.
        assert_eq!(sequence("example.example.com", &[o[1].unwrap()]), vec![0, 0]);
    }

    #[test]
    fn streaming_filer_matches_the_slice_form() {
        let rs = rules(&[
            "||ex*^$dnsrewrite=NXDOMAIN;;",
            "||example.com^$dnsrewrite=target.example",
            "||example.com^$dnsrewrite=1.2.3.4",
            "example.org",
            "||example.com/ads/*",
            "||http^",
            "||http^",
            "|https://x^",
        ]);
        let mut f = OrderFiler::default();
        let streamed: Vec<Option<MatchOrder>> = rs.iter().map(|r| f.push(r)).collect();
        assert_eq!(streamed, urlfilter_order(&rs));
        assert_eq!(f.pushed() as usize, rs.len());
    }
}
