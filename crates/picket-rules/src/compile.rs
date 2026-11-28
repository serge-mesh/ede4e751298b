//! Key-level helpers for core's compiler (bundles.md §2, §8): merging folded rules into a key's
//! value, subsumption pruning, broad-rule tests (with the fixed probe set), the public-suffix
//! guardrail, and the flag-level decision the DNS-blocked-name conditions use.

use std::collections::HashSet;

use crate::adguard::{MatchTarget, URL_PREFIX, shortcut_present};
use crate::analysis::build_regex;
use crate::flags::{Flags, Level};
use crate::ip::is_broad_range;
use crate::modifiers::{NameSemantics, denyallow_permits};
use crate::name::RuleName;
use crate::rule::{Folded, Kind, RichRule, Rule};

/// A domain key's merged value: the union of the plain flags of every rule folded into it, and
/// its rich rules in bundle order (`HAS_RICH` is set when there are any).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyValue {
    pub flags: Flags,
    pub rich: Vec<RichRule>,
}

impl KeyValue {
    /// Folds one rule in. Duplicate rich rules collapse.
    pub fn add(&mut self, f: Folded) {
        self.flags |= f.flags;
        if let Some(r) = f.rich {
            self.flags |= Flags::HAS_RICH;
            if !self.rich.contains(&r) {
                self.rich.push(r);
            }
        }
    }
}

/// Subsumption (bundles.md §2): a key without `HAS_RICH` is fully covered by its ancestors when
/// each of its `X_EXACT` or `X_SUBS` flags has an ancestor's `X_SUBS` (`X` = `B`, `A`, `IMP_B`,
/// `IMP_A`). `ancestors_subs` is the union of the `_SUBS` flags of the ancestor keys in the same
/// part or a hotter one (a hot parent covers hot and cold keys, a cold parent only cold ones).
pub fn is_subsumed(child: Flags, ancestors_subs: Flags) -> bool {
    if child.contains(Flags::HAS_RICH) || child.and(Flags::ALL_LEVELS).is_empty() {
        return false;
    }
    let need = child.exact().exact_as_subs().union(child.subs());
    ancestors_subs.subs().contains(need)
}

/// The part of a block bundle a key goes in (bundles.md §1 Tiers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Part {
    Hot,
    Cold,
}

impl Part {
    /// True when a key in this part can cover one in `child` for subsumption (bundles.md §2): a
    /// hot parent covers hot and cold keys, a cold parent only cold ones.
    pub fn covers(self, child: Part) -> bool {
        self == Part::Hot || child == Part::Cold
    }
}

/// The `_SUBS` flags of a key's ancestors (`(flags, part)` of each) that may cover a key in `part`:
/// the `ancestors_subs` argument of [`is_subsumed`].
pub fn covering_subs(part: Part, ancestors: &[(Flags, Part)]) -> Flags {
    ancestors
        .iter()
        .filter(|(_, p)| p.covers(part))
        .fold(Flags::NONE, |acc, (f, _)| acc.union(f.subs()))
}

/// The decision domain keys give a name by flag level (bundles.md §6), with whether the deciding
/// flag also covers every subdomain (bundles.md §8 "DNS-blocked names", conditions 1 and 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyDecision {
    pub level: Level,
    /// The deciding level's `_SUBS` bit is set at the name or a parent.
    pub covers_subdomains: bool,
}

/// Decides a name from the flags of its own key and the union of its parents' flags (only their
/// `_SUBS` bits apply). `HAS_RICH` keys need rich-rule evaluation and aren't decided here.
pub fn decide_keys(at_name: Flags, parents: Flags) -> Option<KeyDecision> {
    let applying = at_name.exact().union(parents.subs_as_exact());
    let level = applying.top_level()?;
    let subs_bit = level.exact_flag().exact_as_subs();
    let covers = at_name.union(parents).subs().contains(subs_bit);
    Some(KeyDecision {
        level,
        covers_subdomains: covers,
    })
}

/// The fixed probe set for broad patterns (bundles.md §2): popular names across many TLDs, plus
/// random labels. A pattern matching more than half of it is broad.
pub const PROBE_NAMES: &[&str] = &[
    "google.com",
    "www.youtube.com",
    "facebook.com",
    "en.wikipedia.org",
    "amazon.co.uk",
    "baidu.com",
    "yandex.ru",
    "bbc.co.uk",
    "apple.com",
    "github.com",
    "netflix.com",
    "instagram.com",
    "linkedin.com",
    "reddit.com",
    "mail.ru",
    "vk.com",
    "qq.com",
    "spiegel.de",
    "lemonde.fr",
    "rakuten.co.jp",
    "naver.com",
    "globo.com",
    "mercadolibre.com.ar",
    "www.gov.uk",
    "wordpress.org",
    "mozilla.org",
    "archive.org",
    "booking.com",
    "zoom.us",
    "twitch.tv",
    "spotify.com",
    "googleapis.com",
    "cdn.jsdelivr.net",
    "debian.org",
    "nytimes.com",
    "abc.net.au",
    "cbc.ca",
    "www.gov.br",
    "orf.at",
    "nos.nl",
    "rai.it",
    "elpais.es",
    "yahoo.co.jp",
    "sina.com.cn",
    "skroutz.gr",
    "allegro.pl",
    "seznam.cz",
    "sapo.pt",
    "flipkart.in",
    "svt.se",
    "nrk.no",
    "yle.fi",
    "dr.dk",
    "srf.ch",
    "ynet.co.il",
    "news.com.au",
    "stuff.co.nz",
    "kompas.co.id",
    "detik.com",
    "zalo.me",
    "line.me",
    "notion.so",
    "vercel.app",
    "deno.dev",
    "x.ai",
    "bit.ly",
    "t.co",
    "nic.io",
    "registry.zip",
    "example.xyz",
    "qzx7k2.com",
    "mbv81jd.net",
    "xkcd-l9p.org",
    "t4w0zr.de",
    "lp2m8vq.io",
    "rn5ty.co",
    "h3j9u.app",
    "wq0e7.xyz",
    "zk1x4.info",
    "pv6b2.biz",
    "ff8gq.ru",
    "j2k5v.fr",
    "a9s8d7.jp",
    "m1n2b3.com.br",
    "kk2l0.com.au",
    "uy7t6.ca",
    "bg5n4.in",
    "c0v9x.cn",
    "q8w7e.nl",
    "o0p9i.se",
    "d4f5g.pl",
    "z9x8c.it",
    "r2t3y.es",
    "n6m7b.tr",
    "w1e2r.kr",
    "s8d9f.vn",
    "g3h4j.mx",
    "y5u6i.za",
    "e7r8t.ng",
    "i9o0p.ke",
];

/// True when a rule is broad (bundles.md §2): a whole TLD, a pattern matching more than half of
/// [`PROBE_NAMES`] (conditions other than `$denyallow` are ignored, so `||*^$dnstype=AAAA` counts),
/// or an IP rule covering at least a /8 of public IPv4 or a /16 of global unicast IPv6. The
/// caller applies it to blocks (`broad_block`) or allows (`broad_allow`).
pub fn is_broad(rule: &Rule) -> bool {
    if rule.is_badfilter() || rule.kind.is_browser() {
        return false;
    }
    match rule.kind {
        Kind::Name => is_whole_tld(rule),
        Kind::IpRange | Kind::IpLiteral => rule.ip_range().is_some_and(|r| is_broad_range(&r)),
        Kind::Pattern | Kind::Regex => {
            probe_matches(rule).is_some_and(|n| n.saturating_mul(2) > PROBE_NAMES.len())
        }
        _ => false,
    }
}

/// The most addresses a `$client` range may cover and still name an audience narrower than a
/// network: 16 (an IPv4 /28, an IPv6 /124). [`has_scoped_audience`] treats a wider range as
/// broad. Not [`is_broad_range`]'s destination thresholds: those leave private ranges out, and
/// private ranges are where LAN clients live, so a `192.168.1.0/24` audience is a whole LAN.
pub const MAX_SCOPED_CLIENT_ADDRESSES: u128 = 16;

/// True when a rule's client conditions restrict it to a selected audience (#67): at least one
/// positive (not `~`) `$client` or `$ctag` alternative, and no positive `$client` range wider
/// than [`MAX_SCOPED_CLIENT_ADDRESSES`] (alternatives within a modifier are ORed, so one broad
/// range opens the rule to that whole range whatever the other alternatives name). Exclusions
/// alone (`$client=~admin`, `$ctag=~kids`) restrict nothing worth the name: everyone else is the
/// audience. `$dnstype` and `$denyallow` select no audience. This says nothing of how many
/// devices a name or tag stands for, so a broad rule it holds for stays worth a warning.
pub fn has_scoped_audience(rule: &Rule) -> bool {
    let client = rule.spec.client.as_ref();
    let positive_client =
        client.is_some_and(|c| !c.permitted.names.is_empty() || !c.permitted.nets.is_empty());
    let positive_tag = rule.spec.ctag.as_ref().is_some_and(|t| !t.permitted.is_empty());
    let broad_range = client.is_some_and(|c| {
        c.permitted.nets.iter().any(|n| {
            crate::ip::IpRange::parse(n).is_none_or(|r| {
                r.last.saturating_sub(r.first).saturating_add(1) > MAX_SCOPED_CLIENT_ADDRESSES
            })
        })
    });
    (positive_client || positive_tag) && !broad_range
}

/// A single-label key with a subdomain flag: `||com^`, `*.zip^`, `.com^` (block or allow).
pub fn is_whole_tld(rule: &Rule) -> bool {
    rule.kind == Kind::Name && !rule.key.contains('.') && rule.flags.intersects(Flags::ALL_SUBS)
}

/// How many probe names a pattern rule matches (its `$denyallow` applied). `None` when the regex
/// can't be built.
pub fn probe_matches(rule: &Rule) -> Option<usize> {
    let spec = rule.pattern_spec()?;
    let regex = if spec.matches_all {
        None
    } else {
        Some(build_regex(spec.regex.as_deref()?).ok()?)
    };
    let mut n = 0usize;
    for name in PROBE_NAMES {
        let labels: Vec<&[u8]> = name.split('.').map(str::as_bytes).collect();
        // Entities are taken as covering nothing here (no public suffix list): the probe count
        // can only grow, which keeps the broad test on the safe side.
        if !denyallow_permits(&rule.spec.denyallow, &[], &labels, name, NameSemantics::Text) {
            continue;
        }
        if !shortcut_present(spec.shortcut.as_deref(), name) {
            continue;
        }
        let hit = match &regex {
            None => true,
            Some(re) => match spec.target {
                MatchTarget::Host => re.is_match(*name),
                MatchTarget::HttpHost => re.is_match(format!("{URL_PREFIX}{name}").as_str()),
            },
        };
        if hit {
            n = n.saturating_add(1);
        }
    }
    Some(n)
}

/// The public-suffix guardrail (bundles.md §2): a block of a public suffix below the top level,
/// such as `duckdns.org`. `is_public_suffix` is core's PSL lookup (private-section wildcards
/// excluded there). Not a broad block.
pub fn blocks_public_suffix_below_tld<F: Fn(&RuleName) -> bool>(rule: &Rule, is_public_suffix: F) -> bool {
    if rule.kind != Kind::Name || rule.is_exception() || !rule.flags.intersects(Flags::ALL_BLOCK) {
        return false;
    }
    match rule.name() {
        Some(name) => name.label_count() >= 2 && is_public_suffix(&name),
        None => false,
    }
}

/// True when a rule other than an IP rule can match an address's text: an IP-text pattern
/// (rules.md §6, bundles.md §6 `ip_pattern_classes`). Keys whose labels are decimal octets match
/// IPv4 text (a 4-label key at the address itself, a shorter one at its last labels with a
/// subdomain flag, as `||10.0.0^` does); patterns are checked against IPv4 and IPv6 text by their
/// automaton (over-approximating: any string of those characters). IP rules themselves are the
/// address set, not IP-text patterns.
pub fn can_match_ip_text(rule: &Rule) -> bool {
    if rule.is_badfilter() && !rule.is_rewrite() {
        return false;
    }
    match rule.key_kind() {
        Kind::Name | Kind::HostMapping => {
            let labels: Vec<&str> = rule.key.split('.').collect();
            let octets = labels.iter().all(|l| {
                !l.is_empty()
                    && l.len() <= 3
                    && l.bytes().all(|b| b.is_ascii_digit())
                    && l.parse::<u16>().is_ok_and(|v| v <= 255)
            });
            if !octets || labels.len() > 4 {
                return false;
            }
            if labels.len() == 4 {
                rule.flags.intersects(Flags::ALL_EXACT)
            } else {
                rule.flags.intersects(Flags::ALL_SUBS)
            }
        }
        Kind::Pattern | Kind::Regex => {
            let Some(spec) = rule.pattern_spec() else {
                return false;
            };
            if spec.matches_all {
                return true;
            }
            let Some(re) = spec.regex.as_deref() else {
                return false;
            };
            let prefix: &[u8] = match spec.target {
                MatchTarget::Host => b"",
                MatchTarget::HttpHost => URL_PREFIX.as_bytes(),
            };
            let v4 = crate::analysis::can_match_after(re, prefix, b"0123456789.").unwrap_or(true);
            v4 || crate::analysis::can_match_after(re, prefix, b"0123456789abcdef:.").unwrap_or(true)
        }
        _ => false,
    }
}

/// Deduplicates rules by storage identity, keeping the first (bundles.md §2 "dedupe").
pub fn dedupe(rules: Vec<Rule>) -> Vec<Rule> {
    let mut seen = HashSet::new();
    rules.into_iter().filter(|r| seen.insert(r.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Item, Line, classify_adblock_line};

    fn rule(l: &str) -> Rule {
        match classify_adblock_line(l, false) {
            Line::Items(v) => match v.into_iter().next() {
                Some(Item::Rule(r)) => r,
                o => panic!("{l}: {o:?}"),
            },
            o => panic!("{l}: {o:?}"),
        }
    }

    #[test]
    fn scoped_audiences() {
        let scoped = |l: &str| has_scoped_audience(&rule(l));
        for l in [
            "$client=kids-tablet",
            "*$client=kids-tablet",
            "||*^$client=kids-tablet",
            "/./$client=kids-tablet",
            "||com^$client=kids-tablet",
            "$ctag=kids",
            "$client=kids-tablet,dnstype=A",
            "$client=kids-tablet,denyallow=school.example",
            "$client=192.168.1.9",
            "$client=192.168.1.0/28",
            "$client=fd00::1",
            "$client=~admin,ctag=kids",
            "$client=kids-tablet|~admin",
            "$ctag=kids|~admin",
        ] {
            assert!(scoped(l), "{l}");
        }
        for l in [
            "$dnstype=A",
            "$denyallow=school.example",
            "*$denyallow=school.example",
            "||com^",
            "$client=~kids-tablet",
            "$ctag=~kids",
            "$client=~admin,ctag=~guests",
            "$client=0.0.0.0/0",
            "$client=192.168.1.0/24",
            "$client=192.168.1.0/27",
            "$client=fd00::/64",
            "$client=::/0",
            // A positive alternative doesn't hide a broad range beside it.
            "$client=kids-tablet|192.168.0.0/16",
            "$client=192.168.0.0/16,ctag=kids",
        ] {
            assert!(!scoped(l), "{l}");
        }
    }

    #[test]
    fn subsumption() {
        let b = Flags::B_EXACT | Flags::B_SUBS;
        assert!(is_subsumed(Flags::B_EXACT, Flags::B_SUBS));
        assert!(is_subsumed(b, Flags::B_SUBS));
        assert!(!is_subsumed(b | Flags::HAS_RICH, Flags::B_SUBS));
        assert!(!is_subsumed(Flags::A_EXACT, Flags::B_SUBS));
        assert!(!is_subsumed(Flags::B_EXACT | Flags::IMP_B_EXACT, Flags::B_SUBS));
        assert!(is_subsumed(
            Flags::B_EXACT | Flags::IMP_B_EXACT,
            Flags::B_SUBS | Flags::IMP_B_SUBS
        ));
        assert!(!is_subsumed(Flags::B_EXACT, Flags::B_EXACT));
        // Parts: a hot parent covers hot and cold keys, a cold parent only cold ones.
        let hot_parent = [(b, Part::Hot)];
        let cold_parent = [(b, Part::Cold)];
        assert!(is_subsumed(b, covering_subs(Part::Cold, &hot_parent)));
        assert!(is_subsumed(b, covering_subs(Part::Hot, &hot_parent)));
        assert!(is_subsumed(b, covering_subs(Part::Cold, &cold_parent)));
        assert!(!is_subsumed(b, covering_subs(Part::Hot, &cold_parent)));
        let mixed = [(Flags::B_SUBS, Part::Cold), (Flags::A_SUBS, Part::Hot)];
        assert_eq!(covering_subs(Part::Hot, &mixed), Flags::A_SUBS);
    }

    #[test]
    fn key_decisions() {
        let d = decide_keys(Flags::B_EXACT, Flags::NONE).unwrap();
        assert_eq!(
            d,
            KeyDecision {
                level: Level::Block,
                covers_subdomains: false
            }
        );
        let d = decide_keys(Flags::NONE, Flags::B_EXACT | Flags::B_SUBS).unwrap();
        assert!(d.covers_subdomains);
        let d = decide_keys(Flags::B_EXACT | Flags::B_SUBS, Flags::NONE).unwrap();
        assert!(d.covers_subdomains);
        assert_eq!(
            decide_keys(Flags::A_EXACT, Flags::B_SUBS).unwrap().level,
            Level::Allow
        );
        assert_eq!(
            decide_keys(Flags::A_EXACT, Flags::IMP_B_SUBS).unwrap().level,
            Level::ImportantBlock
        );
        assert_eq!(decide_keys(Flags::B_SUBS, Flags::NONE), None);
    }

    #[test]
    fn broad() {
        assert!(is_broad(&rule("||com^")));
        assert!(is_broad(&rule("||zip^")));
        assert!(is_broad(&rule("*.com^")));
        assert!(!is_broad(&rule("|com^")));
        assert!(!is_broad(&rule("||example.com^")));
        assert!(is_broad(&rule("||*^")));
        assert!(is_broad(&rule("*$denyallow=com|net")));
        assert!(is_broad(&rule("||*^$dnstype=AAAA")));
        assert!(!is_broad(&rule("||ads*^")));
        assert!(is_broad(&rule("/./")));
        assert!(!is_broad(&rule("-728x90-")));
        let ip = |s: &str| crate::formats::ip_indicator(crate::ip::IpRange::parse(s).unwrap());
        assert!(is_broad(&ip("8.0.0.0/8")));
        assert!(!is_broad(&ip("10.0.0.0/8")));
        assert!(!is_broad(&ip("1.2.3.0/24")));
        let com_net = PROBE_NAMES
            .iter()
            .filter(|n| n.ends_with(".com") || n.ends_with(".net"))
            .count();
        assert!(com_net * 2 < PROBE_NAMES.len());
        for n in PROBE_NAMES {
            assert!(RuleName::parse(n).is_ok(), "{n}");
        }
    }

    #[test]
    fn public_suffix() {
        let psl = |n: &RuleName| matches!(n.as_str(), "duckdns.org" | "co.uk");
        assert!(blocks_public_suffix_below_tld(&rule("||duckdns.org^"), psl));
        assert!(!blocks_public_suffix_below_tld(&rule("||x.duckdns.org^"), psl));
        assert!(!blocks_public_suffix_below_tld(&rule("@@||duckdns.org^"), psl));
        assert!(!blocks_public_suffix_below_tld(&rule("||org^"), psl));
    }

    #[test]
    fn ip_text_capable() {
        assert!(can_match_ip_text(&rule("||10.0.0^")));
        assert!(can_match_ip_text(&rule("0.0.0.0 1.2.3.4")));
        assert!(!can_match_ip_text(&rule("*.1.2.3.4^")));
        assert!(!can_match_ip_text(&rule("|10.0.0^")));
        assert!(
            !can_match_ip_text(&rule("||1.2.3.4^")),
            "an IP rule, not an IP-text pattern"
        );
        assert!(can_match_ip_text(&rule("1.2.3.4")));
        assert!(can_match_ip_text(&rule("||2001:db8::1^")));
        assert!(can_match_ip_text(&rule("/^10\\./")));
        assert!(!can_match_ip_text(&rule("/^ads\\./")));
        assert!(!can_match_ip_text(&rule("||example.com^")));
        assert!(can_match_ip_text(&rule("||*^")));
    }

    #[test]
    fn key_values() {
        let mut v = KeyValue::default();
        v.add(rule("||d.example^").fold().unwrap());
        v.add(rule("@@|d.example^").fold().unwrap());
        v.add(rule("||d.example^$dnstype=A").fold().unwrap());
        v.add(rule("||d.example^$dnstype=A").fold().unwrap());
        assert_eq!(
            v.flags,
            Flags::B_EXACT | Flags::B_SUBS | Flags::A_EXACT | Flags::HAS_RICH
        );
        assert_eq!(v.rich.len(), 1);
    }
}
