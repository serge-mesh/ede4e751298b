//! The rule model (rules.md §2–§4, bundles.md §4, storage.md §3 `feed_entries`).
//!
//! A [`Rule`] is what one entry of `feed_entries` holds: its identity is (rule type, `key`,
//! `kind`, `flags`, `value_json`); `raw`, `line_no` and the first-seen date are attributes of the
//! line it came from ([`Entry`]). [`Rule::from_stored`] rebuilds a rule from those columns alone,
//! so core can replay and compile without re-parsing. The views [`Rule::fold`],
//! [`Rule::pattern_spec`] and [`Rule::ip_spec`] give picket-bundle what it serialises (keys and
//! flags, `patterns.bin` entries, IP runs and `rich.json` rules) without parsing internals.

use std::net::IpAddr;

use picket_api::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::adguard::{self, MatchTarget};
use crate::entity::EntityExpansion;
use crate::flags::{Flags, Level};
use crate::ip::{IpRange, go_ip_string};
use crate::modifiers::{ClientCond, DnsTypeCond, NameSemantics, QueryCtx, TagCond, denyallow_permits};
use crate::name::{RuleName, reverse_dotted};
use crate::rewrite::DnsRewrite;

/// The rule type (rules.md §2). Every parsed rule has exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    Dns,
    Ip,
    Browser,
}

impl RuleType {
    /// All three, in storage order.
    pub const ALL: [RuleType; 3] = [RuleType::Dns, RuleType::Ip, RuleType::Browser];

    /// The storage text (`dns`, `ip`, `browser`).
    pub fn as_str(self) -> &'static str {
        match self {
            RuleType::Dns => "dns",
            RuleType::Ip => "ip",
            RuleType::Browser => "browser",
        }
    }

    /// Parses the storage text.
    pub fn parse(s: &str) -> Option<RuleType> {
        match s {
            "dns" => Some(RuleType::Dns),
            "ip" => Some(RuleType::Ip),
            "browser" => Some(RuleType::Browser),
            _ => None,
        }
    }
}

/// The match form of a rule (`feed_entries.kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A name folded into a key (host rules, hosts lines with a block address, `plain` and MISP
    /// names, `||d^`, `|d^`, `://d^`, `*.d^`, `.d^`, protocol/port extension). `key` is the
    /// reversed name; `flags` carry the forms.
    Name,
    /// A hosts line with another address (feeds.md §4): `key` is the reversed name.
    HostMapping,
    /// An AdGuard wildcard pattern: `key` is the pattern as urlfilter keeps it, ASCII-lowercased.
    Pattern,
    /// A `/regex/` rule: `key` is the pattern with its slashes, case kept.
    Regex,
    /// `||a.b.c.d^` / `|a.b.c.d^`: an IPv4 rule that also decides the name `a.b.c.d`
    /// (rules.md §1). `key` is the address.
    IpLiteral,
    /// An address or CIDR indicator (`plain` lists, MISP `cidr`), or a protocol/port extension rule
    /// on a bracketed IPv6 host (`|https://[2001:db8::1]^`, which also keeps its `spec.pattern`):
    /// `key` is its text.
    IpRange,
    /// A `$badfilter` rule: `key` is the key its target has; `spec.target` its form.
    Badfilter,
    /// A browser network rule; `key` is the rule text.
    Network,
    /// Element hiding (`##`, `#@#`).
    Cosmetic,
    /// Procedural cosmetic (`#?#`, `#@?#`).
    Procedural,
    /// Scriptlet (`##+js(…)`, `#@#+js(…)`).
    Scriptlet,
    /// uBlock Origin HTML filter (`##^`, `#@#^`).
    HtmlFilter,
    /// CSS injection (`#$#`, `#@$#`, `#$?#`, `#@$?#`).
    CssInject,
}

impl Kind {
    /// The storage text.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Name => "name",
            Kind::HostMapping => "host_mapping",
            Kind::Pattern => "pattern",
            Kind::Regex => "regex",
            Kind::IpLiteral => "ip_literal",
            Kind::IpRange => "ip_range",
            Kind::Badfilter => "badfilter",
            Kind::Network => "network",
            Kind::Cosmetic => "cosmetic",
            Kind::Procedural => "procedural",
            Kind::Scriptlet => "scriptlet",
            Kind::HtmlFilter => "html_filter",
            Kind::CssInject => "css_inject",
        }
    }

    /// Parses the storage text.
    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "name" => Kind::Name,
            "host_mapping" => Kind::HostMapping,
            "pattern" => Kind::Pattern,
            "regex" => Kind::Regex,
            "ip_literal" => Kind::IpLiteral,
            "ip_range" => Kind::IpRange,
            "badfilter" => Kind::Badfilter,
            "network" => Kind::Network,
            "cosmetic" => Kind::Cosmetic,
            "procedural" => Kind::Procedural,
            "scriptlet" => Kind::Scriptlet,
            "html_filter" => Kind::HtmlFilter,
            "css_inject" => Kind::CssInject,
            _ => return None,
        })
    }

    /// True for the browser kinds.
    pub fn is_browser(self) -> bool {
        matches!(
            self,
            Kind::Network
                | Kind::Cosmetic
                | Kind::Procedural
                | Kind::Scriptlet
                | Kind::HtmlFilter
                | Kind::CssInject
        )
    }
}

/// Everything a rule holds beyond key, kind and flags, serialised canonically as `value_json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleSpec {
    /// The AdGuard pattern (as urlfilter keeps it) of a rule written in network syntax whose kind
    /// isn't `pattern` or `regex` (there the key is the pattern). Absent for host rules, hosts
    /// lines and `plain`/MISP names, which `$badfilter` never touches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// `badfilter` rules: the kind of the rules they target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Kind>,
    /// Protocol/port extension (rules.md §2).
    #[serde(default, skip_serializing_if = "is_false")]
    pub extension: bool,
    /// The pattern as written is the bare separator `^`: urlfilter's `NewNetworkRule` sets
    /// `matchesNothing` for it, whatever the modifiers, so the rule never matches and never acts as
    /// a `$badfilter` (rules.md §3). (`/*` also normalises to `^` but matches every name.)
    #[serde(default, skip_serializing_if = "is_false")]
    pub matches_nothing: bool,
    /// A hosts line whose name isn't a key name (an IPv6 address such as `0.0.0.0 2001:db8::1`, or
    /// a token with other bytes): AdGuard's host rule matches that exact text, so the rule is the
    /// pattern `|name|` over the text form. It is still a host rule: never a `$badfilter` target,
    /// and it ranks after network rules (rules.md §3, §4).
    #[serde(default, skip_serializing_if = "is_false")]
    pub host_rule: bool,
    /// Negated request types (`$~image`), sorted. They don't change a DNS decision but are part of
    /// the identity `$badfilter` compares (urlfilter `negatesBadfilter`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnstype: Option<DnsTypeCond>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientCond>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctag: Option<TagCond>,
    /// `$denyallow` names, normalised and sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denyallow: Vec<RuleName>,
    /// `$denyallow` entities (`tracker.*` → `tracker`), sorted ([`crate::entity`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denyallow_entities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnsrewrite: Option<DnsRewrite>,
    /// A host mapping's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_ip: Option<IpAddr>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl RuleSpec {
    /// True when the rule has a condition or answer the key flags can't express (bundles.md §4
    /// `rich.json`): `$dnstype`, `$client`, `$ctag`, `$denyallow`, `$dnsrewrite` or a mapping.
    pub fn is_rich(&self) -> bool {
        self.dnstype.is_some()
            || self.client.is_some()
            || self.ctag.is_some()
            || self.has_denyallow()
            || self.dnsrewrite.is_some()
            || self.hosts_ip.is_some()
    }

    /// True with `$denyallow` names or entities.
    pub fn has_denyallow(&self) -> bool {
        !self.denyallow.is_empty() || !self.denyallow_entities.is_empty()
    }

    /// True with a restriction a DNS rule can carry (urlfilter `hasNoRestrictions`: `$client`,
    /// `$ctag`, `$dnstype`, `$denyallow`), which is what lets a too-wide pattern through.
    pub fn has_restriction(&self) -> bool {
        self.dnstype.is_some() || self.client.is_some() || self.ctag.is_some() || self.has_denyallow()
    }

    /// Number of AdGuard "specifiers" (urlfilter `calcRuleSpecs`, restricted to what DNS rules can
    /// carry): used only to rank rules within a level for attribution (rules.md §4).
    pub fn specifier_count(&self, flags: Flags) -> u32 {
        let important =
            Flags(Flags::IMP_B_EXACT.0 | Flags::IMP_B_SUBS.0 | Flags::IMP_A_EXACT.0 | Flags::IMP_A_SUBS.0);
        let bools = [
            flags.intersects(important),
            self.dnstype.is_some(),
            self.ctag.is_some(),
            self.client.is_some(),
            self.has_denyallow(),
        ];
        let n = bools
            .iter()
            .filter(|b| **b)
            .count()
            .saturating_add(self.not_types.len());
        u32::try_from(n).unwrap_or(u32::MAX)
    }
}

/// True when a stored pattern key is one urlfilter refuses as too wide without a restriction
/// ([`adguard::is_pattern_too_wide`], which judges the pattern as written): a key `x^` may be
/// `x/*` normalised, so it is too wide only when that reading is too.
fn is_too_wide_key(key: &str) -> bool {
    adguard::is_pattern_too_wide(key)
        && key
            .strip_suffix('^')
            .is_none_or(|p| adguard::is_pattern_too_wide(&format!("{p}/*")))
}

/// One parsed rule: its storage identity and structured meaning.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rule {
    pub rule_type: RuleType,
    pub kind: Kind,
    pub key: String,
    pub flags: Flags,
    pub spec: RuleSpec,
}

/// A rule with the attributes of the line it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub rule: Rule,
    /// The line as written (trimmed).
    pub raw: String,
    /// 1-based line number (for MISP, the 1-based index in `list`).
    pub line_no: u64,
    /// The `picket-first-seen` date in force for this line, already clamped to the run time
    /// (feeds.md §4); `None` means the run's own time.
    pub first_seen: Option<Timestamp>,
}

/// Why stored columns don't make a rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoredRuleError {
    #[error("unknown rule type {0:?}")]
    RuleType(String),
    #[error("unknown kind {0:?}")]
    Kind(String),
    #[error("bad value_json: {0}")]
    Value(String),
    #[error("key doesn't fit the kind")]
    Key,
    #[error("columns contradict each other: {0}")]
    Inconsistent(&'static str),
}

impl Rule {
    /// The canonical `value_json` (`{}` when the spec is empty).
    pub fn value_json(&self) -> String {
        serde_json::to_string(&self.spec).unwrap_or_else(|_| "{}".to_string())
    }

    /// Rebuilds a rule from its `feed_entries` identity columns.
    pub fn from_stored(
        rule_type: &str,
        kind: &str,
        key: &str,
        flags: u16,
        value_json: &str,
    ) -> Result<Rule, StoredRuleError> {
        let rule_type =
            RuleType::parse(rule_type).ok_or_else(|| StoredRuleError::RuleType(rule_type.to_string()))?;
        let kind = Kind::parse(kind).ok_or_else(|| StoredRuleError::Kind(kind.to_string()))?;
        let spec: RuleSpec = if value_json.is_empty() {
            RuleSpec::default()
        } else {
            serde_json::from_str(value_json).map_err(|e| StoredRuleError::Value(e.to_string()))?
        };
        let rule = Rule {
            rule_type,
            kind,
            key: key.to_string(),
            flags: Flags(flags),
            spec,
        };
        let key_ok = match rule.key_kind() {
            Kind::Name | Kind::HostMapping => RuleName::from_reversed(key).is_ok(),
            Kind::IpLiteral | Kind::IpRange => IpRange::parse(key).is_some(),
            // A too-wide pattern (`$client=…` alone, `*`, `||`) matches every name; urlfilter
            // keeps it only with a restriction (rules.md §2), as classify does.
            Kind::Pattern if is_too_wide_key(key) => rule.spec.has_restriction(),
            _ => !key.is_empty(),
        };
        if !key_ok {
            return Err(StoredRuleError::Key);
        }
        rule.check_consistent().map_err(StoredRuleError::Inconsistent)?;
        Ok(rule)
    }

    /// The invariants every parsed rule holds, checked on rules read back from storage (a corrupt
    /// row must not become a rule that blocks and allows at once, or a mapping with no address).
    fn check_consistent(&self) -> Result<(), &'static str> {
        let target = match self.kind {
            Kind::Badfilter => match self.spec.target {
                Some(t) if t != Kind::Badfilter && !t.is_browser() => t,
                _ => return Err("a $badfilter rule without a target kind"),
            },
            k => k,
        };
        let type_ok = match target {
            k if k.is_browser() => self.rule_type == RuleType::Browser,
            Kind::Name | Kind::HostMapping | Kind::Regex => self.rule_type == RuleType::Dns,
            Kind::IpLiteral | Kind::IpRange => self.rule_type == RuleType::Ip,
            _ => self.rule_type != RuleType::Browser,
        };
        if !type_ok {
            return Err("rule type doesn't fit the kind");
        }
        if self.kind.is_browser() {
            return if self.flags.is_empty() {
                Ok(())
            } else {
                Err("a browser rule with key flags")
            };
        }
        if self.flags.and(Flags::ALL_LEVELS).is_empty() || !self.flags.without(Flags::ALL_LEVELS).is_empty() {
            return Err("flags without a level bit, or with bits a rule never sets");
        }
        if self.flags.intersects(Flags::ALL_ALLOW) && self.flags.intersects(Flags::ALL_BLOCK) {
            return Err("both allow and block flags");
        }
        // A mapping is a keyed host mapping, or a hosts line's exact-text pattern (a token keys
        // can't hold, such as an IPv6 address: classify::hosts_text_rule).
        let may_map = self.kind == Kind::HostMapping || (self.kind == Kind::Pattern && self.spec.host_rule);
        if (self.kind == Kind::HostMapping && self.spec.hosts_ip.is_none())
            || (self.spec.hosts_ip.is_some() && !may_map)
        {
            return Err("a host mapping needs its address, and only a mapping has one");
        }
        Ok(())
    }

    /// The kind that shapes the key: the target's kind for a `badfilter` rule.
    pub fn key_kind(&self) -> Kind {
        match self.kind {
            Kind::Badfilter => self.spec.target.unwrap_or(Kind::Pattern),
            k => k,
        }
    }

    /// True for a hosts-line mapping to an address (keyed, or a text pattern): it answers with
    /// `spec.hosts_ip` (rules.md §3).
    pub fn is_mapping(&self) -> bool {
        self.spec.hosts_ip.is_some()
    }

    /// True for an exception (`@@`).
    pub fn is_exception(&self) -> bool {
        self.flags.intersects(Flags::ALL_ALLOW)
    }

    /// True for `$important`.
    pub fn is_important(&self) -> bool {
        self.flags.intersects(Flags(
            Flags::IMP_B_EXACT.0 | Flags::IMP_B_SUBS.0 | Flags::IMP_A_EXACT.0 | Flags::IMP_A_SUBS.0,
        ))
    }

    /// The precedence level (rules.md §4).
    pub fn level(&self) -> Option<Level> {
        self.flags.top_level()
    }

    /// True for a `$badfilter` rule.
    pub fn is_badfilter(&self) -> bool {
        self.kind == Kind::Badfilter
    }

    /// True for a `$dnsrewrite` rule (including a `$badfilter` rule that carries one, which acts
    /// as a rewrite in AdGuard).
    pub fn is_rewrite(&self) -> bool {
        self.spec.dnsrewrite.is_some()
    }

    /// The AdGuard pattern of a rule written in network syntax.
    pub fn adguard_pattern(&self) -> Option<&str> {
        match self.kind {
            Kind::Pattern | Kind::Regex => Some(&self.key),
            _ => self.spec.pattern.as_deref(),
        }
    }

    /// The name of a keyed rule (name, host mapping, IP literal, or a badfilter targeting one).
    pub fn name(&self) -> Option<RuleName> {
        match self.key_kind() {
            Kind::Name | Kind::HostMapping => RuleName::from_reversed(&self.key).ok(),
            Kind::IpLiteral => RuleName::parse(&self.key).ok(),
            _ => None,
        }
    }

    /// The address range of an IP rule.
    pub fn ip_range(&self) -> Option<IpRange> {
        match self.key_kind() {
            Kind::IpLiteral | Kind::IpRange => IpRange::parse(&self.key),
            _ => None,
        }
    }

    /// The `rich.json` rule for this rule's conditions and answer, if it has any.
    pub fn rich(&self) -> Option<RichRule> {
        if !self.spec.is_rich() {
            return None;
        }
        Some(RichRule {
            flags: self.flags.and(Flags::ALL_LEVELS),
            dnstype: self.spec.dnstype.clone(),
            client: self.spec.client.clone(),
            ctag: self.spec.ctag.clone(),
            denyallow: self.spec.denyallow.clone(),
            denyallow_entities: self
                .spec
                .denyallow_entities
                .iter()
                .map(|p| EntityExpansion::unexpanded(p))
                .collect(),
            dnsrewrite: self.spec.dnsrewrite.clone(),
            hosts_ip: self.spec.hosts_ip,
            order: None,
            unless: Vec::new(),
        })
    }

    /// The key this rule folds into, for the domain FST (bundles.md §2 "folding rule forms into
    /// flags"): the reversed name and the flags it adds there. A rule with conditions or an
    /// answer adds only `HAS_RICH` and its [`RichRule`] goes to `rich.json`. `None` for patterns,
    /// IP ranges, browser rules and `$badfilter` rules (which the compiler resolves with
    /// [`crate::badfilter::resolve`]), except that a `$badfilter` rule carrying `$dnsrewrite` still
    /// rewrites, as in AdGuard.
    pub fn fold(&self) -> Option<Folded> {
        let key = match self.key_kind() {
            Kind::Name | Kind::HostMapping => self.key.clone(),
            Kind::IpLiteral => reverse_dotted(&self.key),
            _ => return None,
        };
        if self.kind == Kind::Badfilter {
            let rich = self.rich().filter(|r| r.dnsrewrite.is_some())?;
            return Some(Folded {
                key,
                flags: Flags::HAS_RICH,
                rich: Some(rich),
            });
        }
        match self.rich() {
            Some(rich) => Some(Folded {
                key,
                flags: Flags::HAS_RICH,
                rich: Some(rich),
            }),
            None => Some(Folded {
                key,
                flags: self.flags.and(Flags::ALL_LEVELS),
                rich: None,
            }),
        }
    }

    /// The `patterns.bin` view of a wildcard or regex rule (bundles.md §4). Patterns use the
    /// `_EXACT` bits. `None` for other kinds, and for a `$badfilter` rule without `$dnsrewrite`.
    pub fn pattern_spec(&self) -> Option<PatternSpec> {
        if !matches!(self.key_kind(), Kind::Pattern | Kind::Regex) {
            return None;
        }
        let rich = self.rich();
        if self.kind == Kind::Badfilter && rich.as_ref().is_none_or(|r| r.dnsrewrite.is_none()) {
            return None;
        }
        let source = self.key.clone();
        let exact = self.flags.exact().union(self.flags.subs_as_exact());
        let nothing = self.spec.matches_nothing;
        Some(PatternSpec {
            regex: if nothing {
                None
            } else {
                adguard::pattern_rust_regex(&source).ok()
            },
            target: adguard::match_target(&source),
            shortcut: adguard::shortcut(&source),
            matches_all: !nothing
                && (adguard::matches_all(&source) || adguard::pattern_to_go_regex(&source) == ".*"),
            flags: if rich.is_some() { Flags::HAS_RICH } else { exact },
            rich: rich.map(|mut r| {
                r.flags = exact;
                r
            }),
            source,
        })
    }

    /// The IP-shard view of an IP rule (bundles.md §4): its range and the `_EXACT` flags or rich
    /// rule its addresses get.
    pub fn ip_spec(&self) -> Option<IpRuleSpec> {
        if !matches!(self.key_kind(), Kind::IpLiteral | Kind::IpRange) {
            return None;
        }
        if self.kind == Kind::Badfilter && self.spec.dnsrewrite.is_none() {
            return None;
        }
        let range = self.ip_range()?;
        let exact = self.flags.exact().union(self.flags.subs_as_exact());
        let rich = self.rich().map(|mut r| {
            r.flags = exact;
            r
        });
        Some(IpRuleSpec {
            range,
            flags: if rich.is_some() { Flags::HAS_RICH } else { exact },
            rich,
        })
    }

    /// For an IP literal, the address text its key holds.
    pub fn ip_text(&self) -> Option<String> {
        self.ip_range().map(|r| go_ip_string(r.first_ip()))
    }
}

/// A key and the flags a rule adds to it (see [`Rule::fold`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folded {
    /// Reversed name (`org.example.ads`).
    pub key: String,
    /// Level bits, or `HAS_RICH` alone for a rich rule.
    pub flags: Flags,
    /// The rich rule, when the rule has conditions or an answer.
    pub rich: Option<RichRule>,
}

/// A wildcard or regex rule as `patterns.bin` holds it (bundles.md §4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternSpec {
    /// The AdGuard pattern (`||ads*.example^`, `/regex/`).
    pub source: String,
    /// The equivalent Rust regex (`(?i)` included). `None` when Go refuses the regex: the rule
    /// matches nothing, as in AdGuard.
    pub regex: Option<String>,
    /// What the regex runs against.
    pub target: MatchTarget,
    /// urlfilter's shortcut: a literal that must occur in `"http://"` + text for the rule to match.
    /// It doubles as the Aho-Corasick prefilter literal; a rule without one runs on every query.
    pub shortcut: Option<String>,
    /// urlfilter skips the regex: the rule matches every text (that holds its shortcut).
    pub matches_all: bool,
    /// `_EXACT` level bits, or `HAS_RICH` alone when `rich` is set.
    pub flags: Flags,
    /// Conditions and answer, with the level bits in `rich.flags`.
    pub rich: Option<RichRule>,
}

/// An IP rule as an IP shard holds it (bundles.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpRuleSpec {
    pub range: IpRange,
    /// `_EXACT` level bits, or `HAS_RICH` alone when `rich` is set.
    pub flags: Flags,
    pub rich: Option<RichRule>,
}

/// A `rich.json` rule (bundles.md §4): the level bits it decides at, its conditions, and its
/// answer (`$dnsrewrite`, or a host mapping's address).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RichRule {
    /// Level bits: the forms for a key (`_EXACT`/`_SUBS`), `_EXACT` for patterns and IP rules.
    pub flags: Flags,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnstype: Option<DnsTypeCond>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientCond>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctag: Option<TagCond>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denyallow: Vec<RuleName>,
    /// `$denyallow` entities, expanded by the compiler ([`crate::entity::EntityExpansion`]); in
    /// `rich.json` each is a reference into the bundle's [`crate::entity::EntityTable`]. A block
    /// or rewrite rule with an unexpanded one doesn't apply (fail safe).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denyallow_entities: Vec<EntityExpansion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnsrewrite: Option<DnsRewrite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_ip: Option<IpAddr>,
    /// urlfilter's filing of a `$dnsrewrite` rule, which orders a query's rewrites
    /// ([`crate::order`]); set by the compiler from [`crate::matcher::BundleMatcher::match_orders`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<crate::order::MatchOrder>,
    /// `$badfilter` rules with their own `$dnstype`/`$denyallow` remove this rule only for the
    /// queries they match themselves (urlfilter applies a `$badfilter` only when it matches the
    /// request); see [`crate::badfilter`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unless: Vec<Suppressor>,
}

impl RichRule {
    /// True when the rule's conditions hold for this query. `labels` and `text` are the name (or
    /// an address's text) as labels and as AdGuard text; `sem` says how `$denyallow` compares.
    pub fn conditions_match(
        &self,
        labels: &[&[u8]],
        text: &str,
        ctx: &QueryCtx<'_>,
        sem: NameSemantics,
    ) -> bool {
        if self.fails_safe() || self.dnstype.as_ref().is_some_and(|c| !c.matches(ctx.qtype)) {
            return false;
        }
        if self.ctag.as_ref().is_some_and(|c| !c.matches(ctx.client_tags)) {
            return false;
        }
        if self.client.as_ref().is_some_and(|c| !c.matches(ctx)) {
            return false;
        }
        if !denyallow_permits(&self.denyallow, &self.denyallow_entities, labels, text, sem) {
            return false;
        }
        !self.unless.iter().any(|s| s.suppresses(labels, text, ctx, sem))
    }

    /// True when the rule names a `$denyallow` entity that wasn't expanded (no public suffix
    /// list, or not linked to the bundle's [`crate::entity::EntityTable`]).
    pub fn has_unexpanded_entity(&self) -> bool {
        self.denyallow_entities.iter().any(|e| !e.is_expanded())
            || self
                .unless
                .iter()
                .any(|s| s.denyallow_entities.iter().any(|e| !e.is_expanded()))
    }

    /// A block or rewrite rule with an unexpanded entity of its own doesn't apply (it would
    /// exempt no name and so block every one; review round 2, CC4); an exception still applies,
    /// as if the entity covered nothing, since that only allows more.
    fn fails_safe(&self) -> bool {
        !self.flags.intersects(Flags::ALL_ALLOW) && self.denyallow_entities.iter().any(|e| !e.is_expanded())
    }

    /// True when the rule's conditions depend on the query beyond its name: `$dnstype`,
    /// `$client` or `$ctag`.
    pub fn depends_on_query(&self) -> bool {
        self.dnstype.is_some() || self.client.is_some() || self.ctag.is_some()
    }

    /// True when the conditions hold for some query for this name, of any type and from any client
    /// (bundles.md §3): only `$denyallow` and context-free suppressors can rule it out.
    pub fn conditions_match_any_query(&self, labels: &[&[u8]], text: &str, sem: NameSemantics) -> bool {
        let ctx = QueryCtx::default();
        !self.fails_safe()
            && denyallow_permits(&self.denyallow, &self.denyallow_entities, labels, text, sem)
            && !self
                .unless
                .iter()
                .any(|s| s.dnstype.is_none() && s.suppresses(labels, text, &ctx, sem))
    }
}

/// The conditions of a `$badfilter` rule that has its own `$dnstype` or `$denyallow`: it removes
/// its target only for queries where these hold.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Suppressor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnstype: Option<DnsTypeCond>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denyallow: Vec<RuleName>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denyallow_entities: Vec<EntityExpansion>,
}

impl Suppressor {
    /// True when the `$badfilter` rule matches this query (so its target is removed for it).
    pub fn suppresses(&self, labels: &[&[u8]], text: &str, ctx: &QueryCtx<'_>, sem: NameSemantics) -> bool {
        self.dnstype.as_ref().is_none_or(|c| c.matches(ctx.qtype))
            && denyallow_permits(&self.denyallow, &self.denyallow_entities, labels, text, sem)
    }

    /// True when it has no condition: the target is removed outright.
    pub fn is_unconditional(&self) -> bool {
        self.dnstype.is_none() && self.denyallow.is_empty() && self.denyallow_entities.is_empty()
    }

    /// The suppressor of a `$badfilter` rule (its own `$dnstype` and `$denyallow`).
    pub fn of(badfilter: &Rule) -> Suppressor {
        Suppressor {
            dnstype: badfilter.spec.dnstype.clone(),
            denyallow: badfilter.spec.denyallow.clone(),
            denyallow_entities: badfilter
                .spec
                .denyallow_entities
                .iter()
                .map(|p| EntityExpansion::unexpanded(p))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Item, Line, classify_adblock_line};
    use crate::modifiers::DnsTypeCond;

    #[test]
    fn stored_roundtrip() {
        let rule = Rule {
            rule_type: RuleType::Dns,
            kind: Kind::Name,
            key: "org.example".into(),
            flags: Flags::B_EXACT | Flags::B_SUBS,
            spec: RuleSpec {
                pattern: Some("||example.org^".into()),
                dnstype: DnsTypeCond::parse("A"),
                ..RuleSpec::default()
            },
        };
        let json = rule.value_json();
        assert_eq!(
            json,
            r#"{"pattern":"||example.org^","dnstype":{"permitted":[1]}}"#
        );
        let back = Rule::from_stored("dns", "name", "org.example", rule.flags.bits(), &json).unwrap();
        assert_eq!(back, rule);
        assert!(Rule::from_stored("dns", "name", "org..example", 1, "{}").is_err());
        assert!(Rule::from_stored("dns", "bogus", "x", 1, "{}").is_err());
        // Contradictory columns (a corrupt row) don't make a rule.
        let bad = |t: &str, k: &str, key: &str, f: Flags, v: &str| {
            matches!(
                Rule::from_stored(t, k, key, f.bits(), v),
                Err(StoredRuleError::Inconsistent(_))
            )
        };
        assert!(bad(
            "dns",
            "name",
            "org.example",
            Flags::B_EXACT | Flags::A_EXACT,
            "{}"
        ));
        assert!(bad("dns", "name", "org.example", Flags::NONE, "{}"));
        assert!(bad(
            "dns",
            "name",
            "org.example",
            Flags::HAS_RICH | Flags::B_EXACT,
            "{}"
        ));
        assert!(bad("ip", "name", "org.example", Flags::B_EXACT, "{}"));
        assert!(bad("dns", "host_mapping", "org.example", Flags::B_EXACT, "{}"));
        assert!(bad(
            "dns",
            "name",
            "org.example",
            Flags::B_EXACT,
            r#"{"hosts_ip":"192.0.2.1"}"#
        ));
        assert!(bad("dns", "badfilter", "org.example", Flags::B_EXACT, "{}"));
        assert!(bad("browser", "network", "||x^", Flags::B_EXACT, "{}"));
        assert!(bad("dns", "network", "||x^", Flags::NONE, "{}"));
        assert!(bad("dns", "ip_literal", "1.2.3.4", Flags::B_EXACT, "{}"));
        assert!(Rule::from_stored("ip", "pattern", "||2001:db8::1^", 1, "{}").is_ok());
        // An empty pattern stands only with a restriction (fuzz/rules adblock_line found
        // `$client=…` lines that didn't rebuild, so the compiler skipped them).
        for line in [
            "$client=192.168.1.5",
            "@@$client=foo",
            "$dnstype=A",
            "$ctag=kids",
            "$denyallow=example.org",
            "$client=foo,badfilter",
            "$client=192.994.\0\0\0\0\0\0\0\0\x06.0/24",
        ] {
            let Line::Items(items) = classify_adblock_line(line, false) else {
                panic!("{line:?}")
            };
            let [Item::Rule(r)] = &items[..] else {
                panic!("{line:?}: {items:?}")
            };
            assert!(r.key.is_empty(), "{line:?}");
            let back = Rule::from_stored(
                r.rule_type.as_str(),
                r.kind.as_str(),
                &r.key,
                r.flags.bits(),
                &r.value_json(),
            );
            assert_eq!(back.as_ref(), Ok(r), "{line:?}");
        }
        // A corrupt row with a too-wide pattern and no restriction is refused like the line
        // would be; `a^` stands (it may be `a/*`, which isn't too wide), and with a restriction
        // every too-wide key does.
        for key in ["", "*", "||", "|", "^", "ab"] {
            assert!(
                matches!(
                    Rule::from_stored("dns", "pattern", key, 1, "{}"),
                    Err(StoredRuleError::Key)
                ),
                "{key:?}"
            );
            let restricted = r#"{"dnstype":{"permitted":[1]}}"#;
            assert!(
                Rule::from_stored("dns", "pattern", key, 1, restricted).is_ok(),
                "{key:?}"
            );
        }
        for line in ["a/*", "ab/*", "*$client=foo", "||$ctag=kids", "@@*$dnstype=AAAA"] {
            let Line::Items(items) = classify_adblock_line(line, false) else {
                panic!("{line:?}")
            };
            let [Item::Rule(r)] = &items[..] else {
                panic!("{line:?}: {items:?}")
            };
            let back = Rule::from_stored(
                r.rule_type.as_str(),
                r.kind.as_str(),
                &r.key,
                r.flags.bits(),
                &r.value_json(),
            );
            assert_eq!(back.as_ref(), Ok(r), "{line:?}");
        }
        assert!(
            Rule::from_stored(
                "dns",
                "host_mapping",
                "org.example",
                1,
                r#"{"hosts_ip":"192.0.2.1"}"#
            )
            .is_ok()
        );
        let f = rule.fold().unwrap();
        assert_eq!(f.flags, Flags::HAS_RICH);
        assert_eq!(f.rich.unwrap().flags, Flags::B_EXACT | Flags::B_SUBS);
        let plain = Rule {
            spec: RuleSpec::default(),
            ..rule
        };
        assert_eq!(plain.fold().unwrap().flags, Flags::B_EXACT | Flags::B_SUBS);
        assert_eq!(plain.value_json(), "{}");
    }
}
