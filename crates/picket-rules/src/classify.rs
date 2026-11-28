//! Line classification (rules.md §2) for AdGuard/ABP/uBO syntax, with AdGuard's own reading of
//! each line (urlfilter `NewRule`: cosmetic first, then host rule, then network rule).

use std::net::IpAddr;

use crate::adguard::{self, MatchTarget};
use crate::browser::{self, CosmeticParse};
use crate::flags::Flags;
use crate::ip::{IpRange, go_ip_string, parse_go_ip};
use crate::modifiers::{ClientCond, DenyallowError, DnsTypeCond, TagCond, parse_denyallow};
use crate::name::{MAX_NAME_LEN, NameError, RuleName, is_adguard_host_name};
use crate::rewrite::parse_dnsrewrite;
use crate::rule::{Kind, Rule, RuleSpec, RuleType};

/// Why a rule was dropped on purpose (a parse warning, feeds.md §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WarnReason {
    /// An option neither AdGuard's DNS engine nor browsers know (rules.md §2).
    UnknownModifier,
    /// A DNS rule whose pattern is under 3 characters (or `*`, `|`, `||`) with no restriction
    /// (rules.md §2). A browser rule like it is kept ([`NoticeReason::BroadBrowser`]).
    TooWide,
    /// AdGuard-only browser syntax uBlock Origin can't read: `#%#`, `#@%#`, `$$`, `$@$`, and
    /// options such as `$replace`, `$cookie`, `$network`, `$jsonprune` (`ADGUARD_ONLY_MODIFIERS`).
    AdguardOnly,
    /// A `browser` rule between `!#if` and its `!#endif`.
    Conditional,
    /// A DNS modifier with a value AdGuard refuses (`$dnstype=`, `$ctag=Bad`, …).
    InvalidModifierValue,
    /// A value Picket can't express: a host-IP mapping whose name isn't a key name.
    UnsupportedValue,
}

/// Something worth knowing about a rule that is kept (it doesn't drop the rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NoticeReason {
    /// A browser network rule whose pattern is under 3 characters (or `*`, `|`, `||`) with no
    /// restriction (`$image`, `*$third-party`, `$removeparam=utm_source`): it applies to most
    /// requests. The browser blocker applies it with its own semantics, so it is kept; only DNS
    /// rules are dropped for this (rules.md §2).
    BroadBrowser,
}

/// Why a line can't be read (a parse error, feeds.md §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorReason {
    /// Not valid syntax for the format.
    Syntax,
    /// A name that fails normalisation (rules.md §1).
    BadName,
    /// An address that doesn't parse.
    BadAddress,
    /// Longer than the line limit.
    TooLong,
    /// Not valid UTF-8.
    Encoding,
    /// An unparseable `picket-first-seen` directive.
    FirstSeen,
}

/// One result of a line: a rule, a warning or an error. A hosts line with several names gives
/// one item per name.
#[expect(
    clippy::large_enum_variant,
    reason = "transient per line; boxing would allocate for every rule"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Rule(Rule),
    Warning {
        rule_type: Option<RuleType>,
        reason: WarnReason,
    },
    Error(ErrorReason),
    /// About the rule before it on the same line, which is kept.
    Notice(NoticeReason),
}

/// What a line is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// Empty, comment, header or directive.
    Skipped,
    /// Rules, warnings and errors.
    Items(Vec<Item>),
}

/// Request types urlfilter knows; their negations are allowed in `dns` rules.
const URLFILTER_TYPES: &[&str] = &[
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

/// Modifiers browsers (uBlock Origin, ABP, AdGuard) know that make a rule `browser`.
const BROWSER_MODIFIERS: &[&str] = &[
    "script",
    "stylesheet",
    "subdocument",
    "object",
    "object-subrequest",
    "image",
    "xmlhttprequest",
    "media",
    "font",
    "websocket",
    "webrtc",
    "ping",
    "beacon",
    "other",
    "document",
    "doc",
    "popup",
    "popunder",
    "third-party",
    "first-party",
    "3p",
    "1p",
    "strict1p",
    "strict3p",
    "strict-first-party",
    "strict-third-party",
    "all",
    "domain",
    "from",
    "to",
    "csp",
    "redirect",
    "redirect-rule",
    "removeparam",
    "queryprune",
    "rewrite",
    "empty",
    "mp4",
    "inline-script",
    "inline-font",
    "xhr",
    "frame",
    "css",
    "ehide",
    "elemhide",
    "ghide",
    "generichide",
    "shide",
    "specifichide",
    "genericblock",
    "header",
    "method",
    "permissions",
    "cname",
    "ipaddress",
    "uritransform",
    "urltransform",
    "urlskip",
    "match-case",
    "sitekey",
    "reason",
    "_",
];

/// Options only AdGuard reads: uBlock Origin can't, so a rule with one is dropped and counted
/// (rules.md §2, with `$replace`).
const ADGUARD_ONLY_MODIFIERS: &[&str] = &[
    "replace",
    "cookie",
    "network",
    "app",
    "jsinject",
    "urlblock",
    "content",
    "extension",
    "stealth",
    "removeheader",
    "hls",
    "jsonprune",
    "xmlprune",
    "referrerpolicy",
];

/// Classifies one line of an `adblock` feed. `in_conditional` is true between `!#if` and its
/// `!#endif`; directives themselves are skipped here and tracked by the caller.
pub fn classify_adblock_line(line: &str, in_conditional: bool) -> Line {
    let line = line.trim();
    if line.is_empty() {
        return Line::Skipped;
    }
    if line.starts_with('!') {
        return Line::Skipped;
    }
    if line.starts_with('[') && line.ends_with(']') && !line.contains('$') {
        return Line::Skipped;
    }
    if is_adguard_comment(line) {
        return Line::Skipped;
    }
    // 1. Cosmetic (urlfilter tries these first).
    if let Some(c) = browser::parse_cosmetic(line) {
        let item = match c {
            CosmeticParse::AdguardOnly => Item::Warning {
                rule_type: Some(RuleType::Browser),
                reason: WarnReason::AdguardOnly,
            },
            CosmeticParse::Invalid => Item::Error(ErrorReason::Syntax),
            CosmeticParse::Rule(_) if in_conditional => Item::Warning {
                rule_type: Some(RuleType::Browser),
                reason: WarnReason::Conditional,
            },
            CosmeticParse::Rule(r) => Item::Rule(browser_rule(r.kind, line)),
        };
        return Line::Items(vec![item]);
    }
    // 2. Host rule (hosts line or a single valid host name).
    if let Some(items) = host_rule_items(line) {
        return Line::Items(items);
    }
    // 3. Network rule.
    let (item, notice) = classify_network_noting(line, in_conditional, false);
    Line::Items(match notice {
        Some(n) => vec![item, Item::Notice(n)],
        None => vec![item],
    })
}

/// urlfilter `isComment`: `!…`, or `#…` that isn't a cosmetic rule without domains.
fn is_adguard_comment(line: &str) -> bool {
    if line.starts_with('!') {
        return true;
    }
    if !line.starts_with('#') {
        return false;
    }
    if line.len() == 1 {
        return true;
    }
    ![
        "##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#$?#", "#@$?#", "#%#", "#@%#",
    ]
    .iter()
    .any(|m| line.starts_with(m))
}

fn browser_rule(kind: Kind, text: &str) -> Rule {
    Rule {
        rule_type: RuleType::Browser,
        kind,
        key: text.to_string(),
        flags: Flags::NONE,
        spec: RuleSpec::default(),
    }
}

/// True for the addresses whose hosts lines block (feeds.md §4): `0.0.0.0`, `127.0.0.1`, `::`.
pub fn is_block_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.octets() == [127, 0, 0, 1],
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// urlfilter `NewHostRule`. Its comment stripping cuts the line one byte before the first `#`
/// (`ruleText[0 : commentIndex-1]`), as AdGuard does. `None` when the line isn't a host rule.
pub(crate) fn host_rule_items(line: &str) -> Option<Vec<Item>> {
    let mut text = line;
    if let Some(idx) = line.find('#')
        && idx > 0
    {
        let cut = idx.saturating_sub(1);
        text = line.get(..cut).unwrap_or_else(|| line.get(..idx).unwrap_or(""));
    }
    let mut tokens = text.split([' ', '\t']).filter(|t| !t.is_empty());
    let first = tokens.next()?;
    let rest: Vec<&str> = tokens.collect();
    if rest.is_empty() {
        // One token: a host rule if it passes AdGuard's host-name check (rules.md §3), checked on
        // the A-label, lowercase form. A trailing dot fails that check, so such a line stays a
        // pattern (`ads.` is a fragment, not the name `ads`); only keyed forms strip it (§1).
        if first.ends_with('.') {
            return None;
        }
        let name = RuleName::parse(first).ok()?;
        if !is_adguard_host_name(name.as_str()) {
            return None;
        }
        return Some(vec![Item::Rule(name_rule(
            &name,
            Flags::B_EXACT,
            RuleSpec::default(),
        ))]);
    }
    let ip = parse_go_ip(first)?;
    Some(rest.iter().map(|n| hosts_name(ip, n)).collect())
}

/// One name of a hosts line.
pub(crate) fn hosts_name(ip: IpAddr, name: &str) -> Item {
    let name = match RuleName::parse(name) {
        Ok(n) => n,
        // Only bytes keys can't hold make a text rule; rules.md §1 rejects empty labels, names
        // over 253 bytes and failed IDN mappings.
        Err(NameError::BadByte(_)) if name.is_ascii() && name.len() <= MAX_NAME_LEN => {
            return hosts_text_rule(ip, name);
        }
        Err(_) => return Item::Error(ErrorReason::BadName),
    };
    if is_block_address(ip) {
        Item::Rule(name_rule(&name, Flags::B_EXACT, RuleSpec::default()))
    } else {
        Item::Rule(Rule {
            rule_type: RuleType::Dns,
            kind: Kind::HostMapping,
            key: name.reversed(),
            flags: Flags::B_EXACT,
            spec: RuleSpec {
                hosts_ip: Some(ip),
                ..RuleSpec::default()
            },
        })
    }
}

/// A hosts-line name that isn't a key name (urlfilter's `NewHostRule` takes any token): AdGuard's
/// host rule matches exactly that text, which the pattern `|token|` does on the text form
/// (case-insensitively, as rules.md §1 lowercases rule names). An IPv6 address there blocks that
/// answer address, as AdGuard Home's answer check matches its text (rules.md §6). A token holding a
/// pattern mask (`*`, `^`, `|`) can't be written so and is a parse error. A mapping to an address
/// that isn't a block address (`192.0.2.1 2001:db8::1`) is the same pattern carrying `hosts_ip`:
/// it answers the text name with its address, and an answer address it matches is blocked, as
/// AdGuard Home's response check does (rules.md §3, §6; review round 2, CC8).
fn hosts_text_rule(ip: IpAddr, token: &str) -> Item {
    // rules.md §1 for rule text: one trailing dot stripped; empty labels rejected.
    let token = token.strip_suffix('.').unwrap_or(token);
    if token.is_empty() || token.split('.').any(str::is_empty) || token.contains(['*', '^', '|']) {
        return Item::Error(ErrorReason::BadName);
    }
    let hosts_ip = (!is_block_address(ip)).then_some(ip);
    let rule_type = if parse_go_ip(token).is_some() {
        RuleType::Ip
    } else {
        RuleType::Dns
    };
    Item::Rule(Rule {
        rule_type,
        kind: Kind::Pattern,
        key: format!("|{token}|"),
        flags: Flags::B_EXACT,
        spec: RuleSpec {
            host_rule: true,
            hosts_ip,
            ..RuleSpec::default()
        },
    })
}

pub(crate) fn name_rule(name: &RuleName, flags: Flags, spec: RuleSpec) -> Rule {
    Rule {
        rule_type: RuleType::Dns,
        kind: Kind::Name,
        key: name.reversed(),
        flags,
        spec,
    }
}

/// The DNS options of a network rule that passed the modifier check.
#[derive(Default)]
struct DnsOptions {
    important: bool,
    badfilter: bool,
    spec: RuleSpec,
    restricted: bool,
}

#[expect(
    clippy::large_enum_variant,
    reason = "transient per line; boxing would allocate for every rule"
)]
enum OptionsOutcome {
    Dns(DnsOptions),
    /// A browser rule; `restricted` when it has a restriction (urlfilter `hasNoRestrictions`:
    /// `$domain`, and the DNS ones; uBlock Origin's `from` and `to` are `$domain` forms).
    Browser {
        restricted: bool,
    },
    Warn(WarnReason),
}

/// Browser options that restrict where a rule applies, for the too-wide check (rules.md §2).
const BROWSER_RESTRICTIONS: &[&str] = &["domain", "from", "to"];

/// Sorts the options of a network rule into DNS modifiers, browser modifiers and unknown ones.
fn read_options(options: &str) -> OptionsOutcome {
    let mut d = DnsOptions::default();
    let mut browser = false;
    let mut browser_restricted = false;
    let mut unknown = false;
    let mut adguard_only = false;
    let mut invalid = None;
    for opt in adguard::split_escaped(options, ',', '\\') {
        let (name, value) = match opt.find('=') {
            Some(i) if i > 0 => (
                opt.get(..i).unwrap_or(""),
                opt.get(i.saturating_add(1)..).unwrap_or(""),
            ),
            _ => (opt.as_str(), ""),
        };
        match name {
            "important" => d.important = true,
            "badfilter" => d.badfilter = true,
            "dnstype" => match DnsTypeCond::parse(value) {
                Some(c) => {
                    d.spec.dnstype = Some(c);
                    d.restricted = true;
                }
                None => invalid = invalid.or(Some(WarnReason::InvalidModifierValue)),
            },
            "dnsrewrite" => match parse_dnsrewrite(value) {
                Some(r) => d.spec.dnsrewrite = Some(r),
                None => invalid = invalid.or(Some(WarnReason::InvalidModifierValue)),
            },
            "client" => match ClientCond::parse(value) {
                Some(c) => {
                    d.spec.client = Some(c);
                    d.restricted = true;
                }
                None => invalid = invalid.or(Some(WarnReason::InvalidModifierValue)),
            },
            "ctag" => match TagCond::parse(value) {
                Some(c) => {
                    d.spec.ctag = Some(c);
                    d.restricted = true;
                }
                None => invalid = invalid.or(Some(WarnReason::InvalidModifierValue)),
            },
            "denyallow" => match parse_denyallow(value) {
                Ok((names, entities)) => {
                    d.spec.denyallow = names;
                    d.spec.denyallow_entities = entities;
                    d.restricted = true;
                }
                Err(DenyallowError::Invalid) => invalid = invalid.or(Some(WarnReason::InvalidModifierValue)),
            },
            n => {
                let bare = n.strip_prefix('~').unwrap_or(n);
                if ADGUARD_ONLY_MODIFIERS.contains(&bare.to_ascii_lowercase().as_str()) {
                    adguard_only = true;
                } else if n.starts_with('~') && URLFILTER_TYPES.contains(&bare) {
                    if !d.spec.not_types.iter().any(|t| t == bare) {
                        d.spec.not_types.push(bare.to_string());
                    }
                } else if BROWSER_MODIFIERS.contains(&bare.to_ascii_lowercase().as_str()) {
                    browser = true;
                    if !n.starts_with('~')
                        && BROWSER_RESTRICTIONS.contains(&bare.to_ascii_lowercase().as_str())
                    {
                        browser_restricted = true;
                    }
                } else {
                    unknown = true;
                }
            }
        }
    }
    if adguard_only {
        return OptionsOutcome::Warn(WarnReason::AdguardOnly);
    }
    if unknown {
        return OptionsOutcome::Warn(WarnReason::UnknownModifier);
    }
    if browser {
        return OptionsOutcome::Browser {
            restricted: browser_restricted || d.restricted,
        };
    }
    if let Some(w) = invalid {
        return OptionsOutcome::Warn(w);
    }
    d.spec.not_types.sort();
    OptionsOutcome::Dns(d)
}

/// Classifies a network rule (rules.md §2).
pub fn classify_network(line: &str, in_conditional: bool) -> Item {
    classify_network_as(line, in_conditional, false)
}

/// AdGuard's DNS reading of a network rule that rules.md §2 sends to browser lists for its URL
/// path (`/ads/banner`, `||example.com/ads/*`): the same rule as a pattern over the name's text
/// form, which matches only names holding a `/` byte. Never used to build bundles; the parity
/// test uses it to measure that deviation (PARITY.md, review round 1 R10). `None` when the line
/// isn't such a path rule.
pub fn path_rule_as_pattern(line: &str) -> Option<Rule> {
    match classify_network(line, false) {
        Item::Rule(r) if r.kind == Kind::Network => match classify_network_as(line, false, true) {
            Item::Rule(p) if p.rule_type != RuleType::Browser => Some(p),
            _ => None,
        },
        _ => None,
    }
}

fn classify_network_as(line: &str, in_conditional: bool, allow_paths: bool) -> Item {
    classify_network_noting(line, in_conditional, allow_paths).0
}

/// [`classify_network_as`], and a notice about the rule it keeps, if any.
fn classify_network_noting(
    line: &str,
    in_conditional: bool,
    allow_paths: bool,
) -> (Item, Option<NoticeReason>) {
    let mut notice = None;
    let item = classify_network_inner(line, in_conditional, allow_paths, &mut notice);
    (item, notice)
}

fn classify_network_inner(
    line: &str,
    in_conditional: bool,
    allow_paths: bool,
    notice: &mut Option<NoticeReason>,
) -> Item {
    let browser_item = || {
        if in_conditional {
            Item::Warning {
                rule_type: Some(RuleType::Browser),
                reason: WarnReason::Conditional,
            }
        } else {
            Item::Rule(browser_rule(Kind::Network, line))
        }
    };
    let Some(text) = adguard::split_network(line) else {
        return Item::Error(ErrorReason::Syntax);
    };
    let opts = match read_options(&text.options) {
        OptionsOutcome::Dns(d) => d,
        // A browser rule is the browser blocker's to apply, however wide its pattern: kept, with
        // a notice when it applies to most requests (the too-wide drop is for DNS rules only).
        OptionsOutcome::Browser { restricted } => {
            let item = browser_item();
            if matches!(item, Item::Rule(_)) && !restricted && adguard::is_pattern_too_wide(&text.pattern) {
                *notice = Some(NoticeReason::BroadBrowser);
            }
            return item;
        }
        OptionsOutcome::Warn(w) => {
            let rt = if w == WarnReason::AdguardOnly {
                Some(RuleType::Browser)
            } else {
                None
            };
            return Item::Warning {
                rule_type: rt,
                reason: w,
            };
        }
    };
    if adguard::is_pattern_too_wide(&text.pattern) && !opts.restricted {
        return Item::Warning {
            rule_type: Some(RuleType::Dns),
            reason: WarnReason::TooWide,
        };
    }
    let pattern = adguard::normalize_pattern(&text.pattern);
    let form = analyse_pattern(&pattern, text.exception, allow_paths);
    let (rule_type, kind, key, flags, spec_pattern, extension) = match form {
        Form::Browser => return browser_item(),
        Form::Keyed {
            name,
            flags,
            extension,
        } => (
            RuleType::Dns,
            Kind::Name,
            name.reversed(),
            flags,
            Some(pattern_key(&pattern)),
            extension,
        ),
        Form::IpLiteral {
            range,
            flags,
            extension,
        } => (
            RuleType::Ip,
            Kind::IpLiteral,
            go_ip_string(range.first_ip()),
            flags,
            Some(pattern_key(&pattern)),
            extension,
        ),
        Form::IpAddress { range } => (
            RuleType::Ip,
            Kind::IpRange,
            range.to_text(),
            Flags::B_EXACT,
            Some(pattern_key(&pattern)),
            true,
        ),
        Form::Pattern { ip } => {
            let rt = if ip { RuleType::Ip } else { RuleType::Dns };
            (
                rt,
                Kind::Pattern,
                pattern_key(&pattern),
                Flags::B_EXACT,
                None,
                false,
            )
        }
        Form::Regex => (
            RuleType::Dns,
            Kind::Regex,
            pattern.clone(),
            Flags::B_EXACT,
            None,
            false,
        ),
    };
    let mut flags = flags;
    if opts.important {
        flags = flags.with_important();
    }
    if text.exception {
        flags = flags.as_exception();
    }
    let mut spec = opts.spec;
    spec.extension = extension;
    // urlfilter: `matchesNothing: pattern == "^"`, on the pattern before `/*` normalisation.
    spec.matches_nothing = text.pattern == "^";
    let rule = if opts.badfilter {
        spec.target = Some(kind);
        spec.pattern = Some(match kind {
            Kind::Pattern | Kind::Regex => key.clone(),
            _ => spec_pattern.unwrap_or_default(),
        });
        Rule {
            rule_type,
            kind: Kind::Badfilter,
            key,
            flags,
            spec,
        }
    } else {
        spec.pattern = spec_pattern;
        Rule {
            rule_type,
            kind,
            key,
            flags,
            spec,
        }
    };
    Item::Rule(rule)
}

/// The key text of a pattern: the pattern as urlfilter keeps it (`/*` → `^`), case kept. Matching
/// is case-insensitive either way, but urlfilter's `negatesBadfilter` compares the text as
/// written (`r.pattern != other.pattern`), so `||Example.org^$badfilter` doesn't remove
/// `||example.org^` (rules.md §3).
fn pattern_key(pattern: &str) -> String {
    pattern.to_string()
}

/// What a (normalised) DNS pattern is.
enum Form {
    /// Folds into a key (rules.md §3) or a protocol/port extension form (rules.md §2).
    Keyed {
        name: RuleName,
        flags: Flags,
        extension: bool,
    },
    /// `||a.b.c.d^` / `|a.b.c.d^` (or an extension form on an IPv4 host).
    IpLiteral {
        range: IpRange,
        flags: Flags,
        extension: bool,
    },
    /// An extension form on a bracketed IPv6 host (`|https://[2001:db8::1]^`): an IP rule for that
    /// address, as an IPv4 host's form is.
    IpAddress { range: IpRange },
    /// A wildcard pattern; `ip` when it is an IP literal kept as a pattern (IPv6, other forms).
    Pattern { ip: bool },
    /// `/regex/`.
    Regex,
    /// Not applicable to DNS: a URL path, or an exception with another scheme or a port.
    Browser,
}

fn analyse_pattern(p: &str, exception: bool, allow_paths: bool) -> Form {
    // `/regex/` rules run on the name's text form (rules.md §2); one that can't match any text is
    // dropped by the compiler (`analysis::pattern_can_match`), as AdGuard never matches it.
    if adguard::is_regex_pattern(p) {
        return Form::Regex;
    }
    // IP literals.
    if let Some(f) = ip_literal_form(p) {
        return f;
    }
    // Protocol/port forms.
    if let Some(u) = parse_url_form(p) {
        let other_scheme = u
            .scheme
            .as_deref()
            .is_some_and(|s| !s.is_empty() && !s.eq_ignore_ascii_case("http"));
        if other_scheme || u.port {
            if exception {
                return Form::Browser;
            }
            if let Some(f) = extension_form(&u) {
                return f;
            }
            return Form::Browser;
        }
    }
    // Forms that fold into keys.
    for (prefix, flags) in [
        ("||", Flags::B_EXACT | Flags::B_SUBS),
        ("|", Flags::B_EXACT),
        ("://", Flags::B_EXACT),
        ("*.", Flags::B_SUBS),
        (".", Flags::B_SUBS),
    ] {
        if let Some(d) = p.strip_prefix(prefix).and_then(|r| r.strip_suffix('^')) {
            if prefix == "|" && d.starts_with('|') {
                continue;
            }
            if let Ok(name) = keyable_name(d) {
                return Form::Keyed {
                    name,
                    flags,
                    extension: false,
                };
            }
        }
    }
    if wildcard_applies(p) || allow_paths {
        Form::Pattern { ip: false }
    } else {
        Form::Browser
    }
}

/// A name from rule text that may become a key: normalised (rules.md §1).
fn keyable_name(d: &str) -> Result<RuleName, crate::name::NameError> {
    if d.contains(['*', '|', '^', '/', ':', '%', '$']) {
        return Err(crate::name::NameError::BadByte(b'*'));
    }
    RuleName::parse(d)
}

struct UrlForm {
    anchor_subs: bool,
    scheme: Option<String>,
    host: String,
    port: bool,
    tail_ok: bool,
}

/// Reads `[||||]scheme://host[:port][tail]` or `||host:port[tail]`. `None` when the pattern has
/// neither a scheme nor a port.
fn parse_url_form(p: &str) -> Option<UrlForm> {
    let (anchor_subs, rest) = if let Some(r) = p.strip_prefix("||") {
        (true, r)
    } else if let Some(r) = p.strip_prefix('|') {
        (false, r)
    } else {
        (false, p)
    };
    let (scheme, rest) = match rest.find("://") {
        Some(i) => {
            let s = rest.get(..i).unwrap_or("");
            let valid = s.is_empty()
                || (s.starts_with(|c: char| c.is_ascii_alphabetic())
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')));
            if !valid || anchor_subs {
                (None, rest)
            } else {
                (
                    Some(s.to_ascii_lowercase()),
                    rest.get(i.saturating_add(3)..).unwrap_or(""),
                )
            }
        }
        None => (None, rest),
    };
    let host_end = if rest.starts_with('[') {
        // A bracketed IPv6 host (RFC 3986) holds the `:` that would end a host.
        rest.find(']').map_or(rest.len(), |i| i.saturating_add(1))
    } else {
        rest.find([':', '/', '^', '|']).unwrap_or(rest.len())
    };
    let host = rest.get(..host_end).unwrap_or("").to_string();
    let mut tail = rest.get(host_end..).unwrap_or("");
    let mut port = false;
    if let Some(after) = tail.strip_prefix(':') {
        let digits_end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
        let digits = after.get(..digits_end).unwrap_or("");
        let next = after.get(digits_end..).unwrap_or("");
        let valid =
            !digits.is_empty() && digits.len() <= 5 && digits.parse::<u32>().is_ok_and(|v| v <= 65535);
        if valid && (next.is_empty() || next.starts_with(['^', '/', '|'])) {
            port = true;
            tail = next;
        }
    }
    if scheme.as_deref().is_none_or(str::is_empty) && !port {
        return None;
    }
    let tail_ok = matches!(tail, "" | "^" | "/" | "|" | "^|");
    Some(UrlForm {
        anchor_subs,
        scheme,
        host,
        port,
        tail_ok,
    })
}

/// The protocol/port extension (rules.md §2): `scheme://d`, `|scheme://d^`, `scheme://d/*` block
/// `d` exactly; `||d:port^` blocks `d` and its subdomains; no path other than `/` or `/*`.
fn extension_form(u: &UrlForm) -> Option<Form> {
    // A host ending in `.` is a fragment in AdGuard's reading, as the host-rule path treats `ads.`
    // (rules.md §3): `https://ads.` doesn't name the host `ads`, so it stays a browser rule.
    if !u.tail_ok || u.host.is_empty() || u.host.contains('*') || u.host.ends_with('.') {
        return None;
    }
    if u.anchor_subs && u.scheme.is_some() {
        return None;
    }
    let flags = if u.anchor_subs {
        Flags::B_EXACT | Flags::B_SUBS
    } else {
        Flags::B_EXACT
    };
    if let Some(IpAddr::V4(v4)) = parse_go_ip(&u.host) {
        return Some(Form::IpLiteral {
            range: IpRange::single(IpAddr::V4(v4)),
            flags,
            extension: true,
        });
    }
    if let Some(inner) = u.host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return match inner.parse::<std::net::Ipv6Addr>() {
            Ok(v6) => Some(Form::IpAddress {
                range: IpRange::single(IpAddr::V6(v6)),
            }),
            Err(_) => None,
        };
    }
    let name = keyable_name(&u.host).ok()?;
    Some(Form::Keyed {
        name,
        flags,
        extension: true,
    })
}

/// `||a.b.c.d^` and `|a.b.c.d^` become IP rules; other IP-literal patterns (IPv6, other anchors)
/// stay patterns of type `ip` (rules.md §1, §2).
fn ip_literal_form(p: &str) -> Option<Form> {
    let (anchor, rest) = if let Some(r) = p.strip_prefix("||") {
        (2u8, r)
    } else if let Some(r) = p.strip_prefix('|') {
        (1, r)
    } else {
        (0, p)
    };
    let (core, caret) = match rest.strip_suffix('^') {
        Some(c) => (c, true),
        None => (rest.strip_suffix('|').unwrap_or(rest), false),
    };
    let ip = parse_go_ip(core)?;
    if core.contains('%') {
        return Some(Form::Pattern { ip: true });
    }
    match ip {
        IpAddr::V4(_) if caret && anchor == 2 => Some(Form::IpLiteral {
            range: IpRange::single(ip),
            flags: Flags::B_EXACT | Flags::B_SUBS,
            extension: false,
        }),
        IpAddr::V4(_) if caret && anchor == 1 => Some(Form::IpLiteral {
            range: IpRange::single(ip),
            flags: Flags::B_EXACT,
            extension: false,
        }),
        _ => Some(Form::Pattern { ip: true }),
    }
}

/// True when a wildcard pattern has no URL path, so AdGuard's DNS engine applies it to names
/// (rules.md §2: network rules with a URL path are `browser`). The path is a `/` after the part
/// that aligns with `http://` in AdGuard's match target: `||`, `http://`, `://`, or the leading
/// slashes of a `/…​.` pattern. Masks and anchors are not literals.
fn wildcard_applies(p: &str) -> bool {
    let body = match adguard::match_target(p) {
        MatchTarget::Host => p.strip_prefix('|').unwrap_or(p),
        MatchTarget::HttpHost => {
            if let Some(r) = p.strip_prefix("||") {
                r
            } else if let Some(r) = p.strip_prefix("http://") {
                r
            } else if let Some(r) = p.strip_prefix("://") {
                r
            } else if p.starts_with("https://") {
                return false;
            } else {
                let r = p.strip_prefix('/').unwrap_or(p);
                r.strip_prefix('/').unwrap_or(r)
            }
        }
    };
    !body.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Item {
        match classify_adblock_line(line, false) {
            Line::Items(mut v) if v.len() == 1 => v.remove(0),
            other => panic!("{line}: {other:?}"),
        }
    }

    fn rule(line: &str) -> Rule {
        match one(line) {
            Item::Rule(r) => r,
            other => panic!("{line}: {other:?}"),
        }
    }

    fn kind(line: &str) -> (RuleType, Kind) {
        let r = rule(line);
        (r.rule_type, r.kind)
    }

    #[test]
    fn skipped() {
        for l in [
            "",
            "   ",
            "! comment",
            "!#if env_mobile",
            "!#endif",
            "!#include x.txt",
            "[Adblock Plus 2.0]",
            "# comment",
            "#",
        ] {
            assert_eq!(classify_adblock_line(l, false), Line::Skipped, "{l}");
        }
    }

    #[test]
    fn dns_forms() {
        let r = rule("||example.org^");
        assert_eq!(
            (r.kind, r.key.as_str(), r.flags),
            (Kind::Name, "org.example", Flags::B_EXACT | Flags::B_SUBS)
        );
        assert_eq!(r.spec.pattern.as_deref(), Some("||example.org^"));
        assert_eq!(rule("|example.org^").flags, Flags::B_EXACT);
        assert_eq!(rule("://example.org^").flags, Flags::B_EXACT);
        assert_eq!(rule("*.example.org^").flags, Flags::B_SUBS);
        assert_eq!(rule(".example.org^").flags, Flags::B_SUBS);
        let r = rule("example.org");
        assert_eq!(
            (r.kind, r.flags, r.spec.pattern.clone()),
            (Kind::Name, Flags::B_EXACT, None)
        );
        let r = rule("@@||example.org^$important");
        assert_eq!(
            r.flags,
            Flags::A_EXACT | Flags::A_SUBS | Flags::IMP_A_EXACT | Flags::IMP_A_SUBS
        );
        assert_eq!(
            rule("|d.example^$important").flags,
            Flags::B_EXACT | Flags::IMP_B_EXACT
        );
        assert_eq!(rule("||Example.ORG/*").key, "org.example");
        assert_eq!(kind("||ads*.example.org^"), (RuleType::Dns, Kind::Pattern));
        assert_eq!(kind("/^ad[0-9]+\\./"), (RuleType::Dns, Kind::Regex));
        assert_eq!(kind("-728x90-"), (RuleType::Dns, Kind::Pattern));
        assert_eq!(kind("example.org^"), (RuleType::Dns, Kind::Pattern));
        assert_eq!(kind("/banner."), (RuleType::Dns, Kind::Pattern));
        assert_eq!(kind("||example.org^$dnstype=A"), (RuleType::Dns, Kind::Name));
        assert_eq!(kind("||example.org^$~image"), (RuleType::Dns, Kind::Name));
        assert_eq!(
            rule("||example.org^$~image").spec.not_types,
            vec!["image".to_string()]
        );
        assert_eq!(kind("http://example.org^"), (RuleType::Dns, Kind::Pattern));
        // rules.md §3: a host rule is a token that passes AdGuard's host-name check, which a
        // trailing dot fails; such a line stays a pattern (`ads.` is a fragment, not the name `ads`).
        for l in ["ads.", "example.com.", "Example.COM."] {
            assert_eq!(kind(l), (RuleType::Dns, Kind::Pattern), "{l}");
        }
        assert_eq!(
            rule("||example.com.^").key,
            "com.example",
            "a key's name is normalised"
        );
        assert_eq!(rule("0.0.0.0 example.com.").key, "com.example");
    }

    #[test]
    fn hosts_lines() {
        let r = rule("0.0.0.0 ads.example.org");
        assert_eq!(
            (r.kind, r.key.as_str(), r.flags),
            (Kind::Name, "org.example.ads", Flags::B_EXACT)
        );
        let r = rule("192.0.2.10 ads.example.org");
        assert_eq!(r.kind, Kind::HostMapping);
        assert_eq!(r.spec.hosts_ip, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(rule("127.0.0.1 x.example").kind, Kind::Name);
        assert_eq!(rule(":: x.example").kind, Kind::Name);
        assert_eq!(rule("::1 x.example").kind, Kind::HostMapping);
        match classify_adblock_line("0.0.0.0 a.example b.example", false) {
            Line::Items(v) => assert_eq!(v.len(), 2),
            other => panic!("{other:?}"),
        }
        // AdGuard cuts one byte before an inline `#`.
        assert_eq!(rule("0.0.0.0 example.com#x").key, "co.example");
        assert_eq!(rule("0.0.0.0 example.com #x").key, "com.example");
        assert_eq!(
            rule("0.0.0.0 jackbootedroom.com  ## phishing").key,
            "com.jackbootedroom"
        );
    }

    #[test]
    fn ip_rules() {
        let r = rule("||1.2.3.4^");
        assert_eq!(
            (r.rule_type, r.kind, r.key.as_str()),
            (RuleType::Ip, Kind::IpLiteral, "1.2.3.4")
        );
        assert_eq!(r.flags, Flags::B_EXACT | Flags::B_SUBS);
        assert_eq!(rule("|1.2.3.4^").flags, Flags::B_EXACT);
        assert_eq!(kind("||2001:db8::1^"), (RuleType::Ip, Kind::Pattern));
        assert_eq!(kind("1.2.3.4"), (RuleType::Ip, Kind::Pattern));
        assert_eq!(kind("||10.0.0^"), (RuleType::Dns, Kind::Name));
    }

    #[test]
    fn extension() {
        for (l, flags) in [
            ("https://example.org", Flags::B_EXACT),
            ("|https://example.org^", Flags::B_EXACT),
            ("https://example.org/*", Flags::B_EXACT),
            ("wss://example.org^", Flags::B_EXACT),
            ("||example.org:8443^", Flags::B_EXACT | Flags::B_SUBS),
            ("||example.org:8443", Flags::B_EXACT | Flags::B_SUBS),
            ("https://example.org/", Flags::B_EXACT),
        ] {
            let r = rule(l);
            assert_eq!(
                (r.kind, r.key.as_str(), r.flags, r.spec.extension),
                (Kind::Name, "org.example", flags, true),
                "{l}"
            );
        }
        assert_eq!(
            kind("https://example.org/path"),
            (RuleType::Browser, Kind::Network)
        );
        // A trailing dot makes the host a fragment, as for host rules (`ads.` is a pattern).
        assert_eq!(kind("https://ads."), (RuleType::Browser, Kind::Network));
        assert_eq!(kind("||ads.:443^"), (RuleType::Browser, Kind::Network));
        assert_eq!(kind("@@https://example.org^"), (RuleType::Browser, Kind::Network));
        assert_eq!(kind("@@||example.org:443^"), (RuleType::Browser, Kind::Network));
        assert_eq!(kind("https://*.example.org^"), (RuleType::Browser, Kind::Network));
        assert_eq!(kind("|http://example.org^"), (RuleType::Browser, Kind::Network));
        // A bracketed IPv6 host: an IP rule for that address, as for an IPv4 host.
        for l in [
            "|https://[2001:db8::1]^",
            "https://[2001:DB8::1]/",
            "||[2001:db8::1]:443^",
        ] {
            let r = rule(l);
            assert_eq!(
                (r.rule_type, r.kind, r.key.as_str(), r.flags, r.spec.extension),
                (RuleType::Ip, Kind::IpRange, "2001:db8::1", Flags::B_EXACT, true),
                "{l}"
            );
        }
        let r = rule("|https://1.2.3.4^");
        assert_eq!(
            (r.kind, r.key.as_str(), r.spec.extension),
            (Kind::IpLiteral, "1.2.3.4", true)
        );
        assert_eq!(
            kind("https://[2001:db8::1]/ads"),
            (RuleType::Browser, Kind::Network)
        );
        assert_eq!(
            kind("https://[fe80::1%eth0]^"),
            (RuleType::Browser, Kind::Network)
        );
        assert_eq!(
            kind("@@|https://[2001:db8::1]^"),
            (RuleType::Browser, Kind::Network)
        );
        assert_eq!(kind("||[2001:db8::1]^"), (RuleType::Dns, Kind::Pattern));
        let b = rule("|https://[2001:db8::1]^$badfilter");
        assert_eq!((b.kind, b.spec.target), (Kind::Badfilter, Some(Kind::IpRange)));
    }

    #[test]
    fn browser_and_dropped() {
        assert_eq!(kind("example.org##.ad"), (RuleType::Browser, Kind::Cosmetic));
        assert_eq!(kind("##.ad"), (RuleType::Browser, Kind::Cosmetic));
        assert_eq!(kind("example.org#@#.ad"), (RuleType::Browser, Kind::Cosmetic));
        assert_eq!(
            kind("example.org#?#div:has(.ad)"),
            (RuleType::Browser, Kind::Procedural)
        );
        assert_eq!(
            kind("example.org##+js(nobab)"),
            (RuleType::Browser, Kind::Scriptlet)
        );
        assert_eq!(
            kind("example.org#$#body { color: red }"),
            (RuleType::Browser, Kind::CssInject)
        );
        assert_eq!(
            kind("||example.org^$third-party"),
            (RuleType::Browser, Kind::Network)
        );
        assert_eq!(kind("||example.org^$image"), (RuleType::Browser, Kind::Network));
        assert_eq!(
            kind("||example.org^$domain=a.com"),
            (RuleType::Browser, Kind::Network)
        );
        assert_eq!(kind("||example.org/ads/*"), (RuleType::Browser, Kind::Network));
        assert_eq!(kind("/ads/banner.gif"), (RuleType::Browser, Kind::Network));
        assert_eq!(kind("&ad_type="), (RuleType::Dns, Kind::Pattern));
        assert_eq!(kind("/[!]/"), (RuleType::Dns, Kind::Regex));
        assert_eq!(kind("||example.org^$popup"), (RuleType::Browser, Kind::Network));
        assert_eq!(
            kind("||example.org^$document"),
            (RuleType::Browser, Kind::Network)
        );
        assert_eq!(
            kind("||example.org^$csp=script-src 'none'"),
            (RuleType::Browser, Kind::Network)
        );
        assert_eq!(
            kind("/^https?:\\/\\/[a-z]+\\.example\\.com\\/ads/"),
            (RuleType::Dns, Kind::Regex)
        );
        let w = |l: &str| match one(l) {
            Item::Warning { reason, .. } => reason,
            other => panic!("{l}: {other:?}"),
        };
        assert_eq!(w("||example.org^$bogus"), WarnReason::UnknownModifier);
        assert_eq!(
            kind("ab"),
            (RuleType::Dns, Kind::Name),
            "a valid host name, as in AdGuard"
        );
        assert_eq!(w("a*"), WarnReason::TooWide);
        assert_eq!(w("*"), WarnReason::TooWide);
        assert_eq!(w("example.org#%#window.x=1"), WarnReason::AdguardOnly);
        assert_eq!(w("example.org$$script[data-x]"), WarnReason::AdguardOnly);
        assert_eq!(w("||example.org^$replace=/a/b/"), WarnReason::AdguardOnly);
        assert_eq!(w("||example.org^$dnstype="), WarnReason::InvalidModifierValue);
        assert!(matches!(one("a*$dnstype=A"), Item::Rule(_)));
        match classify_adblock_line("example.org##.ad", true) {
            Line::Items(v) => assert_eq!(
                v,
                vec![Item::Warning {
                    rule_type: Some(RuleType::Browser),
                    reason: WarnReason::Conditional
                }]
            ),
            other => panic!("{other:?}"),
        }
        assert!(
            matches!(classify_adblock_line("||example.org^", true), Line::Items(v) if matches!(v[0], Item::Rule(_)))
        );
    }

    #[test]
    fn adguard_only_modifiers() {
        // rules.md §2 "(dropped)": AdGuard-only syntax uBlock Origin can't read.
        let w = |l: &str| match one(l) {
            Item::Warning { rule_type, reason } => (rule_type, reason),
            other => panic!("{l}: {other:?}"),
        };
        for l in [
            "||example.org^$cookie=NAME",
            "@@||example.org^$network",
            "@@||example.org^$jsinject,content",
            "@@||example.org^$extension",
            "@@||example.org^$~extension",
            "@@||example.org^$stealth",
            "@@||example.org^$urlblock",
            "||example.org^$app=org.example.app",
            "||example.org^$removeheader=refresh",
            "||example.org/v.m3u8$hls=/ad/",
            "||example.org/a.json$jsonprune=\\$.ads",
            "||example.org/v.xml$xmlprune=/ad",
            "||example.org^$referrerpolicy=origin",
        ] {
            assert_eq!(w(l), (Some(RuleType::Browser), WarnReason::AdguardOnly), "{l}");
        }
        // uBlock Origin's own options stay browser rules; `$_` is its no-op separator.
        for l in [
            "||example.org^$_,script",
            "||example.org^$permissions=browsing-topics=()",
            "||example.org/a$urlskip=?url",
            "||example.org^$header=via:1.1 google",
            "||example.org^$ipaddress=1.2.3.4",
        ] {
            assert_eq!(kind(l), (RuleType::Browser, Kind::Network), "{l}");
        }
    }

    #[test]
    fn broad_browser_rules_are_kept_with_a_notice() {
        // Patterns under 3 characters with no restriction, whatever the modifiers: a browser
        // rule (the line itself, its modifiers and exception as written) and a notice; `$domain`,
        // `from`, `to` and the DNS restrictions count as restrictions (no notice).
        for l in [
            "$image",
            "*$third-party",
            "|$popup",
            "||$script,third-party",
            "$removeparam=utm_source",
            "@@*$script",
            "@@$image,1p",
        ] {
            let Line::Items(items) = classify_adblock_line(l, false) else {
                panic!("{l}")
            };
            assert_eq!(
                items,
                vec![
                    Item::Rule(Rule {
                        rule_type: RuleType::Browser,
                        kind: Kind::Network,
                        key: l.to_string(),
                        flags: Flags::NONE,
                        spec: RuleSpec::default(),
                    }),
                    Item::Notice(NoticeReason::BroadBrowser),
                ],
                "{l}"
            );
        }
        for l in [
            "*$image,domain=example.org",
            "$popup,third-party,domain=~example.org",
            "*$script,from=example.org",
            "*$script,to=example.org",
            "*$image,client=kid",
            "ads$image",
        ] {
            assert_eq!(kind(l), (RuleType::Browser, Kind::Network), "{l}");
            let Line::Items(items) = classify_adblock_line(l, false) else {
                panic!("{l}")
            };
            assert_eq!(items.len(), 1, "no notice: {l}");
        }
        // Inside `!#if`, a browser rule is dropped as conditional whatever its pattern.
        assert_eq!(
            classify_adblock_line("$image", true),
            Line::Items(vec![Item::Warning {
                rule_type: Some(RuleType::Browser),
                reason: WarnReason::Conditional
            }])
        );
        // AdGuard-only and unknown options are still warnings, not kept rules.
        assert!(matches!(
            one("$replace=/a/b/"),
            Item::Warning {
                reason: WarnReason::AdguardOnly,
                ..
            }
        ));
        assert!(matches!(
            one("*$bogusmodifier"),
            Item::Warning {
                reason: WarnReason::UnknownModifier,
                ..
            }
        ));
        // The DNS too-wide drop is unchanged.
        for l in ["*", "||", "|", "a*", "*$dnstype=A,important", "$important"] {
            let got = classify_adblock_line(l, false);
            let Line::Items(items) = &got else { panic!("{l}") };
            if l.contains("dnstype") {
                assert!(matches!(items[..], [Item::Rule(_)]), "restricted: {l}: {got:?}");
            } else {
                assert_eq!(
                    items,
                    &vec![Item::Warning {
                        rule_type: Some(RuleType::Dns),
                        reason: WarnReason::TooWide
                    }],
                    "{l}"
                );
            }
        }
    }

    #[test]
    fn bare_separator_matches_nothing() {
        // urlfilter NewNetworkRule: `matchesNothing: pattern == "^"` (before `/*` normalisation).
        let r = rule("^$dnstype=A");
        assert!(r.spec.matches_nothing);
        let spec = r.pattern_spec().unwrap();
        assert_eq!((spec.regex, spec.matches_all), (None, false));
        assert!(!crate::analysis::pattern_can_match(&r.pattern_spec().unwrap()));
        let r = rule("/*$dnstype=A");
        assert!(
            !r.spec.matches_nothing,
            "/* normalises to ^ and matches everything"
        );
        assert!(r.pattern_spec().unwrap().regex.is_some());
        assert_ne!(rule("^$dnstype=A"), r, "distinct identities");
        assert!(matches!(
            one("^"),
            Item::Warning {
                reason: WarnReason::TooWide,
                ..
            }
        ));
    }

    #[test]
    fn hosts_line_text_names() {
        // urlfilter NewHostRule takes any token; an IPv6 address there blocks that answer address.
        let r = rule("0.0.0.0 2001:db8::1");
        assert_eq!(
            (r.rule_type, r.kind, r.key.as_str(), r.spec.host_rule),
            (RuleType::Ip, Kind::Pattern, "|2001:db8::1|", true)
        );
        let r = rule("0.0.0.0 a!b.example");
        assert_eq!((r.rule_type, r.key.as_str()), (RuleType::Dns, "|a!b.example|"));
        assert!(
            !crate::badfilter::is_target(&r),
            "a host rule is never a $badfilter target"
        );
        // A mapping of such a token keeps it, with its address (CC8): AdGuard answers the text
        // name with it and blocks an answer address it matches.
        let r = rule("192.0.2.1 2001:db8::1");
        assert_eq!(
            (
                r.rule_type,
                r.kind,
                r.key.as_str(),
                r.spec.host_rule,
                r.spec.hosts_ip
            ),
            (
                RuleType::Ip,
                Kind::Pattern,
                "|2001:db8::1|",
                true,
                Some("192.0.2.1".parse().unwrap())
            )
        );
        assert!(r.is_mapping() && r.spec.is_rich());
        let back = Rule::from_stored(
            r.rule_type.as_str(),
            r.kind.as_str(),
            &r.key,
            r.flags.0,
            &serde_json::to_string(&r.spec).unwrap(),
        )
        .unwrap();
        assert_eq!(back, r);
        assert!(matches!(
            one("0.0.0.0 a*b.example"),
            Item::Error(ErrorReason::BadName)
        ));
    }

    #[test]
    fn badfilter() {
        let r = rule("||example.org^$badfilter");
        assert_eq!(
            (r.kind, r.key.as_str(), r.spec.target),
            (Kind::Badfilter, "org.example", Some(Kind::Name))
        );
        assert_eq!(r.spec.pattern.as_deref(), Some("||example.org^"));
        let r = rule("||ads*.example^$badfilter,dnstype=A");
        assert_eq!((r.kind, r.spec.target), (Kind::Badfilter, Some(Kind::Pattern)));
        assert_eq!(
            kind("||example.org^$badfilter,domain=a.com"),
            (RuleType::Browser, Kind::Network)
        );
    }
}
