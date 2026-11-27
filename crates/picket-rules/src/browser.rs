//! Browser rules (rules.md §2 `browser`, bundles.md §8): parsing network and cosmetic rules into
//! their parts, exact cancellation, the allow-bundle conversion table and the helpers profile
//! lists need (`||host` anchors, `$domain=`/`from=` names, `$redirect-rule` → `$redirect`,
//! `$popup`/`$all`).

use crate::adguard::split_escaped;
use crate::name::RuleName;
use crate::rule::Kind;

/// Cosmetic markers, longest first (urlfilter's list plus uBlock Origin's, which reuse `##`).
const MARKERS: &[(&str, CosmeticMarker)] = &[
    (
        "#@$?#",
        CosmeticMarker {
            family: Family::CssInject,
            exception: true,
        },
    ),
    (
        "#@?#",
        CosmeticMarker {
            family: Family::Procedural,
            exception: true,
        },
    ),
    (
        "#@$#",
        CosmeticMarker {
            family: Family::CssInject,
            exception: true,
        },
    ),
    (
        "#$?#",
        CosmeticMarker {
            family: Family::CssInject,
            exception: false,
        },
    ),
    (
        "#@%#",
        CosmeticMarker {
            family: Family::AdguardJs,
            exception: true,
        },
    ),
    (
        "#@#",
        CosmeticMarker {
            family: Family::Hide,
            exception: true,
        },
    ),
    (
        "#?#",
        CosmeticMarker {
            family: Family::Procedural,
            exception: false,
        },
    ),
    (
        "#$#",
        CosmeticMarker {
            family: Family::CssInject,
            exception: false,
        },
    ),
    (
        "#%#",
        CosmeticMarker {
            family: Family::AdguardJs,
            exception: false,
        },
    ),
    (
        "$@$",
        CosmeticMarker {
            family: Family::AdguardHtml,
            exception: true,
        },
    ),
    (
        "##",
        CosmeticMarker {
            family: Family::Hide,
            exception: false,
        },
    ),
    (
        "$$",
        CosmeticMarker {
            family: Family::AdguardHtml,
            exception: false,
        },
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Hide,
    Procedural,
    CssInject,
    AdguardJs,
    AdguardHtml,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CosmeticMarker {
    family: Family,
    exception: bool,
}

/// Where a cosmetic marker is, as urlfilter finds it (`findCosmeticRuleMarker`): only the first
/// `#` and the first `$` are tried, `#` first, and one preceded by a space doesn't count (hosts
/// lines with `## comment`). Returns the byte index and the marker text.
pub fn find_cosmetic_marker(text: &str) -> Option<(usize, &'static str)> {
    for first in ['#', '$'] {
        let Some(idx) = text.find(first) else { continue };
        if idx > 0 && text.as_bytes().get(idx.saturating_sub(1)) == Some(&b' ') {
            return None;
        }
        let rest = text.get(idx..).unwrap_or("");
        if let Some((m, _)) = MARKERS.iter().find(|(m, _)| rest.starts_with(m)) {
            return Some((idx, m));
        }
    }
    None
}

/// A cosmetic, procedural, scriptlet, HTML-filter or CSS-injection rule split into its parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosmeticRule {
    /// The domains before the marker.
    pub domains: Vec<CosmeticDomain>,
    /// The kind (one of the browser cosmetic kinds).
    pub kind: Kind,
    /// An exception marker (`#@#`, `#@?#`, `#@$#`, …).
    pub exception: bool,
    /// The selector; for a scriptlet, `+js(…)` with its arguments; for an HTML filter, the `^…`.
    pub body: String,
    /// AdGuard's extended CSS injection (`#$?#`, `#@$?#`), kept so the rule writes back as read.
    pub extended: bool,
}

/// One domain of a cosmetic rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CosmeticDomain {
    /// The domain text as written (lowercased), without `~`.
    pub name: String,
    /// `~domain`.
    pub negated: bool,
    /// An entity domain (`example.*`).
    pub entity: bool,
}

/// What [`parse_cosmetic`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CosmeticParse {
    /// A rule browsers read.
    Rule(CosmeticRule),
    /// AdGuard-only syntax uBlock Origin can't read (`#%#`, `#@%#`, `$$`, `$@$`): dropped and
    /// counted (rules.md §2).
    AdguardOnly,
    /// Unreadable (empty body).
    Invalid,
}

/// Parses a cosmetic rule. `None` when the text has no cosmetic marker.
pub fn parse_cosmetic(text: &str) -> Option<CosmeticParse> {
    let (idx, marker) = find_cosmetic_marker(text)?;
    let m = MARKERS.iter().find(|(t, _)| *t == marker).map(|(_, m)| *m)?;
    let body = text
        .get(idx.saturating_add(marker.len())..)
        .unwrap_or("")
        .trim()
        .to_string();
    if matches!(m.family, Family::AdguardJs | Family::AdguardHtml) {
        return Some(CosmeticParse::AdguardOnly);
    }
    // AdGuard's cosmetic modifiers (`[$domain=a.com,path=/x]##sel`): uBlock Origin can't read them
    // (rules.md §2 "(dropped)").
    if text.get(..idx).unwrap_or("").trim_start().starts_with("[$") {
        return Some(CosmeticParse::AdguardOnly);
    }
    if body.is_empty() {
        return Some(CosmeticParse::Invalid);
    }
    let kind = match m.family {
        Family::Hide if body.starts_with("+js(") => Kind::Scriptlet,
        Family::Hide if body.starts_with('^') => Kind::HtmlFilter,
        Family::Hide => Kind::Cosmetic,
        Family::Procedural => Kind::Procedural,
        _ => Kind::CssInject,
    };
    let domains = parse_cosmetic_domains(text.get(..idx).unwrap_or(""));
    Some(CosmeticParse::Rule(CosmeticRule {
        domains,
        kind,
        exception: m.exception,
        body,
        extended: kind == Kind::CssInject && marker.contains('?'),
    }))
}

fn parse_cosmetic_domains(s: &str) -> Vec<CosmeticDomain> {
    let mut out: Vec<CosmeticDomain> = split_cosmetic_domains(s)
        .into_iter()
        .map(|d| {
            let (negated, d) = match d.strip_prefix('~') {
                Some(r) => (true, r),
                None => (false, d),
            };
            // uBlock Origin's regex domains (`/[a-z]+\.example/##.ad`) keep their case.
            let name = if is_regex_domain(d) {
                d.to_string()
            } else {
                d.to_ascii_lowercase()
            };
            CosmeticDomain {
                entity: name.ends_with(".*"),
                name,
                negated,
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A `/regex/` domain entry.
fn is_regex_domain(d: &str) -> bool {
    d.len() > 1 && d.starts_with('/') && d.ends_with('/')
}

/// Splits a cosmetic rule's domain list at commas, keeping a `/regex/` entry whole even when its
/// regex holds a comma (`/a{1,3}\.example/`): such an entry ends at a `/` followed by a comma or
/// the end.
fn split_cosmetic_domains(s: &str) -> Vec<&str> {
    split_domain_list(s, b',')
}

/// Splits a domain list at `sep` (`,` for cosmetic rules, `|` for `$domain=` and the other list
/// options), keeping a `/regex/` entry whole even when its regex holds the separator: such an
/// entry ends at an unescaped `/` followed by `sep` or the end (bundles.md §8, CC7).
fn split_domain_list(s: &str, sep: u8) -> Vec<&str> {
    let b = s.as_bytes();
    let next_comma = |from: usize| -> usize {
        b.get(from..)
            .and_then(|r| r.iter().position(|&c| c == sep))
            .map_or(b.len(), |p| from.saturating_add(p))
    };
    let mut out = Vec::new();
    let mut i = 0usize;
    while i <= b.len() {
        let mut j = i;
        while b.get(j) == Some(&b' ') {
            j = j.saturating_add(1);
        }
        if b.get(j) == Some(&b'~') {
            j = j.saturating_add(1);
        }
        let end = if b.get(j) == Some(&b'/') {
            let mut k = j.saturating_add(1);
            let mut found = None;
            while let Some(&c) = b.get(k) {
                if c == b'\\' {
                    k = k.saturating_add(2);
                    continue;
                }
                if c == b'/' {
                    let mut m = k.saturating_add(1);
                    while b.get(m) == Some(&b' ') {
                        m = m.saturating_add(1);
                    }
                    if m >= b.len() || b.get(m) == Some(&sep) {
                        found = Some(m.min(b.len()));
                        break;
                    }
                }
                k = k.saturating_add(1);
            }
            found.unwrap_or_else(|| next_comma(j))
        } else {
            next_comma(j)
        };
        let d = s.get(i..end).unwrap_or("").trim();
        if !d.is_empty() {
            out.push(d);
        }
        i = end.saturating_add(1);
    }
    out
}

impl CosmeticRule {
    /// True when the rule names no domain it applies to (only negated ones, or none).
    pub fn is_generic(&self) -> bool {
        !self.domains.iter().any(|d| !d.negated)
    }

    /// The marker text for this kind and exception-ness.
    pub fn marker(&self) -> &'static str {
        match (self.kind, self.exception) {
            (Kind::Procedural, false) => "#?#",
            (Kind::Procedural, true) => "#@?#",
            (Kind::CssInject, false) if self.extended => "#$?#",
            (Kind::CssInject, true) if self.extended => "#@$?#",
            (Kind::CssInject, false) => "#$#",
            (Kind::CssInject, true) => "#@$#",
            (_, false) => "##",
            (_, true) => "#@#",
        }
    }

    /// Writes the rule back as text.
    pub fn to_text(&self) -> String {
        let domains: Vec<String> = self
            .domains
            .iter()
            .map(|d| {
                if d.negated {
                    format!("~{}", d.name)
                } else {
                    d.name.clone()
                }
            })
            .collect();
        format!("{}{}{}", domains.join(","), self.marker(), self.body)
    }

    /// The rule's domains as normalised names (rules.md §1) when every one is a plain name it
    /// applies to: no `~d`, no entity (`example.*`), at least one. `None` otherwise: a generic or
    /// negated rule, or one with an entity, which pruning keeps (bundles.md §8).
    pub fn plain_domains(&self) -> Option<Vec<String>> {
        if self.domains.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(self.domains.len());
        for d in &self.domains {
            if d.negated || d.entity {
                return None;
            }
            let name = String::from(RuleName::parse(&d.name).ok()?);
            if !out.contains(&name) {
                out.push(name);
            }
        }
        Some(out)
    }

    /// What exact cancellation compares (bundles.md §8): the selector, or for a scriptlet its
    /// name (without uBlock Origin's optional `.js`) and arguments, so `+js(x,1)` and
    /// `+js( x, 1 )` are the same scriptlet.
    fn comparable_body(&self) -> String {
        match self.scriptlet() {
            Some((name, args)) => {
                let name = name.strip_suffix(".js").unwrap_or(&name);
                let mut s = format!("+js\u{0}{name}");
                for a in args {
                    s.push('\u{0}');
                    s.push_str(&a);
                }
                s
            }
            None => self.body.clone(),
        }
    }

    /// A scriptlet's name and arguments (`+js(name, a\, b, c)` → `name`, [`a, b`, `c`]).
    pub fn scriptlet(&self) -> Option<(String, Vec<String>)> {
        if self.kind != Kind::Scriptlet {
            return None;
        }
        let inner = self.body.strip_prefix("+js(")?.strip_suffix(')')?;
        let mut parts = split_escaped(inner, ',', '\\')
            .into_iter()
            .map(|p| p.trim().to_string());
        let name = parts.next()?;
        Some((name, parts.collect()))
    }

    /// True for `##+js(…)`, CSS injection and HTML filters (`##^…`, which rewrite the response
    /// before the page sees it, as `:remove()` does to the page), or a selector with an action
    /// operator (`:style()`, `:remove()`, `:remove-attr()`, `:remove-class()`): rules that do more
    /// than hide (feeds.md §8 `browser_changes`).
    pub fn changes_page(&self) -> bool {
        matches!(self.kind, Kind::Scriptlet | Kind::CssInject | Kind::HtmlFilter)
            || [":style(", ":remove(", ":remove-attr(", ":remove-class("]
                .iter()
                .any(|op| self.body.contains(op))
    }
}

/// A browser network rule split into pattern and options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRule {
    /// `@@` rule.
    pub exception: bool,
    /// The pattern as written.
    pub pattern: String,
    /// The options in written order.
    pub options: Vec<BrowserOption>,
}

/// One `$` option of a browser network rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BrowserOption {
    /// Name without `~`, lowercased.
    pub name: String,
    /// `~name`.
    pub negated: bool,
    /// The value after `=`, if any.
    pub value: Option<String>,
}

/// Option aliases (uBlock Origin, ABP, AdGuard): alias → (name, negates).
const OPTION_ALIASES: &[(&str, &str, bool)] = &[
    ("xhr", "xmlhttprequest", false),
    ("css", "stylesheet", false),
    ("frame", "subdocument", false),
    ("doc", "document", false),
    ("from", "domain", false),
    ("3p", "third-party", false),
    ("1p", "third-party", true),
    ("first-party", "third-party", true),
    ("strict1p", "strict-first-party", false),
    ("strict3p", "strict-third-party", false),
    ("ghide", "generichide", false),
    ("ehide", "elemhide", false),
    ("shide", "specifichide", false),
    ("queryprune", "removeparam", false),
    ("object-subrequest", "object", false),
    ("beacon", "ping", false),
];

/// Options whose value is a `|`-separated set.
const LIST_OPTIONS: &[&str] = &["domain", "to", "denyallow", "method", "ctag", "client"];

impl BrowserOption {
    /// The option with its alias resolved and a list value sorted (domain entries lowercased,
    /// `/regex/` entries kept).
    fn canonical(&self) -> BrowserOption {
        let (name, negated) = match OPTION_ALIASES.iter().find(|(a, _, _)| *a == self.name) {
            Some((_, n, flip)) => ((*n).to_string(), self.negated != *flip),
            None => (self.name.clone(), self.negated),
        };
        let value = self.value.as_ref().map(|v| {
            if !LIST_OPTIONS.contains(&name.as_str()) {
                return v.clone();
            }
            let mut parts: Vec<String> = split_domain_list(v, b'|')
                .into_iter()
                .map(|p| {
                    let bare = p.strip_prefix('~').unwrap_or(p);
                    if name == "client" || is_regex_domain(bare) {
                        p.to_string()
                    } else {
                        p.to_ascii_lowercase()
                    }
                })
                .collect();
            parts.sort();
            parts.dedup();
            parts.join("|")
        });
        BrowserOption { name, negated, value }
    }

    fn to_text(&self) -> String {
        let mut s = String::new();
        if self.negated {
            s.push('~');
        }
        s.push_str(&self.name);
        if let Some(v) = &self.value {
            s.push('=');
            s.push_str(v);
        }
        s
    }
}

/// Options that change a request or response instead of blocking it (feeds.md §8).
const MODIFYING: &[&str] = &[
    "redirect",
    "redirect-rule",
    "csp",
    "removeparam",
    "queryprune",
    "rewrite",
    "permissions",
    "removeheader",
    "cookie",
    "replace",
    "urltransform",
    "uritransform",
    "urlskip",
    "hls",
    "jsonprune",
    "xmlprune",
    "referrerpolicy",
    "empty",
    "mp4",
];

/// Parses a network rule (`@@`, pattern, `$` options split at unescaped commas).
pub fn parse_network(text: &str) -> NetworkRule {
    let (exception, rest) = match text.strip_prefix("@@") {
        Some(r) => (true, r),
        None => (false, text),
    };
    let split = crate::adguard::split_network(if exception { text } else { rest });
    let (pattern, options) = match split {
        Some(t) => (t.pattern, t.options),
        None => (rest.to_string(), String::new()),
    };
    let options = split_escaped(&options, ',', '\\')
        .into_iter()
        .map(|o| {
            let (name, value) = match o.find('=') {
                Some(i) if i > 0 => (
                    o.get(..i).unwrap_or("").to_string(),
                    Some(o.get(i.saturating_add(1)..).unwrap_or("").to_string()),
                ),
                _ => (o.clone(), None),
            };
            let (negated, name) = match name.strip_prefix('~') {
                Some(n) => (true, n.to_string()),
                None => (false, name),
            };
            BrowserOption {
                name: name.to_ascii_lowercase(),
                negated,
                value,
            }
        })
        .collect();
    NetworkRule {
        exception,
        pattern,
        options,
    }
}

impl NetworkRule {
    /// The option named `name` (not negated).
    pub fn option(&self, name: &str) -> Option<&BrowserOption> {
        self.options.iter().find(|o| o.name == name && !o.negated)
    }

    /// True when it carries `$badfilter`.
    pub fn is_badfilter(&self) -> bool {
        self.option("badfilter").is_some()
    }

    /// True when an option changes the request or response (feeds.md §8 `browser_changes`).
    pub fn changes_request(&self) -> bool {
        self.options.iter().any(|o| MODIFYING.contains(&o.name.as_str()))
    }

    /// True for `$popup`, `$popunder` or `$all` rules, which pruning never leaves out
    /// (bundles.md §8: DNS can't close a popup).
    pub fn is_popup_or_all(&self) -> bool {
        self.options
            .iter()
            .any(|o| !o.negated && matches!(o.name.as_str(), "popup" | "popunder" | "all"))
    }

    /// The host of a `||host` anchor followed by `^`, `/` or `:` (bundles.md §8), lowercased.
    pub fn host_anchor(&self) -> Option<String> {
        host_anchor(&self.pattern)
    }

    /// The names of `$domain=` and `from=` (with `~` for negated ones), lowercased; a `/regex/`
    /// entry stays whole, as written.
    pub fn domain_names(&self) -> Vec<(String, bool)> {
        let mut out = Vec::new();
        for o in &self.options {
            if o.negated || !(o.name == "domain" || o.name == "from") {
                continue;
            }
            for d in split_domain_list(o.value.as_deref().unwrap_or(""), b'|') {
                let (neg, d) = match d.strip_prefix('~') {
                    Some(r) => (true, r),
                    None => (false, d),
                };
                // A `/regex/` entry is kept whole and keeps its case.
                out.push((
                    if is_regex_domain(d) {
                        d.to_string()
                    } else {
                        d.to_ascii_lowercase()
                    },
                    neg,
                ));
            }
        }
        out
    }

    /// The `$domain=` / `from=` names, normalised (rules.md §1), when the rule lists only plain
    /// names it applies to (bundles.md §8 "Network rules for DNS-blocked pages"). `None` without
    /// the option, or with a negated (`~d`), entity (`example.*`), regex (`/…/`) or invalid entry.
    pub fn page_domains(&self) -> Option<Vec<String>> {
        let entries = self.domain_names();
        if entries.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(entries.len());
        for (name, negated) in entries {
            if negated || name.ends_with(".*") || name.starts_with('/') {
                return None;
            }
            let name = String::from(RuleName::parse(&name).ok()?);
            if !out.contains(&name) {
                out.push(name);
            }
        }
        Some(out)
    }

    /// The options other than those in `skip`, normalised and sorted: the comparison key of exact
    /// cancellation (bundles.md §8 "the same options, ignoring option order"). Aliases map to one
    /// name (`xhr` → `xmlhttprequest`, `3p` → `third-party`, `1p`/`first-party` →
    /// `~third-party`, `from` → `domain`, …) and list values (`domain=b.com|a.com`) are sorted.
    fn option_set(&self, skip: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = self
            .options
            .iter()
            .map(BrowserOption::canonical)
            .filter(|o| !skip.contains(&o.name.as_str()))
            .map(|o| o.to_text())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Writes the rule back as text.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        if self.exception {
            s.push_str("@@");
        }
        s.push_str(&self.pattern);
        if !self.options.is_empty() {
            s.push('$');
            let opts: Vec<String> = self
                .options
                .iter()
                .map(|o| o.to_text().replace(',', "\\,").replace('$', "\\$"))
                .collect();
            s.push_str(&opts.join(","));
        }
        s
    }
}

/// `||host` followed by `^`, `/` or `:` → `host`, normalised as rule names are (rules.md §1: ASCII
/// lowercase, IDN → A-labels, a trailing dot stripped) so it compares with DNS keys; `None` for
/// other patterns or a host that isn't a valid name (wildcards included).
pub fn host_anchor(pattern: &str) -> Option<String> {
    let rest = pattern.strip_prefix("||")?;
    let end = rest.find(['^', '/', ':'])?;
    let host = rest.get(..end)?;
    if host.is_empty() || host.contains(['*', '|']) {
        return None;
    }
    RuleName::parse(host).ok().map(String::from)
}

/// A browser rule of any kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserRule {
    Network(NetworkRule),
    Cosmetic(CosmeticRule),
}

/// Parses a stored browser rule's text.
pub fn parse_browser(text: &str) -> BrowserRule {
    match parse_cosmetic(text) {
        Some(CosmeticParse::Rule(c)) => BrowserRule::Cosmetic(c),
        _ => BrowserRule::Network(parse_network(text)),
    }
}

impl BrowserRule {
    /// True for exceptions and `$badfilter` rules.
    pub fn is_exception_or_badfilter(&self) -> bool {
        match self {
            BrowserRule::Network(n) => n.exception || n.is_badfilter(),
            BrowserRule::Cosmetic(c) => c.exception,
        }
    }

    /// True for `browser_changes` (feeds.md §8): scriptlets and injections, action operators,
    /// request- or response-modifying options, exceptions and `$badfilter`.
    pub fn is_browser_change(&self) -> bool {
        match self {
            BrowserRule::Network(n) => n.exception || n.is_badfilter() || n.changes_request(),
            BrowserRule::Cosmetic(c) => c.exception || c.changes_page(),
        }
    }

    /// True when it carries `$client` or `$ctag` (feeds.md §8 `client_rules`).
    pub fn has_client_modifier(&self) -> bool {
        match self {
            BrowserRule::Network(n) => n.options.iter().any(|o| o.name == "client" || o.name == "ctag"),
            BrowserRule::Cosmetic(_) => false,
        }
    }

    /// Writes the rule back as text.
    pub fn to_text(&self) -> String {
        match self {
            BrowserRule::Network(n) => n.to_text(),
            BrowserRule::Cosmetic(c) => c.to_text(),
        }
    }
}

/// True when `canceller` (an exception or `$badfilter` rule) cancels `rule` **exactly**
/// (bundles.md §8 "Exact cancellation").
pub fn exactly_cancels(canceller: &BrowserRule, rule: &BrowserRule) -> bool {
    match (canceller, rule) {
        (BrowserRule::Network(c), BrowserRule::Network(r)) => {
            if r.is_badfilter() {
                return false;
            }
            if c.is_badfilter() {
                return c.exception == r.exception
                    && c.pattern == r.pattern
                    && c.option_set(&["badfilter"]) == r.option_set(&[]);
            }
            c.exception
                && !r.exception
                && c.pattern == r.pattern
                && c.option_set(&["important"]) == r.option_set(&["important"])
        }
        (BrowserRule::Cosmetic(c), BrowserRule::Cosmetic(r)) => {
            if !c.exception || r.exception || c.kind != r.kind || c.comparable_body() != r.comparable_body() {
                return false;
            }
            // "Generic" here means no domains at all: `~a.com#@#.ad` lists a domain (negated) and
            // doesn't cancel `a.com##.ad` (it applies everywhere except there).
            c.domains.is_empty() || c.domains == r.domains
        }
        _ => false,
    }
}

/// How an allow bundle writes one of its `browser` rules (bundles.md §8 "Allow bundles").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowConversion {
    /// Written as this exception.
    Written(String),
    /// Already an exception or `$badfilter`: written as it stands.
    Unchanged(String),
    /// `$redirect`/`$redirect-rule`: dropped and counted.
    Dropped,
}

/// Converts an allow-bundle `browser` rule into the exception a browser list writes.
pub fn allow_conversion(rule: &BrowserRule) -> AllowConversion {
    match rule {
        BrowserRule::Network(n) => {
            if n.exception || n.is_badfilter() {
                return AllowConversion::Unchanged(n.to_text());
            }
            if n.options
                .iter()
                .any(|o| o.name == "redirect" || o.name == "redirect-rule")
            {
                return AllowConversion::Dropped;
            }
            let mut e = n.clone();
            e.exception = true;
            e.options.retain(|o| o.name != "important");
            AllowConversion::Written(e.to_text())
        }
        BrowserRule::Cosmetic(c) => {
            if c.exception {
                return AllowConversion::Unchanged(c.to_text());
            }
            let mut e = c.clone();
            e.exception = true;
            AllowConversion::Written(e.to_text())
        }
    }
}

/// `$redirect-rule=X` → `$redirect=X` (bundles.md §8 pruned lists): `None` when the rule has no
/// `$redirect-rule`.
pub fn redirect_rule_to_redirect(rule: &NetworkRule) -> Option<String> {
    if !rule.options.iter().any(|o| o.name == "redirect-rule") {
        return None;
    }
    let mut r = rule.clone();
    for o in &mut r.options {
        if o.name == "redirect-rule" {
            o.name = "redirect".to_string();
        }
    }
    Some(r.to_text())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers() {
        assert_eq!(find_cosmetic_marker("example.org##.ad"), Some((11, "##")));
        assert_eq!(find_cosmetic_marker("0.0.0.0 a.com  ## comment"), None);
        assert_eq!(find_cosmetic_marker("a.com#@?#div"), Some((5, "#@?#")));
        assert_eq!(find_cosmetic_marker("||a.com^$domain=b.com"), None);
        assert_eq!(find_cosmetic_marker("a.com$$script"), Some((5, "$$")));
        assert!(matches!(
            parse_cosmetic("a.com#%#window.x=1"),
            Some(CosmeticParse::AdguardOnly)
        ));
        assert!(matches!(parse_cosmetic("a.com##"), Some(CosmeticParse::Invalid)));
        let Some(CosmeticParse::Rule(r)) = parse_cosmetic("A.com,~b.com##+js(set-constant, x, 1)") else {
            panic!()
        };
        assert_eq!(r.kind, Kind::Scriptlet);
        assert_eq!(r.domains.len(), 2);
        assert!(r.changes_page());
        assert_eq!(
            r.scriptlet(),
            Some(("set-constant".to_string(), vec!["x".to_string(), "1".to_string()]))
        );
        let Some(CosmeticParse::Rule(r)) = parse_cosmetic("a.com##^script:has-text(x)") else {
            panic!()
        };
        assert_eq!(r.kind, Kind::HtmlFilter);
        let Some(CosmeticParse::Rule(r)) = parse_cosmetic("example.*##.ad") else {
            panic!()
        };
        assert!(r.domains[0].entity);
    }

    #[test]
    fn conversion_table() {
        let conv = |s: &str| allow_conversion(&parse_browser(s));
        assert_eq!(
            conv("||x.com/p$script,important"),
            AllowConversion::Written("@@||x.com/p$script".into())
        );
        assert_eq!(
            conv("d.com##.sel"),
            AllowConversion::Written("d.com#@#.sel".into())
        );
        assert_eq!(conv("##.sel"), AllowConversion::Written("#@#.sel".into()));
        assert_eq!(
            conv("d.com#?#div:has(.x)"),
            AllowConversion::Written("d.com#@?#div:has(.x)".into())
        );
        assert_eq!(
            conv("d.com##+js(nobab)"),
            AllowConversion::Written("d.com#@#+js(nobab)".into())
        );
        assert_eq!(
            conv("d.com##^script"),
            AllowConversion::Written("d.com#@#^script".into())
        );
        assert_eq!(conv("||x.com^$redirect=noop.js"), AllowConversion::Dropped);
        assert_eq!(conv("||x.com^$redirect-rule=noop.js"), AllowConversion::Dropped);
        assert_eq!(
            conv("@@||x.com^$script"),
            AllowConversion::Unchanged("@@||x.com^$script".into())
        );
        assert_eq!(
            conv("d.com#@#.sel"),
            AllowConversion::Unchanged("d.com#@#.sel".into())
        );
        assert_eq!(
            conv("||x.com^$badfilter"),
            AllowConversion::Unchanged("||x.com^$badfilter".into())
        );
    }

    #[test]
    fn cancellation() {
        let c = |a: &str, b: &str| exactly_cancels(&parse_browser(a), &parse_browser(b));
        assert!(c(
            "@@||x.com^$script,third-party",
            "||x.com^$third-party,script,important"
        ));
        assert!(!c("@@||x.com^$script", "||x.com^$image"));
        assert!(!c("@@||x.com^", "||*.x.com^"));
        assert!(c("||x.com^$script,badfilter", "||x.com^$script"));
        assert!(!c("||x.com^$script,badfilter", "||x.com^$script,important"));
        assert!(c("#@#.ad", "a.com,b.com##.ad"));
        assert!(c("b.com,a.com#@#.ad", "a.com,b.com##.ad"));
        assert!(!c("a.com#@#.ad", "a.com,b.com##.ad"));
        assert!(!c("a.com#@#.ad", "a.com#?#.ad"));
        assert!(c("a.com#@#+js(x, 1)", "a.com##+js(x, 1)"));
    }

    #[test]
    fn negated_only_cosmetic_exception_is_not_generic() {
        // bundles.md §8: "the exception is generic or lists exactly the rule's domains";
        // `~example.com#@#.ad` applies everywhere except example.com.
        let c = |a: &str, b: &str| exactly_cancels(&parse_browser(a), &parse_browser(b));
        assert!(!c("~example.com#@#.ad", "example.com##.ad"));
        assert!(!c("~example.com#@#.ad", "other.com##.ad"));
        assert!(c("~example.com#@#.ad", "~example.com##.ad"));
        assert!(c("#@#.ad", "~example.com##.ad"));
    }

    #[test]
    fn options_compare_normalised() {
        // bundles.md §8 "the same options, ignoring option order": aliases and value order.
        let c = |a: &str, b: &str| exactly_cancels(&parse_browser(a), &parse_browser(b));
        assert!(c("@@||x.com^$xmlhttprequest", "||x.com^$xhr,important"));
        assert!(c("@@||x.com^$3p", "||x.com^$third-party"));
        assert!(c("@@||x.com^$1p", "||x.com^$~third-party"));
        assert!(c("@@||x.com^$first-party", "||x.com^$1p"));
        assert!(c(
            "@@||x.com^$css,frame,doc",
            "||x.com^$document,subdocument,stylesheet"
        ));
        assert!(c("@@||x.com^$domain=b.com|A.com", "||x.com^$from=a.com|b.com"));
        assert!(c("||x.com^$xhr,badfilter", "||x.com^$xmlhttprequest"));
        assert!(!c("@@||x.com^$3p", "||x.com^$1p"));
        assert!(!c("@@||x.com^$domain=a.com", "||x.com^$domain=a.com|b.com"));
        assert!(!c("@@||x.com^$domain=/A+/", "||x.com^$domain=/a+/"));
        // CC7: a regex entry's internal `|` doesn't split it, and its case counts.
        assert!(!c(
            "@@||x.com^$domain=/Foo|bar/",
            "||x.com^$domain=/foo|bar/,important"
        ));
        assert!(!c("@@||x.com^$domain=/a|b/", "||x.com^$domain=/b|a/"));
        assert!(c(
            "@@||x.com^$domain=/Foo|bar/|B.com",
            "||x.com^$domain=b.com|/Foo|bar/"
        ));
        assert!(c("@@||x.com^$domain=~/A|b/", "||x.com^$domain=~/A|b/"));
        assert_eq!(
            parse_network("||x.com^$domain=/Foo|bar/|A.com").domain_names(),
            vec![("/Foo|bar/".to_string(), false), ("a.com".to_string(), false)]
        );
    }

    #[test]
    fn writes_escapes_back() {
        // The `$` inside an option value is escaped as written, and regex cosmetic domains keep
        // their case and their commas.
        let t = "||x.com^$removeparam=/^ab\\$/";
        assert_eq!(parse_browser(t).to_text(), t);
        let t = "@@||x.com^$removeparam=/^a\\$|b\\,c/,domain=a.com";
        assert_eq!(parse_browser(t).to_text(), t);
        let BrowserRule::Cosmetic(r) = parse_browser("/[A-Z]{1,3}\\.example/,B.com##.ad") else {
            panic!()
        };
        let names: Vec<&str> = r.domains.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["/[A-Z]{1,3}\\.example/", "b.com"]);
        assert_eq!(r.to_text(), "/[A-Z]{1,3}\\.example/,b.com##.ad");
    }

    #[test]
    fn adguard_cosmetic_modifiers_are_dropped() {
        // rules.md §2 "(dropped)": AdGuard-only browser syntax uBlock Origin can't read.
        assert!(matches!(
            parse_cosmetic("[$domain=example.com]##.ad"),
            Some(CosmeticParse::AdguardOnly)
        ));
        assert!(matches!(
            parse_cosmetic("[$path=/page]example.com##.ad"),
            Some(CosmeticParse::AdguardOnly)
        ));
        assert!(matches!(
            parse_cosmetic("example.com##.ad"),
            Some(CosmeticParse::Rule(_))
        ));
    }

    #[test]
    fn scriptlets_cancel_by_name_and_arguments() {
        // bundles.md §8: "for a scriptlet, the same scriptlet and arguments".
        let c = |a: &str, b: &str| exactly_cancels(&parse_browser(a), &parse_browser(b));
        assert!(c("a.com#@#+js(nowebrtc)", "a.com##+js( nowebrtc )"));
        assert!(c(
            "a.example#@#+js(set-constant, x, 1)",
            "a.example##+js(set-constant,x,1)"
        ));
        assert!(c(
            "a.com#@#+js(set-constant.js, x, 1)",
            "a.com##+js(set-constant, x, 1)"
        ));
        assert!(!c(
            "a.example#@#+js(set-constant, x, 2)",
            "a.example##+js(set-constant,x,1)"
        ));
        assert!(!c("a.com#@#+js(x, a\\, b)", "a.com##+js(x, a, b)"));
        assert!(c("a.example#@#^script", "a.example##^script"));
        assert!(c("a.example#@?#.x:has(a)", "a.example#?#.x:has(a)"));
    }

    #[test]
    fn html_filters_are_browser_changes() {
        // feeds.md §8: an HTML filter rewrites the response before the page sees it, as
        // `:remove()` does to the page; its exception is a change either way.
        assert!(parse_browser("a.com##^script:has-text(adblock)").is_browser_change());
        assert!(parse_browser("a.com##^.ad").is_browser_change());
        assert!(!parse_browser("a.com##.ad").is_browser_change());
    }

    #[test]
    fn extended_css_injection_round_trips() {
        let r = parse_browser("a.com#$?#.ad:has(> a) { display: none !important; }");
        assert_eq!(r.to_text(), "a.com#$?#.ad:has(> a) { display: none !important; }");
        assert_eq!(
            allow_conversion(&r),
            AllowConversion::Written("a.com#@$?#.ad:has(> a) { display: none !important; }".into())
        );
        assert_eq!(
            parse_browser("a.com#@$?#.x { y: z }").to_text(),
            "a.com#@$?#.x { y: z }"
        );
    }

    #[test]
    fn pruning_names_are_normalised() {
        // bundles.md §8 compares rule names with DNS keys, which hold A-labels (rules.md §1).
        assert_eq!(host_anchor("||Пример.РФ^"), Some("xn--e1afmkfd.xn--p1ai".into()));
        assert_eq!(
            host_anchor("||ADS.Example.com./x"),
            Some("ads.example.com".into())
        );
        assert_eq!(host_anchor("||a b.com^"), None);
        let n = parse_network("/ads/*$script,domain=A.example|b.example");
        assert_eq!(
            n.page_domains(),
            Some(vec!["a.example".into(), "b.example".into()])
        );
        for r in [
            "/ads/*$script,domain=a.example|~b.a.example",
            "/ads/*$script,domain=example.*",
            "/ads/*$script,domain=/^a\\.example$/",
            "/ads/*$script",
        ] {
            assert_eq!(parse_network(r).page_domains(), None, "{r}");
        }
        assert_eq!(
            parse_network("||x.com^$script,from=a.com|b.org").page_domains(),
            Some(vec!["a.com".into(), "b.org".into()])
        );
        let cos = |s: &str| match parse_browser(s) {
            BrowserRule::Cosmetic(c) => c,
            BrowserRule::Network(_) => panic!("{s}"),
        };
        assert_eq!(
            cos("B.example,a.example##.ad").plain_domains(),
            Some(vec!["a.example".into(), "b.example".into()])
        );
        for r in [
            "##.ad",
            "~a.example##.ad",
            "a.example,~b.a.example##.ad",
            "example.*##.ad",
        ] {
            assert_eq!(cos(r).plain_domains(), None, "{r}");
        }
    }

    #[test]
    fn helpers() {
        let n = parse_network("||ads.example.com^$domain=a.com|~b.com,redirect-rule=noop.js");
        assert_eq!(n.host_anchor().as_deref(), Some("ads.example.com"));
        assert_eq!(
            n.domain_names(),
            vec![("a.com".into(), false), ("b.com".into(), true)]
        );
        assert_eq!(
            redirect_rule_to_redirect(&n).unwrap(),
            "||ads.example.com^$domain=a.com|~b.com,redirect=noop.js"
        );
        assert!(parse_network("||x.com^$popup").is_popup_or_all());
        assert!(parse_network("||x.com^$all").is_popup_or_all());
        assert_eq!(host_anchor("||x.com/path"), Some("x.com".into()));
        assert_eq!(host_anchor("||x.com:8080"), Some("x.com".into()));
        assert_eq!(host_anchor("||x.com"), None);
        assert_eq!(host_anchor("||*.x.com^"), None);
        assert!(parse_browser("@@||x.com^").is_browser_change());
        assert!(parse_browser("||x.com^$csp=script-src 'none'").is_browser_change());
        assert!(!parse_browser("||x.com^$script").is_browser_change());
        assert!(parse_browser("||x.com^$client=kid,script").has_client_modifier());
    }
}
