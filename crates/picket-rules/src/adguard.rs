//! AdGuard's network-rule text model, as urlfilter v0.23 implements it (rules.md §3).
//!
//! Everything here mirrors `urlfilter/rules/network.go` and `rules/regexp.go`: splitting a rule
//! into pattern and options, the pattern → regex conversion, the match target (the name's text, or
//! `"http://"` + text) and the *shortcut*, the literal urlfilter requires in `"http://"` + text
//! before it runs a rule's regex (its `matchShortcut`). The shortcut is part of AdGuard's decision:
//! a rule whose shortcut is absent never matches, even if its regex would, so Picket keeps it as a
//! hard requirement (the "required literal" of `patterns.bin`, bundles.md §4).

use serde::{Deserialize, Serialize};

use crate::goregex::{self, GoRegexError};

/// AdGuard's separator class (`^`).
pub const REGEX_SEPARATOR: &str = "([^ a-zA-Z0-9.%_-]|$)";
/// AdGuard's `||` prefix.
pub const REGEX_START_URL: &str = r"^(http|https|ws|wss)://([a-z0-9-_.]+\.)?";
/// The prefix of the URL urlfilter builds for a hostname request.
pub const URL_PREFIX: &str = "http://";

/// What a pattern's regex runs against (rules.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchTarget {
    /// The name's text form (or an address's text).
    Host,
    /// `"http://"` + that text: patterns starting `||`, `http://`, `https://` or `://`, or starting
    /// with `/` and ending with `.` (at least 4 bytes).
    HttpHost,
}

/// A network rule split as urlfilter's `parseRuleText` does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkText {
    /// `@@` rule.
    pub exception: bool,
    /// The pattern, before the `/*` → `^` normalisation.
    pub pattern: String,
    /// The options text after the last unescaped `$`, with `\$` unescaped; empty when none.
    pub options: String,
    /// True when a `$` delimiter was found.
    pub has_options: bool,
}

/// Splits network rule text into exception marker, pattern and options (urlfilter
/// `parseRuleText`). `None` for `""` and `"@@"`.
pub fn split_network(text: &str) -> Option<NetworkText> {
    if text.is_empty() || text == "@@" {
        return None;
    }
    let (exception, rest) = match text.strip_prefix("@@") {
        Some(r) => (true, r),
        None => (false, text),
    };
    // A regex rule without options: `/…/` with no `replace=` inside.
    if rest.starts_with('/') && rest.ends_with('/') && !rest.contains("replace=") {
        return Some(NetworkText {
            exception,
            pattern: rest.to_string(),
            options: String::new(),
            has_options: false,
        });
    }
    let bytes = rest.as_bytes();
    let mut has_escaped = false;
    let mut idx = None;
    let mut i = bytes.len();
    while i > 0 {
        i = i.saturating_sub(1);
        if bytes.get(i) != Some(&b'$') {
            continue;
        }
        if i > 0 && bytes.get(i.saturating_sub(1)) == Some(&b'\\') {
            has_escaped = true;
            continue;
        }
        idx = Some(i);
        break;
    }
    match idx {
        None => Some(NetworkText {
            exception,
            pattern: rest.to_string(),
            options: String::new(),
            has_options: false,
        }),
        Some(i) => {
            let pattern = rest.get(..i).unwrap_or("").to_string();
            let mut options = rest.get(i.saturating_add(1)..).unwrap_or("").to_string();
            if has_escaped {
                options = options.replace("\\$", "$");
            }
            Some(NetworkText {
                exception,
                pattern,
                options,
                has_options: true,
            })
        }
    }
}

/// Splits `s` at `sep`, where `esc` + `sep` is a literal `sep`, dropping empty parts (urlfilter
/// `splitWithEscapeCharacter`). Other escapes are kept as written.
pub fn split_escaped(s: &str, sep: char, esc: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == esc && chars.peek() == Some(&sep) {
            cur.push(sep);
            chars.next();
        } else if c == sep {
            if !cur.is_empty() {
                parts.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

/// The pattern as urlfilter keeps it: `…/*` becomes `…^`.
pub fn normalize_pattern(pattern: &str) -> String {
    match pattern.strip_suffix("/*") {
        Some(p) => format!("{p}^"),
        None => pattern.to_string(),
    }
}

/// True for a `/…/` regex pattern (urlfilter `isRegexPattern`).
pub fn is_regex_pattern(pattern: &str) -> bool {
    pattern.len() > 1 && pattern.starts_with('/') && pattern.ends_with('/')
}

/// urlfilter's `isPatternTooWide`, applied to the pattern before `/*` normalisation; such a rule is
/// refused unless it has a restriction (`$domain`, `$client`, `$ctag`, `$dnstype`, `$denyallow`).
pub fn is_pattern_too_wide(pattern: &str) -> bool {
    pattern == "||" || pattern == "|" || pattern == "*" || pattern.is_empty() || pattern.len() < 3
}

/// The match target of a (normalised) pattern (urlfilter `shouldMatchHostname`).
pub fn match_target(pattern: &str) -> MatchTarget {
    if pattern.starts_with("||")
        || pattern.starts_with("http://")
        || pattern.starts_with("https://")
        || pattern.starts_with("://")
        || (pattern.len() >= 4 && pattern.starts_with('/') && pattern.ends_with('.'))
    {
        MatchTarget::HttpHost
    } else {
        MatchTarget::Host
    }
}

/// True when urlfilter treats the pattern's regex as matching everything (`.*`).
pub fn matches_all(pattern: &str) -> bool {
    pattern == "||" || pattern == "|" || pattern == "*" || pattern.is_empty()
}

/// urlfilter `patternToRegexp` for a normalised pattern, in Go syntax, without the `(?i)` prefix.
/// Linear in the pattern length.
pub fn pattern_to_go_regex(pattern: &str) -> String {
    if matches_all(pattern) {
        return ".*".to_string();
    }
    if is_regex_pattern(pattern) {
        return pattern
            .get(1..pattern.len().saturating_sub(1))
            .unwrap_or("")
            .to_string();
    }
    // 1. Escape special characters (a byte-wise replacer in Go).
    let mut s = String::with_capacity(pattern.len().saturating_mul(2));
    for c in pattern.chars() {
        if matches!(
            c,
            '.' | '+' | '?' | '$' | '{' | '}' | '(' | ')' | '[' | ']' | '/' | '\\'
        ) {
            s.push('\\');
        }
        s.push(c);
    }
    // 2. Escape pipes between the prefix (`|` or `||`) and the last byte.
    let s = escape_pipes(&s);
    // 3. Masks: `*` → `.*`, `^` → the separator class.
    let mut m = String::with_capacity(s.len().saturating_mul(2));
    for c in s.chars() {
        match c {
            '*' => m.push_str(".*"),
            '^' => m.push_str(REGEX_SEPARATOR),
            _ => m.push(c),
        }
    }
    // 4. Prefix and 5. suffix.
    let mut r = if let Some(rest) = m.strip_prefix("||") {
        format!("{REGEX_START_URL}{rest}")
    } else if let Some(rest) = m.strip_prefix('|') {
        format!("^{rest}")
    } else {
        m
    };
    if r.ends_with('|') {
        r.pop();
        r.push('$');
    }
    r
}

fn escape_pipes(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() <= 1 {
        return s.to_string();
    }
    let prefix_len = if s.starts_with("||") { 2 } else { 1 };
    let last = b.len().saturating_sub(1);
    if last < prefix_len {
        return s.to_string();
    }
    // Byte-wise, as Go slices it; `|` is ASCII, so UTF-8 sequences stay intact.
    let mut out: Vec<u8> = Vec::with_capacity(b.len().saturating_add(8));
    out.extend_from_slice(b.get(..prefix_len).unwrap_or(&[]));
    for &c in b.get(prefix_len..last).unwrap_or(&[]) {
        if c == b'|' {
            out.push(b'\\');
        }
        out.push(c);
    }
    out.extend_from_slice(b.get(last..).unwrap_or(&[]));
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// The full Go regex urlfilter compiles for a DNS rule: `(?i)` + the converted pattern
/// (`$match-case` makes a rule `browser`, so DNS rules are always case-insensitive).
pub fn pattern_go_regex_full(pattern: &str) -> String {
    format!("(?i){}", pattern_to_go_regex(pattern))
}

/// The Rust regex equivalent to [`pattern_go_regex_full`], or the reason Go would refuse it (the
/// rule then matches nothing, as in AdGuard).
pub fn pattern_rust_regex(pattern: &str) -> Result<String, GoRegexError> {
    goregex::translate(&pattern_go_regex_full(pattern))
}

/// urlfilter's shortcut for a normalised pattern: the literal that must occur in `"http://"` +
/// text (lowercased) for the rule to match, or `None` when it has none (shorter than 2 bytes).
pub fn shortcut(pattern: &str) -> Option<String> {
    let s = if is_regex_pattern(pattern) {
        find_regexp_shortcut(pattern)
    } else {
        find_shortcut(pattern)
    };
    if s.len() > 1 { Some(s.to_lowercase()) } else { None }
}

/// The longest substring without `*`, `^` or `|`; the first one on a tie (urlfilter
/// `findShortcut`).
fn find_shortcut(pattern: &str) -> String {
    let mut best = "";
    for part in pattern.split(['*', '^', '|']) {
        if part.len() > best.len() {
            best = part;
        }
    }
    best.to_string()
}

/// urlfilter `findRegexpShortcut`, quirks included: the bracket strippers are greedy, the
/// "escaped characters" pattern only matches the literal text `[a-zA-Z]`, and a `?` anywhere
/// means no shortcut.
fn find_regexp_shortcut(pattern: &str) -> String {
    let inner = pattern.get(1..pattern.len().saturating_sub(1)).unwrap_or("");
    if inner.contains('?') {
        return String::new();
    }
    let mut s = format!("...{inner}");
    s = strip_brackets(&s, '{', '}');
    s = strip_brackets(&s, '(', ')');
    s = strip_brackets(&s, '[', ']');
    s = strip_escaped_letters_literal(&s);
    let mut best = "";
    for part in s.split([
        '\\', '^', '$', '*', '+', '?', '.', '(', ')', '|', '[', ']', '{', '}',
    ]) {
        if part.len() > best.len() {
            best = part;
        }
    }
    best.to_string()
}

/// Go `regexp.MustCompile("([^\\])\\" + open + ".*[^\\]\\" + close).ReplaceAllString(s, "$1...")`:
/// leftmost match, greedy, so at most one replacement: from the first `open` preceded by a
/// non-backslash to the last `close` preceded by a non-backslash at least two characters later.
fn strip_brackets(s: &str, open: char, close: char) -> String {
    let chars: Vec<char> = s.chars().collect();
    // Last valid close: chars[j] == close && chars[j-1] != '\\'.
    let mut last_close = None;
    for j in (1..chars.len()).rev() {
        if chars.get(j) == Some(&close) && chars.get(j.saturating_sub(1)) != Some(&'\\') {
            last_close = Some(j);
            break;
        }
    }
    let Some(lc) = last_close else {
        return s.to_string();
    };
    for p in 0..chars.len() {
        let (Some(&pc), Some(&oc)) = (chars.get(p), chars.get(p.saturating_add(1))) else {
            break;
        };
        if pc != '\\' && oc == open && lc >= p.saturating_add(3) {
            let mut out: String = chars.get(..=p).unwrap_or(&[]).iter().collect();
            out.push_str("...");
            out.extend(chars.get(lc.saturating_add(1)..).unwrap_or(&[]).iter());
            return out;
        }
    }
    s.to_string()
}

/// Go `regexp.MustCompile("([^\\])\\[a-zA-Z]").ReplaceAllString(s, "$1...")`: in Go syntax `\[`
/// is a literal `[`, so this replaces the literal text `[a-zA-Z]` after a non-backslash.
fn strip_escaped_letters_literal(s: &str) -> String {
    const LIT: &[char] = &['[', 'a', '-', 'z', 'A', '-', 'Z', ']'];
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        let rest = chars.get(i.saturating_add(1)..).unwrap_or(&[]);
        if c != '\\' && rest.starts_with(LIT) {
            out.push(c);
            out.push_str("...");
            i = i.saturating_add(1).saturating_add(LIT.len());
            continue;
        }
        out.push(c);
        i = i.saturating_add(1);
    }
    out
}

/// True when `shortcut` is absent or occurs in `"http://"` + `text` (urlfilter `matchShortcut`).
pub fn shortcut_present(shortcut: Option<&str>, text: &str) -> bool {
    match shortcut {
        None => true,
        Some(sc) => {
            if text.contains(sc) {
                return true;
            }
            // Occurrences overlapping the `http://` prefix.
            let mut url = String::with_capacity(URL_PREFIX.len().saturating_add(sc.len()));
            url.push_str(URL_PREFIX);
            url.push_str(text.get(..sc.len().min(text.len())).unwrap_or(text));
            url.contains(sc)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split() {
        let t = split_network("@@||example.org^$important,dnstype=A").unwrap();
        assert!(t.exception);
        assert_eq!(t.pattern, "||example.org^");
        assert_eq!(t.options, "important,dnstype=A");
        let t = split_network("/ads$/").unwrap();
        assert_eq!(t.pattern, "/ads$/");
        assert!(!t.has_options);
        let t = split_network("/ads$/$important").unwrap();
        assert_eq!(t.pattern, "/ads$/");
        assert_eq!(t.options, "important");
        let t = split_network("||a.com^$dnsrewrite=NOERROR;TXT;a\\$b").unwrap();
        assert_eq!(t.options, "dnsrewrite=NOERROR;TXT;a$b");
        assert!(split_network("@@").is_none());
        assert_eq!(split_escaped("a,,b\\,c", ',', '\\'), vec!["a", "b,c"]);
    }

    #[test]
    fn regexes() {
        assert_eq!(
            pattern_to_go_regex("||example.org^"),
            format!("{REGEX_START_URL}example\\.org{REGEX_SEPARATOR}")
        );
        assert_eq!(pattern_to_go_regex("|example.org|"), "^example\\.org$");
        assert_eq!(pattern_to_go_regex("a|b"), "a\\|b");
        assert_eq!(pattern_to_go_regex("ads*.com"), "ads.*\\.com");
        assert_eq!(pattern_to_go_regex("/a.b/"), "a.b");
        assert_eq!(pattern_to_go_regex("||"), ".*");
        assert_eq!(pattern_to_go_regex("|"), ".*");
        assert_eq!(pattern_to_go_regex("x|"), "x$");
        assert_eq!(pattern_to_go_regex("a||"), "a\\|$");
        assert_eq!(pattern_to_go_regex("|||"), format!("{REGEX_START_URL}$"));
        assert_eq!(pattern_to_go_regex("*ad*"), ".*ad.*");
    }

    #[test]
    fn targets() {
        assert_eq!(match_target("||a.com^"), MatchTarget::HttpHost);
        assert_eq!(match_target("://a.com^"), MatchTarget::HttpHost);
        assert_eq!(match_target("/banner."), MatchTarget::HttpHost);
        assert_eq!(match_target("/ba."), MatchTarget::HttpHost);
        assert_eq!(match_target("/b."), MatchTarget::Host);
        assert_eq!(match_target("|a.com^"), MatchTarget::Host);
        assert_eq!(match_target("/regex/"), MatchTarget::Host);
        assert_eq!(
            match_target("HTTP://x"),
            MatchTarget::Host,
            "the prefix test is case-sensitive"
        );
        assert_eq!(match_target("ads."), MatchTarget::Host);
    }

    #[test]
    fn shortcuts() {
        assert_eq!(shortcut("||example.org^").as_deref(), Some("example.org"));
        assert_eq!(shortcut("||ads*.example.org^").as_deref(), Some(".example.org"));
        assert_eq!(shortcut("a^").as_deref(), None);
        assert_eq!(shortcut("/ads|tracker/").as_deref(), Some("tracker"));
        assert_eq!(shortcut(r"/\bads\b/").as_deref(), Some("bads"));
        assert_eq!(shortcut("/ads?x/").as_deref(), None);
        assert_eq!(shortcut("/(ads|track)er/").as_deref(), Some("er"));
        assert_eq!(shortcut("/ad\\.server/").as_deref(), Some("server"));
        assert_eq!(shortcut("/[a-z]{3}banner/").as_deref(), Some("banner"));
        assert_eq!(shortcut("/x[a-zA-Z]yz/").as_deref(), None.or(Some("yz")));
        assert_eq!(shortcut("||example.org^*ads").as_deref(), Some("example.org"));
        assert_eq!(shortcut("http://ads.").as_deref(), Some("http://ads."));
        assert_eq!(shortcut("/a{2}b{3}/"), None, "a one-byte shortcut is none");
        assert_eq!(shortcut("/\\101/").as_deref(), Some("101"));
        assert!(shortcut_present(Some("://ex"), "example.org"));
        assert!(shortcut_present(Some("p://"), "x"));
        assert!(!shortcut_present(Some("bads"), "ads.example"));
    }

    #[test]
    fn regexp_shortcut_bracket_stripping() {
        assert_eq!(strip_brackets("...a{1}b{2}c", '{', '}'), "...a...c");
        assert_eq!(strip_brackets("...a\\{1\\}b", '{', '}'), "...a\\{1\\}b");
        assert_eq!(strip_escaped_letters_literal("...x[a-zA-Z]yz"), "...x...yz");
        assert_eq!(strip_escaped_letters_literal("\\[a-zA-Z]"), "\\[a-zA-Z]");
    }
}
