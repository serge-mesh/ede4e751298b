//! MISP warninglist `list.json` (feeds.md §4, §7), streamed: a small pull reader walks the JSON
//! byte by byte and hands each `list` value to the mapper as it goes, so memory stays bounded per
//! entry (one string of at most `max_line_len` bytes), never per file.
//!
//! Two passes over a fresh reader each (from `open`): the first validates the whole document and
//! finds the list's `type` (MISP writes it after `list`, keys being sorted), the second emits. A
//! malformed document emits nothing and is one parse error ([`parse_misp`]).
//!
//! Types: `hostname` → name and subdomains (`||value^`); `string` → exact name; `substring` →
//! `*value*`; `regex` → `/value/`; `cidr` → IP range. A value that doesn't fit its type is a
//! parse error; a missing or unknown type makes the document unreadable (every value an error,
//! error ratio 1).

use std::io::{self, BufRead};

use crate::classify::{ErrorReason, Item, name_rule};
use crate::flags::Flags;
use crate::formats::{ParseConfig, ParseStats, ip_indicator};
use crate::ip::IpRange;
use crate::name::RuleName;
use crate::rule::{Entry, Kind, Rule, RuleSpec, RuleType};

/// The warninglist types Picket reads (feeds.md §7).
pub const KNOWN_TYPES: &[&str] = &["hostname", "string", "substring", "regex", "cidr"];

/// Deepest nesting skipped inside values we don't read.
const MAX_DEPTH: u32 = 64;

/// Parses a MISP warninglist; see the module docs.
///
/// The first pass validates the whole document as JSON (RFC 8259: structure, literals, numbers,
/// strings, nothing after the top-level object) and finds `type`; only the second pass emits. A
/// file that isn't valid JSON can't be read at all (README §2 "Untrusted input"): it counts as one
/// parse error on one line and emits nothing, so its error ratio is 1 and the run is rejected
/// (feeds.md §5). Read failures of the underlying reader are returned as `Err`.
pub fn parse_misp<R, O, F>(mut open: O, cfg: &ParseConfig, mut sink: F) -> io::Result<ParseStats>
where
    R: BufRead,
    O: FnMut() -> io::Result<R>,
    F: FnMut(Entry),
{
    let mut stats = ParseStats::default();
    let list_type = match walk(open()?, cfg, None, &mut stats, &mut sink) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            let mut bad_file = ParseStats {
                lines: 1,
                rule_lines: 1,
                ..ParseStats::default()
            };
            bad_file.error(0, ErrorReason::Syntax, &e.to_string());
            return Ok(bad_file);
        }
        Err(e) => return Err(e),
    };
    let list_type = match list_type {
        Some(t) if KNOWN_TYPES.contains(&t.as_str()) => t,
        other => {
            // Valid JSON whose `type` is missing or unknown can't be read (feeds.md §4, §7):
            // every value is an error, and at least one, so the error ratio is 1 and the run
            // fails the parse gate (feeds.md §5) instead of emitting nothing that a replace-mode
            // apply would take for an empty list.
            let what = match &other {
                None => "list.json without a type".to_string(),
                Some(t) => format!("list.json with an unknown type {:?}", t.get(..64).unwrap_or(t)),
            };
            stats.error(0, ErrorReason::Syntax, &what);
            stats.errors = stats.errors.max(stats.rule_lines);
            return Ok(stats);
        }
    };
    let mut stats2 = ParseStats::default();
    walk(open()?, cfg, Some(list_type), &mut stats2, &mut sink)?;
    Ok(stats2)
}

/// One pass over the document. With `emit_as: None` it only validates and counts the list's values
/// (into `stats.lines`/`rule_lines`, so a typeless list's ratio is right) and returns the `type`;
/// with `Some(type)` it maps and emits every value.
fn walk<R: BufRead, F: FnMut(Entry)>(
    r: R,
    cfg: &ParseConfig,
    emit_as: Option<String>,
    stats: &mut ParseStats,
    sink: &mut F,
) -> io::Result<Option<String>> {
    let mut j = JsonReader {
        r,
        max: cfg.max_line_len,
    };
    let mut list_type: Option<String> = None;
    j.ws()?;
    if j.next()? != Some(b'{') {
        return Err(bad("not a JSON object"));
    }
    j.ws()?;
    let mut first = true;
    loop {
        if first && j.peek()? == Some(b'}') {
            j.next()?;
            break;
        }
        first = false;
        if j.peek()? != Some(b'"') {
            return Err(bad("expected a key"));
        }
        let key = j.string()?;
        j.ws()?;
        if j.next()? != Some(b':') {
            return Err(bad("expected ':'"));
        }
        j.ws()?;
        match key.as_deref() {
            Some("type") if j.peek()? == Some(b'"') => {
                list_type = j.string()?;
                if list_type.is_none() {
                    list_type = Some(String::new());
                }
            }
            Some("list") if j.peek()? == Some(b'[') => {
                j.next()?;
                j.ws()?;
                let mut index: u64 = 0;
                if j.peek()? == Some(b']') {
                    j.next()?;
                } else {
                    loop {
                        index = index.saturating_add(1);
                        stats.lines = stats.lines.saturating_add(1);
                        stats.rule_lines = stats.rule_lines.saturating_add(1);
                        if j.peek()? == Some(b'"') {
                            let value = j.string()?;
                            if let Some(t) = &emit_as {
                                match value {
                                    Some(v) => map_value(t, &v, index, stats, sink),
                                    None => stats.error(index, ErrorReason::TooLong, ""),
                                }
                            }
                        } else {
                            j.skip_value()?;
                            if emit_as.is_some() {
                                stats.error(index, ErrorReason::Syntax, "not a string");
                            }
                        }
                        j.ws()?;
                        match j.next()? {
                            Some(b',') => j.ws()?,
                            Some(b']') => break,
                            _ => return Err(bad("expected ',' or ']'")),
                        }
                    }
                }
            }
            _ => j.skip_value()?,
        }
        j.ws()?;
        match j.next()? {
            Some(b',') => j.ws()?,
            Some(b'}') => break,
            _ => return Err(bad("expected ',' or '}'")),
        }
    }
    j.ws()?;
    if j.peek()?.is_some() {
        return Err(bad("data after the top-level object"));
    }
    Ok(emit_as.or(list_type))
}

fn map_value<F: FnMut(Entry)>(
    list_type: &str,
    value: &str,
    index: u64,
    stats: &mut ParseStats,
    sink: &mut F,
) {
    let v = value.trim();
    let item = if v.is_empty() {
        Item::Error(ErrorReason::Syntax)
    } else {
        map_item(list_type, v)
    };
    match item {
        Item::Rule(rule) => {
            stats.entries.add(Some(rule.rule_type));
            sink(Entry {
                rule,
                raw: value.to_string(),
                line_no: index,
                first_seen: None,
            });
        }
        Item::Error(e) => stats.error(index, e, value),
        Item::Warning { rule_type, .. } => stats.warnings.add(rule_type),
        // MISP values map to DNS and IP rules only.
        Item::Notice(_) => {}
    }
}

/// Maps one MISP value by the list's type (feeds.md §7).
pub fn map_item(list_type: &str, v: &str) -> Item {
    match list_type {
        "hostname" => {
            let n = v.strip_prefix("*.").or_else(|| v.strip_prefix('.')).unwrap_or(v);
            match RuleName::parse(n) {
                Ok(name) => Item::Rule(name_rule(
                    &name,
                    Flags::B_EXACT | Flags::B_SUBS,
                    RuleSpec::default(),
                )),
                Err(_) => Item::Error(ErrorReason::BadName),
            }
        }
        "string" => match RuleName::parse(v) {
            Ok(name) => Item::Rule(name_rule(&name, Flags::B_EXACT, RuleSpec::default())),
            Err(_) => Item::Error(ErrorReason::BadName),
        },
        "substring" => {
            let rule = if v.contains(['*', '^', '|']) || v.starts_with('/') {
                Rule {
                    rule_type: RuleType::Dns,
                    kind: Kind::Regex,
                    key: format!("/{}/", quote_meta(v)),
                    flags: Flags::B_EXACT,
                    spec: RuleSpec::default(),
                }
            } else {
                Rule {
                    rule_type: RuleType::Dns,
                    kind: Kind::Pattern,
                    key: format!("*{}*", v.to_ascii_lowercase()),
                    flags: Flags::B_EXACT,
                    spec: RuleSpec::default(),
                }
            };
            Item::Rule(rule)
        }
        "regex" => Item::Rule(Rule {
            rule_type: RuleType::Dns,
            kind: Kind::Regex,
            key: format!("/{v}/"),
            flags: Flags::B_EXACT,
            spec: RuleSpec::default(),
        }),
        "cidr" => match IpRange::parse(v) {
            Some(r) => Item::Rule(ip_indicator(r)),
            None => Item::Error(ErrorReason::BadAddress),
        },
        _ => Item::Error(ErrorReason::Syntax),
    }
}

/// Go `regexp.QuoteMeta`.
fn quote_meta(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_mul(2));
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("list.json: {msg}"))
}

/// A streaming UTF-8 check (Unicode §3.9, table 3-7: no overlong forms, surrogates or code
/// points past U+10FFFF), byte by byte, so strings that aren't kept are validated too.
#[derive(Default)]
struct Utf8 {
    /// Continuation bytes still due.
    due: u8,
    /// The range the next continuation byte must fall in.
    lo: u8,
    hi: u8,
}

impl Utf8 {
    /// False when `b` can't come next. A quote or backslash while a sequence is open fails too,
    /// so a string never ends inside one.
    fn feed(&mut self, b: u8) -> bool {
        if self.due > 0 {
            if !(self.lo..=self.hi).contains(&b) {
                return false;
            }
            self.due = self.due.saturating_sub(1);
            (self.lo, self.hi) = (0x80, 0xBF);
            return true;
        }
        let (due, lo, hi) = match b {
            0x00..=0x7F => return true,
            0xC2..=0xDF => (1, 0x80, 0xBF),
            0xE0 => (2, 0xA0, 0xBF),
            0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
            0xED => (2, 0x80, 0x9F),
            0xF0 => (3, 0x90, 0xBF),
            0xF1..=0xF3 => (3, 0x80, 0xBF),
            0xF4 => (3, 0x80, 0x8F),
            _ => return false,
        };
        (self.due, self.lo, self.hi) = (due, lo, hi);
        true
    }
}

/// A minimal pull reader over JSON bytes.
struct JsonReader<R> {
    r: R,
    max: usize,
}

impl<R: BufRead> JsonReader<R> {
    fn peek(&mut self) -> io::Result<Option<u8>> {
        loop {
            match self.r.fill_buf() {
                Ok(b) => return Ok(b.first().copied()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn next(&mut self) -> io::Result<Option<u8>> {
        let b = self.peek()?;
        if b.is_some() {
            self.r.consume(1);
        }
        Ok(b)
    }

    fn ws(&mut self) -> io::Result<()> {
        while let Some(b) = self.peek()? {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.r.consume(1);
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Reads a string at the cursor (which is on its `"`). `Ok(None)` when it is longer than the
    /// limit; the whole string is consumed and validated either way (escapes, control bytes and
    /// UTF-8, as serde_json does), also when nothing is kept (`max` 0, skipped values).
    fn string(&mut self) -> io::Result<Option<String>> {
        if self.next()? != Some(b'"') {
            return Err(bad("expected a string"));
        }
        let mut utf8 = Utf8::default();
        let mut out: Vec<u8> = Vec::new();
        let mut over = false;
        let mut push = |out: &mut Vec<u8>, bytes: &[u8], max: usize| {
            if out.len().saturating_add(bytes.len()) > max {
                over = true;
                out.clear();
            } else if !over {
                out.extend_from_slice(bytes);
            }
        };
        loop {
            let b = self.next()?.ok_or_else(|| bad("unterminated string"))?;
            if !utf8.feed(b) {
                return Err(bad("invalid UTF-8"));
            }
            match b {
                b'"' => break,
                b'\\' => {
                    let e = self.next()?.ok_or_else(|| bad("unterminated escape"))?;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                if self.next()? != Some(b'\\') || self.next()? != Some(b'u') {
                                    return Err(bad("lone surrogate"));
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(bad("bad surrogate pair"));
                                }
                                let cp = 0x10000u32
                                    .saturating_add((hi.saturating_sub(0xD800)) << 10)
                                    .saturating_add(lo.saturating_sub(0xDC00));
                                char::from_u32(cp).ok_or_else(|| bad("bad code point"))?
                            } else {
                                char::from_u32(hi).ok_or_else(|| bad("bad code point"))?
                            }
                        }
                        _ => return Err(bad("bad escape")),
                    };
                    let mut tmp = [0u8; 4];
                    push(&mut out, c.encode_utf8(&mut tmp).as_bytes(), self.max);
                }
                0x00..=0x1f => return Err(bad("control character in string")),
                _ => push(&mut out, &[b], self.max),
            }
        }
        if over {
            return Ok(None);
        }
        String::from_utf8(out).map(Some).map_err(|_| bad("invalid UTF-8"))
    }

    fn hex4(&mut self) -> io::Result<u32> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let b = self.next()?.ok_or_else(|| bad("short \\u escape"))?;
            let d = (b as char).to_digit(16).ok_or_else(|| bad("bad \\u escape"))?;
            v = v.saturating_mul(16).saturating_add(d);
        }
        Ok(v)
    }

    /// Skips one JSON value of any kind, validating it (RFC 8259), iteratively, with a depth limit.
    fn skip_value(&mut self) -> io::Result<()> {
        // Open containers: `{` or `[`.
        let mut stack: Vec<u8> = Vec::new();
        loop {
            // A value.
            self.ws()?;
            match self.peek()?.ok_or_else(|| bad("unexpected end"))? {
                open @ (b'{' | b'[') => {
                    self.next()?;
                    self.ws()?;
                    let close = if open == b'{' { b'}' } else { b']' };
                    if self.peek()? == Some(close) {
                        self.next()?;
                    } else {
                        if stack.len() >= MAX_DEPTH as usize {
                            return Err(bad("nesting too deep"));
                        }
                        stack.push(open);
                        if open == b'{' {
                            self.member_key()?;
                        }
                        continue;
                    }
                }
                b'"' => {
                    let saved = self.max;
                    self.max = 0;
                    let r = self.string();
                    self.max = saved;
                    r?;
                }
                b't' => self.literal(b"true")?,
                b'f' => self.literal(b"false")?,
                b'n' => self.literal(b"null")?,
                b'-' | b'0'..=b'9' => self.number()?,
                _ => return Err(bad("unexpected byte")),
            }
            // After a value: close containers, or a comma and the next member.
            loop {
                let Some(&top) = stack.last() else {
                    return Ok(());
                };
                self.ws()?;
                match self.next()? {
                    Some(b',') => {
                        if top == b'{' {
                            self.ws()?;
                            self.member_key()?;
                        }
                        break;
                    }
                    Some(b'}') if top == b'{' => {
                        stack.pop();
                    }
                    Some(b']') if top == b'[' => {
                        stack.pop();
                    }
                    _ => return Err(bad("expected ',' or a closing bracket")),
                }
            }
        }
    }

    /// An object member's key and its `:`.
    fn member_key(&mut self) -> io::Result<()> {
        if self.peek()? != Some(b'"') {
            return Err(bad("expected a key"));
        }
        let saved = self.max;
        self.max = 0;
        let r = self.string();
        self.max = saved;
        r?;
        self.ws()?;
        if self.next()? != Some(b':') {
            return Err(bad("expected ':'"));
        }
        Ok(())
    }

    /// Exactly `word` (`true`, `false`, `null`).
    fn literal(&mut self, word: &[u8]) -> io::Result<()> {
        for &w in word {
            if self.next()? != Some(w) {
                return Err(bad("bad literal"));
            }
        }
        if self.peek()?.is_some_and(|b| b.is_ascii_alphanumeric()) {
            return Err(bad("bad literal"));
        }
        Ok(())
    }

    /// A number: `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`, at most 64 bytes.
    fn number(&mut self) -> io::Result<()> {
        let mut n = 0u32;
        let mut take = |this: &mut Self| -> io::Result<Option<u8>> {
            let b = this.peek()?;
            if b.is_some() {
                this.next()?;
                n = n.saturating_add(1);
                if n > 64 {
                    return Err(bad("number too long"));
                }
            }
            Ok(b)
        };
        let digits =
            |this: &mut Self, take: &mut dyn FnMut(&mut Self) -> io::Result<Option<u8>>| -> io::Result<u32> {
                let mut count = 0u32;
                while this.peek()?.is_some_and(|b| b.is_ascii_digit()) {
                    take(this)?;
                    count = count.saturating_add(1);
                }
                Ok(count)
            };
        if self.peek()? == Some(b'-') {
            take(self)?;
        }
        match self.peek()? {
            Some(b'0') => {
                take(self)?;
            }
            Some(b'1'..=b'9') => {
                digits(self, &mut take)?;
            }
            _ => return Err(bad("bad number")),
        }
        if self.peek()? == Some(b'.') {
            take(self)?;
            if digits(self, &mut take)? == 0 {
                return Err(bad("bad number"));
            }
        }
        if matches!(self.peek()?, Some(b'e' | b'E')) {
            take(self)?;
            if matches!(self.peek()?, Some(b'+' | b'-')) {
                take(self)?;
            }
            if digits(self, &mut take)? == 0 {
                return Err(bad("bad number"));
            }
        }
        if self
            .peek()?
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'+' || b == b'-')
        {
            return Err(bad("bad number"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::{DomainsAs, Format};
    use picket_api::time::Timestamp;

    fn run(json: &str) -> (Vec<Entry>, ParseStats, usize) {
        let cfg = ParseConfig::new(Format::MispWarninglist, DomainsAs::Exact, Timestamp::now());
        let mut out = Vec::new();
        let mut opens = 0usize;
        let stats = parse_misp(
            || {
                opens += 1;
                Ok(json.as_bytes())
            },
            &cfg,
            |e| out.push(e),
        )
        .unwrap();
        (out, stats, opens)
    }

    #[test]
    fn types_after_list_take_two_passes() {
        let json = r#"{"description":"x","list":["google.com",".googleapis.com","bad..name",42],"matching_attributes":["hostname"],"name":"n","type":"hostname","version":3}"#;
        let (e, s, opens) = run(json);
        assert_eq!(opens, 2);
        assert_eq!(e.len(), 2);
        assert_eq!(e[1].rule.key, "com.googleapis");
        assert_eq!(e[0].rule.flags, Flags::B_EXACT | Flags::B_SUBS);
        assert_eq!(s.errors, 2);
        assert_eq!(s.rule_lines, 4);
    }

    #[test]
    fn each_type() {
        let (e, _, opens) = run(r#"{"type":"cidr","list":["8.8.8.0/24","2001:4860::/32","1.1.1.1"]}"#);
        assert_eq!(opens, 2, "validate, then emit");
        assert_eq!(
            e.iter().map(|e| e.rule.key.as_str()).collect::<Vec<_>>(),
            vec!["8.8.8.0/24", "2001:4860::/32", "1.1.1.1"]
        );
        let (e, _, _) = run(r#"{"type":"string","list":["Example.org"]}"#);
        assert_eq!(
            (e[0].rule.key.as_str(), e[0].rule.flags),
            ("org.example", Flags::B_EXACT)
        );
        let (e, _, _) = run(r#"{"type":"substring","list":["tracker","a*b"]}"#);
        assert_eq!(
            (e[0].rule.kind, e[0].rule.key.as_str()),
            (Kind::Pattern, "*tracker*")
        );
        assert_eq!((e[1].rule.kind, e[1].rule.key.as_str()), (Kind::Regex, "/a\\*b/"));
        let (e, _, _) = run(r#"{"type":"regex","list":["^ads\\d+\\."]}"#);
        assert_eq!(e[0].rule.key, "/^ads\\d+\\./");
        let (e, s, _) = run(r#"{"type":"weird","list":["a"]}"#);
        assert!(e.is_empty());
        assert_eq!(s.errors, 1);
    }

    #[test]
    fn escapes_nesting_and_limits() {
        let (e, _, _) =
            run(r#"{"meta":{"a":[1,{"b":null}],"c":"\"x\""},"type":"string","list":["example.org"]}"#);
        assert_eq!(e[0].rule.key, "org.example");
        let long = "a".repeat(70_000);
        let (e, s, _) = run(&format!(r#"{{"type":"string","list":["{long}","ok.example"]}}"#));
        assert_eq!(e.len(), 1);
        assert_eq!(s.errors, 1);
        let cfg = ParseConfig::new(Format::MispWarninglist, DomainsAs::Exact, Timestamp::now());
        let deep = format!(
            r#"{{"x":{}1{},"type":"string","list":[]}}"#,
            "[".repeat(100),
            "]".repeat(100)
        );
        let mut n = 0usize;
        let s = parse_misp(|| Ok(deep.as_bytes()), &cfg, |_| n += 1).unwrap();
        assert_eq!((n, s.errors, s.rule_lines), (0, 1, 1), "too deep: unreadable");
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        // README §2 syntax validation, feeds.md §5: nothing is emitted and the run is rejected.
        for json in [
            r#"{"type":"hostname","list":["example.com"],"ignored":nope}"#,
            r#"{"type":"hostname","list":["example.com"],}"#,
            r#"{"type":"hostname","list":["example.com",]}"#,
            r#"{"type":"hostname","list":["example.com"]} garbage"#,
            r#"{"type":"hostname","list":["example.com"]},"#,
            r#"{"type":"hostname","x":[1 2],"list":["example.com"]}"#,
            r#"{"type":"hostname","x":{"a" 1},"list":["example.com"]}"#,
            r#"{"type":"hostname","x":{1:2},"list":["example.com"]}"#,
            r#"{"type":"hostname","x":[,],"list":["example.com"]}"#,
            r#"{"type":"hostname","x":01,"list":["example.com"]}"#,
            r#"{"type":"hostname","x":1.,"list":["example.com"]}"#,
            r#"{"type":"hostname","x":-,"list":["example.com"]}"#,
            r#"{"type":"hostname","x":truex,"list":["example.com"]}"#,
            r#"{"type":"hostname","list":["example.com"]"#,
            r#"{,"type":"hostname","list":["example.com"]}"#,
            r#"["example.com"]"#,
        ] {
            let (e, s, _) = run(json);
            assert!(e.is_empty(), "{json}");
            assert_eq!((s.errors, s.rule_lines), (1, 1), "{json}");
            assert_eq!(s.error_ratio(), 1.0, "{json}");
        }
        // Valid JSON of every kind still reads.
        let (e, s, _) =
            run(r#" {"x":[1,-2.5e+3,0,true,false,null,{"a":[]},{}],"type":"string","list":["a.example"]} "#);
        assert_eq!((e.len(), s.errors), (1, 0));
    }

    #[test]
    fn a_list_without_a_readable_type_fails_the_parse_gate() {
        // CC2, feeds.md §4–§5: a structurally valid document whose type is missing or unknown
        // can't be read; it emits nothing and its error ratio is 1, so it can't pass the gate
        // and erase an applied feed in replace mode.
        let names: Vec<String> = (0..100).map(|i| format!("\"h{i}.example\"")).collect();
        let list = names.join(",");
        for json in [
            format!(r#"{{"list":[{list}]}}"#),
            format!(r#"{{"list":[{list}],"type":"bogus"}}"#),
            format!(r#"{{"list":[{list}],"type":""}}"#),
            format!(r#"{{"list":[{list}],"type":7}}"#),
            r#"{"list":[]}"#.to_string(),
            r#"{"list":[],"type":"bogus"}"#.to_string(),
            r#"{"name":"x"}"#.to_string(),
        ] {
            let (e, s, _) = run(&json);
            assert!(e.is_empty(), "{json}");
            assert!(s.errors >= 1, "{json}");
            assert_eq!(s.error_ratio(), 1.0, "{json}");
        }
        // A known type with an empty list is an empty list.
        let (e, s, _) = run(r#"{"list":[],"type":"hostname"}"#);
        assert!(e.is_empty());
        assert_eq!(s.error_ratio(), 0.0);
    }

    #[test]
    fn invalid_utf8_anywhere_is_malformed_json() {
        // CC9, README §2 syntax validation: serde_json rejects invalid UTF-8 in any string, read
        // or skipped (ignored metadata, keys, over-long values).
        let long = "a".repeat(200);
        for json in [
            b"{\"description\":\"x\xffy\",\"type\":\"hostname\",\"list\":[\"example.com\"]}".to_vec(),
            b"{\"x\xff\":1,\"type\":\"hostname\",\"list\":[\"example.com\"]}".to_vec(),
            b"{\"m\":{\"k\":[\"\xc3\"]},\"type\":\"hostname\",\"list\":[\"example.com\"]}".to_vec(),
            b"{\"m\":\"\xed\xa0\x80\",\"type\":\"hostname\",\"list\":[\"example.com\"]}".to_vec(),
            b"{\"m\":\"\xc0\xaf\",\"type\":\"hostname\",\"list\":[\"example.com\"]}".to_vec(),
            format!("{{\"type\":\"hostname\",\"list\":[\"{long}\u{1}\"]}}").into_bytes(),
            [
                format!("{{\"type\":\"hostname\",\"list\":[\"{long}").as_bytes(),
                b"\xff\"]}",
            ]
            .concat(),
        ] {
            assert!(serde_json::from_slice::<serde_json::Value>(&json).is_err());
            let mut cfg = ParseConfig::new(Format::MispWarninglist, DomainsAs::Exact, Timestamp::now());
            cfg.max_line_len = 100;
            let mut n = 0usize;
            let s = parse_misp(|| Ok(&json[..]), &cfg, |_| n += 1).unwrap();
            assert_eq!(
                (n, s.errors, s.rule_lines),
                (0, 1, 1),
                "{}",
                String::from_utf8_lossy(&json)
            );
        }
        // Valid multi-byte UTF-8 in skipped and read strings still reads.
        let ok = "{\"description\":\"caf\u{e9} \u{1F600} \u{20AC}\",\"type\":\"hostname\",\"list\":[\"b\u{fc}cher.example\"]}";
        assert!(serde_json::from_str::<serde_json::Value>(ok).is_ok());
        let (e, s, _) = run(ok);
        assert_eq!((e.len(), s.errors), (1, 0));
    }

    #[test]
    fn streams_large_lists() {
        // 100k entries through a small buffer: memory is bounded by one value.
        let mut json = String::from(r#"{"list":["#);
        for i in 0..100_000 {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!("\"h{i}.example\""));
        }
        json.push_str(r#"],"type":"hostname"}"#);
        let cfg = ParseConfig::new(Format::MispWarninglist, DomainsAs::Exact, Timestamp::now());
        let mut n = 0usize;
        let s = parse_misp(
            || Ok(std::io::BufReader::with_capacity(4096, json.as_bytes())),
            &cfg,
            |_| n += 1,
        )
        .unwrap();
        assert_eq!(n, 100_000);
        assert_eq!(s.errors, 0);
    }
}
