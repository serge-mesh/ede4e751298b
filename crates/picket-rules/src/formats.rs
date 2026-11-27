//! Streaming feed parsers (feeds.md §4, §5): `adblock`, `hosts`, `plain` and `misp-warninglist`,
//! the `picket-first-seen` directive, and the counts a run records.
//!
//! Lines are read one at a time from a `BufRead` with a bounded buffer: a line longer than
//! [`ParseConfig::max_line_len`] is a parse error and is skipped without being held in memory.

use std::borrow::Cow;
use std::io::{self, BufRead};
use std::net::IpAddr;

use jiff::civil;
use jiff::tz::Offset;
use picket_api::time::{ParseError, Timestamp};
use serde::{Deserialize, Serialize};

use crate::classify::{self, ErrorReason, Item, Line};
use crate::flags::Flags;
use crate::ip::IpRange;
use crate::misp;
use crate::name::RuleName;
use crate::rule::{Entry, Kind, Rule, RuleSpec, RuleType};

/// Default line limit (64 KiB): long enough for uBlock Origin scriptlet and `$domain=` lines.
pub const DEFAULT_MAX_LINE_LEN: usize = 64 * 1024;
/// How many parse errors a run keeps as samples.
pub const MAX_ERROR_SAMPLES: usize = 20;
/// The longest `! Expires:` interval a list may ask for (30 days); longer values are clamped.
pub const MAX_EXPIRES_SECS: u64 = 30 * 86_400;

/// A feed's format (feeds.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Adblock,
    Hosts,
    Plain,
    MispWarninglist,
}

/// `format_options.domains_as` for `plain` feeds (feeds.md §1, §4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainsAs {
    /// The exact name (AdGuard semantics), the default.
    #[default]
    Exact,
    /// The name and its subdomains, as `||name^`.
    Subdomains,
}

/// How to parse one run.
#[derive(Clone, Debug)]
pub struct ParseConfig {
    pub format: Format,
    pub domains_as: DomainsAs,
    /// The run's time: future first-seen dates are clamped to it (feeds.md §4).
    pub run_time: Timestamp,
    /// Longest line accepted.
    pub max_line_len: usize,
}

impl ParseConfig {
    /// A config with the default line limit.
    pub fn new(format: Format, domains_as: DomainsAs, run_time: Timestamp) -> ParseConfig {
        ParseConfig {
            format,
            domains_as,
            run_time,
            max_line_len: DEFAULT_MAX_LINE_LEN,
        }
    }
}

/// Counts per rule type; `unknown` for warnings whose rule type isn't known (unknown modifiers).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeCounts {
    pub dns: u64,
    pub ip: u64,
    pub browser: u64,
    pub unknown: u64,
}

impl TypeCounts {
    /// Adds one to the type's count.
    pub fn add(&mut self, t: Option<RuleType>) {
        let c = match t {
            Some(RuleType::Dns) => &mut self.dns,
            Some(RuleType::Ip) => &mut self.ip,
            Some(RuleType::Browser) => &mut self.browser,
            None => &mut self.unknown,
        };
        *c = c.saturating_add(1);
    }

    /// The total.
    pub fn total(&self) -> u64 {
        self.dns
            .saturating_add(self.ip)
            .saturating_add(self.browser)
            .saturating_add(self.unknown)
    }
}

/// One parse error kept as a sample.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorSample {
    pub line_no: u64,
    pub reason: String,
    /// The line, cut to 200 bytes.
    pub text: String,
}

/// What a run's parse found (feeds.md §5, §6).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseStats {
    /// Physical lines (MISP: list values).
    pub lines: u64,
    /// Empty lines, comments, headers and directives.
    pub skipped: u64,
    /// Non-empty, non-comment lines: the denominator of the parse-error ratio.
    pub rule_lines: u64,
    /// Parse errors: lines the format can't read, and unparseable first-seen directives.
    pub errors: u64,
    /// Rules dropped on purpose, per type.
    pub warnings: TypeCounts,
    /// Rules dropped on purpose, per reason (`UnknownModifier`, `TooWide`, `AdguardOnly`,
    /// `Conditional`, `InvalidModifierValue`, `UnsupportedValue`).
    pub warning_reasons: std::collections::BTreeMap<String, u64>,
    /// Entries emitted, per type (before modes and `rule_policy`).
    pub entries: TypeCounts,
    /// The first parse errors.
    pub error_samples: Vec<ErrorSample>,
    /// An `adblock` list's `! Expires:` header in seconds (at most [`MAX_EXPIRES_SECS`]): on cron
    /// schedules, the minimum interval between full downloads (feeds.md §5). Read from the
    /// comments before the first rule; `None` without one or when it can't be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_secs: Option<u64>,
}

impl ParseStats {
    /// errors ÷ non-empty, non-comment lines (feeds.md §5); 0 for an empty file.
    pub fn error_ratio(&self) -> f64 {
        if self.rule_lines == 0 {
            if self.errors == 0 { 0.0 } else { 1.0 }
        } else {
            self.errors as f64 / self.rule_lines as f64
        }
    }

    pub(crate) fn error(&mut self, line_no: u64, reason: ErrorReason, text: &str) {
        self.errors = self.errors.saturating_add(1);
        if self.error_samples.len() < MAX_ERROR_SAMPLES {
            let mut cut = text.len().min(200);
            while !text.is_char_boundary(cut) {
                cut = cut.saturating_sub(1);
            }
            self.error_samples.push(ErrorSample {
                line_no,
                reason: format!("{reason:?}"),
                text: text.get(..cut).unwrap_or("").to_string(),
            });
        }
    }
}

/// The value of a `picket-first-seen` directive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Directive {
    /// Lines after it carry this date (clamped).
    Date(Timestamp),
    /// `none`: back to the default.
    Reset,
    /// Unparseable: a parse error; lines use the default.
    Invalid,
}

/// Reads a first-seen directive from a comment's text after its `!` or `#`. `None` when the
/// comment isn't one.
pub fn parse_directive(comment: &str, run_time: Timestamp) -> Option<Directive> {
    let c = comment.trim();
    const NAME: &str = "picket-first-seen:";
    let head = c.get(..NAME.len())?;
    if !head.eq_ignore_ascii_case(NAME) {
        return None;
    }
    let v = c.get(NAME.len()..).unwrap_or("").trim();
    if v.eq_ignore_ascii_case("none") {
        return Some(Directive::Reset);
    }
    Some(match parse_rfc3339(v) {
        Some(t) => Directive::Date(t.min(run_time)),
        None => Directive::Invalid,
    })
}

/// RFC 3339 date or date-time; UTC when no zone is given (feeds.md §4). Read as chrono read
/// it: a date-time with an offset through [`picket_api::time::parse`], the other forms with
/// strptime ([`naive_utc`]). A real date past the end of the timestamp range (`9999-12-31`, a
/// common "never") reads as [`Timestamp::MAX`], which the run's time then clamps, as before.
pub fn parse_rfc3339(v: &str) -> Option<Timestamp> {
    if v.len() == 10 {
        return naive_utc(&format!("{v}T00:00:00"));
    }
    let norm: String = v
        .chars()
        .map(|c| {
            if c == 't' || c == ' ' {
                'T'
            } else if c == 'z' {
                'Z'
            } else {
                c
            }
        })
        .collect();
    match picket_api::time::parse(&norm) {
        Ok(t) => return Some(t),
        Err(ParseError::OutOfRange) => return Some(Timestamp::MAX),
        Err(ParseError::Invalid) => {}
    }
    naive_utc(&cut_fraction(&norm))
}

/// strptime's form of a date-time without a zone.
const NAIVE: &str = "%Y-%m-%dT%H:%M:%S%.f";
/// The years chrono's dates held; a signed year outside them was refused.
const CHRONO_YEARS: std::ops::RangeInclusive<i64> = -262_143..=262_142;

/// A date-time without a zone, in UTC, read as chrono's `%Y-%m-%dT%H:%M:%S%.f` read it: an
/// unsigned year of up to four digits, or a signed one of any length within chrono's years
/// (`+002026`, `+10000`, `-0001`; jiff's `%Y` takes four digits at most). Past the timestamp
/// range it saturates.
fn naive_utc(s: &str) -> Option<Timestamp> {
    if !s.starts_with(['+', '-']) {
        return Some(utc(civil::DateTime::strptime(NAIVE, s).ok()?));
    }
    let digits = s.get(1..)?.bytes().take_while(u8::is_ascii_digit).count();
    let (year, rest) = s.split_at_checked(digits.checked_add(1)?)?;
    let year: i64 = year.parse().ok()?;
    if !CHRONO_YEARS.contains(&year) {
        return None;
    }
    // The rest under a leap-year stand-in, so 02-29 reads; the real year is checked here.
    let dt = civil::DateTime::strptime(NAIVE, format!("2000{rest}")).ok()?;
    let leap = year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    if dt.month() == 2 && dt.day() == 29 && !leap {
        return None;
    }
    Some(match i16::try_from(year) {
        Ok(y) if (-9999..=9999).contains(&y) => utc(dt.with().year(y).build().ok()?),
        _ if year < 0 => Timestamp::MIN,
        _ => Timestamp::MAX,
    })
}

/// `dt` in UTC, saturating at the ends of the timestamp range.
fn utc(dt: civil::DateTime) -> Timestamp {
    Offset::UTC.to_timestamp(dt).unwrap_or(if dt.year() < 0 {
        Timestamp::MIN
    } else {
        Timestamp::MAX
    })
}

/// `s` without the fraction digits past the ninth, which chrono's `%.f` dropped (jiff's refuses
/// them).
fn cut_fraction(s: &str) -> Cow<'_, str> {
    let Some((date_time, frac)) = s.split_once('.') else {
        return Cow::Borrowed(s);
    };
    let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
    match (frac.get(..9), frac.get(digits..)) {
        (Some(kept), Some(tail)) if digits > 9 => Cow::Owned(format!("{date_time}.{kept}{tail}")),
        _ => Cow::Borrowed(s),
    }
}

/// Parses a feed, calling `sink` for each entry. `open` gives a fresh reader of the whole file:
/// line formats call it once; `misp-warninglist` may call it twice when `type` follows `list`
/// (bounded memory: the list is never held, [`misp`]).
pub fn parse_feed<R, O, F>(mut open: O, cfg: &ParseConfig, sink: F) -> io::Result<ParseStats>
where
    R: BufRead,
    O: FnMut() -> io::Result<R>,
    F: FnMut(Entry),
{
    match cfg.format {
        Format::MispWarninglist => misp::parse_misp(open, cfg, sink),
        _ => parse_lines(open()?, cfg, sink),
    }
}

/// Parses a line format (`adblock`, `hosts`, `plain`) from one reader.
pub fn parse_lines<R: BufRead, F: FnMut(Entry)>(
    mut reader: R,
    cfg: &ParseConfig,
    mut sink: F,
) -> io::Result<ParseStats> {
    let mut stats = ParseStats::default();
    let mut buf = Vec::with_capacity(256);
    let mut line_no: u64 = 0;
    let mut first_seen: Option<Timestamp> = None;
    let mut if_depth: u32 = 0;
    loop {
        let read = read_bounded_line(&mut reader, &mut buf, cfg.max_line_len)?;
        let too_long = match read {
            ReadLine::Eof => break,
            ReadLine::Line => false,
            ReadLine::TooLong => true,
        };
        line_no = line_no.saturating_add(1);
        stats.lines = stats.lines.saturating_add(1);
        if too_long {
            stats.rule_lines = stats.rule_lines.saturating_add(1);
            stats.error(line_no, ErrorReason::TooLong, "");
            continue;
        }
        let Ok(text) = std::str::from_utf8(&buf) else {
            stats.rule_lines = stats.rule_lines.saturating_add(1);
            stats.error(line_no, ErrorReason::Encoding, &String::from_utf8_lossy(&buf));
            continue;
        };
        let text = text.trim_start_matches('\u{feff}').trim();
        // Comments, directives and first-seen.
        let comment = comment_body(cfg.format, text);
        if text.is_empty() {
            stats.skipped = stats.skipped.saturating_add(1);
            continue;
        }
        if let Some(body) = comment {
            stats.skipped = stats.skipped.saturating_add(1);
            if cfg.format == Format::Adblock && stats.rule_lines == 0 && stats.expires_secs.is_none() {
                stats.expires_secs = parse_expires_header(body);
            }
            match parse_directive(body, cfg.run_time) {
                Some(Directive::Date(t)) => first_seen = Some(t),
                Some(Directive::Reset) => first_seen = None,
                Some(Directive::Invalid) => {
                    first_seen = None;
                    stats.error(line_no, ErrorReason::FirstSeen, text);
                }
                None => {}
            }
            if cfg.format == Format::Adblock {
                let d = body.trim_start();
                if d.starts_with("#if") {
                    if_depth = if_depth.saturating_add(1);
                } else if d.starts_with("#endif") {
                    if_depth = if_depth.saturating_sub(1);
                }
            }
            continue;
        }
        let line = parse_line(cfg.format, cfg.domains_as, text, if_depth > 0);
        let items = match line {
            Line::Skipped => {
                stats.skipped = stats.skipped.saturating_add(1);
                continue;
            }
            Line::Items(items) => items,
        };
        stats.rule_lines = stats.rule_lines.saturating_add(1);
        let mut line_error = None;
        for item in items {
            match item {
                Item::Rule(rule) => {
                    stats.entries.add(Some(rule.rule_type));
                    sink(Entry {
                        rule,
                        raw: text.to_string(),
                        line_no,
                        first_seen,
                    });
                }
                Item::Warning { rule_type, reason } => {
                    stats.warnings.add(rule_type);
                    let n = stats.warning_reasons.entry(format!("{reason:?}")).or_insert(0);
                    *n = n.saturating_add(1);
                }
                Item::Error(e) => line_error = line_error.or(Some(e)),
            }
        }
        if let Some(e) = line_error {
            stats.error(line_no, e, text);
        }
    }
    Ok(stats)
}

/// Reads an `Expires:` header from a comment's text after its `!` (`! Expires: 4 days (update
/// frequency)`): a count of days by default, or of hours with a unit starting `h`, as uBlock
/// Origin reads it. Clamped to [`MAX_EXPIRES_SECS`]; `None` when the comment isn't one or the
/// value can't be read.
pub fn parse_expires_header(comment: &str) -> Option<u64> {
    const NAME: &str = "expires:";
    let c = comment.trim_start();
    let head = c.get(..NAME.len())?;
    if !head.eq_ignore_ascii_case(NAME) {
        return None;
    }
    let v = c.get(NAME.len()..)?.trim_start();
    let digits_end = v.find(|ch: char| !ch.is_ascii_digit()).unwrap_or(v.len());
    let n: u64 = v.get(..digits_end)?.parse().ok()?;
    let unit = v.get(digits_end..)?.trim_start();
    let per = match unit.bytes().next().map(|b| b.to_ascii_lowercase()) {
        Some(b'h') => 3_600u64,
        None | Some(b'd' | b'(') => 86_400,
        _ => return None,
    };
    Some(n.saturating_mul(per).min(MAX_EXPIRES_SECS))
}

/// The text after a line's comment marker when the line is a comment in this format.
fn comment_body(format: Format, text: &str) -> Option<&str> {
    match format {
        Format::Adblock => text.strip_prefix('!'),
        Format::Hosts => text.strip_prefix('#'),
        Format::Plain => text
            .strip_prefix('!')
            .or_else(|| text.strip_prefix('#'))
            .or_else(|| text.strip_prefix(';')),
        Format::MispWarninglist => None,
    }
}

/// Classifies one non-comment line of a line format. Core also uses it to re-classify a stored
/// `raw` line (feeds.md §8 "classified from raw").
pub fn parse_line(format: Format, domains_as: DomainsAs, text: &str, in_conditional: bool) -> Line {
    match format {
        Format::Adblock => classify::classify_adblock_line(text, in_conditional),
        Format::Hosts => hosts_line(text),
        Format::Plain => plain_line(text, domains_as),
        Format::MispWarninglist => Line::Items(vec![Item::Error(ErrorReason::Syntax)]),
    }
}

/// A `hosts` line: `address name…`, or a single host name, read as AdGuard reads host rules.
fn hosts_line(text: &str) -> Line {
    if text.starts_with('#') {
        return Line::Skipped;
    }
    match classify::host_rule_items(text) {
        Some(items) => Line::Items(items),
        None => Line::Items(vec![Item::Error(ErrorReason::Syntax)]),
    }
}

/// A `plain` line: one name, address or CIDR, maybe followed by a comment.
fn plain_line(text: &str, domains_as: DomainsAs) -> Line {
    let mut tokens = text.split_whitespace();
    let Some(token) = tokens.next() else {
        return Line::Skipped;
    };
    if let Some(next) = tokens.next()
        && !next.starts_with(['#', ';', '!'])
    {
        return Line::Items(vec![Item::Error(ErrorReason::Syntax)]);
    }
    Line::Items(vec![plain_token(token, domains_as)])
}

/// One `plain` (or MISP) value: an address or CIDR → an `ip` indicator; `*.name` or `.name` →
/// subdomains only (as `*.d^` and `.d^`); a name → exact or name and subdomains per `domains_as`.
pub(crate) fn plain_token(token: &str, domains_as: DomainsAs) -> Item {
    if token.contains(':') || token.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        if let Some(range) = IpRange::parse(token) {
            return Item::Rule(ip_indicator(range));
        }
        if token.contains('/') || token.contains(':') {
            return Item::Error(ErrorReason::BadAddress);
        }
    }
    let (subs_only, name) = match token.strip_prefix("*.").or_else(|| token.strip_prefix('.')) {
        Some(n) => (true, n),
        None => (false, token),
    };
    match RuleName::parse(name) {
        Ok(name) => {
            let flags = if subs_only {
                Flags::B_SUBS
            } else {
                match domains_as {
                    DomainsAs::Exact => Flags::B_EXACT,
                    DomainsAs::Subdomains => Flags::B_EXACT | Flags::B_SUBS,
                }
            };
            Item::Rule(classify::name_rule(&name, flags, RuleSpec::default()))
        }
        Err(_) => Item::Error(ErrorReason::BadName),
    }
}

/// An IP or CIDR indicator rule.
pub(crate) fn ip_indicator(range: IpRange) -> Rule {
    Rule {
        rule_type: RuleType::Ip,
        kind: Kind::IpRange,
        key: range.to_text(),
        flags: Flags::B_EXACT,
        spec: RuleSpec::default(),
    }
}

/// A host mapping or block for `name` from a hosts-style address (for providers that convert).
pub fn hosts_entry(ip: IpAddr, name: &str) -> Option<Rule> {
    match classify::hosts_name(ip, name) {
        Item::Rule(r) => Some(r),
        _ => None,
    }
}

enum ReadLine {
    Eof,
    Line,
    TooLong,
}

/// Reads one line (without its `\n`/`\r\n`) into `buf`, never holding more than `max` bytes: a
/// longer line is consumed to its end and reported as too long.
fn read_bounded_line<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>, max: usize) -> io::Result<ReadLine> {
    buf.clear();
    let mut too_long = false;
    let mut any = false;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            if !any {
                return Ok(ReadLine::Eof);
            }
            break;
        }
        any = true;
        let (chunk, done, used) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (available.get(..i).unwrap_or(&[]), true, i.saturating_add(1)),
            None => (available, false, available.len()),
        };
        if !too_long {
            if buf.len().saturating_add(chunk.len()) > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        reader.consume(used);
        if done {
            break;
        }
    }
    if too_long {
        return Ok(ReadLine::TooLong);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(ReadLine::Line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The instant at a UTC date and time.
    fn utc(y: i16, mo: i8, d: i8, h: i8, mi: i8) -> Timestamp {
        Offset::UTC
            .to_timestamp(civil::datetime(y, mo, d, h, mi, 0, 0))
            .unwrap()
    }

    fn run(format: Format, domains_as: DomainsAs, text: &str) -> (Vec<Entry>, ParseStats) {
        let cfg = ParseConfig::new(format, domains_as, utc(2026, 11, 21, 0, 0));
        let mut out = Vec::new();
        let stats = parse_lines(text.as_bytes(), &cfg, |e| out.push(e)).unwrap();
        (out, stats)
    }

    #[test]
    fn plain_mix() {
        let text = "# comment\n; another\n! third\nexample.com\n*.wild.example\n1.2.3.4\n10.0.0.0/8\n2001:db8::/32\n::ffff:9.9.9.9\nexample.org # note\nbad..name\n300.1.1.1/8\n\n";
        let (e, s) = run(Format::Plain, DomainsAs::Exact, text);
        let keys: Vec<(&str, Flags, Kind)> = e
            .iter()
            .map(|e| (e.rule.key.as_str(), e.rule.flags, e.rule.kind))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("com.example", Flags::B_EXACT, Kind::Name),
                ("example.wild", Flags::B_SUBS, Kind::Name),
                ("1.2.3.4", Flags::B_EXACT, Kind::IpRange),
                ("10.0.0.0/8", Flags::B_EXACT, Kind::IpRange),
                ("2001:db8::/32", Flags::B_EXACT, Kind::IpRange),
                ("9.9.9.9", Flags::B_EXACT, Kind::IpRange),
                ("org.example", Flags::B_EXACT, Kind::Name),
            ]
        );
        assert_eq!(s.errors, 2);
        assert_eq!(s.skipped, 4);
        assert_eq!(s.rule_lines, 9);
        assert_eq!(s.entries.dns, 3);
        assert_eq!(s.entries.ip, 4);
        let (e, _) = run(Format::Plain, DomainsAs::Subdomains, "example.com\n");
        assert_eq!(e[0].rule.flags, Flags::B_EXACT | Flags::B_SUBS);
    }

    #[test]
    fn first_seen_each_format() {
        let text = "! picket-first-seen: 2021-06-01\n||old.example^\n! picket-first-seen: 2023-02-14T09:30:00Z\n||phish.example^\n! picket-first-seen: none\n||new.example^\n! picket-first-seen: 2099-01-01\n||future.example^\n! picket-first-seen: yesterday\n||after-bad.example^\n! picket-first-seen: 2023-02-14T09:30:00+02:00\n||zoned.example^\n! picket-first-seen: 2023-02-14 09:30:00\n||naive.example^\n";
        let (e, s) = run(Format::Adblock, DomainsAs::Exact, text);
        let fs: Vec<Option<Timestamp>> = e.iter().map(|e| e.first_seen).collect();
        assert_eq!(
            fs,
            vec![
                Some(utc(2021, 6, 1, 0, 0)),
                Some(utc(2023, 2, 14, 9, 30)),
                None,
                Some(utc(2026, 11, 21, 0, 0)),
                None,
                Some(utc(2023, 2, 14, 7, 30)),
                Some(utc(2023, 2, 14, 9, 30)),
            ]
        );
        assert_eq!(s.errors, 1);
        let (e, _) = run(
            Format::Hosts,
            DomainsAs::Exact,
            "# picket-first-seen: 2020-01-01\n0.0.0.0 a.example\n",
        );
        assert_eq!(e[0].first_seen, Some(utc(2020, 1, 1, 0, 0)));
        let (e, _) = run(
            Format::Plain,
            DomainsAs::Exact,
            "! picket-first-seen: 2020-01-01\na.example\n",
        );
        assert_eq!(e[0].first_seen, Some(utc(2020, 1, 1, 0, 0)));
    }

    #[test]
    fn hosts_format() {
        let text = "127.0.0.1 localhost\n0.0.0.0 ads.example # comment\n192.0.2.10 mapped.example other.example\nnot a hosts line\n0.0.0.0 bad..name\nsingle.example\n";
        let (e, s) = run(Format::Hosts, DomainsAs::Exact, text);
        let kinds: Vec<(&str, Kind)> = e.iter().map(|e| (e.rule.key.as_str(), e.rule.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                ("localhost", Kind::Name),
                ("example.ads", Kind::Name),
                ("example.mapped", Kind::HostMapping),
                ("example.other", Kind::HostMapping),
                ("example.single", Kind::Name),
            ]
        );
        assert_eq!(s.errors, 2);
    }

    #[test]
    fn conditional_browser_rules() {
        let text = "!#if env_mobile\nexample.org##.ad\n||inside.example^\n!#endif\nexample.org##.ad\n";
        let (e, s) = run(Format::Adblock, DomainsAs::Exact, text);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].rule.key, "example.inside");
        assert_eq!(e[1].rule.rule_type, RuleType::Browser);
        assert_eq!(s.warnings.browser, 1);
        assert_eq!(s.warning_reasons.get("Conditional"), Some(&1));
    }

    #[test]
    fn bounded_lines() {
        let long = "a".repeat(100);
        let text = format!("||ok.example^\n{long}\n||after.example^\r\n");
        let cfg = ParseConfig {
            max_line_len: 50,
            ..ParseConfig::new(Format::Adblock, DomainsAs::Exact, Timestamp::now())
        };
        let mut out = Vec::new();
        let s = parse_lines(
            std::io::BufReader::with_capacity(16, text.as_bytes()),
            &cfg,
            |e| out.push(e),
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].rule.key, "example.after");
        assert_eq!(out[1].line_no, 3);
        assert_eq!(s.errors, 1);
        let bad = b"\xff\xfe||x.example^\n";
        let s = parse_lines(&bad[..], &cfg, |_| {}).unwrap();
        assert_eq!(s.errors, 1);
    }

    #[test]
    fn expires_header() {
        assert_eq!(
            parse_expires_header(" Expires: 4 days (update frequency)"),
            Some(4 * 86_400)
        );
        assert_eq!(parse_expires_header(" expires: 12 hours"), Some(12 * 3_600));
        assert_eq!(parse_expires_header("Expires:1h"), Some(3_600));
        assert_eq!(parse_expires_header(" Expires: 2"), Some(2 * 86_400));
        assert_eq!(
            parse_expires_header(" Expires: 9999 days"),
            Some(MAX_EXPIRES_SECS)
        );
        assert_eq!(parse_expires_header(" Expires: soon"), None);
        assert_eq!(parse_expires_header(" Expires: 3 weeks"), None);
        assert_eq!(parse_expires_header(" Title: Expires: 1 day"), None);
        let text = "[Adblock Plus 2.0]\n! Title: x\n! Expires: 2 days\n||a.example^\n! Expires: 1 hours\n";
        let (_, s) = run(Format::Adblock, DomainsAs::Exact, text);
        assert_eq!(s.expires_secs, Some(2 * 86_400));
        let (_, s) = run(
            Format::Adblock,
            DomainsAs::Exact,
            "||a.example^\n! Expires: 1 hours\n",
        );
        assert_eq!(
            s.expires_secs, None,
            "only the header before the first rule counts"
        );
        let (_, s) = run(
            Format::Hosts,
            DomainsAs::Exact,
            "# Expires: 1 day\n0.0.0.0 a.example\n",
        );
        assert_eq!(s.expires_secs, None);
    }

    #[test]
    fn plain_leading_dot() {
        let (e, s) = run(
            Format::Plain,
            DomainsAs::Subdomains,
            ".dot.example\n*.wild.example\n.\n",
        );
        let keys: Vec<(&str, Flags)> = e.iter().map(|e| (e.rule.key.as_str(), e.rule.flags)).collect();
        assert_eq!(
            keys,
            vec![("example.dot", Flags::B_SUBS), ("example.wild", Flags::B_SUBS)]
        );
        assert_eq!(s.errors, 1);
    }

    #[test]
    fn rfc3339() {
        assert!(parse_rfc3339("2021-06-01").is_some());
        assert!(parse_rfc3339("2021-13-01").is_none());
        assert!(parse_rfc3339("2021-06-01t10:00:00z").is_some());
        assert!(parse_rfc3339("June 1").is_none());
    }

    /// jiff's RFC 3339 reader takes forms chrono refused; feeds still have them refused.
    #[test]
    fn rfc3339_refuses_what_chrono_refused() {
        for input in [
            "2026-11-13T10:22Z",
            "2026-11-13T10:22",
            "2026-11-13T10Z",
            "2026-11-13T10:22:01+0200",
            "2026-11-13T10:22:01+02",
            "2026-11-13T10:22:01,5Z",
            "2026-11-13T10:22:01Z[UTC]",
            "2026-11-13T10:22:01[UTC]",
            "20261113T102201Z",
            "2026-11-13T10:22:01.Z",
            "+2026-11-13T10:22:01Z",
            "2026-11-13T10:22:01+02:0",
        ] {
            assert_eq!(parse_rfc3339(input), None, "{input:?}");
        }
        assert_eq!(
            parse_rfc3339("2026-11-13T05:22:01.5-05:00")
                .as_ref()
                .map(picket_api::time::format_micros)
                .as_deref(),
            Some("2026-11-13T10:22:01.500000Z")
        );
    }

    /// chrono read dates past jiff's range and the run's time clamped them; long fractions were
    /// truncated; a leap second reads as `:59`.
    #[test]
    fn rfc3339_edges_read_as_chrono_did() {
        let f1 = |v: &str| parse_rfc3339(v).as_ref().map(picket_api::time::format_micros);
        for never in [
            "9999-12-31",
            "9999-12-31T23:59:59Z",
            "9999-12-31 23:59:59",
            "9999-12-31T00:00:00+00:00",
        ] {
            assert_eq!(parse_rfc3339(never), Some(Timestamp::MAX), "{never:?}");
            let run = utc(2026, 11, 21, 0, 0);
            assert_eq!(
                parse_directive(&format!("picket-first-seen: {never}"), run),
                Some(Directive::Date(run)),
                "{never:?}"
            );
        }
        for long in [
            "2026-11-13T10:22:01.1234567891Z",
            "2026-11-13T10:22:01.123456789123",
            "2026-11-13 10:22:01.1234567891",
        ] {
            assert_eq!(
                f1(long).as_deref(),
                Some("2026-11-13T10:22:01.123456Z"),
                "{long:?}"
            );
        }
        for leap in ["2026-11-13T10:22:60Z", "2026-11-13T10:22:60"] {
            assert_eq!(
                f1(leap).as_deref(),
                Some("2026-11-13T10:22:59.000000Z"),
                "{leap:?}"
            );
        }
        assert_eq!(f1("2026-11-13T10:22:61Z"), None);
        assert_eq!(f1("2026-11-13T10:22:01+24:00"), None);
    }

    /// The no-zone forms take chrono's `%Y`: a signed year of any length within chrono's years,
    /// an unsigned one of up to four digits. Instants as chrono read them (Unix seconds,
    /// recorded from chrono 0.4.45); past the timestamp range they saturate.
    #[test]
    fn rfc3339_signed_years_read_as_chrono_did() {
        let secs = |v: &str| parse_rfc3339(v).map(Timestamp::as_second);
        for (input, want) in [
            ("+002026-11-13T10:22:01", Some(1_794_565_321)),
            ("+0002026-11-13T10:22:01", Some(1_794_565_321)),
            ("+2026-11-13 10:22:01", Some(1_794_565_321)),
            ("-0001-11-13T10:22:01", Some(-62_171_415_479)),
            ("-999-01-01", Some(-93_692_592_000)),
            ("+999-01-01", Some(-30_641_760_000)),
            ("02026-11-13T10:22:01", None),
            ("+10001-02-29T00:00:00", None),
            ("+262143-12-31T23:59:59", None),
            ("-262144-01-01T00:00:00", None),
            ("+002026-11-13T10:22:01Z", None),
        ] {
            assert_eq!(secs(input), want, "{input:?}");
        }
        let run = utc(2026, 11, 21, 0, 0);
        for (input, want) in [
            ("+10000-11-13T10:22:01", Timestamp::MAX),
            ("+262142-12-31T23:59:59", Timestamp::MAX),
            ("+10004-02-29T00:00:00", Timestamp::MAX),
            ("-12026-11-13T10:22:01", Timestamp::MIN),
        ] {
            assert_eq!(parse_rfc3339(input), Some(want), "{input:?}");
        }
        assert_eq!(
            parse_directive("picket-first-seen: +10000-11-13T10:22:01", run),
            Some(Directive::Date(run))
        );
    }

    /// Golden (plan §5 step 1): each date and the instant read, as F1, recorded from chrono and
    /// unchanged after the move to jiff. Left out: `2026-11-13T10:22Z`, which chrono refuses and
    /// jiff's RFC 3339 parser reads.
    #[test]
    fn golden_rfc3339_corpus() {
        const CORPUS: &[(&str, Option<&str>)] = &[
            ("2026-11-13", Some("2026-11-13T00:00:00.000000Z")),
            ("2026-11-13T10:22:01Z", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13t10:22:01z", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13 10:22:01Z", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13T10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13T10:22:01.123456", Some("2026-11-13T10:22:01.123456Z")),
            (
                "2026-11-13T10:22:01.123456789",
                Some("2026-11-13T10:22:01.123456Z"),
            ),
            ("2026-11-13T10:22:01.5", Some("2026-11-13T10:22:01.500000Z")),
            ("2026-11-13T12:22:01+02:00", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13T10:22:01.120Z", Some("2026-11-13T10:22:01.120000Z")),
            ("2026-11-13T10:22", None),
            ("2026-02-30", None),
            ("2026-1-1", None),
            ("20261113", None),
            ("2026-11-13X", None),
            ("2026/11/13", None),
            ("", None),
            ("2026-11-13T10:22:01.Z", None),
            ("2026-11-13T25:00:00", None),
            ("1970-01-01", Some("1970-01-01T00:00:00.000000Z")),
            ("9999-12-30", Some("9999-12-30T00:00:00.000000Z")),
        ];
        for (input, want) in CORPUS {
            let got = parse_rfc3339(input).as_ref().map(picket_api::time::format_micros);
            assert_eq!(got.as_deref(), *want, "{input:?}");
        }
    }
}
