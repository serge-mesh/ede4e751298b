//! Dates a source reports (providers.md §3): `Last-Modified` and `Retry-After` HTTP dates, and a
//! list header's date line (`! Last modified: …`, `# Updated : …`), read leniently in the forms
//! lists use. All of it is untrusted input: bounded, never panicking, and a time core can't
//! read is simply not exact (feed-scheduling.md §3 then treats the change as an interval).

use jiff::fmt::rfc2822;
use jiff::tz::Offset;
use jiff::{Timestamp, civil};

/// The longest text read as one date.
const MAX_DATE: usize = 80;
/// How many header lines a date line is looked for in.
pub const DATE_LINE_SCAN_LINES: usize = 64;

/// An HTTP date (RFC 9110 §5.6.7: IMF-fixdate, plus the obsolete RFC 850 and asctime forms).
pub fn parse_http_date(s: &str) -> Option<Timestamp> {
    let s = s.trim();
    if s.is_empty() || s.len() > MAX_DATE {
        return None;
    }
    if let Ok(t) = rfc2822::DateTimeParser::new().parse_timestamp(s) {
        return Some(t);
    }
    // RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
    if let Some(rest) = s.split_once(", ").map(|(_, r)| r)
        && let Some(r) = rest.strip_suffix(" GMT")
        && let Some(t) = utc_strptime("%d-%b-%y %H:%M:%S", r)
    {
        return Some(t);
    }
    // asctime: Sun Nov  6 08:49:37 1994
    let squashed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    utc_strptime("%a %b %e %H:%M:%S %Y", &squashed)
}

/// `s` read with a strptime date-and-time format (jiff's argument order: format first), in UTC.
fn utc_strptime(fmt: &str, s: &str) -> Option<Timestamp> {
    let dt = civil::DateTime::strptime(fmt, s).ok()?;
    Offset::UTC.to_timestamp(dt).ok()
}

/// A free-form date as list headers write them: RFC 3339, RFC 2822, `YYYY-MM-DD[ HH:MM[:SS]]`
/// with an optional `UTC`/`GMT`/`Z`, `DD Mon YYYY HH:MM[:SS] [UTC]`, or a bare date. UTC when no
/// zone is given.
pub fn parse_loose_date(s: &str) -> Option<Timestamp> {
    let s = s
        .trim()
        .trim_matches(|c: char| c == '(' || c == ')' || c == '"' || c == '\'');
    if s.is_empty() || s.len() > MAX_DATE {
        return None;
    }
    if let Some(t) = parse_http_date(s) {
        return Some(t);
    }
    // RFC 3339, with or without a zone, as feeds' `picket-first-seen` reads it: it refuses the
    // extra forms jiff's own reader takes, as chrono's did.
    if let Some(t) = picket_rules::formats::parse_rfc3339(s) {
        return Some(t);
    }
    let mut t = s.to_string();
    for zone in [" UTC", " GMT", "Z", " (UTC)", " +0000", "+00:00"] {
        if let Some(stripped) = t.strip_suffix(zone) {
            t = stripped.trim().to_string();
            break;
        }
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%d %b %Y %H:%M:%S",
        "%d %b %Y %H:%M",
        "%a, %d %b %Y %H:%M:%S",
        "%a %d %b %Y %H:%M:%S",
        "%d %B %Y %H:%M:%S",
        "%d %B %Y %H:%M",
        "%B %d, %Y %H:%M:%S",
        // jiff's `%B` takes only full month names (chrono's took `Nov` too).
        "%b %d, %Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%d.%m.%Y %H:%M:%S",
        "%d.%m.%Y %H:%M",
    ] {
        if let Ok(v) = civil::DateTime::strptime(fmt, &t) {
            return Offset::UTC.to_timestamp(v).ok();
        }
    }
    for fmt in [
        "%Y-%m-%d",
        "%d %b %Y",
        "%d %B %Y",
        "%B %d, %Y",
        "%b %d, %Y",
        "%Y/%m/%d",
        "%d.%m.%Y",
    ] {
        if let Ok(d) = civil::Date::strptime(fmt, &t) {
            return Offset::UTC
                .to_timestamp(d.to_datetime(civil::Time::midnight()))
                .ok();
        }
    }
    None
}

/// The header words a date line starts with, after its comment marker.
const DATE_LINE_WORDS: &[&str] = &[
    "last modified",
    "last-modified",
    "lastmodified",
    "last updated",
    "updated",
    "last update",
    "date",
    "timestamp",
    "generated",
    "version",
];

/// Finds a date line in the head of a list (the first [`DATE_LINE_SCAN_LINES`] lines of
/// `head`). With `regex`, the first match's first capture group (or the whole match) is the
/// date; else a comment line (`!`, `#`, `;`, `//`) whose text starts with one of the usual
/// words, then `:` or `=`, then a date.
pub fn find_date_line(head: &[u8], regex: Option<&regex::Regex>) -> Option<Timestamp> {
    let text = String::from_utf8_lossy(head);
    for line in text.lines().take(DATE_LINE_SCAN_LINES) {
        let line = line.trim();
        if line.len() > 512 {
            continue;
        }
        if let Some(re) = regex {
            if let Some(c) = re.captures(line) {
                let m = c.get(1).or_else(|| c.get(0))?;
                if let Some(t) = parse_loose_date(m.as_str()) {
                    return Some(t);
                }
            }
            continue;
        }
        let Some(body) = line
            .strip_prefix("//")
            .or_else(|| line.strip_prefix('!'))
            .or_else(|| line.strip_prefix('#'))
            .or_else(|| line.strip_prefix(';'))
        else {
            continue;
        };
        let body = body.trim();
        let lower = body.to_ascii_lowercase();
        for w in DATE_LINE_WORDS {
            if let Some(rest) = lower.strip_prefix(w) {
                let rest = rest.trim_start();
                let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) else {
                    continue;
                };
                // The same span of the original (case kept for month names).
                let start = body.len() - rest.len();
                if let Some(t) = body.get(start..).and_then(parse_loose_date) {
                    return Some(t);
                }
            }
        }
    }
    None
}

/// The longest server cooldown honoured (`Retry-After`, GitHub's `x-ratelimit-reset`): a week.
/// Any valid deadline up to it is kept whole, however far past an hour; a later one is held to
/// it ([`bound_cooldown`]), so a bad header can't park a provider for good.
pub const MAX_COOLDOWN: jiff::SignedDuration = jiff::SignedDuration::from_hours(7 * 24);

/// `Retry-After` (RFC 9110 §10.2.3) as the deadline it names: delta-seconds (ASCII digits only;
/// more than fit in 64 bits saturate) after `now`, or an HTTP date ([`parse_http_date`]).
/// Unbounded and possibly not after `now`: [`bound_cooldown`] makes it a wait. `None` for
/// anything else (a sign, a fraction, junk, more than [`MAX_DATE`] bytes).
pub fn retry_after(v: &str, now: Timestamp) -> Option<Timestamp> {
    let v = v.trim();
    if v.is_empty() || v.len() > MAX_DATE {
        return None;
    }
    if v.bytes().all(|b| b.is_ascii_digit()) {
        let secs = v.parse::<u64>().unwrap_or(u64::MAX);
        let d = jiff::SignedDuration::from_secs(crate::util::sat_i64(secs));
        return Some(picket_api::time::saturating_add(now, d));
    }
    parse_http_date(v)
}

/// A server's cooldown deadline as a wait from `now`: `None` when it isn't after `now` (nothing
/// to wait for: the ordinary error backoff applies), else the deadline, held to at most
/// [`MAX_COOLDOWN`] after `now`.
pub fn bound_cooldown(until: Timestamp, now: Timestamp) -> Option<Timestamp> {
    (until > now).then(|| until.min(picket_api::time::saturating_add(now, MAX_COOLDOWN)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(y: i16, m: i8, d: i8, h: i8, mi: i8, s: i8) -> Timestamp {
        Offset::UTC
            .to_timestamp(civil::datetime(y, m, d, h, mi, s, 0))
            .unwrap()
    }

    #[test]
    fn http_dates() {
        let t = utc(1994, 11, 6, 8, 49, 37);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(t));
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), Some(t));
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(t));
        assert_eq!(parse_http_date("yesterday"), None);
        assert_eq!(parse_http_date(&"9".repeat(200)), None);
    }

    #[test]
    fn date_lines() {
        let t = utc(2026, 11, 20, 14, 5, 0);
        for head in [
            "! Title: x\n! Last modified: 2026-11-20T14:05:00Z\n||a.example^\n",
            "# Updated : 2026-11-20 14:05 UTC\n0.0.0.0 a.example\n",
            "! Last modified: 20 Nov 2026 14:05 UTC\n",
            "[Adblock Plus]\n! Version: 2026-11-20 14:05:00\n",
            "# Date: Fri, 20 Nov 2026 14:05:00 GMT\n",
        ] {
            assert_eq!(find_date_line(head.as_bytes(), None), Some(t), "{head}");
        }
        assert_eq!(find_date_line(b"! Title: no date here\n||a^\n", None), None);
        assert_eq!(
            find_date_line(b"! Updated: 2026-11-20\n", None),
            Some(utc(2026, 11, 20, 0, 0, 0))
        );
        let re = regex::Regex::new(r"^# Generated on (.+)$").unwrap();
        assert_eq!(
            find_date_line(b"# Generated on 2026-11-20 14:05\n", Some(&re)),
            Some(t)
        );
        // Not past the scanned head.
        let mut long = "! c\n".repeat(100);
        long.push_str("! Last modified: 2026-11-20T14:05:00Z\n");
        assert_eq!(find_date_line(long.as_bytes(), None), None);
        // Bytes that aren't UTF-8 don't stop the scan.
        assert_eq!(
            find_date_line(b"\xff\xfe\n! Updated: 2026-11-20T14:05:00Z\n", None),
            Some(t)
        );
    }

    #[test]
    fn retry_after_forms() {
        let now = utc(2026, 1, 1, 0, 0, 0);
        assert_eq!(retry_after("120", now), Some(utc(2026, 1, 1, 0, 2, 0)));
        assert_eq!(
            retry_after("Thu, 01 Jan 2026 00:10:00 GMT", now),
            Some(utc(2026, 1, 1, 0, 10, 0))
        );
        assert_eq!(retry_after("soon", now), None);
        assert_eq!(retry_after("+5", now), None, "digits only");
        assert_eq!(retry_after("1.5", now), None);
        // Longer than an hour: kept whole.
        assert_eq!(retry_after("7200", now), Some(utc(2026, 1, 1, 2, 0, 0)));
    }

    #[test]
    fn cooldowns_are_bounded() {
        let now = utc(2026, 1, 1, 0, 0, 0);
        let h3 = utc(2026, 1, 1, 3, 0, 0);
        assert_eq!(bound_cooldown(h3, now), Some(h3), "a 3 h wait is kept whole");
        assert_eq!(bound_cooldown(now, now), None, "nothing to wait for");
        assert_eq!(bound_cooldown(utc(2025, 12, 31, 0, 0, 0), now), None);
        assert_eq!(
            bound_cooldown(Timestamp::MAX, now),
            Some(utc(2026, 1, 8, 0, 0, 0)),
            "at most a week"
        );
        let huge = retry_after("99999999999999999999999", now).unwrap();
        assert_eq!(huge, Timestamp::MAX, "saturates, never wraps");
        assert_eq!(bound_cooldown(huge, now), Some(utc(2026, 1, 8, 0, 0, 0)));
    }

    fn f1(t: Option<picket_api::time::Timestamp>) -> Option<String> {
        t.as_ref().map(picket_api::time::format_micros)
    }

    /// Golden (untrusted dates; plan §5 step 1): each input and the instant read, as F1,
    /// recorded from chrono; unchanged after the move to jiff (`Nov 13, 2026` needs `%b` formats
    /// there: jiff's `%B` takes only full month names).
    #[test]
    fn golden_date_corpus() {
        const HTTP: &[(&str, Option<&str>)] = &[
            (
                "Sun, 06 Nov 1994 08:49:37 GMT",
                Some("1994-11-06T08:49:37.000000Z"),
            ),
            (
                "Sunday, 06-Nov-94 08:49:37 GMT",
                Some("1994-11-06T08:49:37.000000Z"),
            ),
            ("Sun Nov  6 08:49:37 1994", Some("1994-11-06T08:49:37.000000Z")),
            ("Sun Nov 6 08:49:37 1994", Some("1994-11-06T08:49:37.000000Z")),
            (
                "Fri, 13 Nov 2026 10:22:01 GMT",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            (
                "  Fri, 13 Nov 2026 10:22:01 GMT  ",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            (
                "Fri, 13 Nov 2026 10:22:01 +0000",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            (
                "Fri, 13 Nov 2026 12:22:01 +0200",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            ("13 Nov 2026 10:22:01 GMT", Some("2026-11-13T10:22:01.000000Z")),
            (
                "Fri, 13 Nov 2026 10:22:01 UT",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            (
                "Fri, 13 Nov 2026 05:22:01 EST",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            (
                "Fri, 13 Nov 2026 03:22:01 PDT",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            ("Fri, 13 Nov 2026 10:22:01 Z", Some("2026-11-13T10:22:01.000000Z")),
            ("Fri, 13 Nov 26 10:22:01 GMT", Some("2026-11-13T10:22:01.000000Z")),
            ("Fri, 13 Nov 2026 10:22 GMT", Some("2026-11-13T10:22:00.000000Z")),
            (
                "Fri, 13 Nov 2026 10:22:01 GMT (comment)",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            (
                "fri, 13 nov 2026 10:22:01 gmt",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            (
                "Friday, 13-Nov-26 10:22:01 GMT",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            (
                "Thursday, 01-Jan-70 00:00:00 GMT",
                Some("1970-01-01T00:00:00.000000Z"),
            ),
            ("Fri Nov 13 10:22:01 2026", Some("2026-11-13T10:22:01.000000Z")),
            ("Sat, 13 Nov 2026 10:22:01 GMT", None),
            ("Sat Nov 13 10:22:01 2026", None),
            ("Fri, 32 Nov 2026 10:22:01 GMT", None),
            ("Fri, 13 Foo 2026 10:22:01 GMT", None),
            ("Fri, 13 Nov 2026 10:22:01", None),
            ("", None),
            ("garbage", None),
            ("2026-11-13T10:22:01Z", None),
            ("Sunday, 06-Nov-94 08:49:37 UTC", None),
            (
                "Fri, 13 Nov 2026 10:22:01 GMT plus a very long tail that goes on and on past eighty bytes ...",
                None,
            ),
        ];
        for (input, want) in HTTP {
            assert_eq!(f1(parse_http_date(input)).as_deref(), *want, "{input:?}");
        }
        const LOOSE: &[(&str, Option<&str>)] = &[
            ("2026-11-13T10:22:01Z", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13T10:22:01.5+01:00", Some("2026-11-13T09:22:01.500000Z")),
            (
                "2026-11-13T10:22:01.123456789Z",
                Some("2026-11-13T10:22:01.123456Z"),
            ),
            ("2026-11-13 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13 10:22", Some("2026-11-13T10:22:00.000000Z")),
            ("2026-11-13 10:22 UTC", Some("2026-11-13T10:22:00.000000Z")),
            ("2026-11-13 10:22:01 GMT", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13 10:22:01 +0000", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13T10:22:01+00:00", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13T10:22", Some("2026-11-13T10:22:00.000000Z")),
            ("2026-11-13T10:22Z", Some("2026-11-13T10:22:00.000000Z")),
            ("2026-11-13T10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("2026-11-13t10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("13 Nov 2026 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("13 Nov 2026 10:22 UTC", Some("2026-11-13T10:22:00.000000Z")),
            ("13 nov 2026 10:22", Some("2026-11-13T10:22:00.000000Z")),
            ("13 November 2026 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("13 November 2026 10:22", Some("2026-11-13T10:22:00.000000Z")),
            ("13 November 2026", Some("2026-11-13T00:00:00.000000Z")),
            ("13 Nov 2026", Some("2026-11-13T00:00:00.000000Z")),
            ("November 13, 2026 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("November 13, 2026", Some("2026-11-13T00:00:00.000000Z")),
            ("Nov 13, 2026", Some("2026-11-13T00:00:00.000000Z")),
            ("Nov 13, 2026 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("2026/11/13 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("2026/11/13 10:22", Some("2026-11-13T10:22:00.000000Z")),
            ("2026/11/13", Some("2026-11-13T00:00:00.000000Z")),
            ("13.11.2026 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("13.11.2026 10:22", Some("2026-11-13T10:22:00.000000Z")),
            ("13.11.2026", Some("2026-11-13T00:00:00.000000Z")),
            ("2026-11-13", Some("2026-11-13T00:00:00.000000Z")),
            ("(2026-11-13)", Some("2026-11-13T00:00:00.000000Z")),
            ("\"2026-11-13 10:22:01\"", Some("2026-11-13T10:22:01.000000Z")),
            ("'2026-11-13'", Some("2026-11-13T00:00:00.000000Z")),
            ("Fri, 13 Nov 2026 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            ("Fri 13 Nov 2026 10:22:01", Some("2026-11-13T10:22:01.000000Z")),
            (
                "Fri, 13 Nov 2026 10:22:01 GMT",
                Some("2026-11-13T10:22:01.000000Z"),
            ),
            ("Sun Nov  6 08:49:37 1994", Some("1994-11-06T08:49:37.000000Z")),
            ("2026-11-31", None),
            ("2026-11-13 25:00", None),
            ("yesterday", None),
            ("", None),
            ("  ", None),
            ("20261113", None),
            ("2026-11-13 10:22:01 PST", None),
        ];
        for (input, want) in LOOSE {
            assert_eq!(f1(parse_loose_date(input)).as_deref(), *want, "{input:?}");
        }
        let now = picket_api::time::golden::ts_from_nanos(1_794_565_321_000_000_000);
        for (input, want) in [
            ("120", Some("2026-11-13T10:24:01.000000Z")),
            (" 7 ", Some("2026-11-13T10:22:08.000000Z")),
            ("100000", Some("2026-11-14T14:08:41.000000Z")),
            (
                "Fri, 13 Nov 2026 10:22:31 GMT",
                Some("2026-11-13T10:22:31.000000Z"),
            ),
            (
                "Fri, 13 Nov 2026 10:00:00 GMT",
                Some("2026-11-13T10:00:00.000000Z"),
            ),
            ("-1", None),
            ("+1", None),
            ("soon", None),
        ] {
            assert_eq!(f1(retry_after(input, now)).as_deref(), want, "{input:?}");
        }
    }
}
