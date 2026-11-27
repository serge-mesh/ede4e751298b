//! `Retry-After` (RFC 9110 §10.2.3): delay-seconds or an HTTP-date (IMF-fixdate, and the
//! obsolete RFC 850 and asctime forms recipients must accept, §5.6.7). None or unreadable: `None`
//! (providers.md §5 `http_json`, 429 row).

use std::time::Duration;

use jiff::Timestamp;
use jiff::civil;
use jiff::tz::Offset;

/// The longest header value read.
const MAX_LEN: usize = 64;

/// The wait a `Retry-After` value asks for, measured from `now`. A date in the past is zero.
pub fn parse(value: &[u8], now: Timestamp) -> Option<Duration> {
    if value.len() > MAX_LEN {
        return None;
    }
    let s = std::str::from_utf8(value).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        // Big values are capped later (pause ≤ 1 h); an absurd length isn't a number.
        return s.parse::<u64>().ok().map(Duration::from_secs);
    }
    let date = parse_http_date(s)?;
    Some(Duration::try_from(date.duration_since(now)).unwrap_or(Duration::ZERO))
}

fn parse_http_date(s: &str) -> Option<Timestamp> {
    // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
    // RFC 850:     "Sunday, 06-Nov-94 08:49:37 GMT"
    // asctime:     "Sun Nov  6 08:49:37 1994"
    const FORMATS: [&str; 3] = [
        "%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
    ];
    // jiff's strptime takes the format first.
    let dt = FORMATS
        .iter()
        .find_map(|f| civil::DateTime::strptime(f, s).ok())?;
    Offset::UTC.to_timestamp(dt).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        "1994-11-06T08:49:00Z".parse::<Timestamp>().unwrap()
    }

    #[test]
    fn seconds_and_dates() {
        assert_eq!(parse(b"120", now()), Some(Duration::from_secs(120)));
        assert_eq!(parse(b" 0 ", now()), Some(Duration::ZERO));
        let in_37 = Some(Duration::from_secs(37));
        assert_eq!(parse(b"Sun, 06 Nov 1994 08:49:37 GMT", now()), in_37);
        assert_eq!(parse(b"Sunday, 06-Nov-94 08:49:37 GMT", now()), in_37);
        assert_eq!(parse(b"Sun Nov  6 08:49:37 1994", now()), in_37);
        assert_eq!(
            parse(b"Sat, 05 Nov 1994 08:49:37 GMT", now()),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn unreadable_is_none() {
        for bad in [
            &b""[..],
            b"soon",
            b"-5",
            b"1.5",
            b"99999999999999999999999",
            b"Sun, 06 Nov 1994 08:49:37 PST",
            b"\xff\xfe",
        ] {
            assert_eq!(parse(bad, now()), None, "{bad:?}");
        }
    }

    /// Golden (plan §5 step 1): each `Retry-After` value and the wait it gives, in seconds, from
    /// 1994-11-06T08:49:00Z; recorded from chrono, unchanged after the move to jiff.
    #[test]
    fn golden_corpus() {
        let now = picket_api::time::golden::ts_from_nanos(784_111_740_000_000_000);
        const CORPUS: &[(&str, Option<u64>)] = &[
            ("120", Some(120)),
            (" 0 ", Some(0)),
            ("Sun, 06 Nov 1994 08:49:37 GMT", Some(37)),
            ("Sunday, 06-Nov-94 08:49:37 GMT", Some(37)),
            ("Sun Nov  6 08:49:37 1994", Some(37)),
            ("Sun Nov 6 08:49:37 1994", Some(37)),
            ("Sun, 06 Nov 1994 08:48:00 GMT", Some(0)),
            ("Sun, 06 Nov 1994 08:49:37 +0000", None),
            ("Mon, 06 Nov 1994 08:49:37 GMT", None),
            ("Sun, 06 Nov 1994 08:49:37.5 GMT", None),
            ("Sun, 06 Nov 1994 09:49:00 GMT", Some(3600)),
            ("Wed, 07 Dec 1994 08:49:00 GMT", Some(2678400)),
            ("sun, 06 nov 1994 08:49:37 GMT", Some(37)),
            ("-5", None),
            ("1.5", None),
            ("", None),
            ("99999999999999999999", None),
            ("18446744073709551615", Some(u64::MAX)),
            (
                "Sun, 06 Nov 1994 08:49:37 GMT                                    x",
                None,
            ),
            ("tomorrow", None),
        ];
        for (input, want) in CORPUS {
            assert_eq!(
                parse(input.as_bytes(), now),
                want.map(Duration::from_secs),
                "{input:?}"
            );
        }
    }
}
