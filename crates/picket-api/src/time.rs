//! Timestamps: RFC 3339 with microseconds, UTC (api.md §5).
//!
//! [`Timestamp`] is jiff's, built without its serde feature: a serialized timestamp field names
//! one of the adapters below ([`micros`], [`micros_opt`], [`autosi`], [`autosi_opt`]), so none
//! takes jiff's own form, which trims trailing zeros and matches neither stored form (README §2
//! "Compatibility": what N−1 stored or sent stays byte-identical). Every picket time is UTC; jiff
//! is built without a time-zone database.

use std::fmt::{self, Write as _};

pub use jiff::{SignedDuration, Timestamp};

#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod golden;

/// Formats a timestamp as RFC 3339 with exactly six fractional digits (truncated, never rounded)
/// and a `Z` suffix: the storage and wire form (api.md §5).
pub fn format_micros(ts: &Timestamp) -> String {
    // `YYYY-MM-DDTHH:MM:SS.ffffffZ`: one allocation.
    let mut s = String::with_capacity(27);
    // Writing into a `String` can't fail.
    let _ = write!(s, "{ts:.6}");
    s
}

/// Formats a timestamp as RFC 3339 in whole seconds with a `Z` suffix (the helper's
/// `last_repair`, api.md §4; GitHub's `since` parameter).
pub fn format_secs(ts: &Timestamp) -> String {
    format!("{ts:.0}")
}

/// The form chrono's default serde wrote, kept for the JSON that has always used it (the
/// download modules' states in `feed_state.last_json`, verdict delta lines): RFC 3339 with 0, 3,
/// 6 or 9 fractional digits, the fewest that hold the instant exactly, and `Z`.
pub fn format_autosi(ts: &Timestamp) -> String {
    AutoSi(*ts).to_string()
}

/// [`format_autosi`] as a `Display`, for writing without an intermediate `String`.
struct AutoSi(Timestamp);

impl fmt::Display for AutoSi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.0;
        let ns = t.subsec_nanosecond();
        if ns == 0 {
            write!(f, "{t:.0}")
        } else if ns % 1_000_000 == 0 {
            write!(f, "{t:.3}")
        } else if ns % 1_000 == 0 {
            write!(f, "{t:.6}")
        } else {
            write!(f, "{t:.9}")
        }
    }
}

/// Why [`parse`] refused a timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Not RFC 3339 date-time text as chrono read it, or no such date or time.
    Invalid,
    /// A real date and time past the end of the timestamp range
    /// (9999-12-30T22:00:00.999999999Z): chrono read those, a [`Timestamp`] can't hold them.
    OutOfRange,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseError::Invalid => "not an RFC 3339 timestamp",
            ParseError::OutOfRange => "an RFC 3339 timestamp past 9999-12-30T22:00:00.999999999Z",
        })
    }
}

impl std::error::Error for ParseError {}

/// Reads RFC 3339 date-time text (§5.6) exactly as chrono's `parse_from_rfc3339` did, so every
/// stored or received timestamp reads as before and nothing more is accepted (README §2
/// "Compatibility", "Untrusted input"): `YYYY-MM-DD`, `T`, `t` or a space, `HH:MM:SS`, an
/// optional `.` and digits (those past the ninth dropped), then `Z`, `z` or `±HH:MM` up to
/// ±23:59 (U+2212 `−` is a minus too). A leap second (`:60`) reads as `:59`.
///
/// jiff's own reader also takes `T10:22Z`, `+0200`, `+02`, `,5`, `[…]` annotations, the basic
/// format, signed six-digit years and offsets to ±25:59, so it never reads stored or received
/// text.
pub fn parse(s: &str) -> Result<Timestamp, ParseError> {
    let (dt, offset) = parse_parts(s.as_bytes()).ok_or(ParseError::Invalid)?;
    offset.to_timestamp(dt).map_err(|_| ParseError::OutOfRange)
}

/// The civil date-time and offset of RFC 3339 text in chrono's profile ([`parse`]).
fn parse_parts(b: &[u8]) -> Option<(jiff::civil::DateTime, jiff::tz::Offset)> {
    // The number in `b[at..at + len]`, all ASCII digits.
    let num = |at: usize, len: usize| -> Option<i32> {
        b.get(at..at + len)?.iter().try_fold(0i32, |n, c| {
            c.is_ascii_digit().then(|| n * 10 + i32::from(c - b'0'))
        })
    };
    let at = |i: usize| b.get(i).copied();
    let year = i16::try_from(num(0, 4)?).ok()?;
    let month = i8::try_from(num(5, 2)?).ok()?;
    let day = i8::try_from(num(8, 2)?).ok()?;
    let hour = i8::try_from(num(11, 2)?).ok()?;
    let minute = i8::try_from(num(14, 2)?).ok()?;
    let second = i8::try_from(num(17, 2)?).ok()?;
    let shaped = at(4) == Some(b'-')
        && at(7) == Some(b'-')
        && matches!(at(10), Some(b'T' | b't' | b' '))
        && at(13) == Some(b':')
        && at(16) == Some(b':');
    if !shaped || second > 60 {
        return None;
    }
    let mut i = 19;
    let mut nanos = 0i32;
    if at(i) == Some(b'.') {
        let digits = b.get(i + 1..)?.iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        // The first nine digits, as nanoseconds; chrono dropped the rest.
        let kept = digits.min(9);
        nanos = num(i + 1, kept)?;
        for _ in kept..9 {
            nanos *= 10;
        }
        i += 1 + digits;
    }
    let rest = b.get(i..)?;
    let offset_secs = match rest {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => offset_secs(*sign == b'-', [*h1, *h2, *m1, *m2])?,
        // U+2212 MINUS SIGN.
        [0xe2, 0x88, 0x92, h1, h2, b':', m1, m2] => offset_secs(true, [*h1, *h2, *m1, *m2])?,
        _ => return None,
    };
    let dt = jiff::civil::DateTime::new(year, month, day, hour, minute, second.min(59), nanos).ok()?;
    let offset = jiff::tz::Offset::from_seconds(offset_secs).ok()?;
    Some((dt, offset))
}

/// An offset's seconds from its `HHMM` digits: at most 23:59, as RFC 3339's `time-numoffset`.
fn offset_secs(negative: bool, hhmm: [u8; 4]) -> Option<i32> {
    if !hhmm.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let [h1, h2, m1, m2] = hhmm.map(|c| i32::from(c - b'0'));
    let (hours, minutes) = (h1 * 10 + h2, m1 * 10 + m2);
    if hours > 23 || minutes > 59 {
        return None;
    }
    let secs = hours * 3600 + minutes * 60;
    Some(if negative { -secs } else { secs })
}

/// Clamps a received timestamp to the receiver's clock (README §2, Untrusted input): never later
/// than `now`.
pub fn clamp_to_now(ts: Timestamp, now: Timestamp) -> Timestamp {
    if ts > now { now } else { ts }
}

/// `ts + d`, saturating at the ends of the timestamp range. jiff's range ends at
/// 9999-12-30T22:00:00.999999999Z, so a long duration from config, input or storage overflows
/// where it didn't under chrono; `+` would panic.
pub fn saturating_add(ts: Timestamp, d: SignedDuration) -> Timestamp {
    ts.checked_add(d).unwrap_or(if d.is_negative() {
        Timestamp::MIN
    } else {
        Timestamp::MAX
    })
}

/// `ts - d`, saturating at the ends of the timestamp range (see [`saturating_add`]).
pub fn saturating_sub(ts: Timestamp, d: SignedDuration) -> Timestamp {
    ts.checked_sub(d).unwrap_or(if d.is_negative() {
        Timestamp::MAX
    } else {
        Timestamp::MIN
    })
}

/// Deserializes an RFC 3339 string through [`parse`] without copying it.
struct Rfc3339;

impl serde::de::Visitor<'_> for Rfc3339 {
    type Value = Timestamp;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an RFC 3339 timestamp")
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Timestamp, E> {
        parse(s).map_err(E::custom)
    }
}

/// A timestamp read as RFC 3339, for the `Option` adapters.
struct Read(Timestamp);

impl<'de> serde::Deserialize<'de> for Read {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_str(Rfc3339).map(Read)
    }
}

/// Serde adapter writing a [`Timestamp`] as RFC 3339 with microseconds ([`format_micros`]).
pub mod micros {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ts: &Timestamp, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&format_args!("{ts:.6}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Timestamp, D::Error> {
        de.deserialize_str(Rfc3339)
    }
}

/// Serde adapter for `Option<Timestamp>` written as RFC 3339 with microseconds, or `null`.
pub mod micros_opt {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ts: &Option<Timestamp>, ser: S) -> Result<S::Ok, S::Error> {
        match ts {
            Some(t) => super::micros::serialize(t, ser),
            None => ser.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Timestamp>, D::Error> {
        Ok(Option::<Read>::deserialize(de)?.map(|r| r.0))
    }
}

/// Serde adapter writing a [`Timestamp`] in chrono's default serde form ([`format_autosi`]).
pub mod autosi {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ts: &Timestamp, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&AutoSi(*ts))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Timestamp, D::Error> {
        de.deserialize_str(Rfc3339)
    }
}

/// Serde adapter for `Option<Timestamp>` in chrono's default serde form, or `null`.
pub mod autosi_opt {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ts: &Option<Timestamp>, ser: S) -> Result<S::Ok, S::Error> {
        match ts {
            Some(t) => super::autosi::serialize(t, ser),
            None => ser.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Timestamp>, D::Error> {
        Ok(Option::<Read>::deserialize(de)?.map(|r| r.0))
    }
}

#[cfg(test)]
mod tests {
    use super::golden::{PARSE_OK, PARSE_REJECTED, ROWS, ts_from_nanos};
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Stored {
        #[serde(with = "micros")]
        at: Timestamp,
        #[serde(with = "micros_opt")]
        maybe: Option<Timestamp>,
    }

    fn read(at: &str) -> Result<Stored, serde_json::Error> {
        let json = serde_json::json!({ "at": at, "maybe": at });
        serde_json::from_value(json)
    }

    /// Golden (F1, F3; plan §5 step 1, unchanged after the move to jiff): the written forms,
    /// truncated to microseconds or seconds, never rounded.
    #[test]
    fn golden_written_forms() {
        for r in ROWS {
            let t = ts_from_nanos(r.nanos);
            assert_eq!(format_micros(&t), r.micros, "{}", r.name);
            assert_eq!(format_secs(&t), r.secs, "{}", r.name);
            assert_eq!(clamp_to_now(t, t), t, "{}", r.name);
        }
    }

    /// Golden (F1 through serde): the adapters write F1 and `null`, and read it back as the
    /// instant truncated to microseconds; they also read every F2 form at full precision.
    #[test]
    fn golden_serde_adapters() {
        for r in ROWS {
            let t = ts_from_nanos(r.nanos);
            let truncated = ts_from_nanos(r.nanos - r.nanos.rem_euclid(1_000));
            let json = serde_json::to_string(&Stored {
                at: t,
                maybe: Some(t),
            })
            .unwrap();
            assert_eq!(
                json,
                format!(r#"{{"at":"{0}","maybe":"{0}"}}"#, r.micros),
                "{}",
                r.name
            );
            let back: Stored = serde_json::from_str(&json).unwrap();
            assert_eq!((back.at, back.maybe), (truncated, Some(truncated)), "{}", r.name);
            let none = serde_json::to_string(&Stored { at: t, maybe: None }).unwrap();
            assert_eq!(
                none,
                format!(r#"{{"at":"{}","maybe":null}}"#, r.micros),
                "{}",
                r.name
            );
            let back: Stored = serde_json::from_str(&none).unwrap();
            assert_eq!(back.maybe, None, "{}", r.name);
            let full = read(r.autosi).unwrap();
            assert_eq!((full.at, full.maybe), (t, Some(t)), "{}", r.name);
        }
    }

    /// Golden (reading RFC 3339): what the adapters accept and refuse.
    #[test]
    fn golden_parse() {
        for (input, want) in PARSE_OK {
            let got = read(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
            assert_eq!(format_micros(&got.at), *want, "{input:?}");
            assert_eq!(
                got.maybe.as_ref().map(format_micros).as_deref(),
                Some(*want),
                "{input:?}"
            );
        }
        for input in PARSE_REJECTED {
            assert!(read(input).is_err(), "{input:?}");
            let opt: Result<Option<Timestamp>, _> = micros_opt::deserialize(
                &mut serde_json::Deserializer::from_str(&serde_json::to_string(input).unwrap()),
            );
            assert!(opt.is_err(), "{input:?}");
        }
    }

    /// F2 (chrono's default serde form, kept for the JSON that always used it): the writer and
    /// the adapters against the golden table.
    #[test]
    fn autosi_writes_the_golden_form() {
        #[derive(Debug, Serialize, Deserialize)]
        struct Auto {
            #[serde(with = "autosi")]
            at: Timestamp,
            #[serde(with = "autosi_opt")]
            maybe: Option<Timestamp>,
        }
        for r in ROWS {
            let t = ts_from_nanos(r.nanos);
            assert_eq!(format_autosi(&t), r.autosi, "{}", r.name);
            let json = serde_json::to_string(&Auto {
                at: t,
                maybe: Some(t),
            })
            .unwrap();
            assert_eq!(
                json,
                format!(r#"{{"at":"{0}","maybe":"{0}"}}"#, r.autosi),
                "{}",
                r.name
            );
            let back: Auto = serde_json::from_str(&json).unwrap();
            assert_eq!((back.at, back.maybe), (t, Some(t)), "{}", r.name);
            let none = serde_json::to_string(&Auto { at: t, maybe: None }).unwrap();
            assert_eq!(none, format!(r#"{{"at":"{}","maybe":null}}"#, r.autosi));
            let back: Auto = serde_json::from_str(&none).unwrap();
            assert_eq!(back.maybe, None, "{}", r.name);
        }
        let bad: Result<Auto, _> = serde_json::from_str(r#"{"at":1,"maybe":null}"#);
        assert!(bad.is_err());
    }

    /// `parse` tells a real instant past the range from text that isn't one, and reads a leap
    /// second as `:59`.
    #[test]
    fn parse_errors_and_leap_seconds() {
        assert_eq!(parse("9999-12-31T23:59:59Z"), Err(ParseError::OutOfRange));
        assert_eq!(parse("9999-12-30T22:00:01Z"), Err(ParseError::OutOfRange));
        assert_eq!(parse("2026-11-13T10:22Z"), Err(ParseError::Invalid));
        assert_eq!(parse("2026-02-29T00:00:00Z"), Err(ParseError::Invalid));
        assert_eq!(
            parse("2026-11-13T10:22:60.5Z")
                .as_ref()
                .map(format_micros)
                .as_deref(),
            Ok("2026-11-13T10:22:59.500000Z")
        );
    }

    /// `parse` reads what the serde adapters read.
    #[test]
    fn parse_reads_like_the_adapters() {
        for (input, want) in PARSE_OK {
            assert_eq!(format_micros(&parse(input).unwrap()), *want, "{input:?}");
        }
        for input in PARSE_REJECTED {
            assert!(parse(input).is_err(), "{input:?}");
        }
    }

    /// Arithmetic with a duration from config or input saturates at jiff's range ends instead of
    /// panicking.
    #[test]
    fn arithmetic_saturates_at_the_range_ends() {
        let t = ts_from_nanos(1_794_565_321_000_000_000);
        let one = SignedDuration::from_secs(1);
        assert_eq!(
            format_micros(&saturating_add(t, one)),
            "2026-11-13T10:22:02.000000Z"
        );
        assert_eq!(
            format_micros(&saturating_sub(t, one)),
            "2026-11-13T10:22:00.000000Z"
        );
        assert_eq!(saturating_add(t, SignedDuration::MAX), Timestamp::MAX);
        assert_eq!(saturating_add(t, SignedDuration::MIN), Timestamp::MIN);
        assert_eq!(saturating_sub(t, SignedDuration::MAX), Timestamp::MIN);
        assert_eq!(saturating_sub(t, SignedDuration::MIN), Timestamp::MAX);
        // 20,000 years: chrono's range held it, jiff's (years -9999 to 9999) doesn't.
        let long = SignedDuration::from_hours(24 * 366 * 20_000);
        assert_eq!(saturating_add(t, long), Timestamp::MAX);
        assert_eq!(saturating_sub(t, long), Timestamp::MIN);
    }
}
