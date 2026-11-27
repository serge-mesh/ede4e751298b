//! Golden timestamps for the compatibility tests of every stored or sent time format (README §2
//! "Compatibility": N reads what N−1 wrote and an edge rolled back to N−1 reads what N wrote, so
//! each written string stays byte-identical).
//!
//! Recorded from chrono 0.4.45 before the move to jiff (spec issue #340, plan
//! `dev/briefs/jiff-migration-plan.md` §3): the tests built on this table must pass unchanged
//! after it. Tests build their inputs only through [`ts_from_nanos`], the one function the move
//! rewrites, and compare formatted strings and integers, never library values.
//!
//! The format names (F1…F13) are the plan's. A row's instant is `nanos` after the Unix epoch;
//! every other field is what picket writes for it.

use super::Timestamp;

/// The timestamp `nanos` nanoseconds after the Unix epoch.
#[allow(
    clippy::expect_used,
    reason = "the golden tables only hold timestamps in range"
)]
pub fn ts_from_nanos(nanos: i128) -> Timestamp {
    Timestamp::from_nanosecond(nanos).expect("a golden timestamp in range")
}

/// One instant and every form picket writes it in.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub name: &'static str,
    /// Nanoseconds since the Unix epoch.
    pub nanos: i128,
    /// F1: RFC 3339, exactly 6 fractional digits, `Z`, truncated (api.md §5): SQLite TEXT, edge
    /// JSON files, the edge↔core protocol, log records, config export.
    pub micros: &'static str,
    /// F2: chrono's default serde form (0, 3, 6 or 9 digits, `Z`): `feed_state.last_json`, the
    /// download modules' states, verdict delta lines.
    pub autosi: &'static str,
    /// F3: RFC 3339 whole seconds, `Z`: the helper's `last_repair`, GitHub's `since`.
    pub secs: &'static str,
    /// F5: an hour, `%Y-%m-%dT%H`: log partition names, `log_progress.hour`.
    pub hour: &'static str,
    /// The start of that hour, as F1.
    pub hour_start: &'static str,
    /// F6: a day, `%Y-%m-%d`: lookup day counters, the config export's file name.
    pub day: &'static str,
    /// F7: `%Y%m%d%H%M`: a browser list's version.
    pub list_version: &'static str,
    /// F8: `%d %b %Y %H:%M UTC`: a browser list's `Last modified`.
    pub list_date: &'static str,
    /// F9: an HTTP date (RFC 9110 IMF-fixdate): `Last-Modified`.
    pub http_date: &'static str,
    /// F10: `%Y-%m-%d %H:%M`: the LAN CA's name.
    pub minute: &'static str,
    /// F11: Unix seconds, milliseconds and microseconds (truncated): INTEGER columns, the bypass
    /// API's `expires_at`, verdict records.
    pub unix_s: i64,
    pub unix_ms: i64,
    pub unix_us: i64,
    /// F13: seconds as `f64` (the feed scheduling model), and what reading it back gives, as F1.
    pub f64_secs: f64,
    pub f64_back: &'static str,
}

/// Epoch; whole seconds; every fraction length F1 truncates and F2 picks a width for; a leap day;
/// the end of 2099; the latest whole second jiff holds (9999-12-30T22:00:00Z).
pub const ROWS: &[Row] = &[
    Row {
        name: "epoch",
        nanos: 0,
        micros: "1970-01-01T00:00:00.000000Z",
        autosi: "1970-01-01T00:00:00Z",
        secs: "1970-01-01T00:00:00Z",
        hour: "1970-01-01T00",
        hour_start: "1970-01-01T00:00:00.000000Z",
        day: "1970-01-01",
        list_version: "197001010000",
        list_date: "01 Jan 1970 00:00 UTC",
        http_date: "Thu, 01 Jan 1970 00:00:00 GMT",
        minute: "1970-01-01 00:00",
        unix_s: 0,
        unix_ms: 0,
        unix_us: 0,
        f64_secs: 0.0,
        f64_back: "1970-01-01T00:00:00.000000Z",
    },
    Row {
        name: "whole",
        nanos: 1_794_565_321_000_000_000,
        micros: "2026-11-13T10:22:01.000000Z",
        autosi: "2026-11-13T10:22:01Z",
        secs: "2026-11-13T10:22:01Z",
        hour: "2026-11-13T10",
        hour_start: "2026-11-13T10:00:00.000000Z",
        day: "2026-11-13",
        list_version: "202611131022",
        list_date: "13 Nov 2026 10:22 UTC",
        http_date: "Fri, 13 Nov 2026 10:22:01 GMT",
        minute: "2026-11-13 10:22",
        unix_s: 1_794_565_321,
        unix_ms: 1_794_565_321_000,
        unix_us: 1_794_565_321_000_000,
        f64_secs: 1794565321.0,
        f64_back: "2026-11-13T10:22:01.000000Z",
    },
    Row {
        name: "ns9",
        nanos: 1_794_565_321_123_456_789,
        micros: "2026-11-13T10:22:01.123456Z",
        autosi: "2026-11-13T10:22:01.123456789Z",
        secs: "2026-11-13T10:22:01Z",
        hour: "2026-11-13T10",
        hour_start: "2026-11-13T10:00:00.000000Z",
        day: "2026-11-13",
        list_version: "202611131022",
        list_date: "13 Nov 2026 10:22 UTC",
        http_date: "Fri, 13 Nov 2026 10:22:01 GMT",
        minute: "2026-11-13 10:22",
        unix_s: 1_794_565_321,
        unix_ms: 1_794_565_321_123,
        unix_us: 1_794_565_321_123_456,
        f64_secs: 1794565321.123456,
        f64_back: "2026-11-13T10:22:01.123456Z",
    },
    Row {
        name: "us6",
        nanos: 1_794_565_321_123_456_000,
        micros: "2026-11-13T10:22:01.123456Z",
        autosi: "2026-11-13T10:22:01.123456Z",
        secs: "2026-11-13T10:22:01Z",
        hour: "2026-11-13T10",
        hour_start: "2026-11-13T10:00:00.000000Z",
        day: "2026-11-13",
        list_version: "202611131022",
        list_date: "13 Nov 2026 10:22 UTC",
        http_date: "Fri, 13 Nov 2026 10:22:01 GMT",
        minute: "2026-11-13 10:22",
        unix_s: 1_794_565_321,
        unix_ms: 1_794_565_321_123,
        unix_us: 1_794_565_321_123_456,
        f64_secs: 1794565321.123456,
        f64_back: "2026-11-13T10:22:01.123456Z",
    },
    Row {
        name: "ms120",
        nanos: 1_794_565_321_120_000_000,
        micros: "2026-11-13T10:22:01.120000Z",
        autosi: "2026-11-13T10:22:01.120Z",
        secs: "2026-11-13T10:22:01Z",
        hour: "2026-11-13T10",
        hour_start: "2026-11-13T10:00:00.000000Z",
        day: "2026-11-13",
        list_version: "202611131022",
        list_date: "13 Nov 2026 10:22 UTC",
        http_date: "Fri, 13 Nov 2026 10:22:01 GMT",
        minute: "2026-11-13 10:22",
        unix_s: 1_794_565_321,
        unix_ms: 1_794_565_321_120,
        unix_us: 1_794_565_321_120_000,
        f64_secs: 1794565321.12,
        f64_back: "2026-11-13T10:22:01.119999Z",
    },
    Row {
        name: "frac1234",
        nanos: 1_794_565_321_123_400_000,
        micros: "2026-11-13T10:22:01.123400Z",
        autosi: "2026-11-13T10:22:01.123400Z",
        secs: "2026-11-13T10:22:01Z",
        hour: "2026-11-13T10",
        hour_start: "2026-11-13T10:00:00.000000Z",
        day: "2026-11-13",
        list_version: "202611131022",
        list_date: "13 Nov 2026 10:22 UTC",
        http_date: "Fri, 13 Nov 2026 10:22:01 GMT",
        minute: "2026-11-13 10:22",
        unix_s: 1_794_565_321,
        unix_ms: 1_794_565_321_123,
        unix_us: 1_794_565_321_123_400,
        f64_secs: 1794565321.1234,
        f64_back: "2026-11-13T10:22:01.123399Z",
    },
    Row {
        name: "max_ns",
        nanos: 1_794_565_321_999_999_999,
        micros: "2026-11-13T10:22:01.999999Z",
        autosi: "2026-11-13T10:22:01.999999999Z",
        secs: "2026-11-13T10:22:01Z",
        hour: "2026-11-13T10",
        hour_start: "2026-11-13T10:00:00.000000Z",
        day: "2026-11-13",
        list_version: "202611131022",
        list_date: "13 Nov 2026 10:22 UTC",
        http_date: "Fri, 13 Nov 2026 10:22:01 GMT",
        minute: "2026-11-13 10:22",
        unix_s: 1_794_565_321,
        unix_ms: 1_794_565_321_999,
        unix_us: 1_794_565_321_999_999,
        f64_secs: 1794565321.999999,
        f64_back: "2026-11-13T10:22:01.999999Z",
    },
    Row {
        name: "one_ns",
        nanos: 1_794_565_321_000_000_001,
        micros: "2026-11-13T10:22:01.000000Z",
        autosi: "2026-11-13T10:22:01.000000001Z",
        secs: "2026-11-13T10:22:01Z",
        hour: "2026-11-13T10",
        hour_start: "2026-11-13T10:00:00.000000Z",
        day: "2026-11-13",
        list_version: "202611131022",
        list_date: "13 Nov 2026 10:22 UTC",
        http_date: "Fri, 13 Nov 2026 10:22:01 GMT",
        minute: "2026-11-13 10:22",
        unix_s: 1_794_565_321,
        unix_ms: 1_794_565_321_000,
        unix_us: 1_794_565_321_000_000,
        f64_secs: 1794565321.0,
        f64_back: "2026-11-13T10:22:01.000000Z",
    },
    Row {
        name: "half_us",
        nanos: 1_794_565_321_000_000_500,
        micros: "2026-11-13T10:22:01.000000Z",
        autosi: "2026-11-13T10:22:01.000000500Z",
        secs: "2026-11-13T10:22:01Z",
        hour: "2026-11-13T10",
        hour_start: "2026-11-13T10:00:00.000000Z",
        day: "2026-11-13",
        list_version: "202611131022",
        list_date: "13 Nov 2026 10:22 UTC",
        http_date: "Fri, 13 Nov 2026 10:22:01 GMT",
        minute: "2026-11-13 10:22",
        unix_s: 1_794_565_321,
        unix_ms: 1_794_565_321_000,
        unix_us: 1_794_565_321_000_000,
        f64_secs: 1794565321.0,
        f64_back: "2026-11-13T10:22:01.000000Z",
    },
    Row {
        name: "leap_day",
        nanos: 951_811_750_011_000_000,
        micros: "2000-02-29T08:09:10.011000Z",
        autosi: "2000-02-29T08:09:10.011Z",
        secs: "2000-02-29T08:09:10Z",
        hour: "2000-02-29T08",
        hour_start: "2000-02-29T08:00:00.000000Z",
        day: "2000-02-29",
        list_version: "200002290809",
        list_date: "29 Feb 2000 08:09 UTC",
        http_date: "Tue, 29 Feb 2000 08:09:10 GMT",
        minute: "2000-02-29 08:09",
        unix_s: 951_811_750,
        unix_ms: 951_811_750_011,
        unix_us: 951_811_750_011_000,
        f64_secs: 951811750.011,
        f64_back: "2000-02-29T08:09:10.011000Z",
    },
    Row {
        name: "end_2099",
        nanos: 4_102_444_799_000_001_000,
        micros: "2099-12-31T23:59:59.000001Z",
        autosi: "2099-12-31T23:59:59.000001Z",
        secs: "2099-12-31T23:59:59Z",
        hour: "2099-12-31T23",
        hour_start: "2099-12-31T23:00:00.000000Z",
        day: "2099-12-31",
        list_version: "209912312359",
        list_date: "31 Dec 2099 23:59 UTC",
        http_date: "Thu, 31 Dec 2099 23:59:59 GMT",
        minute: "2099-12-31 23:59",
        unix_s: 4_102_444_799,
        unix_ms: 4_102_444_799_000,
        unix_us: 4_102_444_799_000_001,
        f64_secs: 4102444799.000001,
        f64_back: "2099-12-31T23:59:59.000000Z",
    },
    Row {
        name: "jiff_max",
        nanos: 253_402_207_200_000_000_000,
        micros: "9999-12-30T22:00:00.000000Z",
        autosi: "9999-12-30T22:00:00Z",
        secs: "9999-12-30T22:00:00Z",
        hour: "9999-12-30T22",
        hour_start: "9999-12-30T22:00:00.000000Z",
        day: "9999-12-30",
        list_version: "999912302200",
        list_date: "30 Dec 9999 22:00 UTC",
        http_date: "Thu, 30 Dec 9999 22:00:00 GMT",
        minute: "9999-12-30 22:00",
        unix_s: 253_402_207_200,
        unix_ms: 253_402_207_200_000,
        unix_us: 253_402_207_200_000_000,
        f64_secs: 253402207200.0,
        f64_back: "9999-12-30T22:00:00.000000Z",
    },
];

/// RFC 3339 text every reader of a stored F1 timestamp accepts (core's `parse_ts`, the `micros`
/// serde adapters), and the instant it reads, as F1.
///
/// Left out on purpose: the leap second `:60` (chrono kept it, picket reads `:59`) and real
/// instants past 9999-12-30T22:00:00.999999999Z (chrono read them, a jiff `Timestamp` can't
/// hold them). picket never writes either.
pub const PARSE_OK: &[(&str, &str)] = &[
    ("2026-11-13T10:22:01Z", "2026-11-13T10:22:01.000000Z"),
    ("2026-11-13T10:22:01.120000Z", "2026-11-13T10:22:01.120000Z"),
    ("2026-11-13T10:22:01.123456789Z", "2026-11-13T10:22:01.123456Z"),
    ("2026-11-13T10:22:01.000000500Z", "2026-11-13T10:22:01.000000Z"),
    ("2026-11-13T10:22:01.1Z", "2026-11-13T10:22:01.100000Z"),
    ("2026-11-13t10:22:01z", "2026-11-13T10:22:01.000000Z"),
    ("2026-11-13 10:22:01Z", "2026-11-13T10:22:01.000000Z"),
    ("2026-11-13T12:22:01+02:00", "2026-11-13T10:22:01.000000Z"),
    ("2026-11-13T05:22:01.5-05:00", "2026-11-13T10:22:01.500000Z"),
    ("2026-11-13T10:22:01+00:00", "2026-11-13T10:22:01.000000Z"),
    ("2026-11-13T10:22:01-00:00", "2026-11-13T10:22:01.000000Z"),
    ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00.000000Z"),
    ("2000-02-29T08:09:10.011Z", "2000-02-29T08:09:10.011000Z"),
    ("9999-12-30T22:00:00Z", "9999-12-30T22:00:00.000000Z"),
    // Fraction digits past the ninth are dropped.
    ("2026-11-13T10:22:01.1234567891Z", "2026-11-13T10:22:01.123456Z"),
    (
        "2026-11-13T10:22:01.123456789123456Z",
        "2026-11-13T10:22:01.123456Z",
    ),
    // Offsets up to ±23:59, and U+2212 as a minus.
    ("2026-11-13T10:22:01+23:59", "2026-11-12T10:23:01.000000Z"),
    ("2026-11-13T10:22:01-23:59", "2026-11-14T10:21:01.000000Z"),
    ("2026-11-13T10:22:01.5+05:30", "2026-11-13T04:52:01.500000Z"),
    ("2026-11-13T10:22:01\u{2212}05:00", "2026-11-13T15:22:01.000000Z"),
];

/// RFC 3339 text those readers refuse. The second group is what jiff's own reader takes and
/// chrono refused.
pub const PARSE_REJECTED: &[&str] = &[
    "",
    "not a date",
    "2026-11-13",
    "2026-11-13T10:22:01",
    "2026-02-30T00:00:00Z",
    "2026-13-01T00:00:00Z",
    "2026-11-13T24:00:00Z",
    "2026-11-13T10:60:01Z",
    "2026-11-13T10:22:61Z",
    "2026-11-13T10:22:01.Z",
    "2026-11-13T10:22:01ZZ",
    "2026-11-13T10:22:01 Z",
    " 2026-11-13T10:22:01Z",
    "2026-11-13T10:22:01Z ",
    "2026-11-13T10:22:01.123456Z\n",
    "2026-11-13X10:22:01Z",
    "26-11-13T10:22:01Z",
    "2026-1-13T10:22:01Z",
    "10000-01-01T00:00:00Z",
    "2026-02-29T00:00:00Z",
    "2026-11-13T10:22:01 +05:30",
    "2026-11-13T10:22:01+05:00:00",
    "2026-11-13T10:22:01+23:60",
    // Accepted by jiff's reader, refused by chrono's.
    "2026-11-13T10:22Z",
    "2026-11-13T10Z",
    "2026-11-13T10:22:01+0200",
    "2026-11-13T10:22:01+02",
    "2026-11-13T10:22:01,5Z",
    "2026-11-13T10:22:01Z[UTC]",
    "20261113T102201Z",
    "-009999-01-02T01:59:59Z",
    "+002026-11-13T10:22:01Z",
    "2026-11-13T10:22:01+24:00",
    "2026-11-13T10:22:01-25:59",
];
