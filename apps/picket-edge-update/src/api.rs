//! The files the updater shares with picket-edge (edge.md §14, edge-unifi.md §2), mirrored from
//! `picket_api::update` so the root updater doesn't link picket-api's dependencies (jiff,
//! blake3, rand, sha2, schemars; build-and-test.md §4). `tests::mirror` checks that both
//! serialise identically and read each other's output.
//!
//! JSON compatibility (README §2): fields are only ever added, every field has a default and
//! unknown fields are ignored.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// `<data_dir>/releases/pending.json`, written by the unprivileged edge. Untrusted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pending {
    pub version: String,
    /// The `install_now` id the edge acts on, or `None`.
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rollback: bool,
}

/// `ok` or `failed`, as in `picket_api::session::Outcome`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    #[default]
    Ok,
    Failed,
}

/// `bin/update-result.json`, written by the updater (`root:picket`, 0640).
///
/// `at` is kept as the RFC 3339 string (microseconds, `Z`) that `picket_api::time::micros`
/// writes and reads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateResult {
    pub result_id: String,
    pub request_id: Option<String>,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub version: String,
    pub at: String,
}

/// Update failure stages (`picket_api::update::stage`).
pub mod stage {
    pub const VERIFY: &str = "verify";
    pub const UNITS: &str = "units";
    pub const READINESS: &str = "readiness";
    pub const ROLLBACK: &str = "rollback";
    pub const LOCKED: &str = "locked";
    pub const SUPERSEDED: &str = "superseded";
    pub const UNPACK: &str = "unpack";
    pub const PENDING: &str = "pending";
}

/// Output of `picket-edge-update units`: `{"format": 1, "units": {"<file name>": "<text>"}}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnitsOutput {
    pub format: u32,
    pub units: BTreeMap<String, String>,
}

/// The only `units` format this updater knows (edge-unifi.md §2).
pub const UNITS_FORMAT: u32 = 1;

/// Parses a release signature's trusted comment, `picket-edge <version> <arch>`.
pub fn parse_trusted_comment(comment: &str) -> Option<(&str, &str)> {
    let mut it = comment.split(' ');
    if it.next()? != "picket-edge" {
        return None;
    }
    let version = it.next()?;
    let arch = it.next()?;
    if it.next().is_some() {
        return None;
    }
    Some((version, arch))
}

/// True when `v` matches `^[0-9]+\.[0-9]+\.[0-9]+$` (edge.md §14).
pub fn is_release_version(v: &str) -> bool {
    let mut parts = 0;
    for p in v.split('.') {
        parts += 1;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    parts == 3
}

/// Compares two release versions numerically; `None` if either is malformed (or a part
/// overflows `u64`).
pub fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    fn parse(v: &str) -> Option<[u64; 3]> {
        if !is_release_version(v) {
            return None;
        }
        let mut out = [0u64; 3];
        for (slot, p) in out.iter_mut().zip(v.split('.')) {
            *slot = p.parse().ok()?;
        }
        Some(out)
    }
    Some(parse(a)?.cmp(&parse(b)?))
}

/// Formats a wall-clock time as RFC 3339 UTC with microseconds and a `Z` suffix, as
/// `picket_api::time::format_micros` does (api.md §5). Times before 1970 clamp to the epoch.
pub fn format_rfc3339_micros(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let micros = d.subsec_micros();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, day) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (H. Hinnant's algorithm,
/// for non-negative day counts).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn versions() {
        assert!(is_release_version("1.4.0"));
        assert!(is_release_version("10.0.123"));
        assert!(!is_release_version("1.4"));
        assert!(!is_release_version("1.4.0.1"));
        assert!(!is_release_version("1.4.0-rc1"));
        assert!(!is_release_version("../1.2.3"));
        assert!(!is_release_version("1..3"));
        assert!(!is_release_version(""));
        assert!(!is_release_version("1.2.3\n"));
        assert_eq!(
            compare_versions("1.10.0", "1.9.9"),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(
            compare_versions("1.2.3", "1.2.3"),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(compare_versions("1.2", "1.2.3"), None);
        assert_eq!(compare_versions("99999999999999999999.0.0", "1.0.0"), None);
    }

    #[test]
    fn trusted_comments() {
        assert_eq!(
            parse_trusted_comment("picket-edge 1.4.0 aarch64"),
            Some(("1.4.0", "aarch64"))
        );
        assert_eq!(parse_trusted_comment("picket-edge 1.4.0"), None);
        assert_eq!(parse_trusted_comment("picket-edge 1.4.0 aarch64 x"), None);
        assert_eq!(parse_trusted_comment("picket-core 1.4.0 aarch64"), None);
        assert_eq!(parse_trusted_comment("timestamp:1\tfile:x"), None);
    }

    #[test]
    fn rfc3339() {
        assert_eq!(format_rfc3339_micros(UNIX_EPOCH), "1970-01-01T00:00:00.000000Z");
        let t = UNIX_EPOCH + Duration::new(1_763_034_121, 123_456_789);
        assert_eq!(format_rfc3339_micros(t), "2025-11-13T11:42:01.123456Z");
        // A leap day and the end of a century year.
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(format_rfc3339_micros(t), "2000-02-29T00:00:00.000000Z");
        let t = UNIX_EPOCH + Duration::from_secs(4_102_444_799);
        assert_eq!(format_rfc3339_micros(t), "2099-12-31T23:59:59.000000Z");
    }

    /// The mirrored types serialise exactly as picket-api's and read each other's output.
    mod mirror {
        use super::super::*;
        use picket_api::update as api;

        fn at() -> (String, picket_api::time::Timestamp) {
            let t = UNIX_EPOCH + std::time::Duration::new(1_763_034_121, 123_456_000);
            let s = format_rfc3339_micros(t);
            let ts = picket_api::time::Timestamp::new(1_763_034_121, 123_456_000).expect("valid timestamp");
            assert_eq!(picket_api::time::format_micros(&ts), s);
            (s, ts)
        }

        /// The release-name checks agree with picket-api's, which picket-edge uses on the same
        /// files and signatures.
        #[test]
        fn release_names_match_picket_api() {
            for v in [
                "1.4.0",
                "10.0.123",
                "1.4",
                "1.4.0.1",
                "1.4.0-rc1",
                "../1.2.3",
                "1..3",
                "",
                "1.2.3\n",
                "99999999999999999999.0.0",
                " 1.2.3",
                "1.2.3 ",
            ] {
                assert_eq!(is_release_version(v), api::is_release_version(v), "{v:?}");
                for w in ["1.2.3", "1.10.0", "1.9.9", "1.2"] {
                    assert_eq!(
                        compare_versions(v, w),
                        api::compare_versions(v, w),
                        "{v:?} vs {w:?}"
                    );
                }
            }
            for c in [
                "picket-edge 1.4.0 aarch64",
                "picket-edge 1.4.0",
                "picket-edge 1.4.0 aarch64 x",
                "picket-core 1.4.0 aarch64",
                "picket-edge  1.4.0 aarch64",
                "timestamp:1\tfile:x",
                "",
            ] {
                assert_eq!(parse_trusted_comment(c), api::parse_trusted_comment(c), "{c:?}");
            }
        }

        /// The hand-written formatter writes what picket-api's does, leap days and the far
        /// future (the latest instant jiff holds, 9999-12-30T22:00:00.999999999Z) included.
        #[test]
        fn timestamps_match_picket_api() {
            for (secs, nanos) in [
                (0i64, 0u32),
                (951_782_400, 999_999_000),
                (1_709_208_000, 0),
                (1_763_634_121, 123_456_789),
                (4_102_444_800, 1_000),
                (253_402_207_200, 999_999_999),
            ] {
                let st = UNIX_EPOCH + std::time::Duration::new(u64::try_from(secs).unwrap(), nanos);
                let ts = picket_api::time::Timestamp::new(secs, i32::try_from(nanos).unwrap()).unwrap();
                assert_eq!(
                    format_rfc3339_micros(st),
                    picket_api::time::format_micros(&ts),
                    "{secs}.{nanos}"
                );
            }
        }

        #[test]
        fn pending() {
            for (version, request_id, rollback) in [
                ("1.5.0", Some("req-1"), true),
                ("1.5.0", None, false),
                ("", Some(""), false),
            ] {
                let ours = Pending {
                    version: version.into(),
                    request_id: request_id.map(Into::into),
                    rollback,
                };
                let theirs = api::Pending {
                    version: version.into(),
                    request_id: request_id.map(Into::into),
                    rollback,
                };
                let a = serde_json::to_string(&ours).unwrap();
                let b = serde_json::to_string(&theirs).unwrap();
                assert_eq!(a, b);
                let back: Pending = serde_json::from_str(&b).unwrap();
                assert_eq!(back, ours);
            }
            // Defaults for missing fields, unknown fields ignored, on both sides.
            let ours: Pending = serde_json::from_str(r#"{"future": 1}"#).unwrap();
            let theirs: api::Pending = serde_json::from_str(r#"{"future": 1}"#).unwrap();
            assert_eq!(
                serde_json::to_string(&ours).unwrap(),
                serde_json::to_string(&theirs).unwrap()
            );
        }

        #[test]
        fn update_result() {
            let (s, ts) = at();
            for (outcome, stage) in [(Outcome::Ok, None), (Outcome::Failed, Some(stage::ROLLBACK))] {
                let ours = UpdateResult {
                    result_id: "00f1e2d3c4b5a697".into(),
                    request_id: Some("req-7".into()),
                    outcome,
                    stage: stage.map(Into::into),
                    version: "1.5.0".into(),
                    at: s.clone(),
                };
                let theirs = api::UpdateResult {
                    result_id: "00f1e2d3c4b5a697".into(),
                    request_id: Some("req-7".into()),
                    outcome: match outcome {
                        Outcome::Ok => picket_api::session::Outcome::Ok,
                        Outcome::Failed => picket_api::session::Outcome::Failed,
                    },
                    stage: stage.map(Into::into),
                    version: "1.5.0".into(),
                    at: ts,
                };
                let a = serde_json::to_string(&ours).unwrap();
                let b = serde_json::to_string(&theirs).unwrap();
                assert_eq!(a, b);
                let back: api::UpdateResult = serde_json::from_str(&a).unwrap();
                assert_eq!(back, theirs);
                let back: UpdateResult = serde_json::from_str(&b).unwrap();
                assert_eq!(back, ours);
            }
        }

        #[test]
        fn units_output_and_helpers() {
            let mut ours = UnitsOutput {
                format: UNITS_FORMAT,
                ..Default::default()
            };
            ours.units.insert("picket-edge.service".into(), "[Unit]\n".into());
            let mut theirs = api::UnitsOutput {
                format: api::UNITS_FORMAT,
                ..Default::default()
            };
            theirs
                .units
                .insert("picket-edge.service".into(), "[Unit]\n".into());
            assert_eq!(
                serde_json::to_string(&ours).unwrap(),
                serde_json::to_string(&theirs).unwrap()
            );
            assert_eq!(UNITS_FORMAT, api::UNITS_FORMAT);
            for (a, b) in [
                (stage::VERIFY, api::stage::VERIFY),
                (stage::UNITS, api::stage::UNITS),
                (stage::READINESS, api::stage::READINESS),
                (stage::ROLLBACK, api::stage::ROLLBACK),
                (stage::LOCKED, api::stage::LOCKED),
                (stage::SUPERSEDED, api::stage::SUPERSEDED),
                (stage::UNPACK, api::stage::UNPACK),
                (stage::PENDING, api::stage::PENDING),
            ] {
                assert_eq!(a, b);
            }
            for v in ["1.4.0", "1.4", "../1.2.3", "1.2.3.4", "01.2.3", ""] {
                assert_eq!(is_release_version(v), api::is_release_version(v), "{v}");
            }
            for (a, b) in [
                ("1.10.0", "1.9.9"),
                ("1.0.0", "1.0.0"),
                ("0.9.1", "1.0.0"),
                ("x", "1.0.0"),
            ] {
                assert_eq!(compare_versions(a, b), api::compare_versions(a, b));
            }
            for c in [
                "picket-edge 1.4.0 aarch64",
                "picket-edge 1.4.0",
                "x 1 2",
                "picket-edge a b c",
            ] {
                assert_eq!(parse_trusted_comment(c), api::parse_trusted_comment(c));
            }
            assert_eq!(
                parse_trusted_comment(&api::trusted_comment("1.2.3", "x86_64")),
                Some(("1.2.3", "x86_64"))
            );
        }
    }
}
