//! Files exchanged between picket-edge and picket-edge-update (edge.md §14, edge-unifi.md §2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::session::Outcome;
use crate::time::Timestamp;

/// `<data_dir>/releases/pending.json`, written by the unprivileged edge.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pending {
    pub version: String,
    /// The `install_now` id the edge acts on, or `None`.
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rollback: bool,
}

/// `bin/update-result.json`, written by the updater (`root:picket`, 0640).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateResult {
    pub result_id: String,
    pub request_id: Option<String>,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub version: String,
    #[serde(with = "crate::time::micros")]
    pub at: Timestamp,
}

/// Update failure stages.
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

pub const UNITS_FORMAT: u32 = 1;

/// The trusted comment a release signature carries: `picket-edge <version> <arch>`.
pub fn trusted_comment(version: &str, arch: &str) -> String {
    format!("picket-edge {version} {arch}")
}

/// Parses a trusted comment into `(version, arch)`.
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
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Compares two release versions numerically; `None` if either is malformed.
pub fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    if !is_release_version(a) || !is_release_version(b) {
        return None;
    }
    let pa: Vec<u64> = a.split('.').filter_map(|p| p.parse().ok()).collect();
    let pb: Vec<u64> = b.split('.').filter_map(|p| p.parse().ok()).collect();
    if pa.len() != 3 || pb.len() != 3 {
        return None;
    }
    Some(pa.cmp(&pb))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(is_release_version("1.4.0"));
        assert!(!is_release_version("1.4"));
        assert!(!is_release_version("1.4.0-rc1"));
        assert!(!is_release_version("../1.2.3"));
        assert_eq!(
            compare_versions("1.10.0", "1.9.9"),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(
            parse_trusted_comment("picket-edge 1.4.0 aarch64"),
            Some(("1.4.0", "aarch64"))
        );
        assert_eq!(parse_trusted_comment("picket-edge 1.4.0"), None);
    }
}
