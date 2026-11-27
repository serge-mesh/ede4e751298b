//! The WebSocket control session (api.md §3): `{"type": "<type>", "data": {…}}` in text frames,
//! carrying only `hello`, `welcome`, `changed` and `heartbeat`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::histogram::Histogram;
use crate::logs::Versions;
use crate::time::Timestamp;

/// A session message envelope. Unknown types are kept as `Unknown` so newer peers don't break
/// older ones.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SessionMessage {
    Hello(Box<Hello>),
    Welcome(Welcome),
    Changed(Changed),
    Heartbeat(Box<Heartbeat>),
    Unknown,
}

impl<'de> Deserialize<'de> for SessionMessage {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(rename = "type")]
            kind: String,
            #[serde(default)]
            data: serde_json::Value,
        }
        let raw = Raw::deserialize(de)?;
        let data = if raw.data.is_null() {
            serde_json::Value::Object(Default::default())
        } else {
            raw.data
        };
        let err = serde::de::Error::custom;
        Ok(match raw.kind.as_str() {
            "hello" => Self::Hello(Box::new(serde_json::from_value(data).map_err(err)?)),
            "welcome" => Self::Welcome(serde_json::from_value(data).map_err(err)?),
            "changed" => Self::Changed(serde_json::from_value(data).map_err(err)?),
            "heartbeat" => Self::Heartbeat(Box::new(serde_json::from_value(data).map_err(err)?)),
            _ => Self::Unknown,
        })
    }
}

/// edge → core, first message of every session.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hello {
    pub edge_version: String,
    /// `aarch64` or `x86_64`.
    pub arch: String,
    pub os: String,
    pub kernel: String,
    pub platform: String,
    /// First line of `/usr/lib/version` on UniFi (≤ 128 bytes), else `None`.
    pub firmware: Option<String>,
    pub mem_total: Option<u64>,
    pub mem_available: Option<u64>,
    pub allowed_binds: Vec<String>,
    pub updates_enabled: bool,
    pub have: Have,
    pub boot: String,
    /// Starts since the edge's last session with core.
    pub starts: u32,
    pub conditions: Vec<Condition>,
    pub applied: Applied,
    pub update: Option<UpdateOutcome>,
    /// For each managed TLS listener that holds a certificate: the `SHA256:` fingerprint
    /// ([`crate::ids::cert_fingerprint`]) of the LAN CA root that signed the certificate it
    /// serves now. Core keeps trusting a previous root until every assigned managed listener
    /// reports a certificate from the current root (core.md §11 `lanca.zones`).
    pub cert_roots: BTreeMap<String, String>,
}

/// What the edge keeps on disk, active first then previous, plus what it is fetching.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Have {
    pub config: Vec<String>,
    pub bundles: BTreeMap<String, Vec<String>>,
    pub verdict_sets: BTreeMap<String, Vec<String>>,
    /// The installed release version.
    pub release: Option<String>,
    pub in_progress: InProgress,
    /// ETag of the newest config object the edge has fetched.
    pub fetched: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InProgress {
    pub config: Option<String>,
    pub bundles: BTreeMap<String, Vec<String>>,
    pub verdict_sets: BTreeMap<String, Vec<String>>,
}

/// core → edge, reply to `hello`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Welcome {
    pub core_version: String,
    pub edge_id: String,
    pub edge_name: String,
    #[serde(with = "crate::time::micros")]
    pub server_time: Timestamp,
}

/// core → edge: the edge's config object changed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Changed {
    pub etag: String,
}

/// edge → core every 30 s. Counters and histograms are running totals since the process
/// started; gauges are values at `ts`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Heartbeat {
    #[serde(with = "crate::time::micros")]
    pub ts: Timestamp,
    pub boot: String,
    pub up_ms: u64,
    pub metrics: Metrics,
    pub spool: SpoolInfo,
    pub logs: LogsInfo,
    pub rss: Option<u64>,
    pub mem_available: Option<u64>,
    pub cpu_ms: CpuMs,
    pub cgroup_mem: CgroupMem,
    pub disk: Disk,
    pub fw: Option<FwStats>,
    pub versions: Option<Versions>,
    pub ready_version: Option<String>,
    pub have: Have,
    pub conditions: Vec<Condition>,
    pub applied: Applied,
    pub update: Option<UpdateOutcome>,
    /// As in [`Hello::cert_roots`], at the time of the heartbeat.
    pub cert_roots: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Metrics {
    pub queries: u64,
    pub by_decision: ByDecision,
    pub rejected: u64,
    pub refused: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub stale_served: u64,
    pub latency_us: Histogram,
    pub panics: u64,
    pub fw_ack_late: u64,
    pub upstream: BTreeMap<String, UpstreamMetrics>,
    pub lookups: BTreeMap<String, LookupMetrics>,
    pub cold: BTreeMap<String, ColdMetrics>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ByDecision {
    pub allow: u64,
    pub block: u64,
    pub rewrite: u64,
    pub refused: u64,
    pub servfail: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamMetrics {
    pub queries: u64,
    pub hedges: u64,
    pub rtt_ms: Histogram,
    pub errors: u64,
    pub invalid: BTreeMap<String, u64>,
    /// Records the scrub removed from this upstream's valid answers, by reason (edge.md §7 step
    /// 3: "Scrub removals are counted"). Running totals; left out when empty. Not yet in api.md
    /// §3 (owner to add).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub scrubbed: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LookupMetrics {
    pub calls: u64,
    pub call_ms: Histogram,
    pub timeouts: u64,
    pub late: u64,
    pub errors: u64,
    pub rejected: u64,
    /// Gauge: 1 while the breaker is open.
    pub breaker_open: u64,
    pub paused: u64,
    pub cache_hits: u64,
    pub set_hits: u64,
    pub cache_misses: u64,
    pub evictions: u64,
    /// Gauge.
    pub entries: u64,
    /// Gauge.
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ColdMetrics {
    pub blocks: u64,
    pub unchecked: u64,
    pub page_reads: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpoolInfo {
    pub bytes: u64,
    #[serde(with = "crate::time::micros_opt")]
    pub oldest_ts: Option<Timestamp>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogsInfo {
    /// By reason: `buffer_full`, `evicted`, `too_old`, `rejected`.
    pub dropped: BTreeMap<String, u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CpuMs {
    pub edge: Option<u64>,
    pub helper: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CgroupMem {
    pub unit: Option<u64>,
    pub helper_rss: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Disk {
    pub data_dir: Option<DiskUse>,
    pub ssd_dir: Option<DiskUse>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskUse {
    pub used: Option<u64>,
    pub free: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FwStats {
    pub entries: u64,
    pub max: u64,
    pub rejects: u64,
    pub mon_rejects: u64,
}

/// One condition holding now (api.md §3). A condition missing from a received list has cleared.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(with = "crate::time::micros")]
    pub since: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// Condition kinds (api.md §3).
pub mod condition_kind {
    pub const UPSTREAM_DOWN: &str = "upstream_down";
    pub const REDIRECT_MISSING: &str = "redirect_missing";
    pub const HELPER_UNREACHABLE: &str = "helper_unreachable";
    pub const UNIFI_CONFLICT: &str = "unifi_conflict";
    pub const LISTENER_FAILED: &str = "listener_failed";
    pub const SSD_UNAVAILABLE: &str = "ssd_unavailable";
    pub const MEMORY_LOW: &str = "memory_low";
    pub const FW_SET_FULL: &str = "fw_set_full";
    pub const SPOOL_EVICTING: &str = "spool_evicting";
    pub const HELPER_DISABLED: &str = "helper_disabled";
    pub const FW_LAYOUT_UNKNOWN: &str = "fw_layout_unknown";
    pub const FW_CATCH_ALL: &str = "fw_catch_all";
    pub const FW_DRIFT: &str = "fw_drift";
    pub const FIRMWARE_CHECK_FAILED: &str = "firmware_check_failed";
}

/// The request ids the edge last applied, each `None` until it has applied one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Applied {
    pub flush_dns: Option<String>,
    pub flush_lookups: BTreeMap<String, String>,
    pub install_now: Option<String>,
    pub revoked_allows: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    #[default]
    Ok,
    Failed,
}

/// The latest terminal update outcome, kept in `state.json` (edge.md §14).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateOutcome {
    pub result_id: String,
    pub outcome: Outcome,
    pub version: String,
    #[serde(with = "crate::time::micros")]
    pub at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope() {
        let m = SessionMessage::Changed(Changed { etag: "abc".into() });
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(s, r#"{"type":"changed","data":{"etag":"abc"}}"#);
        let back: SessionMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
        let unknown: SessionMessage = serde_json::from_str(r#"{"type":"future","data":{}}"#).unwrap();
        assert_eq!(unknown, SessionMessage::Unknown);
    }

    #[test]
    fn heartbeat_roundtrip() {
        let hb = Heartbeat {
            boot: "7f3a91".into(),
            up_ms: 5,
            ..Default::default()
        };
        let s = serde_json::to_string(&SessionMessage::Heartbeat(Box::new(hb.clone()))).unwrap();
        let back: SessionMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(back, SessionMessage::Heartbeat(Box::new(hb)));
    }
}
