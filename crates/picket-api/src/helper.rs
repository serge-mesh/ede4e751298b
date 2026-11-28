//! The picket-edge-helper socket protocol (edge-firewall.md §4): length-delimited JSON frames
//! (`tokio-util` `LengthDelimitedCodec`, 1 MiB maximum on both sides), each
//! `{type, id?, data}`. A response repeats its request's `id`; events have none.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::edge_config::FwMode;

/// Protocol version checked at `hello`; a mismatch makes the edge refuse to start.
pub const PROTO_VERSION: u32 = 1;
/// Largest frame on either side.
pub const MAX_FRAME: usize = 1 << 20;
/// Largest `dump` page.
pub const MAX_DUMP_LIMIT: u32 = 4096;
/// Default socket path.
pub const DEFAULT_SOCKET: &str = "/run/picket-helper/helper.sock";
/// Largest timeout the helper accepts, in seconds (edge-firewall.md §4).
pub const MAX_TIMEOUT_S: u32 = 2_147_483;
/// Most networks one [`LocalDst`] snapshot carries; a larger set is reported `too_large`.
pub const MAX_LOCAL_DST_NETS: usize = 1024;
/// Most networks all of one family's [`LocalDst`] entries carry together: each interface's entry
/// repeats its set, and every message carrying the conditions must stay under [`MAX_FRAME`]
/// (4,096 IPv6 networks of both families take under 400 KiB). An entry that would pass it is
/// reported `too_large`.
pub const MAX_LOCAL_DST_TOTAL: usize = 4096;

/// The four timed sets `ensure` and `delete` may touch.
pub mod sets {
    pub const PICKET4: &str = "picket4";
    pub const PICKET6: &str = "picket6";
    pub const PICKET_G4: &str = "picket-g4";
    pub const PICKET_G6: &str = "picket-g6";
    pub const STATIC4: &str = "picket-static4";
    pub const STATIC6: &str = "picket-static6";
    pub const EXEMPT4: &str = "picket-exempt4";
    pub const EXEMPT6: &str = "picket-exempt6";
    pub const TIMED: [&str; 4] = [PICKET4, PICKET6, PICKET_G4, PICKET_G6];
    pub const MAXELEM: u32 = 262_144;
    pub const DEFAULT_TIMEOUT_S: u32 = 300;
}

/// One frame on the helper socket.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(default)]
    pub data: serde_json::Value,
}

/// Frame types.
pub mod kind {
    pub const HELLO: &str = "hello";
    pub const APPLY: &str = "apply";
    pub const DISABLE: &str = "disable";
    pub const ENABLE: &str = "enable";
    pub const ENSURE: &str = "ensure";
    pub const DELETE: &str = "delete";
    pub const DUMP: &str = "dump";
    pub const STATUS: &str = "status";
    pub const ERROR: &str = "error";
    // events
    pub const RULES_REPAIRED: &str = "rules_repaired";
    pub const SET_FULL: &str = "set_full";
    pub const CONDITIONS: &str = "conditions";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HelloRequest {
    pub proto_version: u32,
    /// Subscribe this connection to events (`rules_repaired`, `set_full`, `conditions`).
    /// Default `true`: the control connection says `hello` and gets events; the fast
    /// connection either sends no `hello` or sets this to `false`. A connection that never says
    /// `hello` gets no events. Any request may come first on any connection.
    pub events: bool,
}

impl Default for HelloRequest {
    fn default() -> Self {
        Self {
            proto_version: 0,
            events: true,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HelloResponse {
    pub proto_version: u32,
    pub helper_version: String,
    pub sets: Vec<SetStatus>,
    pub interfaces: Vec<InterfaceMode>,
    /// As in [`ApplyResponse::rules_ok`].
    pub rules_ok: bool,
    pub conditions: Conditions,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InterfaceMode {
    pub name: String,
    pub mode: FwMode,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApplyRequest {
    pub interfaces: Vec<InterfaceMode>,
    #[serde(rename = "static")]
    pub static_allow: Vec<String>,
    pub exempt: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectCheck>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedirectCheck {
    pub interfaces: Vec<String>,
    /// The `dns` listener's port the redirect must target.
    pub port: u16,
    pub ipv6: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetEntry {
    pub set: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<IpAddr>,
    pub dst: IpAddr,
    #[serde(default)]
    pub timeout_s: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnsureRequest {
    pub entries: Vec<SetEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnsureResponse {
    pub ok: bool,
    pub failed: Vec<EntryFailure>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EntryFailure {
    pub index: usize,
    /// e.g. `set_full`, `invalid`, `lock_timeout`.
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DeleteRequest {
    pub entries: Vec<SetEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DumpRequest {
    pub set: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limit: u32,
}

/// The response to `apply`, `disable` and `enable` (edge-firewall.md §4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApplyResponse {
    /// The request was valid and is in force; the helper keeps converging on it at every
    /// re-assert even if a step failed now. It is persisted in `rules.json` (while that write
    /// fails, `pending` holds `persist`, retried at every re-assert).
    pub ok: bool,
    /// Every set, chain and jump is in place right now, with the static and exempt sets' contents
    /// (false while `disable` is in force, while a protected interface has no place for its
    /// jump, or while a step on those objects is pending). Rule presence only (edge-firewall.md
    /// §4 `status`): the steps that don't change Picket's kernel objects — `persist` (writing
    /// `rules.json`), and reading the nat tables and the gateway's addresses for the redirect
    /// and DNSFILTER checks (`nat4:…`, `nat6:…`, `addresses:…`) — appear in `pending` but leave
    /// it true; their findings come as `conditions`.
    pub rules_ok: bool,
    /// Steps that failed and will be retried at the next re-assert, e.g.
    /// `restore4:lock_timeout`, `restore6:lock_permission`, `set:picket4:netlink_io`.
    pub pending: Vec<String>,
    pub conditions: Conditions,
}

/// `HelperError.code` values.
pub mod error_code {
    /// The request's data doesn't validate (bad CIDR, interface name, set, limit…).
    pub const INVALID: &str = "invalid";
    /// Unknown frame `type`.
    pub const UNKNOWN_TYPE: &str = "unknown_type";
    /// The helper is busy (its work queue is full); retry.
    pub const BUSY: &str = "busy";
    /// A `dump` cursor the helper no longer holds; restart the dump without a cursor.
    pub const CURSOR_EXPIRED: &str = "cursor_expired";
    /// The set doesn't exist in the kernel (e.g. while `disable` is in force after a reboot).
    pub const NO_SET: &str = "no_set";
    /// An ipset or iptables call failed; the message says which.
    pub const INTERNAL: &str = "internal";
    /// The peer may not send this request: `disable` and `enable` are the CLI's (root's).
    pub const FORBIDDEN: &str = "forbidden";
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DumpResponse {
    pub entries: Vec<DumpEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<IpAddr>,
    pub dst: IpAddr,
    /// Remaining timeout in seconds as of the page being served; 0 for an entry without a
    /// timeout (permanent, so not Picket's own).
    #[serde(default)]
    pub timeout_s: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusResponse {
    /// As in [`ApplyResponse::rules_ok`].
    pub rules_ok: bool,
    pub sets: Vec<SetStatus>,
    /// RFC 3339 time of the last repair.
    pub last_repair: Option<String>,
    pub conditions: Conditions,
    /// Growth since picket-edge's previous `status` of the final `RETURN` counters.
    pub rejects: u64,
    pub mon_rejects: u64,
    /// Steps that failed and will be retried at the next re-assert (as in `ApplyResponse`).
    pub pending: Vec<String>,
}

/// Fill of one of the four timed sets, as `hello` and `status` list them (`entries` counts
/// what the kernel holds, expired entries it hasn't collected yet included).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SetStatus {
    pub name: String,
    pub entries: u64,
    pub max: u64,
}

/// The helper's current findings, sent on every change.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Conditions {
    /// Families (`ipv4`, `ipv6`) whose port-53 redirect is missing.
    pub redirect_missing: Vec<String>,
    /// Features (e.g. `dnsfilter`) or `shadowed_rules`.
    pub unifi_conflict: Vec<String>,
    pub fw_layout_unknown: Vec<String>,
    pub fw_catch_all: Vec<CatchAllFinding>,
    pub helper_disabled: bool,
    /// UniFi: per `enforce` interface and family, the destinations whose traffic never reaches
    /// Picket's jump. Not a condition the edge raises:
    /// `FwClient::ip_blocked` uses it.
    pub local_dst: Vec<LocalDst>,
}

/// UniFi's own networks for one interface and family: the members of the
/// `…local_zoned_subnets` set that guards the only way into the interface's zone→External
/// chain. Traffic from the interface to them is decided by UniFi's zone policies and never
/// meets Picket's jump, so Picket never blocks it. Read afresh on every pass of the helper.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalDst {
    pub interface: String,
    /// `ipv4` or `ipv6`.
    pub family: String,
    pub set: String,
    /// The set's members (`addr/len`), at most [`MAX_LOCAL_DST_NETS`]; empty when
    /// `unavailable` is set.
    pub nets: Vec<String>,
    /// Why the set can't be used, if it can't: `layout:<what>`, `read:<reason>`,
    /// `set_type:<type>`, `family`, `nomatch`, `undecodable` or `too_large`. The edge then
    /// treats every destination as one that can be blocked.
    pub unavailable: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CatchAllFinding {
    pub interface: String,
    /// `allow`, `drop` or `partial`.
    pub found: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesRepaired {
    /// What was re-added: `set:<name>`, `chain4:<chain>` / `chain6:<chain>`, `jump4:<if>` /
    /// `jump6:<if>`, `dns6:<if>`, and `moved4:<if>` / `moved6:<if>` / `moved-dns6:<if>` for a
    /// jump moved back above its catch-all.
    pub missing: Vec<String>,
    /// Upper bound of the repair gap: milliseconds since the repaired objects were last seen
    /// in place (the largest among them).
    pub gap_ms: u64,
    pub recreated_sets: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SetFull {
    pub set: String,
}

/// Error response data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HelperError {
    pub code: String,
    pub message: String,
}

impl Frame {
    pub fn request<T: Serialize>(kind: &str, id: u64, data: &T) -> Self {
        Self {
            kind: kind.into(),
            id: Some(id),
            data: serde_json::to_value(data).unwrap_or_default(),
        }
    }
    pub fn event<T: Serialize>(kind: &str, data: &T) -> Self {
        Self {
            kind: kind.into(),
            id: None,
            data: serde_json::to_value(data).unwrap_or_default(),
        }
    }
    pub fn parse_data<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.data.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_fields_default_for_older_peers() {
        // A hello without `events` (an older edge) still subscribes the connection.
        let h: HelloRequest = serde_json::from_str(r#"{"proto_version":1}"#).unwrap();
        assert_eq!(
            h,
            HelloRequest {
                proto_version: 1,
                events: true
            }
        );
        assert!(HelloRequest::default().events);
        // A status without `pending` (an older helper) reads as none pending.
        let s: StatusResponse = serde_json::from_str(r#"{"rules_ok":true,"rejects":3}"#).unwrap();
        assert!(s.pending.is_empty());
        assert_eq!(s.rejects, 3);
        let a: ApplyResponse = serde_json::from_str(r#"{"ok":true,"unknown_field":1}"#).unwrap();
        assert!(a.ok && !a.rules_ok && a.pending.is_empty());
    }
}
