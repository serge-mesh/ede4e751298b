//! The bypass API served by the edge on listeners with `"api": true` (api.md §6), for
//! picket-browser-extension. Every request must carry `X-Picket-Client: extension`.

use serde::{Deserialize, Serialize};

use crate::logs::AllowKind;

/// Header every bypass request and every extension DoH probe carries.
pub const CLIENT_HEADER: &str = "x-picket-client";
pub const CLIENT_HEADER_VALUE: &str = "extension";

/// One entry of a `PUT` or `PATCH` body: `{block_id, expires_at, subdomains?}` (DNS),
/// `{ip, expires_at}` (IP) or `{allow_id, expires_at}`. `expires_at` is Unix seconds; a past
/// one revokes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_id: Option<String>,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomains: Option<bool>,
}

/// One active allow in a response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowView {
    pub allow_id: String,
    pub kind: AllowKind,
    /// The name (DNS) or IP.
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomains: Option<bool>,
    /// Unix seconds.
    pub expires_at: i64,
    /// Only on allows the request created or re-timed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

/// Error body: `{"error": {"code", "message", "index"?}}`; `index` names the failing entry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BypassError {
    pub error: BypassErrorDetail,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BypassErrorDetail {
    /// The error's code, e.g. `forbidden`, `rate_limited`, `max_active`, `no_block`. `too_short`
    /// (403): a DNS allow would end while browsers may still use its block's cached answer (its
    /// hold, max(65 s, block TTL + 5 s), plus 5 s for the reload), whether the request or the
    /// governing profiles' `bypass.max_duration` is what is short; the message says how long it
    /// needs or when to ask again, and nothing is recorded or counted against limits (#50).
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
}
