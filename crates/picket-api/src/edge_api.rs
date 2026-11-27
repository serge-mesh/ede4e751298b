//! The edge API served by core on port 7443 with mTLS (api.md §2).

use serde::{Deserialize, Serialize};

/// Default edge API port.
pub const DEFAULT_EDGE_PORT: u16 = 7443;
/// Default web port.
pub const DEFAULT_WEB_PORT: u16 = 8443;

pub mod paths {
    pub const SESSION: &str = "/v1/session";
    pub const LOGS: &str = "/v1/logs";
    pub const CSR: &str = "/v1/csr";
    /// Prefix of the path-style S3 bucket `objects`.
    pub const OBJECTS: &str = "/objects/";
}

/// Object keys in the `objects` bucket (api.md §2).
pub mod keys {
    pub fn config(fp_path: &str) -> String {
        format!("configs/{fp_path}.json")
    }
    pub fn bundle_head(bundle: &str, head_id: &str) -> String {
        format!("bundles/{bundle}/heads/{head_id}.json")
    }
    pub fn verdict_set_head(provider: &str, head_id: &str) -> String {
        format!("verdict-sets/{provider}/heads/{head_id}.json")
    }
    pub fn blob(blake3: &str) -> String {
        format!("blobs/{blake3}")
    }
    pub fn release_tarball(version: &str, arch: &str) -> String {
        format!("releases/{version}/picket-edge-{version}-{arch}.tar.gz")
    }
    pub fn release_minisig(version: &str, arch: &str) -> String {
        format!("releases/{version}/picket-edge-{version}-{arch}.tar.gz.minisig")
    }
}

/// `POST /v1/csr` body.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CsrRequest {
    pub csr_pem: String,
    /// The managed listener's id.
    pub listener: String,
}

/// `POST /v1/csr` reply, signed by the LAN CA.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CsrResponse {
    pub cert_pem: String,
    pub chain_pem: String,
    /// RFC 3339.
    pub not_after: String,
}

/// Error body shared by the edge API and the UI API: `{"error": {"code", "message"}}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}
