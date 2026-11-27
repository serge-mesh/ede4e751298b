//! Serde types for every Picket interface (api.md): the edge API, the WebSocket session,
//! `EdgeConfig`, log records, the bypass API, the helper socket protocol and the updater's files.
//!
//! JSON compatibility rule (README §2): types only ever gain fields, every field has a default
//! when missing, and unknown fields are ignored. Never add `deny_unknown_fields` here.

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]

pub mod bypass;
pub mod duration;
pub mod edge_api;
pub mod edge_config;
pub mod helper;
pub mod histogram;
pub mod ids;
pub mod logs;
pub mod names;
pub mod session;
pub mod time;
pub mod update;

pub use duration::DurationStr;
pub use edge_config::EdgeConfig;
pub use histogram::Histogram;

/// The release version of every Picket binary built from this workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The edge port's API major version, used in paths (`/v1/...`).
pub const API_VERSION: &str = "v1";
