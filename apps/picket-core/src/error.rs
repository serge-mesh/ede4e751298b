//! Errors shared across core.

use std::fmt;

/// `EX_CONFIG`: `run` without the marker, a failed migration, a database newer than the binary
/// or too little space for the pre-migration copies (core.md §13, storage.md §5). The units list
/// it in `RestartPreventExitStatus=` so systemd leaves core stopped.
pub const EXIT_CONFIG: u8 = 78;

/// `EX_TEMPFAIL`: another picket-core process holds the data directory's lock. Not 78: the
/// other process may stop, so a restart can succeed.
pub const EXIT_IN_USE: u8 = 75;

/// An error that ends the process with a specific exit code and a message for the operator.
#[derive(Debug, Clone)]
pub struct ExitError {
    pub code: u8,
    pub message: String,
}

impl ExitError {
    pub fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Exit 78 (`EX_CONFIG`).
    pub fn config(message: impl Into<String>) -> Self {
        Self::new(EXIT_CONFIG, message)
    }

    /// Exit 1: a start failure a restart may fix (busy database, bind error, certificate
    /// issuance); 78 is only for the cases core.md §13 names.
    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(1, message)
    }
}

impl fmt::Display for ExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExitError {}

/// Errors from core's services, mapped to UI API statuses by the web module.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    /// A conflict the caller must tell apart from others (`409` with this code instead of
    /// `conflict`; api.md §2 error shape): e.g. `lanca_root_changed`, a rotation asked for from
    /// a LAN CA root another change replaced.
    #[error("{1}")]
    ConflictCode(&'static str, String),
    #[error("{0}")]
    Invalid(String),
    /// A save that would introduce configuration problems (core.md §2).
    #[error("the change was refused: {}", summarize(.0))]
    Validation(Vec<crate::config::validate::Issue>),
    #[error("{0}")]
    Forbidden(String),
    /// Refused for now, for a reason that passes (e.g. the wall clock isn't synchronised yet,
    /// README §2 Clocks): `503`.
    #[error("{0}")]
    Unavailable(String),
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

fn summarize(issues: &[crate::config::validate::Issue]) -> String {
    let mut s = String::new();
    for (i, issue) in issues.iter().take(3).enumerate() {
        if i > 0 {
            s.push_str("; ");
        }
        s.push_str(&issue.message);
    }
    if issues.len() > 3 {
        s.push_str(&format!(" (and {} more)", issues.len() - 3));
    }
    s
}

pub type CoreResult<T> = Result<T, CoreError>;
