//! iptables, by exec only (edge-firewall.md §4 "Implementation"): a model of the tables parsed
//! from `iptables-save`, jump placement on UniFi's zone-based layout and on Debian, the restore
//! text that repairs Picket's chains and jumps, and the port-53 redirect check.

pub mod exec;
pub mod layout;
pub mod model;
pub mod nat;
pub mod plan;

pub use layout::Platform;
pub use plan::Family;

/// The table a read concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TableName {
    Filter,
    Nat,
}

impl TableName {
    pub fn as_str(self) -> &'static str {
        match self {
            TableName::Filter => "filter",
            TableName::Nat => "nat",
        }
    }
}

/// A failed `iptables*` or `ip` run.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    /// `-w 5` ran out waiting for `/run/xtables.lock`: retried at the next re-assert.
    #[error("timed out waiting for the xtables lock")]
    LockTimeout,
    /// The lock file couldn't be opened (permissions): not a timeout, and retrying won't help
    /// until the unit's `ExecStartPre` lines have fixed the file's group.
    #[error("cannot open the xtables lock: {0}")]
    LockPermission(String),
    /// iptables refused for lack of privilege.
    #[error("permission denied: {0}")]
    Permission(String),
    /// The command ran past the helper's own deadline and was killed.
    #[error("command timed out")]
    Timeout,
    #[error("command output exceeded {0} bytes")]
    OutputTooLarge(usize),
    #[error("cannot run {0}")]
    Spawn(String),
    #[error("command failed ({code:?}): {stderr}")]
    Failed { code: Option<i32>, stderr: String },
    #[error("malformed output: {0}")]
    Parse(String),
}

impl ExecError {
    /// The code reported to the edge (`pending`, `HelperError.code`).
    pub fn code(&self) -> &'static str {
        match self {
            ExecError::LockTimeout => "lock_timeout",
            ExecError::LockPermission(_) => "lock_permission",
            ExecError::Permission(_) => "permission",
            ExecError::Timeout => "exec_timeout",
            ExecError::OutputTooLarge(_) => "output_too_large",
            ExecError::Spawn(_) => "spawn_failed",
            ExecError::Failed { .. } => "exec_failed",
            ExecError::Parse(_) => "parse_failed",
        }
    }
}
