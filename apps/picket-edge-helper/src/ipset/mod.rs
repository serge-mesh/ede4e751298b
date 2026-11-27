//! ipset over netlink in pure Rust (edge-firewall.md §4 "Implementation"): the protocol in
//! [`proto`], a blocking socket client in [`client`].

pub mod client;
pub mod proto;

pub use proto::{CreateSpec, Elem, Member, SetFamily, SetHeader, SetType};

/// An ipset operation that failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IpsetError {
    /// The kernel refused the request: a positive errno or ipset error code.
    #[error("ipset error {0} ({reason})", reason = proto::errno_reason(*.0))]
    Kernel(i32),
    #[error("netlink I/O error: {0}")]
    Io(String),
    #[error("netlink reply timed out")]
    Timeout,
    #[error("malformed netlink reply: {0}")]
    Decode(#[from] proto::DecodeError),
    /// The kernel speaks an ipset protocol this client doesn't.
    #[error("unsupported ipset protocol {0}")]
    Protocol(u8),
}

impl IpsetError {
    /// The reason string reported in `EntryFailure.reason` and elsewhere.
    pub fn reason(&self) -> String {
        match self {
            IpsetError::Kernel(e) => proto::errno_reason(*e),
            IpsetError::Io(_) => "netlink_io".into(),
            IpsetError::Timeout => "netlink_timeout".into(),
            IpsetError::Decode(_) => "netlink_decode".into(),
            IpsetError::Protocol(_) => "ipset_protocol".into(),
        }
    }
    pub fn is_set_full(&self) -> bool {
        matches!(self, IpsetError::Kernel(proto::IPSET_ERR_HASH_FULL))
    }
    /// No set with that name (`ENOENT`).
    pub fn is_no_set(&self) -> bool {
        matches!(self, IpsetError::Kernel(2))
    }
}
