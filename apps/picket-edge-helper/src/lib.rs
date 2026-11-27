//! picket-edge-helper: the only long-running Picket process with `CAP_NET_ADMIN` and
//! `CAP_NET_RAW`. It owns Picket's ipsets and iptables rules and serves picket-edge over a Unix
//! socket (edge-firewall.md §4, edge-unifi.md §3–§4). It has no DNS, HTTP or parsing code
//! beyond what that needs.

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]

pub mod backend;
pub mod cli;
pub mod dump;
pub mod engine;
#[cfg(any(test, feature = "testkit"))]
pub mod fake;
pub mod fast;
pub mod ipset;
pub mod iptables;
pub mod rules;
pub mod server;
pub mod shared;
pub mod snapshot;
pub mod users;
