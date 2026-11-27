//! picket-wire: DNS on hickory-proto for picket-edge, picket-lookup's `dns` module and core.
//!
//! hickory-proto decodes every query and every upstream answer and encodes scrubbed answers
//! (edge.md §4 "Parsing", §7). This crate has no DNS message or name decoder of its own: it applies
//! the server policy hickory leaves to its caller, applies policy to hickory's decoded records and
//! EDNS option payloads, writes every reply, upstream query and cache hit into caller-provided
//! buffers, and walks only cache copies hickory encoded, to find their TTL offsets (edge.md §8).
//!
//! The edge's per-query path decodes a query once ([`query::check_query`]), checks an upstream
//! answer once ([`answer::check_answer`] → [`cache::CacheValue`]) and serves cache hits without
//! decoding ([`cache::serve_hit`]). Core rebuilds the reply a client got with the same offsets,
//! predicate and size limits ([`cache::rebuild_reply`], core.md §6).
//!
//! Modules:
//! - [`query`]: the query check (edge.md §4 "Parsing", §16).
//! - [`name`]: query names in a stack buffer, owned names, reversed-label keys, log and AdGuard
//!   text (rules.md §3, api.md §5).
//! - [`reply`]: reply writers: rcode-only, negative with a synthesised SOA, sinkhole, generic
//!   records, RFC 8482 ANY, local answers (edge.md §4), sized to the client and the listener's
//!   `limits.udp_payload` (edge.md §5), padded to 468-byte blocks for padded DoT/DoH queries
//!   (RFC 7830 §4, RFC 8467 §4.1); core's reply parameters from a log record.
//! - [`ede`]: Extended DNS Errors with the EXTRA-TEXT token rules (edge.md §4 EDE).
//! - [`upstream`]: the upstream query writer with RFC 8467 padding (edge.md §6).
//! - [`answer`]: the upstream answer pipeline: structure checks, scrub, facts, encode (edge.md §7);
//!   per-reason counter names; the TC check a UDP transport makes before retrying over TCP.
//! - [`dnssec`]: the DO=0 strip predicate shared by edge and core (edge.md §7 step 4).
//! - [`cache`]: the cache value, hit serving, the stale variant and core's rebuild (edge.md §8).
//! - [`facts`]: answer facts and the EXTRA-TEXT `detail` for the `dns` lookup module
//!   (providers.md §5).
//! - [`reverse`]: reverse names both ways and private ranges for `private_reverse` (edge.md §6).
//! - [`log`]: log-record limits, the answer preview and the `answer` record id (api.md §5).
//! - [`svcb`]: RFC 9460 checks and the facts of HTTPS/SVCB data, also for rewrite values.
//! - [`types`]: type, class and rcode numbers with their mnemonics, EDE and EDNS option codes.

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]
// security.md §1: crates that handle raw bytes deny these outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod answer;
pub mod cache;
pub mod dnssec;
pub mod ede;
mod edns;
pub mod facts;
pub mod log;
pub mod name;
pub mod query;
pub mod reply;
pub mod reverse;
pub mod svcb;
pub mod types;
pub mod upstream;
mod wire;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod testutil;

pub use answer::{
    AddrSource, AnswerAddr, AnswerFacts, AnswerLimits, EdeInfo, Invalid, Negative, ScrubCounts,
    ScrubbedAnswer, SentQuery, check_answer,
};
pub use cache::{CacheValue, ServeParams, StaleServe, rebuild_reply, serve_hit};
pub use ede::EdeOption;
pub use edns::EdnsOptions;
pub use name::{NameError, NameRef, QName, ReversedName, WireName};
pub use query::{Edns, FormErr, NoReply, Query, QueryError, check_query, write_query_error};
pub use reply::{RecordData, RecordSpec, Reply, ReplyTo, Transport};
pub use wire::WriteError;

/// The largest DNS message: the TCP length prefix is 16 bits (RFC 1035 §4.2.2).
pub const MAX_MESSAGE: usize = 65_535;

/// The default listener `limits.udp_payload` (edge.md §5): the UDP payload size a listener
/// advertises and the largest UDP reply it sends, whatever a client advertises (RFC 6891 §6.2.5;
/// DNS Flag Day 2020's 1,232 bytes avoids IP fragmentation). Upstream queries advertise it too.
pub const EDGE_UDP_PAYLOAD: u16 = 1232;
