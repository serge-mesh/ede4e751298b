//! Unit tests across modules: hand-built messages (crate::testutil) and recorded answers
//! (fixtures/wire/), for the rules of edge.md §4, §7, §8 and the build-and-test.md §5 "Edge
//! pipeline" and "Wire check" rows that belong to this layer.

mod answer;
mod cache;
mod differential;
mod fixtures;
mod lookup;
pub(crate) mod oracle;
mod query;
mod replies;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

/// Decodes a message we wrote with hickory's full message decoder, as a client would.
pub(crate) fn decode(msg: &[u8]) -> Message {
    Message::from_bytes(msg).expect("hickory decodes what picket-wire writes")
}
