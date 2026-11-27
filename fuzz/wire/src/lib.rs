//! Shared pieces of the picket-wire fuzz targets.

/// The `domain` side of the differential oracle, shared with picket-wire's unit tests.
#[path = "../../../crates/picket-wire/src/tests/oracle.rs"]
pub mod oracle;

use hickory_proto::op::{Header, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use picket_wire::name::QName;

/// The ID and question a message carries, as the query it would answer (so arbitrary input
/// reaches the checks after the ID and question match).
pub fn sent_of(msg: &[u8]) -> Option<(u16, QName, u16, u16)> {
    let mut d = BinDecoder::new(msg);
    let h = Header::read(&mut d).ok()?;
    if h.counts.queries != 1 {
        return None;
    }
    let q = Query::read(&mut d).ok()?;
    let name = QName::from_hickory(q.name()).ok()?;
    Some((h.id, name, u16::from(q.query_type()), u16::from(q.query_class())))
}
