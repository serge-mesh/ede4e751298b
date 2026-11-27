//! The upstream query writer (edge.md §6 "Upstream query", "Padding", "DO"; providers.md §5
//! `dns`).
//!
//! The edge builds every query it sends upstream itself: a new random ID, RD set, the client's
//! CD, the upstream DO the caller chooses, the question, and the edge's own OPT. A client's EDNS
//! options are never forwarded and no Client Subnet is added. Queries to DoT and DoH upstreams end
//! their OPT with an EDNS(0) Padding option (RFC 8467 §4.1) that brings the DNS message, not
//! counting DoT's 2-byte length prefix, to a multiple of 128 bytes; `udp` and `tcp` queries aren't
//! padded. The `dns` lookup module uses the same writer (DO and CD clear, padding on dot/doh).

use crate::EDGE_UDP_PAYLOAD;
use crate::name::NameRef;
use crate::reply::OPT_FIXED;
use crate::types::{edns_code, rtype};
use crate::wire::{Out, WriteError};

/// The block size padded queries are brought to (RFC 8467 §4.1).
pub const PAD_BLOCK: usize = 128;

/// The flags of an upstream query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryParams {
    /// A fresh random ID, unique among the queries in flight on the connection.
    pub id: u16,
    /// The client's CD (CD clear for lookups).
    pub cd: bool,
    /// The upstream DO: 1 for upstream groups; the client's for plain groups and forward zones;
    /// 0 for lookups (edge.md §6).
    pub do_bit: bool,
    /// Pad to a multiple of [`PAD_BLOCK`]: true for DoT and DoH, false for udp and tcp.
    pub pad: bool,
}

/// A random query ID.
pub fn random_query_id() -> u16 {
    rand::random()
}

/// The length of the query [`write_query`] writes for this name and padding choice.
pub fn query_len(qname: NameRef<'_>, pad: bool) -> usize {
    let unpadded = 12usize
        .saturating_add(qname.wire_len())
        .saturating_add(4)
        .saturating_add(OPT_FIXED);
    if pad {
        let with_header = unpadded.saturating_add(4);
        with_header.saturating_add(pad_len(with_header))
    } else {
        unpadded
    }
}

/// Zero bytes that bring `len` up to a multiple of [`PAD_BLOCK`].
fn pad_len(len: usize) -> usize {
    match len % PAD_BLOCK {
        0 => 0,
        r => PAD_BLOCK.saturating_sub(r),
    }
}

/// Writes an upstream query for `qname` (lowercase wire form), `qtype` and `qclass` into
/// `out`, and returns its length.
pub fn write_query(
    out: &mut [u8],
    qname: NameRef<'_>,
    qtype: u16,
    qclass: u16,
    p: &QueryParams,
) -> Result<usize, WriteError> {
    let mut o = Out::new(out);
    o.u16(p.id)?;
    o.u8(0x01)?; // QUERY, RD
    o.u8(if p.cd { 0x10 } else { 0 })?;
    o.u16(1)?;
    o.u16(0)?;
    o.u16(0)?;
    o.u16(1)?;
    o.put(qname.wire())?;
    o.u16(qtype)?;
    o.u16(qclass)?;
    // Our own OPT: no client option, no Client Subnet.
    o.u8(0)?;
    o.u16(rtype::OPT)?;
    o.u16(EDGE_UDP_PAYLOAD)?;
    o.u8(0)?; // extended rcode
    o.u8(0)?; // version 0
    o.u16(if p.do_bit { 0x8000 } else { 0 })?;
    if p.pad {
        let rdlen_at = o.pos();
        o.u16(0)?;
        // The padding option's own 4 header bytes count toward the block.
        let fill = pad_len(o.pos().saturating_add(4));
        o.u16(edns_code::PADDING)?;
        o.u16(u16::try_from(fill).map_err(|_| WriteError::TooLong)?)?;
        o.zeros(fill)?;
        o.patch_u16(
            rdlen_at,
            u16::try_from(fill.saturating_add(4)).map_err(|_| WriteError::TooLong)?,
        )?;
    } else {
        o.u16(0)?;
    }
    Ok(o.pos())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::QName;

    #[test]
    fn padded_to_128() {
        for name in ["a", "example.com", &"x".repeat(63), &vec!["a"; 100].join(".")] {
            let q = QName::from_text(name).unwrap();
            let mut buf = [0u8; 600];
            let p = QueryParams {
                id: 7,
                cd: true,
                do_bit: true,
                pad: true,
            };
            let n = write_query(&mut buf, q.as_name(), 1, 1, &p).unwrap();
            assert_eq!(n % PAD_BLOCK, 0, "{name}");
            assert_eq!(n, query_len(q.as_name(), true));
            let plain = QueryParams { pad: false, ..p };
            let m = write_query(&mut buf, q.as_name(), 1, 1, &plain).unwrap();
            assert_eq!(m, 12 + q.wire().len() + 4 + 11);
            assert_eq!(m, query_len(q.as_name(), false));
        }
    }

    #[test]
    fn exact_multiple_needs_empty_padding_option() {
        // 12 + name + 4 + 11 + 4 == 128 needs a zero-length padding option.
        let label_bytes = 128 - 12 - 4 - 11 - 4 - 1; // 96 bytes of name wire before the root
        let q = QName::from_text(&format!(
            "{}.{}",
            "a".repeat(63),
            "b".repeat(label_bytes - 64 - 1)
        ))
        .unwrap();
        assert_eq!(q.wire().len(), 97);
        let mut buf = [0u8; 300];
        let p = QueryParams {
            id: 1,
            cd: false,
            do_bit: false,
            pad: true,
        };
        let n = write_query(&mut buf, q.as_name(), 1, 1, &p).unwrap();
        assert_eq!(n, 128);
        // The padding option is present with length 0.
        assert_eq!(&buf[n - 4..n], &[0, 12, 0, 0]);
    }
}
