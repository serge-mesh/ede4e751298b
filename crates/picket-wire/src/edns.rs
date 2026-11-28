//! Reading records with hickory's lower-level decoders, and policy on EDNS option payloads.
//!
//! [`read_item`] mirrors hickory's `Record::read` with hickory's own pieces (`Name::read`,
//! `BinDecoder`, `RData::read`), except that an OPT record's options are checked here as raw
//! option TLVs instead of going through hickory's `OPT` type: that keeps a query's OPT
//! allocation-free (build-and-test.md §4) and refuses malformed option lists, which hickory's
//! `OPT` decoder silently empties.
//!
//! Where hickory reads data that isn't in its type's format, [`read_item`] refuses the record
//! itself, in whatever section it is and whether or not the scrub would keep it (edge.md §7 step
//! 1, "the formats of the types it knows"): empty data for a type that needs data, an empty TXT,
//! an NSEC/NSEC3 type bitmap that breaks its framing, and SVCB/HTTPS parameters RFC 9460 forbids
//! ([`crate::svcb`]).

use std::ops::Range;

use hickory_proto::rr::rdata::{HTTPS, NULL};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, Restrict};

use crate::types::rtype;
use crate::wire::get_u16;

/// One record read from a message. Returned by value and matched at once, so the size
/// difference between the variants costs nothing worth an allocation per record.
#[expect(
    clippy::large_enum_variant,
    reason = "returned by value and matched at once: boxing would allocate per record"
)]
pub(crate) enum Item {
    Record(ReadRecord),
    Opt(OptRecord),
}

/// A non-OPT record as hickory decoded it, with the wire fields policy needs.
pub(crate) struct ReadRecord {
    pub rec: Record,
    pub rtype: u16,
    pub class: u16,
}

/// An OPT pseudo-record (RFC 6891 §6.1.2). `options` indexes the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OptRecord {
    pub udp: u16,
    pub ext_rcode: u8,
    pub version: u8,
    pub flags: u16,
    pub options: Range<usize>,
    pub count: u16,
}

impl OptRecord {
    pub(crate) fn do_bit(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ItemError {
    /// hickory couldn't decode the record.
    Decode,
    /// An OPT record whose owner isn't the root, or whose options don't exactly fill its data.
    MalformedOpt,
    /// An SVCB or HTTPS record hickory decoded whose parameters RFC 9460 forbids (§2.2: the
    /// record is malformed), such as a `port` with bytes past its value.
    BadSvcb,
}

/// Reads one record at the decoder's position.
pub(crate) fn read_item(dec: &mut BinDecoder<'_>) -> Result<Item, ItemError> {
    let name = Name::read(dec).map_err(|_| ItemError::Decode)?;
    let rtype = read_u16(dec)?;
    let class = read_u16(dec)?;
    let ttl = dec
        .read_u32()
        .map_err(|_| ItemError::Decode)?
        .unverified(/*any u32*/);
    let rdlen = read_u16(dec)?;
    if usize::from(rdlen) > dec.len() {
        return Err(ItemError::Decode);
    }
    if rtype == rtype::OPT {
        if !name.is_root() {
            return Err(ItemError::MalformedOpt);
        }
        let start = dec.index();
        let data = dec
            .read_slice(usize::from(rdlen))
            .map_err(|_| ItemError::Decode)?
            .unverified(/*walked below*/);
        let count = count_options(data).ok_or(ItemError::MalformedOpt)?;
        let [ext_rcode, version, f0, f1] = ttl.to_be_bytes();
        return Ok(Item::Opt(OptRecord {
            udp: class,
            ext_rcode,
            version,
            flags: u16::from_be_bytes([f0, f1]),
            options: start..start.saturating_add(usize::from(rdlen)),
            count,
        }));
    }
    let record_type = RecordType::from(rtype);
    // hickory's `Record::read` takes empty RDATA as RFC 2136's "no data" form for any type,
    // skipping the type's format. Outside UPDATE that's malformed wherever the type's own
    // decoder refuses empty data (an A, a DS, a CNAME, …), so it is refused here; types whose
    // empty form is valid (NULL, unknown types) keep hickory's representation.
    let rdata_at = dec.index();
    let alias = if matches!(rtype, rtype::SVCB | rtype::HTTPS) {
        let at = u16::try_from(rdata_at).map_err(|_| ItemError::Decode)?;
        let raw = dec
            .clone(at)
            .read_slice(usize::from(rdlen))
            .map_err(|_| ItemError::Decode)?
            .unverified(/*checked by svcb::alias*/);
        crate::svcb::is_alias_rdata(raw).then_some(raw)
    } else {
        None
    };
    let rdata = if let Some(raw) = alias {
        // AliasMode: its structure is checked and its bytes kept as received, never handed to
        // hickory's parameter decoder (RFC 9460 §2.4.2; crate::svcb).
        match crate::svcb::alias(raw) {
            Ok(_) => {}
            Err(crate::svcb::AliasError::Malformed) => return Err(ItemError::Decode),
            Err(crate::svcb::AliasError::Compressed) => return Err(ItemError::BadSvcb),
        }
        let data = raw.to_vec();
        dec.read_slice(usize::from(rdlen))
            .map_err(|_| ItemError::Decode)?;
        RData::Unknown {
            code: record_type,
            rdata: NULL::with(data),
        }
    } else if rdlen == 0 {
        // RFC 1035 §3.3.14: TXT data is one or more character strings.
        if rtype == rtype::TXT {
            return Err(ItemError::Decode);
        }
        let empty: [u8; 0] = [];
        let mut d = BinDecoder::new(&empty);
        RData::read(&mut d, record_type, Restrict::new(0)).map_err(|_| ItemError::Decode)?;
        RData::Update0(record_type)
    } else {
        match RData::read(dec, record_type, Restrict::new(rdlen)) {
            Ok(d) => d,
            Err(_) if matches!(rtype, rtype::NSEC3 | rtype::NSEC3PARAM) => {
                let at = u16::try_from(rdata_at).map_err(|_| ItemError::Decode)?;
                let mut raw = dec.clone(at);
                let data = raw
                    .read_slice(usize::from(rdlen))
                    .map_err(|_| ItemError::Decode)?
                    .unverified(/*checked by nsec3_unknown_values*/);
                let opaque = nsec3_unknown_values(rtype, data).ok_or(ItemError::Decode)?;
                *dec = raw;
                opaque
            }
            Err(_) => return Err(ItemError::Decode),
        }
    };
    if matches!(rtype, rtype::NSEC | rtype::NSEC3) && !type_bitmap_ok(dec, rdata_at, rtype, rdlen) {
        return Err(ItemError::Decode);
    }
    if let RData::SVCB(s) | RData::HTTPS(HTTPS(s)) = &rdata {
        let at = u16::try_from(rdata_at).map_err(|_| ItemError::Decode)?;
        let raw = dec
            .clone(at)
            .read_slice(usize::from(rdlen))
            .map_err(|_| ItemError::Decode)?
            .unverified(/*compared with hickory's re-encoding*/);
        if !crate::svcb::check(s, raw) {
            return Err(ItemError::BadSvcb);
        }
    }
    let mut rec = Record::from_rdata(name, ttl, rdata);
    rec.dns_class = DNSClass::from(class);
    Ok(Item::Record(ReadRecord { rec, rtype, class }))
}

/// NSEC3 or NSEC3PARAM data hickory refused only for its hash algorithm or flags, kept as opaque
/// bytes. hickory 0.26 knows only hash algorithm 1 and refuses undefined flag bits, but a
/// validator ignores such records (RFC 5155 §8.1, §8.2, §4.1.2) and a forwarder passes them
/// through (RFC 3597). The format is still checked: a copy with algorithm 1 and only the defined
/// flag (opt-out, bit 0) must decode, filling the data exactly. The data holds no names, so the
/// bytes are safe to copy (edge.md §7 step 1). `None` when the data is malformed anyway.
fn nsec3_unknown_values(rtype: u16, data: &[u8]) -> Option<RData> {
    let (alg, flags) = (*data.first()?, *data.get(1)?);
    let known_flags = if rtype == rtype::NSEC3 { flags & 0x01 } else { 0 };
    if alg == 1 && flags == known_flags {
        return None; // refused for another reason
    }
    let mut copy = data.to_vec();
    *copy.first_mut()? = 1;
    *copy.get_mut(1)? = known_flags;
    let len = u16::try_from(copy.len()).ok()?;
    let mut d = BinDecoder::new(&copy);
    RData::read(&mut d, RecordType::from(rtype), Restrict::new(len)).ok()?;
    if !d.is_empty() {
        return None;
    }
    Some(RData::Unknown {
        code: RecordType::from(rtype),
        rdata: NULL::with(data.to_vec()),
    })
}

/// RFC 4034 §4.1.2 / RFC 5155 §3.2.1: the type bitmap of an NSEC or NSEC3 record hickory
/// decoded is window blocks in increasing order, each with a length of 1 to 32 that its bytes
/// fill exactly. hickory keeps the bitmap's original bytes without checking that framing.
fn type_bitmap_ok(dec: &BinDecoder<'_>, rdata_at: usize, rtype: u16, rdlen: u16) -> bool {
    let Ok(at) = u16::try_from(rdata_at) else {
        return false;
    };
    let mut d = dec.clone(at);
    let fixed = if rtype == rtype::NSEC {
        // The next owner name, read as hickory read it.
        if Name::read(&mut d).is_err() {
            return false;
        }
        d.index().saturating_sub(rdata_at)
    } else {
        // Hash algorithm, flags, iterations, salt, hash.
        let Ok(head) = d.read_slice(4) else {
            return false;
        };
        let _ = head;
        let Ok(salt_len) = d.read_u8() else {
            return false;
        };
        if d.read_slice(usize::from(salt_len.unverified())).is_err() {
            return false;
        }
        let Ok(hash_len) = d.read_u8() else {
            return false;
        };
        if d.read_slice(usize::from(hash_len.unverified())).is_err() {
            return false;
        }
        d.index().saturating_sub(rdata_at)
    };
    let Some(len) = usize::from(rdlen).checked_sub(fixed) else {
        return false;
    };
    let Ok(bitmap) = d.read_slice(len) else {
        return false;
    };
    let bitmap = bitmap.unverified();
    let mut rest = bitmap;
    let mut last: Option<u8> = None;
    while let [window, blen, tail @ ..] = rest {
        let blen = usize::from(*blen);
        if blen == 0 || blen > 32 || last.is_some_and(|l| *window <= l) || tail.len() < blen {
            return false;
        }
        last = Some(*window);
        rest = tail.get(blen..).unwrap_or(&[]);
    }
    rest.is_empty()
}

fn read_u16(dec: &mut BinDecoder<'_>) -> Result<u16, ItemError> {
    Ok(dec
        .read_u16()
        .map_err(|_| ItemError::Decode)?
        .unverified(/*any u16*/))
}

/// Counts the option TLVs in OPT data; `None` unless they fill it exactly (RFC 6891 §6.1.2).
fn count_options(data: &[u8]) -> Option<u16> {
    let mut dec = BinDecoder::new(data);
    let mut n: u16 = 0;
    while !dec.is_empty() {
        let _code = dec.read_u16().ok()?;
        let len = dec.read_u16().ok()?.unverified(/*bounded by read_slice*/);
        dec.read_slice(usize::from(len)).ok()?;
        n = n.checked_add(1)?;
    }
    Some(n)
}

/// The options of an OPT record as `(code, payload)` pairs. Built only over option data whose
/// TLVs were checked to fill it exactly.
#[derive(Clone, Debug)]
pub struct EdnsOptions<'m> {
    rest: &'m [u8],
}

impl<'m> EdnsOptions<'m> {
    pub(crate) fn new(checked: &'m [u8]) -> Self {
        Self { rest: checked }
    }

    pub(crate) fn empty() -> Self {
        Self { rest: &[] }
    }
}

impl<'m> Iterator for EdnsOptions<'m> {
    type Item = (u16, &'m [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let code = get_u16(self.rest, 0)?;
        let len = usize::from(get_u16(self.rest, 2)?);
        let end = len.checked_add(4)?;
        let payload = self.rest.get(4..end)?;
        self.rest = self.rest.get(end..)?;
        Some((code, payload))
    }
}

/// An Extended DNS Error option payload (RFC 8914 §2): INFO-CODE and EXTRA-TEXT. `None` when
/// the payload is shorter than the INFO-CODE.
pub(crate) fn parse_ede(payload: &[u8]) -> Option<(u16, &[u8])> {
    Some((get_u16(payload, 0)?, payload.get(2..)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_iterate_and_count() {
        let data = [0, 10, 0, 2, 0xAA, 0xBB, 0, 12, 0, 0];
        assert_eq!(count_options(&data), Some(2));
        let v: Vec<_> = EdnsOptions::new(&data).collect();
        assert_eq!(v, vec![(10, &[0xAA, 0xBB][..]), (12, &[][..])]);
        assert_eq!(count_options(&[0, 10, 0, 3, 1]), None);
        assert_eq!(count_options(&[0, 10, 0]), None);
        assert_eq!(count_options(&[]), Some(0));
    }

    #[test]
    fn ede_payload() {
        assert_eq!(parse_ede(&[0, 15, b'h', b'i']), Some((15, &b"hi"[..])));
        assert_eq!(parse_ede(&[0, 3]), Some((3, &b""[..])));
        assert_eq!(parse_ede(&[0]), None);
    }
}
