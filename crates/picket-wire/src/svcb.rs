//! RFC 9460 checks on SVCB and HTTPS records hickory decoded, and the facts response checks use:
//! the target name and the `ipv4hint`/`ipv6hint` addresses (rules.md §6).
//!
//! [`check`] runs on every SVCB/HTTPS record as it is read, in any section of a query or an
//! upstream answer, whether or not the scrub keeps it: a record that fails is malformed (RFC 9460
//! §2.2), like one hickory can't decode (edge.md §4 "Parsing", §7 step 1).
//!
//! hickory's decoder already refuses SvcParamKeys that aren't in strictly increasing numeric
//! order (so duplicates too), hints that aren't whole addresses, and empty `alpn` or
//! `mandatory` lists. On top of that, a ServiceMode record (priority above 0) is refused when:
//! - an `alpn` holds an empty protocol id (RFC 9460 §7.1.1; RFC 7301 §3.1: "Empty strings MUST
//!   NOT be included");
//! - an `ipv4hint` or `ipv6hint` is empty (RFC 9460 §7.3: "An empty list of addresses is
//!   invalid");
//! - `mandatory` isn't strictly increasing, lists `mandatory` itself, or names a key the record
//!   doesn't have (RFC 9460 §8);
//! - a parameter defined after RFC 9460 that hickory keeps opaque breaks its own format:
//!   `dohpath` not UTF-8 (RFC 9461 §5), `ohttp` not empty (RFC 9540 §4), `tls-supported-groups`
//!   empty or of odd length (a list of 16-bit groups);
//! - hickory's re-encoding of the RDATA isn't the received RDATA byte for byte: a parameter with
//!   bytes past its value (a 3-byte `port`, RFC 9460 §7.2) or a compressed target name (RFC 9460
//!   §2.2) that hickory read and would otherwise silently fix. Comparing bytes, not lengths,
//!   catches each on its own, so one can't hide another (a pointer that expands by as many bytes
//!   as a `port` carries past its value).
//!
//! An AliasMode record (priority 0) is checked only for an uncompressed target: recipients MUST
//! ignore its SvcParams (RFC 9460 §2.4.2), so they are neither checked nor give hints. hickory
//! still decodes them, so what its decoder refuses (above) still makes the record malformed.

use std::net::IpAddr;

use hickory_proto::rr::rdata::SVCB;
use hickory_proto::rr::rdata::svcb::{Alpn, IpHint, Mandatory, SvcParamKey, SvcParamValue, Unknown};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict};

use crate::answer::{AddrSource, AnswerAddr};
use crate::name::WireName;
use crate::types::rtype;

/// What response checks and the firewall use from an HTTPS/SVCB record (rules.md §6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SvcbFacts {
    /// The target name, unless it is the root (`.`).
    pub target: Option<WireName>,
    /// `ipv4hint` then `ipv6hint` addresses.
    pub hints: Vec<AnswerAddr>,
}

/// The facts of uncompressed HTTPS or SVCB RDATA, such as a `$dnsrewrite` value the edge answers
/// with (edge.md §4: a rewrite's addresses go to the firewall). hickory decodes it; `None` when it
/// can't, or when RFC 9460 forbids its parameters.
pub fn rdata_facts(record_type: u16, rdata: &[u8]) -> Option<SvcbFacts> {
    if !matches!(record_type, rtype::SVCB | rtype::HTTPS) {
        return None;
    }
    let len = u16::try_from(rdata.len()).ok()?;
    let mut d = BinDecoder::new(rdata);
    let svcb = match RData::read(&mut d, RecordType::from(record_type), Restrict::new(len)).ok()? {
        RData::SVCB(s) => s,
        RData::HTTPS(h) => h.0,
        _ => return None,
    };
    if !d.is_empty() || !check(&svcb, rdata) {
        return None;
    }
    let target = if svcb.target_name.is_root() {
        None
    } else {
        Some(WireName::from_hickory(&svcb.target_name).ok()?)
    };
    let hints = hints(&svcb)
        .map(|(ip, v4)| AnswerAddr {
            ip,
            source: if v4 {
                AddrSource::Ipv4Hint
            } else {
                AddrSource::Ipv6Hint
            },
        })
        .collect();
    Some(SvcbFacts { target, hints })
}

/// SvcParamKeys registered after RFC 9460 (IANA "Service Parameter Keys").
const DOHPATH: u16 = 7;
const OHTTP: u16 = 8;
const TLS_SUPPORTED_GROUPS: u16 = 9;

/// Checks a decoded SVCB/HTTPS record against RFC 9460; `raw` is its RDATA as received.
pub(crate) fn check(svcb: &SVCB, raw: &[u8]) -> bool {
    // hickory writes the target uncompressed and in its received case, and every value in its
    // wire form, so a well-formed RDATA re-encodes to exactly its received bytes.
    let mut buf = Vec::with_capacity(raw.len());
    let mut enc = BinEncoder::new(&mut buf);
    if is_alias(svcb) {
        // RFC 9460 §2.4.2: the SvcParams are ignored; the priority and target must be as read.
        return svcb.svc_priority.emit(&mut enc).is_ok()
            && svcb.target_name.emit(&mut enc).is_ok()
            && raw.starts_with(&buf);
    }
    for (key, value) in &svcb.svc_params {
        if let SvcParamValue::Unknown(Unknown(data)) = value {
            let ok = match u16::from(*key) {
                DOHPATH => std::str::from_utf8(data).is_ok(),
                OHTTP => data.is_empty(),
                TLS_SUPPORTED_GROUPS => !data.is_empty() && data.len() % 2 == 0,
                _ => true,
            };
            if !ok {
                return false;
            }
        }
        match value {
            SvcParamValue::Alpn(Alpn(ids)) if ids.iter().any(String::is_empty) => return false,
            SvcParamValue::Ipv4Hint(IpHint(v)) if v.is_empty() => return false,
            SvcParamValue::Ipv6Hint(IpHint(v)) if v.is_empty() => return false,
            SvcParamValue::Mandatory(Mandatory(list)) if !mandatory_ok(list, svcb) => return false,
            _ => {}
        }
    }
    svcb.emit(&mut enc).is_ok() && buf == raw
}

/// An AliasMode record (RFC 9460 §2.4.2): priority 0.
fn is_alias(svcb: &SVCB) -> bool {
    svcb.svc_priority == 0
}

/// RFC 9460 §8: the `mandatory` keys strictly increase, never name `mandatory` itself, and are
/// each in the record. hickory keeps the record's keys strictly increasing, so one merge pass over
/// both lists does it.
fn mandatory_ok(list: &[SvcParamKey], svcb: &SVCB) -> bool {
    let mut present = svcb.svc_params.iter().map(|(k, _)| u16::from(*k)).peekable();
    let mut last: Option<u16> = None;
    for k in list.iter().map(|k| u16::from(*k)) {
        if k == u16::from(SvcParamKey::Mandatory) || last.is_some_and(|l| k <= l) {
            return false;
        }
        last = Some(k);
        while present.next_if(|p| *p < k).is_some() {}
        if present.next_if_eq(&k).is_none() {
            return false;
        }
    }
    true
}

/// The hint addresses of a checked record, in order: `ipv4hint` then `ipv6hint`. An AliasMode
/// record has none: its SvcParams are ignored (RFC 9460 §2.4.2).
pub(crate) fn hints(svcb: &SVCB) -> impl Iterator<Item = (IpAddr, bool)> + '_ {
    let params: &[(SvcParamKey, SvcParamValue)] = if is_alias(svcb) { &[] } else { &svcb.svc_params };
    params.iter().flat_map(|(_, v)| {
        let (v4, v6): (&[hickory_proto::rr::rdata::A], &[hickory_proto::rr::rdata::AAAA]) = match v {
            SvcParamValue::Ipv4Hint(IpHint(h)) => (h.as_slice(), &[]),
            SvcParamValue::Ipv6Hint(IpHint(h)) => (&[], h.as_slice()),
            _ => (&[], &[]),
        };
        v4.iter()
            .map(|a| (IpAddr::V4(a.0), true))
            .chain(v6.iter().map(|a| (IpAddr::V6(a.0), false)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{a, aaaa, svcb as svcb_rdata};

    #[test]
    fn rewrite_rdata_facts() {
        let data = svcb_rdata(
            1,
            "pool.example",
            &[
                (1, b"\x02h2".to_vec()),
                (4, a("192.0.2.1")),
                (6, aaaa("::ffff:192.0.2.2")),
            ],
        );
        let f = rdata_facts(rtype::HTTPS, &data).unwrap();
        assert_eq!(f.target.unwrap().log_text(), "pool.example");
        assert_eq!(f.hints.len(), 2);
        assert_eq!(
            f.hints[1].mapped_v4(),
            Some(std::net::Ipv4Addr::new(192, 0, 2, 2))
        );
        let f = rdata_facts(rtype::SVCB, &svcb_rdata(0, ".", &[])).unwrap();
        assert!(f.target.is_none() && f.hints.is_empty());
        assert!(rdata_facts(rtype::HTTPS, &svcb_rdata(1, ".", &[(4, vec![])])).is_none());
        assert!(rdata_facts(rtype::HTTPS, &[0, 1]).is_none());
        assert!(rdata_facts(rtype::A, &[1, 2, 3, 4]).is_none());
    }
}
