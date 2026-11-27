//! The DO=0 predicate (edge.md §7 step 4, RFC 3225): a response to a client that didn't set DO
//! leaves out only unsolicited DNSSEC records: RRSIG, NSEC, NSEC3, DNSKEY, DS and DNAME records,
//! except those of the type asked for. Where a DNAME is left out, its synthesised CNAME stays.
//!
//! The edge applies it when it builds a cache entry's DO=0 copy at insert, and core when it
//! rebuilds the reply a client got (core.md §6): both call [`strip_for_do0`].

use crate::types::rtype;

/// True when a record of `record_type` is left out of the answer to a DO=0 query for `qtype`.
pub fn strip_for_do0(record_type: u16, qtype: u16) -> bool {
    matches!(
        record_type,
        rtype::RRSIG | rtype::NSEC | rtype::NSEC3 | rtype::DNSKEY | rtype::DS | rtype::DNAME
    ) && record_type != qtype
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate() {
        for t in [
            rtype::RRSIG,
            rtype::NSEC,
            rtype::NSEC3,
            rtype::DNSKEY,
            rtype::DS,
            rtype::DNAME,
        ] {
            assert!(strip_for_do0(t, rtype::A));
            assert!(!strip_for_do0(t, t), "the asked type stays");
        }
        assert!(!strip_for_do0(rtype::CNAME, rtype::A));
        assert!(!strip_for_do0(rtype::SOA, rtype::A));
        assert!(!strip_for_do0(rtype::A, rtype::A));
        // ANY isn't the type of an RRSIG: DNSSEC records are still left out.
        assert!(strip_for_do0(rtype::RRSIG, rtype::ANY));
        // A query for RRSIG keeps RRSIGs but not NSEC.
        assert!(!strip_for_do0(rtype::RRSIG, rtype::RRSIG));
        assert!(strip_for_do0(rtype::NSEC, rtype::RRSIG));
    }
}
