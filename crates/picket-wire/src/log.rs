//! What a `q` log record carries about an answer (api.md §5): the `answer` wire (at most 4 KiB),
//! the `response` the edge made (at most 2 KiB), and the preview: at most 4 IPs and 4 target
//! names, the deciding value first on a response-phase block, with `truncated` when the answer
//! didn't fit; and the `answer` record's id, which edge and core both compute here.

use std::net::IpAddr;

use crate::answer::AnswerFacts;
use crate::name::WireName;

/// The largest `answer` wire logged; a larger answer isn't sent and records referencing it are
/// `truncated`.
pub const ANSWER_WIRE_MAX: usize = 4096;
/// The largest `response` logged.
pub const RESPONSE_MAX: usize = 2048;
/// The most entries in `answers` and in `targets`.
pub const PREVIEW_MAX: usize = 4;

/// The `id` of an `answer` log record as a number: the first 8 bytes of the BLAKE3 of its decoded
/// `wire`, big-endian (api.md §5), so [`answer_id_text`] is the hash's first 16 hex characters.
pub fn answer_id(wire: &[u8]) -> u64 {
    let hash = picket_api::ids::object_id(wire);
    u64::from_str_radix(picket_api::ids::short_id(&hash), 16).unwrap_or(0)
}

/// An `answer` record id as the log writes it: 16 lowercase hex characters.
pub fn answer_id_text(id: u64) -> String {
    format!("{id:016x}")
}

/// True when an answer wire is small enough to log.
pub fn answer_fits(wire: &[u8]) -> bool {
    wire.len() <= ANSWER_WIRE_MAX
}

/// True when a reply the edge made is small enough to log as `response`.
pub fn response_fits(reply: &[u8]) -> bool {
    reply.len() <= RESPONSE_MAX
}

/// An IP as log text, as Go's `net.IP.String()` writes it (AdGuard Home's form, rules.md §1):
/// an IPv4-mapped IPv6 address prints as dotted IPv4.
pub fn ip_text(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// The preview of an answer for a log record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Preview {
    /// A/AAAA addresses, then HTTPS/SVCB hints; at most [`PREVIEW_MAX`].
    pub answers: Vec<IpAddr>,
    /// HTTPS/SVCB target names; at most [`PREVIEW_MAX`].
    pub targets: Vec<WireName>,
    /// Some address or target didn't fit the preview.
    pub cut: bool,
}

impl Preview {
    /// The preview of `facts`, with `deciding_ip` or `deciding_target` (a response-phase
    /// block's deciding value) first.
    pub fn of(facts: &AnswerFacts, deciding_ip: Option<IpAddr>, deciding_target: Option<&WireName>) -> Self {
        let mut answers: Vec<IpAddr> = Vec::with_capacity(PREVIEW_MAX);
        let mut cut = false;
        let ips = deciding_ip.into_iter().chain(facts.addrs.iter().map(|a| a.ip));
        for ip in ips {
            if answers.contains(&ip) {
                continue;
            }
            if answers.len() == PREVIEW_MAX {
                cut = true;
                break;
            }
            answers.push(ip);
        }
        let mut targets: Vec<WireName> = Vec::with_capacity(PREVIEW_MAX);
        for t in deciding_target.into_iter().chain(facts.targets.iter()) {
            if targets.contains(t) {
                continue;
            }
            if targets.len() == PREVIEW_MAX {
                cut = true;
                break;
            }
            targets.push(t.clone());
        }
        Self {
            answers,
            targets,
            cut,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answer::{AddrSource, AnswerAddr};

    fn facts(n: u8) -> AnswerFacts {
        AnswerFacts {
            rcode: 0,
            tc: false,
            aa: false,
            chain: vec![],
            addrs: (1..=n)
                .map(|i| AnswerAddr {
                    ip: IpAddr::from([192, 0, 2, i]),
                    source: AddrSource::A,
                })
                .collect(),
            targets: vec![],
            ede: vec![],
            ede_dropped: 0,
            stale: false,
            negative: None,
            soa: false,
            min_ttl: None,
            negative_ttl: None,
            cache_ttl: None,
        }
    }

    #[test]
    fn preview_caps_and_orders() {
        let p = Preview::of(&facts(3), None, None);
        assert_eq!(p.answers.len(), 3);
        assert!(!p.cut);
        let p = Preview::of(&facts(6), Some(IpAddr::from([192, 0, 2, 6])), None);
        assert_eq!(p.answers[0], IpAddr::from([192, 0, 2, 6]));
        assert_eq!(p.answers.len(), 4);
        assert!(p.cut);
    }

    #[test]
    fn ip_text_like_go() {
        assert_eq!(ip_text("::ffff:192.0.2.1".parse().unwrap()), "192.0.2.1");
        assert_eq!(ip_text("2001:db8::1".parse().unwrap()), "2001:db8::1");
        assert_eq!(ip_text("0.0.0.0".parse().unwrap()), "0.0.0.0");
        assert_eq!(ip_text("::".parse().unwrap()), "::");
    }

    #[test]
    fn answer_ids() {
        let wire = b"\x12\x34\x81\x80";
        let id = answer_id(wire);
        let text = answer_id_text(id);
        assert_eq!(text.len(), 16);
        assert_eq!(text, picket_api::ids::short_id(&picket_api::ids::object_id(wire)));
        assert_ne!(answer_id(b"other"), id);
        assert_eq!(answer_id_text(1), "0000000000000001");
    }

    #[test]
    fn limits() {
        assert!(answer_fits(&[0; 4096]));
        assert!(!answer_fits(&[0; 4097]));
        assert!(response_fits(&[0; 2048]));
        assert!(!response_fits(&[0; 2049]));
    }
}
