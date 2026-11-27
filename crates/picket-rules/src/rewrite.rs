//! `$dnsrewrite` (rules.md §4): parsing as urlfilter v0.23 does, the merge AdGuard Home's
//! `processDNSRewrites` applies, and the `@@…$dnsrewrite` cancellation of urlfilter's
//! `DNSResult.DNSRewrites`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::ip::{netip_string, parse_go_ip};
use crate::name::validate_rewrite_host;
use crate::rrtype::{parse_rcode, parse_rr_type, rcodes, types};

/// The record data a rewrite returns.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteValue {
    /// A or AAAA (an AAAA value may be IPv4-mapped).
    Ip(IpAddr),
    /// TXT text, as written.
    Text(String),
    /// PTR target, fully qualified (trailing dot).
    Ptr(String),
    /// MX.
    Mx { preference: u16, exchange: String },
    /// SRV.
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// HTTPS or SVCB: priority, target (`.` allowed) and `key=value` parameters, sorted by key.
    Svcb {
        priority: u16,
        target: String,
        params: Vec<(String, String)>,
    },
}

impl RewriteValue {
    /// Canonical text, as the urlfilter oracle prints it (PARITY.md).
    pub fn to_text(&self) -> String {
        match self {
            RewriteValue::Ip(ip) => netip_string(*ip),
            RewriteValue::Text(t) => t.clone(),
            RewriteValue::Ptr(p) => p.clone(),
            RewriteValue::Mx { preference, exchange } => format!("{preference} {exchange}"),
            RewriteValue::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {target}"),
            RewriteValue::Svcb {
                priority,
                target,
                params,
            } => {
                let mut s = format!("{priority} {target}");
                for (k, v) in params {
                    s.push(' ');
                    s.push_str(k);
                    s.push('=');
                    s.push_str(v);
                }
                s
            }
        }
    }
}

/// One `$dnsrewrite` value (urlfilter `DNSRewrite`). The empty value (`$dnsrewrite` with nothing,
/// or `NOERROR;;`) is all-zero: as an exception it cancels every other (non-important) rewrite.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DnsRewrite {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rcode: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rrtype: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<RewriteValue>,
    /// A CNAME rewrite's target, as written (an IDN as its A-label form).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
}

fn is_zero(v: &u16) -> bool {
    *v == 0
}

impl DnsRewrite {
    /// True for the empty value.
    pub fn is_empty(&self) -> bool {
        *self == DnsRewrite::default()
    }

    /// True when it returns records (a CNAME, or a value under NOERROR): the `redirects` option of
    /// `rule_policy` (feeds.md §8). An rcode-only rewrite is a block.
    pub fn returns_records(&self) -> bool {
        self.cname.is_some() || (self.rcode == rcodes::NOERROR && self.rrtype != 0 && self.value.is_some())
    }
}

/// Parses an option value (urlfilter `parseDNSRewrite`). `None` when AdGuard refuses it.
pub fn parse_dnsrewrite(s: &str) -> Option<DnsRewrite> {
    let parts: Vec<&str> = s.splitn(3, ';').collect();
    match parts.as_slice() {
        [short] => parse_short(short),
        [rcode, rr, value] => parse_normal(rcode, rr, value),
        _ => None,
    }
}

fn parse_short(s: &str) -> Option<DnsRewrite> {
    if s.is_empty() {
        return Some(DnsRewrite::default());
    }
    if s.bytes().all(|b| b.is_ascii_uppercase()) {
        return match s {
            "NOERROR" | "SERVFAIL" | "NXDOMAIN" | "REFUSED" => Some(DnsRewrite {
                rcode: parse_rcode(s)?,
                ..DnsRewrite::default()
            }),
            _ => None,
        };
    }
    if let Some(ip) = parse_go_ip(s) {
        if s.contains('%') {
            return None;
        }
        let rrtype = if ip.is_ipv4() { types::A } else { types::AAAA };
        return Some(DnsRewrite {
            rcode: 0,
            rrtype,
            value: Some(RewriteValue::Ip(ip)),
            cname: None,
        });
    }
    let host = validate_rewrite_host(s)?;
    Some(DnsRewrite {
        cname: Some(host),
        ..DnsRewrite::default()
    })
}

fn parse_normal(rcode: &str, rr: &str, value: &str) -> Option<DnsRewrite> {
    let rcode = parse_rcode(rcode)?;
    if rcode != rcodes::NOERROR || (rr.is_empty() && value.is_empty()) {
        return Some(DnsRewrite {
            rcode,
            ..DnsRewrite::default()
        });
    }
    let rrtype = parse_rr_type(rr)?;
    let v = |value: RewriteValue| {
        Some(DnsRewrite {
            rcode,
            rrtype,
            value: Some(value),
            cname: None,
        })
    };
    match rrtype {
        types::A => match parse_go_ip(value) {
            Some(ip @ IpAddr::V4(_)) => v(RewriteValue::Ip(ip)),
            _ => None,
        },
        types::AAAA => match parse_go_ip(value) {
            Some(ip @ IpAddr::V6(_)) if !value.contains('%') => v(RewriteValue::Ip(ip)),
            _ => None,
        },
        types::CNAME => Some(DnsRewrite {
            cname: Some(validate_rewrite_host(value)?),
            ..DnsRewrite::default()
        }),
        types::MX => {
            let (pref, exch) = value.split_once(' ')?;
            let preference = parse_u16(pref)?;
            v(RewriteValue::Mx {
                preference,
                exchange: validate_rewrite_host(exch)?,
            })
        }
        types::PTR => {
            let bare = value.strip_suffix('.').unwrap_or(value);
            let host = validate_rewrite_host(bare)?;
            v(RewriteValue::Ptr(format!("{host}.")))
        }
        types::TXT => v(RewriteValue::Text(value.to_string())),
        types::SRV => {
            let f: Vec<&str> = value.split(' ').collect();
            let (Some(p), Some(w), Some(port), Some(t)) = (f.first(), f.get(1), f.get(2), f.get(3)) else {
                return None;
            };
            let target = if *t == "." {
                ".".to_string()
            } else {
                validate_rewrite_host(t)?
            };
            v(RewriteValue::Srv {
                priority: parse_u16(p)?,
                weight: parse_u16(w)?,
                port: parse_u16(port)?,
                target,
            })
        }
        types::HTTPS | types::SVCB => {
            let f: Vec<&str> = value.split(' ').collect();
            let (Some(p), Some(t)) = (f.first(), f.get(1)) else {
                return None;
            };
            let priority = parse_u16(p)?;
            let target = if *t == "." {
                ".".to_string()
            } else {
                validate_rewrite_host(t)?
            };
            let mut params: Vec<(String, String)> = Vec::new();
            for pair in f.get(2..).unwrap_or(&[]) {
                let kv: Vec<&str> = pair.split('=').collect();
                let [k, val] = kv.as_slice() else { return None };
                // Go keeps the last value of a repeated key (a map).
                params.retain(|(pk, _)| pk != k);
                params.push(((*k).to_string(), (*val).to_string()));
            }
            params.sort();
            v(RewriteValue::Svcb {
                priority,
                target,
                params,
            })
        }
        // Types without a handler keep only rcode and type (urlfilter).
        _ => Some(DnsRewrite {
            rcode,
            rrtype,
            value: None,
            cname: None,
        }),
    }
}

/// Go `strconv.ParseUint(s, 10, 16)`.
fn parse_u16(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// A rewrite candidate for the merge: its value, whether it is `$important` and an exception.
#[derive(Clone, Debug)]
pub struct RewriteCandidate<'a> {
    /// The rewrite.
    pub rewrite: &'a DnsRewrite,
    /// `$important`.
    pub important: bool,
    /// `@@` rule.
    pub exception: bool,
}

/// urlfilter `DNSResult.DNSRewrites`: applies each `@@…$dnsrewrite` in order and returns the
/// indices (into `cands`) of the rewrites left, in order, and of those each exception removed.
pub fn apply_rewrite_exceptions(cands: &[RewriteCandidate<'_>]) -> (Vec<usize>, Vec<usize>) {
    let (left, removed) = apply_rewrite_exceptions_by(cands);
    (left, removed.into_iter().map(|(r, _)| r).collect())
}

/// As [`apply_rewrite_exceptions`], with each removed rewrite paired with the exception (index
/// into `cands`) that removed it.
pub fn apply_rewrite_exceptions_by(cands: &[RewriteCandidate<'_>]) -> (Vec<usize>, Vec<(usize, usize)>) {
    let mut live: Vec<usize> = (0..cands.len()).collect();
    let mut removed = Vec::new();
    let mut i = 0usize;
    while let Some(&idx) = live.get(i) {
        let Some(exc) = cands.get(idx) else { break };
        if !exc.exception {
            i = i.saturating_add(1);
            continue;
        }
        live.remove(i);
        let before = live.clone();
        if exc.rewrite.is_empty() {
            if exc.important {
                live.clear();
            } else {
                live.retain(|&j| cands.get(j).is_some_and(|c| c.important));
            }
        } else {
            live.retain(|&j| cands.get(j).is_none_or(|nr| !exception_cancels(nr, exc)));
        }
        removed.extend(before.into_iter().filter(|j| !live.contains(j)).map(|j| (j, idx)));
    }
    (live, removed)
}

/// urlfilter `matchException`. Go compares record values with `==` on interface values, so MX,
/// SRV and HTTPS/SVCB values (pointers) never match.
fn exception_cancels(nr: &RewriteCandidate<'_>, exc: &RewriteCandidate<'_>) -> bool {
    if !exc.important && nr.important {
        return false;
    }
    let (n, e) = (nr.rewrite, exc.rewrite);
    if let Some(ec) = &e.cname {
        return n.cname.as_deref() == Some(ec.as_str());
    }
    if n.rcode == e.rcode {
        if e.rcode != rcodes::NOERROR {
            return true;
        }
        if n.rrtype == e.rrtype {
            return match (&n.value, &e.value) {
                (None, None) => true,
                (Some(RewriteValue::Ip(a)), Some(RewriteValue::Ip(b))) => a == b,
                (Some(RewriteValue::Text(a)), Some(RewriteValue::Text(b))) => a == b,
                (Some(RewriteValue::Ptr(a)), Some(RewriteValue::Ptr(b))) => a == b,
                _ => false,
            };
        }
    }
    false
}

/// What the rewrites left for a name answer (AdGuard Home `processDNSRewrites`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteAnswer {
    /// A CNAME rewrite: answered as the CNAME plus the target's records (edge.md §4).
    Cname(String),
    /// An rcode other than NOERROR, with no records (`NXDOMAIN;;`, `REFUSED;;`, `SERVFAIL`).
    Rcode(u16),
    /// NOERROR with these records (type, value), deduplicated and sorted; empty means NODATA.
    Records(Vec<(u16, RewriteValue)>),
}

/// Merges the rewrites left, in order: the first CNAME or non-NOERROR rewrite answers alone;
/// otherwise every value merges (AdGuard Home `processDNSRewrites`). Returns the answer and the
/// indices (into `left`) of the rules that shaped it.
pub fn merge_rewrites(left: &[&DnsRewrite]) -> Option<(RewriteAnswer, Vec<usize>)> {
    if left.is_empty() {
        return None;
    }
    let mut records: Vec<(u16, RewriteValue)> = Vec::new();
    let mut used = Vec::new();
    for (i, r) in left.iter().enumerate() {
        if let Some(c) = &r.cname {
            return Some((RewriteAnswer::Cname(c.clone()), vec![i]));
        }
        if r.rcode != rcodes::NOERROR {
            return Some((RewriteAnswer::Rcode(r.rcode), vec![i]));
        }
        if let Some(v) = &r.value {
            records.push((r.rrtype, v.clone()));
        }
        used.push(i);
    }
    records.sort();
    records.dedup();
    Some((RewriteAnswer::Records(records), used))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> DnsRewrite {
        parse_dnsrewrite(s).unwrap_or_else(|| panic!("{s}"))
    }

    #[test]
    fn parses() {
        assert!(p("").is_empty());
        assert!(p("NOERROR;;").is_empty());
        assert_eq!(p("NXDOMAIN;;").rcode, 3);
        assert_eq!(p("REFUSED").rcode, 5);
        assert_eq!(p("nxdomain;;").rcode, 3);
        assert_eq!(p("nxdomain").cname.as_deref(), Some("nxdomain"));
        assert!(parse_dnsrewrite("BOGUS").is_none());
        assert_eq!(
            p("1.2.3.4").value,
            Some(RewriteValue::Ip("1.2.3.4".parse().unwrap()))
        );
        assert_eq!(p("::1").rrtype, 28);
        assert_eq!(p("::ffff:1.2.3.4").rrtype, 28);
        assert_eq!(
            p("Example.ORG").cname.as_deref(),
            Some("Example.ORG"),
            "kept as written (urlfilter)"
        );
        assert!(parse_dnsrewrite("a;b").is_none());
        assert_eq!(p("NOERROR;A;1.2.3.4").rrtype, 1);
        assert!(parse_dnsrewrite("NOERROR;A;::1").is_none());
        assert!(parse_dnsrewrite("NOERROR;AAAA;1.2.3.4").is_none());
        assert_eq!(p("NOERROR;CNAME;x.example").cname.as_deref(), Some("x.example"));
        assert_eq!(
            p("NOERROR;MX;10 mail.example").value,
            Some(RewriteValue::Mx {
                preference: 10,
                exchange: "mail.example".into()
            })
        );
        assert_eq!(
            p("NOERROR;TXT;hello world").value,
            Some(RewriteValue::Text("hello world".into()))
        );
        assert_eq!(
            p("NOERROR;PTR;host.example").value,
            Some(RewriteValue::Ptr("host.example.".into()))
        );
        assert_eq!(
            p("NOERROR;PTR;host.example.").value,
            Some(RewriteValue::Ptr("host.example.".into()))
        );
        assert_eq!(
            p("NOERROR;SRV;10 60 5060 sip.example extra").value,
            Some(RewriteValue::Srv {
                priority: 10,
                weight: 60,
                port: 5060,
                target: "sip.example".into()
            })
        );
        assert_eq!(
            p("NOERROR;HTTPS;1 . alpn=h2 ipv4hint=1.2.3.4")
                .value
                .unwrap()
                .to_text(),
            "1 . alpn=h2 ipv4hint=1.2.3.4"
        );
        assert!(parse_dnsrewrite("NOERROR;HTTPS;1 . alpn").is_none());
        assert_eq!(p("NOERROR;NS;x").value, None);
        assert_eq!(
            p("SERVFAIL;A;1.2.3.4"),
            DnsRewrite {
                rcode: 2,
                ..DnsRewrite::default()
            }
        );
        assert!(parse_dnsrewrite("NOERROR;BOGUS;x").is_none());
        assert!(parse_dnsrewrite("NOERROR;NONE;x").is_none());
        assert!(parse_dnsrewrite("FOO;A;1.2.3.4").is_none());
        assert!(parse_dnsrewrite("bad_host.example").is_none());
        assert_eq!(
            p("noerror;cname;Example.ORG").cname.as_deref(),
            Some("Example.ORG"),
            "rcode and type in any case; the value as written"
        );
        assert!(!p("NXDOMAIN;;").returns_records());
        assert!(!p("").returns_records());
        assert!(p("1.2.3.4").returns_records());
        assert!(p("x.example").returns_records());
    }

    #[test]
    fn merge_and_cancel() {
        let a = p("1.2.3.4");
        let b = p("1.2.3.5");
        let c = p("x.example");
        let n = p("NXDOMAIN;;");
        assert_eq!(
            merge_rewrites(&[&a, &b, &a]).unwrap().0,
            RewriteAnswer::Records(vec![
                (1, RewriteValue::Ip("1.2.3.4".parse().unwrap())),
                (1, RewriteValue::Ip("1.2.3.5".parse().unwrap()))
            ])
        );
        assert_eq!(
            merge_rewrites(&[&a, &c]).unwrap().0,
            RewriteAnswer::Cname("x.example".into())
        );
        assert_eq!(merge_rewrites(&[&n, &c]).unwrap().0, RewriteAnswer::Rcode(3));
        let empty = DnsRewrite::default();
        let cands = [
            RewriteCandidate {
                rewrite: &a,
                important: false,
                exception: false,
            },
            RewriteCandidate {
                rewrite: &b,
                important: true,
                exception: false,
            },
            RewriteCandidate {
                rewrite: &empty,
                important: false,
                exception: true,
            },
        ];
        let (left, removed) = apply_rewrite_exceptions(&cands);
        assert_eq!(left, vec![1]);
        assert_eq!(removed, vec![0]);
        assert_eq!(apply_rewrite_exceptions_by(&cands).1, vec![(0, 2)]);
        let cands = [
            RewriteCandidate {
                rewrite: &a,
                important: false,
                exception: false,
            },
            RewriteCandidate {
                rewrite: &b,
                important: false,
                exception: false,
            },
            RewriteCandidate {
                rewrite: &a,
                important: false,
                exception: true,
            },
        ];
        assert_eq!(apply_rewrite_exceptions(&cands).0, vec![1]);
        let mx = p("NOERROR;MX;10 mail.example");
        let cands = [
            RewriteCandidate {
                rewrite: &mx,
                important: false,
                exception: false,
            },
            RewriteCandidate {
                rewrite: &mx,
                important: false,
                exception: true,
            },
        ];
        assert_eq!(apply_rewrite_exceptions(&cands).0, vec![0]);
        let cands = [
            RewriteCandidate {
                rewrite: &n,
                important: false,
                exception: false,
            },
            RewriteCandidate {
                rewrite: &p("NXDOMAIN"),
                important: false,
                exception: true,
            },
        ];
        assert_eq!(apply_rewrite_exceptions(&cands).0, Vec::<usize>::new());
    }
}
