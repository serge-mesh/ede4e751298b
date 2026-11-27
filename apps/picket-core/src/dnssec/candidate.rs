//! Which logged queries DNSSEC validation and the cross-check take (core.md §8 "Candidates",
//! "Coverage", the cross-check's "Sinkhole check"), read from a stored record and the parts of
//! the published `EdgeConfig` its `versions.config` names (core.md §6 "Published configs"; the
//! current configuration when that config is gone).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

use picket_api::edge_config::UpstreamProtocol;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;

use crate::config::model::Model;
use crate::logs::record::Rec;

/// The parts of a published config the candidate rules read.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ConfigParts {
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfilePart>,
    #[serde(default)]
    pub forward_zones: BTreeMap<String, ZonePart>,
    #[serde(default)]
    pub upstreams: BTreeMap<String, UpstreamPart>,
    #[serde(default)]
    pub upstream_groups: BTreeMap<String, GroupPart>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProfilePart {
    #[serde(default)]
    pub forward_zones: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ZonePart {
    #[serde(default)]
    pub zone: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpstreamPart {
    pub protocol: UpstreamProtocol,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GroupPart {
    #[serde(default)]
    pub upstreams: Vec<String>,
}

impl ConfigParts {
    /// The parts of the current configuration (a record whose published config is gone).
    pub fn from_model(m: &Model) -> Self {
        let mut p = ConfigParts::default();
        for (id, prof) in &m.profiles {
            p.profiles.insert(
                id.clone(),
                ProfilePart {
                    forward_zones: prof.edge.forward_zones.clone(),
                },
            );
        }
        for (id, z) in &m.forward_zones {
            p.forward_zones
                .insert(id.clone(), ZonePart { zone: z.zone.clone() });
        }
        for (id, u) in &m.upstreams {
            p.upstreams
                .insert(id.clone(), UpstreamPart { protocol: u.protocol });
        }
        for (id, g) in &m.upstream_groups {
            p.upstream_groups.insert(
                id.clone(),
                GroupPart {
                    upstreams: g.upstreams.clone(),
                },
            );
        }
        p
    }

    /// True when `qname` is in one of `profile`'s forward zones.
    pub fn in_forward_zone(&self, profile: Option<&str>, qname: &str) -> bool {
        let Some(p) = profile.and_then(|p| self.profiles.get(p)) else {
            return false;
        };
        p.forward_zones.iter().any(|z| {
            self.forward_zones
                .get(z)
                .is_some_and(|fz| crate::logs::evidence::under(qname, &fz.zone))
        })
    }

    /// True when the answering upstream (else its group's) is plain `udp`/`tcp`.
    pub fn plain_upstream(&self, up: &UpstreamRef) -> bool {
        let proto = up
            .upstream
            .as_ref()
            .and_then(|u| self.upstreams.get(u))
            .map(|u| u.protocol)
            .or_else(|| {
                up.group
                    .as_ref()
                    .and_then(|g| self.upstream_groups.get(g))
                    .and_then(|g| g.upstreams.iter().find_map(|u| self.upstreams.get(u)))
                    .map(|u| u.protocol)
            });
        matches!(proto, Some(UpstreamProtocol::Udp | UpstreamProtocol::Tcp))
    }
}

/// A record's `upstream` (api.md §5: `{group, upstream, ms, cached, stale}`).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpstreamRef {
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub upstream: Option<String>,
}

/// The record's upstream, `None` for an answer the edge made itself.
pub fn upstream_of(r: &Rec) -> Option<UpstreamRef> {
    let j = r.upstream_json.as_deref()?;
    let v: serde_json::Value = serde_json::from_str(j).ok()?;
    if v.is_null() {
        return None;
    }
    serde_json::from_value(v).ok()
}

type PartsKey = (String, String);
type PartsMap = HashMap<PartsKey, Option<std::sync::Arc<ConfigParts>>>;

/// Published config parts by (edge, short id), bounded.
#[derive(Default)]
pub struct PartsCache {
    inner: Mutex<(PartsMap, VecDeque<PartsKey>)>,
}

const PARTS_CACHE: usize = 256;

impl PartsCache {
    pub fn get(
        &self,
        c: &Connection,
        edge: &str,
        short: &str,
    ) -> rusqlite::Result<Option<std::sync::Arc<ConfigParts>>> {
        let key = (edge.to_string(), short.to_string());
        if let Ok(g) = self.inner.lock()
            && let Some(v) = g.0.get(&key)
        {
            return Ok(v.clone());
        }
        let v = load_parts(c, edge, short)?.map(std::sync::Arc::new);
        if let Ok(mut g) = self.inner.lock() {
            if g.0.insert(key.clone(), v.clone()).is_none() {
                g.1.push_back(key);
            }
            while g.0.len() > PARTS_CACHE {
                let Some(old) = g.1.pop_front() else { break };
                g.0.remove(&old);
            }
        }
        Ok(v)
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.0.clear();
            g.1.clear();
        }
    }
}

fn load_parts(c: &Connection, edge: &str, short: &str) -> rusqlite::Result<Option<ConfigParts>> {
    if short.is_empty() || short.len() > 64 || !short.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let short = short.to_ascii_lowercase();
    let body: Option<String> = c
        .query_row(
            "SELECT body_json FROM edge_configs
             WHERE config_id >= ?1 AND config_id < ?1 || 'g' AND edge_id = ?2 ORDER BY published_at DESC LIMIT 1",
            params![short, edge],
            |r| r.get(0),
        )
        .optional()?;
    Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
}

/// The `versions.config` short id of a record.
pub fn config_short(r: &Rec) -> String {
    serde_json::from_str::<serde_json::Value>(&r.versions_json)
        .ok()
        .and_then(|v| v.get("config").and_then(|c| c.as_str()).map(str::to_string))
        .unwrap_or_default()
}

/// What core does with one stored record (core.md §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Class {
    /// Not an answer a client got (decision `block`, `rewrite`, `refused`): not counted.
    NotAnswer,
    /// Counted at once under this coverage class: `edge`, `forward_zone`, `plain_upstream`, `off`.
    Unchecked(&'static str),
    /// Validated: the logged answer (`answer_id` with its wire held in the partition).
    Answer,
    /// Core's own query: the answer isn't held (over 4 KiB, `answer_missing`).
    Fallback,
    /// An upstream SERVFAIL: core's own query, never retried.
    Servfail,
}

/// Classifies `r` (core.md §8 "Candidates" and "Coverage": the first class that fits).
pub fn classify(r: &Rec, parts: &ConfigParts, enabled: bool) -> Class {
    let decision = r.decision.as_str();
    if decision != "allow" && decision != "servfail" {
        return Class::NotAnswer;
    }
    let Some(up) = upstream_of(r) else {
        return Class::Unchecked("edge");
    };
    if parts.in_forward_zone(r.profile.as_deref(), &r.qname) {
        return Class::Unchecked("forward_zone");
    }
    if parts.plain_upstream(&up) {
        return Class::Unchecked("plain_upstream");
    }
    if !enabled {
        return Class::Unchecked("off");
    }
    if decision == "servfail" {
        return Class::Servfail;
    }
    if r.answer_id.is_some() && !r.answer_missing && !r.truncated && r.answer_wire.is_some() {
        Class::Answer
    } else {
        Class::Fallback
    }
}

/// True when the record's upstream answer is NODATA (NOERROR without data for its question): no
/// RRset of the question's type at the name or at the end of its CNAME chain, so a CNAME chain
/// alone is NODATA (core.md §8: "a CNAME or proof records alone aren't data"). Read from the
/// logged answer when core holds it, else from the preview (its addresses and HTTPS/SVCB
/// targets; the CNAME chain doesn't count).
pub fn nodata(r: &Rec) -> bool {
    if r.rcode != "NOERROR" {
        return false;
    }
    if let Some(w) = &r.answer_wire
        && let Ok(m) = hickory_net::proto::op::Message::from_vec(w)
        && let Some(qtype) = super::validator::parse_qtype(&r.qtype)
    {
        return !m.answers.iter().any(|rec| rec.record_type() == qtype);
    }
    r.answers.is_empty() && r.targets.is_empty()
}

/// True when the negative check takes a record whose DNSSEC outcome is Insecure: its upstream
/// answered NXDOMAIN or SERVFAIL (any type), or NODATA to an A query (core.md §8).
pub fn negative_candidate(rcode: &str, qtype: &str, nodata: bool) -> bool {
    rcode == "NXDOMAIN" || rcode == "SERVFAIL" || (qtype == "A" && rcode == "NOERROR" && nodata)
}

/// True for an address a sinkhole answers with: `0.0.0.0`, `::`, loopback, private or
/// link-local, or one of `crosscheck.block_page_ips` (core.md §8 "Sinkhole check").
pub fn sinkhole_ip(ip: IpAddr, block_page: &[IpAddr]) -> bool {
    let ip = ip.to_canonical();
    if block_page.iter().any(|b| b.to_canonical() == ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_unspecified() || v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

/// The addresses of a record's answer for the sinkhole check: the referenced answer's A/AAAA
/// records of the question and its chain (else the preview).
pub fn answer_addrs(r: &Rec) -> Vec<IpAddr> {
    if let Some(w) = &r.answer_wire
        && let Ok(m) = hickory_net::proto::op::Message::from_vec(w)
    {
        let mut out = Vec::new();
        for rec in &m.answers {
            match &rec.data {
                hickory_net::proto::rr::RData::A(a) => out.push(IpAddr::V4(a.0)),
                hickory_net::proto::rr::RData::AAAA(a) => out.push(IpAddr::V6(a.0)),
                _ => {}
            }
            if out.len() >= 64 {
                break;
            }
        }
        return out;
    }
    r.answers
        .iter()
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .collect()
}

/// True when the sinkhole check flags `r`: an allowed A or AAAA answer for a public name (one
/// with a registrable domain, outside the `lookup-exclude` bundle, checked by the caller)
/// holding a sinkhole address.
pub fn sinkhole_flag(r: &Rec, block_page: &[IpAddr]) -> Option<Vec<IpAddr>> {
    if r.decision != "allow" || (r.qtype != "A" && r.qtype != "AAAA") {
        return None;
    }
    upstream_of(r)?;
    let addrs = answer_addrs(r);
    addrs
        .iter()
        .any(|ip| sinkhole_ip(*ip, block_page))
        .then_some(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(decision: &str, upstream: Option<&str>) -> Rec {
        Rec {
            qname: "www.example.com".into(),
            qtype: "A".into(),
            rcode: "NOERROR".into(),
            decision: decision.into(),
            profile: Some("p".into()),
            upstream_json: upstream.map(str::to_string),
            ..Default::default()
        }
    }

    fn parts() -> ConfigParts {
        serde_json::from_value(serde_json::json!({
            "profiles": {"p": {"forward_zones": ["lan"]}},
            "forward_zones": {"lan": {"zone": "home.arpa", "group": "local"}},
            "upstreams": {"cf": {"protocol": "dot", "ip": "1.1.1.1", "port": 853}, "dnsmasq": {"protocol": "udp", "ip": "10.0.0.1", "port": 53}},
            "upstream_groups": {"cloudflare": {"upstreams": ["cf"]}, "local": {"upstreams": ["dnsmasq"]}}
        }))
        .unwrap()
    }

    #[test]
    fn coverage_classes_in_order() {
        let p = parts();
        assert_eq!(classify(&rec("block", None), &p, true), Class::NotAnswer);
        assert_eq!(classify(&rec("allow", None), &p, true), Class::Unchecked("edge"));
        assert_eq!(
            classify(&rec("allow", Some("null")), &p, true),
            Class::Unchecked("edge")
        );
        let mut r = rec("allow", Some(r#"{"group":"local","upstream":"dnsmasq"}"#));
        r.qname = "nas.home.arpa".into();
        assert_eq!(classify(&r, &p, true), Class::Unchecked("forward_zone"));
        r.qname = "example.org".into();
        assert_eq!(classify(&r, &p, true), Class::Unchecked("plain_upstream"));
        let mut r = rec("allow", Some(r#"{"group":"cloudflare","upstream":"cf"}"#));
        assert_eq!(classify(&r, &p, false), Class::Unchecked("off"));
        assert_eq!(classify(&r, &p, true), Class::Fallback, "no answer held");
        r.answer_id = Some("0123456789abcdef".into());
        r.answer_wire = Some(vec![0; 12]);
        assert_eq!(classify(&r, &p, true), Class::Answer);
        r.answer_missing = true;
        assert_eq!(classify(&r, &p, true), Class::Fallback);
        let r = rec("servfail", Some(r#"{"group":"cloudflare"}"#));
        assert_eq!(classify(&r, &p, true), Class::Servfail);
    }

    #[test]
    fn a_cname_chain_without_the_type_is_nodata() {
        use hickory_net::proto::op::{Message, MessageType, OpCode, Query};
        use hickory_net::proto::rr::rdata::{A, CNAME};
        use hickory_net::proto::rr::{Name, RData, Record, RecordType};
        let mut r = rec("allow", Some(r#"{"group":"cloudflare"}"#));
        r.cname = vec!["target.example.com".into()];
        assert!(nodata(&r), "a CNAME without a terminal A RRset is NODATA for A");
        r.answers = vec!["192.0.2.1".into()];
        assert!(!nodata(&r));
        r.answers.clear();
        r.rcode = "NXDOMAIN".into();
        assert!(!nodata(&r));
        // From the logged answer: a CNAME alone, then the chain's A record.
        r.rcode = "NOERROR".into();
        let name = |s: &str| Name::from_ascii(s).unwrap();
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name("www.example.com."), RecordType::A));
        m.answers.push(Record::from_rdata(
            name("www.example.com."),
            60,
            RData::CNAME(CNAME(name("target.example.com."))),
        ));
        r.answer_wire = Some(m.to_vec().unwrap());
        assert!(nodata(&r));
        m.answers.push(Record::from_rdata(
            name("target.example.com."),
            60,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));
        r.answer_wire = Some(m.to_vec().unwrap());
        assert!(!nodata(&r));
    }

    #[test]
    fn negative_and_sinkhole_rules() {
        assert!(negative_candidate("NXDOMAIN", "MX", false));
        assert!(negative_candidate("SERVFAIL", "AAAA", false));
        assert!(negative_candidate("NOERROR", "A", true));
        assert!(
            !negative_candidate("NOERROR", "AAAA", true),
            "NODATA is normal for AAAA"
        );
        let bp: Vec<IpAddr> = vec!["203.0.113.5".parse().unwrap()];
        for ip in [
            "0.0.0.0",
            "::",
            "127.0.0.2",
            "::1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "203.0.113.5",
            "::ffff:127.0.0.1",
        ] {
            assert!(sinkhole_ip(ip.parse().unwrap(), &bp), "{ip}");
        }
        for ip in ["93.184.216.34", "2606:4700::1111", "100.64.0.1"] {
            assert!(!sinkhole_ip(ip.parse().unwrap(), &bp), "{ip}");
        }
        let mut r = rec("allow", Some(r#"{"group":"cloudflare"}"#));
        r.answers = vec!["0.0.0.0".into()];
        assert!(sinkhole_flag(&r, &[]).is_some());
        r.answers = vec!["93.184.216.34".into()];
        assert!(sinkhole_flag(&r, &[]).is_none());
        r.qtype = "MX".into();
        r.answers = vec!["0.0.0.0".into()];
        assert!(sinkhole_flag(&r, &[]).is_none());
    }
}
