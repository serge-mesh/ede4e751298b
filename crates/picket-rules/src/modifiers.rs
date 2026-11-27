//! DNS modifiers that restrict a rule (rules.md §2, §4): `$dnstype`, `$client`, `$ctag`,
//! `$denyallow`, parsed and evaluated as urlfilter v0.23 does.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::adguard::split_escaped;
use crate::entity::EntityExpansion;
use crate::ip::{IpRange, canonical_ip, is_go_ip_string, parse_go_ip};
use crate::name::{RuleName, is_adguard_host_name, labels_within, text_within};
use crate::rrtype::parse_rr_type;

/// The query a rule is evaluated for: its type and the client (rules.md §4, core.md §6 step 2).
#[derive(Clone, Copy, Debug, Default)]
pub struct QueryCtx<'a> {
    /// The query type, or for a response-phase check the record's type (rules.md §6).
    pub qtype: u16,
    /// The client's address, if known. IPv4-mapped IPv6 is treated as IPv4.
    pub client_ip: Option<IpAddr>,
    /// Names `$client` may match: the client entry's `name` and, in replay, the device name.
    pub client_names: &'a [&'a str],
    /// The client entry's `tags`, for `$ctag`.
    pub client_tags: &'a [&'a str],
}

/// `$dnstype=A|~AAAA` (urlfilter `parseDNSTypes`): sorted and deduplicated.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DnsTypeCond {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permitted: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restricted: Vec<u16>,
}

impl DnsTypeCond {
    /// Parses the option value. `None` for an empty part or an unknown type (the rule is refused).
    pub fn parse(value: &str) -> Option<DnsTypeCond> {
        if value.is_empty() {
            return None;
        }
        let mut c = DnsTypeCond::default();
        for part in value.split('|') {
            let (neg, name) = match part.strip_prefix('~') {
                Some(n) => (true, n),
                None => (false, part),
            };
            if name.is_empty() {
                return None;
            }
            let t = parse_rr_type(name)?;
            if neg {
                c.restricted.push(t)
            } else {
                c.permitted.push(t)
            }
        }
        c.permitted.sort_unstable();
        c.permitted.dedup();
        c.restricted.sort_unstable();
        c.restricted.dedup();
        Some(c)
    }

    /// urlfilter `matchDNSType`.
    pub fn matches(&self, qtype: u16) -> bool {
        if self.restricted.contains(&qtype) {
            return false;
        }
        self.permitted.is_empty() || self.permitted.contains(&qtype)
    }
}

/// One side of `$client`: client names and address ranges (urlfilter `clients`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientSet {
    /// Names, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// Ranges as masked CIDR text (`192.168.1.0/24`, `::1/128`), sorted as urlfilter sorts them
    /// (IPv4 first, then by prefix length, then address).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nets: Vec<String>,
}

impl ClientSet {
    fn is_empty(&self) -> bool {
        self.names.is_empty() && self.nets.is_empty()
    }

    fn add(&mut self, client: String) {
        let net = if client.contains('/') {
            IpRange::parse(&client).filter(|_| !client.contains('%'))
        } else {
            parse_go_ip(&client).map(IpRange::single)
        };
        match net {
            Some(r) => {
                // An IPv4-mapped IPv6 address or prefix stays IPv6, as Go's `netip.Prefix` keeps it:
                // it never contains the (IPv4) address of an IPv4 client.
                let text = if client.contains(':') && r.v4 {
                    let len = r.prefix_len().unwrap_or(32);
                    format!(
                        "{V4_MAPPED_PREFIX}{}/{}",
                        crate::ip::go_ip_string(r.first_ip()),
                        u16::from(len).saturating_add(96)
                    )
                } else {
                    cidr_text(&r)
                };
                if !self.nets.contains(&text) {
                    self.nets.push(text);
                }
            }
            None => {
                if !self.names.contains(&client) {
                    self.names.push(client);
                }
            }
        }
    }

    fn finish(&mut self) {
        self.names.sort();
        self.nets.sort_by_key(|n| net_sort_key(n));
    }

    fn matches(&self, ctx: &QueryCtx<'_>) -> bool {
        if self.names.iter().any(|n| ctx.client_names.contains(&n.as_str())) {
            return true;
        }
        match ctx.client_ip {
            Some(ip) => self
                .nets
                .iter()
                .filter(|n| !n.starts_with(V4_MAPPED_PREFIX))
                .filter_map(|n| IpRange::parse(n))
                .any(|r| r.contains(canonical_ip(ip))),
            None => false,
        }
    }
}

/// How an IPv4-mapped client entry is written (`::ffff:10.0.0.1/128`); such entries never match.
const V4_MAPPED_PREFIX: &str = "::ffff:";

fn cidr_text(r: &IpRange) -> String {
    let len = r.prefix_len().unwrap_or(if r.v4 { 32 } else { 128 });
    format!("{}/{}", crate::ip::go_ip_string(r.first_ip()), len)
}

fn net_sort_key(n: &str) -> (u8, u8, u128) {
    match IpRange::parse(n) {
        Some(r) if n.starts_with(V4_MAPPED_PREFIX) => {
            (1, r.prefix_len().unwrap_or(0).saturating_add(96), r.first)
        }
        Some(r) => (u8::from(!r.v4), r.prefix_len().unwrap_or(0), r.first),
        None => (2, 0, 0),
    }
}

/// `$client=…` (urlfilter `parseClients`): permitted and restricted (`~`) clients.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientCond {
    #[serde(default, skip_serializing_if = "ClientSet::is_empty")]
    pub permitted: ClientSet,
    #[serde(default, skip_serializing_if = "ClientSet::is_empty")]
    pub restricted: ClientSet,
}

impl ClientCond {
    /// Parses the option value: `|`-separated (`\|` escapes it), each an IP, a CIDR or a client
    /// name, optionally `~`-prefixed, a name optionally in `'…'` or `"…"` with `\'`/`\"` and `\,`
    /// escapes. `None` for an empty value or an empty client.
    pub fn parse(value: &str) -> Option<ClientCond> {
        if value.is_empty() {
            return None;
        }
        let mut c = ClientCond::default();
        for raw in split_escaped(value, '|', '\\') {
            let (neg, mut client) = match raw.strip_prefix('~') {
                Some(r) => (true, r.to_string()),
                None => (false, raw.clone()),
            };
            let quote = {
                let b = client.as_bytes();
                match (b.first(), b.last()) {
                    (Some(&q), Some(&l)) if b.len() >= 2 && (q == b'\'' || q == b'"') && q == l => {
                        Some(q as char)
                    }
                    _ => None,
                }
            };
            if quote.is_some() {
                client = client
                    .get(1..client.len().saturating_sub(1))
                    .unwrap_or("")
                    .to_string();
            }
            client = client.replace("\\,", ",");
            if let Some(q) = quote {
                client = client.replace(&format!("\\{q}"), &q.to_string());
            }
            if client.is_empty() {
                return None;
            }
            if neg {
                c.restricted.add(client)
            } else {
                c.permitted.add(client)
            }
        }
        c.permitted.finish();
        c.restricted.finish();
        Some(c)
    }

    /// urlfilter `matchClient`.
    pub fn matches(&self, ctx: &QueryCtx<'_>) -> bool {
        if self.restricted.matches(ctx) {
            return false;
        }
        self.permitted.is_empty() || self.permitted.matches(ctx)
    }
}

/// `$ctag=…` (urlfilter `parseCTags`): sorted tag sets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TagCond {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permitted: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restricted: Vec<String>,
}

impl TagCond {
    /// Parses the option value: `|`-separated tags of `a-z0-9_`, optionally `~`-prefixed. `None`
    /// for an empty value or an invalid tag (the rule is refused).
    pub fn parse(value: &str) -> Option<TagCond> {
        if value.is_empty() {
            return None;
        }
        let mut c = TagCond::default();
        for part in value.split('|') {
            let (neg, tag) = match part.strip_prefix('~') {
                Some(t) => (true, t),
                None => (false, part),
            };
            if !tag
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return None;
            }
            if neg {
                c.restricted.push(tag.to_string())
            } else {
                c.permitted.push(tag.to_string())
            }
        }
        c.permitted.sort();
        c.permitted.dedup();
        c.restricted.sort();
        c.restricted.dedup();
        Some(c)
    }

    /// urlfilter `matchClientTags`.
    pub fn matches(&self, tags: &[&str]) -> bool {
        if self.restricted.iter().any(|t| tags.contains(&t.as_str())) {
            return false;
        }
        self.permitted.is_empty() || self.permitted.iter().any(|t| tags.contains(&t.as_str()))
    }
}

/// Why a `$denyallow` value is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyallowError {
    /// Empty, a `~` entry or not a domain: AdGuard refuses the rule.
    Invalid,
}

/// Parses `$denyallow=a.com|b.org|tracker.*` (urlfilter `parseDomains` +
/// `setDenyAllowOptionHandler`): each entry passes AdGuard's domain check or ends with `.*` (an
/// entity), none is negated. Names are normalised (rules.md §1), and so are entity prefixes that
/// are names (`Tracker.*` → `tracker`); other prefixes are kept, ASCII-lowercased (urlfilter
/// accepts any text before `.*`). Returns the names and the entity prefixes, each sorted.
pub fn parse_denyallow(value: &str) -> Result<(Vec<RuleName>, Vec<String>), DenyallowError> {
    if value.is_empty() {
        return Err(DenyallowError::Invalid);
    }
    let mut out = Vec::new();
    let mut entities: Vec<String> = Vec::new();
    for part in value.split('|') {
        if part.starts_with('~') {
            return Err(DenyallowError::Invalid);
        }
        if let Some(prefix) = part.strip_suffix(".*") {
            let p = match RuleName::parse(prefix) {
                Ok(n) => String::from(n),
                Err(_) => prefix.to_ascii_lowercase(),
            };
            if !entities.contains(&p) {
                entities.push(p);
            }
            continue;
        }
        if !is_adguard_host_name(part) {
            return Err(DenyallowError::Invalid);
        }
        let name = RuleName::parse(part).map_err(|_| DenyallowError::Invalid)?;
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out.sort();
    entities.sort();
    Ok((out, entities))
}

/// How a rule meets names: by whole wire labels (keyed rules and their `$denyallow`, rules.md §3)
/// or by AdGuard's text form (patterns).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameSemantics {
    /// Whole labels.
    Labels,
    /// AdGuard text form.
    Text,
}

/// urlfilter `matchRequestDomain`: true when the rule may match `name` given its `$denyallow`
/// names and entities ([`crate::entity`]). A name whose text is an IP address never matches a
/// `$denyallow` rule (urlfilter skips IP text, AdGuardHome#3175).
pub fn denyallow_permits(
    list: &[RuleName],
    entities: &[EntityExpansion],
    labels: &[&[u8]],
    text: &str,
    sem: NameSemantics,
) -> bool {
    if list.is_empty() && entities.is_empty() {
        return true;
    }
    if is_go_ip_string(text) {
        return false;
    }
    let by_name = match sem {
        NameSemantics::Labels => list.iter().any(|d| labels_within(labels, d)),
        NameSemantics::Text => list.iter().any(|d| text_within(text, d.as_str())),
    };
    !by_name && !entities.iter().any(|e| e.covers(labels, text, sem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnstype() {
        let c = DnsTypeCond::parse("A|~AAAA|a").unwrap();
        assert_eq!(c.permitted, vec![1]);
        assert_eq!(c.restricted, vec![28]);
        assert!(c.matches(1));
        assert!(!c.matches(28));
        assert!(!c.matches(65));
        let c = DnsTypeCond::parse("~AAAA").unwrap();
        assert!(c.matches(65));
        assert!(!c.matches(28));
        assert!(DnsTypeCond::parse("").is_none());
        assert!(DnsTypeCond::parse("A|").is_none());
        assert!(DnsTypeCond::parse("BOGUS").is_none());
        assert!(DnsTypeCond::parse("none").is_none());
    }

    #[test]
    fn clients() {
        let c = ClientCond::parse("'Frank\\'s laptop'|192.168.1.0/24|~10.0.0.1|\"a,b\"").unwrap();
        assert_eq!(
            c.permitted.names,
            vec!["Frank's laptop".to_string(), "a,b".to_string()]
        );
        assert_eq!(c.permitted.nets, vec!["192.168.1.0/24".to_string()]);
        assert_eq!(c.restricted.nets, vec!["10.0.0.1/32".to_string()]);
        let names = ["Frank's laptop"];
        let ctx = QueryCtx {
            client_names: &names,
            ..QueryCtx::default()
        };
        assert!(c.matches(&ctx));
        let ip: IpAddr = "192.168.1.7".parse().unwrap();
        assert!(c.matches(&QueryCtx {
            client_ip: Some(ip),
            ..QueryCtx::default()
        }));
        let ip: IpAddr = "::ffff:192.168.1.7".parse().unwrap();
        assert!(c.matches(&QueryCtx {
            client_ip: Some(ip),
            ..QueryCtx::default()
        }));
        assert!(!c.matches(&QueryCtx::default()));
        let r = ClientCond::parse("~kid").unwrap();
        assert!(r.matches(&QueryCtx::default()));
        let names = ["kid"];
        assert!(!r.matches(&QueryCtx {
            client_names: &names,
            ..QueryCtx::default()
        }));
        assert!(ClientCond::parse("").is_none());
        assert!(ClientCond::parse("~").is_none());
        let a = ClientCond::parse("b|a|10.0.0.0/8|1.2.3.4").unwrap();
        let b = ClientCond::parse("1.2.3.4|a|10.1.0.0/8|b").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ctags() {
        let c = TagCond::parse("device_phone|~user_admin").unwrap();
        assert!(c.matches(&["device_phone"]));
        assert!(!c.matches(&["device_phone", "user_admin"]));
        assert!(!c.matches(&[]));
        assert!(TagCond::parse("Bad").is_none());
        assert!(TagCond::parse("").is_none());
    }

    #[test]
    fn denyallow() {
        let (l, e) = parse_denyallow("Example.COM|b.org").unwrap();
        assert_eq!((l.len(), e.len()), (2, 0));
        assert_eq!(parse_denyallow("~a.com"), Err(DenyallowError::Invalid));
        assert_eq!(
            parse_denyallow("Tracker.*|a.com|*.*"),
            Ok((
                vec![RuleName::parse("a.com").unwrap()],
                vec!["*".to_string(), "tracker".to_string()]
            ))
        );
        assert_eq!(parse_denyallow("1.2.3.4"), Err(DenyallowError::Invalid));
        assert!(parse_denyallow("com").is_ok());
        let (l, _) = parse_denyallow("example.com").unwrap();
        let lab: Vec<&[u8]> = vec![b"a", b"example", b"com"];
        assert!(!denyallow_permits(
            &l,
            &[],
            &lab,
            "a.example.com",
            NameSemantics::Labels
        ));
        assert!(!denyallow_permits(
            &l,
            &[],
            &lab,
            "a.example.com",
            NameSemantics::Text
        ));
        let lab: Vec<&[u8]> = vec![b"a.example", b"com"];
        assert!(denyallow_permits(
            &l,
            &[],
            &lab,
            "a\\.example.com",
            NameSemantics::Labels
        ));
        assert!(!denyallow_permits(
            &l,
            &[],
            &[b"1", b"2", b"3", b"4"],
            "1.2.3.4",
            NameSemantics::Labels
        ));
    }
}
