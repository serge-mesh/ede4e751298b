//! The `dns` module's config (providers.md §5 `dns`): as stored ([`RawConfig`], whose schema the
//! UI form renders) and checked ([`Config`]).

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;
use picket_api::edge_config::UpstreamProtocol;
use picket_wire::name::WireName;
use picket_wire::types::{rcode, rtype};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ctx::DnsServer;
use crate::module::SelfTest;
use crate::name::check_name;
use crate::selftest::parse_cron;

/// The form's warning while `transport` is `udp` or `tcp` (providers.md §5 `dns` "Plain DNS").
pub const PLAIN_DNS_WARNING: &str = "Plain DNS is unencrypted. Every name this provider looks up is sent in clear text, and anyone on the network path can read it or change the answer, letting a blocked name through or blocking any name. Use DoT or DoH unless the resolver offers neither.";
/// 1–8 servers.
pub const MAX_SERVERS: usize = 8;
/// At most 32 rules.
pub const MAX_RULES: usize = 32;
/// The most entries in one condition's list.
pub const MAX_LIST: usize = 64;
/// The longest `ede_text`.
pub const MAX_EDE_TEXT: usize = 256;
/// The largest `trust_store` (PEM text).
pub const MAX_TRUST_STORE: usize = 64 * 1024;
/// The longest DoH path.
pub const MAX_PATH: usize = picket_api::edge_config::MAX_DOH_PATH;
/// The DoH path when none is set.
pub const DEFAULT_DOH_PATH: &str = "/dns-query";

/// The config as stored and edited. The example is the `quad9` preset for DoT.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[schemars(example = example())]
pub struct RawConfig {
    /// One transport per provider, so an encrypted provider never falls back to plain DNS:
    /// `dot` (default; port 853), `doh` (443), `udp` (53; a truncated answer is retried over TCP)
    /// or `tcp` (53).
    #[serde(default)]
    #[schemars(extend("x-picket-warning" = {"when": ["udp", "tcp"], "text": PLAIN_DNS_WARNING}))]
    pub transport: UpstreamProtocol,
    /// Tried in order; a server that failed is skipped for 30 s while another works.
    #[schemars(length(min = 1, max = 8))]
    pub servers: Vec<RawServer>,
    /// The query type, whatever the client asked.
    #[serde(default)]
    pub qtype: Qtype,
    /// Checked in order; the first whose conditions all hold decides.
    #[serde(default)]
    #[schemars(length(max = 32))]
    pub rules: Vec<RawRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_test: Option<SelfTest>,
}

fn example() -> serde_json::Value {
    super::presets::quad9_config(super::presets::Encrypted::Dot)
}

/// A server, by IP (never resolved), as for upstreams (edge.md §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawServer {
    pub ip: IpAddr,
    /// Default: 53 for `udp`/`tcp`, 853 for `dot`, 443 for `doh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The TLS name (`dot`, `doh`; required there).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_host: Option<String>,
    /// PEM text (`dot`, `doh`); none: the Mozilla roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_store: Option<String>,
    /// The DoH path, default `/dns-query`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Qtype {
    #[default]
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
}

impl Qtype {
    pub fn code(self) -> u16 {
        match self {
            Self::A => rtype::A,
            Self::Aaaa => rtype::AAAA,
        }
    }
}

/// A rule: an `id` (`[a-z0-9_]{1,32}`), one or more conditions, and a verdict.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RawRule {
    #[schemars(regex(pattern = r"^[a-z0-9_]{1,32}$"))]
    pub id: String,
    pub when: RawWhen,
    pub verdict: RuleVerdict,
    /// A Block's score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
}

/// A rule's verdict: `block` (a Block whose reason is the rule's id), `clean` or `unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RuleVerdict {
    Block,
    Clean,
    Unknown,
}

/// The conditions; all set ones must hold.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawWhen {
    /// The rcode is one of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<Vec<RcodeName>>,
    /// An EDE carries one of these INFO-CODEs; `"none"`: the answer has no EDE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ede: Option<EdeCond>,
    /// An EDE's EXTRA-TEXT contains this text (ASCII case-insensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ede_text: Option<String>,
    /// The answer has A or AAAA records and every one is in these IPs or CIDRs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers_in: Option<Vec<String>>,
    /// The answer's CNAME chain ends at a name under one of these suffixes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_suffix: Option<Vec<String>>,
    /// `true`: the authority section holds an SOA; `false`: it doesn't.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soa: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum RcodeName {
    #[serde(rename = "NOERROR")]
    NoError,
    #[serde(rename = "NXDOMAIN")]
    NxDomain,
    #[serde(rename = "SERVFAIL")]
    ServFail,
    #[serde(rename = "REFUSED")]
    Refused,
}

impl RcodeName {
    pub fn code(self) -> u16 {
        match self {
            Self::NoError => rcode::NOERROR,
            Self::NxDomain => rcode::NXDOMAIN,
            Self::ServFail => rcode::SERVFAIL,
            Self::Refused => rcode::REFUSED,
        }
    }
}

/// `ede`: a list of INFO-CODEs, or `"none"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum EdeCond {
    Codes(Vec<u16>),
    Keyword(EdeKeyword),
}

impl<'de> Deserialize<'de> for EdeCond {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Codes(Vec<u16>),
            Keyword(EdeKeyword),
        }
        match Either::deserialize(d) {
            Ok(Either::Codes(c)) => Ok(Self::Codes(c)),
            Ok(Either::Keyword(k)) => Ok(Self::Keyword(k)),
            Err(_) => Err(serde::de::Error::custom(
                "ede: a list of INFO-CODEs (0 to 65535) or \"none\"",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EdeKeyword {
    #[serde(rename = "none")]
    None,
}

// ---------------------------------------------------------------------------------------------

/// A checked config: deserialises from [`RawConfig`] and checks it; its schema is
/// [`RawConfig`]'s.
#[derive(Clone, Debug)]
pub struct Config {
    pub transport: UpstreamProtocol,
    pub servers: Vec<Server>,
    pub qtype: u16,
    pub rules: Vec<Rule>,
    pub self_test: Option<SelfTest>,
}

/// A checked server.
#[derive(Clone, Debug)]
pub struct Server {
    pub dns: DnsServer,
    /// How the detail names it: the IP, with the port when it isn't the transport's default.
    pub label: String,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub when: When,
    pub verdict: RuleVerdict,
    pub score: Option<f32>,
}

/// Checked conditions.
#[derive(Clone, Debug, Default)]
pub struct When {
    pub rcode: Option<Vec<u16>>,
    pub ede: Option<EdeMatch>,
    /// Lowercase.
    pub ede_text: Option<Vec<u8>>,
    pub answers_in: Option<Vec<IpNet>>,
    pub cname_suffix: Option<Vec<WireName>>,
    pub soa: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdeMatch {
    Codes(Vec<u16>),
    None,
}

/// Why a config was refused: names the field at fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn err(msg: impl Into<String>) -> ConfigError {
    ConfigError(msg.into())
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawConfig::deserialize(d)?;
        Config::try_from(raw).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for Config {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        RawConfig::schema_name()
    }

    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        RawConfig::json_schema(g)
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, ConfigError> {
        if raw.servers.is_empty() || raw.servers.len() > MAX_SERVERS {
            return Err(err(format!("servers: 1 to {MAX_SERVERS}")));
        }
        let servers = raw
            .servers
            .iter()
            .enumerate()
            .map(|(i, s)| server(raw.transport, s).map_err(|e| err(format!("servers[{i}]: {e}"))))
            .collect::<Result<Vec<_>, _>>()?;
        if raw.rules.len() > MAX_RULES {
            return Err(err(format!("rules: at most {MAX_RULES}")));
        }
        let mut ids = BTreeSet::new();
        let mut rules = Vec::with_capacity(raw.rules.len());
        for (i, r) in raw.rules.iter().enumerate() {
            let rule = rule(r).map_err(|e| err(format!("rules[{i}]: {e}")))?;
            if !ids.insert(rule.id.clone()) {
                return Err(err(format!("rules[{i}]: duplicate id {:?}", rule.id)));
            }
            rules.push(rule);
        }
        if let Some(t) = &raw.self_test {
            if check_name(&t.name).is_none() {
                return Err(err(
                    "self_test.name: a name of letters, digits, hyphens and underscores",
                ));
            }
            parse_cron(&t.cron).map_err(|e| err(format!("self_test.cron: {e}")))?;
        }
        Ok(Self {
            transport: raw.transport,
            servers,
            qtype: raw.qtype.code(),
            rules,
            self_test: raw.self_test.map(|t| SelfTest {
                name: check_name(&t.name).map(|n| n.into_owned()).unwrap_or(t.name),
                ..t
            }),
        })
    }
}

fn default_port(t: UpstreamProtocol) -> u16 {
    match t {
        UpstreamProtocol::Udp | UpstreamProtocol::Tcp => 53,
        UpstreamProtocol::Dot => 853,
        UpstreamProtocol::Doh => 443,
    }
}

/// A TLS name: a DNS name of letters, digits and hyphens (case-folded).
fn tls_name(s: &str) -> Option<String> {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    let ok = s.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    ok.then(|| s.to_ascii_lowercase())
}

fn server(t: UpstreamProtocol, s: &RawServer) -> Result<Server, String> {
    if s.ip.is_unspecified() || s.ip.is_multicast() {
        return Err("ip: a unicast address".into());
    }
    // A link-local address needs an interface scope, which a server (an IP and a port) can't
    // carry: its socket would fail every query (EINVAL).
    if matches!(s.ip.to_canonical(), IpAddr::V6(v6) if v6.is_unicast_link_local()) {
        return Err(
            "ip: an IPv6 link-local address (fe80::/10) needs an interface scope, which a server can't carry; use its ULA, private or global address".into(),
        );
    }
    let port = s.port.unwrap_or_else(|| default_port(t));
    if port == 0 {
        return Err("port: 1 to 65535".into());
    }
    let encrypted = t.is_encrypted();
    let tls_host = if encrypted {
        let h = s
            .tls_host
            .as_deref()
            .ok_or("tls_host: required for dot and doh")?;
        Some(tls_name(h).ok_or("tls_host: a DNS name")?)
    } else {
        None
    };
    let trust_store = match (&s.trust_store, encrypted) {
        (Some(p), true) => {
            if p.len() > MAX_TRUST_STORE || !p.contains("-----BEGIN CERTIFICATE-----") {
                return Err(format!(
                    "trust_store: PEM certificates, at most {MAX_TRUST_STORE} bytes"
                ));
            }
            Some(p.clone())
        }
        _ => None,
    };
    let path = if t == UpstreamProtocol::Doh {
        let p = s.path.as_deref().unwrap_or(DEFAULT_DOH_PATH);
        if !picket_api::edge_config::is_doh_path(p) {
            return Err(format!("path: {}", picket_api::edge_config::DOH_PATH_RULE));
        }
        Some(p.to_owned())
    } else {
        None
    };
    let label = if port == default_port(t) {
        s.ip.to_string()
    } else {
        std::net::SocketAddr::new(s.ip, port).to_string()
    };
    Ok(Server {
        dns: DnsServer {
            transport: t,
            ip: s.ip,
            port,
            tls_host,
            trust_store,
            path,
        },
        label,
    })
}

fn rule_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn list<T>(field: &str, v: &[T]) -> Result<(), String> {
    if v.is_empty() || v.len() > MAX_LIST {
        return Err(format!("when.{field}: 1 to {MAX_LIST} entries"));
    }
    Ok(())
}

fn rule(r: &RawRule) -> Result<Rule, String> {
    if !rule_id_ok(&r.id) {
        return Err("id: 1 to 32 of a-z, 0-9 and _".into());
    }
    if let Some(s) = r.score {
        if r.verdict != RuleVerdict::Block {
            return Err("score: only for a block verdict".into());
        }
        if !s.is_finite() {
            return Err("score: a finite number".into());
        }
    }
    let w = &r.when;
    let mut when = When::default();
    let mut any = false;
    if let Some(rc) = &w.rcode {
        list("rcode", rc)?;
        when.rcode = Some(rc.iter().map(|r| r.code()).collect());
        any = true;
    }
    if let Some(e) = &w.ede {
        when.ede = Some(match e {
            EdeCond::Codes(c) => {
                list("ede", c)?;
                EdeMatch::Codes(c.clone())
            }
            EdeCond::Keyword(EdeKeyword::None) => EdeMatch::None,
        });
        any = true;
    }
    if let Some(t) = &w.ede_text {
        if t.is_empty() || t.len() > MAX_EDE_TEXT {
            return Err(format!("when.ede_text: 1 to {MAX_EDE_TEXT} bytes"));
        }
        when.ede_text = Some(t.as_bytes().to_ascii_lowercase());
        any = true;
    }
    if let Some(a) = &w.answers_in {
        list("answers_in", a)?;
        let nets = a
            .iter()
            .enumerate()
            .map(|(i, s)| {
                // The error quotes the value as resolved, never the trimmed form: a secret with
                // its own spaces is then quoted whole, which the redactor knows (README §2
                // "Secrets"; review round 2, CR7).
                let t = s.trim();
                t.parse::<IpNet>()
                    .or_else(|_| t.parse::<IpAddr>().map(IpNet::from))
                    .map(|n| n.trunc())
                    .map_err(|_| format!("when.answers_in[{i}]: not an IP or CIDR{}", shown(s)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        when.answers_in = Some(nets);
        any = true;
    }
    if let Some(c) = &w.cname_suffix {
        list("cname_suffix", c)?;
        let names = c
            .iter()
            .enumerate()
            .map(|(i, s)| {
                WireName::from_text(s.trim())
                    .map_err(|_| format!("when.cname_suffix[{i}]: not a name{}", shown(s)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        when.cname_suffix = Some(names);
        any = true;
    }
    if let Some(s) = w.soa {
        when.soa = Some(s);
        any = true;
    }
    if !any {
        return Err("when: at least one condition".into());
    }
    Ok(Rule {
        id: r.id.clone(),
        when,
        verdict: r.verdict,
        score: r.score,
    })
}

/// The longest value an error message quotes.
const MAX_SHOWN: usize = 64;

/// A value for an error message: `: "value"` (Rust-quoted, a form the `LookupClient`'s redactor
/// knows) when it is at most [`MAX_SHOWN`] bytes, otherwise nothing. Never a cut or otherwise
/// transformed value (trimmed, case-folded), so a secret resolved into it is either quoted whole,
/// and redacted, or not shown at all (README §2 "Secrets"); callers pass the value as resolved.
fn shown(s: &str) -> String {
    if s.len() <= MAX_SHOWN {
        format!(": {s:?}")
    } else {
        String::new()
    }
}
