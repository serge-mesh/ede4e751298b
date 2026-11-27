//! The `dns` presets (providers.md §5 `dns` "Presets"): `quad9` and `nextdns`. Each builds a full
//! config, saved like one typed by hand. Sources: `README.md` beside this file.

use anyhow::{Context as _, bail};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::module::{Category, Preset};

/// The hourly schedule the presets fill in.
pub const HOURLY: &str = "0 * * * *";

/// Quad9's resolvers.
pub const QUAD9_SERVERS: [&str; 4] = ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"];
pub const QUAD9_TLS_HOST: &str = "dns.quad9.net";
/// NextDNS's anycast resolvers.
pub const NEXTDNS_SERVERS: [&str; 4] = ["45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::"];

/// The presets offer DoT and DoH only (plain DNS isn't offered).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Encrypted {
    #[default]
    Dot,
    Doh,
}

impl Encrypted {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dot => "dot",
            Self::Doh => "doh",
        }
    }
}

/// `quad9` parameters.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct Quad9Params {
    /// `dot` (default) or `doh`.
    #[serde(default)]
    pub transport: Encrypted,
}

/// `nextdns` parameters.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct NextDnsParams {
    /// The NextDNS configuration ID (e.g. `abc123`).
    #[schemars(regex(pattern = r"^[A-Za-z0-9]{1,32}$"))]
    pub profile: String,
    /// `dot` (default) or `doh`.
    #[serde(default)]
    pub transport: Encrypted,
    /// A name on the profile's denylist, checked hourly (catches the free plan's monthly limit,
    /// past which NextDNS answers without filtering).
    #[serde(default)]
    pub self_test: Option<String>,
}

fn params<T: for<'de> Deserialize<'de> + Default>(v: &Value) -> anyhow::Result<T> {
    if v.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(v.clone()).context("invalid preset parameters")
}

/// The `quad9` config, exactly as providers.md §5 `dns` gives it (for DoH: the same servers
/// with path `/dns-query`).
pub fn quad9_config(t: Encrypted) -> Value {
    let servers: Vec<Value> = QUAD9_SERVERS
        .iter()
        .map(|ip| match t {
            Encrypted::Dot => json!({"ip": ip, "tls_host": QUAD9_TLS_HOST}),
            Encrypted::Doh => json!({"ip": ip, "tls_host": QUAD9_TLS_HOST, "path": "/dns-query"}),
        })
        .collect();
    json!({
        "transport": t.as_str(),
        "servers": servers,
        "qtype": "A",
        "rules": [
            {"id": "blocked",  "when": {"ede": [15]}, "verdict": "block"},
            {"id": "censored", "when": {"ede": [16]}, "verdict": "block"},
            {"id": "filtered", "when": {"ede": [17]}, "verdict": "block"},
            {"id": "nxdomain_without_soa", "when": {"rcode": ["NXDOMAIN"], "soa": false, "ede": "none"}, "verdict": "unknown"}
        ],
        "self_test": {"name": "isitblocked.org", "expect": "block", "cron": HOURLY}
    })
}

fn build_quad9(v: &Value) -> anyhow::Result<(Value, Option<Category>)> {
    let p: Quad9Params = params(v)?;
    Ok((quad9_config(p.transport), Some(Category::Security)))
}

/// The `nextdns` config for a profile.
pub fn nextdns_config(p: &NextDnsParams) -> anyhow::Result<Value> {
    let profile = p.profile.trim();
    if profile.is_empty() || profile.len() > 32 || !profile.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("profile: the NextDNS configuration ID, letters and digits");
    }
    let profile = profile.to_ascii_lowercase();
    let servers: Vec<Value> = NEXTDNS_SERVERS
        .iter()
        .map(|ip| match p.transport {
            Encrypted::Dot => json!({"ip": ip, "tls_host": format!("{profile}.dns.nextdns.io")}),
            Encrypted::Doh => json!({"ip": ip, "tls_host": "dns.nextdns.io", "path": format!("/{profile}")}),
        })
        .collect();
    let mut cfg = json!({
        "transport": p.transport.as_str(),
        "servers": servers,
        "qtype": "A",
        "rules": [
            {"id": "blocked",  "when": {"ede": [15, 16, 17]}, "verdict": "block"},
            {"id": "sinkhole", "when": {"answers_in": ["0.0.0.0", "::"]}, "verdict": "block"}
        ]
    });
    if let Some(name) = p.self_test.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        let Some(name) = crate::name::check_name(name) else {
            bail!("self_test: a name of letters, digits, hyphens and underscores");
        };
        cfg["self_test"] = json!({"name": name, "expect": "block", "cron": HOURLY});
    }
    Ok(cfg)
}

fn build_nextdns(v: &Value) -> anyhow::Result<(Value, Option<Category>)> {
    let p: NextDnsParams = serde_json::from_value(v.clone()).context("invalid preset parameters")?;
    Ok((nextdns_config(&p)?, Some(Category::Mixed)))
}

/// Both presets.
pub fn presets() -> Vec<Preset> {
    vec![
        Preset {
            id: "quad9",
            title: "Quad9",
            params_schema: schemars::schema_for!(Quad9Params),
            build: build_quad9,
        },
        Preset {
            id: "nextdns",
            title: "NextDNS",
            params_schema: schemars::schema_for!(NextDnsParams),
            build: build_nextdns,
        },
    ]
}
