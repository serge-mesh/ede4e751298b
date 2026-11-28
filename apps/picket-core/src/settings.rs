//! Settings (core.md §11) with their defaults, typed accessors and validation.
//!
//! Stored in `core.db` `settings(key, value_json)`, one row per setting key in [`KEYS`] (dotted
//! paths such as `web.port`, or whole objects such as `crosscheck`). A missing row means the
//! default. The UI API reads the whole nested [`Settings`] and writes a partial nested object;
//! `null` at a setting key resets it to its default.
//!
//! Cross-entity rules (`default_profile`, `dnssec.listener`, `web.names` under `lanca.zones`,
//! the cross-check resolver's independence from the upstreams) are checked with the whole model
//! in `config::validate`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use picket_api::DurationStr;
use rusqlite::Connection;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Compiled-in release public keys (`release_keys`, core.md §11; build-and-test.md §1),
// populated at build time from `PICKET_RELEASE_PUB` / `PICKET_RELEASE_PUB_FILE`.
include!(concat!(env!("OUT_DIR"), "/release_keys.rs"));

/// The compiled-in firmware minimums (`dist/firmware.json`, see build.rs).
pub const FIRMWARE_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/firmware.json"));

/// Every stored setting key. A key is the dotted path of a field of [`Settings`].
pub const KEYS: &[&str] = &[
    "web.port",
    "web.tls",
    "web.cert_file",
    "web.key_file",
    "web.names",
    "web.addresses",
    "web.http_port",
    "web.allow_cidrs",
    "lists.allow_cidrs",
    "lists.profile_recheck_interval",
    "metrics.allow_cidrs",
    "edge_api.port",
    "lanca.zones",
    "retention.query_logs",
    "retention.metrics",
    "retention.bundle_versions",
    "retention.raw_downloads",
    "retention.feed_entries",
    "retention.feed_runs",
    "retention.feed_checks",
    "retention.lookup_blocks",
    "retention.dnssec_results",
    "retention.temp_allows",
    "retention.config_changes",
    "retention.edge_events",
    "retention.warnings",
    "resolver",
    "feeds.max_download_mib",
    "feeds.max_per_provider",
    "lookups.verdict_delta_s",
    "dnssec.enabled",
    "dnssec.listener",
    "dnssec.source_ips",
    "dnssec.dedupe_window",
    "dnssec.max_per_minute",
    "crosscheck",
    "alerts.evidence_per_alert",
    "alerts.evidence_total_mib",
    "alerts.thresholds",
    "alerts.feed_stale_days",
    "edges.min_firmware",
    "default_profile",
];

/// Keys a plain settings patch may not change: `lanca.zones` stays with the LAN CA's root, so
/// only a rotation changes it, with the new root (core.md §11, `lanca::rotation`).
pub const READ_ONLY_KEYS: &[&str] = &["lanca.zones"];

/// All settings.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Settings {
    pub web: WebSettings,
    pub lists: ListsSettings,
    pub metrics: MetricsSettings,
    pub edge_api: EdgeApiSettings,
    pub lanca: LancaSettings,
    pub retention: RetentionSettings,
    /// Core's own resolver for feed and provider hostnames: `system`, or an upstream by IP over
    /// DoT or DoH (README §3).
    pub resolver: Resolver,
    pub feeds: FeedsSettings,
    pub lookups: LookupsSettings,
    pub dnssec: DnssecSettings,
    pub crosscheck: Crosscheck,
    pub alerts: AlertsSettings,
    pub edges: EdgesSettings,
    /// The profile for clients no DoH path, DoT name or client entry assigns (edge.md §5).
    pub default_profile: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WebTls {
    /// A LAN-CA certificate for `web.names` and core's local and declared IPs in the LAN ranges.
    #[default]
    Managed,
    /// `web.cert_file` and `web.key_file`.
    File,
    /// Plain HTTP: credentials cross the network in clear.
    Off,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct WebSettings {
    /// The web port (UI, UI API, lists, `/healthz`, `/metrics`).
    pub port: u16,
    pub tls: WebTls,
    /// PEM certificate chain for `web.tls = file`.
    pub cert_file: Option<String>,
    /// PEM private key for `web.tls = file`.
    pub key_file: Option<String>,
    /// Core's own names, under `lanca.zones`: the web certificate and the `Host` allowlist.
    pub names: Vec<String>,
    /// Additional reachable IP literals for the Host allowlist. RFC1918/ULA addresses also enter
    /// the managed certificate; other addresses need a file certificate or a configured DNS name
    /// for verified HTTPS. This does not change binding or client access.
    pub addresses: Vec<String>,
    /// Optional plain-HTTP port for `/lists/*` and the LAN CA root.
    pub http_port: Option<u16>,
    /// Who may reach the UI, the UI API and `/healthz`.
    pub allow_cidrs: Vec<String>,
}

impl Default for WebSettings {
    fn default() -> Self {
        Self {
            port: picket_api::edge_api::DEFAULT_WEB_PORT,
            tls: WebTls::Managed,
            cert_file: None,
            key_file: None,
            names: vec![],
            addresses: vec![],
            http_port: None,
            allow_cidrs: everyone(),
        }
    }
}

fn everyone() -> Vec<String> {
    vec!["0.0.0.0/0".into(), "::/0".into()]
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListsSettings {
    /// Who may fetch browser lists, the LAN CA root and the extension downloads.
    pub allow_cidrs: Vec<String>,
    /// The most often a DNS change rebuilds a profile's pruned browser list.
    pub profile_recheck_interval: DurationStr,
}

impl Default for ListsSettings {
    fn default() -> Self {
        Self {
            allow_cidrs: everyone(),
            profile_recheck_interval: DurationStr::minutes(30),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MetricsSettings {
    /// Ranges that may read `GET /metrics`; empty turns the export off.
    pub allow_cidrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EdgeApiSettings {
    /// The edge API port (mTLS).
    pub port: u16,
}

impl Default for EdgeApiSettings {
    fn default() -> Self {
        Self {
            port: picket_api::edge_api::DEFAULT_EDGE_PORT,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LancaSettings {
    /// The DNS names the LAN CA may sign (core.md §11; default `home.arpa`), first set at `init`.
    /// Changing them rotates the LAN CA to a new root that every device must trust again: a
    /// `PUT settings` with other zones and `lanca.rotate_from` naming the current root
    /// (`lanca.fingerprint`); `lanca.can_rotate` says when one may start.
    pub zones: Vec<String>,
}

impl Default for LancaSettings {
    fn default() -> Self {
        Self {
            zones: vec!["home.arpa".into()],
        }
    }
}

/// Retention windows per data class (storage.md §4; default 72 h, feed checks 60 days).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RetentionSettings {
    /// Query logs, attribution and would-blocks; also published configs, tombstones and edge spools.
    pub query_logs: DurationStr,
    pub metrics: DurationStr,
    /// Bundle and verdict-set versions after the last edge stopped using them.
    pub bundle_versions: DurationStr,
    pub raw_downloads: DurationStr,
    /// Closed `feed_entries` rows.
    pub feed_entries: DurationStr,
    pub feed_runs: DurationStr,
    /// Feed checks and changes.
    pub feed_checks: DurationStr,
    pub lookup_blocks: DurationStr,
    pub dnssec_results: DurationStr,
    pub temp_allows: DurationStr,
    pub config_changes: DurationStr,
    pub edge_events: DurationStr,
    /// Resolved warnings.
    pub warnings: DurationStr,
}

impl Default for RetentionSettings {
    fn default() -> Self {
        let d = DurationStr::hours(72);
        Self {
            query_logs: d,
            metrics: d,
            bundle_versions: d,
            raw_downloads: d,
            feed_entries: d,
            feed_runs: d,
            feed_checks: DurationStr::days(60),
            lookup_blocks: d,
            dnssec_results: d,
            temp_allows: d,
            config_changes: d,
            edge_events: d,
            warnings: d,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ResolverName {
    /// The host's resolver.
    #[default]
    System,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EncryptedProtocol {
    #[default]
    Dot,
    Doh,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolverUpstream {
    pub protocol: EncryptedProtocol,
    pub ip: IpAddr,
    #[serde(default = "default_dot_port")]
    pub port: u16,
    pub tls_host: String,
    /// DoH path, default `/dns-query`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// PEM text; null = the Mozilla roots.
    #[serde(default)]
    pub trust_store: Option<String>,
}

fn default_dot_port() -> u16 {
    853
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Resolver {
    Named(ResolverName),
    Upstream(ResolverUpstream),
}

impl Default for Resolver {
    fn default() -> Self {
        Self::Named(ResolverName::System)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FeedsSettings {
    /// The download size cap, counted decoded.
    pub max_download_mib: u32,
    /// The most feeds one feed provider may have (feeds.md §1).
    pub max_per_provider: u32,
}

impl Default for FeedsSettings {
    fn default() -> Self {
        Self {
            max_download_mib: 256,
            max_per_provider: 50,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LookupsSettings {
    /// The verdict-set delta interval in seconds.
    pub verdict_delta_s: u32,
}

impl Default for LookupsSettings {
    fn default() -> Self {
        Self { verdict_delta_s: 300 }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct DnssecSettings {
    pub enabled: bool,
    /// The edge DoH listener chains are fetched through; null = the first DoH listener on a
    /// connected edge.
    pub listener: Option<String>,
    /// The addresses edges see core's traffic come from; null = core's own addresses (README §3).
    pub source_ips: Option<Vec<String>>,
    pub dedupe_window: DurationStr,
    /// Network requests per minute (chain lookups and fallback queries).
    pub max_per_minute: u32,
}

impl Default for DnssecSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            listener: None,
            source_ips: None,
            dedupe_window: DurationStr::hours(24),
            max_per_minute: 120,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CrosscheckResolver {
    pub protocol: EncryptedProtocol,
    pub ip: IpAddr,
    #[serde(default = "default_dot_port")]
    pub port: u16,
    pub tls_host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Who runs the resolver; it must differ from every upstream's operator (core.md §8).
    pub operator: String,
}

/// The cross-check of unsigned answers (core.md §8). Off by default: the resolver sees every
/// name checked.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Crosscheck {
    pub enabled: bool,
    pub resolver: Option<CrosscheckResolver>,
    pub negative: bool,
    pub sinkhole: bool,
    pub block_page_ips: Vec<IpAddr>,
    pub dedupe_window: DurationStr,
    pub max_per_minute: u32,
}

impl Default for Crosscheck {
    fn default() -> Self {
        Self {
            enabled: false,
            resolver: None,
            negative: true,
            sinkhole: true,
            block_page_ips: vec![],
            dedupe_window: DurationStr::hours(24),
            max_per_minute: 60,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AlertsSettings {
    pub evidence_per_alert: u32,
    pub evidence_total_mib: u32,
    /// Alert kind → how long its condition must hold before it fires (core.md §9). Kinds not
    /// listed use core.md §9's defaults: `edge_offline` 5 min; `edge_upstream_down`,
    /// `edge_redirect_missing`, `edge_fw_layout_unknown` and `edge_fw_catch_all` 2 min;
    /// `edge_helper_unreachable` 1 min; `edge_ssd_unavailable` 10 min; `upstream_invalid_spike`
    /// 5 min; `feed_down`, `feed_provider_down`, `feed_provider_trigger_down` and
    /// `dnssec_unavailable` 60 min; `lookup_provider_down` 15 min; any other kind at once.
    // The defaults: default_threshold (a test checks the list above).
    pub thresholds: BTreeMap<String, DurationStr>,
    /// The days per false `feed_stale` alert its threshold allows (feed-scheduling.md §8).
    pub feed_stale_days: u32,
}

impl Default for AlertsSettings {
    fn default() -> Self {
        Self {
            evidence_per_alert: 1000,
            evidence_total_mib: 128,
            thresholds: BTreeMap::new(),
            feed_stale_days: 30,
        }
    }
}

impl AlertsSettings {
    /// The effective threshold for `kind`.
    pub fn threshold(&self, kind: &str) -> std::time::Duration {
        self.thresholds
            .get(kind)
            .map(|d| d.as_duration())
            .unwrap_or_else(|| default_threshold(kind))
    }
}

/// Default thresholds from core.md §9's table; kinds without one fire at once.
pub fn default_threshold(kind: &str) -> std::time::Duration {
    let mins = match kind {
        "edge_offline" => 5,
        "edge_upstream_down" | "edge_redirect_missing" | "edge_fw_layout_unknown" | "edge_fw_catch_all" => 2,
        "edge_helper_unreachable" => 1,
        "edge_ssd_unavailable" => 10,
        "upstream_invalid_spike" => 5,
        "feed_down" | "feed_provider_down" | "feed_provider_trigger_down" | "dnssec_unavailable" => 60,
        "lookup_provider_down" => 15,
        _ => 0,
    };
    std::time::Duration::from_secs(mins * 60)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FirmwareMin {
    /// The UniFi hardware target (e.g. `UCGF`).
    pub target: String,
    /// The minimum UniFi OS version.
    pub min: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EdgesSettings {
    /// Minimum UniFi OS version per target; a release or an admin raises it.
    pub min_firmware: Vec<FirmwareMin>,
}

impl Default for EdgesSettings {
    fn default() -> Self {
        Self {
            min_firmware: compiled_min_firmware(),
        }
    }
}

impl EdgesSettings {
    /// The minimum each target must run: the higher of the release's compiled-in minimum and
    /// the admin's (core.md §11: a release or an admin raises it, never lowers it). Targets in
    /// target order.
    pub fn effective_min_firmware(&self) -> Vec<FirmwareMin> {
        self.effective_min_firmware_with(&compiled_min_firmware())
    }

    /// [`Self::effective_min_firmware`] against a given compiled-in list (tests).
    pub fn effective_min_firmware_with(&self, compiled: &[FirmwareMin]) -> Vec<FirmwareMin> {
        let mut out: BTreeMap<String, (Vec<u64>, String)> = BTreeMap::new();
        for m in compiled.iter().chain(self.min_firmware.iter()) {
            let Some(v) = parse_firmware_version(&m.min) else {
                continue;
            };
            match out.get(&m.target) {
                Some((cur, _)) if *cur >= v => {}
                _ => {
                    out.insert(m.target.clone(), (v, m.min.clone()));
                }
            }
        }
        out.into_iter()
            .map(|(target, (_, min))| FirmwareMin { target, min })
            .collect()
    }
}

/// The compiled-in `dist/firmware.json`.
pub fn compiled_min_firmware() -> Vec<FirmwareMin> {
    serde_json::from_str(FIRMWARE_JSON).unwrap_or_else(|_| {
        vec![FirmwareMin {
            target: "UCGF".into(),
            min: "6.0.17".into(),
        }]
    })
}

/// Compiled-in release keys (minisign public key lines), for display and verification.
pub fn release_keys() -> Vec<String> {
    RELEASE_KEYS.iter().map(|l| (*l).to_string()).collect()
}

// ---------------------------------------------------------------------------------------------
// Storage

/// Reads every setting row over the defaults.
pub fn load(conn: &Connection) -> Result<Settings> {
    let mut st = conn.prepare("SELECT key, value_json FROM settings")?;
    let rows = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut tree = serde_json::to_value(Settings::default())?;
    for (key, value) in rows {
        if !KEYS.contains(&key.as_str()) {
            continue; // a newer release's key: kept in the table, ignored here
        }
        let v: Value = match serde_json::from_str(&value) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(key, error = %e, "unreadable setting; using its default");
                continue;
            }
        };
        set_path(&mut tree, &key, v);
    }
    match serde_json::from_value::<Settings>(tree.clone()) {
        Ok(s) => Ok(s),
        Err(e) => {
            // One bad row must not stop core: fall back per key.
            tracing::warn!(error = %e, "stored settings don't parse together; dropping bad keys");
            let mut tree = serde_json::to_value(Settings::default())?;
            let mut st = conn.prepare("SELECT key, value_json FROM settings")?;
            let rows = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (key, value) in rows {
                if !KEYS.contains(&key.as_str()) {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<Value>(&value) else {
                    continue;
                };
                let mut trial = tree.clone();
                set_path(&mut trial, &key, v);
                if serde_json::from_value::<Settings>(trial.clone()).is_ok() {
                    tree = trial;
                }
            }
            Ok(serde_json::from_value(tree)?)
        }
    }
}

/// One stored row change: `None` deletes the row (back to the default).
pub type RowChange = (String, Option<Value>);

/// Applies a partial nested settings object. Returns the new settings and the rows to write.
pub fn apply_patch(
    current: &Settings,
    patch: &Value,
    allow_read_only: bool,
) -> Result<(Settings, Vec<RowChange>)> {
    let mut changes = Vec::new();
    collect_changes(patch, "", &mut changes)?;
    let mut tree = serde_json::to_value(current)?;
    let defaults = serde_json::to_value(Settings::default())?;
    for (key, v) in &mut changes {
        if key == "web.addresses"
            && let Some(value) = v.as_mut()
        {
            let addresses: Vec<String> =
                serde_json::from_value(value.clone()).context("invalid web.addresses")?;
            *value = serde_json::to_value(normalize_web_addresses(&addresses)?)?;
        }
        if !allow_read_only && READ_ONLY_KEYS.contains(&key.as_str()) {
            bail!("{key} can't be changed here: it is fixed at init and stays with the LAN CA");
        }
        let value = match v {
            Some(v) => v.clone(),
            None => get_path(&defaults, key).cloned().unwrap_or(Value::Null),
        };
        set_path(&mut tree, key, value);
    }
    let new: Settings = serde_json::from_value(tree).context("invalid settings")?;
    Ok((new, changes))
}

fn collect_changes(v: &Value, prefix: &str, out: &mut Vec<RowChange>) -> Result<()> {
    let Value::Object(map) = v else {
        bail!("settings must be a JSON object");
    };
    for (k, val) in map {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        if KEYS.contains(&key.as_str()) {
            out.push((key, if val.is_null() { None } else { Some(val.clone()) }));
        } else if KEYS.iter().any(|known| known.starts_with(&format!("{key}."))) && val.is_object() {
            collect_changes(val, &key, out)?;
        } else {
            bail!("unknown setting {key}");
        }
    }
    Ok(())
}

/// Writes row changes inside the caller's transaction.
pub fn write_rows(tx: &rusqlite::Transaction<'_>, rows: &[RowChange]) -> Result<()> {
    for (key, v) in rows {
        match v {
            Some(v) => {
                tx.execute(
                    "INSERT INTO settings(key, value_json) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
                    rusqlite::params![key, serde_json::to_string(v)?],
                )?;
            }
            None => {
                tx.execute("DELETE FROM settings WHERE key = ?1", [key])?;
            }
        }
    }
    Ok(())
}

/// The effective value of every key, flat (used for config-change diffs).
pub fn flat(settings: &Settings) -> BTreeMap<String, Value> {
    let tree = serde_json::to_value(settings).unwrap_or(Value::Null);
    KEYS.iter()
        .map(|k| (k.to_string(), get_path(&tree, k).cloned().unwrap_or(Value::Null)))
        .collect()
}

fn set_path(tree: &mut Value, key: &str, v: Value) {
    let mut cur = tree;
    let parts: Vec<&str> = key.split('.').collect();
    for (i, p) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            if let Value::Object(m) = cur {
                m.insert((*p).to_string(), v);
            }
            return;
        }
        if !cur.get(*p).is_some_and(Value::is_object) {
            if let Value::Object(m) = cur {
                m.insert((*p).to_string(), Value::Object(Default::default()));
            } else {
                return;
            }
        }
        match cur.get_mut(*p) {
            Some(next) => cur = next,
            None => return,
        }
    }
}

fn get_path<'a>(tree: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.').try_fold(tree, |cur, p| cur.get(p))
}

// ---------------------------------------------------------------------------------------------
// Validation of settings on their own

/// Parse exact reachable address literals and normalize IPv4-mapped IPv6 to IPv4.
pub fn normalize_web_addresses(addresses: &[String]) -> Result<Vec<String>> {
    if addresses.len() > crate::config::validate::MAX_LIST {
        bail!("web.addresses has too many entries");
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for address in addresses {
        let ip = address
            .parse::<IpAddr>()
            .map(crate::net::canonical_ip)
            .map_err(|_| anyhow!("{address:?} is not an IP address literal"))?;
        if ip.is_unspecified() || ip.is_multicast() || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast()) {
            bail!("{address:?} is not a unicast address");
        }
        let canonical = ip.to_string();
        if seen.insert(ip) {
            out.push(canonical);
        }
    }
    Ok(out)
}

/// A settings problem: the key and a message.
pub type SettingIssue = (String, String);

/// Checks every setting's range and syntax (cross-entity rules live in `config::validate`).
pub fn validate(s: &Settings) -> Vec<SettingIssue> {
    let mut out: Vec<SettingIssue> = Vec::new();
    let mut err = |k: &str, m: String| out.push((k.to_string(), m));

    if s.web.port == 0 {
        err("web.port", "the web port can't be 0".into());
    }
    if s.edge_api.port == 0 {
        err("edge_api.port", "the edge API port can't be 0".into());
    }
    if s.web.port == s.edge_api.port {
        err(
            "edge_api.port",
            "the edge API port must differ from the web port".into(),
        );
    }
    if let Some(p) = s.web.http_port
        && (p == 0 || p == s.web.port || p == s.edge_api.port)
    {
        err(
            "web.http_port",
            "the plain-HTTP port must be set and differ from the web and edge API ports".into(),
        );
    }
    if s.web.tls == WebTls::File {
        for (k, v) in [
            ("web.cert_file", &s.web.cert_file),
            ("web.key_file", &s.web.key_file),
        ] {
            match v {
                Some(p) if p.starts_with('/') => {}
                _ => err(k, format!("{k} must be an absolute path when web.tls is file")),
            }
        }
    }
    if let Err(e) = normalize_web_addresses(&s.web.addresses) {
        err("web.addresses", e.to_string());
    }
    for (k, list) in [
        ("web.allow_cidrs", &s.web.allow_cidrs),
        ("lists.allow_cidrs", &s.lists.allow_cidrs),
        ("metrics.allow_cidrs", &s.metrics.allow_cidrs),
    ] {
        check_cidrs(k, list, &mut err);
    }
    if s.lists.profile_recheck_interval.as_secs() < 60 {
        err("lists.profile_recheck_interval", "must be at least 1m".into());
    }
    match crate::lanca::normalize_zones(&s.lanca.zones) {
        Ok(z) => {
            for n in &s.web.names {
                if !crate::lanca::name_under_zones(n, &z) || n.starts_with("*.") {
                    err(
                        "web.names",
                        format!("{n:?} is not a name under lanca.zones ({})", z.join(", ")),
                    );
                }
            }
        }
        Err(e) => err("lanca.zones", e.to_string()),
    }
    let r = &s.retention;
    for (k, d) in [
        ("retention.query_logs", r.query_logs),
        ("retention.metrics", r.metrics),
        ("retention.bundle_versions", r.bundle_versions),
        ("retention.raw_downloads", r.raw_downloads),
        ("retention.feed_entries", r.feed_entries),
        ("retention.feed_runs", r.feed_runs),
        ("retention.feed_checks", r.feed_checks),
        ("retention.lookup_blocks", r.lookup_blocks),
        ("retention.dnssec_results", r.dnssec_results),
        ("retention.temp_allows", r.temp_allows),
        ("retention.config_changes", r.config_changes),
        ("retention.edge_events", r.edge_events),
        ("retention.warnings", r.warnings),
    ] {
        if d.as_secs() < 3600 || d.as_secs() > 366 * 86_400 {
            err(k, "a retention window must be between 1h and 366d".into());
        }
    }
    if let Resolver::Upstream(u) = &s.resolver {
        check_encrypted_endpoint(
            "resolver",
            u.protocol,
            &u.ip,
            u.port,
            &u.tls_host,
            u.path.as_deref(),
            &mut err,
        );
        if let Some(ts) = &u.trust_store
            && !crate::config::validate::pem_has_certificate(ts)
        {
            err(
                "resolver",
                "the resolver's trust_store must be PEM certificates (≤ 64 KiB)".into(),
            );
        }
    }
    if !(1..=4096).contains(&s.feeds.max_download_mib) {
        err("feeds.max_download_mib", "must be between 1 and 4096".into());
    }
    if !(1..=1000).contains(&s.feeds.max_per_provider) {
        err("feeds.max_per_provider", "must be between 1 and 1000".into());
    }
    if !(10..=86_400).contains(&s.lookups.verdict_delta_s) {
        err("lookups.verdict_delta_s", "must be between 10 and 86400".into());
    }
    if let Some(ips) = &s.dnssec.source_ips {
        check_cidrs("dnssec.source_ips", ips, &mut err);
        if ips.is_empty() {
            err(
                "dnssec.source_ips",
                "set at least one address, or null for core's own".into(),
            );
        }
    }
    check_window("dnssec.dedupe_window", s.dnssec.dedupe_window, &mut err);
    if !(1..=100_000).contains(&s.dnssec.max_per_minute) {
        err("dnssec.max_per_minute", "must be between 1 and 100000".into());
    }
    let c = &s.crosscheck;
    if let Some(res) = &c.resolver {
        check_encrypted_endpoint(
            "crosscheck",
            res.protocol,
            &res.ip,
            res.port,
            &res.tls_host,
            res.path.as_deref(),
            &mut err,
        );
        if res.operator.trim().is_empty() {
            err(
                "crosscheck",
                "the cross-check resolver must name its operator".into(),
            );
        }
    } else if c.enabled {
        err("crosscheck", "the cross-check needs a resolver".into());
    }
    check_window("crosscheck", c.dedupe_window, &mut err);
    if !(1..=100_000).contains(&c.max_per_minute) {
        err("crosscheck", "max_per_minute must be between 1 and 100000".into());
    }
    if !(10..=100_000).contains(&s.alerts.evidence_per_alert) {
        err(
            "alerts.evidence_per_alert",
            "must be between 10 and 100000".into(),
        );
    }
    if !(1..=65_536).contains(&s.alerts.evidence_total_mib) {
        err("alerts.evidence_total_mib", "must be between 1 and 65536".into());
    }
    if !(1..=3650).contains(&s.alerts.feed_stale_days) {
        err("alerts.feed_stale_days", "must be between 1 and 3650".into());
    }
    for (kind, d) in &s.alerts.thresholds {
        if !crate::alerts::is_known_kind(kind) {
            err("alerts.thresholds", format!("unknown alert kind {kind:?}"));
        }
        if d.as_secs() > 7 * 86_400 {
            err("alerts.thresholds", format!("the threshold of {kind} is over 7d"));
        }
    }
    let compiled = compiled_min_firmware();
    for m in &s.edges.min_firmware {
        if m.target.trim().is_empty() || m.target.len() > 64 {
            err("edges.min_firmware", "each entry needs a target".into());
        }
        let Some(v) = parse_firmware_version(&m.min) else {
            err("edges.min_firmware", format!("{:?} is not a version", m.min));
            continue;
        };
        if let Some(c) = compiled.iter().find(|c| c.target == m.target)
            && let Some(cv) = parse_firmware_version(&c.min)
            && v < cv
        {
            err(
                "edges.min_firmware",
                format!(
                    "{} can't go below the release's minimum {} (it can only be raised)",
                    m.target, c.min
                ),
            );
        }
    }
    // A target left out keeps its compiled-in minimum (`EdgesSettings::effective_min_firmware`).
    out
}

fn check_cidrs(key: &str, list: &[String], err: &mut impl FnMut(&str, String)) {
    if list.len() > 1024 {
        err(key, "at most 1024 ranges".into());
    }
    for c in list {
        if crate::net::parse_net(c).is_none() {
            err(key, format!("{c:?} is not an address range"));
        }
    }
}

fn check_window(key: &str, d: DurationStr, err: &mut impl FnMut(&str, String)) {
    if d.as_secs() < 60 || d.as_secs() > 30 * 86_400 {
        err(key, "the dedupe window must be between 1m and 30d".into());
    }
}

fn check_encrypted_endpoint(
    key: &str,
    protocol: EncryptedProtocol,
    ip: &IpAddr,
    port: u16,
    tls_host: &str,
    path: Option<&str>,
    err: &mut impl FnMut(&str, String),
) {
    if ip.is_unspecified() {
        err(key, "the resolver needs an IP".into());
    }
    // A socket address from settings carries no interface scope, so a link-local one fails at
    // connect (EINVAL), as for upstreams (`config::validate`, `link_local`).
    if matches!(crate::net::canonical_ip(*ip), IpAddr::V6(v6) if v6.is_unicast_link_local()) {
        err(
            key,
            "an IPv6 link-local address (fe80::/10) needs an interface scope, which a resolver can't carry: use a global, ULA or loopback address".into(),
        );
    }
    if port == 0 {
        err(key, "the resolver port can't be 0".into());
    }
    if !crate::lanca::is_dns_name(&tls_host.to_ascii_lowercase()) {
        err(key, format!("{tls_host:?} is not a TLS host name"));
    }
    match (protocol, path) {
        (EncryptedProtocol::Doh, Some(p)) if !p.starts_with('/') => {
            err(key, "the DoH path must start with /".into())
        }
        (EncryptedProtocol::Dot, Some(_)) => err(key, "a DoT resolver has no path".into()),
        _ => {}
    }
}

/// Parses a UniFi OS version such as `6.0.17` (leading `v` allowed) into numeric parts.
pub fn parse_firmware_version(s: &str) -> Option<Vec<u64>> {
    let s = s.trim().trim_start_matches('v');
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    s.split('.')
        .map(|p| p.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()
}

/// Shortcut: the settings as a JSON value.
pub fn to_value(s: &Settings) -> Value {
    serde_json::to_value(s).unwrap_or(Value::Null)
}

/// Reads one setting row's value (for tools and tests).
pub fn get_row(conn: &Connection, key: &str) -> Result<Option<Value>> {
    let v: Option<String> = conn
        .query_row("SELECT value_json FROM settings WHERE key = ?1", [key], |r| {
            r.get(0)
        })
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    v.map(|s| serde_json::from_str(&s).map_err(|e| anyhow!(e)))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_resolvers_are_refused() {
        let check = |ip: &str| {
            let mut errs = Vec::new();
            check_encrypted_endpoint(
                "resolver",
                EncryptedProtocol::Dot,
                &ip.parse().unwrap(),
                853,
                "dns.example",
                None,
                &mut |k: &str, m: String| errs.push((k.to_string(), m)),
            );
            errs
        };
        for bad in ["fe80::1", "fe80::abcd:1", "febf::1"] {
            let e = check(bad);
            assert!(
                e.iter().any(|(k, m)| k == "resolver" && m.contains("link-local")),
                "{bad}: {e:?}"
            );
        }
        for ok in ["9.9.9.9", "::1", "fd00::53", "2620:fe::fe", "192.168.1.1"] {
            assert!(check(ok).is_empty(), "{ok}: {:?}", check(ok));
        }
    }

    #[test]
    fn web_address_patch_canonicalizes_each_written_row() {
        let patch = serde_json::json!({"web": {"addresses": ["192.168.1.1"]}, "web.addresses": ["::ffff:192.168.1.2", "192.168.1.2"]});
        let (s, rows) = apply_patch(&Settings::default(), &patch, false).unwrap();
        assert_eq!(s.web.addresses, ["192.168.1.2"]);
        assert_eq!(rows.last().unwrap().1, Some(serde_json::json!(["192.168.1.2"])));
    }

    #[test]
    fn web_address_literals_are_validated_and_canonicalized() {
        let values = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            normalize_web_addresses(&values(&["192.168.1.5", "::ffff:192.168.1.5", "FD00:0:0::1"])).unwrap(),
            values(&["192.168.1.5", "fd00::1"])
        );
        for bad in [
            "example.com",
            "https://10.0.0.1",
            "10.0.0.1:443",
            "10.0.0.0/8",
            "0.0.0.0",
            "::",
            "::ffff:0.0.0.0",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            " 10.0.0.1",
        ] {
            assert!(normalize_web_addresses(&values(&[bad])).is_err(), "{bad}");
        }
    }

    #[test]
    fn defaults_roundtrip_and_are_valid() {
        let s = Settings::default();
        assert_eq!(s.web.port, 8443);
        assert_eq!(s.edge_api.port, 7443);
        assert_eq!(s.lanca.zones, vec!["home.arpa"]);
        assert_eq!(s.retention.query_logs.as_secs(), 72 * 3600);
        assert_eq!(s.retention.feed_checks.as_secs(), 60 * 86_400);
        assert!(!s.crosscheck.enabled);
        assert_eq!(s.edges.min_firmware[0].target, "UCGF");
        assert!(validate(&s).is_empty(), "{:?}", validate(&s));
        let v = serde_json::to_value(&s).unwrap();
        let back: Settings = serde_json::from_value(v).unwrap();
        assert_eq!(s, back);
        assert_eq!(serde_json::to_value(&s.resolver).unwrap(), "system");
        assert_eq!(s.alerts.threshold("edge_offline").as_secs(), 300);
        assert_eq!(s.alerts.threshold("edge_fw_drift").as_secs(), 0);
    }

    #[test]
    fn every_key_is_a_path() {
        let tree = serde_json::to_value(Settings::default()).unwrap();
        for k in KEYS {
            assert!(get_path(&tree, k).is_some(), "{k}");
        }
    }

    #[test]
    fn patch_and_reset() {
        let s = Settings::default();
        let (s2, rows) = apply_patch(&s, &serde_json::json!({"web": {"port": 9443}}), false).unwrap();
        assert_eq!(s2.web.port, 9443);
        assert_eq!(
            rows,
            vec![("web.port".to_string(), Some(serde_json::json!(9443)))]
        );
        let (s3, rows) = apply_patch(&s2, &serde_json::json!({"web": {"port": null}}), false).unwrap();
        assert_eq!(s3.web.port, 8443);
        assert_eq!(rows[0].1, None);
        assert!(apply_patch(&s, &serde_json::json!({"web": {"nope": 1}}), false).is_err());
        assert!(apply_patch(&s, &serde_json::json!({"lanca": {"zones": ["x.arpa"]}}), false).is_err());
        assert!(apply_patch(&s, &serde_json::json!({"web": {"port": "x"}}), false).is_err());
        let (s4, _) = apply_patch(
            &s,
            &serde_json::json!({"crosscheck": {"enabled": true, "resolver": {"protocol": "dot", "ip": "9.9.9.10", "tls_host": "dns10.quad9.net", "operator": "quad9"}}}),
            false,
        )
        .unwrap();
        assert!(s4.crosscheck.enabled);
        assert_eq!(s4.crosscheck.resolver.as_ref().unwrap().port, 853);
        assert!(validate(&s4).is_empty());
    }

    #[test]
    fn validation_catches_bad_values() {
        let mut s = Settings::default();
        s.web.names = vec!["core.example.com".into()];
        s.web.allow_cidrs = vec!["nope".into()];
        s.edge_api.port = 8443;
        s.crosscheck.enabled = true;
        s.edges.min_firmware = vec![FirmwareMin {
            target: "UCGF".into(),
            min: "5.0.0".into(),
        }];
        let issues = validate(&s);
        let keys: Vec<&str> = issues.iter().map(|(k, _)| k.as_str()).collect();
        for k in [
            "web.names",
            "web.allow_cidrs",
            "edge_api.port",
            "crosscheck",
            "edges.min_firmware",
        ] {
            assert!(keys.contains(&k), "{k} in {issues:?}");
        }
    }

    #[test]
    fn compiled_firmware_minimum_always_applies() {
        // core.md §11: "a release or an admin raises it": the effective minimum per target is
        // the higher of the compiled-in one and the admin's.
        let fm = |t: &str, v: &str| FirmwareMin {
            target: t.into(),
            min: v.into(),
        };
        let compiled = vec![fm("UCGF", "6.1.0")];
        let mut e = EdgesSettings {
            min_firmware: vec![fm("UCGF", "6.0.20")],
        };
        // Stored by an admin under an older release, then this release raised the minimum.
        assert_eq!(
            e.effective_min_firmware_with(&compiled),
            vec![fm("UCGF", "6.1.0")]
        );
        e.min_firmware = vec![fm("UCGF", "6.2.0")];
        assert_eq!(
            e.effective_min_firmware_with(&compiled),
            vec![fm("UCGF", "6.2.0")]
        );
        e.min_firmware = vec![fm("UDMPRO", "4.0.0")];
        assert_eq!(
            e.effective_min_firmware_with(&compiled),
            vec![fm("UCGF", "6.1.0"), fm("UDMPRO", "4.0.0")]
        );
        // Leaving a target out isn't an error: its compiled minimum applies anyway.
        let mut s = Settings::default();
        s.edges.min_firmware = vec![];
        assert!(validate(&s).is_empty(), "{:?}", validate(&s));
        assert_eq!(s.edges.effective_min_firmware(), compiled_min_firmware());
    }

    #[test]
    fn storage_roundtrip() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL)")
            .unwrap();
        let mut c = c;
        let (s, rows) = apply_patch(
            &Settings::default(),
            &serde_json::json!({"retention": {"query_logs": "48h"}, "default_profile": "kids"}),
            false,
        )
        .unwrap();
        let tx = c.transaction().unwrap();
        write_rows(&tx, &rows).unwrap();
        tx.commit().unwrap();
        // A newer release's key and a bad row don't break loading.
        c.execute("INSERT INTO settings VALUES ('future.key', '1')", [])
            .unwrap();
        let loaded = load(&c).unwrap();
        assert_eq!(loaded, s);
        c.execute(
            "UPDATE settings SET value_json = '\"bogus\"' WHERE key = 'retention.query_logs'",
            [],
        )
        .unwrap();
        let loaded = load(&c).unwrap();
        assert_eq!(loaded.retention.query_logs.as_secs(), 72 * 3600);
        assert_eq!(loaded.default_profile.as_deref(), Some("kids"));
    }

    #[test]
    fn compiled_release_keys_are_valid() {
        for k in release_keys() {
            assert!(minisign_verify::PublicKey::from_base64(&k).is_ok(), "{k:?}");
        }
    }

    #[allow(dead_code, reason = "build script entrypoints are called from build.rs")]
    mod release_key_build_support {
        include!("../../../build-support/release_keys.rs");

        #[test]
        fn parses_single_multi_and_pub_file_formats() {
            let k1 = minisign::KeyPair::generate_unencrypted_keypair()
                .unwrap()
                .pk
                .to_base64();
            let k2 = minisign::KeyPair::generate_unencrypted_keypair()
                .unwrap()
                .pk
                .to_base64();

            assert_eq!(parse_release_keys(&k1).unwrap(), vec![k1.clone()]);
            assert_eq!(
                parse_release_keys(&format!("untrusted comment: test\n{k1}\n")).unwrap(),
                vec![k1.clone()]
            );
            assert_eq!(
                parse_release_keys(&format!("{k1}, {k2}\n{k1}")).unwrap(),
                vec![k1.clone(), k2.clone()]
            );
            assert_eq!(
                parse_release_keys(&format!(
                    "untrusted comment: old\n{k1}\n\nuntrusted comment: new\n{k2}\n"
                ))
                .unwrap(),
                vec![k1, k2]
            );
            assert!(
                parse_release_keys("untrusted comment: only\n")
                    .unwrap()
                    .is_empty()
            );
        }

        #[test]
        fn rejects_invalid_keys_and_require_flags() {
            for bad in ["not-base64!", "Zm9v", "RWRn", "AAAA"] {
                assert!(parse_release_keys(bad).is_err(), "{bad:?}");
            }
            assert!(!parse_require_flag(None).unwrap());
            assert!(!parse_require_flag(Some("")).unwrap());
            assert!(!parse_require_flag(Some("0")).unwrap());
            assert!(!parse_require_flag(Some("false")).unwrap());
            assert!(parse_require_flag(Some("1")).unwrap());
            assert!(parse_require_flag(Some("TRUE")).unwrap());
            assert!(parse_require_flag(Some("yes")).is_err());
        }
    }
}
