//! `EdgeConfig`: the per-edge config object core renders (api.md §4). Everything the edge should
//! run, fully expanded, plus the heads it should run and the requests it should apply.
//!
//! Defaults here are the spec's defaults, so a document that leaves a field out means the
//! default. Its id is the BLAKE3 of the rendered bytes; the document doesn't carry it.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::DurationStr;

/// The whole desired state of one edge.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EdgeConfig {
    pub edge: EdgeInfo,
    pub listeners: Vec<Listener>,
    /// Profile for clients no DoH path, DoT name or client entry assigns (edge.md §5).
    pub default_profile: Option<String>,
    pub clients: Vec<Client>,
    pub profiles: BTreeMap<String, Profile>,
    pub upstreams: BTreeMap<String, Upstream>,
    pub upstream_groups: BTreeMap<String, UpstreamGroup>,
    /// Only the zones this edge's profiles list.
    pub forward_zones: BTreeMap<String, ForwardZone>,
    pub cache: CacheSettings,
    /// Bundle id → head id (BLAKE3 of its `head.json`) to run.
    pub bundles: BTreeMap<String, String>,
    /// Lookup provider id → verdict-set head id to run.
    pub verdict_sets: BTreeMap<String, String>,
    /// Only the lookup providers this edge's profiles attach `sync`.
    pub lookup_providers: BTreeMap<String, LookupProviderConfig>,
    /// Secret values referenced as `${secret:name}` by the lookup providers above.
    pub secrets: BTreeMap<String, String>,
    pub firewall: FirewallConfig,
    pub unifi: UnifiConfig,
    pub logging: LoggingConfig,
    pub limits: Limits,
    pub memory: MemoryConfig,
    pub release: Option<ReleaseOffer>,
    pub flush: Flush,
    pub revoked_allows: Option<RevokedAllows>,
    /// The fingerprint (`ids::cert_fingerprint`) of the LAN CA root that signs managed listener
    /// certificates now. A `lanca.zones` change makes a new root (core.md §11); the edge then
    /// replaces each managed certificate another root issued (edge.md §5). Null: no check.
    pub lanca_root: Option<String>,
}

impl EdgeConfig {
    /// True when this config needs picket-edge-helper (edge.md §9): any firewall interface or a
    /// UniFi redirect.
    pub fn needs_helper(&self) -> bool {
        !self.firewall.interfaces.is_empty() || self.unifi.redirect.is_some()
    }

    /// The config without the fields whose changes don't count as a config change for
    /// `config/<hash>.json` (edge.md §2): `bundles`, `verdict_sets`, `release`, `flush`,
    /// `revoked_allows`.
    pub fn without_runtime_fields(&self) -> EdgeConfig {
        let mut c = self.clone();
        c.bundles.clear();
        c.verdict_sets.clear();
        c.release = None;
        c.flush = Flush::default();
        c.revoked_allows = None;
        c
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EdgeInfo {
    pub id: String,
    pub name: String,
    pub platform: Platform,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    #[default]
    Unifi,
    Debian,
}

// ---------------------------------------------------------------------------------------------
// Listeners (edge.md §5)

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProto {
    /// UDP and TCP.
    #[default]
    Dns,
    Dot,
    Doh,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Listener {
    pub id: String,
    pub proto: ListenerProto,
    /// `ip:port`, e.g. `[::]:5335` or `192.168.1.1:853`; matched exactly against `allowed_binds`.
    pub bind: String,
    /// Interfaces whose traffic the listener accepts; empty = all.
    pub interfaces: Vec<String>,
    pub tls: Option<ListenerTls>,
    /// Also serve the bypass API (DoH listeners).
    pub api: bool,
    /// The addresses clients reach this listener at, answered for its managed TLS name and its
    /// `*.name` (edge.md §4). Core fills it from a specific bind; set by hand for a wildcard bind.
    pub ips: Vec<IpAddr>,
    pub limits: ListenerLimits,
}

/// Either a managed certificate (`{"managed": "dns.home.arpa"}`) or files.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListenerTls {
    /// The managed TLS name; the edge generates a P-256 key and sends a CSR to core.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListenerLimits {
    pub max_connections: u32,
    pub idle_timeout_ms: u32,
    pub udp_payload: u16,
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self {
            max_connections: 512,
            idle_timeout_ms: 10_000,
            udp_payload: 1232,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Clients and profiles (edge.md §5, rules.md §5)

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Client {
    pub name: String,
    /// Lowercase `aa:bb:cc:dd:ee:ff`.
    pub macs: Vec<String>,
    /// Address ranges (CIDR, or a bare address).
    pub source_ips: Vec<String>,
    /// `None`: the client only names its devices.
    pub profile: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Profile {
    /// Address ranges, MACs and client names admitted; default everyone.
    pub allowed_sources: Vec<String>,
    /// Allow bundles, in order (ladder step 2).
    pub allow: Vec<String>,
    /// Block bundles, in order (ladder step 3).
    pub block: Vec<String>,
    pub forward_zones: Vec<String>,
    pub private_reverse: PrivateReverse,
    /// Lookup providers attached to this profile: `sync` waits up to `sync_lookup_budget_ms` on
    /// the edge before answering, `async` checks on core after answering.
    pub lookup_providers: Vec<LookupAttachment>,
    /// Maximum time in milliseconds (1–10000) the edge waits for `sync` lookup providers before
    /// answering; each provider also has its own `sync_timeout_ms`.
    pub sync_lookup_budget_ms: u32,
    /// Upstream group id.
    pub upstream: String,
    pub ttl: TtlClamp,
    pub block_response: BlockResponse,
    pub response_checks: ResponseChecks,
    pub firewall: ProfileFirewall,
    pub log: LogLevel,
    pub bypass: Bypass,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            allowed_sources: vec!["0.0.0.0/0".into(), "::/0".into()],
            allow: vec![],
            block: vec![],
            forward_zones: vec![],
            private_reverse: PrivateReverse::default(),
            lookup_providers: vec![],
            sync_lookup_budget_ms: 150,
            upstream: "cloudflare".into(),
            ttl: TtlClamp::default(),
            block_response: BlockResponse::default(),
            response_checks: ResponseChecks::default(),
            firewall: ProfileFirewall::default(),
            log: LogLevel::default(),
            bypass: Bypass::default(),
        }
    }
}

/// What a private-range PTR query that none of the profile's forward zones covers gets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrivateReverse {
    /// Answered locally with NXDOMAIN.
    #[default]
    Nxdomain,
    /// Sent to the profile's upstream group like any other name.
    Upstream,
}

/// When an attached lookup provider runs: inline on the edge (`sync`) or on core after answering
/// (`async`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LookupMode {
    /// Run on the edge before answering, waiting up to `sync_lookup_budget_ms`.
    #[default]
    Sync,
    /// Run on core after the edge answers, from the query log.
    Async,
}

/// One lookup provider attached to a profile.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LookupAttachment {
    /// Lookup provider id (not the module id).
    pub provider: String,
    /// Whether this provider runs inline on the edge (`sync`) or on core from the query log
    /// (`async`).
    pub mode: LookupMode,
    /// When non-empty, only names matching one of these bundles are sent to this provider (in
    /// addition to the provider's own `scope.include_bundles`).
    pub include_bundles: Vec<String>,
    /// Names matching any of these bundles are skipped for this provider (in addition to the
    /// provider's own `scope.exclude_bundles`).
    pub exclude_bundles: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TtlClamp {
    pub min: u32,
    pub max: u32,
}

impl Default for TtlClamp {
    fn default() -> Self {
        Self { min: 0, max: 300 }
    }
}

impl TtlClamp {
    pub fn clamp(&self, ttl: u32) -> u32 {
        ttl.max(self.min).min(self.max.max(self.min))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponseType {
    /// 0.0.0.0 or :: for A/AAAA, NODATA for other types.
    #[default]
    NullIp,
    Nxdomain,
    Nodata,
    Refused,
    /// `ipv4`/`ipv6` for A/AAAA, NODATA for other types.
    CustomIp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BlockResponse {
    #[serde(rename = "type")]
    pub kind: BlockResponseType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Addr>,
    pub ttl: u32,
}

impl Default for BlockResponse {
    fn default() -> Self {
        Self {
            kind: BlockResponseType::NullIp,
            ipv4: None,
            ipv6: None,
            ttl: 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseChecks {
    #[default]
    SkipAfterAllow,
    All,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FwGranularity {
    #[default]
    PerClientIp,
    Global,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnFull {
    #[default]
    ReplyAnyway,
    Servfail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ProfileFirewall {
    pub add_entries: bool,
    pub granularity: FwGranularity,
    pub grace_s: u32,
    pub on_full: OnFull,
}

impl Default for ProfileFirewall {
    fn default() -> Self {
        Self {
            add_entries: true,
            granularity: FwGranularity::PerClientIp,
            grace_s: 120,
            on_full: OnFull::ReplyAnyway,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    #[default]
    Full,
    Blocked,
    Off,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BypassMode {
    #[default]
    Off,
    #[serde(rename = "self")]
    SelfService,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Bypass {
    pub mode: BypassMode,
    pub max_duration: DurationStr,
    pub ips: bool,
    pub max_active: u32,
    pub rate_per_hour: u32,
}

impl Default for Bypass {
    fn default() -> Self {
        Self {
            mode: BypassMode::Off,
            max_duration: DurationStr::hours(24),
            ips: false,
            max_active: 50,
            rate_per_hour: 20,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Upstreams and forward zones (edge.md §6)

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    #[default]
    Dot,
    Doh,
    Udp,
    Tcp,
}

impl UpstreamProtocol {
    /// DoT and DoH are encrypted; UDP and TCP are plain.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Dot | Self::Doh)
    }
}

/// One resolver endpoint, by IP plus TLS name (hard rule 9). `operator` is core-only and isn't
/// rendered into `EdgeConfig`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Upstream {
    pub protocol: UpstreamProtocol,
    pub ip: IpAddr,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_host: Option<String>,
    /// DoH path, default `/dns-query` ([`is_doh_path`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// PEM text; `None` = the Mozilla roots.
    pub trust_store: Option<String>,
}

/// The longest block TTL the edge serves (`block_response.ttl`): the extension's shortest allow
/// choice (15 min) minus the 5 s hold slack ([`BLOCK_HOLD_SLACK_S`]) and the 5 s reload margin
/// ([`RELOAD_BEFORE_EXPIRY_S`]), so a cached block answer expires inside any allow of 15 min or
/// more and the reload after it gets the fresh answer. The edge lowers longer TTLs to this; core
/// accepts them with a warning. Shorter allows are possible (`bypass.max_duration` down to 1 min,
/// or a short request): [`min_allow_for_block_s`] says which fit (#50).
pub const MAX_BLOCK_TTL_S: u32 = 890;

/// Seconds past the block TTL that a block's hold adds: a reload right at the TTL can still find
/// the browser's cached block answer unexpired, and Firefox then serves it to the extension's
/// second attempt too, while refreshing it (#15). With the slack the reload finds it expired.
pub const BLOCK_HOLD_SLACK_S: u64 = 5;

/// The shortest hold: browsers that resolve through the system resolver keep an answer for a
/// fixed minute whatever its TTL (Firefox's `network.dnsCacheExpiration`), and Firefox then
/// serves the expired entry once more while refreshing it. A reload right at 60 s can find the
/// entry unexpired, leaving the extension's second attempt to meet that stale copy (#51); 5 s
/// past the minute, the reload itself starts the refresh and the second attempt gets the answer.
pub const BLOCK_HOLD_MIN_S: u64 = 65;

/// How long before an allow ends its reload must happen at the latest: room for the reload and
/// the extension's second attempt 2 s later while the allow still holds.
pub const RELOAD_BEFORE_EXPIRY_S: u64 = 5;

/// A block's hold: how long after a block answer served with `ttl` a browser may still use its
/// cached copy, `max(65 s, TTL + 5 s)` (the `retry_after_s` the bypass API reports for a fresh
/// block).
pub fn block_hold_s(ttl: u32) -> u64 {
    BLOCK_HOLD_MIN_S.max(u64::from(ttl) + BLOCK_HOLD_SLACK_S)
}

/// The shortest temporary allow that lifts a block answer served just now with `ttl` (the edge
/// serves at most [`MAX_BLOCK_TTL_S`]): its hold, then the reload margin before the allow ends.
/// A shorter allow would end while the browser still uses the cached block answer, so the edge
/// refuses one (`403 too_short`) and core refuses a profile whose `bypass.max_duration` is
/// shorter than this for its `block_response.ttl` (#50).
pub fn min_allow_for_block_s(ttl: u32) -> u64 {
    block_hold_s(ttl.min(MAX_BLOCK_TTL_S)) + RELOAD_BEFORE_EXPIRY_S
}

/// The longest DoH request path.
pub const MAX_DOH_PATH: usize = 256;

/// What [`is_doh_path`] accepts, for error messages.
pub const DOH_PATH_RULE: &str = "an absolute path of at most 256 bytes in RFC 3986 path characters \
     (letters, digits, -._~, %XX, !$&'()*+,;=, :, @ and /), without . or .. segments, query or fragment";

/// True for a DoH request path that core and the edge send alike (edge.md §6 upstreams,
/// providers.md §5 lookup `dns` servers): it starts with `/`, has at most [`MAX_DOH_PATH`]
/// bytes, only RFC 3986 path characters (unreserved, `%XX`, sub-delims, `:`, `@`, `/`) and no
/// `.` or `..` segment, percent-encoded or not. So no `\`, `?` or `#`, and the `url` crate
/// (core's client) and `http::Uri` (the edge's) read it the same way, unchanged.
pub fn is_doh_path(p: &str) -> bool {
    let b = p.as_bytes();
    if b.first() != Some(&b'/') || b.len() > MAX_DOH_PATH {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
                {
                    return false;
                }
                i += 3;
            }
            c if c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&c) => i += 1,
            _ => return false,
        }
    }
    // The URL standard also reads `%2e` as a dot in a dot segment.
    p.split('/').all(|seg| {
        let seg = seg.to_ascii_lowercase().replace("%2e", ".");
        seg != "." && seg != ".."
    })
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            protocol: UpstreamProtocol::Dot,
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 853,
            tls_host: None,
            path: None,
            trust_store: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GroupStrategy {
    #[default]
    Fastest,
    Failover,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UpstreamGroup {
    pub upstreams: Vec<String>,
    pub strategy: GroupStrategy,
    pub optimistic: bool,
}

impl Default for UpstreamGroup {
    fn default() -> Self {
        Self {
            upstreams: vec![],
            strategy: GroupStrategy::Fastest,
            optimistic: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ZoneFallback {
    #[default]
    None,
    Default,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ForwardZone {
    pub zone: String,
    /// Upstream group id.
    pub group: String,
    pub fallback: ZoneFallback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct CacheSettings {
    pub size_mib: u32,
    pub stale_ttl_s: u32,
    pub stale_max_s: u32,
    pub prefetch_min_hits: u32,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            size_mib: 8,
            stale_ttl_s: 30,
            stale_max_s: 86_400,
            prefetch_min_hits: 3,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Lookup providers (providers.md §4)

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    #[default]
    Open,
    Closed,
}

/// The per-provider settings the `LookupClient` applies, on edge and core alike.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LookupSettings {
    pub sync_timeout_ms: u32,
    pub async_timeout_ms: u32,
    pub fail_mode: FailMode,
    pub retries: bool,
    pub async_max_attempts: u32,
    pub recheck: Recheck,
    pub scope: LookupScope,
    pub cache: VerdictCacheSettings,
    pub limits: LookupLimits,
    pub breaker: BreakerSettings,
}

impl Default for LookupSettings {
    fn default() -> Self {
        Self {
            sync_timeout_ms: 150,
            async_timeout_ms: 10_000,
            fail_mode: FailMode::Open,
            retries: true,
            async_max_attempts: 5,
            recheck: Recheck::default(),
            scope: LookupScope::default(),
            cache: VerdictCacheSettings::default(),
            limits: LookupLimits::default(),
            breaker: BreakerSettings::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Recheck {
    pub enabled: bool,
    pub after: Vec<DurationStr>,
    pub jitter: DurationStr,
    pub max_per_day: Option<u32>,
}

impl Default for Recheck {
    fn default() -> Self {
        Self {
            enabled: true,
            after: vec![DurationStr::hours(24), DurationStr::hours(48)],
            jitter: DurationStr::hours(1),
            max_per_day: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LookupScope {
    /// When non-empty, only names matching one of these bundles are sent to this provider.
    pub include_bundles: Vec<String>,
    /// Names matching any of these bundles are skipped for this provider.
    pub exclude_bundles: Vec<String>,
    /// Query types that call the provider (a live Block blocks every type in scope).
    pub qtypes: Vec<String>,
}

impl Default for LookupScope {
    fn default() -> Self {
        Self {
            include_bundles: vec![],
            exclude_bundles: vec!["lookup-exclude".into(), "allow-common".into()],
            qtypes: vec!["A".into(), "AAAA".into(), "HTTPS".into(), "CNAME".into()],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct VerdictCacheSettings {
    pub block_ttl_s: u32,
    pub clean_ttl_s: u32,
    pub unknown_ttl_s: u32,
    pub error_ttl_s: u32,
    /// Edge only: the RAM tier's size.
    pub max_mib: u32,
}

impl Default for VerdictCacheSettings {
    fn default() -> Self {
        Self {
            block_ttl_s: 86_400,
            clean_ttl_s: 21_600,
            unknown_ttl_s: 60,
            error_ttl_s: 30,
            max_mib: 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LookupLimits {
    pub max_inflight: u32,
    pub rps: u32,
    pub burst: u32,
}

impl Default for LookupLimits {
    fn default() -> Self {
        Self {
            max_inflight: 64,
            rps: 50,
            burst: 300,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BreakerSettings {
    pub failures: u32,
    pub open_s: u32,
    pub half_open: u32,
}

impl Default for BreakerSettings {
    fn default() -> Self {
        Self {
            failures: 5,
            open_s: 30,
            half_open: 2,
        }
    }
}

/// One lookup provider as an edge runs it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LookupProviderConfig {
    /// The module id (`http_json`, `dns`, …).
    pub module: String,
    /// The module's config; `${secret:name}` references resolve against `EdgeConfig.secrets`.
    pub config: serde_json::Value,
    pub cache_generation: String,
    #[serde(flatten)]
    pub settings: LookupSettings,
}

// ---------------------------------------------------------------------------------------------
// Firewall and UniFi (edge-firewall.md, edge-unifi.md §3)

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FwMode {
    Enforce,
    #[default]
    Monitor,
    Off,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FwInterface {
    pub name: String,
    pub mode: FwMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FirewallConfig {
    pub interfaces: Vec<FwInterface>,
    pub static_allow: Vec<String>,
    pub exempt_sources: Vec<String>,
    pub ack_wait_ms: u32,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            interfaces: vec![],
            static_allow: vec![],
            exempt_sources: vec![],
            ack_wait_ms: 20,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UnifiConfig {
    pub redirect: Option<Redirect>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Redirect {
    pub interfaces: Vec<String>,
    pub ipv6: bool,
}

impl Default for Redirect {
    fn default() -> Self {
        Self {
            interfaces: vec![],
            ipv6: true,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Logging, limits, memory

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LoggingConfig {
    pub spool_after_s: u32,
    pub spool_max_mib: u64,
    /// `None`: no cap beyond the SSD's free-space floor.
    pub ssd_spool_max_mib: Option<u64>,
    pub retention_h: u32,
    pub batch_max: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            spool_after_s: 5,
            spool_max_mib: 256,
            ssd_spool_max_mib: None,
            retention_h: 72,
            batch_max: 1000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Limits {
    pub client_qps: u32,
    pub client_inflight: u32,
    /// The most records one RRset (name, type, class) the edge keeps from an upstream answer may
    /// hold; an answer over it is refused (`rrset_too_large`, SERVFAIL to the client). 0 = no
    /// limit beyond picket-wire's 1,024 records per section. Default 256, above BIND's 100,
    /// which real domains pass.
    pub max_rrset_records: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            client_qps: 100,
            client_inflight: 64,
            max_rrset_records: 256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MemoryConfig {
    pub bundle_budget_mib: u32,
    pub overlay_budget_mib: u32,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            bundle_budget_mib: 384,
            overlay_budget_mib: 4,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Release and requests (api.md §4, edge.md §14)

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ReleaseOffer {
    pub auto_update: bool,
    pub version: String,
    /// BLAKE3 of the tarball for this edge's architecture.
    pub blake3: String,
    /// True when the offer is older than the installed release (a core rollback).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rollback: bool,
    pub install_now: Option<InstallNow>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct InstallNow {
    pub id: String,
    pub version: String,
    pub blake3: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Flush {
    /// Request id: flush the DNS cache.
    pub dns: Option<String>,
    /// Provider id → request id: flush that provider's RAM tier.
    pub lookups: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RevokedAllows {
    pub id: String,
    pub allows: Vec<String>,
}

#[cfg(test)]
mod tests {
    /// edge.md §6, providers.md §5: one DoH path rule, the same reading in `url` and `http`.
    #[test]
    fn doh_paths() {
        for ok in [
            "/dns-query",
            "/",
            "/a//b",
            "/resolve/v1:x@y/!$&'()*+,;=~_-.z",
            "/%2F%7e",
            "/a/...b/.c/d..",
        ] {
            assert!(super::is_doh_path(ok), "{ok}");
            // `url` and `http` keep it as written.
            let u = url::Url::parse(&format!("https://dns.example{ok}")).unwrap();
            assert_eq!(u.path(), ok, "url: {ok}");
            let h: http::Uri = format!("https://dns.example{ok}").parse().unwrap();
            assert_eq!(h.path(), ok, "http: {ok}");
        }
        let long = format!("/{}", "a".repeat(super::MAX_DOH_PATH));
        for bad in [
            "",
            "dns-query",
            "/dns-query#x",
            "/dns-query?dns=x",
            "/dns query",
            "/a\\b",
            "/a/../dns-query",
            "/a/./b",
            "/.",
            "/..",
            "/a/%2e%2E/b",
            "/a/.%2e",
            "/%2e",
            "/caf\u{e9}",
            "/%zz",
            "/%2",
            "/a\"b",
            "/{x}",
            long.as_str(),
        ] {
            assert!(!super::is_doh_path(bad), "{bad:?}");
        }
    }

    use super::*;

    #[test]
    fn example_parses_with_defaults() {
        let doc = r#"{
          "edge": {"id": "e-01", "name": "ucg-fiber", "platform": "unifi"},
          "listeners": [
            {"id": "lan-dns", "proto": "dns", "bind": "[::]:5335", "interfaces": ["br0"]},
            {"id": "lan-doh", "proto": "doh", "bind": "192.168.1.1:9853", "tls": {"managed": "dns.home.arpa"}, "api": true}
          ],
          "default_profile": "kids",
          "clients": [{"name": "office-pc", "macs": ["aa:bb:cc:dd:ee:01"], "profile": "adults", "tags": ["pc"]}],
          "profiles": {"adults": {"allow": ["allow-common"], "block": ["block-common"],
              "lookup_providers": [{"provider": "am-rt", "mode": "sync", "exclude_bundles": ["my-domains"]}],
              "bypass": {"mode": "self", "max_duration": "24h", "ips": true}}},
          "upstreams": {"cf-dot": {"protocol": "dot", "ip": "1.1.1.1", "port": 853, "tls_host": "one.one.one.one", "trust_store": null}},
          "upstream_groups": {"cloudflare": {"upstreams": ["cf-dot"], "strategy": "fastest", "optimistic": true}},
          "lookup_providers": {"am-rt": {"module": "http_json", "config": {"url": "https://x/{domain}"},
              "cache_generation": "3f9a0c17d2e84b65", "sync_timeout_ms": 150, "fail_mode": "open"}},
          "release": {"auto_update": true, "version": "1.4.0", "blake3": "ab", "install_now": null},
          "flush": {"dns": "e2a6b0c94f1d7358", "lookups": {"am-rt": "07b3d9e15a4c62f8"}},
          "revoked_allows": {"id": "9c41e7a02b5d83f6", "allows": ["a-19"]},
          "unknown_future_field": 1
        }"#;
        let c: EdgeConfig = serde_json::from_str(doc).unwrap();
        let p = &c.profiles["adults"];
        assert_eq!(p.allowed_sources, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(p.lookup_providers.len(), 1);
        assert_eq!(p.lookup_providers[0].provider, "am-rt");
        assert_eq!(p.sync_lookup_budget_ms, 150);
        assert_eq!(p.block_response.ttl, 10);
        assert_eq!(p.bypass.mode, BypassMode::SelfService);
        assert_eq!(p.bypass.max_active, 50);
        assert_eq!(c.listeners[0].limits.udp_payload, 1232);
        let lp = &c.lookup_providers["am-rt"];
        assert_eq!(lp.module, "http_json");
        assert_eq!(lp.settings.async_timeout_ms, 10_000);
        assert_eq!(
            lp.settings.scope.exclude_bundles,
            vec!["lookup-exclude", "allow-common"]
        );
        assert!(!c.needs_helper());
        let back = serde_json::to_string(&c).unwrap();
        let again: EdgeConfig = serde_json::from_str(&back).unwrap();
        assert_eq!(c, again);
    }
}
