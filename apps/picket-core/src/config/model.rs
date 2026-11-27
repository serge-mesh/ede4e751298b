//! The configuration model (core.md §2): every entity core stores in `core.db` and the UI API
//! edits. Field descriptions double as UI tooltips (they reach the OpenAPI document through
//! `schemars`).
//!
//! Shapes follow the edge's types where the edge consumes them (`picket_api::edge_config`), plus
//! the core-only fields: a profile's `trial_bundles`, `alert_categories`, `alert_lookup_providers`,
//! `browser_list`; an upstream's `operator`; a lookup provider's `category`, `cache_generation`,
//! `preset`; an edge's budgets.

use std::collections::BTreeMap;
use std::net::IpAddr;

use picket_api::DurationStr;
use picket_api::edge_config::{
    CacheSettings, FirewallConfig, GroupStrategy, Limits, ListenerLimits, ListenerProto, ListenerTls,
    LoggingConfig, LookupSettings, Platform, Profile, UnifiConfig, UpstreamProtocol, ZoneFallback,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::settings::Settings;

/// The whole configuration, loaded at once for validation and rendering.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Model {
    pub settings: Settings,
    pub edges: BTreeMap<String, EdgeDef>,
    pub listeners: BTreeMap<String, ListenerDef>,
    /// In `position` order (edge.md §5: ties go to the first listed).
    pub clients: Vec<ClientDef>,
    pub profiles: BTreeMap<String, ProfileDef>,
    pub upstreams: BTreeMap<String, UpstreamDef>,
    pub upstream_groups: BTreeMap<String, UpstreamGroupDef>,
    pub forward_zones: BTreeMap<String, ForwardZoneDef>,
    pub feed_providers: BTreeMap<String, FeedProviderDef>,
    pub feeds: BTreeMap<String, FeedDef>,
    pub bundles: BTreeMap<String, BundleDef>,
    pub lookup_providers: BTreeMap<String, LookupProviderDef>,
    /// Secret names and whether each has a value; values never live in the model.
    pub secrets: BTreeMap<String, SecretMeta>,
}

// ---------------------------------------------------------------------------------------------
// Edges (core.md §4)

/// A registered edge and its per-edge settings.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EdgeDef {
    /// Stable id (`[a-z0-9-]`); generated when left out.
    pub id: String,
    pub name: String,
    /// The edge's key fingerprint, `SHA256:…` (from `picket-edge key`).
    pub key: String,
    /// Sets presets: `unifi` (UCG-Fiber) or `debian`.
    pub platform: Platform,
    #[serde(flatten)]
    pub settings: EdgeSettings,
    /// When the edge was added (read-only).
    pub created_at: Option<String>,
}

/// Per-edge settings rendered into its `EdgeConfig` (core.md §4, api.md §4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EdgeSettings {
    /// Install the offered release automatically (core.md §5).
    pub auto_update: bool,
    /// Per-edge total of in-memory bundle data in MiB (edge.md §17).
    pub bundle_budget_mib: u32,
    /// Per-edge total of bundle and verdict-set overlays in MiB; null = the platform's default
    /// (16 on UniFi, 4 on Debian).
    pub overlay_budget_mib: Option<u32>,
    /// The UI warns when the edge's sync lookup providers' `max_mib` total passes this.
    pub verdict_budget_mib: u32,
    /// Firewall interfaces and modes, `static_allow`, `exempt_sources`.
    pub firewall: FirewallConfig,
    /// UniFi options (the port-53 redirect check).
    pub unifi: UnifiConfig,
    pub cache: CacheSettings,
    /// Spool and batch settings; `retention_h` always follows core's `retention.query_logs`.
    pub logging: LoggingConfig,
    pub limits: Limits,
}

impl Default for EdgeSettings {
    fn default() -> Self {
        Self {
            auto_update: true,
            bundle_budget_mib: 384,
            overlay_budget_mib: None,
            verdict_budget_mib: 16,
            firewall: FirewallConfig::default(),
            unifi: UnifiConfig::default(),
            cache: CacheSettings::default(),
            logging: LoggingConfig::default(),
            limits: Limits::default(),
        }
    }
}

impl EdgeSettings {
    /// The effective overlay budget: 16 MiB on UniFi, 4 MiB elsewhere unless set (edge.md §17).
    pub fn overlay_budget(&self, platform: Platform) -> u32 {
        self.overlay_budget_mib.unwrap_or(match platform {
            Platform::Unifi => 16,
            Platform::Debian => 4,
        })
    }
}

/// An unknown key that tried to connect (core.md §4: Edges → Pending).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PendingEdge {
    /// `SHA256:…`
    pub key: String,
    /// The key in path form (the hash as unpadded base64url), for `edges/pending/{fp}`.
    pub key_path: String,
    pub addr: Option<String>,
    /// The CN of the key's certificate (`picket-edge setup --name`).
    pub claimed_name: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

// ---------------------------------------------------------------------------------------------
// Listeners (edge.md §5)

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListenerDef {
    pub id: String,
    pub name: String,
    /// `dns` (UDP and TCP), `dot` or `doh`.
    pub proto: ListenerProto,
    /// `ip:port`, e.g. `[::]:5335` or `192.168.1.1:853`.
    pub bind: String,
    /// Interfaces whose traffic it accepts; empty = all.
    pub interfaces: Vec<String>,
    /// `{"managed": "dns.home.arpa"}` (a LAN-CA certificate) or `{"cert_file", "key_file"}`.
    pub tls: Option<ListenerTls>,
    /// Also serve the bypass API (DoH listeners).
    pub api: bool,
    /// Addresses clients reach it at; filled from a specific bind when empty.
    pub ips: Vec<IpAddr>,
    pub limits: ListenerLimits,
    /// The edges it is assigned to.
    pub edges: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Clients and profiles (edge.md §5, core.md §2)

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ClientDef {
    /// Unique; `$client` rules match it.
    pub name: String,
    /// Order in the clients list (lower first); new clients go last when left out.
    pub position: Option<u32>,
    /// `aa:bb:cc:dd:ee:ff`; every address an edge sees for them.
    pub macs: Vec<String>,
    /// Address ranges (CIDR or a bare address).
    pub source_ips: Vec<String>,
    /// Null: the client only names its devices.
    pub profile: Option<String>,
    /// `$ctag` rules match these.
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BrowserList {
    /// Publish this profile's pruned and full browser lists (bundles.md §8).
    pub enabled: bool,
}

/// A profile: the edge's fields plus core-only ones.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ProfileDef {
    /// A DNS label that never changes; it appears in DoH URLs and DoT names.
    pub id: String,
    pub name: String,
    /// System profiles can be edited but not deleted (read-only).
    pub system: bool,
    #[serde(flatten)]
    pub edge: Profile,
    /// Block bundles on trial: compiled, never sent to an edge for this profile, checked
    /// against logged queries on core.
    pub trial_bundles: Vec<String>,
    /// Feed categories whose blocks alert (`security`, `privacy`, `mixed`); `[]` turns them off.
    pub alert_categories: Vec<String>,
    /// Lookup provider ids whose Blocks alert; null = every lookup provider whose category is
    /// `security`; `[]` turns them off.
    pub alert_lookup_providers: Option<Vec<String>>,
    pub browser_list: BrowserList,
}

impl Default for ProfileDef {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            system: false,
            edge: Profile::default(),
            trial_bundles: vec![],
            alert_categories: vec!["security".into()],
            alert_lookup_providers: None,
            browser_list: BrowserList::default(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Upstreams and forward zones (edge.md §6)

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UpstreamDef {
    pub id: String,
    pub name: String,
    pub protocol: UpstreamProtocol,
    /// By IP; never resolved (hard rule 9).
    pub ip: IpAddr,
    pub port: u16,
    /// The TLS name for DoT and DoH.
    pub tls_host: Option<String>,
    /// The DoH path, default `/dns-query`.
    pub path: Option<String>,
    /// PEM text; null = the Mozilla roots.
    pub trust_store: Option<String>,
    /// Who runs the service (`cloudflare`, `quad9`, …); required for DoT and DoH. Core-only:
    /// keeps the cross-check resolver independent (core.md §8).
    pub operator: Option<String>,
}

impl Default for UpstreamDef {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            protocol: UpstreamProtocol::Dot,
            ip: IpAddr::from([0, 0, 0, 0]),
            port: 853,
            tls_host: None,
            path: None,
            trust_store: None,
            operator: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UpstreamGroupDef {
    pub id: String,
    pub name: String,
    /// Upstream ids, all plain (`udp`, `tcp`) or all encrypted (DoT, DoH).
    pub upstreams: Vec<String>,
    pub strategy: GroupStrategy,
    pub optimistic: bool,
}

impl Default for UpstreamGroupDef {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            upstreams: vec![],
            strategy: GroupStrategy::Fastest,
            optimistic: true,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ForwardZoneDef {
    pub id: String,
    /// The DNS zone, e.g. `localdomain` or `1.168.192.in-addr.arpa`.
    pub zone: String,
    /// Upstream group id.
    pub group: String,
    /// `none`: SERVFAIL while the group is down; `default`: fall back to the profile's group.
    pub fallback: ZoneFallback,
}

// ---------------------------------------------------------------------------------------------
// Feeds (feeds.md §1)

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Threats.
    Security,
    /// Ads and tracking.
    Privacy,
    /// Both, or not known.
    #[default]
    Mixed,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Privacy => "privacy",
            Self::Mixed => "mixed",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FeedFormat {
    #[default]
    Adblock,
    Hosts,
    Plain,
    MispWarninglist,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DomainsAs {
    /// AdGuard semantics: the name itself.
    Exact,
    /// The name and its subdomains.
    Subdomains,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FormatOptions {
    /// `plain` format only: how its names match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains_as: Option<DomainsAs>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PolicyOption {
    Drop,
    Keep,
}

/// Which rules beyond plain blocks a feed keeps (feeds.md §8). Left-out options take the
/// default: `drop` for `redirects` and `client_rules`, `keep` for `browser_changes`; manual
/// feeds keep all three. A dropped rule is dropped whole, never weakened into another.
///
/// Each field's description is the UI's tooltip for its drop/keep switch (core.md §12): the
/// rules it covers with examples, what `keep` lets the feed do, and the default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RulePolicy {
    /// Redirects: hosts lines that map a name to another IP (`203.0.113.7 example.com`) and
    /// `$dnsrewrite` rules that return records (`||example.com^$dnsrewrite=203.0.113.7`). An
    /// rcode-only `$dnsrewrite` (`NXDOMAIN`, `REFUSED`, an empty `NOERROR`) is a block and
    /// `@@…$dnsrewrite` only cancels; neither counts. `keep` lets the feed answer a name with an
    /// address or record that no upstream sent. Default `drop` (manual feeds: `keep`).
    pub redirects: Option<PolicyOption>,
    /// Client rules: any rule with `$client` or `$ctag` (`||example.com^$client=192.168.1.20`,
    /// `||example.com^$ctag=device_phone`). `keep` lets the feed treat one client differently
    /// from another. Default `drop` (manual feeds: `keep`).
    pub client_rules: Option<PolicyOption>,
    /// Browser changes: `browser` rules that do more than block a request or hide an element:
    /// scriptlets and injections (`example.com##+js(set-constant, x, false)`, `#$#`), action
    /// operators such as `:style()`, modifiers that change a request or response instead of
    /// blocking it (`$redirect`, `$redirect-rule`, `$csp`, `$removeparam`, …) and exceptions
    /// (`@@||example.com^`, `#@#`, `#@?#`, `$badfilter`). `keep` lets the feed run scripts in
    /// pages, change requests and responses, and unblock what other subscribed lists block, in
    /// the browser lists built from it. No effect while the feed's `browser` mode is `drop`.
    /// Default `keep` (browser filter lists rely on scriptlets), for manual feeds too.
    pub browser_changes: Option<PolicyOption>,
}

impl RulePolicy {
    /// Fills left-out options with the defaults for a manual or downloaded feed.
    pub fn resolved(&self, manual: bool) -> RulePolicy {
        let keep = PolicyOption::Keep;
        let drop = PolicyOption::Drop;
        RulePolicy {
            redirects: Some(self.redirects.unwrap_or(if manual { keep } else { drop })),
            client_rules: Some(self.client_rules.unwrap_or(if manual { keep } else { drop })),
            browser_changes: Some(self.browser_changes.unwrap_or(keep)),
        }
    }
}

/// When a feed provider is checked (feed-scheduling.md). One check covers every enabled feed of
/// the provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Trigger {
    /// When a change to one of its feeds is likely, learned from every successful check, never
    /// more often than `min_interval`.
    Dynamic {
        #[serde(default = "two_minutes")]
        min_interval: DurationStr,
    },
    /// A cron expression (UTC) with random jitter, never more often than `min_interval`.
    Cron {
        cron: String,
        #[serde(default)]
        jitter: DurationStr,
        #[serde(default = "two_minutes")]
        min_interval: DurationStr,
    },
    /// When a message arrives on an AWS SQS queue, and at least every `backstop`
    /// (feed-scheduling.md §7). The AWS keys take only `${secret:name}` references.
    Sqs {
        /// `https://sqs.<region>.amazonaws.com/<12-digit account>/<queue name>`.
        queue_url: String,
        /// `${secret:name}`: an access key id allowed `sqs:ReceiveMessage` and
        /// `sqs:DeleteMessage` on that queue only.
        access_key_id: String,
        /// `${secret:name}`.
        secret_access_key: String,
        #[serde(default = "one_hour")]
        backstop: DurationStr,
        #[serde(default = "two_minutes")]
        min_interval: DurationStr,
    },
}

fn two_minutes() -> DurationStr {
    DurationStr::minutes(2)
}

fn one_hour() -> DurationStr {
    DurationStr::hours(1)
}

impl Trigger {
    /// The hard floor between two checks of the provider, whatever starts them
    /// (feed-scheduling.md).
    pub fn min_interval(&self) -> DurationStr {
        match self {
            Self::Dynamic { min_interval }
            | Self::Cron { min_interval, .. }
            | Self::Sqs { min_interval, .. } => *min_interval,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Dynamic { .. } => "dynamic",
            Self::Cron { .. } => "cron",
            Self::Sqs { .. } => "sqs",
        }
    }
}

impl Default for Trigger {
    fn default() -> Self {
        Self::Dynamic {
            min_interval: two_minutes(),
        }
    }
}

/// One entry of a feed provider's `files` (feeds.md §1 "Provider feeds"): a glob for a module
/// that lists files, a path for one that doesn't, and the settings of the feeds it adds.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileSelect {
    /// A glob (`*` within a path segment, `**` across segments) for a module that lists files,
    /// else a path.
    #[serde(rename = "match")]
    pub pattern: String,
    /// Settings of the feeds this entry adds (any feed setting; `format` is required); the
    /// rest take the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed: Option<Value>,
}

/// A feed provider (providers.md §2): a configured instance of a download module, which says
/// where files come from and when to check them. Each file its `files` selects (minus
/// `exclude`) is one feed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FeedProviderDef {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// System providers can be edited but not deleted (read-only).
    pub system: bool,
    /// The download module (`github`, `http`, `alphamountain_threat_1000`).
    pub module: String,
    /// The module's settings: what the provider's files share (its `Config` JSON Schema).
    pub config: Value,
    pub trigger: Trigger,
    /// The files that are its feeds.
    pub files: Vec<FileSelect>,
    /// Globs of files never to make feeds of (a deleted provider feed's file goes here).
    pub exclude: Vec<String>,
}

impl Default for FeedProviderDef {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            system: false,
            module: String::new(),
            config: Value::Object(Default::default()),
            trigger: Trigger::default(),
            files: vec![],
            exclude: vec![],
        }
    }
}

impl FeedProviderDef {
    /// Secret names referenced as `${secret:name}` in the config and the trigger (`github`'s
    /// `token`, an `http` header, an `sqs` trigger's AWS keys; providers.md §2).
    pub fn secret_refs(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect_secret_refs(&self.config, &mut out);
        if let Ok(t) = serde_json::to_value(&self.trigger) {
            collect_secret_refs(&t, &mut out);
        }
        out.sort();
        out.dedup();
        out
    }

    /// The `match` patterns of `files` (the hint `check()` gets).
    pub fn select(&self) -> Vec<String> {
        self.files.iter().map(|f| f.pattern.clone()).collect()
    }

    /// True when `files` holds a glob (the provider keeps listing even without enabled feeds).
    pub fn has_globs(&self) -> bool {
        self.files
            .iter()
            .any(|f| crate::modules::download::glob::is_glob(&f.pattern))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// The download is the complete set.
    #[default]
    Replace,
    /// Downloads add and refresh; missing entries stay (until `expire_after`).
    Aggregate,
    /// Not stored.
    Drop,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ModeSpec {
    pub mode: Mode,
    /// `aggregate` only: close an entry this long after the first applied run without it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_after: Option<DurationStr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Modes {
    pub dns: ModeSpec,
    pub ip: ModeSpec,
    pub browser: ModeSpec,
}

impl Default for Modes {
    fn default() -> Self {
        Self {
            dns: ModeSpec::default(),
            ip: ModeSpec::default(),
            browser: ModeSpec {
                mode: Mode::Drop,
                expire_after: None,
            },
        }
    }
}

/// Sanity gates per feed run (feeds.md §5).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Sanity {
    pub min_entries: Option<u64>,
    pub max_entries: Option<u64>,
    pub max_change_ratio: f64,
    pub min_change_allowance: u64,
    pub confirm_after: DurationStr,
    pub max_parse_error_ratio: f64,
}

impl Default for Sanity {
    fn default() -> Self {
        Self {
            min_entries: None,
            max_entries: None,
            max_change_ratio: 0.20,
            min_change_allowance: 100,
            confirm_after: DurationStr::hours(1),
            max_parse_error_ratio: 0.01,
        }
    }
}

/// A feed definition (feeds.md §1). Core stores and validates it; checking and ingest are the
/// feeds module's.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FeedDef {
    pub id: String,
    pub name: String,
    pub category: Category,
    /// Warn bundles to check this feed's entries against where it blocks; null = `["warn-common"]`
    /// for a `security` feed and `[]` otherwise.
    pub warn_on: Option<Vec<String>>,
    pub enabled: bool,
    /// Its feed provider (providers.md §2), set when the provider adds the feed and never
    /// changed (read-only); null for a manual feed.
    pub provider: Option<String>,
    /// The provider's file it reads, in the module's terms (read-only); null for a manual feed.
    pub file: Option<String>,
    pub format: FeedFormat,
    pub format_options: FormatOptions,
    pub rule_policy: RulePolicy,
    pub modes: Modes,
    pub sanity: Sanity,
    /// System feeds can be edited but not deleted (read-only).
    pub system: bool,
}

impl Default for FeedDef {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            category: Category::Mixed,
            warn_on: None,
            enabled: true,
            provider: None,
            file: None,
            format: FeedFormat::Adblock,
            format_options: FormatOptions::default(),
            rule_policy: RulePolicy::default(),
            modes: Modes::default(),
            sanity: Sanity::default(),
            system: false,
        }
    }
}

impl FeedDef {
    /// A manual feed: no provider, its file stored on core (feeds.md §1 "Manual feeds").
    pub fn is_manual(&self) -> bool {
        self.provider.is_none()
    }

    /// `warn_on` with its category default applied.
    pub fn effective_warn_on(&self) -> Vec<String> {
        match &self.warn_on {
            Some(w) => w.clone(),
            None if self.category == Category::Security => vec!["warn-common".into()],
            None => vec![],
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Bundles (bundles.md §1)

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BundleAction {
    #[default]
    Block,
    Allow,
    /// Names for lookup scopes; never allows or blocks.
    Scope,
    /// Warninglists; core only.
    Warn,
}

impl BundleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
            Self::Scope => "scope",
            Self::Warn => "warn",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    Dns,
    Ip,
    Browser,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    Hot,
    Cold,
    IntelligentTiering,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Cold => "cold",
            Self::IntelligentTiering => "intelligent-tiering",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BundleFeed {
    pub feed: String,
    /// The feed's rule types the bundle takes; null = every type the feed stores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_types: Option<Vec<RuleType>>,
    /// Block bundles only: `hot` (default), `cold` or `intelligent-tiering`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BundleDef {
    pub id: String,
    pub name: String,
    pub action: BundleAction,
    pub feeds: Vec<BundleFeed>,
    /// Keys per shard; 0 = one shard.
    pub max_shard_keys: u64,
    /// Block bundles only: the hot part's cap for `intelligent-tiering` feeds; null = no cap.
    pub hot_max_mib: Option<u32>,
    /// System bundles can be edited but not deleted (read-only).
    pub system: bool,
}

impl Default for BundleDef {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            action: BundleAction::Block,
            feeds: vec![],
            max_shard_keys: 1_000_000,
            hot_max_mib: None,
            system: false,
        }
    }
}

impl BundleDef {
    /// A block bundle that can have a cold part: a feed with `tier: cold`, or
    /// `intelligent-tiering` with `hot_max_mib` set. Lookup scopes refuse these (edge.md §10).
    pub fn cold_capable(&self) -> bool {
        self.action == BundleAction::Block
            && self.feeds.iter().any(|f| match f.tier {
                Some(Tier::Cold) => true,
                Some(Tier::IntelligentTiering) => self.hot_max_mib.is_some(),
                _ => false,
            })
    }
}

// ---------------------------------------------------------------------------------------------
// Lookup providers (providers.md §4)

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LookupProviderDef {
    pub id: String,
    pub name: String,
    /// The lookup module id (`http_json`, `dns`, …).
    pub module: String,
    /// The module's config; `${secret:name}` references resolve against secrets.
    pub config: Value,
    #[serde(flatten)]
    pub settings: LookupSettings,
    /// As for feeds; default `security`.
    pub category: Category,
    /// The verdict cache generation, a random 64-bit id (read-only; moves on with a flush or a
    /// save with **Clear cached verdicts on save**).
    pub cache_generation: String,
    /// The preset id and parameters the config was built from, if any.
    pub preset: Option<Value>,
    /// The last self-test's time, result and detail (read-only).
    pub last_self_test: Option<Value>,
}

impl Default for LookupProviderDef {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            module: String::new(),
            config: Value::Object(Default::default()),
            settings: LookupSettings::default(),
            category: Category::Security,
            cache_generation: String::new(),
            preset: None,
            last_self_test: None,
        }
    }
}

impl LookupProviderDef {
    /// Secret names referenced as `${secret:name}` anywhere in the config.
    pub fn secret_refs(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect_secret_refs(&self.config, &mut out);
        out.sort();
        out.dedup();
        out
    }
}

fn collect_secret_refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            let mut rest = s.as_str();
            while let Some(i) = rest.find("${secret:") {
                let after = &rest[i + 9..];
                match after.find('}') {
                    Some(j) => {
                        out.push(after[..j].to_string());
                        rest = &after[j + 1..];
                    }
                    None => break,
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_secret_refs(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect_secret_refs(x, out)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------
// Secrets (security.md §4)

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretMeta {
    pub name: String,
    /// The value itself is write-only and never returned.
    pub has_value: bool,
}

// ---------------------------------------------------------------------------------------------
// Entity kinds

/// The kinds of entity the UI API edits generically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Edge,
    Listener,
    Client,
    Profile,
    Upstream,
    UpstreamGroup,
    ForwardZone,
    FeedProvider,
    Feed,
    Bundle,
    LookupProvider,
    Secret,
    Settings,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::Listener => "listener",
            Self::Client => "client",
            Self::Profile => "profile",
            Self::Upstream => "upstream",
            Self::UpstreamGroup => "upstream_group",
            Self::ForwardZone => "forward_zone",
            Self::FeedProvider => "feed_provider",
            Self::Feed => "feed",
            Self::Bundle => "bundle",
            Self::LookupProvider => "lookup_provider",
            Self::Secret => "secret",
            Self::Settings => "settings",
        }
    }
}

impl Model {
    /// How many entities of `kind` the model holds.
    pub fn count(&self, kind: EntityKind) -> usize {
        match kind {
            EntityKind::Edge => self.edges.len(),
            EntityKind::Listener => self.listeners.len(),
            EntityKind::Client => self.clients.len(),
            EntityKind::Profile => self.profiles.len(),
            EntityKind::Upstream => self.upstreams.len(),
            EntityKind::UpstreamGroup => self.upstream_groups.len(),
            EntityKind::ForwardZone => self.forward_zones.len(),
            EntityKind::FeedProvider => self.feed_providers.len(),
            EntityKind::Feed => self.feeds.len(),
            EntityKind::Bundle => self.bundles.len(),
            EntityKind::LookupProvider => self.lookup_providers.len(),
            EntityKind::Secret => self.secrets.len(),
            EntityKind::Settings => 1,
        }
    }

    /// The serialised form of one entity, for change diffs.
    pub fn entity_value(&self, kind: EntityKind, id: &str) -> Option<Value> {
        let v = match kind {
            EntityKind::Edge => serde_json::to_value(self.edges.get(id)?),
            EntityKind::Listener => serde_json::to_value(self.listeners.get(id)?),
            EntityKind::Client => serde_json::to_value(self.clients.iter().find(|c| c.name == id)?),
            EntityKind::Profile => serde_json::to_value(self.profiles.get(id)?),
            EntityKind::Upstream => serde_json::to_value(self.upstreams.get(id)?),
            EntityKind::UpstreamGroup => serde_json::to_value(self.upstream_groups.get(id)?),
            EntityKind::ForwardZone => serde_json::to_value(self.forward_zones.get(id)?),
            EntityKind::FeedProvider => serde_json::to_value(self.feed_providers.get(id)?),
            EntityKind::Feed => serde_json::to_value(self.feeds.get(id)?),
            EntityKind::Bundle => serde_json::to_value(self.bundles.get(id)?),
            EntityKind::LookupProvider => serde_json::to_value(self.lookup_providers.get(id)?),
            EntityKind::Secret => serde_json::to_value(self.secrets.get(id)?),
            EntityKind::Settings => Ok(serde_json::to_value(crate::settings::flat(&self.settings)).ok()?),
        };
        v.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_flattens_edge_fields() {
        let p: ProfileDef = serde_json::from_str(
            r#"{"id": "kids", "name": "Kids", "block": ["block-common"], "trial_bundles": ["adult"], "upstream": "cloudflare"}"#,
        )
        .unwrap();
        assert_eq!(p.edge.block, vec!["block-common"]);
        assert_eq!(p.trial_bundles, vec!["adult"]);
        assert_eq!(p.alert_categories, vec!["security"]);
        assert_eq!(p.edge.allowed_sources, vec!["0.0.0.0/0", "::/0"]);
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["block"][0], "block-common");
        assert!(v.get("edge").is_none());
    }

    #[test]
    fn rule_policy_defaults() {
        let r = RulePolicy::default().resolved(false);
        assert_eq!(r.redirects, Some(PolicyOption::Drop));
        assert_eq!(r.browser_changes, Some(PolicyOption::Keep));
        let m = RulePolicy::default().resolved(true);
        assert_eq!(m.client_rules, Some(PolicyOption::Keep));
    }

    #[test]
    fn secret_refs() {
        let lp = LookupProviderDef {
            config: serde_json::json!({"headers": {"Authorization": "Bearer ${secret:am_rt}"}, "x": ["${secret:b}${secret:a}"]}),
            ..Default::default()
        };
        assert_eq!(lp.secret_refs(), vec!["a", "am_rt", "b"]);
    }

    #[test]
    fn feed_and_provider_defaults() {
        let f: FeedDef = serde_json::from_str(
            r#"{"id": "x-a", "name": "X", "provider": "x", "file": "a.txt", "category": "security"}"#,
        )
        .unwrap();
        assert_eq!(f.effective_warn_on(), vec!["warn-common"]);
        assert_eq!(f.modes.browser.mode, Mode::Drop);
        assert!(!f.is_manual());
        let m: FeedDef = serde_json::from_str(r#"{"id": "m", "name": "M"}"#).unwrap();
        assert!(m.is_manual() && m.file.is_none());
        let p: FeedProviderDef = serde_json::from_str(
            r#"{"id": "hagezi", "module": "github", "config": {"owner": "hagezi", "repo": "dns-blocklists"},
                "files": [{"match": "adblock/*.txt", "feed": {"format": "adblock"}}], "exclude": ["adblock/*-onlydomains.txt"]}"#,
        )
        .unwrap();
        assert_eq!(p.trigger, Trigger::default());
        assert_eq!(p.trigger.min_interval().as_secs(), 120);
        assert!(p.enabled && p.has_globs());
        assert_eq!(p.select(), vec!["adblock/*.txt"]);
        let s: Trigger =
            serde_json::from_str(r#"{"kind": "cron", "cron": "17 */6 * * *", "jitter": "5m"}"#).unwrap();
        assert!(matches!(s, Trigger::Cron { .. }));
        let q: Trigger = serde_json::from_str(
            r#"{"kind": "sqs", "queue_url": "https://sqs.eu-west-1.amazonaws.com/123456789012/lists",
                "access_key_id": "${secret:aws_id}", "secret_access_key": "${secret:aws_key}"}"#,
        )
        .unwrap();
        match &q {
            Trigger::Sqs {
                backstop,
                min_interval,
                ..
            } => {
                assert_eq!((backstop.as_secs(), min_interval.as_secs()), (3600, 120));
            }
            _ => panic!(),
        }
        let p = FeedProviderDef {
            trigger: q,
            config: serde_json::json!({"token": "${secret:gh}"}),
            ..Default::default()
        };
        assert_eq!(p.secret_refs(), vec!["aws_id", "aws_key", "gh"]);
    }

    #[test]
    fn cold_capable() {
        let mut b = BundleDef {
            feeds: vec![BundleFeed {
                feed: "f".into(),
                rule_types: None,
                tier: Some(Tier::IntelligentTiering),
            }],
            ..Default::default()
        };
        assert!(!b.cold_capable());
        b.hot_max_mib = Some(64);
        assert!(b.cold_capable());
        b.action = BundleAction::Allow;
        assert!(!b.cold_capable());
    }
}
