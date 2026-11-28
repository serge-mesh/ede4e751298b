//! Validation of the whole configuration (core.md §2 and the sections it links).
//!
//! Every save validates the *whole* model with the change applied, so rules that relate two
//! entities hold in either save order ("whichever change comes second"), and one bad reference
//! rejects the save. A save is refused when it introduces an error the model didn't have before
//! (`config::store`), so a problem left by an older release never blocks unrelated saves; the UI
//! lists current problems from [`validate`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use picket_api::edge_config::{BlockResponseType, ListenerProto, LookupMode, Platform, UpstreamProtocol};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::model::*;
use super::system;
use crate::lanca::{is_dns_name, is_ldh_label, name_under_zones};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[schemars(rename = "IssueSeverity")]
pub enum Severity {
    Error,
    Warning,
}

/// One problem found in the configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct Issue {
    pub severity: Severity,
    /// The entity kind (`profile`, `listener`, `settings`, …).
    pub entity: String,
    /// The entity's id (a setting's key for `settings`).
    pub id: String,
    /// The field, when one is at fault.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// A stable code for the rule.
    pub code: String,
    pub message: String,
}

impl Issue {
    /// The identity used to tell a new problem from an existing one.
    pub fn key(&self) -> (Severity, &str, &str, Option<&str>, &str, &str) {
        (
            self.severity,
            &self.entity,
            &self.id,
            self.field.as_deref(),
            &self.code,
            &self.message,
        )
    }
}

struct Out(Vec<Issue>);

impl Out {
    fn err(&mut self, entity: &str, id: &str, field: Option<&str>, code: &str, message: String) {
        self.push(Severity::Error, entity, id, field, code, message);
    }
    fn warn(&mut self, entity: &str, id: &str, field: Option<&str>, code: &str, message: String) {
        self.push(Severity::Warning, entity, id, field, code, message);
    }
    fn push(
        &mut self,
        severity: Severity,
        entity: &str,
        id: &str,
        field: Option<&str>,
        code: &str,
        message: String,
    ) {
        self.0.push(Issue {
            severity,
            entity: entity.into(),
            id: id.into(),
            field: field.map(str::to_string),
            code: code.into(),
            message,
        });
    }
}

/// Bounds on collections (README §2: everything is bounded).
pub const MAX_ENTITIES: usize = 10_000;
pub const MAX_LIST: usize = 4096;
pub const MAX_NAME: usize = 128;

/// Entities per kind (README §2, Bounded). Every save loads, validates and clones the whole
/// model, and an edge's config carries every profile and client and what they reference, so
/// each kind has a cap; a create past it is refused. The spec leaves the numbers open; these
/// are far above what one household's Picket needs.
pub fn max_entities(kind: EntityKind) -> usize {
    match kind {
        EntityKind::Edge | EntityKind::Client => MAX_ENTITIES,
        EntityKind::Listener | EntityKind::Profile | EntityKind::UpstreamGroup => 256,
        EntityKind::Upstream | EntityKind::Bundle | EntityKind::Secret => 512,
        EntityKind::ForwardZone | EntityKind::Feed => 1024,
        // 256 an older release allowed, plus one per feed (1,024): upgrading its `http`
        // providers to one provider per feed's URL (`store::upgrade_previous`) always fits.
        EntityKind::FeedProvider => 1280,
        EntityKind::LookupProvider => 64,
        EntityKind::Settings => 1,
    }
}

/// The issue a model with too many entities of `kind` has.
pub fn too_many(kind: EntityKind) -> Issue {
    Issue {
        severity: Severity::Error,
        entity: kind.as_str().into(),
        id: String::new(),
        field: None,
        code: "too_many".into(),
        message: format!(
            "too many entities of kind {} (at most {})",
            kind.as_str(),
            max_entities(kind)
        ),
    }
}

const ALL_KINDS: &[EntityKind] = &[
    EntityKind::Edge,
    EntityKind::Listener,
    EntityKind::Client,
    EntityKind::Profile,
    EntityKind::Upstream,
    EntityKind::UpstreamGroup,
    EntityKind::ForwardZone,
    EntityKind::FeedProvider,
    EntityKind::Feed,
    EntityKind::Bundle,
    EntityKind::LookupProvider,
    EntityKind::Secret,
];

fn count_rules(m: &Model, o: &mut Out) {
    for k in ALL_KINDS {
        if m.count(*k) > max_entities(*k) {
            o.0.push(too_many(*k));
        }
    }
}

/// The largest configuration (settings, entities and secret names, as JSON) a save leaves: three
/// quarters of the cap the config restore reads the export's configuration part with
/// ([`crate::config::export::stream::CONFIGURATION_CAP`]), the rest room for what the export
/// writes differently (stored settings rows, masked credentials), so every configuration this
/// accepts exports and restores (core.md §2; README §2 Bounded).
pub const MAX_CONFIG_BYTES: u64 = crate::config::export::stream::CONFIGURATION_CAP / 4 * 3;

/// A configuration past [`MAX_CONFIG_BYTES`].
fn size_rules(m: &Model, o: &mut Out) {
    /// Counts what is written.
    struct Count(u64);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len() as u64;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut n = Count(0);
    let parts: [&dyn erased::Json; 13] = [
        &m.settings,
        &m.edges,
        &m.listeners,
        &m.clients,
        &m.profiles,
        &m.upstreams,
        &m.upstream_groups,
        &m.forward_zones,
        &m.feed_providers,
        &m.feeds,
        &m.bundles,
        &m.lookup_providers,
        &m.secrets,
    ];
    for p in parts {
        p.write_to(&mut n);
        if n.0 > MAX_CONFIG_BYTES {
            o.err(
                "settings",
                "",
                None,
                "too_large",
                format!(
                    "the configuration is larger than {} MiB as JSON, the most an export can hold for a restore: remove clients, tags or other entities",
                    MAX_CONFIG_BYTES / (1024 * 1024)
                ),
            );
            return;
        }
    }
}

/// Serialising parts of different types through one list.
mod erased {
    pub trait Json {
        fn write_to(&self, w: &mut dyn std::io::Write);
    }
    impl<T: serde::Serialize> Json for T {
        fn write_to(&self, w: &mut dyn std::io::Write) {
            let _ = serde_json::to_writer(w, self);
        }
    }
}

/// A provider config holding a credential in clear instead of a `${secret:name}` reference
/// (README §2 Secrets; security.md §4).
fn literal_credential_rule(o: &mut Out, entity: &str, id: &str, field: &str, cfg: &serde_json::Value) {
    if let Some(path) = super::credentials::find_literal(cfg) {
        o.err(
            entity,
            id,
            Some(field),
            "literal_credential",
            format!(
                "{field}.{path} may hold a credential in clear; store it as a secret and write ${{secret:name}} there (a header map takes literal values only for {})",
                super::credentials::LITERAL_HEADERS.join(", ")
            ),
        );
    }
}

/// The `literal_credential` errors of one feed or lookup provider. A save of that entity is
/// refused while it has any, even if an older release stored them (README §2 Secrets): a save
/// can't keep a credential in clear or swap it for another.
pub fn credential_issues(m: &Model, kind: EntityKind, id: &str) -> Vec<Issue> {
    let mut o = Out(Vec::new());
    match kind {
        EntityKind::FeedProvider => {
            if let Some(p) = m.feed_providers.get(id) {
                literal_credential_rule(&mut o, "feed_provider", id, "config", &p.config);
            }
        }
        EntityKind::LookupProvider => {
            if let Some(p) = m.lookup_providers.get(id) {
                provider_credential_rules(&mut o, id, p);
            }
        }
        _ => {}
    }
    o.0
}

/// A lookup provider's config and its preset's parameters (they build the config).
fn provider_credential_rules(o: &mut Out, id: &str, p: &super::model::LookupProviderDef) {
    literal_credential_rule(o, "lookup_provider", id, "config", &p.config);
    if let Some(preset) = &p.preset {
        literal_credential_rule(o, "lookup_provider", id, "preset", preset);
    }
}

/// Validates the whole model. Errors and warnings, sorted.
pub fn validate(m: &Model) -> Vec<Issue> {
    let mut o = Out(Vec::new());
    count_rules(m, &mut o);
    size_rules(m, &mut o);
    settings_rules(m, &mut o);
    edge_rules(m, &mut o);
    listener_rules(m, &mut o);
    client_rules(m, &mut o);
    profile_rules(m, &mut o);
    upstream_rules(m, &mut o);
    group_rules(m, &mut o);
    zone_rules(m, &mut o);
    feed_provider_rules(m, &mut o);
    feed_rules(m, &mut o);
    bundle_rules(m, &mut o);
    provider_rules(m, &mut o);
    secret_rules(m, &mut o);
    trial_scope_rules(m, &mut o);
    let mut v = o.0;
    v.sort();
    v.dedup();
    v
}

/// The errors of `after` that `before` didn't have: the ones a save introduces.
pub fn new_errors(before: &[Issue], after: &[Issue]) -> Vec<Issue> {
    let old: HashSet<_> = before
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(Issue::key)
        .collect();
    after
        .iter()
        .filter(|i| i.severity == Severity::Error && !old.contains(&i.key()))
        .cloned()
        .collect()
}

/// An id usable in URLs and object keys: 1–64 of `a-z0-9-_`, starting with a letter or digit.
pub fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// A display name: 1–128 characters without control characters.
pub fn is_display_name(s: &str) -> bool {
    !s.trim().is_empty() && s.chars().count() <= MAX_NAME && !s.chars().any(char::is_control)
}

/// A profile id: a DNS label (lowercase letters, digits, hyphens) not ending in `-full`
/// (core.md §2).
pub fn is_profile_id(s: &str) -> bool {
    is_ldh_label(s) && !s.ends_with("-full")
}

/// A zone name: labels of `a-z0-9-_` (forward zones may hold service labels).
fn is_zone_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// An interface name as Linux accepts it: 1–15 bytes, no `/`, whitespace or `:`.
fn is_ifname(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && s.bytes().all(|b| b.is_ascii_graphic() && b != b'/' && b != b':')
}

/// True when `pem` holds one or more PEM certificates and nothing unparseable (a trust store,
/// ≤ 64 KiB).
pub fn pem_has_certificate(pem: &str) -> bool {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    if pem.len() > 64 * 1024 {
        return false;
    }
    let mut any = false;
    for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        match c {
            Ok(der) if x509_parser::parse_x509_certificate(der.as_ref()).is_ok() => any = true,
            _ => return false,
        }
    }
    any
}

/// A client name must not read as an address range or a MAC: `allowed_sources` mixes all three
/// (core.md §2). It also has no leading or trailing whitespace.
pub fn client_name_problem(name: &str) -> Option<&'static str> {
    if name.trim() != name {
        return Some("a client name can't start or end with whitespace");
    }
    if crate::net::parse_net(name).is_some() || crate::net::normalize_mac(name).is_some() {
        return Some(
            "a client name can't look like an address, a range or a MAC (allowed_sources would read it as one)",
        );
    }
    None
}

/// An operator name: 1–64 of letters, digits, `.`, `_` and `-` (`cloudflare`, `quad9`, …).
pub fn is_operator(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn check_id(o: &mut Out, entity: &str, id: &str) {
    if !is_slug(id) {
        o.err(
            entity,
            id,
            Some("id"),
            "bad_id",
            format!("{id:?} is not a valid id (1–64 of a-z, 0-9, - and _)"),
        );
    }
}

fn check_name(o: &mut Out, entity: &str, id: &str, name: &str) {
    if !is_display_name(name) {
        o.err(
            entity,
            id,
            Some("name"),
            "bad_name",
            "the name must be 1–128 characters without control characters".into(),
        );
    }
}

fn check_len<T>(o: &mut Out, entity: &str, id: &str, field: &str, list: &[T]) {
    if list.len() > MAX_LIST {
        o.err(
            entity,
            id,
            Some(field),
            "too_many",
            format!("{field} holds more than {MAX_LIST} items"),
        );
    }
}

fn check_cidrs(o: &mut Out, entity: &str, id: &str, field: &str, list: &[String]) {
    check_len(o, entity, id, field, list);
    for c in list {
        if crate::net::parse_net(c).is_none() {
            o.err(
                entity,
                id,
                Some(field),
                "bad_cidr",
                format!("{c:?} is not an address range"),
            );
        }
    }
}

fn dupes<'a>(items: impl IntoIterator<Item = &'a String>) -> Vec<&'a String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for i in items {
        if !seen.insert(i) {
            out.push(i);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------

fn settings_rules(m: &Model, o: &mut Out) {
    for (key, msg) in crate::settings::validate(&m.settings) {
        o.err("settings", &key, None, "bad_setting", msg);
    }
    let s = &m.settings;
    if let Some(p) = &s.default_profile
        && !m.profiles.contains_key(p)
    {
        o.err(
            "settings",
            "default_profile",
            None,
            "unknown_profile",
            format!("default_profile names no profile {p:?}"),
        );
    }
    if let Some(l) = &s.dnssec.listener {
        match m.listeners.get(l) {
            Some(def) if def.proto == ListenerProto::Doh => {}
            Some(_) => o.err(
                "settings",
                "dnssec.listener",
                None,
                "not_doh",
                format!("dnssec.listener {l:?} is not a DoH listener"),
            ),
            None => o.err(
                "settings",
                "dnssec.listener",
                None,
                "unknown_listener",
                format!("dnssec.listener names no listener {l:?}"),
            ),
        }
    }
    // The cross-check resolver must be run by another operator than the upstreams (core.md §8).
    if let Some(r) = &s.crosscheck.resolver {
        let r_domain = registrable_domain(&r.tls_host);
        for u in m.upstreams.values() {
            if let Some(op) = &u.operator
                && op.trim().eq_ignore_ascii_case(r.operator.trim())
            {
                o.err("settings", "crosscheck", Some("resolver.operator"), "crosscheck_operator",
                    format!("the cross-check resolver's operator {:?} also runs upstream {:?}; pick a resolver run by another operator", r.operator, u.id));
            }
            if crate::net::canonical_ip(u.ip) == crate::net::canonical_ip(r.ip) {
                o.err(
                    "settings",
                    "crosscheck",
                    Some("resolver.ip"),
                    "crosscheck_ip",
                    format!("the cross-check resolver's IP {} is upstream {:?}'s", r.ip, u.id),
                );
            }
            if let (Some(h), Some(rd)) = (&u.tls_host, &r_domain)
                && registrable_domain(h).as_ref() == Some(rd)
            {
                o.err("settings", "crosscheck", Some("resolver.tls_host"), "crosscheck_domain",
                    format!("the cross-check resolver's TLS host shares the registrable domain {rd:?} with upstream {:?}", u.id));
            }
        }
    }
}

fn edge_rules(m: &Model, o: &mut Out) {
    let e = "edge";
    let mut names = BTreeMap::new();
    let mut keys = BTreeMap::new();
    for (id, edge) in &m.edges {
        check_id(o, e, id);
        check_name(o, e, id, &edge.name);
        if let Some(other) = names.insert(edge.name.to_lowercase(), id) {
            o.err(
                e,
                id,
                Some("name"),
                "duplicate_name",
                format!("edge {other:?} already has the name {:?}", edge.name),
            );
        }
        match picket_api::ids::parse_fingerprint(&edge.key) {
            Some(h) => {
                if let Some(other) = keys.insert(h, id) {
                    o.err(
                        e,
                        id,
                        Some("key"),
                        "duplicate_key",
                        format!("edge {other:?} already has this key"),
                    );
                }
            }
            None => o.err(
                e,
                id,
                Some("key"),
                "bad_key",
                "the key must be a SHA256:… fingerprint from `picket-edge key`".into(),
            ),
        }
        let s = &edge.settings;
        if !(16..=65_536).contains(&s.bundle_budget_mib) {
            o.err(
                e,
                id,
                Some("bundle_budget_mib"),
                "range",
                "bundle_budget_mib must be 16–65536".into(),
            );
        }
        if let Some(b) = s.overlay_budget_mib
            && !(1..=4096).contains(&b)
        {
            o.err(
                e,
                id,
                Some("overlay_budget_mib"),
                "range",
                "overlay_budget_mib must be 1–4096".into(),
            );
        }
        if !(1..=4096).contains(&s.verdict_budget_mib) {
            o.err(
                e,
                id,
                Some("verdict_budget_mib"),
                "range",
                "verdict_budget_mib must be 1–4096".into(),
            );
        }
        let fw = &s.firewall;
        check_len(o, e, id, "firewall.interfaces", &fw.interfaces);
        let mut ifs = HashSet::new();
        for i in &fw.interfaces {
            if !is_ifname(&i.name) {
                o.err(
                    e,
                    id,
                    Some("firewall.interfaces"),
                    "bad_interface",
                    format!("{:?} is not an interface name", i.name),
                );
            }
            if !ifs.insert(&i.name) {
                o.err(
                    e,
                    id,
                    Some("firewall.interfaces"),
                    "duplicate_interface",
                    format!("interface {:?} is listed twice", i.name),
                );
            }
        }
        check_cidrs(o, e, id, "firewall.static_allow", &fw.static_allow);
        check_cidrs(o, e, id, "firewall.exempt_sources", &fw.exempt_sources);
        if fw.ack_wait_ms > 2000 {
            o.err(
                e,
                id,
                Some("firewall.ack_wait_ms"),
                "range",
                "ack_wait_ms must be at most 2000".into(),
            );
        }
        if let Some(r) = &s.unifi.redirect {
            // edge.md §9: a redirect needs the helper, which needs firewall interfaces.
            if fw.interfaces.is_empty() {
                o.err(e, id, Some("unifi.redirect"), "redirect_needs_firewall",
                    "a UniFi redirect needs firewall interfaces (the helper checks it); add interfaces or remove the redirect".into());
            }
            if edge.platform != Platform::Unifi {
                o.err(
                    e,
                    id,
                    Some("unifi.redirect"),
                    "redirect_not_unifi",
                    "UniFi options apply only to platform unifi".into(),
                );
            }
            if r.interfaces.is_empty() {
                o.err(
                    e,
                    id,
                    Some("unifi.redirect.interfaces"),
                    "redirect_empty",
                    "the redirect needs the networks its rule covers".into(),
                );
            }
            for i in &r.interfaces {
                if !is_ifname(i) {
                    o.err(
                        e,
                        id,
                        Some("unifi.redirect.interfaces"),
                        "bad_interface",
                        format!("{i:?} is not an interface name"),
                    );
                }
            }
            // edge-unifi.md §3: all in one `dns` listener's interfaces on this edge.
            let covered = m.listeners.values().any(|l| {
                l.proto == ListenerProto::Dns
                    && l.edges.iter().any(|x| x == id)
                    && r.interfaces.iter().all(|i| l.interfaces.contains(i))
            });
            if !r.interfaces.is_empty() && !covered {
                o.err(e, id, Some("unifi.redirect.interfaces"), "redirect_listener",
                    "the redirect's interfaces must all be in one dns listener's interfaces assigned to this edge".into());
            }
        }
        let c = &s.cache;
        if !(1..=4096).contains(&c.size_mib) {
            o.err(
                e,
                id,
                Some("cache.size_mib"),
                "range",
                "cache.size_mib must be 1–4096".into(),
            );
        }
        if c.stale_max_s > 7 * 86_400 || c.stale_ttl_s > 86_400 {
            o.err(
                e,
                id,
                Some("cache"),
                "range",
                "stale_ttl_s must be ≤ 86400 and stale_max_s ≤ 604800".into(),
            );
        }
        let l = &s.logging;
        if l.spool_after_s == 0
            || l.spool_after_s > 3600
            || l.spool_max_mib == 0
            || l.spool_max_mib > 1 << 20
            || !(1..=u32::try_from(picket_api::logs::MAX_BATCH_RECORDS).unwrap_or(u32::MAX))
                .contains(&l.batch_max)
        {
            o.err(
                e,
                id,
                Some("logging"),
                "range",
                "logging: spool_after_s 1–3600, spool_max_mib 1–1048576, batch_max 1–1000".into(),
            );
        }
        if s.limits.client_qps == 0 || s.limits.client_inflight == 0 {
            o.err(
                e,
                id,
                Some("limits"),
                "range",
                "client limits must be above 0".into(),
            );
        }
        let max_rrset = u32::from(picket_wire::answer::MAX_SECTION_RECORDS);
        if s.limits.max_rrset_records > max_rrset {
            o.err(
                e,
                id,
                Some("limits"),
                "range",
                format!("limits: max_rrset_records is 0 (no limit) or 1–{max_rrset}"),
            );
        }
        // Warn when the sync providers' RAM tiers pass verdict_budget_mib (core.md §4).
        let total: u64 = sync_providers(m)
            .iter()
            .filter_map(|p| m.lookup_providers.get(*p))
            .map(|p| u64::from(p.settings.cache.max_mib))
            .sum();
        if total > u64::from(s.verdict_budget_mib) {
            o.warn(e, id, Some("verdict_budget_mib"), "verdict_budget",
                format!("this edge's sync lookup providers take {total} MiB of RAM tier, above its verdict_budget_mib ({})", s.verdict_budget_mib));
        }
    }
}

/// Every provider any profile attaches `sync` (every edge gets every profile).
fn sync_providers(m: &Model) -> BTreeSet<&str> {
    m.profiles
        .values()
        .flat_map(|p| p.edge.lookup_providers.iter())
        .filter(|a| a.mode == LookupMode::Sync)
        .map(|a| a.provider.as_str())
        .collect()
}

fn listener_rules(m: &Model, o: &mut Out) {
    let e = "listener";
    let zones = &m.settings.lanca.zones;
    let core_addresses: HashSet<IpAddr> = m
        .settings
        .web
        .addresses
        .iter()
        .filter_map(|a| a.parse().ok())
        .map(crate::net::canonical_ip)
        .collect();
    let mut binds: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    for (id, l) in &m.listeners {
        check_id(o, e, id);
        check_name(o, e, id, &l.name);
        match l.bind.parse::<SocketAddr>() {
            Ok(sa) if sa.port() != 0 => {}
            _ => o.err(
                e,
                id,
                Some("bind"),
                "bad_bind",
                format!("{:?} is not ip:port (e.g. [::]:5335 or 192.168.1.1:853)", l.bind),
            ),
        }
        // edge.md §16 "Not an open resolver": a wildcard bind must be restricted by `interfaces`.
        // The edge refuses to open one that isn't, so a listener assigned to an edge is refused
        // here, at save time, rather than found later from a `listener_failed` alert.
        let wildcard = l
            .bind
            .parse::<SocketAddr>()
            .is_ok_and(|sa| sa.ip().to_canonical().is_unspecified());
        if wildcard && l.interfaces.is_empty() && !l.edges.is_empty() {
            o.err(
                e,
                id,
                Some("interfaces"),
                "open_wildcard",
                format!(
                    "{} listens on every address: list the LAN interfaces it serves (e.g. br0), or bind a LAN address (edge.md §16: not an open resolver)",
                    l.bind
                ),
            );
        }
        check_len(o, e, id, "interfaces", &l.interfaces);
        for i in &l.interfaces {
            if !is_ifname(i) {
                o.err(
                    e,
                    id,
                    Some("interfaces"),
                    "bad_interface",
                    format!("{i:?} is not an interface name"),
                );
            }
        }
        for ip in &l.ips {
            if ip.is_unspecified() {
                o.err(
                    e,
                    id,
                    Some("ips"),
                    "bad_ip",
                    "a listener IP can't be unspecified".into(),
                );
            }
        }
        match (l.proto, &l.tls) {
            (ListenerProto::Dns, Some(_)) => o.err(
                e,
                id,
                Some("tls"),
                "tls_on_dns",
                "a dns listener has no TLS".into(),
            ),
            (ListenerProto::Dot | ListenerProto::Doh, None) => o.err(
                e,
                id,
                Some("tls"),
                "tls_missing",
                "DoT and DoH listeners need TLS (managed or files)".into(),
            ),
            (_, Some(t)) => match (&t.managed, &t.cert_file, &t.key_file) {
                (Some(name), None, None) => {
                    // A managed edge must not receive a certificate for a declared core address.
                    let mut listener_ips = l.ips.clone();
                    if let Ok(bind) = l.bind.parse::<SocketAddr>() {
                        listener_ips.push(bind.ip());
                    }
                    for ip in listener_ips {
                        let ip = crate::net::canonical_ip(ip);
                        if core_addresses.contains(&ip) {
                            o.err(
                                e,
                                id,
                                Some("ips"),
                                "managed_ip_conflict",
                                format!("{ip} is declared as a core address (web.addresses)"),
                            );
                        }
                    }
                    // core.md §2: managed listener names must be under lanca.zones.
                    let n = name.to_ascii_lowercase();
                    if n.starts_with("*.") || !is_dns_name(&n) {
                        o.err(
                            e,
                            id,
                            Some("tls.managed"),
                            "bad_name",
                            format!("{name:?} is not a DNS name"),
                        );
                    } else if !name_under_zones(&n, zones) {
                        o.err(
                            e,
                            id,
                            Some("tls.managed"),
                            "outside_lanca_zones",
                            format!(
                                "{name:?} is not under lanca.zones ({}); the LAN CA can't sign it",
                                zones.join(", ")
                            ),
                        );
                    } else if let Some(problem) = managed_name_conflict(&n, zones, &m.settings.web.names) {
                        o.err(e, id, Some("tls.managed"), "managed_name_conflict", problem);
                    }
                }
                (None, Some(c), Some(k)) => {
                    if !c.starts_with('/') || !k.starts_with('/') {
                        o.err(
                            e,
                            id,
                            Some("tls"),
                            "bad_path",
                            "cert_file and key_file must be absolute paths on the edge".into(),
                        );
                    }
                }
                _ => o.err(
                    e,
                    id,
                    Some("tls"),
                    "bad_tls",
                    "set either managed, or both cert_file and key_file".into(),
                ),
            },
            (ListenerProto::Dns, None) => {}
        }
        if l.api && l.proto != ListenerProto::Doh {
            o.err(
                e,
                id,
                Some("api"),
                "api_not_doh",
                "only DoH listeners serve the bypass API".into(),
            );
        }
        let lim = &l.limits;
        if lim.max_connections == 0
            || lim.max_connections > 65_536
            || !(512..=4096).contains(&lim.udp_payload)
            || !(1000..=3_600_000).contains(&lim.idle_timeout_ms)
        {
            o.err(
                e,
                id,
                Some("limits"),
                "range",
                "limits: max_connections 1–65536, udp_payload 512–4096, idle_timeout_ms 1000–3600000".into(),
            );
        }
        for d in dupes(&l.edges) {
            o.err(
                e,
                id,
                Some("edges"),
                "duplicate",
                format!("edge {d:?} is listed twice"),
            );
        }
        for edge in &l.edges {
            if !m.edges.contains_key(edge) {
                o.err(e, id, Some("edges"), "unknown_edge", format!("no edge {edge:?}"));
            } else if let Some(other) = binds.insert((edge.as_str(), l.bind.as_str()), id.as_str())
                && proto_overlap(m.listeners.get(other).map(|x| x.proto), l.proto)
            {
                o.err(
                    e,
                    id,
                    Some("bind"),
                    "bind_conflict",
                    format!("listener {other:?} already binds {} on edge {edge:?}", l.bind),
                );
            }
        }
    }
    // A bind missing from an edge's reported `allowed_binds` is flagged from the edges' last
    // hellos ([`allowed_binds`], with the configuration issues).
}

/// Listeners whose bind an assigned edge's reported `allowed_binds` doesn't hold (core.md §4:
/// core flags them; the edge also refuses them and reports): warnings, from each edge's last
/// `hello` (`reported`: edge id → its `allowed_binds`; an edge that never reported is skipped).
pub fn allowed_binds(m: &Model, reported: &BTreeMap<String, Vec<String>>) -> Vec<Issue> {
    let mut out = Vec::new();
    for (id, l) in &m.listeners {
        for edge in &l.edges {
            let Some(allowed) = reported.get(edge) else {
                continue;
            };
            if allowed.iter().any(|b| b == "*" || *b == l.bind) {
                continue;
            }
            let name = m
                .edges
                .get(edge)
                .map(|e| e.name.as_str())
                .unwrap_or(edge.as_str());
            out.push(Issue {
                severity: Severity::Warning,
                entity: "listener".into(),
                id: id.clone(),
                field: Some("bind".into()),
                code: "bind_not_allowed".into(),
                message: format!(
                    "edge {name:?} doesn't allow binding {} (its allowed_binds): it won't open this listener",
                    l.bind
                ),
            });
        }
    }
    out
}

/// Why a managed listener name can't be used: its certificate (SANs `name` and `*.name`, edge.md
/// §5) would cover a whole zone or one of core's own `web.names`, so the edge holding it could
/// present a LAN-CA certificate for core's UI. Edges are untrusted (README §2), so the name must
/// sit strictly under a zone and its wildcard must not reach `web.names`; checked whichever of
/// the listener and `web.names` changes second.
fn managed_name_conflict(name: &str, zones: &[String], web_names: &[String]) -> Option<String> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    if zones
        .iter()
        .any(|z| z.trim_end_matches('.').eq_ignore_ascii_case(&n))
    {
        return Some(format!(
            "{name:?} is a lanca zone itself; its certificate's *.{n} would cover every name in the zone, \
             core's included: use a name under it (e.g. dns.{n})"
        ));
    }
    for w in web_names {
        let w = w.trim_end_matches('.').to_ascii_lowercase();
        let covered = w == n || w.split_once('.').is_some_and(|(_, parent)| parent == n);
        if covered {
            return Some(format!(
                "{name:?}'s certificate (with *.{n}) would cover core's own name {w:?} (web.names)"
            ));
        }
    }
    None
}

fn proto_overlap(_a: Option<ListenerProto>, _b: ListenerProto) -> bool {
    // Every protocol binds TCP on its port, so two listeners on one ip:port always collide.
    true
}

fn client_rules(m: &Model, o: &mut Out) {
    let e = "client";
    let mut names = HashSet::new();
    let mut macs: BTreeMap<String, &str> = BTreeMap::new();
    for c in &m.clients {
        let id = c.name.as_str();
        check_name(o, e, id, &c.name);
        if let Some(msg) = client_name_problem(&c.name) {
            o.err(e, id, Some("name"), "bad_client_name", msg.into());
        }
        if !names.insert(c.name.as_str()) {
            o.err(
                e,
                id,
                Some("name"),
                "duplicate_name",
                format!("two clients are named {:?}", c.name),
            );
        }
        if c.macs.is_empty() && c.source_ips.is_empty() {
            o.err(
                e,
                id,
                None,
                "no_devices",
                "a client names its devices by macs or source_ips".into(),
            );
        }
        check_len(o, e, id, "macs", &c.macs);
        for mac in &c.macs {
            match crate::net::normalize_mac(mac) {
                Some(n) => {
                    if let Some(other) = macs.insert(n.clone(), id)
                        && other != id
                    {
                        o.err(
                            e,
                            id,
                            Some("macs"),
                            "duplicate_mac",
                            format!("{n} is already client {other:?}'s"),
                        );
                    }
                }
                None => o.err(
                    e,
                    id,
                    Some("macs"),
                    "bad_mac",
                    format!("{mac:?} is not a MAC address"),
                ),
            }
        }
        check_cidrs(o, e, id, "source_ips", &c.source_ips);
        if let Some(p) = &c.profile
            && !m.profiles.contains_key(p)
        {
            o.err(
                e,
                id,
                Some("profile"),
                "unknown_profile",
                format!("no profile {p:?}"),
            );
        }
        check_len(o, e, id, "tags", &c.tags);
        for t in &c.tags {
            if t.is_empty()
                || t.len() > 64
                || t.chars()
                    .any(|ch| ch.is_whitespace() || ch.is_control() || ch == ',' || ch == '|')
            {
                o.err(
                    e,
                    id,
                    Some("tags"),
                    "bad_tag",
                    format!("{t:?} is not a tag (1–64 characters, no spaces, commas or |)"),
                );
            }
        }
    }
}

fn profile_rules(m: &Model, o: &mut Out) {
    let e = "profile";
    let client_names: HashSet<&str> = m.clients.iter().map(|c| c.name.as_str()).collect();
    for (id, p) in &m.profiles {
        if !is_profile_id(id) {
            o.err(e, id, Some("id"), "bad_profile_id",
                format!("{id:?} is not a profile id: a DNS label (lowercase letters, digits, hyphens) not ending in -full"));
        }
        check_name(o, e, id, &p.name);
        let ep = &p.edge;
        check_len(o, e, id, "allowed_sources", &ep.allowed_sources);
        for s in &ep.allowed_sources {
            let ok = crate::net::parse_net(s).is_some()
                || crate::net::normalize_mac(s).is_some()
                || client_names.contains(s.as_str());
            if !ok {
                o.err(
                    e,
                    id,
                    Some("allowed_sources"),
                    "bad_source",
                    format!("{s:?} is neither an address range, a MAC nor a client name"),
                );
            }
        }
        for (field, list, want) in [
            ("allow", &ep.allow, BundleAction::Allow),
            ("block", &ep.block, BundleAction::Block),
        ] {
            check_len(o, e, id, field, list);
            for d in dupes(list) {
                o.err(
                    e,
                    id,
                    Some(field),
                    "duplicate",
                    format!("bundle {d:?} is listed twice"),
                );
            }
            for b in list {
                match m.bundles.get(b) {
                    None => o.err(e, id, Some(field), "unknown_bundle", format!("no bundle {b:?}")),
                    Some(def) if def.action != want => o.err(
                        e,
                        id,
                        Some(field),
                        "wrong_action",
                        format!(
                            "{b:?} is a {} bundle; {field} takes only {} bundles",
                            def.action.as_str(),
                            want.as_str()
                        ),
                    ),
                    _ => {}
                }
            }
        }
        for d in dupes(&p.trial_bundles) {
            o.err(
                e,
                id,
                Some("trial_bundles"),
                "duplicate",
                format!("bundle {d:?} is listed twice"),
            );
        }
        for b in &p.trial_bundles {
            match m.bundles.get(b) {
                None => o.err(
                    e,
                    id,
                    Some("trial_bundles"),
                    "unknown_bundle",
                    format!("no bundle {b:?}"),
                ),
                Some(def) if def.action != BundleAction::Block => o.err(
                    e,
                    id,
                    Some("trial_bundles"),
                    "trial_not_block",
                    format!("{b:?} isn't a block bundle; only block bundles go on trial"),
                ),
                _ => {}
            }
            if ep.block.contains(b) {
                o.err(
                    e,
                    id,
                    Some("trial_bundles"),
                    "trial_in_block",
                    format!("{b:?} is also in this profile's block list; enforce it or trial it, not both"),
                );
            }
        }
        // Two forward zones may route one zone (different profiles, different groups), but one
        // profile can't list both: the route would be ambiguous.
        let mut routed: BTreeMap<String, &str> = BTreeMap::new();
        for z in &ep.forward_zones {
            match m.forward_zones.get(z) {
                None => o.err(
                    e,
                    id,
                    Some("forward_zones"),
                    "unknown_zone",
                    format!("no forward zone {z:?}"),
                ),
                Some(def) => {
                    let name = def.zone.trim_end_matches('.').to_ascii_lowercase();
                    if let Some(other) = routed.insert(name, z.as_str())
                        && other != z
                    {
                        o.err(
                            e,
                            id,
                            Some("forward_zones"),
                            "duplicate_zone",
                            format!("forward zones {other:?} and {z:?} both route {:?}", def.zone),
                        );
                    }
                }
            }
        }
        let mut attached = HashSet::new();
        for a in &ep.lookup_providers {
            if !attached.insert(&a.provider) {
                o.err(
                    e,
                    id,
                    Some("lookup_providers"),
                    "duplicate",
                    format!("provider {:?} is attached twice", a.provider),
                );
            }
            if !m.lookup_providers.contains_key(&a.provider) {
                o.err(
                    e,
                    id,
                    Some("lookup_providers"),
                    "unknown_provider",
                    format!("no lookup provider {:?}", a.provider),
                );
            }
            for (field, list) in [
                ("lookup_providers.include_bundles", &a.include_bundles),
                ("lookup_providers.exclude_bundles", &a.exclude_bundles),
            ] {
                scope_bundles(m, o, e, id, field, list);
            }
        }
        if !m.upstream_groups.contains_key(&ep.upstream) {
            o.err(
                e,
                id,
                Some("upstream"),
                "unknown_group",
                format!("no upstream group {:?}", ep.upstream),
            );
        }
        if !(1..=10_000).contains(&ep.sync_lookup_budget_ms) {
            o.err(
                e,
                id,
                Some("sync_lookup_budget_ms"),
                "range",
                "sync_lookup_budget_ms must be 1–10000".into(),
            );
        }
        if ep.ttl.min > ep.ttl.max || ep.ttl.max > 7 * 86_400 {
            o.err(
                e,
                id,
                Some("ttl"),
                "range",
                "ttl.min must be ≤ ttl.max ≤ 604800".into(),
            );
        }
        let br = &ep.block_response;
        if br.kind == BlockResponseType::CustomIp && br.ipv4.is_none() && br.ipv6.is_none() {
            o.err(
                e,
                id,
                Some("block_response"),
                "custom_ip_missing",
                "custom_ip needs ipv4 and/or ipv6".into(),
            );
        }
        if br.ttl > 86_400 {
            o.err(
                e,
                id,
                Some("block_response.ttl"),
                "range",
                "block_response.ttl must be ≤ 86400".into(),
            );
        } else if br.ttl > picket_api::edge_config::MAX_BLOCK_TTL_S {
            // The edge lowers it so a browser's cached block answer expires inside a 15 min allow.
            o.warn(
                e,
                id,
                Some("block_response.ttl"),
                "block_ttl_capped",
                format!(
                    "block_response.ttl {} is above {} s: the edge serves blocked answers with {} s, so a temporary allow can reach a browser that cached the block",
                    br.ttl,
                    picket_api::edge_config::MAX_BLOCK_TTL_S,
                    picket_api::edge_config::MAX_BLOCK_TTL_S
                ),
            );
        }
        if ep.firewall.grace_s > 86_400 {
            o.err(
                e,
                id,
                Some("firewall.grace_s"),
                "range",
                "firewall.grace_s must be ≤ 86400".into(),
            );
        }
        let bp = &ep.bypass;
        if bp.max_duration.as_secs() < 60
            || bp.max_duration.as_secs() > 30 * 86_400
            || bp.max_active > 10_000
            || bp.rate_per_hour > 10_000
        {
            o.err(
                e,
                id,
                Some("bypass"),
                "range",
                "bypass: max_duration 1m–30d, max_active and rate_per_hour ≤ 10000".into(),
            );
        } else if bp.mode == picket_api::edge_config::BypassMode::SelfService
            && br.ttl <= 86_400
            && bp.max_duration.as_secs() < picket_api::edge_config::min_allow_for_block_s(br.ttl)
        {
            // An allow of a fresh block would end while browsers still use its cached answer:
            // the edge refuses those (`too_short`), so such a profile could lift no fresh block
            // (#50).
            let need = picket_api::edge_config::min_allow_for_block_s(br.ttl);
            o.err(
                e,
                id,
                Some("bypass.max_duration"),
                "bypass_shorter_than_block_hold",
                format!(
                    "bypass.max_duration {} s is shorter than the {need} s a temporary allow needs to outlast the cached block answer (block_response.ttl {} s, plus 5 s slack and 5 s for the reload; at least 60 s): raise bypass.max_duration to {need} s or more, or lower block_response.ttl",
                    bp.max_duration.as_secs(),
                    br.ttl.min(picket_api::edge_config::MAX_BLOCK_TTL_S),
                ),
            );
        }
        for c in &p.alert_categories {
            if !["security", "privacy", "mixed"].contains(&c.as_str()) {
                o.err(
                    e,
                    id,
                    Some("alert_categories"),
                    "bad_category",
                    format!("{c:?} is not a category (security, privacy, mixed)"),
                );
            }
        }
        if let Some(list) = &p.alert_lookup_providers {
            for lp in list {
                if !m.lookup_providers.contains_key(lp) {
                    o.err(
                        e,
                        id,
                        Some("alert_lookup_providers"),
                        "unknown_provider",
                        format!("no lookup provider {lp:?}"),
                    );
                }
            }
        }
        if ep.allowed_sources.is_empty() && id != system::DNSSEC_PROFILE {
            o.warn(
                e,
                id,
                Some("allowed_sources"),
                "no_sources",
                "allowed_sources is empty: the profile admits no one".into(),
            );
        }
        if br.kind == BlockResponseType::CustomIp && ep.firewall.add_entries {
            // core.md §12: block answers open no firewall entries.
            o.warn(e, id, Some("block_response"), "custom_ip_firewall",
                "under firewall enforce, clients reach the block-page host only if it is on their own subnet or in the edge's static_allow".into());
        }
        // core.md §8: the dnssec-validator profile sees unfiltered data and costs the edge nothing.
        if id == system::DNSSEC_PROFILE {
            if !ep.allow.is_empty()
                || !ep.block.is_empty()
                || !ep.lookup_providers.is_empty()
                || !ep.forward_zones.is_empty()
                || !p.trial_bundles.is_empty()
            {
                o.err(
                    e,
                    id,
                    None,
                    "validator_filtered",
                    "the dnssec-validator profile has no bundles, lookup providers or forward zones".into(),
                );
            }
            if ep.firewall.add_entries || ep.log != picket_api::edge_config::LogLevel::Off {
                o.err(
                    e,
                    id,
                    None,
                    "validator_settings",
                    "the dnssec-validator profile keeps firewall.add_entries false and log off".into(),
                );
            }
        }
    }
}

/// Lookup scope bundles: exist, and are neither warn bundles nor cold-capable block bundles
/// (edge.md §10), checked whichever side changes.
fn scope_bundles(m: &Model, o: &mut Out, entity: &str, id: &str, field: &str, list: &[String]) {
    check_len(o, entity, id, field, list);
    for b in list {
        match m.bundles.get(b) {
            None => o.err(entity, id, Some(field), "unknown_bundle", format!("no bundle {b:?}")),
            Some(def) if def.action == BundleAction::Warn => o.err(entity, id, Some(field), "scope_warn",
                format!("{b:?} is a warn bundle; lookup scopes can't name warn bundles")),
            Some(def) if def.cold_capable() => o.err(entity, id, Some(field), "scope_cold",
                format!("{b:?} can have a cold part (tier cold, or intelligent-tiering with hot_max_mib); lookup scopes can't name it")),
            _ => {}
        }
    }
}

/// A profile's trial bundles can't be in the scope of its `sync` attachments or of their
/// providers (core.md §2), whichever change comes second.
fn trial_scope_rules(m: &Model, o: &mut Out) {
    for (id, p) in &m.profiles {
        for a in p
            .edge
            .lookup_providers
            .iter()
            .filter(|a| a.mode == LookupMode::Sync)
        {
            let provider = m.lookup_providers.get(&a.provider);
            for t in &p.trial_bundles {
                let in_attachment = a.include_bundles.contains(t) || a.exclude_bundles.contains(t);
                let in_provider = provider.is_some_and(|lp| {
                    lp.settings.scope.include_bundles.contains(t)
                        || lp.settings.scope.exclude_bundles.contains(t)
                });
                if in_attachment || in_provider {
                    let whose = if in_attachment {
                        "its sync attachment of"
                    } else {
                        "the scope of sync provider"
                    };
                    o.err(
                        "profile",
                        id,
                        Some("trial_bundles"),
                        "trial_in_sync_scope",
                        format!(
                            "trial bundle {t:?} is in {whose} {:?}; the edge would need it for that scope",
                            a.provider
                        ),
                    );
                }
            }
        }
    }
}

fn upstream_rules(m: &Model, o: &mut Out) {
    let e = "upstream";
    for (id, u) in &m.upstreams {
        check_id(o, e, id);
        check_name(o, e, id, &u.name);
        if u.ip.is_unspecified() {
            o.err(
                e,
                id,
                Some("ip"),
                "bad_ip",
                "an upstream needs an IP (it is never resolved)".into(),
            );
        }
        if u.port == 0 {
            o.err(e, id, Some("port"), "range", "the port can't be 0".into());
        }
        // edge.md §6: presets fill `operator`, and a custom endpoint must set it.
        match u.operator.as_deref().map(str::trim) {
            None | Some("") => o.err(
                e,
                id,
                Some("operator"),
                "operator_missing",
                "set the operator who runs this upstream (cloudflare, quad9, lan, …)".into(),
            ),
            Some(op) if !is_operator(op) => o.err(
                e,
                id,
                Some("operator"),
                "bad_operator",
                "the operator is 1–64 of letters, digits, '.', '_' and '-'".into(),
            ),
            Some(_) => {}
        }
        if u.protocol.is_encrypted() {
            match &u.tls_host {
                Some(h) if is_dns_name(&h.to_ascii_lowercase()) => {}
                _ => o.err(
                    e,
                    id,
                    Some("tls_host"),
                    "tls_host_missing",
                    "DoT and DoH upstreams need a TLS host name".into(),
                ),
            }
        } else {
            // edge.md §6: plain upstreams only to private or loopback IPs.
            let ip = crate::net::canonical_ip(u.ip);
            let local = ip.is_loopback()
                || crate::net::is_lan_ip(&ip)
                || matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80);
            if !local {
                o.err(
                    e,
                    id,
                    Some("ip"),
                    "plain_public",
                    "udp and tcp upstreams only go to private or loopback IPs".into(),
                );
            }
            if u.path.is_some() {
                o.err(
                    e,
                    id,
                    Some("path"),
                    "path_not_doh",
                    "only DoH upstreams have a path".into(),
                );
            }
        }
        match (&u.protocol, &u.path) {
            (UpstreamProtocol::Doh, Some(p)) if !picket_api::edge_config::is_doh_path(p) => o.err(
                e,
                id,
                Some("path"),
                "bad_path",
                format!(
                    "the DoH path must be {} (default /dns-query)",
                    picket_api::edge_config::DOH_PATH_RULE
                ),
            ),
            (UpstreamProtocol::Dot, Some(_)) => o.err(
                e,
                id,
                Some("path"),
                "path_not_doh",
                "only DoH upstreams have a path".into(),
            ),
            _ => {}
        }
        if let Some(ts) = &u.trust_store
            && !pem_has_certificate(ts)
        {
            o.err(
                e,
                id,
                Some("trust_store"),
                "bad_trust_store",
                "trust_store must be PEM certificates (≤ 64 KiB)".into(),
            );
        }
    }
}

fn group_rules(m: &Model, o: &mut Out) {
    let e = "upstream_group";
    for (id, g) in &m.upstream_groups {
        check_id(o, e, id);
        check_name(o, e, id, &g.name);
        if g.upstreams.is_empty() {
            o.err(
                e,
                id,
                Some("upstreams"),
                "empty_group",
                "a group needs at least one upstream".into(),
            );
        }
        check_len(o, e, id, "upstreams", &g.upstreams);
        for d in dupes(&g.upstreams) {
            o.err(
                e,
                id,
                Some("upstreams"),
                "duplicate",
                format!("upstream {d:?} is listed twice"),
            );
        }
        let mut plain = false;
        let mut encrypted = false;
        for u in &g.upstreams {
            match m.upstreams.get(u) {
                None => o.err(
                    e,
                    id,
                    Some("upstreams"),
                    "unknown_upstream",
                    format!("no upstream {u:?}"),
                ),
                Some(def) if def.protocol.is_encrypted() => encrypted = true,
                Some(_) => plain = true,
            }
        }
        // core.md §2: a plain group keeps the client's DO, so mixing is refused.
        if plain && encrypted {
            o.err(
                e,
                id,
                Some("upstreams"),
                "mixed_group",
                "a group's upstreams must be all plain (udp, tcp) or all encrypted (DoT, DoH)".into(),
            );
        }
    }
}

fn zone_rules(m: &Model, o: &mut Out) {
    let e = "forward_zone";
    for (id, z) in &m.forward_zones {
        check_id(o, e, id);
        let name = z.zone.trim_end_matches('.').to_ascii_lowercase();
        if !is_zone_name(&name) || name != z.zone {
            o.err(
                e,
                id,
                Some("zone"),
                "bad_zone",
                format!("{:?} is not a lowercase zone name without a trailing dot", z.zone),
            );
        }
        if !m.upstream_groups.contains_key(&z.group) {
            o.err(
                e,
                id,
                Some("group"),
                "unknown_group",
                format!("no upstream group {:?}", z.group),
            );
        }
    }
}

/// The most `files` and `exclude` entries a provider may have.
const MAX_FILE_ENTRIES: usize = 256;

/// `https://sqs.<region>.amazonaws.com/<12-digit account>/<queue name>` (feed-scheduling.md §7):
/// the region, account and queue.
pub fn parse_queue_url(url: &str) -> Option<(String, String, String)> {
    let rest = url.strip_prefix("https://sqs.")?;
    let (region, rest) = rest.split_once(".amazonaws.com/")?;
    let (account, queue) = rest.split_once('/')?;
    let region_ok = !region.is_empty()
        && region.len() <= 32
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let account_ok = account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit());
    // SQS queue names: 1–80 of a-z, A-Z, 0-9, - and _ (`.fifo` suffix for FIFO queues).
    let name = queue.strip_suffix(".fifo").unwrap_or(queue);
    let queue_ok = !name.is_empty()
        && queue.len() <= 80
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    (region_ok && account_ok && queue_ok)
        .then(|| (region.to_string(), account.to_string(), queue.to_string()))
}

fn feed_provider_rules(m: &Model, o: &mut Out) {
    let e = "feed_provider";
    let reg = crate::modules::download::builtin();
    let mut queues: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (id, p) in &m.feed_providers {
        check_id(o, e, id);
        check_name(o, e, id, &p.name);
        let module = reg.get(&p.module);
        if module.is_none() {
            o.err(
                e,
                id,
                Some("module"),
                "unknown_module",
                format!(
                    "{:?} is not a download module ({})",
                    p.module,
                    crate::modules::download::known_ids().join(", ")
                ),
            );
        }
        if !p.config.is_object() || p.config.to_string().len() > 64 * 1024 {
            o.err(
                e,
                id,
                Some("config"),
                "bad_config",
                "config must be a JSON object (≤ 64 KiB)".into(),
            );
        }
        literal_credential_rule(o, e, id, "config", &p.config);
        for name in p.secret_refs() {
            match m.secrets.get(&name) {
                Some(sm) if sm.has_value => {}
                _ => o.warn(
                    e,
                    id,
                    Some("config"),
                    "secret_missing",
                    format!("secret {name:?} has no value yet"),
                ),
            }
        }
        // The module's own check of its Config (providers.md §1–§3).
        if let Some(md) = &module
            && p.config.is_object()
            && let Err(msg) = md.normalize_config(&p.config)
        {
            o.err(e, id, Some("config"), "bad_config", msg);
        }
        // Triggers (feed-scheduling.md).
        let min_interval = p.trigger.min_interval();
        if min_interval.as_secs() < 60 || min_interval.as_secs() > 7 * 86_400 {
            o.err(
                e,
                id,
                Some("trigger.min_interval"),
                "range",
                "min_interval must be 1m–7d".into(),
            );
        }
        match &p.trigger {
            Trigger::Dynamic { .. } => {}
            Trigger::Cron { cron, jitter, .. } => {
                if cron.len() > 128 || picket_lookup::cron::parse(cron).is_err() {
                    o.err(
                        e,
                        id,
                        Some("trigger.cron"),
                        "bad_cron",
                        format!("{cron:?} is not a cron expression"),
                    );
                }
                if jitter.as_secs() > 86_400 {
                    o.err(
                        e,
                        id,
                        Some("trigger.jitter"),
                        "range",
                        "jitter must be ≤ 1d".into(),
                    );
                }
            }
            Trigger::Sqs {
                queue_url,
                access_key_id,
                secret_access_key,
                backstop,
                ..
            } => {
                if parse_queue_url(queue_url).is_none() {
                    o.err(
                        e,
                        id,
                        Some("trigger.queue_url"),
                        "bad_queue_url",
                        "queue_url must be https://sqs.<region>.amazonaws.com/<12-digit account>/<queue name>".into(),
                    );
                } else {
                    queues.entry(queue_url.as_str()).or_default().push(id.as_str());
                }
                for (field, v) in [
                    ("trigger.access_key_id", access_key_id),
                    ("trigger.secret_access_key", secret_access_key),
                ] {
                    if !crate::modules::download::is_secret_ref(v) {
                        o.err(
                            e,
                            id,
                            Some(field),
                            "secret_required",
                            format!("{field} takes a ${{secret:name}} reference"),
                        );
                    }
                }
                if backstop.as_secs() < 60 || backstop.as_secs() > 7 * 86_400 {
                    o.err(
                        e,
                        id,
                        Some("trigger.backstop"),
                        "range",
                        "backstop must be 1m–7d".into(),
                    );
                }
            }
        }
        // `files` and `exclude` (feeds.md §1).
        if p.files.len() > MAX_FILE_ENTRIES || p.exclude.len() > MAX_FILE_ENTRIES {
            o.err(
                e,
                id,
                Some("files"),
                "too_many",
                format!("at most {MAX_FILE_ENTRIES} files and exclude entries"),
            );
        }
        let lists = module.as_ref().is_some_and(|md| md.lists_files());
        let mut seen = HashSet::new();
        for (i, f) in p.files.iter().enumerate() {
            let field = format!("files[{i}]");
            if !seen.insert(f.pattern.as_str()) {
                o.err(
                    e,
                    id,
                    Some(&field),
                    "duplicate",
                    format!("{:?} is listed twice", f.pattern),
                );
            }
            if !lists && crate::modules::download::glob::is_glob(&f.pattern) {
                o.err(
                    e,
                    id,
                    Some(&field),
                    "glob_needs_listing",
                    format!("{} doesn't list files: files takes paths, not globs", p.module),
                );
            }
            // No file name is empty or blank, whatever the module (alphamountain_threat_1000's and
            // http's one file have names too).
            if f.pattern.trim().is_empty() {
                o.err(
                    e,
                    id,
                    Some(&field),
                    "empty_file",
                    "a files entry can't be empty or only spaces: name a file (or, for a module that lists files, a glob)"
                        .into(),
                );
            } else if let Some(md) = &module
                && let Err(msg) = md.check_file(&p.config, &f.pattern, true)
            {
                o.err(e, id, Some(&field), "bad_file", msg);
            }
            if let Err(msg) = crate::feeds::select::check_template(f.feed.as_ref()) {
                o.err(e, id, Some(&format!("{field}.feed")), "bad_feed", msg);
            }
            // providers.md §3: alphamountain_threat_1000 writes a plain file.
            if p.module == "alphamountain_threat_1000"
                && f.feed
                    .as_ref()
                    .and_then(|t| t.get("format"))
                    .and_then(|v| v.as_str())
                    != Some("plain")
            {
                o.err(
                    e,
                    id,
                    Some(&format!("{field}.feed.format")),
                    "format_must_be_plain",
                    "an alphamountain_threat_1000 feed's format must be plain".into(),
                );
            }
            // A file is a name: secrets go in the config (headers), never in a file (an http
            // URL's query is config, checked as such).
            if f.pattern.contains("${") {
                o.err(
                    e,
                    id,
                    Some(&field),
                    "bad_file",
                    "a file can't reference a secret; put it in a header".into(),
                );
            }
            // The warn bundles a new feed would name must be warn bundles (feeds.md §1).
            if let Some(ws) = f
                .feed
                .as_ref()
                .and_then(|t| t.get("warn_on"))
                .and_then(|w| w.as_array())
            {
                for w in ws.iter().filter_map(|w| w.as_str()) {
                    if m.bundles.get(w).is_none_or(|b| b.action != BundleAction::Warn) {
                        o.err(
                            e,
                            id,
                            Some(&format!("{field}.feed.warn_on")),
                            "warn_on_not_warn",
                            format!("{w:?} isn't a warn bundle"),
                        );
                    }
                }
            }
        }
        for (i, x) in p.exclude.iter().enumerate() {
            if let Err(msg) = crate::modules::download::glob::check(x) {
                o.err(e, id, Some(&format!("exclude[{i}]")), "bad_glob", msg);
            }
        }
        // providers.md §2: overlapping providers save with a warning naming the other.
        let others = crate::feeds::select::overlapping(m, p);
        if !others.is_empty() {
            let what = if module.as_ref().is_some_and(|md| md.fixed_file().is_some()) {
                "has the same URL"
            } else {
                "covers the same files"
            };
            o.warn(
                e,
                id,
                Some("config"),
                "overlap",
                format!(
                    "feed provider {} {what}; their feeds stay separate, each downloaded on its own",
                    others.join(", ")
                ),
            );
        }
        // feeds.md §1: the feed of a provider of one fixed file (http, alphaMountain) takes the
        // provider's id, so another feed can't have it while that feed is still to be added.
        if let Some(md) = &module
            && let Some(file) = md.fixed_file()
            && crate::feeds::select::selects(p, md.as_ref(), file).is_some()
            && !m
                .feeds
                .values()
                .any(|f| f.provider.as_deref() == Some(p.id.as_str()))
            && let Some(other) = m.feeds.get(&p.id)
        {
            o.err(
                e,
                id,
                Some("id"),
                "id_taken",
                format!(
                    "feed {:?} exists and isn't this provider's: a {} provider's feed takes the provider's id; pick another id, or delete that feed",
                    other.id, p.module
                ),
            );
        }
    }
    // feed-scheduling.md §7: one provider per queue (consumers take each other's messages).
    for (url, ids) in queues {
        if ids.len() > 1 {
            for id in &ids {
                let others: Vec<&str> = ids.iter().copied().filter(|x| x != id).collect();
                o.err(
                    e,
                    id,
                    Some("trigger.queue_url"),
                    "queue_shared",
                    format!(
                        "feed provider {} already reads {url}; each SQS queue may have one feed provider",
                        others.join(", ")
                    ),
                );
            }
        }
    }
}

fn feed_rules(m: &Model, o: &mut Out) {
    let e = "feed";
    let reg = crate::modules::download::builtin();
    let mut files: HashMap<(&str, &str), Vec<&str>> = HashMap::new();
    for (id, f) in &m.feeds {
        check_id(o, e, id);
        check_name(o, e, id, &f.name);
        match (&f.provider, &f.file) {
            (None, None) => {}
            (Some(_), Some(file)) if file.trim().is_empty() => o.err(
                e,
                id,
                Some("file"),
                "empty_file",
                "a provider feed's file can't be empty or only spaces: name the file it reads".into(),
            ),
            (Some(p), Some(file)) => {
                files
                    .entry((p.as_str(), file.as_str()))
                    .or_default()
                    .push(id.as_str());
                match m.feed_providers.get(p) {
                    None => o.err(
                        e,
                        id,
                        Some("provider"),
                        "unknown_provider",
                        format!("no feed provider {p:?}"),
                    ),
                    Some(pd) => {
                        if let Some(md) = reg.get(&pd.module) {
                            if let Err(msg) = md.check_file(&pd.config, file, false) {
                                o.err(e, id, Some("file"), "bad_file", msg);
                            }
                            // providers.md §3: alphamountain_threat_1000 writes a plain file.
                            if pd.module == "alphamountain_threat_1000" && f.format != FeedFormat::Plain {
                                o.err(
                                    e,
                                    id,
                                    Some("format"),
                                    "format_must_be_plain",
                                    "an alphamountain_threat_1000 feed's format must be plain".into(),
                                );
                            }
                        }
                    }
                }
            }
            _ => o.err(
                e,
                id,
                Some("file"),
                "provider_and_file",
                "a provider feed has both provider and file; a manual feed neither".into(),
            ),
        }
        if f.system && !f.is_manual() {
            o.err(
                e,
                id,
                Some("provider"),
                "system_feed_manual",
                "system feeds stay manual feeds".into(),
            );
        }
        if f.format_options.domains_as.is_some() && f.format != FeedFormat::Plain {
            o.err(
                e,
                id,
                Some("format_options.domains_as"),
                "plain_only",
                "domains_as applies to the plain format only".into(),
            );
        }
        for (field, spec) in [
            ("modes.dns", &f.modes.dns),
            ("modes.ip", &f.modes.ip),
            ("modes.browser", &f.modes.browser),
        ] {
            if let Some(x) = spec.expire_after {
                if spec.mode != Mode::Aggregate {
                    o.err(
                        e,
                        id,
                        Some(field),
                        "expire_needs_aggregate",
                        "expire_after applies to aggregate mode only".into(),
                    );
                }
                if x.as_secs() < 3600 || x.as_secs() > 366 * 86_400 {
                    o.err(e, id, Some(field), "range", "expire_after must be 1h–366d".into());
                }
            }
        }
        let s = &f.sanity;
        let ratio_ok = |r: f64| r.is_finite() && (0.0..=1.0).contains(&r);
        if !ratio_ok(s.max_change_ratio) || !ratio_ok(s.max_parse_error_ratio) {
            o.err(
                e,
                id,
                Some("sanity"),
                "range",
                "ratios must be between 0 and 1".into(),
            );
        }
        if s.reject_drop_ratio.is_some_and(|r| !ratio_ok(r) || r <= 0.0) {
            o.err(
                e,
                id,
                Some("sanity.reject_drop_ratio"),
                "range",
                "reject_drop_ratio must be above 0 and at most 1".into(),
            );
        }
        if let (Some(a), Some(b)) = (s.min_entries, s.max_entries)
            && a > b
        {
            o.err(
                e,
                id,
                Some("sanity"),
                "range",
                "min_entries must be ≤ max_entries".into(),
            );
        }
        if s.confirm_after.as_secs() > 7 * 86_400 {
            o.err(
                e,
                id,
                Some("sanity.confirm_after"),
                "range",
                "confirm_after must be ≤ 7d".into(),
            );
        }
        // feeds.md §1: warn_on names only warn bundles.
        for w in f.effective_warn_on() {
            match m.bundles.get(&w) {
                Some(b) if b.action == BundleAction::Warn => {}
                Some(b) => o.err(
                    e,
                    id,
                    Some("warn_on"),
                    "warn_on_not_warn",
                    format!(
                        "{w:?} is a {} bundle; warn_on names only warn bundles",
                        b.action.as_str()
                    ),
                ),
                None => o.err(
                    e,
                    id,
                    Some("warn_on"),
                    "unknown_bundle",
                    format!("no bundle {w:?}"),
                ),
            }
        }
    }
    // providers.md §2: two feeds of one provider can't name the same file.
    for ((p, file), ids) in files {
        if ids.len() > 1 {
            for id in &ids {
                o.err(
                    e,
                    id,
                    Some("file"),
                    "duplicate_file",
                    format!(
                        "feeds {} of provider {p:?} name the same file {file:?}",
                        ids.join(", ")
                    ),
                );
            }
        }
    }
}

fn bundle_rules(m: &Model, o: &mut Out) {
    let e = "bundle";
    for (id, b) in &m.bundles {
        check_id(o, e, id);
        check_name(o, e, id, &b.name);
        if b.max_shard_keys > 100_000_000 {
            o.err(
                e,
                id,
                Some("max_shard_keys"),
                "range",
                "max_shard_keys must be ≤ 100000000".into(),
            );
        }
        check_len(o, e, id, "feeds", &b.feeds);
        let mut seen = HashSet::new();
        for bf in &b.feeds {
            if !seen.insert(&bf.feed) {
                o.err(
                    e,
                    id,
                    Some("feeds"),
                    "duplicate",
                    format!("feed {:?} is listed twice", bf.feed),
                );
            }
            if !m.feeds.contains_key(&bf.feed) {
                o.err(
                    e,
                    id,
                    Some("feeds"),
                    "unknown_feed",
                    format!("no feed {:?}", bf.feed),
                );
            }
            if let Some(rt) = &bf.rule_types {
                if rt.is_empty() {
                    o.err(
                        e,
                        id,
                        Some("feeds.rule_types"),
                        "empty",
                        "rule_types can't be empty; leave it out for every type".into(),
                    );
                }
                if rt.iter().collect::<BTreeSet<_>>().len() != rt.len() {
                    o.err(
                        e,
                        id,
                        Some("feeds.rule_types"),
                        "duplicate",
                        format!("feed {:?}: a rule type is listed twice", bf.feed),
                    );
                }
                if b.action == BundleAction::Scope && rt.iter().any(|t| *t != RuleType::Dns) {
                    o.warn(
                        e,
                        id,
                        Some("feeds.rule_types"),
                        "scope_dns_only",
                        "only dns rules count in a scope bundle".into(),
                    );
                }
            }
            // bundles.md §1: tier and hot_max_mib only on block bundles.
            if bf.tier.is_some() && b.action != BundleAction::Block {
                o.err(
                    e,
                    id,
                    Some("feeds.tier"),
                    "tier_not_block",
                    "tier applies to block bundles only".into(),
                );
            }
        }
        if let Some(h) = b.hot_max_mib {
            if b.action != BundleAction::Block {
                o.err(
                    e,
                    id,
                    Some("hot_max_mib"),
                    "tier_not_block",
                    "hot_max_mib applies to block bundles only".into(),
                );
            }
            if h == 0 || h > 65_536 {
                o.err(
                    e,
                    id,
                    Some("hot_max_mib"),
                    "range",
                    "hot_max_mib must be 1–65536".into(),
                );
            }
        }
        if let Some(want) = system::system_bundle_action(id)
            && b.action != want
        {
            o.err(
                e,
                id,
                Some("action"),
                "system_action",
                format!("system bundle {id:?} stays a {} bundle", want.as_str()),
            );
        }
    }
}

fn provider_rules(m: &Model, o: &mut Out) {
    let e = "lookup_provider";
    for (id, p) in &m.lookup_providers {
        check_id(o, e, id);
        check_name(o, e, id, &p.name);
        let registry = crate::lookups::registry();
        let known = registry.get(&p.module).is_some();
        if !known {
            o.err(
                e,
                id,
                Some("module"),
                "unknown_module",
                format!(
                    "{:?} is not a lookup module ({})",
                    p.module,
                    registry.ids().collect::<Vec<_>>().join(", ")
                ),
            );
        }
        if !p.config.is_object() || p.config.to_string().len() > 64 * 1024 {
            o.err(
                e,
                id,
                Some("config"),
                "bad_config",
                "config must be a JSON object (≤ 64 KiB)".into(),
            );
        }
        provider_credential_rules(o, id, p);
        // The config against the module's `Config` (providers.md §1, §4): `${secret:name}`
        // references well formed, and the config parsing with placeholders in their place, so a
        // message never quotes a secret's value.
        if known
            && p.config.is_object()
            && let Err(err) = registry.validate_config(&p.module, &p.config)
        {
            o.err(
                e,
                id,
                Some("config"),
                "bad_config",
                crate::util::sanitize_for_message(&err.to_string(), 400),
            );
        }
        if !picket_api::ids::is_id64(&p.cache_generation) {
            o.err(
                e,
                id,
                Some("cache_generation"),
                "bad_generation",
                "cache_generation must be 16 hex characters".into(),
            );
        }
        let s = &p.settings;
        if !(1..=10_000).contains(&s.sync_timeout_ms) || !(1..=120_000).contains(&s.async_timeout_ms) {
            o.err(
                e,
                id,
                Some("timeouts"),
                "range",
                "sync_timeout_ms 1–10000, async_timeout_ms 1–120000".into(),
            );
        }
        if !(1..=50).contains(&s.async_max_attempts) {
            o.err(
                e,
                id,
                Some("async_max_attempts"),
                "range",
                "async_max_attempts must be 1–50".into(),
            );
        }
        let ttl_cap = 30 * 86_400;
        let c = &s.cache;
        if [c.block_ttl_s, c.clean_ttl_s, c.unknown_ttl_s, c.error_ttl_s]
            .iter()
            .any(|t| *t > ttl_cap)
        {
            o.err(
                e,
                id,
                Some("cache"),
                "ttl_cap",
                "verdict TTLs are capped at 30 days".into(),
            );
        }
        if c.max_mib == 0 || c.max_mib > 1024 {
            o.err(
                e,
                id,
                Some("cache.max_mib"),
                "range",
                "cache.max_mib must be 1–1024".into(),
            );
        }
        let l = &s.limits;
        if l.max_inflight == 0 || l.rps == 0 || l.burst == 0 || l.max_inflight > 10_000 {
            o.err(
                e,
                id,
                Some("limits"),
                "range",
                "limits must be above 0 (max_inflight ≤ 10000)".into(),
            );
        }
        let b = &s.breaker;
        if b.failures == 0 || b.open_s == 0 || b.half_open == 0 {
            o.err(
                e,
                id,
                Some("breaker"),
                "range",
                "breaker settings must be above 0".into(),
            );
        }
        let r = &s.recheck;
        if r.after.len() > 16
            || r.after
                .iter()
                .any(|d| d.as_secs() == 0 || d.as_secs() > 30 * 86_400)
            || r.jitter.as_secs() > 86_400
        {
            o.err(
                e,
                id,
                Some("recheck"),
                "range",
                "recheck: at most 16 delays of 1s–30d, jitter ≤ 1d".into(),
            );
        }
        for q in &s.scope.qtypes {
            if q.is_empty()
                || q.len() > 10
                || !q.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                o.err(
                    e,
                    id,
                    Some("scope.qtypes"),
                    "bad_qtype",
                    format!("{q:?} is not a query type (e.g. A, AAAA, HTTPS)"),
                );
            }
        }
        scope_bundles(m, o, e, id, "scope.include_bundles", &s.scope.include_bundles);
        scope_bundles(m, o, e, id, "scope.exclude_bundles", &s.scope.exclude_bundles);
        for name in p.secret_refs() {
            match m.secrets.get(&name) {
                Some(sm) if sm.has_value => {}
                _ => o.warn(
                    e,
                    id,
                    Some("config"),
                    "secret_missing",
                    format!("secret {name:?} has no value yet"),
                ),
            }
        }
    }
}

fn secret_rules(m: &Model, o: &mut Out) {
    for name in m.secrets.keys() {
        if !is_slug(name) {
            o.err(
                "secret",
                name,
                Some("name"),
                "bad_id",
                format!("{name:?} is not a valid secret name (1–64 of a-z, 0-9, - and _)"),
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Registrable domains

pub use crate::psl::registrable_domain;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains_follow_the_full_list() {
        // Suffixes outside any short built-in list (core.md §9 groups alerts by them).
        assert_eq!(
            registrable_domain("a.shop.com.ng").as_deref(),
            Some("shop.com.ng")
        );
        assert_eq!(registrable_domain("x.y.gov.in").as_deref(), Some("y.gov.in"));
        assert_eq!(
            registrable_domain("blog.blogspot.com").as_deref(),
            Some("blog.blogspot.com")
        );
        // A public suffix has no registrable domain.
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("com"), None);
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("dns.quad9.net").unwrap(), "quad9.net");
        assert_eq!(registrable_domain("dns10.quad9.net").unwrap(), "quad9.net");
        assert_eq!(registrable_domain("one.one.one.one").unwrap(), "one.one");
        assert_eq!(
            registrable_domain("cloudflare-dns.com").unwrap(),
            "cloudflare-dns.com"
        );
        assert_eq!(registrable_domain("dns.example.co.uk").unwrap(), "example.co.uk");
        assert_eq!(registrable_domain("dns.google").unwrap(), "dns.google");
    }

    /// `sanity.reject_drop_ratio` is null (off) or in (0, 1]: 0 would reject every run.
    #[test]
    fn reject_drop_ratio_range() {
        let mut m = Model::default();
        let issues = |m: &Model| {
            validate(m)
                .into_iter()
                .filter(|i| i.field.as_deref() == Some("sanity.reject_drop_ratio"))
                .count()
        };
        for (v, refused) in [
            (None, false),
            (Some(0.99), false),
            (Some(1.0), false),
            (Some(0.0), true),
            (Some(-0.5), true),
            (Some(1.5), true),
            (Some(f64::NAN), true),
        ] {
            let mut feed = FeedDef {
                id: "f".into(),
                name: "f".into(),
                ..Default::default()
            };
            feed.sanity.reject_drop_ratio = v;
            m.feeds.insert("f".into(), feed);
            assert_eq!(issues(&m), usize::from(refused), "{v:?}");
        }
    }

    /// `limits.max_rrset_records` is 0 (no limit) or up to picket-wire's section bound.
    #[test]
    fn max_rrset_records_range() {
        let mut m = Model::default();
        let issues = |m: &Model| {
            validate(m)
                .into_iter()
                .filter(|i| i.field.as_deref() == Some("limits") && i.message.contains("max_rrset_records"))
                .count()
        };
        for (v, refused) in [(0, false), (1, false), (256, false), (1024, false), (1025, true)] {
            let mut edge = EdgeDef {
                id: "e1".into(),
                name: "e1".into(),
                ..Default::default()
            };
            edge.settings.limits.max_rrset_records = v;
            m.edges.insert("e1".into(), edge);
            assert_eq!(issues(&m), usize::from(refused), "{v}");
        }
    }

    /// ER6 (edge.md §16 "Not an open resolver"): a listener on a wildcard address with no
    /// `interfaces` is refused at save time once it is assigned to an edge (the edge would refuse
    /// to open it); a specific address, `interfaces`, or no edge yet is fine.
    #[test]
    fn wildcard_listeners_on_edges_need_interfaces() {
        let mut m = Model::default();
        m.edges.insert(
            "e1".into(),
            EdgeDef {
                id: "e1".into(),
                name: "e1".into(),
                ..Default::default()
            },
        );
        let open = |m: &Model| {
            validate(m)
                .into_iter()
                .filter(|i| i.code == "open_wildcard")
                .map(|i| (i.id, i.severity, i.field))
                .collect::<Vec<_>>()
        };
        for (bind, interfaces, edges, refused) in [
            ("[::]:5335", vec![], vec!["e1"], true),
            ("0.0.0.0:53", vec![], vec!["e1"], true),
            ("[::ffff:0.0.0.0]:53", vec![], vec!["e1"], true),
            ("[::]:5335", vec!["br0"], vec!["e1"], false),
            ("192.168.1.1:53", vec![], vec!["e1"], false),
            ("[::]:5335", vec![], vec![], false),
        ] {
            m.listeners.insert(
                "l".into(),
                ListenerDef {
                    id: "l".into(),
                    name: "l".into(),
                    bind: bind.into(),
                    interfaces: interfaces.into_iter().map(String::from).collect(),
                    edges: edges.into_iter().map(String::from).collect(),
                    ..Default::default()
                },
            );
            let want = if refused {
                vec![("l".to_owned(), Severity::Error, Some("interfaces".to_owned()))]
            } else {
                vec![]
            };
            assert_eq!(open(&m), want, "{bind}");
        }
    }

    #[test]
    fn ids() {
        assert!(is_profile_id("kids"));
        assert!(is_profile_id("a-1"));
        assert!(!is_profile_id("kids-full"));
        assert!(!is_profile_id("Kids"));
        assert!(!is_profile_id("a_b"));
        assert!(!is_profile_id("-a"));
        assert!(is_slug("cf-dot"));
        assert!(!is_slug("Cf"));
        assert!(!is_slug(""));
        assert!(is_zone_name("_tcp.example"));
        assert!(is_zone_name("1.168.192.in-addr.arpa"));
    }
}
