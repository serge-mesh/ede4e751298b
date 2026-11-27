//! Rendering an edge's config object (api.md §4, core.md §4–§5).
//!
//! [`render`] is a pure function of a model snapshot, the edge's id and the per-edge state
//! (bundle heads, verdict-set heads, the release offer inputs, requests, secret values, core's
//! addresses). Same inputs, same bytes: every map is ordered and the bytes are canonical JSON
//! (keys sorted, no whitespace), and the config's id is the BLAKE3 of those bytes.
//!
//! What goes in: the edge's settings and assigned listeners, `default_profile`, every client and
//! profile, and only what those profiles reference: their upstream groups (and the groups of the
//! forward zones they list) with those groups' upstreams, the forward zones they list, their
//! allow and block bundles (never trial bundles, which stay on core), the scope bundles their
//! `sync` attachments and those providers name, and the lookup providers they attach `sync`, with
//! the secrets those providers reference and their `cache_generation`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use picket_api::EdgeConfig;
use picket_api::edge_config::{
    EdgeInfo, Flush, InstallNow, Listener, LookupMode, LookupProviderConfig, MemoryConfig, ReleaseOffer,
    RevokedAllows, Upstream, UpstreamGroup,
};
use serde::{Deserialize, Serialize};

use crate::config::model::{EdgeDef, Model};
use crate::config::system::DNSSEC_PROFILE;

/// The release core offers (core.md §5): its own version, one tarball per architecture.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseInput {
    pub version: String,
    /// Architecture (`aarch64`, `x86_64`) → BLAKE3 of the tarball.
    pub tarballs: BTreeMap<String, String>,
}

/// What core knows about the release an edge runs (from its `hello`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRunning {
    pub version: Option<String>,
    pub arch: Option<String>,
}

/// The `install_now` request row (`edge_requests`): rendered only while its release is offered.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallRequest {
    pub id: String,
    pub version: String,
    pub blake3: String,
}

/// Requests carried as state in the config object (api.md §4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requests {
    pub flush_dns: Option<String>,
    /// Provider id → request id.
    pub flush_lookups: BTreeMap<String, String>,
    pub install_now: Option<InstallRequest>,
    pub revoked_allows: Option<RevokedAllows>,
}

/// Per-edge inputs besides the model.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EdgeState {
    /// Bundle id → head id core names for this edge.
    pub bundle_heads: BTreeMap<String, String>,
    /// Lookup provider id → verdict-set head id.
    pub verdict_set_heads: BTreeMap<String, String>,
    /// The bundled, verified release (None: no release offered, e.g. `release_invalid`).
    pub release: Option<ReleaseInput>,
    pub running: EdgeRunning,
    pub requests: Requests,
    /// Secret values by name (decrypted by the caller).
    pub secrets: BTreeMap<String, String>,
    /// Core's own addresses: the default `dnssec.source_ips`.
    pub core_ips: Vec<IpAddr>,
    /// The LAN CA's current root: edges replace managed certificates another root issued
    /// (`EdgeConfig.lanca_root`; core.md §11, edge.md §5).
    pub lanca_root: Option<String>,
}

/// A rendered config object.
#[derive(Clone, Debug, PartialEq)]
pub struct Rendered {
    pub config: EdgeConfig,
    /// The canonical bytes served as `configs/<fp>.json`.
    pub bytes: Vec<u8>,
    /// BLAKE3 of `bytes` (64 hex): the config's version.
    pub id: String,
    /// The body stored in `edge_configs`: the same document with every secret value blanked.
    pub stored_body: String,
    /// Bundles the profiles reference that have no head yet (not named in `bundles`).
    pub missing_heads: Vec<String>,
    /// Sync lookup providers without a verdict-set head yet (not named in `verdict_sets`).
    pub missing_verdict_sets: Vec<String>,
    /// Secrets the sync providers reference that have no value.
    pub missing_secrets: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("no edge {0:?}")]
    UnknownEdge(String),
    #[error("cannot serialise the config: {0}")]
    Serialize(String),
}

/// The bundles every edge's config object names heads for (the profiles' allow and block
/// bundles and the scope bundles their `sync` attachments and those providers name; never trial
/// or warn bundles). Every edge renders every profile, so the set is the same for each edge; the
/// compiler's budgets and compaction use it ([`crate::compiler::budget`]).
pub fn edge_bundles(model: &Model) -> BTreeSet<String> {
    let mut bundles: BTreeSet<String> = BTreeSet::new();
    let mut sync: BTreeSet<String> = BTreeSet::new();
    for p in model.profiles.values() {
        bundles.extend(p.edge.allow.iter().cloned());
        bundles.extend(p.edge.block.iter().cloned());
        for a in p.edge.lookups.iter().filter(|a| a.mode == LookupMode::Sync) {
            sync.insert(a.provider.clone());
            bundles.extend(a.include_bundles.iter().cloned());
            bundles.extend(a.exclude_bundles.iter().cloned());
        }
    }
    for pid in &sync {
        if let Some(lp) = model.lookup_providers.get(pid) {
            bundles.extend(lp.settings.scope.include_bundles.iter().cloned());
            bundles.extend(lp.settings.scope.exclude_bundles.iter().cloned());
        }
    }
    bundles.retain(|b| {
        model
            .bundles
            .get(b)
            .is_some_and(|d| d.action != crate::config::model::BundleAction::Warn)
    });
    bundles
}

/// Renders `edge_id`'s config object.
pub fn render(model: &Model, edge_id: &str, state: &EdgeState) -> Result<Rendered, RenderError> {
    let edge = model
        .edges
        .get(edge_id)
        .ok_or_else(|| RenderError::UnknownEdge(edge_id.into()))?;
    let settings = &model.settings;
    let mut cfg = EdgeConfig {
        edge: EdgeInfo {
            id: edge.id.clone(),
            name: edge.name.clone(),
            platform: edge.platform,
        },
        default_profile: settings.default_profile.clone(),
        lanca_root: state.lanca_root.clone(),
        ..EdgeConfig::default()
    };

    // Listeners assigned to this edge, by id.
    for l in model
        .listeners
        .values()
        .filter(|l| l.edges.iter().any(|e| e == edge_id))
    {
        let mut ips = l.ips.clone();
        if ips.is_empty()
            && let Ok(sa) = l.bind.parse::<SocketAddr>()
            && !sa.ip().is_unspecified()
        {
            ips.push(sa.ip()); // filled from a specific bind (api.md §4)
        }
        cfg.listeners.push(Listener {
            id: l.id.clone(),
            proto: l.proto,
            bind: l.bind.clone(),
            interfaces: l.interfaces.clone(),
            tls: l.tls.clone(),
            api: l.api,
            ips,
            limits: l.limits.clone(),
        });
    }

    // Clients in list order.
    for c in &model.clients {
        cfg.clients.push(picket_api::edge_config::Client {
            name: c.name.clone(),
            macs: c.macs.clone(),
            source_ips: c.source_ips.clone(),
            profile: c.profile.clone(),
            tags: c.tags.clone(),
        });
    }

    // Profiles: the edge's fields only (trial bundles and alert settings stay on core).
    let mut groups: BTreeSet<String> = BTreeSet::new();
    let mut zones: BTreeSet<String> = BTreeSet::new();
    let mut bundles: BTreeSet<String> = BTreeSet::new();
    let mut sync: BTreeSet<String> = BTreeSet::new();
    for (id, p) in &model.profiles {
        let mut ep = p.edge.clone();
        if id == DNSSEC_PROFILE {
            // core.md §8: only core's (source) addresses may name it.
            ep.allowed_sources = dnssec_sources(model, state);
        }
        groups.insert(ep.upstream.clone());
        zones.extend(ep.forward_zones.iter().cloned());
        bundles.extend(ep.allow.iter().cloned());
        bundles.extend(ep.block.iter().cloned());
        for a in ep.lookups.iter().filter(|a| a.mode == LookupMode::Sync) {
            sync.insert(a.provider.clone());
            bundles.extend(a.include_bundles.iter().cloned());
            bundles.extend(a.exclude_bundles.iter().cloned());
        }
        cfg.profiles.insert(id.clone(), ep);
    }

    for z in &zones {
        if let Some(def) = model.forward_zones.get(z) {
            groups.insert(def.group.clone());
            cfg.forward_zones.insert(
                z.clone(),
                picket_api::edge_config::ForwardZone {
                    zone: def.zone.clone(),
                    group: def.group.clone(),
                    fallback: def.fallback,
                },
            );
        }
    }
    for g in &groups {
        if let Some(def) = model.upstream_groups.get(g) {
            cfg.upstream_groups.insert(
                g.clone(),
                UpstreamGroup {
                    upstreams: def.upstreams.clone(),
                    strategy: def.strategy,
                    optimistic: def.optimistic,
                },
            );
            for u in &def.upstreams {
                if let Some(ud) = model.upstreams.get(u) {
                    // `operator` is core-only and isn't rendered (edge.md §6).
                    cfg.upstreams.insert(
                        u.clone(),
                        Upstream {
                            protocol: ud.protocol,
                            ip: ud.ip,
                            port: ud.port,
                            tls_host: ud.tls_host.clone(),
                            path: ud.path.clone(),
                            trust_store: ud.trust_store.clone(),
                        },
                    );
                }
            }
        }
    }

    // Sync lookup providers, their scope bundles and secrets.
    let mut secret_names: BTreeSet<String> = BTreeSet::new();
    let mut missing_verdict_sets = Vec::new();
    for pid in &sync {
        if let Some(lp) = model.lookup_providers.get(pid) {
            bundles.extend(lp.settings.scope.include_bundles.iter().cloned());
            bundles.extend(lp.settings.scope.exclude_bundles.iter().cloned());
            secret_names.extend(lp.secret_refs());
            cfg.lookup_providers.insert(
                pid.clone(),
                LookupProviderConfig {
                    module: lp.module.clone(),
                    config: lp.config.clone(),
                    cache_generation: lp.cache_generation.clone(),
                    settings: lp.settings.clone(),
                },
            );
            match state.verdict_set_heads.get(pid) {
                Some(h) => {
                    cfg.verdict_sets.insert(pid.clone(), h.clone());
                }
                None => missing_verdict_sets.push(pid.clone()),
            }
        }
    }
    let mut missing_secrets = Vec::new();
    for n in &secret_names {
        match state.secrets.get(n) {
            Some(v) => {
                cfg.secrets.insert(n.clone(), v.clone());
            }
            None => missing_secrets.push(n.clone()),
        }
    }

    // Bundle heads: allow, block and scope bundles only; warn bundles never reach an edge.
    let mut missing_heads = Vec::new();
    for b in &bundles {
        let Some(def) = model.bundles.get(b) else { continue };
        if def.action == crate::config::model::BundleAction::Warn {
            continue;
        }
        match state.bundle_heads.get(b) {
            Some(h) => {
                cfg.bundles.insert(b.clone(), h.clone());
            }
            None => missing_heads.push(b.clone()),
        }
    }

    let s = &edge.settings;
    cfg.cache = s.cache;
    cfg.firewall = s.firewall.clone();
    cfg.unifi = s.unifi.clone();
    cfg.logging = s.logging;
    // The edge's spool keeps records for the log retention window (storage.md §4), rounded up
    // to whole hours so it never drops a record core would still accept.
    cfg.logging.retention_h = u32::try_from(settings.retention.query_logs.as_secs().div_ceil(3600))
        .unwrap_or(72)
        .max(1);
    cfg.limits = s.limits;
    cfg.memory = MemoryConfig {
        bundle_budget_mib: s.bundle_budget_mib,
        overlay_budget_mib: s.overlay_budget(edge.platform),
    };
    cfg.release = release_offer(edge, state);
    cfg.flush = Flush {
        dns: state.requests.flush_dns.clone(),
        lookups: state
            .requests
            .flush_lookups
            .iter()
            .filter(|(p, _)| sync.contains(*p))
            .map(|(p, id)| (p.clone(), id.clone()))
            .collect(),
    };
    cfg.revoked_allows = state
        .requests
        .revoked_allows
        .clone()
        .filter(|r| !r.allows.is_empty());

    let value = serde_json::to_value(&cfg).map_err(|e| RenderError::Serialize(e.to_string()))?;
    let bytes = picket_api::ids::canonical_json(&value);
    let id = picket_api::ids::object_id(&bytes);
    let mut stored = value;
    if let Some(serde_json::Value::Object(m)) = stored.get_mut("secrets") {
        for v in m.values_mut() {
            *v = serde_json::Value::String(String::new());
        }
    }
    // Saves refuse credentials written into a provider config instead of a `${secret:…}`
    // reference; should one be there anyway (an older release's save), it never reaches the
    // stored copy or the preview either (README §2 Secrets). Replay needs no credentials.
    if let Some(serde_json::Value::Object(m)) = stored.get_mut("lookup_providers") {
        for p in m.values_mut() {
            if let Some(c) = p.get_mut("config") {
                *c = crate::config::credentials::mask(c);
            }
        }
    }
    let stored_body = String::from_utf8(picket_api::ids::canonical_json(&stored)).unwrap_or_default();
    Ok(Rendered {
        config: cfg,
        bytes,
        id,
        stored_body,
        missing_heads,
        missing_verdict_sets,
        missing_secrets,
    })
}

/// `dnssec.source_ips`, or core's own addresses as host routes (README §3).
fn dnssec_sources(model: &Model, state: &EdgeState) -> Vec<String> {
    match &model.settings.dnssec.source_ips {
        Some(list) => list.clone(),
        None => {
            let mut v: Vec<String> = state
                .core_ips
                .iter()
                .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
                .map(|ip| ipnet::IpNet::from(crate::net::canonical_ip(*ip)).to_string())
                .collect();
            v.sort();
            v.dedup();
            v
        }
    }
}

/// The release offer (core.md §5): core's version for the edge's architecture, with
/// `rollback` when the edge runs a newer one; `install_now` only while it names this exact
/// release.
fn release_offer(edge: &EdgeDef, state: &EdgeState) -> Option<ReleaseOffer> {
    let rel = state.release.as_ref()?;
    let arch = state.running.arch.as_deref()?;
    let blake3 = rel.tarballs.get(arch)?.clone();
    let rollback = state
        .running
        .version
        .as_deref()
        .and_then(|v| picket_api::update::compare_versions(v, &rel.version))
        .is_some_and(|o| o == std::cmp::Ordering::Greater);
    let install_now = state
        .requests
        .install_now
        .as_ref()
        .filter(|r| r.version == rel.version && r.blake3 == blake3)
        .map(|r| InstallNow {
            id: r.id.clone(),
            version: r.version.clone(),
            blake3: r.blake3.clone(),
        });
    Some(ReleaseOffer {
        auto_update: edge.settings.auto_update,
        version: rel.version.clone(),
        blake3,
        rollback,
        install_now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::*;
    use crate::config::system;
    use picket_api::edge_config::{FwInterface, FwMode, ListenerProto, LookupAttachment, Platform, Redirect};

    fn model() -> Model {
        let mut m = Model::default();
        for f in [
            "manual-allow",
            "manual-block",
            "manual-warn",
            "lookup-exclude",
            "canaries",
            "adult-feed",
            "trial-feed",
        ] {
            m.feeds.insert(
                f.into(),
                FeedDef {
                    id: f.into(),
                    name: f.into(),
                    ..Default::default()
                },
            );
        }
        let bundle = |id: &str, action, feed: &str| BundleDef {
            id: id.into(),
            name: id.into(),
            action,
            feeds: vec![BundleFeed {
                feed: feed.into(),
                rule_types: None,
                tier: None,
            }],
            ..Default::default()
        };
        m.bundles.insert(
            "allow-common".into(),
            bundle("allow-common", BundleAction::Allow, "manual-allow"),
        );
        m.bundles.insert(
            "block-common".into(),
            bundle("block-common", BundleAction::Block, "manual-block"),
        );
        m.bundles.insert(
            "warn-common".into(),
            bundle("warn-common", BundleAction::Warn, "manual-warn"),
        );
        m.bundles.insert(
            "lookup-exclude".into(),
            bundle("lookup-exclude", BundleAction::Scope, "lookup-exclude"),
        );
        m.bundles
            .insert("adult".into(), bundle("adult", BundleAction::Block, "adult-feed"));
        m.bundles
            .insert("trial".into(), bundle("trial", BundleAction::Block, "trial-feed"));
        m.bundles.insert(
            "unused".into(),
            bundle("unused", BundleAction::Block, "adult-feed"),
        );
        for u in system::cloudflare_upstreams() {
            m.upstreams.insert(u.id.clone(), u);
        }
        m.upstreams.insert(
            "dnsmasq".into(),
            UpstreamDef {
                id: "dnsmasq".into(),
                name: "dnsmasq".into(),
                protocol: picket_api::edge_config::UpstreamProtocol::Udp,
                ip: "127.0.0.1".parse().unwrap(),
                port: 53,
                ..Default::default()
            },
        );
        m.upstreams.insert(
            "unused-up".into(),
            UpstreamDef {
                id: "unused-up".into(),
                name: "x".into(),
                ip: "9.9.9.9".parse().unwrap(),
                tls_host: Some("dns.quad9.net".into()),
                operator: Some("quad9".into()),
                ..Default::default()
            },
        );
        m.upstream_groups
            .insert("cloudflare".into(), system::cloudflare_group());
        m.upstream_groups.insert(
            "local".into(),
            UpstreamGroupDef {
                id: "local".into(),
                name: "local".into(),
                upstreams: vec!["dnsmasq".into()],
                optimistic: false,
                ..Default::default()
            },
        );
        m.upstream_groups.insert(
            "quad9".into(),
            UpstreamGroupDef {
                id: "quad9".into(),
                name: "q".into(),
                upstreams: vec!["unused-up".into()],
                ..Default::default()
            },
        );
        m.forward_zones.insert(
            "localdomain".into(),
            ForwardZoneDef {
                id: "localdomain".into(),
                zone: "localdomain".into(),
                group: "local".into(),
                ..Default::default()
            },
        );
        m.forward_zones.insert(
            "unlisted".into(),
            ForwardZoneDef {
                id: "unlisted".into(),
                zone: "corp".into(),
                group: "local".into(),
                ..Default::default()
            },
        );
        m.lookup_providers.insert(
            "am-rt".into(),
            LookupProviderDef {
                id: "am-rt".into(),
                name: "am".into(),
                module: "http_json".into(),
                config: serde_json::json!({"headers": {"Authorization": "Bearer ${secret:am_rt}"}}),
                cache_generation: "3f9a0c17d2e84b65".into(),
                ..Default::default()
            },
        );
        m.lookup_providers.insert(
            "async-only".into(),
            LookupProviderDef {
                id: "async-only".into(),
                name: "a".into(),
                module: "http_json".into(),
                config: serde_json::json!({"k": "${secret:async_key}"}),
                cache_generation: "0000000000000001".into(),
                ..Default::default()
            },
        );
        let mut adults = ProfileDef {
            id: "adults".into(),
            name: "Adults".into(),
            ..Default::default()
        };
        adults.edge.allow = vec!["allow-common".into()];
        adults.edge.block = vec!["block-common".into()];
        adults.edge.forward_zones = vec!["localdomain".into()];
        adults.edge.lookups = vec![
            LookupAttachment {
                provider: "am-rt".into(),
                mode: LookupMode::Sync,
                include_bundles: vec![],
                exclude_bundles: vec!["lookup-exclude".into()],
            },
            LookupAttachment {
                provider: "async-only".into(),
                mode: LookupMode::Async,
                ..Default::default()
            },
        ];
        adults.trial_bundles = vec!["trial".into()];
        m.profiles.insert("adults".into(), adults);
        let mut kids = ProfileDef {
            id: "kids".into(),
            name: "Kids".into(),
            ..Default::default()
        };
        kids.edge.block = vec!["block-common".into(), "adult".into()];
        m.profiles.insert("kids".into(), kids);
        m.profiles
            .insert(system::DNSSEC_PROFILE.into(), system::dnssec_profile());
        m.settings.default_profile = Some("kids".into());
        m.clients.push(ClientDef {
            name: "office-pc".into(),
            position: Some(0),
            macs: vec!["aa:bb:cc:dd:ee:01".into()],
            profile: Some("adults".into()),
            ..Default::default()
        });
        m.clients.push(ClientDef {
            name: "kids-net".into(),
            position: Some(1),
            source_ips: vec!["192.168.1.128/25".into()],
            profile: Some("kids".into()),
            ..Default::default()
        });
        let mut edge = EdgeDef {
            id: "e-01".into(),
            name: "ucg".into(),
            key: "SHA256:x".into(),
            platform: Platform::Unifi,
            ..Default::default()
        };
        edge.settings.firewall.interfaces = vec![FwInterface {
            name: "br0".into(),
            mode: FwMode::Enforce,
        }];
        edge.settings.unifi.redirect = Some(Redirect {
            interfaces: vec!["br0".into()],
            ipv6: true,
        });
        m.edges.insert("e-01".into(), edge);
        m.edges.insert(
            "e-02".into(),
            EdgeDef {
                id: "e-02".into(),
                name: "deb".into(),
                key: "SHA256:y".into(),
                platform: Platform::Debian,
                ..Default::default()
            },
        );
        m.listeners.insert(
            "lan-dns".into(),
            ListenerDef {
                id: "lan-dns".into(),
                name: "dns".into(),
                proto: ListenerProto::Dns,
                bind: "[::]:5335".into(),
                interfaces: vec!["br0".into()],
                edges: vec!["e-01".into()],
                ..Default::default()
            },
        );
        m.listeners.insert(
            "lan-doh".into(),
            ListenerDef {
                id: "lan-doh".into(),
                name: "doh".into(),
                proto: ListenerProto::Doh,
                bind: "192.168.1.1:9853".into(),
                tls: Some(picket_api::edge_config::ListenerTls {
                    managed: Some("dns.home.arpa".into()),
                    ..Default::default()
                }),
                api: true,
                edges: vec!["e-01".into()],
                ..Default::default()
            },
        );
        m.listeners.insert(
            "other".into(),
            ListenerDef {
                id: "other".into(),
                name: "o".into(),
                proto: ListenerProto::Dns,
                bind: "10.0.0.1:53".into(),
                edges: vec!["e-02".into()],
                ..Default::default()
            },
        );
        m
    }

    fn state() -> EdgeState {
        let mut s = EdgeState::default();
        for b in [
            "allow-common",
            "block-common",
            "adult",
            "lookup-exclude",
            "trial",
            "warn-common",
            "unused",
        ] {
            s.bundle_heads
                .insert(b.into(), picket_api::ids::object_id(b.as_bytes()));
        }
        s.verdict_set_heads.insert("am-rt".into(), "5d0e".repeat(16));
        s.secrets.insert("am_rt".into(), "token-value".into());
        s.secrets.insert("async_key".into(), "must-not-leak".into());
        s.core_ips = vec!["192.168.1.20".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        s.release = Some(ReleaseInput {
            version: "1.4.0".into(),
            tarballs: [("aarch64".to_string(), "ab".repeat(32))].into(),
        });
        s.running = EdgeRunning {
            version: Some("1.3.0".into()),
            arch: Some("aarch64".into()),
        };
        s.lanca_root = Some(format!("SHA256:{}", "ab".repeat(32)));
        s
    }

    #[test]
    fn deterministic() {
        let (m, s) = (model(), state());
        let a = render(&m, "e-01", &s).unwrap();
        let b = render(&m.clone(), "e-01", &s.clone()).unwrap();
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.id, b.id);
        assert_eq!(a.id, picket_api::ids::object_id(&a.bytes));
        // The bytes parse back to the same config.
        let back: EdgeConfig = serde_json::from_slice(&a.bytes).unwrap();
        assert_eq!(back, a.config);
        // A change in a core-only field (trial bundles) changes nothing.
        let mut m2 = m.clone();
        m2.profiles.get_mut("adults").unwrap().trial_bundles.clear();
        m2.profiles.get_mut("adults").unwrap().alert_categories = vec![];
        assert_eq!(render(&m2, "e-01", &s).unwrap().id, a.id);
        // A change in an edge field does.
        let mut m3 = m.clone();
        m3.profiles.get_mut("kids").unwrap().edge.ttl.max = 600;
        assert_ne!(render(&m3, "e-01", &s).unwrap().id, a.id);
    }

    #[test]
    fn a_credential_in_a_provider_config_never_reaches_the_stored_copy() {
        // README §2 Secrets: saves refuse literal credentials; one left by an older release
        // still goes to the edge (it needs it) but not into edge_configs or the preview.
        let mut m = model();
        m.lookup_providers.get_mut("am-rt").unwrap().config = serde_json::json!({
            "url": "https://api.example/{domain}?apikey=literal-in-url",
            "headers": {"Authorization": "Bearer literal-bearer", "X-Ref": "${secret:am_rt}"}
        });
        let r = render(&m, "e-01", &state()).unwrap();
        let bytes = String::from_utf8(r.bytes.clone()).unwrap();
        assert!(bytes.contains("literal-bearer"));
        assert!(!r.stored_body.contains("literal-bearer"), "{}", r.stored_body);
        assert!(!r.stored_body.contains("literal-in-url"), "{}", r.stored_body);
        assert!(r.stored_body.contains("${secret:am_rt}"));
    }

    #[test]
    fn contents() {
        let r = render(&model(), "e-01", &state()).unwrap();
        let c = &r.config;
        assert_eq!(c.edge.id, "e-01");
        assert_eq!(c.default_profile.as_deref(), Some("kids"));
        // The LAN CA's current root, for the edge's managed certificates (core.md §11).
        assert_eq!(c.lanca_root, state().lanca_root);
        assert_eq!(
            c.listeners.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
            vec!["lan-dns", "lan-doh"]
        );
        // ips filled from a specific bind only.
        assert_eq!(c.listeners[1].ips, vec!["192.168.1.1".parse::<IpAddr>().unwrap()]);
        assert!(c.listeners[0].ips.is_empty());
        assert_eq!(
            c.clients.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            vec!["office-pc", "kids-net"]
        );
        // Bundles: allow, block, scope; never trial, warn or unreferenced ones.
        let b: Vec<&str> = c.bundles.keys().map(String::as_str).collect();
        assert_eq!(b, vec!["adult", "allow-common", "block-common", "lookup-exclude"]);
        // Groups and upstreams referenced only.
        assert_eq!(
            c.upstream_groups.keys().collect::<Vec<_>>(),
            vec!["cloudflare", "local"]
        );
        assert!(c.upstreams.contains_key("dnsmasq") && c.upstreams.contains_key("cf-doh"));
        assert!(!c.upstreams.contains_key("unused-up"));
        assert_eq!(c.forward_zones.keys().collect::<Vec<_>>(), vec!["localdomain"]);
        // Sync providers only, with their secrets and cache generation.
        assert_eq!(c.lookup_providers.keys().collect::<Vec<_>>(), vec!["am-rt"]);
        assert_eq!(c.lookup_providers["am-rt"].cache_generation, "3f9a0c17d2e84b65");
        assert_eq!(c.secrets.get("am_rt").map(String::as_str), Some("token-value"));
        assert!(!c.secrets.contains_key("async_key"));
        assert_eq!(c.verdict_sets.keys().collect::<Vec<_>>(), vec!["am-rt"]);
        // dnssec-validator admits core's (non-loopback) addresses.
        assert_eq!(
            c.profiles[system::DNSSEC_PROFILE].allowed_sources,
            vec!["192.168.1.20/32"]
        );
        // UniFi edges default to a 16 MiB overlay budget.
        assert_eq!(c.memory.overlay_budget_mib, 16);
        assert_eq!(c.logging.retention_h, 72);
        let rel = c.release.as_ref().unwrap();
        assert_eq!(
            (rel.version.as_str(), rel.rollback, rel.auto_update),
            ("1.4.0", false, true)
        );
        // Secrets never reach the stored body.
        assert!(!r.stored_body.contains("token-value"));
        assert!(r.stored_body.contains("am_rt"));
        assert!(r.missing_heads.is_empty() && r.missing_secrets.is_empty());
        // The other edge: its own listener; Debian overlay default 4 MiB; no release (no arch).
        let mut s2 = state();
        s2.running = EdgeRunning::default();
        let r2 = render(&model(), "e-02", &s2).unwrap();
        assert_eq!(r2.config.listeners.len(), 1);
        assert_eq!(r2.config.memory.overlay_budget_mib, 4);
        assert!(r2.config.release.is_none());
        assert!(render(&model(), "nope", &s2).is_err());
    }

    #[test]
    fn dnssec_sources_setting() {
        let mut m = model();
        m.settings.dnssec.source_ips = Some(vec!["10.9.9.9/32".into()]);
        let r = render(&m, "e-01", &state()).unwrap();
        assert_eq!(
            r.config.profiles[system::DNSSEC_PROFILE].allowed_sources,
            vec!["10.9.9.9/32"]
        );
    }

    #[test]
    fn release_and_requests() {
        let m = model();
        let mut s = state();
        // An edge on a newer release gets a rollback offer.
        s.running.version = Some("1.5.0".into());
        let r = render(&m, "e-01", &s).unwrap();
        assert!(r.config.release.as_ref().unwrap().rollback);
        // install_now only while it names the offered release.
        s.requests.install_now = Some(InstallRequest {
            id: "0123456789abcdef".into(),
            version: "1.4.0".into(),
            blake3: "ab".repeat(32),
        });
        let r = render(&m, "e-01", &s).unwrap();
        assert_eq!(
            r.config
                .release
                .as_ref()
                .unwrap()
                .install_now
                .as_ref()
                .unwrap()
                .id,
            "0123456789abcdef"
        );
        s.requests.install_now.as_mut().unwrap().version = "1.3.9".into();
        assert!(
            render(&m, "e-01", &s)
                .unwrap()
                .config
                .release
                .unwrap()
                .install_now
                .is_none()
        );
        // Flushes and the revoke list.
        s.requests.flush_dns = Some("e2a6b0c94f1d7358".into());
        s.requests
            .flush_lookups
            .insert("am-rt".into(), "07b3d9e15a4c62f8".into());
        s.requests
            .flush_lookups
            .insert("async-only".into(), "1111111111111111".into());
        s.requests.revoked_allows = Some(RevokedAllows {
            id: "9c41e7a02b5d83f6".into(),
            allows: vec!["a-19".into()],
        });
        let c = render(&m, "e-01", &s).unwrap().config;
        assert_eq!(c.flush.dns.as_deref(), Some("e2a6b0c94f1d7358"));
        assert_eq!(c.flush.lookups.keys().collect::<Vec<_>>(), vec!["am-rt"]);
        assert_eq!(c.revoked_allows.unwrap().allows, vec!["a-19"]);
        // No release offered at all.
        s.release = None;
        assert!(render(&m, "e-01", &s).unwrap().config.release.is_none());
    }

    #[test]
    fn spool_retention_rounds_up_and_missing_verdict_sets_are_reported() {
        let mut m = model();
        // The edge keeps spooled records at least as long as core accepts them.
        m.settings.retention.query_logs = picket_api::DurationStr::minutes(90);
        let mut s = state();
        s.verdict_set_heads.clear();
        let r = render(&m, "e-01", &s).unwrap();
        assert_eq!(r.config.logging.retention_h, 2);
        assert_eq!(r.missing_verdict_sets, vec!["am-rt"]);
        assert!(r.config.verdict_sets.is_empty());
    }

    #[test]
    fn missing_heads_and_secrets_reported() {
        let mut s = state();
        s.bundle_heads.remove("adult");
        s.secrets.clear();
        let r = render(&model(), "e-01", &s).unwrap();
        assert_eq!(r.missing_heads, vec!["adult"]);
        assert_eq!(r.missing_secrets, vec!["am_rt"]);
        assert!(!r.config.bundles.contains_key("adult"));
    }
}
