//! The DNS data path's view of one config (edge.md §4–§6): profiles with their compiled
//! `allowed_sources` and forward zones, clients and devices, listeners, managed listener names,
//! limits and cache settings. Built off the hot path at each config activation and published in
//! the active state, so a query reads the config, its tables and `versions` from one load
//! (edge.md §11 Versions).
//!
//! Core is untrusted as the edge sees it (README §2): every number is clamped into a range, and a
//! malformed item (a listener bind, a range, a zone) is skipped and reported, never trusted.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use picket_api::duration::DurationStr;
use picket_api::edge_config::{
    CacheSettings, EdgeConfig, Limits, ListenerLimits, ListenerProto, ListenerTls, LookupAttachment,
    LookupMode, Profile,
};
use picket_wire::{NameRef, WireName};

use super::profiles::{Admission, Choice, Chooser, Clients, Device};
use super::zones::{ZoneMatch, ZoneTrie};

/// Bounds the edge applies to config numbers (the spec gives defaults; the ranges are ours).
pub mod bounds {
    pub const MAX_LISTENERS: usize = 64;
    pub const MAX_PROFILES: usize = 1024;
    pub const MAX_ZONES_PER_PROFILE: usize = 256;
    pub const MAX_ATTACHMENTS: usize = 32;
    pub const MAX_CONNECTIONS: u32 = 65_535;
    pub const IDLE_MS: (u32, u32) = (1_000, 600_000);
    pub const UDP_PAYLOAD: (u16, u16) = (512, 4_096);
    pub const CACHE_MIB: (u32, u32) = (1, 1_024);
    pub const STALE_TTL_S: (u32, u32) = (1, 3_600);
    pub const STALE_MAX_S: u32 = 7 * 86_400;
    pub const PREFETCH_HITS: (u32, u32) = (1, 1_000_000);
    pub const SYNC_LOOKUP_BUDGET_MS: u32 = 60_000;
    /// The longest block TTL the edge serves ([`picket_api::edge_config::MAX_BLOCK_TTL_S`]): 900 s
    /// − 5 s hold slack (`bypass::ring::HOLD_SLACK_S`) − 5 s reload margin
    /// (`bypass::RETRY_BEFORE_EXPIRY_S`), so a 15 min allow (the extension's shortest choice)
    /// made right after the block still reloads after the cached answer expired; shorter allows
    /// that wouldn't are refused (`bypass::earliest_end`, #50). Longer configured TTLs are
    /// lowered to this (#15, #34).
    pub const BLOCK_TTL_S: u32 = picket_api::edge_config::MAX_BLOCK_TTL_S;
    pub const CLIENT_QPS: (u32, u32) = (1, 100_000);
    pub const CLIENT_INFLIGHT: (u32, u32) = (1, 4_096);
    /// The longest `bypass.max_duration`: the longest timeout a firewall entry can hold
    /// (edge-firewall.md §4 clamps `timeout_s` to 2,147,483 s, ~24.8 days), so an IP allow never
    /// outlives its kernel entry. A policy bound (the spec names none).
    pub const BYPASS_MAX_DURATION_S: u64 = picket_api::helper::MAX_TIMEOUT_S as u64;
}

/// One sync lookup attachment of a profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncAttachment {
    pub provider: Arc<str>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

/// A profile as the pipeline runs it.
#[derive(Debug)]
pub struct ProfileRt {
    pub id: Arc<str>,
    pub cfg: Profile,
    pub admission: Admission,
    pub zones: ZoneTrie,
    /// The profile's upstream group.
    pub group: Arc<str>,
    pub sync: Vec<SyncAttachment>,
}

/// One listener from the config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerSpec {
    pub id: Arc<str>,
    pub proto: ListenerProto,
    /// `None` when the bind text isn't an `ip:port`.
    pub bind: Option<SocketAddr>,
    /// The bind text, matched exactly against `allowed_binds` (edge.md §2).
    pub bind_text: String,
    pub interfaces: Vec<String>,
    pub tls: Option<ListenerTls>,
    pub api: bool,
    /// The addresses its managed name answers with.
    pub ips: Vec<IpAddr>,
    pub limits: ListenerLimits,
    /// The managed TLS name, checked.
    pub managed: Option<WireName>,
}

impl ListenerSpec {
    /// True when the sockets of `self` can serve `other` without rebinding.
    pub fn same_sockets(&self, other: &ListenerSpec) -> bool {
        self.bind == other.bind && self.proto == other.proto
    }
}

/// A managed listener TLS name the edge answers itself (edge.md §4 "Special names").
#[derive(Clone, Debug)]
pub struct ManagedName {
    pub name: WireName,
    pub ips: Vec<IpAddr>,
    pub listener: Arc<str>,
}

/// The compiled config.
#[derive(Debug)]
pub struct DnsRuntime {
    pub config: Arc<EdgeConfig>,
    pub clients: Clients,
    pub profiles: HashMap<String, Arc<ProfileRt>>,
    pub default_profile: Option<Arc<str>>,
    pub listeners: Vec<Arc<ListenerSpec>>,
    pub managed: Vec<ManagedName>,
    pub limits: Limits,
    pub cache: CacheSettings,
    /// What was skipped while building (for the journal and `status`).
    pub warnings: Vec<String>,
}

fn clamp_u32(v: u32, (lo, hi): (u32, u32)) -> u32 {
    v.clamp(lo, hi)
}

/// The listener limits, clamped into range.
pub fn sane_limits(l: &ListenerLimits) -> ListenerLimits {
    let d = ListenerLimits::default();
    ListenerLimits {
        max_connections: if l.max_connections == 0 {
            d.max_connections
        } else {
            l.max_connections.min(bounds::MAX_CONNECTIONS)
        },
        idle_timeout_ms: clamp_u32(l.idle_timeout_ms, bounds::IDLE_MS),
        udp_payload: l.udp_payload.clamp(bounds::UDP_PAYLOAD.0, bounds::UDP_PAYLOAD.1),
    }
}

/// The cache settings, clamped into range.
pub fn sane_cache(c: &CacheSettings) -> CacheSettings {
    CacheSettings {
        size_mib: clamp_u32(c.size_mib, bounds::CACHE_MIB),
        stale_ttl_s: clamp_u32(c.stale_ttl_s, bounds::STALE_TTL_S),
        stale_max_s: c.stale_max_s.min(bounds::STALE_MAX_S),
        prefetch_min_hits: clamp_u32(c.prefetch_min_hits, bounds::PREFETCH_HITS),
    }
}

fn sane_profile(p: &Profile) -> Profile {
    let mut p = p.clone();
    p.sync_lookup_budget_ms = p.sync_lookup_budget_ms.min(bounds::SYNC_LOOKUP_BUDGET_MS);
    p.block_response.ttl = p.block_response.ttl.min(bounds::BLOCK_TTL_S);
    p.ttl.max = p.ttl.max.min(bounds::STALE_MAX_S);
    p.ttl.min = p.ttl.min.min(p.ttl.max);
    p.bypass.max_duration =
        DurationStr::secs(p.bypass.max_duration.as_secs().min(bounds::BYPASS_MAX_DURATION_S));
    p
}

/// A profile's effective `sync` attachments, as the runtime uses them: the first
/// [`bounds::MAX_ATTACHMENTS`] in `sync` mode.
pub fn sync_attachments(p: &Profile) -> impl Iterator<Item = &LookupAttachment> {
    p.lookup_providers
        .iter()
        .filter(|a| a.mode == LookupMode::Sync)
        .take(bounds::MAX_ATTACHMENTS)
}

/// The lookup providers some profile's effective `sync` attachment names: the only ones the edge
/// runs (#44). Every profile counts, used or not: a DoH path or DoT name can select any of them.
pub fn required_providers(cfg: &EdgeConfig) -> BTreeSet<&str> {
    cfg.profiles
        .values()
        .flat_map(sync_attachments)
        .map(|a| a.provider.as_str())
        .collect()
}

/// Drops the lookup providers and verdict sets that [`required_providers`] doesn't name (#44):
/// core sends only those already, and an extra one would cost a client, its RAM tier and its
/// verdict set for nothing. Returns the provider ids dropped (from either map), sorted.
pub fn keep_required_providers(cfg: &mut EdgeConfig) -> Vec<String> {
    let required: BTreeSet<String> = required_providers(cfg).into_iter().map(str::to_owned).collect();
    let mut dropped = BTreeSet::new();
    cfg.lookup_providers.retain(|id, _| {
        required.contains(id) || {
            dropped.insert(id.clone());
            false
        }
    });
    cfg.verdict_sets.retain(|id, _| {
        required.contains(id) || {
            dropped.insert(id.clone());
            false
        }
    });
    dropped.into_iter().collect()
}

impl DnsRuntime {
    /// Builds the runtime. Fails only when the config can't run at all.
    pub fn build(config: Arc<EdgeConfig>) -> Result<DnsRuntime, String> {
        let cfg = &*config;
        let mut warnings = vec![];
        let mut skipped = 0usize;
        let clients = Clients::build(&cfg.clients, &mut skipped);
        if skipped > 0 {
            warnings.push(format!("{skipped} malformed client MAC(s) or range(s) skipped"));
        }
        if cfg.profiles.len() > bounds::MAX_PROFILES {
            return Err(format!(
                "{} profiles (at most {})",
                cfg.profiles.len(),
                bounds::MAX_PROFILES
            ));
        }
        let mut profiles = HashMap::new();
        for (id, p) in &cfg.profiles {
            if p.bypass.max_duration.as_secs() > bounds::BYPASS_MAX_DURATION_S {
                warnings.push(format!(
                    "profile {id}: bypass.max_duration {} is over the longest firewall timeout; using {}",
                    p.bypass.max_duration,
                    DurationStr::secs(bounds::BYPASS_MAX_DURATION_S)
                ));
            }
            let mut sk = 0usize;
            let admission = clients.admission(&p.allowed_sources, &mut sk);
            if sk > 0 {
                warnings.push(format!(
                    "profile {id}: {sk} allowed_sources entr(ies) name no range, MAC or client"
                ));
            }
            let mut zones = ZoneTrie::default();
            for z in p.forward_zones.iter().take(bounds::MAX_ZONES_PER_PROFILE) {
                let Some(fz) = cfg.forward_zones.get(z) else {
                    warnings.push(format!("profile {id}: forward zone {z:?} isn't defined"));
                    continue;
                };
                let Ok(name) = WireName::from_text(&fz.zone) else {
                    warnings.push(format!("forward zone {z:?}: bad zone name"));
                    continue;
                };
                let labels: Vec<&[u8]> = name.as_name().labels().collect();
                zones.insert(
                    &labels,
                    ZoneMatch {
                        id: z.as_str().into(),
                        group: fz.group.as_str().into(),
                        fallback: fz.fallback,
                    },
                );
            }
            let sync = sync_attachments(p)
                .map(|a| SyncAttachment {
                    provider: a.provider.as_str().into(),
                    include: a.include_bundles.clone(),
                    exclude: a.exclude_bundles.clone(),
                })
                .collect();
            profiles.insert(
                id.clone(),
                Arc::new(ProfileRt {
                    id: id.as_str().into(),
                    cfg: sane_profile(p),
                    admission,
                    zones,
                    group: p.upstream.as_str().into(),
                    sync,
                }),
            );
        }
        for d in super::profiles::dangling_profiles(cfg) {
            warnings.push(format!("profile {d:?} is named but not defined"));
        }

        let mut listeners = vec![];
        let mut managed = vec![];
        for l in cfg.listeners.iter().take(bounds::MAX_LISTENERS) {
            let bind = l.bind.parse::<SocketAddr>().ok();
            if bind.is_none() {
                warnings.push(format!("listener {}: bind {:?} isn't ip:port", l.id, l.bind));
            }
            let managed_name = match l.tls.as_ref().and_then(|t| t.managed.as_deref()) {
                Some(n) => match WireName::from_text(n) {
                    Ok(w) if !w.as_name().is_root() => Some(w),
                    _ => {
                        warnings.push(format!("listener {}: bad managed TLS name", l.id));
                        None
                    }
                },
                None => None,
            };
            let mut ips: Vec<IpAddr> = l.ips.iter().map(|ip| ip.to_canonical()).take(32).collect();
            if ips.is_empty()
                && let Some(b) = bind
                && !b.ip().is_unspecified()
            {
                ips.push(b.ip().to_canonical());
            }
            let spec = ListenerSpec {
                id: l.id.as_str().into(),
                proto: l.proto,
                bind,
                bind_text: l.bind.clone(),
                interfaces: l.interfaces.iter().take(64).cloned().collect(),
                tls: l.tls.clone(),
                api: l.api,
                ips: ips.clone(),
                limits: sane_limits(&l.limits),
                managed: managed_name.clone(),
            };
            if let Some(n) = managed_name {
                managed.push(ManagedName {
                    name: n,
                    ips,
                    listener: spec.id.clone(),
                });
            }
            listeners.push(Arc::new(spec));
        }
        let limits = Limits {
            client_qps: clamp_u32(cfg.limits.client_qps, bounds::CLIENT_QPS),
            client_inflight: clamp_u32(cfg.limits.client_inflight, bounds::CLIENT_INFLIGHT),
            // Read by the upstream pool (`UpstreamPool::configure`), not the query path.
            max_rrset_records: cfg.limits.max_rrset_records,
        };
        Ok(DnsRuntime {
            clients,
            profiles,
            default_profile: cfg.default_profile.as_deref().map(Into::into),
            listeners,
            managed,
            limits,
            cache: sane_cache(&cfg.cache),
            warnings,
            config,
        })
    }

    pub fn profile(&self, id: &str) -> Option<&Arc<ProfileRt>> {
        self.profiles.get(id)
    }

    /// The device for a source address.
    pub fn device(&self, ip: IpAddr, mac: Option<crate::neighbours::Mac>) -> Device {
        self.clients.device(ip, mac)
    }

    /// Profile choice (edge.md §5).
    pub fn choose(&self, named: Option<&str>, d: &Device) -> Choice {
        let admits = |p: &str, d: &Device| {
            self.profiles
                .get(p)
                .map(|p| (p.admission.admits(d), Arc::clone(&p.id)))
        };
        Chooser {
            clients: &self.clients,
            admits: &admits,
            default_profile: self.default_profile.as_deref(),
        }
        .choose(named, d)
    }

    /// The managed name `name` is, or is a direct child of (`*.name`: a profile id under it).
    pub fn managed_answer(&self, name: NameRef<'_>) -> Option<&ManagedName> {
        self.managed.iter().find(|m| {
            let m_name = m.name.as_name();
            name == m_name || name.parent().is_some_and(|p| p == m_name)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_clamps_and_skips_bad_items() {
        let cfg: EdgeConfig = serde_json::from_value(serde_json::json!({
            "listeners": [
                {"id": "lan-dns", "proto": "dns", "bind": "[::]:5335", "limits": {"udp_payload": 100, "idle_timeout_ms": 0}},
                {"id": "lan-doh", "proto": "doh", "bind": "192.168.1.1:9853", "tls": {"managed": "DNS.home.arpa"}},
                {"id": "bad", "proto": "dns", "bind": "nowhere"}
            ],
            "default_profile": "kids",
            "profiles": {"kids": {"forward_zones": ["localdomain", "missing"]}},
            "forward_zones": {"localdomain": {"zone": "localdomain", "group": "local"}},
            "cache": {"size_mib": 0, "stale_ttl_s": 0}
        }))
        .unwrap();
        let rt = DnsRuntime::build(Arc::new(cfg)).unwrap();
        assert_eq!(rt.listeners.len(), 3);
        assert_eq!(rt.listeners[0].limits.udp_payload, 512);
        assert_eq!(rt.listeners[0].limits.idle_timeout_ms, 1_000);
        assert!(rt.listeners[2].bind.is_none());
        assert_eq!(rt.cache.size_mib, 1);
        assert_eq!(rt.managed.len(), 1);
        assert_eq!(rt.managed[0].ips, vec!["192.168.1.1".parse::<IpAddr>().unwrap()]);
        let n = WireName::from_text("strict.dns.home.arpa").unwrap();
        assert!(rt.managed_answer(n.as_name()).is_some(), "*.name");
        let n = WireName::from_text("a.strict.dns.home.arpa").unwrap();
        assert!(rt.managed_answer(n.as_name()).is_none());
        let kids = rt.profile("kids").unwrap();
        assert_eq!(kids.zones.len(), 1);
        assert!(rt.warnings.iter().any(|w| w.contains("missing")));
        assert!(rt.warnings.iter().any(|w| w.contains("nowhere")));
    }

    /// #44: the providers kept are those of the effective sync attachments, counted as the
    /// runtime counts them (the first 32 sync ones per profile), across every profile.
    #[test]
    fn only_effective_sync_attachments_keep_a_provider() {
        let mut first: Vec<serde_json::Value> = (0..bounds::MAX_ATTACHMENTS)
            .map(|i| serde_json::json!({"provider": format!("p{i}"), "mode": "sync"}))
            .collect();
        first.insert(1, serde_json::json!({"provider": "asy", "mode": "async"}));
        first.push(serde_json::json!({"provider": "over", "mode": "sync"}));
        let provider = serde_json::json!({"module": "dns", "config": {}, "cache_generation": "0123456789abcdef",
            "sync_timeout_ms": 300, "async_timeout_ms": 600, "fail_mode": "open",
            "scope": {"exclude_bundles": [], "qtypes": ["A"]}});
        let mut providers = serde_json::Map::new();
        let mut sets = serde_json::Map::new();
        for id in (0..bounds::MAX_ATTACHMENTS)
            .map(|i| format!("p{i}"))
            .chain(["asy", "over", "other", "unused"].map(String::from))
        {
            providers.insert(id.clone(), provider.clone());
            sets.insert(id, "0".repeat(64).into());
        }
        let mut cfg: EdgeConfig = serde_json::from_value(serde_json::json!({
            "edge": {"id": "e-01", "name": "t", "platform": "debian"},
            "profiles": {
                "a": {"upstream": "g", "lookup_providers": first, "block_response": {"type": "nxdomain", "ttl": 10}},
                "b": {"upstream": "g", "lookup_providers": [{"provider": "other", "mode": "sync"}],
                    "block_response": {"type": "nxdomain", "ttl": 10}},
            },
            "lookup_providers": providers,
            "verdict_sets": sets,
        }))
        .unwrap();
        let dropped = keep_required_providers(&mut cfg);
        assert_eq!(dropped, ["asy", "over", "unused"]);
        assert_eq!(cfg.lookup_providers.len(), bounds::MAX_ATTACHMENTS + 1);
        assert!(cfg.lookup_providers.contains_key("other") && cfg.lookup_providers.contains_key("p31"));
        assert_eq!(
            cfg.verdict_sets.keys().collect::<Vec<_>>(),
            cfg.lookup_providers.keys().collect::<Vec<_>>()
        );
        assert!(keep_required_providers(&mut cfg).is_empty(), "idempotent");
    }
}
