//! The data path's foundation hooks (edge.md §13): a config-only activator (bundles and verdict
//! sets go through [`crate::bundles::EdgeActivator`], which `service::start` installs), the
//! request handler (`flush.dns`, `flush.lookups`, `revoked_allows`), the `listeners` firmware
//! self-check, and the `versions` block.

use std::sync::Arc;

use async_trait::async_trait;

use picket_api::edge_config::RevokedAllows;
use picket_api::logs::Versions;

use super::runtime::DnsRuntime;
use crate::edge::{ActiveState, Edge};
use crate::hooks::{Activation, ActivationTarget, Activator, RequestHandler, SelfCheck};

/// The `versions` block of a config and the active bundles (api.md §5).
pub fn versions(config_version: &str, bundles: &super::filter::ActiveBundles) -> Versions {
    Versions {
        config: picket_api::ids::short_id(config_version).to_owned(),
        bundles: bundles
            .bundles
            .iter()
            .map(|(id, b)| (id.to_string(), b.versions()))
            .collect(),
        ..Default::default()
    }
}

/// Makes a config-only object live for the data path: builds its [`DnsRuntime`] off the hot path,
/// updates the upstream pool, cache and lookup clients in place, swaps the active state with a new
/// `versions` block, and wakes the listener manager to rebind. Objects naming bundles or verdict
/// sets need [`crate::bundles::EdgeActivator`] (tests use this one with bundles set by hand).
pub struct DnsActivator;

#[async_trait]
impl Activator for DnsActivator {
    async fn activate(&self, edge: &Edge, t: &ActivationTarget) -> Activation {
        if !t.config.bundles.is_empty() || !t.config.verdict_sets.is_empty() {
            // A config goes live only once everything it names is active (edge.md §13).
            return Activation::Retry {
                stage: "load".into(),
                reason: "this activator doesn't activate bundles or verdict sets".into(),
            };
        }
        let config = Arc::clone(&t.config);
        let rt = match tokio::task::spawn_blocking(move || DnsRuntime::build(config)).await {
            Ok(Ok(rt)) => rt,
            Ok(Err(reason)) => {
                return Activation::Failed {
                    stage: "build".into(),
                    reason,
                };
            }
            Err(e) => {
                return Activation::Failed {
                    stage: "build".into(),
                    reason: crate::diag::cap(e),
                };
            }
        };
        for w in &rt.warnings {
            tracing::warn!("config {}: {w}", picket_api::ids::short_id(&t.config_version));
        }
        for w in edge.dns.pool.configure(&t.config) {
            tracing::warn!("config {}: {w}", picket_api::ids::short_id(&t.config_version));
        }
        edge.dns.resolver.cache.configure(rt.cache);
        edge.dns.lookups.configure(&t.config);
        let prev = edge.active();
        let bundles = Arc::clone(&prev.bundles);
        let v = versions(&t.config_version, &bundles);
        edge.active.store(Arc::new(ActiveState {
            object_id: Some(t.object_id.clone()),
            config_version: Some(t.config_version.clone()),
            config_hash: Some(t.config_hash.clone()),
            config: Some(Arc::clone(&t.config)),
            versions: Some(Arc::new(v)),
            bundles,
            dns: Some(Arc::new(rt)),
        }));
        edge.log_control.set_config(t.config.logging);
        edge.dns.listeners.wake.notify_one();
        Activation::Active
    }
}

/// Requests from the config object (api.md §4) and `picket-edge flush-cache`.
pub struct DnsRequests;

#[async_trait]
impl RequestHandler for DnsRequests {
    async fn flush_dns(&self, edge: &Edge) -> anyhow::Result<()> {
        edge.dns.resolver.cache.flush();
        Ok(())
    }
    async fn flush_lookups(&self, edge: &Edge, provider: &str) -> anyhow::Result<()> {
        edge.dns.lookups.flush(provider);
        Ok(())
    }
    async fn flush_all_lookups(&self, edge: &Edge) -> anyhow::Result<()> {
        edge.dns.lookups.flush_all();
        Ok(())
    }
    async fn revoke_allows(&self, edge: &Edge, list: &RevokedAllows) -> anyhow::Result<()> {
        // Each held allow ends (`via: core`), IP allows' set entries at once (edge.md §12).
        let ids: Vec<String> = list
            .allows
            .iter()
            .take(crate::allows::MAX_ALLOWS)
            .cloned()
            .collect();
        let b = Arc::clone(&edge.bypass);
        b.revoke(edge, &ids, "core").await.map(|_| ())
    }
}

/// The `listeners` self-check after a firmware change (edge-unifi.md §1): `ready_version` is set
/// this run and every listener `allowed_binds` allows is bound.
pub struct ListenersCheck;

#[async_trait]
impl SelfCheck for ListenersCheck {
    fn name(&self) -> &'static str {
        "listeners"
    }
    async fn passes(&self, edge: &Edge) -> bool {
        edge.state.get().ready_version.is_some() && edge.dns.listeners.all_bound()
    }
}
