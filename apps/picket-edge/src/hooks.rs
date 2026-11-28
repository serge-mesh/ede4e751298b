//! The interfaces the activation and connectivity layer implements and installs into the
//! foundation ([`crate::service::start`] installs the real ones: [`crate::bundles::EdgeActivator`],
//! [`crate::release::ReleaseHandoff`], [`crate::firewall::FwHelperHooks`],
//! [`crate::bundles::BundleHave`]). Each hook also has a minimal default (activate config-only
//! objects, report no helper) for tests that want one.
//!
//! Install hooks before the core session starts ([`crate::service::start`]'s `install` callback
//! takes them, or call the `set_*` methods); they can also be swapped later.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;

use picket_api::edge_config::{EdgeConfig, InstallNow, ReleaseOffer, RevokedAllows};
use picket_api::session::FwStats;

use crate::edge::Edge;

/// One object to make live (edge.md §13).
#[derive(Clone, Debug)]
pub struct ActivationTarget {
    /// The config object's id (its BLAKE3 = ETag).
    pub object_id: String,
    /// The object's config id as `versions.config` and `have.config` report it: the object id
    /// the config (without runtime fields) was first stored under.
    pub config_version: String,
    /// BLAKE3 of the object without `bundles`, `verdict_sets`, `release`, `flush` and
    /// `revoked_allows` (the name of `config/<hash>.json`).
    pub config_hash: String,
    pub config: Arc<EdgeConfig>,
    /// True when the config differs from the active one outside the runtime fields.
    pub config_changed: bool,
    /// True for the stored config run at start, before core is reached.
    pub from_disk: bool,
}

/// An activation's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activation {
    /// Everything the object names is active.
    Active,
    /// Not yet (a download failed, a part is missing): retried with backoff.
    Retry { stage: String, reason: String },
    /// The object can't be run (it can't be built): the active one keeps running and this object
    /// isn't retried until core sends another.
    Failed { stage: String, reason: String },
}

/// Makes an `EdgeConfig` live: config, bundle heads and verdict sets, swapping the active state
/// (with a new `versions` block) at each step, logging `activated` / `activation_failed` for
/// bundle and verdict-set steps. The convergence loop logs the config's own events and persists
/// `config/<hash>.json` and `state.json` when the config changed.
#[async_trait]
pub trait Activator: Send + Sync {
    async fn activate(&self, edge: &Edge, target: &ActivationTarget) -> Activation;
}

/// Applies the requests a config object carries (edge.md §13): called as soon as an object
/// carrying a request id the edge hasn't applied is fetched. `Ok` records the id as applied.
#[async_trait]
pub trait RequestHandler: Send + Sync {
    /// `flush.dns`: flush the DNS cache.
    async fn flush_dns(&self, edge: &Edge) -> anyhow::Result<()>;
    /// `flush.lookups.<provider>`: flush that provider's RAM tier (verdict sets stay).
    async fn flush_lookups(&self, edge: &Edge, provider: &str) -> anyhow::Result<()>;
    /// `picket-edge flush-cache` without `--lookups <provider>`: every RAM tier.
    async fn flush_all_lookups(&self, edge: &Edge) -> anyhow::Result<()>;
    /// `revoked_allows`: end each listed allow the edge holds (unknown ones are ignored).
    async fn revoke_allows(&self, edge: &Edge, list: &RevokedAllows) -> anyhow::Result<()>;
}

/// The self-update handoff (edge.md §14 step 1: download, verify, write `pending.json`). The
/// rules that decide whether to install at all are the foundation's (`update` module); this is
/// called only when they allow it. `Ok(true)` once handed to the updater (the id then counts as
/// applied), `Ok(false)` to retry later.
#[async_trait]
pub trait UpdateHandoff: Send + Sync {
    async fn hand_off(&self, edge: &Edge, req: &InstallNow, offer: &ReleaseOffer) -> anyhow::Result<bool>;
    /// `auto_update` (edge.md §14 When): hand over the offered release with no request id,
    /// called only when the foundation's rules allow it ([`crate::release::auto_due`]).
    /// `Ok(true)` once handed over.
    async fn auto_update(&self, _edge: &Edge, _offer: &ReleaseOffer) -> anyhow::Result<bool> {
        Ok(false)
    }
    /// `picket-edge update --install` (edge.md §14 When): hand over the offered release here and
    /// now, through the same handoff as the two above, so one download runs at a time.
    async fn hand_off_now(&self, _edge: &Edge, _offer: &ReleaseOffer) -> anyhow::Result<HandOff> {
        Ok(HandOff::Later("this edge has no release handoff"))
    }
}

/// What [`UpdateHandoff::hand_off_now`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandOff {
    /// `pending.json` names the release.
    Done,
    /// The download started and goes on in its own task past the admin command's budget; it
    /// hands the release over when it ends, or logs why not (edge.md §14).
    Downloading,
    /// Nothing now, and why.
    Later(&'static str),
}

/// What the edge learns from picket-edge-helper before each heartbeat (api.md §3). All `None`
/// without a helper. The foundation turns `cpu_ms` into a counter that survives helper restarts
/// by adding up the growth it sees per pid.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HelperSnapshot {
    /// The helper's pid (from `SO_PEERCRED` on its socket).
    pub pid: Option<u32>,
    /// That process's CPU time so far (`/proc/<pid>/stat`), in ms.
    pub cpu_ms: Option<u64>,
    /// `VmRSS` of the helper.
    pub rss: Option<u64>,
    /// `fw` running totals (`rejects` and `mon_rejects` already summed from `status` growth).
    pub fw: Option<FwStats>,
}

#[async_trait]
pub trait HelperProbe: Send + Sync {
    async fn snapshot(&self) -> HelperSnapshot;
}

/// Startup step 2 (edge.md §3): with a stored config that needs the helper, ask the helper for
/// its state and seed the firewall shadow map before `READY=1`.
#[async_trait]
pub trait HelperSeed: Send + Sync {
    async fn seed(&self, edge: &Edge, config: &EdgeConfig) -> anyhow::Result<()>;
}

/// One check of the self-check after a firmware change (edge-unifi.md §1): the helper answers
/// `hello` with `rules_ok`, the port-53 redirect is present, listeners are bound, the SSD passes.
#[async_trait]
pub trait SelfCheck: Send + Sync {
    /// The check's name in `firmware_check_failed.detail.failed`.
    fn name(&self) -> &'static str;
    /// Whether it applies to this edge now (e.g. the SSD check only with `ssd_dir`).
    fn applies(&self, _edge: &Edge) -> bool {
        true
    }
    async fn passes(&self, edge: &Edge) -> bool;
}

/// What `have` reports for bundles and verdict sets, active first then previous.
pub trait HaveProvider: Send + Sync {
    fn bundles(&self) -> std::collections::BTreeMap<String, Vec<String>>;
    fn verdict_sets(&self) -> std::collections::BTreeMap<String, Vec<String>>;
    fn in_progress_bundles(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        Default::default()
    }
    fn in_progress_verdict_sets(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        Default::default()
    }
}

/// No helper: everything null.
pub struct NoHelper;

#[async_trait]
impl HelperProbe for NoHelper {
    async fn snapshot(&self) -> HelperSnapshot {
        HelperSnapshot::default()
    }
}

#[async_trait]
impl HelperSeed for NoHelper {
    async fn seed(&self, _edge: &Edge, _config: &EdgeConfig) -> anyhow::Result<()> {
        // No helper: nothing to seed (the real one is `firewall::FwHelperHooks`).
        Ok(())
    }
}

/// No bundles or verdict sets yet.
pub struct NoHave;

impl HaveProvider for NoHave {
    fn bundles(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        Default::default()
    }
    fn verdict_sets(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        Default::default()
    }
}

/// No update handoff (the real one is `release::ReleaseHandoff`).
pub struct NoHandoff;

#[async_trait]
impl UpdateHandoff for NoHandoff {
    async fn hand_off(&self, _edge: &Edge, _req: &InstallNow, _offer: &ReleaseOffer) -> anyhow::Result<bool> {
        Ok(false)
    }
}

/// The installed hooks, swappable at run time.
pub struct Hooks {
    activator: ArcSwap<Box<dyn Activator>>,
    requests: ArcSwap<Box<dyn RequestHandler>>,
    handoff: ArcSwap<Box<dyn UpdateHandoff>>,
    helper_probe: ArcSwap<Box<dyn HelperProbe>>,
    helper_seed: ArcSwap<Box<dyn HelperSeed>>,
    have: ArcSwap<Box<dyn HaveProvider>>,
    self_checks: ArcSwap<Vec<Arc<dyn SelfCheck>>>,
}

impl Hooks {
    pub fn new(activator: Box<dyn Activator>, requests: Box<dyn RequestHandler>) -> Self {
        Self {
            activator: ArcSwap::from_pointee(activator),
            requests: ArcSwap::from_pointee(requests),
            handoff: ArcSwap::from_pointee(Box::new(NoHandoff)),
            helper_probe: ArcSwap::from_pointee(Box::new(NoHelper)),
            helper_seed: ArcSwap::from_pointee(Box::new(NoHelper)),
            have: ArcSwap::from_pointee(Box::new(NoHave)),
            self_checks: ArcSwap::from_pointee(Vec::new()),
        }
    }

    pub fn activator(&self) -> Arc<Box<dyn Activator>> {
        self.activator.load_full()
    }
    pub fn set_activator(&self, a: Box<dyn Activator>) {
        self.activator.store(Arc::new(a));
    }
    pub fn requests(&self) -> Arc<Box<dyn RequestHandler>> {
        self.requests.load_full()
    }
    pub fn set_requests(&self, r: Box<dyn RequestHandler>) {
        self.requests.store(Arc::new(r));
    }
    pub fn handoff(&self) -> Arc<Box<dyn UpdateHandoff>> {
        self.handoff.load_full()
    }
    pub fn set_handoff(&self, h: Box<dyn UpdateHandoff>) {
        self.handoff.store(Arc::new(h));
    }
    pub fn helper_probe(&self) -> Arc<Box<dyn HelperProbe>> {
        self.helper_probe.load_full()
    }
    pub fn set_helper_probe(&self, h: Box<dyn HelperProbe>) {
        self.helper_probe.store(Arc::new(h));
    }
    pub fn helper_seed(&self) -> Arc<Box<dyn HelperSeed>> {
        self.helper_seed.load_full()
    }
    pub fn set_helper_seed(&self, h: Box<dyn HelperSeed>) {
        self.helper_seed.store(Arc::new(h));
    }
    pub fn have(&self) -> Arc<Box<dyn HaveProvider>> {
        self.have.load_full()
    }
    pub fn set_have(&self, h: Box<dyn HaveProvider>) {
        self.have.store(Arc::new(h));
    }
    pub fn self_checks(&self) -> Arc<Vec<Arc<dyn SelfCheck>>> {
        self.self_checks.load_full()
    }
    /// Adds a firmware self-check (edge-unifi.md §1), replacing one with the same name (the
    /// module that owns a check can install a better one than the foundation's).
    pub fn add_self_check(&self, c: Arc<dyn SelfCheck>) {
        self.self_checks.rcu(|v| {
            let mut v = Vec::clone(v);
            match v.iter_mut().find(|x| x.name() == c.name()) {
                Some(slot) => *slot = Arc::clone(&c),
                None => v.push(Arc::clone(&c)),
            }
            v
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Named(&'static str, bool);

    #[async_trait]
    impl SelfCheck for Named {
        fn name(&self) -> &'static str {
            self.0
        }
        async fn passes(&self, _edge: &Edge) -> bool {
            self.1
        }
    }

    #[test]
    fn a_self_check_replaces_one_with_its_name() {
        let h = Hooks::new(
            Box::new(crate::convergence::ConfigActivator),
            Box::new(crate::convergence::DefaultRequests),
        );
        h.add_self_check(Arc::new(Named("listeners", false)));
        h.add_self_check(Arc::new(Named("ssd", false)));
        h.add_self_check(Arc::new(Named("listeners", true)));
        let names: Vec<&str> = h.self_checks().iter().map(|c| c.name()).collect();
        assert_eq!(names, vec!["listeners", "ssd"], "order kept, no duplicate");
    }
}
