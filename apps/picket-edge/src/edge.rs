//! The shared service context: everything the edge's tasks share, behind `Arc` and lock-free
//! `ArcSwap` cells (edge.md §16: a panic can't poison a lock).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::{ArcSwap, ArcSwapOption};
use serde::Serialize;
use tokio::sync::Notify;

use picket_api::edge_config::EdgeConfig;
use picket_api::logs::Versions;
use picket_api::time::Timestamp;

use crate::admin::AdminRegistry;
use crate::allows::AllowsStore;
use crate::clock::Clock;
use crate::conditions::Conditions;
use crate::hooks::Hooks;
use crate::identity::Identity;
use crate::local_config::LocalConfig;
use crate::logs::LogProducer;
use crate::logs::shipper::LogControl;
use crate::metrics::Metrics;
use crate::neighbours::Neighbours;
use crate::paths::{DataLayout, HostPlatform};
use crate::state::StateStore;
use crate::storage::Storage;
use crate::supervisor::Supervisor;
use crate::systemd::Watchdog;

/// What the edge runs now. Swapped whole at each activation step; a query loads it once and logs
/// `versions` from the same load (edge.md §11 Versions).
#[derive(Clone, Debug, Default)]
pub struct ActiveState {
    /// The config object whose contents run now.
    pub object_id: Option<String>,
    /// The config id `versions.config` and `have.config` report.
    pub config_version: Option<String>,
    /// `config/<hash>.json`'s hash.
    pub config_hash: Option<String>,
    pub config: Option<Arc<EdgeConfig>>,
    /// The block every `q` record carries.
    pub versions: Option<Arc<Versions>>,
    /// The bundles running now (bundles.md §6), as the activator ([`crate::bundles`]) last
    /// swapped them in; empty, every name resolves.
    pub bundles: Arc<crate::dns::filter::ActiveBundles>,
    /// The config compiled for the DNS data path (profiles, clients, listeners, limits).
    pub dns: Option<Arc<crate::dns::runtime::DnsRuntime>>,
}

/// The core session's state for `status` and reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreState {
    /// No `core_key` in `edge.json`: run `picket-edge setup`.
    NotSetUp,
    Connecting,
    Connected,
    /// Core presented another key (api.md §1 Key change).
    KeyMismatch,
    /// Core refused this edge's key: approve it under Edges → Pending.
    NotApproved,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionStatus {
    pub state: CoreState,
    #[serde(with = "picket_api::time::micros")]
    pub since: Timestamp,
    pub core_url: Option<String>,
    pub core_version: Option<String>,
    pub edge_id: Option<String>,
    pub edge_name: Option<String>,
    pub last_error: Option<String>,
}

impl SessionStatus {
    pub fn new(state: CoreState, core_url: Option<String>) -> Self {
        Self {
            state,
            since: Timestamp::now(),
            core_url,
            core_version: None,
            edge_id: None,
            edge_name: None,
            last_error: None,
        }
    }
}

/// Convergence progress for `have` (api.md §3).
#[derive(Clone, Debug, Default, Serialize)]
pub struct ConvergenceStatus {
    /// The ETag of the newest config object fetched.
    pub fetched: Option<String>,
    /// The object being activated, while its config isn't live yet.
    pub in_progress: Option<String>,
    pub last_error: Option<String>,
    #[serde(with = "picket_api::time::micros_opt")]
    pub last_fetch: Option<Timestamp>,
}

/// The shared context.
pub struct Edge {
    pub boot: String,
    pub started: Instant,
    pub platform: HostPlatform,
    pub config_path: PathBuf,
    pub local: LocalConfig,
    pub layout: DataLayout,
    pub runtime_dir: PathBuf,
    pub identity: Identity,
    /// First line of `/usr/lib/version` on UniFi (≤ 128 bytes), else `None`.
    pub firmware: Option<String>,
    pub state: Arc<StateStore>,
    pub logs: LogProducer,
    pub log_control: Arc<LogControl>,
    pub metrics: Arc<Metrics>,
    pub conditions: Arc<Conditions>,
    pub clock: Arc<Clock>,
    pub storage: Arc<Storage>,
    pub allows: Arc<AllowsStore>,
    pub neighbours: Arc<Neighbours>,
    /// The core client, once `core_key` is set (downloads of bundles, verdict sets, releases).
    pub core: ArcSwapOption<crate::core_client::CoreClient>,
    /// Bundle and verdict-set activation (edge.md §13).
    pub bundles: Arc<crate::bundles::BundleManager>,
    /// The firewall client (edge-firewall.md §3–§5).
    pub fw: Arc<crate::firewall::FwClient>,
    /// Temporary allows and the recent-blocks ring (edge.md §12).
    pub bypass: Arc<crate::bypass::Bypass>,
    pub admin: Arc<AdminRegistry>,
    pub hooks: Hooks,
    /// The DNS data path (edge.md §4–§10).
    pub dns: Arc<crate::dns::Dns>,
    pub watchdog: Arc<Watchdog>,
    pub supervisor: Arc<Supervisor>,
    pub active: ArcSwap<ActiveState>,
    pub session: ArcSwap<SessionStatus>,
    pub convergence: ArcSwap<ConvergenceStatus>,
    /// Wakes the convergence loop to fetch the config object now.
    pub fetch_now: Arc<Notify>,
    /// Wakes the session loop to send a heartbeat now (tests, `status` freshness).
    pub heartbeat_now: Notify,
}

impl Edge {
    /// Milliseconds since start (monotonic): `heartbeat.up_ms`.
    pub fn up_ms(&self) -> u64 {
        picket_api::duration::as_millis_u64(self.started.elapsed())
    }

    pub fn active(&self) -> Arc<ActiveState> {
        self.active.load_full()
    }
}
