//! Shared application state: one [`AppState`] behind an `Arc`, handed to every module.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::alerts::Alerts;
use crate::config::ConfigStore;
use crate::db::Db;
use crate::identity::Identity;
use crate::instance::Marker;
use crate::lanca::LanCa;
use crate::scheduler::Scheduler;
use crate::settings::Settings;

/// One message on the UI WebSocket (api.md §7): `{type, data}`.
#[derive(Clone, Debug, Serialize)]
pub struct UiEvent {
    /// `alert`, `edge_status`, `job` (`web::events::JobEvent`), `feed_run`, `bundle_version`,
    /// `restore`, `temp_allow`, `dnssec`, `dnssec_queued`, `lanca`, `lanca_served`
    /// (`web::events::FRAME_TYPES` names each one's data).
    #[serde(rename = "type")]
    pub kind: String,
    pub data: Value,
}

/// The UI event bus: a bounded broadcast channel (a slow subscriber lags and is dropped).
#[derive(Clone)]
pub struct UiEvents {
    tx: broadcast::Sender<UiEvent>,
    /// The coalesced events waiting (`alert`, `feed_run`, `temp_allow`, `dnssec`,
    /// `dnssec_queued`, `lanca_served`), sent by `web::events::forward_coalesced`.
    coalesced: Arc<crate::web::events::Coalesced>,
}

impl Default for UiEvents {
    fn default() -> Self {
        Self::new()
    }
}

impl UiEvents {
    pub const CAPACITY: usize = 1024;

    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(Self::CAPACITY);
        Self {
            tx,
            coalesced: Arc::default(),
        }
    }

    /// Where coalesced events wait (`alert`, `feed_run`, `temp_allow`, `dnssec`, …:
    /// `web::events::Coalesced`).
    pub fn coalesced(&self) -> &Arc<crate::web::events::Coalesced> {
        &self.coalesced
    }

    /// Publishes an event; no subscribers is fine.
    pub fn send(&self, kind: &str, data: Value) {
        let _ = self.tx.send(UiEvent {
            kind: kind.to_string(),
            data,
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.tx.subscribe()
    }

    /// Sends every coalesced event waiting, now (`web::events` module docs: on the core.db writer
    /// right after a config restore commits, so what changed before the restore goes out before
    /// its `restore` event and nothing from before it joins a later event; core.md §2).
    pub fn flush_coalesced(&self) {
        self.coalesced.send_waiting(self);
    }
}

/// Everything a running core shares.
pub struct AppState {
    pub data_dir: PathBuf,
    pub marker: Marker,
    /// `core.db`.
    pub db: Db,
    /// `metrics.db`.
    pub metrics_db: Db,
    pub config: ConfigStore,
    pub alerts: Alerts,
    pub scheduler: Scheduler,
    pub retention: crate::retention::Retention,
    pub events: UiEvents,
    pub identity: Arc<Identity>,
    /// The LAN CA: the current root and the previous roots still trusted (core.md §11).
    pub lanca: ArcSwap<LanCa>,
    /// LAN CA rotations and the dropping of unused previous roots (`lanca::rotation`).
    pub lanca_rt: crate::lanca::rotation::Runtime,
    /// Core's own addresses (refreshed periodically): `Host` allowlist, web certificate,
    /// default `dnssec.source_ips`.
    pub core_ips: ArcSwap<Vec<IpAddr>>,
    pub auth: crate::web::auth::AuthState,
    /// The managed web certificate the web port serves (`web.tls = managed`), swapped when it is
    /// re-issued ([`crate::web::refresh_web_cert`]).
    pub web_cert: std::sync::OnceLock<Arc<crate::web::SwapCert>>,
    /// Whether the wall clock is synchronised (README §2 Clocks): retention waits for it.
    pub clock: Arc<crate::clock::Clock>,
    /// The data directory's lock, held for as long as this core runs.
    pub dir_lock: crate::instance::DataDirLock,
    /// Edge sessions, live state, config publishing and the bundled release (core.md §4–§5).
    pub edges: crate::edges::Runtime,
    /// Log ingest (core.md §6).
    pub logs: Arc<crate::logs::Ingest>,
    /// The analysis of logged queries: attribution, trial, cold and wire checks, retro-match,
    /// alert evidence (core.md §6, §9).
    pub analysis: Arc<crate::logs::analysis::Analysis>,
    /// Metrics (core.md §10).
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Feeds: checks, downloads, ingest, schedules (feeds.md, feed-scheduling.md).
    pub feeds: Arc<crate::feeds::Feeds>,
    /// The bundle compiler (bundles.md §1–§7).
    pub compiler: crate::compiler::Compiler,
    /// Browser lists (bundles.md §8).
    pub lists: crate::lists::Lists,
    /// Async lookups, re-checks, verdict sets and self-tests (core.md §7).
    pub lookups: Arc<crate::lookups::Lookups>,
    /// Async DNSSEC validation and the cross-check (core.md §8).
    pub dnssec: Arc<crate::dnssec::Dnssec>,
    /// The browser extension builds in the package (core.md §12).
    pub extension: Arc<crate::web::extension::Builds>,
    /// The config restore's generation: work that began before a restore never commits after
    /// it (core.md §2).
    pub restore: Arc<crate::config::export::RestoreGate>,
    pub shutdown: CancellationToken,
}

impl AppState {
    /// The current settings snapshot.
    pub fn settings(&self) -> Arc<Settings> {
        self.config.settings()
    }

    pub fn core_ips(&self) -> Arc<Vec<IpAddr>> {
        self.core_ips.load_full()
    }
}

pub type SharedState = Arc<AppState>;
