//! `picket-core run` (core.md §13): the service entry point.
//!
//! 1. Refuse without the marker (exit 78, naming the directory): `run` never creates an instance.
//! 2. Clean temporary files.
//! 3. Copy and migrate `core.db` and `metrics.db` before serving (exit 78 on failure or a newer
//!    database, storage.md §5).
//! 4. Load the identity, the LAN CA and `secrets.key`; create missing system objects.
//! 5. Start the job lanes, retention, the edge runtime, the feeds runtime (which first undoes any
//!    feed run a stop interrupted), the bundle compiler (which builds what is behind its feeds),
//!    the browser lists, the web port and the edge port; log the fingerprint.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio_util::sync::CancellationToken;

use crate::alerts::Alerts;
use crate::config::{ConfigStore, SecretsKey};
use crate::db::{Db, DbOptions, migrate};
use crate::error::ExitError;
use crate::identity::{self, Identity};
use crate::instance;
use crate::lanca;
use crate::scheduler::Scheduler;
use crate::state::{AppState, SharedState, UiEvents};

/// What a started core bound.
#[derive(Clone, Debug)]
pub struct RunInfo {
    pub web: Vec<SocketAddr>,
    pub edge: SocketAddr,
    pub fingerprint: String,
}

/// A start failure a restart may fix: exit 1, so systemd restarts core. Exit 78 is only for no
/// marker, a failed migration, a database newer than the binary and too little space for the
/// migration (core.md §13; those come from `instance` and `migrate`).
fn failed(msg: String) -> ExitError {
    ExitError::failed(msg)
}

/// What a start may vary besides the data directory.
#[derive(Clone, Debug)]
pub struct StartOptions {
    /// Where the edge release bundled with core lives (core.md §5).
    pub release_dir: PathBuf,
    /// The minisign keys that release must verify against (`release_keys`, core.md §11).
    pub release_keys: Vec<String>,
    /// Bind every port to 0 (the system picks a free one; [`RunInfo`] reports it) instead of the
    /// configured ports: tests running many cores at once never race for a port.
    pub any_port: bool,
    /// The feed downloads' HTTP client options (tests add a root and host overrides).
    pub feed_http: crate::modules::download::client::HttpOptions,
    /// Where the browser extension builds in the package live (core.md §12).
    pub browser_extension_dir: PathBuf,
    /// Pins the clock's synchronisation answer instead of probing the host (tests: a CI
    /// container has no time service, so the probe would say "not synchronised").
    pub clock_synced: Option<bool>,
    /// Runs the `core_disk_low` watch (tests turn it off: the host's free space isn't theirs).
    pub disk_watch: bool,
}

impl Default for StartOptions {
    fn default() -> Self {
        Self {
            release_dir: PathBuf::from(crate::edges::releases::DEFAULT_DIR),
            release_keys: crate::settings::release_keys(),
            any_port: false,
            feed_http: Default::default(),
            browser_extension_dir: PathBuf::from(crate::web::browser_extension::DEFAULT_DIR),
            clock_synced: None,
            disk_watch: true,
        }
    }
}

/// Opens everything and starts serving; returns once the ports are bound.
pub async fn start(
    data_dir: &Path,
    shutdown: CancellationToken,
) -> Result<(SharedState, RunInfo), ExitError> {
    start_with(data_dir, shutdown, StartOptions::default()).await
}

/// [`start`] with other options (tests: a test release and its key).
pub async fn start_with(
    data_dir: &Path,
    shutdown: CancellationToken,
    opts: StartOptions,
) -> Result<(SharedState, RunInfo), ExitError> {
    let marker = instance::require_marker(data_dir)?;
    // Before anything changes: another process (an older core still running, a CLI) may use
    // the directory.
    let dir_lock = instance::lock_data_dir(data_dir)?;
    instance::clean_at_start(data_dir)
        .map_err(|e| failed(format!("cannot clean {}: {e:#}", data_dir.display())))?;
    let dir = data_dir.to_path_buf();
    tokio::task::spawn_blocking(move || migrate::migrate_databases(&dir))
        .await
        .map_err(|e| ExitError::config(format!("the migration failed: {e}")))??;

    let db =
        Db::open(DbOptions::core(data_dir)).map_err(|e| failed(format!("cannot open core.db: {e:#}")))?;
    let metrics_db = Db::open(DbOptions::metrics(data_dir))
        .map_err(|e| failed(format!("cannot open metrics.db: {e:#}")))?;
    let identity = Identity::load(&identity::identity_dir(data_dir))
        .map_err(|e| failed(format!("cannot load core's identity: {e:#}")))?;
    // An interrupted LAN CA rotation is finished or discarded first (core.md §11).
    let lanca = lanca::rotation::open(data_dir, &db)
        .await
        .map_err(|e| failed(format!("cannot load the LAN CA: {e:#}")))?;
    let secrets_key =
        SecretsKey::load(data_dir).map_err(|e| failed(format!("cannot read secrets.key: {e:#}")))?;

    // System objects at every start (core.md §2).
    let dd = data_dir.to_path_buf();
    let (upgraded, created) = db
        .write(move |c| {
            let tx = c.transaction()?;
            // What the previous release stored in a since-changed shape reads in the new one
            // (README §2 Compatibility), before anything reads it.
            let upgraded = crate::config::store::upgrade_stored(&tx)?;
            let created = crate::config::system::ensure(&tx, &dd)?;
            tx.commit()?;
            Ok::<_, anyhow::Error>((upgraded, created))
        })
        .await
        .map_err(|e| {
            failed(format!(
                "cannot upgrade the stored configuration or create system objects: {e:#}"
            ))
        })?;
    if !upgraded.is_empty() {
        tracing::info!(
            http_converted = upgraded.converted.len(),
            http_split_off = upgraded.splits.len(),
            alphamountain_named = upgraded.named.len(),
            "upgraded the previous release's stored configuration (one http provider per feed's URL; alphaMountain's file named)"
        );
    }
    if !created.is_empty() {
        tracing::info!(count = created.len(), "created missing system objects");
    }
    let settings = db
        .read(crate::settings::load)
        .await
        .map_err(|e| failed(format!("cannot read settings: {e:#}")))?;
    if lanca.zones()
        != crate::lanca::normalize_zones(&settings.lanca.zones)
            .unwrap_or_default()
            .as_slice()
    {
        tracing::warn!(ca = ?lanca.zones(), setting = ?settings.lanca.zones, "lanca.zones differs from the LAN CA's constraints; the CA's apply");
    }

    let events = UiEvents::new();
    let alerts = Alerts::new(db.clone(), events.clone());
    // What the upgrade at this start changed that the owner should look at.
    crate::config::store::announce_upgrade(&alerts, &upgraded).await;
    let log_writer = crate::logs::writer::LogWriter::start(crate::logs::LogStore::new(data_dir))
        .map_err(|e| failed(format!("cannot start the log writer: {e:#}")))?;
    let state: SharedState = Arc::new(AppState {
        data_dir: data_dir.to_path_buf(),
        marker,
        config: ConfigStore::new(db.clone(), secrets_key.map(Arc::new), settings),
        auth: crate::web::auth::AuthState::new(db.clone(), Some(alerts.clone())),
        alerts,
        scheduler: Scheduler::new(),
        retention: crate::retention::Retention::default(),
        events,
        identity: Arc::new(identity),
        lanca: ArcSwap::from_pointee(lanca),
        lanca_rt: Default::default(),
        core_ips: ArcSwap::from_pointee(crate::net::local_ips()),
        web_cert: std::sync::OnceLock::new(),
        clock: Arc::new({
            let clock = crate::clock::Clock::new();
            if let Some(synced) = opts.clock_synced {
                clock.pin(synced);
            }
            clock
        }),
        dir_lock,
        edges: crate::edges::Runtime::new(opts.release_dir.clone(), opts.release_keys.clone()),
        logs: Arc::new(crate::logs::Ingest::new(log_writer)),
        analysis: Arc::new(crate::logs::analysis::Analysis::default()),
        metrics: Arc::new(crate::metrics::Metrics::default()),
        feeds: Arc::new(crate::feeds::Feeds::new(opts.feed_http.clone())),
        compiler: crate::compiler::Compiler::default(),
        lists: crate::lists::Lists::default(),
        lookups: Arc::new(crate::lookups::Lookups::new()),
        dnssec: Arc::new(crate::dnssec::Dnssec::default()),
        browser_extension: Arc::new(crate::web::browser_extension::Builds::new(
            opts.browser_extension_dir.clone(),
        )),
        restore: Arc::default(),
        shutdown: shutdown.clone(),
        metrics_db,
        db,
    });

    // `job` UI events from the first job on, and the coalesced ones (api.md §7).
    crate::web::events::forward_jobs(&state);
    crate::web::events::forward_coalesced(&state);
    state.scheduler.start(shutdown.clone());
    state.clock.clone().spawn(shutdown.clone());
    state.retention.register(Arc::new(crate::logs::LogRetention));
    state
        .retention
        .register(Arc::new(crate::metrics::MetricsRetention));
    state
        .retention
        .register(Arc::new(crate::feeds::retention::FeedRetention));
    crate::retention::schedule(state.clone());
    crate::logs::cold_share::schedule(state.clone());
    spawn_ip_refresh(state.clone());
    if opts.disk_watch {
        spawn_disk_watch(state.clone());
    }
    crate::metrics::spawn_core_sampler(state.clone());
    crate::edges::start(&state)
        .await
        .map_err(|e| failed(format!("cannot start the edge runtime: {e:#}")))?;
    // A config restore that stopped before its manual feeds' applied blobs ran (core.md §2): those
    // feeds start busy, so each blob runs before the feed's saved file.
    let restore_applied = crate::config::export::pending_applied(&state)
        .await
        .map_err(|e| failed(format!("cannot read the config restore's pending runs: {e:#}")))?;
    if !restore_applied.is_empty() {
        let busy: Vec<String> = restore_applied.iter().map(|(f, _, _, _)| f.clone()).collect();
        state.feeds.forget_for_restore(&busy);
    }
    crate::feeds::start(&state)
        .await
        .map_err(|e| failed(format!("cannot start the feeds runtime: {e:#}")))?;
    crate::config::export::resume_applied(&state, &restore_applied).await;
    crate::compiler::start(&state)
        .await
        .map_err(|e| failed(format!("cannot start the bundle compiler: {e:#}")))?;
    crate::lists::start(&state)
        .await
        .map_err(|e| failed(format!("cannot start the browser lists: {e:#}")))?;
    // A config restore that stopped before emptying the logs and metrics finishes now (core.md
    // §2), before anything reads them.
    crate::config::export::finish_pending(&state)
        .await
        .map_err(|e| failed(format!("cannot finish the config restore: {e:#}")))?;
    crate::logs::analysis::start(&state);
    crate::lookups::start(&state)
        .await
        .map_err(|e| failed(format!("cannot start async lookups: {e:#}")))?;
    crate::dnssec::start(&state, &opts.feed_http);
    crate::lanca::rotation::spawn(&state);

    let (web, _) = crate::web::start(state.clone(), opts.any_port)
        .map_err(|e| failed(format!("cannot start the web port: {e:#}")))?;
    let (edge, _) = crate::edge_api::start(state.clone(), opts.any_port)
        .map_err(|e| failed(format!("cannot start the edge port: {e:#}")))?;
    let info = RunInfo {
        web,
        edge,
        fingerprint: state.identity.fingerprint.clone(),
    };
    tracing::info!(
        version = crate::VERSION,
        fingerprint = %info.fingerprint,
        web = ?info.web,
        edge = %info.edge,
        data_dir = %data_dir.display(),
        "picket-core started"
    );
    Ok((state, info))
}

/// Core's addresses change (DHCP, interfaces): re-read them every minute, and keep the managed
/// web certificate in step.
fn spawn_ip_refresh(state: SharedState) {
    let mut changes = state.config.subscribe();
    let mut web = state.settings().web.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(60));
        t.tick().await;
        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                _ = t.tick() => {
                    let ips = tokio::task::spawn_blocking(crate::net::local_ips).await.unwrap_or_default();
                    if !ips.is_empty() {
                        state.core_ips.store(Arc::new(ips));
                    }
                }
                changed = changes.changed() => {
                    if changed.is_err() { return; }
                    let current = state.settings().web.clone();
                    if current.names == web.names && current.addresses == web.addresses { continue; }
                    web = current;
                }
            }
            // Also retry failed refreshes and renew on the periodic tick.
            let st = state.clone();
            match tokio::task::spawn_blocking(move || crate::web::refresh_web_cert(&st)).await {
                Ok(Ok(true)) => tracing::info!("the web certificate was re-issued"),
                Ok(Ok(false)) => {}
                Ok(Err(e)) => {
                    tracing::warn!(error = %format!("{e:#}"), "cannot re-issue the web certificate")
                }
                Err(e) => tracing::warn!(error = %e, "web certificate refresh task failed"),
            }
        }
    });
}

/// `core_disk_low` (core.md §9): under 10 % or 2 GB free on the data directory's filesystem,
/// checked every minute; resolves when space is back.
fn spawn_disk_watch(state: SharedState) {
    tokio::spawn(async move {
        // When the space went low, on the monotonic clock (README §2 Clocks).
        let mut low_since: Option<tokio::time::Instant> = None;
        let mut t = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                _ = t.tick() => {}
            }
            let dir = state.data_dir.clone();
            let Ok(Ok((free, total))) = tokio::task::spawn_blocking(move || disk_space(&dir)).await else {
                continue;
            };
            let low = free < 2 * 1024 * 1024 * 1024 || (total > 0 && free.saturating_mul(10) < total);
            let now = crate::util::now();
            let mono = tokio::time::Instant::now();
            low_since = if low { low_since.or(Some(mono)) } else { None };
            let since = crate::clock::held_since(low_since, mono, now);
            let spec = crate::alerts::RaiseSpec::new(
                "core_disk_low",
                crate::alerts::Severity::Warning,
                "core_disk_low",
                "Little free space for core's data directory",
                serde_json::json!({"free_bytes": free, "total_bytes": total, "data_dir": state.data_dir.display().to_string()}),
            );
            let threshold = state.settings().alerts.threshold("core_disk_low");
            if let Err(e) = state.alerts.condition(spec, since, threshold, now).await {
                tracing::warn!(error = %e, "core_disk_low check failed");
            }
        }
    });
}

/// (free, total) bytes on the filesystem holding `dir`.
pub fn disk_space(dir: &Path) -> anyhow::Result<(u64, u64)> {
    let st = rustix::fs::statvfs(dir)?;
    Ok((
        st.f_bavail.saturating_mul(st.f_frsize),
        st.f_blocks.saturating_mul(st.f_frsize),
    ))
}

/// Runs until SIGTERM or SIGINT. `any_port`: see [`StartOptions::any_port`].
pub async fn run(data_dir: PathBuf, any_port: bool) -> Result<(), ExitError> {
    let shutdown = CancellationToken::new();
    let opts = StartOptions {
        any_port,
        ..StartOptions::default()
    };
    let (_state, _info) = start_with(&data_dir, shutdown.clone(), opts).await?;
    wait_for_signal().await;
    tracing::info!("stopping");
    shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let term = signal(SignalKind::terminate());
    let int = signal(SignalKind::interrupt());
    match (term, int) {
        (Ok(mut t), Ok(mut i)) => {
            tokio::select! {
                _ = t.recv() => {}
                _ = i.recv() => {}
            }
        }
        _ => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}
