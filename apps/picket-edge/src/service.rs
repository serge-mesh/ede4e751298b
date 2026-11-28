//! `picket-edge run` (edge.md §3): the startup order, the supervised tasks and shutdown.
//!
//! 1. Load `state.json`, set `ready_version` null (written before anything else), count the start,
//!    and verify the stored configs against their BLAKE3 hashes.
//! 2. If the newest stored config needs the helper, seed the firewall shadow map from it
//!    ([`crate::firewall`]).
//! 3. `READY=1`.
//! 4. Connect to core if `core_key` is set, forever with backoff (session + convergence tasks).
//! 5. Run the newest stored config the activator accepts, with the bundle heads `active.json`
//!    records ([`crate::bundles`]); retried while nothing runs (the SSD may mount later).
//! 6. Bind listeners ([`crate::dns::listeners`]); until they are bound the watchdog is fed by a
//!    runtime tick, then by the internal test query (edge.md §16).
//!
//! SIGTERM flushes the log buffer to the spool before exit; a critical task's failure exits with
//! status 1 (systemd restarts the edge).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use tokio::sync::{Notify, mpsc, watch};

use picket_api::session::condition_kind;
use picket_api::time::Timestamp;

use crate::admin::{self, AdminRegistry};
use crate::allows::AllowsStore;
use crate::clock::Clock;
use crate::conditions::Conditions;
use crate::convergence::{self, ConfigActivator, Convergence, DefaultRequests};
use crate::core_client::CoreClient;
use crate::edge::{ActiveState, ConvergenceStatus, CoreState, Edge, SessionStatus};
use crate::fsutil::{self, Owner};
use crate::hooks::Hooks;
use crate::local_config::{self, LocalConfig};
use crate::logs::shipper::{self, LogControl, LogSink, PostOutcome, Shipper};
use crate::logs::{DropCounters, LogProducer};
use crate::metrics::Metrics;
use crate::neighbours::Neighbours;
use crate::paths::{self, DataLayout, HostPlatform};
use crate::state::StateStore;
use crate::storage::{MountTables, Storage};
use crate::supervisor::{self, Fatal, Kind, Supervisor};
use crate::systemd::{self, Watchdog};
use crate::{commands, firmware, identity, session, sysinfo, update, users};

/// MemAvailable below this holds `memory_low` (core.md §9).
pub const MEMORY_LOW: u64 = 512 << 20;

/// Command-line paths (edge.md §15).
#[derive(Clone, Debug)]
pub struct Options {
    pub config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub runtime_dir: PathBuf,
}

/// Knobs tests set; production uses the defaults.
pub struct Tuning {
    pub platform: Option<HostPlatform>,
    pub mounts: MountTables,
    pub clock: Option<Arc<Clock>>,
    /// A controlled neighbour table for tests; `None` starts the live netlink watcher.
    pub neighbours: Option<Arc<Neighbours>>,
    pub firmware_file: PathBuf,
    /// `bin/update-result.json`; `None` derives it from the installed layout.
    pub update_result: Option<PathBuf>,
    /// Socket perms as the service (0660 group picket) or not (0600); `None` detects.
    pub service: Option<bool>,
    pub session: session::Timings,
    pub convergence: convergence::Timings,
    pub shipper: shipper::Timings,
    pub firmware: firmware::Timings,
    pub supervisor: supervisor::Backoff,
    pub import_every: Duration,
    pub client_timeouts: Option<crate::core_client::Timeouts>,
    /// The DNS data path's timings.
    pub dns: crate::dns::DnsTuning,
    /// Lookup modules (tests install scripted ones); `None`: the built-in registry.
    pub lookup_registry: Option<Arc<picket_lookup::Registry>>,
    /// Bundle activation's timings.
    pub bundles: crate::bundles::BundleTuning,
    /// The firewall client's socket and timings.
    pub firewall: crate::firewall::FwTuning,
    /// The SSD's start window and checks.
    pub storage: crate::storage::StorageTuning,
    /// The check for UniFi features that fight Picket (edge-unifi.md §7).
    pub unifi: crate::unifi::UnifiTuning,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            platform: None,
            mounts: MountTables::default(),
            clock: None,
            neighbours: None,
            firmware_file: PathBuf::from(firmware::VERSION_FILE),
            update_result: None,
            service: None,
            session: Default::default(),
            convergence: Default::default(),
            shipper: Default::default(),
            firmware: Default::default(),
            supervisor: Default::default(),
            import_every: Duration::from_secs(5),
            client_timeouts: None,
            dns: Default::default(),
            lookup_registry: None,
            bundles: Default::default(),
            firewall: Default::default(),
            storage: Default::default(),
            unifi: Default::default(),
        }
    }
}

/// A started edge.
pub struct Running {
    pub edge: Arc<Edge>,
    shutdown: watch::Sender<bool>,
    fatal: mpsc::UnboundedReceiver<Fatal>,
    shipper: tokio::task::JoinHandle<()>,
    pub socket: PathBuf,
}

/// Before the core session exists: everything spools (with no `core_key` the edge has no core).
struct NoCore;

#[async_trait::async_trait]
impl LogSink for NoCore {
    async fn post(&self, _b: bytes::Bytes) -> PostOutcome {
        PostOutcome::Unreachable("no core configured (run picket-edge setup)".into())
    }
}

/// Creates a missing `data_dir` (0750; handed to `picket` when root creates it).
pub fn ensure_data_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fsutil::create_dir_all_mode(parent, 0o755)?;
    }
    let owner = if users::is_root() {
        Owner {
            uid: users::picket_uid(),
            gid: users::picket_gid(),
        }
    } else {
        Owner::default()
    };
    fsutil::ensure_dir_nofollow(path, 0o750, owner)
        .with_context(|| format!("data_dir {}", path.display()))?;
    Ok(())
}

/// Resolves the config path, `edge.json` and `data_dir`.
pub fn resolve(opts: &Options, platform: HostPlatform) -> Result<(PathBuf, LocalConfig, PathBuf)> {
    let config = opts.config.clone().unwrap_or_else(|| platform.default_config());
    let local = local_config::load(&config)?;
    let data_dir = local_config::resolve_data_dir(opts.data_dir.as_deref(), &local, platform);
    Ok((config, local, data_dir))
}

/// Starts the edge: startup steps 1–5 and every task. `hooks` lets the caller install its own
/// implementations before anything runs.
pub async fn start(opts: Options, tuning: Tuning, install: impl FnOnce(&Hooks)) -> Result<Running> {
    let started = Instant::now();
    let platform = tuning.platform.unwrap_or_else(HostPlatform::detect);
    // Before anything is written: a second edge on the same runtime directory would share the
    // first one's state (state.json, the spool) and take its admin socket.
    let socket = opts.runtime_dir.join(paths::ADMIN_SOCKET);
    if admin::edge_answers(&socket) {
        bail!(
            "another picket-edge is running with runtime directory {}",
            opts.runtime_dir.display()
        );
    }
    let (config_path, local, data_dir) = resolve(&opts, platform)?;
    ensure_data_dir(&data_dir)?;
    let layout = DataLayout::new(&data_dir);
    // Temporary files an earlier run left anywhere in data_dir (README §2 Restarts): state,
    // identity, configs, the spool, and the bundle and verdict-set trees.
    fsutil::sweep_temp_files_tree(&layout.root, 8);

    // Step 1.
    let state = Arc::new(StateStore::load_or_reset(&layout.state_json())?);
    state.record_start().context("writing state.json at start")?;
    let unusable = convergence::unusable_stored(&layout, &state.get());
    if !unusable.is_empty() {
        tracing::warn!(
            "dropping {} stored config(s) that fail verification",
            unusable.len()
        );
        state
            .update(|s| s.configs.retain(|c| !unusable.contains(&c.hash)))
            .context("writing state.json at start")?;
        convergence::delete_unreferenced_configs(&layout, &state.get());
    }
    let identity = identity::load_or_create(&layout)?;

    let boot = picket_api::ids::new_boot_id();
    let dropped = Arc::new(DropCounters::default());
    let (logs, logs_rx) = LogProducer::new(boot.clone(), Arc::clone(&dropped));
    let metrics = Metrics::new();
    let conditions = Conditions::new(logs.clone());
    let clock = tuning.clock.clone().unwrap_or_else(|| {
        if std::env::var("PICKET_CLOCK_SYNCED").is_ok_and(|v| v == "1") {
            Clock::fixed(true)
        } else {
            Clock::new()
        }
    });
    let storage = Storage::new(
        platform,
        layout.clone(),
        local.ssd_dir.clone(),
        tuning.mounts.clone(),
        Arc::clone(&conditions),
        Arc::clone(&clock),
    );
    storage.tune(&tuning.storage);
    let allows = AllowsStore::load(&layout.allows_json(), logs.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (sup, fatal_rx) = Supervisor::new(
        logs.clone(),
        Arc::clone(&metrics),
        shutdown_rx.clone(),
        tuning.supervisor,
    );
    let dns = crate::dns::Dns::new(
        Arc::clone(&metrics),
        Arc::clone(&conditions),
        logs.clone(),
        tuning.dns.clone(),
        tuning.lookup_registry.clone(),
    );
    let watch_neighbours = tuning.neighbours.is_none();
    let neighbours = tuning.neighbours.unwrap_or_else(Neighbours::new);
    let fw = crate::firewall::FwClient::new(
        tuning.firewall.clone(),
        Arc::clone(&neighbours),
        Arc::clone(&dns.interfaces),
        Arc::clone(&conditions),
        logs.clone(),
        Arc::clone(&clock),
        Arc::clone(&allows),
    );
    let bundles = crate::bundles::BundleManager::new(Arc::clone(&metrics), tuning.bundles.clone());
    let bypass = crate::bypass::Bypass::new();
    let hooks = Hooks::new(Box::new(ConfigActivator), Box::new(DefaultRequests));
    hooks.add_self_check(Arc::new(firmware::ListenersCheck));
    hooks.add_self_check(Arc::new(firmware::SsdCheck));
    // The data path's and the activation layer's hooks; the caller's `install` may still replace
    // them.
    hooks.set_activator(Box::new(crate::bundles::EdgeActivator));
    hooks.set_requests(Box::new(crate::dns::activation::DnsRequests));
    // Convergence's wake-up, shared with the release handoff (a background download ending).
    let fetch_now = Arc::new(Notify::new());
    hooks.set_handoff(Box::new(crate::release::ReleaseHandoff::with_wake(Arc::clone(
        &fetch_now,
    ))));
    hooks.set_helper_probe(Box::new(crate::firewall::FwHelperHooks(Arc::clone(&fw))));
    hooks.set_helper_seed(Box::new(crate::firewall::FwHelperHooks(Arc::clone(&fw))));
    hooks.set_have(Box::new(crate::bundles::BundleHave(Arc::clone(&bundles))));
    hooks.add_self_check(Arc::new(crate::dns::activation::ListenersCheck));
    hooks.add_self_check(Arc::new(crate::firewall::HelperCheck(Arc::clone(&fw))));
    hooks.add_self_check(Arc::new(crate::firewall::RedirectSelfCheck(Arc::clone(&fw))));
    install(&hooks);
    let admin_reg = AdminRegistry::new();
    commands::register(&admin_reg);
    admin_reg.register("explain", crate::dns::explain::explain);
    let log_control = Arc::new(LogControl::default());

    let core_ready = local.core_url.is_some() && local.core_key.is_some();
    let edge = Arc::new(Edge {
        boot,
        started,
        platform,
        config_path,
        firmware: firmware::read(platform, &tuning.firmware_file),
        local: local.clone(),
        layout: layout.clone(),
        runtime_dir: opts.runtime_dir.clone(),
        identity,
        state: Arc::clone(&state),
        logs: logs.clone(),
        log_control: Arc::clone(&log_control),
        metrics,
        conditions: Arc::clone(&conditions),
        clock: Arc::clone(&clock),
        storage: Arc::clone(&storage),
        allows,
        neighbours,
        core: arc_swap::ArcSwapOption::empty(),
        bundles,
        fw,
        bypass,
        admin: admin_reg,
        hooks,
        dns,
        watchdog: Watchdog::new(),
        supervisor: Arc::clone(&sup),
        active: ArcSwap::from_pointee(ActiveState::default()),
        session: ArcSwap::from_pointee(SessionStatus::new(
            if core_ready {
                CoreState::Connecting
            } else {
                CoreState::NotSetUp
            },
            local.core_url.as_ref().map(|u| u.text.clone()),
        )),
        convergence: ArcSwap::from_pointee(ConvergenceStatus::default()),
        fetch_now,
        heartbeat_now: Notify::new(),
    });

    // The data path's seams: the firewall ensure point and the recent-blocks ring.
    edge.dns
        .hooks
        .firewall
        .store(Arc::new(Box::new(crate::firewall::FwHook(Arc::clone(&edge.fw)))));
    edge.dns
        .hooks
        .recent_blocks
        .store(Arc::new(Box::new(crate::bypass::RingHook {
            bypass: Arc::clone(&edge.bypass),
            fw: Arc::clone(&edge.fw),
            interfaces: Arc::clone(&edge.dns.interfaces),
            allows: Arc::clone(&edge.allows),
            clock: Arc::clone(&edge.clock),
        })));
    // `active.json` (edge.md §2): the bundle heads a start from disk runs with.
    edge.bundles.load_record(&edge);

    // The install id bookkeeping must precede any handoff (edge.md §14).
    let result_path = tuning
        .update_result
        .clone()
        .or_else(|| paths::install_bin_dir().map(|b| b.join("update-result.json")));
    if let Err(e) = update::record_startup_install_id(&state, &layout.releases_dir(), result_path.as_deref())
    {
        tracing::warn!("recording the pending install id: {}", crate::diag::cap_chain(&e));
    }
    // `releases/<version>/` once applied (edge.md §2).
    crate::release::cleanup(&layout.releases_dir());

    // Logging: the shipper drains the buffer; core when set up.
    let client = if core_ready {
        let url = local.core_url.clone().context("core_url")?;
        let key = local.core_key.clone().context("core_key")?;
        let mut c = CoreClient::new(url, &edge.identity, &key)?;
        if let Some(t) = tuning.client_timeouts {
            c.timeouts = t;
        }
        let c = Arc::new(c);
        edge.core.store(Some(Arc::clone(&c)));
        Some(c)
    } else {
        tracing::warn!(
            "no core_key in {}: run picket-edge setup",
            edge.config_path.display()
        );
        None
    };
    let sink: Arc<dyn LogSink> = match &client {
        Some(c) => Arc::clone(c) as Arc<dyn LogSink>,
        None => Arc::new(NoCore),
    };
    let ship = Shipper::new(
        logs_rx,
        Arc::clone(&storage) as Arc<dyn crate::logs::spool::SpoolEnv>,
        sink,
        Arc::clone(&log_control),
        dropped,
        tuning.shipper,
    );
    // The shipper owns the buffer; a panic there exits the process rather than lose it quietly.
    let shipper_handle = {
        let sup = Arc::clone(&sup);
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let h = tokio::spawn(ship.run(rx));
            if let Err(e) = h.await
                && e.is_panic()
            {
                sup.report_fatal("log-shipper", supervisor::panic_message(e.into_panic()));
            }
        })
    };

    // Background tasks.
    {
        let s = Arc::clone(&storage);
        sup.spawn("storage", Kind::Background, move || Arc::clone(&s).run());
        let c = Arc::clone(&clock);
        sup.spawn("clock", Kind::Background, move || Arc::clone(&c).run());
        if watch_neighbours {
            let n = Arc::clone(&edge.neighbours);
            sup.spawn("neighbours", Kind::Background, move || Arc::clone(&n).run());
        }
        let w = Arc::clone(&edge.watchdog);
        sup.spawn("watchdog", Kind::Background, move || Arc::clone(&w).run());
        let e = Arc::clone(&edge);
        let ft = tuning.firmware;
        sup.spawn("firmware-check", Kind::Background, move || {
            firmware::self_check(Arc::clone(&e), ft)
        });
        let e = Arc::clone(&edge);
        sup.spawn("memory", Kind::Background, move || memory_monitor(Arc::clone(&e)));
        // UniFi features that fight Picket, checked in files (edge-unifi.md §7).
        if platform == HostPlatform::Unifi {
            let c = Arc::clone(&edge.conditions);
            let t = tuning.unifi.clone();
            sup.spawn("unifi-check", Kind::Background, move || {
                crate::unifi::run(Arc::clone(&c), t.clone())
            });
        }
        let e = Arc::clone(&edge);
        sup.spawn("allows-expiry", Kind::Background, move || {
            allows_expiry(Arc::clone(&e))
        });
        // These three own the only receivers of their queues: a panic there (a bug) exits the
        // process, as a critical task does, rather than leave the queue unread (edge.md §16).
        let b = Arc::clone(&edge.bundles);
        let e = Arc::clone(&edge);
        sup.spawn("bundle-refetch", Kind::Critical, move || {
            Arc::clone(&b).run_refetch(Arc::clone(&e))
        });
        let b = Arc::clone(&edge.bundles);
        let e = Arc::clone(&edge);
        sup.spawn("bundle-follow", Kind::Background, move || {
            Arc::clone(&b).run_follow(Arc::clone(&e))
        });
        let f = Arc::clone(&edge.fw);
        sup.spawn("fw-control", Kind::Critical, move || Arc::clone(&f).run_control());
        let f = Arc::clone(&edge.fw);
        sup.spawn("fw-fast", Kind::Critical, move || Arc::clone(&f).run_fast());
        let f = Arc::clone(&edge.fw);
        let n = Arc::clone(&edge.neighbours);
        sup.spawn("fw-maintenance", Kind::Background, move || {
            Arc::clone(&f).run_maintenance(Arc::clone(&n))
        });
        let b = Arc::clone(&edge.bypass);
        let e = Arc::clone(&edge);
        sup.spawn("bypass-rechecks", Kind::Background, move || {
            Arc::clone(&b).run_rechecks(Arc::clone(&e))
        });
        if let Some(p) = result_path.clone() {
            let e = Arc::clone(&edge);
            let every = tuning.import_every;
            sup.spawn("update-import", Kind::Background, move || {
                update::import_loop(Arc::clone(&e), p.clone(), every)
            });
        }
    }

    // Step 2: seed the firewall from the helper if the newest stored config needs it. After the
    // firewall tasks above start (they say `hello` and seed), so a healthy helper answers at once
    // instead of the wait running out (#69). A helper speaking another protocol stops the start
    // here, before the admin socket, any listener or `ready_version`: the shipper flushes the
    // `helper_protocol_mismatch` event to the spool and the process exits unsuccessfully.
    let stored = convergence::load_stored(&layout, &state.get());
    let seeded = match stored.first() {
        Some((_, cfg, _)) if cfg.needs_helper() => edge.hooks.helper_seed().seed(&edge, cfg).await,
        _ => Ok(()),
    };
    drop(stored);
    if let Err(e) = seeded {
        if e.downcast_ref::<crate::firewall::HelperIncompatible>().is_some() {
            // As `Running::shutdown`, short of the admin socket (not bound yet: the path may be
            // another instance's).
            systemd::notify_stopping();
            let _ = shutdown_tx.send(true);
            if tokio::time::timeout(Duration::from_secs(20), shipper_handle)
                .await
                .is_err()
            {
                tracing::warn!("log shipper didn't stop in time; some buffered records may be lost");
            }
            return Err(e.context("the firewall helper is incompatible"));
        }
        tracing::warn!(
            "seeding the firewall from the helper: {}",
            crate::diag::cap_chain(&e)
        );
    }

    // Step 3.
    systemd::notify_ready("started; waiting for a config, core or the SSD");

    // The admin socket. A failure here doesn't stop DNS: the task retries with backoff.
    let service = tuning.service.unwrap_or_else(users::is_service);
    let first = admin::ensure_runtime_dir(&opts.runtime_dir).and_then(|()| admin::bind(&socket, service));
    let listener = match first {
        Ok(l) => Some(l),
        Err(e) => {
            tracing::error!("admin socket: {}", crate::diag::cap_chain(&e));
            None
        }
    };
    let listener = Arc::new(tokio::sync::Mutex::new(listener));
    let runtime_dir = opts.runtime_dir.clone();
    {
        let e = Arc::clone(&edge);
        let sock = socket.clone();
        sup.spawn("admin-socket", Kind::Background, move || {
            let e = Arc::clone(&e);
            let l = Arc::clone(&listener);
            let sock = sock.clone();
            let rd = runtime_dir.clone();
            async move {
                let taken = l.lock().await.take();
                let listener = match taken {
                    Some(l) => l,
                    None => {
                        admin::ensure_runtime_dir(&rd)?;
                        admin::bind(&sock, service)?
                    }
                };
                admin::serve(e, listener).await
            }
        });
    }

    // The DNS data path's tasks: listeners bind once a config is active (step 6).
    crate::dns::spawn(&edge, client.clone());

    // Step 5 (config part): run the newest stored config while core is being reached.
    convergence::start_from_disk(&edge).await;

    // Step 4: the core session and convergence.
    if let Some(client) = client {
        let e = Arc::clone(&edge);
        let c = Arc::clone(&client);
        let t = tuning.convergence;
        sup.spawn("convergence", Kind::Background, move || {
            Convergence::new(Arc::clone(&e), Arc::clone(&c), t).run()
        });
        let e = Arc::clone(&edge);
        let t = tuning.session;
        sup.spawn("core-session", Kind::Background, move || {
            session::run(Arc::clone(&e), Arc::clone(&client), t)
        });
    }

    Ok(Running {
        edge,
        shutdown: shutdown_tx,
        fatal: fatal_rx,
        shipper: shipper_handle,
        socket,
    })
}

impl Running {
    /// Stops every task and flushes the log buffer to the spool.
    pub async fn shutdown(self) {
        systemd::notify_stopping();
        // Pending `tls_version_refused` counts go out with the buffer (listeners::handshake).
        self.edge.dns.listeners.tls_refusals.drain_and_log(&self.edge);
        let _ = self.shutdown.send(true);
        if tokio::time::timeout(Duration::from_secs(20), self.shipper)
            .await
            .is_err()
        {
            tracing::warn!("log shipper didn't stop in time; some buffered records may be lost");
        }
        let _ = std::fs::remove_file(&self.socket);
    }

    /// Waits for SIGTERM/SIGINT (exit 0) or a critical task's failure (exit 1), then shuts down.
    pub async fn wait(mut self) -> i32 {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("can't watch SIGTERM: {e}");
                return 1;
            }
        };
        let mut int = signal(SignalKind::interrupt()).ok();
        let code = tokio::select! {
            _ = term.recv() => 0,
            _ = async { match int.as_mut() { Some(s) => { s.recv().await; } None => std::future::pending::<()>().await } } => 0,
            f = self.fatal.recv() => {
                if let Some(f) = f {
                    tracing::error!("critical task {} failed: {}; exiting", f.task, f.reason);
                }
                1
            }
        };
        self.shutdown().await;
        code
    }
}

/// `memory_low` while MemAvailable is under 512 MiB (with 32 MiB of hysteresis).
async fn memory_monitor(edge: Arc<Edge>) -> Result<()> {
    let mut low = false;
    loop {
        if let (_, Some(avail)) = sysinfo::meminfo() {
            if !low && avail < MEMORY_LOW {
                low = true;
                edge.conditions
                    .set(condition_kind::MEMORY_LOW, None, Some(avail.into()));
            } else if low && avail >= MEMORY_LOW + (32 << 20) {
                low = false;
                edge.conditions.clear(condition_kind::MEMORY_LOW, None);
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Ends lapsed temporary allows, once the wall clock is synchronised.
async fn allows_expiry(edge: Arc<Edge>) -> Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        if !edge.clock.synced() {
            continue;
        }
        let allows = Arc::clone(&edge.allows);
        let now = Timestamp::now();
        // An expired IP allow's set entries lapse with their own timeout (the allow's), and the
        // shadow map's `allow_exp` with them (edge-firewall.md §3).
        tokio::task::spawn_blocking(move || allows.expire(now)).await??;
    }
}

/// The `run` entry point.
pub async fn run(opts: Options) -> i32 {
    match start(opts, Tuning::default(), |_| {}).await {
        Ok(r) => r.wait().await,
        Err(e) => {
            tracing::error!("can't start: {}", crate::diag::cap_chain(&e));
            eprintln!(
                "picket-edge: can't start: {}",
                crate::diag::cap_to(format_args!("{e:#}"), crate::diag::MAX_JOURNAL)
            );
            1
        }
    }
}
