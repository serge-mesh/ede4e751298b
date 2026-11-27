//! picket-edge-helper (edge-firewall.md §4, edge.md §15).

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, sync_channel};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use notify::{RecursiveMode, Watcher};
use picket_api::helper::DEFAULT_SOCKET;
use picket_edge_helper::backend::RealBackend;
use picket_edge_helper::engine::{self, Cmd, Engine};
use picket_edge_helper::iptables::Platform;
use picket_edge_helper::server::{self, Server, ServerConfig};
use picket_edge_helper::shared::Shared;
use picket_edge_helper::{cli, fast, users};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{oneshot, watch};

/// UniFi's udapi state file: re-provisioning writes it (edge-unifi.md §4).
const UDAPI_STATE: &str = "/data/udapi-config/ubios-udapi-server/ubios-udapi-server.state";
/// Present on UniFi OS (as for `picket-edge-update install`'s platform default, edge-unifi.md §2).
const UDAPI_DIR: &str = "/data/udapi-config/ubios-udapi-server";

#[derive(Parser)]
#[command(
    name = "picket-edge-helper",
    version,
    about = "Picket's ipset and iptables helper"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum PlatformArg {
    Unifi,
    Debian,
}

#[derive(Subcommand)]
enum Command {
    /// Service entry point (picket-edge-helper.service).
    Run {
        /// <helper_dir>: rules.json and, from a stop to the next start, snap.json.
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        /// The edge's user (name or UID); it and root may connect.
        #[arg(long, default_value = "picket")]
        edge_user: String,
        /// The socket's group; default: the edge user's primary group.
        #[arg(long)]
        socket_group: Option<String>,
        /// Jump placement; default: unifi if UniFi's udapi directory exists, else debian.
        #[arg(long, value_enum)]
        platform: Option<PlatformArg>,
    },
    /// Emergency: remove Picket's firewall rules and stop repairing them until `enable` (kept
    /// across restarts).
    Disable {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Re-add Picket's firewall rules after `disable`.
    Enable {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .without_time() // journald stamps each line
        .init();
    let cli = Cli::parse();
    let res = match cli.cmd {
        Command::Run {
            state_dir,
            socket,
            edge_user,
            socket_group,
            platform,
        } => run(&state_dir, &socket, &edge_user, socket_group.as_deref(), platform),
        Command::Disable { socket } => control(&socket, "disable"),
        Command::Enable { socket } => control(&socket, "enable"),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("picket-edge-helper: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn control(socket: &Path, what: &str) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let r = rt.block_on(cli::control(socket, what))?;
    let state = if r.conditions.helper_disabled {
        "disabled"
    } else {
        "enabled"
    };
    println!("firewall {state}; rules_ok={}", r.rules_ok);
    if !r.pending.is_empty() {
        println!("pending (retried every 2 s): {}", r.pending.join(", "));
    }
    println!("{}", serde_json::to_string_pretty(&r.conditions)?);
    Ok(())
}

/// `<helper_dir>` must be a directory nobody else can write to (edge-firewall.md §4 "Unit").
fn check_state_dir(dir: &Path) -> anyhow::Result<()> {
    match std::fs::metadata(dir) {
        Ok(md) => {
            if !md.is_dir() {
                bail!("{} is not a directory", dir.display());
            }
            if md.permissions().mode() & 0o022 != 0 {
                bail!("{} is writable by group or others; expected 0700", dir.display());
            }
            if md.uid() != rustix::process::geteuid().as_raw() {
                tracing::warn!(dir = %dir.display(), "state directory is owned by another user");
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("cannot create {}", dir.display())),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", dir.display())),
    }
}

/// inotify on UniFi's state file (watching its directory, as UniFi may replace the file).
fn watch_udapi(etx: SyncSender<Cmd>) -> Option<notify::RecommendedWatcher> {
    let path = Path::new(UDAPI_STATE);
    let dir = path.parent()?;
    if !dir.is_dir() {
        return None;
    }
    let name = path.file_name()?.to_owned();
    let mut w = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res
            && ev.paths.iter().any(|p| p.file_name() == Some(name.as_os_str()))
        {
            let _ = etx.try_send(Cmd::Trigger);
        }
    })
    .map_err(|e| tracing::warn!(error = %e, "inotify unavailable; relying on the 2 s check"))
    .ok()?;
    w.watch(dir, RecursiveMode::NonRecursive)
        .map_err(|e| tracing::warn!(error = %e, "cannot watch UniFi's state file"))
        .ok()?;
    Some(w)
}

fn run(
    state_dir: &Path,
    socket: &Path,
    edge_user: &str,
    socket_group: Option<&str>,
    platform: Option<PlatformArg>,
) -> anyhow::Result<()> {
    check_state_dir(state_dir)?;
    let platform = match platform {
        Some(PlatformArg::Unifi) => Platform::Unifi,
        Some(PlatformArg::Debian) => Platform::Debian,
        None if Path::new(UDAPI_DIR).is_dir() => Platform::Unifi,
        None => Platform::Debian,
    };
    let (edge_uid, edge_gid) = match users::lookup_user(edge_user) {
        Some((u, g)) => (Some(u), g),
        None => {
            tracing::warn!(
                user = edge_user,
                "edge user not found; only root may connect until it exists"
            );
            (None, None)
        }
    };
    let gid = match socket_group {
        Some(g) => users::lookup_group(g),
        None => edge_gid.or_else(|| users::lookup_group("picket")),
    };

    let b = Arc::new(RealBackend::new(state_dir.to_path_buf()));
    let shared = Shared::new();
    let listener = server::bind(socket, gid).with_context(|| format!("cannot bind {}", socket.display()))?;

    // Start-up step 1 (edge-firewall.md §5), before READY=1.
    let mut engine = Engine::new(b.clone(), shared.clone(), platform);
    let rep = engine.startup();
    tracing::info!(
        platform = ?platform,
        rules_ok = rep.rules_ok,
        disabled = engine.disabled(),
        pending = ?rep.pending,
        "start-up done"
    );
    let (etx, erx) = sync_channel::<Cmd>(16);
    let engine_thread = std::thread::Builder::new()
        .name("engine".into())
        .spawn(move || engine::run(engine, erx))?;
    let fast = fast::spawn(b.clone(), shared.clone(), etx.clone()).context("cannot start fast worker")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(async {
        let listener = tokio::net::UnixListener::from_std(listener)?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let _watcher = if platform == Platform::Unifi {
            watch_udapi(etx.clone())
        } else {
            None
        };
        let cfg = ServerConfig {
            edge_user: Some(edge_user.to_string()),
            edge_uid,
            ..ServerConfig::default()
        };
        let srv = Server::new(b.clone(), shared.clone(), etx.clone(), fast.clone(), cfg);
        let serving = tokio::spawn(srv.serve(listener, stop_rx.clone()));
        tokio::spawn(server::watchdog(
            fast.clone(),
            shared.clone(),
            b.clone(),
            stop_rx.clone(),
        ));
        let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);

        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        tracing::info!("stopping");
        let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
        let _ = stop_tx.send(true);
        let _ = serving.await;
        // The engine writes the snapshot, then exits.
        let (tx, rx) = oneshot::channel();
        let etx2 = etx.clone();
        let _ = tokio::task::spawn_blocking(move || etx2.send(Cmd::Shutdown(tx))).await;
        let _ = rx.await;
        anyhow::Ok(())
    })?;
    drop(etx);
    let _ = engine_thread.join();
    let _ = std::fs::remove_file(socket);
    Ok(())
}
