//! Helpers shared by the integration tests.

#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

pub mod bundles;
pub mod edge;
pub mod feeds;
pub mod github;
pub mod logs;
pub mod prom;
pub mod zones;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use picket_core::instance::{InitOptions, InitOutcome};
use picket_core::run::RunInfo;
use picket_core::state::SharedState;
use tokio_util::sync::CancellationToken;

pub fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_picket-core"))
}

/// A port nothing listens on right now (only for "nothing listening there" checks and `init`'s
/// stored settings: cores in tests bind port 0 and report what they got, so tests never race for
/// a port).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

/// Two distinct free ports.
pub fn free_ports() -> (u16, u16) {
    loop {
        let (a, b) = (free_port(), free_port());
        if a != b {
            return (a, b);
        }
    }
}

/// `init` in-process with random ports.
pub fn init_dir() -> (tempfile::TempDir, InitOutcome, u16, u16) {
    let d = tempfile::tempdir().unwrap();
    let (web, edge) = free_ports();
    let out = picket_core::instance::init(&InitOptions {
        data_dir: d.path().to_path_buf(),
        web_port: Some(web),
        edge_port: Some(edge),
        lanca_zones: None,
    })
    .unwrap();
    (d, out, web, edge)
}

/// Writes setting rows straight into core.db (before start).
pub fn set_settings(dir: &Path, patch: serde_json::Value) {
    let opts = picket_core::db::DbOptions::core(dir);
    let mut c = picket_core::db::open_connection(&opts, 1024).unwrap();
    let tx = c.transaction().unwrap();
    picket_core::config::store::apply_settings(&tx, &patch, &picket_core::config::Actor::cli(), true)
        .unwrap();
    tx.commit().unwrap();
}

/// Copies a core's data directory into `to` as one consistent state, whether that core still runs
/// or not: each SQLite database through `VACUUM INTO` (its last committed state, never a torn copy
/// of a file being written), then every other file. A blob is renamed into place before a row
/// names it, so every blob the copied rows name is there whole; `staging/` and `tmp/` stay empty
/// (start empties them anyway).
///
/// It doesn't wait for the core to stop: a core cancelled while its heavy lane still holds jobs
/// keeps its state alive in this process (the jobs hold it and the lane holds the jobs), so its
/// tasks never all end and its directory stays locked until the test process exits.
pub fn snapshot_dir(from: &Path, to: &Path) {
    snapshot_dbs(from, to);
    copy_files(from, to);
}

fn snapshot_dbs(from: &Path, to: &Path) {
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        let t = to.join(&name);
        if e.file_type().unwrap().is_dir() {
            if name != "staging" && name != "tmp" {
                std::fs::create_dir_all(&t).unwrap();
                snapshot_dbs(&e.path(), &t);
            }
        } else if name.ends_with(".db") {
            let c = rusqlite::Connection::open(e.path()).unwrap();
            c.busy_timeout(Duration::from_secs(60)).unwrap();
            c.execute("VACUUM INTO ?1", [t.to_str().unwrap()])
                .unwrap_or_else(|err| panic!("VACUUM INTO {}: {err}", t.display()));
        }
    }
}

fn copy_files(from: &Path, to: &Path) {
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        let t = to.join(&name);
        let kind = e.file_type().unwrap();
        if kind.is_dir() {
            std::fs::create_dir_all(&t).unwrap();
            if name != "staging" && name != "tmp" {
                copy_files(&e.path(), &t);
            }
        } else if kind.is_file()
            && ![".db", ".db-wal", ".db-shm", ".db-journal"]
                .iter()
                .any(|s| name.ends_with(s))
        {
            match std::fs::copy(e.path(), &t) {
                // A running core may remove a file after the listing named it.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                r => {
                    r.unwrap();
                }
            }
        }
    }
}

/// A running core in this process.
pub struct Core {
    pub dir: tempfile::TempDir,
    pub init: InitOutcome,
    pub state: SharedState,
    pub info: RunInfo,
    pub stop: CancellationToken,
}

impl Core {
    pub fn web(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.info.web[0].port()))
    }
    pub fn base(&self, scheme: &str) -> String {
        format!("{scheme}://127.0.0.1:{}", self.info.web[0].port())
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Inits and starts a core in-process; `patch` adjusts settings first.
pub async fn start_core(patch: Option<serde_json::Value>) -> Core {
    start_core_with(
        patch,
        picket_core::run::StartOptions {
            // No bundled release unless a test provides one.
            release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
            ..Default::default()
        },
    )
    .await
}

/// [`start_core`] with start options (a test release and its key). Every port binds 0 and
/// [`Core::info`] holds what the system gave it.
pub async fn start_core_with(patch: Option<serde_json::Value>, opts: picket_core::run::StartOptions) -> Core {
    let (dir, init, _web, _edge) = init_dir();
    if let Some(p) = patch {
        set_settings(dir.path(), p);
    }
    let stop = CancellationToken::new();
    // Deterministic across hosts: the clock counts as synchronised unless a test says
    // otherwise, and the host's free disk space raises no `core_disk_low`.
    let opts = picket_core::run::StartOptions {
        any_port: true,
        clock_synced: opts.clock_synced.or(Some(true)),
        disk_watch: false,
        ..opts
    };
    // Many cores share this test process. When another test's core forks a child (the clock
    // probe runs `timedatectl`), the child holds a copy of every open descriptor until it
    // execs, including the data-directory lock `init` just released, so `run`'s lock can see it
    // as held for a moment. Production never re-locks a directory within one process; here
    // a short retry on "in use" (exit 75) rides out that window.
    let mut tries = 0;
    let (state, info) = loop {
        match picket_core::run::start_with(dir.path(), stop.clone(), opts.clone()).await {
            Err(e) if e.code == picket_core::error::EXIT_IN_USE && tries < 100 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            r => break r.unwrap(),
        }
    };
    Core {
        dir,
        init,
        state,
        info,
        stop,
    }
}

/// An HTTP client that accepts the LAN-CA certificate without trusting it.
/// Waits until core's startup work has settled: no bundle build requested, queued or running
/// and no heavy job queued or running. The system bundles' first builds publish new config
/// objects, so a test that counts `changed` messages waits for them first (they run late on a
/// loaded machine).
pub async fn settled(c: &Core) {
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
    let idle = || {
        c.state.compiler.idle()
            && c.state.scheduler.heavy.depth() == 0
            && c.state.scheduler.heavy.stats().running.is_none()
    };
    loop {
        // Twice, 200 ms apart: a build's commit can request the next one.
        if idle() {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if idle() {
                return;
            }
        }
        assert!(tokio::time::Instant::now() < end, "core never settled");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .tls_danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap()
}

/// Runs the binary to completion.
pub fn run_bin(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .env_remove("PICKET_CORE_DATA_DIR")
        .output()
        .unwrap()
}

/// Starts `picket-core run` as a child process with every port bound to 0, and waits for its
/// start log line; returns the child and the edge port the system gave it.
pub fn spawn_run(dir: &Path) -> (Child, u16) {
    let mut child = Command::new(bin())
        .args(["run", "--any-port", "--data-dir"])
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    // Reads the log to the end, so the child never blocks on a full pipe.
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut tx = Some(tx);
        for line in std::io::BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if let Some(port) = start_line_edge_port(&line)
                && let Some(t) = tx.take()
            {
                let _ = t.send(port);
            }
        }
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(port) => (child, port),
        Err(_) => {
            kill(child);
            panic!("core never logged its start line");
        }
    }
}

/// The edge port in core's "picket-core started" log line (`edge=<addr>`), colours removed.
fn start_line_edge_port(line: &str) -> Option<u16> {
    let mut plain = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // An ANSI escape: up to its final letter.
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    if !plain.contains("picket-core started") {
        return None;
    }
    let addr = plain.split(" edge=").nth(1)?.split_whitespace().next()?;
    addr.parse::<SocketAddr>().ok().map(|a| a.port())
}

/// Waits until `probe` sees `fp` on `port`.
pub fn wait_for_core(port: u16, fp: &str) {
    for _ in 0..200 {
        let out = run_bin(&[
            "probe",
            &format!("https://127.0.0.1:{port}"),
            "--expect-identity",
            fp,
        ]);
        if out.status.code() == Some(0) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("core on port {port} never came up");
}

pub fn kill(mut c: Child) {
    let _ = c.kill();
    let _ = c.wait();
}

/// The directory's entry names, sorted (for "changed nothing" checks).
pub fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}
