//! Isolated memory probe for issue #86. The Python driver owns the wire buffers; this process
//! runs the real socket server and engine with an in-memory backend, without firewall privileges.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a diagnostic executable: a failed operation terminates the probe"
)]

use std::io::{self, BufRead};
use std::path::Path;
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use picket_edge_helper::engine::{self, Cmd, Engine};
use picket_edge_helper::fake::FakeBackend;
use picket_edge_helper::fast;
use picket_edge_helper::iptables::{Family, Platform, TableName};
use picket_edge_helper::server::{self, Server, ServerConfig};
use picket_edge_helper::shared::Shared;
use serde_json::json;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tokio::sync::watch;

#[global_allocator]
static GLOBAL: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

fn memory() -> serde_json::Value {
    let stats = GLOBAL.stats();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let kb = |key: &str| {
        status.lines().find_map(|l| {
            l.strip_prefix(key)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
    };
    json!({
        "rss_kib": kb("VmRSS:"), "hwm_kib": kb("VmHWM:"),
        "live_requested": stats.bytes_allocated.saturating_sub(stats.bytes_deallocated),
        "allocated": stats.bytes_allocated, "deallocated": stats.bytes_deallocated,
    })
}

fn decode(path: &Path) {
    let f = std::fs::read(path).unwrap();
    let region = Region::new(GLOBAL);
    let parsed = server::parse_request(&f);
    let stats = region.change();
    let mut result = json!({
        "wire_bytes": f.len(), "decode_allocated": stats.bytes_allocated,
        "decode_live": stats.bytes_allocated.saturating_sub(stats.bytes_deallocated),
        "decoded": parsed.is_ok(), "memory": memory(),
    });
    drop(parsed);
    result["after_drop"] = memory();
    println!("{result}");
}

fn serve(path: &Path, wait_ms: u64, admin: bool, background_mib: usize) {
    // Explicit budget charge for two retained 9 MiB dump copies. This measures headroom
    // with resident background storage, rather than the dump-building workflow.
    let mut background = vec![0_u8; background_mib * (1 << 20)];
    for page in background.chunks_mut(4096) {
        page[0] = 1;
    }
    let b = Arc::new(FakeBackend::new());
    for (family, name) in [
        (Family::V4, "filter-block-all-reject.rules"),
        (Family::V6, "filter6-block-all-reject.rules"),
    ] {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/unifi")
            .join(name);
        b.set_table(
            family,
            TableName::Filter,
            &std::fs::read_to_string(fixture).unwrap(),
        );
    }
    let shared = Shared::new();
    let mut e = Engine::new(b.clone(), shared.clone(), Platform::Unifi);
    e.startup();
    let (etx, erx) = sync_channel::<Cmd>(16);
    // Suspend the engine before dequeueing. Unlike the fake restore's 20 s timeout this can
    // exercise the real 120 s response timeout. The driver bounds the experiment to < 300 s
    // when using production timing (the engine watchdog's stall threshold).
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let engine_gate = gate.clone();
    std::thread::spawn(move || {
        let (lock, wake) = &*engine_gate;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
        drop(released);
        engine::run(e, erx);
    });
    let fast = fast::spawn(b.clone(), shared.clone(), etx.clone()).unwrap();
    let listener = server::bind(path, None).unwrap();
    let me = rustix::process::getuid().as_raw();
    let cfg = ServerConfig {
        edge_uid: Some(me),
        admin_uid: if admin { me } else { me.wrapping_add(1) },
        engine_timeout: Duration::from_millis(wait_ms),
        ..ServerConfig::default()
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (stop, rx) = watch::channel(false);
        let server = Server::new(b.clone(), shared, etx.clone(), fast, cfg);
        let serving = tokio::spawn(server.serve(tokio::net::UnixListener::from_std(listener).unwrap(), rx));
        std::thread::spawn(move || {
            let release = || {
                *gate.0.lock().unwrap() = true;
                gate.1.notify_all();
            };
            println!("{}", json!({"ready": true, "memory": memory()}));
            for line in io::stdin().lock().lines() {
                match line.unwrap().as_str() {
                    "sample" => println!("{}", memory()),
                    "release" => {
                        release();
                        println!("{}", json!({"released": true}));
                    }
                    "drain" => {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        etx.send(Cmd::Shutdown(tx)).ok().unwrap();
                        rx.blocking_recv().unwrap();
                        println!("{}", json!({"drained": true}));
                    }
                    "quit" => {
                        release();
                        let _ = stop.send(true);
                        return;
                    }
                    _ => panic!("expected sample, release or quit"),
                }
            }
            release();
            let _ = stop.send(true);
        });
        serving.await.unwrap();
    });
    std::hint::black_box(&background);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("decode") => decode(Path::new(&args[2])),
        Some("serve") => serve(
            Path::new(&args[2]),
            args[3].parse().unwrap(),
            args[4] == "admin",
            args.get(5).map_or(0, |s| s.parse().unwrap()),
        ),
        _ => panic!("usage: apply-memory decode FILE | serve SOCKET TIMEOUT_MS edge|admin"),
    }
}
