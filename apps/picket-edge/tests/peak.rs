//! Activation peak RAM (edge.md §17; bundles.md §6 "Activation": one part extra, "if memory is
//! short"): a config replacing one large bundle with another of the same size, under a
//! `bundle_budget_mib` that fits one of them, never holds both whole. The running config's bundle
//! stays loaded until a replacement is live (#70), so the new one is refused at stage `budget`
//! once it no longer fits beside it: the heap peaks near the budget plus the part being built,
//! not at both bundles. A budget that fits both lets the same change through.
//!
//! Measured, not accounted: the live heap (every allocation the process makes, counted by the
//! global allocator) is sampled every millisecond while the config activates. One test in its own
//! binary: the counting allocator is global.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod bundlekit;
mod dnsh;
mod support;

use std::alloc::System;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering::SeqCst};
use std::time::Duration;

use serde_json::{Value, json};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

use bundlekit::*;
use dnsh::*;
use picket_edge::service::{self, Options, Tuning};
use support::{MockCore, wait_until, write_edge_json};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const T: Duration = Duration::from_secs(60);
const MIB: usize = 1 << 20;

/// Bytes allocated and not freed, process-wide.
fn live() -> isize {
    let s = GLOBAL.stats();
    s.bytes_allocated as isize - s.bytes_deallocated as isize + s.bytes_reallocated
}

/// Samples [`live`] every millisecond until stopped; returns the highest.
struct Sampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicIsize>,
    thread: std::thread::JoinHandle<()>,
}

impl Sampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicIsize::new(live()));
        let (s, p) = (Arc::clone(&stop), Arc::clone(&peak));
        let thread = std::thread::spawn(move || {
            while !s.load(SeqCst) {
                p.fetch_max(live(), SeqCst);
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        Self { stop, peak, thread }
    }
    fn finish(self) -> isize {
        self.stop.store(true, SeqCst);
        self.thread.join().unwrap();
        self.peak.load(SeqCst).max(live())
    }
}

/// Names that share no structure (the FST can't fold them away).
fn names(seed: u64, n: usize) -> Vec<String> {
    let mut x = seed;
    (0..n)
        .map(|i| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            format!("||p{seed}-{i}-{:016x}.example^", x)
        })
        .collect()
}

/// A block bundle of `n` such names in about 16 hot shards.
fn bundle(name: &str, seed: u64, n: usize) -> picket_bundle::compile::BuiltBundle {
    let lines = names(seed, n);
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let c = compile(&refs);
    let mut o = picket_bundle::compile::BuildOptions::new(name, picket_rules::matcher::BundleAction::Block);
    o.max_shard_keys = (n / 16) as u64;
    picket_bundle::compile::build(&c, &o).unwrap()
}

fn config(up: &FakeUpstream, bundle: &str, head: &str, budget_mib: usize) -> Value {
    json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
        "listeners": [{"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"}],
        "default_profile": "default",
        "profiles": {"default": {"upstream": "g", "block": [bundle], "block_response": {"type": "nxdomain", "ttl": 10}}},
        "upstreams": {"up1": plain_upstream(up, "udp")},
        "upstream_groups": {"g": {"upstreams": ["up1"], "strategy": "failover"}},
        "bundles": {bundle: head},
        "memory": {"bundle_budget_mib": budget_mib, "overlay_budget_mib": 16},
        "logging": {"spool_after_s": 1},
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacing_a_large_bundle_never_holds_both_and_keeps_the_running_one() {
    let n = 200_000;
    let (bx, by) = (bundle("x", 7, n), bundle("y", 11, n));
    assert!(bx.head.shards.len() >= 8, "{} shards", bx.head.shards.len());
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| match m.qtype {
        1 => Act::Answer(Ans::records(vec![a(&m.qname, "93.184.216.34", 300)])),
        _ => Act::Answer(Ans::records(vec![])),
    })
    .await;
    let core = MockCore::start().await;
    let idx = publish(&core, &bx.head, &bx.blobs);
    let idy = publish(&core, &by.head, &by.blobs);
    drop((bx, by));
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().to_path_buf();
    let (cfg_path, data, run) = (root.join("edge.json"), root.join("data"), root.join("run"));
    write_edge_json(&cfg_path, Some(&core), json!({}));
    let cfg1 = core.set_config(&config(&up, "x", &idx, 256));
    let mut t = Tuning {
        platform: Some(picket_edge::paths::HostPlatform::Debian),
        clock: Some(picket_edge::clock::Clock::fixed(true)),
        update_result: Some(data.join("no-update-result.json")),
        service: Some(false),
        firmware_file: data.join("no-such-version-file"),
        ..Default::default()
    };
    t.session.heartbeat = Duration::from_millis(300);
    t.session.backoff_min = Duration::from_millis(50);
    t.session.backoff_max = Duration::from_millis(300);
    t.convergence.retry_min = Duration::from_millis(50);
    t.convergence.retry_max = Duration::from_millis(300);
    t.firewall.socket = run.join("no-helper.sock");
    let r = service::start(
        Options {
            config: Some(cfg_path),
            data_dir: Some(data),
            runtime_dir: run,
        },
        t,
        |_| {},
    )
    .await
    .unwrap();
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(cfg1.as_str())).await);
    let mx = edge.active().bundles.get("x").unwrap().memory_usage();
    assert!(mx >= 3 * MIB, "x takes {} KiB: too small to measure", mx >> 10);
    // A budget that fits one of them (with room to spare), not both.
    let budget_mib = (mx * 13 / 10).div_ceil(MIB);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let base = live();
    let sampler = Sampler::start();
    let cfg2 = core.set_config(&config(&up, "y", &idy, budget_mib));
    core.changed(&cfg2);
    let refused = || {
        core.with(|s| {
            s.logs
                .iter()
                .any(|l| l["kind"] == "activation_failed" && l["bundle"] == "y" && l["stage"] == "budget")
        })
    };
    assert!(
        wait_until(T, refused).await,
        "refused at stage budget; convergence {:?}",
        edge.convergence.load()
    );
    let peak = sampler.finish();
    assert_eq!(edge.active().object_id.as_deref(), Some(cfg1.as_str()));
    assert!(
        edge.active().bundles.get("x").is_some(),
        "x stays for the running config"
    );
    assert!(edge.active().bundles.get("y").is_none());
    let my = mx; // y never loads whole here: built from as many names as x, so about its size
    let extra = (peak - base).max(0) as usize;
    eprintln!(
        "x {} KiB, y {} KiB, budget {budget_mib} MiB: the heap peaked {} KiB above where it stood with x",
        mx >> 10,
        my >> 10,
        extra >> 10
    );
    assert!(
        extra < my * 7 / 10,
        "the heap rose {} KiB while replacing a {} KiB bundle under a {budget_mib} MiB budget: both were held",
        extra >> 10,
        mx >> 10
    );
    // A budget that fits both: the change goes through.
    let cfg3 = core.set_config(&config(&up, "y", &idy, (mx * 3).div_ceil(MIB) + 1));
    core.changed(&cfg3);
    assert!(
        wait_until(T, || edge.active().object_id.as_deref() == Some(cfg3.as_str())
            && edge.active().bundles.get("x").is_none())
        .await,
        "the new config goes live; convergence {:?}",
        edge.convergence.load()
    );
    r.shutdown().await;
}
