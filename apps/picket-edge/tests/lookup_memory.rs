//! Lookup memory by configuration (#44): the heap a [`Lookups`] holds, and the process's RSS and
//! PSS, for the configurations the issue names. A measurement, not a pass/fail check (the
//! allocation and release rules are checked deterministically in picket-lookup's registry tests,
//! the HTTP client's tests and `activation.rs`), so it is ignored by default:
//!
//! ```text
//! cargo test --release -p picket-edge --test lookup_memory -- --ignored --nocapture
//! ```
//!
//! **Method:** one test in its own binary, since the counting allocator is global. Each scenario
//! builds a fresh `Lookups` on a current-thread runtime and reports the heap it still holds
//! after its steps (bytes allocated minus freed since just before it was built), then drops it
//! and reports what is still held after that; each figure is the median of 5 runs. A warm-up scenario runs first so that process-wide
//! one-time allocations (the crypto provider, tracing) don't land on the first scenario. RSS and
//! PSS come from `/proc/self/smaps_rollup` (Linux): the allocator keeps freed pages, so they show
//! retention, not the live heap, and aren't expected to drop when a scenario's memory is freed.
//!
//! Only `Lookups`' long-standing API is used, so the same file measures the code before and
//! after #44.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::print_stdout,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast and print freely"
)]

use std::alloc::System;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::time::Instant;

use serde_json::{Value, json};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

use picket_api::edge_config::EdgeConfig;
use picket_edge::dns::lookups::Lookups;
use picket_edge::logs::{DropCounters, LogProducer};
use picket_lookup::{Registry, SyncRequest};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Bytes allocated and not freed, process-wide.
fn live() -> isize {
    let s = GLOBAL.stats();
    s.bytes_allocated as isize - s.bytes_deallocated as isize + s.bytes_reallocated
}

/// RSS and PSS in KiB.
fn rss_pss() -> (u64, u64) {
    let Ok(s) = std::fs::read_to_string("/proc/self/smaps_rollup") else {
        return (0, 0);
    };
    let field = |name: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    };
    (field("Rss:"), field("Pss:"))
}

fn provider(module: &str, config: &Value) -> Value {
    json!({"module": module, "config": config, "cache_generation": "0123456789abcdef",
        "sync_timeout_ms": 500, "async_timeout_ms": 1000, "fail_mode": "open",
        "scope": {"exclude_bundles": [], "qtypes": ["A", "AAAA"]}})
}

fn dns_config() -> Value {
    json!({"transport": "udp", "servers": [{"ip": "127.0.0.1", "port": 9}], "qtype": "A",
        "rules": [{"id": "blocked", "when": {"ede": [15]}, "verdict": "block"}]})
}

fn http_config(port: u16) -> Value {
    json!({"url": format!("https://127.0.0.1:{port}/v1/{{domain}}"),
        "verdict": {"pointer": "/risk_score", "block_if": ">= 7.0", "clean_if": "< 4.0"}})
}

/// A config listing `listed` providers and attaching `attached` of them `sync` to one profile.
fn config(listed: &[(&str, &str, Value)], attached: &[&str]) -> EdgeConfig {
    let providers: serde_json::Map<String, Value> = listed
        .iter()
        .map(|(id, module, cfg)| ((*id).to_owned(), provider(module, cfg)))
        .collect();
    let attachments: Vec<Value> = attached
        .iter()
        .map(|p| json!({"provider": p, "mode": "sync"}))
        .collect();
    serde_json::from_value(json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
        "default_profile": "default",
        "profiles": {"default": {"upstream": "g", "lookup_providers": attachments,
            "block_response": {"type": "nxdomain", "ttl": 10}}},
        "upstream_groups": {"g": {"upstreams": [], "strategy": "failover"}},
        "lookup_providers": providers,
    }))
    .unwrap()
}

async fn lookup(l: &Lookups, provider: &str, name: &str) {
    let c = l.get(provider).expect("a client for the provider");
    let _ = c
        .lookup_sync(SyncRequest {
            name,
            deadline: Instant::now() + Duration::from_millis(500),
            call: true,
            tag: None,
        })
        .await;
}

/// A TCP listener that accepts and closes each connection: an HTTPS request gets as far as the
/// TLS handshake.
async fn closing_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            drop(c);
        }
    });
    port
}

struct Row {
    name: &'static str,
    held: isize,
    after_drop: isize,
    rss: u64,
    pss: u64,
}

/// Runs `steps` [`RUNS`] times, each on a fresh `Lookups`, and keeps the median of each figure.
async fn scenario(name: &'static str, steps: impl AsyncFn(&Lookups), logs: &LogProducer) -> Row {
    let mut runs = vec![];
    for _ in 0..RUNS {
        runs.push(once(name, &steps, logs).await);
    }
    let median = |f: fn(&Row) -> isize| {
        let mut v: Vec<isize> = runs.iter().map(f).collect();
        v.sort_unstable();
        v[v.len() / 2]
    };
    Row {
        name,
        held: median(|r| r.held),
        after_drop: median(|r| r.after_drop),
        rss: median(|r| r.rss as isize) as u64,
        pss: median(|r| r.pss as isize) as u64,
    }
}

const RUNS: usize = 5;

async fn once(name: &'static str, steps: &impl AsyncFn(&Lookups), logs: &LogProducer) -> Row {
    // Let the previous scenario's tasks finish and free what they hold.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = live();
    let l = Lookups::with_registry(Weak::new(), logs.clone(), Arc::new(Registry::builtin()), None);
    steps(&l).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let held = live() - base;
    let (rss, pss) = rss_pss();
    drop(l);
    tokio::time::sleep(Duration::from_millis(200)).await;
    Row {
        name,
        held,
        after_drop: live() - base,
        rss,
        pss,
    }
}

#[test]
#[ignore = "a measurement: run with --ignored --nocapture"]
fn lookup_memory_by_configuration() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (logs, _rx) = LogProducer::new("boot".into(), Arc::new(DropCounters::default()));
        let port = closing_server().await;
        let dns = ("d1", "dns", dns_config());
        let http = ("h1", "http_json", http_config(port));
        let mut rows = vec![];
        let warm = {
            let (dns, http) = (dns.clone(), http.clone());
            async move |l: &Lookups| {
                l.configure(&config(&[dns.clone(), http.clone()], &["d1", "h1"]));
                lookup(l, "h1", "warm.example").await;
                lookup(l, "d1", "warm.example").await;
            }
        };
        let _ = scenario("warm-up", warm, &logs).await;
        rows.push(
            scenario(
                "no lookups",
                async |l: &Lookups| l.configure(&config(&[], &[])),
                &logs,
            )
            .await,
        );
        rows.push(
            scenario(
                "2 providers listed, none attached",
                {
                    let (dns, http) = (dns.clone(), http.clone());
                    async move |l: &Lookups| l.configure(&config(&[dns.clone(), http.clone()], &[]))
                },
                &logs,
            )
            .await,
        );
        rows.push(
            scenario(
                "DNS only, after a lookup",
                {
                    let dns = dns.clone();
                    async move |l: &Lookups| {
                        l.configure(&config(std::slice::from_ref(&dns), &["d1"]));
                        lookup(l, "d1", "a.example").await;
                    }
                },
                &logs,
            )
            .await,
        );
        rows.push(
            scenario(
                "HTTP, before its first request",
                {
                    let http = http.clone();
                    async move |l: &Lookups| l.configure(&config(std::slice::from_ref(&http), &["h1"]))
                },
                &logs,
            )
            .await,
        );
        rows.push(
            scenario(
                "HTTP, after its first request",
                {
                    let http = http.clone();
                    async move |l: &Lookups| {
                        l.configure(&config(std::slice::from_ref(&http), &["h1"]));
                        lookup(l, "h1", "a.example").await;
                    }
                },
                &logs,
            )
            .await,
        );
        rows.push(
            scenario(
                "DNS + HTTP, after a lookup each",
                {
                    let (dns, http) = (dns.clone(), http.clone());
                    async move |l: &Lookups| {
                        l.configure(&config(&[dns.clone(), http.clone()], &["d1", "h1"]));
                        lookup(l, "h1", "a.example").await;
                        lookup(l, "d1", "a.example").await;
                    }
                },
                &logs,
            )
            .await,
        );
        rows.push(
            scenario(
                "DNS + HTTP used, then removed",
                {
                    let (dns, http) = (dns.clone(), http.clone());
                    async move |l: &Lookups| {
                        l.configure(&config(&[dns.clone(), http.clone()], &["d1", "h1"]));
                        lookup(l, "h1", "a.example").await;
                        lookup(l, "d1", "a.example").await;
                        l.configure(&config(&[], &[]));
                    }
                },
                &logs,
            )
            .await,
        );
        println!("| scenario | heap held (bytes) | after dropping Lookups | RSS (KiB) | PSS (KiB) |");
        println!("|---|---:|---:|---:|---:|");
        for r in rows {
            println!(
                "| {} | {} | {} | {} | {} |",
                r.name, r.held, r.after_drop, r.rss, r.pss
            );
        }
    });
}
