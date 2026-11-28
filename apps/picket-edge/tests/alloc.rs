//! Hot-path allocation budgets, measured on the real serving path: an edge started in process
//! with a config and a block bundle, and each query driven through `pipeline::serve_with`, the
//! entry every listener uses (decode, device limits, profile choice, the ladder, the cache, the
//! reply and the log step). This file is the budgets' source of truth.
//!
//! **Metric:** allocation operations, allocations plus reallocations (a buffer that grows counts
//! each time it moves), as `picket-wire`'s `alloc_budget` and `picket-bundle`'s `alloc` count.
//!
//! **Fixtures:** the baseline queries, a block reply (`x.ads.example.com/A`, blocked by the
//! bundle, `null_ip`) and a cache hit (`www.example.com/A`, one warmed answer), each with and
//! without temporary allows in `allows.json`, from a client with no name, into a reply buffer the
//! listener lends (listeners reuse theirs).
//!
//! - **Serving, `log: off`:** at most 2 operations per query, decoding included, and none after
//!   decoding. Nothing else is allocated: the `q` record's fields are built only when the profile
//!   keeps the record.
//! - **Logging, `log: full`:** the log step builds the `q` record's fields (with a copy of
//!   `versions`), its reason and preview, serializes its JSON line and enqueues it, synchronously
//!   before `serve_with` returns. Its operations are the difference between a fixture with
//!   `log: full` and the same fixture with `log: off`: at most [`LOG_FULL_CEILING`] (32) on these
//!   fixtures, so at most 34 in all with the serving budget, and at most the measured
//!   per-fixture regression thresholds [`LOG_FULL_BLOCK`] and [`LOG_FULL_HIT`]. These are
//!   baseline regression budgets for these fixtures, not a maximum for every configuration:
//!   richer previews, longer names and larger bundle-version sets allocate more.
//!
//! **Method:** one test in its own binary, since the counting allocator is global. The edge runs
//! on a current-thread runtime and each measured query is polled once, synchronously, so none of
//! its background tasks runs inside a measurement: transport and task overhead (sockets, the
//! listener's task) and the shipping of log records to core aren't counted. Each fixture is
//! served three times first (first-use allocations: the device's bucket, the allow index,
//! matchers), then each count is the least of 7 runs, with inputs prepared and results dropped
//! outside the count.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod dnsh;

use std::alloc::System;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use futures_util::FutureExt as _;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

use picket_api::logs::Proto;
use picket_edge::dns::cache::{Entry, KeyRef};
use picket_edge::dns::pipeline::{self, Admitted, Inbound};
use picket_edge::edge::Edge;
use picket_edge::hooks::{Activation, ActivationTarget, Activator};
use picket_rules::matcher::BundleAction;
use picket_wire::{AnswerLimits, CacheValue, SentQuery};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// The most allocation operations the log step may add on the baseline fixtures (`log: full`
/// over `log: off`).
const LOG_FULL_CEILING: usize = 32;
/// The log step's committed regression thresholds per fixture, measured with this metric
/// (allocations plus reallocations) at 26 (block reply) and 28 (cache hit), with and without
/// temporary allows, plus about 5 % rounded up. A change that needs more raises these in the same
/// commit, reviewed like code, within [`LOG_FULL_CEILING`].
const LOG_FULL_BLOCK: usize = 28;
const LOG_FULL_HIT: usize = 30;

async fn activate(edge: &Edge, log: &str, n: u8) {
    let cfg: picket_api::edge_config::EdgeConfig = serde_json::from_value(serde_json::json!({
        "default_profile": "default",
        "profiles": {"default": {"upstream": "g", "block": ["block-common"], "log": log}},
        "upstreams": {"up1": {"protocol": "udp", "ip": "127.0.0.1", "port": 9}},
        "upstream_groups": {"g": {"upstreams": ["up1"]}},
    }))
    .unwrap();
    let id = format!("{n:064x}");
    let t = ActivationTarget {
        object_id: id.clone(),
        config_version: id.clone(),
        config_hash: id,
        config: Arc::new(cfg),
        config_changed: true,
        from_disk: false,
    };
    assert_eq!(
        picket_edge::dns::activation::DnsActivator
            .activate(edge, &t)
            .await,
        Activation::Active
    );
    dnsh::set_bundles(
        edge,
        vec![(
            "block-common",
            dnsh::bundle(
                "block-common",
                BundleAction::Block,
                &["||ads.example.com^", "||tracker.example^"],
            ),
        )],
    );
}

/// A DNS allow for `device` (its address text) in `allows.json`, as the bypass API stores it.
fn stored_dns_allow(id: &str, device: &str, target: &str) -> picket_edge::allows::StoredAllow {
    serde_json::from_value(serde_json::json!({
        "allow_id": id, "kind": "dns", "device": device, "client": device,
        "target": target, "created_at": "2026-01-01T00:00:00.000000Z",
        "expires_at": "2099-01-01T00:00:00.000000Z",
    }))
    .unwrap()
}

/// Caches one checked upstream answer for www.example.com/A in the profile's group.
fn warm_cache(edge: &Edge) {
    let www = dnsh::Q::new("www.example.com", 1).bytes();
    let q = picket_wire::check_query(&www).unwrap();
    let answer = dnsh::answer(
        &www,
        &dnsh::Ans::records(vec![dnsh::a("www.example.com", "93.184.216.34", 300)]),
    );
    let sent = SentQuery {
        id: q.id,
        qname: q.qname().as_name(),
        qtype: 1,
        qclass: 1,
    };
    let scrubbed = picket_wire::check_answer(&answer, &sent, &AnswerLimits::default()).unwrap();
    let g = edge.dns.pool.group("g").unwrap();
    let key = KeyRef::new(q.qname().as_name(), 1, 1, false, false, "g", g.generation);
    edge.dns.resolver.cache.insert(
        key.to_owned(),
        Arc::new(Entry::new(
            CacheValue::new(scrubbed, SystemTime::now(), Instant::now()),
            "up1".into(),
        )),
    );
}

fn inbound(msg: &[u8]) -> Inbound<'_> {
    Inbound {
        msg,
        client: SocketAddr::from(([192, 168, 1, 140], 53000)),
        listener: "lan-dns",
        udp_payload: 1232,
        proto: Proto::Udp,
        named_profile: None,
        extension: false,
        internal: false,
        admitted: Admitted::Here,
    }
}

/// Serves `msg` once, polled synchronously, into a lent buffer; returns the reply's rcode.
fn serve(edge: &Edge, msg: &[u8], buf: Vec<u8>) -> (u16, Option<Vec<u8>>) {
    let out = pipeline::serve_with(edge, inbound(msg), buf)
        .now_or_never()
        .expect("answered without waiting");
    let reply = out.reply.expect("a reply");
    (u16::from(reply[3] & 0x0F), Some(reply))
}

/// The least count of allocation operations (allocations plus reallocations: a buffer that grows
/// counts each time it moves, as in `picket-wire`'s and `picket-bundle`'s budgets) of `f` over 7
/// runs, inputs prepared and the result dropped outside the count.
fn least<P, R>(mut prep: impl FnMut() -> P, mut f: impl FnMut(P) -> R) -> usize {
    (0..7)
        .map(|_| {
            let p = prep();
            let reg = Region::new(GLOBAL);
            let r = f(p);
            let s = reg.change();
            drop(r);
            s.allocations + s.reallocations
        })
        .min()
        .unwrap()
}

#[test]
fn cache_hit_and_block_reply_budgets_on_the_real_serving_path() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("dev")).unwrap();
    std::fs::write(dir.path().join("dev/edge.json"), br#"{"updates_enabled": false}"#).unwrap();
    rt.block_on(async {
        let running = picket_edge::service::start(
            picket_edge::service::Options {
                config: Some(dir.path().join("dev/edge.json")),
                data_dir: Some(dir.path().join("dev/edge")),
                runtime_dir: dir.path().join("dev/run"),
            },
            picket_edge::service::Tuning {
                platform: Some(picket_edge::paths::HostPlatform::Debian),
                clock: Some(picket_edge::clock::Clock::fixed(true)),
                service: Some(false),
                firmware_file: dir.path().join("none"),
                ..Default::default()
            },
            |_| {},
        )
        .await
        .unwrap();
        let edge = Arc::clone(&running.edge);
        let block_msg = dnsh::Q::new("x.ads.example.com", 1).bytes();
        let hit_msg = dnsh::Q::new("www.example.com", 1).bytes();
        let lend = || Vec::with_capacity(4096);
        // The `log: off` counts of the run just before, for the log step's increment.
        let mut unlogged: Option<(usize, usize)> = None;
        // (n, log, temporary allows): also measured with a non-empty `allows.json`, so ladder
        // step 1 looks the device up by its text (`DeviceKey::with_text`, on the stack).
        for (n, log, allows) in [
            (1u8, "off", false),
            (2, "full", false),
            (3, "off", true),
            (4, "full", true),
        ] {
            activate(&edge, log, n).await;
            warm_cache(&edge);
            if allows {
                for (id, device, target) in [
                    ("a1", "192.168.1.140", "allowed.example"),
                    ("a2", "192.168.1.99", "x.ads.example.com"),
                ] {
                    edge.allows.upsert(stored_dns_allow(id, device, target)).unwrap();
                }
            }
            // Warm-up: first-use allocations (the device's bucket, the allow index, matchers).
            for _ in 0..3 {
                assert_eq!(serve(&edge, &block_msg, lend()).0, 0, "blocked: null_ip NOERROR");
                assert_eq!(serve(&edge, &hit_msg, lend()).0, 0);
                tokio::task::yield_now().await;
            }
            let decode_block = least(|| (), |_| picket_wire::check_query(&block_msg).unwrap());
            let decode_hit = least(|| (), |_| picket_wire::check_query(&hit_msg).unwrap());
            let block = least(lend, |b| serve(&edge, &block_msg, b));
            let hit = least(lend, |b| serve(&edge, &hit_msg, b));
            eprintln!(
                "allocation operations per query, log {log}, allows {allows}: block reply {block} \
                 (decode {decode_block}), cache hit {hit} (decode {decode_hit})"
            );
            match log {
                "off" => {
                    assert!(block <= 2, "block reply, decoding included: {block}");
                    assert_eq!(
                        block, decode_block,
                        "a block reply after decoding allocates nothing"
                    );
                    assert!(hit <= 2, "cache hit, decoding included: {hit}");
                    assert_eq!(hit, decode_hit, "serving a hit after decoding allocates nothing");
                    unlogged = Some((block, hit));
                }
                _ => {
                    let (off_block, off_hit) = unlogged.take().expect("the log: off run comes first");
                    let (log_block, log_hit) = (block - off_block, hit - off_hit);
                    eprintln!(
                        "  log step (full over off), allows {allows}: block reply {log_block}, cache hit {log_hit}"
                    );
                    for (what, n, threshold) in [
                        ("block reply", log_block, LOG_FULL_BLOCK),
                        ("cache hit", log_hit, LOG_FULL_HIT),
                    ] {
                        assert!(
                            n <= LOG_FULL_CEILING,
                            "{what}'s log step: {n} operations, over the ceiling of {LOG_FULL_CEILING}"
                        );
                        assert!(
                            n <= threshold,
                            "{what}'s log step: {n} operations, over its regression threshold of {threshold}"
                        );
                    }
                }
            }
        }
        drop(edge);
        running.shutdown().await;
    });
}
