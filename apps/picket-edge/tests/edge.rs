//! End-to-end tests of the edge foundation against an in-process mock core (build-and-test.md
//! §5 rows: Edge conditions (edge side), Convergence, Edge requests, Development edge, Metrics,
//! log shipping and spool, mTLS/TOFU on the edge side, self-update result import).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use picket_api::edge_config::RevokedAllows;
use picket_api::logs::Decision;
use picket_api::time::Timestamp;
use picket_edge::edge::{CoreState, Edge};
use picket_edge::hooks::{RequestHandler, SelfCheck};
use picket_edge::service::{self, Options, Running, Tuning};
use support::{MockCore, wait_until, write_edge_json};

const T: Duration = Duration::from_secs(10);

struct Dirs {
    _tmp: tempfile::TempDir,
    config: PathBuf,
    data: PathBuf,
    run: PathBuf,
    result: PathBuf,
}

fn dirs() -> Dirs {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Dirs {
        config: root.join("dev/edge.json"),
        data: root.join("dev/edge"),
        run: root.join("dev/run"),
        result: root.join("bin/update-result.json"),
        _tmp: tmp,
    }
}

fn tuning(d: &Dirs) -> Tuning {
    let mut t = Tuning {
        platform: Some(picket_edge::paths::HostPlatform::Debian),
        clock: Some(picket_edge::clock::Clock::fixed(true)),
        update_result: Some(d.result.clone()),
        service: Some(false),
        firmware_file: d.data.join("no-such-version-file"),
        import_every: Duration::from_millis(200),
        ..Default::default()
    };
    t.session.heartbeat = Duration::from_millis(200);
    t.session.backoff_min = Duration::from_millis(50);
    t.session.backoff_max = Duration::from_millis(200);
    t.convergence.retry_min = Duration::from_millis(50);
    t.convergence.retry_max = Duration::from_millis(200);
    t.shipper.tick = Duration::from_millis(50);
    t.shipper.retry_min = Duration::from_millis(20);
    t.shipper.retry_max = Duration::from_millis(100);
    t.supervisor.min = Duration::from_millis(20);
    // Tests that run as UniFi read no UniFi files of this host (edge-unifi.md §7).
    t.unifi.dnsfilter = d.data.join("no-dnsfilter");
    t.unifi.dnsmasq = vec![];
    t
}

async fn start(d: &Dirs, t: Tuning, install: impl FnOnce(&picket_edge::hooks::Hooks)) -> Running {
    service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        t,
        install,
    )
    .await
    .unwrap()
}

/// Counts request applications; can be told to fail.
#[derive(Default)]
struct Counting {
    dns: AtomicU32,
    lookups: AtomicU32,
    revokes: AtomicU32,
    fail_dns: AtomicU32,
}

struct CountingHandler(Arc<Counting>);

#[async_trait]
impl RequestHandler for CountingHandler {
    async fn flush_dns(&self, _e: &Edge) -> anyhow::Result<()> {
        if self.0.fail_dns.load(Ordering::SeqCst) > 0 {
            self.0.fail_dns.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("cache busy");
        }
        self.0.dns.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn flush_lookups(&self, _e: &Edge, _p: &str) -> anyhow::Result<()> {
        self.0.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn flush_all_lookups(&self, _e: &Edge) -> anyhow::Result<()> {
        Ok(())
    }
    async fn revoke_allows(&self, e: &Edge, l: &RevokedAllows) -> anyhow::Result<()> {
        self.0.revokes.fetch_add(1, Ordering::SeqCst);
        picket_edge::convergence::DefaultRequests
            .revoke_allows(e, l)
            .await
    }
}

fn config_doc(cache_mib: u32, flush_dns: Option<&str>, extra: serde_json::Value) -> serde_json::Value {
    let mut v = json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
        "listeners": [{"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"}],
        "default_profile": "default",
        "profiles": {"default": {}},
        "cache": {"size_mib": cache_mib},
        "logging": {"spool_after_s": 1, "batch_max": 1000},
        "flush": {"dns": flush_dns, "lookups": {}},
    });
    if let (Some(m), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        for (k, x) in e {
            m.insert(k.clone(), x.clone());
        }
    }
    v
}

fn events(core: &MockCore, kind: &str) -> Vec<serde_json::Value> {
    core.with(|s| {
        s.logs
            .iter()
            .filter(|l| l["t"] == "event" && l["kind"] == kind)
            .cloned()
            .collect()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_hello_welcome_heartbeats_and_changed() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({"allowed_binds": ["127.0.0.1:0"]}));
    let id = core.set_config(&config_doc(8, None, json!({})));
    let r = start(&d, tuning(&d), |_| {}).await;
    let edge = Arc::clone(&r.edge);

    assert!(
        wait_until(T, || core.with(|s| !s.hellos.is_empty())).await,
        "hello"
    );
    let h = core.with(|s| s.hellos[0].clone());
    assert_eq!(h.edge_version, picket_api::VERSION);
    assert_eq!(h.platform, "debian");
    assert_eq!(h.boot, edge.boot);
    assert_eq!(h.starts, 1, "first start since a session");
    assert_eq!(h.allowed_binds, vec!["127.0.0.1:0"]);
    assert!(!h.updates_enabled);
    assert_eq!(h.have.release.as_deref(), Some(picket_api::VERSION));
    assert!(!h.arch.is_empty() && !h.kernel.is_empty());
    assert!(h.firmware.is_none(), "null off UniFi");
    assert!(h.mem_total.is_some());
    assert!(
        core.with(|s| s.client_fps.contains(&edge.identity.fingerprint)),
        "mTLS with the edge key"
    );

    // Welcome: connected, starts reset, the config object fetched without If-None-Match.
    assert!(wait_until(T, || edge.session.load().state == CoreState::Connected).await);
    assert!(wait_until(T, || edge.state.get().starts == 0).await);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    assert_eq!(core.with(|s| s.fetches[0].clone()), None);
    assert_eq!(edge.session.load().core_version.as_deref(), Some("0.1.0"));

    // Heartbeats with running totals and the versions block.
    assert!(wait_until(T, || core.with(|s| s.heartbeats.len() >= 2)).await);
    let hb = core.with(|s| s.heartbeats.last().unwrap().clone());
    assert_eq!(hb.boot, edge.boot);
    assert_eq!(
        hb.versions.as_ref().unwrap().config,
        picket_api::ids::short_id(&id)
    );
    assert_eq!(hb.have.config, vec![id.clone()]);
    assert_eq!(hb.have.fetched.as_deref(), Some(id.as_str()));
    // ready_version is set once the config's listener is bound (edge.md §3 step 6, §14).
    assert!(
        wait_until(T, || core.with(|s| {
            s.heartbeats
                .last()
                .is_some_and(|h| h.ready_version.as_deref() == Some(picket_api::VERSION))
        }))
        .await
    );
    assert!(hb.rss.is_some() && hb.cpu_ms.edge.is_some());
    assert!(hb.disk.data_dir.is_some() && hb.disk.ssd_dir.is_none());
    assert!(hb.cpu_ms.helper.is_none() && hb.fw.is_none(), "no helper");
    for k in ["buffer_full", "evicted", "too_old", "rejected"] {
        assert!(hb.logs.dropped.contains_key(k), "{k}");
    }
    // Running totals: never reset by a heartbeat.
    edge.metrics.count_decision(Decision::Block);
    edge.metrics.count_decision(Decision::Allow);
    let before = core.with(|s| s.heartbeats.len());
    assert!(wait_until(T, || core.with(|s| s.heartbeats.len() >= before + 2)).await);
    let (a, b) = core.with(|s| {
        let n = s.heartbeats.len();
        (
            s.heartbeats[n - 2].metrics.queries,
            s.heartbeats[n - 1].metrics.queries,
        )
    });
    assert_eq!((a, b), (2, 2), "the totals stay; a lost heartbeat loses nothing");

    // `changed` → a fetch with If-None-Match (304).
    let n = core.with(|s| s.fetches.len());
    core.changed(&id);
    assert!(wait_until(T, || core.with(|s| s.fetches.len() > n)).await);
    assert_eq!(core.with(|s| s.fetches.last().unwrap().clone()), Some(id.clone()));

    // A config change outside the runtime fields: activated, stored, reported.
    let id2 = core.set_config(&config_doc(16, None, json!({})));
    core.changed(&id2);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id2.as_str())).await);
    // The swap comes first; the config file, state.json and the event follow it.
    let short2 = picket_api::ids::short_id(&id2).to_owned();
    assert!(
        wait_until(T, || events(&core, "activated")
            .iter()
            .any(|e| e["config"] == short2.as_str()))
        .await
    );
    let st = edge.state.get();
    assert_eq!(st.configs.len(), 2);
    assert_eq!(st.configs[0].object, id2);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_apply_once_collapse_and_survive_restarts() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let counts = Arc::new(Counting::default());

    // An allow core will revoke.
    std::fs::create_dir_all(&d.data).unwrap();
    let now = Timestamp::now();
    let allows = json!({"version": 1, "allows": [{
        "allow_id": "a-19", "kind": "ip", "device": "aa:bb:cc:dd:ee:02", "client": "192.168.1.140",
        "target": "100.100.100.100", "created_at": picket_api::time::format_micros(&now),
        "expires_at": picket_api::time::format_micros(&(now + jiff::SignedDuration::from_hours(1)))}]});
    std::fs::write(d.data.join("allows.json"), allows.to_string()).unwrap();

    let id1 = core.set_config(&config_doc(
        8,
        Some("1111111111111111"),
        json!({"revoked_allows": {"id": "9c41e7a02b5d83f6", "allows": ["a-19", "a-unknown"]},
               "flush": {"dns": "1111111111111111", "lookups": {"am-rt": "07b3d9e15a4c62f8"}},
               "lookup_providers": {"am-rt": {"module": "http_json", "config": {}, "cache_generation": "3f9a0c17d2e84b65"}}}),
    ));
    let c = Arc::clone(&counts);
    let r = start(&d, tuning(&d), move |h| {
        h.set_requests(Box::new(CountingHandler(c)))
    })
    .await;
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.state.get().applied.revoked_allows.as_deref()
            == Some("9c41e7a02b5d83f6"))
        .await
    );
    let st = edge.state.get();
    assert_eq!(st.applied.flush_dns.as_deref(), Some("1111111111111111"));
    assert_eq!(
        st.applied.flush_lookups.get("am-rt").map(String::as_str),
        Some("07b3d9e15a4c62f8")
    );
    assert_eq!(counts.dns.load(Ordering::SeqCst), 1);
    assert!(edge.allows.list().is_empty(), "a-19 revoked; a-unknown ignored");
    assert!(
        wait_until(T, || core.with(|s| s.logs.iter().any(|l| l["t"] == "allow"
            && l["action"] == "revoked"
            && l["via"] == "core"
            && l["allow_id"] == "a-19")))
        .await
    );
    // Same object again (a periodic fetch, a 304): nothing repeats.
    core.changed(&id1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(counts.dns.load(Ordering::SeqCst), 1);
    assert_eq!(counts.revokes.load(Ordering::SeqCst), 1);
    r.shutdown().await;

    // Offline: several flushes requested meanwhile collapse into one on reconnect.
    core.set_config(&config_doc(8, Some("2222222222222222"), json!({})));
    let _id3 = core.set_config(&config_doc(8, Some("3333333333333333"), json!({})));
    let c = Arc::clone(&counts);
    let r = start(&d, tuning(&d), move |h| {
        h.set_requests(Box::new(CountingHandler(c)))
    })
    .await;
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.state.get().applied.flush_dns.as_deref()
            == Some("3333333333333333"))
        .await
    );
    assert_eq!(
        counts.dns.load(Ordering::SeqCst),
        2,
        "one flush for the collapsed requests"
    );
    assert!(
        edge.state.get().applied.flush_lookups.is_empty(),
        "providers no longer named are pruned"
    );
    r.shutdown().await;

    // A restart repeats nothing.
    let c = Arc::clone(&counts);
    let r = start(&d, tuning(&d), move |h| {
        h.set_requests(Box::new(CountingHandler(c)))
    })
    .await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.session.load().state == CoreState::Connected).await);
    assert!(wait_until(T, || core.with(|s| s.fetches.len() >= 4)).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(counts.dns.load(Ordering::SeqCst), 2);

    // A core restored from a backup with an older id: compared by equality, applied once more.
    let id5 = core.set_config(&config_doc(8, Some("1111111111111111"), json!({})));
    core.changed(&id5);
    assert!(
        wait_until(T, || edge.state.get().applied.flush_dns.as_deref()
            == Some("1111111111111111"))
        .await
    );
    assert_eq!(counts.dns.load(Ordering::SeqCst), 3);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_requests_retry_after_304_and_restart_fetches_whole() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let counts = Arc::new(Counting::default());
    counts.fail_dns.store(1, Ordering::SeqCst);
    let id = core.set_config(&config_doc(8, Some("4444444444444444"), json!({})));
    let c = Arc::clone(&counts);
    let r = start(&d, tuning(&d), move |h| {
        h.set_requests(Box::new(CountingHandler(c)))
    })
    .await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || core.with(|s| !s.fetches.is_empty())).await);
    assert!(
        edge.state.get().applied.flush_dns.is_none(),
        "the first attempt failed"
    );
    // The object hasn't changed: the next fetch is a 304, and the request is still retried.
    core.changed(&id);
    assert!(
        wait_until(T, || edge.state.get().applied.flush_dns.as_deref()
            == Some("4444444444444444"))
        .await
    );
    assert!(
        core.with(|s| s.fetches.iter().any(|f| f.as_deref() == Some(id.as_str()))),
        "a 304 round"
    );
    r.shutdown().await;

    // After a restart the edge holds no object, so it asks without If-None-Match.
    let before = core.with(|s| s.fetches.len());
    let r = start(&d, tuning(&d), |_| {}).await;
    assert!(wait_until(T, || core.with(|s| s.fetches.len() > before)).await);
    assert_eq!(core.with(|s| s.fetches[before].clone()), None);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn starts_from_state_json_while_core_is_down() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&config_doc(12, None, json!({})));
    let r = start(&d, tuning(&d), |_| {}).await;
    assert!(wait_until(T, || r.edge.active().object_id.as_deref() == Some(id.as_str())).await);
    let hash = r.edge.active().config_hash.clone().unwrap();
    assert!(
        wait_until(T, || r
            .edge
            .state
            .get()
            .configs
            .first()
            .is_some_and(|c| c.hash == hash))
        .await
    );
    // The config can arrive over REST before the session's `welcome`, which resets `starts`
    // (edge.md §11): wait for it, so the count below starts from this session.
    assert!(
        wait_until(T, || r.edge.session.load().state == CoreState::Connected
            && r.edge.state.get().starts == 0)
        .await
    );
    r.shutdown().await;
    drop(core);

    // Core gone: the edge runs the stored config from disk and counts starts.
    let r = start(&d, tuning(&d), |_| {}).await;
    let a = r.edge.active();
    assert_eq!(a.config_hash.as_deref(), Some(hash.as_str()));
    assert_eq!(a.config.as_ref().unwrap().cache.size_mib, 12);
    assert_eq!(
        a.versions.as_ref().unwrap().config,
        picket_api::ids::short_id(&id)
    );
    assert!(r.edge.state.get().starts >= 1);
    r.shutdown().await;
    let r = start(&d, tuning(&d), |_| {}).await;
    assert_eq!(
        r.edge.state.get().starts,
        2,
        "starts since the last session keep counting"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundles_wait_and_bad_objects_leave_the_active_config_running() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&config_doc(8, None, json!({})));
    let r = start(&d, tuning(&d), |_| {}).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    // An object naming a bundle can't go live in this build: activation_failed, retried.
    let b = core.set_config(&config_doc(
        8,
        None,
        json!({"bundles": {"block-common": "a".repeat(64)}}),
    ));
    core.changed(&b);
    assert!(wait_until(T, || !events(&core, "activation_failed").is_empty()).await);
    assert_eq!(edge.active().object_id.as_deref(), Some(id.as_str()));
    assert_eq!(
        edge.convergence.load().in_progress,
        None,
        "bundles-only change: same config"
    );
    // An object whose config doesn't parse: the active one keeps running; its event once.
    let bad = core.set_config(&json!({"listeners": "nope", "flush": {"dns": "5555555555555555"}}));
    core.changed(&bad);
    assert!(
        wait_until(T, || edge.state.get().applied.flush_dns.as_deref()
            == Some("5555555555555555"))
        .await
    );
    assert_eq!(edge.active().object_id.as_deref(), Some(id.as_str()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let fails = events(&core, "activation_failed");
    assert_eq!(
        fails.iter().filter(|e| e["stage"] == "parse").count(),
        1,
        "{fails:?}"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_mismatch_is_refused() {
    let core = MockCore::start().await;
    let d = dirs();
    let other = support::core_identity();
    write_edge_json(
        &d.config,
        None,
        json!({"core_url": core.url(), "core_key": other.fingerprint}),
    );
    let r = start(&d, tuning(&d), |_| {}).await;
    assert!(wait_until(T, || r.edge.session.load().state == CoreState::KeyMismatch).await);
    assert!(core.with(|s| s.hellos.is_empty() && s.fetches.is_empty()));
    let err = r.edge.session.load().last_error.clone().unwrap();
    assert!(err.contains(&core.id.fingerprint), "{err}");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logs_carry_answers_spool_while_core_fails_and_drain_in_order() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    core.set_config(&config_doc(8, None, json!({})));
    let r = start(&d, tuning(&d), |_| {}).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().config.is_some()).await);

    let ans = picket_edge::logs::Answer::new(bytes::Bytes::from_static(b"\x12\x34scrubbed-answer")).unwrap();
    let mut q = sample_q();
    q.decision = Decision::Allow;
    for _ in 0..3 {
        edge.logs.emit_query(
            q.clone(),
            picket_edge::logs::AnswerSlot::Attached(Arc::clone(&ans)),
        );
    }
    assert!(
        wait_until(T, || core.with(|s| s
            .logs
            .iter()
            .filter(|l| l["t"] == "q")
            .count()
            >= 3))
        .await
    );
    core.with(|s| {
        let first_q = s.logs.iter().position(|l| l["t"] == "q").unwrap();
        let first_a = s
            .logs
            .iter()
            .position(|l| l["t"] == "answer" && l["id"] == ans.id.as_str())
            .unwrap();
        assert!(first_a < first_q, "the answer travels ahead of its first record");
        assert_eq!(s.logs[first_q]["answer_id"], ans.id.as_str());
        assert_eq!(s.logs[first_q]["boot"], edge.boot.as_str());
    });

    // Core fails: after spool_after_s (1 s) the records go to the spool.
    core.with(|s| s.log_default = 503);
    for i in 0..5 {
        edge.logs
            .event("test", picket_edge::logs::fields(&[("n", i.into())]));
    }
    assert!(wait_until(T, || edge.log_control.status.load().spool_segments > 0).await);
    assert!(d.data.join("spool/security").read_dir().unwrap().next().is_some());
    // Back: the spool drains oldest first, then shipping returns to memory.
    core.with(|s| s.log_default = 200);
    assert!(
        wait_until(T, || edge.log_control.status.load().spool_segments == 0
            && edge.log_control.status.load().mode == "memory")
        .await
    );
    let ns: Vec<i64> = core.with(|s| {
        s.logs
            .iter()
            .filter(|l| l["kind"] == "test")
            .map(|l| l["n"].as_i64().unwrap())
            .collect()
    });
    assert_eq!(ns, vec![0, 1, 2, 3, 4]);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whole_batch_rejects_split_and_events_made_offline_arrive_after_restart() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    core.set_config(&config_doc(8, None, json!({})));
    let r = start(&d, tuning(&d), |_| {}).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().config.is_some()).await);
    assert!(wait_until(T, || core.with(|s| s.log_batches >= 1)).await); // the activation event
    // 413 for the whole batch, then 400 for one half: split, resent, all arrive.
    core.with(|s| s.log_script.extend([413, 400]));
    for i in 0..4 {
        edge.logs
            .event("split", picket_edge::logs::fields(&[("n", i.into())]));
    }
    assert!(
        wait_until(T, || core.with(|s| s
            .logs
            .iter()
            .filter(|l| l["kind"] == "split")
            .count()
            == 4))
        .await
    );
    r.shutdown().await;

    // Events made while core is down spool at shutdown and arrive after the restart.
    core.with(|s| s.log_default = 503);
    let r = start(&d, tuning(&d), |_| {}).await;
    r.edge.logs.event("offline", picket_edge::logs::fields(&[]));
    r.edge
        .conditions
        .set(picket_api::session::condition_kind::MEMORY_LOW, None, None);
    tokio::time::sleep(Duration::from_millis(200)).await;
    r.shutdown().await;
    assert!(core.with(|s| !s.logs.iter().any(|l| l["kind"] == "offline")));
    core.with(|s| s.log_default = 200);
    let r = start(&d, tuning(&d), |_| {}).await;
    assert!(wait_until(T, || core.with(|s| s.logs.iter().any(|l| l["kind"] == "offline"))).await);
    assert!(core.with(|s| {
        s.logs
            .iter()
            .any(|l| l["t"] == "condition" && l["kind"] == "memory_low" && l["change"] == "appeared")
    }));
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conditions_ride_in_hello_and_heartbeats() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let r = start(&d, tuning(&d), |_| {}).await;
    let edge = Arc::clone(&r.edge);
    edge.conditions.set(
        picket_api::session::condition_kind::UPSTREAM_DOWN,
        Some("cloudflare"),
        None,
    );
    assert!(
        wait_until(T, || core.with(|s| s
            .heartbeats
            .last()
            .is_some_and(|h| h.conditions.iter().any(|c| c.kind == "upstream_down"))))
        .await
    );
    edge.conditions.clear(
        picket_api::session::condition_kind::UPSTREAM_DOWN,
        Some("cloudflare"),
    );
    assert!(
        wait_until(T, || core
            .with(|s| s.heartbeats.last().is_some_and(|h| h.conditions.is_empty())))
        .await
    );
    assert!(
        wait_until(T, || core.with(|s| s
            .logs
            .iter()
            .filter(|l| l["t"] == "condition" && l["kind"] == "upstream_down")
            .count()
            == 2))
        .await
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn development_edge_runs_as_an_ordinary_user_and_status_works() {
    let d = dirs();
    // pipelines.md §9: the developer's own edge.json, no core, no Picket accounts or services.
    write_edge_json(&d.config, None, json!({"allowed_binds": ["127.0.0.1:5353"]}));
    let r = start(&d, tuning(&d), |_| {}).await;
    let sock = d.run.join("edge.sock");
    assert_eq!(picket_edge::admin::socket_mode(&sock).unwrap().0, 0o600);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&d.run).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let v = picket_edge::admin::call(&sock, "status", json!({}))
        .await
        .unwrap();
    assert_eq!(v["edge_version"], picket_api::VERSION);
    assert_eq!(v["core"]["state"], "not_set_up");
    assert_eq!(v["listeners"], json!([]));
    assert!(v["firewall"].is_null());
    assert_eq!(v["fingerprint"], r.edge.identity.fingerprint.as_str());
    // `explain` works offline, but needs a config to explain against.
    let e = picket_edge::admin::call(&sock, "explain", json!({"name": "x"}))
        .await
        .unwrap_err();
    assert!(
        matches!(e, picket_edge::admin::CallError::Remote(ref a) if a.code == "not_ready"),
        "{e}"
    );
    // `update --check` with no config: nothing is offered, so nothing is installable.
    let v = picket_edge::admin::call(&sock, "update", json!({"check": true}))
        .await
        .unwrap();
    assert_eq!(v["running"], picket_api::VERSION);
    assert_eq!(v["installable"], false);
    assert!(v["offered"].is_null());
    let v = picket_edge::admin::call(&sock, "flush", json!({})).await.unwrap();
    assert_eq!(v["dns"], true);
    let v = picket_edge::admin::call(&sock, "allows.list", json!({}))
        .await
        .unwrap();
    assert_eq!(v, json!([]));
    r.shutdown().await;
    assert!(!sock.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_results_import_once_even_with_a_bad_version() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    std::fs::create_dir_all(d.result.parent().unwrap()).unwrap();
    std::fs::write(
        &d.result,
        json!({"result_id": "a1b2c3d4e5f60718", "request_id": "6666666666666666", "outcome": "failed",
               "stage": "readiness", "version": "", "at": picket_api::time::format_micros(&Timestamp::now())})
        .to_string(),
    )
    .unwrap();
    let r = start(&d, tuning(&d), |_| {}).await;
    let edge = Arc::clone(&r.edge);
    assert_eq!(
        edge.state.get().applied.install_now.as_deref(),
        Some("6666666666666666"),
        "recorded at start"
    );
    assert!(
        wait_until(T, || edge
            .state
            .get()
            .update
            .as_ref()
            .is_some_and(|u| u.result_id == "a1b2c3d4e5f60718"))
        .await
    );
    let evs = events(&core, "update_failed");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0]["stage"], "readiness");
    assert_eq!(evs[0]["version"], "");
    // hello/heartbeats carry it as `update`.
    assert!(
        wait_until(T, || core
            .with(|s| s.heartbeats.last().is_some_and(|h| h.update.is_some())))
        .await
    );
    r.shutdown().await;
    // One result across restarts: imported once.
    let r = start(&d, tuning(&d), |_| {}).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(events(&core, "update_failed").len(), 1);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tofu_setup_pins_only_a_verified_key() {
    let core = MockCore::start().await;
    let d = dirs();
    let common = picket_edge::cli::Common {
        config: Some(d.config.clone()),
        data_dir: Some(d.data.clone()),
        runtime_dir: d.run.clone(),
    };
    std::fs::create_dir_all(d.config.parent().unwrap()).unwrap();
    std::fs::write(&d.config, br#"{"updates_enabled": false, "x-keep": 1}"#).unwrap();
    // Declined: nothing written.
    let e = picket_edge::cli::setup(&common, Some(core.url()), None, None, false, &mut &b"n\n"[..])
        .await
        .unwrap_err();
    assert!(e.to_string().contains("not trusted"));
    assert!(!std::fs::read_to_string(&d.config).unwrap().contains("core_key"));
    // Accepted: the verified fingerprint is pinned, other fields kept.
    picket_edge::cli::setup(
        &common,
        Some(core.url()),
        None,
        Some("ucg-fiber".into()),
        false,
        &mut &b"y\n"[..],
    )
    .await
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&d.config).unwrap()).unwrap();
    assert_eq!(v["core_key"], core.id.fingerprint.as_str());
    assert_eq!(v["x-keep"], 1);
    let id = picket_edge::identity::load_existing(&picket_edge::paths::DataLayout::new(&d.data)).unwrap();
    assert_eq!(id.name, "ucg-fiber");
    // A name instead of an IP literal is refused, and an IPv4 address not written as a dotted
    // quad (octal here: it would dial 192.168.1.16).
    for bad in ["https://core.lan:7443", "https://192.168.1.020:7443"] {
        assert!(
            picket_edge::cli::setup(&common, Some(bad.into()), None, None, true, &mut &b""[..])
                .await
                .is_err(),
            "{bad}"
        );
    }
    // A server whose handshake isn't signed by the key it presents: no fingerprint is taken.
    let liar = MockCore::start_with(support::core_identity(), Some(())).await;
    let url = picket_edge::local_config::CoreUrl::parse(&liar.url()).unwrap();
    assert!(picket_edge::cli::tofu_fingerprint(&url, &id).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn firmware_self_check_holds_its_condition_across_restarts() {
    struct Flag(Arc<std::sync::atomic::AtomicBool>);
    #[async_trait]
    impl SelfCheck for Flag {
        fn name(&self) -> &'static str {
            "listeners"
        }
        async fn passes(&self, _e: &Edge) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }
    let d = dirs();
    write_edge_json(&d.config, None, json!({}));
    let fw = d.data.join("version");
    std::fs::create_dir_all(&d.data).unwrap();
    std::fs::write(&fw, "UCGF.ipq9574.v6.0.17.1\n").unwrap();
    let mk = |d: &Dirs| {
        let mut t = tuning(d);
        t.platform = Some(picket_edge::paths::HostPlatform::Unifi);
        t.firmware_file = fw.clone();
        t.firmware.window = Duration::from_millis(100);
        t.firmware.during = Duration::from_millis(20);
        t.firmware.after = Duration::from_millis(50);
        t
    };
    // First start records the firmware.
    let r = start(&d, mk(&d), |_| {}).await;
    assert!(
        wait_until(T, || r.edge.state.get().firmware.last.as_deref()
            == Some("UCGF.ipq9574.v6.0.17.1"))
        .await
    );
    r.shutdown().await;
    // A firmware change with a failing check: the condition after the window, the result kept.
    std::fs::write(&fw, "UCGF.ipq9574.v6.0.18.2\n").unwrap();
    let ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let o = Arc::clone(&ok);
    let r = start(&d, mk(&d), move |h| h.add_self_check(Arc::new(Flag(o)))).await;
    let kind = picket_api::session::condition_kind::FIRMWARE_CHECK_FAILED;
    assert!(wait_until(T, || r.edge.conditions.is_set(kind, None)).await);
    let c = r
        .edge
        .conditions
        .snapshot()
        .into_iter()
        .find(|c| c.kind == kind)
        .unwrap();
    assert_eq!(c.detail.unwrap()["failed"], json!(["listeners"]));
    assert!(r.edge.state.get().firmware.check.is_some());
    assert_eq!(
        r.edge.state.get().firmware.last.as_deref(),
        Some("UCGF.ipq9574.v6.0.17.1")
    );
    r.shutdown().await;
    // After a restart the failed result holds the condition from the start, until a pass.
    let mut t = mk(&d);
    t.firmware.window = Duration::from_secs(3600);
    let o = Arc::clone(&ok);
    let r = start(&d, t, move |h| h.add_self_check(Arc::new(Flag(o)))).await;
    assert!(wait_until(T, || r.edge.conditions.is_set(kind, None)).await);
    ok.store(true, Ordering::SeqCst);
    assert!(wait_until(T, || !r.edge.conditions.is_set(kind, None)).await);
    assert_eq!(
        r.edge.state.get().firmware.last.as_deref(),
        Some("UCGF.ipq9574.v6.0.18.2")
    );
    assert!(r.edge.state.get().firmware.check.is_none());
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_is_a_new_boot_with_totals_from_zero() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let r = start(&d, tuning(&d), |_| {}).await;
    r.edge.metrics.count_decision(Decision::Allow);
    let boot1 = r.edge.boot.clone();
    assert!(
        wait_until(T, || core
            .with(|s| s.heartbeats.iter().any(|h| h.metrics.queries == 1)))
        .await
    );
    r.shutdown().await;
    let r = start(&d, tuning(&d), |_| {}).await;
    assert_ne!(r.edge.boot, boot1);
    let boot2 = r.edge.boot.clone();
    assert!(wait_until(T, || core.with(|s| s.heartbeats.iter().any(|h| h.boot == boot2))).await);
    let hb = core.with(|s| {
        s.heartbeats
            .iter()
            .rev()
            .find(|h| h.boot == boot2)
            .cloned()
            .unwrap()
    });
    assert_eq!(hb.metrics.queries, 0);
    // Record seqs start again under the new boot.
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downloads_verify_blake3_and_size_and_csr_posts() {
    let core = MockCore::start().await;
    let d = dirs();
    let layout = picket_edge::paths::DataLayout::new(&d.data);
    std::fs::create_dir_all(&d.data).unwrap();
    let id = picket_edge::identity::load_or_create(&layout).unwrap();
    let url = picket_edge::local_config::CoreUrl::parse(&core.url()).unwrap();
    let client = picket_edge::core_client::CoreClient::new(url, &id, &core.id.fingerprint).unwrap();
    let good = vec![7u8; 100_000];
    let good_id = picket_api::ids::object_id(&good);
    let bad_id = picket_api::ids::object_id(b"something else");
    core.with(|s| {
        s.objects.insert(format!("blobs/{good_id}"), good.clone());
        s.objects.insert(format!("blobs/{bad_id}"), good.clone());
    });
    let dir = d.data.join("bundles");
    std::fs::create_dir_all(&dir).unwrap();
    let p = client
        .download_object(&format!("blobs/{good_id}"), &dir, &good_id, 1 << 20)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), good);
    let e = client
        .download_object(&format!("blobs/{bad_id}"), &dir, &bad_id, 1 << 20)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("blake3"), "{e}");
    let e = client
        .download_object(&format!("blobs/{good_id}"), &dir, &good_id, 1000)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("over"), "{e}");
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![good_id.clone()],
        "no temporary file or bad blob left behind"
    );
    assert!(matches!(
        client
            .download_object("blobs/missing", &dir, &good_id, 1 << 20)
            .await,
        Err(picket_edge::core_client::ClientError::NotFound)
    ));
    assert!(client.get_object("../etc/passwd", None, 10).await.is_err());
    let r = client
        .post_csr(&picket_api::edge_api::CsrRequest {
            csr_pem: "pem".into(),
            listener: "lan-doh".into(),
        })
        .await
        .unwrap();
    assert_eq!(r.not_after, "2027-12-01T00:00:00Z");
    assert_eq!(core.with(|s| s.csrs[0]["listener"].clone()), "lan-doh");
    // Pinned to another key: refused as a key mismatch, not "unreachable".
    let other = support::core_identity();
    let url = picket_edge::local_config::CoreUrl::parse(&core.url()).unwrap();
    let wrong = picket_edge::core_client::CoreClient::new(url, &id, &other.fingerprint).unwrap();
    match wrong.get_object("configs/x.json", None, 10).await {
        Err(picket_edge::core_client::ClientError::KeyMismatch { presented }) => {
            assert_eq!(presented, core.id.fingerprint)
        }
        other => panic!("{other:?}"),
    }
    // Nothing listening: unreachable, never a mismatch (even after one).
    drop(core);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(matches!(
        wrong.get_object("configs/x.json", None, 10).await,
        Err(picket_edge::core_client::ClientError::Unreachable(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnects_keep_open_conditions_and_hello_counts_starts_during_an_outage() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    core.set_config(&config_doc(8, None, json!({})));
    let r = start(&d, tuning(&d), |_| {}).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || core.with(|s| s.hellos.len() == 1)).await);
    assert!(wait_until(T, || core.with(|s| !s.fetches.is_empty())).await);
    // The listener manager has reconciled this config (it clears `listener_failed` for listeners
    // the config doesn't name), so nothing else touches the condition set below.
    assert!(wait_until(T, || !edge.dns.listeners.local_addrs("lan-dns").is_empty()).await);
    let fetches = core.with(|s| s.fetches.len());
    edge.conditions.set(
        picket_api::session::condition_kind::LISTENER_FAILED,
        Some("lan-dot"),
        None,
    );
    // Core drops the session: the edge reconnects, says hello again and fetches again.
    core.kick();
    assert!(
        wait_until(T, || core.with(|s| s.hellos.len() == 2)).await,
        "reconnected"
    );
    let h = core.with(|s| s.hellos[1].clone());
    assert_eq!(h.starts, 0);
    assert_eq!(h.boot, edge.boot, "same process, same boot");
    assert!(
        h.conditions
            .iter()
            .any(|c| c.kind == "listener_failed" && c.key.as_deref() == Some("lan-dot")),
        "a lost session clears nothing"
    );
    assert!(wait_until(T, || core.with(|s| s.fetches.len() > fetches)).await);
    r.shutdown().await;

    // Two starts while core is down.
    let id = core.id.same();
    drop(core);
    for _ in 0..2 {
        let r = start(&d, tuning(&d), |_| {}).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        r.shutdown().await;
    }
    // Core is back with its key (at a new address): hello carries the starts since the session.
    let core = MockCore::start_with(id, None).await;
    write_edge_json(&d.config, Some(&core), json!({}));
    let r = start(&d, tuning(&d), |_| {}).await;
    assert!(wait_until(T, || core.with(|s| !s.hellos.is_empty())).await);
    assert_eq!(core.with(|s| s.hellos[0].starts), 3);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_config_object_is_fetched_periodically_without_changed() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id1 = core.set_config(&config_doc(8, None, json!({})));
    let mut t = tuning(&d);
    t.convergence.every = Duration::from_millis(300);
    let r = start(&d, t, |_| {}).await;
    assert!(wait_until(T, || r.edge.active().object_id.as_deref() == Some(id1.as_str())).await);
    // No `changed`: the periodic fetch (every 60 s in production) picks the new object up.
    let id2 = core.set_config(&config_doc(9, None, json!({})));
    assert!(wait_until(T, || r.edge.active().object_id.as_deref() == Some(id2.as_str())).await);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_errors_are_retried_without_spooling_and_without_core_everything_spools() {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    core.set_config(&config_doc(8, None, json!({})));
    let r = start(&d, tuning(&d), |_| {}).await;
    assert!(wait_until(T, || r.edge.active().config.is_some()).await);
    assert!(wait_until(T, || core.with(|s| s.log_batches >= 1)).await);
    core.with(|s| s.log_script.extend([500, 503]));
    r.edge.logs.event("retried", picket_edge::logs::fields(&[]));
    assert!(wait_until(T, || core.with(|s| s.logs.iter().any(|l| l["kind"] == "retried"))).await);
    assert!(core.with(|s| s.log_script.is_empty()), "both errors were served");
    let st = r.edge.log_control.status.load();
    assert_eq!(
        (st.mode, st.spool_segments),
        ("memory", 0),
        "within spool_after_s: no spool"
    );
    r.shutdown().await;

    // A development edge without core: every record goes to the spool.
    let d = dirs();
    write_edge_json(&d.config, None, json!({}));
    let r = start(&d, tuning(&d), |_| {}).await;
    r.edge.logs.event("offline", picket_edge::logs::fields(&[]));
    assert!(wait_until(T, || r.edge.log_control.status.load().spool_segments > 0).await);
    assert_eq!(r.edge.log_control.status.load().mode, "spool");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_edge_on_the_same_runtime_directory_is_refused_before_it_writes_anything() {
    let d = dirs();
    write_edge_json(&d.config, None, json!({}));
    let r = start(&d, tuning(&d), |_| {}).await;
    let state_before = std::fs::read(d.data.join("state.json")).unwrap();
    let second = service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        tuning(&d),
        |_| {},
    )
    .await;
    let Err(e) = second else {
        panic!("a second edge started")
    };
    assert!(format!("{e:#}").contains("another picket-edge"), "{e:#}");
    assert_eq!(
        std::fs::read(d.data.join("state.json")).unwrap(),
        state_before,
        "the running edge's state.json untouched (ready_version, starts)"
    );
    let v = picket_edge::admin::call(&d.run.join("edge.sock"), "status", json!({}))
        .await
        .unwrap();
    assert_eq!(v["boot"], r.edge.boot.as_str(), "the first edge keeps its socket");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_commands_that_panic_or_hang_answer_an_error() {
    let d = dirs();
    write_edge_json(&d.config, None, json!({}));
    let r = start(&d, tuning(&d), |_| {}).await;
    r.edge.admin.register("boom", |_e, _a| async move {
        if std::hint::black_box(true) {
            panic!("kaboom");
        }
        Ok(json!(null))
    });
    r.edge.admin.register("hang", |_e, _a| async move {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Ok(json!(null))
    });
    let sock = d.run.join("edge.sock");
    // A panic must win over the timeout even where unwinding is slow (CI sets RUST_BACKTRACE,
    // and capturing a backtrace can take longer than a short timeout), so only the hang case
    // runs under the short one.
    for (cmd, want, timeout) in [
        ("boom", "kaboom", Duration::from_secs(30)),
        ("hang", "didn't finish", Duration::from_millis(100)),
    ] {
        r.edge.admin.set_timeout(timeout);
        match picket_edge::admin::call(&sock, cmd, json!({})).await {
            Err(picket_edge::admin::CallError::Remote(a)) => {
                assert_eq!(a.code, "internal");
                assert!(a.message.contains(want), "{a}");
            }
            other => panic!("{cmd}: {other:?}"),
        }
    }
    assert!(
        picket_edge::admin::call(&sock, "status", json!({})).await.is_ok(),
        "the socket keeps serving"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn firmware_self_check_needs_bound_listeners_and_fails_a_hung_check() {
    struct Hung;
    #[async_trait]
    impl SelfCheck for Hung {
        fn name(&self) -> &'static str {
            "redirect"
        }
        async fn passes(&self, _e: &Edge) -> bool {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            true
        }
    }
    let d = dirs();
    write_edge_json(&d.config, None, json!({}));
    let fw = d.data.join("version");
    std::fs::create_dir_all(&d.data).unwrap();
    std::fs::write(&fw, "UCGF.ipq9574.v6.0.17.1\n").unwrap();
    let mk = |d: &Dirs| {
        let mut t = tuning(d);
        t.platform = Some(picket_edge::paths::HostPlatform::Unifi);
        t.firmware_file = fw.clone();
        t.firmware.window = Duration::from_millis(50);
        t.firmware.during = Duration::from_millis(20);
        t.firmware.after = Duration::from_millis(50);
        t.firmware.check_timeout = Duration::from_millis(50);
        t
    };
    let r = start(&d, mk(&d), |_| {}).await;
    assert!(wait_until(T, || r.edge.state.get().firmware.last.is_some()).await);
    r.shutdown().await;
    std::fs::write(&fw, "UCGF.ipq9574.v6.0.18.2\n").unwrap();
    let r = start(&d, mk(&d), |h| h.add_self_check(Arc::new(Hung))).await;
    let kind = picket_api::session::condition_kind::FIRMWARE_CHECK_FAILED;
    let failed = |r: &Running| {
        r.edge
            .conditions
            .snapshot()
            .into_iter()
            .find(|c| c.kind == kind)
            .and_then(|c| c.detail)
            .map(|d| d["failed"].clone())
    };
    // No config, so no listener is bound; and the helper's check never answers.
    assert!(wait_until(T, || failed(&r) == Some(json!(["listeners", "redirect"]))).await);
    // `ready_version` alone isn't enough: the data path's check wants its listeners bound
    // (tests/dns.rs passes it with a bound listener).
    r.edge.state.mark_ready(picket_api::VERSION).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(failed(&r), Some(json!(["listeners", "redirect"])));
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_runs_a_development_edge_and_the_cli_reaches_it() {
    use std::process::{Command, Stdio};
    let bin = env!("CARGO_BIN_EXE_picket-edge");
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    std::fs::create_dir_all(cwd.join("dev")).unwrap();
    std::fs::write(cwd.join("dev/edge.json"), br#"{"updates_enabled": false}"#).unwrap();
    // pipelines.md §9: relative paths, an ordinary user, no systemd.
    let flags = [
        "--config",
        "./dev/edge.json",
        "--data-dir",
        "./dev/edge",
        "--runtime-dir",
        "./dev/run",
    ];
    let cmd = |args: &[&str]| {
        let mut c = Command::new(bin);
        c.current_dir(cwd)
            .args(args)
            .args(flags)
            .env_remove("NOTIFY_SOCKET")
            .env_remove("WATCHDOG_USEC")
            .env_remove("PICKET_EDGE_SERVICE");
        c
    };
    let mut child = cmd(&["run"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let sock = cwd.join("dev/run/edge.sock");
    assert!(wait_until(T, || sock.exists()).await, "admin socket");
    let out = cmd(&["status", "--json"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["edge_version"], picket_api::VERSION);
    assert_eq!(v["paths"]["runtime_dir"], "./dev/run");
    let out = cmd(&["status"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("picket-edge"));
    // `key` prints the identity the running edge uses.
    let out = cmd(&["key"]).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        v["fingerprint"].as_str().unwrap()
    );
    // A second edge with the same runtime directory exits at once.
    let out = cmd(&["run"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("another picket-edge"));
    // SIGTERM: a clean exit, the socket removed.
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&child),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "{status:?}");
    assert!(!sock.exists());
    let out = cmd(&["status"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("isn't running"));
}

fn sample_q() -> picket_api::logs::QueryRecord {
    serde_json::from_value(json!({
        "t": "q", "ts": "2026-11-13T10:22:01.123456Z", "boot": "x", "seq": 0,
        "listener": "lan-dns", "proto": "udp", "client": "192.168.1.140", "qname": "example.com", "qtype": "A",
        "rcode": "NOERROR", "decision": "allow"
    }))
    .map(|r: picket_api::logs::LogRecord| match r {
        picket_api::logs::LogRecord::Query(q) => *q,
        _ => unreachable!(),
    })
    .unwrap()
}
