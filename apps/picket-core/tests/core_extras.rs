//! Core's remaining parts (core.md §1 `web`, §4, §8 restarts, §10 Core, §12 Browser extension):
//! the extension downloads, core's resource gauges and job durations, listener binds an edge
//! doesn't allow, and the DNSSEC queue across a restart. (A `lanca.zones` change, a LAN CA
//! rotation: `lanca_rotation.rs`.)

use crate::common;

use std::sync::Arc;

use common::bundles::{get, put_entity, ui};
use common::edge::FakeEdge;
use common::zones::{World, ZoneResolver, name};
use hickory_proto::rr::RecordType;
use jiff::Timestamp;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::Digest;

#[tokio::test(flavor = "multi_thread")]
async fn extension_builds_are_served_open_with_their_sums() {
    let ext = tempfile::tempdir().unwrap();
    std::fs::write(
        ext.path().join("picket-browser-extension-0.1.0-brave.zip"),
        b"brave build",
    )
    .unwrap();
    std::fs::write(
        ext.path().join("picket-browser-extension-0.1.0-firefox.xpi"),
        b"firefox build",
    )
    .unwrap();
    std::fs::write(ext.path().join("notes.txt"), b"not a build").unwrap();
    let c = common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
            browser_extension_dir: ext.path().to_path_buf(),
            ..Default::default()
        },
    )
    .await;
    let (st, v) = get(&c, "/browser-extension").await;
    assert_eq!(st, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{v}");
    let brave = items.iter().find(|i| i["browser"] == json!("brave")).unwrap();
    assert_eq!(brave["version"], json!("0.1.0"));
    assert_eq!(brave["size"], json!(11));
    assert_eq!(
        brave["sha256"],
        json!(hex::encode(sha2::Sha256::digest(b"brave build")))
    );
    let path = brave["path"].as_str().unwrap();
    assert_eq!(
        path,
        "/browser-extension/picket-browser-extension-0.1.0-brave.zip"
    );
    // The download is open: no basic auth.
    let r = reqwest::get(format!("{}{path}", c.base("http"))).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"brave build");
    for bad in [
        "/browser-extension/notes.txt",
        "/browser-extension/picket-browser-extension-0.2.0-brave.zip",
        "/browser-extension/..%2Fcore.db",
    ] {
        let r = reqwest::get(format!("{}{bad}", c.base("http"))).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{bad}");
    }
    // lists.allow_cidrs decides who may download.
    let r = ui(&c, Method::PUT, "/settings")
        .json(&json!({"lists": {"allow_cidrs": ["10.0.0.0/8"]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = reqwest::get(format!("{}{path}", c.base("http"))).await.unwrap();
    assert_ne!(r.status(), StatusCode::OK, "outside lists.allow_cidrs");
}

#[tokio::test(flavor = "multi_thread")]
async fn core_samples_its_resources_and_job_durations() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let base = picket_core::metrics::resources::CpuBase::default();
    c.state.metrics.jobs.record("resource_test", 1200);
    c.state.metrics.jobs.record("resource_test", 40);
    picket_core::metrics::resources::write(&c.state, &base).await;
    picket_core::metrics::resources::write(&c.state, &base).await;
    let points = |n: &'static str| {
        let st = c.state.clone();
        async move {
            st.metrics_db
                .read(move |db| {
                    Ok::<_, anyhow::Error>(db.query_row(
                        "SELECT count(*) FROM points p JOIN series s ON s.id = p.series_id WHERE s.name = ?1",
                        [n],
                        |r| r.get::<_, i64>(0),
                    )?)
                })
                .await
                .unwrap()
        }
    };
    for n in [
        "core_rss",
        "core_disk_used",
        "core_disk_free",
        "db_bytes",
        "core_cpu_ms",
        "queue_depth",
    ] {
        assert!(points(n).await >= 1, "{n}");
    }
    // Startup jobs and the live sampler run concurrently. Count only this test's
    // jobs across all samples: a background drain may split the two observations.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let (count, sum): (i64, f64) = c
            .state
            .metrics_db
            .read(|db| {
                Ok::<_, anyhow::Error>(db.query_row(
                    "SELECT coalesce(sum(h.count), 0), coalesce(sum(h.sum), 0)
                     FROM histograms h JOIN series s ON s.id = h.series_id
                     WHERE s.name = 'job_ms' AND json_extract(s.labels_json, '$.kind') = 'resource_test'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        if (count, sum) == (2, 1240.0) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "two jobs must be stored exactly once, totaling 1240 ms: count={count}, sum={sum}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // The UI charts them.
    let (st, v) = get(
        &c,
        "/metrics?series=job_ms.p50,job_ms.p99,core_rss,db_bytes&window=1h",
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let series = v["series"].as_array().unwrap();
    let p99 = series
        .iter()
        .find(|l| l["name"] == json!("job_ms.p99") && l["labels"]["kind"] == json!("resource_test"))
        .unwrap_or_else(|| panic!("{v}"));
    let max = p99["points"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p[1].as_f64())
        .fold(0.0, f64::max);
    assert!(max > 500.0 && max < 2000.0, "p99 of 40 and 1200 ms: {max}");
    assert!(
        series
            .iter()
            .any(|l| l["name"] == json!("db_bytes") && l["labels"]["db"] == json!("core"))
    );
}

/// api.md §7: the Prometheus export holds `job_ms` as totals since core started, one histogram
/// per job kind (core.md §10), never one per provider.
#[tokio::test(flavor = "multi_thread")]
async fn prometheus_exports_job_ms_by_kind() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    c.state.metrics.jobs.record("compile", 1500);
    c.state
        .metrics
        .jobs
        .record(&picket_core::scheduler::job_kind("lookup:quad9"), 20);
    c.state
        .metrics
        .jobs
        .record(&picket_core::scheduler::job_kind("lookup:spamhaus"), 30);
    // A sample takes the per-sample histograms; the export's totals stay.
    c.state.metrics.jobs.take();
    let scrape = common::prom::parse(&picket_core::metrics::export::body(&c.state).await);
    assert_eq!(
        scrape.kind("picket_job_ms"),
        Some(prometheus_scraper::owned::MetricType::Histogram)
    );
    let compile = scrape.histogram("picket_job_ms", &[("kind", "compile")]).unwrap();
    assert_eq!((compile.count, compile.sum), (1, 1500.0));
    let lookup = scrape.histogram("picket_job_ms", &[("kind", "lookup")]).unwrap();
    assert_eq!((lookup.count, lookup.sum), (2, 50.0));
    let kinds: Vec<_> = scrape
        .family("picket_job_ms")
        .metric
        .iter()
        .map(common::prom::labels)
        .collect();
    assert_eq!(kinds.len(), 2, "a kind, not a provider: {kinds:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn binds_an_edge_does_not_allow_are_flagged() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let edge = FakeEdge::registered(&c, "e1").await;
    put_entity(
        &c,
        "listeners",
        "lan-dot",
        json!({"id": "lan-dot", "name": "lan-dot", "proto": "dot", "bind": "192.168.1.1:853", "tls": {"managed": "dns.home.arpa"}, "edges": [edge.id]}),
    )
    .await;
    let flagged = |v: &Value| {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["code"] == json!("bind_not_allowed") && i["id"] == json!("lan-dot"))
    };
    let (_, v) = get(&c, "/config/issues").await;
    assert!(!flagged(&v), "no hello yet: nothing reported");
    let (mut ws, _) = edge
        .session(json!({"edge_version": picket_api::VERSION, "arch": "x86_64", "os": "debian", "kernel": "6",
                        "platform": "debian", "firmware": null, "mem_total": 1, "mem_available": 1,
                        "allowed_binds": ["192.168.1.1:53"], "updates_enabled": true, "boot": "b1", "starts": 1,
                        "conditions": [], "applied": {}, "have": {}}))
        .await;
    assert!(
        common::edge::eventually(|| async {
            let (_, v) = get(&c, "/config/issues").await;
            flagged(&v)
        })
        .await,
        "a bind the edge's allowed_binds doesn't hold is flagged"
    );
    let _ = common::edge::closed(&mut ws).await;
}

/// edge.md §6, providers.md §5: a DoH path an older release stored that today's rule refuses (a
/// query, a dot segment) is listed in the config issues, upstream and lookup provider by id with
/// the rule, so the owner sees it after the upgrade (the edge drops such an upstream, and such a
/// lookup config no longer parses there).
#[tokio::test(flavor = "multi_thread")]
async fn doh_paths_stored_before_the_path_rule_are_config_issues() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    put_entity(
        &c,
        "upstreams",
        "old-doh",
        json!({"id": "old-doh", "name": "old-doh", "protocol": "doh", "ip": "192.0.2.53", "port": 443,
               "tls_host": "dns.example", "path": "/dns-query", "operator": "me"}),
    )
    .await;
    put_entity(
        &c,
        "lookup-providers",
        "old-dns",
        json!({"id": "old-dns", "name": "old-dns", "module": "dns", "category": "security",
               "config": {"transport": "doh", "servers": [{"ip": "192.0.2.1", "tls_host": "r.example", "path": "/dns-query"}]},
               "recheck": {"enabled": false}}),
    )
    .await;
    let issues = || async {
        let (_, v) = get(&c, "/config/issues").await;
        v["items"].as_array().unwrap().clone()
    };
    assert!(
        !issues()
            .await
            .iter()
            .any(|i| i["id"] == "old-doh" || i["id"] == "old-dns"),
        "valid paths: no issue"
    );
    // As an older release saved them (its rule took these).
    c.state
        .db
        .write(|db| {
            db.execute("UPDATE upstreams SET path = '/dns-query?x=1' WHERE id = 'old-doh'", [])?;
            db.execute(
                "UPDATE lookup_providers SET config_json = replace(config_json, '/dns-query', '/a/../dns-query')
                 WHERE id = 'old-dns'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let now = issues().await;
    let up = now
        .iter()
        .find(|i| i["id"] == "old-doh")
        .unwrap_or_else(|| panic!("the upstream is listed: {now:?}"));
    assert_eq!(
        (up["severity"].as_str(), up["code"].as_str()),
        (Some("error"), Some("bad_path")),
        "{up}"
    );
    assert!(
        up["message"].as_str().unwrap().contains("query or fragment"),
        "{up}"
    );
    let lp = now
        .iter()
        .find(|i| i["id"] == "old-dns")
        .unwrap_or_else(|| panic!("the lookup provider is listed: {now:?}"));
    assert_eq!(
        (lp["severity"].as_str(), lp["code"].as_str()),
        (Some("error"), Some("bad_config")),
        "{lp}"
    );
    let m = lp["message"].as_str().unwrap();
    assert!(m.contains("path") && m.contains("segments"), "{lp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dnssec_queue_survives_a_restart_and_drops_what_ages_out() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    c.state.analysis.set_paused(true);
    c.state.dnssec.set_paused(true);
    c.state.clock.pin(true);
    let world = World::standard();
    c.state.dnssec.set_trust_anchors(world.anchors());
    c.state.dnssec.set_resolver(Arc::new(ZoneResolver(world.clone())));
    let edge = FakeEdge::registered(&c, "e1").await;
    let ts = |t: Timestamp| picket_api::time::format_micros(&t);
    let mut lines = Vec::new();
    for (i, n) in ["www.test", "mail.test"].iter().enumerate() {
        let wire = world.answer(&name(&format!("{n}.")), RecordType::A);
        let (a, id) = common::edge::answer("b0", (i * 2 + 1) as u64, &ts(Timestamp::now()), &wire);
        let mut q = common::edge::query("b0", (i * 2 + 2) as u64, &ts(Timestamp::now()), n, Some(&id));
        q["received_at"] = json!(ts(Timestamp::now()));
        q["profile"] = json!("default");
        lines.push(a);
        lines.push(q);
    }
    assert_eq!(edge.post_logs(&lines).await.status(), 200);
    picket_core::logs::analysis::drain(&c.state).await.unwrap();
    assert_eq!(picket_core::dnssec::queue_depth(&c.state).await.unwrap(), 2);
    // One item is older than the retention window.
    c.state
        .db
        .write(|db| {
            Ok::<_, anyhow::Error>(db.execute(
                "UPDATE dnssec_queue SET first_seen = '2000-01-01T00:00:00.000000Z' WHERE qname = 'mail.test'",
                [],
            )?)
        })
        .await
        .unwrap();
    // Restart (on a snapshot of the directory taken after the stop).
    c.stop.cancel();
    let copy = tempfile::tempdir().unwrap();
    common::snapshot_dir(c.dir.path(), copy.path());
    let stop = tokio_util::sync::CancellationToken::new();
    let opts = picket_core::run::StartOptions {
        release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
        any_port: true,
        clock_synced: Some(true),
        disk_watch: false,
        ..Default::default()
    };
    let (state, _info) = picket_core::run::start_with(copy.path(), stop.clone(), opts)
        .await
        .unwrap();
    state.dnssec.set_paused(true);
    state.clock.pin(true);
    state.dnssec.set_trust_anchors(world.anchors());
    state.dnssec.set_resolver(Arc::new(ZoneResolver(world.clone())));
    assert_eq!(
        picket_core::dnssec::queue_depth(&state).await.unwrap(),
        2,
        "the queue is in core.db"
    );
    picket_core::dnssec::drain(&state).await.unwrap();
    assert_eq!(picket_core::dnssec::queue_depth(&state).await.unwrap(), 0);
    let by = picket_core::dnssec::results_by_outcome(&state).await.unwrap();
    assert_eq!(by.get("secure"), Some(&1), "{by:?}");
    let dropped: f64 = state
        .metrics_db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT coalesce(sum(p.value), 0) FROM points p JOIN series s ON s.id = p.series_id
                 WHERE s.name = 'dnssec_coverage' AND s.labels_json LIKE '%\"class\":\"dropped\"%'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(
        dropped, 1.0,
        "an item past the retention window is dropped and counted"
    );
    stop.cancel();
}
