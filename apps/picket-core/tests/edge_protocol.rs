//! The edge API against an in-process fake edge (build-and-test.md §5 rows: mTLS / TOFU (the
//! bucket's access rules, a raw-download blob), Convergence (core side), Edge requests (core
//! side), Edge conditions, Metrics, LAN CA (a CSR for another edge's listener), Independence (a
//! batch with a record core parses but can't store), and log ingest (api.md §2, §5; core.md §6)).

use crate::common;

use std::time::Duration;

use common::edge::{
    FakeEdge, answer, closed, eventually, heartbeat, hello, query, recv_changed, recv_type, send,
};
use jiff::Timestamp;
use picket_core::config::model::EntityKind;
use picket_core::config::{Actor, Op};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

fn plain() -> Option<Value> {
    Some(json!({"web": {"tls": "off"}}))
}

fn ts(t: Timestamp) -> String {
    picket_api::time::format_micros(&t)
}

async fn add_client(c: &common::Core, name: &str) {
    let mac = format!("02:00:00:00:00:{:02x}", name.len() as u8 + name.as_bytes()[0]);
    c.state
        .config
        .apply(
            EntityKind::Client,
            Op::Create(json!({"name": name, "macs": [mac]})),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
}

async fn q1<T: rusqlite::types::FromSql + Send + 'static>(
    c: &common::Core,
    sql: &'static str,
    p: Vec<String>,
) -> Option<T> {
    c.state
        .db
        .read(move |conn| {
            Ok::<_, anyhow::Error>(
                conn.query_row(sql, rusqlite::params_from_iter(p.iter()), |r| r.get(0))
                    .optional()?,
            )
        })
        .await
        .unwrap()
}

async fn alert_open(c: &common::Core, key: &str) -> bool {
    c.state
        .alerts
        .get_by_key(key)
        .await
        .unwrap()
        .is_some_and(|a| a.state == picket_core::alerts::AlertState::Open)
}

#[tokio::test(flavor = "multi_thread")]
async fn config_objects_etags_ranges_and_access_rules() {
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let b = FakeEdge::registered(&c, "edge-b").await;

    // 200: the edge's own config, ETag = BLAKE3 of the bytes, no-store (api.md §2).
    let r = a.get(&a.config_path()).await;
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    let body = r.bytes().await.unwrap();
    let id = picket_api::ids::object_id(&body);
    assert_eq!(h["etag"], format!("\"{id}\"").as_str());
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["accept-ranges"], "bytes");
    assert!(h.contains_key("last-modified"));
    assert_eq!(h["content-length"], body.len().to_string().as_str());
    let cfg: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(cfg["edge"]["id"], a.id.as_str());
    assert_eq!(cfg["edge"]["name"], "edge-a");

    // 304 on a matching If-None-Match: the status alone.
    let (st, etag, _) = a.config(Some(&id)).await;
    assert_eq!(st, 304);
    assert_eq!(etag.as_deref(), Some(id.as_str()));
    let r = a
        .http
        .get(a.url(&a.config_path()))
        .header("If-None-Match", format!("\"{id}\""))
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("content-type").is_none());

    // 403: another edge's config, existing or not.
    assert_eq!(a.get(&b.config_path()).await.status(), 403);
    assert_eq!(a.get("/objects/configs/AAAA.json").await.status(), 403);
    // 405: not GET or HEAD, with no body and no Content-Type.
    let r = a.http.post(a.url(&a.config_path())).send().await.unwrap();
    assert_eq!(r.status(), 405);
    assert!(r.headers().get("content-type").is_none());
    assert!(r.bytes().await.unwrap().is_empty());
    // 412: If-Match fails.
    let r = a
        .http
        .get(a.url(&a.config_path()))
        .header("If-Match", "\"0000\"")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 412);
    // Ranges: 206 with Content-Range; 416 for a bad one.
    let r = a
        .http
        .get(a.url(&a.config_path()))
        .header("Range", "bytes=0-9")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 206);
    assert_eq!(
        r.headers()["content-range"],
        format!("bytes 0-9/{}", body.len()).as_str()
    );
    assert_eq!(r.bytes().await.unwrap(), body.slice(0..10));
    let r = a
        .http
        .get(a.url(&a.config_path()))
        .header("Range", "bytes=999999-")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 416);
    // HEAD: headers only.
    let r = a.http.head(a.url(&a.config_path())).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["etag"], format!("\"{id}\"").as_str());

    // Blobs: bundle and verdict-set kinds only; a raw download is 404 (api.md §2 Sources).
    let dd = c.state.data_dir.clone();
    let (raw, bundle_blob, head) = c
        .state
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let raw = picket_core::blobs::put(&tx, &dd, picket_core::blobs::kind::DOWNLOAD, b"||ads.example^\n")?;
            let bb = picket_core::blobs::put(&tx, &dd, picket_core::blobs::kind::BUNDLE, b"bundle file bytes")?;
            let head = picket_core::blobs::put(&tx, &dd, picket_core::blobs::kind::BUNDLE, br#"{"head":1}"#)?;
            tx.execute(
                "INSERT INTO bundle_versions(bundle_id, head_id, heads_json, feed_runs_json, definition_hash, published_at)
                 VALUES ('block-common', ?1, '{}', '{}', 'x', '2026-01-01T00:00:00.000000Z')",
                [&head],
            )?;
            tx.commit()?;
            Ok::<_, anyhow::Error>((raw, bb, head))
        })
        .await
        .unwrap();
    assert_eq!(a.get(&format!("/objects/blobs/{raw}")).await.status(), 404);
    let r = a.get(&format!("/objects/blobs/{bundle_blob}")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["cache-control"], "max-age=31536000, immutable");
    assert_eq!(r.headers()["etag"], format!("\"{bundle_blob}\"").as_str());
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"bundle file bytes");
    let r = a
        .http
        .get(a.url(&format!("/objects/blobs/{bundle_blob}")))
        .header("Range", "bytes=-5")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 206);
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"bytes");
    let r = a
        .get(&format!("/objects/bundles/block-common/heads/{head}.json"))
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), br#"{"head":1}"#);
    assert_eq!(
        a.get(&format!("/objects/bundles/other/heads/{head}.json"))
            .await
            .status(),
        404
    );
    assert_eq!(a.get("/objects/nothing/here").await.status(), 404);
    assert_eq!(
        a.get("/objects/releases/0.1.0/picket-edge-0.1.0-x86_64.tar.gz")
            .await
            .status(),
        404
    );

    // Serving the config pinned it for that edge (storage.md §4).
    let pinned: Option<String> = q1(
        &c,
        "SELECT id FROM edge_pins WHERE edge_id = ?1 AND kind = 'config'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(pinned.as_deref(), Some(id.as_str()));
}

#[tokio::test(flavor = "multi_thread")]
async fn session_flow_changed_after_an_edit_and_one_session_per_edge() {
    let c = common::start_core(plain()).await;
    // The system bundles' first builds publish config objects of their own: on a loaded machine
    // they land late, so the `changed` counted below would be theirs.
    common::settled(&c).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, welcome) = a.session(hello("b1")).await;
    assert_eq!(welcome["edge_id"], a.id.as_str());
    assert_eq!(welcome["edge_name"], "edge-a");
    assert_eq!(welcome["core_version"], picket_api::VERSION);
    assert!(welcome["server_time"].as_str().is_some());
    let version: Option<String> = q1(
        &c,
        "SELECT edge_version FROM edge_boots WHERE edge_id = ?1 AND boot = 'b1'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(version.as_deref(), Some(picket_api::VERSION));

    let (st, etag1, _) = a.config(None).await;
    assert_eq!(st, 200);
    let etag1 = etag1.unwrap();

    // A heartbeat lands in edge_status and the live state.
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": heartbeat("b1", Timestamp::now(), 1000, 3)}),
    )
    .await;
    assert!(
        eventually(|| async {
            q1::<Option<String>>(
                &c,
                "SELECT heartbeat_json FROM edge_status WHERE edge_id = ?1",
                vec![a.id.clone()],
            )
            .await
            .flatten()
            .is_some()
        })
        .await
    );
    let view = picket_core::edges::status::view(&c.state, &a.id).await.unwrap();
    assert!(view.online);
    assert!(view.session.is_some());
    assert_eq!(view.hello.as_ref().unwrap().arch, "x86_64");

    // A config edit → `changed` with the new ETag; the edge fetches it with If-None-Match. Each
    // `changed` names the object current when it was sent; the edit's is the one whose object
    // holds the client (any other publication is skipped, as the edge would refetch).
    add_client(&c, "office-pc").await;
    let mut last = etag1.clone();
    let etag2 = loop {
        let etag2 = recv_changed(&mut ws, &last).await.expect("changed");
        let (st, etag, body) = a.config(Some(&etag1)).await;
        assert_eq!(st, 200);
        let has = body["clients"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["name"] == "office-pc");
        if has && etag.as_deref() == Some(etag2.as_str()) {
            break etag2;
        }
        last = etag2;
    };
    assert_eq!(a.config(Some(&etag2)).await.0, 304);

    // A newer session replaces the older, which is closed; the newer gets `changed`.
    let (mut ws2, _) = a.session(hello("b1")).await;
    assert!(closed(&mut ws).await, "the older session closes");
    add_client(&c, "tablet").await;
    recv_changed(&mut ws2, &etag2)
        .await
        .expect("changed on the newer session");

    // A deleted edge loses its session.
    c.state
        .config
        .apply(EntityKind::Edge, Op::Delete(a.id.clone()), Actor::cli(), None)
        .await
        .unwrap();
    assert!(closed(&mut ws2).await, "a deleted edge's session closes");
}

#[tokio::test(flavor = "multi_thread")]
async fn log_ingest_dedupes_stores_answers_by_id_and_acks_after_commit() {
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (_ws, _) = a.session(hello("b1")).await;
    let now = Timestamp::now();
    let t1 = ts(now - jiff::SignedDuration::from_mins(1));
    // The previous hour, whatever the time now (never the same hour as t1).
    let h1 = now - jiff::SignedDuration::from_mins(1);
    let h0 = picket_core::logs::partition::hour_start(&h1) - jiff::SignedDuration::from_mins(30);
    let t0 = ts(h0);
    let wire = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00scrubbed answer";
    let (ans, aid) = answer("b1", 1, &t1, wire);
    let lines = vec![
        ans,
        query("b1", 2, &t1, "a.example.com", Some(&aid)),
        // The same answer referenced from the previous hour: stored there too (core.md §6).
        query("b1", 3, &t0, "b.example.com", Some(&aid)),
        // An answer neither the batch nor the partition holds.
        query("b1", 4, &t1, "c.example.com", Some("0123456789abcdef")),
        json!({"t": "event", "ts": t1, "boot": "b1", "seq": 5, "kind": "activated", "config": "x"}),
        json!({"t": "condition", "ts": t1, "boot": "b1", "seq": 6, "kind": "memory_low", "change": "appeared", "time": t1}),
        json!({"t": "allow", "ts": t1, "boot": "b1", "seq": 7, "action": "created", "allow_id": "a-19",
               "client": "192.168.1.140", "kind": "ip", "target": "100.100.100.100", "via": "extension"}),
        json!({"t": "q", "ts": t1, "boot": "b1", "seq": 8}),
        query(
            "b1",
            9,
            &ts(now - jiff::SignedDuration::from_hours(100)),
            "old.example.com",
            None,
        ),
        // A boot core never heard a hello from: kept under release `unknown`.
        query("zz9", 1, &t1, "d.example.com", None),
    ];
    let r = a.post_logs(&lines).await;
    assert_eq!(r.status(), 200);
    let ack: Value = r.json().await.unwrap();
    assert_eq!(ack["acked"]["boot"], "zz9");
    assert_eq!(ack["acked"]["seq"], 1);

    let store = picket_core::logs::LogStore::new(&c.state.data_dir);
    let count = |hour: Timestamp, sql: &str| -> i64 {
        let p = store
            .open(&picket_core::logs::partition::hour_start(&hour), false)
            .unwrap()
            .unwrap();
        p.conn.query_row(sql, [], |r| r.get(0)).unwrap()
    };
    assert_eq!(count(h1, "SELECT count(*) FROM events WHERE edge_id <> ''"), 3);
    assert_eq!(count(h1, "SELECT count(*) FROM answers"), 1);
    assert_eq!(count(h0, "SELECT count(*) FROM events"), 1);
    assert_eq!(
        count(h0, "SELECT count(*) FROM answers"),
        1,
        "the answer goes with each partition's record"
    );
    assert_eq!(count(h1, "SELECT answer_missing FROM events WHERE seq = 4"), 1);
    assert_eq!(count(h1, "SELECT answer_missing FROM events WHERE seq = 2"), 0);
    assert_eq!(count(h1, "SELECT count(*) FROM version_sets"), 1);
    // Other records went to core.db.
    let n: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_events WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(n, Some(2));
    let allow: Option<String> = q1(
        &c,
        "SELECT target FROM temp_allows WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(allow.as_deref(), Some("100.100.100.100"));
    let unknown: Option<Option<String>> = q1(
        &c,
        "SELECT edge_version FROM edge_boots WHERE edge_id = ?1 AND boot = 'zz9'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(unknown, Some(None), "release unknown");
    // Dropped records are counted by reason.
    let dropped = |reason: &str| -> f64 {
        c.state
            .metrics
            .counters
            .totals()
            .iter()
            .filter(|((n, l), _)| n == "log_dropped" && l.get("reason").map(String::as_str) == Some(reason))
            .map(|(_, v)| *v)
            .sum()
    };
    assert_eq!(dropped("invalid"), 1.0);
    assert_eq!(dropped("too_old"), 1.0);

    // The same batch again (delivery is at-least-once): deduplicated, still acked.
    let r = a.post_logs(&lines).await;
    assert_eq!(r.status(), 200);
    assert_eq!(count(h1, "SELECT count(*) FROM events WHERE edge_id <> ''"), 3);
    assert_eq!(count(h1, "SELECT count(*) FROM answers"), 1);
    let n: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_events WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(n, Some(2));

    // Whole-batch errors are what the edge's splitter expects (edge.md §11).
    assert_eq!(a.post_raw_logs(b"not gzip".to_vec()).await.status(), 400);
    let many: Vec<Value> = (0..1001)
        .map(|i| query("b1", 100 + i, &t1, "x.example.com", None))
        .collect();
    assert_eq!(a.post_logs(&many).await.status(), 400);
    let r = a
        .http
        .post(a.url("/v1/logs"))
        .body(common::edge::gzip(b"{}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400, "no Content-Encoding: gzip");
    let huge: Vec<u8> = (0..(17u32 << 20))
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    assert_eq!(a.post_raw_logs(huge).await.status(), 413);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_core_cannot_store_is_dropped_and_an_io_failure_gets_503() {
    // build-and-test.md §5 Independence: a batch with a record core parses but can't store is
    // acked without it; a failure that isn't the record's gets 503 (core.md §6).
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let now = Timestamp::now() - jiff::SignedDuration::from_mins(2);
    let store = picket_core::logs::LogStore::new(&c.state.data_dir);
    let hour = picket_core::logs::partition::hour_start(&now);
    {
        let p = store.open(&hour, true).unwrap().unwrap();
        p.conn
            .execute_batch(
                "CREATE TRIGGER poison BEFORE INSERT ON events WHEN NEW.qname = 'poison.example'
                 BEGIN SELECT RAISE(ABORT, 'poison'); END;",
            )
            .unwrap();
    }
    let t = ts(now);
    let r = a
        .post_logs(&[
            query("b1", 1, &t, "good.example", None),
            query("b1", 2, &t, "poison.example", None),
            query("b1", 3, &t, "good2.example", None),
        ])
        .await;
    assert_eq!(r.status(), 200);
    let p = store.open(&hour, false).unwrap().unwrap();
    let n: i64 = p
        .conn
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2);
    let failed: f64 = c
        .state
        .metrics
        .counters
        .totals()
        .iter()
        .filter(|((n, l), _)| {
            n == "log_dropped" && l.get("reason").map(String::as_str) == Some("store_failed")
        })
        .map(|(_, v)| *v)
        .sum();
    assert_eq!(failed, 1.0);

    // An hour whose partition can't be opened (a directory in its place): 503, retried.
    let bad = now - jiff::SignedDuration::from_hours(2);
    std::fs::create_dir_all(store.path_for(&picket_core::logs::partition::hour_start(&bad))).unwrap();
    let r = a
        .post_logs_once(&[query("b1", 9, &ts(bad), "x.example", None)])
        .await;
    assert_eq!(r.status(), 503);
    assert!(r.headers().contains_key("retry-after"));
}

#[tokio::test(flavor = "multi_thread")]
async fn heartbeat_metrics_take_deltas_within_a_boot_and_restart_from_zero() {
    let c = common::start_core(Some(
        json!({"web": {"tls": "off"}, "metrics": {"allow_cidrs": ["127.0.0.0/8"]}}),
    ))
    .await;
    // Several heartbeats in a row: store each (core stores one per 20 s otherwise).
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let a = FakeEdge::registered(&c, "edge-a").await;
    let t0 = Timestamp::now() - jiff::SignedDuration::from_mins(20);
    let (mut ws, _) = a.session(hello("b1")).await;
    let hb = |boot: &str, dt: i64, up: u64, q: u64, lat: &[u64]| {
        let mut v = heartbeat(boot, t0 + jiff::SignedDuration::from_secs(dt), up, q);
        let mut h = picket_api::Histogram::default();
        for us in lat {
            h.record(*us, *us);
        }
        v["metrics"]["latency_us"] = serde_json::to_value(&h).unwrap();
        v["metrics"]["upstream"] = json!({"cf-dot": {"queries": q, "invalid": {"bad_id": 0}}});
        json!({"type": "heartbeat", "data": v})
    };
    send(&mut ws, hb("b1", 0, 60_000, 10, &[100; 10])).await;
    send(&mut ws, hb("b1", 30, 90_000, 30, &[100; 30])).await;
    // A lost heartbeat changes nothing: the next one's totals cover its time.
    send(&mut ws, hb("b1", 90, 150_000, 70, &[100; 70])).await;
    let mdb = c.state.metrics_db.clone();
    let edge = a.id.clone();
    let samples = |n: i64| {
        let (mdb, edge) = (mdb.clone(), edge.clone());
        async move {
            mdb.read(move |conn| {
                conn.query_row("SELECT count(*) FROM samples WHERE edge_id = ?1", [edge], |r| {
                    r.get::<_, i64>(0)
                })
                .map_err(anyhow::Error::from)
            })
            .await
            .unwrap()
                == n
        }
    };
    // A replaced session's messages change nothing, so let these land first.
    assert!(eventually(|| samples(3)).await);
    drop(ws);
    // A restart: a new boot whose totals start from 0.
    let (mut ws, _) = a.session(hello("b2")).await;
    send(&mut ws, hb("b2", 150, 30_000, 5, &[5000; 5])).await;
    assert!(eventually(|| samples(4)).await);
    let chart = |series: Vec<String>, edges: picket_core::metrics::query::EdgeSel| {
        let mdb = mdb.clone();
        async move {
            mdb.read(move |conn| {
                picket_core::metrics::query::chart(
                    conn,
                    &series,
                    picket_core::metrics::query::Window::parse("1h").unwrap(),
                    &edges,
                    Timestamp::now().as_millisecond(),
                    72 * 3600,
                )
                .map_err(|e| anyhow::anyhow!("{e}"))
            })
            .await
            .unwrap()
        }
    };
    let ch = chart(vec!["queries".into()], picket_core::metrics::query::EdgeSel::All).await;
    assert_eq!(ch.step_s, 30);
    let line = &ch.series[0];
    assert!(line.edge.is_none(), "summed across edges");
    let total: f64 = line.points.iter().filter_map(|(_, v)| *v).sum();
    assert!((total - 75.0).abs() < 1e-6, "10 + 20 + 40 + 5 = 75, got {total}");
    assert!(
        line.points.iter().filter_map(|(_, v)| *v).all(|v| v >= 0.0),
        "no negative counts"
    );
    // Before the first boot started there is no data: a gap, never a zero.
    assert!(line.points[0].1.is_none());
    // Per upstream, and per edge.
    let ch = chart(
        vec!["upstream.cf-dot.queries".into()],
        picket_core::metrics::query::EdgeSel::Each,
    )
    .await;
    assert_eq!(ch.series[0].edge.as_deref(), Some(a.id.as_str()));
    let up: f64 = ch.series[0].points.iter().filter_map(|(_, v)| *v).sum();
    assert!((up - 75.0).abs() < 1e-6, "{up}");
    // p99 from the summed buckets: the restart's slow queries show in their step.
    let ch = chart(
        vec!["latency_us.p99".into()],
        picket_core::metrics::query::EdgeSel::All,
    )
    .await;
    let max = ch.series[0]
        .points
        .iter()
        .filter_map(|(_, v)| *v)
        .fold(0.0, f64::max);
    assert!(max > 3000.0 && max <= 5657.0, "{max}");
    // A window longer than the metrics retention is refused.
    let mdb2 = mdb.clone();
    let r = mdb2
        .read(|conn| {
            Ok::<_, anyhow::Error>(picket_core::metrics::query::chart(
                conn,
                &["queries".into()],
                picket_core::metrics::query::Window::parse("72h").unwrap(),
                &picket_core::metrics::query::EdgeSel::All,
                Timestamp::now().as_millisecond(),
                24 * 3600,
            ))
        })
        .await
        .unwrap();
    assert!(r.is_err());

    // The Prometheus export carries the last heartbeat, labelled `edge`.
    let text = common::client()
        .get(format!("{}/metrics", c.base("http")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let scrape = common::prom::parse(&text);
    assert_eq!(
        scrape.value("picket_queries_total", &[("edge", &a.id)]),
        Some(5.0)
    );
    assert_eq!(
        scrape.kind("picket_latency_us"),
        Some(prometheus_scraper::owned::MetricType::Histogram)
    );
    assert_eq!(
        scrape.value(
            "picket_upstream_queries_total",
            &[("edge", &a.id), ("upstream", "cf-dot")]
        ),
        Some(5.0)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn csr_signs_only_assigned_managed_listeners_with_names_from_core() {
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let b = FakeEdge::registered(&c, "edge-b").await;
    for (id, edge, managed) in [
        ("lan-dot", &a.id, true),
        ("plain-dns", &a.id, false),
        ("b-dot", &b.id, true),
    ] {
        let mut body = json!({"id": id, "name": id, "proto": if managed { "dot" } else { "dns" },
            "bind": if id == "b-dot" { "192.168.1.2:853" } else if managed { "192.168.1.1:853" } else { "192.168.1.1:5335" },
            "edges": [edge]});
        if managed {
            body["tls"] = json!({"managed": if id == "b-dot" { "b.home.arpa" } else { "dns.home.arpa" }});
        }
        c.state
            .config
            .apply(EntityKind::Listener, Op::Create(body), Actor::cli(), None)
            .await
            .unwrap();
    }
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = rcgen::CertificateParams::new(vec!["evil.example.com".to_string()])
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let post = |e: &FakeEdge, listener: &str, pem: &str| {
        e.http
            .post(e.url("/v1/csr"))
            .json(&json!({"csr_pem": pem, "listener": listener}))
            .send()
    };
    let r = post(&a, "lan-dot", &csr).await.unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    let pem = v["cert_pem"].as_str().unwrap();
    let der = picket_core::identity::pem_to_der(pem, "CERTIFICATE").unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let sans: Vec<String> = cert
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .map(|g| format!("{g:?}"))
        .collect();
    let joined = sans.join(" ");
    assert!(
        joined.contains("dns.home.arpa") && joined.contains("*.dns.home.arpa"),
        "{joined}"
    );
    assert!(
        joined.contains("192.168.1.1") || joined.contains("[192, 168, 1, 1]"),
        "{joined}"
    );
    assert!(
        !joined.contains("evil"),
        "names come from the listener, never the CSR"
    );
    assert!(v["chain_pem"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    assert!(v["not_after"].as_str().is_some());

    // Another edge's listener, an unmanaged one, an unknown one: 403.
    assert_eq!(post(&a, "b-dot", &csr).await.unwrap().status(), 403);
    assert_eq!(post(&b, "lan-dot", &csr).await.unwrap().status(), 403);
    assert_eq!(post(&a, "plain-dns", &csr).await.unwrap().status(), 403);
    assert_eq!(post(&a, "nope", &csr).await.unwrap().status(), 403);
    // A CSR that doesn't parse or verify: 400.
    assert_eq!(post(&a, "lan-dot", "garbage").await.unwrap().status(), 400);
    // A leaf that would cover core's own address is refused.
    c.state
        .core_ips
        .store(std::sync::Arc::new(vec!["192.168.1.1".parse().unwrap()]));
    let r = post(&a, "lan-dot", &csr).await.unwrap();
    assert_eq!(r.status(), 403);
    let e: Value = r.json().await.unwrap();
    assert_eq!(e["error"]["code"], "conflict");
}

#[tokio::test(flavor = "multi_thread")]
async fn conditions_raise_after_their_threshold_and_resolve_when_cleared() {
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let now = Timestamp::now();
    let mut h = hello("b1");
    h["conditions"] = json!([
        {"kind": "memory_low", "since": ts(now - jiff::SignedDuration::from_hours(1))},
        {"kind": "upstream_down", "key": "cloudflare", "since": ts(now)},
        {"kind": "redirect_missing", "key": "ipv4", "since": ts(now - jiff::SignedDuration::from_mins(5))},
    ]);
    let (mut ws, _) = a.session(h).await;
    let mem = format!("edge_memory_low:{}", a.id);
    let up = format!("edge_upstream_down:{}:cloudflare", a.id);
    let redirect = format!("edge_redirect_missing:{}:ipv4", a.id);
    assert!(
        eventually(|| alert_open(&c, &mem)).await,
        "memory_low fires at once"
    );
    assert!(
        eventually(|| alert_open(&c, &redirect)).await,
        "held 5 min ≥ 2 min"
    );
    let ra = c.state.alerts.get_by_key(&redirect).await.unwrap().unwrap();
    assert!(ra.details["steps"].as_str().unwrap().contains("Policy Table"));
    assert!(!alert_open(&c, &up).await, "upstream_down waits for its 2 min");

    // The heartbeat no longer carries memory_low: resolved; upstream_down has now held 10 min.
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["conditions"] = json!([{"kind": "upstream_down", "key": "cloudflare", "since": ts(now - jiff::SignedDuration::from_mins(10))}]);
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    assert!(eventually(|| async { !alert_open(&c, &mem).await }).await);
    assert!(eventually(|| alert_open(&c, &up)).await);
    assert!(!alert_open(&c, &redirect).await);

    // A condition change from the log goes into the alert's history only.
    let r = a
        .post_logs(&[json!({"t": "condition", "ts": ts(Timestamp::now()), "boot": "b1", "seq": 1, "kind": "upstream_down",
                           "key": "cloudflare", "change": "appeared", "time": ts(now - jiff::SignedDuration::from_mins(10))})])
        .await;
    assert_eq!(r.status(), 200);
    let alert = c.state.alerts.get_by_key(&up).await.unwrap().unwrap();
    let (_, history) = c.state.alerts.get(alert.id).await.unwrap();
    assert!(history.iter().any(|h| h.change == "condition_appeared"));

    // A lost session clears nothing.
    drop(ws);
    assert!(eventually(|| async { c.state.edges.hub.session(&a.id).is_none() }).await);
    picket_core::edges::status::watch_once(&c.state).await.unwrap();
    assert!(alert_open(&c, &up).await);

    // After a restart core knows only the stored last-seen time: a core that started a moment
    // ago doesn't count its own outage as the edge's (review A14) …
    c.state.edges.hub.update_live(&a.id, |l| {
        l.last_seen = Some(Timestamp::now() - jiff::SignedDuration::from_mins(10));
        l.last_seen_mono = None;
    });
    picket_core::edges::status::watch_once(&c.state).await.unwrap();
    let offline = format!("edge_offline:{}", a.id);
    assert!(!alert_open(&c, &offline).await, "core started under 5 min ago");
    // … while a core running for an hour does: edge_offline after 5 min without a heartbeat; a
    // new session resolves it.
    c.state.edges.backdate_start(Duration::from_secs(3600));
    picket_core::edges::status::watch_once(&c.state).await.unwrap();
    assert!(alert_open(&c, &offline).await);
    assert!(
        !picket_core::edges::all_healthy(&c.state.db, Timestamp::now())
            .await
            .unwrap()
    );
    let (_ws, _) = a.session(hello("b1")).await;
    assert!(eventually(|| async { !alert_open(&c, &offline).await }).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_outcomes_raise_once_and_only_a_later_success_resolves() {
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let now = Timestamp::now();
    let mut h = hello("b1");
    h["update"] = json!({"result_id": "r1", "outcome": "failed", "version": "9.9.9", "at": ts(now - jiff::SignedDuration::from_hours(1))});
    let (mut ws, _) = a.session(h).await;
    let key = format!("edge_update_failed:{}", a.id);
    assert!(eventually(|| alert_open(&c, &key)).await);
    // The same result arriving as a spooled event later: no second raise.
    let ev = |seq: u64, kind: &str, id: &str, at: Timestamp| json!({"t": "event", "ts": ts(at), "boot": "b1", "seq": seq, "kind": kind, "result_id": id, "version": "9.9.9", "stage": "verify"});
    assert_eq!(
        a.post_logs(&[ev(
            1,
            "update_failed",
            "r1",
            now - jiff::SignedDuration::from_hours(1)
        )])
        .await
        .status(),
        200
    );
    // An older success delivered last never clears the newer failure.
    assert_eq!(
        a.post_logs(&[ev(
            2,
            "update_ok",
            "r0",
            now - jiff::SignedDuration::from_hours(2)
        )])
        .await
        .status(),
        200
    );
    let al = c.state.alerts.get_by_key(&key).await.unwrap().unwrap();
    assert_eq!(al.count, 1);
    assert!(alert_open(&c, &key).await);
    // A later success resolves.
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["update"] = json!({"result_id": "r2", "outcome": "ok", "version": "9.9.9", "at": ts(now - jiff::SignedDuration::from_mins(30))});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    assert!(eventually(|| async { !alert_open(&c, &key).await }).await);
}

/// Records a bundle head and a published config of `edge`, as core's compiler and publisher
/// would (activation targets core offered).
async fn offered(c: &common::Core, edge: &str, bundle: &str, head: &str, config: &str) {
    let (edge, bundle, head, config) = (
        edge.to_string(),
        bundle.to_string(),
        head.to_string(),
        config.to_string(),
    );
    c.state
        .db
        .write(move |conn| {
            let now = picket_core::util::now_ts();
            conn.execute(
                "INSERT INTO bundle_versions(bundle_id, head_id, heads_json, feed_runs_json, definition_hash, published_at)
                 VALUES (?1, ?2, '{}', '{}', 'x', ?3)",
                rusqlite::params![bundle, head, now],
            )?;
            conn.execute(
                "INSERT INTO edge_configs(config_id, edge_id, published_at, body_json) VALUES (?1, ?2, ?3, '{}')",
                rusqlite::params![config, edge, now],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn activation_failures_resolve_on_completion_or_plain_versions_only() {
    let c = common::start_core(plain()).await;
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    let head = picket_api::ids::object_id(b"head");
    let short = picket_api::ids::short_id(&head).to_string();
    let cfg = picket_api::ids::object_id(b"config c1");
    let cfg_short = picket_api::ids::short_id(&cfg).to_string();
    offered(&c, &a.id, "block-common", &head, &cfg).await;
    let t = ts(Timestamp::now());
    let r = a
        .post_logs(&[
            json!({"t": "event", "ts": t, "boot": "b1", "seq": 1, "kind": "activation_failed", "bundle": "block-common",
                   "head": short, "part": "shards/1", "stage": "verify", "reason": "blake3 mismatch"}),
            json!({"t": "event", "ts": t, "boot": "b1", "seq": 2, "kind": "activation_failed", "config": cfg,
                   "stage": "parse", "reason": "bad"}),
            json!({"t": "event", "ts": t, "boot": "b1", "seq": 3, "kind": "panic", "task": "x"}),
        ])
        .await;
    assert_eq!(r.status(), 200);
    // Keyed by the full id of what core offered, whichever form the edge logged.
    let bkey = format!("edge_activation_failed:{}:bundle:block-common:{head}", a.id);
    let ckey = format!("edge_activation_failed:{}:config:{cfg}", a.id);
    assert!(alert_open(&c, &bkey).await);
    assert!(alert_open(&c, &ckey).await);
    assert!(alert_open(&c, &format!("edge_panic:{}", a.id)).await);
    // A matching head inside the object form resolves nothing (a partial retry). The heartbeat's
    // alert effects commit with it, so once it is stored the answer is in.
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["versions"] = json!({"config": cfg_short, "bundles": {"block-common": {"head": short, "shards": {"0": short}, "ip_shards": {}, "segments": {}}}});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    assert!(
        eventually(|| async {
            q1::<Option<String>>(
                &c,
                "SELECT versions_json FROM edge_status WHERE edge_id = ?1",
                vec![a.id.clone()],
            )
            .await
            .flatten()
            .is_some()
        })
        .await
    );
    assert!(alert_open(&c, &bkey).await);
    // The plain form (every part active) resolves it.
    let mut hb = heartbeat("b1", Timestamp::now(), 2000, 0);
    hb["versions"] = json!({"config": cfg_short, "bundles": {"block-common": short}});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    assert!(eventually(|| async { !alert_open(&c, &bkey).await }).await);
    // The completion event resolves the config's.
    let r = a
        .post_logs(&[json!({"t": "event", "ts": ts(Timestamp::now()), "boot": "b1", "seq": 4, "kind": "activated", "config": cfg_short})])
        .await;
    assert_eq!(r.status(), 200);
    assert!(!alert_open(&c, &ckey).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_ride_in_the_config_and_stay_pending_until_applied() {
    let c = common::start_core(plain()).await;
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    let (_, etag0, _) = a.config(None).await;
    let etag0 = etag0.unwrap();

    // A flush: a new id in the config object; pending until `applied` carries it.
    let id = picket_core::edges::requests::flush(&c.state, &a.id, None)
        .await
        .unwrap();
    let etag1 = recv_changed(&mut ws, &etag0).await.expect("changed");
    let (st, etag, cfg) = a.config(Some(&etag0)).await;
    assert_eq!(st, 200);
    assert_eq!(etag.as_deref(), Some(etag1.as_str()));
    assert_eq!(cfg["flush"]["dns"], id.as_str());
    let pending = |v: &picket_core::edges::status::EdgeStatusView, kind: &str| {
        v.requests.iter().find(|r| r.kind == kind).map(|r| r.pending)
    };
    let v = picket_core::edges::status::view(&c.state, &a.id).await.unwrap();
    assert_eq!(pending(&v, "flush_dns"), Some(true));
    // Two more while "offline" collapse into one id.
    let _ = picket_core::edges::requests::flush(&c.state, &a.id, None)
        .await
        .unwrap();
    let id3 = picket_core::edges::requests::flush(&c.state, &a.id, None)
        .await
        .unwrap();
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["applied"] = json!({"flush_dns": id3});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    assert!(
        eventually(|| async {
            let v = picket_core::edges::status::view(&c.state, &a.id).await.unwrap();
            pending(&v, "flush_dns") == Some(false)
        })
        .await
    );

    // A revoke: listed until the edge acknowledges a list id that covered it.
    let t = ts(Timestamp::now());
    a.post_logs(&[json!({"t": "allow", "ts": t, "boot": "b1", "seq": 1, "action": "created", "allow_id": "a-19",
                         "client": "192.168.1.140", "kind": "ip", "target": "100.100.100.100", "via": "extension"})])
        .await;
    let rid = picket_core::edges::requests::revoke_allow(&c.state, &a.id, "a-19")
        .await
        .unwrap();
    assert!(
        eventually(|| async {
            let (_, _, cfg) = a.config(None).await;
            cfg["revoked_allows"]["id"] == rid.as_str() && cfg["revoked_allows"]["allows"] == json!(["a-19"])
        })
        .await
    );
    // An older list id acknowledges nothing (ids compare for equality only).
    let mut hb = heartbeat("b1", Timestamp::now(), 2000, 0);
    hb["applied"] = json!({"revoked_allows": "0000000000000000"});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    // Stored (the live copy follows the commit) and nothing acknowledged.
    assert!(
        eventually(|| async {
            c.state
                .edges
                .hub
                .live(&a.id)
                .heartbeat
                .is_some_and(|h| h.up_ms == 2000)
        })
        .await
    );
    let acked: Option<Option<String>> = q1(
        &c,
        "SELECT revoke_acked_at FROM temp_allows WHERE edge_id = ?1 AND allow_id = 'a-19'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(acked, Some(None));
    let (_, _, cfg) = a.config(None).await;
    assert_eq!(cfg["revoked_allows"]["allows"], json!(["a-19"]));
    // The current id: acknowledged, the list empties and is no longer rendered.
    let mut hb = heartbeat("b1", Timestamp::now(), 3000, 0);
    hb["applied"] = json!({"revoked_allows": rid});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    assert!(
        eventually(|| async {
            let (_, _, cfg) = a.config(None).await;
            cfg["revoked_allows"].is_null()
        })
        .await
    );
    // An allow the edge's log shows ended leaves the list too.
    let rid2 = picket_core::edges::requests::revoke_allow(&c.state, &a.id, "a-20")
        .await
        .unwrap();
    assert!(eventually(|| async { a.config(None).await.2["revoked_allows"]["id"] == rid2.as_str() }).await);
    a.post_logs(&[json!({"t": "allow", "ts": ts(Timestamp::now()), "boot": "b1", "seq": 2, "action": "expired",
                         "allow_id": "a-20", "client": "192.168.1.140", "kind": "dns", "target": "x.example", "via": "expiry"})])
        .await;
    assert!(eventually(|| async { a.config(None).await.2["revoked_allows"].is_null() }).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn pins_end_on_a_have_report_and_convergence_is_tracked() {
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    let (_, Some(id_a), _) = a.config(None).await else {
        panic!()
    };
    add_client(&c, "pc").await;
    let id_b = recv_changed(&mut ws, &id_a).await.expect("changed");
    let (st, _, _) = a.config(Some(&id_a)).await;
    assert_eq!(st, 200);
    let pins = |c: &common::Core, edge: String| {
        let db = c.state.db.clone();
        async move {
            db.read(move |conn| {
                let mut st = conn
                    .prepare("SELECT id FROM edge_pins WHERE edge_id = ?1 AND kind = 'config' ORDER BY id")?;
                Ok::<_, anyhow::Error>(
                    st.query_map([edge], |r| r.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?,
                )
            })
            .await
            .unwrap()
        }
    };
    let mut both = vec![id_a.clone(), id_b.clone()];
    both.sort();
    assert_eq!(pins(&c, a.id.clone()).await, both);
    // The edge fetched B and runs it: A's pin ends, B's stays; B shows active.
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["have"] = json!({"config": [id_b], "fetched": id_b});
    hb["versions"] = json!({"config": picket_api::ids::short_id(&id_b), "bundles": {}});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    assert!(eventually(|| async { pins(&c, a.id.clone()).await == vec![id_b.clone()] }).await);
    let active: Option<String> = q1(
        &c,
        "SELECT active_at FROM edge_named WHERE edge_id = ?1 AND kind = 'config'",
        vec![a.id.clone()],
    )
    .await;
    assert!(active.is_some());
    assert!(
        c.state.metrics.counters.gauges().iter().any(
            |((n, l), _)| n == "convergence_lag_s" && l.get("kind").map(String::as_str) == Some("config")
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_loops_and_listener_flags_from_hello() {
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    c.state
        .config
        .apply(
            EntityKind::Listener,
            Op::Create(json!({"id": "lan-dns", "name": "lan-dns", "proto": "dns", "bind": "192.168.1.1:5335", "edges": [a.id]})),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    let mut h = hello("b1");
    h["starts"] = json!(4);
    h["allowed_binds"] = json!(["[::]:5335"]);
    let (_ws, _) = a.session(h).await;
    let crash = format!("edge_crash_loop:{}", a.id);
    assert!(eventually(|| alert_open(&c, &crash)).await);
    let v = picket_core::edges::status::view(&c.state, &a.id).await.unwrap();
    assert_eq!(
        v.listeners[0].allowed,
        Some(false),
        "a bind outside allowed_binds is flagged"
    );
    // listener_rejected → alert; the listener unassigned → resolved by the watcher.
    let r = a
        .post_logs(&[
            json!({"t": "event", "ts": ts(Timestamp::now()), "boot": "b1", "seq": 1, "kind": "listener_rejected",
                           "listener": "lan-dns", "bind": "192.168.1.1:5335"}),
        ])
        .await;
    assert_eq!(r.status(), 200);
    let key = format!("edge_listener_rejected:{}:lan-dns", a.id);
    assert!(alert_open(&c, &key).await);
    c.state
        .config
        .apply(
            EntityKind::Listener,
            Op::Update("lan-dns".into(), json!({"id": "lan-dns", "name": "lan-dns", "proto": "dns", "bind": "192.168.1.1:5335", "edges": []})),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    picket_core::edges::status::watch_once(&c.state).await.unwrap();
    assert!(!alert_open(&c, &key).await);
}

// ---------------------------------------------------------------------------------------------
// Review round 1 (core edge side): one test per finding, each failing before its fix.

/// Replaces `edge`'s key with `fp` (Edges → the edge → key).
async fn replace_key(c: &common::Core, edge: &str, fp: &str) {
    let m = c.state.config.model().await.unwrap();
    let mut def = m.edges[edge].clone();
    def.key = fp.to_string();
    c.state
        .config
        .apply(
            EntityKind::Edge,
            Op::Update(edge.to_string(), serde_json::to_value(&def).unwrap()),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_change_or_a_deletion_ends_waiting_and_open_sessions() {
    // api.md §1 Key change (A1): the old key stops working at once, for a session already up and
    // for one that upgraded and still waits to send its hello.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let rid = picket_core::edges::requests::revoke_allow(&c.state, &a.id, "a-1")
        .await
        .unwrap();
    let (mut open, _) = a.session(hello("b1")).await;
    let mut waiting = a.connect().await;
    let new = FakeEdge::new(&c, "edge-a");
    replace_key(&c, &a.id, &new.fingerprint).await;
    assert!(closed(&mut open).await, "the open session ends");
    // The waiting session's hello gets no session, and changes nothing: no status, no alert, no
    // acknowledgement of a revoke list it learned earlier, no boot.
    let mut h = hello("b2");
    h["applied"] = json!({"revoked_allows": rid});
    h["conditions"] =
        json!([{"kind": "memory_low", "since": ts(Timestamp::now() - jiff::SignedDuration::from_hours(1))}]);
    send(&mut waiting, json!({"type": "hello", "data": h})).await;
    assert!(common::edge::recv_type(&mut waiting, "welcome").await.is_none());
    assert_ne!(
        c.state.edges.hub.live(&a.id).hello.map(|h| h.boot).as_deref(),
        Some("b2")
    );
    assert!(!alert_open(&c, &format!("edge_memory_low:{}", a.id)).await);
    let acked: Option<Option<String>> = q1(
        &c,
        "SELECT revoke_acked_at FROM temp_allows WHERE edge_id = ?1 AND allow_id = 'a-1'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(acked, Some(None));
    let b2: Option<i64> = q1(
        &c,
        "SELECT 1 FROM edge_boots WHERE edge_id = ?1 AND boot = 'b2'",
        vec![a.id.clone()],
    )
    .await;
    assert!(b2.is_none());
    // The old key is refused on new requests; the new key gets a session.
    assert!(a.http.get(a.url(&a.config_path())).send().await.is_err());
    let (_ws, _) = new.session(hello("b3")).await;

    // A deleted edge: its open session ends, a waiting one gets nothing.
    let d = FakeEdge::registered(&c, "edge-d").await;
    let (mut open_d, _) = d.session(hello("d1")).await;
    let mut waiting_d = d.connect().await;
    c.state
        .config
        .apply(EntityKind::Edge, Op::Delete(d.id.clone()), Actor::cli(), None)
        .await
        .unwrap();
    assert!(closed(&mut open_d).await);
    send(&mut waiting_d, json!({"type": "hello", "data": hello("d2")})).await;
    assert!(common::edge::recv_type(&mut waiting_d, "welcome").await.is_none());
    let d2: Option<i64> = q1(
        &c,
        "SELECT 1 FROM edge_boots WHERE edge_id = ?1 AND boot = 'd2'",
        vec![d.id.clone()],
    )
    .await;
    assert!(d2.is_none());
}

/// Opens a raw HTTP/1.1 `POST /v1/logs` whose body never finishes (`Content-Length` far beyond
/// what is sent).
async fn endless_log_post(e: &FakeEdge) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use tokio::io::AsyncWriteExt;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", e.port))
        .await
        .unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(e.tls_config()))
        .connect(rustls_pki_types::ServerName::try_from("core").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(
        b"POST /v1/logs HTTP/1.1\r\nHost: core\r\nContent-Encoding: gzip\r\nContent-Type: application/jsonl\r\nContent-Length: 4000000\r\n\r\n\x1f\x8b",
    )
    .await
    .unwrap();
    tls.flush().await.unwrap();
    tls
}

/// The status line of the response on `s`, or "" when none arrives within `wait`.
async fn status_within(
    s: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    wait: Duration,
) -> String {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 512];
    match tokio::time::timeout(wait, s.read(&mut buf)).await {
        Ok(Ok(n)) => String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_log_body_is_read_only_once_the_edge_holds_its_slot() {
    // README §2 Bounded (A2): an edge's batch takes its slot before its body is read, so two
    // batches of one edge never hold two bodies: the second is refused with 503 before reading
    // its body (here a body that never ends), not after.
    let c = common::start_core(plain()).await;
    c.state.logs.set_admit_wait(Duration::from_millis(300));
    let a = FakeEdge::registered(&c, "edge-a").await;
    let mut first = endless_log_post(&a).await;
    let mut second = endless_log_post(&a).await;
    let (s1, s2) = tokio::join!(
        status_within(&mut first, Duration::from_secs(5)),
        status_within(&mut second, Duration::from_secs(5))
    );
    let refused = [&s1, &s2]
        .iter()
        .filter(|s| s.starts_with("HTTP/1.1 503"))
        .count();
    assert_eq!(
        refused, 1,
        "one batch holds the slot, the other is refused: {s1:?} {s2:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_sessions_keep_their_connection_share() {
    // README §2 Bounded (A3): an upgraded session keeps its connection's share of the port, so
    // sessions waiting for their hello can't push one address past its share.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let mut held = Vec::new();
    for _ in 0..picket_core::edge_api::MAX_CONNECTIONS_PER_IP {
        held.push(a.connect().await);
    }
    assert!(
        a.http.get(a.url(&a.config_path())).send().await.is_err(),
        "this address's share is held by its sessions"
    );
    drop(held);
    assert!(
        eventually(|| async { a.http.get(a.url(&a.config_path())).send().await.is_ok() }).await,
        "the share comes back when the sessions end"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_messages_are_stored_at_a_capped_rate() {
    // README §2 Bounded, api.md §3 (A4): heartbeats sooner than the interval after the last
    // stored one only update the live copy; hellos are admitted at a capped rate per edge.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    let now = Timestamp::now();
    for i in 0..5u64 {
        let hb = heartbeat(
            "b1",
            now + jiff::SignedDuration::from_secs(i as i64),
            1000 * (i + 1),
            10 * i,
        );
        send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    }
    assert!(
        eventually(|| async {
            c.state
                .edges
                .hub
                .live(&a.id)
                .heartbeat
                .is_some_and(|h| h.up_ms == 5000)
        })
        .await,
        "the live copy shows the last heartbeat"
    );
    let edge = a.id.clone();
    let samples: i64 = c
        .state
        .metrics_db
        .read(move |conn| {
            conn.query_row("SELECT count(*) FROM samples WHERE edge_id = ?1", [edge], |r| {
                r.get(0)
            })
            .map_err(anyhow::Error::from)
        })
        .await
        .unwrap();
    assert_eq!(samples, 1, "one heartbeat stored per interval");
    let stored: Option<String> = q1(
        &c,
        "SELECT heartbeat_json FROM edge_status WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    let stored: Value = serde_json::from_str(&stored.unwrap()).unwrap();
    assert_eq!(stored["up_ms"], 1000);
    drop(ws);
    // A reconnect loop with a fresh boot each time: a burst, then refused.
    let mut welcomed = 0;
    for i in 0..15 {
        let mut ws = a.connect().await;
        send(&mut ws, json!({"type": "hello", "data": hello(&format!("r{i}"))})).await;
        if common::edge::recv_type(&mut ws, "welcome").await.is_some() {
            welcomed += 1;
        }
    }
    let burst = picket_core::edges::hub::HELLO_BURST as i64;
    assert_eq!(welcomed, burst - 1, "the first session took one hello");
    let boots: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_boots WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(boots, Some(burst));
}

#[tokio::test(flavor = "multi_thread")]
async fn alert_effects_follow_their_reports_in_commit_order() {
    // core.md §9 (A6): an older success held up after its commit, then a newer failure from a
    // replacement session, then the success's effects: the stored outcome is the failure, and so
    // must be the alert. The metrics writer is held to delay the first report past its commit,
    // and only until the replacement's hello has committed (the hello itself writes metrics
    // before its `welcome`, so the test never waits for that while holding the writer).
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    // The hold: it begins before the heartbeat is sent, and ends when `hold_tx` sends or is
    // dropped (a failing assertion releases the writer at once).
    let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let mdb = c.state.metrics_db.clone();
    let held = tokio::spawn(async move {
        mdb.write(move |_| {
            let _ = started_tx.send(());
            let _ = hold_rx.recv_timeout(Duration::from_secs(120));
            Ok::<_, anyhow::Error>(())
        })
        .await
    });
    started_rx.await.unwrap();
    let now = Timestamp::now();
    let mut hb = heartbeat("b1", now, 1000, 0);
    hb["update"] = json!({"result_id": "r2", "outcome": "ok", "version": "9.9.9", "at": ts(now - jiff::SignedDuration::from_mins(30))});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    let record = || async {
        q1::<Option<String>>(
            &c,
            "SELECT update_result_json FROM edge_status WHERE edge_id = ?1",
            vec![a.id.clone()],
        )
        .await
        .flatten()
        .unwrap_or_default()
    };
    let key = format!("edge_update_failed:{}", a.id);
    assert!(
        within(Duration::from_secs(60), || async {
            record().await.contains("\"r2\"")
        })
        .await
    );
    // A replacement session reports a newer failure; its hello commits (the record and the
    // alert) before anything of it needs the held writer.
    let mut h = hello("b2");
    h["update"] = json!({"result_id": "r3", "outcome": "failed", "version": "9.9.9", "at": ts(now - jiff::SignedDuration::from_mins(10))});
    let mut ws2 = a.connect().await;
    send(&mut ws2, json!({"type": "hello", "data": h})).await;
    assert!(
        within(Duration::from_secs(60), || async {
            record().await.contains("\"r3\"") && alert_open(&c, &key).await
        })
        .await,
        "the replacement's hello committed"
    );
    // The first report resumes; its processing ends with an `edge_status` heartbeat event.
    let mut events = c.state.events.subscribe();
    hold_tx.send(()).unwrap();
    held.await.unwrap().unwrap();
    let done = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match events.recv().await {
                Ok(ev) if ev.kind == "edge_status" && ev.data["event"] == "heartbeat" => return,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => panic!("events closed"),
            }
        }
    })
    .await;
    assert!(done.is_ok(), "the held heartbeat finished");
    assert!(record().await.contains("\"r3\""));
    assert!(
        alert_open(&c, &key).await,
        "the stored failure's alert stays open"
    );
    // The replacement session comes up once the writer is free (each wait is 10 s).
    let mut welcome = None;
    for _ in 0..6 {
        welcome = recv_type(&mut ws2, "welcome").await;
        if welcome.is_some() {
            break;
        }
    }
    assert!(welcome.is_some(), "the replacement session's welcome");
}

/// Polls `f` until it is true or `bound` passes (a generous bound: CI machines are slow).
async fn within<F, Fut>(bound: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let end = tokio::time::Instant::now() + bound;
    while tokio::time::Instant::now() < end {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f().await
}

#[tokio::test(flavor = "multi_thread")]
async fn activation_failures_of_unoffered_targets_share_one_alert() {
    // README §2 capped shares (A7): targets come from the edge; one core never offered can't make
    // its own alert key.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let lines: Vec<Value> = (1..=20u64)
        .map(|i| {
            json!({"t": "event", "ts": ts(Timestamp::now()), "boot": "b1", "seq": i, "kind": "activation_failed",
                   "bundle": format!("made-up-{i}"), "head": picket_api::ids::object_id(&i.to_be_bytes()),
                   "part": "head", "stage": "verify", "reason": "x"})
        })
        .collect();
    assert_eq!(a.post_logs(&lines).await.status(), 200);
    let other = format!("edge_activation_failed:{}:other", a.id);
    let al = c.state.alerts.get_by_key(&other).await.unwrap().unwrap();
    assert_eq!(al.count, 20);
    let n: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM alerts WHERE kind = 'edge_activation_failed' AND edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(n, Some(1));
    // A completion for an unknown target resolves nothing.
    let r = a
        .post_logs(&[
            json!({"t": "event", "ts": ts(Timestamp::now()), "boot": "b1", "seq": 21, "kind": "activated",
                            "bundle": "made-up-1", "head": picket_api::ids::object_id(&1u64.to_be_bytes())}),
        ])
        .await;
    assert_eq!(r.status(), 200);
    assert!(alert_open(&c, &other).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_condition_alert_raised_late_resolves_on_the_next_report() {
    // core.md §9 (A8): every report resolves the open condition alerts it doesn't carry, so one
    // the watcher raised just after a heartbeat cleared it doesn't stay open; and the watcher
    // raises only conditions the stored report still carries.
    let c = common::start_core(plain()).await;
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": heartbeat("b1", Timestamp::now(), 1000, 0)}),
    )
    .await;
    assert!(eventually(|| async { c.state.edges.hub.live(&a.id).heartbeat.is_some() }).await);
    let key = format!("edge_memory_low:{}", a.id);
    c.state
        .alerts
        .raise(
            picket_core::alerts::RaiseSpec::new(
                "edge_memory_low",
                picket_core::alerts::Severity::Warning,
                key.clone(),
                "late",
                Value::Null,
            )
            .edge(&a.id),
        )
        .await
        .unwrap();
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": heartbeat("b1", Timestamp::now(), 2000, 0)}),
    )
    .await;
    assert!(eventually(|| async { !alert_open(&c, &key).await }).await);
    // The live copy says memory_low (a moment before the stored report), the stored report
    // doesn't: the watcher raises nothing.
    c.state.edges.hub.update_live(&a.id, |l| {
        l.conditions = vec![picket_api::session::Condition {
            kind: "memory_low".into(),
            key: None,
            since: Timestamp::now() - jiff::SignedDuration::from_hours(1),
            detail: None,
        }];
    });
    picket_core::edges::status::watch_once(&c.state).await.unwrap();
    assert!(!alert_open(&c, &key).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retry_across_an_hour_boundary_is_still_a_duplicate() {
    // core.md §6 (A11): a record whose ts is ahead of core's clock is clamped on each attempt;
    // a retry after the hour turns must land in the first attempt's partition and dedupe there.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let hour =
        picket_core::logs::partition::hour_start(&Timestamp::now()) - jiff::SignedDuration::from_hours(1);
    let raw = hour + jiff::SignedDuration::from_hours(1) + jiff::SignedDuration::from_secs(30);
    let line = query("b1", 7, &ts(raw), "x.example", None).to_string();
    let attempt = |now: Timestamp| {
        let ctx = picket_core::logs::decode::Context {
            now,
            oldest: now - jiff::SignedDuration::from_hours(72),
        };
        picket_core::logs::decode::decode_lines(line.as_bytes(), &ctx, &picket_core::logs::decode::LIMITS)
            .unwrap()
    };
    // First attempt just before the hour turns: clamped into the earlier hour.
    let r1 = c
        .state
        .logs
        .store_batch(
            &c.state,
            &a.id,
            &a.fingerprint,
            attempt(hour + jiff::SignedDuration::from_mins(59)),
        )
        .await
        .unwrap();
    assert_eq!(r1.stored, 1);
    // The ack was lost; the retry comes after the hour turned.
    let r2 = c
        .state
        .logs
        .store_batch(
            &c.state,
            &a.id,
            &a.fingerprint,
            attempt(raw + jiff::SignedDuration::from_secs(10)),
        )
        .await
        .unwrap();
    assert_eq!((r2.stored, r2.duplicates), (0, 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn fw_drift_is_charted() {
    // core.md §10 (A12): fw_drift{edge, kind} is stored like the other core gauges.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["conditions"] = json!([{"kind": "fw_drift", "since": ts(Timestamp::now()), "detail": {"missing": 3, "unknown": 1, "longer": 0}}]);
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    let mdb = c.state.metrics_db.clone();
    let missing = || {
        let mdb = mdb.clone();
        async move {
            mdb.read(|conn| {
                picket_core::metrics::query::chart(
                    conn,
                    &["fw_drift".to_string()],
                    picket_core::metrics::query::Window::parse("1h").unwrap(),
                    &picket_core::metrics::query::EdgeSel::All,
                    Timestamp::now().as_millisecond(),
                    72 * 3600,
                )
                .map_err(|e| anyhow::anyhow!("{e}"))
            })
            .await
            .unwrap()
            .series
            .iter()
            .filter(|l| l.labels.get("kind").map(String::as_str) == Some("missing"))
            .flat_map(|l| l.points.iter().filter_map(|p| p.1))
            .collect::<Vec<f64>>()
        }
    };
    assert!(eventually(|| async { missing().await.contains(&3.0) }).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_logged_update_result_reaches_the_live_status() {
    // core.md §4–§5, §9 (A13): the status the UI reads follows the stored update record, also
    // when an update event from the log replaced it.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let now = Timestamp::now();
    let mut h = hello("b1");
    h["update"] = json!({"result_id": "r1", "outcome": "failed", "version": "9.9.9", "at": ts(now - jiff::SignedDuration::from_hours(1))});
    let (_ws, _) = a.session(h).await;
    let r = a
        .post_logs(&[
            json!({"t": "event", "ts": ts(now - jiff::SignedDuration::from_mins(5)), "boot": "b1", "seq": 1,
                            "kind": "update_ok", "result_id": "r2", "version": "9.9.9"}),
        ])
        .await;
    assert_eq!(r.status(), 200);
    let v = picket_core::edges::status::view(&c.state, &a.id).await.unwrap();
    assert_eq!(v.update.map(|u| u.result_id).as_deref(), Some("r2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_crash_loop_never_costs_records_and_its_boots_age_out() {
    // core.md §6, storage.md §4 (A15): past the unknown-boot share, records are still stored;
    // boots first seen in spooled records while the edge has a current boot are superseded.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (_ws, _) = a.session(hello("current")).await;
    let n = picket_core::logs::ingest::MAX_UNKNOWN_BOOTS as u64 + 44;
    let lines: Vec<Value> = (0..n)
        .map(|i| json!({"t": "event", "ts": ts(Timestamp::now()), "boot": format!("crash{i}"), "seq": 1, "kind": "panic"}))
        .collect();
    assert_eq!(a.post_logs(&lines).await.status(), 200);
    let stored: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_events WHERE edge_id = ?1 AND kind = 'panic'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(stored, Some(n as i64));
    let unknown: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_boots WHERE edge_id = ?1 AND edge_version IS NULL",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(unknown, Some(picket_core::logs::ingest::MAX_UNKNOWN_BOOTS));
    let unsuperseded: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_boots WHERE edge_id = ?1 AND edge_version IS NULL AND superseded_at IS NULL",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(unsuperseded, Some(0));
    // The current boot's records still go in.
    let r = a
        .post_logs(&[
            json!({"t": "event", "ts": ts(Timestamp::now()), "boot": "current", "seq": 1, "kind": "panic"}),
        ])
        .await;
    assert_eq!(r.status(), 200);
    let stored: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_events WHERE edge_id = ?1 AND kind = 'panic'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(stored, Some(n as i64 + 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn temporary_allows_stay_within_the_edges_share() {
    // README §2 Bounded (A5): allow ids come from the edge; a new one past the edge's share of
    // the table is dropped and counted, existing ones still update.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let cap = picket_core::logs::ingest::MAX_TEMP_ALLOWS_PER_EDGE;
    let edge = a.id.clone();
    c.state
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            for i in 0..cap - 1 {
                tx.execute(
                    "INSERT INTO temp_allows(edge_id, allow_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
                    rusqlite::params![edge, format!("pre-{i}"), picket_core::util::now_ts()],
                )?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let allow = |seq: u64, id: &str| {
        json!({"t": "allow", "ts": ts(Timestamp::now()), "boot": "b1", "seq": seq, "action": "created", "allow_id": id,
               "client": "192.168.1.140", "kind": "ip", "target": "100.100.100.100", "via": "extension"})
    };
    let r = a
        .post_logs(&[allow(1, "new-1"), allow(2, "new-2"), allow(3, "pre-0")])
        .await;
    assert_eq!(r.status(), 200);
    let rows: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM temp_allows WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(rows, Some(cap));
    let new2: Option<i64> = q1(
        &c,
        "SELECT 1 FROM temp_allows WHERE edge_id = ?1 AND allow_id = 'new-2'",
        vec![a.id.clone()],
    )
    .await;
    assert!(new2.is_none(), "over the share");
    let pre0: Option<Option<String>> = q1(
        &c,
        "SELECT target FROM temp_allows WHERE edge_id = ?1 AND allow_id = 'pre-0'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(
        pre0,
        Some(Some("100.100.100.100".into())),
        "an existing allow still updates"
    );
    assert!(
        c.state
            .metrics
            .counters
            .totals()
            .iter()
            .any(|((n, l), v)| n == "log_dropped"
                && l.get("reason").map(String::as_str) == Some("store_failed")
                && *v >= 1.0)
    );
}

// ---------------------------------------------------------------------------------------------
// Review round 2 re-check (core edge side): one test per finding, each failing before its fix.

/// Waits until `n` heartbeats have finished processing (their `edge_status` event, the last
/// step of a stored heartbeat, after its metrics).
async fn heartbeats_done(rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>, n: usize) {
    let mut seen = 0;
    let done = tokio::time::timeout(Duration::from_secs(15), async {
        while seen < n {
            match rx.recv().await {
                Ok(ev) if ev.kind == "edge_status" && ev.data["event"] == "heartbeat" => seen += 1,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => panic!("events closed"),
            }
        }
    })
    .await;
    assert!(done.is_ok(), "{n} heartbeats processed");
}

async fn metrics_q1(c: &common::Core, sql: &'static str, edge: &str) -> i64 {
    let edge = edge.to_string();
    c.state
        .metrics_db
        .read(move |conn| {
            Ok::<_, anyhow::Error>(
                conn.query_row(sql, rusqlite::params_from_iter([edge].iter()), |r| r.get(0))?,
            )
        })
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn series_ids_of_a_failed_heartbeat_are_never_reused() {
    // core.md §10, README §2 Restarts (CC1): a heartbeat whose metrics transaction rolls back
    // leaves no series ids behind; the next heartbeat creates its series again and charts them.
    let c = common::start_core(plain()).await;
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    let mut events = c.state.events.subscribe();
    // Histogram rows fail on the metrics writer: the first heartbeat's transaction rolls back
    // after its series and points went in.
    c.state
        .metrics_db
        .write(|conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_hist BEFORE INSERT ON histograms BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let t0 = Timestamp::now() - jiff::SignedDuration::from_secs(40);
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": heartbeat("b1", t0, 60_000, 10)}),
    )
    .await;
    heartbeats_done(&mut events, 1).await;
    c.state
        .metrics_db
        .write(|conn| {
            conn.execute_batch("DROP TRIGGER temp.fail_hist;")?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    assert_eq!(
        metrics_q1(&c, "SELECT count(*) FROM samples WHERE edge_id = ?1", &a.id).await,
        0,
        "the first heartbeat rolled back"
    );
    let t1 = t0 + jiff::SignedDuration::from_secs(30);
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": heartbeat("b1", t1, 90_000, 30)}),
    )
    .await;
    heartbeats_done(&mut events, 1).await;
    let orphans = metrics_q1(
        &c,
        "SELECT count(*) FROM points p WHERE NOT EXISTS (SELECT 1 FROM series s WHERE s.id = p.series_id) AND ?1 <> ''",
        &a.id,
    )
    .await;
    assert_eq!(orphans, 0, "every point belongs to a series");
    let queries = metrics_q1(
        &c,
        "SELECT count(*) FROM points p JOIN series s ON s.id = p.series_id
         WHERE s.name = 'queries' AND json_extract(s.labels_json, '$.edge') = ?1",
        &a.id,
    )
    .await;
    assert_eq!(
        queries, 1,
        "the second heartbeat's queries point is under the queries series"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_watcher_never_resolves_a_crash_loop_raised_after_its_read() {
    // core.md §9 (CC2): edge_crash_loop resolves only after 10 min without a new boot, decided
    // when the resolve commits: a hello that registers a new boot and raises the alert while the
    // watcher waits for the writer must leave it open. Writer barriers order the steps: the
    // watcher's boot read, then the hello's commit, then the watcher's resolve.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (ws0, _) = a.session(hello("b0")).await;
    drop(ws0);
    // An earlier crash loop's alert, still open: its boots and its raise are 20 min old.
    let key = format!("edge_crash_loop:{}", a.id);
    c.state
        .alerts
        .raise(
            picket_core::alerts::RaiseSpec::new(
                "edge_crash_loop",
                picket_core::alerts::Severity::Critical,
                key.clone(),
                "earlier",
                Value::Null,
            )
            .edge(&a.id),
        )
        .await
        .unwrap();
    let (edge, k) = (a.id.clone(), key.clone());
    c.state
        .db
        .write(move |conn| {
            let old = ts(Timestamp::now() - jiff::SignedDuration::from_mins(20));
            conn.execute(
                "UPDATE edge_boots SET first_seen = ?2 WHERE edge_id = ?1",
                rusqlite::params![edge, old],
            )?;
            conn.execute(
                "UPDATE alerts SET last_seen = ?2 WHERE dedupe_key = ?1",
                rusqlite::params![k, old],
            )?;
            // Enough firewall repairs that the watcher raises edge_fw_repairs (a write) between
            // its boot read and its crash-loop resolve.
            for seq in 0..=picket_core::edges::status::FW_REPAIRS_PER_HOUR {
                conn.execute(
                    "INSERT INTO edge_events(edge_id, boot, seq, at, kind) VALUES (?1, 'b0', ?2, ?3, 'rules_repaired')",
                    rusqlite::params![edge, 100 + seq, ts(Timestamp::now())],
                )?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let hold = |db: picket_core::db::Db| {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let h = tokio::spawn(async move {
            db.write(move |_| {
                let _ = rx.recv_timeout(Duration::from_secs(30));
                Ok::<_, anyhow::Error>(())
            })
            .await
        });
        (tx, h)
    };
    let pause = || tokio::time::sleep(Duration::from_millis(400));
    // The watcher queues behind a first barrier; a second barrier queues behind the watcher's
    // first write, so after that write the watcher reads the boots and waits behind it.
    let (release1, h1) = hold(c.state.db.clone());
    pause().await;
    let st = c.state.clone();
    let watcher = tokio::spawn(async move { picket_core::edges::status::watch_once(&st).await });
    pause().await;
    let (release2, h2) = hold(c.state.db.clone());
    pause().await;
    release1.send(()).unwrap();
    h1.await.unwrap().unwrap();
    pause().await;
    // A hello counting 4 starts, from a new boot, queues behind the second barrier, ahead of
    // the watcher's resolve.
    let mut ws = a.connect().await;
    let mut h = hello("b1");
    h["starts"] = json!(4);
    send(&mut ws, json!({"type": "hello", "data": h})).await;
    pause().await;
    release2.send(()).unwrap();
    h2.await.unwrap().unwrap();
    assert!(common::edge::recv_type(&mut ws, "welcome").await.is_some());
    watcher.await.unwrap().unwrap();
    assert!(alert_open(&c, &key).await, "the new boot's alert stays open");
    picket_core::edges::status::watch_once(&c.state).await.unwrap();
    assert!(alert_open(&c, &key).await);
    // Ten minutes on, with no new boot since: resolved.
    let (edge, k) = (a.id.clone(), key.clone());
    c.state
        .db
        .write(move |conn| {
            let old = ts(Timestamp::now() - jiff::SignedDuration::from_mins(11));
            conn.execute(
                "UPDATE edge_boots SET first_seen = ?2 WHERE edge_id = ?1",
                rusqlite::params![edge, old],
            )?;
            conn.execute(
                "UPDATE alerts SET last_seen = ?2 WHERE dedupe_key = ?1",
                rusqlite::params![k, old],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    picket_core::edges::status::watch_once(&c.state).await.unwrap();
    assert!(!alert_open(&c, &key).await);
}

/// A batch of `q` records from `boot`, seqs `seqs`, all at `at` by the edge's clock, decoded
/// at core time `now`.
fn clamped_batch(
    boot: &str,
    seqs: impl IntoIterator<Item = u64>,
    at: Timestamp,
    now: Timestamp,
) -> picket_core::logs::decode::Batch {
    let text: String = seqs
        .into_iter()
        .map(|s| format!("{}\n", query(boot, s, &ts(at), "x.example", None)))
        .collect();
    let ctx = picket_core::logs::decode::Context {
        now,
        oldest: now - jiff::SignedDuration::from_hours(72),
    };
    picket_core::logs::decode::decode_lines(text.as_bytes(), &ctx, &picket_core::logs::decode::LIMITS)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edge_clock_hours_ahead_costs_core_db_a_row_per_run_not_per_record() {
    // README §2 Bounded, core.md §6 (CC3): an edge whose clock is hours ahead sends every query
    // record from a later hour. Their first attempts' hours are kept as runs of seqs, not one
    // core.db row per record, and every retry after the hour turns is still a duplicate.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let hour =
        picket_core::logs::partition::hour_start(&Timestamp::now()) - jiff::SignedDuration::from_hours(2);
    let ahead = hour + jiff::SignedDuration::from_hours(3);
    // A record logged before the clock jumped, never clamped: the run below comes to cover its
    // seq, but it stays in its own hour on every attempt.
    let early = hour - jiff::SignedDuration::from_mins(30);
    let r = c
        .state
        .logs
        .store_batch(
            &c.state,
            &a.id,
            &a.fingerprint,
            clamped_batch("b1", [2], early, hour + jiff::SignedDuration::from_mins(5)),
        )
        .await
        .unwrap();
    assert_eq!(r.stored, 1);
    // Seqs with gaps (other records of the spool take the rest), three batches in one hour.
    for (i, at) in [10, 20, 30].into_iter().enumerate() {
        let seqs = (0..50u64).map(move |k| 1 + 3 * (50 * i as u64 + k));
        let r = c
            .state
            .logs
            .store_batch(
                &c.state,
                &a.id,
                &a.fingerprint,
                clamped_batch("b1", seqs, ahead, hour + jiff::SignedDuration::from_mins(at)),
            )
            .await
            .unwrap();
        assert_eq!(r.stored, 50);
    }
    let rows: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM log_clamped WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(rows, Some(1), "one run for the hour");
    // Every record retried after the hour turned, regrouped: all duplicates.
    let r = c
        .state
        .logs
        .store_batch(
            &c.state,
            &a.id,
            &a.fingerprint,
            clamped_batch(
                "b1",
                (0..150u64).map(|k| 1 + 3 * k),
                ahead,
                hour + jiff::SignedDuration::from_mins(65),
            ),
        )
        .await
        .unwrap();
    assert_eq!((r.stored, r.duplicates), (0, 150));
    let r = c
        .state
        .logs
        .store_batch(
            &c.state,
            &a.id,
            &a.fingerprint,
            clamped_batch("b1", [2], early, hour + jiff::SignedDuration::from_mins(66)),
        )
        .await
        .unwrap();
    assert_eq!((r.stored, r.duplicates), (0, 1));
}

/// Opens a raw HTTP/1.1 `POST /v1/logs` with a `body` of known length, sending only its first
/// `sent` bytes.
async fn partial_log_post(
    e: &FakeEdge,
    body: &[u8],
    sent: usize,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use tokio::io::AsyncWriteExt;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", e.port))
        .await
        .unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(e.tls_config()))
        .connect(rustls_pki_types::ServerName::try_from("core").unwrap(), tcp)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: core\r\nContent-Encoding: gzip\r\nContent-Type: application/jsonl\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    tls.write_all(head.as_bytes()).await.unwrap();
    tls.write_all(&body[..sent]).await.unwrap();
    tls.flush().await.unwrap();
    tls
}

#[tokio::test(flavor = "multi_thread")]
async fn a_log_post_whose_key_was_replaced_while_its_body_arrived_stores_nothing() {
    // api.md §1 Key change (CC5): the old key is refused from the replacement on, also for a
    // batch whose request began before it: its allow records and update result change nothing.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let rid = picket_core::edges::requests::revoke_allow(&c.state, &a.id, "a-1")
        .await
        .unwrap();
    assert!(!rid.is_empty());
    let now = Timestamp::now();
    let lines = [
        json!({"t": "allow", "ts": ts(now), "boot": "b1", "seq": 1, "action": "revoked", "allow_id": "a-1",
               "client": "192.168.1.140", "kind": "ip", "target": "100.100.100.100", "via": "extension"}),
        json!({"t": "event", "ts": ts(now), "boot": "b1", "seq": 2, "kind": "update_ok", "result_id": "r9",
               "version": "9.9.9"}),
    ];
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let body = common::edge::gzip(text.as_bytes());
    let mut post = partial_log_post(&a, &body, body.len() / 2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let new = FakeEdge::new(&c, "edge-a");
    replace_key(&c, &a.id, &new.fingerprint).await;
    {
        use tokio::io::AsyncWriteExt;
        post.write_all(&body[body.len() / 2..]).await.unwrap();
        post.flush().await.unwrap();
    }
    let status = status_within(&mut post, Duration::from_secs(10)).await;
    assert!(status.starts_with("HTTP/1.1 403"), "refused: {status:?}");
    let events: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_events WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(events, Some(0));
    let ended: Option<Option<String>> = q1(
        &c,
        "SELECT ended_at FROM temp_allows WHERE edge_id = ?1 AND allow_id = 'a-1'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(ended, Some(None), "the allow stays on the revoke list");
}

#[tokio::test(flavor = "multi_thread")]
async fn hellos_from_a_replaced_key_spend_none_of_the_edges_tokens() {
    // README §2 Bounded, api.md §1 (CC6): an edge's hello tokens are taken only by hellos from
    // its registered key, so sessions of an old key that upgraded before the key change can't
    // lock the edge's new key out.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let burst = picket_core::edges::hub::HELLO_BURST as usize;
    let mut waiting = Vec::new();
    for _ in 0..burst {
        waiting.push(a.connect().await);
    }
    let new = FakeEdge::new(&c, "edge-a");
    replace_key(&c, &a.id, &new.fingerprint).await;
    for (i, ws) in waiting.iter_mut().enumerate() {
        send(ws, json!({"type": "hello", "data": hello(&format!("old{i}"))})).await;
        assert!(common::edge::recv_type(ws, "welcome").await.is_none());
    }
    drop(waiting);
    let mut ws = new.connect().await;
    send(&mut ws, json!({"type": "hello", "data": hello("b1")})).await;
    assert!(
        common::edge::recv_type(&mut ws, "welcome").await.is_some(),
        "the new key gets its session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_heartbeat_interval_runs_from_arrival_not_from_a_late_commit() {
    // README §2 Bounded, api.md §3 (CC7): a heartbeat is stored when the interval has passed
    // since the last stored one arrived, however long the writer took to commit it.
    let c = common::start_core(plain()).await;
    c.state.edges.hub.set_heartbeat_interval(Duration::from_secs(1));
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    let (release, rx) = std::sync::mpsc::channel::<()>();
    let db = c.state.db.clone();
    let held = tokio::spawn(async move {
        db.write(move |_| {
            let _ = rx.recv_timeout(Duration::from_secs(30));
            Ok::<_, anyhow::Error>(())
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let t0 = Timestamp::now();
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": heartbeat("b1", t0, 1000, 1)}),
    )
    .await;
    // The writer commits the first heartbeat 1.8 s after it arrived …
    tokio::time::sleep(Duration::from_millis(1800)).await;
    release.send(()).unwrap();
    held.await.unwrap().unwrap();
    // … and the second arrives 2 s after the first: the interval (1 s) has passed.
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": heartbeat("b1", t0 + jiff::SignedDuration::from_secs(2), 3000, 2)}),
    )
    .await;
    assert!(
        eventually(|| async {
            c.state
                .edges
                .hub
                .live(&a.id)
                .heartbeat
                .is_some_and(|h| h.up_ms == 3000)
        })
        .await
    );
    let stored: Option<String> = q1(
        &c,
        "SELECT heartbeat_json FROM edge_status WHERE edge_id = ?1",
        vec![a.id.clone()],
    )
    .await;
    let stored: Value = serde_json::from_str(&stored.unwrap()).unwrap();
    assert_eq!(stored["up_ms"], 3000, "the second heartbeat was stored");
}

/// Issue 79: an allow is history, never an alert. Each allow record updates its `temp_allows`
/// row (created, re-timed, revoked, expired; a repeated or older delivery changes nothing), and
/// no record raises an alert, makes an evidence rule or copies traffic, before or after it. The
/// setting that turned alerts on is gone.
#[tokio::test(flavor = "multi_thread")]
async fn allows_are_history_never_alerts() {
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (_ws, _) = a.session(hello("b1")).await;
    let now = Timestamp::now();
    let t = |s: i64| ts(now - jiff::SignedDuration::from_secs(60 - s));
    let exp = ts(now + jiff::SignedDuration::from_hours(1));
    let allow = |seq: u64, action: &str, id: &str, device: Option<&str>, kind: &str, target: &str| {
        let mut r = json!({"t": "allow", "ts": t(seq as i64), "boot": "b1", "seq": seq, "action": action,
                           "allow_id": id, "client": "192.168.1.140", "kind": kind, "target": target,
                           "expires_at": exp, "via": "extension"});
        if let Some(d) = device {
            r["device"] = json!(d);
        }
        r
    };
    let q = |seq: u64, qname: &str, decision: &str| {
        let mut r = query("b1", seq, &t(seq as i64), qname, None);
        r["client"] = json!("192.168.1.140");
        r["device"] = json!("emma-tablet");
        r["answers"] = json!(["192.0.2.1"]);
        r["decision"] = json!(decision);
        r
    };
    assert_eq!(a.post_logs(&[q(1, "cdn.example.org", "block")]).await.status(), 200);
    assert_eq!(
        a.post_logs(&[
            allow(2, "created", "a-1", Some("emma-tablet"), "dns", "cdn.example.org"),
            allow(3, "created", "a-2", None, "ip", "198.51.100.9"),
            q(4, "www.example.org", "allow"),
        ])
        .await
        .status(),
        200
    );
    let row = |id: &str| {
        q1::<String>(
            &c,
            "SELECT json_array(created_at, updated_at, ended_at, expires_at, kind, target, coalesce(device, '')) FROM temp_allows WHERE allow_id = ?1",
            vec![id.to_string()],
        )
    };
    let created: Value = serde_json::from_str(&row("a-1").await.unwrap()).unwrap();
    assert_eq!(
        created,
        json!([t(2), t(2), null, exp, "dns", "cdn.example.org", "emma-tablet"])
    );
    // A re-time, a revoke, a repeated creation and an expiry: the rows follow, nothing else.
    a.post_logs(&[
        allow(5, "changed", "a-1", Some("emma-tablet"), "dns", "cdn.example.org"),
        allow(6, "revoked", "a-1", Some("emma-tablet"), "dns", "cdn.example.org"),
        allow(2, "created", "a-1", Some("emma-tablet"), "dns", "cdn.example.org"),
        allow(7, "expired", "a-2", None, "ip", "198.51.100.9"),
        q(8, "example.org", "allow"),
    ])
    .await;
    let ended: Value = serde_json::from_str(&row("a-1").await.unwrap()).unwrap();
    assert_eq!((&ended[0], &ended[1], &ended[2]), (&json!(t(2)), &json!(t(6)), &json!(t(6))));
    let ip: Value = serde_json::from_str(&row("a-2").await.unwrap()).unwrap();
    assert_eq!(ip[2], json!(t(7)));
    for sql in [
        "SELECT count(*) FROM alerts WHERE type = 'security'",
        "SELECT count(*) FROM alert_evidence_rules",
        "SELECT count(*) FROM alert_evidence",
    ] {
        assert_eq!(q1::<i64>(&c, sql, vec![]).await, Some(0), "{sql}");
    }
    // No switch brings the alert back.
    assert!(
        c.state
            .config
            .patch_settings(json!({"alerts": {"temporary_allow": true}}), Actor::cli())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_version_refusals_raise_one_alert_per_device_and_resolve_after_a_quiet_day() {
    // api.md §5 `tls_version_refused` → core.md §9-style `edge_tls_version_refused`.
    use picket_core::alerts::{AlertState, AlertType, Severity};
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let ev = |seq: u64, device: Value, client: &str, listener: &str, transport: &str, refused: u64| {
        json!({"t": "event", "ts": ts(Timestamp::now()), "boot": "b1", "seq": seq, "kind": "tls_version_refused",
               "listener": listener, "transport": transport, "client": client, "device": device,
               "sni": "dns.home.arpa", "offered": "tls12", "refused": refused})
    };
    let batch = [
        ev(1, json!("old-printer"), "192.168.1.50", "lan-dot", "dot", 1),
        // The same device from another address and listener: the same alert, its latest details.
        ev(2, json!("old-printer"), "192.168.1.51", "lan-doh", "doh", 3),
        // A device with no name and no MAC: keyed on its address.
        ev(3, Value::Null, "::ffff:192.168.1.60", "lan-dot", "dot", 1),
    ];
    assert_eq!(a.post_logs(&batch).await.status(), 200);
    let key = format!("edge_tls_version_refused:{}:old-printer", a.id);
    let alert = c.state.alerts.get_by_key(&key).await.unwrap().expect("raised");
    assert_eq!(
        (alert.alert_type, alert.severity, alert.state),
        (AlertType::Operational, Severity::Warning, AlertState::Open)
    );
    assert_eq!(alert.count, 4, "the handshakes the records stand for");
    assert_eq!(alert.edge.as_deref(), Some(a.id.as_str()));
    assert_eq!(
        alert.details,
        json!({"edge": a.id, "device": "old-printer", "mac": null, "client": "192.168.1.51", "listener": "lan-doh",
               "transport": "doh", "sni": "dns.home.arpa", "offered": "tls12"})
    );
    assert!(
        alert.title.contains("old-printer offers no TLS 1.3"),
        "{}",
        alert.title
    );
    let by_addr = format!("edge_tls_version_refused:{}:192.168.1.60", a.id);
    let other = c
        .state
        .alerts
        .get_by_key(&by_addr)
        .await
        .unwrap()
        .expect("raised");
    assert_eq!(other.details["device"], Value::Null);
    assert_eq!(other.count, 1);
    // Each record is on the edge's page; a resent one changes nothing.
    assert_eq!(a.post_logs(&batch[..1]).await.status(), 200);
    let stored: Option<i64> = q1(
        &c,
        "SELECT count(*) FROM edge_events WHERE edge_id = ?1 AND kind = 'tls_version_refused'",
        vec![a.id.clone()],
    )
    .await;
    assert_eq!(stored, Some(3));
    assert_eq!(c.state.alerts.get_by_key(&key).await.unwrap().unwrap().count, 4);
    // A day without a new refusal resolves it; the other alert, refused just now, stays open.
    let k = key.clone();
    c.state
        .db
        .write(move |conn| {
            let old = ts(Timestamp::now() - jiff::SignedDuration::from_hours(25));
            conn.execute(
                "UPDATE alerts SET last_seen = ?2 WHERE dedupe_key = ?1",
                rusqlite::params![k, old],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    picket_core::edges::status::watch_once(&c.state).await.unwrap();
    assert!(!alert_open(&c, &key).await);
    assert!(alert_open(&c, &by_addr).await);
    // The device trying again reopens it.
    let again = ev(4, json!("old-printer"), "192.168.1.51", "lan-dot", "dot", 2);
    assert_eq!(a.post_logs(&[again]).await.status(), 200);
    let reopened = c.state.alerts.get_by_key(&key).await.unwrap().unwrap();
    assert_eq!((reopened.state, reopened.count), (AlertState::Open, 6));
}

/// A `tls_version_refused` event record.
fn tls_refused(seq: u64, fields: Value) -> Value {
    let mut e = json!({"t": "event", "ts": ts(Timestamp::now()), "boot": "b1", "seq": seq, "kind": "tls_version_refused",
                       "listener": "lan-dot", "transport": "dot", "client": "192.168.1.50", "device": null,
                       "sni": "dns.home.arpa", "offered": "tls12", "refused": 1});
    e.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    e
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_refusal_alerts_group_by_mac_then_name_and_keep_unicode_names() {
    // Review r10 U5: devices behind one client name are told apart by their MACs; T4: a name of
    // 128 characters (config's limit) in any script keeps its grouping.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let name = "子供のタブレット".repeat(6); // 48 characters, 144 bytes
    let batch = [
        tls_refused(
            1,
            json!({"device": "kids", "mac": "02:00:00:00:00:01", "client": "192.168.1.51"}),
        ),
        tls_refused(
            2,
            json!({"device": "kids", "mac": "02:00:00:00:00:02", "client": "192.168.1.52"}),
        ),
        tls_refused(3, json!({"device": name, "client": "192.168.1.60"})),
        tls_refused(4, json!({"device": name, "client": "fd00::60"})),
    ];
    assert_eq!(a.post_logs(&batch).await.status(), 200);
    for mac in ["02:00:00:00:00:01", "02:00:00:00:00:02"] {
        let key = format!("edge_tls_version_refused:{}:{mac}", a.id);
        let alert = c
            .state
            .alerts
            .get_by_key(&key)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{key}"));
        assert_eq!(
            (alert.details["mac"].as_str(), alert.details["device"].as_str()),
            (Some(mac), Some("kids"))
        );
        assert_eq!(alert.count, 1);
    }
    let key = format!("edge_tls_version_refused:{}:{name}", a.id);
    let alert = c
        .state
        .alerts
        .get_by_key(&key)
        .await
        .unwrap()
        .expect("keyed on the name");
    assert_eq!(alert.count, 2, "its IPv4 and IPv6 refusals are one device");
}

#[tokio::test(flavor = "multi_thread")]
async fn unlogged_tls_refusals_are_counted() {
    // Review r10 T3/U2: refusals the edge's full table couldn't attribute reach a core counter.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let batch = [
        tls_refused(1, json!({"unlogged": 5})),
        tls_refused(2, json!({"unlogged": 2, "client": "192.168.1.9"})),
    ];
    assert_eq!(a.post_logs(&batch).await.status(), 200);
    let total: f64 = c
        .state
        .metrics
        .counters
        .totals()
        .into_iter()
        .filter(|((n, l), _)| n == "tls_refused_unlogged" && l.get("edge") == Some(&a.id))
        .map(|(_, v)| v)
        .sum();
    assert_eq!(total, 7.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hourly_tls_refusals_never_crowd_other_events_off_the_edge_page() {
    // Review r10 U4: the edge page shows 72 h of events (core.md §9); refusal events, up to one
    // per listener and client an hour, take only a capped part of it.
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let t0 = Timestamp::now() - jiff::SignedDuration::from_hours(10);
    let mut batch =
        vec![json!({"t": "event", "ts": ts(t0), "boot": "b1", "seq": 1, "kind": "panic", "task": "x"})];
    for i in 0..80u64 {
        let mut e = tls_refused(2 + i, json!({"client": format!("192.168.1.{}", 10 + i)}));
        e["ts"] = json!(ts(t0 + jiff::SignedDuration::from_mins(i as i64)));
        batch.push(e);
    }
    assert_eq!(a.post_logs(&batch).await.status(), 200);
    let v = picket_core::edges::status::view(&c.state, &a.id).await.unwrap();
    assert!(
        v.events.iter().any(|e| e.kind == "panic"),
        "{:?}",
        v.events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
    let refusals = v
        .events
        .iter()
        .filter(|e| e.kind == "tls_version_refused")
        .count();
    assert!(refusals > 0 && refusals <= 20, "{refusals}");
    assert!(v.events.windows(2).all(|w| w[0].at >= w[1].at), "newest first");
}

// #71: log batches across a config restore ----------------------------------------------------

/// Decodes JSON lines into a batch as the ingest would.
fn batch_of(lines: &[Value]) -> picket_core::logs::decode::Batch {
    let now = Timestamp::now();
    let ctx = picket_core::logs::decode::Context {
        now,
        oldest: now - jiff::SignedDuration::from_hours(72),
    };
    let text = lines.iter().map(Value::to_string).collect::<Vec<_>>().join("\n");
    picket_core::logs::decode::decode_lines(text.as_bytes(), &ctx, &picket_core::logs::decode::LIMITS).unwrap()
}

/// Exports the configuration and restores it (the edge and its key are kept).
async fn restore_same(c: &common::Core) {
    let dir = c.state.data_dir.clone();
    let doc = c
        .state
        .db
        .read(move |db| picket_core::config::export::export(db, &dir))
        .await
        .unwrap();
    picket_core::config::export::restore(&c.state, doc, None).await.unwrap();
    assert!(!c.state.restore.logs_pending(), "the restore emptied the logs");
}

/// Stores `lines` in a task, holds it at `point`, restores the configuration meanwhile, then
/// lets it go on: the batch's result.
async fn store_across_a_restore(
    c: &common::Core,
    a: &FakeEdge,
    lines: &[Value],
    point: picket_core::logs::ingest::IngestPoint,
) -> Result<picket_core::logs::ingest::IngestReport, picket_core::logs::ingest::IngestError> {
    let pause = c.state.logs.pause_at(point);
    let (st, id, fp, b) = (c.state.clone(), a.id.clone(), a.fingerprint.clone(), batch_of(lines));
    let task = tokio::spawn(async move { st.logs.store_batch(&st, &id, &fp, b).await });
    pause.reached.notified().await;
    restore_same(c).await;
    pause.resume.notify_one();
    task.await.unwrap()
}

async fn events_of(c: &common::Core, edge: &str) -> i64 {
    q1::<i64>(c, "SELECT count(*) FROM edge_events WHERE edge_id = ?1", vec![edge.to_string()])
        .await
        .unwrap()
}

/// `q` records in every partition.
async fn stored_queries(c: &common::Core) -> i64 {
    let store = picket_core::logs::LogStore::new(&c.state.data_dir);
    tokio::task::spawn_blocking(move || {
        let mut n = 0;
        for (hour, _) in store.list().unwrap() {
            if let Some(p) = store.open(&hour, false).unwrap() {
                n += p
                    .conn
                    .query_row("SELECT count(*) FROM events WHERE edge_id <> ''", [], |r| r.get::<_, i64>(0))
                    .unwrap();
            }
        }
        n
    })
    .await
    .unwrap()
}

async fn log_records_points(c: &common::Core, edge: &str) -> i64 {
    metrics_q1(
        c,
        "SELECT count(*) FROM points p JOIN series s ON s.id = p.series_id
         WHERE s.name = 'log_records' AND s.labels_json LIKE '%' || ?1 || '%'",
        edge,
    )
    .await
}

fn is_retryable(r: &Result<picket_core::logs::ingest::IngestReport, picket_core::logs::ingest::IngestError>) -> bool {
    matches!(r, Err(picket_core::logs::ingest::IngestError::Unavailable(m)) if m.contains("config restore"))
}

/// A mixed batch held after its partition writes (two partition hours) while a restore commits
/// and empties the partitions: its later effects (events) never commit into the restored state
/// and it gets the retryable answer, not an ack. The edge's retry (its key retained) stores the
/// whole batch once; a second retry is all duplicates.
#[tokio::test(flavor = "multi_thread")]
async fn a_batch_paused_after_its_partitions_commits_nothing_after_a_restore() {
    use picket_core::logs::ingest::IngestPoint;
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let now = Timestamp::now() - jiff::SignedDuration::from_mins(1);
    let earlier = picket_core::logs::partition::hour_start(&now) - jiff::SignedDuration::from_mins(30);
    let lines = vec![
        query("b1", 1, &ts(now), "a.example.com", None),
        query("b1", 2, &ts(earlier), "b.example.com", None),
        json!({"t": "event", "ts": ts(now), "boot": "b1", "seq": 3, "kind": "activated", "config": "x"}),
    ];
    let r = store_across_a_restore(&c, &a, &lines, IngestPoint::AfterPartitions).await;
    assert!(is_retryable(&r), "{r:?}");
    assert_eq!(events_of(&c, &a.id).await, 0, "no stale event in the restored state");
    assert_eq!(stored_queries(&c).await, 0, "the restore emptied what the batch wrote");
    assert_eq!(log_records_points(&c, &a.id).await, 0);
    // The edge retries: everything once.
    let r = c.state.logs.store_batch(&c.state, &a.id, &a.fingerprint, batch_of(&lines)).await.unwrap();
    assert_eq!((r.stored, r.events), (2, 1));
    assert_eq!(events_of(&c, &a.id).await, 1);
    assert_eq!(stored_queries(&c).await, 2);
    let r = c.state.logs.store_batch(&c.state, &a.id, &a.fingerprint, batch_of(&lines)).await.unwrap();
    assert_eq!((r.stored, r.duplicates, r.events), (0, 2, 0));
    assert_eq!(events_of(&c, &a.id).await, 1);
}

/// An already admitted batch of events and allows only (no partition write to refuse it) held
/// before its events' transaction while a restore commits: nothing of it commits, retryable.
#[tokio::test(flavor = "multi_thread")]
async fn an_events_only_batch_admitted_before_a_restore_commits_nothing_after_it() {
    use picket_core::logs::ingest::IngestPoint;
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let t = ts(Timestamp::now() - jiff::SignedDuration::from_mins(1));
    let lines = vec![
        json!({"t": "event", "ts": t, "boot": "b1", "seq": 1, "kind": "panic", "task": "x"}),
        json!({"t": "allow", "ts": t, "boot": "b1", "seq": 2, "action": "created", "allow_id": "a-1",
               "client": "192.168.1.140", "kind": "ip", "target": "100.100.100.100", "via": "extension"}),
    ];
    let r = store_across_a_restore(&c, &a, &lines, IngestPoint::AfterBoots).await;
    assert!(is_retryable(&r), "{r:?}");
    assert_eq!(events_of(&c, &a.id).await, 0);
    assert_eq!(
        q1::<i64>(&c, "SELECT count(*) FROM temp_allows WHERE edge_id = ?1", vec![a.id.clone()]).await,
        Some(0)
    );
    assert!(!alert_open(&c, &format!("edge_panic:{}", a.id)).await);
    let r = c.state.logs.store_batch(&c.state, &a.id, &a.fingerprint, batch_of(&lines)).await.unwrap();
    assert_eq!(r.events, 2, "{r:?}");
    assert_eq!(events_of(&c, &a.id).await, 1);
}

/// A restore between a batch's events and its lookups, or between its lookups and its metrics:
/// what follows commits nothing (no metric increment of the stale attempt) and the batch isn't
/// acked; the retry counts it once.
#[tokio::test(flavor = "multi_thread")]
async fn a_restore_during_lookup_or_metric_publication_refuses_the_rest() {
    use picket_core::logs::ingest::IngestPoint;
    let c = common::start_core(plain()).await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    for (i, point) in [IngestPoint::AfterEvents, IngestPoint::AfterLookups].into_iter().enumerate() {
        let now = Timestamp::now() - jiff::SignedDuration::from_mins(1);
        let boot = format!("b{i}");
        let lines = vec![
            query(&boot, 1, &ts(now), "a.example.com", None),
            json!({"t": "event", "ts": ts(now), "boot": boot, "seq": 2, "kind": "activated", "config": "x"}),
        ];
        let r = store_across_a_restore(&c, &a, &lines, point).await;
        assert!(is_retryable(&r), "{point:?}: {r:?}");
        assert_eq!(log_records_points(&c, &a.id).await, 0, "{point:?}");
        let r = c.state.logs.store_batch(&c.state, &a.id, &a.fingerprint, batch_of(&lines)).await.unwrap();
        assert_eq!(r.stored, 1, "{point:?}: {r:?}");
        assert!(log_records_points(&c, &a.id).await > 0, "{point:?}");
    }
}
