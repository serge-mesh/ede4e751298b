//! Logs, attribution and the checks that read logged queries (core.md §6, §9, §10, §12;
//! build-and-test.md §5 rows "Attribution", "Wire check", "Trial bundles", the retro-match parts
//! of "Re-checks and retro-match" and the feed parts of "Block alerts").
//!
//! Each test starts a core with manual feeds in a block bundle and a trial bundle, profiles that
//! enforce or trial them, and a registered edge whose published config the records name; records
//! go in through `POST /v1/logs`. The background analysis is paused, so each test runs the
//! analysis itself ([`picket_core::logs::analysis::drain`]) and sees every result.

use crate::common;

use base64::Engine;
use common::bundles::{build, get, manual_feed, put_entity, save, ui, wait};
use common::logs::{Setup, answer_record, answer_wire, run_retention, short, ts};
use jiff::Timestamp;
use reqwest::Method;
use serde_json::{Value, json};

/// Attribution (core.md §6 steps 1–4): each role, the self-check, an unavailable version, a
/// response-phase block, per-feed hit counters, `last_hit_at`, and `category_blocked` with its
/// evidence; the query-log API shows it all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attribution_roles_self_check_and_block_alerts() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut gone = s.block("b-1", 5, now, "gone.example", "gone.example");
    gone["versions"]["bundles"]["b1"] = json!("deadbeefdeadbeef");
    let mut resp = s.q(
        "b-1",
        4,
        now,
        "cdn.example",
        "block",
        json!({"step": 5, "bundle": "b1", "key": "198.51.100.7", "kind": "ip", "stage": "answer_ip",
               "value": "198.51.100.7"}),
    );
    resp["answers"] = json!(["198.51.100.7", "192.0.2.80"]);
    s.post(vec![
        s.block("b-1", 1, now, "ads.example", "ads.example"),
        s.q(
            "b-1",
            2,
            now,
            "tracker.example",
            "block",
            json!({"step": 3, "bundle": "b1", "key": "tracker.example", "kind": "exact", "stage": "query"}),
        ),
        // Logged as decided by b1, but nothing in b1 matches: a self-check mismatch.
        s.block("b-1", 3, now, "clean.example", "clean.example"),
        resp,
        gone,
        // Not decided by a rule: no attribution.
        s.q("b-1", 6, now, "plain.example", "allow", Value::Null),
    ])
    .await;
    assert_eq!(s.drain().await, 6);

    // Roles: decisive, also matched, overridden by $badfilter.
    let (st, page) = get(&s.c, "/logs?qname=ads.example&match=exact").await;
    assert_eq!(st, 200, "{page}");
    let id = page["items"][0]["id"].as_str().unwrap().to_string();
    // Bounds past the end of the timestamp range (a date picker's 9999-12-31) are its end; a
    // form chrono refused stays refused.
    let (st, far) = get(
        &s.c,
        "/logs?qname=ads.example&match=exact&to=9999-12-31T23:59:00.000Z",
    )
    .await;
    assert_eq!(st, 200, "{far}");
    assert_eq!(far["items"][0]["id"].as_str(), Some(id.as_str()), "{far}");
    let (st, none) = get(
        &s.c,
        "/logs?qname=ads.example&match=exact&from=9999-12-31T23:59:00.000Z",
    )
    .await;
    assert_eq!(st, 200, "{none}");
    assert_eq!(none["items"].as_array().map(Vec::len), Some(0), "{none}");
    let (st, bad) = get(&s.c, "/logs?qname=ads.example&match=exact&to=2026-11-13T10:22Z").await;
    assert_eq!(st, 400, "{bad}");
    let (st, d) = get(&s.c, &format!("/logs/{id}")).await;
    assert_eq!(st, 200, "{d}");
    assert_eq!(d["attribution"]["state"], "complete", "{d}");
    assert_eq!(d["attribution"]["self_check"], "ok", "{d}");
    let roles: Vec<(String, String)> = d["attribution"]["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["feed"].as_str().unwrap().into(),
                m["role"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(
        roles.contains(&("f-sec".into(), "decisive".into()))
            || roles.contains(&("f-priv".into(), "decisive".into())),
        "{roles:?}"
    );
    assert_eq!(roles.len(), 2, "both feeds' rules are found: {roles:?}");
    assert!(roles.iter().any(|(_, r)| r == "also_matched"), "{roles:?}");
    let m0 = &d["attribution"]["matches"][0];
    assert_eq!(m0["text"], "||ads.example^");
    assert_eq!(m0["format"], "adblock");
    assert!(m0["line"].as_i64().is_some());

    let (_, page) = get(&s.c, "/logs?qname=tracker.example&match=exact").await;
    let id = page["items"][0]["id"].as_str().unwrap().to_string();
    let (_, d) = get(&s.c, &format!("/logs/{id}")).await;
    let ms = d["attribution"]["matches"].as_array().unwrap();
    let decisive: Vec<&Value> = ms.iter().filter(|m| m["role"] == "decisive").collect();
    assert_eq!(decisive.len(), 1, "{d}");
    assert_eq!(decisive[0]["text"], "|tracker.example^");
    let over: Vec<&Value> = ms.iter().filter(|m| m["role"] == "overridden").collect();
    assert_eq!(over.len(), 1, "{d}");
    assert_eq!(over[0]["text"], "||tracker.example^");
    assert_eq!(over[0]["by"], "badfilter");

    // The response-phase block: the address rule decides at stage answer_ip.
    let (_, page) = get(&s.c, "/logs?qname=cdn.example&match=exact").await;
    let id = page["items"][0]["id"].as_str().unwrap().to_string();
    let (_, d) = get(&s.c, &format!("/logs/{id}")).await;
    let ms = d["attribution"]["matches"].as_array().unwrap();
    assert!(
        ms.iter()
            .any(|m| m["role"] == "decisive" && m["stage"] == "answer_ip" && m["text"] == "||198.51.100.7^"),
        "{d}"
    );
    assert_eq!(d["attribution"]["self_check"], "ok", "{d}");

    // Self-check (step 4).
    let a = s
        .alert(&format!("attribution_mismatch:{}:b1", s.edge.id))
        .await
        .expect("mismatch alert");
    assert_eq!(a["details"]["qname"], "clean.example");
    // A version that is gone: unavailable, an alert once per edge and version, no self-check.
    let (_, page) = get(&s.c, "/logs?qname=gone.example&match=exact").await;
    let id = page["items"][0]["id"].as_str().unwrap().to_string();
    let (_, d) = get(&s.c, &format!("/logs/{id}")).await;
    assert_eq!(d["attribution"]["state"], "unavailable", "{d}");
    assert_eq!(d["attribution"]["self_check"], "skipped");
    assert!(d["attribution"]["matches"].as_array().unwrap().is_empty());
    let key = format!("attribution_unavailable:{}:b1:deadbeefdeadbeef", s.edge.id);
    assert_eq!(s.alert(&key).await.expect("unavailable alert")["count"], 1);
    // Not rule-decided: no attribution row.
    let (_, page) = get(&s.c, "/logs?qname=plain.example&match=exact").await;
    let id = page["items"][0]["id"].as_str().unwrap().to_string();
    let (_, d) = get(&s.c, &format!("/logs/{id}")).await;
    assert!(d["attribution"].is_null(), "{d}");
    assert_eq!(d["response"]["source"], "preview");

    // Per-feed hit counters at the record's event time (core.md §10 feed_hits{feed, role}).
    assert!(s.metric_total("feed_hits", "\"feed\":\"f-sec\"").await >= 2.0);
    assert!(s.metric_total("feed_hits", "\"role\":\"decisive\"").await >= 3.0);

    // category_blocked (core.md §9): f-sec is a security feed, p1 alerts on security; keyed on
    // (device, registrable domain); evidence copies the record.
    let a = s
        .alert(&picket_core::alerts::category_blocked_key(
            "tablet",
            "ads.example",
        ))
        .await
        .expect("category_blocked");
    assert_eq!(a["severity"], "warning");
    // C3 (core.md §9 record `edge?`): the edge whose record raised it, not only in the details.
    assert_eq!(a["edge"], json!(s.edge.id), "{a}");
    let id = a["id"].as_i64().unwrap();
    // Capture starts after the batch; its backfill copies the record.
    wait("the alert's evidence", || async {
        let (_, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
        ev["items"].as_array().is_some_and(|i| !i.is_empty())
    })
    .await;
    let (st, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
    assert_eq!(st, 200);
    assert_eq!(ev["items"][0]["qname"], "ads.example");
    assert_eq!(ev["counts"]["name"]["ads.example"], 1, "{ev}");
    assert_eq!(ev["rule"]["device"], "tablet");
    // A privacy-only match (f-priv's `|tracker.example^` decides) raises nothing: p1 alerts on
    // security only, but f-sec's overridden rule doesn't count either.
    assert!(
        s.alert(&picket_core::alerts::category_blocked_key(
            "tablet",
            "tracker.example"
        ))
        .await
        .is_none()
    );
    // Later records of the alert's subject are copied as they are analysed.
    s.post(vec![s.block(
        "b-1",
        7,
        Timestamp::now(),
        "www.ads.example",
        "ads.example",
    )])
    .await;
    s.drain().await;
    let (_, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
    assert_eq!(ev["items"].as_array().unwrap().len(), 2, "{ev}");
    assert_eq!(ev["counts"]["name"]["www.ads.example"], 1, "{ev}");
    let (_, missing) = get(&s.c, "/alerts/999999/evidence").await;
    assert_eq!(missing["error"]["code"], "not_found");
}

/// The wire check (core.md §6): agreeing answers, each mismatch kind counted, alerted under the
/// release of the boot that logged them (`unknown` without a hello), kept as examples with their
/// wire; truncated and answer_missing records skipped; the ack never waits for the check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_check_mismatches_examples_and_releases() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let wire = answer_wire("www.example.com", &["cdn.example.net"], &[[192, 0, 2, 1]]);
    let (aid, ans) = answer_record("b-x", 1, now, &wire);
    let mut ok = s.q("b-x", 2, now, "www.example.com", "allow", Value::Null);
    ok["answer_id"] = json!(aid);
    ok["cname"] = json!(["cdn.example.net"]);
    ok["answers"] = json!(["192.0.2.1"]);
    let mut bad = s.q("b-x", 3, now, "www.example.com", "allow", Value::Null);
    bad["answer_id"] = json!(aid);
    bad["cname"] = json!(["other.example"]);
    bad["answers"] = json!(["192.0.2.99"]);
    bad["targets"] = json!(["svc.example"]);
    let mut trunc = s.q("b-x", 4, now, "www.example.com", "allow", Value::Null);
    trunc["answer_id"] = json!(aid);
    trunc["truncated"] = json!(true);
    trunc["answers"] = json!(["192.0.2.77"]);
    let mut missing = s.q("b-x", 5, now, "www.example.com", "allow", Value::Null);
    missing["answer_id"] = json!("00000000000000aa");
    missing["answers"] = json!(["192.0.2.77"]);
    // The ack comes before any check runs (analysis is paused).
    s.post(vec![ans, ok, bad, trunc, missing]).await;
    assert_eq!(
        s.part::<i64>(
            now,
            "SELECT count(*) FROM events WHERE wire_check IS NULL AND answer_id IS NOT NULL"
        ),
        4
    );
    s.drain().await;
    let checks: Vec<(i64, Option<String>)> = {
        let p =
            s.c.dir
                .path()
                .join("logs")
                .join(picket_core::logs::partition::partition_file_name(&now));
        let conn = rusqlite::Connection::open(p).unwrap();
        let mut st = conn
            .prepare("SELECT seq, wire_check FROM events ORDER BY seq")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(
        checks,
        vec![
            (2, Some("ok".into())),
            (3, Some("mismatch".into())),
            (4, Some("skipped".into())),
            (5, Some("skipped".into()))
        ]
    );
    // Counted per kind at the record's event time.
    for kind in ["cname", "answers", "targets"] {
        assert_eq!(
            s.metric_total("wire_mismatch", &format!("\"kind\":\"{kind}\""))
                .await,
            1.0,
            "{kind}"
        );
    }
    // No hello from boot b-x: release `unknown`.
    let a = s
        .alert(&format!("wire_mismatch:{}:unknown", s.edge.id))
        .await
        .expect("wire_mismatch");
    let id = a["id"].as_i64().unwrap();
    let (_, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
    let ex = &ev["examples"][0];
    assert_eq!(ex["kind"], "cname");
    let w = base64::engine::general_purpose::STANDARD
        .decode(ex["wire"].as_str().unwrap())
        .unwrap();
    assert_eq!(w, wire, "the example's wire is the fuzz case");
    assert_eq!(ex["decoded"]["decoded"]["chain"], json!(["cdn.example.net"]));
    assert_eq!(ex["record"]["seq"], 3);

    // A boot the edge reported in hello: its records keep that release, also when they arrive
    // after a newer boot's hello (delayed records across an update).
    let (mut ws, _) = s.edge.session(common::edge::hello("b-old")).await;
    let _ = &mut ws;
    drop(ws);
    let mut later = s.q("b-old", 2, now, "www.example.com", "allow", Value::Null);
    later["answer_id"] = json!(aid);
    later["answers"] = json!(["198.51.100.200"]);
    let (_, ans2) = answer_record("b-old", 1, now, &wire);
    let mut h2 = common::edge::hello("b-new");
    h2["edge_version"] = json!("0.0.1-newer");
    let (ws2, _) = s.edge.session(h2).await;
    drop(ws2);
    // A retention sweep between the new boot's hello and the old boot's spooled batch keeps the
    // old boot's release (storage.md §4: for the log window after it was superseded).
    run_retention(&s.c).await;
    s.post(vec![ans2, later]).await;
    s.drain().await;
    let key = format!("wire_mismatch:{}:{}", s.edge.id, picket_api::VERSION);
    assert!(s.alert(&key).await.is_some(), "the old boot's own release");
    assert!(
        s.alert(&format!("wire_mismatch:{}:0.0.1-newer", s.edge.id))
            .await
            .is_none()
    );
}

/// Trial bundles (core.md §6): would-blocks on the query name, a CNAME target and an answer
/// address; an exception inside the trial bundle; no alert and no EdgeConfig change; a trial
/// enabled while records await their first check; the trial view.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trial_bundles_would_block() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut cname = s.q("b-t", 2, now, "chain.example", "allow", Value::Null);
    cname["cname"] = json!(["x.trial.example"]);
    let mut addr = s.q("b-t", 3, now, "addr.example", "allow", Value::Null);
    addr["answers"] = json!(["203.0.113.9"]);
    // Allowed by an allow bundle (step 2): never checked.
    let step2 = s.q(
        "b-t",
        5,
        now,
        "w.trial.example",
        "allow",
        json!({"step": 2, "bundle": "allow-common", "key": "w.trial.example", "kind": "exact", "stage": "query"}),
    );
    let config_before = s.config.clone();
    s.post(vec![
        s.q("b-t", 1, now, "trial.example", "allow", Value::Null),
        cname,
        addr,
        s.q("b-t", 4, now, "ok.trial.example", "allow", Value::Null),
        step2,
    ])
    .await;
    s.drain().await;
    let rows: Vec<(i64, String, String)> = {
        let p =
            s.c.dir
                .path()
                .join("logs")
                .join(picket_core::logs::partition::partition_file_name(&now));
        let conn = rusqlite::Connection::open(p).unwrap();
        let mut st = conn
            .prepare("SELECT seq, stage, key FROM would_blocks WHERE bundle_id = 'trial-b' ORDER BY seq")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!((rows[0].0, rows[0].1.as_str()), (1, "query"));
    assert_eq!(rows[0].2, "trial.example");
    assert_eq!((rows[1].0, rows[1].1.as_str()), (2, "cname"));
    assert_eq!((rows[2].0, rows[2].1.as_str()), (3, "answer_ip"));
    assert_eq!(
        s.part::<Option<String>>(now, "SELECT trial_check FROM events WHERE seq = 5"),
        None,
        "an allow bundle's allow isn't checked"
    );
    assert!(
        s.part::<Option<String>>(now, "SELECT trial_check FROM events WHERE seq = 4")
            .is_some()
    );
    // Attribution of a would-block: role would_block.
    let mj: String = s.part(now, "SELECT matches_json FROM would_blocks WHERE seq = 1");
    let ms: Value = serde_json::from_str(&mj).unwrap();
    assert_eq!(ms[0]["role"], "would_block");
    assert_eq!(ms[0]["text"], "||trial.example^");
    assert_eq!(
        s.metric_total("trial_would_block", "\"bundle\":\"trial-b\"")
            .await,
        3.0
    );
    // C5 (core.md §10, §12 trial view per edge): recorded per edge, so one edge's chart has
    // them and the all-edges sum still does.
    assert_eq!(
        s.metric_total("trial_would_block", &format!("\"edge\":\"{}\"", s.edge.id))
            .await,
        3.0
    );
    let chart_total = |edge: String| {
        let c = &s.c;
        async move {
            let (st, v) = get(
                c,
                &format!("/metrics?series=trial_would_block&window=1h&edge={edge}"),
            )
            .await;
            assert_eq!(st, 200, "{v}");
            v["series"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|l| l["labels"]["bundle"] == "trial-b")
                .flat_map(|l| l["points"].as_array().unwrap().clone())
                .filter_map(|p| p[1].as_f64())
                .sum::<f64>()
        }
    };
    assert_eq!(chart_total(s.edge.id.clone()).await, 3.0, "one edge's chart");
    assert_eq!(chart_total("all".into()).await, 3.0, "the all-edges sum");
    // No alert, no config change.
    let n: i64 = s
        .scalar_core("SELECT count(*) FROM alerts WHERE kind = 'category_blocked'")
        .await;
    assert_eq!(n, 0);
    assert_eq!(
        s.c.state.edges.publisher.current(&s.edge.id).unwrap().id,
        config_before
    );
    // The trial view.
    let (st, v) = get(&s.c, "/trial-results?profile=p1&bundle=trial-b&window=1h").await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["total"], 3);
    assert!(
        v["names"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["name"] == "chain.example" && n["stage"] == "cname")
    );
    assert_eq!(v["devices"][0]["key"], "tablet");
    assert_eq!(v["limits"].as_array().unwrap().len(), 3);

    // A trial bundle added while a record waits for its first check is checked against it.
    s.post(vec![s.q("b-t", 9, now, "ads.example", "allow", Value::Null)])
        .await;
    put_entity(
        &s.c,
        "profiles",
        "p1",
        json!({"id": "p1", "name": "p1", "block": [], "trial_bundles": ["trial-b", "b1"]}),
    )
    .await;
    s.drain().await;
    assert_eq!(
        s.part::<i64>(
            now,
            "SELECT count(*) FROM would_blocks WHERE seq = 9 AND bundle_id = 'b1'"
        ),
        1
    );
    // A window past the query-log retention is refused.
    let (st, _) = get(&s.c, "/trial-results?profile=p1&bundle=trial-b&window=96h").await;
    assert_eq!(st, 400);
}

/// Retro-match (core.md §6, §7): a feed run's new `dns` entry against the closed hour's
/// answered queries, counted in `retro_hits{feed}` and raising `category_answered` only for the
/// profile that enforces the bundle (not the one that trials it); a late record matched against
/// additions already applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retro_match_raises_category_answered_for_the_enforcing_profile() {
    let s = Setup::new(None).await;
    let then = Timestamp::now() - jiff::SignedDuration::from_mins(150);
    let mut trialled = s.q("b-r", 2, then, "later.example", "allow", Value::Null);
    trialled["profile"] = json!("p2");
    trialled["device"] = json!("laptop");
    let mut via_target = s.q("b-r", 3, then, "front.example", "allow", Value::Null);
    via_target["cname"] = json!(["edge.later.example"]);
    s.post(vec![
        s.q("b-r", 1, then, "later.example", "allow", Value::Null),
        trialled,
        via_target,
    ])
    .await;
    s.drain().await;
    // The hour closes: its answered names are stored.
    picket_core::logs::analysis::drain_retro(&s.c.state)
        .await
        .unwrap();
    assert!(
        s.part::<i64>(
            then,
            "SELECT count(*) FROM answered_names WHERE qname = 'later.example'"
        ) >= 1
    );
    assert_eq!(
        s.part::<i64>(
            then,
            "SELECT count(*) FROM answered_names WHERE qname = 'edge.later.example'"
        ),
        1
    );
    // f-sec adds the name.
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n||later.example^\n",
    )
    .await;
    let hits = picket_core::logs::analysis::drain_retro(&s.c.state)
        .await
        .unwrap();
    assert_eq!(
        hits, 2,
        "the enforcing profile's two records, not the trialling one's"
    );
    assert_eq!(s.metric_total("retro_hits", "\"feed\":\"f-sec\"").await, 2.0);
    let key = picket_core::alerts::category_answered_key(
        picket_core::alerts::AnsweredBy::Feed("f-sec"),
        "later.example",
    );
    let a = s.alert(&key).await.expect("category_answered");
    assert_eq!(a["details"]["profile"], "p1");
    assert_eq!(a["count"], 2);
    // Matching again finds nothing new.
    assert_eq!(
        picket_core::logs::analysis::drain_retro(&s.c.state)
            .await
            .unwrap(),
        0
    );
    // A late record in the closed hour, answered before the addition: matched on arrival.
    s.post(vec![s.q(
        "b-r",
        4,
        then,
        "www.later.example",
        "allow",
        Value::Null,
    )])
    .await;
    s.drain().await;
    let hits = picket_core::logs::analysis::drain_retro(&s.c.state)
        .await
        .unwrap();
    assert_eq!(hits, 1);
    // The hour's retro progress (core.db) covers the late record.
    let seen: i64 = s
        .scalar_core(&format!(
            "SELECT seen FROM retro_progress WHERE hour = '{}'",
            picket_core::logs::partition::hour_key(&then)
        ))
        .await;
    assert_eq!(
        seen,
        s.part::<i64>(then, "SELECT rowid FROM events WHERE seq = 4")
    );
    assert_eq!(
        s.part::<i64>(
            then,
            "SELECT count(*) FROM answered_names WHERE qname = 'www.later.example'"
        ),
        1
    );
    assert_eq!(s.alert(&key).await.unwrap()["count"], 3);
}

/// The query-log API (core.md §12, api.md §7): filters and cursor paging, the top panels,
/// devices, the device and profile views; results kept across a restart, and a restart
/// mid-analysis loses nothing and stores nothing twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_log_api_and_restart() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(60);
    let mut lines = Vec::new();
    for i in 0..7u64 {
        lines.push(s.block(
            "b-q",
            i + 1,
            now + jiff::SignedDuration::from_millis(i as i64),
            "ads.example",
            "ads.example",
        ));
    }
    let mut other = s.q("b-q", 20, now, "news.example", "allow", Value::Null);
    other["device"] = json!("phone");
    other["client"] = json!("192.0.2.20");
    lines.push(other);
    s.post(lines).await;
    // Search with paging.
    let (st, p1) = get(&s.c, "/logs?decision=block&limit=3").await;
    assert_eq!(st, 200, "{p1}");
    assert_eq!(p1["items"].as_array().unwrap().len(), 3);
    let cur = p1["next_cursor"].as_str().unwrap().to_string();
    let (_, p2) = get(&s.c, &format!("/logs?decision=block&limit=3&cursor={cur}")).await;
    let (_, p3) = get(
        &s.c,
        &format!(
            "/logs?decision=block&limit=3&cursor={}",
            p2["next_cursor"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(p3["items"].as_array().unwrap().len(), 1);
    assert!(p3["next_cursor"].is_null());
    let seqs: Vec<i64> = [&p1, &p2, &p3]
        .iter()
        .flat_map(|p| {
            p["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["seq"].as_i64().unwrap())
        })
        .collect();
    assert_eq!(seqs, vec![7, 6, 5, 4, 3, 2, 1], "newest first, each once");
    let (_, v) = get(&s.c, "/logs?qname=example&match=substring&device=phone").await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    let (_, v) = get(&s.c, "/logs?qname=example&match=suffix").await;
    assert_eq!(v["items"].as_array().unwrap().len(), 8);
    let (_, v) = get(&s.c, "/logs?bundle=b1&profile=p1&client=192.0.2.10").await;
    assert_eq!(v["items"].as_array().unwrap().len(), 7);
    let (st, v) = get(&s.c, "/logs?decision=maybe").await;
    assert_eq!(st, 400, "{v}");
    let (st, _) = get(&s.c, "/logs/not-an-id").await;
    assert_eq!(st, 400);
    // Top panels.
    let (st, t) = get(&s.c, "/top?kind=blocked&window=1h").await;
    assert_eq!(st, 200, "{t}");
    assert_eq!(t["items"][0], json!({"key": "ads.example", "count": 7}));
    let (_, t) = get(&s.c, "/top?kind=clients&window=1h&limit=1").await;
    assert_eq!(t["items"], json!([{"key": "tablet", "count": 7}]));
    let (_, t) = get(&s.c, "/top?kind=allowed&window=1h").await;
    assert_eq!(t["items"][0]["key"], "news.example");
    let (st, _) = get(&s.c, "/top?kind=blocked&window=72h").await;
    assert_eq!(st, 200);
    let (st, _) = get(&s.c, "/top?kind=nope&window=1h").await;
    assert_eq!(st, 400);
    // Devices and views.
    let (_, d) = get(&s.c, "/devices").await;
    let keys: Vec<&str> = d["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["key"].as_str().unwrap())
        .collect();
    assert!(keys.contains(&"tablet") && keys.contains(&"phone"), "{d}");
    let (st, sum) = get(&s.c, "/query-summary?device=tablet&window=1h").await;
    assert_eq!(st, 200, "{sum}");
    assert_eq!(sum["queries"], 7);
    assert_eq!(sum["blocked"], 7);
    assert_eq!(sum["top_blocked"][0]["bundle"], "b1");
    assert_eq!(sum["decisions"][0]["labels"]["decision"], "block");
    let (_, sum) = get(&s.c, "/query-summary?profile=p1&window=6h").await;
    assert_eq!(sum["queries"], 8);
    assert_eq!(sum["devices"].as_array().unwrap().len(), 2);
    let (st, _) = get(&s.c, "/query-summary?window=1h").await;
    assert_eq!(st, 400);

    // A stop cuts a pass off after its partition results, before its core.db effects: nothing
    // of it counted yet. The restarted core repeats the batch, storing each result and raising
    // each alert once (README §2 Restarts; build-and-test.md §5).
    s.c.state
        .analysis
        .fail_at(picket_core::logs::analysis::FailPoint::AnalysisBeforeEffects);
    assert!(
        picket_core::logs::analysis::run_batch(&s.c.state, picket_core::logs::partition::hour_start(&now))
            .await
            .is_err()
    );
    let key = picket_core::alerts::category_blocked_key("tablet", "ads.example");
    assert!(s.alert(&key).await.is_none(), "no effect before the commit");
    // The stopped core may keep its directory's lock while this process runs (see
    // `common::snapshot_dir`), so the restart runs on a snapshot taken after the stop.
    s.c.stop.cancel();
    let copy = tempfile::tempdir().unwrap();
    common::snapshot_dir(s.c.dir.path(), copy.path());
    let dir = copy.path().to_path_buf();
    let stop = tokio_util::sync::CancellationToken::new();
    let opts = picket_core::run::StartOptions {
        release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
        any_port: true,
        clock_synced: Some(true),
        disk_watch: false,
        ..Default::default()
    };
    let (state, _info) = picket_core::run::start_with(&dir, stop.clone(), opts)
        .await
        .unwrap();
    // The background loop finds the pending records at start: its progress reaches the last.
    let part = dir
        .join("logs")
        .join(picket_core::logs::partition::partition_file_name(&now));
    let last: i64 = rusqlite::Connection::open(&part)
        .unwrap()
        .query_row("SELECT max(rowid) FROM events", [], |r| r.get(0))
        .unwrap();
    let hk = picket_core::logs::partition::hour_key(&now);
    wait("the restarted core's analysis", || {
        let st = state.clone();
        let hk = hk.clone();
        async move {
            st.db
                .read(move |c| {
                    Ok::<_, anyhow::Error>(picket_core::logs::analysis::progress_get(
                        c,
                        &hk,
                        picket_core::logs::analysis::PROGRESS,
                    )?)
                })
                .await
                .unwrap()
                == last
        }
    })
    .await;
    let a = state
        .alerts
        .get_by_key(&key)
        .await
        .unwrap()
        .expect("raised after the restart");
    assert_eq!(a.count, 7, "once per blocked record, none twice");
    let conn = rusqlite::Connection::open(&part).unwrap();
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM attribution", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 7, "one attribution row per blocked record");
    let would: i64 = conn
        .query_row("SELECT count(*) FROM would_blocks", [], |r| r.get(0))
        .unwrap();
    assert_eq!(would, 0);
    drop(state);
    stop.cancel();
}

/// Unchecked cold lookups (core.md §6; bundles.md §6): core checks the name against the cold
/// shards of the head the record's versions name; a hit is a missed block, counted, with the
/// key's `last_hit_at` set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unchecked_cold_lookups_find_missed_blocks() {
    let s = Setup::new(None).await;
    manual_feed(&s.c, "f-cold", json!({"category": "security"})).await;
    save(&s.c, "f-cold", "||coldhit.example^\n||other-cold.example^\n").await;
    put_entity(
        &s.c,
        "bundles",
        "b-cold",
        json!({"id": "b-cold", "name": "b-cold", "feeds": [{"feed": "f-cold", "tier": "cold"}]}),
    )
    .await;
    let head = build(&s.c, "b-cold").await.expect("cold head");
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut r = s.q("b-c", 1, now, "www.coldhit.example", "allow", Value::Null);
    r["cold_unchecked"] = json!(["b-cold"]);
    r["versions"]["bundles"]["b-cold"] = json!(short(&head));
    let mut miss = s.q("b-c", 2, now, "fine.example", "allow", Value::Null);
    miss["cold_unchecked"] = json!(["b-cold"]);
    miss["versions"]["bundles"]["b-cold"] = json!(short(&head));
    s.post(vec![r, miss]).await;
    s.drain().await;
    assert_eq!(
        s.part::<String>(now, "SELECT cold_check FROM events WHERE seq = 1"),
        "missed"
    );
    assert_eq!(
        s.part::<String>(now, "SELECT cold_check FROM events WHERE seq = 2"),
        "ok"
    );
    assert_eq!(
        s.metric_total("cold_missed_blocks", "\"bundle\":\"b-cold\"")
            .await,
        1.0
    );
    let n: i64 = s
        .scalar_core("SELECT count(*) FROM bundle_key_hits WHERE bundle_id = 'b-cold'")
        .await;
    assert_eq!(n, 1);
}

/// The UI's paths are registered, described in the OpenAPI document, and behind basic auth.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoints_are_described_and_protected() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let (_, doc) = get(&c, "/openapi.json").await;
    for p in [
        "/api/ui/v1/logs",
        "/api/ui/v1/logs/{id}",
        "/api/ui/v1/top",
        "/api/ui/v1/devices",
        "/api/ui/v1/query-summary",
        "/api/ui/v1/trial-results",
        "/api/ui/v1/alerts/{id}/evidence",
    ] {
        assert!(
            doc["paths"].get(p).is_some(),
            "{p} missing from the OpenAPI document"
        );
    }
    for s in [
        "LogPage",
        "LogDetail",
        "TopList",
        "DeviceList",
        "Summary",
        "TrialResults",
        "EvidenceView",
    ] {
        assert!(doc["components"]["schemas"].get(s).is_some(), "schema {s}");
    }
    let r = common::client()
        .get(format!("{}/api/ui/v1/logs", c.base("http")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = ui(&c, Method::GET, "/devices").send().await.unwrap();
    assert_eq!(r.status(), 200);
}

/// The reply a client got (core.md §6; build-and-test.md §5 Attribution): TTLs rebuilt under the
/// profile clamp and for a stale reply, a TC reply, a CNAME rewrite's reply, and one whose final
/// reply was too large for `response` (shown from its preview, incomplete, with its upstream
/// answer as separate evidence).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replies_are_rebuilt_as_the_client_got_them() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    // TTL 256 in the logged answer.
    let wire = answer_wire("www.example.com", &[], &[[192, 0, 2, 1]]);
    let (aid, ans) = answer_record("b-p", 1, now, &wire);
    let with = |seq: u64, f: &dyn Fn(&mut Value)| {
        let mut r = s.q("b-p", seq, now, "www.example.com", "allow", Value::Null);
        r["answer_id"] = json!(aid);
        r["answers"] = json!(["192.0.2.1"]);
        r["age_s"] = json!(10);
        r["upstream"] =
            json!({"group": "cloudflare", "upstream": "cf-dot", "ms": 3, "cached": true, "stale": false});
        f(&mut r);
        r
    };
    let fresh = with(2, &|_| {});
    let stale = with(3, &|r| {
        r["upstream"]["stale"] = json!(true);
        r["upstream"]["cause"] = json!("timeout");
    });
    let tc = with(4, &|r| r["tc"] = json!(true));
    // A CNAME rewrite whose reply the edge logged (`response`), and one too large to log.
    let reply = answer_wire("www.example.com", &["mine.example"], &[[192, 0, 2, 9]]);
    let rewrite = with(5, &|r| {
        r["decision"] = json!("rewrite");
        r["reason"] =
            json!({"step": 3, "bundle": "b1", "key": "www.example.com", "kind": "rich", "stage": "query"});
        r["response"] = json!(base64::engine::general_purpose::STANDARD.encode(&reply));
        r["cname"] = json!(["mine.example"]);
    });
    let big = with(6, &|r| {
        r["decision"] = json!("rewrite");
        r["reason"] =
            json!({"step": 3, "bundle": "b1", "key": "www.example.com", "kind": "rich", "stage": "query"});
        r["truncated"] = json!(true);
    });
    s.post(vec![ans, fresh, stale, tc, rewrite, big]).await;
    let c = &s.c;
    let edge = s.edge.id.clone();
    let detail = |seq: i64| {
        let id = picket_core::logs::record::record_id(&ts(now), &edge, "b-p", seq);
        async move { get(c, &format!("/logs/{id}")).await.1 }
    };
    let d = detail(2).await;
    assert_eq!(d["response"]["source"], "answer", "{d}");
    let recs = d["response"]["records"].as_array().unwrap();
    // 256 − 10 s cached, clamped to the profile's max of 120.
    assert!(
        recs.iter()
            .any(|r| r.as_str().unwrap().contains(" 120 IN A 192.0.2.1")),
        "{recs:?}"
    );
    assert_eq!(d["answer"]["id"], aid);
    let d = detail(3).await;
    let recs = d["response"]["records"].as_array().unwrap();
    assert!(
        recs.iter()
            .any(|r| r.as_str().unwrap().contains(" 30 IN A 192.0.2.1")),
        "stale_ttl: {recs:?}"
    );
    let d = detail(4).await;
    assert_eq!(d["response"]["source"], "tc", "{d}");
    assert_eq!(d["response"]["tc"], true);
    assert!(
        d["response"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.as_str().unwrap().starts_with(';')),
        "a TC reply holds the question only: {d}"
    );
    let d = detail(5).await;
    assert_eq!(d["response"]["source"], "response", "{d}");
    assert_eq!(d["response"]["incomplete"], false);
    assert!(
        d["response"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap().contains("CNAME"))
    );
    let d = detail(6).await;
    assert_eq!(d["response"]["source"], "preview", "{d}");
    assert_eq!(d["response"]["incomplete"], true);
    assert_eq!(
        d["answer"]["id"], aid,
        "the upstream answer stays separate evidence"
    );
}

/// The tiering dry run (bundles.md §2 Tiering): a tier change replays the window's blocks
/// against the proposed split and reports how many would have come from cold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tiering_dry_run_counts_blocks_from_cold() {
    let s = Setup::new(None).await;
    // This test runs the dry run itself.
    s.c.state.compiler.set_dry_runs_paused(true);
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n||sec-only.example^\n",
    )
    .await;
    build(&s.c, "b1").await.unwrap();
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut lines = Vec::new();
    for i in 0..3u64 {
        lines.push(s.block("b-d", i + 1, now, "ads.example", "ads.example"));
    }
    for i in 0..2u64 {
        lines.push(s.block("b-d", i + 10, now, "x.sec-only.example", "sec-only.example"));
    }
    s.post(lines).await;
    let due = picket_core::compiler::tier::dry_runs_due(&s.c.state)
        .await
        .unwrap();
    assert!(due.is_empty(), "no cold-capable bundle yet: {due:?}");
    put_entity(
        &s.c,
        "bundles",
        "b1",
        json!({"id": "b1", "name": "b1", "feeds": [{"feed": "f-sec", "tier": "cold"}, {"feed": "f-priv"}]}),
    )
    .await;
    let due = picket_core::compiler::tier::dry_runs_due(&s.c.state)
        .await
        .unwrap();
    assert_eq!(due.len(), 1);
    let r = picket_core::compiler::tier::dry_run(&s.c.state, &due[0], Timestamp::now())
        .await
        .unwrap();
    assert_eq!(r.status, "done", "{r:?}");
    assert_eq!(r.blocks, Some(5));
    // ads.example is also listed by f-priv (hot): only sec-only.example's two blocks go cold.
    assert_eq!(r.cold_blocks, Some(2), "{r:?}");
    assert!(
        picket_core::compiler::tier::dry_runs_due(&s.c.state)
            .await
            .unwrap()
            .is_empty()
    );
    let (_, st) = get(&s.c, "/bundles/b1/status").await;
    assert_eq!(st["dry_run"]["cold_blocks"], 2, "{st}");
}

/// Evidence at its caps (core.md §9): half the first and half the latest copies, exact counts,
/// and `alert_evidence_full` when the budget fills.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evidence_keeps_first_and_latest_within_its_caps() {
    let s = Setup::new(Some(
        json!({"alerts": {"evidence_per_alert": 10, "evidence_total_mib": 1}}),
    ))
    .await;
    let t0 = Timestamp::now() - jiff::SignedDuration::from_secs(120);
    s.post(vec![s.block("b-e", 1, t0, "ads.example", "ads.example")])
        .await;
    s.drain().await;
    let a = s
        .alert(&picket_core::alerts::category_blocked_key(
            "tablet",
            "ads.example",
        ))
        .await
        .unwrap();
    let id = a["id"].as_i64().unwrap();
    wait("capture to start", || async {
        let (_, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
        ev["rule"].is_object()
    })
    .await;
    let mut lines = Vec::new();
    for i in 0..20u64 {
        lines.push(s.block(
            "b-e",
            i + 2,
            t0 + jiff::SignedDuration::from_secs(i as i64 + 1),
            &format!("h{i}.ads.example"),
            "ads.example",
        ));
    }
    s.post(lines).await;
    s.drain().await;
    let (_, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
    // In event-time order (the view pages newest stored first).
    let mut items: Vec<(&str, &str)> = ev["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["ts"].as_str().unwrap(), r["qname"].as_str().unwrap()))
        .collect();
    items.sort();
    let names: Vec<&str> = items.into_iter().map(|(_, n)| n).collect();
    assert_eq!(names.len(), 10, "{names:?}");
    // The first five and the latest five.
    assert_eq!(names[0], "ads.example");
    assert_eq!(names[4], "h3.ads.example");
    assert_eq!(names[5], "h15.ads.example");
    assert_eq!(names[9], "h19.ads.example");
    assert_eq!(ev["counts"]["client"]["tablet"], 21, "{ev}");
    assert_eq!(ev["counts"]["name"].as_object().unwrap().len(), 21);
    // Fill the budget: alert_evidence_full.
    let filler = "x".repeat(1024 * 1024);
    let id2 = id;
    s.c.state
        .db
        .write(move |db| {
            db.execute(
                "INSERT INTO alert_evidence(alert_id, edge_id, boot, seq, ts, record_json) VALUES (?1, 'e', 'b', 999999, '2000-01-01T00:00:00.000000Z', ?2)",
                rusqlite::params![id2, filler],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    picket_core::logs::evidence::check_budget(&s.c.state, &s.c.state.alerts)
        .await
        .unwrap();
    let full = s.alert("alert_evidence_full").await.expect("alert_evidence_full");
    assert_eq!(full["severity"], "critical");
    // Full: counts go on, nothing more is copied.
    s.post(vec![s.block(
        "b-e",
        100,
        Timestamp::now(),
        "late.ads.example",
        "ads.example",
    )])
    .await;
    s.drain().await;
    let (_, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
    assert!(
        ev["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["qname"] != "late.ads.example")
    );
    assert_eq!(ev["counts"]["client"]["tablet"], 22);
}

/// Attribution against parts from different heads (core.md §6 step 1; api.md §5 `versions`): a
/// key is replayed against its own shard's head, so a rule a newer head removed still decides
/// while that shard is on the previous head.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parts_replay_against_their_own_heads() {
    let s = Setup::new(None).await;
    let head1 = s.b1.clone();
    // Head 2: f-sec drops tracker.example's rule and adds another.
    save(&s.c, "f-sec", "||ads.example^\n||198.51.100.7^\n||new.example^\n").await;
    save(&s.c, "f-priv", "||ads.example^\n").await;
    let head2 = build(&s.c, "b1").await.unwrap();
    assert_ne!(head1, head2);
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut parts = s.block("b-v", 1, now, "tracker.example", "tracker.example");
    parts["versions"]["bundles"]["b1"] = json!({
        "head": short(&head2),
        "shards": {"0": short(&head1)},
        "ip_shards": {},
        "segments": {"patterns.bin": short(&head2), "rich.json": short(&head1)},
    });
    let mut plain = s.block("b-v", 2, now, "tracker.example", "tracker.example");
    plain["versions"]["bundles"]["b1"] = json!(short(&head2));
    s.post(vec![parts, plain]).await;
    s.drain().await;
    let id = picket_core::logs::record::record_id(&ts(now), &s.edge.id, "b-v", 1);
    let (_, d) = get(&s.c, &format!("/logs/{id}")).await;
    assert_eq!(d["attribution"]["self_check"], "ok", "shard 0 is on head 1: {d}");
    assert!(
        d["attribution"]["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["role"] == "decisive" && m["feed"] == "f-priv")
    );
    let id = picket_core::logs::record::record_id(&ts(now), &s.edge.id, "b-v", 2);
    let (_, d) = get(&s.c, &format!("/logs/{id}")).await;
    assert_eq!(
        d["attribution"]["self_check"], "mismatch",
        "head 2 has no such rule: {d}"
    );
    assert!(d["attribution"]["matches"].as_array().unwrap().is_empty());
}

/// `category_blocked` for a block by a sync lookup (core.md §9 "Block alerts per profile";
/// build-and-test.md §5 "Block alerts", each `alert_lookup_providers` setting): unset alerts on every
/// `security` provider, a list on the providers it names (a non-security one raises `info`), `[]`
/// on none. The alert keys on (device, domain) with the feed blocks' evidence rule and edge, and
/// names the provider's reason and detail; analysing again or a resent record adds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_lookup_blocks_raise_category_blocked_per_alert_lookup_providers() {
    let s = Setup::new(None).await;
    for (id, category) in [("q-sec", "security"), ("q-priv", "privacy")] {
        put_entity(
            &s.c,
            "lookup-providers",
            id,
            json!({"id": id, "name": id, "module": "http_json", "category": category,
                   "config": {"url": "https://lookup.example/{domain}", "verdict": {"pointer": "/risk", "block_if": ">= 7"}},
                   "recheck": {"enabled": false}}),
        )
        .await;
    }
    for (id, alerting) in [
        ("p-unset", None),
        ("p-list", Some(json!(["q-priv"]))),
        ("p-none", Some(json!([]))),
    ] {
        let mut body = json!({"id": id, "name": id,
            "lookup_providers": [{"provider": "q-sec", "mode": "sync"}, {"provider": "q-priv", "mode": "sync"}]});
        if let Some(a) = alerting {
            body["alert_lookup_providers"] = a;
        }
        put_entity(&s.c, "profiles", id, body).await;
    }
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let item = |provider: &str| {
        json!({"provider": provider, "verdict": "block", "score": 0.97, "reason": format!("{provider}: risk >= 7"),
               "cached": false, "obtained_at": ts(now), "gen": "0000000000000000", "ms": 12,
               "timed_out": false, "retry": false, "detail": {"risk": 9, "list": "malware"}})
    };
    let clean = json!({"provider": "q-priv", "verdict": "clean", "cached": true, "gen": "0000000000000000",
                       "ms": 0, "timed_out": false, "retry": false});
    let rec = |seq: u64, profile: &str, device: &str, qname: &str, lookups: Value| {
        let mut r = s.q(
            "b-lk",
            seq,
            now,
            qname,
            "block",
            json!({"step": 4, "kind": "lookup", "stage": "query", "provider": lookups[0]["provider"]}),
        );
        r["profile"] = json!(profile);
        r["device"] = json!(device);
        r["answers"] = json!(["0.0.0.0"]);
        r["lookups"] = lookups;
        r
    };
    let records = vec![
        // Unset: every security provider alerts (warning), a privacy one doesn't.
        rec(
            1,
            "p-unset",
            "dev-1",
            "www.bad.example",
            json!([item("q-sec"), clean.clone()]),
        ),
        rec(2, "p-unset", "dev-2", "priv.example", json!([item("q-priv")])),
        // A list: only the providers it names, a non-security one at `info`.
        rec(3, "p-list", "dev-3", "listed.example", json!([item("q-priv")])),
        rec(4, "p-list", "dev-4", "unlisted.example", json!([item("q-sec")])),
        // []: none.
        rec(
            5,
            "p-none",
            "dev-5",
            "none.example",
            json!([item("q-sec"), item("q-priv")]),
        ),
    ];
    s.post(records.clone()).await;
    assert_eq!(s.drain().await, 5);

    let key = |d: &str, n: &str| picket_core::alerts::category_blocked_key(d, n);
    let a = s
        .alert(&key("dev-1", "www.bad.example"))
        .await
        .expect("unset alert_lookup_providers: a security provider's Block alerts");
    assert_eq!(a["severity"], "warning", "{a}");
    assert_eq!(a["edge"], json!(s.edge.id), "{a}");
    assert_eq!(a["details"]["domain"], "bad.example", "{a}");
    let providers = a["details"]["providers"].as_array().expect("providers");
    assert_eq!(providers.len(), 1, "only Blocks from alerting providers: {a}");
    assert_eq!(providers[0]["provider"], "q-sec");
    assert_eq!(providers[0]["category"], "security");
    assert_eq!(providers[0]["reason"], "q-sec: risk >= 7");
    assert_eq!(providers[0]["detail"]["list"], "malware");
    // F3 (providers.md §4 `score: Option<f32>`): the provider's 0.97 stays 0.97, not the f32's
    // widened 0.9700000286102296, in the alert and in the record's view.
    assert_eq!(providers[0]["score"], json!(0.97), "{a}");
    let (_, page) = get(&s.c, "/logs?qname=www.bad.example&match=exact").await;
    let rid = page["items"][0]["id"]
        .as_str()
        .expect("the record's id")
        .to_string();
    let (_, rec) = get(&s.c, &format!("/logs/{rid}")).await;
    assert_eq!(rec["lookups"][0]["score"], json!(0.97), "{rec}");
    // providers.md §4, api.md §5: the record's view holds the module's detail as the object the
    // alert's `details.providers[]` holds, not as JSON text.
    assert_eq!(rec["lookups"][0]["detail"], providers[0]["detail"], "{rec}");
    assert_eq!(rec["lookups"][0]["detail"]["list"], "malware", "{rec}");
    let id = a["id"].as_i64().unwrap();
    wait("the lookup alert's evidence", || async {
        let (_, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
        ev["items"].as_array().is_some_and(|i| !i.is_empty())
    })
    .await;
    let (_, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
    assert_eq!(ev["items"][0]["qname"], "www.bad.example", "{ev}");
    assert_eq!(ev["rule"]["device"], "dev-1", "{ev}");
    assert_eq!(ev["rule"]["domain"], "bad.example", "{ev}");

    assert!(
        s.alert(&key("dev-2", "priv.example")).await.is_none(),
        "unset alert_lookup_providers: a privacy provider doesn't alert"
    );
    let a = s
        .alert(&key("dev-3", "listed.example"))
        .await
        .expect("a listed provider alerts");
    assert_eq!(a["severity"], "info", "a non-security provider: {a}");
    assert_eq!(a["details"]["providers"][0]["provider"], "q-priv", "{a}");
    assert!(
        s.alert(&key("dev-4", "unlisted.example")).await.is_none(),
        "a provider the list doesn't name doesn't alert"
    );
    assert!(
        s.alert(&key("dev-5", "none.example")).await.is_none(),
        "alert_lookup_providers [] turns them off"
    );
    let n: i64 = s
        .scalar_core("SELECT count(*) FROM alerts WHERE kind = 'category_blocked'")
        .await;
    assert_eq!(n, 2);

    // Exactly once: nothing left to analyse, and a resent batch is deduplicated.
    assert_eq!(s.drain().await, 0);
    s.post(records).await;
    s.drain().await;
    let (count, history): (i64, i64) = (
        s.scalar_core("SELECT sum(count) FROM alerts WHERE kind = 'category_blocked'")
            .await,
        s.scalar_core(
            "SELECT count(*) FROM alert_history WHERE alert_id IN
               (SELECT id FROM alerts WHERE kind = 'category_blocked')",
        )
        .await,
    );
    assert_eq!((count, history), (2, 2));
}
