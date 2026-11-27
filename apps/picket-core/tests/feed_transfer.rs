//! Feed export and import (build-and-test.md §5 "Feed export and import", feeds.md §4, api.md
//! §7): both export forms of each format imported as a new manual feed with the same settings,
//! open entries and first-seen dates; merging and replacing a manual feed; merging into an
//! `aggregate` provider feed (an import run); the refusals.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use common::feeds::{create_feed, ui, wait_until};
use common::{Core, client};
use jiff::Timestamp;
use picket_core::modules::download::testkit::{Reply, Seen, TestServer};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const HOST: &str = "lists.example";

async fn core_with(srv: Option<&TestServer>) -> Core {
    common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
            feed_http: srv.map(|s| s.http_options()).unwrap_or_default(),
            ..Default::default()
        },
    )
    .await
}

async fn get(c: &Core, path: &str) -> reqwest::Response {
    client()
        .get(common::feeds::url(c, path))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap()
}

async fn get_json(c: &Core, path: &str) -> Value {
    let r = get(c, path).await;
    assert_eq!(r.status(), StatusCode::OK, "{path}");
    r.json().await.unwrap()
}

async fn runs(c: &Core, feed: &str) -> i64 {
    let f = feed.to_string();
    c.state
        .db
        .read(move |db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT count(*) FROM feed_runs WHERE feed_id = ?1",
                [f],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap()
}

/// (rule_type, raw, first_seen_at) of each open entry, sorted.
async fn entries(c: &Core, feed: &str) -> Vec<(String, String, String)> {
    let f = feed.to_string();
    c.state
        .db
        .read(move |db| {
            let mut st = db.prepare(
                "SELECT rule_type, raw, first_seen_at FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NULL ORDER BY 1, 2",
            )?;
            let v = st
                .query_map([f], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap()
}

/// Waits until `feed` has `n` runs and is free.
async fn runs_done(c: &Core, feed: &str, n: i64) {
    wait_until("the runs", || async {
        runs(c, feed).await >= n && !c.state.feeds.is_busy(feed)
    })
    .await;
}

async fn save(c: &Core, feed: &str, content: &str) {
    let info = get(c, &format!("/feeds/{feed}/file")).await;
    let base = if info.status() == StatusCode::OK {
        Some(
            info.json::<Value>().await.unwrap()["version"]
                .as_str()
                .unwrap()
                .to_string(),
        )
    } else {
        None
    };
    let r = ui(c, Method::PUT, &format!("/feeds/{feed}/file"))
        .json(&json!({"content": content, "base_version": base}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

async fn import(c: &Core, path: &str, body: Vec<u8>) -> (StatusCode, Value) {
    let r = ui(c, Method::POST, path)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let st = r.status();
    (st, r.json().await.unwrap_or(Value::Null))
}

fn day(s: &str) -> String {
    format!("{s}T00:00:00.000000Z")
}

/// An `adblock` manual feed (browser rules kept, dates set by directives): its JSON export and
/// its file export each imported as a new manual feed give the same open entries and dates, its
/// settings, every rule type `replace`; a file export's header restores category and warn_on.
#[tokio::test(flavor = "multi_thread")]
async fn adblock_round_trips_through_both_exports() {
    let c = core_with(None).await;
    create_feed(
        &c,
        json!({"id": "src", "name": "Source list", "format": "adblock", "category": "security", "warn_on": [],
               "modes": {"dns": {"mode": "replace"}, "ip": {"mode": "replace"}, "browser": {"mode": "replace"}}}),
    )
    .await;
    save(
        &c,
        "src",
        "! a list\n! picket-first-seen: 2021-06-01\n||old.example^\n||old2.example^\n! picket-first-seen: 2023-02-14T09:30:00Z\n||phish.example^\n! picket-first-seen: none\n||new.example^\nexample.org##.ad\n",
    )
    .await;
    runs_done(&c, "src", 1).await;
    let src = entries(&c, "src").await;
    assert_eq!(src.len(), 5, "{src:?}");
    assert!(
        src.iter()
            .any(|e| e.1 == "||old.example^" && e.2 == day("2021-06-01"))
    );
    assert!(src.iter().any(|e| e.0 == "browser"));
    // The JSON export: settings, then entries as stored.
    let r = get(&c, "/feeds/src/export").await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("src.json")
    );
    let export = r.bytes().await.unwrap().to_vec();
    let doc: Value = serde_json::from_slice(&export).unwrap();
    assert_eq!(doc["picket_feed_export"], 1);
    assert_eq!(doc["feed"]["category"], "security");
    assert_eq!(doc["entries"].as_array().unwrap().len(), 5);
    let first_key = std::str::from_utf8(&export)
        .unwrap()
        .find("\"picket_feed_export\"")
        .unwrap();
    assert!(first_key < std::str::from_utf8(&export).unwrap().find("\"entries\"").unwrap());
    let (st, v) = import(&c, "/feeds/import?id=copy", export.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    runs_done(&c, "copy", 1).await;
    let copy = entries(&c, "copy").await;
    assert_eq!(copy, src, "the same open entries and first-seen dates");
    let f = get_json(&c, "/feeds/copy").await;
    assert_eq!(
        (f["name"].as_str(), f["category"].as_str()),
        (Some("Source list"), Some("security"))
    );
    assert_eq!(f["warn_on"], json!([]));
    assert_eq!(f["provider"], Value::Null);
    for t in ["dns", "ip", "browser"] {
        assert_eq!(f["modes"][t]["mode"], "replace", "{t}");
    }
    // A taken id: 409, nothing changed.
    let (st, _) = import(&c, "/feeds/import?id=copy", export.clone()).await;
    assert_eq!(st, StatusCode::CONFLICT);
    // The file export: a header, a directive per run of equal dates, `none` at the end.
    let r = get(&c, "/feeds/src/export?as=file").await;
    assert!(
        r.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("src.txt")
    );
    let text = r.text().await.unwrap();
    assert!(text.starts_with("! picket-feed-export: 1\n"), "{text}");
    assert!(
        text.contains("! category: security\n") && text.contains("! warn_on: []\n"),
        "{text}"
    );
    assert!(text.trim_end().ends_with("! picket-first-seen: none"), "{text}");
    let (st, v) = import(
        &c,
        "/feeds/import?id=copy2",
        serde_json::to_vec(&json!({"file": text})).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    runs_done(&c, "copy2", 1).await;
    assert_eq!(entries(&c, "copy2").await, src);
    let f = get_json(&c, "/feeds/copy2").await;
    assert_eq!(
        (f["category"].as_str(), f["warn_on"].clone()),
        (Some("security"), json!([]))
    );
    // A JSON export with entries before feed: refused.
    let (st, _) = import(
        &c,
        "/feeds/import?id=bad",
        br#"{"picket_feed_export": 1, "entries": [], "feed": {"format": "adblock"}}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    // A plain list file, sent as {"file"}, the format picked by the admin.
    let (st, v) = import(
        &c,
        "/feeds/import?id=plain&format=plain",
        br#"{"file": "a.example\nb.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    runs_done(&c, "plain", 1).await;
    assert_eq!(entries(&c, "plain").await.len(), 2);
    let r = get_json(&c, "/feeds/plain/file").await;
    assert_eq!(
        r["content"], "a.example\nb.example\n",
        "a plain list file is imported unchanged"
    );
}

/// A MISP warninglist: both exports imported with their `misp_type` and `picket_first_seen`
/// dates; an empty feed's export too; a bad date is a parse error of its value, a key not in
/// `list` ignored.
#[tokio::test(flavor = "multi_thread")]
async fn misp_round_trips_with_its_type_and_dates() {
    let c = core_with(None).await;
    create_feed(&c, json!({"id": "w", "name": "W", "format": "misp-warninglist", "sanity": {"max_parse_error_ratio": 0.5}})).await;
    save(
        &c,
        "w",
        r#"{"name": "w", "type": "string", "list": ["a.example", "b.example", "c.example"],
            "picket_first_seen": {"a.example": "2020-01-02", "c.example": "nope", "zzz.example": "2019-01-01"}}"#,
    )
    .await;
    runs_done(&c, "w", 1).await;
    let src = entries(&c, "w").await;
    assert!(
        src.iter().any(|e| e.1 == "a.example" && e.2 == day("2020-01-02")),
        "{src:?}"
    );
    let run = get_json(&c, "/feeds/w/runs?limit=1").await;
    assert_eq!(
        run["items"][0]["parse"]["errors"], 1,
        "a bad date is a parse error: {run}"
    );
    assert_eq!(run["items"][0]["parse"]["misp_type"], "string");
    let export = get(&c, "/feeds/w/export").await.bytes().await.unwrap().to_vec();
    let doc: Value = serde_json::from_slice(&export).unwrap();
    assert_eq!(doc["feed"]["misp_type"], "string");
    let (st, v) = import(&c, "/feeds/import?id=w2", export).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    runs_done(&c, "w2", 1).await;
    assert_eq!(entries(&c, "w2").await, src);
    let file = get(&c, "/feeds/w/export?as=file").await.text().await.unwrap();
    let f: Value = serde_json::from_str(&file).unwrap();
    assert_eq!(
        (f["type"].as_str(), f["picket_first_seen"]["a.example"].as_str()),
        (Some("string"), Some(day("2020-01-02").as_str()))
    );
    let (st, v) = import(
        &c,
        "/feeds/import?id=w3",
        serde_json::to_vec(&json!({"file": file})).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    runs_done(&c, "w3", 1).await;
    assert_eq!(entries(&c, "w3").await, src);
    // Merging joins the lists and maps; another list type is refused.
    let (st, v) = import(
        &c,
        &format!("/feeds/w3/import?mode=merge&base_version={}", get_json(&c, "/feeds/w3/file").await["version"].as_str().unwrap()),
        serde_json::to_vec(&json!({"file": r#"{"type": "string", "list": ["d.example", "a.example"], "picket_first_seen": {"a.example": "2019-05-05"}}"#})).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    runs_done(&c, "w3", 2).await;
    let e = entries(&c, "w3").await;
    assert!(e.iter().any(|x| x.1 == "d.example"));
    assert!(
        e.iter().any(|x| x.1 == "a.example" && x.2 == day("2019-05-05")),
        "the earlier date wins: {e:?}"
    );
    let (st, _) = import(
        &c,
        &format!(
            "/feeds/w3/import?mode=merge&base_version={}",
            get_json(&c, "/feeds/w3/file").await["version"].as_str().unwrap()
        ),
        serde_json::to_vec(&json!({"file": r#"{"type": "hostname", "list": ["e.example"]}"#})).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "another MISP type");
    // An empty MISP feed's JSON export imports with its type.
    create_feed(&c, json!({"id": "e", "name": "E", "format": "misp-warninglist"})).await;
    save(&c, "e", r#"{"type": "cidr", "list": []}"#).await;
    runs_done(&c, "e", 1).await;
    let export = get(&c, "/feeds/e/export").await.bytes().await.unwrap().to_vec();
    let (st, v) = import(&c, "/feeds/import?id=e2", export).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let f = get_json(&c, "/feeds/e2/file").await;
    assert!(f["content"].as_str().unwrap().contains("\"cidr\""), "{f}");
}

/// Merging into a manual feed adds the imported lines between `picket-first-seen: none` lines:
/// duplicates collapse with the earlier date, an undated imported line keeps the default date
/// even after a file that ends under a directive; replacing swaps the file; a stale
/// `base_version` is 409; another `format_options` 422.
#[tokio::test(flavor = "multi_thread")]
async fn merging_and_replacing_a_manual_feed() {
    let c = core_with(None).await;
    create_feed(&c, json!({"id": "m", "name": "M", "format": "plain"})).await;
    save(
        &c,
        "m",
        "! picket-first-seen: 2020-01-01\na.example\nkeep.example\n",
    )
    .await;
    runs_done(&c, "m", 1).await;
    let v1 = get_json(&c, "/feeds/m/file").await["version"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, v) = import(
        &c,
        &format!("/feeds/m/import?mode=merge&base_version={v1}"),
        serde_json::to_vec(&json!({"file": "! picket-first-seen: 2019-01-01\na.example\n! picket-first-seen: none\nb.example\n"})).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    runs_done(&c, "m", 2).await;
    let e = entries(&c, "m").await;
    let date = |raw: &str| e.iter().find(|x| x.1 == raw).unwrap().2.clone();
    assert_eq!(date("a.example"), day("2019-01-01"), "the earlier date wins");
    assert_eq!(
        date("keep.example"),
        day("2020-01-01"),
        "the feed's own dates stay"
    );
    assert!(
        date("b.example") > day("2026-01-01"),
        "an undated imported line keeps the default date"
    );
    assert_eq!(e.len(), 3);
    // An undated plain list merged into a file that ends under a directive keeps its own dates.
    let v2 = get_json(&c, "/feeds/m/file").await["version"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, _) = import(
        &c,
        &format!("/feeds/m/import?mode=merge&base_version={v2}"),
        br#"{"file": "c.example"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    runs_done(&c, "m", 3).await;
    let e = entries(&c, "m").await;
    assert!(e.iter().find(|x| x.1 == "c.example").unwrap().2 > day("2026-01-01"));
    // A stale base_version: 409, nothing changed.
    let (st, _) = import(
        &c,
        &format!("/feeds/m/import?mode=replace&base_version={v1}"),
        br#"{"file": "z.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    // Another format_options: 422.
    let other = "! picket-feed-export: 1\n! format: plain\n! format_options: {\"domains_as\":\"subdomains\"}\nq.example\n";
    let v3 = get_json(&c, "/feeds/m/file").await["version"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, _) = import(
        &c,
        &format!("/feeds/m/import?mode=merge&base_version={v3}"),
        serde_json::to_vec(&json!({"file": other})).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    // Replacing swaps the file.
    let (st, v) = import(
        &c,
        &format!("/feeds/m/import?mode=replace&base_version={v3}"),
        br#"{"file": "z.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    runs_done(&c, "m", 4).await;
    assert_eq!(
        entries(&c, "m")
            .await
            .iter()
            .map(|e| e.1.as_str())
            .collect::<Vec<_>>(),
        vec!["z.example"]
    );
    // Appends to a misp-warninglist feed are refused.
    create_feed(&c, json!({"id": "w", "name": "W", "format": "misp-warninglist"})).await;
    let r = ui(&c, Method::POST, "/feeds/w/file/lines")
        .json(&json!({"lines": ["a.example"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// Merging into an `aggregate` provider feed is an import run: its `aggregate` entries are
/// inserted with their dates and kept past the next download, other types skipped and counted;
/// it is never the provider's `last`; replacing is refused; a downloaded feed's export imports
/// as a manual feed without its provider.
#[tokio::test(flavor = "multi_thread")]
async fn merging_into_an_aggregate_provider_feed() {
    let body = std::sync::Arc::new(std::sync::Mutex::new("live.example\n".to_string()));
    let b = body.clone();
    let srv = TestServer::start(&[HOST], move |_s: &Seen| Reply::ok(b.lock().unwrap().clone())).await;
    let c = core_with(Some(&srv)).await;
    create_feed(
        &c,
        json!({"id": "agg", "name": "Agg", "provider": "http", "provider_config": {"url": format!("https://{HOST}/agg.txt")},
               "format": "plain", "modes": {"dns": {"mode": "aggregate"}, "ip": {"mode": "replace"}}}),
    )
    .await;
    runs_done(&c, "agg", 1).await;
    let last_before: Option<String> = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT last_json FROM feed_state WHERE feed_id = 'agg'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    // Replacing a provider feed is refused.
    let (st, _) = import(
        &c,
        "/feeds/agg/import?mode=replace",
        br#"{"file": "x.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    // Keys in order: picket_feed_export first, feed before entries.
    let export =
        br#"{"picket_feed_export": 1, "feed": {"id": "elsewhere", "format": "plain", "format_options": {}},
        "entries": [
            {"raw": "seen-elsewhere.example", "first_seen_at": "2018-03-04T00:00:00Z"},
            {"raw": "live.example", "first_seen_at": "2017-01-01T00:00:00Z"},
            {"raw": "10.9.9.9"}
        ]}"#;
    let (st, v) = import(&c, "/feeds/agg/import?mode=merge", export.to_vec()).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["run_queued"], true);
    runs_done(&c, "agg", 2).await;
    let run = get_json(&c, "/feeds/agg/runs?limit=1").await["items"][0].clone();
    assert_eq!(
        (run["kind"].as_str(), run["status"].as_str()),
        (Some("import"), Some("applied")),
        "{run}"
    );
    assert_eq!(
        run["parse"]["import_skipped"]["ip"], 1,
        "the replace type is skipped and counted: {run}"
    );
    let e = entries(&c, "agg").await;
    let date = |raw: &str| e.iter().find(|x| x.1 == raw).map(|x| x.2.clone());
    assert_eq!(
        date("seen-elsewhere.example"),
        Some("2018-03-04T00:00:00.000000Z".into())
    );
    assert_eq!(
        date("live.example"),
        Some("2017-01-01T00:00:00.000000Z".into()),
        "earliest wins"
    );
    assert_eq!(date("10.9.9.9"), None);
    let last_after: Option<String> = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT last_json FROM feed_state WHERE feed_id = 'agg'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(last_before, last_after, "an import is never the provider's last");
    // The next download keeps the aggregate entries the import added.
    *body.lock().unwrap() = "live.example\nnext.example\n".into();
    common::feeds::check_now(&c, "agg").await;
    let e = entries(&c, "agg").await;
    assert!(
        e.iter().any(|x| x.1 == "seen-elsewhere.example"),
        "kept past the next download: {e:?}"
    );
    assert!(e.iter().any(|x| x.1 == "next.example"));
    // A downloaded feed's export imports as a manual feed, without its provider.
    let export = get(&c, "/feeds/agg/export").await.bytes().await.unwrap().to_vec();
    let doc: Value = serde_json::from_slice(&export).unwrap();
    assert_eq!(doc["feed"]["provider"], "agg");
    let (st, v) = import(&c, "/feeds/import?id=kept", export).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    runs_done(&c, "kept", 1).await;
    let f = get_json(&c, "/feeds/kept").await;
    assert_eq!(f["provider"], Value::Null);
    assert_eq!(entries(&c, "kept").await.len(), entries(&c, "agg").await.len());
    let size = get_json(&c, "/feeds/agg/export-size").await;
    assert!(
        size["entries"].as_u64().unwrap() >= 3 && size["file_cap"].as_u64().unwrap() > 0,
        "{size}"
    );
}

/// Blocks the heavy lane with a job waiting on the returned gate, and fills its queue (`fill`).
async fn block_heavy_lane_with(c: &Core, fill: bool) -> std::sync::Arc<tokio::sync::Notify> {
    use picket_core::scheduler::{HeavyLane, Priority};
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let g = gate.clone();
    c.state
        .scheduler
        .heavy
        .submit_fn("test", "block", Priority::P0, move || async move {
            g.notified().await;
            Ok(())
        });
    wait_until("the blocking job", || async {
        c.state.scheduler.heavy.stats().running.as_deref() == Some("test:block")
    })
    .await;
    for i in 0..if fill { HeavyLane::CAP } else { 0 } {
        c.state
            .scheduler
            .heavy
            .submit_fn("test", &format!("{i}"), Priority::P3, || async { Ok(()) });
    }
    gate
}

async fn block_heavy_lane(c: &Core) -> std::sync::Arc<tokio::sync::Notify> {
    block_heavy_lane_with(c, true).await
}

async fn pending_imports(c: &Core) -> i64 {
    c.state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row("SELECT count(*) FROM feed_imports", [], |r| r.get(0))?)
        })
        .await
        .unwrap()
}

async fn agg_feed(c: &Core) {
    create_feed(
        c,
        json!({"id": "agg", "name": "Agg", "provider": "http", "provider_config": {"url": format!("https://{HOST}/agg.txt")},
               "format": "plain", "modes": {"dns": {"mode": "aggregate"}}}),
    )
    .await;
    runs_done(c, "agg", 1).await;
}

async fn put_feed(c: &Core, id: &str, f: impl FnOnce(&mut Value)) {
    let mut v = get_json(c, &format!("/feeds/{id}")).await;
    f(&mut v);
    let r = ui(c, Method::PUT, &format!("/feeds/{id}"))
        .json(&v)
        .send()
        .await
        .unwrap();
    let st = r.status();
    assert_eq!(st, StatusCode::OK, "{}", r.text().await.unwrap());
}

/// FP2 (feeds.md §4; README §2 Restarts): a provider-feed merge that the heavy lane can't queue
/// is still accepted durably (`feed_imports`), and is applied once the lane has room, or at the
/// next start.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_provider_import_survives_a_full_heavy_lane_and_a_restart() {
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("live.example\n")).await;
    let c = core_with(Some(&srv)).await;
    agg_feed(&c).await;
    let gate = block_heavy_lane(&c).await;
    let dropped = c.state.scheduler.heavy.stats().dropped;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "imported.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["run_queued"], true);
    assert!(
        c.state.scheduler.heavy.stats().dropped > dropped,
        "the lane refused the import's job"
    );
    assert_eq!(pending_imports(&c).await, 1, "the accepted import is on disk");
    // The refused run is retried in a minute, from memory.
    wait_until("the in-memory retry", || async {
        c.state.feeds.import_retry_at("agg").is_some() && !c.state.feeds.is_busy("agg")
    })
    .await;
    gate.notify_one();
    wait_until("the heavy lane to drain", || async {
        c.state.scheduler.heavy.stats().queued == 0
    })
    .await;
    // What a start does with it, from the record alone.
    picket_core::feeds::resume_imports_now(&c.state).await;
    let mut applied = false;
    for _ in 0..150 {
        if entries(&c, "agg").await.iter().any(|e| e.1 == "imported.example") && !c.state.feeds.is_busy("agg")
        {
            applied = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(applied, "the start resumed the import from its record");
    assert_eq!(pending_imports(&c).await, 0, "the run took its record with it");
    let run = get_json(&c, "/feeds/agg/runs?limit=1").await["items"][0].clone();
    assert_eq!(
        (run["kind"].as_str(), run["status"].as_str()),
        (Some("import"), Some("applied")),
        "{run}"
    );
}

/// FP5 (feeds.md §4): an import is bound to the feed it was checked against. One accepted
/// before the feed's format changed gets a rejected run (`import_stale`) and changes nothing; one
/// accepted before the feed was deleted and created again never reaches the new feed; one whose
/// check raced a format edit while it waited for the feed is refused (`409`).
#[tokio::test(flavor = "multi_thread")]
async fn an_import_is_bound_to_the_feed_and_settings_it_was_checked_against() {
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("live.example\n")).await;
    let c = core_with(Some(&srv)).await;
    agg_feed(&c).await;
    // Accepted, then the format changes before its run.
    let gate = block_heavy_lane(&c).await;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "stale-format.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    put_feed(&c, "agg", |v| {
        v["format_options"] = json!({"domains_as": "subdomains"})
    })
    .await;
    wait_until("the edit", || async {
        c.state
            .feeds
            .def("agg")
            .is_some_and(|d| d.format_options.domains_as.is_some())
    })
    .await;
    gate.notify_one();
    wait_until("the heavy lane to drain", || async {
        c.state.scheduler.heavy.stats().queued == 0
    })
    .await;
    picket_core::feeds::resume_imports_now(&c.state).await;
    wait_until("the stale import's run", || async {
        pending_imports(&c).await == 0 && !c.state.feeds.is_busy("agg")
    })
    .await;
    let items = get_json(&c, "/feeds/agg/runs?limit=10").await["items"].clone();
    let imp = items
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "import")
        .cloned()
        .unwrap_or_else(|| panic!("an import run: {items}"));
    assert_eq!(
        (imp["status"].as_str(), imp["gate"].as_str()),
        (Some("rejected"), Some("import_stale")),
        "{imp}"
    );
    assert!(
        !entries(&c, "agg")
            .await
            .iter()
            .any(|e| e.1.contains("stale-format")),
        "nothing checked under the old settings was ingested"
    );
    // Accepted, then the feed is deleted and created again under its id.
    let gate = block_heavy_lane(&c).await;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "old-feed.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    gate.notify_one();
    wait_until("the heavy lane to drain", || async {
        c.state.scheduler.heavy.stats().queued == 0
    })
    .await;
    for path in ["/feeds/agg", "/feed-providers/agg"] {
        let r = ui(&c, Method::DELETE, path)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
    }
    agg_feed(&c).await;
    picket_core::feeds::resume_imports_now(&c.state).await;
    wait_until("the old import to go", || async {
        pending_imports(&c).await == 0
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !entries(&c, "agg").await.iter().any(|e| e.1.contains("old-feed")),
        "the feed created again took the deleted one's import"
    );
    // A format edit while the import waits for the feed: refused when it would be accepted.
    let gate = block_heavy_lane_with(&c, false).await;
    put_feed(&c, "agg", |v| v["modes"]["ip"] = json!({"mode": "aggregate"})).await;
    wait_until("the feed busy with its re-ingest", || async {
        c.state.feeds.is_busy("agg")
    })
    .await;
    let c2 = std::sync::Arc::new(c);
    let c3 = c2.clone();
    let req = tokio::spawn(async move {
        import(
            &c3,
            "/feeds/agg/import?mode=merge",
            br#"{"file": "raced.example\n"}"#.to_vec(),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    put_feed(&c2, "agg", |v| {
        v["format_options"] = json!({"domains_as": "subdomains"})
    })
    .await;
    wait_until("the edit", || async {
        c2.state
            .feeds
            .def("agg")
            .is_some_and(|d| d.format_options.domains_as.is_some())
    })
    .await;
    gate.notify_one();
    let (st, v) = req.await.unwrap();
    assert_eq!(st, StatusCode::CONFLICT, "{v}");
    assert_eq!(pending_imports(&c2).await, 0);
}

async fn import_attempts(c: &Core) -> i64 {
    c.state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT coalesce(sum(attempts), 0) FROM feed_imports",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap()
}

/// Q7 (README §2 Bounded; feeds.md §4; storage.md §4): a provider feed holds at most one
/// accepted import waiting for its run: while one waits (here refused by a full heavy lane, its
/// retry a minute away and the feed free), another is refused (`503`, nothing stored) instead of
/// piling up with its blob. A refusal of its run counts as an attempt, so retries are bounded.
/// Deleting the feed deletes its waiting import at once, which unpins its blob.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_feed_holds_one_waiting_import_and_deleting_it_drops_that_import() {
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("live.example\n")).await;
    let c = core_with(Some(&srv)).await;
    agg_feed(&c).await;
    let gate = block_heavy_lane(&c).await;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "first.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    wait_until("the refused run's retry", || async {
        c.state.feeds.import_retry_at("agg").is_some() && !c.state.feeds.is_busy("agg")
    })
    .await;
    wait_until("the refusal counted", || async { import_attempts(&c).await >= 1 }).await;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "second.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert_eq!(v["error"]["code"], "busy", "{v}");
    assert_eq!(pending_imports(&c).await, 1, "the second import isn't stored");
    let blob: String = c
        .state
        .db
        .read(|db| Ok::<_, anyhow::Error>(db.query_row("SELECT blob FROM feed_imports", [], |r| r.get(0))?))
        .await
        .unwrap();
    for path in ["/feeds/agg", "/feed-providers/agg"] {
        let r = ui(&c, Method::DELETE, path)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
    }
    assert_eq!(
        pending_imports(&c).await,
        0,
        "the deleted feed's waiting import goes with it"
    );
    let pinned: i64 = c
        .state
        .db
        .read(move |db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT count(*) FROM feed_imports WHERE blob = ?1",
                [&blob],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(pinned, 0, "nothing pins its blob for retention");
    gate.notify_one();
}

/// Q7 (README §2 Bounded): accepted imports waiting for their runs hold at most four download
/// caps of blobs in all (`feeds.max_download_mib` 1 here: 4 MiB); an import past that is
/// refused (`503`) and stores nothing.
#[tokio::test(flavor = "multi_thread")]
async fn waiting_imports_are_bounded_in_bytes() {
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("live.example\n")).await;
    let c = common::start_core_with(
        Some(json!({"web": {"tls": "off"}, "feeds": {"max_download_mib": 1}})),
        picket_core::run::StartOptions {
            release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
            feed_http: srv.http_options(),
            ..Default::default()
        },
    )
    .await;
    for i in 1..=5 {
        create_feed(
            &c,
            json!({"id": format!("agg{i}"), "name": format!("Agg {i}"), "provider": "http",
                   "provider_config": {"url": format!("https://{HOST}/agg{i}.txt")},
                   "format": "plain", "modes": {"dns": {"mode": "aggregate"}}}),
        )
        .await;
        runs_done(&c, &format!("agg{i}"), 1).await;
    }
    let gate = block_heavy_lane(&c).await;
    for i in 1..=5 {
        // About 0.9 MiB each: within the download cap.
        let mut file = String::new();
        let mut n = 0;
        while file.len() < 900 * 1024 {
            file.push_str(&format!("i{i}-{n:07}.example\n"));
            n += 1;
        }
        let body = serde_json::to_vec(&json!({ "file": file })).unwrap();
        let (st, v) = import(&c, &format!("/feeds/agg{i}/import?mode=merge"), body).await;
        if i <= 4 {
            assert_eq!(st, StatusCode::OK, "import {i}: {v}");
        } else {
            assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "import {i}: {v}");
            assert_eq!(v["error"]["code"], "busy", "{v}");
        }
    }
    assert_eq!(pending_imports(&c).await, 4);
    gate.notify_one();
}

async fn import_ids(c: &Core) -> Vec<(i64, String)> {
    c.state
        .db
        .read(|db| {
            let mut st = db.prepare("SELECT id, feed_id FROM feed_imports ORDER BY id")?;
            let v = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap()
}

/// Z1 (feeds.md §4; storage.md §4): an import's cleanup is bound to its own record. A feed's
/// import is queued behind a busy heavy lane, the feed is deleted, and another feed's import is
/// accepted: its record never takes the deleted import's id (ids are never reused), and when the
/// deleted feed's queued job starts and finds its feed gone, the other feed's accepted import
/// survives and is applied.
#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_feeds_queued_import_never_removes_another_feeds_import() {
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("live.example\n")).await;
    let c = core_with(Some(&srv)).await;
    agg_feed(&c).await;
    create_feed(
        &c,
        json!({"id": "other", "name": "Other", "provider": "http", "provider_config": {"url": format!("https://{HOST}/other.txt")},
               "format": "plain", "modes": {"dns": {"mode": "aggregate"}}}),
    )
    .await;
    runs_done(&c, "other", 1).await;
    let gate = block_heavy_lane_with(&c, false).await;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "deleted.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let old = import_ids(&c).await;
    assert_eq!(old.len(), 1, "{old:?}");
    let r = ui(&c, Method::DELETE, "/feeds/agg")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(pending_imports(&c).await, 0);
    let (st, v) = import(
        &c,
        "/feeds/other/import?mode=merge",
        br#"{"file": "kept.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let new = import_ids(&c).await;
    assert_eq!(new.len(), 1, "{new:?}");
    assert!(
        new[0].0 > old[0].0,
        "an import id is never reused: {old:?} then {new:?}"
    );
    gate.notify_one();
    wait_until("both jobs finish", || async {
        c.state.scheduler.heavy.stats().queued == 0
            && c.state.scheduler.heavy.stats().running.is_none()
            && !c.state.feeds.is_busy("other")
            && pending_imports(&c).await == 0
    })
    .await;
    assert!(
        entries(&c, "other").await.iter().any(|e| e.1 == "kept.example"),
        "the deleted feed's queued job removed the other feed's accepted import"
    );
}

/// Z4 (README §2 "dropped and counted"; feeds.md §4): an accepted import whose run the full heavy
/// lane keeps refusing is dropped after its attempts, and the drop is a rejected import run in
/// the feed's runs (gate `import_dropped`) whose reason says the heavy lane was full, never that
/// a run failed that didn't start; one whose run starts only once its attempts are spent says
/// the same.
#[tokio::test(flavor = "multi_thread")]
async fn an_import_dropped_after_its_attempts_is_a_rejected_run_that_says_why() {
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("live.example\n")).await;
    let c = core_with(Some(&srv)).await;
    agg_feed(&c).await;
    let refusals = |n: i64| {
        let c = &c;
        async move {
            for i in 1..n {
                wait_until("the refusal counted", || async {
                    import_attempts(c).await >= i && !c.state.feeds.is_busy("agg")
                })
                .await;
                // As at a start: the pending import's run is queued again (and refused again).
                picket_core::feeds::resume_imports_now(&c.state).await;
            }
        }
    };
    let import_runs = || async {
        let items = get_json(&c, "/feeds/agg/runs?limit=20").await["items"].clone();
        items
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "import")
            .cloned()
            .collect::<Vec<_>>()
    };
    // Refused every time: dropped once its attempts are spent, as a rejected run.
    let gate = block_heavy_lane(&c).await;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "refused.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    refusals(picket_core::feeds::ingest::MAX_IMPORT_ATTEMPTS + 1).await;
    wait_until("the import dropped", || async {
        pending_imports(&c).await == 0 && !import_runs().await.is_empty()
    })
    .await;
    let runs = import_runs().await;
    assert_eq!(runs.len(), 1, "{runs:?}");
    let run = &runs[0];
    assert_eq!(
        (run["status"].as_str(), run["gate"].as_str()),
        (Some("rejected"), Some("import_dropped")),
        "{run}"
    );
    let reason = run["error"].as_str().unwrap_or_default();
    assert!(reason.contains("heavy lane was full"), "{reason}");
    assert!(!reason.contains("failed"), "no run of it started: {reason}");
    gate.notify_one();
    wait_until("the heavy lane to drain", || async {
        c.state.scheduler.heavy.stats().queued == 0 && c.state.scheduler.heavy.stats().running.is_none()
    })
    .await;
    assert!(
        !entries(&c, "agg").await.iter().any(|e| e.1.contains("refused")),
        "nothing of the dropped import was ingested"
    );
    // Refused until its attempts are spent, then started: rejected at its start, saying why.
    let gate = block_heavy_lane(&c).await;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "late.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    refusals(picket_core::feeds::ingest::MAX_IMPORT_ATTEMPTS).await;
    wait_until("the last refusal counted", || async {
        import_attempts(&c).await >= picket_core::feeds::ingest::MAX_IMPORT_ATTEMPTS
            && !c.state.feeds.is_busy("agg")
    })
    .await;
    gate.notify_one();
    wait_until("the heavy lane to drain", || async {
        c.state.scheduler.heavy.stats().queued == 0
    })
    .await;
    picket_core::feeds::resume_imports_now(&c.state).await;
    wait_until("the late import's run", || async {
        pending_imports(&c).await == 0 && import_runs().await.len() == 2 && !c.state.feeds.is_busy("agg")
    })
    .await;
    let run = import_runs().await[0].clone();
    assert_eq!(
        (run["status"].as_str(), run["gate"].as_str()),
        (Some("rejected"), Some("import_dropped")),
        "{run}"
    );
    let reason = run["error"].as_str().unwrap_or_default();
    assert!(reason.contains("heavy lane was full 10 times"), "{reason}");
    assert!(
        !reason.contains("failed"),
        "no earlier run of it started: {reason}"
    );
}

/// The `issues[0].field` of a refusal.
fn field(v: &Value) -> Option<&str> {
    v["error"]["issues"][0]["field"].as_str()
}

/// F1 (feeds.md §4: a new feed's settings come from the export; api.md §7: another format,
/// `format_options` or MISP list type is `422`): a query setting that differs from what an
/// export declares is refused, naming the field, for a JSON export, a file export's header and a
/// MISP export; one equal to it is fine; an import into an existing feed refuses a setting that
/// isn't the feed's own. A plain list file and a bare MISP list keep taking the query's settings.
#[tokio::test(flavor = "multi_thread")]
async fn query_settings_never_override_an_export() {
    let c = core_with(None).await;
    create_feed(
        &c,
        json!({"id": "src", "name": "Source", "format": "adblock", "category": "security", "warn_on": [],
               "rule_policy": {"redirects": "drop"}}),
    )
    .await;
    save(&c, "src", "||a.example^\n").await;
    runs_done(&c, "src", 1).await;
    let export = get(&c, "/feeds/src/export").await.bytes().await.unwrap().to_vec();
    let text = get(&c, "/feeds/src/export?as=file").await.text().await.unwrap();
    let text_body = serde_json::to_vec(&json!({"file": text})).unwrap();
    for (query, f) in [
        ("format=hosts", "format"),
        ("category=privacy", "category"),
        ("domains_as=subdomains", "format_options"),
        ("warn_on=warn-common", "warn_on"),
        ("redirects=keep", "rule_policy"),
    ] {
        for (kind, body) in [("JSON export", &export), ("file export", &text_body)] {
            let (st, v) = import(&c, &format!("/feeds/import?id=x&{query}"), body.clone()).await;
            assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{kind} {query}: {v}");
            assert_eq!(field(&v), Some(f), "{kind} {query}: {v}");
        }
    }
    assert!(c.state.feeds.def("x").is_none(), "nothing was created");
    // Equal to what the export declares: fine.
    let (st, v) = import(
        &c,
        "/feeds/import?id=same&format=adblock&category=security&warn_on=&redirects=drop&client_rules=keep",
        export.clone(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let (st, v) = import(
        &c,
        "/feeds/import?id=same2&format=adblock&category=security",
        text_body.clone(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let f = get_json(&c, "/feeds/same2").await;
    assert_eq!(
        (
            f["format"].as_str(),
            f["category"].as_str(),
            f["rule_policy"]["redirects"].as_str()
        ),
        (Some("adblock"), Some("security"), Some("drop")),
        "{f}"
    );
    // A MISP export: its format is misp-warninglist whatever the query or the target says.
    create_feed(
        &c,
        json!({"id": "w", "name": "W", "format": "misp-warninglist", "category": "privacy"}),
    )
    .await;
    save(
        &c,
        "w",
        r#"{"name": "w", "type": "hostname", "list": ["a.example"]}"#,
    )
    .await;
    runs_done(&c, "w", 1).await;
    let misp = get(&c, "/feeds/w/export?as=file").await.text().await.unwrap();
    let misp_body = serde_json::to_vec(&json!({"file": misp})).unwrap();
    let (st, v) = import(&c, "/feeds/import?id=w2&format=adblock", misp_body.clone()).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(field(&v), Some("format"), "{v}");
    let (st, v) = import(&c, "/feeds/import?id=w2&category=security", misp_body.clone()).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(field(&v), Some("category"), "{v}");
    let v1 = get_json(&c, "/feeds/same/file").await["version"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, v) = import(
        &c,
        &format!("/feeds/same/import?mode=merge&base_version={v1}"),
        misp_body.clone(),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a MISP export into an adblock feed: {v}"
    );
    // Into an existing feed: a format in the query must be the feed's; settings don't apply.
    let plain = br#"{"file": "b.example\n"}"#.to_vec();
    let (st, v) = import(
        &c,
        &format!("/feeds/same/import?mode=merge&base_version={v1}&format=hosts"),
        plain.clone(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(field(&v), Some("format"), "{v}");
    let (st, v) = import(
        &c,
        &format!("/feeds/same/import?mode=merge&base_version={v1}&category=privacy"),
        plain.clone(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(field(&v), Some("category"), "{v}");
    let (st, v) = import(
        &c,
        &format!(
            "/feeds/same/import?mode=merge&base_version={v1}&format=adblock&category=security&redirects=drop"
        ),
        plain,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "settings equal to the feed's: {v}");
    // A bare MISP list takes the query's settings.
    let (st, v) = import(
        &c,
        "/feeds/import?id=bare&category=security&redirects=drop",
        serde_json::to_vec(&json!({"file": r#"{"name": "n", "type": "string", "list": ["x.example"]}"#}))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let f = get_json(&c, "/feeds/bare").await;
    assert_eq!(
        (
            f["format"].as_str(),
            f["category"].as_str(),
            f["rule_policy"]["redirects"].as_str()
        ),
        (Some("misp-warninglist"), Some("security"), Some("drop")),
        "{f}"
    );
}

/// F2 (feeds.md §4: the admin picks a plain list's settings): `POST feeds/import` takes
/// `rule_policy` (one switch per parameter) and `warn_on` (comma-separated) for a plain list
/// file, validated as the feed's own fields (`422` naming the field).
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_list_import_takes_rule_policy_and_warn_on() {
    let c = core_with(None).await;
    let list = br#"{"file": "a.example\n"}"#.to_vec();
    let (st, v) = import(
        &c,
        "/feeds/import?id=p&format=plain&category=security&warn_on=&redirects=drop&client_rules=drop",
        list.clone(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let f = get_json(&c, "/feeds/p").await;
    assert_eq!(f["warn_on"], json!([]), "{f}");
    assert_eq!(
        f["rule_policy"],
        json!({"redirects": "drop", "client_rules": "drop", "browser_changes": "keep"}),
        "{f}"
    );
    let (st, v) = import(&c, "/feeds/import?id=p2&warn_on=warn-common", list.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!(get_json(&c, "/feeds/p2").await["warn_on"], json!(["warn-common"]));
    // Defaults: a manual feed keeps all three; warn_on follows the category.
    let (st, v) = import(&c, "/feeds/import?id=p3", list.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let f = get_json(&c, "/feeds/p3").await;
    assert_eq!(f["warn_on"], Value::Null, "{f}");
    assert_eq!(
        f["rule_policy"],
        json!({"redirects": "keep", "client_rules": "keep", "browser_changes": "keep"}),
        "{f}"
    );
    // Validated like the feed's fields: warn_on names warn bundles only.
    let (st, v) = import(&c, "/feeds/import?id=p4&warn_on=block-common", list.clone()).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(field(&v), Some("warn_on"), "{v}");
    assert!(c.state.feeds.def("p4").is_none());
    let (st, _) = import(&c, "/feeds/import?id=p5&redirects=maybe", list).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "an unknown switch value");
}

/// F3 (feeds.md §1, api.md §7): saves, appends and imports into manual feeds return the file's
/// `saved_at` beside its version; the run that reads the file carries it as `updated_at`, and
/// `GET feeds/{id}/file` gives the same.
#[tokio::test(flavor = "multi_thread")]
async fn manual_writes_return_saved_at_which_the_run_carries() {
    let c = core_with(None).await;
    create_feed(&c, json!({"id": "m", "name": "M", "format": "adblock"})).await;
    let r = ui(&c, Method::PUT, "/feeds/m/file")
        .json(&json!({"content": "||a.example^\n", "base_version": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let saved: Value = r.json().await.unwrap();
    let at = saved["saved_at"].as_str().expect("saved_at").to_string();
    runs_done(&c, "m", 1).await;
    let file = get_json(&c, "/feeds/m/file").await;
    assert_eq!(file["saved_at"].as_str(), Some(at.as_str()));
    let run = get_json(&c, "/feeds/m/runs?limit=1").await["items"][0].clone();
    assert_eq!(run["updated_at"].as_str(), Some(at.as_str()), "{run}");
    assert_eq!(run["version"], saved["version"], "{run}");
    // An append: a new save.
    let r = ui(&c, Method::POST, "/feeds/m/file/lines")
        .json(&json!({"lines": ["||b.example^"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let appended: Value = r.json().await.unwrap();
    let at2 = appended["saved_at"].as_str().expect("saved_at").to_string();
    assert_ne!(at2, at);
    runs_done(&c, "m", 2).await;
    let run = get_json(&c, "/feeds/m/runs?limit=1").await["items"][0].clone();
    assert_eq!(run["updated_at"].as_str(), Some(at2.as_str()), "{run}");
    // An unchanged save gives the current file's.
    let v = appended["version"].as_str().unwrap();
    let r = ui(&c, Method::PUT, "/feeds/m/file")
        .json(&json!({"content": "||a.example^\n||b.example^\n", "base_version": v}))
        .send()
        .await
        .unwrap();
    let same: Value = r.json().await.unwrap();
    assert_eq!(same["changed"], false, "{same}");
    assert_eq!(same["saved_at"].as_str(), Some(at2.as_str()), "{same}");
    // An import into a new manual feed and into an existing one.
    let (st, v) = import(
        &c,
        "/feeds/import?id=n",
        br#"{"file": "||c.example^\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    runs_done(&c, "n", 1).await;
    let run = get_json(&c, "/feeds/n/runs?limit=1").await["items"][0].clone();
    assert_eq!(run["updated_at"], v["saved_at"], "{run} {v}");
    let mv = appended["version"].as_str().unwrap();
    let (st, v) = import(
        &c,
        &format!("/feeds/m/import?mode=merge&base_version={mv}"),
        br#"{"file": "||d.example^\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert!(v["saved_at"].is_string(), "{v}");
    assert_eq!(get_json(&c, "/feeds/m/file").await["saved_at"], v["saved_at"]);
}

/// The next UI event of `kind` (api.md §7 UI WebSocket), within 30 s.
async fn next_event(
    rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>,
    kind: &str,
) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match rx.recv().await {
                Ok(e) if e.kind == kind => return e.data,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("events closed: {e}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} event"))
}

/// The next coalesced `feed_run` event's item for a run of `feed` (api.md §7: each event lists
/// the runs stored since the previous one).
async fn next_run_of(
    rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>,
    feed: &str,
) -> Value {
    loop {
        let ev = next_event(rx, "feed_run").await;
        assert!(
            ev["stored"].as_u64().unwrap() >= ev["runs"].as_array().unwrap().len() as u64,
            "{ev}"
        );
        if let Some(run) = ev["runs"].as_array().unwrap().iter().find(|r| r["feed"] == feed) {
            return run.clone();
        }
    }
}

/// F4 and F5 (feeds.md §1, api.md §7): a manual feed's status gives its file's `version` and
/// `saved_at` without the content, and the retry core makes after a full heavy lane refused its
/// run (`manual_retry_at`), so "no run yet" differs from "no run coming"; the `feed_run` event
/// carries the run's `version` and, for a manual feed, `saved_at`.
#[tokio::test(flavor = "multi_thread")]
async fn manual_status_and_feed_run_events_carry_version_and_saved_at() {
    let body = std::sync::Arc::new(std::sync::Mutex::new("live.example\n".to_string()));
    let b2 = body.clone();
    let srv = TestServer::start(&[HOST], move |_s: &Seen| Reply::ok(b2.lock().unwrap().clone())).await;
    let c = core_with(Some(&srv)).await;
    create_feed(&c, json!({"id": "m", "name": "M", "format": "adblock"})).await;
    let st = get_json(&c, "/feeds/m/status").await;
    assert_eq!(
        (st["version"].clone(), st["saved_at"].clone()),
        (Value::Null, Value::Null),
        "{st}"
    );
    let mut rx = c.state.events.subscribe();
    let r = ui(&c, Method::PUT, "/feeds/m/file")
        .json(&json!({"content": "||a.example^\n", "base_version": null}))
        .send()
        .await
        .unwrap();
    let saved: Value = r.json().await.unwrap();
    let ev = next_run_of(&mut rx, "m").await;
    assert_eq!(ev["version"], saved["version"], "{ev}");
    assert_eq!(ev["saved_at"], saved["saved_at"], "{ev}");
    runs_done(&c, "m", 1).await;
    let st = get_json(&c, "/feeds/m/status").await;
    assert_eq!(st["version"], saved["version"], "{st}");
    assert_eq!(st["saved_at"], saved["saved_at"], "{st}");
    assert_eq!(st["manual_retry_at"], Value::Null, "{st}");
    // A full heavy lane refuses the next save's run: the status shows the retry coming.
    let gate = block_heavy_lane(&c).await;
    let r = ui(&c, Method::PUT, "/feeds/m/file")
        .json(&json!({"content": "||a.example^\n||b.example^\n", "base_version": saved["version"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let saved2: Value = r.json().await.unwrap();
    wait_until("the refused run's retry", || async {
        c.state.feeds.manual_retry("m").is_some() && !c.state.feeds.is_busy("m")
    })
    .await;
    let st = get_json(&c, "/feeds/m/status").await;
    assert!(st["manual_retry_at"].is_string(), "{st}");
    assert_eq!(
        st["version"], saved2["version"],
        "the file's version without a run: {st}"
    );
    assert_eq!(st["busy"], false, "{st}");
    gate.notify_one();
    wait_until("the heavy lane to drain", || async {
        c.state.scheduler.heavy.stats().queued == 0
    })
    .await;
    c.state.feeds.retry_manual("m", Timestamp::now());
    runs_done(&c, "m", 2).await;
    let st = get_json(&c, "/feeds/m/status").await;
    assert_eq!(st["manual_retry_at"], Value::Null, "{st}");
    assert_eq!(st["latest_run"]["version"], saved2["version"], "{st}");
    // A provider feed's run event: its version, no saved_at.
    agg_feed(&c).await;
    let st = get_json(&c, "/feeds/agg/status").await;
    assert_eq!(
        (st["version"].clone(), st["saved_at"].clone()),
        (Value::Null, Value::Null),
        "{st}"
    );
    let mut rx = c.state.events.subscribe();
    *body.lock().unwrap() = "live.example\nmore.example\n".to_string();
    common::feeds::check_provider(&c, "agg").await;
    let ev = next_run_of(&mut rx, "agg").await;
    assert!(ev["version"].is_string(), "{ev}");
    assert!(ev["saved_at"].is_null(), "{ev}");
}

/// X1 (feeds.md §4: a `.txt` export's header declares its settings; api.md §7: another format
/// → `422`): a line-format file export is read as one whatever format the query or the target
/// expects, so it is never taken for a MISP list. As a new feed with `format=misp-warninglist`
/// it is refused naming `format` (nothing created); replacing or merging a MISP feed's file
/// with it is refused and leaves the file as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_line_format_export_is_never_read_as_a_misp_list() {
    let c = core_with(None).await;
    create_feed(
        &c,
        json!({"id": "src", "name": "Source", "format": "adblock", "category": "security", "warn_on": [],
               "rule_policy": {"redirects": "drop"}}),
    )
    .await;
    save(&c, "src", "||a.example^\n||b.example^\n").await;
    runs_done(&c, "src", 1).await;
    let text = get(&c, "/feeds/src/export?as=file").await.text().await.unwrap();
    let text_body = serde_json::to_vec(&json!({"file": text})).unwrap();
    for query in [
        "id=m1&format=misp-warninglist&category=privacy",
        "id=m1&format=misp-warninglist",
    ] {
        let (st, v) = import(&c, &format!("/feeds/import?{query}"), text_body.clone()).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{query}: {v}");
        assert_eq!(field(&v), Some("format"), "{query}: {v}");
    }
    assert!(c.state.feeds.def("m1").is_none(), "nothing was created");
    create_feed(&c, json!({"id": "w", "name": "W", "format": "misp-warninglist"})).await;
    save(
        &c,
        "w",
        r#"{"name": "w", "type": "hostname", "list": ["a.example"]}"#,
    )
    .await;
    runs_done(&c, "w", 1).await;
    let before = get_json(&c, "/feeds/w/file").await;
    let v1 = before["version"].as_str().unwrap().to_string();
    for mode in ["replace", "merge"] {
        let (st, v) = import(
            &c,
            &format!("/feeds/w/import?mode={mode}&base_version={v1}"),
            text_body.clone(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{mode} a MISP feed with an adblock export: {v}"
        );
    }
    let after = get_json(&c, "/feeds/w/file").await;
    assert_eq!(after["version"], before["version"], "the file is unchanged");
    assert_eq!(after["content"], before["content"]);
}

/// X3 (feeds.md §1: `warn_on` is a set of warn bundles): a query's `warn_on` naming the same
/// bundles as the export or the feed, in another order, is the same setting, not a conflict.
#[tokio::test(flavor = "multi_thread")]
async fn warn_on_in_another_order_is_the_same_setting() {
    let c = core_with(None).await;
    let r = ui(&c, Method::POST, "/bundles")
        .json(&json!({"id": "warn-x", "name": "X", "action": "warn", "feeds": []}))
        .send()
        .await
        .unwrap();
    let st = r.status();
    assert_eq!(st, StatusCode::CREATED, "{}", r.text().await.unwrap());
    create_feed(
        &c,
        json!({"id": "src", "name": "Source", "format": "adblock", "category": "security",
               "warn_on": ["warn-common", "warn-x"]}),
    )
    .await;
    save(&c, "src", "||a.example^\n").await;
    runs_done(&c, "src", 1).await;
    let export = get(&c, "/feeds/src/export").await.bytes().await.unwrap().to_vec();
    let text = get(&c, "/feeds/src/export?as=file").await.text().await.unwrap();
    let text_body = serde_json::to_vec(&json!({"file": text})).unwrap();
    for (id, body) in [("y", &export), ("y2", &text_body)] {
        let (st, v) = import(
            &c,
            &format!("/feeds/import?id={id}&warn_on=warn-x,warn-common"),
            body.clone(),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{id}: {v}");
        assert_eq!(
            get_json(&c, &format!("/feeds/{id}")).await["warn_on"],
            json!(["warn-common", "warn-x"]),
            "the export's own setting"
        );
    }
    let (st, v) = import(&c, "/feeds/import?id=y3&warn_on=warn-x", export).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "another set: {v}");
    assert_eq!(field(&v), Some("warn_on"), "{v}");
    let v1 = get_json(&c, "/feeds/src/file").await["version"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, v) = import(
        &c,
        &format!("/feeds/src/import?mode=merge&base_version={v1}&warn_on=warn-x,warn-common"),
        br#"{"file": "||b.example^\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "into the feed, the same set: {v}");
    let v2 = v["version"].as_str().unwrap().to_string();
    let (st, v) = import(
        &c,
        &format!("/feeds/src/import?mode=merge&base_version={v2}&warn_on=warn-x"),
        br#"{"file": "||c.example^\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNPROCESSABLE_ENTITY,
        "into the feed, another set: {v}"
    );
    assert_eq!(field(&v), Some("warn_on"), "{v}");
}

/// X7 (Z1; feeds.md §4, storage.md §4): a queued import job's cleanup is bound to its record's
/// id, feed and source generation, not to the id alone. Another feed's accepted import record
/// is moved onto the deleted feed's old import id (as ids could meet after a restore of an
/// older core.db); when the deleted feed's queued job (it runs first) finds its feed gone, it
/// leaves that record alone, so the record is applied (by the other feed's run of its oldest
/// pending import once its own job found nothing, else as at a start).
#[tokio::test(flavor = "multi_thread")]
async fn an_import_cleanup_never_removes_another_feeds_record_with_the_same_id() {
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("live.example\n")).await;
    let c = core_with(Some(&srv)).await;
    agg_feed(&c).await;
    create_feed(
        &c,
        json!({"id": "other", "name": "Other", "provider": "http", "provider_config": {"url": format!("https://{HOST}/other.txt")},
               "format": "plain", "modes": {"dns": {"mode": "aggregate"}}}),
    )
    .await;
    runs_done(&c, "other", 1).await;
    let gate = block_heavy_lane_with(&c, false).await;
    let (st, v) = import(
        &c,
        "/feeds/agg/import?mode=merge",
        br#"{"file": "deleted.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let old = import_ids(&c).await;
    assert_eq!(old.len(), 1, "{old:?}");
    let r = ui(&c, Method::DELETE, "/feeds/agg")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let (st, v) = import(
        &c,
        "/feeds/other/import?mode=merge",
        br#"{"file": "kept.example\n"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let old_id = old[0].0;
    c.state
        .db
        .write(move |db| {
            db.execute("UPDATE feed_imports SET id = ?1", [old_id])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    assert_eq!(import_ids(&c).await, vec![(old_id, "other".to_string())]);
    gate.notify_one();
    wait_until("both queued jobs ran", || async {
        let h = c.state.scheduler.heavy.stats();
        h.queued == 0 && h.running.is_none() && !c.state.feeds.is_busy("other")
    })
    .await;
    picket_core::feeds::resume_imports_now(&c.state).await;
    wait_until("the moved record applied", || async {
        entries(&c, "other").await.iter().any(|e| e.1 == "kept.example")
    })
    .await;
    wait_until("its record gone once applied", || async {
        import_ids(&c).await.is_empty() && !c.state.feeds.is_busy("other")
    })
    .await;
}
