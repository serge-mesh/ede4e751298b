//! The config export and restore (core.md §2 "Export and restore"; build-and-test.md §5 rows
//! "Config export", and the restore parts of "Convergence", "Edge requests" and "Attribution").
//!
//! A core with a feed provider (its `files` and `exclude`) against a local HTTPS server, a manual
//! feed, secrets, an alert and journal rows is exported through `GET config/export` and restored
//! with `PUT config/export` into an empty core and into a populated one.

use crate::common;

use std::sync::{Arc, Mutex};

use common::Core;
use common::bundles::{manual_feed, put_entity, save};
use common::edge::FakeEdge;
use common::feeds::{ui, wait_until};
use picket_core::modules::download::testkit::{Reply, Seen, TestServer};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

async fn core_with(srv: &TestServer) -> Core {
    common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
            feed_http: srv.http_options(),
            ..Default::default()
        },
    )
    .await
}

async fn q_i64(c: &Core, sql: &str) -> i64 {
    let s = sql.to_string();
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&s, [], |r| r.get::<_, i64>(0))?))
        .await
        .unwrap()
}

async fn export(c: &Core) -> (String, Value) {
    let r = ui(c, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment; filename=\"picket-config-")
    );
    let text = r.text().await.unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    (text, v)
}

async fn restore(c: &Core, doc: &Value) -> reqwest::Response {
    ui(c, Method::PUT, "/config/export")
        .json(doc)
        .send()
        .await
        .unwrap()
}

async fn server() -> (TestServer, Arc<Mutex<(String, String)>>) {
    let body = Arc::new(Mutex::new((
        "a.example\nb.example\n".to_string(),
        "\"e1\"".to_string(),
    )));
    let b = body.clone();
    let srv = TestServer::start(&["lists.example"], move |s: &Seen| {
        let (text, etag) = b.lock().unwrap().clone();
        if s.header("if-none-match") == Some(etag.as_str()) {
            return Reply::status(304);
        }
        Reply::ok(text).header("etag", &etag)
    })
    .await;
    (srv, body)
}

/// A core with a provider feed (applied), a manual feed, a secret, an alert and journal rows.
async fn populated(srv: &TestServer) -> Core {
    let c = core_with(srv).await;
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&json!({"id": "p", "name": "P", "module": "http", "config": {"url": "https://lists.example/l.txt"},
                      "files": [{"match": "response", "feed": {"format": "plain", "category": "security"}}],
                      "exclude": ["old.txt"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    wait_until("the provider feed's first run", || async {
        q_i64(
            &c,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'p' AND status = 'applied'",
        )
        .await
            >= 1
            && !c.state.feeds.is_busy("p")
            && !c.state.feeds.is_checking("p")
    })
    .await;
    manual_feed(&c, "m1", json!({"category": "security"})).await;
    save(&c, "m1", "||ads.example^\n||tracker.example^\n").await;
    put_entity(
        &c,
        "bundles",
        "b1",
        json!({"id": "b1", "name": "b1", "feeds": [{"feed": "m1"}, {"feed": "p"}]}),
    )
    .await;
    let r = ui(&c, Method::PUT, "/secrets/s1")
        .json(&json!({"value": "v1-secret"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    c.state
        .alerts
        .raise(picket_core::alerts::RaiseSpec::new(
            "feed_held",
            picket_core::alerts::Severity::Warning,
            "feed_held:m1",
            "held",
            json!({"why": "test"}),
        ))
        .await
        .unwrap();
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn an_export_restores_into_an_empty_and_a_populated_core() {
    let (srv, _body) = server().await;
    let a = populated(&srv).await;
    let (text, mut doc) = export(&a).await;
    // The document: format, configuration with files and exclude, secrets by name only.
    assert_eq!(doc["format_version"], json!(1));
    let p = doc["configuration"]["feed_providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == json!("p"))
        .unwrap()
        .clone();
    assert_eq!(p["exclude"], json!(["old.txt"]));
    assert_eq!(p["files"][0]["match"], json!("response"));
    assert!(
        doc["configuration"]["feeds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == json!("p"))
    );
    assert_eq!(doc["configuration"]["secrets"], json!([{"name": "s1"}]));
    assert!(!text.contains("v1-secret"), "no secret value in an export");
    assert!(
        doc["manual_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["feed"] == json!("m1"))
    );
    assert!(!doc["config_changes"].as_array().unwrap().is_empty());
    let alert = doc["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["alert"]["dedupe_key"] == json!("feed_held:m1"))
        .unwrap()
        .clone();
    assert!(!alert["history"].as_array().unwrap().is_empty());
    assert!(
        doc["feed_state"]["feeds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["feed"] == json!("p") && f["seen_blake3"].is_string())
    );
    assert!(doc.get("logs").is_none() && doc.get("metrics").is_none());

    // An empty core: a stored s1 keeps its value, s3 gets the document's, s4 has none.
    let b = core_with(&srv).await;
    let r = ui(&b, Method::PUT, "/secrets/s1")
        .json(&json!({"value": "b-own"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let secrets = doc["configuration"]["secrets"].as_array_mut().unwrap();
    secrets.push(json!({"name": "s3", "value": "v3"}));
    secrets.push(json!({"name": "s4"}));
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    let res: Value = r.json().await.unwrap();
    assert_eq!(res["missing_secrets"], json!(["s4"]));
    let vals = b
        .state
        .config
        .secret_values(vec!["s1".into(), "s3".into(), "s4".into()])
        .await
        .unwrap();
    assert_eq!(vals.get("s1").map(String::as_str), Some("b-own"));
    assert_eq!(vals.get("s3").map(String::as_str), Some("v3"));
    assert!(!vals.contains_key("s4"));
    // The configuration, the manual file, the alert (same id) and the journal are back.
    let (st, prov) = common::bundles::get(&b, "/feed-providers/p").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(prov["exclude"], json!(["old.txt"]));
    let (st, f) = common::bundles::get(&b, "/feeds/m1/file").await;
    assert_eq!(st, StatusCode::OK, "{f}");
    assert!(
        f["content"].as_str().unwrap_or("").contains("||tracker.example^")
            || f.to_string().contains("tracker.example"),
        "{f}"
    );
    let alert_id = alert["alert"]["id"].as_i64().unwrap();
    assert_eq!(
        q_i64(
            &b,
            &format!("SELECT count(*) FROM alerts WHERE id = {alert_id} AND dedupe_key = 'feed_held:m1'")
        )
        .await,
        1
    );
    assert!(
        q_i64(&b, "SELECT count(*) FROM config_changes").await
            >= doc["config_changes"].as_array().unwrap().len() as i64
    );
    // Feeds come back with their providers: none is added or raised again (the document's
    // feed_added alert comes back as it was, its count unchanged).
    let added = "SELECT coalesce(sum(count), 0) * 10 + coalesce(sum(state = 'open'), 0) FROM alerts WHERE kind = 'feed_added'";
    let added_a = q_i64(&a, added).await;
    assert_eq!(q_i64(&b, added).await, added_a);
    // The provider's next check is a first check: the same bytes record no change.
    let changes = q_i64(&a, "SELECT count(*) FROM feed_changes WHERE feed_id = 'p'").await;
    wait_until("the restored provider's first check and run", || async {
        q_i64(
            &b,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'p' AND status = 'applied'",
        )
        .await
            >= 1
            && !b.state.feeds.is_busy("p")
            && !b.state.feeds.is_checking("p")
    })
    .await;
    assert_eq!(
        q_i64(&b, "SELECT count(*) FROM feed_changes WHERE feed_id = 'p'").await,
        changes,
        "no faked change after a restore"
    );
    assert_eq!(
        q_i64(&b, added).await,
        added_a,
        "no feed is raised again by its first check"
    );
    // The manual feed's file was run.
    wait_until("the manual feed's run", || async {
        q_i64(
            &b,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'm1' AND status = 'applied'",
        )
        .await
            >= 1
    })
    .await;

    // A populated core: everything the document doesn't hold goes.
    put_entity(&a, "profiles", "extra", json!({"id": "extra", "name": "extra"})).await;
    let (_, original) = export(&b).await;
    let r = restore(&a, &original).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(
        q_i64(&a, "SELECT count(*) FROM profiles WHERE id = 'extra'").await,
        0
    );
    assert_eq!(q_i64(&a, "SELECT count(*) FROM feeds WHERE id = 'p'").await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn other_lanca_zones_and_bad_references_reject_the_whole_document() {
    let (srv, _) = server().await;
    let a = populated(&srv).await;
    let (_, doc) = export(&a).await;
    let b = core_with(&srv).await;
    put_entity(&b, "profiles", "keep", json!({"id": "keep", "name": "keep"})).await;
    let mut other = doc.clone();
    other["configuration"]["settings"]["lanca.zones"] = json!(["other.example"]);
    let r = restore(&b, &other).await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = r.text().await.unwrap();
    assert!(body.contains("other.example"), "names the zones it needs: {body}");
    // One bad reference: a bundle naming a feed the document doesn't hold.
    let mut bad = doc.clone();
    bad["configuration"]["bundles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "bx", "name": "bx", "feeds": [{"feed": "no-such-feed"}]}));
    let r = restore(&b, &bad).await;
    assert_eq!(
        r.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        r.text().await.unwrap()
    );
    // A newer format.
    let mut newer = doc.clone();
    newer["format_version"] = json!(99);
    assert_eq!(
        restore(&b, &newer).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Issue 74: an `http` provider of a `base_url` and paths (a shape no release produces now) is
    // refused like any other bad config, not converted.
    let mut old = doc.clone();
    old["configuration"]["feed_providers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "old", "name": "Old", "module": "http", "enabled": false,
                     "config": {"base_url": "https://lists.example/"},
                     "files": [{"match": "response", "feed": {"format": "plain"}}]}));
    let r = restore(&b, &old).await;
    let st = r.status();
    let body = r.text().await.unwrap();
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.contains("\"old\""), "names the provider: {body}");
    assert!(body.contains("base_url"), "names the field: {body}");
    // Nothing changed.
    assert_eq!(
        q_i64(&b, "SELECT count(*) FROM profiles WHERE id = 'keep'").await,
        1
    );
    assert_eq!(q_i64(&b, "SELECT count(*) FROM feeds WHERE id = 'p'").await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_sqs_provider_is_restored_without_its_keys() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    let (_, mut doc) = export(&a).await;
    doc["configuration"]["feed_providers"].as_array_mut().unwrap().push(json!({
        "id": "q", "name": "Q", "module": "http", "enabled": false, "config": {"url": "https://lists.example/q.txt"},
        "trigger": {"kind": "sqs", "queue_url": "https://sqs.eu-west-1.amazonaws.com/123456789012/lists",
                    "access_key_id": "${secret:aws_id}", "secret_access_key": "${secret:aws_key}"},
        "files": [{"match": "response", "feed": {"format": "plain"}}]}));
    doc["configuration"]["secrets"] = json!([{"name": "aws_id"}, {"name": "aws_key"}]);
    let b = core_with(&srv).await;
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    let res: Value = r.json().await.unwrap();
    assert_eq!(res["missing_secrets"], json!(["aws_id", "aws_key"]), "{res}");
    assert!(
        !b.state.feeds.sqs_running("q"),
        "no queue is read until the keys are entered"
    );
}

/// A restored core keeps naming, and keeps the files of, the heads each edge runs until the
/// bundle's downloaded feeds have their first runs (core.md §2; "Convergence": a core restored
/// from a backup). Requests are compared by equality ("Edge requests").
#[tokio::test(flavor = "multi_thread")]
async fn edges_keep_their_heads_until_restored_feeds_have_runs() {
    let (srv, body) = server().await;
    let a = populated(&srv).await;
    // The edge runs the head b1 has now, as its heartbeat reports.
    let head = common::bundles::build(&a, "b1").await.expect("b1 head");
    put_entity(
        &a,
        "profiles",
        "default",
        json!({"id": "default", "name": "Default", "allow": ["allow-common"], "block": ["block-common", "b1"]}),
    )
    .await;
    let edge = FakeEdge::registered(&a, "e1").await;
    let short: String = head.chars().take(16).collect();
    let id = edge.id.clone();
    let versions = json!({"config": "0000000000000000", "bundles": {"b1": short}}).to_string();
    a.state
        .db
        .write(move |c| {
            c.execute(
                "INSERT INTO edge_status(edge_id, versions_json) VALUES (?1, ?2)
                 ON CONFLICT(edge_id) DO UPDATE SET versions_json = excluded.versions_json",
                rusqlite::params![id, versions],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let (_, doc) = export(&a).await;
    // The server sends the same bytes under another ETag: the restored feed's first check.
    body.lock().unwrap().1 = "\"e9\"".into();
    let r = restore(&a, &doc).await;
    assert_eq!(r.status(), StatusCode::OK);
    // C2: the reply says which edge keeps which bundle's head, and that providers check again.
    let res: Value = r.json().await.unwrap();
    let warnings = res["warnings"].to_string();
    assert!(
        warnings.contains("Edge e1 keeps running its current versions of b1"),
        "{res}"
    );
    assert!(warnings.contains("check again at once"), "{res}");
    assert_eq!(q_i64(&a, "SELECT count(*) FROM restore_holds").await, 1);
    // The edge's config keeps naming the head it runs.
    a.state.edges.publisher.render(&a.state, None).await.unwrap();
    let named = a
        .state
        .edges
        .publisher
        .current(&edge.id)
        .map(|p| p.config.bundles.get("b1").cloned());
    // Until the feed's first run the old head stays named (or the object holds it); once the
    // run is in, the hold ends.
    wait_until("the restored feed's first run", || async {
        q_i64(
            &a,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'p' AND status = 'applied'",
        )
        .await
            >= 1
    })
    .await;
    if let Some(Some(h)) = named {
        assert_eq!(h, head, "the head the edge runs stays named");
    }
    assert!(
        q_i64(
            &a,
            &format!("SELECT count(*) FROM bundle_versions WHERE head_id = '{head}'")
        )
        .await
            == 1,
        "its version (and files) are kept"
    );
    a.state.edges.publisher.render(&a.state, None).await.unwrap();
    assert_eq!(
        q_i64(&a, "SELECT count(*) FROM restore_holds").await,
        0,
        "the hold ends"
    );
    // Requests made before the restore are gone; a new one gets a fresh id (equality only).
    assert_eq!(q_i64(&a, "SELECT count(*) FROM edge_requests").await, 0);
}

/// A manual feed whose latest save was rejected exports its file and its latest applied run's
/// blob; the restore applies that blob and keeps the saved file as its file ("Manual feeds":
/// export and restore after a rejected save).
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_save_is_restored_with_the_applied_blob() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    put_entity(
        &a,
        "feeds",
        "m2",
        json!({"id": "m2", "name": "m2", "format": "plain"}),
    )
    .await;
    save(&a, "m2", "good.example\n").await;
    // Parse errors past max_parse_error_ratio: the run is rejected, the file still saved.
    save(&a, "m2", "good.example\nnew.example\nthis is not a plain line\n").await;
    assert_eq!(
        q_i64(
            &a,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'm2' AND status = 'rejected'"
        )
        .await,
        1
    );
    let (_, doc) = export(&a).await;
    let mf = doc["manual_files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["feed"] == json!("m2"))
        .unwrap()
        .clone();
    assert!(
        mf["applied"].is_object(),
        "the applied blob travels when it differs: {mf}"
    );
    let b = core_with(&srv).await;
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK);
    // C2: the reply says the applied version runs first.
    let res: Value = r.json().await.unwrap();
    assert!(
        res["warnings"]
            .to_string()
            .contains("Manual feed m2: its applied version from the document is applied first"),
        "{res}"
    );
    wait_until("the applied blob's run and the file's run", || async {
        q_i64(
            &b,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'm2' AND status = 'applied'",
        )
        .await
            >= 1
            && q_i64(
                &b,
                "SELECT count(*) FROM feed_runs WHERE feed_id = 'm2' AND status = 'rejected'",
            )
            .await
                >= 1
            && !b.state.feeds.is_busy("m2")
    })
    .await;
    let open = |k: &'static str| {
        format!(
            "SELECT count(*) FROM feed_entries WHERE feed_id = 'm2' AND removed_run IS NULL AND key = '{k}'"
        )
    };
    assert_eq!(q_i64(&b, &open("example.good")).await, 1);
    assert_eq!(
        q_i64(&b, &open("example.new")).await,
        0,
        "the rejected save isn't applied"
    );
    let (_, f) = common::bundles::get(&b, "/feeds/m2/file").await;
    assert!(
        f.to_string().contains("not a plain line"),
        "the saved file stays its file: {f}"
    );
}

/// README §2 Compatibility: a document from an older release (fields it lacks, unknown ones it
/// carries) restores; missing parts take their defaults, and the system objects come back.
#[tokio::test(flavor = "multi_thread")]
async fn an_older_document_restores_with_defaults() {
    let (srv, _) = server().await;
    let b = core_with(&srv).await;
    put_entity(&b, "profiles", "gone", json!({"id": "gone", "name": "gone"})).await;
    let doc = json!({
        "format_version": 1,
        "configuration": {
            "settings": {"retention.query_logs": "48h", "future.setting": true},
            "profiles": [{"id": "kids", "name": "Kids", "a_newer_field": 1}],
            "feeds": [{"id": "m9", "name": "m9", "format": "adblock"}]
        },
        "manual_files": [{"feed": "m9", "file": "fHxhZHMuZXhhbXBsZV4K"}],
        "something_newer": {"ignored": true}
    });
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(
        q_i64(&b, "SELECT count(*) FROM profiles WHERE id = 'gone'").await,
        0
    );
    assert_eq!(
        q_i64(&b, "SELECT count(*) FROM profiles WHERE id = 'kids'").await,
        1
    );
    // System objects are created again (core.md §2).
    assert_eq!(
        q_i64(&b, "SELECT count(*) FROM profiles WHERE id = 'dnssec-validator'").await,
        1
    );
    assert_eq!(
        q_i64(&b, "SELECT count(*) FROM feeds WHERE id = 'manual-block'").await,
        1
    );
    assert_eq!(
        b.state.settings().retention.query_logs.as_secs(),
        48 * 3600,
        "the document's settings are live at once"
    );
    wait_until("the restored manual feed's run", || async {
        q_i64(
            &b,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'm9' AND status = 'applied'",
        )
        .await
            >= 1
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// Review round 1 (wave 5C)

/// Starts a core on `dir`, a [`common::snapshot_dir`] no core has run on (so nothing holds its lock, and
/// any start error is the test's failure).
async fn start_on(
    dir: &std::path::Path,
    srv: &TestServer,
) -> (
    picket_core::state::SharedState,
    tokio_util::sync::CancellationToken,
) {
    let stop = tokio_util::sync::CancellationToken::new();
    let opts = picket_core::run::StartOptions {
        release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
        feed_http: srv.http_options(),
        any_port: true,
        clock_synced: Some(true),
        disk_watch: false,
        ..Default::default()
    };
    let (state, _) = picket_core::run::start_with(dir, stop.clone(), opts)
        .await
        .unwrap();
    (state, stop)
}

async fn sql_i64(state: &picket_core::state::SharedState, sql: &str) -> i64 {
    let s = sql.to_string();
    state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&s, [], |r| r.get::<_, i64>(0))?))
        .await
        .unwrap()
}

/// core.md §2 "one bad reference rejects the whole document": check history naming a provider or
/// feed the document doesn't hold is refused (422) before anything changes. A deleted provider's
/// history stays until retention, but it isn't the document's: an export leaves it out and
/// restores.
#[tokio::test(flavor = "multi_thread")]
async fn bad_check_history_references_reject_the_document() {
    let (srv, _) = server().await;
    let a = populated(&srv).await;
    let (_, doc) = export(&a).await;
    let b = core_with(&srv).await;
    put_entity(&b, "profiles", "keep", json!({"id": "keep", "name": "keep"})).await;
    for (what, part) in [
        (
            "nonexistent",
            json!({"provider": "nonexistent", "t": "2026-11-01T00:00:00.000Z", "ok": false, "feeds": []}),
        ),
        (
            "no-such-feed",
            json!({"provider": null, "t": "2026-11-01T00:00:00.000Z", "ok": true,
                   "feeds": [{"feed": "no-such-feed", "t": "2026-11-01T00:00:00.000Z", "ok": true, "changes": []}]}),
        ),
    ] {
        let mut bad = doc.clone();
        bad["feed_state"]["checks"].as_array_mut().unwrap().push(part);
        let r = restore(&b, &bad).await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY, "{what}");
        let body = r.text().await.unwrap();
        assert!(body.contains(what), "{body}");
        assert_eq!(
            q_i64(&b, "SELECT count(*) FROM profiles WHERE id = 'keep'").await,
            1,
            "nothing changed"
        );
    }
    // A provider checked, then deleted: its history stays on A, out of A's export.
    let r = ui(&a, Method::POST, "/feed-providers")
        .json(&json!({"id": "q", "name": "Q", "module": "http", "config": {"url": "https://lists.example/l.txt"},
                      "files": [{"match": "response", "feed": {"format": "plain", "category": "privacy"}}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    wait_until("q's first check", || async {
        q_i64(
            &a,
            "SELECT count(*) FROM feed_provider_checks WHERE provider_id = 'q'",
        )
        .await
            >= 1
            && !a.state.feeds.is_checking("q")
    })
    .await;
    for path in ["/feeds/q", "/feed-providers/q"] {
        let r = ui(&a, Method::DELETE, path)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "{path}: {}", r.text().await.unwrap());
    }
    let r = ui(&a, Method::GET, "/feed-providers/q").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert!(
        q_i64(
            &a,
            "SELECT count(*) FROM feed_provider_checks WHERE provider_id = 'q'"
        )
        .await
            >= 1
    );
    let (_, doc) = export(&a).await;
    assert!(
        !doc["feed_state"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["provider"] == json!("q")),
        "a deleted provider's history isn't the document's"
    );
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
}

/// README §3 (requests wait in the edge's config object until it reconnects): a restore keeps
/// the edges' pending requests and temporary allows for the edges the document holds, so a revoke
/// made while an edge was offline still reaches it. A flush of a lookup provider the document
/// doesn't hold goes.
#[tokio::test(flavor = "multi_thread")]
async fn pending_edge_requests_and_revocations_survive_a_restore() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    let edge = FakeEdge::registered(&a, "e1").await;
    picket_core::edges::requests::revoke_allow(&a.state, &edge.id, "allow-1")
        .await
        .unwrap();
    picket_core::edges::requests::flush(&a.state, &edge.id, None)
        .await
        .unwrap();
    let id = edge.id.clone();
    a.state
        .db
        .write(move |db| {
            Ok::<_, anyhow::Error>(db.execute(
                "INSERT INTO edge_requests(edge_id, kind, provider, request_id, requested_at)
                 VALUES (?1, 'flush_lookups', 'gone', '0123456789abcdef', '2026-11-24T00:00:00.000Z')",
                [&id],
            )?)
        })
        .await
        .unwrap();
    let (_, doc) = export(&a).await;
    let r = restore(&a, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(
        q_i64(
            &a,
            "SELECT count(*) FROM temp_allows WHERE allow_id = 'allow-1' AND revoke_requested_at IS NOT NULL"
        )
        .await,
        1,
        "the revocation stays"
    );
    assert_eq!(
        q_i64(
            &a,
            "SELECT count(*) FROM edge_requests WHERE kind IN ('revoked_allows', 'flush_dns')"
        )
        .await,
        2,
        "the pending requests stay"
    );
    assert_eq!(
        q_i64(
            &a,
            "SELECT count(*) FROM edge_requests WHERE kind = 'flush_lookups'"
        )
        .await,
        0,
        "a flush of a provider the document doesn't hold goes"
    );
}

/// README §2 Restarts: the applied blob a restore applies first is recorded in its transaction;
/// a stop before that run (here: a copy of the directory with the runs taken out, as right
/// after the commit) applies it at the next start, then runs the saved file.
#[tokio::test(flavor = "multi_thread")]
async fn an_applied_blob_survives_a_stop_after_the_restore() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    put_entity(
        &a,
        "feeds",
        "m2",
        json!({"id": "m2", "name": "m2", "format": "plain"}),
    )
    .await;
    save(&a, "m2", "good.example\n").await;
    save(&a, "m2", "good.example\nnew.example\nthis is not a plain line\n").await;
    let (_, doc) = export(&a).await;
    let b = core_with(&srv).await;
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(
        q_i64(&b, "SELECT count(*) FROM restore_applied WHERE feed_id = 'm2'").await,
        1,
        "recorded in the restore's transaction"
    );
    // The record as the commit left it (it goes once the blob's own run is stored).
    let marker: (String, String, String) = b
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT blob, version, updated_at FROM restore_applied WHERE feed_id = 'm2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })
        .await
        .unwrap();
    wait_until("the restore's runs", || async {
        q_i64(&b, "SELECT count(*) FROM feed_runs WHERE feed_id = 'm2'").await >= 2
            && !b.state.feeds.is_busy("m2")
    })
    .await;
    b.stop.cancel();
    let copy = tempfile::tempdir().unwrap();
    common::snapshot_dir(b.dir.path(), copy.path());
    {
        let c = rusqlite::Connection::open(copy.path().join("core.db")).unwrap();
        c.execute_batch(
            "DELETE FROM feed_runs WHERE feed_id = 'm2'; DELETE FROM feed_entries WHERE feed_id = 'm2';",
        )
        .unwrap();
        c.execute(
            "INSERT OR REPLACE INTO restore_applied(feed_id, blob, version, updated_at) VALUES ('m2', ?1, ?2, ?3)",
            rusqlite::params![marker.0, marker.1, marker.2],
        )
        .unwrap();
    }
    let (state, stop) = start_on(copy.path(), &srv).await;
    let open = |k: &'static str| {
        format!(
            "SELECT count(*) FROM feed_entries WHERE feed_id = 'm2' AND removed_run IS NULL AND key = '{k}'"
        )
    };
    let mut ok = false;
    for _ in 0..300 {
        if sql_i64(&state, &open("example.good")).await == 1
            && sql_i64(
                &state,
                "SELECT count(*) FROM feed_runs WHERE feed_id = 'm2' AND status = 'rejected'",
            )
            .await
                >= 1
            && !state.feeds.is_busy("m2")
        {
            ok = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ok, "the applied blob ran, then the saved file");
    assert_eq!(sql_i64(&state, &open("example.new")).await, 0);
    stop.cancel();
}

/// core.md §2, §3: manual files travel in base64 chunks (an export never holds a whole file or
/// document in memory) and restore from them; a malformed document is 422 (api.md §7), as is one
/// with a string past the bound the restore reads with.
#[tokio::test(flavor = "multi_thread")]
async fn large_files_travel_in_chunks_and_malformed_documents_are_422() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    put_entity(
        &a,
        "feeds",
        "m3",
        json!({"id": "m3", "name": "m3", "format": "plain"}),
    )
    .await;
    let text: String = (0..120_000).map(|i| format!("host{i}.example\n")).collect();
    save(&a, "m3", &text).await;
    let (_, doc) = export(&a).await;
    let mf = doc["manual_files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["feed"] == json!("m3"))
        .unwrap()
        .clone();
    let chunks = mf["file"].as_array().expect("a list of chunks");
    assert!(
        chunks.len() >= 3,
        "{} chunks for {} bytes",
        chunks.len(),
        text.len()
    );
    let b = core_with(&srv).await;
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    let blob: String = b
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT blob FROM manual_files WHERE feed_id = 'm3'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(blob, picket_api::ids::object_id(text.as_bytes()), "the same file");
    for (body, what) in [
        ("not json".to_string(), "not a config export"),
        (
            format!(
                r#"{{"format_version": 1, "configuration": {{"settings": {{"x": "{}"}}}}}}"#,
                "a".repeat(5 << 20)
            ),
            "longer than",
        ),
        (r#"{"configuration": {}}"#.to_string(), "format_version"),
    ] {
        let r = ui(&b, Method::PUT, "/config/export")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY, "{what}");
        let t = r.text().await.unwrap();
        assert!(t.contains(what), "{t}");
    }
}

/// core.md §2: an export is one snapshot (one read transaction), whatever commits while it is
/// written; and past its bound it is refused, naming what makes it large.
#[tokio::test(flavor = "multi_thread")]
async fn an_export_is_one_snapshot_and_bounded() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    manual_feed(&a, "m4", json!({"category": "security"})).await;
    save(&a, "m4", "||ads.example^\n").await;
    /// Deletes m4 through another connection on its first write.
    struct Hook {
        out: Vec<u8>,
        db: Option<std::path::PathBuf>,
    }
    impl std::io::Write for Hook {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if let Some(p) = self.db.take() {
                let c = rusqlite::Connection::open(p).unwrap();
                c.busy_timeout(std::time::Duration::from_secs(10)).unwrap();
                c.execute_batch(
                    "DELETE FROM manual_files WHERE feed_id = 'm4'; DELETE FROM feeds WHERE id = 'm4';",
                )
                .unwrap();
            }
            self.out.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let dir = a.dir.path().to_path_buf();
    let doc: Value = a
        .state
        .db
        .read(move |c| {
            let mut h = Hook {
                out: Vec::new(),
                db: Some(dir.join("core.db")),
            };
            picket_core::config::export::write_export_within(c, &dir, &mut h, 1 << 30)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok::<_, anyhow::Error>(serde_json::from_slice(&h.out)?)
        })
        .await
        .unwrap();
    assert!(
        doc["manual_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["feed"] == json!("m4")),
        "the file of a feed in the snapshot is in the document"
    );
    assert_eq!(
        q_i64(&a, "SELECT count(*) FROM feeds WHERE id = 'm4'").await,
        0,
        "deleted meanwhile"
    );
    let dir = a.dir.path().to_path_buf();
    let e = a
        .state
        .db
        .read(move |c| {
            Ok::<_, anyhow::Error>(
                picket_core::config::export::write_export_within(c, &dir, std::io::sink(), 4096)
                    .unwrap_err()
                    .to_string(),
            )
        })
        .await
        .unwrap();
    assert!(
        e.contains("larger than") && e.contains("manual feed files"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------------------------
// Review round 2

/// core.md §2 "the old state until it completes, then only the new one": a bundle build that read
/// pre-restore feed entries commits nothing after the restore (no keys, no version, no build row
/// naming pre-restore runs), here for a bundle with no downloaded member (so no restore hold),
/// and the bundle builds again from the restored state. Twice: the restore commits between two
/// of the build's steps (the step's generation check ends it), then inside its commit step,
/// after that check and right before the commit's write (the check inside the write ends it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_build_in_flight_commits_nothing_after_a_restore() {
    use picket_core::scheduler::HeavyJob;
    let (srv, _) = server().await;
    let c = core_with(&srv).await;
    manual_feed(&c, "rf", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "rb",
        json!({"id": "rb", "name": "rb", "feeds": [{"feed": "rf"}]}),
    )
    .await;
    save(&c, "rf", "||restored.example^\n").await;
    common::bundles::settle(&c, "rb").await;
    let (_, doc) = export(&c).await;
    for inside_commit in [false, true] {
        save(&c, "rf", "||restored.example^\n||stale.example^\n").await;
        common::bundles::settle(&c, "rb").await;
        // A build of the pre-restore state, run up to its commit step.
        picket_core::compiler::retire(&c.state, "rb").await.unwrap();
        let mut job = picket_core::compiler::build::BuildJob::new(c.state.clone(), "rb");
        while job.phase_name() != "commit" {
            assert_ne!(job.phase_name(), "done");
            job.step().await.unwrap();
        }
        let job = if inside_commit {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
            let release = Arc::new(tokio::sync::Notify::new());
            let rel = release.clone();
            c.state.compiler.pause_next_commit(Box::pin(async move {
                let _ = entered_tx.send(());
                rel.notified().await;
            }));
            let task = tokio::spawn(async move {
                job.step().await.unwrap();
                job
            });
            entered_rx.await.unwrap();
            let r = restore(&c, &doc).await;
            assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
            release.notify_one();
            task.await.unwrap()
        } else {
            let r = restore(&c, &doc).await;
            assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
            job.step().await.unwrap();
            job
        };
        assert_eq!(job.phase_name(), "done");
        assert_eq!(
            q_i64(&c, "SELECT count(*) FROM bundle_builds WHERE bundle_id = 'rb'").await,
            0,
            "no build row naming pre-restore runs (inside commit: {inside_commit})"
        );
        assert_eq!(
            q_i64(&c, "SELECT count(*) FROM bundle_versions WHERE bundle_id = 'rb'").await,
            0,
            "no version built from pre-restore entries (inside commit: {inside_commit})"
        );
        assert_eq!(
            q_i64(&c, "SELECT count(*) FROM bundle_keys WHERE bundle_id = 'rb'").await,
            0,
            "no pre-restore keys (inside commit: {inside_commit})"
        );
        // The build ended: the bundle builds again from the restored feed.
        drop(job);
        wait_until("the restored bundle's build", || async {
            q_i64(
                &c,
                "SELECT count(*) FROM bundle_keys WHERE bundle_id = 'rb' AND key LIKE '%restored%'",
            )
            .await
                > 0
                && !c.state.compiler.busy("rb")
        })
        .await;
        assert_eq!(
            q_i64(
                &c,
                "SELECT count(*) FROM bundle_keys WHERE bundle_id = 'rb' AND key LIKE '%stale%'"
            )
            .await,
            0
        );
    }
}

/// core.md §2, README §2 Restarts: when the heavy queue refuses the run of a restored applied
/// blob, the manual retry runs that blob, not the saved file, and the restore's marker stays
/// until the blob's own run is stored; feed retention meanwhile keeps the blob the marker names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_applied_blob_run_is_retried_with_that_blob() {
    use picket_core::retention::RetentionHook;
    use picket_core::scheduler::{FnJob, HeavyLane, Priority, Step, Submitted};
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    put_entity(
        &a,
        "feeds",
        "m2",
        json!({"id": "m2", "name": "m2", "format": "plain"}),
    )
    .await;
    save(&a, "m2", "good.example\n").await;
    save(&a, "m2", "good.example\nnew.example\nthis is not a plain line\n").await;
    let (_, doc) = export(&a).await;
    let b = core_with(&srv).await;
    // The heavy lane busy, its queue full.
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (en, rel) = (entered.clone(), release.clone());
    b.state.scheduler.heavy.submit(
        Priority::P0,
        Box::new(FnJob::new("test_gate", "gate", move || async move {
            en.notify_one();
            rel.notified().await;
            Ok(())
        })),
    );
    tokio::time::timeout(std::time::Duration::from_secs(20), entered.notified())
        .await
        .unwrap();
    for i in 0..HeavyLane::CAP + 1 {
        let job = FnJob::new("test_fill", i.to_string(), || async { Ok(()) });
        if b.state.scheduler.heavy.submit(Priority::P0, Box::new(job)) == Submitted::Dropped {
            break;
        }
    }
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    // Retention in that window keeps the blob the restore's marker names.
    b.state
        .db
        .write(|db| {
            db.execute("UPDATE blobs SET created_at = '2000-01-01T00:00:00.000000Z'", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let hook = picket_core::feeds::retention::FeedRetention;
    while hook.step(&b.state).await.unwrap() == Step::More {}
    assert_eq!(
        q_i64(
            &b,
            "SELECT count(*) FROM blobs WHERE blake3 = (SELECT blob FROM restore_applied WHERE feed_id = 'm2')"
        )
        .await,
        1,
        "the applied blob is kept"
    );
    release.notify_one();
    wait_until("the heavy queue to drain", || async {
        b.state.scheduler.heavy.depth() == 0 && !b.state.feeds.is_busy("m2")
    })
    .await;
    // The retry the one-minute manual timer runs, without waiting the minute.
    b.state
        .db
        .write(|db| {
            db.execute("UPDATE restore_applied SET next_at = NULL", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    b.state.feeds.trigger_manual(&b.state, "m2");
    wait_until("the applied blob's run, then the saved file's", || async {
        q_i64(
            &b,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'm2' AND status = 'rejected'",
        )
        .await
            > 0
            && !b.state.feeds.is_busy("m2")
    })
    .await;
    let open = |k: &str| {
        format!(
            "SELECT count(*) FROM feed_entries WHERE feed_id = 'm2' AND removed_run IS NULL AND key = '{k}'"
        )
    };
    assert_eq!(
        q_i64(&b, &open("example.good")).await,
        1,
        "the previous working rules came back"
    );
    assert_eq!(q_i64(&b, &open("example.new")).await, 0);
    assert_eq!(
        q_i64(&b, "SELECT count(*) FROM restore_applied").await,
        0,
        "done once the blob's run is stored"
    );
}

/// README §2 Untrusted input, Bounded: the restore's part caps hold for a key written with JSON
/// escapes too (the pre-scan reads keys as the parser does).
#[test]
fn part_caps_apply_to_escaped_keys() {
    use picket_core::config::export::stream;
    let entries = vec!["\"x\""; 4_500_000].join(",");
    let normal = format!(r#"{{"format_version":1,"configuration":{{"settings":{{"x":[{entries}]}}}}}}"#);
    let escaped = normal.replacen("configuration", r"\u0063onfiguration", 1);
    assert!(stream::prescan(normal.as_bytes()).is_err());
    let e = stream::prescan(escaped.as_bytes()).unwrap_err();
    assert!(e.contains("configuration"), "{e}");
    // An escaped key the parser reads as another part's is that part.
    let surrogate = normal.replacen("configuration", r"\u0063onfigur\u0061tion", 1);
    assert!(stream::prescan(surrogate.as_bytes()).is_err());
}

/// README §2 Compatibility: a previous-format export whose manual file is one base64 string past
/// the string cap (a file just over 3 MiB) passes the pre-scan, and restores: the string is
/// decoded as it streams.
#[tokio::test(flavor = "multi_thread")]
async fn a_previous_format_single_string_file_restores() {
    use base64::Engine;
    use picket_core::config::export::stream;
    let file = "AAAA".repeat((3 * 1024 * 1024 / 3) + 1);
    let document = format!(r#"{{"format_version":1,"manual_files":[{{"feed":"m","file":"{file}"}}]}}"#);
    assert!(stream::prescan(document.as_bytes()).is_ok());
    // Other strings keep their cap.
    let other = format!(r#"{{"format_version":1,"manual_files":[{{"feed":"{file}","file":"AAAA"}}]}}"#);
    assert!(stream::prescan(other.as_bytes()).is_err());
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    put_entity(
        &a,
        "feeds",
        "m5",
        json!({"id": "m5", "name": "m5", "format": "plain"}),
    )
    .await;
    save(&a, "m5", "x.example\n").await;
    let (_, mut doc) = export(&a).await;
    let text: String = (0..230_000).map(|i| format!("host{i}.example\n")).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    assert!(b64.len() > 4 * 1024 * 1024);
    for m in doc["manual_files"].as_array_mut().unwrap() {
        if m["feed"] == json!("m5") {
            m["file"] = json!(b64);
        }
    }
    let b = core_with(&srv).await;
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    let blob: String = b
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT blob FROM manual_files WHERE feed_id = 'm5'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(blob, picket_api::ids::object_id(text.as_bytes()), "the same file");
}

/// README §2 Bounded, core.md §2: a configuration validation accepts fits the restore's part
/// caps (validation refuses one past them), and the export applies exactly the caps the restore
/// applies: a configuration past them (written around validation) is refused with 422 naming
/// the part, not exported into a document no restore reads.
#[tokio::test(flavor = "multi_thread")]
async fn exports_apply_the_restore_part_caps() {
    use picket_core::config::{model::ClientDef, store, validate};
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    let tags: Vec<String> = (0..4096).map(|i| format!("{i:064}")).collect();
    let clients: Vec<ClientDef> = (0..65)
        .map(|i| ClientDef {
            name: format!("client-{i}"),
            source_ips: vec![format!("192.168.1.{}/32", i + 1).parse().unwrap()],
            tags: tags.clone(),
            ..Default::default()
        })
        .collect();
    let mut model = a.state.config.model().await.unwrap();
    model.clients.extend(clients.clone());
    let issues = validate::validate(&model);
    assert!(
        issues
            .iter()
            .any(|i| i.severity == validate::Severity::Error && i.code == "too_large"),
        "validation refuses a configuration past the restore's cap"
    );
    // Written around validation (as an older release could have stored it).
    a.state
        .db
        .write(move |db| {
            let tx = db.transaction()?;
            for c in &clients {
                store::write_client(&tx, c)?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let r = ui(&a, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let t = r.text().await.unwrap();
    assert!(t.contains("configuration"), "{t}");
}

/// README §2 Bounded: one export and one restore at a time (409 while one runs), and neither
/// starts without room for it on the data disk (507).
#[tokio::test(flavor = "multi_thread")]
async fn exports_and_restores_run_one_at_a_time_with_room_on_disk() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    let (_, doc) = export(&a).await;
    let slot = a.state.restore.begin_export().expect("no export runs");
    let r = ui(&a, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    drop(slot);
    export(&a).await;
    let slot = a.state.restore.begin_restore().expect("no restore runs");
    assert_eq!(restore(&a, &doc).await.status(), StatusCode::CONFLICT);
    drop(slot);
    // A data disk without room for the job and the margin.
    a.state.restore.set_margins(u64::MAX / 4, u64::MAX / 4);
    let r = ui(&a, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(restore(&a, &doc).await.status(), StatusCode::INSUFFICIENT_STORAGE);
    // A small job leaves a margin of its own size, the floor here, not the cap (final check,
    // round 3): it runs with less free than the cap.
    let free = picket_core::run::disk_space(a.dir.path()).unwrap().0;
    a.state.restore.set_margins(1 << 20, free + (1 << 30));
    export(&a).await;
    let r = restore(&a, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    a.state.restore.set_margins(
        picket_core::config::export::DISK_MARGIN_FLOOR,
        picket_core::config::export::DISK_MARGIN,
    );
    let r = restore(&a, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert!(a.state.restore.begin_export().is_some());
    assert!(a.state.restore.begin_restore().is_some());
}

// ---------------------------------------------------------------------------------------------
// Final check (round 3)

/// README §2 Compatibility, Untrusted input; api.md §7: the previous format's single-string
/// manual file is read as JSON reads it. JSON's escapes decode (`\/` is `/`, `A` is `A`),
/// so such a file restores; an escape JSON doesn't have (`\Q`) leaves the document malformed
/// (`422`), never a base64 character.
#[tokio::test(flavor = "multi_thread")]
async fn a_previous_format_file_string_reads_json_escapes_only() {
    use base64::Engine;
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    put_entity(
        &a,
        "feeds",
        "esc",
        json!({"id": "esc", "name": "esc", "format": "plain"}),
    )
    .await;
    save(&a, "esc", "x.example\n").await;
    let (_, mut doc) = export(&a).await;
    let text = "Allowed.example\n???\n";
    let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    assert!(b64.contains('/') && b64.starts_with('Q'), "{b64}");
    for m in doc["manual_files"].as_array_mut().unwrap() {
        if m["feed"] == json!("esc") {
            m["file"] = json!(b64);
        }
    }
    let plain = serde_json::to_string(&doc).unwrap();
    let field = format!(r#""file":"{b64}""#);
    assert!(plain.contains(&field));
    let put = |c: &Core, body: String| {
        ui(c, Method::PUT, "/config/export")
            .header("content-type", "application/json")
            .body(body)
            .send()
    };
    // Valid escapes: the same file.
    let escaped = format!(r#""file":"Q{}""#, b64[1..].replace('/', r"\/"));
    let b = core_with(&srv).await;
    let r = put(&b, plain.replace(&field, &escaped)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    let blob: String = b
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT blob FROM manual_files WHERE feed_id = 'esc'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(blob, picket_api::ids::object_id(text.as_bytes()), "the same file");
    // An escape JSON doesn't have (`\Q`: without its backslash, the same valid base64), and a
    // `u` escape with a digit that isn't hex: malformed.
    for bad in [
        format!(r#""file":"\Q{}""#, &b64[1..]),
        format!(r#""file":"\u00G1{b64}""#),
    ] {
        let body = plain.replace(&field, &bad);
        assert!(serde_json::from_str::<Value>(&body).is_err());
        let c = core_with(&srv).await;
        let r = put(&c, body).await.unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{bad}: {}",
            r.text().await.unwrap()
        );
        assert_eq!(
            q_i64(&c, "SELECT count(*) FROM feeds WHERE id = 'esc'").await,
            0,
            "nothing restored"
        );
    }
}

/// core.md §2 (what the document holds), README §2 Bounded: a provider's listing stays out of
/// the export, since the restore clears each provider's module state, so its first check lists
/// again. A listing as large as a module may store (a GitHub tree of 200,000 paths, past the
/// restore's 32 MiB `feed_state.providers` cap) never keeps the user from exporting.
#[tokio::test(flavor = "multi_thread")]
async fn provider_listings_stay_out_of_the_export() {
    let (srv, _body) = server().await;
    let a = populated(&srv).await;
    let files: Vec<String> = (0..200_000)
        .map(|i| {
            format!(
                "lists/category-{:03}/source-{i:06}/{}.txt",
                i % 500,
                "x".repeat(130)
            )
        })
        .collect();
    let listing = serde_json::to_string(&json!({"files": files, "whole": true})).unwrap();
    assert!(listing.len() > 32 << 20);
    a.state
        .db
        .write(move |db| {
            let n = db.execute(
                "UPDATE feed_provider_state SET listing_json = ?1, k = 2.5 WHERE provider_id = 'p'",
                [&listing],
            )?;
            assert_eq!(n, 1);
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let (text, doc) = export(&a).await;
    assert!(!text.contains("category-000"));
    let providers = doc["feed_state"]["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(
        providers[0],
        json!({"provider": "p", "k": 2.5}),
        "its k, not its listing"
    );
    let b = core_with(&srv).await;
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(
        q_i64(
            &b,
            "SELECT count(*) FROM feed_provider_state WHERE provider_id = 'p' AND listing_json IS NULL"
        )
        .await,
        1
    );
    // An older document's listing is still restored.
    let mut older = doc.clone();
    older["feed_state"]["providers"][0]["listing"] = json!({"files": ["l.txt"], "whole": true});
    let c = core_with(&srv).await;
    let r = restore(&c, &older).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(
        q_i64(
            &c,
            "SELECT count(*) FROM feed_provider_state WHERE provider_id = 'p' AND listing_json LIKE '%l.txt%'"
        )
        .await,
        1
    );
}

/// README §2 Bounded: a restore upload that stalls is ended (`408`), giving the restore's slot
/// back, so the next restore runs instead of getting `409`.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_upload_gives_the_restore_slot_back() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    let (text, doc) = export(&a).await;
    a.state
        .restore
        .set_stream_idle(std::time::Duration::from_millis(500));
    // Half the document, then nothing.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(1);
    tx.send(Ok(text.as_bytes()[..text.len() / 2].to_vec()))
        .await
        .unwrap();
    let body = reqwest::Body::wrap_stream(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|c| (c, rx))
    }));
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        ui(&a, Method::PUT, "/config/export")
            .header("content-type", "application/json")
            .body(body)
            .send(),
    )
    .await
    .expect("the stalled upload is ended")
    .unwrap();
    assert_eq!(r.status(), StatusCode::REQUEST_TIMEOUT);
    let r = restore(&a, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    drop(tx);
}

// ---------------------------------------------------------------------------------------------
// Final check 2

/// core.md §2 "Export and restore" (step 3: the running parts reload; "a failed restore changes
/// nothing", so a committed one finishes), README §2 Restarts: a restore whose client goes away
/// after the commit (a closed tab, a proxy timeout) still runs to its end: the old log
/// partitions and metrics are emptied (log batches are taken again) and the running parts reload.
/// `metrics.db`'s writer is held so the restore waits in emptying it, after the commit, while the
/// client goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_whose_client_goes_runs_to_its_end() {
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    manual_feed(&a, "m1", json!({"category": "security"})).await;
    save(&a, "m1", "||ads.example^\n").await;
    let (text, _) = export(&a).await;
    let b = core_with(&srv).await;
    let before = b.state.restore.generation();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let stall = {
        let db = b.state.metrics_db.clone();
        tokio::spawn(async move {
            db.write(move |_| {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap()
        })
    };
    started_rx.await.unwrap();
    let put = tokio::spawn(
        ui(&b, Method::PUT, "/config/export")
            .header("content-type", "application/json")
            .body(text)
            .send(),
    );
    wait_until("the restore's commit", || async {
        b.state.restore.generation() > before
    })
    .await;
    assert!(b.state.restore.logs_pending(), "the logs aren't emptied yet");
    // The client goes; the server sees its connection close.
    put.abort();
    let _ = put.await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    release_tx.send(()).unwrap();
    stall.await.unwrap();
    wait_until("the restore's end", || async {
        !b.state.restore.logs_pending() && b.state.restore.begin_restore().is_some()
    })
    .await;
    assert_eq!(q_i64(&b, "SELECT count(*) FROM restore_pending").await, 0);
    wait_until("the restored manual feed's run", || async {
        q_i64(
            &b,
            "SELECT count(*) FROM feed_runs WHERE feed_id = 'm1' AND status = 'applied'",
        )
        .await
            >= 1
    })
    .await;
}

/// Opens the FIFO at its path for reading and writing when dropped (which never blocks on Linux),
/// so a reader waiting for a writer goes on even when the test fails first.
struct Unblock(std::path::PathBuf);

impl Drop for Unblock {
    fn drop(&mut self) {
        let _ = std::fs::OpenOptions::new().read(true).write(true).open(&self.0);
    }
}

/// The staged export files of the core with data directory `data_dir` this process has open
/// (other tests' cores run in the same process).
fn open_staged_exports(data_dir: &std::path::Path) -> usize {
    let staging = std::fs::canonicalize(data_dir.join("staging")).unwrap();
    let prefix = format!("{}/export-", staging.display());
    std::fs::read_dir("/proc/self/fd")
        .map(|d| {
            d.filter_map(Result::ok)
                .filter_map(|e| std::fs::read_link(e.path()).ok())
                .filter(|p| p.to_string_lossy().starts_with(&prefix))
                .count()
        })
        .unwrap_or(0)
}

/// README §2 Bounded (one export at a time, each leaving its margin; a job's slot, staged file
/// and disk space go back when it ends): an export whose client goes away while core writes it
/// (the UI's Cancel, a closed tab) keeps its slot until the write has stopped, so no second
/// export runs alongside it; and the write stops at its next chunk instead of writing on. The
/// manual feed's blob (more than one chunk) is made a FIFO, so the write waits in reading it; the
/// test then gives it only the first chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_export_whose_client_goes_keeps_its_slot_until_the_write_stops() {
    use picket_core::config::export::CHUNK_BYTES;
    let (srv, _) = server().await;
    let a = core_with(&srv).await;
    manual_feed(&a, "m1", json!({"category": "security"})).await;
    let line = format!("! {}\n", "x".repeat(97));
    let text: String = (0..(CHUNK_BYTES * 3 / 2) / line.len())
        .map(|_| line.as_str())
        .collect();
    save(&a, "m1", &text).await;
    let blob = {
        let s = "SELECT blob FROM manual_files WHERE feed_id = 'm1'".to_string();
        a.state
            .db
            .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&s, [], |r| r.get::<_, String>(0))?))
            .await
            .unwrap()
    };
    let path = picket_core::blobs::path(&a.state.data_dir, &blob).unwrap();
    let content = std::fs::read(&path).unwrap();
    assert!(content.len() > CHUNK_BYTES);
    std::fs::remove_file(&path).unwrap();
    let made = std::process::Command::new("mkfifo").arg(&path).status().unwrap();
    assert!(made.success());
    let _unblock = Unblock(path.clone());
    // The client gives up while core waits on the blob.
    let gave_up = ui(&a, Method::GET, "/config/export")
        .timeout(std::time::Duration::from_secs(1))
        .send()
        .await;
    assert!(gave_up.is_err(), "the export is still being written");
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            a.state.restore.begin_export().is_none(),
            "the slot is held while the export is written"
        );
    }
    let r = ui(&a, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT, "no second export alongside");
    // The blob's first chunk arrives, the rest never does: the write stops at that chunk (its
    // client is gone), giving the slot back.
    let (fifo, first) = (path.clone(), content[..CHUNK_BYTES].to_vec());
    let feeding = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        f.write_all(&first).unwrap();
        f
    });
    wait_until("the export's slot back", || async {
        a.state.restore.begin_export().is_some()
    })
    .await;
    let fed = feeding.await.unwrap();
    assert_eq!(
        open_staged_exports(&a.state.data_dir),
        0,
        "no staged export left open"
    );
    let staged: Vec<_> = std::fs::read_dir(a.state.data_dir.join("staging"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("export-"))
        .collect();
    assert!(staged.is_empty(), "no staged export left: {staged:?}");
    drop(fed);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, &content).unwrap();
    let (_, doc) = export(&a).await;
    assert!(doc.to_string().contains("m1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn declared_web_addresses_survive_export_and_restore() {
    let a = common::start_core(Some(
        json!({"web": {"tls": "off", "addresses": ["192.168.88.8", "fd00::8"]}}),
    ))
    .await;
    let (_, mut doc) = export(&a).await;
    assert_eq!(
        doc["configuration"]["settings"]["web.addresses"],
        json!(["192.168.88.8", "fd00::8"])
    );
    doc["configuration"]["settings"]["web.addresses"] =
        json!(["::ffff:192.168.88.8", "192.168.88.8", "fd00::8"]);
    let b = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let r = restore(&b, &doc).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(b.state.settings().web.addresses, ["192.168.88.8", "fd00::8"]);
    let (_, restored) = export(&b).await;
    assert_eq!(
        restored["configuration"]["settings"]["web.addresses"],
        json!(["192.168.88.8", "fd00::8"])
    );
}
