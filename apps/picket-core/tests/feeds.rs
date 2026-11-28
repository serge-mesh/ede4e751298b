//! Feeds end to end (build-and-test.md §5 rows "Formats", "Feed modes", "Rule policy",
//! "Providers", "Manual feeds", "Scheduler"): a running core with download providers pointed at
//! a local HTTPS server, the UI API, the ingest and its gates, `rule_policy`, presets, alerts and
//! the undo of a run that didn't finish.

use crate::common;

use std::io::Write as _;
use std::sync::{Arc, Mutex};

use common::feeds::{check_now, create_feed, ui, update_feed, url, wait_until};
use common::{Core, client};
use jiff::Timestamp;
use picket_core::modules::download::testkit::{Reply, Seen, TestServer};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const HOST: &str = "lists.example";

async fn core_with(srv: Option<&TestServer>, patch: Option<Value>) -> Core {
    let mut p = json!({"web": {"tls": "off"}});
    if let Some(extra) = patch
        && let (Some(a), Some(b)) = (p.as_object_mut(), extra.as_object())
    {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
    common::start_core_with(
        Some(p),
        picket_core::run::StartOptions {
            release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
            feed_http: srv.map(|s| s.http_options()).unwrap_or_default(),
            ..Default::default()
        },
    )
    .await
}

async fn get_json(c: &Core, path: &str) -> Value {
    let r = client()
        .get(url(c, path))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{path}");
    r.json().await.unwrap()
}

async fn count(c: &Core, sql: &'static str, feed: &str) -> i64 {
    let f = feed.to_string();
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(sql, [f], |r| r.get::<_, i64>(0))?))
        .await
        .unwrap()
}

async fn runs(c: &Core, feed: &str) -> i64 {
    count(c, "SELECT count(*) FROM feed_runs WHERE feed_id = ?1", feed).await
}

async fn checks(c: &Core, feed: &str) -> i64 {
    count(
        c,
        "SELECT count(*) FROM feed_checks WHERE feed_id = ?1 AND method <> 'bootstrap'",
        feed,
    )
    .await
}

async fn open_keys(c: &Core, feed: &str) -> Vec<String> {
    let f = feed.to_string();
    c.state
        .db
        .read(move |db| {
            let mut st = db.prepare(
                "SELECT rule_type || ':' || key FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NULL ORDER BY 1",
            )?;
            let v = st
                .query_map([f], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap()
}

/// The newest run: (status, kind, gate, added, removed, total).
async fn newest_run(c: &Core, feed: &str) -> Value {
    let v = get_json(c, &format!("/feeds/{feed}/runs?limit=1")).await;
    v["items"][0].clone()
}

async fn alert_state(c: &Core, key: &str) -> Option<String> {
    c.state.alerts.get_by_key(key).await.unwrap().map(|a| {
        serde_json::to_value(a.state)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    })
}

/// A server whose list body tests change.
async fn list_server() -> (TestServer, Arc<Mutex<String>>) {
    let body = Arc::new(Mutex::new(String::new()));
    let b = body.clone();
    let srv = TestServer::start(&[HOST], move |_s: &Seen| Reply::ok(b.lock().unwrap().clone())).await;
    (srv, body)
}

fn names(prefix: &str, n: usize) -> String {
    (0..n).map(|i| format!("{prefix}{i}.example\n")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn replace_mode_diffs_and_change_ratio_hold() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 200);
    create_feed(
        &c,
        json!({"id": "list", "name": "List", "provider": "http", "provider_config": {"url": format!("https://{HOST}/list.txt")}, "format": "plain"}),
    )
    .await;
    // The new feed is due at once.
    wait_until("the first run", || async {
        runs(&c, "list").await >= 1 && !c.state.feeds.is_busy("list")
    })
    .await;
    let r = newest_run(&c, "list").await;
    assert_eq!(r["status"], "applied", "{r}");
    assert_eq!(r["added"]["dns"], 200);
    assert_eq!(open_keys(&c, "list").await.len(), 200);

    // 10 out, 10 in: within max(0.5 × 200, 100).
    *body.lock().unwrap() = format!("{}{}", names("a", 190), names("b", 10));
    check_now(&c, "list").await;
    let r = newest_run(&c, "list").await;
    assert_eq!(
        (
            r["status"].as_str(),
            r["added"]["dns"].as_u64(),
            r["removed"]["dns"].as_u64()
        ),
        (Some("applied"), Some(10), Some(10)),
        "{r}"
    );
    assert_eq!(r["total"]["dns"], 200);
    let closed = count(
        &c,
        "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NOT NULL",
        "list",
    )
    .await;
    assert_eq!(closed, 10, "closed rows stay for replay");

    // The same body again: unchanged, no run; the newest run is confirmed.
    let n = runs(&c, "list").await;
    check_now(&c, "list").await;
    assert_eq!(runs(&c, "list").await, n);
    assert!(newest_run(&c, "list").await["confirmed_at"].is_string());

    // A whole new list: 400 changes, over the limit → held, the applied set stays.
    *body.lock().unwrap() = names("z", 200);
    check_now(&c, "list").await;
    let held = newest_run(&c, "list").await;
    assert_eq!(held["status"], "held", "{held}");
    assert_eq!(held["gate"], "change_ratio");
    assert!(open_keys(&c, "list").await.iter().any(|k| k.contains("a0")));
    assert_eq!(alert_state(&c, "feed_held:list").await.as_deref(), Some("open"));
    let st = get_json(&c, "/feeds/list/status").await;
    assert_eq!(st["held_run"], held["id"]);

    // A newer run within the limit of the applied one is applied; the held run is rejected.
    *body.lock().unwrap() = format!("{}{}", names("a", 195), names("c", 5));
    check_now(&c, "list").await;
    let r = newest_run(&c, "list").await;
    assert_eq!(r["status"], "applied", "{r}");
    let old = get_json(&c, &format!("/feeds/list/runs/{}", held["id"])).await;
    assert_eq!(old["run"]["status"], "rejected");
    assert_eq!(old["run"]["gate"], "superseded");
    assert_eq!(
        alert_state(&c, "feed_held:list").await.as_deref(),
        Some("resolved")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn held_run_confirmed_after_confirm_after() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 50);
    create_feed(
        &c,
        json!({"id": "conf", "name": "Conf", "provider": "http", "provider_config": {"url": format!("https://{HOST}/c.txt")},
               "format": "plain", "sanity": {"max_change_ratio": 0.1, "min_change_allowance": 5, "confirm_after": "1h"}}),
    )
    .await;
    wait_until("the first run", || async {
        runs(&c, "conf").await >= 1 && !c.state.feeds.is_busy("conf")
    })
    .await;
    *body.lock().unwrap() = names("b", 50);
    check_now(&c, "conf").await;
    let held = newest_run(&c, "conf").await;
    assert_eq!(held["status"], "held");
    // Before confirm_after: an unchanged check confirms nothing.
    check_now(&c, "conf").await;
    assert_eq!(newest_run(&c, "conf").await["status"], "held");
    // Once confirm_after has passed (moved back here), the next check that finds the source
    // still serving it applies it.
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_state SET held_since = '2020-01-01T00:00:00.000000Z' WHERE feed_id = 'conf'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    check_now(&c, "conf").await;
    wait_until("the confirmation", || async { !c.state.feeds.is_busy("conf") }).await;
    let r = get_json(&c, &format!("/feeds/conf/runs/{}", held["id"])).await;
    assert_eq!(r["run"]["status"], "applied", "{r}");
    assert!(
        open_keys(&c, "conf")
            .await
            .iter()
            .all(|k| k.contains(":example.b")),
        "the held entries are applied"
    );
    assert_eq!(
        alert_state(&c, "feed_held:conf").await.as_deref(),
        Some("resolved")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_extreme_drop_is_rejected_not_held() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 200);
    let def = json!({"id": "drop", "name": "Drop", "provider": "http", "provider_config": {"url": format!("https://{HOST}/d.txt")},
                     "format": "plain"});
    create_feed(&c, def.clone()).await;
    wait_until("the first run", || async {
        runs(&c, "drop").await >= 1 && !c.state.feeds.is_busy("drop")
    })
    .await;
    assert_eq!(newest_run(&c, "drop").await["status"], "applied");

    // 200 → 1 (99.5 %): rejected, never held for confirm_after; the applied set stays.
    *body.lock().unwrap() = names("a", 1);
    check_now(&c, "drop").await;
    let r = newest_run(&c, "drop").await;
    assert_eq!(
        (r["status"].as_str(), r["gate"].as_str()),
        (Some("rejected"), Some("drop")),
        "{r}"
    );
    assert_eq!(open_keys(&c, "drop").await.len(), 200);
    assert_eq!(alert_state(&c, "feed_held:drop").await.as_deref(), Some("open"));
    assert!(get_json(&c, "/feeds/drop/status").await["held_run"].is_null());

    // Turning the gate off judges the rejected run again: the change-ratio gate holds it.
    let mut off = def.clone();
    off["sanity"] = json!({"reject_drop_ratio": null});
    update_feed(&c, "drop", off).await;
    wait_until("the re-gate", || async {
        newest_run(&c, "drop").await["status"] == "held"
    })
    .await;
    assert_eq!(newest_run(&c, "drop").await["gate"], "change_ratio");
    assert_eq!(open_keys(&c, "drop").await.len(), 200);

    // With the gate back on, the source recovering is applied and resolves feed_held.
    update_feed(&c, "drop", def).await;
    wait_until("the re-gate", || async {
        newest_run(&c, "drop").await["status"] == "rejected" && !c.state.feeds.is_busy("drop")
    })
    .await;
    *body.lock().unwrap() = format!("{}{}", names("a", 195), names("c", 5));
    check_now(&c, "drop").await;
    let r = newest_run(&c, "drop").await;
    assert_eq!(r["status"], "applied", "{r}");
    assert_eq!(open_keys(&c, "drop").await.len(), 200);
    assert_eq!(
        alert_state(&c, "feed_held:drop").await.as_deref(),
        Some("resolved")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reject_gates_parse_errors_and_entry_counts() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = format!("{}not a name at all\n{}", names("a", 10), "bad..name\n".repeat(5));
    create_feed(
        &c,
        json!({"id": "bad", "name": "Bad", "provider": "http", "provider_config": {"url": format!("https://{HOST}/b.txt")}, "format": "plain"}),
    )
    .await;
    wait_until("the first run", || async {
        runs(&c, "bad").await >= 1 && !c.state.feeds.is_busy("bad")
    })
    .await;
    let r = newest_run(&c, "bad").await;
    assert_eq!(
        (r["status"].as_str(), r["gate"].as_str()),
        (Some("rejected"), Some("parse_errors")),
        "{r}"
    );
    assert!(
        open_keys(&c, "bad").await.is_empty(),
        "a rejected run is never applied"
    );
    assert!(!r["parse"]["error_samples"].as_array().unwrap().is_empty());
    assert_eq!(alert_state(&c, "feed_held:bad").await.as_deref(), Some("open"));
    // The provider's last moved on: the same file isn't run again.
    let n = runs(&c, "bad").await;
    check_now(&c, "bad").await;
    assert_eq!(runs(&c, "bad").await, n);

    // Editing sanity judges the newest rejected run again.
    update_feed(
        &c,
        "bad",
        json!({"name": "Bad", "provider": "http", "provider_config": {"url": format!("https://{HOST}/b.txt")}, "format": "plain",
               "sanity": {"max_parse_error_ratio": 0.5}}),
    )
    .await;
    // The diff's entries show before the run's row is final (another heavy job, such as a bundle
    // build, may run between the two steps): wait for both.
    wait_until("the re-gate", || async {
        open_keys(&c, "bad").await.len() == 10 && newest_run(&c, "bad").await["status"] == "applied"
    })
    .await;

    // Entry limits.
    update_feed(
        &c,
        "bad",
        json!({"name": "Bad", "provider": "http", "provider_config": {"url": format!("https://{HOST}/b.txt")}, "format": "plain",
               "sanity": {"max_parse_error_ratio": 0.5, "min_entries": 50}}),
    )
    .await;
    *body.lock().unwrap() = names("q", 20);
    check_now(&c, "bad").await;
    let r = newest_run(&c, "bad").await;
    assert_eq!(
        (r["status"].as_str(), r["gate"].as_str()),
        (Some("rejected"), Some("entries")),
        "{r}"
    );
    assert_eq!(open_keys(&c, "bad").await.len(), 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn aggregate_mode_expiry_drop_mode_and_first_seen() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    c.state.clock.pin(true);
    *body.lock().unwrap() = "! picket-first-seen: 2021-06-01\nold.example\nnew.example\n10.0.0.0/8\n".into();
    create_feed(
        &c,
        json!({"id": "agg", "name": "Agg", "provider": "http", "provider_config": {"url": format!("https://{HOST}/a.txt")},
               "format": "plain", "modes": {"dns": {"mode": "aggregate", "expire_after": "1h"}, "ip": {"mode": "drop"}}}),
    )
    .await;
    wait_until("the first run", || async {
        runs(&c, "agg").await >= 1 && !c.state.feeds.is_busy("agg")
    })
    .await;
    assert_eq!(
        open_keys(&c, "agg").await,
        vec!["dns:example.new", "dns:example.old"],
        "ip is a drop type"
    );
    let fs: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT first_seen_at FROM feed_entries WHERE key = 'example.old'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(fs.starts_with("2021-06-01"), "{fs}");
    // The next download misses old.example: aggregate keeps it, marked dropped; a later date
    // in a directive never moves first_seen later.
    *body.lock().unwrap() = "! picket-first-seen: 2025-01-01\nnew.example\nthird.example\n".into();
    check_now(&c, "agg").await;
    assert_eq!(open_keys(&c, "agg").await.len(), 3);
    let dropped = count(&c, "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND dropped_at IS NOT NULL AND removed_run IS NULL", "agg").await;
    assert_eq!(dropped, 1);
    // An hour after the first run without it, the sweep closes it under an `expired` run.
    c.state
        .db
        .write(|db| {
            db.execute("UPDATE feed_entries SET dropped_at = '2020-01-01T00:00:00.000000Z' WHERE dropped_at IS NOT NULL", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    picket_core::feeds::sweep_expired(&c.state);
    wait_until("the sweep", || async {
        open_keys(&c, "agg").await.len() == 2 && !c.state.feeds.is_busy("agg")
    })
    .await;
    let r = newest_run(&c, "agg").await;
    assert_eq!(
        (r["status"].as_str(), r["kind"].as_str()),
        (Some("expired"), Some("expire")),
        "{r}"
    );
    assert!(r["blob"].is_null());
    assert_eq!(r["removed"]["dns"], 1);
    // It comes back if the source lists it again (and its dropped mark clears on return).
    *body.lock().unwrap() = "new.example\nthird.example\nold.example\n".into();
    check_now(&c, "agg").await;
    assert_eq!(open_keys(&c, "agg").await.len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_policy_drop_keep_and_switching() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = "0.0.0.0 block.example\n192.0.2.7 redirect.example\n".into();
    create_feed(
        &c,
        json!({"id": "hosts", "name": "Hosts", "provider": "http", "provider_config": {"url": format!("https://{HOST}/h.txt")}, "format": "hosts"}),
    )
    .await;
    wait_until("the first run", || async {
        runs(&c, "hosts").await >= 1 && !c.state.feeds.is_busy("hosts")
    })
    .await;
    assert_eq!(
        open_keys(&c, "hosts").await,
        vec!["dns:example.block"],
        "a downloaded feed drops redirects"
    );
    let r = newest_run(&c, "hosts").await;
    assert_eq!(r["policy_dropped"]["redirects"], 1);
    assert_eq!(
        alert_state(&c, "feed_rules_dropped:hosts").await.as_deref(),
        Some("open")
    );
    let drops = get_json(&c, "/feeds/hosts/policy-drops").await;
    assert_eq!(drops["items"][0]["raw"], "192.0.2.7 redirect.example");
    // Switching to keep re-ingests the latest applied blob: the redirect comes in, and a
    // downloaded feed that keeps redirects and adds one alerts.
    let base = json!({"name": "Hosts", "provider": "http", "provider_config": {"url": format!("https://{HOST}/h.txt")}, "format": "hosts"});
    let mut keep = base.clone();
    keep["rule_policy"] = json!({"redirects": "keep"});
    let n = runs(&c, "hosts").await;
    update_feed(&c, "hosts", keep).await;
    wait_until("the re-ingest", || async {
        runs(&c, "hosts").await > n && !c.state.feeds.is_busy("hosts")
    })
    .await;
    assert_eq!(open_keys(&c, "hosts").await.len(), 2);
    let r = newest_run(&c, "hosts").await;
    assert_eq!(r["kind"], "reingest");
    assert_eq!(
        alert_state(&c, "feed_redirect_added:hosts").await.as_deref(),
        Some("open")
    );
    // And back to drop: the open redirect entry is closed under a new run.
    let mut drop = base.clone();
    drop["rule_policy"] = json!({"redirects": "drop"});
    let n = runs(&c, "hosts").await;
    update_feed(&c, "hosts", drop).await;
    wait_until("the policy run", || async {
        runs(&c, "hosts").await > n && !c.state.feeds.is_busy("hosts")
    })
    .await;
    assert_eq!(open_keys(&c, "hosts").await.len(), 1);
    // Manual feeds keep all three by default.
    create_feed(
        &c,
        json!({"id": "m", "name": "M", "provider": "manual", "format": "hosts"}),
    )
    .await;
    let f = get_json(&c, "/feeds/m").await;
    assert_eq!(
        f["rule_policy"],
        json!({"redirects": "keep", "client_rules": "keep", "browser_changes": "keep"})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_policy_client_rules_and_browser_changes() {
    let c = core_with(None, None).await;
    let text = "||plain.example^\n||kid.example^$client=kid\nexample.org##.ad\nexample.org##+js(nobab)\n";
    // Dropping both options on a manual adblock feed with browser rules stored.
    create_feed(
        &c,
        json!({"id": "pol", "name": "Pol", "provider": "manual", "format": "adblock",
               "modes": {"browser": {"mode": "replace"}},
               "rule_policy": {"client_rules": "drop", "browser_changes": "drop"}}),
    )
    .await;
    assert_eq!(put_file(&c, "pol", text, None).await.status(), StatusCode::OK);
    wait_until("the run", || async {
        runs(&c, "pol").await == 1 && !c.state.feeds.is_busy("pol")
    })
    .await;
    let keys = open_keys(&c, "pol").await;
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert!(keys.iter().any(|k| k == "dns:example.plain") && keys.iter().any(|k| k.starts_with("browser:")));
    let r = newest_run(&c, "pol").await;
    assert_eq!(
        (
            r["policy_dropped"]["client_rules"].as_u64(),
            r["policy_dropped"]["browser_changes"].as_u64()
        ),
        (Some(1), Some(1)),
        "{r}"
    );
    // Whole rules only: the $client rule never became a rule for every client.
    assert!(!keys.iter().any(|k| k.contains("kid")));
    // Keep both: re-ingested, all four are in.
    let n = runs(&c, "pol").await;
    update_feed(
        &c,
        "pol",
        json!({"name": "Pol", "provider": "manual", "format": "adblock", "modes": {"browser": {"mode": "replace"}},
               "rule_policy": {"client_rules": "keep", "browser_changes": "keep"}}),
    )
    .await;
    wait_until("the re-ingest", || async {
        runs(&c, "pol").await > n && !c.state.feeds.is_busy("pol")
    })
    .await;
    assert_eq!(open_keys(&c, "pol").await.len(), 4);
    // browser_changes has no effect while browser is drop: nothing browser is stored or counted.
    let n = runs(&c, "pol").await;
    update_feed(
        &c,
        "pol",
        json!({"name": "Pol", "provider": "manual", "format": "adblock", "modes": {"browser": {"mode": "drop"}},
               "rule_policy": {"client_rules": "keep", "browser_changes": "drop"}}),
    )
    .await;
    wait_until("the re-ingest", || async {
        runs(&c, "pol").await > n && !c.state.feeds.is_busy("pol")
    })
    .await;
    let keys = open_keys(&c, "pol").await;
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert!(
        newest_run(&c, "pol").await["policy_dropped"]
            .get("browser_changes")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn appends_to_hosts_and_adblock_manual_feeds() {
    let c = core_with(None, None).await;
    // One-click Block/Allow: lines appended to an adblock manual feed (manual-block exists).
    let r = ui(&c, Method::POST, "/feeds/manual-block/file/lines")
        .json(&json!({"lines": ["||clicked.example^"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("manual-block's run", || async {
        open_keys(&c, "manual-block")
            .await
            .contains(&"dns:example.clicked".to_string())
    })
    .await;
    let r = ui(&c, Method::POST, "/feeds/manual-allow/file/lines")
        .json(&json!({"lines": ["@@||allowed.example^"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("manual-allow's run", || async {
        open_keys(&c, "manual-allow")
            .await
            .contains(&"dns:example.allowed".to_string())
    })
    .await;
    // A script appending to a hosts feed (no file yet, no trailing newline issues).
    create_feed(
        &c,
        json!({"id": "h", "name": "H", "provider": "manual", "format": "hosts"}),
    )
    .await;
    assert_eq!(
        put_file(&c, "h", "0.0.0.0 first.example", None).await.status(),
        StatusCode::OK
    );
    let r = ui(&c, Method::POST, "/feeds/h/file/lines")
        .json(&json!({"lines": ["0.0.0.0 second.example", "192.0.2.1 mapped.example"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("the hosts runs", || async { open_keys(&c, "h").await.len() == 3 }).await;
    let file = get_json(&c, "/feeds/h/file").await;
    assert_eq!(
        file["content"], "0.0.0.0 first.example\n0.0.0.0 second.example\n192.0.2.1 mapped.example\n",
        "a newline first when the file lacks one"
    );
    // System feeds stay: lookup-exclude and canaries were pre-loaded and ingested at start.
    wait_until("canaries' run", || async {
        open_keys(&c, "canaries").await.len() == 3
    })
    .await;
}

async fn put_file(c: &Core, feed: &str, content: &str, base: Option<&str>) -> reqwest::Response {
    ui(c, Method::PUT, &format!("/feeds/{feed}/file"))
        .json(&json!({"content": content, "base_version": base}))
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn manual_feed_saves_appends_and_limits() {
    let c = core_with(None, Some(json!({"feeds": {"max_download_mib": 1}}))).await;
    create_feed(
        &c,
        json!({"id": "mine", "name": "Mine", "provider": "manual", "format": "plain"}),
    )
    .await;
    // A save with base_version null while the feed has no file.
    let r = put_file(&c, "mine", "one.example\n10.1.0.0/16\n", None).await;
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    let v1 = v["version"].as_str().unwrap().to_string();
    assert_eq!(v["changed"], true);
    wait_until("the save's run", || async {
        runs(&c, "mine").await == 1 && !c.state.feeds.is_busy("mine")
    })
    .await;
    assert_eq!(
        open_keys(&c, "mine").await,
        vec!["dns:example.one", "ip:10.1.0.0/16"]
    );
    // A stale base_version: 409, nothing changes.
    let r = put_file(&c, "mine", "x.example\n", None).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r = put_file(&c, "mine", "x.example\n", Some("0000")).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    // The same text: no run.
    let r = put_file(&c, "mine", "one.example\n10.1.0.0/16\n", Some(&v1)).await;
    let v: Value = r.json().await.unwrap();
    assert_eq!(
        (v["changed"].as_bool(), v["version"].as_str()),
        (Some(false), Some(v1.as_str()))
    );
    // Appends: a script adding hostnames, a first-seen directive included.
    let r = ui(&c, Method::POST, "/feeds/mine/file/lines")
        .json(&json!({"lines": ["! picket-first-seen: 2022-02-02", "two.example"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v2 = r.json::<Value>().await.unwrap()["version"]
        .as_str()
        .unwrap()
        .to_string();
    wait_until("the append's run", || async {
        runs(&c, "mine").await == 2 && !c.state.feeds.is_busy("mine")
    })
    .await;
    assert!(
        open_keys(&c, "mine")
            .await
            .contains(&"dns:example.two".to_string())
    );
    let file = get_json(&c, "/feeds/mine/file").await;
    assert_eq!(
        file["content"],
        "one.example\n10.1.0.0/16\n! picket-first-seen: 2022-02-02\ntwo.example\n"
    );
    assert_eq!(file["version"], v2);
    // A line with a break in it: 422, nothing changes.
    let r = ui(&c, Method::POST, "/feeds/mine/file/lines")
        .json(&json!({"lines": ["a.example\nb.example"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Past the size cap (1 MiB here): 413 for a save and for an append, nothing stored.
    let big = "x".repeat(1024 * 1024 + 10);
    let r = put_file(&c, "mine", &big, Some(&v2)).await;
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let r = ui(&c, Method::POST, "/feeds/mine/file/lines")
        .json(&json!({"lines": [big]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(get_json(&c, "/feeds/mine/file").await["version"], v2);
    // A gzip-compressed body.
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(
        json!({"content": "three.example\n", "base_version": v2})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let r = ui(&c, Method::PUT, "/feeds/mine/file")
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(gz.finish().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    wait_until("the gzip save's run", || async {
        open_keys(&c, "mine").await == vec!["dns:example.three".to_string()]
    })
    .await;
    // Manual feeds skip the change-ratio gate: everything replaced at once.
    assert_eq!(newest_run(&c, "mine").await["status"], "applied");
    // Not a manual feed: 422.
    create_feed(&c, json!({"id": "dl", "name": "Dl", "provider": "http", "enabled": false, "provider_config": {"url": "https://lists.example/x"}})).await;
    assert_eq!(
        put_file(&c, "dl", "x", None).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn misp_warninglist_and_adblock_types() {
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "wl", "name": "WL", "provider": "manual", "format": "misp-warninglist"}),
    )
    .await;
    let list = json!({"name": "Test", "type": "hostname", "list": ["cloudfront.net", "akamai.net"], "version": 1, "description": "x", "matching_attributes": ["hostname"]});
    assert_eq!(
        put_file(&c, "wl", &list.to_string(), None).await.status(),
        StatusCode::OK
    );
    wait_until("the warninglist run", || async {
        open_keys(&c, "wl").await.len() == 2
    })
    .await;
    create_feed(
        &c,
        json!({"id": "ab", "name": "AB", "provider": "manual", "format": "adblock", "modes": {"browser": {"mode": "replace"}}}),
    )
    .await;
    assert_eq!(
        put_file(
            &c,
            "ab",
            "||ads.example^\n||1.2.3.4^\nexample.org##.banner\n! comment\n",
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    wait_until("the adblock run", || async {
        open_keys(&c, "ab").await.len() == 3
    })
    .await;
    let keys = open_keys(&c, "ab").await;
    assert!(
        keys.iter().any(|k| k.starts_with("browser:")) && keys.iter().any(|k| k.starts_with("ip:")),
        "{keys:?}"
    );
    let wl = get_json(&c, "/warninglists").await;
    assert!(
        wl.as_array()
            .unwrap()
            .iter()
            .any(|b| b["bundle"] == "warn-common")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failing_checks_raise_feed_down_and_back_off() {
    let ok = Arc::new(Mutex::new(false));
    let o = ok.clone();
    let srv = TestServer::start(&[HOST], move |_s: &Seen| {
        if *o.lock().unwrap() {
            Reply::ok("a.example\n")
        } else {
            Reply::status(503)
        }
    })
    .await;
    let c = core_with(
        Some(&srv),
        Some(json!({"alerts": {"thresholds": {"feed_down": "0s", "feed_provider_down": "0s"}}})),
    )
    .await;
    create_feed(
        &c,
        json!({"id": "down", "name": "Down", "provider": "http", "provider_config": {"url": format!("https://{HOST}/d.txt")}}),
    )
    .await;
    wait_until("the failed check", || async {
        checks(&c, "down").await >= 1 && !c.state.feeds.is_busy("down")
    })
    .await;
    // The provider's only file failed: the whole provider failed, so feed_provider_down covers
    // it and the feed raises no feed_down (core.md §9).
    wait_until("feed_provider_down", || async {
        alert_state(&c, "feed_provider_down:down").await.as_deref() == Some("open")
    })
    .await;
    assert_eq!(alert_state(&c, "feed_down:down").await, None);
    let st = get_json(&c, "/feeds/down/status").await;
    assert_eq!(st["failures"], 1);
    // The backoff: the next check about a minute later at the soonest... and min_interval (2 m).
    let due = picket_api::time::parse(st["next_check"].as_str().unwrap()).unwrap();
    let last = picket_api::time::parse(st["last_check"].as_str().unwrap()).unwrap();
    assert!(due - last >= jiff::SignedDuration::from_mins(2), "{due} {last}");
    let ch = get_json(&c, "/feeds/down/checks").await;
    assert_eq!(ch["items"][0]["ok"], false);
    assert!(ch["items"][0]["error"].as_str().unwrap().contains("503"));
    *ok.lock().unwrap() = true;
    check_now(&c, "down").await;
    assert_eq!(
        alert_state(&c, "feed_provider_down:down").await.as_deref(),
        Some("resolved")
    );
    // Check now right after a check: held back by min_interval; a feed has no check route.
    let r = ui(&c, Method::POST, "/feed-providers/down/check")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["result"], "scheduled");
    let r = ui(&c, Method::POST, "/feeds/down/check")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "checks are per provider, never per feed"
    );
}

/// core.md §9: one file failing while the provider's other files work raises `feed_down` for
/// that feed (saying when the file is gone), not `feed_provider_down`.
#[tokio::test(flavor = "multi_thread")]
async fn one_file_failing_raises_feed_down_not_feed_provider_down() {
    // A provider of several files (`github`; an `http` provider is one URL): one goes, the
    // other stays.
    let (srv, repo) = common::github::fake().await;
    repo.lock()
        .unwrap()
        .set(1, &[("good.txt", "a.example\n"), ("gone.txt", "b.example\n")]);
    let c = core_with(
        Some(&srv),
        Some(json!({"alerts": {"thresholds": {"feed_down": "0s", "feed_provider_down": "0s"}}})),
    )
    .await;
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(
            &json!({"id": "two", "name": "Two", "module": "github", "config": {"owner": "o", "repo": "r"},
                      "files": [{"match": "*.txt", "feed": {"format": "plain"}}]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    // The first check lists and adds the feeds; the next one runs them.
    wait_until("the listing's feeds", || async {
        c.state.feeds.provider_feeds("two").len() == 2 && !c.state.feeds.is_checking("two")
    })
    .await;
    common::feeds::check_provider(&c, "two").await;
    wait_until("both feeds' first runs", || async {
        runs(&c, "two-good").await >= 1
            && runs(&c, "two-gone").await >= 1
            && !c.state.feeds.is_checking("two")
            && !c.state.feeds.is_busy("two-good")
            && !c.state.feeds.is_busy("two-gone")
    })
    .await;
    repo.lock().unwrap().set(2, &[("good.txt", "a.example\n")]);
    common::feeds::check_provider(&c, "two").await;
    wait_until("feed_down", || async {
        alert_state(&c, "feed_down:two-gone").await.as_deref() == Some("open")
    })
    .await;
    assert_eq!(alert_state(&c, "feed_provider_down:two").await, None);
    assert_eq!(alert_state(&c, "feed_down:two-good").await, None);
    let a = c
        .state
        .alerts
        .get_by_key("feed_down:two-gone")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.details["file_gone"], true, "{}", a.details);
    assert_eq!(a.feed_provider.as_deref(), Some("two"));
}

/// feeds.md §3 "Editing a feed provider": a new config clears the `last` of each of its feeds
/// and makes the next check a first check; the module checks the config at save time.
#[tokio::test(flavor = "multi_thread")]
async fn editing_the_provider_clears_last_and_checks_configs() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 3);
    create_feed(
        &c,
        json!({"id": "e", "name": "E", "provider": "http", "provider_config": {"url": format!("https://{HOST}/e.txt")}, "format": "plain"}),
    )
    .await;
    wait_until("the first run", || async {
        runs(&c, "e").await >= 1 && !c.state.feeds.is_busy("e")
    })
    .await;
    let last = |c: &Core| {
        let s = c.state.clone();
        async move {
            s.db.read(|db| {
                Ok::<_, anyhow::Error>(db.query_row(
                    "SELECT last_json FROM feed_state WHERE feed_id = 'e'",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )?)
            })
            .await
            .unwrap()
        }
    };
    assert!(last(&c).await.is_some());
    update_feed(
        &c,
        "e",
        json!({"name": "E", "provider": "http", "enabled": false, "provider_config": {"url": format!("https://{HOST}/other.txt")}, "format": "plain"}),
    )
    .await;
    assert!(last(&c).await.is_none(), "the next check is a first check");
    // Config checks at save time: HTTPS only, credentials as secrets.
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&json!({"id": "x", "name": "X", "module": "http", "config": {"url": "http://lists.example/x.txt"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&json!({"id": "x", "name": "X", "module": "github", "config": {"owner": "o", "repo": "r", "token": "ghp_literal"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // A provider feed comes only from its provider's files.
    let r = ui(&c, Method::POST, "/feeds")
        .json(&json!({"id": "y", "name": "Y", "provider": "e", "file": "y.txt"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let mods = get_json(&c, "/download-modules").await;
    let ids: Vec<&str> = mods
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["alphamountain_threat_1000", "github", "http"]);
    assert_eq!(mods[1]["lists_files"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_resolve_for_checks_and_never_show() {
    let srv = TestServer::start(&[HOST], |s: &Seen| {
        if s.header("x-api-key") == Some("sup3r-s3cret-value") {
            Reply::ok("a.example\n")
        } else {
            Reply::status(401)
        }
    })
    .await;
    let c = core_with(Some(&srv), None).await;
    let r = ui(&c, Method::PUT, "/secrets/listkey")
        .json(&json!({"value": "sup3r-s3cret-value"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    create_feed(
        &c,
        json!({"id": "s", "name": "S", "provider": "http", "format": "plain",
               "provider_config": {"url": format!("https://{HOST}/s.txt"), "headers": {"X-Api-Key": "${secret:listkey}"}}}),
    )
    .await;
    wait_until("the run", || async { runs(&c, "s").await >= 1 }).await;
    let p = get_json(&c, "/feed-providers/s").await;
    assert_eq!(p["config"]["headers"]["X-Api-Key"], "${secret:listkey}");
    let all = serde_json::to_string(&get_json(&c, "/feeds/s/checks").await).unwrap()
        + &serde_json::to_string(&get_json(&c, "/feed-providers/s/checks").await).unwrap()
        + &serde_json::to_string(&get_json(&c, "/feed-providers/s").await).unwrap();
    assert!(!all.contains("sup3r"));
}

/// R3 (README §2 JSON everywhere; core.md §12; api.md §7): Check now and a preset install read no
/// body. The JSON body a mutation carries is ignored when it is empty or malformed, never
/// answered with axum's plain-text `400`.
#[tokio::test(flavor = "multi_thread")]
async fn check_now_and_preset_installs_ignore_an_empty_or_malformed_body() {
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("a.example\n")).await;
    let c = core_with(Some(&srv), None).await;
    create_feed(
        &c,
        json!({"id": "b", "name": "B", "provider": "http", "provider_config": {"url": format!("https://{HOST}/b.txt")}}),
    )
    .await;
    for (path, status, field) in [
        ("/feed-providers/b/check", StatusCode::ACCEPTED, "result"),
        ("/feed-presets/private-ipv4", StatusCode::OK, "created"),
    ] {
        for body in ["", "{\"x\": "] {
            let r = ui(&c, Method::POST, path)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            let st = r.status();
            let ct = r
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let text = r.text().await.unwrap();
            assert_eq!(st, status, "{path} {body:?}: {text}");
            assert!(ct.starts_with("application/json"), "{path} {body:?}: {ct}");
            let v: Value = serde_json::from_str(&text).unwrap();
            assert!(v.get(field).is_some(), "{path} {body:?}: {text}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn presets_install_and_restore() {
    let c = core_with(None, None).await;
    let list = get_json(&c, "/feed-presets").await;
    assert_eq!(list.as_array().unwrap().len(), 7);
    let r = ui(&c, Method::POST, "/feed-presets/private-ipv4")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    wait_until("the preset's run", || async {
        open_keys(&c, "private-ipv4").await.len() == 7
    })
    .await;
    let b = get_json(&c, "/bundles/block-common").await;
    assert!(
        b["feeds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["feed"] == "private-ipv4")
    );
    // A lost file comes back on the next install; an existing one is left as edited.
    c.state
        .db
        .write(|db| {
            db.execute("DELETE FROM manual_files WHERE feed_id = 'private-ipv4'", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let r: Value = ui(&c, Method::POST, "/feed-presets/private-ipv4")
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        (
            r["created"].as_bool(),
            r["file_restored"].as_bool(),
            r["bundle_added"].as_bool()
        ),
        (Some(false), Some(true), Some(false))
    );
    assert_eq!(
        get_json(&c, "/feed-presets")
            .await
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["installed"] == true)
            .count(),
        1
    );
    // A provider preset: its provider and its feeds (each preset's files select just its own),
    // in the bundle; a deleted preset feed comes back on the next install.
    let r: Value = ui(&c, Method::POST, "/feed-presets/firehol-level1")
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["provider"], "firehol");
    assert_eq!(r["feeds"], json!(["firehol"]));
    // The preset names its feed (a provider feed is otherwise named after its file); the id
    // stays `<provider>-<file>`.
    assert_eq!(get_json(&c, "/feeds/firehol").await["name"], "FireHOL level 1");
    let b = get_json(&c, "/bundles/block-common").await;
    assert!(
        b["feeds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["feed"] == "firehol")
    );
    let r = ui(&c, Method::DELETE, "/feeds/firehol")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let st = r.status();
    assert_eq!(st, StatusCode::OK, "{}", r.text().await.unwrap());
    let p = get_json(&c, "/feed-providers/firehol").await;
    assert_eq!(p["exclude"], json!(["response"]));
    let r: Value = ui(&c, Method::POST, "/feed-presets/firehol-level1")
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["feeds"], json!(["firehol"]), "{r}");
    assert_eq!(
        get_json(&c, "/feed-providers/firehol").await["exclude"],
        json!([])
    );
    assert_eq!(
        get_json(&c, "/feeds/firehol").await["name"],
        "FireHOL level 1",
        "a restored preset feed is named too"
    );
    // The older release's OISD big (an http provider of https://big.oisd.nl/, as upgraded) is
    // the preset, installed: shown so, and installing it leaves it as it is and bundles its feed.
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(
            &json!({"id": "oisd-big", "name": "OISD big", "module": "http", "enabled": false,
                      "config": {"url": "https://big.oisd.nl/"}}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let installed = |presets: &Value, id: &str| {
        presets
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .unwrap()["installed"]
            .clone()
    };
    assert_eq!(installed(&get_json(&c, "/feed-presets").await, "oisd-big"), true);
    let r = ui(&c, Method::POST, "/feed-presets/oisd-big")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    assert_eq!(
        (v["provider"].as_str(), v["feeds"].clone()),
        (Some("oisd-big"), json!(["oisd-big"])),
        "{v}"
    );
    assert_eq!(get_json(&c, "/feed-providers/oisd-big").await["module"], "http");
    assert!(
        get_json(&c, "/bundles/block-common").await["feeds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["feed"] == "oisd-big")
    );
    // Another module's provider with a preset's id isn't merged into: refused, saying what to
    // do (ids never change, so not "rename"), and the preset isn't installed.
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(
            &json!({"id": "adguard", "name": "Mine", "module": "http", "enabled": false,
                      "config": {"url": "https://lists.example/adguard.txt"}}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let r = ui(&c, Method::POST, "/feed-presets/adguard-dns-filter")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let msg = r.json::<Value>().await.unwrap()["error"]["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        msg.contains("delete it first") && !msg.contains("rename"),
        "{msg}"
    );
    assert_eq!(
        installed(&get_json(&c, "/feed-presets").await, "adguard-dns-filter"),
        false
    );
    // A name the admin gave stays on the next install.
    let mut f = get_json(&c, "/feeds/firehol").await;
    f["name"] = json!("Mine");
    let r = ui(&c, Method::PUT, "/feeds/firehol")
        .json(&f)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    ui(&c, Method::POST, "/feed-presets/firehol-level1")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(get_json(&c, "/feeds/firehol").await["name"], "Mine");
    // A GitHub preset's feeds come with its first listing, named by the preset; installing it
    // again names a feed still on its default name, and keeps a name the admin gave.
    let r = ui(&c, Method::POST, "/feed-presets/hagezi")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_provider_state SET listing_json = ?1 WHERE provider_id = 'hagezi'",
                [r#"{"files": ["adblock/tif.txt", "adblock/ultimate.txt"], "whole": true}"#],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    // The listing applied (as a check that listed applies it): the provider saved as it is.
    let hz = get_json(&c, "/feed-providers/hagezi").await;
    let r = ui(&c, Method::PUT, "/feed-providers/hagezi")
        .json(&hz)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let name = |id: &'static str| {
        let c = &c;
        async move { get_json(c, &format!("/feeds/{id}")).await["name"].clone() }
    };
    assert_eq!(
        name("hagezi-adblock-tif").await,
        "HaGeZi Threat Intelligence Feeds"
    );
    assert_eq!(name("hagezi-adblock-ultimate").await, "HaGeZi Multi ULTIMATE");
    for (id, n) in [
        ("hagezi-adblock-tif", "adblock/tif.txt"),
        ("hagezi-adblock-ultimate", "Mine too"),
    ] {
        let mut f = get_json(&c, &format!("/feeds/{id}")).await;
        f["name"] = json!(n);
        let r = ui(&c, Method::PUT, &format!("/feeds/{id}"))
            .json(&f)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
    let r = ui(&c, Method::POST, "/feed-presets/hagezi")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        name("hagezi-adblock-tif").await,
        "HaGeZi Threat Intelligence Feeds",
        "a feed on its default name (its file's) takes the preset's"
    );
    assert_eq!(
        name("hagezi-adblock-ultimate").await,
        "Mine too",
        "an admin's name stays"
    );
}

/// #73: a provider with a preset's id and module that reads another source is the admin's, not
/// the preset: not shown installed, and installing the preset is refused (409) with nothing
/// changed (the provider, its exclusions, feeds, bundles). The same source in another spelling is
/// the preset, installed, and a reinstall brings back its files and keeps the admin's settings.
#[tokio::test(flavor = "multi_thread")]
async fn preset_install_refuses_a_provider_of_another_source() {
    let c = core_with(None, None).await;
    let installed = |presets: Value, id: &str| {
        presets
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .unwrap()["installed"]
            .clone()
    };
    let snapshot = || async {
        (
            get_json(&c, "/feed-providers/hagezi").await,
            get_json(&c, "/feeds").await,
            get_json(&c, "/bundles/block-common").await,
        )
    };
    let try_install = |id: &'static str| {
        let c = &c;
        async move {
            let r = ui(c, Method::POST, &format!("/feed-presets/{id}"))
                .json(&json!({}))
                .send()
                .await
                .unwrap();
            let status = r.status();
            (status, r.json::<Value>().await.unwrap())
        }
    };
    // The admin's own GitHub provider named `hagezi`, of an unrelated repository, excluding a
    // file the preset selects.
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&json!({"id": "hagezi", "name": "Mine", "module": "github", "enabled": false,
                      "config": {"owner": "someone", "repo": "lists"},
                      "files": [{"match": "mine.txt", "feed": {"format": "plain", "category": "mixed"}}],
                      "exclude": ["adblock/tif.txt"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    for (config, why) in [
        (json!({"owner": "someone", "repo": "lists"}), "another owner and repository"),
        (json!({"owner": "hagezi", "repo": "lists"}), "another repository"),
        (json!({"owner": "someone", "repo": "dns-blocklists"}), "another owner"),
        (
            json!({"owner": "hagezi", "repo": "dns-blocklists", "branch": "release"}),
            "an explicit branch, not the default the preset follows",
        ),
    ] {
        let mut p = get_json(&c, "/feed-providers/hagezi").await;
        p["config"] = config;
        let r = ui(&c, Method::PUT, "/feed-providers/hagezi")
            .json(&p)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{why}: {}", r.text().await.unwrap());
        assert_eq!(installed(get_json(&c, "/feed-presets").await, "hagezi"), false, "{why}");
        let before = snapshot().await;
        let (status, body) = try_install("hagezi").await;
        assert_eq!(status, StatusCode::CONFLICT, "{why}: {body}");
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(
            msg.contains("another source") && msg.contains("delete it first") && msg.contains("keep it"),
            "{why}: {msg}"
        );
        assert_eq!(snapshot().await, before, "{why}: a refused install changes nothing");
    }
    // The preset's source in another spelling (GitHub names are case-insensitive) is the
    // preset, installed; a reinstall brings back its files and keeps the admin's name, files
    // entry and other exclusions.
    let mut p = get_json(&c, "/feed-providers/hagezi").await;
    p["config"] = json!({"owner": "HaGeZi", "repo": "DNS-Blocklists"});
    p["exclude"] = json!(["adblock/tif.txt", "other.txt"]);
    let r = ui(&c, Method::PUT, "/feed-providers/hagezi")
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(installed(get_json(&c, "/feed-presets").await, "hagezi"), true);
    let (status, body) = try_install("hagezi").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["created"], false);
    let p = get_json(&c, "/feed-providers/hagezi").await;
    assert_eq!(p["name"], "Mine");
    assert_eq!(p["exclude"], json!(["other.txt"]));
    let files: Vec<&str> = p["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["match"].as_str().unwrap())
        .collect();
    assert_eq!(files, ["mine.txt", "adblock/tif.txt", "adblock/ultimate.txt"]);

    // http: another URL under the preset's provider id is refused; the same canonical URL (host
    // case, the scheme's default port spelled out) is the preset.
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&json!({"id": "firehol", "name": "Mine", "module": "http", "enabled": false,
                      "config": {"url": "https://lists.example/firehol_level2.netset"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let feeds_before = get_json(&c, "/feeds").await;
    let bundle_before = get_json(&c, "/bundles/block-common").await;
    assert_eq!(installed(get_json(&c, "/feed-presets").await, "firehol-level1"), false);
    let (status, body) = try_install("firehol-level1").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(get_json(&c, "/feeds").await, feeds_before);
    assert_eq!(get_json(&c, "/bundles/block-common").await, bundle_before);
    let mut p = get_json(&c, "/feed-providers/firehol").await;
    p["config"] = json!({"url": "https://IPLISTS.firehol.org:443/files/firehol_level1.netset"});
    let r = ui(&c, Method::PUT, "/feed-providers/firehol")
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(installed(get_json(&c, "/feed-presets").await, "firehol-level1"), true);
    let (status, body) = try_install("firehol-level1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(get_json(&c, "/feed-providers/firehol").await["name"], "Mine");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_or_interrupted_run_leaves_no_partial_applied_set() {
    let c = core_with(None, None).await;
    create_feed(&c, json!({"id": "u", "name": "U", "provider": "manual", "format": "plain", "modes": {"dns": {"mode": "aggregate"}}})).await;
    assert_eq!(
        put_file(&c, "u", "a.example\nb.example\n", None).await.status(),
        StatusCode::OK
    );
    wait_until("the first run", || async {
        runs(&c, "u").await == 1 && !c.state.feeds.is_busy("u")
    })
    .await;
    let snapshot = || async {
        c.state
            .db
            .read(|db| {
                let mut st = db.prepare(
                    "SELECT key, last_seen_run, last_seen_at, first_seen_at, coalesce(dropped_at, ''), coalesce(removed_run, 0)
                     FROM feed_entries WHERE feed_id = 'u' ORDER BY id",
                )?;
                let v = st
                    .query_map([], |r| {
                        Ok(format!(
                            "{}|{}|{}|{}|{}|{}",
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, i64>(5)?
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
            .unwrap()
    };
    let before = snapshot().await;
    // A run that refreshes the already-open `b.example` (aggregate), marks `a.example` dropped
    // and inserts `c.example`, stopped after its diff and before its row: what a crash leaves.
    let blob = {
        let staging = c.state.data_dir.join("staging");
        let mut w = picket_core::modules::download::ctx::stage_sync_in(&staging, "u", 1 << 20).unwrap();
        w.write(b"b.example\nc.example\n").unwrap();
        let mut f = w.finish().unwrap();
        let b3 = f.blake3().to_string();
        let tmp = f.take_temp_path().unwrap();
        let dst = picket_core::blobs::path(&c.state.data_dir, &b3).unwrap();
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::rename(tmp, &dst).unwrap();
        let size = std::fs::metadata(&dst).unwrap().len();
        let b = b3.clone();
        c.state
            .db
            .write(move |db| {
                let tx = db.transaction()?;
                picket_core::blobs::register(&tx, &b, "manual_file", size)?;
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap();
        b3
    };
    assert!(!c.state.feeds.is_busy("u"));
    let source_gen = c
        .state
        .db
        .read(|db| Ok::<_, anyhow::Error>(picket_core::feeds::store::source_gen(db, "u")?))
        .await
        .unwrap();
    let guard = picket_core::feeds::JobGuard::new(c.state.clone(), "u");
    let mut job = picket_core::feeds::ingest::IngestJob::new(
        c.state.clone(),
        "u",
        picket_core::feeds::ingest::Work::Download(picket_core::feeds::ingest::DownloadInput {
            blob,
            version: "v2".into(),
            updated_at: Timestamp::now(),
            downloaded_at: Timestamp::now(),
            state: json!({}),
            source_gen,
            trigger_cron: false,
        }),
        guard,
    );
    use picket_core::scheduler::HeavyJob;
    // Setup, parse, gates, apply: four steps (the parse fits in one), then stop before finalize.
    for _ in 0..4 {
        assert_eq!(job.step().await.unwrap(), picket_core::scheduler::Step::More);
    }
    let mid = snapshot().await;
    assert_ne!(mid, before, "the diff wrote");
    assert!(mid.iter().any(|r| r.starts_with("example.c|")), "{mid:?}");
    // A crash: nothing runs the job's guard; the next start undoes the open run.
    std::mem::forget(job);
    let n = picket_core::feeds::undo::undo_open_runs(&c.state.db)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(snapshot().await, before, "exactly the last finished run's set");
    assert_eq!(runs(&c, "u").await, 1, "the interrupted run never got a row");
    let undo_rows: i64 = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row("SELECT count(*) FROM feed_entry_undo", [], |r| r.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(undo_rows, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_open_row_is_refused_by_the_unique_index() {
    let c = core_with(None, None).await;
    let r = c
        .state
        .db
        .write(|db| {
            let ins = "INSERT INTO feed_entries(feed_id, rule_type, key, kind, flags, value_json, raw, first_run, last_seen_run, last_seen_at, first_seen_at)
                       VALUES ('f', 'dns', 'example.a', 'name', 1, '{}', 'a.example', 1, 1, 't', 't')";
            db.execute(ins, [])?;
            Ok::<_, anyhow::Error>(db.execute(ins, []).is_err())
        })
        .await
        .unwrap();
    assert!(r, "a second open row for the same entry fails");
    // A closed row and a new open one coexist (the temporal store).
    let ok = c
        .state
        .db
        .write(|db| {
            db.execute("UPDATE feed_entries SET removed_run = 2 WHERE feed_id = 'f'", [])?;
            Ok::<_, anyhow::Error>(
                db.execute(
                    "INSERT INTO feed_entries(feed_id, rule_type, key, kind, flags, value_json, raw, first_run, last_seen_run, last_seen_at, first_seen_at)
                     VALUES ('f', 'dns', 'example.a', 'name', 1, '{}', 'a.example', 3, 3, 't', 't')",
                    [],
                )
                .is_ok(),
            )
        })
        .await
        .unwrap();
    assert!(ok);
}

#[tokio::test(flavor = "multi_thread")]
async fn status_schedule_and_backtest_endpoints() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 5);
    create_feed(
        &c,
        json!({"id": "st", "name": "St", "provider": "http", "provider_config": {"url": format!("https://{HOST}/st.txt")}, "format": "plain"}),
    )
    .await;
    wait_until("the first run", || async {
        runs(&c, "st").await >= 1 && !c.state.feeds.is_busy("st")
    })
    .await;
    let st = get_json(&c, "/feeds/st/status").await;
    assert_eq!(st["totals"]["dns"], 5);
    assert!(st["next_check"].is_string());
    assert_eq!(st["checks_24h"], 1);
    let all = get_json(&c, "/feed-status").await;
    assert!(all["items"].as_array().unwrap().iter().any(|f| f["feed"] == "st"));
    let sched = get_json(&c, "/feeds/st/schedule").await;
    assert_eq!(sched["kind"], "dynamic");
    // The backtest is per provider (feed-scheduling.md §6).
    let bt = get_json(&c, "/feed-providers/st/backtest?days=1").await;
    assert_eq!(bt.as_array().unwrap().len(), 4);
    let ps = get_json(&c, "/feed-providers/st/status").await;
    assert_eq!(
        (ps["trigger"].as_str(), ps["checks_24h"].as_i64()),
        (Some("dynamic"), Some(1)),
        "{ps}"
    );
    assert_eq!(ps["feeds"], json!(["st"]));
    assert!(ps["next_check"].is_string());
    let all = get_json(&c, "/feed-provider-status").await;
    assert!(
        all["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["provider"] == "st")
    );
    let pc = get_json(&c, "/feed-providers/st/checks").await;
    assert_eq!(pc["items"][0]["cause"], "first", "{pc}");
    let files = get_json(&c, "/feed-providers/st/listing").await;
    assert_eq!(
        files,
        json!({"prefixes": [], "items": [{"file": "response", "selected": true, "feed": "st"}],
               "next_cursor": null, "listing": null})
    );
    let entries = get_json(&c, "/feeds/st/entries?rule_type=dns&q=a3").await;
    assert_eq!(entries["items"].as_array().unwrap().len(), 1);
    let openapi = get_json(&c, "/openapi.json").await;
    assert!(openapi["paths"]["/api/ui/v1/feeds/{id}/file/lines"].is_object());
}

/// api.md §3 pagination: the feed and feed-provider status lists page in id order, the cursor
/// naming the last id returned, and the last page has none.
#[tokio::test(flavor = "multi_thread")]
async fn status_lists_page_in_id_order() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 2);
    for id in ["pc", "pa", "pb"] {
        create_feed(
            &c,
            json!({"id": id, "name": id, "provider": "http", "provider_config": {"url": format!("https://{HOST}/{id}.txt")}, "format": "plain"}),
        )
        .await;
    }
    for (list, field) in [("/feed-status", "feed"), ("/feed-provider-status", "provider")] {
        let ids = |page: &Value| -> Vec<String> {
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i[field].as_str().unwrap().to_string())
                .collect()
        };
        // Every id on one page (the built-in feeds too), in order.
        let all = ids(&get_json(&c, &format!("{list}?limit=500")).await);
        assert!(all.is_sorted(), "{all:?}");
        assert!(
            ["pa", "pb", "pc"].iter().all(|id| all.iter().any(|x| x == id)),
            "{all:?}"
        );
        let mut seen = Vec::new();
        let mut path = format!("{list}?limit=2");
        let mut pages = 0;
        loop {
            let page = get_json(&c, &path).await;
            pages += 1;
            let got = ids(&page);
            assert!(got.len() <= 2, "{page}");
            seen.extend(got);
            match page["next_cursor"].as_str() {
                Some(cur) => path = format!("{list}?limit=2&cursor={cur}"),
                None => break,
            }
        }
        assert_eq!(seen, all, "{list}");
        assert_eq!(pages, all.len().div_ceil(2), "{list}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_keeps_what_bundle_versions_need() {
    use picket_core::retention::RetentionHook;
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "r", "name": "R", "provider": "manual", "format": "plain"}),
    )
    .await;
    let v1: Value = put_file(&c, "r", "a.example\nb.example\n", None)
        .await
        .json()
        .await
        .unwrap();
    wait_until("run 1", || async {
        runs(&c, "r").await == 1 && !c.state.feeds.is_busy("r")
    })
    .await;
    let first_blob: String = newest_run(&c, "r").await["blob"].as_str().unwrap().to_string();
    assert_eq!(
        put_file(&c, "r", "b.example\nc.example\n", v1["version"].as_str())
            .await
            .status(),
        StatusCode::OK
    );
    wait_until("run 2", || async {
        runs(&c, "r").await == 2 && !c.state.feeds.is_busy("r")
    })
    .await;
    let run1: i64 = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT min(id) FROM feed_runs WHERE feed_id = 'r'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    // Everything is old now; a bundle version still records run 1.
    c.state
        .db
        .write(move |db| {
            db.execute_batch(
                "UPDATE feed_runs SET downloaded_at = '2020-01-01T00:00:00.000000Z', confirmed_at = '2020-01-01T00:00:00.000000Z' WHERE feed_id = 'r';
                 UPDATE blobs SET created_at = '2020-01-01T00:00:00.000000Z';",
            )?;
            db.execute(
                "INSERT INTO bundle_versions(bundle_id, head_id, heads_json, feed_runs_json, definition_hash, published_at)
                 VALUES ('b', 'h', '{}', ?1, 'd', '2020-01-01T00:00:00.000000Z')",
                [format!("{{\"r\":{run1}}}")],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let hook = picket_core::feeds::retention::FeedRetention;
    while hook.step(&c.state).await.unwrap() == picket_core::scheduler::Step::More {}
    let closed = count(
        &c,
        "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NOT NULL",
        "r",
    )
    .await;
    assert_eq!(closed, 1, "a.example is needed to replay run 1");
    assert_eq!(runs(&c, "r").await, 2, "run 1 is recorded by a bundle version");
    // Once no version records it, the closed row, the run and its raw download go.
    c.state
        .db
        .write(|db| {
            db.execute("DELETE FROM bundle_versions", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    while hook.step(&c.state).await.unwrap() == picket_core::scheduler::Step::More {}
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NOT NULL",
            "r"
        )
        .await,
        0
    );
    assert_eq!(
        runs(&c, "r").await,
        1,
        "the newest (and latest applied) run stays"
    );
    assert_eq!(open_keys(&c, "r").await.len(), 2, "open entries never age out");
    let b = first_blob.clone();
    let left: i64 = c
        .state
        .db
        .read(move |db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT count(*) FROM blobs WHERE blake3 = ?1",
                [b],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(left, 0, "a raw download nothing names goes");
    assert!(
        !picket_core::blobs::path(&c.state.data_dir, &first_blob)
            .unwrap()
            .exists()
    );
    // The current file's blob stays (manual_files names it).
    assert!(
        get_json(&c, "/feeds/r/file").await["content"]
            .as_str()
            .unwrap()
            .contains("c.example")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_newer_run_within_the_held_runs_limit_confirms_it() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 50);
    create_feed(
        &c,
        json!({"id": "nh", "name": "NH", "provider": "http", "provider_config": {"url": format!("https://{HOST}/nh.txt")},
               "format": "plain", "sanity": {"max_change_ratio": 0.1, "min_change_allowance": 5, "confirm_after": "1h"}}),
    )
    .await;
    wait_until("the first run", || async {
        runs(&c, "nh").await >= 1 && !c.state.feeds.is_busy("nh")
    })
    .await;
    *body.lock().unwrap() = names("b", 50);
    check_now(&c, "nh").await;
    let first_held = newest_run(&c, "nh").await;
    assert_eq!(first_held["status"], "held");
    // Before confirm_after, a run close to the held one is held in its place (the hold goes on).
    *body.lock().unwrap() = format!("{}{}", names("b", 49), names("c", 1));
    check_now(&c, "nh").await;
    let second_held = newest_run(&c, "nh").await;
    assert_eq!(second_held["status"], "held", "{second_held}");
    let old = get_json(&c, &format!("/feeds/nh/runs/{}", first_held["id"])).await;
    assert_eq!(old["run"]["status"], "rejected");
    // After confirm_after (since the hold began), the next run within the held run's limit is
    // applied: the source confirmed the big change.
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_state SET held_since = '2020-01-01T00:00:00.000000Z' WHERE feed_id = 'nh'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    *body.lock().unwrap() = format!("{}{}", names("b", 48), names("c", 2));
    check_now(&c, "nh").await;
    let r = newest_run(&c, "nh").await;
    assert_eq!(r["status"], "applied", "{r}");
    assert_eq!(open_keys(&c, "nh").await.len(), 50);
    assert!(
        open_keys(&c, "nh")
            .await
            .iter()
            .all(|k| !k.contains(":example.a"))
    );
    assert_eq!(alert_state(&c, "feed_held:nh").await.as_deref(), Some("resolved"));
}
