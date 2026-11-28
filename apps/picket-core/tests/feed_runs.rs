//! Feed runs end to end, around holds, run order, undo, retention and deleted feeds
//! (feeds.md §3, §5, §8; storage.md §3–§4; core.md §3, §9; feed-scheduling.md §5–§6;
//! providers.md §2–§3; api.md §7): a running core with download providers pointed at a local
//! HTTPS server.

use crate::common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::feeds::{check_now, create_feed, ui, update_feed, url, wait_until};
use common::{Core, client};
use picket_core::modules::download::testkit::{Reply, Seen, TestServer};
use picket_core::scheduler::{HeavyJob, Step};
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

async fn delete_feed(c: &Core, id: &str) {
    let r = ui(c, Method::DELETE, &format!("/feeds/{id}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let st = r.status();
    let v: Value = r.json().await.unwrap();
    assert_eq!(st, StatusCode::OK, "{v}");
    // The tests' one-feed providers go with their feed (a provider can't be deleted while a feed
    // uses it), so the feed can be created again with its id.
    let r = ui(c, Method::DELETE, &format!("/feed-providers/{id}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(
        r.status() == StatusCode::OK || r.status() == StatusCode::NOT_FOUND,
        "{}",
        r.status()
    );
}

async fn q_i64(c: &Core, sql: &str, feed: &str) -> i64 {
    let (sql, f) = (sql.to_string(), feed.to_string());
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&sql, [f], |r| r.get::<_, i64>(0))?))
        .await
        .unwrap()
}

async fn exec(c: &Core, sql: &str) {
    let sql = sql.to_string();
    c.state
        .db
        .write(move |db| {
            db.execute_batch(&sql)?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
}

async fn runs(c: &Core, feed: &str) -> i64 {
    q_i64(c, "SELECT count(*) FROM feed_runs WHERE feed_id = ?1", feed).await
}

async fn checks(c: &Core, feed: &str) -> i64 {
    q_i64(
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

/// `id:status:kind:source_run` per run, oldest first.
async fn run_list(c: &Core, feed: &str) -> Vec<(i64, String, String, Option<i64>)> {
    let f = feed.to_string();
    c.state
        .db
        .read(move |db| {
            let mut st = db.prepare(
                "SELECT id, status, coalesce(kind, ''), source_run FROM feed_runs WHERE feed_id = ?1 ORDER BY id",
            )?;
            let v = st
                .query_map([f], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap()
}

async fn newest_run(c: &Core, feed: &str) -> Value {
    let v = get_json(c, &format!("/feeds/{feed}/runs?limit=1")).await;
    v["items"][0].clone()
}

/// Replay's rule (storage.md §3): a row is open at run r when `first_run ≤ r < removed_run`,
/// so no row may be closed by a run older than the one that inserted it.
async fn assert_replayable(c: &Core, feed: &str) {
    let bad = q_i64(
        c,
        "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NOT NULL AND removed_run < first_run",
        feed,
    )
    .await;
    assert_eq!(
        bad, 0,
        "rows closed by an older run than the one that inserted them"
    );
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

/// A `plain` http feed with a tight change-ratio gate (5 changes on a 50-entry list).
fn feed_def(id: &str, domains_as: &str) -> Value {
    json!({"id": id, "name": "F", "provider": "http", "provider_config": {"url": format!("https://{HOST}/{id}.txt")},
           "format": "plain", "format_options": {"domains_as": domains_as},
           "sanity": {"max_change_ratio": 0.1, "min_change_allowance": 5, "confirm_after": "1h"}})
}

async fn first_run(c: &Core, feed: &str) {
    wait_until("the first run", || async {
        runs(c, feed).await >= 1 && !c.state.feeds.is_busy(feed)
    })
    .await;
}

/// `confirm_after` has passed for the current hold.
async fn age_hold(c: &Core, feed: &str) {
    exec(
        c,
        &format!("UPDATE feed_state SET held_since = '2020-01-01T00:00:00.000000Z' WHERE feed_id = '{feed}'"),
    )
    .await;
}

/// Stores `text` as a blob (as a download would) and returns its BLAKE3.
async fn store_blob(c: &Core, feed: &str, text: &[u8]) -> String {
    let staging = c.state.data_dir.join("staging");
    let mut w = picket_core::modules::download::ctx::stage_sync_in(&staging, feed, 1 << 24).unwrap();
    w.write(text).unwrap();
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
            picket_core::blobs::register(&tx, &b, "download", size)?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    b3
}

/// A download's run, as a check of the feed's current source would queue it.
async fn download_job(c: &Core, feed: &str, blob: String) -> picket_core::feeds::ingest::IngestJob {
    let source_gen = source_gen(c, feed).await;
    let guard = picket_core::feeds::JobGuard::new(c.state.clone(), feed);
    picket_core::feeds::ingest::IngestJob::new(
        c.state.clone(),
        feed,
        picket_core::feeds::ingest::Work::Download(picket_core::feeds::ingest::DownloadInput {
            blob,
            version: "v-test".into(),
            updated_at: Timestamp::now(),
            downloaded_at: Timestamp::now(),
            state: json!({}),
            source_gen,
            trigger_cron: false,
        }),
        guard,
    )
}

/// The feed's current source generation.
async fn source_gen(c: &Core, feed: &str) -> Option<i64> {
    let f = feed.to_string();
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(picket_core::feeds::store::source_gen(db, &f)?))
        .await
        .unwrap()
}

async fn retention_pass(c: &Core) {
    use picket_core::retention::RetentionHook;
    let hook = picket_core::feeds::retention::FeedRetention;
    while hook.step(&c.state).await.unwrap() == Step::More {}
}

/// F1, F12: a held run confirmed after a re-ingest is applied under a new, newer id (the
/// waiting row moves there, `source_run` keeps its old id), so the next re-ingest reads the
/// confirmed blob; a re-ingest while a run is held leaves `feed_held` open and the hold's start
/// as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_confirmed_held_run_takes_a_new_id_after_a_reingest() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 50);
    create_feed(&c, feed_def("f", "exact")).await;
    first_run(&c, "f").await;
    *body.lock().unwrap() = names("b", 50);
    check_now(&c, "f").await;
    let held = newest_run(&c, "f").await;
    assert_eq!(held["status"], "held");
    let held_id = held["id"].as_i64().unwrap();
    assert_eq!(alert_state(&c, "feed_held:f").await.as_deref(), Some("open"));
    let since_before: Option<String> = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT held_since FROM feed_state WHERE feed_id = 'f'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(since_before.is_some());
    // An edit while held: a re-ingest of the applied blob A. The hold keeps waiting (F12).
    update_feed(&c, "f", feed_def("f", "subdomains")).await;
    wait_until("the re-ingest", || async {
        runs(&c, "f").await >= 3 && !c.state.feeds.is_busy("f")
    })
    .await;
    assert_eq!(
        alert_state(&c, "feed_held:f").await.as_deref(),
        Some("open"),
        "a re-ingest accepts no version"
    );
    let since_after: Option<String> = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT held_since FROM feed_state WHERE feed_id = 'f'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(
        since_after, since_before,
        "the confirm_after window doesn't restart"
    );
    assert_eq!(get_json(&c, "/feeds/f/status").await["held_run"], held_id);
    let reingest_id = run_list(&c, "f").await.last().unwrap().0;
    // confirm_after passed; the source still serves B: confirmed, under a new id.
    age_hold(&c, "f").await;
    check_now(&c, "f").await;
    wait_until("the confirmation", || async { !c.state.feeds.is_busy("f") }).await;
    let list = run_list(&c, "f").await;
    let confirmed = list.last().unwrap().clone();
    assert!(confirmed.0 > reingest_id, "{list:?}");
    assert_eq!(
        (confirmed.1.as_str(), confirmed.2.as_str(), confirmed.3),
        ("applied", "download", Some(held_id)),
        "{list:?}"
    );
    assert!(
        !list.iter().any(|r| r.0 == held_id),
        "the waiting row moved: {list:?}"
    );
    // The old id still finds it.
    let r = get_json(&c, &format!("/feeds/f/runs/{held_id}")).await;
    assert_eq!(r["run"]["id"], confirmed.0);
    assert_eq!(r["run"]["source_run"], held_id);
    assert_eq!(alert_state(&c, "feed_held:f").await.as_deref(), Some("resolved"));
    assert!(open_keys(&c, "f").await.iter().all(|k| k.contains("example.b")));
    // The next edit re-ingests the latest applied blob: B, not the pre-hold A.
    update_feed(&c, "f", feed_def("f", "exact")).await;
    wait_until("the second re-ingest", || async {
        run_list(&c, "f").await.last().is_some_and(|r| r.0 > confirmed.0) && !c.state.feeds.is_busy("f")
    })
    .await;
    let keys = open_keys(&c, "f").await;
    assert!(
        keys.iter().all(|k| k.contains("example.b")),
        "{:?}",
        &keys[..3.min(keys.len())]
    );
    assert_replayable(&c, "f").await;
    // A revert to A is a change again (judged against B), not "unchanged".
    *body.lock().unwrap() = names("a", 50);
    check_now(&c, "f").await;
    assert_eq!(newest_run(&c, "f").await["status"], "held");
}

/// F1: an expiry sweep while a run is held, then the confirmation: run ids stay in the order
/// the runs changed entries.
#[tokio::test(flavor = "multi_thread")]
async fn an_expiry_sweep_during_a_hold_keeps_run_ids_in_order() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    c.state.clock.pin(true);
    *body.lock().unwrap() = names("a", 50);
    let mut def = feed_def("s", "exact");
    def["modes"] = json!({"dns": {"mode": "aggregate", "expire_after": "1h"}});
    create_feed(&c, def).await;
    first_run(&c, "s").await;
    // a45..a49 go missing: kept (aggregate), marked dropped, then aged past expire_after.
    *body.lock().unwrap() = names("a", 45);
    check_now(&c, "s").await;
    exec(
        &c,
        "UPDATE feed_entries SET dropped_at = '2020-01-01T00:00:00.000000Z' WHERE dropped_at IS NOT NULL",
    )
    .await;
    // A whole new list: held.
    *body.lock().unwrap() = names("c", 50);
    check_now(&c, "s").await;
    let held = newest_run(&c, "s").await;
    assert_eq!(held["status"], "held");
    let held_id = held["id"].as_i64().unwrap();
    // The hourly sweep closes the expired entries under a new run.
    picket_core::feeds::sweep_expired(&c.state);
    wait_until("the sweep", || async {
        run_list(&c, "s").await.iter().any(|r| r.1 == "expired") && !c.state.feeds.is_busy("s")
    })
    .await;
    let sweep_id = run_list(&c, "s")
        .await
        .iter()
        .find(|r| r.1 == "expired")
        .unwrap()
        .0;
    assert!(sweep_id > held_id);
    assert_eq!(
        alert_state(&c, "feed_held:s").await.as_deref(),
        Some("open"),
        "a sweep accepts no version"
    );
    age_hold(&c, "s").await;
    check_now(&c, "s").await;
    wait_until("the confirmation", || async { !c.state.feeds.is_busy("s") }).await;
    let list = run_list(&c, "s").await;
    let last = list.last().unwrap();
    assert!(last.0 > sweep_id, "{list:?}");
    assert_eq!((last.1.as_str(), last.3), ("applied", Some(held_id)), "{list:?}");
    assert_replayable(&c, "s").await;
    let keys = open_keys(&c, "s").await;
    assert!(
        keys.iter().any(|k| k.contains("example.c")) && !keys.iter().any(|k| k.contains("example.a46")),
        "{keys:?}"
    );
}

/// F4: a confirmation judges the parse-error gate again with the current format; a held
/// adblock download read as `plain` is rejected, and the applied entries stay.
#[tokio::test(flavor = "multi_thread")]
async fn a_confirmation_judges_parse_errors_with_the_current_format() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    let rules = |p: &str| {
        (0..50)
            .map(|i| format!("||{p}{i}.example^\n"))
            .collect::<String>()
    };
    *body.lock().unwrap() = rules("a");
    let def = |format: &str| {
        json!({"id": "ab", "name": "AB", "provider": "http", "provider_config": {"url": format!("https://{HOST}/ab.txt")},
               "format": format, "sanity": {"max_change_ratio": 0.1, "min_change_allowance": 5, "confirm_after": "1h"}})
    };
    create_feed(&c, def("adblock")).await;
    first_run(&c, "ab").await;
    let applied = open_keys(&c, "ab").await;
    assert_eq!(applied.len(), 50);
    *body.lock().unwrap() = rules("b");
    check_now(&c, "ab").await;
    let held = newest_run(&c, "ab").await;
    assert_eq!(held["status"], "held");
    // The format becomes plain: `||…^` lines are parse errors there.
    update_feed(&c, "ab", def("plain")).await;
    wait_until("the re-ingest", || async {
        runs(&c, "ab").await >= 3 && !c.state.feeds.is_busy("ab")
    })
    .await;
    age_hold(&c, "ab").await;
    check_now(&c, "ab").await;
    wait_until("the confirmation", || async { !c.state.feeds.is_busy("ab") }).await;
    let r = get_json(&c, &format!("/feeds/ab/runs/{}", held["id"])).await;
    assert_eq!(
        (r["run"]["status"].as_str(), r["run"]["gate"].as_str()),
        (Some("rejected"), Some("parse_errors")),
        "{r}"
    );
    assert_eq!(open_keys(&c, "ab").await, applied, "nothing applied");
    assert!(get_json(&c, "/feeds/ab/status").await["held_run"].is_null());
}

/// A confirmation still counts for the drop gate: a held run that drops 99 % or more (held
/// before the gate existed, with its params already saying the gate is on, so no re-gate judges
/// it first) is rejected when the source keeps serving it, and the applied entries stay.
#[tokio::test(flavor = "multi_thread")]
async fn a_confirmation_is_rejected_by_the_drop_gate() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 200);
    let def = |sanity: Value| {
        json!({"id": "d", "name": "D", "provider": "http", "provider_config": {"url": format!("https://{HOST}/d.txt")},
               "format": "plain", "sanity": sanity})
    };
    let base = json!({"max_change_ratio": 0.1, "min_change_allowance": 5, "confirm_after": "1h"});
    let mut off = base.clone();
    off["reject_drop_ratio"] = Value::Null;
    create_feed(&c, def(off)).await;
    first_run(&c, "d").await;
    let applied = open_keys(&c, "d").await;
    assert_eq!(applied.len(), 200);
    *body.lock().unwrap() = names("a", 1);
    check_now(&c, "d").await;
    let held = newest_run(&c, "d").await;
    assert_eq!(held["status"], "held", "{held}");
    // As if held before the upgrade: its params carry the default drop gate, as the feed's do.
    exec(
        &c,
        &format!(
            "UPDATE feed_runs SET params_json = json_set(params_json, '$.sanity.reject_drop_ratio', 0.99) WHERE id = {}",
            held["id"]
        ),
    )
    .await;
    update_feed(&c, "d", def(base)).await;
    wait_until("the edit", || async { !c.state.feeds.is_busy("d") }).await;
    assert_eq!(newest_run(&c, "d").await["status"], "held", "no re-gate");
    age_hold(&c, "d").await;
    check_now(&c, "d").await;
    wait_until("the confirmation", || async { !c.state.feeds.is_busy("d") }).await;
    let r = get_json(&c, &format!("/feeds/d/runs/{}", held["id"])).await;
    assert_eq!(
        (r["run"]["status"].as_str(), r["run"]["gate"].as_str()),
        (Some("rejected"), Some("drop")),
        "{r}"
    );
    assert_eq!(open_keys(&c, "d").await, applied, "nothing applied");
    assert!(get_json(&c, "/feeds/d/status").await["held_run"].is_null());
    assert_eq!(alert_state(&c, "feed_held:d").await.as_deref(), Some("open"));
}

/// F5: an unchanged result confirms only the held run whose blob the source serves: with A
/// applied (and re-ingested), B held, and the source back to A, B is never applied; it is
/// superseded and `feed_held` resolves.
#[tokio::test(flavor = "multi_thread")]
async fn an_unchanged_check_confirms_only_the_run_the_source_serves() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 50);
    create_feed(&c, feed_def("u", "exact")).await;
    first_run(&c, "u").await;
    *body.lock().unwrap() = names("b", 50);
    check_now(&c, "u").await;
    let held = newest_run(&c, "u").await;
    assert_eq!(held["status"], "held");
    update_feed(&c, "u", feed_def("u", "subdomains")).await;
    wait_until("the re-ingest", || async {
        runs(&c, "u").await >= 3 && !c.state.feeds.is_busy("u")
    })
    .await;
    age_hold(&c, "u").await;
    // The source reverts to A: identical to the re-ingest's blob.
    *body.lock().unwrap() = names("a", 50);
    check_now(&c, "u").await;
    wait_until("the feed", || async { !c.state.feeds.is_busy("u") }).await;
    assert!(
        open_keys(&c, "u").await.iter().all(|k| k.contains("example.a")),
        "B must not be applied"
    );
    let r = get_json(&c, &format!("/feeds/u/runs/{}", held["id"])).await;
    assert_eq!(
        (r["run"]["status"].as_str(), r["run"]["gate"].as_str()),
        (Some("rejected"), Some("superseded")),
        "{r}"
    );
    assert_eq!(alert_state(&c, "feed_held:u").await.as_deref(), Some("resolved"));
    // Later unchanged checks confirm nothing either.
    check_now(&c, "u").await;
    assert!(open_keys(&c, "u").await.iter().all(|k| k.contains("example.a")));
    assert!(!run_list(&c, "u").await.iter().any(|r| r.1 == "held"));
}

/// feeds.md §5: the `http` Range rung never confirms a held run.
#[tokio::test(flavor = "multi_thread")]
async fn the_range_rung_never_confirms_a_held_run() {
    let body = Arc::new(Mutex::new(names("a", 50)));
    let b = body.clone();
    let srv = TestServer::start(&[HOST], move |s: &Seen| {
        let text = b.lock().unwrap().clone();
        if s.header("range").is_some() {
            let mut r = Reply::ok(text[..4096.min(text.len())].to_string()).header(
                "content-range",
                &format!("bytes 0-{}/{}", 4095.min(text.len() - 1), text.len()),
            );
            r.status = 206;
            return r;
        }
        Reply::ok(text)
    })
    .await;
    let c = core_with(Some(&srv), None).await;
    create_feed(&c, feed_def("rg", "exact")).await;
    first_run(&c, "rg").await;
    *body.lock().unwrap() = names("b", 50);
    check_now(&c, "rg").await;
    let held = newest_run(&c, "rg").await;
    assert_eq!(held["status"], "held");
    age_hold(&c, "rg").await;
    let n = runs(&c, "rg").await;
    check_now(&c, "rg").await;
    let last: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT method FROM feed_checks WHERE feed_id = 'rg' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(last, "range");
    assert_eq!(runs(&c, "rg").await, n);
    assert_eq!(
        newest_run(&c, "rg").await["status"],
        "held",
        "the Range rung confirms nothing"
    );
    assert!(open_keys(&c, "rg").await.iter().all(|k| k.contains("example.a")));
}

/// F13: an edit whose new parameters an in-flight run read, when that run ends held, still
/// re-ingests the applied blob (the comparison is with the latest applied run's parameters).
#[tokio::test(flavor = "multi_thread")]
async fn an_edit_read_by_a_run_that_ends_held_still_reingests() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 50);
    create_feed(&c, feed_def("e", "exact")).await;
    first_run(&c, "e").await;
    *body.lock().unwrap() = names("b", 50);
    check_now(&c, "e").await;
    assert_eq!(newest_run(&c, "e").await["status"], "held");
    // As if the held run had read the edit while in flight: its parameters are the new ones.
    exec(
        &c,
        "UPDATE feed_runs SET params_json = json_set(params_json, '$.domains_as', 'subdomains') WHERE feed_id = 'e' AND status = 'held'",
    )
    .await;
    let n = runs(&c, "e").await;
    update_feed(&c, "e", feed_def("e", "subdomains")).await;
    wait_until("the re-ingest", || async {
        runs(&c, "e").await > n && !c.state.feeds.is_busy("e")
    })
    .await;
    let list = run_list(&c, "e").await;
    let last = list.last().unwrap();
    assert_eq!(
        (last.1.as_str(), last.2.as_str()),
        ("applied", "reingest"),
        "{list:?}"
    );
    let p: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT json_extract(params_json, '$.domains_as') FROM feed_runs WHERE feed_id = 'e' AND status = 'applied' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(p, "subdomains");
}

/// F14: the comparison with a held run (its blob parsed again) and the change counts run in
/// steps of their own, so a P0 delta can run between them.
#[tokio::test(flavor = "multi_thread")]
async fn the_held_comparison_runs_in_bounded_steps() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 50);
    create_feed(&c, feed_def("st", "exact")).await;
    first_run(&c, "st").await;
    *body.lock().unwrap() = names("b", 50);
    check_now(&c, "st").await;
    assert_eq!(newest_run(&c, "st").await["status"], "held");
    // A download within the held run's limit (one more name), driven step by step.
    let text = format!("{}extra.example\n", names("b", 50));
    let blob = store_blob(&c, "st", text.as_bytes()).await;
    let mut job = download_job(&c, "st", blob).await;
    let mut steps = 0;
    loop {
        steps += 1;
        if job.step().await.unwrap() == Step::Done {
            break;
        }
        assert!(steps < 100);
    }
    // Setup, parse, gates, count vs applied, parse held, count vs held, finalize.
    assert!(steps >= 7, "{steps} steps");
    let r = newest_run(&c, "st").await;
    assert_eq!(
        r["status"], "held",
        "within the held run's limit, but confirm_after hasn't passed: {r}"
    );
    drop(job);
}

/// F3, F2: retention between an ingest's diff and its row keeps the rows the open run closed;
/// a job dropped there is undone by an undo job in the heavy lane, back to the last finished
/// set; and an undo never touches a run that finished.
#[tokio::test(flavor = "multi_thread")]
async fn retention_and_undo_around_an_unfinished_run() {
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "u", "name": "U", "provider": "manual", "format": "plain"}),
    )
    .await;
    let r = ui(&c, Method::PUT, "/feeds/u/file")
        .json(&json!({"content": "a.example\nb.example\n", "base_version": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("run 1", || async {
        runs(&c, "u").await == 1 && !c.state.feeds.is_busy("u")
    })
    .await;
    let before = open_keys(&c, "u").await;
    // Retention may delete rows closed long ago: make the clock irrelevant.
    exec(
        &c,
        "UPDATE feed_runs SET downloaded_at = '2020-01-01T00:00:00.000000Z', confirmed_at = NULL",
    )
    .await;
    for round in 0..2 {
        let blob = store_blob(&c, "u", b"b.example\nc.example\n").await;
        let mut job = download_job(&c, "u", blob).await;
        // Setup, parse, gates, apply: the diff closed a.example under the open run.
        for _ in 0..4 {
            assert_eq!(job.step().await.unwrap(), Step::More);
        }
        let closed = q_i64(
            &c,
            "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NOT NULL",
            "u",
        )
        .await;
        assert_eq!(closed, 1);
        retention_pass(&c).await;
        let closed_after = q_i64(
            &c,
            "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NOT NULL",
            "u",
        )
        .await;
        assert_eq!(
            closed_after, 1,
            "a row an open run closed is never a retention candidate"
        );
        if round == 0 {
            // A crash: the next start undoes the open run.
            std::mem::forget(job);
            picket_core::feeds::undo::undo_open_runs(&c.state.db)
                .await
                .unwrap();
        } else {
            // A dropped job: its guard queues the undo in the heavy lane.
            drop(job);
            wait_until("the undo", || async {
                q_i64(&c, "SELECT count(*) FROM feed_runs_open WHERE feed_id = ?1", "u").await == 0
            })
            .await;
        }
        assert_eq!(
            open_keys(&c, "u").await,
            before,
            "round {round}: back to the last finished set"
        );
        assert_eq!(runs(&c, "u").await, 1);
    }
    // A finished run is never undone, whoever asks (F2): the check is made inside the writer.
    let r = ui(&c, Method::PUT, "/feeds/u/file")
        .json(&json!({"content": "b.example\nd.example\n", "base_version": get_json(&c, "/feeds/u/file").await["version"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("run 2", || async {
        runs(&c, "u").await == 2 && !c.state.feeds.is_busy("u")
    })
    .await;
    let after = open_keys(&c, "u").await;
    let last = run_list(&c, "u").await.last().unwrap().0;
    assert_eq!(
        picket_core::feeds::undo::undo_run(&c.state.db, last)
            .await
            .unwrap(),
        None
    );
    picket_core::feeds::undo::UndoJob::new(c.state.clone(), "u", last).submit();
    tokio::time::sleep(Duration::from_millis(300)).await;
    wait_until("the feed", || async { !c.state.feeds.is_busy("u") }).await;
    assert_eq!(open_keys(&c, "u").await, after, "the stored run's changes stay");
}

/// F7: a bundle version that records a run of a feed whose id holds `_` keeps that run.
#[tokio::test(flavor = "multi_thread")]
async fn retention_keeps_recorded_runs_of_feed_ids_with_underscores() {
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "my_feed", "name": "R", "provider": "manual", "format": "plain"}),
    )
    .await;
    let v1: Value = ui(&c, Method::PUT, "/feeds/my_feed/file")
        .json(&json!({"content": "a.example\n", "base_version": null}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    wait_until("run 1", || async {
        runs(&c, "my_feed").await == 1 && !c.state.feeds.is_busy("my_feed")
    })
    .await;
    let r = ui(&c, Method::PUT, "/feeds/my_feed/file")
        .json(&json!({"content": "b.example\n", "base_version": v1["version"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("run 2", || async {
        runs(&c, "my_feed").await == 2 && !c.state.feeds.is_busy("my_feed")
    })
    .await;
    let run1 = q_i64(&c, "SELECT min(id) FROM feed_runs WHERE feed_id = ?1", "my_feed").await;
    exec(
        &c,
        &format!(
            "UPDATE feed_runs SET downloaded_at = '2020-01-01T00:00:00.000000Z', confirmed_at = '2020-01-01T00:00:00.000000Z' WHERE feed_id = 'my_feed';
             INSERT INTO bundle_versions(bundle_id, head_id, heads_json, feed_runs_json, definition_hash, published_at)
               VALUES ('b', 'h', '{{}}', '{{\"my_feed\":{run1}}}', 'd', '2020-01-01T00:00:00.000000Z');"
        ),
    )
    .await;
    retention_pass(&c).await;
    assert_eq!(
        runs(&c, "my_feed").await,
        2,
        "run {run1} is recorded by a bundle version"
    );
    // The rows open at run 1 stay too (a.example, closed by run 2).
    let a = q_i64(
        &c,
        "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND key = 'example.a'",
        "my_feed",
    )
    .await;
    assert_eq!(a, 1);
}

/// F6: rows kept for replay never crowd out rows that may go.
#[tokio::test(flavor = "multi_thread")]
async fn retention_pins_never_starve_deletable_rows() {
    let c = core_with(None, None).await;
    for id in ["p", "q"] {
        create_feed(
            &c,
            json!({"id": id, "name": id, "provider": "manual", "format": "plain"}),
        )
        .await;
    }
    // 25,000 closed rows of `p` that a bundle version pinning run 10 needs (closed by run 11),
    // inserted first, and one row of `q` that may go.
    exec(
        &c,
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 25000)
         INSERT INTO feed_entries(feed_id, rule_type, key, kind, flags, value_json, raw, first_run, last_seen_run, removed_run, last_seen_at, first_seen_at)
           SELECT 'p', 'dns', 'example.p' || i, 'exact', 0, '', 'p', 1, 1, 11, '2020-01-01T00:00:00.000000Z', '2020-01-01T00:00:00.000000Z' FROM n;
         INSERT INTO feed_entries(feed_id, rule_type, key, kind, flags, value_json, raw, first_run, last_seen_run, removed_run, last_seen_at, first_seen_at)
           VALUES ('q', 'dns', 'example.q', 'exact', 0, '', 'q', 1, 1, 12, '2020-01-01T00:00:00.000000Z', '2020-01-01T00:00:00.000000Z');
         INSERT INTO bundle_versions(bundle_id, head_id, heads_json, feed_runs_json, definition_hash, published_at)
           VALUES ('b', 'h', '{}', '{\"p\":10}', 'd', '2020-01-01T00:00:00.000000Z');",
    )
    .await;
    retention_pass(&c).await;
    assert_eq!(
        q_i64(&c, "SELECT count(*) FROM feed_entries WHERE feed_id = ?1", "q").await,
        0,
        "q's row goes"
    );
    assert_eq!(
        q_i64(&c, "SELECT count(*) FROM feed_entries WHERE feed_id = ?1", "p").await,
        25_000,
        "p's rows stay"
    );
}

/// F8: `policy_drops` is bounded: resolved rows age out, and a feed keeps at most
/// `MAX_DROPS_PER_FEED` rows.
#[tokio::test(flavor = "multi_thread")]
async fn policy_drops_are_bounded() {
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "pd", "name": "PD", "provider": "manual", "format": "hosts", "rule_policy": {"redirects": "drop"}}),
    )
    .await;
    let per = picket_core::feeds::ingest::MAX_DROPS_PER_RUN;
    let mut version: Option<String> = None;
    for (n, p) in ["a", "b", "c"].iter().enumerate() {
        let text: String = (0..per).map(|i| format!("192.0.2.1 {p}{i}.example\n")).collect();
        let r = ui(&c, Method::PUT, "/feeds/pd/file")
            .json(&json!({"content": text, "base_version": version}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let v: Value = r.json().await.unwrap();
        version = v["version"].as_str().map(String::from);
        wait_until("the run", || async {
            runs(&c, "pd").await == n as i64 + 1 && !c.state.feeds.is_busy("pd")
        })
        .await;
    }
    let total = q_i64(&c, "SELECT count(*) FROM policy_drops WHERE feed_id = ?1", "pd").await;
    assert_eq!(
        total,
        picket_core::feeds::ingest::MAX_DROPS_PER_FEED,
        "capped per feed"
    );
    let open = q_i64(
        &c,
        "SELECT count(*) FROM policy_drops WHERE feed_id = ?1 AND status = 'open'",
        "pd",
    )
    .await;
    assert_eq!(open, per as i64, "the latest run's rules stay open");
    let oldest = q_i64(
        &c,
        "SELECT count(*) FROM policy_drops WHERE feed_id = ?1 AND raw LIKE '% a%'",
        "pd",
    )
    .await;
    assert_eq!(oldest, 0, "the oldest resolved rows went first");
    // Resolved rows age out with the resolved-warnings window.
    exec(
        &c,
        "UPDATE policy_drops SET resolved_at = '2020-01-01T00:00:00.000000Z' WHERE status = 'resolved'",
    )
    .await;
    retention_pass(&c).await;
    let left = q_i64(&c, "SELECT count(*) FROM policy_drops WHERE feed_id = ?1", "pd").await;
    assert_eq!(left, per as i64);
}

/// F15: a deleted feed's data is retired, so a feed created again with the same id starts
/// clean: its first run skips the change-ratio gate and inherits no aggregate entries; the old
/// runs move to a tombstone id and the old entries stay closed for replay.
#[tokio::test(flavor = "multi_thread")]
async fn a_feed_created_again_starts_clean() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 50);
    let mut def = feed_def("re", "exact");
    def["modes"] = json!({"dns": {"mode": "aggregate"}});
    create_feed(&c, def.clone()).await;
    first_run(&c, "re").await;
    let old_runs = run_list(&c, "re").await;
    delete_feed(&c, "re").await;
    *body.lock().unwrap() = names("b", 50);
    create_feed(&c, def).await;
    wait_until("the new feed's first run", || async {
        run_list(&c, "re")
            .await
            .iter()
            .any(|r| !old_runs.iter().any(|o| o.0 == r.0))
            && !c.state.feeds.is_busy("re")
    })
    .await;
    let r = newest_run(&c, "re").await;
    assert_eq!(r["status"], "applied", "a first run: no change-ratio gate ({r})");
    let keys = open_keys(&c, "re").await;
    assert_eq!(keys.len(), 50);
    assert!(
        keys.iter().all(|k| k.contains("example.b")),
        "nothing inherited: {:?}",
        &keys[..3]
    );
    let list = run_list(&c, "re").await;
    assert!(
        !list.iter().any(|r| old_runs.iter().any(|o| o.0 == r.0)),
        "{list:?}"
    );
    let tomb = q_i64(
        &c,
        "SELECT count(*) FROM feed_runs WHERE feed_id LIKE ?1 || '#%'",
        "re",
    )
    .await;
    assert_eq!(
        tomb,
        old_runs.len() as i64,
        "the old runs moved to a tombstone id"
    );
    let old_closed = q_i64(
        &c,
        "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND key LIKE 'example.a%' AND removed_run IS NOT NULL",
        "re",
    )
    .await;
    assert_eq!(
        old_closed, 50,
        "the old entries are closed, kept for replay until retention"
    );
    assert_eq!(
        q_i64(&c, "SELECT count(*) FROM feed_purges WHERE feed_id = ?1", "re").await,
        0
    );
    assert_replayable(&c, "re").await;
    // Retention: no version records the old runs, so they and the old rows go.
    retention_pass(&c).await;
    assert_eq!(
        q_i64(
            &c,
            "SELECT count(*) FROM feed_runs WHERE feed_id LIKE ?1 || '#%'",
            "re"
        )
        .await,
        0
    );
    assert_eq!(
        q_i64(
            &c,
            "SELECT count(*) FROM feed_entries WHERE feed_id = ?1 AND key LIKE 'example.a%'",
            "re"
        )
        .await,
        0
    );
    assert_eq!(open_keys(&c, "re").await.len(), 50);
}

/// F11: on a cron schedule, a list's `! Expires:` spaces full downloads from the download it
/// came with; a full download with identical content counts as a download.
#[tokio::test(flavor = "multi_thread")]
async fn cron_feeds_honour_expires_from_the_new_file() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = format!(
        "! Expires: 1 day\n{}",
        (0..10).map(|i| format!("||e{i}.example^\n")).collect::<String>()
    );
    create_feed(
        &c,
        json!({"id": "cr", "name": "CR", "provider": "http", "provider_config": {"url": format!("https://{HOST}/cr.txt")},
               "format": "adblock", "schedule": {"kind": "cron", "cron": "* * * * *", "jitter": "0s"}}),
    )
    .await;
    first_run(&c, "cr").await;
    let next = c.state.feeds.next_due("cr").unwrap();
    assert!(
        next > Timestamp::now() + jiff::SignedDuration::from_hours(23),
        "next check {next}"
    );
    // What a restart recomputes the floor from.
    assert_eq!(
        q_i64(&c, "SELECT expires_s FROM feed_state WHERE feed_id = ?1", "cr").await,
        86_400
    );
    let dl1 = q_i64(
        &c,
        "SELECT count(*) FROM feed_state WHERE feed_id = ?1 AND last_download_at IS NOT NULL",
        "cr",
    )
    .await;
    assert_eq!(dl1, 1);
    let at1: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT last_download_at FROM feed_state WHERE feed_id = 'cr'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    // "Check now": a full GET with the same content is unchanged, and a download.
    tokio::time::sleep(Duration::from_millis(20)).await;
    check_now(&c, "cr").await;
    let at2: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT last_download_at FROM feed_state WHERE feed_id = 'cr'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(at2 > at1, "{at1} → {at2}");
    assert!(c.state.feeds.next_due("cr").unwrap() > Timestamp::now() + jiff::SignedDuration::from_hours(23));
}

/// F16: a failure before the provider is called is a recorded failed check that backs off; one
/// that can't be recorded backs off in memory.
#[tokio::test(flavor = "multi_thread")]
async fn failures_before_the_check_are_recorded_and_back_off() {
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 10);
    let r = ui(&c, Method::PUT, "/secrets/tok")
        .json(&json!({"value": "s3cret"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    create_feed(
        &c,
        json!({"id": "pre", "name": "Pre", "provider": "http", "format": "plain",
               "provider_config": {"url": format!("https://{HOST}/pre.txt"), "headers": {"x-token": "${secret:tok}"}}}),
    )
    .await;
    first_run(&c, "pre").await;
    // The secrets can't be read (a database error): a failed check, recorded.
    exec(&c, "ALTER TABLE secrets RENAME TO secrets_gone").await;
    check_now(&c, "pre").await;
    exec(&c, "ALTER TABLE secrets_gone RENAME TO secrets").await;
    let st = get_json(&c, "/feeds/pre/status").await;
    assert_eq!(st["failures"], 1, "{st}");
    let err: Option<String> = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT error FROM feed_checks WHERE feed_id = 'pre' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(err.is_some_and(|e| !e.contains("s3cret")));
    assert!(st["failing_since"].is_string());
    // Nothing can be recorded (the check history is gone): the backoff grows in memory.
    exec(&c, "ALTER TABLE feed_checks RENAME TO feed_checks_gone").await;
    let mut gaps = vec![];
    for _ in 0..2 {
        c.state.feeds.clear_last_check("pre");
        let t0 = Timestamp::now();
        picket_core::feeds::check::run(c.state.clone(), "pre".into(), picket_core::feeds::Cause::CheckNow)
            .await;
        gaps.push((c.state.feeds.next_due("pre").unwrap() - t0).as_secs());
    }
    exec(&c, "ALTER TABLE feed_checks_gone RENAME TO feed_checks").await;
    assert!(gaps[0] >= 55 && gaps[1] >= 115, "{gaps:?}");
}

/// F9: the warm-start history runs inside the check's light-lane job, and a rate-limited
/// history pauses the provider like a rate-limited check (no `ls-refs` is sent).
#[tokio::test(flavor = "multi_thread")]
async fn a_rate_limited_history_pauses_the_provider() {
    let srv = TestServer::start(
        &["github.com", "api.github.com", "raw.githubusercontent.com"],
        |s: &Seen| {
            if s.host.starts_with("api.github.com") && s.path.contains("/commits") {
                return Reply::status(429).header("retry-after", "600");
            }
            Reply::status(500)
        },
    )
    .await;
    let c = core_with(Some(&srv), None).await;
    // A provider whose stored listing selects list.txt: its feed exists before any check.
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&json!({"id": "gh", "name": "GH", "enabled": false, "module": "github", "config": {"owner": "o", "repo": "r"},
                      "files": [{"match": "list.txt", "feed": {"format": "adblock"}}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    exec(&c, r#"UPDATE feed_provider_state SET listing_json = '{"files": ["list.txt"], "whole": true}' WHERE provider_id = 'gh'"#).await;
    let r = ui(&c, Method::PUT, "/feed-providers/gh")
        .json(
            &json!({"name": "GH", "enabled": true, "module": "github", "config": {"owner": "o", "repo": "r"},
                      "files": [{"match": "list.txt", "feed": {"format": "adblock"}}]}),
        )
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["feeds_added"], json!(["gh-list"]), "{v}");
    wait_until("the first check", || async {
        checks(&c, "gh-list").await >= 1 && !c.state.feeds.is_busy("gh-list")
    })
    .await;
    let until = c.state.feeds.paused_until("github");
    assert!(
        until.is_some_and(|u| u > Timestamp::now() + jiff::SignedDuration::from_mins(5)),
        "{until:?}"
    );
    let err: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT error FROM feed_checks WHERE feed_id = 'gh-list' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(err.contains("rate limited"), "{err}");
    assert!(
        !srv.seen().iter().any(|s| s.path.ends_with("git-upload-pack")),
        "no check request while rate limited"
    );
}

/// F10: a client that stops sending its upload holds neither the feed's save lock nor a
/// blocking thread: another save to the same feed goes through meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_upload_holds_no_lock() {
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "m", "name": "M", "provider": "manual", "format": "plain"}),
    )
    .await;
    // A body that sends its start and then nothing.
    let stalled = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(bytes::Bytes::from_static(
        b"{\"base_version\": null, \"content\": \"a.example\\n",
    ))])
    .chain(futures_util::stream::pending());
    let req = ui(&c, Method::PUT, "/feeds/m/file")
        .header("content-type", "application/json")
        .body(reqwest::Body::wrap_stream(stalled))
        .send();
    let stalled_task = tokio::spawn(req);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        ui(&c, Method::PUT, "/feeds/m/file")
            .json(&json!({"content": "b.example\n", "base_version": null}))
            .send(),
    )
    .await
    .expect("the second save isn't blocked by the stalled one")
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("the run", || async {
        runs(&c, "m").await == 1 && !c.state.feeds.is_busy("m")
    })
    .await;
    assert_eq!(open_keys(&c, "m").await, vec!["dns:example.b"]);
    stalled_task.abort();
}

use futures_util::StreamExt as _;
use jiff::Timestamp;

/// A server for the in-flight races: `/<feed>.txt` serves `a` names, slowly (one chunk after
/// `delay`) once `slow` is set, with ETag `"v1"` (fast) or `"v2"` (slow); `/new.txt` serves `c`
/// names at once with ETag `"v3"`. A matching `If-None-Match` gets 304.
async fn race_server(delay: Duration) -> (TestServer, Arc<std::sync::atomic::AtomicBool>) {
    use picket_core::modules::download::testkit::ReplyBody;
    use std::sync::atomic::{AtomicBool, Ordering};
    let slow = Arc::new(AtomicBool::new(false));
    let s = slow.clone();
    let srv = TestServer::start(&[HOST], move |seen: &Seen| {
        let new = seen.path.trim_end_matches('/') == "/new.txt";
        let slow = s.load(Ordering::SeqCst);
        let tag = match (new, slow) {
            (true, _) => "\"v3\"",
            (false, true) => "\"v2\"",
            (false, false) => "\"v1\"",
        };
        if seen.header("if-none-match") == Some(tag) {
            return Reply::status(304).header("etag", tag);
        }
        if new {
            return Reply::ok(names("c", 50)).header("etag", tag);
        }
        if !slow {
            return Reply::ok(names("a", 50)).header("etag", tag);
        }
        Reply {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/plain".into()),
                ("etag".into(), tag.into()),
            ],
            body: ReplyBody::Slow {
                chunk: bytes::Bytes::from(format!("{}{}", names("a", 50), names("b", 1))),
                count: 1,
                delay,
            },
        }
    })
    .await;
    (srv, slow)
}

/// Starts a check of `feed` whose download is slow, and waits until its request is in flight.
async fn start_slow_check(c: &Core, srv: &TestServer, slow: &std::sync::atomic::AtomicBool, feed: &str) {
    srv.clear();
    slow.store(true, std::sync::atomic::Ordering::SeqCst);
    c.state.feeds.clear_last_check(feed);
    let _ = c
        .state
        .feeds
        .trigger_provider(&c.state, feed, picket_core::feeds::Cause::CheckNow);
    wait_until("the in-flight request", || async { !srv.seen().is_empty() }).await;
}

/// FR1 (feeds.md §5 "skipped on a feed's first run"; storage.md §4): a check in flight when its
/// feed is deleted and created again stores nothing: no run, no `last`, no check state for the
/// new feed, whose first download is its own source's.
#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_feeds_inflight_check_never_reaches_the_feed_created_again() {
    let (srv, slow) = race_server(Duration::from_secs(8)).await;
    let c = core_with(Some(&srv), None).await;
    let mut def = feed_def("race", "exact");
    def["modes"] = json!({"dns": {"mode": "aggregate"}});
    create_feed(&c, def.clone()).await;
    first_run(&c, "race").await;
    start_slow_check(&c, &srv, &slow, "race").await;
    delete_feed(&c, "race").await;
    def["provider_config"]["url"] = json!(format!("https://{HOST}/new.txt"));
    create_feed(&c, def).await;
    wait_until("the new feed's first run", || async {
        q_i64(&c, "SELECT count(*) FROM feed_purges WHERE feed_id = ?1", "race").await == 0
            && !open_keys(&c, "race").await.is_empty()
            && !c.state.feeds.is_busy("race")
    })
    .await;
    let keys = open_keys(&c, "race").await;
    let list = run_list(&c, "race").await;
    assert_eq!(
        keys,
        names("c", 50)
            .lines()
            .map(|n| {
                let mut l: Vec<&str> = n.split('.').collect();
                l.reverse();
                format!("dns:{}", l.join("."))
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>(),
        "the new feed holds only its own source's names: {list:?}"
    );
    assert_eq!(list.len(), 1, "one run, the new source's first: {list:?}");
    let last = q_i64(
        &c,
        "SELECT count(*) FROM feed_state WHERE feed_id = ?1 AND last_json LIKE '%v3%'",
        "race",
    )
    .await;
    assert_eq!(last, 1, "`last` is the new source's");
}

/// FR1: a run whose job was set up for the deleted feed (queued before the deletion, stepped
/// after the purge) ends with nothing in the feed created again.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_from_before_a_deletion_changes_nothing_in_the_feed_created_again() {
    let c = core_with(None, None).await;
    let def = json!({"id": "x", "name": "X", "provider": "manual", "format": "plain", "modes": {"dns": {"mode": "aggregate"}}});
    create_feed(&c, def.clone()).await;
    let r = ui(&c, Method::PUT, "/feeds/x/file")
        .json(&json!({"content": "a.example\n", "base_version": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("run 1", || async {
        runs(&c, "x").await == 1 && !c.state.feeds.is_busy("x")
    })
    .await;
    // The old feed's download, queued before the deletion.
    let blob = store_blob(&c, "x", b"old-source.example\n").await;
    let mut job = download_job(&c, "x", blob).await;
    delete_feed(&c, "x").await;
    create_feed(&c, def).await;
    wait_until("the purge", || async {
        q_i64(&c, "SELECT count(*) FROM feed_purges WHERE feed_id = ?1", "x").await == 0
            && !c.state.feeds.is_busy("x")
    })
    .await;
    for _ in 0..20 {
        if job.step().await.unwrap() == Step::Done {
            break;
        }
    }
    drop(job);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let keys = open_keys(&c, "x").await;
    let list = run_list(&c, "x").await;
    assert!(
        !keys.iter().any(|k| k.contains("old-source")),
        "the new feed inherited the deleted feed's download: {keys:?} {list:?}"
    );
    assert!(list.is_empty(), "no run for the new feed: {list:?}");
}

/// FR2 (feeds.md §3 "Editing a feed"): a check in flight when `provider_config` changes stores
/// nothing, so the cleared `last` stays cleared and the new source's check is a first check.
#[tokio::test(flavor = "multi_thread")]
async fn a_source_edit_during_a_check_keeps_last_cleared() {
    let (srv, slow) = race_server(Duration::from_secs(6)).await;
    let c = core_with(Some(&srv), None).await;
    let mut def = feed_def("edit", "exact");
    create_feed(&c, def.clone()).await;
    first_run(&c, "edit").await;
    start_slow_check(&c, &srv, &slow, "edit").await;
    def["provider_config"]["url"] = json!(format!("https://{HOST}/new.txt"));
    update_feed(&c, "edit", def).await;
    wait_until("the new source's first check", || async {
        srv.seen()
            .iter()
            .any(|x| x.path.trim_end_matches('/') == "/new.txt")
            && !c.state.feeds.is_busy("edit")
    })
    .await;
    let seen = srv.seen();
    let first = seen
        .iter()
        .find(|x| x.path.trim_end_matches('/') == "/new.txt")
        .unwrap();
    assert!(
        first.header("if-none-match").is_none(),
        "the old source's validators reached the new one: {:?}",
        first.headers
    );
    // The old source's slow download never became a run.
    assert!(
        !open_keys(&c, "edit")
            .await
            .iter()
            .any(|k| k.contains("example.b0")),
        "{:?}",
        run_list(&c, "edit").await
    );
}

/// FR3 (core.md §3; feeds.md §3): an undo the full heavy queue refuses still runs in the lane
/// (a reserved place), never next to another heavy job.
#[tokio::test(flavor = "multi_thread")]
async fn an_undo_refused_by_a_full_heavy_queue_still_waits_in_the_lane() {
    use picket_core::scheduler::{HeavyLane, Priority, Submitted};
    let c = core_with(None, None).await;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    assert_eq!(
        c.state
            .scheduler
            .heavy
            .submit_fn("block", "test", Priority::P0, move || async move {
                let _ = entered_tx.send(());
                let _ = release_rx.await;
                Ok(())
            }),
        Submitted::Queued
    );
    entered_rx.await.unwrap();
    exec(
        &c,
        "INSERT INTO feed_run_ids(feed_id, at) VALUES ('u', '2026-01-01');
         INSERT INTO feed_runs_open(run_id, feed_id, started_at) VALUES (last_insert_rowid(), 'u', '2026-01-01');",
    )
    .await;
    let id = q_i64(&c, "SELECT run_id FROM feed_runs_open WHERE feed_id = ?1", "u").await;
    for n in 0..HeavyLane::CAP {
        let s = c
            .state
            .scheduler
            .heavy
            .submit_fn("fill", &format!("t{n}"), Priority::P3, || async { Ok(()) });
        if s == Submitted::Dropped {
            break;
        }
    }
    assert_eq!(c.state.scheduler.heavy.depth(), HeavyLane::CAP);
    picket_core::feeds::undo::UndoJob::new(c.state.clone(), "u", id).submit();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let open = q_i64(&c, "SELECT count(*) FROM feed_runs_open WHERE feed_id = ?1", "u").await;
    let _ = release_tx.send(());
    assert_eq!(open, 1, "the undo ran next to the blocked heavy job");
    // It runs once the lane is free (P0, before the queued P3 jobs).
    wait_until("the undo", || async {
        q_i64(&c, "SELECT count(*) FROM feed_runs_open WHERE feed_id = ?1", "u").await == 0
    })
    .await;
}

/// FR1, FR2: a run set up before a change of its feed: after a source edit the run is stored
/// (the file was the feed's when fetched) but the edit's cleared `last` stays cleared; after a
/// deletion the run is undone and nothing of it stays.
#[tokio::test(flavor = "multi_thread")]
async fn a_source_edit_or_a_deletion_during_a_run() {
    use picket_core::scheduler::{Priority, Submitted};
    let (srv, body) = list_server().await;
    let c = core_with(Some(&srv), None).await;
    *body.lock().unwrap() = names("a", 50);
    for id in ["ed", "del"] {
        create_feed(&c, feed_def(id, "exact")).await;
        first_run(&c, id).await;
        // Disabled: no check of the runtime's own races the job driven here.
        let mut d = feed_def(id, "exact");
        d["enabled"] = json!(false);
        update_feed(&c, id, d).await;
    }
    // The source edit, between the run's setup and its other steps.
    let blob = store_blob(&c, "ed", format!("{}x.example\n", names("a", 50)).as_bytes()).await;
    let mut job = download_job(&c, "ed", blob).await;
    assert_eq!(job.step().await.unwrap(), Step::More);
    let mut d = feed_def("ed", "exact");
    d["enabled"] = json!(false);
    d["provider_config"]["url"] = json!(format!("https://{HOST}/other.txt"));
    update_feed(&c, "ed", d).await;
    while job.step().await.unwrap() == Step::More {}
    drop(job);
    let list = run_list(&c, "ed").await;
    assert_eq!(list.len(), 2, "{list:?}");
    assert_eq!(list[1].1, "applied");
    assert!(open_keys(&c, "ed").await.contains(&"dns:example.x".to_string()));
    let last = q_i64(
        &c,
        "SELECT count(*) FROM feed_state WHERE feed_id = ?1 AND last_json IS NULL",
        "ed",
    )
    .await;
    assert_eq!(last, 1, "the edit's cleared `last` stays cleared");
    // The deletion: the purge waits behind a blocked heavy lane, as it waits for a busy feed.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    assert_eq!(
        c.state
            .scheduler
            .heavy
            .submit_fn("block", "test", Priority::P0, move || async move {
                let _ = release_rx.await;
                Ok(())
            }),
        Submitted::Queued
    );
    let blob = store_blob(&c, "del", format!("{}y.example\n", names("a", 50)).as_bytes()).await;
    let mut job = download_job(&c, "del", blob).await;
    assert_eq!(job.step().await.unwrap(), Step::More);
    let run = q_i64(&c, "SELECT run_id FROM feed_runs_open WHERE feed_id = ?1", "del").await;
    delete_feed(&c, "del").await;
    let mut failed = false;
    for _ in 0..20 {
        match job.step().await {
            Ok(Step::More) => {}
            Ok(Step::Done) => break,
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    drop(job);
    assert!(failed, "the run of a deleted feed isn't stored");
    let rows = q_i64(
        &c,
        &format!("SELECT count(*) FROM feed_entries WHERE first_run = {run} AND ?1 = ?1"),
        "del",
    )
    .await;
    let stored = q_i64(
        &c,
        &format!("SELECT count(*) FROM feed_runs WHERE id = {run} AND ?1 = ?1"),
        "del",
    )
    .await;
    let open = q_i64(
        &c,
        "SELECT count(*) FROM feed_runs_open WHERE feed_id = ?1",
        "del",
    )
    .await;
    assert_eq!((rows, stored, open), (0, 0, 0), "the run is undone");
    let _ = release_tx.send(());
}

/// FR4 (core.md §3; build-and-test.md §6): a parse step reads at most about `STEP_BYTES` of the
/// file, whether its lines are staged or not: a large file of parse errors and `drop`-mode rules
/// is read in many steps, not one.
#[tokio::test(flavor = "multi_thread")]
async fn a_parse_step_is_bounded_by_the_bytes_read() {
    use picket_core::feeds::ingest::STEP_BYTES;
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "big", "name": "Big", "provider": "manual", "format": "plain",
               "modes": {"dns": {"mode": "replace"}, "ip": {"mode": "drop"}}}),
    )
    .await;
    let mut text = String::from("kept.example\n");
    let mut i = 0u64;
    while (text.len() as u64) < 3 * STEP_BYTES + STEP_BYTES / 2 {
        text.push_str(&format!(
            "10.{}.{}.{}\n",
            (i >> 16) & 255,
            (i >> 8) & 255,
            i & 255
        ));
        text.push_str(&format!(
            "not a rule at all, line {i} ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        ));
        i += 1;
    }
    let blob = store_blob(&c, "big", text.as_bytes()).await;
    let mut job = download_job(&c, "big", blob).await;
    let mut steps = 0u64;
    loop {
        steps += 1;
        if job.step().await.unwrap() == Step::Done {
            break;
        }
        assert!(steps < 1000);
    }
    drop(job);
    // Setup, at least 3.5 MiB-worth of parse steps, gates, finalize.
    let parse_steps = text.len() as u64 / STEP_BYTES;
    assert!(steps >= 3 + parse_steps, "{steps} steps for {} bytes", text.len());
    let r = newest_run(&c, "big").await;
    assert!(
        r["status"] == "rejected" || r["status"] == "applied",
        "the whole file was read and judged: {r}"
    );
}

/// FR5 (feeds.md §5): under a cron trigger, a scheduled check leaves out a feed before its
/// list's `! Expires:` floor (no check recorded for it), while a feed past none is checked;
/// "Check now" is exempt.
#[tokio::test(flavor = "multi_thread")]
async fn a_cron_providers_check_leaves_out_a_feed_before_its_expires_floor() {
    let bodies: Arc<Mutex<std::collections::HashMap<String, String>>> = Arc::default();
    let b = bodies.clone();
    let srv = TestServer::start(&[HOST], move |s: &Seen| {
        Reply::ok(
            b.lock()
                .unwrap()
                .get(s.path.as_str())
                .cloned()
                .unwrap_or_default(),
        )
    })
    .await;
    bodies.lock().unwrap().insert(
        "/cr.txt".into(),
        format!(
            "! Expires: 1 day\n{}",
            (0..10).map(|i| format!("||e{i}.example^\n")).collect::<String>()
        ),
    );
    bodies.lock().unwrap().insert("/dyn.txt".into(), names("d", 10));
    let c = core_with(Some(&srv), None).await;
    // Two cron providers (an http provider is one URL): `p`'s list sets a floor, `d`'s none.
    for (id, file, format) in [("p", "cr.txt", "adblock"), ("d", "dyn.txt", "plain")] {
        let r = ui(&c, Method::POST, "/feed-providers")
            .json(&json!({"id": id, "name": id, "module": "http", "config": {"url": format!("https://{HOST}/{file}")},
                          "trigger": {"kind": "cron", "cron": "* * * * *", "jitter": "0s"},
                          "files": [{"match": "response", "feed": {"format": format}}]}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
    }
    first_run(&c, "p").await;
    first_run(&c, "d").await;
    wait_until("the providers to be free", || async {
        !c.state.feeds.is_checking("p") && !c.state.feeds.is_checking("d")
    })
    .await;
    let (cr, dy) = (checks(&c, "p").await, checks(&c, "d").await);
    // Scheduled checks: `d` is checked, `p`'s feed waits for its floor.
    bodies.lock().unwrap().insert("/dyn.txt".into(), names("d", 11));
    for id in ["p", "d"] {
        c.state.feeds.clear_last_check(id);
        picket_core::feeds::check::run(c.state.clone(), id.into(), picket_core::feeds::Cause::Trigger).await;
    }
    wait_until("d's run", || async { !c.state.feeds.is_busy("d") }).await;
    assert_eq!(checks(&c, "d").await, dy + 1);
    assert_eq!(
        checks(&c, "p").await,
        cr,
        "the cron feed wasn't checked before its floor"
    );
    // "Check now" is exempt.
    check_now(&c, "p").await;
    assert_eq!(checks(&c, "p").await, cr + 1);
}

/// FR6 (feeds.md §1 "a save is the download"): a manual save whose run can't be queued (the
/// heavy lane is full) runs later, without another save.
#[tokio::test(flavor = "multi_thread")]
async fn a_manual_save_whose_run_cant_be_queued_is_retried() {
    use picket_core::scheduler::{HeavyLane, Priority, Submitted};
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "m", "name": "M", "provider": "manual", "format": "plain"}),
    )
    .await;
    // Block the heavy lane and fill its queue.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    assert_eq!(
        c.state
            .scheduler
            .heavy
            .submit_fn("block", "test", Priority::P0, move || async move {
                let _ = entered_tx.send(());
                let _ = release_rx.await;
                Ok(())
            }),
        Submitted::Queued
    );
    entered_rx.await.unwrap();
    for n in 0..HeavyLane::CAP {
        if c.state
            .scheduler
            .heavy
            .submit_fn("fill", &format!("t{n}"), Priority::P3, || async { Ok(()) })
            == Submitted::Dropped
        {
            break;
        }
    }
    let r = ui(&c, Method::PUT, "/feeds/m/file")
        .json(&json!({"content": "a.example\n", "base_version": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("the retry", || async {
        c.state.feeds.manual_retry("m").is_some() && !c.state.feeds.is_busy("m")
    })
    .await;
    assert_eq!(runs(&c, "m").await, 0);
    // The lane frees up; the retry (moved to now here, a minute in core) runs the saved file.
    let _ = release_tx.send(());
    wait_until("the queue to drain", || async {
        c.state.scheduler.heavy.depth() == 0
    })
    .await;
    c.state.feeds.retry_manual("m", Timestamp::now());
    wait_until("the saved file's run", || async {
        runs(&c, "m").await == 1 && !c.state.feeds.is_busy("m")
    })
    .await;
    assert_eq!(open_keys(&c, "m").await, vec!["dns:example.a"]);
    assert!(c.state.feeds.manual_retry("m").is_none());
}

/// A request body that sends `first` and then nothing.
fn stalled_body(first: Vec<u8>) -> reqwest::Body {
    reqwest::Body::wrap_stream(
        futures_util::stream::iter(vec![Ok::<_, std::io::Error>(bytes::Bytes::from(first))])
            .chain(futures_util::stream::pending()),
    )
}

/// FR7 (README §2 Bounded): at most `MAX_UPLOADS` manual feed uploads run at once, and their
/// spools share a byte budget; past either, `503`.
#[tokio::test(flavor = "multi_thread")]
async fn manual_uploads_are_bounded_in_number_and_spool_bytes() {
    use picket_core::feeds::manual::MAX_UPLOADS;
    let c = core_with(None, Some(json!({"feeds": {"max_download_mib": 1}}))).await;
    create_feed(
        &c,
        json!({"id": "m", "name": "M", "provider": "manual", "format": "plain"}),
    )
    .await;
    let put = |b: reqwest::Body| {
        ui(&c, Method::PUT, "/feeds/m/file")
            .header("content-type", "application/json")
            .body(b)
            .send()
    };
    let start = br#"{"base_version": null, "content": "a.example\n"#.to_vec();
    let stalled: Vec<_> = (0..MAX_UPLOADS)
        .map(|_| tokio::spawn(put(stalled_body(start.clone()))))
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r = put(reqwest::Body::from(
        json!({"content": "b.example\n", "base_version": null}).to_string(),
    ))
    .await
    .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        r.text().await.unwrap()
    );
    for t in stalled {
        t.abort();
    }
    // The slots come back with the stalled requests; two big spools then fill most of the shared
    // bytes (2 × one upload's cap of ≈ 2.2 MB at 1 MiB): a third body past what is left is
    // refused.
    let big = |n: usize| {
        let mut b = start.clone();
        b.extend(std::iter::repeat_n(b'x', n));
        b
    };
    wait_until("free upload slots", || async {
        let r = put(reqwest::Body::from(
            json!({"content": "c.example\n", "base_version": null}).to_string(),
        ))
        .await
        .unwrap();
        r.status() != StatusCode::SERVICE_UNAVAILABLE
    })
    .await;
    let spools: Vec<_> = (0..2)
        .map(|_| tokio::spawn(put(stalled_body(big(2_090_000)))))
        .collect();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let r = put(reqwest::Body::from(big(300_000))).await.unwrap();
    assert_eq!(
        r.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        r.text().await.unwrap()
    );
    for t in spools {
        t.abort();
    }
}

/// FP15 (feed-scheduling.md §4: failed or voided checks never train the model): a check in
/// flight when its feed is deleted and its file added again (a new feed under the same id)
/// stores nothing, and its outcome doesn't train the new feed's model either.
#[tokio::test(flavor = "multi_thread")]
async fn a_voided_check_trains_no_model() {
    let (srv, slow) = race_server(Duration::from_secs(4)).await;
    let c = core_with(Some(&srv), None).await;
    create_feed(&c, feed_def("race", "exact")).await;
    first_run(&c, "race").await;
    start_slow_check(&c, &srv, &slow, "race").await;
    let r = ui(&c, Method::DELETE, "/feeds/race")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    slow.store(false, std::sync::atomic::Ordering::SeqCst);
    let r = ui(&c, Method::POST, "/feed-providers/race/files")
        .json(&json!({"file": "response", "feed": {"format": "plain"}}))
        .send()
        .await
        .unwrap();
    let st = r.status();
    assert_eq!(st, StatusCode::OK, "{}", r.text().await.unwrap());
    wait_until("the new feed's first check", || async {
        q_i64(&c, "SELECT count(*) FROM feed_purges WHERE feed_id = ?1", "race").await == 0
            && checks(&c, "race").await >= 1
            && !c.state.feeds.is_busy("race")
            && !c.state.feeds.is_checking("race")
    })
    .await;
    let l = c.state.feeds.learner("race").unwrap();
    assert_eq!(
        l.checks.len(),
        1,
        "only the new feed's own check trained it: {:?}",
        l.checks
    );
}

/// FP7 (core.md §3, build-and-test.md §6): a `misp-warninglist` file's metadata passes (its
/// list `type` and `picket_first_seen` map) count toward a parse step's bytes like the rule
/// parser's, so a large document is read in many bounded steps, never one long one.
#[tokio::test(flavor = "multi_thread")]
async fn misp_metadata_passes_are_bounded_by_the_bytes_read() {
    use picket_core::feeds::ingest::STEP_BYTES;
    let c = core_with(None, None).await;
    create_feed(
        &c,
        json!({"id": "mispbig", "name": "MISP big", "provider": "manual", "format": "misp-warninglist"}),
    )
    .await;
    // A short list after a long ignored array, so `type` and the dates come late.
    let mut pad = String::new();
    let mut i = 0u64;
    while (pad.len() as u64) < 4 * STEP_BYTES {
        pad.push_str(&format!("\"padding value {i} ~~~~~~~~~~~~~~~~~~~~~~~~\","));
        i += 1;
    }
    pad.pop();
    let doc = format!(
        "{{\"name\": \"x\", \"padding\": [{pad}], \"type\": \"hostname\", \"list\": [\"a.example\"], \
         \"picket_first_seen\": {{\"a.example\": \"2020-01-01\"}}}}"
    );
    let blob = store_blob(&c, "mispbig", doc.as_bytes()).await;
    let mut job = download_job(&c, "mispbig", blob).await;
    let mut steps = 0u64;
    loop {
        steps += 1;
        if job.step().await.unwrap() == Step::Done {
            break;
        }
        assert!(steps < 1000);
    }
    drop(job);
    // The rule parser reads the document twice (type, then values); the type and date passes
    // twice more: about 4 × 8 MiB in 2 MiB steps.
    let per_pass = doc.len() as u64 / STEP_BYTES;
    assert!(
        steps >= 3 + 3 * per_pass,
        "{steps} steps for 4 passes over {} bytes",
        doc.len()
    );
    let keys = open_keys(&c, "mispbig").await;
    assert_eq!(keys.len(), 1, "{keys:?}");
}

/// FP9 (feeds.md §3 step 1): "Check now" waits for a busy feed the same way a check does: the
/// check leaves the feed out (no check recorded for it), and once its run is stored another
/// check, for the same cause, covers it.
#[tokio::test(flavor = "multi_thread")]
async fn check_now_waits_for_a_busy_feed() {
    use picket_core::scheduler::Priority;
    let srv = TestServer::start(&[HOST], |_s: &Seen| Reply::ok("a.example\nb.example\n")).await;
    let c = core_with(Some(&srv), None).await;
    create_feed(&c, feed_def("busy", "exact")).await;
    first_run(&c, "busy").await;
    let gate = Arc::new(tokio::sync::Notify::new());
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
    // Its re-ingest waits behind the blocking job: the feed is busy.
    let mut f: Value = client()
        .get(url(&c, "/feeds/busy"))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    f["modes"]["dns"] = json!({"mode": "aggregate"});
    let r = ui(&c, Method::PUT, "/feeds/busy").json(&f).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("the feed busy", || async { c.state.feeds.is_busy("busy") }).await;
    let by_check_now = || async {
        q_i64(
            &c,
            "SELECT count(*) FROM feed_checks fc JOIN feed_provider_checks pc ON pc.id = fc.provider_check_id
             WHERE fc.feed_id = ?1 AND pc.cause = 'check_now'",
            "busy",
        )
        .await
    };
    let provider_checks = || async {
        q_i64(
            &c,
            "SELECT count(*) FROM feed_provider_checks WHERE provider_id = ?1 AND cause = 'check_now'",
            "busy",
        )
        .await
    };
    c.state.feeds.clear_last_check("busy");
    let r = ui(&c, Method::POST, "/feed-providers/busy/check")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    wait_until("the check", || async {
        provider_checks().await == 1 && !c.state.feeds.is_checking("busy")
    })
    .await;
    assert_eq!(by_check_now().await, 0, "the busy feed was left out");
    assert_eq!(c.state.feeds.owed("busy"), Some("check_now"));
    gate.notify_one();
    wait_until("the run stored", || async { !c.state.feeds.is_busy("busy") }).await;
    c.state.feeds.clear_last_check("busy");
    wait_until("the check that covers it", || async { by_check_now().await == 1 }).await;
    assert_eq!(provider_checks().await, 2);
}
