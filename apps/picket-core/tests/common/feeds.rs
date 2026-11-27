//! Feed helpers shared by the feed tests: a running core with download modules pointed at a
//! local HTTPS server, and feeds written as one body.
//!
//! **One body per feed:** a test writes a downloaded feed as
//! `{id, …settings, "provider": "<module>", "provider_config": {"url": …, …}, "schedule"?}`.
//! [`create_feed`] makes it a feed provider whose id is the feed's id, whose config is
//! `provider_config` (an `http` provider: the URL), and whose one `files` entry carries the
//! feed's settings (`response` for `http`, a `path` for `github`), so the feed core creates for
//! it has the test's id (feeds.md §1: a provider of one fixed file gives its feed its id). A
//! manual feed (`"provider": "manual"`, or none) is created as is. [`check_now`] checks the
//! feed's provider.

use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{Core, client};

pub fn url(c: &Core, path: &str) -> String {
    format!("{}/api/ui/v1{path}", c.base("http"))
}

pub fn ui(c: &Core, method: Method, path: &str) -> reqwest::RequestBuilder {
    client()
        .request(method, url(c, path))
        .basic_auth("admin", Some(&c.init.password))
        .header("X-Picket-UI", "1")
}

/// Waits (generously: CI is slow) until `f` holds.
pub async fn wait_until<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..600 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

/// The keys of a feed body that belong to its provider, or to core.
const PROVIDER_KEYS: &[&str] = &[
    "id",
    "name",
    "provider",
    "provider_config",
    "schedule",
    "enabled",
    "system",
    "file",
];

/// A test's feed body split into its provider (`None` for a manual feed) and its feed settings.
pub fn split(body: &Value) -> (Option<Value>, Value) {
    let module = body.get("provider").and_then(Value::as_str).unwrap_or("manual");
    let mut feed = body.clone();
    let o = feed.as_object_mut().expect("a feed body is an object");
    if module == "manual" {
        o.remove("provider");
        o.remove("provider_config");
        o.remove("schedule");
        return (None, feed);
    }
    let id = body["id"].as_str().unwrap_or_default().to_string();
    let mut config = body.get("provider_config").cloned().unwrap_or_else(|| json!({}));
    let co = config.as_object_mut().expect("provider_config is an object");
    // An http provider is one URL (`provider_config.url`), its one file `response`; its feed
    // takes the provider's id, the test's (feeds.md §1).
    let mut files = json!([{ "match": "response" }]);
    if module == "github"
        && let Some(p) = co.remove("path").and_then(|p| p.as_str().map(str::to_string))
    {
        files = json!([{"match": p}]);
    }
    let mut template = serde_json::Map::new();
    for (k, v) in body.as_object().unwrap() {
        if !PROVIDER_KEYS.contains(&k.as_str()) {
            template.insert(k.clone(), v.clone());
        }
    }
    template.entry("format").or_insert(json!("adblock"));
    files[0]["feed"] = Value::Object(template);
    let mut provider = json!({"id": id, "name": body.get("name").cloned().unwrap_or(json!(id)), "module": module, "config": config, "files": files});
    if let Some(s) = body.get("schedule") {
        provider["trigger"] = s.clone();
    }
    for k in PROVIDER_KEYS {
        if *k != "name" {
            o.remove(*k);
        }
    }
    (Some(provider), feed)
}

/// Creates a test's feed (its provider first, for a downloaded one) and waits until the runtime
/// knows it.
pub async fn create_feed(c: &Core, body: Value) {
    let id = body["id"].as_str().unwrap_or_default().to_string();
    let (provider, mut feed) = split(&body);
    match provider {
        None => {
            let r = ui(c, Method::POST, "/feeds").json(&feed).send().await.unwrap();
            let st = r.status();
            let t = r.text().await.unwrap();
            assert_eq!(st, StatusCode::CREATED, "{t}");
        }
        Some(p) => {
            let r = ui(c, Method::POST, "/feed-providers")
                .json(&p)
                .send()
                .await
                .unwrap();
            let st = r.status();
            let t = r.text().await.unwrap();
            assert_eq!(st, StatusCode::CREATED, "{t}");
            let v: Value = serde_json::from_str(&t).unwrap();
            assert_eq!(v["feeds_added"], json!([id]), "{t}");
            // A new provider feed is enabled (feeds.md §1); a test's disabled one is disabled now.
            if body.get("enabled") == Some(&json!(false)) {
                feed["enabled"] = json!(false);
                if let Some(o) = feed.as_object_mut() {
                    o.entry("format").or_insert(json!("adblock"));
                }
                let r = ui(c, Method::PUT, &format!("/feeds/{id}"))
                    .json(&feed)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(r.status(), StatusCode::OK);
            }
        }
    }
    let s = c.state.clone();
    let f = id.clone();
    wait_until("the runtime to know the feed", || {
        let (s, f) = (s.clone(), f.clone());
        async move { s.feeds.def_or_reload(&s, &f).await.is_some() }
    })
    .await;
}

/// Updates a test's feed: its provider when the body's provider part differs from the stored
/// one, then its settings. Returns the feed save's outcome.
pub async fn update_feed(c: &Core, id: &str, body: Value) -> Value {
    let mut full = body.clone();
    full["id"] = json!(id);
    let (provider, mut feed) = split(&full);
    if let Some(mut p) = provider {
        let r = client()
            .get(url(c, &format!("/feed-providers/{id}")))
            .basic_auth("admin", Some(&c.init.password))
            .send()
            .await
            .unwrap();
        let cur: Value = r.json().await.unwrap();
        // The stored files keep their settings: only the provider's own fields change here.
        p["files"] = cur["files"].clone();
        p["exclude"] = cur["exclude"].clone();
        if p.get("trigger").is_none() {
            p["trigger"] = cur["trigger"].clone();
        }
        if p["config"] != cur["config"] || p["trigger"] != cur["trigger"] {
            let r = ui(c, Method::PUT, &format!("/feed-providers/{id}"))
                .json(&p)
                .send()
                .await
                .unwrap();
            let st = r.status();
            let v: Value = r.json().await.unwrap();
            assert_eq!(st, StatusCode::OK, "{v}");
        }
    }
    if let Some(o) = feed.as_object_mut() {
        o.remove("id");
        o.entry("format").or_insert(json!("adblock"));
    }
    if body.get("enabled").is_some() {
        feed["enabled"] = body["enabled"].clone();
    }
    let r = ui(c, Method::PUT, &format!("/feeds/{id}"))
        .json(&feed)
        .send()
        .await
        .unwrap();
    let st = r.status();
    let v: Value = r.json().await.unwrap();
    assert_eq!(st, StatusCode::OK, "{v}");
    v
}

/// Checks recorded for a feed (warm-start rows left out).
pub async fn checks(c: &Core, feed: &str) -> i64 {
    let f = feed.to_string();
    c.state
        .db
        .read(move |db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT count(*) FROM feed_checks WHERE feed_id = ?1 AND method <> 'bootstrap' AND method <> 'history'",
                [f],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap()
}

/// "Check now" on a provider (its `min_interval` forgotten); `Accepted` expected.
pub async fn check_provider(c: &Core, provider: &str) -> Value {
    c.state.feeds.clear_last_check(provider);
    let r = ui(c, Method::POST, &format!("/feed-providers/{provider}/check"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    r.json().await.unwrap()
}

/// Checks a feed now through its provider and waits until the check is recorded and the feed is
/// free again (its run, if any, stored).
pub async fn check_now(c: &Core, feed: &str) {
    let before = checks(c, feed).await;
    let provider = c
        .state
        .feeds
        .def(feed)
        .and_then(|d| d.provider)
        .unwrap_or_else(|| feed.to_string());
    // A check of the provider may be running (a first check): wait for it, then check again.
    wait_until("the provider to be free", || async {
        !c.state.feeds.is_checking(&provider)
    })
    .await;
    let body = check_provider(c, &provider).await;
    assert!(
        ["started", "queued"].contains(&body["result"].as_str().unwrap()),
        "{body}"
    );
    wait_until("the check", || async {
        checks(c, feed).await > before
            && !c.state.feeds.is_busy(feed)
            && !c.state.feeds.is_checking(&provider)
    })
    .await;
}
