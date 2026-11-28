//! Feed providers and their feeds end to end (build-and-test.md §5 rows "Download modules",
//! "Feed providers and their feeds"): a running core with the `github` and `http` modules
//! pointed at local fakes.

use crate::common;

use common::feeds::{check_provider, ui, wait_until};
use common::github::{self, commit};
use common::{Core, client};
use jiff::Timestamp;
use picket_core::modules::download::testkit::{Reply, Seen, TestServer};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

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
        .get(common::feeds::url(c, path))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{path}");
    r.json().await.unwrap()
}

async fn post(c: &Core, path: &str, body: Value) -> (StatusCode, Value) {
    let r = ui(c, Method::POST, path).json(&body).send().await.unwrap();
    let st = r.status();
    (st, r.json().await.unwrap_or(Value::Null))
}

async fn put(c: &Core, path: &str, body: Value) -> (StatusCode, Value) {
    let r = ui(c, Method::PUT, path).json(&body).send().await.unwrap();
    let st = r.status();
    (st, r.json().await.unwrap_or(Value::Null))
}

async fn q_i64(c: &Core, sql: &str, arg: &str) -> i64 {
    let (s, a) = (sql.to_string(), arg.to_string());
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&s, [a], |r| r.get::<_, i64>(0))?))
        .await
        .unwrap()
}

async fn runs(c: &Core, feed: &str) -> i64 {
    q_i64(c, "SELECT count(*) FROM feed_runs WHERE feed_id = ?1", feed).await
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

fn feed_ids(c: &Core) -> Vec<String> {
    let mut v: Vec<String> = c
        .state
        .feeds
        .provider_feeds("hz")
        .into_iter()
        .map(|f| f.id)
        .collect();
    v.sort();
    v
}

/// Waits until the provider is free and its feeds' runs are stored.
async fn settle(c: &Core, provider: &str) {
    wait_until("the provider to settle", || async {
        !c.state.feeds.is_checking(provider)
            && c.state
                .feeds
                .provider_feeds(provider)
                .iter()
                .all(|f| !c.state.feeds.is_busy(&f.id))
    })
    .await;
}

/// feeds.md §1: a provider whose `files` holds globs lists on its first check (with no feed
/// yet); each selected file becomes an enabled feed in no bundle, named after its file, with
/// the entry's settings, checked and ingested, raising `feed_added` until it joins a bundle or is
/// disabled; `exclude` keeps files out; the cap skips the rest in one alert; a deleted provider
/// feed doesn't come back. providers.md §2: a head move changing one file downloads only it.
#[tokio::test(flavor = "multi_thread")]
async fn discovery_review_cap_exclude_and_a_head_move() {
    let (srv, repo) = github::fake().await;
    let now = Timestamp::now();
    let t = |h: i64| picket_api::time::format_secs(&(now - jiff::SignedDuration::from_hours(h)));
    {
        let mut r = repo.lock().unwrap();
        r.set(
            1,
            &[
                ("adblock/tif.txt", "||a.example^\n"),
                ("adblock/pro.txt", "||p.example^\n"),
                ("adblock/pro-onlydomains.txt", "p.example\n"),
                ("adblock/light.txt", "||l.example^\n"),
                ("hosts/tif.txt", "0.0.0.0 a.example\n"),
            ],
        );
        r.commits = vec![commit(&t(1), false)];
    }
    let c = core_with(Some(&srv), Some(json!({"feeds": {"max_per_provider": 2}}))).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "hz", "name": "HZ", "module": "github", "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "adblock/*.txt", "feed": {"format": "adblock", "category": "security"}}],
               "exclude": ["adblock/*-onlydomains.txt"]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert!(v.get("feeds_added").is_none(), "globs wait for a listing: {v}");
    // The first check lists; two feeds (the cap), the third file skipped in one alert.
    wait_until("the listing's feeds", || async { feed_ids(&c).len() == 2 }).await;
    assert_eq!(feed_ids(&c), vec!["hz-adblock-light", "hz-adblock-pro"]);
    let f = get_json(&c, "/feeds/hz-adblock-pro").await;
    assert_eq!(
        (f["name"].as_str(), f["file"].as_str(), f["category"].as_str()),
        (Some("adblock/pro.txt"), Some("adblock/pro.txt"), Some("security"))
    );
    assert_eq!(f["enabled"], true);
    wait_until("the new feeds' alerts", || async {
        alert_state(&c, "feed_added:hz-adblock-pro").await.as_deref() == Some("open")
            && alert_state(&c, "feed_added:provider:hz").await.as_deref() == Some("open")
    })
    .await;
    let cap = c
        .state
        .alerts
        .get_by_key("feed_added:provider:hz")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        cap.details["skipped"],
        json!(["adblock/tif.txt"]),
        "{}",
        cap.details
    );
    let review = get_json(&c, "/feed-providers-review").await;
    assert_eq!(review.as_array().unwrap().len(), 2, "{review}");
    // The new feeds are checked and ingested like any feed (their provider is due again).
    c.state.feeds.clear_last_check("hz");
    wait_until("the new feeds' runs", || async {
        runs(&c, "hz-adblock-pro").await >= 1 && runs(&c, "hz-adblock-light").await >= 1
    })
    .await;
    settle(&c, "hz").await;
    // Joining a bundle resolves feed_added; so does disabling.
    let mut b = get_json(&c, "/bundles/block-common").await;
    b["feeds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"feed": "hz-adblock-pro"}));
    let (st, v) = put(&c, "/bundles/block-common", b).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let mut light = get_json(&c, "/feeds/hz-adblock-light").await;
    light["enabled"] = json!(false);
    let (st, v) = put(&c, "/feeds/hz-adblock-light", light).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    wait_until("feed_added resolved", || async {
        alert_state(&c, "feed_added:hz-adblock-pro").await.as_deref() == Some("resolved")
            && alert_state(&c, "feed_added:hz-adblock-light").await.as_deref() == Some("resolved")
    })
    .await;
    // Raising the cap adds the skipped file at the next listing; the cap alert resolves.
    let (st, v) = put(&c, "/settings", json!({"feeds": {"max_per_provider": 50}})).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    {
        let mut r = repo.lock().unwrap();
        let files: Vec<(String, String)> = r.trees[&github::head(1)]
            .iter()
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect();
        let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        r.set(2, &refs);
    }
    check_provider(&c, "hz").await;
    wait_until("the third feed", || async { feed_ids(&c).len() == 3 }).await;
    wait_until("the cap alert to resolve", || async {
        alert_state(&c, "feed_added:provider:hz").await.as_deref() == Some("resolved")
    })
    .await;
    settle(&c, "hz").await;
    // A deleted provider feed's file goes to exclude and doesn't come back.
    let r = ui(&c, Method::DELETE, "/feeds/hz-adblock-tif")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let p = get_json(&c, "/feed-providers/hz").await;
    assert_eq!(
        p["exclude"],
        json!(["adblock/*-onlydomains.txt", "adblock/tif.txt"])
    );
    wait_until("the deletion to reach the runtime", || async {
        feed_ids(&c).len() == 2
    })
    .await;
    // A head move that changes only pro.txt: one new run for it, none for light.
    let (pro0, light0) = (
        runs(&c, "hz-adblock-pro").await,
        runs(&c, "hz-adblock-light").await,
    );
    let mut light = get_json(&c, "/feeds/hz-adblock-light").await;
    light["enabled"] = json!(true);
    put(&c, "/feeds/hz-adblock-light", light).await;
    {
        let mut r = repo.lock().unwrap();
        r.set(
            3,
            &[
                ("adblock/tif.txt", "||a.example^\n"),
                ("adblock/pro.txt", "||p.example^\n||q.example^\n"),
                ("adblock/pro-onlydomains.txt", "p.example\n"),
                ("adblock/light.txt", "||l.example^\n"),
                ("hosts/tif.txt", "0.0.0.0 a.example\n"),
            ],
        );
        r.commits = vec![commit(&t(0), false)];
    }
    srv.clear();
    settle(&c, "hz").await;
    check_provider(&c, "hz").await;
    wait_until("pro's new run", || async {
        runs(&c, "hz-adblock-pro").await == pro0 + 1
    })
    .await;
    settle(&c, "hz").await;
    assert_eq!(runs(&c, "hz-adblock-light").await, light0, "light didn't change");
    assert!(
        !feed_ids(&c).contains(&"hz-adblock-tif".to_string()),
        "an excluded file never comes back"
    );
    let raws: Vec<String> = srv
        .seen()
        .iter()
        .filter(|s| s.host == "raw.githubusercontent.com")
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        raws,
        vec![format!("/o/r/{}/adblock/pro.txt", github::head(3))],
        "only the changed file is downloaded"
    );
    assert_eq!(
        srv.seen().iter().filter(|s| s.host == "github.com").count(),
        1,
        "one ls-refs per check"
    );
    // The provider's listing: each listed file with its feed or none.
    let files = get_json(&c, "/feed-providers/hz/listing").await;
    let row = |f: &str| {
        files["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["file"] == f)
            .cloned()
            .unwrap()
    };
    assert_eq!(row("adblock/pro.txt")["feed"], "hz-adblock-pro");
    assert_eq!(row("adblock/tif.txt")["selected"], false, "excluded");
    assert_eq!(row("hosts/tif.txt")["feed"], Value::Null);
    // Add as feed: hosts/tif.txt joins files and becomes a feed at once (the listing has it).
    let (st, v) = post(
        &c,
        "/feed-providers/hz/files",
        json!({"file": "hosts/tif.txt", "feed": {"format": "hosts"}}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["feeds_added"], json!(["hz-hosts-tif"]));
}

/// providers.md §3, core.md §9: a truncated tree whose walk can't finish gives no listing and
/// raises `feed_provider_listing_incomplete` for a provider whose `files` holds globs, resolved
/// once a listing finishes; a provider with globs and no enabled feed keeps listing hourly.
#[tokio::test(flavor = "multi_thread")]
async fn an_unfinished_listing_raises_listing_incomplete_until_one_finishes() {
    let (srv, repo) = github::fake().await;
    {
        let mut r = repo.lock().unwrap();
        r.set(1, &[("lists/a.txt", "a.example\n")]);
        r.truncated = true;
    }
    let c = core_with(Some(&srv), None).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "big", "name": "Big", "module": "github", "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "**/*.txt", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    wait_until("listing_incomplete", || async {
        alert_state(&c, "feed_provider_listing_incomplete:big")
            .await
            .as_deref()
            == Some("open")
    })
    .await;
    wait_until("the provider to be free", || async {
        !c.state.feeds.is_checking("big")
    })
    .await;
    assert!(
        c.state.feeds.provider_feeds("big").is_empty(),
        "no listing, no feeds"
    );
    let next = c.state.feeds.next_due("big").unwrap();
    assert!(
        next <= Timestamp::now() + jiff::SignedDuration::from_hours(1),
        "globs keep listing at least hourly: {next}"
    );
    let ps = get_json(&c, "/feed-providers/big/status").await;
    assert_eq!(ps["listing_incomplete"], true);
    // FP13: the tree at a commit never changes, so a check at the same head doesn't walk it
    // again (an unfinishable walk costs its requests once per head, not at every check), and
    // the alert stays open.
    let pchecks = || async {
        q_i64(
            &c,
            "SELECT count(*) FROM feed_provider_checks WHERE provider_id = ?1",
            "big",
        )
        .await
    };
    let before = pchecks().await;
    srv.clear();
    check_provider(&c, "big").await;
    wait_until("the check at the same head", || async {
        pchecks().await > before && !c.state.feeds.is_checking("big")
    })
    .await;
    let trees = srv
        .seen()
        .iter()
        .filter(|s| s.host == "api.github.com" && s.path.contains("/git/trees/"))
        .count();
    assert_eq!(trees, 0, "no walk again at the same head");
    assert_eq!(
        alert_state(&c, "feed_provider_listing_incomplete:big")
            .await
            .as_deref(),
        Some("open")
    );
    // A new head whose tree isn't truncated: the next listing finishes and resolves it.
    {
        let mut r = repo.lock().unwrap();
        r.set(
            2,
            &[(
                "lists/a.txt",
                "a.example
",
            )],
        );
        r.truncated = false;
    }
    check_provider(&c, "big").await;
    wait_until("the listing", || async {
        alert_state(&c, "feed_provider_listing_incomplete:big")
            .await
            .as_deref()
            == Some("resolved")
    })
    .await;
    wait_until("the feed", || async {
        !c.state.feeds.provider_feeds("big").is_empty()
    })
    .await;
    assert_eq!(c.state.feeds.provider_feeds("big")[0].id, "big-lists-a");
}

/// providers.md §3 "Adding a feed by URL": a raw.githubusercontent.com URL on the default branch
/// maps onto the provider that follows it (the default branch resolved with ls-refs); another
/// branch gets a new provider; any other https URL goes to the http provider of that URL
/// (matched with its scheme and host lowercase and no default port), else a new one; a URL
/// that has its feed returns it, saying so.
#[tokio::test(flavor = "multi_thread")]
async fn adding_feeds_by_url() {
    let (srv, repo) = github::fake().await;
    repo.lock()
        .unwrap()
        .set(1, &[("a.txt", "a.example\n"), ("b.txt", "b.example\n")]);
    let c = core_with(Some(&srv), None).await;
    let (st, _) = post(
        &c,
        "/feed-providers",
        json!({"id": "or", "name": "o/r", "enabled": false, "module": "github", "config": {"owner": "o", "repo": "r"}}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://raw.githubusercontent.com/o/r/main/a.txt", "feed": {"format": "plain"}}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["provider"].as_str(),
            v["created_provider"].as_bool(),
            v["file"].as_str()
        ),
        (Some("or"), Some(false), Some("a.txt"))
    );
    let p = get_json(&c, "/feed-providers/or").await;
    assert_eq!(p["files"][0]["match"], "a.txt");
    // README §2 Secrets: a URL's user name or password is refused, not dropped.
    for url in [
        "https://user:pw@a.example/lists/x.txt",
        "https://user@raw.githubusercontent.com/o/r/main/a.txt",
    ] {
        let (st, v) = post(&c, "/feed-providers-add-url", json!({ "url": url })).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{url}: {v}");
        assert!(v.to_string().contains("use a header with a secret"), "{url}: {v}");
    }
    // jsDelivr @latest: the default branch, and the UI says so.
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://cdn.jsdelivr.net/gh/o/r@latest/b.txt"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["provider"], "or");
    assert!(v["notice"].as_str().unwrap().contains("12 hours"));
    // Another branch: a new provider following it.
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://raw.githubusercontent.com/o/r/dev/a.txt"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["created_provider"], true);
    let np = get_json(
        &c,
        &format!("/feed-providers/{}", v["provider"].as_str().unwrap()),
    )
    .await;
    assert_eq!(np["config"]["branch"], "dev");
    assert!(
        v["outcome"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "overlap"),
        "{v}"
    );
    // http (providers.md §3): the provider whose url is the URL (scheme and host lowercase, no
    // default port, otherwise exact, the query too), else a new one; its feed has its id.
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "l1", "name": "L1", "enabled": false, "module": "http",
               "config": {"url": "https://lists.example/sub/x/list.txt?v=1"}}),
    )
    .await;
    assert_eq!(
        (st, &v["feeds_added"]),
        (StatusCode::CREATED, &json!(["l1"])),
        "{v}"
    );
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "HTTPS://Lists.Example:443/sub/x/list.txt?v=1", "feed": {"format": "plain"}}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["provider"].as_str(),
            v["feed"].as_str(),
            v["created_provider"].as_bool(),
            v["file"].as_str()
        ),
        (Some("l1"), Some("l1"), Some(false), Some("response")),
        "the same URL: its feed, no duplicate: {v}"
    );
    assert_eq!(v["outcome"].get("feeds_added"), None, "{v}");
    assert_eq!(v["existing"], true, "it says the URL had its feed: {v}");
    // An older release's literal credential never comes back in the reply (masked as every
    // entity the UI API returns).
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_providers SET config_json = ?1 WHERE id = 'l1'",
                [r#"{"url": "https://lists.example/sub/x/list.txt?v=1", "headers": {"Authorization": "Bearer LEAKED-1"}}"#],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://lists.example/sub/x/list.txt?v=1"}),
    )
    .await;
    assert_eq!((st, v["existing"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
    assert!(!v.to_string().contains("LEAKED"), "{v}");
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://lists.example/sub/x/list.txt?v=2"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["created_provider"], true, "another query is another URL: {v}");
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://other.example/dir/list.txt", "feed": {"format": "plain"}}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (v["provider"].as_str(), v["feed"].as_str()),
        (Some("other-example-list-txt"), Some("other-example-list-txt")),
        "{v}"
    );
    let np = get_json(&c, "/feed-providers/other-example-list-txt").await;
    assert_eq!(np["config"]["url"], "https://other.example/dir/list.txt");
    assert_eq!(np["name"], "list.txt (other.example)");
    assert_eq!(
        get_json(&c, "/feeds/other-example-list-txt").await["name"],
        "list.txt (other.example)",
        "the feed's default name is the provider's"
    );
    // A deleted feed's URL added again: the feed comes back, on the same provider, with the
    // settings chosen now.
    let r = ui(&c, Method::DELETE, "/feeds/other-example-list-txt")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://other.example/dir/list.txt", "feed": {"format": "hosts"}}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["provider"].as_str(),
            v["feed"].as_str(),
            v["created_provider"].as_bool(),
            v["existing"].as_bool()
        ),
        (
            Some("other-example-list-txt"),
            Some("other-example-list-txt"),
            Some(false),
            Some(false)
        ),
        "{v}"
    );
    assert_eq!(
        get_json(&c, "/feeds/other-example-list-txt").await["format"],
        "hosts"
    );
    // A derived id another feed has is skipped: the provider and its feed share the next free
    // one.
    let (st, v) = post(
        &c,
        "/feeds",
        json!({"id": "x-example-a-txt", "name": "Mine", "format": "plain"}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://x.example/a.txt"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (v["provider"].as_str(), v["feed"].as_str()),
        (Some("x-example-a-txt-2"), Some("x-example-a-txt-2")),
        "{v}"
    );
    // A provider created under that feed's id by hand is refused (`id_taken`).
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "x-example-a-txt", "name": "X", "module": "http", "config": {"url": "https://x.example/b.txt"}}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v.to_string().contains("id_taken"), "{v}");
    let (st, v) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://x.example/a#top"}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["error"]["message"].as_str().unwrap().contains("fragment"),
        "{v}"
    );
    let (st, _) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://o.github.io/list.txt"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "<owner>.github.io is an http file");
    let (st, _) = post(
        &c,
        "/feed-providers-add-url",
        json!({"url": "https://cdn.jsdelivr.net/gh/o/r@1.0/a.txt"}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "tags are never followed");
}

/// feeds.md §3, feed-scheduling.md §4 and §8: a provider pointed at another repository starts a
/// new model epoch for each feed: `last` cleared, `seen_blake3` and the staleness reference
/// dropped, an open `feed_stale` resolved (retargeted), the next check a first check.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_pointed_elsewhere_starts_new_epochs() {
    let srv = TestServer::start(&["lists.example", "mirror.example"], |_s: &Seen| {
        Reply::ok("a.example\n")
    })
    .await;
    let c = core_with(Some(&srv), None).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "p", "name": "P", "module": "http", "config": {"url": "https://lists.example/a.txt"},
               "files": [{"match": "response", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    wait_until("the first run", || async {
        runs(&c, "p").await >= 1 && !c.state.feeds.is_busy("p")
    })
    .await;
    let epoch0: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT epoch_at FROM feed_state WHERE feed_id = 'p'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    // A staleness reference and an open feed_stale, as an earlier epoch left them.
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_state SET stale_ref_json = '{}' WHERE feed_id = 'p'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    c.state
        .alerts
        .raise(
            picket_core::alerts::RaiseSpec::new(
                "feed_stale",
                picket_core::alerts::Severity::Warning,
                "feed_stale:p",
                "stale",
                json!({}),
            )
            .feed("p"),
        )
        .await
        .unwrap();
    // A header edit doesn't point elsewhere: the epoch stays.
    settle(&c, "p").await;
    let before_header_checks = common::feeds::checks(&c, "p").await;
    let (st, v) = put(
        &c,
        "/feed-providers/p",
        json!({"name": "P", "module": "http", "config": {"url": "https://lists.example/a.txt", "headers": {"Accept": "text/plain"}},
               "files": [{"match": "response", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        q_i64(
            &c,
            "SELECT count(*) FROM feed_state WHERE feed_id = ?1 AND stale_ref_json IS NOT NULL",
            "p"
        )
        .await,
        1
    );
    // The header edit starts its own asynchronous check. Wait for that edit to reach
    // the runtime and finish before testing a separate retarget; a short sleep does
    // not establish either condition on a loaded runner.
    wait_until("the header edit to reach the runtime", || async {
        common::feeds::checks(&c, "p").await > before_header_checks
            && c.state
                .feeds
                .provider_def("p")
                .is_some_and(|p| p.config["headers"]["Accept"] == "text/plain")
    })
    .await;
    settle(&c, "p").await;
    // Another url points elsewhere. Keep its epoch timestamp distinct.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (st, v) = put(
        &c,
        "/feed-providers/p",
        json!({"name": "P", "module": "http", "config": {"url": "https://mirror.example/a.txt"},
               "files": [{"match": "response", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let (epoch1, seen, sref, last): (String, Option<String>, Option<String>, Option<String>) = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT epoch_at, seen_blake3, stale_ref_json, last_json FROM feed_state WHERE feed_id = 'p'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?)
        })
        .await
        .unwrap();
    assert!(epoch1 > epoch0, "{epoch0} → {epoch1}");
    assert_eq!((seen, sref), (None, None));
    let _ = last;
    wait_until("feed_stale resolved as retargeted", || async {
        alert_state(&c, "feed_stale:p").await.as_deref() == Some("resolved")
    })
    .await;
    // The next check, a first check, downloads from the new location.
    wait_until("the mirror's download", || async {
        srv.seen().iter().any(|s| s.host == "mirror.example")
    })
    .await;
}

/// core.md §9: a provider's whole check failing raises `feed_provider_down` and no `feed_down`
/// for its feeds; a provider can't be deleted while it has feeds; deleting them first works.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_failing_as_a_whole_and_deletion_order() {
    let srv = TestServer::start(
        &["github.com", "api.github.com", "raw.githubusercontent.com"],
        |_s: &Seen| Reply::status(500),
    )
    .await;
    let c = core_with(
        Some(&srv),
        Some(json!({"alerts": {"thresholds": {"feed_provider_down": "0s", "feed_down": "0s"}}})),
    )
    .await;
    let (st, _) = post(
        &c,
        "/feed-providers",
        json!({"id": "gh", "name": "GH", "module": "github", "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "a.txt", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    wait_until("feed_provider_down", || async {
        alert_state(&c, "feed_provider_down:gh").await.as_deref() == Some("open")
    })
    .await;
    let pc = get_json(&c, "/feed-providers/gh/checks").await;
    assert_eq!(pc["items"][0]["ok"], false);
    assert!(pc["items"][0]["error"].as_str().unwrap().contains("500"), "{pc}");
    // A provider with no feed can be deleted.
    let r = ui(&c, Method::DELETE, "/feed-providers/gh")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("the alert to resolve", || async {
        alert_state(&c, "feed_provider_down:gh").await.as_deref() == Some("resolved")
    })
    .await;
    // An http provider with a feed can't be deleted until the feed is.
    let (st, _) = post(
        &c,
        "/feed-providers",
        json!({"id": "h", "name": "H", "enabled": false, "module": "http", "config": {"url": "https://lists.example/a.txt"},
               "files": [{"match": "response", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let r = ui(&c, Method::DELETE, "/feed-providers/h")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r = ui(&c, Method::DELETE, "/feeds/h")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = ui(&c, Method::DELETE, "/feed-providers/h")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

/// FP3 (providers.md §2 Listing, feeds.md §3 "Editing a feed provider"): `files` edited while a
/// check lists for the old selection (a tree too large for one answer, walked only where the old
/// patterns reach): the check stores neither its provider state nor its limited listing, so the
/// reset the edit made holds, and the next check lists for the new selection and adds its feed.
#[tokio::test(flavor = "multi_thread")]
async fn a_files_edit_during_a_check_lists_for_the_new_selection() {
    let (srv, repo) = github::fake().await;
    {
        let mut r = repo.lock().unwrap();
        r.set(
            1,
            &[("lists/a.txt", "a.example\n"), ("other/b.txt", "b.example\n")],
        );
        r.truncated = true;
        r.walkable = true;
    }
    let c = core_with(Some(&srv), None).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "w", "name": "W", "module": "github", "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "lists/*.txt", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    wait_until("the first listing's feed", || async {
        c.state.feeds.def("w-lists-a").is_some()
    })
    .await;
    settle(&c, "w").await;
    // A head move makes the next check list; its tree answers are slow.
    {
        let mut r = repo.lock().unwrap();
        r.set(
            2,
            &[
                ("lists/a.txt", "a.example\n"),
                ("lists/c.txt", "c.example\n"),
                ("other/b.txt", "b.example\n"),
            ],
        );
        r.slow_trees = Some(std::time::Duration::from_secs(2));
    }
    srv.clear();
    check_provider(&c, "w").await;
    wait_until("the listing in flight", || async {
        srv.seen().iter().any(|s| s.path.contains("/git/trees/"))
    })
    .await;
    // The selection broadens while it runs.
    let mut p = get_json(&c, "/feed-providers/w").await;
    p["files"]
        .as_array_mut()
        .unwrap()
        .push(json!({"match": "other/*.txt", "feed": {"format": "plain"}}));
    let (st, v) = put(&c, "/feed-providers/w", p).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    repo.lock().unwrap().slow_trees = None;
    wait_until("the check in flight to end", || async {
        !c.state.feeds.is_checking("w")
    })
    .await;
    settle(&c, "w").await;
    check_provider(&c, "w").await;
    wait_until("the new selection's feed", || async {
        c.state.feeds.def("w-other-b").is_some()
    })
    .await;
}

/// Q6 (feeds.md §3: editing `files` or `exclude` applies them at once; providers.md §2): after a
/// walk that couldn't finish (no listing, its head not walked again for a while), a selection
/// edit resets the provider's state, so the next check lists the new selection at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_selection_edit_after_a_failed_walk_lists_again_at_once() {
    let (srv, repo) = github::fake().await;
    {
        let files: Vec<(String, String)> = (0..60)
            .map(|n| (format!("dir{n}/a.txt"), "a.example\n".to_string()))
            .collect();
        let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let mut r = repo.lock().unwrap();
        r.set(1, &refs);
        r.truncated = true;
        r.walkable = true;
    }
    let c = core_with(Some(&srv), None).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "w", "name": "W", "module": "github", "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "**/*.txt", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    wait_until("the failed walk", || async {
        alert_state(&c, "feed_provider_listing_incomplete:w")
            .await
            .as_deref()
            == Some("open")
            && !c.state.feeds.is_checking("w")
    })
    .await;
    let mut p = get_json(&c, "/feed-providers/w").await;
    p["files"] = json!([{"match": "dir0/*.txt", "feed": {"format": "plain"}}]);
    let (st, v) = put(&c, "/feed-providers/w", p).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    wait_until("the edit", || async {
        c.state
            .feeds
            .provider_def("w")
            .is_some_and(|p| p.files[0].pattern == "dir0/*.txt")
    })
    .await;
    // The edit makes the provider due at once; min_interval holds it back, which the test skips.
    c.state.feeds.clear_last_check("w");
    wait_until("the feed of the new selection", || async {
        c.state.feeds.def("w-dir0-a").is_some()
    })
    .await;
    wait_until("listing_incomplete resolved", || async {
        alert_state(&c, "feed_provider_listing_incomplete:w")
            .await
            .as_deref()
            == Some("resolved")
    })
    .await;
}

/// Z2 (feeds.md §3: `files` and `exclude` edits apply at once; providers.md §2): a provider
/// keeps an older head's whole listing while a walk at the new head couldn't finish (its retry
/// delay running). A selection edit then ends that delay, so the next check walks the new head
/// for the new selection instead of applying it to the obsolete listing.
#[tokio::test(flavor = "multi_thread")]
async fn a_selection_edit_retries_a_failed_walk_despite_an_older_whole_listing() {
    let (srv, repo) = github::fake().await;
    repo.lock().unwrap().set(1, &[("dir0/a.txt", "old.example\n")]);
    let c = core_with(Some(&srv), None).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "w", "name": "W", "module": "github", "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "**/*.txt", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    wait_until("the first whole listing", || async {
        c.state.feeds.def("w-dir0-a").is_some()
    })
    .await;
    settle(&c, "w").await;
    {
        let files: Vec<(String, String)> = (0..60)
            .map(|n| (format!("dir{n}/a.txt"), "new.example\n".to_string()))
            .collect();
        let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let mut r = repo.lock().unwrap();
        r.set(2, &refs);
        r.truncated = true;
        r.walkable = true;
    }
    check_provider(&c, "w").await;
    wait_until("the failed walk at the new head", || async {
        alert_state(&c, "feed_provider_listing_incomplete:w")
            .await
            .as_deref()
            == Some("open")
            && !c.state.feeds.is_checking("w")
    })
    .await;
    let mut p = get_json(&c, "/feed-providers/w").await;
    p["files"] = json!([{"match": "dir59/*.txt", "feed": {"format": "plain"}}]);
    let (st, v) = put(&c, "/feed-providers/w?delete_unselected=true", p).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    wait_until("the edit", || async {
        c.state
            .feeds
            .provider_def("w")
            .is_some_and(|p| p.files[0].pattern == "dir59/*.txt")
    })
    .await;
    check_provider(&c, "w").await;
    settle(&c, "w").await;
    assert!(
        c.state.feeds.def("w-dir59-a").is_some(),
        "the new selection was applied to the obsolete listing: no walk at the new head"
    );
}

/// A provider's listing (core.md §12 Feed providers page) with S3 ListObjectsV2 semantics over the
/// stored flat listing, paged (api.md §7): `prefix` + `delimiter=/` gives the files directly under
/// the prefix and the common prefixes (with file and feed counts, nested and root files alike),
/// merged in key order and both counting toward `limit` (100 by default, 1 to 500, else `400`);
/// a prefix nothing is under is empty. A walk inside a big folder across a new listing repeats
/// and skips no entry listed throughout. `q` searches the paths under `prefix`, paged the same
/// way. Bad cursors, delimiters, prefixes and searches are `400`.
#[tokio::test(flavor = "multi_thread")]
async fn a_providers_listing_lists_like_s3_and_pages_through_listing_changes() {
    let (srv, repo) = github::fake().await;
    let big = |i: u32| format!("big/f{i:03}.txt");
    let set = |n: u32, files: &[String]| {
        let body: Vec<(&str, &str)> = files.iter().map(|f| (f.as_str(), "a.example\n")).collect();
        repo.lock().unwrap().set(n, &body);
    };
    let mut first: Vec<String> = [
        "README.md",
        "hosts.txt",
        "adblock/pro.txt",
        "adblock/tif.txt",
        "adblock/sub/deep.txt",
    ]
    .map(String::from)
    .to_vec();
    first.extend((0..105).map(big));
    set(1, &first);
    let c = core_with(Some(&srv), None).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "pg", "name": "Paged", "module": "github", "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "adblock/*.txt", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let listed = |n: u64| {
        let c = &c;
        async move {
            let s = get_json(c, "/feed-providers/pg/status").await;
            s["listing"]["files"].as_u64() == Some(n) && !c.state.feeds.is_checking("pg")
        }
    };
    wait_until("the first listing", || listed(110)).await;
    let get = |path: String| {
        let c = &c;
        async move {
            let r = ui(c, Method::GET, &format!("/feed-providers/pg/listing{path}"))
                .send()
                .await
                .unwrap();
            let st = r.status();
            (st, r.json::<Value>().await.unwrap())
        }
    };
    let files = |page: &Value| -> Vec<String> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["file"].as_str().unwrap().to_string())
            .collect()
    };
    let prefixes = |page: &Value| -> Vec<String> {
        page["prefixes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["prefix"].as_str().unwrap().to_string())
            .collect()
    };

    // The root: files and folders, the folders with their counts at any depth.
    let (st, root) = get("?delimiter=/".into()).await;
    assert_eq!(st, StatusCode::OK, "{root}");
    assert_eq!(files(&root), ["README.md", "hosts.txt"]);
    assert_eq!(
        root["prefixes"],
        json!([
            {"prefix": "adblock/", "files": 3, "feeds": 2},
            {"prefix": "big/", "files": 105, "feeds": 0},
        ])
    );
    assert_eq!(root["next_cursor"], Value::Null);
    assert_eq!(root["listing"], json!({"files": 110, "whole": true}));
    // Prefixes and files merge in key order and both count toward the limit.
    let (_, r1) = get("?delimiter=/&limit=2".into()).await;
    assert_eq!(
        (files(&r1), prefixes(&r1)),
        (vec!["README.md".into()], vec!["adblock/".into()])
    );
    let cur = r1["next_cursor"].as_str().unwrap();
    let (_, r2) = get(format!("?delimiter=/&limit=2&cursor={cur}")).await;
    assert_eq!(
        (files(&r2), prefixes(&r2)),
        (vec!["hosts.txt".into()], vec!["big/".into()])
    );
    assert_eq!(r2["next_cursor"], Value::Null);
    // A folder, a nested one, a trailing-slash-less prefix, no delimiter, an unknown folder.
    let (_, ad) = get("?prefix=adblock/&delimiter=/".into()).await;
    assert_eq!(
        ad["items"],
        json!([
            {"file": "adblock/pro.txt", "selected": true, "feed": "pg-adblock-pro"},
            {"file": "adblock/tif.txt", "selected": true, "feed": "pg-adblock-tif"},
        ])
    );
    assert_eq!(
        ad["prefixes"],
        json!([{"prefix": "adblock/sub/", "files": 1, "feeds": 0}])
    );
    let (_, sub) = get("?prefix=adblock/sub/&delimiter=/".into()).await;
    assert_eq!(
        sub["items"],
        json!([{"file": "adblock/sub/deep.txt", "selected": false, "feed": null}])
    );
    assert_eq!(sub["prefixes"], json!([]));
    let (_, flat) = get("?prefix=adblock/".into()).await;
    assert_eq!(
        (files(&flat), prefixes(&flat).len()),
        (
            vec![
                "adblock/pro.txt".into(),
                "adblock/sub/deep.txt".into(),
                "adblock/tif.txt".into()
            ],
            0
        ),
        "no delimiter: every file under the prefix"
    );
    let (st, none) = get("?prefix=nope/&delimiter=/".into()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        (none["items"].clone(), none["prefixes"].clone()),
        (json!([]), json!([]))
    );

    // 400s, the largest page, an unknown provider.
    // Each bad value alone, so the handler's own check refuses it (a repeated parameter is
    // refused before it runs); `limit=x` and `cursor=%FF` don't parse at all.
    for (bad, why) in [
        ("limit=0".to_string(), "limit: 1 to 500"),
        ("limit=501".into(), "limit: 1 to 500"),
        ("limit=x".into(), ""),
        ("cursor=!!".into(), "bad cursor"),
        ("cursor=%FF".into(), ""),
        ("delimiter=-".into(), "delimiter: only /"),
        (
            format!("prefix={}", "p".repeat(4097)),
            "prefix: at most 4096 bytes",
        ),
        (format!("q={}", "x".repeat(257)), "q: at most 256 characters"),
    ] {
        let (st, v) = get(format!("?{bad}")).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}: {v}");
        let msg = v["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.contains(why), "{bad}: {v}");
    }
    let (st, v) = get("?prefix=adblock/&delimiter=".into()).await;
    assert_eq!(
        (st, files(&v).len(), prefixes(&v).len()),
        (StatusCode::OK, 3, 0),
        "an empty delimiter is none, as in S3: {v}"
    );
    let (st, v) = get("?prefix=big/&limit=500".into()).await;
    assert_eq!((st, files(&v).len()), (StatusCode::OK, 105), "{v}");
    let (st, v) = get(format!("?prefix={}&delimiter=/", "p".repeat(4096))).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    // The listing is read at `listing`; `files` (the selection setting's name) takes only
    // Add as feed's POST.
    let r = ui(&c, Method::GET, "/feed-providers/pg/files")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    let r = ui(&c, Method::GET, "/feed-providers/nope/listing")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // Inside the big folder: 100 by default, then the rest.
    let (_, b1) = get("?prefix=big/&delimiter=/".into()).await;
    assert_eq!(files(&b1).len(), 100);
    let cur = b1["next_cursor"].as_str().unwrap();
    let (_, b2) = get(format!("?prefix=big/&delimiter=/&cursor={cur}")).await;
    assert_eq!(files(&b2), (100..105).map(big).collect::<Vec<_>>());
    assert_eq!(b2["next_cursor"], Value::Null);

    // A walk at 40: after the first page a new listing drops a file already returned (f010) and
    // one not reached yet (f050), and adds one before the cursor (big/a.txt), one just after it
    // (f0395) and a folder past it (big/new/), which a later page brings.
    let (_, w1) = get("?prefix=big/&delimiter=/&limit=40".into()).await;
    assert_eq!(files(&w1), (0..40).map(big).collect::<Vec<_>>());
    let mut cursor = w1["next_cursor"].as_str().unwrap().to_string();
    let mut second: Vec<String> = first
        .iter()
        .filter(|f| **f != big(10) && **f != big(50))
        .cloned()
        .collect();
    second.extend(["big/a.txt", "big/f0395.txt", "big/new/x.txt"].map(String::from));
    set(2, &second);
    check_provider(&c, "pg").await;
    wait_until("the new listing", || listed(111)).await;
    let (mut walked, mut walked_prefixes, mut pages) = (files(&w1), Vec::new(), 1);
    loop {
        let (st, page) = get(format!("?prefix=big/&delimiter=/&limit=40&cursor={cursor}")).await;
        assert_eq!(st, StatusCode::OK, "{page}");
        let (f, p) = (files(&page), prefixes(&page));
        assert!(!f.is_empty() || !p.is_empty(), "{page}");
        assert!(f.len() + p.len() <= 40, "{page}");
        walked.extend(f);
        walked_prefixes.extend(p);
        pages += 1;
        match page["next_cursor"].as_str() {
            Some(next) => cursor = next.to_string(),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    let mut want: Vec<String> = (0..40).map(big).collect();
    want.push("big/f0395.txt".into());
    want.extend((40..105).filter(|i| *i != 50).map(big));
    assert_eq!(
        walked, want,
        "each file listed throughout exactly once, in order; f050 went before it was reached"
    );
    assert_eq!(walked_prefixes, ["big/new/"]);
    let (_, root) = get("?delimiter=/".into()).await;
    assert_eq!(
        root["prefixes"][1],
        json!({"prefix": "big/", "files": 106, "feeds": 0})
    );

    // `q`: case-insensitive, under the prefix, files only, paged like the rest.
    let (_, v) = get("?q=readme".into()).await;
    assert_eq!(files(&v), ["README.md"]);
    let (_, v) = get("?q=DEEP&delimiter=/".into()).await;
    assert_eq!(
        (files(&v), prefixes(&v).len()),
        (vec!["adblock/sub/deep.txt".into()], 0),
        "no grouping"
    );
    let (_, v) = get("?q=txt&prefix=adblock/".into()).await;
    assert_eq!(files(&v).len(), 3);
    let (_, s1) = get("?q=F1&limit=3".into()).await;
    assert_eq!(files(&s1), [big(100), big(101), big(102)]);
    let cur = s1["next_cursor"].as_str().unwrap();
    let (_, s2) = get(format!("?q=F1&limit=3&cursor={cur}")).await;
    assert_eq!(files(&s2), [big(103), big(104)]);
    assert_eq!(s2["next_cursor"], Value::Null);
    let (st, v) = get(format!("?q={}", "x".repeat(256))).await;
    assert_eq!((st, files(&v).len()), (StatusCode::OK, 0), "{v}");
    settle(&c, "pg").await;
}

/// No file name is empty (providers.md §3): a `files` entry `""` is refused for every module
/// (`empty_file`), as is Add as feed with `""`; an http provider's one file is `response`. The
/// stored-listing reader drops an empty path a row still holds. The search lowercases Unicode
/// on both sides.
#[tokio::test(flavor = "multi_thread")]
async fn no_file_name_is_empty_and_search_lowercases_unicode() {
    let c = core_with(None, None).await;
    let codes = |v: &Value| -> Vec<String> {
        v["error"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|i| i["code"].as_str().map(str::to_string))
            .collect()
    };
    for (module, config) in [
        ("http", json!({"url": "https://lists.example/a.txt"})),
        ("github", json!({"owner": "o", "repo": "r"})),
    ] {
        for blank in ["", " "] {
            let (st, v) = post(
                &c,
                "/feed-providers",
                json!({"id": "e", "name": "E", "module": module, "enabled": false, "config": config,
                       "files": [{"match": blank, "feed": {"format": "plain"}}]}),
            )
            .await;
            assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{module} {blank:?}: {v}");
            assert_eq!(codes(&v), ["empty_file"], "{module} {blank:?}: {v}");
        }
    }
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "e", "name": "E", "module": "http", "enabled": false,
               "config": {"url": "https://lists.example/a.txt"},
               "files": [{"match": "a.txt", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(
        codes(&v),
        ["bad_file"],
        "an http provider's one file is response: {v}"
    );
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "dp", "name": "Declared", "module": "github", "enabled": false,
               "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "**/*.txt", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let (st, v) = post(
        &c,
        "/feed-providers/dp/files",
        json!({"file": "", "feed": {"format": "plain"}}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(codes(&v), ["empty_file"], "{v}");
    // A stored listing holding an empty or blank path (written before the rule): never shown or
    // counted.
    c.state
        .db
        .write(|db| {
            db.execute(
                "INSERT OR IGNORE INTO feed_provider_state(provider_id) VALUES ('dp')",
                [],
            )?;
            db.execute(
                "UPDATE feed_provider_state SET listing_json = ?1 WHERE provider_id = 'dp'",
                [r#"{"files": ["", "  ", "x.txt", "docs/École.txt"], "whole": true}"#],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let all = get_json(&c, "/feed-providers/dp/listing").await;
    let files: Vec<&str> = all["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["file"].as_str().unwrap())
        .collect();
    assert_eq!(files, ["docs/École.txt", "x.txt"], "{all}");
    assert_eq!(all["listing"], json!({"files": 2, "whole": true}));
    let status = get_json(&c, "/feed-providers/dp/status").await;
    assert_eq!(status["listing"]["files"], 2, "{status}");
    // `éCOLE` finds `École.txt`: each character lowercased, Unicode, on both sides.
    let found = get_json(&c, "/feed-providers/dp/listing?q=%C3%A9COLE").await;
    assert_eq!(found["items"][0]["file"], "docs/École.txt", "{found}");
    assert_eq!(found["items"].as_array().unwrap().len(), 1, "{found}");
}

/// No file name is blank: a fresh listing's blank path (a git tree may hold one) is no file:
/// `**` adds no feed for it, and the listing shows none.
#[tokio::test(flavor = "multi_thread")]
async fn a_listings_blank_path_is_no_file() {
    let (srv, repo) = github::fake().await;
    repo.lock()
        .unwrap()
        .set(1, &[(" ", "blank.example\n"), ("a.txt", "a.example\n")]);
    let c = core_with(Some(&srv), None).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "bl", "name": "BL", "module": "github", "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "**", "feed": {"format": "plain"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    wait_until("the listing's feed", || async {
        !c.state.feeds.provider_feeds("bl").is_empty() && !c.state.feeds.is_checking("bl")
    })
    .await;
    let files: Vec<Option<String>> = c
        .state
        .feeds
        .provider_feeds("bl")
        .into_iter()
        .map(|f| f.file)
        .collect();
    assert_eq!(files, [Some("a.txt".to_string())]);
    let listing = get_json(&c, "/feed-providers/bl/listing").await;
    assert_eq!(listing["items"].as_array().unwrap().len(), 1, "{listing}");
    assert_eq!(listing["listing"]["files"], 1, "{listing}");
}

/// Adds `n` disabled manual feeds straight to the configuration (filler toward the feed limit).
async fn fill_feeds(c: &Core, n: i64) {
    c.state
        .config
        .change(move |tx| {
            for i in 0..n {
                let f = picket_core::config::model::FeedDef {
                    id: format!("filler-{i}"),
                    name: format!("Filler {i}"),
                    enabled: false,
                    ..Default::default()
                };
                picket_core::config::store::write_feed(tx, &f).map_err(picket_core::error::CoreError::Other)?;
                picket_core::feeds::store::new_source_gen(tx, &f.id)
                    .map_err(|e| picket_core::error::CoreError::Other(e.into()))?;
            }
            Ok(())
        })
        .await
        .unwrap();
}

async fn feed_count(c: &Core) -> i64 {
    q_i64(c, "SELECT count(*) FROM feeds WHERE ?1 = ?1", "").await
}

/// #72: feeds core creates for selected files never take the configuration past its feed limit
/// (the one a restore enforces): not a fixed-file `http` provider's save, not a listing of many
/// files, with manual feeds and other providers taking the slots. The files skipped for lack of
/// room raise one deduplicated operational warning per provider, with the limit, the feeds in
/// use, how many were skipped and a bounded sample, distinct from the per-provider cap's; freed
/// room gives the skipped files their feeds and resolves it; the configuration exports and
/// restores.
#[tokio::test(flavor = "multi_thread")]
async fn auto_created_feeds_stay_within_the_feed_limit() {
    const LIMIT: i64 = 1024;
    let c = core_with(None, Some(json!({"feeds": {"max_per_provider": 50}}))).await;
    let have = feed_count(&c).await;
    // Two slots left.
    fill_feeds(&c, LIMIT - 2 - have).await;
    let http = |id: &str| {
        json!({"id": id, "name": id, "module": "http", "enabled": false,
               "config": {"url": format!("https://lists.example/{id}.txt")}})
    };
    // Just below the limit: each fixed-file provider's save creates its feed.
    for id in ["a", "b"] {
        let (st, v) = post(&c, "/feed-providers", http(id)).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        assert_eq!(v["feeds_added"], json!([id]), "{v}");
    }
    assert_eq!(feed_count(&c).await, LIMIT);
    // At the limit: the provider is saved, its file gets no feed, and the save says why.
    let (st, v) = post(&c, "/feed-providers", http("c")).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert!(v.get("feeds_added").is_none(), "{v}");
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "feed_limit" && w["field"] == "files"),
        "{v}"
    );
    assert_eq!(feed_count(&c).await, LIMIT, "never past the limit");
    wait_until("the limit warning", || async {
        alert_state(&c, "feed_limit_reached:c").await.as_deref() == Some("open")
    })
    .await;
    let a = c.state.alerts.get_by_key("feed_limit_reached:c").await.unwrap().unwrap();
    assert_eq!(
        (
            serde_json::to_value(a.alert_type).unwrap(),
            serde_json::to_value(a.severity).unwrap(),
            a.kind.as_str(),
            a.feed_provider.as_deref()
        ),
        (json!("operational"), json!("warning"), "feed_limit_reached", Some("c"))
    );
    assert_eq!(
        (
            &a.details["limit"],
            &a.details["feeds"],
            &a.details["skipped"],
            &a.details["files"]
        ),
        (&json!(LIMIT), &json!(LIMIT), &json!(1), &json!(["response"])),
        "{}",
        a.details
    );
    assert!(a.details["guidance"].as_str().unwrap().contains("Delete feeds you don't use"));
    // It isn't the per-provider cap's alert.
    assert_eq!(alert_state(&c, "feed_added:provider:c").await, None);
    // A provider that lists files: a listing of three files with one slot freed creates one
    // feed and skips two; repeated saves don't raise the warning again.
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "hz", "name": "HZ", "module": "github", "enabled": false,
               "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "*.txt", "feed": {"format": "adblock", "category": "mixed"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_provider_state SET listing_json = ?1 WHERE provider_id = 'hz'",
                [r#"{"files": ["1.txt", "2.txt", "3.txt"], "whole": true}"#],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    // Freeing a slot (a filler deleted) gives it to the provider skipped first, in id order: c.
    let r = ui(&c, Method::DELETE, "/feeds/filler-0").json(&json!({})).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    assert_eq!(feed_count(&c).await, LIMIT);
    assert_eq!(
        q_i64(&c, "SELECT count(*) FROM feeds WHERE provider_id = ?1", "c").await,
        1,
        "freed room goes to the skipped file"
    );
    wait_until("c's warning to resolve", || async {
        alert_state(&c, "feed_limit_reached:c").await.as_deref() == Some("resolved")
    })
    .await;
    // The listing applied with no room: three files skipped.
    let hz = get_json(&c, "/feed-providers/hz").await;
    for _ in 0..2 {
        let (st, v) = put(&c, "/feed-providers/hz", hz.clone()).await;
        assert_eq!(st, StatusCode::OK, "{v}");
    }
    assert_eq!(feed_count(&c).await, LIMIT);
    wait_until("hz's warning", || async {
        alert_state(&c, "feed_limit_reached:hz").await.as_deref() == Some("open")
    })
    .await;
    let a = c.state.alerts.get_by_key("feed_limit_reached:hz").await.unwrap().unwrap();
    assert_eq!(a.count, 1, "repeated checks don't raise it again");
    assert_eq!(a.details["skipped"], json!(3), "{}", a.details);
    assert_eq!(a.details["files"], json!(["1.txt", "2.txt", "3.txt"]));
    // Two slots freed: two of the three files get feeds, the warning's details follow.
    for f in ["filler-1", "filler-2"] {
        let r = ui(&c, Method::DELETE, &format!("/feeds/{f}")).json(&json!({})).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    }
    assert_eq!(feed_count(&c).await, LIMIT);
    assert_eq!(q_i64(&c, "SELECT count(*) FROM feeds WHERE provider_id = ?1", "hz").await, 2);
    wait_until("hz's warning updated", || async {
        c.state
            .alerts
            .get_by_key("feed_limit_reached:hz")
            .await
            .unwrap()
            .is_some_and(|a| a.details["skipped"] == json!(1) && a.count == 1)
    })
    .await;
    assert_eq!(alert_state(&c, "feed_limit_reached:hz").await.as_deref(), Some("open"));
    // A manual feed at the limit is refused as before.
    let (st, v) = post(
        &c,
        "/feeds",
        json!({"id": "m", "name": "M", "format": "plain", "category": "mixed"}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    // The configuration these paths produced exports and restores.
    let r = ui(&c, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let doc: Value = r.json().await.unwrap();
    assert_eq!(doc["configuration"]["feeds"].as_array().unwrap().len() as i64, LIMIT);
    let r = ui(&c, Method::PUT, "/config/export").json(&doc).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
}

/// #72: the per-provider cap still applies on its own, under the feed limit: a provider past
/// `feeds.max_per_provider` skips its files into the cap's alert, not the limit's.
#[tokio::test(flavor = "multi_thread")]
async fn the_per_provider_cap_is_not_the_feed_limit() {
    let c = core_with(None, Some(json!({"feeds": {"max_per_provider": 1}}))).await;
    let (st, v) = post(
        &c,
        "/feed-providers",
        json!({"id": "hz", "name": "HZ", "module": "github", "enabled": false,
               "config": {"owner": "o", "repo": "r"},
               "files": [{"match": "*.txt", "feed": {"format": "adblock", "category": "mixed"}}]}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_provider_state SET listing_json = ?1 WHERE provider_id = 'hz'",
                [r#"{"files": ["1.txt", "2.txt"], "whole": true}"#],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let hz = get_json(&c, "/feed-providers/hz").await;
    let (st, v) = put(&c, "/feed-providers/hz", hz).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert!(
        v["warnings"].as_array().unwrap().iter().any(|w| w["code"] == "feed_cap"),
        "{v}"
    );
    assert!(
        !v["warnings"].as_array().unwrap().iter().any(|w| w["code"] == "feed_limit"),
        "{v}"
    );
    wait_until("the cap alert", || async {
        alert_state(&c, "feed_added:provider:hz").await.as_deref() == Some("open")
    })
    .await;
    assert_eq!(alert_state(&c, "feed_limit_reached:hz").await, None);
}
