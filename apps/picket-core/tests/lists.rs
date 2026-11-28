//! Browser lists end to end (build-and-test.md §5 "Browser lists"; bundles.md §8): a bundle list
//! and a profile's pruned and full lists written from feeds' `browser` rules, served under
//! `/lists/*` with ETag and gzip, `404` for a profile whose list is off, and the warnings.

use crate::common;

use common::bundles::*;
use common::{Core, client, start_core};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

async fn core() -> Core {
    start_core(Some(json!({"web": {"tls": "off"}}))).await
}

/// A manual feed keeping its `browser` rules.
async fn browser_feed(c: &Core, id: &str) {
    manual_feed(
        c,
        id,
        json!({"modes": {"dns": {"mode": "replace"}, "ip": {"mode": "replace"}, "browser": {"mode": "replace"}}}),
    )
    .await;
}

async fn fetch(c: &Core, path: &str, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut r = client().get(format!("{}{path}", c.base("http")));
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    r.send().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundle_and_profile_lists() {
    let c = core().await;
    browser_feed(&c, "bf").await;
    browser_feed(&c, "af").await;
    put_entity(
        &c,
        "bundles",
        "bl",
        json!({"id": "bl", "name": "bl", "feeds": [{"feed": "bf"}]}),
    )
    .await;
    put_entity(
        &c,
        "bundles",
        "al",
        json!({"id": "al", "name": "al", "action": "allow", "feeds": [{"feed": "af"}]}),
    )
    .await;
    save(
        &c,
        "bf",
        "||tracker.example^\n||tracker.example/pixel.gif\n||tracker.example^$redirect-rule=noopjs\n||tracker.example^$popup\n\
         tracker.example##.banner\nother.example##.banner\n||good.example/ads.js\n||cdn.example/x.js\n||cdn.example/x.js\n",
    )
    .await;
    save(
        &c,
        "af",
        "||good.example/ads.js\nnews.example##.sponsored\n||video.example^$redirect=noopmp4-1s\n",
    )
    .await;
    build(&c, "bl").await;
    build(&c, "al").await;
    picket_core::lists::build_bundle_list(&c.state, "bl")
        .await
        .unwrap();
    picket_core::lists::build_bundle_list(&c.state, "al")
        .await
        .unwrap();
    // The bundle list: header, rules deduplicated, no DNS rule.
    let r = fetch(&c, "/lists/bl.txt", &[]).await;
    assert_eq!(r.status(), StatusCode::OK);
    let etag = r.headers()["etag"].to_str().unwrap().to_string();
    assert!(r.headers().contains_key("last-modified"));
    let text = r.text().await.unwrap();
    assert!(text.starts_with("! Title: Picket bl\n! Version: "), "{text}");
    assert!(text.contains("! Expires: 1 hours\n"));
    assert_eq!(text.matches("||cdn.example/x.js\n").count(), 1, "deduplicated");
    assert!(
        !text.lines().any(|l| l == "||tracker.example^"),
        "a dns rule isn't a browser rule"
    );
    // ETag and gzip.
    let r = fetch(&c, "/lists/bl.txt", &[("If-None-Match", &etag)]).await;
    assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    // The gzip copy, as it goes over the wire (no client-side decoding).
    let raw = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .build()
        .unwrap();
    let r = raw
        .get(format!("{}/lists/bl.txt", c.base("http")))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.headers().get("content-encoding").map(|v| v.to_str().unwrap()),
        Some("gzip")
    );
    let gz = r.bytes().await.unwrap();
    let mut body = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut body).unwrap();
    assert_eq!(body, text, "the gzip copy holds the same list");
    // The allow bundle's list: exceptions; $redirect dropped.
    let text = fetch(&c, "/lists/al.txt", &[]).await.text().await.unwrap();
    assert!(text.contains("@@||good.example/ads.js\n"));
    assert!(text.contains("news.example#@#.sponsored\n"));
    assert!(!text.contains("video.example"));
    // Profile lists: off by default (404), on → pruned and full.
    assert_eq!(
        fetch(&c, "/lists/profiles/default.txt", &[]).await.status(),
        StatusCode::NOT_FOUND
    );
    let (_, mut p) = get(&c, "/profiles/default").await;
    p["browser_list"] = json!({"enabled": true});
    p["allow"] = json!(["al"]);
    p["block"] = json!(["bl"]);
    let r = ui(&c, Method::PUT, "/profiles/default")
        .json(&p)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    picket_core::lists::build_profile_lists(&c.state, "default")
        .await
        .unwrap();
    let pruned = fetch(&c, "/lists/profiles/default.txt", &[])
        .await
        .text()
        .await
        .unwrap();
    let full = fetch(&c, "/lists/profiles/default-full.txt", &[])
        .await
        .text()
        .await
        .unwrap();
    assert!(pruned.starts_with("! Title: Picket profile default\n"));
    assert!(full.starts_with("! Title: Picket profile default (full)\n"));
    // The allow's exception first; the block it cancels exactly left out of both.
    assert!(full.contains("@@||good.example/ads.js\n") && !full.contains("\n||good.example/ads.js\n"));
    // DNS blocks tracker.example and its subdomains: the pruned list leaves out its network and
    // cosmetic rules, keeps the popup rule, and writes the $redirect-rule as $redirect.
    assert!(!pruned.contains("||tracker.example/pixel.gif"));
    assert!(!pruned.contains("tracker.example##.banner"));
    assert!(pruned.contains("||tracker.example^$popup\n"));
    assert!(pruned.contains("||tracker.example^$redirect=noopjs\n"));
    assert!(pruned.contains("other.example##.banner\n"));
    // The full list keeps them, the $redirect-rule as written.
    assert!(full.contains("||tracker.example/pixel.gif\n"));
    assert!(full.contains("||tracker.example^$redirect-rule=noopjs\n"));
    // The UI lists every served list with its counts.
    let (_, lists) = get(&c, "/browser-lists").await;
    let pruned_row = lists
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["url"] == "/lists/profiles/default.txt")
        .unwrap()
        .clone();
    assert!(
        pruned_row["stats"]["dns_blocked"].as_u64().unwrap() >= 2,
        "{pruned_row}"
    );
    assert_eq!(pruned_row["stats"]["cancelled"], 1);
    // Off again: 404, the files gone.
    p["browser_list"] = json!({"enabled": false});
    let r = ui(&c, Method::PUT, "/profiles/default")
        .json(&p)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    picket_core::lists::build_profile_lists(&c.state, "default")
        .await
        .unwrap();
    assert_eq!(
        fetch(&c, "/lists/profiles/default.txt", &[]).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fetch(&c, "/lists/profiles/default-full.txt", &[]).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fetch(&c, "/lists/nope.txt", &[]).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fetch(&c, "/lists/..%2Fcore.db", &[]).await.status(),
        StatusCode::NOT_FOUND
    );
}

/// Browser list warnings (bundles.md §8): an exception of one feed exactly cancelling another
/// feed's rule in a bundle list raises one `bundle_warning`, resolved once the exception goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_list_warnings() {
    let c = core().await;
    browser_feed(&c, "w1").await;
    browser_feed(&c, "w2").await;
    put_entity(
        &c,
        "bundles",
        "wl",
        json!({"id": "wl", "name": "wl", "feeds": [{"feed": "w1"}, {"feed": "w2"}]}),
    )
    .await;
    save(&c, "w1", "||ads.example/banner.js\n").await;
    save(&c, "w2", "@@||ads.example/banner.js\n").await;
    build(&c, "wl").await;
    picket_core::lists::build_bundle_list(&c.state, "wl")
        .await
        .unwrap();
    let open = |c: &Core| {
        let st = c.state.clone();
        async move {
            st.alerts
                .list(
                    picket_core::alerts::AlertFilter {
                        kind: Some("bundle_warning".into()),
                        bundle: Some("wl".into()),
                        state: Some(picket_core::alerts::AlertState::Open),
                        ..Default::default()
                    },
                    None,
                    50,
                )
                .await
                .unwrap()
                .into_iter()
                .filter(|a| a.details["warning"] == "browser_between_feeds")
                .map(|a| a.details)
                .collect::<Vec<Value>>()
        }
    };
    let w = open(&c).await;
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!(w[0]["rule"], "@@||ads.example/banner.js");
    save(&c, "w2", "").await;
    build(&c, "wl").await;
    picket_core::lists::build_bundle_list(&c.state, "wl")
        .await
        .unwrap();
    assert!(open(&c).await.is_empty());
}

/// The served text of a list (empty while it isn't served).
/// Issue 80: browser rules with no restriction and a pattern under 3 characters (`$image`,
/// `*$third-party`, `$removeparam=utm_source`, `@@*$script`) are kept through ingest and reach the
/// browser list as written; the run counts them as a non-blocking notice with samples. A broad DNS
/// rule is still dropped as too wide, and a feed whose browser mode drops browser rules keeps none
/// (and notes none).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broad_browser_rules_reach_the_lists() {
    let c = core().await;
    browser_feed(&c, "bf").await;
    put_entity(
        &c,
        "bundles",
        "bl",
        json!({"id": "bl", "name": "bl", "feeds": [{"feed": "bf"}]}),
    )
    .await;
    let broad = ["$removeparam=utm_source", "$image,third-party", "*$third-party", "@@*$script"];
    save(
        &c,
        "bf",
        &format!("{}\n||ok.example/ads.js\n*\n||dns.example^\n", broad.join("\n")),
    )
    .await;
    let parse = |feed: &str| {
        let f = feed.to_string();
        let state = c.state.clone();
        async move {
            let s: String = state
                .db
                .read(move |db| {
                    Ok::<_, anyhow::Error>(db.query_row(
                        "SELECT parse_json FROM feed_runs WHERE feed_id = ?1 ORDER BY id DESC LIMIT 1",
                        [f],
                        |r| r.get(0),
                    )?)
                })
                .await
                .unwrap();
            serde_json::from_str::<Value>(&s).unwrap()
        }
    };
    let p = parse("bf").await;
    assert_eq!(p["entries"]["browser"], 5, "{p}");
    assert_eq!(p["warnings"], json!({"TooWide": 1}), "only the DNS `*`: {p}");
    assert_eq!(p["notices"], json!({"BroadBrowser": 4}), "{p}");
    assert_eq!(p["notice_samples"][0]["text"], broad[0], "{p}");
    assert_eq!(p["notice_samples"][0]["line_no"], 1, "{p}");
    build(&c, "bl").await;
    picket_core::lists::build_bundle_list(&c.state, "bl")
        .await
        .unwrap();
    let text = served(&c, "/lists/bl.txt").await;
    for l in broad.iter().chain(&["||ok.example/ads.js"]) {
        assert!(text.lines().any(|x| x == *l), "{l} in the list: {text}");
    }
    assert!(!text.lines().any(|x| x == "*"), "{text}");
    // Browser rules dropped by the feed's mode: none kept, no notice.
    manual_feed(&c, "df", json!({})).await;
    save(&c, "df", &format!("{}\n||dns.example^\n", broad.join("\n"))).await;
    let p = parse("df").await;
    assert_eq!(p.get("notices"), None, "{p}");
    assert_eq!(p["kept"], 1, "{p}");
    // Browser rules the rule policy drops (`browser_changes: drop` takes `$removeparam` and the
    // exception): no notice for them, the kept ones still noted.
    manual_feed(
        &c,
        "pf",
        json!({"modes": {"browser": {"mode": "replace"}}, "rule_policy": {"browser_changes": "drop"}}),
    )
    .await;
    save(&c, "pf", &format!("{}\n", broad.join("\n"))).await;
    let p = parse("pf").await;
    assert_eq!(p["notices"], json!({"BroadBrowser": 2}), "{p}");
    let texts: Vec<&str> = p["notice_samples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts, vec![broad[1], broad[2]], "{p}");
}

async fn served(c: &Core, path: &str) -> String {
    let r = fetch(c, path, &[]).await;
    if r.status() != StatusCode::OK {
        return String::new();
    }
    r.text().await.unwrap()
}

/// Turns the default profile's list on with these block bundles and no allow bundle.
async fn profile_list(c: &Core, block: &[&str]) {
    let (_, mut p) = get(c, "/profiles/default").await;
    p["browser_list"] = json!({"enabled": true});
    p["allow"] = json!([]);
    p["block"] = json!(block);
    let r = ui(c, Method::PUT, "/profiles/default")
        .json(&p)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
}

/// Rules anchored on an IP host stay in the pruned list (review round 1, CP3; bundles.md §8): a
/// browser never asks DNS for an address, whatever key the address folds into.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ip_host_rules_stay_in_the_pruned_list() {
    let c = core().await;
    browser_feed(&c, "bf").await;
    put_entity(
        &c,
        "bundles",
        "bl",
        json!({"id": "bl", "name": "bl", "feeds": [{"feed": "bf"}]}),
    )
    .await;
    save(
        &c,
        "bf",
        "||1.2.3.4^\n||1.2.3.4/ads.js\n1.2.3.4##.ad\n||blocked.example^\n||blocked.example/x.js\n",
    )
    .await;
    build(&c, "bl").await;
    profile_list(&c, &["bl"]).await;
    picket_core::lists::build_profile_lists(&c.state, "default")
        .await
        .unwrap();
    let pruned = served(&c, "/lists/profiles/default.txt").await;
    assert!(pruned.contains("||1.2.3.4/ads.js\n"), "{pruned}");
    assert!(pruned.contains("1.2.3.4##.ad\n"), "{pruned}");
    assert!(!pruned.contains("||blocked.example/x.js"), "{pruned}");
}

/// A subdomain-only exception at the name lets subdomains resolve (review round 1, CP4; bundles.md
/// §8 DNS-blocked names): the name's scope isn't DNS-blocked, so its rules stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subdomain_exception_at_the_name_keeps_its_rules() {
    let c = core().await;
    browser_feed(&c, "bf").await;
    put_entity(
        &c,
        "bundles",
        "bl",
        json!({"id": "bl", "name": "bl", "feeds": [{"feed": "bf"}]}),
    )
    .await;
    save(
        &c,
        "bf",
        "||tracker.example^\n@@*.tracker.example^\n||tracker.example/pixel.gif\n||plain.example^\n||plain.example/x.gif\n",
    )
    .await;
    build(&c, "bl").await;
    profile_list(&c, &["bl"]).await;
    picket_core::lists::build_profile_lists(&c.state, "default")
        .await
        .unwrap();
    let pruned = served(&c, "/lists/profiles/default.txt").await;
    assert!(pruned.contains("||tracker.example/pixel.gif\n"), "{pruned}");
    assert!(!pruned.contains("||plain.example/x.gif"), "{pruned}");
}

/// Lists follow their triggers (review round 1, CP2, CP15; bundles.md §8 Builds) with no direct
/// call: a feed run's browser rules reach the bundle list, turning a profile's list on writes it,
/// and a new exception pattern (only `patterns.bin` changes) rebuilds the pruned list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lists_follow_their_triggers() {
    let c = core().await;
    browser_feed(&c, "bf3").await;
    put_entity(
        &c,
        "bundles",
        "bl3",
        json!({"id": "bl3", "name": "bl3", "feeds": [{"feed": "bf3"}]}),
    )
    .await;
    save(&c, "bf3", "||blocked.example^\n||blocked.example/x.js\n").await;
    wait("the bundle list", || async {
        served(&c, "/lists/bl3.txt")
            .await
            .contains("||blocked.example/x.js\n")
    })
    .await;
    profile_list(&c, &["bl3"]).await;
    wait("the profile lists", || async {
        let full = served(&c, "/lists/profiles/default-full.txt").await;
        let pruned = served(&c, "/lists/profiles/default.txt").await;
        full.contains("||blocked.example/x.js\n") && pruned.starts_with("! Title") && !pruned.contains("x.js")
    })
    .await;
    // An exception pattern: blocked.example resolves again, so the pruned list takes the rule back.
    save(
        &c,
        "bf3",
        "||blocked.example^\n||blocked.example/x.js\n@@/blocked\\.example/\n",
    )
    .await;
    wait("the DNS-change rebuild", || async {
        served(&c, "/lists/profiles/default.txt")
            .await
            .contains("||blocked.example/x.js\n")
    })
    .await;
}

/// A member that stops giving `browser` rules leaves the profile's lists (review round 1, CP5;
/// bundles.md §8 Builds).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_types_change_reaches_the_profile_lists() {
    let c = core().await;
    browser_feed(&c, "bf5").await;
    put_entity(
        &c,
        "bundles",
        "bl5",
        json!({"id": "bl5", "name": "bl5", "feeds": [{"feed": "bf5"}]}),
    )
    .await;
    save(
        &c,
        "bf5",
        "||ads.example/x.js\nexample.com##.ad\n||blocked.example^\n",
    )
    .await;
    build(&c, "bl5").await;
    profile_list(&c, &["bl5"]).await;
    wait("the profile list", || async {
        served(&c, "/lists/profiles/default-full.txt")
            .await
            .contains("example.com##.ad\n")
    })
    .await;
    put_entity(
        &c,
        "bundles",
        "bl5",
        json!({"id": "bl5", "name": "bl5", "feeds": [{"feed": "bf5", "rule_types": ["dns"]}]}),
    )
    .await;
    wait("the rewrite", || async {
        let full = served(&c, "/lists/profiles/default-full.txt").await;
        full.starts_with("! Title") && !full.contains("example.com##.ad")
    })
    .await;
    wait("the bundle list to go", || async {
        fetch(&c, "/lists/bl5.txt", &[]).await.status() == StatusCode::NOT_FOUND
    })
    .await;
}
