//! `http_json` tests (providers.md §5; build-and-test.md §5 "Lookup sharing": each `http_json`
//! status, and which count against health). Recorded bodies are in this directory.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use picket_api::edge_config::LookupSettings;
use serde_json::{Value, json};
use tokio::time::Instant;

use super::{Config, MAX_BODY, interpret};
use crate::client::{ClientOptions, LookupClient, ProviderSpec, Role, SyncRequest, SyncResult};
use crate::ctx::{Connections, HttpError, HttpResponse};
use crate::module::{LookupError, Verdict};
use crate::registry::Registry;
use crate::testkit::{MockDns, MockHttp, connections};

const HIGH: &str = include_str!("risk-high.json");
const LOW: &str = include_str!("risk-low.json");
const MIDDLE: &str = include_str!("risk-middle.json");
const NO_SCORE: &str = include_str!("no-score.json");
const HTML: &str = include_str!("captive-portal.html");

fn spec_cfg() -> Value {
    json!({"method": "GET", "url": "https://api.example.net/v1/domain/{domain}",
           "headers": {"Authorization": "Bearer ${secret:key}"},
           "verdict": {"pointer": "/risk_score", "block_if": ">= 7.0", "clean_if": "< 4.0"}})
}

fn cfg(v: Value) -> Config {
    serde_json::from_value(v).unwrap()
}

fn now() -> Timestamp {
    "2026-11-21T10:00:00Z".parse::<Timestamp>().unwrap()
}

fn ok(status: u16, body: &str) -> Result<HttpResponse, HttpError> {
    Ok(MockHttp::response(status, &[], body.as_bytes()))
}

#[test]
fn status_table() {
    let c = cfg(spec_cfg());
    let v = |r| interpret(&c, r, now());
    // 200: parsed.
    assert_eq!(
        v(ok(200, HIGH)).unwrap().verdict,
        Verdict::Block {
            score: Some(8.5),
            reason: "/risk_score >= 7.0".into()
        }
    );
    assert_eq!(v(ok(200, LOW)).unwrap().verdict, Verdict::Clean);
    assert_eq!(
        v(ok(200, MIDDLE)).unwrap().verdict,
        Verdict::Unknown,
        "no comparison matched"
    );
    assert_eq!(
        v(ok(200, NO_SCORE)).unwrap().verdict,
        Verdict::Unknown,
        "missing pointer"
    );
    assert!(
        matches!(v(ok(200, HTML)), Err(LookupError::Failed(_))),
        "not JSON"
    );
    assert!(v(ok(200, HIGH)).unwrap().detail.is_none());
    // 404: Unknown.
    assert_eq!(v(ok(404, "{}")).unwrap().verdict, Verdict::Unknown);
    // 429: Rejected, with Retry-After in seconds or as an HTTP date; none or unreadable: None.
    let r429 = |h: &[(&str, &str)]| v(Ok(MockHttp::response(429, h, b"")));
    assert!(matches!(
        r429(&[("retry-after", "120")]),
        Err(LookupError::Rejected { retry_after: Some(d) }) if d == Duration::from_secs(120)
    ));
    assert!(matches!(
        r429(&[("retry-after", "Sat, 21 Nov 2026 10:05:00 GMT")]),
        Err(LookupError::Rejected { retry_after: Some(d) }) if d == Duration::from_secs(300)
    ));
    assert!(matches!(
        r429(&[]),
        Err(LookupError::Rejected { retry_after: None })
    ));
    assert!(matches!(
        r429(&[("retry-after", "later")]),
        Err(LookupError::Rejected { retry_after: None })
    ));
    // 5xx, timeouts and transport errors: Failed.
    for s in [500, 502, 503, 599] {
        assert!(matches!(v(ok(s, "")), Err(LookupError::Failed(_))), "{s}");
    }
    for e in [
        HttpError::Timeout,
        HttpError::Connect("refused".into()),
        HttpError::Transport("reset".into()),
        HttpError::BodyTooLarge { limit: MAX_BODY },
    ] {
        assert!(matches!(v(Err(e.clone())), Err(LookupError::Failed(_))), "{e}");
    }
    // Any other status, redirects included: Other.
    for s in [201, 204, 301, 302, 307, 308, 400, 401, 403, 410, 451] {
        assert!(matches!(v(ok(s, "")), Err(LookupError::Other(_))), "{s}");
    }
    assert!(matches!(
        v(Err(HttpError::Refused("scheme".into()))),
        Err(LookupError::Other(_))
    ));
    // A body past the cap is Failed even if a client hands it over.
    let big = format!("{{\"risk_score\": 9, \"pad\": \"{}\"}}", "x".repeat(MAX_BODY));
    assert!(matches!(v(ok(200, &big)), Err(LookupError::Failed(_))));
}

/// Review round 2, CR7: a Block's reason holds `block_if` as written (the client then redacts
/// it), not trimmed: a secret resolved into it with its own surrounding spaces stays whole.
/// README §2 Secrets: the checked config's `Debug` (and the raw config's) prints no resolved
/// secret: not the query, user info or header values.
#[test]
fn config_debug_leaves_secrets_out() {
    let v = json!({"url": "https://api.example/v1/{domain}?key=SECRET1&format=json",
                   "headers": {"X-Api-Key": "SECRET2"},
                   "verdict": {"pointer": "/risk", "block_if": ">= 7"}});
    let c = cfg(v.clone());
    let raw: super::RawConfig = serde_json::from_value(v).unwrap();
    let text = format!("{c:?} {raw:?}");
    for leak in ["SECRET1", "SECRET2", "format=json"] {
        assert!(!text.contains(leak), "{leak} in {text}");
    }
    assert!(text.contains("https://api.example/v1/{domain}"), "{text}");
    assert!(text.contains("x-api-key") && text.contains("X-Api-Key"), "{text}");
    assert_eq!(
        super::template_for_logs("https://u:p@{domain}.dnsbl.example/x?k=v#f"),
        "https://{domain}.dnsbl.example/x"
    );
}

/// README §2 Secrets: a resolved secret anywhere in the config (the URL's host or path, a verdict
/// comparison) is redacted from the checked and raw configs' `{:?}`.
#[test]
fn config_debug_redacts_secrets_in_host_path_and_comparisons() {
    let secrets: BTreeMap<String, String> = [
        ("dqs", "dqskeyhost2024"),
        ("ipqs", "ipqspathkey2025"),
        ("token", "comparetoken2026"),
        ("hdr", "headervalue2027"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let v = json!({"url": "https://${secret:dqs}.zen.example/url/${secret:ipqs}/{domain}",
                   "headers": {"X-Key": "${secret:hdr}"},
                   "verdict": {"pointer": "/v", "block_if": "== \"${secret:token}\""}});
    let resolved = crate::secrets::resolve(&v, &secrets).unwrap().config;
    let c = cfg(resolved.clone());
    let raw: super::RawConfig = serde_json::from_value(resolved).unwrap();
    for text in [format!("{c:?}"), format!("{raw:?}"), format!("{c:#?}")] {
        for s in secrets.values() {
            assert!(!text.contains(s.as_str()), "{s} in {text}");
        }
        assert!(
            text.contains("${secret:token}") && text.contains("${secret:ipqs}"),
            "{text}"
        );
    }
}

#[test]
fn reason_keeps_block_if_as_written() {
    let c = cfg(json!({"url": "https://x.example/{domain}",
                       "verdict": {"pointer": "/s", "block_if": "  == true  "}}));
    assert_eq!(
        c.decide(&json!({"s": true})),
        Verdict::Block {
            score: None,
            reason: "/s   == true  ".into()
        }
    );
}

#[test]
fn comparisons_and_pointers() {
    let c = cfg(json!({"url": "https://x.example/{domain}",
                       "verdict": {"pointer": "/data/0/category", "block_if": "== \"malicious\""}}));
    let doc = json!({"data": [{"category": "malicious"}]});
    assert_eq!(
        c.decide(&doc),
        Verdict::Block {
            score: None,
            reason: "/data/0/category == \"malicious\"".into()
        }
    );
    assert_eq!(
        c.decide(&json!({"data": [{"category": "benign"}]})),
        Verdict::Unknown
    );
    // block_if is checked first.
    let c = cfg(json!({"url": "https://x.example/{domain}",
                       "verdict": {"pointer": "/s", "block_if": ">= 5", "clean_if": ">= 1"}}));
    assert!(matches!(c.decide(&json!({"s": 6})), Verdict::Block { .. }));
    assert_eq!(c.decide(&json!({"s": 2})), Verdict::Clean);
    // Only clean_if.
    let c = cfg(json!({"url": "https://x.example/{domain}",
                       "verdict": {"pointer": "/listed", "clean_if": "== false"}}));
    assert_eq!(c.decide(&json!({"listed": false})), Verdict::Clean);
    assert_eq!(c.decide(&json!({"listed": true})), Verdict::Unknown);
}

#[test]
fn request_formation() {
    let c = cfg(
        json!({"method": "POST", "url": "https://api.example.net/v1/{domain}/info?d={domain}&k=1",
                       "headers": {"Authorization": "Bearer abc", "Accept": "application/vnd.x+json"},
                       "verdict": {"pointer": "/s", "block_if": ">= 1"}}),
    );
    let req = c.request("a b/c?d#e").unwrap();
    assert_eq!(req.method, http::Method::POST);
    assert_eq!(
        req.url.as_str(),
        "https://api.example.net/v1/a%20b%2Fc%3Fd%23e/info?d=a%20b%2Fc%3Fd%23e&k=1"
    );
    assert_eq!(req.headers["authorization"], "Bearer abc");
    assert_eq!(req.headers["accept"], "application/vnd.x+json");
    assert_eq!(req.max_body, MAX_BODY);
    assert!(req.body.is_none());
    let c = cfg(spec_cfg());
    let req = c.request("bad.example.org").unwrap();
    assert_eq!(req.method, http::Method::GET);
    assert_eq!(
        req.url.as_str(),
        "https://api.example.net/v1/domain/bad.example.org"
    );
    assert_eq!(req.headers["accept"], "application/json");
}

#[test]
fn config_checks() {
    let base = |url: &str, headers: Value, verdict: Value| {
        serde_json::from_value::<Config>(json!({"url": url, "headers": headers, "verdict": verdict}))
            .map_err(|e| e.to_string())
    };
    let v = json!({"pointer": "/s", "block_if": ">= 1"});
    assert!(base("https://x.example/{domain}", json!({}), v.clone()).is_ok());
    for (url, why) in [
        ("http://x.example/{domain}", "https"),
        ("https://x.example/d", "{domain}"),
        ("https://{domain}.x.example/", "after the host"),
        ("https://user:pw@x.example/{domain}", "user info"),
        ("https://x.example/{domain}#frag", "fragment"),
        ("not a url {domain}", "url"),
    ] {
        let e = base(url, json!({}), v.clone()).unwrap_err();
        assert!(e.contains(why), "{url}: {e}");
    }
    let secret = "s3cr3t-value";
    for (headers, why) in [
        (json!({"Host": "x"}), "set by the client"),
        (json!({"bad header": "x"}), "invalid header name"),
        (
            json!({"X-Key": format!("{secret}\r\nInjected: 1")}),
            "invalid value",
        ),
        (json!({"X-Key": "x".repeat(5000)}), "over"),
    ] {
        let e = base("https://x.example/{domain}", headers.clone(), v.clone()).unwrap_err();
        assert!(e.contains(why), "{headers}: {e}");
        assert!(
            !e.contains(secret),
            "a header value never appears in an error: {e}"
        );
    }
    for (verdict, why) in [
        (json!({"pointer": "s", "block_if": ">= 1"}), "pointer"),
        (json!({"pointer": "/s"}), "block_if, clean_if or both"),
        (json!({"pointer": "/s", "block_if": "about 7"}), "block_if"),
        (json!({"pointer": "/s", "clean_if": "< x"}), "clean_if"),
    ] {
        let e = base("https://x.example/{domain}", json!({}), verdict.clone()).unwrap_err();
        assert!(e.contains(why), "{verdict}: {e}");
    }
    let many: BTreeMap<String, String> = (0..33).map(|i| (format!("x-h{i}"), "v".into())).collect();
    assert!(base("https://x.example/{domain}", json!(many), v).is_err());
}

// ---------------------------------------------------------------------------------------------
// Through the LookupClient

fn client(http: Arc<MockHttp>, settings: LookupSettings) -> LookupClient {
    let conns = connections(
        http,
        MockDns::new(|_, _| Err(crate::ctx::DnsClientError::Timeout)),
    );
    let factory: crate::ctx::ConnectionFactory = Arc::new(move |_: &str| -> Connections { conns.clone() });
    let secrets = BTreeMap::from([("key".to_owned(), "s3cr3t-token".to_owned())]);
    LookupClient::new(
        ProviderSpec {
            id: "am-rt".into(),
            module: "http_json".into(),
            config: spec_cfg(),
            generation: "3f9a0c17d2e84b65".into(),
            settings,
        },
        &secrets,
        ClientOptions::new(Role::Edge, Arc::new(Registry::builtin()), factory),
    )
}

async fn sync(c: &LookupClient, name: &str) -> SyncResult {
    c.lookup_sync(SyncRequest {
        name,
        deadline: Instant::now() + Duration::from_secs(5),
        call: true,
        tag: None,
    })
    .await
    .result
}

fn no_cache() -> LookupSettings {
    let mut s = LookupSettings::default();
    s.cache.block_ttl_s = 0;
    s.cache.clean_ttl_s = 0;
    s.cache.unknown_ttl_s = 0;
    s.cache.error_ttl_s = 0;
    s
}

/// The header's `${secret:key}` is resolved before the call.
#[tokio::test]
async fn secrets_resolved_before_the_call() {
    let http = MockHttp::new(|_| ok(200, HIGH));
    let c = client(http.clone(), no_cache());
    assert!(matches!(
        sync(&c, "bad.example.org").await,
        SyncResult::Verdict { .. }
    ));
    let sent = http.sent();
    assert_eq!(sent[0].headers["authorization"], "Bearer s3cr3t-token");
}

/// A transport error quoting the request (as some clients do) reaches no one with the secret.
#[tokio::test]
async fn secret_values_redacted_from_errors() {
    let http = MockHttp::new(|req| {
        Err(HttpError::Transport(format!(
            "error sending {} with {:?}",
            req.url,
            req.headers.get("authorization")
        )))
    });
    let c = client(http, no_cache());
    match sync(&c, "bad.example.org").await {
        SyncResult::Error { message, .. } => {
            assert!(!message.contains("s3cr3t-token"), "{message}");
            assert!(message.contains("${secret:key}"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

/// build-and-test.md §5 "Lookup sharing": 5xx counts against health (the breaker opens after
/// `failures`), other statuses don't, and 429 pauses the provider.
#[tokio::test(start_paused = true)]
async fn which_statuses_count_against_health() {
    // 403 five times: Other, the breaker stays closed.
    let c = client(MockHttp::new(|_| ok(403, "")), no_cache());
    for i in 0..6 {
        let r = sync(&c, &format!("n{i}.example")).await;
        assert!(
            matches!(
                r,
                SyncResult::Error {
                    kind: crate::client::ErrorKind::Other,
                    ..
                }
            ),
            "{r:?}"
        );
    }
    assert_eq!(c.metrics().breaker_open, 0);
    assert_eq!(c.metrics().errors, 6);

    // 503 five times: Failed, the breaker opens and the next lookup makes no call.
    let http = MockHttp::new(|_| ok(503, ""));
    let c = client(http.clone(), no_cache());
    for i in 0..5 {
        let r = sync(&c, &format!("n{i}.example")).await;
        assert!(
            matches!(
                r,
                SyncResult::Error {
                    kind: crate::client::ErrorKind::Failed,
                    ..
                }
            ),
            "{r:?}"
        );
    }
    assert_eq!(c.metrics().breaker_open, 1);
    assert_eq!(sync(&c, "n9.example").await, SyncResult::BreakerOpen);
    assert_eq!(http.sent().len(), 5);

    // 429: a rejection, then the provider is paused: no call while paused.
    let http = MockHttp::new(|_| Ok(MockHttp::response(429, &[("retry-after", "30")], b"")));
    let c = client(http.clone(), no_cache());
    assert_eq!(
        sync(&c, "a.example").await,
        SyncResult::Rejected { paused: false }
    );
    assert_eq!(sync(&c, "b.example").await, SyncResult::Rejected { paused: true });
    assert_eq!(http.sent().len(), 1);
    let m = c.metrics();
    assert_eq!((m.rejected, m.paused, m.breaker_open), (1, 1, 0));
}

#[tokio::test]
async fn not_found_is_unknown_and_cached_briefly() {
    let http = MockHttp::new(|_| ok(404, ""));
    let c = client(http.clone(), LookupSettings::default());
    for _ in 0..3 {
        assert!(matches!(
            sync(&c, "new.example").await,
            SyncResult::Verdict {
                verdict: crate::StoredVerdict::Unknown,
                ..
            }
        ));
    }
    assert_eq!(http.sent().len(), 1, "unknown_ttl_s 60 keeps it");
}
