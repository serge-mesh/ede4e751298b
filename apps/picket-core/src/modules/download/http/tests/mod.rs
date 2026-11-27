//! `http` against a local HTTPS server: the probe, each rung of the ladder, 304s, ETags,
//! redirects, oversized, slow, gzip and HTML bodies, change times, a provider's one file and a
//! URL gone (`Missing`) (build-and-test.md §5 "Download modules").

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::modules::download::client::{Http, HttpOptions};
use crate::modules::download::testkit::{Reply, ReplyBody, Seen, TestServer};

const HOST: &str = "lists.example";

fn ctx(opts: HttpOptions, dir: &std::path::Path, last_ok: Option<Timestamp>) -> Ctx {
    Ctx::new(Http::new(opts).unwrap(), "f1", dir, 1 << 20, Default::default())
        .with_now(Timestamp::now(), last_ok)
}

/// A provider's check of its one file, [`FILE`].
async fn check1(
    m: &Module,
    ctx: &Ctx,
    cfg: &serde_json::Value,
    last: Option<&LastRun>,
) -> Result<CheckOutcome, CheckError> {
    let feeds = [FileCheck {
        file: FILE.into(),
        last: last.cloned(),
    }];
    let pc = m.check(ctx, cfg, None, &feeds, &[]).await?;
    assert!(pc.listing.is_none(), "http lists no files");
    let (f, r) = pc.files.into_iter().next().unwrap();
    assert_eq!(f, FILE);
    r
}

fn last_of(out: &CheckOutcome) -> LastRun {
    match out {
        CheckOutcome::Changed {
            updated_at,
            version,
            state,
            ..
        } => LastRun {
            updated_at: *updated_at,
            version: version.clone(),
            state: state.clone(),
        },
        o => panic!("expected Changed: {o:?}"),
    }
}

fn method_of(l: &LastRun) -> String {
    l.state["method"].as_str().unwrap_or_default().to_string()
}

/// A server that serves `body` with an ETag and honours `If-None-Match`.
fn etag_server(body: Arc<Mutex<(String, String)>>) -> impl Fn(&Seen) -> Reply + Send + Sync + 'static {
    move |s: &Seen| {
        let (b, etag) = body.lock().unwrap().clone();
        if s.header("if-none-match") == Some(etag.as_str()) {
            return Reply::status(304);
        }
        Reply::ok(b).header("etag", &etag)
    }
}

#[tokio::test]
async fn conditional_rung_with_etags_and_304() {
    let body = Arc::new(Mutex::new(("||a.example^\n".to_string(), "\"v1\"".to_string())));
    let srv = TestServer::start(&[HOST], etag_server(body.clone())).await;
    let d = tempfile::tempdir().unwrap();
    let cfg = json!({"url": format!("https://{HOST}/list.txt")});

    let out = check1(&Module, &ctx(srv.http_options(), d.path(), None), &cfg, None)
        .await
        .unwrap();
    let last = last_of(&out);
    assert_eq!(method_of(&last), "conditional");
    assert_eq!(last.version, "\"v1\"");
    // probe: a plain GET then the conditional probe.
    assert_eq!(srv.seen().len(), 2);
    drop(out);
    assert_eq!(
        std::fs::read_dir(d.path()).unwrap().count(),
        0,
        "the staged file went with the outcome"
    );

    srv.clear();
    let out = check1(
        &Module,
        &ctx(srv.http_options(), d.path(), None),
        &cfg,
        Some(&last),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            out,
            CheckOutcome::Unchanged {
                method: "conditional",
                ..
            }
        ),
        "{out:?}"
    );
    assert_eq!(srv.seen()[0].header("if-none-match"), Some("\"v1\""));

    // New content: Changed with the new ETag.
    *body.lock().unwrap() = ("||b.example^\n".into(), "\"v2\"".into());
    let out = check1(
        &Module,
        &ctx(srv.http_options(), d.path(), None),
        &cfg,
        Some(&last),
    )
    .await
    .unwrap();
    let last2 = last_of(&out);
    assert_eq!(last2.version, "\"v2\"");
    drop(out);

    // A new ETag with the same body: Unchanged, with the new validator kept.
    *body.lock().unwrap() = ("||b.example^\n".into(), "\"v3\"".into());
    match check1(
        &Module,
        &ctx(srv.http_options(), d.path(), None),
        &cfg,
        Some(&last2),
    )
    .await
    .unwrap()
    {
        CheckOutcome::Unchanged { state: Some(st), .. } => assert_eq!(st["etag"], "\"v3\""),
        o => panic!("{o:?}"),
    }
}

#[tokio::test]
async fn range_rung_and_full_backstop() {
    let body = Arc::new(Mutex::new(
        "! Last modified: 2026-11-20T10:00:00Z\n||a.example^\n".to_string(),
    ));
    // The server answers ranges with 206.
    let srv206 = {
        let b = body.clone();
        TestServer::start(&[HOST], move |s: &Seen| {
            let text = b.lock().unwrap().clone();
            if s.header("range").is_some() {
                let mut r = Reply::ok(text.clone()).header(
                    "content-range",
                    &format!("bytes 0-{}/{}", text.len() - 1, text.len()),
                );
                r.status = 206;
                return r;
            }
            Reply::ok(text)
        })
        .await
    };
    let d = tempfile::tempdir().unwrap();
    let cfg = json!({"url": format!("https://{HOST}/list.txt")});

    let out = check1(&Module, &ctx(srv206.http_options(), d.path(), None), &cfg, None)
        .await
        .unwrap();
    let last = last_of(&out);
    assert_eq!(method_of(&last), "range");
    match &out {
        CheckOutcome::Changed { change_times, .. } => assert_eq!(
            change_times,
            &vec![ChangeTime::Exact("2026-11-20T10:00:00Z".parse().unwrap())],
            "the header date line is the change time"
        ),
        _ => unreachable!(),
    }
    drop(out);
    srv206.clear();
    let out = check1(
        &Module,
        &ctx(srv206.http_options(), d.path(), None),
        &cfg,
        Some(&last),
    )
    .await
    .unwrap();
    assert!(
        matches!(out, CheckOutcome::Unchanged { method: "range", .. }),
        "{out:?}"
    );
    assert_eq!(srv206.seen().len(), 1, "only the first 4 KiB");

    // A size change: the range differs, so a full GET follows.
    body.lock().unwrap().push_str("||b.example^\n");
    let out = check1(
        &Module,
        &ctx(srv206.http_options(), d.path(), None),
        &cfg,
        Some(&last),
    )
    .await
    .unwrap();
    assert!(
        matches!(out, CheckOutcome::Changed { method: "full", .. }),
        "{out:?}"
    );

    // The backstop: a day after the last full GET, a full GET even if the range matches.
    let mut stale = last.clone();
    stale.state["last_full"] = json!(picket_api::time::format_micros(
        &(Timestamp::now() - jiff::SignedDuration::from_hours(25))
    ));
    body.lock().unwrap().clear();
    body.lock()
        .unwrap()
        .push_str("! Last modified: 2026-11-20T10:00:00Z\n||a.example^\n");
    srv206.clear();
    let out = check1(
        &Module,
        &ctx(srv206.http_options(), d.path(), None),
        &cfg,
        Some(&stale),
    )
    .await
    .unwrap();
    assert!(
        matches!(out, CheckOutcome::Unchanged { method: "full", .. }),
        "{out:?}"
    );
    assert!(srv206.seen().iter().all(|s| s.header("range").is_none()));
}

#[tokio::test]
async fn full_rung_compares_bodies() {
    let srv = TestServer::start(&[HOST], |_| Reply::ok("1.2.3.4\n")).await;
    let d = tempfile::tempdir().unwrap();
    let cfg = json!({"url": format!("https://{HOST}/ips.txt")});

    let past = Timestamp::now() - jiff::SignedDuration::from_hours(1);
    let out = check1(
        &Module,
        &ctx(srv.http_options(), d.path(), Some(past)),
        &cfg,
        None,
    )
    .await
    .unwrap();
    let last = last_of(&out);
    assert_eq!(method_of(&last), "full");
    assert_eq!(last.version, hex::encode(sha2::Sha256::digest(b"1.2.3.4\n")));
    match &out {
        CheckOutcome::Changed { change_times, .. } => {
            assert!(
                matches!(change_times[0], ChangeTime::Interval { .. }),
                "no date: an interval"
            )
        }
        _ => unreachable!(),
    }
    let out = check1(
        &Module,
        &ctx(srv.http_options(), d.path(), None),
        &cfg,
        Some(&last),
    )
    .await
    .unwrap();
    assert!(matches!(out, CheckOutcome::Unchanged { method: "full", .. }));
}

#[tokio::test]
async fn last_modified_is_the_change_time_and_gzip_is_decoded() {
    let srv = TestServer::start(&[HOST], |_| {
        Reply::ok("||gz.example^\n".repeat(100))
            .header("last-modified", "Fri, 20 Nov 2026 10:00:00 GMT")
            .gzip()
    })
    .await;
    let d = tempfile::tempdir().unwrap();
    let cfg = json!({"url": format!("https://{HOST}/list.txt")});
    let out = check1(&Module, &ctx(srv.http_options(), d.path(), None), &cfg, None)
        .await
        .unwrap();
    match out {
        CheckOutcome::Changed {
            file,
            change_times,
            updated_at,
            ..
        } => {
            assert_eq!(
                std::fs::read(file.path()).unwrap(),
                "||gz.example^\n".repeat(100).as_bytes()
            );
            let t: Timestamp = "2026-11-20T10:00:00Z".parse().unwrap();
            assert_eq!(change_times, vec![ChangeTime::Exact(t)]);
            assert_eq!(updated_at, t);
        }
        o => panic!("{o:?}"),
    }
    let ae = srv.seen()[0].header("accept-encoding").unwrap().replace(' ', "");
    assert_eq!(ae, "gzip,br");
    assert!(srv.seen()[0].header("user-agent").unwrap().starts_with("picket/"));
}

#[tokio::test]
async fn failed_checks() {
    let srv = TestServer::start(&[HOST], |s: &Seen| match s.path.as_str() {
        "/html" => Reply::ok("<html>login</html>").header("content-type", "text/html; charset=utf-8"),
        "/500" => Reply::status(500),
        "/404" => Reply::status(404),
        "/big" => Reply::ok(vec![b'a'; 2 << 20]),
        "/slow" => Reply {
            status: 200,
            headers: vec![],
            body: ReplyBody::Slow {
                chunk: bytes::Bytes::from_static(b"a\n"),
                count: 10,
                delay: Duration::from_secs(3),
            },
        },
        _ => Reply::ok("ok\n"),
    })
    .await;
    let d = tempfile::tempdir().unwrap();
    let mut opts = srv.http_options();
    opts.idle_timeout = Duration::from_millis(500);
    for path in ["/html", "/500", "/404", "/big", "/slow"] {
        let cfg = json!({"url": format!("https://{HOST}{path}")});
        let r = check1(&Module, &ctx(opts.clone(), d.path(), None), &cfg, None).await;
        if path == "/404" {
            assert!(matches!(r, Err(CheckError::Missing)), "{path}: {r:?}");
        } else {
            assert!(matches!(r, Err(CheckError::Failed(_))), "{path}: {r:?}");
        }
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            0,
            "{path}: nothing staged is left behind"
        );
    }
}

#[tokio::test]
async fn redirects_are_bounded_https_only_and_drop_credentials() {
    let srv = TestServer::start(&[HOST, "mirror.example"], |s: &Seen| match s.path.as_str() {
        "/moved" => Reply::status(302).header("location", "https://mirror.example/list.txt"),
        "/loop" => Reply::status(302).header("location", "/loop"),
        "/plain" => Reply::status(301).header("location", "http://mirror.example/list.txt"),
        "/userinfo" => Reply::status(302).header("location", "https://u:pw@mirror.example/list.txt"),
        "/relative" => Reply::status(302).header("location", "/list.txt"),
        _ => Reply::ok("||r.example^\n"),
    })
    .await;
    let d = tempfile::tempdir().unwrap();
    let cfg = json!({"url": format!("https://{HOST}/moved"), "headers": {"X-Api-Key": "k-123456789", "Accept": "text/plain"}});
    let out = check1(&Module, &ctx(srv.http_options(), d.path(), None), &cfg, None)
        .await
        .unwrap();
    assert!(matches!(out, CheckOutcome::Changed { .. }));
    let seen = srv.seen();
    assert_eq!(
        seen[0].header("x-api-key"),
        Some("k-123456789"),
        "to the configured host"
    );
    assert_eq!(seen[1].host, "mirror.example");
    assert_eq!(seen[1].header("x-api-key"), None, "never across a redirect");
    assert_eq!(seen[1].header("accept"), Some("text/plain"), "plain headers stay");

    let cfg = json!({"url": format!("https://{HOST}/loop")});
    let e = check1(&Module, &ctx(srv.http_options(), d.path(), None), &cfg, None)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("redirects"), "{e}");
    let cfg = json!({"url": format!("https://{HOST}/plain")});
    let e = check1(&Module, &ctx(srv.http_options(), d.path(), None), &cfg, None)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("HTTPS"), "{e}");

    // README §2 Secrets: no credential crosses a redirect, user info included. A Location's
    // user info is dropped (reqwest would send it as Basic auth), and a request URL with user
    // info isn't sent at all (a relative redirect would keep it on every hop).
    srv.clear();
    let cfg = json!({"url": format!("https://{HOST}/userinfo")});
    check1(&Module, &ctx(srv.http_options(), d.path(), None), &cfg, None)
        .await
        .unwrap();
    let seen = srv.seen();
    assert!(seen.iter().any(|s| s.host == "mirror.example"), "{seen:?}");
    assert!(
        seen.iter().all(|s| s.header("authorization").is_none()),
        "{seen:?}"
    );
    let http = crate::modules::download::client::Http::new(srv.http_options()).unwrap();
    for url in [
        format!("https://u:pw@{HOST}/relative"),
        format!("https://u@{HOST}/relative"),
    ] {
        let e = http
            .send(crate::modules::download::client::Req::get(
                Url::parse(&url).unwrap(),
            ))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("user name or password"), "{url}: {e}");
    }
}

#[test]
fn config_checks() {
    let p = Module;
    // providers.md §3: one https URL, a query part of it; no fragment.
    for ok in [
        json!({"url": "https://a.example/x/"}),
        json!({"url": "https://a.example/list.txt"}),
        json!({"url": "https://a.example/?format=abp"}),
        json!({"url": "https://a.example/", "headers": {"Authorization": "Bearer ${secret:k}"}}),
    ] {
        assert!(p.normalize_config(&ok).is_ok(), "{ok}");
    }
    for bad in [
        json!({"url": "http://a.example/x"}),
        json!({"url": "https://a.example/x#part"}),
        json!({"url": "https://a.example/", "headers": {"Range": "x"}}),
        json!({"url": "https://a.example/", "date_line_regex": "("}),
        json!({"url": "https://a.example/", "extra": 1}),
        json!({"base_url": "https://a.example/x/"}),
    ] {
        assert!(p.normalize_config(&bad).is_err(), "{bad}");
    }
    // README §2 Secrets: no user info in a URL, written in clear or as a reference.
    for url in [
        "https://u:pw@a.example/x/",
        "https://u:${secret:pw}@a.example/x/",
        "https://u@a.example/x/",
    ] {
        let e = p.normalize_config(&json!({ "url": url })).unwrap_err();
        assert!(e.contains("use a header with a secret"), "{url}: {e}");
        let e = check_url(url).unwrap_err();
        assert!(e.contains("use a header with a secret"), "{url}: {e}");
    }
    // The location is the URL as providers are matched by it: scheme and host lowercase, no
    // default port or fragment, otherwise exact (the query too).
    assert_eq!(
        p.location(&json!({"url": "HTTPS://Lists.Example:443/A/b.txt?x=1#f"})),
        "https://lists.example/A/b.txt?x=1"
    );
    assert_eq!(
        url_key(&Url::parse("https://a.example:8443/x").unwrap()),
        "https://a.example:8443/x"
    );
    // One file, `response`; no file name is empty.
    assert!(p.check_file(&json!({}), FILE, false).is_ok());
    for bad in ["", " ", "./", "a.txt", "?x=1"] {
        let e = p.check_file(&json!({}), bad, false).unwrap_err();
        assert!(e.contains("\"response\""), "{bad}: {e}");
    }
    assert_eq!(p.fixed_file(), Some("response"));
    assert_eq!(p.default_files()[0].0, "response");
    assert_eq!(content_range_total("bytes 0-4095/123456"), Some(123456));
    assert_eq!(content_range_total("bytes 0-4095/*"), None);
    assert_eq!(content_range_total("junk"), None);
}

/// A provider is one URL: its one file is checked there; a `404` or `410` is `Missing`; any
/// other file name fails without a request.
#[tokio::test]
async fn one_file_per_provider_and_a_missing_url() {
    let srv = TestServer::start(&[HOST], |s: &Seen| match (s.path.as_str(), s.query.as_deref()) {
        ("/lists/a.txt", Some("v=2")) => Reply::ok("a.example\n").header("etag", "\"a1\""),
        ("/lists/gone.txt", _) => Reply::status(410),
        ("/lists/nope.txt", _) => Reply::status(404),
        _ => Reply::status(500),
    })
    .await;
    let d = tempfile::tempdir().unwrap();
    let c = ctx(srv.http_options(), d.path(), None);
    let files = |names: &[&str]| -> Vec<FileCheck> {
        names
            .iter()
            .map(|f| FileCheck {
                file: f.to_string(),
                last: None,
            })
            .collect()
    };
    let cfg = json!({"url": format!("https://{HOST}/lists/a.txt?v=2")});
    let pc = Module
        .check(&c, &cfg, None, &files(&[FILE, "b.txt"]), &[])
        .await
        .unwrap();
    assert!(matches!(pc.files[0], (ref f, Ok(CheckOutcome::Changed { .. })) if f == FILE));
    assert!(matches!(&pc.files[1].1, Err(CheckError::Failed(e)) if e.to_string().contains("one file")));
    assert!(
        srv.seen()
            .iter()
            .all(|s| s.path == "/lists/a.txt" && s.query.as_deref() == Some("v=2")),
        "only the URL, query and all"
    );
    for gone in ["gone.txt", "nope.txt"] {
        let cfg = json!({"url": format!("https://{HOST}/lists/{gone}")});
        assert!(
            matches!(check1(&Module, &c, &cfg, None).await, Err(CheckError::Missing)),
            "{gone}"
        );
    }
}
