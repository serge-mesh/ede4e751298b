//! `alphamountain_threat_1000` against a local HTTPS server with the recorded CSV.

use serde_json::json;

use super::*;
use crate::modules::download::client::Http;
use crate::modules::download::testkit::{Reply, Seen, TestServer};

const CSV: &str = include_str!("list.csv");
const HOST: &str = "files.alphamountain.ai";

/// The provider's one file, `community-threat-1000`.
async fn check1(
    ctx: &Ctx,
    cfg: &serde_json::Value,
    last: Option<&LastRun>,
) -> Result<CheckOutcome, CheckError> {
    let feeds = [FileCheck {
        file: FILE.into(),
        last: last.cloned(),
    }];
    let pc = Module.check(ctx, cfg, None, &feeds, &[]).await?;
    pc.files.into_iter().next().unwrap().1
}

#[tokio::test]
async fn converts_and_answers_304() {
    let srv = TestServer::start(&[HOST], |s: &Seen| {
        if s.header("if-none-match") == Some("\"am1\"") {
            return Reply::status(304);
        }
        Reply::ok(CSV)
            .header("content-type", "text/csv")
            .header("etag", "\"am1\"")
            .header("last-modified", "Fri, 20 Nov 2026 06:00:00 GMT")
    })
    .await;
    let d = tempfile::tempdir().unwrap();
    let ctx = || {
        Ctx::new(
            Http::new(srv.http_options()).unwrap(),
            "am",
            d.path(),
            1 << 20,
            Default::default(),
        )
    };
    let cfg = json!({});
    let out = check1(&ctx(), &cfg, None).await.unwrap();
    let last = match out {
        CheckOutcome::Changed {
            file,
            version,
            state,
            updated_at,
            ..
        } => {
            assert_eq!(version, "\"am1\"");
            assert_eq!(updated_at, "2026-11-20T06:00:00Z".parse::<Timestamp>().unwrap());
            let text = std::fs::read_to_string(file.path()).unwrap();
            let names: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
            assert_eq!(
                names,
                vec![
                    "malware-dropper.example",
                    "phish-login.example",
                    "quoted-host.example",
                    "borderline.example",
                    "not a hostname"
                ],
                "the plain parser rejects and counts the bad name"
            );
            assert_eq!(state["csv"]["rejected_cells"], 1);
            // The plain parser reads it: four names, one error.
            let cfgp = picket_rules::formats::ParseConfig::new(
                picket_rules::formats::Format::Plain,
                picket_rules::formats::DomainsAs::Exact,
                Timestamp::now(),
            );
            let mut n = 0;
            let stats = picket_rules::formats::parse_lines(text.as_bytes(), &cfgp, |_| n += 1).unwrap();
            assert_eq!((n, stats.errors), (4, 1));
            LastRun {
                updated_at,
                version,
                state,
            }
        }
        o => panic!("{o:?}"),
    };
    let out = check1(&ctx(), &cfg, Some(&last)).await.unwrap();
    assert!(matches!(out, CheckOutcome::Unchanged { .. }), "{out:?}");
    // A new minimum converts again, without the validators.
    let out = check1(&ctx(), &json!({"min_risk_score": 9.0}), Some(&last))
        .await
        .unwrap();
    match out {
        CheckOutcome::Changed { file, .. } => {
            let text = std::fs::read_to_string(file.path()).unwrap();
            assert_eq!(text.lines().filter(|l| !l.starts_with('#')).count(), 3);
        }
        o => panic!("{o:?}"),
    }
    assert!(Module.normalize_config(&json!({"min_risk_score": 11})).is_err());
    assert!(
        Module
            .normalize_config(&json!({"url": "http://x.example/a.csv"}))
            .is_err()
    );
    // README §2 Secrets: no user info in the configurable URL (it uses check_url).
    let e = Module
        .normalize_config(&json!({"url": "https://u:${secret:pw}@x.example/a.csv"}))
        .unwrap_err();
    assert!(e.contains("use a header with a secret"), "{e}");
    // providers.md §3: one file, `community-threat-1000`, which `files` selects by default; no
    // file name is empty.
    assert!(
        Module
            .check_file(&json!({}), "community-threat-1000", false)
            .is_ok()
    );
    assert!(Module.check_file(&json!({}), "x", false).is_err());
    let e = Module.check_file(&json!({}), "", false).unwrap_err();
    assert!(e.contains("community-threat-1000"), "{e}");
    assert_eq!(Module.default_files()[0].0, "community-threat-1000");
    assert_eq!(Module.location(&json!({})), DEFAULT_URL);
    let feeds = [FileCheck {
        file: "other".into(),
        last: None,
    }];
    let pc = Module.check(&ctx(), &json!({}), None, &feeds, &[]).await.unwrap();
    assert!(pc.files[0].1.is_err(), "another file fails");
}
