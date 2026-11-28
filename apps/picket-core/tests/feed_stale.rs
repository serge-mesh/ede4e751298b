//! `feed_stale` and the feed side of a restore (build-and-test.md §5 "Scheduler", "Config
//! export"; feed-scheduling.md §3, §6, §8): a `github` feed's warm-start history with a gap cut
//! in raises `feed_stale` on its first check, the unmodified history doesn't; a restored feed
//! fakes no change when its server sends the same bytes under another ETag, stays stale, and
//! records a real change.

use crate::common;

use std::sync::{Arc, Mutex};

use common::Core;
use common::feeds::{check_provider, ui, wait_until};
use common::github::{self, commit};
use jiff::Timestamp;
use picket_core::feeds::schedule::learner::Obs;
use picket_core::modules::download::testkit::{Reply, Seen, TestServer};
use reqwest::{Method, StatusCode};
use serde_json::json;

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

async fn alert_state(c: &Core, key: &str) -> Option<String> {
    c.state.alerts.get_by_key(key).await.unwrap().map(|a| {
        serde_json::to_value(a.state)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    })
}

/// A github provider whose one file changed once a day for 20 days, the newest change `last_h`
/// hours ago; returns once the feed's first check (with its warm start) ran.
async fn github_feed(last_h: i64) -> (TestServer, Core) {
    let (srv, repo) = github::fake().await;
    let now = Timestamp::now();
    {
        let mut r = repo.lock().unwrap();
        r.set(1, &[("list.txt", "||a.example^\n")]);
        r.commits = (0..20)
            .map(|i| {
                let t = now - jiff::SignedDuration::from_hours(last_h + 24 * i);
                commit(&picket_api::time::format_secs(&t), false)
            })
            .collect();
    }
    let c = core_with(&srv).await;
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(
            &json!({"id": "gh", "name": "GH", "module": "github", "config": {"owner": "o", "repo": "r"},
                      "files": [{"match": "list.txt", "feed": {"format": "adblock"}}]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    // The provider's first check lists the repository and adds the feed; the feed's own first
    // check reads its history first.
    wait_until("the feed", || async { c.state.feeds.def("gh-list").is_some() }).await;
    // The listing's check queued the new feed's check, which `min_interval` holds back; a
    // provider without a previous check is due at once.
    wait_until("the provider to be free", || async {
        !c.state.feeds.is_checking("gh")
    })
    .await;
    c.state.feeds.clear_last_check("gh");
    wait_until("the feed's first check", || async {
        q_i64(
            &c,
            "SELECT count(*) FROM feed_checks WHERE feed_id = 'gh-list' AND method <> 'bootstrap'",
        )
        .await
            >= 1
            && !c.state.feeds.is_busy("gh-list")
            && !c.state.feeds.is_checking("gh")
    })
    .await;
    (srv, c)
}

/// feed-scheduling.md §6, §8: a daily feed quiet for 10 days (a gap cut into its history) is
/// stale at its first check; one whose last change was an hour ago isn't. The warm start's
/// changes count toward the 5 it needs, and the reference is frozen from them as the model stood
/// right after the last change (not one that has also seen the quiet days since, which would
/// explain them away), with `n` averaged over the 19 days the warm start read (≈ 1.05 a day:
/// threshold ln(30 × 1.05) ≈ 3.45), not over 60 days (0.33, threshold 3).
#[tokio::test(flavor = "multi_thread")]
async fn a_history_with_a_gap_raises_feed_stale_and_the_unmodified_one_doesnt() {
    for (last_h, stale) in [(10 * 24, true), (1, false)] {
        let (_srv, c) = github_feed(last_h).await;
        assert_eq!(
            q_i64(
                &c,
                "SELECT count(*) FROM feed_state WHERE feed_id = 'gh-list' AND warm_started_at IS NOT NULL"
            )
            .await,
            1
        );
        assert_eq!(
            q_i64(
                &c,
                "SELECT count(*) FROM feed_state WHERE feed_id = 'gh-list' AND stale_ref_json IS NOT NULL"
            )
            .await,
            1,
            "the warm start froze a reference"
        );
        let j: String = c
            .state
            .db
            .read(|db| {
                Ok::<_, anyhow::Error>(db.query_row(
                    "SELECT stale_ref_json FROM feed_state WHERE feed_id = 'gh-list'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        let r: picket_core::feeds::stale::Reference = serde_json::from_str(&j).unwrap();
        assert!(
            (r.n - 20.0 / 19.0).abs() < 0.01,
            "n over the span read, not 60 days: {}",
            r.n
        );
        let state = alert_state(&c, "feed_stale:gh-list").await;
        if stale {
            assert_eq!(state.as_deref(), Some("open"), "quiet for 10 days");
            let a = c
                .state
                .alerts
                .get_by_key("feed_stale:gh-list")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(a.details["changes_in_60d"], 20, "{}", a.details);
            assert!(a.details["usual_gap_s"].as_f64().unwrap() > 0.0, "{}", a.details);
            assert_eq!(a.feed_provider.as_deref(), Some("gh"));
        } else {
            assert_eq!(state, None, "the unmodified history isn't stale");
        }
    }
}

/// A daily learner frozen at a change `quiet_days` ago, as a staleness reference.
fn daily_reference(quiet_days: f64) -> String {
    let day = 86_400.0;
    let now = picket_core::feeds::schedule::to_secs(Timestamp::now());
    let start = now - (quiet_days + 30.0) * day;
    let mut l = picket_core::feeds::Learner::new();
    let mut t = start;
    let mut last = start;
    while t < now - quiet_days * day {
        t += 900.0;
        let exact = if t - last >= day {
            last = t - 1.0;
            vec![t - 1.0]
        } else {
            vec![]
        };
        l.observe(
            &Obs {
                t,
                exact,
                interval: false,
            },
            false,
        );
    }
    l.refit(t);
    picket_core::feeds::stale::Reference::new(l.frozen(), last, 30, 60.0, "daily".into()).to_json()
}

/// core.md §2, feed-scheduling.md §3: a restore clears every feed's `last`, so its next check is
/// a first check, which records a change only if the bytes differ from its `seen_blake3`. The
/// same bytes under another ETag fake no change (a stale feed stays stale); new bytes record one
/// and resolve `feed_stale`.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_feed_fakes_no_change() {
    let body = Arc::new(Mutex::new(("a.example\n".to_string(), "\"e1\"".to_string())));
    let b = body.clone();
    let srv = TestServer::start(&["lists.example"], move |s: &Seen| {
        let (text, etag) = b.lock().unwrap().clone();
        if s.header("if-none-match") == Some(etag.as_str()) {
            return Reply::status(304);
        }
        Reply::ok(text).header("etag", &etag)
    })
    .await;
    let c = core_with(&srv).await;
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&json!({"id": "p", "name": "P", "module": "http", "config": {"url": "https://lists.example/l.txt"},
                      "files": [{"match": "response", "feed": {"format": "plain"}}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    wait_until("the first run", || async {
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
    assert_eq!(
        q_i64(
            &c,
            "SELECT count(*) FROM feed_state WHERE feed_id = 'p' AND seen_blake3 IS NOT NULL"
        )
        .await,
        1
    );
    // Quiet for 6 days by its frozen reference; the export taken now carries it.
    let reference = daily_reference(6.0);
    c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE feed_state SET stale_ref_json = ?1 WHERE feed_id = 'p'",
                [reference],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let (side, checks) = c
        .state
        .db
        .read(|db| {
            let side = picket_core::feeds::restore::export(db)?;
            let mut checks = Vec::new();
            picket_core::feeds::restore::export_checks(db, |part| {
                checks.push(part);
                Ok(())
            })?;
            Ok::<_, anyhow::Error>((side, checks))
        })
        .await
        .unwrap();
    assert!(
        side.feeds
            .iter()
            .any(|f| f.feed == "p" && f.seen_blake3.is_some() && f.stale_ref.is_some()),
        "{side:?}"
    );
    // The restore's feed side: `last` cleared, the history and the reference back.
    let changes = q_i64(&c, "SELECT count(*) FROM feed_changes WHERE feed_id = 'p'").await;
    c.state
        .config
        .change(move |tx| {
            tx.execute("DELETE FROM feed_changes", [])?;
            tx.execute("DELETE FROM feed_checks", [])?;
            tx.execute("DELETE FROM feed_provider_checks", [])?;
            picket_core::feeds::restore::restore_in(tx, &side.feeds, &side.providers)?;
            for part in &checks {
                picket_core::feeds::restore::restore_check_in(tx, part)?;
            }
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        q_i64(&c, "SELECT count(*) FROM feed_state WHERE feed_id = 'p' AND last_json IS NULL AND stale_ref_json IS NOT NULL").await,
        1
    );
    assert_eq!(
        q_i64(&c, "SELECT count(*) FROM feed_changes WHERE feed_id = 'p'").await,
        changes,
        "the history is back"
    );
    // The same bytes under another ETag: a first check without a change; the feed is stale.
    body.lock().unwrap().1 = "\"e2\"".into();
    wait_until("the provider to be free", || async {
        !c.state.feeds.is_checking("p")
    })
    .await;
    let checks = q_i64(&c, "SELECT count(*) FROM feed_checks WHERE feed_id = 'p'").await;
    check_provider(&c, "p").await;
    wait_until("the check", || async {
        q_i64(&c, "SELECT count(*) FROM feed_checks WHERE feed_id = 'p'").await > checks
            && !c.state.feeds.is_busy("p")
            && !c.state.feeds.is_checking("p")
    })
    .await;
    assert_eq!(
        q_i64(&c, "SELECT count(*) FROM feed_changes WHERE feed_id = 'p'").await,
        changes,
        "no faked change"
    );
    assert_eq!(alert_state(&c, "feed_stale:p").await.as_deref(), Some("open"));
    // New bytes: a real change, recorded; feed_stale resolves.
    *body.lock().unwrap() = ("b.example\n".into(), "\"e3\"".into());
    let checks = q_i64(&c, "SELECT count(*) FROM feed_checks WHERE feed_id = 'p'").await;
    check_provider(&c, "p").await;
    wait_until("the change", || async {
        q_i64(&c, "SELECT count(*) FROM feed_checks WHERE feed_id = 'p'").await > checks
            && !c.state.feeds.is_busy("p")
            && !c.state.feeds.is_checking("p")
    })
    .await;
    assert_eq!(
        q_i64(&c, "SELECT count(*) FROM feed_changes WHERE feed_id = 'p'").await,
        changes + 1
    );
    assert_eq!(alert_state(&c, "feed_stale:p").await.as_deref(), Some("resolved"));
}

/// FP8 (feed-scheduling.md §4 "Rebuild", §6): a learner rebuild replays the epoch's warm start
/// with its span (its first `bootstrap` check predates the epoch), so the warm-start changes still
/// train the model after the start-up and daily rebuilds.
#[tokio::test(flavor = "multi_thread")]
async fn a_rebuild_keeps_the_warm_start() {
    let (_srv, c) = github_feed(1).await;
    let before = c.state.feeds.learner("gh-list").unwrap();
    assert!(before.changes.len() >= 19, "{:?}", before.changes);
    c.state.feeds.rebuild_learners_now(&c.state).await;
    let after = c.state.feeds.learner("gh-list").unwrap();
    assert!(
        after.changes.len() >= 19,
        "the rebuilt model still has the warm start's changes: {:?}",
        after.changes
    );
    let t = picket_core::feeds::schedule::to_secs(Timestamp::now());
    let (a, b) = (after.rate(t), before.rate(t));
    assert!(a > b / 3.0 && a < b * 3.0, "rate {a} after vs {b} before");
}
