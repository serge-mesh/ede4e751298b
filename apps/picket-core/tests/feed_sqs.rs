//! The `sqs` trigger against a local SQS-compatible server (build-and-test.md §5 "Scheduler",
//! feed-scheduling.md §7): SigV4-signed JSON-protocol requests, messages coalesced into one
//! nudge and one check, the nudge recorded in core.db before the batch is deleted (so a restart
//! between receive and check loses none), a redelivered message id ignored, a delete reply with
//! failed entries retried, a nudge during a check, the backstop, receives failing raising
//! `feed_provider_trigger_down`, and a queue a second provider can't use.

use crate::common;

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::feeds::{check_provider, ui, wait_until};
use common::{Core, client};
use jiff::Timestamp;
use picket_core::modules::download::testkit::{Reply, ReplyBody, Seen, TestServer};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const SQS: &str = "sqs.us-east-1.amazonaws.com";
const LISTS: &str = "lists.example";
const QUEUE: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/lists";
/// A second queue (a trigger edited to another queue).
const OTHER: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/other";
const BODY: &str = "SECRET-MESSAGE-BODY {\"Records\": []}";

/// The fake queue.
#[derive(Default)]
struct Queue {
    /// (id, receipt) waiting.
    waiting: VecDeque<(String, String)>,
    /// Receipts deleted, in order.
    deleted: Vec<String>,
    /// Receipts whose delete fails (once each).
    fail_delete: HashSet<String>,
    /// Receipts whose delete fails once with `ReceiptHandleIsInvalid` (a sender fault), as a FIFO
    /// queue's do after the visibility timeout.
    stale_once: HashSet<String>,
    /// Message ids whose deletes always fail: `(code, sender fault)`.
    fail_always: std::collections::HashMap<String, (String, bool)>,
    /// Messages received and not deleted come back at the next receive with a new receipt handle
    /// (a visibility timeout of zero).
    redeliver: bool,
    /// (id, receipt) received and not deleted.
    inflight: Vec<(String, String)>,
    receive_fails: bool,
    receives: usize,
    /// `nudged_at` as core.db held it when each delete arrived.
    nudged_at_delete: Vec<bool>,
    /// A request whose signature header was wrong.
    bad_auth: Vec<String>,
    db: Option<std::path::PathBuf>,
    next: u32,
    /// Delete entries answered with a failure from `fail_always`.
    delete_failures: usize,
    /// Delete replies arrive 3 s late (a delete in flight).
    slow_delete: bool,
    /// Receives of [`OTHER`].
    other_receives: usize,
}

impl Queue {
    fn push(&mut self, id: &str) {
        self.next += 1;
        self.waiting
            .push_back((id.to_string(), format!("rh-{id}-{}", self.next)));
    }
}

fn handle(q: &Mutex<Queue>, s: &Seen) -> Reply {
    let mut q = q.lock().unwrap();
    let auth = s.header("authorization").unwrap_or_default().to_string();
    if !(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/")
        && auth.contains("/us-east-1/sqs/aws4_request")
        && auth.contains("SignedHeaders=")
        && auth.contains("Signature=")
        && s.header("x-amz-date").is_some()
        && !auth.contains("wJalrXUtnFEMI"))
    {
        q.bad_auth.push(auth.clone());
    }
    let body: Value = serde_json::from_slice(&s.body).unwrap_or(Value::Null);
    if body["QueueUrl"] == OTHER {
        // The other queue is only ever polled, and stays empty.
        assert_eq!(s.header("x-amz-target"), Some("AmazonSQS.ReceiveMessage"));
        q.other_receives += 1;
        return Reply {
            status: 200,
            headers: vec![("content-type".into(), "application/x-amz-json-1.0".into())],
            body: ReplyBody::Slow {
                chunk: bytes::Bytes::from_static(b"{\"Messages\": []}"),
                count: 1,
                delay: Duration::from_millis(200),
            },
        };
    }
    assert_eq!(body["QueueUrl"], QUEUE);
    match s.header("x-amz-target") {
        Some("AmazonSQS.ReceiveMessage") => {
            q.receives += 1;
            if q.receive_fails {
                let mut r = Reply::ok(
                    "{\"__type\": \"com.amazonaws.sqs#AccessDenied\", \"message\": \"account 123456789012\"}",
                )
                .header("content-type", "application/x-amz-json-1.0");
                r.status = 400;
                return r;
            }
            if q.redeliver {
                let back: Vec<(String, String)> = std::mem::take(&mut q.inflight);
                for (id, _) in back.into_iter().rev() {
                    q.next += 1;
                    let rh = format!("rh-{id}-{}", q.next);
                    q.waiting.push_front((id, rh));
                }
            }
            let batch: Vec<(String, String)> = {
                let n = q.waiting.len().min(10);
                q.waiting.drain(..n).collect()
            };
            if q.redeliver {
                q.inflight.extend(batch.iter().cloned());
            }
            let msgs: Vec<Value> = batch
                .into_iter()
                .map(|(id, rh)| json!({"MessageId": id, "ReceiptHandle": rh, "MD5OfBody": "x", "Body": BODY}))
                .collect();
            let text = json!({"Messages": msgs}).to_string();
            if msgs.is_empty() {
                // A long poll that waits: a short delay keeps the loop from spinning.
                return Reply {
                    status: 200,
                    headers: vec![("content-type".into(), "application/x-amz-json-1.0".into())],
                    body: ReplyBody::Slow {
                        chunk: bytes::Bytes::from(text),
                        count: 1,
                        delay: Duration::from_millis(200),
                    },
                };
            }
            Reply::ok(text).header("content-type", "application/x-amz-json-1.0")
        }
        Some("AmazonSQS.DeleteMessageBatch") => {
            let nudged = q.db.as_ref().is_some_and(|db| {
                let c = rusqlite::Connection::open(db).unwrap();
                c.query_row(
                    "SELECT nudged_at IS NOT NULL FROM feed_provider_state WHERE provider_id = 'q'",
                    [],
                    |r| r.get::<_, bool>(0),
                )
                .unwrap_or(false)
            });
            q.nudged_at_delete.push(nudged);
            let mut ok = Vec::new();
            let mut failed = Vec::new();
            let entries = body["Entries"].as_array().cloned().unwrap_or_default();
            assert!(entries.len() <= 10, "DeleteMessageBatch takes at most 10 entries");
            for e in entries {
                let rh = e["ReceiptHandle"].as_str().unwrap().to_string();
                let id = e["Id"].as_str().unwrap().to_string();
                let msg = rh
                    .strip_prefix("rh-")
                    .and_then(|r| r.rsplit_once('-'))
                    .map(|(m, _)| m.to_string())
                    .unwrap_or_default();
                if let Some((code, sender)) = q.fail_always.get(&msg).cloned() {
                    failed.push(json!({"Id": id, "SenderFault": sender, "Code": code, "Message": "x"}));
                    q.delete_failures += 1;
                } else if q.stale_once.remove(&rh) {
                    failed.push(
                        json!({"Id": id, "SenderFault": true, "Code": "ReceiptHandleIsInvalid", "Message": "x"}),
                    );
                    q.delete_failures += 1;
                } else if q.fail_delete.remove(&rh) {
                    failed.push(
                        json!({"Id": id, "SenderFault": false, "Code": "InternalError", "Message": "x"}),
                    );
                } else {
                    q.inflight.retain(|(_, r)| *r != rh);
                    q.deleted.push(rh);
                    ok.push(json!({"Id": id}));
                }
            }
            Reply::ok(json!({"Successful": ok, "Failed": failed}).to_string())
                .header("content-type", "application/x-amz-json-1.0")
        }
        other => panic!("unexpected SQS target {other:?}"),
    }
}

/// The fake SQS and a list server (slow while `slow` holds).
async fn servers() -> (TestServer, Arc<Mutex<Queue>>, Arc<std::sync::atomic::AtomicBool>) {
    let q = Arc::new(Mutex::new(Queue::default()));
    let slow = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (q2, s2) = (q.clone(), slow.clone());
    let srv = TestServer::start(&[SQS, LISTS], move |s: &Seen| {
        if s.host == SQS {
            let mut reply = handle(&q2, s);
            let slow_delete = s.header("x-amz-target") == Some("AmazonSQS.DeleteMessageBatch")
                && q2.lock().unwrap().slow_delete;
            if slow_delete && let ReplyBody::Bytes(chunk) = reply.body {
                reply.body = ReplyBody::Slow {
                    chunk,
                    count: 1,
                    delay: Duration::from_secs(3),
                };
            }
            return reply;
        }
        if s2.load(std::sync::atomic::Ordering::SeqCst) {
            return Reply {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: ReplyBody::Slow {
                    chunk: bytes::Bytes::from_static(b"a.example\nb.example\n"),
                    count: 1,
                    delay: Duration::from_secs(5),
                },
            };
        }
        Reply::ok("a.example\n")
    })
    .await;
    (srv, q, slow)
}

async fn core_with(srv: &TestServer, patch: Value) -> Core {
    let mut p = json!({"web": {"tls": "off"}});
    for (k, v) in patch.as_object().unwrap() {
        p[k] = v.clone();
    }
    common::start_core_with(
        Some(p),
        picket_core::run::StartOptions {
            release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
            feed_http: srv.http_options(),
            ..Default::default()
        },
    )
    .await
}

async fn secrets(c: &Core) {
    for (n, v) in [
        ("aws_id", "AKIDTEST"),
        ("aws_key", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
    ] {
        let r = ui(c, Method::PUT, &format!("/secrets/{n}"))
            .json(&json!({"value": v}))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
    }
}

fn provider(min_interval: &str, backstop: &str) -> Value {
    json!({"id": "q", "name": "Q", "module": "http", "config": {"url": format!("https://{LISTS}/a.txt")},
           "files": [{"match": "response", "feed": {"format": "plain"}}],
           "trigger": {"kind": "sqs", "queue_url": QUEUE, "access_key_id": "${secret:aws_id}",
                       "secret_access_key": "${secret:aws_key}", "backstop": backstop, "min_interval": min_interval}})
}

async fn q_i64(c: &Core, sql: &str) -> i64 {
    let s = sql.to_string();
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&s, [], |r| r.get::<_, i64>(0))?))
        .await
        .unwrap()
}

async fn sqs_checks(c: &Core) -> i64 {
    q_i64(
        c,
        "SELECT count(*) FROM feed_provider_checks WHERE provider_id = 'q' AND cause = 'sqs'",
    )
    .await
}

async fn nudged(c: &Core) -> bool {
    q_i64(
        c,
        "SELECT count(*) FROM feed_provider_state WHERE provider_id = 'q' AND nudged_at IS NOT NULL",
    )
    .await
        == 1
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

async fn start(srv: &TestServer, q: &Arc<Mutex<Queue>>, patch: Value) -> Core {
    let c = core_with(srv, patch).await;
    q.lock().unwrap().db = Some(c.dir.path().join("core.db"));
    secrets(&c).await;
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&provider("1m", "1h"))
        .send()
        .await
        .unwrap();
    let st = r.status();
    assert_eq!(st, StatusCode::CREATED, "{}", r.text().await.unwrap());
    wait_until("the first check", || async {
        q_i64(
            &c,
            "SELECT count(*) FROM feed_provider_checks WHERE provider_id = 'q'",
        )
        .await
            >= 1
            && !c.state.feeds.is_checking("q")
            && !c.state.feeds.is_busy("q")
    })
    .await;
    c
}

/// Messages coalesce into one nudge and one check; the nudge is in core.db before the batch is
/// deleted; a redelivered id doesn't nudge again; a delete with a failed entry is retried; the
/// body is never stored; every request is signed.
#[tokio::test(flavor = "multi_thread")]
async fn messages_nudge_once_are_deleted_after_the_nudge_and_redeliveries_are_ignored() {
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    {
        let mut g = q.lock().unwrap();
        g.push("m1");
        g.push("m2");
        g.push("m3");
    }
    wait_until("the nudge", || async {
        nudged(&c).await || sqs_checks(&c).await >= 1
    })
    .await;
    // min_interval holds the check back; the test skips the wait.
    c.state.feeds.clear_last_check("q");
    wait_until("one sqs check", || async {
        sqs_checks(&c).await == 1 && !nudged(&c).await
    })
    .await;
    wait_until("the deletes", || async { q.lock().unwrap().deleted.len() == 3 }).await;
    assert!(
        q.lock().unwrap().nudged_at_delete.iter().all(|n| *n),
        "the nudge is recorded before the batch is deleted"
    );
    // A redelivered id: deleted, no new nudge.
    let receives = q.lock().unwrap().receives;
    q.lock().unwrap().push("m2");
    wait_until("the redelivery's delete", || async {
        q.lock().unwrap().deleted.len() == 4
    })
    .await;
    wait_until("another receive", || async {
        q.lock().unwrap().receives > receives + 1
    })
    .await;
    c.state.feeds.clear_last_check("q");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        sqs_checks(&c).await,
        1,
        "a redelivered message id doesn't nudge again"
    );
    // A delete reply with a failed entry (HTTP 200): retried.
    {
        let mut g = q.lock().unwrap();
        g.push("m4");
        let rh = g.waiting.back().unwrap().1.clone();
        g.fail_delete.insert(rh);
    }
    wait_until("the retried delete", || async {
        let g = q.lock().unwrap();
        g.deleted.iter().any(|d| d.starts_with("rh-m4-"))
    })
    .await;
    c.state.feeds.clear_last_check("q");
    wait_until("m4's check", || async { sqs_checks(&c).await == 2 }).await;
    // The body is never stored; the trigger's state keeps counts and times.
    let all: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT trigger_state_json FROM feed_provider_state WHERE provider_id = 'q'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(!all.contains("SECRET-MESSAGE-BODY"), "{all}");
    let st: Value = serde_json::from_str(&all).unwrap();
    assert_eq!(st["messages"], 4, "{st}");
    assert!(st["last_receive_at"].is_string() && st["last_message_at"].is_string());
    let ps = client()
        .get(common::feeds::url(&c, "/feed-providers/q/status"))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(ps["trigger"], "sqs");
    assert!(ps["sqs"]["last_receive_at"].is_string(), "{ps}");
    assert!(
        q.lock().unwrap().bad_auth.is_empty(),
        "{:?}",
        q.lock().unwrap().bad_auth
    );
}

/// A check clears only the nudges recorded before it started: one recorded during a check makes
/// the provider due again when it ends; the task doesn't poll while a check runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_nudge_during_a_check_makes_the_provider_due_again() {
    let (srv, q, slow) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    slow.store(true, std::sync::atomic::Ordering::SeqCst);
    let before = sqs_checks(&c).await;
    let started = || async {
        c.state
            .db
            .read(|db| {
                Ok::<_, anyhow::Error>(db.query_row(
                    "SELECT check_started_at FROM feed_provider_state WHERE provider_id = 'q'",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )?)
            })
            .await
            .unwrap()
    };
    let started_before = started().await;
    check_provider(&c, "q").await;
    // The check has recorded its start (a nudge after it is one "during" the check).
    wait_until("the check to run", || async {
        c.state.feeds.is_checking("q") && started().await != started_before
    })
    .await;
    let receives = q.lock().unwrap().receives;
    // What the poll task records when a long poll that began before the check returns now.
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_provider_state SET nudged_at = ?1 WHERE provider_id = 'q'",
                [picket_core::util::now_ts()],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    slow.store(false, std::sync::atomic::Ordering::SeqCst);
    wait_until("the check to end", || async { !c.state.feeds.is_checking("q") }).await;
    assert!(nudged(&c).await, "a nudge during the check survives it");
    assert!(
        q.lock().unwrap().receives <= receives + 1,
        "no polling while a check runs"
    );
    c.state.feeds.clear_last_check("q");
    wait_until("the nudge's check", || async {
        sqs_checks(&c).await > before && !nudged(&c).await
    })
    .await;
}

/// The backstop: with no message, the provider is due `backstop` after its previous check.
#[tokio::test(flavor = "multi_thread")]
async fn the_backstop_schedules_a_quiet_queue() {
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    let last: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT last_check_at FROM feed_provider_state WHERE provider_id = 'q'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    let last = picket_core::util::parse_ts(&last).unwrap();
    let due = c.state.feeds.next_due("q").unwrap();
    let gap = (due - last).as_secs();
    assert!((3500..=3700).contains(&gap), "the backstop (1 h): {gap} s");
}

/// Receives failing for the threshold raise `feed_provider_trigger_down` (which says which);
/// both succeeding again resolve it. A second provider can't use the queue.
#[tokio::test(flavor = "multi_thread")]
async fn failing_receives_raise_trigger_down_and_a_shared_queue_is_refused() {
    let (srv, q, _) = servers().await;
    q.lock().unwrap().receive_fails = true;
    let c = start(
        &srv,
        &q,
        json!({"alerts": {"thresholds": {"feed_provider_trigger_down": "0s"}}}),
    )
    .await;
    wait_until("trigger_down", || async {
        alert_state(&c, "feed_provider_trigger_down:q").await.as_deref() == Some("open")
    })
    .await;
    let a = c
        .state
        .alerts
        .get_by_key("feed_provider_trigger_down:q")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.details["failing"], json!(["receive"]), "{}", a.details);
    assert!(a.details["last_error"].as_str().unwrap().contains("AccessDenied"));
    assert!(
        !a.details.to_string().contains("123456789012"),
        "nothing the reply said beyond its type"
    );
    // Backstop checks go on: the provider keeps its schedule.
    assert!(c.state.feeds.next_due("q").is_some());
    q.lock().unwrap().receive_fails = false;
    wait_until("trigger_down resolved", || async {
        alert_state(&c, "feed_provider_trigger_down:q").await.as_deref() == Some("resolved")
    })
    .await;
    let mut other = provider("2m", "1h");
    other["id"] = json!("q2");
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(&other)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(r.text().await.unwrap().contains("queue_shared"));
}

async fn edit_provider(c: &Core, f: impl FnOnce(&mut Value)) {
    let r = client()
        .get(common::feeds::url(c, "/feed-providers/q"))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap();
    let mut p: Value = r.json().await.unwrap();
    f(&mut p);
    let r = ui(c, Method::PUT, "/feed-providers/q")
        .json(&p)
        .send()
        .await
        .unwrap();
    let st = r.status();
    assert_eq!(st, StatusCode::OK, "{}", r.text().await.unwrap());
}

/// Messages counted in the trigger's state.
async fn messages(c: &Core) -> i64 {
    q_i64(
        c,
        "SELECT coalesce(json_extract(trigger_state_json, '$.messages'), 0) FROM feed_provider_state WHERE provider_id = 'q'",
    )
    .await
}

/// Lets the pending nudge's check run (min_interval holds it back) and waits until it is served.
async fn serve_nudge(c: &Core) {
    wait_until("the nudge", || async { nudged(c).await }).await;
    c.state.feeds.clear_last_check("q");
    wait_until("the nudge's check", || async {
        !nudged(c).await && !c.state.feeds.is_checking("q")
    })
    .await;
}

/// feed-scheduling.md §7: the nudge is recorded before the batch is deleted. A nudge that can't
/// be recorded deletes nothing; the message comes back and is deleted once its nudge is stored.
#[tokio::test(flavor = "multi_thread")]
async fn a_nudge_that_cant_be_recorded_deletes_nothing() {
    let (srv, q, _) = servers().await;
    q.lock().unwrap().redeliver = true;
    let c = start(&srv, &q, json!({})).await;
    c.state
        .db
        .write(|db| {
            db.execute_batch(
                "CREATE TRIGGER fail_nudge BEFORE UPDATE OF nudged_at ON feed_provider_state
                 WHEN NEW.nudged_at IS NOT NULL BEGIN SELECT RAISE(FAIL, 'simulated storage failure'); END",
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let receives = q.lock().unwrap().receives;
    q.lock().unwrap().push("m1");
    wait_until("the message received again", || async {
        q.lock().unwrap().receives >= receives + 3
    })
    .await;
    assert!(
        q.lock().unwrap().deleted.is_empty(),
        "no delete without a durable nudge"
    );
    assert!(!nudged(&c).await);
    c.state
        .db
        .write(|db| {
            db.execute_batch("DROP TRIGGER fail_nudge")?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    wait_until("the delete", || async { !q.lock().unwrap().deleted.is_empty() }).await;
    assert!(q.lock().unwrap().nudged_at_delete.iter().all(|n| *n));
    serve_nudge(&c).await;
    assert_eq!(sqs_checks(&c).await, 1);
}

/// feed-scheduling.md §7 Errors: a delete entry that can't succeed with its receipt handle (an
/// invalid one, as a FIFO queue's become after the visibility timeout) is a failing delete that
/// isn't retried with that handle: its message comes back and the delete goes through with the
/// fresh one, which ends the streak. One the server keeps failing is retried on its own backoff
/// while receives go on (its message coming back meanwhile takes the fresh handle and waits for
/// that backoff), raises `feed_provider_trigger_down` ("delete") after its threshold, and
/// resolves once it goes through.
#[tokio::test(flavor = "multi_thread")]
async fn failing_deletes_never_stop_receives() {
    let (srv, q, _) = servers().await;
    q.lock().unwrap().redeliver = true;
    let c = start(
        &srv,
        &q,
        json!({"alerts": {"thresholds": {"feed_provider_trigger_down": "0s"}}}),
    )
    .await;
    let key = "feed_provider_trigger_down:q";
    {
        let mut g = q.lock().unwrap();
        g.push("m1");
        let rh = g.waiting.back().unwrap().1.clone();
        g.stale_once.insert(rh);
    }
    wait_until("m1's failed delete", || async {
        q.lock().unwrap().delete_failures >= 1
    })
    .await;
    wait_until("trigger_down", || async {
        alert_state(&c, key).await.as_deref() == Some("open")
    })
    .await;
    serve_nudge(&c).await;
    wait_until("m1 deleted with its fresh receipt handle", || async {
        q.lock().unwrap().deleted.iter().any(|d| d.starts_with("rh-m1-"))
    })
    .await;
    assert_eq!(
        q.lock().unwrap().delete_failures,
        1,
        "an entry that can't succeed isn't retried with its handle"
    );
    wait_until("trigger_down resolved", || async {
        alert_state(&c, key).await.as_deref() == Some("resolved")
    })
    .await;
    q.lock().unwrap().push("m2");
    wait_until("m2's nudge", || async { messages(&c).await >= 2 }).await;
    serve_nudge(&c).await;
    // The server fails m3's delete every time.
    q.lock()
        .unwrap()
        .fail_always
        .insert("m3".into(), ("InternalError".into(), false));
    q.lock().unwrap().push("m3");
    wait_until("m3's retries", || async {
        q.lock().unwrap().delete_failures >= 3
    })
    .await;
    wait_until("trigger_down", || async {
        alert_state(&c, key).await.as_deref() == Some("open")
    })
    .await;
    let a = c.state.alerts.get_by_key(key).await.unwrap().unwrap();
    assert_eq!(a.details["failing"], json!(["delete"]), "{}", a.details);
    serve_nudge(&c).await;
    q.lock().unwrap().push("m4");
    wait_until("m4's nudge while m3's delete is retried", || async {
        messages(&c).await >= 4
    })
    .await;
    wait_until("m4 deleted", || async {
        q.lock().unwrap().deleted.iter().any(|d| d.starts_with("rh-m4-"))
    })
    .await;
    assert_eq!(
        alert_state(&c, key).await.as_deref(),
        Some("open"),
        "m3's delete still fails"
    );
    q.lock().unwrap().fail_always.clear();
    wait_until("m3 deleted", || async {
        q.lock().unwrap().deleted.iter().any(|d| d.starts_with("rh-m3-"))
    })
    .await;
    wait_until("trigger_down resolved", || async {
        alert_state(&c, key).await.as_deref() == Some("resolved")
    })
    .await;
}

/// feed-scheduling.md §7, README §2 Alerts: pending deletes live in memory, so a task's start
/// ends a delete streak a stop left behind (an idle queue raises no `feed_provider_trigger_down`
/// for it); a trigger changed away from `sqs` resolves an open one.
#[tokio::test(flavor = "multi_thread")]
async fn a_task_start_ends_a_delete_streak_and_leaving_sqs_resolves_trigger_down() {
    let (srv, q, _) = servers().await;
    let c = start(
        &srv,
        &q,
        json!({"alerts": {"thresholds": {"feed_provider_trigger_down": "0s"}}}),
    )
    .await;
    let key = "feed_provider_trigger_down:q";
    let old = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(2)));
    c.state
        .db
        .write(move |db| {
            let j: String = db.query_row(
                "SELECT trigger_state_json FROM feed_provider_state WHERE provider_id = 'q'",
                [],
                |r| r.get(0),
            )?;
            let mut v: Value = serde_json::from_str(&j)?;
            v["delete_failing_since"] = json!(old);
            db.execute(
                "UPDATE feed_provider_state SET trigger_state_json = ?1 WHERE provider_id = 'q'",
                [v.to_string()],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    // The task starts again, as after a restart (a trigger edit restarts it).
    edit_provider(&c, |p| p["trigger"]["backstop"] = json!("2h")).await;
    let receives = q.lock().unwrap().receives;
    wait_until("receives of the new task", || async {
        q.lock().unwrap().receives >= receives + 2
    })
    .await;
    assert_ne!(
        alert_state(&c, key).await.as_deref(),
        Some("open"),
        "no delete is pending, so nothing is failing"
    );
    // Receives failing: open; the trigger changed to `dynamic`: resolved.
    q.lock().unwrap().receive_fails = true;
    wait_until("trigger_down", || async {
        alert_state(&c, key).await.as_deref() == Some("open")
    })
    .await;
    edit_provider(&c, |p| {
        p["trigger"] = json!({"kind": "dynamic", "min_interval": "1m"})
    })
    .await;
    wait_until("trigger_down resolved", || async {
        alert_state(&c, key).await.as_deref() == Some("resolved")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        alert_state(&c, key).await.as_deref(),
        Some("resolved"),
        "the stopped task writes nothing more"
    );
}

/// feed-scheduling.md §5: a trigger edit takes effect at once: `sqs` to a minutely `cron` with a
/// 1-minute floor is due within minutes, not at the old trigger's or a default hour.
#[tokio::test(flavor = "multi_thread")]
async fn a_trigger_edit_takes_effect_at_once() {
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    edit_provider(
        &c,
        |p| p["trigger"] = json!({"kind": "cron", "cron": "* * * * *", "jitter": "0s", "min_interval": "1m"}),
    )
    .await;
    wait_until("the cron edit", || async {
        c.state
            .feeds
            .provider_def("q")
            .is_some_and(|d| matches!(d.trigger, picket_core::config::model::Trigger::Cron { .. }))
    })
    .await;
    // The definition lands first and the next check is recomputed right after it (same reload),
    // so wait for that rather than reading once; a regression to the old trigger's time (an hour
    // away) still fails here.
    wait_until("a minutely cron's next check within minutes", || async {
        c.state
            .feeds
            .next_due("q")
            .is_some_and(|due| due < Timestamp::now() + jiff::SignedDuration::from_mins(3))
    })
    .await;
}

/// feeds.md §3 step 1: a busy feed (its run waiting) is left out of a check "until its run is
/// stored": a nudge the check couldn't serve for it stays recorded (durable), and once the run
/// is stored the provider is due again and a check covers the feed.
#[tokio::test(flavor = "multi_thread")]
async fn a_nudge_waits_for_a_busy_feed() {
    use picket_core::scheduler::Priority;
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
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
    // the feed's re-ingest waits behind it: the feed is busy.
    let r = client()
        .get(common::feeds::url(&c, "/feeds/q"))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap();
    let mut f: Value = r.json().await.unwrap();
    f["modes"]["dns"] = json!({"mode": "aggregate"});
    let r = ui(&c, Method::PUT, "/feeds/q").json(&f).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("the feed busy", || async { c.state.feeds.is_busy("q") }).await;
    let feed_checks = || async {
        q_i64(
            &c,
            "SELECT count(*) FROM feed_checks fc JOIN feed_provider_checks pc ON pc.id = fc.provider_check_id
             WHERE fc.feed_id = 'q' AND pc.cause = 'sqs'",
        )
        .await
    };
    q.lock().unwrap().push("m1");
    wait_until("the nudge", || async { nudged(&c).await }).await;
    c.state.feeds.clear_last_check("q");
    wait_until("the nudge's check", || async {
        sqs_checks(&c).await == 1 && !c.state.feeds.is_checking("q")
    })
    .await;
    assert_eq!(feed_checks().await, 0, "the feed was left out");
    assert!(nudged(&c).await, "the nudge stays for the feed left out");
    assert_eq!(c.state.feeds.owed("q"), Some("sqs"));
    gate.notify_one();
    wait_until("the feed's run stored", || async { !c.state.feeds.is_busy("q") }).await;
    c.state.feeds.clear_last_check("q");
    wait_until("the check that covers the feed", || async {
        feed_checks().await == 1 && !nudged(&c).await && !c.state.feeds.is_checking("q")
    })
    .await;
    assert_eq!(c.state.feeds.owed("q"), None);
}

/// The trigger's stored state.
async fn trigger_state(c: &Core) -> Value {
    let j: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT trigger_state_json FROM feed_provider_state WHERE provider_id = 'q'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    serde_json::from_str(&j).unwrap()
}

/// Q1 (feed-scheduling.md §7 Errors, core.md §9): a failed delete entry SQS says can't succeed
/// with its receipt handle (`SenderFault`) is a failing delete: it starts the delete streak
/// (`feed_provider_trigger_down` "delete" after its threshold), which only a delete that goes
/// through ends; the message comes back and is deleted with its fresh receipt handle.
#[tokio::test(flavor = "multi_thread")]
async fn a_delete_entry_that_cant_succeed_keeps_the_streak_until_a_delete_succeeds() {
    let (srv, q, _) = servers().await;
    q.lock().unwrap().redeliver = true;
    let c = start(
        &srv,
        &q,
        json!({"alerts": {"thresholds": {"feed_provider_trigger_down": "0s"}}}),
    )
    .await;
    let key = "feed_provider_trigger_down:q";
    q.lock()
        .unwrap()
        .fail_always
        .insert("m1".into(), ("AccessDenied".into(), true));
    q.lock().unwrap().push("m1");
    wait_until("trigger_down", || async {
        alert_state(&c, key).await.as_deref() == Some("open")
    })
    .await;
    let a = c.state.alerts.get_by_key(key).await.unwrap().unwrap();
    assert_eq!(a.details["failing"], json!(["delete"]), "{}", a.details);
    // Served, the queue hands m1 back: still failing, still open.
    serve_nudge(&c).await;
    let fails = q.lock().unwrap().delete_failures;
    wait_until("m1's delete retried", || async {
        q.lock().unwrap().delete_failures > fails
    })
    .await;
    assert_eq!(alert_state(&c, key).await.as_deref(), Some("open"));
    assert!(trigger_state(&c).await["delete_failing_since"].is_string());
    // The delete goes through with m1's fresh receipt handle: resolved.
    q.lock().unwrap().fail_always.clear();
    wait_until("m1 deleted", || async {
        q.lock().unwrap().deleted.iter().any(|d| d.starts_with("rh-m1-"))
    })
    .await;
    wait_until("trigger_down resolved", || async {
        alert_state(&c, key).await.as_deref() == Some("resolved")
    })
    .await;
    assert!(trigger_state(&c).await["delete_failing_since"].is_null());
}

/// Q4 (feed-scheduling.md §7 Errors and Pacing): a message whose delete is pending comes back
/// (here at once, a visibility timeout of zero): it takes its fresh receipt handle and waits for
/// the pending backoff (1, 2, 4 … s), and receives that bring only such messages wait for it too
/// (at most a long poll's time), instead of a delete, a receive and a core.db write per loop.
#[tokio::test(flavor = "multi_thread")]
async fn a_redelivered_message_whose_delete_is_pending_waits_for_its_backoff() {
    let (srv, q, _) = servers().await;
    q.lock().unwrap().redeliver = true;
    let c = start(&srv, &q, json!({})).await;
    q.lock()
        .unwrap()
        .fail_always
        .insert("m1".into(), ("InternalError".into(), false));
    q.lock().unwrap().push("m1");
    serve_nudge(&c).await;
    let (f0, r0) = {
        let g = q.lock().unwrap();
        (g.delete_failures, g.receives)
    };
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (f1, r1) = {
        let g = q.lock().unwrap();
        (g.delete_failures, g.receives)
    };
    assert!(f1 - f0 <= 4, "{} failed deletes in 5 s", f1 - f0);
    assert!(r1 - r0 <= 6, "{} receives in 5 s", r1 - r0);
    // It is still retried, and deleted once SQS lets it.
    q.lock().unwrap().fail_always.clear();
    wait_until("m1 deleted", || async {
        q.lock().unwrap().deleted.iter().any(|d| d.starts_with("rh-m1-"))
    })
    .await;
}

/// Q5 (feed-scheduling.md §7, README §2 Alerts): disabling an `sqs` provider ends its trigger
/// state like a trigger change (the receive streak goes, so enabling it again doesn't alert at
/// the first failed receive), and a stopped task's delete still in flight writes nothing (its
/// result can't reopen `feed_provider_trigger_down`).
#[tokio::test(flavor = "multi_thread")]
async fn disabling_ends_the_trigger_state_and_a_stopped_task_writes_nothing() {
    let (srv, q, _) = servers().await;
    let c = start(
        &srv,
        &q,
        json!({"alerts": {"thresholds": {"feed_provider_trigger_down": "0s"}}}),
    )
    .await;
    let key = "feed_provider_trigger_down:q";
    q.lock().unwrap().receive_fails = true;
    wait_until("trigger_down", || async {
        alert_state(&c, key).await.as_deref() == Some("open")
    })
    .await;
    edit_provider(&c, |p| p["enabled"] = json!(false)).await;
    wait_until("trigger_down resolved", || async {
        alert_state(&c, key).await.as_deref() == Some("resolved")
    })
    .await;
    wait_until("the task stopped", || async { !c.state.feeds.sqs_running("q") }).await;
    assert!(
        trigger_state(&c).await["receive_failing_since"].is_null(),
        "the receive streak ends with the task"
    );
    // Enabled again; a delete fails slowly and the provider is disabled while it is in flight.
    q.lock().unwrap().receive_fails = false;
    edit_provider(&c, |p| p["enabled"] = json!(true)).await;
    {
        let mut g = q.lock().unwrap();
        g.slow_delete = true;
        g.fail_always.insert("m1".into(), ("InternalError".into(), false));
        g.push("m1");
    }
    wait_until("the slow delete", || async {
        q.lock().unwrap().delete_failures >= 1
    })
    .await;
    edit_provider(&c, |p| p["enabled"] = json!(false)).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_ne!(
        alert_state(&c, key).await.as_deref(),
        Some("open"),
        "a stopped task reopened a disabled provider's alert"
    );
    assert!(trigger_state(&c).await["delete_failing_since"].is_null());
}

/// Q3 (feed-scheduling.md §5): a trigger edit during a check takes effect when the check ends:
/// the check stores no schedule of the trigger it started under (`sqs`, backstop 1 h); the
/// minutely `cron` with a 1-minute floor is due within minutes.
#[tokio::test(flavor = "multi_thread")]
async fn a_trigger_edit_during_a_check_takes_effect_when_it_ends() {
    let (srv, q, slow) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    slow.store(true, std::sync::atomic::Ordering::SeqCst);
    check_provider(&c, "q").await;
    wait_until("the check", || async { c.state.feeds.is_checking("q") }).await;
    edit_provider(
        &c,
        |p| p["trigger"] = json!({"kind": "cron", "cron": "* * * * *", "jitter": "0s", "min_interval": "1m"}),
    )
    .await;
    wait_until("the cron edit", || async {
        c.state
            .feeds
            .provider_def("q")
            .is_some_and(|d| matches!(d.trigger, picket_core::config::model::Trigger::Cron { .. }))
    })
    .await;
    assert!(c.state.feeds.is_checking("q"), "the edit landed during the check");
    slow.store(false, std::sync::atomic::Ordering::SeqCst);
    wait_until("the check to end", || async {
        !c.state.feeds.is_checking("q") && !c.state.feeds.is_busy("q")
    })
    .await;
    let due = c.state.feeds.next_due("q").unwrap();
    let now = Timestamp::now();
    assert!(
        due < now + jiff::SignedDuration::from_mins(3),
        "a minutely cron edited during a check is next due at {due} (now {now})"
    );
    let stored: Option<String> = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT next_check_at FROM feed_provider_state WHERE provider_id = 'q'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    let stored = stored.and_then(|s| picket_core::util::parse_ts(&s)).unwrap();
    assert!(
        stored < now + jiff::SignedDuration::from_mins(3),
        "the stored next check is the cron's: {stored}"
    );
}

/// Q8 (feed-scheduling.md: `min_interval` is a hard floor "whatever starts them"): the check an
/// edit of `config` makes is a first check; a busy feed it leaves out owes its provider an edit's
/// check, which waits for `min_interval` after that check, not a first check due at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_feed_left_out_of_an_edits_check_waits_for_min_interval() {
    use picket_core::scheduler::Priority;
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
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
    // the feed's re-ingest waits behind it: the feed is busy.
    let r = client()
        .get(common::feeds::url(&c, "/feeds/q"))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap();
    let mut f: Value = r.json().await.unwrap();
    f["modes"]["dns"] = json!({"mode": "aggregate"});
    let r = ui(&c, Method::PUT, "/feeds/q").json(&f).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    wait_until("the feed busy", || async { c.state.feeds.is_busy("q") }).await;
    let checks = || async {
        q_i64(
            &c,
            "SELECT count(*) FROM feed_provider_checks WHERE provider_id = 'q'",
        )
        .await
    };
    let before = checks().await;
    // A config edit: its check, due at once, is a first check; the feed is left out.
    edit_provider(&c, |p| {
        p["config"]["headers"] = json!({"user-agent": "picket-test"})
    })
    .await;
    wait_until("the edit's check", || async {
        checks().await > before && !c.state.feeds.is_checking("q")
    })
    .await;
    assert!(c.state.feeds.owed("q").is_some(), "the feed was left out");
    let edit_check = checks().await;
    gate.notify_one();
    wait_until("the feed's run stored", || async { !c.state.feeds.is_busy("q") }).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        checks().await,
        edit_check,
        "no check sooner than min_interval after the edit's check"
    );
    let due = c.state.feeds.next_due("q").unwrap();
    assert!(
        due > Timestamp::now() + jiff::SignedDuration::from_secs(30),
        "the owed check waits for min_interval (1 min): due {due}"
    );
}

/// Q3 (feed-scheduling.md §5): the feeds' asks a check stores follow its provider's current
/// trigger: a check that started under `dynamic` (its feed asking by the model) and ended after
/// an edit to a yearly `cron` leaves no model ask holding the provider, which waits for the cron.
#[tokio::test(flavor = "multi_thread")]
async fn a_trigger_edit_during_a_check_rederives_the_feeds_asks() {
    let (srv, q, slow) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    edit_provider(&c, |p| {
        p["trigger"] = json!({"kind": "dynamic", "min_interval": "1m"})
    })
    .await;
    wait_until("the dynamic edit", || async {
        c.state
            .feeds
            .provider_def("q")
            .is_some_and(|d| matches!(d.trigger, picket_core::config::model::Trigger::Dynamic { .. }))
    })
    .await;
    slow.store(true, std::sync::atomic::Ordering::SeqCst);
    check_provider(&c, "q").await;
    wait_until("the check", || async { c.state.feeds.is_checking("q") }).await;
    edit_provider(
        &c,
        |p| p["trigger"] = json!({"kind": "cron", "cron": "0 0 1 1 *", "jitter": "0s", "min_interval": "1m"}),
    )
    .await;
    wait_until("the cron edit", || async {
        c.state
            .feeds
            .provider_def("q")
            .is_some_and(|d| matches!(d.trigger, picket_core::config::model::Trigger::Cron { .. }))
    })
    .await;
    assert!(c.state.feeds.is_checking("q"), "the edit landed during the check");
    slow.store(false, std::sync::atomic::Ordering::SeqCst);
    wait_until("the check to end", || async {
        !c.state.feeds.is_checking("q") && !c.state.feeds.is_busy("q")
    })
    .await;
    wait_until("the asks re-derived", || async {
        c.state.feeds.ask("q").is_none()
    })
    .await;
    let due = c.state.feeds.next_due("q").unwrap();
    assert!(
        due > Timestamp::now() + jiff::SignedDuration::from_hours(24),
        "the yearly cron decides: due {due}"
    );
    let stored: Option<String> = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT next_ask_at FROM feed_state WHERE feed_id = 'q'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(stored, None, "no stored ask of the old trigger");
}

/// Z3 (feed-scheduling.md §7; README §2 Restarts): a poll task that ends by itself (the stored
/// trigger names another queue for a while, as when edits A→B→A are coalesced into one reload)
/// leaves no entry behind, so the next reload starts a new task and the queue is read again.
#[tokio::test(flavor = "multi_thread")]
async fn a_poll_task_that_ends_by_itself_is_started_again() {
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    wait_until("receives", || async { q.lock().unwrap().receives >= 2 }).await;
    let orig: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT trigger_json FROM feed_providers WHERE id = 'q'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(orig.contains(QUEUE), "{orig}");
    // The stored trigger names another queue (an edit committed, its reload not run yet): the
    // task sees it and ends.
    let changed = orig.replace("/lists", "/other");
    c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE feed_providers SET trigger_json = ?1 WHERE id = 'q'",
                [&changed],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    wait_until("the task to end by itself", || async {
        !c.state.feeds.sqs_running("q")
    })
    .await;
    // The first queue again, then an ordinary edit's reload: a new task reads the queue.
    let o2 = orig.clone();
    c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE feed_providers SET trigger_json = ?1 WHERE id = 'q'",
                [&o2],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    edit_provider(&c, |p| p["name"] = json!("Q renamed")).await;
    wait_until("a new task", || async { c.state.feeds.sqs_running("q") }).await;
    let r0 = q.lock().unwrap().receives;
    wait_until("receives again", || async { q.lock().unwrap().receives > r0 }).await;
    q.lock().unwrap().push("m9");
    wait_until("the message's nudge", || async { nudged(&c).await }).await;
}

/// The stored trigger, as `trigger_json`.
async fn stored_trigger(c: &Core) -> String {
    c.state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT trigger_json FROM feed_providers WHERE id = 'q'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap()
}

async fn set_stored_trigger(c: &Core, json: String) {
    c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE feed_providers SET trigger_json = ?1 WHERE id = 'q'",
                [&json],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
}

/// A pause that tells the test it was reached, then waits for the test's go (at most 60 s).
fn pause() -> (
    picket_core::feeds::sqs::Pause,
    tokio::task::JoinHandle<()>,
    std::sync::mpsc::SyncSender<()>,
) {
    let (at_tx, at_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (go_tx, go_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let reached = tokio::task::spawn_blocking(move || {
        at_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the pause reached")
    });
    let f = Box::new(move || {
        let _ = at_tx.send(());
        let _ = go_rx.recv_timeout(Duration::from_secs(60));
    });
    (f, reached, go_tx)
}

/// The edited queue polled within `within` (`false`: not polled by then).
async fn other_polled_within(q: &Arc<Mutex<Queue>>, within: Duration) -> bool {
    tokio::time::timeout(
        within,
        wait_until("the edited queue polled", || async {
            q.lock().unwrap().other_receives >= 1
        }),
    )
    .await
    .is_ok()
}

/// The edited queue is polled, and goes on being polled by a registered task.
async fn other_queue_keeps_its_poller(c: &Core, q: &Arc<Mutex<Queue>>) {
    wait_until("the edited queue polled", || async {
        q.lock().unwrap().other_receives >= 1
    })
    .await;
    let r0 = q.lock().unwrap().other_receives;
    wait_until("the edited queue still polled", || async {
        q.lock().unwrap().other_receives >= r0 + 3
    })
    .await;
    assert!(c.state.feeds.sqs_running("q"));
}

/// X4, R2 (feed-scheduling.md §7: one long-poll task per enabled `sqs` provider, following its
/// trigger): syncs of the task map don't overlap. A sync that has read the definitions before a
/// trigger edit (held here once it has read them) makes the edit's own sync wait until it is
/// done, so that one reads the edited definitions after it, and the older sync never puts back a
/// task for the old queue in place of the edited queue's (which would end at once, leaving no
/// poller). A sync reading the definitions outside the task map's lock would let the edit's sync
/// run first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_sync_never_replaces_a_newer_syncs_poller() {
    use picket_core::feeds::sqs::PausePoint;
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    wait_until("receives", || async { q.lock().unwrap().receives >= 2 }).await;
    let (f, reached, go) = pause();
    c.state.feeds.sqs_pause_once(PausePoint::SyncRead, f);
    let s = c.state.clone();
    let older = tokio::task::spawn_blocking(move || picket_core::feeds::sqs::sync(&s));
    reached.await.unwrap();
    edit_provider(&c, |p| p["trigger"]["queue_url"] = json!(OTHER)).await;
    assert!(
        !other_polled_within(&q, Duration::from_secs(3)).await,
        "the edit's sync waits for the older sync"
    );
    go.send(()).unwrap();
    older.await.unwrap();
    other_queue_keeps_its_poller(&c, &q).await;
}

/// X4 (feed-scheduling.md §7; Z3): a task that ended by itself because the stored trigger named
/// another queue, while the edit back to its own queue was reloaded before it removed its entry
/// (that reload's sync saw it still registered and kept it), starts its successor at once
/// (`restart_if_back`), so the queue is read again without another reload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_task_ending_after_its_trigger_came_back_starts_its_successor() {
    use picket_core::feeds::sqs::PausePoint;
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    wait_until("receives", || async { q.lock().unwrap().receives >= 2 }).await;
    let orig = stored_trigger(&c).await;
    assert!(orig.contains(QUEUE), "{orig}");
    let (f, reached, go) = pause();
    c.state.feeds.sqs_pause_once(PausePoint::TaskEnding, f);
    // An edit to another queue, committed and not reloaded yet: the task sees it and ends.
    set_stored_trigger(&c, orig.replace("/lists", "/other")).await;
    reached.await.unwrap();
    let r0 = q.lock().unwrap().receives;
    // The edit undone, and a reload while the ending task is still registered: its sync keeps
    // the entry. (The reload follows the edit asynchronously: wait for its sync to finish.)
    let (synced_tx, synced_rx) = std::sync::mpsc::sync_channel::<()>(1);
    c.state.feeds.sqs_pause_once(
        PausePoint::SyncDone,
        Box::new(move || {
            let _ = synced_tx.send(());
        }),
    );
    set_stored_trigger(&c, orig).await;
    edit_provider(&c, |p| p["name"] = json!("Q renamed")).await;
    tokio::task::spawn_blocking(move || {
        synced_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the reload's sync")
    })
    .await
    .unwrap();
    assert!(
        c.state.feeds.sqs_running("q"),
        "the ending task is still registered"
    );
    go.send(()).unwrap();
    wait_until("the queue read again", || async {
        q.lock().unwrap().receives > r0 + 1
    })
    .await;
    assert!(c.state.feeds.sqs_running("q"));
    q.lock().unwrap().push("m9");
    wait_until("the message's nudge", || async { nudged(&c).await }).await;
}

/// R1 (feed-scheduling.md §7: one long-poll task per enabled `sqs` provider; core.md §2 edits):
/// reloads don't overlap. A one-off reload (a request for a feed not loaded yet) that has begun
/// before a trigger edit, held here after its first read, makes the config watcher's reload of
/// the edit wait until it is done, so it never applies its older definitions after the edit's
/// (which would put back a task for the old queue that ends at once, leaving no poller, and keep
/// the old definitions until the next edit).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_reload_never_applies_its_definitions_after_a_newer_one() {
    let (srv, q, _) = servers().await;
    let c = start(&srv, &q, json!({})).await;
    wait_until("receives", || async { q.lock().unwrap().receives >= 2 }).await;
    let old = c.state.feeds.def_or_reload(&c.state, "missing-probe-feed");
    tokio::pin!(old);
    assert!(futures_util::poll!(old.as_mut()).is_pending());
    tokio::time::sleep(Duration::from_millis(500)).await;
    edit_provider(&c, |p| p["trigger"]["queue_url"] = json!(OTHER)).await;
    assert!(
        !other_polled_within(&q, Duration::from_secs(3)).await,
        "the edit's reload waits for the older reload"
    );
    assert!(old.await.is_none());
    other_queue_keeps_its_poller(&c, &q).await;
    let t = serde_json::to_value(c.state.feeds.provider_def("q").unwrap().trigger).unwrap();
    assert_eq!(t["queue_url"], OTHER, "the runtime holds the edited definitions");
}
