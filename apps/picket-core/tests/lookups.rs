//! Async lookups and verdict sets end to end on a real core (core.md §7, §9, §10, §12;
//! providers.md §4; bundles.md §4–§5; storage.md §3–§4; build-and-test.md §5 rows "Lookup
//! providers", "Verdict caches", "Lookup sharing", "Re-checks and retro-match" (re-checks), "Block
//! alerts" (providers), "Lookup self-tests"), with a scripted lookup module standing in for
//! `http_json` (the provider configs are real `http_json` configs, so validation is the real one).

use crate::common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use common::edge::FakeEdge;
use common::{Core, start_core};
use jiff::Timestamp;
use picket_bundle::verdict::{VerdictKind, VerdictRecord};
use picket_core::config::model::EntityKind;
use picket_core::config::{Actor, Op};
use picket_lookup::testkit::ScriptedModule;
use picket_lookup::{Answer, Expect, LookupError, Registry, SelfTest, Verdict};
use reqwest::Method;
use serde_json::{Value, json};

fn now_ts() -> String {
    picket_api::time::format_micros(&Timestamp::now())
}

fn ts_at(t: Timestamp) -> String {
    picket_api::time::format_micros(&t)
}

async fn wait_for<F, Fut>(what: &str, secs: u64, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    // Generous on purpose (returns as soon as the condition holds): CI's shared runner and a
    // loaded build machine have both missed the nominal deadlines.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs * 3);
    while tokio::time::Instant::now() < deadline {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(f().await, "timed out waiting for {what}");
}

async fn q<T: rusqlite::types::FromSql + Send + 'static>(c: &Core, sql: &str) -> T {
    let s = sql.to_string();
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&s, [], |r| r.get(0))?))
        .await
        .unwrap()
}

/// A core counter's total for a series with these labels.
fn counter(c: &Core, name: &str, labels: &[(&str, &str)]) -> f64 {
    c.state
        .metrics
        .counters
        .totals()
        .into_iter()
        .filter(|((n, l), _)| {
            n == name
                && labels
                    .iter()
                    .all(|(k, v)| l.get(*k).map(String::as_str) == Some(*v))
        })
        .map(|(_, v)| v)
        .sum()
}

fn http_json(extra: Value) -> Value {
    let mut v = json!({"id": "q9", "name": "Q9", "module": "http_json",
        "config": {"url": "https://lookup.example/{domain}", "verdict": {"pointer": "/risk", "block_if": ">= 7"}},
        "recheck": {"enabled": false}});
    if let (Value::Object(m), Value::Object(e)) = (&mut v, extra) {
        m.extend(e);
    }
    v
}

/// Answers Block for names starting with `bad` or `evil`, Clean otherwise.
fn by_name() -> Arc<ScriptedModule> {
    ScriptedModule::new("http_json", |_cfg, name, _n| {
        Box::pin(async move {
            let verdict = if name.starts_with("bad") || name.starts_with("evil") {
                Verdict::Block {
                    score: Some(9.0),
                    reason: "risk >= 7".into(),
                }
            } else {
                Verdict::Clean
            };
            Ok(Answer {
                verdict,
                detail: None,
            })
        })
    })
}

struct Setup {
    c: Core,
    edge: FakeEdge,
    module: Arc<ScriptedModule>,
    seq: std::sync::atomic::AtomicU64,
}

impl Setup {
    async fn new(provider: Value, profile: Value, module: Arc<ScriptedModule>) -> Setup {
        Self::with(vec![provider], profile, module).await
    }

    async fn with(providers: Vec<Value>, profile: Value, module: Arc<ScriptedModule>) -> Setup {
        let c = start_core(Some(json!({"web": {"tls": "off"}}))).await;
        // Expiry, age drops and verdict sets need a synchronised clock (README §2 Clocks).
        c.state.clock.pin(true);
        let mut r = Registry::builtin();
        r.insert(module.clone());
        c.state.lookups.set_registry(&c.state, r).await;
        let pid = providers[0]["id"].as_str().unwrap().to_string();
        for provider in providers {
            c.state
                .config
                .apply(
                    EntityKind::LookupProvider,
                    Op::Create(provider),
                    Actor::cli(),
                    None,
                )
                .await
                .unwrap();
        }
        c.state
            .config
            .apply(EntityKind::Profile, Op::Create(profile), Actor::cli(), None)
            .await
            .unwrap();
        wait_for("the lookups runtime to see the config", 10, || async {
            let m = c.state.lookups.model();
            m.lookup_providers.contains_key(&pid) && m.profiles.contains_key("kids")
        })
        .await;
        let edge = FakeEdge::registered(&c, "e1").await;
        // Registering the edge publishes another configuration generation. Drain that
        // reload before a test deliberately changes rows behind the runtime's snapshot.
        assert!(
            c.state.lookups.reloaded(&c.state, Duration::from_secs(10)).await,
            "the lookups runtime saw the edge registration"
        );
        Setup {
            c,
            edge,
            module,
            seq: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn generation(&self, p: &str) -> String {
        self.c.state.lookups.model().lookup_providers[p]
            .cache_generation
            .clone()
    }

    fn next(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    async fn post(&self, lines: Vec<Value>) {
        let r = self.edge.post_logs(&lines).await;
        assert_eq!(r.status(), 200, "{:?}", r.text().await);
    }

    fn query(&self, qname: &str) -> Value {
        common::edge::query("b1", self.next(), &now_ts(), qname, None)
    }

    fn late(&self, provider: &str, qname: &str, verdict: &str, obtained_at: &str) -> Value {
        json!({"t": "lookup", "ts": now_ts(), "boot": "b1", "seq": self.next(), "profile": "kids",
               "qname": qname, "provider": provider, "verdict": verdict, "reason": "blocked",
               "obtained_at": obtained_at, "gen": self.generation(provider), "ms": 171})
    }
}

/// Source (b): an allowed query in a profile with an `async` attachment queues a lookup; core
/// stores the result (source `core`); a later query for a name with a live entry is settled
/// at admission without a call; queries forwarded, let through by an allow bundle or of a type
/// outside `scope.qtypes` queue nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_attachments_queue_and_live_entries_settle() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    s.post(vec![s.query("bad.example.org"), s.query("good.example.org")])
        .await;
    wait_for("both verdicts stored by core", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE provider_id = 'q9' AND source = 'core'",
        )
        .await
            == 2
            && q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    assert_eq!(s.module.calls(), 2);
    assert_eq!(
        q::<String>(
            &s.c,
            "SELECT verdict FROM lookup_verdicts WHERE name = 'bad.example.org'"
        )
        .await,
        "block"
    );
    // A live entry settles the next one at admission.
    s.post(vec![s.query("good.example.org")]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(s.module.calls(), 2, "no call for a name with a live entry");
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await, 0);
    // Not at ladder step 3 or later, or a type the provider isn't called for: nothing queued.
    let mut fwd = s.query("printer.corp");
    fwd["reason"] = json!({"step": 0, "kind": "forward", "stage": "query"});
    let mut allowed = s.query("allowed.example");
    allowed["reason"] = json!({"step": 2, "bundle": "allow-common", "kind": "exact", "stage": "query"});
    let mut txt = s.query("text.example");
    txt["qtype"] = json!("TXT");
    s.post(vec![fwd, allowed, txt]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(s.module.calls(), 2);
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await, 0);
    // The Block was kept apart for alerts, with a counted verdict.
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_blocks").await, 1);
    assert_eq!(
        counter(
            &s.c,
            "lookup_verdicts",
            &[("provider", "q9"), ("result", "block")]
        ),
        1.0
    );
}

/// Source (a): a failed sync lookup is retried after `async_timeout_ms` + 5 s, so the edge's
/// late answer arrives first and settles it without a call; another retry with no late answer
/// calls. `retries` off queues nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_wait_for_late_answers() {
    let s = Setup::new(
        http_json(json!({"async_timeout_ms": 100})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    let g = s.generation("q9");
    let item = |verdict: &str| {
        json!([{"provider": "q9", "verdict": verdict, "cached": false, "gen": g, "ms": 150,
                "timed_out": true, "retry": true}])
    };
    let mut a = s.query("bad.late.example");
    a["lookups"] = item("timeout");
    let mut b = s.query("bad.nolate.example");
    b["lookups"] = item("error");
    s.post(vec![a, b]).await;
    assert_eq!(
        q::<String>(
            &s.c,
            "SELECT reason FROM lookup_queue WHERE name = 'bad.late.example'"
        )
        .await,
        "retry"
    );
    // The late answer for the first.
    s.post(vec![s.late("q9", "bad.late.example", "block", &now_ts())])
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(s.module.calls(), 0, "no attempt before async_timeout_ms + 5 s");
    wait_for("the retries to be done", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    assert_eq!(s.module.calls(), 1, "only the retry without a late answer called");
    assert_eq!(
        q::<String>(
            &s.c,
            "SELECT source FROM lookup_verdicts WHERE name = 'bad.late.example'"
        )
        .await,
        s.edge.id
    );
    assert_eq!(
        q::<String>(
            &s.c,
            "SELECT source FROM lookup_verdicts WHERE name = 'bad.nolate.example'"
        )
        .await,
        "core"
    );
    // retries off: nothing queued.
    let mut p = s.c.state.config.model().await.unwrap().lookup_providers["q9"].clone();
    p.settings.retries = false;
    s.c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Update("q9".into(), serde_json::to_value(&p).unwrap()),
            Actor::cli(),
            Some(false),
        )
        .await
        .unwrap();
    wait_for("retries off", 10, || async {
        !s.c.state.lookups.model().lookup_providers["q9"].settings.retries
    })
    .await;
    let mut c2 = s.query("bad.off.example");
    c2["lookups"] = item("rejected");
    s.post(vec![c2]).await;
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await, 0);
}

/// Re-checks (core.md §7): a due re-check calls although the name has a live entry (skipping the
/// cache) and its result replaces the entry; a later answer adds no deadline while one is
/// pending; a name in an allow bundle, in `lookup-exclude` (out of scope) or blocked since is
/// skipped; past `max_per_day` dropped; a provider only in `alert_lookup_providers` is never re-checked.
/// Counted in `rechecks{provider, result}` and `recheck_blocks`.
///
/// A deadline is met by any provider call made at or after it, so a re-check that runs late (a
/// stalled host holding the dispatcher past the next deadline) meets both of a name's deadlines
/// with one call. Every assertion here holds whether a name's two deadlines get one call or two;
/// [`a_call_between_two_deadlines_meets_only_the_first`] checks that each delay calls again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rechecks_run_skip_and_drop() {
    // Block for `turns…` names (whose sync lookup on the edge answered Clean), Clean otherwise.
    let module = ScriptedModule::new("http_json", |_cfg, name, _n| {
        let block = name.starts_with("turns");
        Box::pin(async move {
            Ok(Answer {
                verdict: if block {
                    Verdict::Block {
                        score: None,
                        reason: "now bad".into(),
                    }
                } else {
                    Verdict::Clean
                },
                detail: None,
            })
        })
    });
    // q2 is only in alert_lookup_providers: never re-checked.
    let s = Setup::with(
        vec![
            http_json(json!({"recheck": {"enabled": true, "after": ["1s", "2s"], "jitter": "0s", "max_per_day": 3}})),
            http_json(json!({"id": "q2", "name": "Q2", "recheck": {"enabled": true, "after": ["1s"], "jitter": "0s"}})),
        ],
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}],
               "alert_lookup_providers": ["q9", "q2"]}),
        module.clone(),
    )
    .await;
    let rechecks = |result: &str| counter(&s.c, "rechecks", &[("provider", "q9"), ("result", result)]);
    let at = |v: &Value| picket_api::time::parse(v.as_str().unwrap()).unwrap();
    common::bundles::save(&s.c, "manual-allow", "||allowed.example^\n").await;
    // Two answers of turns.example in one batch, each with the edge's sync answer (Clean: a live
    // entry); the second, a millisecond later, comes while the first's deadlines are pending.
    let g = s.generation("q9");
    let mut first = s.query("turns.example");
    let answered = at(&first["ts"]);
    let mut second = s.query("turns.example");
    second["ts"] = json!(ts_at(answered + jiff::SignedDuration::from_millis(1)));
    for r in [&mut first, &mut second] {
        let obtained = r["ts"].clone();
        r["lookups"] = json!([{"provider": "q9", "verdict": "clean", "cached": false,
            "obtained_at": obtained, "gen": g, "ms": 12, "timed_out": false, "retry": false}]);
    }
    s.post(vec![first, second]).await;
    // What is left of the row (a re-check may have met a deadline already) is the first answer's.
    let ctx: Option<String> = q(
        &s.c,
        "SELECT max(context_json) FROM lookup_queue WHERE name = 'turns.example'",
    )
    .await;
    if let Some(ctx) = ctx {
        let ctx: Value = serde_json::from_str(&ctx).unwrap();
        let firsts = [1, 2].map(|d| json!(ts_at(answered + jiff::SignedDuration::from_secs(d))));
        let pending = ctx["rechecks"].as_array().unwrap();
        assert!(
            !pending.is_empty() && pending.iter().all(|d| firsts.contains(d)),
            "the second answer adds none: {ctx}"
        );
        assert_eq!(ctx["answered_at"], json!(ts_at(answered)), "{ctx}");
    }
    assert_eq!(
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue WHERE provider_id = 'q2'").await,
        0,
        "alert_lookup_providers never adds a provider to a re-check"
    );
    // The first re-check calls despite the live entry and finds a Block, which replaces the
    // entry; a deadline left after it is skipped: the name has been blocked since.
    wait_for("the re-checks of turns.example", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_queue WHERE name = 'turns.example'",
        )
        .await
            == 0
    })
    .await;
    assert_eq!(rechecks("run"), 1.0, "one re-check call");
    assert!(rechecks("skipped") <= 1.0);
    assert_eq!(counter(&s.c, "recheck_blocks", &[("provider", "q9")]), 1.0);
    assert_eq!(
        module.calls(),
        1,
        "the sync answer came from the edge; one re-check call"
    );
    assert_eq!(
        q::<String>(
            &s.c,
            "SELECT verdict FROM lookup_verdicts WHERE name = 'turns.example'"
        )
        .await,
        "block",
        "a re-check's result replaces the entry"
    );
    // Skips: an allow bundle, lookup-exclude (out of scope), blocked since (the provider's late
    // Block, in the same batch, after the answer). Each name's deadlines are skipped one by one,
    // or both at once.
    let before = rechecks("skipped");
    s.post(vec![
        s.query("allowed.example"),
        s.query("printer.lan"),
        s.query("gone.example"),
        s.late("q9", "gone.example", "block", &now_ts()),
    ])
    .await;
    wait_for("the skips", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    let skips = rechecks("skipped") - before;
    assert!((3.0..=6.0).contains(&skips), "{skips} skips");
    assert_eq!(rechecks("run"), 1.0);
    assert_eq!(module.calls(), 1, "skipped re-checks make no call");
    // max_per_day 3, one used: a Clean name's re-checks run (its last deadline met by a call at or
    // after it) ...
    let answer = s.query("other.example");
    let last = at(&answer["ts"]) + jiff::SignedDuration::from_secs(2);
    s.post(vec![answer]).await;
    wait_for("the re-checks of other.example", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_queue WHERE name = 'other.example'",
        )
        .await
            == 0
    })
    .await;
    let obtained: String = q(
        &s.c,
        "SELECT obtained_at FROM lookup_verdicts WHERE name = 'other.example'",
    )
    .await;
    assert!(at(&json!(obtained)) >= last, "{obtained} before {last}");
    if rechecks("run") < 3.0 {
        // ... one late call met both: another name's first re-check uses the last of the day.
        s.post(vec![s.query("more.example")]).await;
        wait_for("the re-checks of more.example", 20, || async {
            q::<i64>(
                &s.c,
                "SELECT count(*) FROM lookup_queue WHERE name = 'more.example'",
            )
            .await
                == 0
        })
        .await;
    }
    assert_eq!(rechecks("run"), 3.0);
    // ... and the next name's are dropped.
    s.post(vec![s.query("third.example")]).await;
    wait_for("max_per_day", 20, || async {
        rechecks("dropped") >= 1.0 && q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    assert_eq!(rechecks("run"), 3.0);
    assert_eq!(module.calls(), 3);
}

/// Re-checks (core.md §7): a deadline is met only by a provider call made at or after it, so a
/// call between a name's two deadlines meets the first only; the row keeps the second, from the
/// same answer, and it calls again once due. The `after` delays are an hour apart and core's
/// lookup clock is moved on to the second, so no stall merges the two calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_between_two_deadlines_meets_only_the_first() {
    let s = Setup::new(
        http_json(json!({"recheck": {"enabled": true, "after": ["1s", "1h"], "jitter": "0s"}})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    let run = || counter(&s.c, "rechecks", &[("provider", "q9"), ("result", "run")]);
    let answer = s.query("twice.example");
    let answered = picket_api::time::parse(answer["ts"].as_str().unwrap()).unwrap();
    s.post(vec![answer]).await;
    let second = json!([ts_at(answered + jiff::SignedDuration::from_hours(1))]);
    wait_for("the first deadline met", 20, || async {
        q::<Option<String>>(
            &s.c,
            "SELECT max(context_json) FROM lookup_queue WHERE name = 'twice.example'",
        )
        .await
        .is_some_and(|c| serde_json::from_str::<Value>(&c).unwrap()["rechecks"] == second)
    })
    .await;
    let ctx: Value = serde_json::from_str(
        &q::<String>(
            &s.c,
            "SELECT context_json FROM lookup_queue WHERE name = 'twice.example'",
        )
        .await,
    )
    .unwrap();
    assert_eq!(ctx["answered_at"], json!(ts_at(answered)), "{ctx}");
    assert_eq!(run(), 1.0);
    assert_eq!(s.module.calls(), 1);
    // An hour on, the second deadline calls again.
    s.c.state
        .lookups
        .simulate_clock_offset(jiff::SignedDuration::from_hours(1));
    wait_for("the second re-check", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    assert_eq!(run(), 2.0, "each delay calls again");
    assert_eq!(s.module.calls(), 2);
}

/// `category_answered` from provider Blocks (core.md §7, §9): Block before the answer and after
/// it, a TTL-0 Block, a profile whose `alert_lookup_providers` is `[]`, a cache hit of a known Block
/// checked once, and a name without a registrable domain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn category_answered_fires_in_either_order() {
    let s = Setup::new(
        http_json(json!({"cache": {"block_ttl_s": 0}})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    s.c.state
        .config
        .apply(
            EntityKind::Profile,
            Op::Create(json!({"id": "quiet", "name": "Quiet", "alert_lookup_providers": []})),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    // Block first (TTL 0: no live verdict, but the Block is kept), then the answer.
    s.post(vec![s.late("q9", "evil.example.com", "block", &now_ts())])
        .await;
    wait_for("the Block checked", 10, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await
            == 1
    })
    .await;
    assert_eq!(
        q::<Option<String>>(&s.c, "SELECT verdict FROM lookup_verdicts").await,
        None
    );
    s.post(vec![s.query("evil.example.com")]).await;
    let key = "category_answered:provider:q9:example.com";
    let count_of = |k: &str| {
        let k = k.to_string();
        let st = s.c.state.clone();
        async move {
            st.alerts
                .get_by_key(&k)
                .await
                .unwrap()
                .map(|a| a.count)
                .unwrap_or(0)
        }
    };
    wait_for("the alert from the answer", 10, || async {
        count_of(key).await == 1
    })
    .await;
    let a = s.c.state.alerts.get_by_key(key).await.unwrap().unwrap();
    // C3 (core.md §9 record `edge?`): the edge whose answer raised it.
    assert_eq!(a.edge.as_deref(), Some(s.edge.id.as_str()));
    assert_eq!(a.details["provider"], "q9");
    assert_eq!(a.details["reason"], "blocked");
    assert_eq!(a.details["add_to_manual_block"]["line"], "||example.com^");
    // Answer first, then the Block (from core's own lookup this time: an async attachment).
    let mut ans = s.query("bad.other.org");
    ans["profile"] = json!("kids");
    s.post(vec![ans]).await;
    s.post(vec![s.late("q9", "bad.other.org", "block", &now_ts())])
        .await;
    wait_for("the alert from the Block", 10, || async {
        count_of("category_answered:provider:q9:other.org").await == 1
    })
    .await;
    // Raised by the Block's scan: the edge of the answer it found.
    let a =
        s.c.state
            .alerts
            .get_by_key("category_answered:provider:q9:other.org")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(a.edge.as_deref(), Some(s.edge.id.as_str()));
    // Evidence: each alert's answer is copied by the shared capture (off the ingest path).
    wait_for("the evidence copies", 10, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM alert_evidence").await >= 2
    })
    .await;
    // The same Block again (an edge's cache hit, same obtained_at): not checked again.
    let at = q::<String>(
        &s.c,
        "SELECT obtained_at FROM lookup_blocks WHERE name = 'bad.other.org'",
    )
    .await;
    let mut hit = s.query("bad.other.org");
    hit["decision"] = json!("block");
    hit["lookups"] = json!([{"provider": "q9", "verdict": "block", "reason": "blocked", "cached": true,
                             "obtained_at": at, "gen": s.generation("q9"), "ms": 0, "timed_out": false, "retry": false}]);
    s.post(vec![hit]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count_of("category_answered:provider:q9:other.org").await, 1);
    // A profile that alerts on no provider raises nothing.
    s.post(vec![s.late("q9", "bad.quiet.net", "block", &now_ts())])
        .await;
    let mut quiet = s.query("bad.quiet.net");
    quiet["profile"] = json!("quiet");
    s.post(vec![quiet]).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(count_of("category_answered:provider:q9:quiet.net").await, 0);
    // A name with no registrable domain keys on the full name.
    s.post(vec![s.late("q9", "bad-host", "block", &now_ts())]).await;
    s.post(vec![s.query("bad-host")]).await;
    wait_for("the full-name key", 10, || async {
        count_of("category_answered:provider:q9:bad-host").await == 1
    })
    .await;
}

/// Loads a published verdict-set head with picket-bundle's reader from core's blob store.
fn load_set(c: &Core, head: &str) -> (picket_bundle::verdict::VerdictSet, picket_bundle::page::MemPages) {
    let read = |id: &str| std::fs::read(picket_core::blobs::path(c.dir.path(), id).unwrap()).unwrap();
    let head_bytes = read(head);
    let h = picket_bundle::verdict::VerdictHead::from_bytes(&head_bytes).unwrap();
    let pages = picket_bundle::page::MemPages {
        files: [(h.base.clone(), read(&h.base))].into_iter().collect(),
    };
    let deltas = |id: &str| Some(read(id));
    let set = picket_bundle::verdict::load_verdict_set(&head_bytes, &deltas, &pages).unwrap();
    (set, pages)
}

/// What core's live rows say each name's record is.
async fn expected(c: &Core, provider: &str) -> BTreeMap<String, Option<(String, i64)>> {
    let p = provider.to_string();
    c.state
        .db
        .read(move |db| {
            let mut st =
                db.prepare("SELECT name, verdict, obtained_at FROM lookup_verdicts WHERE provider_id = ?1")?;
            let v = st
                .query_map([&p], |r| {
                    let at: String = r.get(2)?;
                    let us = picket_api::time::parse(&at).unwrap().as_microsecond();
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?.map(|v| (v, us)),
                    ))
                })?
                .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap()
}

fn kind_text(k: VerdictKind) -> &'static str {
    match k {
        VerdictKind::Block => "block",
        VerdictKind::Clean => "clean",
        VerdictKind::Unknown => "unknown",
    }
}

fn assert_same(
    set: &picket_bundle::verdict::VerdictSet,
    pages: &picket_bundle::page::MemPages,
    want: &BTreeMap<String, Option<(String, i64)>>,
) {
    for (name, w) in want {
        let got: Option<VerdictRecord> = set.lookup(name, pages).unwrap();
        let got = got.map(|r| (kind_text(r.verdict).to_string(), r.obtained_at.as_microsecond()));
        assert_eq!(&got, w, "{name}");
    }
    assert_eq!(set.lookup("never.example", pages).unwrap(), None);
}

/// Verdict sets (core.md §7; bundles.md §4–§5): core writes a base and deltas that picket-bundle's
/// reader (the edge's) reads back with identical lookups; the edge's config object names the
/// head; the head and blobs are served on the edge port; a Block publishes a delta at once; a
/// tombstone deletes the name; a flush starts a new generation with a new base and the old head
/// is no longer named.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_sets_round_trip_through_the_edge_reader() {
    let s = Setup::new(
        http_json(json!({"cache": {"clean_ttl_s": 86400}})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    // The first base (empty) comes on its own: the provider is attached `sync`.
    wait_for("the first base", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM verdict_set_state WHERE provider_id = 'q9'",
        )
        .await
            == 1
    })
    .await;
    let first: String = q(&s.c, "SELECT head_id FROM verdict_set_state").await;
    // Verdicts from the log: Blocks and Cleans.
    let mut lines = Vec::new();
    for i in 0..40 {
        let v = if i % 4 == 0 { "block" } else { "clean" };
        let name = format!("{}{i}.example.org", if v == "block" { "bad" } else { "ok" });
        lines.push(s.late("q9", &name, v, &now_ts()));
    }
    s.post(lines).await;
    // A Block publishes a delta at once.
    wait_for("a delta", 20, || async {
        q::<i64>(&s.c, "SELECT seq FROM verdict_set_state").await >= 1
            && q::<i64>(&s.c, "SELECT published_seq FROM verdict_set_state").await
                >= q::<i64>(&s.c, "SELECT max(changed_seq) FROM lookup_verdicts").await
    })
    .await;
    let head: String = q(&s.c, "SELECT head_id FROM verdict_set_state").await;
    assert_ne!(head, first);
    let (set, pages) = load_set(&s.c, &head);
    assert_same(&set, &pages, &expected(&s.c, "q9").await);
    // A later Clean with TTL 0 leaves a tombstone: the delta deletes the name.
    let mut p = s.c.state.config.model().await.unwrap().lookup_providers["q9"].clone();
    p.settings.cache.unknown_ttl_s = 0;
    s.c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Update("q9".into(), serde_json::to_value(&p).unwrap()),
            Actor::cli(),
            Some(false),
        )
        .await
        .unwrap();
    wait_for("the TTL edit", 10, || async {
        s.c.state.lookups.model().lookup_providers["q9"]
            .settings
            .cache
            .unknown_ttl_s
            == 0
    })
    .await;
    s.post(vec![s.late("q9", "bad0.example.org", "unknown", &now_ts())])
        .await;
    s.post(vec![s.late("q9", "bad100.example.org", "block", &now_ts())])
        .await;
    wait_for("the second delta", 20, || async {
        q::<i64>(&s.c, "SELECT seq FROM verdict_set_state").await >= 2
            && q::<i64>(&s.c, "SELECT published_seq FROM verdict_set_state").await
                >= q::<i64>(&s.c, "SELECT max(changed_seq) FROM lookup_verdicts").await
    })
    .await;
    let head2: String = q(&s.c, "SELECT head_id FROM verdict_set_state").await;
    let (set2, pages2) = load_set(&s.c, &head2);
    let want = expected(&s.c, "q9").await;
    assert_eq!(want["bad0.example.org"], None, "a tombstone");
    assert_same(&set2, &pages2, &want);
    // The edge's config names the head; the head and its blobs are served to edges.
    wait_for("the config naming the head", 10, || async {
        let (_, _, cfg) = s.edge.config(None).await;
        cfg["verdict_sets"]["q9"] == json!(head2)
    })
    .await;
    let r = s
        .edge
        .get(&format!("/objects/verdict-sets/q9/heads/{head2}.json"))
        .await;
    assert_eq!(r.status(), 200);
    let h = picket_bundle::verdict::VerdictHead::from_bytes(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(h.deltas.len(), 2);
    for d in &h.deltas {
        assert_eq!(
            s.edge.get(&format!("/objects/blobs/{}", d.blake3)).await.status(),
            200
        );
    }
    // A flush: a new generation, a new base, the old head no longer named.
    let r = common::bundles::ui(&s.c, Method::POST, "/lookup-providers/q9/flush")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    let g = body["cache_generation"].as_str().unwrap().to_string();
    assert_eq!(
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_verdicts").await,
        0,
        "verdicts and tombstones go"
    );
    wait_for("a new base for the new generation", 20, || async {
        q::<String>(&s.c, "SELECT generation FROM verdict_set_state").await == g
    })
    .await;
    let head3: String = q(&s.c, "SELECT head_id FROM verdict_set_state").await;
    let (set3, pages3) = load_set(&s.c, &head3);
    assert_eq!(set3.lookup("bad4.example.org", &pages3).unwrap(), None);
    assert_eq!(*set3.generation, *g);
    wait_for("the config naming the new head", 10, || async {
        let (_, _, cfg) = s.edge.config(None).await;
        cfg["verdict_sets"]["q9"] == json!(head3)
            && cfg["lookup_providers"]["q9"]["cache_generation"] == json!(g)
    })
    .await;
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM verdict_sets WHERE superseded_at IS NOT NULL"
        )
        .await,
        3
    );
}

/// Verdict-set retention (storage.md §4): versions out of use past the window go with their
/// blobs; the current head, pinned heads and their blobs stay; tombstones and expired verdicts go
/// after the log window, live ones stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retention_collects_old_versions_and_tombstones() {
    use picket_core::retention::RetentionHook as _;
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    wait_for("the first base", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM verdict_set_state").await == 1
    })
    .await;
    s.post(vec![s.late("q9", "bad.a.example", "block", &now_ts())])
        .await;
    wait_for("a delta", 20, || async {
        q::<i64>(&s.c, "SELECT seq FROM verdict_set_state").await == 1
    })
    .await;
    let current: String = q(&s.c, "SELECT head_id FROM verdict_set_state").await;
    let edge_id = s.edge.id.clone();
    wait_for("the served config naming the current head", 10, || async {
        s.c.state
            .edges
            .publisher
            .current(&edge_id)
            .is_some_and(|p| p.config.verdict_sets.get("q9") == Some(&current))
    })
    .await;
    // Age every version and blob past the window.
    let old = ts_at(Timestamp::now() - jiff::SignedDuration::from_hours(24 * 10));
    let o2 = old.clone();
    s.c.state
        .db
        .write(move |db| {
            db.execute("UPDATE verdict_sets SET published_at = ?1, superseded_at = ?1, last_used_at = NULL", [&o2])?;
            db.execute("UPDATE blobs SET created_at = ?1 WHERE kind = 'verdict_set'", [&o2])?;
            // A tombstone and an expired Clean from 10 days ago, and a live Block.
            db.execute(
                "INSERT INTO lookup_verdicts(provider_id, name, verdict, obtained_at, generation, source)
                 SELECT 'q9', 'tomb.example', NULL, ?1, cache_generation, 'core' FROM lookup_providers WHERE id = 'q9'",
                [&o2],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let blobs_before: i64 = q(&s.c, "SELECT count(*) FROM blobs WHERE kind = 'verdict_set'").await;
    let hook = picket_core::lookups::verdict_sets::SetRetention;
    while hook.step(&s.c.state).await.unwrap() == picket_core::scheduler::Step::More {}
    let left: Vec<String> =
        s.c.state
            .db
            .read(|db| {
                let mut st = db.prepare("SELECT head_id FROM verdict_sets")?;
                let v = st
                    .query_map([], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
            .unwrap();
    assert_eq!(left, vec![current.clone()], "only the current head stays");
    let blobs_after: i64 = q(&s.c, "SELECT count(*) FROM blobs WHERE kind = 'verdict_set'").await;
    assert!(blobs_after < blobs_before, "{blobs_before} → {blobs_after}");
    // The current head's blobs are all still there.
    let (set, pages) = load_set(&s.c, &current);
    assert_eq!(
        set.lookup("bad.a.example", &pages).unwrap().unwrap().verdict,
        VerdictKind::Block
    );
    // Verdict retention: the tombstone goes, the live Block stays.
    let vr = picket_core::lookups::VerdictRetention;
    while vr.step(&s.c.state).await.unwrap() == picket_core::scheduler::Step::More {}
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE name = 'tomb.example'"
        )
        .await,
        0
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE name = 'bad.a.example'"
        )
        .await,
        1
    );
}

/// Self-tests (providers.md §4; build-and-test.md §5 "Lookup self-tests"): a wrong verdict is
/// tested again; a second wrong verdict raises `lookup_self_test_failed` with the answer's detail
/// and the flush action; an error isn't a failed test; the next pass resolves it. Test now runs
/// through the API; the last result is kept on the provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_tests_raise_on_two_wrong_verdicts_and_resolve() {
    let mode = Arc::new(AtomicU8::new(0));
    let m2 = mode.clone();
    let module = ScriptedModule::with_self_test(
        "http_json",
        SelfTest {
            name: "malware.testcategory.example".into(),
            expect: Expect::Block,
            cron: "0 0 1 1 *".into(),
        },
        move |_cfg, _name, _n| {
            let m = m2.load(Ordering::SeqCst);
            Box::pin(async move {
                match m {
                    0 => Ok(Answer {
                        verdict: Verdict::Clean,
                        detail: Some(json!({"rule": "none"})),
                    }),
                    1 => Err(LookupError::Failed(anyhow::anyhow!("connection reset"))),
                    _ => Ok(Answer {
                        verdict: Verdict::Block {
                            score: None,
                            reason: "malware".into(),
                        },
                        detail: None,
                    }),
                }
            })
        },
    );
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        module,
    )
    .await;
    let test = || async {
        let r = common::bundles::ui(&s.c, Method::POST, "/lookup-providers/q9/test")
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        r.json::<Value>().await.unwrap()
    };
    let key = "lookup_self_test_failed:q9";
    let open = || async {
        s.c.state
            .alerts
            .get_by_key(key)
            .await
            .unwrap()
            .is_some_and(|a| a.state == picket_core::alerts::AlertState::Open)
    };
    // The save-time run may come first; start from a known state with two manual runs.
    let v = test().await;
    assert_eq!(v["result"], "wrong");
    let v = test().await;
    assert_eq!(v["result"], "wrong");
    assert_eq!(v["state"], "failing");
    assert!(open().await, "two wrong verdicts raise the alert");
    let a = s.c.state.alerts.get_by_key(key).await.unwrap().unwrap();
    assert_eq!(a.details["detail"]["rule"], "none");
    assert_eq!(a.details["flush"]["action"], "lookup-providers/q9/flush");
    // An error isn't a pass or a failure.
    mode.store(1, Ordering::SeqCst);
    let v = test().await;
    assert_eq!(v["result"], "inconclusive");
    assert!(open().await);
    // A pass resolves it.
    mode.store(2, Ordering::SeqCst);
    let v = test().await;
    assert_eq!(v["result"], "pass");
    assert!(!open().await);
    let st: Value = common::bundles::get(&s.c, "/lookup-providers/q9/status").await.1;
    assert_eq!(st["last_self_test"]["result"], "pass");
    assert_eq!(st["self_test"]["name"], "malware.testcategory.example");
    // A self-test's result is never cached or stored as a verdict.
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_verdicts").await, 0);
}

/// The UI endpoints (api.md §7, core.md §12): modules with schemas and presets, a preset's
/// built config (nothing changes), status, temporary allows with their revoke state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ui_endpoints() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    let (st, mods) = common::bundles::get(&s.c, "/lookup-modules").await;
    assert_eq!(st, 200);
    let dns = mods
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "dns")
        .unwrap();
    let presets: Vec<&str> = dns["presets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert!(
        presets.contains(&"quad9") && presets.contains(&"nextdns"),
        "{presets:?}"
    );
    assert!(dns["config_schema"].is_object());
    let changes_before: i64 = q(&s.c, "SELECT count(*) FROM config_changes").await;
    let r = common::bundles::ui(&s.c, Method::POST, "/lookup-modules/dns/presets/quad9")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let built: Value = r.json().await.unwrap();
    assert!(built["config"].is_object(), "{built}");
    assert_eq!(
        q::<i64>(&s.c, "SELECT count(*) FROM config_changes").await,
        changes_before,
        "changes nothing"
    );
    let r = common::bundles::ui(&s.c, Method::POST, "/lookup-modules/dns/presets/nope")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    // Status.
    s.post(vec![s.query("bad.status.example")]).await;
    // L16: the call count moves before the item's row goes; wait for both.
    wait_for("the lookup to settle", 20, || async {
        s.module.calls() == 1 && q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    let (st, v) = common::bundles::get(&s.c, "/lookup-providers/q9/status").await;
    assert_eq!(st, 200);
    assert_eq!(v["breaker"], "closed");
    assert_eq!(v["calls"], 1);
    assert_eq!(v["queue"], 0);
    assert_eq!(
        common::bundles::get(&s.c, "/lookup-providers/nope/status")
            .await
            .0,
        404
    );
    // Temporary allows from the edge's log, with a revoke pending.
    s.post(vec![json!({"t": "allow", "ts": now_ts(), "boot": "b1", "seq": s.next(), "action": "created",
        "allow_id": "a-1", "client": "192.168.1.140", "device": "emma-tablet", "kind": "dns",
        "target": "ads.example.com", "expires_at": ts_at(Timestamp::now() + jiff::SignedDuration::from_hours(1)), "via": "extension"})])
        .await;
    let r = common::bundles::ui(
        &s.c,
        Method::POST,
        &format!("/edges/{}/allows/a-1/revoke", s.edge.id),
    )
    .json(&json!({}))
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), 200);
    let (st, v) = common::bundles::get(&s.c, "/temp-allows").await;
    assert_eq!(st, 200);
    let a = &v["items"][0];
    assert_eq!(a["allow_id"], "a-1");
    assert_eq!(a["state"], "active");
    assert_eq!(a["revoke_pending"], true);
    assert_eq!(a["target"], "ads.example.com");
    let (_, v) = common::bundles::get(&s.c, "/temp-allows?state=recent").await;
    assert!(v["items"].as_array().unwrap().is_empty());
}

/// Restarts (README §2 Restarts): a queue item persisted by an earlier run is worked after the
/// start, and a Block whose answer check an earlier run claimed but didn't finish is checked
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persisted_work_resumes_after_a_restart() {
    let (dir, _init, _w, _e) = common::init_dir();
    common::set_settings(dir.path(), json!({"web": {"tls": "off"}}));
    let due = Timestamp::now() + jiff::SignedDuration::from_secs(3);
    {
        // What a core that stopped left behind.
        let opts = picket_core::db::DbOptions::core(dir.path());
        let mut db = picket_core::db::open_connection(&opts, 1024).unwrap();
        let tx = db.transaction().unwrap();
        picket_core::config::store::apply(
            &tx,
            EntityKind::LookupProvider,
            Op::Create(http_json(json!({}))),
            &Actor::cli(),
            None,
        )
        .unwrap();
        picket_core::config::store::apply(
            &tx,
            EntityKind::Profile,
            Op::Create(
                json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
            ),
            &Actor::cli(),
            None,
        )
        .unwrap();
        let ctx = json!({"need": {"kind": "async", "due_at": ts_at(due)}, "profiles": ["kids"]});
        tx.execute(
            "INSERT INTO lookup_queue(provider_id, name, reason, first_seen, attempts, next_at, context_json, class)
             VALUES ('q9', 'bad.queued.example', 'async', ?1, 0, ?2, ?3, 1)",
            rusqlite::params![now_ts(), ts_at(due), ctx.to_string()],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO lookup_blocks(provider_id, name, obtained_at, source, answers_checked, generation)
             SELECT 'q9', 'evil.claimed.example', ?1, 'core', 1, cache_generation FROM lookup_providers WHERE id = 'q9'",
            [now_ts()],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let stop = tokio_util::sync::CancellationToken::new();
    let opts = picket_core::run::StartOptions {
        release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
        any_port: true,
        clock_synced: Some(true),
        disk_watch: false,
        ..Default::default()
    };
    let mut tries = 0;
    let (state, _info) = loop {
        match picket_core::run::start_with(dir.path(), stop.clone(), opts.clone()).await {
            Err(e) if e.code == picket_core::error::EXIT_IN_USE && tries < 100 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            r => break r.unwrap(),
        }
    };
    let module = by_name();
    let mut r = Registry::builtin();
    r.insert(module.clone());
    state.lookups.set_registry(&state, r).await;
    let one = |sql: &'static str| {
        let st = state.clone();
        async move {
            st.db
                .read(move |db| Ok::<_, anyhow::Error>(db.query_row(sql, [], |r| r.get::<_, i64>(0))?))
                .await
                .unwrap()
        }
    };
    wait_for("the persisted lookup worked", 20, || async {
        one("SELECT count(*) FROM lookup_verdicts WHERE name = 'bad.queued.example' AND source = 'core'")
            .await
            == 1
    })
    .await;
    assert_eq!(module.calls(), 1);
    wait_for("the claimed Block checked again", 20, || async {
        one("SELECT answers_checked FROM lookup_blocks WHERE name = 'evil.claimed.example'").await == 2
    })
    .await;
    stop.cancel();
}

/// Two lookup providers from one module (build-and-test.md §5 "Lookup providers", "Verdict
/// caches"): each has its own client, queue items, verdicts, generation and verdict set; a flush
/// or a save with **Clear cached verdicts on save** ticked moves only its own generation on (its
/// verdicts go, its set starts from a new base), unticked keeps them; the other's stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_providers_from_one_module_keep_their_own_caches() {
    let s = Setup::with(
        vec![
            http_json(json!({})),
            http_json(json!({"id": "am", "name": "AM",
                "config": {"url": "https://other.example/v1/{domain}", "verdict": {"pointer": "/score", "block_if": ">= 9"}}})),
        ],
        json!({"id": "kids", "name": "Kids", "lookup_providers": [
            {"provider": "q9", "mode": "async"}, {"provider": "am", "mode": "async"}]}),
        by_name(),
    )
    .await;
    s.post(vec![s.query("bad.both.example")]).await;
    wait_for("both providers' verdicts", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE name = 'bad.both.example'",
        )
        .await
            == 2
    })
    .await;
    assert_eq!(s.module.calls(), 2, "one call per provider");
    assert_ne!(s.generation("q9"), s.generation("am"));
    // Unticked: the save keeps the verdicts and the generation.
    let g_am = s.generation("am");
    let mut p = s.c.state.config.model().await.unwrap().lookup_providers["am"].clone();
    p.config["verdict"]["block_if"] = json!(">= 8");
    s.c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Update("am".into(), serde_json::to_value(&p).unwrap()),
            Actor::cli(),
            Some(false),
        )
        .await
        .unwrap();
    assert_eq!(
        s.c.state.config.model().await.unwrap().lookup_providers["am"].cache_generation,
        g_am
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE provider_id = 'am'"
        )
        .await,
        1
    );
    // Ticked: a new generation; only am's verdicts go.
    p.config["verdict"]["block_if"] = json!(">= 7");
    s.c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Update("am".into(), serde_json::to_value(&p).unwrap()),
            Actor::cli(),
            Some(true),
        )
        .await
        .unwrap();
    assert_ne!(
        s.c.state.config.model().await.unwrap().lookup_providers["am"].cache_generation,
        g_am
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE provider_id = 'am'"
        )
        .await,
        0
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE provider_id = 'q9'"
        )
        .await,
        1
    );
    // A flush of q9 leaves am alone.
    s.post(vec![s.query("bad.again.example")]).await;
    wait_for("am's new verdict", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE provider_id = 'am'",
        )
        .await
            == 1
    })
    .await;
    let r = common::bundles::ui(&s.c, Method::POST, "/lookup-providers/q9/flush")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE provider_id = 'q9'"
        )
        .await,
        0
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE provider_id = 'am'"
        )
        .await,
        1
    );
    // An unknown provider: 404.
    let r = common::bundles::ui(&s.c, Method::POST, "/lookup-providers/nope/flush")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

/// `category_answered` from the other Block sources (core.md §7): an edge's sync lookup (a
/// `lookups[]` item) before the answer, and core's own async lookup after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn category_answered_from_sync_and_async_blocks() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    let count_of = |k: &'static str| {
        let st = s.c.state.clone();
        async move {
            st.alerts
                .get_by_key(k)
                .await
                .unwrap()
                .map(|a| a.count)
                .unwrap_or(0)
        }
    };
    // An edge's sync lookup blocked the name for one client …
    let mut blocked = s.query("bad.sync.example");
    blocked["decision"] = json!("block");
    blocked["reason"] = json!({"step": 4, "kind": "lookup", "stage": "query", "provider": "q9"});
    blocked["lookups"] = json!([{"provider": "q9", "verdict": "block", "reason": "risk >= 7", "cached": false,
        "obtained_at": now_ts(), "gen": s.generation("q9"), "ms": 40, "timed_out": false, "retry": false}]);
    s.post(vec![blocked]).await;
    wait_for("the sync Block checked", 10, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE name = 'bad.sync.example' AND answers_checked = 2",
        )
        .await
            == 1
    })
    .await;
    // … and another got an answer later.
    let mut answered = s.query("bad.sync.example");
    answered["client"] = json!("192.168.1.141");
    s.post(vec![answered]).await;
    wait_for("the alert", 10, || async {
        count_of("category_answered:provider:q9:sync.example").await == 1
    })
    .await;
    // Core's async lookup finds the Block after the answer.
    s.post(vec![s.query("bad.async.example")]).await;
    wait_for("the alert from core's own lookup", 20, || async {
        count_of("category_answered:provider:q9:async.example").await == 1
    })
    .await;
    let a =
        s.c.state
            .alerts
            .get_by_key("category_answered:provider:q9:async.example")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(a.details["block_source"], "core");
}

// ---- Review round 1 of wave 5B: a test per finding (L1–L16) ----

/// What a recording module was asked: (the provider's URL, name), in call order.
type CallLog = Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// Like [`by_name`], recording which provider (by its config's URL) was asked for which name.
fn recording() -> (Arc<ScriptedModule>, CallLog) {
    let log: CallLog = Arc::default();
    let l2 = log.clone();
    let m = ScriptedModule::new("http_json", move |cfg, name, _n| {
        l2.lock()
            .unwrap()
            .push((cfg["url"].as_str().unwrap_or_default().to_string(), name.clone()));
        Box::pin(async move {
            let verdict = if name.starts_with("bad") || name.starts_with("evil") {
                Verdict::Block {
                    score: Some(9.0),
                    reason: "risk >= 7".into(),
                }
            } else {
                Verdict::Clean
            };
            Ok(Answer {
                verdict,
                detail: None,
            })
        })
    });
    (m, log)
}

/// An `http_json` provider `id` whose config URL names it.
fn named_provider(id: &str, extra: Value) -> Value {
    let mut v = http_json(json!({"id": id, "name": id.to_uppercase(),
        "config": {"url": format!("https://{id}.example/{{domain}}"), "verdict": {"pointer": "/risk", "block_if": ">= 7"}}}));
    if let (Value::Object(m), Value::Object(e)) = (&mut v, extra) {
        m.extend(e);
    }
    v
}

/// L2 — core.md §7 Sources (b) ("within the attachment's and the provider's scope"); providers.md
/// §4 Scope; edge.md §10 Scope: an async attachment calls only for names in scope. The provider's
/// default `lookup-exclude` keeps `printer.lan` out; an attachment's `include_bundles` keeps every
/// other name out and its `exclude_bundles` applies like the provider's; a profile that no longer
/// attaches the provider asks for no call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_attachments_call_only_within_their_scope() {
    let (module, log) = recording();
    let s = Setup::with(
        vec![
            http_json(json!({})),
            named_provider("q2", json!({"scope": {"exclude_bundles": []}})),
            named_provider("q3", json!({"scope": {"exclude_bundles": []}})),
        ],
        json!({"id": "kids", "name": "Kids", "lookup_providers": [
            {"provider": "q9", "mode": "async"},
            {"provider": "q2", "mode": "async", "include_bundles": ["lookup-exclude"]},
            {"provider": "q3", "mode": "async", "exclude_bundles": ["lookup-exclude"]}]}),
        module,
    )
    .await;
    // `lookup-exclude` with its rules applied (its preloaded `||lan^` plus one more).
    common::bundles::save(
        &s.c,
        "lookup-exclude",
        "||local^\n||lan^\n||arpa^\n||home.arpa^\n||excluded.example^\n",
    )
    .await;
    s.post(vec![s.query("printer.lan"), s.query("www.example.org")])
        .await;
    wait_for("the queue to settle", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    let mut calls = log.lock().unwrap().clone();
    calls.sort();
    let pair = |u: &str, n: &str| (u.to_string(), n.to_string());
    assert_eq!(
        calls,
        vec![
            pair("https://lookup.example/{domain}", "www.example.org"),
            pair("https://q2.example/{domain}", "printer.lan"),
            pair("https://q3.example/{domain}", "www.example.org"),
        ]
    );
    // The profile no longer attaches q3: a queued item for it makes no call.
    s.c.state
        .config
        .apply(
            EntityKind::Profile,
            Op::Update(
                "kids".into(),
                json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
            ),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    wait_for("the runtime to see the change", 10, || async {
        s.c.state.lookups.model().profiles["kids"]
            .edge
            .lookup_providers
            .len()
            == 1
    })
    .await;
    let ctx = json!({"need": {"kind": "async", "due_at": now_ts()}, "profiles": ["kids"]});
    let c2 = ctx.to_string();
    s.c.state
        .db
        .write(move |db| {
            db.execute(
                "INSERT INTO lookup_queue(provider_id, name, reason, first_seen, attempts, next_at, context_json, class)
                 VALUES ('q3', 'detached.example.org', 'async', ?1, 0, ?1, ?2, 1)",
                rusqlite::params![now_ts(), c2],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    wait_for("the detached item to go", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    assert_eq!(log.lock().unwrap().len(), 3, "no call for a detached provider");
}

/// L1 — core.md §7 Verdict sets; storage.md §4: a verdict set's change numbers never go back.
/// Retention sweeping the rows with the newest numbers (an expired verdict from a spool replay,
/// kept as a tombstone) leaves the next write a number past everything published, so a new
/// Block still reaches the set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_set_change_numbers_survive_retention() {
    use picket_core::retention::RetentionHook as _;
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    wait_for("the first base", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM verdict_set_state").await == 1
    })
    .await;
    s.post(vec![s.late("q9", "bad.a.example", "block", &now_ts())])
        .await;
    wait_for("a delta", 20, || async {
        q::<i64>(&s.c, "SELECT seq FROM verdict_set_state").await == 1
    })
    .await;
    // A spooled Clean from 4 days ago: already expired, a tombstone with the newest number.
    let old = ts_at(Timestamp::now() - jiff::SignedDuration::from_hours(24 * 4));
    s.post(vec![s.late("q9", "ok.old.example", "clean", &old)]).await;
    picket_core::lookups::verdict_sets::publish_delta(&s.c.state, "q9")
        .await
        .unwrap();
    let published: i64 = q(&s.c, "SELECT published_seq FROM verdict_set_state").await;
    let vr = picket_core::lookups::VerdictRetention;
    while vr.step(&s.c.state).await.unwrap() == picket_core::scheduler::Step::More {}
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE name = 'ok.old.example'"
        )
        .await,
        0,
        "the tombstone is swept"
    );
    s.post(vec![s.late("q9", "bad.b.example", "block", &now_ts())])
        .await;
    let seq_b: i64 = q(
        &s.c,
        "SELECT changed_seq FROM lookup_verdicts WHERE name = 'bad.b.example'",
    )
    .await;
    assert!(
        seq_b > published,
        "a new row's number ({seq_b}) passes the published one ({published})"
    );
    picket_core::lookups::verdict_sets::publish_delta(&s.c.state, "q9")
        .await
        .unwrap();
    wait_for("the new Block in the set", 20, || async {
        let head: String = q(&s.c, "SELECT head_id FROM verdict_set_state").await;
        let (set, pages) = load_set(&s.c, &head);
        set.lookup("bad.b.example", &pages).unwrap().is_some()
    })
    .await;
}

/// L3 — core.md §7 category_answered ("checked when either arrives"); README §2 Bounded: answers
/// in one batch are grouped by name, so many answers for one known-bad name don't hide another's;
/// the alert says how many answers the batch held, and (U9, core.md §9) its count goes up by
/// that many occurrences.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_busy_name_hides_no_other_answer() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    s.post(vec![
        s.late("q9", "bad.one.test", "block", &now_ts()),
        s.late("q9", "evil.two.test", "block", &now_ts()),
    ])
    .await;
    wait_for("both Blocks checked", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await
            == 2
    })
    .await;
    let mut lines: Vec<Value> = (0..70).map(|_| s.query("bad.one.test")).collect();
    lines.push(s.query("evil.two.test"));
    s.post(lines).await;
    let alerts =
        s.c.state
            .db
            .read(|db| {
                let mut st = db.prepare(
                    "SELECT details_json FROM alerts WHERE kind = 'category_answered' ORDER BY dedupe_key",
                )?;
                let v = st
                    .query_map([], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
            .unwrap();
    let details: Vec<Value> = alerts.iter().map(|d| serde_json::from_str(d).unwrap()).collect();
    let by_name = |n: &str| details.iter().find(|d| d["name"] == n).cloned();
    assert_eq!(
        by_name("bad.one.test").map(|d| d["answers"].clone()),
        Some(json!(70)),
        "{details:?}"
    );
    assert!(by_name("evil.two.test").is_some(), "{details:?}");
    let count = |key: &'static str| {
        let st = s.c.state.clone();
        async move {
            st.alerts
                .get_by_key(key)
                .await
                .unwrap()
                .map(|a| a.count)
                .unwrap_or(0)
        }
    };
    assert_eq!(
        count("category_answered:provider:q9:one.test").await,
        70,
        "one occurrence per answer"
    );
    assert_eq!(count("category_answered:provider:q9:two.test").await, 1);
}

/// L4a — providers.md §4 Cache generation; core.md §7: a verdict of the old generation logged
/// after a flush committed is dropped, whatever the lookups runtime's snapshot still says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flush_drops_verdicts_of_the_old_generation_at_once() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    // Hold every reader, so the runtime's reload after the flush can't run yet.
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let (entered, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut joins = Vec::new();
    for _ in 0..4 {
        let st = s.c.state.clone();
        let g = gate.clone();
        let tx = entered.clone();
        joins.push(tokio::spawn(async move {
            st.db
                .read(move |_| {
                    tx.send(()).unwrap();
                    let (l, c) = &*g;
                    let mut open = l.lock().unwrap();
                    while !*open {
                        open = c.wait(open).unwrap();
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await
                .unwrap();
        }));
    }
    for _ in 0..4 {
        rx.recv().await.unwrap();
    }
    let rec: picket_api::logs::LookupRecord =
        serde_json::from_value(s.late("q9", "old.example.org", "clean", &now_ts())).unwrap();
    let generation = picket_core::lookups::flush(&s.c.state, "q9", Actor::cli())
        .await
        .unwrap();
    assert_ne!(generation, s.generation("q9"), "the runtime hasn't reloaded yet");
    let applied = picket_core::lookups::ingest::apply(&s.c.state, "e1", vec![], vec![rec])
        .await
        .unwrap();
    {
        let (l, c) = &*gate;
        *l.lock().unwrap() = true;
        c.notify_all();
    }
    for j in joins {
        j.await.unwrap();
    }
    assert_eq!(
        applied.verdicts, 0,
        "an old-generation verdict was stored after the flush"
    );
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_verdicts").await, 0);
}

/// L4b — core.md §7, providers.md §4: a flush discards the old generation's Blocks too, so an
/// answer that arrives after it raises no `category_answered`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn category_answered_ignores_blocks_from_before_a_flush() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    s.post(vec![s.late("q9", "bad.flushed.example", "block", &now_ts())])
        .await;
    wait_for("the Block checked", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await
            == 1
    })
    .await;
    let generation = picket_core::lookups::flush(&s.c.state, "q9", Actor::cli())
        .await
        .unwrap();
    wait_for("the runtime to see the flush", 10, || async {
        s.generation("q9") == generation
    })
    .await;
    s.post(vec![s.query("bad.flushed.example")]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM alerts WHERE kind = 'category_answered'"
        )
        .await,
        0,
        "a Block of the flushed generation alerted"
    );
}

/// L4c — providers.md §4 ("a verdict carries the generation current when its call started, and
/// isn't stored if that side emptied the provider's cache after the call started"); core.md §7
/// Queue: a call that spans a flush stores nothing, and its item isn't settled by the dropped
/// result: the next attempt calls under the new generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_spanning_a_flush_is_dropped_and_made_again() {
    let module = ScriptedModule::new("http_json", |_cfg, _name, n| {
        Box::pin(async move {
            if n == 0 {
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            Ok(Answer {
                verdict: Verdict::Clean,
                detail: None,
            })
        })
    });
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        module.clone(),
    )
    .await;
    let old = s.generation("q9");
    s.post(vec![s.query("spanning.example.org")]).await;
    wait_for("the first call", 10, || async { module.calls() == 1 }).await;
    let generation = picket_core::lookups::flush(&s.c.state, "q9", Actor::cli())
        .await
        .unwrap();
    let g2 = generation.clone();
    wait_for("a verdict of the new generation", 30, || {
        let g = g2.clone();
        let st = s.c.state.clone();
        async move {
            st.db
                .read(move |db| {
                    Ok::<_, anyhow::Error>(db.query_row(
                        "SELECT count(*) FROM lookup_verdicts WHERE generation = ?1",
                        [&g],
                        |r| r.get::<_, i64>(0),
                    )?)
                })
                .await
                .unwrap()
                == 1
        }
    })
    .await;
    assert_eq!(module.calls(), 2);
    let o2 = old.clone();
    let stale: i64 =
        s.c.state
            .db
            .read(move |db| {
                Ok::<_, anyhow::Error>(db.query_row(
                    "SELECT count(*) FROM lookup_verdicts WHERE generation = ?1",
                    [&o2],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
    assert_eq!(stale, 0, "nothing of the flushed generation is stored");
}

/// L5 — README §2 Restarts; core.md §7: when the lookup step fails after the batch's records are
/// in their partitions, the edge's resend (all duplicates now) still adds the re-check deadlines
/// and checks the answers against Blocks; a later resend adds nothing twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_effects_survive_a_failure_after_the_partitions_commit() {
    let s = Setup::new(
        http_json(json!({"recheck": {"enabled": true, "after": ["1h"], "jitter": "0s"}})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    s.post(vec![s.late("q9", "bad.resent.example", "block", &now_ts())])
        .await;
    wait_for("the Block checked", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await
            == 1
    })
    .await;
    // Inject a failure into the lookup step's transaction (its queue writes).
    s.c.state
        .db
        .write(|db| {
            db.execute_batch(
                "CREATE TRIGGER fail_lookup_step BEFORE INSERT ON lookup_queue
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let batch = vec![s.query("bad.resent.example"), s.query("fine.resent.example")];
    let r = s.edge.post_logs_once(&batch).await;
    assert_eq!(r.status(), 503, "the lookup step failed");
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await, 0);
    s.c.state
        .db
        .write(|db| {
            db.execute_batch("DROP TRIGGER fail_lookup_step")?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let count = || async {
        s.c.state
            .alerts
            .get_by_key("category_answered:provider:q9:resent.example")
            .await
            .unwrap()
            .map(|a| a.count)
            .unwrap_or(0)
    };
    // The resend: every record is a duplicate in its partition.
    s.post(batch.clone()).await;
    assert_eq!(
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await,
        2,
        "both answers' re-check deadlines"
    );
    assert_eq!(count().await, 1, "the answer checked against the Block");
    // Another resend changes nothing.
    s.post(batch).await;
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await, 2);
    assert_eq!(count().await, 1, "checked once");
}

/// L6 — core.md §7 Re-checks ("re-checks over max_per_day are dropped and counted"): the day's
/// allowance is reserved before the call, so concurrent re-checks can't pass it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_per_day_holds_for_concurrent_rechecks() {
    let module = ScriptedModule::new("http_json", |_, _, _| {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(Answer {
                verdict: Verdict::Clean,
                detail: None,
            })
        })
    });
    let s = Setup::new(
        http_json(json!({"recheck": {"enabled": true, "after": ["1s"], "jitter": "0s", "max_per_day": 1}})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        module.clone(),
    )
    .await;
    let old = ts_at(Timestamp::now() - jiff::SignedDuration::from_secs(3));
    let mut a = s.query("one.example.org");
    let mut b = s.query("two.example.org");
    a["ts"] = json!(old);
    b["ts"] = json!(old);
    s.post(vec![a, b]).await;
    wait_for("both due items to settle", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    assert_eq!(module.calls(), 1, "max_per_day 1");
    assert_eq!(
        counter(&s.c, "rechecks", &[("provider", "q9"), ("result", "dropped")]),
        1.0
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count FROM lookup_recheck_days WHERE provider_id = 'q9'"
        )
        .await,
        1
    );
}

/// L8 — README §2 Clocks: with the clock not yet synchronised, an item due long ago is neither
/// dropped as too old nor called (U1: core's calls stamp core's clock), no verdict set is
/// published, and a verdict that looks expired, or a Block that looks older than the window, is
/// kept rather than discarded. Once the clock is synchronised the item is judged by it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookups_wait_for_a_synchronised_clock_before_discarding() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    s.c.state.clock.pin(false);
    s.c.state
        .db
        .write(|db| {
            db.execute("DELETE FROM verdict_set_state", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let due = ts_at(Timestamp::now() - jiff::SignedDuration::from_hours(24 * 4));
    // A retry of a sync lookup, due 4 days ago by this clock.
    let ctx = json!({"need": {"kind": "retry", "due_at": due}, "profiles": ["kids"]});
    let (d2, c2) = (due.clone(), ctx.to_string());
    s.c.state
        .db
        .write(move |db| {
            db.execute(
                "INSERT INTO lookup_queue(provider_id, name, reason, first_seen, attempts, next_at, context_json, class)
                 VALUES ('q9', 'long.ago.example', 'retry', ?1, 0, ?1, ?2, 0)",
                rusqlite::params![d2, c2],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(s.module.calls(), 0, "no call on an unsynchronised clock");
    assert_eq!(
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await,
        1,
        "kept"
    );
    assert_eq!(
        counter(
            &s.c,
            "lookup_dropped",
            &[("provider", "q9"), ("reason", "too_old")]
        ),
        0.0
    );
    // A Block obtained 4 days ago by this clock: kept for alerts, and kept as a verdict.
    s.post(vec![s.late("q9", "bad.old.example", "block", &due)]).await;
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE name = 'bad.old.example'"
        )
        .await,
        1
    );
    assert_eq!(
        q::<Option<String>>(
            &s.c,
            "SELECT verdict FROM lookup_verdicts WHERE name = 'bad.old.example'"
        )
        .await,
        Some("block".into())
    );
    // No verdict set while unsynchronised; one as soon as the clock is.
    picket_core::lookups::verdict_sets::plan(&s.c.state)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM verdict_set_state").await, 0);
    s.c.state.clock.pin(true);
    picket_core::lookups::verdict_sets::plan(&s.c.state)
        .await
        .unwrap();
    wait_for("the base", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM verdict_set_state").await == 1
    })
    .await;
    // Synchronised, the clock says the retry is 4 days old: dropped and counted, never called.
    wait_for("the old item judged", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    assert_eq!(s.module.calls(), 0);
    assert_eq!(
        counter(
            &s.c,
            "lookup_dropped",
            &[("provider", "q9"), ("reason", "too_old")]
        ),
        1.0
    );
}

/// L9 — README §2 "Settings reach their user"; core.md §11: a new `resolver` reaches the
/// existing lookup clients' connection options.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_resolver_reaches_existing_lookup_clients() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    assert!(s.c.state.lookups.http_options().resolver.is_none());
    let r = common::bundles::ui(&s.c, Method::PUT, "/settings")
        .json(&json!({"resolver": {"protocol": "dot", "ip": "192.0.2.53", "tls_host": "dns.example"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{:?}", r.text().await);
    wait_for("the new resolver in the lookup clients' options", 10, || async {
        s.c.state
            .lookups
            .http_options()
            .resolver
            .as_ref()
            .is_some_and(|u| u.ip.to_string() == "192.0.2.53")
    })
    .await;
}

/// L11 — api.md §7 paging: a state filter fills each page and keeps a cursor while matching rows
/// remain, however many rows of another state come first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn temp_allows_pages_with_a_state_filter() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    let now = Timestamp::now();
    let allow = |id: String, created: Timestamp, expires: Timestamp, seq: u64| {
        json!({"t": "allow", "ts": ts_at(created), "boot": "b1", "seq": seq, "action": "created",
            "allow_id": id, "client": "192.168.1.140", "kind": "dns", "target": "x.example.org",
            "expires_at": ts_at(expires), "via": "extension"})
    };
    let mut rows = vec![allow(
        "old-active".into(),
        now - jiff::SignedDuration::from_mins(20),
        now + jiff::SignedDuration::from_hours(1),
        s.next(),
    )];
    for i in 0..9 {
        rows.push(allow(
            format!("expired-{i}"),
            now - jiff::SignedDuration::from_mins(10) + jiff::SignedDuration::from_secs(i),
            now - jiff::SignedDuration::from_mins(5),
            s.next(),
        ));
    }
    s.post(rows).await;
    let (st, body) = common::bundles::get(&s.c, "/temp-allows?state=active&limit=1").await;
    assert_eq!(st, 200);
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["items"][0]["allow_id"], "old-active");
    // Every ended one, two per page.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let path = match &cursor {
            Some(c) => format!("/temp-allows?state=recent&limit=2&cursor={c}"),
            None => "/temp-allows?state=recent&limit=2".into(),
        };
        let (st, body) = common::bundles::get(&s.c, &path).await;
        assert_eq!(st, 200);
        for i in body["items"].as_array().unwrap() {
            seen.push(i["allow_id"].as_str().unwrap().to_string());
        }
        cursor = body["next_cursor"].as_str().map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen.len(), 9, "{seen:?}");
}

/// L12 — core.md §12 status: a timed-out call is one error, never two (the client's `errors`
/// already counts calls that ran out of `async_timeout_ms`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_counts_a_timeout_once() {
    let module = ScriptedModule::new("http_json", |_, _, _| {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(Answer {
                verdict: Verdict::Clean,
                detail: None,
            })
        })
    });
    let s = Setup::new(
        http_json(json!({"async_timeout_ms": 5, "async_max_attempts": 1})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        module,
    )
    .await;
    s.post(vec![s.query("timeout.example.org")]).await;
    wait_for("the failed call to settle", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    let (_, body) = common::bundles::get(&s.c, "/lookup-providers/q9/status").await;
    assert_eq!(body["error_rate"].as_f64(), Some(1.0), "{body}");
}

/// One heartbeat reporting provider q9's `paused` and `rejected` totals.
async fn lookup_beat(ws: &mut common::edge::Ws, paused: u64, rejected: u64, up: u64) {
    let mut hb = common::edge::heartbeat("b1", Timestamp::now(), up, 0);
    hb["metrics"]["lookups"] = json!({"q9": {"paused": paused, "rejected": rejected}});
    common::edge::send(ws, json!({"type": "heartbeat", "data": hb})).await;
}

/// L13 — core.md §9 `lookup_provider_down` ("paused by rejections, for 15 min"): an edge
/// reporting the provider paused counts while its pause is fresh; a sample between two pauses
/// (the edge's pause no longer fresh, but the provider down less than `UP_GRACE` ago) doesn't
/// restart the 15 minutes; one after `UP_GRACE` without a pause does (U6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_down_counts_edge_pauses_and_keeps_its_timer_across_gaps() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        by_name(),
    )
    .await;
    let (mut ws, _) = s.edge.session(common::edge::hello("b1")).await;
    let edge_id = s.edge.id.clone();
    let seen = |n: u64| {
        let st = s.c.state.clone();
        let e = edge_id.clone();
        async move {
            st.edges
                .hub
                .live(&e)
                .heartbeat
                .as_ref()
                .and_then(|h| h.metrics.lookups.get("q9").map(|m| m.paused))
                == Some(n)
        }
    };
    lookup_beat(&mut ws, 0, 0, 1000).await;
    wait_for("the first heartbeat", 10, || seen(0)).await;
    picket_core::lookups::sample_once(&s.c.state).await.unwrap();
    assert!(s.c.state.lookups.runtime("q9").down_since.is_none());
    // The edge answered lookups as paused since its last heartbeat.
    lookup_beat(&mut ws, 7, 1, 31_000).await;
    wait_for("the paused heartbeat", 10, || seen(7)).await;
    picket_core::lookups::sample_once(&s.c.state).await.unwrap();
    let since = s.c.state.lookups.runtime("q9").down_since;
    assert!(since.is_some(), "an edge's pause counts");
    let paused_at = tokio::time::Instant::now();
    // A heartbeat whose totals didn't move.
    lookup_beat(&mut ws, 7, 1, 61_000).await;
    wait_for("the quiet heartbeat", 10, || async {
        s.c.state
            .edges
            .hub
            .live(&edge_id)
            .heartbeat
            .as_ref()
            .is_some_and(|h| h.up_ms == 61_000)
    })
    .await;
    // Sampled past EDGE_PAUSE_FRESH (the edge no longer counts as paused) but within UP_GRACE of
    // the last sample that found the provider down: the timer goes on.
    let gap = picket_core::lookups::EDGE_PAUSE_FRESH + Duration::from_secs(5);
    assert!(gap < picket_core::lookups::UP_GRACE);
    picket_core::lookups::sample_at(&s.c.state, paused_at + gap)
        .await
        .unwrap();
    let rt = s.c.state.lookups.runtime("q9");
    assert_eq!(rt.down_since, since, "a gap between pauses keeps the timer");
    // Up for UP_GRACE: the 15 minutes start again at the next pause.
    picket_core::lookups::sample_at(
        &s.c.state,
        paused_at + gap + picket_core::lookups::UP_GRACE + Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(
        s.c.state.lookups.runtime("q9").down_since.is_none(),
        "up for UP_GRACE ends the timer"
    );
}

/// L14 — providers.md §4 Self-tests ("when the provider is saved"): a save that changes only
/// settings runs the self-test too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settings_only_save_runs_the_self_test() {
    let module = ScriptedModule::with_self_test(
        "http_json",
        SelfTest {
            name: "malware.testcategory.example".into(),
            expect: Expect::Block,
            cron: "0 0 1 1 *".into(),
        },
        |_cfg, _name, _n| {
            Box::pin(async move {
                Ok(Answer {
                    verdict: Verdict::Block {
                        score: None,
                        reason: "malware".into(),
                    },
                    detail: None,
                })
            })
        },
    );
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        module.clone(),
    )
    .await;
    wait_for("the save-time self-test", 20, || async { module.calls() >= 1 }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = module.calls();
    let mut p = http_json(json!({"async_timeout_ms": 9000}));
    p["id"] = json!("q9");
    s.c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Update("q9".into(), p),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    wait_for("the self-test after the settings save", 20, || async {
        module.calls() > before
    })
    .await;
}

/// L15 — core.md §10, §12; api.md §7: core's own call durations are kept as a histogram per
/// provider, charted by percentile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn core_call_durations_are_charted() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    s.post(vec![s.query("timed.example.org")]).await;
    wait_for("the call", 20, || async {
        s.module.calls() == 1 && q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    picket_core::lookups::sample_once(&s.c.state).await.unwrap();
    let (st, body) = common::bundles::get(&s.c, "/metrics?series=lookup_call_ms.p50&window=1h").await;
    assert_eq!(st, 200, "{body}");
    let line = body["series"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["labels"]["provider"] == "q9")
        .cloned()
        .unwrap_or_else(|| panic!("no q9 line: {body}"));
    assert!(
        line["points"].as_array().unwrap().iter().any(|p| !p[1].is_null()),
        "{line}"
    );
}

/// The count of the alert with this dedupe key (0 when there is none).
async fn alert_count(c: &Core, key: &str) -> i64 {
    c.state
        .alerts
        .get_by_key(key)
        .await
        .unwrap()
        .map(|a| a.count)
        .unwrap_or(0)
}

/// U1 — README §2 Clocks; core.md §7: core makes no call before its wall clock is synchronised
/// (its calls stamp `obtained_at` with it). With a boot clock four days ahead an async lookup
/// waits, due from its record's time; once NTP corrects the clock the call stamps the right time,
/// so an edge's accurately dated later Block replaces its Clean at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_boot_clock_ahead_leaves_no_verdict_after_the_correction() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    // Core runs four days ahead, not yet synchronised.
    s.c.state.clock.pin(false);
    s.c.state
        .lookups
        .simulate_clock_offset(jiff::SignedDuration::from_hours(24 * 4));
    // The edge's record carries the edge's time, an hour behind core's clock here.
    let edge_ts = Timestamp::now() - jiff::SignedDuration::from_hours(1);
    let mut a = s.query("clock.example.org");
    a["ts"] = json!(ts_at(edge_ts));
    s.post(vec![a]).await;
    assert_eq!(
        q::<String>(
            &s.c,
            "SELECT next_at FROM lookup_queue WHERE name = 'clock.example.org'"
        )
        .await,
        ts_at(edge_ts),
        "due from its record's time"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(s.module.calls(), 0, "no call on an unsynchronised clock");
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_verdicts").await, 0);
    // NTP corrects the clock.
    s.c.state
        .lookups
        .simulate_clock_offset(jiff::SignedDuration::ZERO);
    s.c.state.clock.pin(true);
    wait_for("core's verdict", 20, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_verdicts WHERE source = 'core'").await == 1
    })
    .await;
    assert_eq!(s.module.calls(), 1);
    let at = q::<String>(
        &s.c,
        "SELECT obtained_at FROM lookup_verdicts WHERE name = 'clock.example.org'",
    )
    .await;
    assert!(at <= now_ts(), "stamped by the corrected clock: {at}");
    // An edge's Block obtained after it wins (later obtained_at).
    s.post(vec![s.late("q9", "clock.example.org", "block", &now_ts())])
        .await;
    assert_eq!(
        q::<Option<String>>(
            &s.c,
            "SELECT verdict FROM lookup_verdicts WHERE name = 'clock.example.org'"
        )
        .await,
        Some("block".into())
    );
}

/// U2 — core.md §9 Evidence; README §2 Restarts: a provider's `category_answered` raised by an
/// arriving answer gets its evidence rule, with its backfill, in the transaction that raises it
/// and marks the record applied, so a stop right after the commit (no worker runs) still leaves
/// the rule; a resend then adds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answer_alerts_store_their_evidence_rule_with_the_alert() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    s.post(vec![s.late("q9", "bad.evidence.example", "block", &now_ts())])
        .await;
    wait_for("the Block checked", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await
            == 1
    })
    .await;
    // No worker runs from here on.
    s.c.stop.cancel();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let query: picket_api::logs::QueryRecord =
        serde_json::from_value(s.query("bad.evidence.example")).unwrap();
    let info = picket_core::lookups::ingest::QueryInfo::of(&query, false);
    picket_core::lookups::ingest::apply(&s.c.state, &s.edge.id, vec![info.clone()], vec![])
        .await
        .unwrap();
    let key = "category_answered:provider:q9:evidence.example";
    assert_eq!(alert_count(&s.c, key).await, 1);
    let rules = "SELECT count(*) FROM alert_evidence_rules r JOIN alerts a ON a.id = r.alert_id
                 WHERE a.kind = 'category_answered'";
    assert_eq!(q::<i64>(&s.c, rules).await, 1, "the rule came with the alert");
    picket_core::lookups::ingest::apply(&s.c.state, &s.edge.id, vec![info], vec![])
        .await
        .unwrap();
    assert_eq!(alert_count(&s.c, key).await, 1, "a resend adds nothing");
    assert_eq!(q::<i64>(&s.c, rules).await, 1);
}

/// Inserts a Block row as core's store would (provider q9).
async fn insert_block(c: &Core, name: &str, generation: &str) {
    let (n, g) = (name.to_string(), generation.to_string());
    c.state
        .db
        .write(move |db| {
            db.execute(
                "INSERT INTO lookup_blocks(provider_id, name, obtained_at, source, generation)
                 VALUES ('q9', ?1, ?2, 'core', ?3)",
                rusqlite::params![n, now_ts(), g],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
}

/// U3 — providers.md §4 Cache generation; core.md §7: a flush while a Block's scan of the
/// partitions runs deletes the Block, so the scan's commit raises nothing and marks no other
/// Block (Block ids are never reused); an undisturbed scan raises its alert with its evidence
/// rule (U2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flush_during_a_block_scan_raises_nothing() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    s.post(vec![s.query("bad.scan.example"), s.query("bad.calm.example")])
        .await;
    // No background worker from here on: the test runs the Block checker's passes.
    s.c.stop.cancel();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Older partitions held exclusively stall the scan (each up to its busy timeout) after it
    // found the answer in the current hour and before its commit.
    let store = picket_core::logs::LogStore::new(&s.c.state.data_dir);
    let mut held = Vec::new();
    for h in 1..=5 {
        let hour = picket_core::logs::partition::hour_start(
            &(Timestamp::now() - jiff::SignedDuration::from_hours(h)),
        );
        let part = store.open(&hour, true).unwrap().unwrap();
        part.conn
            .execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE")
            .unwrap();
        held.push(part);
    }
    insert_block(&s.c, "bad.scan.example", &s.generation("q9")).await;
    let st = s.c.state.clone();
    let job = tokio::spawn(async move { picket_core::lookups::answered::pass(&st).await.unwrap() });
    wait_for("the Block claimed", 10, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 1",
        )
        .await
            == 1
    })
    .await;
    let next = picket_core::lookups::flush(&s.c.state, "q9", Actor::cli())
        .await
        .unwrap();
    assert_eq!(q::<i64>(&s.c, "SELECT count(*) FROM lookup_blocks").await, 0);
    insert_block(&s.c, "bad.new.example", &next).await;
    for p in &held {
        p.conn.execute_batch("ROLLBACK").unwrap();
    }
    drop(held);
    job.await.unwrap();
    let alerts = "SELECT count(*) FROM alerts WHERE kind = 'category_answered'";
    assert_eq!(
        q::<i64>(&s.c, alerts).await,
        0,
        "the flushed Block raised nothing"
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT answers_checked FROM lookup_blocks WHERE name = 'bad.new.example'"
        )
        .await,
        0,
        "the new Block is still unchecked"
    );
    // Undisturbed: the new generation's Block for an answered name alerts, with its rule.
    insert_block(&s.c, "bad.calm.example", &next).await;
    picket_core::lookups::answered::pass(&s.c.state).await.unwrap();
    assert_eq!(q::<i64>(&s.c, alerts).await, 1);
    assert_eq!(
        q::<i64>(&s.c, "SELECT count(*) FROM alert_evidence_rules").await,
        1,
        "its rule came with it"
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2"
        )
        .await,
        2
    );
}

/// U4 — README §2 Restarts and Bounded; edge.md §11 (at-least-once delivery): a batch whose
/// records span many boots is applied once; its resend after a lost ack adds nothing (no boot of
/// the batch is forgotten).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_spanning_many_boots_is_applied_once() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    s.post(vec![s.late("q9", "bad.replay.example", "block", &now_ts())])
        .await;
    wait_for("the Block checked", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await
            == 1
    })
    .await;
    let batch: Vec<Value> = (0..100)
        .map(|i| {
            let mut v = s.query("bad.replay.example");
            v["boot"] = json!(format!("crashloop{i:03}"));
            v
        })
        .collect();
    s.post(batch.clone()).await;
    let key = "category_answered:provider:q9:replay.example";
    assert_eq!(alert_count(&s.c, key).await, 100);
    assert_eq!(
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_ingested").await,
        100,
        "every boot of the batch is kept"
    );
    s.post(batch).await;
    assert_eq!(alert_count(&s.c, key).await, 100, "a resend adds nothing");
}

/// U5 — core.md §7 Re-checks ("re-checks over max_per_day are dropped and counted"): the day's
/// allowance counts calls the provider answered; a rejected call gives its share back, so the
/// re-check still runs after the pause.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_per_day_gives_back_a_rejected_call() {
    let module = ScriptedModule::new("http_json", |_, _, n| {
        Box::pin(async move {
            if n == 0 {
                return Err(LookupError::Rejected {
                    retry_after: Some(Duration::from_secs(1)),
                });
            }
            Ok(Answer {
                verdict: Verdict::Clean,
                detail: None,
            })
        })
    });
    let s = Setup::new(
        http_json(json!({"recheck": {"enabled": true, "after": ["1s"], "jitter": "0s", "max_per_day": 1}})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        module.clone(),
    )
    .await;
    let mut a = s.query("rejected.example.org");
    a["ts"] = json!(ts_at(Timestamp::now() - jiff::SignedDuration::from_secs(3)));
    s.post(vec![a]).await;
    wait_for("the re-check to settle", 30, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    assert_eq!(module.calls(), 2, "the re-check ran after the rejection");
    assert_eq!(
        counter(&s.c, "rechecks", &[("provider", "q9"), ("result", "run")]),
        1.0
    );
    assert_eq!(
        counter(&s.c, "rechecks", &[("provider", "q9"), ("result", "dropped")]),
        0.0
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count FROM lookup_recheck_days WHERE provider_id = 'q9'"
        )
        .await,
        1,
        "only the answered call counts"
    );
}

/// U5 — core.md §7; providers.md §4 Cache generation: a re-check's call whose result a flush
/// discards gives its share back, and the call under the new generation is a call of its own:
/// reserved before it is made and counted (`lookup_calls`), never a hidden restart of the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_recheck_call_is_reserved_and_counted() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let g = gate.clone();
    let module = ScriptedModule::new("http_json", move |_, _, n| {
        let g = g.clone();
        Box::pin(async move {
            if n == 0 {
                g.notified().await;
            }
            Ok(Answer {
                verdict: Verdict::Clean,
                detail: None,
            })
        })
    });
    let s = Setup::new(
        http_json(json!({"recheck": {"enabled": true, "after": ["1s"], "jitter": "0s", "max_per_day": 1}})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
        module.clone(),
    )
    .await;
    let mut a = s.query("flushed.example.org");
    a["ts"] = json!(ts_at(Timestamp::now() - jiff::SignedDuration::from_secs(3)));
    s.post(vec![a]).await;
    wait_for("the first call", 20, || async { module.calls() == 1 }).await;
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count FROM lookup_recheck_days WHERE provider_id = 'q9'"
        )
        .await,
        1,
        "reserved before the call"
    );
    let generation = picket_core::lookups::flush(&s.c.state, "q9", Actor::cli())
        .await
        .unwrap();
    wait_for("the new generation", 10, || async {
        s.generation("q9") == generation
    })
    .await;
    wait_for("the re-check to settle", 30, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue").await == 0
    })
    .await;
    gate.notify_one();
    assert_eq!(module.calls(), 2);
    assert_eq!(
        counter(&s.c, "lookup_calls", &[("provider", "q9")]),
        2.0,
        "each call core made, counted"
    );
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count FROM lookup_recheck_days WHERE provider_id = 'q9'"
        )
        .await,
        1,
        "the discarded call's share went back; the second call's is kept"
    );
    assert_eq!(
        counter(&s.c, "rechecks", &[("provider", "q9"), ("result", "run")]),
        1.0
    );
    let g2 = generation.clone();
    let stored: i64 =
        s.c.state
            .db
            .read(move |db| {
                Ok::<_, anyhow::Error>(db.query_row(
                    "SELECT count(*) FROM lookup_verdicts WHERE generation = ?1",
                    [&g2],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
    assert_eq!(stored, 1, "the second call's result, under the new generation");
}

/// U8 — storage.md §4; providers.md §4 Cache generation: retention reads each provider's
/// generation in its own transaction, so rows a flush let in just before it (the runtime not yet
/// reloaded) stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retention_keeps_the_rows_of_a_generation_it_has_not_reloaded() {
    use picket_core::retention::RetentionHook as _;
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    let old = s.generation("q9");
    // A flush committed (as its own transaction would), and a verdict of the new generation was
    // stored, before the runtime's snapshot saw it.
    s.c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE lookup_providers SET cache_generation = '00000000000000f2' WHERE id = 'q9'",
                [],
            )?;
            db.execute(
                "INSERT INTO lookup_verdicts(provider_id, name, verdict, obtained_at, generation, source, changed_seq)
                 VALUES ('q9', 'fresh.example', 'clean', ?1, '00000000000000f2', 'core', 1)",
                [now_ts()],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    assert_eq!(s.generation("q9"), old, "the snapshot is the old generation");
    picket_core::lookups::VerdictRetention
        .step(&s.c.state)
        .await
        .unwrap();
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_verdicts WHERE name = 'fresh.example'"
        )
        .await,
        1
    );
}

/// U1 — README §2 Clocks; providers.md §4 Self-tests: the self-test schedule is wall-clock time,
/// so a save's test waits while the clock isn't synchronised and runs once it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_tests_wait_for_a_synchronised_clock() {
    let module = ScriptedModule::with_self_test(
        "http_json",
        SelfTest {
            name: "malware.testcategory.example".into(),
            expect: Expect::Block,
            cron: "0 0 1 1 *".into(),
        },
        |_cfg, _name, _n| {
            Box::pin(async move {
                Ok(Answer {
                    verdict: Verdict::Block {
                        score: None,
                        reason: "malware".into(),
                    },
                    detail: None,
                })
            })
        },
    );
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        module.clone(),
    )
    .await;
    wait_for("the save-time self-test", 20, || async { module.calls() >= 1 }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = module.calls();
    s.c.state.clock.pin(false);
    let mut p = http_json(json!({"async_timeout_ms": 9000}));
    p["id"] = json!("q9");
    s.c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Update("q9".into(), p),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(module.calls(), before, "no test on an unsynchronised clock");
    s.c.state.clock.pin(true);
    wait_for("the save's test once synchronised", 30, || async {
        module.calls() > before
    })
    .await;
}

/// W1 — core.md §2 Export and restore, §7 `category_answered`; README §2 Restarts: a Block check
/// takes the restore generation in the transaction that claims its Blocks. A restore that commits
/// just before the claim, followed by a new Block, never leaves that Block claimed by a check
/// whose commit the restore ends: it is checked, not stranded until a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_just_before_a_block_claim_strands_no_block() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    let (status, doc) = common::bundles::get(&s.c, "/config/export").await;
    assert_eq!(status, 200);
    let path = s.c.dir.path().join("restore.json");
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
    // No background worker from here on: the test runs the Block checker's passes.
    s.c.stop.cancel();
    tokio::time::sleep(Duration::from_millis(500)).await;
    // The writer is held, so the restore, a new Block and the check's claim queue on it in
    // that order.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let st = s.c.state.clone();
    let blocker = tokio::spawn(async move {
        st.db
            .write(move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap();
    });
    entered_rx.await.unwrap();
    let queued = s.c.state.db.pending_writes();
    let st = s.c.state.clone();
    let restore = tokio::spawn(async move {
        picket_core::config::export::restore_file(&st, &path, None)
            .await
            .unwrap();
    });
    wait_for("the restore on the writer's queue", 10, || async {
        s.c.state.db.pending_writes() > queued
    })
    .await;
    let queued = s.c.state.db.pending_writes();
    let st = s.c.state.clone();
    let insert = tokio::spawn(async move {
        st.db
            .write(move |db| {
                db.execute(
                    "INSERT INTO lookup_blocks(provider_id, name, obtained_at, source, generation)
                     SELECT 'q9', 'bad.restored.example', ?1, 'core', cache_generation
                     FROM lookup_providers WHERE id = 'q9'",
                    [now_ts()],
                )?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap();
    });
    wait_for("the new Block on the writer's queue", 10, || async {
        s.c.state.db.pending_writes() > queued
    })
    .await;
    let queued = s.c.state.db.pending_writes();
    let st = s.c.state.clone();
    let pass = tokio::spawn(async move { picket_core::lookups::answered::pass(&st).await.unwrap() });
    wait_for("the claim on the writer's queue", 10, || async {
        s.c.state.db.pending_writes() > queued
    })
    .await;
    release_tx.send(()).unwrap();
    blocker.await.unwrap();
    restore.await.unwrap();
    insert.await.unwrap();
    pass.await.unwrap();
    assert_eq!(s.c.state.restore.generation(), 1, "the restore committed");
    let current = "SELECT count(*) FROM lookup_blocks b JOIN lookup_providers p
                   ON b.provider_id = p.id AND b.generation = p.cache_generation";
    assert_eq!(
        q::<i64>(&s.c, current).await,
        1,
        "the new Block is of the restored state"
    );
    picket_core::lookups::answered::pass(&s.c.state).await.unwrap();
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2"
        )
        .await,
        1,
        "the Block was checked, not left claimed"
    );
}

/// W2 — README §2 Clocks; core.md §7 Execution: a call that fails after the clock lost its
/// synchronisation (and jumped four days ahead) writes no retry time from that clock; once the
/// clock is corrected the item is due again at once, not parked for four days.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failure_after_sync_is_lost_parks_nothing_on_the_wrong_clock() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let g = gate.clone();
    let module = ScriptedModule::new("http_json", move |_, _, _| {
        let g = g.clone();
        Box::pin(async move {
            g.notified().await;
            Err(LookupError::Failed(anyhow::anyhow!("transport failed")))
        })
    });
    let s = Setup::new(
        http_json(json!({"async_max_attempts": 3, "async_timeout_ms": 20000})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        module.clone(),
    )
    .await;
    s.post(vec![s.query("lost-sync.example")]).await;
    wait_for("the call", 10, || async { module.calls() == 1 }).await;
    // During the call the clock loses its synchronisation and jumps four days ahead.
    s.c.state.clock.pin(false);
    s.c.state
        .lookups
        .simulate_clock_offset(jiff::SignedDuration::from_hours(24 * 4));
    gate.notify_one();
    wait_for("the failure recorded", 10, || async {
        q::<i64>(&s.c, "SELECT count(*) FROM lookup_queue WHERE attempts = 1").await == 1
    })
    .await;
    let next = q::<String>(&s.c, "SELECT next_at FROM lookup_queue").await;
    // NTP corrects the clock.
    s.c.state
        .lookups
        .simulate_clock_offset(jiff::SignedDuration::ZERO);
    s.c.state.clock.pin(true);
    assert!(
        next < ts_at(Timestamp::now() + jiff::SignedDuration::from_mins(1)),
        "parked past the correction: {next}"
    );
    wait_for("the retry once synchronised", 20, || async {
        module.calls() == 2
    })
    .await;
    gate.notify_one();
}

/// W2 — README §2 Clocks; core.md §7 Execution: a queued lookup waiting for the provider's
/// token makes no call once the clock has lost its synchronisation meanwhile (the check is
/// made right before the call, after the wait); the item stays queued for later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lookup_waiting_for_a_token_makes_no_call_once_sync_is_lost() {
    let s = Setup::new(
        http_json(json!({"limits": {"max_inflight": 4, "rps": 1, "burst": 1}})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    // No background worker from here on: the test works the item itself.
    s.c.stop.cancel();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let query: picket_api::logs::QueryRecord = serde_json::from_value(s.query("waiting.example")).unwrap();
    picket_core::lookups::ingest::apply(
        &s.c.state,
        &s.edge.id,
        vec![picket_core::lookups::ingest::QueryInfo::of(&query, false)],
        vec![],
    )
    .await
    .unwrap();
    let client = s.c.state.lookups.client("q9").unwrap();
    // Another lookup takes the bucket's one token.
    client
        .lookup_async("token.example", picket_lookup::AsyncOptions::default())
        .await;
    assert_eq!(s.module.calls(), 1);
    let misses = client.metrics().cache_misses;
    let st = s.c.state.clone();
    let job = tokio::spawn(async move {
        picket_core::lookups::queue::process(&st, "q9", "waiting.example")
            .await
            .unwrap();
    });
    wait_for("the item waiting for a token", 10, || async {
        client.metrics().cache_misses > misses
    })
    .await;
    assert_eq!(s.module.calls(), 1);
    s.c.state.clock.pin(false);
    job.await.unwrap();
    assert_eq!(s.module.calls(), 1, "no call once synchronisation is lost");
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_queue WHERE name = 'waiting.example' AND attempts = 0"
        )
        .await,
        1,
        "the item waits, no attempt used"
    );
}

/// Writes a real answer for `qname` (edge `edge`, boot `b1`, seq `seq`) straight into its
/// partition, as log ingest does before its lookup step runs, and returns the record.
fn answer_in_partition(c: &Core, edge: &str, seq: u64, qname: &str) -> picket_api::logs::QueryRecord {
    answer_at(c, edge, seq, qname, &now_ts())
}

/// [`answer_in_partition`] at time `ts`.
fn answer_at(c: &Core, edge: &str, seq: u64, qname: &str, ts: &str) -> picket_api::logs::QueryRecord {
    let rec: picket_api::logs::QueryRecord =
        serde_json::from_value(common::edge::query("b1", seq, ts, qname, None)).unwrap();
    let store = picket_core::logs::LogStore::new(&c.state.data_dir);
    let hour = picket_core::logs::partition::hour_start(&rec.h.ts);
    let part = store.open(&hour, true).unwrap().unwrap();
    let seq = i64::try_from(seq).unwrap();
    part.insert(
        "events",
        &[
            ("edge_id", &edge),
            ("boot", &"b1"),
            ("seq", &seq),
            ("ts", &ts),
            ("profile", &"kids"),
            ("client_ip", &"10.0.0.2"),
            ("qname", &qname),
            ("qtype", &"A"),
            ("rcode", &"NOERROR"),
            ("decision", &"allow"),
        ],
        false,
    )
    .unwrap();
    rec
}

/// W3 — core.md §7 `category_answered`, §9 Dedupe: each answer counts once in its alert. A
/// second Block row for the name (another source, a later `obtained_at`) scans the same answers
/// and adds nothing; a new answer still counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_answer_counts_once_across_block_rows() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    // Re-scans: three answers, then two Block rows for the name.
    s.post(vec![
        s.query("bad.count.example"),
        s.query("bad.count.example"),
        s.query("bad.count.example"),
    ])
    .await;
    let key = "category_answered:provider:q9:count.example";
    let t1 = ts_at(Timestamp::now() - jiff::SignedDuration::from_hours(2));
    s.post(vec![s.late("q9", "bad.count.example", "block", &t1)])
        .await;
    wait_for("the first Block checked", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await
            == 1
    })
    .await;
    assert_eq!(alert_count(&s.c, key).await, 3);
    let t2 = ts_at(Timestamp::now() - jiff::SignedDuration::from_hours(1));
    s.post(vec![s.late("q9", "bad.count.example", "block", &t2)])
        .await;
    wait_for("the second Block checked", 20, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await
            == 2
    })
    .await;
    assert_eq!(
        alert_count(&s.c, key).await,
        3,
        "a re-scan counts no answer again"
    );
    // A new answer still counts.
    s.post(vec![s.query("bad.count.example")]).await;
    wait_for("the new answer counted", 20, || async {
        alert_count(&s.c, key).await == 4
    })
    .await;
}

/// W3 — core.md §7 `category_answered`, §9 Dedupe: an answer the Block's scan counted, whose own
/// lookup step runs after the scan, counts once; so does one the ingest counted while the scan,
/// which had read it, was still running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_counts_once_whether_the_scan_or_the_ingest_sees_it_first() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    // No background worker from here on: the test orders the scan and the ingest.
    s.c.stop.cancel();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let generation = s.generation("q9");
    let info = |r: &picket_api::logs::QueryRecord| picket_core::lookups::ingest::QueryInfo::of(r, false);

    // The scan counts the answer, then the answer's own lookup step runs.
    let key = "category_answered:provider:q9:after.example";
    insert_block(&s.c, "bad.after.example", &generation).await;
    let rec = answer_in_partition(&s.c, &s.edge.id, 9001, "bad.after.example");
    picket_core::lookups::answered::pass(&s.c.state).await.unwrap();
    assert_eq!(alert_count(&s.c, key).await, 1);
    picket_core::lookups::ingest::apply(&s.c.state, &s.edge.id, vec![info(&rec)], vec![])
        .await
        .unwrap();
    assert_eq!(
        alert_count(&s.c, key).await,
        1,
        "the ingest adds the scan's answer again"
    );

    // The scan reads the answer and stalls (older partitions held exclusively, each up to its
    // busy timeout); the answer's lookup step runs while the Block is claimed.
    let key = "category_answered:provider:q9:during.example";
    let store = picket_core::logs::LogStore::new(&s.c.state.data_dir);
    let mut held = Vec::new();
    for h in 1..=3 {
        let hour = picket_core::logs::partition::hour_start(
            &(Timestamp::now() - jiff::SignedDuration::from_hours(h)),
        );
        let part = store.open(&hour, true).unwrap().unwrap();
        part.conn
            .execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE")
            .unwrap();
        held.push(part);
    }
    insert_block(&s.c, "bad.during.example", &generation).await;
    let rec = answer_in_partition(&s.c, &s.edge.id, 9002, "bad.during.example");
    let st = s.c.state.clone();
    let job = tokio::spawn(async move { picket_core::lookups::answered::pass(&st).await.unwrap() });
    wait_for("the Block claimed", 10, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE name = 'bad.during.example' AND answers_checked = 1",
        )
        .await
            == 1
    })
    .await;
    picket_core::lookups::ingest::apply(&s.c.state, &s.edge.id, vec![info(&rec)], vec![])
        .await
        .unwrap();
    assert_eq!(alert_count(&s.c, key).await, 1, "the ingest counts it");
    for p in &held {
        p.conn.execute_batch("ROLLBACK").unwrap();
    }
    drop(held);
    job.await.unwrap();
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT answers_checked FROM lookup_blocks WHERE name = 'bad.during.example'"
        )
        .await,
        2
    );
    assert_eq!(alert_count(&s.c, key).await, 1, "the scan adds it again");
}

// ---------------------------------------------------------------------------------------------
// Final check 2 (F3): the counted answers a running scan holds are never forgotten

/// core.md §7 `category_answered`, §9 Dedupe (README §2 Bounded): 300 answers with one
/// timestamp, all counted, leave the newest 200 identities; a later Block row's scan orders its
/// answers as the ledger keeps them (time, then edge, boot and seq), so it reads only identities
/// still kept and counts none again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_with_equal_times_are_counted_once() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    // No background worker from here on: the test orders the scans and the ingest.
    s.c.stop.cancel();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let generation = s.generation("q9");
    let (name, key) = ("bad.equal.example", "category_answered:provider:q9:equal.example");
    insert_block(&s.c, name, &generation).await;
    picket_core::lookups::answered::pass(&s.c.state).await.unwrap();
    let ts = now_ts();
    let infos: Vec<_> = (1..=300)
        .map(|seq| {
            let rec = answer_at(&s.c, &s.edge.id, seq, name, &ts);
            picket_core::lookups::ingest::QueryInfo::of(&rec, false)
        })
        .collect();
    picket_core::lookups::ingest::apply(&s.c.state, &s.edge.id, infos, vec![])
        .await
        .unwrap();
    assert_eq!(alert_count(&s.c, key).await, 300);
    insert_block(&s.c, name, &generation).await;
    picket_core::lookups::answered::pass(&s.c.state).await.unwrap();
    assert_eq!(
        alert_count(&s.c, key).await,
        300,
        "every answer was counted already"
    );
}

/// core.md §7 `category_answered`, §9 Dedupe (README §2 Bounded): a Block's scan reads 99
/// counted answers and stalls (older partitions held exclusively, each up to its busy timeout);
/// meanwhile 201 newer answers arrive and are counted, past the 200 identities kept per name. The
/// identities the running scan holds are kept until it commits, so it counts none of them again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_scan_keeps_the_counted_answers_it_holds() {
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids"}),
        by_name(),
    )
    .await;
    s.c.stop.cancel();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let generation = s.generation("q9");
    let (name, key) = (
        "bad.racing.example",
        "category_answered:provider:q9:racing.example",
    );
    let info = |r: &picket_api::logs::QueryRecord| picket_core::lookups::ingest::QueryInfo::of(r, false);
    insert_block(&s.c, name, &generation).await;
    picket_core::lookups::answered::pass(&s.c.state).await.unwrap();
    let infos: Vec<_> = (1..=99)
        .map(|seq| info(&answer_in_partition(&s.c, &s.edge.id, seq, name)))
        .collect();
    picket_core::lookups::ingest::apply(&s.c.state, &s.edge.id, infos, vec![])
        .await
        .unwrap();
    assert_eq!(alert_count(&s.c, key).await, 99);
    let store = picket_core::logs::LogStore::new(&s.c.state.data_dir);
    let mut held = Vec::new();
    for h in 1..=5 {
        let hour = picket_core::logs::partition::hour_start(
            &(Timestamp::now() - jiff::SignedDuration::from_hours(h)),
        );
        let part = store.open(&hour, true).unwrap().unwrap();
        part.conn
            .execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE")
            .unwrap();
        held.push(part);
    }
    insert_block(&s.c, name, &generation).await;
    let st = s.c.state.clone();
    let scan = tokio::spawn(async move { picket_core::lookups::answered::pass(&st).await.unwrap() });
    wait_for("the Block claimed", 10, || async {
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 1",
        )
        .await
            == 1
    })
    .await;
    // The scan has read the current hour (answers 1–99) and waits on the held partitions.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let infos: Vec<_> = (100..=300)
        .map(|seq| info(&answer_in_partition(&s.c, &s.edge.id, seq, name)))
        .collect();
    picket_core::lookups::ingest::apply(&s.c.state, &s.edge.id, infos, vec![])
        .await
        .unwrap();
    assert_eq!(alert_count(&s.c, key).await, 300);
    for p in &held {
        p.conn.execute_batch("ROLLBACK").unwrap();
    }
    drop(held);
    scan.await.unwrap();
    assert_eq!(
        q::<i64>(
            &s.c,
            "SELECT count(*) FROM lookup_blocks WHERE answers_checked = 2",
        )
        .await,
        2,
        "the scan finished"
    );
    assert_eq!(
        alert_count(&s.c, key).await,
        300,
        "the scan's answers were counted before it read them"
    );
}

/// #71 (review of #89): a config restore overtaking a batch between its events and its lookups
/// leaves the lookup step committing nothing (no queued call, no verdict) and the batch is
/// retried; the retry goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_before_the_lookup_step_commits_no_lookup() {
    use picket_core::logs::ingest::IngestPoint;
    let s = Setup::new(
        http_json(json!({})),
        json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "async"}]}),
        by_name(),
    )
    .await;
    let lines = vec![s.query("bad.restore.example")];
    let r = crate::edge_protocol::store_across_a_restore(&s.c, &s.edge, &lines, IngestPoint::AfterEvents).await;
    assert!(crate::edge_protocol::is_retryable(&r), "{r:?}");
    let touched = "SELECT (SELECT count(*) FROM lookup_queue) + (SELECT count(*) FROM lookup_verdicts \
                   WHERE name = 'bad.restore.example')";
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(q::<i64>(&s.c, touched).await, 0, "nothing of the batch's lookups committed");
    wait_for("the lookups runtime to see the restored config", 10, || async {
        s.c.state.lookups.model().lookup_providers.contains_key("q9")
    })
    .await;
    let r = s
        .c
        .state
        .logs
        .store_batch(&s.c.state, &s.edge.id, &s.edge.fingerprint, crate::edge_protocol::batch_of(&lines))
        .await
        .unwrap();
    assert_eq!(r.stored, 1, "{r:?}");
    wait_for("the retry's lookup", 20, || async { q::<i64>(&s.c, touched).await > 0 }).await;
}
