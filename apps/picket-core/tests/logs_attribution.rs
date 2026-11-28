//! Attribution replay, its bounds and the check of unchecked cold lookups (core.md §6, §9;
//! bundles.md §2, §6; build-and-test.md §5 rows "Attribution" and "Hot and cold parts"); review
//! fix-w5a items N12 (one compiled-pattern budget), N15 (allows by an exception), N19 (capped
//! replays skip the self-check) and N20 (cold checks only for names that reached the cold stage),
//! and a bundle version an edge keeps running past retention.
//!
//! Each test uses the logs fixture ([`common::logs::Setup`]): records go in through
//! `POST /v1/logs` and the test runs the analysis itself.

use crate::common;

use common::bundles::{build, manual_feed, put_entity, save, wait};
use common::logs::{Setup, short};
use jiff::Timestamp;
use serde_json::{Value, json};

/// Re-renders the edge's config after a profile change and returns the new config id, once the
/// published config holds `profile`.
async fn publish(s: &Setup, profile: &str) -> String {
    s.c.state.edges.publisher.render(&s.c.state, None).await.unwrap();
    let mut id = String::new();
    wait(&format!("a config with profile {profile}"), || {
        let cur = s.c.state.edges.publisher.current(&s.edge.id);
        let ok = cur
            .as_ref()
            .is_some_and(|p| p.config.profiles.contains_key(profile));
        if let Some(p) = &cur {
            id = p.id.clone();
        }
        async move { ok }
    })
    .await;
    id
}

/// One record's stored attribution: (status, matches_json).
fn attribution(s: &Setup, at: Timestamp, seq: u64) -> (String, Value) {
    let status: String = s.part(at, &format!("SELECT status FROM attribution WHERE seq = {seq}"));
    let m: String = s.part(
        at,
        &format!("SELECT matches_json FROM attribution WHERE seq = {seq}"),
    );
    (status, serde_json::from_str(&m).unwrap())
}

/// A record of profile `profile` under `versions` (`pv`).
fn rec(
    s: &Setup,
    seq: u64,
    at: Timestamp,
    qname: &str,
    decision: &str,
    reason: Value,
    pv: (&str, &Value),
) -> Value {
    let (profile, versions) = pv;
    let mut r = s.q("b-a", seq, at, qname, decision, reason);
    r["profile"] = json!(profile);
    r["versions"] = versions.clone();
    r
}

/// N15 and N20 (core.md §6 "an allow by an allow bundle or exception"; rules.md §5 step 5;
/// bundles.md §6 "Cold lookup"): an allow by a block-bundle exception is attributed with the
/// exception decisive and passes the self-check; a cold check covers only the names whose cold
/// stage the edge reached: no CNAME target after an exception pass under `skip_after_allow`
/// (logged as such, or found by replay for an edge that didn't log it), every one under `all`;
/// no target an allow bundle allows, and none an exception in the same bundle lets through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exception_passes_are_attributed_and_cold_checks_follow_the_ladder() {
    let s = Setup::new(None).await;
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n@@||ok.ads.example^\n",
    )
    .await;
    let b1 = build(&s.c, "b1").await.expect("b1 head");
    manual_feed(&s.c, "f-allow", json!({"category": "privacy"})).await;
    save(&s.c, "f-allow", "||allowed-target.example^\n").await;
    put_entity(
        &s.c,
        "bundles",
        "allow-b",
        json!({"id": "allow-b", "name": "allow-b", "action": "allow", "feeds": [{"feed": "f-allow"}]}),
    )
    .await;
    let allow_head = build(&s.c, "allow-b").await.expect("allow head");
    manual_feed(&s.c, "f-cold", json!({"category": "security"})).await;
    save(
        &s.c,
        "f-cold",
        "||coldhit.example^\n||allowed-target.example^\n@@||safe.coldhit.example^\n",
    )
    .await;
    put_entity(
        &s.c,
        "bundles",
        "b-cold",
        json!({"id": "b-cold", "name": "b-cold", "feeds": [{"feed": "f-cold", "tier": "cold"}]}),
    )
    .await;
    let cold_head = build(&s.c, "b-cold").await.expect("cold head");
    put_entity(
        &s.c,
        "profiles",
        "p3",
        json!({"id": "p3", "name": "p3", "allow": ["allow-b"], "block": ["b1", "b-cold"]}),
    )
    .await;
    put_entity(
        &s.c,
        "profiles",
        "p4",
        json!({"id": "p4", "name": "p4", "allow": ["allow-b"], "block": ["b1", "b-cold"],
               "response_checks": "all"}),
    )
    .await;
    publish(&s, "p3").await;
    let config = publish(&s, "p4").await;
    let versions = json!({"config": short(&config), "bundles": {
        "b1": short(&b1), "allow-b": short(&allow_head), "b-cold": short(&cold_head)}});
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let exc = json!({"step": 3, "bundle": "b1", "key": "ok.ads.example", "kind": "subs", "stage": "query"});
    let with_cname = |mut r: Value, target: &str| {
        r["cname"] = json!([target]);
        r["answers"] = json!(["192.0.2.5"]);
        r["cold_unchecked"] = json!(["b-cold"]);
        r
    };
    let lines = vec![
        // 1: an exception pass, attributed.
        rec(
            &s,
            1,
            now,
            "www.ok.ads.example",
            "allow",
            exc.clone(),
            ("p3", &versions),
        ),
        // 2: an exception pass under skip_after_allow: its CNAME target wasn't checked.
        with_cname(
            rec(
                &s,
                2,
                now,
                "www.ok.ads.example",
                "allow",
                exc.clone(),
                ("p3", &versions),
            ),
            "coldhit.example",
        ),
        // 3: the same from an edge that logged no reason: the replay finds the exception.
        with_cname(
            rec(
                &s,
                3,
                now,
                "www.ok.ads.example",
                "allow",
                Value::Null,
                ("p3", &versions),
            ),
            "coldhit.example",
        ),
        // 4: under `all` the target was checked: a missed block.
        with_cname(
            rec(
                &s,
                4,
                now,
                "www.ok.ads.example",
                "allow",
                exc.clone(),
                ("p4", &versions),
            ),
            "www.coldhit.example",
        ),
        // 5: a target the allow bundle allows never reached the cold stage.
        with_cname(
            rec(
                &s,
                5,
                now,
                "plain.example",
                "allow",
                Value::Null,
                ("p3", &versions),
            ),
            "allowed-target.example",
        ),
        // 6: a target the cold bundle's own (hot) exception lets through neither.
        with_cname(
            rec(
                &s,
                6,
                now,
                "plain2.example",
                "allow",
                Value::Null,
                ("p3", &versions),
            ),
            "safe.coldhit.example",
        ),
    ];
    s.post(lines).await;
    s.drain().await;
    let (status, m) = attribution(&s, now, 1);
    assert_eq!(status, "complete", "{m}");
    assert_eq!(m["self_check"], "ok", "{m}");
    assert_eq!(m["decisive"], json!([3, "b1"]), "{m}");
    let decisive: Vec<&Value> = m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["role"] == "decisive")
        .collect();
    assert_eq!(decisive.len(), 1, "{m}");
    assert_eq!(decisive[0]["text"], "@@||ok.ads.example^", "{m}");
    assert_eq!(decisive[0]["feed"], "f-sec");
    assert!(
        m["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["text"] == "||ads.example^" && x["role"] == "overridden" && x["by"] == "exception"),
        "{m}"
    );
    let mismatch: i64 = s
        .scalar_core("SELECT count(*) FROM alerts WHERE kind = 'attribution_mismatch'")
        .await;
    assert_eq!(mismatch, 0, "an exception pass passes the self-check");
    let cold = |seq: u64| s.part::<String>(now, &format!("SELECT cold_check FROM events WHERE seq = {seq}"));
    assert_eq!(cold(2), "ok", "skip_after_allow: the target wasn't checked");
    assert_eq!(
        cold(3),
        "ok",
        "the replay finds the exception the edge didn't log"
    );
    assert_eq!(cold(4), "missed", "`all` checks the target after an exception");
    assert_eq!(cold(5), "ok", "an allow bundle allowed the target");
    assert_eq!(cold(6), "ok", "the bundle's exception let the target through");
    assert_eq!(
        s.metric_total("cold_missed_blocks", "\"bundle\":\"b-cold\"")
            .await,
        1.0
    );
    let hits: i64 = s
        .scalar_core("SELECT count(*) FROM bundle_key_hits WHERE bundle_id = 'b-cold'")
        .await;
    assert_eq!(hits, 1, "only the real miss promotes its key");
}

/// N19 (core.md §6 step 4; README §2 Bounded): a value with more candidate rules than replay
/// reads ([`picket_core::logs::replay::MAX_CANDIDATES`]) is replayed partially: its attribution
/// is `incomplete` and skips the self-check, so no `attribution_mismatch` only a person could
/// clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_replays_are_incomplete_and_skip_the_self_check() {
    let s = Setup::new(None).await;
    let n = picket_core::logs::replay::MAX_CANDIDATES + 1;
    let mut text = String::from("||ads.example^\n||tracker.example^\n");
    for i in 0..n {
        text.push_str(&format!(
            "||capped.example^$client=10.{}.{}.{}\n",
            i / 65536,
            (i / 256) % 256,
            i % 256
        ));
    }
    save(&s.c, "f-sec", &text).await;
    let head = build(&s.c, "b1").await.expect("b1 head");
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut r = s.q(
        "b-p",
        1,
        now,
        "capped.example",
        "block",
        json!({"step": 3, "bundle": "b1", "key": "capped.example", "kind": "rich", "stage": "query"}),
    );
    r["versions"] = json!({"config": short(&s.config), "bundles": {"b1": short(&head)}});
    s.post(vec![r]).await;
    s.drain().await;
    let (status, m) = attribution(&s, now, 1);
    assert_eq!(status, "incomplete", "{m}");
    assert_eq!(m["self_check"], "skipped", "{m}");
    let mismatch: i64 = s
        .scalar_core("SELECT count(*) FROM alerts WHERE kind = 'attribution_mismatch'")
        .await;
    assert_eq!(mismatch, 0);
}

/// N12 (core.md §6: patterns "compiled lazily, LRU-cached …, 32 MB cap"): the compiled regexes a
/// replay uses are charged to the one budget, and clearing the caches gives the charge back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compiled_patterns_share_one_budget_given_back_on_clear() {
    let s = Setup::new(None).await;
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n/^ad[0-9]+\\.example$/\n",
    )
    .await;
    let head = build(&s.c, "b1").await.expect("b1 head");
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut r = s.q(
        "b-1",
        1,
        now,
        "ad1.example",
        "block",
        json!({"step": 3, "bundle": "b1", "key": "/^ad[0-9]+\\.example$/", "kind": "pattern", "stage": "query"}),
    );
    r["versions"] = json!({"config": short(&s.config), "bundles": {"b1": short(&head)}});
    s.post(vec![r]).await;
    s.drain().await;
    let (status, m) = attribution(&s, now, 1);
    assert_eq!(status, "complete", "{m}");
    assert_eq!(m["self_check"], "ok", "{m}");
    let budget = &s.c.state.analysis.caches.budget;
    assert!(budget.used() > 0 && budget.used() <= budget.max());
    assert_eq!(
        budget.len(),
        1,
        "one regex, shared by the feed run's patterns and the matcher"
    );
    assert_eq!(
        budget.builds(),
        1,
        "the candidate matcher compiled no copy of its own"
    );
    s.c.state.analysis.caches.clear();
    assert_eq!(budget.used(), 0, "clear gives the compiled bytes back");
}

/// build-and-test.md §5 "Attribution": an edge kept on one head past retention keeps complete
/// attribution (core.md §6 step 1; storage.md §4: a version an edge reports active stays, with
/// the feed runs and closed entries it needs), on real history: the rule the head was built from
/// is gone from the feed's newer runs. Once the edge runs a newer head and retention collects
/// the old one, a record on it is `unavailable` and raises `attribution_unavailable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_an_edge_keeps_running_past_retention_attributes_completely() {
    use picket_core::retention::RetentionHook;
    let s = Setup::new(None).await;
    let old = s.b1.clone();
    // The edge reports the head active.
    let (mut ws, _) = s.edge.session(common::edge::hello("b-r")).await;
    let mut hb = common::edge::heartbeat("b-r", Timestamp::now(), 1000, 1);
    hb["versions"] = json!({"config": short(&s.config), "bundles": {"b1": short(&old)}});
    common::edge::send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    let want = short(&old);
    let sr = &s;
    wait("the edge's reported versions", || {
        let want = want.clone();
        async move {
            sr.scalar_core::<Option<String>>("SELECT versions_json FROM edge_status")
                .await
                .is_some_and(|v| v.contains(&want))
        }
    })
    .await;
    // The feeds move on: `||ads.example^` leaves f-sec (and f-priv), so b1 gets newer heads.
    save(
        &s.c,
        "f-sec",
        "||tracker.example^\n||198.51.100.7^\n||new.example^\n",
    )
    .await;
    save(
        &s.c,
        "f-priv",
        "||tracker.example^$badfilter\n|tracker.example^\n",
    )
    .await;
    let newer = build(&s.c, "b1").await.expect("newer head");
    assert_ne!(newer, old);
    // Everything is old enough to go, unless in use.
    let backdate = || async {
        s.c.state
            .db
            .write(|db| {
                db.execute_batch(
                    "UPDATE feed_runs SET downloaded_at = '2020-01-01T00:00:00.000000Z',
                        confirmed_at = '2020-01-01T00:00:00.000000Z', updated_at = '2020-01-01T00:00:00.000000Z';
                     UPDATE bundle_versions SET published_at = '2020-01-01T00:00:00.000000Z',
                        superseded_at = '2020-01-01T00:00:00.000000Z', last_used_at = '2020-01-01T00:00:00.000000Z'
                        WHERE superseded_at IS NOT NULL;",
                )?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap();
    };
    let sweep = || async {
        let b = picket_core::compiler::retention::BundleRetention;
        while b.step(&s.c.state).await.unwrap() == picket_core::scheduler::Step::More {}
        let f = picket_core::feeds::retention::FeedRetention;
        while f.step(&s.c.state).await.unwrap() == picket_core::scheduler::Step::More {}
    };
    backdate().await;
    sweep().await;
    let kept: i64 = s
        .scalar_core(&format!(
            "SELECT count(*) FROM bundle_versions WHERE bundle_id = 'b1' AND head_id = '{old}'"
        ))
        .await;
    assert_eq!(kept, 1, "a head the edge runs stays past the window");
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut r = s.block("b-r", 1, now, "www.ads.example", "ads.example");
    r["versions"] = json!({"config": short(&s.config), "bundles": {"b1": short(&old)}});
    s.post(vec![r]).await;
    s.drain().await;
    let (status, m) = attribution(&s, now, 1);
    assert_eq!(status, "complete", "{m}");
    assert_eq!(m["self_check"], "ok", "{m}");
    let decisive: Vec<&Value> = m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["role"] == "decisive")
        .collect();
    assert_eq!(decisive.len(), 1, "{m}");
    assert_eq!(decisive[0]["feed"], "f-sec", "{m}");
    assert_eq!(decisive[0]["text"], "||ads.example^", "{m}");
    // The edge moves to the newer head and forgets the old one: its status as a later heartbeat
    // leaves it, written once the session is over (heartbeats are stored at the hub's interval);
    // retention collects the old one.
    drop(ws);
    wait("the session's end", || {
        let gone = s.c.state.edges.hub.session(&s.edge.id).is_none();
        async move { gone }
    })
    .await;
    // The config core serves names the newer head (rendered after the build).
    wait("a config naming the newer head", || {
        let ok =
            s.c.state
                .edges
                .publisher
                .current(&s.edge.id)
                .is_some_and(|p| p.config.bundles.get("b1").is_some_and(|h| *h == newer));
        async move { ok }
    })
    .await;
    let now_v = json!({"config": short(&s.config), "bundles": {"b1": short(&newer)}}).to_string();
    s.c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE edge_status SET versions_json = ?1, previous_versions_json = NULL",
                [now_v],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    backdate().await;
    sweep().await;
    let kept: i64 = s
        .scalar_core(&format!(
            "SELECT count(*) FROM bundle_versions WHERE bundle_id = 'b1' AND head_id = '{old}'"
        ))
        .await;
    assert_eq!(kept, 0, "out of use past the window: collected");
    s.c.state.analysis.caches.clear();
    let mut r = s.block("b-r", 2, now, "x.ads.example", "ads.example");
    r["versions"] = json!({"config": short(&s.config), "bundles": {"b1": short(&old)}});
    s.post(vec![r]).await;
    s.drain().await;
    let (status, m) = attribution(&s, now, 2);
    assert_eq!(status, "unavailable", "{m}");
    let key = format!("attribution_unavailable:{}:b1:{}", s.edge.id, short(&old));
    assert!(s.alert(&key).await.is_some(), "attribution_unavailable raised");
}
