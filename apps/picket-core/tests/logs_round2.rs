//! Log analysis, retro-match, trial checks, evidence and metrics after review round 2 (wave 5
//! part A): progress that a retention prune can't take from a live partition (README §2
//! Restarts), replay admitting exactly the compiler's patterns (bundles.md §2 Determinism), the
//! compiled-pattern and LRU bounds (README §2 Bounded; core.md §6), retro-match aggregating in
//! capped steps, trial results recovered across restarts (core.md §6 "checked once"), the
//! evidence budget across rollbacks (core.md §9), the metric outbox across restores and failures
//! (core.md §2, §10), the tiering hold (bundles.md §2 Tiering) and per-record isolation (README §2
//! "a bad item never stalls the receiver").

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use common::bundles::{build, manual_feed, put_entity, save};
use common::logs::Setup;
use jiff::Timestamp;
use picket_core::logs::analysis::{self, FailPoint};
use picket_core::logs::partition::partition_file_name;
use serde_json::{Value, json};

fn adblock_rule(line: &str) -> picket_rules::Rule {
    match picket_rules::classify::classify_adblock_line(line, false) {
        picket_rules::classify::Line::Items(items) => items
            .into_iter()
            .find_map(|x| match x {
                picket_rules::classify::Item::Rule(r) => Some(r),
                _ => None,
            })
            .unwrap(),
        _ => panic!("rule rejected: {line}"),
    }
}

/// A synchronised clock (README §2 Clocks: the outbox ages its rows only by one).
fn synced() -> picket_core::clock::Clock {
    let c = picket_core::clock::Clock::default();
    c.pin(true);
    c
}

fn core_db() -> rusqlite::Connection {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    for schema in picket_core::db::schema::CORE {
        db.execute_batch(schema).unwrap();
    }
    db
}

fn insert_entry(tx: &rusqlite::Connection, feed: &str, run: i64, raw: &str) {
    let r = adblock_rule(raw);
    tx.execute(
        "INSERT INTO feed_entries(feed_id, rule_type, key, kind, flags, value_json, raw, first_run, last_seen_run,
                                  last_seen_at, first_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 't', 't')",
        rusqlite::params![
            feed,
            r.rule_type.as_str(),
            r.key,
            r.kind.as_str(),
            r.flags.bits(),
            r.value_json(),
            raw,
            run
        ],
    )
    .unwrap();
}

// S1 ------------------------------------------------------------------------------------------

/// The progress of an hour whose partition the prune didn't see (a file made right after its
/// listing, whose first batch committed before the prune's write) is kept: the hour is inside
/// the retention window, so its records are never analysed twice (README §2 Restarts).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prune_never_takes_the_progress_of_a_live_partition() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![
        s.block("b-1", 1, now, "ads.example", "ads.example"),
        s.block("b-1", 2, now, "x.ads.example", "ads.example"),
    ])
    .await;
    s.drain().await;
    let key = picket_core::alerts::category_blocked_key("tablet", "ads.example");
    let before = s.alert(&key).await.unwrap()["count"].clone();
    let hits_before = s.metric_total("feed_hits", "\"feed\":\"f-sec\"").await;
    // The hour's file isn't there while the prune runs.
    let dir = s.c.state.data_dir.join("logs");
    let f = dir.join(partition_file_name(&now));
    let hidden = dir.join("hidden.tmp");
    std::fs::rename(&f, &hidden).unwrap();
    analysis::prune_progress(&s.c.state).await.unwrap();
    std::fs::rename(&hidden, &f).unwrap();
    assert_eq!(s.drain().await, 0, "nothing is analysed again");
    assert_eq!(s.alert(&key).await.unwrap()["count"], before);
    assert_eq!(
        s.metric_total("feed_hits", "\"feed\":\"f-sec\"").await,
        hits_before
    );
}

/// Progress of an hour past the retention window with no partition left goes (and so does a
/// deleted partition's, with the partition itself).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn progress_of_hours_past_the_window_goes() {
    let s = Setup::new(None).await;
    let old = "2020-01-01T00";
    s.c.state
        .db
        .write(move |c| {
            c.execute(
                "INSERT INTO log_progress(hour, kind, value) VALUES (?1, 'analysis', 7)",
                [old],
            )?;
            c.execute(
                "INSERT INTO trial_pending(hour, rowid_, bundle) VALUES (?1, 1, 'x')",
                [old],
            )?;
            c.execute("INSERT INTO retro_progress(hour, seen) VALUES (?1, 3)", [old])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    analysis::prune_progress(&s.c.state).await.unwrap();
    for t in ["log_progress", "trial_pending", "retro_progress"] {
        assert_eq!(
            s.scalar_core::<i64>(&format!("SELECT count(*) FROM {t} WHERE hour = '{old}'"))
                .await,
            0,
            "{t}"
        );
    }
}

// S2 ------------------------------------------------------------------------------------------

/// Replay admits exactly the patterns the compiler admitted (bundles.md §2 Determinism): block
/// patterns that fill the pattern budget push the bundle's exception past it, so the compiled
/// bundle (and its reference matcher) blocks; the trial check's replay must block too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_drops_the_patterns_the_compiler_dropped() {
    let s = Setup::new(None).await;
    manual_feed(&s.c, "f-big", json!({"category": "security"})).await;
    let mut text = String::new();
    for i in 0..200 {
        text.push_str(&format!("/(?:(?:\\w|-){{900}}a{i}|common\\.example)/\n"));
    }
    text.push_str("@@/common\\.example/\n");
    save(&s.c, "f-big", &text).await;
    put_entity(
        &s.c,
        "bundles",
        "trial-big",
        json!({"id": "trial-big", "name": "trial-big", "feeds": [{"feed": "f-big"}]}),
    )
    .await;
    build(&s.c, "trial-big").await.expect("trial-big head");
    let reference = common::bundles::reference(&s.c, "trial-big").await;
    assert_eq!(
        common::bundles::decide_ref(&reference, &common::bundles::Q::name("common.example")),
        "block",
        "the compiler dropped the exception past the budget"
    );
    put_entity(
        &s.c,
        "profiles",
        "p1",
        json!({"id": "p1", "name": "p1", "block": ["b1"], "trial_bundles": ["trial-big"]}),
    )
    .await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![s.q("b-big", 1, now, "common.example", "allow", Value::Null)])
        .await;
    s.drain().await;
    assert_eq!(
        s.part::<i64>(
            now,
            "SELECT count(*) FROM would_blocks WHERE bundle_id = 'trial-big'"
        ),
        1,
        "replay must not bring back the exception the compiler dropped"
    );
}

// S3 ------------------------------------------------------------------------------------------

/// An entry heavier than the LRU's whole byte budget is never kept (README §2 Bounded).
#[test]
fn replay_lru_refuses_a_single_entry_bigger_than_its_byte_budget() {
    let mut cache = picket_core::logs::replay::Lru::new(8192, 64 * 1024 * 1024);
    cache.insert("small", (), 1024);
    cache.insert("wide-candidate", (), 64 * 1024 * 1024 + 1);
    assert!(
        cache.weight() <= 64 * 1024 * 1024,
        "oversize entry is still resident: {}",
        cache.weight()
    );
    assert!(cache.get(&"wide-candidate").is_none());
    assert!(cache.get(&"small").is_some(), "a refused entry evicts nothing");
}

/// The pattern budget charges each regex what it really holds (its heap and a fresh cache, with
/// cache growth in one shared pool), so 32 MiB holds thousands of ordinary patterns and a pass
/// over them twice builds each once (core.md §6: "compiled lazily, LRU-cached …, 32 MB cap").
#[test]
fn the_pattern_budget_holds_thousands_of_ordinary_patterns() {
    let caches = picket_core::logs::replay::ReplayCaches::default();
    let n = 2_000;
    let specs: Vec<picket_rules::rule::PatternSpec> = (0..n)
        .map(|i| {
            adblock_rule(&format!("/^ad{i}[0-9]+\\.example$/"))
                .pattern_spec()
                .unwrap()
        })
        .collect();
    for _ in 0..2 {
        for (i, p) in specs.iter().enumerate() {
            let _ = caches.pattern_hits(p, &format!("ad{i}7.example"));
            let _ = caches.pattern_hits(p, "x.y.z.example.com");
        }
    }
    assert_eq!(caches.budget.len(), n, "every regex kept");
    assert_eq!(caches.budget.builds(), n as u64, "each built once");
    assert!(caches.budget.used() <= caches.budget.max());
}

// S5 ------------------------------------------------------------------------------------------

/// A run's patterns are capped among its block patterns only: 20,001 exceptions then one block
/// pattern keep the block, and nothing is left out (core.md §6 retro-match counts blocks).
#[test]
fn retro_pattern_cap_applies_to_kept_blocks_and_counts_omissions() {
    use picket_core::logs::replay::{ReplayCaches, Value as RV};
    use picket_core::logs::retro::{RunMatcher, SeenRun};
    let mut db = core_db();
    let tx = db.transaction().unwrap();
    for i in 0..20_001 {
        insert_entry(&tx, "f", 1, &format!("@@/^allow{i}[0-9]+\\.example$/"));
    }
    insert_entry(&tx, "f", 1, "/^bad[0-9]+\\.example$/");
    tx.commit().unwrap();
    let run = SeenRun {
        id: 1,
        feed: "f".into(),
        at: Timestamp::now(),
    };
    let m = RunMatcher::load(&db, &run).unwrap();
    let hits = m
        .entries_for(
            &db,
            &ReplayCaches::default(),
            &RV::name_from_log("bad1.example").unwrap(),
            &mut 0,
        )
        .unwrap();
    assert_eq!(hits.len(), 1, "omissions counted: {}", m.patterns_left_out);
    assert_eq!(m.patterns_left_out, 0);
}

/// Past the cap, the block patterns left out are counted, every one of them.
#[test]
fn retro_patterns_past_the_cap_are_all_counted() {
    use picket_core::logs::retro::{RUN_PATTERNS, RunMatcher, SeenRun};
    let mut db = core_db();
    let tx = db.transaction().unwrap();
    for i in 0..RUN_PATTERNS + 7 {
        insert_entry(&tx, "f", 1, &format!("/^bad{i}[0-9]+\\.example$/"));
    }
    tx.commit().unwrap();
    let run = SeenRun {
        id: 1,
        feed: "f".into(),
        at: Timestamp::now(),
    };
    let m = RunMatcher::load(&db, &run).unwrap();
    assert_eq!(m.patterns_left_out, 7);
}

/// A run whose added key rows outnumber the in-memory cap but whose distinct keys fit it is
/// never held as a complete key set that misses keys (README §2 Bounded: a truncated set is
/// never taken as complete).
#[test]
fn retro_key_sets_are_complete_or_not_used() {
    use picket_core::logs::replay::{ReplayCaches, Value as RV};
    use picket_core::logs::retro::{RUN_KEYS, RunMatcher, SeenRun};
    let mut db = core_db();
    let tx = db.transaction().unwrap();
    // One key under many rule variants (each its own row), then the key a record names.
    for i in 0..=RUN_KEYS {
        insert_entry(
            &tx,
            "f",
            1,
            &format!("||dup.example^$client=10.0.{}.{}", i / 250, i % 250),
        );
    }
    insert_entry(&tx, "f", 1, "||target.example^");
    tx.commit().unwrap();
    let run = SeenRun {
        id: 1,
        feed: "f".into(),
        at: Timestamp::now(),
    };
    let m = RunMatcher::load(&db, &run).unwrap();
    let hits = m
        .entries_for(
            &db,
            &ReplayCaches::default(),
            &RV::name_from_log("target.example").unwrap(),
            &mut 0,
        )
        .unwrap();
    assert_eq!(hits.len(), 1, "the key past the loader's limit is still found");
}

// S6 ------------------------------------------------------------------------------------------

/// A record checked against one trial bundle before a stop (its would-block stored, another
/// bundle still without a head) keeps that result after the bundle's head changes, and counts it
/// once (core.md §6: each record is checked once; README §2 Restarts).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_partial_trial_preserves_completed_results_and_metrics() {
    let s = Setup::new(None).await;
    manual_feed(&s.c, "f-new", json!({"category": "security"})).await;
    put_entity(
        &s.c,
        "bundles",
        "trial-new",
        json!({"id": "trial-new", "name": "trial-new", "feeds": [{"feed": "f-new"}]}),
    )
    .await;
    put_entity(
        &s.c,
        "profiles",
        "p1",
        json!({"id": "p1", "name": "p1", "block": ["b1"], "trial_bundles": ["trial-b", "trial-new"]}),
    )
    .await;
    s.without_head("trial-new").await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![s.q(
        "partial-restart",
        1,
        now,
        "trial.example",
        "allow",
        Value::Null,
    )])
    .await;
    s.c.state.analysis.fail_at(FailPoint::AnalysisBeforeEffects);
    assert!(analysis::drain(&s.c.state).await.is_err());
    assert_eq!(
        s.part::<i64>(
            now,
            "SELECT count(*) FROM would_blocks WHERE bundle_id = 'trial-b'"
        ),
        1
    );
    assert!(
        s.part::<Option<String>>(now, "SELECT trial_check FROM events WHERE seq = 1")
            .is_none()
    );
    save(&s.c, "f-trial", "||different.example^\n").await;
    build(&s.c, "trial-b").await.unwrap();
    s.drain().await;
    assert_eq!(
        s.part::<i64>(
            now,
            "SELECT count(*) FROM would_blocks WHERE bundle_id = 'trial-b'"
        ),
        1
    );
    assert_eq!(
        s.metric_total("trial_would_block", "\"bundle\":\"trial-b\"")
            .await,
        1.0,
        "the persisted would-block is counted on restart"
    );
}

/// A pending record whose retry stored its would-block but stopped before its core.db commit
/// keeps that result when the bundle's head changes before the next retry, and counts it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_trial_retry_preserves_first_checked_head() {
    let s = Setup::new(None).await;
    manual_feed(&s.c, "f-new", json!({"category": "security"})).await;
    put_entity(
        &s.c,
        "bundles",
        "trial-new",
        json!({"id": "trial-new", "name": "trial-new", "feeds": [{"feed": "f-new"}]}),
    )
    .await;
    put_entity(
        &s.c,
        "profiles",
        "p1",
        json!({"id": "p1", "name": "p1", "block": ["b1"], "trial_bundles": ["trial-new"]}),
    )
    .await;
    s.without_head("trial-new").await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![s.q(
        "retry-first",
        1,
        now,
        "new.example",
        "allow",
        Value::Null,
    )])
    .await;
    s.drain().await;
    save(&s.c, "f-new", "||new.example^\n").await;
    build(&s.c, "trial-new").await.unwrap();
    // The pending row's transaction fails once, after the partition's result is written: the
    // same seam as a stop.
    s.c.state
        .db
        .write(|c| {
            c.execute_batch(
                "CREATE TRIGGER stop_pending BEFORE DELETE ON trial_pending BEGIN SELECT RAISE(FAIL, 'review stop'); END;",
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    assert!(picket_core::logs::trial::retry_pending(&s.c.state).await.is_err());
    assert_eq!(
        s.part::<i64>(
            now,
            "SELECT count(*) FROM would_blocks WHERE bundle_id = 'trial-new'"
        ),
        1
    );
    s.c.state
        .db
        .write(|c| {
            c.execute_batch("DROP TRIGGER stop_pending;")?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    // The hour backed off after its failure; its wait passes.
    s.c.state.analysis.end_backoffs();
    save(&s.c, "f-new", "||other.example^\n").await;
    build(&s.c, "trial-new").await.unwrap();
    picket_core::logs::trial::retry_pending(&s.c.state).await.unwrap();
    picket_core::metrics::outbox::flush(&s.c.state).await.unwrap();
    assert_eq!(
        s.metric_total("trial_would_block", "\"bundle\":\"trial-new\"")
            .await,
        1.0,
        "the retry reuses the stored result"
    );
    assert_eq!(
        s.scalar_core::<i64>("SELECT count(*) FROM trial_pending").await,
        0
    );
}

// S7 ------------------------------------------------------------------------------------------

/// A copy whose transaction rolls back gives back nothing it evicted: the budget never counts
/// less than what is stored (core.md §9 `alerts.evidence_total_mib`).
#[test]
fn evidence_budget_still_holds_after_an_eviction_is_rolled_back() {
    use picket_core::logs::{evidence::Capture, record::Rec};
    let mut db = core_db();
    for id in [1, 2] {
        db.execute(
            "INSERT INTO alerts(id, type, severity, kind, dedupe_key, title, details_json, first_seen, last_seen, count, state)
             VALUES (?1, 'security', 'warning', 'category_blocked', ?2, 'test', '{}', 't', 't', 1, 'open')",
            rusqlite::params![id, format!("a{id}")],
        )
        .unwrap();
        db.execute(
            "INSERT INTO alert_evidence_rules(alert_id, rule_json, created_at, domain) VALUES (?1, '{}', 't', 'x.example')",
            [id],
        )
        .unwrap();
    }
    let cap = Capture::default();
    let total = 20_000;
    let rec = |seq, padding: usize| Rec {
        edge: "e".into(),
        boot: "b".into(),
        seq,
        ts: format!("2026-11-24T00:00:0{seq}Z"),
        qname: "x.example".into(),
        client_ip: "192.0.2.1".into(),
        versions_json: "{}".into(),
        lookups_json: Some(
            serde_json::to_string(&json!(
                (0..4)
                    .map(|i| json!({"provider": format!("p{i}"), "verdict": "clean",
                                "detail": {"padding": "x".repeat(padding / 4)}}))
                    .collect::<Vec<_>>()
            ))
            .unwrap(),
        ),
        ..Rec::default()
    };
    for r in [rec(1, 0), rec(2, 10_000)] {
        let tx = db.transaction().unwrap();
        let c = cap.copy_in(&tx, 1, &r, 2, total).unwrap();
        assert!(c.copied);
        tx.commit().unwrap();
        cap.release(c.freed);
    }
    {
        // A failed transaction restores the large second copy it evicted.
        let tx = db.transaction().unwrap();
        let c = cap.copy_in(&tx, 1, &rec(3, 0), 2, total).unwrap();
        assert!(c.copied);
        assert!(c.freed > 10_000, "the large copy was evicted: {c:?}");
        tx.rollback().unwrap();
    }
    let stored = Capture::default().recount(&db).unwrap();
    assert!(
        cap.used() >= stored,
        "tracked {} < stored {stored} after a rollback",
        cap.used()
    );
    let tx = db.transaction().unwrap();
    let c = cap.copy_in(&tx, 2, &rec(4, 14_000), 2, total).unwrap();
    tx.commit().unwrap();
    cap.release(c.freed);
    let actual = Capture::default().recount(&db).unwrap();
    assert!(actual <= total, "stored {actual} > budget {total}");
}

// S11 -----------------------------------------------------------------------------------------

/// Moving the last cold feed back to hot is a tier change too: it waits for its dry run (or the
/// hold's end) like any other (bundles.md §2 Tiering).
#[test]
fn returning_all_feeds_to_hot_still_waits_for_its_tier_change_dry_run() {
    use picket_core::compiler::{
        spec::{Member, Spec},
        tier,
    };
    use picket_core::config::model::{BundleAction, Tier};
    let db = core_db();
    let now = Timestamp::now();
    let spec = Spec {
        id: "b".into(),
        action: BundleAction::Block,
        members: vec![Member {
            feed: "f".into(),
            position: 0,
            types: vec![picket_rules::RuleType::Dns],
            tier: Tier::Hot,
            downloaded: false,
            warn_on: vec![],
        }],
        max_shard_keys: 100_000,
        hot_max_mib: None,
        def_hash: "new-hot".into(),
    };
    let proposal = tier::proposed(&spec).to_string();
    let released = json!({"hot_max_mib": null, "tiers": {"f": "cold"}}).to_string();
    db.execute(
        "INSERT INTO tier_dry_runs(bundle_id, definition_hash, proposed_json, status, started_at, released_json)
         VALUES ('b', 'new-hot', ?1, 'running', ?2, ?3)",
        rusqlite::params![proposal, picket_core::util::ts(&now), released],
    )
    .unwrap();
    let (effective, release) = tier::effective_in(&db, &spec, now).unwrap();
    assert_eq!(
        effective.members[0].tier,
        Tier::Cold,
        "the old cold tier holds until the new hot proposal reports"
    );
    assert!(!release);
    // Once it reports, the all-hot split applies.
    db.execute("UPDATE tier_dry_runs SET status = 'done'", [])
        .unwrap();
    let (effective, release) = tier::effective_in(&db, &spec, now).unwrap();
    assert_eq!(effective.members[0].tier, Tier::Hot);
    assert!(release);
}

// S4 ------------------------------------------------------------------------------------------

/// A run whose additions match many answered records is matched in steps capped by work, its
/// matches aggregated (each counted once, none lost), never one hit per match held at once
/// (README §2 Bounded; core.md §6 retro-match).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retro_steps_are_capped_by_work_and_count_every_match() {
    let s = Setup::new(None).await;
    let then = Timestamp::now() - jiff::SignedDuration::from_mins(150);
    let recs: Vec<Value> = (0..40)
        .map(|i| {
            s.q(
                "b-w",
                i + 1,
                then,
                &format!("w{i}.wide.example"),
                "allow",
                Value::Null,
            )
        })
        .collect();
    s.post(recs).await;
    s.drain().await;
    analysis::drain_retro(&s.c.state).await.unwrap();
    // Thirty patterns each match every one of the forty names.
    let mut text = String::from("||ads.example^\n||tracker.example^\n||198.51.100.7^\n");
    for i in 0..30 {
        text.push_str(&format!("/wide{i}|wide\\.example$/\n"));
    }
    save(&s.c, "f-sec", &text).await;
    s.c.state
        .db
        .write(|c| Ok::<_, anyhow::Error>(picket_core::logs::retro::record_new_runs(c)?))
        .await
        .unwrap();
    s.c.state.analysis.set_retro_work(100);
    let mut steps_with_hits = 0;
    let mut total = 0;
    let mut most = 0;
    let hour = picket_core::logs::partition::hour_start(&then);
    for _ in 0..10_000 {
        let model = s.c.state.analysis.model(&s.c.state).await.unwrap();
        let out = picket_core::logs::retro::step(&s.c.state, hour, model)
            .await
            .unwrap();
        if out.hits > 0 {
            steps_with_hits += 1;
            most = most.max(out.hits);
        }
        total += out.hits;
        if !out.more {
            break;
        }
    }
    picket_core::metrics::outbox::flush(&s.c.state).await.unwrap();
    assert_eq!(total, 40 * 30, "every match counted once");
    assert_eq!(
        s.metric_total("retro_hits", "\"feed\":\"f-sec\"").await,
        (40 * 30) as f64
    );
    assert!(
        steps_with_hits > 1,
        "the work cap split the matching ({steps_with_hits} steps)"
    );
    assert!(most <= 100, "a step's matches stay within its work: {most}");
    assert_eq!(
        analysis::drain_retro(&s.c.state).await.unwrap(),
        0,
        "nothing left"
    );
    let key = picket_core::alerts::category_answered_key(
        picket_core::alerts::AnsweredBy::Feed("f-sec"),
        "w0.wide.example",
    );
    let a = s.alert(&key).await.expect("category_answered");
    assert_eq!(
        a["count"],
        40 * 30,
        "one key (the registrable domain), every match"
    );
    // C3 (core.md §9 record `edge?`): the edge whose records raised it.
    assert_eq!(a["edge"], serde_json::json!(s.edge.id), "{a}");
}

// S8 ------------------------------------------------------------------------------------------

/// A flush that read the outbox before a restore writes nothing into the restored metrics
/// (core.md §2: only the new state after a restore).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flush_cut_by_a_restore_writes_no_old_increments() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![s.block("b-1", 1, now, "ads.example", "ads.example")])
        .await;
    // The batch commits its effects and stops before moving its increments.
    s.c.state.analysis.fail_at(FailPoint::AnalysisAfterEffects);
    assert!(analysis::drain(&s.c.state).await.is_err());
    assert!(
        s.scalar_core::<i64>("SELECT count(*) FROM metric_outbox").await > 0,
        "the increments wait in the outbox"
    );
    let pause = s.c.state.analysis.pause_at(FailPoint::OutboxAfterRead);
    let st = s.c.state.clone();
    let flush = tokio::spawn(async move { picket_core::metrics::outbox::flush(&st).await });
    pause.reached.notified().await;
    let dir = s.c.state.data_dir.clone();
    let doc =
        s.c.state
            .db
            .read(move |c| picket_core::config::export::export(c, &dir))
            .await
            .unwrap();
    picket_core::config::export::restore(&s.c.state, doc, None)
        .await
        .unwrap();
    pause.resume.notify_one();
    flush.await.unwrap().unwrap();
    assert_eq!(
        s.metric_total("feed_hits", "").await,
        0.0,
        "no increment read before the restore reached the restored metrics"
    );
}

/// While metrics.db takes nothing, the outbox stays within its bounds: the oldest rows go and
/// are counted (README §2 Bounded).
#[test]
fn the_metric_outbox_is_bounded() {
    use picket_core::metrics::outbox::{MAX_ROWS, queue_in};
    let mut db = core_db();
    let item = |i: i64| {
        (
            "feed_hits".to_string(),
            picket_core::metrics::labels("", &[("feed", "f"), ("role", "decisive")]),
            i * 1000,
            1.0,
        )
    };
    for i in 0..MAX_ROWS + 50 {
        let tx = db.transaction().unwrap();
        queue_in(&tx, &[item(i)], &synced()).unwrap();
        tx.commit().unwrap();
    }
    let n: i64 = db
        .query_row("SELECT count(*) FROM metric_outbox", [], |r| r.get(0))
        .unwrap();
    assert!(n <= MAX_ROWS + 1, "{n} rows");
    let dropped: i64 = db
        .query_row(
            "SELECT count(*) FROM metric_outbox WHERE items_json LIKE '%metric_outbox%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(dropped >= 1, "the dropped rows are counted");
    // Rows older than the age bound go too.
    db.execute("UPDATE metric_outbox SET queued_at = 1", []).unwrap();
    let tx = db.transaction().unwrap();
    queue_in(&tx, &[item(1)], &synced()).unwrap();
    tx.commit().unwrap();
    let n: i64 = db
        .query_row("SELECT count(*) FROM metric_outbox", [], |r| r.get(0))
        .unwrap();
    assert!(n <= 3, "{n} rows after ageing");
}

// S9 ------------------------------------------------------------------------------------------

/// The retry of records awaiting a trial head reads the waiting rows through their `bundle`
/// index, from the bundles with a head, never by scanning them all.
#[test]
fn the_trial_retry_never_scans_the_waiting_rows() {
    let db = core_db();
    let plan: Vec<String> = {
        let mut st = db
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                picket_core::logs::trial::READY_SQL
            ))
            .unwrap();
        st.query_map(rusqlite::params![512, "[\"2026-01-01T00\"]"], |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
    };
    assert!(
        plan.iter()
            .any(|l| l.contains("trial_pending") && l.contains("INDEX")),
        "{plan:?}"
    );
    assert!(!plan.iter().any(|l| l.starts_with("SCAN p")), "{plan:?}");
}

// S10 -----------------------------------------------------------------------------------------

/// A restore keeps the split each bundle's builds last applied, so a restored bundle builds with
/// it until its next dry run reports (bundles.md §2 Tiering), and drops the rows of bundles it
/// doesn't restore.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_keeps_the_split_last_applied() {
    let s = Setup::new(None).await;
    // b1's own first build (and any dry run it waits for) must be done before the row below is
    // written, or its finishing job overwrites released_json (seen in a parallel root run).
    common::bundles::settle(&s.c, "b1").await;
    // The row below proposes another split than b1's definition, so a dry run is due once it is
    // restored; when that reports, b1's next build applies the definition's split. Held until
    // the restored value is read (seen under load in the 5d53a3f gate).
    s.c.state.compiler.set_dry_runs_paused(true);
    let released = json!({"hot_max_mib": null, "tiers": {"f-sec": "cold", "f-priv": "hot"}}).to_string();
    let r2 = released.clone();
    s.c.state
        .db
        .write(move |c| {
            for b in ["b1", "gone"] {
                c.execute(
                    "INSERT INTO tier_dry_runs(bundle_id, definition_hash, proposed_json, status, started_at, released_json)
                     VALUES (?1, 'h', ?2, 'done', '2026-11-24T00:00:00Z', ?2)",
                    rusqlite::params![b, r2],
                )?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let dir = s.c.state.data_dir.clone();
    let doc =
        s.c.state
            .db
            .read(move |c| picket_core::config::export::export(c, &dir))
            .await
            .unwrap();
    picket_core::config::export::restore(&s.c.state, doc, None)
        .await
        .unwrap();
    assert_eq!(
        s.scalar_core::<String>("SELECT released_json FROM tier_dry_runs WHERE bundle_id = 'b1'")
            .await,
        released
    );
    s.c.state.compiler.set_dry_runs_paused(false);
    picket_core::compiler::tier::submit_dry_runs(&s.c.state).await;
    assert_eq!(
        s.scalar_core::<i64>("SELECT count(*) FROM tier_dry_runs WHERE bundle_id = 'gone'")
            .await,
        0
    );
}

/// A tiering dry-run pause holds even when it is set while submit_dry_runs is suspended right
/// before registering a due proposal: nothing is registered, run or released after it (the
/// pause used to be checked only before that await).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dry_run_pause_set_mid_submission_holds() {
    let s = Setup::new(None).await;
    common::bundles::settle(&s.c, "b1").await;
    // b1's last dry run proposed another split than its definition: a dry run is due.
    let proposed = json!({"hot_max_mib": null, "tiers": {"f-sec": "cold", "f-priv": "hot"}}).to_string();
    let p2 = proposed.clone();
    s.c.state
        .db
        .write(move |c| {
            c.execute(
                "INSERT INTO tier_dry_runs(bundle_id, definition_hash, proposed_json, status, started_at, released_json)
                 VALUES ('b1', 'h', ?1, 'done', '2026-11-24T00:00:00Z', ?1)",
                rusqlite::params![p2],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let st = s.c.state.clone();
    s.c.state
        .compiler
        .pause_next_dry_run_register(Box::pin(async move { st.compiler.set_dry_runs_paused(true) }));
    picket_core::compiler::tier::submit_dry_runs(&s.c.state).await;
    assert!(s.c.state.compiler.dry_runs_paused(), "the hook ran");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let row =
        s.c.state
            .db
            .read(|c| {
                Ok::<_, anyhow::Error>(c.query_row(
                    "SELECT proposed_json, status, released_json FROM tier_dry_runs WHERE bundle_id = 'b1'",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    },
                )?)
            })
            .await
            .unwrap();
    assert_eq!(
        row,
        (proposed.clone(), "done".to_string(), proposed),
        "nothing registered, run or released"
    );
}

// S12 -----------------------------------------------------------------------------------------

/// A record whose retro-match keeps failing is skipped and counted after its attempts; the
/// hour's other records are matched (README §2: a bad item never stalls the receiver).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_failing_retro_match_is_skipped_after_its_attempts() {
    let s = Setup::new(None).await;
    let then = Timestamp::now() - jiff::SignedDuration::from_mins(150);
    s.post(vec![
        s.q("b-p", 1, then, "a.later.example", "allow", Value::Null),
        s.q("b-p", 2, then, "bad.later.example", "allow", Value::Null),
        s.q("b-p", 3, then, "c.later.example", "allow", Value::Null),
    ])
    .await;
    s.drain().await;
    analysis::drain_retro(&s.c.state).await.unwrap();
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n||later.example^\n",
    )
    .await;
    s.c.state.analysis.poison_in("retro", Some("bad.later.example"));
    let mut failures = 0;
    let mut hits = 0;
    for _ in 0..10 {
        match analysis::drain_retro(&s.c.state).await {
            Ok(n) => {
                hits += n;
                break;
            }
            Err(_) => failures += 1,
        }
    }
    assert_eq!(failures, picket_core::logs::analysis::MAX_ATTEMPTS as usize - 1);
    assert_eq!(hits, 2, "the other records are matched");
    assert_eq!(
        s.metric_total("analysis_skipped", "\"work\":\"retro\"").await,
        1.0
    );
}

/// A record whose effects keep failing inside the analysis transaction is skipped and counted
/// after its attempts; the batch's other records get theirs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_whose_effects_keep_failing_is_skipped() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![
        s.block("b-e", 1, now, "ads.example", "ads.example"),
        s.block("b-e", 2, now, "x.tracker.example", "tracker.example"),
    ])
    .await;
    s.c.state.analysis.poison_in("effects", Some("x.tracker.example"));
    let mut failures = 0;
    for _ in 0..10 {
        match analysis::drain(&s.c.state).await {
            Ok(_) => break,
            Err(_) => failures += 1,
        }
    }
    assert_eq!(failures, picket_core::logs::analysis::MAX_ATTEMPTS as usize - 1);
    let ads = picket_core::alerts::category_blocked_key("tablet", "ads.example");
    assert_eq!(s.alert(&ads).await.unwrap()["count"], 1, "counted once");
    let trk = picket_core::alerts::category_blocked_key("tablet", "x.tracker.example");
    assert!(
        s.alert(&trk).await.is_none(),
        "the failing record's effects are skipped"
    );
    assert_eq!(
        s.metric_total("analysis_skipped", "\"work\":\"analysis\"").await,
        1.0
    );
    assert_eq!(s.drain().await, 0, "the batch is done");
}
