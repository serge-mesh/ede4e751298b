//! Progress through the logs across restarts and failures (README §2 Restarts, Bounded,
//! Compatibility; build-and-test.md §5 "a restart mid-batch loses nothing and duplicates
//! nothing"; core.md §6 attribution, retro-match and trial bundles; storage.md §5 partitions of
//! older log schemas).
//!
//! Stops are made with the analysis's fail points, which cut a pass off where a crash would.

use crate::common;

use common::bundles::{build, manual_feed, put_entity, save};
use common::logs::Setup;
use jiff::Timestamp;
use picket_core::logs::analysis::{self, FailPoint};
use picket_core::logs::partition::{hour_key, hour_start, partition_file_name};
use serde_json::{Value, json};

/// The log schema of release N−1 (log schema version 2), as it created partitions.
const LOG_SCHEMA_V2: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    version_set INTEGER,
    listener TEXT,
    proto TEXT,
    client_ip TEXT,
    device TEXT,
    profile TEXT,
    qname TEXT,
    qtype TEXT,
    rcode TEXT,
    decision TEXT,
    step INTEGER,
    bundle TEXT,
    rule_key TEXT,
    match_kind TEXT,
    stage TEXT,
    block_id TEXT,
    answers_json TEXT,
    targets_json TEXT,
    truncated INTEGER NOT NULL DEFAULT 0,
    response BLOB,
    tc INTEGER NOT NULL DEFAULT 0,
    answer_id TEXT,
    received_at TEXT,
    age_s INTEGER,
    answer_missing INTEGER NOT NULL DEFAULT 0,
    wire_check TEXT,
    trial_check TEXT,
    client_do INTEGER,
    cname_json TEXT,
    lookups_json TEXT,
    cold_unchecked_json TEXT,
    upstream_json TEXT,
    fw_json TEXT,
    timings_json TEXT,
    reason_json TEXT,
    edns_json TEXT,
    PRIMARY KEY (edge_id, boot, seq)
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_qname ON events(qname);
CREATE INDEX IF NOT EXISTS events_client_ip ON events(client_ip);
CREATE INDEX IF NOT EXISTS events_device ON events(device);
CREATE INDEX IF NOT EXISTS events_decision ON events(decision);

CREATE TABLE IF NOT EXISTS answers (
    id TEXT PRIMARY KEY,
    wire BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS answered_names (
    qname TEXT NOT NULL,
    profile TEXT NOT NULL,
    PRIMARY KEY (qname, profile)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS answered_ips (
    ip TEXT NOT NULL,
    profile TEXT NOT NULL,
    PRIMARY KEY (ip, profile)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS attribution (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    matches_json TEXT,
    status TEXT NOT NULL,
    PRIMARY KEY (edge_id, boot, seq)
);

CREATE TABLE IF NOT EXISTS would_blocks (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    bundle_id TEXT NOT NULL,
    head_id TEXT NOT NULL,
    key TEXT,
    stage TEXT,
    matches_json TEXT,
    status TEXT,
    PRIMARY KEY (edge_id, boot, seq, bundle_id)
);
CREATE INDEX IF NOT EXISTS would_blocks_bundle ON would_blocks(bundle_id);

CREATE TABLE IF NOT EXISTS version_sets (
    id INTEGER PRIMARY KEY,
    blake3 TEXT NOT NULL UNIQUE,
    versions_json TEXT NOT NULL
);
"#;

async fn outbox_rows(s: &Setup) -> i64 {
    s.scalar_core::<i64>("SELECT count(*) FROM metric_outbox").await
}

/// A stop at each point of a batch (before its core.db effects, after them, and between the
/// metrics.db commit and the outbox's cleanup): every alert raise and metric increment counts
/// exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_mid_batch_repeats_and_loses_nothing() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![
        s.block("b-1", 1, now, "ads.example", "ads.example"),
        s.block("b-1", 2, now, "x.ads.example", "ads.example"),
    ])
    .await;
    let key = picket_core::alerts::category_blocked_key("tablet", "ads.example");
    let an = &s.c.state.analysis;

    // Cut off after the partition's results, before the effects: nothing counted yet.
    an.fail_at(FailPoint::AnalysisBeforeEffects);
    assert!(analysis::drain(&s.c.state).await.is_err());
    assert!(s.alert(&key).await.is_none());
    assert_eq!(s.metric_total("feed_hits", "\"feed\":\"f-sec\"").await, 0.0);
    assert_eq!(
        s.part::<i64>(now, "SELECT count(*) FROM attribution"),
        2,
        "the results are in (idempotent)"
    );

    // Cut off after the effects committed, before the metrics moved: the repeat finds the
    // batch done; the queued increments move once.
    an.fail_at(FailPoint::AnalysisAfterEffects);
    assert!(analysis::drain(&s.c.state).await.is_err());
    assert_eq!(s.alert(&key).await.unwrap()["count"], 2);
    assert!(outbox_rows(&s).await >= 1, "the increments wait in the outbox");

    // Cut off between metrics.db's commit and the outbox's cleanup.
    an.fail_at(FailPoint::OutboxAfterMetrics);
    assert!(analysis::drain(&s.c.state).await.is_err());
    let after_metrics = s.metric_total("feed_hits", "\"feed\":\"f-sec\"").await;
    assert_eq!(after_metrics, 2.0, "one f-sec hit per record");

    // The next pass: nothing repeated.
    assert_eq!(analysis::drain(&s.c.state).await.unwrap(), 0);
    assert_eq!(s.metric_total("feed_hits", "\"feed\":\"f-sec\"").await, 2.0);
    assert_eq!(outbox_rows(&s).await, 0);
    assert_eq!(s.alert(&key).await.unwrap()["count"], 2);
    assert_eq!(s.part::<i64>(now, "SELECT count(*) FROM attribution"), 2);
}

/// Retro-match in small steps (durable cursors, bounded pages): a stop before a step's
/// effects loses no `category_answered` raise or `retro_hits` increment and repeats none; the
/// step's matches raise their key once with their count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retro_match_steps_survive_a_stop_and_count_once() {
    let s = Setup::new(None).await;
    s.c.state.analysis.set_retro_steps(2, 2);
    let then = Timestamp::now() - jiff::SignedDuration::from_mins(150);
    let mut via_target = s.q("b-r", 3, then, "front.example", "allow", Value::Null);
    via_target["cname"] = json!(["edge.later.example"]);
    s.post(vec![
        s.q("b-r", 1, then, "later.example", "allow", Value::Null),
        s.q("b-r", 2, then, "a.later.example", "allow", Value::Null),
        via_target,
        s.q("b-r", 4, then, "b.later.example", "allow", Value::Null),
        s.q("b-r", 5, then, "other.example", "allow", Value::Null),
        s.q("b-r", 6, then, "c.later.example", "allow", Value::Null),
    ])
    .await;
    s.drain().await;
    // The hour closes in pages of two.
    analysis::drain_retro(&s.c.state).await.unwrap();
    let hk = hour_key(&then);
    assert_eq!(
        s.scalar_core::<i64>(&format!("SELECT closed FROM retro_progress WHERE hour = '{hk}'"))
            .await,
        1
    );
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n||later.example^\n",
    )
    .await;
    // A stop just before the first step whose matches would commit.
    s.c.state.analysis.fail_at(FailPoint::RetroBeforeEffects);
    let mut stopped = 0;
    let mut hits = 0;
    for _ in 0..4 {
        match analysis::drain_retro(&s.c.state).await {
            Ok(n) => {
                hits += n;
                break;
            }
            Err(_) => stopped += 1,
        }
    }
    assert_eq!(stopped, 1);
    assert_eq!(
        hits, 5,
        "every record under later.example, the CNAME front included"
    );
    let key = picket_core::alerts::category_answered_key(
        picket_core::alerts::AnsweredBy::Feed("f-sec"),
        "later.example",
    );
    let a = s.alert(&key).await.expect("category_answered");
    assert_eq!(a["count"], 5);
    assert_eq!(s.metric_total("retro_hits", "\"feed\":\"f-sec\"").await, 5.0);
    // The steps' raises were grouped: fewer history rows than matches.
    let raises: i64 = s
        .scalar_core(&format!(
            "SELECT count(*) FROM alert_history WHERE alert_id = {}",
            a["id"]
        ))
        .await;
    assert!(raises < 5, "{raises} raises for 5 matches");
    assert_eq!(analysis::drain_retro(&s.c.state).await.unwrap(), 0);
    assert_eq!(s.alert(&key).await.unwrap()["count"], 5);
    assert_eq!(
        s.scalar_core::<i64>("SELECT count(*) FROM retro_values").await,
        0,
        "the run's hit values go when it is done"
    );
}

/// A conditional pattern (`$dnstype=A`) added by a feed run counts for the records whose type
/// it matches, evaluated for each record (core.md §6 retro-match: "whose `$client`, `$ctag` or
/// `$dnstype`, if any, matches the record").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retro_match_evaluates_conditional_patterns_per_record() {
    let s = Setup::new(None).await;
    let then = Timestamp::now() - jiff::SignedDuration::from_mins(150);
    let mut aaaa = s.q("b-c", 2, then, "cond2.example", "allow", Value::Null);
    aaaa["qtype"] = json!("AAAA");
    s.post(vec![
        s.q("b-c", 1, then, "cond1.example", "allow", Value::Null),
        aaaa,
    ])
    .await;
    s.drain().await;
    analysis::drain_retro(&s.c.state).await.unwrap();
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n||cond*.example^$dnstype=A\n",
    )
    .await;
    let hits = analysis::drain_retro(&s.c.state).await.unwrap();
    assert_eq!(hits, 1, "the A query only");
    let key = picket_core::alerts::category_answered_key(
        picket_core::alerts::AnsweredBy::Feed("f-sec"),
        "cond1.example",
    );
    assert!(s.alert(&key).await.is_some());
}

/// Partitions an older release created (log schema 2, without this release's columns) are
/// analysed and retro-matched like new ones, including records appended to them after the
/// upgrade (README §2 Compatibility; storage.md §5: partitions are never migrated).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn older_partitions_are_analysed_and_retro_matched() {
    let s = Setup::new(None).await;
    let then = Timestamp::now() - jiff::SignedDuration::from_mins(150);
    // N−1 made the hour's partition.
    let dir = s.c.dir.path().join("logs");
    std::fs::create_dir_all(&dir).unwrap();
    {
        let c = rusqlite::Connection::open(dir.join(partition_file_name(&then))).unwrap();
        c.execute_batch(LOG_SCHEMA_V2).unwrap();
        c.pragma_update(None, "user_version", 2).unwrap();
    }
    s.post(vec![
        s.block("b-o", 1, then, "ads.example", "ads.example"),
        s.q("b-o", 2, then, "later.example", "allow", Value::Null),
    ])
    .await;
    assert_eq!(s.part::<i64>(then, "PRAGMA user_version"), 2, "never migrated");
    assert_eq!(s.drain().await, 2);
    assert_eq!(
        s.part::<String>(then, "SELECT status FROM attribution WHERE seq = 1"),
        "complete"
    );
    analysis::drain_retro(&s.c.state).await.unwrap();
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n||later.example^\n",
    )
    .await;
    assert_eq!(analysis::drain_retro(&s.c.state).await.unwrap(), 1);
    // A record appended to the old partition after the upgrade is analysed too.
    s.post(vec![s.block("b-o", 3, then, "www.ads.example", "ads.example")])
        .await;
    assert_eq!(s.drain().await, 1);
    assert_eq!(
        s.part::<i64>(then, "SELECT count(*) FROM attribution WHERE seq = 3"),
        1
    );
    let cold_check_columns: i64 = s.part(
        then,
        "SELECT count(*) FROM pragma_table_info('events') WHERE name = 'cold_check'",
    );
    assert_eq!(cold_check_columns, 0, "the partition keeps its schema");
}

/// A record whose analysis keeps failing is skipped and counted after its attempts, the records
/// after it go on, and another partition isn't held up meanwhile (README §2: a bad item never
/// stalls the receiver).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_poisoned_record_is_skipped_and_other_partitions_go_on() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let older = now - jiff::SignedDuration::from_hours(2);
    s.post(vec![
        s.block("b-p", 1, older, "ads.example", "ads.example"),
        s.block("b-p", 2, now, "ads.example", "ads.example"),
        s.q("b-p", 3, now, "poison.example", "allow", Value::Null),
        s.block("b-p", 4, now, "tracker.example", "tracker.example"),
    ])
    .await;
    let an = &s.c.state.analysis;
    an.poison_qname(Some("poison.example"));
    an.wake([hour_start(&now), hour_start(&older)]);
    analysis::batches(&s.c.state).await.unwrap();
    // The newer partition stopped at the poisoned record; the older one went on.
    assert_eq!(
        s.part::<i64>(older, "SELECT count(*) FROM attribution WHERE seq = 1"),
        1
    );
    assert_eq!(
        s.part::<i64>(now, "SELECT count(*) FROM attribution WHERE seq = 2"),
        1
    );
    assert_eq!(
        s.part::<i64>(now, "SELECT count(*) FROM attribution WHERE seq = 4"),
        0
    );
    // Its last attempt skips it; the record after it is analysed.
    for _ in 0..3 {
        if analysis::drain(&s.c.state).await.is_ok() {
            break;
        }
    }
    assert_eq!(
        s.part::<i64>(now, "SELECT count(*) FROM attribution WHERE seq = 4"),
        1
    );
    assert_eq!(
        s.metric_total("analysis_skipped", "\"work\":\"analysis\"").await,
        1.0
    );
    assert_eq!(analysis::drain(&s.c.state).await.unwrap(), 0);
}

/// Trial bundles: a host-IP mapping on the query name is a would-block (a REWRITE, core.md §6);
/// a trial bundle with no built head leaves the record waiting for it, and the record is
/// checked against it once it has one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trial_host_mappings_and_bundles_waiting_for_a_head() {
    let s = Setup::new(None).await;
    save(
        &s.c,
        "f-trial",
        "||trial.example^\n@@||ok.trial.example^\n||203.0.113.9^\n192.0.2.55 mapped.example\n",
    )
    .await;
    build(&s.c, "trial-b").await.expect("trial head");
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
    s.post(vec![
        s.q("b-t", 1, now, "mapped.example", "allow", Value::Null),
        s.q("b-t", 2, now, "new.example", "allow", Value::Null),
    ])
    .await;
    s.drain().await;
    assert_eq!(
        s.part::<String>(
            now,
            "SELECT stage FROM would_blocks WHERE seq = 1 AND bundle_id = 'trial-b'"
        ),
        "query",
        "a host mapping on the query name would block"
    );
    // trial-new has no head: both records wait for it.
    assert_eq!(
        s.scalar_core::<i64>("SELECT count(*) FROM trial_pending").await,
        2
    );
    assert!(
        s.part::<Option<String>>(now, "SELECT trial_check FROM events WHERE seq = 2")
            .is_none()
    );
    save(&s.c, "f-new", "||new.example^\n").await;
    build(&s.c, "trial-new").await.expect("trial-new head");
    picket_core::logs::trial::retry_pending(&s.c.state).await.unwrap();
    assert_eq!(
        s.part::<i64>(
            now,
            "SELECT count(*) FROM would_blocks WHERE seq = 2 AND bundle_id = 'trial-new'"
        ),
        1
    );
    assert!(
        s.part::<Option<String>>(now, "SELECT trial_check FROM events WHERE seq = 2")
            .is_some()
    );
    assert_eq!(
        s.scalar_core::<i64>("SELECT count(*) FROM trial_pending").await,
        0
    );
    picket_core::metrics::outbox::flush(&s.c.state).await.unwrap();
    assert_eq!(
        s.metric_total("trial_would_block", "\"bundle\":\"trial-new\"")
            .await,
        1.0
    );
}

/// README §2 Bounded: an idle core's analysis loop waits for a wake, a feed run or its tick. It
/// used to wake itself every turn (queuing the current hours through `wake`), so the next wait
/// returned at once and the loop spun on one CPU core.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_analysis_loop_waits() {
    let s = Setup::new(None).await;
    // The harness pauses the loop's batches; the spin happened on a running loop's turn.
    s.c.state.analysis.set_paused(false);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let before = s.c.state.analysis.turns();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let turns = s.c.state.analysis.turns() - before;
    // The tick is 15 s; a stray wake (a start-up event) may add one or two.
    assert!(turns <= 3, "{turns} turns in 3 s while idle");
}

/// README §2 Bounded: a turn that leaves work ready starts the next at once, but a paused loop
/// waits whatever the last turn left. It used to keep "ready" across paused turns and spin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paused_analysis_loop_waits_with_work_ready() {
    let s = Setup::new(None).await;
    let st = s.c.state.clone();
    // An increment in the outbox, so the turn's metrics flush stops at the pause point.
    let clock = st.clock.clone();
    st.db
        .write(move |c| {
            let tx = c.transaction()?;
            picket_core::metrics::outbox::queue_in(
                &tx,
                &[picket_core::dnssec::crosscheck::count("sinkhole", "dropped")],
                &clock,
            )?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let pause = st.analysis.pause_at(FailPoint::OutboxAfterRead);
    // More hours than one turn's batches (old hours, no partitions): the turn ends with work
    // ready, then flushes the metrics and stops there.
    let old = hour_start(&Timestamp::now()) - jiff::SignedDuration::from_hours(24 * 30);
    st.analysis
        .wake((0..40).map(|h| old - jiff::SignedDuration::from_hours(h)));
    st.analysis.set_paused(false);
    tokio::time::timeout(std::time::Duration::from_secs(30), pause.reached.notified())
        .await
        .expect("the turn reaches its metrics flush");
    st.analysis.set_paused(true);
    pause.resume.notify_one();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let before = st.analysis.turns();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let turns = st.analysis.turns() - before;
    // The tick is 15 s; a stray wake may add one or two.
    assert!(turns <= 3, "{turns} turns in 2 s while paused");
}
