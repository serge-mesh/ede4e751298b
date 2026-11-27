//! Log analysis, retro-match, trial checks, evidence and metrics after the final check of wave 5
//! part A: live evidence capture of a batch's records against rules raised later in the same batch
//! (core.md §9 Evidence), retro-match's value phase within its work cap (README §2 Bounded;
//! core.md §6), the metric outbox's byte and age caps on a small queue (core.md §10; README §2
//! Bounded) and the trial retry isolating failures per hour and per record (README §2 "a bad item
//! never stalls the receiver"; core.md §6 Trial would-block).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use common::logs::Setup;
use jiff::Timestamp;
use serde_json::Value;

// V1 ------------------------------------------------------------------------------------------

/// core.md §9 Evidence: "then each new one as it is ingested". Record 1 (allowed,
/// cdn.ads.example, tablet) and record 2 (blocked, ads.example, tablet) are analysed in one batch;
/// record 2 raises category_blocked:tablet:ads.example, whose rule {ads.example, tablet} record 1
/// matches. The rule's backfill covers only records at or below the progress when it was made
/// (before the batch), so record 1 has to come from the batch's live capture.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_raised_mid_batch_captures_the_batchs_earlier_records() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let allowed = s.q("b-v1", 1, now, "cdn.ads.example", "allow", Value::Null);
    s.post(vec![
        allowed,
        s.block("b-v1", 2, now, "ads.example", "ads.example"),
    ])
    .await;
    s.drain().await;
    let key = picket_core::alerts::category_blocked_key("tablet", "ads.example");
    let a = s.alert(&key).await.expect("raised");
    let id = a["id"].as_i64().unwrap();
    let g = s.c.state.restore.generation();
    picket_core::logs::evidence::run_backfill(&s.c.state, g, id)
        .await
        .unwrap();
    let copies = s
        .scalar_core::<i64>(&format!(
            "SELECT count(*) FROM alert_evidence WHERE alert_id = {id}"
        ))
        .await;
    assert_eq!(copies, 2, "both related records of the batch are copied");
    let names = s
        .scalar_core::<String>(&format!(
            "SELECT group_concat(key, ',') FROM (SELECT key FROM alert_evidence_counts
             WHERE alert_id = {id} AND kind = 'name' ORDER BY key)"
        ))
        .await;
    assert_eq!(names, "ads.example,cdn.ads.example", "both are counted per name");
    let clients = s
        .scalar_core::<i64>(&format!(
            "SELECT sum(count) FROM alert_evidence_counts WHERE alert_id = {id} AND kind = 'client'"
        ))
        .await;
    assert_eq!(clients, 2, "both are counted per client");
}

/// Every ingested record related to an alert is copied (core.md §9), one whose effects were
/// skipped too; a record whose capture keeps failing is skipped and counted after its attempts
/// (README §2), while its effects and the batch's other copies stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capture_is_isolated_per_record_and_takes_records_whose_effects_were_skipped() {
    use picket_core::logs::analysis::{self, MAX_ATTEMPTS};
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![
        s.block("b-v1i", 1, now, "ads.example", "ads.example"),
        s.block("b-v1i", 2, now, "x.ads.example", "ads.example"),
        s.block("b-v1i", 3, now, "y.ads.example", "ads.example"),
    ])
    .await;
    // Record 2's effects keep failing: skipped, but it is still an ingested record of the alert.
    s.c.state.analysis.poison_in("effects", Some("x.ads.example"));
    let mut failures = 0;
    for _ in 0..10 {
        match analysis::drain(&s.c.state).await {
            Ok(_) => break,
            Err(_) => failures += 1,
        }
    }
    assert_eq!(failures, MAX_ATTEMPTS as usize - 1);
    let key = picket_core::alerts::category_blocked_key("tablet", "ads.example");
    let id = s.alert(&key).await.expect("raised")["id"].as_i64().unwrap();
    let copied = |id: i64| {
        format!(
            "SELECT group_concat(q, ',') FROM (SELECT json_extract(record_json, '$.qname') AS q FROM alert_evidence WHERE alert_id = {id} ORDER BY q)"
        )
    };
    assert_eq!(
        s.scalar_core::<String>(&copied(id)).await,
        "ads.example,x.ads.example,y.ads.example",
        "the record whose effects were skipped is copied too"
    );
    // Record 5's capture keeps failing: skipped and counted; its effects (the alert's count) and
    // record 4's copy stay.
    s.c.state.analysis.poison_in("evidence", Some("z.ads.example"));
    s.post(vec![
        s.block("b-v1i", 4, now, "w.ads.example", "ads.example"),
        s.block("b-v1i", 5, now, "z.ads.example", "ads.example"),
    ])
    .await;
    let before = s.alert(&key).await.unwrap()["count"].as_i64().unwrap();
    let mut failures = 0;
    for _ in 0..10 {
        match analysis::drain(&s.c.state).await {
            Ok(_) => break,
            Err(_) => failures += 1,
        }
    }
    assert_eq!(failures, MAX_ATTEMPTS as usize - 1);
    assert_eq!(
        s.scalar_core::<String>(&copied(id)).await,
        "ads.example,w.ads.example,x.ads.example,y.ads.example",
        "record 4 is copied, record 5 is not"
    );
    assert_eq!(
        s.alert(&key).await.unwrap()["count"].as_i64().unwrap(),
        before + 2,
        "both records' effects are applied once"
    );
    assert_eq!(
        s.metric_total("analysis_skipped", "\"work\":\"evidence\"").await,
        1.0
    );
    assert_eq!(s.drain().await, 0, "the batch is done");
}

// V2 ------------------------------------------------------------------------------------------

/// Retro-match's steps are bounded by their work (README §2 Bounded; core.md §3 bounded steps),
/// counting every pattern probe, hit or miss: forty answered names, a run adding forty patterns
/// that match none of them and one that matches all. Each value costs 41 probes, so with a cap of
/// 50 a step of the value phase stops after two values (resuming after the second) and a step of
/// the record phase after two records; every match is still counted once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retro_steps_count_every_pattern_probe_in_both_phases() {
    let s = Setup::new(None).await;
    let then = Timestamp::now() - jiff::SignedDuration::from_mins(150);
    let recs: Vec<Value> = (0..40)
        .map(|i| {
            s.q(
                "b-v2",
                i + 1,
                then,
                &format!("w{i:02}.wide.example"),
                "allow",
                Value::Null,
            )
        })
        .collect();
    s.post(recs).await;
    s.drain().await;
    picket_core::logs::analysis::drain_retro(&s.c.state)
        .await
        .unwrap();
    let mut text = String::from("||ads.example^\n||tracker.example^\n||198.51.100.7^\n");
    for i in 0..40 {
        text.push_str(&format!("/nomatch{i}\\.example$/\n"));
    }
    text.push_str("/wide\\.example$/\n");
    common::bundles::save(&s.c, "f-sec", &text).await;
    s.c.state
        .db
        .write(|c| Ok::<_, anyhow::Error>(picket_core::logs::retro::record_new_runs(c)?))
        .await
        .unwrap();
    s.c.state.analysis.set_retro_work(50);
    let hour = picket_core::logs::partition::hour_start(&then);
    let (mut total, mut most_hits, mut most_values, mut values) = (0, 0, 0i64, 0i64);
    for _ in 0..10_000 {
        let model = s.c.state.analysis.model(&s.c.state).await.unwrap();
        let out = picket_core::logs::retro::step(&s.c.state, hour, model)
            .await
            .unwrap();
        let now = s.scalar_core::<i64>("SELECT count(*) FROM retro_values").await;
        most_values = most_values.max(now - values);
        values = now;
        most_hits = most_hits.max(out.hits);
        total += out.hits;
        if !out.more {
            break;
        }
    }
    assert!(
        most_values <= 2,
        "a value-phase step stays within its work: {most_values} values"
    );
    assert!(
        most_hits <= 2,
        "a record-phase step stays within its work: {most_hits} records"
    );
    assert_eq!(total, 40, "every match counted once");
    picket_core::metrics::outbox::flush(&s.c.state).await.unwrap();
    assert_eq!(s.metric_total("retro_hits", "\"feed\":\"f-sec\"").await, 40.0);
}

// V3 ------------------------------------------------------------------------------------------

/// A clock pinned synchronised or not (README §2 Clocks).
fn clock(synced: bool) -> picket_core::clock::Clock {
    let c = picket_core::clock::Clock::default();
    c.pin(synced);
    c
}

fn core_db() -> rusqlite::Connection {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    for schema in picket_core::db::schema::CORE {
        db.execute_batch(schema).unwrap();
    }
    db
}

/// The metric outbox keeps at most `MAX_BYTES` whatever its row count (README §2 Bounded): forty
/// batches of ordinary per-feed increments (10,240 series each, about 1.2 MB a row) while
/// `metrics.db` takes none.
#[test]
fn a_small_outbox_still_keeps_its_byte_cap() {
    use picket_core::metrics::outbox::{MAX_BYTES, queue_in};
    let mut db = core_db();
    let items: Vec<_> = (0..1024)
        .flat_map(|i| {
            (0..10).map(move |bin| {
                (
                    "feed_hits".to_string(),
                    picket_core::metrics::labels(
                        "",
                        &[("feed", &format!("feed-{i:057}")), ("role", "also_matched")],
                    ),
                    bin * 30_000,
                    1.0,
                )
            })
        })
        .collect();
    for _ in 0..40 {
        let tx = db.transaction().unwrap();
        queue_in(&tx, &items, &clock(true)).unwrap();
        tx.commit().unwrap();
    }
    let (n, bytes, dropped): (i64, i64, i64) = db
        .query_row(
            "SELECT count(*), sum(bytes), sum(items_json LIKE '%metric_outbox%') FROM metric_outbox",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(bytes <= MAX_BYTES, "{n} rows hold {bytes} bytes");
    assert!(n > 20, "the newest rows that fit stay: {n}");
    assert!(dropped >= 1, "the dropped rows are counted");
}

/// No row older than `MAX_AGE_MS` stays, on a quiet instance too (a two-row outbox).
#[test]
fn a_small_outbox_still_ages_its_rows() {
    use picket_core::metrics::outbox::queue_in;
    let mut db = core_db();
    let item = (
        "feed_hits".to_string(),
        picket_core::metrics::labels("", &[("feed", "f")]),
        1_000,
        1.0,
    );
    let tx = db.transaction().unwrap();
    queue_in(&tx, std::slice::from_ref(&item), &clock(true)).unwrap();
    tx.commit().unwrap();
    db.execute("UPDATE metric_outbox SET queued_at = 1", []).unwrap();
    let tx = db.transaction().unwrap();
    queue_in(&tx, &[item], &clock(true)).unwrap();
    tx.commit().unwrap();
    let old: i64 = db
        .query_row(
            "SELECT count(*) FROM metric_outbox WHERE queued_at = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old, 0, "a stale row ages out of a small outbox");
    let left: i64 = db
        .query_row("SELECT count(*) FROM metric_outbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 2, "the new row and the count of the dropped one");
}

// V4 ------------------------------------------------------------------------------------------

/// A setup whose profile p1 trials `trial-new` (feed f-new), which has no head yet
/// ([`Setup::without_head`]).
async fn trial_new_setup() -> Setup {
    use common::bundles::{manual_feed, put_entity};
    use serde_json::json;
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
    s
}

/// Gives `trial-new` its first head, blocking new.example.
async fn give_trial_new_a_head(s: &Setup) {
    common::bundles::save(&s.c, "f-new", "||new.example^\n").await;
    common::bundles::build(&s.c, "trial-new")
        .await
        .expect("trial-new head");
}

/// A partition that can't be opened fails only its own hour of the trial retry (README §2: a bad
/// item never stalls the receiver): the records waiting in later hours are checked and counted
/// (core.md §6 Trial would-block) in the same round, and the failing hour, backing off, keeps its
/// waiting rows for a later round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trial_retry_isolates_an_hour_that_cannot_be_opened() {
    let s = trial_new_setup().await;
    let early = Timestamp::now() - jiff::SignedDuration::from_hours(3);
    let late = Timestamp::now() - jiff::SignedDuration::from_hours(2);
    s.post(vec![
        s.q("b-v4h", 1, early, "new.example", "allow", Value::Null),
        s.q("b-v4h", 2, late, "new.example", "allow", Value::Null),
    ])
    .await;
    s.drain().await;
    assert_eq!(
        s.scalar_core::<i64>("SELECT count(*) FROM trial_pending").await,
        2
    );
    give_trial_new_a_head(&s).await;
    // The early hour's partition can't be opened any more (a directory where its file was).
    let file =
        s.c.dir
            .path()
            .join("logs")
            .join(picket_core::logs::partition::partition_file_name(&early));
    std::fs::remove_file(&file).unwrap();
    std::fs::create_dir(&file).unwrap();
    let round = picket_core::logs::trial::retry_pending(&s.c.state).await;
    assert!(round.is_err(), "the failing hour is reported");
    assert_eq!(
        s.part::<i64>(
            late,
            "SELECT count(*) FROM would_blocks WHERE bundle_id = 'trial-new'"
        ),
        1,
        "the later hour's record is checked in the same round"
    );
    picket_core::metrics::outbox::flush(&s.c.state).await.unwrap();
    assert_eq!(
        s.metric_total("trial_would_block", "\"bundle\":\"trial-new\"")
            .await,
        1.0
    );
    assert_eq!(
        s.scalar_core::<String>("SELECT group_concat(hour) FROM trial_pending")
            .await,
        picket_core::logs::partition::hour_key(&picket_core::logs::partition::hour_start(&early)),
        "the failing hour's record still waits"
    );
    // While it backs off, the next round leaves it out and succeeds.
    assert_eq!(
        picket_core::logs::trial::retry_pending(&s.c.state).await.unwrap(),
        0
    );
}

/// A record whose trial check keeps failing holds up neither its hour's other records nor later
/// rounds: it is retried, then after its attempts its waiting rows go, counted
/// (`analysis_skipped{work="trial_pending"}`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trial_retry_isolates_a_record_whose_check_keeps_failing() {
    use picket_core::logs::analysis::MAX_ATTEMPTS;
    let s = trial_new_setup().await;
    let at = Timestamp::now() - jiff::SignedDuration::from_mins(30);
    s.post(vec![
        s.q("b-v4r", 1, at, "bad.new.example", "allow", Value::Null),
        s.q("b-v4r", 2, at, "new.example", "allow", Value::Null),
    ])
    .await;
    s.drain().await;
    give_trial_new_a_head(&s).await;
    s.c.state.analysis.poison_in("trial", Some("bad.new.example"));
    let first = picket_core::logs::trial::retry_pending(&s.c.state).await.unwrap();
    assert_eq!(first, 1, "the other record is checked");
    assert_eq!(
        s.part::<i64>(
            at,
            "SELECT count(*) FROM would_blocks WHERE seq = 2 AND bundle_id = 'trial-new'"
        ),
        1
    );
    assert_eq!(
        s.scalar_core::<i64>("SELECT count(*) FROM trial_pending").await,
        1,
        "the failing record waits for its next attempt"
    );
    for _ in 1..MAX_ATTEMPTS {
        picket_core::logs::trial::retry_pending(&s.c.state).await.unwrap();
    }
    assert_eq!(
        s.scalar_core::<i64>("SELECT count(*) FROM trial_pending").await,
        0,
        "given up after its attempts"
    );
    picket_core::metrics::outbox::flush(&s.c.state).await.unwrap();
    assert_eq!(
        s.metric_total("analysis_skipped", "\"work\":\"trial_pending\"")
            .await,
        1.0
    );
    assert_eq!(
        s.metric_total("trial_would_block", "\"bundle\":\"trial-new\"")
            .await,
        1.0
    );
}

// Final check 2 ---------------------------------------------------------------------------------

/// core.md §9 Evidence ("each new one as it is ingested"); README §2 (a bad item is skipped after
/// its attempts): a record's capture has attempts of its own. Record 2's effects use all theirs
/// and are skipped; its capture then fails once (a transient failure), so the batch is tried
/// again and the record is copied, not skipped on that one failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capture_keeps_its_attempts_after_the_records_effects_used_theirs() {
    use picket_core::logs::analysis::{self, MAX_ATTEMPTS};
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![
        s.block("b-f4", 1, now, "ads.example", "ads.example"),
        s.block("b-f4", 2, now, "x.ads.example", "ads.example"),
    ])
    .await;
    s.c.state.analysis.poison_in("effects", Some("x.ads.example"));
    s.c.state.analysis.poison_also("evidence", "x.ads.example");
    let mut failures = 0;
    for _ in 0..MAX_ATTEMPTS {
        if analysis::drain(&s.c.state).await.is_err() {
            failures += 1;
        }
    }
    // The effects' attempts are used (the last skipped them), and the capture failed once.
    assert_eq!(failures, MAX_ATTEMPTS as usize);
    // The capture's failure was transient; the effects still fail (and stay skipped).
    s.c.state.analysis.poison_in("effects", Some("x.ads.example"));
    assert!(analysis::drain(&s.c.state).await.is_ok());
    let key = picket_core::alerts::category_blocked_key("tablet", "ads.example");
    let id = s.alert(&key).await.expect("raised")["id"].as_i64().unwrap();
    assert_eq!(
        s.scalar_core::<String>(&format!(
            "SELECT group_concat(q, ',') FROM (SELECT json_extract(record_json, '$.qname') AS q
             FROM alert_evidence WHERE alert_id = {id} ORDER BY q)"
        ))
        .await,
        "ads.example,x.ads.example",
        "the record whose effects were skipped is copied after its capture's one failure"
    );
    assert_eq!(
        s.metric_total("analysis_skipped", "\"work\":\"evidence\"").await,
        0.0,
        "no capture was skipped"
    );
    assert_eq!(s.drain().await, 0, "the batch is done");
}

/// README §2 Clocks ("decisions that need wall-clock time wait until it is synchronised"); core.md
/// §10, README §2 Bounded (the outbox's age bound): a row queued before the clock is synchronised
/// has no queue time, so a boot clock far behind never makes it look a week old once corrected;
/// its age counts from the first queue after the sync. While the clock isn't synchronised no row
/// ages out (its time can't be trusted); once it is, the age bound applies again.
#[test]
fn the_outbox_ages_rows_only_by_a_synchronised_clock() {
    use picket_core::metrics::outbox::{MAX_AGE_MS, queue_in};
    let mut db = core_db();
    let item = |feed: &str| {
        (
            "feed_hits".to_string(),
            picket_core::metrics::labels("", &[("feed", feed)]),
            1_000,
            1.0,
        )
    };
    let rows = |db: &rusqlite::Connection, like: &str| -> i64 {
        db.query_row(
            "SELECT count(*) FROM metric_outbox WHERE items_json LIKE ?1",
            [like],
            |r| r.get(0),
        )
        .unwrap()
    };
    let queue = |db: &mut rusqlite::Connection, feed: &str, synced: bool| {
        let tx = db.transaction().unwrap();
        queue_in(&tx, &[item(feed)], &clock(synced)).unwrap();
        tx.commit().unwrap();
    };
    // Queued at boot, the clock 30 days behind: the time it would have stamped is a month old by
    // the corrected clock.
    queue(&mut db, "boot", false);
    db.execute(
        "UPDATE metric_outbox SET queued_at = queued_at - 30 * 86400000 WHERE queued_at > 0",
        [],
    )
    .unwrap();
    // The clock is synchronised (corrected): the boot row stays, stamped now.
    queue(&mut db, "synced", true);
    assert_eq!(rows(&db, "%\"boot\"%"), 1, "the boot row stays");
    assert_eq!(rows(&db, "%metric_outbox%"), 0, "nothing was dropped");
    let unstamped: i64 = db
        .query_row(
            "SELECT count(*) FROM metric_outbox WHERE queued_at <= 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(unstamped, 0, "its age counts from the sync");
    // A row really past the age bound; then the clock loses its sync: nothing ages out until it
    // is synchronised again.
    db.execute(
        "UPDATE metric_outbox SET queued_at = queued_at - ?1 WHERE items_json LIKE '%\"boot\"%'",
        [MAX_AGE_MS + 60_000],
    )
    .unwrap();
    queue(&mut db, "unsynced", false);
    assert_eq!(
        rows(&db, "%\"boot\"%"),
        1,
        "no age bound without a synchronised clock"
    );
    queue(&mut db, "again", true);
    assert_eq!(rows(&db, "%\"boot\"%"), 0, "the age bound applies once it is");
    assert_eq!(rows(&db, "%metric_outbox%"), 1, "the dropped row is counted");
    assert_eq!(rows(&db, "%\"unsynced\"%"), 1, "the row queued meanwhile stays");
}
