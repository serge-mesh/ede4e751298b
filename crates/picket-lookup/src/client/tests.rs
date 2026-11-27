//! `LookupClient` tests (providers.md §4, edge.md §10, §13, core.md §7; build-and-test.md §5
//! "Lookup providers", "Verdict caches", "Lookup sharing"). Timing tests run on tokio's paused
//! clock, so they don't depend on the machine's speed.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Duration;

use anyhow::anyhow;
use jiff::{SignedDuration, Timestamp};
use picket_api::edge_config::{FailMode, LookupSettings};
use picket_api::logs::LookupVerdict;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::ram::{RamEntry, RamTier};
use super::*;
use crate::ctx::Connections;
use crate::module::{Answer, Expect, SelfTest, Verdict};
use crate::selftest::SelfTestResult;
use crate::testkit::{ManualClock, ScriptFuture, ScriptedModule};

const GEN: &str = "3f9a0c17d2e84b65";
const GEN2: &str = "b71e4d09a2c63f58";

fn t0() -> Timestamp {
    "2026-11-21T10:00:00Z".parse::<Timestamp>().unwrap()
}

fn block(reason: &str) -> Verdict {
    Verdict::Block {
        score: Some(9.0),
        reason: reason.into(),
    }
}

fn answer(v: Verdict) -> Result<Answer, LookupError> {
    Ok(Answer {
        verdict: v,
        detail: Some(json!({"from": "provider"})),
    })
}

/// A module driven by its config: `verdict` (`block`, `clean`, `unknown`), `mode` (`failed`,
/// `other`, `reject`, `panic`, `hang`, `echo_secret`, `big_detail`, `secret_detail`),
/// `delay_ms`, `retry_after_s`.
fn configurable() -> Arc<ScriptedModule> {
    ScriptedModule::new("scripted", |cfg: Value, _name, _n| -> ScriptFuture {
        Box::pin(async move {
            if let Some(ms) = cfg["delay_ms"].as_u64() {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            match cfg["mode"].as_str().unwrap_or("") {
                "failed" => Err(LookupError::Failed(anyhow!("upstream reset"))),
                "other" => Err(LookupError::Other(anyhow!("HTTP 403"))),
                "reject" => Err(LookupError::Rejected {
                    retry_after: cfg["retry_after_s"].as_u64().map(Duration::from_secs),
                }),
                "panic" => panic!("module bug"),
                "hang" => std::future::pending().await,
                "echo_secret" => Err(LookupError::Failed(anyhow!(
                    "GET https://x/?k={} failed",
                    cfg["token"].as_str().unwrap_or("")
                ))),
                "big_detail" => Ok(Answer {
                    verdict: Verdict::Clean,
                    detail: Some(json!({"x": "y".repeat(600)})),
                }),
                "secret_detail" => Ok(Answer {
                    verdict: Verdict::Clean,
                    detail: Some(json!({"echo": cfg["token"]})),
                }),
                _ => answer(match cfg["verdict"].as_str().unwrap_or("clean") {
                    "block" => block(cfg["reason"].as_str().unwrap_or("listed")),
                    "unknown" => Verdict::Unknown,
                    _ => Verdict::Clean,
                }),
            }
        })
    })
}

struct Fixture {
    client: LookupClient,
    module: Arc<ScriptedModule>,
    clock: Arc<ManualClock>,
    factory_calls: Arc<AtomicU64>,
}

fn spec(id: &str, cfg: Value, settings: LookupSettings) -> ProviderSpec {
    ProviderSpec {
        id: id.into(),
        module: "scripted".into(),
        config: cfg,
        generation: GEN.into(),
        settings,
    }
}

fn fixture_with(
    role: Role,
    module: Arc<ScriptedModule>,
    cfg: Value,
    settings: LookupSettings,
    secrets: &BTreeMap<String, String>,
) -> Fixture {
    let mut reg = Registry::empty();
    reg.insert(module.clone());
    let clock = ManualClock::new(t0());
    let factory_calls = Arc::new(AtomicU64::new(0));
    let fc = factory_calls.clone();
    let factory: ConnectionFactory = Arc::new(move |_: &str| {
        fc.fetch_add(1, AtomicOrdering::SeqCst);
        Connections::none()
    });
    let mut opts = ClientOptions::new(role, Arc::new(reg), factory);
    opts.clock = clock.clone();
    let client = LookupClient::new(spec("p1", cfg, settings), secrets, opts);
    Fixture {
        client,
        module,
        clock,
        factory_calls,
    }
}

fn fixture(cfg: Value) -> Fixture {
    fixture_with(
        Role::Edge,
        configurable(),
        cfg,
        LookupSettings::default(),
        &BTreeMap::new(),
    )
}

fn req(name: &str, budget: Duration) -> SyncRequest<'_> {
    SyncRequest {
        name,
        deadline: Instant::now() + budget,
        call: true,
        tag: None,
    }
}

async fn sync(c: &LookupClient, name: &str) -> SyncOutcome {
    c.lookup_sync(req(name, Duration::from_secs(5))).await
}

fn source(o: &SyncOutcome) -> Option<Source> {
    match &o.result {
        SyncResult::Verdict { source, .. } => Some(*source),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Name check, tiers, TTLs

#[tokio::test]
async fn name_check_unknown_without_call() {
    let f = fixture(json!({"verdict": "block"}));
    for name in ["a b.example", "x!.example", "", "a..b", "é.example"] {
        let o = sync(&f.client, name).await;
        assert_eq!(source(&o), Some(Source::NameCheck), "{name:?}");
        assert!(!o.retry());
        let item = o.log_item("p1").unwrap();
        assert_eq!(item.verdict, LookupVerdict::Unknown);
        assert!(item.obtained_at.is_none());
    }
    assert_eq!(f.module.calls(), 0);
    // Upper case and a trailing dot are normalised before the call.
    sync(&f.client, "Bad.Example.").await;
    assert_eq!(f.module.names.lock().unwrap()[0], "bad.example");
}

#[tokio::test]
async fn ram_tier_hit() {
    let f = fixture(json!({"verdict": "block", "reason": "phishing"}));
    let first = sync(&f.client, "bad.example").await;
    assert_eq!(source(&first), Some(Source::Call));
    let item = first.log_item("p1").unwrap();
    assert_eq!(item.verdict, LookupVerdict::Block);
    assert_eq!(item.reason.as_deref(), Some("phishing"));
    assert_eq!(item.score, Some(9.0));
    assert!(!item.cached);
    assert_eq!(item.generation, GEN);
    assert_eq!(item.obtained_at, Some(t0()));
    assert_eq!(item.detail, Some(json!({"from": "provider"})));

    f.clock.advance(Duration::from_secs(5));
    let second = sync(&f.client, "bad.example").await;
    assert_eq!(source(&second), Some(Source::Ram));
    let item = second.log_item("p1").unwrap();
    assert!(item.cached);
    assert_eq!(
        item.obtained_at,
        Some(t0()),
        "a hit carries the original obtained_at"
    );
    assert!(item.detail.is_none(), "the RAM tier keeps no detail");
    assert_eq!(f.module.calls(), 1);
    let m = f.client.metrics();
    assert_eq!((m.calls, m.cache_hits, m.cache_misses), (1, 1, 1));
    assert_eq!(m.entries, 1);
    assert!(m.bytes > 0);
    assert_eq!(m.call_ms.count, 1);
}

#[tokio::test]
async fn ttl_zero_stores_nothing() {
    let mut s = LookupSettings::default();
    s.cache.clean_ttl_s = 0;
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"verdict": "clean"}),
        s,
        &BTreeMap::new(),
    );
    for _ in 0..3 {
        sync(&f.client, "ok.example").await;
    }
    assert_eq!(f.module.calls(), 3);
    assert_eq!(f.client.metrics().entries, 0);
}

#[tokio::test(start_paused = true)]
async fn ttl_edits_apply_to_existing_entries_and_hits_dont_extend() {
    let f = fixture(json!({"verdict": "clean"}));
    sync(&f.client, "ok.example").await; // clean_ttl_s 21600
    tokio::time::advance(Duration::from_secs(100)).await;
    assert_eq!(source(&sync(&f.client, "ok.example").await), Some(Source::Ram));
    // Shorten the TTL below the entry's age: it expires at once.
    let mut s = LookupSettings::default();
    s.cache.clean_ttl_s = 50;
    f.client.update(
        spec("p1", json!({"verdict": "clean"}), s.clone()),
        &BTreeMap::new(),
    );
    assert_eq!(source(&sync(&f.client, "ok.example").await), Some(Source::Call));
    assert_eq!(f.module.calls(), 2);
    // Hits don't extend: at 40 s a hit, at 50 s expired.
    tokio::time::advance(Duration::from_secs(40)).await;
    assert_eq!(source(&sync(&f.client, "ok.example").await), Some(Source::Ram));
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(source(&sync(&f.client, "ok.example").await), Some(Source::Call));
    // Lengthening it also applies to the existing entry.
    s.cache.clean_ttl_s = 1000;
    f.client
        .update(spec("p1", json!({"verdict": "clean"}), s), &BTreeMap::new());
    tokio::time::advance(Duration::from_secs(900)).await;
    assert_eq!(source(&sync(&f.client, "ok.example").await), Some(Source::Ram));
}

#[tokio::test(start_paused = true)]
async fn ttl_capped_at_30_days() {
    let mut s = LookupSettings::default();
    s.cache.block_ttl_s = u32::MAX;
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"verdict": "block"}),
        s,
        &BTreeMap::new(),
    );
    sync(&f.client, "bad.example").await;
    tokio::time::advance(TTL_CAP - Duration::from_secs(1)).await;
    assert_eq!(source(&sync(&f.client, "bad.example").await), Some(Source::Ram));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(source(&sync(&f.client, "bad.example").await), Some(Source::Call));
}

// ---------------------------------------------------------------------------------------------
// Generations and flushes

#[tokio::test(start_paused = true)]
async fn generation_change_makes_misses() {
    let f = fixture(json!({"verdict": "block"}));
    sync(&f.client, "bad.example").await;
    let mut sp = spec("p1", json!({"verdict": "block"}), LookupSettings::default());
    sp.generation = GEN2.into();
    let eff = f.client.update(sp, &BTreeMap::new());
    assert!(eff.generation_changed && !eff.config_changed);
    let o = sync(&f.client, "bad.example").await;
    assert_eq!(source(&o), Some(Source::Call));
    assert_eq!(&*o.generation, GEN2);
    assert_eq!(f.module.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn result_of_old_generation_not_stored_or_logged_late() {
    let f = fixture(json!({"verdict": "block", "delay_ms": 200}));
    let (tx, mut rx) = mpsc::unbounded_channel();
    f.client.set_late_sink(Some(Arc::new(move |l| {
        let _ = tx.send(l);
    })));
    // Times out at 50 ms; the call goes on.
    let o = f
        .client
        .lookup_sync(req("bad.example", Duration::from_millis(50)))
        .await;
    assert_eq!(o.result, SyncResult::Timeout);
    assert_eq!(&*o.generation, GEN);
    // The generation moves on while the call is out.
    let mut sp = spec(
        "p1",
        json!({"verdict": "block", "delay_ms": 200}),
        LookupSettings::default(),
    );
    sp.generation = GEN2.into();
    f.client.update(sp, &BTreeMap::new());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        rx.try_recv().is_err(),
        "a late answer from an old generation isn't used"
    );
    assert_eq!(f.client.metrics().entries, 0, "nor stored");
}

#[tokio::test(start_paused = true)]
async fn flush_empties_ram_keeps_set_and_drops_inflight_result() {
    let f = fixture(json!({"verdict": "block", "delay_ms": 100}));
    sync(&f.client, "a.example").await;
    assert_eq!(f.client.metrics().entries, 1);
    let set = TestSet::new();
    set.put("a.example", StoredVerdict::Clean, t0(), GEN);
    f.client.set_verdict_set(Some(set.clone()));
    f.client.flush();
    assert_eq!(f.client.metrics().entries, 0);
    // The verdict set still answers.
    assert_eq!(source(&sync(&f.client, "a.example").await), Some(Source::Set));
    // A call in flight across a flush isn't stored.
    let c2 = f.client.clone();
    let h = tokio::spawn(async move { sync(&c2, "b.example").await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    f.client.flush();
    let o = h.await.unwrap();
    assert_eq!(source(&o), Some(Source::Call), "the caller still gets its answer");
    assert_eq!(f.client.metrics().entries, 0);
    assert_eq!(source(&sync(&f.client, "b.example").await), Some(Source::Call));
}

// ---------------------------------------------------------------------------------------------
// Verdict-set tier

struct TestSet {
    records: std::sync::Mutex<BTreeMap<String, SetRecord>>,
    fail: std::sync::atomic::AtomicBool,
    reads: AtomicU64,
}

impl TestSet {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            records: Default::default(),
            fail: Default::default(),
            reads: AtomicU64::new(0),
        })
    }

    fn put(&self, name: &str, verdict: StoredVerdict, obtained_at: Timestamp, generation: &str) {
        self.records.lock().unwrap().insert(
            name.into(),
            SetRecord {
                verdict,
                obtained_at,
                generation: generation.into(),
            },
        );
    }
}

#[async_trait::async_trait]
impl VerdictSet for TestSet {
    async fn get(&self, name: &str) -> anyhow::Result<Option<SetRecord>> {
        self.reads.fetch_add(1, AtomicOrdering::SeqCst);
        if self.fail.load(AtomicOrdering::SeqCst) {
            anyhow::bail!("page checksum mismatch");
        }
        Ok(self.records.lock().unwrap().get(name).cloned())
    }
}

#[tokio::test]
async fn ram_then_set_then_call() {
    let f = fixture(json!({"verdict": "clean"}));
    let set = TestSet::new();
    let stored_block = StoredVerdict::Block {
        score: None,
        reason: "set".into(),
    };
    set.put("bad.example", stored_block.clone(), t0(), GEN);
    f.client.set_verdict_set(Some(set.clone()));
    let o = sync(&f.client, "bad.example").await;
    assert_eq!(source(&o), Some(Source::Set));
    assert!(o.blocks(FailMode::Open));
    let item = o.log_item("p1").unwrap();
    assert!(item.cached);
    assert_eq!(item.reason.as_deref(), Some("set"));
    assert_eq!(f.module.calls(), 0);
    assert_eq!(f.client.metrics().set_hits, 1);

    // A live RAM entry wins over the set: the call's Clean is stored, then served from RAM.
    sync(&f.client, "other.example").await;
    set.put("other.example", stored_block.clone(), t0(), GEN);
    assert_eq!(source(&sync(&f.client, "other.example").await), Some(Source::Ram));

    // Another generation's record, an expired record and a failing read are misses.
    set.put("old.example", stored_block.clone(), t0(), GEN2);
    assert_eq!(source(&sync(&f.client, "old.example").await), Some(Source::Call));
    set.put(
        "stale.example",
        stored_block.clone(),
        t0() - SignedDuration::from_hours(24 * 2),
        GEN,
    );
    assert_eq!(
        source(&sync(&f.client, "stale.example").await),
        Some(Source::Call)
    );
    set.fail.store(true, AtomicOrdering::SeqCst);
    assert_eq!(source(&sync(&f.client, "fail.example").await), Some(Source::Call));
    // A record "from the future" is clamped to now (README §2).
    set.fail.store(false, AtomicOrdering::SeqCst);
    set.put(
        "future.example",
        stored_block,
        t0() + SignedDuration::from_hours(24 * 400),
        GEN,
    );
    match sync(&f.client, "future.example").await.result {
        SyncResult::Verdict { obtained_at, .. } => assert_eq!(obtained_at, Some(t0())),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn cached_error_stops_the_call_only_when_the_set_misses() {
    let f = fixture(json!({"mode": "failed"}));
    let set = TestSet::new();
    f.client.set_verdict_set(Some(set.clone()));
    let o = sync(&f.client, "x.example").await;
    assert!(matches!(
        o.result,
        SyncResult::Error {
            cached: false,
            kind: ErrorKind::Failed,
            ..
        }
    ));
    assert!(o.retry());
    assert_eq!(f.module.calls(), 1);
    // The error is cached for error_ttl_s (30 s): no call while it lives...
    let o = sync(&f.client, "x.example").await;
    assert!(matches!(o.result, SyncResult::Error { cached: true, .. }));
    assert!(o.log_item("p1").unwrap().cached);
    assert_eq!(f.module.calls(), 1);
    // ...but the set is still read, and its verdict wins.
    set.put("x.example", StoredVerdict::Clean, t0(), GEN);
    assert_eq!(source(&sync(&f.client, "x.example").await), Some(Source::Set));
    // After error_ttl_s the call is made again.
    set.records.lock().unwrap().clear();
    tokio::time::advance(Duration::from_secs(30)).await;
    sync(&f.client, "x.example").await;
    assert_eq!(f.module.calls(), 2);
}

#[tokio::test]
async fn core_role_has_no_ram_tier_and_no_error_cache() {
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"mode": "other"}),
        LookupSettings::default(),
        &BTreeMap::new(),
    );
    for _ in 0..3 {
        let o = f.client.lookup_async("x.example", AsyncOptions::default()).await;
        assert!(matches!(
            o.result,
            AsyncResult::Error {
                kind: ErrorKind::Other,
                timed_out: false,
                ..
            }
        ));
    }
    assert_eq!(f.module.calls(), 3);
    let m = f.client.metrics();
    assert_eq!((m.entries, m.bytes, m.errors), (0, 0, 3));
}

#[tokio::test]
async fn cache_only_lookups_never_call() {
    let f = fixture(json!({"verdict": "block"}));
    let r = SyncRequest {
        call: false,
        ..req("bad.example", Duration::from_secs(1))
    };
    let o = f.client.lookup_sync(r.clone()).await;
    assert_eq!(o.result, SyncResult::Miss);
    assert!(o.log_item("p1").is_none());
    assert!(!o.blocks(FailMode::Closed));
    sync(&f.client, "bad.example").await;
    let o = f.client.lookup_sync(r).await;
    assert_eq!(source(&o), Some(Source::Ram));
    assert!(o.blocks(FailMode::Open));
    assert_eq!(f.module.calls(), 1);
    // Only a live Block decides a cache-only lookup: a cached Unknown or error never applies
    // the fail mode to a query type that doesn't call the provider.
    for (cfg, name) in [
        (json!({"verdict": "unknown"}), "u.example"),
        (json!({"mode": "failed"}), "e.example"),
    ] {
        let f = fixture(cfg);
        let first = sync(&f.client, name).await;
        assert!(first.blocks(FailMode::Closed));
        let o = f
            .client
            .lookup_sync(SyncRequest {
                call: false,
                ..req(name, Duration::from_secs(1))
            })
            .await;
        assert_eq!(o.result, SyncResult::Miss, "{name}");
        assert!(!o.blocks(FailMode::Closed));
    }
}

// ---------------------------------------------------------------------------------------------
// Single-flight, timeouts, late answers

#[tokio::test(start_paused = true)]
async fn single_flight_per_name() {
    let f = fixture(json!({"verdict": "block", "delay_ms": 100}));
    let mut handles = Vec::new();
    for _ in 0..10 {
        let c = f.client.clone();
        handles.push(tokio::spawn(async move { sync(&c, "bad.example").await }));
    }
    let mut sources = Vec::new();
    for h in handles {
        sources.push(source(&h.await.unwrap()).unwrap());
    }
    assert_eq!(f.module.calls(), 1);
    assert_eq!(sources.iter().filter(|s| **s == Source::Call).count(), 1);
    assert_eq!(sources.iter().filter(|s| **s == Source::Joined).count(), 9);
    assert_eq!(f.client.metrics().calls, 1);
}

#[tokio::test(start_paused = true)]
async fn timeout_then_late_answer_logged_and_stored() {
    let f = fixture(json!({"verdict": "block", "reason": "late", "delay_ms": 400}));
    let (tx, mut rx) = mpsc::unbounded_channel();
    f.client.set_late_sink(Some(Arc::new(move |l| {
        let _ = tx.send(l);
    })));
    let start = Instant::now();
    let deadline = f.client.sync_deadline(start, 100); // min(150, 100)
    assert_eq!(deadline, start + Duration::from_millis(100));
    let mk = |tag: &str| SyncRequest {
        name: "slow.example",
        deadline,
        call: true,
        tag: Some(tag.into()),
    };
    let (a, b, c) = tokio::join!(
        f.client.lookup_sync(mk("kids")),
        f.client.lookup_sync(mk("adults")),
        f.client.lookup_sync(mk("kids")),
    );
    for o in [&a, &b, &c] {
        assert_eq!(o.result, SyncResult::Timeout);
        assert!(o.retry());
        assert!(o.blocks(FailMode::Closed) && !o.blocks(FailMode::Open));
        let item = o.log_item("p1").unwrap();
        assert!(item.timed_out && item.retry);
        assert_eq!(item.verdict, LookupVerdict::Timeout);
        assert!(item.obtained_at.is_none());
    }
    assert!(Instant::now() - start < Duration::from_millis(150));
    let late = rx.recv().await.unwrap();
    assert_eq!(&*late.name, "slow.example");
    assert_eq!(&*late.provider, "p1");
    assert_eq!(&*late.generation, GEN);
    assert_eq!(late.tags.len(), 2, "distinct tags");
    assert!(late.ms >= 400);
    let rec = late.to_record(
        picket_api::logs::RecordHeader {
            ts: t0(),
            boot: "7f3a91".into(),
            seq: 1052,
        },
        Some("kids".into()),
    );
    assert_eq!(rec.verdict, LookupVerdict::Block);
    assert_eq!(rec.reason.as_deref(), Some("late"));
    assert_eq!(rec.qname, "slow.example");
    assert!(rec.detail.is_some());
    assert!(rx.try_recv().is_err(), "one late answer per call");
    // It went into the RAM tier.
    assert_eq!(source(&sync(&f.client, "slow.example").await), Some(Source::Ram));
    let m = f.client.metrics();
    assert_eq!((m.timeouts, m.late, m.calls), (3, 1, 1));
    assert!(m.call_ms.sum >= 400, "call_ms counts the late call's duration");
}

#[tokio::test(start_paused = true)]
async fn call_ends_at_async_timeout_and_its_error_is_cached() {
    let s = LookupSettings {
        async_timeout_ms: 1000,
        ..LookupSettings::default()
    };
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"mode": "hang"}),
        s,
        &BTreeMap::new(),
    );
    let (tx, mut rx) = mpsc::unbounded_channel::<LateAnswer>();
    f.client.set_late_sink(Some(Arc::new(move |l| {
        let _ = tx.send(l);
    })));
    let o = f
        .client
        .lookup_sync(req("x.example", Duration::from_millis(150)))
        .await;
    assert_eq!(o.result, SyncResult::Timeout);
    assert_eq!(f.client.inflight(), 1);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(f.client.inflight(), 0, "the call ended at async_timeout_ms");
    assert!(rx.try_recv().is_err(), "no late answer from a failed call");
    let o = sync(&f.client, "x.example").await;
    assert!(matches!(o.result, SyncResult::Error { cached: true, .. }));
    let m = f.client.metrics();
    assert_eq!((m.errors, m.late, m.timeouts), (1, 0, 1));
}

// ---------------------------------------------------------------------------------------------
// Breaker, pause, limits

#[tokio::test(start_paused = true)]
async fn breaker_counts_failed_only() {
    let s = no_cache();
    let module = ScriptedModule::new("scripted", |cfg, name, _| -> ScriptFuture {
        Box::pin(async move {
            let _ = cfg;
            if name.starts_with("other") {
                Err(LookupError::Other(anyhow!("HTTP 418")))
            } else if name.starts_with("reject") {
                Err(LookupError::Rejected { retry_after: None })
            } else if name.starts_with("ok") {
                answer(Verdict::Clean)
            } else {
                Err(LookupError::Failed(anyhow!("HTTP 503")))
            }
        })
    });
    let f = fixture_with(Role::Edge, module, json!({}), s, &BTreeMap::new());
    for i in 0..10 {
        sync(&f.client, &format!("other{i}.example")).await;
    }
    assert_eq!(f.client.metrics().breaker_open, 0, "Other doesn't count");
    for i in 0..4 {
        sync(&f.client, &format!("fail{i}.example")).await;
    }
    assert_eq!(f.client.metrics().breaker_open, 0);
    sync(&f.client, "fail4.example").await;
    assert_eq!(f.client.metrics().breaker_open, 1);
    let o = sync(&f.client, "ok1.example").await;
    assert_eq!(o.result, SyncResult::BreakerOpen);
    assert!(o.retry() && o.blocks(FailMode::Closed));
    assert_eq!(o.log_item("p1").unwrap().verdict, LookupVerdict::Error);
    // Core's async lookups get the time to wait until.
    match f
        .client
        .lookup_async("ok1.example", AsyncOptions::default())
        .await
        .result
    {
        AsyncResult::BreakerOpen { until } => assert!(until > Instant::now()),
        other => panic!("{other:?}"),
    }
    // After open_s: half-open trials; two answers close it.
    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(f.client.metrics().breaker_open, 0);
    assert_eq!(source(&sync(&f.client, "ok2.example").await), Some(Source::Call));
    assert_eq!(source(&sync(&f.client, "ok3.example").await), Some(Source::Call));
    assert_eq!(source(&sync(&f.client, "ok4.example").await), Some(Source::Call));
    // Rejections never count toward the breaker (each starts a pause; let them lapse).
    for i in 0..6 {
        sync(&f.client, &format!("reject{i}.example")).await;
        tokio::time::advance(Duration::from_secs(4000)).await;
    }
    assert_eq!(f.client.metrics().breaker_open, 0);
}

fn no_cache() -> LookupSettings {
    let mut s = LookupSettings::default();
    s.cache.block_ttl_s = 0;
    s.cache.clean_ttl_s = 0;
    s.cache.unknown_ttl_s = 0;
    s.cache.error_ttl_s = 0;
    s
}

#[tokio::test(start_paused = true)]
async fn rejection_pauses_the_provider_then_one_probe() {
    let rejecting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r2 = rejecting.clone();
    let module = ScriptedModule::new("scripted", move |_, _, _| -> ScriptFuture {
        let reject = r2.load(AtomicOrdering::SeqCst);
        Box::pin(async move {
            if reject {
                Err(LookupError::Rejected {
                    retry_after: Some(Duration::from_secs(10)),
                })
            } else {
                answer(Verdict::Clean)
            }
        })
    });
    let f = fixture_with(Role::Edge, module, json!({}), no_cache(), &BTreeMap::new());
    assert_eq!(f.client.paused_until(), None);
    let o = sync(&f.client, "a.example").await;
    assert_eq!(o.result, SyncResult::Rejected { paused: false });
    // The pause is readable without a lookup (core's `lookup_provider_down`).
    let until = f.client.paused_until().expect("paused after a rejection");
    assert!(until > Instant::now() && until <= Instant::now() + Duration::from_secs(12));
    let item = o.log_item("p1").unwrap();
    assert_eq!(item.verdict, LookupVerdict::Rejected);
    assert_eq!(item.rejected, Some(true));
    assert!(item.retry);
    // Paused: the fail mode applies at once, without a call, logged as rejected.
    let o = sync(&f.client, "b.example").await;
    assert_eq!(o.result, SyncResult::Rejected { paused: true });
    assert!(o.blocks(FailMode::Closed) && !o.blocks(FailMode::Open));
    assert_eq!(f.module.calls(), 1);
    match f
        .client
        .lookup_async("b.example", AsyncOptions::default())
        .await
        .result
    {
        AsyncResult::Paused { until } => assert!(until > Instant::now()),
        other => panic!("{other:?}"),
    }
    // After retry_after (± 20 %), one call goes through; another rejection starts a new pause.
    tokio::time::advance(Duration::from_secs(13)).await;
    assert_eq!(
        sync(&f.client, "c.example").await.result,
        SyncResult::Rejected { paused: false }
    );
    assert_eq!(f.module.calls(), 2);
    assert_eq!(
        sync(&f.client, "d.example").await.result,
        SyncResult::Rejected { paused: true }
    );
    // An answer to the probe ends the pause.
    rejecting.store(false, AtomicOrdering::SeqCst);
    tokio::time::advance(Duration::from_secs(13)).await;
    assert_eq!(source(&sync(&f.client, "e.example").await), Some(Source::Call));
    assert_eq!(f.client.paused_until(), None);
    assert_eq!(source(&sync(&f.client, "f.example").await), Some(Source::Call));
    let m = f.client.metrics();
    assert_eq!((m.rejected, m.paused, m.breaker_open), (2, 3, 0));
}

#[tokio::test(start_paused = true)]
async fn limits_exhausted_apply_the_fail_mode() {
    let mut s = no_cache();
    s.limits.max_inflight = 1;
    s.limits.rps = 1;
    s.limits.burst = 2;
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"verdict": "clean", "delay_ms": 500}),
        s,
        &BTreeMap::new(),
    );
    let c = f.client.clone();
    let slow = tokio::spawn(async move { sync(&c, "a.example").await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    // max_inflight reached.
    let o = sync(&f.client, "b.example").await;
    assert_eq!(o.result, SyncResult::LimitsExhausted);
    assert!(o.blocks(FailMode::Closed) && o.retry());
    // Joining the call in flight needs no slot.
    assert_eq!(source(&sync(&f.client, "a.example").await), Some(Source::Joined));
    slow.await.unwrap();
    let mut s = no_cache();
    s.limits.max_inflight = 1;
    s.limits.rps = 1;
    s.limits.burst = 2;
    f.client
        .update(spec("p1", json!({"verdict": "clean"}), s), &BTreeMap::new());
    // Burst of 2, refilled by 0.5 while `a` ran: one token left, then empty.
    sync(&f.client, "c.example").await;
    assert_eq!(
        sync(&f.client, "d.example").await.result,
        SyncResult::LimitsExhausted
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(source(&sync(&f.client, "d.example").await), Some(Source::Call));
}

#[tokio::test(start_paused = true)]
async fn async_lookups_wait_for_tokens() {
    let mut s = no_cache();
    s.limits.rps = 10;
    s.limits.burst = 1;
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"verdict": "block"}),
        s,
        &BTreeMap::new(),
    );
    let start = Instant::now();
    for i in 0..3 {
        let o = f
            .client
            .lookup_async(&format!("n{i}.example"), AsyncOptions::default())
            .await;
        assert!(
            matches!(o.result, AsyncResult::Answer { storable: true, .. }),
            "{o:?}"
        );
    }
    // The bucket paced the second and third call by 100 ms each.
    assert!(Instant::now() - start >= Duration::from_millis(200));
    assert_eq!(f.module.calls(), 3);
}

// ---------------------------------------------------------------------------------------------
// Two lookup providers from one module

/// build-and-test.md §5 "Lookup providers": two lookup providers from one module, with
/// different configs and independent caches, breakers and metrics.
#[tokio::test(start_paused = true)]
async fn two_providers_from_one_module() {
    let module = configurable();
    let mut reg = Registry::empty();
    reg.insert(module.clone());
    let reg = Arc::new(reg);
    let make = |id: &str, cfg: Value| {
        LookupClient::new(
            spec(id, cfg, LookupSettings::default()),
            &BTreeMap::new(),
            ClientOptions::new(Role::Edge, reg.clone(), Arc::new(|_: &str| Connections::none())),
        )
    };
    let strict = make("strict", json!({"verdict": "block", "reason": "strict-list"}));
    let lenient = make("lenient", json!({"verdict": "clean"}));
    let s = sync(&strict, "x.example").await;
    let l = sync(&lenient, "x.example").await;
    assert!(s.blocks(FailMode::Open));
    assert!(!l.blocks(FailMode::Open));
    assert_eq!(strict.id(), "strict");
    assert_eq!(s.log_item(strict.id()).unwrap().provider, "strict");
    // Independent caches.
    assert_eq!(source(&sync(&strict, "x.example").await), Some(Source::Ram));
    lenient.flush();
    assert_eq!(source(&sync(&strict, "x.example").await), Some(Source::Ram));
    assert_eq!(source(&sync(&lenient, "x.example").await), Some(Source::Call));
    // Independent breakers: break `strict` only.
    let mut broken = spec("strict", json!({"mode": "failed"}), no_cache());
    broken.generation = GEN2.into();
    strict.update(broken, &BTreeMap::new());
    for i in 0..5 {
        sync(&strict, &format!("f{i}.example")).await;
    }
    assert_eq!(strict.metrics().breaker_open, 1);
    assert_eq!(lenient.metrics().breaker_open, 0);
    assert_eq!(source(&sync(&lenient, "y.example").await), Some(Source::Call));
    assert_eq!(strict.metrics().calls, 6);
    assert_eq!(lenient.metrics().calls, 3);
}

// ---------------------------------------------------------------------------------------------
// In-place updates, connections, secrets, modules

#[tokio::test(start_paused = true)]
async fn settings_update_keeps_state_and_connections() {
    let f = fixture(json!({"mode": "failed"}));
    assert_eq!(f.factory_calls.load(AtomicOrdering::SeqCst), 1);
    for i in 0..5 {
        sync(&f.client, &format!("f{i}.example")).await;
    }
    assert_eq!(f.client.metrics().breaker_open, 1);
    let mut s = LookupSettings {
        sync_timeout_ms: 300,
        ..LookupSettings::default()
    };
    s.cache.max_mib = 4;
    let eff = f
        .client
        .update(spec("p1", json!({"mode": "failed"}), s), &BTreeMap::new());
    assert_eq!(eff, UpdateEffect::default());
    assert_eq!(
        f.client.metrics().breaker_open,
        1,
        "the breaker survives a settings edit"
    );
    assert_eq!(
        f.client.metrics().entries,
        5,
        "so does the RAM tier (cached errors)"
    );
    assert_eq!(f.client.settings().sync_timeout_ms, 300);
    assert_eq!(
        f.factory_calls.load(AtomicOrdering::SeqCst),
        1,
        "same connections"
    );
    // A config change replaces the connections, keeping the cache (same generation).
    let eff = f.client.update(
        spec("p1", json!({"verdict": "clean"}), LookupSettings::default()),
        &BTreeMap::new(),
    );
    assert!(eff.config_changed && !eff.generation_changed);
    assert_eq!(f.factory_calls.load(AtomicOrdering::SeqCst), 2);
    assert_eq!(f.client.metrics().entries, 5);
}

#[tokio::test]
async fn secrets_resolved_redacted_and_missing() {
    let secrets = BTreeMap::from([("tok".to_owned(), "hunter2-secret".to_owned())]);
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"mode": "echo_secret", "token": "${secret:tok}"}),
        no_cache(),
        &secrets,
    );
    match sync(&f.client, "x.example").await.result {
        SyncResult::Error { message, .. } => {
            assert!(!message.contains("hunter2"), "{message}");
            assert!(message.contains("${secret:tok}"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    // A detail holding a secret value is dropped.
    f.client.update(
        spec(
            "p1",
            json!({"mode": "secret_detail", "token": "${secret:tok}"}),
            no_cache(),
        ),
        &secrets,
    );
    match sync(&f.client, "x.example").await.result {
        SyncResult::Verdict { detail, .. } => assert!(detail.is_none()),
        other => panic!("{other:?}"),
    }
    // A missing secret: no call, an Other error naming the secret.
    let calls = f.module.calls();
    f.client.update(
        spec(
            "p1",
            json!({"mode": "secret_detail", "token": "${secret:gone}"}),
            no_cache(),
        ),
        &secrets,
    );
    match sync(&f.client, "x.example").await.result {
        SyncResult::Error {
            kind: ErrorKind::Other,
            message,
            ..
        } => {
            assert!(message.contains("gone"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(f.module.calls(), calls);
    // A new secret value keeps the cached verdicts and resolves anew.
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"verdict": "block", "token": "${secret:tok}"}),
        LookupSettings::default(),
        &secrets,
    );
    sync(&f.client, "x.example").await;
    let new_secrets = BTreeMap::from([("tok".to_owned(), "rotated".to_owned())]);
    let eff = f.client.update(
        spec(
            "p1",
            json!({"verdict": "block", "token": "${secret:tok}"}),
            LookupSettings::default(),
        ),
        &new_secrets,
    );
    assert_eq!(eff, UpdateEffect::default());
    assert_eq!(source(&sync(&f.client, "x.example").await), Some(Source::Ram));
}

#[tokio::test]
async fn oversized_detail_dropped() {
    let f = fixture(json!({"mode": "big_detail"}));
    match sync(&f.client, "x.example").await.result {
        SyncResult::Verdict { detail, verdict, .. } => {
            assert!(detail.is_none());
            assert_eq!(verdict, StoredVerdict::Clean);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn unknown_module_and_panics_are_other_errors() {
    let mut sp = spec("p1", json!({}), no_cache());
    sp.module = "nope".into();
    let c = LookupClient::new(
        sp,
        &BTreeMap::new(),
        ClientOptions::new(
            Role::Edge,
            Arc::new(Registry::empty()),
            Arc::new(|_: &str| Connections::none()),
        ),
    );
    match sync(&c, "x.example").await.result {
        SyncResult::Error {
            kind: ErrorKind::Other,
            message,
            ..
        } => {
            assert!(message.contains("unknown lookup module"))
        }
        other => panic!("{other:?}"),
    }
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"mode": "panic"}),
        no_cache(),
        &BTreeMap::new(),
    );
    match sync(&f.client, "x.example").await.result {
        SyncResult::Error {
            kind: ErrorKind::Other,
            message,
            ..
        } => {
            assert!(message.contains("panicked"))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(f.client.inflight(), 0);
    assert_eq!(f.client.metrics().breaker_open, 0);
}

#[tokio::test(start_paused = true)]
async fn dropping_the_client_cancels_its_calls() {
    let f = fixture(json!({"mode": "hang"}));
    let c = f.client.clone();
    let _ = c.lookup_sync(req("x.example", Duration::from_millis(10))).await;
    assert_eq!(f.client.inflight(), 1);
    let module = f.module.clone();
    drop(c);
    drop(f);
    tokio::time::sleep(Duration::from_millis(10)).await;
    // The module future was dropped: only the test's handle keeps it alive.
    assert_eq!(Arc::strong_count(&module), 1);
}

// ---------------------------------------------------------------------------------------------
// Async (core)

#[tokio::test(start_paused = true)]
async fn async_answers_storable_unless_generation_moved() {
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"verdict": "block", "delay_ms": 100}),
        LookupSettings::default(),
        &BTreeMap::new(),
    );
    let o = f.client.lookup_async("a.example", AsyncOptions::default()).await;
    match o.result {
        AsyncResult::Answer {
            storable,
            source,
            ref detail,
            ..
        } => {
            assert!(storable);
            assert_eq!(source, Source::Call);
            assert!(detail.is_some());
        }
        ref other => panic!("{other:?}"),
    }
    // The generation moves on during the call: its result isn't used; the lookup calls again
    // under the new generation, and that answer is storable.
    let c = f.client.clone();
    let h = tokio::spawn(async move { c.lookup_async("b.example", AsyncOptions::default()).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut sp = spec(
        "p1",
        json!({"verdict": "block", "delay_ms": 100}),
        LookupSettings::default(),
    );
    sp.generation = GEN2.into();
    f.client.update(sp, &BTreeMap::new());
    let o = h.await.unwrap();
    assert_eq!(&*o.generation, GEN2, "the generation its call started under");
    assert!(matches!(o.result, AsyncResult::Answer { storable: true, .. }));
    assert_eq!(f.module.calls(), 3);
    // A flush during the call: the answer is used but not storable.
    let c = f.client.clone();
    let h = tokio::spawn(async move { c.lookup_async("c.example", AsyncOptions::default()).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    f.client.flush();
    let o = h.await.unwrap();
    assert_eq!(&*o.generation, GEN2);
    assert!(matches!(o.result, AsyncResult::Answer { storable: false, .. }));
    // A name failing the label check.
    assert_eq!(
        f.client
            .lookup_async("bad name", AsyncOptions::default())
            .await
            .result,
        AsyncResult::NameCheck
    );
}

#[tokio::test(start_paused = true)]
async fn async_timeout_counts() {
    let s = LookupSettings {
        async_timeout_ms: 2000,
        ..LookupSettings::default()
    };
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"mode": "hang"}),
        s,
        &BTreeMap::new(),
    );
    let o = f.client.lookup_async("x.example", AsyncOptions::default()).await;
    assert!(matches!(
        o.result,
        AsyncResult::Error {
            timed_out: true,
            kind: ErrorKind::Failed,
            ..
        }
    ));
    assert!(o.elapsed >= Duration::from_secs(2));
    let m = f.client.metrics();
    assert_eq!((m.timeouts, m.errors), (1, 1));
}

#[tokio::test]
async fn recheck_skips_the_cache() {
    let f = fixture(json!({"verdict": "clean"}));
    sync(&f.client, "x.example").await;
    let o = f.client.lookup_async("x.example", AsyncOptions::default()).await;
    assert!(matches!(
        o.result,
        AsyncResult::Cached {
            source: Source::Ram,
            ..
        }
    ));
    let o = f
        .client
        .lookup_async(
            "x.example",
            AsyncOptions {
                skip_cache: true,
                ..AsyncOptions::default()
            },
        )
        .await;
    assert!(matches!(o.result, AsyncResult::Answer { .. }));
    assert_eq!(f.module.calls(), 2);
}

// ---------------------------------------------------------------------------------------------
// Self-tests

#[tokio::test]
async fn self_test_skips_and_never_fills_the_cache() {
    let test = SelfTest {
        name: "isitblocked.org".into(),
        expect: Expect::Block,
        cron: "0 * * * *".into(),
    };
    let module = ScriptedModule::with_self_test("scripted", test.clone(), |_, _, _| -> ScriptFuture {
        Box::pin(async { answer(Verdict::Clean) })
    });
    let f = fixture_with(
        Role::Edge,
        module,
        json!({}),
        LookupSettings::default(),
        &BTreeMap::new(),
    );
    let run = f.client.run_self_test().await.unwrap();
    assert_eq!(run.test, test);
    assert!(matches!(
        run.result,
        SelfTestResult::Wrong {
            verdict: StoredVerdict::Clean,
            ..
        }
    ));
    let run = f.client.run_self_test().await.unwrap();
    assert!(matches!(run.result, SelfTestResult::Wrong { .. }));
    assert_eq!(f.module.calls(), 2, "never answered from the cache");
    assert_eq!(f.client.metrics().entries, 0, "never cached");
    // A missing secret: the test still runs, and its failed call is inconclusive.
    let test2 = test.clone();
    let module = ScriptedModule::with_self_test("scripted", test2, |_, _, _| -> ScriptFuture {
        Box::pin(async { answer(Verdict::Clean) })
    });
    let f2 = fixture_with(
        Role::Core,
        module,
        json!({"k": "${secret:gone}"}),
        LookupSettings::default(),
        &BTreeMap::new(),
    );
    let run = f2.client.run_self_test().await.unwrap();
    assert!(
        matches!(run.result, SelfTestResult::Inconclusive { .. }),
        "{:?}",
        run.result
    );
    assert_eq!(f2.module.calls(), 0);
    // No self-test named: None.
    let f = fixture(json!({}));
    assert!(f.client.run_self_test().await.is_none());
}

// ---------------------------------------------------------------------------------------------
// Verdict-set activation, RAM tier internals, outcome mapping

#[tokio::test]
async fn set_activation_drops_superseded_entries_before_the_swap() {
    let f = fixture(json!({"verdict": "block"}));
    sync(&f.client, "a.example").await; // RAM: Block obtained at t0
    sync(&f.client, "b.example").await;
    let set = TestSet::new();
    set.put(
        "a.example",
        StoredVerdict::Clean,
        t0() + SignedDuration::from_secs(5),
        GEN,
    );
    set.put(
        "b.example",
        StoredVerdict::Clean,
        t0() - SignedDuration::from_secs(5),
        GEN,
    );
    f.clock.advance(Duration::from_secs(10));
    let dropped = f.client.activate_set_delta(
        set.clone(),
        name_hash,
        [
            (name_hash("a.example"), t0() + SignedDuration::from_secs(5)),
            (name_hash("b.example"), t0() - SignedDuration::from_secs(5)),
        ],
    );
    assert_eq!(dropped, 1);
    // a: the set's record is newer, so the set answers; b: the RAM entry is newer and stays.
    assert_eq!(source(&sync(&f.client, "a.example").await), Some(Source::Set));
    assert_eq!(source(&sync(&f.client, "b.example").await), Some(Source::Ram));
    // A new base: every entry checked.
    let dropped = f.client.activate_set_base(set, |name| {
        (name == "b.example").then(|| t0() + SignedDuration::from_secs(1))
    });
    assert_eq!(dropped, 1);
    assert_eq!(source(&sync(&f.client, "b.example").await), Some(Source::Set));
}

/// The verdict-set record key of a name in these tests (the edge uses `xxh3_128` with the
/// set's seed).
fn name_hash(name: &str) -> u128 {
    u128::from(generation_key(name)) << 64 | 7
}

#[tokio::test]
async fn verdict_set_activation_drops_only_older_or_equal_entries() {
    let f = fixture(json!({"verdict": "block"}));
    sync(&f.client, "a.example").await; // obtained at t0
    sync(&f.client, "b.example").await;
    sync(&f.client, "c.example").await;
    sync(&f.client, "d.example").await;
    let set = TestSet::new();
    // A delta's record obtained earlier than the RAM entry: the RAM entry stays.
    let older = [(name_hash("a.example"), t0() - SignedDuration::from_secs(1))];
    assert_eq!(f.client.activate_set_delta(set.clone(), name_hash, older), 0);
    // Equal or later: dropped. Duplicate keys: the latest record counts.
    let changed = [
        (name_hash("a.example"), t0()),
        (name_hash("b.example"), t0() - SignedDuration::from_secs(9)),
        (name_hash("b.example"), t0() + SignedDuration::from_secs(1)),
    ];
    assert_eq!(f.client.activate_set_delta(set.clone(), name_hash, changed), 2);
    assert_eq!(f.client.metrics().entries, 2);
    // A new base: every RAM entry checked; one obtained after the record stays, and a record
    // from the future counts as obtained now (clamped).
    let dropped = f.client.activate_set_base(set, |name| match name {
        "c.example" => Some(t0() - SignedDuration::from_secs(1)),
        "d.example" => Some(t0() + SignedDuration::from_hours(24)),
        _ => None,
    });
    assert_eq!(dropped, 1);
    assert_eq!(f.client.metrics().entries, 1);
    assert_eq!(source(&sync(&f.client, "c.example").await), Some(Source::Ram));
}

#[test]
fn ram_tier_bounded_by_bytes_with_evictions() {
    let mut c = LookupSettings::default().cache;
    c.max_mib = 1;
    let ram = RamTier::new(&c);
    let now = Instant::now();
    for i in 0..20_000 {
        ram.insert(
            &format!("name-{i}.example.com"),
            RamEntry {
                result: RamResult::Verdict(StoredVerdict::Clean),
                obtained_at: t0(),
                obtained_mono: now,
                gen_key: 1,
                epoch: 0,
            },
            &c,
        );
    }
    assert!(ram.bytes() <= 1024 * 1024 + 4096, "{}", ram.bytes());
    assert!(ram.len() < 20_000);
    assert!(ram.evictions() > 0);
    // Shrinking evicts down to the new size... and 0 empties it.
    c.max_mib = 0;
    ram.set_capacity(&c);
    assert_eq!(ram.len(), 0);
    ram.insert(
        "x.example",
        RamEntry {
            result: RamResult::Verdict(StoredVerdict::Clean),
            obtained_at: t0(),
            obtained_mono: now,
            gen_key: 1,
            epoch: 0,
        },
        &c,
    );
    assert_eq!(ram.len(), 0);
}

#[test]
fn outcomes_under_each_fail_mode() {
    let o = |result| SyncOutcome {
        result,
        generation: GEN.into(),
        elapsed: Duration::from_millis(12),
    };
    let cases = [
        (
            o(SyncResult::Verdict {
                verdict: StoredVerdict::Block {
                    score: None,
                    reason: "r".into(),
                },
                source: Source::Call,
                obtained_at: Some(t0()),
                detail: None,
            }),
            true,
            true,
            false,
            LookupVerdict::Block,
        ),
        (
            o(SyncResult::Verdict {
                verdict: StoredVerdict::Clean,
                source: Source::Ram,
                obtained_at: Some(t0()),
                detail: None,
            }),
            false,
            false,
            false,
            LookupVerdict::Clean,
        ),
        (
            o(SyncResult::Verdict {
                verdict: StoredVerdict::Unknown,
                source: Source::Call,
                obtained_at: Some(t0()),
                detail: None,
            }),
            false,
            true,
            false,
            LookupVerdict::Unknown,
        ),
        (o(SyncResult::Timeout), false, true, true, LookupVerdict::Timeout),
        (
            o(SyncResult::Error {
                kind: ErrorKind::Failed,
                message: "x".into(),
                cached: false,
            }),
            false,
            true,
            true,
            LookupVerdict::Error,
        ),
        (
            o(SyncResult::Rejected { paused: true }),
            false,
            true,
            true,
            LookupVerdict::Rejected,
        ),
        (
            o(SyncResult::BreakerOpen),
            false,
            true,
            true,
            LookupVerdict::Error,
        ),
        (
            o(SyncResult::LimitsExhausted),
            false,
            true,
            true,
            LookupVerdict::Error,
        ),
    ];
    for (out, open, closed, retry, verdict) in cases {
        assert_eq!(out.blocks(FailMode::Open), open, "{out:?}");
        assert_eq!(out.blocks(FailMode::Closed), closed, "{out:?}");
        let item = out.log_item("q9").unwrap();
        assert_eq!(item.retry, retry, "{out:?}");
        assert_eq!(item.verdict, verdict);
        assert_eq!(item.ms, 12);
        assert_eq!(item.generation, GEN);
        assert_eq!(out.log_verdict(), Some(verdict));
    }
}

#[test]
fn generation_keys() {
    assert_eq!(generation_key("000000000000000a"), 10);
    assert_ne!(generation_key("not-hex"), generation_key("not-hex2"));
}

// ---------------------------------------------------------------------------------------------
// Generations and settings across a call (providers.md §4 "Cache generation", edge.md §13)

/// A module whose delay per name comes from `cfg.delays` (ms) and whose verdict is
/// `cfg.verdict`.
fn by_name() -> Arc<ScriptedModule> {
    ScriptedModule::new("scripted", |cfg: Value, name, _n| -> ScriptFuture {
        Box::pin(async move {
            if let Some(ms) = cfg["delays"][name.as_str()].as_u64() {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            answer(match cfg["verdict"].as_str().unwrap_or("clean") {
                "block" => block("listed"),
                _ => Verdict::Clean,
            })
        })
    })
}

fn with_gen(mut sp: ProviderSpec, generation: &str) -> ProviderSpec {
    sp.generation = generation.into();
    sp
}

/// A sync waiter never decides a query with the answer of a call whose generation moved on
/// while it ran: it retries under the new generation within its deadline.
#[tokio::test(start_paused = true)]
async fn sync_waiter_never_uses_an_old_generation_answer() {
    let f = fixture(json!({"verdict": "block", "delay_ms": 100}));
    let c = f.client.clone();
    let h = tokio::spawn(async move { c.lookup_sync(req("x.example", Duration::from_millis(150))).await });
    let c = f.client.clone();
    let joined =
        tokio::spawn(async move { c.lookup_sync(req("x.example", Duration::from_millis(150))).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.client.update(
        with_gen(
            spec("p1", json!({"verdict": "clean"}), LookupSettings::default()),
            GEN2,
        ),
        &BTreeMap::new(),
    );
    for o in [h.await.unwrap(), joined.await.unwrap()] {
        assert!(
            !o.blocks(FailMode::Open),
            "the old generation's Block isn't used: {o:?}"
        );
        assert_eq!(&*o.generation, GEN2, "{o:?}");
        assert!(
            matches!(
                o.result,
                SyncResult::Verdict {
                    verdict: StoredVerdict::Clean,
                    ..
                }
            ),
            "{o:?}"
        );
    }
    assert_eq!(f.module.calls(), 2);
}

/// The same with no time left to retry: a timeout under the new generation, never a verdict.
#[tokio::test(start_paused = true)]
async fn sync_waiter_without_time_to_retry_times_out() {
    let f = fixture(json!({"verdict": "block", "delay_ms": 100}));
    let c = f.client.clone();
    let h = tokio::spawn(async move { c.lookup_sync(req("x.example", Duration::from_millis(150))).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.client.update(
        with_gen(
            spec(
                "p1",
                json!({"verdict": "clean", "delay_ms": 500}),
                LookupSettings::default(),
            ),
            GEN2,
        ),
        &BTreeMap::new(),
    );
    let o = h.await.unwrap();
    assert_eq!(o.result, SyncResult::Timeout);
    assert_eq!(&*o.generation, GEN2);
}

/// An async lookup waiting for a slot is admitted under the limits current when it gets one.
#[tokio::test(start_paused = true)]
async fn async_waiter_admitted_under_current_limits() {
    let mut s = no_cache();
    s.limits.max_inflight = 2;
    let cfg = json!({"delays": {"a.example": 100, "b.example": 1000, "c.example": 1000}});
    let f = fixture_with(Role::Core, by_name(), cfg.clone(), s.clone(), &BTreeMap::new());
    let mut handles = Vec::new();
    for n in ["a.example", "b.example", "c.example"] {
        let c = f.client.clone();
        handles.push(tokio::spawn(async move {
            c.lookup_async(n, AsyncOptions::default()).await
        }));
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(f.client.inflight(), 2);
    s.limits.max_inflight = 1;
    f.client.update(spec("p1", cfg, s), &BTreeMap::new());
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(f.client.inflight(), 1, "c waits until b is done");
    for h in handles {
        assert!(matches!(h.await.unwrap().result, AsyncResult::Answer { .. }));
    }
}

/// An async lookup that waited for a token while the generation moved on runs under the new
/// generation and config, and its answer is storable.
#[tokio::test(start_paused = true)]
async fn async_waiter_runs_under_the_new_generation() {
    let mut s = no_cache();
    s.limits.rps = 1;
    s.limits.burst = 1;
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"verdict": "block"}),
        s.clone(),
        &BTreeMap::new(),
    );
    f.client.lookup_async("a.example", AsyncOptions::default()).await;
    let c = f.client.clone();
    let h = tokio::spawn(async move { c.lookup_async("b.example", AsyncOptions::default()).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    f.client.update(
        with_gen(spec("p1", json!({"verdict": "clean"}), s), GEN2),
        &BTreeMap::new(),
    );
    let o = h.await.unwrap();
    assert_eq!(&*o.generation, GEN2);
    assert!(
        matches!(
            o.result,
            AsyncResult::Answer {
                verdict: StoredVerdict::Clean,
                storable: true,
                ..
            }
        ),
        "{o:?}"
    );
}

/// An async waiter whose call's generation moves on retries under the new one.
#[tokio::test(start_paused = true)]
async fn async_waiter_never_uses_an_old_generation_answer() {
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"verdict": "block", "delay_ms": 100}),
        no_cache(),
        &BTreeMap::new(),
    );
    let c = f.client.clone();
    let h = tokio::spawn(async move { c.lookup_async("x.example", AsyncOptions::default()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.client.update(
        with_gen(spec("p1", json!({"verdict": "clean"}), no_cache()), GEN2),
        &BTreeMap::new(),
    );
    let o = h.await.unwrap();
    assert_eq!(&*o.generation, GEN2);
    assert!(
        matches!(
            o.result,
            AsyncResult::Answer {
                verdict: StoredVerdict::Clean,
                storable: true,
                ..
            }
        ),
        "{o:?}"
    );
}

/// With `one_attempt`, a generation that moves on during the call ends the lookup with
/// `GenerationMoved` after that one call: the caller decides about the next (core reserves a
/// re-check's daily allowance per call).
#[tokio::test(start_paused = true)]
async fn one_attempt_ends_when_the_generation_moves_on() {
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"verdict": "block", "delay_ms": 100}),
        no_cache(),
        &BTreeMap::new(),
    );
    let c = f.client.clone();
    let once = AsyncOptions {
        skip_cache: true,
        one_attempt: true,
    };
    let h = tokio::spawn(async move { c.lookup_async("x.example", once).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.client.update(
        with_gen(spec("p1", json!({"verdict": "clean"}), no_cache()), GEN2),
        &BTreeMap::new(),
    );
    let o = h.await.unwrap();
    assert_eq!(o.result, AsyncResult::GenerationMoved { called: true }, "{o:?}");
    assert_eq!(&*o.generation, GEN2);
    assert_eq!(f.module.calls(), 1, "no second call");
    // The next lookup calls under the new generation.
    let o = f.client.lookup_async("x.example", once).await;
    assert!(
        matches!(
            o.result,
            AsyncResult::Answer {
                verdict: StoredVerdict::Clean,
                storable: true,
                ..
            }
        ),
        "{o:?}"
    );
    assert_eq!(f.module.calls(), 2);
}

/// With `one_attempt`, a generation that moves on while the lookup waits for a token, before
/// any call, ends it with `GenerationMoved { called: false }`: no call was made under either
/// generation, and the next lookup calls under the new one.
#[tokio::test(start_paused = true)]
async fn one_attempt_ends_without_a_call_when_the_generation_moves_on_first() {
    let mut s = no_cache();
    s.limits.rps = 1;
    s.limits.burst = 1;
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"verdict": "block"}),
        s.clone(),
        &BTreeMap::new(),
    );
    f.client.lookup_async("a.example", AsyncOptions::default()).await;
    assert_eq!(f.module.calls(), 1);
    let once = AsyncOptions {
        skip_cache: true,
        one_attempt: true,
    };
    let c = f.client.clone();
    let h = tokio::spawn(async move { c.lookup_async("b.example", once).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    f.client.update(
        with_gen(spec("p1", json!({"verdict": "clean"}), s), GEN2),
        &BTreeMap::new(),
    );
    let o = h.await.unwrap();
    assert_eq!(o.result, AsyncResult::GenerationMoved { called: false }, "{o:?}");
    assert_eq!(&*o.generation, GEN2);
    assert_eq!(f.module.calls(), 1, "no call was made");
    let o = f.client.lookup_async("b.example", once).await;
    assert!(
        matches!(
            o.result,
            AsyncResult::Answer {
                verdict: StoredVerdict::Clean,
                ..
            }
        ),
        "{o:?}"
    );
    assert_eq!(f.module.calls(), 2);
}

/// README §2 Clocks; core.md §7: an async lookup makes no call while the client's clock isn't
/// synchronised, including one that lost its synchronisation while the lookup waited for a
/// token (the check is right before the call).
#[tokio::test(start_paused = true)]
async fn no_async_call_on_an_unsynchronised_clock() {
    let mut s = LookupSettings::default();
    s.limits.rps = 1;
    s.limits.burst = 1;
    let f = fixture_with(
        Role::Core,
        configurable(),
        json!({"verdict": "block"}),
        s,
        &BTreeMap::new(),
    );
    f.clock.set_synced(false);
    let o = f.client.lookup_async("a.example", AsyncOptions::default()).await;
    assert_eq!(o.result, AsyncResult::ClockUnsynced, "{o:?}");
    assert_eq!(f.module.calls(), 0);
    f.clock.set_synced(true);
    let o = f.client.lookup_async("a.example", AsyncOptions::default()).await;
    assert!(matches!(o.result, AsyncResult::Answer { .. }), "{o:?}");
    assert_eq!(f.module.calls(), 1);
    // The token is spent: the next lookup waits for one, and the clock loses its
    // synchronisation meanwhile.
    let c = f.client.clone();
    let h = tokio::spawn(async move { c.lookup_async("b.example", AsyncOptions::default()).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    f.clock.set_synced(false);
    let o = h.await.unwrap();
    assert_eq!(o.result, AsyncResult::ClockUnsynced, "{o:?}");
    assert_eq!(f.module.calls(), 1, "no call once synchronisation is lost");
}

/// A verdict-set tier that answers nothing after a delay.
struct SlowSet(Duration);

#[async_trait::async_trait]
impl VerdictSet for SlowSet {
    async fn get(&self, _: &str) -> anyhow::Result<Option<SetRecord>> {
        tokio::time::sleep(self.0).await;
        Ok(None)
    }
}

/// A sync lookup whose verdict-set read spans a save calls with the saved config, once.
#[tokio::test(start_paused = true)]
async fn sync_call_starts_under_the_settings_current_after_the_set_read() {
    let f = fixture(json!({"verdict": "block"}));
    f.client
        .set_verdict_set(Some(Arc::new(SlowSet(Duration::from_millis(50)))));
    let c = f.client.clone();
    let h = tokio::spawn(async move { sync(&c, "x.example").await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    f.client.update(
        with_gen(
            spec("p1", json!({"verdict": "clean"}), LookupSettings::default()),
            GEN2,
        ),
        &BTreeMap::new(),
    );
    let o = h.await.unwrap();
    assert_eq!(&*o.generation, GEN2);
    assert!(
        matches!(
            o.result,
            SyncResult::Verdict {
                verdict: StoredVerdict::Clean,
                source: Source::Call,
                ..
            }
        ),
        "{o:?}"
    );
    assert_eq!(f.module.calls(), 1, "no call under the old config");
}

/// A verdict-set tier whose reads wait at a gate, then answer with its record.
struct GatedSet {
    started: tokio::sync::Notify,
    gate: tokio::sync::Semaphore,
    record: SetRecord,
}

impl GatedSet {
    fn new(verdict: StoredVerdict, generation: &str) -> Arc<Self> {
        Arc::new(Self {
            started: tokio::sync::Notify::new(),
            gate: tokio::sync::Semaphore::new(0),
            record: SetRecord {
                verdict,
                obtained_at: t0(),
                generation: generation.into(),
            },
        })
    }
}

#[async_trait::async_trait]
impl VerdictSet for GatedSet {
    async fn get(&self, _: &str) -> anyhow::Result<Option<SetRecord>> {
        self.started.notify_one();
        self.gate.acquire().await?.forget();
        Ok(Some(self.record.clone()))
    }
}

/// Review round 2, CR6: a set read that returns a record after the provider's generation moved
/// on and its set was removed isn't used (an obsolete Block, or an obsolete Clean that would skip
/// the fail mode): sync and async lookups start again under the new generation.
#[tokio::test]
async fn a_set_record_read_across_a_generation_change_is_not_used() {
    for asynchronous in [false, true] {
        let f = fixture(json!({"verdict": "clean"}));
        let set = GatedSet::new(
            StoredVerdict::Block {
                score: None,
                reason: "old generation".into(),
            },
            GEN,
        );
        f.client.set_verdict_set(Some(set.clone()));
        let c = f.client.clone();
        let h = tokio::spawn(async move {
            if asynchronous {
                let o = c.lookup_async("x.example", AsyncOptions::default()).await;
                (format!("{:?}", o.result), o.generation)
            } else {
                let o = sync(&c, "x.example").await;
                (format!("{:?}", o.result), o.generation)
            }
        });
        set.started.notified().await;
        f.client.update(
            with_gen(
                spec("p1", json!({"verdict": "clean"}), LookupSettings::default()),
                GEN2,
            ),
            &BTreeMap::new(),
        );
        f.client.set_verdict_set(None);
        set.gate.add_permits(1);
        let (result, generation) = h.await.unwrap();
        assert_eq!(&*generation, GEN2, "async {asynchronous}: {result}");
        assert!(
            result.contains("Clean") && !result.contains("Block") && !result.contains("Set"),
            "async {asynchronous}: {result}"
        );
        assert_eq!(f.module.calls(), 1);
    }
}

/// … nor is a record read from a set an activation replaced meanwhile: the lookup reads the
/// set now active.
#[tokio::test]
async fn a_set_record_read_across_an_activation_is_not_used() {
    for asynchronous in [false, true] {
        let f = fixture(json!({"verdict": "block"}));
        let old = GatedSet::new(
            StoredVerdict::Block {
                score: None,
                reason: "superseded".into(),
            },
            GEN,
        );
        f.client.set_verdict_set(Some(old.clone()));
        let c = f.client.clone();
        let h = tokio::spawn(async move {
            if asynchronous {
                let o = c.lookup_async("x.example", AsyncOptions::default()).await;
                format!("{:?}", o.result)
            } else {
                format!("{:?}", sync(&c, "x.example").await.result)
            }
        });
        old.started.notified().await;
        let new = TestSet::new();
        new.put("x.example", StoredVerdict::Clean, t0(), GEN);
        f.client
            .activate_set_delta(new.clone(), name_hash, [(name_hash("x.example"), t0())]);
        old.gate.add_permits(1);
        let result = h.await.unwrap();
        assert!(
            result.contains("Clean") && result.contains("Set") && !result.contains("superseded"),
            "async {asynchronous}: {result}"
        );
        assert_eq!(f.module.calls(), 0);
    }
}

// ---------------------------------------------------------------------------------------------
// Verdict-set activation against calls in flight (edge.md §10)

/// A call that started before an activation and ends after it never puts an entry in the RAM
/// tier that hides the new set's newer record.
#[tokio::test(start_paused = true)]
async fn a_call_spanning_an_activation_never_hides_the_new_set() {
    let f = fixture(json!({"verdict": "clean", "delay_ms": 100}));
    let o = f
        .client
        .lookup_sync(req("x.example", Duration::from_millis(10)))
        .await;
    assert_eq!(o.result, SyncResult::Timeout);
    let set = TestSet::new();
    let later = t0() + SignedDuration::from_secs(5);
    set.put(
        "x.example",
        StoredVerdict::Block {
            score: None,
            reason: "set".into(),
        },
        later,
        GEN,
    );
    f.client
        .activate_set_delta(set.clone(), name_hash, [(name_hash("x.example"), later)]);
    // The call ends after the activation; the provider answered at t0, before the set's record.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let o = sync(&f.client, "x.example").await;
    assert_eq!(source(&o), Some(Source::Set), "{o:?}");
    assert!(o.blocks(FailMode::Open));
}

/// Activation checks entries with no RAM-tier lock held, so RAM reads go on meanwhile.
#[test]
fn activation_checks_entries_without_holding_ram_locks() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let f = rt.block_on(async {
        let f = fixture(json!({"verdict": "block"}));
        for i in 0..64 {
            sync(&f.client, &format!("n{i}.example")).await;
        }
        f
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let client = f.client.clone();
    std::thread::spawn(move || {
        let ram_reader = client.clone();
        client.activate_set_base(TestSet::new(), move |name| {
            // A RAM read of the same shard while the entry is checked.
            let ram = ram_reader.inner.ram.as_ref().unwrap();
            let _ = ram.get(name, &LookupSettings::default().cache, 0, 0, Instant::now());
            None
        });
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(10)).is_ok(),
        "activation blocked on a RAM-tier lock"
    );
}

// ---------------------------------------------------------------------------------------------
// State that survives updates, bounds

/// edge.md §13: an update keeps the rejection pause and the token bucket.
#[tokio::test(start_paused = true)]
async fn pause_and_token_bucket_survive_updates() {
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"mode": "reject", "retry_after_s": 60}),
        no_cache(),
        &BTreeMap::new(),
    );
    assert_eq!(
        sync(&f.client, "a.example").await.result,
        SyncResult::Rejected { paused: false }
    );
    let s = LookupSettings {
        sync_timeout_ms: 300,
        ..no_cache()
    };
    f.client
        .update(spec("p1", json!({"verdict": "clean"}), s), &BTreeMap::new());
    assert_eq!(
        sync(&f.client, "b.example").await.result,
        SyncResult::Rejected { paused: true },
        "the pause survives a settings and config update"
    );
    assert_eq!(f.module.calls(), 1);

    let mut s = no_cache();
    s.limits.rps = 1;
    s.limits.burst = 1;
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"verdict": "clean"}),
        s.clone(),
        &BTreeMap::new(),
    );
    assert_eq!(source(&sync(&f.client, "a.example").await), Some(Source::Call));
    s.sync_timeout_ms = 300;
    f.client
        .update(spec("p1", json!({"verdict": "block"}), s), &BTreeMap::new());
    assert_eq!(
        sync(&f.client, "b.example").await.result,
        SyncResult::LimitsExhausted,
        "the spent token stays spent"
    );
}

/// providers.md §4 "Detail": under 512 bytes serialised.
#[test]
fn detail_must_stay_under_512_bytes() {
    // {"x":""} is 8 bytes.
    let sized = |len: usize| json!({"x": "y".repeat(len - 8)});
    assert_eq!(serde_json::to_string(&sized(512)).unwrap().len(), 512);
    assert!(sanitize_detail(sized(512), &Redactor::default()).is_none());
    assert!(sanitize_detail(sized(511), &Redactor::default()).is_some());
}

/// providers.md §4 "Detail": a small JSON object. Anything else is dropped here, so the edge never
/// logs a detail core would refuse (core drops a record whose lookup detail isn't an object).
#[test]
fn detail_must_be_an_object() {
    for d in [json!("text"), json!([1, 2]), json!(42), json!(true), Value::Null] {
        assert!(sanitize_detail(d.clone(), &Redactor::default()).is_none(), "{d}");
    }
    assert!(sanitize_detail(json!({"server": "9.9.9.9"}), &Redactor::default()).is_some());
}

/// README §2 Secrets: a detail echoing a secret with `"` or `\` is dropped (the check sees the
/// JSON-escaped form), and a one-character secret doesn't drop every detail.
#[tokio::test]
async fn secret_redaction_sees_escaped_forms_and_spares_short_secrets() {
    let secrets = BTreeMap::from([("tok".to_owned(), "quote\"and\\backslash".to_owned())]);
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"mode": "secret_detail", "token": "${secret:tok}"}),
        no_cache(),
        &secrets,
    );
    match sync(&f.client, "x.example").await.result {
        SyncResult::Verdict { detail, .. } => assert!(detail.is_none(), "{detail:?}"),
        other => panic!("{other:?}"),
    }
    let secrets = BTreeMap::from([("tok".to_owned(), "o".to_owned())]);
    let f = fixture_with(
        Role::Edge,
        configurable(),
        json!({"verdict": "clean", "token": "${secret:tok}"}),
        no_cache(),
        &secrets,
    );
    match sync(&f.client, "x.example").await.result {
        // {"from": "provider"} holds "o" only inside words.
        SyncResult::Verdict { detail, .. } => assert!(detail.is_some()),
        other => panic!("{other:?}"),
    }
}

/// README §2 Bounded: `cache.max_mib` from core is capped at [`MAX_RAM_MIB`].
#[test]
fn ram_tier_capacity_capped() {
    let mut c = LookupSettings::default().cache;
    c.max_mib = u32::MAX;
    let ram = RamTier::new(&c);
    assert_eq!(ram.capacity(), u64::from(MAX_RAM_MIB) * 1024 * 1024);
    c.max_mib = 3;
    ram.set_capacity(&c);
    assert_eq!(ram.capacity(), 3 * 1024 * 1024);
    c.max_mib = MAX_RAM_MIB + 1;
    ram.set_capacity(&c);
    assert_eq!(ram.capacity(), u64::from(MAX_RAM_MIB) * 1024 * 1024);
}
