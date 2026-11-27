//! Logs (edge.md §11, api.md §5): the producer API every module emits records through, the
//! memory buffer → core shipper, and the disk spool.
//!
//! - Every record gets `(boot, seq)` here: `boot` is random per process start, `seq` increments.
//! - A `q` record that names an upstream answer carries an `Arc<Answer>`: the buffer keeps the
//!   answer's wire alive, so a cache eviction can't lose it, and each batch or spool segment
//!   writes the answer once, ahead of the first record referencing it ([`shipper`], [`spool`]).
//! - An answer over 4 KiB is never sent: [`AnswerSlot::Oversized`] makes the producer set
//!   `truncated` and drop `answer_id`, `received_at` and `age_s` (api.md §5).
//! - `emit` never blocks: a full buffer (10,000 records) drops the record and counts
//!   `buffer_full`.

pub mod shipper;
pub mod spool;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use base64::Engine as _;
use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use picket_api::edge_config::{LogLevel, LoggingConfig};
use picket_api::logs::{
    AnswerRecord, Decision, EventRecord, LogRecord, LookupVerdict, MAX_ANSWER_WIRE, MAX_RESPONSE_WIRE,
    QueryRecord, RecordHeader,
};
use picket_api::time::Timestamp;

/// Records the memory buffer holds at most (edge.md §11).
pub const BUFFER_MAX: usize = 10_000;
/// Longest record line kept (README §2 Bounded): far above any record the edge makes, and what
/// bounds how far one spool member can carry a segment past [`spool::SEGMENT_RAW`]. A longer
/// record is dropped and counted `rejected`.
pub const MAX_LINE: usize = 1 << 20;

/// Ranges for `EdgeConfig.logging` (README §2: core's values are range-checked before use). The
/// spec gives only defaults; these bounds are the implementer's.
pub mod bounds {
    use std::ops::RangeInclusive;

    /// One hour to a year: 0 would drop every record at once; a huge value would overflow the
    /// age arithmetic.
    pub const RETENTION_H: RangeInclusive<u32> = 1..=8760;
    /// Core's range (apps/picket-core config validation). 0 would abandon every memory-mode POST
    /// at its first poll, however healthy core is, so every batch would be fsynced to the spool
    /// and posted twice (edge.md §11; hard rule 8: eMMC writes).
    pub const SPOOL_AFTER_S: RangeInclusive<u32> = 1..=3600;
    /// 1 MiB to 1 TiB, for `spool_max_mib` and `ssd_spool_max_mib`. Each location also always
    /// leaves its filesystem's free-space floor, whatever its cap.
    pub const SPOOL_MIB: RangeInclusive<u64> = 1..=(1 << 20);
    /// api.md §5: a batch holds at most 1,000 records.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a const (no TryFrom): MAX_BATCH_RECORDS (1000) fits a u32"
    )]
    pub const BATCH_MAX: RangeInclusive<u32> = 1..=(picket_api::logs::MAX_BATCH_RECORDS as u32);
}

/// The first logging setting out of its range ([`bounds`]), if any: validation rejects such a
/// config (README §2 Untrusted input).
pub fn logging_problem(c: &LoggingConfig) -> Option<String> {
    let bad =
        |name: &str, v: &dyn std::fmt::Display, lo: &dyn std::fmt::Display, hi: &dyn std::fmt::Display| {
            Some(format!("logging.{name} {v} is outside {lo}..={hi}"))
        };
    let (r, a, m, b) = (
        &bounds::RETENTION_H,
        &bounds::SPOOL_AFTER_S,
        &bounds::SPOOL_MIB,
        &bounds::BATCH_MAX,
    );
    if !r.contains(&c.retention_h) {
        return bad("retention_h", &c.retention_h, r.start(), r.end());
    }
    if !a.contains(&c.spool_after_s) {
        return bad("spool_after_s", &c.spool_after_s, a.start(), a.end());
    }
    if !m.contains(&c.spool_max_mib) {
        return bad("spool_max_mib", &c.spool_max_mib, m.start(), m.end());
    }
    if let Some(v) = c.ssd_spool_max_mib
        && !m.contains(&v)
    {
        return bad("ssd_spool_max_mib", &v, m.start(), m.end());
    }
    if !b.contains(&c.batch_max) {
        return bad("batch_max", &c.batch_max, b.start(), b.end());
    }
    None
}

/// `c` with every value clamped into its range: what the shipper runs, whatever reaches it
/// (validation rejects such configs, but a stored one is only parsed at start).
pub fn clamp_logging(c: LoggingConfig) -> LoggingConfig {
    let clamp = |v: u64| v.clamp(*bounds::SPOOL_MIB.start(), *bounds::SPOOL_MIB.end());
    LoggingConfig {
        spool_after_s: c
            .spool_after_s
            .clamp(*bounds::SPOOL_AFTER_S.start(), *bounds::SPOOL_AFTER_S.end()),
        spool_max_mib: clamp(c.spool_max_mib),
        ssd_spool_max_mib: c.ssd_spool_max_mib.map(clamp),
        retention_h: c
            .retention_h
            .clamp(*bounds::RETENTION_H.start(), *bounds::RETENTION_H.end()),
        batch_max: c
            .batch_max
            .clamp(*bounds::BATCH_MAX.start(), *bounds::BATCH_MAX.end()),
    }
}

/// The two spool classes (edge.md §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    /// Blocks, lookup hits, failures and late answers, unchecked cold lookups, allows, condition
    /// changes, events, errors.
    Security,
    /// Allowed queries.
    Bulk,
}

impl Class {
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Bulk => "bulk",
        }
    }
    pub const ALL: [Class; 2] = [Class::Security, Class::Bulk];
}

/// The spool class of a record (edge.md §11). Only a plain allowed query is `bulk`: one with a
/// lookup hit or failure, or an unchecked cold lookup, is `security`, and so is every other
/// decision (blocks, rewrites, REFUSED and SERVFAIL) and every non-`q` record.
pub fn classify(rec: &LogRecord) -> Class {
    match rec {
        LogRecord::Query(q) => classify_query(q),
        _ => Class::Security,
    }
}

pub fn classify_query(q: &QueryRecord) -> Class {
    let lookup_hit_or_failure = q.lookups.iter().any(|l| {
        !matches!(l.verdict, LookupVerdict::Clean | LookupVerdict::Unknown)
            || l.timed_out
            || l.rejected == Some(true)
    });
    if q.decision == Decision::Allow && !lookup_hit_or_failure && q.cold_unchecked.is_empty() {
        Class::Bulk
    } else {
        Class::Security
    }
}

/// Whether a profile's `log` level admits a `q` record (edge.md §11): `full` everything,
/// `blocked` only blocks, rewrites, REFUSED, lookup failures and unchecked cold lookups, `off`
/// nothing. The query pipeline ([`crate::dns::pipeline`]) calls this before emitting.
pub fn query_admitted(level: LogLevel, q: &QueryRecord) -> bool {
    match level {
        LogLevel::Full => true,
        LogLevel::Off => false,
        LogLevel::Blocked => {
            matches!(
                q.decision,
                Decision::Block | Decision::Rewrite | Decision::Refused
            ) || q.lookups.iter().any(|l| {
                matches!(
                    l.verdict,
                    LookupVerdict::Timeout | LookupVerdict::Error | LookupVerdict::Rejected
                ) || l.timed_out
                    || l.rejected == Some(true)
                    || l.retry
            }) || !q.cold_unchecked.is_empty()
        }
    }
}

/// Whether a profile's `log` level admits a `lookup` record (a late answer to a timed-out sync
/// lookup): both `full` and `blocked` keep late answers to lookup failures.
pub fn lookup_admitted(level: LogLevel) -> bool {
    !matches!(level, LogLevel::Off)
}

/// An upstream answer a `q` record references (api.md §5 `answer`). Shared through `Arc` by the
/// cache entry and every buffered record that references it.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    /// First 16 hex characters of the BLAKE3 of `wire`.
    pub id: String,
    /// The scrubbed answer, ≤ 4 KiB.
    pub wire: Bytes,
}

impl Answer {
    /// Wraps a scrubbed answer, or `None` when it is over 4 KiB (never sent).
    pub fn new(wire: Bytes) -> Option<Arc<Self>> {
        if wire.len() > MAX_ANSWER_WIRE {
            return None;
        }
        let id = picket_api::ids::short_id(&picket_api::ids::object_id(&wire)).to_owned();
        Some(Arc::new(Self { id, wire }))
    }

    /// The JSON line of one copy of this answer, with its own header.
    pub fn line(&self, h: RecordHeader) -> String {
        let rec = LogRecord::Answer(AnswerRecord {
            h,
            id: self.id.clone(),
            wire: base64::engine::general_purpose::STANDARD.encode(&self.wire),
        });
        serde_json::to_string(&rec).unwrap_or_default()
    }
}

/// What a `q` record's upstream answer is.
#[derive(Clone, Debug, Default)]
pub enum AnswerSlot {
    /// The record names no upstream answer.
    #[default]
    None,
    /// The answer travels with the record.
    Attached(Arc<Answer>),
    /// The answer was over 4 KiB: the record keeps only its preview and sets `truncated`.
    Oversized,
}

/// Why the edge dropped a record itself (api.md §3 `logs.dropped`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    BufferFull,
    Evicted,
    TooOld,
    Rejected,
}

impl DropReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BufferFull => "buffer_full",
            Self::Evicted => "evicted",
            Self::TooOld => "too_old",
            Self::Rejected => "rejected",
        }
    }
}

/// `logs.dropped` counters.
#[derive(Default)]
pub struct DropCounters {
    pub buffer_full: AtomicU64,
    pub evicted: AtomicU64,
    pub too_old: AtomicU64,
    pub rejected: AtomicU64,
}

impl DropCounters {
    pub fn add(&self, r: DropReason, n: u64) {
        if n == 0 {
            return;
        }
        let c = match r {
            DropReason::BufferFull => &self.buffer_full,
            DropReason::Evicted => &self.evicted,
            DropReason::TooOld => &self.too_old,
            DropReason::Rejected => &self.rejected,
        };
        c.fetch_add(n, Relaxed);
    }

    /// Running totals by reason, every reason present.
    pub fn snapshot(&self) -> BTreeMap<String, u64> {
        [
            DropReason::BufferFull,
            DropReason::Evicted,
            DropReason::TooOld,
            DropReason::Rejected,
        ]
        .into_iter()
        .map(|r| {
            let c = match r {
                DropReason::BufferFull => &self.buffer_full,
                DropReason::Evicted => &self.evicted,
                DropReason::TooOld => &self.too_old,
                DropReason::Rejected => &self.rejected,
            };
            (r.as_str().to_owned(), c.load(Relaxed))
        })
        .collect()
    }
}

/// How a record left the edge's hands (for callers that wait, such as the update import, which
/// saves a result only once its event is acked or in the spool on disk, edge.md §14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Core acknowledged a batch holding it.
    Acked,
    /// Written to a spool segment and fsynced.
    Spooled,
    /// Dropped by the edge.
    Dropped(DropReason),
}

/// One buffered record.
pub(crate) struct Entry {
    pub seq: u64,
    pub ts: Timestamp,
    pub class: Class,
    pub line: Box<str>,
    pub answer: Option<Arc<Answer>>,
    pub receipt: Option<oneshot::Sender<Delivery>>,
}

impl Entry {
    pub(crate) fn resolve(&mut self, d: Delivery) {
        if let Some(tx) = self.receipt.take() {
            let _ = tx.send(d);
        }
    }
}

struct ProducerShared {
    boot: String,
    seq: AtomicU64,
    buffered: AtomicU64,
    tx: mpsc::UnboundedSender<Entry>,
    dropped: Arc<DropCounters>,
}

/// The handle every module logs through. Cheap to clone.
#[derive(Clone)]
pub struct LogProducer {
    inner: Arc<ProducerShared>,
}

/// The shipper's end of the producer: receives buffered entries and releases buffer slots.
pub struct ProducerRx {
    pub(crate) rx: mpsc::UnboundedReceiver<Entry>,
    inner: Arc<ProducerShared>,
}

impl ProducerRx {
    /// Gives back `n` buffer slots once records left the memory buffer (acked, spooled or
    /// dropped).
    pub(crate) fn release(&self, n: usize) {
        let _ = self
            .inner
            .buffered
            .try_update(Relaxed, Relaxed, |b| Some(b.saturating_sub(n as u64)));
    }

    /// Hands out `(boot, seq)` headers for records the shipper writes itself (answer copies).
    pub(crate) fn headers(&self) -> HeaderGen {
        HeaderGen {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Stamps records written after emission (each batch's or segment's copy of an answer) with a
/// fresh `seq` of this boot and `ts` = now.
#[derive(Clone)]
pub struct HeaderGen {
    inner: Arc<ProducerShared>,
}

impl HeaderGen {
    pub fn next(&self) -> RecordHeader {
        RecordHeader {
            ts: Timestamp::now(),
            boot: self.inner.boot.clone(),
            seq: self.inner.seq.fetch_add(1, Relaxed),
        }
    }

    /// A generator for tests.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        let (p, _rx) = LogProducer::new("t".into(), Arc::default());
        Self { inner: p.inner }
    }
}

impl LogProducer {
    /// A producer and the receiving end for the shipper. `boot` is this process's boot id.
    pub fn new(boot: String, dropped: Arc<DropCounters>) -> (Self, ProducerRx) {
        // Unbounded on purpose, yet bounded (README §2 Bounded): `buffered` counts every record
        // from its push until it leaves memory (acked, spooled or dropped,
        // [`ProducerRx::release`]), and a push past BUFFER_MAX is dropped and counted. That bound
        // also covers the batch the shipper holds, which a bounded channel wouldn't.
        let (tx, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(ProducerShared {
            boot,
            seq: AtomicU64::new(1),
            buffered: AtomicU64::new(0),
            tx,
            dropped,
        });
        (
            Self {
                inner: Arc::clone(&inner),
            },
            ProducerRx { rx, inner },
        )
    }

    pub fn boot(&self) -> &str {
        &self.inner.boot
    }

    pub fn dropped(&self) -> &Arc<DropCounters> {
        &self.inner.dropped
    }

    /// Emits a record stamped now. Returns false when it was dropped (buffer full).
    pub fn emit(&self, rec: LogRecord) -> bool {
        self.push(rec, None, None, false).0
    }

    /// Emits a record with an explicit `ts` (an update result's `at`, edge.md §14) and returns a
    /// receipt that resolves when core acks it, it is fsynced into the spool, or it is dropped.
    pub fn emit_at_with_receipt(&self, rec: LogRecord, ts: Timestamp) -> oneshot::Receiver<Delivery> {
        self.push(rec, None, Some(ts), true)
            .1
            .unwrap_or_else(|| oneshot::channel().1)
    }

    /// Emits a record and returns a receipt (see [`Self::emit_at_with_receipt`]).
    pub fn emit_with_receipt(&self, rec: LogRecord) -> oneshot::Receiver<Delivery> {
        self.push(rec, None, None, true)
            .1
            .unwrap_or_else(|| oneshot::channel().1)
    }

    /// Emits a `q` record with its upstream answer (or the note that it was over 4 KiB).
    pub fn emit_query(&self, mut q: QueryRecord, answer: AnswerSlot) -> bool {
        let answer = match answer {
            AnswerSlot::Attached(a) => Some(a),
            AnswerSlot::Oversized => {
                q.answer_id = None;
                q.received_at = None;
                q.age_s = None;
                q.truncated = true;
                None
            }
            AnswerSlot::None => None,
        };
        self.push(LogRecord::Query(Box::new(q)), answer, None, false).0
    }

    /// Emits an `event` record of `kind` with `fields` (api.md §5).
    pub fn event(&self, kind: &str, fields: serde_json::Map<String, serde_json::Value>) -> bool {
        self.emit(event_record(kind, fields))
    }

    fn push(
        &self,
        mut rec: LogRecord,
        answer: Option<Arc<Answer>>,
        ts: Option<Timestamp>,
        want_receipt: bool,
    ) -> (bool, Option<oneshot::Receiver<Delivery>>) {
        let (rtx, rrx) = if want_receipt {
            let (a, b) = oneshot::channel();
            (Some(a), Some(b))
        } else {
            (None, None)
        };
        let mut answer = answer;
        match &mut rec {
            // Answers ride along with the records that reference them (edge.md §11); an
            // unknown record has nothing to send.
            LogRecord::Answer(_) | LogRecord::Unknown => return (false, rrx),
            LogRecord::Query(q) => enforce_query_rules(q, &answer),
            _ => answer = None,
        }
        let prev = self.inner.buffered.fetch_add(1, Relaxed);
        if prev >= BUFFER_MAX as u64 {
            self.inner.buffered.fetch_sub(1, Relaxed);
            self.inner.dropped.add(DropReason::BufferFull, 1);
            if let Some(tx) = rtx {
                let _ = tx.send(Delivery::Dropped(DropReason::BufferFull));
            }
            return (false, rrx);
        }
        let ts = ts.unwrap_or_else(Timestamp::now);
        let seq = self.inner.seq.fetch_add(1, Relaxed);
        let h = RecordHeader {
            ts,
            boot: self.inner.boot.clone(),
            seq,
        };
        set_header(&mut rec, h);
        let class = classify(&rec);
        let line = match serde_json::to_string(&rec) {
            Ok(l) if l.len() <= MAX_LINE => l.into_boxed_str(),
            Ok(l) => {
                tracing::warn!("log record of {} bytes dropped (over {MAX_LINE})", l.len());
                self.inner.buffered.fetch_sub(1, Relaxed);
                self.inner.dropped.add(DropReason::Rejected, 1);
                if let Some(tx) = rtx {
                    let _ = tx.send(Delivery::Dropped(DropReason::Rejected));
                }
                return (false, rrx);
            }
            Err(e) => {
                tracing::warn!("log record not serialisable: {}", crate::diag::cap(e));
                self.inner.buffered.fetch_sub(1, Relaxed);
                self.inner.dropped.add(DropReason::Rejected, 1);
                if let Some(tx) = rtx {
                    let _ = tx.send(Delivery::Dropped(DropReason::Rejected));
                }
                return (false, rrx);
            }
        };
        let entry = Entry {
            seq,
            ts,
            class,
            line,
            answer,
            receipt: rtx,
        };
        if let Err(mpsc::error::SendError(mut e)) = self.inner.tx.send(entry) {
            // The shipper is gone (shutdown): nothing will carry the record.
            self.inner.buffered.fetch_sub(1, Relaxed);
            self.inner.dropped.add(DropReason::BufferFull, 1);
            e.resolve(Delivery::Dropped(DropReason::BufferFull));
            return (false, rrx);
        }
        (true, rrx)
    }
}

/// The producer's rules for a `q` record (api.md §5): `answer_id` names the answer that travels
/// with it; without one, `answer_id`, `received_at` and `age_s` go and `truncated` is set; a
/// `response` over 2 KiB decoded is left out and sets `truncated`.
fn enforce_query_rules(q: &mut QueryRecord, answer: &Option<Arc<Answer>>) {
    match answer {
        Some(a) => q.answer_id = Some(a.id.clone()),
        None => {
            if q.answer_id.take().is_some() {
                q.received_at = None;
                q.age_s = None;
                q.truncated = true;
            }
        }
    }
    if let Some(resp) = &q.response {
        let len = base64::engine::general_purpose::STANDARD
            .decode(resp)
            .map_or(usize::MAX, |b| b.len());
        if len > MAX_RESPONSE_WIRE {
            q.response = None;
            q.truncated = true;
        }
    }
}

/// Builds an `event` record (the header is filled in by the producer).
pub fn event_record(kind: &str, fields: serde_json::Map<String, serde_json::Value>) -> LogRecord {
    LogRecord::Event(EventRecord {
        h: placeholder_header(),
        kind: kind.to_owned(),
        fields,
    })
}

/// A header the producer overwrites.
pub fn placeholder_header() -> RecordHeader {
    RecordHeader {
        ts: Timestamp::UNIX_EPOCH,
        boot: String::new(),
        seq: 0,
    }
}

fn set_header(rec: &mut LogRecord, h: RecordHeader) {
    match rec {
        LogRecord::Query(r) => r.h = h,
        LogRecord::Answer(r) => r.h = h,
        LogRecord::Allow(r) => r.h = h,
        LogRecord::Lookup(r) => r.h = h,
        LogRecord::Condition(r) => r.h = h,
        LogRecord::Event(r) => r.h = h,
        LogRecord::Unknown => {}
    }
}

/// Builds event fields from pairs (`picket_api::logs::event_fields` re-exported for brevity).
pub fn fields(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    picket_api::logs::event_fields(pairs)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use picket_api::logs::{LookupItem, Versions};

    pub fn q(decision: Decision) -> QueryRecord {
        QueryRecord {
            h: placeholder_header(),
            listener: "lan-dns".into(),
            proto: Default::default(),
            client: "192.168.1.140".into(),
            device: None,
            profile: Some("kids".into()),
            qname: "example.com".into(),
            qtype: "A".into(),
            dnssec_ok: false,
            rcode: "NOERROR".into(),
            decision,
            reason: None,
            answers: vec![],
            targets: vec![],
            truncated: false,
            cname: vec![],
            lookups: vec![],
            upstream: None,
            fw: None,
            us: Default::default(),
            versions: Versions::default(),
            answer_id: None,
            received_at: None,
            age_s: None,
            response: None,
            tc: false,
            cold_unchecked: vec![],
            edns: None,
        }
    }

    #[test]
    fn classification_and_levels() {
        assert_eq!(classify_query(&q(Decision::Allow)), Class::Bulk);
        assert_eq!(classify_query(&q(Decision::Block)), Class::Security);
        assert_eq!(classify_query(&q(Decision::Rewrite)), Class::Security);
        assert_eq!(classify_query(&q(Decision::Servfail)), Class::Security);
        let mut failed = q(Decision::Allow);
        failed.lookups.push(LookupItem {
            verdict: LookupVerdict::Timeout,
            timed_out: true,
            retry: true,
            ..Default::default()
        });
        assert_eq!(classify_query(&failed), Class::Security);
        let mut cold = q(Decision::Allow);
        cold.cold_unchecked.push("block-common".into());
        assert_eq!(classify_query(&cold), Class::Security);
        assert_eq!(
            classify(&event_record("panic", Default::default())),
            Class::Security
        );

        assert!(query_admitted(LogLevel::Full, &q(Decision::Allow)));
        assert!(!query_admitted(LogLevel::Blocked, &q(Decision::Allow)));
        assert!(query_admitted(LogLevel::Blocked, &q(Decision::Block)));
        assert!(query_admitted(LogLevel::Blocked, &q(Decision::Refused)));
        assert!(query_admitted(LogLevel::Blocked, &failed));
        assert!(query_admitted(LogLevel::Blocked, &cold));
        assert!(!query_admitted(LogLevel::Off, &q(Decision::Block)));
        assert!(lookup_admitted(LogLevel::Blocked));
        assert!(!lookup_admitted(LogLevel::Off));
    }

    #[test]
    fn producer_stamps_boot_and_seq_and_enforces_answers() {
        let (p, mut rx) = LogProducer::new("b00t".into(), Arc::default());
        assert!(p.event("activated", fields(&[("config", "abc".into())])));
        let a = Answer::new(Bytes::from_static(b"\x00\x01wire")).unwrap();
        let mut rec = q(Decision::Allow);
        rec.received_at = Some(Timestamp::now());
        assert!(p.emit_query(rec.clone(), AnswerSlot::Attached(Arc::clone(&a))));
        let mut stray = rec.clone();
        stray.answer_id = Some("ffffffffffffffff".into());
        assert!(p.emit_query(stray, AnswerSlot::None));
        assert!(p.emit_query(rec, AnswerSlot::Oversized));

        let e1 = rx.rx.try_recv().unwrap();
        let e2 = rx.rx.try_recv().unwrap();
        let e3 = rx.rx.try_recv().unwrap();
        let e4 = rx.rx.try_recv().unwrap();
        assert_eq!((e1.seq, e2.seq), (1, 2));
        assert!(e1.line.contains("\"boot\":\"b00t\""));
        assert!(e2.line.contains(&format!("\"answer_id\":\"{}\"", a.id)));
        assert!(e2.answer.is_some());
        for e in [&e3, &e4] {
            assert!(!e.line.contains("answer_id"), "{}", e.line);
            assert!(!e.line.contains("received_at"), "{}", e.line);
            assert!(e.line.contains("\"truncated\":true"));
            assert!(e.answer.is_none());
        }
        assert!(Answer::new(Bytes::from(vec![0u8; MAX_ANSWER_WIRE + 1])).is_none());
        assert_eq!(a.id.len(), 16);
    }

    #[test]
    fn producer_caps_response_and_refuses_records_it_must_not_send_alone() {
        let (p, mut rx) = LogProducer::new("b".into(), Arc::default());
        let b64 = |n: usize| base64::engine::general_purpose::STANDARD.encode(vec![0u8; n]);
        // A reply over 2 KiB decoded is left out and marks the record truncated (api.md §5).
        let mut big = q(Decision::Rewrite);
        big.response = Some(b64(MAX_RESPONSE_WIRE + 1));
        assert!(p.emit_query(big, AnswerSlot::None));
        let mut fits = q(Decision::Rewrite);
        fits.response = Some(b64(MAX_RESPONSE_WIRE));
        assert!(p.emit_query(fits, AnswerSlot::None));
        // A `q` record emitted directly can't reference an answer that doesn't travel with it.
        let mut stray = q(Decision::Allow);
        stray.answer_id = Some("ffffffffffffffff".into());
        stray.age_s = Some(3);
        assert!(p.emit(LogRecord::Query(Box::new(stray))));
        // Answers ride along with the records that reference them; they're never sent alone.
        assert!(!p.emit(LogRecord::Answer(AnswerRecord {
            h: placeholder_header(),
            id: "0123456789abcdef".into(),
            wire: String::new(),
        })));
        assert!(!p.emit(LogRecord::Unknown));

        let e1 = rx.rx.try_recv().unwrap();
        assert!(!e1.line.contains("\"response\""), "{}", e1.line);
        assert!(e1.line.contains("\"truncated\":true"));
        let e2 = rx.rx.try_recv().unwrap();
        assert!(e2.line.contains("\"response\""));
        assert!(!e2.line.contains("\"truncated\":true"));
        let e3 = rx.rx.try_recv().unwrap();
        assert!(
            !e3.line.contains("answer_id") && !e3.line.contains("age_s"),
            "{}",
            e3.line
        );
        assert!(e3.line.contains("\"truncated\":true"));
        assert!(rx.rx.try_recv().is_err(), "nothing else queued");
        assert_eq!(p.dropped().snapshot()["buffer_full"], 0);
    }

    #[test]
    fn full_buffer_drops_and_counts() {
        let dropped = Arc::new(DropCounters::default());
        let (p, rx) = LogProducer::new("b".into(), Arc::clone(&dropped));
        for _ in 0..BUFFER_MAX {
            assert!(p.event("x", Default::default()));
        }
        assert!(!p.event("x", Default::default()));
        let r = p.emit_with_receipt(event_record("x", Default::default()));
        assert_eq!(
            r.blocking_recv().unwrap(),
            Delivery::Dropped(DropReason::BufferFull)
        );
        assert_eq!(dropped.snapshot()["buffer_full"], 2);
        rx.release(1);
        assert!(p.event("x", Default::default()));
    }
}
