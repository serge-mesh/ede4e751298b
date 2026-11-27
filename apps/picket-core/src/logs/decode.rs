//! Decoding a `POST /v1/logs` body (api.md §2, §5): gzip JSON lines → checked records.
//!
//! Every edge is untrusted (README §2): the body is bounded compressed and decompressed, a batch
//! holds at most [`picket_api::logs::MAX_BATCH_RECORDS`] lines, and each record is checked for
//! size, syntax and range before use. A batch core can't read at all is refused whole
//! ([`BatchError`]: `400` for bad gzip or too many records, `413` for too large), so the edge
//! splits it (edge.md §11); a record core can't parse or validate is dropped and counted, and the
//! rest of the batch still goes in (api.md §2). Timestamps are clamped to core's clock, and
//! records older than the log retention window are dropped as `too_old` (core.md §6), except
//! `answer` records: an answer is kept with the records that reference it, whatever its own time
//! (core.md §6, storage.md §4), and its `ts` is only when the edge wrote that copy.
//!
//! Pure functions of their inputs: fuzzed (`fuzz/core`, `log_batch`).

use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine as _;
use jiff::Timestamp;
use picket_api::logs::{
    AllowRecord, AnswerRecord, BundleVersion, ConditionRecord, EventRecord, LogRecord, LookupItem,
    LookupRecord, QueryRecord, RecordHeader, Versions,
};

/// Size bounds of a batch (README §2, Bounded). The edge keeps a batch under 4 MiB
/// uncompressed (its `BATCH_RAW_MAX`), so these leave room without letting one request cost
/// core more than a few tens of MiB.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The gzip body as received.
    pub max_body: usize,
    /// What the gzip stream may yield.
    pub max_decoded: usize,
    /// Lines (records, `answer` records included) per batch (api.md §5: ≤ 1,000).
    pub max_records: usize,
    /// One JSON line; a longer one is an invalid record, not a bad batch.
    pub max_line: usize,
}

pub const LIMITS: Limits = Limits {
    max_body: 16 << 20,
    max_decoded: 32 << 20,
    max_records: picket_api::logs::MAX_BATCH_RECORDS,
    max_line: 256 << 10,
};

/// Why a whole batch is refused (api.md §2): the edge splits it in half and resends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BatchError {
    #[error("the body isn't readable gzip")]
    BadGzip,
    #[error("more than 1000 records in one batch")]
    TooManyRecords,
    #[error("the batch is too large")]
    TooLarge,
}

impl BatchError {
    /// The HTTP status the edge's splitter expects: `400` or `413`.
    pub fn status(self) -> u16 {
        match self {
            Self::BadGzip | Self::TooManyRecords => 400,
            Self::TooLarge => 413,
        }
    }
}

/// Why one record was dropped (`log_dropped{edge, reason}`, core.md §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DropReason {
    /// It couldn't be parsed or validated.
    Invalid,
    /// Older than the log retention window.
    TooOld,
    /// Parsed and checked, but storing it failed for a reason of its own.
    StoreFailed,
}

impl DropReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::TooOld => "too_old",
            Self::StoreFailed => "store_failed",
        }
    }
}

/// What a record is checked against.
#[derive(Clone, Copy, Debug)]
pub struct Context {
    /// Core's clock: later timestamps are clamped to it.
    pub now: Timestamp,
    /// The oldest event time kept (now − the log retention window).
    pub oldest: Timestamp,
}

/// A checked `answer` record: its wire decoded, its id verified against the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub h: RecordHeader,
    pub id: String,
    pub wire: Vec<u8>,
}

/// A checked `q` record, with its `response` decoded and its `versions` in canonical form.
#[derive(Clone, Debug, PartialEq)]
pub struct Query {
    pub q: Box<QueryRecord>,
    /// Its `ts` was in a later hour than core's clock and was clamped to now, so its partition
    /// depends on when it arrives (ingest pins it to its first attempt's hour).
    pub from_later_hour: bool,
    /// The decoded `response`, if any.
    pub response: Option<Vec<u8>>,
    /// Canonical JSON of `versions` (keys sorted, no whitespace) and its BLAKE3 (storage.md §3).
    pub versions_json: String,
    pub versions_blake3: String,
}

/// One checked record.
#[derive(Clone, Debug, PartialEq)]
pub enum Record {
    Query(Query),
    Answer(Answer),
    Allow(AllowRecord),
    Lookup(LookupRecord),
    Condition(ConditionRecord),
    Event(EventRecord),
}

impl Record {
    pub fn header(&self) -> &RecordHeader {
        match self {
            Self::Query(q) => &q.q.h,
            Self::Answer(a) => &a.h,
            Self::Allow(r) => &r.h,
            Self::Lookup(r) => &r.h,
            Self::Condition(r) => &r.h,
            Self::Event(r) => &r.h,
        }
    }
}

/// A decoded batch: the records that passed, and what was dropped.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Batch {
    pub records: Vec<Record>,
    pub dropped: BTreeMap<DropReason, u64>,
    /// Lines in the batch (records and answers, dropped ones included).
    pub lines: usize,
    /// The batch's last record (its last line with a readable `boot` and `seq`), dropped or
    /// not: what the ack names (api.md §2, §5).
    pub last: Option<picket_api::logs::AckPoint>,
}

impl Batch {
    fn drop_one(&mut self, r: DropReason) {
        *self.dropped.entry(r).or_insert(0) += 1;
    }

    /// The ack (api.md §2, §5): the batch's last record, whether core kept it or not. Empty
    /// when no line has a readable `boot` and `seq` (the edge ignores the body).
    pub fn ack(&self) -> picket_api::logs::AckPoint {
        self.last.clone().unwrap_or_default()
    }
}

/// Decompresses a gzip body, refusing more than `max` decoded bytes.
pub fn gunzip(body: &[u8], max: usize) -> Result<Vec<u8>, BatchError> {
    let mut out = Vec::with_capacity(body.len().saturating_mul(4).min(max.min(4 << 20)));
    let mut d = flate2::read::GzDecoder::new(body).take(max as u64 + 1);
    d.read_to_end(&mut out).map_err(|_| BatchError::BadGzip)?;
    if out.len() > max {
        return Err(BatchError::TooLarge);
    }
    Ok(out)
}

/// Decodes a whole body: `gzip` says whether it carries `Content-Encoding: gzip` (api.md §5:
/// it must). Whole-batch problems are errors; per-record problems are counted in the batch.
pub fn decode_body(body: &[u8], gzip: bool, ctx: &Context, limits: &Limits) -> Result<Batch, BatchError> {
    if body.len() > limits.max_body {
        return Err(BatchError::TooLarge);
    }
    if !gzip {
        return Err(BatchError::BadGzip);
    }
    let text = gunzip(body, limits.max_decoded)?;
    decode_lines(&text, ctx, limits)
}

/// Decodes JSON lines (already decompressed).
pub fn decode_lines(text: &[u8], ctx: &Context, limits: &Limits) -> Result<Batch, BatchError> {
    let lines: Vec<&[u8]> = text
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
        .collect();
    if lines.len() > limits.max_records {
        return Err(BatchError::TooManyRecords);
    }
    let mut batch = Batch {
        lines: lines.len(),
        last: lines
            .iter()
            .rev()
            .filter(|l| l.len() <= limits.max_line)
            .find_map(|l| ack_point(l)),
        ..Default::default()
    };
    for line in lines {
        if line.len() > limits.max_line {
            batch.drop_one(DropReason::Invalid);
            continue;
        }
        match decode_record(line, ctx) {
            Ok(r) => batch.records.push(r),
            Err(reason) => batch.drop_one(reason),
        }
    }
    Ok(batch)
}

/// A line's `boot` and `seq`, when they are readable whatever else is wrong with it.
fn ack_point(line: &[u8]) -> Option<picket_api::logs::AckPoint> {
    #[derive(serde::Deserialize)]
    struct Head {
        boot: String,
        seq: u64,
    }
    let h: Head = serde_json::from_slice(line).ok()?;
    (is_boot_id(&h.boot) && h.seq <= i64::MAX as u64).then_some(picket_api::logs::AckPoint {
        boot: h.boot,
        seq: h.seq,
    })
}

// ---------------------------------------------------------------------------------------------
// Bounds on record fields (api.md §5 where it gives them; README §2 Bounded elsewhere)

/// A log-text name: up to 255 wire bytes, each escaped as `\DDD` at worst.
pub const MAX_NAME: usize = 1100;
const MAX_ID: usize = 128;
const MAX_SHORT: usize = 64;
const MAX_DEVICE: usize = 256;
const MAX_TEXT: usize = 512;
const MAX_DETAIL: usize = 4096;
const MAX_EVENT_FIELDS: usize = 16 << 10;
const MAX_CNAME: usize = 32;
const MAX_LOOKUPS: usize = 32;
const MAX_COLD_UNCHECKED: usize = 256;
const MAX_VERSION_BUNDLES: usize = 512;
const MAX_VERSION_PARTS: usize = 4096;
const MAX_VERSIONS_JSON: usize = 256 << 10;

fn short(s: &str, max: usize) -> bool {
    s.len() <= max
}

fn opt_short(s: &Option<String>, max: usize) -> bool {
    s.as_deref().is_none_or(|s| s.len() <= max)
}

/// A boot id: random per process start (edge.md §11); 1–64 of `[0-9A-Za-z_-]`.
pub fn is_boot_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SHORT
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// An event or condition kind: 1–64 of `[a-z0-9_]`.
pub fn is_kind(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SHORT
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A short answer id: the first 16 hex characters of a BLAKE3 (api.md §5).
pub fn is_short_id(s: &str) -> bool {
    picket_api::ids::is_id64(s)
}

fn json_len(v: &serde_json::Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(usize::MAX)
}

fn detail_ok(v: &Option<serde_json::Value>) -> bool {
    v.as_ref().is_none_or(|v| json_len(v) <= MAX_DETAIL)
}

/// A lookup's `detail`: the module's detail of the answer, a small JSON object (providers.md §4
/// "Detail"; api.md §5), so the query log, alerts and evidence all hold an object or nothing.
fn lookup_detail_ok(v: &Option<serde_json::Value>) -> bool {
    v.as_ref().is_none_or(serde_json::Value::is_object) && detail_ok(v)
}

/// Checks a header, clamping `ts` to core's clock; `too_old` below the window.
fn check_header(h: &mut RecordHeader, ctx: &Context) -> Result<(), DropReason> {
    check_header_ids(h, ctx)?;
    if h.ts < ctx.oldest {
        return Err(DropReason::TooOld);
    }
    Ok(())
}

/// Checks a header's `boot` and `seq` and clamps its `ts` to core's clock, with no age check.
fn check_header_ids(h: &mut RecordHeader, ctx: &Context) -> Result<(), DropReason> {
    if !is_boot_id(&h.boot) || h.seq > i64::MAX as u64 {
        return Err(DropReason::Invalid);
    }
    h.ts = picket_api::time::clamp_to_now(h.ts, ctx.now);
    Ok(())
}

fn b64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')))
        .ok()
}

/// Checks `versions` and returns its canonical JSON and BLAKE3.
pub fn check_versions(v: &Versions) -> Option<(String, String)> {
    if !short(&v.config, MAX_SHORT) || v.bundles.len() > MAX_VERSION_BUNDLES {
        return None;
    }
    for (b, bv) in &v.bundles {
        if !short(b, MAX_ID) {
            return None;
        }
        match bv {
            BundleVersion::Plain(h) => {
                if !short(h, MAX_SHORT) {
                    return None;
                }
            }
            BundleVersion::Parts(p) => {
                let parts = p.shards.len() + p.cold_shards.len() + p.ip_shards.len() + p.segments.len();
                if !short(&p.head, MAX_SHORT) || parts > MAX_VERSION_PARTS {
                    return None;
                }
            }
        }
    }
    if v.not_loaded.cold.len() > MAX_VERSION_BUNDLES || v.not_loaded.verdict_sets.len() > MAX_VERSION_BUNDLES
    {
        return None;
    }
    let value = serde_json::to_value(v).ok()?;
    let bytes = picket_api::ids::canonical_json(&value);
    if bytes.len() > MAX_VERSIONS_JSON {
        return None;
    }
    let id = picket_api::ids::object_id(&bytes);
    Some((String::from_utf8(bytes).ok()?, id))
}

fn check_lookup_item(l: &LookupItem) -> bool {
    !l.provider.is_empty()
        && short(&l.provider, MAX_ID)
        && opt_short(&l.reason, MAX_TEXT)
        && short(&l.generation, MAX_SHORT)
        && lookup_detail_ok(&l.detail)
        && l.score.is_none_or(f32::is_finite)
}

fn check_query(mut q: Box<QueryRecord>, ctx: &Context) -> Result<Query, DropReason> {
    let from_later_hour = super::partition::hour_start(&q.h.ts) > super::partition::hour_start(&ctx.now);
    check_header(&mut q.h, ctx)?;
    let ok = short(&q.listener, MAX_ID)
        && q.client.len() <= MAX_SHORT
        && q.client.parse::<std::net::IpAddr>().is_ok()
        && opt_short(&q.device, MAX_DEVICE)
        && opt_short(&q.profile, MAX_SHORT)
        && short(&q.qname, MAX_NAME)
        && short(&q.qtype, 16)
        && short(&q.rcode, 16)
        && q.answers.len() <= picket_api::logs::MAX_PREVIEW
        && q.answers.iter().all(|a| short(a, MAX_SHORT))
        && q.targets.len() <= picket_api::logs::MAX_PREVIEW
        && q.targets.iter().all(|t| short(t, MAX_NAME))
        && q.cname.len() <= MAX_CNAME
        && q.cname.iter().all(|t| short(t, MAX_NAME))
        && q.lookups.len() <= MAX_LOOKUPS
        && q.lookups.iter().all(check_lookup_item)
        && q.cold_unchecked.len() <= MAX_COLD_UNCHECKED
        && q.cold_unchecked.iter().all(|b| short(b, MAX_ID))
        && q.answer_id.as_deref().is_none_or(is_short_id)
        && q.reason.as_ref().is_none_or(|r| {
            opt_short(&r.bundle, MAX_ID)
                && opt_short(&r.key, MAX_NAME)
                && opt_short(&r.block_id, MAX_SHORT)
                && opt_short(&r.provider, MAX_ID)
                && opt_short(&r.allow_id, MAX_SHORT)
                && opt_short(&r.value, MAX_NAME)
        })
        && q.upstream
            .as_ref()
            .is_none_or(|u| short(&u.group, MAX_ID) && opt_short(&u.upstream, MAX_ID));
    if !ok {
        return Err(DropReason::Invalid);
    }
    if let Some(r) = q.received_at {
        q.received_at = Some(picket_api::time::clamp_to_now(r, ctx.now));
    }
    let response = match q.response.as_deref() {
        None => None,
        Some(s) => {
            let wire = b64(s).ok_or(DropReason::Invalid)?;
            if wire.len() > picket_api::logs::MAX_RESPONSE_WIRE {
                return Err(DropReason::Invalid);
            }
            Some(wire)
        }
    };
    let (versions_json, versions_blake3) = check_versions(&q.versions).ok_or(DropReason::Invalid)?;
    Ok(Query {
        q,
        from_later_hour,
        response,
        versions_json,
        versions_blake3,
    })
}

fn check_answer(mut a: AnswerRecord, ctx: &Context) -> Result<Answer, DropReason> {
    // No age check: the answer goes with the records that reference it (core.md §6), and the
    // edge writes it once per spool segment, so its `ts` may be older than theirs.
    check_header_ids(&mut a.h, ctx)?;
    if !is_short_id(&a.id) || a.wire.len() > (picket_api::logs::MAX_ANSWER_WIRE / 3 + 2) * 4 {
        return Err(DropReason::Invalid);
    }
    let wire = b64(&a.wire).ok_or(DropReason::Invalid)?;
    if wire.is_empty() || wire.len() > picket_api::logs::MAX_ANSWER_WIRE {
        return Err(DropReason::Invalid);
    }
    // The id names the wire (api.md §5): one that doesn't is corrupt, and must not shadow the
    // real answer under that id in the partition.
    if picket_api::ids::short_id(&picket_api::ids::object_id(&wire)) != a.id {
        return Err(DropReason::Invalid);
    }
    Ok(Answer {
        h: a.h,
        id: a.id,
        wire,
    })
}

fn check_allow(mut r: AllowRecord, ctx: &Context) -> Result<AllowRecord, DropReason> {
    check_header(&mut r.h, ctx)?;
    let ok = !r.allow_id.is_empty()
        && short(&r.allow_id, MAX_SHORT)
        && short(&r.client, MAX_SHORT)
        && opt_short(&r.device, MAX_DEVICE)
        && short(&r.target, MAX_NAME)
        && opt_short(&r.block_id, MAX_SHORT)
        && opt_short(&r.profile, MAX_SHORT)
        && short(&r.via, 32);
    if !ok {
        return Err(DropReason::Invalid);
    }
    Ok(r)
}

fn check_lookup(mut r: LookupRecord, ctx: &Context) -> Result<LookupRecord, DropReason> {
    check_header(&mut r.h, ctx)?;
    let ok = opt_short(&r.profile, MAX_SHORT)
        && short(&r.qname, MAX_NAME)
        && !r.provider.is_empty()
        && short(&r.provider, MAX_ID)
        && opt_short(&r.reason, MAX_TEXT)
        && short(&r.generation, MAX_SHORT)
        && lookup_detail_ok(&r.detail)
        && r.score.is_none_or(f32::is_finite);
    if !ok {
        return Err(DropReason::Invalid);
    }
    if let Some(t) = r.obtained_at {
        r.obtained_at = Some(picket_api::time::clamp_to_now(t, ctx.now));
    }
    Ok(r)
}

fn check_condition(mut r: ConditionRecord, ctx: &Context) -> Result<ConditionRecord, DropReason> {
    check_header(&mut r.h, ctx)?;
    if !is_kind(&r.kind) || !opt_short(&r.key, MAX_ID) || !detail_ok(&r.detail) {
        return Err(DropReason::Invalid);
    }
    r.time = picket_api::time::clamp_to_now(r.time, ctx.now);
    Ok(r)
}

fn check_event(mut r: EventRecord, ctx: &Context) -> Result<EventRecord, DropReason> {
    check_header(&mut r.h, ctx)?;
    if !is_kind(&r.kind) {
        return Err(DropReason::Invalid);
    }
    let size = serde_json::to_vec(&r.fields)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    if size > MAX_EVENT_FIELDS {
        return Err(DropReason::Invalid);
    }
    Ok(r)
}

/// Decodes and checks one JSON line.
pub fn decode_record(line: &[u8], ctx: &Context) -> Result<Record, DropReason> {
    let rec: LogRecord = serde_json::from_slice(line).map_err(|_| DropReason::Invalid)?;
    Ok(match rec {
        LogRecord::Query(q) => Record::Query(check_query(q, ctx)?),
        LogRecord::Answer(a) => Record::Answer(check_answer(a, ctx)?),
        LogRecord::Allow(a) => Record::Allow(check_allow(a, ctx)?),
        LogRecord::Lookup(l) => Record::Lookup(check_lookup(l, ctx)?),
        LogRecord::Condition(c) => Record::Condition(check_condition(c, ctx)?),
        LogRecord::Event(e) => Record::Event(check_event(e, ctx)?),
        // A record kind this release doesn't know: dropped and counted (api.md §2).
        LogRecord::Unknown => return Err(DropReason::Invalid),
    })
}

/// A string field of an event record, if it is a short string.
pub fn event_str<'a>(e: &'a EventRecord, key: &str) -> Option<&'a str> {
    e.fields
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|s| s.len() <= MAX_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn ctx() -> Context {
        let now = "2026-11-13T12:00:00Z".parse::<Timestamp>().unwrap();
        Context {
            now,
            oldest: now - jiff::SignedDuration::from_hours(72),
        }
    }

    fn gz(text: &str) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(text.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    fn answer_line(seq: u64, wire: &[u8]) -> String {
        let id = picket_api::ids::short_id(&picket_api::ids::object_id(wire)).to_string();
        let b = base64::engine::general_purpose::STANDARD.encode(wire);
        format!(
            r#"{{"t":"answer","ts":"2026-11-13T10:22:01.874213Z","boot":"7f3a91","seq":{seq},"id":"{id}","wire":"{b}"}}"#
        )
    }

    const Q: &str = r#"{"t":"q","ts":"2026-11-13T10:22:01.123456Z","boot":"7f3a91","seq":1042,"listener":"lan-dns","proto":"udp","client":"192.168.1.140","device":"emma-tablet","profile":"kids","qname":"ads.example.com","qtype":"A","do":false,"rcode":"NOERROR","decision":"block","reason":{"step":3,"bundle":"block-common","key":"example.com","kind":"subs","stage":"query","block_id":"k3j9q2"},"answers":["0.0.0.0"],"targets":[],"truncated":false,"cname":[],"lookups":[],"upstream":null,"fw":null,"us":{"total":41,"filter":6},"versions":{"config":"9f3a91c27d0e4b6a","bundles":{"allow-common":"4be1d2a07c9e3f15"}}}"#;

    #[test]
    fn whole_batch_errors_map_to_the_splitter_statuses() {
        let c = ctx();
        assert_eq!(
            decode_body(b"not gzip", true, &c, &LIMITS),
            Err(BatchError::BadGzip)
        );
        assert_eq!(BatchError::BadGzip.status(), 400);
        assert_eq!(decode_body(&gz(Q), false, &c, &LIMITS), Err(BatchError::BadGzip));
        let many: String = (0..1001)
            .map(|i| Q.replace("1042", &i.to_string()) + "\n")
            .collect();
        assert_eq!(
            decode_body(&gz(&many), true, &c, &LIMITS),
            Err(BatchError::TooManyRecords)
        );
        assert_eq!(BatchError::TooManyRecords.status(), 400);
        let small = Limits {
            max_decoded: 100,
            ..LIMITS
        };
        assert_eq!(
            decode_body(&gz(&"x".repeat(1000)), true, &c, &small),
            Err(BatchError::TooLarge)
        );
        let tiny = Limits {
            max_body: 10,
            ..LIMITS
        };
        assert_eq!(decode_body(&gz(Q), true, &c, &tiny), Err(BatchError::TooLarge));
        assert_eq!(BatchError::TooLarge.status(), 413);
        // Exactly 1000 lines is fine.
        let ok: String = (0..1000)
            .map(|i| Q.replace("1042", &i.to_string()) + "\n")
            .collect();
        assert_eq!(
            decode_body(&gz(&ok), true, &c, &LIMITS).unwrap().records.len(),
            1000
        );
    }

    /// K3 (providers.md §4 "Detail": a small JSON object; README §2 Untrusted input): a lookup
    /// whose detail isn't an object is a bad item, so its record is dropped and counted (as one
    /// too large is); no detail, or null, is none.
    #[test]
    fn a_lookup_detail_is_an_object_or_nothing() {
        let c = ctx();
        let q = |seq: u64, detail: &str| {
            let item = format!(
                r#"[{{"provider":"q9","verdict":"clean","cached":false,"gen":"g1","ms":5,"timed_out":false,"retry":false,"detail":{detail}}}]"#
            );
            Q.replace("1042", &seq.to_string())
                .replace(r#""lookups":[]"#, &format!(r#""lookups":{item}"#))
        };
        let lookup = |seq: u64, detail: &str| {
            format!(
                r#"{{"t":"lookup","ts":"2026-11-13T10:22:01.874213Z","boot":"7f3a91","seq":{seq},"profile":"adults","qname":"bad.example.org","provider":"q9","verdict":"block","reason":"blocked","obtained_at":"2026-11-13T10:22:02.118204Z","gen":"b71e4d09a2c63f58","ms":171,"detail":{detail}}}"#
            )
        };
        let text = [
            q(1, r#"{"server":"9.9.9.9"}"#),
            q(2, "null"),
            q(3, r#""text""#),
            q(4, "[1, 2]"),
            lookup(5, r#"{"server":"9.9.9.9"}"#),
            lookup(6, "42"),
        ]
        .join("\n");
        let b = decode_body(&gz(&text), true, &c, &LIMITS).unwrap();
        let kept: Vec<u64> = b
            .records
            .iter()
            .map(|r| match r {
                Record::Query(q) => q.q.h.seq,
                Record::Lookup(l) => l.h.seq,
                _ => panic!("{r:?}"),
            })
            .collect();
        assert_eq!(kept, [1, 2, 5]);
        assert_eq!(b.dropped[&DropReason::Invalid], 3);
    }

    #[test]
    fn bad_records_are_dropped_and_counted_and_the_rest_kept() {
        let c = ctx();
        let wire = b"\x12\x34\x81\x80\x00\x01";
        let text = [
            answer_line(1, wire),
            Q.to_string(),
            "{not json".into(),
            r#"{"t":"future","ts":"2026-11-13T10:22:01Z","boot":"b","seq":1}"#.into(),
            Q.replace("2026-11-13T10:22", "2026-11-01T10:22"),
            Q.replace(r#""client":"192.168.1.140""#, r#""client":"not an ip""#),
            Q.replace(r#""boot":"7f3a91""#, r#""boot":"bad boot!""#),
            // An answer whose id doesn't name its wire.
            answer_line(2, wire).replace("\"seq\":2", "\"seq\":3").replace(
                picket_api::ids::short_id(&picket_api::ids::object_id(wire)),
                "0000000000000000",
            ),
        ]
        .join("\n");
        let b = decode_body(&gz(&text), true, &c, &LIMITS).unwrap();
        assert_eq!(b.lines, 8);
        assert_eq!(b.records.len(), 2);
        assert_eq!(b.dropped[&DropReason::Invalid], 5);
        assert_eq!(b.dropped[&DropReason::TooOld], 1);
        let Record::Answer(a) = &b.records[0] else {
            panic!()
        };
        assert_eq!(a.wire, wire);
        let Record::Query(q) = &b.records[1] else { panic!() };
        assert_eq!(q.q.h.seq, 1042);
        assert_eq!(q.versions_blake3.len(), 64);
        // The ack names the batch's last record (the dropped answer, seq 3).
        assert_eq!(b.ack().seq, 3);
        assert_eq!(b.ack().boot, "7f3a91");
    }

    #[test]
    fn an_old_answer_is_kept_for_the_records_that_reference_it() {
        // core.md §6, storage.md §4 (review A9): an answer goes with its records, whatever its
        // own time; only the records' times decide `too_old`.
        let c = ctx();
        let wire = b"\x12\x34\x81\x80\x00\x01";
        let old = answer_line(1, wire).replace("2026-11-13T10:22:01.874213Z", "2026-11-09T10:00:00Z");
        let b = decode_lines(format!("{old}\n{Q}").as_bytes(), &c, &LIMITS).unwrap();
        assert!(b.dropped.is_empty(), "{:?}", b.dropped);
        assert!(matches!(b.records[0], Record::Answer(_)));
    }

    #[test]
    fn the_ack_names_the_batch_last_record_even_when_it_was_dropped() {
        // api.md §2, §5 (review nit): the ack is the batch's last record.
        let c = ctx();
        let dropped = Q
            .replace(r#""seq":1042"#, r#""seq":1043"#)
            .replace(r#""client":"192.168.1.140""#, r#""client":"not an ip""#);
        let b = decode_lines(format!("{Q}\n{dropped}").as_bytes(), &c, &LIMITS).unwrap();
        assert_eq!(b.records.len(), 1);
        assert_eq!(b.ack().seq, 1043);
        // A last line with no readable header: the line before it.
        let b = decode_lines(format!("{Q}\n{{not json").as_bytes(), &c, &LIMITS).unwrap();
        assert_eq!((b.ack().boot.as_str(), b.ack().seq), ("7f3a91", 1042));
        // Nothing readable: empty.
        let b = decode_lines(b"{not json", &c, &LIMITS).unwrap();
        assert_eq!(b.ack(), Default::default());
    }

    #[test]
    fn a_record_from_a_later_hour_is_flagged() {
        let c = ctx();
        let later = Q.replace("2026-11-13T10:22:01.123456Z", "2026-11-13T13:00:01Z");
        let Record::Query(q) = decode_record(later.as_bytes(), &c).unwrap() else {
            panic!()
        };
        assert!(q.from_later_hour);
        assert_eq!(q.q.h.ts, c.now);
        let same = Q.replace("2026-11-13T10:22:01.123456Z", "2026-11-13T12:30:00Z");
        let Record::Query(q) = decode_record(same.as_bytes(), &c).unwrap() else {
            panic!()
        };
        assert!(!q.from_later_hour, "clamped within the same hour");
    }

    #[test]
    fn future_timestamps_are_clamped_to_core_clock() {
        let c = ctx();
        let line = Q.replace("2026-11-13T10:22:01.123456Z", "2030-01-01T00:00:00Z");
        let Record::Query(q) = decode_record(line.as_bytes(), &c).unwrap() else {
            panic!()
        };
        assert_eq!(q.q.h.ts, c.now);
    }

    #[test]
    fn oversized_fields_are_invalid() {
        let c = ctx();
        let long = "a".repeat(MAX_NAME + 1);
        let line = Q.replace("ads.example.com", &long);
        assert_eq!(decode_record(line.as_bytes(), &c), Err(DropReason::Invalid));
        let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 2049]);
        let line = Q.replace(r#""answers""#, &format!(r#""response":"{big}","answers""#));
        assert_eq!(decode_record(line.as_bytes(), &c), Err(DropReason::Invalid));
        let line = Q.replace(r#""seq":1042"#, r#""seq":18446744073709551615"#);
        assert_eq!(decode_record(line.as_bytes(), &c), Err(DropReason::Invalid));
    }
}
