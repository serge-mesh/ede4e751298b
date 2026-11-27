//! The cache value and cache-hit serving (edge.md §8), and core's rebuild of the reply a client
//! got (core.md §6).
//!
//! A value holds, per copy (the full scrubbed answer, and a DO=0 copy when there was something to
//! strip), the message hickory encoded, the range of its answer and authority records (the blob a
//! hit copies), and the offset of every record header TTL with its original value, found once at
//! insert by walking the encoded copy. It also holds the rcode, the received time, the `answer`
//! record id slot and the extracted facts, so a hit runs response checks without parsing.
//!
//! Serving a hit writes the header, copies the client's question bytes, copies the right blob,
//! sets each TTL to the original less its age (at least 0) clamped to the profile's `ttl`, and
//! appends our own OPT with the client's DO only if the query had one. Over the client's limit it
//! sends the header, the question and any OPT with TC set; so does an upstream answer that had TC
//! set, whose records may be partial (RFC 1035 §4.1.1). The cached answer is never decoded or
//! re-encoded. The blob's compression pointers stay valid because every client's question for a
//! cache key has the length of the question the copy was encoded with (the query check refuses a
//! compressed question name).

use std::time::{Instant, SystemTime};

use hickory_proto::op::{Header, MessageType, Metadata, OpCode, Query as HQuery};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use picket_api::edge_config::TtlClamp;

use crate::answer::{
    AnswerFacts, AnswerLimits, EncodedCopy, Invalid, ScrubbedAnswer, SentQuery, check_answer,
};
use crate::ede::EdeOption;
use crate::edns::{Item, read_item};
use crate::name::{NameRef, WireName};
use crate::reply::{Body, Flags, Reply, ReplyTo, TtlRule, assemble, assemble_flags};
use crate::wire::{WriteError, get_u16};

/// A cached upstream answer (edge.md §8 "Value").
#[derive(Clone, Debug)]
pub struct CacheValue {
    question_len: u16,
    qtype: u16,
    full: EncodedCopy,
    stripped: Option<EncodedCopy>,
    facts: AnswerFacts,
    received_at: SystemTime,
    received_mono: Instant,
    /// The id of this answer's `answer` log record ([`crate::log::answer_id`] of
    /// [`CacheValue::wire`], api.md §5), set by the edge once it logs the answer.
    pub answer_id: Option<u64>,
}

impl CacheValue {
    /// The value for a checked answer, received at `received_at` (wall clock, logged as
    /// `received_at`) and `received_mono` (monotonic, for ages).
    pub fn new(answer: ScrubbedAnswer, received_at: SystemTime, received_mono: Instant) -> Self {
        Self {
            question_len: answer.question_len,
            qtype: answer.qtype,
            full: answer.full,
            stripped: answer.stripped,
            facts: answer.facts,
            received_at,
            received_mono,
            answer_id: None,
        }
    }

    /// Core: the value the edge held for a logged `answer` wire (api.md §5), so a reply is
    /// rebuilt with the same copies, offsets and DO=0 predicate as the edge served it. The wire is
    /// checked like an upstream answer, with its own ID and question; the scrub is idempotent, so
    /// the full copy equals the logged wire.
    pub fn from_logged_wire(
        wire: &[u8],
        received_at: SystemTime,
        received_mono: Instant,
    ) -> Result<Self, Invalid> {
        let mut dec = BinDecoder::new(wire);
        let header = Header::read(&mut dec).map_err(|_| Invalid::ShortHeader)?;
        if header.counts.queries != 1 {
            return Err(Invalid::QuestionCount);
        }
        let q = HQuery::read(&mut dec).map_err(|_| Invalid::Undecodable)?;
        let qname = WireName::from_hickory(q.name()).map_err(|_| Invalid::Undecodable)?;
        let sent = SentQuery {
            id: header.id,
            qname: qname.as_name(),
            qtype: u16::from(q.query_type()),
            qclass: u16::from(q.query_class()),
        };
        let answer = check_answer(wire, &sent, &AnswerLimits::default())?;
        Ok(Self::new(answer, received_at, received_mono))
    }

    /// What the answer says: names and addresses for response checks, rcode, TTLs.
    pub fn facts(&self) -> &AnswerFacts {
        &self.facts
    }

    pub fn rcode(&self) -> u16 {
        self.facts.rcode
    }

    /// The question type the answer is for.
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    /// How long the entry may be cached; `None` when it may not be (edge.md §8: TC, EDE 3, …).
    pub fn ttl(&self) -> Option<u32> {
        self.facts.cache_ttl
    }

    pub fn is_cacheable(&self) -> bool {
        self.facts.cache_ttl.is_some()
    }

    /// True for NXDOMAIN and NODATA (never served stale, edge.md §8).
    pub fn is_negative(&self) -> bool {
        self.facts.negative.is_some()
    }

    /// The scrubbed answer message: what the `answer` log record carries (api.md §5).
    pub fn wire(&self) -> &[u8] {
        &self.full.msg
    }

    /// The question the answer is for, as the copies carry it (lowercase name, QTYPE, QCLASS):
    /// the length of every client question for this cache key. Core rebuilds a reply with it
    /// ([`ReplyTo::logged`]).
    pub fn question(&self) -> &[u8] {
        let end = 12usize.saturating_add(usize::from(self.question_len));
        self.full.msg.get(12..end).unwrap_or(&[])
    }

    /// The answer's CD bit: the CD of the query sent upstream, which is the client's (part of the
    /// cache key, edge.md §8; upstreams copy it, RFC 4035 §3.1.6).
    pub fn cd(&self) -> bool {
        get_u16(&self.full.msg, 2).is_some_and(|flags| flags & 0x0010 != 0)
    }

    /// True when a DO=0 copy exists (there was something to strip).
    pub fn has_stripped_copy(&self) -> bool {
        self.stripped.is_some()
    }

    pub fn received_at(&self) -> SystemTime {
        self.received_at
    }

    pub fn received_mono(&self) -> Instant {
        self.received_mono
    }

    /// Whole seconds since the answer was received (`age_s`, api.md §5).
    pub fn age_s(&self, now: Instant) -> u32 {
        u32::try_from(now.saturating_duration_since(self.received_mono).as_secs()).unwrap_or(u32::MAX)
    }

    /// True once the entry is older than its TTL (or was never cacheable).
    pub fn is_expired(&self, now: Instant) -> bool {
        self.ttl().is_none_or(|t| self.age_s(now) >= t)
    }

    /// Bytes the value holds, for the cache's byte weigher.
    pub fn weight(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.full.heap_size())
            .saturating_add(self.stripped.as_ref().map_or(0, EncodedCopy::heap_size))
            .saturating_add(self.facts.heap_size())
    }

    /// The copy a client gets: the DO=0 copy, when there is one, for a client without DO.
    fn copy_for(&self, do_bit: bool) -> &EncodedCopy {
        match (&self.stripped, do_bit) {
            (Some(s), false) => s,
            _ => &self.full,
        }
    }

    /// The bytes a hit copies for a client with or without DO (tests and diagnostics).
    pub fn blob(&self, do_bit: bool) -> &[u8] {
        self.copy_for(do_bit).blob()
    }

    /// The whole encoded message of a copy (tests).
    #[cfg(test)]
    pub(crate) fn copy_message(&self, do_bit: bool) -> &[u8] {
        &self.copy_for(do_bit).msg
    }
}

/// How a hit is served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeParams<'a> {
    /// Whole seconds the answer has been cached (0 for a fresh answer).
    pub age_s: u32,
    /// The profile's `ttl` clamp.
    pub clamp: TtlClamp,
    /// Serve as a stale answer: every TTL `stale_ttl`, plus EDE 3 with `cause=…` (edge.md §8).
    pub stale: Option<StaleServe<'a>>,
}

/// The stale variant of a hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaleServe<'a> {
    pub ttl: u32,
    /// `optimistic`, or the last upstream failure (edge.md §4 EDE).
    pub cause: &'a str,
}

impl<'a> ServeParams<'a> {
    /// The EDE a reply carries: EDE 3 with `cause=…` when served stale (edge.md §4 EDE table).
    fn ede(&self) -> Option<EdeOption<'a>> {
        self.stale.map(|s| EdeOption::stale(s.cause))
    }

    fn rule(&self) -> TtlRule {
        match self.stale {
            Some(s) => TtlRule::Fixed(s.ttl),
            None => TtlRule::Aged {
                age: self.age_s,
                clamp: self.clamp,
            },
        }
    }
}

/// Serves a cache hit (or a fresh answer, with `age_s` 0) into `out`, without decoding the
/// cached answer. `out` must hold `to.limit` bytes or the whole reply.
pub fn serve_hit(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    value: &CacheValue,
    p: &ServeParams<'_>,
) -> Result<Reply, WriteError> {
    if to.question.len() != usize::from(value.question_len) {
        return Err(WriteError::QuestionLength);
    }
    let copy = value.copy_for(to.do_bit());
    let stale_ede = p.ede();
    let ede = stale_ede.as_slice();
    // An upstream answer with TC set may be partial: the client gets the TC form, never records
    // it would take for the whole answer (RFC 1035 §4.1.1, RFC 2181 §9).
    let flags = Flags {
        aa: false,
        truncated: value.facts.tc,
    };
    assemble_flags(
        out,
        to,
        value.rcode(),
        flags,
        Body::Blob {
            bytes: copy.blob(),
            an: copy.an,
            ns: copy.ns,
            ttls: &copy.ttls,
            rule: p.rule(),
        },
        ede,
    )
}

/// Core: rebuilds the reply a client got from the value of its logged answer (core.md §6), byte
/// for byte as the edge served it but for the ID and the question's letter case. `to` comes from
/// [`ReplyTo::logged`], so the size limit, OPT and padding are the edge's: EDE tokens and options
/// are dropped, and TC set, exactly where the edge did. `p` is the record's `age_s`, its
/// profile's `ttl` and, on a stale answer (`upstream.stale`), its config's `stale_ttl` and the
/// logged `upstream.cause`. `logged_tc` is the record's `tc`: a rebuild that disagrees with it is
/// [`WriteError::TcMismatch`], since the record's fields then don't describe what the client got.
/// `out` must hold the reply.
pub fn rebuild_reply(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    value: &CacheValue,
    p: &ServeParams<'_>,
    logged_tc: bool,
) -> Result<Reply, WriteError> {
    let r = serve_hit(out, to, value, p)?;
    if r.tc != logged_tc {
        return Err(WriteError::TcMismatch);
    }
    Ok(r)
}

/// A CNAME rewrite (edge.md §4 "Rewrites"): the CNAME from the question's name to `target`,
/// plus the target's answer under the original question. The target's copy (DO=0 or full, by
/// the client's DO) is decoded and, with the CNAME ahead of it, re-encoded by hickory, since its
/// pointers were made for the target's question; its TTLs are aged and clamped per `p`. A stale
/// target answer (`p.stale`) is served as a hit on it would be: its records at `stale_ttl` and
/// EDE 3 with the cause (edge.md §4 EDE table); the rewrite itself adds no EDE. A target answer
/// with TC set gives the TC form, as a hit on it would.
pub fn write_cname_rewrite(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    cname_ttl: u32,
    target: NameRef<'_>,
    target_answer: &CacheValue,
    p: &ServeParams<'_>,
) -> Result<Reply, WriteError> {
    let stale_ede = p.ede();
    let ede = stale_ede.as_slice();
    if target_answer.facts.tc {
        let flags = Flags {
            aa: false,
            truncated: true,
        };
        return assemble_flags(out, to, target_answer.rcode(), flags, Body::Empty, ede);
    }
    let copy = target_answer.copy_for(to.do_bit());
    let rule = p.rule();

    // The client's question, decoded by hickory (it passed the query check: uncompressed).
    let mut qd = BinDecoder::new(to.question);
    let qname = Name::read(&mut qd).map_err(|_| WriteError::Encode)?;
    let qtype = qd.read_u16().map_err(|_| WriteError::Encode)?.unverified();
    let qclass = qd.read_u16().map_err(|_| WriteError::Encode)?.unverified();
    let target_name = target.to_hickory().ok_or(WriteError::Encode)?;

    // The target copy's records, decoded by hickory within their own message.
    let base = BinDecoder::new(&copy.msg);
    let start = u16::try_from(copy.records.start).map_err(|_| WriteError::Encode)?;
    let mut dec = base.clone(start);
    let mut records: Vec<Record> = Vec::with_capacity(
        usize::from(copy.an)
            .saturating_add(usize::from(copy.ns))
            .saturating_add(1),
    );
    let mut cname = Record::from_rdata(qname.clone(), cname_ttl, RData::CNAME(CNAME(target_name)));
    // IN for the QCLASS-only values ANY and NONE, as every record the edge makes.
    cname.dns_class = DNSClass::from(to.record_class());
    records.push(cname);
    for _ in 0..usize::from(copy.an).saturating_add(usize::from(copy.ns)) {
        match read_item(&mut dec) {
            Ok(Item::Record(mut r)) => {
                r.rec.ttl = rule.apply(r.rec.ttl);
                records.push(r.rec);
            }
            _ => return Err(WriteError::Encode),
        }
    }
    let an = copy.an.checked_add(1).ok_or(WriteError::TooLong)?;
    let ns = copy.ns;

    let mut header = Header {
        metadata: Metadata::new(to.id, MessageType::Response, OpCode::Query),
        counts: Default::default(),
    };
    header.counts.queries = 1;
    header.counts.answers = an;
    header.counts.authorities = ns;
    let mut question = HQuery::query(qname, RecordType::from(qtype));
    question.set_query_class(DNSClass::from(qclass));
    let mut buf: Vec<u8> = Vec::with_capacity(
        copy.msg
            .len()
            .saturating_add(to.question.len())
            .saturating_add(64),
    );
    {
        let mut enc = BinEncoder::new(&mut buf);
        header.emit(&mut enc).map_err(|_| WriteError::Encode)?;
        question.emit(&mut enc).map_err(|_| WriteError::Encode)?;
        for r in &records {
            r.emit(&mut enc).map_err(|_| WriteError::Encode)?;
        }
    }
    let records_at = 12usize.saturating_add(to.question.len());
    // hickory wrote the question exactly as the client sent it, so the pointers in the records
    // line up with the reply `assemble` writes.
    if buf.get(12..records_at) != Some(to.question) {
        return Err(WriteError::Encode);
    }
    let body = buf.get(records_at..).ok_or(WriteError::Encode)?;
    assemble(
        out,
        to,
        target_answer.rcode(),
        Body::Blob {
            bytes: body,
            an,
            ns,
            ttls: &[],
            rule: TtlRule::Fixed(0),
        },
        ede,
    )
}
