//! The upstream answer pipeline (edge.md §7), used by the edge for every upstream answer, by
//! picket-lookup's `dns` module (providers.md §5) and by core to rebuild a reply (core.md §6).
//!
//! 1. **Structure.** Before the body is decoded: the message is within the size cap; it is a
//!    QUERY response with one question and the ID that was sent; then its header counts at most
//!    [`MAX_SECTION_RECORDS`] records per section. hickory then decodes the body (label and name
//!    lengths, backward non-overlapping pointers, RDLENGTH within the message, the formats of
//!    the types it knows).
//!    The question matches what was sent; nothing trails; at most one OPT, in the additional
//!    section; at most 8 CNAME/DNAME hops. Where hickory reads data outside its type's format, the
//!    record makes the answer invalid in any section, kept or not: empty data for a type that
//!    needs data, an empty TXT, a broken NSEC/NSEC3 type bitmap, and SVCB/HTTPS parameters RFC 9460
//!    forbids (§2.2; [`crate::svcb`]). A DNAME target is decoded with hickory's name decoder over
//!    the record data alone and must be one uncompressed name that fills it. A kept record of a
//!    type whose data may hold compressed names that hickory doesn't decode makes the answer
//!    invalid; other undecoded data stays opaque (RFC 3597 §4).
//! 2. **Scrub.** Answer owners of every type are limited to the question and its CNAME/DNAME chain
//!    (bailiwick); answer types to the qtype, CNAME, DNAME, RRSIG, NSEC and NSEC3; classes to the
//!    question's (any class for QCLASS *, RFC 1035 §3.2.5). The authority
//!    and additional sections are dropped except the OPT (without its Padding option), the SOA for
//!    negative caching (judged against the chain's terminal name) and the NSEC/NSEC3 proofs. An
//!    RRSIG stays when it covers an RRset the scrub keeps in its section; a question for RRSIG
//!    keeps the answer's RRSIGs. An ambiguous chain (two CNAME targets at one owner, a DNAME whose
//!    synthesised CNAME conflicts with the CNAME present) is invalid. With
//!    [`AnswerLimits::max_rrset`] set, a kept answer RRset over it makes the answer invalid
//!    (`rrset_too_large`); records the scrub drops never count toward it.
//! 3. **Encode.** hickory encodes the kept records, so compression pointers point only at names it
//!    wrote, never at record data such as a TTL (edge.md §8). The DO=0 copy is encoded separately
//!    from its own record list when there is something to strip.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Range;

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Header, MessageType, Metadata, OpCode, Query as HQuery, ResponseCode};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder, Restrict};
use thiserror::Error;

use crate::MAX_MESSAGE;
use crate::dnssec::strip_for_do0;
use crate::edns::{EdnsOptions, Item, ItemError, OptRecord, parse_ede, read_item};
use crate::name::{MAX_WIRE, NameRef, WireName};
use crate::reply::normalize_ttl;
use crate::types::{class, ede_code, edns_code, is_meta_type, may_hold_compressed_names, rcode, rtype};
use crate::wire::{TtlSlot, walk_ttls};

/// The most records per section an upstream answer may claim in its header (edge.md §7). A
/// safety bound on the work one answer can cause, not a judgement of what is normal: a 65,535-byte
/// TCP answer holds about 4,000 address records, and real answers (large TXT sets, address pools)
/// pass 64. What a kept RRset may hold is [`AnswerLimits::max_rrset`]'s job.
pub const MAX_SECTION_RECORDS: u16 = 1024;
/// The default [`AnswerLimits::max_rrset`] the edge applies to upstream answers: above BIND's 100
/// (`max-records-per-type`), which real domains are known to pass.
pub const DEFAULT_MAX_RRSET: u16 = 256;
/// Below this many decoded records, exact duplicates are found by a linear scan, which allocates
/// nothing; from it on, by a hash index, so a large answer costs linear time rather than quadratic.
const LINEAR_SCAN_MAX: usize = 32;
/// The most distinct RRSIG signers of the answer section that anchor NSEC/NSEC3 proofs in the
/// authority section when no SOA does: a real answer has one per zone of its chain, at most
/// [`MAX_CNAME_HOPS`] + 1; the bound keeps the proof check linear in the authority section.
const MAX_SIGNER_ANCHORS: usize = 16;
/// The most CNAME/DNAME hops in a chain (edge.md §7).
pub const MAX_CNAME_HOPS: usize = 8;
/// The most EDE options kept in an answer's facts. More is well-formed (README "Health"): the
/// rest are counted in [`AnswerFacts::ede_dropped`] ("Bounded"), and every option is still
/// scanned for EDE 3.
pub const MAX_EDE: usize = 8;

/// The answer size caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerLimits {
    /// The largest message accepted (default: the 65,535-byte DNS maximum; the edge may pass
    /// its transport's receive limit).
    pub max_len: usize,
    /// The most records one kept answer RRset (owner, type, class) may hold, counted after
    /// duplicates are removed; `None` (the default) for no limit beyond
    /// [`MAX_SECTION_RECORDS`]. The edge sets it for upstream answers (`limits.max_rrset_records`,
    /// default [`DEFAULT_MAX_RRSET`]); re-checks of answers already accepted (cache restores,
    /// core's replays) and lookups leave it unset.
    pub max_rrset: Option<u16>,
}

impl Default for AnswerLimits {
    fn default() -> Self {
        Self {
            max_len: MAX_MESSAGE,
            max_rrset: None,
        }
    }
}

/// What was sent: the answer must carry the same ID and question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentQuery<'a> {
    pub id: u16,
    /// The query name as sent (lowercase wire form); the answer's question matches it
    /// case-insensitively.
    pub qname: NameRef<'a>,
    pub qtype: u16,
    pub qclass: u16,
}

/// Why an upstream answer is invalid, per reason for counters (edge.md §7 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Error)]
pub enum Invalid {
    #[error("over the size cap")]
    TooLarge,
    #[error("header unreadable")]
    ShortHeader,
    #[error("QR clear")]
    NotResponse,
    #[error("opcode is not QUERY")]
    Opcode,
    #[error("more than 1024 records in a section")]
    TooManyRecords,
    #[error("QDCOUNT is not 1")]
    QuestionCount,
    #[error("ID differs from the query's")]
    IdMismatch,
    #[error("hickory couldn't decode the message")]
    Undecodable,
    #[error("question differs from the query's")]
    QuestionMismatch,
    #[error("trailing bytes")]
    TrailingBytes,
    #[error("OPT outside the additional section")]
    OptNotAdditional,
    #[error("more than one OPT")]
    DuplicateOpt,
    #[error("malformed OPT or EDE option")]
    MalformedOpt,
    #[error("more than 8 CNAME/DNAME hops")]
    CnameHops,
    #[error("CNAME/DNAME loop")]
    CnameLoop,
    #[error("ambiguous CNAME/DNAME chain")]
    AmbiguousChain,
    #[error("DNAME target compressed or not filling its data")]
    DnameTarget,
    #[error("empty data for a type that needs data")]
    EmptyRdata,
    #[error("undecoded data of a type that may hold compressed names")]
    OpaqueCompressible,
    #[error("SVCB/HTTPS parameters RFC 9460 forbids")]
    BadSvcb,
    #[error("encoding the scrubbed answer failed")]
    Encode,
    #[error("a kept answer RRset over the record limit")]
    RrsetTooLarge,
}

impl Invalid {
    /// Every reason, so counters can be registered up front.
    pub const ALL: [Invalid; 22] = [
        Self::TooLarge,
        Self::ShortHeader,
        Self::NotResponse,
        Self::Opcode,
        Self::TooManyRecords,
        Self::QuestionCount,
        Self::IdMismatch,
        Self::Undecodable,
        Self::QuestionMismatch,
        Self::TrailingBytes,
        Self::OptNotAdditional,
        Self::DuplicateOpt,
        Self::MalformedOpt,
        Self::CnameHops,
        Self::CnameLoop,
        Self::AmbiguousChain,
        Self::DnameTarget,
        Self::EmptyRdata,
        Self::OpaqueCompressible,
        Self::BadSvcb,
        Self::Encode,
        Self::RrsetTooLarge,
    ];

    /// A stable reason name for counters (`invalid` per reason and upstream, edge.md §7).
    pub fn reason(&self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::ShortHeader => "short_header",
            Self::NotResponse => "not_response",
            Self::Opcode => "opcode",
            Self::TooManyRecords => "too_many_records",
            Self::QuestionCount => "question_count",
            Self::IdMismatch => "id_mismatch",
            Self::Undecodable => "undecodable",
            Self::QuestionMismatch => "question_mismatch",
            Self::TrailingBytes => "trailing_bytes",
            Self::OptNotAdditional => "opt_not_additional",
            Self::DuplicateOpt => "duplicate_opt",
            Self::MalformedOpt => "malformed_opt",
            Self::CnameHops => "cname_hops",
            Self::CnameLoop => "cname_loop",
            Self::AmbiguousChain => "ambiguous_chain",
            Self::DnameTarget => "dname_target",
            Self::EmptyRdata => "empty_rdata",
            Self::OpaqueCompressible => "opaque_compressible",
            Self::BadSvcb => "bad_svcb",
            Self::Encode => "encode",
            Self::RrsetTooLarge => "rrset_too_large",
        }
    }

    /// True when the answer was refused for its size alone ([`Self::TooManyRecords`],
    /// [`Self::RrsetTooLarge`]), both reached only once the header matched the query: a limit,
    /// not a sign the upstream is broken, so the edge leaves its breaker alone (edge.md §6).
    pub fn is_size_limit(&self) -> bool {
        matches!(self, Self::TooManyRecords | Self::RrsetTooLarge)
    }

    /// True when the refusal says nothing about the upstream's health, so the edge fails the
    /// attempt without judging it (edge.md §6): a size limit ([`Self::is_size_limit`]), or
    /// [`Self::BadSvcb`], an SVCB/HTTPS record that decodes but whose parameters RFC 9460 forbids.
    /// That is one domain's data, which the upstream relays (it reached the records, so the header
    /// and question matched); counting it would let one such domain open a resolver-wide breaker.
    /// Undecodable answers, identity and protocol errors stay health signals.
    pub fn leaves_upstream_unjudged(&self) -> bool {
        self.is_size_limit() || matches!(self, Self::BadSvcb)
    }
}

/// Records the scrub removed, by reason (edge.md §7 step 3: "Scrub removals are counted").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrubCounts {
    /// Answer records whose owner isn't the question or a chain name.
    pub out_of_bailiwick: u16,
    /// Answer records of a type other than the qtype, CNAME, DNAME, RRSIG, NSEC and NSEC3.
    pub unexpected_type: u16,
    /// Answer records of another class than the question's.
    pub wrong_class: u16,
    /// RRSIGs that cover no RRset the scrub keeps.
    pub rrsig: u16,
    /// Authority records other than the negative-caching SOA, the proofs and their RRSIGs.
    pub authority: u16,
    /// Additional records other than the OPT.
    pub additional: u16,
    /// Exact duplicates of an earlier record in the same section.
    pub duplicate: u16,
    /// The OPT's Padding option (RFC 7830), 0 or 1.
    pub padding: u16,
}

impl ScrubCounts {
    /// Every reason's stable counter name, in [`Self::labelled`]'s order, so counters can be
    /// registered up front.
    pub const REASONS: [&'static str; 8] = [
        "out_of_bailiwick",
        "unexpected_type",
        "wrong_class",
        "rrsig",
        "authority",
        "additional",
        "duplicate",
        "padding",
    ];

    /// `(reason, count)` for every reason, for per-reason counters.
    pub fn labelled(&self) -> [(&'static str, u16); 8] {
        let [a, b, c, d, e, f, g, h] = Self::REASONS;
        [
            (a, self.out_of_bailiwick),
            (b, self.unexpected_type),
            (c, self.wrong_class),
            (d, self.rrsig),
            (e, self.authority),
            (f, self.additional),
            (g, self.duplicate),
            (h, self.padding),
        ]
    }

    pub fn total(&self) -> u32 {
        self.labelled()
            .iter()
            .map(|&(_, v)| u32::from(v))
            .fold(0u32, u32::saturating_add)
    }
}

/// An Extended DNS Error an upstream answer carried (RFC 8914).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdeInfo {
    pub code: u16,
    /// EXTRA-TEXT, lossily decoded as UTF-8; empty when absent.
    pub text: String,
}

/// Where an extracted address came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrSource {
    A,
    Aaaa,
    Ipv4Hint,
    Ipv6Hint,
}

/// An address response checks look at (rules.md §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerAddr {
    pub ip: IpAddr,
    pub source: AddrSource,
}

impl AddrSource {
    /// True for an HTTPS/SVCB hint (response-check stage `svcb`, api.md §5), false for A and
    /// AAAA (stage `answer_ip`).
    pub fn is_hint(self) -> bool {
        matches!(self, Self::Ipv4Hint | Self::Ipv6Hint)
    }
}

impl AnswerAddr {
    /// The IPv4 address inside an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
    pub fn mapped_v4(&self) -> Option<Ipv4Addr> {
        match self.ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
            IpAddr::V4(_) => None,
        }
    }

    /// The address IP rules match: an IPv4-mapped IPv6 address matches as its IPv4 address
    /// (rules.md §6).
    pub fn match_ip(&self) -> IpAddr {
        self.mapped_v4().map_or(self.ip, IpAddr::V4)
    }
}

/// A negative answer (RFC 2308).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Negative {
    Nxdomain,
    Nodata,
}

/// What the scrubbed answer says, extracted once so cache hits and lookups never parse it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerFacts {
    /// The full rcode, with the OPT's upper bits.
    pub rcode: u16,
    pub tc: bool,
    pub aa: bool,
    /// The CNAME chain after the question name, DNAME-synthesised CNAMEs included, in order.
    pub chain: Vec<WireName>,
    /// A and AAAA addresses of chain names, then HTTPS/SVCB hints, in answer order.
    pub addrs: Vec<AnswerAddr>,
    /// HTTPS/SVCB target names other than the root.
    pub targets: Vec<WireName>,
    /// The first [`MAX_EDE`] EDE options, in order.
    pub ede: Vec<EdeInfo>,
    /// EDE options past the first [`MAX_EDE`], left out of `ede` and counted (README "Bounded").
    pub ede_dropped: u16,
    /// The answer carries EDE 3 (Stale Answer), in any position: never cached; withheld from DO
    /// clients (edge.md §7 step 3, §8).
    pub stale: bool,
    pub negative: Option<Negative>,
    /// The scrubbed answer kept a negative-caching SOA in its authority section.
    pub soa: bool,
    /// The smallest header TTL of the kept records (RFC 2181 §8: top-bit values count as 0).
    pub min_ttl: Option<u32>,
    /// RFC 2308 §5: min(SOA TTL, SOA MINIMUM) of the kept SOA.
    pub negative_ttl: Option<u32>,
    /// How long the answer may be cached; `None` when it may not be (TC, EDE 3, an rcode other
    /// than NOERROR/NXDOMAIN, a negative answer without an SOA, or a TTL of 0).
    pub cache_ttl: Option<u32>,
}

impl AnswerFacts {
    /// Heap bytes held, for cache weighers.
    pub fn heap_size(&self) -> usize {
        let names = self
            .chain
            .iter()
            .chain(self.targets.iter())
            .map(|n| n.heap_size().saturating_add(std::mem::size_of::<WireName>()))
            .fold(0usize, usize::saturating_add);
        let addrs = self
            .addrs
            .capacity()
            .saturating_mul(std::mem::size_of::<AnswerAddr>());
        let ede = self
            .ede
            .iter()
            .map(|e| e.text.capacity().saturating_add(std::mem::size_of::<EdeInfo>()))
            .fold(0usize, usize::saturating_add);
        names.saturating_add(addrs).saturating_add(ede)
    }
}

/// One encoded copy of a scrubbed answer: a whole message as hickory encoded it, the range of
/// its answer and authority records (the bytes a cache hit copies), and every record header TTL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncodedCopy {
    pub msg: Box<[u8]>,
    pub records: Range<usize>,
    pub an: u16,
    pub ns: u16,
    pub ttls: Box<[TtlSlot]>,
}

impl EncodedCopy {
    pub(crate) fn blob(&self) -> &[u8] {
        self.msg.get(self.records.clone()).unwrap_or(&[])
    }

    pub(crate) fn heap_size(&self) -> usize {
        self.msg
            .len()
            .saturating_add(self.ttls.len().saturating_mul(std::mem::size_of::<TtlSlot>()))
    }
}

/// A checked, scrubbed and encoded upstream answer.
#[derive(Clone, Debug)]
pub struct ScrubbedAnswer {
    pub(crate) full: EncodedCopy,
    pub(crate) stripped: Option<EncodedCopy>,
    pub(crate) question_len: u16,
    pub(crate) qtype: u16,
    /// What the answer says.
    pub facts: AnswerFacts,
    /// What the scrub removed.
    pub removed: ScrubCounts,
}

impl ScrubbedAnswer {
    /// The scrubbed answer message, as the cache holds it and the `answer` log record stores it
    /// (api.md §5): original TTLs, DNSSEC records included, the upstream's OPT without Padding.
    pub fn wire(&self) -> &[u8] {
        &self.full.msg
    }

    /// True when a DO=0 copy was encoded (there was something to strip).
    pub fn has_stripped_copy(&self) -> bool {
        self.stripped.is_some()
    }
}

/// True when `msg` is a response to the query with ID `id` that has TC set, read from its header
/// alone: a UDP transport retries such an answer over TCP before checking it (RFC 7766 §5;
/// providers.md §5 `dns`), since a truncated answer may be cut anywhere.
pub fn is_truncated_response(msg: &[u8], id: u16) -> bool {
    let mut dec = BinDecoder::new(msg);
    Header::read(&mut dec)
        .is_ok_and(|h| h.id == id && h.message_type == MessageType::Response && h.truncation)
}

/// Checks, scrubs and encodes an upstream answer to `sent` (edge.md §7).
pub fn check_answer(
    msg: &[u8],
    sent: &SentQuery<'_>,
    limits: &AnswerLimits,
) -> Result<ScrubbedAnswer, Invalid> {
    let a = analyze(msg, sent, limits)?;
    let full = encode(&a, msg, Which::Full)?;
    let stripped = if a.kept.iter().any(|k| strip_for_do0(k.rtype, a.qtype)) {
        Some(encode(&a, msg, Which::Stripped)?)
    } else {
        None
    };
    Ok(ScrubbedAnswer {
        full,
        stripped,
        question_len: a.question_len,
        qtype: a.qtype,
        facts: a.facts,
        removed: a.removed,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Section {
    Answer,
    Authority,
    Additional,
}

struct Rec {
    section: Section,
    owner: WireName,
    rtype: u16,
    class: u16,
    rec: Record,
}

/// What makes two records exact duplicates: section, type, class, owner and data.
type RecKey<'a> = (Section, u16, u16, &'a WireName, &'a RData);

impl Rec {
    fn key(&self) -> RecKey<'_> {
        (self.section, self.rtype, self.class, &self.owner, &self.rec.data)
    }
}

/// Finds exact duplicates among the decoded records: a linear scan below [`LINEAR_SCAN_MAX`]
/// records (no allocation, the common case), then a hash index (randomly keyed, so an upstream
/// can't aim collisions at it) from each record's hash to the first record with that hash.
#[derive(Default)]
struct DupIndex {
    index: Option<(RandomState, HashMap<u64, usize>)>,
}

impl DupIndex {
    /// True when `cand` duplicates a record in `recs`. When it doesn't, the caller pushes it next
    /// (it is indexed at `recs.len()`).
    fn is_dup(&mut self, recs: &[Rec], cand: RecKey<'_>) -> bool {
        if self.index.is_none() && recs.len() < LINEAR_SCAN_MAX {
            return recs.iter().any(|p| p.key() == cand);
        }
        let (state, map) = self.index.get_or_insert_with(|| {
            let state = RandomState::new();
            let mut map = HashMap::with_capacity(recs.len().saturating_mul(2));
            for (i, p) in recs.iter().enumerate() {
                map.entry(state.hash_one(p.key())).or_insert(i);
            }
            (state, map)
        });
        let h = state.hash_one(cand);
        match map.get(&h) {
            Some(&i) if recs.get(i).is_some_and(|p| p.key() == cand) => true,
            // A 64-bit collision with a different record: the scan settles it.
            Some(_) => recs.iter().any(|p| p.key() == cand),
            None => {
                map.insert(h, recs.len());
                false
            }
        }
    }
}

/// A link of the chain: the name, and how it was reached.
#[derive(Clone, Debug)]
struct Link {
    name: WireName,
    /// The DNAME record (index into the answer list) that synthesised this name, if any.
    dname: Option<usize>,
    /// True when the answer also holds the synthesised CNAME (or a plain CNAME led here).
    has_cname: bool,
    /// TTL for a CNAME synthesised in the DO=0 copy: the DNAME's.
    dname_ttl: u32,
}

struct Kept {
    section: Section,
    rtype: u16,
    /// Index into the answer list for answer records (to place synthesised CNAMEs).
    answer_idx: Option<usize>,
    rec: Record,
}

impl Kept {
    /// The SOA kept for negative caching: the only SOA the scrub keeps in the authority section.
    fn is_negative_soa(&self) -> bool {
        self.section == Section::Authority && self.rtype == rtype::SOA
    }
}

/// The decoded, checked and scrubbed answer, before encoding.
pub(crate) struct Analysis {
    header: Header,
    question: HQuery,
    question_len: u16,
    qtype: u16,
    opt: Option<OptRecord>,
    kept: Vec<Kept>,
    chain: Vec<Link>,
    facts: AnswerFacts,
    removed: ScrubCounts,
}

impl Analysis {
    pub(crate) fn facts(&self) -> &AnswerFacts {
        &self.facts
    }
}

/// Decodes and checks an answer and decides the scrub, without encoding (lookups stop here).
pub(crate) fn analyze(msg: &[u8], sent: &SentQuery<'_>, limits: &AnswerLimits) -> Result<Analysis, Invalid> {
    // 1. Structure, from the header, before the body is decoded.
    if msg.len() > limits.max_len.min(MAX_MESSAGE) {
        return Err(Invalid::TooLarge);
    }
    let mut dec = BinDecoder::new(msg);
    let header = Header::read(&mut dec).map_err(|_| Invalid::ShortHeader)?;
    let counts = header.counts;
    if header.message_type != MessageType::Response {
        return Err(Invalid::NotResponse);
    }
    if header.op_code != OpCode::Query {
        return Err(Invalid::Opcode);
    }
    if counts.queries != 1 {
        return Err(Invalid::QuestionCount);
    }
    if header.id != sent.id {
        return Err(Invalid::IdMismatch);
    }
    // After the header says this is the response to what was sent: a refusal for size alone
    // isn't a health signal for the edge, so it must not be reachable by a reply that isn't one.
    if counts.answers > MAX_SECTION_RECORDS
        || counts.authorities > MAX_SECTION_RECORDS
        || counts.additionals > MAX_SECTION_RECORDS
    {
        return Err(Invalid::TooManyRecords);
    }

    // hickory decodes the body.
    let qname = Name::read(&mut dec).map_err(|_| Invalid::Undecodable)?;
    let qtype = read_u16(&mut dec)?;
    let qclass = read_u16(&mut dec)?;
    let qwire = WireName::from_hickory(&qname).map_err(|_| Invalid::Undecodable)?;
    if qwire.wire() != sent.qname.wire() || qtype != sent.qtype || qclass != sent.qclass {
        return Err(Invalid::QuestionMismatch);
    }
    // The encoded copies carry the question uncompressed, as sent: the same length as every
    // client's question for this cache key (edge.md §8).
    let question_len =
        u16::try_from(qwire.wire().len().saturating_add(4)).map_err(|_| Invalid::Undecodable)?;

    // The header's counts are unchecked claims: room for more than a few is made as records
    // decode, so a lying header can't make this allocate for records that aren't there.
    let mut recs: Vec<Rec> = Vec::with_capacity(
        usize::from(counts.answers)
            .saturating_add(usize::from(counts.authorities))
            .saturating_add(usize::from(counts.additionals))
            .min(LINEAR_SCAN_MAX),
    );
    let mut dups = DupIndex::default();
    let mut opt: Option<OptRecord> = None;
    let mut removed = ScrubCounts::default();
    for (section, count) in [
        (Section::Answer, counts.answers),
        (Section::Authority, counts.authorities),
        (Section::Additional, counts.additionals),
    ] {
        for _ in 0..count {
            match read_item(&mut dec) {
                Ok(Item::Opt(o)) => {
                    if section != Section::Additional {
                        return Err(Invalid::OptNotAdditional);
                    }
                    if opt.is_some() {
                        return Err(Invalid::DuplicateOpt);
                    }
                    opt = Some(o);
                }
                Ok(Item::Record(r)) => {
                    let owner = WireName::from_hickory(&r.rec.name).map_err(|_| Invalid::Undecodable)?;
                    let mut rec = r.rec;
                    rec.name = rec.name.to_lowercase();
                    if dups.is_dup(&recs, (section, r.rtype, r.class, &owner, &rec.data)) {
                        removed.duplicate = removed.duplicate.saturating_add(1);
                        continue;
                    }
                    recs.push(Rec {
                        section,
                        owner,
                        rtype: r.rtype,
                        class: r.class,
                        rec,
                    });
                }
                Err(ItemError::Decode) => return Err(Invalid::Undecodable),
                Err(ItemError::MalformedOpt) => return Err(Invalid::MalformedOpt),
                Err(ItemError::BadSvcb) => return Err(Invalid::BadSvcb),
            }
        }
    }
    if !dec.is_empty() {
        return Err(Invalid::TrailingBytes);
    }

    // EDE options (RFC 8914): every one is checked and scanned for EDE 3; the first MAX_EDE are
    // kept with their text, the rest counted.
    let mut ede: Vec<EdeInfo> = Vec::new();
    let mut ede_dropped: u16 = 0;
    let mut stale = false;
    if let Some(o) = &opt {
        let data = msg.get(o.options.clone()).ok_or(Invalid::MalformedOpt)?;
        for (code, payload) in EdnsOptions::new(data) {
            if code == edns_code::EDE {
                let (info, text) = parse_ede(payload).ok_or(Invalid::MalformedOpt)?;
                stale |= info == ede_code::STALE_ANSWER;
                if ede.len() < MAX_EDE {
                    ede.push(EdeInfo {
                        code: info,
                        text: String::from_utf8_lossy(text).into_owned(),
                    });
                } else {
                    ede_dropped = ede_dropped.saturating_add(1);
                }
            } else if code == edns_code::PADDING {
                removed.padding = removed.padding.saturating_add(1);
            }
        }
    }
    let full_rcode =
        (u16::from(opt.as_ref().map_or(0, |o| o.ext_rcode)) << 4) | u16::from(header.response_code.low());

    // 2. The chain over the answer section.
    let answer: Vec<&Rec> = recs.iter().filter(|r| r.section == Section::Answer).collect();
    let (chain, applied_dnames) = build_chain(&answer, &qwire, qclass)?;
    let in_chain = |n: &WireName| chain.iter().any(|l| l.name == *n);

    // Answer section: bailiwick, expected types; RRSIGs decided once the RRsets are known.
    let mut keep_answer = vec![false; answer.len()];
    for (i, r) in answer.iter().enumerate() {
        if r.rtype == rtype::RRSIG {
            continue;
        }
        if !class_matches(qclass, r.class) {
            removed.wrong_class = removed.wrong_class.saturating_add(1);
            continue;
        }
        if r.rtype == rtype::DNAME {
            let asked = qtype == rtype::DNAME || qtype == rtype::ANY;
            if applied_dnames.contains(&i) || (asked && in_chain(&r.owner)) {
                // A kept DNAME's target must decode (edge.md §7 step 1).
                dname_target(r)?;
                mark(&mut keep_answer, i);
            } else if in_chain(&r.owner) {
                removed.unexpected_type = removed.unexpected_type.saturating_add(1);
            } else {
                removed.out_of_bailiwick = removed.out_of_bailiwick.saturating_add(1);
            }
            continue;
        }
        if !in_chain(&r.owner) {
            removed.out_of_bailiwick = removed.out_of_bailiwick.saturating_add(1);
            continue;
        }
        let expected = r.rtype == qtype
            || qtype == rtype::ANY
            || matches!(r.rtype, rtype::CNAME | rtype::NSEC | rtype::NSEC3);
        if expected {
            mark(&mut keep_answer, i);
        } else {
            removed.unexpected_type = removed.unexpected_type.saturating_add(1);
        }
    }
    let kept_sets: Vec<(&WireName, u16)> = answer
        .iter()
        .zip(&keep_answer)
        .filter(|(_, k)| **k)
        .map(|(r, _)| (&r.owner, r.rtype))
        .collect();
    let mut answer_signers: Vec<WireName> = Vec::new();
    for (i, r) in answer.iter().enumerate() {
        if r.rtype != rtype::RRSIG {
            continue;
        }
        let Some((covered, signer)) = rrsig_parts(&r.rec) else {
            removed.rrsig = removed.rrsig.saturating_add(1);
            continue;
        };
        if !class_matches(qclass, r.class) {
            removed.wrong_class = removed.wrong_class.saturating_add(1);
            continue;
        }
        let covers = kept_sets.iter().any(|(o, t)| **o == r.owner && *t == covered);
        let asked = (qtype == rtype::RRSIG || qtype == rtype::ANY) && in_chain(&r.owner);
        if covers || asked {
            mark(&mut keep_answer, i);
            if let Ok(s) = WireName::from_hickory(&signer)
                && answer_signers.len() < MAX_SIGNER_ANCHORS
                && !answer_signers.contains(&s)
            {
                answer_signers.push(s);
            }
        } else if in_chain(&r.owner) {
            removed.rrsig = removed.rrsig.saturating_add(1);
        } else {
            removed.out_of_bailiwick = removed.out_of_bailiwick.saturating_add(1);
        }
    }

    if let Some(max) = limits.max_rrset.filter(|m| *m > 0) {
        check_rrset_sizes(&answer, &keep_answer, max)?;
    }

    // Negative or positive, judged at the chain's terminal name.
    let terminal = chain
        .last()
        .map(|l| l.name.clone())
        .unwrap_or_else(|| qwire.clone());
    let positive = answer
        .iter()
        .zip(&keep_answer)
        .any(|(r, k)| *k && (r.rtype == qtype || (qtype == rtype::ANY && r.owner == terminal)));
    let negative = match full_rcode {
        rcode::NXDOMAIN => Some(Negative::Nxdomain),
        rcode::NOERROR if !positive => Some(Negative::Nodata),
        _ => None,
    };

    // Authority: the SOA for negative caching, the NSEC/NSEC3 proofs, their RRSIGs.
    let authority: Vec<&Rec> = recs.iter().filter(|r| r.section == Section::Authority).collect();
    let mut keep_auth = vec![false; authority.len()];
    let mut soa_idx: Option<usize> = None;
    if negative.is_some() {
        soa_idx = authority.iter().position(|r| {
            r.rtype == rtype::SOA
                && class_matches(qclass, r.class)
                && terminal.as_name().is_at_or_below(r.owner.as_name())
        });
    }
    if let Some(i) = soa_idx {
        mark(&mut keep_auth, i);
    }
    let anchors: Vec<WireName> = match soa_idx.and_then(|i| authority.get(i)) {
        Some(soa) => vec![soa.owner.clone()],
        None => answer_signers,
    };
    for (i, r) in authority.iter().enumerate() {
        if matches!(r.rtype, rtype::NSEC | rtype::NSEC3)
            && class_matches(qclass, r.class)
            && anchors
                .iter()
                .any(|a| r.owner.as_name().is_at_or_below(a.as_name()))
        {
            mark(&mut keep_auth, i);
        }
    }
    let kept_auth_sets: Vec<(&WireName, u16)> = authority
        .iter()
        .zip(&keep_auth)
        .filter(|(_, k)| **k)
        .map(|(r, _)| (&r.owner, r.rtype))
        .collect();
    for (i, r) in authority.iter().enumerate() {
        if r.rtype == rtype::RRSIG
            && class_matches(qclass, r.class)
            && rrsig_parts(&r.rec).is_some_and(|(covered, _)| {
                kept_auth_sets
                    .iter()
                    .any(|(o, t)| **o == r.owner && *t == covered)
            })
        {
            mark(&mut keep_auth, i);
        }
    }
    removed.authority = count_dropped(&keep_auth);
    removed.additional =
        u16::try_from(recs.iter().filter(|r| r.section == Section::Additional).count()).unwrap_or(u16::MAX);

    // The kept records, answer then authority, checked for what can't be kept.
    let mut kept: Vec<Kept> = Vec::new();
    for (i, (r, k)) in answer.iter().zip(&keep_answer).enumerate() {
        if *k {
            check_kept(r)?;
            kept.push(Kept {
                section: Section::Answer,
                rtype: r.rtype,
                answer_idx: Some(i),
                rec: r.rec.clone(),
            });
        }
    }
    for (r, k) in authority.iter().zip(&keep_auth) {
        if *k {
            check_kept(r)?;
            kept.push(Kept {
                section: Section::Authority,
                rtype: r.rtype,
                answer_idx: None,
                rec: r.rec.clone(),
            });
        }
    }

    // Facts.
    let mut addrs: Vec<AnswerAddr> = Vec::new();
    let mut targets: Vec<WireName> = Vec::new();
    for (r, k) in answer.iter().zip(&keep_answer) {
        if !*k {
            continue;
        }
        match &r.rec.data {
            RData::A(a) => addrs.push(AnswerAddr {
                ip: IpAddr::V4(a.0),
                source: AddrSource::A,
            }),
            RData::AAAA(a) => addrs.push(AnswerAddr {
                ip: IpAddr::V6(a.0),
                source: AddrSource::Aaaa,
            }),
            RData::SVCB(s) => svcb_facts(s, &mut addrs, &mut targets),
            RData::HTTPS(h) => svcb_facts(&h.0, &mut addrs, &mut targets),
            // An AliasMode record, kept as received (crate::svcb::alias): its target, no hints.
            RData::Unknown { code, rdata }
                if matches!(u16::from(*code), rtype::SVCB | rtype::HTTPS)
                    && crate::svcb::is_alias_rdata(&rdata.anything)
                    && let Ok(t) = crate::svcb::alias(&rdata.anything)
                    && !t.as_name().is_root()
                    && !targets.contains(&t) =>
            {
                targets.push(t);
            }
            _ => {}
        }
    }
    let min_ttl = kept.iter().map(|k| normalize_ttl(k.rec.ttl)).min();
    let soa_rec = soa_idx.and_then(|i| authority.get(i));
    let negative_ttl = soa_rec.and_then(|r| match &r.rec.data {
        RData::SOA(soa) => Some(normalize_ttl(r.rec.ttl).min(normalize_ttl(soa.minimum))),
        _ => None,
    });
    let cache_ttl = cache_ttl(
        &kept,
        negative,
        negative_ttl,
        full_rcode,
        header.truncation,
        stale,
    );
    let facts = AnswerFacts {
        rcode: full_rcode,
        tc: header.truncation,
        aa: header.authoritative,
        chain: chain.iter().skip(1).map(|l| l.name.clone()).collect(),
        addrs,
        targets,
        ede,
        ede_dropped,
        stale,
        negative,
        soa: soa_rec.is_some(),
        min_ttl,
        negative_ttl,
        cache_ttl,
    };

    let mut question = HQuery::query(qname.to_lowercase(), RecordType::from(qtype));
    question.set_query_class(DNSClass::from(qclass));
    Ok(Analysis {
        header,
        question,
        question_len,
        qtype,
        opt,
        kept,
        chain,
        facts,
        removed,
    })
}

/// True when a record of class `rclass` answers a question of class `qclass`: the same class, or
/// any class for QCLASS * (RFC 1035 §3.2.5).
fn class_matches(qclass: u16, rclass: u16) -> bool {
    qclass == class::ANY || rclass == qclass
}

fn read_u16(dec: &mut BinDecoder<'_>) -> Result<u16, Invalid> {
    Ok(dec.read_u16().map_err(|_| Invalid::Undecodable)?.unverified())
}

fn mark(keep: &mut [bool], i: usize) {
    if let Some(k) = keep.get_mut(i) {
        *k = true;
    }
}

fn count_dropped(keep: &[bool]) -> u16 {
    u16::try_from(keep.iter().filter(|k| !**k).count()).unwrap_or(u16::MAX)
}

/// [`Invalid::RrsetTooLarge`] when a kept answer RRset (owner, type, class) holds more than `max`
/// records. Nothing is counted (or allocated) unless the kept records together pass `max`.
fn check_rrset_sizes(answer: &[&Rec], keep: &[bool], max: u16) -> Result<(), Invalid> {
    let max = usize::from(max);
    let kept = || answer.iter().zip(keep).filter(|(_, k)| **k).map(|(r, _)| *r);
    if kept().count() <= max {
        return Ok(());
    }
    let mut sizes: HashMap<(&WireName, u16, u16), usize> = HashMap::new();
    for r in kept() {
        let n = sizes.entry((&r.owner, r.rtype, r.class)).or_insert(0);
        *n = n.saturating_add(1);
        if *n > max {
            return Err(Invalid::RrsetTooLarge);
        }
    }
    Ok(())
}

/// An RRSIG's covered type and signer name.
fn rrsig_parts(rec: &Record) -> Option<(u16, Name)> {
    match &rec.data {
        RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
            let input = sig.input();
            Some((u16::from(input.type_covered), input.signer_name.clone()))
        }
        _ => None,
    }
}

/// A DNAME's target: hickory's name decoder over the record data alone, which must be one
/// uncompressed name that fills it exactly (a pointer can't point before offset 0, so any
/// compressed target fails to decode).
fn dname_target(r: &Rec) -> Result<WireName, Invalid> {
    let data: &[u8] = match &r.rec.data {
        RData::Unknown { rdata, .. } => &rdata.anything,
        RData::Update0(_) => &[],
        _ => return Err(Invalid::DnameTarget),
    };
    let mut d = BinDecoder::new(data);
    let name = Name::read(&mut d).map_err(|_| Invalid::DnameTarget)?;
    if !d.is_empty() {
        return Err(Invalid::DnameTarget);
    }
    WireName::from_hickory(&name).map_err(|_| Invalid::DnameTarget)
}

/// `cur` (below `owner`) with the `owner` suffix replaced by `target`; `None` when the result
/// would be over 255 bytes (RFC 6672 §2.2: the server answers YXDOMAIN).
fn synthesize(cur: &WireName, owner: &WireName, target: &WireName) -> Option<WireName> {
    let prefix_len = cur.wire().len().checked_sub(owner.wire().len())?;
    let prefix = cur.wire().get(..prefix_len)?;
    if prefix_len.saturating_add(target.wire().len()) > MAX_WIRE {
        return None;
    }
    let mut labels: Vec<&[u8]> = NameRef::from_trusted(prefix).labels().collect();
    labels.extend(target.as_name().labels());
    WireName::from_labels(labels).ok()
}

/// Follows CNAMEs and DNAMEs from the question name (edge.md §7: at most 8 hops). Returns the
/// chain (question name first) and the answer indices of the DNAMEs that applied.
fn build_chain(answer: &[&Rec], qname: &WireName, qclass: u16) -> Result<(Vec<Link>, Vec<usize>), Invalid> {
    let mut chain = vec![Link {
        name: qname.clone(),
        dname: None,
        has_cname: false,
        dname_ttl: 0,
    }];
    let mut applied: Vec<usize> = Vec::new();
    loop {
        let Some(cur) = chain.last().map(|l| l.name.clone()) else {
            break;
        };
        // The CNAME at this name: one target, or the chain is ambiguous.
        let mut cname: Option<WireName> = None;
        for r in answer
            .iter()
            .filter(|r| r.rtype == rtype::CNAME && class_matches(qclass, r.class) && r.owner == cur)
        {
            let RData::CNAME(CNAME(t)) = &r.rec.data else {
                return Err(Invalid::Undecodable);
            };
            let t = WireName::from_hickory(t).map_err(|_| Invalid::Undecodable)?;
            match &cname {
                None => cname = Some(t),
                Some(prev) if *prev == t => {}
                Some(_) => return Err(Invalid::AmbiguousChain),
            }
        }
        // The DNAME that applies here: owned by a proper ancestor of this name.
        let mut dname: Option<(usize, WireName, Option<WireName>, u32)> = None;
        for (i, r) in answer.iter().enumerate() {
            if r.rtype != rtype::DNAME
                || !class_matches(qclass, r.class)
                || r.owner == cur
                || !cur.as_name().is_at_or_below(r.owner.as_name())
            {
                continue;
            }
            let target = dname_target(r)?;
            match &dname {
                None => {
                    let synth = synthesize(&cur, &r.owner, &target);
                    dname = Some((i, r.owner.clone(), synth, r.rec.ttl));
                    if !applied.contains(&i) {
                        applied.push(i);
                    }
                }
                Some((j, owner, _, _)) => {
                    let same = answer
                        .get(*j)
                        .is_some_and(|p| *owner == r.owner && p.rec.data == r.rec.data);
                    if !same {
                        return Err(Invalid::AmbiguousChain);
                    }
                }
            }
        }
        let next = match (cname, dname) {
            (Some(c), Some((di, _, Some(s), ttl))) => {
                if c != s {
                    return Err(Invalid::AmbiguousChain);
                }
                Link {
                    name: c,
                    dname: Some(di),
                    has_cname: true,
                    dname_ttl: ttl,
                }
            }
            (Some(_), Some((_, _, None, _))) => return Err(Invalid::AmbiguousChain),
            (Some(c), None) => Link {
                name: c,
                dname: None,
                has_cname: true,
                dname_ttl: 0,
            },
            (None, Some((di, _, Some(s), ttl))) => Link {
                name: s,
                dname: Some(di),
                has_cname: false,
                dname_ttl: ttl,
            },
            (None, Some((_, _, None, _))) | (None, None) => break,
        };
        if chain.len() > MAX_CNAME_HOPS {
            return Err(Invalid::CnameHops);
        }
        if chain.iter().any(|l| l.name == next.name) {
            return Err(Invalid::CnameLoop);
        }
        chain.push(next);
    }
    Ok((chain, applied))
}

/// What a kept record can't be (edge.md §7 step 1). Format checks that hold for every record,
/// such as RFC 9460's on SVCB/HTTPS, ran when it was read.
fn check_kept(r: &Rec) -> Result<(), Invalid> {
    match &r.rec.data {
        RData::Update0(t) => {
            // Empty data is valid only where hickory's own decoder accepts it for the type.
            let t = u16::from(*t);
            if is_meta_type(t) || t == rtype::DNAME {
                return Err(Invalid::EmptyRdata);
            }
            let empty: [u8; 0] = [];
            let mut d = BinDecoder::new(&empty);
            if RData::read(&mut d, RecordType::from(t), Restrict::new(0)).is_err() {
                return Err(Invalid::EmptyRdata);
            }
            if may_hold_compressed_names(t) {
                return Err(Invalid::EmptyRdata);
            }
            Ok(())
        }
        RData::Unknown { code, .. } if may_hold_compressed_names(u16::from(*code)) => {
            Err(Invalid::OpaqueCompressible)
        }
        _ => {
            if is_meta_type(r.rtype) {
                return Err(Invalid::Undecodable);
            }
            Ok(())
        }
    }
}

fn svcb_facts(s: &hickory_proto::rr::rdata::SVCB, addrs: &mut Vec<AnswerAddr>, targets: &mut Vec<WireName>) {
    if !s.target_name.is_root()
        && let Ok(t) = WireName::from_hickory(&s.target_name)
        && !targets.contains(&t)
    {
        targets.push(t);
    }
    for (ip, v4) in crate::svcb::hints(s) {
        addrs.push(AnswerAddr {
            ip,
            source: if v4 {
                AddrSource::Ipv4Hint
            } else {
                AddrSource::Ipv6Hint
            },
        });
    }
}

fn cache_ttl(
    kept: &[Kept],
    negative: Option<Negative>,
    negative_ttl: Option<u32>,
    full_rcode: u16,
    tc: bool,
    stale: bool,
) -> Option<u32> {
    if tc || stale || !matches!(full_rcode, rcode::NOERROR | rcode::NXDOMAIN) {
        return None;
    }
    // The negative-caching SOA's lifetime is `negative_ttl`; an SOA in the answer section is an
    // ordinary record of the qtype and bounds a positive answer like any other.
    let records = kept
        .iter()
        .filter(|k| !k.is_negative_soa())
        .map(|k| normalize_ttl(k.rec.ttl))
        .min();
    let ttl = match negative {
        // RFC 2308 §5: without an SOA a negative answer isn't cached.
        Some(_) => {
            let neg = negative_ttl?;
            records.map_or(neg, |r| r.min(neg))
        }
        None => records?,
    };
    (ttl > 0).then_some(ttl)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Full,
    Stripped,
}

/// hickory encodes one copy: the header (AD cleared), the question as sent, the kept records
/// (the DO=0 copy without the stripped ones, with a CNAME for each left-out DNAME whose CNAME the
/// answer lacked) and, in the full copy, the upstream's OPT without its Padding option.
fn encode(a: &Analysis, msg: &[u8], which: Which) -> Result<EncodedCopy, Invalid> {
    let mut records: Vec<(Section, Record)> = Vec::with_capacity(a.kept.len());
    // The negative-caching SOA's place among the encoded records (at most one).
    let mut negative_soa: Option<usize> = None;
    for k in &a.kept {
        if which == Which::Stripped && strip_for_do0(k.rtype, a.qtype) {
            if k.rtype == rtype::DNAME {
                // RFC 6672 §3: the DNAME goes, its synthesised CNAME stays.
                for (pos, link) in a.chain.iter().enumerate() {
                    if link.dname != k.answer_idx || link.dname.is_none() || link.has_cname {
                        continue;
                    }
                    let Some(prev) = pos.checked_sub(1).and_then(|p| a.chain.get(p)) else {
                        continue;
                    };
                    let (Some(owner), Some(target)) =
                        (prev.name.as_name().to_hickory(), link.name.as_name().to_hickory())
                    else {
                        return Err(Invalid::Encode);
                    };
                    let mut cname = Record::from_rdata(owner, link.dname_ttl, RData::CNAME(CNAME(target)));
                    // The DNAME's class (the question's may be ANY, RFC 1035 §3.2.5).
                    cname.dns_class = k.rec.dns_class;
                    records.push((Section::Answer, cname));
                }
            }
            continue;
        }
        if k.is_negative_soa() {
            negative_soa = Some(records.len());
        }
        records.push((k.section, k.rec.clone()));
    }
    let an = u16::try_from(records.iter().filter(|(s, _)| *s == Section::Answer).count())
        .map_err(|_| Invalid::Encode)?;
    let ns = u16::try_from(records.len())
        .map_err(|_| Invalid::Encode)?
        .saturating_sub(an);
    let opt = match which {
        Which::Full => a.opt.as_ref(),
        Which::Stripped => None,
    };

    let mut meta = Metadata::new(a.header.id, MessageType::Response, OpCode::Query);
    meta.authoritative = a.header.authoritative;
    meta.truncation = a.header.truncation;
    meta.recursion_desired = a.header.recursion_desired;
    meta.recursion_available = a.header.recursion_available;
    meta.authentic_data = false; // hard rule 6: the edge never validates
    meta.checking_disabled = a.header.checking_disabled;
    meta.response_code = ResponseCode::from_low(a.header.response_code.low());
    let mut header = a.header;
    header.metadata = meta;
    header.counts.queries = 1;
    header.counts.answers = an;
    header.counts.authorities = ns;
    header.counts.additionals = u16::from(opt.is_some());

    let mut buf: Vec<u8> = Vec::with_capacity(msg.len().saturating_add(64));
    {
        let mut enc = BinEncoder::new(&mut buf);
        header.emit(&mut enc).map_err(|_| Invalid::Encode)?;
        a.question.emit(&mut enc).map_err(|_| Invalid::Encode)?;
        for (_, r) in &records {
            r.emit(&mut enc).map_err(|_| Invalid::Encode)?;
        }
    }
    let start = 12usize.saturating_add(usize::from(a.question_len));
    let (mut ttls, end) = walk_ttls(&buf, start, records.len()).ok_or(Invalid::Encode)?;
    if end != buf.len() {
        return Err(Invalid::Encode);
    }
    // RFC 2308 §5: a negative answer lives min(SOA TTL, SOA MINIMUM), carried in the SOA's
    // header TTL, which decrements while cached. The copy keeps the upstream's TTL (the logged
    // wire has original TTLs, api.md §5); a hit ages the negative TTL instead, so an almost
    // expired entry never tells a downstream cache it has MINIMUM left.
    if let (Some(i), Some(t)) = (negative_soa, a.facts.negative_ttl)
        && let Some(slot) = ttls.get_mut(i)
    {
        slot.ttl = t;
    }
    if let Some(o) = opt {
        // The OPT holds no names: written as the upstream sent it, less Padding.
        let data = msg.get(o.options.clone()).ok_or(Invalid::Encode)?;
        let kept_len: usize = EdnsOptions::new(data)
            .filter(|(c, _)| *c != edns_code::PADDING)
            .map(|(_, p)| p.len().saturating_add(4))
            .fold(0usize, usize::saturating_add);
        buf.push(0);
        buf.extend_from_slice(&rtype::OPT.to_be_bytes());
        buf.extend_from_slice(&o.udp.to_be_bytes());
        buf.extend_from_slice(&[o.ext_rcode, o.version]);
        buf.extend_from_slice(&o.flags.to_be_bytes());
        buf.extend_from_slice(
            &u16::try_from(kept_len)
                .map_err(|_| Invalid::Encode)?
                .to_be_bytes(),
        );
        for (code, payload) in EdnsOptions::new(data).filter(|(c, _)| *c != edns_code::PADDING) {
            buf.extend_from_slice(&code.to_be_bytes());
            buf.extend_from_slice(
                &u16::try_from(payload.len())
                    .map_err(|_| Invalid::Encode)?
                    .to_be_bytes(),
            );
            buf.extend_from_slice(payload);
        }
    }
    if buf.len() > MAX_MESSAGE {
        return Err(Invalid::Encode);
    }
    Ok(EncodedCopy {
        msg: buf.into_boxed_slice(),
        records: start..end,
        an,
        ns,
        ttls: ttls.into_boxed_slice(),
    })
}
