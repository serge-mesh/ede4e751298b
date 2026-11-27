//! The query check (edge.md §4 "Parsing", §16).
//!
//! From the header, before the body is decoded: QR set → no reply; an opcode other than QUERY →
//! NOTIMP; `QDCOUNT != 1` or more than 8 other records → FORMERR. Then hickory decodes the body:
//! one it can't decode, a compression pointer in the question name, an OPT outside the additional
//! section or a second OPT, or trailing bytes → FORMERR; an EDNS version above 0 → BADVERS. A
//! client UDP size below 512 counts as 512. The query's raw question bytes are kept for replies.
//! UDP replies are capped at the client's UDP size and the listener's `limits.udp_payload`
//! (edge.md §5), which every reply's OPT advertises.
//!
//! On the baseline query shapes (a short name, with or without an OPT and its options) this
//! makes no heap allocation; hickory's `Name` keeps 32 label bytes and 24 labels inline.

use hickory_proto::op::{Header, MessageType, OpCode};
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use picket_api::logs::EdnsInfo;
use thiserror::Error;

use crate::MAX_MESSAGE;
use crate::edns::{EdnsOptions, Item, ItemError, read_item};
use crate::name::{MAX_WIRE, QName};
use crate::reply::{OPT_FIXED, REPLY_PAD_BLOCK, ReplyTo, Transport, udp_limit, write_opt};
use crate::types::{edns_code, rcode};
use crate::wire::{Out, WriteError};

/// The most records a query may carry besides its question (edge.md §4).
pub const MAX_OTHER_RECORDS: u16 = 8;

/// The longest question: a 255-byte name, QTYPE and QCLASS.
pub const MAX_QUESTION: usize = MAX_WIRE + 4;

/// The client's EDNS(0) state (RFC 6891).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edns {
    /// The client's UDP payload size; a value below 512 counts as 512.
    pub udp_size: u16,
    /// The DNSSEC OK bit (RFC 3225).
    pub do_bit: bool,
    /// The EDNS version the client asked for.
    pub version: u8,
    /// How many options the client sent. They are never forwarded upstream (edge.md §6).
    pub option_count: u16,
    /// The query carried a Padding option (RFC 7830): replies over DoT and DoH are padded.
    pub padding: bool,
    options_start: u16,
    options_len: u16,
}

/// A query that passed the check: everything the pipeline and the reply writers need, owned, so
/// it can outlive the receive buffer.
#[derive(Clone)]
pub struct Query {
    pub id: u16,
    /// Recursion desired. Only RD queries are answered (edge.md §16); the edge decides.
    pub rd: bool,
    /// Checking disabled; passed upstream and part of the cache key (edge.md §7 step 4).
    pub cd: bool,
    pub qtype: u16,
    pub qclass: u16,
    qname: QName,
    question: [u8; MAX_QUESTION],
    question_len: u16,
    /// Present when the query had an OPT record.
    pub edns: Option<Edns>,
}

impl Query {
    /// The query name, ASCII-lowercased, with its wire label boundaries.
    pub fn qname(&self) -> &QName {
        &self.qname
    }

    /// The question exactly as the client sent it (name in its own case, QTYPE, QCLASS); every
    /// reply copies these bytes.
    pub fn question(&self) -> &[u8] {
        self.question.get(..usize::from(self.question_len)).unwrap_or(&[])
    }

    pub fn has_opt(&self) -> bool {
        self.edns.is_some()
    }

    /// The client's DO bit; false without an OPT.
    pub fn do_bit(&self) -> bool {
        self.edns.is_some_and(|e| e.do_bit)
    }

    /// The largest UDP reply for this client on a listener whose `limits.udp_payload` is
    /// `listener_payload` (edge.md §5; [`crate::EDGE_UDP_PAYLOAD`] by default): 512 without an
    /// OPT, else the client's UDP size, at most the listener's (RFC 6891 §6.2.5: a responder also
    /// keeps to its own payload size). Sizes below 512 count as 512.
    pub fn udp_limit(&self, listener_payload: u16) -> usize {
        udp_limit(self.edns.map(|e| e.udp_size), listener_payload)
    }

    /// The reply parameters for this query on `transport`, from a listener whose
    /// `limits.udp_payload` is `listener_payload`: it caps UDP replies and is what the reply's OPT
    /// advertises. Replies over DoT and DoH to a query with a Padding option are padded.
    pub fn reply_to(&self, transport: Transport, listener_payload: u16) -> ReplyTo<'_> {
        ReplyTo {
            id: self.id,
            rd: self.rd,
            cd: self.cd,
            question: self.question(),
            client_opt: self.edns.map(|e| e.do_bit),
            limit: match transport {
                Transport::Udp => self.udp_limit(listener_payload),
                Transport::Stream | Transport::Encrypted => MAX_MESSAGE,
            },
            payload: listener_payload.max(512),
            pad: transport == Transport::Encrypted && self.edns.is_some_and(|e| e.padding),
        }
    }

    /// What the `q` log record carries of this query's OPT (`edns`, api.md §5), so core rebuilds
    /// the reply's size, EDE and padding as the edge chose them ([`ReplyTo::logged`]). `None`
    /// without an OPT.
    pub fn edns_log(&self) -> Option<EdnsInfo> {
        self.edns.map(|e| EdnsInfo {
            udp: e.udp_size,
            pad: e.padding,
        })
    }

    /// The client's EDNS options in `msg`, the message this query was checked from. They are
    /// only ever inspected, never forwarded (edge.md §6).
    pub fn client_options<'m>(&self, msg: &'m [u8]) -> EdnsOptions<'m> {
        let Some(e) = self.edns else {
            return EdnsOptions::empty();
        };
        let start = usize::from(e.options_start);
        let end = start.saturating_add(usize::from(e.options_len));
        msg.get(start..end)
            .map(EdnsOptions::new)
            .unwrap_or_else(EdnsOptions::empty)
    }
}

impl std::fmt::Debug for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Query")
            .field("id", &self.id)
            .field("qname", &self.qname)
            .field("qtype", &self.qtype)
            .field("qclass", &self.qclass)
            .field("rd", &self.rd)
            .field("cd", &self.cd)
            .field("edns", &self.edns)
            .finish()
    }
}

/// Why a query gets no reply at all (edge.md §16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum NoReply {
    /// Shorter than a header: there is no ID to answer.
    #[error("header unreadable")]
    ShortHeader,
    /// QR is set: a response, never answered (so two servers can't loop).
    #[error("QR set")]
    Response,
}

/// Why a query is malformed (FORMERR).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FormErr {
    #[error("QDCOUNT is not 1")]
    QuestionCount,
    #[error("more than 8 records besides the question")]
    TooManyRecords,
    #[error("message over 65,535 bytes")]
    TooLong,
    #[error("body undecodable")]
    Undecodable,
    #[error("compression pointer in the question name")]
    CompressedQuestion,
    #[error("OPT outside the additional section")]
    OptNotAdditional,
    #[error("second OPT record")]
    DuplicateOpt,
    #[error("malformed OPT record")]
    MalformedOpt,
    #[error("trailing bytes")]
    TrailingBytes,
}

/// What an error reply can echo: the header fields, the question if it was decoded, and the
/// client's OPT if one was read before the failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorContext {
    pub id: u16,
    pub opcode: u8,
    pub rd: bool,
    pub cd: bool,
    /// Length of the question at offset 12 of the message, if it was decoded.
    pub question_len: Option<u16>,
    pub edns: Option<Edns>,
}

/// A query that failed the check, classified by how the edge answers it (edge.md §16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum QueryError {
    #[error("no reply: {0}")]
    NoReply(NoReply),
    #[error("opcode not implemented")]
    NotImp(ErrorContext),
    #[error("malformed query: {1}")]
    FormErr(ErrorContext, FormErr),
    #[error("EDNS version not supported")]
    BadVers(ErrorContext),
}

impl QueryError {
    /// Every [`Self::counter`] name, so counters can be registered up front.
    pub const COUNTERS: [&'static str; 5] = ["header_unreadable", "qr_set", "notimp", "formerr", "badvers"];

    /// The rcode of the reply, or `None` when there is none.
    pub fn rcode(&self) -> Option<u16> {
        match self {
            Self::NoReply(_) => None,
            Self::NotImp(_) => Some(rcode::NOTIMP),
            Self::FormErr(..) => Some(rcode::FORMERR),
            Self::BadVers(_) => Some(rcode::BADVERS),
        }
    }

    /// A stable name for counters.
    pub fn counter(&self) -> &'static str {
        match self {
            Self::NoReply(NoReply::ShortHeader) => "header_unreadable",
            Self::NoReply(NoReply::Response) => "qr_set",
            Self::NotImp(_) => "notimp",
            Self::FormErr(..) => "formerr",
            Self::BadVers(_) => "badvers",
        }
    }
}

/// Checks a query message (edge.md §4 "Parsing").
pub fn check_query(msg: &[u8]) -> Result<Query, QueryError> {
    let mut dec = BinDecoder::new(msg);
    let header = Header::read(&mut dec).map_err(|_| QueryError::NoReply(NoReply::ShortHeader))?;
    let mut ctx = ErrorContext {
        id: header.id,
        opcode: u8::from(header.op_code),
        rd: header.recursion_desired,
        cd: header.checking_disabled,
        question_len: None,
        edns: None,
    };
    // From the header, before the body is decoded.
    if header.message_type == MessageType::Response {
        return Err(QueryError::NoReply(NoReply::Response));
    }
    if header.op_code != OpCode::Query {
        return Err(QueryError::NotImp(ctx));
    }
    let counts = header.counts;
    if counts.queries != 1 {
        return Err(QueryError::FormErr(ctx, FormErr::QuestionCount));
    }
    let others = u32::from(counts.answers)
        .saturating_add(u32::from(counts.authorities))
        .saturating_add(u32::from(counts.additionals));
    if others > u32::from(MAX_OTHER_RECORDS) {
        return Err(QueryError::FormErr(ctx, FormErr::TooManyRecords));
    }
    if msg.len() > MAX_MESSAGE {
        return Err(QueryError::FormErr(ctx, FormErr::TooLong));
    }

    // The question, decoded by hickory.
    let qstart = dec.index();
    let name = Name::read(&mut dec).map_err(|_| QueryError::FormErr(ctx, FormErr::Undecodable))?;
    let consumed = dec.index().saturating_sub(qstart);
    // Without a pointer, the bytes read are exactly the name's wire length; a pointer replaces
    // the root byte with two bytes and drops the labels it points at, so the two differ.
    if consumed != name_wire_len(&name) {
        return Err(QueryError::FormErr(ctx, FormErr::CompressedQuestion));
    }
    let qtype = dec
        .read_u16()
        .map_err(|_| QueryError::FormErr(ctx, FormErr::Undecodable))?
        .unverified(/*any type*/);
    let qclass = dec
        .read_u16()
        .map_err(|_| QueryError::FormErr(ctx, FormErr::Undecodable))?
        .unverified(/*any class*/);
    let qname = QName::from_hickory(&name).map_err(|_| QueryError::FormErr(ctx, FormErr::Undecodable))?;
    let qend = dec.index();
    let raw_question = msg
        .get(qstart..qend)
        .ok_or(QueryError::FormErr(ctx, FormErr::Undecodable))?;
    let question_len =
        u16::try_from(raw_question.len()).map_err(|_| QueryError::FormErr(ctx, FormErr::Undecodable))?;
    let mut question = [0u8; MAX_QUESTION];
    question
        .get_mut(..raw_question.len())
        .ok_or(QueryError::FormErr(ctx, FormErr::Undecodable))?
        .copy_from_slice(raw_question);
    ctx.question_len = Some(question_len);

    // The other records: hickory decodes each; an OPT's options are checked as raw TLVs.
    let mut edns: Option<Edns> = None;
    let sections = [
        (counts.answers, false),
        (counts.authorities, false),
        (counts.additionals, true),
    ];
    for (count, additional) in sections {
        for _ in 0..count {
            match read_item(&mut dec) {
                Ok(Item::Opt(opt)) => {
                    if !additional {
                        return Err(QueryError::FormErr(ctx, FormErr::OptNotAdditional));
                    }
                    if edns.is_some() {
                        return Err(QueryError::FormErr(ctx, FormErr::DuplicateOpt));
                    }
                    let padding = msg
                        .get(opt.options.clone())
                        .is_some_and(|d| EdnsOptions::new(d).any(|(c, _)| c == edns_code::PADDING));
                    let e = Edns {
                        udp_size: opt.udp.max(512),
                        do_bit: opt.do_bit(),
                        version: opt.version,
                        option_count: opt.count,
                        padding,
                        options_start: u16::try_from(opt.options.start).unwrap_or(0),
                        options_len: u16::try_from(opt.options.len()).unwrap_or(0),
                    };
                    edns = Some(e);
                    ctx.edns = Some(e);
                }
                Ok(Item::Record(_)) => {}
                // A record outside its type's format, RFC 9460's for SVCB/HTTPS included, is a
                // body the edge can't decode (edge.md §4 "Parsing").
                Err(ItemError::Decode | ItemError::BadSvcb) => {
                    return Err(QueryError::FormErr(ctx, FormErr::Undecodable));
                }
                Err(ItemError::MalformedOpt) => {
                    return Err(QueryError::FormErr(ctx, FormErr::MalformedOpt));
                }
            }
        }
    }
    if !dec.is_empty() {
        return Err(QueryError::FormErr(ctx, FormErr::TrailingBytes));
    }
    if edns.is_some_and(|e| e.version > 0) {
        return Err(QueryError::BadVers(ctx));
    }

    Ok(Query {
        id: header.id,
        rd: header.recursion_desired,
        cd: header.checking_disabled,
        qtype,
        qclass,
        qname,
        question,
        question_len,
        edns,
    })
}

/// The wire length of an uncompressed name: a length byte per label, the labels, the root byte.
pub(crate) fn name_wire_len(name: &Name) -> usize {
    name.iter()
        .fold(1usize, |acc, l| acc.saturating_add(1).saturating_add(l.len()))
}

/// Writes the reply a failed query gets into `out`: `Ok(None)` when it gets none. `msg` is the
/// message that was checked (the reply echoes its question when it was decoded);
/// `listener_payload` is the listener's `limits.udp_payload`, which the reply's OPT advertises.
/// Error replies are header + question + OPT, at most 512 bytes; over DoT and DoH, one whose
/// query's OPT carried a Padding option is padded to 468 bytes (RFC 7830 §4, RFC 8467 §4.1).
pub fn write_query_error(
    out: &mut [u8],
    msg: &[u8],
    err: &QueryError,
    transport: Transport,
    listener_payload: u16,
) -> Result<Option<usize>, WriteError> {
    let (ctx, rc) = match err {
        QueryError::NoReply(_) => return Ok(None),
        QueryError::NotImp(c) => (c, rcode::NOTIMP),
        QueryError::FormErr(c, _) => (c, rcode::FORMERR),
        QueryError::BadVers(c) => (c, rcode::BADVERS),
    };
    // NOTIMP is decided from the header alone, before the body is decoded: no question.
    let question = match (err, ctx.question_len) {
        (QueryError::NotImp(_), _) | (_, None) => &[][..],
        (_, Some(len)) => msg
            .get(12..12usize.saturating_add(usize::from(len)))
            .unwrap_or(&[]),
    };
    let mut o = Out::new(out);
    o.u16(ctx.id)?;
    // QR, the client's opcode and RD; RA set; CD echoed; the rcode's low 4 bits.
    let b2 = 0x80 | ((ctx.opcode & 0x0F) << 3) | u8::from(ctx.rd);
    let b3 = 0x80 | if ctx.cd { 0x10 } else { 0 } | ((rc & 0x0F) as u8);
    o.u8(b2)?;
    o.u8(b3)?;
    o.u16(u16::from(!question.is_empty()))?;
    o.u16(0)?;
    o.u16(0)?;
    o.u16(u16::from(ctx.edns.is_some()))?;
    o.put(question)?;
    if let Some(e) = ctx.edns {
        let pad = (transport == Transport::Encrypted && e.padding).then(|| {
            // The 4 bytes of the option's header count toward the block.
            let len = o.pos().saturating_add(OPT_FIXED).saturating_add(4);
            REPLY_PAD_BLOCK.saturating_sub(len % REPLY_PAD_BLOCK) % REPLY_PAD_BLOCK
        });
        write_opt(&mut o, rc, e.do_bit, listener_payload, &[], None, pad)?;
    }
    Ok(Some(o.pos()))
}
