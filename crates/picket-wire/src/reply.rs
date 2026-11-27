//! Reply writers (edge.md §4): every reply the edge makes itself, written into a caller-provided
//! buffer without allocating.
//!
//! All replies share one layout and one size rule: the header, the client's raw question bytes,
//! the records, then an OPT (with the client's DO, the listener's UDP payload size and any EDE
//! options) only when the query had one. AD is always clear (hard rule 6). When the reply is over
//! the client's limit, EDE tokens and then EDE options are dropped first (edge.md §4 EDE); if the
//! records still don't fit, the reply is the header, the question and any OPT, with TC set
//! (edge.md §8). Synthesised records carry the question's class (IN for the QCLASS-only values
//! ANY and NONE).
//!
//! A reply to a DoT or DoH query that carried a Padding option ends its OPT with one that brings
//! the message to a multiple of 468 bytes (RFC 7830 §4: responders MUST pad; RFC 8467 §4.1: 468-
//! byte blocks), within the client's limit, after the EDE and TC choices are made. Plain UDP and
//! TCP replies aren't padded: padding without encryption hides nothing (RFC 7830 §6).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use picket_api::edge_config::{BlockResponse, BlockResponseType, TtlClamp};
use picket_api::logs::{EdnsInfo, Proto};

use crate::MAX_MESSAGE;
use crate::ede::{EdeOption, EdePlan};
use crate::name::NameRef;
use crate::types::{class, edns_code, rcode, rtype};
use crate::wire::{Out, TtlSlot, WriteError};

/// How the reply travels, which sets its size limit and whether it may be padded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// UDP: the client's UDP size (512 without an OPT), at most the listener's UDP payload
    /// size (`limits.udp_payload`, default [`crate::EDGE_UDP_PAYLOAD`], edge.md §5).
    Udp,
    /// Plain TCP: up to 65,535 bytes.
    Stream,
    /// DoT and DoH: up to 65,535 bytes, and a reply to a query that carried a Padding option is
    /// padded (RFC 7830 §4, RFC 8467 §4.1).
    Encrypted,
}

impl Transport {
    /// The transport of a logged `proto` (api.md §5).
    pub fn of_proto(proto: Proto) -> Self {
        match proto {
            Proto::Udp => Self::Udp,
            Proto::Tcp => Self::Stream,
            Proto::Dot | Proto::Doh => Self::Encrypted,
        }
    }
}

/// The block size padded replies are brought to (RFC 8467 §4.1).
pub const REPLY_PAD_BLOCK: usize = 468;

/// The largest UDP reply for a client whose OPT advertised `client_udp` (`None` without an OPT)
/// on a listener whose `limits.udp_payload` is `listener_payload`: 512 without an OPT, else the
/// client's size, at most the listener's (RFC 6891 §6.2.5); sizes below 512 count as 512.
pub(crate) fn udp_limit(client_udp: Option<u16>, listener_payload: u16) -> usize {
    match client_udp {
        None => 512,
        Some(u) => usize::from(u.max(512).min(listener_payload.max(512))),
    }
}

/// Who a reply goes to: the parts of the query every reply echoes, its size limit and whether it
/// is padded. Built by [`crate::Query::reply_to`] on the edge, or by core with
/// [`ReplyTo::logged`] from a log record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyTo<'a> {
    pub id: u16,
    pub rd: bool,
    pub cd: bool,
    /// The question bytes as the client sent them (uncompressed name, QTYPE, QCLASS).
    pub question: &'a [u8],
    /// `Some(client DO)` when the query had an OPT; replies then carry one.
    pub client_opt: Option<bool>,
    /// The largest reply this client takes on this transport.
    pub limit: usize,
    /// The UDP payload size the reply's OPT advertises: the listener's `limits.udp_payload`
    /// (edge.md §5; [`crate::EDGE_UDP_PAYLOAD`] by default).
    pub payload: u16,
    /// Pad the reply to a multiple of [`REPLY_PAD_BLOCK`] bytes: the query carried a Padding
    /// option and came over DoT or DoH. Ignored without an OPT.
    pub pad: bool,
}

impl<'a> ReplyTo<'a> {
    /// Core: the reply parameters of a logged query (core.md §6), sized and padded exactly as the
    /// edge's [`crate::Query::reply_to`] made them. From the `q` record (api.md §5): `proto`,
    /// `do` and `edns`; `payload` is the listener's `limits.udp_payload` in the record's config
    /// version; `question` and `cd` come from the referenced answer
    /// ([`crate::CacheValue::question`], [`crate::CacheValue::cd`]): CD is part of the cache key,
    /// and upstreams copy it into their answer (RFC 4035 §3.1.6). The log has neither the ID nor
    /// the question's letter case, which the edge echoes from the query: the ID is 0 and the
    /// question lowercase, which changes no length and no choice the edge made. RD is set: the
    /// edge answers only recursion-desired queries (edge.md §16).
    pub fn logged(
        question: &'a [u8],
        cd: bool,
        proto: Proto,
        do_bit: bool,
        edns: Option<&EdnsInfo>,
        payload: u16,
    ) -> Self {
        let transport = Transport::of_proto(proto);
        Self {
            id: 0,
            rd: true,
            cd,
            question,
            client_opt: edns.map(|_| do_bit),
            limit: match transport {
                Transport::Udp => udp_limit(edns.map(|e| e.udp), payload),
                Transport::Stream | Transport::Encrypted => MAX_MESSAGE,
            },
            payload: payload.max(512),
            pad: transport == Transport::Encrypted && edns.is_some_and(|e| e.pad),
        }
    }
}

impl ReplyTo<'_> {
    /// The client's DO bit (false without an OPT).
    pub fn do_bit(&self) -> bool {
        self.client_opt == Some(true)
    }

    fn qtype(&self) -> u16 {
        let n = self.question.len();
        crate::wire::get_u16(self.question, n.saturating_sub(4)).unwrap_or(0)
    }

    fn qclass(&self) -> u16 {
        let n = self.question.len();
        crate::wire::get_u16(self.question, n.saturating_sub(2)).unwrap_or(class::IN)
    }

    /// The class of the records the edge synthesises: the question's, or IN for the
    /// QCLASS-only values ANY and NONE (RFC 1035 §3.2.5, RFC 2136 §2.3).
    pub(crate) fn record_class(&self) -> u16 {
        match self.qclass() {
            class::ANY | class::NONE => class::IN,
            c => c,
        }
    }
}

/// A written reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Bytes written at the start of the output buffer.
    pub len: usize,
    /// True when the records didn't fit and the reply was cut to header, question and OPT with
    /// TC set (logged as `tc`, api.md §5).
    pub tc: bool,
    /// How many EDE options the reply carries.
    pub ede: usize,
}

/// The data of a record the edge synthesises (rewrites, local answers, blocks). Names are
/// written uncompressed; `Raw` data is copied as given and must not hold compression pointers
/// (HTTPS/SVCB data from a rewrite is uncompressed by definition, RFC 9460 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordData<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(NameRef<'a>),
    Ptr(NameRef<'a>),
    Ns(NameRef<'a>),
    Mx {
        preference: u16,
        exchange: NameRef<'a>,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: NameRef<'a>,
    },
    /// Character strings of at most 255 bytes each.
    Txt(&'a [&'a [u8]]),
    /// One text of any length (a `$dnsrewrite` TXT value), written as character strings of 255
    /// bytes, the last one shorter; an empty text is one empty string.
    TxtSplit(&'a [u8]),
    Hinfo {
        cpu: &'a [u8],
        os: &'a [u8],
    },
    Soa {
        mname: NameRef<'a>,
        rname: NameRef<'a>,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// Any other type, with its uncompressed RDATA.
    Raw {
        rtype: u16,
        rdata: &'a [u8],
    },
}

impl RecordData<'_> {
    pub fn rtype(&self) -> u16 {
        match self {
            Self::A(_) => rtype::A,
            Self::Aaaa(_) => rtype::AAAA,
            Self::Cname(_) => rtype::CNAME,
            Self::Ptr(_) => rtype::PTR,
            Self::Ns(_) => rtype::NS,
            Self::Mx { .. } => rtype::MX,
            Self::Srv { .. } => rtype::SRV,
            Self::Txt(_) | Self::TxtSplit(_) => rtype::TXT,
            Self::Hinfo { .. } => rtype::HINFO,
            Self::Soa { .. } => rtype::SOA,
            Self::Raw { rtype, .. } => *rtype,
        }
    }

    fn len(&self) -> Result<usize, WriteError> {
        Ok(match self {
            Self::A(_) => 4,
            Self::Aaaa(_) => 16,
            Self::Cname(n) | Self::Ptr(n) | Self::Ns(n) => n.wire_len(),
            Self::Mx { exchange, .. } => exchange.wire_len().saturating_add(2),
            Self::Srv { target, .. } => target.wire_len().saturating_add(6),
            Self::Txt(strings) => {
                let mut n = 0usize;
                for s in *strings {
                    if s.len() > 255 {
                        return Err(WriteError::TooLong);
                    }
                    n = n.saturating_add(s.len()).saturating_add(1);
                }
                n
            }
            Self::TxtSplit(text) => {
                let strings = text.len().div_ceil(255).max(1);
                text.len().saturating_add(strings)
            }
            Self::Hinfo { cpu, os } => {
                if cpu.len() > 255 || os.len() > 255 {
                    return Err(WriteError::TooLong);
                }
                cpu.len().saturating_add(os.len()).saturating_add(2)
            }
            Self::Soa { mname, rname, .. } => mname
                .wire_len()
                .saturating_add(rname.wire_len())
                .saturating_add(20),
            Self::Raw { rdata, .. } => rdata.len(),
        })
    }

    fn write(&self, o: &mut Out<'_>) -> Result<(), WriteError> {
        match self {
            Self::A(a) => o.put(&a.octets()),
            Self::Aaaa(a) => o.put(&a.octets()),
            Self::Cname(n) | Self::Ptr(n) | Self::Ns(n) => o.put(n.wire()),
            Self::Mx { preference, exchange } => {
                o.u16(*preference)?;
                o.put(exchange.wire())
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                o.u16(*priority)?;
                o.u16(*weight)?;
                o.u16(*port)?;
                o.put(target.wire())
            }
            Self::Txt(strings) => {
                for s in *strings {
                    o.u8(u8::try_from(s.len()).map_err(|_| WriteError::TooLong)?)?;
                    o.put(s)?;
                }
                Ok(())
            }
            Self::TxtSplit(text) => {
                if text.is_empty() {
                    return o.u8(0);
                }
                for chunk in text.chunks(255) {
                    o.u8(u8::try_from(chunk.len()).map_err(|_| WriteError::TooLong)?)?;
                    o.put(chunk)?;
                }
                Ok(())
            }
            Self::Hinfo { cpu, os } => {
                o.u8(u8::try_from(cpu.len()).map_err(|_| WriteError::TooLong)?)?;
                o.put(cpu)?;
                o.u8(u8::try_from(os.len()).map_err(|_| WriteError::TooLong)?)?;
                o.put(os)
            }
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                o.put(mname.wire())?;
                o.put(rname.wire())?;
                for v in [serial, refresh, retry, expire, minimum] {
                    o.u32(*v)?;
                }
                Ok(())
            }
            Self::Raw { rdata, .. } => o.put(rdata),
        }
    }
}

/// A record the edge synthesises. `owner: None` is the question's name, written as a pointer
/// to the client's question (offset 12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordSpec<'a> {
    pub owner: Option<NameRef<'a>>,
    pub ttl: u32,
    pub data: RecordData<'a>,
}

impl RecordSpec<'_> {
    fn len(&self) -> Result<usize, WriteError> {
        let owner = self.owner.map_or(2, NameRef::wire_len);
        let rdata = self.data.len()?;
        if rdata > usize::from(u16::MAX) {
            return Err(WriteError::TooLong);
        }
        Ok(owner.saturating_add(10).saturating_add(rdata))
    }

    fn write(&self, o: &mut Out<'_>, rclass: u16) -> Result<(), WriteError> {
        match self.owner {
            None => o.u16(0xC00C)?,
            Some(n) => o.put(n.wire())?,
        }
        o.u16(self.data.rtype())?;
        o.u16(rclass)?;
        o.u32(self.ttl)?;
        o.u16(u16::try_from(self.data.len()?).map_err(|_| WriteError::TooLong)?)?;
        self.data.write(o)
    }
}

/// How TTLs in a copied cache blob are set (edge.md §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TtlRule {
    /// The original less its age, at least 0, clamped to the profile's `ttl`.
    Aged { age: u32, clamp: TtlClamp },
    /// Every TTL set to this value (a stale answer's `stale_ttl`).
    Fixed(u32),
}

/// A header TTL as served: values with the top bit set count as 0 (RFC 2181 §8).
pub(crate) fn normalize_ttl(ttl: u32) -> u32 {
    if ttl > i32::MAX as u32 { 0 } else { ttl }
}

impl TtlRule {
    pub(crate) fn apply(&self, original: u32) -> u32 {
        match self {
            Self::Aged { age, clamp } => clamp.clamp(normalize_ttl(original).saturating_sub(*age)),
            Self::Fixed(t) => *t,
        }
    }
}

/// Addresses for an answer to an A or AAAA question: each written as the record of its family.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AddrList<'a> {
    Ips(&'a [IpAddr]),
    V4(&'a [Ipv4Addr]),
    V6(&'a [Ipv6Addr]),
}

impl AddrList<'_> {
    fn for_each(&self, mut f: impl FnMut(IpAddr) -> Result<(), WriteError>) -> Result<(), WriteError> {
        match self {
            Self::Ips(v) => v.iter().try_for_each(|a| f(*a)),
            Self::V4(v) => v.iter().try_for_each(|a| f(IpAddr::V4(*a))),
            Self::V6(v) => v.iter().try_for_each(|a| f(IpAddr::V6(*a))),
        }
    }
}

/// What follows the question.
pub(crate) enum Body<'x> {
    Empty,
    Specs {
        answer: &'x [RecordSpec<'x>],
        authority: &'x [RecordSpec<'x>],
    },
    /// A/AAAA records for the question's name, one per address of the question's family.
    Addrs {
        list: AddrList<'x>,
        ttl: u32,
    },
    /// A cache copy's records, copied verbatim with their TTLs set by `rule`.
    Blob {
        bytes: &'x [u8],
        an: u16,
        ns: u16,
        ttls: &'x [TtlSlot],
        rule: TtlRule,
    },
}

impl Body<'_> {
    /// Encoded length and the answer/authority counts.
    fn measure(&self, qtype: u16) -> Result<(usize, u16, u16), WriteError> {
        match self {
            Self::Empty => Ok((0, 0, 0)),
            Self::Specs { answer, authority } => {
                let mut len = 0usize;
                for r in answer.iter().chain(authority.iter()) {
                    len = len.saturating_add(r.len()?);
                }
                Ok((len, count(answer.len())?, count(authority.len())?))
            }
            Self::Addrs { list, .. } => {
                let mut len = 0usize;
                let mut n = 0usize;
                list.for_each(|a| {
                    if let Some(rdlen) = addr_rdlen(a, qtype) {
                        len = len.saturating_add(12).saturating_add(usize::from(rdlen));
                        n = n.saturating_add(1);
                    }
                    Ok(())
                })?;
                Ok((len, count(n)?, 0))
            }
            Self::Blob { bytes, an, ns, .. } => Ok((bytes.len(), *an, *ns)),
        }
    }

    fn write(&self, o: &mut Out<'_>, qtype: u16, rclass: u16) -> Result<(), WriteError> {
        match self {
            Self::Empty => Ok(()),
            Self::Specs { answer, authority } => {
                for r in answer.iter().chain(authority.iter()) {
                    r.write(o, rclass)?;
                }
                Ok(())
            }
            Self::Addrs { list, ttl } => list.for_each(|a| {
                let Some(rdlen) = addr_rdlen(a, qtype) else {
                    return Ok(());
                };
                o.u16(0xC00C)?;
                o.u16(qtype)?;
                o.u16(rclass)?;
                o.u32(*ttl)?;
                o.u16(rdlen)?;
                match a {
                    IpAddr::V4(v) => o.put(&v.octets()),
                    IpAddr::V6(v) => o.put(&v.octets()),
                }
            }),
            Self::Blob {
                bytes, ttls, rule, ..
            } => {
                let start = o.pos();
                o.put(bytes)?;
                for slot in *ttls {
                    o.patch_u32(
                        start.saturating_add(usize::from(slot.offset)),
                        rule.apply(slot.ttl),
                    )?;
                }
                Ok(())
            }
        }
    }
}

fn addr_rdlen(a: IpAddr, qtype: u16) -> Option<u16> {
    match (a, qtype) {
        (IpAddr::V4(_), rtype::A) => Some(4),
        (IpAddr::V6(_), rtype::AAAA) => Some(16),
        _ => None,
    }
}

fn count(n: usize) -> Result<u16, WriteError> {
    u16::try_from(n).map_err(|_| WriteError::TooLong)
}

/// The fixed part of an OPT record (owner, TYPE, CLASS, TTL, RDLENGTH).
pub(crate) const OPT_FIXED: usize = 11;

/// Writes our own OPT: the listener's UDP payload size (at least 512), the rcode's upper 8 bits,
/// version 0, the client's DO, the planned EDE options and, last, a Padding option with `pad`
/// zero bytes when `pad` is `Some`.
pub(crate) fn write_opt(
    o: &mut Out<'_>,
    rc: u16,
    do_bit: bool,
    payload: u16,
    ede: &[EdeOption<'_>],
    plan: Option<&EdePlan>,
    pad: Option<usize>,
) -> Result<(), WriteError> {
    o.u8(0)?;
    o.u16(rtype::OPT)?;
    o.u16(payload.max(512))?;
    o.u8(u8::try_from(rc >> 4).unwrap_or(0))?;
    o.u8(0)?;
    o.u16(if do_bit { 0x8000 } else { 0 })?;
    let padding = pad.map_or(0, |n| n.saturating_add(4));
    let rdlen = plan.map_or(0, |p| p.size(ede)).saturating_add(padding);
    o.u16(u16::try_from(rdlen).map_err(|_| WriteError::TooLong)?)?;
    if let Some(p) = plan {
        p.write(o, ede)?;
    }
    if let Some(n) = pad {
        o.u16(edns_code::PADDING)?;
        o.u16(u16::try_from(n).map_err(|_| WriteError::TooLong)?)?;
        o.zeros(n)?;
    }
    Ok(())
}

/// The zero bytes of the Padding option that brings a `len`-byte reply to the next multiple of
/// [`REPLY_PAD_BLOCK`] (the option's own 4 header bytes count), or as far as `limit` allows when
/// the next block is over it (RFC 7830 §4: never past the client's maximum). `None` when not even
/// an empty option fits.
fn reply_padding(len: usize, limit: usize) -> Option<usize> {
    let with_header = len.checked_add(4)?;
    if with_header > limit {
        return None;
    }
    let padded = with_header
        .div_ceil(REPLY_PAD_BLOCK)
        .saturating_mul(REPLY_PAD_BLOCK)
        .min(limit);
    Some(padded.saturating_sub(with_header))
}

/// Writes a complete reply.
pub(crate) fn assemble(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    rc: u16,
    body: Body<'_>,
    ede: &[EdeOption<'_>],
) -> Result<Reply, WriteError> {
    assemble_flags(out, to, rc, Flags::default(), body, ede)
}

/// Header choices beyond the size rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Flags {
    /// Set AA: an answer for a name the edge is the authority for.
    pub aa: bool,
    /// Send the TC form whatever the size: the upstream answer the reply serves had TC set, so
    /// its records may be partial (RFC 1035 §4.1.1, RFC 2181 §9).
    pub truncated: bool,
}

/// Writes a complete reply with `flags`.
pub(crate) fn assemble_flags(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    rc: u16,
    flags: Flags,
    body: Body<'_>,
    ede: &[EdeOption<'_>],
) -> Result<Reply, WriteError> {
    let qtype = to.qtype();
    let (body_len, an, ns) = body.measure(qtype)?;
    let has_opt = to.client_opt.is_some();
    // EDE only when the query has an OPT (RFC 6891 §7).
    let ede = if has_opt { ede } else { &[] };
    let base = 12usize
        .saturating_add(to.question.len())
        .saturating_add(if has_opt { OPT_FIXED } else { 0 });
    let full = base.saturating_add(body_len);
    let mut plan = EdePlan::new(ede);
    let tc = if flags.truncated || full > to.limit {
        plan = EdePlan::none();
        true
    } else {
        plan.shrink_to(ede, to.limit.saturating_sub(full));
        false
    };
    // Padding last, within the limit, after the EDE and TC choices (RFC 7830 §4).
    let pad = if has_opt && to.pad {
        let len = if tc { base } else { full }.saturating_add(plan.size(ede));
        reply_padding(len, to.limit)
    } else {
        None
    };
    let aa = flags.aa;
    // An extended rcode needs an OPT to carry its upper bits.
    let rc = if rc > 0x0F && !has_opt {
        rcode::SERVFAIL
    } else {
        rc
    };

    let mut o = Out::new(out);
    o.u16(to.id)?;
    o.u8(0x80 | if aa { 0x04 } else { 0 } | if tc { 0x02 } else { 0 } | u8::from(to.rd))?;
    o.u8(0x80 | if to.cd { 0x10 } else { 0 } | (rc & 0x0F) as u8)?;
    o.u16(u16::from(!to.question.is_empty()))?;
    o.u16(if tc { 0 } else { an })?;
    o.u16(if tc { 0 } else { ns })?;
    o.u16(u16::from(has_opt))?;
    o.put(to.question)?;
    if !tc {
        body.write(&mut o, qtype, to.record_class())?;
    }
    if let Some(do_bit) = to.client_opt {
        write_opt(&mut o, rc, do_bit, to.payload, ede, Some(&plan), pad)?;
    }
    Ok(Reply {
        len: o.pos(),
        tc,
        ede: plan.kept(),
    })
}

/// A reply with only an rcode: REFUSED, SERVFAIL, NOTIMP, … with optional EDE options
/// (e.g. REFUSED with EDE 18, SERVFAIL with EDE 23).
pub fn write_rcode(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    rc: u16,
    ede: &[EdeOption<'_>],
) -> Result<Reply, WriteError> {
    assemble(out, to, rc, Body::Empty, ede)
}

/// A negative answer kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegativeKind {
    Nxdomain,
    Nodata,
}

const SOA_MNAME: NameRef<'static> = NameRef::from_static(b"\x02ns\x06picket\x07invalid\x00");
const SOA_RNAME: NameRef<'static> = NameRef::from_static(b"\x0ahostmaster\x06picket\x07invalid\x00");

/// The synthesised SOA of a negative answer: owned by the question's name, with TTL and
/// MINIMUM both `ttl` (edge.md §4), so downstream negative caching lasts `ttl`.
pub fn synthesised_soa(ttl: u32) -> RecordSpec<'static> {
    RecordSpec {
        owner: None,
        ttl,
        data: RecordData::Soa {
            mname: SOA_MNAME,
            rname: SOA_RNAME,
            serial: 1,
            refresh: 1800,
            retry: 900,
            expire: 604_800,
            minimum: ttl,
        },
    }
}

/// NXDOMAIN or NODATA with a synthesised SOA whose TTL and MINIMUM are `ttl`.
pub fn write_negative(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    kind: NegativeKind,
    ttl: u32,
    ede: &[EdeOption<'_>],
) -> Result<Reply, WriteError> {
    let soa = [synthesised_soa(ttl)];
    let rc = match kind {
        NegativeKind::Nxdomain => rcode::NXDOMAIN,
        NegativeKind::Nodata => rcode::NOERROR,
    };
    assemble(
        out,
        to,
        rc,
        Body::Specs {
            answer: &[],
            authority: &soa,
        },
        ede,
    )
}

/// A sinkhole answer: `v4` for A, `v6` for AAAA, NODATA (with the synthesised SOA) for other
/// types. The EDE options are written as given.
pub fn write_sinkhole(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    ttl: u32,
    ede: &[EdeOption<'_>],
) -> Result<Reply, WriteError> {
    match to.qtype() {
        rtype::A => assemble(
            out,
            to,
            rcode::NOERROR,
            Body::Addrs {
                list: AddrList::V4(&[v4]),
                ttl,
            },
            ede,
        ),
        rtype::AAAA => assemble(
            out,
            to,
            rcode::NOERROR,
            Body::Addrs {
                list: AddrList::V6(&[v6]),
                ttl,
            },
            ede,
        ),
        _ => write_negative(out, to, NegativeKind::Nodata, ttl, ede),
    }
}

/// True when a block under `resp` answers this question with records (a sinkhole A or AAAA),
/// so the reply adds EDE 4 *Forged Answer* (edge.md §4). Under `custom_ip`, a family without a
/// configured address answers NODATA.
pub fn block_has_records(resp: &BlockResponse, qtype: u16) -> bool {
    match (resp.kind, qtype) {
        (BlockResponseType::NullIp, rtype::A | rtype::AAAA) => true,
        (BlockResponseType::CustomIp, rtype::A) => resp.ipv4.is_some(),
        (BlockResponseType::CustomIp, rtype::AAAA) => resp.ipv6.is_some(),
        _ => false,
    }
}

/// The blocked answer per the profile's `block_response` (edge.md §4 "Blocked answers"):
/// `null_ip` (0.0.0.0 or ::, NODATA for other types), `custom_ip` (`ipv4` for A, `ipv6` for AAAA;
/// NODATA for other types and for a family without an address), `nxdomain`, `nodata` or
/// `refused`, all with TTL `block_response.ttl`. Carries `block_ede` (EDE 15 with its tokens), plus
/// EDE 4 when the answer has records.
pub fn write_block(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    resp: &BlockResponse,
    block_ede: EdeOption<'_>,
) -> Result<Reply, WriteError> {
    let with_forged = [block_ede, EdeOption::forged()];
    let only = [block_ede];
    let ttl = resp.ttl;
    match resp.kind {
        BlockResponseType::NullIp | BlockResponseType::CustomIp => {
            if !block_has_records(resp, to.qtype()) {
                return write_negative(out, to, NegativeKind::Nodata, ttl, &only);
            }
            let (v4, v6) = match resp.kind {
                BlockResponseType::CustomIp => (
                    resp.ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    resp.ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED),
                ),
                _ => (Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED),
            };
            write_sinkhole(out, to, v4, v6, ttl, &with_forged)
        }
        BlockResponseType::Nxdomain => write_negative(out, to, NegativeKind::Nxdomain, ttl, &only),
        BlockResponseType::Nodata => write_negative(out, to, NegativeKind::Nodata, ttl, &only),
        BlockResponseType::Refused => write_rcode(out, to, rcode::REFUSED, &only),
    }
}

/// What a host-IP mapping answer turned out to be (edge.md §4 "Host-IP mappings").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingAnswer {
    /// The answer carries mapped addresses: a rewrite, no EDE, addresses go to the firewall.
    Rewrite,
    /// 0.0.0.0, :: or NODATA: a block, with EDE 15 (and 4 on records).
    Block,
}

/// A host-IP mapping under `null_ip`, as AdGuard Home's `default` blocking mode answers: A with
/// the mapped IPv4 addresses, AAAA with the IPv6 ones; a family with none gets 0.0.0.0 or ::,
/// other types NODATA. `ttl` is `block_response.ttl`; `block_ede` is used only on a block.
pub fn write_host_mapping(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    v4: &[Ipv4Addr],
    v6: &[Ipv6Addr],
    ttl: u32,
    block_ede: EdeOption<'_>,
) -> Result<(Reply, MappingAnswer), WriteError> {
    let list = match to.qtype() {
        rtype::A if !v4.is_empty() => Some(AddrList::V4(v4)),
        rtype::AAAA if !v6.is_empty() => Some(AddrList::V6(v6)),
        _ => None,
    };
    match list {
        Some(list) => Ok((
            assemble(out, to, rcode::NOERROR, Body::Addrs { list, ttl }, &[])?,
            MappingAnswer::Rewrite,
        )),
        None => {
            let resp = BlockResponse {
                kind: BlockResponseType::NullIp,
                ipv4: None,
                ipv6: None,
                ttl,
            };
            Ok((write_block(out, to, &resp, block_ede)?, MappingAnswer::Block))
        }
    }
}

/// A reply with the given records (rewrites and other local answers).
pub fn write_records(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    rc: u16,
    answer: &[RecordSpec<'_>],
    authority: &[RecordSpec<'_>],
    ede: &[EdeOption<'_>],
) -> Result<Reply, WriteError> {
    assemble(out, to, rc, Body::Specs { answer, authority }, ede)
}

/// The minimal answer to `ANY` (RFC 8482 §4.2): one HINFO record, CPU `RFC8482`, OS empty.
pub fn write_any_minimal(out: &mut [u8], to: &ReplyTo<'_>, ttl: u32) -> Result<Reply, WriteError> {
    let hinfo = [RecordSpec {
        owner: None,
        ttl,
        data: RecordData::Hinfo {
            cpu: b"RFC8482",
            os: b"",
        },
    }];
    write_records(out, to, rcode::NOERROR, &hinfo, &[], &[])
}

/// A local answer (a managed listener TLS name, edge.md §4): A or AAAA with the listener's
/// addresses of that family; NODATA with the synthesised SOA when it has none, or for other
/// types. The edge is the authority for these names, so AA is set.
pub fn write_local_answer(
    out: &mut [u8],
    to: &ReplyTo<'_>,
    addrs: &[IpAddr],
    ttl: u32,
) -> Result<Reply, WriteError> {
    let qtype = to.qtype();
    let any = addrs.iter().any(|a| addr_rdlen(*a, qtype).is_some());
    let soa = [synthesised_soa(ttl)];
    let body = if any {
        Body::Addrs {
            list: AddrList::Ips(addrs),
            ttl,
        }
    } else {
        Body::Specs {
            answer: &[],
            authority: &soa,
        }
    };
    let flags = Flags {
        aa: true,
        truncated: false,
    };
    assemble_flags(out, to, rcode::NOERROR, flags, body, &[])
}
