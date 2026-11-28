//! The ipset netlink protocol, built by hand from the kernel's uapi headers
//! (`include/uapi/linux/netfilter/ipset/ip_set.h`, `include/uapi/linux/netfilter/nfnetlink.h`)
//! and the kernel's `net/netfilter/ipset/ip_set_core.c` (edge-firewall.md §4 "Implementation").
//!
//! Pure functions only: request encoding, reply decoding. The socket lives in `client`. Every
//! decoder here treats the kernel's bytes as untrusted input (README "Untrusted input"): lengths
//! are checked before every slice, and nothing panics on malformed data (fuzzed in
//! `fuzz/helper`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NetlinkBuffer, NetlinkDeserializable,
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};

// ---- nfnetlink.h -------------------------------------------------------------------------------

/// `NFNL_SUBSYS_IPSET`: the nfnetlink subsystem id; the message type is `(subsys << 8) | cmd`.
pub const NFNL_SUBSYS_IPSET: u16 = 6;
/// `NFNETLINK_V0`: `nfgenmsg.version`.
pub const NFNETLINK_V0: u8 = 0;
/// `sizeof(struct nfgenmsg)`: `{u8 nfgen_family; u8 version; __be16 res_id}`.
pub const NFGENMSG_LEN: usize = 4;
/// `NFPROTO_IPV4` (== `AF_INET`).
pub const NFPROTO_IPV4: u8 = 2;
/// `NFPROTO_IPV6` (== `AF_INET6`).
pub const NFPROTO_IPV6: u8 = 10;

// ---- ip_set.h: protocol ------------------------------------------------------------------------

/// `IPSET_PROTOCOL`: the protocol version this client speaks (kernel 3.x and later: 6 or 7).
pub const IPSET_PROTOCOL: u8 = 7;
/// `IPSET_PROTOCOL_MIN`: the oldest version a kernel with protocol 7 still accepts.
pub const IPSET_PROTOCOL_MIN: u8 = 6;
/// `IPSET_MAXNAMELEN`: set and type names, including the terminating NUL.
pub const IPSET_MAXNAMELEN: usize = 32;

// ---- ip_set.h: enum ipset_cmd ------------------------------------------------------------------

pub const IPSET_CMD_PROTOCOL: u8 = 1;
pub const IPSET_CMD_CREATE: u8 = 2;
pub const IPSET_CMD_DESTROY: u8 = 3;
pub const IPSET_CMD_FLUSH: u8 = 4;
pub const IPSET_CMD_LIST: u8 = 7;
pub const IPSET_CMD_ADD: u8 = 9;
pub const IPSET_CMD_DEL: u8 = 10;
pub const IPSET_CMD_TYPE: u8 = 13;

// ---- ip_set.h: attributes at command level -----------------------------------------------------

pub const IPSET_ATTR_PROTOCOL: u16 = 1;
pub const IPSET_ATTR_SETNAME: u16 = 2;
pub const IPSET_ATTR_TYPENAME: u16 = 3;
pub const IPSET_ATTR_REVISION: u16 = 4;
pub const IPSET_ATTR_FAMILY: u16 = 5;
pub const IPSET_ATTR_FLAGS: u16 = 6;
pub const IPSET_ATTR_DATA: u16 = 7;
pub const IPSET_ATTR_ADT: u16 = 8;
pub const IPSET_ATTR_LINENO: u16 = 9;
/// `IPSET_ATTR_PROTOCOL_MIN`, also `IPSET_ATTR_REVISION_MIN` in a `TYPE` reply.
pub const IPSET_ATTR_PROTOCOL_MIN: u16 = 10;
pub const IPSET_ATTR_REVISION_MIN: u16 = 10;

// ---- ip_set.h: CADT (create and ADT) attributes, inside IPSET_ATTR_DATA ------------------------

pub const IPSET_ATTR_IP: u16 = 1;
pub const IPSET_ATTR_CIDR: u16 = 3;
pub const IPSET_ATTR_TIMEOUT: u16 = 6;
pub const IPSET_ATTR_CADT_FLAGS: u16 = 8;
// create-only
pub const IPSET_ATTR_HASHSIZE: u16 = 18;
pub const IPSET_ATTR_MAXELEM: u16 = 19;
// kernel-only (LIST header)
pub const IPSET_ATTR_ELEMENTS: u16 = 24;
pub const IPSET_ATTR_REFERENCES: u16 = 25;
pub const IPSET_ATTR_MEMSIZE: u16 = 26;
// ADT-specific
pub const IPSET_ATTR_IP2: u16 = 20;
pub const IPSET_ATTR_CIDR2: u16 = 21;

// ---- ip_set.h: IP address attributes, nested inside IPSET_ATTR_IP / IPSET_ATTR_IP2 -------------

pub const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
pub const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

// ---- ip_set.h: flags at command level (IPSET_ATTR_FLAGS) ---------------------------------------

/// `IPSET_FLAG_LIST_HEADER`: `LIST` returns the header only, no members.
pub const IPSET_FLAG_LIST_HEADER: u32 = 1 << 2;

// ---- ip_set.h: flags of an element (IPSET_ATTR_CADT_FLAGS) -------------------------------------

/// `IPSET_FLAG_NOMATCH`: the element is an exception, a packet it matches doesn't match the set.
pub const IPSET_FLAG_NOMATCH: u32 = 1 << 2;

// ---- ip_set.h: enum ipset_errno, and ip_set_hash.h ---------------------------------------------

pub const IPSET_ERR_PRIVATE: i32 = 4096;
pub const IPSET_ERR_PROTOCOL: i32 = 4097;
pub const IPSET_ERR_FIND_TYPE: i32 = 4098;
pub const IPSET_ERR_MAX_SETS: i32 = 4099;
pub const IPSET_ERR_BUSY: i32 = 4100;
pub const IPSET_ERR_EXIST_SETNAME2: i32 = 4101;
pub const IPSET_ERR_TYPE_MISMATCH: i32 = 4102;
pub const IPSET_ERR_EXIST: i32 = 4103;
pub const IPSET_ERR_INVALID_CIDR: i32 = 4104;
pub const IPSET_ERR_INVALID_NETMASK: i32 = 4105;
pub const IPSET_ERR_INVALID_FAMILY: i32 = 4106;
pub const IPSET_ERR_TIMEOUT: i32 = 4107;
pub const IPSET_ERR_REFERENCED: i32 = 4108;
/// `IPSET_ERR_TYPE_SPECIFIC`; for hash types `IPSET_ERR_HASH_FULL` (ip_set_hash.h).
pub const IPSET_ERR_HASH_FULL: i32 = 4352;
pub const IPSET_ERR_HASH_ELEM: i32 = 4353;

// ---- netlink attribute flags (linux/netlink.h) -------------------------------------------------

pub const NLA_F_NESTED: u16 = 0x8000;
pub const NLA_F_NET_BYTEORDER: u16 = 0x4000;
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
const NLA_HDRLEN: usize = 4;
const NLMSG_HDRLEN: usize = 16;

/// Align to 4 bytes (`NLA_ALIGN` / `NLMSG_ALIGN`).
pub const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// The netlink message type of an ipset command.
pub const fn msg_type(cmd: u8) -> u16 {
    (NFNL_SUBSYS_IPSET << 8) | cmd as u16
}

/// Address family of an ipset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SetFamily {
    Inet,
    Inet6,
}

impl SetFamily {
    pub fn nfproto(self) -> u8 {
        match self {
            SetFamily::Inet => NFPROTO_IPV4,
            SetFamily::Inet6 => NFPROTO_IPV6,
        }
    }
    pub fn from_nfproto(v: u8) -> Option<Self> {
        match v {
            NFPROTO_IPV4 => Some(SetFamily::Inet),
            NFPROTO_IPV6 => Some(SetFamily::Inet6),
            _ => None,
        }
    }
    pub fn host_mask(self) -> u8 {
        match self {
            SetFamily::Inet => 32,
            SetFamily::Inet6 => 128,
        }
    }
    pub fn of(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => SetFamily::Inet,
            IpAddr::V6(_) => SetFamily::Inet6,
        }
    }
}

/// The three set types Picket uses (edge-firewall.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SetType {
    /// `hash:net,net`, matched `src,dst`: per_client_ip.
    HashNetNet,
    /// `hash:ip`: global.
    HashIp,
    /// `hash:net`: static and exempt.
    HashNet,
}

impl SetType {
    pub fn name(self) -> &'static str {
        match self {
            SetType::HashNetNet => "hash:net,net",
            SetType::HashIp => "hash:ip",
            SetType::HashNet => "hash:net",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "hash:net,net" => Some(SetType::HashNetNet),
            "hash:ip" => Some(SetType::HashIp),
            "hash:net" => Some(SetType::HashNet),
            _ => None,
        }
    }
}

/// One element of a set: `ip[/cidr][,ip2[/cidr2]]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Elem {
    pub ip: IpAddr,
    pub cidr: Option<u8>,
    pub ip2: Option<IpAddr>,
    pub cidr2: Option<u8>,
}

impl Elem {
    /// A `hash:ip` element.
    pub fn ip(ip: IpAddr) -> Self {
        Self {
            ip,
            cidr: None,
            ip2: None,
            cidr2: None,
        }
    }
    /// A `hash:net` element.
    pub fn net(ip: IpAddr, cidr: u8) -> Self {
        Self {
            ip,
            cidr: Some(cidr),
            ip2: None,
            cidr2: None,
        }
    }
    /// A `hash:net,net` element of two host addresses (`/32` or `/128` members).
    pub fn host_pair(src: IpAddr, dst: IpAddr) -> Self {
        let m = SetFamily::of(&src).host_mask();
        Self {
            ip: src,
            cidr: Some(m),
            ip2: Some(dst),
            cidr2: Some(m),
        }
    }
}

/// A member as `LIST` returns it, with its remaining timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub elem: Elem,
    /// Remaining seconds; `None` on a set without timeouts, `Some(0)` for a permanent entry
    /// (kernel `ip_set_timeout_get`).
    pub timeout: Option<u32>,
    /// A `nomatch` element (`IPSET_FLAG_NOMATCH`): an exception inside a wider element.
    pub nomatch: bool,
}

/// Header data of a set (`LIST` with `IPSET_FLAG_LIST_HEADER`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetHeader {
    pub name: String,
    pub type_name: String,
    pub family: Option<SetFamily>,
    pub revision: u8,
    pub maxelem: Option<u32>,
    pub elements: Option<u32>,
    pub references: Option<u32>,
    /// The set's default timeout; present only on sets created with timeout support.
    pub timeout: Option<u32>,
    /// Members of a `LIST` that didn't decode (skipped).
    pub undecoded: u32,
}

// ---- attribute writer --------------------------------------------------------------------------

/// Encodes netlink attributes (`struct nlattr` TLVs, 4-byte aligned).
#[derive(Default)]
pub struct AttrWriter {
    buf: Vec<u8>,
    nests: Vec<usize>,
}

impl AttrWriter {
    pub fn new() -> Self {
        Self::default()
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "every attribute the request builders write is a set name (at most 32 bytes), an \
                  address, a port or a 32-bit value: far below 64 KiB"
    )]
    fn put(&mut self, kind: u16, value: &[u8]) {
        let len = NLA_HDRLEN + value.len();
        debug_assert!(len <= u16::MAX as usize);
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(value);
        self.buf.resize(align4(self.buf.len()), 0);
    }

    pub fn u8(&mut self, kind: u16, v: u8) -> &mut Self {
        self.put(kind, &[v]);
        self
    }

    /// A 32-bit value in network byte order, flagged `NLA_F_NET_BYTEORDER` as the kernel's
    /// `ip_set_attr_netorder` requires for timeouts, maxelem, hashsize and flags.
    pub fn be32(&mut self, kind: u16, v: u32) -> &mut Self {
        self.put(kind | NLA_F_NET_BYTEORDER, &v.to_be_bytes());
        self
    }

    /// A NUL-terminated string (`NLA_NUL_STRING`, like `mnl_attr_put_strz`).
    pub fn strz(&mut self, kind: u16, s: &str) -> &mut Self {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.put(kind, &v);
        self
    }

    pub fn begin_nested(&mut self, kind: u16) -> &mut Self {
        self.nests.push(self.buf.len());
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        self
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "a nest holds one element's few attributes (a request carries at most one): far \
                  below 64 KiB"
    )]
    pub fn end_nested(&mut self) -> &mut Self {
        if let Some(start) = self.nests.pop() {
            let len = (self.buf.len() - start) as u16;
            self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        }
        self
    }

    /// An address: a nested attribute holding `IPSET_ATTR_IPADDR_IPV4|6` in network byte order
    /// (kernel `ip_set_get_ipaddr4` / `ip_set_get_ipaddr6`).
    pub fn ip(&mut self, kind: u16, ip: &IpAddr) -> &mut Self {
        self.begin_nested(kind);
        match ip {
            IpAddr::V4(a) => self.put(IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER, &a.octets()),
            IpAddr::V6(a) => self.put(IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER, &a.octets()),
        }
        self.end_nested()
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

// ---- attribute parser --------------------------------------------------------------------------

/// One decoded attribute.
#[derive(Clone, Copy, Debug)]
pub struct Attr<'a> {
    pub kind: u16,
    pub nested: bool,
    pub value: &'a [u8],
}

impl<'a> Attr<'a> {
    pub fn u8(&self) -> Option<u8> {
        self.value.first().copied()
    }
    pub fn be32(&self) -> Option<u32> {
        let b: [u8; 4] = self.value.get(..4)?.try_into().ok()?;
        Some(u32::from_be_bytes(b))
    }
    pub fn be16(&self) -> Option<u16> {
        let b: [u8; 2] = self.value.get(..2)?.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    }
    /// A NUL-terminated or plain string, at most `IPSET_MAXNAMELEN` bytes; `None` if not UTF-8.
    pub fn string(&self) -> Option<String> {
        let v = self.value;
        let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
        let s = std::str::from_utf8(&v[..end.min(IPSET_MAXNAMELEN)]).ok()?;
        Some(s.to_string())
    }
    pub fn children(&self) -> AttrIter<'a> {
        AttrIter { buf: self.value }
    }
    /// A nested IPv4/IPv6 address attribute.
    pub fn ip(&self) -> Option<IpAddr> {
        for a in self.children() {
            let a = a.ok()?;
            match a.kind {
                IPSET_ATTR_IPADDR_IPV4 => {
                    let b: [u8; 4] = a.value.get(..4)?.try_into().ok()?;
                    return Some(IpAddr::V4(Ipv4Addr::from(b)));
                }
                IPSET_ATTR_IPADDR_IPV6 => {
                    let b: [u8; 16] = a.value.get(..16)?.try_into().ok()?;
                    return Some(IpAddr::V6(Ipv6Addr::from(b)));
                }
                _ => {}
            }
        }
        None
    }
}

/// Iterates over a buffer of attributes. A malformed attribute yields one error and ends the
/// iteration.
#[derive(Clone)]
pub struct AttrIter<'a> {
    buf: &'a [u8],
}

pub fn attrs(buf: &[u8]) -> AttrIter<'_> {
    AttrIter { buf }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Result<Attr<'a>, DecodeError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < NLA_HDRLEN {
            // Trailing padding shorter than a header is ignored, like the kernel's nla_ok().
            self.buf = &[];
            return None;
        }
        let len = u16::from_ne_bytes([self.buf[0], self.buf[1]]) as usize;
        let raw_kind = u16::from_ne_bytes([self.buf[2], self.buf[3]]);
        if len < NLA_HDRLEN || len > self.buf.len() {
            self.buf = &[];
            return Some(Err(DecodeError::Attr));
        }
        let value = &self.buf[NLA_HDRLEN..len];
        let next = align4(len).min(self.buf.len());
        self.buf = &self.buf[next..];
        Some(Ok(Attr {
            kind: raw_kind & NLA_TYPE_MASK,
            nested: raw_kind & NLA_F_NESTED != 0,
            value,
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("malformed netlink message")]
    Message,
    #[error("malformed netlink attribute")]
    Attr,
    #[error("unexpected netlink message type {0:#x}")]
    UnexpectedType(u16),
}

// ---- requests ----------------------------------------------------------------------------------

/// One ipset request: command, header flags and encoded attributes (after `nfgenmsg`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub cmd: u8,
    pub flags: u16,
    pub attrs: Vec<u8>,
}

/// The `nfgenmsg` + attributes payload, as netlink-packet-core's inner message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpsetPayload {
    pub message_type: u16,
    pub body: Vec<u8>,
}

impl NetlinkSerializable for IpsetPayload {
    fn message_type(&self) -> u16 {
        self.message_type
    }
    fn buffer_len(&self) -> usize {
        self.body.len()
    }
    fn serialize(&self, buffer: &mut [u8]) {
        buffer[..self.body.len()].copy_from_slice(&self.body);
    }
}

impl NetlinkDeserializable for IpsetPayload {
    type Error = DecodeError;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            message_type: header.message_type,
            body: payload.to_vec(),
        })
    }
}

impl Request {
    /// Encodes the request as one netlink message with sequence number `seq`. The `nfgenmsg`
    /// family is `AF_INET` as in libipset (`ipset_mnl_fill_hdr`); the kernel reads the set
    /// family from `IPSET_ATTR_FAMILY`.
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let mut body = Vec::with_capacity(NFGENMSG_LEN + self.attrs.len());
        body.push(NFPROTO_IPV4);
        body.push(NFNETLINK_V0);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&self.attrs);
        let mut header = NetlinkHeader::default();
        header.flags = self.flags;
        header.sequence_number = seq;
        let mut msg = NetlinkMessage::new(
            header,
            NetlinkPayload::InnerMessage(IpsetPayload {
                message_type: msg_type(self.cmd),
                body,
            }),
        );
        msg.finalize();
        let mut out = vec![0u8; msg.buffer_len()];
        msg.serialize(&mut out);
        out
    }

    pub fn wants_ack(&self) -> bool {
        self.flags & NLM_F_ACK != 0
    }
    pub fn is_dump(&self) -> bool {
        self.flags & NLM_F_DUMP == NLM_F_DUMP
    }
}

fn base(protocol: u8, name: Option<&str>) -> AttrWriter {
    let mut w = AttrWriter::new();
    w.u8(IPSET_ATTR_PROTOCOL, protocol);
    if let Some(n) = name {
        w.strz(IPSET_ATTR_SETNAME, n);
    }
    w
}

/// `IPSET_CMD_PROTOCOL`: asks the kernel for its protocol version.
pub fn req_protocol() -> Request {
    Request {
        cmd: IPSET_CMD_PROTOCOL,
        flags: NLM_F_REQUEST,
        attrs: base(IPSET_PROTOCOL, None).finish(),
    }
}

/// `IPSET_CMD_TYPE`: the revision range the kernel supports for a set type and family.
pub fn req_type(protocol: u8, t: SetType, family: SetFamily) -> Request {
    let mut w = base(protocol, None);
    w.strz(IPSET_ATTR_TYPENAME, t.name())
        .u8(IPSET_ATTR_FAMILY, family.nfproto());
    Request {
        cmd: IPSET_CMD_TYPE,
        flags: NLM_F_REQUEST,
        attrs: w.finish(),
    }
}

/// What a set is created with (edge-firewall.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSpec {
    pub name: String,
    pub set_type: SetType,
    pub family: SetFamily,
    pub revision: u8,
    /// Default timeout; `None` for a set without timeout support.
    pub timeout: Option<u32>,
    pub maxelem: u32,
}

/// `IPSET_CMD_CREATE` without `NLM_F_EXCL`, so an identical existing set is not an error
/// (kernel `ip_set_create`, like `ipset create -exist`).
pub fn req_create(protocol: u8, spec: &CreateSpec) -> Request {
    let mut w = base(protocol, Some(&spec.name));
    w.strz(IPSET_ATTR_TYPENAME, spec.set_type.name())
        .u8(IPSET_ATTR_REVISION, spec.revision)
        .u8(IPSET_ATTR_FAMILY, spec.family.nfproto())
        .begin_nested(IPSET_ATTR_DATA);
    if let Some(t) = spec.timeout {
        w.be32(IPSET_ATTR_TIMEOUT, t);
    }
    w.be32(IPSET_ATTR_MAXELEM, spec.maxelem).end_nested();
    Request {
        cmd: IPSET_CMD_CREATE,
        flags: NLM_F_REQUEST | NLM_F_ACK,
        attrs: w.finish(),
    }
}

/// `IPSET_CMD_DESTROY` of one set.
pub fn req_destroy(protocol: u8, name: &str) -> Request {
    Request {
        cmd: IPSET_CMD_DESTROY,
        flags: NLM_F_REQUEST | NLM_F_ACK,
        attrs: base(protocol, Some(name)).finish(),
    }
}

/// `IPSET_CMD_FLUSH` of one set.
pub fn req_flush(protocol: u8, name: &str) -> Request {
    Request {
        cmd: IPSET_CMD_FLUSH,
        flags: NLM_F_REQUEST | NLM_F_ACK,
        attrs: base(protocol, Some(name)).finish(),
    }
}

fn elem_attrs(w: &mut AttrWriter, e: &Elem, timeout: Option<u32>) {
    w.begin_nested(IPSET_ATTR_DATA);
    w.ip(IPSET_ATTR_IP, &e.ip);
    if let Some(c) = e.cidr {
        w.u8(IPSET_ATTR_CIDR, c);
    }
    if let Some(t) = timeout {
        w.be32(IPSET_ATTR_TIMEOUT, t);
    }
    if let Some(ip2) = &e.ip2 {
        w.ip(IPSET_ATTR_IP2, ip2);
    }
    if let Some(c) = e.cidr2 {
        w.u8(IPSET_ATTR_CIDR2, c);
    }
    w.end_nested();
}

/// `IPSET_CMD_ADD` of one element, **without** `NLM_F_EXCL`: the kernel then sets
/// `IPSET_FLAG_EXIST` (`flag_exist()` in ip_set_core.c), so an existing element is not an error
/// and its timeout is overwritten, like `ipset add -exist` (edge-firewall.md §4).
pub fn req_add(protocol: u8, set: &str, e: &Elem, timeout: Option<u32>) -> Request {
    let mut w = base(protocol, Some(set));
    elem_attrs(&mut w, e, timeout);
    Request {
        cmd: IPSET_CMD_ADD,
        flags: NLM_F_REQUEST | NLM_F_ACK,
        attrs: w.finish(),
    }
}

/// `IPSET_CMD_DEL` of one element, without `NLM_F_EXCL`, so deleting an absent element is not
/// an error.
pub fn req_del(protocol: u8, set: &str, e: &Elem) -> Request {
    let mut w = base(protocol, Some(set));
    elem_attrs(&mut w, e, None);
    Request {
        cmd: IPSET_CMD_DEL,
        flags: NLM_F_REQUEST | NLM_F_ACK,
        attrs: w.finish(),
    }
}

/// `IPSET_CMD_LIST` of one set as a dump; with `header_only`, `IPSET_FLAG_LIST_HEADER`.
/// No `NLM_F_ACK`: a dump ends with `NLMSG_DONE` (or an `NLMSG_ERROR` from its start callback).
pub fn req_list(protocol: u8, set: &str, header_only: bool) -> Request {
    let mut w = base(protocol, Some(set));
    if header_only {
        w.be32(IPSET_ATTR_FLAGS, IPSET_FLAG_LIST_HEADER);
    }
    Request {
        cmd: IPSET_CMD_LIST,
        flags: NLM_F_REQUEST | NLM_F_DUMP,
        attrs: w.finish(),
    }
}

// ---- replies -----------------------------------------------------------------------------------

/// One decoded netlink message from the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `NLMSG_ERROR` with code 0.
    Ack { seq: u32 },
    /// `NLMSG_ERROR` with a non-zero code (positive errno, e.g. `IPSET_ERR_HASH_FULL`).
    Error { seq: u32, errno: i32 },
    /// `NLMSG_DONE`; `errno` non-zero if the dump failed part-way.
    Done { seq: u32, errno: i32 },
    /// An ipset message (`LIST`, `TYPE`, `PROTOCOL` reply): command and attributes after
    /// `nfgenmsg`.
    Ipset { seq: u32, cmd: u8, attrs: Vec<u8> },
    /// Any other message type (ignored).
    Other { seq: u32 },
}

impl Reply {
    pub fn seq(&self) -> u32 {
        match self {
            Reply::Ack { seq }
            | Reply::Error { seq, .. }
            | Reply::Done { seq, .. }
            | Reply::Ipset { seq, .. }
            | Reply::Other { seq } => *seq,
        }
    }
}

/// Splits one datagram into netlink messages and decodes each. Bounds-checked: a truncated or
/// inconsistent message ends decoding with an error.
pub fn decode_datagram(mut buf: &[u8]) -> Result<Vec<Reply>, DecodeError> {
    let mut out = Vec::new();
    while buf.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            return Err(DecodeError::Message);
        }
        out.push(decode_message(&buf[..len])?);
        let next = align4(len).min(buf.len());
        buf = &buf[next..];
    }
    Ok(out)
}

fn decode_message(msg: &[u8]) -> Result<Reply, DecodeError> {
    let nb = NetlinkBuffer::new_checked(msg).map_err(|_| DecodeError::Message)?;
    let seq = nb.sequence_number();
    let ty = nb.message_type();
    let payload = nb.payload();
    match ty {
        NLMSG_ERROR | NLMSG_DONE => {
            let parsed =
                NetlinkMessage::<IpsetPayload>::deserialize(msg).map_err(|_| DecodeError::Message)?;
            match parsed.payload {
                NetlinkPayload::Error(e) => {
                    let code = e.raw_code();
                    if code == 0 {
                        Ok(Reply::Ack { seq })
                    } else {
                        Ok(Reply::Error {
                            seq,
                            errno: code.checked_neg().unwrap_or(i32::MAX),
                        })
                    }
                }
                NetlinkPayload::Done(d) => Ok(Reply::Done {
                    seq,
                    errno: d.code.checked_neg().unwrap_or(i32::MAX),
                }),
                _ => Err(DecodeError::Message),
            }
        }
        t if t >> 8 == NFNL_SUBSYS_IPSET => {
            if payload.len() < NFGENMSG_LEN {
                return Err(DecodeError::Message);
            }
            Ok(Reply::Ipset {
                seq,
                cmd: (t & 0xff) as u8,
                attrs: payload[NFGENMSG_LEN..].to_vec(),
            })
        }
        _ => Ok(Reply::Other { seq }),
    }
}

/// Decodes a `PROTOCOL` reply: `(protocol, protocol_min)`.
pub fn decode_protocol(attrs_buf: &[u8]) -> Result<(u8, Option<u8>), DecodeError> {
    let mut proto = None;
    let mut min = None;
    for a in attrs(attrs_buf) {
        let a = a?;
        match a.kind {
            IPSET_ATTR_PROTOCOL => proto = a.u8(),
            IPSET_ATTR_PROTOCOL_MIN => min = a.u8(),
            _ => {}
        }
    }
    Ok((proto.ok_or(DecodeError::Attr)?, min))
}

/// Decodes a `TYPE` reply: `(revision_max, revision_min)`.
pub fn decode_type(attrs_buf: &[u8]) -> Result<(u8, u8), DecodeError> {
    let mut max = None;
    let mut min = None;
    for a in attrs(attrs_buf) {
        let a = a?;
        match a.kind {
            IPSET_ATTR_REVISION => max = a.u8(),
            IPSET_ATTR_REVISION_MIN => min = a.u8(),
            _ => {}
        }
    }
    let max = max.ok_or(DecodeError::Attr)?;
    Ok((max, min.unwrap_or(0)))
}

/// Decodes one `LIST` message: header fields (first message of a set) into `header`, and each
/// member into `sink`. Members that don't decode are skipped and counted in the return value.
pub fn decode_list(
    attrs_buf: &[u8],
    header: &mut SetHeader,
    sink: &mut dyn FnMut(Member),
) -> Result<usize, DecodeError> {
    let mut bad = 0;
    for a in attrs(attrs_buf) {
        let a = a?;
        match a.kind {
            IPSET_ATTR_SETNAME => header.name = a.string().unwrap_or_default(),
            IPSET_ATTR_TYPENAME => header.type_name = a.string().unwrap_or_default(),
            IPSET_ATTR_FAMILY => header.family = a.u8().and_then(SetFamily::from_nfproto),
            IPSET_ATTR_REVISION => header.revision = a.u8().unwrap_or(0),
            IPSET_ATTR_DATA if a.nested => {
                for d in a.children() {
                    let d = d?;
                    match d.kind {
                        IPSET_ATTR_MAXELEM => header.maxelem = d.be32(),
                        IPSET_ATTR_ELEMENTS => header.elements = d.be32(),
                        IPSET_ATTR_REFERENCES => header.references = d.be32(),
                        IPSET_ATTR_TIMEOUT => header.timeout = d.be32(),
                        _ => {}
                    }
                }
            }
            IPSET_ATTR_ADT if a.nested => {
                for d in a.children() {
                    let d = d?;
                    if d.kind != IPSET_ATTR_DATA || !d.nested {
                        continue;
                    }
                    match decode_member(&d) {
                        Some(m) => sink(m),
                        None => bad += 1,
                    }
                }
            }
            _ => {}
        }
    }
    Ok(bad)
}

fn decode_member(data: &Attr<'_>) -> Option<Member> {
    let mut ip = None;
    let mut ip2 = None;
    let mut cidr = None;
    let mut cidr2 = None;
    let mut timeout = None;
    let mut flags = 0;
    for a in data.children() {
        let a = a.ok()?;
        match a.kind {
            IPSET_ATTR_IP if a.nested => ip = Some(a.ip()?),
            IPSET_ATTR_IP2 if a.nested => ip2 = Some(a.ip()?),
            IPSET_ATTR_CIDR => cidr = Some(a.u8()?),
            IPSET_ATTR_CIDR2 => cidr2 = Some(a.u8()?),
            IPSET_ATTR_TIMEOUT => timeout = Some(a.be32()?),
            IPSET_ATTR_CADT_FLAGS => flags = a.be32()?,
            _ => {}
        }
    }
    let ip: IpAddr = ip?;
    let fam = SetFamily::of(&ip);
    // Range checks: a CIDR beyond the family's host mask or a second address of another family
    // is malformed.
    if cidr.is_some_and(|c| c > fam.host_mask()) || cidr2.is_some_and(|c| c > fam.host_mask()) {
        return None;
    }
    if ip2.is_some_and(|i| SetFamily::of(&i) != fam) {
        return None;
    }
    Some(Member {
        elem: Elem { ip, cidr, ip2, cidr2 },
        timeout,
        nomatch: flags & IPSET_FLAG_NOMATCH != 0,
    })
}

/// Maps an ipset errno to the reason string the protocol reports (`EntryFailure.reason`).
pub fn errno_reason(errno: i32) -> String {
    match errno {
        IPSET_ERR_HASH_FULL => "set_full".into(),
        2 => "no_set".into(), // ENOENT: no set with that name
        IPSET_ERR_PROTOCOL => "protocol".into(),
        IPSET_ERR_TYPE_MISMATCH | IPSET_ERR_INVALID_FAMILY => "type_mismatch".into(),
        IPSET_ERR_INVALID_CIDR => "invalid_cidr".into(),
        IPSET_ERR_TIMEOUT => "no_timeout_support".into(),
        IPSET_ERR_REFERENCED => "referenced".into(),
        1 | 13 => "permission".into(), // EPERM, EACCES
        e => format!("kernel_error_{e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Header bytes on a little-endian host (the targets are aarch64 and x86_64 LE).
    #[cfg(target_endian = "little")]
    #[test]
    fn protocol_request_bytes() {
        let b = req_protocol().encode(7);
        #[rustfmt::skip]
        let want: Vec<u8> = vec![
            // nlmsghdr: len 28, type 0x0601, flags NLM_F_REQUEST, seq 7, pid 0
            28, 0, 0, 0,  0x01, 0x06,  0x01, 0x00,  7, 0, 0, 0,  0, 0, 0, 0,
            // nfgenmsg: AF_INET, v0, res_id 0
            2, 0, 0, 0,
            // IPSET_ATTR_PROTOCOL = 7 (len 5, padded to 8)
            5, 0, 1, 0, 7, 0, 0, 0,
        ];
        assert_eq!(b, want);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn create_hash_net_net_bytes() {
        let spec = CreateSpec {
            name: "picket4".into(),
            set_type: SetType::HashNetNet,
            family: SetFamily::Inet,
            revision: 2,
            timeout: Some(300),
            maxelem: 262_144,
        };
        let b = req_create(7, &spec).encode(1);
        let attrs_part = &b[20..];
        #[rustfmt::skip]
        let want: Vec<u8> = vec![
            5, 0, 1, 0, 7, 0, 0, 0,                                   // PROTOCOL 7
            12, 0, 2, 0, b'p', b'i', b'c', b'k', b'e', b't', b'4', 0, // SETNAME "picket4\0"
            17, 0, 3, 0, b'h', b'a', b's', b'h', b':', b'n', b'e', b't', b',', b'n', b'e', b't', 0, 0, 0, 0, // TYPENAME
            5, 0, 4, 0, 2, 0, 0, 0,                                   // REVISION 2
            5, 0, 5, 0, 2, 0, 0, 0,                                   // FAMILY NFPROTO_IPV4
            20, 0, 7, 0x80,                                           // DATA (nested)
            8, 0, 6, 0x40, 0, 0, 1, 44,                               //   TIMEOUT 300 (net order)
            8, 0, 19, 0x40, 0, 4, 0, 0,                               //   MAXELEM 262144 (net order)
        ];
        assert_eq!(attrs_part, &want[..]);
        // header: type 0x0602, flags REQUEST|ACK, no EXCL
        assert_eq!(&b[4..8], &[0x02, 0x06, 0x05, 0x00]);
        assert_eq!(u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize, b.len());
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn add_pair_bytes_have_no_excl_and_net_order() {
        let e = Elem::host_pair(v4("192.168.1.10"), v4("93.184.216.34"));
        let b = req_add(7, "picket4", &e, Some(420)).encode(9);
        // flags: REQUEST|ACK only (0x0005): no NLM_F_EXCL (0x0200), so the add acts as -exist.
        assert_eq!(&b[4..8], &[0x09, 0x06, 0x05, 0x00]);
        let attrs_part = &b[20..];
        #[rustfmt::skip]
        let want: Vec<u8> = vec![
            5, 0, 1, 0, 7, 0, 0, 0,
            12, 0, 2, 0, b'p', b'i', b'c', b'k', b'e', b't', b'4', 0,
            52, 0, 7, 0x80,                                    // DATA
            12, 0, 1, 0x80,  8, 0, 1, 0x40, 192, 168, 1, 10,   //   IP { IPV4 net order }
            5, 0, 3, 0, 32, 0, 0, 0,                           //   CIDR 32
            8, 0, 6, 0x40, 0, 0, 1, 164,                       //   TIMEOUT 420
            12, 0, 20, 0x80, 8, 0, 1, 0x40, 93, 184, 216, 34,  //   IP2 { IPV4 }
            5, 0, 21, 0, 32, 0, 0, 0,                          //   CIDR2 32
        ];
        assert_eq!(attrs_part, &want[..]);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn add_hash_ip_v6_bytes() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let b = req_add(7, "picket-g6", &Elem::ip(ip), Some(1)).encode(2);
        let attrs_part = &b[20..];
        let mut want: Vec<u8> = vec![5, 0, 1, 0, 7, 0, 0, 0];
        want.extend_from_slice(&[14, 0, 2, 0]);
        want.extend_from_slice(b"picket-g6\0\0\0");
        want.extend_from_slice(&[36, 0, 7, 0x80, 24, 0, 1, 0x80, 20, 0, 2, 0x40]);
        want.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        want.extend_from_slice(&[8, 0, 6, 0x40, 0, 0, 0, 1]);
        assert_eq!(attrs_part, &want[..]);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn list_header_request_bytes() {
        let b = req_list(7, "picket-g4", true).encode(3);
        // type LIST, flags REQUEST|DUMP (0x0301), no ACK
        assert_eq!(&b[4..8], &[0x07, 0x06, 0x01, 0x03]);
        let attrs_part = &b[20..];
        let tail = &attrs_part[attrs_part.len() - 8..];
        assert_eq!(tail, &[8, 0, 6, 0x40, 0, 0, 0, 4]); // FLAGS = LIST_HEADER, net order
    }

    #[test]
    fn del_net_has_cidr_and_no_timeout() {
        let r = req_del(7, "picket-static4", &Elem::net(v4("10.0.0.0"), 8));
        let mut found_cidr = false;
        let mut found_timeout = false;
        for a in attrs(&r.attrs) {
            let a = a.unwrap();
            if a.kind == IPSET_ATTR_DATA {
                for c in a.children() {
                    let c = c.unwrap();
                    found_cidr |= c.kind == IPSET_ATTR_CIDR && c.u8() == Some(8);
                    found_timeout |= c.kind == IPSET_ATTR_TIMEOUT;
                }
            }
        }
        assert!(found_cidr && !found_timeout);
        assert_eq!(r.flags & netlink_packet_core::NLM_F_EXCL, 0);
    }

    /// Builds a kernel-style LIST message for tests (and the fuzz corpus).
    pub(crate) fn list_message(seq: u32, header: bool, members: &[(Elem, Option<u32>)]) -> Vec<u8> {
        let mut w = AttrWriter::new();
        w.u8(IPSET_ATTR_PROTOCOL, 7).strz(IPSET_ATTR_SETNAME, "picket4");
        if header {
            w.strz(IPSET_ATTR_TYPENAME, "hash:net,net")
                .u8(IPSET_ATTR_FAMILY, NFPROTO_IPV4)
                .u8(IPSET_ATTR_REVISION, 2)
                .begin_nested(IPSET_ATTR_DATA)
                .be32(IPSET_ATTR_HASHSIZE, 1024)
                .be32(IPSET_ATTR_MAXELEM, 262_144)
                .be32(IPSET_ATTR_REFERENCES, 1)
                .be32(IPSET_ATTR_MEMSIZE, 4096)
                .be32(IPSET_ATTR_ELEMENTS, members.len() as u32)
                .be32(IPSET_ATTR_TIMEOUT, 300)
                .end_nested();
        }
        if !members.is_empty() {
            w.begin_nested(IPSET_ATTR_ADT);
            for (e, t) in members {
                elem_attrs(&mut w, e, *t);
            }
            w.end_nested();
        }
        let req = Request {
            cmd: IPSET_CMD_LIST,
            flags: 2, /* NLM_F_MULTI */
            attrs: w.finish(),
        };
        req.encode(seq)
    }

    #[test]
    fn decode_list_marks_nomatch_members() {
        let mut w = AttrWriter::new();
        w.strz(IPSET_ATTR_SETNAME, "UBIOS_local_zoned_subnets")
            .strz(IPSET_ATTR_TYPENAME, "hash:net")
            .begin_nested(IPSET_ATTR_ADT);
        for (net, cidr, flags) in [("192.168.0.0", 16, 0), ("192.168.20.0", 24, IPSET_FLAG_NOMATCH)] {
            w.begin_nested(IPSET_ATTR_DATA);
            w.ip(IPSET_ATTR_IP, &v4(net));
            w.u8(IPSET_ATTR_CIDR, cidr);
            if flags != 0 {
                w.be32(IPSET_ATTR_CADT_FLAGS, flags);
            }
            w.end_nested();
        }
        w.end_nested();
        let mut h = SetHeader::default();
        let mut got = vec![];
        assert_eq!(decode_list(&w.finish(), &mut h, &mut |m| got.push(m)).unwrap(), 0);
        assert_eq!(h.type_name, "hash:net");
        assert_eq!(
            got.iter().map(|m| (m.elem, m.nomatch)).collect::<Vec<_>>(),
            vec![
                (Elem::net(v4("192.168.0.0"), 16), false),
                (Elem::net(v4("192.168.20.0"), 24), true)
            ]
        );
    }

    #[test]
    fn decode_list_reply_with_members_and_timeouts() {
        let m1 = Elem::host_pair(v4("192.168.1.10"), v4("1.1.1.1"));
        let m2 = Elem::host_pair(v4("192.168.1.11"), v4("8.8.8.8"));
        let mut dgram = list_message(5, true, &[(m1, Some(120)), (m2, Some(1))]);
        // NLMSG_DONE
        let mut done = vec![20, 0, 0, 0, 3, 0, 2, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        dgram.append(&mut done);
        let replies = decode_datagram(&dgram).unwrap();
        assert_eq!(replies.len(), 2);
        let Reply::Ipset { cmd, attrs: a, .. } = &replies[0] else {
            panic!()
        };
        assert_eq!(*cmd, IPSET_CMD_LIST);
        let mut h = SetHeader::default();
        let mut got = vec![];
        let bad = decode_list(a, &mut h, &mut |m| got.push(m)).unwrap();
        assert_eq!(bad, 0);
        assert_eq!(h.name, "picket4");
        assert_eq!(h.type_name, "hash:net,net");
        assert_eq!(h.family, Some(SetFamily::Inet));
        assert_eq!(h.maxelem, Some(262_144));
        assert_eq!(h.elements, Some(2));
        assert_eq!(h.timeout, Some(300));
        assert_eq!(
            got,
            vec![
                Member {
                    elem: m1,
                    timeout: Some(120),
                    nomatch: false,
                },
                Member {
                    elem: m2,
                    timeout: Some(1),
                    nomatch: false,
                }
            ]
        );
        assert_eq!(replies[1], Reply::Done { seq: 5, errno: 0 });
    }

    #[test]
    fn decode_error_and_ack() {
        // NLMSG_ERROR with -4352 (IPSET_ERR_HASH_FULL) and the echoed header
        let mut m = vec![36, 0, 0, 0, 2, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&(-4352i32).to_ne_bytes());
        m.extend_from_slice(&[0u8; 16]);
        let r = decode_datagram(&m).unwrap();
        assert_eq!(r, vec![Reply::Error { seq: 9, errno: 4352 }]);
        assert_eq!(errno_reason(4352), "set_full");
        let mut ack = vec![36, 0, 0, 0, 2, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0];
        ack.extend_from_slice(&0i32.to_ne_bytes());
        ack.extend_from_slice(&[0u8; 16]);
        assert_eq!(decode_datagram(&ack).unwrap(), vec![Reply::Ack { seq: 10 }]);
    }

    #[test]
    fn malformed_inputs_never_panic() {
        let good = list_message(
            1,
            true,
            &[(Elem::host_pair(v4("10.0.0.1"), v4("10.0.0.2")), Some(5))],
        );
        for cut in 0..good.len() {
            let _ = decode_datagram(&good[..cut]);
        }
        // Corrupt every byte in turn.
        for i in 0..good.len() {
            let mut b = good.clone();
            b[i] ^= 0xff;
            if let Ok(rs) = decode_datagram(&b) {
                for r in rs {
                    if let Reply::Ipset { attrs: a, .. } = r {
                        let mut h = SetHeader::default();
                        let _ = decode_list(&a, &mut h, &mut |_| {});
                    }
                }
            }
        }
        // A member with an out-of-range CIDR is rejected, not trusted.
        let bad = Elem {
            ip: v4("10.0.0.1"),
            cidr: Some(99),
            ip2: None,
            cidr2: None,
        };
        let msg = list_message(1, false, &[(bad, None)]);
        let Reply::Ipset { attrs: a, .. } = &decode_datagram(&msg).unwrap()[0] else {
            panic!()
        };
        let mut h = SetHeader::default();
        let mut n = 0;
        assert_eq!(decode_list(a, &mut h, &mut |_| n += 1).unwrap(), 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn decode_type_and_protocol() {
        let mut w = AttrWriter::new();
        w.u8(IPSET_ATTR_PROTOCOL, 7)
            .strz(IPSET_ATTR_TYPENAME, "hash:ip")
            .u8(IPSET_ATTR_FAMILY, 2)
            .u8(IPSET_ATTR_REVISION, 5)
            .u8(IPSET_ATTR_REVISION_MIN, 0);
        assert_eq!(decode_type(&w.finish()).unwrap(), (5, 0));
        let mut w = AttrWriter::new();
        w.u8(IPSET_ATTR_PROTOCOL, 7).u8(IPSET_ATTR_PROTOCOL_MIN, 6);
        assert_eq!(decode_protocol(&w.finish()).unwrap(), (7, Some(6)));
    }
}
