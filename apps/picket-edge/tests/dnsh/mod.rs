//! The DNS test harness: fake upstream servers (UDP, TCP, DoT, DoH) that answer with crafted
//! messages, query clients for every listener kind, raw message builders and readers, in-memory
//! bundles, and an edge started against the mock core with a config.

#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{CertificateParams, KeyPair};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use picket_api::time::Timestamp;
use picket_bundle::matcher::Bundle;
use picket_edge::edge::{ActiveState, Edge};
use picket_rules::matcher::BundleAction;

pub const T: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------------------------
// Raw messages

pub fn wire(name: &str) -> Vec<u8> {
    let mut out = vec![];
    for l in name.trim_end_matches('.').split('.') {
        if l.is_empty() {
            continue;
        }
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    out
}

/// A query a client sends.
#[derive(Clone, Debug)]
pub struct Q {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub rd: bool,
    pub cd: bool,
    /// `Some(do)`: with an OPT.
    pub opt: Option<bool>,
    pub udp_size: u16,
    /// Extra EDNS options (code, data), e.g. a Client Subnet.
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Q {
    pub fn new(name: &str, qtype: u16) -> Self {
        Self {
            id: rand::random(),
            name: name.into(),
            qtype,
            qclass: 1,
            rd: true,
            cd: false,
            opt: Some(false),
            udp_size: 1232,
            options: vec![],
        }
    }
    pub fn dnssec(mut self) -> Self {
        self.opt = Some(true);
        self
    }
    pub fn no_opt(mut self) -> Self {
        self.opt = None;
        self
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&self.id.to_be_bytes());
        b.push(u8::from(self.rd));
        b.push(if self.cd { 0x10 } else { 0 });
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&u16::from(self.opt.is_some()).to_be_bytes());
        b.extend_from_slice(&wire(&self.name));
        b.extend_from_slice(&self.qtype.to_be_bytes());
        b.extend_from_slice(&self.qclass.to_be_bytes());
        if let Some(d) = self.opt {
            b.push(0);
            b.extend_from_slice(&41u16.to_be_bytes());
            b.extend_from_slice(&self.udp_size.to_be_bytes());
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&(if d { 0x8000u16 } else { 0 }).to_be_bytes());
            let mut opts = vec![];
            for (c, data) in &self.options {
                opts.extend_from_slice(&c.to_be_bytes());
                opts.extend_from_slice(&(data.len() as u16).to_be_bytes());
                opts.extend_from_slice(data);
            }
            b.extend_from_slice(&(opts.len() as u16).to_be_bytes());
            b.extend_from_slice(&opts);
        }
        b
    }
}

/// A resource record for a crafted answer (names written uncompressed).
#[derive(Clone, Debug)]
pub struct Rr {
    pub owner: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

pub fn a(owner: &str, ip: &str, ttl: u32) -> Rr {
    let ip: Ipv4Addr = ip.parse().unwrap();
    Rr {
        owner: owner.into(),
        rtype: 1,
        ttl,
        rdata: ip.octets().to_vec(),
    }
}

pub fn aaaa(owner: &str, ip: &str, ttl: u32) -> Rr {
    let ip: std::net::Ipv6Addr = ip.parse().unwrap();
    Rr {
        owner: owner.into(),
        rtype: 28,
        ttl,
        rdata: ip.octets().to_vec(),
    }
}

pub fn cname(owner: &str, target: &str, ttl: u32) -> Rr {
    Rr {
        owner: owner.into(),
        rtype: 5,
        ttl,
        rdata: wire(target),
    }
}

pub fn soa(owner: &str, ttl: u32, minimum: u32) -> Rr {
    let mut d = wire("ns.example");
    d.extend(wire("hostmaster.example"));
    for v in [1u32, 7200, 900, 1209600, minimum] {
        d.extend_from_slice(&v.to_be_bytes());
    }
    Rr {
        owner: owner.into(),
        rtype: 6,
        ttl,
        rdata: d,
    }
}

/// An RRSIG over `covered` (signature bytes are filler: the edge never validates).
pub fn rrsig(owner: &str, covered: u16, ttl: u32) -> Rr {
    let mut d = vec![];
    d.extend_from_slice(&covered.to_be_bytes());
    d.push(13); // ECDSAP256SHA256
    d.push(owner.trim_end_matches('.').split('.').count() as u8);
    d.extend_from_slice(&ttl.to_be_bytes());
    d.extend_from_slice(&2_000_000_000u32.to_be_bytes());
    d.extend_from_slice(&1_600_000_000u32.to_be_bytes());
    d.extend_from_slice(&12345u16.to_be_bytes());
    d.extend(wire("example.com"));
    d.extend_from_slice(&[7u8; 64]);
    Rr {
        owner: owner.into(),
        rtype: 46,
        ttl,
        rdata: d,
    }
}

/// HTTPS (type 65) with `ipv4hint`s.
pub fn https(owner: &str, priority: u16, target: &str, v4hints: &[&str], ttl: u32) -> Rr {
    let mut d = priority.to_be_bytes().to_vec();
    d.extend(wire(target));
    if !v4hints.is_empty() {
        d.extend_from_slice(&4u16.to_be_bytes());
        d.extend_from_slice(&((v4hints.len() * 4) as u16).to_be_bytes());
        for h in v4hints {
            d.extend_from_slice(&h.parse::<Ipv4Addr>().unwrap().octets());
        }
    }
    Rr {
        owner: owner.into(),
        rtype: 65,
        ttl,
        rdata: d,
    }
}

/// A crafted upstream answer.
#[derive(Clone, Debug, Default)]
pub struct Ans {
    pub rcode: u8,
    pub tc: bool,
    pub answers: Vec<Rr>,
    pub authority: Vec<Rr>,
    /// With an OPT carrying these EDE options (code, text).
    pub ede: Vec<(u16, String)>,
    /// Mirror the query's OPT (DO) when it had one.
    pub opt: bool,
}

impl Ans {
    pub fn records(answers: Vec<Rr>) -> Self {
        Self {
            answers,
            opt: true,
            ..Default::default()
        }
    }
    pub fn nxdomain(zone: &str) -> Self {
        Self {
            rcode: 3,
            authority: vec![soa(zone, 300, 60)],
            opt: true,
            ..Default::default()
        }
    }
}

fn put_rr(b: &mut Vec<u8>, r: &Rr) {
    b.extend(wire(&r.owner));
    b.extend_from_slice(&r.rtype.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&r.ttl.to_be_bytes());
    b.extend_from_slice(&(r.rdata.len() as u16).to_be_bytes());
    b.extend_from_slice(&r.rdata);
}

/// The question section of a query (bytes 12.. up to QTYPE/QCLASS).
pub fn question(q: &[u8]) -> &[u8] {
    let mut at = 12;
    while q[at] != 0 {
        at += 1 + q[at] as usize;
    }
    &q[12..at + 5]
}

/// Builds the answer to `query` (its ID, question, RD and CD).
pub fn answer(query: &[u8], a: &Ans) -> Vec<u8> {
    let qdo = query_opt(query).map(|o| o.do_bit);
    let mut b = vec![];
    b.extend_from_slice(&query[..2]);
    b.push(0x80 | (query[2] & 0x01) | if a.tc { 0x02 } else { 0 });
    b.push(0x80 | (query[3] & 0x10) | (a.rcode & 0x0F));
    let with_opt = a.opt && qdo.is_some() || !a.ede.is_empty();
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&(a.answers.len() as u16).to_be_bytes());
    b.extend_from_slice(&(a.authority.len() as u16).to_be_bytes());
    b.extend_from_slice(&u16::from(with_opt).to_be_bytes());
    b.extend_from_slice(question(query));
    for r in &a.answers {
        put_rr(&mut b, r);
    }
    for r in &a.authority {
        put_rr(&mut b, r);
    }
    if with_opt {
        b.push(0);
        b.extend_from_slice(&41u16.to_be_bytes());
        b.extend_from_slice(&1232u16.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&(if qdo == Some(true) { 0x8000u16 } else { 0 }).to_be_bytes());
        let mut opts = vec![];
        for (code, text) in &a.ede {
            opts.extend_from_slice(&15u16.to_be_bytes());
            opts.extend_from_slice(&((text.len() + 2) as u16).to_be_bytes());
            opts.extend_from_slice(&code.to_be_bytes());
            opts.extend_from_slice(text.as_bytes());
        }
        b.extend_from_slice(&(opts.len() as u16).to_be_bytes());
        b.extend_from_slice(&opts);
    }
    b
}

/// A decoded message (replies from the edge, queries the upstreams got).
#[derive(Clone, Debug, Default)]
pub struct Msg {
    pub id: u16,
    pub qr: bool,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: u16,
    pub qname: String,
    pub qtype: u16,
    pub answers: Vec<(String, u16, u32, Vec<u8>)>,
    pub authority: Vec<(String, u16, u32, Vec<u8>)>,
    pub opt: Option<Opt>,
    pub len: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Opt {
    pub udp: u16,
    pub do_bit: bool,
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Msg {
    /// EDE options: (code, EXTRA-TEXT).
    pub fn ede(&self) -> Vec<(u16, String)> {
        self.opt
            .as_ref()
            .map(|o| {
                o.options
                    .iter()
                    .filter(|(c, _)| *c == 15)
                    .map(|(_, d)| {
                        (
                            u16::from_be_bytes([d[0], d[1]]),
                            String::from_utf8_lossy(&d[2..]).into_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn ede_codes(&self) -> Vec<u16> {
        self.ede().into_iter().map(|e| e.0).collect()
    }
    pub fn ips(&self) -> Vec<IpAddr> {
        self.answers
            .iter()
            .filter_map(|(_, t, _, d)| match (*t, d.len()) {
                (1, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(&d[..]).unwrap())),
                (28, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(&d[..]).unwrap())),
                _ => None,
            })
            .collect()
    }
    pub fn types(&self) -> Vec<u16> {
        self.answers.iter().map(|r| r.1).collect()
    }
    pub fn ttls(&self) -> Vec<u32> {
        self.answers.iter().map(|r| r.2).collect()
    }
}

fn read_name(m: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels = vec![];
    let mut end = None;
    let mut hops = 0;
    loop {
        let l = *m.get(at)?;
        if l == 0 {
            at += 1;
            break;
        }
        if l & 0xC0 == 0xC0 {
            let p = (usize::from(l & 0x3F) << 8) | usize::from(*m.get(at + 1)?);
            if end.is_none() {
                end = Some(at + 2);
            }
            at = p;
            hops += 1;
            if hops > 64 {
                return None;
            }
            continue;
        }
        let s = m.get(at + 1..at + 1 + l as usize)?;
        labels.push(String::from_utf8_lossy(s).to_ascii_lowercase());
        at += 1 + l as usize;
    }
    Some((labels.join("."), end.unwrap_or(at)))
}

/// Parses a message (names may be compressed).
pub fn parse(m: &[u8]) -> Msg {
    let u16at = |i: usize| u16::from_be_bytes([m[i], m[i + 1]]);
    let mut msg = Msg {
        id: u16at(0),
        qr: m[2] & 0x80 != 0,
        aa: m[2] & 0x04 != 0,
        tc: m[2] & 0x02 != 0,
        rd: m[2] & 0x01 != 0,
        ad: m[3] & 0x20 != 0,
        cd: m[3] & 0x10 != 0,
        rcode: u16::from(m[3] & 0x0F),
        len: m.len(),
        ..Default::default()
    };
    let (qd, an, ns, ar) = (u16at(4), u16at(6), u16at(8), u16at(10));
    let mut at = 12;
    for _ in 0..qd {
        let (n, e) = read_name(m, at).unwrap();
        msg.qname = n;
        msg.qtype = u16at(e);
        at = e + 4;
    }
    for i in 0..(an + ns + ar) {
        let (n, e) = read_name(m, at).unwrap();
        let t = u16at(e);
        let class = u16at(e + 2);
        let ttl = u32::from_be_bytes([m[e + 4], m[e + 5], m[e + 6], m[e + 7]]);
        let len = usize::from(u16at(e + 8));
        let d = m[e + 10..e + 10 + len].to_vec();
        at = e + 10 + len;
        if t == 41 {
            let mut opts = vec![];
            let mut j = 0;
            while j + 4 <= d.len() {
                let c = u16::from_be_bytes([d[j], d[j + 1]]);
                let l = usize::from(u16::from_be_bytes([d[j + 2], d[j + 3]]));
                opts.push((c, d[j + 4..j + 4 + l].to_vec()));
                j += 4 + l;
            }
            msg.rcode |= u16::from(ttl.to_be_bytes()[0]) << 4;
            msg.opt = Some(Opt {
                udp: class,
                do_bit: ttl & 0x8000 != 0,
                options: opts,
            });
            continue;
        }
        let rec = (n, t, ttl, d);
        if i < an {
            msg.answers.push(rec);
        } else if i < an + ns {
            msg.authority.push(rec);
        }
    }
    msg
}

#[derive(Clone, Copy, Debug)]
pub struct QueryOpt {
    pub do_bit: bool,
}

fn query_opt(q: &[u8]) -> Option<QueryOpt> {
    let m = parse(q);
    m.opt.map(|o| QueryOpt { do_bit: o.do_bit })
}

// ---------------------------------------------------------------------------------------------
// Fake upstreams

/// What a fake upstream does with one query.
#[derive(Clone, Debug)]
pub enum Act {
    Answer(Ans),
    Raw(Vec<u8>),
    Drop,
    Delay(Duration, Box<Act>),
}

pub type Handler = Arc<dyn Fn(&Msg, &[u8]) -> Act + Send + Sync>;

/// One query an upstream received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub transport: &'static str,
    pub msg: Msg,
    pub raw: Vec<u8>,
}

pub struct FakeUpstream {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub handler: Arc<Mutex<Handler>>,
    /// For DoT/DoH: the server certificate (trust store PEM) and TLS name.
    pub cert_pem: Option<String>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub const UPSTREAM_TLS_NAME: &str = "upstream.test";

async fn act(
    h: &Arc<Mutex<Handler>>,
    seen: &Arc<Mutex<Vec<Seen>>>,
    transport: &'static str,
    q: &[u8],
) -> Option<Vec<u8>> {
    let msg = parse(q);
    seen.lock().unwrap().push(Seen {
        transport,
        msg: msg.clone(),
        raw: q.to_vec(),
    });
    let handler = h.lock().unwrap().clone();
    let mut a = handler(&msg, q);
    loop {
        match a {
            Act::Answer(ans) => return Some(answer(q, &ans)),
            Act::Raw(r) => return Some(r),
            Act::Drop => return None,
            Act::Delay(d, next) => {
                tokio::time::sleep(d).await;
                a = *next;
            }
        }
    }
}

fn tls_server(alpn: &[&[u8]]) -> (tokio_rustls::TlsAcceptor, String) {
    let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let p = CertificateParams::new(vec![UPSTREAM_TLS_NAME.to_owned()]).unwrap();
    let cert = p.self_signed(&kp).unwrap();
    let key = PrivateKeyDer::from_pem_slice(kp.serialize_pem().as_bytes()).unwrap();
    let mut cfg =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    (tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), cert.pem())
}

impl FakeUpstream {
    pub fn set(&self, h: impl Fn(&Msg, &[u8]) -> Act + Send + Sync + 'static) {
        *self.handler.lock().unwrap() = Arc::new(h);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// UDP and TCP on one port (a port free for UDP may be taken for TCP: another is tried).
    pub async fn plain(h: impl Fn(&Msg, &[u8]) -> Act + Send + Sync + 'static) -> Self {
        let mut tries = 0;
        let (udp, addr, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = udp.local_addr().unwrap();
            match TcpListener::bind(addr).await {
                Ok(tcp) => break (udp, addr, tcp),
                Err(_) if tries < 100 => tries += 1,
                Err(e) => panic!("no port free for both UDP and TCP: {e}"),
            }
        };
        let seen = Arc::new(Mutex::new(vec![]));
        let handler: Arc<Mutex<Handler>> = Arc::new(Mutex::new(Arc::new(h)));
        let udp = Arc::new(udp);
        let (s1, h1, u1) = (Arc::clone(&seen), Arc::clone(&handler), Arc::clone(&udp));
        let t1 = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, peer)) = u1.recv_from(&mut buf).await else {
                    return;
                };
                let q = buf[..n].to_vec();
                let (s, h, u) = (Arc::clone(&s1), Arc::clone(&h1), Arc::clone(&u1));
                tokio::spawn(async move {
                    if let Some(r) = act(&h, &s, "udp", &q).await {
                        let _ = u.send_to(&r, peer).await;
                    }
                });
            }
        });
        let (s2, h2) = (Arc::clone(&seen), Arc::clone(&handler));
        let t2 = tokio::spawn(async move {
            loop {
                let Ok((c, _)) = tcp.accept().await else { return };
                let (s, h) = (Arc::clone(&s2), Arc::clone(&h2));
                tokio::spawn(serve_stream(c, s, h, "tcp"));
            }
        });
        Self {
            addr,
            seen,
            handler,
            cert_pem: None,
            tasks: vec![t1, t2],
        }
    }

    pub async fn dot(h: impl Fn(&Msg, &[u8]) -> Act + Send + Sync + 'static) -> Self {
        let (acceptor, pem) = tls_server(&[]);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(vec![]));
        let handler: Arc<Mutex<Handler>> = Arc::new(Mutex::new(Arc::new(h)));
        let (s2, h2) = (Arc::clone(&seen), Arc::clone(&handler));
        let t = tokio::spawn(async move {
            loop {
                let Ok((c, _)) = tcp.accept().await else { return };
                let (s, h, acc) = (Arc::clone(&s2), Arc::clone(&h2), acceptor.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acc.accept(c).await {
                        serve_stream(tls, s, h, "dot").await;
                    }
                });
            }
        });
        Self {
            addr,
            seen,
            handler,
            cert_pem: Some(pem),
            tasks: vec![t],
        }
    }

    pub async fn doh(h: impl Fn(&Msg, &[u8]) -> Act + Send + Sync + 'static) -> Self {
        let (acceptor, pem) = tls_server(&[b"h2"]);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(vec![]));
        let handler: Arc<Mutex<Handler>> = Arc::new(Mutex::new(Arc::new(h)));
        let (s2, h2) = (Arc::clone(&seen), Arc::clone(&handler));
        let t = tokio::spawn(async move {
            loop {
                let Ok((c, _)) = tcp.accept().await else { return };
                let (s, h, acc) = (Arc::clone(&s2), Arc::clone(&h2), acceptor.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acc.accept(c).await else { return };
                    let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                        let (s, h) = (Arc::clone(&s), Arc::clone(&h));
                        async move {
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map(|b| b.to_bytes())
                                .unwrap_or_default();
                            let r = act(&h, &s, "doh", &body).await;
                            let resp = match r {
                                Some(r) => hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/dns-message")
                                    .body(Full::new(Bytes::from(r)))
                                    .unwrap(),
                                None => hyper::Response::builder()
                                    .status(502)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        Self {
            addr,
            seen,
            handler,
            cert_pem: Some(pem),
            tasks: vec![t],
        }
    }
}

async fn serve_stream<S>(c: S, seen: Arc<Mutex<Vec<Seen>>>, h: Arc<Mutex<Handler>>, transport: &'static str)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    let (mut rd, wr) = tokio::io::split(c);
    let wr = Arc::new(tokio::sync::Mutex::new(wr));
    loop {
        let mut len = [0u8; 2];
        if rd.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if rd.read_exact(&mut q).await.is_err() {
            return;
        }
        let (s, h, w) = (Arc::clone(&seen), Arc::clone(&h), Arc::clone(&wr));
        tokio::spawn(async move {
            if let Some(r) = act(&h, &s, transport, &q).await {
                let mut frame = (r.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&r);
                let _ = w.lock().await.write_all(&frame).await;
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Clients

pub async fn udp(addr: SocketAddr, q: &[u8]) -> Option<Vec<u8>> {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(q, addr).await.unwrap();
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

pub async fn udp_q(addr: SocketAddr, q: &Q) -> Msg {
    let r = udp(addr, &q.bytes()).await.expect("UDP answer");
    let m = parse(&r);
    assert_eq!(m.id, q.id);
    m
}

async fn stream_queries<S>(mut s: S, qs: &[Vec<u8>]) -> Vec<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    for q in qs {
        let mut f = (q.len() as u16).to_be_bytes().to_vec();
        f.extend_from_slice(q);
        s.write_all(&f).await.unwrap();
    }
    let mut out = vec![];
    for _ in qs {
        let mut len = [0u8; 2];
        if tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut len))
            .await
            .is_err()
        {
            break;
        }
        let mut r = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut r).await.unwrap();
        out.push(r);
    }
    out
}

pub async fn tcp(addr: SocketAddr, qs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let s = TcpStream::connect(addr).await.unwrap();
    stream_queries(s, qs).await
}

pub fn client_tls(ca_pem: &str, alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    client_tls_versions(ca_pem, alpn, rustls::DEFAULT_VERSIONS)
}

/// [`client_tls`] offering only `versions` (a TLS 1.2-only client: `&[&rustls::version::TLS12]`).
pub fn client_tls_versions(
    ca_pem: &str,
    alpn: &[&[u8]],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

/// A TLS handshake to `addr` from a client offering only `versions`; the error is the client's
/// (a refused version: rustls's `AlertReceived(ProtocolVersion)`).
pub async fn tls_handshake(
    addr: SocketAddr,
    sni: &str,
    ca_pem: &str,
    alpn: &[&[u8]],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    tokio_rustls::TlsConnector::from(client_tls_versions(ca_pem, alpn, versions))
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), tcp)
        .await
}

pub async fn dot(addr: SocketAddr, sni: &str, ca_pem: &str, qs: &[Vec<u8>]) -> std::io::Result<Vec<Vec<u8>>> {
    let tcp = TcpStream::connect(addr).await?;
    let tls = tokio_rustls::TlsConnector::from(client_tls(ca_pem, &[]))
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), tcp)
        .await?;
    Ok(stream_queries(tls, qs).await)
}

/// A DoH exchange: (status, headers, body).
pub async fn doh(
    addr: SocketAddr,
    sni: &str,
    ca_pem: &str,
    path: &str,
    q: &[u8],
    get: bool,
    headers: &[(&str, &str)],
) -> (u16, http::HeaderMap, Vec<u8>) {
    use base64::Engine as _;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(client_tls(ca_pem, &[b"h2"]))
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    let (mut s, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let uri = if get {
        format!(
            "https://{sni}{path}?dns={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(q)
        )
    } else {
        format!("https://{sni}{path}")
    };
    let mut b = http::Request::builder()
        .method(if get { "GET" } else { "POST" })
        .uri(uri);
    if !get {
        b = b.header("content-type", "application/dns-message");
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let req = b
        .body(Full::new(Bytes::from(if get { vec![] } else { q.to_vec() })))
        .unwrap();
    let resp = s.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let h = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, h, body)
}

// ---------------------------------------------------------------------------------------------
// Bundles

pub fn bundle(name: &str, action: BundleAction, rules: &[&str]) -> Arc<Bundle> {
    bundle_fmt(name, action, rules, picket_rules::formats::Format::Adblock)
}

pub fn bundle_fmt(
    name: &str,
    action: BundleAction,
    rules: &[&str],
    fmt: picket_rules::formats::Format,
) -> Arc<Bundle> {
    use picket_bundle::compile::{BuildOptions, CompileOptions, build, compile_rules, load_bundle};
    use picket_rules::formats::{DomainsAs, ParseConfig, parse_lines};
    let text = rules.join("\n");
    let cfg = ParseConfig::new(fmt, DomainsAs::Exact, Timestamp::now());
    let mut rs = vec![];
    parse_lines(text.as_bytes(), &cfg, |e| rs.push(e.rule)).unwrap();
    let compiled = compile_rules(&rs, &CompileOptions::new(action, None));
    let built = build(&compiled, &BuildOptions::new(name, action)).unwrap();
    Arc::new(
        load_bundle(
            &built.head_blob.bytes,
            &built.blobs,
            None,
            picket_bundle::patterns::DEFAULT_BUDGET,
        )
        .unwrap(),
    )
}

/// Installs bundles into the active state, as wave 4's activator will.
pub fn set_bundles(edge: &Edge, list: Vec<(&str, Arc<Bundle>)>) {
    let prev = edge.active();
    let ab = picket_edge::dns::filter::ActiveBundles {
        bundles: list
            .into_iter()
            .map(|(k, b)| (std::sync::Arc::<str>::from(k), b))
            .collect(),
        pages: None,
    };
    let v = picket_edge::dns::activation::versions(prev.config_version.as_deref().unwrap_or(""), &ab);
    let mut next = ActiveState::clone(&prev);
    next.bundles = Arc::new(ab);
    next.versions = Some(Arc::new(v));
    edge.active.store(Arc::new(next));
}

// ---------------------------------------------------------------------------------------------
// Config snippets

pub fn plain_upstream(u: &FakeUpstream, proto: &str) -> serde_json::Value {
    serde_json::json!({"protocol": proto, "ip": "127.0.0.1", "port": u.addr.port()})
}

pub fn tls_upstream(u: &FakeUpstream, proto: &str) -> serde_json::Value {
    let mut v = serde_json::json!({
        "protocol": proto, "ip": "127.0.0.1", "port": u.addr.port(),
        "tls_host": UPSTREAM_TLS_NAME, "trust_store": u.cert_pem,
    });
    if proto == "doh" {
        v["path"] = "/dns-query".into();
    }
    v
}

/// Merges `extra` into `base` (top-level keys; objects merge one level deep).
pub fn merge(base: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            match (b.get_mut(k), v) {
                (Some(serde_json::Value::Object(bo)), serde_json::Value::Object(eo)) => {
                    for (k2, v2) in eo {
                        bo.insert(k2.clone(), v2.clone());
                    }
                }
                _ => {
                    b.insert(k.clone(), v.clone());
                }
            }
        }
    }
}

pub fn sorted<K: Ord + Clone, V: Clone>(m: &BTreeMap<K, V>) -> Vec<(K, V)> {
    m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}
