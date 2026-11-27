//! The transports to one DNS server, shared by upstreams (edge.md §6) and the `dns` lookup
//! module's servers (providers.md §5, through [`super::super::lookups`]'s server client): UDP
//! (retried over TCP when the answer has TC set), TCP, DoT and DoH. Each takes a query with the
//! caller's ID and returns the raw answer with that ID, unchecked: the caller checks it with
//! picket-wire's upstream-answer code.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

use picket_api::edge_config::UpstreamProtocol;

use super::doh::DohTransport;
use super::stream::{StreamTransport, TlsTarget};

/// Largest answer read (the DNS maximum).
pub const MAX_ANSWER: usize = picket_wire::MAX_MESSAGE;
/// Most UDP queries in flight to one server.
pub const MAX_UDP_INFLIGHT: usize = 512;
/// The UDP receive buffer. Every query the edge sends advertises a UDP size of
/// [`picket_wire::EDGE_UDP_PAYLOAD`] (1232); a datagram that fills this buffer broke that limit and
/// may have been cut, so it is retried over TCP like a TC answer.
pub const UDP_RECV: usize = 4096;

/// Why a server gave no answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    #[error("timed out")]
    Timeout,
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("answer over the size limit")]
    TooLarge,
    /// An answer with our ID but another question (edge.md §6: matched on ID plus question).
    #[error("answer for another question")]
    Mismatch,
}

/// The length of the question section of a query this crate (or a lookup module) wrote: an
/// uncompressed name plus QTYPE and QCLASS. 0 when it can't be read.
pub fn question_len(msg: &[u8]) -> usize {
    let mut at = 12usize;
    loop {
        let Some(&l) = msg.get(at) else { return 0 };
        if l == 0 {
            at += 1;
            break;
        }
        if l & 0xC0 != 0 {
            return 0;
        }
        at += 1 + usize::from(l);
    }
    if at + 4 > msg.len() { 0 } else { at + 4 - 12 }
}

/// True when the answer's question section equals `question` (ASCII case-insensitively).
pub fn question_matches(answer: &[u8], question: &[u8]) -> bool {
    if question.is_empty() {
        return true;
    }
    match answer.get(12..12 + question.len()) {
        Some(q) => q.eq_ignore_ascii_case(question),
        None => false,
    }
}

/// A UDP server; TC answers are retried over TCP to the same address. Each query uses a new
/// socket on a random port (RFC 5452 §9.2: source port randomisation against off-path spoofing):
/// a socket is never reused across queries.
pub struct UdpTransport {
    addr: SocketAddr,
    tcp: StreamTransport,
    sem: Semaphore,
}

impl UdpTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            tcp: StreamTransport::new(addr, None),
            sem: Semaphore::new(MAX_UDP_INFLIGHT),
        }
    }

    /// Sends `msg`; returns the raw answer and whether it came over the TCP retry (where TC
    /// fails the upstream, owner decision S6).
    pub async fn query(&self, msg: &[u8], timeout: Duration) -> Result<(Vec<u8>, bool), TxError> {
        if msg.len() < 12 {
            return Err(TxError::Transport("query size".into()));
        }
        let deadline = Instant::now() + timeout;
        let _p = tokio::time::timeout_at(deadline.into(), self.sem.acquire())
            .await
            .map_err(|_| TxError::Timeout)?
            .map_err(|_| TxError::Transport("closed".into()))?;
        let local: SocketAddr = match self.addr.ip() {
            IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let sock = UdpSocket::bind(local)
            .await
            .map_err(|e| TxError::Connect(crate::diag::cap(e)))?;
        sock.connect(self.addr)
            .await
            .map_err(|e| TxError::Connect(crate::diag::cap(e)))?;
        let id: u16 = rand::random();
        let mut q = msg.to_vec();
        q[..2].copy_from_slice(&id.to_be_bytes());
        let qlen = question_len(&q);
        sock.send(&q)
            .await
            .map_err(|e| TxError::Connect(crate::diag::cap(e)))?;
        let mut buf = vec![0u8; UDP_RECV];
        loop {
            let n = match tokio::time::timeout_at(deadline.into(), sock.recv(&mut buf)).await {
                Err(_) => return Err(TxError::Timeout),
                Ok(Err(e)) => return Err(TxError::Transport(crate::diag::cap(e))),
                Ok(Ok(n)) => n,
            };
            let a = &buf[..n];
            // A datagram with another ID or question isn't the answer (a late or spoofed one).
            if n < 12 || a[..2] != id.to_be_bytes() || !question_matches(a, &q[12..12 + qlen]) {
                continue;
            }
            if picket_wire::answer::is_truncated_response(a, id) || n >= UDP_RECV {
                // RFC 7766 §5: retry over TCP.
                let left = deadline.saturating_duration_since(Instant::now());
                return self.tcp.query(msg, left, None).await.map(|a| (a, true));
            }
            let mut out = a.to_vec();
            out[..2].copy_from_slice(&msg[..2]);
            return Ok((out, false));
        }
    }
}

/// One server, by IP plus TLS name, over its protocol.
pub enum Transport {
    Udp(UdpTransport),
    Tcp(StreamTransport),
    Dot(StreamTransport),
    Doh(DohTransport),
}

/// Where a server is and how to reach it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub protocol: UpstreamProtocol,
    pub ip: IpAddr,
    pub port: u16,
    pub tls_host: Option<String>,
    pub trust_store: Option<String>,
    pub path: Option<String>,
}

impl Transport {
    /// Builds the transport for `ep` (no connection is made yet).
    pub fn new(ep: &Endpoint) -> Result<Arc<Transport>> {
        let addr = SocketAddr::new(ep.ip.to_canonical(), ep.port);
        Ok(Arc::new(match ep.protocol {
            UpstreamProtocol::Udp => Transport::Udp(UdpTransport::new(addr)),
            UpstreamProtocol::Tcp => Transport::Tcp(StreamTransport::new(addr, None)),
            UpstreamProtocol::Dot => {
                let config = super::tls::client_config(ep.trust_store.as_deref(), &[], true)?;
                let name = super::tls::server_name(ep.tls_host.as_deref(), ep.ip)?;
                Transport::Dot(StreamTransport::new(addr, Some(TlsTarget { config, name })))
            }
            UpstreamProtocol::Doh => Transport::Doh(DohTransport::new(
                addr,
                ep.tls_host.as_deref(),
                ep.path.as_deref().unwrap_or("/dns-query"),
                ep.trust_store.as_deref(),
            )?),
        }))
    }

    /// True for DoT and DoH: queries are padded (edge.md §6).
    pub fn encrypted(&self) -> bool {
        matches!(self, Transport::Dot(_) | Transport::Doh(_))
    }

    /// Sends `msg` and returns the raw answer with `msg`'s ID. `p99` feeds the DoT idle-suspect
    /// check.
    pub async fn query(
        &self,
        msg: &[u8],
        timeout: Duration,
        p99: Option<Duration>,
    ) -> Result<Vec<u8>, TxError> {
        self.query_leg(msg, timeout, p99).await.map(|(a, _)| a)
    }

    /// [`Self::query`], also saying whether the answer came over a stream (TCP, DoT, DoH, or a
    /// UDP query's TCP retry): there an answer with TC set fails the upstream (owner decision
    /// S6, edge.md §6).
    pub async fn query_leg(
        &self,
        msg: &[u8],
        timeout: Duration,
        p99: Option<Duration>,
    ) -> Result<(Vec<u8>, bool), TxError> {
        match self {
            Transport::Udp(t) => t.query(msg, timeout).await,
            Transport::Tcp(t) | Transport::Dot(t) => t.query(msg, timeout, p99).await.map(|a| (a, true)),
            Transport::Doh(t) => t.query(msg, timeout).await.map(|a| (a, true)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_bounds() {
        let q = picket_wire::QName::from_text("example.com").unwrap();
        let mut buf = [0u8; 512];
        let n = picket_wire::upstream::write_query(
            &mut buf,
            q.as_name(),
            1,
            1,
            &picket_wire::upstream::QueryParams {
                id: 1,
                cd: false,
                do_bit: false,
                pad: true,
            },
        )
        .unwrap();
        let msg = &buf[..n];
        assert_eq!(question_len(msg), q.wire().len() + 4);
        let mut upper = msg.to_vec();
        upper[13] = b'E';
        assert!(question_matches(&upper, &msg[12..12 + question_len(msg)]));
        assert!(!question_matches(&msg[..20], &msg[12..12 + question_len(msg)]));
        assert_eq!(question_len(&[0u8; 12]), 0);
        assert_eq!(
            question_len(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1]),
            0
        );
    }
}
