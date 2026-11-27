//! DoH to one server (edge.md §6: "DoH upstreams use one hyper h2 connection each"; RFC 8484):
//! POST `application/dns-message` to the server's path over one HTTP/2 connection, TLS 1.3 to
//! its IP with its TLS name. The query goes out with ID 0 (RFC 8484 §4.1) and the answer comes
//! back with the caller's ID. Bodies are bounded by the DNS maximum.
//!
//! A connection that stops answering (a WAN address change or PPPoE reconnect leaves it open on
//! our side) is replaced, never reused until TCP gives up (edge.md §6 connection model; README §2
//! Health):
//! - a query that times out on a connection drops it: the next query opens a fresh one;
//! - HTTP/2 PINGs carry DoT's idle-suspect rule: while a query is open on a connection that has
//!   read nothing for [`SUSPECT_IDLE`], it is pinged, and closed unless the ping is acknowledged
//!   within [`SUSPECT_MAX`]; the query then retries once on a fresh connection.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;

use super::stream::{CONNECT_TIMEOUT, SUSPECT_IDLE, SUSPECT_MAX};
use super::transport::{MAX_ANSWER, TxError};

const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(10);

pub const DNS_MESSAGE: &str = "application/dns-message";

struct Backoff {
    next_allowed: Option<Instant>,
    delay: Duration,
}

/// The HTTP/2 keep-alive: a PING after this long without reading anything, while a query is
/// open, and how long its acknowledgement may take.
#[derive(Clone, Copy, Debug)]
pub struct KeepAlive {
    pub interval: Duration,
    pub timeout: Duration,
}

/// Edge.md §6's idle-suspect rule, as HTTP/2 PINGs (whose acknowledgements don't wait for DNS).
pub const KEEP_ALIVE: KeepAlive = KeepAlive {
    interval: SUSPECT_IDLE,
    timeout: SUSPECT_MAX,
};

/// The open connection and its generation (each connect makes a new one), so a query drops or
/// replaces only the connection it used.
struct Cached {
    generation: u64,
    sender: SendRequest<Full<Bytes>>,
}

pub struct DohTransport {
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    uri: http::Uri,
    keep_alive: KeepAlive,
    /// The last generation made, and the open connection.
    conn: Mutex<(u64, Option<Cached>)>,
    /// One connect at a time.
    connect_lock: tokio::sync::Mutex<()>,
    backoff: Mutex<Backoff>,
}

impl DohTransport {
    pub fn new(
        addr: SocketAddr,
        tls_host: Option<&str>,
        path: &str,
        trust_store: Option<&str>,
    ) -> Result<Self> {
        Self::with_keep_alive(addr, tls_host, path, trust_store, KEEP_ALIVE)
    }

    fn with_keep_alive(
        addr: SocketAddr,
        tls_host: Option<&str>,
        path: &str,
        trust_store: Option<&str>,
        keep_alive: KeepAlive,
    ) -> Result<Self> {
        let config = super::tls::client_config(trust_store, &[b"h2"], true)?;
        let name = super::tls::server_name(tls_host, addr.ip())?;
        // core's client sends the same path (picket_api::edge_config::is_doh_path).
        if !picket_api::edge_config::is_doh_path(path) {
            bail!(
                "DoH path {path:?}: it must be {}",
                picket_api::edge_config::DOH_PATH_RULE
            );
        }
        let authority = authority(tls_host, addr);
        let uri: http::Uri = format!("https://{authority}{path}")
            .parse()
            .map_err(|e| anyhow!("DoH URI: {e}"))?;
        Ok(Self {
            addr,
            config,
            name,
            uri,
            keep_alive,
            conn: Mutex::new((0, None)),
            connect_lock: tokio::sync::Mutex::new(()),
            backoff: Mutex::new(Backoff {
                next_allowed: None,
                delay: BACKOFF_MIN,
            }),
        })
    }

    async fn connect(&self) -> Result<SendRequest<Full<Bytes>>, TxError> {
        {
            let b = self.backoff.lock().unwrap_or_else(|p| p.into_inner());
            if b.next_allowed.is_some_and(|t| Instant::now() < t) {
                return Err(TxError::Connect("reconnect backing off".into()));
            }
        }
        let fut = async {
            let tcp = TcpStream::connect(self.addr)
                .await
                .map_err(|e| TxError::Connect(crate::diag::cap(e)))?;
            let _ = tcp.set_nodelay(true);
            let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.config))
                .connect(self.name.clone(), tcp)
                .await
                .map_err(|e| TxError::Connect(format!("TLS: {}", crate::diag::cap(e))))?;
            let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .keep_alive_interval(self.keep_alive.interval)
                .keep_alive_timeout(self.keep_alive.timeout)
                .keep_alive_while_idle(false)
                .max_concurrent_reset_streams(64)
                .handshake(TokioIo::new(tls))
                .await
                .map_err(|e| TxError::Connect(format!("HTTP/2: {}", crate::diag::cap(e))))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok::<_, TxError>(sender)
        };
        let r = match tokio::time::timeout(CONNECT_TIMEOUT, fut).await {
            Ok(r) => r,
            Err(_) => Err(TxError::Connect("connect timed out".into())),
        };
        let mut b = self.backoff.lock().unwrap_or_else(|p| p.into_inner());
        match &r {
            Ok(_) => {
                b.next_allowed = None;
                b.delay = BACKOFF_MIN;
            }
            Err(_) => {
                let jitter = 0.8 + rand::random::<f64>() * 0.4;
                b.next_allowed = Some(Instant::now() + b.delay.mul_f64(jitter));
                b.delay = (b.delay * 2).min(BACKOFF_MAX);
            }
        }
        r
    }

    /// The open connection, or a fresh one when there is none, it closed, or it is `failed` (the
    /// generation a query found dead; a connection another query already replaced it with is
    /// kept).
    async fn sender(&self, failed: Option<u64>) -> Result<(u64, SendRequest<Full<Bytes>>), TxError> {
        if let Some(c) = self.current(failed) {
            return Ok(c);
        }
        let _one = self.connect_lock.lock().await;
        // Another query may have connected meanwhile.
        if let Some(c) = self.current(failed) {
            return Ok(c);
        }
        let s = self.connect().await?;
        let mut g = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        g.0 += 1;
        let generation = g.0;
        g.1 = Some(Cached {
            generation,
            sender: s.clone(),
        });
        Ok((generation, s))
    }

    fn current(&self, failed: Option<u64>) -> Option<(u64, SendRequest<Full<Bytes>>)> {
        let g = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        g.1.as_ref()
            .filter(|c| !c.sender.is_closed() && failed != Some(c.generation))
            .map(|c| (c.generation, c.sender.clone()))
    }

    /// Drops the connection of `generation` if it is still the open one: a query on it timed out.
    fn drop_conn(&self, generation: u64) {
        let mut g = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if g.1.as_ref().is_some_and(|c| c.generation == generation) {
            g.1 = None;
        }
    }

    pub async fn query(&self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>, TxError> {
        if msg.len() < 12 {
            return Err(TxError::Transport("query size".into()));
        }
        let deadline = Instant::now() + timeout;
        let mut q = msg.to_vec();
        q[..2].copy_from_slice(&[0, 0]);
        let body = Bytes::from(q);
        let mut failed = None;
        loop {
            let (generation, mut s) = tokio::time::timeout_at(deadline.into(), self.sender(failed))
                .await
                .map_err(|_| TxError::Timeout)??;
            let req = Request::builder()
                .method(Method::POST)
                .uri(self.uri.clone())
                .header(header::CONTENT_TYPE, DNS_MESSAGE)
                .header(header::ACCEPT, DNS_MESSAGE)
                .body(Full::new(body.clone()))
                .map_err(|e| TxError::Transport(crate::diag::cap(e)))?;
            let resp = match tokio::time::timeout_at(deadline.into(), s.send_request(req)).await {
                Err(_) => {
                    // No answer in time: the connection may be dead; the next query opens a new one.
                    self.drop_conn(generation);
                    return Err(TxError::Timeout);
                }
                Ok(Err(e)) => {
                    // The request failed on this connection: it died between queries, a
                    // keep-alive PING found it dead (the error may be any HTTP/2 error, before
                    // the connection reads as closed), or the server reset the stream. Once
                    // more on a fresh connection, which replaces this one.
                    if failed.is_none() {
                        failed = Some(generation);
                        continue;
                    }
                    return Err(TxError::Transport(crate::diag::cap(e)));
                }
                Ok(Ok(r)) => r,
            };
            if resp.status() != StatusCode::OK {
                return Err(TxError::Transport(format!("HTTP {}", resp.status().as_u16())));
            }
            let ct_ok = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|t| t.trim().eq_ignore_ascii_case(DNS_MESSAGE))
                });
            if !ct_ok {
                return Err(TxError::Transport("not application/dns-message".into()));
            }
            let collected = tokio::time::timeout_at(
                deadline.into(),
                Limited::new(resp.into_body(), MAX_ANSWER).collect(),
            )
            .await;
            let Ok(collected) = collected else {
                // The answer stalled mid-body: as a query that timed out.
                self.drop_conn(generation);
                return Err(TxError::Timeout);
            };
            let collected = collected.map_err(|e| {
                if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                    TxError::TooLarge
                } else {
                    TxError::Transport(crate::diag::cap(e))
                }
            })?;
            let mut out = collected.to_bytes().to_vec();
            if out.len() < 12 {
                return Err(TxError::Transport("short answer".into()));
            }
            if out[..2] != [0, 0] {
                return Err(TxError::Mismatch);
            }
            out[..2].copy_from_slice(&msg[..2]);
            return Ok(out);
        }
    }
}

/// The request's `:authority`: the TLS name, else the address, with the port when it isn't 443
/// (RFC 9110 §4.2.3: a URI may leave the default port out).
fn authority(tls_host: Option<&str>, addr: SocketAddr) -> String {
    let host = match tls_host {
        Some(h) if !h.is_empty() => match h.parse::<std::net::Ipv6Addr>() {
            Ok(_) => format!("[{h}]"),
            Err(_) => h.to_owned(),
        },
        _ => match addr.ip() {
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            std::net::IpAddr::V4(ip) => ip.to_string(),
        },
    };
    match addr.port() {
        443 => host,
        port => format!("{host}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    /// The authority names the port when it isn't 443 (it used to leave it out), and the path
    /// rule is core's.
    #[test]
    fn authority_and_path() {
        let a = |h: Option<&str>, addr: &str| super::authority(h, addr.parse().unwrap());
        assert_eq!(a(Some("dns.example"), "192.0.2.1:8443"), "dns.example:8443");
        assert_eq!(a(Some("dns.example"), "192.0.2.1:443"), "dns.example");
        assert_eq!(a(None, "192.0.2.1:853"), "192.0.2.1:853");
        assert_eq!(a(None, "[fd00::1]:443"), "[fd00::1]");
        assert_eq!(a(Some("fd00::53"), "[fd00::53]:8443"), "[fd00::53]:8443");
        let t =
            DohTransport::new("192.0.2.1:8443".parse().unwrap(), Some("dns.example"), "/q", None).unwrap();
        assert_eq!(t.uri.to_string(), "https://dns.example:8443/q");
        for bad in ["/a/../q", "/q#x", "/q q", "q"] {
            assert!(
                DohTransport::new("192.0.2.1:443".parse().unwrap(), None, bad, None).is_err(),
                "{bad}"
            );
        }
    }

    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    use hyper::body::Incoming;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const NAME: &str = "upstream.test";

    fn tls_server() -> (tokio_rustls::TlsAcceptor, String) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![NAME.to_owned()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        let key = rustls_pki_types::PrivateKeyDer::try_from(kp.serialize_der()).unwrap();
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        (tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), cert.pem())
    }

    /// A DNS query for `x.example` A with ID 0x1234.
    fn query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x01x\x07example\x00\x00\x01\x00\x01");
        q
    }

    /// A DoH server answering every query (an echo with QR set); connection `n` (from 0) answers
    /// only if `answers(n)`. Returns its address, its certificate and its accept count.
    async fn server(answers: fn(usize) -> bool) -> (SocketAddr, String, Arc<AtomicUsize>) {
        let (acceptor, pem) = tls_server();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let a2 = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok((c, _)) = tcp.accept().await else { return };
                let n = a2.fetch_add(1, SeqCst);
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acc.accept(c).await else { return };
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| async move {
                        let mut body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|b| b.to_bytes().to_vec())
                            .unwrap_or_default();
                        if !answers(n) {
                            // Stops answering, but keeps the connection open (and acks pings).
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                        }
                        if body.len() > 2 {
                            body[2] |= 0x80;
                        }
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-type", DNS_MESSAGE)
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        (addr, pem, accepts)
    }

    /// ER3 (edge.md §6 connection model; README §2 Health): a connection whose server stopped
    /// answering is dropped when a query on it times out, so the next query opens a fresh one
    /// (a WAN address change or PPPoE reconnect leaves such connections behind).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_connection_is_replaced() {
        let (addr, pem, accepts) = server(|n| n > 0).await;
        let t = DohTransport::new(addr, Some(NAME), "/dns-query", Some(&pem)).unwrap();
        let q = query();
        let first = t.query(&q, Duration::from_millis(500)).await;
        assert_eq!(first, Err(TxError::Timeout));
        for i in 0..5 {
            let a = t.query(&q, Duration::from_millis(500)).await;
            assert!(a.is_ok(), "query {i} after the timeout: {a:?}");
            assert_eq!(a.unwrap()[..2], [0x12, 0x34]);
        }
        assert_eq!(
            accepts.load(SeqCst),
            2,
            "one fresh connection replaced the wedged one"
        );
    }

    /// A TCP proxy to `to`. Bumping the returned epoch kills the path of every connection opened
    /// before: bytes are swallowed both ways and nothing is closed (a WAN address change), while
    /// new connections pass.
    async fn proxy(to: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let epoch = Arc::new(AtomicUsize::new(0));
        let e2 = Arc::clone(&epoch);
        tokio::spawn(async move {
            loop {
                let Ok((c, _)) = l.accept().await else { return };
                let Ok(u) = TcpStream::connect(to).await else {
                    return;
                };
                let mine = e2.load(SeqCst);
                let (cr, cw) = c.into_split();
                let (ur, uw) = u.into_split();
                for (mut r, mut w) in [(cr, uw), (ur, cw)].map(|(r, w)| (r, w)) {
                    let e = Arc::clone(&e2);
                    tokio::spawn(async move {
                        let mut b = vec![0u8; 16 << 10];
                        loop {
                            match r.read(&mut b).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) if e.load(SeqCst) == mine => {
                                    if w.write_all(&b[..n]).await.is_err() {
                                        return;
                                    }
                                }
                                Ok(_) => {}
                            }
                        }
                    });
                }
            }
        });
        (addr, epoch)
    }

    /// ER3 (edge.md §6: "a query on a connection idle > 8 s that gets no reply within …" is retried
    /// on a fresh one): a query opened on a connection that has read nothing for the keep-alive
    /// interval pings it; a dead path doesn't acknowledge, the connection is closed, and the query
    /// retries on a fresh one well before its own timeout. (Short intervals here; the real ones are
    /// [`KEEP_ALIVE`].)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_keep_alive_ping_finds_a_dead_connection() {
        let (addr, pem, accepts) = server(|_| true).await;
        let (via, epoch) = proxy(addr).await;
        let ka = KeepAlive {
            interval: Duration::from_millis(300),
            timeout: Duration::from_millis(200),
        };
        let t = DohTransport::with_keep_alive(via, Some(NAME), "/dns-query", Some(&pem), ka).unwrap();
        let q = query();
        assert!(t.query(&q, Duration::from_secs(2)).await.is_ok());
        epoch.fetch_add(1, SeqCst);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = Instant::now();
        let a = t.query(&q, Duration::from_secs(3)).await;
        let took = started.elapsed();
        assert!(a.is_ok(), "retried on a fresh connection: {a:?}");
        assert!(
            took < Duration::from_millis(1500),
            "found dead by the ping: {took:?}"
        );
        assert_eq!(accepts.load(SeqCst), 2);
    }
}
