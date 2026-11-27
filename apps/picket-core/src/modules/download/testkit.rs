//! An in-process HTTPS server for download-provider tests (build-and-test.md §5 "Providers":
//! recorded fixtures, 304/206 servers, rate-limit replies). It binds port 0 on 127.0.0.1, serves
//! a fresh test CA's certificate for the host names a test names, and records every request.
//! [`TestServer::http_options`] gives a client that trusts that CA and sends those host names to
//! the server, so providers keep their real URLs (`https://github.com/…`).
//!
//! Hidden from the docs: not part of core's API. Compiled for this crate's tests and with the
//! `testkit` feature, which its integration tests turn on; the shipped binary doesn't carry it.

#![allow(clippy::expect_used, reason = "a test double: a failure is the test's report")]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use super::client::HttpOptions;

/// A request the server saw.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    /// The `Host` (or `:authority`) the client asked for.
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// What to answer.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: ReplyBody,
}

/// A body, sent at once, gzip-compressed, or trickled.
#[derive(Clone, Debug)]
pub enum ReplyBody {
    Bytes(Bytes),
    /// Compressed with gzip and sent with `Content-Encoding: gzip`.
    Gzip(Bytes),
    /// `chunk` bytes, `count` times, `delay` apart.
    Slow {
        chunk: Bytes,
        count: usize,
        delay: Duration,
    },
}

impl Reply {
    pub fn ok(body: impl Into<Bytes>) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: ReplyBody::Bytes(body.into()),
        }
    }

    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: ReplyBody::Bytes(Bytes::new()),
        }
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
        self.headers.push((k.to_string(), v.to_string()));
        self
    }

    pub fn gzip(mut self) -> Self {
        if let ReplyBody::Bytes(b) = self.body {
            self.body = ReplyBody::Gzip(b);
        }
        self
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// A running server; stopped when dropped.
pub struct TestServer {
    pub addr: SocketAddr,
    /// The test CA (DER).
    pub root_der: Vec<u8>,
    hosts: Vec<String>,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: CancellationToken,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl TestServer {
    /// Starts a server for `hosts`, answering every request with `handler`.
    pub async fn start(hosts: &[&str], handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Self {
        let (root_der, chain, key) = issue(hosts);
        let provider = crate::identity::crypto_provider();
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("test certificate");
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = CancellationToken::new();
        let handler: Handler = Arc::new(handler);
        {
            let seen = seen.clone();
            let stop = stop.clone();
            tokio::spawn(async move {
                loop {
                    let (tcp, _) = tokio::select! {
                        _ = stop.cancelled() => return,
                        a = listener.accept() => match a { Ok(a) => a, Err(_) => continue },
                    };
                    let acceptor = acceptor.clone();
                    let handler = handler.clone();
                    let seen = seen.clone();
                    let stop = stop.clone();
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let svc =
                            hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                                let handler = handler.clone();
                                let seen = seen.clone();
                                async move { Ok::<_, Infallible>(serve(req, &handler, &seen).await) }
                            });
                        let conn = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                        tokio::select! {
                            _ = stop.cancelled() => {}
                            _ = conn.serve_connection(TokioIo::new(tls), svc) => {}
                        }
                    });
                }
            });
        }
        Self {
            addr,
            root_der,
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            seen,
            stop,
        }
    }

    /// Client options that trust the test CA and send the server's host names here.
    pub fn http_options(&self) -> HttpOptions {
        HttpOptions {
            extra_roots: vec![self.root_der.clone()],
            resolve: self.hosts.iter().map(|h| (h.clone(), self.addr)).collect(),
            ..HttpOptions::default()
        }
    }

    /// Every request so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Forgets the requests seen so far.
    pub fn clear(&self) {
        if let Ok(mut s) = self.seen.lock() {
            s.clear();
        }
    }
}

type BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>;

async fn serve(
    req: hyper::Request<hyper::body::Incoming>,
    handler: &Handler,
    seen: &Arc<Mutex<Vec<Seen>>>,
) -> hyper::Response<BoxBody> {
    let (parts, body) = req.into_parts();
    let body = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let host = parts
        .uri
        .authority()
        .map(|a| a.host().to_string())
        .or_else(|| {
            parts
                .headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        })
        .unwrap_or_default();
    let s = Seen {
        method: parts.method.to_string(),
        host,
        path: parts.uri.path().to_string(),
        query: parts.uri.query().map(str::to_string),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
            .collect(),
        body,
    };
    let reply = handler(&s);
    if let Ok(mut v) = seen.lock() {
        v.push(s);
    }
    let mut b = hyper::Response::builder().status(reply.status);
    for (k, v) in &reply.headers {
        b = b.header(k.as_str(), v.as_str());
    }
    let body: BoxBody = match reply.body {
        ReplyBody::Bytes(bytes) => Full::new(bytes).boxed_unsync(),
        ReplyBody::Gzip(bytes) => {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let _ = enc.write_all(&bytes);
            let gz = enc.finish().unwrap_or_default();
            b = b.header("content-encoding", "gzip");
            Full::new(Bytes::from(gz)).boxed_unsync()
        }
        ReplyBody::Slow { chunk, count, delay } => {
            let stream = futures_util::stream::unfold(0usize, move |i| {
                let chunk = chunk.clone();
                async move {
                    if i >= count {
                        return None;
                    }
                    tokio::time::sleep(delay).await;
                    Some((Ok::<_, Infallible>(Frame::data(chunk)), i + 1))
                }
            });
            BodyExt::boxed_unsync(StreamBody::new(stream))
        }
    };
    b.body(body)
        .unwrap_or_else(|_| hyper::Response::new(Full::new(Bytes::new()).boxed_unsync()))
}

/// A test CA and a leaf for `hosts`, signed by it.
fn issue(
    hosts: &[&str],
) -> (
    Vec<u8>,
    Vec<rustls_pki_types::CertificateDer<'static>>,
    rustls_pki_types::PrivateKeyDer<'static>,
) {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "picket test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf_params = rcgen::CertificateParams::new(hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>())
        .expect("leaf params");
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf cert");
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
    (
        ca_cert.der().to_vec(),
        vec![leaf.der().clone(), ca_cert.der().clone()],
        key,
    )
}
