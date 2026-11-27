//! The edge port (core.md §1, api.md §1–§2): TLS 1.3 with core's identity, client certificates
//! required. A client key is pinned when a registered edge holds it; the TLS layer checks the
//! certificate's signature and validity as usual, and names and CAs are ignored.
//!
//! - The TLS server, the post-handshake pin check, unknown keys listed as pending (fingerprint,
//!   address, claimed name), and `edge_key_mismatch` when an unknown key's certificate claims a
//!   registered edge's name (core.md §4).
//! - Every request is checked against the registry again, so a key replaced or an edge deleted
//!   while its connection is open is refused from then on (api.md §1 Key change).
//! - The edge API (api.md §2): `GET /v1/session` ([`session`]), `POST /v1/logs` and
//!   `POST /v1/csr` ([`api`]), and the `objects` bucket ([`objects`]).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use hyper_util::rt::TokioIo;
use rustls::DistinguishedName;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls_pki_types::{CertificateDer, UnixTime};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tower::ServiceExt;

use crate::alerts::{RaiseSpec, Severity};
use crate::state::SharedState;

pub mod api;
pub mod objects;
pub mod session;

const MAX_CONNECTIONS: usize = 512;
/// A write on an edge-port connection that makes no progress for this long fails, closing the
/// connection (README §2, Bounded: deadlines on socket writes; a peer that stops reading a blob
/// or its session can't hold a capped connection for ever).
pub const WRITE_STALL: Duration = Duration::from_secs(60);
/// Connections per peer IP, handshakes included (README §2, Bounded: a capped share each). An
/// edge keeps one session plus a few transfers open; the spec leaves the value open.
pub const MAX_CONNECTIONS_PER_IP: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent HTTP/2 streams per edge-port connection (README §2, Bounded). Each stream can
/// carry a log batch or a blob transfer; the edge speaks HTTP/1.1 and keeps a few connections,
/// so a handful is plenty. The spec gives no number.
pub const EDGE_H2_STREAMS: u32 = 8;

/// A connection's share of the edge port: the global and per-IP permits it was admitted with.
/// Every request carries a clone and a WebSocket session keeps one, so a connection hyper hands
/// over to an upgraded session still holds its share until the session ends (README §2,
/// Bounded).
#[derive(Clone)]
pub struct ConnShare(
    #[expect(dead_code, reason = "held for its drop, which releases the share")]
    Arc<(tokio::sync::OwnedSemaphorePermit, crate::net::PerIpGuard)>,
);
/// Unknown keys one IP may get recorded (pending list, `edge_key_mismatch`) per window; beyond
/// it the handshake is refused without a database write and counted. An edge with a new key
/// retries with its session backoff, so this only slows a flood (README §2, Bounded). The spec
/// leaves the value open.
pub const UNKNOWN_KEYS_PER_WINDOW: u32 = 10;
pub const UNKNOWN_KEY_WINDOW: Duration = Duration::from_secs(60);
/// IPs the unknown-key limiter tracks at once.
const UNKNOWN_KEY_IPS: usize = 4096;

/// Per-client admission of unknown keys to the database (fixed windows), by IPv4 address or
/// IPv6 /64.
#[derive(Default)]
pub struct UnknownKeys {
    ips: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (tokio::time::Instant, u32)>>,
    dropped: std::sync::atomic::AtomicU64,
}

impl UnknownKeys {
    /// True when `ip` may have one more unknown key recorded now.
    pub fn admit(&self, ip: std::net::IpAddr) -> bool {
        // One rate per IPv4 address or IPv6 /64 (crate::net::share_key).
        let ip = crate::net::share_key(ip);
        let now = tokio::time::Instant::now();
        let ok = match self.ips.lock() {
            Ok(mut m) => {
                if m.len() >= UNKNOWN_KEY_IPS && !m.contains_key(&ip) {
                    m.retain(|_, (start, _)| now.duration_since(*start) < UNKNOWN_KEY_WINDOW);
                }
                if m.len() >= UNKNOWN_KEY_IPS && !m.contains_key(&ip) {
                    false
                } else {
                    let e = m.entry(ip).or_insert((now, 0));
                    if now.duration_since(e.0) >= UNKNOWN_KEY_WINDOW {
                        *e = (now, 0);
                    }
                    e.1 += 1;
                    e.1 <= UNKNOWN_KEYS_PER_WINDOW
                }
            }
            Err(_) => false,
        };
        if !ok {
            self.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        ok
    }

    /// Unknown-key handshakes refused without a record.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The pinned edge a connection belongs to, in each request's extensions.
#[derive(Clone, Debug)]
pub struct EdgePeer {
    pub edge_id: String,
    pub edge_name: String,
    pub fingerprint: String,
    pub addr: SocketAddr,
}

/// Accepts any client certificate whose signature and validity check out; the key itself is
/// pinned after the handshake against the registry (api.md §1).
#[derive(Debug)]
pub struct AnyClientCert {
    provider: Arc<CryptoProvider>,
}

impl AnyClientCert {
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        check_client_cert(end_entity, now.as_secs()).map_err(rustls::Error::InvalidCertificate)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The check [`AnyClientCert`] makes on an untrusted client certificate (DER): it parses, and
/// `now` (Unix seconds) is inside its validity. Names and CAs are ignored; the key is pinned
/// after the handshake (api.md §1). Fuzzed (`fuzz/core`, `client_cert`).
pub fn check_client_cert(der: &[u8], now: u64) -> Result<(), rustls::CertificateError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|_| rustls::CertificateError::BadEncoding)?;
    let t = i64::try_from(now).unwrap_or(i64::MAX);
    let v = cert.validity();
    if t < v.not_before.timestamp() {
        return Err(rustls::CertificateError::NotValidYet);
    }
    if t > v.not_after.timestamp() {
        return Err(rustls::CertificateError::Expired);
    }
    Ok(())
}

/// The edge port's TLS config: core's identity, client certificates required, TLS 1.3 only
/// (api.md: all interfaces are TLS 1.3).
pub fn tls_config(state: &SharedState) -> Result<Arc<rustls::ServerConfig>> {
    let provider = crate::identity::crypto_provider();
    let key = state.identity.certified_key(&provider)?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AnyClientCert::new(provider)))
        .with_cert_resolver(Arc::new(SingleCert(key)));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct SingleCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for SingleCert {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The router pinned edges reach (api.md §2).
pub fn router(state: SharedState) -> Router {
    use axum::routing::{any, get, post};
    Router::new()
        .route(picket_api::edge_api::paths::SESSION, get(session::upgrade))
        .route(picket_api::edge_api::paths::LOGS, post(api::logs))
        .route(picket_api::edge_api::paths::CSR, post(api::csr))
        .route("/objects/{*key}", any(objects::handle))
        .fallback(|| async { api::error(StatusCode::NOT_FOUND, "not_found", "no such edge API path") })
        .layer(axum::middleware::from_fn_with_state(state.clone(), still_pinned))
        .with_state(state)
}

/// Refuses a request whose key is no longer registered for its edge (a key replaced or an edge
/// deleted while the connection was open; api.md §1).
async fn still_pinned(
    axum::extract::State(state): axum::extract::State<SharedState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let Some(peer) = req.extensions().get::<EdgePeer>().cloned() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let ok = match state.edges.hub.registered(&peer.fingerprint) {
        Some(r) => r.id == peer.edge_id,
        // The registry follows commits a moment later: ask the database.
        None => {
            matches!(crate::edges::by_key(&state.db, &peer.fingerprint).await, Ok(Some((id, _))) if id == peer.edge_id)
        }
    };
    if !ok {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

/// Handles a client key after the handshake: a registered key gets the router; an unknown key
/// is listed as pending (and checked for a name mismatch) and the connection closes. Unknown
/// keys are admitted to the database at a capped rate per IP, the pending list keeps a capped
/// share per address ([`crate::edges::MAX_PENDING_PER_ADDR`]), and `edge_key_mismatch` has one
/// alert per edge whose details name the latest key (core.md §4; README §2, Bounded).
async fn admit(
    state: &SharedState,
    unknown: &UnknownKeys,
    cert: &[u8],
    addr: SocketAddr,
) -> Option<EdgePeer> {
    let fp = crate::identity::cert_fingerprint(cert).ok()?;
    // Read before the database: a refresh after it means the read may be older than the
    // registry, and the note is skipped (api.md §1 Key change).
    let generation = state.edges.hub.registry_generation();
    match crate::edges::by_key(&state.db, &fp).await {
        Ok(Some((id, name))) => {
            state.edges.hub.note_registered(
                &crate::edges::hub::Registered {
                    id: id.clone(),
                    name: name.clone(),
                    fingerprint: fp.clone(),
                },
                generation,
            );
            Some(EdgePeer {
                edge_id: id,
                edge_name: name,
                fingerprint: fp,
                addr,
            })
        }
        Ok(None) => {
            if !unknown.admit(addr.ip()) {
                tracing::debug!(addr = %addr, "unknown edge key over this address's rate; not recorded");
                return None;
            }
            let cn = crate::identity::cert_common_name(cert);
            if let Err(e) =
                crate::edges::record_pending(&state.db, &fp, Some(addr.ip().to_string()), cn.clone()).await
            {
                tracing::warn!(error = %e, "cannot record a pending edge");
            }
            if let Some(cn) = cn
                && let Ok(Some(edge_id)) = crate::edges::by_name(&state.db, &cn).await
            {
                let name = crate::util::sanitize_for_message(&cn, 128);
                // One alert per edge: a new key repeats it (count, last_seen) and its details
                // name the latest key and address, so fresh keys can't fill the alert table.
                let spec = RaiseSpec::new(
                    "edge_key_mismatch",
                    Severity::Critical,
                    format!("edge_key_mismatch:{edge_id}"),
                    format!("A key that isn't edge {name}'s claims its name"),
                    serde_json::json!({"edge": edge_id, "claimed_name": name, "key": fp, "addr": addr.ip().to_string()}),
                )
                .edge(edge_id);
                let _ = state.alerts.raise(spec).await;
            }
            tracing::info!(key = %fp, addr = %addr, "unknown edge key; listed as pending");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "edge key lookup failed");
            None
        }
    }
}

/// Starts the edge port. Returns its bound address. With `any_port`, it binds port 0 instead
/// (tests). Called inside the runtime (it spawns the server).
pub fn start(state: SharedState, any_port: bool) -> Result<(SocketAddr, JoinHandle<()>)> {
    let port = if any_port {
        0
    } else {
        state.settings().edge_api.port
    };
    let listener: TcpListener = crate::web::bind(port)?;
    let addr = listener.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config(&state)?);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let per_ip = crate::net::PerIp::new(MAX_CONNECTIONS_PER_IP);
    let unknown = Arc::new(UnknownKeys::default());
    let shutdown = state.shutdown.clone();
    let app = router(state.clone());
    let h = tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                _ = shutdown.cancelled() => return,
                r = listener.accept() => match r {
                    Ok(x) => x,
                    Err(_) => { tokio::time::sleep(Duration::from_millis(50)).await; continue; }
                },
            };
            let peer = crate::net::canonical_addr(peer);
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let Some(share) = per_ip.try_acquire(peer.ip()) else {
                continue; // this IP holds its share of the port
            };
            let acceptor = acceptor.clone();
            let state = state.clone();
            let unknown = unknown.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let conn_share = ConnShare(Arc::new((permit, share)));
                let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                else {
                    return;
                };
                let cert = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| c.to_vec());
                let Some(cert) = cert else { return };
                let Some(edge) = admit(&state, &unknown, &cert, peer).await else {
                    return;
                };
                let router = app;
                let svc =
                    hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                        req.extensions_mut().insert(edge.clone());
                        req.extensions_mut().insert(conn_share.clone());
                        let router = router.clone();
                        async move { router.oneshot(req.map(axum::body::Body::new)).await }
                    });
                let builder = crate::web::conn_builder(&crate::web::ServeLimits {
                    h2_streams: EDGE_H2_STREAMS,
                    ..crate::web::ServeLimits::default()
                });
                let conn = builder
                    .serve_connection_with_upgrades(TokioIo::new(WriteDeadline::new(tls, WRITE_STALL)), svc);
                tokio::select! {
                    _ = conn => {}
                    _ = state.shutdown.cancelled() => {}
                }
            });
        }
    });
    Ok((addr, h))
}

/// A connection whose writes fail once they make no progress for `stall` ([`WRITE_STALL`]).
pub struct WriteDeadline<T> {
    inner: T,
    stall: Duration,
    timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl<T> WriteDeadline<T> {
    pub fn new(inner: T, stall: Duration) -> Self {
        Self {
            inner,
            stall,
            timer: None,
        }
    }

    /// Maps a pending write to a timeout once it has been pending for `stall`.
    fn pending<R>(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<R>> {
        use std::future::Future;
        let stall = self.stall;
        let t = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
        match t.as_mut().poll(cx) {
            std::task::Poll::Ready(()) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write stalled",
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WriteDeadline<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WriteDeadline<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, buf) {
            std::task::Poll::Ready(r) => {
                this.timer = None;
                std::task::Poll::Ready(r)
            }
            std::task::Poll::Pending => this.pending(cx),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_flush(cx) {
            std::task::Poll::Ready(r) => {
                this.timer = None;
                std::task::Poll::Ready(r)
            }
            std::task::Poll::Pending => this.pending(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_shutdown(cx) {
            std::task::Poll::Ready(r) => {
                this.timer = None;
                std::task::Poll::Ready(r)
            }
            std::task::Poll::Pending => this.pending(cx),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// `picket-core probe`

/// Records the server certificate from the handshake and whether its signature verified.
#[derive(Debug)]
struct CaptureCert {
    provider: Arc<CryptoProvider>,
    cert: std::sync::Mutex<Option<Vec<u8>>>,
    proven: std::sync::atomic::AtomicBool,
}

impl CaptureCert {
    /// Records a handshake signature that verified.
    fn note(
        &self,
        r: Result<HandshakeSignatureValid, rustls::Error>,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if r.is_ok() {
            self.proven.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        r
    }
}

impl rustls::client::danger::ServerCertVerifier for CaptureCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Ok(mut g) = self.cert.lock() {
            *g = Some(end_entity.to_vec());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.note(rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.note(rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The result of a probe (core.md §13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    /// Exit 0.
    Match,
    /// Exit 3: another identity (its fingerprint).
    Other(String),
    /// Exit 4: no TLS server certificate seen (unreachable, refused or timed out).
    NoCert(String),
}

impl ProbeResult {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Match => 0,
            Self::Other(_) => 3,
            Self::NoCert(_) => 4,
        }
    }
}

/// Parses `https://host:port[/…]` or `host:port` (default port 7443).
pub fn parse_probe_target(url: &str) -> Result<(String, u16), String> {
    let s = url.trim();
    let s = s.strip_prefix("https://").unwrap_or(s);
    if s.contains("://") {
        return Err("the URL must be https://host:port".into());
    }
    let authority = s.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err("the URL has no host".into());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or("bad IPv6 literal")?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| "bad port")?,
            None if tail.is_empty() => picket_api::edge_api::DEFAULT_EDGE_PORT,
            None => return Err("bad URL".into()),
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad port")?),
            None => (authority.to_string(), picket_api::edge_api::DEFAULT_EDGE_PORT),
        }
    };
    if port == 0 {
        return Err("bad port".into());
    }
    Ok((host, port))
}

/// Opens TLS to the edge port without a client certificate, reads the server certificate from
/// the handshake and compares its SPKI fingerprint with `expected`. Sends nothing else.
pub async fn probe(url: &str, expected: &str, timeout: Duration) -> ProbeResult {
    let (host, port) = match parse_probe_target(url) {
        Ok(x) => x,
        Err(e) => return ProbeResult::NoCert(e),
    };
    let provider = crate::identity::crypto_provider();
    let capture = Arc::new(CaptureCert {
        provider: provider.clone(),
        cert: std::sync::Mutex::new(None),
        proven: std::sync::atomic::AtomicBool::new(false),
    });
    let cfg = match rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    {
        Ok(b) => b
            .dangerous()
            .with_custom_certificate_verifier(capture.clone())
            .with_no_client_auth(),
        Err(e) => return ProbeResult::NoCert(e.to_string()),
    };
    let server_name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => rustls_pki_types::ServerName::IpAddress(ip.into()),
        Err(_) => match rustls_pki_types::ServerName::try_from(host.clone()) {
            Ok(n) => n,
            Err(_) => return ProbeResult::NoCert(format!("bad host {host:?}")),
        },
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let attempt = async {
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
        let _ = connector.connect(server_name, tcp).await; // the server may refuse us afterwards
        Ok::<_, std::io::Error>(())
    };
    let outcome = tokio::time::timeout(timeout, attempt).await;
    let cert = capture.cert.lock().ok().and_then(|g| g.clone());
    let proven = capture.proven.load(std::sync::atomic::Ordering::SeqCst);
    let Some(cert) = cert else {
        return ProbeResult::NoCert(match outcome {
            Err(_) => "timed out".into(),
            Ok(Err(e)) => e.to_string(),
            Ok(Ok(())) => "no certificate in the handshake".into(),
        });
    };
    let fp = match crate::identity::cert_fingerprint(&cert) {
        Ok(fp) => fp,
        Err(e) => return ProbeResult::NoCert(format!("unreadable server certificate: {e}")),
    };
    let want = picket_api::ids::parse_fingerprint(expected.trim());
    let got = picket_api::ids::parse_fingerprint(&fp);
    // A certificate whose key the server can't prove it holds isn't core's identity, even when
    // it is core's certificate: "another identity" (exit 3), never "no certificate seen".
    if proven && want.is_some() && want == got {
        ProbeResult::Match
    } else {
        ProbeResult::Other(fp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_stalled_write_times_out() {
        use tokio::io::AsyncWriteExt;
        // A peer that never reads: the pipe fills, then the write fails after the stall.
        let (a, _b) = tokio::io::duplex(64);
        let mut w = WriteDeadline::new(a, Duration::from_millis(100));
        let r = tokio::time::timeout(Duration::from_secs(5), w.write_all(&[0u8; 4096])).await;
        let e = r.expect("the write gives up on its own").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn unknown_keys_are_limited_per_ipv6_slash_64() {
        // README §2 Bounded (CC10): privacy addresses from one /64 share one rate.
        let u = UnknownKeys::default();
        let admitted = (0..64u16)
            .filter(|i| u.admit(std::net::IpAddr::from([0x2001, 0xdb8, 1, 2, *i, 0, 0, 1])))
            .count();
        assert_eq!(admitted, UNKNOWN_KEYS_PER_WINDOW as usize);
        assert!(u.admit("2001:db8:1:3::1".parse().unwrap()));
        assert_eq!(u.ips.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn probe_calls_an_unproven_certificate_another_identity() {
        // A server that presents core's certificate but can't sign with its key isn't core:
        // a certificate was seen, so the answer is "another identity" (exit 3), not 4.
        let (shown, _) = crate::identity::Identity::generate().unwrap();
        let (_, other_key) = crate::identity::Identity::generate().unwrap();
        let provider = crate::identity::crypto_provider();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            rcgen::KeyPair::from_pem(&other_key).unwrap().serialize_der(),
        ));
        let signing = provider.key_provider.load_private_key(key).unwrap();
        let ck = Arc::new(rustls::sign::CertifiedKey::new(
            vec![shown.cert_der.clone()],
            signing,
        ));
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCert(ck)));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((s, _)) = listener.accept().await {
                let _ = acceptor.accept(s).await;
            }
        });
        let r = probe(
            &format!("https://127.0.0.1:{port}"),
            &shown.fingerprint,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(r, ProbeResult::Other(shown.fingerprint.clone()));
        assert_eq!(r.exit_code(), 3);
    }

    #[test]
    fn client_certificate_bytes_never_panic() {
        // README §2 Untrusted input: what an unauthenticated client sends in its handshake.
        let (id, _) = crate::identity::Identity::generate().unwrap();
        let der: Vec<u8> = id.cert_der.to_vec();
        assert!(check_client_cert(&der, 1_800_000_000).is_ok());
        assert_eq!(
            check_client_cert(&der, 0),
            Err(rustls::CertificateError::NotValidYet)
        );
        for n in 0..der.len() {
            let _ = check_client_cert(&der[..n], 1_800_000_000);
            let _ = crate::identity::cert_fingerprint(&der[..n]);
            let _ = crate::identity::cert_common_name(&der[..n]);
            let mut flipped = der.clone();
            flipped[n] ^= 0xff;
            let _ = check_client_cert(&flipped, 1_800_000_000);
            let _ = crate::identity::cert_common_name(&flipped);
        }
    }

    #[test]
    fn targets() {
        assert_eq!(
            parse_probe_target("https://192.168.1.20:7443").unwrap(),
            ("192.168.1.20".into(), 7443)
        );
        assert_eq!(
            parse_probe_target("https://[::1]:9000/x").unwrap(),
            ("::1".into(), 9000)
        );
        assert_eq!(
            parse_probe_target("core.home.arpa").unwrap(),
            ("core.home.arpa".into(), 7443)
        );
        assert!(parse_probe_target("http://x:1").is_err());
        assert!(parse_probe_target("https://x:0").is_err());
    }
}
