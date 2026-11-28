//! The web port (core.md §1, §12): UI assets, `/api/ui/v1`, the UI WebSocket, `/lists/*`, the
//! LAN CA root, `/healthz`, `/metrics`, behind the mandatory protections ([`protect`]).
//!
//! `web.tls`: `managed` serves a LAN-CA certificate for `web.names` and core's LAN IPs
//! (`lanca/web.{crt,key}`, re-issued when its names change, or, on a synchronised clock, when its
//! root changes, it nears expiry or starts in the future), `file` serves
//! `web.cert_file`/`web.key_file`, `off` serves plain HTTP. `web.http_port`, when set, serves only
//! `/lists/*` and the LAN CA root over plain HTTP.

pub mod api;
pub mod assets;
pub mod auth;
pub mod browser_extension;
pub mod error;
pub mod events;
pub mod openapi;
pub mod protect;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{StatusCode, header};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tower::ServiceExt;

use crate::lanca;
use crate::settings::WebTls;
use crate::state::SharedState;
use protect::PeerAddr;

/// UI API request bodies (JSON) are capped; manual-feed uploads stream on their own routes.
pub const API_BODY_LIMIT: usize = 1024 * 1024;
/// Concurrent connections per port.
const MAX_CONNECTIONS: usize = 1024;
/// Concurrent connections per peer IP (README §2, Bounded: a capped share each). A browser
/// opens at most ~6 HTTP/1.1 connections per host (one with HTTP/2), so 64 leaves room for
/// several browsers behind one NAT address while one host can hold at most 1/16 of the port.
/// The spec leaves the value open.
pub const MAX_CONNECTIONS_PER_IP: usize = 64;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
struct HealthQuery {
    edges: Option<String>,
}

/// `/healthz`: 200 when the database writer answers within 2 s, else 503; with `?edges=1`,
/// also 503 while any edge is offline or has an open condition. The body holds no details.
async fn healthz(State(s): State<SharedState>, Query(q): Query<HealthQuery>) -> Response {
    let unavailable = || {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CACHE_CONTROL, "no-store")],
            "unavailable\n",
        )
            .into_response()
    };
    if !s.db.ping(Duration::from_secs(2)).await {
        return unavailable();
    }
    if q.edges.as_deref() == Some("1") {
        match crate::edges::all_healthy(&s.db, crate::util::now()).await {
            Ok(true) => {}
            _ => return unavailable(),
        }
    }
    (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")], "ok\n").into_response()
}

/// `/metrics` (reached only when `metrics.allow_cidrs` admits the caller): the Prometheus
/// export (api.md §7, core.md §10).
async fn metrics(State(s): State<SharedState>) -> Response {
    let body = crate::metrics::export::body(&s).await;
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

/// The LAN CA root, DER, for devices and browsers to install.
async fn ca_der(State(s): State<SharedState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"picket-lan-ca.crt\"",
            ),
        ],
        s.lanca.load().cert_der.clone(),
    )
        .into_response()
}

async fn ca_pem(State(s): State<SharedState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"picket-lan-ca.pem\"",
            ),
        ],
        s.lanca.load().cert_pem.clone(),
    )
        .into_response()
}

/// The web port's router.
pub fn router(state: SharedState) -> Router {
    Router::new()
        .nest(
            "/api/ui/v1",
            api::router().layer(DefaultBodyLimit::max(API_BODY_LIMIT)),
        )
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/lanca/ca.crt", get(ca_der))
        .route("/lanca/ca.pem", get(ca_pem))
        .route("/lists/{*path}", get(crate::lists::serve::get))
        .route("/browser-extension/{name}", get(browser_extension::download))
        .fallback(assets::serve)
        .layer(from_fn_with_state(state.clone(), protect::guard))
        .layer(from_fn(protect::headers))
        .with_state(state)
}

/// The plain-HTTP port's router: `/lists/*` and the LAN CA root only.
pub fn http_router(state: SharedState) -> Router {
    Router::new()
        .route("/lanca/ca.crt", get(ca_der))
        .route("/lanca/ca.pem", get(ca_pem))
        .route("/lists/{*path}", get(crate::lists::serve::get))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found\n") })
        .layer(from_fn_with_state(state.clone(), protect::guard))
        .layer(from_fn(protect::lists_only))
        .layer(from_fn(protect::headers))
        .with_state(state)
}

/// A server certificate that can be swapped at runtime (re-issue, renewal).
#[derive(Debug)]
pub struct SwapCert(pub ArcSwap<CertifiedKey>);

impl ResolvesServerCert for SwapCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.load_full())
    }
}

/// The names and IPs the managed web certificate covers: `web.names` and core's IPs in the LAN
/// ranges. With neither, `core.<first zone>` so TLS still works (set `web.names`).
pub fn web_cert_sans(state: &SharedState) -> (Vec<String>, Vec<IpAddr>) {
    let s = state.settings();
    let mut names: Vec<String> = s
        .web
        .names
        .iter()
        .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    let ips = crate::net::local_lan_ips(&state.core_ips());
    if names.is_empty() && ips.is_empty() {
        let zone = state
            .lanca
            .load()
            .zones()
            .first()
            .cloned()
            .unwrap_or_else(|| "home.arpa".into());
        names.push(format!("core.{zone}"));
    }
    names.sort();
    names.dedup();
    (names, ips)
}

/// Loads or (re)issues `lanca/web.{crt,key}` for the current SANs, one issue at a time
/// ([`crate::lanca::rotation::Runtime::web_cert_lock`]).
pub fn managed_web_cert(
    state: &SharedState,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<Arc<CertifiedKey>> {
    let _one = state.lanca_rt.web_cert_lock();
    load_or_issue_web_cert(state, provider)
}

/// [`managed_web_cert`] with its lock held. The stored pair is used when its certificate is
/// current ([`web_cert_current`]) and the key is the certificate's: a stop between the two writes
/// below leaves a key without its certificate, which is caught here and re-issued, never served
/// (README §2 Restarts).
fn load_or_issue_web_cert(
    state: &SharedState,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<Arc<CertifiedKey>> {
    let dir = lanca::lanca_dir(&state.data_dir);
    let (names, ips) = web_cert_sans(state);
    let synced = state.clock.synced();
    let crt = dir.join(lanca::WEB_CERT);
    let key = dir.join(lanca::WEB_KEY);
    let current = std::fs::read_to_string(&crt)
        .ok()
        .zip(std::fs::read_to_string(&key).ok());
    let lanca = state.lanca.load_full();
    if let Some((c, k)) = &current
        && crate::identity::pem_to_der(c, "CERTIFICATE")
            .is_ok_and(|der| web_cert_current(&der, &names, &ips, synced, &lanca))
    {
        match certified_key(c, k, provider) {
            Ok(ck) if ck.keys_match().is_ok() => return Ok(ck),
            Ok(_) => {
                tracing::warn!("lanca/web.key isn't the key of lanca/web.crt; re-issuing the web certificate")
            }
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "lanca/web.{{crt,key}} don't load; re-issuing the web certificate")
            }
        }
    }
    let (issued, key_pem) = lanca
        .issue_with_new_key(&names, &ips, lanca::LEAF_VALIDITY)
        .map_err(|e| anyhow::anyhow!("issue the web certificate: {e}"))?;
    let chain = format!("{}{}", issued.cert_pem, issued.chain_pem);
    crate::util::write_atomic(&key, key_pem.as_bytes(), 0o600)?;
    crate::util::write_atomic(&crt, chain.as_bytes(), 0o600)?;
    tracing::info!(names = ?names, ips = ?ips, "issued the web certificate from the LAN CA");
    certified_key(&chain, &key_pem, provider)
}

/// Re-issues the managed web certificate when it isn't current ([`web_cert_current`]): the names
/// or LAN IPs it should cover changed, or, on a synchronised clock, the LAN CA's current root
/// didn't sign it (a rotation, core.md §11), it has under 30 days left or starts in the future;
/// and swaps it into the running web port. One at a time, with the check: two refreshes never
/// both issue. `Ok(false)` when nothing needed doing (or the web port doesn't serve a managed
/// certificate).
pub fn refresh_web_cert(state: &SharedState) -> Result<bool> {
    let Some(swap) = state.web_cert.get() else {
        return Ok(false);
    };
    let _one = state.lanca_rt.web_cert_lock();
    let (names, ips) = web_cert_sans(state);
    let current = swap.0.load_full();
    let lanca = state.lanca.load_full();
    let synced = state.clock.synced();
    if current
        .cert
        .first()
        .is_some_and(|c| web_cert_current(c.as_ref(), &names, &ips, synced, &lanca))
    {
        return Ok(false);
    }
    let key = load_or_issue_web_cert(state, &crate::identity::crypto_provider())?;
    swap.0.store(key);
    Ok(true)
}

/// True when the web certificate `der` needs no re-issue: it covers exactly these SANs and passes
/// the time checks ([`der_matches`]), and, on a synchronised clock, the LAN CA's current root
/// signed it. Issuing dates a certificate, so before the clock is synchronised only the names
/// decide (README §2 Clocks): after a rotation the certificate from the previous root, dated while
/// the clock was synchronised, stays (devices that trust that root keep accepting it) until the
/// clock is synchronised again, and the minute refresh then re-issues it from the new root.
fn web_cert_current(
    der: &[u8],
    names: &[String],
    ips: &[IpAddr],
    clock_synced: bool,
    lanca: &lanca::LanCa,
) -> bool {
    der_matches(der, names, ips, clock_synced) && (!clock_synced || lanca.signed(der))
}

/// True when the DER certificate covers exactly these SANs and, on a synchronised clock, has over
/// 30 days left and has started: one issued while the clock was ahead starts in the future and no
/// browser accepts it yet. Before the clock is synchronised no date decides (README §2 Clocks), so
/// a wrong clock never replaces a good certificate with a badly dated one.
fn der_matches(der: &[u8], names: &[String], ips: &[IpAddr], clock_synced: bool) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    if clock_synced {
        let now = jiff::Timestamp::now().as_second();
        if cert.validity().not_after.timestamp() - now < 30 * 86_400
            || cert.validity().not_before.timestamp() > now
        {
            return false;
        }
    }
    let mut have_names = Vec::new();
    let mut have_ips = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for g in &san.value.general_names {
            match g {
                x509_parser::extensions::GeneralName::DNSName(n) => have_names.push(n.to_ascii_lowercase()),
                x509_parser::extensions::GeneralName::IPAddress(b) => {
                    if let Ok(a) = <[u8; 4]>::try_from(*b) {
                        have_ips.push(IpAddr::from(a));
                    } else if let Ok(a) = <[u8; 16]>::try_from(*b) {
                        have_ips.push(IpAddr::from(a));
                    }
                }
                _ => {}
            }
        }
    }
    have_names.sort();
    let mut want_ips: Vec<IpAddr> = ips.iter().map(|i| crate::net::canonical_ip(*i)).collect();
    want_ips.sort();
    have_ips.sort();
    have_names == names && have_ips == want_ips
}

/// Builds a rustls key from PEM chain + key text.
pub fn certified_key(
    chain_pem: &str,
    key_pem: &str,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<Arc<CertifiedKey>> {
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_slice_iter(chain_pem.as_bytes())
            .collect::<Result<_, _>>()
            .context("parse certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("no certificate in the PEM");
    }
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("parse key PEM")?;
    let signing = provider.key_provider.load_private_key(key).context("load key")?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

/// The web port's TLS config, or None for `web.tls = off`.
pub fn tls_config(state: &SharedState) -> Result<Option<(Arc<rustls::ServerConfig>, Arc<SwapCert>)>> {
    let provider = crate::identity::crypto_provider();
    let s = state.settings();
    let key = match s.web.tls {
        WebTls::Off => return Ok(None),
        WebTls::Managed => managed_web_cert(state, &provider)?,
        WebTls::File => {
            let c = s.web.cert_file.as_deref().context("web.cert_file is not set")?;
            let k = s.web.key_file.as_deref().context("web.key_file is not set")?;
            let chain = std::fs::read_to_string(c).with_context(|| format!("read {c}"))?;
            let key = std::fs::read_to_string(k).with_context(|| format!("read {k}"))?;
            certified_key(&chain, &key, &provider)?
        }
    };
    let swap = Arc::new(SwapCert(ArcSwap::from(key)));
    // Every interface uses TLS 1.3 (api.md, opening paragraph).
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(swap.clone());
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Some((Arc::new(cfg), swap)))
}

/// Binds `port` on every address (IPv6 dual-stack, else IPv4).
///
/// Every core port (web, plain-HTTP, and edge) intentionally listens on all interfaces with no
/// bind-address setting so container host networking and multi-homed hosts work without extra
/// configuration; `web.allow_cidrs`, `lists.allow_cidrs`, `metrics.allow_cidrs`, mTLS on the
/// edge port, and the host firewall control who is served.
pub fn bind(port: u16) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let try_v6 = || -> std::io::Result<std::net::TcpListener> {
        let s = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        s.set_only_v6(false)?;
        s.set_reuse_address(true)?;
        s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        s.listen(1024)?;
        s.set_nonblocking(true)?;
        Ok(s.into())
    };
    let std_listener = match try_v6() {
        Ok(l) => l,
        Err(_) => {
            let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            s.set_reuse_address(true)?;
            s.bind(&SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)).into())
                .with_context(|| format!("bind port {port}"))?;
            s.listen(1024)?;
            s.set_nonblocking(true)?;
            s.into()
        }
    };
    Ok(TcpListener::from_std(std_listener)?)
}

/// Per-connection limits of a server (README §2, Bounded).
#[derive(Clone, Copy, Debug)]
pub struct ServeLimits {
    pub max_connections: usize,
    /// Concurrent connections per peer IP, handshakes included.
    pub per_ip: usize,
    pub handshake_timeout: Duration,
    /// How long a client may take to send a request's headers (HTTP/1.1), so a slow or idle
    /// client can't hold one of the capped connections for ever.
    pub header_timeout: Duration,
    /// How long a client may take to send a JSON request body ([`error::ApiJson`]; at most
    /// [`API_BODY_LIMIT`]), so a stalled body can't hold a connection or an HTTP/2 stream for
    /// ever (`408` past it). Streamed uploads keep their own deadlines (`feeds::manual`,
    /// `config::export`).
    pub body_timeout: Duration,
    /// Concurrent streams per HTTP/2 connection.
    pub h2_streams: u32,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            per_ip: MAX_CONNECTIONS_PER_IP,
            handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
            header_timeout: Duration::from_secs(30),
            body_timeout: BODY_TIMEOUT,
            h2_streams: 128,
        }
    }
}

/// [`ServeLimits::body_timeout`]'s default: as long as the headers may take; a whole
/// [`API_BODY_LIMIT`] body in that time needs ≈ 35 KB/s.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// The JSON body deadline of the server a request arrived on ([`ServeLimits::body_timeout`]), in
/// each request's extensions; [`error::ApiJson`] applies it ([`BODY_TIMEOUT`] without one).
#[derive(Clone, Copy, Debug)]
pub struct BodyTimeout(pub Duration);

/// Whether a request arrived over TLS, in each request's extensions: the UI WebSocket's
/// `Origin` must use the scheme the connection uses (core.md §12), which a saved `web.tls`
/// change only alters at restart.
#[derive(Clone, Copy, Debug)]
pub struct ConnTls(pub bool);

/// An HTTP/1.1 + HTTP/2 connection builder with the limits applied.
pub fn conn_builder(limits: &ServeLimits) -> hyper_util::server::conn::auto::Builder<TokioExecutor> {
    use hyper_util::rt::TokioTimer;
    let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    b.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout)
        .keep_alive(true);
    b.http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(limits.h2_streams);
    b
}

/// Serves `router` on `listener` (TLS when `tls` is set) until shutdown.
pub fn serve(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    router: Router,
    shutdown: tokio_util::sync::CancellationToken,
) -> JoinHandle<()> {
    serve_with(listener, tls, router, shutdown, ServeLimits::default())
}

/// [`serve`] with explicit limits.
pub fn serve_with(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    router: Router,
    shutdown: tokio_util::sync::CancellationToken,
    limits: ServeLimits,
) -> JoinHandle<()> {
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let per_ip = crate::net::PerIp::new(limits.per_ip);
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                _ = shutdown.cancelled() => return,
                r = listener.accept() => match r {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let peer = crate::net::canonical_addr(peer);
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                drop(stream); // over the connection cap
                continue;
            };
            let Some(share) = per_ip.try_acquire(peer.ip()) else {
                drop(stream); // this IP holds its share of the port
                continue;
            };
            let _ = stream.set_nodelay(true);
            let router = router.clone();
            let acceptor = acceptor.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let _permit = (permit, share);
                let is_tls = acceptor.is_some();
                let body_timeout = limits.body_timeout;
                let svc =
                    hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                        req.extensions_mut().insert(PeerAddr(peer));
                        req.extensions_mut().insert(ConnTls(is_tls));
                        req.extensions_mut().insert(BodyTimeout(body_timeout));
                        let router = router.clone();
                        async move { router.oneshot(req.map(axum::body::Body::new)).await }
                    });
                let builder = conn_builder(&limits);
                let result = match acceptor {
                    Some(acc) => {
                        match tokio::time::timeout(limits.handshake_timeout, acc.accept(stream)).await {
                            Ok(Ok(tls)) => {
                                let conn = builder.serve_connection_with_upgrades(TokioIo::new(tls), svc);
                                tokio::select! { r = conn => r, _ = shutdown.cancelled() => Ok(()) }
                            }
                            _ => return,
                        }
                    }
                    None => {
                        let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), svc);
                        tokio::select! { r = conn => r, _ = shutdown.cancelled() => Ok(()) }
                    }
                };
                if let Err(e) = result {
                    tracing::debug!(error = %e, peer = %peer, "connection ended with an error");
                }
            });
        }
    })
}

/// Starts the web port (and the plain-HTTP port when set). Returns the bound addresses. With
/// `any_port`, each binds port 0 instead (tests). Called inside the runtime (it spawns the
/// servers).
pub fn start(state: SharedState, any_port: bool) -> Result<(Vec<SocketAddr>, Vec<JoinHandle<()>>)> {
    let s = state.settings();
    let port = |p: u16| if any_port { 0 } else { p };
    let mut addrs = Vec::new();
    let mut handles = Vec::new();
    let listener = bind(port(s.web.port))?;
    addrs.push(listener.local_addr()?);
    let tls = tls_config(&state)?;
    match &tls {
        None => tracing::warn!("web.tls is off: the UI's credentials cross the network in clear"),
        Some((_, swap)) if s.web.tls == WebTls::Managed => {
            let _ = state.web_cert.set(swap.clone());
        }
        Some(_) => {}
    }
    handles.push(serve(
        listener,
        tls.map(|(c, _)| c),
        router(state.clone()),
        state.shutdown.clone(),
    ));
    if let Some(p) = s.web.http_port {
        let l = bind(port(p))?;
        addrs.push(l.local_addr()?);
        handles.push(serve(l, None, http_router(state.clone()), state.shutdown.clone()));
    }
    Ok((addrs, handles))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// R3 (README §2 Clocks): on a synchronised clock the web certificate is re-issued when it
    /// starts in the future (issued while the clock was ahead) or has under 30 days left; before
    /// the clock is synchronised no date decides, only the names.
    #[test]
    fn web_certificate_time_checks_wait_for_a_synchronised_clock() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let names = vec!["core.home.arpa".to_string()];
        let now = rcgen::date_time_ymd(1970, 1, 1)
            + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
        let day = Duration::from_secs(86_400);
        let leaf = |nb, na| {
            let mut p = rcgen::CertificateParams::new(names.clone()).unwrap();
            p.not_before = nb;
            p.not_after = na;
            p.self_signed(&key).unwrap().der().to_vec()
        };
        let good = leaf(now - Duration::from_secs(3600), now + 397 * day);
        let future = leaf(now + 2 * day, now + 399 * day);
        let ending = leaf(now - 380 * day, now + 10 * day);
        for synced in [true, false] {
            assert!(der_matches(&good, &names, &[], synced));
            assert_eq!(
                der_matches(&future, &names, &[], synced),
                !synced,
                "synced={synced}"
            );
            assert_eq!(
                der_matches(&ending, &names, &[], synced),
                !synced,
                "synced={synced}"
            );
            assert!(!der_matches(&good, &["other.home.arpa".into()], &[], synced));
        }
    }

    async fn connect_from(src: [u8; 4], addr: SocketAddr) -> tokio::net::TcpStream {
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind(SocketAddr::from((src, 0))).unwrap();
        sock.connect(addr).await.unwrap()
    }

    /// True when the server closed the connection without answering a request.
    async fn dropped(mut s: tokio::net::TcpStream) -> bool {
        let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => true,
            Ok(Ok(_)) => false,
            Err(_) => panic!("no answer and no close"),
        }
    }

    #[tokio::test]
    async fn one_host_cannot_take_every_connection() {
        // README §2, Bounded: each client gets a capped share of the port's connections, so a
        // host holding idle connections leaves room for everyone else.
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let stop = tokio_util::sync::CancellationToken::new();
        let limits = ServeLimits {
            per_ip: 3,
            ..ServeLimits::default()
        };
        let router = Router::new().route("/", get(|| async { "ok" }));
        let _h = serve_with(listener, None, router, stop.clone(), limits);
        let mut idle = Vec::new();
        for _ in 0..3 {
            idle.push(connect_from([127, 0, 0, 1], addr).await);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            dropped(connect_from([127, 0, 0, 1], addr).await).await,
            "over its share"
        );
        assert!(
            !dropped(connect_from([127, 0, 0, 2], addr).await).await,
            "another host is served"
        );
        drop(idle);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !dropped(connect_from([127, 0, 0, 1], addr).await).await,
            "the share came back"
        );
        stop.cancel();
    }

    #[tokio::test]
    async fn a_json_body_that_never_finishes_gets_a_timeout_in_the_error_shape() {
        // README §2, Bounded: a client that sends a JSON request's headers but not all of its
        // body can't hold the connection (or an HTTP/2 stream) for ever: `ApiJson` answers 408
        // with the API's error shape once the body deadline passes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = tokio_util::sync::CancellationToken::new();
        let limits = ServeLimits {
            body_timeout: Duration::from_millis(300),
            ..ServeLimits::default()
        };
        let router = Router::new().route(
            "/",
            axum::routing::post(
                |error::ApiJson(v): error::ApiJson<serde_json::Value>| async move { axum::Json(v) },
            ),
        );
        let _h = serve_with(listener, None, router, stop.clone(), limits);
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"a\":")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("an answer within the body deadline")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.starts_with("HTTP/1.1 408"), "{text}");
        assert!(text.contains("\"code\":\"timeout\""), "{text}");
        stop.cancel();
    }

    #[tokio::test]
    async fn a_client_that_never_finishes_its_headers_is_dropped() {
        // README §2, Bounded: a slow client can't hold one of the capped connections forever.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = tokio_util::sync::CancellationToken::new();
        let limits = ServeLimits {
            header_timeout: Duration::from_millis(300),
            ..ServeLimits::default()
        };
        let router = Router::new().route("/", get(|| async { "ok" }));
        let _h = serve_with(listener, None, router, stop.clone(), limits);
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        let mut buf = [0u8; 256];
        let r = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await;
        match r {
            Ok(Ok(n)) => {
                // Closed, possibly after a 408.
                let text = String::from_utf8_lossy(&buf[..n]);
                assert!(n == 0 || text.starts_with("HTTP/1.1 408"), "{text}");
            }
            Ok(Err(_)) => {}
            Err(_) => panic!("the connection was still open after 5 s"),
        }
        stop.cancel();
    }
}
