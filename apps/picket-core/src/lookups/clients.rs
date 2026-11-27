//! Core's connections for lookup providers (providers.md §4 `LookupCtx`; core.md §7): an HTTP/2
//! client and a DNS server client per provider, never shared, replaced when the provider's config
//! changes (the `LookupClient` asks its [`picket_lookup::ConnectionFactory`] again).
//!
//! - **Settings reach their user** (README §2; core.md §11): the factory and every provider's
//!   HTTP client read core's current connection options ([`LiveOptions`]: the `resolver` and the
//!   test overrides) rather than a copy taken when the client was built. A new `resolver` bumps
//!   the options' version; each provider's HTTP client then rebuilds its connections before its
//!   next request, keeping the provider's breaker, pause and token bucket.
//!
//! - **HTTP** ([`CoreHttp`]): `reqwest` over rustls with the Mozilla roots, HTTPS only, HTTP/2
//!   where the server offers it, **no redirect followed** (a 3xx comes back as a response, so
//!   credentials never cross a redirect, README §2 Secrets), host names resolved by core's
//!   `resolver` (core.md §11). `timeout` bounds the whole exchange and the body is read up to
//!   `max_body` bytes. Errors never carry a URL (a URL may hold a resolved secret).
//! - **DNS servers** ([`CoreDns`]): one query to a server the provider names, by IP, never through
//!   `resolver` (providers.md §5 `dns`): `udp` (answers up to 65,535 bytes, matched by the query's
//!   id from the server's own address), `tcp` and `dot` (one length-prefixed message; DoT over
//!   rustls with the server's `tls_host` and trust store) or `doh` (POST
//!   `application/dns-message` to `https://<tls_host>:<port><path>`, connected to the IP). The
//!   answer goes back unchecked: the module checks it with the edge's upstream-answer code.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use picket_api::edge_config::UpstreamProtocol;
use picket_lookup::{
    Connections, DnsClientError, DnsServer, DnsServerClient, HttpClient, HttpError, HttpRequest, HttpResponse,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::modules::download::client::HttpOptions;

/// Most response headers kept (README §2 Bounded).
const MAX_HEADERS: usize = 100;
/// The largest DNS message (16-bit length).
const MAX_DNS: usize = 65_535;
/// DoH clients one provider keeps (one per server it names; README §2 Bounded).
const MAX_DOH_CLIENTS: usize = 16;

fn roots(extra: &[Vec<u8>], pem: Option<&str>) -> anyhow::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    match pem {
        Some(pem) => {
            use rustls_pki_types::pem::PemObject;
            for c in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
                roots
                    .add(c.map_err(|e| anyhow::anyhow!("trust_store: {e}"))?)
                    .map_err(|e| anyhow::anyhow!("trust_store: {e}"))?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    for der in extra {
        roots
            .add(rustls_pki_types::CertificateDer::from(der.clone()))
            .map_err(|e| anyhow::anyhow!("bad extra root: {e}"))?;
    }
    Ok(roots)
}

fn tls_config(roots: rustls::RootCertStore, alpn: &[&[u8]]) -> anyhow::Result<rustls::ClientConfig> {
    let mut tls = rustls::ClientConfig::builder_with_provider(crate::identity::crypto_provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(tls)
}

/// A `reqwest` error's text without its URL.
fn reqwest_text(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(&e);
    let mut depth = 0;
    while let Some(s) = src {
        if depth >= 4 {
            break;
        }
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
        depth += 1;
    }
    crate::util::sanitize_for_message(&msg, 400)
}

/// The wall clock core's lookups read (README §2 Clocks): the clients stamp `obtained_at` with
/// it and the queue's deadlines come from it ([`super::Lookups::now`]). It is the system clock,
/// plus an offset only tests set, to simulate a boot clock that is wrong until NTP corrects it
/// ([`super::Lookups::simulate_clock_offset`]). It counts as synchronised only while core's
/// [`crate::clock::Clock`] says so (not before it is linked), so a client makes no call on an
/// unsynchronised clock, even one that lost its synchronisation while the lookup waited for a
/// token ([`picket_lookup::Clock::synced`]).
#[derive(Debug, Default)]
pub struct WallClock {
    offset_ms: std::sync::atomic::AtomicI64,
    sync: std::sync::OnceLock<Arc<crate::clock::Clock>>,
}

impl WallClock {
    pub fn set_offset(&self, offset: jiff::SignedDuration) {
        let ms = i64::try_from(offset.as_millis()).unwrap_or(if offset.is_negative() {
            i64::MIN
        } else {
            i64::MAX
        });
        self.offset_ms.store(ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Links core's synchronisation flag (once; later calls keep the first).
    pub fn follow(&self, clock: &Arc<crate::clock::Clock>) {
        let _ = self.sync.set(clock.clone());
    }
}

impl picket_lookup::Clock for WallClock {
    fn now(&self) -> jiff::Timestamp {
        let ms = self.offset_ms.load(std::sync::atomic::Ordering::SeqCst);
        picket_api::time::saturating_add(crate::util::now(), jiff::SignedDuration::from_millis(ms))
    }

    fn synced(&self) -> bool {
        self.sync.get().is_some_and(|c| c.synced())
    }
}

/// Core's current connection options for lookup providers (module docs), shared by the factory
/// and every provider's HTTP client.
#[derive(Default)]
pub struct LiveOptions {
    current: Mutex<(u64, Arc<HttpOptions>)>,
}

impl LiveOptions {
    pub fn new(opts: HttpOptions) -> Self {
        Self {
            current: Mutex::new((0, Arc::new(opts))),
        }
    }

    /// The options now, and their version.
    pub fn get(&self) -> (u64, Arc<HttpOptions>) {
        self.current
            .lock()
            .map(|g| (g.0, g.1.clone()))
            .unwrap_or_else(|p| {
                let g = p.into_inner();
                (g.0, g.1.clone())
            })
    }

    /// Replaces the options when they differ; true when they did (a new version).
    pub fn set(&self, opts: HttpOptions) -> bool {
        let mut g = self.current.lock().unwrap_or_else(|p| p.into_inner());
        if same_options(&g.1, &opts) {
            return false;
        }
        *g = (g.0.wrapping_add(1), Arc::new(opts));
        true
    }
}

/// True when two option sets make the same connections.
fn same_options(a: &HttpOptions, b: &HttpOptions) -> bool {
    a.resolver == b.resolver
        && a.resolve == b.resolve
        && a.extra_roots == b.extra_roots
        && a.connect_timeout == b.connect_timeout
        && a.max_redirects == b.max_redirects
}

/// One provider's HTTP client, built from core's current options and rebuilt when they change.
pub struct CoreHttp {
    live: Option<Arc<LiveOptions>>,
    built: Mutex<(u64, Result<reqwest::Client, String>)>,
}

impl CoreHttp {
    /// A client that follows `live` (module docs).
    pub fn following(live: Arc<LiveOptions>) -> Self {
        let (v, opts) = live.get();
        let built = build_http(&opts).map_err(|e| format!("{e:#}"));
        Self {
            live: Some(live),
            built: Mutex::new((v, built)),
        }
    }

    /// A client of fixed options.
    pub fn new(opts: &HttpOptions) -> anyhow::Result<Self> {
        Ok(Self {
            live: None,
            built: Mutex::new((0, Ok(build_http(opts)?))),
        })
    }

    /// The client for the current options (rebuilt first when they changed).
    fn client(&self) -> Result<reqwest::Client, HttpError> {
        let mut g = self.built.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(live) = &self.live {
            let (v, opts) = live.get();
            if v != g.0 {
                *g = (v, build_http(&opts).map_err(|e| format!("{e:#}")));
            }
        }
        g.1.clone()
            .map_err(|e| HttpError::Refused(format!("cannot build the provider's HTTP client: {e}")))
    }
}

/// Builds the HTTP client of `opts` (module docs).
fn build_http(opts: &HttpOptions) -> anyhow::Result<reqwest::Client> {
    let tls = tls_config(roots(&opts.extra_roots, None)?, &[b"h2", b"http/1.1"])?;
    let mut b = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(crate::modules::download::client::user_agent())
        .gzip(true)
        .brotli(true)
        .no_proxy()
        .referer(false)
        .connect_timeout(opts.connect_timeout)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(8);
    for (host, addr) in &opts.resolve {
        b = b.resolve(host, *addr);
    }
    if let Some(up) = &opts.resolver {
        b = b.dns_resolver(Arc::new(
            crate::modules::download::client::resolver::CoreResolver::new(up)?,
        ));
    }
    Ok(b.build()?)
}

impl CoreHttp {
    async fn exchange(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        if req.url.scheme() != "https" {
            return Err(HttpError::Refused("lookup providers are HTTPS only".into()));
        }
        let client = self.client()?;
        let mut rb = client.request(req.method.clone(), req.url.clone());
        for (k, v) in req.headers.iter() {
            rb = rb.header(k.clone(), v.clone());
        }
        if let Some(b) = req.body {
            rb = rb.body(b);
        }
        let resp = rb.send().await.map_err(|e| {
            if e.is_connect() {
                HttpError::Connect(reqwest_text(e))
            } else {
                HttpError::Transport(reqwest_text(e))
            }
        })?;
        let status = resp.status().as_u16();
        let mut headers = http::HeaderMap::new();
        for (k, v) in resp.headers().iter().take(MAX_HEADERS) {
            headers.append(k.clone(), v.clone());
        }
        let mut body = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| HttpError::Transport(reqwest_text(e)))?;
            if body.len() + chunk.len() > req.max_body {
                return Err(HttpError::BodyTooLarge { limit: req.max_body });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[async_trait::async_trait]
impl HttpClient for CoreHttp {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        let t = req.timeout;
        tokio::time::timeout(t, self.exchange(req))
            .await
            .map_err(|_| HttpError::Timeout)?
    }
}

/// One provider's DNS server client.
pub struct CoreDns {
    extra_roots: Vec<Vec<u8>>,
    doh: Mutex<HashMap<DnsServer, reqwest::Client>>,
}

impl CoreDns {
    pub fn new(opts: &HttpOptions) -> Self {
        Self {
            extra_roots: opts.extra_roots.clone(),
            doh: Mutex::new(HashMap::new()),
        }
    }

    fn doh_client(&self, s: &DnsServer) -> Result<reqwest::Client, DnsClientError> {
        if let Some(c) = self.doh.lock().ok().and_then(|m| m.get(s).cloned()) {
            return Ok(c);
        }
        let host = s
            .tls_host
            .clone()
            .ok_or_else(|| DnsClientError::Connect("a DoH server needs tls_host".into()))?;
        let tls = tls_config(
            roots(&self.extra_roots, s.trust_store.as_deref())
                .map_err(|e| DnsClientError::Connect(e.to_string()))?,
            &[b"h2", b"http/1.1"],
        )
        .map_err(|e| DnsClientError::Connect(e.to_string()))?;
        let c = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .referer(false)
            // Connected by IP: the name is the TLS name only, never resolved (README §2 rule 9).
            .resolve(&host, SocketAddr::new(s.ip, s.port))
            .build()
            .map_err(|e| DnsClientError::Connect(reqwest_text(e)))?;
        if let Ok(mut m) = self.doh.lock() {
            if m.len() >= MAX_DOH_CLIENTS {
                m.clear();
            }
            m.insert(s.clone(), c.clone());
        }
        Ok(c)
    }

    async fn udp(s: &DnsServer, query: &[u8]) -> Result<Vec<u8>, DnsClientError> {
        let bind: SocketAddr = if s.ip.is_ipv4() {
            "0.0.0.0:0"
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
        } else {
            "[::]:0"
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([0u16; 8], 0)))
        };
        let sock = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|e| DnsClientError::Connect(e.to_string()))?;
        let to = SocketAddr::new(s.ip, s.port);
        sock.connect(to)
            .await
            .map_err(|e| DnsClientError::Connect(e.to_string()))?;
        sock.send(query)
            .await
            .map_err(|e| DnsClientError::Transport(e.to_string()))?;
        let mut buf = vec![0u8; MAX_DNS];
        loop {
            let n = sock
                .recv(&mut buf)
                .await
                .map_err(|e| DnsClientError::Transport(e.to_string()))?;
            // A connected socket only takes the server's datagrams; one that isn't the answer to
            // this query (another id) is skipped.
            if n >= 2 && query.len() >= 2 && buf.get(..2) == query.get(..2) {
                buf.truncate(n);
                return Ok(buf);
            }
        }
    }

    async fn tcp(s: &DnsServer, query: &[u8]) -> Result<Vec<u8>, DnsClientError> {
        let stream = tokio::net::TcpStream::connect(SocketAddr::new(s.ip, s.port))
            .await
            .map_err(|e| DnsClientError::Connect(e.to_string()))?;
        exchange_framed(stream, query).await
    }

    async fn dot(&self, s: &DnsServer, query: &[u8]) -> Result<Vec<u8>, DnsClientError> {
        let host = s
            .tls_host
            .clone()
            .ok_or_else(|| DnsClientError::Connect("a DoT server needs tls_host".into()))?;
        let tls = tls_config(
            roots(&self.extra_roots, s.trust_store.as_deref())
                .map_err(|e| DnsClientError::Connect(e.to_string()))?,
            &[b"dot"],
        )
        .map_err(|e| DnsClientError::Connect(e.to_string()))?;
        let name = rustls_pki_types::ServerName::try_from(host)
            .map_err(|_| DnsClientError::Connect("tls_host isn't a TLS name".into()))?;
        let tcp = tokio::net::TcpStream::connect(SocketAddr::new(s.ip, s.port))
            .await
            .map_err(|e| DnsClientError::Connect(e.to_string()))?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(name, tcp)
            .await
            .map_err(|e| DnsClientError::Connect(e.to_string()))?;
        exchange_framed(stream, query).await
    }

    async fn doh(&self, s: &DnsServer, query: &[u8]) -> Result<Vec<u8>, DnsClientError> {
        let c = self.doh_client(s)?;
        let host = s.tls_host.as_deref().unwrap_or_default();
        let path = s.path.as_deref().unwrap_or("/dns-query");
        // The edge's transport sends the same path (picket_api::edge_config::is_doh_path).
        if !picket_api::edge_config::is_doh_path(path) {
            return Err(DnsClientError::Connect(format!(
                "DoH path {path:?}: it must be {}",
                picket_api::edge_config::DOH_PATH_RULE
            )));
        }
        let url = url::Url::parse(&format!("https://{host}:{}{}", s.port, path))
            .map_err(|_| DnsClientError::Connect("a DoH URL that doesn't parse".into()))?;
        let resp = c
            .post(url)
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::ACCEPT, "application/dns-message")
            .body(query.to_vec())
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    DnsClientError::Connect(reqwest_text(e))
                } else {
                    DnsClientError::Transport(reqwest_text(e))
                }
            })?;
        if !resp.status().is_success() {
            return Err(DnsClientError::Transport(format!(
                "HTTP {}",
                resp.status().as_u16()
            )));
        }
        let mut out = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| DnsClientError::Transport(reqwest_text(e)))?;
            if out.len() + chunk.len() > MAX_DNS {
                return Err(DnsClientError::TooLarge);
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// Writes one length-prefixed message and reads one back (RFC 1035 §4.2.2, RFC 7858).
pub async fn exchange_framed<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    query: &[u8],
) -> Result<Vec<u8>, DnsClientError> {
    let len = u16::try_from(query.len()).map_err(|_| DnsClientError::Transport("query too large".into()))?;
    let mut msg = Vec::with_capacity(query.len() + 2);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(query);
    stream
        .write_all(&msg)
        .await
        .map_err(|e| DnsClientError::Transport(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| DnsClientError::Transport(e.to_string()))?;
    read_framed(&mut stream).await
}

/// Reads one length-prefixed DNS message (at most 65,535 bytes by construction).
pub async fn read_framed<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, DnsClientError> {
    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|e| DnsClientError::Transport(e.to_string()))?;
    let n = usize::from(u16::from_be_bytes(len));
    if n == 0 {
        return Err(DnsClientError::Transport("an empty answer".into()));
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| DnsClientError::Transport(e.to_string()))?;
    Ok(buf)
}

#[async_trait::async_trait]
impl DnsServerClient for CoreDns {
    async fn query(
        &self,
        server: &DnsServer,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsClientError> {
        let fut = async {
            match server.transport {
                UpstreamProtocol::Udp => Self::udp(server, query).await,
                UpstreamProtocol::Tcp => Self::tcp(server, query).await,
                UpstreamProtocol::Dot => self.dot(server, query).await,
                UpstreamProtocol::Doh => self.doh(server, query).await,
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| DnsClientError::Timeout)?
    }
}

/// The connection factory core's lookup clients use: new connections each time a provider's
/// config changes, from core's current options (`live`, module docs). A client that can't be
/// built refuses every request (the call fails, and the provider's status shows why) until the
/// options change.
pub fn factory(live: Arc<LiveOptions>) -> picket_lookup::ConnectionFactory {
    Arc::new(move |provider: &str| {
        let http = CoreHttp::following(live.clone());
        if let Ok(g) = http.built.lock()
            && let Err(e) = &g.1
        {
            tracing::warn!(provider, error = %e, "cannot build the provider's HTTP client");
        }
        let (_, opts) = live.get();
        Connections {
            http: Arc::new(http),
            dns: Arc::new(CoreDns::new(&opts)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framed_messages_roundtrip_and_refuse_short_reads() {
        let (mut a, b) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let q = read_framed(&mut a).await.unwrap();
            assert_eq!(q, b"\x12\x34query");
            let mut out = vec![0, 6];
            out.extend_from_slice(b"\x12\x34resp");
            a.write_all(&out).await.unwrap();
        });
        let r = exchange_framed(b, b"\x12\x34query").await.unwrap();
        assert_eq!(r, b"\x12\x34resp");
        server.await.unwrap();
        // A length the stream doesn't deliver is an error, not a hang or a panic.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 10, 1, 2]).await.unwrap();
        drop(a);
        assert!(read_framed(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn udp_answers_are_matched_by_id() {
        let srv = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = srv.recv_from(&mut buf).await.unwrap();
            // Another id first: skipped.
            srv.send_to(b"\xff\xffwrong", from).await.unwrap();
            let mut out = buf[..2].to_vec();
            out.extend_from_slice(b"right");
            srv.send_to(&out, from).await.unwrap();
            let _ = n;
        });
        let s = DnsServer {
            transport: UpstreamProtocol::Udp,
            ip: addr.ip(),
            port: addr.port(),
            tls_host: None,
            trust_store: None,
            path: None,
        };
        let c = CoreDns::new(&HttpOptions::default());
        let r = c.query(&s, b"\xab\xcdq", Duration::from_secs(5)).await.unwrap();
        assert_eq!(r, b"\xab\xcdright");
    }

    #[tokio::test]
    async fn http_refuses_plain_http() {
        let h = CoreHttp::new(&HttpOptions::default()).unwrap();
        let r = h
            .send(HttpRequest {
                method: http::Method::GET,
                url: url::Url::parse("http://example.org/").unwrap(),
                headers: http::HeaderMap::new(),
                body: None,
                timeout: Duration::from_secs(1),
                max_body: 1024,
            })
            .await;
        assert!(matches!(r, Err(HttpError::Refused(_))), "{r:?}");
    }

    /// L9 (README §2 "Settings reach their user"; core.md §11): a provider's existing HTTP client
    /// follows core's current options: after a change, its next request connects where the new
    /// options say (here a host override standing in for a new `resolver`).
    #[tokio::test]
    async fn http_clients_follow_new_options() {
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = a.local_addr().unwrap().port();
        let Ok(b) = tokio::net::TcpListener::bind(("127.0.0.2", port)).await else {
            return; // no second loopback address here
        };
        let opts = |ip: &str| HttpOptions {
            resolve: vec![("lookup.example".into(), format!("{ip}:{port}").parse().unwrap())],
            ..HttpOptions::default()
        };
        let live = Arc::new(LiveOptions::new(opts("127.0.0.1")));
        let h = CoreHttp::following(live.clone());
        let req = || HttpRequest {
            method: http::Method::GET,
            url: url::Url::parse(&format!("https://lookup.example:{port}/")).unwrap(),
            headers: http::HeaderMap::new(),
            body: None,
            timeout: Duration::from_secs(2),
            max_body: 1024,
        };
        let accepted = |l: tokio::net::TcpListener| {
            tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(5), l.accept())
                    .await
                    .is_ok()
            })
        };
        let wa = accepted(a);
        let _ = h.send(req()).await;
        assert!(wa.await.unwrap(), "the first options' address");
        assert!(!live.set(opts("127.0.0.1")), "the same options are no change");
        assert!(live.set(opts("127.0.0.2")));
        let wb = accepted(b);
        let _ = h.send(req()).await;
        assert!(wb.await.unwrap(), "the new options' address");
    }
}
