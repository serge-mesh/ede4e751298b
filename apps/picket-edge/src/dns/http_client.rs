//! The HTTP client a lookup provider uses on the edge (edge.md §10 "Connections",
//! providers.md §4 `HttpClient`): hyper + rustls, HTTP/2 where the server offers it (kept alive
//! and reused), HTTP/1.1 otherwise.
//!
//! - **HTTPS only,** as core's clients (security.md §4): a request for any other scheme is
//!   refused, so a secret in a URL never goes out in clear.
//! - **No redirect is followed:** a 3xx comes back as a response, so credentials never cross one.
//! - The request's `timeout` bounds the whole exchange, body included; at most `max_body` body
//!   bytes are read; response headers are bounded (hyper's limits, set below).
//! - Host names resolve through the edge's own upstreams, unfiltered; IP literals are used as is.
//! - Each lookup provider has its own client and so its own connections and TLS sessions. The
//!   TLS configuration is built for the client's first connection, not before (#44).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use tokio::net::TcpStream;

use picket_lookup::{HttpClient, HttpError, HttpRequest, HttpResponse};

use super::lookups::UpstreamNames;

/// Most response header bytes (HTTP/2 header list; HTTP/1.1 read buffer).
const MAX_HEADER_BYTES: usize = 64 << 10;
const MAX_H1_HEADERS: usize = 100;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IDLE_H1: usize = 4;

/// A connection pool key: the URL's host as it appears in the authority (an IPv6 literal in
/// brackets) and its port.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Origin {
    host: String,
    port: u16,
}

/// Where a request connects: the host's address when it is an IP literal (otherwise its name is
/// resolved), and the name the server's certificate must carry.
struct Dest {
    ip: Option<IpAddr>,
    name: String,
    tls: rustls_pki_types::ServerName<'static>,
}

impl Dest {
    /// From the URL's parsed host: an IP literal is an address (and the certificate's IP
    /// name), a domain a DNS name.
    fn of(host: url::Host<&str>) -> Result<Self, HttpError> {
        use rustls_pki_types::ServerName;
        Ok(match host {
            url::Host::Domain(d) => Dest {
                ip: None,
                name: d.to_owned(),
                tls: ServerName::try_from(d.to_owned())
                    .map_err(|_| HttpError::Refused(format!("bad host {d:?}")))?,
            },
            url::Host::Ipv4(ip) => Self::ip(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Self::ip(IpAddr::V6(ip)),
        })
    }

    fn ip(ip: IpAddr) -> Self {
        Dest {
            ip: Some(ip),
            name: ip.to_string(),
            tls: rustls_pki_types::ServerName::IpAddress(ip.into()),
        }
    }
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

#[derive(Default)]
struct Pool {
    h2: HashMap<Origin, http2::SendRequest<Full<Bytes>>>,
    h1: HashMap<Origin, Vec<http1::SendRequest<Full<Bytes>>>>,
}

pub struct EdgeHttpClient {
    names: Arc<UpstreamNames>,
    /// Extra roots for HTTPS APIs (tests; production uses the Mozilla roots only).
    extra_roots: Option<Arc<str>>,
    /// The TLS configuration (its root store and session cache), built for the first connection
    /// (#44): a provider that never makes an HTTP request, or is answered from its caches, never
    /// builds one. Per client, so providers share no TLS sessions; dropped with the client.
    tls: OnceLock<Option<Arc<ClientConfig>>>,
    tls_builds: AtomicU32,
    pool: tokio::sync::Mutex<Pool>,
}

impl EdgeHttpClient {
    pub fn new(names: Arc<UpstreamNames>, extra_roots: Option<Arc<str>>) -> Self {
        Self {
            names,
            extra_roots,
            tls: OnceLock::new(),
            tls_builds: AtomicU32::new(0),
            pool: tokio::sync::Mutex::new(Pool::default()),
        }
    }

    /// The TLS configuration, built once on first use (concurrent first uses wait for the one
    /// build).
    fn tls(&self) -> Option<&Arc<ClientConfig>> {
        self.tls
            .get_or_init(|| {
                self.tls_builds.fetch_add(1, Ordering::Relaxed);
                super::upstream::tls::web_client_config(self.extra_roots.as_deref(), &[b"h2", b"http/1.1"])
                    .inspect_err(|e| tracing::warn!("lookup HTTP client: no TLS configuration: {e:#}"))
                    .ok()
            })
            .as_ref()
    }

    /// How many times this client built its TLS configuration: 0 before its first connection,
    /// then 1 (#44).
    pub fn tls_builds(&self) -> u32 {
        self.tls_builds.load(Ordering::Relaxed)
    }

    async fn pooled(&self, o: &Origin) -> Option<Sender> {
        let mut p = self.pool.lock().await;
        if let Some(s) = p.h2.get(o) {
            if !s.is_closed() {
                return Some(Sender::H2(s.clone()));
            }
            p.h2.remove(o);
        }
        if let Some(list) = p.h1.get_mut(o) {
            while let Some(s) = list.pop() {
                if !s.is_closed() && s.is_ready() {
                    return Some(Sender::H1(s));
                }
            }
        }
        None
    }

    async fn give_back(&self, o: &Origin, s: Sender) {
        let mut p = self.pool.lock().await;
        match s {
            Sender::H2(s) => {
                if !s.is_closed() {
                    p.h2.insert(o.clone(), s);
                }
            }
            Sender::H1(s) => {
                if !s.is_closed() {
                    let list = p.h1.entry(o.clone()).or_default();
                    if list.len() < MAX_IDLE_H1 {
                        list.push(s);
                    }
                }
            }
        }
    }

    async fn connect(&self, o: &Origin, dest: &Dest, deadline: Instant) -> Result<Sender, HttpError> {
        let addrs: Vec<IpAddr> = match dest.ip {
            Some(ip) => vec![ip],
            None => self.names.lookup(&dest.name).await.map_err(HttpError::Connect)?,
        };
        let mut last = HttpError::Connect("no address".into());
        for ip in addrs.into_iter().take(4) {
            let limit = deadline.min(Instant::now() + CONNECT_TIMEOUT);
            let tcp =
                match tokio::time::timeout_at(limit.into(), TcpStream::connect(SocketAddr::new(ip, o.port)))
                    .await
                {
                    Ok(Ok(t)) => t,
                    Ok(Err(e)) => {
                        last = HttpError::Connect(crate::diag::cap(e));
                        continue;
                    }
                    Err(_) => {
                        last = HttpError::Timeout;
                        continue;
                    }
                };
            let _ = tcp.set_nodelay(true);
            let Some(tls) = self.tls() else {
                return Err(HttpError::Refused("no TLS configuration".into()));
            };
            let stream = match tokio::time::timeout_at(
                deadline.into(),
                tokio_rustls::TlsConnector::from(Arc::clone(tls)).connect(dest.tls.clone(), tcp),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    last = HttpError::Connect(format!("TLS: {}", crate::diag::cap(e)));
                    continue;
                }
                Err(_) => return Err(HttpError::Timeout),
            };
            let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            return if is_h2 {
                h2(stream, deadline).await
            } else {
                h1(stream, deadline).await
            };
        }
        Err(last)
    }
}

async fn h1<S>(io: S, deadline: Instant) -> Result<Sender, HttpError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (s, conn) = tokio::time::timeout_at(
        deadline.into(),
        http1::Builder::new()
            .max_buf_size(MAX_HEADER_BYTES.max(8192))
            .max_headers(MAX_H1_HEADERS)
            .handshake(TokioIo::new(io)),
    )
    .await
    .map_err(|_| HttpError::Timeout)?
    .map_err(|e| HttpError::Connect(crate::diag::cap(e)))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(Sender::H1(s))
}

async fn h2<S>(io: S, deadline: Instant) -> Result<Sender, HttpError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (s, conn) = tokio::time::timeout_at(
        deadline.into(),
        http2::Builder::new(TokioExecutor::new())
            .max_header_list_size(u32::try_from(MAX_HEADER_BYTES).unwrap_or(u32::MAX))
            .keep_alive_interval(Duration::from_secs(20))
            .keep_alive_while_idle(false)
            .timer(hyper_util::rt::TokioTimer::new())
            .handshake(TokioIo::new(io)),
    )
    .await
    .map_err(|_| HttpError::Timeout)?
    .map_err(|e| HttpError::Connect(crate::diag::cap(e)))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(Sender::H2(s))
}

#[async_trait]
impl HttpClient for EdgeHttpClient {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        let deadline = Instant::now() + req.timeout;
        if req.url.scheme() != "https" {
            return Err(HttpError::Refused(format!(
                "scheme {:?}: only https is allowed",
                req.url.scheme()
            )));
        }
        let (Some(host), Some(parsed)) = (req.url.host_str(), req.url.host()) else {
            return Err(HttpError::Refused("no host".into()));
        };
        let dest = Dest::of(parsed)?;
        let port = req
            .url
            .port_or_known_default()
            .ok_or_else(|| HttpError::Refused("no port".into()))?;
        let origin = Origin {
            host: host.to_owned(),
            port,
        };
        let path = match req.url.query() {
            Some(q) => format!("{}?{}", req.url.path(), q),
            None => req.url.path().to_owned(),
        };
        let authority = match port {
            443 => origin.host.clone(),
            _ => format!("{}:{}", origin.host, port),
        };
        let body = Bytes::from(req.body.clone().unwrap_or_default());
        let build = |h2: bool| {
            let uri = if h2 {
                format!("https://{authority}{path}")
            } else {
                path.clone()
            };
            let mut b = Request::builder().method(req.method.clone()).uri(uri);
            if !h2 {
                b = b.header(header::HOST, &authority);
            }
            for (k, v) in req.headers.iter() {
                if k == header::HOST || k == header::CONNECTION || k == header::TRANSFER_ENCODING {
                    continue;
                }
                b = b.header(k, v);
            }
            b.body(Full::new(body.clone()))
                .map_err(|e| HttpError::Refused(crate::diag::cap(e)))
        };
        let mut sender = match self.pooled(&origin).await {
            Some(s) => s,
            None => self.connect(&origin, &dest, deadline).await?,
        };
        let first = match &mut sender {
            Sender::H1(s) => tokio::time::timeout_at(deadline.into(), s.send_request(build(false)?)).await,
            Sender::H2(s) => tokio::time::timeout_at(deadline.into(), s.send_request(build(true)?)).await,
        };
        let resp = match first {
            Err(_) => return Err(HttpError::Timeout),
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) if e.is_closed() || e.is_canceled() => {
                // A pooled connection that went away: once more on a fresh one.
                sender = self.connect(&origin, &dest, deadline).await?;
                let again = match &mut sender {
                    Sender::H1(s) => {
                        tokio::time::timeout_at(deadline.into(), s.send_request(build(false)?)).await
                    }
                    Sender::H2(s) => {
                        tokio::time::timeout_at(deadline.into(), s.send_request(build(true)?)).await
                    }
                };
                match again {
                    Err(_) => return Err(HttpError::Timeout),
                    Ok(Ok(resp)) => resp,
                    Ok(Err(e)) => return Err(HttpError::Transport(crate::diag::cap(e))),
                }
            }
            Ok(Err(e)) => return Err(HttpError::Transport(crate::diag::cap(e))),
        };
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let collected = tokio::time::timeout_at(
            deadline.into(),
            Limited::new(resp.into_body(), req.max_body).collect(),
        )
        .await
        .map_err(|_| HttpError::Timeout)?
        .map_err(|e| {
            if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                HttpError::BodyTooLarge { limit: req.max_body }
            } else {
                HttpError::Transport(crate::diag::cap(e))
            }
        })?;
        self.give_back(&origin, sender).await;
        Ok(HttpResponse {
            status,
            headers,
            body: collected.to_bytes().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> HttpRequest {
        HttpRequest {
            method: http::Method::GET,
            url: url::Url::parse(url).unwrap(),
            headers: http::HeaderMap::new(),
            body: None,
            timeout: Duration::from_secs(5),
            max_body: 1 << 16,
        }
    }

    /// The TLS name comes from the parsed host: an IP literal (IPv6 included, whose host text
    /// is bracketed) is an IP name, a domain a DNS name. No socket needed.
    #[test]
    fn tls_names_follow_the_parsed_host() {
        use rustls_pki_types::ServerName;
        let v6: std::net::Ipv6Addr = "fd00::53".parse().unwrap();
        let d = Dest::of(url::Host::Ipv6(v6)).unwrap();
        assert_eq!(d.ip, Some(IpAddr::V6(v6)));
        assert_eq!(d.tls, ServerName::IpAddress(IpAddr::V6(v6).into()));
        let v4 = std::net::Ipv4Addr::new(192, 0, 2, 53);
        assert_eq!(
            Dest::of(url::Host::Ipv4(v4)).unwrap().tls,
            ServerName::IpAddress(IpAddr::V4(v4).into())
        );
        let d = Dest::of(url::Host::Domain("api.example")).unwrap();
        assert_eq!((d.ip, d.name.as_str()), (None, "api.example"));
        assert_eq!(d.tls, ServerName::try_from("api.example").unwrap());
        // As a request's URL parses: the bracketed host text isn't what the name is made from.
        let u = url::Url::parse("https://[fd00::53]:8443/v1/x").unwrap();
        assert_eq!(u.host_str(), Some("[fd00::53]"));
        assert_eq!(
            Dest::of(u.host().unwrap()).unwrap().tls,
            ServerName::IpAddress(IpAddr::V6(v6).into())
        );
    }

    /// security.md §4: only HTTPS goes out, as from core's clients; a plain `http://` request
    /// is refused before any connection.
    #[tokio::test]
    async fn plain_http_is_refused() {
        let c = EdgeHttpClient::new(Arc::new(UpstreamNames::detached()), None);
        for url in ["http://127.0.0.1:9/v1/x?key=k", "ftp://127.0.0.1/x"] {
            let e = c.send(request(url)).await.unwrap_err();
            assert!(
                matches!(&e, HttpError::Refused(m) if m.contains("only https")),
                "{url}: {e:?}"
            );
        }
        assert_eq!(c.tls_builds(), 0, "a refused request builds no TLS configuration");
    }

    /// An HTTPS API at an IP literal, IPv6 included: the certificate is checked against the IP
    /// (the bracketed host text isn't a server name).
    #[tokio::test]
    async fn https_to_ip_literals_checks_the_ip_name() {
        for (bind, host) in [("127.0.0.1:0", "127.0.0.1"), ("[::1]:0", "[::1]")] {
            let Ok(l) = tokio::net::TcpListener::bind(bind).await else {
                eprintln!("skipped {bind}: no such address here");
                continue;
            };
            let ip = host.trim_start_matches('[').trim_end_matches(']');
            let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = rcgen::CertificateParams::new(vec![ip.to_owned()])
                .unwrap()
                .self_signed(&kp)
                .unwrap();
            let key = rustls_pki_types::PrivateKeyDer::try_from(kp.serialize_der()).unwrap();
            let mut sc = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap();
            sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));
            let port = l.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                loop {
                    let Ok((c, _)) = l.accept().await else { return };
                    let Ok(tls) = acceptor.accept(c).await else {
                        continue;
                    };
                    let svc =
                        hyper::service::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from_static(b"ok"),
                            )))
                        });
                    tokio::spawn(async move {
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), svc)
                            .await;
                    });
                }
            });
            let c = EdgeHttpClient::new(Arc::new(UpstreamNames::detached()), Some(cert.pem().into()));
            assert_eq!(c.tls_builds(), 0, "{host}: no TLS configuration before a request");
            // #44: concurrent first requests build the TLS configuration once; later ones reuse it.
            let url = format!("https://{host}:{port}/v1/x");
            let first = futures_util::future::join_all((0..8).map(|_| c.send(request(&url)))).await;
            for r in first.into_iter().chain([c.send(request(&url)).await]) {
                let r = r.unwrap_or_else(|e| panic!("{host}: {e:?}"));
                assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]), "{host}");
            }
            assert_eq!(c.tls_builds(), 1, "{host}");
            server.abort();
        }
    }
}
