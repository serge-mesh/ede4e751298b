//! The download providers' HTTP client (providers.md §2 `Ctx`): `reqwest` over rustls with the
//! Mozilla roots, `Accept-Encoding: gzip, br` (bodies are decoded as they stream), a generic
//! `User-Agent: picket/<ver>`, and core's resolver (`resolver`, core.md §11: the host's, or an
//! upstream by IP over DoT or DoH through `hickory-resolver`).
//!
//! **HTTPS only**, and redirects are followed here, not by `reqwest`: at most
//! [`HttpOptions::max_redirects`] (5), each to an `https://` URL. Headers marked as credentials
//! go only with the first request, to the host they are configured for, never across a redirect
//! (README §2 Secrets).
//!
//! **Deadlines** on every exchange (README §2 Bounded): connecting, waiting for the response
//! head, the gap between two body chunks, and the whole body. Bodies are bounded by the caller:
//! [`Resp::bytes_limited`] for small API answers, [`Ctx::stage`] for downloads (the decoded
//! size cap, `feeds.max_download_mib`).
//!
//! Errors never carry a URL (`reqwest::Error::without_url`): a URL may hold a resolved secret.
//!
//! [`Ctx::stage`]: super::Ctx::stage

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use url::Url;

/// Client settings. Tests add a root and map host names to a local server; production uses
/// the defaults.
#[derive(Clone, Debug)]
pub struct HttpOptions {
    pub connect_timeout: Duration,
    /// Until the response head arrives.
    pub response_timeout: Duration,
    /// The longest gap between two body chunks.
    pub idle_timeout: Duration,
    /// The longest a whole download body may take.
    pub body_deadline: Duration,
    pub max_redirects: usize,
    /// Extra trusted roots (DER), beside the Mozilla roots (tests).
    pub extra_roots: Vec<Vec<u8>>,
    /// Host name → address overrides, before any resolver (tests).
    pub resolve: Vec<(String, SocketAddr)>,
    /// Core's resolver: `None` for the host's.
    pub resolver: Option<crate::settings::ResolverUpstream>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(30),
            // What a list download needs (README §2 Bounded; core.md §3: a check holds a
            // light-lane slot while it runs): 30 s without a byte, 5 min for a whole body (the
            // 256 MiB cap needs ≈ 0.9 MB/s; a 40 MB list ≈ 0.14 MB/s).
            idle_timeout: Duration::from_secs(30),
            body_deadline: Duration::from_secs(5 * 60),
            max_redirects: 5,
            extra_roots: vec![],
            resolve: vec![],
            resolver: None,
        }
    }
}

/// An HTTP failure, without any URL or secret in its text.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("{0}")]
    Transport(String),
    #[error("timed out {0}")]
    Timeout(&'static str),
    #[error("{0}")]
    Refused(String),
    #[error("the body is larger than {0} bytes")]
    TooLarge(u64),
    #[error("cancelled")]
    Cancelled,
}

impl HttpError {
    fn from_reqwest(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            return Self::Timeout("waiting for the server");
        }
        let e = e.without_url();
        // The source chain (connect errors, TLS alerts) without the URL.
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
        Self::Transport(crate::util::sanitize_for_message(&msg, 400))
    }
}

/// One request header. Its `Debug` leaves the value out (it may hold a secret).
#[derive(Clone)]
pub struct Header {
    pub name: HeaderName,
    pub value: HeaderValue,
    /// Sent only with the first request, never after a redirect.
    pub credential: bool,
}

impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header")
            .field("name", &self.name)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

/// A request. Its `Debug` leaves out the URL's query and user info, header values and the body,
/// and redacts every resolved secret value from the rest (README §2 Secrets).
#[derive(Clone)]
pub struct Req {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<Header>,
    pub body: Option<Bytes>,
}

impl std::fmt::Debug for Req {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        picket_lookup::secrets::debug_redacted(f, |f| {
            f.debug_struct("Req")
                .field("method", &self.method)
                .field("url", &picket_lookup::url_for_logs(&self.url))
                .field(
                    "headers",
                    &self.headers.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(),
                )
                .finish_non_exhaustive()
        })
    }
}

impl Req {
    pub fn get(url: Url) -> Self {
        Self {
            method: Method::GET,
            url,
            headers: vec![],
            body: None,
        }
    }

    pub fn post(url: Url, body: Bytes) -> Self {
        Self {
            method: Method::POST,
            url,
            headers: vec![],
            body: Some(body),
        }
    }

    /// Adds a header; values that aren't valid header text are refused.
    pub fn header(mut self, name: &str, value: &str) -> Result<Self, HttpError> {
        self.headers.push(make_header(name, value, false)?);
        Ok(self)
    }

    /// Adds a credential header (never sent across a redirect).
    pub fn credential(mut self, name: &str, value: &str) -> Result<Self, HttpError> {
        let mut h = make_header(name, value, true)?;
        h.value.set_sensitive(true);
        self.headers.push(h);
        Ok(self)
    }
}

fn make_header(name: &str, value: &str, credential: bool) -> Result<Header, HttpError> {
    let n = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| HttpError::Refused(format!("{name:?} is not a header name")))?;
    // The value is never quoted: it may hold a secret.
    let v = HeaderValue::from_str(value)
        .map_err(|_| HttpError::Refused(format!("the value of header {n} is not valid header text")))?;
    Ok(Header {
        name: n,
        value: v,
        credential,
    })
}

/// A response whose head has arrived; the body is read with [`Resp::bytes_limited`] or
/// [`Ctx::stage`](super::Ctx::stage).
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    /// The URL that answered (after redirects).
    pub url: Url,
    /// Redirects followed.
    pub redirects: usize,
    inner: reqwest::Response,
    opts: Arc<HttpOptions>,
}

impl std::fmt::Debug for Resp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resp")
            .field("status", &self.status)
            .field("redirects", &self.redirects)
            .finish_non_exhaustive()
    }
}

impl Resp {
    /// A header as text.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The media type, lowercased, without parameters.
    pub fn media_type(&self) -> Option<String> {
        self.header("content-type")
            .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
    }

    /// True for `text/html` (captive portals, error pages): a failed check (providers.md §2).
    pub fn is_html(&self) -> bool {
        self.media_type().as_deref() == Some("text/html")
    }

    /// Reads the whole (decoded) body, at most `max` bytes, within the body deadline.
    pub async fn bytes_limited(self, max: usize) -> Result<Bytes, HttpError> {
        let idle = self.opts.idle_timeout;
        let deadline = tokio::time::Instant::now() + self.opts.body_deadline;
        let mut stream = self.inner.bytes_stream();
        let mut out = BytesMut::new();
        loop {
            let next =
                tokio::time::timeout_at(deadline.min(tokio::time::Instant::now() + idle), stream.next())
                    .await
                    .map_err(|_| HttpError::Timeout("reading the body"))?;
            match next {
                None => break,
                Some(Err(e)) => return Err(HttpError::from_reqwest(e)),
                Some(Ok(chunk)) => {
                    if out.len() + chunk.len() > max {
                        return Err(HttpError::TooLarge(max as u64));
                    }
                    out.extend_from_slice(&chunk);
                }
            }
        }
        Ok(out.freeze())
    }

    /// Streams the decoded body into `w`, chunk by chunk, within the deadlines; `w` enforces the
    /// size cap. Returns the bytes written.
    pub async fn stream_into(
        self,
        w: &mut super::StageWriter,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<u64, HttpError> {
        let idle = self.opts.idle_timeout;
        let deadline = tokio::time::Instant::now() + self.opts.body_deadline;
        let mut stream = self.inner.bytes_stream();
        let mut total = 0u64;
        loop {
            let wait = deadline.min(tokio::time::Instant::now() + idle);
            let next = tokio::select! {
                _ = cancel.cancelled() => return Err(HttpError::Cancelled),
                n = tokio::time::timeout_at(wait, stream.next()) => {
                    n.map_err(|_| HttpError::Timeout("reading the body"))?
                }
            };
            match next {
                None => break,
                Some(Err(e)) => return Err(HttpError::from_reqwest(e)),
                Some(Ok(chunk)) => {
                    total += chunk.len() as u64;
                    w.write(&chunk).await?;
                }
            }
        }
        Ok(total)
    }

    /// Drops the body unread (a probe that didn't want it).
    pub fn discard(self) {}
}

/// The client. Cheap to clone.
#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    opts: Arc<HttpOptions>,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http").finish_non_exhaustive()
    }
}

/// The generic `User-Agent` (providers.md §2).
pub fn user_agent() -> String {
    format!("picket/{}", crate::VERSION)
}

impl Http {
    pub fn new(opts: HttpOptions) -> anyhow::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for der in &opts.extra_roots {
            roots
                .add(rustls_pki_types::CertificateDer::from(der.clone()))
                .map_err(|e| anyhow::anyhow!("bad extra root: {e}"))?;
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(crate::identity::crypto_provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut b = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(user_agent())
            .gzip(true)
            .brotli(true)
            .no_proxy()
            .referer(false)
            .connect_timeout(opts.connect_timeout)
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(4);
        for (host, addr) in &opts.resolve {
            b = b.resolve(host, *addr);
        }
        if let Some(up) = &opts.resolver {
            b = b.dns_resolver(Arc::new(resolver::CoreResolver::new(up)?));
        }
        Ok(Self {
            client: b.build()?,
            opts: Arc::new(opts),
        })
    }

    pub fn options(&self) -> &HttpOptions {
        &self.opts
    }

    /// Sends `req`, following at most `max_redirects` HTTPS redirects; credential headers go
    /// only with the first request. Returns once the response head of the last hop arrived.
    pub async fn send(&self, req: Req) -> Result<Resp, HttpError> {
        let mut url = req.url.clone();
        // README §2 Secrets: reqwest would send user info as Basic auth on every hop of a
        // same-host redirect. Modules refuse such URLs; the client does too.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HttpError::Refused(
                "a URL with a user name or password; use a header with a secret".into(),
            ));
        }
        let mut method = req.method.clone();
        let mut body = req.body.clone();
        let mut redirects = 0usize;
        loop {
            if url.scheme() != "https" {
                return Err(HttpError::Refused("downloads are HTTPS only".into()));
            }
            let mut rb = self.client.request(method.clone(), url.clone());
            for h in &req.headers {
                if h.credential && redirects > 0 {
                    continue; // never across a redirect (README §2 Secrets)
                }
                rb = rb.header(h.name.clone(), h.value.clone());
            }
            if let Some(b) = &body {
                rb = rb.body(b.clone());
            }
            let resp = tokio::time::timeout(self.opts.response_timeout, rb.send())
                .await
                .map_err(|_| HttpError::Timeout("waiting for the response"))?
                .map_err(HttpError::from_reqwest)?;
            let status = resp.status();
            if status.is_redirection() && status != StatusCode::NOT_MODIFIED {
                let Some(loc) = resp
                    .headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                else {
                    return Err(HttpError::Refused(format!(
                        "a {status} redirect without a Location"
                    )));
                };
                let mut next = url
                    .join(loc)
                    .map_err(|_| HttpError::Refused("a redirect to an unreadable Location".into()))?;
                // No credentials across a redirect (README §2 Secrets): a Location's user info is
                // dropped, so reqwest sends no Basic auth from it.
                let _ = next.set_username("");
                let _ = next.set_password(None);
                if next.scheme() != "https" {
                    return Err(HttpError::Refused("a redirect away from HTTPS".into()));
                }
                redirects += 1;
                if redirects > self.opts.max_redirects {
                    return Err(HttpError::Refused(format!(
                        "more than {} redirects",
                        self.opts.max_redirects
                    )));
                }
                if status == StatusCode::SEE_OTHER
                    || ((status == StatusCode::MOVED_PERMANENTLY || status == StatusCode::FOUND)
                        && method == Method::POST)
                {
                    method = Method::GET;
                    body = None;
                }
                url = next;
                continue;
            }
            return Ok(Resp {
                status,
                headers: resp.headers().clone(),
                url,
                redirects,
                inner: resp,
                opts: self.opts.clone(),
            });
        }
    }
}

/// Core's resolver for feed and lookup-provider hosts (core.md §11 `resolver`): an upstream by IP
/// over DoT or DoH, never resolved itself (README §2 rule 9).
pub mod resolver {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    use crate::settings::{EncryptedProtocol, ResolverUpstream};

    pub struct CoreResolver {
        inner: TokioResolver,
    }

    impl CoreResolver {
        pub fn new(up: &ResolverUpstream) -> anyhow::Result<Self> {
            let name: Arc<str> = Arc::from(up.tls_host.as_str());
            let mut conn = match up.protocol {
                EncryptedProtocol::Dot => ConnectionConfig::tls(name),
                EncryptedProtocol::Doh => ConnectionConfig::https(name, up.path.as_deref().map(Arc::from)),
            };
            conn.port = up.port;
            let ns = NameServerConfig::new(up.ip, true, vec![conn]);
            let cfg = ResolverConfig::from_name_servers(vec![ns]);
            let mut roots = rustls::RootCertStore::empty();
            match &up.trust_store {
                Some(pem) => {
                    use rustls_pki_types::pem::PemObject;
                    for c in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
                        roots
                            .add(c.map_err(|e| anyhow::anyhow!("resolver trust_store: {e}"))?)
                            .map_err(|e| anyhow::anyhow!("resolver trust_store: {e}"))?;
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            let tls = rustls::ClientConfig::builder_with_provider(crate::identity::crypto_provider())
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            let mut b =
                TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default()).with_tls_config(tls);
            b.options_mut().timeout = std::time::Duration::from_secs(5);
            b.options_mut().attempts = 2;
            Ok(Self {
                inner: b.build().map_err(|e| anyhow::anyhow!("core's resolver: {e}"))?,
            })
        }
    }

    impl reqwest::dns::Resolve for CoreResolver {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let r = self.inner.clone();
            let host = name.as_str().to_string();
            Box::pin(async move {
                let ips = r
                    .lookup_ip(host.as_str())
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                let addrs: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(ip, 0)).collect();
                let it: reqwest::dns::Addrs = Box::new(addrs.into_iter());
                Ok(it)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// README §2 Secrets: a request's `Debug` prints no resolved secret (user info, query,
    /// header values, body), only the method, origin, path and header names.
    #[test]
    fn debug_leaves_secrets_out() {
        let url = Url::parse("https://u:SECRET1@api.example:8443/v1/x?key=SECRET2#SECRET6").unwrap();
        let r = Req::post(url, Bytes::from_static(b"SECRET5"))
            .credential("Authorization", "Bearer SECRET3")
            .unwrap()
            .header("X-Plain", "SECRET4")
            .unwrap();
        let text = format!("{r:?} {:?}", r.headers);
        for leak in ["SECRET1", "SECRET2", "SECRET3", "SECRET4", "SECRET5", "SECRET6"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        for shown in [
            "POST",
            "https://api.example:8443/v1/x",
            "authorization",
            "x-plain",
        ] {
            assert!(text.contains(shown), "{shown} missing from {text}");
        }
    }

    /// README §2 Secrets: a resolved secret in the URL's host or path is redacted from `{:?}`.
    #[test]
    fn debug_redacts_resolved_secrets_in_host_and_path() {
        let secrets: std::collections::BTreeMap<String, String> =
            [("h", "hostsecret3141"), ("p", "pathsecret2718")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        let cfg = serde_json::json!({"url": "https://${secret:h}.feeds.example/list/${secret:p}.txt"});
        let r = picket_lookup::secrets::resolve(&cfg, &secrets).unwrap();
        let req = Req::get(Url::parse(r.config["url"].as_str().unwrap()).unwrap());
        let text = format!("{req:?}");
        assert!(
            !text.contains("hostsecret3141") && !text.contains("pathsecret2718"),
            "{text}"
        );
        assert!(
            text.contains("${secret:h}.feeds.example/list/${secret:p}.txt"),
            "{text}"
        );
    }

    #[test]
    fn headers_refuse_bad_text_without_quoting_it() {
        let e = Req::get(Url::parse("https://example.org/").unwrap())
            .credential("Authorization", "Bearer s3cr3t\nX-Injected: 1")
            .unwrap_err();
        assert!(!e.to_string().contains("s3cr3t"), "{e}");
        assert!(
            Req::get(Url::parse("https://example.org/").unwrap())
                .header("bad name", "x")
                .is_err()
        );
    }

    #[test]
    fn client_builds_with_and_without_a_resolver() {
        Http::new(HttpOptions::default()).unwrap();
        let up = crate::settings::ResolverUpstream {
            protocol: crate::settings::EncryptedProtocol::Doh,
            ip: "9.9.9.9".parse().unwrap(),
            port: 443,
            tls_host: "dns.quad9.net".into(),
            path: None,
            trust_store: None,
        };
        let opts = HttpOptions {
            resolver: Some(up),
            ..HttpOptions::default()
        };
        // Building needs a runtime for hickory's provider.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async { Http::new(opts).unwrap() });
    }
}
