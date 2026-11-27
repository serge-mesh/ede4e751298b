//! `LookupCtx` (providers.md §4): what a module may use for one lookup provider. Its HTTP client
//! and DNS server client, the provider's own per-provider state, a wall clock, cancellation and
//! the call's deadline.
//!
//! Each lookup provider has its own `LookupCtx` and so its own connections (edge.md §10
//! "Connections"); saving a provider's config replaces them (the `LookupClient` builds a new
//! context through its [`ConnectionFactory`]). `${secret:name}` references in the config are
//! resolved by the `LookupClient` before a call, so modules only see resolved values.
//!
//! The client implementations live with their users: on the edge, hyper + rustls with names
//! resolved through the edge's own unfiltered upstreams, and the upstream transports for DNS
//! servers (edge.md §6, §10); on core, core's resolver and `hickory-net` clients configured the
//! same way (core.md §7).

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use picket_api::edge_config::UpstreamProtocol;
use picket_api::time::Timestamp;
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------------------------
// HTTP

/// One HTTP request a module sends. Its `Debug` leaves out the query, user info, header values
/// and the body, and redacts every resolved secret value from the rest (README §2 Secrets).
#[derive(Clone)]
pub struct HttpRequest {
    pub method: http::Method,
    pub url: url::Url,
    pub headers: http::HeaderMap,
    pub body: Option<Vec<u8>>,
    /// For the whole exchange, body included.
    pub timeout: Duration,
    /// The most body bytes to read; a longer body is [`HttpError::BodyTooLarge`].
    pub max_body: usize,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::secrets::debug_redacted(f, |f| {
            f.debug_struct("HttpRequest")
                .field("method", &self.method)
                .field("url", &url_for_logs(&self.url))
                .field("headers", &header_names(&self.headers))
                .field("timeout", &self.timeout)
                .field("max_body", &self.max_body)
                .finish_non_exhaustive()
        })
    }
}

/// `scheme://host[:port]/path` of `u`: without its user info, query and fragment, which may
/// carry a resolved secret (README §2 Secrets). For `Debug` output and logs; a secret in the host
/// or path is left to [`crate::secrets::redact_resolved`].
pub fn url_for_logs(u: &url::Url) -> String {
    let mut s = format!("{}://{}", u.scheme(), u.host_str().unwrap_or_default());
    if let Some(p) = u.port() {
        s.push(':');
        s.push_str(&p.to_string());
    }
    s.push_str(u.path());
    s
}

/// The names of `h`, without values (which may carry a secret).
pub fn header_names(h: &http::HeaderMap) -> Vec<&str> {
    h.keys().map(http::HeaderName::as_str).collect()
}

/// An HTTP response with its whole (bounded) body.
#[derive(Clone, Debug, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
}

/// Why no response came back. Messages must not quote request headers; the `LookupClient`
/// also redacts secret values from every message it passes on.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    #[error("timed out")]
    Timeout,
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("response body over {limit} bytes")]
    BodyTooLarge { limit: usize },
    /// The client refused to send the request (e.g. a scheme or address it doesn't allow).
    #[error("request refused: {0}")]
    Refused(String),
}

/// The HTTP/2 client a lookup provider uses (providers.md §4).
///
/// Contract: HTTPS (rustls) with HTTP/2 where the server offers it; **no redirect is followed**
/// (a 3xx comes back as a response, providers.md §5 `http_json`), so credentials never cross a
/// redirect (README §2 "Secrets"); `timeout` bounds the whole exchange; at most `max_body` body
/// bytes are read, decoded; response headers are bounded (count and size) by the
/// implementation; host names are resolved by the side's own resolver.
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError>;
}

// ---------------------------------------------------------------------------------------------
// DNS servers

/// A DNS server a provider names (providers.md §5 `dns`), by IP: never resolved.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsServer {
    pub transport: UpstreamProtocol,
    pub ip: IpAddr,
    pub port: u16,
    /// The TLS name for `dot` and `doh`.
    pub tls_host: Option<String>,
    /// PEM text for `dot` and `doh`; `None` = the Mozilla roots (`webpki-roots`).
    pub trust_store: Option<String>,
    /// The DoH path.
    pub path: Option<String>,
}

impl fmt::Debug for DnsServer {
    // A trust store is long and uninteresting in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsServer")
            .field("transport", &self.transport)
            .field("ip", &self.ip)
            .field("port", &self.port)
            .field("tls_host", &self.tls_host)
            .field("trust_store", &self.trust_store.as_ref().map(|_| "…"))
            .field("path", &self.path)
            .finish()
    }
}

/// Why a DNS server gave no answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DnsClientError {
    #[error("timed out")]
    Timeout,
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("answer over the size limit")]
    TooLarge,
}

/// The server client (providers.md §4): sends one query to a server the provider names and
/// returns the raw answer, unchecked (the module checks it with picket-wire's upstream-answer
/// code). `udp`, `tcp`, `dot` (one length-prefixed message) or `doh` (POST
/// `application/dns-message` to `path`); on the edge over the upstream transports (edge.md §6),
/// never an upstream group, and the answer never enters the DNS cache. UDP answers are read up to
/// 65,535 bytes; TCP, DoT and DoH answers are bounded by their 16-bit length or the DNS maximum.
#[async_trait::async_trait]
pub trait DnsServerClient: Send + Sync {
    async fn query(
        &self,
        server: &DnsServer,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsClientError>;
}

/// A server client for sides that have none: every query fails to connect.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDnsClient;

#[async_trait::async_trait]
impl DnsServerClient for NoDnsClient {
    async fn query(&self, _: &DnsServer, _: &[u8], _: Duration) -> Result<Vec<u8>, DnsClientError> {
        Err(DnsClientError::Connect("no DNS server client".into()))
    }
}

/// An HTTP client for sides that have none: every request is refused.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHttpClient;

#[async_trait::async_trait]
impl HttpClient for NoHttpClient {
    async fn send(&self, _: HttpRequest) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Refused("no HTTP client".into()))
    }
}

/// The connections of one lookup provider, built by a [`ConnectionFactory`].
#[derive(Clone)]
pub struct Connections {
    pub http: Arc<dyn HttpClient>,
    pub dns: Arc<dyn DnsServerClient>,
}

impl Connections {
    /// Connections that refuse everything (tests, or a side without one of the clients).
    pub fn none() -> Self {
        Self {
            http: Arc::new(NoHttpClient),
            dns: Arc::new(NoDnsClient),
        }
    }
}

/// Builds a lookup provider's own connections, given its id. Called when the client is created
/// and whenever the provider's config changes ("saving a provider's config replaces its
/// connections", providers.md §4).
pub type ConnectionFactory = Arc<dyn Fn(&str) -> Connections + Send + Sync>;

// ---------------------------------------------------------------------------------------------
// Clock

/// Wall-clock time. Durations use tokio's monotonic clock; the wall clock stamps `obtained_at`,
/// checks verdict-set expiry and reads `Retry-After` dates.
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;

    /// Whether this clock can stamp a provider's answer (README §2 Clocks): false while the wall
    /// clock isn't synchronised. An async lookup makes no call then
    /// ([`crate::AsyncResult::ClockUnsynced`]), checked right before each call after any wait
    /// for a slot or a token. Clocks that don't know (the system clock) count as synchronised.
    fn synced(&self) -> bool {
        true
    }
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

// ---------------------------------------------------------------------------------------------
// LookupCtx

type StateMap = HashMap<TypeId, Arc<dyn Any + Send + Sync>>;

/// What a module gets for one lookup provider (providers.md §4). The `LookupClient` hands each
/// call a view of the provider's context carrying the call's deadline ([`Self::deadline`]);
/// connections and state are the provider's, shared by every view.
pub struct LookupCtx {
    shared: Arc<Shared>,
    deadline: Option<tokio::time::Instant>,
}

struct Shared {
    provider_id: Arc<str>,
    http: Arc<dyn HttpClient>,
    dns: Arc<dyn DnsServerClient>,
    clock: Arc<dyn Clock>,
    cancel: CancellationToken,
    state: Mutex<StateMap>,
}

impl fmt::Debug for LookupCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LookupCtx")
            .field("provider_id", &self.shared.provider_id)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl LookupCtx {
    pub fn new(
        provider_id: &str,
        conns: Connections,
        clock: Arc<dyn Clock>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                provider_id: provider_id.into(),
                http: conns.http,
                dns: conns.dns,
                clock,
                cancel,
                state: Mutex::new(HashMap::new()),
            }),
            deadline: None,
        }
    }

    /// The same provider context for one call that the caller drops at `deadline`
    /// (`async_timeout_ms` after it started).
    pub fn with_deadline(&self, deadline: tokio::time::Instant) -> Self {
        Self {
            shared: self.shared.clone(),
            deadline: Some(deadline),
        }
    }

    /// When the caller drops this call, if it said: a module that tries several servers in turn
    /// fits its per-server timeouts into the time left (providers.md §5 `dns` "Transport").
    pub fn deadline(&self) -> Option<tokio::time::Instant> {
        self.deadline
    }

    /// The lookup provider's id (not the module id).
    pub fn provider_id(&self) -> &str {
        &self.shared.provider_id
    }

    /// The provider's HTTP/2 client.
    pub fn http(&self) -> &dyn HttpClient {
        &*self.shared.http
    }

    /// The provider's DNS server client.
    pub fn dns(&self) -> &dyn DnsServerClient {
        &*self.shared.dns
    }

    /// Wall-clock now.
    pub fn now(&self) -> Timestamp {
        self.shared.clock.now()
    }

    /// Cancelled when the provider's client is dropped (no profile attaches it any more).
    pub fn cancelled(&self) -> &CancellationToken {
        &self.shared.cancel
    }

    /// Per-provider state a module keeps (e.g. which `dns` servers failed recently), one value
    /// per type, created on first use. It lives as long as this context: a config change
    /// starts over.
    pub fn state<T: Default + Send + Sync + 'static>(&self) -> Arc<T> {
        let mut map = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        let entry = map
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Arc::new(T::default()) as Arc<dyn Any + Send + Sync>);
        match Arc::clone(entry).downcast::<T>() {
            Ok(v) => v,
            // Unreachable: the key is T's TypeId. Replace rather than panic.
            Err(_) => {
                let v = Arc::new(T::default());
                *entry = v.clone();
                v
            }
        }
    }

    /// The config parsed as `T`, kept until the config changes, so a module doesn't
    /// deserialise (and re-validate) its config on every call. The parse error's message is
    /// redacted by the `LookupClient` before it goes anywhere.
    pub fn parsed<T>(&self, cfg: &serde_json::Value) -> Result<Arc<T>, serde_json::Error>
    where
        T: DeserializeOwned + Send + Sync + 'static,
    {
        let slot = self.state::<ParsedSlot<T>>();
        let mut guard = slot.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((raw, parsed)) = guard.as_ref()
            && raw == cfg
        {
            return Ok(parsed.clone());
        }
        let parsed = Arc::new(T::deserialize(cfg)?);
        *guard = Some((cfg.clone(), parsed.clone()));
        Ok(parsed)
    }
}

struct ParsedSlot<T>(Mutex<Option<(serde_json::Value, Arc<T>)>>);

impl<T> Default for ParsedSlot<T> {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// README §2 Secrets: `{:?}` of a request prints no resolved secret.
    #[test]
    fn http_request_debug_leaves_secrets_out() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-api-key", http::HeaderValue::from_static("SECRET3"));
        let r = HttpRequest {
            method: http::Method::GET,
            url: url::Url::parse("https://u:SECRET1@api.example/v1/domain/x?key=SECRET2").unwrap(),
            headers,
            body: Some(b"SECRET4".to_vec()),
            timeout: Duration::from_secs(1),
            max_body: 10,
        };
        let text = format!("{r:?}");
        for leak in ["SECRET1", "SECRET2", "SECRET3", "SECRET4"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        assert!(
            text.contains("https://api.example/v1/domain/x") && text.contains("x-api-key"),
            "{text}"
        );
    }

    /// README §2 Secrets: a resolved secret in a URL's host or path (a Spamhaus-DQS-style host
    /// label, an IPQS-style path segment) is redacted from `{:?}` too, as are header and query
    /// values.
    #[test]
    fn http_request_debug_redacts_secrets_in_host_and_path() {
        let secrets: std::collections::BTreeMap<String, String> = [
            ("dqs", "dqskeyhost4711"),
            ("ipqs", "ipqspathkey0815"),
            ("hdr", "headervalue9999"),
            ("q", "queryvalue12345"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let cfg = serde_json::json!({
            "url": "https://${secret:dqs}.zen.example/url/${secret:ipqs}/x?key=${secret:q}",
            "headers": {"x-key": "${secret:hdr}"},
        });
        let r = crate::secrets::resolve(&cfg, &secrets).unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-key",
            http::HeaderValue::from_str(r.config["headers"]["x-key"].as_str().unwrap()).unwrap(),
        );
        let req = HttpRequest {
            method: http::Method::GET,
            url: url::Url::parse(r.config["url"].as_str().unwrap()).unwrap(),
            headers,
            body: None,
            timeout: Duration::from_secs(1),
            max_body: 10,
        };
        for text in [format!("{req:?}"), format!("{req:#?}")] {
            for v in secrets.values() {
                assert!(!text.contains(v.as_str()), "{v} in {text}");
            }
            assert!(
                text.contains("${secret:dqs}.zen.example/url/${secret:ipqs}/x"),
                "{text}"
            );
        }
    }
}
