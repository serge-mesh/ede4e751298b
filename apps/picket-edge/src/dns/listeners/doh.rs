//! DoH listeners (edge.md §5; RFC 8484): hyper 1 serving h2 and http/1.1 over TLS 1.3 (refusals
//! reported: [`super::handshake`]).
//!
//! - Paths `/dns-query` and `/dns-query/<profile id>`; GET with `?dns=` (base64url) and POST
//!   with `application/dns-message`.
//! - `Cache-Control: private, max-age=<the minimum TTL>`, or `no-store` on a reply to a query with
//!   `X-Picket-Client: extension`.
//! - A profile named in the path that doesn't exist or doesn't admit the client: HTTP 403 with
//!   the body `profile not permitted from this address`.
//! - Bounds (README §2 "Bounded", edge.md §16, §17): `max_connections` per listener and the
//!   per-source share ([`super::share`]), taken at `accept` (TLS handshakes count); at most
//!   [`MAX_STREAMS`] concurrent requests per connection, and small HTTP/2 receive windows, so a
//!   client can't make the edge buffer more than a window of unread body data per stream and
//!   per connection; a connection that completed no request for `idle_timeout_ms` (trickled
//!   bytes don't count) is shut down gracefully.
//! - **POST bodies** are read only after the device's limits admitted the query, each charged to
//!   its source's and the total body budget while it is read ([`super::share`]); a body over the
//!   DNS maximum gets 413, one that doesn't fit the budget 503, one not finished within
//!   [`BODY_TIMEOUT`] 408. A device over its limits (edge.md §16) gets 429 at once, its body never
//!   read: the DNS message a REFUSED would echo is in that body, and reading it would let a
//!   stalled over-limit body hold a stream and budget until the timeout (policy choice, flagged
//!   for the owner). A GET carries its message in the URL and gets REFUSED as on every transport.
//! - `api: true` listeners also serve the bypass API at `/v1/temporary-allows` (edge.md §12,
//!   api.md §6; [`crate::bypass`]).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

use anyhow::Result;
use base64::Engine as _;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;

use picket_api::logs::Proto;

use super::SharedSpec;
use super::stream::{HANDSHAKE_TIMEOUT, admit_conn};
use crate::dns::pipeline::{self, Admitted, Inbound};
use crate::dns::upstream::doh::DNS_MESSAGE;
use crate::edge::Edge;

pub const PATH: &str = "/dns-query";
/// The body of a 403 for a refused named profile (edge.md §4 EDE table).
pub const REFUSED_BODY: &str = "profile not permitted from this address";
/// Largest DNS message accepted (RFC 8484 §6: the DNS maximum).
const MAX_MSG: usize = picket_wire::MAX_MESSAGE;
/// Concurrent requests per HTTP/2 connection (clients queue the rest; policy choice).
pub const MAX_STREAMS: u32 = 32;
/// HTTP/2 receive windows: one DNS message per stream, a few per connection.
const STREAM_WINDOW: u32 = 65_535;
const CONN_WINDOW: u32 = 256 << 10;
const MAX_HEADER_BYTES: usize = 16 << 10;
/// A POST body must arrive within this.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection's request activity, for the idle shutdown: requests in flight and when the last
/// one finished.
struct Activity {
    base: Instant,
    last: AtomicU64,
    inflight: AtomicUsize,
}

impl Activity {
    fn quiet(&self) -> Option<Duration> {
        if self.inflight.load(Relaxed) > 0 {
            return None;
        }
        let now = picket_api::duration::as_millis_u64(self.base.elapsed());
        Some(Duration::from_millis(now.saturating_sub(self.last.load(Relaxed))))
    }
}

/// One request in flight; its end (however it ends) is progress.
struct InFlight(Arc<Activity>);

impl InFlight {
    fn new(a: &Arc<Activity>) -> Self {
        a.inflight.fetch_add(1, Relaxed);
        Self(Arc::clone(a))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.last.store(
            picket_api::duration::as_millis_u64(self.0.base.elapsed()),
            Relaxed,
        );
        self.0.inflight.fetch_sub(1, Relaxed);
    }
}

pub fn spawn(
    edge: Arc<Edge>,
    l: std::net::TcpListener,
    spec: SharedSpec,
    mut shutdown: watch::Receiver<bool>,
    tls: Arc<rustls::ServerConfig>,
    live: Arc<super::Live>,
) -> Result<tokio::task::JoinHandle<()>> {
    let l = TcpListener::from_std(l)?;
    Ok(tokio::spawn(async move {
        let count = Arc::new(AtomicUsize::new(0));
        // The watchdog's liveness mark (edge.md §16): the first tick is at once. Not stamped
        // while the last accept failed for want of descriptors or memory (the connection waits
        // in the backlog and the next try repeats it), so lasting exhaustion fails the test.
        let mut tick = live.interval();
        let mut exhausted = false;
        loop {
            live.park_if_stalled().await;
            let (tcp, peer) = tokio::select! {
                _ = shutdown.changed() => return,
                _ = tick.tick() => {
                    if !exhausted {
                        live.stamp();
                    }
                    continue;
                }
                r = l.accept() => match r {
                    Ok(x) => {
                        exhausted = false;
                        x
                    }
                    Err(e) => {
                        exhausted = super::out_of_resources(&e);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                },
            };
            let Some(guards) = admit_conn(&edge, &spec, &count, &tcp, peer) else {
                continue;
            };
            let edge = Arc::clone(&edge);
            let cfg = Arc::clone(&tls);
            let spec = Arc::clone(&spec);
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let _guards = guards;
                let id = Arc::clone(&spec.load().id);
                let transport = super::handshake::Transport::Doh;
                let Some(tls) =
                    super::handshake::accept(&edge, &cfg, tcp, peer, &id, transport, HANDSHAKE_TIMEOUT).await
                else {
                    return;
                };
                serve_conn(edge, tls, peer, spec, shutdown).await;
            });
        }
    }))
}

async fn serve_conn<S>(
    edge: Arc<Edge>,
    io: S,
    peer: SocketAddr,
    spec: SharedSpec,
    mut shutdown: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let activity = Arc::new(Activity {
        base: Instant::now(),
        last: AtomicU64::new(0),
        inflight: AtomicUsize::new(0),
    });
    let svc = {
        let edge = Arc::clone(&edge);
        let spec = Arc::clone(&spec);
        let activity = Arc::clone(&activity);
        service_fn(move |req: Request<Incoming>| {
            let edge = Arc::clone(&edge);
            let spec = Arc::clone(&spec);
            let busy = InFlight::new(&activity);
            async move {
                let _busy = busy;
                Ok::<_, Infallible>(handle(&edge, req, peer, &spec).await)
            }
        })
    };
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(MAX_MSG + MAX_HEADER_BYTES)
        .max_headers(64);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(MAX_STREAMS)
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .adaptive_window(false)
        .max_header_list_size(u32::try_from(MAX_HEADER_BYTES).unwrap_or(u32::MAX))
        .max_pending_accept_reset_streams(Some(64));
    let conn = builder.serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    let idle = Duration::from_millis(u64::from(spec.load().limits.idle_timeout_ms));
    let mut tick = tokio::time::interval(Duration::from_millis(250).min(idle));
    let mut closing = false;
    loop {
        tokio::select! {
            _ = conn.as_mut() => return,
            _ = tick.tick(), if !closing => {
                // Idle: no request in flight, and none finished for the idle timeout.
                if activity.quiet().is_some_and(|q| q >= idle) {
                    conn.as_mut().graceful_shutdown();
                    closing = true;
                }
            }
            _ = shutdown.changed(), if !closing => {
                conn.as_mut().graceful_shutdown();
                closing = true;
            }
        }
        if closing {
            let _ = tokio::time::timeout(Duration::from_secs(10), conn.as_mut()).await;
            return;
        }
    }
}

fn status(code: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *r.status_mut() = code;
    if !body.is_empty() {
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
    r
}

/// What a request path names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DohPath<'a> {
    /// `/dns-query`: no profile named.
    Default,
    /// `/dns-query/<profile id>`.
    Profile(&'a str),
    /// Any other path.
    NotFound,
}

/// The profile a path names (edge.md §5).
pub fn path_profile(path: &str) -> DohPath<'_> {
    if path == PATH || path == "/dns-query/" {
        return DohPath::Default;
    }
    match path.strip_prefix("/dns-query/") {
        Some(p) if !p.is_empty() && !p.contains('/') && p.len() <= 63 => DohPath::Profile(p),
        _ => DohPath::NotFound,
    }
}

/// The `dns` parameter of a GET query string, decoded (base64url, padding optional).
pub fn get_param(query: Option<&str>) -> Option<Vec<u8>> {
    let q = query?;
    let v = q.split('&').find_map(|kv| kv.strip_prefix("dns="))?;
    if v.len() > MAX_MSG.div_ceil(3) * 4 + 4 {
        return None;
    }
    let v = v.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v).ok()
}

async fn handle(
    edge: &Arc<Edge>,
    req: Request<Incoming>,
    peer: SocketAddr,
    spec: &SharedSpec,
) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_owned();
    if path == crate::bypass::PATH {
        if !spec.load().api {
            return status(StatusCode::NOT_FOUND, "");
        }
        let b = std::sync::Arc::clone(&edge.bypass);
        return b.handle_http(edge, req, peer).await;
    }
    let named = match path_profile(&path) {
        DohPath::Default => None,
        DohPath::Profile(p) => Some(p.to_owned()),
        DohPath::NotFound => return status(StatusCode::NOT_FOUND, ""),
    };
    let extension = req
        .headers()
        .get("x-picket-client")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"extension"));
    let mut slot = None;
    let mut admitted = Admitted::Here;
    let msg = match *req.method() {
        Method::GET => match get_param(req.uri().query()) {
            Some(m) => m,
            None => return status(StatusCode::BAD_REQUEST, "missing or malformed dns parameter"),
        },
        Method::POST => {
            let ct_ok = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|t| t.trim().eq_ignore_ascii_case(DNS_MESSAGE))
                });
            if !ct_ok {
                return status(StatusCode::UNSUPPORTED_MEDIA_TYPE, "");
            }
            // The device's limits apply before its body is read (edge.md §16): over them, the
            // request is refused at once and its body never read.
            match pipeline::admit_early(edge, peer) {
                Ok(Some(s)) => {
                    slot = Some(s);
                    admitted = Admitted::Held;
                }
                Ok(None) => {}
                Err(_) => {
                    edge.metrics.rejected.fetch_add(1, Relaxed);
                    let mut r = status(StatusCode::TOO_MANY_REQUESTS, "");
                    r.headers_mut()
                        .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
                    return r;
                }
            }
            match read_body(edge, req, peer).await {
                Ok(m) => m,
                Err(code) => return status(code, ""),
            }
        }
        _ => {
            let mut r = status(StatusCode::METHOD_NOT_ALLOWED, "");
            r.headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static("GET, POST"));
            return r;
        }
    };
    let sp = spec.load_full();
    let out = pipeline::serve(
        edge,
        Inbound {
            msg: &msg,
            client: peer,
            listener: &sp.id,
            udp_payload: sp.limits.udp_payload,
            proto: Proto::Doh,
            named_profile: named.as_deref(),
            extension,
            internal: false,
            admitted,
        },
    )
    .await;
    drop(slot);
    if out.named_refused {
        return status(StatusCode::FORBIDDEN, REFUSED_BODY);
    }
    let Some(reply) = out.reply else {
        return status(StatusCode::BAD_REQUEST, "");
    };
    let cc = if extension {
        "no-store".to_owned()
    } else {
        format!("private, max-age={}", out.min_ttl.unwrap_or(0))
    };
    let mut r = Response::new(Full::new(Bytes::from(reply)));
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(DNS_MESSAGE),
    );
    if let Ok(v) = header::HeaderValue::from_str(&cc) {
        h.insert(header::CACHE_CONTROL, v);
    }
    r
}

/// Reads a POST body (at most the DNS maximum, within [`BODY_TIMEOUT`]), charging it to the
/// source's and the total body budget while it is read.
async fn read_body(edge: &Edge, req: Request<Incoming>, peer: SocketAddr) -> Result<Vec<u8>, StatusCode> {
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_MSG as u64) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let key = super::share::source_key(edge, peer.ip());
    let mut charge = edge.dns.listeners.shares.body(key);
    let mut msg = match declared {
        Some(n) => {
            let n = usize::try_from(n).unwrap_or(usize::MAX);
            // The declared size is charged at once; the body may not be longer.
            if !charge.add(n) {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            Vec::with_capacity(n)
        }
        None => Vec::new(),
    };
    let mut body = req.into_body();
    let deadline = tokio::time::Instant::now() + BODY_TIMEOUT;
    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => return Err(StatusCode::REQUEST_TIMEOUT),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(StatusCode::BAD_REQUEST),
            Ok(Some(Ok(f))) => f,
        };
        let Ok(data) = frame.into_data() else { continue };
        let len = msg.len().saturating_add(data.len());
        if len > MAX_MSG || declared.is_some_and(|n| len as u64 > n) {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        if declared.is_none() && !charge.add(data.len()) {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        msg.extend_from_slice(&data);
    }
    drop(charge);
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_params() {
        assert_eq!(path_profile("/dns-query"), DohPath::Default);
        assert_eq!(path_profile("/dns-query/kids"), DohPath::Profile("kids"));
        assert_eq!(path_profile("/dns-query/a/b"), DohPath::NotFound);
        assert_eq!(path_profile("/other"), DohPath::NotFound);
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xfb, 0xff, 1]);
        assert_eq!(
            get_param(Some(&format!("x=1&dns={b}"))),
            Some(vec![0xfb, 0xff, 1])
        );
        assert_eq!(get_param(Some("dns=%%%")), None);
        assert_eq!(get_param(None), None);
    }
}
