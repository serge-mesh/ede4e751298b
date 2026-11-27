//! The edge API client (api.md §2): REST over hyper 1 (HTTP/1.1) and the WebSocket session, both
//! over TLS 1.3 with core's key pinned and the edge identity as client certificate (api.md §1).
//!
//! - `GET /objects/<key>` with `If-None-Match` (304 handling), bounded in size and time; objects
//!   that go to disk stream into a temporary file, verified against their BLAKE3 before they are
//!   renamed into place.
//! - `POST /v1/logs` with a gzip JSONL body (`Content-Encoding: gzip`): 200 = ack, 400/413 = the
//!   batch is unreadable (split it), anything else is retried.
//! - `POST /v1/csr`: managed listener certificates ([`crate::dns::certs`]).
//! - Every call has a timeout, and every reply body an overall deadline as well as an idle one;
//!   idle HTTP/1.1 connections are reused (at most a few).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use picket_api::edge_api::{CsrRequest, CsrResponse, paths};

use crate::identity::Identity;
use crate::local_config::CoreUrl;
use crate::logs::shipper::{LogSink, PostOutcome};
use crate::tls::{self, CoreVerifier};

/// Largest WebSocket message accepted from core.
pub const MAX_WS_MESSAGE: usize = 1 << 20;
/// Idle connections kept for reuse.
const POOL_MAX: usize = 4;
/// Largest JSON reply body (log acks, CSR replies, errors).
const MAX_SMALL_BODY: u64 = 1 << 20;

/// Timeouts for every external call.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// TCP connect + TLS handshake.
    pub connect: Duration,
    /// From sending a request to its response head.
    pub response: Duration,
    /// Between body chunks.
    pub body_idle: Duration,
    /// A whole reply read into memory (config objects, log acks, CSR replies), however steadily
    /// its bytes arrive.
    pub body_total: Duration,
    /// A whole download.
    pub download: Duration,
    /// The WebSocket upgrade.
    pub ws_handshake: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            response: Duration::from_secs(30),
            body_idle: Duration::from_secs(30),
            body_total: Duration::from_secs(120),
            download: Duration::from_secs(1800),
            ws_handshake: Duration::from_secs(15),
        }
    }
}

/// Why a call to core failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// No answer: connect, TLS or a timeout.
    #[error("core unreachable: {0}")]
    Unreachable(String),
    /// Core presented another key than the pinned one (api.md §1 Key change).
    #[error("core presented key {presented}, not the pinned core_key; refusing the connection")]
    KeyMismatch { presented: String },
    /// 403: another edge's config, or this edge's key isn't approved on core yet.
    #[error("core refused (403): this edge's key may not be approved yet")]
    Forbidden,
    #[error("not found (404)")]
    NotFound,
    #[error("HTTP {0}")]
    Status(u16),
    /// A reply that broke a limit or failed verification.
    #[error("invalid reply: {0}")]
    Invalid(String),
    #[error("local I/O: {0}")]
    Io(String),
}

/// A `GET /objects/<key>` result.
#[derive(Debug)]
pub enum ObjectReply {
    NotModified,
    Body {
        bytes: Bytes,
        /// The `ETag` header without quotes, when present.
        etag: Option<String>,
    },
}

/// The live WebSocket stream type.
pub type WsStream = WebSocketStream<TlsStream<TcpStream>>;

/// A client for one core.
pub struct CoreClient {
    url: CoreUrl,
    tls: Arc<rustls::ClientConfig>,
    verifier: Arc<CoreVerifier>,
    idle: Mutex<Vec<SendRequest<Full<Bytes>>>>,
    pub timeouts: Timeouts,
}

impl CoreClient {
    /// A client pinned to `core_key`.
    pub fn new(url: CoreUrl, id: &Identity, core_key: &str) -> anyhow::Result<Self> {
        let verifier = CoreVerifier::pinned(core_key)?;
        let tls = tls::client_config(id, Arc::clone(&verifier))?;
        Ok(Self {
            url,
            tls,
            verifier,
            idle: Mutex::new(Vec::new()),
            timeouts: Timeouts::default(),
        })
    }

    pub fn url(&self) -> &CoreUrl {
        &self.url
    }

    async fn connect_tls(&self) -> Result<TlsStream<TcpStream>, ClientError> {
        match tls::connect(self.url.addr, Arc::clone(&self.tls), self.timeouts.connect).await {
            Ok(s) => Ok(s),
            Err(e) => {
                if tls::is_pin_mismatch(&e) {
                    let presented = self
                        .verifier
                        .last_mismatch()
                        .unwrap_or_else(|| "(unknown)".into());
                    return Err(ClientError::KeyMismatch { presented });
                }
                Err(ClientError::Unreachable(crate::diag::cap_chain(&e)))
            }
        }
    }

    async fn new_sender(&self) -> Result<SendRequest<Full<Bytes>>, ClientError> {
        let tls = self.connect_tls().await?;
        let (sender, conn) = tokio::time::timeout(
            self.timeouts.connect,
            hyper::client::conn::http1::handshake(TokioIo::new(tls)),
        )
        .await
        .map_err(|_| ClientError::Unreachable("HTTP handshake timed out".into()))?
        .map_err(|e| ClientError::Unreachable(crate::diag::cap(e)))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }

    fn pooled(&self) -> Option<SendRequest<Full<Bytes>>> {
        let mut idle = self.idle.lock().unwrap_or_else(|p| p.into_inner());
        while let Some(s) = idle.pop() {
            if !s.is_closed() && s.is_ready() {
                return Some(s);
            }
        }
        None
    }

    fn give_back(&self, s: SendRequest<Full<Bytes>>) {
        if s.is_closed() {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(|p| p.into_inner());
        if idle.len() < POOL_MAX {
            idle.push(s);
        }
    }

    /// Sends a request; a failure on a reused connection is retried once on a fresh one (the
    /// edge's calls are idempotent: GETs, and log batches core deduplicates).
    async fn send(
        &self,
        build: impl Fn() -> Request<Full<Bytes>>,
    ) -> Result<(hyper::Response<Incoming>, SendRequest<Full<Bytes>>), ClientError> {
        if let Some(mut s) = self.pooled() {
            // A stale connection falls through to a fresh one.
            if let Ok(Ok(resp)) = tokio::time::timeout(self.timeouts.response, s.send_request(build())).await
            {
                return Ok((resp, s));
            }
        }
        let mut s = self.new_sender().await?;
        match tokio::time::timeout(self.timeouts.response, s.send_request(build())).await {
            Ok(Ok(resp)) => Ok((resp, s)),
            Ok(Err(e)) => Err(ClientError::Unreachable(crate::diag::cap(e))),
            Err(_) => Err(ClientError::Unreachable("no response in time".into())),
        }
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        body: Bytes,
        extra: &[(header::HeaderName, &str)],
    ) -> Request<Full<Bytes>> {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, self.url.authority())
            .header(
                header::USER_AGENT,
                concat!("picket-edge/", env!("CARGO_PKG_VERSION")),
            );
        for (k, v) in extra {
            b = b.header(k, *v);
        }
        b.body(Full::new(body))
            .unwrap_or_else(|_| Request::new(Full::new(Bytes::new())))
    }

    /// `GET /objects/<key>` into memory, at most `max` bytes. With `if_none_match`, a 304 is
    /// [`ObjectReply::NotModified`].
    pub async fn get_object(
        &self,
        key: &str,
        if_none_match: Option<&str>,
        max: u64,
    ) -> Result<ObjectReply, ClientError> {
        check_key(key)?;
        let path = format!("{}{key}", paths::OBJECTS);
        let inm = if_none_match.map(|e| format!("\"{e}\""));
        let (resp, sender) = self
            .send(|| {
                let extra: Vec<(header::HeaderName, &str)> = inm
                    .as_deref()
                    .map(|v| (header::IF_NONE_MATCH, v))
                    .into_iter()
                    .collect();
                self.request(Method::GET, &path, Bytes::new(), &extra)
            })
            .await?;
        match resp.status() {
            StatusCode::NOT_MODIFIED => {
                let _ = read_body(
                    resp.into_body(),
                    0,
                    self.timeouts.body_idle,
                    self.timeouts.body_total,
                )
                .await;
                self.give_back(sender);
                Ok(ObjectReply::NotModified)
            }
            StatusCode::OK => {
                if content_length(&resp).is_some_and(|l| l > max) {
                    return Err(ClientError::Invalid(format!("object {key} is over {max} bytes")));
                }
                let etag = resp
                    .headers()
                    .get(header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.trim().trim_start_matches("W/").trim_matches('"').to_owned());
                let bytes = read_body(
                    resp.into_body(),
                    max,
                    self.timeouts.body_idle,
                    self.timeouts.body_total,
                )
                .await?;
                self.give_back(sender);
                Ok(ObjectReply::Body { bytes, etag })
            }
            s => Err(status_error(s)),
        }
    }

    /// Streams `GET /objects/<key>` into `dir/<expected_blake3>` (tmp → fsync → rename), at most
    /// `max` bytes, verifying the BLAKE3 before the rename. For page files and release tarballs,
    /// which are never read into memory.
    pub async fn download_object(
        &self,
        key: &str,
        dir: &Path,
        expected_blake3: &str,
        max: u64,
    ) -> Result<PathBuf, ClientError> {
        check_key(key)?;
        if !picket_api::ids::is_object_id(expected_blake3) {
            return Err(ClientError::Invalid("expected id isn't a BLAKE3 id".into()));
        }
        let path = format!("{}{key}", paths::OBJECTS);
        let (resp, sender) = self
            .send(|| self.request(Method::GET, &path, Bytes::new(), &[]))
            .await?;
        if resp.status() != StatusCode::OK {
            return Err(status_error(resp.status()));
        }
        if content_length(&resp).is_some_and(|l| l > max) {
            return Err(ClientError::Invalid(format!("object {key} is over {max} bytes")));
        }
        let final_path = dir.join(expected_blake3);
        let tmp_path = dir.join(crate::fsutil::tmp_name(expected_blake3));
        let result = tokio::time::timeout(self.timeouts.download, async {
            let mut f = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o640)
                .open(&tmp_path)
                .await
                .map_err(|e| ClientError::Io(crate::diag::cap(e)))?;
            let mut hasher = blake3::Hasher::new();
            let mut total = 0u64;
            let mut body = resp.into_body();
            loop {
                let frame = tokio::time::timeout(self.timeouts.body_idle, body.frame())
                    .await
                    .map_err(|_| ClientError::Unreachable("download stalled".into()))?;
                let Some(frame) = frame else { break };
                let frame = frame.map_err(|e| ClientError::Unreachable(crate::diag::cap(e)))?;
                if let Some(chunk) = frame.data_ref() {
                    total += chunk.len() as u64;
                    if total > max {
                        return Err(ClientError::Invalid(format!("object {key} is over {max} bytes")));
                    }
                    hasher.update(chunk);
                    f.write_all(chunk)
                        .await
                        .map_err(|e| ClientError::Io(crate::diag::cap(e)))?;
                }
            }
            f.sync_all()
                .await
                .map_err(|e| ClientError::Io(crate::diag::cap(e)))?;
            let got = hasher.finalize().to_hex().to_string();
            if got != expected_blake3 {
                return Err(ClientError::Invalid(format!("blake3 mismatch for {key}")));
            }
            tokio::fs::rename(&tmp_path, &final_path)
                .await
                .map_err(|e| ClientError::Io(crate::diag::cap(e)))?;
            crate::fsutil::fsync_dir(dir).map_err(|e| ClientError::Io(crate::diag::cap(e)))?;
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err(ClientError::Unreachable("download timed out".into())));
        match result {
            Ok(()) => {
                self.give_back(sender);
                Ok(final_path)
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                Err(e)
            }
        }
    }

    /// `POST /v1/logs`.
    pub async fn post_logs(&self, gz_body: Bytes) -> PostOutcome {
        let res = self
            .send(|| {
                self.request(
                    Method::POST,
                    paths::LOGS,
                    gz_body.clone(),
                    &[
                        (header::CONTENT_TYPE, "application/jsonl"),
                        (header::CONTENT_ENCODING, "gzip"),
                    ],
                )
            })
            .await;
        let (resp, sender) = match res {
            Ok(r) => r,
            Err(e) => return PostOutcome::Unreachable(e.to_string()),
        };
        let status = resp.status();
        let body = read_body(
            resp.into_body(),
            MAX_SMALL_BODY,
            self.timeouts.body_idle,
            self.timeouts.body_total,
        )
        .await;
        if body.is_ok() {
            self.give_back(sender);
        }
        match status {
            StatusCode::OK => match body {
                Ok(_) => PostOutcome::Acked,
                // The ack didn't arrive whole: retry (core deduplicates).
                Err(e) => PostOutcome::Unreachable(e.to_string()),
            },
            StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE => PostOutcome::Rejected,
            s => PostOutcome::Retry(format!("HTTP {}", s.as_u16())),
        }
    }

    /// `POST /v1/csr`: core signs a managed listener's key (api.md §2 CSR).
    pub async fn post_csr(&self, req: &CsrRequest) -> Result<CsrResponse, ClientError> {
        let body =
            Bytes::from(serde_json::to_vec(req).map_err(|e| ClientError::Invalid(crate::diag::cap(e)))?);
        let (resp, sender) = self
            .send(|| {
                self.request(
                    Method::POST,
                    paths::CSR,
                    body.clone(),
                    &[(header::CONTENT_TYPE, "application/json")],
                )
            })
            .await?;
        let status = resp.status();
        if status != StatusCode::OK {
            return Err(status_error(status));
        }
        let bytes = read_body(
            resp.into_body(),
            MAX_SMALL_BODY,
            self.timeouts.body_idle,
            self.timeouts.body_total,
        )
        .await?;
        self.give_back(sender);
        serde_json::from_slice(&bytes).map_err(|e| ClientError::Invalid(crate::diag::cap(e)))
    }

    /// Opens the WebSocket session (`GET /v1/session` upgrade) over a fresh pinned connection.
    pub async fn connect_session(&self) -> Result<WsStream, ClientError> {
        let tls = self.connect_tls().await?;
        let mut req = format!("wss://{}{}", self.url.authority(), paths::SESSION)
            .into_client_request()
            .map_err(|e| ClientError::Invalid(crate::diag::cap(e)))?;
        if let Ok(v) = concat!("picket-edge/", env!("CARGO_PKG_VERSION")).parse() {
            req.headers_mut().insert(header::USER_AGENT, v);
        }
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_WS_MESSAGE))
            .max_frame_size(Some(MAX_WS_MESSAGE));
        let (ws, _resp) = tokio::time::timeout(
            self.timeouts.ws_handshake,
            tokio_tungstenite::client_async_with_config(req, tls, Some(config)),
        )
        .await
        .map_err(|_| ClientError::Unreachable("WebSocket upgrade timed out".into()))?
        .map_err(|e| match e {
            tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == StatusCode::FORBIDDEN => {
                ClientError::Forbidden
            }
            tokio_tungstenite::tungstenite::Error::Http(r) => ClientError::Status(r.status().as_u16()),
            e => ClientError::Unreachable(crate::diag::cap(e)),
        })?;
        Ok(ws)
    }
}

#[async_trait::async_trait]
impl LogSink for CoreClient {
    async fn post(&self, gz_body: Bytes) -> PostOutcome {
        self.post_logs(gz_body).await
    }
}

fn content_length<B>(r: &hyper::Response<B>) -> Option<u64> {
    r.headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

fn status_error(s: StatusCode) -> ClientError {
    match s {
        StatusCode::FORBIDDEN => ClientError::Forbidden,
        StatusCode::NOT_FOUND => ClientError::NotFound,
        s => ClientError::Status(s.as_u16()),
    }
}

/// Reads a body of at most `max` bytes, with an idle timeout between chunks and an overall
/// deadline (README §2 Bounded: a core dripping one byte per idle period can't hold a reply, and
/// with it convergence or log shipping, open indefinitely).
async fn read_body<B>(mut body: B, max: u64, idle: Duration, total: Duration) -> Result<Bytes, ClientError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let deadline = tokio::time::Instant::now() + total;
    let mut buf = bytes::BytesMut::new();
    loop {
        let frame = tokio::time::timeout_at(deadline.min(tokio::time::Instant::now() + idle), body.frame())
            .await
            .map_err(|_| ClientError::Unreachable("reply stalled or too slow".into()))?;
        let Some(frame) = frame else { break };
        let frame = frame.map_err(|e| ClientError::Unreachable(crate::diag::cap(e)))?;
        if let Some(chunk) = frame.data_ref() {
            if (buf.len() + chunk.len()) as u64 > max {
                return Err(ClientError::Invalid(format!("reply over {max} bytes")));
            }
            buf.extend_from_slice(chunk);
        }
    }
    Ok(buf.freeze())
}

/// Object keys come from core's config object: only path-safe characters, no `..` segments.
fn check_key(key: &str) -> Result<(), ClientError> {
    let ok = !key.is_empty()
        && key.len() <= 512
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
        && key
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..");
    if ok {
        Ok(())
    } else {
        Err(ClientError::Invalid(format!(
            "unsafe object key {:?}",
            crate::diag::cap(key)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_dripping_reply_hits_the_overall_deadline() {
        // README §2 Bounded (every external call has a timeout): a core that sends one byte just
        // before each idle timeout must not hold a reply open indefinitely.
        let drip = futures_util::stream::unfold((), |()| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some((
                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(Bytes::from_static(b"x"))),
                (),
            ))
        });
        let body = http_body_util::StreamBody::new(Box::pin(drip));
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            read_body(
                body,
                1 << 20,
                Duration::from_millis(500),
                Duration::from_millis(300),
            ),
        )
        .await
        .expect("read_body gives up on its own");
        assert!(matches!(r, Err(ClientError::Unreachable(_))), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn object_keys_are_checked() {
        assert!(check_key("configs/abc_-.json").is_ok());
        assert!(check_key("bundles/block-common/heads/0123.json").is_ok());
        for bad in ["", "../x", "a//b", "a/./b", "a b", "a%2f", "a?x=1"] {
            assert!(check_key(bad).is_err(), "{bad}");
        }
    }
}
