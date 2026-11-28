//! `POST /v1/logs` and `POST /v1/csr` (api.md §2). Errors are `{"error": {"code", "message"}}`
//! with the matching status.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use axum::Extension;
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use picket_api::edge_api::{CsrRequest, CsrResponse, ErrorBody};
use picket_api::logs::LogsAck;

use super::EdgePeer;
use crate::lanca::SignError;
use crate::logs::IngestError;
use crate::state::SharedState;

/// How long a log batch's body may take to arrive (README §2, Bounded: a slow client can't
/// hold an ingest slot).
pub const BODY_DEADLINE: Duration = Duration::from_secs(60);
/// Largest CSR request body.
pub const MAX_CSR_BODY: usize = 64 << 10;
/// CSRs one edge may have signed per window (signing costs CPU; an edge needs one per managed
/// listener and renews them after 265 days).
pub const CSR_PER_WINDOW: u32 = 30;
pub const CSR_WINDOW: Duration = Duration::from_secs(600);

/// An error with the API's body shape.
pub fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (status, Json(ErrorBody::new(code, message))).into_response()
}

/// `POST /v1/logs`: a gzip JSONL batch → `200 {"acked": {"boot", "seq"}}` once it is durable;
/// `400`/`413` for a batch core can't read at all (the edge splits it); `503` to retry.
pub async fn logs(
    State(state): State<SharedState>,
    Extension(peer): Extension<EdgePeer>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let limits = crate::logs::decode::LIMITS;
    let gzip = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("gzip"));
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > DRAIN_MAX as u64) {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "the batch is too large",
        );
    }
    // The edge's one batch in progress, before its body is read (README §2, Bounded): an edge
    // holds at most one body in memory however many connections or streams it opens.
    let slot = match state.logs.admit(&peer.edge_id).await {
        Ok(s) => s,
        Err(e) => return unavailable(&peer.edge_id, &e),
    };
    let bytes = match tokio::time::timeout(BODY_DEADLINE, read_capped(body, limits.max_body)).await {
        Err(_) => {
            return error(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "the batch arrived too slowly",
            );
        }
        Ok(Err(BodyError::TooLarge)) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "the batch is too large",
            );
        }
        Ok(Err(BodyError::Unreadable)) => {
            return error(
                StatusCode::BAD_REQUEST,
                "bad_body",
                "the batch body couldn't be read",
            );
        }
        Ok(Ok(b)) => b,
    };
    // A config restore is emptying the log partitions of pre-restore records (core.md §2): a
    // batch stored now would go with them after its ack, so it waits in the edge's spool and
    // comes again once they are gone. This early answer saves decoding it; the check that
    // counts is the log writer's, ordered with the deletions (a batch past this point when the
    // restore commits is refused there: `LogWriter::write_unless`).
    if state.restore.logs_pending() {
        let mut r = error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "a config restore is emptying the logs; retry later",
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return r;
    }
    match state
        .logs
        .ingest(&state, slot, &peer.edge_id, &peer.fingerprint, bytes, gzip)
        .await
    {
        Ok(report) => (StatusCode::OK, Json(LogsAck { acked: report.ack })).into_response(),
        // api.md §1 Key change: replaced (or the edge deleted) while the body arrived.
        Err(IngestError::KeyGone) => error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this key is no longer registered",
        ),
        Err(IngestError::Batch(e)) => {
            let status = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_REQUEST);
            error(
                status,
                if e.status() == 413 {
                    "too_large"
                } else {
                    "bad_batch"
                },
                e.to_string(),
            )
        }
        Err(e) => unavailable(&peer.edge_id, &e),
    }
}

/// `503` with `Retry-After`: the edge retries the batch.
fn unavailable(edge: &str, e: &IngestError) -> Response {
    tracing::warn!(edge = %edge, error = %e, "log batch not stored; the edge retries");
    let mut r = error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", e.to_string());
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    r
}

/// A body past the cap is still read (and dropped) up to this much, so the edge reads the `413`
/// instead of a reset connection and splits the batch (edge.md §11).
pub const DRAIN_MAX: usize = 64 << 20;

enum BodyError {
    TooLarge,
    Unreadable,
}

/// Reads a body of at most `max` bytes; past it, drains up to [`DRAIN_MAX`] and reports
/// `TooLarge`.
async fn read_capped(mut body: Body, max: usize) -> Result<bytes::Bytes, BodyError> {
    use http_body_util::BodyExt;
    let mut buf = bytes::BytesMut::new();
    let mut total = 0usize;
    let mut over = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyError::Unreadable)?;
        let Some(d) = frame.data_ref() else { continue };
        total = total.saturating_add(d.len());
        if total > DRAIN_MAX {
            return Err(BodyError::TooLarge);
        }
        if !over {
            if buf.len() + d.len() > max {
                over = true;
                buf = bytes::BytesMut::new();
            } else {
                buf.extend_from_slice(d);
            }
        }
    }
    if over {
        Err(BodyError::TooLarge)
    } else {
        Ok(buf.freeze())
    }
}

/// `503` while core's wall clock isn't synchronised: nothing is signed (README §2 Clocks).
fn clock_refusal() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "clock_unsynchronised",
        "core's clock isn't synchronised yet; retry later",
    )
}

/// Per-edge CSR admission (fixed windows).
#[derive(Default)]
pub struct CsrLimiter {
    edges: Mutex<HashMap<String, (tokio::time::Instant, u32)>>,
}

impl CsrLimiter {
    pub fn admit(&self, edge: &str) -> bool {
        let now = tokio::time::Instant::now();
        let Ok(mut m) = self.edges.lock() else {
            return false;
        };
        if m.len() > 4096 {
            m.retain(|_, (t, _)| now.duration_since(*t) < CSR_WINDOW);
        }
        let e = m.entry(edge.to_string()).or_insert((now, 0));
        if now.duration_since(e.0) >= CSR_WINDOW {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= CSR_PER_WINDOW
    }
}

/// The names and IPs a managed listener's certificate carries (edge.md §5): the name, `*.name`
/// (profile ids) and the listener's IPs inside RFC 1918 or ULA, from the listener's config,
/// never from the CSR.
pub fn listener_sans(l: &crate::config::model::ListenerDef) -> Option<(Vec<String>, Vec<std::net::IpAddr>)> {
    let name = l
        .tls
        .as_ref()?
        .managed
        .as_ref()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let mut ips = l.ips.clone();
    if ips.is_empty()
        && let Ok(sa) = l.bind.parse::<std::net::SocketAddr>()
        && !sa.ip().is_unspecified()
    {
        ips.push(sa.ip());
    }
    let mut ips: Vec<std::net::IpAddr> = ips
        .into_iter()
        .map(crate::net::canonical_ip)
        .filter(crate::net::is_lan_ip)
        .collect();
    ips.sort();
    ips.dedup();
    Some((vec![name.clone(), format!("*.{name}")], ips))
}

/// `POST /v1/csr` `{csr_pem, listener}` → `{cert_pem, chain_pem, not_after}`, signed by the LAN
/// CA only for a managed listener assigned to the requesting edge (else `403`), with the subject
/// and SANs from that listener's config; the CSR supplies only the public key, its signature
/// checked. A leaf whose names or IPs would cover core's own is refused too, and nothing is signed
/// while core's wall clock isn't synchronised (`503`).
pub async fn csr(
    State(state): State<SharedState>,
    Extension(peer): Extension<EdgePeer>,
    body: Body,
) -> Response {
    let bytes = match tokio::time::timeout(BODY_DEADLINE, axum::body::to_bytes(body, MAX_CSR_BODY)).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "the request is too large",
            );
        }
        Err(_) => {
            return error(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "the request arrived too slowly",
            );
        }
    };
    let req: CsrRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "the body isn't a CSR request",
            );
        }
    };
    // A certificate's dates come from core's wall clock: signing waits until it is synchronised
    // (README §2 Clocks), so no edge gets a certificate that starts in the future or has already
    // ended. The edge keeps serving the one it has and retries with its backoff (edge.md §5).
    // Checked before the CSR budget, so the retries meanwhile don't spend it.
    if !state.clock.synced() {
        return clock_refusal();
    }
    if !state.edges.csr.admit(&peer.edge_id) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many CSRs; retry later",
        );
    }
    let model = match state.config.model_of(crate::config::EntityKind::Listener).await {
        Ok(m) => m,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "retry later"),
    };
    let forbidden = || {
        error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "no managed listener with that id is assigned to this edge",
        )
    };
    let Some(l) = model.listeners.get(&req.listener) else {
        return forbidden();
    };
    if !l.edges.contains(&peer.edge_id) {
        return forbidden();
    }
    let Some((names, ips)) = listener_sans(l) else {
        return forbidden();
    };
    let settings = state.settings();
    let core_ips: Vec<_> = state
        .core_ips()
        .iter()
        .copied()
        .chain(settings.web.addresses.iter().filter_map(|a| a.parse().ok()))
        .collect();
    if let Some(why) = crate::lanca::edge_leaf_conflict(&names, &ips, &settings.web.names, &core_ips) {
        tracing::warn!(edge = %peer.edge_id, listener = %req.listener, "CSR refused: {why}");
        return error(StatusCode::FORBIDDEN, "conflict", why);
    }
    let lanca = state.lanca.load_full();
    let csr_pem = req.csr_pem;
    let clock = state.clock.clone();
    let signed = tokio::task::spawn_blocking(move || {
        // Again right before the certificate is dated: the clock may have stopped being
        // synchronised while the listener was looked up.
        clock
            .synced()
            .then(|| lanca.sign_leaf(&csr_pem, &names, &ips, crate::lanca::LEAF_VALIDITY))
    })
    .await;
    match signed {
        Ok(None) => clock_refusal(),
        Ok(Some(Ok(cert))) => {
            // Core keeps trusting a previous root until the edge reports serving a certificate
            // from the current one (`cert_roots`, lanca::rotation), not when it signs one: the
            // edge may never install it.
            tracing::info!(edge = %peer.edge_id, listener = %req.listener, "listener certificate signed");
            (
                StatusCode::OK,
                Json(CsrResponse {
                    cert_pem: cert.cert_pem,
                    chain_pem: cert.chain_pem,
                    not_after: crate::util::ts(&cert.not_after),
                }),
            )
                .into_response()
        }
        Ok(Some(Err(e @ (SignError::BadCsr | SignError::BadSignature | SignError::BadKey)))) => {
            error(StatusCode::BAD_REQUEST, "bad_csr", e.to_string())
        }
        Ok(Some(Err(e @ SignError::Signing(_)))) => {
            tracing::warn!(error = %e, "LAN CA signing failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "signing failed")
        }
        Ok(Some(Err(e))) => error(StatusCode::FORBIDDEN, "refused", e.to_string()),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "signing failed"),
    }
}
