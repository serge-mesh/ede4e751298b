//! The web port's mandatory protections (core.md §12), applied to every request in this order:
//!
//! 1. the IP allowlist for the path's class: `lists.allow_cidrs` for `/lists/*`, the LAN CA root
//!    and the extension downloads, `metrics.allow_cidrs` for `/metrics` (off, `404`, while
//!    empty), `web.allow_cidrs` for everything else;
//! 2. the `Host` allowlist (`web.names`, declared addresses and core's IPs; defeats DNS rebinding);
//! 3. no CORS: preflights are refused and no CORS header is ever sent;
//! 4. mutating requests need `X-Picket-UI: 1` and a JSON body, else `403` (forces a preflight
//!    that core never approves);
//! 5. basic auth on the UI's assets, `/api/ui/v1` and the UI WebSocket upgrade; `/lists/*`, the
//!    LAN CA root, the extension downloads, `/healthz` and `/metrics` stay open.
//!
//! The Content-Security-Policy header goes on every response (a layer in `web::router`).

use std::net::{IpAddr, SocketAddr};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::error::ApiError;
use crate::state::SharedState;
use crate::web::auth::AuthResult;

/// The CSP on every web-port response, exactly as core.md §12 gives it.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The peer address of a connection, put in each request's extensions by the server.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

/// Which allowlist and auth rule a path falls under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathClass {
    /// `/lists/*`, the LAN CA root, extension downloads: `lists.allow_cidrs`, no auth.
    Lists,
    /// `/metrics`: `metrics.allow_cidrs`, no auth.
    Metrics,
    /// `/healthz`: `web.allow_cidrs`, no auth.
    Health,
    /// The UI, `/api/ui/v1`, the UI WebSocket: `web.allow_cidrs` and basic auth.
    Ui,
}

pub fn classify(path: &str) -> PathClass {
    if path == "/metrics" {
        PathClass::Metrics
    } else if path == "/healthz" {
        PathClass::Health
    } else if path.starts_with("/lists/")
        || path == "/lists"
        || path.starts_with("/lanca/")
        || path.starts_with("/extension/")
    {
        PathClass::Lists
    } else {
        PathClass::Ui
    }
}

fn plain(status: StatusCode, text: &'static str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        text,
    )
        .into_response()
}

/// True when the `Host` (or HTTP/2 `:authority`) names core: one of `web.names`, declared addresses or core's IPs.
pub fn host_allowed(state: &SharedState, req: &Request) -> bool {
    let authority = req.uri().authority().map(|a| a.as_str().to_string()).or_else(|| {
        req.headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string)
    });
    let Some(host) = authority.as_deref().and_then(crate::net::host_without_port) else {
        return false;
    };
    let settings = state.settings();
    if settings
        .web
        .names
        .iter()
        .any(|n| n.trim_end_matches('.').eq_ignore_ascii_case(&host))
    {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => {
            let ip = crate::net::canonical_ip(ip);
            settings
                .web
                .addresses
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .any(|c| crate::net::canonical_ip(c) == ip)
                || state
                    .core_ips()
                    .iter()
                    .any(|c| crate::net::canonical_ip(*c) == ip)
        }
        Err(_) => false,
    }
}

fn is_mutating(m: &Method) -> bool {
    !matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE)
}

fn json_content_type(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            let m = m.trim().to_ascii_lowercase();
            m == "application/json" || (m.starts_with("application/") && m.ends_with("+json"))
        })
}

/// The protection middleware for the web port.
pub async fn guard(State(state): State<SharedState>, req: Request, next: Next) -> Response {
    let peer = req.extensions().get::<PeerAddr>().map(|p| p.0.ip());
    let Some(peer) = peer else {
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    };
    let class = classify(req.uri().path());
    let settings = state.settings();

    // 1. IP allowlists.
    let (list, off_is_404) = match class {
        PathClass::Lists => (&settings.lists.allow_cidrs, false),
        PathClass::Metrics => (&settings.metrics.allow_cidrs, true),
        PathClass::Health | PathClass::Ui => (&settings.web.allow_cidrs, false),
    };
    let nets: Vec<ipnet::IpNet> = list.iter().filter_map(|s| crate::net::parse_net(s)).collect();
    if nets.is_empty() && off_is_404 {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    if !crate::net::nets_contain(&nets, peer) {
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }

    // 2. Host allowlist.
    if !host_allowed(&state, &req) {
        return plain(StatusCode::FORBIDDEN, "forbidden: unknown Host\n");
    }

    // 3. No CORS: preflights are refused.
    if req.method() == Method::OPTIONS {
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }

    // 4. Mutations need X-Picket-UI: 1 and a JSON body.
    if is_mutating(req.method()) {
        let ui = req
            .headers()
            .get("x-picket-ui")
            .is_some_and(|v| v.as_bytes() == b"1");
        if !ui {
            return ApiError::forbidden("mutating requests need the X-Picket-UI: 1 header").into_response();
        }
        if !json_content_type(&req) {
            return ApiError::forbidden(
                "mutating requests need a JSON body (Content-Type: application/json)",
            )
            .into_response();
        }
    }

    // 5. Basic auth where it applies.
    if class == PathClass::Ui {
        let header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        // `ui_auth_failures` is raised by the auth state where the failure is counted.
        let (result, _) = state.auth.check(peer, header.as_deref()).await;
        match result {
            AuthResult::Ok => {}
            AuthResult::Missing | AuthResult::Failed => {
                let mut r = plain(StatusCode::UNAUTHORIZED, "authentication required\n");
                r.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(r#"Basic realm="picket-core", charset="UTF-8""#),
                );
                return r;
            }
            AuthResult::Blocked(d) => {
                let mut r = plain(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many failed logins; try again later\n",
                );
                if let Ok(v) = HeaderValue::from_str(&d.as_secs().max(1).to_string()) {
                    r.headers_mut().insert(header::RETRY_AFTER, v);
                }
                return r;
            }
            AuthResult::Throttled => {
                let mut r = plain(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many password checks from this address at once; try again\n",
                );
                r.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return r;
            }
            AuthResult::Busy => {
                let mut r = plain(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "too many password checks at once; try again\n",
                );
                r.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
                return r;
            }
        }
    }
    next.run(req).await
}

/// The plain-HTTP port (`web.http_port`) serves only `/lists/*` and the LAN CA root (core.md
/// §11): every other path is `404` here, before the allowlists and basic auth, so the port never
/// asks for (or checks) the admin password in clear.
pub async fn lists_only(req: Request, next: Next) -> Response {
    if classify(req.uri().path()) != PathClass::Lists {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    next.run(req).await
}

/// Adds the CSP and a few hardening headers to every response.
///
/// `Strict-Transport-Security` is intentionally omitted:
/// - browsers ignore HSTS for IP literals (RFC 6797 §8.1);
/// - for a name in `web.names`, HSTS rewrites `http://<name>:<web.http_port>/...` to `https://`
///   on the same port (RFC 6797 §8.3), breaking LAN-CA root bootstrap before the browser trusts
///   the CA;
/// - it removes click-through on certificate errors and outlives a switch to `web.tls = off`.
///
/// The TLS web port accepts only TLS 1.3 and `web.http_port` serves only `/lists/*` and the LAN
/// CA root without authentication, so there is nothing to downgrade.
pub async fn headers(req: Request<Body>, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.remove(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    r
}

/// The UI WebSocket's `Origin` rule: `https://` (`http://` with `web.tls` off) followed by the
/// request's own `Host`; missing or anything else is refused.
pub fn origin_allowed(origin: Option<&str>, host: Option<&str>, tls: bool) -> bool {
    match (origin, host) {
        (Some(o), Some(h)) if !h.is_empty() => {
            let scheme = if tls { "https://" } else { "http://" };
            o.strip_prefix(scheme)
                .is_some_and(|rest| rest.eq_ignore_ascii_case(h))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(classify("/lists/block-common.txt"), PathClass::Lists);
        assert_eq!(classify("/lanca/ca.crt"), PathClass::Lists);
        assert_eq!(classify("/metrics"), PathClass::Metrics);
        assert_eq!(classify("/healthz"), PathClass::Health);
        assert_eq!(classify("/api/ui/v1/profiles"), PathClass::Ui);
        assert_eq!(classify("/"), PathClass::Ui);
        assert_eq!(classify("/listsx"), PathClass::Ui);
    }

    #[test]
    fn origins() {
        assert!(origin_allowed(
            Some("https://core.home.arpa:8443"),
            Some("core.home.arpa:8443"),
            true
        ));
        assert!(!origin_allowed(
            Some("http://core.home.arpa:8443"),
            Some("core.home.arpa:8443"),
            true
        ));
        assert!(origin_allowed(
            Some("http://10.0.0.2:8443"),
            Some("10.0.0.2:8443"),
            false
        ));
        assert!(!origin_allowed(
            Some("https://evil.example"),
            Some("core.home.arpa:8443"),
            true
        ));
        assert!(!origin_allowed(None, Some("core.home.arpa:8443"), true));
        assert!(!origin_allowed(
            Some("https://core.home.arpa:8443.evil"),
            Some("core.home.arpa:8443"),
            true
        ));
    }
}
