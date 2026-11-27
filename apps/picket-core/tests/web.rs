//! The "UI API protections" suite (build-and-test.md §5): basic auth on every path that needs it
//! and on none that doesn't; the first password, its file and its change; the failed-login
//! limit; each mandatory protection of the UI and its WebSocket (core.md §12, api.md §7).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::time::Duration;

use common::*;
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn plain() -> Option<Value> {
    Some(json!({"web": {"tls": "off"}}))
}

async fn get(c: &Core, path: &str, auth: Option<&str>) -> reqwest::Response {
    let mut r = client().get(format!("{}{path}", c.base(scheme(c))));
    if let Some(pw) = auth {
        r = r.basic_auth("admin", Some(pw));
    }
    r.send().await.unwrap()
}

fn scheme(c: &Core) -> &'static str {
    if c.state.settings().web.tls == picket_core::settings::WebTls::Off {
        "http"
    } else {
        "https"
    }
}

/// A mutating request with the UI header and a JSON body.
fn ui(c: &Core, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
    client()
        .request(method, format!("{}{path}", c.base(scheme(c))))
        .basic_auth("admin", Some(&c.init.password))
        .header("X-Picket-UI", "1")
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_where_needed_and_nowhere_else() {
    let c = start_core(None).await; // managed TLS
    let pw = c.init.password.clone();
    for path in [
        "/",
        "/index.html",
        "/some/ui/route",
        "/api/ui/v1/identity",
        "/api/ui/v1/profiles",
        "/api/ui/v1/openapi.json",
        "/api/ui/v1/events",
    ] {
        let r = get(&c, path, None).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert!(
            r.headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("Basic"),
            "{path}"
        );
        assert_eq!(r.headers().get("content-security-policy").unwrap(), CSP, "{path}");
    }
    let r = get(&c, "/api/ui/v1/identity", Some(&pw)).await;
    assert_eq!(r.status(), StatusCode::OK);
    let id: Value = r.json().await.unwrap();
    assert_eq!(id["fingerprint"], c.init.fingerprint);
    assert_eq!(get(&c, "/", Some(&pw)).await.status(), StatusCode::OK);
    // Open paths: no auth asked.
    assert_eq!(get(&c, "/healthz", None).await.status(), StatusCode::OK);
    let ca = get(&c, "/lanca/ca.crt", None).await;
    assert_eq!(ca.status(), StatusCode::OK);
    assert_eq!(
        ca.bytes().await.unwrap().as_ref(),
        c.state.lanca.load().cert_der.as_slice()
    );
    assert_eq!(get(&c, "/lanca/ca.pem", None).await.status(), StatusCode::OK);
    assert_eq!(
        get(&c, "/lists/block-common.txt", None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&c, "/extension/picket-brave.zip", None).await.status(),
        StatusCode::NOT_FOUND
    );
    // /metrics is off (404) while metrics.allow_cidrs is empty.
    let m = get(&c, "/metrics", None).await;
    assert_eq!(m.status(), StatusCode::NOT_FOUND);
    assert_eq!(m.headers().get("content-security-policy").unwrap(), CSP);
    // The OpenAPI document is 3.1.
    let doc: Value = get(&c, "/api/ui/v1/openapi.json", Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    // The managed certificate comes from the LAN CA.
    let (names, _) = picket_core::web::web_cert_sans(&c.state);
    assert!(!names.is_empty() || !picket_core::net::local_lan_ips(&c.state.core_ips()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn open_paths_serve_only_their_own_resources() {
    // core.md §12: /lists/*, the LAN CA root and the extension downloads skip basic auth, so
    // nothing else may answer under them: never the UI document.
    let c = start_core(plain()).await;
    for path in [
        "/lists",
        "/lanca/anything",
        "/lanca/settings",
        "/lanca/",
        "/extension/x/y",
    ] {
        let r = get(&c, path, None).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        let body = r.text().await.unwrap();
        assert!(!body.contains("<html"), "{path}: {body}");
    }
    assert_eq!(get(&c, "/lanca/ca.crt", None).await.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_plain_http_port_never_asks_for_the_password() {
    // core.md §11: web.http_port serves only /lists/* and the LAN CA root; every other path is
    // 404 before auth, with or without credentials, and nothing challenges for them.
    // Managed TLS on web.port. The plain-HTTP port binds 0 like every test port (the setting
    // only switches it on), and the bound address is read back.
    let c = start_core(Some(json!({"web": {"http_port": 1}}))).await;
    let http = c.info.web[1].port();
    let pw = c.init.password.clone();
    for (path, auth) in [
        ("/api/ui/v1/identity", None),
        ("/api/ui/v1/identity", Some(pw.as_str())),
        ("/", None),
        ("/", Some(pw.as_str())),
        ("/healthz", None),
        ("/api/ui/v1/events", Some(pw.as_str())),
    ] {
        let mut r = client().get(format!("http://127.0.0.1:{http}{path}"));
        if let Some(p) = auth {
            r = r.basic_auth("admin", Some(p));
        }
        let r = r.send().await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path} {auth:?}");
        assert!(r.headers().get("www-authenticate").is_none(), "{path}");
    }
    let ca = client()
        .get(format!("http://127.0.0.1:{http}/lanca/ca.crt"))
        .send()
        .await
        .unwrap();
    assert_eq!(ca.status(), StatusCode::OK);
}

/// Whether a TLS handshake with only `version` offered succeeds on `port`.
async fn handshake(port: u16, version: &'static rustls::SupportedProtocolVersion) -> bool {
    #[derive(Debug)]
    struct AnyServer(std::sync::Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for AnyServer {
        fn verify_server_cert(
            &self,
            _: &rustls_pki_types::CertificateDer<'_>,
            _: &[rustls_pki_types::CertificateDer<'_>],
            _: &rustls_pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &rustls_pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &rustls_pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyServer(provider)))
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg))
        .connect(
            rustls_pki_types::ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
            tcp,
        )
        .await
        .is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_web_port_speaks_only_tls_1_3() {
    // api.md: every interface uses TLS 1.3.
    let c = start_core(None).await; // managed TLS
    let port = c.web().port();
    assert!(handshake(port, &rustls::version::TLS13).await);
    assert!(!handshake(port, &rustls::version::TLS12).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_open_for_its_ranges() {
    let c = start_core(Some(
        json!({"web": {"tls": "off"}, "metrics": {"allow_cidrs": ["127.0.0.0/8", "::1/128"]}}),
    ))
    .await;
    let r = get(&c, "/metrics", None).await;
    assert_eq!(r.status(), StatusCode::OK);
    let scrape = common::prom::parse(&r.text().await.unwrap());
    assert_eq!(scrape.value("picket_up", &[]), Some(1.0));
}

#[tokio::test(flavor = "multi_thread")]
async fn first_password_file_and_change() {
    let c = start_core(plain()).await;
    let file = c.dir.path().join(picket_core::instance::INITIAL_PASSWORD);
    let first = std::fs::read_to_string(&file).unwrap().trim().to_string();
    assert_eq!(first, c.init.password);
    assert_eq!(
        get(&c, "/api/ui/v1/identity", Some(&first)).await.status(),
        StatusCode::OK
    );
    // Wrong current password.
    let r = ui(&c, reqwest::Method::POST, "/api/ui/v1/account/password")
        .json(&json!({"current": "wrong wrong wrong", "new": "a new long password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(file.exists());
    // Too short.
    let r = ui(&c, reqwest::Method::POST, "/api/ui/v1/account/password")
        .json(&json!({"current": first, "new": "short"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = r.json().await.unwrap();
    assert!(body["error"]["message"].as_str().is_some());
    // Changed: the file goes, the old password stops working.
    let r = ui(&c, reqwest::Method::POST, "/api/ui/v1/account/password")
        .json(&json!({"current": first, "new": "a new long password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(!file.exists());
    assert_eq!(
        get(&c, "/api/ui/v1/identity", Some(&first)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(&c, "/api/ui/v1/identity", Some("a new long password"))
            .await
            .status(),
        StatusCode::OK
    );
    // The journal records the change without the password.
    let changes: Value = get(&c, "/api/ui/v1/config-changes", Some("a new long password"))
        .await
        .json()
        .await
        .unwrap();
    let text = changes.to_string();
    assert!(text.contains("account"));
    assert!(!text.contains("a new long password"));
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_login_limit_and_alert() {
    let c = start_core(plain()).await;
    let pw = c.init.password.clone();
    for _ in 0..4 {
        assert_eq!(
            get(&c, "/api/ui/v1/identity", Some("nope")).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    // The fifth failure blocks: 429, even with the right password, for a minute.
    assert_eq!(
        get(&c, "/api/ui/v1/identity", Some("nope")).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let r = get(&c, "/api/ui/v1/identity", Some(&pw)).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().get("retry-after").is_some());
    // Open paths stay open.
    assert_eq!(get(&c, "/healthz", None).await.status(), StatusCode::OK);

    // 10 failures within 10 min (spread out, so no block) raise ui_auth_failures.
    let c = start_core(plain()).await;
    let now = tokio::time::Instant::now();
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    for i in 0..9u64 {
        let o = c
            .state
            .auth
            .record_failure_at(ip, now - Duration::from_secs(540 - i * 55));
        assert!(!o.blocked);
    }
    assert_eq!(
        get(&c, "/api/ui/v1/identity", Some("nope")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let mut found = None;
    for _ in 0..50 {
        found = c
            .state
            .alerts
            .get_by_key("ui_auth_failures:127.0.0.1")
            .await
            .unwrap();
        if found.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let a = found.expect("ui_auth_failures raised");
    assert_eq!(a.kind, "ui_auth_failures");
    assert_eq!(serde_json::to_value(a.alert_type).unwrap(), "security");
    assert_eq!(serde_json::to_value(a.severity).unwrap(), "warning");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_guesses_cannot_outrun_the_failed_login_limit() {
    // core.md §12: after 5 failures in 1 min from one IP, core answers 429. Guesses queued
    // behind the argon2 slots before the block started are stopped by it, not verified: a
    // burst of 21 guesses one failure short of the block gets at most the slots' worth checked,
    // so the 10 failures that raise ui_auth_failures are never reached.
    let c = start_core(plain()).await;
    let pw = c.init.password.clone();
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let now = tokio::time::Instant::now();
    for _ in 0..4 {
        assert!(!c.state.auth.record_failure_at(ip, now).blocked);
    }
    let mut tasks = Vec::new();
    for i in 0..21 {
        let url = format!("{}/api/ui/v1/identity", c.base("http"));
        let guess = format!("wrong guess {i}");
        tasks.push(tokio::spawn(async move {
            client()
                .get(url)
                .basic_auth("admin", Some(guess))
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    for t in tasks {
        let s = t.await.unwrap();
        assert!(
            s == StatusCode::UNAUTHORIZED || s == StatusCode::TOO_MANY_REQUESTS,
            "{s}"
        );
    }
    // The IP is blocked now, the right password included.
    assert_eq!(
        get(&c, "/api/ui/v1/identity", Some(&pw)).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        c.state
            .alerts
            .get_by_key("ui_auth_failures:127.0.0.1")
            .await
            .unwrap()
            .is_none(),
        "the queued guesses were verified after the block"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mandatory_protections() {
    let c = start_core(plain()).await;
    let pw = c.init.password.clone();
    let url = format!("{}/api/ui/v1/upstream-groups", c.base("http"));
    let body = json!({"id": "g1", "name": "G", "upstreams": ["cf-dot-1"]});
    // Mutations without X-Picket-UI: 403.
    let r = client()
        .post(&url)
        .basic_auth("admin", Some(&pw))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(r.headers().get("content-security-policy").unwrap(), CSP);
    // With the header but no JSON body: 403.
    let r = client()
        .post(&url)
        .basic_auth("admin", Some(&pw))
        .header("X-Picket-UI", "1")
        .header("content-type", "text/plain")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // A form post (what a cross-site page can send without a preflight): 403.
    let r = client()
        .post(&url)
        .basic_auth("admin", Some(&pw))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("id=g1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // Both: created.
    let r = ui(&c, reqwest::Method::POST, "/api/ui/v1/upstream-groups")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    // Preflights are refused and no CORS header is ever sent.
    let r = client()
        .request(reqwest::Method::OPTIONS, &url)
        .header("Origin", "https://evil.example")
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(r.headers().get("access-control-allow-origin").is_none());
    // The Host allowlist (DNS rebinding).
    let r = client()
        .get(format!("{}/api/ui/v1/identity", c.base("http")))
        .basic_auth("admin", Some(&pw))
        .header("Host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = client()
        .get(format!("{}/healthz", c.base("http")))
        .header("Host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "healthz is behind the Host check too"
    );
    // web.names are allowed hosts.
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/settings")
        .json(&json!({"web": {"names": ["core.home.arpa"]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = client()
        .get(format!("{}/healthz", c.base("http")))
        .header("Host", format!("core.home.arpa:{}", c.web().port()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // lists.allow_cidrs governs the LAN CA root; web.allow_cidrs the rest.
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/settings")
        .json(&json!({"lists": {"allow_cidrs": ["10.0.0.0/8"]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        get(&c, "/lanca/ca.crt", None).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(get(&c, "/healthz", None).await.status(), StatusCode::OK);
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/settings")
        .json(&json!({"web": {"allow_cidrs": ["10.0.0.0/8"]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(get(&c, "/healthz", None).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        get(&c, "/api/ui/v1/identity", Some(&pw)).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_websocket_upgrades_give_their_slot_back() {
    // core.md §12, README §2 Bounded: the UI WebSocket count is capped; an upgrade that fails
    // (the client is gone when the 101 is written) must free its slot, or after 64 failures the
    // UI gets 503 for every event stream until a restart. The web router is driven over an
    // in-memory pipe whose client end is gone, so the 101's write fails every time.
    use tokio::io::AsyncWriteExt;
    use tower::ServiceExt;
    let c = start_core(plain()).await;
    let port = c.web().port();
    let auth = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("admin:{}", c.init.password),
    );
    let req = format!(
        "GET /api/ui/v1/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\n\
         Authorization: Basic {auth}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().unwrap();
    for _ in 0..70 {
        // A 16-byte pipe: the server's 101 can't be written in one go, and the client goes
        // away once it has seen the status line.
        let (mut client_end, server_end) = tokio::io::duplex(16);
        let req = req.clone();
        let client = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            client_end.write_all(req.as_bytes()).await.unwrap();
            let mut status = [0u8; 12];
            client_end.read_exact(&mut status).await.unwrap();
            status
        });
        let router = picket_core::web::router(c.state.clone());
        let svc = hyper::service::service_fn(move |mut r: hyper::Request<hyper::body::Incoming>| {
            r.extensions_mut()
                .insert(picket_core::web::protect::PeerAddr(peer));
            r.extensions_mut().insert(picket_core::web::ConnTls(false));
            let router = router.clone();
            async move { router.oneshot(r.map(axum::body::Body::new)).await }
        });
        let conn = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(server_end), svc)
            .with_upgrades();
        let (r, status) = tokio::join!(conn, client);
        assert_eq!(
            String::from_utf8_lossy(&status.unwrap()),
            "HTTP/1.1 101",
            "a slot was free"
        );
        assert!(r.is_err(), "the upgrade failed");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut r = format!("ws://127.0.0.1:{port}/api/ui/v1/events")
        .into_client_request()
        .unwrap();
    r.headers_mut()
        .insert("Origin", format!("http://127.0.0.1:{port}").parse().unwrap());
    r.headers_mut()
        .insert("Authorization", format!("Basic {auth}").parse().unwrap());
    match tokio_tungstenite::connect_async(r).await {
        Ok(_) => {}
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            panic!("event stream refused with {}: slots leaked", resp.status())
        }
        Err(e) => panic!("{e}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_origin_and_events() {
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    let c = start_core(plain()).await;
    let port = c.web().port();
    let auth = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("admin:{}", c.init.password)
        )
    );
    let connect = |origin: Option<String>, with_auth: bool| {
        let auth = auth.clone();
        async move {
            let mut req = format!("ws://127.0.0.1:{port}/api/ui/v1/events")
                .into_client_request()
                .unwrap();
            if let Some(o) = origin {
                req.headers_mut()
                    .insert("Origin", HeaderValue::from_str(&o).unwrap());
            }
            if with_auth {
                req.headers_mut()
                    .insert("Authorization", HeaderValue::from_str(&auth).unwrap());
            }
            tokio_tungstenite::connect_async(req).await
        }
    };
    let status = |r: Result<_, tokio_tungstenite::tungstenite::Error>| match r {
        Ok(_) => 101,
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => resp.status().as_u16(),
        Err(e) => panic!("{e}"),
    };
    let own = format!("http://127.0.0.1:{port}");
    assert_eq!(status(connect(Some(own.clone()), false).await.map(|_| ())), 401);
    assert_eq!(status(connect(None, true).await.map(|_| ())), 403);
    assert_eq!(
        status(
            connect(Some("https://evil.example".into()), true)
                .await
                .map(|_| ())
        ),
        403
    );
    assert_eq!(
        status(
            connect(Some(format!("https://127.0.0.1:{port}")), true)
                .await
                .map(|_| ())
        ),
        403,
        "https:// with tls off"
    );
    let (mut ws, resp) = connect(Some(own), true).await.unwrap();
    assert_eq!(resp.status().as_u16(), 101);
    // An alert reaches the socket as {type: "alert", data}: coalesced, listing it (api.md §7).
    c.state
        .alerts
        .raise(picket_core::alerts::RaiseSpec::new(
            "feed_held",
            picket_core::alerts::Severity::Warning,
            "feed_held:x",
            "held",
            json!({}),
        ))
        .await
        .unwrap();
    // Other events (e.g. `job` reports from background work started with core) may come first.
    let v: Value = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) => {
                    let v: Value = serde_json::from_str(&t).unwrap();
                    if v["type"] == "alert" {
                        return v;
                    }
                }
                Some(Ok(_)) => continue,
                other => panic!("{other:?}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(v["type"], "alert");
    assert_eq!(v["data"]["alerts"][0]["kind"], "feed_held", "{v}");
    assert_eq!(v["data"]["alerts"][0]["state"], "open", "{v}");
    assert_eq!(v["data"]["alerts"][0]["deleted"], false, "{v}");
    drop(ws);

    // A web.tls change takes effect at restart: until then the Origin must match the scheme
    // the connection actually uses, not the saved setting.
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/settings")
        .json(&json!({"web": {"tls": "managed"}}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    assert_eq!(
        status(
            connect(Some(format!("http://127.0.0.1:{port}")), true)
                .await
                .map(|_| ())
        ),
        101,
        "the server still speaks plain HTTP"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn healthz_with_edges() {
    let c = start_core(plain()).await;
    assert_eq!(
        get(&c, "/healthz?edges=1", None).await.status(),
        StatusCode::OK,
        "no edges: healthy"
    );
    let fp = picket_api::ids::fingerprint_spki(b"edge");
    let r = ui(&c, reqwest::Method::POST, "/api/ui/v1/edges")
        .json(&json!({"name": "ucg", "key": fp}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    // Never seen: offline.
    let r = get(&c, "/healthz?edges=1", None).await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.text().await.unwrap(), "unavailable\n", "no details");
    assert_eq!(get(&c, "/healthz", None).await.status(), StatusCode::OK);
    let out: Value = get(&c, "/api/ui/v1/edges", Some(&c.init.password))
        .await
        .json()
        .await
        .unwrap();
    let id = out["items"][0]["id"].as_str().unwrap().to_string();
    // Online with no condition: healthy; with a condition: not.
    let now = picket_core::util::now_ts();
    let (db, id2, now2) = (c.state.db.clone(), id.clone(), now.clone());
    db.write(move |conn| {
        conn.execute(
            "INSERT INTO edge_status(edge_id, last_seen, conditions_json) VALUES (?1, ?2, '[]')",
            [&id2, &now2],
        )?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .unwrap();
    assert_eq!(get(&c, "/healthz?edges=1", None).await.status(), StatusCode::OK);
    let db = c.state.db.clone();
    db.write(move |conn| {
        conn.execute(
            "UPDATE edge_status SET conditions_json = '[{\"kind\":\"memory_low\",\"since\":\"2026-01-01T00:00:00Z\"}]' WHERE edge_id = ?1",
            [&id],
        )?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .unwrap();
    assert_eq!(
        get(&c, "/healthz?edges=1", None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crud_validation_pending_and_secrets() {
    let c = start_core(plain()).await;
    let pw = c.init.password.clone();
    // A profile: create, read, list with paging, update, refuse an id change, delete.
    let r = ui(&c, reqwest::Method::POST, "/api/ui/v1/profiles")
        .json(&json!({"id": "kids", "name": "Kids", "block": ["block-common"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let p: Value = get(&c, "/api/ui/v1/profiles/kids", Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(p["block"][0], "block-common");
    assert_eq!(p["alert_categories"][0], "security");
    let page: Value = get(&c, "/api/ui/v1/profiles?limit=1", Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let cursor = page["next_cursor"].as_str().unwrap().to_string();
    let page2: Value = get(
        &c,
        &format!("/api/ui/v1/profiles?limit=10&cursor={cursor}"),
        Some(&pw),
    )
    .await
    .json()
    .await
    .unwrap();
    assert!(!page2["items"].as_array().unwrap().is_empty());
    assert_ne!(page["items"][0]["id"], page2["items"][0]["id"]);
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/profiles/kids")
        .json(&json!({"id": "children", "name": "Kids"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY, "ids never change");
    // A refused save names its problems.
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/profiles/kids")
        .json(&json!({"name": "Kids", "block": ["allow-common"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let e: Value = r.json().await.unwrap();
    assert_eq!(e["error"]["code"], "validation");
    assert_eq!(e["error"]["issues"][0]["code"], "wrong_action");
    // System objects can't be deleted.
    let r = ui(&c, reqwest::Method::DELETE, "/api/ui/v1/bundles/block-common")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = ui(&c, reqwest::Method::DELETE, "/api/ui/v1/profiles/kids")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        get(&c, "/api/ui/v1/profiles/kids", Some(&pw)).await.status(),
        StatusCode::NOT_FOUND
    );
    // A lanca.zones change is a LAN CA rotation (core.md §11); a public suffix is refused.
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/settings")
        .json(&json!({"lanca": {"zones": ["com"]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Pending edges: listed, approved by the path form of the key.
    let fp = picket_api::ids::fingerprint_spki(b"pending edge");
    picket_core::edges::record_pending(&c.state.db, &fp, Some("192.168.1.1".into()), Some("ucg".into()))
        .await
        .unwrap();
    let pend: Value = get(&c, "/api/ui/v1/edges/pending", Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(pend["items"][0]["key"], fp);
    assert_eq!(pend["items"][0]["claimed_name"], "ucg");
    let path = picket_api::ids::fingerprint_path(&picket_api::ids::parse_fingerprint(&fp).unwrap());
    let r = ui(
        &c,
        reqwest::Method::POST,
        &format!("/api/ui/v1/edges/pending/{path}/approve"),
    )
    .json(&json!({"name": "ucg"}))
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let pend: Value = get(&c, "/api/ui/v1/edges/pending", Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert!(pend["items"].as_array().unwrap().is_empty());
    let edges: Value = get(&c, "/api/ui/v1/edges", Some(&pw)).await.json().await.unwrap();
    let edge_id = edges["items"][0]["id"].as_str().unwrap().to_string();
    let preview: Value = get(&c, &format!("/api/ui/v1/edges/{edge_id}/config"), Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(preview["config"]["edge"]["name"], "ucg");
    assert_eq!(preview["id"].as_str().unwrap().len(), 64);
    // Secrets are write-only and never journaled.
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/secrets/am_rt")
        .json(&json!({"value": "s3cr3t-value"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let s = get(&c, "/api/ui/v1/secrets", Some(&pw))
        .await
        .text()
        .await
        .unwrap();
    assert!(s.contains("am_rt") && !s.contains("s3cr3t-value"));
    let j = get(&c, "/api/ui/v1/config-changes?limit=500", Some(&pw))
        .await
        .text()
        .await
        .unwrap();
    assert!(j.contains("am_rt") && !j.contains("s3cr3t-value"));
    // Unknown API paths answer in the error shape.
    let r = get(&c, "/api/ui/v1/nope", Some(&pw)).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let e: Value = r.json().await.unwrap();
    assert_eq!(e["error"]["code"], "not_found");
    // The config export names secrets, never their values (core.md §2).
    let r = get(&c, "/api/ui/v1/config/export", Some(&pw)).await;
    assert_eq!(r.status(), StatusCode::OK);
    let x = r.text().await.unwrap();
    assert!(x.contains("am_rt") && !x.contains("s3cr3t-value"));
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_api() {
    let c = start_core(plain()).await;
    let pw = c.init.password.clone();
    for i in 0..3 {
        c.state
            .alerts
            .raise(picket_core::alerts::RaiseSpec::new(
                "feed_held",
                picket_core::alerts::Severity::Warning,
                format!("k{i}"),
                "held",
                json!({"i": i}),
            ))
            .await
            .unwrap();
    }
    let page: Value = get(&c, "/api/ui/v1/alerts?type=operational&limit=2", Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    let cur = page["next_cursor"].as_str().unwrap();
    let page2: Value = get(
        &c,
        &format!("/api/ui/v1/alerts?type=operational&limit=2&cursor={cur}"),
        Some(&pw),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(page2["items"].as_array().unwrap().len(), 1);
    let id = page["items"][0]["id"].as_i64().unwrap();
    let r = ui(
        &c,
        reqwest::Method::POST,
        &format!("/api/ui/v1/alerts/{id}/resolve"),
    )
    .json(&json!({}))
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let d: Value = get(&c, &format!("/api/ui/v1/alerts/{id}"), Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(d["alert"]["state"], "resolved");
    assert_eq!(d["history"].as_array().unwrap().len(), 2);
    let open: Value = get(&c, "/api/ui/v1/alerts?state=open", Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(open["items"].as_array().unwrap().len(), 2);
    let ids: Vec<i64> = open["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_i64().unwrap())
        .collect();
    let r = ui(&c, reqwest::Method::DELETE, "/api/ui/v1/alerts")
        .json(&json!({"ids": ids}))
        .send()
        .await
        .unwrap();
    let del: Value = r.json().await.unwrap();
    assert_eq!(del["deleted"], 2);
    let r = ui(&c, reqwest::Method::DELETE, &format!("/api/ui/v1/alerts/{id}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let all: Value = get(&c, "/api/ui/v1/alerts", Some(&pw))
        .await
        .json()
        .await
        .unwrap();
    assert!(all["items"].as_array().unwrap().is_empty());
}

/// The SAN DNS names of the certificate the web port serves now.
fn served_names(c: &Core) -> Vec<String> {
    let swap = c.state.web_cert.get().expect("managed web certificate");
    let key = swap.0.load_full();
    let (_, cert) = x509_parser::parse_x509_certificate(key.cert[0].as_ref()).unwrap();
    let mut names = vec![];
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for g in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(n) = g {
                names.push(n.to_string());
            }
        }
    }
    names
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_web_certificate_follows_web_names_while_running() {
    // core.md §11: the managed certificate covers web.names and core's LAN IPs; a change to
    // them is served without a restart, and so is a renewal before it runs out.
    let c = start_core(None).await;
    assert!(!served_names(&c).contains(&"ui.home.arpa".to_string()));
    let r = ui(&c, reqwest::Method::PUT, "/api/ui/v1/settings")
        .json(&json!({"web": {"names": ["ui.home.arpa"]}}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    assert!(picket_core::web::refresh_web_cert(&c.state).unwrap(), "re-issued");
    assert_eq!(served_names(&c), vec!["ui.home.arpa"]);
    // Nothing changed since: no new certificate.
    assert!(!picket_core::web::refresh_web_cert(&c.state).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn every_documented_operation_is_routed() {
    // The OpenAPI document generates the UI's client (api.md §7): each operation it describes
    // must reach a handler (no 405, no API fallback 404) and never fail with a 500.
    let c = start_core(plain()).await;
    let doc = picket_core::web::openapi::document();
    let paths = doc["paths"].as_object().unwrap();
    assert!(paths.len() > 20);
    let mut checked = 0;
    for (path, item) in paths {
        if path.ends_with("/events") {
            continue; // the WebSocket upgrade (tested with its Origin rules)
        }
        for (method, _) in item.as_object().unwrap() {
            let Ok(m) = reqwest::Method::from_bytes(method.to_ascii_uppercase().as_bytes()) else {
                continue;
            };
            if ![
                reqwest::Method::GET,
                reqwest::Method::PUT,
                reqwest::Method::POST,
                reqwest::Method::DELETE,
                reqwest::Method::PATCH,
            ]
            .contains(&m)
            {
                continue;
            }
            let concrete: String = path
                .split('/')
                .map(|seg| match seg {
                    "{fp}" => "AAAA",
                    s if s.starts_with('{') => "zz-none",
                    s => s,
                })
                .collect::<Vec<_>>()
                .join("/");
            let mut req = ui(&c, m.clone(), &concrete);
            if m != reqwest::Method::GET {
                req = req.header("Content-Type", "application/json").body("{}");
            }
            let r = req.send().await.unwrap();
            let status = r.status();
            let text = r.text().await.unwrap();
            assert_ne!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path} isn't routed"
            );
            assert!(
                !(status == StatusCode::NOT_FOUND && text.contains("no such UI API endpoint")),
                "{method} {path} isn't routed"
            );
            assert_ne!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{method} {path}: {text}"
            );
            checked += 1;
        }
    }
    assert!(checked > 30, "{checked}");
}

/// The next `job` event's data, within 10 s.
async fn next_job(
    rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>,
) -> Result<Value, tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let e = rx.recv().await.unwrap();
            if e.kind == "job" {
                return e.data;
            }
        }
    })
    .await
}

/// F6 (api.md §7 UI WebSocket `job`): each heavy job's start and end reach the event bus with the
/// fields `GET jobs` returns; a burst is paced (at most one event per gap), each job's end stands
/// for its start not sent yet (`coalesced`), reports past the bound are counted in `dropped`, and
/// the newest report comes last, showing the lane idle.
#[tokio::test(flavor = "multi_thread")]
async fn job_events_report_heavy_jobs_paced_and_coalesced() {
    use picket_core::scheduler::Priority;
    let c = start_core(plain()).await;
    let mut rx = c.state.events.subscribe();
    // Let the start-up jobs pass, and their last events.
    let idle = || {
        let h = c.state.scheduler.heavy.stats();
        h.queued == 0 && h.running.is_none()
    };
    for _ in 0..3 {
        common::feeds::wait_until("the heavy lane idle", || async { idle() }).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    while rx.try_recv().is_ok() {}
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let g = gate.clone();
    c.state
        .scheduler
        .heavy
        .submit_fn("test", "one", Priority::P0, move || async move {
            g.notified().await;
            Ok(())
        });
    let start = loop {
        let e = next_job(&mut rx).await.expect("a start event");
        if e["job"] == "test:one" {
            break e;
        }
    };
    assert_eq!(
        (
            start["phase"].as_str(),
            start["job"].as_str(),
            start["outcome"].clone()
        ),
        (Some("start"), Some("test:one"), Value::Null),
        "{start}"
    );
    assert_eq!(start["heavy_running"], "test:one", "{start}");
    for k in [
        "light_depth",
        "light_dropped",
        "heavy_depth",
        "heavy_dropped",
        "heavy_completed",
        "heavy_failed",
    ] {
        assert!(start[k].is_u64(), "{k}: {start}");
    }
    gate.notify_one();
    let end = next_job(&mut rx).await.expect("an end event");
    assert_eq!(
        (
            end["phase"].as_str(),
            end["job"].as_str(),
            end["outcome"].as_str()
        ),
        (Some("end"), Some("test:one"), Some("ok")),
        "{end}"
    );
    assert!(end["ms"].is_u64(), "{end}");
    assert!(start["run"].is_u64(), "{start}");
    assert_eq!(end["run"], start["run"], "a run's start and end carry its id");
    // A burst of 300 jobs: paced and coalesced, the last event showing the lane idle.
    common::feeds::wait_until("the heavy lane idle", || async { idle() }).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    while rx.try_recv().is_ok() {}
    let t0 = std::time::Instant::now();
    for i in 0..300 {
        c.state
            .scheduler
            .heavy
            .submit_fn("burst", &i.to_string(), Priority::P3, || async { Ok(()) });
    }
    let mut events = Vec::new();
    loop {
        match next_job(&mut rx).await {
            Ok(e) => {
                let last = e["phase"] == "end" && e["job"] == "burst:299";
                events.push(e);
                if last {
                    break;
                }
            }
            Err(_) => panic!("no end of the last job; got {} events", events.len()),
        }
    }
    let elapsed = t0.elapsed();
    let allowed = (elapsed.as_millis() / 100) as usize + 2;
    assert!(events.len() <= allowed, "{} events in {elapsed:?}", events.len());
    let sum = |k: &str| -> u64 { events.iter().map(|e| e[k].as_u64().unwrap()).sum() };
    assert!(sum("coalesced") > 0, "each end stands for its start");
    let max = picket_core::web::events::MAX_PENDING_JOB_REPORTS;
    assert!(
        sum("dropped") > 0,
        "300 jobs' ends overflow the {max} waiting: counted"
    );
    // Each of the 600 reports was sent, stood for by its job's end, or counted as dropped
    // (more if another job ran meanwhile).
    let total = events.len() as u64 + sum("coalesced") + sum("dropped");
    assert!(total >= 600, "{total} reports accounted for");
    let last = events.last().unwrap();
    assert!(
        last["heavy_depth"] == 0 && last["heavy_running"].is_null(),
        "the newest report comes last, the lane idle: {last}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    while let Ok(e) = rx.try_recv() {
        assert_ne!(e.kind, "job", "nothing after the newest report: {}", e.data);
    }
}

/// F7 (core.md §12: the UI routes on the client): an unknown non-API GET path is a client-side
/// route, served the UI document even when its last segment holds a dot (a device's address),
/// while a missing asset (under `assets/`, or a top-level file such as a script, icon or
/// manifest) is a 404 and never HTML; only GET and HEAD are served the document.
#[tokio::test(flavor = "multi_thread")]
async fn dotted_client_routes_get_the_ui_and_missing_assets_404() {
    let c = start_core(plain()).await;
    let pw = c.init.password.clone();
    for path in [
        "/clients/device/192.168.1.20",
        "/logs/qname/example.com",
        "/feeds/hagezi-tif",
        "/settings",
    ] {
        let r = get(&c, path, Some(&pw)).await;
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        assert!(
            r.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html"),
            "{path}"
        );
    }
    for path in [
        "/assets/missing-abc123.js",
        "/assets/sub/missing.css",
        "/assets/missing",
        "/missing.js",
        "/favicon.ico",
        "/robots.txt",
        "/site.webmanifest",
    ] {
        let r = get(&c, path, Some(&pw)).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        let body = r.text().await.unwrap();
        assert!(!body.contains("<html"), "{path}: {body}");
    }
    let r = ui(&c, reqwest::Method::POST, "/clients/device/192.168.1.20")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "a POST to a client route");
}

/// X2 (api.md §7 `job` events; README §2 Bounded): the reports of a burst are coalesced per job
/// (a job's end stands for its start not sent yet), never across jobs: each job's end reaches the
/// bus, a failure included, while the events stay paced.
#[tokio::test(flavor = "multi_thread")]
async fn job_events_never_lose_another_jobs_end() {
    use picket_core::scheduler::Priority;
    let c = start_core(plain()).await;
    let mut rx = c.state.events.subscribe();
    let idle = || {
        let h = c.state.scheduler.heavy.stats();
        h.queued == 0 && h.running.is_none()
    };
    for _ in 0..3 {
        common::feeds::wait_until("the heavy lane idle", || async { idle() }).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    while rx.try_recv().is_ok() {}
    let g1 = std::sync::Arc::new(tokio::sync::Notify::new());
    let g2 = std::sync::Arc::new(tokio::sync::Notify::new());
    let (a, b) = (g1.clone(), g2.clone());
    c.state
        .scheduler
        .heavy
        .submit_fn("gate", "g", Priority::P0, move || async move {
            a.notified().await;
            Ok(())
        });
    loop {
        let e = next_job(&mut rx).await.expect("the gate's start");
        if e["job"] == "gate:g" {
            break;
        }
    }
    // Within one gap: the gate ends, a quick job starts and fails, a long one starts.
    c.state
        .scheduler
        .heavy
        .submit_fn("quick", "x", Priority::P1, || async { anyhow::bail!("x failed") });
    c.state
        .scheduler
        .heavy
        .submit_fn("long", "y", Priority::P2, move || async move {
            b.notified().await;
            Ok(())
        });
    let t0 = std::time::Instant::now();
    g1.notify_one();
    let mut seen = Vec::new();
    while seen.len() < 3 {
        let e = next_job(&mut rx).await.expect("the burst's events");
        seen.push((
            e["phase"].as_str().unwrap().to_string(),
            e["job"].as_str().unwrap().to_string(),
            e["outcome"].as_str().map(str::to_string),
            e["coalesced"].as_u64().unwrap(),
            e["dropped"].as_u64(),
        ));
    }
    let elapsed = t0.elapsed();
    g2.notify_one();
    let names: Vec<_> = seen
        .iter()
        .map(|(p, j, o, _, _)| (p.as_str(), j.as_str(), o.as_deref()))
        .collect();
    assert_eq!(
        names,
        vec![
            ("end", "gate:g", Some("ok")),
            ("end", "quick:x", Some("failed")),
            ("start", "long:y", None),
        ],
        "{seen:?}"
    );
    assert_eq!(seen[1].3, 1, "the quick job's end stands for its start: {seen:?}");
    assert!(seen.iter().all(|s| s.4 == Some(0)), "nothing dropped: {seen:?}");
    assert!(
        elapsed >= picket_core::web::events::JOB_EVENT_GAP * 2,
        "paced: {elapsed:?}"
    );
}

/// X5 (README §2 JSON everywhere; api.md §7 error shape): a query or path value the UI API can't
/// read is answered with the API's JSON error object, on the import endpoints and every other.
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_query_and_path_values_get_the_json_error_shape() {
    let c = start_core(plain()).await;
    let pw = c.init.password.clone();
    let check = |what: String, r: reqwest::Response| async move {
        let st = r.status();
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let text = r.text().await.unwrap();
        assert_eq!(st, StatusCode::BAD_REQUEST, "{what}: {text}");
        assert!(ct.starts_with("application/json"), "{what}: {ct} {text}");
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        assert_eq!(v["error"]["code"], "bad_request", "{what}: {text}");
        assert!(
            v["error"]["message"].as_str().is_some_and(|m| !m.is_empty()),
            "{what}: {text}"
        );
    };
    for path in [
        "/api/ui/v1/feeds/import?id=p&redirects=maybe",
        "/api/ui/v1/feeds/import?id=p&format=nope",
        "/api/ui/v1/feeds/m/import?mode=merge&browser_changes=maybe",
    ] {
        let r = ui(&c, reqwest::Method::POST, path)
            .header("content-type", "application/json")
            .body(r#"{"file": "a.example\n"}"#)
            .send()
            .await
            .unwrap();
        check(format!("POST {path}"), r).await;
    }
    for path in [
        "/api/ui/v1/feeds?limit=lots",
        "/api/ui/v1/alerts?limit=-1",
        "/api/ui/v1/alerts/not-a-number",
        "/api/ui/v1/feeds/m/runs/not-a-number",
    ] {
        check(format!("GET {path}"), get(&c, path, Some(&pw)).await).await;
    }
}

/// `GET identity`'s `plain_http`, over `scheme`.
async fn plain_http_over(c: &Core, scheme: &str) -> Value {
    let r = client()
        .get(format!("{}/api/ui/v1/identity", c.base(scheme)))
        .basic_auth("admin", Some(&c.init.password))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json::<Value>().await.unwrap()["plain_http"].clone()
}

/// `PUT settings` with `patch`, over `scheme`.
async fn save_settings_over(c: &Core, scheme: &str, patch: Value) {
    let r = client()
        .put(format!("{}/api/ui/v1/settings", c.base(scheme)))
        .basic_auth("admin", Some(&c.init.password))
        .header("X-Picket-UI", "1")
        .json(&patch)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cleartext_warning_follows_the_connection_until_a_restart() {
    // core.md §12: with `web.tls` off the UI warns that credentials cross the network in clear.
    // A saved `web.tls` change applies at the next start, so a plain-HTTP port keeps warning
    // after `managed` is saved, and a TLS port doesn't start warning when `off` is.
    let c = start_core(plain()).await;
    assert_eq!(plain_http_over(&c, "http").await, json!(true));
    save_settings_over(&c, "http", json!({"web": {"tls": "managed"}})).await;
    assert_eq!(c.state.settings().web.tls, picket_core::settings::WebTls::Managed);
    assert_eq!(plain_http_over(&c, "http").await, json!(true), "still cleartext");

    let t = start_core(None).await;
    assert_eq!(plain_http_over(&t, "https").await, json!(false));
    save_settings_over(&t, "https", json!({"web": {"tls": "off"}})).await;
    assert_eq!(plain_http_over(&t, "https").await, json!(false), "still TLS");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unsupported_method_gets_the_error_shape_and_allow() {
    // api.md §7 (errors in the §2 shape) and RFC 9110 §15.5.6: a method a UI API route doesn't
    // take is a 405 with the routes' `Allow` and the JSON error body, nested entity routes too.
    let c = start_core(plain()).await;
    for (method, path, allowed) in [
        (reqwest::Method::DELETE, "/api/ui/v1/identity", vec!["GET"]),
        (reqwest::Method::PATCH, "/api/ui/v1/settings", vec!["GET", "PUT"]),
        (reqwest::Method::PATCH, "/api/ui/v1/clients", vec!["GET", "POST"]),
    ] {
        let r = ui(&c, method.clone(), path)
            .header("Content-Type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        let allow = r
            .headers()
            .get("allow")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        for m in allowed {
            assert!(
                allow.split(',').any(|a| a.trim() == m),
                "{method} {path}: Allow {allow:?}"
            );
        }
        let body: Value = r.json().await.unwrap_or(Value::Null);
        assert_eq!(
            body["error"]["code"], "method_not_allowed",
            "{method} {path}: {body}"
        );
    }
}
