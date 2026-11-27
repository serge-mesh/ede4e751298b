//! An in-process fake edge (api.md §1–§5): an Ed25519 identity like `picket-edge` makes, a
//! rustls client that pins core's key and presents the edge's certificate, the REST calls and
//! the WebSocket session.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519, PublicKeyData};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use serde_json::{Value, json};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::Core;
use jiff::Timestamp;

/// How long [`FakeEdge::post_logs`] resends a batch core answers `503` (a real edge resends from
/// its spool until core acks).
pub const LOG_RETRY_FOR: Duration = Duration::from_secs(60);

/// Accepts the server certificate whose SPKI hash is pinned (api.md §1).
#[derive(Debug)]
pub struct PinCore {
    provider: Arc<rustls::crypto::CryptoProvider>,
    fingerprint: String,
}

impl ServerCertVerifier for PinCore {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_, c) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if picket_api::ids::fingerprint_spki(c.tbs_certificate.subject_pki.raw) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub type Ws = WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// A fake edge.
pub struct FakeEdge {
    pub name: String,
    pub cert: CertificateDer<'static>,
    key_der: Vec<u8>,
    pub fingerprint: String,
    /// The fingerprint's path form (`configs/<fp>.json`).
    pub fp_path: String,
    pub port: u16,
    pub core_fp: String,
    pub http: reqwest::Client,
    /// The id core gave it (empty until registered).
    pub id: String,
}

impl FakeEdge {
    /// A new identity for `core` (not registered yet).
    pub fn new(core: &Core, name: &str) -> Self {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, name);
        let cert = p.self_signed(&key).unwrap();
        let fingerprint = picket_api::ids::fingerprint_spki(&key.subject_public_key_info());
        let fp_path =
            picket_api::ids::fingerprint_path(&picket_api::ids::parse_fingerprint(&fingerprint).unwrap());
        let mut e = Self {
            name: name.to_string(),
            cert: cert.der().clone(),
            key_der: key.serialize_der(),
            fingerprint,
            fp_path,
            port: core.info.edge.port(),
            core_fp: core.info.fingerprint.clone(),
            http: reqwest::Client::new(),
            id: String::new(),
        };
        e.http = reqwest::Client::builder()
            .no_proxy()
            .tls_backend_preconfigured(e.tls_config())
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        e
    }

    /// A new identity, registered on `core` under its name.
    pub async fn registered(core: &Core, name: &str) -> Self {
        let mut e = Self::new(core, name);
        let out = picket_core::edges::add(
            &core.state.config,
            picket_core::config::model::EdgeDef {
                name: name.into(),
                key: e.fingerprint.clone(),
                ..Default::default()
            },
            picket_core::config::Actor::cli(),
        )
        .await
        .unwrap();
        e.id = out.id;
        e
    }

    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    /// TLS 1.3, core's key pinned, the edge's certificate presented.
    pub fn tls_config(&self) -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinCore {
                provider,
                fingerprint: self.core_fp.clone(),
            }))
            .with_client_auth_cert(vec![self.cert.clone()], self.key())
            .unwrap();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        cfg
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    /// The edge's own config object key.
    pub fn config_path(&self) -> String {
        format!("/objects/configs/{}.json", self.fp_path)
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.http.get(self.url(path)).send().await.unwrap()
    }

    /// Fetches the edge's config object: (status, ETag, parsed body).
    pub async fn config(&self, if_none_match: Option<&str>) -> (u16, Option<String>, Value) {
        let mut req = self.http.get(self.url(&self.config_path()));
        if let Some(e) = if_none_match {
            req = req.header("If-None-Match", format!("\"{e}\""));
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        let etag = r
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string());
        let body = r.bytes().await.unwrap();
        let v = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, etag, v)
    }

    /// `POST /v1/logs` with the lines gzip-compressed, resent while core answers `503`, as the
    /// edge's spool resends (core.md §6: a failure that isn't the record's, such as a partition
    /// still busy past its `busy_timeout` under load, gets `503` and the edge retries), for up to
    /// [`LOG_RETRY_FOR`]. A test that expects a `503` uses [`FakeEdge::post_logs_once`].
    pub async fn post_logs(&self, lines: &[Value]) -> reqwest::Response {
        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        let body = gzip(text.as_bytes());
        let end = tokio::time::Instant::now() + LOG_RETRY_FOR;
        let mut wait = Duration::from_millis(100);
        loop {
            let r = self.post_raw_logs(body.clone()).await;
            if r.status() != reqwest::StatusCode::SERVICE_UNAVAILABLE
                || tokio::time::Instant::now() + wait > end
            {
                return r;
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(Duration::from_secs(2));
        }
    }

    /// `POST /v1/logs` once, with the lines gzip-compressed (a test of the `503` itself).
    pub async fn post_logs_once(&self, lines: &[Value]) -> reqwest::Response {
        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        self.post_raw_logs(gzip(text.as_bytes())).await
    }

    pub async fn post_raw_logs(&self, body: Vec<u8>) -> reqwest::Response {
        self.http
            .post(self.url("/v1/logs"))
            .header("Content-Encoding", "gzip")
            .header("Content-Type", "application/jsonl")
            .body(body)
            .send()
            .await
            .unwrap()
    }

    /// Opens the WebSocket session.
    pub async fn connect(&self) -> Ws {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
            .await
            .unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(self.tls_config()))
            .connect(ServerName::try_from("core").unwrap(), tcp)
            .await
            .unwrap();
        let req = format!("wss://127.0.0.1:{}/v1/session", self.port)
            .into_client_request()
            .unwrap();
        let (ws, _) = tokio_tungstenite::client_async(req, tls).await.unwrap();
        ws
    }

    /// Opens a session and sends `hello`; returns the stream and the `welcome`.
    pub async fn session(&self, hello: Value) -> (Ws, Value) {
        let mut ws = self.connect().await;
        send(&mut ws, json!({"type": "hello", "data": hello})).await;
        let welcome = recv_type(&mut ws, "welcome").await.expect("welcome");
        (ws, welcome)
    }
}

/// A minimal hello.
pub fn hello(boot: &str) -> Value {
    json!({"edge_version": picket_api::VERSION, "arch": "x86_64", "os": "debian", "kernel": "6.1",
           "platform": "debian", "boot": boot, "allowed_binds": ["*"], "updates_enabled": true,
           "have": {}, "starts": 0, "conditions": [], "applied": {}})
}

/// A minimal heartbeat at `ts` with `queries` total.
pub fn heartbeat(boot: &str, ts: Timestamp, up_ms: u64, queries: u64) -> Value {
    json!({"ts": picket_api::time::format_micros(&ts), "boot": boot, "up_ms": up_ms,
           "metrics": {"queries": queries, "by_decision": {"allow": queries}},
           "have": {}, "conditions": [], "applied": {}})
}

pub async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

/// The next message of `kind` within 10 s (other messages are skipped).
pub async fn recv_type(ws: &mut Ws, kind: &str) -> Option<Value> {
    let end = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let m = tokio::time::timeout_at(end, ws.next()).await.ok()??;
        match m {
            Ok(Message::Text(t)) => {
                let v: Value = serde_json::from_str(t.as_str()).ok()?;
                if v["type"] == kind {
                    return Some(v["data"].clone());
                }
            }
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

/// The next `changed` announcing an ETag other than `old` (an edge may be told about the object
/// it already holds, e.g. the first publication of a new edge's config).
pub async fn recv_changed(ws: &mut Ws, old: &str) -> Option<String> {
    loop {
        let v = recv_type(ws, "changed").await?;
        let etag = v["etag"].as_str()?.to_string();
        if etag != old {
            return Some(etag);
        }
    }
}

/// True when the session gets closed within 10 s.
pub async fn closed(ws: &mut Ws) -> bool {
    let end = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(end, ws.next()).await {
            Err(_) => return false,
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return true,
            Ok(Some(Ok(_))) => {}
        }
    }
}

pub fn gzip(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

/// Polls `f` until it is true or 60 s pass: generous, since CI runs the suite as root on a slower
/// shared machine and the dev host can stall every process for seconds (only the time to a
/// failure grows).
pub async fn eventually<F, Fut>(mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let end = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < end {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f().await
}

/// An `answer` record and its id.
pub fn answer(boot: &str, seq: u64, ts: &str, wire: &[u8]) -> (Value, String) {
    use base64::Engine as _;
    let id = picket_api::ids::short_id(&picket_api::ids::object_id(wire)).to_string();
    (
        json!({"t": "answer", "ts": ts, "boot": boot, "seq": seq, "id": id,
               "wire": base64::engine::general_purpose::STANDARD.encode(wire)}),
        id,
    )
}

/// A `q` record.
pub fn query(boot: &str, seq: u64, ts: &str, qname: &str, answer_id: Option<&str>) -> Value {
    let mut v = json!({"t": "q", "ts": ts, "boot": boot, "seq": seq, "listener": "lan-dns", "proto": "udp",
        "client": "192.168.1.140", "device": "emma-tablet", "profile": "kids", "qname": qname, "qtype": "A",
        "do": false, "rcode": "NOERROR", "decision": "allow", "answers": ["192.0.2.1"], "targets": [],
        "truncated": false, "cname": [], "lookups": [], "upstream": {"group": "cloudflare", "upstream": "cf-dot", "ms": 3, "cached": false, "stale": false},
        "fw": null, "us": {"total": 41, "filter": 6},
        "versions": {"config": "9f3a91c27d0e4b6a", "bundles": {"allow-common": "4be1d2a07c9e3f15"}}});
    if let Some(a) = answer_id {
        v["answer_id"] = json!(a);
    }
    v
}
