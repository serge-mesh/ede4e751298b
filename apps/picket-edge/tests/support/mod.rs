//! An in-process mock of picket-core's edge API (api.md §2, §3): TLS 1.3 with a self-signed
//! Ed25519 identity, client certificates required (any key accepted and recorded), the
//! `objects` bucket for the edge's config object, `POST /v1/logs` and the WebSocket session.

#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

use std::collections::VecDeque;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName as TlsDn, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::Role;

use picket_api::session::{Heartbeat, Hello, SessionMessage, Welcome};
use picket_api::time::Timestamp;

/// Core's identity.
pub struct CoreIdentity {
    pub cert: CertificateDer<'static>,
    pub key: PrivatePkcs8KeyDer<'static>,
    pub fingerprint: String,
}

impl CoreIdentity {
    /// The same identity again (a core restarted with its key).
    pub fn same(&self) -> CoreIdentity {
        CoreIdentity {
            cert: self.cert.clone(),
            key: self.key.clone_key(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

pub fn core_identity() -> CoreIdentity {
    let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "picket-core");
    p.distinguished_name = dn;
    let cert = p.self_signed(&kp).unwrap();
    CoreIdentity {
        cert: cert.der().clone(),
        key: PrivatePkcs8KeyDer::from(kp.serialize_der()),
        fingerprint: picket_api::ids::fingerprint_spki(&kp.subject_public_key_info()),
    }
}

#[derive(Debug)]
struct AnyClient {
    seen: Arc<Mutex<Vec<String>>>,
}

impl ClientCertVerifier for AnyClient {
    fn root_hint_subjects(&self) -> &[TlsDn] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, c) = x509_parser::parse_x509_certificate(end_entity.as_ref()).unwrap();
        self.seen.lock().unwrap().push(picket_api::ids::fingerprint_spki(
            c.tbs_certificate.subject_pki.raw,
        ));
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// What the mock recorded and what it serves.
#[derive(Default)]
pub struct MockState {
    pub hellos: Vec<Hello>,
    pub heartbeats: Vec<Heartbeat>,
    pub logs: Vec<serde_json::Value>,
    pub log_batches: usize,
    /// The edge's config object; `None` → 404.
    pub config: Option<Vec<u8>>,
    /// Answer 403 to config fetches.
    pub forbid_config: bool,
    /// Each config fetch's `If-None-Match` header.
    pub fetches: Vec<Option<String>>,
    /// Status codes for the next log posts (default 200).
    pub log_script: VecDeque<u16>,
    /// The default log status once the script is empty.
    pub log_default: u16,
    pub sessions: u32,
    pub client_fps: Vec<String>,
    /// `objects/<key>` → bytes, for keys other than configs.
    pub objects: std::collections::HashMap<String, Vec<u8>>,
    /// How many times each object other than configs was asked for.
    pub object_gets: std::collections::HashMap<String, u32>,
    /// Objects answered only after a delay (a slow download).
    pub object_delays: std::collections::HashMap<String, std::time::Duration>,
    /// CSR bodies received.
    pub csrs: Vec<serde_json::Value>,
    /// When set, CSRs are signed by a test CA (key PEM, cert PEM) with these SANs and validity;
    /// otherwise the answer is a placeholder.
    pub csr_signer: Option<CsrSigner>,
    /// Answer the next CSRs with 503.
    pub csr_fail: u32,
}

/// A LAN CA stand-in for CSR tests.
#[derive(Clone)]
pub struct CsrSigner {
    pub ca_key_pem: String,
    pub ca_cert_pem: String,
    pub dns_names: Vec<String>,
    pub ips: Vec<std::net::IpAddr>,
    /// (year, month, day) of `not_before`; `not_after` is 397 days later.
    pub not_before: (i32, u8, u8),
}

impl CsrSigner {
    pub fn new(names: &[&str], ips: &[&str], not_before: (i32, u8, u8)) -> Self {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test LAN CA");
        p.distinguished_name = dn;
        let cert = p.self_signed(&kp).unwrap();
        Self {
            ca_key_pem: kp.serialize_pem(),
            ca_cert_pem: cert.pem(),
            dns_names: names.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
            not_before,
        }
    }

    /// Signs a CSR: the key from the CSR, the SANs and validity from the signer (core takes
    /// them from the listener's config, api.md §2).
    pub fn sign(&self, csr_pem: &str) -> Option<(String, String)> {
        let mut req = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).ok()?;
        let mut sans: Vec<rcgen::SanType> = self
            .dns_names
            .iter()
            .map(|n| rcgen::SanType::DnsName(n.clone().try_into().unwrap()))
            .collect();
        sans.extend(self.ips.iter().map(|ip| rcgen::SanType::IpAddress(*ip)));
        req.params.subject_alt_names = sans;
        let (y, m, d) = self.not_before;
        req.params.not_before = rcgen::date_time_ymd(y, m, d);
        req.params.not_after = req.params.not_before + std::time::Duration::from_secs(397 * 86_400);
        let ca_kp = KeyPair::from_pem(&self.ca_key_pem).ok()?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test LAN CA");
        ca_params.distinguished_name = dn;
        let issuer = rcgen::Issuer::new(ca_params, ca_kp);
        let cert = req.signed_by(&issuer).ok()?;
        Some((cert.pem(), self.ca_cert_pem.clone()))
    }
}

pub struct MockCore {
    pub addr: SocketAddr,
    pub id: CoreIdentity,
    pub state: Arc<Mutex<MockState>>,
    changed: broadcast::Sender<String>,
    kick: broadcast::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockCore {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockCore {
    pub async fn start() -> Self {
        Self::start_with(core_identity(), None).await
    }

    /// `bad_signer`: present `id`'s certificate but sign the handshake with another key.
    pub async fn start_with(id: CoreIdentity, bad_signer: Option<()>) -> Self {
        let state = Arc::new(Mutex::new(MockState {
            log_default: 200,
            ..Default::default()
        }));
        let seen = Arc::new(Mutex::new(vec![]));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(AnyClient {
                seen: Arc::clone(&seen),
            }));
        let mut cfg = if bad_signer.is_some() {
            let other = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
                PrivatePkcs8KeyDer::from(other.serialize_der()),
            ))
            .unwrap();
            let ck = Arc::new(rustls::sign::CertifiedKey::new(vec![id.cert.clone()], signer));
            builder.with_cert_resolver(Arc::new(Fixed(ck)))
        } else {
            builder
                .with_single_cert(vec![id.cert.clone()], PrivateKeyDer::Pkcs8(id.key.clone_key()))
                .unwrap()
        };
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (changed, _) = broadcast::channel(16);
        let (kick, _) = broadcast::channel(4);
        let st = Arc::clone(&state);
        let ch = changed.clone();
        let kk = kick.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let st = Arc::clone(&st);
                let ch = ch.clone();
                let kk = kk.clone();
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    st.lock().unwrap().client_fps = seen.lock().unwrap().clone();
                    let svc = service_fn(move |req| handle(req, Arc::clone(&st), ch.clone(), kk.clone()));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        Self {
            addr,
            id,
            state,
            changed,
            kick,
            task,
        }
    }

    /// Drops every open session (the edge reconnects).
    pub fn kick(&self) {
        let _ = self.kick.send(());
    }

    pub fn url(&self) -> String {
        format!("https://{}", self.addr)
    }

    /// Serves `v` as the edge's config object; returns its id.
    pub fn set_config(&self, v: &serde_json::Value) -> String {
        let bytes = serde_json::to_vec(v).unwrap();
        let id = picket_api::ids::object_id(&bytes);
        self.state.lock().unwrap().config = Some(bytes);
        id
    }

    /// Sends `changed` on every open session.
    pub fn changed(&self, etag: &str) {
        let _ = self.changed.send(etag.to_owned());
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut MockState) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }
}

#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

type Body = Full<Bytes>;

fn resp(status: u16, body: impl Into<Bytes>) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Full::new(body.into()))
        .unwrap()
}

async fn handle(
    req: Request<Incoming>,
    st: Arc<Mutex<MockState>>,
    changed: broadcast::Sender<String>,
    kick: broadcast::Sender<()>,
) -> Result<Response<Body>, std::convert::Infallible> {
    let path = req.uri().path().to_owned();
    if path == "/v1/session" {
        let key = req
            .headers()
            .get("sec-websocket-key")
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default();
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(&key);
        let st2 = Arc::clone(&st);
        let rx = changed.subscribe();
        let kick_rx = kick.subscribe();
        tokio::spawn(async move {
            if let Ok(up) = hyper::upgrade::on(req).await {
                let ws = WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Server, None).await;
                session(ws, st2, rx, kick_rx).await;
            }
        });
        return Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-accept", accept)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    if path == "/v1/logs" {
        let body = req
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let mut text = String::new();
        if flate2::read::GzDecoder::new(&body[..])
            .read_to_string(&mut text)
            .is_err()
        {
            return Ok(resp(400, ""));
        }
        let code = {
            let mut s = st.lock().unwrap();
            s.log_script.pop_front().unwrap_or(s.log_default)
        };
        if code != 200 {
            return Ok(resp(code, ""));
        }
        let mut s = st.lock().unwrap();
        s.log_batches += 1;
        let mut max = 0;
        for l in text.lines() {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            max = max.max(v["seq"].as_u64().unwrap_or(0));
            s.logs.push(v);
        }
        return Ok(resp(200, format!(r#"{{"acked":{{"boot":"x","seq":{max}}}}}"#)));
    }
    if let Some(key) = path.strip_prefix("/objects/") {
        let inm = req
            .headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_owned());
        let (body, delay) = {
            let mut s = st.lock().unwrap();
            if key.starts_with("configs/") {
                s.fetches.push(inm.clone());
                if s.forbid_config {
                    return Ok(resp(403, ""));
                }
                let Some(cfg) = s.config.clone() else {
                    return Ok(resp(404, ""));
                };
                let id = picket_api::ids::object_id(&cfg);
                if inm.as_deref() == Some(id.as_str()) {
                    return Ok(resp(304, ""));
                }
                return Ok(Response::builder()
                    .status(200)
                    .header(header::ETAG, format!("\"{id}\""))
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(Full::new(Bytes::from(cfg)))
                    .unwrap());
            }
            *s.object_gets.entry(key.to_owned()).or_default() += 1;
            (s.objects.get(key).cloned(), s.object_delays.get(key).copied())
        };
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        return Ok(match body {
            Some(b) => resp(200, b),
            None => resp(404, ""),
        });
    }
    if path == "/v1/csr" {
        let body = req
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let (signer, fail) = {
            let mut g = st.lock().unwrap();
            g.csrs.push(v.clone());
            let fail = g.csr_fail > 0;
            if fail {
                g.csr_fail -= 1;
            }
            (g.csr_signer.clone(), fail)
        };
        if fail {
            return Ok(resp(503, ""));
        }
        if let Some(s) = signer {
            return Ok(match s.sign(v["csr_pem"].as_str().unwrap_or("")) {
                Some((cert, chain)) => resp(
                    200,
                    serde_json::to_string(&serde_json::json!({
                        "cert_pem": cert, "chain_pem": chain, "not_after": "2030-01-01T00:00:00Z"
                    }))
                    .unwrap(),
                ),
                None => resp(400, ""),
            });
        }
        return Ok(resp(
            200,
            r#"{"cert_pem":"-----BEGIN CERTIFICATE-----","chain_pem":"","not_after":"2027-12-01T00:00:00Z"}"#,
        ));
    }
    Ok(resp(404, ""))
}

async fn session(
    ws: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    st: Arc<Mutex<MockState>>,
    mut changed: broadcast::Receiver<String>,
    mut kick: broadcast::Receiver<()>,
) {
    let (mut sink, mut stream) = ws.split();
    st.lock().unwrap().sessions += 1;
    loop {
        tokio::select! {
            _ = kick.recv() => {
                let _ = sink.send(Message::Close(None)).await;
                return;
            }
            m = stream.next() => {
                let Some(Ok(m)) = m else { return };
                if let Message::Text(t) = m {
                    match serde_json::from_str::<SessionMessage>(&t) {
                        Ok(SessionMessage::Hello(h)) => {
                            st.lock().unwrap().hellos.push(*h);
                            let w = SessionMessage::Welcome(Welcome {
                                core_version: "0.1.0".into(),
                                edge_id: "e-01".into(),
                                edge_name: "test-edge".into(),
                                server_time: Timestamp::now(),
                            });
                            let _ = sink.send(Message::Text(serde_json::to_string(&w).unwrap().into())).await;
                        }
                        Ok(SessionMessage::Heartbeat(h)) => st.lock().unwrap().heartbeats.push(*h),
                        _ => {}
                    }
                }
            }
            e = changed.recv() => {
                let Ok(etag) = e else { continue };
                let m = SessionMessage::Changed(picket_api::session::Changed { etag });
                let _ = sink.send(Message::Text(serde_json::to_string(&m).unwrap().into())).await;
            }
        }
    }
}

/// Polls `f` until it is true or `timeout` passes.
pub async fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < end {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    f()
}

/// Writes an `edge.json` pinning `core`.
pub fn write_edge_json(path: &Path, core: Option<&MockCore>, extra: serde_json::Value) {
    let mut v = serde_json::json!({"updates_enabled": false});
    if let Some(c) = core {
        v["core_url"] = c.url().into();
        v["core_key"] = c.id.fingerprint.clone().into();
    }
    if let (Some(m), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        for (k, x) in e {
            m.insert(k.clone(), x.clone());
        }
    }
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}
