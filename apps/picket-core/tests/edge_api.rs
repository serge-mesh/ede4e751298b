//! The edge port's key pinning (api.md §1, core.md §4): an unknown key is listed as pending
//! with its address and claimed name; one whose certificate claims a registered edge's name
//! raises `edge_key_mismatch`; a registered key is served (an unknown path answers `404` from the
//! edge API's fallback, which only a pinned connection reaches).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519, PublicKeyData};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// An edge identity like `picket-edge setup --name` makes: Ed25519, CN = the name.
fn edge_identity(name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>, String) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, name);
    let cert = p.self_signed(&key).unwrap();
    let fp = picket_api::ids::fingerprint_spki(&key.subject_public_key_info());
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        fp,
    )
}

/// Connects with a client certificate and sends one HTTP/1.1 request; returns the status line
/// (empty when the server closed the connection).
async fn request(port: u16, cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> String {
    request_from([127, 0, 0, 1], port, cert, key).await
}

/// [`request`] from a chosen loopback source address (another LAN host).
async fn request_from(
    src: [u8; 4],
    port: u16,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> String {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_client_auth_cert(vec![cert], key)
        .unwrap();
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(std::net::SocketAddr::from((src, 0))).unwrap();
    let tcp = sock
        .connect(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .unwrap();
    let Ok(mut tls) = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("core").unwrap(), tcp)
        .await
    else {
        return String::new();
    };
    let _ = tls
        .write_all(b"GET /v1/no-such-path HTTP/1.1\r\nHost: core\r\nConnection: close\r\n\r\n")
        .await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn pinning_pending_and_key_mismatch() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let port = c.info.edge.port();

    // An unknown key: no service, listed as pending with its claimed name.
    let (cert, key, fp) = edge_identity("garage-edge");
    assert_eq!(request(port, cert.clone(), key.clone_key()).await, "");
    let mut pending = vec![];
    for _ in 0..50 {
        pending = picket_core::edges::list_pending(&c.state.db).await.unwrap();
        if !pending.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key, fp);
    assert_eq!(pending[0].claimed_name.as_deref(), Some("garage-edge"));
    assert_eq!(pending[0].addr.as_deref(), Some("127.0.0.1"));
    // The listing carries the path form the approve and delete routes take (api.md §1).
    let hash = picket_api::ids::parse_fingerprint(&fp).unwrap();
    assert_eq!(pending[0].key_path, picket_api::ids::fingerprint_path(&hash));

    // A registered edge named "ucg"; another key claiming that name raises edge_key_mismatch.
    let (_, _, ucg_fp) = edge_identity("ucg");
    let edge = picket_core::config::model::EdgeDef {
        name: "ucg".into(),
        key: ucg_fp,
        ..Default::default()
    };
    picket_core::edges::add(&c.state.config, edge, picket_core::config::Actor::cli())
        .await
        .unwrap();
    let (imp_cert, imp_key, imp_fp) = edge_identity("ucg");
    assert_eq!(request(port, imp_cert, imp_key).await, "");
    let mut alert = None;
    for _ in 0..50 {
        let list = c.state.alerts.list(Default::default(), None, 10).await.unwrap();
        alert = list.into_iter().find(|a| a.kind == "edge_key_mismatch");
        if alert.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let alert = alert.expect("edge_key_mismatch raised");
    assert_eq!(alert.details["key"], imp_fp.as_str());
    assert_eq!(serde_json::to_value(alert.alert_type).unwrap(), "security");

    // Approving the pending key pins it: the connection is served.
    let edge = picket_core::config::model::EdgeDef {
        name: "garage".into(),
        ..Default::default()
    };
    picket_core::edges::approve_pending(&c.state.config, &fp, edge, picket_core::config::Actor::cli())
        .await
        .unwrap();
    let status = request(port, cert, key).await;
    assert!(status.starts_with("HTTP/1.1 404"), "{status:?}");
    assert!(
        picket_core::edges::list_pending(&c.state.db)
            .await
            .unwrap()
            .iter()
            .all(|p| p.key != fp)
    );
}

async fn pending_from(c: &common::Core, addr: &str) -> usize {
    picket_core::edges::list_pending(&c.state.db)
        .await
        .unwrap()
        .iter()
        .filter(|p| p.addr.as_deref() == Some(addr))
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn one_host_cannot_flood_alerts_or_the_pending_list() {
    // core.md §4, README §2 Bounded: fresh self-signed keys claiming a registered edge's name
    // raise one edge_key_mismatch per edge (its details name the latest key), and one host
    // gets a capped share of the pending list, so another host's key stays listed.
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let port = c.info.edge.port();
    let (_, _, ucg_fp) = edge_identity("ucg");
    let edge = picket_core::config::model::EdgeDef {
        name: "ucg".into(),
        key: ucg_fp,
        ..Default::default()
    };
    picket_core::edges::add(&c.state.config, edge, picket_core::config::Actor::cli())
        .await
        .unwrap();
    // A key from another host first.
    let (other_cert, other_key, other_fp) = edge_identity("garage");
    assert_eq!(
        request_from([127, 0, 0, 2], port, other_cert, other_key).await,
        ""
    );
    for _ in 0..40 {
        let (cert, key, _) = edge_identity("ucg");
        assert_eq!(request(port, cert, key).await, "");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let alerts = c
        .state
        .alerts
        .list(
            picket_core::alerts::AlertFilter {
                kind: Some("edge_key_mismatch".into()),
                ..Default::default()
            },
            None,
            100,
        )
        .await
        .unwrap();
    assert_eq!(alerts.len(), 1, "one alert per edge");
    assert!(
        alerts[0].count >= 2 && alerts[0].count <= 40,
        "{}",
        alerts[0].count
    );
    assert!(
        picket_core::edges::list_pending(&c.state.db)
            .await
            .unwrap()
            .iter()
            .any(|p| p.key == alerts[0].details["key"].as_str().unwrap()),
        "the alert names a recorded key"
    );
    assert!(
        pending_from(&c, "127.0.0.1").await <= picket_core::edges::MAX_PENDING_PER_ADDR,
        "one address's share of the pending list"
    );
    assert!(
        picket_core::edges::list_pending(&c.state.db)
            .await
            .unwrap()
            .iter()
            .any(|p| p.key == other_fp),
        "another host's key is still pending"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_key_rotation() {
    // build-and-test.md §5 "mTLS / TOFU", api.md §1 "Key change": a new edge key is refused
    // (pending, edge_key_mismatch) until the admin replaces the key; then the new key is served
    // and the old one refused.
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let port = c.info.edge.port();
    let (old_cert, old_key, old_fp) = edge_identity("ucg");
    let out = picket_core::edges::add(
        &c.state.config,
        picket_core::config::model::EdgeDef {
            name: "ucg".into(),
            key: old_fp.clone(),
            ..Default::default()
        },
        picket_core::config::Actor::cli(),
    )
    .await
    .unwrap();
    let status = request(port, old_cert.clone(), old_key.clone_key()).await;
    assert!(status.starts_with("HTTP/1.1 404"), "{status:?}");
    // The edge's identity/ was deleted: a new key with the same name.
    let (new_cert, new_key, new_fp) = edge_identity("ucg");
    assert_eq!(request(port, new_cert.clone(), new_key.clone_key()).await, "");
    assert!(
        picket_core::edges::list_pending(&c.state.db)
            .await
            .unwrap()
            .iter()
            .any(|p| p.key == new_fp)
    );
    let a = c
        .state
        .alerts
        .get_by_key(&format!("edge_key_mismatch:{}", out.id))
        .await
        .unwrap()
        .expect("edge_key_mismatch");
    assert_eq!(a.details["key"], new_fp.as_str());
    // The admin replaces the key (Edges → the edge → key).
    let mut body = out.entity.unwrap();
    body["key"] = json!(new_fp);
    c.state
        .config
        .apply(
            picket_core::config::model::EntityKind::Edge,
            picket_core::config::Op::Update(out.id.clone(), body),
            picket_core::config::Actor::cli(),
            None,
        )
        .await
        .unwrap();
    let status = request(port, new_cert, new_key).await;
    assert!(status.starts_with("HTTP/1.1 404"), "{status:?}");
    assert!(
        picket_core::edges::list_pending(&c.state.db)
            .await
            .unwrap()
            .iter()
            .all(|p| p.key != new_fp),
        "the replaced key is no longer pending"
    );
    assert_eq!(
        request(port, old_cert, old_key).await,
        "",
        "the old key is refused"
    );
}
