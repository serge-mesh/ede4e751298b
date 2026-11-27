//! mTLS to core with key pinning (api.md §1): a custom `ServerCertVerifier` accepts a server whose
//! SubjectPublicKeyInfo SHA-256 equals the pinned `core_key`. Names and CAs are ignored; the
//! certificate's validity dates and the TLS handshake signature are checked as usual. The edge
//! authenticates with its own identity. TLS 1.3 only (api.md: "TLS 1.3, rustls").
//!
//! For `setup` (TOFU) the verifier runs unpinned and records the server's fingerprint only after
//! the server proved it holds the key (its CertificateVerify signature checked out), so a key is
//! never "seen" before verification succeeded.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::identity::{self, Identity};

/// How the verifier treats core's key.
#[derive(Clone, Debug)]
pub enum Pin {
    /// Accept only this SPKI SHA-256.
    Key([u8; 32]),
    /// Accept any key (TOFU in `setup`); the verified fingerprint is recorded.
    Tofu,
}

/// The edge's verifier for core's certificate.
#[derive(Debug)]
pub struct CoreVerifier {
    pin: Pin,
    algs: WebPkiSupportedAlgorithms,
    /// The fingerprint of the key that signed the handshake, set only after its signature
    /// verified.
    verified: Mutex<Option<String>>,
    /// The fingerprint core presented when it didn't match the pin.
    mismatch: Mutex<Option<String>>,
}

impl CoreVerifier {
    pub fn new(pin: Pin) -> Arc<Self> {
        Arc::new(Self {
            pin,
            algs: rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            verified: Mutex::new(None),
            mismatch: Mutex::new(None),
        })
    }

    /// Builds a pinned verifier from a `SHA256:…` fingerprint.
    pub fn pinned(fp: &str) -> Result<Arc<Self>> {
        let hash = picket_api::ids::parse_fingerprint(fp).ok_or_else(|| anyhow!("bad core_key {fp:?}"))?;
        Ok(Self::new(Pin::Key(hash)))
    }

    /// The fingerprint whose handshake signature verified (TOFU), if any.
    pub fn verified_fingerprint(&self) -> Option<String> {
        self.verified.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The fingerprint core presented the last time it didn't match the pin.
    pub fn last_mismatch(&self) -> Option<String> {
        self.mismatch.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn check_validity(cert: &CertificateDer<'_>, now: UnixTime) -> Result<(), TlsError> {
        let (_, c) = x509_parser::parse_x509_certificate(cert.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        let secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        let at = x509_parser::time::ASN1Time::from_timestamp(secs)
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        let v = c.validity();
        if at < v.not_before {
            return Err(TlsError::InvalidCertificate(CertificateError::NotValidYet));
        }
        if at > v.not_after {
            return Err(TlsError::InvalidCertificate(CertificateError::Expired));
        }
        Ok(())
    }

    fn record_verified(&self, cert: &CertificateDer<'_>) {
        if let Ok(fp) = identity::cert_fingerprint(cert) {
            *self.verified.lock().unwrap_or_else(|p| p.into_inner()) = Some(fp);
        }
    }
}

impl ServerCertVerifier for CoreVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Self::check_validity(end_entity, now)?;
        let spki = identity::spki_of_cert(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        match &self.pin {
            Pin::Key(want) => {
                let got: [u8; 32] = sha256(&spki);
                if &got != want {
                    let presented = picket_api::ids::fingerprint_from_hash(&got);
                    *self.mismatch.lock().unwrap_or_else(|p| p.into_inner()) = Some(presented);
                    return Err(TlsError::InvalidCertificate(
                        CertificateError::ApplicationVerificationFailure,
                    ));
                }
            }
            Pin::Tofu => {}
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let ok = rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)?;
        self.record_verified(cert);
        Ok(ok)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let ok = rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)?;
        self.record_verified(cert);
        Ok(ok)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// SHA-256 of `b`, through picket-api's fingerprint helper (the one definition of the hash).
/// True when `e` is our verifier refusing core's key (the pin didn't match), as opposed to any
/// other connect or TLS failure.
pub fn is_pin_mismatch(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        let tls = c
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
            .and_then(|i| i.downcast_ref::<TlsError>());
        matches!(
            tls.or_else(|| c.downcast_ref::<TlsError>()),
            Some(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure
            ))
        )
    })
}

fn sha256(b: &[u8]) -> [u8; 32] {
    picket_api::ids::parse_fingerprint(&picket_api::ids::fingerprint_spki(b)).unwrap_or_default()
}

/// The rustls client config for core: TLS 1.3, the given verifier, the edge identity for client
/// auth, ALPN `http/1.1` (REST and the WebSocket upgrade).
pub fn client_config(id: &Identity, verifier: Arc<CoreVerifier>) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![id.cert_der.clone()], id.private_key())
        .context("edge identity for client auth")?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Connects TCP + TLS to `addr` within `timeout`.
pub async fn connect(
    addr: SocketAddr,
    cfg: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<TlsStream<TcpStream>> {
    let fut = async {
        let tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to {addr}"))?;
        let _ = tcp.set_nodelay(true);
        let name = ServerName::IpAddress(addr.ip().into());
        TlsConnector::from(cfg)
            .connect(name, tcp)
            .await
            .with_context(|| format!("TLS with {addr}"))
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow!("connecting to {addr}: timed out after {timeout:?}"))?
}
