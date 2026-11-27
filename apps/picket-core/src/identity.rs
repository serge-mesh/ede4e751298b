//! Core's identity: a self-signed Ed25519 key and X.509 certificate in `identity/core.{key,crt}`
//! (0600), pinned by every edge (api.md §1, security.md §2, core.md §4). `init` generates it
//! unless one was pre-placed; its fingerprint is `SHA256:<base64 of SHA-256(SPKI DER)>`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519, PublicKeyData};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub const IDENTITY_DIR: &str = "identity";
pub const KEY_FILE: &str = "core.key";
pub const CERT_FILE: &str = "core.crt";

/// Core's loaded identity.
pub struct Identity {
    pub cert_pem: String,
    pub cert_der: CertificateDer<'static>,
    key_pkcs8_der: Vec<u8>,
    /// `SHA256:…` of the certificate's SubjectPublicKeyInfo.
    pub fingerprint: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

pub fn identity_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(IDENTITY_DIR)
}

impl Identity {
    /// Generates a new key and self-signed certificate with rcgen's default dates (1975 to 4096,
    /// so it never expires; api.md §1).
    pub fn generate() -> Result<(Self, String)> {
        let key = KeyPair::generate_for(&PKCS_ED25519).context("generate Ed25519 key")?;
        let cert = self_signed(&key)?;
        let key_pem = key.serialize_pem();
        let fingerprint = picket_api::ids::fingerprint_spki(&key.subject_public_key_info());
        Ok((
            Self {
                cert_pem: cert.pem(),
                cert_der: cert.der().clone(),
                key_pkcs8_der: key.serialize_der(),
                fingerprint,
            },
            key_pem,
        ))
    }

    /// Generates an identity and writes it to `dir` (created if missing), both files 0600.
    pub fn create(dir: &Path) -> Result<Self> {
        crate::util::ensure_dir(dir)?;
        let (id, key_pem) = Self::generate()?;
        crate::util::write_atomic(&dir.join(KEY_FILE), key_pem.as_bytes(), 0o600)?;
        crate::util::write_atomic(&dir.join(CERT_FILE), id.cert_pem.as_bytes(), 0o600)?;
        Ok(id)
    }

    /// Completes a pre-placed key with a self-signed certificate (0600): the pin is the key's
    /// SPKI, so a deployment may pre-place just `core.key`.
    pub fn complete(dir: &Path) -> Result<Self> {
        let key_path = dir.join(KEY_FILE);
        let key_pem =
            fs::read_to_string(&key_path).with_context(|| format!("read {}", key_path.display()))?;
        let key = KeyPair::from_pem(&key_pem).context("parse identity key")?;
        if key.algorithm() != &PKCS_ED25519 {
            bail!("the identity key must be Ed25519");
        }
        let cert_pem = self_signed(&key)?.pem();
        crate::util::write_atomic(&dir.join(CERT_FILE), cert_pem.as_bytes(), 0o600)?;
        Self::from_pem(&key_pem, &cert_pem)
    }

    /// Loads `identity/core.{key,crt}` and checks that the key belongs to the certificate.
    pub fn load(dir: &Path) -> Result<Self> {
        let key_path = dir.join(KEY_FILE);
        let cert_path = dir.join(CERT_FILE);
        let key_pem =
            fs::read_to_string(&key_path).with_context(|| format!("read {}", key_path.display()))?;
        let cert_pem =
            fs::read_to_string(&cert_path).with_context(|| format!("read {}", cert_path.display()))?;
        Self::from_pem(&key_pem, &cert_pem)
    }

    /// Builds an identity from PEM text, checking that the key is Ed25519 and matches the
    /// certificate (security.md §2).
    pub fn from_pem(key_pem: &str, cert_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("parse identity key")?;
        if key.algorithm() != &PKCS_ED25519 {
            bail!("the identity key must be Ed25519");
        }
        let cert_der = pem_to_der(cert_pem, "CERTIFICATE").context("parse identity certificate")?;
        let spki = cert_spki_der(&cert_der)?;
        if spki != key.subject_public_key_info() {
            bail!("the identity key doesn't belong to the identity certificate");
        }
        Ok(Self {
            cert_pem: cert_pem.to_string(),
            cert_der: CertificateDer::from(cert_der),
            key_pkcs8_der: key.serialize_der(),
            fingerprint: picket_api::ids::fingerprint_spki(&spki),
        })
    }

    /// The private key for rustls.
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()))
    }

    /// A rustls certified key for servers.
    pub fn certified_key(
        &self,
        provider: &rustls::crypto::CryptoProvider,
    ) -> Result<Arc<rustls::sign::CertifiedKey>> {
        let signing = provider
            .key_provider
            .load_private_key(self.private_key())
            .context("load identity key into rustls")?;
        Ok(Arc::new(rustls::sign::CertifiedKey::new(
            vec![self.cert_der.clone()],
            signing,
        )))
    }
}

/// Core's self-signed certificate for `key`: CN `picket-core`, rcgen's default dates (it never
/// expires, api.md §1).
fn self_signed(key: &KeyPair) -> Result<rcgen::Certificate> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "picket-core");
    params.self_signed(key).context("self-sign identity")
}

/// What a pre-placed `identity/` holds (core.md §4: core's identity can be pre-placed before
/// `init`, which keeps it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preplaced {
    /// Key and certificate: kept as they are.
    Both,
    /// The key alone: `init` self-signs a certificate for it.
    KeyOnly,
}

/// Checks a pre-placed identity without changing anything; refuses an unusable one.
pub fn check_preplaced(dir: &Path) -> Result<Preplaced> {
    let (key, cert) = (dir.join(KEY_FILE), dir.join(CERT_FILE));
    match (key.exists(), cert.exists()) {
        (true, true) => Identity::load(dir).map(|_| Preplaced::Both),
        (true, false) => {
            let pem = fs::read_to_string(&key).with_context(|| format!("read {}", key.display()))?;
            let k = KeyPair::from_pem(&pem).context("parse identity key")?;
            if k.algorithm() != &PKCS_ED25519 {
                bail!("the identity key must be Ed25519");
            }
            Ok(Preplaced::KeyOnly)
        }
        (false, true) => bail!("{} holds a certificate but no key ({KEY_FILE})", dir.display()),
        (false, false) => bail!("{} holds neither {KEY_FILE} nor {CERT_FILE}", dir.display()),
    }
}

/// Reads the fingerprint from `identity/core.crt` without the key (`picket-core identity`).
pub fn fingerprint_from_cert_file(dir: &Path) -> Result<String> {
    let cert_path = dir.join(CERT_FILE);
    let pem = fs::read_to_string(&cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let der = pem_to_der(&pem, "CERTIFICATE")?;
    Ok(picket_api::ids::fingerprint_spki(&cert_spki_der(&der)?))
}

/// The SubjectPublicKeyInfo DER of a certificate.
pub fn cert_spki_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| anyhow::anyhow!("parse certificate: {e}"))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// The `SHA256:…` fingerprint of a certificate's SPKI.
pub fn cert_fingerprint(cert_der: &[u8]) -> Result<String> {
    Ok(picket_api::ids::fingerprint_spki(&cert_spki_der(cert_der)?))
}

/// The subject CN of a certificate, if any (edges put their name there, api.md §1).
pub fn cert_common_name(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()?
        .as_str()
        .ok()?
        .to_string();
    Some(cn)
}

/// Decodes the first PEM block with label `label`.
pub fn pem_to_der(pem_text: &str, label: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem_text
        .find(&begin)
        .with_context(|| format!("no {label} PEM block"))?
        + begin.len();
    let stop = pem_text[start..]
        .find(&end)
        .with_context(|| format!("unterminated {label} PEM block"))?
        + start;
    let b64: String = pem_text[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("bad PEM base64")
}

/// The rustls crypto provider core uses everywhere (aws-lc-rs, build-and-test.md §2).
pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_load_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let id = Identity::create(d.path()).unwrap();
        assert!(id.fingerprint.starts_with("SHA256:"));
        let again = Identity::load(d.path()).unwrap();
        assert_eq!(id.fingerprint, again.fingerprint);
        assert_eq!(fingerprint_from_cert_file(d.path()).unwrap(), id.fingerprint);
        assert_eq!(cert_common_name(&id.cert_der).unwrap(), "picket-core");
        use std::os::unix::fs::PermissionsExt;
        for f in [KEY_FILE, CERT_FILE] {
            let m = fs::metadata(d.path().join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
        // The certificate never expires (rcgen defaults).
        let (_, cert) = x509_parser::parse_x509_certificate(&id.cert_der).unwrap();
        assert!(cert.validity().not_after.timestamp() > 4_000_000_000);
    }

    #[test]
    fn mismatched_key_refused() {
        let (a, _) = Identity::generate().unwrap();
        let (_, key_b) = Identity::generate().unwrap();
        assert!(Identity::from_pem(&key_b, &a.cert_pem).is_err());
    }
}
