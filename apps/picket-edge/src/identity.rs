//! The edge identity (api.md §1, security.md §2): an Ed25519 key and a self-signed certificate
//! (`rcgen` default dates, so it never expires) in `<data_dir>/identity/{key.pem,cert.pem}`, 0600.
//! The certificate's CN is the edge's name (default: the hostname); `setup --name` reissues the
//! certificate with the same key, so core's pin doesn't change.
//!
//! The identity directory is opened without following symlinks and files inside it relative to
//! that descriptor; run as root (`setup`, `key`), new files are handed to `picket` through
//! `fchown` on their own descriptors.

use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::fsutil::{self, Owner, WriteOpts};
use crate::paths::DataLayout;
use crate::users;

const KEY_FILE: &str = "key.pem";
const CERT_FILE: &str = "cert.pem";
const MAX_PEM: u64 = 64 << 10;
/// X.509 upper bound for a common name.
pub const MAX_NAME: usize = 64;

/// The loaded identity. The private key never appears in `Debug` output.
pub struct Identity {
    pub cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    /// `SHA256:<base64 of SHA-256(SPKI DER)>`.
    pub fingerprint: String,
    /// The certificate's CN.
    pub name: String,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            cert_der: self.cert_der.clone(),
            key_der: self.key_der.clone_key(),
            fingerprint: self.fingerprint.clone(),
            name: self.name.clone(),
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// The private key for rustls client auth.
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key_der.clone_key())
    }

    /// The path form of the fingerprint (`configs/<fp>.json`, api.md §1).
    pub fn fp_path(&self) -> String {
        let hash = picket_api::ids::parse_fingerprint(&self.fingerprint).unwrap_or_default();
        picket_api::ids::fingerprint_path(&hash)
    }
}

/// The default name: the host name (api.md §1), cut to a valid CN.
pub fn default_name() -> String {
    let uname = rustix::system::uname();
    let n = uname.nodename().to_string_lossy().into_owned();
    let n = sanitize_name(&n);
    if n.is_empty() { "picket-edge".into() } else { n }
}

fn sanitize_name(n: &str) -> String {
    let s: String = n.chars().filter(|c| !c.is_control()).collect();
    crate::diag::truncate(s.trim(), MAX_NAME)
        .trim_end_matches('…')
        .to_owned()
}

/// Checks a `setup --name` value.
pub fn validate_name(n: &str) -> Result<()> {
    if n.trim().is_empty() || n.len() > MAX_NAME || n.chars().any(char::is_control) || n.trim() != n {
        bail!("edge name must be 1–{MAX_NAME} printable characters without leading or trailing spaces");
    }
    Ok(())
}

/// The owner new identity files get: `picket` when root runs this (so the service can read
/// them), else whoever runs it.
fn file_owner() -> Owner {
    if users::is_root() {
        Owner {
            uid: users::picket_uid(),
            gid: users::picket_gid(),
        }
    } else {
        Owner::default()
    }
}

fn open_identity_dir(layout: &DataLayout) -> Result<OwnedFd> {
    let dir = layout.identity_dir();
    fsutil::ensure_dir_nofollow(&dir, 0o700, file_owner())
        .with_context(|| format!("identity directory {}", dir.display()))
}

/// Loads the identity, creating the key and certificate at first use (api.md §1 step 1).
pub fn load_or_create(layout: &DataLayout) -> Result<Identity> {
    let dir = open_identity_dir(layout)?;
    match read_key(&dir)? {
        Some(key) => {
            match read_cert(&dir)? {
                Some(cert) if spki_of_cert(&cert)? == key.subject_public_key_info() => build(&key, cert),
                existing => {
                    // A missing certificate (a stop between the two writes) or one for another
                    // key: issue it again from the key, keeping the old name if there was one.
                    let name = existing
                        .as_ref()
                        .and_then(|c| cert_cn(c).ok())
                        .unwrap_or_else(default_name);
                    issue(&dir, &key, &name)
                }
            }
        }
        None => {
            let key =
                KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|e| anyhow!("generating key: {e}"))?;
            let opts = WriteOpts {
                mode: 0o600,
                owner: file_owner(),
            };
            fsutil::atomic_write_at(&dir, KEY_FILE, key.serialize_pem().as_bytes(), opts)
                .with_context(|| format!("writing {}", layout.identity_dir().join(KEY_FILE).display()))?;
            issue(&dir, &key, &default_name())
        }
    }
}

/// Reissues the certificate with `name` as its CN, keeping the key (`setup --name`).
pub fn reissue(layout: &DataLayout, name: &str) -> Result<Identity> {
    validate_name(name)?;
    load_or_create(layout)?;
    let dir = open_identity_dir(layout)?;
    let key = read_key(&dir)?.ok_or_else(|| anyhow!("identity key vanished"))?;
    issue(&dir, &key, name)
}

/// Loads an existing identity without creating anything.
pub fn load_existing(layout: &DataLayout) -> Result<Identity> {
    let dir = fsutil::open_dir_nofollow(&layout.identity_dir())
        .with_context(|| format!("identity directory {}", layout.identity_dir().display()))?;
    let key = read_key(&dir)?.ok_or_else(|| anyhow!("no identity key yet"))?;
    let cert = read_cert(&dir)?.ok_or_else(|| anyhow!("no identity certificate yet"))?;
    build(&key, cert)
}

fn issue(dir: &OwnedFd, key: &KeyPair, name: &str) -> Result<Identity> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| anyhow!("{e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    let cert = params
        .self_signed(key)
        .map_err(|e| anyhow!("issuing certificate: {e}"))?;
    let opts = WriteOpts {
        mode: 0o600,
        owner: file_owner(),
    };
    fsutil::atomic_write_at(dir, CERT_FILE, cert.pem().as_bytes(), opts).context("writing cert.pem")?;
    build(key, cert.der().clone())
}

fn read_key(dir: &OwnedFd) -> Result<Option<KeyPair>> {
    match fsutil::read_at_bounded(dir, KEY_FILE, MAX_PEM) {
        Ok((b, _)) => {
            let text = String::from_utf8(b).map_err(|_| anyhow!("key.pem isn't text"))?;
            let key = KeyPair::from_pem(&text).map_err(|e| anyhow!("key.pem: {e}"))?;
            if !key.is_compatible(&rcgen::PKCS_ED25519) {
                bail!("key.pem isn't an Ed25519 key");
            }
            Ok(Some(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("key.pem: {}", crate::diag::cap(e))),
    }
}

fn read_cert(dir: &OwnedFd) -> Result<Option<CertificateDer<'static>>> {
    match fsutil::read_at_bounded(dir, CERT_FILE, MAX_PEM) {
        Ok((b, _)) => Ok(CertificateDer::from_pem_slice(&b).ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("cert.pem: {}", crate::diag::cap(e))),
    }
}

fn build(key: &KeyPair, cert_der: CertificateDer<'static>) -> Result<Identity> {
    let name = cert_cn(&cert_der).unwrap_or_default();
    Ok(Identity {
        fingerprint: picket_api::ids::fingerprint_spki(&key.subject_public_key_info()),
        key_der: PrivatePkcs8KeyDer::from(key.serialize_der()),
        cert_der,
        name,
    })
}

/// The SubjectPublicKeyInfo DER of a certificate.
pub fn spki_of_cert(cert: &CertificateDer<'_>) -> Result<Vec<u8>> {
    let (_, c) =
        x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|e| anyhow!("bad certificate: {e}"))?;
    Ok(c.tbs_certificate.subject_pki.raw.to_vec())
}

/// The fingerprint of a certificate's key (api.md §1).
pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> Result<String> {
    Ok(picket_api::ids::fingerprint_spki(&spki_of_cert(cert)?))
}

fn cert_cn(cert: &CertificateDer<'_>) -> Result<String> {
    let (_, c) =
        x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|e| anyhow!("bad certificate: {e}"))?;
    let cn = c
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or_default();
    Ok(cn.to_owned())
}

/// True when the identity files exist (for `key` without side effects in status output).
pub fn exists(layout: &DataLayout) -> bool {
    Path::new(&layout.identity_dir().join(KEY_FILE)).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn create_load_and_reissue_keep_the_key() {
        let d = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(d.path());
        let a = load_or_create(&layout).unwrap();
        assert!(a.fingerprint.starts_with("SHA256:"));
        for f in [KEY_FILE, CERT_FILE] {
            let m = std::fs::metadata(layout.identity_dir().join(f)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600, "{f}");
        }
        let m = std::fs::metadata(layout.identity_dir()).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o700);
        let b = load_or_create(&layout).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        let c = reissue(&layout, "ucg-fiber").unwrap();
        assert_eq!(c.fingerprint, a.fingerprint);
        assert_eq!(c.name, "ucg-fiber");
        assert_eq!(load_existing(&layout).unwrap().name, "ucg-fiber");
        assert_eq!(cert_fingerprint(&c.cert_der).unwrap(), a.fingerprint);
        assert!(format!("{c:?}").contains("fingerprint"));
        assert!(!format!("{c:?}").contains("PRIVATE"));
        assert!(reissue(&layout, "bad\nname").is_err());
        assert!(reissue(&layout, &"x".repeat(65)).is_err());
    }

    #[test]
    fn missing_cert_is_reissued_from_the_key() {
        let d = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(d.path());
        let a = reissue(&layout, "edge-a").unwrap();
        std::fs::remove_file(layout.identity_dir().join(CERT_FILE)).unwrap();
        let b = load_or_create(&layout).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn refuses_symlinked_identity_dir() {
        let d = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), d.path().join("identity")).unwrap();
        let layout = DataLayout::new(d.path());
        let e = load_or_create(&layout).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(std::fs::read_dir(elsewhere.path()).unwrap().next().is_none());
    }

    #[test]
    fn refuses_symlinked_key_file() {
        let d = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(d.path());
        std::fs::create_dir(layout.identity_dir()).unwrap();
        let target = d.path().join("elsewhere.pem");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, layout.identity_dir().join(KEY_FILE)).unwrap();
        assert!(load_or_create(&layout).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"x");
    }
}
