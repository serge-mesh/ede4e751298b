//! The LAN CA (security.md §2): an ECDSA P-256 root in `lanca/ca.{key,crt}` (0600),
//! name-constrained to `lanca.zones` and the LAN ranges (RFC 1918, ULA). It signs edge listener
//! certificates from CSRs (api.md §2, edge.md §5) and core's web certificate (core.md §11). Every
//! certificate it issues carries only names under the zones and IPs in the LAN ranges; anything
//! else is refused before signing.
//!
//! Changing `lanca.zones` makes a new root (core.md §11): [`rotation`] commits it with the
//! settings, keeps the previous root trusted by core until every assigned managed listener reports
//! a certificate from the new one, and recovers an interrupted rotation at start.

pub mod rotation;

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use jiff::Timestamp;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256, SanType,
    SerialNumber,
};
use x509_parser::prelude::FromDer;

use crate::identity::pem_to_der;

pub const LANCA_DIR: &str = "lanca";
pub const CA_KEY: &str = "ca.key";
pub const CA_CERT: &str = "ca.crt";
/// The web certificate core issues itself in `managed` mode (core.md §11).
pub const WEB_KEY: &str = "web.key";
pub const WEB_CERT: &str = "web.crt";

/// Listener leaves last 397 days (edge.md §5); the web certificate uses the same.
pub const LEAF_VALIDITY: Duration = Duration::from_secs(397 * 86_400);
/// The longest leaf the CA signs: browsers refuse server certificates valid for longer.
pub const MAX_LEAF_VALIDITY: Duration = Duration::from_secs(398 * 86_400);
/// The shortest leaf the CA signs.
pub const MIN_LEAF_VALIDITY: Duration = Duration::from_secs(86_400);
/// A rotated root lasts 20 years from the synchronised clock that dates it ([`rotation`], core.md
/// §11: other `lanca.zones` mean a new root).
const ROOT_VALIDITY_DAYS: u64 = 20 * 365;

/// The initial root's validity starts here (#46): `init` creates it before the clock may be
/// synchronised, so its dates are constants rather than the bootstrap clock. The start predates
/// every release, so no client sees the root as not yet valid once its own clock is right.
pub const BOOTSTRAP_ROOT_NOT_BEFORE: (i32, u8, u8) = (2026, 1, 1);

/// How a root's validity is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootDates {
    /// The initial root, created by `init` whatever the clock says (README "Clocks"): valid
    /// from [`BOOTSTRAP_ROOT_NOT_BEFORE`] with RFC 5280's "no well-defined expiration"
    /// (`notAfter` 9999-12-31T23:59:59Z, §4.1.2.5). It never ends by date: it is replaced only
    /// by a rotation. Synchronising the clock never regenerates it.
    Bootstrap,
    /// A rotated root, dated by the synchronised clock (callers check it): from a day before
    /// now, for [`ROOT_VALIDITY_DAYS`].
    Clock,
}
pub fn lanca_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(LANCA_DIR)
}

/// True when two zone lists name the same zones (order and case aside): the root's name
/// constraints are a set.
pub fn same_zones(a: &[String], b: &[String]) -> bool {
    let norm = |z: &[String]| {
        let mut v: Vec<String> = z
            .iter()
            .map(|z| z.trim().trim_end_matches('.').to_ascii_lowercase())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    norm(a) == norm(b)
}

/// A previous root core still trusts (its TLS to edge DoH listeners, core.md §8) until every
/// assigned managed listener reports a certificate from the current root ([`rotation`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviousRoot {
    /// [`picket_api::ids::cert_fingerprint`] of the root.
    pub fingerprint: String,
    pub cert_pem: String,
}

/// A certificate the CA issued.
#[derive(Clone, Debug)]
pub struct IssuedCert {
    pub cert_pem: String,
    /// The CA root, for `chain_pem` (api.md §2).
    pub chain_pem: String,
    pub not_after: Timestamp,
}

/// Why a signing request was refused.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("the CSR can't be parsed")]
    BadCsr,
    #[error("the CSR's signature doesn't verify")]
    BadSignature,
    #[error("unsupported public key in the CSR")]
    BadKey,
    #[error("{0:?} is not under the LAN CA's zones ({1})")]
    NameOutsideZones(String, String),
    #[error("{0:?} is not a valid DNS name")]
    BadName(String),
    #[error("{0} is not in the LAN ranges (RFC 1918, ULA)")]
    IpOutsideLan(IpAddr),
    #[error("a certificate needs at least one name or IP")]
    Empty,
    #[error("a leaf certificate lasts between 1 day and 398 days")]
    BadValidity,
    #[error("signing failed: {0}")]
    Signing(String),
}

/// The loaded LAN CA: the current root, which signs, and the previous roots core still trusts.
#[derive(Clone)]
pub struct LanCa {
    key: Arc<KeyPair>,
    pub cert_pem: String,
    pub cert_der: Vec<u8>,
    zones: Vec<String>,
    /// Previous roots still in use (newest first); never used to sign.
    pub previous: Vec<PreviousRoot>,
}

impl std::fmt::Debug for LanCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanCa")
            .field("zones", &self.zones)
            .finish_non_exhaustive()
    }
}

impl LanCa {
    /// Creates a new root for `zones` in `dir` (both files 0600).
    /// Used by `init` before the clock may be synchronised: its dates are [`RootDates::Bootstrap`].
    pub fn create(dir: &Path, zones: &[String], instance_id: &str) -> Result<Self> {
        let ca = Self::generate_with(
            zones,
            &format!("Picket LAN CA {}", picket_api::ids::short_id(instance_id)),
            RootDates::Bootstrap,
        )?;
        crate::util::ensure_dir(dir)?;
        crate::util::write_atomic(&dir.join(CA_KEY), ca.key_pem().as_bytes(), 0o600)?;
        crate::util::write_atomic(&dir.join(CA_CERT), ca.cert_pem.as_bytes(), 0o600)?;
        Ok(ca)
    }

    /// A new root for `zones` named `common_name`, dated by the clock (the caller checked it is
    /// synchronised), in memory only (a rotation writes it itself, [`rotation`]).
    pub fn generate(zones: &[String], common_name: &str) -> Result<Self> {
        Self::generate_with(zones, common_name, RootDates::Clock)
    }

    /// A new root for `zones` named `common_name` with `dates`, in memory only.
    pub fn generate_with(zones: &[String], common_name: &str, dates: RootDates) -> Result<Self> {
        let zones = normalize_zones(zones)?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate CA key")?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Picket");
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        match dates {
            RootDates::Bootstrap => {
                let (y, m, d) = BOOTSTRAP_ROOT_NOT_BEFORE;
                params.not_before = rcgen::date_time_ymd(y, m, d);
                params.not_after = rcgen::date_time_ymd(9999, 12, 31) + Duration::from_secs(86_400 - 1);
            }
            RootDates::Clock => {
                let now = rcgen::date_time_ymd(1970, 1, 1) + since_epoch();
                params.not_before = now - Duration::from_secs(86_400);
                params.not_after = now + Duration::from_secs(ROOT_VALIDITY_DAYS * 86_400);
            }
        }
        params.serial_number = Some(random_serial());
        let mut permitted: Vec<GeneralSubtree> =
            zones.iter().map(|z| GeneralSubtree::DnsName(z.clone())).collect();
        for net in crate::net::lan_ranges() {
            permitted.push(GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(
                net.network(),
                net.prefix_len(),
            )));
        }
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: vec![],
        });
        let cert = params.self_signed(&key).context("self-sign LAN CA")?;
        Ok(Self {
            key: Arc::new(key),
            cert_pem: cert.pem(),
            cert_der: cert.der().to_vec(),
            zones,
            previous: Vec::new(),
        })
    }

    /// The root's private key as PEM (written to `lanca/ca.key` only).
    pub(crate) fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// Loads `lanca/ca.{key,crt}`. The zones are read from the root's name constraints: they
    /// are what browsers enforce.
    pub fn load(dir: &Path) -> Result<Self> {
        let key_pem = fs::read_to_string(dir.join(CA_KEY)).context("read lanca/ca.key")?;
        let cert_pem = fs::read_to_string(dir.join(CA_CERT)).context("read lanca/ca.crt")?;
        let key = KeyPair::from_pem(&key_pem).context("parse lanca/ca.key")?;
        let cert_der = pem_to_der(&cert_pem, "CERTIFICATE")?;
        let (_, cert) =
            x509_parser::parse_x509_certificate(&cert_der).map_err(|e| anyhow!("parse lanca/ca.crt: {e}"))?;
        if cert.tbs_certificate.subject_pki.raw != rcgen::PublicKeyData::subject_public_key_info(&key) {
            bail!("lanca/ca.key doesn't belong to lanca/ca.crt");
        }
        let mut zones = Vec::new();
        if let Ok(Some(nc)) = cert.name_constraints()
            && let Some(permitted) = &nc.value.permitted_subtrees
        {
            for st in permitted {
                if let x509_parser::extensions::GeneralName::DNSName(n) = &st.base {
                    zones.push(n.to_ascii_lowercase());
                }
            }
        }
        if zones.is_empty() {
            bail!("lanca/ca.crt has no DNS name constraints");
        }
        Ok(Self {
            key: Arc::new(key),
            cert_pem,
            cert_der,
            zones,
            previous: Vec::new(),
        })
    }

    /// The zones the CA may sign names under.
    pub fn zones(&self) -> &[String] {
        &self.zones
    }

    /// The root's `SHA256:` fingerprint (shown next to the download in the UI, and carried in
    /// `EdgeConfig.lanca_root`).
    pub fn fingerprint(&self) -> String {
        picket_api::ids::cert_fingerprint(&self.cert_der)
    }

    /// The roots core's own TLS clients of edge listeners trust (core.md §8): the current one
    /// and every previous one an edge may still serve a certificate from.
    pub fn trust_pem(&self) -> String {
        let mut pem = self.cert_pem.clone();
        for p in &self.previous {
            if !pem.ends_with('\n') {
                pem.push('\n');
            }
            pem.push_str(&p.cert_pem);
        }
        pem
    }

    /// True when the current root signed `leaf_der`: its issuer is the root's subject and the
    /// root's key verifies its signature (the web certificate is re-issued otherwise, after a
    /// rotation).
    pub fn signed(&self, leaf_der: &[u8]) -> bool {
        let (Ok((_, leaf)), Ok((_, root))) = (
            x509_parser::parse_x509_certificate(leaf_der),
            x509_parser::parse_x509_certificate(&self.cert_der),
        ) else {
            return false;
        };
        leaf.issuer().as_raw() == root.subject().as_raw()
            && leaf.verify_signature(Some(root.public_key())).is_ok()
    }

    /// True when `name` (or the name under a leading `*.`) is a zone or under one.
    pub fn name_allowed(&self, name: &str) -> bool {
        name_under_zones(name, &self.zones)
    }

    /// Checks names and IPs against the constraints (also used by config validation for
    /// managed listener names and `web.names`, core.md §2).
    pub fn check_sans(&self, names: &[String], ips: &[IpAddr]) -> Result<(), SignError> {
        check_sans(&self.zones, names, ips)
    }

    /// Signs a server-auth leaf for `names` and `ips` with the public key from `csr_pem`
    /// (api.md §2). The CSR's signature is verified; its subject, SANs and extensions are
    /// ignored: only its public key is used. The leaf has no CA flag and EKU `serverAuth`.
    pub fn sign_leaf(
        &self,
        csr_pem: &str,
        names: &[String],
        ips: &[IpAddr],
        validity: Duration,
    ) -> Result<IssuedCert, SignError> {
        if csr_pem.len() > 64 * 1024 {
            return Err(SignError::BadCsr);
        }
        let der = pem_to_der(csr_pem, "CERTIFICATE REQUEST").map_err(|_| SignError::BadCsr)?;
        let spki = csr_public_key(&der)?;
        self.issue(&spki, names, ips, validity)
    }

    /// Issues a leaf for a key core holds itself (the web certificate in `managed` mode).
    /// Returns the issued certificate and the new key's PEM.
    pub fn issue_with_new_key(
        &self,
        names: &[String],
        ips: &[IpAddr],
        validity: Duration,
    ) -> Result<(IssuedCert, String), SignError> {
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| SignError::Signing(e.to_string()))?;
        let spki =
            rcgen::SubjectPublicKeyInfo::from_der(&rcgen::PublicKeyData::subject_public_key_info(&key))
                .map_err(|e| SignError::Signing(e.to_string()))?;
        let cert = self.issue(&spki, names, ips, validity)?;
        Ok((cert, key.serialize_pem()))
    }

    fn issue(
        &self,
        public_key: &rcgen::SubjectPublicKeyInfo,
        names: &[String],
        ips: &[IpAddr],
        validity: Duration,
    ) -> Result<IssuedCert, SignError> {
        self.check_sans(names, ips)?;
        if !(MIN_LEAF_VALIDITY..=MAX_LEAF_VALIDITY).contains(&validity) {
            return Err(SignError::BadValidity);
        }
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        if let Some(first) = names.first() {
            dn.push(DnType::CommonName, first.to_ascii_lowercase());
        }
        params.distinguished_name = dn;
        for n in names {
            let ia5 = rcgen::string::Ia5String::try_from(n.to_ascii_lowercase())
                .map_err(|_| SignError::BadName(n.clone()))?;
            params.subject_alt_names.push(SanType::DnsName(ia5));
        }
        for ip in ips {
            params
                .subject_alt_names
                .push(SanType::IpAddress(crate::net::canonical_ip(*ip)));
        }
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(random_serial());
        let now = rcgen::date_time_ymd(1970, 1, 1) + since_epoch();
        params.not_before = now - Duration::from_secs(3600);
        params.not_after = now + validity;
        let ca_der = rustls_pki_types::CertificateDer::from(self.cert_der.as_slice());
        let issuer = Issuer::from_ca_cert_der(&ca_der, self.key.as_ref())
            .map_err(|e| SignError::Signing(e.to_string()))?;
        let cert = params
            .signed_by(public_key, &issuer)
            .map_err(|e| SignError::Signing(e.to_string()))?;
        let not_after =
            Timestamp::from_second(params.not_after.unix_timestamp()).unwrap_or_else(|_| Timestamp::now());
        Ok(IssuedCert {
            cert_pem: cert.pem(),
            chain_pem: self.cert_pem.clone(),
            not_after,
        })
    }
}

/// Extracts and checks the public key of a DER CSR after verifying its signature.
fn csr_public_key(der: &[u8]) -> Result<rcgen::SubjectPublicKeyInfo, SignError> {
    let (rest, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(der)
        .map_err(|_| SignError::BadCsr)?;
    if !rest.is_empty() {
        return Err(SignError::BadCsr);
    }
    csr.verify_signature().map_err(|_| SignError::BadSignature)?;
    rcgen::SubjectPublicKeyInfo::from_der(csr.certification_request_info.subject_pki.raw)
        .map_err(|_| SignError::BadKey)
}

/// Lowercases, strips trailing dots and checks each zone is a DNS name.
pub fn normalize_zones(zones: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for z in zones {
        let z = z.trim().trim_end_matches('.').to_ascii_lowercase();
        if !is_dns_name(&z) {
            bail!("lanca zone {z:?} is not a DNS name");
        }
        // A LAN CA every device trusts must not sign names others register on the internet
        // (security.md §2): no public suffix (bundled list), home.arpa excepted.
        if crate::psl::is_public_suffix(&z) {
            bail!(
                "lanca zone {z:?} is a public suffix: a LAN CA for it could sign other people's names on \
                 the internet; use home.arpa or a zone under a domain you own"
            );
        }
        if !out.contains(&z) {
            out.push(z);
        }
    }
    if out.is_empty() {
        bail!("lanca.zones needs at least one zone");
    }
    Ok(out)
}

/// True when `name` is a zone or under one; a leading `*.` is allowed (listener SANs carry
/// `*.name` for profile ids, edge.md §5).
pub fn name_under_zones(name: &str, zones: &[String]) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let base = n.strip_prefix("*.").unwrap_or(&n);
    if !is_dns_name(base) {
        return false;
    }
    zones
        .iter()
        .any(|z| base == z || base.ends_with(&format!(".{z}")))
}

/// Why a leaf for an edge's listener must not be signed even within the zones: its SANs would
/// cover one of core's own names (`web.names`, also under a `*.` SAN) or addresses, so the edge
/// holding it could present a LAN-CA certificate for core's UI. Edges are untrusted (README §2);
/// config validation refuses such names at save time, and the CSR route (`POST /v1/csr`, next
/// wave, api.md §2) must refuse them here too, since only it knows core's current addresses.
pub fn edge_leaf_conflict(
    names: &[String],
    ips: &[IpAddr],
    web_names: &[String],
    core_ips: &[IpAddr],
) -> Option<String> {
    for n in names {
        let n = n.trim_end_matches('.').to_ascii_lowercase();
        let (wild, base) = match n.strip_prefix("*.") {
            Some(b) => (true, b.to_string()),
            None => (false, n.clone()),
        };
        for w in web_names {
            let w = w.trim_end_matches('.').to_ascii_lowercase();
            let covered = if wild {
                w.split_once('.').is_some_and(|(_, parent)| parent == base)
            } else {
                w == base
            };
            if covered {
                return Some(format!("{n} covers core's own name {w}"));
            }
        }
    }
    let core: Vec<IpAddr> = core_ips.iter().map(|i| crate::net::canonical_ip(*i)).collect();
    ips.iter()
        .map(|i| crate::net::canonical_ip(*i))
        .find(|i| core.contains(i))
        .map(|i| format!("{i} is one of core's own addresses"))
}

/// Checks SANs against zones and LAN ranges.
pub fn check_sans(zones: &[String], names: &[String], ips: &[IpAddr]) -> Result<(), SignError> {
    if names.is_empty() && ips.is_empty() {
        return Err(SignError::Empty);
    }
    for n in names {
        let base = n.strip_prefix("*.").unwrap_or(n);
        if !is_dns_name(&base.to_ascii_lowercase()) {
            return Err(SignError::BadName(n.clone()));
        }
        if !name_under_zones(n, zones) {
            return Err(SignError::NameOutsideZones(n.clone(), zones.join(", ")));
        }
    }
    for ip in ips {
        if !crate::net::is_lan_ip(ip) {
            return Err(SignError::IpOutsideLan(*ip));
        }
    }
    Ok(())
}

/// A hostname: 1–253 characters, labels of 1–63 letters, digits and hyphens (no leading or
/// trailing hyphen). Lowercase input expected.
pub fn is_dns_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(is_ldh_label)
}

/// One LDH label: 1–63 of `a-z0-9-`, not starting or ending with `-`.
pub fn is_ldh_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn random_serial() -> SerialNumber {
    let mut b = crate::util::random_bytes::<16>();
    b[0] &= 0x7f; // positive
    SerialNumber::from_slice(&b)
}

/// Time since the Unix epoch. Certificate dates are `rcgen::date_time_ymd(1970, 1, 1)` plus
/// this, so core needs no date crate of its own besides jiff.
fn since_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca() -> (tempfile::TempDir, LanCa) {
        let d = tempfile::tempdir().unwrap();
        let ca = LanCa::create(d.path(), &["home.arpa".into()], "0123456789abcdef0123").unwrap();
        (d, ca)
    }

    fn csr_for(names: &[&str]) -> String {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    /// #46: the initial root's dates are constants, whatever the clock says at `init`; a
    /// rotated root is dated by the (synchronised) clock.
    #[test]
    fn the_bootstrap_root_is_dated_independently_of_the_clock() {
        let (_d, ca) = ca();
        let (_, cert) = x509_parser::parse_x509_certificate(&ca.cert_der).unwrap();
        let v = cert.validity();
        assert_eq!(v.not_before.timestamp(), 1_767_225_600, "2026-01-01T00:00:00Z");
        assert_eq!(v.not_after.timestamp(), 253_402_300_799, "9999-12-31T23:59:59Z");
        // Another init (any clock) gets the same dates: only the key and serial differ.
        let other = LanCa::generate_with(&["home.arpa".into()], "x", RootDates::Bootstrap).unwrap();
        let (_, c2) = x509_parser::parse_x509_certificate(&other.cert_der).unwrap();
        assert_eq!(c2.validity().not_before, v.not_before);
        assert_eq!(c2.validity().not_after, v.not_after);
        assert_ne!(other.fingerprint(), ca.fingerprint());
        // A rotated root: a day back from now, 20 years on.
        let rotated = LanCa::generate(&["home.arpa".into()], "r").unwrap();
        let (_, c3) = x509_parser::parse_x509_certificate(&rotated.cert_der).unwrap();
        let now = Timestamp::now().as_second();
        assert!((now - 86_400 - 5..=now - 86_400 + 5).contains(&c3.validity().not_before.timestamp()));
        let span = c3.validity().not_after.timestamp() - c3.validity().not_before.timestamp();
        assert_eq!(span, i64::try_from((ROOT_VALIDITY_DAYS + 1) * 86_400).unwrap());
    }

    /// Leaves from the bootstrap root still carry the dates of the clock that signs them (callers
    /// sign only on a synchronised clock, except the bootstrap web certificate, which the web
    /// port re-issues once the clock is synchronised); the root's own dates take no part.
    #[test]
    fn a_bootstrap_roots_leaves_are_dated_by_the_signing_clock() {
        let (_d, ca) = ca();
        let (issued, _) = ca
            .issue_with_new_key(&["core.home.arpa".into()], &[], LEAF_VALIDITY)
            .unwrap();
        let der = crate::identity::pem_to_der(&issued.cert_pem, "CERTIFICATE").unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        let now = Timestamp::now().as_second();
        assert!(cert.validity().not_before.timestamp() <= now);
        assert!(cert.validity().not_after.timestamp() > now + 390 * 86_400);
        assert!(ca.signed(&der));
    }

    #[test]
    fn create_and_load() {
        let (d, ca) = ca();
        let again = LanCa::load(d.path()).unwrap();
        assert_eq!(again.zones(), ["home.arpa"]);
        assert_eq!(ca.fingerprint(), again.fingerprint());
        let (_, cert) = x509_parser::parse_x509_certificate(&ca.cert_der).unwrap();
        assert!(cert.is_ca());
        let nc = cert.name_constraints().unwrap().unwrap();
        let permitted = nc.value.permitted_subtrees.as_ref().unwrap();
        assert_eq!(permitted.len(), 5); // home.arpa + 3 RFC 1918 + ULA
    }

    #[test]
    fn signs_leaf_with_only_csr_key() {
        let (_d, ca) = ca();
        // The CSR asks for other names; they are ignored.
        let csr = csr_for(&["evil.example.com"]);
        let issued = ca
            .sign_leaf(
                &csr,
                &["dns.home.arpa".into(), "*.dns.home.arpa".into()],
                &["192.168.1.1".parse().unwrap()],
                LEAF_VALIDITY,
            )
            .unwrap();
        let der = pem_to_der(&issued.cert_pem, "CERTIFICATE").unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert!(!cert.is_ca());
        let eku = cert.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.server_auth);
        let san = cert.subject_alternative_name().unwrap().unwrap();
        let names: Vec<String> = san.value.general_names.iter().map(|g| format!("{g}")).collect();
        assert!(names.iter().any(|n| n.contains("dns.home.arpa")));
        assert!(!names.iter().any(|n| n.contains("evil")));
        assert!(issued.not_after > Timestamp::now() + jiff::SignedDuration::from_hours(24 * 390));
    }

    #[test]
    fn refuses_outside_zones_and_ranges() {
        let (_d, ca) = ca();
        let csr = csr_for(&["x"]);
        assert!(matches!(
            ca.sign_leaf(&csr, &["dns.example.com".into()], &[], LEAF_VALIDITY),
            Err(SignError::NameOutsideZones(..))
        ));
        assert!(matches!(
            ca.sign_leaf(&csr, &["home.arpa.evil.com".into()], &[], LEAF_VALIDITY),
            Err(SignError::NameOutsideZones(..))
        ));
        assert!(matches!(
            ca.sign_leaf(&csr, &["evilhome.arpa".into()], &[], LEAF_VALIDITY),
            Err(SignError::NameOutsideZones(..))
        ));
        assert!(matches!(
            ca.sign_leaf(
                &csr,
                &["dns.home.arpa".into()],
                &["8.8.8.8".parse().unwrap()],
                LEAF_VALIDITY
            ),
            Err(SignError::IpOutsideLan(_))
        ));
        assert!(matches!(
            ca.sign_leaf(&csr, &[], &["2001:db8::1".parse().unwrap()], LEAF_VALIDITY),
            Err(SignError::IpOutsideLan(_))
        ));
        assert!(matches!(
            ca.sign_leaf(&csr, &[], &[], LEAF_VALIDITY),
            Err(SignError::Empty)
        ));
    }

    #[test]
    fn leaf_validity_is_bounded() {
        let (_d, ca) = ca();
        let csr = csr_for(&["x"]);
        let names = ["dns.home.arpa".to_string()];
        for v in [0, 3600, 399 * 86_400, u64::MAX] {
            assert!(
                matches!(
                    ca.sign_leaf(&csr, &names, &[], Duration::from_secs(v)),
                    Err(SignError::BadValidity)
                ),
                "{v}"
            );
            assert!(matches!(
                ca.issue_with_new_key(&names, &[], Duration::from_secs(v)),
                Err(SignError::BadValidity)
            ));
        }
        assert!(
            ca.sign_leaf(&csr, &names, &[], Duration::from_secs(86_400))
                .is_ok()
        );
        assert!(ca.sign_leaf(&csr, &names, &[], LEAF_VALIDITY).is_ok());
    }

    #[test]
    fn refuses_bad_csr() {
        let (_d, ca) = ca();
        assert!(matches!(
            ca.sign_leaf("garbage", &["a.home.arpa".into()], &[], LEAF_VALIDITY),
            Err(SignError::BadCsr)
        ));
        // Flip a byte in the signature: the CSR must not verify.
        let csr = csr_for(&["x"]);
        let mut der = pem_to_der(&csr, "CERTIFICATE REQUEST").unwrap();
        let last = der.len() - 2;
        der[last] ^= 0x55;
        use base64::Engine as _;
        let pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        assert!(matches!(
            ca.sign_leaf(&pem, &["a.home.arpa".into()], &[], LEAF_VALIDITY),
            Err(SignError::BadSignature) | Err(SignError::BadCsr)
        ));
    }

    #[test]
    fn zone_matching() {
        let zones = vec!["home.arpa".to_string()];
        assert!(name_under_zones("home.arpa", &zones));
        assert!(name_under_zones("Core.Home.Arpa.", &zones));
        assert!(name_under_zones("*.dns.home.arpa", &zones));
        assert!(!name_under_zones("xhome.arpa", &zones));
        assert!(!name_under_zones("a..home.arpa", &zones));
    }

    #[test]
    fn edge_leaves_never_cover_core() {
        let web = vec!["core.home.arpa".to_string()];
        let core_ips: Vec<IpAddr> = vec!["192.168.1.20".parse().unwrap()];
        let n = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let lan: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
        assert!(
            edge_leaf_conflict(&n(&["dns.home.arpa", "*.dns.home.arpa"]), &lan, &web, &core_ips).is_none()
        );
        assert!(edge_leaf_conflict(&n(&["home.arpa", "*.home.arpa"]), &[], &web, &core_ips).is_some());
        assert!(edge_leaf_conflict(&n(&["core.home.arpa"]), &[], &web, &core_ips).is_some());
        let mapped: IpAddr = "::ffff:192.168.1.20".parse().unwrap();
        assert!(edge_leaf_conflict(&n(&["dns.home.arpa"]), &[mapped], &web, &core_ips).is_some());
    }

    #[test]
    fn public_suffix_zones_are_refused() {
        // `--lanca-zones com` would let the LAN CA sign any .com name for every device that
        // trusts it.
        for z in ["com", "co.uk", "github.io"] {
            assert!(normalize_zones(&[z.to_string()]).is_err(), "{z}");
        }
        assert_eq!(
            normalize_zones(&["home.arpa".into(), "lan".into(), "home.example.com".into()]).unwrap(),
            vec!["home.arpa", "lan", "home.example.com"]
        );
    }
}
