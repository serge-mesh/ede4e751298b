//! Listener certificates (edge.md §5 "Certificates").
//!
//! - **Managed** (`"tls": {"managed": "dns.home.arpa"}`): the edge generates an ECDSA P-256 key
//!   (browsers don't accept Ed25519 certificates) and sends a CSR to core (`POST /v1/csr`); core
//!   signs a 397-day leaf whose SANs it takes from the listener's config (the name, `*.name` and
//!   the listener IPs inside RFC 1918 or ULA). The edge renews it 265 days after issue, or at once
//!   when its SANs no longer match the config, or when another root than the LAN CA root the
//!   config names (`lanca_root`) issued it: a `lanca.zones` change makes a new root (core.md
//!   §11), and an edge that was offline re-issues when it gets the config. On a synchronised
//!   clock, a certificate that starts in the future (signed while a clock was ahead) is replaced
//!   too (README §2 Clocks). A failed request is retried with the session backoff (1 s → 60 s,
//!   jitter). An expired certificate is still served. The root that signed what each listener
//!   serves goes to core in `hello` and every heartbeat (`cert_roots`, api.md §3), at once after a
//!   new certificate: core keeps trusting a previous root until every listener serves one from the
//!   current root. Key and chain are kept
//!   together in `<data_dir>/tls/<listener>.pem` (0600) and served from there after a restart,
//!   with or without core. The pair is replaced in one fsync'd rename, so a crash leaves the old
//!   pair or the new one, never a new key with the old certificate; the pair it replaced stays in
//!   `<listener>.prev.pem`, the fallback when the current file doesn't load (README §2
//!   "Restarts").
//! - **Files** (`cert_file`, `key_file`): read and reloaded on change (size or mtime), keeping
//!   the last good pair when a new one doesn't load.
//!
//! A TLS listener serves whatever its slot holds now ([`CertSlot`] is the rustls resolver), so a
//! renewal or reload never rebinds; with nothing to serve, handshakes fail until a certificate
//! arrives. Listeners speak only TLS 1.3 ([`CertSlot::server_config`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::{ArcSwap, ArcSwapOption};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use jiff::{SignedDuration, civil};
use picket_api::edge_api::CsrRequest;
use picket_api::time::Timestamp;

use super::runtime::ListenerSpec;
use crate::core_client::CoreClient;
use crate::edge::Edge;
use crate::fsutil::{self, WriteOpts};

/// Renew this long after issue (edge.md §5: 397-day leaves renewed after 265 days).
pub const RENEW_AFTER: Duration = Duration::from_secs(265 * 86_400);
/// When the issue time can't be read: renew this long before expiry.
pub const RENEW_BEFORE_EXPIRY: Duration = Duration::from_secs((397 - 265) * 86_400);
/// Largest certificate or key file read.
pub const MAX_PEM: u64 = 1 << 20;

/// What a listener's certificate comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertSource {
    /// `root`: the LAN CA root that must have issued it (`EdgeConfig.lanca_root`), if named.
    Managed {
        name: String,
        ips: Vec<IpAddr>,
        root: Option<String>,
    },
    Files {
        cert: PathBuf,
        key: PathBuf,
    },
}

/// What `status` shows of a certificate.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct CertInfo {
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub names: Vec<String>,
    /// The fingerprint (`picket_api::ids::cert_fingerprint`) of the chain certificate that signed
    /// the leaf: the LAN CA root for a managed certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip)]
    pub not_before_ts: Option<i64>,
    #[serde(skip)]
    pub not_after_ts: Option<i64>,
    #[serde(skip)]
    pub ip_sans: Vec<IpAddr>,
}

struct Retry {
    next: Option<Instant>,
    delay: Duration,
}

/// One TLS listener's certificate, swapped in place.
pub struct CertSlot {
    pub listener: Arc<str>,
    source: ArcSwap<CertSource>,
    key: ArcSwapOption<CertifiedKey>,
    info: ArcSwap<CertInfo>,
    retry: Mutex<Retry>,
    files_seen: Mutex<Option<(u64, SystemTime, u64, SystemTime)>>,
    loaded_from_disk: Mutex<bool>,
    /// The settings core last issued this slot's certificate for: a SAN mismatch asks again only
    /// when the settings changed since (core decides the SANs; a difference it keeps making
    /// mustn't turn into a request every backoff period).
    issued_for: Mutex<Option<CertSource>>,
}

impl std::fmt::Debug for CertSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertSlot")
            .field("listener", &self.listener)
            .field("has_cert", &self.key.load().is_some())
            .finish()
    }
}

impl ResolvesServerCert for CertSlot {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.key.load_full()
    }
}

impl CertSlot {
    fn new(listener: Arc<str>, source: CertSource) -> Self {
        Self {
            listener,
            source: ArcSwap::from_pointee(source),
            key: ArcSwapOption::empty(),
            info: ArcSwap::from_pointee(CertInfo::default()),
            retry: Mutex::new(Retry {
                next: None,
                delay: Duration::ZERO,
            }),
            files_seen: Mutex::new(None),
            loaded_from_disk: Mutex::new(false),
            issued_for: Mutex::new(None),
        }
    }

    pub fn has_cert(&self) -> bool {
        self.key.load().is_some()
    }

    pub fn info(&self) -> Arc<CertInfo> {
        self.info.load_full()
    }

    /// The DNS names the certificate holds (for the DoT SNI profile prefix of file
    /// certificates).
    pub fn names(&self) -> Vec<String> {
        self.info.load().names.clone()
    }

    fn set(&self, key: Arc<CertifiedKey>, info: CertInfo) {
        self.key.store(Some(key));
        self.info.store(Arc::new(info));
    }

    fn set_error(&self, e: String) {
        let mut i = CertInfo::clone(&self.info.load());
        i.last_error = Some(crate::diag::cap(e));
        self.info.store(Arc::new(i));
    }

    /// The rustls server config for a listener served by this slot: TLS 1.3 only (api.md: every
    /// interface speaks TLS 1.3). A client that offers no TLS 1.3 is refused and reported
    /// (`super::listeners::handshake`).
    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(self) as Arc<dyn ResolvesServerCert>);
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        Ok(Arc::new(cfg))
    }
}

/// A certificate date as `status` has always shown it: RFC 3339 in whole seconds with `+00:00`
/// (README §2 "Compatibility"). Built from civil time rather than a [`Timestamp`]: a certificate
/// may run to 9999-12-31T23:59:59Z, past the latest instant a `Timestamp` holds.
fn cert_date(unix_secs: i64) -> Option<String> {
    let dt = civil::date(1970, 1, 1)
        .at(0, 0, 0, 0)
        .checked_add(SignedDuration::from_secs(unix_secs))
        .ok()?;
    Some(dt.strftime("%Y-%m-%dT%H:%M:%S+00:00").to_string())
}
/// Parses a leaf for what `status` and renewal need.
fn describe(chain: &[CertificateDer<'static>], source: &'static str) -> CertInfo {
    let mut info = CertInfo {
        source,
        ..Default::default()
    };
    let Some(leaf) = chain.first() else { return info };
    let Ok((_, c)) = x509_parser::parse_x509_certificate(leaf.as_ref()) else {
        return info;
    };
    // The issuer: the chain certificate whose subject is the leaf's issuer and whose key
    // verifies the leaf's signature (the chain holds at most 16 certificates).
    info.root = chain.iter().skip(1).find_map(|ca| {
        let (_, ca_cert) = x509_parser::parse_x509_certificate(ca.as_ref()).ok()?;
        (ca_cert.subject().as_raw() == c.issuer().as_raw()
            && c.verify_signature(Some(ca_cert.public_key())).is_ok())
        .then(|| picket_api::ids::cert_fingerprint(ca.as_ref()))
    });
    let nb = c.validity().not_before.timestamp();
    let na = c.validity().not_after.timestamp();
    info.not_before_ts = Some(nb);
    info.not_after_ts = Some(na);
    info.not_before = cert_date(nb);
    info.not_after = cert_date(na);
    if let Ok(Some(san)) = c.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                x509_parser::extensions::GeneralName::DNSName(d) => info.names.push(d.to_ascii_lowercase()),
                x509_parser::extensions::GeneralName::IPAddress(b) => {
                    let ip = match b.len() {
                        4 => <[u8; 4]>::try_from(*b).ok().map(IpAddr::from),
                        16 => <[u8; 16]>::try_from(*b).ok().map(IpAddr::from),
                        _ => None,
                    };
                    info.ip_sans.extend(ip);
                }
                _ => {}
            }
        }
    }
    info
}

fn spki_of(leaf: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let (_, c) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    Some(c.tbs_certificate.subject_pki.raw.to_vec())
}

/// Builds a served key from PEM texts.
pub fn certified_key(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<(Arc<CertifiedKey>, Vec<CertificateDer<'static>>)> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .take(16)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("certificate PEM: {e}"))?;
    if chain.is_empty() {
        anyhow::bail!("no certificate in the PEM");
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| anyhow::anyhow!("key PEM: {e}"))?;
    let signer =
        rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).map_err(|e| anyhow::anyhow!("key: {e}"))?;
    let ck = CertifiedKey::new(chain.clone(), signer);
    ck.keys_match()
        .map_err(|e| anyhow::anyhow!("certificate and key don't match: {e}"))?;
    Ok((Arc::new(ck), chain))
}

/// The SANs core puts on a managed listener's leaf (edge.md §5): the name, `*.name`, and the
/// listener IPs inside RFC 1918 or ULA.
pub fn desired_sans(name: &str, ips: &[IpAddr]) -> (Vec<String>, Vec<IpAddr>) {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut dns = vec![name.clone(), format!("*.{name}")];
    dns.sort();
    let mut v: Vec<IpAddr> = ips
        .iter()
        .map(|ip| ip.to_canonical())
        .filter(|ip| match ip {
            IpAddr::V4(a) => a.is_private(),
            IpAddr::V6(a) => (a.segments()[0] & 0xfe00) == 0xfc00,
        })
        .collect();
    v.sort();
    v.dedup();
    (dns, v)
}

/// The listener certificates.
pub struct Certs {
    slots: Mutex<HashMap<Arc<str>, Arc<CertSlot>>>,
    pub wake: tokio::sync::Notify,
}

impl Certs {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(HashMap::new()),
            wake: tokio::sync::Notify::new(),
        })
    }

    /// Makes the slots match the TLS listeners of a config; returns each listener's slot.
    /// `lanca_root` is the config's LAN CA root, which must have issued managed certificates.
    pub fn sync(
        &self,
        listeners: &[Arc<ListenerSpec>],
        lanca_root: Option<&str>,
    ) -> HashMap<Arc<str>, Arc<CertSlot>> {
        let mut g = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = HashMap::new();
        let mut changed = false;
        for l in listeners {
            let Some(tls) = &l.tls else { continue };
            let source = match (&tls.managed, &tls.cert_file, &tls.key_file) {
                (Some(n), _, _) => CertSource::Managed {
                    name: n.trim_end_matches('.').to_ascii_lowercase(),
                    ips: l.ips.clone(),
                    root: lanca_root.map(str::to_owned),
                },
                (None, Some(c), Some(k)) => CertSource::Files {
                    cert: PathBuf::from(c),
                    key: PathBuf::from(k),
                },
                _ => continue,
            };
            let slot = match g.get(&l.id) {
                Some(s) => {
                    if **s.source.load() != source {
                        s.source.store(Arc::new(source));
                        *s.files_seen.lock().unwrap_or_else(|p| p.into_inner()) = None;
                        s.retry.lock().unwrap_or_else(|p| p.into_inner()).next = None;
                        changed = true;
                    }
                    Arc::clone(s)
                }
                None => {
                    changed = true;
                    Arc::new(CertSlot::new(Arc::clone(&l.id), source))
                }
            };
            next.insert(Arc::clone(&l.id), slot);
        }
        *g = next.clone();
        drop(g);
        if changed {
            self.wake.notify_one();
        }
        next
    }

    pub fn slot(&self, listener: &str) -> Option<Arc<CertSlot>> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(listener)
            .cloned()
    }

    /// `cert_roots` for `hello` and `heartbeat` (api.md §3): each managed listener holding a
    /// certificate, and the root that signed the one it serves now. Core keeps trusting a previous
    /// LAN CA root until every assigned listener reports one from the current root (core.md §11),
    /// so a certificate core signed but the edge never installed keeps the old root trusted.
    pub fn served_roots(&self) -> std::collections::BTreeMap<String, String> {
        self.all()
            .into_iter()
            .filter(|s| matches!(**s.source.load(), CertSource::Managed { .. }) && s.has_cert())
            .filter_map(|s| Some((s.listener.to_string(), s.info().root.clone()?)))
            .collect()
    }

    fn all(&self) -> Vec<Arc<CertSlot>> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// One pass over every slot.
    pub async fn check_all(&self, edge: &Edge, core: Option<&Arc<CoreClient>>) {
        for s in self.all() {
            match &**s.source.load() {
                CertSource::Files { cert, key } => check_files(&s, cert, key),
                CertSource::Managed { name, ips, root } => {
                    check_managed(edge, core, &s, name, ips, root.as_deref()).await
                }
            }
        }
    }
}

fn file_stamp(p: &Path) -> Option<(u64, SystemTime)> {
    let m = std::fs::metadata(p).ok()?;
    Some((m.len(), m.modified().ok()?))
}

fn check_files(s: &CertSlot, cert: &Path, key: &Path) {
    let (Some(c), Some(k)) = (file_stamp(cert), file_stamp(key)) else {
        if !s.has_cert() {
            s.set_error(format!("{} or {} can't be read", cert.display(), key.display()));
        }
        return;
    };
    let stamp = (c.0, c.1, k.0, k.1);
    {
        let seen = s.files_seen.lock().unwrap_or_else(|p| p.into_inner());
        if *seen == Some(stamp) {
            return;
        }
    }
    let loaded = fsutil::read_bounded(cert, MAX_PEM)
        .and_then(|c| fsutil::read_bounded(key, MAX_PEM).map(|k| (c, k)))
        .map_err(anyhow::Error::from)
        .and_then(|(c, k)| certified_key(&c, &k));
    match loaded {
        Ok((ck, chain)) => {
            s.set(ck, describe(&chain, "files"));
            *s.files_seen.lock().unwrap_or_else(|p| p.into_inner()) = Some(stamp);
        }
        Err(e) => {
            tracing::warn!(
                "listener {}: certificate files don't load (keeping the last good pair): {}",
                s.listener,
                crate::diag::cap_chain(&e)
            );
            s.set_error(crate::diag::cap_chain(&e));
            // Try again only when the files change again.
            *s.files_seen.lock().unwrap_or_else(|p| p.into_inner()) = Some(stamp);
        }
    }
}

/// The stored pair's file names: the current one and the one it replaced.
fn stored_names(listener: &str) -> (String, String) {
    (format!("{listener}.pem"), format!("{listener}.prev.pem"))
}

/// A stored pair: the key and its chain in one PEM text.
pub fn combined_pem(key_pem: &str, chain_pem: &str) -> String {
    let mut s = String::with_capacity(key_pem.len() + chain_pem.len() + 1);
    s.push_str(key_pem);
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s.push_str(chain_pem);
    s
}

/// Loads a managed listener's stored pair from `dir`: the current one, else the one it replaced.
/// The flag says the previous one was used.
pub fn load_stored(
    dir: &Path,
    listener: &str,
) -> Option<(Arc<CertifiedKey>, Vec<CertificateDer<'static>>, bool)> {
    let dirfd = fsutil::open_dir_nofollow(dir).ok()?;
    let (cur, prev) = stored_names(listener);
    for (name, is_prev) in [(cur, false), (prev, true)] {
        let Ok((pem, _)) = fsutil::read_at_bounded(&dirfd, &name, MAX_PEM) else {
            continue;
        };
        match certified_key(&pem, &pem) {
            Ok((ck, chain)) => return Some((ck, chain, is_prev)),
            Err(e) => tracing::warn!(
                "listener {listener}: stored {name} doesn't load: {}",
                crate::diag::cap_chain(&e)
            ),
        }
    }
    None
}

/// Stores a managed listener's new pair (`pem`: key and chain) in `dir`: the current pair, when
/// it loads, becomes the previous one, then the new one replaces it. Each step is one atomic,
/// fsync'd write, so a crash at any point leaves a pair that loads.
pub fn store_pair(dir: &Path, listener: &str, pem: &[u8]) -> std::io::Result<()> {
    let dirfd = fsutil::open_dir_nofollow(dir)?;
    let (cur, prev) = stored_names(listener);
    if let Ok((old, _)) = fsutil::read_at_bounded(&dirfd, &cur, MAX_PEM)
        && certified_key(&old, &old).is_ok()
    {
        fsutil::atomic_write_at(&dirfd, &prev, &old, WriteOpts::mode(0o600))?;
    }
    fsutil::atomic_write_at(&dirfd, &cur, pem, WriteOpts::mode(0o600))
}

/// Whether a managed certificate needs a new one: none; SANs that don't match the config, or
/// another issuer than the LAN CA root it names (`root`, core.md §11), unless core issued it for
/// these very settings (`issued_for_current`); or, on a synchronised clock, 265 days past issue,
/// or a start (`not_before`) still in the future: signed while a clock was ahead, it isn't valid
/// yet and nothing else would replace it before its renewal date (README §2 Clocks).
#[expect(
    clippy::too_many_arguments,
    reason = "a pure decision over a slot's facts, kept apart from the slot so tests can call it"
)]
pub fn needs_renewal(
    info: &CertInfo,
    has: bool,
    name: &str,
    ips: &[IpAddr],
    root: Option<&str>,
    issued_for_current: bool,
    clock_synced: bool,
    now: i64,
) -> bool {
    if !has {
        return true;
    }
    let (want_dns, want_ips) = desired_sans(name, ips);
    let mut have_dns = info.names.clone();
    have_dns.sort();
    let mut have_ips: Vec<IpAddr> = info.ip_sans.iter().map(|i| i.to_canonical()).collect();
    have_ips.sort();
    have_ips.dedup();
    let other_root = root.is_some_and(|r| info.root.as_deref() != Some(r));
    if !issued_for_current && (have_dns != want_dns || have_ips != want_ips || other_root) {
        return true;
    }
    if !clock_synced {
        return false;
    }
    match (info.not_before_ts, info.not_after_ts) {
        (Some(nb), _) => now < nb || now >= nb.saturating_add(picket_api::duration::as_secs_i64(RENEW_AFTER)),
        (None, Some(na)) => now >= na.saturating_sub(picket_api::duration::as_secs_i64(RENEW_BEFORE_EXPIRY)),
        (None, None) => true,
    }
}

async fn check_managed(
    edge: &Edge,
    core: Option<&Arc<CoreClient>>,
    s: &Arc<CertSlot>,
    name: &str,
    ips: &[IpAddr],
    root: Option<&str>,
) {
    let dir = edge.layout.tls_dir();
    {
        let mut loaded = s.loaded_from_disk.lock().unwrap_or_else(|p| p.into_inner());
        if !*loaded {
            *loaded = true;
            if let Some((ck, chain, from_prev)) = load_stored(&dir, &s.listener) {
                if from_prev {
                    tracing::warn!(
                        "listener {}: serving the previous certificate (the current one doesn't load)",
                        s.listener
                    );
                }
                s.set(ck, describe(&chain, "managed"));
            }
        }
    }
    let info = s.info();
    let now = Timestamp::now().as_second();
    let current = CertSource::Managed {
        name: name.to_owned(),
        ips: ips.to_vec(),
        root: root.map(str::to_owned),
    };
    let issued_for_current =
        s.issued_for.lock().unwrap_or_else(|p| p.into_inner()).as_ref() == Some(&current);
    if !needs_renewal(
        &info,
        s.has_cert(),
        name,
        ips,
        root,
        issued_for_current,
        edge.clock.synced(),
        now,
    ) {
        return;
    }
    let Some(core) = core else {
        if !s.has_cert() {
            s.set_error("no core to sign a certificate (run picket-edge setup)".into());
        }
        return;
    };
    {
        let r = s.retry.lock().unwrap_or_else(|p| p.into_inner());
        if r.next.is_some_and(|t| Instant::now() < t) {
            return;
        }
    }
    let outcome = request(core, s, &dir).await.and_then(|()| {
        *s.issued_for.lock().unwrap_or_else(|p| p.into_inner()) = Some(current);
        // Core reports what each listener serves (`cert_roots`) so it can stop trusting a
        // previous LAN CA root once none does (core.md §11): tell it now, not at the next
        // heartbeat.
        edge.heartbeat_now.notify_one();
        // A certificate that isn't valid yet (core signed it with a clock ahead of ours) is
        // asked for again, but with the backoff, never in a loop (README §2 Clocks).
        match s.info().not_before_ts {
            Some(nb) if edge.clock.synced() && Timestamp::now().as_second() < nb => Err(anyhow::anyhow!(
                "core's certificate starts in the future ({}): is core's clock ahead?",
                s.info().not_before.as_deref().unwrap_or("?")
            )),
            _ => Ok(()),
        }
    });
    match outcome {
        Ok(()) => {
            let mut r = s.retry.lock().unwrap_or_else(|p| p.into_inner());
            r.next = None;
            r.delay = Duration::ZERO;
        }
        Err(e) => {
            tracing::warn!(
                "listener {}: certificate request failed: {}",
                s.listener,
                crate::diag::cap_chain(&e)
            );
            s.set_error(crate::diag::cap_chain(&e));
            let (min, max) = edge.dns.tuning.csr_backoff;
            let mut r = s.retry.lock().unwrap_or_else(|p| p.into_inner());
            r.delay = if r.delay.is_zero() {
                min
            } else {
                (r.delay * 2).min(max)
            };
            let jitter = 0.8 + rand::random::<f64>() * 0.4;
            r.next = Some(Instant::now() + r.delay.mul_f64(jitter));
        }
    }
}

async fn request(core: &Arc<CoreClient>, s: &Arc<CertSlot>, dir: &Path) -> anyhow::Result<()> {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    // Core takes the subject and SANs from the listener's config; the CSR supplies the key.
    let params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    let csr = params.serialize_request(&kp)?.pem()?;
    let resp = core
        .post_csr(&CsrRequest {
            csr_pem: csr,
            listener: s.listener.to_string(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("POST /v1/csr: {e}"))?;
    let mut chain_pem = resp.cert_pem.clone();
    if !chain_pem.ends_with('\n') {
        chain_pem.push('\n');
    }
    chain_pem.push_str(&resp.chain_pem);
    let key_pem = kp.serialize_pem();
    let (ck, chain) = certified_key(chain_pem.as_bytes(), key_pem.as_bytes())?;
    let leaf_spki = chain.first().and_then(spki_of);
    if leaf_spki.as_deref() != Some(rcgen::PublicKeyData::subject_public_key_info(&kp).as_slice()) {
        anyhow::bail!("core's certificate is for another key");
    }
    fsutil::create_dir_all_mode(dir, 0o700)?;
    store_pair(dir, &s.listener, combined_pem(&key_pem, &chain_pem).as_bytes())?;
    s.set(ck, describe(&chain, "managed"));
    tracing::info!("listener {}: new certificate from core", s.listener);
    Ok(())
}

/// The certificate task: checks every slot periodically and when woken.
pub async fn run(edge: Arc<Edge>, core: Option<Arc<CoreClient>>) -> anyhow::Result<()> {
    let every = edge.dns.tuning.certs_every;
    loop {
        edge.dns.certs.check_all(&edge, core.as_ref()).await;
        // Sooner while a request waits for its backoff.
        let soon = edge
            .dns
            .certs
            .all()
            .iter()
            .filter_map(|s| s.retry.lock().unwrap_or_else(|p| p.into_inner()).next)
            .min()
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(every)
            .min(every)
            .max(Duration::from_millis(50));
        tokio::select! {
            _ = tokio::time::sleep(soon) => {}
            _ = edge.dns.certs.wake.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sans_follow_the_config() {
        let (dns, ips) = desired_sans(
            "DNS.home.arpa.",
            &[
                "192.168.1.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                "fd00::1".parse().unwrap(),
            ],
        );
        assert_eq!(dns, vec!["*.dns.home.arpa", "dns.home.arpa"]);
        assert_eq!(ips.len(), 2, "public listener IPs are left out");
    }

    /// Golden (F4: `status`'s certificate dates; plan §5 step 1, unchanged after the move to
    /// jiff): RFC 3339 with `+00:00` in whole seconds, and the Unix seconds, including a
    /// `notAfter` of 9999-12-31T23:59:59Z, past the latest instant jiff's `Timestamp` holds.
    #[test]
    fn golden_certificate_dates() {
        let at = |y, m, d, secs| rcgen::date_time_ymd(y, m, d) + Duration::from_secs(secs);
        for (nb, na, want) in [
            (
                at(2026, 11, 13, 37_321),
                at(2027, 2, 11, 37_321),
                (
                    "2026-11-13T10:22:01+00:00",
                    1_794_565_321,
                    "2027-02-11T10:22:01+00:00",
                    1_802_341_321,
                ),
            ),
            (
                at(1970, 1, 1, 0),
                at(9999, 12, 31, 86_399),
                (
                    "1970-01-01T00:00:00+00:00",
                    0,
                    "9999-12-31T23:59:59+00:00",
                    253_402_300_799,
                ),
            ),
            (
                at(2000, 2, 29, 29_350),
                at(2049, 12, 31, 86_399),
                (
                    "2000-02-29T08:09:10+00:00",
                    951_811_750,
                    "2049-12-31T23:59:59+00:00",
                    2_524_607_999,
                ),
            ),
        ] {
            let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = rcgen::CertificateParams::new(vec!["dns.home.arpa".to_owned()]).unwrap();
            params.not_before = nb;
            params.not_after = na;
            let cert = params.self_signed(&kp).unwrap();
            let info = describe(&[cert.der().clone()], "user");
            let got = (
                info.not_before.as_deref().unwrap(),
                info.not_before_ts.unwrap(),
                info.not_after.as_deref().unwrap(),
                info.not_after_ts.unwrap(),
            );
            assert_eq!(got, want);
        }
    }

    fn pair(name: &str) -> String {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        combined_pem(&kp.serialize_pem(), &cert.pem())
    }

    fn leaf_names(dir: &Path) -> Option<(Vec<String>, bool)> {
        load_stored(dir, "lan-dot").map(|(_, chain, prev)| (describe(&chain, "managed").names, prev))
    }

    /// D9 (README §2 Restarts, edge.md §5): a renewal interrupted at any point leaves a stored
    /// pair whose key matches its certificate, so the edge still serves after a restart without
    /// core.
    #[test]
    fn a_renewal_interrupted_at_any_step_leaves_a_servable_pair() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let (cur, prev) = stored_names("lan-dot");
        let old = pair("old.home.arpa");
        let new = pair("new.home.arpa");
        store_pair(dir, "lan-dot", old.as_bytes()).unwrap();
        assert_eq!(leaf_names(dir), Some((vec!["old.home.arpa".into()], false)));
        // Crash after the first step (the old pair copied to `prev`), before the new one landed.
        std::fs::write(dir.join(&prev), &old).unwrap();
        assert_eq!(leaf_names(dir), Some((vec!["old.home.arpa".into()], false)));
        // A crash inside a write leaves only a temporary file beside an intact current pair.
        std::fs::write(dir.join(fsutil::tmp_name(&cur)), &new.as_bytes()[..new.len() / 2]).unwrap();
        assert_eq!(leaf_names(dir), Some((vec!["old.home.arpa".into()], false)));
        // The renewal completes: the new pair is current, the old one kept as the previous.
        store_pair(dir, "lan-dot", new.as_bytes()).unwrap();
        assert_eq!(leaf_names(dir), Some((vec!["new.home.arpa".into()], false)));
        assert_eq!(std::fs::read_to_string(dir.join(&prev)).unwrap(), old);
        // A current file that doesn't load (torn by a lost write, or a key that doesn't match):
        // the previous pair is served.
        std::fs::write(dir.join(&cur), &new.as_bytes()[..new.len() / 2]).unwrap();
        assert_eq!(leaf_names(dir), Some((vec!["old.home.arpa".into()], true)));
        let other_key = pair("x");
        let key_only: String = other_key
            .split("-----BEGIN CERTIFICATE-----")
            .next()
            .unwrap()
            .into();
        let cert_only = new.split_at(new.find("-----BEGIN CERTIFICATE-----").unwrap()).1;
        std::fs::write(dir.join(&cur), combined_pem(&key_only, cert_only)).unwrap();
        assert_eq!(leaf_names(dir), Some((vec!["old.home.arpa".into()], true)));
        // A broken current pair never overwrites the good previous one.
        store_pair(dir, "lan-dot", pair("third.home.arpa").as_bytes()).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join(&prev)).unwrap(), old);
        assert_eq!(leaf_names(dir), Some((vec!["third.home.arpa".into()], false)));
        // A listener id that isn't a file name stores nothing.
        assert!(store_pair(dir, "../escape", old.as_bytes()).is_err());
    }

    #[test]
    fn renewal_rules() {
        let ips: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
        let mut info = CertInfo {
            names: vec!["dns.home.arpa".into(), "*.dns.home.arpa".into()],
            ip_sans: ips.clone(),
            not_before_ts: Some(0),
            not_after_ts: Some(397 * 86_400),
            ..Default::default()
        };
        let day = 86_400;
        let n = "dns.home.arpa";
        assert!(
            needs_renewal(&info, false, n, &ips, None, false, true, 0),
            "no certificate yet"
        );
        assert!(!needs_renewal(&info, true, n, &ips, None, false, true, 264 * day));
        assert!(needs_renewal(&info, true, n, &ips, None, false, true, 265 * day));
        assert!(
            !needs_renewal(&info, true, n, &ips, None, false, false, 400 * day),
            "no wall-clock decision before the clock is synchronised"
        );
        // README §2 Clocks: a start still in the future (signed while a clock was ahead) is
        // replaced once the clock is synchronised, even when core issued it for these settings.
        let future = CertInfo {
            not_before_ts: Some(10 * day),
            not_after_ts: Some(407 * day),
            ..info.clone()
        };
        assert!(needs_renewal(&future, true, n, &ips, None, true, true, 9 * day));
        assert!(!needs_renewal(&future, true, n, &ips, None, true, false, 9 * day));
        assert!(!needs_renewal(&future, true, n, &ips, None, true, true, 10 * day));
        let other = "other.home.arpa";
        assert!(
            needs_renewal(&info, true, other, &ips, None, false, false, 0),
            "SANs changed"
        );
        assert!(
            !needs_renewal(&info, true, other, &ips, None, true, false, 0),
            "core already issued for these settings: no request loop"
        );
        // core.md §11: a new LAN CA root replaces certificates from the old one at once, clock or
        // not; one core issued for these settings ends the requests.
        info.root = Some("SHA256:old".into());
        assert!(!needs_renewal(
            &info,
            true,
            n,
            &ips,
            Some("SHA256:old"),
            false,
            false,
            0
        ));
        assert!(
            needs_renewal(&info, true, n, &ips, Some("SHA256:new"), false, false, 0),
            "another root issued it"
        );
        assert!(!needs_renewal(
            &info,
            true,
            n,
            &ips,
            Some("SHA256:new"),
            true,
            false,
            0
        ));
        assert!(
            !needs_renewal(&info, true, n, &ips, None, false, false, 0),
            "a config without a root checks none"
        );
        info.ip_sans.clear();
        assert!(needs_renewal(&info, true, n, &ips, None, false, false, 0));
    }

    /// The issuer is read from the stored chain, and only a chain certificate that signed the
    /// leaf counts.
    #[test]
    fn the_root_that_signed_the_leaf_is_known() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test root");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["dns.home.arpa".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let chain = vec![leaf.der().clone(), ca_cert.der().clone()];
        assert_eq!(
            describe(&chain, "managed").root.as_deref(),
            Some(picket_api::ids::cert_fingerprint(ca_cert.der()).as_str())
        );
        // A chain whose second certificate didn't sign the leaf names no root.
        let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut other = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        other.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        other
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test root");
        let other = other.self_signed(&other_key).unwrap();
        let chain = vec![leaf.der().clone(), other.der().clone()];
        assert_eq!(describe(&chain, "managed").root, None);
    }
}
