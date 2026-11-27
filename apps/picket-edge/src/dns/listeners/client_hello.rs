//! What a refused ClientHello offered: its legacy version, its `supported_versions` list and its
//! SNI, read from the bytes a listener's handshake received (RFC 8446 §4.1.2, §4.2.1; RFC 5246
//! §7.4.1.2; RFC 6066 §3), for `tls_version_refused` events ([`super::handshake`]).
//!
//! rustls decides every refusal; this reader only describes the hello. It is needed because
//! rustls refuses a hello without `signature_algorithms` before it looks at versions
//! (`PeerIncompatible::SignatureAlgorithmsExtensionRequired`), and every TLS 1.0 and 1.1 client
//! sends such a hello (RFC 5246 §7.4.1.4.1 added the extension in TLS 1.2), and because rustls's
//! version refusals don't say what a `supported_versions` list held.
//!
//! The input is untrusted and bounded by the caller ([`super::handshake::MAX_HELLO_BYTES`]): the
//! reader joins the handshake records it holds (a ClientHello may span several), needs the whole
//! ClientHello inside them, and reads only lengths it has checked; anything else is `None`.
//! Fuzzed: `fuzz/edge` target `client_hello` (seeds in `fuzz/edge/corpus/client_hello/`).
//!
//! It is a diagnostic reader behind rustls, not a validator: by design it is lenient where rustls
//! is strict, since rustls has already refused the hello. A repeated extension counts by its last
//! copy, and bytes after the ClientHello (or after its extensions) are ignored. Its limits:
//! - an old hello larger than the capture ([`super::handshake::MAX_HELLO_BYTES`]) can't be read,
//!   so a refusal for lacking `signature_algorithms` produces no event (old stacks send a few
//!   hundred bytes); a version refusal still gets one, described from rustls's refusal alone;
//! - after a HelloRetryRequest the capture holds the first hello only, so a second hello without
//!   TLS 1.3 (RFC 8446 §4.1.2 forbids it) reads as offering TLS 1.3 and the event falls back to
//!   rustls's `no_tls13`.
//!
//! An SNI, read here or from rustls, is reported in one form ([`sni_text`]).

use std::net::IpAddr;

use picket_api::logs::tls_offered;

const HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLS12: u16 = 0x0303;
const TLS13: u16 = 0x0304;
/// The longest DNS name (RFC 1035 §2.3.4, in presentation form without the trailing dot).
const MAX_SNI: usize = 253;

/// The versions and name a ClientHello offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloOffer {
    /// `legacy_version` (TLS 1.2 and earlier: `client_version`, the newest version offered).
    pub legacy: u16,
    /// The `supported_versions` list, GREASE values (RFC 8701) left out, when the extension is
    /// there. At most 127 entries (a one-byte length).
    pub supported: Option<Vec<u16>>,
    /// The first `host_name` of `server_name`, lowercase, when it is a DNS name.
    pub sni: Option<String>,
}

impl HelloOffer {
    pub fn offers_tls13(&self) -> bool {
        self.supported.as_ref().is_some_and(|v| v.contains(&TLS13))
    }

    /// What it offered instead of TLS 1.3, as `tls_version_refused`'s `offered` says it (one of
    /// [`picket_api::logs::tls_offered`]); `None` when it offers TLS 1.3. The newest version
    /// offered decides: the newest of SSL 3.0 to TLS 1.2 in `supported_versions`, or without that
    /// extension the legacy version (rustls reads one of TLS 1.2 or above as TLS 1.2).
    pub fn offered(&self) -> Option<&'static str> {
        let newest = match &self.supported {
            Some(_) if self.offers_tls13() => return None,
            Some(v) => v.iter().copied().filter(|x| (0x0300..=TLS12).contains(x)).max(),
            None => Some(self.legacy),
        };
        Some(match newest {
            Some(v) if v >= TLS12 => tls_offered::TLS12,
            Some(_) => tls_offered::TLS11_OR_OLDER,
            None => tls_offered::NO_TLS13,
        })
    }
}

/// A bounds-checked reader over a byte slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
    /// A sub-reader over the next `n` bytes.
    fn sub(&mut self, n: usize) -> Option<Reader<'a>> {
        self.take(n).map(Reader)
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The ClientHello at the start of `received` (TLS records as a client sent them), or `None`
/// when they don't hold a whole, well-formed one.
pub fn read(received: &[u8]) -> Option<HelloOffer> {
    // Join the leading handshake records' fragments (RFC 8446 §5.1): never more bytes than given.
    let mut msg = Vec::new();
    let mut r = Reader(received);
    while let Some(header) = r.take(5) {
        if header[0] != HANDSHAKE {
            break;
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        match r.take(len) {
            Some(fragment) => msg.extend_from_slice(fragment),
            None => {
                msg.extend_from_slice(r.0);
                break;
            }
        }
    }
    let mut m = Reader(&msg);
    if m.u8()? != CLIENT_HELLO {
        return None;
    }
    let len = m.u24()?;
    let mut b = m.sub(len)?;
    let legacy = b.u16()?;
    b.take(32)?; // random
    let session_id = b.u8()?;
    b.take(usize::from(session_id))?;
    let suites = b.u16()?;
    b.take(usize::from(suites))?;
    let compression = b.u8()?;
    b.take(usize::from(compression))?;
    let mut offer = HelloOffer {
        legacy,
        supported: None,
        sni: None,
    };
    // Extensions are optional before TLS 1.3 (RFC 5246 §7.4.1.2).
    if b.is_empty() {
        return Some(offer);
    }
    let ext_len = b.u16()?;
    let mut exts = b.sub(usize::from(ext_len))?;
    while !exts.is_empty() {
        let kind = exts.u16()?;
        let len = exts.u16()?;
        let mut data = exts.sub(usize::from(len))?;
        match kind {
            EXT_SUPPORTED_VERSIONS => offer.supported = Some(versions(&mut data)?),
            EXT_SERVER_NAME => offer.sni = server_name(&mut data),
            _ => {}
        }
    }
    Some(offer)
}

/// RFC 8701 GREASE values: 0x0A0A, 0x1A1A, … 0xFAFA.
fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn versions(data: &mut Reader<'_>) -> Option<Vec<u16>> {
    let n = data.u8()?;
    let mut list = data.sub(usize::from(n))?;
    let mut out = Vec::with_capacity(usize::from(n) / 2);
    while !list.is_empty() {
        let v = list.u16()?;
        if !grease(v) {
            out.push(v);
        }
    }
    Some(out)
}

/// The first `host_name` entry, in [`sni_text`]'s form.
fn server_name(data: &mut Reader<'_>) -> Option<String> {
    let n = data.u16()?;
    let mut list = data.sub(usize::from(n))?;
    while !list.is_empty() {
        let kind = list.u8()?;
        let len = list.u16()?;
        let name = list.take(usize::from(len))?;
        if kind == 0 {
            return sni_text(std::str::from_utf8(name).ok()?);
        }
    }
    None
}

/// An SNI as `tls_version_refused` reports it, whether this reader or rustls read it: lowercase,
/// without a trailing dot, of `a-z`, `0-9`, `.`, `-` and `_` only, at most 253 bytes, and a DNS
/// name, not an address (RFC 6066 §3); anything else is `None`.
pub fn sni_text(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let chars_ok = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_'));
    (chars_ok
        && !name.is_empty()
        && !name.ends_with('.')
        && name.len() <= MAX_SNI
        && name.parse::<IpAddr>().is_err()
        && rustls_pki_types::DnsName::try_from(name.as_str()).is_ok())
    .then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A ClientHello: `legacy`, `exts` as (type, data) pairs, wrapped in one record.
    fn hello(legacy: u16, exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = legacy.to_be_bytes().to_vec();
        body.extend([7u8; 32]);
        body.extend([0, 0, 2, 0xc0, 0x2f, 1, 0]);
        let mut e = vec![];
        for (k, d) in exts {
            e.extend(k.to_be_bytes());
            e.extend((d.len() as u16).to_be_bytes());
            e.extend(d);
        }
        if !exts.is_empty() {
            body.extend((e.len() as u16).to_be_bytes());
            body.extend(e);
        }
        let mut m = vec![CLIENT_HELLO];
        m.extend(&(body.len() as u32).to_be_bytes()[1..]);
        m.extend(body);
        records(&m, usize::MAX)
    }

    /// `msg` in handshake records of at most `size` bytes each.
    fn records(msg: &[u8], size: usize) -> Vec<u8> {
        let mut out = vec![];
        for c in msg.chunks(size.min(16_384)) {
            out.extend([HANDSHAKE, 3, 1]);
            out.extend((c.len() as u16).to_be_bytes());
            out.extend(c);
        }
        out
    }

    fn sv(vs: &[u16]) -> (u16, Vec<u8>) {
        let mut d = vec![(vs.len() * 2) as u8];
        for v in vs {
            d.extend(v.to_be_bytes());
        }
        (EXT_SUPPORTED_VERSIONS, d)
    }

    fn sni(name: &str) -> (u16, Vec<u8>) {
        let mut entry = vec![0u8];
        entry.extend((name.len() as u16).to_be_bytes());
        entry.extend(name.as_bytes());
        let mut d = (entry.len() as u16).to_be_bytes().to_vec();
        d.extend(entry);
        (EXT_SERVER_NAME, d)
    }

    /// The first flight of a rustls client offering `versions`.
    fn rustls_hello(versions: &[&'static rustls::SupportedProtocolVersion]) -> Vec<u8> {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let name = rustls_pki_types::ServerName::try_from("Dns.Home.Arpa").unwrap();
        let mut c = rustls::ClientConnection::new(Arc::new(cfg), name).unwrap();
        let mut out = vec![];
        while c.wants_write() {
            c.write_tls(&mut out).unwrap();
        }
        out
    }

    #[test]
    fn rustls_hellos_with_and_without_tls13() {
        let h = read(&rustls_hello(&[&rustls::version::TLS12])).unwrap();
        assert_eq!(h.supported, Some(vec![TLS12]));
        assert_eq!(h.sni.as_deref(), Some("dns.home.arpa"));
        assert_eq!(h.offered(), Some(tls_offered::TLS12));
        let h = read(&rustls_hello(rustls::ALL_VERSIONS)).unwrap();
        assert!(h.offers_tls13());
        assert_eq!(h.offered(), None);
    }

    #[test]
    fn the_newest_version_offered_decides() {
        let old = |legacy| read(&hello(legacy, &[])).unwrap().offered();
        assert_eq!(
            old(0x0301),
            Some(tls_offered::TLS11_OR_OLDER),
            "TLS 1.0, no extensions"
        );
        assert_eq!(old(0x0302), Some(tls_offered::TLS11_OR_OLDER), "TLS 1.1");
        assert_eq!(old(0x0300), Some(tls_offered::TLS11_OR_OLDER), "SSL 3.0");
        assert_eq!(old(0x0303), Some(tls_offered::TLS12));
        let listed = |vs: &[u16]| read(&hello(0x0303, &[sv(vs)])).unwrap().offered();
        assert_eq!(listed(&[0x0302, 0x0301]), Some(tls_offered::TLS11_OR_OLDER));
        assert_eq!(
            listed(&[0x1a1a, 0x0303]),
            Some(tls_offered::TLS12),
            "GREASE left out"
        );
        assert_eq!(
            listed(&[0x7f1c]),
            Some(tls_offered::NO_TLS13),
            "a TLS 1.3 draft only"
        );
        assert_eq!(listed(&[0x2a2a, 0x0304, 0x0303]), None, "offers TLS 1.3");
    }

    #[test]
    fn the_sni_is_a_lowercase_dns_name_or_nothing() {
        let name = |n: &str| read(&hello(0x0303, &[sni(n)])).unwrap().sni;
        assert_eq!(name("Old.Dns.Home.Arpa."), Some("old.dns.home.arpa".into()));
        assert_eq!(name("192.168.1.1"), None);
        assert_eq!(name("bad name"), None);
        assert_eq!(name(&"a".repeat(254)), None);
        assert_eq!(name("dns.home.arpa.."), None);
        assert_eq!(name("*.dns.home.arpa"), None);
        // rustls's form (it keeps a trailing dot) comes out the same.
        assert_eq!(sni_text("Dns.Home.Arpa."), Some("dns.home.arpa".into()));
        assert_eq!(sni_text("dns.home.arpa"), Some("dns.home.arpa".into()));
    }

    #[test]
    fn a_repeated_extension_counts_by_its_last_copy_and_trailing_bytes_are_ignored() {
        let mut h = hello(
            0x0303,
            &[
                sv(&[0x0304, 0x0303]),
                sv(&[0x0303]),
                sni("a.example"),
                sni("b.example"),
            ],
        );
        let r = read(&h).unwrap();
        assert_eq!(
            (r.supported, r.sni.as_deref()),
            (Some(vec![0x0303]), Some("b.example"))
        );
        h.extend([0x15, 3, 3, 0, 2, 2, 40]);
        assert!(read(&h).is_some());
    }

    #[test]
    fn fragments_are_joined_and_anything_short_or_foreign_is_none() {
        let whole = hello(0x0301, &[sni("dns.home.arpa"), sv(&[0x0302])]);
        let msg = &whole[5..];
        let split = read(&records(msg, 7)).unwrap();
        assert_eq!(split, read(&whole).unwrap());
        assert_eq!(split.supported, Some(vec![0x0302]));
        // Every truncation is None, never a panic.
        for n in 0..whole.len() {
            assert_eq!(read(&whole[..n]), None, "{n}");
        }
        // Not a handshake record (plain DNS on port 853, HTTP on a DoH port).
        assert_eq!(read(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(read(&[0, 29, 0x12, 0x34, 1, 0]), None);
        // A length running past its container.
        let mut bad = whole.clone();
        let at = bad.len() - 3; // supported_versions' list length
        bad[at] = 200;
        assert_eq!(read(&bad), None);
    }
}
