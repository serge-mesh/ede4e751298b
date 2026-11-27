//! Identifiers shared by core and edge (api.md §1, §2, §4).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Prefix of a key fingerprint.
pub const FP_PREFIX: &str = "SHA256:";

/// Fingerprint of a SubjectPublicKeyInfo: `SHA256:<base64 of SHA-256(SPKI DER)>` (api.md §1).
pub fn fingerprint_spki(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    format!("{FP_PREFIX}{}", STANDARD_NO_PAD.encode(digest))
}

/// Parses a `SHA256:…` fingerprint into its 32-byte hash. Accepts padded or unpadded base64.
pub fn parse_fingerprint(fp: &str) -> Option<[u8; 32]> {
    let b64 = fp.strip_prefix(FP_PREFIX)?.trim_end_matches('=');
    let bytes = STANDARD_NO_PAD.decode(b64).ok()?;
    bytes.try_into().ok()
}

/// The path form of a fingerprint: the hash as unpadded base64url, without `SHA256:` (api.md §1).
pub fn fingerprint_path(fp_hash: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(fp_hash)
}

/// Parses the path form back into the hash.
pub fn parse_fingerprint_path(path: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(path).ok()?;
    bytes.try_into().ok()
}

/// Formats a 32-byte hash as a `SHA256:…` fingerprint.
pub fn fingerprint_from_hash(hash: &[u8; 32]) -> String {
    format!("{FP_PREFIX}{}", STANDARD_NO_PAD.encode(hash))
}

/// A certificate's fingerprint: `SHA256:` and the lowercase hex SHA-256 of its DER bytes, as
/// browsers show it. The LAN CA root's (core.md §11) is shown under Settings and carried in
/// `EdgeConfig.lanca_root`, against which an edge checks the root that issued its managed
/// listener certificates (edge.md §5).
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(cert_der);
    let mut s = String::with_capacity(FP_PREFIX.len() + 64);
    s.push_str(FP_PREFIX);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// True when `s` is a well-formed [`cert_fingerprint`]: `SHA256:` and 64 lowercase hex
/// characters.
pub fn is_cert_fingerprint(s: &str) -> bool {
    s.strip_prefix(FP_PREFIX).is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// An object id: the BLAKE3 of an object's bytes as 64 lowercase hex characters (api.md §2).
pub fn object_id(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// True when `s` is a well-formed object id (64 lowercase hex characters).
pub fn is_object_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The short form of an id used in logs, `versions` and EDE text: its first 16 hex characters.
pub fn short_id(id: &str) -> &str {
    id.get(..16).unwrap_or(id)
}

/// A new random 64-bit id written as 16 lowercase hex characters: request ids, cache
/// generations, revoke-list ids and updater result ids (api.md §4, providers.md §4).
pub fn new_id64() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// True when `s` is 16 lowercase hex characters.
pub fn is_id64(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A new random boot id, generated once per process start (edge.md §11).
pub fn new_boot_id() -> String {
    format!("{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff)
}

/// The BLAKE3 of a canonical JSON value: object keys sorted, no whitespace (storage.md §3).
pub fn canonical_json_blake3(value: &serde_json::Value) -> String {
    let bytes = canonical_json(value);
    object_id(&bytes)
}

/// Serialises a JSON value canonically: object keys sorted, no whitespace.
pub fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    if let Some(val) = m.get(k) {
                        out.insert(k.clone(), sort(val));
                    }
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    // serde_json's Map preserves insertion order only with `preserve_order`; without it the
    // map is a BTreeMap and already sorted. Sorting explicitly keeps this correct either way.
    serde_json::to_vec(&sort(value)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_roundtrip() {
        let fp = fingerprint_spki(b"example spki");
        let hash = parse_fingerprint(&fp).unwrap();
        assert_eq!(fingerprint_from_hash(&hash), fp);
        let path = fingerprint_path(&hash);
        assert!(!path.contains('='));
        assert_eq!(parse_fingerprint_path(&path).unwrap(), hash);
    }

    #[test]
    fn cert_fingerprints_are_hex_sha256() {
        let fp = cert_fingerprint(b"abc");
        assert_eq!(
            fp,
            "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_cert_fingerprint(&fp));
        for bad in [
            "",
            "SHA256:",
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a",
            "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015adx",
        ] {
            assert!(!is_cert_fingerprint(bad), "{bad}");
        }
    }

    #[test]
    fn ids() {
        let id = object_id(b"x");
        assert!(is_object_id(&id));
        assert_eq!(short_id(&id).len(), 16);
        assert!(is_id64(&new_id64()));
    }

    #[test]
    fn canonical() {
        let v: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":{"d":2,"c":3}}"#).unwrap();
        assert_eq!(canonical_json(&v), br#"{"a":{"c":3,"d":2},"b":1}"#);
    }
}
