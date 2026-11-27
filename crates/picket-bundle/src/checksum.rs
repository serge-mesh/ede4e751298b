//! Set checksums (bundles.md §5): the sum mod 2¹²⁸ of `BLAKE3(entry)[..16]` over a shard's entries,
//! updated in O(delta). A domain entry is `key ‖ value`, an IP run `first ‖ last ‖ value`, a
//! verdict record `hash ‖ value`.
//!
//! Byte forms: a domain key is its reversed-name bytes and the value its `u64` little-endian; an
//! IP run's addresses are 16 bytes big-endian with IPv4 as IPv4-mapped (as `bundle_ip_ranges`
//! stores them, storage.md §3); a verdict record is its 16-byte little-endian hash and its
//! encoded value. The 16 BLAKE3 bytes are read as a little-endian `u128`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A set checksum.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SetChecksum(pub u128);

fn entry_hash(parts: &[&[u8]]) -> u128 {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(out.as_bytes().get(..16).unwrap_or(&[0; 16]));
    u128::from_le_bytes(b)
}

/// The 16-byte storage form of an IP address (IPv4 as IPv4-mapped), big-endian.
pub fn ip_storage_bytes(v4: bool, addr: u128) -> [u8; 16] {
    if v4 {
        let mapped = (0xffffu128 << 32) | (addr & 0xffff_ffff);
        mapped.to_be_bytes()
    } else {
        addr.to_be_bytes()
    }
}

impl SetChecksum {
    pub const ZERO: SetChecksum = SetChecksum(0);

    /// The hash one domain entry contributes.
    pub fn domain_entry(key: &[u8], value: u64) -> u128 {
        entry_hash(&[key, &value.to_le_bytes()])
    }

    /// The hash one IP run contributes.
    pub fn ip_entry(v4: bool, first: u128, last: u128, value: u64) -> u128 {
        entry_hash(&[
            &ip_storage_bytes(v4, first),
            &ip_storage_bytes(v4, last),
            &value.to_le_bytes(),
        ])
    }

    /// The hash one verdict record contributes.
    pub fn record_entry(hash: u128, value: &[u8]) -> u128 {
        entry_hash(&[&hash.to_le_bytes(), value])
    }

    /// Adds an entry's hash.
    #[must_use]
    pub fn plus(self, h: u128) -> SetChecksum {
        SetChecksum(self.0.wrapping_add(h))
    }

    /// Removes an entry's hash.
    #[must_use]
    pub fn minus(self, h: u128) -> SetChecksum {
        SetChecksum(self.0.wrapping_sub(h))
    }

    /// Adds a domain entry.
    #[must_use]
    pub fn add_domain(self, key: &[u8], value: u64) -> SetChecksum {
        self.plus(Self::domain_entry(key, value))
    }

    /// Removes a domain entry.
    #[must_use]
    pub fn sub_domain(self, key: &[u8], value: u64) -> SetChecksum {
        self.minus(Self::domain_entry(key, value))
    }

    /// 32 lowercase hex characters (the number, big-endian).
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }

    /// Parses [`SetChecksum::to_hex`].
    pub fn from_hex(s: &str) -> Option<SetChecksum> {
        crate::bytes::from_hex::<16>(s).map(|b| SetChecksum(u128::from_be_bytes(b)))
    }
}

impl fmt::Display for SetChecksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for SetChecksum {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SetChecksum {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SetChecksum::from_hex(&s).ok_or_else(|| serde::de::Error::custom("bad set checksum"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_free_and_updatable() {
        let a = SetChecksum::ZERO.add_domain(b"com.a", 1).add_domain(b"com.b", 3);
        let b = SetChecksum::ZERO.add_domain(b"com.b", 3).add_domain(b"com.a", 1);
        assert_eq!(a, b);
        let c = a.sub_domain(b"com.b", 3).add_domain(b"com.b", 2);
        assert_ne!(a, c);
        assert_eq!(
            c,
            SetChecksum::ZERO.add_domain(b"com.a", 1).add_domain(b"com.b", 2)
        );
        assert_eq!(SetChecksum::from_hex(&c.to_hex()), Some(c));
        assert_eq!(
            ip_storage_bytes(true, 0x0102_0304),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]
        );
    }
}
