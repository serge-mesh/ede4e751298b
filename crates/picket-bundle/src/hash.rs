//! Key hashing (bundles.md §4 "Shards", providers.md §4 "Verdict cache").
//!
//! A domain key's identity is `xxh3_128(hash_seed, reversed name)`: the low 64 bits feed the
//! binary fuse filter and place a record in a page file, the top 8 bits of the high half index the
//! 256-entry shard directory, and the whole 128 bits key the overlays (bundles.md §6). A verdict
//! set hashes the name itself with its own seed.
//!
//! `hash_seed` is derived from the bundle id (or the lookup provider and its cache generation)
//! and the format version, so the same inputs always give the same files (bundles.md §2
//! "Determinism"); it changes only with a format change, which rebuilds every shard.

use xxhash_rust::xxh3::xxh3_128_with_seed;

use crate::FORMAT;

/// A key's 128-bit hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyHash(pub u128);

impl KeyHash {
    /// `xxh3_128(seed, bytes)`.
    pub fn of(seed: u64, bytes: &[u8]) -> KeyHash {
        KeyHash(xxh3_128_with_seed(bytes, seed))
    }

    /// The low 64 bits: the filter's key and the page-file placement.
    pub fn low64(self) -> u64 {
        halves(self.0).0
    }

    /// The high 64 bits.
    pub fn high64(self) -> u64 {
        (self.0 >> 64) as u64
    }

    /// The top 8 bits of the high half: the shard directory index.
    pub fn dir_index(self) -> u8 {
        (self.0 >> 120) as u8
    }

    /// The 16 little-endian bytes (as in page files and checksums).
    pub fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// 32 hex characters (verdict-set delta keys): the hash as a big-endian number.
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }

    /// Parses [`KeyHash::to_hex`].
    pub fn from_hex(s: &str) -> Option<KeyHash> {
        let b = crate::bytes::from_hex::<16>(s)?;
        Some(KeyHash(u128::from_be_bytes(b)))
    }
}

fn derive_seed(context: &str, parts: &[&[u8]]) -> u64 {
    let mut h = blake3::Hasher::new_derive_key(context);
    h.update(&FORMAT.to_le_bytes());
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let out = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(out.as_bytes().get(..8).unwrap_or(&[0; 8]));
    u64::from_le_bytes(b)
}

/// A bundle's `hash_seed`, from its id and the format version (bundles.md §2, §4).
pub fn bundle_hash_seed(bundle: &str) -> u64 {
    derive_seed("picket-bundle 2026-11 bundle hash_seed", &[bundle.as_bytes()])
}

/// A verdict set's `hash_seed`, from the lookup provider id, its cache generation and the format
/// version (providers.md §4).
pub fn verdict_hash_seed(provider: &str, generation: &str) -> u64 {
    derive_seed(
        "picket-bundle 2026-11 verdict-set hash_seed",
        &[provider.as_bytes(), generation.as_bytes()],
    )
}

/// The low and high 64-bit halves of a 128-bit hash.
#[expect(
    clippy::cast_possible_truncation,
    reason = "splits a u128 into its two 64-bit halves"
)]
pub(crate) const fn halves(h: u128) -> (u64, u64) {
    (h as u64, (h >> 64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_are_stable_and_distinct() {
        assert_eq!(bundle_hash_seed("block-common"), bundle_hash_seed("block-common"));
        assert_ne!(bundle_hash_seed("block-common"), bundle_hash_seed("allow-common"));
        assert_ne!(verdict_hash_seed("a", "bc"), verdict_hash_seed("ab", "c"));
    }

    #[test]
    fn parts() {
        let h = KeyHash(0xAB00_0000_0000_0000_0000_0000_0000_0001);
        assert_eq!(h.dir_index(), 0xAB);
        assert_eq!(h.low64(), 1);
        assert_eq!(KeyHash::from_hex(&h.to_hex()), Some(h));
    }
}
