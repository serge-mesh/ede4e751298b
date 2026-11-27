//! `domains.fst` (bundles.md §4): an [`fst::Map`] from the reversed name (`org.example.ads`) to the
//! key's [`Value`], built streaming from keys in sorted order. No feed data.
//!
//! The reader takes the file into a `Vec<u8>` (`fst::Map::new`, heap), checks the FST's own
//! CRC-32C checksum (`Fst::verify`), that its key count is the manifest's, and walks its structure
//! once (the cost of streaming every key), because the `fst` crate's lookups index into the file
//! without bounds checks of their own and would panic on a crafted file that passes its checksum.
//!
//! **Walk budget** (README §2 "Bounded", "Untrusted input"; review round 1, B4): the walk visits
//! each trie node of the key set once per path reaching it, so a valid FST costs two steps per
//! trie edge (its node's transitions checked, the transition followed): at most twice the total
//! key length, ≤ 2 × keys × [`MAX_KEY_LEN`], however small the file (shared tails compress
//! hundreds of thousands of keys into a few hundred bytes). The budget is that, from the
//! manifest's key count, plus 256 steps per possible index table; the walk also stops as soon as it
//! has seen more keys than the manifest claims, and a manifest claiming more than
//! [`MAX_SHARD_KEYS`] is refused before walking. A crafted file can so cost at most
//! ≈ 2 × [`MAX_SHARD_KEYS`] × 253 ≈ 2 G steps (seconds to tens of seconds), against ~6.7 G for a
//! 13 MB file under the old size-based budget, and valid files are never refused.

use crate::value::Value;

/// Why an FST file is refused or can't be built.
#[derive(Debug, thiserror::Error)]
pub enum FstError {
    #[error("fst: {0}")]
    Fst(#[from] fst::Error),
    #[error("keys out of order or repeated at {0:?}")]
    Order(String),
    #[error("key count {got} doesn't match the manifest's {want}")]
    Count { got: u64, want: u64 },
    #[error("a key is empty or longer than 253 bytes")]
    Key,
    #[error("fst structure refused: {0}")]
    Structure(String),
    #[error("a shard holds at most {MAX_SHARD_KEYS} keys")]
    TooManyKeys,
}

/// The longest key (a name of at most 253 bytes, rules.md §1).
pub const MAX_KEY_LEN: usize = 253;

/// Streams sorted keys into an FST.
pub struct FstWriter {
    builder: fst::MapBuilder<Vec<u8>>,
    last: Vec<u8>,
    count: u64,
}

impl Default for FstWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl FstWriter {
    pub fn new() -> FstWriter {
        FstWriter {
            builder: fst::MapBuilder::memory(),
            last: Vec::new(),
            count: 0,
        }
    }

    /// Adds the next key; keys must be strictly increasing (bytewise). Refused past
    /// [`MAX_SHARD_KEYS`], which the reader refuses, so the writer never builds a base no edge
    /// would load (review round 2, CR3; the shard planner splits before that, [`crate::shard_dir::plan`]).
    pub fn insert(&mut self, key: &[u8], value: Value) -> Result<(), FstError> {
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Err(FstError::Key);
        }
        if self.count >= MAX_SHARD_KEYS {
            return Err(FstError::TooManyKeys);
        }
        if self.count > 0 && key <= self.last.as_slice() {
            return Err(FstError::Order(String::from_utf8_lossy(key).into_owned()));
        }
        self.builder.insert(key, value.0)?;
        self.last.clear();
        self.last.extend_from_slice(key);
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Keys added.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The FST bytes.
    pub fn finish(self) -> Result<Vec<u8>, FstError> {
        Ok(self.builder.into_inner()?)
    }
}

/// A loaded `domains.fst`.
pub struct DomainsFst {
    map: fst::Map<Vec<u8>>,
    /// The largest `rich_idx` among its values (`None` without rich values).
    max_rich: Option<u32>,
}

impl std::fmt::Debug for DomainsFst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainsFst")
            .field("keys", &self.map.len())
            .finish()
    }
}

/// Most keys one shard's FST may hold on the edge: four times the default `max_shard_keys`
/// (bundles.md §1), room for a shard that can't split again and grows (§4 "Shards"), ≈ 52 MB of
/// FST at 13 B/key, beyond any edge's `bundle_budget_mib` default. Policy bound (owner to confirm).
pub const MAX_SHARD_KEYS: u64 = 4 * 1024 * 1024;

/// Walks every node reachable from the root as a lookup would: each transition, every input byte
/// of each node with an index table, every final output. Returns the number of keys. Paths deeper
/// than [`MAX_KEY_LEN`] (or cycles), outputs past the value's defined bits, more keys than
/// `expected`, and work past the step budget (see the module docs) are refused. Any panic inside
/// `fst` on a malformed node is caught and refused, so once this passes, [`DomainsFst::get`] only
/// touches validated nodes and can't panic or overflow.
fn walk(map: &fst::Map<Vec<u8>>, expected: u64) -> Result<(u64, Option<u32>), String> {
    let raw = map.as_fst();
    // Two steps per trie edge, ≤ keys × MAX_KEY_LEN edges; 256 per index table (a node with one
    // has > 32 transitions, so at least 33 bytes).
    let budget = expected
        .saturating_mul((MAX_KEY_LEN as u64).saturating_mul(2))
        .saturating_add((raw.size() as u64 / 33).saturating_add(1).saturating_mul(256))
        .saturating_add(4096);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(u64, Option<u32>), String> {
            let mut steps = 0u64;
            let mut keys = 0u64;
            let mut max_rich: Option<u32> = None;
            let mut dense_ok: std::collections::HashSet<usize> = std::collections::HashSet::new();
            // (node address, next transition, depth, output so far)
            let mut stack: Vec<(usize, usize, usize, u64)> = vec![(raw.root().addr(), 0, 0, 0)];
            while let Some(top) = stack.last_mut() {
                let (addr, i, depth, out) = *top;
                let node = raw.node(addr);
                if i == 0 {
                    if node.is_final() {
                        // A key's value: the outputs along its path plus the final output (each at
                        // most `Value::DEFINED`, at most 254 of them: no overflow).
                        let v = out.wrapping_add(node.final_output().value());
                        if node.final_output().value() > Value::DEFINED || v > Value::DEFINED {
                            return Err("output out of range".into());
                        }
                        if let Some(r) = Value(v).rich_idx() {
                            max_rich = max_rich.max(Some(r));
                        }
                        keys = keys.saturating_add(1);
                        if keys > expected {
                            return Err("more keys than the manifest's".into());
                        }
                    }
                    // Inputs strictly increasing, so a lookup's scan finds exactly the transitions
                    // the walk follows.
                    let mut prev: Option<u8> = None;
                    for j in 0..node.len() {
                        let inp = node.transition(j).inp;
                        if prev.is_some_and(|p| p >= inp) {
                            return Err("transitions out of order".into());
                        }
                        prev = Some(inp);
                    }
                    steps = steps.saturating_add(node.len() as u64);
                    if steps > budget {
                        return Err("structure too large for its key count".into());
                    }
                    // A node with an index table: the index agrees with the transitions both ways.
                    if node.len() > 32 && dense_ok.insert(addr) {
                        for b in 0..=255u8 {
                            if let Some(j) = node.find_input(b)
                                && (j >= node.len() || node.transition(j).inp != b)
                            {
                                return Err("bad transition index".into());
                            }
                        }
                        for j in 0..node.len() {
                            if node.find_input(node.transition(j).inp) != Some(j) {
                                return Err("index misses a transition".into());
                            }
                        }
                        steps = steps.saturating_add(256);
                    }
                }
                if i >= node.len() {
                    stack.pop();
                    continue;
                }
                top.1 = i.saturating_add(1);
                let t = node.transition(i);
                if t.out.value() > Value::DEFINED {
                    return Err("output out of range".into());
                }
                steps = steps.saturating_add(1);
                if steps > budget {
                    return Err("structure too large for its key count".into());
                }
                let d = depth.saturating_add(1);
                if d > MAX_KEY_LEN {
                    return Err("path longer than any key (or a cycle)".into());
                }
                // Touch the child now, so a bad address fails here.
                let _ = raw.node(t.addr).len();
                stack.push((t.addr, 0, d, out.wrapping_add(t.out.value())));
            }
            Ok((keys, max_rich))
        },
    ));
    match res {
        Ok(r) => r,
        Err(_) => Err("malformed node".into()),
    }
}

impl DomainsFst {
    /// Loads and checks an FST holding `keys` keys: its format, its CRC-32C checksum, and a
    /// structural walk of every reachable node (`walk`), so lookups never panic on a crafted file.
    pub fn from_bytes(data: Vec<u8>, keys: u64) -> Result<DomainsFst, FstError> {
        let map = fst::Map::new(data)?;
        map.as_fst().verify()?;
        let got = map.len() as u64;
        if got != keys || keys > MAX_SHARD_KEYS {
            return Err(FstError::Count { got, want: keys });
        }
        let (walked, max_rich) = walk(&map, keys).map_err(FstError::Structure)?;
        if walked != keys {
            return Err(FstError::Count {
                got: walked,
                want: keys,
            });
        }
        Ok(DomainsFst { map, max_rich })
    }

    /// The largest `rich_idx` among the values (checked against the part's `rich.json`).
    pub fn max_rich_idx(&self) -> Option<u32> {
        self.max_rich
    }

    /// The value of `key`.
    pub fn get(&self, key: &[u8]) -> Option<Value> {
        self.map.get(key).map(Value::from_stored)
    }

    /// Key count.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Bytes held.
    pub fn memory_usage(&self) -> usize {
        self.map.as_fst().size()
    }

    /// Every key and value, in order (tests and diagnostics).
    pub fn entries(&self) -> Vec<(Vec<u8>, Value)> {
        use fst::Streamer;
        let mut out = Vec::with_capacity(self.map.len());
        let mut s = self.map.stream();
        while let Some((k, v)) = s.next() {
            out.push((k.to_vec(), Value::from_stored(v)));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_rules::Flags;

    #[test]
    fn build_and_read() {
        let mut w = FstWriter::new();
        w.insert(b"com.example", Value::flags_only(Flags::B_EXACT))
            .unwrap();
        w.insert(b"com.example.ads", Value::flags_only(Flags::B_SUBS))
            .unwrap();
        assert!(w.insert(b"com.example", Value(1)).is_err(), "order");
        let bytes = w.finish().unwrap();
        let f = DomainsFst::from_bytes(bytes.clone(), 2).unwrap();
        assert_eq!(f.get(b"com.example"), Some(Value(1)));
        assert_eq!(f.get(b"com.examplex"), None);
        assert!(matches!(
            DomainsFst::from_bytes(bytes.clone(), 3),
            Err(FstError::Count { .. })
        ));
        let mut bad = bytes;
        let n = bad.len();
        bad[n - 10] ^= 0x55;
        assert!(DomainsFst::from_bytes(bad, 2).is_err(), "checksum");
    }

    /// fst's checksum (CRC-32C, masked), so a test can corrupt a node and still pass `verify`.
    fn fix_crc(b: &mut [u8]) {
        let n = b.len() - 4;
        let mut crc: u32 = !0;
        for &x in &b[..n] {
            crc ^= u32::from(x);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0x82F6_3B78
                } else {
                    crc >> 1
                };
            }
        }
        let sum = !crc;
        let masked = (sum.wrapping_shr(15) | sum.wrapping_shl(17)).wrapping_add(0xA282_EAD8);
        b[n..].copy_from_slice(&masked.to_le_bytes());
    }

    fn fst_of(keys: &[Vec<u8>]) -> Vec<u8> {
        let mut w = FstWriter::new();
        for k in keys {
            w.insert(k, Value::flags_only(Flags::B_EXACT)).unwrap();
        }
        w.finish().unwrap()
    }

    /// Review round 1, B4: the walk's budget follows the manifest's key count, not the file's
    /// size, so valid, highly compressible FSTs load.
    #[test]
    fn compressible_fsts_load() {
        // Sequential names: a few hundred bytes of FST for 600,000 keys (Codex's case).
        let keys: Vec<Vec<u8>> = (0..600_000u32)
            .map(|i| format!("com.example.a{i:06}").into_bytes())
            .collect();
        let b = fst_of(&keys);
        assert!(b.len() < 4096, "{}", b.len());
        let f = DomainsFst::from_bytes(b, keys.len() as u64).unwrap();
        assert_eq!(f.get(b"com.example.a012345"), Some(Value(1)));
        // 16,384 218-byte keys sharing a 200-byte tail (Opus's case).
        let tail: String = (0..20).map(|_| "aaaaaaaaa").collect::<Vec<_>>().join(".");
        let mut keys: Vec<Vec<u8>> = (0u32..(1 << 14))
            .map(|i| {
                let lab: String = (0..14).map(|b| if i >> b & 1 == 1 { 'b' } else { 'a' }).collect();
                format!("com.{lab}.{tail}").into_bytes()
            })
            .collect();
        keys.sort();
        let b = fst_of(&keys);
        assert!(b.len() < 1024, "{}", b.len());
        assert!(DomainsFst::from_bytes(b, keys.len() as u64).is_ok());
    }

    /// The walk stops as soon as it has seen more keys than the manifest claims, and a manifest
    /// claiming more keys than any shard holds is refused before walking.
    #[test]
    fn walk_is_bounded_by_the_claimed_count() {
        let keys: Vec<Vec<u8>> = (0..1000u32)
            .map(|i| format!("com.k{i:04}").into_bytes())
            .collect();
        let b = fst_of(&keys);
        let raw = fst::Map::new(b.clone()).unwrap();
        assert!(walk(&raw, 999).is_err(), "more keys than claimed");
        assert_eq!(walk(&raw, 1000), Ok((1000, None)));
        assert!(matches!(
            DomainsFst::from_bytes(b, MAX_SHARD_KEYS + 1),
            Err(FstError::Count { .. })
        ));
    }

    #[test]
    fn structural_walk_refuses_crafted_nodes() {
        // Found by fuzzing: one byte changed in a node, checksum fixed: transitions out of order,
        // so streaming finds keys a lookup doesn't. Refused at load.
        let keys: [&[u8]; 3] = [
            b"\r\0\0\0\0\0\0\0\\\r\r",
            b"\r\0\r\r\r\r\r\x01\0\0\0\0\0\0W\ree",
            b"\r\0\r\re*`",
        ];
        let mut w = FstWriter::new();
        for (i, k) in keys.iter().enumerate() {
            w.insert(k, Value(i as u64 * 977)).unwrap();
        }
        let good = w.finish().unwrap();
        assert!(DomainsFst::from_bytes(good.clone(), 3).is_ok());
        let mut b = good.clone();
        b[91] ^= 0x0d;
        fix_crc(&mut b);
        assert!(matches!(
            DomainsFst::from_bytes(b, 3),
            Err(FstError::Structure(_))
        ));
        // Every single-byte change with the checksum fixed: refused, or consistent (each key
        // the walk counts is found by a lookup), and never a panic escaping the loader.
        for at in 0..good.len() - 4 {
            for x in [0x01u8, 0x80, 0xff] {
                let mut b = good.clone();
                b[at] ^= x;
                fix_crc(&mut b);
                if let Ok(f) = DomainsFst::from_bytes(b, 3) {
                    for (k, _) in f.entries() {
                        assert!(f.get(&k).is_some(), "at {at} ^ {x}");
                    }
                }
            }
        }
    }
}
