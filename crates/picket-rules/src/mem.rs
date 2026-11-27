//! Heap accounting for structures that report their memory (README §2 "Bounded"; edge.md §17;
//! review round 2, CR1): what an allocation really takes, not just the bytes requested.

use std::collections::HashMap;

/// The bytes the system allocator takes for a request of `n` bytes: glibc's malloc on 64-bit
/// Linux (the edge's) adds an 8-byte header and rounds up to 16 bytes, 32 at least; 0 for none.
pub fn alloc_bytes(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (n.saturating_add(8).saturating_add(15) & !15).max(32)
}

/// The buffer of a `Vec<T>` with capacity `cap`.
pub fn vec_bytes<T>(cap: usize) -> usize {
    alloc_bytes(cap.saturating_mul(std::mem::size_of::<T>()))
}

/// The buffer of a `String`.
pub fn string_bytes(s: &str, capacity: usize) -> usize {
    alloc_bytes(capacity.max(s.len()))
}

/// The table of a std `HashMap<K, V>` holding `capacity` entries (hashbrown: a power-of-two
/// number of buckets, at most 7/8 full past 8, each a `(K, V)` plus a control byte, and one
/// 16-byte control group).
pub fn hash_map_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    let cap = map.capacity();
    if cap == 0 {
        return 0;
    }
    let buckets = if cap < 4 {
        4
    } else if cap < 8 {
        8
    } else {
        cap.saturating_mul(8).div_ceil(7).next_power_of_two()
    };
    let entry = std::mem::size_of::<(K, V)>();
    alloc_bytes(buckets.saturating_mul(entry.saturating_add(1)).saturating_add(16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounding() {
        assert_eq!(alloc_bytes(0), 0);
        assert_eq!(alloc_bytes(1), 32);
        assert_eq!(alloc_bytes(24), 32);
        assert_eq!(alloc_bytes(25), 48);
        assert_eq!(alloc_bytes(40), 48);
        assert_eq!(alloc_bytes(41), 64);
        assert_eq!(vec_bytes::<u32>(4), 32);
        let mut m: HashMap<String, usize> = HashMap::new();
        assert_eq!(hash_map_bytes(&m), 0);
        m.insert("a".into(), 1);
        assert_eq!(hash_map_bytes(&m), alloc_bytes(4 * 33 + 16));
    }
}
