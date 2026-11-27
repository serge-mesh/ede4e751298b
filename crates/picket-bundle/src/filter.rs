//! `domains.bf8` and `cold.bf8` (bundles.md §4): a [`xorf::BinaryFuse8`] over the low 64 bits of
//! each key's hash.
//!
//! Layout (little-endian): a 16-byte header (magic `PKTBF8\0\0`, format `u32`, reserved `u32` 0),
//! the filter's fields (`seed` u64; `segment_length`, `segment_length_mask`,
//! `segment_count_length` u32), then the fingerprints. The reader rebuilds the filter from its
//! fields (no `unsafe`, no zero-copy cast) and refuses a file whose length doesn't match them: the
//! fingerprints must be exactly `segment_count_length + 2 × segment_length` bytes, the segment
//! length a power of two with its mask, and `segment_count_length` a non-zero multiple of it, so
//! every index the lookup computes is in bounds (the first index is below
//! `segment_count_length`, the others at most two segments above).

use xorf::{BinaryFuse8, Descriptor, Filter};

use crate::FORMAT;
use crate::bytes::ByteReader;

/// The file magic.
pub const MAGIC: [u8; 8] = *b"PKTBF8\0\0";
/// Header plus fields.
pub const PREFIX_LEN: usize = 16 + 20;
/// The largest segment length the builder uses.
const MAX_SEGMENT_LENGTH: u32 = 1 << 18;

/// Why a filter file is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("not a filter file")]
    Magic,
    #[error("filter format {0} is not supported")]
    Format(u32),
    #[error("filter fields are inconsistent")]
    Fields,
    #[error("filter length {got} doesn't match its fields ({want})")]
    Length { got: usize, want: usize },
    #[error("filter construction failed: {0}")]
    Build(&'static str),
}

/// A loaded filter.
#[derive(Clone, Debug)]
pub struct KeyFilter {
    inner: BinaryFuse8,
}

impl KeyFilter {
    /// True when the key may be present (no false negatives; ~0.4 % false positives).
    pub fn contains(&self, low64: u64) -> bool {
        self.inner.contains(&low64)
    }

    /// Bytes held.
    pub fn memory_usage(&self) -> usize {
        self.inner
            .fingerprints
            .len()
            .saturating_add(std::mem::size_of::<Self>())
    }

    /// Parses and validates a filter file.
    pub fn from_bytes(data: &[u8]) -> Result<KeyFilter, FilterError> {
        let mut r = ByteReader::new(data);
        let magic: [u8; 8] = r.array().map_err(|_| FilterError::Magic)?;
        if magic != MAGIC {
            return Err(FilterError::Magic);
        }
        let format = r.u32().map_err(|_| FilterError::Magic)?;
        if format != FORMAT {
            return Err(FilterError::Format(format));
        }
        let _reserved = r.u32().map_err(|_| FilterError::Magic)?;
        let seed = r.u64().map_err(|_| FilterError::Fields)?;
        let segment_length = r.u32().map_err(|_| FilterError::Fields)?;
        let segment_length_mask = r.u32().map_err(|_| FilterError::Fields)?;
        let segment_count_length = r.u32().map_err(|_| FilterError::Fields)?;
        if segment_length == 0
            || !segment_length.is_power_of_two()
            || segment_length > MAX_SEGMENT_LENGTH
            || segment_length_mask != segment_length.wrapping_sub(1)
            || segment_count_length < segment_length
            || segment_count_length.checked_rem(segment_length) != Some(0)
        {
            return Err(FilterError::Fields);
        }
        // Every index is below segment_count_length + 2 × segment_length, which must also fit
        // the u32 arithmetic of the lookup.
        let want = u64::from(segment_count_length)
            .checked_add(u64::from(segment_length).saturating_mul(2))
            .ok_or(FilterError::Fields)?;
        if want > u64::from(u32::MAX) {
            return Err(FilterError::Fields);
        }
        let want = usize::try_from(want).map_err(|_| FilterError::Fields)?;
        let fps = r.rest();
        if fps.len() != want {
            return Err(FilterError::Length { got: fps.len(), want });
        }
        Ok(KeyFilter {
            inner: BinaryFuse8 {
                descriptor: Descriptor {
                    seed,
                    segment_length,
                    segment_length_mask,
                    segment_count_length,
                },
                fingerprints: fps.to_vec().into_boxed_slice(),
            },
        })
    }
}

/// Builds a filter file over these low-64-bit hashes (sorted and deduplicated first, so the
/// output depends only on the set: bundles.md §2 "Determinism").
pub fn build(hashes: &mut Vec<u64>) -> Result<Vec<u8>, FilterError> {
    hashes.sort_unstable();
    hashes.dedup();
    let f = BinaryFuse8::try_from(hashes.as_slice()).map_err(FilterError::Build)?;
    let mut out = Vec::with_capacity(PREFIX_LEN.saturating_add(f.fingerprints.len()));
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&f.descriptor.seed.to_le_bytes());
    out.extend_from_slice(&f.descriptor.segment_length.to_le_bytes());
    out.extend_from_slice(&f.descriptor.segment_length_mask.to_le_bytes());
    out.extend_from_slice(&f.descriptor.segment_count_length.to_le_bytes());
    out.extend_from_slice(&f.fingerprints);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_refusals() {
        for n in [0usize, 1, 2, 5, 1000] {
            let mut keys: Vec<u64> = (0..n as u64)
                .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                .collect();
            let bytes = build(&mut keys.clone()).unwrap();
            let f = KeyFilter::from_bytes(&bytes).unwrap();
            for k in keys.drain(..) {
                assert!(f.contains(k), "n={n}");
            }
            let mut short = bytes.clone();
            short.pop();
            assert!(matches!(
                KeyFilter::from_bytes(&short),
                Err(FilterError::Length { .. })
            ));
            let mut long = bytes.clone();
            long.push(0);
            assert!(KeyFilter::from_bytes(&long).is_err());
        }
        let mut bad = build(&mut vec![1, 2, 3]).unwrap();
        bad[24] = 3; // segment_length not a power of two
        assert_eq!(KeyFilter::from_bytes(&bad).unwrap_err(), FilterError::Fields);
        assert_eq!(KeyFilter::from_bytes(b"nope").unwrap_err(), FilterError::Magic);
        // Found by fuzzing: no segment at all (segment_count_length 0) would index past the end.
        let crash = b"PKTBF8\0\0\x01\0\0\0\0\0BFPK\xac\xbeF8\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\x08R";
        assert_eq!(KeyFilter::from_bytes(crash).unwrap_err(), FilterError::Fields);
    }

    #[test]
    fn deterministic() {
        let a = build(&mut vec![5, 3, 9, 3]).unwrap();
        let b = build(&mut vec![9, 5, 3]).unwrap();
        assert_eq!(a, b);
    }
}
