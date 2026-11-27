//! The one fixed histogram layout every duration histogram uses (api.md §3): `buckets[i]` for
//! i = 0…45 counts durations up to ⌊10 × √2^i⌋ µs and above the previous bound; `buckets[46]`
//! counts the longer ones. Trailing zero buckets may be left out. `sum` is in the field's unit.

use serde::{Deserialize, Serialize};

/// Number of buckets, the overflow bucket included.
pub const BUCKETS: usize = 47;

/// Upper bound in µs of bucket `i` (0…45); `None` for the overflow bucket.
pub fn bound_us(i: usize) -> Option<u64> {
    if i >= BUCKETS - 1 {
        return None;
    }
    Some(BOUNDS_US[i])
}

/// ⌊10 × √2^i⌋ for i = 0…45, computed exactly: even i → 10·2^(i/2); odd i → ⌊10·2^((i-1)/2)·√2⌋.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a const (no TryFrom): the largest bound, 10 x sqrt(2)^44, is far below u64::MAX"
)]
pub const BOUNDS_US: [u64; BUCKETS - 1] = {
    let mut out = [0u64; BUCKETS - 1];
    let mut i = 0;
    while i < BUCKETS - 1 {
        let pow = 1u64 << (i / 2);
        out[i] = if i % 2 == 0 {
            10 * pow
        } else {
            // floor(10 * pow * sqrt(2)) = floor(sqrt(200 * pow^2))
            isqrt(200 * (pow as u128) * (pow as u128)) as u64
        };
        i += 1;
    }
    out
};

const fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Index of the bucket holding a duration of `us` microseconds.
pub fn bucket_index(us: u64) -> usize {
    BOUNDS_US.partition_point(|&b| b < us)
}

/// A histogram sample: running totals since the process started.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Histogram {
    pub buckets: Vec<u64>,
    pub sum: u64,
    pub count: u64,
}

impl Histogram {
    /// Records one duration in microseconds; `sum_value` is added to `sum` in the field's unit.
    pub fn record(&mut self, us: u64, sum_value: u64) {
        let i = bucket_index(us);
        if self.buckets.len() <= i {
            self.buckets.resize(i + 1, 0);
        }
        self.buckets[i] = self.buckets[i].saturating_add(1);
        self.sum = self.sum.saturating_add(sum_value);
        self.count = self.count.saturating_add(1);
    }

    /// Bucket count, treating left-out trailing buckets as zero.
    pub fn bucket(&self, i: usize) -> u64 {
        self.buckets.get(i).copied().unwrap_or(0)
    }

    /// Drops trailing zero buckets.
    pub fn trim(&mut self) {
        while self.buckets.last() == Some(&0) {
            self.buckets.pop();
        }
    }

    /// Element-wise difference `self - earlier` (both running totals of one boot), saturating.
    pub fn delta(&self, earlier: &Histogram) -> Histogram {
        let n = self.buckets.len().max(earlier.buckets.len()).min(BUCKETS);
        let buckets = (0..n)
            .map(|i| self.bucket(i).saturating_sub(earlier.bucket(i)))
            .collect();
        Histogram {
            buckets,
            sum: self.sum.saturating_sub(earlier.sum),
            count: self.count.saturating_sub(earlier.count),
        }
    }

    /// Adds another histogram's counts into this one.
    pub fn add(&mut self, other: &Histogram) {
        let n = other.buckets.len().min(BUCKETS);
        if self.buckets.len() < n {
            self.buckets.resize(n, 0);
        }
        for (i, slot) in self.buckets.iter_mut().enumerate().take(n) {
            *slot = slot.saturating_add(other.bucket(i));
        }
        self.sum = self.sum.saturating_add(other.sum);
        self.count = self.count.saturating_add(other.count);
    }

    /// The `q` quantile (0..=1) in µs, interpolated linearly within a bucket. `None` when empty.
    /// The overflow bucket reports the last finite bound.
    pub fn quantile_us(&self, q: f64) -> Option<f64> {
        let total: u64 = (0..BUCKETS).map(|i| self.bucket(i)).sum();
        if total == 0 {
            return None;
        }
        let target = (q.clamp(0.0, 1.0) * total as f64).max(1.0);
        let mut seen = 0.0;
        for i in 0..BUCKETS {
            let c = self.bucket(i) as f64;
            if c == 0.0 {
                continue;
            }
            if seen + c >= target {
                let lo = if i == 0 { 0.0 } else { BOUNDS_US[i - 1] as f64 };
                let Some(hi) = bound_us(i) else {
                    return Some(BOUNDS_US[BUCKETS - 2] as f64);
                };
                let frac = (target - seen) / c;
                return Some(lo + (hi as f64 - lo) * frac);
            }
            seen += c;
        }
        Some(BOUNDS_US[BUCKETS - 2] as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        assert_eq!(BOUNDS_US[0], 10);
        assert_eq!(BOUNDS_US[1], 14);
        assert_eq!(BOUNDS_US[2], 20);
        assert_eq!(BOUNDS_US[3], 28);
        // ~59 s at the top
        assert_eq!(BOUNDS_US[45], 59_316_416);
        for w in BOUNDS_US.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn record_and_quantile() {
        let mut h = Histogram::default();
        for us in [5, 10, 11, 100, 1000] {
            h.record(us, us);
        }
        assert_eq!(h.count, 5);
        assert_eq!(h.bucket(0), 2); // 5 and 10
        assert_eq!(h.bucket(1), 1); // 11
        let p50 = h.quantile_us(0.5).unwrap();
        assert!(p50 > 10.0 && p50 <= 14.0, "{p50}");
        h.record(u64::MAX, 0);
        assert_eq!(h.bucket(46), 1);
    }
}
