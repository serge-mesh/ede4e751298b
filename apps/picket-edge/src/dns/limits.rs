//! Per-device limits (edge.md §16): `limits.client_qps` (default 100) as a token bucket whose
//! burst is sized for page loads (hundreds of queries), and `limits.client_inflight` (default 64)
//! queries in flight. A query over either gets REFUSED, isn't logged, and counts as `rejected`.
//!
//! The table is bounded: sharded, each shard holding at most [`MAX_DEVICES_PER_SHARD`] devices;
//! a full shard first drops devices idle with nothing in flight, sweeping its table at most once
//! per [`SWEEP_EVERY`] (a scan under the shard's lock, so spoofed-source churn can't make every
//! packet pay for one). While it is still full, new
//! devices share the shard's one overflow bucket, under the same per-device limits: a flood of
//! new sources (address churn) can neither lock the devices already in the table out nor get
//! unlimited admission (README §2 "Bounded": each client gets a capped share). The overflow
//! bucket is a policy choice (flagged for the owner): new devices that land in a saturated shard
//! share one device's limits until idle devices age out.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::profiles::DeviceKey;

const SHARDS: usize = 16;
pub const MAX_DEVICES_PER_SHARD: usize = 1024;
/// Burst = this many seconds of `client_qps`, at least [`MIN_BURST`].
pub const BURST_SECONDS: u32 = 5;
pub const MIN_BURST: u32 = 300;
const IDLE_DROP: Duration = Duration::from_secs(120);
/// A full shard's table is swept for idle devices at most this often.
pub const SWEEP_EVERY: Duration = Duration::from_secs(1);

struct Bucket {
    tokens: f64,
    last: Instant,
    inflight: u32,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Bucket {
            tokens: burst,
            last: now,
            inflight: 0,
        }
    }

    /// Refills at `qps` up to `burst`, then takes one token and one in-flight slot.
    fn take(&mut self, qps: u32, burst: f64, inflight: u32, now: Instant) -> Result<(), Over> {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * f64::from(qps)).min(burst);
        self.last = now;
        if self.inflight >= inflight {
            return Err(Over::Inflight);
        }
        if self.tokens < 1.0 {
            return Err(Over::Qps);
        }
        self.tokens -= 1.0;
        self.inflight += 1;
        Ok(())
    }
}

struct Shard {
    devices: HashMap<DeviceKey, Bucket>,
    /// Shared by new devices while the shard is full.
    overflow: Bucket,
    /// When the full table may next be swept.
    next_sweep: Option<Instant>,
    /// Sweeps of the full table so far.
    sweeps: u64,
}

/// Whose in-flight slot a [`Slot`] holds.
enum SlotKey {
    Device(DeviceKey),
    Overflow(usize),
}

/// Why a query was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Over {
    Qps,
    Inflight,
}

pub struct DeviceLimiter {
    shards: Vec<Mutex<Shard>>,
    hasher: std::collections::hash_map::RandomState,
}

/// Holds one in-flight slot; released on drop.
pub struct Slot {
    limiter: Arc<DeviceLimiter>,
    key: Option<SlotKey>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        match self.key.take() {
            Some(SlotKey::Device(k)) => {
                let mut g = self.limiter.shard(&k).lock().unwrap_or_else(|p| p.into_inner());
                if let Some(b) = g.devices.get_mut(&k) {
                    b.inflight = b.inflight.saturating_sub(1);
                }
            }
            Some(SlotKey::Overflow(i)) => {
                let mut g = self.limiter.shards[i].lock().unwrap_or_else(|p| p.into_inner());
                g.overflow.inflight = g.overflow.inflight.saturating_sub(1);
            }
            None => {}
        }
    }
}

impl Default for DeviceLimiter {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Shard {
                        devices: HashMap::new(),
                        overflow: Bucket::full(f64::from(MIN_BURST), now),
                        next_sweep: None,
                        sweeps: 0,
                    })
                })
                .collect(),
            hasher: Default::default(),
        }
    }
}

impl DeviceLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn index(&self, k: &DeviceKey) -> usize {
        usize::try_from(self.hasher.hash_one(k) % SHARDS as u64).unwrap_or(0)
    }

    fn shard(&self, k: &DeviceKey) -> &Mutex<Shard> {
        &self.shards[self.index(k)]
    }

    /// Admits one query from `key` under `qps` and `inflight`, or says which limit it is over.
    pub fn admit(
        self: &Arc<Self>,
        key: DeviceKey,
        qps: u32,
        inflight: u32,
        now: Instant,
    ) -> Result<Slot, Over> {
        let burst = f64::from(qps.saturating_mul(BURST_SECONDS).max(MIN_BURST));
        let i = self.index(&key);
        let mut g = self.shards[i].lock().unwrap_or_else(|p| p.into_inner());
        if !g.devices.contains_key(&key) && g.devices.len() >= MAX_DEVICES_PER_SHARD {
            if g.next_sweep.is_none_or(|t| now >= t) {
                g.next_sweep = Some(now + SWEEP_EVERY);
                g.sweeps += 1;
                g.devices
                    .retain(|_, b| b.inflight > 0 || now.saturating_duration_since(b.last) < IDLE_DROP);
            }
            if g.devices.len() >= MAX_DEVICES_PER_SHARD {
                // Still full: the new device shares the shard's overflow bucket, never unlimited.
                g.overflow.take(qps, burst, inflight, now)?;
                return Ok(Slot {
                    limiter: Arc::clone(self),
                    key: Some(SlotKey::Overflow(i)),
                });
            }
        }
        // Clones the key only for a device new to the table.
        let b = match g.devices.get_mut(&key) {
            Some(b) => b,
            None => g.devices.entry(key.clone()).or_insert(Bucket::full(burst, now)),
        };
        b.take(qps, burst, inflight, now)?;
        Ok(Slot {
            limiter: Arc::clone(self),
            key: Some(SlotKey::Device(key)),
        })
    }

    /// Sweeps of full shards so far (each at most once per [`SWEEP_EVERY`]).
    pub fn sweeps(&self) -> u64 {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|p| p.into_inner()).sweeps)
            .sum()
    }

    pub fn devices(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|p| p.into_inner()).devices.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> DeviceKey {
        DeviceKey::Mac([0xaa, 0, 0, 0, 0, n])
    }

    #[test]
    fn qps_bucket_with_page_load_burst() {
        let l = DeviceLimiter::new();
        let t0 = Instant::now();
        let mut ok = 0;
        let mut held = vec![];
        for _ in 0..1000 {
            match l.admit(k(1), 100, 10_000, t0) {
                Ok(s) => {
                    ok += 1;
                    held.push(s);
                }
                Err(e) => assert_eq!(e, Over::Qps),
            }
        }
        assert_eq!(ok, 500, "burst = 5 s of qps");
        // Refill at 100/s.
        let t1 = t0 + Duration::from_millis(100);
        assert!(l.admit(k(1), 100, 10_000, t1).is_ok());
        // Other devices are independent.
        assert!(l.admit(k(2), 100, 10_000, t0).is_ok());
    }

    /// D10: a full table never admits new devices without limits: address churn shares each
    /// shard's overflow bucket, and devices already in the table keep their own buckets.
    #[test]
    fn a_full_table_limits_new_devices_through_a_shared_bucket() {
        let l = DeviceLimiter::new();
        let t0 = Instant::now();
        let key = |i: u32| DeviceKey::Addr(std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(i))));
        let mut held = vec![];
        let mut ok = 0usize;
        let n = 4 * (SHARDS * MAX_DEVICES_PER_SHARD) as u32;
        for i in 0..n {
            if let Ok(s) = l.admit(key(i), 100, 10_000, t0) {
                ok += 1;
                held.push(s);
            }
        }
        let burst = (100 * BURST_SECONDS).max(MIN_BURST) as usize;
        assert!(
            ok <= SHARDS * MAX_DEVICES_PER_SHARD + SHARDS * burst,
            "{ok} of {n} churned sources admitted"
        );
        assert_eq!(l.devices(), SHARDS * MAX_DEVICES_PER_SHARD);
        // A device already in the table still has its own bucket.
        assert!(l.admit(key(0), 100, 10_000, t0).is_ok());
        // Overflow slots are given back on drop.
        drop(held);
        assert!(
            l.admit(key(n + 1), 100, 10_000, t0 + Duration::from_secs(10))
                .is_ok()
        );
    }

    /// ER8 (README §2 Bounded): while a shard is full, unknown devices (spoofed-source churn) go
    /// to the overflow bucket without each scanning the shard's table under its lock: a full shard
    /// is swept at most about once a second, and a sweep still frees idle devices' entries.
    #[test]
    fn a_full_shard_is_swept_at_most_once_a_second() {
        let l = DeviceLimiter::new();
        let t0 = Instant::now();
        let key = |i: u32| DeviceKey::Addr(std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(i))));
        let n = (SHARDS * MAX_DEVICES_PER_SHARD) as u32;
        let mut held = vec![];
        let mut i = 0;
        while l.devices() < SHARDS * MAX_DEVICES_PER_SHARD {
            if let Ok(s) = l.admit(key(i), 100, 10_000, t0) {
                held.push(s);
            }
            i += 1;
        }
        let before = l.sweeps();
        // Churn: thousands of unknown devices within the same second.
        for j in 0..4 * n {
            let _ = l.admit(
                key(i + j),
                100,
                10_000,
                t0 + Duration::from_millis(u64::from(j % 900)),
            );
        }
        let during = l.sweeps() - before;
        assert!(
            during <= SHARDS as u64,
            "{during} sweeps of full shards within a second"
        );
        // Later, with every device idle long enough, a sweep frees entries for new devices.
        drop(held);
        let later = t0 + IDLE_DROP + Duration::from_secs(2);
        assert!(l.admit(key(u32::MAX), 100, 10_000, later).is_ok());
        assert!(
            l.devices() < SHARDS * MAX_DEVICES_PER_SHARD,
            "idle devices dropped"
        );
    }

    #[test]
    fn inflight_limit_releases_on_drop() {
        let l = DeviceLimiter::new();
        let t0 = Instant::now();
        let slots: Vec<Slot> = (0..64).map(|_| l.admit(k(1), 100, 64, t0).unwrap()).collect();
        assert_eq!(l.admit(k(1), 100, 64, t0).err(), Some(Over::Inflight));
        drop(slots);
        assert!(l.admit(k(1), 100, 64, t0).is_ok());
    }
}
