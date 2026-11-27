//! The recent-blocks ring (edge.md §12, browser-extension.md §3): per device, the last 64 DNS
//! blocks (id, time, name, stage and the target that blocked, the block's EDE source, block TTL,
//! profile, and the block response it was answered with), 1 MB overall, least recently active
//! devices evicted first.
//!
//! Recording happens on every block reply, so recording allocates only while a device's ring
//! grows (build-and-test.md §4): entries keep the name inline (a heap copy only past 96 bytes)
//! and share the bundle, head, provider and profile ids with the active config (`Arc`). A ring
//! grows by doubling as blocks arrive, so a device with one block holds room for a few, not 64.
//! The 1 MB budget counts what the rings really take: each ring's allocated room, the names and
//! targets that spilled to the heap, and each device's own bookkeeping.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use picket_api::edge_config::BlockResponse;
use picket_api::logs::Stage;
use picket_api::time::Timestamp;
use smallvec::SmallVec;

use crate::dns::profiles::DeviceKey;
use crate::dns::{BlockNote, BlockSource};

/// Entries kept per device.
pub const PER_DEVICE: usize = 64;
/// The ring's whole budget.
pub const MAX_BYTES: usize = 1 << 20;
/// Most devices kept, whatever their entries (README §2 Bounded).
pub const MAX_DEVICES: usize = 4096;

/// What decided a block, for its EDE (edge.md §4 EDE table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Bundle {
        bundle: Arc<str>,
        head: Arc<str>,
    },
    Lookup {
        provider: Arc<str>,
        verdict: &'static str,
    },
}

/// One recorded block.
#[derive(Clone, Debug)]
pub struct Entry {
    pub block_id: [u8; 8],
    pub at: Instant,
    pub wall: Timestamp,
    /// The query name's wire form (lowercase).
    pub name: SmallVec<[u8; 96]>,
    pub stage: Stage,
    pub target: Option<Box<str>>,
    pub source: Source,
    pub response: BlockResponse,
    pub profile: Arc<str>,
}

/// Seconds past the block TTL that `hold` adds: a reload right at the TTL can still find the
/// browser's cached block answer unexpired, and Firefox then serves it to the extension's second
/// attempt too, while refreshing it (#15). With the slack the reload finds it expired, and the
/// second attempt gets the fresh answer.
pub const HOLD_SLACK_S: u64 = 5;

/// `hold` for a block TTL: max(60 s, TTL + [`HOLD_SLACK_S`]) (edge.md §12 `retry_after_s`).
pub fn hold_s(ttl: u32) -> u64 {
    60u64.max(u64::from(ttl) + HOLD_SLACK_S)
}

impl Entry {
    /// Heap bytes beyond the entry itself (a spilled name, the target).
    fn extra(&self) -> usize {
        (if self.name.spilled() { self.name.len() } else { 0 }) + self.target.as_ref().map_or(0, |t| t.len())
    }

    pub fn block_id(&self) -> &str {
        std::str::from_utf8(&self.block_id).unwrap_or("")
    }

    /// `hold` = max(60 s, block TTL + [`HOLD_SLACK_S`]) (edge.md §12 `retry_after_s`).
    pub fn hold_s(&self) -> u64 {
        hold_s(self.response.ttl)
    }
}

struct DeviceRing {
    entries: VecDeque<Entry>,
    /// The entries' heap bytes beyond themselves.
    extra: usize,
    tick: u64,
}

/// A device's bookkeeping besides its entries: its map slot (key and ring) and some slack for
/// the map's own overhead.
const DEVICE_OVERHEAD: usize = std::mem::size_of::<DeviceKey>() + std::mem::size_of::<DeviceRing>() + 16;

impl DeviceRing {
    /// What this device's ring takes: its allocated room, spilled bytes and bookkeeping.
    fn bytes(&self) -> usize {
        DEVICE_OVERHEAD + self.entries.capacity() * std::mem::size_of::<Entry>() + self.extra
    }
}

#[derive(Default)]
struct Inner {
    devices: HashMap<DeviceKey, DeviceRing>,
    bytes: usize,
    tick: u64,
}

/// The ring.
#[derive(Default)]
pub struct Ring {
    inner: Mutex<Inner>,
}

impl Ring {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Records a block for `device`.
    pub fn record(&self, device: &DeviceKey, note: &BlockNote<'_>) {
        let mut block_id = [0u8; 8];
        let b = note.block_id.as_bytes();
        let n = b.len().min(8);
        block_id[..n].copy_from_slice(&b[..n]);
        let source = match note.source {
            BlockSource::Bundle { bundle, head } => Source::Bundle {
                bundle: Arc::clone(bundle),
                head: Arc::clone(head),
            },
            BlockSource::Lookup { provider, verdict } => Source::Lookup {
                provider: Arc::clone(provider),
                verdict,
            },
        };
        let e = Entry {
            block_id,
            at: Instant::now(),
            wall: Timestamp::now(),
            name: SmallVec::from_slice(note.name.wire()),
            stage: note.stage,
            target: note.target.map(Box::from),
            source,
            response: *note.response,
            profile: Arc::clone(note.profile),
        };
        let mut g = self.lock();
        g.tick = g.tick.wrapping_add(1);
        let tick = g.tick;
        if !g.devices.contains_key(device) {
            if g.devices.len() >= MAX_DEVICES {
                evict_one(&mut g);
            }
            // Room grows as blocks arrive (allocated at the first push).
            let d = DeviceRing {
                entries: VecDeque::new(),
                extra: 0,
                tick,
            };
            g.bytes += d.bytes();
            g.devices.insert(device.clone(), d);
        }
        let (mut before, mut after) = (0usize, 0usize);
        if let Some(d) = g.devices.get_mut(device) {
            before = d.bytes();
            d.tick = tick;
            if d.entries.len() >= PER_DEVICE
                && let Some(old) = d.entries.pop_front()
            {
                d.extra = d.extra.saturating_sub(old.extra());
            }
            d.extra += e.extra();
            d.entries.push_back(e);
            after = d.bytes();
        }
        g.bytes = g.bytes.saturating_sub(before) + after;
        while g.bytes > MAX_BYTES && g.devices.len() > 1 {
            if !evict_one_except(&mut g, device) {
                break;
            }
        }
    }

    /// The device's most recent block of `name` (wire form, lowercase).
    pub fn find_name(&self, device: &DeviceKey, name: &[u8]) -> Option<Entry> {
        let g = self.lock();
        let d = g.devices.get(device)?;
        d.entries
            .iter()
            .rev()
            .find(|e| e.name.as_slice().eq_ignore_ascii_case(name))
            .cloned()
    }

    /// The device's block with this id.
    pub fn find_id(&self, device: &DeviceKey, block_id: &str) -> Option<Entry> {
        let g = self.lock();
        let d = g.devices.get(device)?;
        d.entries.iter().rev().find(|e| e.block_id() == block_id).cloned()
    }

    /// Bytes held (tests).
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// The heap the rings really take (tests): each device's entry storage as allocated, plus
    /// spilled names and targets.
    pub fn heap_bytes(&self) -> usize {
        let g = self.lock();
        g.devices
            .values()
            .map(|d| {
                d.entries.capacity() * std::mem::size_of::<Entry>()
                    + d.entries.iter().map(Entry::extra).sum::<usize>()
            })
            .sum()
    }

    pub fn devices(&self) -> usize {
        self.lock().devices.len()
    }
}

fn evict_one(g: &mut Inner) {
    let Some(k) = g
        .devices
        .iter()
        .min_by_key(|(_, d)| d.tick)
        .map(|(k, _)| k.clone())
    else {
        return;
    };
    if let Some(d) = g.devices.remove(&k) {
        g.bytes = g.bytes.saturating_sub(d.bytes());
    }
}

fn evict_one_except(g: &mut Inner, keep: &DeviceKey) -> bool {
    let Some(k) = g
        .devices
        .iter()
        .filter(|(k, _)| *k != keep)
        .min_by_key(|(_, d)| d.tick)
        .map(|(k, _)| k.clone())
    else {
        return false;
    };
    if let Some(d) = g.devices.remove(&k) {
        g.bytes = g.bytes.saturating_sub(d.bytes());
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_wire::QName;

    fn note<'a>(
        id: &'a str,
        name: &'a QName,
        src: BlockSource<'a>,
        profile: &'a Arc<str>,
        br: &'a BlockResponse,
    ) -> BlockNote<'a> {
        BlockNote {
            block_id: id,
            name: name.as_name(),
            stage: Stage::Query,
            target: None,
            source: src,
            response: br,
            profile,
        }
    }

    #[test]
    fn keeps_the_last_64_per_device_and_evicts_least_recently_active_devices() {
        let r = Ring::default();
        let b: Arc<str> = "block-common".into();
        let h: Arc<str> = "0".repeat(64).into();
        let p: Arc<str> = "kids".into();
        let br = BlockResponse::default();
        let d1 = DeviceKey::Addr("192.168.1.10".parse().unwrap());
        for i in 0..70 {
            let n = QName::from_text(&format!("n{i}.example")).unwrap();
            r.record(
                &d1,
                &note(
                    "abcdefgh",
                    &n,
                    BlockSource::Bundle { bundle: &b, head: &h },
                    &p,
                    &br,
                ),
            );
        }
        let n0 = QName::from_text("n0.example").unwrap();
        let n69 = QName::from_text("n69.example").unwrap();
        assert!(r.find_name(&d1, n0.wire()).is_none(), "the oldest went");
        assert!(r.find_name(&d1, n69.wire()).is_some());
        assert_eq!(r.find_id(&d1, "abcdefgh").unwrap().name.as_slice(), n69.wire());
        // Fill the budget with other devices: the least recently active go first, d1 last used
        // long ago.
        for dev in 0..2000u32 {
            let d = DeviceKey::Addr(std::net::IpAddr::from([10, 0, (dev >> 8) as u8, dev as u8]));
            for i in 0..4 {
                let n = QName::from_text(&format!("x{i}.example")).unwrap();
                r.record(
                    &d,
                    &note(
                        "zzzzzzzz",
                        &n,
                        BlockSource::Bundle { bundle: &b, head: &h },
                        &p,
                        &br,
                    ),
                );
            }
        }
        assert!(r.bytes() <= MAX_BYTES, "{}", r.bytes());
        assert!(r.find_name(&d1, n69.wire()).is_none(), "d1 evicted first");
    }

    #[test]
    fn the_budget_counts_what_the_rings_allocate() {
        // Many devices with one block each: the 1 MB cap holds for the memory really taken,
        // not only for the entries in it (edge.md §12).
        let r = Ring::default();
        let b: Arc<str> = "block-common".into();
        let h: Arc<str> = "0".repeat(64).into();
        let p: Arc<str> = "kids".into();
        let br = BlockResponse::default();
        let n = QName::from_text("x.example").unwrap();
        for dev in 0..MAX_DEVICES as u32 {
            let d = DeviceKey::Addr(std::net::IpAddr::from([10, 1, (dev >> 8) as u8, dev as u8]));
            r.record(
                &d,
                &note(
                    "zzzzzzzz",
                    &n,
                    BlockSource::Bundle { bundle: &b, head: &h },
                    &p,
                    &br,
                ),
            );
        }
        assert!(r.heap_bytes() <= MAX_BYTES, "{} bytes allocated", r.heap_bytes());
        assert!(
            r.bytes() >= r.heap_bytes(),
            "{} counted, {} allocated",
            r.bytes(),
            r.heap_bytes()
        );
        assert!(r.devices() > 100, "still many devices: {}", r.devices());
    }
}
