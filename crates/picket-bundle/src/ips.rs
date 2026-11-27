//! `ips.bin` (bundles.md §4): one IP shard's base.
//!
//! IP shards are by address: IPv4 by the first octet (`v4/0` … `v4/255`), IPv6 as one shard
//! (`v6`). A shard's entries are its **runs**, maximal ranges of addresses with one [`Value`].
//!
//! Layout, little-endian: a 16-byte header (magic `PKTIPS\0\0`, format `u32`, shard `u32`: the
//! first octet, or 256 for `v6`), the set checksum at the base (`u128`), then:
//! - **IPv4:** the side table (`u32` count, then sorted disjoint 16-byte entries `{first u32,
//!   last u32, value u64}`) for every address whose value isn't a plain block; a 256-entry
//!   directory, one per /16 (`{kind u8, 0 u8, count u16, offset u32}`; kind 0 empty, 1 a sorted
//!   `u16` array of `count` addresses, 2 a list of `count` runs `{start u16, len − 1 u16}`, 3 an
//!   8 KiB bitmap); then the containers (`u32` length + bytes). The address set holds the
//!   addresses whose value is a plain block (`B_EXACT` alone), each /16 in the smallest container
//!   (Roaring-style).
//! - **IPv6:** sorted disjoint 40-byte entries `{first u128, last u128, value u64}` (`u32` count
//!   first).
//!
//! **Base id = BLAKE3 of this file.** The reader validates every container and table (sorted,
//! disjoint, in bounds, inside the shard) once at load, so lookups never fail.

use std::fmt;
use std::str::FromStr;

use picket_rules::Flags;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::FORMAT;
use crate::bytes::ByteReader;
use crate::checksum::SetChecksum;
use crate::value::Value;

/// The file magic.
pub const MAGIC: [u8; 8] = *b"PKTIPS\0\0";
const BITMAP_BYTES: usize = 8192;
const KIND_NONE: u8 = 0;
const KIND_ARRAY: u8 = 1;
const KIND_RUNS: u8 = 2;
const KIND_BITMAP: u8 = 3;

/// An IP shard id: `v4/<first octet>` or `v6` (api.md §5 `ip_shards`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpShardId {
    V4(u8),
    V6,
}

impl IpShardId {
    /// The header code: the octet, or 256.
    pub fn code(self) -> u32 {
        match self {
            IpShardId::V4(o) => u32::from(o),
            IpShardId::V6 => 256,
        }
    }

    fn from_code(c: u32) -> Option<IpShardId> {
        match c {
            256 => Some(IpShardId::V6),
            c => u8::try_from(c).ok().map(IpShardId::V4),
        }
    }

    /// True for an IPv4 shard.
    pub fn is_v4(self) -> bool {
        matches!(self, IpShardId::V4(_))
    }

    /// The shard of an address (IPv4 in the low 32 bits).
    pub fn of(v4: bool, addr: u128) -> IpShardId {
        if v4 {
            IpShardId::V4(((addr >> 24) & 0xff) as u8)
        } else {
            IpShardId::V6
        }
    }

    /// The addresses it covers.
    pub fn bounds(self) -> (u128, u128) {
        match self {
            IpShardId::V4(o) => {
                let first = u128::from(o) << 24;
                (first, first | 0x00ff_ffff)
            }
            IpShardId::V6 => (0, u128::MAX),
        }
    }
}

impl fmt::Display for IpShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpShardId::V4(o) => write!(f, "v4/{o}"),
            IpShardId::V6 => f.write_str("v6"),
        }
    }
}

impl FromStr for IpShardId {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        if s == "v6" {
            return Ok(IpShardId::V6);
        }
        let n = s.strip_prefix("v4/").ok_or(())?;
        if n.is_empty()
            || n.len() > 3
            || !n.bytes().all(|b| b.is_ascii_digit())
            || (n.len() > 1 && n.starts_with('0'))
        {
            return Err(());
        }
        n.parse::<u8>().map(IpShardId::V4).map_err(|_| ())
    }
}

impl Serialize for IpShardId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpShardId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(|_| serde::de::Error::custom("bad IP shard id"))
    }
}

/// A run: addresses `first..=last` (IPv4 in the low 32 bits) with one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Run {
    pub first: u128,
    pub last: u128,
    pub value: Value,
}

/// Why an `ips.bin` is refused or can't be written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IpsError {
    #[error("not an IP shard file")]
    Magic,
    #[error("IP shard format {0} is not supported")]
    Format(u32),
    #[error("IP shard file is malformed: {0}")]
    Malformed(&'static str),
    #[error("IP shard is {got}, expected {want}")]
    Shard { got: String, want: String },
    #[error("runs are unsorted, overlapping or outside the shard")]
    Runs,
}

/// The low 16 bits of an IPv4 address: its place in its /16.
fn low16(a: u32) -> u16 {
    let [_, _, hi, lo] = a.to_be_bytes();
    u16::from_be_bytes([hi, lo])
}

/// The plain-block value the address set stands for.
pub fn plain_value() -> Value {
    Value::flags_only(Flags::B_EXACT)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Container {
    kind: u8,
    count: u16,
    offset: u32,
}

/// A loaded IP shard base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpBase(Inner);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Inner {
    V4 {
        octet: u8,
        dir: Box<[Container; 256]>,
        area: Vec<u8>,
        side: Vec<(u32, u32, u64)>,
        checksum: SetChecksum,
    },
    V6 {
        ranges: Vec<(u128, u128, u64)>,
        checksum: SetChecksum,
    },
}

impl IpBase {
    /// The shard.
    pub fn shard(&self) -> IpShardId {
        match &self.0 {
            Inner::V4 { octet, .. } => IpShardId::V4(*octet),
            Inner::V6 { .. } => IpShardId::V6,
        }
    }

    /// The set checksum at the base.
    pub fn checksum(&self) -> SetChecksum {
        match &self.0 {
            Inner::V4 { checksum, .. } | Inner::V6 { checksum, .. } => *checksum,
        }
    }

    /// The value at `addr` (IPv4 in the low 32 bits), if an IP rule covers it, and whether it came
    /// from the address set.
    pub fn get(&self, addr: u128) -> Option<(Value, bool)> {
        match &self.0 {
            Inner::V4 {
                octet,
                dir,
                area,
                side,
                ..
            } => {
                let a = u32::try_from(addr).ok()?;
                let [first, second, hi, lo] = a.to_be_bytes();
                if first != *octet {
                    return None;
                }
                let c = dir.get(usize::from(second)).copied().unwrap_or_default();
                if container_has(&c, area, u16::from_be_bytes([hi, lo])) {
                    return Some((plain_value(), true));
                }
                range_get(side, a).map(|v| (Value::from_stored(v), false))
            }
            Inner::V6 { ranges, .. } => range_get(ranges, addr).map(|v| (Value::from_stored(v), false)),
        }
    }

    /// Every run of the base, sorted (plain-block ranges merged across /16 boundaries).
    pub fn runs(&self) -> Vec<Run> {
        let mut out = Vec::new();
        match &self.0 {
            Inner::V4 {
                octet,
                dir,
                area,
                side,
                ..
            } => {
                let base = u128::from(*octet) << 24;
                let mut set: Vec<(u128, u128)> = Vec::new();
                for (b, c) in dir.iter().enumerate() {
                    let hi = base | ((b as u128) << 16);
                    for (s, e) in container_ranges(c, area) {
                        let (s, e) = (hi | u128::from(s), hi | u128::from(e));
                        match set.last_mut() {
                            Some(l) if l.1.wrapping_add(1) == s => l.1 = e,
                            _ => set.push((s, e)),
                        }
                    }
                }
                for (s, e) in set {
                    out.push(Run {
                        first: s,
                        last: e,
                        value: plain_value(),
                    });
                }
                for &(f, l, v) in side {
                    out.push(Run {
                        first: u128::from(f),
                        last: u128::from(l),
                        value: Value::from_stored(v),
                    });
                }
                out.sort_unstable();
            }
            Inner::V6 { ranges, .. } => {
                for &(f, l, v) in ranges {
                    out.push(Run {
                        first: f,
                        last: l,
                        value: Value::from_stored(v),
                    });
                }
            }
        }
        out
    }

    /// The largest `rich_idx` among the base's values (checked against the part's `rich.json`).
    pub fn max_rich_idx(&self) -> Option<u32> {
        let vals: Box<dyn Iterator<Item = u64> + '_> = match &self.0 {
            Inner::V4 { side, .. } => Box::new(side.iter().map(|r| r.2)),
            Inner::V6 { ranges, .. } => Box::new(ranges.iter().map(|r| r.2)),
        };
        vals.filter_map(|v| Value::from_stored(v).rich_idx()).max()
    }

    /// Bytes held (by capacity).
    pub fn memory_usage(&self) -> usize {
        match &self.0 {
            Inner::V4 { area, side, .. } => area
                .capacity()
                .saturating_add(
                    side.capacity()
                        .saturating_mul(std::mem::size_of::<(u32, u32, u64)>()),
                )
                .saturating_add(std::mem::size_of::<[Container; 256]>()),
            Inner::V6 { ranges, .. } => {
                ranges
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u128, u128, u64)>())
            }
        }
    }

    /// Parses and validates `ips.bin`.
    pub fn from_bytes(data: &[u8]) -> Result<IpBase, IpsError> {
        let m = IpsError::Malformed;
        let mut r = ByteReader::new(data);
        let magic: [u8; 8] = r.array().map_err(|_| IpsError::Magic)?;
        if magic != MAGIC {
            return Err(IpsError::Magic);
        }
        let format = r.u32().map_err(|_| IpsError::Magic)?;
        if format != FORMAT {
            return Err(IpsError::Format(format));
        }
        let shard = IpShardId::from_code(r.u32().map_err(|_| IpsError::Magic)?).ok_or(m("shard"))?;
        let checksum = SetChecksum(r.u128().map_err(|_| m("checksum"))?);
        let base = match shard {
            IpShardId::V4(octet) => {
                let n =
                    usize::try_from(r.u32().map_err(|_| m("side count"))?).map_err(|_| m("side count"))?;
                if n > r.remaining() / 16 {
                    return Err(m("side count"));
                }
                let mut side = Vec::with_capacity(n);
                for _ in 0..n {
                    let f = r.u32().map_err(|_| m("side"))?;
                    let l = r.u32().map_err(|_| m("side"))?;
                    let v = r.u64().map_err(|_| m("side"))?;
                    side.push((f, l, v));
                }
                check_ranges(&side, |&(f, l, _)| (u128::from(f), u128::from(l)), shard)?;
                let mut dir = Box::new([Container::default(); 256]);
                for c in dir.iter_mut() {
                    let kind = r.u8().map_err(|_| m("directory"))?;
                    let _ = r.u8().map_err(|_| m("directory"))?;
                    let count = r.u16().map_err(|_| m("directory"))?;
                    let offset = r.u32().map_err(|_| m("directory"))?;
                    *c = Container { kind, count, offset };
                }
                let alen =
                    usize::try_from(r.u32().map_err(|_| m("containers"))?).map_err(|_| m("containers"))?;
                let area = r.bytes(alen).map_err(|_| m("containers"))?.to_vec();
                for c in dir.iter() {
                    check_container(c, &area)?;
                }
                Inner::V4 {
                    octet,
                    dir,
                    area,
                    side,
                    checksum,
                }
            }
            IpShardId::V6 => {
                let n = usize::try_from(r.u32().map_err(|_| m("count"))?).map_err(|_| m("count"))?;
                if n > r.remaining() / 40 {
                    return Err(m("count"));
                }
                let mut ranges = Vec::with_capacity(n);
                for _ in 0..n {
                    let f = r.u128().map_err(|_| m("range"))?;
                    let l = r.u128().map_err(|_| m("range"))?;
                    let v = r.u64().map_err(|_| m("range"))?;
                    ranges.push((f, l, v));
                }
                check_ranges(&ranges, |&(f, l, _)| (f, l), shard)?;
                Inner::V6 { ranges, checksum }
            }
        };
        if r.remaining() != 0 {
            return Err(m("trailing bytes"));
        }
        Ok(IpBase(base))
    }
}

fn check_ranges<T>(v: &[T], f: impl Fn(&T) -> (u128, u128), shard: IpShardId) -> Result<(), IpsError> {
    let (lo, hi) = shard.bounds();
    let mut prev: Option<u128> = None;
    for e in v {
        let (a, b) = f(e);
        if a > b || a < lo || b > hi || prev.is_some_and(|p| p >= a) {
            return Err(IpsError::Runs);
        }
        prev = Some(b);
    }
    Ok(())
}

fn u16_at(area: &[u8], at: usize) -> Option<u16> {
    let b = area.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
}

fn check_container(c: &Container, area: &[u8]) -> Result<(), IpsError> {
    let m = IpsError::Malformed;
    let off = usize::try_from(c.offset).map_err(|_| m("offset"))?;
    let n = usize::from(c.count);
    match c.kind {
        KIND_NONE => {
            if c.count != 0 || c.offset != 0 {
                return Err(m("empty container"));
            }
        }
        KIND_ARRAY => {
            let end = off
                .checked_add(n.checked_mul(2).ok_or(m("array"))?)
                .ok_or(m("array"))?;
            if n == 0 || end > area.len() {
                return Err(m("array"));
            }
            let mut prev: Option<u16> = None;
            for i in 0..n {
                let v = u16_at(area, off.saturating_add(i.saturating_mul(2))).ok_or(m("array"))?;
                if prev.is_some_and(|p| p >= v) {
                    return Err(m("array order"));
                }
                prev = Some(v);
            }
        }
        KIND_RUNS => {
            let end = off
                .checked_add(n.checked_mul(4).ok_or(m("runs"))?)
                .ok_or(m("runs"))?;
            if n == 0 || end > area.len() {
                return Err(m("runs"));
            }
            let mut prev_end: Option<u32> = None;
            for i in 0..n {
                let at = off.saturating_add(i.saturating_mul(4));
                let s = u32::from(u16_at(area, at).ok_or(m("runs"))?);
                let l = u32::from(u16_at(area, at.saturating_add(2)).ok_or(m("runs"))?);
                let e = s.saturating_add(l);
                if e > 0xffff || prev_end.is_some_and(|p| p >= s) {
                    return Err(m("run order"));
                }
                prev_end = Some(e);
            }
        }
        KIND_BITMAP => {
            let end = off.checked_add(BITMAP_BYTES).ok_or(m("bitmap"))?;
            if end > area.len() {
                return Err(m("bitmap"));
            }
        }
        _ => return Err(m("container kind")),
    }
    Ok(())
}

fn container_has(c: &Container, area: &[u8], low: u16) -> bool {
    let off = c.offset as usize;
    let n = usize::from(c.count);
    match c.kind {
        KIND_ARRAY => {
            let (mut lo, mut hi) = (0usize, n);
            while lo < hi {
                let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
                match u16_at(area, off.saturating_add(mid.saturating_mul(2))) {
                    Some(v) if v == low => return true,
                    Some(v) if v < low => lo = mid.saturating_add(1),
                    Some(_) => hi = mid,
                    None => return false,
                }
            }
            false
        }
        KIND_RUNS => {
            // The last run starting at or before `low`.
            let (mut lo, mut hi) = (0usize, n);
            while lo < hi {
                let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
                match u16_at(area, off.saturating_add(mid.saturating_mul(4))) {
                    Some(s) if s <= low => lo = mid.saturating_add(1),
                    _ => hi = mid,
                }
            }
            let Some(i) = lo.checked_sub(1) else { return false };
            let at = off.saturating_add(i.saturating_mul(4));
            match (u16_at(area, at), u16_at(area, at.saturating_add(2))) {
                (Some(s), Some(l)) => u32::from(low) <= u32::from(s).saturating_add(u32::from(l)),
                _ => false,
            }
        }
        KIND_BITMAP => area
            .get(off.saturating_add(usize::from(low >> 3)))
            .is_some_and(|b| b & (1u8 << (low & 7)) != 0),
        _ => false,
    }
}

fn container_ranges(c: &Container, area: &[u8]) -> Vec<(u16, u16)> {
    let off = c.offset as usize;
    let n = usize::from(c.count);
    let mut out: Vec<(u16, u16)> = Vec::new();
    let mut push = |v: u16| match out.last_mut() {
        Some(l) if l.1.checked_add(1) == Some(v) => l.1 = v,
        _ => out.push((v, v)),
    };
    match c.kind {
        KIND_ARRAY => {
            for i in 0..n {
                if let Some(v) = u16_at(area, off.saturating_add(i.saturating_mul(2))) {
                    push(v);
                }
            }
        }
        KIND_RUNS => {
            for i in 0..n {
                let at = off.saturating_add(i.saturating_mul(4));
                if let (Some(s), Some(l)) = (u16_at(area, at), u16_at(area, at.saturating_add(2))) {
                    out.push((s, s.saturating_add(l)));
                }
            }
        }
        KIND_BITMAP => {
            for v in 0..=u16::MAX {
                if container_has(c, area, v) {
                    push(v);
                }
            }
        }
        _ => {}
    }
    out
}

/// Binary search in sorted disjoint ranges.
pub(crate) fn range_get<A: Copy + Ord>(v: &[(A, A, u64)], a: A) -> Option<u64> {
    let i = v.partition_point(|&(f, _, _)| f <= a);
    let &(_, l, val) = v.get(i.checked_sub(1)?)?;
    (a <= l).then_some(val)
}

/// Writes `ips.bin` for `shard` from its runs (sorted, disjoint, inside the shard) and returns
/// it with the set checksum.
pub fn write(shard: IpShardId, runs: &[Run]) -> Result<(Vec<u8>, SetChecksum), IpsError> {
    check_ranges(runs, |r| (r.first, r.last), shard)?;
    let v4 = shard.is_v4();
    let checksum = runs.iter().fold(SetChecksum::ZERO, |c, r| {
        c.plus(SetChecksum::ip_entry(v4, r.first, r.last, r.value.0))
    });
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT.to_le_bytes());
    out.extend_from_slice(&shard.code().to_le_bytes());
    out.extend_from_slice(&checksum.0.to_le_bytes());
    match shard {
        IpShardId::V4(_) => {
            let plain = plain_value();
            let side: Vec<&Run> = runs.iter().filter(|r| r.value != plain).collect();
            out.extend_from_slice(
                &u32::try_from(side.len())
                    .map_err(|_| IpsError::Runs)?
                    .to_le_bytes(),
            );
            for r in &side {
                let first = u32::try_from(r.first).map_err(|_| IpsError::Runs)?;
                let last = u32::try_from(r.last).map_err(|_| IpsError::Runs)?;
                out.extend_from_slice(&first.to_le_bytes());
                out.extend_from_slice(&last.to_le_bytes());
                out.extend_from_slice(&r.value.0.to_le_bytes());
            }
            // Plain-block ranges per /16.
            let mut per16: Vec<Vec<(u16, u16)>> = vec![Vec::new(); 256];
            for r in runs.iter().filter(|r| r.value == plain) {
                let mut s = u32::try_from(r.first).map_err(|_| IpsError::Runs)?;
                let e = u32::try_from(r.last).map_err(|_| IpsError::Runs)?;
                loop {
                    let b = (s >> 16) & 0xff;
                    let block_end = s | 0xffff;
                    let end = e.min(block_end);
                    if let Some(v) = per16.get_mut(b as usize) {
                        v.push((low16(s), low16(end)));
                    }
                    if end == e {
                        break;
                    }
                    s = end.saturating_add(1);
                }
            }
            let mut area: Vec<u8> = Vec::new();
            let mut dir = Vec::with_capacity(256 * 8);
            for ranges in &per16 {
                if ranges.is_empty() {
                    dir.extend_from_slice(&[KIND_NONE, 0, 0, 0, 0, 0, 0, 0]);
                    continue;
                }
                let card: usize = ranges
                    .iter()
                    .map(|&(s, e)| usize::from(e).saturating_sub(usize::from(s)).saturating_add(1))
                    .sum();
                let array_cost = card.saturating_mul(2);
                let runs_cost = ranges.len().saturating_mul(4);
                let offset = u32::try_from(area.len()).map_err(|_| IpsError::Runs)?;
                let (kind, count) = if array_cost <= runs_cost && array_cost < BITMAP_BYTES {
                    for &(s, e) in ranges {
                        for v in s..=e {
                            area.extend_from_slice(&v.to_le_bytes());
                        }
                    }
                    (KIND_ARRAY, card)
                } else if runs_cost < BITMAP_BYTES {
                    for &(s, e) in ranges {
                        area.extend_from_slice(&s.to_le_bytes());
                        area.extend_from_slice(&e.wrapping_sub(s).to_le_bytes());
                    }
                    (KIND_RUNS, ranges.len())
                } else {
                    let mut bm = vec![0u8; BITMAP_BYTES];
                    for &(s, e) in ranges {
                        for v in s..=e {
                            if let Some(b) = bm.get_mut(usize::from(v >> 3)) {
                                *b |= 1u8 << (v & 7);
                            }
                        }
                    }
                    area.extend_from_slice(&bm);
                    (KIND_BITMAP, 0)
                };
                dir.push(kind);
                dir.push(0);
                dir.extend_from_slice(&u16::try_from(count).map_err(|_| IpsError::Runs)?.to_le_bytes());
                dir.extend_from_slice(&offset.to_le_bytes());
            }
            out.extend_from_slice(&dir);
            out.extend_from_slice(
                &u32::try_from(area.len())
                    .map_err(|_| IpsError::Runs)?
                    .to_le_bytes(),
            );
            out.extend_from_slice(&area);
        }
        IpShardId::V6 => {
            out.extend_from_slice(
                &u32::try_from(runs.len())
                    .map_err(|_| IpsError::Runs)?
                    .to_le_bytes(),
            );
            for r in runs {
                out.extend_from_slice(&r.first.to_le_bytes());
                out.extend_from_slice(&r.last.to_le_bytes());
                out.extend_from_slice(&r.value.0.to_le_bytes());
            }
        }
    }
    Ok((out, checksum))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(s: &str) -> u128 {
        u128::from(u32::from(s.parse::<std::net::Ipv4Addr>().unwrap()))
    }

    #[test]
    fn shard_ids() {
        assert_eq!("v4/45".parse::<IpShardId>(), Ok(IpShardId::V4(45)));
        assert_eq!("v6".parse::<IpShardId>(), Ok(IpShardId::V6));
        assert!("v4/045".parse::<IpShardId>().is_err());
        assert!("v4/256".parse::<IpShardId>().is_err());
        assert_eq!(IpShardId::V4(7).to_string(), "v4/7");
    }

    #[test]
    fn v4_containers_roundtrip() {
        let plain = plain_value();
        let other = Value::flags_only(Flags::A_EXACT);
        let mut runs = vec![
            // An array /16 (scattered).
            Run {
                first: ip4("45.1.0.1"),
                last: ip4("45.1.0.1"),
                value: plain,
            },
            Run {
                first: ip4("45.1.0.9"),
                last: ip4("45.1.0.9"),
                value: plain,
            },
            // A run /16.
            Run {
                first: ip4("45.2.0.0"),
                last: ip4("45.2.255.255"),
                value: plain,
            },
            // A side-table entry.
            Run {
                first: ip4("45.3.1.0"),
                last: ip4("45.3.1.255"),
                value: other,
            },
            // Spanning two /16s.
            Run {
                first: ip4("45.4.255.0"),
                last: ip4("45.5.0.10"),
                value: plain,
            },
        ];
        // A bitmap /16: every other address.
        for i in 0..5000u128 {
            runs.push(Run {
                first: ip4("45.9.0.0") + 2 * i,
                last: ip4("45.9.0.0") + 2 * i,
                value: plain,
            });
        }
        runs.sort();
        let (bytes, cs) = write(IpShardId::V4(45), &runs).unwrap();
        let base = IpBase::from_bytes(&bytes).unwrap();
        assert_eq!(base.checksum(), cs);
        assert_eq!(base.get(ip4("45.1.0.9")), Some((plain, true)));
        assert_eq!(base.get(ip4("45.1.0.8")), None);
        assert_eq!(base.get(ip4("45.2.7.7")), Some((plain, true)));
        assert_eq!(base.get(ip4("45.3.1.7")), Some((other, false)));
        assert_eq!(base.get(ip4("45.5.0.10")), Some((plain, true)));
        assert_eq!(base.get(ip4("45.5.0.11")), None);
        assert_eq!(base.get(ip4("45.9.0.2")), Some((plain, true)));
        assert_eq!(base.get(ip4("45.9.0.3")), None);
        assert_eq!(base.get(ip4("46.1.0.1")), None);
        // Runs read back merge adjacent plain ranges across /16s.
        let back = base.runs();
        assert!(back.contains(&Run {
            first: ip4("45.4.255.0"),
            last: ip4("45.5.0.10"),
            value: plain
        }));
        assert_eq!(back.len(), runs.len());
        // Truncations are refused.
        for cut in [0, 10, 40, bytes.len() - 1] {
            assert!(IpBase::from_bytes(&bytes[..cut]).is_err());
        }
        // Runs outside the shard are refused.
        assert_eq!(write(IpShardId::V4(46), &runs).unwrap_err(), IpsError::Runs);
    }

    #[test]
    fn v6_roundtrip() {
        let runs = vec![
            Run {
                first: 10,
                last: 20,
                value: Value(1),
            },
            Run {
                first: 30,
                last: u128::MAX,
                value: Value(4),
            },
        ];
        let (bytes, _) = write(IpShardId::V6, &runs).unwrap();
        let base = IpBase::from_bytes(&bytes).unwrap();
        assert_eq!(base.get(15), Some((Value(1), false)));
        assert_eq!(base.get(25), None);
        assert_eq!(base.get(u128::MAX), Some((Value(4), false)));
        assert_eq!(base.runs(), runs);
    }
}
