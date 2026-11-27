//! `<helper_dir>/snap.json`: the timed sets' entries written at stop and restored after a reboot
//! (edge-firewall.md §4 "Persistence").
//!
//! Format (written in this key order, which the reader relies on to stream):
//!
//! ```json
//! {"version":1,"written_at_ms":1763700000000,"sets":[
//!   {"set":"picket4","entries":[["192.168.1.10","93.184.216.34",250], …]},
//!   {"set":"picket-g4","entries":[[null,"1.1.1.1",30], …]}, …]}
//! ```
//!
//! Each entry is `[src | null, dst, remaining seconds]`. Up to four sets of 262,144 entries is
//! tens of MB of JSON, more than the helper's `MemoryMax=64M` could hold at once, so both the
//! writer (from the kernel dump) and the reader (into the kernel, in batches) stream.
//!
//! Restore rules: only into sets the helper had to create at this start; elapsed time is the
//! larger of the wall-clock difference and the uptime; an entry gets what was left minus the
//! elapsed time, never more than it had at stop, and is skipped below 1 s; nothing is restored if
//! the clock is earlier than the time of writing. The caller deletes the file either way.
//!
//! Reading and adding four full sets takes seconds, so the elapsed time keeps growing while the
//! restore runs: each batch is aged again, by the monotonic clock, just before it is added. An
//! entry thus gets what is left of it when it is added, and one that ran out meanwhile is
//! skipped (edge-firewall.md §4 "Restore").

use std::fmt;
use std::io::{self, Read};
use std::net::IpAddr;
use std::time::Duration;

use picket_api::helper::{MAX_TIMEOUT_S, sets};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::backend::{Backend, SetOp};
use crate::ipset::Elem;

pub const SNAP_FILE: &str = "snap.json";
/// Largest snapshot read (four full sets are ~60–70 MB).
pub const SNAP_MAX: u64 = 256 << 20;
const BATCH: usize = 512;

/// Writes the four timed sets with their remaining timeouts. A set that is missing is written
/// empty. Returns the number of entries written.
pub fn write<B: Backend + ?Sized>(b: &B) -> io::Result<usize> {
    let written_at = b.wall_ms();
    let mut total = 0usize;
    b.write_file(SNAP_FILE, &mut |w| {
        write!(w, "{{\"version\":1,\"written_at_ms\":{written_at},\"sets\":[")?;
        for (i, set) in sets::TIMED.iter().enumerate() {
            if i > 0 {
                w.write_all(b",")?;
            }
            write!(w, "{{\"set\":\"{set}\",\"entries\":[")?;
            let mut first = true;
            let mut err: Option<io::Error> = None;
            let listed = b.ipset_list(set, &mut |m| {
                if err.is_some() {
                    return;
                }
                // Permanent entries (timeout 0) and wider prefixes aren't Picket's; skip them.
                let Some(t) = m.timeout.filter(|t| *t > 0) else {
                    return;
                };
                if !crate::dump::is_host_member(&m.elem) {
                    return;
                }
                let (src, dst) = match m.elem.ip2 {
                    Some(ip2) => (Some(m.elem.ip), ip2),
                    None => (None, m.elem.ip),
                };
                let r = (|| {
                    if !first {
                        w.write_all(b",")?;
                    }
                    match src {
                        Some(s) => write!(w, "[\"{s}\",\"{dst}\",{t}]"),
                        None => write!(w, "[null,\"{dst}\",{t}]"),
                    }
                })();
                first = false;
                total += 1;
                if let Err(e) = r {
                    err = Some(e);
                }
            });
            if let Some(e) = err {
                return Err(e);
            }
            if let Err(e) = listed
                && !e.is_no_set()
            {
                tracing::warn!(set, error = %e, "snapshot: could not list set");
            }
            w.write_all(b"]}")?;
        }
        w.write_all(b"]}\n")
    })?;
    Ok(total)
}

/// What a restore did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub restored: usize,
    /// Expired (< 1 s left), malformed or over the set's size.
    pub skipped: usize,
    pub failed: usize,
    /// The clock is earlier than the time of writing: nothing restored.
    pub clock_earlier: bool,
}

struct Ctx<'a, B: Backend + ?Sized> {
    b: &'a B,
    targets: &'a [&'static str],
    now_ms: i64,
    uptime_ms: i64,
    /// Elapsed time from writing to the start of the restore.
    elapsed_ms: Option<i64>,
    /// Monotonic time at the start of the restore.
    mono_start: Duration,
    /// Entries waiting for the next batch, each with what it had left at stop (ms).
    batch: Vec<(&'static str, Elem, i64)>,
    per_set: usize,
    report: RestoreReport,
}

impl<B: Backend + ?Sized> Ctx<'_, B> {
    /// Elapsed time from writing until now: the start's, plus how long the restore has run.
    fn elapsed_now(&self, start: i64) -> i64 {
        let ran = self.b.mono().saturating_sub(self.mono_start).as_millis();
        start.saturating_add(i64::try_from(ran).unwrap_or(i64::MAX))
    }

    fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let Some(start) = self.elapsed_ms else {
            self.batch.clear();
            return;
        };
        let elapsed = self.elapsed_now(start);
        let mut ops = Vec::with_capacity(self.batch.len());
        for (set, elem, t_ms) in self.batch.drain(..) {
            let left_ms = t_ms - elapsed;
            if left_ms < 1000 {
                // Ran out while the restore was reading or adding earlier entries.
                self.report.skipped += 1;
                continue;
            }
            ops.push(SetOp {
                set,
                elem,
                timeout: Some(u32::try_from(left_ms / 1000).unwrap_or(MAX_TIMEOUT_S)),
            });
        }
        for r in self.b.ipset_add_ctl(&ops) {
            match r {
                Ok(()) => self.report.restored += 1,
                Err(_) => self.report.failed += 1,
            }
        }
    }

    fn entry(&mut self, set: &'static str, src: Option<IpAddr>, dst: IpAddr, t: u64) {
        let Some(elapsed) = self.elapsed_ms else { return };
        if self.per_set >= sets::MAXELEM as usize {
            self.report.skipped += 1;
            return;
        }
        let t_ms = i64::from(u32::try_from(t).map_or(MAX_TIMEOUT_S, |t| t.min(MAX_TIMEOUT_S))) * 1000;
        // Already out by the elapsed time at the start (aged again when its batch is added).
        if t_ms - elapsed < 1000 {
            self.report.skipped += 1;
            return;
        }
        let elem = match (set, src) {
            (sets::PICKET4, Some(s @ IpAddr::V4(_))) if dst.is_ipv4() => Elem::host_pair(s, dst),
            (sets::PICKET6, Some(s @ IpAddr::V6(_))) if dst.is_ipv6() => Elem::host_pair(s, dst),
            (sets::PICKET_G4, None) if dst.is_ipv4() => Elem::ip(dst),
            (sets::PICKET_G6, None) if dst.is_ipv6() => Elem::ip(dst),
            _ => {
                self.report.skipped += 1;
                return;
            }
        };
        self.per_set += 1;
        self.batch.push((set, elem, t_ms));
        if self.batch.len() >= BATCH {
            self.flush();
        }
    }
}

struct Top<'c, 'a, B: Backend + ?Sized>(&'c mut Ctx<'a, B>);
struct SetsSeed<'c, 'a, B: Backend + ?Sized>(&'c mut Ctx<'a, B>);
struct SetSeed<'c, 'a, B: Backend + ?Sized>(&'c mut Ctx<'a, B>);
struct EntriesSeed<'c, 'a, B: Backend + ?Sized>(&'c mut Ctx<'a, B>, &'static str);

/// Aborts the parse without an error once the clock is found to be earlier than the snapshot.
const CLOCK_EARLIER: &str = "picket: clock earlier than snapshot";

impl<'de, B: Backend + ?Sized> DeserializeSeed<'de> for Top<'_, '_, B> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de, B: Backend + ?Sized> Visitor<'de> for Top<'_, '_, B> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a snapshot object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut version = None;
        let mut written_at = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "version" => version = Some(map.next_value::<u32>()?),
                "written_at_ms" => {
                    let w = map.next_value::<i64>()?;
                    written_at = Some(w);
                    if self.0.now_ms < w {
                        self.0.report.clock_earlier = true;
                        return Err(de::Error::custom(CLOCK_EARLIER));
                    }
                    let diff = self.0.now_ms.saturating_sub(w);
                    self.0.elapsed_ms = Some(diff.max(self.0.uptime_ms));
                }
                "sets" => {
                    if version != Some(1) || written_at.is_none() {
                        return Err(de::Error::custom(
                            "snapshot header missing or unsupported version",
                        ));
                    }
                    map.next_value_seed(SetsSeed(&mut *self.0))?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

impl<'de, B: Backend + ?Sized> DeserializeSeed<'de> for SetsSeed<'_, '_, B> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de, B: Backend + ?Sized> Visitor<'de> for SetsSeed<'_, '_, B> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list of sets")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(SetSeed(&mut *self.0))?.is_some() {}
        Ok(())
    }
}

impl<'de, B: Backend + ?Sized> DeserializeSeed<'de> for SetSeed<'_, '_, B> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de, B: Backend + ?Sized> Visitor<'de> for SetSeed<'_, '_, B> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a set object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut target: Option<&'static str> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "set" => {
                    let name = map.next_value::<String>()?;
                    target = self.0.targets.iter().copied().find(|t| *t == name);
                }
                "entries" => match target {
                    Some(set) => {
                        self.0.per_set = 0;
                        map.next_value_seed(EntriesSeed(&mut *self.0, set))?;
                    }
                    None => {
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

impl<'de, B: Backend + ?Sized> DeserializeSeed<'de> for EntriesSeed<'_, '_, B> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de, B: Backend + ?Sized> Visitor<'de> for EntriesSeed<'_, '_, B> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list of entries")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        loop {
            // A malformed entry fails the rest of the file; what was restored before stays.
            match seq.next_element::<(Option<IpAddr>, IpAddr, u64)>()? {
                Some((src, dst, t)) => self.0.entry(self.1, src, dst, t),
                None => return Ok(()),
            }
        }
    }
}

/// Restores the snapshot into `targets` (the timed sets created at this start). Doesn't delete
/// the file.
pub fn restore<B: Backend + ?Sized>(b: &B, targets: &[&'static str]) -> io::Result<RestoreReport> {
    let Some(reader) = b.open_file(SNAP_FILE)? else {
        return Ok(RestoreReport::default());
    };
    if targets.is_empty() {
        return Ok(RestoreReport::default());
    }
    let uptime_ms = b
        .uptime()
        .map(|u| i64::try_from(u.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let mut ctx = Ctx {
        b,
        targets,
        now_ms: b.wall_ms(),
        uptime_ms,
        elapsed_ms: None,
        mono_start: b.mono(),
        batch: Vec::with_capacity(BATCH),
        per_set: 0,
        report: RestoreReport::default(),
    };
    let mut de = serde_json::Deserializer::from_reader(reader.take(SNAP_MAX));
    let res = Top(&mut ctx).deserialize(&mut de);
    ctx.flush();
    match res {
        Ok(()) => Ok(ctx.report),
        Err(_) if ctx.report.clock_earlier => Ok(ctx.report),
        Err(e) => {
            tracing::warn!(error = %e, restored = ctx.report.restored, "snapshot: malformed, restore stopped");
            Ok(ctx.report)
        }
    }
}
