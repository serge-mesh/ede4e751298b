//! Paged `dump` (edge-firewall.md §4): one page of a timed set's entries with their remaining
//! timeouts, at most `limit` (≤ 4,096) per page.
//!
//! The first page lists the set from the kernel once and keeps a compact copy (12 bytes per
//! IPv4 pair, 36 per IPv6 pair: 9 MiB for a full `picket6`); later pages are cut from that copy,
//! each entry's timeout aged by the time since the listing, so every page reports what is left
//! **as of that page**, and entries that expired in between are left out. At most
//! [`MAX_SNAPSHOTS`] copies exist at once, kept or still being listed (≤ 18 MiB against the
//! helper's `MemoryMax=64M`; README "Bounded"): a first page takes a slot before it lists the
//! set, evicting the least recently used kept copy, and is refused as `busy` if every slot holds
//! a listing in progress. Each copy is sized from the set's header up front, so it isn't built
//! by doubling. A copy is dropped after [`CURSOR_TTL`] without use or when its last page is
//! served. A cursor the helper no longer holds gets `cursor_expired`, and the edge restarts its
//! dump. Members Picket can't have added (wider prefixes than `/32` or `/128`) are deleted on
//! the way.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use picket_api::helper::{
    DumpEntry, DumpRequest, DumpResponse, HelperError, MAX_DUMP_LIMIT, error_code, sets,
};

use crate::backend::{Backend, SetOp};
use crate::ipset::Elem;

pub const MAX_SNAPSHOTS: usize = 2;
pub const CURSOR_TTL: Duration = Duration::from_secs(120);
const MAX_CURSOR_LEN: usize = 48;

/// Compact rows: addresses as byte arrays, so an IPv6 row isn't padded to `u128`'s 16-byte
/// alignment (a `(u128, u128, u32)` takes 48 bytes, this 36).
enum Rows {
    V4Pair(Vec<([u8; 4], [u8; 4], u32)>),
    V4(Vec<([u8; 4], u32)>),
    V6Pair(Vec<([u8; 16], [u8; 16], u32)>),
    V6(Vec<([u8; 16], u32)>),
}

/// Pushes within `cap`, growing by an eighth rather than doubling when the reservation made
/// from the header falls short (entries added while listing).
fn push<T>(v: &mut Vec<T>, x: T, cap: usize) {
    if v.len() == v.capacity() {
        let room = cap.saturating_sub(v.len()).max(1);
        v.reserve_exact((v.capacity() / 8).max(1024).min(room));
    }
    v.push(x);
}

impl Rows {
    fn new(set: &str, reserve: usize) -> Rows {
        match set {
            sets::PICKET4 => Rows::V4Pair(Vec::with_capacity(reserve)),
            sets::PICKET6 => Rows::V6Pair(Vec::with_capacity(reserve)),
            sets::PICKET_G4 => Rows::V4(Vec::with_capacity(reserve)),
            _ => Rows::V6(Vec::with_capacity(reserve)),
        }
    }
    fn len(&self) -> usize {
        match self {
            Rows::V4Pair(v) => v.len(),
            Rows::V4(v) => v.len(),
            Rows::V6Pair(v) => v.len(),
            Rows::V6(v) => v.len(),
        }
    }
    /// Heap bytes held.
    fn bytes(&self) -> usize {
        fn of<T>(v: &Vec<T>) -> usize {
            v.capacity() * std::mem::size_of::<T>()
        }
        match self {
            Rows::V4Pair(v) => of(v),
            Rows::V4(v) => of(v),
            Rows::V6Pair(v) => of(v),
            Rows::V6(v) => of(v),
        }
    }
    fn get(&self, i: usize) -> (Option<IpAddr>, IpAddr, u32) {
        match self {
            Rows::V4Pair(v) => {
                let (s, d, t) = v[i];
                (Some(Ipv4Addr::from(s).into()), Ipv4Addr::from(d).into(), t)
            }
            Rows::V4(v) => (None, Ipv4Addr::from(v[i].0).into(), v[i].1),
            Rows::V6Pair(v) => {
                let (s, d, t) = v[i];
                (Some(Ipv6Addr::from(s).into()), Ipv6Addr::from(d).into(), t)
            }
            Rows::V6(v) => (None, Ipv6Addr::from(v[i].0).into(), v[i].1),
        }
    }
}

struct Snap {
    id: u64,
    set: &'static str,
    taken: Duration,
    used: Duration,
    rows: Rows,
}

#[derive(Default)]
pub struct DumpStore {
    snaps: Vec<Snap>,
    next_id: u64,
    /// First pages listing their set right now; each holds a slot.
    listing: usize,
}

impl DumpStore {
    /// Heap bytes held by the kept copies.
    pub fn bytes(&self) -> usize {
        self.snaps.iter().map(|s| s.rows.bytes()).sum()
    }
}

/// A slot taken for a listing in progress: handed to the kept copy, or given back when dropped
/// (the listing failed).
struct Listing<'a> {
    store: &'a Mutex<DumpStore>,
    held: bool,
}

impl Listing<'_> {
    /// The slot now belongs to the copy about to be kept in `st` (under the store's lock, so no
    /// other listing can take it in between).
    fn into_kept(mut self, st: &mut DumpStore) {
        st.listing = st.listing.saturating_sub(1);
        self.held = false;
    }
}

impl Drop for Listing<'_> {
    fn drop(&mut self) {
        if self.held {
            let mut st = lock(self.store);
            st.listing = st.listing.saturating_sub(1);
        }
    }
}

/// Takes a slot for a new listing: expired copies go, then the least recently used kept ones
/// until there is room; with every slot holding a listing in progress, `busy`.
fn reserve(store: &Mutex<DumpStore>, now: Duration) -> Result<Listing<'_>, HelperError> {
    let mut st = lock(store);
    st.snaps.retain(|s| now.saturating_sub(s.used) < CURSOR_TTL);
    while st.snaps.len() + st.listing >= MAX_SNAPSHOTS && !st.snaps.is_empty() {
        let i = st
            .snaps
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| s.used)
            .map(|(i, _)| i)
            .unwrap_or(0);
        st.snaps.remove(i);
    }
    if st.snaps.len() + st.listing >= MAX_SNAPSHOTS {
        return Err(HelperError {
            code: error_code::BUSY.into(),
            message: "every dump slot is listing a set; retry".into(),
        });
    }
    st.listing += 1;
    Ok(Listing { store, held: true })
}

fn invalid(m: impl Into<String>) -> HelperError {
    HelperError {
        code: error_code::INVALID.into(),
        message: m.into(),
    }
}

fn lock(m: &Mutex<DumpStore>) -> std::sync::MutexGuard<'_, DumpStore> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Most members Picket never adds that one dump deletes; any more go at the next dump.
const MAX_FOREIGN: usize = 4096;

/// Is this a member Picket can have added: host addresses only (`/32` or `/128` members of
/// `hash:net,net`; `hash:ip` lists no prefix)?
pub fn is_host_member(e: &Elem) -> bool {
    let host = |ip: &IpAddr, c: Option<u8>| c.is_none_or(|c| c == if ip.is_ipv4() { 32 } else { 128 });
    host(&e.ip, e.cidr) && e.ip2.as_ref().is_none_or(|ip2| host(ip2, e.cidr2))
}

/// Lists `set` from the kernel into compact rows. Members with a wider prefix (added by hand)
/// are left out and deleted: they would allow whole ranges, the edge can't express them in a
/// `delete`, and the reconcile never adopts what it didn't add (edge-firewall.md §3).
fn take<B: Backend + ?Sized>(b: &B, set: &'static str) -> Result<Rows, HelperError> {
    let cap = sets::MAXELEM as usize;
    // Sized from the header (expired entries not yet collected included), so the copy isn't
    // built by doubling; a failed header read just starts small.
    let expect = match b.ipset_header(set) {
        Ok(Some(h)) => (h.elements.unwrap_or(0) as usize).min(cap),
        _ => 0,
    };
    let mut rows = Rows::new(set, expect);
    let mut over = 0usize;
    let mut foreign: Vec<Elem> = Vec::new();
    let res = b.ipset_list(set, &mut |m| {
        if !is_host_member(&m.elem) {
            if foreign.len() < MAX_FOREIGN {
                foreign.push(m.elem);
            }
            return;
        }
        if rows.len() >= cap {
            over += 1;
            return;
        }
        let t = m.timeout.unwrap_or(0);
        match (&mut rows, m.elem.ip, m.elem.ip2) {
            (Rows::V4Pair(v), IpAddr::V4(s), Some(IpAddr::V4(d))) => {
                push(v, (s.octets(), d.octets(), t), cap)
            }
            (Rows::V6Pair(v), IpAddr::V6(s), Some(IpAddr::V6(d))) => {
                push(v, (s.octets(), d.octets(), t), cap)
            }
            (Rows::V4(v), IpAddr::V4(d), None) => push(v, (d.octets(), t), cap),
            (Rows::V6(v), IpAddr::V6(d), None) => push(v, (d.octets(), t), cap),
            _ => {}
        }
    });
    if over > 0 {
        tracing::warn!(
            set,
            over,
            "dump: set holds more entries than maxelem; the rest are left out"
        );
    }
    if !foreign.is_empty() {
        let ops: Vec<SetOp> = foreign
            .iter()
            .map(|&elem| SetOp {
                set,
                elem,
                timeout: None,
            })
            .collect();
        let failed = b.ipset_del_ctl(&ops).iter().filter(|r| r.is_err()).count();
        tracing::warn!(
            set,
            deleted = ops.len() - failed,
            failed,
            "dump: deleted members with a wider prefix than Picket adds"
        );
    }
    match res {
        Ok(_) => Ok(rows),
        Err(e) if e.is_no_set() => Err(HelperError {
            code: error_code::NO_SET.into(),
            message: format!("no set {set}"),
        }),
        Err(e) => Err(HelperError {
            code: error_code::INTERNAL.into(),
            message: e.to_string(),
        }),
    }
}

fn parse_cursor(c: &str) -> Option<(u64, usize)> {
    if c.len() > MAX_CURSOR_LEN {
        return None;
    }
    let (id, off) = c.split_once('.')?;
    Some((id.parse().ok()?, off.parse().ok()?))
}

/// Serves one `dump` page. Blocking (the first page lists the set from the kernel).
pub fn page<B: Backend + ?Sized>(
    store: &Mutex<DumpStore>,
    b: &B,
    req: &DumpRequest,
) -> Result<DumpResponse, HelperError> {
    let set = sets::TIMED
        .iter()
        .copied()
        .find(|s| *s == req.set)
        .ok_or_else(|| invalid("dump reaches only the four timed sets"))?;
    if req.limit == 0 {
        return Err(invalid("limit must be at least 1"));
    }
    let limit = req.limit.min(MAX_DUMP_LIMIT) as usize;
    let now = b.mono();

    let (id, offset) = match &req.cursor {
        None => {
            // The slot is taken before the listing, so copies being built count too.
            let slot = reserve(store, now)?;
            let rows = take(b, set)?;
            let mut st = lock(store);
            slot.into_kept(&mut st);
            st.next_id = st.next_id.wrapping_add(1);
            let id = st.next_id;
            st.snaps.push(Snap {
                id,
                set,
                taken: now,
                used: now,
                rows,
            });
            (id, 0)
        }
        Some(c) => {
            let (id, off) = parse_cursor(c).ok_or_else(|| invalid("malformed cursor"))?;
            (id, off)
        }
    };

    let mut st = lock(store);
    st.snaps
        .retain(|s| now.saturating_sub(s.used) < CURSOR_TTL || s.id == id && req.cursor.is_none());
    let Some(pos) = st.snaps.iter().position(|s| s.id == id && s.set == set) else {
        return Err(HelperError {
            code: error_code::CURSOR_EXPIRED.into(),
            message: "cursor expired; restart the dump".into(),
        });
    };
    let snap = &mut st.snaps[pos];
    snap.used = now;
    // Whole seconds elapsed since the listing, rounded to nearest.
    let elapsed =
        u32::try_from((now.saturating_sub(snap.taken).as_millis() + 500) / 1000).unwrap_or(u32::MAX);
    let mut entries = Vec::with_capacity(limit.min(snap.rows.len().saturating_sub(offset)));
    let mut i = offset;
    while i < snap.rows.len() && entries.len() < limit {
        let (src, dst, t) = snap.rows.get(i);
        i += 1;
        let left = if t == 0 { 0 } else { t.saturating_sub(elapsed) };
        if t != 0 && left == 0 {
            continue; // expired since the listing
        }
        entries.push(DumpEntry {
            src,
            dst,
            timeout_s: left,
        });
    }
    let next_cursor = if i < snap.rows.len() {
        Some(format!("{id}.{i}"))
    } else {
        st.snaps.remove(pos);
        None
    };
    Ok(DumpResponse { entries, next_cursor })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeBackend;
    use crate::ipset::{CreateSpec, SetFamily, SetType};

    fn setup(n: u32) -> FakeBackend {
        let b = FakeBackend::new();
        b.ipset_create(&CreateSpec {
            name: "picket4".into(),
            set_type: SetType::HashNetNet,
            family: SetFamily::Inet,
            revision: 0,
            timeout: Some(300),
            maxelem: 262_144,
        })
        .unwrap();
        let ops: Vec<SetOp> = (0..n)
            .map(|i| SetOp {
                set: "picket4",
                elem: Elem::host_pair(
                    Ipv4Addr::new(192, 168, 1, 10).into(),
                    Ipv4Addr::from(0x0a00_0000 + i).into(),
                ),
                // Entry i lives 10 + i seconds.
                timeout: Some(10 + i),
            })
            .collect();
        assert!(b.ipset_add(&ops).iter().all(|r| r.is_ok()));
        b
    }

    fn req(cursor: Option<String>, limit: u32) -> DumpRequest {
        DumpRequest {
            set: "picket4".into(),
            cursor,
            limit,
        }
    }

    #[test]
    fn pages_age_timeouts_and_drop_expired() {
        let b = setup(100);
        let store = Mutex::new(DumpStore::default());
        let p1 = page(&store, &b, &req(None, 40)).unwrap();
        assert_eq!(p1.entries.len(), 40);
        let first_t: Vec<u32> = p1.entries.iter().map(|e| e.timeout_s).collect();
        assert!(first_t.iter().all(|t| (10..110).contains(t)));
        // 30 s later the next page reports what is left now; entries with ≤ 30 s are gone.
        b.advance(Duration::from_secs(30));
        let p2 = page(&store, &b, &req(p1.next_cursor.clone(), 40)).unwrap();
        for e in &p2.entries {
            let IpAddr::V4(d) = e.dst else { panic!() };
            let i = u32::from(d) - 0x0a00_0000;
            assert_eq!(
                e.timeout_s,
                10 + i - 30,
                "timeout as of this page, not the listing"
            );
        }
        let mut all = p1.entries.len() + p2.entries.len();
        let mut cur = p2.next_cursor;
        while let Some(c) = cur {
            let p = page(&store, &b, &req(Some(c), 40)).unwrap();
            assert!(p.entries.len() <= 40);
            all += p.entries.len();
            cur = p.next_cursor;
        }
        // The first 40 were served before the clock moved; among the other 60, those with
        // 10 + i ≤ 30 (i ≤ 20) expired — none of them, as i ≥ 40 there.
        assert_eq!(all, 100);
        // The last page removed the copy: its cursor is gone.
        assert!(store.lock().unwrap().snaps.is_empty());
    }

    #[test]
    fn limit_is_capped_and_validated() {
        let b = setup(5000);
        let store = Mutex::new(DumpStore::default());
        let p = page(&store, &b, &req(None, 100_000)).unwrap();
        assert_eq!(p.entries.len(), MAX_DUMP_LIMIT as usize);
        assert!(p.next_cursor.is_some());
        assert_eq!(page(&store, &b, &req(None, 0)).unwrap_err().code, "invalid");
        let bad = DumpRequest {
            set: "picket-static4".into(),
            cursor: None,
            limit: 10,
        };
        assert_eq!(page(&store, &b, &bad).unwrap_err().code, "invalid");
        let p = page(&store, &b, &req(Some("999.0".into()), 10)).unwrap_err();
        assert_eq!(p.code, "cursor_expired");
    }

    #[test]
    fn members_picket_never_adds_are_left_out_and_deleted() {
        // A /24 pair (added by hand): the edge can neither see nor delete it, and it would
        // allow a whole range, so the dump drops it from the set.
        let b = setup(3);
        let wide = Elem {
            ip: Ipv4Addr::new(10, 9, 0, 0).into(),
            cidr: Some(24),
            ip2: Some(Ipv4Addr::new(1, 1, 1, 1).into()),
            cidr2: Some(32),
        };
        let narrow_dst = Elem {
            cidr2: Some(16),
            ..Elem::host_pair(
                Ipv4Addr::new(192, 168, 1, 10).into(),
                Ipv4Addr::new(8, 8, 0, 0).into(),
            )
        };
        let ops: Vec<SetOp> = [wide, narrow_dst]
            .into_iter()
            .map(|elem| SetOp {
                set: "picket4",
                elem,
                timeout: Some(100),
            })
            .collect();
        assert!(b.ipset_add(&ops).iter().all(|r| r.is_ok()));
        let store = Mutex::new(DumpStore::default());
        let p = page(&store, &b, &req(None, 100)).unwrap();
        assert_eq!(p.entries.len(), 3);
        assert!(
            p.entries
                .iter()
                .all(|e| e.src == Some(Ipv4Addr::new(192, 168, 1, 10).into()))
        );
        assert!(
            !p.entries
                .iter()
                .any(|e| e.dst == IpAddr::from(Ipv4Addr::new(8, 8, 0, 0)))
        );
        let left = b.members("picket4");
        assert_eq!(left.len(), 3);
        assert!(
            left.iter()
                .all(|(e, _)| e.cidr == Some(32) && e.cidr2 == Some(32))
        );
    }

    #[test]
    fn a_full_ipv6_pair_copy_stays_compact() {
        // README "Bounded", MemoryMax=64M: a full picket6 copy is 36 bytes a row, with no
        // over-allocation.
        let b = FakeBackend::new();
        b.ipset_create(&CreateSpec {
            name: "picket6".into(),
            set_type: SetType::HashNetNet,
            family: SetFamily::Inet6,
            revision: 0,
            timeout: Some(300),
            maxelem: sets::MAXELEM,
        })
        .unwrap();
        let ops: Vec<SetOp> = (0..sets::MAXELEM as u128)
            .map(|i| SetOp {
                set: "picket6",
                elem: Elem::host_pair(
                    Ipv6Addr::from(0xfd00_u128 << 112 | i).into(),
                    Ipv6Addr::from(0x2001_0db8_u128 << 96 | i).into(),
                ),
                timeout: Some(300),
            })
            .collect();
        assert!(b.ipset_add(&ops).iter().all(|r| r.is_ok()));
        drop(ops);
        let store = Mutex::new(DumpStore::default());
        let r = DumpRequest {
            set: "picket6".into(),
            cursor: None,
            limit: 10,
        };
        let p = page(&store, &b, &r).unwrap();
        assert_eq!(p.entries.len(), 10);
        let bytes = store.lock().unwrap().bytes();
        assert!(
            bytes <= sets::MAXELEM as usize * 36 + 64 * 1024,
            "{bytes} bytes for a full IPv6 pair set"
        );
    }

    #[test]
    fn listings_in_progress_take_a_slot() {
        // At most MAX_SNAPSHOTS copies exist at once, kept or still being listed: a first page
        // that finds every slot taken by a listing is refused as busy, not listed.
        let b = setup(10);
        let store = Mutex::new(DumpStore::default());
        let held: Vec<_> = (0..MAX_SNAPSHOTS)
            .map(|_| reserve(&store, b.mono()).unwrap())
            .collect();
        assert_eq!(page(&store, &b, &req(None, 2)).unwrap_err().code, "busy");
        drop(held);
        assert!(page(&store, &b, &req(None, 2)).is_ok());
        // A kept copy gives way to a new listing (least recently used first).
        for _ in 0..MAX_SNAPSHOTS + 1 {
            page(&store, &b, &req(None, 2)).unwrap();
        }
        assert_eq!(store.lock().unwrap().snaps.len(), MAX_SNAPSHOTS);
    }

    #[test]
    fn idle_cursor_expires_and_slots_are_bounded() {
        let b = setup(10);
        let store = Mutex::new(DumpStore::default());
        let p = page(&store, &b, &req(None, 2)).unwrap();
        b.advance(CURSOR_TTL + Duration::from_secs(1));
        assert_eq!(
            page(&store, &b, &req(p.next_cursor, 2)).unwrap_err().code,
            "cursor_expired"
        );
        for _ in 0..5 {
            page(&store, &b, &req(None, 2)).unwrap();
        }
        assert!(store.lock().unwrap().snaps.len() <= MAX_SNAPSHOTS);
    }
}
