//! The log spool (edge.md §11, edge-unifi.md §1): `spool/{security,bulk}/<n>.jsonl.gz`, about
//! 1 MiB gzip JSONL segments, under `ssd_dir` while the SSD passes its checks, else in `data_dir`.
//!
//! - Segments are opened, appended (one gzip member per append) and closed: never held open, so
//!   UniFi can unmount the SSD. Each append is fsynced before its records count as spooled.
//! - A segment is appended to only by the process that created it, and created with
//!   `O_CREAT|O_EXCL`: a new segment is never an earlier run's file, which may end in a member
//!   torn by a crash. An append that fails part-way is cut back to the segment's last complete
//!   member and the segment takes no more appends, so a torn member never hides later records.
//! - Segment numbers grow across both locations and across runs: the next free number is
//!   reserved in `<data_dir>/spool/next-segment` (on the eMMC, there whether or not the SSD is),
//!   so a segment a run writes to `data_dir` before the drive is mounted still sorts after the
//!   drive's older backlog. Draining merges the two classes' oldest segments by record order
//!   (`seq` within a run, segment number across runs), so delivery keeps the order records were
//!   made in.
//! - A class's records run in segment-number order, whichever location each segment is in: a
//!   write seals the class's open segment at the other location, and an open segment takes
//!   records only while no segment of its class holding records has a higher number.
//! - A segment rotates at [`SEGMENT_BYTES`] compressed or [`SEGMENT_RAW`] decompressed, whichever
//!   comes first, so the reader's limit ([`MAX_SEGMENT_RAW`]) never cuts a segment short.
//! - Each segment holds, once, every `answer` its records reference, ahead of the first such
//!   record, so evicting or dropping one segment never orphans another.
//! - Limits per location: `data_dir` `spool_max_mib`; `ssd_dir` `ssd_spool_max_mib` (null: no
//!   cap). Both always leave their filesystem's floor actually free (`f_bavail`): on the SSD the
//!   check's floor; on `data_dir` the same max(1 GiB, 1 %), so the spool never takes the last of
//!   the eMMC that UniFi OS shares (hard rule 8). The oldest `bulk` segments are evicted first,
//!   then the oldest `security` ones.
//! - Records older than `retention_h` are dropped, but only once the clock is synchronised
//!   (README §2 Clocks); whole segments past the window go at once, open ones included.
//! - A transient read error (EIO, the drive gone) never deletes a segment; only corrupt data
//!   (a torn gzip member) ends one, after its readable records were shipped.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use serde::Deserialize;

use picket_api::time::Timestamp;

use super::{Answer, Class, DropCounters, DropReason, Entry, HeaderGen};
use crate::fsutil::{self, WriteOpts};

/// A segment takes no more appends once it reaches this size.
pub const SEGMENT_BYTES: u64 = 1 << 20;
/// ... or once it holds this many decompressed bytes. Typical records compress 5–10×, so this
/// rarely comes first; it bounds highly compressible ones, and with them what a drain reads into
/// memory per segment.
pub const SEGMENT_RAW: u64 = 8 << 20;
/// Raw (uncompressed) bytes per gzip member.
const MEMBER_RAW: usize = 512 << 10;
/// Most decompressed bytes read from one segment. Above what this release writes (one member
/// can carry a segment past [`SEGMENT_RAW`] by at most one record and its answer), and as high as
/// earlier releases read, so their segments still read back whole.
pub const MAX_SEGMENT_RAW: u64 = 64 << 20;
const _: () = assert!(SEGMENT_RAW + super::MAX_LINE as u64 + (64 << 10) <= MAX_SEGMENT_RAW);
/// Space above a floor before `spool_evicting` clears.
const FLOOR_HEADROOM: u64 = 2 << 20;
/// `<data_dir>/spool/<NEXT_FILE>`: the first segment number no run may have handed out yet.
const NEXT_FILE: &str = "next-segment";
/// Segment numbers reserved per write of [`NEXT_FILE`] (one small eMMC write per ~1 GiB spooled).
const RESERVE: u64 = 1024;
/// Names tried for a new segment before giving up (each taken one is an earlier run's).
const CREATE_TRIES: usize = 64;

/// Room under a cap before `spool_evicting` clears (hysteresis): 2 MiB, or an eighth of a
/// smaller cap.
fn headroom(cap: u64) -> u64 {
    (cap / 8).min(2 << 20)
}

/// Most segments indexed per class directory.
const MAX_SEGMENTS: usize = 1_000_000;

/// Where a segment lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Loc {
    DataDir,
    Ssd,
}

impl Loc {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataDir => "data_dir",
            Self::Ssd => "ssd_dir",
        }
    }
}

/// Spool roots right now: `data_dir/spool`, and `ssd_dir/spool` only while the SSD passes.
#[derive(Clone, Debug)]
pub struct SpoolDirs {
    pub data: PathBuf,
    pub ssd: Option<PathBuf>,
}

/// A filesystem's free space and the floor the spool leaves free there.
#[derive(Clone, Copy, Debug)]
pub struct SsdSpace {
    /// `f_bavail × f_frsize`, Picket's own files not counted as free.
    pub avail: u64,
    /// max(1 GiB, 1 % of the filesystem).
    pub floor: u64,
}

/// What the spool needs from the rest of the edge.
pub trait SpoolEnv: Send + Sync {
    fn dirs(&self) -> SpoolDirs;
    /// The SSD's spool root whether or not the drive passes now: its segment names are only
    /// listed (never written) at start, so new segments are numbered after them.
    fn ssd_spool_root(&self) -> Option<PathBuf> {
        None
    }
    fn ssd_space(&self) -> Option<SsdSpace>;
    /// `data_dir`'s free space and floor; `None` when it can't be read (no floor applied: the
    /// eMMC spool is the last resort).
    fn data_space(&self) -> Option<SsdSpace> {
        None
    }
    /// A write or read on the SSD failed: re-run the SSD checks (edge-unifi.md §1).
    fn ssd_failed(&self);
    /// True once the wall clock is synchronised (README §2 Clocks).
    fn clock_synced(&self) -> bool;
    /// Picket's disk use changed by `delta` bytes at `loc` (heartbeat `disk`).
    fn disk_delta(&self, _loc: Loc, _delta: i64) {}
    /// The spool is evicting at `loc` (true) or no longer is (false): `spool_evicting`.
    fn evicting(&self, _loc: Loc, _on: bool) {}
}

/// The limits in force (from `EdgeConfig.logging`).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub data_max: u64,
    pub ssd_max: Option<u64>,
    pub retention: jiff::SignedDuration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegKey {
    pub n: u64,
    pub loc: Loc,
    pub class: Class,
}

#[derive(Debug)]
pub struct SegMeta {
    pub path: PathBuf,
    /// Apparent size (limits).
    pub len: u64,
    /// Allocated size (what deleting it frees on the drive).
    pub alloc: u64,
    /// Decompressed bytes this process appended (open segments only).
    pub raw: u64,
    /// Records (not counting answers), when known.
    pub count: Option<u64>,
    pub oldest: Option<Timestamp>,
    pub newest: Option<Timestamp>,
    pub mtime: Option<SystemTime>,
    /// Appendable by this process.
    pub open: bool,
    /// Answer ids already in the segment (open segments only).
    pub answers: HashSet<String>,
    /// After a partial drain: the records not yet acked or rejected, which are all an eviction
    /// or the age limit would still drop.
    pub unshipped: Option<u64>,
    /// `oldest` was looked up from the file already.
    pub oldest_read: bool,
}

/// One line read back from a segment.
#[derive(Debug, Clone)]
pub struct Line {
    pub text: Arc<str>,
    pub kind: LineKind,
    pub ts: Option<Timestamp>,
    /// The record's `boot` and `seq`: its place in the order records were made in.
    pub boot: Option<Arc<str>>,
    pub seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineKind {
    Answer(String),
    Record { answer_id: Option<String> },
}

/// A segment read back.
#[derive(Debug, Default)]
pub struct SegContent {
    pub lines: Vec<Line>,
    /// Lines that weren't JSON records (counted as `rejected`).
    pub bad: u64,
    /// The data ended in a corrupt or torn gzip member.
    pub corrupt: bool,
}

/// The oldest segment of a class, as a drain takes it.
#[derive(Clone, Debug)]
pub struct Head {
    pub key: SegKey,
    pub path: PathBuf,
    /// Its class has a later segment: a merge must not run past this one's last record.
    pub more: bool,
}

#[derive(Deserialize)]
struct Peek {
    t: String,
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    answer_id: Option<String>,
    #[serde(default)]
    boot: Option<String>,
    #[serde(default)]
    seq: Option<u64>,
}

/// The spool index and writer. Owned by the shipper task.
pub struct Spool {
    segs: BTreeMap<SegKey, SegMeta>,
    next_n: u64,
    /// Numbers below this are reserved in [`NEXT_FILE`].
    reserved: u64,
    /// `<data_dir>/spool/next-segment`.
    next_file: PathBuf,
    /// The SSD root last indexed (re-indexed when the SSD passes again).
    ssd_indexed: Option<PathBuf>,
    evicting: HashMap<Loc, bool>,
    dropped: Arc<DropCounters>,
    /// Heads a drain POST is shipping from right now ([`Self::begin_flight`]).
    in_flight: HashSet<SegKey>,
    /// In-flight heads evicted meanwhile, with the records an eviction would have counted:
    /// they count as evicted only for what the drain doesn't deliver, which the shipper knows
    /// once the POST has an answer.
    evicted_in_flight: Vec<(SegKey, u64)>,
    /// Tests: the next append writes only this many bytes of its member, then fails (a disk
    /// that fills mid-write).
    #[cfg(test)]
    pub(crate) write_fault: Option<usize>,
}

impl Spool {
    /// Indexes the segments already on disk (from earlier runs); they are never appended to.
    pub fn open(env: &dyn SpoolEnv, dropped: Arc<DropCounters>) -> Self {
        let dirs = env.dirs();
        let next_file = dirs.data.join(NEXT_FILE);
        let mut s = Self {
            segs: BTreeMap::new(),
            next_n: 1,
            reserved: 0,
            next_file,
            ssd_indexed: None,
            evicting: HashMap::new(),
            dropped,
            in_flight: HashSet::new(),
            evicted_in_flight: Vec::new(),
            #[cfg(test)]
            write_fault: None,
        };
        // A crash may leave the counter's temporary file behind (README §2 Restarts).
        fsutil::sweep_temp_files(&dirs.data);
        if let Some(n) = fsutil::read_nofollow_bounded(&s.next_file, 32)
            .ok()
            .and_then(|b| std::str::from_utf8(&b).ok()?.trim().parse::<u64>().ok())
        {
            s.next_n = s.next_n.max(n);
        }
        s.index_root(&dirs.data, Loc::DataDir);
        if let Some(ssd) = &dirs.ssd {
            s.index_root(ssd, Loc::Ssd);
            s.ssd_indexed = Some(ssd.clone());
        } else if let Some(root) = env.ssd_spool_root() {
            // The drive hasn't passed yet: only number after what it may hold.
            s.next_n = s.next_n.max(max_segment_n(&root).saturating_add(1));
        }
        s
    }

    fn index_root(&mut self, root: &Path, loc: Loc) {
        for class in Class::ALL {
            let dir = root.join(class.dir_name());
            fsutil::sweep_temp_files(&dir);
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten().take(MAX_SEGMENTS) {
                let Some(n) = segment_n(&e.file_name()) else {
                    continue;
                };
                let Ok(meta) = e.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                self.next_n = self.next_n.max(n.saturating_add(1));
                self.segs.insert(
                    SegKey { n, loc, class },
                    SegMeta {
                        path: e.path(),
                        len: meta.len(),
                        alloc: fsutil::allocated_bytes(&meta),
                        raw: 0,
                        count: None,
                        oldest: None,
                        newest: None,
                        mtime: meta.modified().ok(),
                        open: false,
                        answers: HashSet::new(),
                        unshipped: None,
                        oldest_read: false,
                    },
                );
            }
        }
    }

    /// Brings the SSD part of the index in line with the SSD's state: segments there are
    /// indexed when it passes its checks and forgotten (left on the drive) while it doesn't.
    pub fn sync_ssd(&mut self, env: &dyn SpoolEnv) {
        self.sync_ssd_to(env.dirs().ssd);
    }

    fn sync_ssd_to(&mut self, ssd: Option<PathBuf>) {
        if ssd == self.ssd_indexed {
            return;
        }
        self.segs.retain(|k, _| k.loc != Loc::Ssd);
        if let Some(root) = &ssd {
            self.index_root(root, Loc::Ssd);
        }
        self.ssd_indexed = ssd;
    }

    pub fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }

    pub fn contains(&self, key: &SegKey) -> bool {
        self.segs.contains_key(key)
    }

    pub fn segment_count(&self) -> usize {
        self.segs.len()
    }

    /// Total bytes in the spool (heartbeat `spool.bytes`).
    pub fn bytes(&self) -> u64 {
        self.segs.values().map(|m| m.len).sum()
    }

    fn loc_bytes(&self, loc: Loc) -> u64 {
        self.segs
            .iter()
            .filter(|(k, _)| k.loc == loc)
            .map(|(_, m)| m.len)
            .sum()
    }

    /// The oldest record time known (heartbeat `spool.oldest_ts`); for segments from an earlier
    /// run, read from the oldest one on demand.
    pub fn oldest_ts(&mut self) -> Option<Timestamp> {
        let (_, first) = self.segs.iter_mut().next()?;
        if first.oldest.is_none() && !first.oldest_read {
            // Once per segment: its first records (a segment read can't fail any worse later).
            first.oldest_read = true;
            if let Ok(c) = read_segment(&first.path, 256 << 10) {
                first.oldest = c.lines.iter().filter_map(|l| l.ts).min();
            }
        }
        self.segs.values().filter_map(|m| m.oldest.or(m.newest)).min()
    }

    /// Appends `entries` (one class) and fsyncs. On success every entry is in a segment on
    /// disk. `header` gives each answer copy its own `(boot, seq)` and `ts`.
    pub(crate) fn append(
        &mut self,
        class: Class,
        entries: &[&Entry],
        env: &dyn SpoolEnv,
        limits: &Limits,
        header: &HeaderGen,
    ) -> io::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut start = 0;
        while start < entries.len() {
            // Prefer the SSD while it passes; on a failed write there, retry at once in data_dir
            // and have the SSD checked again (edge-unifi.md §1: no spool record is lost).
            let dirs = env.dirs();
            // The SSD may have passed (or failed) since the last step: index it before
            // numbering a segment there, so the number follows its earlier segments.
            self.sync_ssd_to(dirs.ssd.clone());
            let mut done = None;
            if let Some(ssd) = dirs.ssd.as_ref() {
                match self.append_member(Loc::Ssd, ssd, class, &entries[start..], env, limits, header) {
                    Ok(Some(n)) => done = Some(n),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(
                            "spool write on the SSD failed, using data_dir: {}",
                            crate::diag::cap(e)
                        );
                        env.ssd_failed();
                    }
                }
            }
            let n = match done {
                Some(n) => n,
                None => self
                    .append_member(
                        Loc::DataDir,
                        &dirs.data,
                        class,
                        &entries[start..],
                        env,
                        limits,
                        header,
                    )?
                    .ok_or_else(|| {
                        io::Error::other("no room in the spool: data_dir is down to its free-space floor")
                    })?,
            };
            if n == 0 {
                return Err(io::Error::other("spool append made no progress"));
            }
            start += n;
        }
        Ok(())
    }

    /// Writes one member with as many leading entries as fit [`MEMBER_RAW`] and the segment's
    /// raw budget. Returns how many entries it wrote, or `None` when `loc` has no room (a floor).
    #[expect(
        clippy::too_many_arguments,
        reason = "one member append: where, what and the limits, all borrowed from the caller"
    )]
    fn append_member(
        &mut self,
        loc: Loc,
        root: &Path,
        class: Class,
        entries: &[&Entry],
        env: &dyn SpoolEnv,
        limits: &Limits,
        header: &HeaderGen,
    ) -> io::Result<Option<usize>> {
        // Build the member against the open segment's answer set, then make room. Eviction may
        // take that very segment (it can be the oldest bulk one); the member is then rebuilt for
        // the new segment, so every answer stays in the segment of the records referencing it.
        let mut built = None;
        for _ in 0..3 {
            let key = self.current_segment(loc, root, class)?;
            let seg = &self.segs[&key];
            let room = usize::try_from(SEGMENT_RAW.saturating_sub(seg.raw)).unwrap_or(usize::MAX);
            let m = build_member(&seg.answers, entries, header, room)?;
            if !self.make_room(loc, m.bytes.len() as u64, env, limits) {
                return Ok(None);
            }
            if self.segs.get(&key).is_some_and(|s| s.open) {
                built = Some((key, m));
                break;
            }
        }
        let Some((key, m)) = built else {
            return Err(io::Error::other("spool segment kept vanishing while making room"));
        };
        self.seal_elsewhere(key);
        let path = self
            .segs
            .get(&key)
            .map(|m| m.path.clone())
            .ok_or_else(|| io::Error::other("segment vanished"))?;
        // The file exists (created by `current_segment`): never create one here.
        let mut f = OpenOptions::new()
            .append(true)
            .custom_flags(fsutil::o_nofollow())
            .open(&path)
            .map_err(|e| fsutil::annotate(e, &path))?;
        let before = f.metadata()?;
        let written = self.write_member(&mut f, &m.bytes).and_then(|()| f.sync_data());
        if let Err(e) = written {
            // A failed append may have left part of the member (ENOSPC, EIO, the drive pulled):
            // cut the file back to its last complete member, and append no more to it either
            // way, so nothing is ever written behind damage that would end its read-back
            // (edge.md §11; edge-unifi.md §1: no spool record is lost). The entries stay with
            // the caller, which writes them again to a new segment.
            let _ = f.set_len(before.len()).and_then(|()| f.sync_data());
            let now = f.metadata().ok();
            drop(f);
            if let (Some(meta), Some(now)) = (self.segs.get_mut(&key), now) {
                let alloc = fsutil::allocated_bytes(&now);
                env.disk_delta(loc, fsutil::byte_delta(alloc, meta.alloc));
                meta.len = now.len();
                meta.alloc = alloc;
            }
            self.seal(key);
            return Err(e);
        }
        let after_meta = f.metadata()?;
        drop(f);
        let alloc_before = fsutil::allocated_bytes(&before);
        let alloc_after = fsutil::allocated_bytes(&after_meta);
        env.disk_delta(loc, fsutil::byte_delta(alloc_after, alloc_before));
        if let Some(meta) = self.segs.get_mut(&key) {
            meta.len = after_meta.len();
            meta.alloc = alloc_after;
            meta.raw = meta.raw.saturating_add(m.raw as u64);
            meta.count = Some(meta.count.unwrap_or(0) + m.taken as u64);
            meta.oldest = match (meta.oldest, m.oldest) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            meta.newest = match (meta.newest, m.newest) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            meta.mtime = Some(SystemTime::now());
            meta.answers.extend(m.added);
            if meta.len >= SEGMENT_BYTES || meta.raw >= SEGMENT_RAW {
                meta.open = false;
                meta.answers.clear();
            }
        }
        Ok(Some(m.taken))
    }

    fn write_member(&mut self, f: &mut std::fs::File, member: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if let Some(n) = self.write_fault.take() {
            f.write_all(&member[..n.min(member.len())])?;
            return Err(io::Error::other("injected write fault"));
        }
        f.write_all(member)
    }

    /// Hands out the next segment number, first reserving a block of them in [`NEXT_FILE`] when
    /// the reservation runs out. A failed reservation doesn't stop spooling (the number still
    /// follows every segment this process has seen); it is retried with the next segment.
    fn alloc_n(&mut self) -> u64 {
        let n = self.next_n;
        self.next_n = n.saturating_add(1);
        if n >= self.reserved {
            let upto = n.saturating_add(RESERVE);
            let saved = self
                .next_file
                .parent()
                .map_or(Ok(()), |d| fsutil::create_dir_all_mode(d, 0o750))
                .and_then(|()| {
                    fsutil::atomic_write(
                        &self.next_file,
                        upto.to_string().as_bytes(),
                        WriteOpts::mode(0o600),
                    )
                });
            match saved {
                Ok(()) => self.reserved = upto,
                Err(e) => tracing::warn!(
                    "can't reserve spool segment numbers in {}: {}",
                    self.next_file.display(),
                    crate::diag::cap(e)
                ),
            }
        }
        n
    }

    /// The open segment for (loc, class), else a new one: its file is created here, empty, with
    /// `O_EXCL`, under the next number whose name is free.
    ///
    /// The open segment is reused only while no segment of the class holding records has a
    /// higher number (one may, at the other location: this one can sit empty while that
    /// location takes the writes, e.g. an SSD at its floor). An empty one that fell behind is
    /// replaced, not left behind as an empty file. With [`Self::seal_elsewhere`] at every
    /// write, a class's records run in segment-number order across both locations, which is all
    /// a drain taking one head per class sees (edge.md §11: keeping order, oldest first).
    fn current_segment(&mut self, loc: Loc, root: &Path, class: Class) -> io::Result<SegKey> {
        let newest_used = self
            .segs
            .iter()
            .filter(|(k, m)| k.class == class && m.len > 0)
            .map(|(k, _)| k.n)
            .max();
        if let Some((k, empty, path)) = self
            .segs
            .iter()
            .find(|(k, m)| k.loc == loc && k.class == class && m.open)
            .map(|(k, m)| (*k, m.len == 0 && m.alloc == 0, m.path.clone()))
        {
            if newest_used.is_none_or(|n| k.n >= n) {
                return Ok(k);
            }
            let removed = empty
                && match std::fs::remove_file(&path) {
                    Ok(()) => true,
                    Err(e) => e.kind() == io::ErrorKind::NotFound,
                };
            if removed {
                self.segs.remove(&k);
            } else {
                self.seal(k);
            }
        }
        let dir = root.join(class.dir_name());
        if !dir.is_dir() {
            fsutil::create_dir_all_mode(&dir, 0o750)?;
        }
        for _ in 0..CREATE_TRIES {
            let n = self.alloc_n();
            let path = dir.join(format!("{n}.jsonl.gz"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(fsutil::o_nofollow())
                .open(&path)
            {
                Ok(f) => {
                    drop(f);
                    fsutil::fsync_dir(&dir)?;
                    let key = SegKey { n, loc, class };
                    self.segs.insert(
                        key,
                        SegMeta {
                            path,
                            len: 0,
                            alloc: 0,
                            raw: 0,
                            count: Some(0),
                            oldest: None,
                            newest: None,
                            mtime: None,
                            open: true,
                            answers: HashSet::new(),
                            unshipped: None,
                            oldest_read: true,
                        },
                    );
                    return Ok(key);
                }
                // An earlier run's segment not indexed (yet): never append to it.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(fsutil::annotate(e, &path)),
            }
        }
        Err(io::Error::other(format!(
            "no free spool segment name in {}",
            dir.display()
        )))
    }

    /// Evicts the oldest `bulk` segments, then `security` ones, at `loc` until `need` more bytes
    /// fit its cap and its floor. Returns false when `loc` can't take them even empty (a floor),
    /// so the caller writes elsewhere. The free space is read once per call and the space each
    /// eviction frees is added to it, never re-read in between (no double counting).
    fn make_room(&mut self, loc: Loc, need: u64, env: &dyn SpoolEnv, limits: &Limits) -> bool {
        let cap = match loc {
            Loc::DataDir => Some(limits.data_max),
            Loc::Ssd => limits.ssd_max,
        };
        let space = match loc {
            Loc::Ssd => env.ssd_space(),
            Loc::DataDir => env.data_space(),
        };
        if loc == Loc::Ssd && space.is_none() {
            // Can't read the SSD's free space: don't write there.
            return false;
        }
        let mut avail = space.map(|s| s.avail);
        let mut evicted = false;
        loop {
            let over_cap = cap.is_some_and(|c| self.loc_bytes(loc).saturating_add(need) > c);
            let under_floor = match (avail, space) {
                (Some(a), Some(s)) => a.saturating_sub(need) < s.floor,
                _ => false,
            };
            if !over_cap && !under_floor {
                break;
            }
            let Some(victim) = self.victim(loc) else {
                // Nothing left to evict. Over a cap with an empty spool: write anyway (one
                // member can't be split further); under a floor: go elsewhere, or nowhere.
                if under_floor {
                    self.set_evicting(loc, evicted, env);
                    return false;
                }
                break;
            };
            match self.delete(victim, env, DropReason::Evicted) {
                Some(freed) => {
                    evicted = true;
                    if let Some(a) = avail.as_mut() {
                        *a = a.saturating_add(freed);
                    }
                }
                None => {
                    // Couldn't delete (a transient error): stop here rather than loop.
                    self.set_evicting(loc, true, env);
                    return !under_floor;
                }
            }
        }
        let still_tight = cap.is_some_and(|c| self.loc_bytes(loc).saturating_add(need + headroom(c)) > c)
            || matches!((avail, space), (Some(a), Some(s)) if a.saturating_sub(need + FLOOR_HEADROOM) < s.floor);
        self.set_evicting(loc, evicted || (still_tight && self.is_evicting(loc)), env);
        true
    }

    fn is_evicting(&self, loc: Loc) -> bool {
        self.evicting.get(&loc).copied().unwrap_or(false)
    }

    fn set_evicting(&mut self, loc: Loc, on: bool, env: &dyn SpoolEnv) {
        if self.is_evicting(loc) != on {
            self.evicting.insert(loc, on);
            env.evicting(loc, on);
        }
    }

    /// Re-evaluates `spool_evicting` after the spool shrank (drained or expired).
    pub fn relax_evicting(&mut self, env: &dyn SpoolEnv, limits: &Limits) {
        for loc in [Loc::DataDir, Loc::Ssd] {
            if !self.is_evicting(loc) {
                continue;
            }
            let cap = match loc {
                Loc::DataDir => Some(limits.data_max),
                Loc::Ssd => limits.ssd_max,
            };
            let cap_ok = cap.is_none_or(|c| self.loc_bytes(loc) + headroom(c) <= c);
            let floor_ok = match loc {
                Loc::Ssd => env
                    .ssd_space()
                    .is_some_and(|s| s.avail >= s.floor + FLOOR_HEADROOM),
                Loc::DataDir => env
                    .data_space()
                    .is_none_or(|s| s.avail >= s.floor + FLOOR_HEADROOM),
            };
            if cap_ok && floor_ok {
                self.set_evicting(loc, false, env);
            }
        }
    }

    /// The eviction victim at `loc`: the oldest non-empty `bulk` segment (the open one
    /// included), else the oldest non-empty `security` one.
    fn victim(&self, loc: Loc) -> Option<SegKey> {
        let pick = |class| {
            self.segs
                .iter()
                .find(|(k, m)| k.loc == loc && k.class == class && m.len > 0)
                .map(|(k, _)| *k)
        };
        pick(Class::Bulk).or_else(|| pick(Class::Security))
    }

    /// Deletes a segment, counting its records under `reason`. Returns the bytes it freed, or
    /// `None` when it couldn't be deleted (left in place and in the index).
    ///
    /// An in-flight head is evicted like any other segment (its space is freed now), but its
    /// records are counted by the shipper once the POST shipping them has an answer: those core
    /// acks were delivered, not evicted (api.md §3 `logs.dropped.evicted`).
    fn delete(&mut self, key: SegKey, env: &dyn SpoolEnv, reason: DropReason) -> Option<u64> {
        let meta = self.segs.get(&key)?;
        let deferred = reason == DropReason::Evicted && self.in_flight.contains(&key);
        let count = match meta.unshipped.or(meta.count) {
            Some(c) => c,
            None => read_segment(&meta.path, MAX_SEGMENT_RAW)
                .map(|c| {
                    c.lines
                        .iter()
                        .filter(|l| matches!(l.kind, LineKind::Record { .. }))
                        .count() as u64
                })
                .unwrap_or(0),
        };
        match std::fs::remove_file(&meta.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    "can't delete spool segment {}: {}",
                    meta.path.display(),
                    crate::diag::cap(e)
                );
                if key.loc == Loc::Ssd {
                    env.ssd_failed();
                }
                return None;
            }
        }
        let meta = self.segs.remove(&key)?;
        env.disk_delta(key.loc, fsutil::byte_delta(0, meta.alloc));
        if deferred {
            self.evicted_in_flight.push((key, count));
        } else {
            self.dropped.add(reason, count);
        }
        Some(meta.alloc)
    }

    /// A drain is about to POST records read from `heads`: until [`Self::end_flight`], evicting
    /// one of them doesn't count its records (see [`Self::delete`]).
    pub fn begin_flight(&mut self, heads: &[SegKey]) {
        self.abandon_flight();
        self.in_flight = heads.iter().copied().collect();
    }

    /// The drain's POSTs have their answers: returns the heads evicted meanwhile. The shipper
    /// counts as evicted those of their records the drain didn't deliver.
    pub fn end_flight(&mut self) -> Vec<SegKey> {
        self.in_flight.clear();
        self.evicted_in_flight.drain(..).map(|(k, _)| k).collect()
    }

    /// A flight that ended without its answers (the drain was cancelled at shutdown): nothing
    /// shows core took the evicted heads' records, so they count as evicted.
    pub fn abandon_flight(&mut self) {
        self.in_flight.clear();
        for (_, n) in self.evicted_in_flight.drain(..) {
            self.dropped.add(DropReason::Evicted, n);
        }
    }

    /// Drops whole segments past the retention window, open ones included. Does nothing until
    /// the clock is synchronised.
    pub fn expire(&mut self, now: Timestamp, env: &dyn SpoolEnv, limits: &Limits) {
        if !env.clock_synced() {
            return;
        }
        let Some(cutoff) = now.checked_sub(limits.retention).ok() else {
            return;
        };
        let old: Vec<SegKey> = self
            .segs
            .iter()
            .filter(|(_, m)| {
                let newest = m
                    .newest
                    .or_else(|| m.mtime.and_then(|t| Timestamp::try_from(t).ok()));
                newest.is_some_and(|t| t < cutoff)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in old {
            self.delete(k, env, DropReason::TooOld);
        }
        self.relax_evicting(env, limits);
    }

    /// The oldest segment.
    pub fn oldest(&self) -> Option<(SegKey, PathBuf)> {
        let (k, m) = self.segs.iter().next()?;
        Some((*k, m.path.clone()))
    }

    /// The oldest segment of each class: a drain merges them by record order. They may be open
    /// ones: draining runs in the same task as appending, which seals a segment being drained
    /// before appending anything while a drain is under way.
    pub fn heads(&self) -> Vec<Head> {
        let mut heads: Vec<Head> = vec![];
        for (k, m) in &self.segs {
            match heads.iter_mut().find(|h| h.key.class == k.class) {
                Some(h) => h.more = true,
                None => heads.push(Head {
                    key: *k,
                    path: m.path.clone(),
                    more: false,
                }),
            }
            if heads.len() == Class::ALL.len() && heads.iter().all(|h| h.more) {
                break;
            }
        }
        heads
    }

    /// Records how many of a partly drained segment's records are still to be shipped. Only a
    /// sealed segment keeps the number (an open one may still grow).
    pub fn set_unshipped(&mut self, key: SegKey, n: u64) {
        if let Some(m) = self.segs.get_mut(&key)
            && !m.open
        {
            m.unshipped = Some(n);
        }
    }

    /// Stops appends to a segment (new records go to a new one).
    pub fn seal(&mut self, key: SegKey) {
        if let Some(m) = self.segs.get_mut(&key) {
            m.open = false;
            m.answers.clear();
        }
    }

    /// Seals the open segment of `key`'s class at the other location, before records go into
    /// `key`: when writing moves between `data_dir` and the SSD and back, the next records start
    /// a new, higher-numbered segment instead of joining one that sorts before what was written
    /// meanwhile (edge.md §11: keeping order). An empty one holds nothing to order and stays
    /// open ([`Self::current_segment`] replaces it if it falls behind).
    fn seal_elsewhere(&mut self, key: SegKey) {
        let others: Vec<SegKey> = self
            .segs
            .iter()
            .filter(|(k, m)| k.class == key.class && k.loc != key.loc && m.open && m.len > 0)
            .map(|(k, _)| *k)
            .collect();
        for k in others {
            self.seal(k);
        }
    }

    /// Removes a fully drained segment (every record acked or rejected by core).
    pub fn finish(&mut self, key: SegKey, env: &dyn SpoolEnv, limits: &Limits) -> bool {
        let ok = match self.segs.get(&key) {
            Some(meta) => match std::fs::remove_file(&meta.path) {
                Ok(()) => true,
                Err(e) if e.kind() == io::ErrorKind::NotFound => true,
                Err(e) => {
                    tracing::warn!(
                        "can't delete drained segment {}: {}",
                        meta.path.display(),
                        crate::diag::cap(e)
                    );
                    if key.loc == Loc::Ssd {
                        env.ssd_failed();
                    }
                    false
                }
            },
            None => true,
        };
        if ok && let Some(m) = self.segs.remove(&key) {
            env.disk_delta(key.loc, fsutil::byte_delta(0, m.alloc));
        }
        self.relax_evicting(env, limits);
        ok
    }

    #[cfg(test)]
    pub fn keys(&self) -> Vec<SegKey> {
        self.segs.keys().copied().collect()
    }
}

/// The number in a segment file name (`<n>.jsonl.gz`).
fn segment_n(name: &std::ffi::OsStr) -> Option<u64> {
    name.to_str()?.strip_suffix(".jsonl.gz")?.parse().ok()
}

/// The highest segment number under a spool root (names only; nothing is opened or changed).
fn max_segment_n(root: &Path) -> u64 {
    let mut max = 0;
    for class in Class::ALL {
        let Ok(rd) = std::fs::read_dir(root.join(class.dir_name())) else {
            continue;
        };
        for e in rd.flatten().take(MAX_SEGMENTS) {
            if let Some(n) = segment_n(&e.file_name()) {
                max = max.max(n);
            }
        }
    }
    max
}

/// One gzip member ready to append.
struct Member {
    bytes: Vec<u8>,
    /// Its decompressed size.
    raw: usize,
    taken: usize,
    added: Vec<String>,
    oldest: Option<Timestamp>,
    newest: Option<Timestamp>,
}

/// Compresses as many leading entries as fit [`MEMBER_RAW`] and `room` (the segment's raw
/// budget), at least one, each new answer once, ahead of its first referencing record; `known`
/// are the answers the segment holds.
fn build_member(
    known: &HashSet<String>,
    entries: &[&Entry],
    header: &HeaderGen,
    room: usize,
) -> io::Result<Member> {
    let cap = MEMBER_RAW.min(room);
    let mut added: Vec<String> = Vec::new();
    let mut raw = String::new();
    let mut taken = 0;
    let (mut oldest, mut newest): (Option<Timestamp>, Option<Timestamp>) = (None, None);
    for e in entries {
        if taken > 0 && raw.len() >= cap {
            break;
        }
        if let Some(a) = &e.answer
            && !known.contains(&a.id)
            && !added.contains(&a.id)
        {
            raw.push_str(&Answer::line(a, header.next()));
            raw.push('\n');
            added.push(a.id.clone());
        }
        raw.push_str(&e.line);
        raw.push('\n');
        oldest = Some(oldest.map_or(e.ts, |o| o.min(e.ts)));
        newest = Some(newest.map_or(e.ts, |o| o.max(e.ts)));
        taken += 1;
    }
    let mut enc = GzEncoder::new(Vec::with_capacity(raw.len() / 4 + 64), Compression::default());
    enc.write_all(raw.as_bytes())?;
    Ok(Member {
        bytes: enc.finish()?,
        raw: raw.len(),
        taken,
        added,
        oldest,
        newest,
    })
}

/// Reads a segment back, decompressing at most `max_raw` bytes. An I/O error from the file
/// (EIO, the drive gone, permissions) is returned as an error and must not lead to deleting the
/// segment; corrupt data (a torn or damaged gzip member) ends the content with `corrupt` set.
pub fn read_segment(path: &Path, max_raw: u64) -> io::Result<SegContent> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(fsutil::o_nofollow())
        .open(path)
        .map_err(|e| fsutil::annotate(e, path))?;
    read_from(f, max_raw)
}

/// [`read_segment`] over bytes already in memory (fuzzing, tests).
pub fn read_segment_bytes(data: &[u8], max_raw: u64) -> io::Result<SegContent> {
    read_from(data, max_raw)
}

fn read_from(f: impl Read, max_raw: u64) -> io::Result<SegContent> {
    let mut dec = MultiGzDecoder::new(io::BufReader::new(f));
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 << 10];
    let mut corrupt = false;
    loop {
        match dec.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() as u64 > max_raw {
                    buf.truncate(usize::try_from(max_raw).unwrap_or(usize::MAX));
                    corrupt = true;
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // An OS error comes from the file itself: transient, keep the segment.
            Err(e) if e.raw_os_error().is_some() => return Err(e),
            // Anything else is the decoder rejecting the data.
            Err(_) => {
                corrupt = true;
                break;
            }
        }
    }
    let mut content = SegContent {
        corrupt,
        ..Default::default()
    };
    // A segment's records come from one run: share its `boot` text between them.
    let mut last_boot: Option<Arc<str>> = None;
    let mut parts: Vec<&[u8]> = buf.split(|b| *b == b'\n').collect();
    // The last piece is either the empty tail after the final newline or an incomplete line.
    parts.pop();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        let Ok(text) = std::str::from_utf8(p) else {
            content.bad += 1;
            continue;
        };
        let Ok(peek) = serde_json::from_str::<Peek>(text) else {
            content.bad += 1;
            continue;
        };
        let ts = peek.ts.as_deref().and_then(|s| picket_api::time::parse(s).ok());
        let boot = peek.boot.map(|b| match &last_boot {
            Some(l) if **l == *b => Arc::clone(l),
            _ => {
                let a: Arc<str> = Arc::from(b);
                last_boot = Some(Arc::clone(&a));
                a
            }
        });
        let kind = if peek.t == "answer" {
            match peek.id {
                Some(id) => LineKind::Answer(id),
                None => {
                    content.bad += 1;
                    continue;
                }
            }
        } else {
            LineKind::Record {
                answer_id: peek.answer_id,
            }
        };
        content.lines.push(Line {
            text: Arc::from(text),
            kind,
            ts,
            boot,
            seq: peek.seq,
        });
    }
    Ok(content)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub(crate) struct FakeEnv {
        pub data: PathBuf,
        pub ssd: Mutex<Option<PathBuf>>,
        /// The SSD spool root whether or not it passes (listed at open for numbering).
        pub ssd_root: Mutex<Option<PathBuf>>,
        pub space: Mutex<Option<SsdSpace>>,
        pub data_space: Mutex<Option<SsdSpace>>,
        pub synced: AtomicBool,
        pub ssd_failures: Mutex<u32>,
        pub evicting: Mutex<Vec<(Loc, bool)>>,
    }

    impl FakeEnv {
        pub fn new(root: &Path) -> Self {
            Self {
                data: root.join("data/spool"),
                ssd: Mutex::new(None),
                ssd_root: Mutex::new(None),
                space: Mutex::new(None),
                data_space: Mutex::new(None),
                synced: AtomicBool::new(true),
                ssd_failures: Mutex::new(0),
                evicting: Mutex::new(vec![]),
            }
        }
    }

    impl SpoolEnv for FakeEnv {
        fn dirs(&self) -> SpoolDirs {
            SpoolDirs {
                data: self.data.clone(),
                ssd: self.ssd.lock().unwrap().clone(),
            }
        }
        fn ssd_spool_root(&self) -> Option<PathBuf> {
            self.ssd_root.lock().unwrap().clone()
        }
        fn ssd_space(&self) -> Option<SsdSpace> {
            *self.space.lock().unwrap()
        }
        fn data_space(&self) -> Option<SsdSpace> {
            *self.data_space.lock().unwrap()
        }
        fn ssd_failed(&self) {
            *self.ssd_failures.lock().unwrap() += 1;
        }
        fn clock_synced(&self) -> bool {
            self.synced.load(Ordering::Relaxed)
        }
        fn evicting(&self, loc: Loc, on: bool) {
            self.evicting.lock().unwrap().push((loc, on));
        }
    }

    pub(crate) fn entry(
        seq: u64,
        class: Class,
        ts: Timestamp,
        answer: Option<Arc<Answer>>,
        pad: usize,
    ) -> Entry {
        let line = format!(
            r#"{{"t":"q","ts":"{}","boot":"b","seq":{seq}{}{}}}"#,
            picket_api::time::format_micros(&ts),
            answer
                .as_ref()
                .map(|a| format!(r#","answer_id":"{}""#, a.id))
                .unwrap_or_default(),
            if pad > 0 {
                format!(r#","pad":"{}""#, random_hex(pad))
            } else {
                String::new()
            }
        );
        Entry {
            seq,
            ts,
            class,
            line: line.into_boxed_str(),
            answer,
            receipt: None,
        }
    }

    fn random_hex(n: usize) -> String {
        (0..n.div_ceil(16))
            .map(|_| format!("{:016x}", rand::random::<u64>()))
            .collect::<String>()[..n]
            .to_owned()
    }

    fn limits() -> Limits {
        Limits {
            data_max: 256 << 20,
            ssd_max: None,
            retention: jiff::SignedDuration::from_hours(72),
        }
    }

    fn hdr() -> HeaderGen {
        HeaderGen::for_tests()
    }

    #[test]
    fn append_writes_answers_once_per_segment_and_reads_back() {
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let mut s = Spool::open(&env, Arc::default());
        let a = Answer::new(bytes::Bytes::from_static(b"wire-1")).unwrap();
        let now = Timestamp::now();
        let e1 = entry(1, Class::Bulk, now, Some(Arc::clone(&a)), 0);
        let e2 = entry(2, Class::Bulk, now, Some(Arc::clone(&a)), 0);
        s.append(Class::Bulk, &[&e1, &e2], &env, &limits(), &hdr())
            .unwrap();
        let e3 = entry(3, Class::Bulk, now, Some(Arc::clone(&a)), 0);
        s.append(Class::Bulk, &[&e3], &env, &limits(), &hdr()).unwrap();
        let keys = s.keys();
        assert_eq!(keys.len(), 1);
        let (k, path) = s.oldest().unwrap();
        assert_eq!(k.class, Class::Bulk);
        let c = read_segment(&path, MAX_SEGMENT_RAW).unwrap();
        assert!(!c.corrupt);
        let kinds: Vec<_> = c.lines.iter().map(|l| l.kind.clone()).collect();
        assert_eq!(
            kinds[0],
            LineKind::Answer(a.id.clone()),
            "answer ahead of its first record"
        );
        assert_eq!(
            kinds.iter().filter(|k| matches!(k, LineKind::Answer(_))).count(),
            1
        );
        assert_eq!(kinds.len(), 4);
        // A restarted process never appends to an old segment.
        let mut s2 = Spool::open(&env, Arc::default());
        let e4 = entry(4, Class::Bulk, now, Some(Arc::clone(&a)), 0);
        s2.append(Class::Bulk, &[&e4], &env, &limits(), &hdr()).unwrap();
        assert_eq!(s2.keys().len(), 2);
        let newest = s2.keys().last().copied().unwrap();
        assert!(newest.n > k.n);
        let c2 = read_segment(&s2.segs[&newest].path, MAX_SEGMENT_RAW).unwrap();
        assert!(
            matches!(c2.lines[0].kind, LineKind::Answer(_)),
            "each segment stands alone"
        );
    }

    #[test]
    fn data_dir_cap_evicts_oldest_bulk_first_and_counts() {
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let dropped = Arc::new(DropCounters::default());
        let mut s = Spool::open(&env, Arc::clone(&dropped));
        let mut lim = limits();
        lim.data_max = 1_500_000;
        let now = Timestamp::now();
        let mut seq = 0;
        let mut fill = |s: &mut Spool, class: Class, n: usize| {
            for _ in 0..n {
                let es: Vec<Entry> = (0..100)
                    .map(|_| {
                        seq += 1;
                        entry(seq, class, now, None, 4096)
                    })
                    .collect();
                let refs: Vec<&Entry> = es.iter().collect();
                s.append(class, &refs, &env, &lim, &hdr()).unwrap();
            }
        };
        fill(&mut s, Class::Security, 3); // ~1.2 MiB of incompressible security records
        fill(&mut s, Class::Bulk, 6);
        assert!(s.bytes() <= lim.data_max, "{} > {}", s.bytes(), lim.data_max);
        let classes: Vec<Class> = s.keys().iter().map(|k| k.class).collect();
        assert!(
            classes.contains(&Class::Security),
            "security kept while bulk can go: {classes:?}"
        );
        assert!(dropped.snapshot()["evicted"] > 0);
        assert!(env.evicting.lock().unwrap().contains(&(Loc::DataDir, true)));
        // Draining everything relaxes the condition.
        while let Some((k, _)) = s.oldest() {
            s.finish(k, &env, &lim);
        }
        assert_eq!(env.evicting.lock().unwrap().last(), Some(&(Loc::DataDir, false)));
    }

    #[test]
    fn ssd_floor_eviction_adds_freed_space_once() {
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let ssd = d.path().join("ssd/spool");
        *env.ssd.lock().unwrap() = Some(ssd.clone());
        *env.space.lock().unwrap() = Some(SsdSpace {
            avail: 100 << 30,
            floor: 1 << 30,
        });
        let dropped = Arc::new(DropCounters::default());
        let mut s = Spool::open(&env, Arc::clone(&dropped));
        let now = Timestamp::now();
        let mut seq = 0;
        for _ in 0..12 {
            let es: Vec<Entry> = (0..60)
                .map(|_| {
                    seq += 1;
                    entry(seq, Class::Bulk, now, None, 4096)
                })
                .collect();
            let refs: Vec<&Entry> = es.iter().collect();
            s.append(Class::Bulk, &refs, &env, &limits(), &hdr()).unwrap();
        }
        let segs_before: Vec<SegKey> = s.keys();
        assert!(segs_before.iter().all(|k| k.loc == Loc::Ssd));
        let alloc_first = s.segs[&segs_before[0]].alloc;
        assert!(segs_before.len() >= 2);
        // The drive is now just short of the floor: one eviction's freed space is enough. A
        // second, double-counting pass would evict more than one segment.
        let next = entry(9_999, Class::Bulk, now, None, 0);
        *env.space.lock().unwrap() = Some(SsdSpace {
            avail: (1 << 30) + 10,
            floor: 1 << 30,
        });
        // The member for one tiny record is < alloc_first, so freeing the oldest segment is enough.
        assert!(alloc_first > 4096);
        s.append(Class::Bulk, &[&next], &env, &limits(), &hdr()).unwrap();
        let after = s.keys();
        assert_eq!(
            segs_before.iter().filter(|k| !after.contains(k)).count(),
            1,
            "exactly one segment evicted"
        );
        assert!(!after.contains(&segs_before[0]), "the oldest went");
        // An SSD too full even when empty sends the write to data_dir.
        *env.space.lock().unwrap() = Some(SsdSpace {
            avail: 0,
            floor: 1 << 30,
        });
        let more = entry(10_000, Class::Security, now, None, 0);
        s.append(Class::Security, &[&more], &env, &limits(), &hdr())
            .unwrap();
        assert!(
            s.keys()
                .iter()
                .any(|k| k.loc == Loc::DataDir && k.class == Class::Security)
        );
    }

    #[test]
    fn failed_ssd_write_goes_to_data_dir_and_triggers_a_check() {
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        // An SSD root that can't be created (a file in the way).
        std::fs::write(d.path().join("ssdfile"), b"x").unwrap();
        *env.ssd.lock().unwrap() = Some(d.path().join("ssdfile/spool"));
        *env.space.lock().unwrap() = Some(SsdSpace {
            avail: 100 << 30,
            floor: 1 << 30,
        });
        let mut s = Spool::open(&env, Arc::default());
        let e = entry(1, Class::Security, Timestamp::now(), None, 0);
        s.append(Class::Security, &[&e], &env, &limits(), &hdr()).unwrap();
        assert!(*env.ssd_failures.lock().unwrap() >= 1);
        assert!(s.keys().iter().all(|k| k.loc == Loc::DataDir));
    }

    #[test]
    fn retention_waits_for_a_synced_clock_and_covers_open_segments() {
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let dropped = Arc::new(DropCounters::default());
        let mut s = Spool::open(&env, Arc::clone(&dropped));
        let old = Timestamp::now() - jiff::SignedDuration::from_hours(80);
        let e = entry(1, Class::Bulk, old, None, 0);
        s.append(Class::Bulk, &[&e], &env, &limits(), &hdr()).unwrap();
        assert!(s.segs.values().next().unwrap().open);
        env.synced.store(false, Ordering::Relaxed);
        s.expire(Timestamp::now(), &env, &limits());
        assert_eq!(s.keys().len(), 1, "no age decision on an unsynchronised clock");
        env.synced.store(true, Ordering::Relaxed);
        s.expire(Timestamp::now(), &env, &limits());
        assert!(s.is_empty(), "the open segment is covered too");
        assert_eq!(dropped.snapshot()["too_old"], 1);
    }

    #[test]
    fn evicting_a_partly_drained_segment_counts_only_its_unshipped_records() {
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let dropped = Arc::new(DropCounters::default());
        let mut s = Spool::open(&env, Arc::clone(&dropped));
        let now = Timestamp::now();
        let es: Vec<Entry> = (0..10).map(|i| entry(i, Class::Bulk, now, None, 0)).collect();
        let refs: Vec<&Entry> = es.iter().collect();
        s.append(Class::Bulk, &refs, &env, &limits(), &hdr()).unwrap();
        let (key, _) = s.oldest().unwrap();
        s.set_unshipped(key, 4);
        assert_eq!(s.segs[&key].unshipped, None, "an open segment may still grow");
        s.seal(key);
        s.set_unshipped(key, 4);
        s.delete(key, &env, DropReason::Evicted).unwrap();
        assert_eq!(
            dropped.snapshot()["evicted"],
            4,
            "the six records core already acked aren't counted as dropped"
        );
    }

    #[test]
    fn torn_segment_is_read_up_to_the_damage() {
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let mut s = Spool::open(&env, Arc::default());
        let now = Timestamp::now();
        let e1 = entry(1, Class::Bulk, now, None, 0);
        s.append(Class::Bulk, &[&e1], &env, &limits(), &hdr()).unwrap();
        let (_, path) = s.oldest().unwrap();
        // Simulate a crash mid-append: half a second member.
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"{\"t\":\"q\",\"seq\":2}\n").unwrap();
        let m = enc.finish().unwrap();
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&m[..m.len() / 2]).unwrap();
        drop(f);
        let c = read_segment(&path, MAX_SEGMENT_RAW).unwrap();
        assert!(c.corrupt);
        assert_eq!(c.lines.len(), 1);
    }

    /// The `seq` of every record line in a segment, in file order.
    fn record_seqs(c: &SegContent) -> Vec<u64> {
        c.lines
            .iter()
            .filter(|l| matches!(l.kind, LineKind::Record { .. }))
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(&l.text).unwrap()["seq"]
                    .as_u64()
                    .unwrap()
            })
            .collect()
    }

    /// Every indexed segment read back in key order: (all record seqs, any segment corrupt).
    fn read_all(s: &Spool) -> (Vec<u64>, bool) {
        let mut seqs = vec![];
        let mut corrupt = false;
        for k in s.keys() {
            let c = read_segment(&s.segs[&k].path, MAX_SEGMENT_RAW).unwrap();
            corrupt |= c.corrupt;
            seqs.extend(record_seqs(&c));
        }
        (seqs, corrupt)
    }

    fn gz(text: &str) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(text.as_bytes()).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn a_failed_append_is_cut_back_and_later_appends_never_land_behind_it() {
        // edge.md §11, edge-unifi.md §1 (no spool record is lost): a torn member left by a failed
        // append must never hide records appended (and reported spooled) after it.
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let mut s = Spool::open(&env, Arc::default());
        let now = Timestamp::now();
        let a = entry(1, Class::Security, now, None, 0);
        s.append(Class::Security, &[&a], &env, &limits(), &hdr()).unwrap();
        // The disk fills mid-append: only 10 bytes of B's member reach the file.
        s.write_fault = Some(10);
        let b = entry(2, Class::Security, now, None, 0);
        assert!(s.append(Class::Security, &[&b], &env, &limits(), &hdr()).is_err());
        // The shipper keeps B buffered and writes it again with C once there is room.
        let c = entry(3, Class::Security, now, None, 0);
        s.append(Class::Security, &[&b, &c], &env, &limits(), &hdr())
            .unwrap();
        let (seqs, corrupt) = read_all(&s);
        assert!(!corrupt, "no segment ends in a torn member");
        assert_eq!(seqs, vec![1, 2, 3], "every record reported spooled reads back");
    }

    #[test]
    fn writes_moving_between_locations_keep_segment_order_without_extra_segments() {
        // edge.md §11 (keeping order), hard rule 8 (eMMC writes): an SSD at its floor leaves an
        // empty segment open there while data_dir takes the writes; that must neither start a
        // new data_dir segment per append nor later take records that sort before data_dir's.
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        *env.ssd.lock().unwrap() = Some(d.path().join("ssd/spool"));
        *env.space.lock().unwrap() = Some(SsdSpace {
            avail: 0,
            floor: 1 << 30,
        });
        let mut s = Spool::open(&env, Arc::default());
        let now = Timestamp::now();
        let mut seq = 0;
        let mut add = |s: &mut Spool| {
            seq += 1;
            let e = entry(seq, Class::Security, now, None, 0);
            s.append(Class::Security, &[&e], &env, &limits(), &hdr()).unwrap();
        };
        for _ in 0..3 {
            add(&mut s);
        }
        let used = |s: &Spool, loc| s.segs.iter().filter(|(k, m)| k.loc == loc && m.len > 0).count();
        assert_eq!(
            used(&s, Loc::DataDir),
            1,
            "one data_dir segment, not one per append"
        );
        assert_eq!(used(&s, Loc::Ssd), 0);
        assert!(s.segs.len() <= 2, "{:?}", s.keys());
        // data_dir's segment rotates; the next one is numbered after the SSD's empty one.
        let first = *s.keys().iter().find(|k| k.loc == Loc::DataDir).unwrap();
        s.seal(first);
        add(&mut s);
        // The SSD has room again: its records go after data_dir's.
        *env.space.lock().unwrap() = Some(SsdSpace {
            avail: 100 << 30,
            floor: 1 << 30,
        });
        add(&mut s);
        assert_eq!(used(&s, Loc::Ssd), 1);
        // Back to data_dir (the SSD failed its checks), then the SSD again.
        *env.ssd.lock().unwrap() = None;
        add(&mut s);
        *env.ssd.lock().unwrap() = Some(d.path().join("ssd/spool"));
        add(&mut s);
        let (seqs, corrupt) = read_all(&s);
        assert!(!corrupt);
        assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6, 7], "segment order is record order");
    }

    #[test]
    fn a_newly_passing_ssd_never_reopens_an_earlier_runs_segment() {
        // edge-unifi.md §1: the drive may pass its checks while the shipper is busy, before the
        // spool re-indexes it. A new segment must never be an earlier run's file (which may end in
        // a member torn by a crash).
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let ssd = d.path().join("ssd/spool");
        std::fs::create_dir_all(ssd.join("security")).unwrap();
        let mut old = gz(
            "{\"t\":\"event\",\"ts\":\"2026-11-21T10:00:00.000000Z\",\"boot\":\"old\",\"seq\":1,\"kind\":\"x\"}\n",
        );
        let torn = gz(
            "{\"t\":\"event\",\"ts\":\"2026-11-21T10:00:01.000000Z\",\"boot\":\"old\",\"seq\":2,\"kind\":\"x\"}\n",
        );
        old.extend_from_slice(&torn[..torn.len() / 2]);
        std::fs::write(ssd.join("security/1.jsonl.gz"), &old).unwrap();
        *env.space.lock().unwrap() = Some(SsdSpace {
            avail: 100 << 30,
            floor: 1 << 30,
        });
        // This run starts before the SSD passes.
        let mut s = Spool::open(&env, Arc::default());
        *env.ssd.lock().unwrap() = Some(ssd.clone());
        let e = entry(7, Class::Security, Timestamp::now(), None, 0);
        s.append(Class::Security, &[&e], &env, &limits(), &hdr()).unwrap();
        assert_eq!(
            std::fs::read(ssd.join("security/1.jsonl.gz")).unwrap(),
            old,
            "the earlier run's segment is untouched"
        );
        let mine: Vec<SegKey> = s
            .keys()
            .into_iter()
            .filter(|k| {
                let c = read_segment(&s.segs[k].path, MAX_SEGMENT_RAW).unwrap();
                record_seqs(&c).contains(&7)
            })
            .collect();
        assert_eq!(mine.len(), 1);
        assert!(mine[0].n > 1, "numbered after the earlier run's segments");
        let c = read_segment(&s.segs[&mine[0]].path, MAX_SEGMENT_RAW).unwrap();
        assert!(!c.corrupt);
        assert_eq!(record_seqs(&c), vec![7]);
    }

    #[test]
    fn a_highly_compressible_segment_always_reads_back_whole() {
        // edge.md §11 (at-least-once): what the writer puts in a segment, the reader reads back in
        // full, however well the records compress.
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let mut s = Spool::open(&env, Arc::default());
        let now = Timestamp::now();
        let pad = "a".repeat(8 << 10);
        let total = (MAX_SEGMENT_RAW as usize) / (8 << 10) + 500;
        let mut seq = 0u64;
        while (seq as usize) < total {
            let es: Vec<Entry> = (0..500)
                .map(|_| {
                    seq += 1;
                    let mut e = entry(seq, Class::Bulk, now, None, 0);
                    e.line = format!(
                        r#"{{"t":"q","ts":"{}","boot":"b","seq":{seq},"pad":"{pad}"}}"#,
                        picket_api::time::format_micros(&now)
                    )
                    .into_boxed_str();
                    e
                })
                .collect();
            let refs: Vec<&Entry> = es.iter().collect();
            s.append(Class::Bulk, &refs, &env, &limits(), &hdr()).unwrap();
        }
        let (seqs, corrupt) = read_all(&s);
        assert!(!corrupt, "no segment is cut short by the reader's limit");
        assert_eq!(seqs.len(), seq as usize);
    }

    #[test]
    fn data_dir_always_keeps_its_free_space_floor() {
        // Hard rule 8, README §2 range checks: whatever cap core sets, the eMMC spool never
        // takes the space UniFi OS needs; the oldest bulk goes first, then nothing more is
        // written.
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let dropped = Arc::new(DropCounters::default());
        let mut s = Spool::open(&env, Arc::clone(&dropped));
        let mut lim = limits();
        lim.data_max = 1 << 40;
        let now = Timestamp::now();
        let es: Vec<Entry> = (0..50).map(|i| entry(i, Class::Bulk, now, None, 4096)).collect();
        let refs: Vec<&Entry> = es.iter().collect();
        s.append(Class::Bulk, &refs, &env, &lim, &hdr()).unwrap();
        let bulk = s.keys()[0];
        // The filesystem is now down to its floor.
        *env.data_space.lock().unwrap() = Some(SsdSpace {
            avail: (1 << 30) + 100,
            floor: 1 << 30,
        });
        let e = entry(100, Class::Security, now, None, 4096);
        s.append(Class::Security, &[&e], &env, &lim, &hdr()).unwrap();
        assert!(!s.keys().contains(&bulk), "the bulk segment made room");
        assert!(dropped.snapshot()["evicted"] > 0);
        assert!(env.evicting.lock().unwrap().contains(&(Loc::DataDir, true)));
        // An empty spool on a filesystem below its floor writes nothing.
        *env.data_space.lock().unwrap() = Some(SsdSpace {
            avail: 0,
            floor: 1 << 30,
        });
        let mut s2 = Spool::open(&env, Arc::default());
        for k in s2.keys() {
            s2.finish(k, &env, &lim);
        }
        let e3 = entry(102, Class::Security, now, None, 0);
        assert!(
            s2.append(Class::Security, &[&e3], &env, &lim, &hdr()).is_err(),
            "an empty spool still can't write below the floor"
        );
    }

    #[test]
    fn segment_numbers_grow_across_runs_and_locations() {
        // edge.md §11 (drain oldest first): numbers are reserved in data_dir, so a run that
        // can't see the SSD still numbers after the segments an earlier run put there.
        let d = tempfile::tempdir().unwrap();
        let env = FakeEnv::new(d.path());
        let ssd = d.path().join("ssd/spool");
        *env.ssd.lock().unwrap() = Some(ssd.clone());
        *env.space.lock().unwrap() = Some(SsdSpace {
            avail: 100 << 30,
            floor: 1 << 30,
        });
        let now = Timestamp::now();
        let mut s = Spool::open(&env, Arc::default());
        let e = entry(1, Class::Security, now, None, 0);
        s.append(Class::Security, &[&e], &env, &limits(), &hdr()).unwrap();
        let on_ssd = s.keys()[0];
        assert_eq!(on_ssd.loc, Loc::Ssd);
        // Next run: no SSD at all.
        let env2 = FakeEnv::new(d.path());
        let mut s2 = Spool::open(&env2, Arc::default());
        s2.append(Class::Security, &[&e], &env2, &limits(), &hdr())
            .unwrap();
        let on_data = s2.keys()[0];
        assert!(on_data.n > on_ssd.n, "{on_data:?} after {on_ssd:?}");
        // A run that sees the SSD's names (not passing yet) numbers after them too, even
        // without the reservation file.
        std::fs::remove_file(d.path().join("data/spool").join(NEXT_FILE)).unwrap();
        std::fs::create_dir_all(ssd.join("bulk")).unwrap();
        std::fs::write(ssd.join("bulk/5000.jsonl.gz"), b"").unwrap();
        let env3 = FakeEnv::new(d.path());
        *env3.ssd_root.lock().unwrap() = Some(ssd.clone());
        let mut s3 = Spool::open(&env3, Arc::default());
        s3.append(Class::Bulk, &[&e], &env3, &limits(), &hdr()).unwrap();
        assert!(s3.keys().iter().all(|k| k.loc == Loc::DataDir));
        assert!(s3.keys().iter().any(|k| k.class == Class::Bulk && k.n > 5000));
    }

    #[test]
    fn transient_read_error_is_an_error_not_corruption() {
        let d = tempfile::tempdir().unwrap();
        // A directory where a segment should be: reading fails with an OS error (EISDIR).
        let p = d.path().join("7.jsonl.gz");
        std::fs::create_dir(&p).unwrap();
        let r = read_segment(&p, MAX_SEGMENT_RAW);
        assert!(
            r.is_err(),
            "an OS error must surface, never read as an empty/corrupt segment"
        );
        // Missing file (unmounted drive) likewise.
        assert!(read_segment(&d.path().join("8.jsonl.gz"), MAX_SEGMENT_RAW).is_err());
    }
}
