//! Storage locations and the SSD (edge-unifi.md §1).
//!
//! The SSD is checked before anything is written there: at start, every minute, and within a
//! second of any mount change (`/proc/self/mountinfo`, polled each second). All must hold:
//! 1. the host's mount table (`/proc/1/mountinfo`) and the edge's own show the same filesystem
//!    (major:minor) at `ssd_dir`'s parent, and it isn't `data_dir`'s (`unmounted`,
//!    `stale_mount`); a table that can't be read fails as `unmounted`;
//! 2. the marker `<ssd_dir>/.picket-ssd` matches `<data_dir>/ssd-id` (`no_marker`, `foreign`);
//! 3. `bundles/`, `spool/` and `verdicts/` there are writable (`not_writable`);
//! 4. at least max(1 GiB, 1 %) of the drive is free to `picket` (`f_bavail`), counting Picket's
//!    own files there as free (`low_space`).
//!
//! A failure holds `ssd_unavailable` with the reason. The service tells the spool and the bundle
//! and verdict-set code ([`crate::bundles::store`]) where their files go, including the first 10
//! minutes after start, while the SSD hasn't passed yet, when hot bundle files stay in memory only.
//! The edge never holds a file open on the SSD between uses.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::sync::{Notify, watch};

use picket_api::session::{Disk, DiskUse, condition_kind};

use crate::clock::Clock;
use crate::conditions::Conditions;
use crate::fsutil;
use crate::logs::spool::{Loc, SpoolDirs, SpoolEnv, SsdSpace};
use crate::paths::{DataLayout, HostPlatform, SsdLayout};

/// How long after start the SSD may take to pass before hot bundle files go to an eMMC copy.
pub const START_WINDOW: Duration = Duration::from_secs(600);
const GIB: u64 = 1 << 30;

/// Why the SSD fails its checks (api.md §3 `ssd_unavailable` detail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsdFailure {
    Unmounted,
    StaleMount,
    NoMarker,
    Foreign,
    NotWritable,
    LowSpace,
}

impl SsdFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unmounted => "unmounted",
            Self::StaleMount => "stale_mount",
            Self::NoMarker => "no_marker",
            Self::Foreign => "foreign",
            Self::NotWritable => "not_writable",
            Self::LowSpace => "low_space",
        }
    }
}

/// The SSD's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsdState {
    /// No `ssd_dir` in `edge.json`.
    NotConfigured,
    /// Not checked yet.
    Unknown,
    Passing,
    Failing(SsdFailure),
}

/// Where bundle files go now (edge-unifi.md §1 Bundles).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundlesLocation {
    /// `<ssd_dir>/bundles` (the SSD passes its checks).
    Ssd(PathBuf),
    /// The first 10 minutes after start while the SSD hasn't passed: hot files and activations
    /// stay in memory only; cold page files and verdict sets wait.
    MemoryOnly,
    /// `<data_dir>/bundles`: the eMMC copy of hot parts during an SSD failure, or their only
    /// place without `ssd_dir` (on Debian, cold parts too: `data_dir` counts as an SSD).
    DataDir(PathBuf),
}

/// The SSD checks' stand-in (tests: a drive that mounts late without a second filesystem).
pub type SsdCheckFn = Arc<dyn Fn() -> Result<(), SsdFailure> + Send + Sync>;

/// Knobs tests set.
#[derive(Clone)]
pub struct StorageTuning {
    /// How long after start the SSD may take to pass before hot files go to an eMMC copy.
    pub start_window: Duration,
    /// Replaces the four checks when set.
    pub ssd_check: Option<SsdCheckFn>,
}

impl Default for StorageTuning {
    fn default() -> Self {
        Self {
            start_window: START_WINDOW,
            ssd_check: None,
        }
    }
}

/// Paths of the mount tables (injectable for tests).
#[derive(Clone, Debug)]
pub struct MountTables {
    pub host: PathBuf,
    pub own: PathBuf,
}

impl Default for MountTables {
    fn default() -> Self {
        Self {
            host: PathBuf::from("/proc/1/mountinfo"),
            own: PathBuf::from("/proc/self/mountinfo"),
        }
    }
}

/// The four SSD checks.
#[derive(Clone, Debug)]
pub struct SsdChecker {
    pub ssd: SsdLayout,
    pub data: DataLayout,
    pub mounts: MountTables,
}

/// One mount table entry we care about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    pub dev: String,
    pub mount_point: PathBuf,
}

/// Parses `/proc/<pid>/mountinfo`: `id parent major:minor root mount-point options … - fstype …`.
pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            Some(MountEntry {
                dev: (*f.get(2)?).to_owned(),
                mount_point: PathBuf::from(unescape_octal(f.get(4)?)),
            })
        })
        .collect()
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`, the octal value of one byte
/// (`\000` to `\377`). Anything else, such as `\444`, is kept as written (untrusted input:
/// README §2).
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if let [b'\\', o1 @ b'0'..=b'3', o2 @ b'0'..=b'7', o3 @ b'0'..=b'7', ..] = b[i..] {
            out.push((o1 - b'0') * 64 + (o2 - b'0') * 8 + (o3 - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The device of the last mount at `point` (later mounts stack over earlier ones).
fn mount_at(table: &[MountEntry], point: &Path) -> Option<String> {
    table
        .iter()
        .rev()
        .find(|e| e.mount_point == point)
        .map(|e| e.dev.clone())
}

impl SsdChecker {
    /// Runs all four checks. `own_bytes` is the size of Picket's files on the SSD.
    pub fn check(&self, own_bytes: u64) -> Result<(), SsdFailure> {
        let parent = self.ssd.root.parent().ok_or(SsdFailure::Unmounted)?;
        // 1. Same filesystem in the host's and the unit's mount tables, not data_dir's.
        let own = fsutil::read_bounded(&self.mounts.own, 4 << 20)
            .map(|b| parse_mountinfo(&String::from_utf8_lossy(&b)))
            .map_err(|_| SsdFailure::Unmounted)?;
        // Both tables must agree. One the edge can't read can't show the drive is (still)
        // mounted, so it fails as `unmounted`: the unit's own table alone can be a stale
        // namespace that keeps passing after UniFi changed or removed the host mount.
        let host = fsutil::read_bounded(&self.mounts.host, 4 << 20)
            .map(|b| parse_mountinfo(&String::from_utf8_lossy(&b)))
            .map_err(|_| SsdFailure::Unmounted)?;
        let own_dev = mount_at(&own, parent);
        let Some(host_dev) = mount_at(&host, parent) else {
            return Err(SsdFailure::Unmounted);
        };
        if own_dev.as_deref() != Some(host_dev.as_str()) {
            return Err(SsdFailure::StaleMount);
        }
        let parent_dev = std::fs::metadata(parent)
            .map_err(|_| SsdFailure::Unmounted)?
            .dev();
        let data_dev = std::fs::metadata(&self.data.root).map(|m| m.dev()).ok();
        if data_dev == Some(parent_dev) {
            return Err(SsdFailure::Unmounted);
        }
        // 2. The marker.
        let marker = match fsutil::read_nofollow_bounded(&self.ssd.marker(), 256) {
            Ok(b) => String::from_utf8_lossy(&b).trim().to_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(SsdFailure::NoMarker),
            Err(_) => return Err(SsdFailure::NotWritable),
        };
        if marker.is_empty() {
            return Err(SsdFailure::NoMarker);
        }
        let local = fsutil::read_nofollow_bounded(&self.data.ssd_id(), 256)
            .map(|b| String::from_utf8_lossy(&b).trim().to_owned())
            .unwrap_or_default();
        if local != marker {
            return Err(SsdFailure::Foreign);
        }
        // 3. Writable directories (access(2) also reports a read-only mount).
        for dir in [
            self.ssd.bundles_dir(),
            self.ssd.spool_dir(),
            self.ssd.verdicts_dir(),
        ] {
            let ok = std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir())
                && rustix::fs::access(&dir, rustix::fs::Access::WRITE_OK).is_ok();
            if !ok {
                return Err(SsdFailure::NotWritable);
            }
        }
        // 4. Free space, Picket's own files counted as free.
        let (avail, floor) = ssd_space(&self.ssd.root).ok_or(SsdFailure::NotWritable)?;
        if avail.saturating_add(own_bytes) < floor {
            return Err(SsdFailure::LowSpace);
        }
        Ok(())
    }
}

/// (`f_bavail × f_frsize`, max(1 GiB, 1 % of the drive)) for the filesystem holding `path`: the
/// SSD check's floor, which the spool also leaves free on `data_dir`.
pub fn ssd_space(path: &Path) -> Option<(u64, u64)> {
    let s = rustix::fs::statvfs(path).ok()?;
    let avail = s.f_bavail.saturating_mul(s.f_frsize);
    let total = s.f_blocks.saturating_mul(s.f_frsize);
    Some((avail, GIB.max(total / 100)))
}

/// `f_bavail × f_frsize` for `path` (heartbeat `disk.*.free`).
pub fn free_bytes(path: &Path) -> Option<u64> {
    rustix::fs::statvfs(path)
        .ok()
        .map(|s| s.f_bavail.saturating_mul(s.f_frsize))
}

/// Picket's disk use per location: running totals, recounted at start (api.md §3 `disk`).
#[derive(Default)]
pub struct DiskUsage {
    pub data_dir: AtomicU64,
    pub ssd_dir: AtomicU64,
    /// Set once the first recount finished (before it, `used` is null).
    pub counted: std::sync::atomic::AtomicBool,
}

impl DiskUsage {
    pub fn add(&self, loc: Loc, delta: i64) {
        let c = match loc {
            Loc::DataDir => &self.data_dir,
            Loc::Ssd => &self.ssd_dir,
        };
        let _ = c.try_update(Relaxed, Relaxed, |v| Some(v.saturating_add_signed(delta)));
    }

    pub fn get(&self, loc: Loc) -> u64 {
        match loc {
            Loc::DataDir => self.data_dir.load(Relaxed),
            Loc::Ssd => self.ssd_dir.load(Relaxed),
        }
    }
}

/// Sums the allocated size of the files under `roots` (bounded walk, no symlinks followed).
pub fn count_bytes(roots: &[PathBuf]) -> u64 {
    let mut total = 0u64;
    let mut stack: Vec<(PathBuf, u32)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    let mut seen = 0usize;
    while let Some((p, depth)) = stack.pop() {
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        seen += 1;
        if seen > 2_000_000 {
            break;
        }
        if m.is_file() {
            total = total.saturating_add(fsutil::allocated_bytes(&m));
        } else if m.is_dir()
            && depth < 12
            && let Ok(rd) = std::fs::read_dir(&p)
        {
            for e in rd.flatten() {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    total
}

/// The storage service: SSD state, locations, disk use.
pub struct Storage {
    pub platform: HostPlatform,
    pub data: DataLayout,
    pub ssd: Option<SsdLayout>,
    checker: Option<SsdChecker>,
    started: Instant,
    state: watch::Sender<SsdState>,
    recheck: Notify,
    conditions: Arc<Conditions>,
    pub disk: DiskUsage,
    clock: Arc<Clock>,
    last_check: ArcSwap<Option<Instant>>,
    /// The SSD has passed its checks at least once since start.
    ever_passed: std::sync::atomic::AtomicBool,
    start_window: std::sync::Mutex<Duration>,
    check_override: std::sync::Mutex<Option<SsdCheckFn>>,
}

impl Storage {
    pub fn new(
        platform: HostPlatform,
        data: DataLayout,
        ssd_dir: Option<PathBuf>,
        mounts: MountTables,
        conditions: Arc<Conditions>,
        clock: Arc<Clock>,
    ) -> Arc<Self> {
        let ssd = ssd_dir.map(|root| SsdLayout { root });
        let checker = ssd.clone().map(|ssd| SsdChecker {
            ssd,
            data: data.clone(),
            mounts,
        });
        let initial = if checker.is_some() {
            SsdState::Unknown
        } else {
            SsdState::NotConfigured
        };
        Arc::new(Self {
            platform,
            data,
            ssd,
            checker,
            started: Instant::now(),
            state: watch::channel(initial).0,
            recheck: Notify::new(),
            conditions,
            disk: DiskUsage::default(),
            clock,
            last_check: ArcSwap::from_pointee(None),
            ever_passed: std::sync::atomic::AtomicBool::new(false),
            start_window: std::sync::Mutex::new(START_WINDOW),
            check_override: std::sync::Mutex::new(None),
        })
    }

    /// Applies test knobs.
    pub fn tune(&self, t: &StorageTuning) {
        *self.start_window.lock().unwrap_or_else(|p| p.into_inner()) = t.start_window;
        *self.check_override.lock().unwrap_or_else(|p| p.into_inner()) = t.ssd_check.clone();
    }

    pub fn ssd_state(&self) -> SsdState {
        *self.state.borrow()
    }

    pub fn ssd_passing(&self) -> bool {
        self.ssd_state() == SsdState::Passing
    }

    /// Changes in the SSD's state.
    pub fn subscribe(&self) -> watch::Receiver<SsdState> {
        self.state.subscribe()
    }

    /// The first 10 minutes after start, while the SSD hasn't passed its checks yet. Once it
    /// has, a later failure is a failure, window or not (edge-unifi.md §1: "or fails them
    /// later").
    pub fn in_start_window(&self) -> bool {
        let window = *self.start_window.lock().unwrap_or_else(|p| p.into_inner());
        self.started.elapsed() < window && !self.ever_passed.load(Relaxed)
    }

    /// Asks for a check within a second (a write on the SSD failed).
    pub fn recheck(&self) {
        self.recheck.notify_one();
    }

    /// Where the spool writes new segments.
    pub fn spool_root(&self) -> PathBuf {
        match (&self.ssd, self.ssd_passing()) {
            (Some(s), true) => s.spool_dir(),
            _ => self.data.spool_dir(),
        }
    }

    /// Where bundle files go now.
    pub fn bundles_location(&self) -> BundlesLocation {
        match (&self.ssd, self.ssd_state()) {
            (None, _) => BundlesLocation::DataDir(self.data.bundles_dir()),
            (Some(s), SsdState::Passing) => BundlesLocation::Ssd(s.bundles_dir()),
            (Some(_), _) if self.in_start_window() => BundlesLocation::MemoryOnly,
            (Some(_), _) => BundlesLocation::DataDir(self.data.bundles_dir()),
        }
    }

    /// Where cold page files and verdict sets live, if anywhere usable now: the SSD while it
    /// passes; `data_dir` on Debian without `ssd_dir` (taken to be an SSD, edge-unifi.md §9);
    /// nowhere otherwise (cold lookups go unchecked, lookups skip verdict sets).
    pub fn cold_root(&self) -> Option<PathBuf> {
        match (&self.ssd, self.ssd_state()) {
            (Some(s), SsdState::Passing) => Some(s.root.clone()),
            (Some(_), _) => None,
            (None, _) if self.platform == HostPlatform::Debian => Some(self.data.root.clone()),
            (None, _) => None,
        }
    }

    /// Runs the checks now and publishes the result.
    pub fn check_now(&self) -> SsdState {
        let Some(c) = &self.checker else {
            return SsdState::NotConfigured;
        };
        let stand_in = self
            .check_override
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut result = match &stand_in {
            Some(f) => f(),
            None => c.check(self.disk.get(Loc::Ssd)),
        };
        if result == Err(SsdFailure::LowSpace) && stand_in.is_none() {
            // Picket's own files count as free: make sure that count is current (the drive may
            // have been mounted after start, or the spool grown since the last recount) before
            // failing the drive for space.
            self.recount_ssd();
            result = c.check(self.disk.get(Loc::Ssd));
        }
        let st = match result {
            Ok(()) => SsdState::Passing,
            Err(f) => SsdState::Failing(f),
        };
        self.last_check.store(Arc::new(Some(Instant::now())));
        self.apply(st);
        st
    }

    /// Publishes a check result: the condition, the state, and what follows a change.
    fn apply(&self, st: SsdState) {
        let prev = self.ssd_state();
        if st == SsdState::Passing && prev != st {
            self.ever_passed.store(true, Relaxed);
            if let Some(s) = &self.ssd {
                // Temporary files a crash left on the drive (README §2 Restarts), then Picket's
                // bytes there, which the drive may hold from before it went away.
                for d in [s.bundles_dir(), s.spool_dir(), s.verdicts_dir()] {
                    fsutil::sweep_temp_files_tree(&d, 8);
                }
                self.recount_ssd();
            }
        }
        if prev != st {
            match st {
                SsdState::Failing(f) => {
                    self.conditions
                        .set(condition_kind::SSD_UNAVAILABLE, None, Some(f.as_str().into()))
                }
                _ => self.conditions.clear(condition_kind::SSD_UNAVAILABLE, None),
            }
            self.state.send_replace(st);
        }
    }

    /// Recounts Picket's disk use (at start, then periodically to correct drift).
    pub fn recount(&self) {
        let data = count_bytes(std::slice::from_ref(&self.data.root));
        self.disk.data_dir.store(data, Relaxed);
        self.recount_ssd();
        self.disk.counted.store(true, Relaxed);
    }

    /// Recounts Picket's files on the SSD.
    fn recount_ssd(&self) {
        if let Some(s) = &self.ssd {
            let ssd = count_bytes(&[s.bundles_dir(), s.spool_dir(), s.verdicts_dir(), s.marker()]);
            self.disk.ssd_dir.store(ssd, Relaxed);
        }
    }

    /// The heartbeat's `disk` block.
    pub fn disk_snapshot(&self) -> Disk {
        let counted = self.disk.counted.load(Relaxed);
        Disk {
            data_dir: Some(DiskUse {
                used: counted.then(|| self.disk.get(Loc::DataDir)),
                free: free_bytes(&self.data.root),
            }),
            ssd_dir: self.ssd.as_ref().map(|s| DiskUse {
                used: counted.then(|| self.disk.get(Loc::Ssd)),
                free: if self.ssd_passing() {
                    free_bytes(&s.root)
                } else {
                    None
                },
            }),
        }
    }

    /// Checks at start, every minute, within a second of a mount change and on request; recounts
    /// disk use every 10 minutes.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let me = Arc::clone(&self);
        tokio::task::spawn_blocking(move || {
            me.recount();
            me.check_now();
        })
        .await?;
        if self.checker.is_none() {
            let mut recount = tokio::time::interval(Duration::from_secs(600));
            recount.tick().await;
            loop {
                recount.tick().await;
                let me = Arc::clone(&self);
                tokio::task::spawn_blocking(move || me.recount()).await?;
            }
        }
        let own_table = self
            .checker
            .as_ref()
            .map(|c| c.mounts.own.clone())
            .unwrap_or_default();
        let mut last_table = mount_digest(&own_table);
        let mut poll = tokio::time::interval(Duration::from_secs(1));
        let mut last_full = Instant::now();
        let mut last_recount = Instant::now();
        loop {
            tokio::select! {
                _ = poll.tick() => {}
                _ = self.recheck.notified() => { last_table = None; }
            }
            let digest = mount_digest(&own_table);
            let due = digest != last_table || last_full.elapsed() >= Duration::from_secs(60);
            if due {
                last_table = digest;
                last_full = Instant::now();
                let me = Arc::clone(&self);
                tokio::task::spawn_blocking(move || me.check_now()).await?;
            }
            if last_recount.elapsed() >= Duration::from_secs(600) {
                last_recount = Instant::now();
                let me = Arc::clone(&self);
                tokio::task::spawn_blocking(move || me.recount()).await?;
            }
        }
    }

    pub fn clock(&self) -> &Arc<Clock> {
        &self.clock
    }
}

fn mount_digest(p: &Path) -> Option<blake3::Hash> {
    fsutil::read_bounded(p, 4 << 20).ok().map(|b| blake3::hash(&b))
}

impl SpoolEnv for Storage {
    fn dirs(&self) -> SpoolDirs {
        SpoolDirs {
            data: self.data.spool_dir(),
            ssd: match (&self.ssd, self.ssd_passing()) {
                (Some(s), true) => Some(s.spool_dir()),
                _ => None,
            },
        }
    }

    fn ssd_spool_root(&self) -> Option<PathBuf> {
        self.ssd.as_ref().map(SsdLayout::spool_dir)
    }

    fn ssd_space(&self) -> Option<SsdSpace> {
        let s = self.ssd.as_ref()?;
        let (avail, floor) = ssd_space(&s.root)?;
        Some(SsdSpace { avail, floor })
    }

    /// `data_dir` keeps the SSD check's floor too, max(1 GiB, 1 %), Picket's own files not
    /// counted as free: on UniFi it is the eMMC's `/data`, which UniFi OS shares (hard rule 8),
    /// so no `spool_max_mib` can make the spool fill it.
    fn data_space(&self) -> Option<SsdSpace> {
        let (avail, floor) = ssd_space(&self.data.root)?;
        Some(SsdSpace { avail, floor })
    }

    fn ssd_failed(&self) {
        self.recheck();
    }

    fn clock_synced(&self) -> bool {
        self.clock.synced()
    }

    fn disk_delta(&self, loc: Loc, delta: i64) {
        self.disk.add(loc, delta);
    }

    fn evicting(&self, loc: Loc, on: bool) {
        // One condition; its detail names where the spool evicts (api.md §3).
        let mut wh: Vec<&str> = vec![];
        let cur = self
            .conditions
            .snapshot()
            .into_iter()
            .find(|c| c.kind == condition_kind::SPOOL_EVICTING)
            .and_then(|c| c.detail)
            .and_then(|d| d.as_str().map(str::to_owned))
            .unwrap_or_default();
        for l in [Loc::DataDir, Loc::Ssd] {
            let was = cur.split(',').any(|w| w.trim() == l.as_str());
            if (l == loc && on) || (l != loc && was) {
                wh.push(l.as_str());
            }
        }
        if wh.is_empty() {
            self.conditions.clear(condition_kind::SPOOL_EVICTING, None);
        } else {
            self.conditions
                .set(condition_kind::SPOOL_EVICTING, None, Some(wh.join(",").into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::LogProducer;

    struct Fixture {
        _d: tempfile::TempDir,
        checker: SsdChecker,
    }

    /// A fake SSD: `ssd_parent` is a separate filesystem only if the temp dir and /dev/shm differ;
    /// we fake the mount tables instead and use a data_dir on another device when possible.
    fn fixture() -> Fixture {
        let d = tempfile::tempdir().unwrap();
        let vol = d.path().join("volume1");
        let ssd = vol.join(".picket");
        for sub in ["bundles", "spool", "verdicts"] {
            std::fs::create_dir_all(ssd.join(sub)).unwrap();
        }
        std::fs::write(ssd.join(".picket-ssd"), "abc123\n").unwrap();
        // data_dir on a different device than the temp dir, if /dev/shm is one; else /proc.
        let data_root = PathBuf::from("/proc/self");
        let data = DataLayout::new(data_root);
        let mounts = MountTables {
            host: d.path().join("host-mountinfo"),
            own: d.path().join("own-mountinfo"),
        };
        let line = format!(
            "36 25 259:1 / {} rw,relatime shared:1 - ext4 /dev/nvme0n1 rw\n",
            vol.display()
        );
        std::fs::write(&mounts.host, &line).unwrap();
        std::fs::write(&mounts.own, &line).unwrap();
        let checker = SsdChecker {
            ssd: SsdLayout { root: ssd },
            data,
            mounts,
        };
        Fixture { _d: d, checker }
    }

    /// The marker check reads data_dir/ssd-id; with data_dir at /proc/self we can't write it,
    /// so these tests point the checker at a writable data dir on the same fs and expect
    /// `unmounted` where the device check applies.
    #[test]
    fn mount_table_checks() {
        let f = fixture();
        let c = &f.checker;
        // Not mounted at all on the host or in our namespace.
        let mut c2 = c.clone();
        std::fs::write(&c2.mounts.host, "1 0 8:1 / / rw - ext4 /dev/root rw\n").unwrap();
        std::fs::write(&c2.mounts.own, "1 0 8:1 / / rw - ext4 /dev/root rw\n").unwrap();
        assert_eq!(c2.check(0), Err(SsdFailure::Unmounted));
        // Mounted on the host, but this unit sees something else there: stale.
        let vol = c.ssd.root.parent().unwrap().display().to_string();
        std::fs::write(
            &c2.mounts.host,
            format!("36 25 259:1 / {vol} rw - ext4 /dev/nvme0n1 rw\n"),
        )
        .unwrap();
        std::fs::write(
            &c2.mounts.own,
            format!("36 25 0:55 / {vol} rw - tmpfs tmpfs rw\n"),
        )
        .unwrap();
        assert_eq!(c2.check(0), Err(SsdFailure::StaleMount));
        c2.mounts.own = c2.mounts.host.clone();
        // Same mount everywhere; data_dir (/proc/self) is another fs: past check 1, then the
        // marker check compares with /proc/self/ssd-id, which doesn't exist → foreign.
        assert_eq!(c2.check(0), Err(SsdFailure::Foreign));
        // The host's table can't be read: the unit's own table alone can't show the drive is
        // still mounted on the host (edge-unifi.md §1: both tables must agree).
        let mut c3 = c2.clone();
        c3.mounts.host = c.ssd.root.join("no-such-mountinfo");
        assert_eq!(c3.check(0), Err(SsdFailure::Unmounted));
    }

    #[test]
    fn marker_writability_and_space() {
        let f = fixture();
        let d = tempfile::tempdir().unwrap();
        // A data dir on another filesystem than the SSD fixture: use /dev/shm when it is one.
        let shm = Path::new("/dev/shm");
        let tmp_dev = std::fs::metadata(f.checker.ssd.root.parent().unwrap())
            .unwrap()
            .dev();
        let data_root = if shm.is_dir() && std::fs::metadata(shm).unwrap().dev() != tmp_dev {
            tempfile::tempdir_in(shm).unwrap().keep()
        } else {
            // No second filesystem available: skip the rest (the device check would fail).
            return;
        };
        let mut c = f.checker.clone();
        c.data = DataLayout::new(&data_root);
        std::fs::write(c.data.ssd_id(), "abc123").unwrap();
        assert_eq!(c.check(0), Ok(()));
        std::fs::write(c.data.ssd_id(), "other").unwrap();
        assert_eq!(c.check(0), Err(SsdFailure::Foreign));
        std::fs::write(c.data.ssd_id(), "abc123").unwrap();
        std::fs::remove_file(c.ssd.marker()).unwrap();
        assert_eq!(c.check(0), Err(SsdFailure::NoMarker));
        std::fs::write(c.ssd.marker(), "abc123").unwrap();
        std::fs::remove_dir(c.ssd.verdicts_dir()).unwrap();
        assert_eq!(c.check(0), Err(SsdFailure::NotWritable));
        std::os::unix::fs::symlink(d.path(), c.ssd.verdicts_dir()).unwrap();
        assert_eq!(
            c.check(0),
            Err(SsdFailure::NotWritable),
            "a symlink isn't the directory"
        );
        std::fs::remove_file(c.ssd.verdicts_dir()).unwrap();
        std::fs::create_dir(c.ssd.verdicts_dir()).unwrap();
        assert_eq!(c.check(0), Ok(()));
        let _ = std::fs::remove_dir_all(&data_root);
    }

    #[test]
    fn low_space_counts_own_files_as_free() {
        // The floor is at least 1 GiB; a temp filesystem may have more or less free. Compute
        // the expected answer from statvfs and check own_bytes tips it.
        let f = fixture();
        let (avail, floor) = ssd_space(&f.checker.ssd.root).unwrap();
        let shortfall = floor.saturating_sub(avail);
        let shm = Path::new("/dev/shm");
        let tmp_dev = std::fs::metadata(f.checker.ssd.root.parent().unwrap())
            .unwrap()
            .dev();
        if !(shm.is_dir() && std::fs::metadata(shm).unwrap().dev() != tmp_dev) {
            return;
        }
        let data_root = tempfile::tempdir_in(shm).unwrap().keep();
        let mut c = f.checker.clone();
        c.data = DataLayout::new(&data_root);
        std::fs::write(c.data.ssd_id(), "abc123").unwrap();
        if shortfall > 0 {
            assert_eq!(c.check(0), Err(SsdFailure::LowSpace));
            assert_eq!(c.check(shortfall), Ok(()));
        } else {
            assert_eq!(c.check(0), Ok(()));
        }
        let _ = std::fs::remove_dir_all(&data_root);
    }

    #[test]
    fn mountinfo_parsing() {
        let t = "36 25 259:1 / /volume1 rw,relatime shared:1 - ext4 /dev/nvme0n1 rw\n37 25 0:5 / /with\\040space rw - tmpfs t rw\n";
        let e = parse_mountinfo(t);
        assert_eq!(e[0].dev, "259:1");
        assert_eq!(e[1].mount_point, PathBuf::from("/with space"));
        assert_eq!(mount_at(&e, Path::new("/volume1")).as_deref(), Some("259:1"));
        // fuzz/edge local_files found `\444` overflowing a byte: an escape is one byte's octal
        // value, so a first digit over 3 isn't one and stays as written.
        let e = parse_mountinfo("44 3 z  \\444");
        assert_eq!(e[0].mount_point, PathBuf::from("\\444"));
        assert_eq!(unescape_octal("a\\377\\134\\400\\7\\"), "a\u{fffd}\\\\400\\7\\");
    }

    #[tokio::test]
    async fn locations_follow_ssd_state_and_window() {
        let d = tempfile::tempdir().unwrap();
        let (p, _rx) = LogProducer::new("b".into(), Arc::default());
        let conds = Conditions::new(p);
        let s = Storage::new(
            HostPlatform::Unifi,
            DataLayout::new(d.path().join("var")),
            Some(d.path().join("volume1/.picket")),
            MountTables {
                host: d.path().join("none"),
                own: d.path().join("none"),
            },
            Arc::clone(&conds),
            Clock::fixed(true),
        );
        assert_eq!(s.bundles_location(), BundlesLocation::MemoryOnly);
        assert_eq!(s.spool_root(), d.path().join("var/spool"));
        assert_eq!(s.check_now(), SsdState::Failing(SsdFailure::Unmounted));
        assert!(conds.is_set(condition_kind::SSD_UNAVAILABLE, None));
        assert_eq!(conds.snapshot()[0].detail, Some("unmounted".into()));
        assert_eq!(s.cold_root(), None);
        assert!(s.dirs().ssd.is_none());
        let deb = Storage::new(
            HostPlatform::Debian,
            DataLayout::new(d.path().join("var")),
            None,
            MountTables::default(),
            conds,
            Clock::fixed(true),
        );
        assert_eq!(deb.cold_root(), Some(d.path().join("var")));
        assert_eq!(
            deb.bundles_location(),
            BundlesLocation::DataDir(d.path().join("var/bundles"))
        );
    }

    #[tokio::test]
    async fn a_failure_after_the_ssd_passed_goes_to_the_emmc_copy_at_once() {
        let d = tempfile::tempdir().unwrap();
        let (p, _rx) = LogProducer::new("b".into(), Arc::default());
        let s = Storage::new(
            HostPlatform::Unifi,
            DataLayout::new(d.path().join("var")),
            Some(d.path().join("volume1/.picket")),
            MountTables::default(),
            Conditions::new(p),
            Clock::fixed(true),
        );
        assert_eq!(s.bundles_location(), BundlesLocation::MemoryOnly);
        s.apply(SsdState::Passing);
        assert_eq!(
            s.bundles_location(),
            BundlesLocation::Ssd(d.path().join("volume1/.picket/bundles"))
        );
        // Still inside the first 10 minutes, but the SSD has passed: a later failure means the
        // eMMC copy now, not memory only (edge-unifi.md §1).
        s.apply(SsdState::Failing(SsdFailure::Unmounted));
        assert_eq!(
            s.bundles_location(),
            BundlesLocation::DataDir(d.path().join("var/bundles"))
        );
    }

    #[tokio::test]
    async fn passing_sweeps_temp_files_on_the_ssd_and_recounts_its_bytes() {
        let d = tempfile::tempdir().unwrap();
        let ssd = d.path().join("volume1/.picket");
        let seg_dir = ssd.join("spool/bulk");
        std::fs::create_dir_all(&seg_dir).unwrap();
        std::fs::write(seg_dir.join("7.jsonl.gz"), vec![1u8; 20_000]).unwrap();
        std::fs::write(seg_dir.join(fsutil::tmp_name("8.jsonl.gz")), b"x").unwrap();
        let (p, _rx) = LogProducer::new("b".into(), Arc::default());
        let s = Storage::new(
            HostPlatform::Unifi,
            DataLayout::new(d.path().join("var")),
            Some(ssd),
            MountTables::default(),
            Conditions::new(p),
            Clock::fixed(true),
        );
        assert_eq!(s.disk.get(Loc::Ssd), 0, "counted while the drive was away");
        s.apply(SsdState::Passing);
        assert_eq!(std::fs::read_dir(&seg_dir).unwrap().count(), 1);
        assert!(s.disk.get(Loc::Ssd) >= 20_000);
    }

    #[test]
    fn evicting_condition_tracks_locations() {
        let d = tempfile::tempdir().unwrap();
        let (p, _rx) = LogProducer::new("b".into(), Arc::default());
        let conds = Conditions::new(p);
        let s = Storage::new(
            HostPlatform::Unifi,
            DataLayout::new(d.path()),
            None,
            MountTables::default(),
            Arc::clone(&conds),
            Clock::fixed(true),
        );
        s.evicting(Loc::DataDir, true);
        assert_eq!(conds.snapshot()[0].detail, Some("data_dir".into()));
        s.evicting(Loc::Ssd, true);
        assert_eq!(conds.snapshot()[0].detail, Some("data_dir,ssd_dir".into()));
        s.evicting(Loc::DataDir, false);
        assert_eq!(conds.snapshot()[0].detail, Some("ssd_dir".into()));
        s.evicting(Loc::Ssd, false);
        assert!(conds.snapshot().is_empty());
    }

    #[test]
    fn disk_counting() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a"), vec![1u8; 10_000]).unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/b"), vec![1u8; 10_000]).unwrap();
        assert!(count_bytes(&[d.path().to_path_buf()]) >= 20_000);
        let u = DiskUsage::default();
        u.add(Loc::DataDir, 100);
        u.add(Loc::DataDir, -300);
        assert_eq!(u.get(Loc::DataDir), 0);
    }
}
