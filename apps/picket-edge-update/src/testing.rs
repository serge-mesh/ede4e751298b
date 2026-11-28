//! Test support: a fake [`System`] with a small model of systemd (unit files, enablement links,
//! active states, daemon-reload, `Requires=`/`Wants=` on start, a reboot), injected failures and
//! simulated crashes, plus builders for signed release tarballs.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, Metadata};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::api::UpdateResult;
use crate::fsx::Root;
use crate::install::{InstallOptions, InstallReport, install};
use crate::platform::{Layout, Platform, Purpose, UNIT_DIR, load_settings};
use crate::release::BINARIES;
use crate::system::{CmdOutput, RunError, System};
use crate::units::{self, UPDATE_SERVICE};
use crate::update::{self, Env, RunEnd};

/// The payload of a simulated crash (a power cut at a checkpoint).
#[derive(Debug)]
pub struct Crash(pub String);

/// Which versions of the edge report ready after a (re)start.
#[derive(Clone, Debug)]
pub enum Ready {
    All,
    Except(Vec<String>),
    /// The edge never touches `state.json`.
    Silent,
    /// These versions find the helper speaking another protocol (#69): each start writes
    /// `ready_version: null` (its starts counted), refuses to run and exits; systemd starts it
    /// again every `RestartSec` (5 s), and it never says ready. Other versions report ready.
    Incompatible(Vec<String>),
}

#[derive(Debug)]
pub struct State {
    pub calls: Vec<String>,
    pub clock: Duration,
    pub boot_id: String,
    pub rand: u64,
    pub owners: HashMap<PathBuf, (u32, u32)>,
    /// unit → its enablement links (`<target>.wants/<unit>`, `alias:<name>`).
    pub links: BTreeMap<String, BTreeSet<String>>,
    pub active: BTreeMap<String, String>,
    /// Unit text as of the last daemon-reload (or reboot).
    pub loaded: BTreeMap<String, Vec<u8>>,
    /// Units started with a file newer than their loaded text (a missing daemon-reload).
    pub stale_starts: Vec<String>,
    /// `systemctl` command lines (prefix match) that fail, with how many more times.
    pub fail: Vec<(String, u32)>,
    pub units_out: HashMap<String, Vec<u8>>,
    pub ready: Ready,
    pub data_dir: String,
    pub bin_dir: String,
    pub model: Option<String>,
    pub is_root: bool,
    pub booted: bool,
    pub mountinfo: String,
    /// Crash at the nth (1-based) time this checkpoint is reached.
    pub crash_at: Option<(String, u32)>,
    pub checkpoint_hits: HashMap<String, u32>,
    /// Restarts of an edge refusing to run ([`Ready::Incompatible`]) after its first start.
    pub refused_starts: u32,
    /// Checkpoints that return an error.
    pub fail_checkpoint: BTreeSet<String>,
    pub sysusers_conflict: bool,
    pub runtime_masked: BTreeSet<String>,
    pub arch: String,
    /// At this checkpoint the edge replaces `pending.json` (a new inode) with this content.
    pub replace_pending_at: Option<(String, String)>,
    /// Dropped at the first sleep: a lock holder that exits while the run waits for it.
    pub release_on_sleep: Option<File>,
    /// How long each `start`, `stop`, `restart` or `disable --now` takes, failed or not.
    pub job_cost: Duration,
}

pub struct FakeSystem {
    pub root: PathBuf,
    pub st: RefCell<State>,
}

pub const DEFAULT_MOUNTINFO: &str = "\
22 1 179:2 / / rw,relatime shared:1 - ext4 /dev/root rw
30 22 179:5 / /data rw,noatime shared:2 - ext4 /dev/mmcblk0p5 rw
40 22 259:1 / /volume1 rw,relatime shared:9 - ext4 /dev/nvme0n1p1 rw
";

impl FakeSystem {
    pub fn new(root: &Path, layout: &Layout) -> FakeSystem {
        FakeSystem {
            root: root.to_path_buf(),
            st: RefCell::new(State {
                calls: vec![],
                clock: Duration::ZERO,
                boot_id: "boot-1".into(),
                rand: 0x1000,
                owners: HashMap::new(),
                links: BTreeMap::new(),
                active: BTreeMap::new(),
                loaded: BTreeMap::new(),
                stale_starts: vec![],
                fail: vec![],
                units_out: HashMap::new(),
                ready: Ready::All,
                data_dir: layout.default_data_dir.into(),
                bin_dir: layout.bin_dir.into(),
                model: Some("UniFi Cloud Gateway Fiber".into()),
                is_root: true,
                booted: true,
                mountinfo: DEFAULT_MOUNTINFO.into(),
                crash_at: None,
                checkpoint_hits: HashMap::new(),
                refused_starts: 0,
                fail_checkpoint: BTreeSet::new(),
                sysusers_conflict: false,
                runtime_masked: BTreeSet::new(),
                arch: "x86_64".into(),
                replace_pending_at: None,
                release_on_sleep: None,
                job_cost: Duration::ZERO,
            }),
        }
    }

    fn real(&self, logical: impl AsRef<Path>) -> PathBuf {
        Root::new(&self.root).real(logical)
    }

    fn unit_path(&self, unit: &str) -> PathBuf {
        self.real(Path::new(UNIT_DIR).join(unit))
    }

    /// The unit file: `None` if missing, `Err(target)` for a symlink.
    pub fn unit_file(&self, unit: &str) -> Option<Result<Vec<u8>, PathBuf>> {
        let p = self.unit_path(unit);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => Some(Err(std::fs::read_link(&p).unwrap_or_default())),
            Ok(_) => std::fs::read(&p).ok().map(Ok),
            Err(_) => None,
        }
    }

    fn is_masked(&self, unit: &str) -> bool {
        matches!(self.unit_file(unit), Some(Err(t)) if t == Path::new("/dev/null"))
            || self.st.borrow().runtime_masked.contains(unit)
    }

    fn install_links(unit: &str, text: &[u8]) -> BTreeSet<String> {
        units::install_entries(text)
            .into_iter()
            .flat_map(|(k, v)| {
                v.split_whitespace()
                    .map(|t| match k.as_str() {
                        "WantedBy" => format!("{t}.wants/{unit}"),
                        "RequiredBy" => format!("{t}.requires/{unit}"),
                        "UpheldBy" => format!("{t}.upholds/{unit}"),
                        "Alias" => format!("alias:{t}"),
                        _ => format!("also:{t}"),
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn state(&self, unit: &str) -> String {
        self.st
            .borrow()
            .active
            .get(unit)
            .cloned()
            .unwrap_or_else(|| "inactive".into())
    }

    pub fn set_active(&self, unit: &str, state: &str) {
        self.st.borrow_mut().active.insert(unit.into(), state.into());
    }

    pub fn links(&self, unit: &str) -> BTreeSet<String> {
        self.st.borrow().links.get(unit).cloned().unwrap_or_default()
    }

    pub fn fail(&self, pattern: &str, times: u32) {
        self.st.borrow_mut().fail.push((pattern.into(), times));
    }

    pub fn calls(&self) -> Vec<String> {
        self.st.borrow().calls.clone()
    }

    pub fn clear_calls(&self) {
        self.st.borrow_mut().calls.clear();
    }

    pub fn set_owner(&self, logical: &str, uid: u32, gid: u32) {
        self.st
            .borrow_mut()
            .owners
            .insert(PathBuf::from(logical), (uid, gid));
    }

    pub fn owner_of(&self, logical: &str) -> (u32, u32) {
        self.st
            .borrow()
            .owners
            .get(Path::new(logical))
            .copied()
            .unwrap_or((0, 0))
    }

    fn take_failure(&self, line: &str) -> bool {
        let mut st = self.st.borrow_mut();
        for (pat, times) in st.fail.iter_mut() {
            if *times > 0 && line.starts_with(pat.as_str()) {
                *times -= 1;
                return true;
            }
        }
        false
    }

    fn deps(text: &[u8]) -> Vec<String> {
        units::section_entries(text, "Unit")
            .into_iter()
            .filter(|(k, _)| k == "Requires" || k == "Wants")
            .flat_map(|(_, v)| v.split_whitespace().map(String::from).collect::<Vec<_>>())
            .collect()
    }

    fn start_unit(&self, unit: &str, depth: u32) -> Result<(), String> {
        if self.is_masked(unit) {
            return Err(format!("Unit {unit} is masked."));
        }
        let Some(Ok(text)) = self.unit_file(unit) else {
            if depth > 0 {
                return Ok(());
            }
            return Err(format!("Unit {unit} not found."));
        };
        let loaded = self.st.borrow().loaded.get(unit).cloned();
        let text = match loaded {
            Some(l) => {
                if l != text {
                    self.st.borrow_mut().stale_starts.push(unit.into());
                }
                l
            }
            None => text,
        };
        if depth < 4 {
            for d in Self::deps(&text) {
                if d != unit && !crate::systemd::is_running(&self.state(&d)) {
                    let _ = self.start_unit(&d, depth + 1);
                }
            }
        }
        self.set_active(
            unit,
            if unit.ends_with(".service")
                && !text_has(&text, "RemainAfterExit=yes")
                && text_has(&text, "Type=oneshot")
            {
                "inactive"
            } else {
                "active"
            },
        );
        if unit == units::EDGE {
            self.edge_started();
        }
        Ok(())
    }

    /// What the edge does at start: `ready_version` null, then its version once ready (true).
    fn edge_started(&self) -> bool {
        let (bin, data, ready) = {
            let st = self.st.borrow();
            (st.bin_dir.clone(), st.data_dir.clone(), st.ready.clone())
        };
        let version = std::fs::read_link(self.real(Path::new(&bin).join("current")))
            .ok()
            .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()));
        if matches!(ready, Ready::Silent) {
            return false;
        }
        let ok = match (&ready, &version) {
            (_, None) | (Ready::Silent, _) => false,
            (Ready::All, Some(_)) => true,
            (Ready::Except(v) | Ready::Incompatible(v), Some(ver)) => !v.contains(ver),
        };
        let state = match (ok, version) {
            (true, Some(v)) => format!("{{\"ready_version\": \"{v}\", \"other\": [1, 2]}}"),
            _ => "{\"ready_version\": null}".into(),
        };
        let dir = self.real(&data);
        if dir.is_dir() {
            let _ = std::fs::write(dir.join("state.json"), state);
        }
        ok
    }

    /// A reboot: a new boot ID, every unit reloaded, enabled units (and what they pull in)
    /// active, everything else inactive.
    pub fn reboot(&self) {
        let names: Vec<String> = std::fs::read_dir(self.real(UNIT_DIR))
            .map(|rd| {
                rd.filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        {
            let mut st = self.st.borrow_mut();
            st.boot_id = format!("{}-next", st.boot_id);
            st.active.clear();
            st.loaded.clear();
        }
        for n in &names {
            if let Some(Ok(t)) = self.unit_file(n) {
                self.st.borrow_mut().loaded.insert(n.clone(), t);
            }
        }
        for n in &names {
            if !self.links(n).is_empty() && !self.is_masked(n) {
                let _ = self.start_unit(n, 0);
            }
        }
    }

    /// Reaching a checkpoint: count it, maybe crash or fail.
    fn hit(&self, at: &str) -> io::Result<()> {
        let crash = {
            let mut st = self.st.borrow_mut();
            st.calls.push(format!("checkpoint {at}"));
            let n = {
                let c = st.checkpoint_hits.entry(at.to_string()).or_insert(0);
                *c += 1;
                *c
            };
            if st.fail_checkpoint.contains(at) {
                return Err(io::Error::other(format!("injected failure at {at}")));
            }
            matches!(&st.crash_at, Some((name, nth)) if name == at && *nth == n)
        };
        let replace = {
            let mut st = self.st.borrow_mut();
            match st.replace_pending_at.take() {
                Some((name, content)) if name == at => Some((st.data_dir.clone(), content)),
                other => {
                    st.replace_pending_at = other;
                    None
                }
            }
        };
        if let Some((data, content)) = replace {
            let dir = self.real(Path::new(&data).join("releases"));
            std::fs::write(dir.join("pending.json.new"), content)?;
            std::fs::rename(dir.join("pending.json.new"), dir.join("pending.json"))?;
        }
        if crash {
            self.st.borrow_mut().crash_at = None;
            std::panic::panic_any(Crash(at.to_string()));
        }
        Ok(())
    }
}

fn text_has(text: &[u8], line: &str) -> bool {
    String::from_utf8_lossy(text).lines().any(|l| l.trim() == line)
}

fn out(status: i32, stdout: &str, stderr: &str) -> io::Result<CmdOutput> {
    Ok(CmdOutput {
        status: Some(status),
        stdout: stdout.into(),
        stderr: stderr.into(),
    })
}

impl System for FakeSystem {
    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput> {
        let line = args.join(" ");
        self.st.borrow_mut().calls.push(format!("systemctl {line}"));
        let verb = args.first().copied().unwrap_or("");
        let unit = args.last().copied().unwrap_or("");
        if matches!(verb, "start" | "stop" | "restart") || args.contains(&"--now") {
            let mut st = self.st.borrow_mut();
            let cost = st.job_cost;
            st.clock += cost;
        }
        if self.take_failure(&format!("systemctl {line}")) {
            return out(1, "", "injected failure");
        }
        match verb {
            "daemon-reload" => {
                let names: Vec<String> = std::fs::read_dir(self.real(UNIT_DIR))
                    .map(|rd| {
                        rd.filter_map(|e| e.ok()?.file_name().into_string().ok())
                            .collect()
                    })
                    .unwrap_or_default();
                let mut loaded = BTreeMap::new();
                for n in names {
                    if let Some(Ok(t)) = self.unit_file(&n) {
                        loaded.insert(n, t);
                    }
                }
                self.st.borrow_mut().loaded = loaded;
                out(0, "", "")
            }
            "is-enabled" => {
                if self.st.borrow().runtime_masked.contains(unit) {
                    return out(1, "masked-runtime\n", "");
                }
                match self.unit_file(unit) {
                    None => out(
                        1,
                        "",
                        &format!("Failed to get unit file state for {unit}: No such file or directory"),
                    ),
                    Some(Err(t)) if t == Path::new("/dev/null") => out(1, "masked\n", ""),
                    Some(Err(_)) => out(0, "linked\n", ""),
                    Some(Ok(text)) if !units::has_install_section(&text) => out(0, "static\n", ""),
                    Some(Ok(_)) if !self.links(unit).is_empty() => out(0, "enabled\n", ""),
                    Some(Ok(_)) => out(1, "disabled\n", ""),
                }
            }
            "is-active" => {
                let s = self.state(unit);
                out(if s == "active" { 0 } else { 3 }, &format!("{s}\n"), "")
            }
            "enable" | "reenable" => {
                if self.is_masked(unit) {
                    return out(
                        1,
                        "",
                        &format!("Failed to enable unit: Unit file {unit} is masked."),
                    );
                }
                let Some(Ok(text)) = self.unit_file(unit) else {
                    return out(
                        1,
                        "",
                        &format!("Failed to enable unit: Unit {unit} does not exist"),
                    );
                };
                let links = Self::install_links(unit, &text);
                let mut st = self.st.borrow_mut();
                if links.is_empty() {
                    if verb == "reenable" {
                        st.links.remove(unit);
                    }
                } else {
                    st.links.insert(unit.into(), links);
                }
                out(0, "", "")
            }
            "disable" => {
                self.st.borrow_mut().links.remove(unit);
                if args.contains(&"--now") {
                    self.set_active(unit, "inactive");
                }
                out(0, "", "")
            }
            "start" | "restart" => match self.start_unit(unit, 0) {
                Ok(()) => out(0, "", ""),
                Err(e) => out(5, "", &e),
            },
            "stop" => {
                self.set_active(unit, "inactive");
                out(0, "", "")
            }
            _ => out(1, "", &format!("fake systemctl: unknown verb {verb}")),
        }
    }

    fn sysusers(&self, conf: &Path) -> io::Result<CmdOutput> {
        self.st.borrow_mut().calls.push("systemd-sysusers".into());
        let text = std::fs::read_to_string(conf)?;
        let etc = self.real("/etc");
        std::fs::create_dir_all(&etc)?;
        let mut passwd = std::fs::read_to_string(etc.join("passwd")).unwrap_or_default();
        let mut group = std::fs::read_to_string(etc.join("group")).unwrap_or_default();
        let conflict = self.st.borrow().sysusers_conflict;
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                ["g", name, gid, ..] if !group.lines().any(|l| l.starts_with(&format!("{name}:"))) => {
                    group.push_str(&format!("{name}:x:{gid}:\n"));
                }
                ["u", name, ids, ..] if !passwd.lines().any(|l| l.starts_with(&format!("{name}:"))) => {
                    let (uid, gid) = ids.split_once(':').unwrap_or((ids, ids));
                    let uid = if conflict && *name == "picket" {
                        "1234"
                    } else {
                        uid
                    };
                    passwd.push_str(&format!("{name}:x:{uid}:{gid}::/nonexistent:/usr/sbin/nologin\n"));
                }
                _ => {}
            }
        }
        std::fs::write(etc.join("passwd"), passwd)?;
        std::fs::write(etc.join("group"), group)?;
        out(0, "", "")
    }

    fn analyze_verify(&self, _units: &[PathBuf]) -> io::Result<CmdOutput> {
        self.st.borrow_mut().calls.push("systemd-analyze verify".into());
        out(0, "", "")
    }

    fn device_model(&self) -> io::Result<String> {
        self.st
            .borrow()
            .model
            .clone()
            .ok_or_else(|| io::Error::other("ubnt-device-info: not found"))
    }

    fn run_units(&self, exe: &Path, platform: Platform) -> Result<Vec<u8>, RunError> {
        let version = exe
            .parent()
            .and_then(Path::file_name)
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.st
            .borrow_mut()
            .calls
            .push(format!("units {version} --platform {}", platform.as_str()));
        if !exe.is_file() {
            return Err(RunError::Spawn(io::Error::other("no such file")));
        }
        self.st
            .borrow()
            .units_out
            .get(&version)
            .cloned()
            .ok_or_else(|| RunError::Io(io::Error::other("no units output registered")))
    }

    fn is_root(&self) -> bool {
        self.st.borrow().is_root
    }

    fn booted_with_systemd(&self) -> bool {
        self.st.borrow().booted
    }

    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_790_000_000) + self.st.borrow().clock
    }

    fn monotonic(&self) -> Duration {
        self.st.borrow().clock
    }

    fn sleep(&self, d: Duration) {
        let mut st = self.st.borrow_mut();
        let before = st.clock;
        st.clock += d;
        drop(st.release_on_sleep.take());
        // An edge refusing to run is restarted by systemd every 5 s, each start writing
        // `state.json` again.
        let restarts = matches!(st.ready, Ready::Incompatible(_))
            && st.active.get(units::EDGE).is_some_and(|a| a == "active")
            && before.as_secs() / 5 != st.clock.as_secs() / 5;
        drop(st);
        if restarts && !self.edge_started() {
            self.st.borrow_mut().refused_starts += 1;
        }
    }

    fn boot_id(&self) -> io::Result<String> {
        Ok(self.st.borrow().boot_id.clone())
    }

    fn host_arch(&self) -> String {
        self.st.borrow().arch.clone()
    }

    fn random_u64(&self) -> io::Result<u64> {
        let mut st = self.st.borrow_mut();
        st.rand = st
            .rand
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        Ok(st.rand)
    }

    fn chown(&self, _file: &File, logical: &Path, uid: u32, gid: u32) -> io::Result<()> {
        let mut st = self.st.borrow_mut();
        st.calls.push(format!("chown {} {uid}:{gid}", logical.display()));
        st.owners.insert(logical.to_path_buf(), (uid, gid));
        Ok(())
    }

    fn owner(&self, _meta: &Metadata, logical: &Path) -> (u32, u32) {
        self.st.borrow().owners.get(logical).copied().unwrap_or((0, 0))
    }

    fn mountinfo(&self) -> io::Result<String> {
        Ok(self.st.borrow().mountinfo.clone())
    }

    fn checkpoint(&self, at: &'static str) -> io::Result<()> {
        self.hit(at)
    }
}

/// A tar entry for test tarballs.
#[derive(Clone, Debug)]
pub struct TarEntry {
    pub path: String,
    pub kind: tar::EntryType,
    pub data: Vec<u8>,
    pub link: String,
}

impl TarEntry {
    pub fn file(path: &str, data: &[u8]) -> TarEntry {
        TarEntry {
            path: path.into(),
            kind: tar::EntryType::Regular,
            data: data.to_vec(),
            link: String::new(),
        }
    }
    pub fn dir(path: &str) -> TarEntry {
        TarEntry {
            path: path.into(),
            kind: tar::EntryType::Directory,
            data: vec![],
            link: String::new(),
        }
    }
    pub fn symlink(path: &str, target: &str) -> TarEntry {
        TarEntry {
            path: path.into(),
            kind: tar::EntryType::Symlink,
            data: vec![],
            link: target.into(),
        }
    }
    pub fn hardlink(path: &str, target: &str) -> TarEntry {
        TarEntry {
            path: path.into(),
            kind: tar::EntryType::Link,
            data: vec![],
            link: target.into(),
        }
    }
    pub fn fifo(path: &str) -> TarEntry {
        TarEntry {
            path: path.into(),
            kind: tar::EntryType::Fifo,
            data: vec![],
            link: String::new(),
        }
    }
}

/// Builds a `.tar.gz`. Paths are written raw into the header, so tests can build archives a
/// well-behaved tar would refuse to (`../x`, `/etc/x`).
pub fn tar_gz(entries: &[TarEntry]) -> Vec<u8> {
    let mut raw = Vec::new();
    for e in entries {
        let mut h = tar::Header::new_gnu();
        {
            let name = &mut h.as_old_mut().name;
            name.fill(0);
            name[..e.path.len()].copy_from_slice(e.path.as_bytes());
        }
        h.set_entry_type(e.kind);
        h.set_size(e.data.len() as u64);
        h.set_mode(0o755);
        h.set_mtime(0);
        if !e.link.is_empty() {
            let l = &mut h.as_old_mut().linkname;
            l.fill(0);
            l[..e.link.len()].copy_from_slice(e.link.as_bytes());
        }
        h.set_cksum();
        raw.extend_from_slice(h.as_bytes());
        raw.extend_from_slice(&e.data);
        let pad = (512 - e.data.len() % 512) % 512;
        raw.extend(std::iter::repeat_n(0u8, pad));
    }
    raw.extend(std::iter::repeat_n(0u8, 1024));
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap()
}

/// A release signing key.
pub struct Keys {
    pub kp: minisign::KeyPair,
    pub pub_b64: String,
}

impl Keys {
    pub fn new() -> Keys {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let pub_b64 = kp.pk.to_base64();
        Keys { kp, pub_b64 }
    }

    pub fn sign(&self, data: &[u8], trusted_comment: &str) -> String {
        minisign::sign(Some(&self.kp.pk), &self.kp.sk, data, Some(trusted_comment), None)
            .unwrap()
            .into_string()
    }
}

/// The three binaries of a test release.
pub fn release_entries(version: &str) -> Vec<TarEntry> {
    BINARIES
        .iter()
        .map(|b| TarEntry::file(b, format!("#!{b} {version}\n").as_bytes()))
        .collect()
}

/// A temporary root with a fake system, an installed layout and a release key.
pub struct World {
    /// Keeps the temporary root alive.
    pub _tmp: tempfile::TempDir,
    pub src: tempfile::TempDir,
    pub root: Root,
    pub sys: FakeSystem,
    pub keys: Keys,
    pub layout: Layout,
}

impl World {
    pub fn new(platform: Platform) -> World {
        let tmp = tempfile::tempdir().unwrap();
        let root = Root::new(tmp.path());
        let layout = Layout::for_platform(platform);
        for d in ["etc/systemd/system", "volume1", "run/systemd/system", "usr/lib"] {
            std::fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        std::fs::write(tmp.path().join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        std::fs::write(tmp.path().join("etc/group"), "root:x:0:\n").unwrap();
        if platform == Platform::Unifi {
            std::fs::create_dir_all(tmp.path().join("data/udapi-config/ubios-udapi-server")).unwrap();
            std::fs::write(
                tmp.path().join("usr/lib/version"),
                "UCGF.ipq9574.v6.0.17.1a2b3c4.250430.1720\n",
            )
            .unwrap();
        }
        let sys = FakeSystem::new(tmp.path(), &layout);
        let w = World {
            src: tempfile::tempdir().unwrap(),
            root,
            sys,
            keys: Keys::new(),
            layout,
            _tmp: tmp,
        };
        w.write_edge_json(None);
        w
    }

    pub fn real(&self, logical: impl AsRef<Path>) -> PathBuf {
        self.root.real(logical)
    }

    /// `edge.json` with this world's release key (and an optional `ssd_dir`).
    pub fn write_edge_json(&self, ssd_dir: Option<&str>) {
        let dir = self.real(self.layout.config_dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ssd = ssd_dir
            .map(|s| format!("\"{s}\""))
            .unwrap_or_else(|| "null".into());
        std::fs::write(
            dir.join("edge.json"),
            format!(
                "{{\"core_url\": \"https://192.168.1.20:7443\", \"ssd_dir\": {ssd}, \"release_keys\": [\"{}\"], \"data_dir\": \"{}\"}}\n",
                self.keys.pub_b64, self.layout.default_data_dir
            ),
        )
        .unwrap();
    }

    /// Runs `install` of `version` from a source directory holding its three binaries.
    pub fn install(&self, version: &str, force: bool) -> crate::error::Result<InstallReport> {
        for b in BINARIES {
            std::fs::write(self.src.path().join(b), format!("#!{b} {version}\n")).unwrap();
        }
        install(
            &self.root,
            &self.sys,
            &InstallOptions {
                platform: None,
                force,
                src_dir: self.src.path().to_path_buf(),
                version: version.into(),
            },
        )
    }

    /// The units this version writes for the current `edge.json`.
    pub fn units(&self) -> BTreeMap<String, String> {
        let s = load_settings(&self.root, &self.layout, &self.sys, Purpose::Units).unwrap();
        units::render(&self.layout, &s)
    }

    pub fn units_json(units: &BTreeMap<String, String>) -> Vec<u8> {
        serde_json::to_vec(&crate::api::UnitsOutput {
            format: 1,
            units: units.clone(),
        })
        .unwrap()
    }

    /// Places a signed release of `version` as the edge would, with `units` as its `units`
    /// output (this version's units when `None`).
    pub fn release(&self, version: &str, units: Option<BTreeMap<String, String>>) {
        let comment = format!("picket-edge {version} x86_64");
        self.release_raw(version, &release_entries(version), &comment, &self.keys);
        let units = units.unwrap_or_else(|| self.units());
        self.sys
            .st
            .borrow_mut()
            .units_out
            .insert(version.into(), Self::units_json(&units));
    }

    pub fn release_raw(&self, version: &str, entries: &[TarEntry], comment: &str, keys: &Keys) {
        let tar = tar_gz(entries);
        let sig = keys.sign(&tar, comment);
        let dir = self.real(
            Path::new(self.layout.default_data_dir)
                .join("releases")
                .join(version),
        );
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("picket-edge-{version}-x86_64.tar.gz")), &tar).unwrap();
        std::fs::write(
            dir.join(format!("picket-edge-{version}-x86_64.tar.gz.minisig")),
            sig,
        )
        .unwrap();
    }

    pub fn pending_path(&self) -> PathBuf {
        self.real(Path::new(self.layout.default_data_dir).join("releases/pending.json"))
    }

    pub fn pending(&self, version: &str, request_id: Option<&str>, rollback: bool) {
        let p = crate::api::Pending {
            version: version.into(),
            request_id: request_id.map(Into::into),
            rollback,
        };
        std::fs::create_dir_all(self.pending_path().parent().unwrap()).unwrap();
        std::fs::write(self.pending_path(), serde_json::to_vec(&p).unwrap()).unwrap();
    }

    /// One run of the update service.
    pub fn update(&self) -> RunEnd {
        self.sys.set_active(UPDATE_SERVICE, "activating");
        let r = update::run(&Env {
            root: &self.root,
            sys: &self.sys,
            platform: self.layout.platform,
            data_dir: None,
        })
        .expect("update run");
        self.sys.set_active(UPDATE_SERVICE, "inactive");
        r
    }

    /// One run that crashes at the configured checkpoint; returns the checkpoint.
    pub fn update_crashing(&self, at: &str, nth: u32) -> String {
        self.sys.st.borrow_mut().crash_at = Some((at.into(), nth));
        self.sys.set_active(UPDATE_SERVICE, "activating");
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            update::run(&Env {
                root: &self.root,
                sys: &self.sys,
                platform: self.layout.platform,
                data_dir: None,
            })
        }));
        self.sys.set_active(UPDATE_SERVICE, "inactive");
        match r {
            Err(payload) => match payload.downcast::<Crash>() {
                Ok(c) => c.0,
                Err(p) => std::panic::resume_unwind(p),
            },
            Ok(r) => panic!("the run didn't crash: {r:?}"),
        }
    }

    pub fn result(&self) -> Option<UpdateResult> {
        let b = std::fs::read(self.real(Path::new(self.layout.bin_dir).join("update-result.json"))).ok()?;
        serde_json::from_slice(&b).ok()
    }

    pub fn current(&self) -> Option<String> {
        std::fs::read_link(self.real(Path::new(self.layout.bin_dir).join("current")))
            .ok()
            .map(|t| t.to_string_lossy().into_owned())
    }

    pub fn unit_text(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.real(Path::new(UNIT_DIR).join(name))).ok()
    }

    pub fn write_unit(&self, name: &str, text: &str) {
        std::fs::write(self.real(Path::new(UNIT_DIR).join(name)), text).unwrap();
    }

    pub fn exists(&self, logical: impl AsRef<Path>) -> bool {
        std::fs::symlink_metadata(self.real(logical)).is_ok()
    }

    pub fn snapshot_exists(&self) -> bool {
        self.exists(Path::new(self.layout.bin_dir).join(".units-prev"))
    }

    pub fn version_dirs(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.real(self.layout.bin_dir))
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| crate::api::is_release_version(n))
            .collect();
        v.sort();
        v
    }

    /// No step ever started, stopped, restarted or disabled the update service.
    pub fn assert_own_service_untouched(&self) {
        for c in self.sys.calls() {
            if c.starts_with("systemctl ")
                && !c.starts_with("systemctl is-")
                && !c.contains("reenable")
                && !c.contains("daemon-reload")
            {
                assert!(!c.ends_with(UPDATE_SERVICE), "touched its own service: {c}");
            }
        }
        assert!(
            self.sys.st.borrow().stale_starts.is_empty(),
            "started without daemon-reload: {:?}",
            self.sys.st.borrow().stale_starts
        );
    }
}
