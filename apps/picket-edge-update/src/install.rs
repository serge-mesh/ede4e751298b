//! `picket-edge-update install [--platform unifi|debian] [--force]`, run by hand as root: install
//! or repair binaries, accounts, directories and units (edge-unifi.md §2 steps 1–6). Each step
//! changes only what differs, so a second run changes and restarts nothing, and a re-run
//! repairs deleted or edited units.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Seek, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::accounts::{self, HELPER_GID, HELPER_UID, PICKET_GID, PICKET_UID};
use crate::api::{compare_versions, is_release_version};
use crate::error::{Context, Error, Result};
use crate::fsx::{self, Dir, ReadError, Root, is_link_or_not_dir};
use crate::hostinfo;
use crate::lock::{self, LOCK_WAIT, LockError};
use crate::platform::{Layout, Platform, Purpose, Settings, UNIT_DIR, check_root_only, load_settings};
use crate::release::BINARIES;
use crate::snapshot;
use crate::system::System;
use crate::systemd::Systemd;
use crate::units::{self, EDGE, HELPER, UPDATE_PATH, UPDATE_SERVICE};
use crate::update::{CURRENT, read_current};

/// What to install.
#[derive(Clone, Debug)]
pub struct InstallOptions {
    /// `--platform`; detected when `None`.
    pub platform: Option<Platform>,
    /// `--force`: install over a newer `bin/current` (a manual downgrade).
    pub force: bool,
    /// The directory holding the three binaries: the unpacked tarball, or `bin/<version>/`
    /// itself when re-run from `bin/current`.
    pub src_dir: PathBuf,
    /// The version being installed: this binary's.
    pub version: String,
}

/// What `install` did, for the operator.
#[derive(Clone, Debug, Default)]
pub struct InstallReport {
    pub version: String,
    pub platform: Option<Platform>,
    pub actions: Vec<String>,
    pub warnings: Vec<String>,
}

const BINARY_MAX: u64 = 256 * 1024 * 1024;
const ID_MAX: u64 = 256;
pub const SSD_MARKER: &str = ".picket-ssd";
pub const SSD_ID: &str = "ssd-id";

/// Runs `install`.
pub fn install(root: &Root, sys: &dyn System, opts: &InstallOptions) -> Result<InstallReport> {
    // Step 1: root, under systemd.
    if !sys.is_root() {
        crate::bail!("install must run as root");
    }
    if !sys.booted_with_systemd() {
        crate::bail!("install needs a system booted with systemd");
    }
    if !is_release_version(&opts.version) {
        crate::bail!("{:?} isn't a release version", opts.version);
    }
    let mut source = open_source(sys, &opts.src_dir)?;
    let platform = opts.platform.unwrap_or_else(|| Platform::detect(root));
    let layout = Layout::for_platform(platform);
    // Read before the lock, which lives in bin/ (created below if missing), so a bad edge.json
    // is refused before anything changes. Nothing writes edge.json under the lock, so reading it
    // first races with no update or install.
    let settings = load_settings(root, &layout, sys, Purpose::Install)?;
    let mut rep = InstallReport {
        version: opts.version.clone(),
        platform: Some(platform),
        ..Default::default()
    };
    if platform == Platform::Unifi {
        check_unifi(root, sys, &mut rep);
    }

    // The lock lives in bin/, so the install and bin directories are created first if missing;
    // an existing one is repaired only once the lock is held, so an install that times out
    // waiting changes nothing.
    let install_dir = ensure_path(root, sys, layout.install_dir, (0, 0), 0o755, false)?;
    let (bin, _) = ensure_dir(&install_dir, sys, "bin", (0, 0), 0o755, false)?;
    let _lock = lock::acquire(&bin, sys, LOCK_WAIT).map_err(|e| match e {
        LockError::Timeout => Error::msg(format!(
            "an update holds {}/.lock and didn't finish within {} s; nothing was changed, try again later",
            layout.bin_dir,
            LOCK_WAIT.as_secs()
        )),
        LockError::Io(e) => Error::msg(format!("can't take {}/.lock: {e}", layout.bin_dir)),
    })?;
    for d in [&install_dir, &bin] {
        fix_meta(sys, d.file(), d.logical(), (0, 0), 0o755, &mut rep)?;
    }
    // Read bin/current again now that the lock is held.
    let current = read_current(&bin);
    // Temporary files a run cut short left behind (README §2, Restarts).
    fsx::remove_temp_files(&bin, ".");
    if let Ok(d) = bin.subdir(&opts.version) {
        fsx::remove_temp_files(&d, ".");
    }
    if let Ok(d) = units::open_unit_dir(root) {
        fsx::remove_temp_files(&d, ".picket-");
    }
    if let Some(cur) = &current
        && compare_versions(cur, &opts.version) == Some(std::cmp::Ordering::Greater)
        && !opts.force
    {
        crate::bail!(
            "bin/current is {cur}, newer than {}; use --force to downgrade",
            opts.version
        );
    }

    let mut owed = Owed::read(&bin, units::render(&layout, &settings).into_keys(), &mut rep);

    // Step 2: binaries into bin/<version>/, and bin/current. The restarts this owes the running
    // units are recorded before any binary is copied.
    let differing = binaries_differing(&bin, &mut source, current.as_deref())?;
    owed.add(&bin, sys, differing.iter().map(|b| b.to_string()), [])?;
    copy_binaries(&bin, sys, &mut source, &opts.version, &mut rep)?;
    if current.as_deref() != Some(opts.version.as_str()) {
        bin.symlink_atomic(sys, CURRENT, Path::new(&opts.version))
            .context("can't point bin/current")?;
        rep.actions.push(format!("bin/current -> {}", opts.version));
        // Only the current and previous versions are kept; with no valid previous link there
        // is no previous version to tell apart, so nothing is deleted.
        if let Some(c) = &current {
            prune(&bin, &[opts.version.as_str(), c], &mut rep);
        }
    }

    // Step 3: accounts.
    let config = ensure_path(root, sys, layout.config_dir, (0, 0), 0o750, false)?;
    let conf_changed = write_if_different(
        &config,
        sys,
        "sysusers.conf",
        accounts::SYSUSERS_CONF.as_bytes(),
        0o644,
        (0, 0),
    )?;
    if conf_changed {
        rep.actions
            .push(format!("wrote {}/sysusers.conf", layout.config_dir));
    }
    if conf_changed || accounts::verify(root).is_err() {
        let conf = root.real(accounts::conf_path(layout.config_dir));
        let out = sys.sysusers(&conf).context("can't run systemd-sysusers")?;
        if !out.success() {
            crate::bail!("systemd-sysusers failed: {}", out.stderr.trim());
        }
        rep.actions.push("ran systemd-sysusers".into());
    }
    accounts::verify(root).map_err(|e| {
        Error::msg(format!(
            "the accounts aren't as {}/sysusers.conf declares them: {e}. Free those names and IDs, then re-run install",
            layout.config_dir
        ))
    })?;

    // Step 4: directories and ownership.
    fix_meta(
        sys,
        config.file(),
        config.logical(),
        (0, PICKET_GID),
        0o750,
        &mut rep,
    )?;
    match fix_file(&config, sys, "edge.json", (0, PICKET_GID), 0o640, &mut rep) {
        Ok(true) => {}
        // install never writes it (edge-unifi.md §2 step 4); say who does.
        Ok(false) => rep.warnings.push(format!(
            "{} doesn't exist yet: run `picket-edge setup` as root to write it. Until then the \
             units use the platform's data_dir and no ssd_dir; re-run install if you set either",
            layout.edge_json
        )),
        Err(e) => rep
            .warnings
            .push(format!("{}: {e}; left alone", layout.edge_json)),
    }
    let data = ensure_path(
        root,
        sys,
        &settings.data_dir,
        (PICKET_UID, PICKET_GID),
        0o750,
        false,
    )?;
    ensure_path(
        root,
        sys,
        layout.helper_dir,
        (HELPER_UID, HELPER_GID),
        0o700,
        false,
    )?;
    ssd(root, sys, &settings, &data, &mut rep);

    // Step 5: units.
    let changed_units = write_units(root, sys, &layout, &settings, &bin, &mut owed, &mut rep)?;

    // Step 6: start and restart, including what a run cut short owed.
    let owed_bins: BTreeSet<&'static str> = BINARIES
        .into_iter()
        .filter(|b| owed.binaries.contains(*b))
        .collect();
    start_units(sys, &layout, &settings, &changed_units, &owed_bins, &mut rep)?;
    if let Err(e) = bin
        .remove(OWED)
        .and_then(|removed| if removed { bin.sync() } else { Ok(()) })
    {
        rep.warnings.push(format!(
            "can't delete {}/{OWED}: {e}; the next install restarts its units again",
            layout.bin_dir
        ));
    }
    Ok(rep)
}

/// `bin/.install-owed`: the restarts an `install` owes running units, recorded before the step
/// that creates them (copying a binary, which the switch makes current, or writing or retiring a
/// unit) and deleted once step 6 has made them. A run cut short (a crash, a failed restart, a
/// refusal after the switch) leaves them to the re-run, which would otherwise find binaries and
/// units already right and restart nothing while the old processes run on (edge-unifi.md §2: a
/// re-run repairs an install; README §2 Restarts).
pub const OWED: &str = ".install-owed";
const OWED_MAX: u64 = 64 * 1024;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Owed {
    /// Binaries whose units restart.
    #[serde(default)]
    binaries: BTreeSet<String>,
    /// Unit files written or retired: reload, then re-enable and restart those still listed.
    #[serde(default)]
    units: BTreeSet<String>,
}

impl Owed {
    /// What a run cut short left. A file that can't be read owes every binary and unit.
    fn read(bin: &Dir, all_units: impl Iterator<Item = String>, rep: &mut InstallReport) -> Owed {
        let why = match bin.read_bounded(OWED, OWED_MAX, true) {
            Err(ReadError::Missing) => return Owed::default(),
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(o) => return o,
                Err(e) => e.to_string(),
            },
            Err(e) => e.to_string(),
        };
        rep.warnings.push(format!(
            "{}: {why}; restarting every unit",
            bin.logical_at(OWED).display()
        ));
        Owed {
            binaries: BINARIES.iter().map(|b| b.to_string()).collect(),
            units: all_units.collect(),
        }
    }

    /// Adds to what is owed and writes it down (root:root 0600) before the caller acts.
    fn add(
        &mut self,
        bin: &Dir,
        sys: &dyn System,
        binaries: impl IntoIterator<Item = String>,
        units: impl IntoIterator<Item = String>,
    ) -> Result<()> {
        let before = (self.binaries.len(), self.units.len());
        self.binaries.extend(binaries);
        self.units.extend(units);
        if (self.binaries.len(), self.units.len()) != before {
            let bytes = serde_json::to_vec(self).map_err(|e| Error::msg(e.to_string()))?;
            bin.write_atomic(sys, OWED, &bytes, 0o600, (0, 0))
                .with_context(|| format!("can't write {}", bin.logical_at(OWED).display()))?;
        }
        Ok(())
    }
}

/// The release's three binaries, opened before anything changes, from a directory nobody but
/// root can change, and never through a link. Otherwise picket-edge could swap in its own
/// picket-edge-update (say the tarball was unpacked in its `releases/<version>/`) for the next
/// update to run as root (security.md §3). Every directory up to `/` must be root's and writable
/// by root alone, or sticky like `/tmp`; each binary root's and writable by root alone.
struct Source {
    files: Vec<(&'static str, File)>,
}

fn open_source(sys: &dyn System, src_dir: &Path) -> Result<Source> {
    let advice = "install copies the binaries only from a directory nobody but root can change: \
                  unpack the tarball as root into a new directory such as /root/picket-edge \
                  (with `tar --no-same-owner`) and run install from there";
    let dir_path =
        std::fs::canonicalize(src_dir).with_context(|| format!("can't resolve {}", src_dir.display()))?;
    let mut p = dir_path.clone();
    loop {
        let meta = std::fs::symlink_metadata(&p).with_context(|| p.display().to_string())?;
        check_root_only(sys, &meta, &p, true).map_err(|why| Error::msg(format!("{why}; {advice}")))?;
        if !p.pop() {
            break;
        }
    }
    let dir = Dir::open(&Root::system(), &dir_path)
        .with_context(|| format!("can't open {}", dir_path.display()))?;
    let (opened, checked) = (dir.metadata()?, std::fs::symlink_metadata(&dir_path)?);
    if (opened.dev(), opened.ino()) != (checked.dev(), checked.ino()) {
        crate::bail!("{} changed while install checked it", dir_path.display());
    }
    let mut files = Vec::new();
    for b in BINARIES {
        let path = dir_path.join(b);
        let (file, meta) = dir
            .open_regular(b)
            .map_err(|e| Error::msg(format!("can't open {}: {e}", path.display())))?;
        if meta.len() > BINARY_MAX {
            crate::bail!("{} is larger than {BINARY_MAX} bytes", path.display());
        }
        check_root_only(sys, &meta, &path, false).map_err(|why| Error::msg(format!("{why}; {advice}")))?;
        files.push((b, file));
    }
    Ok(Source { files })
}

fn check_unifi(root: &Root, sys: &dyn System, rep: &mut InstallReport) {
    match sys.device_model() {
        Ok(m) if m == hostinfo::EXPECTED_MODEL => {}
        Ok(m) => rep.warnings.push(format!(
            "this is a {m:?}, not a {}; carrying on",
            hostinfo::EXPECTED_MODEL
        )),
        Err(e) => rep
            .warnings
            .push(format!("can't read the device model: {e}; carrying on")),
    }
    let version = Dir::open_follow(root, "/usr/lib")
        .ok()
        .and_then(|d| d.read_bounded("version", 4096, false).ok())
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    if let Some(w) = hostinfo::firmware_warning(version.as_deref(), &hostinfo::firmware_minimums()) {
        rep.warnings.push(format!("{w}; carrying on"));
    }
}

/// The binaries that differ from the ones `bin/current` holds: their units restart.
fn binaries_differing(
    bin: &Dir,
    source: &mut Source,
    current: Option<&str>,
) -> Result<BTreeSet<&'static str>> {
    let cur_dir = current.and_then(|c| bin.subdir(c).ok());
    let mut differing = BTreeSet::new();
    for (b, src) in &mut source.files {
        src.rewind()?;
        let same = match cur_dir.as_ref().map(|d| d.open_regular(b)) {
            Some(Ok((mut f, _))) => fsx::same_contents(&mut f, src)?,
            _ => false,
        };
        if !same {
            differing.insert(*b);
        }
    }
    Ok(differing)
}

/// Copies the binaries into `bin/<version>/` where they differ.
fn copy_binaries(
    bin: &Dir,
    sys: &dyn System,
    source: &mut Source,
    version: &str,
    rep: &mut InstallReport,
) -> Result<()> {
    let (vdir, _) = ensure_dir(bin, sys, version, (0, 0), 0o755, true)?;
    for (b, src) in &mut source.files {
        let b: &'static str = b;
        src.rewind()?;
        let same_dest = match vdir.open_regular(b) {
            Ok((mut f, _)) => fsx::same_contents(&mut f, src)?,
            Err(_) => false,
        };
        src.rewind()?;
        if same_dest {
            fix_file(&vdir, sys, b, (0, 0), 0o755, rep).with_context(|| format!("bin/{version}/{b}"))?;
            continue;
        }
        let tmp = format!(".{b}.tmp-{:016x}", sys.random_u64()?);
        let mut out = vdir.create_new(&tmp, 0o755)?;
        let r = (|| -> std::io::Result<()> {
            fsx::copy_capped(src, &mut out, BINARY_MAX)?;
            out.flush()?;
            out.set_permissions(std::fs::Permissions::from_mode(0o755))?;
            sys.chown(&out, &vdir.logical_at(b), 0, 0)?;
            out.sync_all()?;
            vdir.rename(&tmp, b)
        })();
        if let Err(e) = r {
            let _ = vdir.remove(&tmp);
            return Err(e).with_context(|| format!("can't copy {b} into bin/{version}"));
        }
        vdir.sync()?;
        rep.actions.push(format!("copied {b} to bin/{version}/"));
    }
    Ok(())
}

/// Keeps only the current and previous `bin/<version>/`.
fn prune(bin: &Dir, keep: &[&str], rep: &mut InstallReport) {
    let Ok(names) = bin.names(10_000) else { return };
    for name in names {
        if is_release_version(&name)
            && !keep.contains(&name.as_str())
            && bin
                .lstat(&name)
                .ok()
                .flatten()
                .is_some_and(|m| m.file_type().is_dir())
        {
            match bin.remove(&name) {
                Ok(_) => rep.actions.push(format!("deleted bin/{name}")),
                Err(e) => rep.warnings.push(format!("can't delete bin/{name}: {e}")),
            }
        }
    }
}

/// Step 5: write the units as files, retire unlisted `picket-*` units, delete a leftover
/// snapshot, reload, enable. Returns the units whose files changed, in this run or a run cut
/// short before it made their restarts ([`OWED`]).
fn write_units(
    root: &Root,
    sys: &dyn System,
    layout: &Layout,
    settings: &Settings,
    bin: &Dir,
    owed: &mut Owed,
    rep: &mut InstallReport,
) -> Result<BTreeSet<String>> {
    let sd = Systemd { sys };
    let unit_dir = ensure_path(root, sys, UNIT_DIR, (0, 0), 0o755, false)?;
    let new_units = units::render(layout, settings);
    let installed = units::scan_installed(&unit_dir)?;
    let mut enabled_state = BTreeMap::new();
    let mut masked = BTreeSet::new();
    for name in new_units.keys() {
        let st = sd.is_enabled(name)?;
        if st.starts_with("masked") || installed.get(name).is_some_and(units::Installed::is_mask) {
            masked.insert(name.clone());
        }
        enabled_state.insert(name.clone(), st);
    }

    // Retire every picket-* unit this version doesn't list (never its own service; masks stay).
    let retired: Vec<&String> = installed
        .iter()
        .filter(|(n, e)| !new_units.contains_key(*n) && !e.is_mask() && n.as_str() != UPDATE_SERVICE)
        .map(|(n, _)| n)
        .collect();
    let to_write: BTreeSet<&String> = new_units
        .iter()
        .filter(|(n, t)| !masked.contains(*n) && !installed.get(*n).is_some_and(|e| e.is_file_with(t)))
        .map(|(n, _)| n)
        .collect();
    owed.add(
        bin,
        sys,
        [],
        retired.iter().chain(&to_write).map(|n| n.to_string()),
    )?;
    for u in &retired {
        sd.disable_now(u)?;
        unit_dir.remove(u).with_context(|| format!("can't delete {u}"))?;
        rep.actions.push(format!("retired {u}"));
    }
    // A snapshot left by an interrupted update is obsolete once install rewrites everything.
    for name in snapshot::delete_leftovers(bin)? {
        rep.actions.push(format!("deleted leftover bin/{name}"));
    }
    if bin.remove(snapshot::NAME)? {
        rep.actions
            .push(format!("deleted leftover bin/{}", snapshot::NAME));
    }

    for (name, text) in &new_units {
        if masked.contains(name) {
            rep.warnings.push(format!(
                "{name} is masked; left alone (unmask it and re-run install)"
            ));
            continue;
        }
        if !to_write.contains(name) {
            fix_file(&unit_dir, sys, name, (0, 0), 0o644, rep)?;
            continue;
        }
        unit_dir
            .write_atomic(sys, name, text.as_bytes(), 0o644, (0, 0))
            .with_context(|| format!("can't write {UNIT_DIR}/{name}"))?;
        rep.actions.push(format!("wrote {UNIT_DIR}/{name}"));
    }
    // Written or retired now or by a run cut short: the reload, re-enabling and restarts may not
    // have happened yet.
    let changed: BTreeSet<String> = owed
        .units
        .iter()
        .filter(|n| new_units.contains_key(*n) && !masked.contains(*n))
        .cloned()
        .collect();
    if !owed.units.is_empty() {
        sd.daemon_reload()?;
    }
    for (name, text) in &new_units {
        if masked.contains(name) || !units::has_install_section(text.as_bytes()) {
            continue;
        }
        let enabled = enabled_state.get(name).map(String::as_str) == Some("enabled");
        if enabled && changed.contains(name) {
            // No link from an older [Install] section stays behind.
            sd.reenable(name)?;
            rep.actions.push(format!("re-enabled {name}"));
        } else if !enabled {
            sd.enable(name)?;
            rep.actions.push(format!("enabled {name}"));
        }
    }
    if !changed.is_empty() {
        let paths: Vec<PathBuf> = changed
            .iter()
            .map(|n| root.real(Path::new(UNIT_DIR).join(n)))
            .collect();
        match sys.analyze_verify(&paths) {
            Ok(out) if out.success() => {}
            Ok(out) => rep.warnings.push(format!(
                "systemd-analyze verify: {}",
                format!("{} {}", out.stdout.trim(), out.stderr.trim()).trim()
            )),
            Err(e) => rep
                .warnings
                .push(format!("can't run systemd-analyze verify: {e}")),
        }
    }
    Ok(changed)
}

/// True when a unit runs this binary from `bin/current`.
fn references_binary(text: &str, binary: &str) -> bool {
    let needle = format!("/bin/current/{binary}");
    text.match_indices(&needle).any(|(i, _)| {
        text[i + needle.len()..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
    })
}

/// Step 6: start the helper, then the edge, then the path unit and other enabled units; restart
/// a running unit only if its binary or unit file changed; never touch the update service.
fn start_units(
    sys: &dyn System,
    layout: &Layout,
    settings: &Settings,
    changed_units: &BTreeSet<String>,
    changed_bins: &BTreeSet<&'static str>,
    rep: &mut InstallReport,
) -> Result<()> {
    let sd = Systemd { sys };
    let new_units = units::render(layout, settings);
    let needs_restart = |name: &str, text: &str| {
        changed_units.contains(name) || changed_bins.iter().any(|b| references_binary(text, b))
    };
    let running = |st: &str| matches!(st, "active" | "activating" | "reloading" | "refreshing");
    let masked = |name: &str| sd.is_enabled(name).is_ok_and(|s| s.starts_with("masked"));

    // Units without [Install] (the accounts oneshot) only restart, and only if they changed.
    for (name, text) in &new_units {
        if name == UPDATE_SERVICE || units::has_install_section(text.as_bytes()) || masked(name) {
            continue;
        }
        if running(&sd.is_active(name)?) && needs_restart(name, text) {
            sd.restart(name)?;
            rep.actions.push(format!("restarted {name}"));
        }
    }
    let mut order: Vec<&str> = vec![HELPER, EDGE, UPDATE_PATH];
    for name in new_units.keys() {
        if !order.contains(&name.as_str()) {
            order.push(name);
        }
    }
    for name in order {
        let Some(text) = new_units.get(name) else { continue };
        if name == UPDATE_SERVICE || !units::has_install_section(text.as_bytes()) || masked(name) {
            continue;
        }
        if running(&sd.is_active(name)?) {
            if needs_restart(name, text) {
                sd.restart(name)?;
                rep.actions.push(format!("restarted {name}"));
            }
        } else {
            sd.start(name)?;
            rep.actions.push(format!("started {name}"));
        }
    }
    Ok(())
}

/// Creates the directory at `logical` if missing (missing parents root-owned, 0755) and opens it
/// without following a link in its last component. With `fix_existing`, an existing directory
/// also gets `owner` and `mode`.
fn ensure_path(
    root: &Root,
    sys: &dyn System,
    logical: &str,
    owner: (u32, u32),
    mode: u32,
    fix_existing: bool,
) -> Result<Dir> {
    let path = Path::new(logical);
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        crate::bail!("{logical} has no parent");
    };
    let parent_real = root.real(parent);
    if !parent_real.is_dir() {
        std::fs::create_dir_all(&parent_real)
            .with_context(|| format!("can't create {}", parent.display()))?;
    }
    let parent_dir =
        Dir::open_follow(root, parent).with_context(|| format!("can't open {}", parent.display()))?;
    let (dir, _) = ensure_dir(
        &parent_dir,
        sys,
        &name.to_string_lossy(),
        owner,
        mode,
        fix_existing,
    )
    .with_context(|| logical.to_string())?;
    Ok(dir)
}

/// Opens `parent/name`, creating it (with `owner` and `mode`) if missing. A link or
/// non-directory there is refused, never followed. Returns whether it was created.
fn ensure_dir(
    parent: &Dir,
    sys: &dyn System,
    name: &str,
    owner: (u32, u32),
    mode: u32,
    fix_existing: bool,
) -> Result<(Dir, bool)> {
    match parent.subdir(name) {
        Ok(d) => {
            if fix_existing {
                let mut scratch = InstallReport::default();
                fix_meta(sys, d.file(), d.logical(), owner, mode, &mut scratch)?;
            }
            Ok((d, false))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            parent
                .mkdir(name, mode)
                .with_context(|| format!("can't create {}", parent.logical_at(name).display()))?;
            let d = parent.subdir(name)?;
            d.file().set_permissions(std::fs::Permissions::from_mode(mode))?;
            sys.chown(d.file(), d.logical(), owner.0, owner.1)?;
            Ok((d, true))
        }
        Err(e) if is_link_or_not_dir(&e) => Err(Error::msg(format!(
            "{} is a link or not a directory; left alone",
            parent.logical_at(name).display()
        ))),
        Err(e) => Err(e).with_context(|| format!("can't open {}", parent.logical_at(name).display())),
    }
}

/// Opens `parent/name` if `owner` owns it, or creates it with `owner` and `mode` if missing. An
/// existing directory is never chowned or chmodded, and one owned by anyone else is refused, so a
/// folder named by mistake (a UniFi one, say) stays as it was (edge-unifi.md §2 step 4: "create
/// … if missing").
fn ensure_own_dir(
    parent: &Dir,
    sys: &dyn System,
    name: &str,
    owner: (u32, u32),
    mode: u32,
) -> Result<(Dir, bool)> {
    let (d, created) = ensure_dir(parent, sys, name, owner, mode, false)?;
    if !created {
        let (uid, _) = sys.owner(&d.metadata()?, d.logical());
        if uid != owner.0 {
            crate::bail!(
                "{} exists and is owned by uid {uid}, not {}; left alone. If it is meant for \
                 Picket, give it to that user (or delete it) and re-run install",
                d.logical().display(),
                owner.0
            );
        }
    }
    Ok((d, created))
}

/// Gives an open file or directory `owner` and `mode` where they differ.
fn fix_meta(
    sys: &dyn System,
    file: &File,
    logical: &Path,
    owner: (u32, u32),
    mode: u32,
    rep: &mut InstallReport,
) -> Result<()> {
    let meta = file.metadata()?;
    if sys.owner(&meta, logical) != owner {
        sys.chown(file, logical, owner.0, owner.1)
            .with_context(|| format!("can't chown {}", logical.display()))?;
        rep.actions
            .push(format!("chown {}:{} {}", owner.0, owner.1, logical.display()));
    }
    if meta.mode() & 0o7777 != mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        rep.actions.push(format!("chmod {mode:o} {}", logical.display()));
    }
    Ok(())
}

/// Gives an existing regular file `owner` and `mode`, opened without following a link and
/// refused if it has other hard links (so a chown never reaches another file). `Ok(false)` if
/// it is missing.
fn fix_file(
    dir: &Dir,
    sys: &dyn System,
    name: &str,
    owner: (u32, u32),
    mode: u32,
    rep: &mut InstallReport,
) -> Result<bool> {
    match dir.open_regular(name) {
        Ok((file, meta)) => {
            if meta.nlink() != 1 {
                crate::bail!(
                    "{} has {} hard links; not changing it",
                    dir.logical_at(name).display(),
                    meta.nlink()
                );
            }
            fix_meta(sys, &file, &dir.logical_at(name), owner, mode, rep)?;
            Ok(true)
        }
        Err(ReadError::Missing) => Ok(false),
        Err(e) => crate::bail!("{}: {e}", dir.logical_at(name).display()),
    }
}

/// Writes a file unless it already holds exactly `bytes`; returns whether it wrote.
fn write_if_different(
    dir: &Dir,
    sys: &dyn System,
    name: &str,
    bytes: &[u8],
    mode: u32,
    owner: (u32, u32),
) -> Result<bool> {
    if let Ok(existing) = dir.read_bounded(name, 1024 * 1024, true)
        && existing == bytes
    {
        let mut scratch = InstallReport::default();
        fix_file(dir, sys, name, owner, mode, &mut scratch)?;
        return Ok(false);
    }
    dir.write_atomic(sys, name, bytes, mode, owner)
        .with_context(|| format!("can't write {}", dir.logical_at(name).display()))?;
    Ok(true)
}

/// A marker id: 32 lowercase hex digits.
fn parse_id(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    (s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
    .then(|| s.to_string())
}

/// Step 4's SSD part: only when `ssd_dir`'s parent is a mount point on another filesystem than
/// `data_dir`. Every problem is a warning; one bad entry doesn't stop the rest or the install.
fn ssd(root: &Root, sys: &dyn System, settings: &Settings, data: &Dir, rep: &mut InstallReport) {
    let Some(ssd) = settings.ssd_dir.as_deref() else {
        return;
    };
    let path = Path::new(ssd);
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let parent_s = parent.to_string_lossy();
    let mounts = match sys.mountinfo() {
        Ok(t) => hostinfo::parse_mountinfo(&t),
        Err(e) => {
            rep.warnings.push(format!("SSD: can't read the mount table: {e}"));
            return;
        }
    };
    if let Err(why) = hostinfo::ssd_mount_usable(&mounts, &parent_s, &settings.data_dir) {
        rep.warnings.push(format!(
            "SSD: {why}; not preparing {ssd}. Re-run install once the SSD is mounted"
        ));
        return;
    }
    let picket = (PICKET_UID, PICKET_GID);
    let ssd_dir = match Dir::open(root, parent)
        .map_err(Error::from)
        .and_then(|p| ensure_own_dir(&p, sys, &name.to_string_lossy(), picket, 0o750))
    {
        Ok((d, created)) => {
            if created {
                rep.actions.push(format!("created {ssd}"));
            }
            d
        }
        Err(e) => {
            rep.warnings.push(format!("SSD: {e}"));
            return;
        }
    };
    for sub in ["bundles", "spool", "verdicts"] {
        if let Err(e) = ensure_own_dir(&ssd_dir, sys, sub, picket, 0o750) {
            rep.warnings.push(format!("SSD: {e}"));
        }
    }
    // The id: <data_dir>/ssd-id, generated on first use.
    let id = match data.read_bounded(SSD_ID, ID_MAX, true) {
        Ok(b) => match parse_id(&b) {
            Some(id) => {
                if let Err(e) = fix_file(data, sys, SSD_ID, picket, 0o640, rep) {
                    rep.warnings.push(format!("SSD: {e}"));
                }
                id
            }
            None => {
                rep.warnings.push(format!(
                    "SSD: {}/{SSD_ID} doesn't hold an id; not writing the marker",
                    settings.data_dir
                ));
                return;
            }
        },
        Err(ReadError::Missing) => {
            let id = match (sys.random_u64(), sys.random_u64()) {
                (Ok(a), Ok(b)) => format!("{a:016x}{b:016x}"),
                (Err(e), _) | (_, Err(e)) => {
                    rep.warnings.push(format!("SSD: no random id: {e}"));
                    return;
                }
            };
            if let Err(e) = data.write_atomic(sys, SSD_ID, format!("{id}\n").as_bytes(), 0o640, picket) {
                rep.warnings
                    .push(format!("SSD: can't write {}/{SSD_ID}: {e}", settings.data_dir));
                return;
            }
            rep.actions.push(format!("wrote {}/{SSD_ID}", settings.data_dir));
            id
        }
        Err(e) => {
            rep.warnings.push(format!(
                "SSD: {}/{SSD_ID}: {e}; not writing the marker",
                settings.data_dir
            ));
            return;
        }
    };
    match ssd_dir.read_bounded(SSD_MARKER, ID_MAX, true) {
        Err(ReadError::Missing) => {
            match ssd_dir.write_atomic(sys, SSD_MARKER, format!("{id}\n").as_bytes(), 0o640, picket) {
                Ok(()) => rep.actions.push(format!("wrote {ssd}/{SSD_MARKER}")),
                Err(e) => rep
                    .warnings
                    .push(format!("SSD: can't write {ssd}/{SSD_MARKER}: {e}")),
            }
        }
        Ok(b) if parse_id(&b).as_deref() == Some(id.as_str()) => {
            if let Err(e) = fix_file(&ssd_dir, sys, SSD_MARKER, picket, 0o640, rep) {
                rep.warnings.push(format!("SSD: {e}"));
            }
        }
        Ok(_) => rep.warnings.push(format!(
            "SSD: {ssd}/{SSD_MARKER} holds another id (another gateway's drive?); left alone. \
             Delete it and re-run install to give this drive to this gateway"
        )),
        Err(e) => rep
            .warnings
            .push(format!("SSD: {ssd}/{SSD_MARKER}: {e}; left alone")),
    }
}
