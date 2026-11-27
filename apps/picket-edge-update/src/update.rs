//! The update run: `picket-edge-update` with no arguments, started by
//! `picket-edge-update.service` (edge.md §14 "How" steps 2–4, Lock, Interrupted update, Result).
//!
//! In order, it takes the lock; recovers from a leftover snapshot; drops a duplicate request;
//! checks the version; compares with `bin/current`; copies, verifies and unpacks the release;
//! runs the new `units`; snapshots; retires, writes, enables and switches; restarts; waits for
//! readiness; and then writes its result, rolling back on failure. `pending.json` is deleted only
//! when the run ends, and kept if its result can't be written.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::api::{self, Outcome, Pending, UpdateResult, compare_versions, is_release_version, stage};
use crate::error::{Context, Result};
use crate::fsx::{self, Dir, ReadError, Root, is_link_or_not_dir};
use crate::lock::{self, LOCK_WAIT};
use crate::platform::{
    Layout, Platform, Purpose, Settings, check_data_dir, check_dir_setting, load_settings,
};
use crate::release::{self, LIMITS};
use crate::snapshot::{self, Manifest, Snapshot};
use crate::system::System;
use crate::systemd::{Systemd, is_running};
use crate::units::{self, EDGE, HELPER, Installed, UPDATE_SERVICE};
use crate::{accounts, log, result};

/// Readiness: up to 120 s for `state.json.ready_version == <version>` (edge.md §14 step 4).
pub const READY_WAIT: Duration = Duration::from_secs(120);
const READY_POLL: Duration = Duration::from_millis(500);
const PENDING_MAX: u64 = 64 * 1024;
const STATE_MAX: u64 = 16 * 1024 * 1024;
const REQUEST_ID_MAX: usize = 256;
/// The root-owned directory the release is copied into and verified in.
pub const STAGING: &str = ".staging";
const UNPACK_PREFIX: &str = ".unpack-";
pub const CURRENT: &str = "current";

/// What a run ended with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEnd {
    /// No `pending.json`.
    Nothing,
    /// A request the existing result already carries: `pending.json` deleted, result left.
    Duplicate,
    /// A result was written.
    Result(UpdateResult),
    /// A result was due but couldn't be written, even after retries: the run kept
    /// `pending.json`, so a later run records the outcome once the write works.
    Unrecorded(UpdateResult),
}

/// The host and platform a run works on.
pub struct Env<'a> {
    pub root: &'a Root,
    pub sys: &'a dyn System,
    pub platform: Platform,
    /// `--data-dir`: the `data_dir` the units were written for, which the path unit watches.
    /// It wins over `edge.json`'s, which may since have changed or become unreadable.
    pub data_dir: Option<String>,
}

/// `pending.json` as found.
enum PendingState {
    Missing,
    /// `releases` itself isn't a directory.
    BadReleases,
    /// A link, directory, FIFO, socket or device.
    NotRegular,
    Invalid(String),
    Valid(Pending),
}

struct PendingFile {
    /// The directory holding it (`data_dir` for [`PendingState::BadReleases`]).
    dir: Option<Dir>,
    /// The entry to delete at the end, with its identity when read: one the edge replaced
    /// meanwhile is left for the next run.
    entry: Option<(String, (u64, u64))>,
    state: PendingState,
}

impl PendingFile {
    fn ids(&self) -> (Option<String>, String) {
        match &self.state {
            PendingState::Valid(p) => (
                p.request_id.clone(),
                if is_release_version(&p.version) {
                    p.version.clone()
                } else {
                    String::new()
                },
            ),
            _ => (None, String::new()),
        }
    }
}

struct Run<'a> {
    root: &'a Root,
    sys: &'a dyn System,
    layout: Layout,
    settings: Settings,
    bin: Dir,
    sd: Systemd<'a>,
    result_id: String,
    gid: u32,
    /// The result couldn't be written: `pending.json` stays (see [`Run::write_result`]).
    unrecorded: Cell<bool>,
}

/// Runs one update.
pub fn run(env: &Env) -> Result<RunEnd> {
    let layout = Layout::for_platform(env.platform);
    let bin = Dir::open(env.root, layout.bin_dir).with_context(|| {
        format!(
            "can't open {} (is picket-edge installed for {}? run `picket-edge-update install` first)",
            layout.bin_dir,
            layout.platform.as_str()
        )
    })?;
    // The lock comes before the first check (edge.md §14, Lock); a run that times out still
    // needs the settings to find and end its request.
    let lock = lock::acquire(&bin, env.sys, LOCK_WAIT);
    let mut settings = load_settings(env.root, &layout, env.sys, Purpose::Update)?;
    if let Some(d) = &env.data_dir {
        match check_dir_setting("data_dir", d).and_then(|()| check_data_dir(&layout, d)) {
            Ok(()) => settings.data_dir = d.clone(),
            Err(e) => settings
                .notes
                .push(format!("--data-dir: {e}; using {}", settings.data_dir)),
        }
    }
    for note in &settings.notes {
        log(note);
    }
    let run = Run {
        root: env.root,
        sys: env.sys,
        result_id: format!("{:016x}", env.sys.random_u64()?),
        gid: accounts::picket_gid(env.root),
        layout,
        settings,
        bin,
        sd: Systemd { sys: env.sys },
        unrecorded: Cell::new(false),
    };
    let end = match lock {
        Ok(_lock) => run.locked()?,
        Err(e) => run.lock_timed_out(&e),
    };
    Ok(match end {
        RunEnd::Result(r) if run.unrecorded.get() => RunEnd::Unrecorded(r),
        end => end,
    })
}

impl Run<'_> {
    /// Another update or `install` held the lock for the whole wait: change nothing but recording
    /// the result (stage `locked`) and ending the request.
    fn lock_timed_out(&self, e: &lock::LockError) -> RunEnd {
        log(&format!("can't take the lock: {e}"));
        let pending = self.open_data().map(|d| read_pending(&d));
        let (request_id, version) = pending.as_ref().map(PendingFile::ids).unwrap_or_default();
        if pending
            .as_ref()
            .is_none_or(|p| matches!(p.state, PendingState::Missing))
        {
            return RunEnd::Nothing;
        }
        let r = self.write_result(Outcome::Failed, Some(stage::LOCKED), request_id, version);
        self.delete_pending(pending.as_ref());
        RunEnd::Result(r)
    }

    fn locked(&self) -> Result<RunEnd> {
        self.delete_leftovers();
        let existing = result::read(&self.bin);

        // Interrupted update: recover from bin/.units-prev/ first.
        match snapshot::read(&self.bin) {
            Ok(None) => {}
            Ok(Some(snap)) => {
                if let Err(e) = self.recover(&snap, existing.as_ref()) {
                    log(&format!("recovery from {} failed: {e}", snapshot::NAME));
                    let pending = self.open_data().map(|d| read_pending(&d));
                    // The result is this run's: for its pending.json, or with none, for the
                    // interrupted update.
                    let (request_id, version) = match &pending {
                        Some(p) if !matches!(p.state, PendingState::Missing) => p.ids(),
                        _ => (snap.manifest.request_id.clone(), snap.manifest.version.clone()),
                    };
                    let r = self.write_result(Outcome::Failed, Some(stage::ROLLBACK), request_id, version);
                    self.delete_pending(pending.as_ref());
                    return Ok(RunEnd::Result(r));
                }
            }
            Err(e) => {
                log(&format!(
                    "can't read {}: {e}; run install to repair",
                    snapshot::NAME
                ));
                let pending = self.open_data().map(|d| read_pending(&d));
                let (request_id, version) = pending.as_ref().map(PendingFile::ids).unwrap_or_default();
                let r = self.write_result(Outcome::Failed, Some(stage::ROLLBACK), request_id, version);
                self.delete_pending(pending.as_ref());
                return Ok(RunEnd::Result(r));
            }
        }

        let Some(data) = self.open_data() else {
            return Ok(RunEnd::Nothing);
        };
        let pending_file = read_pending(&data);
        let pending = match &pending_file.state {
            PendingState::Missing => return Ok(RunEnd::Nothing),
            PendingState::BadReleases | PendingState::NotRegular | PendingState::Invalid(_) => {
                let why = match &pending_file.state {
                    PendingState::BadReleases => "releases isn't a directory".to_string(),
                    PendingState::NotRegular => "pending.json isn't a regular file".to_string(),
                    PendingState::Invalid(e) => format!("pending.json is invalid: {e}"),
                    _ => String::new(),
                };
                log(&why);
                return Ok(self.finish(
                    &pending_file,
                    Outcome::Failed,
                    Some(stage::PENDING),
                    None,
                    String::new(),
                ));
            }
            PendingState::Valid(p) => p.clone(),
        };

        // Only then: a request the existing result already carries is done.
        if let Some(id) = &pending.request_id
            && existing.as_ref().and_then(|r| r.request_id.as_ref()) == Some(id)
        {
            log(&format!("request {id} already has a result; nothing to do"));
            self.delete_pending(Some(&pending_file));
            return Ok(RunEnd::Duplicate);
        }

        // The version is checked before it is used in any path.
        if !is_release_version(&pending.version) {
            log(&format!(
                "pending.json names an invalid version {:?}",
                pending.version
            ));
            return Ok(self.finish(
                &pending_file,
                Outcome::Failed,
                Some(stage::PENDING),
                pending.request_id,
                String::new(),
            ));
        }
        let version = pending.version.clone();
        let request_id = pending.request_id.clone();

        let current = self.read_current();
        if current.as_deref() == Some(version.as_str()) {
            log(&format!("{version} is already installed"));
            return Ok(self.finish(&pending_file, Outcome::Ok, None, request_id, version));
        }
        if let Some(cur) = &current
            && compare_versions(cur, &version) == Some(std::cmp::Ordering::Greater)
            && !pending.rollback
        {
            log(&format!(
                "{cur} is newer than {version}, which isn't marked as a rollback"
            ));
            return Ok(self.finish(
                &pending_file,
                Outcome::Failed,
                Some(stage::SUPERSEDED),
                request_id,
                version,
            ));
        }

        // Copy into a root-owned directory and verify there.
        let arch = self.sys.host_arch();
        if let Err(e) = self.stage_and_verify(&data, &version, &arch) {
            log(&format!("verify: {e}"));
            let _ = self.bin.remove(STAGING);
            return Ok(self.finish(
                &pending_file,
                Outcome::Failed,
                Some(stage::VERIFY),
                request_id,
                version,
            ));
        }

        // Unpack that copy into bin/<version>/.
        let created_version_dir = match self.unpack(&version, &arch) {
            Ok(created) => created,
            Err(e) => {
                log(&format!("unpack: {e}"));
                let _ = self.bin.remove(STAGING);
                let _ = self.bin.remove(&format!("{UNPACK_PREFIX}{version}"));
                return Ok(self.finish(
                    &pending_file,
                    Outcome::Failed,
                    Some(stage::UNPACK),
                    request_id,
                    version,
                ));
            }
        };
        let _ = self.bin.remove(STAGING);
        let fail_before_snapshot = |e: String| {
            log(&format!("units: {e}"));
            if created_version_dir {
                let _ = self.bin.remove(&version);
            }
            Ok(self.finish(
                &pending_file,
                Outcome::Failed,
                Some(stage::UNITS),
                request_id.clone(),
                version.clone(),
            ))
        };

        // Units: the only new-release code run as root before readiness.
        let exe = self.root.real(
            Path::new(self.layout.bin_dir)
                .join(&version)
                .join("picket-edge-update"),
        );
        let new_units = match self
            .sys
            .run_units(&exe, self.layout.platform)
            .map_err(|e| format!("{version}'s `units`: {e}"))
            .and_then(|raw| units::parse_units_output(&raw).map_err(|e| format!("{version}'s `units`: {e}")))
        {
            Ok(u) => u,
            Err(e) => return fail_before_snapshot(e),
        };

        // Snapshot.
        let (snap, masked) = match self.take_snapshot(
            &new_units,
            &version,
            request_id.clone(),
            created_version_dir,
            current.clone(),
        ) {
            Ok(s) => s,
            Err(e) => {
                let _ = self.bin.remove(snapshot::TEMP_NAME);
                return fail_before_snapshot(format!("snapshot: {e}"));
            }
        };
        if let Err(e) = self.sys.checkpoint("snapshot-written") {
            return Ok(self.roll_back_and_finish(&snap, stage::UNITS, &e.to_string(), &pending_file));
        }

        // Retire, write, enable, switch, restart.
        if let Err(e) = self.apply(&snap, &new_units, &masked, &version) {
            return Ok(self.roll_back_and_finish(&snap, stage::UNITS, &e.to_string(), &pending_file));
        }

        // Readiness.
        if !self.wait_ready(&data, &version) {
            return Ok(self.roll_back_and_finish(
                &snap,
                stage::READINESS,
                &format!("{version} didn't report ready within {} s", READY_WAIT.as_secs()),
                &pending_file,
            ));
        }

        // Success: the result first, so a failed or interrupted snapshot delete can't later
        // trigger a rollback (see `recover`).
        let r = self.write_result(Outcome::Ok, None, request_id, version.clone());
        if let Err(e) = self.sys.checkpoint("result-written") {
            log(&format!("{e}"));
        }
        if let Err(e) = snapshot::delete(&self.bin, self.sys) {
            log(&format!(
                "can't delete {} after a successful update: {e}",
                snapshot::NAME
            ));
        }
        let mut keep = vec![version.as_str()];
        if let Some(c) = &snap.manifest.current {
            keep.push(c);
        }
        self.prune(&keep);
        self.delete_pending(Some(&pending_file));
        Ok(RunEnd::Result(r))
    }

    /// Temporary files are deleted at start (README §2, Restarts); a snapshot still under its
    /// temporary name is deleted, since nothing had changed yet (edge.md §14). A failure here
    /// is logged, never fatal: the run must still end its request.
    fn delete_leftovers(&self) {
        match snapshot::delete_leftovers(&self.bin) {
            Ok(names) => names
                .iter()
                .for_each(|n| log(&format!("deleted leftover bin/{n}"))),
            Err(e) => log(&format!("can't delete a leftover snapshot: {e}")),
        }
        match self.bin.names(10_000) {
            Ok(names) => {
                for name in names {
                    if (name == STAGING || name.starts_with(UNPACK_PREFIX) || fsx::is_temp_name(&name, "."))
                        && let Err(e) = self.bin.remove(&name)
                    {
                        log(&format!("can't delete bin/{name}: {e}"));
                    }
                }
            }
            Err(e) => log(&format!("can't list bin: {e}")),
        }
        if let Ok(dir) = units::open_unit_dir(self.root) {
            fsx::remove_temp_files(&dir, ".picket-");
        }
    }

    fn open_data(&self) -> Option<Dir> {
        match Dir::open(self.root, &self.settings.data_dir) {
            Ok(d) => Some(d),
            Err(e) => {
                log(&format!("can't open data_dir {}: {e}", self.settings.data_dir));
                None
            }
        }
    }

    fn read_current(&self) -> Option<String> {
        read_current(&self.bin)
    }

    fn stage_and_verify(&self, data: &Dir, version: &str, arch: &str) -> std::result::Result<(), String> {
        self.bin.remove(STAGING).map_err(|e| e.to_string())?;
        self.bin
            .mkdir(STAGING, 0o700)
            .map_err(|e| format!("can't create {STAGING}: {e}"))?;
        let staging = self.bin.subdir(STAGING).map_err(|e| e.to_string())?;
        self.sys
            .chown(staging.file(), staging.logical(), 0, 0)
            .map_err(|e| e.to_string())?;
        release::copy_release(data, version, arch, &staging, &LIMITS)?;
        release::verify_staged(&staging, version, arch, &self.settings.release_keys, &LIMITS)
    }

    /// Unpacks the verified copy into `bin/<version>/`; returns whether that directory is new.
    fn unpack(&self, version: &str, arch: &str) -> std::result::Result<bool, String> {
        let staging = self.bin.subdir(STAGING).map_err(|e| e.to_string())?;
        let tmp = format!("{UNPACK_PREFIX}{version}");
        self.bin.remove(&tmp).map_err(|e| e.to_string())?;
        self.bin.mkdir(&tmp, 0o755).map_err(|e| e.to_string())?;
        let dest = self.bin.subdir(&tmp).map_err(|e| e.to_string())?;
        self.sys
            .chown(dest.file(), dest.logical(), 0, 0)
            .map_err(|e| e.to_string())?;
        release::unpack(
            &staging,
            &release::tarball_name(version, arch),
            &dest,
            self.sys,
            &LIMITS,
        )?;
        let existed = self.bin.lstat(version).map_err(|e| e.to_string())?.is_some();
        if existed {
            // Never the current version: that case ended earlier.
            self.bin.remove(version).map_err(|e| e.to_string())?;
        }
        self.bin.rename(&tmp, version).map_err(|e| e.to_string())?;
        self.bin.sync().map_err(|e| e.to_string())?;
        Ok(!existed)
    }

    /// Records every current `picket-*` unit, `bin/current`, the enabled and active states and
    /// the boot ID, and returns the snapshot with the units an admin masked.
    fn take_snapshot(
        &self,
        new_units: &BTreeMap<String, String>,
        version: &str,
        request_id: Option<String>,
        created_version_dir: bool,
        current: Option<String>,
    ) -> Result<(Snapshot, BTreeSet<String>)> {
        let unit_dir = units::open_unit_dir(self.root).context("can't open the unit directory")?;
        let installed = units::scan_installed(&unit_dir)?;
        let mut masked = BTreeSet::new();
        let mut recorded = BTreeMap::new();
        for (name, entry) in &installed {
            let en = self.sd.is_enabled(name)?;
            let active = self.sd.is_active(name)? == "active";
            if entry.is_mask() || en.starts_with("masked") {
                masked.insert(name.clone());
            }
            recorded.insert(name.clone(), snapshot::snap_unit(entry, en == "enabled", active));
        }
        for name in new_units.keys().filter(|n| !installed.contains_key(*n)) {
            // A runtime mask (/run/systemd/system) has no file here.
            if self.sd.is_enabled(name)?.starts_with("masked") {
                masked.insert(name.clone());
            }
        }
        let manifest = Manifest {
            format: snapshot::FORMAT,
            result_id: self.result_id.clone(),
            request_id,
            version: version.to_string(),
            created_version_dir,
            current,
            boot_id: self.sys.boot_id().context("can't read the boot id")?,
            units: recorded,
        };
        snapshot::write(&self.bin, self.sys, &manifest, &installed).context("can't write the snapshot")?;
        Ok((
            Snapshot {
                manifest,
                files: installed,
            },
            masked,
        ))
    }

    /// Step 3 after the snapshot: retire, write, enable, switch, restart.
    fn apply(
        &self,
        snap: &Snapshot,
        new_units: &BTreeMap<String, String>,
        masked: &BTreeSet<String>,
        version: &str,
    ) -> Result<()> {
        let unit_dir = units::open_unit_dir(self.root).context("can't open the unit directory")?;
        let installed = &snap.files;

        // Retire, before the switch, so each unit stops under the text and binaries it started with.
        let retired: Vec<&String> = installed
            .iter()
            .filter(|(n, e)| !new_units.contains_key(*n) && !e.is_mask() && n.as_str() != UPDATE_SERVICE)
            .map(|(n, _)| n)
            .collect();
        for u in &retired {
            self.sd.disable_now(u)?;
            self.sys.checkpoint("retired-unit")?;
        }
        for u in &retired {
            unit_dir.remove(u).with_context(|| format!("can't delete {u}"))?;
        }
        if !retired.is_empty() {
            self.sd.daemon_reload()?;
        }

        // Write; an admin's mask is never replaced.
        let mut changed = Vec::new();
        for (name, text) in new_units {
            if masked.contains(name) {
                log(&format!("{name} is masked; leaving it alone"));
                continue;
            }
            if installed.get(name).is_some_and(|e| e.is_file_with(text)) {
                continue;
            }
            unit_dir
                .write_atomic(self.sys, name, text.as_bytes(), 0o644, (0, 0))
                .with_context(|| format!("can't write {name}"))?;
            changed.push(name.clone());
        }
        self.sys.checkpoint("units-written")?;
        if !changed.is_empty() {
            self.sd.daemon_reload()?;
        }
        let added: Vec<&String> = new_units
            .keys()
            .filter(|n| !installed.contains_key(*n) && !masked.contains(*n))
            .collect();
        let mut enabled_added = Vec::new();
        for u in &added {
            if units::has_install_section(new_units[*u].as_bytes()) {
                self.sd.enable(u)?;
                enabled_added.push(*u);
            }
        }
        // An enabled unit whose file changed gets links matching its new [Install] section;
        // a unit an admin disabled stays disabled.
        for u in &changed {
            if snap.manifest.units.get(u).is_some_and(|s| s.enabled) {
                self.sd.reenable(u)?;
            }
        }

        // Switch, keeping the previous version.
        self.bin
            .symlink_atomic(self.sys, CURRENT, Path::new(version))
            .context("can't switch bin/current")?;
        self.sys.checkpoint("switched")?;

        // The helper, then the edge, then other running units whose file changed, then the
        // added units it enabled. Never its own service.
        for u in [HELPER, EDGE] {
            if new_units.contains_key(u) && !masked.contains(u) {
                self.sd.restart(u)?;
            }
        }
        for u in &changed {
            if [HELPER, EDGE, UPDATE_SERVICE].contains(&u.as_str()) || added.contains(&u) {
                continue;
            }
            if is_running(&self.sd.is_active(u)?) {
                self.sd.restart(u)?;
            }
        }
        for u in enabled_added {
            if ![HELPER, EDGE, UPDATE_SERVICE].contains(&u.as_str()) {
                self.sd.start(u)?;
            }
        }
        Ok(())
    }

    /// Waits for `state.json.ready_version == version`, reading it relative to the open
    /// `data_dir` without following links.
    fn wait_ready(&self, data: &Dir, version: &str) -> bool {
        let start = self.sys.monotonic();
        loop {
            if read_ready_version(data).as_deref() == Some(version) {
                return true;
            }
            if self.sys.monotonic().saturating_sub(start) >= READY_WAIT {
                return false;
            }
            self.sys.sleep(READY_POLL);
        }
    }

    /// Rolls back after a failure past the snapshot, then records the outcome.
    fn roll_back_and_finish(
        &self,
        snap: &Snapshot,
        failed_stage: &'static str,
        why: &str,
        pending: &PendingFile,
    ) -> RunEnd {
        log(&format!(
            "update to {} failed at stage {failed_stage}: {why}; rolling back",
            snap.manifest.version
        ));
        let (request_id, version) = (snap.manifest.request_id.clone(), snap.manifest.version.clone());
        match self.roll_back(snap, true) {
            Ok(()) => {
                let end = self.finish(pending, Outcome::Failed, Some(failed_stage), request_id, version);
                self.forget_snapshot(snap);
                end
            }
            Err(e) => {
                log(&format!(
                    "rollback failed: {e}; keeping {} for the next run",
                    snapshot::NAME
                ));
                self.finish(
                    pending,
                    Outcome::Failed,
                    Some(stage::ROLLBACK),
                    request_id,
                    version,
                )
            }
        }
    }

    /// After a completed rollback: delete the snapshot and a version directory the run created.
    fn forget_snapshot(&self, snap: &Snapshot) {
        if let Err(e) = snapshot::delete(&self.bin, self.sys) {
            log(&format!("can't delete {}: {e}", snapshot::NAME));
        }
        let m = &snap.manifest;
        if m.created_version_dir
            && self.read_current().as_deref() != Some(m.version.as_str())
            && is_release_version(&m.version)
            && let Err(e) = self.bin.remove(&m.version)
        {
            log(&format!("can't delete bin/{}: {e}", m.version));
        }
    }

    /// Interrupted update: roll back from the snapshot (unit files, enablement, `bin/current`,
    /// active states), unless a result shows the run that wrote it finished.
    fn recover(&self, snap: &Snapshot, existing: Option<&UpdateResult>) -> std::result::Result<(), String> {
        let m = &snap.manifest;
        if let Some(r) = existing
            && r.result_id == m.result_id
            && (r.outcome == Outcome::Ok || r.stage.as_deref() != Some(stage::ROLLBACK))
        {
            // That run wrote its final result (success, or a completed rollback) and only the
            // snapshot delete didn't happen: rolling back now would undo a finished update.
            log(&format!(
                "{} belongs to a finished run ({}); deleting it",
                snapshot::NAME,
                r.result_id
            ));
            self.forget_snapshot(snap);
            return Ok(());
        }
        let same_boot = self.sys.boot_id().map(|b| b == m.boot_id).unwrap_or(false);
        log(&format!(
            "recovering from an interrupted update to {}{}",
            m.version,
            if same_boot {
                ""
            } else {
                " (recorded in another boot)"
            }
        ));
        self.roll_back(snap, same_boot)?;
        self.forget_snapshot(snap);
        Ok(())
    }

    /// The rollback of edge.md §14 step 4. Each step is retried with backoff; a step that still
    /// fails doesn't stop the others, so the system gets as close to the snapshot as it can, and
    /// the run then reports stage `rollback` and keeps the snapshot.
    fn roll_back(&self, snap: &Snapshot, same_boot: bool) -> std::result::Result<(), String> {
        let m = &snap.manifest;
        let mut failures: Vec<String> = Vec::new();
        let mut step = |what: String, r: Result<()>| {
            if let Err(e) = r {
                failures.push(format!("{what}: {e}"));
            }
        };
        let unit_dir = match units::open_unit_dir(self.root) {
            Ok(d) => d,
            Err(e) => return Err(format!("can't open the unit directory: {e}")),
        };
        // Active states hold only for the boot they were recorded in.
        let active = |name: &str| {
            m.units
                .get(name)
                .is_some_and(|u| u.active || (!same_boot && u.enabled))
        };
        let is_mask = |name: &str| snap.files.get(name).is_some_and(Installed::is_mask);
        let sd = &self.sd;

        // Stop, disable and delete each unit the snapshot doesn't hold (one the update added),
        // even when stopping it fails. As below, a unit that isn't running gets no stop, since a
        // stop also stops the units that require it.
        let now = match units::scan_installed(&unit_dir) {
            Ok(n) => n,
            Err(e) => {
                step("scan the unit directory".into(), Err(e));
                BTreeMap::new()
            }
        };
        for (name, entry) in &now {
            if snap.files.contains_key(name) || entry.is_mask() || name == UPDATE_SERVICE {
                continue;
            }
            step(
                format!("stop {name}"),
                sd.retry(&format!("stop {name}"), || {
                    if is_running(&sd.is_active(name)?) {
                        sd.stop(name)
                    } else {
                        Ok(())
                    }
                }),
            );
            step(
                format!("disable {name}"),
                sd.retry(&format!("disable {name}"), || sd.disable(name)),
            );
            step(
                format!("delete {name}"),
                sd.retry(&format!("delete {name}"), || {
                    unit_dir.remove(name).map(|_| ()).map_err(Into::into)
                }),
            );
        }

        // Put back the saved unit files byte for byte, then reload.
        for (name, saved) in &snap.files {
            if now.get(name) == Some(saved) {
                continue;
            }
            step(
                format!("restore {name}"),
                sd.retry(&format!("restore {name}"), || {
                    match saved {
                        Installed::File(b) => unit_dir.write_atomic(self.sys, name, b, 0o644, (0, 0)),
                        Installed::Symlink(t) => unit_dir.symlink_atomic(self.sys, name, t),
                    }
                    .map_err(Into::into)
                }),
            );
        }
        step(
            "daemon-reload".into(),
            sd.retry("daemon-reload", || sd.daemon_reload()),
        );

        // Re-enable every unit recorded as enabled, so its links are exactly what its restored
        // [Install] section names. A unit recorded as not enabled is left as it is.
        for (name, u) in &m.units {
            if u.enabled {
                step(
                    format!("reenable {name}"),
                    sd.retry(&format!("reenable {name}"), || sd.reenable(name)),
                );
            }
        }

        // Stop each unit recorded as not active that is running now, except the helper, the edge
        // and its own service. A unit that isn't running gets no stop.
        for name in m.units.keys() {
            if active(name) || [HELPER, EDGE, UPDATE_SERVICE].contains(&name.as_str()) || is_mask(name) {
                continue;
            }
            step(
                format!("stop {name}"),
                sd.retry(&format!("stop {name}"), || {
                    if is_running(&sd.is_active(name)?) {
                        sd.stop(name)
                    } else {
                        Ok(())
                    }
                }),
            );
        }

        // Point bin/current back, then restart the helper, the edge, and every other unit
        // recorded as active except its own service.
        if let Some(cur) = &m.current
            && !cur.is_empty()
            && !cur.contains('/')
            && cur != "."
            && cur != ".."
        {
            {
                step(
                    "point bin/current back".into(),
                    sd.retry("point bin/current back", || {
                        if self.read_current().as_deref() == Some(cur.as_str()) {
                            return Ok(());
                        }
                        self.bin
                            .symlink_atomic(self.sys, CURRENT, Path::new(cur))
                            .map_err(Into::into)
                    }),
                );
            }
        }
        for u in [HELPER, EDGE] {
            if m.units.contains_key(u) && !is_mask(u) {
                step(
                    format!("restart {u}"),
                    sd.retry(&format!("restart {u}"), || sd.restart(u)),
                );
            }
        }
        for name in m.units.keys() {
            if [HELPER, EDGE, UPDATE_SERVICE].contains(&name.as_str()) || !active(name) || is_mask(name) {
                continue;
            }
            step(
                format!("restart {name}"),
                sd.retry(&format!("restart {name}"), || sd.restart(name)),
            );
        }
        drop(step);
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    /// Keeps only these `bin/<version>/` directories (edge.md §2).
    fn prune(&self, keep: &[&str]) {
        let names = match self.bin.names(10_000) {
            Ok(n) => n,
            Err(e) => {
                log(&format!("can't list bin: {e}"));
                return;
            }
        };
        for name in names {
            if !is_release_version(&name) || keep.contains(&name.as_str()) {
                continue;
            }
            if let Ok(Some(meta)) = self.bin.lstat(&name)
                && meta.file_type().is_dir()
            {
                match self.bin.remove(&name) {
                    Ok(_) => log(&format!("deleted bin/{name}")),
                    Err(e) => log(&format!("can't delete bin/{name}: {e}")),
                }
            }
        }
    }

    /// Writes `bin/update-result.json` (`root:picket`, 0640), retrying a failure with backoff at
    /// most 3 times, as a rollback step. A result that still can't be written means the run
    /// hasn't recorded its end, so it keeps `pending.json` (edge.md §14, Interrupted update: a run
    /// deletes it only when it ends) and the run exits non-zero. The next run then finds the
    /// update installed and records `ok`, or, after a rollback, tries the update again as after
    /// a power cut at that point; either way the edge gets an outcome once the write works.
    fn write_result(
        &self,
        outcome: Outcome,
        failed_stage: Option<&str>,
        request_id: Option<String>,
        version: String,
    ) -> UpdateResult {
        let r = UpdateResult {
            result_id: self.result_id.clone(),
            request_id,
            outcome,
            stage: failed_stage.map(String::from),
            version,
            at: api::format_rfc3339_micros(self.sys.now()),
        };
        let written = self.sd.retry(&format!("write {}", result::NAME), || {
            result::write(&self.bin, self.sys, &r, self.gid).map_err(Into::into)
        });
        match written {
            Ok(()) => log(&format!(
                "result {}: {:?}{} for {:?}",
                r.result_id,
                r.outcome,
                r.stage
                    .as_deref()
                    .map(|s| format!(" at stage {s}"))
                    .unwrap_or_default(),
                r.version
            )),
            Err(e) => {
                log(&format!(
                    "can't write {}: {e}; keeping pending.json so a later run records the outcome",
                    result::NAME
                ));
                self.unrecorded.set(true);
            }
        }
        r
    }

    /// Records the result and ends the request.
    fn finish(
        &self,
        pending: &PendingFile,
        outcome: Outcome,
        failed_stage: Option<&str>,
        request_id: Option<String>,
        version: String,
    ) -> RunEnd {
        let r = self.write_result(outcome, failed_stage, request_id, version);
        self.delete_pending(Some(pending));
        RunEnd::Result(r)
    }

    /// Deletes `pending.json` (whatever it is) if it is still the entry this run read, unless the
    /// run's result couldn't be written. The directory is fsynced after, so a power cut can't
    /// bring the request back: one with a null `request_id` has no duplicate check and would run
    /// again.
    fn delete_pending(&self, pending: Option<&PendingFile>) {
        if self.unrecorded.get() {
            return;
        }
        let Some(PendingFile {
            dir: Some(dir),
            entry: Some((name, ident)),
            ..
        }) = pending
        else {
            return;
        };
        match dir.lstat(name) {
            Ok(Some(meta)) if (meta.dev(), meta.ino()) == *ident => {
                if let Err(e) = dir.remove(name).and_then(|_| dir.sync()) {
                    log(&format!("can't delete {}: {e}", dir.logical_at(name).display()));
                }
            }
            Ok(Some(_)) => log(&format!(
                "{} was replaced during the run; leaving it for the next run",
                dir.logical_at(name).display()
            )),
            Ok(None) => {}
            Err(e) => log(&format!("{}: {e}", dir.logical_at(name).display())),
        }
    }
}

/// The version `bin/current` points at: a link to `<version>` (as the updater writes it) or to
/// `<bin>/<version>`. Anything else (a link elsewhere, even to a directory of that name, a name
/// that isn't a version, or no link) is `None`, so `install` repairs it rather than trusting it.
pub fn read_current(bin: &Dir) -> Option<String> {
    let target = bin.read_link(CURRENT).ok().flatten()?;
    let name = target.file_name()?.to_str()?;
    let parent_ok = match target.parent() {
        None => true,
        Some(p) => p.as_os_str().is_empty() || p == bin.logical(),
    };
    (parent_ok && is_release_version(name)).then(|| name.to_string())
}

/// Reads `<data_dir>/releases/pending.json` (untrusted) without following links.
fn read_pending(data: &Dir) -> PendingFile {
    let releases = match data.subdir("releases") {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return PendingFile {
                dir: None,
                entry: None,
                state: PendingState::Missing,
            };
        }
        Err(e) if is_link_or_not_dir(&e) => {
            // Something the path unit may see through: remove it so it can't trigger forever.
            let entry = data
                .lstat("releases")
                .ok()
                .flatten()
                .map(|m| ("releases".to_string(), (m.dev(), m.ino())));
            return PendingFile {
                dir: data.try_clone().ok(),
                entry,
                state: PendingState::BadReleases,
            };
        }
        Err(e) => {
            return PendingFile {
                dir: None,
                entry: None,
                state: PendingState::Invalid(format!("can't open releases: {e}")),
            };
        }
    };
    let name = "pending.json";
    let meta = match releases.lstat(name) {
        Ok(Some(m)) => m,
        Ok(None) => {
            return PendingFile {
                dir: Some(releases),
                entry: None,
                state: PendingState::Missing,
            };
        }
        Err(e) => {
            return PendingFile {
                dir: Some(releases),
                entry: None,
                state: PendingState::Invalid(e.to_string()),
            };
        }
    };
    let entry = Some((name.to_string(), (meta.dev(), meta.ino())));
    if !meta.file_type().is_file() {
        return PendingFile {
            dir: Some(releases),
            entry,
            state: PendingState::NotRegular,
        };
    }
    let state = match releases.read_bounded(name, PENDING_MAX, true) {
        Ok(bytes) => parse_pending(&bytes),
        Err(ReadError::NotRegular) => PendingState::NotRegular,
        Err(e) => PendingState::Invalid(e.to_string()),
    };
    PendingFile {
        dir: Some(releases),
        entry,
        state,
    }
}

/// Parses `pending.json`. Public for the fuzz target.
pub fn parse_pending_bytes(bytes: &[u8]) -> std::result::Result<Pending, String> {
    let p: Pending = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if p.request_id.as_ref().is_some_and(|id| id.len() > REQUEST_ID_MAX) {
        return Err(format!("request_id longer than {REQUEST_ID_MAX} bytes"));
    }
    Ok(p)
}

fn parse_pending(bytes: &[u8]) -> PendingState {
    match parse_pending_bytes(bytes) {
        Ok(p) => PendingState::Valid(p),
        Err(e) => PendingState::Invalid(e),
    }
}

#[derive(Deserialize)]
struct StateReady {
    #[serde(default)]
    ready_version: Option<String>,
}

/// `state.json`'s `ready_version`, read relative to the open `data_dir` with `O_NOFOLLOW`.
pub fn read_ready_version(data: &Dir) -> Option<String> {
    let bytes = data.read_bounded("state.json", STATE_MAX, false).ok()?;
    parse_ready_version(&bytes)
}

/// Parses `state.json` (untrusted) for `ready_version`. Public for the fuzz target.
pub fn parse_ready_version(bytes: &[u8]) -> Option<String> {
    serde_json::from_slice::<StateReady>(bytes).ok()?.ready_version
}
