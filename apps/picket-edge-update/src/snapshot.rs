//! `bin/.units-prev/`, the rollback snapshot (edge.md §14 step 3): each current `picket-*` unit
//! file byte for byte, the version `bin/current` points at, each unit's enabled and active state,
//! and the boot ID. Written under a temporary name and renamed into place; a snapshot still under
//! its temporary name is deleted, since nothing had changed yet (Interrupted update).
//!
//! Layout: `snapshot.json` (the manifest) and `units/<name>` (each regular unit file).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::fsx::{Dir, ReadError};
use crate::system::System;
use crate::units::Installed;

pub const NAME: &str = ".units-prev";
pub const TEMP_NAME: &str = ".units-prev.tmp";
/// A snapshot being deleted: renamed first, so a delete cut short never looks like a snapshot.
pub const TRASH_PREFIX: &str = ".units-prev.trash-";
const MANIFEST: &str = "snapshot.json";
const UNITS: &str = "units";
pub const FORMAT: u32 = 1;
const MANIFEST_MAX: u64 = 1024 * 1024;
const UNIT_MAX: u64 = 1024 * 1024;

/// One unit as it was before the update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapUnit {
    /// `file` or `symlink`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `systemctl is-enabled` printed `enabled`.
    pub enabled: bool,
    /// `systemctl is-active` printed `active`.
    pub active: bool,
}

/// The manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    /// The result id the run that wrote this snapshot uses: a result carrying it shows that run
    /// finished (see `update::recover`).
    pub result_id: String,
    pub request_id: Option<String>,
    /// The version being installed.
    pub version: String,
    /// The run created `bin/<version>/` (it didn't exist before), so a rollback removes it.
    pub created_version_dir: bool,
    /// What `bin/current` pointed at.
    pub current: Option<String>,
    pub boot_id: String,
    pub units: BTreeMap<String, SnapUnit>,
}

/// A snapshot read back: the manifest and the saved unit entries.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub manifest: Manifest,
    pub files: BTreeMap<String, Installed>,
}

/// Writes the snapshot: under [`TEMP_NAME`], fsynced, then renamed to [`NAME`].
pub fn write(
    bin: &Dir,
    sys: &dyn System,
    manifest: &Manifest,
    files: &BTreeMap<String, Installed>,
) -> std::io::Result<()> {
    bin.remove(TEMP_NAME)?;
    bin.mkdir(TEMP_NAME, 0o700)?;
    let tmp = bin.subdir(TEMP_NAME)?;
    tmp.mkdir(UNITS, 0o700)?;
    let units = tmp.subdir(UNITS)?;
    for (name, entry) in files {
        if let Installed::File(bytes) = entry {
            let mut f = units.create_new(name, 0o600)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
    }
    units.sync()?;
    let mut f = tmp.create_new(MANIFEST, 0o600)?;
    f.write_all(&serde_json::to_vec_pretty(manifest).map_err(std::io::Error::other)?)?;
    f.sync_all()?;
    tmp.sync()?;
    sys.checkpoint("snapshot-before-rename")?;
    bin.rename(TEMP_NAME, NAME)?;
    bin.sync()
}

/// Reads the snapshot, if there is one.
pub fn read(bin: &Dir) -> Result<Option<Snapshot>, String> {
    let dir = match bin.subdir(NAME) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{NAME}: {e}")),
    };
    let bytes = dir
        .read_bounded(MANIFEST, MANIFEST_MAX, false)
        .map_err(|e| format!("{NAME}/{MANIFEST}: {e}"))?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| format!("{NAME}/{MANIFEST}: {e}"))?;
    if manifest.format != FORMAT {
        return Err(format!("{NAME}: unknown format {}", manifest.format));
    }
    let units = dir.subdir(UNITS).map_err(|e| format!("{NAME}/{UNITS}: {e}"))?;
    let mut files = BTreeMap::new();
    for (name, u) in &manifest.units {
        if !crate::units::is_managed_name(name) {
            return Err(format!("{NAME}: unexpected unit name {name:?}"));
        }
        let entry = match (u.kind.as_str(), &u.target) {
            ("file", _) => match units.read_bounded(name, UNIT_MAX, false) {
                Ok(b) => Installed::File(b),
                Err(ReadError::Missing) => return Err(format!("{NAME}: {name} is missing")),
                Err(e) => return Err(format!("{NAME}/{UNITS}/{name}: {e}")),
            },
            ("symlink", Some(t)) => Installed::Symlink(PathBuf::from(t)),
            _ => return Err(format!("{NAME}: bad entry for {name}")),
        };
        files.insert(name.clone(), entry);
    }
    Ok(Some(Snapshot { manifest, files }))
}

/// The manifest entry for an installed unit.
pub fn snap_unit(entry: &Installed, enabled: bool, active: bool) -> SnapUnit {
    match entry {
        Installed::File(_) => SnapUnit {
            kind: "file".into(),
            target: None,
            enabled,
            active,
        },
        Installed::Symlink(t) => SnapUnit {
            kind: "symlink".into(),
            target: Some(t.to_string_lossy().into_owned()),
            enabled,
            active,
        },
    }
}

/// Deletes the snapshot: renamed to a trash name first (atomic), then removed.
pub fn delete(bin: &Dir, sys: &dyn System) -> std::io::Result<()> {
    if bin.lstat(NAME)?.is_none() {
        return Ok(());
    }
    sys.checkpoint("snapshot-delete")?;
    let trash = format!("{TRASH_PREFIX}{:016x}", sys.random_u64()?);
    bin.rename(NAME, &trash)?;
    bin.sync()?;
    bin.remove(&trash)?;
    Ok(())
}

/// Deletes a snapshot left under its temporary name and any half-deleted snapshot.
pub fn delete_leftovers(bin: &Dir) -> std::io::Result<Vec<String>> {
    let mut removed = Vec::new();
    for name in bin.names(10_000)? {
        if name == TEMP_NAME || name.starts_with(TRASH_PREFIX) {
            bin.remove(&name)?;
            removed.push(name);
        }
    }
    Ok(removed)
}
