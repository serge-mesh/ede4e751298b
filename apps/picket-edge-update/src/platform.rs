//! Platforms, their paths, and what the updater reads from `edge.json`: `data_dir`, `ssd_dir`
//! and `release_keys` only (edge.md §2; edge-unifi.md §2, §9).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Context, Result};
use crate::fsx::{self, Dir, ReadError, Root};
use crate::system::System;

/// `--platform unifi|debian` (edge-unifi.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Unifi,
    Debian,
}

impl Platform {
    pub fn parse(s: &str) -> Option<Platform> {
        match s {
            "unifi" => Some(Platform::Unifi),
            "debian" => Some(Platform::Debian),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Unifi => "unifi",
            Platform::Debian => "debian",
        }
    }

    /// The default: `unifi` if `/data/udapi-config/ubios-udapi-server/` exists, else `debian`.
    pub fn detect(root: &Root) -> Platform {
        if root.real("/data/udapi-config/ubios-udapi-server").is_dir() {
            Platform::Unifi
        } else {
            Platform::Debian
        }
    }
}

/// Where systemd units go on both platforms: they survive firmware upgrades there
/// (edge-unifi.md §1) and load before `/data` is mounted (§2 step 5).
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// The fixed paths of a platform (edge-unifi.md §2 and §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub platform: Platform,
    /// The root-owned install directory; `bin/` lives under it.
    pub install_dir: &'static str,
    pub bin_dir: &'static str,
    /// The config directory: `edge.json` and `sysusers.conf`.
    pub config_dir: &'static str,
    pub edge_json: &'static str,
    /// `<helper_dir>`, the helper's `--state-dir`.
    pub helper_dir: &'static str,
    pub default_data_dir: &'static str,
}

impl Layout {
    pub fn for_platform(platform: Platform) -> Layout {
        match platform {
            Platform::Unifi => Layout {
                platform,
                install_dir: "/data/picket",
                bin_dir: "/data/picket/bin",
                config_dir: "/data/picket/etc",
                edge_json: "/data/picket/etc/edge.json",
                helper_dir: "/data/picket/helper",
                default_data_dir: "/data/picket/var",
            },
            Platform::Debian => Layout {
                platform,
                install_dir: "/opt/picket",
                bin_dir: "/opt/picket/bin",
                config_dir: "/etc/picket",
                edge_json: "/etc/picket/edge.json",
                helper_dir: "/var/lib/picket-helper",
                default_data_dir: "/var/lib/picket",
            },
        }
    }
}

// Compiled-in default `release_keys` (build-and-test.md §1), populated at build time from
// `PICKET_RELEASE_PUB` / `PICKET_RELEASE_PUB_FILE`.
include!(concat!(env!("OUT_DIR"), "/release_keys.rs"));

/// The compiled-in minisign public key lines.
pub fn default_release_keys() -> Vec<String> {
    RELEASE_KEYS.iter().map(|k| (*k).to_owned()).collect()
}

/// What the updater takes from `edge.json`, with defaults filled in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub data_dir: String,
    pub ssd_dir: Option<String>,
    /// minisign public keys (base64).
    pub release_keys: Vec<String>,
    /// Why defaults replaced something from `edge.json`, for the journal.
    pub notes: Vec<String>,
}

impl Settings {
    pub fn defaults(layout: &Layout) -> Settings {
        Settings {
            data_dir: layout.default_data_dir.to_string(),
            ssd_dir: None,
            release_keys: default_release_keys(),
            notes: Vec::new(),
        }
    }

    /// The SSD's mount point: `ssd_dir`'s parent (edge-unifi.md §1).
    pub fn ssd_mount(&self) -> Option<String> {
        let ssd = self.ssd_dir.as_deref()?;
        Path::new(ssd).parent().map(|p| p.to_string_lossy().into_owned())
    }
}

/// Who reads the settings: the update run must survive a bad `edge.json`, and trusts its
/// `release_keys` only if picket-edge can't have written them (security.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Install,
    Units,
    Update,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct EdgeJson {
    data_dir: Option<String>,
    ssd_dir: Option<String>,
    release_keys: Option<Vec<String>>,
}

const EDGE_JSON_MAX: u64 = 1024 * 1024;
const MAX_KEYS: usize = 64;

/// Checks a directory from `edge.json` before it reaches a unit file or a path: absolute,
/// normalised, and only characters that need no quoting or escaping in a unit file (no spaces,
/// `%` specifiers, quotes or newlines).
pub fn check_dir_setting(field: &str, value: &str) -> Result<()> {
    let ok_chars = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._+-".contains(&b));
    if value.len() > 512 || !ok_chars || !fsx::is_normal_absolute(Path::new(value)) || value == "/" {
        crate::bail!(
            "edge.json: {field} {value:?} must be an absolute, normalised path of letters, digits and ._+-"
        );
    }
    if field == "ssd_dir" && Path::new(value).parent() == Some(Path::new("/")) {
        crate::bail!(
            "edge.json: ssd_dir {value:?} must be a folder under the SSD's mount point, not under /"
        );
    }
    Ok(())
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// `data_dir` belongs to the edge (`picket:picket`), so it may not overlap a root-owned path: one
/// holding `bin/`, the config directory, `<helper_dir>` or the units would let the edge replace
/// what root runs or trusts, or take the helper's state (edge.md §2, security.md §3). It may sit
/// under the install directory, as on UniFi, but not contain it.
pub fn check_data_dir(layout: &Layout, data_dir: &str) -> Result<()> {
    let d = Path::new(data_dir);
    if Path::new(layout.install_dir).starts_with(d) {
        crate::bail!("edge.json: data_dir {data_dir:?} contains {}", layout.install_dir);
    }
    for p in [layout.bin_dir, layout.config_dir, layout.helper_dir, UNIT_DIR] {
        if overlaps(d, Path::new(p)) {
            crate::bail!("edge.json: data_dir {data_dir:?} overlaps {p}, which root owns");
        }
    }
    Ok(())
}

/// `ssd_dir` belongs to the edge too: it may overlap neither a root-owned path nor `data_dir`.
pub fn check_ssd_dir(layout: &Layout, ssd_dir: &str, data_dir: &str) -> Result<()> {
    let s = Path::new(ssd_dir);
    for p in [
        layout.install_dir,
        layout.bin_dir,
        layout.config_dir,
        layout.helper_dir,
        UNIT_DIR,
    ] {
        if overlaps(s, Path::new(p)) {
            crate::bail!("edge.json: ssd_dir {ssd_dir:?} overlaps {p}, which root owns");
        }
    }
    if overlaps(s, Path::new(data_dir)) {
        crate::bail!("edge.json: ssd_dir {ssd_dir:?} overlaps data_dir {data_dir:?}");
    }
    Ok(())
}

/// Reads the settings. `Install` and `Units` refuse a bad `edge.json`; `Update` falls back to the
/// defaults and notes why.
pub fn load_settings(root: &Root, layout: &Layout, sys: &dyn System, purpose: Purpose) -> Result<Settings> {
    let mut s = Settings::defaults(layout);
    let parsed = match read_edge_json(root, layout) {
        Ok(None) => return Ok(s),
        Ok(Some(bytes)) if purpose != Purpose::Update => {
            parse_edge_json(&bytes).with_context(|| format!("{} is invalid", layout.edge_json))?
        }
        Ok(Some(bytes)) => match parse_edge_json(&bytes) {
            Ok(p) => p,
            Err(e) => {
                s.notes.push(format!(
                    "{} is invalid ({e}); using the defaults",
                    layout.edge_json
                ));
                return Ok(s);
            }
        },
        Err(e) if purpose != Purpose::Update => return Err(e),
        Err(e) => {
            s.notes.push(format!("{e}; using the defaults"));
            return Ok(s);
        }
    };
    for (field, value) in [("data_dir", &parsed.data_dir), ("ssd_dir", &parsed.ssd_dir)] {
        if let Some(v) = value {
            if let Err(e) = check_dir_setting(field, v) {
                if purpose != Purpose::Update {
                    return Err(e);
                }
                s.notes.push(format!("{e}; using the default"));
                continue;
            }
            match field {
                "data_dir" => s.data_dir = v.clone(),
                _ => s.ssd_dir = Some(v.clone()),
            }
        }
    }
    if let Err(e) = check_data_dir(layout, &s.data_dir) {
        if purpose != Purpose::Update {
            return Err(e);
        }
        s.notes.push(format!("{e}; using the default"));
        s.data_dir = layout.default_data_dir.to_string();
    }
    if let Some(ssd) = s.ssd_dir.clone()
        && let Err(e) = check_ssd_dir(layout, &ssd, &s.data_dir)
    {
        if purpose != Purpose::Update {
            return Err(e);
        }
        s.notes.push(format!("{e}; ignoring it"));
        s.ssd_dir = None;
    }
    if let Some(mut keys) = parsed.release_keys {
        if keys.len() > MAX_KEYS {
            // Trusting none is safer than falling back: verification then fails, visibly.
            s.notes.push(format!(
                "{}: more than {MAX_KEYS} release_keys; using none",
                layout.edge_json
            ));
            keys.clear();
        }
        match purpose {
            Purpose::Update => match edge_json_trusted(root, layout, sys) {
                Ok(()) => s.release_keys = keys,
                Err(why) => s.notes.push(format!(
                    "not trusting release_keys in {}: {why}; using the compiled-in key",
                    layout.edge_json
                )),
            },
            _ => s.release_keys = keys,
        }
    }
    Ok(s)
}

fn parse_edge_json(bytes: &[u8]) -> serde_json::Result<EdgeJson> {
    serde_json::from_slice(bytes)
}

/// Reads `edge.json` without following a link; `None` if there is none.
fn read_edge_json(root: &Root, layout: &Layout) -> Result<Option<Vec<u8>>> {
    let dir = match Dir::open(root, layout.config_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("can't open {}", layout.config_dir)),
    };
    match dir.read_bounded("edge.json", EDGE_JSON_MAX, false) {
        Ok(b) => Ok(Some(b)),
        Err(ReadError::Missing) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("can't read {}", layout.edge_json)),
    }
}

/// `edge.json` and every directory above it must be root-owned and writable by root alone, so
/// picket-edge can't have chosen the keys the updater trusts (edge.md §2, security.md §3).
pub fn edge_json_trusted(root: &Root, layout: &Layout, sys: &dyn System) -> std::result::Result<(), String> {
    let dir = Dir::open(root, layout.config_dir).map_err(|e| format!("{}: {e}", layout.config_dir))?;
    let (file, meta) = dir
        .open_regular("edge.json")
        .map_err(|e| format!("{}: {e}", layout.edge_json))?;
    drop(file);
    check_root_only(sys, &meta, Path::new(layout.edge_json), false)?;
    if meta.nlink() != 1 {
        return Err(format!("{} has more than one hard link", layout.edge_json));
    }
    let mut p = PathBuf::from(layout.config_dir);
    loop {
        let meta = std::fs::symlink_metadata(root.real(&p)).map_err(|e| format!("{}: {e}", p.display()))?;
        if !meta.file_type().is_dir() {
            return Err(format!("{} isn't a directory", p.display()));
        }
        check_root_only(sys, &meta, &p, false)?;
        if !p.pop() {
            break;
        }
    }
    Ok(())
}

/// Root owns it and nobody else can write it. With `sticky_ok`, a directory others may write
/// passes if it has the sticky bit (like `/tmp`): others can't rename or delete root's entries
/// there.
pub fn check_root_only(
    sys: &dyn System,
    meta: &std::fs::Metadata,
    logical: &Path,
    sticky_ok: bool,
) -> std::result::Result<(), String> {
    let (uid, _) = sys.owner(meta, logical);
    if uid != 0 {
        return Err(format!("{} is owned by uid {uid}, not root", logical.display()));
    }
    let sticky = sticky_ok && meta.file_type().is_dir() && meta.mode() & 0o1000 != 0;
    if meta.mode() & 0o022 != 0 && !sticky {
        return Err(format!(
            "{} is writable by group or others (mode {:o})",
            logical.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_keys_are_valid_minisign_keys() {
        let keys = default_release_keys();
        for k in &keys {
            assert!(minisign_verify::PublicKey::from_base64(k).is_ok(), "{k:?}");
        }
    }

    #[test]
    fn dir_settings() {
        for ok in ["/data/picket/var", "/volume1/.picket", "/var/lib/picket"] {
            check_dir_setting("data_dir", ok).unwrap();
        }
        check_dir_setting("ssd_dir", "/volume1/.picket").unwrap();
        for bad in [
            "",
            "/",
            "relative",
            "/a b",
            "/a\nExecStartPre=+/bin/sh",
            "/a/../b",
            "/a/",
            "/a%i",
            "/a\"b",
        ] {
            assert!(check_dir_setting("data_dir", bad).is_err(), "{bad:?}");
        }
        assert!(check_dir_setting("ssd_dir", "/.picket").is_err());
    }

    #[test]
    fn edge_dirs_never_overlap_root_owned_paths() {
        let u = Layout::for_platform(Platform::Unifi);
        check_data_dir(&u, "/data/picket/var").unwrap();
        check_data_dir(&u, "/data/picket/var2").unwrap();
        check_data_dir(&u, "/data/picket/helperx").unwrap();
        for bad in [
            "/data",
            "/data/picket",
            "/data/picket/bin",
            "/data/picket/bin/x",
            "/data/picket/etc",
            "/data/picket/helper",
            "/data/picket/helper/x",
            "/etc",
            "/etc/systemd/system/x",
        ] {
            assert!(check_data_dir(&u, bad).is_err(), "{bad}");
        }
        check_ssd_dir(&u, "/volume1/.picket", "/data/picket/var").unwrap();
        for bad in [
            "/data/picket/x",
            "/data/picket/bin/ssd",
            "/data/picket/var/ssd",
            "/etc/systemd",
        ] {
            assert!(check_ssd_dir(&u, bad, "/data/picket/var").is_err(), "{bad}");
        }
        assert!(check_ssd_dir(&u, "/volume1/.picket", "/volume1/.picket/var").is_err());
        let d = Layout::for_platform(Platform::Debian);
        check_data_dir(&d, "/var/lib/picket").unwrap();
        check_ssd_dir(&d, "/mnt/ssd/.picket", "/var/lib/picket").unwrap();
        assert!(check_data_dir(&d, "/var/lib/picket-helper").is_err());
        assert!(check_data_dir(&d, "/opt").is_err());
        assert!(check_data_dir(&d, "/etc/picket/var").is_err());
    }

    /// `install` and `units` refuse an overlapping directory; an update falls back to the
    /// default and notes why, so it still ends its request.
    #[test]
    fn overlapping_dirs_per_purpose() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Root::new(tmp.path());
        let layout = Layout::for_platform(Platform::Unifi);
        std::fs::create_dir_all(tmp.path().join("data/picket/etc")).unwrap();
        std::fs::write(
            tmp.path().join("data/picket/etc/edge.json"),
            r#"{"data_dir": "/data/picket/helper", "ssd_dir": "/data/picket/helper/ssd"}"#,
        )
        .unwrap();
        let sys = crate::system::RealSystem::default();
        for p in [Purpose::Install, Purpose::Units] {
            let e = load_settings(&root, &layout, &sys, p).unwrap_err().to_string();
            assert!(e.contains("overlaps /data/picket/helper"), "{e}");
        }
        let s = load_settings(&root, &layout, &sys, Purpose::Update).unwrap();
        assert_eq!(s.data_dir, "/data/picket/var");
        assert_eq!(s.ssd_dir, None);
        assert_eq!(s.notes.len(), 2, "{:?}", s.notes);
    }

    #[test]
    fn layouts() {
        let u = Layout::for_platform(Platform::Unifi);
        assert_eq!(u.bin_dir, "/data/picket/bin");
        assert_eq!(u.edge_json, "/data/picket/etc/edge.json");
        let d = Layout::for_platform(Platform::Debian);
        assert_eq!(d.edge_json, "/etc/picket/edge.json");
        assert_eq!(d.helper_dir, "/var/lib/picket-helper");
        assert_eq!(Platform::parse("unifi"), Some(Platform::Unifi));
        assert_eq!(Platform::parse("UniFi"), None);
    }

    #[test]
    fn detection() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Root::new(tmp.path());
        assert_eq!(Platform::detect(&root), Platform::Debian);
        std::fs::create_dir_all(tmp.path().join("data/udapi-config/ubios-udapi-server")).unwrap();
        assert_eq!(Platform::detect(&root), Platform::Unifi);
    }
}
