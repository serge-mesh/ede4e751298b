//! Platform detection, default paths and the `data_dir` layout (edge.md §2, edge-unifi.md §2, §9).

use std::path::{Path, PathBuf};

/// The directory whose presence marks a UniFi gateway, as picket-edge-update decides
/// (edge-unifi.md §2 `--platform`).
pub const UNIFI_MARKER: &str = "/data/udapi-config/ubios-udapi-server/";

/// Default runtime directory (the unit's `RuntimeDirectory=picket`).
pub const DEFAULT_RUNTIME_DIR: &str = "/run/picket";

/// The admin socket's file name inside the runtime directory.
pub const ADMIN_SOCKET: &str = "edge.sock";

/// The host platform, picked like picket-edge-update does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPlatform {
    Unifi,
    Debian,
}

impl HostPlatform {
    pub fn detect() -> Self {
        Self::detect_with(Path::new(UNIFI_MARKER))
    }

    pub fn detect_with(marker: &Path) -> Self {
        if marker.is_dir() {
            Self::Unifi
        } else {
            Self::Debian
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unifi => "unifi",
            Self::Debian => "debian",
        }
    }

    /// Default `edge.json` (edge.md §2).
    pub fn default_config(self) -> PathBuf {
        match self {
            Self::Unifi => PathBuf::from("/data/picket/etc/edge.json"),
            Self::Debian => PathBuf::from("/etc/picket/edge.json"),
        }
    }

    /// Default `data_dir` (edge-unifi.md §2, §9).
    pub fn default_data_dir(self) -> PathBuf {
        match self {
            Self::Unifi => PathBuf::from("/data/picket/var"),
            Self::Debian => PathBuf::from("/var/lib/picket"),
        }
    }
}

/// The installed layout's `bin/` directory, found from our own executable: an installed edge runs
/// as `<install>/bin/<version>/picket-edge` next to `<install>/bin/current`. Anything else (a
/// development build) has no install directory, so no updater result to import (edge.md §14).
pub fn install_bin_dir() -> Option<PathBuf> {
    let exe = std::fs::read_link("/proc/self/exe").ok()?;
    install_bin_dir_from(&exe)
}

pub fn install_bin_dir_from(exe: &Path) -> Option<PathBuf> {
    let s = exe.to_str()?;
    let exe = Path::new(s.strip_suffix(" (deleted)").unwrap_or(s));
    let version_dir = exe.parent()?;
    let bin = version_dir.parent()?;
    let current = bin.join("current");
    std::fs::symlink_metadata(&current).ok()?;
    Some(bin.to_path_buf())
}

/// Paths inside `data_dir` (edge.md §2).
#[derive(Clone, Debug)]
pub struct DataLayout {
    pub root: PathBuf,
}

impl DataLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn identity_dir(&self) -> PathBuf {
        self.root.join("identity")
    }
    pub fn state_json(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }
    pub fn bundles_dir(&self) -> PathBuf {
        self.root.join("bundles")
    }
    pub fn verdicts_dir(&self) -> PathBuf {
        self.root.join("verdicts")
    }
    pub fn tls_dir(&self) -> PathBuf {
        self.root.join("tls")
    }
    pub fn spool_dir(&self) -> PathBuf {
        self.root.join("spool")
    }
    pub fn allows_json(&self) -> PathBuf {
        self.root.join("allows.json")
    }
    pub fn ssd_id(&self) -> PathBuf {
        self.root.join("ssd-id")
    }
    pub fn releases_dir(&self) -> PathBuf {
        self.root.join("releases")
    }
}

/// Paths under `ssd_dir` (edge-unifi.md §1).
#[derive(Clone, Debug)]
pub struct SsdLayout {
    pub root: PathBuf,
}

impl SsdLayout {
    pub fn marker(&self) -> PathBuf {
        self.root.join(".picket-ssd")
    }
    pub fn bundles_dir(&self) -> PathBuf {
        self.root.join("bundles")
    }
    pub fn spool_dir(&self) -> PathBuf {
        self.root.join("spool")
    }
    pub fn verdicts_dir(&self) -> PathBuf {
        self.root.join("verdicts")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_and_install_dir() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            HostPlatform::detect_with(&d.path().join("nope")),
            HostPlatform::Debian
        );
        assert_eq!(HostPlatform::detect_with(d.path()), HostPlatform::Unifi);

        let bin = d.path().join("bin");
        std::fs::create_dir_all(bin.join("1.4.0")).unwrap();
        let exe = bin.join("1.4.0/picket-edge");
        assert_eq!(install_bin_dir_from(&exe), None);
        std::os::unix::fs::symlink("1.4.0", bin.join("current")).unwrap();
        assert_eq!(install_bin_dir_from(&exe), Some(bin.clone()));
        let deleted = PathBuf::from(format!("{} (deleted)", exe.display()));
        assert_eq!(install_bin_dir_from(&deleted), Some(bin));
    }
}
