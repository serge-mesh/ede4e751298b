//! The unit files this version writes (edge-unifi.md §2 step 5), compiled in from `dist/edge/`
//! (build-and-test.md §1), and the `picket-*` units installed in `/etc/systemd/system`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::api::{UNITS_FORMAT, UnitsOutput};
use crate::fsx::{Dir, ReadError, Root};
use crate::platform::{Layout, Platform, Settings, UNIT_DIR};

pub const ACCOUNTS: &str = "picket-accounts.service";
pub const EDGE: &str = "picket-edge.service";
pub const HELPER: &str = "picket-edge-helper.service";
pub const UPDATE_PATH: &str = "picket-edge-update.path";
/// The updater's own service: nothing here ever starts, stops or restarts it (edge.md §14).
pub const UPDATE_SERVICE: &str = "picket-edge-update.service";

const TEMPLATES: [(&str, &str); 5] = [
    (
        ACCOUNTS,
        include_str!("../../../dist/edge/picket-accounts.service"),
    ),
    (EDGE, include_str!("../../../dist/edge/picket-edge.service")),
    (
        HELPER,
        include_str!("../../../dist/edge/picket-edge-helper.service"),
    ),
    (
        UPDATE_PATH,
        include_str!("../../../dist/edge/picket-edge-update.path"),
    ),
    (
        UPDATE_SERVICE,
        include_str!("../../../dist/edge/picket-edge-update.service"),
    ),
];

/// UniFi's memory settings for the edge and helper units (edge-unifi.md §6).
const UNIFI_EDGE_MEMORY: &str = include_str!("../../../dist/edge/unifi-edge-memory.conf");
const UNIFI_HELPER_MEMORY: &str = include_str!("../../../dist/edge/unifi-helper-memory.conf");

/// Caps on a release's `units` output, beyond the 1 MiB output cap.
pub const MAX_UNITS: usize = 64;
const MAX_UNIT_FILE: u64 = 1024 * 1024;
const MAX_UNIT_DIR_ENTRIES: usize = 100_000;

/// Fills the templates for a platform and `edge.json`'s settings. `install` writes exactly this
/// and `units` prints it, so both write the same text (edge-unifi.md §2).
pub fn render(layout: &Layout, settings: &Settings) -> BTreeMap<String, String> {
    let ssd_rw = settings
        .ssd_mount()
        .map(|m| format!("ReadWritePaths=-{m}"))
        .unwrap_or_default();
    let (edge_platform, helper_platform) = match layout.platform {
        Platform::Unifi => (UNIFI_EDGE_MEMORY.trim_end(), UNIFI_HELPER_MEMORY.trim_end()),
        Platform::Debian => ("", ""),
    };
    let vars: [(&str, &str); 9] = [
        ("PLATFORM", layout.platform.as_str()),
        ("INSTALL_DIR", layout.install_dir),
        ("DATA_DIR", &settings.data_dir),
        ("CONFIG_DIR", layout.config_dir),
        ("CONFIG_FILE", layout.edge_json),
        ("HELPER_DIR", layout.helper_dir),
        ("SSD_READ_WRITE", &ssd_rw),
        ("EDGE_PLATFORM", edge_platform),
        ("HELPER_PLATFORM", helper_platform),
    ];
    TEMPLATES
        .iter()
        .map(|(name, text)| (name.to_string(), fill(text, &vars)))
        .collect()
}

/// Replaces `{{NAME}}`; a line holding only a placeholder that is empty is dropped.
fn fill(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    for line in template.lines() {
        let mut l = line.to_string();
        let mut only_empty = false;
        for (k, v) in vars {
            let ph = format!("{{{{{k}}}}}");
            if l.trim() == ph && v.is_empty() {
                only_empty = true;
                break;
            }
            l = l.replace(&ph, v);
        }
        if !only_empty {
            out.push_str(&l);
            out.push('\n');
        }
    }
    out
}

/// The `units` output for this version.
pub fn units_output(layout: &Layout, settings: &Settings) -> UnitsOutput {
    UnitsOutput {
        format: UNITS_FORMAT,
        units: render(layout, settings),
    }
}

/// A `picket-*.service`, `picket-*.path` or `picket-*.timer` file name (edge.md §14 step 3), in
/// the characters systemd allows in a unit name (ASCII letters, digits and `:-_.\`, plus one `@`
/// before an instance, as in `picket-x@y.service`), at most 255 bytes. Refused: a template
/// (`picket-x@.service`), since its instances are what run and no update step could start,
/// restart or retire them through it; `picket-core*`, which is core's ([`is_managed_name`]); and
/// `..`.
pub fn is_release_unit_name(name: &str) -> bool {
    let Some(stem) = name
        .strip_suffix(".service")
        .or_else(|| name.strip_suffix(".path"))
        .or_else(|| name.strip_suffix(".timer"))
    else {
        return false;
    };
    let Some(rest) = stem.strip_prefix("picket-") else {
        return false;
    };
    name.len() <= 255
        && !rest.is_empty()
        && is_managed_name(name)
        && !name.contains("..")
        && name.bytes().filter(|&b| b == b'@').count() <= 1
        && !stem.ends_with('@')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:\\@".contains(&b))
}

/// Parses and checks a release's `units` output: a format this updater knows, release unit
/// names only, both update units present, no NUL in any text (edge.md §14 step 3).
pub fn parse_units_output(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let out: UnitsOutput = serde_json::from_slice(bytes).map_err(|e| format!("not units JSON: {e}"))?;
    if out.format != UNITS_FORMAT {
        return Err(format!("unknown units format {}", out.format));
    }
    if out.units.len() > MAX_UNITS {
        return Err(format!("more than {MAX_UNITS} units"));
    }
    for (name, text) in &out.units {
        if !is_release_unit_name(name) {
            return Err(format!(
                "{name:?} isn't a picket-*.service, .path or .timer file name"
            ));
        }
        if text.contains('\0') {
            return Err(format!("{name} contains a NUL byte"));
        }
    }
    for required in [UPDATE_PATH, UPDATE_SERVICE] {
        if !out.units.contains_key(required) {
            return Err(format!("{required} is missing"));
        }
    }
    Ok(out.units)
}

/// True when a unit's `[Install]` section names something `enable` acts on. A unit without one
/// is left to whatever triggers it (edge.md §14 step 3).
pub fn has_install_section(text: &[u8]) -> bool {
    !install_entries(text).is_empty()
}

/// The `[Install]` entries (`WantedBy=`, `RequiredBy=`, `UpheldBy=`, `Alias=`, `Also=`) of a unit.
pub fn install_entries(text: &[u8]) -> Vec<(String, String)> {
    section_entries(text, "Install")
        .into_iter()
        .filter(|(k, v)| {
            matches!(
                k.as_str(),
                "WantedBy" | "RequiredBy" | "UpheldBy" | "Alias" | "Also"
            ) && !v.is_empty()
        })
        .collect()
}

/// The `key=value` lines of one section (no continuation lines; our units have none).
pub fn section_entries(text: &[u8], section: &str) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(text);
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            inside = &line[1..line.len() - 1] == section;
            continue;
        }
        if inside && let Some((k, v)) = line.split_once('=') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// An installed unit entry in `/etc/systemd/system`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Installed {
    File(Vec<u8>),
    /// A symlink unit file; `/dev/null` is a mask.
    Symlink(PathBuf),
}

impl Installed {
    pub fn is_mask(&self) -> bool {
        matches!(self, Installed::Symlink(t) if t == Path::new("/dev/null"))
    }

    /// True when the entry holds exactly this text as a regular file.
    pub fn is_file_with(&self, text: &str) -> bool {
        matches!(self, Installed::File(b) if b == text.as_bytes())
    }
}

/// Unit types systemd knows, for recognising `picket-*` units to retire.
const UNIT_SUFFIXES: [&str; 11] = [
    ".service",
    ".socket",
    ".device",
    ".mount",
    ".automount",
    ".swap",
    ".target",
    ".path",
    ".timer",
    ".slice",
    ".scope",
];

/// A `picket-*` unit file name the updater manages. `picket-core*` is excluded: core's units
/// are never an edge release's, and an admin running core on a Debian test host may have copied
/// them into `/etc/systemd/system` (`systemctl edit --full`).
pub fn is_managed_name(name: &str) -> bool {
    name.starts_with("picket-")
        && !name.starts_with("picket-core")
        && UNIT_SUFFIXES
            .iter()
            .any(|s| name.ends_with(s) && name.len() > s.len() + "picket-".len())
        && !name.contains('/')
}

/// Opens the unit directory.
pub fn open_unit_dir(root: &Root) -> std::io::Result<Dir> {
    Dir::open(root, UNIT_DIR)
}

/// Every managed `picket-*` unit file in `/etc/systemd/system`: regular files and symlinks
/// (masks included), but not directories (drop-ins, `.wants`) and not aliases that `enable`
/// created (symlinks to another unit in the same directory).
pub fn scan_installed(dir: &Dir) -> crate::error::Result<BTreeMap<String, Installed>> {
    use crate::error::Context;
    let mut out = BTreeMap::new();
    for name in dir
        .names(MAX_UNIT_DIR_ENTRIES)
        .context("can't list the unit directory")?
    {
        if !is_managed_name(&name) {
            continue;
        }
        let Some(meta) = dir.lstat(&name)? else { continue };
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = dir.read_link(&name)?.unwrap_or_default();
            let is_alias = target != Path::new("/dev/null")
                && (target.parent() == Some(Path::new(UNIT_DIR))
                    || target.parent() == Some(Path::new(""))
                    || target.parent().is_none());
            if is_alias {
                continue;
            }
            out.insert(name, Installed::Symlink(target));
        } else if ft.is_file() {
            let bytes = match dir.read_bounded(&name, MAX_UNIT_FILE, false) {
                Ok(b) => b,
                Err(ReadError::Missing) => continue,
                Err(e) => crate::bail!("can't read {}: {e}", dir.logical_at(&name).display()),
            };
            out.insert(name, Installed::File(bytes));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(ssd: Option<&str>) -> Settings {
        Settings {
            data_dir: "/data/picket/var".into(),
            ssd_dir: ssd.map(Into::into),
            release_keys: vec![],
            notes: vec![],
        }
    }

    #[test]
    fn unifi_units() {
        let units = render(
            &Layout::for_platform(Platform::Unifi),
            &settings(Some("/volume1/.picket")),
        );
        assert_eq!(
            units.keys().map(String::as_str).collect::<Vec<_>>(),
            [ACCOUNTS, HELPER, UPDATE_PATH, UPDATE_SERVICE, EDGE]
        );
        for (name, text) in &units {
            assert!(!text.contains("{{"), "{name}: {text}");
            assert!(
                text.contains("RequiresMountsFor=/data/picket /data/picket/var"),
                "{name}"
            );
            assert!(is_release_unit_name(name));
        }
        let edge = &units[EDGE];
        for line in [
            "ExecStart=/data/picket/bin/current/picket-edge run --config /data/picket/etc/edge.json --data-dir /data/picket/var",
            "ReadWritePaths=/data/picket/var",
            "ReadWritePaths=-/volume1",
            "Environment=MALLOC_ARENA_MAX=4",
            "OOMScoreAdjust=-900",
            "MemoryMin=128M",
            "MemoryHigh=640M",
            "MemoryMax=768M",
            "MemorySwapMax=0",
            "ManagedOOMPreference=omit",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "Type=notify",
            "WatchdogSec=30",
            "RuntimeDirectoryMode=0770",
            "LimitNOFILE=65536",
            "SystemCallFilter=@system-service",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX",
            "User=picket",
            "Group=picket",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "RuntimeDirectory=picket",
            "Restart=always",
            "RestartSec=1",
        ] {
            assert!(edge.lines().any(|l| l == line), "missing {line:?} in\n{edge}");
        }
        assert!(!edge.contains("ReadWritePaths=-/volume1/.picket"));
        let helper = &units[HELPER];
        for line in [
            "ExecStartPre=+/usr/bin/touch /run/xtables.lock",
            "ExecStartPre=+/usr/bin/chgrp picket-helper /run/xtables.lock",
            "ExecStartPre=+/usr/bin/chmod 0640 /run/xtables.lock",
            "ExecStart=/data/picket/bin/current/picket-edge-helper run --state-dir /data/picket/helper",
            "ReadWritePaths=/data/picket/helper",
            "SupplementaryGroups=picket",
            "Environment=MALLOC_ARENA_MAX=2",
            "ManagedOOMPreference=omit",
            "MemoryMax=64M",
            "RuntimeDirectoryMode=0755",
            "Type=notify",
            "WatchdogSec=30",
            "User=picket-helper",
            "Group=picket-helper",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW",
            "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectControlGroups=yes",
            "RuntimeDirectory=picket-helper",
            "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6",
            "SystemCallFilter=@system-service",
            "Restart=always",
            "RestartSec=1",
        ] {
            assert!(helper.lines().any(|l| l == line), "missing {line:?}");
        }
        // StartLimitIntervalSec=0 belongs in [Unit] (security.md §3, edge-firewall.md §4); the
        // helper and edge want the accounts oneshot and start after it (edge-unifi.md §2 step 3),
        // and the helper starts before the edge (edge-firewall.md §4).
        for (name, wants) in [
            (EDGE, "picket-accounts.service"),
            (HELPER, "picket-accounts.service"),
        ] {
            let unit = section_entries(units[name].as_bytes(), "Unit");
            let has = |k: &str, v: &str| {
                unit.iter()
                    .any(|(key, val)| key == k && val.split_whitespace().any(|x| x == v))
            };
            assert!(has("StartLimitIntervalSec", "0"), "{name}");
            assert!(has("Wants", wants) && has("After", wants), "{name}");
        }
        assert!(
            section_entries(units[HELPER].as_bytes(), "Unit")
                .iter()
                .any(|(k, v)| k == "Before" && v.split_whitespace().any(|x| x == EDGE))
        );
        assert!(
            units[UPDATE_SERVICE]
                .lines()
                .any(|l| l == "Environment=MALLOC_ARENA_MAX=2")
        );
        assert!(
            units[UPDATE_SERVICE]
                .lines()
                .any(|l| l == "ExecStart=/data/picket/bin/current/picket-edge-update --platform unifi --data-dir /data/picket/var")
        );
        assert!(
            units[UPDATE_PATH]
                .lines()
                .any(|l| l == "PathExists=/data/picket/var/releases/pending.json")
        );
        assert!(
            units[ACCOUNTS]
                .lines()
                .any(|l| l == "ExecStart=/usr/bin/systemd-sysusers /data/picket/etc/sysusers.conf")
        );
        assert!(!has_install_section(units[ACCOUNTS].as_bytes()));
        assert!(!has_install_section(units[UPDATE_SERVICE].as_bytes()));
        assert!(has_install_section(units[UPDATE_PATH].as_bytes()));
        assert!(has_install_section(units[EDGE].as_bytes()));
    }

    #[test]
    fn debian_units() {
        let layout = Layout::for_platform(Platform::Debian);
        let mut s = settings(None);
        s.data_dir = "/var/lib/picket".into();
        let units = render(&layout, &s);
        let edge = &units[EDGE];
        assert!(edge.contains("ExecStart=/opt/picket/bin/current/picket-edge run --config /etc/picket/edge.json --data-dir /var/lib/picket"));
        assert!(edge.contains("RequiresMountsFor=/opt/picket /var/lib/picket"));
        assert!(edge.lines().any(|l| l == "Environment=MALLOC_ARENA_MAX=4"));
        assert!(!edge.contains("OOMScoreAdjust"));
        assert!(!edge.contains("ManagedOOMPreference"));
        assert!(!edge.contains("ReadWritePaths=-"));
        assert!(!units[HELPER].contains("ManagedOOMPreference"));
        assert!(units[HELPER].contains("--state-dir /var/lib/picket-helper"));
        assert!(
            units[UPDATE_SERVICE]
                .lines()
                .any(|l| l == "ExecStart=/opt/picket/bin/current/picket-edge-update --platform debian --data-dir /var/lib/picket")
        );
        for text in units.values() {
            assert!(!text.contains("{{"));
            assert!(!text.contains("\n\n\n"), "{text}");
        }
    }

    #[test]
    fn unit_names() {
        for ok in [
            "picket-edge.service",
            "picket-edge-update.path",
            "picket-x.timer",
            "picket-a_b.c.service",
            // Every other character systemd allows in a unit name, and instances.
            "picket-a:b.service",
            "picket-a\\x2db.service",
            "picket-a@b.service",
            "picket-a@b.timer",
            "picket-@b.service",
        ] {
            assert!(is_release_unit_name(ok), "{ok}");
        }
        for bad in [
            "picket-.service",
            "edge.service",
            "picket-edge.socket",
            "picket-edge",
            "../picket-edge.service",
            "picket-a/b.service",
            "picket-a..b.service",
            // A template: no unit to start, restart or retire (its instances are what run).
            "picket-a@.service",
            "picket-a@.timer",
            "picket-a@b@c.service",
            "picket-a b.service",
            "picket-a%i.service",
            "picket-a\nb.service",
            "picket-core.service",
            "",
        ] {
            assert!(!is_release_unit_name(bad), "{bad}");
        }
        assert!(is_managed_name("picket-old.socket"));
        assert!(!is_managed_name("picket-core.service"));
        assert!(!is_managed_name("picket-core-init.service"));
        assert!(!is_managed_name("picket-edge.service.d"));
        assert!(!is_managed_name("picket.service"));
    }

    #[test]
    fn units_output_checks() {
        let layout = Layout::for_platform(Platform::Unifi);
        let good = serde_json::to_vec(&units_output(&layout, &settings(None))).unwrap();
        assert_eq!(parse_units_output(&good).unwrap().len(), 5);
        let cases: [(&str, &str); 7] = [
            (r#"{"format": 2, "units": {}}"#, "unknown units format"),
            (
                r#"{"format": 1, "units": {"picket-edge-update.path": ""}}"#,
                "missing",
            ),
            (
                r#"{"format": 1, "units": {"picket-edge-update.path": "", "picket-edge-update.service": "", "x.service": ""}}"#,
                "isn't",
            ),
            (
                r#"{"format": 1, "units": {"picket-edge-update.path": "", "picket-edge-update.service": "a\u0000b"}}"#,
                "NUL",
            ),
            (r#"not json"#, "not units JSON"),
            (r#"{"format": "1"}"#, "not units JSON"),
            (r#"{}"#, "unknown units format 0"),
        ];
        for (input, want) in cases {
            let e = parse_units_output(input.as_bytes()).unwrap_err();
            assert!(e.contains(want), "{input}: {e}");
        }
    }

    #[test]
    fn install_sections() {
        let t = b"[Unit]\nWantedBy=x\n[Install]\n# c\nWantedBy=multi-user.target\nAlias=\n";
        assert_eq!(
            install_entries(t),
            vec![("WantedBy".into(), "multi-user.target".into())]
        );
        assert!(!has_install_section(
            b"[Unit]\nDescription=x\n[Install]\nWantedBy=\n"
        ));
    }

    /// The real systemd accepts every unit on both platforms, with the binaries stubbed. Needs
    /// `systemd-analyze`, which the CI container lacks, so it runs only when asked for and then
    /// fails rather than skips without it:
    /// `cargo test -p picket-edge-update -- --ignored systemd_analyze_verify`.
    #[test]
    #[ignore = "needs systemd-analyze: cargo test -p picket-edge-update -- --ignored systemd_analyze_verify"]
    fn systemd_analyze_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin/current");
        std::fs::create_dir_all(&bin).unwrap();
        for b in crate::release::BINARIES {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(bin.join(b), "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(bin.join(b), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        for (platform, data_dir) in [
            (Platform::Unifi, "/data/picket/var"),
            (Platform::Debian, "/var/lib/picket"),
        ] {
            let layout = Layout::for_platform(platform);
            let mut s = settings(Some("/volume1/.picket"));
            s.data_dir = data_dir.into();
            let dir = tmp.path().join(platform.as_str());
            std::fs::create_dir_all(&dir).unwrap();
            let mut paths = Vec::new();
            for (name, text) in render(&layout, &s) {
                let text = text.replace(
                    &format!("{}/bin/current/", layout.install_dir),
                    &format!("{}/", bin.display()),
                );
                std::fs::write(dir.join(&name), text).unwrap();
                paths.push(dir.join(&name));
            }
            let out = std::process::Command::new("systemd-analyze")
                .arg("verify")
                .args(&paths)
                .output()
                .expect("systemd-analyze runs (install systemd)");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                out.status.success() && stderr.trim().is_empty(),
                "{platform:?}: {stderr}"
            );
        }
    }

    #[test]
    fn scan() {
        let tmp = tempfile::tempdir().unwrap();
        let ud = tmp.path().join("etc/systemd/system");
        std::fs::create_dir_all(ud.join("picket-edge.service.d")).unwrap();
        std::fs::create_dir_all(ud.join("multi-user.target.wants")).unwrap();
        std::fs::write(ud.join("picket-edge.service"), "[Unit]\n").unwrap();
        std::fs::write(ud.join("picket-core.service"), "[Unit]\n").unwrap();
        std::fs::write(ud.join("other.service"), "[Unit]\n").unwrap();
        std::os::unix::fs::symlink("/dev/null", ud.join("picket-masked.service")).unwrap();
        std::os::unix::fs::symlink(
            "/etc/systemd/system/picket-edge.service",
            ud.join("picket-alias.service"),
        )
        .unwrap();
        std::os::unix::fs::symlink("/data/picket/old.service", ud.join("picket-linked.service")).unwrap();
        let dir = open_unit_dir(&Root::new(tmp.path())).unwrap();
        let got = scan_installed(&dir).unwrap();
        assert_eq!(
            got.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "picket-edge.service",
                "picket-linked.service",
                "picket-masked.service"
            ]
        );
        assert!(got["picket-masked.service"].is_mask());
        assert!(got["picket-edge.service"].is_file_with("[Unit]\n"));
    }
}
