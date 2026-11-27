//! Host facts `install` checks: the mount table (for the SSD, edge-unifi.md §1 and §2 step 4),
//! the UniFi OS version against `dist/firmware.json`, and the device model (§1).

use std::path::Path;

use serde::Deserialize;

/// One `/proc/self/mountinfo` line, as far as the updater needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    /// `major:minor` of the mounted filesystem.
    pub dev: String,
    pub mount_point: String,
}

/// Parses `/proc/self/mountinfo` (proc(5)); malformed lines are skipped.
pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split(' ');
            let _id = f.next()?;
            let _parent = f.next()?;
            let dev = f.next()?;
            let _root = f.next()?;
            let mp = f.next()?;
            if !dev.contains(':') || !mp.starts_with('/') {
                return None;
            }
            Some(Mount {
                dev: dev.to_string(),
                mount_point: unescape_octal(mp),
            })
        })
        .collect()
}

/// Undoes the kernel's `\ooo` escapes (space, tab, newline, backslash).
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            if let Ok(v) = u8::try_from(v) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mount at exactly `path` (the last one wins: later mounts hide earlier ones).
pub fn mount_at<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    mounts.iter().rev().find(|m| m.mount_point == path)
}

/// The mount `path` lives on: the longest mount point that contains it (the last one wins).
pub fn mount_containing<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    let p = Path::new(path);
    mounts
        .iter()
        .enumerate()
        .filter(|(_, m)| p.starts_with(&m.mount_point))
        .max_by_key(|(i, m)| (m.mount_point.len(), *i))
        .map(|(_, m)| m)
}

/// The SSD rule of `install` step 4: `ssd_dir`'s parent is a mount point, on a different
/// filesystem from `data_dir`.
pub fn ssd_mount_usable(mounts: &[Mount], ssd_parent: &str, data_dir: &str) -> Result<(), String> {
    let Some(pm) = mount_at(mounts, ssd_parent) else {
        return Err(format!("{ssd_parent} isn't a mount point (is the SSD mounted?)"));
    };
    match mount_containing(mounts, data_dir) {
        Some(dm) if dm.dev == pm.dev => Err(format!(
            "{ssd_parent} is on the same filesystem as {data_dir} ({})",
            pm.dev
        )),
        _ => Ok(()),
    }
}

/// `dist/firmware.json`: the minimum UniFi OS version per target (edge-unifi.md §1).
pub const FIRMWARE_JSON: &str = include_str!("../../../dist/firmware.json");

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct FirmwareMin {
    pub target: String,
    pub min: String,
}

pub fn firmware_minimums() -> Vec<FirmwareMin> {
    serde_json::from_str(FIRMWARE_JSON).unwrap_or_default()
}

/// `/usr/lib/version` → (target, version): the first field and the `vX.Y.Z` field
/// (`UCGF.ipq9574.v6.0.17.…` is `UCGF`, `6.0.17`).
pub fn parse_usr_lib_version(text: &str) -> Option<(String, String)> {
    let line = text.lines().next()?.trim();
    let fields: Vec<&str> = line.split('.').collect();
    let target = fields.first().filter(|t| !t.is_empty())?.to_string();
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    for i in 1..fields.len() {
        let Some(major) = fields[i].strip_prefix('v') else {
            continue;
        };
        if digits(major)
            && fields.get(i + 1).is_some_and(|f| digits(f))
            && fields.get(i + 2).is_some_and(|f| digits(f))
        {
            return Some((target, format!("{major}.{}.{}", fields[i + 1], fields[i + 2])));
        }
    }
    None
}

/// `install`'s firmware warning, if any: below the minimum for its target, or unreadable.
pub fn firmware_warning(usr_lib_version: Option<&str>, mins: &[FirmwareMin]) -> Option<String> {
    let Some(text) = usr_lib_version else {
        return Some("can't read /usr/lib/version to check the UniFi OS version".into());
    };
    let Some((target, version)) = parse_usr_lib_version(text) else {
        return Some(format!("can't parse /usr/lib/version ({:?})", text.trim()));
    };
    let Some(min) = mins.iter().find(|m| m.target == target) else {
        return Some(format!(
            "no minimum UniFi OS version is known for target {target}"
        ));
    };
    match crate::api::compare_versions(&version, &min.min) {
        Some(std::cmp::Ordering::Less) => Some(format!(
            "UniFi OS {version} is below the minimum {} for {target}",
            min.min
        )),
        Some(_) => None,
        None => Some(format!(
            "can't compare UniFi OS version {version} with {}",
            min.min
        )),
    }
}

/// The model `install` expects (edge-unifi.md §1).
pub const EXPECTED_MODEL: &str = "UniFi Cloud Gateway Fiber";

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 179:2 / / rw,relatime shared:1 - ext4 /dev/root rw
30 22 179:5 / /data rw,noatime shared:2 - ext4 /dev/mmcblk0p5 rw
31 22 0:25 / /run rw,nosuid shared:3 - tmpfs tmpfs rw
40 22 259:1 / /volume1 rw,relatime shared:9 - ext4 /dev/nvme0n1p1 rw
41 22 259:1 /.srv /srv rw,relatime shared:9 - ext4 /dev/nvme0n1p1 rw
42 22 0:50 / /mnt/with\\040space rw - tmpfs tmpfs rw
garbage line
";

    #[test]
    fn mountinfo() {
        let m = parse_mountinfo(MOUNTINFO);
        assert_eq!(m.len(), 6);
        assert_eq!(m[5].mount_point, "/mnt/with space");
        assert_eq!(mount_at(&m, "/volume1").unwrap().dev, "259:1");
        assert!(mount_at(&m, "/volume2").is_none());
        assert_eq!(mount_containing(&m, "/data/picket/var").unwrap().dev, "179:5");
        assert_eq!(mount_containing(&m, "/datax").unwrap().dev, "179:2");
        assert!(ssd_mount_usable(&m, "/volume1", "/data/picket/var").is_ok());
        assert!(
            ssd_mount_usable(&m, "/volume2", "/data/picket/var")
                .unwrap_err()
                .contains("isn't a mount point")
        );
        assert!(
            ssd_mount_usable(&m, "/data", "/data/picket/var")
                .unwrap_err()
                .contains("same filesystem")
        );
        // An empty mount hiding a drive (a later mount at the same point) wins.
        let hidden = format!("{MOUNTINFO}50 40 179:5 /picket/var /volume1 rw - ext4 /dev/mmcblk0p5 rw\n");
        let m = parse_mountinfo(&hidden);
        assert!(ssd_mount_usable(&m, "/volume1", "/data/picket/var").is_err());
    }

    #[test]
    fn firmware() {
        assert_eq!(
            parse_usr_lib_version("UCGF.ipq9574.v6.0.17.0e5e4e1.250430.1720\n"),
            Some(("UCGF".into(), "6.0.17".into()))
        );
        assert_eq!(
            parse_usr_lib_version("UCGF.ipq9574.v10.2.3"),
            Some(("UCGF".into(), "10.2.3".into()))
        );
        assert_eq!(parse_usr_lib_version("UCGF.ipq9574"), None);
        assert_eq!(parse_usr_lib_version(""), None);
        let mins = firmware_minimums();
        assert_eq!(
            mins,
            vec![FirmwareMin {
                target: "UCGF".into(),
                min: "6.0.17".into()
            }]
        );
        assert_eq!(firmware_warning(Some("UCGF.ipq9574.v6.0.17.x"), &mins), None);
        assert_eq!(firmware_warning(Some("UCGF.ipq9574.v6.1.2.x"), &mins), None);
        assert!(
            firmware_warning(Some("UCGF.ipq9574.v6.0.16.x"), &mins)
                .unwrap()
                .contains("below the minimum")
        );
        assert!(
            firmware_warning(Some("UDMPRO.al324.v4.0.0.x"), &mins)
                .unwrap()
                .contains("no minimum")
        );
        assert!(firmware_warning(None, &mins).is_some());
    }
}
