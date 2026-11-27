//! Picket's system accounts (edge-unifi.md §2 step 3): declared in `sysusers.conf` with fixed IDs
//! outside the ranges UniFi OS 6.0.17 allocates (0–132 and 966–999), and applied with the
//! system's own `systemd-sysusers`, so no account code reaches the updater.

use std::path::Path;

use crate::fsx::{Dir, Root};

pub const PICKET: &str = "picket";
pub const PICKET_HELPER: &str = "picket-helper";
pub const PICKET_UID: u32 = 880;
pub const PICKET_GID: u32 = 880;
pub const HELPER_UID: u32 = 881;
pub const HELPER_GID: u32 = 881;

/// `<config_dir>/sysusers.conf`: system users and groups with fixed IDs, no home, no login shell.
pub const SYSUSERS_CONF: &str = "\
# Picket's system accounts (edge-unifi.md §2 step 3), written by `picket-edge-update install`.
# picket-accounts.service applies this at every boot, since a firmware upgrade wipes /etc/passwd.
# The IDs are fixed, outside UniFi OS's own allocations (0-132 and 966-999), so the files under
# /data keep their owners.
g picket 880
g picket-helper 881
u picket 880:880 \"Picket edge\" /nonexistent /usr/sbin/nologin
u picket-helper 881:881 \"Picket edge helper\" /nonexistent /usr/sbin/nologin
";

const DB_MAX: u64 = 16 * 1024 * 1024;

/// A `/etc/passwd` entry: (uid, gid).
pub fn lookup_user(root: &Root, name: &str) -> Option<(u32, u32)> {
    let text = read_db(root, "passwd")?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 4 && f[0] == name).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))?
    })
}

/// A `/etc/group` entry's gid.
pub fn lookup_group(root: &Root, name: &str) -> Option<u32> {
    let text = read_db(root, "group")?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 3 && f[0] == name).then(|| f[2].parse().ok())?
    })
}

fn read_db(root: &Root, name: &str) -> Option<String> {
    let dir = Dir::open(root, "/etc").ok()?;
    let bytes = dir.read_bounded(name, DB_MAX, false).ok()?;
    String::from_utf8(bytes).ok()
}

/// Checks the accounts exist with exactly the fixed IDs. `systemd-sysusers` never changes an
/// existing account, so a name or ID taken by something else shows up here, before anything is
/// chowned to the wrong account.
pub fn verify(root: &Root) -> Result<(), String> {
    let mut problems = Vec::new();
    for (name, uid, gid) in [
        (PICKET, PICKET_UID, PICKET_GID),
        (PICKET_HELPER, HELPER_UID, HELPER_GID),
    ] {
        match lookup_user(root, name) {
            Some((u, g)) if u == uid && g == gid => {}
            Some((u, g)) => problems.push(format!("user {name} is {u}:{g}, expected {uid}:{gid}")),
            None => problems.push(format!("user {name} is missing")),
        }
        match lookup_group(root, name) {
            Some(g) if g == gid => {}
            Some(g) => problems.push(format!("group {name} has gid {g}, expected {gid}")),
            None => problems.push(format!("group {name} is missing")),
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// The gid that owns `bin/update-result.json`: the `picket` group as the system knows it, else the
/// fixed GID that `sysusers.conf` gives it.
pub fn picket_gid(root: &Root) -> u32 {
    lookup_group(root, PICKET).unwrap_or(PICKET_GID)
}

/// The path of the conf under a config directory.
pub fn conf_path(config_dir: &str) -> std::path::PathBuf {
    Path::new(config_dir).join("sysusers.conf")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_outside_unifi_ranges() {
        for id in [PICKET_UID, PICKET_GID, HELPER_UID, HELPER_GID] {
            assert!(!(0..=132).contains(&id) && !(966..=999).contains(&id));
        }
        assert!(SYSUSERS_CONF.contains("u picket 880:880"));
        assert!(SYSUSERS_CONF.contains("g picket-helper 881"));
    }

    #[test]
    fn lookups_and_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Root::new(tmp.path());
        std::fs::create_dir_all(tmp.path().join("etc")).unwrap();
        assert!(verify(&root).unwrap_err().contains("missing"));
        assert_eq!(picket_gid(&root), PICKET_GID);
        std::fs::write(
            tmp.path().join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\npicket:x:880:880::/nonexistent:/usr/sbin/nologin\npicket-helper:x:1234:881::/:/x\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("etc/group"),
            "root:x:0:\npicket:x:880:\npicket-helper:x:881:\n",
        )
        .unwrap();
        assert_eq!(lookup_user(&root, "picket"), Some((880, 880)));
        assert_eq!(lookup_group(&root, "picket-helper"), Some(881));
        let e = verify(&root).unwrap_err();
        assert!(e.contains("user picket-helper is 1234:881"), "{e}");
        std::fs::write(
            tmp.path().join("etc/passwd"),
            "picket:x:880:880::/:/x\npicket-helper:x:881:881::/:/x\n",
        )
        .unwrap();
        verify(&root).unwrap();
    }
}
