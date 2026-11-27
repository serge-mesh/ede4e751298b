//! Accounts: the `picket` user and group (edge-unifi.md §2 step 3), looked up in `/etc/passwd`
//! and `/etc/group` without NSS (the edge has no resolver and needs no other source).

use std::path::Path;

use crate::fsutil;

/// The service account and group (security.md §3).
pub const PICKET: &str = "picket";

/// Set to `1` by a unit (or a test) to say "running as the service" when the user name can't
/// tell (edge.md §2: the admin socket is group `picket`, 0660, under the service).
pub const SERVICE_ENV: &str = "PICKET_EDGE_SERVICE";

const MAX_DB: u64 = 4 << 20;

/// Looks up a user's uid by name in a passwd-format file.
pub fn uid_by_name_in(db: &Path, name: &str) -> Option<u32> {
    field_lookup(db, |f| {
        (f.first() == Some(&name))
            .then(|| f.get(2)?.parse().ok())
            .flatten()
    })
}

/// Looks up a user's name by uid in a passwd-format file.
pub fn name_by_uid_in(db: &Path, uid: u32) -> Option<String> {
    field_lookup(db, |f| {
        let u: u32 = f.get(2)?.parse().ok()?;
        (u == uid).then(|| f.first().map(|s| (*s).to_owned())).flatten()
    })
}

/// Looks up a group's gid by name in a group-format file.
pub fn gid_by_name_in(db: &Path, name: &str) -> Option<u32> {
    field_lookup(db, |f| {
        (f.first() == Some(&name))
            .then(|| f.get(2)?.parse().ok())
            .flatten()
    })
}

fn field_lookup<T>(db: &Path, mut f: impl FnMut(&[&str]) -> Option<T>) -> Option<T> {
    let bytes = fsutil::read_bounded(db, MAX_DB).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| f(&l.split(':').collect::<Vec<_>>()))
}

/// uid of `picket`, if the account exists.
pub fn picket_uid() -> Option<u32> {
    uid_by_name_in(Path::new("/etc/passwd"), PICKET)
}

/// gid of group `picket`, if it exists.
pub fn picket_gid() -> Option<u32> {
    gid_by_name_in(Path::new("/etc/group"), PICKET)
}

/// The effective uid.
pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// True when running as root.
pub fn is_root() -> bool {
    euid() == 0
}

/// True when this process runs as the service: as user `picket`, or with `PICKET_EDGE_SERVICE=1`.
pub fn is_service() -> bool {
    if std::env::var(SERVICE_ENV).is_ok_and(|v| v == "1") {
        return true;
    }
    name_by_uid_in(Path::new("/etc/passwd"), euid()).is_some_and(|n| n == PICKET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("passwd");
        std::fs::write(
            &p,
            "root:x:0:0:root:/root:/bin/sh\n# comment\npicket:x:620:620::/nonexistent:/usr/sbin/nologin\n",
        )
        .unwrap();
        assert_eq!(uid_by_name_in(&p, "picket"), Some(620));
        assert_eq!(name_by_uid_in(&p, 0).as_deref(), Some("root"));
        assert_eq!(uid_by_name_in(&p, "nobody"), None);
        let g = d.path().join("group");
        std::fs::write(&g, "root:x:0:\npicket:x:620:\n").unwrap();
        assert_eq!(gid_by_name_in(&g, "picket"), Some(620));
    }
}
