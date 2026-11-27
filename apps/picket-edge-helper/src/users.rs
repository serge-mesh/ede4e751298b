//! Account lookups for the socket's access control (edge-firewall.md §4 "Socket"): the edge's UID
//! from its user name, and the socket's group, read from `/etc/passwd` and `/etc/group`.

use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_FILE: u64 = 4 << 20;

fn read(path: &Path) -> Option<String> {
    let mut s = String::new();
    File::open(path)
        .ok()?
        .take(MAX_FILE)
        .read_to_string(&mut s)
        .ok()?;
    Some(s)
}

/// `(uid, primary gid)` of a user given by name or numeric UID.
pub fn user_in(passwd: &str, who: &str) -> Option<(u32, u32)> {
    let by_uid = who.parse::<u32>().ok();
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let _pw = f.next()?;
        let uid = f.next()?.parse::<u32>().ok()?;
        let gid = f.next()?.parse::<u32>().ok()?;
        (name == who || by_uid == Some(uid)).then_some((uid, gid))
    })
}

pub fn group_in(group: &str, name: &str) -> Option<u32> {
    group.lines().find_map(|l| {
        let mut f = l.split(':');
        let n = f.next()?;
        let _pw = f.next()?;
        let gid = f.next()?.parse::<u32>().ok()?;
        (n == name).then_some(gid)
    })
}

/// Looks up a user in `/etc/passwd`; a bare number that isn't listed is taken as the UID.
pub fn lookup_user(who: &str) -> Option<(u32, Option<u32>)> {
    if let Some((u, g)) = read(Path::new("/etc/passwd")).and_then(|p| user_in(&p, who)) {
        return Some((u, Some(g)));
    }
    who.parse::<u32>().ok().map(|u| (u, None))
}

pub fn lookup_group(name: &str) -> Option<u32> {
    if let Some(g) = read(Path::new("/etc/group")).and_then(|g| group_in(&g, name)) {
        return Some(g);
    }
    name.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_passwd_and_group() {
        let p =
            "root:x:0:0:root:/root:/bin/bash\npicket:x:2001:2001::/nonexistent:/usr/sbin/nologin\nbroken\n";
        assert_eq!(user_in(p, "picket"), Some((2001, 2001)));
        assert_eq!(user_in(p, "2001"), Some((2001, 2001)));
        assert_eq!(user_in(p, "nobody"), None);
        assert_eq!(
            group_in("picket:x:2001:\npicket-helper:x:2002:\n", "picket-helper"),
            Some(2002)
        );
    }
}
