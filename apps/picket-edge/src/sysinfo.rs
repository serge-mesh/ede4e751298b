//! System facts for `hello` and heartbeats (api.md §3 system fields), read from `/proc`, cgroups
//! and `uname`. Any value that can't be read is `None` (null on the wire).

use std::path::{Path, PathBuf};

use crate::fsutil;

const MAX_PROC: u64 = 1 << 20;

fn read(path: &Path) -> Option<String> {
    fsutil::read_bounded(path, MAX_PROC)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// A `Key:   123 kB` field of a `/proc` key-value file, in bytes.
fn kb_field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let rest = l.strip_prefix(key)?.strip_prefix(':')?;
        let n: u64 = rest.split_whitespace().next()?.parse().ok()?;
        Some(n.saturating_mul(1024))
    })
}

/// (`MemTotal`, `MemAvailable`) in bytes.
pub fn meminfo() -> (Option<u64>, Option<u64>) {
    meminfo_from(Path::new("/proc/meminfo"))
}

pub fn meminfo_from(p: &Path) -> (Option<u64>, Option<u64>) {
    match read(p) {
        Some(t) => (kb_field(&t, "MemTotal"), kb_field(&t, "MemAvailable")),
        None => (None, None),
    }
}

/// `VmRSS` of a process in bytes (`self` or a pid).
pub fn rss(pid: Option<u32>) -> Option<u64> {
    let p = proc_path(pid, "status");
    kb_field(&read(&p)?, "VmRSS")
}

/// User plus system CPU time of a process in milliseconds, from `/proc/<pid>/stat`.
pub fn cpu_ms(pid: Option<u32>) -> Option<u64> {
    let text = read(&proc_path(pid, "stat"))?;
    cpu_ms_from_stat(&text, rustix::param::clock_ticks_per_second())
}

pub fn cpu_ms_from_stat(text: &str, ticks_per_s: u64) -> Option<u64> {
    // The command name may hold spaces and parentheses: fields start after the last ')'.
    let rest = &text[text.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After ')' the fields are state(3) ppid(4) … utime(14) stime(15): indices 11 and 12 here.
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    let ticks = utime.saturating_add(stime);
    Some(ticks.saturating_mul(1000) / ticks_per_s.max(1))
}

fn proc_path(pid: Option<u32>, file: &str) -> PathBuf {
    match pid {
        Some(p) => PathBuf::from(format!("/proc/{p}/{file}")),
        None => PathBuf::from(format!("/proc/self/{file}")),
    }
}

/// `memory.current` of the edge's own cgroup (its unit's), found through `/proc/self/cgroup`;
/// cgroup v1's `memory.usage_in_bytes` as a fallback.
pub fn cgroup_memory() -> Option<u64> {
    let text = read(Path::new("/proc/self/cgroup"))?;
    cgroup_memory_path(&text, Path::new("/sys/fs/cgroup")).and_then(|p| read(&p)?.trim().parse().ok())
}

pub fn cgroup_memory_path(cgroup: &str, root: &Path) -> Option<PathBuf> {
    for line in cgroup.lines() {
        let mut parts = line.splitn(3, ':');
        let (_id, ctrls, path) = (parts.next()?, parts.next()?, parts.next()?);
        let rel = path.trim_start_matches('/');
        if rel.contains("..") {
            continue;
        }
        if ctrls.is_empty() {
            return Some(root.join(rel).join("memory.current"));
        }
        if ctrls.split(',').any(|c| c == "memory") {
            return Some(root.join("memory").join(rel).join("memory.usage_in_bytes"));
        }
    }
    None
}

/// The kernel release (`uname -r`).
pub fn kernel() -> String {
    rustix::system::uname().release().to_string_lossy().into_owned()
}

/// `aarch64` or `x86_64` (api.md §3 `arch`).
pub fn arch() -> &'static str {
    std::env::consts::ARCH
}

/// `PRETTY_NAME` from `/etc/os-release`, else `linux`.
pub fn os() -> String {
    read(Path::new("/etc/os-release"))
        .and_then(|t| {
            t.lines().find_map(|l| {
                let v = l.strip_prefix("PRETTY_NAME=")?;
                Some(crate::diag::truncate(v.trim_matches('"'), 128))
            })
        })
        .unwrap_or_else(|| std::env::consts::OS.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("meminfo");
        std::fs::write(
            &p,
            "MemTotal:        3000000 kB\nMemFree: 1 kB\nMemAvailable:    2048 kB\n",
        )
        .unwrap();
        assert_eq!(meminfo_from(&p), (Some(3_072_000_000), Some(2_097_152)));
        let stat = "1234 (picket edge) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 4 0 100 0 0";
        assert_eq!(cpu_ms_from_stat(stat, 100), Some(3000));
        assert!(rss(None).is_some());
        assert!(cpu_ms(None).is_some());
    }

    #[test]
    fn cgroup_paths() {
        let root = Path::new("/sys/fs/cgroup");
        assert_eq!(
            cgroup_memory_path("0::/system.slice/picket-edge.service\n", root),
            Some(PathBuf::from(
                "/sys/fs/cgroup/system.slice/picket-edge.service/memory.current"
            ))
        );
        assert_eq!(
            cgroup_memory_path("5:cpu,cpuacct:/x\n4:memory:/system.slice/a.service\n", root),
            Some(PathBuf::from(
                "/sys/fs/cgroup/memory/system.slice/a.service/memory.usage_in_bytes"
            ))
        );
        assert_eq!(cgroup_memory_path("0::/../../etc\n", root), None);
    }
}
