//! UniFi features that fight Picket (edge-unifi.md §7): Ad Blocking / Content Filtering (UniFi's
//! `dnsfilter` service: CoreDNS on 1053 with its own port-53 DNAT) and Encrypted DNS / DNS Shield
//! (dnscrypt-proxy on 5053, which dnsmasq forwards to). Checked at start and every minute, on
//! UniFi only:
//!
//! - `/run/dnsfilter/dnsfilter` exists: key `dnsfilter`, the key the helper gives a non-empty
//!   `DNSFILTER` chain, the same feature (edge-firewall.md §4);
//! - a non-comment line of dnsmasq's config names `127.0.0.1#5053`: key `dns_shield`.
//!
//! Each finding is the condition `unifi_conflict` keyed by feature (api.md §3), reported as this
//! check's own set ([`Source::UnifiFiles`]), so the helper's reports, which come and go with the
//! firewall, neither clear it nor are cleared by it; a feature that goes away clears at the next
//! check. Nothing changes UniFi settings. Reads are bounded (README §2): at most
//! [`MAX_DIR_ENTRIES`] files per directory and [`MAX_FILE`] bytes per file.
//!
//! A path that exists but can't be read (permissions: the edge runs as `picket`; a symlink loop)
//! tells nothing either way: the feature counts as off for that path, as a missing file does, and
//! the journal says so once per path until it reads again (README §2 Health: no silent "off").
//! The helper's `DNSFILTER` chain check, where it runs, may still see Ad Blocking.
//!
//! The spec names no dnsmasq config path. [`DNSMASQ_CONFIG`] lists where UniFi OS keeps it
//! (`ubios-udapi-server` writes `/run/dnsmasq.conf.d/`, which dnsmasq reads as a `conf-dir`),
//! plus Debian's defaults; this is a best reading, to be confirmed on a gateway (flagged for the
//! owner).

use std::collections::HashSet;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use picket_api::session::condition_kind::UNIFI_CONFLICT;

use crate::conditions::{Conditions, Source};

/// Ad Blocking / Content Filtering's file (edge-unifi.md §7).
pub const DNSFILTER_FILE: &str = "/run/dnsfilter/dnsfilter";
/// dnsmasq's config files and `conf-dir`s (not named by the spec; to be confirmed on a gateway).
pub const DNSMASQ_CONFIG: [&str; 4] = [
    "/run/dnsmasq.conf.d",
    "/run/dnsmasq.dhcp.conf.d",
    "/etc/dnsmasq.conf",
    "/etc/dnsmasq.d",
];
/// The forwarder DNS Shield points dnsmasq at.
pub const SHIELD_FORWARDER: &str = "127.0.0.1#5053";
/// Feature keys of `unifi_conflict`.
pub const DNSFILTER: &str = "dnsfilter";
pub const DNS_SHIELD: &str = "dns_shield";
/// Most files read in one config directory.
pub const MAX_DIR_ENTRIES: usize = 256;
/// Most bytes read from one config file.
pub const MAX_FILE: u64 = 1 << 20;

/// Where the check looks, and how often (tests point it elsewhere).
#[derive(Clone, Debug)]
pub struct UnifiTuning {
    pub dnsfilter: PathBuf,
    /// Files, or directories whose files are read (not recursively).
    pub dnsmasq: Vec<PathBuf>,
    pub every: Duration,
}

impl Default for UnifiTuning {
    fn default() -> Self {
        Self {
            dnsfilter: PathBuf::from(DNSFILTER_FILE),
            dnsmasq: DNSMASQ_CONFIG.iter().map(PathBuf::from).collect(),
            every: Duration::from_secs(60),
        }
    }
}

/// A path the check couldn't read: the path, the error, and the feature it was looking for.
pub type Unreadable = (PathBuf, std::io::Error, &'static str);

/// The features the files show now; paths that exist but can't be read go to `unreadable`.
pub fn findings(t: &UnifiTuning, unreadable: &mut Vec<Unreadable>) -> Vec<&'static str> {
    let mut out = Vec::new();
    match t.dnsfilter.try_exists() {
        Ok(true) => out.push(DNSFILTER),
        Ok(false) => {}
        Err(e) if absent(&e) => {}
        Err(e) => unreadable.push((t.dnsfilter.clone(), e, DNSFILTER)),
    }
    if t.dnsmasq.iter().any(|p| names_shield(p, unreadable)) {
        out.push(DNS_SHIELD);
    }
    out
}

/// Errors that mean the path isn't there (a component that isn't a directory included).
fn absent(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

/// Whether the config file at `p`, or a file in the directory at `p`, forwards to DNS Shield.
fn names_shield(p: &Path, unreadable: &mut Vec<Unreadable>) -> bool {
    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(e) if absent(&e) => return false,
        Err(e) => {
            unreadable.push((p.to_path_buf(), e, DNS_SHIELD));
            return false;
        }
    };
    if !meta.is_dir() {
        return file_names_shield(p, unreadable);
    }
    let rd = match std::fs::read_dir(p) {
        Ok(rd) => rd,
        Err(e) => {
            unreadable.push((p.to_path_buf(), e, DNS_SHIELD));
            return false;
        }
    };
    for entry in rd.take(MAX_DIR_ENTRIES) {
        match entry {
            Ok(e) if e.path().is_file() => {
                if file_names_shield(&e.path(), unreadable) {
                    return true;
                }
            }
            Ok(_) => {}
            Err(e) => unreadable.push((p.to_path_buf(), e, DNS_SHIELD)),
        }
    }
    false
}

fn file_names_shield(p: &Path, unreadable: &mut Vec<Unreadable>) -> bool {
    let mut bytes = Vec::new();
    let read = std::fs::File::open(p).and_then(|f| f.take(MAX_FILE).read_to_end(&mut bytes));
    match read {
        Ok(_) => {}
        Err(e) if absent(&e) => return false,
        Err(e) => {
            unreadable.push((p.to_path_buf(), e, DNS_SHIELD));
            return false;
        }
    }
    String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .any(|l| !l.starts_with('#') && l.contains(SHIELD_FORWARDER))
}

/// One check: `unifi_conflict` for each feature found, cleared for each gone. Each unreadable
/// path is logged once while it stays unreadable (`warned` holds them between checks; bounded by
/// the paths one check reads). Returns the paths logged now.
pub fn check(conditions: &Conditions, t: &UnifiTuning, warned: &mut HashSet<PathBuf>) -> Vec<PathBuf> {
    let mut unreadable = Vec::new();
    let current: Vec<(String, Option<String>, Option<serde_json::Value>)> = findings(t, &mut unreadable)
        .into_iter()
        .map(|f| (UNIFI_CONFLICT.to_owned(), Some(f.to_owned()), None))
        .collect();
    conditions.sync_kinds(Source::UnifiFiles, &[UNIFI_CONFLICT], &current);
    warned.retain(|p| unreadable.iter().any(|(u, _, _)| u == p));
    let mut logged = Vec::new();
    for (path, e, feature) in unreadable {
        if warned.insert(path.clone()) {
            let what = match feature {
                DNSFILTER => {
                    "Ad Blocking counts as off here until it can be read (the helper's DNSFILTER chain check may still see it)"
                }
                _ => "this file counts as not forwarding to DNS Shield until it can be read",
            };
            tracing::warn!(
                "UniFi feature check: can't read {}: {}; {what} (edge-unifi.md §7)",
                path.display(),
                crate::diag::cap(e)
            );
            logged.push(path);
        }
    }
    logged
}

/// Checks at start and every `t.every` (edge-unifi.md §7).
pub async fn run(conditions: Arc<Conditions>, t: UnifiTuning) -> anyhow::Result<()> {
    let mut warned = HashSet::new();
    loop {
        let (c, tt) = (Arc::clone(&conditions), t.clone());
        warned = tokio::task::spawn_blocking(move || {
            check(&c, &tt, &mut warned);
            warned
        })
        .await?;
        tokio::time::sleep(t.every).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::LogProducer;

    struct Fx {
        _d: tempfile::TempDir,
        t: UnifiTuning,
        conf_d: PathBuf,
        conf: PathBuf,
    }

    /// A gateway's files under a temporary root: no feature on yet.
    fn fx() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let conf_d = d.path().join("run/dnsmasq.conf.d");
        std::fs::create_dir_all(&conf_d).unwrap();
        std::fs::write(conf_d.join("dns.conf"), "server=1.1.1.1\nno-resolv\n").unwrap();
        let conf = d.path().join("etc/dnsmasq.conf");
        std::fs::create_dir_all(conf.parent().unwrap()).unwrap();
        std::fs::write(&conf, "# server=127.0.0.1#5053 (a comment)\n").unwrap();
        let t = UnifiTuning {
            dnsfilter: d.path().join("run/dnsfilter/dnsfilter"),
            dnsmasq: vec![conf_d.clone(), conf.clone(), d.path().join("missing.d")],
            every: Duration::from_millis(20),
        };
        Fx {
            _d: d,
            t,
            conf_d,
            conf,
        }
    }

    fn conditions() -> Arc<Conditions> {
        Conditions::new(LogProducer::new("b".into(), Arc::default()).0)
    }

    #[test]
    fn each_feature_is_found_by_its_file_and_clears_when_it_goes() {
        let f = fx();
        let c = conditions();
        check(&c, &f.t, &mut HashSet::new());
        assert!(c.snapshot().is_empty(), "nothing on; a comment doesn't count");
        // Ad Blocking: its file appears.
        std::fs::create_dir_all(f.t.dnsfilter.parent().unwrap()).unwrap();
        std::fs::write(&f.t.dnsfilter, b"").unwrap();
        // DNS Shield: dnsmasq forwards to dnscrypt-proxy, in a conf-dir file or the main file.
        std::fs::write(f.conf_d.join("shield.conf"), "server=127.0.0.1#5053\n").unwrap();
        check(&c, &f.t, &mut HashSet::new());
        assert!(c.is_set(UNIFI_CONFLICT, Some(DNSFILTER)));
        assert!(c.is_set(UNIFI_CONFLICT, Some(DNS_SHIELD)));
        std::fs::remove_file(f.conf_d.join("shield.conf")).unwrap();
        std::fs::write(&f.conf, "  server=/example/127.0.0.1#5053\n").unwrap();
        check(&c, &f.t, &mut HashSet::new());
        assert!(c.is_set(UNIFI_CONFLICT, Some(DNS_SHIELD)), "the main file too");
        // Both turned off: both clear.
        std::fs::remove_file(&f.t.dnsfilter).unwrap();
        std::fs::write(&f.conf, "server=1.1.1.1\n").unwrap();
        check(&c, &f.t, &mut HashSet::new());
        assert!(c.snapshot().is_empty(), "{:?}", c.snapshot());
    }

    #[test]
    fn the_helpers_reports_never_clear_the_files_findings() {
        let f = fx();
        let c = conditions();
        std::fs::create_dir_all(f.t.dnsfilter.parent().unwrap()).unwrap();
        std::fs::write(&f.t.dnsfilter, b"").unwrap();
        check(&c, &f.t, &mut HashSet::new());
        // The helper finds the same feature's chain, then nothing (or goes away: an empty set).
        let chain = [(UNIFI_CONFLICT.to_owned(), Some(DNSFILTER.to_owned()), None)];
        c.sync_kinds(Source::Helper, &[UNIFI_CONFLICT], &chain);
        c.sync_kinds(Source::Helper, &[UNIFI_CONFLICT], &[]);
        assert!(
            c.is_set(UNIFI_CONFLICT, Some(DNSFILTER)),
            "the file still shows it"
        );
        std::fs::remove_file(&f.t.dnsfilter).unwrap();
        c.sync_kinds(Source::Helper, &[UNIFI_CONFLICT], &chain);
        check(&c, &f.t, &mut HashSet::new());
        assert!(
            c.is_set(UNIFI_CONFLICT, Some(DNSFILTER)),
            "the chain still shows it"
        );
        c.sync_kinds(Source::Helper, &[UNIFI_CONFLICT], &[]);
        assert!(!c.is_set(UNIFI_CONFLICT, Some(DNSFILTER)));
    }

    #[tokio::test]
    async fn the_check_runs_at_start_and_every_period() {
        let f = fx();
        let c = conditions();
        std::fs::create_dir_all(f.t.dnsfilter.parent().unwrap()).unwrap();
        std::fs::write(&f.t.dnsfilter, b"").unwrap();
        let task = tokio::spawn(run(Arc::clone(&c), f.t.clone()));
        let until = |want: bool| {
            let c = Arc::clone(&c);
            async move {
                for _ in 0..500 {
                    if c.is_set(UNIFI_CONFLICT, Some(DNSFILTER)) == want {
                        return true;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                false
            }
        };
        assert!(until(true).await, "found at start");
        std::fs::remove_file(&f.t.dnsfilter).unwrap();
        assert!(until(false).await, "cleared by a later check");
        task.abort();
    }

    /// A path that exists but can't be read (a symlink loop here: unreadable for root too) counts
    /// as off and is logged once, not at every check, and again after it read fine in between
    /// (edge-unifi.md §7; README §2 Health).
    #[test]
    fn an_unreadable_file_is_logged_once_and_counts_as_off() {
        let f = fx();
        let c = conditions();
        let mut warned = HashSet::new();
        std::fs::create_dir_all(f.t.dnsfilter.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&f.t.dnsfilter, &f.t.dnsfilter).unwrap();
        std::fs::remove_file(&f.conf).unwrap();
        std::os::unix::fs::symlink(&f.conf, &f.conf).unwrap();
        let mut logged = check(&c, &f.t, &mut warned);
        logged.sort();
        let mut want = vec![f.t.dnsfilter.clone(), f.conf.clone()];
        want.sort();
        assert_eq!(logged, want);
        assert!(c.snapshot().is_empty(), "unreadable counts as off");
        assert!(check(&c, &f.t, &mut warned).is_empty(), "logged once");
        std::fs::remove_file(&f.conf).unwrap();
        std::fs::write(&f.conf, "server=1.1.1.1\n").unwrap();
        assert!(check(&c, &f.t, &mut warned).is_empty());
        std::fs::remove_file(&f.conf).unwrap();
        std::os::unix::fs::symlink(&f.conf, &f.conf).unwrap();
        assert_eq!(
            check(&c, &f.t, &mut warned),
            vec![f.conf.clone()],
            "unreadable again"
        );
    }

    #[test]
    fn reads_are_bounded() {
        let f = fx();
        // The forwarder past the read cap isn't seen.
        let mut big = vec![b'#'; MAX_FILE as usize];
        big.extend_from_slice(b"\nserver=127.0.0.1#5053\n");
        std::fs::write(&f.conf, &big).unwrap();
        assert!(findings(&f.t, &mut Vec::new()).is_empty());
    }
}
