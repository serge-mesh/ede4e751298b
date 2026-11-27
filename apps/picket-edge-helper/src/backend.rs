//! Everything the helper does to the system goes through [`Backend`]: ipset over netlink,
//! iptables by exec, the gateway's addresses, clocks and the files in `<helper_dir>`. The real
//! implementation is [`RealBackend`]; `fake::FakeBackend` (feature `testkit`) backs the tests, so
//! the protocol and the state machine run without root or `CAP_NET_ADMIN`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ipset::client::NetlinkIpset;
use crate::ipset::{CreateSpec, Elem, IpsetError, Member, SetHeader};
use crate::iptables::exec;
use crate::iptables::nat::IfAddr;
use crate::iptables::{ExecError, Family, TableName};

/// One add or delete. Set names are always one of Picket's eight (validated before this).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetOp {
    pub set: &'static str,
    pub elem: Elem,
    /// Timeout for an add to a timed set; `None` for the static and exempt sets.
    pub timeout: Option<u32>,
}

pub trait Backend: Send + Sync + 'static {
    // ipset, control path (its own netlink socket)
    fn ipset_header(&self, name: &str) -> Result<Option<SetHeader>, IpsetError>;
    fn ipset_create(&self, spec: &CreateSpec) -> Result<(), IpsetError>;
    fn ipset_destroy(&self, name: &str) -> Result<(), IpsetError>;
    fn ipset_list(&self, name: &str, sink: &mut dyn FnMut(Member)) -> Result<SetHeader, IpsetError>;
    fn ipset_add_ctl(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>>;
    fn ipset_del_ctl(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>>;

    // ipset, fast path (`ensure`, `delete`, the watchdog probe; its own netlink socket)
    fn ipset_add(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>>;
    fn ipset_del(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>>;
    fn ipset_probe(&self) -> Result<(), IpsetError>;

    // iptables and addresses
    /// `iptables-save` output, with bytes that aren't UTF-8 escaped ([`exec::save_text`]).
    fn save(&self, family: Family, table: TableName) -> Result<String, ExecError>;
    /// Runs `iptables-restore --noflush` on `text`, escapes undone ([`exec::restore_bytes`]).
    fn restore(&self, family: Family, text: &str) -> Result<(), ExecError>;
    fn addresses(&self) -> Result<Vec<IfAddr>, ExecError>;

    // clocks
    /// Wall clock, Unix milliseconds.
    fn wall_ms(&self) -> i64;
    /// Monotonic time since an arbitrary origin.
    fn mono(&self) -> Duration;
    /// System uptime (`/proc/uptime`).
    fn uptime(&self) -> Option<Duration>;

    // files in the state directory
    fn read_file(&self, name: &str, max: u64) -> io::Result<Option<Vec<u8>>>;
    fn open_file(&self, name: &str) -> io::Result<Option<Box<dyn Read + Send>>>;
    /// Writes `name` atomically: `name.tmp`, fsync, rename, fsync of the directory.
    fn write_file(
        &self,
        name: &str,
        write: &mut dyn FnMut(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<()>;
    fn remove_file(&self, name: &str) -> io::Result<()>;
}

/// Exec limits.
const SAVE_TIMEOUT: Duration = Duration::from_secs(15);
const SAVE_MAX: usize = 32 << 20;
/// `-w 5` waits up to 5 s for the lock, plus the restore itself.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(20);
const IP_TIMEOUT: Duration = Duration::from_secs(5);
const IP_MAX: usize = 4 << 20;

pub struct RealBackend {
    fast: Mutex<Option<NetlinkIpset>>,
    ctl: Mutex<Option<NetlinkIpset>>,
    state_dir: PathBuf,
    origin: Instant,
}

impl RealBackend {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            fast: Mutex::new(None),
            ctl: Mutex::new(None),
            state_dir,
            origin: Instant::now(),
        }
    }

    /// Runs `f` on a socket, opening it if needed; after an I/O error or timeout the socket is
    /// dropped and reopened next time, so a confused socket can't wedge the helper.
    fn with<T>(
        slot: &Mutex<Option<NetlinkIpset>>,
        f: impl FnOnce(&mut NetlinkIpset) -> Result<T, IpsetError>,
    ) -> Result<T, IpsetError> {
        let mut g = slot.lock().unwrap_or_else(|p| p.into_inner());
        let sock = match g.take() {
            Some(s) => s,
            None => NetlinkIpset::open()?,
        };
        let r = f(g.insert(sock));
        if matches!(
            r,
            Err(IpsetError::Io(_) | IpsetError::Timeout | IpsetError::Decode(_))
        ) {
            *g = None;
        }
        r
    }

    fn batch(slot: &Mutex<Option<NetlinkIpset>>, ops: &[SetOp], add: bool) -> Vec<Result<(), IpsetError>> {
        let mut g = slot.lock().unwrap_or_else(|p| p.into_inner());
        let sock = match g.take() {
            Some(s) => s,
            None => match NetlinkIpset::open() {
                Ok(s) => s,
                Err(e) => return vec![Err(e); ops.len()],
            },
        };
        let sock = g.insert(sock);
        let r = if add {
            let v: Vec<(&str, Elem, Option<u32>)> = ops.iter().map(|o| (o.set, o.elem, o.timeout)).collect();
            sock.add(&v)
        } else {
            let v: Vec<(&str, Elem)> = ops.iter().map(|o| (o.set, o.elem)).collect();
            sock.del(&v)
        };
        if r.iter().any(|x| {
            matches!(
                x,
                Err(IpsetError::Io(_) | IpsetError::Timeout | IpsetError::Decode(_))
            )
        }) {
            *g = None;
        }
        r
    }

    fn path(&self, name: &str) -> PathBuf {
        self.state_dir.join(name)
    }
}

fn tool(family: Family, base: &str) -> String {
    match family {
        Family::V4 => format!("ip{base}"),
        Family::V6 => format!("ip6{base}"),
    }
}

impl Backend for RealBackend {
    fn ipset_header(&self, name: &str) -> Result<Option<SetHeader>, IpsetError> {
        Self::with(&self.ctl, |s| s.header(name))
    }
    fn ipset_create(&self, spec: &CreateSpec) -> Result<(), IpsetError> {
        Self::with(&self.ctl, |s| s.create(spec))
    }
    fn ipset_destroy(&self, name: &str) -> Result<(), IpsetError> {
        Self::with(&self.ctl, |s| s.destroy(name))
    }
    fn ipset_list(&self, name: &str, sink: &mut dyn FnMut(Member)) -> Result<SetHeader, IpsetError> {
        Self::with(&self.ctl, |s| s.list(name, sink))
    }
    fn ipset_add_ctl(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        Self::batch(&self.ctl, ops, true)
    }
    fn ipset_del_ctl(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        Self::batch(&self.ctl, ops, false)
    }
    fn ipset_add(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        Self::batch(&self.fast, ops, true)
    }
    fn ipset_del(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        Self::batch(&self.fast, ops, false)
    }
    fn ipset_probe(&self) -> Result<(), IpsetError> {
        Self::with(&self.fast, |s| s.probe())
    }

    fn save(&self, family: Family, table: TableName) -> Result<String, ExecError> {
        // iptables-save reads each table atomically and never waits on the xtables lock, so the
        // 2 s re-assert keeps reading while another writer holds it; -c adds the counters.
        let cmd = tool(family, "tables-save");
        let args: &[&str] = match table {
            TableName::Filter => &["-c", "-t", "filter"],
            TableName::Nat => &["-t", "nat"],
        };
        let out = exec::run(&cmd, args, None, SAVE_TIMEOUT, SAVE_MAX)?;
        Ok(exec::save_text(out.stdout))
    }

    fn restore(&self, family: Family, text: &str) -> Result<(), ExecError> {
        let cmd = tool(family, "tables-restore");
        // Bytes of rules read from the kernel that aren't UTF-8 go back as they came.
        let bytes = exec::restore_bytes(text);
        exec::run(
            &cmd,
            &["--noflush", "-w", "5"],
            Some(&bytes),
            RESTORE_TIMEOUT,
            64 * 1024,
        )
        .map(|_| ())
    }

    fn addresses(&self) -> Result<Vec<IfAddr>, ExecError> {
        let out = exec::run("ip", &["-j", "addr", "show"], None, IP_TIMEOUT, IP_MAX)?;
        exec::parse_ip_addr_json(&out.stdout)
    }

    fn wall_ms(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
            Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
        }
    }
    fn mono(&self) -> Duration {
        self.origin.elapsed()
    }
    fn uptime(&self) -> Option<Duration> {
        let s = fs::read_to_string("/proc/uptime").ok()?;
        let secs: f64 = s.split_whitespace().next()?.parse().ok()?;
        (secs.is_finite() && secs >= 0.0).then(|| Duration::from_secs_f64(secs))
    }

    fn read_file(&self, name: &str, max: u64) -> io::Result<Option<Vec<u8>>> {
        match File::open(self.path(name)) {
            Ok(f) => {
                let mut v = Vec::new();
                f.take(max + 1).read_to_end(&mut v)?;
                if v.len() as u64 > max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{name} is too large"),
                    ));
                }
                Ok(Some(v))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn open_file(&self, name: &str) -> io::Result<Option<Box<dyn Read + Send>>> {
        match File::open(self.path(name)) {
            Ok(f) => Ok(Some(Box::new(io::BufReader::with_capacity(64 * 1024, f)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn write_file(
        &self,
        name: &str,
        write: &mut dyn FnMut(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<()> {
        let tmp = self.path(&format!("{name}.tmp"));
        let res = (|| {
            let f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            let mut w = io::BufWriter::with_capacity(64 * 1024, f);
            write(&mut w)?;
            let f = w.into_inner().map_err(|e| e.into_error())?;
            f.sync_all()?;
            fs::rename(&tmp, self.path(name))?;
            File::open(&self.state_dir)?.sync_all()
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }
    fn remove_file(&self, name: &str) -> io::Result<()> {
        match fs::remove_file(self.path(name)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn state_files_are_written_atomically_and_privately() {
        let dir = tempfile::tempdir().unwrap();
        let b = RealBackend::new(dir.path().to_path_buf());
        assert!(b.read_file("rules.json", 100).unwrap().is_none());
        assert!(b.open_file("rules.json").unwrap().is_none());
        b.remove_file("rules.json").unwrap();
        b.write_file("rules.json", &mut |w| w.write_all(b"{}")).unwrap();
        assert_eq!(b.read_file("rules.json", 100).unwrap().unwrap(), b"{}");
        let mode = fs::metadata(dir.path().join("rules.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // A write that fails part-way keeps the old file and leaves no temporary file.
        let failed = b.write_file("rules.json", &mut |w| {
            w.write_all(b"partial")?;
            Err(io::Error::other("no space left on device"))
        });
        assert!(failed.is_err());
        assert_eq!(b.read_file("rules.json", 100).unwrap().unwrap(), b"{}");
        assert!(!dir.path().join("rules.json.tmp").exists());
        // Over the cap: refused, never truncated.
        assert!(b.read_file("rules.json", 1).is_err());
        let mut s = String::new();
        b.open_file("rules.json")
            .unwrap()
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "{}");
        b.remove_file("rules.json").unwrap();
        assert!(b.read_file("rules.json", 100).unwrap().is_none());
    }
}
