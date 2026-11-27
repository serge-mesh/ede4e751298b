//! Everything the updater asks of the host, behind one trait so tests can run every step against
//! a temporary root with a fake systemd (`crate::testing::FakeSystem`).
//!
//! The real implementation runs the system's own tools (`systemctl`, `systemd-sysusers`,
//! `systemd-analyze`, `ubnt-device-info`) with a clean environment, a timeout and an output cap
//! (README §2, Bounded), and reads `/proc` directly.

use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::platform::Platform;

/// A finished command.
#[derive(Clone, Debug, Default)]
pub struct CmdOutput {
    /// The exit code; `None` if a signal ended it.
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    /// The first line of stdout, trimmed (`systemctl is-enabled` and `is-active` print one word).
    pub fn word(&self) -> &str {
        self.stdout.lines().next().unwrap_or("").trim()
    }
}

/// Why a bounded command failed.
#[derive(Debug)]
pub enum RunError {
    Spawn(io::Error),
    Timeout,
    OutputTooLarge,
    Io(io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Spawn(e) => write!(f, "couldn't start: {e}"),
            RunError::Timeout => f.write_str("timed out"),
            RunError::OutputTooLarge => f.write_str("output over the cap"),
            RunError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// The host as the updater sees it.
pub trait System {
    /// `systemctl <args>`. `Err` only if it couldn't run or timed out; a non-zero exit is in the
    /// output.
    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput>;
    /// `systemd-sysusers <conf>` (edge-unifi.md §2 step 3).
    fn sysusers(&self, conf: &Path) -> io::Result<CmdOutput>;
    /// `systemd-analyze verify <units>`: advisory, after `install` writes units.
    fn analyze_verify(&self, units: &[PathBuf]) -> io::Result<CmdOutput>;
    /// `ubnt-device-info model` (edge-unifi.md §1).
    fn device_model(&self) -> io::Result<String>;
    /// Runs `<exe> units --platform <p>` as root: 10 s timeout, 1 MiB output cap (edge.md §14
    /// step 3). Returns stdout of a successful run.
    fn run_units(&self, exe: &Path, platform: Platform) -> Result<Vec<u8>, RunError>;
    /// Effective UID 0.
    fn is_root(&self) -> bool;
    /// The system was booted with systemd (`/run/systemd/system` is a directory, as `sd_booted`).
    fn booted_with_systemd(&self) -> bool;
    /// Wall-clock time, for result timestamps only.
    fn now(&self) -> SystemTime;
    /// A monotonic clock, for every timeout (README §2, Clocks).
    fn monotonic(&self) -> Duration;
    fn sleep(&self, d: Duration);
    /// `/proc/sys/kernel/random/boot_id`.
    fn boot_id(&self) -> io::Result<String>;
    /// The architecture name release signatures carry (`aarch64`, `x86_64`).
    fn host_arch(&self) -> String;
    fn random_u64(&self) -> io::Result<u64>;
    /// `fchown` of an open file or directory; `logical` names it for logs and the fake.
    fn chown(&self, file: &File, logical: &Path, uid: u32, gid: u32) -> io::Result<()>;
    /// The owner of a file, from its metadata (the fake keeps its own record).
    fn owner(&self, meta: &Metadata, logical: &Path) -> (u32, u32);
    /// `/proc/self/mountinfo`.
    fn mountinfo(&self) -> io::Result<String>;
    /// A named point between steps. The real system does nothing; the fake can fail or simulate
    /// a crash there, to test interrupted runs.
    fn checkpoint(&self, _at: &'static str) -> io::Result<()> {
        Ok(())
    }
}

/// A fixed `PATH` for the tools the updater runs, so the caller's environment can't pick them.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Timeouts and caps for the commands the real system runs.
pub const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(300);
pub const TOOL_TIMEOUT: Duration = Duration::from_secs(60);
pub const MODEL_TIMEOUT: Duration = Duration::from_secs(10);
pub const UNITS_TIMEOUT: Duration = Duration::from_secs(10);
pub const UNITS_OUTPUT_CAP: usize = 1024 * 1024;
const OUTPUT_CAP: usize = 1024 * 1024;
const STDERR_CAP: usize = 64 * 1024;
/// The mount table is the kernel's, but every read is bounded (README §2).
const MOUNTINFO_CAP: u64 = 16 * 1024 * 1024;

/// The host.
pub struct RealSystem {
    start: Instant,
    pub units_timeout: Duration,
    pub units_cap: usize,
}

impl Default for RealSystem {
    fn default() -> Self {
        RealSystem {
            start: Instant::now(),
            units_timeout: UNITS_TIMEOUT,
            units_cap: UNITS_OUTPUT_CAP,
        }
    }
}

fn tool(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .env("SYSTEMD_PAGER", "")
        .env("SYSTEMD_COLORS", "0")
        .current_dir("/");
    cmd
}

fn to_output(b: Bounded) -> CmdOutput {
    CmdOutput {
        status: b.status.code(),
        stdout: String::from_utf8_lossy(&b.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&b.stderr).into_owned(),
    }
}

fn run_err_to_io(e: RunError) -> io::Error {
    match e {
        RunError::Spawn(e) | RunError::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

impl System for RealSystem {
    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput> {
        let mut cmd = tool("systemctl");
        // Never wait for a password agent: nobody answers a root oneshot.
        cmd.arg("--no-ask-password").args(args);
        run_bounded(cmd, SYSTEMCTL_TIMEOUT, OUTPUT_CAP)
            .map(to_output)
            .map_err(run_err_to_io)
    }

    fn sysusers(&self, conf: &Path) -> io::Result<CmdOutput> {
        let mut cmd = tool("systemd-sysusers");
        cmd.arg(conf);
        run_bounded(cmd, TOOL_TIMEOUT, OUTPUT_CAP)
            .map(to_output)
            .map_err(run_err_to_io)
    }

    fn analyze_verify(&self, units: &[PathBuf]) -> io::Result<CmdOutput> {
        let mut cmd = tool("systemd-analyze");
        cmd.arg("verify").args(units);
        run_bounded(cmd, TOOL_TIMEOUT, OUTPUT_CAP)
            .map(to_output)
            .map_err(run_err_to_io)
    }

    fn device_model(&self) -> io::Result<String> {
        let mut cmd = tool("ubnt-device-info");
        cmd.arg("model");
        let out = run_bounded(cmd, MODEL_TIMEOUT, 4096)
            .map(to_output)
            .map_err(run_err_to_io)?;
        if !out.success() {
            return Err(io::Error::other(format!(
                "ubnt-device-info model failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(out.stdout.trim().to_string())
    }

    fn run_units(&self, exe: &Path, platform: Platform) -> Result<Vec<u8>, RunError> {
        let mut cmd = tool(&exe.to_string_lossy());
        cmd.arg("units").arg("--platform").arg(platform.as_str());
        let out = run_bounded(cmd, self.units_timeout, self.units_cap)?;
        if !out.status.success() {
            return Err(RunError::Io(io::Error::other(format!(
                "exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ))));
        }
        Ok(out.stdout)
    }

    fn is_root(&self) -> bool {
        euid_from_status(&std::fs::read_to_string("/proc/self/status").unwrap_or_default()) == Some(0)
    }

    fn booted_with_systemd(&self) -> bool {
        Path::new("/run/systemd/system").is_dir()
    }

    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic(&self) -> Duration {
        self.start.elapsed()
    }

    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }

    fn boot_id(&self) -> io::Result<String> {
        Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_string())
    }

    fn host_arch(&self) -> String {
        std::env::consts::ARCH.to_string()
    }

    fn random_u64(&self) -> io::Result<u64> {
        let mut b = [0u8; 8];
        File::open("/dev/urandom")?.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn chown(&self, file: &File, _logical: &Path, uid: u32, gid: u32) -> io::Result<()> {
        std::os::unix::fs::fchown(file, Some(uid), Some(gid))
    }

    fn owner(&self, meta: &Metadata, _logical: &Path) -> (u32, u32) {
        (meta.uid(), meta.gid())
    }

    fn mountinfo(&self) -> io::Result<String> {
        let mut text = String::new();
        let n = File::open("/proc/self/mountinfo")?
            .take(MOUNTINFO_CAP + 1)
            .read_to_string(&mut text)?;
        if n as u64 > MOUNTINFO_CAP {
            return Err(io::Error::other(format!(
                "/proc/self/mountinfo is larger than {MOUNTINFO_CAP} bytes"
            )));
        }
        Ok(text)
    }
}

/// The effective UID from `/proc/self/status` (`Uid: real effective saved fs`).
pub fn euid_from_status(status: &str) -> Option<u32> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

/// A finished bounded command.
pub struct Bounded {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

enum Msg {
    Out(io::Result<(Vec<u8>, bool)>),
    Err(io::Result<(Vec<u8>, bool)>),
}

/// Reads a pipe to EOF keeping at most `cap` bytes. With `stop_at_cap`, stops reading as soon as
/// the cap is passed (and says so); otherwise drains and discards the excess, so the child never
/// blocks on a full pipe.
fn read_pipe(mut r: impl Read, cap: usize, stop_at_cap: bool) -> io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let mut over = false;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let room = cap.saturating_sub(out.len());
        if n > room {
            over = true;
            out.extend_from_slice(&buf[..room]);
            if stop_at_cap {
                break;
            }
        } else {
            out.extend_from_slice(&buf[..n]);
        }
    }
    Ok((out, over))
}

/// Runs a command with stdin closed, a timeout and a stdout cap. On timeout or overflow the child
/// is killed. std can't signal a process group, so a grandchild the child left behind survives
/// until the updater's oneshot ends and systemd stops its control group (`KillMode=` default);
/// a grandchild holding the pipe open only makes this call time out.
pub fn run_bounded(mut cmd: Command, timeout: Duration, cap: usize) -> Result<Bounded, RunError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(RunError::Spawn)?;
    let deadline = Instant::now() + timeout;
    // Two readers, one message each: the bound is the message count, so no send blocks.
    let (tx, rx) = mpsc::sync_channel(2);
    if let Some(out) = child.stdout.take() {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Msg::Out(read_pipe(out, cap, true)));
        });
    }
    if let Some(err) = child.stderr.take() {
        thread::spawn(move || {
            let _ = tx.send(Msg::Err(read_pipe(err, STDERR_CAP, false)));
        });
    } else {
        drop(tx);
    }
    let mut stdout = None;
    let mut stderr = None;
    let mut status = None;
    let fail = |child: &mut std::process::Child, e: RunError| {
        let _ = child.kill();
        let _ = child.wait();
        Err(e)
    };
    loop {
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(Msg::Out(Ok((buf, over)))) => {
                if over {
                    return fail(&mut child, RunError::OutputTooLarge);
                }
                stdout = Some(buf);
            }
            Ok(Msg::Err(Ok((buf, _)))) => stderr = Some(buf),
            Ok(Msg::Out(Err(e)) | Msg::Err(Err(e))) => return fail(&mut child, RunError::Io(e)),
            Err(mpsc::RecvTimeoutError::Timeout) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }
        if status.is_none() {
            status = child.try_wait().map_err(RunError::Io)?;
        }
        if let (Some(s), Some(_), Some(_)) = (status, &stdout, &stderr) {
            return Ok(Bounded {
                status: s,
                stdout: stdout.unwrap_or_default(),
                stderr: stderr.unwrap_or_default(),
            });
        }
        if Instant::now() >= deadline {
            return fail(&mut child, RunError::Timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn euid() {
        let s = "Name:\tx\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(euid_from_status(s), Some(0));
        assert_eq!(euid_from_status("Uid:\t5\t7\t5\t5\n"), Some(7));
        assert_eq!(euid_from_status("nothing"), None);
    }

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(script);
        c
    }

    #[test]
    fn bounded_success_and_caps() {
        let out = run_bounded(sh("printf hello; printf oops >&2"), Duration::from_secs(5), 100).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hello");
        assert_eq!(out.stderr, b"oops");
        // Over the stdout cap: killed and refused.
        let r = run_bounded(sh("head -c 5000 /dev/zero"), Duration::from_secs(5), 1000);
        assert!(matches!(r, Err(RunError::OutputTooLarge)), "{:?}", r.err());
        // Exactly at the cap is fine.
        let out = run_bounded(sh("head -c 1000 /dev/zero"), Duration::from_secs(5), 1000).unwrap();
        assert_eq!(out.stdout.len(), 1000);
    }

    #[test]
    fn bounded_timeout() {
        let t = Instant::now();
        let r = run_bounded(sh("exec sleep 30"), Duration::from_millis(300), 100);
        assert!(matches!(r, Err(RunError::Timeout)));
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    /// The real `units` runner: a release whose `units` prints too much, hangs or fails is
    /// refused (edge.md §14 step 3).
    #[test]
    fn real_units_runner() {
        let tmp = tempfile::tempdir().unwrap();
        let write = |name: &str, body: &str| {
            use std::os::unix::fs::PermissionsExt;
            let p = tmp.path().join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let real = RealSystem {
            units_timeout: Duration::from_millis(500),
            units_cap: 2048,
            ..Default::default()
        };
        // Another test forking while a script here is still open for writing makes its exec fail
        // with ETXTBSY until that child execs; try again then.
        struct Retrying(RealSystem);
        impl Retrying {
            fn run_units(&self, exe: &Path, platform: Platform) -> Result<Vec<u8>, RunError> {
                for _ in 0..100 {
                    match self.0.run_units(exe, platform) {
                        Err(RunError::Spawn(e)) if e.raw_os_error() == Some(26) => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        r => return r,
                    }
                }
                self.0.run_units(exe, platform)
            }
        }
        let sys = Retrying(real);
        let ok = write(
            "ok",
            "#!/bin/sh\n[ \"$1 $2 $3\" = \"units --platform debian\" ] || exit 9\nprintf '{\"format\":1,\"units\":{}}'\n",
        );
        assert_eq!(
            sys.run_units(&ok, Platform::Debian).unwrap(),
            br#"{"format":1,"units":{}}"#
        );
        let big = write("big", "#!/bin/sh\nhead -c 4096 /dev/zero\n");
        assert!(matches!(
            sys.run_units(&big, Platform::Unifi),
            Err(RunError::OutputTooLarge)
        ));
        let slow = write("slow", "#!/bin/sh\nexec sleep 30\n");
        assert!(matches!(
            sys.run_units(&slow, Platform::Unifi),
            Err(RunError::Timeout)
        ));
        let bad = write("bad", "#!/bin/sh\necho no >&2\nexit 3\n");
        assert!(matches!(
            sys.run_units(&bad, Platform::Unifi),
            Err(RunError::Io(_))
        ));
        assert!(matches!(
            sys.run_units(&tmp.path().join("missing"), Platform::Unifi),
            Err(RunError::Spawn(_))
        ));
        // The environment is clean: only the fixed PATH and locale.
        let env = write(
            "env",
            "#!/bin/sh\nenv | grep -v '^PWD=' | grep -v '^SHLVL=' | grep -v '^_=' | sort | tr '\\n' ' '\n",
        );
        let out = sys.run_units(&env, Platform::Unifi).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("PATH=/usr/local/sbin"), "{out}");
        assert!(!out.contains("HOME="), "{out}");
    }
}
