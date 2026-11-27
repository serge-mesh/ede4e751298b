//! Running `iptables-save`, `iptables-restore` and `ip` with a deadline, a clean environment and
//! capped output (README "Bounded": every external call has a timeout).

use std::io::{Read, Write};
use std::net::IpAddr;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::ExecError;
use super::nat::IfAddr;

/// `PATH` for child processes; nothing is inherited from the service environment.
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
/// Largest stderr kept.
const MAX_STDERR: usize = 64 * 1024;

pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Reads all of `r`, keeping at most `cap` bytes; returns the bytes and whether more came.
fn read_capped(mut r: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let mut over = false;
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                if n > room {
                    over = true;
                }
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    (out, over)
}

/// Classifies a failed iptables run from its stderr. The texts are xtables' (`xshared.c`):
/// a lock wait that ran out is `lock_timeout`; a lock file that can't be opened is a permission
/// problem, never a timeout.
pub fn classify_failure(status: Option<i32>, stderr: &str) -> ExecError {
    let first = stderr
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(300)
        .collect::<String>();
    if stderr.contains("Stopped waiting after") || stderr.contains("holding the xtables lock") {
        return ExecError::LockTimeout;
    }
    if stderr.contains("can't open lock file") || stderr.contains("Can't open lock file") {
        return ExecError::LockPermission(first);
    }
    if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
        return ExecError::Permission(first);
    }
    ExecError::Failed {
        code: status,
        stderr: stderr.chars().take(512).collect(),
    }
}

/// Runs `cmd args…`, feeding `stdin`, killing it after `timeout`.
pub fn run(
    cmd: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
    max_out: usize,
) -> Result<Output, ExecError> {
    let mut child = Command::new(cmd)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ExecError::Spawn(format!("{cmd}: {e}")))?;
    let writer = match (stdin, child.stdin.take()) {
        (Some(data), Some(mut si)) => {
            let data = data.to_vec();
            Some(thread::spawn(move || {
                let _ = si.write_all(&data);
            }))
        }
        _ => None,
    };
    let so = child.stdout.take();
    let se = child.stderr.take();
    let out_t = thread::spawn(move || so.map(|s| read_capped(s, max_out)).unwrap_or_default());
    let err_t = thread::spawn(move || se.map(|s| read_capped(s, MAX_STDERR)).unwrap_or_default());
    let deadline = Instant::now() + timeout;
    let mut nap = Duration::from_millis(1);
    let status: ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ExecError::Timeout);
            }
            Ok(None) => {
                thread::sleep(nap);
                nap = (nap * 2).min(Duration::from_millis(20));
            }
            Err(e) => return Err(ExecError::Spawn(format!("{cmd}: {e}"))),
        }
    };
    if let Some(w) = writer {
        let _ = w.join();
    }
    let (stdout, over) = out_t.join().unwrap_or_default();
    let (stderr, _) = err_t.join().unwrap_or_default();
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    if !status.success() {
        return Err(classify_failure(status.code(), &stderr));
    }
    if over {
        return Err(ExecError::OutputTooLarge(max_out));
    }
    Ok(Output { stdout, stderr })
}

/// Marks a byte of `iptables-save` output that isn't UTF-8 (a noncharacter, so no comment holds
/// it by accident; one that does is escaped too).
pub const BYTE_ESC: char = '\u{FDD0}';
/// A byte `b` is carried as [`BYTE_ESC`] followed by `char::from_u32(BYTE_BASE + b)`.
const BYTE_BASE: u32 = 0x100;

/// `iptables-save` output as text, losslessly. Bytes that aren't UTF-8 (a UniFi comment cut
/// mid-character) don't fail the whole table: each becomes [`BYTE_ESC`] plus a character
/// standing for it, and a genuine `BYTE_ESC` is doubled. The parser sees ordinary characters
/// in a comment, and [`restore_bytes`] gives back the original bytes, so a stray jump to
/// Picket's chains read from such a line can still be deleted by its exact rule spec
/// (edge-firewall.md §4 `apply`, `disable`, re-assert).
pub fn save_text(out: Vec<u8>) -> String {
    let e = match String::from_utf8(out) {
        Ok(s) if !s.contains(BYTE_ESC) => return s,
        Ok(s) => return s.replace(BYTE_ESC, &format!("{BYTE_ESC}{BYTE_ESC}")),
        Err(e) => e.into_bytes(),
    };
    let mut s = String::with_capacity(e.len() + 16);
    for chunk in e.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == BYTE_ESC {
                s.push(BYTE_ESC);
            }
            s.push(c);
        }
        for &b in chunk.invalid() {
            s.push(BYTE_ESC);
            s.push(byte_char(b));
        }
    }
    s
}

/// The character standing for byte `b` after [`BYTE_ESC`].
#[expect(
    clippy::expect_used,
    reason = "BYTE_BASE + a byte is U+0100..=U+01FF, always a char"
)]
fn byte_char(b: u8) -> char {
    char::from_u32(BYTE_BASE + u32::from(b)).expect("U+0100..=U+01FF")
}

/// The bytes `iptables-restore` is fed for `text`: [`save_text`]'s escapes undone, so a rule
/// read from the kernel is named again byte for byte. Text Picket generates holds no escapes.
pub fn restore_bytes(text: &str) -> Vec<u8> {
    if !text.contains(BYTE_ESC) {
        return text.as_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut buf = [0u8; 4];
    while let Some(c) = chars.next() {
        if c == BYTE_ESC {
            match chars.peek().copied() {
                Some(BYTE_ESC) => {
                    chars.next();
                    out.extend_from_slice(BYTE_ESC.encode_utf8(&mut buf).as_bytes());
                    continue;
                }
                Some(n) => {
                    if let Some(b) = u32::from(n)
                        .checked_sub(BYTE_BASE)
                        .and_then(|v| u8::try_from(v).ok())
                    {
                        chars.next();
                        out.push(b);
                        continue;
                    }
                }
                _ => {}
            }
        }
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    out
}

#[derive(Deserialize)]
struct IpLink {
    #[serde(default)]
    ifname: String,
    #[serde(default)]
    addr_info: Vec<IpAddrInfo>,
}

#[derive(Deserialize)]
struct IpAddrInfo {
    #[serde(default)]
    local: Option<IpAddr>,
    #[serde(default)]
    prefixlen: Option<u8>,
}

/// Most interfaces and addresses kept from `ip -j addr`.
const MAX_LINKS: usize = 4096;
const MAX_ADDRS_PER_LINK: usize = 1024;

/// Parses `ip -j addr show` output into the gateway's addresses.
pub fn parse_ip_addr_json(out: &[u8]) -> Result<Vec<IfAddr>, ExecError> {
    let links: Vec<IpLink> = serde_json::from_slice(out).map_err(|e| ExecError::Parse(e.to_string()))?;
    let mut v = Vec::new();
    for l in links.into_iter().take(MAX_LINKS) {
        if l.ifname.is_empty() || l.ifname.len() > 15 {
            continue;
        }
        for a in l.addr_info.into_iter().take(MAX_ADDRS_PER_LINK) {
            let (Some(addr), Some(prefix)) = (a.local, a.prefixlen) else {
                continue;
            };
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if prefix <= max {
                v.push(IfAddr {
                    ifname: l.ifname.clone(),
                    addr,
                    prefix,
                });
            }
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_messages_are_classified_apart() {
        let t = classify_failure(
            Some(4),
            "Another app is currently holding the xtables lock. Stopped waiting after 5s.\n",
        );
        assert_eq!(t, ExecError::LockTimeout);
        assert_eq!(t.code(), "lock_timeout");
        let p = classify_failure(
            Some(4),
            "Fatal: can't open lock file /run/xtables.lock: Permission denied\n",
        );
        assert!(matches!(p, ExecError::LockPermission(_)));
        assert_eq!(p.code(), "lock_permission");
        let r = classify_failure(
            Some(3),
            "iptables v1.8.7 (legacy): can't initialize iptables table `filter': Permission denied (you must be root)\n",
        );
        assert_eq!(r.code(), "permission");
        assert_eq!(
            classify_failure(Some(1), "iptables-restore: line 3 failed\n").code(),
            "exec_failed"
        );
    }

    #[test]
    fn save_output_with_invalid_utf8_still_parses() {
        // A comment cut mid-character (xt_comment holds 255 bytes) mustn't cost the whole table.
        let mut out = b"*filter\n:C - [0:0]\n[0:0] -A C -m comment --comment \"FIREWALL_POLICY 1 Bl".to_vec();
        out.extend_from_slice(&[0xf0, 0x9f]);
        out.extend_from_slice(b"\" -j REJECT\n[0:0] -A C -j ACCEPT\nCOMMIT\n");
        let text = save_text(out);
        let t = super::super::model::Table::parse(&text).unwrap();
        let c = t.chain("C").unwrap();
        assert_eq!(c.rules.len(), 2);
        assert_eq!(c.rules[0].target_name(), Some("REJECT"));
        assert!(
            c.rules[0]
                .spec()
                .unwrap()
                .comment()
                .unwrap()
                .starts_with("FIREWALL_POLICY 1 Bl")
        );
    }

    #[test]
    fn bytes_that_are_not_utf8_survive_the_round_trip() {
        // A stray jump to PICKET-FWD whose comment was cut mid-character must be deletable: the
        // `-D` names it with its original bytes (edge-firewall.md §4 apply, disable, re-assert).
        let mut save = b"*filter\n:FORWARD ACCEPT [0:0]\n:PICKET-FWD - [0:0]\n[0:0] -A FORWARD -i lo -m comment --comment \"Bl".to_vec();
        save.extend_from_slice(&[0xf0, 0x9f]);
        save.extend_from_slice(b"\" -j PICKET-FWD\n[0:0] -A FORWARD -j REJECT\nCOMMIT\n");
        let text = save_text(save.clone());
        assert_eq!(restore_bytes(&text), save);
        let t = super::super::model::Table::parse(&text).unwrap();
        let w = super::super::plan::Want {
            family: super::super::Family::V4,
            platform: super::super::Platform::Debian,
            interfaces: &[],
            dns6: &[],
            disabled: false,
        };
        let restore = super::super::plan::plan(&t, &w).restore.unwrap();
        let mut del = b"-D FORWARD -i lo -m comment --comment \"Bl".to_vec();
        del.extend_from_slice(&[0xf0, 0x9f]);
        del.extend_from_slice(b"\" -j PICKET-FWD\n");
        let bytes = restore_bytes(&restore);
        assert!(bytes.windows(del.len()).any(|w| w == del), "{restore}");
        // Text that happens to hold the escape character itself round-trips too, and valid
        // UTF-8 is left as it is.
        for b in [
            "x\u{FDD0}y".as_bytes().to_vec(),
            "\u{FDD0}\u{0180}".as_bytes().to_vec(),
            "naïve Block All".as_bytes().to_vec(),
            vec![0xff, b'a', 0x80, 0xc3],
        ] {
            assert_eq!(restore_bytes(&save_text(b.clone())), b);
        }
        assert_eq!(save_text("naïve".as_bytes().to_vec()), "naïve");
    }

    #[test]
    fn run_times_out_and_caps_output() {
        assert_eq!(
            run("sleep", &["5"], None, Duration::from_millis(100), 1024).err(),
            Some(ExecError::Timeout)
        );
        let r = run(
            "head",
            &["-c", "5000", "/dev/zero"],
            None,
            Duration::from_secs(5),
            1000,
        );
        assert_eq!(r.err(), Some(ExecError::OutputTooLarge(1000)));
        let ok = run("cat", &[], Some(b"hello"), Duration::from_secs(5), 1000).unwrap();
        assert_eq!(ok.stdout, b"hello");
        // The environment is clean.
        let env = run("env", &[], None, Duration::from_secs(5), 10_000).unwrap();
        let env = String::from_utf8(env.stdout).unwrap();
        assert!(!env.contains("NOTIFY_SOCKET"));
        assert!(env.contains("LC_ALL=C"));
    }

    #[test]
    fn parses_ip_json() {
        let j = br#"[{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
            {"ifindex":5,"ifname":"br0","addr_info":[{"family":"inet","local":"192.168.1.1","prefixlen":24},
            {"family":"inet6","local":"fe80::1","prefixlen":64},{"family":"inet6","local":"fd00::1","prefixlen":200}]}]"#;
        let v = parse_ip_addr_json(j).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(
            v[1],
            IfAddr {
                ifname: "br0".into(),
                addr: "192.168.1.1".parse().unwrap(),
                prefix: 24
            }
        );
        assert!(parse_ip_addr_json(b"{").is_err());
    }
}
