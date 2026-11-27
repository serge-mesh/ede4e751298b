//! Small helpers: private files, atomic writes, time, random strings.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use picket_api::time::Timestamp;

/// Now, in UTC.
pub fn now() -> Timestamp {
    Timestamp::now()
}

/// The storage form of a timestamp: RFC 3339 with microseconds and `Z` (api.md §5). Strings in
/// this form sort in time order, so SQL compares them directly.
pub fn ts(t: &Timestamp) -> String {
    picket_api::time::format_micros(t)
}

/// [`ts`] of now.
pub fn now_ts() -> String {
    ts(&now())
}

/// Parses a stored timestamp (RFC 3339, any offset).
pub fn parse_ts(s: &str) -> Option<Timestamp> {
    picket_api::time::parse(s).ok()
}

/// `end - len` for a window from settings (a retention, expiry or lookback window), saturating
/// at the start of the timestamp range (jiff's is narrower than chrono's, and `-` would panic).
pub fn window_start(end: Timestamp, len: std::time::Duration) -> Timestamp {
    end.checked_sub(len).unwrap_or(Timestamp::MIN)
}

/// A UTC day, `YYYY-MM-DD`: the lookup day counters' key and the config export's file name.
pub fn day_key(t: &Timestamp) -> String {
    t.strftime("%Y-%m-%d").to_string()
}

/// An HTTP date (RFC 9110 §5.6.7, IMF-fixdate), as `Last-Modified` carries it.
pub fn http_date(t: &Timestamp) -> String {
    t.strftime("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// A UTC minute, `YYYY-MM-DD HH:MM`, as the LAN CA's name carries it.
pub fn utc_minute(t: &Timestamp) -> String {
    t.strftime("%Y-%m-%d %H:%M").to_string()
}

/// fsyncs a directory so a rename or unlink in it is durable.
pub fn fsync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    f.sync_all().with_context(|| format!("fsync {}", dir.display()))
}

/// Writes `bytes` to `path` atomically: a temporary file next to it (mode `mode`), fsync,
/// rename, fsync of the directory. A crash leaves the old file or the new one, plus at most the
/// temporary file, which its owner deletes at start.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let name = path
        .file_name()
        .context("path has no file name")?
        .to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path).with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
    fsync_dir(dir)
}

/// Writes a new private file (0600) that must not exist yet, and fsyncs it.
pub fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Creates a directory (and parents) with mode 0750 when missing.
pub fn ensure_dir(path: &Path) -> Result<()> {
    if !path.is_dir() {
        fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o750));
    }
    Ok(())
}

const ALNUM: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

/// A random password of `len` characters from an unambiguous alphanumeric alphabet (no 0/O,
/// 1/l/I), drawn from the thread CSPRNG (core.md §12: 24 random characters).
pub fn random_password(len: usize) -> String {
    (0..len)
        .map(|_| {
            let i = rand::random_range(0..ALNUM.len());
            char::from(ALNUM[i])
        })
        .collect()
}

/// `n` random bytes from the thread CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

/// A random lowercase hex id of `bytes` bytes.
pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::fill(&mut b[..]);
    hex::encode(b)
}

/// Escapes control characters for logs and messages (core.md §12: control characters are shown
/// escaped), and caps the length.
pub fn sanitize_for_message(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if out.len() >= max {
            out.push('…');
            break;
        }
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

// Integer conversions without a lossy `as` (#343). SQLite integers are i64; counts and sizes
// go in as u64 or usize directly (rusqlite's `fallible_uint`: an error past i64::MAX).

/// A count or size read from SQLite as u64: a negative value (never written) reads as 0.
pub fn nonneg(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// [`nonneg`] as a usize.
pub fn nonneg_usize(v: i64) -> usize {
    usize::try_from(v).unwrap_or(0)
}

/// A count, size or length as i64, saturating at i64::MAX (comparisons with SQLite counts).
pub fn sat_i64(n: impl TryInto<i64>) -> i64 {
    n.try_into().unwrap_or(i64::MAX)
}

/// Float to integer: Rust's `as` saturates at the integer type's ends and reads NaN as 0, which
/// is what these callers want (scores, quantile indexes, schedule times).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "float-to-int `as` saturates (NaN is 0): the intended conversion"
)]
pub fn f64_to_u64(f: f64) -> u64 {
    f as u64
}

/// [`f64_to_u64`] for usize.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "float-to-int `as` saturates (NaN is 0): the intended conversion"
)]
pub fn f64_to_usize(f: f64) -> usize {
    f as usize
}

/// [`f64_to_u64`] for i64.
#[expect(
    clippy::cast_possible_truncation,
    reason = "float-to-int `as` saturates (NaN is 0): the intended conversion"
)]
pub fn f64_to_i64(f: f64) -> i64 {
    f as i64
}

/// [`f64_to_u64`] for u32.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "float-to-int `as` saturates (NaN is 0): the intended conversion"
)]
pub fn f64_to_u32(f: f64) -> u32 {
    f as u32
}

/// A score kept as f32: a value beyond f32's range becomes infinite (callers drop it).
#[expect(
    clippy::cast_possible_truncation,
    reason = "f64 to f32 rounds; beyond f32's range it becomes infinite, which callers drop"
)]
pub fn f64_to_f32(f: f64) -> f32 {
    f as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_shape() {
        let p = random_password(24);
        assert_eq!(p.len(), 24);
        assert!(p.bytes().all(|b| ALNUM.contains(&b)));
        assert_ne!(p, random_password(24));
    }

    #[test]
    fn atomic_write_replaces() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        write_atomic(&p, b"one", 0o600).unwrap();
        write_atomic(&p, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_for_message("a\nb", 10), "a\\nb");
        assert!(sanitize_for_message(&"x".repeat(50), 10).ends_with('…'));
    }

    /// Golden (F1, F6, F9, F10 and reading stored timestamps; plan §5 step 1, unchanged after the
    /// move to jiff).
    #[test]
    fn golden_time_forms() {
        use picket_api::time::golden::{PARSE_OK, PARSE_REJECTED, ROWS, ts_from_nanos};
        for r in ROWS {
            let t = ts_from_nanos(r.nanos);
            assert_eq!(ts(&t), r.micros, "{}", r.name);
            assert_eq!(day_key(&t), r.day, "{}", r.name);
            assert_eq!(http_date(&t), r.http_date, "{}", r.name);
            assert_eq!(utc_minute(&t), r.minute, "{}", r.name);
            assert_eq!(
                parse_ts(r.micros),
                Some(ts_from_nanos(r.nanos - r.nanos.rem_euclid(1_000))),
                "{}",
                r.name
            );
            assert_eq!(parse_ts(r.autosi), Some(t), "{}", r.name);
        }
        for (input, want) in PARSE_OK {
            assert_eq!(
                parse_ts(input).as_ref().map(ts).as_deref(),
                Some(*want),
                "{input:?}"
            );
        }
        for input in PARSE_REJECTED {
            assert_eq!(parse_ts(input), None, "{input:?}");
        }
    }

    #[test]
    fn timestamps_sort() {
        let a = ts(&parse_ts("2026-01-01T00:00:00Z").unwrap());
        let b = ts(&parse_ts("2026-01-01T00:00:00.5Z").unwrap());
        assert!(a < b);
    }
}
