//! Filesystem access that never follows a link it didn't mean to.
//!
//! std has no `openat`, so a [`Dir`] holds an open directory and reaches its entries through
//! `/proc/self/fd/<fd>/<name>`: the kernel resolves the magic link to the directory it opened,
//! and `O_NOFOLLOW` then applies to `<name>` alone. That gives `openat`, `mkdirat`, `unlinkat`,
//! `renameat` and `symlinkat` semantics without `unsafe` or libc (edge.md §14: "opens anything
//! there with `O_NOFOLLOW`, relative to a directory it opened").
//!
//! Every path is handled as a *logical* absolute path (as the units and the spec name it) under a
//! [`Root`] prefix, which is `/` in production and a temporary directory in tests.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::system::System;

// Linux open(2) flags std doesn't export. They differ between architectures; the edge ships for
// aarch64 and x86_64 only (build-and-test.md §3). `tests::nofollow_constants` checks them.
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: i32 = 0o100000;
#[cfg(target_arch = "aarch64")]
pub const O_DIRECTORY: i32 = 0o40000;
#[cfg(not(target_arch = "aarch64"))]
pub const O_NOFOLLOW: i32 = 0o400000;
#[cfg(not(target_arch = "aarch64"))]
pub const O_DIRECTORY: i32 = 0o200000;
pub const O_NONBLOCK: i32 = 0o4000;
pub const O_NOCTTY: i32 = 0o400;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("picket-edge-update supports aarch64 and x86_64 Linux only (open(2) flag values)");

const ELOOP: i32 = 40;
const ENOTDIR: i32 = 20;

/// The prefix every logical path lives under: `/` in production.
#[derive(Clone, Debug)]
pub struct Root {
    base: PathBuf,
}

impl Root {
    pub fn new(base: impl Into<PathBuf>) -> Root {
        Root { base: base.into() }
    }

    pub fn system() -> Root {
        Root::new("/")
    }

    /// The real path of a logical absolute path.
    pub fn real(&self, logical: impl AsRef<Path>) -> PathBuf {
        let logical = logical.as_ref();
        let rel = logical.strip_prefix("/").unwrap_or(logical);
        if rel.as_os_str().is_empty() {
            self.base.clone()
        } else {
            self.base.join(rel)
        }
    }
}

/// Why a bounded read failed.
#[derive(Debug)]
pub enum ReadError {
    Missing,
    /// A symlink, directory, FIFO, socket or device.
    NotRegular,
    /// More than one hard link (when the caller requires one).
    Linked,
    TooLarge,
    Io(io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Missing => f.write_str("missing"),
            ReadError::NotRegular => f.write_str("not a regular file (a link, directory or special file)"),
            ReadError::Linked => f.write_str("has more than one hard link"),
            ReadError::TooLarge => f.write_str("too large"),
            ReadError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// True for the errors an `O_NOFOLLOW | O_DIRECTORY` open returns on a symlink or non-directory.
pub fn is_link_or_not_dir(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(ELOOP) | Some(ENOTDIR))
}

/// Opens a directory without following a symlink in its last component.
pub fn open_dir_nofollow(real: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(real)
}

/// An open directory, addressed by its logical path.
#[derive(Debug)]
pub struct Dir {
    file: File,
    logical: PathBuf,
}

impl Dir {
    /// Opens `logical` under `root`. Earlier components may be links; the last may not.
    pub fn open(root: &Root, logical: impl AsRef<Path>) -> io::Result<Dir> {
        let logical = logical.as_ref().to_path_buf();
        let file = open_dir_nofollow(&root.real(&logical))?;
        Ok(Dir { file, logical })
    }

    /// Opens `logical` under `root`, following links in every component: for root-owned
    /// parents only, never for a directory the updater changes.
    pub fn open_follow(root: &Root, logical: impl AsRef<Path>) -> io::Result<Dir> {
        let logical = logical.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY)
            .open(root.real(&logical))?;
        Ok(Dir { file, logical })
    }

    pub fn logical(&self) -> &Path {
        &self.logical
    }

    /// A second handle on the same open directory.
    pub fn try_clone(&self) -> io::Result<Dir> {
        Ok(Dir {
            file: self.file.try_clone()?,
            logical: self.logical.clone(),
        })
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }

    /// The logical path of an entry.
    pub fn logical_at(&self, name: &str) -> PathBuf {
        self.logical.join(name)
    }

    /// The `/proc/self/fd` path of an entry, which resolves relative to this open directory.
    pub fn at(&self, name: &str) -> io::Result<PathBuf> {
        check_name(name)?;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}/{name}",
            self.file.as_raw_fd()
        )))
    }

    /// Opens a subdirectory without following a link.
    pub fn subdir(&self, name: &str) -> io::Result<Dir> {
        let file = open_dir_nofollow(&self.at(name)?)?;
        Ok(Dir {
            file,
            logical: self.logical_at(name),
        })
    }

    /// `lstat` of an entry; `None` if it doesn't exist.
    pub fn lstat(&self, name: &str) -> io::Result<Option<Metadata>> {
        match fs::symlink_metadata(self.at(name)?) {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Opens an entry for reading without following a link and without blocking on a FIFO, and
    /// checks it is a regular file.
    pub fn open_regular(&self, name: &str) -> Result<(File, Metadata), ReadError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
            .open(self.at(name).map_err(ReadError::Io)?)
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => ReadError::Missing,
                _ if e.raw_os_error() == Some(ELOOP) => ReadError::NotRegular,
                _ => ReadError::Io(e),
            })?;
        let meta = file.metadata().map_err(ReadError::Io)?;
        if !meta.file_type().is_file() {
            return Err(ReadError::NotRegular);
        }
        Ok((file, meta))
    }

    /// Reads a regular file of at most `max` bytes. With `single_link`, a file with other hard
    /// links is refused.
    pub fn read_bounded(&self, name: &str, max: u64, single_link: bool) -> Result<Vec<u8>, ReadError> {
        let (file, meta) = self.open_regular(name)?;
        if single_link && meta.nlink() != 1 {
            return Err(ReadError::Linked);
        }
        read_capped(file, max)
    }

    /// Removes an entry of any type (a directory with its contents) without following links.
    /// Returns false if it didn't exist.
    pub fn remove(&self, name: &str) -> io::Result<bool> {
        let Some(meta) = self.lstat(name)? else {
            return Ok(false);
        };
        let path = self.at(name)?;
        let r = if meta.file_type().is_dir() {
            // std's remove_dir_all opens each level with O_NOFOLLOW and unlinks relative to it.
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        match r {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Reads a symlink entry; `None` if missing, an error if it isn't a symlink.
    pub fn read_link(&self, name: &str) -> io::Result<Option<PathBuf>> {
        match fs::read_link(self.at(name)?) {
            Ok(t) => Ok(Some(t)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn mkdir(&self, name: &str, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(mode).create(self.at(name)?)
    }

    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        fs::rename(self.at(from)?, self.at(to)?)
    }

    /// fsync of the directory itself, so renames and creations in it are durable.
    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// The names in this directory (bounded by `max`; more is an error).
    pub fn names(&self, max: usize) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(format!("/proc/self/fd/{}", self.file.as_raw_fd()))? {
            let entry = entry?;
            if out.len() >= max {
                return Err(io::Error::other(format!(
                    "{} has more than {max} entries",
                    self.logical.display()
                )));
            }
            match entry.file_name().into_string() {
                Ok(n) => out.push(n),
                // Not UTF-8: none of ours; skip it.
                Err(_) => continue,
            }
        }
        out.sort();
        Ok(out)
    }

    /// Creates a new file (never an existing one or through a link) for writing.
    pub fn create_new(&self, name: &str, mode: u32) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(O_NOFOLLOW | O_NOCTTY)
            .open(self.at(name)?)
    }

    /// Writes `name` atomically: a new temporary file with exactly `mode` and `owner`, fsync,
    /// rename over `name` (replacing a link, never writing through it), fsync of the directory.
    pub fn write_atomic(
        &self,
        sys: &dyn System,
        name: &str,
        bytes: &[u8],
        mode: u32,
        owner: (u32, u32),
    ) -> io::Result<()> {
        let (tmp, mut file) = self.create_temp(sys, name, mode)?;
        let r = (|| {
            file.write_all(bytes)?;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            sys.chown(&file, &self.logical_at(name), owner.0, owner.1)?;
            file.sync_all()?;
            self.rename(&tmp, name)
        })();
        if r.is_err() {
            let _ = fs::remove_file(self.at(&tmp)?);
            return r;
        }
        self.sync()
    }

    /// Points the symlink `name` at `target` atomically (temporary link, then rename).
    pub fn symlink_atomic(&self, sys: &dyn System, name: &str, target: &Path) -> io::Result<()> {
        let mut last = None;
        for _ in 0..8 {
            let tmp = format!(".{name}.tmp-{:016x}", sys.random_u64()?);
            match std::os::unix::fs::symlink(target, self.at(&tmp)?) {
                Ok(()) => {
                    if let Err(e) = self.rename(&tmp, name) {
                        let _ = fs::remove_file(self.at(&tmp)?);
                        return Err(e);
                    }
                    return self.sync();
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no free temporary name")))
    }

    fn create_temp(&self, sys: &dyn System, name: &str, mode: u32) -> io::Result<(String, File)> {
        let mut last = None;
        for _ in 0..8 {
            let tmp = format!(".{name}.tmp-{:016x}", sys.random_u64()?);
            match self.create_new(&tmp, mode) {
                Ok(f) => return Ok((tmp, f)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no free temporary name")))
    }
}

/// A temporary name [`Dir::write_atomic`] or [`Dir::symlink_atomic`] creates
/// (`.<name>.tmp-<hex>`), starting with `prefix`.
pub fn is_temp_name(name: &str, prefix: &str) -> bool {
    name.starts_with(prefix) && name.starts_with('.') && name.contains(".tmp-")
}

/// Deletes temporary files a run cut short left in `dir` (README §2, Restarts); returns their
/// names. Failures are skipped: they are retried at the next start.
pub fn remove_temp_files(dir: &Dir, prefix: &str) -> Vec<String> {
    let Ok(names) = dir.names(100_000) else {
        return Vec::new();
    };
    names
        .into_iter()
        .filter(|n| is_temp_name(n, prefix) && dir.remove(n).is_ok())
        .collect()
}

/// Rejects names that would leave the directory.
fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid file name {name:?}"),
        ));
    }
    Ok(())
}

/// Reads at most `max` bytes; more is [`ReadError::TooLarge`].
pub fn read_capped(file: File, max: u64) -> Result<Vec<u8>, ReadError> {
    let mut buf = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(ReadError::Io)?;
    if buf.len() as u64 > max {
        return Err(ReadError::TooLarge);
    }
    Ok(buf)
}

/// Copies at most `max` bytes from `src` to `dst`; more is an error. Returns the length.
pub fn copy_capped(src: &mut impl Read, dst: &mut impl Write, max: u64) -> io::Result<u64> {
    let n = io::copy(&mut src.take(max.saturating_add(1)), dst)?;
    if n > max {
        return Err(io::Error::other(format!("larger than {max} bytes")));
    }
    Ok(n)
}

/// True when two readers yield the same bytes.
pub fn same_contents(a: &mut impl Read, b: &mut impl Read) -> io::Result<bool> {
    let mut ba = vec![0u8; 64 * 1024];
    let mut bb = vec![0u8; 64 * 1024];
    loop {
        let na = read_full(a, &mut ba)?;
        let nb = read_full(b, &mut bb)?;
        if na != nb || ba[..na] != bb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Checks a logical path is absolute and normalised: no `.`, `..` or empty components.
pub fn is_normal_absolute(p: &Path) -> bool {
    let s = p.as_os_str().as_encoded_bytes();
    let Some(rest) = s.strip_prefix(b"/") else {
        return false;
    };
    rest.is_empty()
        || rest
            .split(|&b| b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b".." && !c.contains(&0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-written flag values do what they claim on this architecture.
    #[test]
    fn nofollow_constants() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Root::new(tmp.path());
        fs::create_dir(tmp.path().join("d")).unwrap();
        fs::write(tmp.path().join("f"), b"x").unwrap();
        std::os::unix::fs::symlink("f", tmp.path().join("l")).unwrap();
        std::os::unix::fs::symlink("d", tmp.path().join("ld")).unwrap();
        let dir = Dir::open(&root, "/").unwrap();
        // O_NOFOLLOW: a symlink in the last component is refused.
        assert!(matches!(dir.open_regular("l"), Err(ReadError::NotRegular)));
        let e = dir.subdir("ld").unwrap_err();
        assert!(is_link_or_not_dir(&e), "{e}");
        // O_DIRECTORY: a regular file isn't a directory.
        let e = dir.subdir("f").unwrap_err();
        assert!(is_link_or_not_dir(&e), "{e}");
        assert!(dir.subdir("d").is_ok());
        assert_eq!(dir.read_bounded("f", 10, true).unwrap(), b"x");
        assert!(matches!(dir.read_bounded("f", 0, true), Err(ReadError::TooLarge)));
        assert!(matches!(
            dir.read_bounded("missing", 10, true),
            Err(ReadError::Missing)
        ));
        assert!(matches!(
            dir.read_bounded("d", 10, true),
            Err(ReadError::NotRegular)
        ));
        fs::hard_link(tmp.path().join("f"), tmp.path().join("h")).unwrap();
        assert!(matches!(dir.read_bounded("h", 10, true), Err(ReadError::Linked)));
        assert!(dir.read_bounded("h", 10, false).is_ok());
    }

    #[test]
    fn fifo_is_not_opened_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        // std can't make a FIFO; coreutils' mkfifo is everywhere the tests run, so its absence
        // fails rather than skips the test.
        let status = std::process::Command::new("mkfifo")
            .arg(tmp.path().join("p"))
            .status()
            .expect("mkfifo (coreutils) runs");
        assert!(status.success(), "mkfifo failed");
        let dir = Dir::open(&Root::new(tmp.path()), "/").unwrap();
        assert!(matches!(
            dir.read_bounded("p", 10, true),
            Err(ReadError::NotRegular)
        ));
        assert!(dir.remove("p").unwrap());
    }

    #[test]
    fn remove_never_follows() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"x").unwrap();
        fs::create_dir(tmp.path().join("d")).unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("d/link")).unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("top")).unwrap();
        let dir = Dir::open(&Root::new(tmp.path()), "/").unwrap();
        assert!(dir.remove("d").unwrap());
        assert!(dir.remove("top").unwrap());
        assert!(!dir.remove("top").unwrap());
        assert!(outside.path().join("keep").exists());
    }

    #[test]
    fn names_are_checked() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::open(&Root::new(tmp.path()), "/").unwrap();
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            assert!(dir.at(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn normal_paths() {
        for ok in ["/", "/data/picket/var", "/volume1/.picket"] {
            assert!(is_normal_absolute(Path::new(ok)), "{ok}");
        }
        for bad in [
            "",
            "data",
            "/data/",
            "/data//x",
            "/data/./x",
            "/data/../x",
            "/a/..",
        ] {
            assert!(!is_normal_absolute(Path::new(bad)), "{bad}");
        }
    }

    #[test]
    fn contents() {
        assert!(same_contents(&mut &b"abc"[..], &mut &b"abc"[..]).unwrap());
        assert!(!same_contents(&mut &b"abc"[..], &mut &b"abd"[..]).unwrap());
        assert!(!same_contents(&mut &b"abc"[..], &mut &b"abcd"[..]).unwrap());
        let mut out = Vec::new();
        assert!(copy_capped(&mut &b"abcd"[..], &mut out, 3).is_err());
        assert_eq!(copy_capped(&mut &b"abc"[..], &mut Vec::new(), 3).unwrap(), 3);
    }
}
