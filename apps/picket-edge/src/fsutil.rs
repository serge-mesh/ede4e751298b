//! File helpers shared by every module that writes state (edge.md §2: "writes are tmp → fsync →
//! rename"; README §2 Restarts: temporary files are deleted when their work ends, and at start).
//!
//! Directories that carry trust (the identity and the config directory) are opened with
//! `O_NOFOLLOW | O_DIRECTORY`, and every file inside them is opened relative to that directory
//! descriptor with `O_NOFOLLOW`, so a root `setup` or `key` never follows a planted symlink and
//! never chowns through one: ownership changes go through `fchown` on a descriptor we opened.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Gid, Mode, OFlags, Uid};

/// Marker every temporary file name carries: `.<name>.tmp.<random>`.
pub const TMP_MARK: &str = ".tmp.";

/// Ownership to give a file we write (applied with `fchown` on our own descriptor).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Owner {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl Owner {
    pub fn is_none(&self) -> bool {
        self.uid.is_none() && self.gid.is_none()
    }
}

/// Opens an existing directory without following a symlink in its last component. A symlink
/// gives `ELOOP` (reported as "is a symlink"); a non-directory gives `ENOTDIR`.
pub fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| annotate(e.into(), path))
}

/// Opens (creating it with `mode` if missing) a directory without following symlinks in its last
/// component. A newly created directory gets `owner` through `fchown` on its descriptor.
pub fn ensure_dir_nofollow(path: &Path, mode: u32, owner: Owner) -> io::Result<OwnedFd> {
    match rustix::fs::mkdir(path, Mode::from_raw_mode(mode)) {
        Ok(()) => {
            let fd = open_dir_nofollow(path)?;
            // mkdir applies the umask; set the mode we asked for.
            rustix::fs::fchmod(&fd, Mode::from_raw_mode(mode))?;
            chown_fd(&fd, owner)?;
            Ok(fd)
        }
        Err(rustix::io::Errno::EXIST) => open_dir_nofollow(path),
        Err(e) => Err(annotate(e.into(), path)),
    }
}

/// Creates `path` and its missing parents (like `mkdir -p`) with `mode` for the directories it
/// creates. Existing directories are left as they are.
pub fn create_dir_all_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|e| annotate(e, path))
}

/// Changes the owner of an open descriptor (no-op for an empty `Owner`).
pub fn chown_fd(fd: &impl AsFd, owner: Owner) -> io::Result<()> {
    if owner.is_none() {
        return Ok(());
    }
    rustix::fs::fchown(fd, owner.uid.map(Uid::from_raw), owner.gid.map(Gid::from_raw))?;
    Ok(())
}

/// Options for [`atomic_write_at`].
#[derive(Clone, Copy, Debug)]
pub struct WriteOpts {
    pub mode: u32,
    pub owner: Owner,
}

impl WriteOpts {
    pub fn mode(mode: u32) -> Self {
        Self {
            mode,
            owner: Owner::default(),
        }
    }
}

/// Writes `name` inside the directory `dir` atomically: a temporary file created with
/// `O_EXCL | O_NOFOLLOW`, its mode and owner set through its descriptor, written, fsynced, renamed
/// over `name`, then the directory fsynced. The temporary file is removed on any failure.
pub fn atomic_write_at(dir: &OwnedFd, name: &str, bytes: &[u8], opts: WriteOpts) -> io::Result<()> {
    check_name(name)?;
    let tmp = tmp_name(name);
    let fd = rustix::fs::openat(
        dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(opts.mode),
    )?;
    let result = (|| -> io::Result<()> {
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(opts.mode))?;
        chown_fd(&fd, opts.owner)?;
        let mut f = File::from(fd);
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        rustix::fs::renameat(dir, tmp.as_str(), dir, name)?;
        rustix::fs::fsync(dir)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(dir, tmp.as_str(), AtFlags::empty());
    }
    result
}

/// [`atomic_write_at`] for a path whose parent directory may be followed normally (state under
/// `data_dir`, which the edge owns).
pub fn atomic_write(path: &Path, bytes: &[u8], opts: WriteOpts) -> io::Result<()> {
    let (dir, name) = split(path)?;
    let dirfd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| annotate(e.into(), dir))?;
    atomic_write_at(&dirfd, name, bytes, opts).map_err(|e| annotate(e, path))
}

/// Reads `name` inside `dir` with `O_NOFOLLOW`, refusing anything over `max` bytes or that isn't
/// a regular file. Returns the bytes and the file's metadata.
pub fn read_at_bounded(dir: &OwnedFd, name: &str, max: u64) -> io::Result<(Vec<u8>, std::fs::Metadata)> {
    check_name(name)?;
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    read_fd_bounded(File::from(fd), max)
}

/// Reads a file by path (following symlinks), bounded to `max` bytes.
pub fn read_bounded(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let f = File::open(path).map_err(|e| annotate(e, path))?;
    read_fd_bounded(f, max)
        .map(|(b, _)| b)
        .map_err(|e| annotate(e, path))
}

/// Reads a file by path without following a symlink in its last component, bounded.
pub fn read_nofollow_bounded(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| annotate(e.into(), path))?;
    read_fd_bounded(File::from(fd), max)
        .map(|(b, _)| b)
        .map_err(|e| annotate(e, path))
}

fn read_fd_bounded(f: File, max: u64) -> io::Result<(Vec<u8>, std::fs::Metadata)> {
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    if meta.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file is {} bytes, over the {max}-byte limit", meta.len()),
        ));
    }
    let mut buf = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    // Bound the read itself too: the file may grow between fstat and read.
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file is over the {max}-byte limit"),
        ));
    }
    Ok((buf, meta))
}

/// Deletes the temporary files (`.<name>.tmp.<random>`) a previous run left in `dir`. Missing
/// directories are fine. Returns how many were removed.
pub fn sweep_temp_files(dir: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0;
    for entry in rd.flatten().take(100_000) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if is_tmp_name(name) {
            let p = entry.path();
            let removed = match entry.file_type() {
                Ok(t) if t.is_dir() => std::fs::remove_dir_all(&p),
                _ => std::fs::remove_file(&p),
            };
            if removed.is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// Deletes leftover temporary files in `root` and the directories under it, at most
/// `max_depth` levels down. Symlinks are never followed, and the walk is bounded. Returns how
/// many were removed.
pub fn sweep_temp_files_tree(root: &Path, max_depth: usize) -> usize {
    const MAX_DIRS: usize = 100_000;
    let mut removed = 0;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut dirs = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        dirs += 1;
        if dirs > MAX_DIRS {
            break;
        }
        removed += sweep_temp_files(&dir);
        if depth >= max_depth {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten().take(1_000_000) {
            // `file_type` doesn't follow symlinks: a link to a directory is left alone.
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    removed
}

/// True for names [`tmp_name`] produces.
pub fn is_tmp_name(name: &str) -> bool {
    name.starts_with('.') && name.contains(TMP_MARK)
}

/// A fresh temporary name for `name`.
pub fn tmp_name(name: &str) -> String {
    format!(".{name}{TMP_MARK}{:016x}", rand::random::<u64>())
}

/// fsyncs a directory (after creating, renaming or deleting entries in it).
pub fn fsync_dir(path: &Path) -> io::Result<()> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| annotate(e.into(), path))?;
    rustix::fs::fsync(&fd)?;
    Ok(())
}

/// Allocated size of a file's data in bytes (`st_blocks × 512`), what deleting it frees.
pub fn allocated_bytes(meta: &std::fs::Metadata) -> u64 {
    meta.blocks().saturating_mul(512)
}

/// The change from `before` to `after` bytes, saturating at the ends of `i64` (disk usage
/// counters).
pub fn byte_delta(after: u64, before: u64) -> i64 {
    if after >= before {
        i64::try_from(after - before).unwrap_or(i64::MAX)
    } else {
        i64::try_from(before - after).map_or(i64::MIN, |d| -d)
    }
}

/// `O_NOFOLLOW` for `OpenOptionsExt::custom_flags` (an `i32` of flag bits).
pub fn o_nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits().cast_signed()
}

/// Splits a path into (parent directory, file name).
pub fn split(path: &Path) -> io::Result<(&Path, &str)> {
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad file path {}", path.display()),
        )
    })?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    Ok((dir, name))
}

fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad file name {name:?}"),
        ));
    }
    Ok(())
}

/// Adds the path to an error's message, turning `ELOOP` from `O_NOFOLLOW` into a clear refusal.
pub fn annotate(e: io::Error, path: &Path) -> io::Error {
    // O_NOFOLLOW gives ELOOP on a symlink, or ENOTDIR together with O_DIRECTORY.
    let loop_or_notdir = [rustix::io::Errno::LOOP, rustix::io::Errno::NOTDIR]
        .iter()
        .any(|c| e.raw_os_error() == Some(c.raw_os_error()));
    if loop_or_notdir && std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return io::Error::new(
            e.kind(),
            format!("{} is a symlink; refusing to follow it", path.display()),
        );
    }
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

/// Joins `rel` onto `base` unless `rel` is absolute.
pub fn resolve(base: &Path, rel: &Path) -> PathBuf {
    if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        base.join(rel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn atomic_write_sets_mode_and_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.json");
        atomic_write(&p, b"{}", WriteOpts::mode(0o600)).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        atomic_write(&p, b"{\"a\":1}", WriteOpts::mode(0o640)).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"{\"a\":1}");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640);
        let leftovers: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .flatten()
            .filter(|e| is_tmp_name(e.file_name().to_str().unwrap()))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn refuses_symlinked_directory() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = d.path().join("identity");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = open_dir_nofollow(&link).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        let e = ensure_dir_nofollow(&link, 0o700, Owner::default()).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
    }

    #[test]
    fn read_at_refuses_symlinked_file_and_oversize() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("target"), b"secret").unwrap();
        std::os::unix::fs::symlink(d.path().join("target"), d.path().join("key.pem")).unwrap();
        let dir = open_dir_nofollow(d.path()).unwrap();
        assert!(read_at_bounded(&dir, "key.pem", 100).is_err());
        assert_eq!(read_at_bounded(&dir, "target", 100).unwrap().0, b"secret");
        assert!(read_at_bounded(&dir, "target", 3).is_err());
        assert!(read_at_bounded(&dir, "../x", 3).is_err());
    }

    #[test]
    fn sweeps_temp_files_in_a_bounded_tree_without_following_links() {
        let d = tempfile::tempdir().unwrap();
        let deep = d.path().join("bundles/block-common/shards/1");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join(tmp_name("base")), b"x").unwrap();
        std::fs::write(deep.join("base"), b"x").unwrap();
        std::fs::write(d.path().join(tmp_name("state.json")), b"x").unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join(tmp_name("theirs")), b"x").unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), d.path().join("link")).unwrap();
        assert_eq!(sweep_temp_files_tree(d.path(), 2), 1, "too deep for depth 2");
        assert_eq!(sweep_temp_files_tree(d.path(), 6), 1);
        assert!(deep.join("base").exists());
        assert_eq!(
            std::fs::read_dir(elsewhere.path()).unwrap().count(),
            1,
            "a symlinked directory isn't walked"
        );
    }

    #[test]
    fn sweeps_temp_files() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(tmp_name("state.json")), b"x").unwrap();
        std::fs::write(d.path().join("state.json"), b"x").unwrap();
        assert_eq!(sweep_temp_files(d.path()), 1);
        assert!(d.path().join("state.json").exists());
        assert_eq!(sweep_temp_files(&d.path().join("missing")), 0);
    }
}
