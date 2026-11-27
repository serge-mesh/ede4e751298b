//! `bin/.lock`, shared by every update and `install` (edge.md §14, Lock): an exclusive `flock`,
//! `root:root` 0600, created if missing, opened with `O_NOFOLLOW | O_CLOEXEC` (std opens every
//! file close-on-exec) so children don't inherit it, held until the process exits. The kernel
//! releases it when the holder exits or dies.

use std::fs::{File, OpenOptions, Permissions, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::time::Duration;

use crate::fsx::{Dir, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK};
use crate::system::System;

pub const LOCK_NAME: &str = ".lock";
/// How long a second update or `install` waits (edge.md §14, edge-unifi.md §2).
pub const LOCK_WAIT: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_millis(500);

/// The held lock; dropping it releases the `flock`.
#[derive(Debug)]
pub struct Lock {
    _file: File,
}

#[derive(Debug)]
pub enum LockError {
    /// Another holder kept it for the whole wait.
    Timeout,
    Io(io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Timeout => write!(
                f,
                "another update or install held bin/.lock for {} s",
                LOCK_WAIT.as_secs()
            ),
            LockError::Io(e) => write!(f, "bin/.lock: {e}"),
        }
    }
}

/// Takes the lock in `bin`, waiting up to `wait`.
pub fn acquire(bin: &Dir, sys: &dyn System, wait: Duration) -> Result<Lock, LockError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
        .open(bin.at(LOCK_NAME).map_err(LockError::Io)?)
        .map_err(LockError::Io)?;
    let meta = file.metadata().map_err(LockError::Io)?;
    if !meta.file_type().is_file() {
        return Err(LockError::Io(io::Error::other("not a regular file")));
    }
    let logical = bin.logical_at(LOCK_NAME);
    if sys.owner(&meta, &logical) != (0, 0) {
        sys.chown(&file, &logical, 0, 0).map_err(LockError::Io)?;
    }
    if meta.mode() & 0o7777 != 0o600 {
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(LockError::Io)?;
    }
    let start = sys.monotonic();
    let mut said = false;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Lock { _file: file }),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) => return Err(LockError::Io(e)),
        }
        if sys.monotonic().saturating_sub(start) >= wait {
            return Err(LockError::Timeout);
        }
        if !said {
            // So whoever started it knows why nothing happens for a while.
            crate::log(&format!(
                "waiting up to {} s for {} (an update or install holds it)",
                wait.as_secs(),
                logical.display()
            ));
            said = true;
        }
        sys.sleep(POLL);
    }
}
