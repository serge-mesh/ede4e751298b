//! A small error type with context, so the updater needs no error-handling crates
//! (build-and-test.md §4, "Updater dependencies").

use std::fmt;

/// An error message, with context prepended as it propagates.
#[derive(Debug)]
pub struct Error(String);

impl Error {
    pub fn msg(m: impl Into<String>) -> Self {
        Error(m.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Adds context to any displayable error.
pub trait Context<T> {
    fn context<C: fmt::Display>(self, c: C) -> Result<T>;
    fn with_context<C: fmt::Display, F: FnOnce() -> C>(self, f: F) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context<C: fmt::Display>(self, c: C) -> Result<T> {
        self.map_err(|e| Error(format!("{c}: {e}")))
    }

    fn with_context<C: fmt::Display, F: FnOnce() -> C>(self, f: F) -> Result<T> {
        self.map_err(|e| Error(format!("{}: {e}", f())))
    }
}

/// Returns early with a formatted [`Error`].
#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => {
        return Err($crate::error::Error::msg(format!($($t)*)))
    };
}
