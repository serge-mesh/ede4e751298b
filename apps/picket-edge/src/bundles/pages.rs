//! Reading page files (bundles.md §4 "Page file", §6 "Cold lookup"; edge.md §10): cold shard
//! bases and verdict-set bases stay on the SSD (or Debian's `data_dir`) and are read one 4 KiB page
//! at a time: open, `pread`, close, in the caller's blocking thread. The edge keeps no file open
//! between reads (edge-unifi.md §1 "Never hold the drive") and has no page cache of its own.
//!
//! Page files are registered by id (their BLAKE3) with their path and owner (a bundle or a
//! lookup provider, for the `cold.page_reads` metric and the `page_file_refetched` event). A
//! read of an unregistered file, a file being fetched again, or a file that isn't there fails:
//! the caller fails open and marks the lookup unchecked (edge.md §9).

use std::collections::HashMap;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use arc_swap::ArcSwap;

use picket_bundle::page::{PAGE_SIZE, PageReader};

use crate::metrics::Metrics;

/// Whose page file it is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Owner {
    Bundle(Arc<str>),
    Provider(Arc<str>),
}

#[derive(Clone, Debug)]
pub struct PageFile {
    pub path: PathBuf,
    pub owner: Owner,
    /// Being deleted and fetched again: reads fail until it is back.
    pub refetching: bool,
}

/// The edge's page reader.
pub struct FilePages {
    files: ArcSwap<HashMap<String, PageFile>>,
    write: std::sync::Mutex<()>,
    metrics: Arc<Metrics>,
}

/// Most page files registered (README §2 Bounded: 256 cold shards per bundle, a few bundles,
/// one per verdict set, and a previous head's during moves).
pub const MAX_FILES: usize = 16_384;

impl FilePages {
    pub fn new(metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            files: ArcSwap::from_pointee(HashMap::new()),
            write: std::sync::Mutex::new(()),
            metrics,
        })
    }

    fn update(&self, f: impl FnOnce(&mut HashMap<String, PageFile>)) {
        let _g = self.write.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = HashMap::clone(&self.files.load());
        f(&mut next);
        self.files.store(Arc::new(next));
    }

    /// Registers page file `id` at `path`.
    pub fn register(&self, id: &str, path: PathBuf, owner: Owner) {
        self.update(|m| {
            if m.len() >= MAX_FILES && !m.contains_key(id) {
                return;
            }
            m.insert(
                id.to_owned(),
                PageFile {
                    path,
                    owner,
                    refetching: false,
                },
            );
        });
    }

    /// Forgets every file not in `keep`.
    pub fn retain(&self, keep: &dyn Fn(&str) -> bool) {
        self.update(|m| m.retain(|k, _| keep(k)));
    }

    /// Forgets every file of `owner`.
    pub fn forget_owner(&self, owner: &Owner) {
        self.update(|m| m.retain(|_, f| f.owner != *owner));
    }

    /// Marks a file as being fetched again (reads fail meanwhile); returns its entry when it was
    /// registered and not already being fetched.
    pub fn begin_refetch(&self, id: &str) -> Option<PageFile> {
        let mut out = None;
        self.update(|m| {
            if let Some(f) = m.get_mut(id)
                && !f.refetching
            {
                f.refetching = true;
                out = Some(f.clone());
            }
        });
        out
    }

    /// Ends a refetch: reads go to the file again.
    pub fn end_refetch(&self, id: &str) {
        self.update(|m| {
            if let Some(f) = m.get_mut(id) {
                f.refetching = false;
            }
        });
    }

    pub fn get(&self, id: &str) -> Option<PageFile> {
        self.files.load().get(id).cloned()
    }
}

impl PageReader for FilePages {
    fn read_page(&self, file: &str, file_page: u64, buf: &mut [u8; PAGE_SIZE]) -> std::io::Result<()> {
        let files = self.files.load();
        let f = files
            .get(file)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "page file not held"))?;
        if f.refetching {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "page file being fetched again",
            ));
        }
        if let Owner::Bundle(b) = &f.owner {
            self.metrics.cold.get(b).page_reads.fetch_add(1, Relaxed);
        }
        let offset = file_page
            .checked_mul(PAGE_SIZE as u64)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "page out of range"))?;
        // Opened for this read and closed after it (edge-unifi.md §1).
        let fh = std::fs::File::open(&f.path)?;
        fh.read_exact_at(buf, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_registered_files_and_counts_per_bundle() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let mut data = vec![0u8; PAGE_SIZE * 2];
        data[PAGE_SIZE] = 7;
        std::fs::write(&p, &data).unwrap();
        let m = Metrics::new();
        let pages = FilePages::new(Arc::clone(&m));
        let mut buf = [0u8; PAGE_SIZE];
        assert!(pages.read_page("f", 1, &mut buf).is_err(), "not registered");
        pages.register("f", p, Owner::Bundle("b".into()));
        pages.read_page("f", 1, &mut buf).unwrap();
        assert_eq!(buf[0], 7);
        assert!(pages.read_page("f", 2, &mut buf).is_err(), "past the end");
        assert_eq!(m.cold.get("b").page_reads.load(Relaxed), 2);
        assert!(pages.begin_refetch("f").is_some());
        assert!(pages.begin_refetch("f").is_none(), "one refetch at a time");
        assert!(pages.read_page("f", 1, &mut buf).is_err(), "refetching");
        pages.end_refetch("f");
        assert!(pages.read_page("f", 1, &mut buf).is_ok());
    }
}
