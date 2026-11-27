//! picket-bundle: the bundle and verdict-set file formats (bundles.md §4–§5, providers.md §4
//! "Verdict cache"), the writer core uses, and the reader and matcher the edge uses
//! (bundles.md §6).
//!
//! Core owns SQLite and the blob store; this crate owns the bytes. The writer builds each file
//! deterministically from sorted inputs (bundles.md §2 "Determinism"); the reader loads files
//! from `Vec<u8>` (no mmap, no `unsafe`), refuses anything malformed without panicking or
//! allocating beyond the file's own size, and matches names and addresses exactly as
//! [`picket_rules::matcher::BundleMatcher`] (the reference semantics) does.
//!
//! Module map:
//! - [`hash`], [`value`], [`checksum`]: key hashing and `hash_seed`, the 64-bit key value
//!   `{flags | rich_idx}`, set checksums.
//! - [`shard_dir`]: extendible-hashing shard directories, splits and merges.
//! - [`filter`], [`domains`], [`page`]: `domains.bf8` / `cold.bf8`, `domains.fst`, the page file
//!   (cold shards and verdict sets).
//! - [`rich`], [`patterns`]: the `rich.json` and `patterns.bin` segments.
//! - [`ips`], [`runs`]: `ips.bin` IP shard bases; folding IP rules into runs.
//! - [`delta`], [`overlay`]: delta files and the in-memory overlays they build.
//! - [`head`]: `head.json`, `manifest.json`, blob verification.
//! - [`writer`]: building bases, segments, deltas and heads for core.
//! - [`compile`]: rules → compiled keys, patterns and runs, mirroring core's compiler, plus a
//!   from-scratch bundle build.
//! - [`reader`], [`matcher`]: loading parts on the edge and the per-bundle lookup.
//! - [`verdict`]: lookup verdict sets.
//!
//! Every multi-byte integer in a binary file is little-endian; nothing depends on the host's
//! endianness or pointer width (build-and-test.md §4 golden files).

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod bytes;
mod charge;
pub mod checksum;
pub mod compile;
pub mod delta;
pub mod domains;
pub mod filter;
pub mod hash;
pub mod head;
pub mod ips;
pub mod matcher;
pub mod overlay;
pub mod page;
pub mod patterns;
pub mod reader;
pub mod rich;
pub mod runs;
pub mod shard_dir;
pub mod value;
pub mod verdict;
pub mod writer;

pub use checksum::SetChecksum;
pub use hash::KeyHash;
pub use head::{Head, Manifest};
pub use matcher::{Bundle, ColdCheck, Decision, Reason};
pub use page::{PAGE_SIZE, PageReader};
pub use value::Value;

/// The format version of every file this crate writes. A format change rebuilds every shard
/// (bundles.md §4 "Shards"); a reader refuses a version it doesn't know.
pub const FORMAT: u32 = 1;
