//! The writer core uses (bundles.md §2, §4, §5): core owns SQLite (`bundle_keys`,
//! `bundle_shards`, `bundle_ip_ranges`, `bundle_ip_shards`, `bundle_versions`, storage.md §3) and
//! the blob store; this module turns rows into blobs.
//!
//! - Hot shard base ([`HotBaseWriter`]): stream a shard's keys sorted by reversed name → the FST
//!   (streaming) and the filter from the shard's hashes (the only part held in RAM) → the set
//!   checksum → `manifest.json`. Base id = BLAKE3 of the manifest.
//! - Cold shard base ([`ColdBaseWriter`]): the same with the page file in place of the FST.
//! - IP shard base ([`ip_base`]) from its runs (`bundle_ip_ranges`). Base id = BLAKE3 of the file.
//! - Deltas ([`key_delta`], [`ip_delta`]) from per-key or per-run changes, with the checksums
//!   computed in O(delta) from the old values core holds in `bundle_keys` / `bundle_ip_ranges`.
//! - Segments ([`segments`]): `patterns.bin` and `rich.json`.
//!
//! Every output is deterministic: identical inputs give byte-identical blobs.

use crate::checksum::SetChecksum;
use crate::delta::{DeltaHeader, KeyOp, RangeOp, write_key_delta, write_range_delta};
use crate::domains::{FstError, FstWriter};
use crate::filter::{self, FilterError};
use crate::hash::KeyHash;
use crate::head::{COLD_BF8, COLD_PAGES, DOMAINS_BF8, DOMAINS_FST, FileRef, Manifest, PartKind};
use crate::ips::{self, IpShardId, IpsError, Run};
use crate::page::{self, PageFileKind, PageWriteError};
use crate::patterns::{self, BuiltPatterns, PatternInput};
use crate::rich::RichBuilder;
use crate::shard_dir::ShardDir;
use crate::value::Value;
use crate::{FORMAT, bytes::object_id};

/// Why a blob can't be built.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error(transparent)]
    Fst(#[from] FstError),
    #[error(transparent)]
    Filter(#[from] FilterError),
    #[error(transparent)]
    Page(#[from] PageWriteError),
    #[error(transparent)]
    Ips(#[from] IpsError),
    #[error("cold values must be plain blocks")]
    NotPlain,
    #[error(transparent)]
    Rich(#[from] crate::rich::RichError),
    #[error(transparent)]
    Patterns(#[from] crate::patterns::PatternsError),
}

/// One content-addressed file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob {
    pub id: String,
    pub bytes: Vec<u8>,
}

impl Blob {
    pub fn new(bytes: Vec<u8>) -> Blob {
        Blob {
            id: object_id(&bytes),
            bytes,
        }
    }

    /// Its size, as heads list it.
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// A hot or cold shard base: its manifest (whose id is the base id) and files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardBase {
    pub manifest: Blob,
    /// The files the manifest lists, by name.
    pub files: Vec<(String, Blob)>,
    pub checksum: SetChecksum,
    pub keys: u64,
}

impl ShardBase {
    /// The base id.
    pub fn id(&self) -> &str {
        &self.manifest.id
    }

    /// The file named `name`.
    pub fn file(&self, name: &str) -> Option<&Blob> {
        self.files.iter().find(|(n, _)| n == name).map(|(_, b)| b)
    }
}

/// The shard of a key in a directory (core's `bundle_keys.shard`).
pub fn shard_of(dir: &ShardDir, hash_seed: u64, key: &[u8]) -> u32 {
    dir.shard_of(KeyHash::of(hash_seed, key))
}

/// Streams a hot shard's sorted keys into its base.
pub struct HotBaseWriter {
    bundle: String,
    shard: u32,
    hash_seed: u64,
    fst: FstWriter,
    hashes: Vec<u64>,
    checksum: SetChecksum,
}

impl HotBaseWriter {
    pub fn new(bundle: &str, shard: u32, hash_seed: u64) -> HotBaseWriter {
        HotBaseWriter {
            bundle: bundle.to_string(),
            shard,
            hash_seed,
            fst: FstWriter::new(),
            hashes: Vec::new(),
            checksum: SetChecksum::ZERO,
        }
    }

    /// Adds the next key (reversed name, strictly increasing).
    pub fn insert(&mut self, key: &[u8], value: Value) -> Result<(), WriteError> {
        self.fst.insert(key, value)?;
        self.hashes.push(KeyHash::of(self.hash_seed, key).low64());
        self.checksum = self.checksum.add_domain(key, value.0);
        Ok(())
    }

    pub fn finish(mut self) -> Result<ShardBase, WriteError> {
        let keys = self.fst.count();
        let fst = Blob::new(self.fst.finish()?);
        let bf8 = Blob::new(filter::build(&mut self.hashes)?);
        let manifest = Manifest {
            format: FORMAT,
            bundle: self.bundle,
            part: PartKind::Hot,
            shard: self.shard,
            keys,
            checksum: self.checksum,
            files: [
                (DOMAINS_FST.to_string(), file_ref(&fst)),
                (DOMAINS_BF8.to_string(), file_ref(&bf8)),
            ]
            .into_iter()
            .collect(),
            pages: None,
        };
        let (mb, _) = manifest.to_blob();
        Ok(ShardBase {
            manifest: Blob::new(mb),
            files: vec![(DOMAINS_FST.to_string(), fst), (DOMAINS_BF8.to_string(), bf8)],
            checksum: self.checksum,
            keys,
        })
    }
}

fn file_ref(b: &Blob) -> FileRef {
    FileRef {
        blake3: b.id.clone(),
        size: b.size(),
    }
}

/// Collects a cold shard's keys into its base (`cold.bf8` + `cold.pages`). Values must be plain
/// blocks (bundles.md §1).
pub struct ColdBaseWriter {
    bundle: String,
    shard: u32,
    hash_seed: u64,
    records: Vec<(u128, [u8; 8])>,
    hashes: Vec<u64>,
    checksum: SetChecksum,
}

impl ColdBaseWriter {
    pub fn new(bundle: &str, shard: u32, hash_seed: u64) -> ColdBaseWriter {
        ColdBaseWriter {
            bundle: bundle.to_string(),
            shard,
            hash_seed,
            records: Vec::new(),
            hashes: Vec::new(),
            checksum: SetChecksum::ZERO,
        }
    }

    /// Adds a key.
    pub fn insert(&mut self, key: &[u8], value: Value) -> Result<(), WriteError> {
        if !value.is_plain_block() {
            return Err(WriteError::NotPlain);
        }
        if !crate::delta::valid_key(key) {
            return Err(WriteError::Fst(FstError::Key));
        }
        let h = KeyHash::of(self.hash_seed, key);
        self.records.push((h.0, value.0.to_le_bytes()));
        self.hashes.push(h.low64());
        self.checksum = self.checksum.add_domain(key, value.0);
        Ok(())
    }

    pub fn finish(mut self) -> Result<ShardBase, WriteError> {
        let keys = self.records.len() as u64;
        let pages = page::write(
            PageFileKind::ColdShard,
            self.checksum.0,
            self.hash_seed,
            u64::from(self.shard),
            &mut self.records,
        )?;
        let page_count = page::PageFileHeader::parse(pages.get(..page::PAGE_SIZE).unwrap_or(&[]))
            .map(|h| h.page_count)
            .unwrap_or(1);
        let pages = Blob::new(pages);
        let bf8 = Blob::new(filter::build(&mut self.hashes)?);
        let manifest = Manifest {
            format: FORMAT,
            bundle: self.bundle,
            part: PartKind::Cold,
            shard: self.shard,
            keys,
            checksum: self.checksum,
            files: [
                (COLD_BF8.to_string(), file_ref(&bf8)),
                (COLD_PAGES.to_string(), file_ref(&pages)),
            ]
            .into_iter()
            .collect(),
            pages: Some(page_count),
        };
        let (mb, _) = manifest.to_blob();
        Ok(ShardBase {
            manifest: Blob::new(mb),
            files: vec![(COLD_BF8.to_string(), bf8), (COLD_PAGES.to_string(), pages)],
            checksum: self.checksum,
            keys,
        })
    }
}

/// An IP shard base: `ips.bin` (its id is the base id) and its checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpBaseBlob {
    pub blob: Blob,
    pub checksum: SetChecksum,
}

/// Builds an IP shard base from its runs (sorted, disjoint, inside the shard).
pub fn ip_base(shard: IpShardId, runs: &[Run]) -> Result<IpBaseBlob, WriteError> {
    let (bytes, checksum) = ips::write(shard, runs)?;
    Ok(IpBaseBlob {
        blob: Blob::new(bytes),
        checksum,
    })
}

/// One key's change: its value before (as `bundle_keys` holds it for this part) and after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyChange {
    pub key: Vec<u8>,
    pub old: Option<Value>,
    pub new: Option<Value>,
}

/// A written delta and the checksums it moves the shard to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaBlob {
    pub blob: Blob,
    pub header: DeltaHeader,
    /// Ops written (an unchanged key writes none).
    pub ops: usize,
}

/// Where a delta applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaTarget<'a> {
    pub bundle: &'a str,
    /// The base id the chain starts from.
    pub base: &'a str,
    pub seq: u64,
    /// The shard's checksum before the delta.
    pub prev: SetChecksum,
    /// RFC 3339.
    pub created_at: &'a str,
}

/// Builds a hot or cold delta from key changes. A cold delta's header carries `mid_checksum`,
/// the checksum after its upserts (bundles.md §5).
pub fn key_delta(t: &DeltaTarget<'_>, part: PartKind, shard: u32, changes: &[KeyChange]) -> DeltaBlob {
    let mut ops = Vec::new();
    let mut mid = t.prev;
    let mut dels: Vec<(&[u8], Value)> = Vec::new();
    for c in changes {
        match (c.old, c.new) {
            (o, Some(n)) if o != Some(n) => {
                if let Some(o) = o {
                    mid = mid.sub_domain(&c.key, o.0);
                }
                mid = mid.add_domain(&c.key, n.0);
                ops.push(KeyOp::Upsert {
                    key: c.key.clone(),
                    value: n,
                });
            }
            (Some(o), None) => {
                dels.push((&c.key, o));
                ops.push(KeyOp::Delete { key: c.key.clone() });
            }
            _ => {}
        }
    }
    let new = dels.iter().fold(mid, |cs, (k, o)| cs.sub_domain(k, o.0));
    let header = DeltaHeader {
        bundle: t.bundle.to_string(),
        shard: (part == PartKind::Hot).then_some(shard),
        cold_shard: (part == PartKind::Cold).then_some(shard),
        ip_shard: None,
        base: t.base.to_string(),
        seq: t.seq,
        prev_checksum: t.prev,
        mid_checksum: (part == PartKind::Cold).then_some(mid),
        new_checksum: new,
        created_at: t.created_at.to_string(),
    };
    let n = ops.len();
    DeltaBlob {
        blob: Blob::new(write_key_delta(&header, &ops)),
        header,
        ops: n,
    }
}

/// Builds an IP delta: `deletes` are runs as they stand (whole runs), `upserts` the runs replacing
/// them ([`crate::runs::diff_runs`]).
pub fn ip_delta(t: &DeltaTarget<'_>, shard: IpShardId, deletes: &[Run], upserts: &[Run]) -> DeltaBlob {
    let v4 = shard.is_v4();
    let mut cs = t.prev;
    let mut ops = Vec::new();
    for r in deletes {
        cs = cs.minus(SetChecksum::ip_entry(v4, r.first, r.last, r.value.0));
        ops.push(RangeOp::Delete {
            first: r.first,
            last: r.last,
        });
    }
    for r in upserts {
        cs = cs.plus(SetChecksum::ip_entry(v4, r.first, r.last, r.value.0));
        ops.push(RangeOp::Upsert {
            first: r.first,
            last: r.last,
            value: r.value,
        });
    }
    let header = DeltaHeader {
        bundle: t.bundle.to_string(),
        shard: None,
        cold_shard: None,
        ip_shard: Some(shard),
        base: t.base.to_string(),
        seq: t.seq,
        prev_checksum: t.prev,
        mid_checksum: None,
        new_checksum: cs,
        created_at: t.created_at.to_string(),
    };
    let n = ops.len();
    DeltaBlob {
        blob: Blob::new(write_range_delta(&header, &ops)),
        header,
        ops: n,
    }
}

/// The two segments of a head.
#[derive(Clone, Debug)]
pub struct Segments {
    pub patterns: Blob,
    pub rich: Blob,
    /// What happened to each pattern input (dropped ones raise `bundle_warning` on core).
    pub fates: Vec<patterns::PatternFate>,
    /// The bytes `patterns.bin`'s automata take on the edge.
    pub patterns_edge_memory: usize,
}

/// Builds `patterns.bin` (keeping what each input's admission keeps; its automata within
/// `budget` on the edge) and `rich.json`.
pub fn segments(inputs: &[PatternInput], budget: usize, rich: &RichBuilder) -> Result<Segments, WriteError> {
    let BuiltPatterns {
        bytes,
        fates,
        edge_memory,
    } = patterns::build(inputs, budget)?;
    Ok(Segments {
        patterns: Blob::new(bytes),
        rich: Blob::new(rich.to_bytes()?),
        fates,
        patterns_edge_memory: edge_memory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_rules::Flags;

    #[test]
    fn deterministic_bases() {
        let build = || {
            let mut w = HotBaseWriter::new("b", 0, 5);
            w.insert(b"com.a", Value(1)).unwrap();
            w.insert(b"com.b", Value(3)).unwrap();
            w.finish().unwrap()
        };
        let a = build();
        assert_eq!(a, build());
        assert_eq!(a.keys, 2);
        let mut c = ColdBaseWriter::new("b", 1, 5);
        c.insert(b"com.c", Value(1)).unwrap();
        assert!(matches!(
            c.insert(b"com.d", Value::flags_only(Flags::A_EXACT)),
            Err(WriteError::NotPlain)
        ));
        let cb = c.finish().unwrap();
        let m = Manifest::from_bytes(&cb.manifest.bytes).unwrap();
        assert_eq!(m.pages, Some(1));
    }

    #[test]
    fn delta_checksums() {
        let prev = SetChecksum::ZERO.add_domain(b"com.a", 1).add_domain(b"com.b", 3);
        let t = DeltaTarget {
            bundle: "b",
            base: "x",
            seq: 1,
            prev,
            created_at: "t",
        };
        let d = key_delta(
            &t,
            PartKind::Cold,
            2,
            &[
                KeyChange {
                    key: b"com.a".to_vec(),
                    old: Some(Value(1)),
                    new: None,
                },
                KeyChange {
                    key: b"com.c".to_vec(),
                    old: None,
                    new: Some(Value(2)),
                },
                KeyChange {
                    key: b"com.b".to_vec(),
                    old: Some(Value(3)),
                    new: Some(Value(3)),
                },
            ],
        );
        assert_eq!(d.ops, 2);
        assert_eq!(d.header.mid_checksum, Some(prev.add_domain(b"com.c", 2)));
        assert_eq!(
            d.header.new_checksum,
            SetChecksum::ZERO.add_domain(b"com.b", 3).add_domain(b"com.c", 2)
        );
        assert_eq!(d.header.cold_shard, Some(2));
    }
}
