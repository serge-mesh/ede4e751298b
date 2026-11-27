//! The page file (bundles.md §4 "Page file"): records looked up by a 128-bit hash, read one 4 KiB
//! page at a time with no index in RAM. Cold shard bases (`cold.pages`) and verdict-set bases
//! (providers.md §4) use it.
//!
//! Layout, every integer little-endian:
//! - **Header page** (page 0): magic `PKTPAGE\0`, format `u32`, file kind `u32`, record page count
//!   `u32`, reserved `u32`, record count `u64`, identity `u128` (the set checksum at the base),
//!   `hash_seed` `u64`, a kind field `u64` (cold: the shard number; verdict set: the cache
//!   generation), zeros, and at bytes 4088..4096 `xxh3_64` of the first 4088 bytes.
//! - **Record page** `p` (file page `p + 1`): a record count `u16`, then the records sorted by
//!   hash, each the hash (16 bytes), a `u16` value length and the value; zero padding; and at
//!   4088..4096 the page checksum, `xxh3_64` of the first 4088 bytes seeded with the identity's
//!   low 64 bits and the page number, so a page from another file or place fails it.
//! - **Placement:** a record lives on page `(low64(hash) × page count) >> 64`; the writer picks
//!   the page count so that no page overflows.
//!
//! Reading checks the page's checksum, then searches it. A page failing its checksum is a failed
//! read ([`PageError::Checksum`]): the edge deletes the file, fetches it again and logs
//! `page_file_refetched` (api.md §5).

use xxhash_rust::xxh3::{xxh3_64, xxh3_64_with_seed};

use crate::FORMAT;
use crate::bytes::ByteReader;

/// Page size.
pub const PAGE_SIZE: usize = 4096;
/// The file magic.
pub const MAGIC: [u8; 8] = *b"PKTPAGE\0";
/// Bytes of a record page usable for records (count and checksum excluded).
pub const PAGE_PAYLOAD: usize = PAGE_SIZE - 2 - 8;
/// Bytes a record takes beyond its value.
pub const RECORD_OVERHEAD: usize = 16 + 2;
/// The longest value a record may carry.
pub const MAX_VALUE_LEN: usize = 1024;
/// Most record pages a file may have (2³⁰ pages = 4 TiB: far beyond any shard).
pub const MAX_PAGES: u32 = 1 << 30;
const CHECKSUM_AT: usize = PAGE_SIZE - 8;

/// What a page file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PageFileKind {
    /// A cold shard base (`cold.pages`): values are the key's `u64` little-endian.
    ColdShard,
    /// A verdict-set base: values are encoded verdicts ([`crate::verdict`]).
    VerdictSet,
}

impl PageFileKind {
    fn code(self) -> u32 {
        match self {
            PageFileKind::ColdShard => 1,
            PageFileKind::VerdictSet => 2,
        }
    }

    fn from_code(c: u32) -> Option<PageFileKind> {
        match c {
            1 => Some(PageFileKind::ColdShard),
            2 => Some(PageFileKind::VerdictSet),
            _ => None,
        }
    }
}

/// Why a page file or page is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PageError {
    #[error("not a page file")]
    Magic,
    #[error("page file format {0} is not supported")]
    Format(u32),
    #[error("page file kind doesn't match")]
    Kind,
    #[error("page {0} fails its checksum")]
    Checksum(u64),
    #[error("page {0} is malformed")]
    Malformed(u64),
    #[error("page read failed: {0}")]
    Io(String),
    #[error("page file length doesn't match its header")]
    Length,
}

impl PageError {
    /// True when the file must be deleted and fetched again (a checksum failure or malformed
    /// content), as opposed to a read error.
    pub fn needs_refetch(&self) -> bool {
        !matches!(self, PageError::Io(_))
    }
}

/// The header page's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFileHeader {
    pub kind: PageFileKind,
    /// Record pages (the file has one more, the header).
    pub page_count: u32,
    pub record_count: u64,
    /// The set checksum at the base; seeds every page checksum.
    pub identity: u128,
    pub hash_seed: u64,
    /// Cold: the shard number. Verdict set: the cache generation.
    pub field: u64,
}

impl PageFileHeader {
    /// Encodes the header page.
    pub fn to_page(&self) -> [u8; PAGE_SIZE] {
        let mut p = [0u8; PAGE_SIZE];
        let mut w = PageWriter::new(&mut p);
        w.put(&MAGIC);
        w.put(&FORMAT.to_le_bytes());
        w.put(&self.kind.code().to_le_bytes());
        w.put(&self.page_count.to_le_bytes());
        w.put(&0u32.to_le_bytes());
        w.put(&self.record_count.to_le_bytes());
        w.put(&self.identity.to_le_bytes());
        w.put(&self.hash_seed.to_le_bytes());
        w.put(&self.field.to_le_bytes());
        seal_header_page(&mut p);
        p
    }

    /// Parses and checks the header page.
    pub fn parse(page: &[u8]) -> Result<PageFileHeader, PageError> {
        if page.len() != PAGE_SIZE {
            return Err(PageError::Magic);
        }
        let (body, sum) = page.split_at(CHECKSUM_AT);
        let mut r = ByteReader::new(body);
        let magic: [u8; 8] = r.array().map_err(|_| PageError::Magic)?;
        if magic != MAGIC {
            return Err(PageError::Magic);
        }
        let mut sb = [0u8; 8];
        sb.copy_from_slice(sum);
        if xxh3_64(body) != u64::from_le_bytes(sb) {
            return Err(PageError::Checksum(0));
        }
        let format = r.u32().map_err(|_| PageError::Malformed(0))?;
        if format != FORMAT {
            return Err(PageError::Format(format));
        }
        let kind =
            PageFileKind::from_code(r.u32().map_err(|_| PageError::Malformed(0))?).ok_or(PageError::Kind)?;
        let page_count = r.u32().map_err(|_| PageError::Malformed(0))?;
        let _ = r.u32().map_err(|_| PageError::Malformed(0))?;
        let record_count = r.u64().map_err(|_| PageError::Malformed(0))?;
        let identity = r.u128().map_err(|_| PageError::Malformed(0))?;
        let hash_seed = r.u64().map_err(|_| PageError::Malformed(0))?;
        let field = r.u64().map_err(|_| PageError::Malformed(0))?;
        if page_count == 0 || page_count > MAX_PAGES {
            return Err(PageError::Malformed(0));
        }
        // A record takes at least RECORD_OVERHEAD bytes.
        let max_records = u64::from(page_count).saturating_mul((PAGE_PAYLOAD / RECORD_OVERHEAD) as u64);
        if record_count > max_records {
            return Err(PageError::Malformed(0));
        }
        Ok(PageFileHeader {
            kind,
            page_count,
            record_count,
            identity,
            hash_seed,
            field,
        })
    }

    /// The file's length in bytes.
    pub fn file_len(&self) -> u64 {
        u64::from(self.page_count)
            .saturating_add(1)
            .saturating_mul(PAGE_SIZE as u64)
    }

    /// The record page a hash lives on.
    pub fn page_for(&self, hash: u128) -> u32 {
        page_for(hash, self.page_count)
    }
}

/// A record's page: `(low64(hash) × page count) >> 64`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "(low64 x page_count) >> 64 is below page_count, a u32"
)]
pub fn page_for(hash: u128, page_count: u32) -> u32 {
    let low = u128::from(crate::hash::halves(hash).0);
    (low.wrapping_mul(u128::from(page_count)) >> 64) as u32
}

fn page_seed(identity: u128, page: u32) -> u64 {
    crate::hash::halves(identity).0
        ^ u64::from(page)
            .wrapping_add(1)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Writes record page `page`'s checksum into its last 8 bytes (the writer's last step; tests and
/// fuzzing use it to build pages that reach the record parser).
pub fn seal_record_page(data: &mut [u8; PAGE_SIZE], page: u32, identity: u128) {
    let sum = xxh3_64_with_seed(data.get(..CHECKSUM_AT).unwrap_or(&[]), page_seed(identity, page));
    if let Some(s) = data.get_mut(CHECKSUM_AT..) {
        s.copy_from_slice(&sum.to_le_bytes());
    }
}

/// Writes the header page's checksum into its last 8 bytes.
pub fn seal_header_page(data: &mut [u8; PAGE_SIZE]) {
    let sum = xxh3_64(data.get(..CHECKSUM_AT).unwrap_or(&[]));
    if let Some(s) = data.get_mut(CHECKSUM_AT..) {
        s.copy_from_slice(&sum.to_le_bytes());
    }
}

/// Checks record page `page` (0-based record page; file page `page + 1`) and returns its records.
pub fn check_page(data: &[u8], page: u32, identity: u128) -> Result<PageRecords<'_>, PageError> {
    let file_page = u64::from(page).saturating_add(1);
    if data.len() != PAGE_SIZE {
        return Err(PageError::Malformed(file_page));
    }
    let (body, sum) = data.split_at(CHECKSUM_AT);
    let mut sb = [0u8; 8];
    sb.copy_from_slice(sum);
    if xxh3_64_with_seed(body, page_seed(identity, page)) != u64::from_le_bytes(sb) {
        return Err(PageError::Checksum(file_page));
    }
    let mut r = ByteReader::new(body);
    let count = r.u16().map_err(|_| PageError::Malformed(file_page))?;
    Ok(PageRecords {
        r,
        left: count,
        last: None,
        file_page,
    })
}

/// The records of a checked page, in order. Yields an error (once) for a malformed record or
/// records out of order.
pub struct PageRecords<'a> {
    r: ByteReader<'a>,
    left: u16,
    last: Option<u128>,
    file_page: u64,
}

impl<'a> Iterator for PageRecords<'a> {
    type Item = Result<(u128, &'a [u8]), PageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left = self.left.saturating_sub(1);
        let err = PageError::Malformed(self.file_page);
        let rec = (|| {
            let hash = self.r.u128().ok()?;
            let len = usize::from(self.r.u16().ok()?);
            if len > MAX_VALUE_LEN {
                return None;
            }
            let value = self.r.bytes(len).ok()?;
            Some((hash, value))
        })();
        match rec {
            Some((hash, value)) if self.last.is_none_or(|l| l < hash) => {
                self.last = Some(hash);
                Some(Ok((hash, value)))
            }
            _ => {
                self.left = 0;
                Some(Err(err))
            }
        }
    }
}

/// Checks page `page` and finds `hash` in it.
pub fn find_in_page(data: &[u8], page: u32, identity: u128, hash: u128) -> Result<Option<&[u8]>, PageError> {
    for rec in check_page(data, page, identity)? {
        let (h, v) = rec?;
        if h == hash {
            return Ok(Some(v));
        }
        if h > hash {
            break;
        }
    }
    Ok(None)
}

/// How the edge reads pages: open the file, `pread` one page, close, in a blocking thread
/// (bundles.md §6). `file` is the page file's BLAKE3 id; `file_page` counts from the header
/// (record page `p` is file page `p + 1`).
pub trait PageReader: Send + Sync {
    fn read_page(&self, file: &str, file_page: u64, buf: &mut [u8; PAGE_SIZE]) -> std::io::Result<()>;
}

/// A page file held in memory (core's checks, tests, and a reader over local bytes).
#[derive(Clone, Debug, Default)]
pub struct MemPages {
    pub files: std::collections::HashMap<String, Vec<u8>>,
}

impl PageReader for MemPages {
    fn read_page(&self, file: &str, file_page: u64, buf: &mut [u8; PAGE_SIZE]) -> std::io::Result<()> {
        let data = self
            .files
            .get(file)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such page file"))?;
        let start = usize::try_from(file_page)
            .ok()
            .and_then(|p| p.checked_mul(PAGE_SIZE))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "page out of range"))?;
        let page = data
            .get(start..start.saturating_add(PAGE_SIZE))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "page out of range"))?;
        buf.copy_from_slice(page);
        Ok(())
    }
}

/// Reads record page `page` of `file` and finds `hash` in it.
pub fn read_record(
    reader: &dyn PageReader,
    file: &str,
    header_identity: u128,
    page_count: u32,
    hash: u128,
    buf: &mut [u8; PAGE_SIZE],
) -> Result<Option<Vec<u8>>, PageError> {
    let page = page_for(hash, page_count);
    reader
        .read_page(file, u64::from(page).saturating_add(1), buf)
        .map_err(|e| PageError::Io(e.to_string()))?;
    Ok(find_in_page(buf, page, header_identity, hash)?.map(<[u8]>::to_vec))
}

struct PageWriter<'a> {
    p: &'a mut [u8; PAGE_SIZE],
    at: usize,
}

impl<'a> PageWriter<'a> {
    fn new(p: &'a mut [u8; PAGE_SIZE]) -> Self {
        Self { p, at: 0 }
    }

    fn put(&mut self, b: &[u8]) {
        let end = self.at.saturating_add(b.len());
        if let Some(dst) = self.p.get_mut(self.at..end) {
            dst.copy_from_slice(b);
            self.at = end;
        }
    }
}

/// Why a page file can't be written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PageWriteError {
    #[error("a value is longer than {MAX_VALUE_LEN} bytes")]
    ValueTooLong,
    #[error("two records share a hash")]
    DuplicateHash,
    #[error("records can't be placed without overflowing a page (hashes collide on their low 64 bits)")]
    Overflow,
}

/// Writes a page file of `records` (any order). Deterministic: the page count and layout depend
/// only on the records.
pub fn write<V: AsRef<[u8]>>(
    kind: PageFileKind,
    identity: u128,
    hash_seed: u64,
    field: u64,
    records: &mut [(u128, V)],
) -> Result<Vec<u8>, PageWriteError> {
    if records.iter().any(|(_, v)| v.as_ref().len() > MAX_VALUE_LEN) {
        return Err(PageWriteError::ValueTooLong);
    }
    records.sort_unstable_by_key(|(h, _)| *h);
    if records
        .windows(2)
        .any(|w| w.first().map(|a| a.0) == w.get(1).map(|b| b.0))
    {
        return Err(PageWriteError::DuplicateHash);
    }
    let size = |v: &V| RECORD_OVERHEAD.saturating_add(v.as_ref().len());
    let total: usize = records
        .iter()
        .map(|(_, v)| size(v))
        .fold(0usize, usize::saturating_add);
    // Start at about 80 % fill and grow until no page overflows.
    let target = PAGE_PAYLOAD.saturating_mul(4) / 5;
    let mut pages = u32::try_from(total.div_ceil(target).max(1)).map_err(|_| PageWriteError::Overflow)?;
    let mut fill: Vec<usize>;
    let mut tries = 0u32;
    loop {
        fill = vec![0usize; usize::try_from(pages).map_err(|_| PageWriteError::Overflow)?];
        let mut ok = true;
        for (h, v) in records.iter() {
            let p = usize::try_from(page_for(*h, pages)).map_err(|_| PageWriteError::Overflow)?;
            if let Some(f) = fill.get_mut(p) {
                *f = f.saturating_add(size(v));
                if *f > PAGE_PAYLOAD {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            break;
        }
        tries = tries.saturating_add(1);
        if tries > 64 {
            return Err(PageWriteError::Overflow);
        }
        pages = pages
            .checked_add(pages / 8)
            .and_then(|p| p.checked_add(1))
            .filter(|&p| p <= MAX_PAGES)
            .ok_or(PageWriteError::Overflow)?;
    }
    let header = PageFileHeader {
        kind,
        page_count: pages,
        record_count: records.len() as u64,
        identity,
        hash_seed,
        field,
    };
    let len = usize::try_from(header.file_len()).map_err(|_| PageWriteError::Overflow)?;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&header.to_page());
    // Records sorted by hash; within a page sorted by hash too (placement is monotone in the low
    // 64 bits only, so group by page first).
    let mut order: Vec<(u32, usize)> = records
        .iter()
        .enumerate()
        .map(|(i, (h, _))| (page_for(*h, pages), i))
        .collect();
    order.sort_unstable_by_key(|&(p, i)| (p, records.get(i).map_or(0, |r| r.0)));
    let mut it = order.into_iter().peekable();
    for page in 0..pages {
        let mut p = [0u8; PAGE_SIZE];
        let mut w = PageWriter::new(&mut p);
        w.put(&[0, 0]);
        let mut count = 0u16;
        while let Some(&(pp, i)) = it.peek() {
            if pp != page {
                break;
            }
            it.next();
            if let Some((h, v)) = records.get(i) {
                let v = v.as_ref();
                w.put(&h.to_le_bytes());
                w.put(&u16::try_from(v.len()).unwrap_or(0).to_le_bytes());
                w.put(v);
                count = count.saturating_add(1);
            }
        }
        if let Some(c) = p.get_mut(..2) {
            c.copy_from_slice(&count.to_le_bytes());
        }
        seal_record_page(&mut p, page, identity);
        out.extend_from_slice(&p);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(n: u64) -> Vec<(u128, Vec<u8>)> {
        (0..n)
            .map(|i| {
                let h = crate::hash::KeyHash::of(7, &i.to_le_bytes()).0;
                (h, i.to_le_bytes().to_vec())
            })
            .collect()
    }

    #[test]
    fn write_and_find() {
        for n in [0u64, 1, 10, 5000] {
            let mut recs = records(n);
            let file = write(PageFileKind::ColdShard, 42, 7, 3, &mut recs).unwrap();
            let header = PageFileHeader::parse(&file[..PAGE_SIZE]).unwrap();
            assert_eq!(header.record_count, n);
            assert_eq!(header.file_len() as usize, file.len());
            let mem = MemPages {
                files: [("f".to_string(), file.clone())].into_iter().collect(),
            };
            let mut buf = [0u8; PAGE_SIZE];
            for (h, v) in &recs {
                let got = read_record(&mem, "f", 42, header.page_count, *h, &mut buf).unwrap();
                assert_eq!(got.as_deref(), Some(v.as_slice()));
            }
            assert_eq!(
                read_record(&mem, "f", 42, header.page_count, 12345, &mut buf).unwrap(),
                None
            );
            // Every page within its payload.
            for p in 0..header.page_count {
                let start = (p as usize + 1) * PAGE_SIZE;
                let page = &file[start..start + PAGE_SIZE];
                assert!(check_page(page, p, 42).unwrap().all(|r| r.is_ok()));
            }
        }
    }

    #[test]
    fn corrupted_pages_fail() {
        let mut recs = records(200);
        let mut file = write(PageFileKind::VerdictSet, 9, 1, 0, &mut recs).unwrap();
        let header = PageFileHeader::parse(&file[..PAGE_SIZE]).unwrap();
        let (h, _) = recs[0];
        let p = header.page_for(h);
        let at = (p as usize + 1) * PAGE_SIZE + 5;
        file[at] ^= 1;
        let page = &file[(p as usize + 1) * PAGE_SIZE..(p as usize + 2) * PAGE_SIZE];
        let e = find_in_page(page, p, 9, h).unwrap_err();
        assert_eq!(e, PageError::Checksum(u64::from(p) + 1));
        assert!(e.needs_refetch());
        // The right page under another identity (another file) fails too.
        let mut recs2 = records(200);
        let file2 = write(PageFileKind::VerdictSet, 9, 1, 0, &mut recs2).unwrap();
        let page2 = &file2[(p as usize + 1) * PAGE_SIZE..(p as usize + 2) * PAGE_SIZE];
        assert!(find_in_page(page2, p, 10, h).is_err());
        // A corrupted header.
        let mut hdr = file2[..PAGE_SIZE].to_vec();
        hdr[20] ^= 1;
        assert_eq!(PageFileHeader::parse(&hdr), Err(PageError::Checksum(0)));
    }

    #[test]
    fn overflow_is_avoided_or_reported() {
        // Large values push the writer to more pages; nothing overflows.
        let mut recs: Vec<(u128, Vec<u8>)> = records(300)
            .into_iter()
            .map(|(h, _)| (h, vec![7u8; 900]))
            .collect();
        let file = write(PageFileKind::VerdictSet, 1, 1, 0, &mut recs).unwrap();
        let header = PageFileHeader::parse(&file[..PAGE_SIZE]).unwrap();
        assert!(header.page_count as usize * PAGE_PAYLOAD >= 300 * 918);
        // Records whose low 64 bits collide can't be spread: reported, never a panic.
        let mut same: Vec<(u128, Vec<u8>)> = (0..10u128).map(|i| ((i << 64) | 5, vec![0u8; 900])).collect();
        assert_eq!(
            write(PageFileKind::VerdictSet, 1, 1, 0, &mut same),
            Err(PageWriteError::Overflow)
        );
        let mut dup = vec![(1u128, vec![1u8]), (1u128, vec![2u8])];
        assert_eq!(
            write(PageFileKind::VerdictSet, 1, 1, 0, &mut dup),
            Err(PageWriteError::DuplicateHash)
        );
    }
}
