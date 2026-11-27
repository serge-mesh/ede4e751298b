//! Byte-level helpers: a bounds-checked writer over a caller-provided buffer (every reply, query
//! and cache hit is written with it, edge.md §4, §8) and the walk over cache copies hickory
//! encoded (edge.md §8: "found once at insert by walking each encoded copy").
//!
//! Nothing here decodes untrusted input: the walk only reads copies this crate had hickory encode.

use thiserror::Error;

/// Why a reply, query or cache hit couldn't be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum WriteError {
    /// The output buffer is smaller than the message. Size it for the transport's limit
    /// ([`crate::reply::Transport`]); a reply over the client's limit is cut with TC instead.
    #[error("output buffer too small")]
    BufferTooSmall,
    /// A name, label or character string is over its wire limit.
    #[error("value too long for the wire format")]
    TooLong,
    /// The client's question isn't the length of the cached answer's question, so the copy's
    /// compression pointers wouldn't line up (edge.md §8). The cache key makes this impossible
    /// unless the caller mixes entries.
    #[error("question length differs from the cached answer's")]
    QuestionLength,
    /// hickory failed to encode a record (only on paths that re-encode, such as CNAME rewrites).
    #[error("encoding failed")]
    Encode,
    /// Core's rebuild of a logged reply set TC differently from the record's `tc`: the record's
    /// fields don't describe the reply the client got (core.md §6).
    #[error("rebuilt reply's TC differs from the logged tc")]
    TcMismatch,
}

/// A bounds-checked writer over `&mut [u8]`. It never allocates and never panics: every write
/// past the end fails with [`WriteError::BufferTooSmall`].
pub(crate) struct Out<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> Out<'b> {
    pub(crate) fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(WriteError::BufferTooSmall)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(WriteError::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    pub(crate) fn u8(&mut self, v: u8) -> Result<(), WriteError> {
        self.put(&[v])
    }

    pub(crate) fn u16(&mut self, v: u16) -> Result<(), WriteError> {
        self.put(&v.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, v: u32) -> Result<(), WriteError> {
        self.put(&v.to_be_bytes())
    }

    pub(crate) fn zeros(&mut self, n: usize) -> Result<(), WriteError> {
        let end = self.pos.checked_add(n).ok_or(WriteError::BufferTooSmall)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(WriteError::BufferTooSmall)?
            .fill(0);
        self.pos = end;
        Ok(())
    }

    /// Overwrites a big-endian u16 written earlier.
    pub(crate) fn patch_u16(&mut self, at: usize, v: u16) -> Result<(), WriteError> {
        set_u16(self.buf, at, v).ok_or(WriteError::BufferTooSmall)
    }

    /// Overwrites a big-endian u32 written earlier.
    pub(crate) fn patch_u32(&mut self, at: usize, v: u32) -> Result<(), WriteError> {
        set_u32(self.buf, at, v).ok_or(WriteError::BufferTooSmall)
    }
}

pub(crate) fn get_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

pub(crate) fn get_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Some(u32::from_be_bytes(a))
}

pub(crate) fn set_u16(b: &mut [u8], at: usize, v: u16) -> Option<()> {
    b.get_mut(at..at.checked_add(2)?)?
        .copy_from_slice(&v.to_be_bytes());
    Some(())
}

pub(crate) fn set_u32(b: &mut [u8], at: usize, v: u32) -> Option<()> {
    b.get_mut(at..at.checked_add(4)?)?
        .copy_from_slice(&v.to_be_bytes());
    Some(())
}

/// Skips one name in a message this crate had hickory encode: labels up to a root byte or a
/// compression pointer. Returns the offset just past the name. Bounds-checked; `None` on bytes
/// that aren't a name (never expected for a hickory-encoded copy).
pub(crate) fn skip_encoded_name(msg: &[u8], mut at: usize) -> Option<usize> {
    // A name is at most 255 bytes: 128 steps bound the loop even on corrupt input.
    for _ in 0..128 {
        let len = *msg.get(at)?;
        match len & 0xC0 {
            0x00 if len == 0 => return at.checked_add(1),
            0x00 => at = at.checked_add(1)?.checked_add(usize::from(len))?,
            0xC0 => return at.checked_add(2),
            _ => return None,
        }
    }
    None
}

/// One record header TTL in an encoded copy (edge.md §8): its byte offset from the start of the
/// copy's records and the original TTL a hit ages: the TTL as the copy holds it, except for a
/// negative answer's SOA, which ages from min(SOA TTL, SOA MINIMUM) (RFC 2308 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtlSlot {
    pub offset: u16,
    pub ttl: u32,
}

/// Walks `count` records starting at `start` in a message this crate had hickory encode, and
/// returns the offset (relative to `start`) of every record's header TTL with its value, and the
/// offset just past the last record. Never touches RDATA fields such as SOA MINIMUM.
pub(crate) fn walk_ttls(msg: &[u8], start: usize, count: usize) -> Option<(Vec<TtlSlot>, usize)> {
    let mut slots = Vec::with_capacity(count);
    let mut at = start;
    for _ in 0..count {
        let after_name = skip_encoded_name(msg, at)?;
        // TYPE (2) and CLASS (2), then the TTL.
        let ttl_at = after_name.checked_add(4)?;
        let ttl = get_u32(msg, ttl_at)?;
        let rdlen = get_u16(msg, ttl_at.checked_add(4)?)?;
        let rdata_at = ttl_at.checked_add(6)?;
        let end = rdata_at.checked_add(usize::from(rdlen))?;
        if end > msg.len() {
            return None;
        }
        slots.push(TtlSlot {
            offset: u16::try_from(ttl_at.checked_sub(start)?).ok()?,
            ttl,
        });
        at = end;
    }
    Some((slots, at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_bounds() {
        let mut b = [0u8; 4];
        let mut o = Out::new(&mut b);
        o.u16(0x0102).unwrap();
        assert_eq!(o.u32(1), Err(WriteError::BufferTooSmall));
        o.u8(3).unwrap();
        o.patch_u16(0, 0xAABB).unwrap();
        assert_eq!(o.patch_u16(3, 1), Err(WriteError::BufferTooSmall));
        assert_eq!(o.pos(), 3);
        assert_eq!(&b[..3], &[0xAA, 0xBB, 3]);
    }

    #[test]
    fn skip_names() {
        assert_eq!(skip_encoded_name(&[0], 0), Some(1));
        assert_eq!(skip_encoded_name(&[1, b'a', 0], 0), Some(3));
        assert_eq!(skip_encoded_name(&[1, b'a', 0xC0, 0x0C], 0), Some(4));
        assert_eq!(skip_encoded_name(&[1, b'a'], 0), None);
        assert_eq!(skip_encoded_name(&[0x80], 0), None);
    }
}
