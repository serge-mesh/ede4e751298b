//! Checked little-endian reading of untrusted bytes, and the hex forms ids and checksums use.
//!
//! Every read checks the remaining length first, so a truncated or hostile file yields
//! [`Truncated`] instead of a panic, and callers check counts against [`ByteReader::remaining`]
//! before allocating (README §2 "Untrusted input").

/// The input ended before a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("truncated input")]
pub struct Truncated;

/// A cursor over a byte slice.
#[derive(Clone, Debug)]
pub struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not read yet.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// The read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The next `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let end = self.pos.checked_add(n).ok_or(Truncated)?;
        let s = self.data.get(self.pos..end).ok_or(Truncated)?;
        self.pos = end;
        Ok(s)
    }

    /// The next `N` bytes as an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        let s = self.bytes(N)?;
        <[u8; N]>::try_from(s).map_err(|_| Truncated)
    }

    pub fn u8(&mut self) -> Result<u8, Truncated> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    pub fn u16(&mut self) -> Result<u16, Truncated> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, Truncated> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, Truncated> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn u128(&mut self) -> Result<u128, Truncated> {
        Ok(u128::from_le_bytes(self.array()?))
    }

    /// The rest of the input.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = self.data.get(self.pos..).unwrap_or(&[]);
        self.pos = self.data.len();
        s
    }
}

/// Lowercase hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    let digit = |n: u8| char::from(DIGITS.get(usize::from(n)).copied().unwrap_or(b'0'));
    for &b in bytes {
        s.push(digit(b >> 4));
        s.push(digit(b & 0x0f));
    }
    s
}

/// Parses lowercase (or uppercase) hex into exactly `N` bytes.
pub fn from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0u8; N];
    let (pairs, _) = b.as_chunks::<2>();
    for (o, &[hi, lo]) in out.iter_mut().zip(pairs) {
        *o = (hex_digit(hi)? << 4) | hex_digit(lo)?;
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// True for a BLAKE3 object id: 64 lowercase hex characters (api.md §2).
pub fn is_object_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The BLAKE3 object id of `bytes` (api.md §2).
pub fn object_id(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_is_checked() {
        let mut r = ByteReader::new(&[1, 0, 2, 0, 0, 0, 9]);
        assert_eq!(r.u16(), Ok(1));
        assert_eq!(r.u32(), Ok(2));
        assert_eq!(r.remaining(), 1);
        assert_eq!(r.u16(), Err(Truncated));
        assert_eq!(r.u8(), Ok(9));
        assert_eq!(r.bytes(usize::MAX), Err(Truncated));
    }

    #[test]
    fn hex() {
        assert_eq!(to_hex(&[0x0f, 0xa0]), "0fa0");
        assert_eq!(from_hex::<2>("0fa0"), Some([0x0f, 0xa0]));
        assert_eq!(from_hex::<2>("0fa"), None);
        assert_eq!(from_hex::<1>("zz"), None);
        assert!(is_object_id(&object_id(b"x")));
        assert!(!is_object_id("ABC"));
    }
}
