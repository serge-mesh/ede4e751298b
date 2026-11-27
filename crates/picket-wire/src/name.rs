//! Names: the query name in a fixed stack buffer with its wire label boundaries (edge.md §4
//! "Parsing"), owned names for extracted facts, the reversed-label form bundles look up
//! (bundles.md §6), and the two text forms: log text (api.md §5, via `picket_api::names`) and
//! AdGuard Home's text form that patterns match (rules.md §3, `picket_api::names::adguard_text`).
//!
//! Every name here is held in lowercase uncompressed wire form (length-prefixed labels ending with
//! the root byte). Names come only from hickory's decoder, from labels, or from presentation text,
//! and are validated when built, so the accessors walk trusted bytes. Matching is on raw labels:
//! a `.` byte inside a label is part of that label, never a boundary (rules.md §3).

use std::fmt;

use hickory_proto::rr::Name;
use smallvec::SmallVec;
use thiserror::Error;

/// The longest name in wire form (RFC 1035 §3.1).
pub const MAX_WIRE: usize = 255;
/// The longest label (RFC 1035 §3.1).
pub const MAX_LABEL: usize = 63;
/// The most labels a name can have: 127 one-byte labels plus the root fill 255 bytes.
pub const MAX_LABELS: usize = 127;

/// Why a name couldn't be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum NameError {
    #[error("empty label")]
    EmptyLabel,
    #[error("label over 63 bytes")]
    LabelTooLong,
    #[error("name over 255 bytes")]
    NameTooLong,
    #[error("malformed escape")]
    BadEscape,
}

/// Builds a lowercase wire name into a fixed buffer.
struct Builder {
    buf: [u8; MAX_WIRE],
    len: usize,
    starts: [u8; MAX_LABELS + 1],
    n: usize,
}

impl Builder {
    fn new() -> Self {
        Self {
            buf: [0; MAX_WIRE],
            len: 0,
            starts: [0; MAX_LABELS + 1],
            n: 0,
        }
    }

    fn push_label(&mut self, label: &[u8]) -> Result<(), NameError> {
        if label.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        let ll = u8::try_from(label.len())
            .ok()
            .filter(|&l| usize::from(l) <= MAX_LABEL)
            .ok_or(NameError::LabelTooLong)?;
        // Room for the length byte, the label and the final root byte.
        let end = self
            .len
            .checked_add(1)
            .and_then(|v| v.checked_add(label.len()))
            .filter(|&e| e < MAX_WIRE)
            .ok_or(NameError::NameTooLong)?;
        let start = u8::try_from(self.len).map_err(|_| NameError::NameTooLong)?;
        *self.starts.get_mut(self.n).ok_or(NameError::NameTooLong)? = start;
        *self.buf.get_mut(self.len).ok_or(NameError::NameTooLong)? = ll;
        let dst = self
            .buf
            .get_mut(self.len.saturating_add(1)..end)
            .ok_or(NameError::NameTooLong)?;
        for (d, s) in dst.iter_mut().zip(label) {
            *d = s.to_ascii_lowercase();
        }
        self.len = end;
        self.n = self.n.saturating_add(1);
        Ok(())
    }

    fn finish(mut self) -> Result<QName, NameError> {
        *self.buf.get_mut(self.len).ok_or(NameError::NameTooLong)? = 0;
        let len = self.len.checked_add(1).ok_or(NameError::NameTooLong)?;
        Ok(QName {
            buf: self.buf,
            len: u8::try_from(len).map_err(|_| NameError::NameTooLong)?,
            starts: self.starts,
            n: u8::try_from(self.n).map_err(|_| NameError::NameTooLong)?,
        })
    }
}

/// Splits presentation text into labels, decoding `\DDD` and `\X` escapes (RFC 1035 §5.1; the
/// log text of api.md §5 and AdGuard's text form both read back). A trailing dot is optional;
/// `""` and `"."` are the root.
fn parse_text(text: &str, mut each: impl FnMut(&[u8]) -> Result<(), NameError>) -> Result<(), NameError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes == b"." {
        return Ok(());
    }
    let mut label: SmallVec<[u8; 64]> = SmallVec::new();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        i = i.saturating_add(1);
        match b {
            b'.' => {
                each(&label)?;
                label.clear();
                if i == bytes.len() {
                    return Ok(()); // trailing dot
                }
            }
            b'\\' => {
                let next = *bytes.get(i).ok_or(NameError::BadEscape)?;
                if next.is_ascii_digit() {
                    let d = bytes.get(i..i.saturating_add(3)).ok_or(NameError::BadEscape)?;
                    let mut v: u16 = 0;
                    for &c in d {
                        if !c.is_ascii_digit() {
                            return Err(NameError::BadEscape);
                        }
                        v = v
                            .saturating_mul(10)
                            .saturating_add(u16::from(c.saturating_sub(b'0')));
                    }
                    label.push(u8::try_from(v).map_err(|_| NameError::BadEscape)?);
                    i = i.saturating_add(3);
                } else {
                    label.push(next);
                    i = i.saturating_add(1);
                }
            }
            _ => label.push(b),
        }
        if label.len() > MAX_LABEL {
            return Err(NameError::LabelTooLong);
        }
    }
    each(&label)
}

/// A query name: ASCII-lowercased wire form in a fixed stack buffer with the offset of every
/// label, so labels, suffixes and the reversed form come without allocating (edge.md §4).
#[derive(Clone)]
pub struct QName {
    buf: [u8; MAX_WIRE],
    len: u8,
    starts: [u8; MAX_LABELS + 1],
    n: u8,
}

impl QName {
    /// The root name.
    pub fn root() -> Self {
        Self {
            buf: [0u8; MAX_WIRE],
            len: 1,
            starts: [0; MAX_LABELS + 1],
            n: 0,
        }
    }

    /// Builds a name from labels (without length bytes), lowercasing them.
    pub fn from_labels<'l, I>(labels: I) -> Result<Self, NameError>
    where
        I: IntoIterator<Item = &'l [u8]>,
    {
        let mut b = Builder::new();
        for l in labels {
            b.push_label(l)?;
        }
        b.finish()
    }

    /// Builds a name from presentation or log text (`\DDD` and `\X` escapes decoded).
    pub fn from_text(text: &str) -> Result<Self, NameError> {
        let mut b = Builder::new();
        parse_text(text, |l| b.push_label(l))?;
        b.finish()
    }

    /// Builds a name from a name hickory decoded, lowercasing it.
    pub fn from_hickory(name: &Name) -> Result<Self, NameError> {
        Self::from_labels(name.iter())
    }

    /// The borrowed form, which carries the label and text helpers.
    pub fn as_name(&self) -> NameRef<'_> {
        NameRef(self.buf.get(..usize::from(self.len)).unwrap_or(&[0]))
    }

    /// The lowercase wire form.
    pub fn wire(&self) -> &[u8] {
        self.as_name().0
    }

    pub fn num_labels(&self) -> usize {
        usize::from(self.n)
    }

    pub fn is_root(&self) -> bool {
        self.n == 0
    }

    /// Label `i`, counting from the left (0 is the leftmost label).
    pub fn label(&self, i: usize) -> Option<&[u8]> {
        if i >= self.num_labels() {
            return None;
        }
        let start = usize::from(*self.starts.get(i)?);
        let len = usize::from(*self.buf.get(start)?);
        let from = start.checked_add(1)?;
        self.buf.get(from..from.checked_add(len)?)
    }

    /// The labels, left to right; reversible for a right-to-left walk.
    pub fn labels(&self) -> QLabels<'_> {
        QLabels {
            name: self,
            front: 0,
            back: self.num_labels(),
        }
    }

    /// The name made of the last `n` labels (`n` ≤ the label count).
    pub fn suffix(&self, n: usize) -> Option<NameRef<'_>> {
        let count = self.num_labels();
        if n > count {
            return None;
        }
        if n == 0 {
            return Some(NameRef(
                self.buf
                    .get(usize::from(self.len).checked_sub(1)?..usize::from(self.len))?,
            ));
        }
        let start = usize::from(*self.starts.get(count.checked_sub(n)?)?);
        Some(NameRef(self.buf.get(start..usize::from(self.len))?))
    }

    /// The reversed-label form for bundle lookups (bundles.md §6).
    pub fn reversed(&self) -> ReversedName {
        let mut r = ReversedName::empty();
        for l in self.labels().rev() {
            r.push(l);
        }
        r
    }

    pub fn log_text(&self) -> String {
        self.as_name().log_text()
    }

    pub fn adguard_text(&self) -> String {
        self.as_name().adguard_text()
    }

    pub fn to_wire_name(&self) -> WireName {
        self.as_name().to_wire_name()
    }
}

impl PartialEq for QName {
    fn eq(&self, other: &Self) -> bool {
        self.wire() == other.wire()
    }
}

impl Eq for QName {}

impl fmt::Debug for QName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.as_name(), f)
    }
}

impl<'a> From<&'a QName> for NameRef<'a> {
    fn from(q: &'a QName) -> Self {
        q.as_name()
    }
}

/// The labels of a [`QName`].
pub struct QLabels<'a> {
    name: &'a QName,
    front: usize,
    back: usize,
}

impl<'a> Iterator for QLabels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.front >= self.back {
            return None;
        }
        let l = self.name.label(self.front);
        self.front = self.front.saturating_add(1);
        l
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.back.saturating_sub(self.front);
        (n, Some(n))
    }
}

impl DoubleEndedIterator for QLabels<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        self.back = self.back.saturating_sub(1);
        self.name.label(self.back)
    }
}

impl ExactSizeIterator for QLabels<'_> {}

/// A borrowed name in lowercase uncompressed wire form, validated when its owner was built.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameRef<'a>(&'a [u8]);

impl<'a> NameRef<'a> {
    /// The root name.
    pub const ROOT: NameRef<'static> = NameRef(&[0]);

    /// A name from a constant this crate wrote in valid lowercase wire form.
    pub(crate) const fn from_static(wire: &'static [u8]) -> NameRef<'static> {
        NameRef(wire)
    }

    /// Wire bytes this crate built from validated labels (a label sequence, with or without the
    /// root byte).
    pub(crate) fn from_trusted(wire: &'a [u8]) -> NameRef<'a> {
        NameRef(wire)
    }

    pub fn wire(self) -> &'a [u8] {
        self.0
    }

    pub fn wire_len(self) -> usize {
        self.0.len()
    }

    pub fn is_root(self) -> bool {
        self.0.first() == Some(&0)
    }

    /// The labels, left to right.
    pub fn labels(self) -> Labels<'a> {
        Labels { rest: self.0 }
    }

    pub fn num_labels(self) -> usize {
        self.labels().count()
    }

    /// The name without its leftmost label; `None` at the root.
    pub fn parent(self) -> Option<NameRef<'a>> {
        let len = usize::from(*self.0.first()?);
        if len == 0 {
            return None;
        }
        Some(NameRef(self.0.get(len.checked_add(1)?..)?))
    }

    /// True when `self` is `zone` or a name below it, comparing whole labels.
    pub fn is_at_or_below(self, zone: NameRef<'_>) -> bool {
        self.0.len() >= zone.0.len() && {
            // Walk label boundaries until the remaining suffix is as long as the zone.
            let mut cur = self;
            loop {
                if cur.0.len() == zone.0.len() {
                    break cur.0 == zone.0;
                }
                match cur.parent() {
                    Some(p) if p.0.len() >= zone.0.len() => cur = p,
                    _ => break false,
                }
            }
        }
    }

    /// Log text (api.md §5): lowercase, bytes outside `a-z0-9-_` as `\DDD`; the root is `""`.
    pub fn log_text(self) -> String {
        picket_api::names::encode_labels(self.labels())
    }

    /// AdGuard Home's text form, which patterns match (rules.md §3).
    pub fn adguard_text(self) -> String {
        picket_api::names::adguard_text(self.labels())
    }

    /// Appends AdGuard Home's text form to `out`, so a caller can reuse one buffer.
    pub fn push_adguard_text(self, out: &mut String) {
        picket_api::names::push_adguard_text(out, self.labels());
    }

    /// True when no label holds a byte other than `a-z`, `0-9`, `-` and `_` (rules.md §3), so
    /// the AdGuard text form is the name itself.
    pub fn is_ordinary(self) -> bool {
        self.labels().all(picket_api::names::is_ordinary_label)
    }

    /// The reversed-label form for bundle lookups (bundles.md §6).
    pub fn reversed(self) -> ReversedName {
        let mut starts = [0u8; MAX_LABELS];
        let mut n = 0usize;
        let mut at = 0usize;
        while let Some(&len) = self.0.get(at) {
            if len == 0 {
                break;
            }
            if let (Some(slot), Ok(a)) = (starts.get_mut(n), u8::try_from(at)) {
                *slot = a;
                n = n.saturating_add(1);
            }
            at = at.saturating_add(1).saturating_add(usize::from(len));
        }
        let mut r = ReversedName::empty();
        for &s in starts.get(..n).unwrap_or(&[]).iter().rev() {
            let s = usize::from(s);
            let len = usize::from(self.0.get(s).copied().unwrap_or(0));
            if let Some(l) = self
                .0
                .get(s.saturating_add(1)..s.saturating_add(1).saturating_add(len))
            {
                r.push(l);
            }
        }
        r
    }

    pub fn to_wire_name(self) -> WireName {
        WireName(SmallVec::from_slice(self.0))
    }

    pub fn to_qname(self) -> QName {
        QName::from_labels(self.labels()).unwrap_or_else(|_| QName::root())
    }

    /// The name as hickory's type, for records this crate has hickory encode.
    pub(crate) fn to_hickory(self) -> Option<Name> {
        use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
        let mut d = BinDecoder::new(self.0);
        Name::read(&mut d).ok()
    }
}

impl fmt::Debug for NameRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            f.write_str(".")
        } else {
            f.write_str(&self.log_text())
        }
    }
}

/// The labels of a [`NameRef`], left to right.
#[derive(Clone)]
pub struct Labels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(*self.rest.first()?);
        if len == 0 {
            return None;
        }
        let end = len.checked_add(1)?;
        let label = self.rest.get(1..end)?;
        self.rest = self.rest.get(end..)?;
        Some(label)
    }
}

/// An owned name in lowercase wire form; names of 32 wire bytes or fewer stay inline. Used for
/// the names extracted from answers (CNAME chain, HTTPS/SVCB targets).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WireName(SmallVec<[u8; 32]>);

impl WireName {
    pub fn root() -> Self {
        Self(SmallVec::from_slice(&[0]))
    }

    pub fn from_labels<'l, I>(labels: I) -> Result<Self, NameError>
    where
        I: IntoIterator<Item = &'l [u8]>,
    {
        Ok(QName::from_labels(labels)?.to_wire_name())
    }

    pub fn from_text(text: &str) -> Result<Self, NameError> {
        Ok(QName::from_text(text)?.to_wire_name())
    }

    /// From a name hickory decoded, lowercased.
    pub fn from_hickory(name: &Name) -> Result<Self, NameError> {
        let mut v: SmallVec<[u8; 32]> = SmallVec::new();
        let mut total = 1usize;
        for l in name.iter() {
            if l.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            let ll = u8::try_from(l.len())
                .ok()
                .filter(|&x| usize::from(x) <= MAX_LABEL)
                .ok_or(NameError::LabelTooLong)?;
            total = total.saturating_add(1).saturating_add(l.len());
            if total > MAX_WIRE {
                return Err(NameError::NameTooLong);
            }
            v.push(ll);
            v.extend(l.iter().map(u8::to_ascii_lowercase));
        }
        v.push(0);
        Ok(Self(v))
    }

    pub fn as_name(&self) -> NameRef<'_> {
        NameRef(&self.0)
    }

    pub fn wire(&self) -> &[u8] {
        &self.0
    }

    pub fn log_text(&self) -> String {
        self.as_name().log_text()
    }

    pub fn adguard_text(&self) -> String {
        self.as_name().adguard_text()
    }

    pub fn reversed(&self) -> ReversedName {
        self.as_name().reversed()
    }

    /// Heap bytes this name holds beyond its inline size (for cache weighers).
    pub fn heap_size(&self) -> usize {
        if self.0.spilled() { self.0.capacity() } else { 0 }
    }
}

impl fmt::Debug for WireName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.as_name(), f)
    }
}

impl<'a> From<&'a WireName> for NameRef<'a> {
    fn from(w: &'a WireName) -> Self {
        w.as_name()
    }
}

/// The reversed-label form of a name in a stack buffer: labels from the rightmost to the
/// leftmost, joined by `.` (`ads.www.example.org` → `org.example.www.ads`), as bundle FST keys
/// are written (bundles.md §4, §6). Each suffix of the name is a prefix of this buffer that ends
/// at a label boundary; a suffix that includes a label holding a `.` byte matches no key
/// (rules.md §3), so [`ReversedName::suffix`] doesn't offer it.
#[derive(Clone)]
pub struct ReversedName {
    buf: [u8; MAX_WIRE],
    len: u8,
    ends: [u8; MAX_LABELS],
    n: u8,
    /// How many labels from the right hold no `.` byte.
    clean: u8,
    dirty: bool,
}

impl ReversedName {
    fn empty() -> Self {
        Self {
            buf: [0; MAX_WIRE],
            len: 0,
            ends: [0; MAX_LABELS],
            n: 0,
            clean: 0,
            dirty: false,
        }
    }

    /// Appends the next label (right to left). Names are validated, so this always fits.
    fn push(&mut self, label: &[u8]) {
        let mut at = usize::from(self.len);
        if self.n > 0 {
            if let Some(b) = self.buf.get_mut(at) {
                *b = b'.';
            }
            at = at.saturating_add(1);
        }
        let end = at.saturating_add(label.len()).min(MAX_WIRE);
        if let Some(dst) = self.buf.get_mut(at..end) {
            dst.copy_from_slice(label.get(..end.saturating_sub(at)).unwrap_or(&[]));
        }
        self.len = u8::try_from(end).unwrap_or(u8::MAX);
        if let Some(e) = self.ends.get_mut(usize::from(self.n)) {
            *e = self.len;
        }
        self.n = self.n.saturating_add(1);
        if label.contains(&b'.') {
            self.dirty = true;
        }
        if !self.dirty {
            self.clean = self.n;
        }
    }

    /// The whole reversed form (`org.example.www.ads`); empty for the root.
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..usize::from(self.len)).unwrap_or(&[])
    }

    pub fn num_labels(&self) -> usize {
        usize::from(self.n)
    }

    /// True when some label holds a `.` byte.
    pub fn has_dotted_label(&self) -> bool {
        self.dirty
    }

    /// The key for the suffix made of the last `n` labels (`1 ≤ n ≤` the label count), or
    /// `None` when one of those labels holds a `.` byte.
    pub fn suffix(&self, n: usize) -> Option<&[u8]> {
        if n == 0 || n > usize::from(self.clean) {
            return None;
        }
        let end = usize::from(*self.ends.get(n.checked_sub(1)?)?);
        self.buf.get(..end)
    }

    /// The keys of every suffix that can match, most specific first, with each suffix's label
    /// count (equal to [`Self::num_labels`] for the name itself).
    pub fn suffixes(&self) -> impl Iterator<Item = (usize, &[u8])> + '_ {
        (1..=usize::from(self.clean))
            .rev()
            .filter_map(move |n| self.suffix(n).map(|k| (n, k)))
    }
}

impl fmt::Debug for ReversedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReversedName({:?})", String::from_utf8_lossy(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qname_labels_and_text() {
        let q = QName::from_text("Ads.WWW.Example.org.").unwrap();
        assert_eq!(q.wire(), b"\x03ads\x03www\x07example\x03org\x00");
        assert_eq!(q.num_labels(), 4);
        assert_eq!(q.label(1), Some(&b"www"[..]));
        assert_eq!(q.labels().next_back(), Some(&b"org"[..]));
        assert_eq!(q.log_text(), "ads.www.example.org");
        assert_eq!(q.suffix(2).unwrap().wire(), b"\x07example\x03org\x00");
        assert!(q.suffix(0).unwrap().is_root());
        assert!(q.suffix(5).is_none());
        assert!(QName::root().is_root());
        assert_eq!(QName::from_text(".").unwrap().wire(), &[0]);
        assert_eq!(QName::from_text("").unwrap().wire(), &[0]);
    }

    #[test]
    fn unusual_bytes() {
        // A `.` byte inside a label is part of the label (rules.md §3).
        let q = QName::from_labels([&b"a.b"[..], b"Evil", b"example"]).unwrap();
        assert_eq!(q.num_labels(), 3);
        assert_eq!(q.log_text(), "a\\046b.evil.example");
        assert_eq!(q.adguard_text(), "a\\.b.evil.example");
        assert!(!q.as_name().is_ordinary());
        let back = QName::from_text(&q.log_text()).unwrap();
        assert_eq!(back, q);
        let back2 = QName::from_text(&q.adguard_text()).unwrap();
        assert_eq!(back2, q);
        assert_eq!(QName::from_text("a\\033b.x").unwrap().label(0), Some(&b"a!b"[..]));
        assert_eq!(QName::from_text("a\\25"), Err(NameError::BadEscape));
        assert_eq!(QName::from_text("a\\256.x"), Err(NameError::BadEscape));
        assert_eq!(QName::from_text("a..b"), Err(NameError::EmptyLabel));
    }

    #[test]
    fn limits() {
        let long = "a".repeat(64);
        assert_eq!(QName::from_text(&long), Err(NameError::LabelTooLong));
        let ok63 = "a".repeat(63);
        let name = format!("{ok63}.{ok63}.{ok63}.{}", "a".repeat(61));
        assert_eq!(QName::from_text(&name).unwrap().wire().len(), 255);
        let too = format!("{ok63}.{ok63}.{ok63}.{}", "a".repeat(62));
        assert_eq!(QName::from_text(&too), Err(NameError::NameTooLong));
        let many = vec!["a"; 127].join(".");
        assert_eq!(QName::from_text(&many).unwrap().num_labels(), 127);
        let more = vec!["a"; 128].join(".");
        assert_eq!(QName::from_text(&more), Err(NameError::NameTooLong));
    }

    #[test]
    fn reversed_suffixes() {
        let q = QName::from_text("ads.www.example.org").unwrap();
        let r = q.reversed();
        assert_eq!(r.as_bytes(), b"org.example.www.ads");
        let s: Vec<_> = r.suffixes().collect();
        assert_eq!(
            s,
            vec![
                (4, &b"org.example.www.ads"[..]),
                (3, &b"org.example.www"[..]),
                (2, &b"org.example"[..]),
                (1, &b"org"[..])
            ]
        );
        assert_eq!(q.as_name().reversed().as_bytes(), r.as_bytes());

        // A suffix that includes a dotted label matches no key (rules.md §3).
        let d = QName::from_labels([&b"x"[..], b"a.b", b"example", b"org"]).unwrap();
        let r = d.reversed();
        assert!(r.has_dotted_label());
        assert_eq!(r.suffix(2), Some(&b"org.example"[..]));
        assert_eq!(r.suffix(3), None);
        assert_eq!(r.suffix(4), None);
        assert_eq!(r.suffixes().count(), 2);
    }

    #[test]
    fn at_or_below() {
        let a = WireName::from_text("a.b.example.com").unwrap();
        let z = WireName::from_text("example.com").unwrap();
        let other = WireName::from_text("ample.com").unwrap();
        assert!(a.as_name().is_at_or_below(z.as_name()));
        assert!(z.as_name().is_at_or_below(z.as_name()));
        assert!(!a.as_name().is_at_or_below(other.as_name()));
        assert!(!z.as_name().is_at_or_below(a.as_name()));
        assert!(a.as_name().is_at_or_below(NameRef::ROOT));
        // Whole labels only: "xexample.com" is not below "example.com".
        let x = WireName::from_text("xexample.com").unwrap();
        assert!(!x.as_name().is_at_or_below(z.as_name()));
    }

    #[test]
    fn from_hickory_lowercases() {
        let n = Name::from_ascii("WwW.ExAmple.COM.").unwrap();
        let q = QName::from_hickory(&n).unwrap();
        assert_eq!(q.log_text(), "www.example.com");
        assert_eq!(WireName::from_hickory(&n).unwrap().wire(), q.wire());
        assert_eq!(q.as_name().to_hickory().unwrap(), n);
    }
}
