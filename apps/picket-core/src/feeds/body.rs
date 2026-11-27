//! The manual-feed write bodies (api.md §7), read as they stream: `PUT feeds/{id}/file` with
//! `{content, base_version}` and `POST feeds/{id}/file/lines` with `{lines}`. Neither the body
//! nor the file is held in RAM: a small pull parser walks the JSON byte by byte and hands the
//! decoded text of `content` (or each line) to a sink as it goes.
//!
//! The body is untrusted input: it is bounded (by the caller's counting reader and the sinks'
//! caps), strict JSON (one object, known value types, escapes per RFC 8259 with surrogate pairs,
//! unknown members skipped up to a nesting bound), and never panics. A `lines` item holding a
//! line break is refused (`422`).

use std::io::{self, Read};

/// The deepest nesting skipped inside an unknown member.
const MAX_DEPTH: usize = 32;
/// The longest `base_version` kept.
const MAX_VERSION: usize = 128;
/// Decoded bytes buffered before a sink call.
const FLUSH: usize = 16 * 1024;

/// Why a body can't be used.
#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    /// Not the JSON this endpoint takes (400).
    #[error("{0}")]
    Syntax(String),
    /// Well-formed but unusable: a missing member, a line break in a line (422).
    #[error("{0}")]
    Invalid(String),
    /// Past a size cap (413).
    #[error("the body is too large")]
    TooLarge,
    #[error("cannot read the body: {0}")]
    Io(io::Error),
}

impl From<io::Error> for BodyError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::FileTooLarge {
            BodyError::TooLarge
        } else {
            BodyError::Io(e)
        }
    }
}

/// A byte reader with one byte of lookahead.
struct Bytes<R: Read> {
    r: io::BufReader<R>,
    peeked: Option<u8>,
}

impl<R: Read> Bytes<R> {
    fn new(r: R) -> Self {
        Self {
            r: io::BufReader::with_capacity(64 * 1024, r),
            peeked: None,
        }
    }

    fn next(&mut self) -> Result<Option<u8>, BodyError> {
        if let Some(b) = self.peeked.take() {
            return Ok(Some(b));
        }
        let mut b = [0u8; 1];
        loop {
            match self.r.read(&mut b) {
                Ok(0) => return Ok(None),
                Ok(_) => return Ok(Some(b[0])),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn peek(&mut self) -> Result<Option<u8>, BodyError> {
        if self.peeked.is_none() {
            self.peeked = self.next()?;
        }
        Ok(self.peeked)
    }

    fn must(&mut self) -> Result<u8, BodyError> {
        self.next()?
            .ok_or_else(|| BodyError::Syntax("the JSON body ends too soon".into()))
    }

    fn skip_ws(&mut self) -> Result<(), BodyError> {
        while let Some(b) = self.peek()? {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.peeked = None;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn expect(&mut self, want: u8) -> Result<(), BodyError> {
        self.skip_ws()?;
        match self.must()? {
            b if b == want => Ok(()),
            b => Err(BodyError::Syntax(format!(
                "expected {:?} in the JSON body, found {:?}",
                want as char,
                char::from(b).escape_default().to_string()
            ))),
        }
    }

    fn hex4(&mut self) -> Result<u32, BodyError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.must()?;
            let d = (b as char)
                .to_digit(16)
                .ok_or_else(|| BodyError::Syntax("a bad \\u escape in the JSON body".into()))?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    /// Reads a string (after its opening quote), giving decoded bytes to `out` in chunks.
    fn string(&mut self, out: &mut dyn FnMut(&[u8]) -> Result<(), BodyError>) -> Result<(), BodyError> {
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        loop {
            let b = self.must()?;
            match b {
                b'"' => break,
                b'\\' => {
                    let e = self.must()?;
                    let c: u32 = match e {
                        b'"' => '"' as u32,
                        b'\\' => '\\' as u32,
                        b'/' => '/' as u32,
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => '\n' as u32,
                        b'r' => '\r' as u32,
                        b't' => '\t' as u32,
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                if self.must()? != b'\\' || self.must()? != b'u' {
                                    return Err(BodyError::Syntax(
                                        "a lone surrogate in the JSON body".into(),
                                    ));
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(BodyError::Syntax(
                                        "a lone surrogate in the JSON body".into(),
                                    ));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(BodyError::Syntax("a lone surrogate in the JSON body".into()));
                            } else {
                                hi
                            }
                        }
                        _ => return Err(BodyError::Syntax("a bad escape in the JSON body".into())),
                    };
                    let ch = char::from_u32(c)
                        .ok_or_else(|| BodyError::Syntax("a bad \\u escape in the JSON body".into()))?;
                    let mut tmp = [0u8; 4];
                    buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                }
                0x00..=0x1f => {
                    return Err(BodyError::Syntax(
                        "a control character inside a JSON string".into(),
                    ));
                }
                _ => buf.push(b),
            }
            if buf.len() >= FLUSH {
                out(&buf)?;
                buf.clear();
            }
        }
        if !buf.is_empty() {
            out(&buf)?;
        }
        Ok(())
    }

    /// Skips any JSON value.
    fn skip_value(&mut self, depth: usize) -> Result<(), BodyError> {
        if depth > MAX_DEPTH {
            return Err(BodyError::Syntax("the JSON body nests too deeply".into()));
        }
        self.skip_ws()?;
        match self.must()? {
            b'"' => self.string(&mut |_| Ok(())),
            b'{' => {
                self.skip_ws()?;
                if self.peek()? == Some(b'}') {
                    self.peeked = None;
                    return Ok(());
                }
                loop {
                    self.expect(b'"')?;
                    self.string(&mut |_| Ok(()))?;
                    self.expect(b':')?;
                    self.skip_value(depth + 1)?;
                    self.skip_ws()?;
                    match self.must()? {
                        b',' => continue,
                        b'}' => return Ok(()),
                        _ => return Err(BodyError::Syntax("expected , or } in the JSON body".into())),
                    }
                }
            }
            b'[' => {
                self.skip_ws()?;
                if self.peek()? == Some(b']') {
                    self.peeked = None;
                    return Ok(());
                }
                loop {
                    self.skip_value(depth + 1)?;
                    self.skip_ws()?;
                    match self.must()? {
                        b',' => continue,
                        b']' => return Ok(()),
                        _ => return Err(BodyError::Syntax("expected , or ] in the JSON body".into())),
                    }
                }
            }
            b't' => self.literal(b"rue"),
            b'f' => self.literal(b"alse"),
            b'n' => self.literal(b"ull"),
            b'-' | b'0'..=b'9' => {
                while let Some(b) = self.peek()? {
                    if b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-') {
                        self.peeked = None;
                    } else {
                        break;
                    }
                }
                Ok(())
            }
            _ => Err(BodyError::Syntax(
                "an unexpected character in the JSON body".into(),
            )),
        }
    }

    fn literal(&mut self, rest: &[u8]) -> Result<(), BodyError> {
        for want in rest {
            if self.must()? != *want {
                return Err(BodyError::Syntax("a bad literal in the JSON body".into()));
            }
        }
        Ok(())
    }

    /// Reads a member name.
    fn key(&mut self) -> Result<String, BodyError> {
        self.expect(b'"')?;
        let mut k = Vec::new();
        self.string(&mut |b| {
            if k.len() + b.len() > 256 {
                return Err(BodyError::Syntax("a member name is too long".into()));
            }
            k.extend_from_slice(b);
            Ok(())
        })?;
        Ok(String::from_utf8_lossy(&k).into_owned())
    }

    fn end(&mut self) -> Result<(), BodyError> {
        self.skip_ws()?;
        match self.next()? {
            None => Ok(()),
            Some(_) => Err(BodyError::Syntax("data after the JSON object".into())),
        }
    }

    /// Walks the top-level object, calling `member` for each name (which must consume its
    /// value).
    fn object(
        &mut self,
        mut member: impl FnMut(&mut Self, &str) -> Result<(), BodyError>,
    ) -> Result<(), BodyError> {
        self.expect(b'{')?;
        self.skip_ws()?;
        if self.peek()? == Some(b'}') {
            self.peeked = None;
            return self.end();
        }
        loop {
            let k = self.key()?;
            self.expect(b':')?;
            member(self, &k)?;
            self.skip_ws()?;
            match self.must()? {
                b',' => continue,
                b'}' => break,
                _ => return Err(BodyError::Syntax("expected , or } in the JSON body".into())),
            }
        }
        self.end()
    }
}

/// `PUT feeds/{id}/file`'s body, as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaveBody {
    /// `base_version`: `None` when null (allowed only while the feed has no file).
    pub base_version: Option<String>,
}

/// Reads `{content, base_version}`; `content` goes to `sink` as it is decoded.
pub fn parse_save<R: Read>(
    r: R,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), BodyError>,
) -> Result<SaveBody, BodyError> {
    let mut p = Bytes::new(r);
    let mut content = false;
    let mut base: Option<Option<String>> = None;
    p.object(|p, k| match k {
        "content" => {
            if content {
                return Err(BodyError::Syntax("content appears twice".into()));
            }
            content = true;
            p.expect(b'"')?;
            p.string(sink)
        }
        "base_version" => {
            if base.is_some() {
                return Err(BodyError::Syntax("base_version appears twice".into()));
            }
            p.skip_ws()?;
            match p.peek()? {
                Some(b'n') => {
                    p.peeked = None;
                    p.literal(b"ull")?;
                    base = Some(None);
                    Ok(())
                }
                Some(b'"') => {
                    p.peeked = None;
                    let mut v = Vec::new();
                    p.string(&mut |b| {
                        if v.len() + b.len() > MAX_VERSION {
                            return Err(BodyError::Invalid("base_version is too long".into()));
                        }
                        v.extend_from_slice(b);
                        Ok(())
                    })?;
                    base = Some(Some(String::from_utf8_lossy(&v).into_owned()));
                    Ok(())
                }
                _ => Err(BodyError::Invalid("base_version is a string or null".into())),
            }
        }
        _ => p.skip_value(0),
    })?;
    if !content {
        return Err(BodyError::Invalid("the body has no content".into()));
    }
    let Some(base_version) = base else {
        return Err(BodyError::Invalid(
            "the body has no base_version (null while the feed has no file)".into(),
        ));
    };
    Ok(SaveBody { base_version })
}

/// Reads `{lines}`: each line, decoded, goes to `line` whole (at most `max_line` bytes); a line
/// with CR or LF in it is refused. Returns how many lines there were.
pub fn parse_lines<R: Read>(
    r: R,
    max_line: usize,
    line: &mut dyn FnMut(&[u8]) -> Result<(), BodyError>,
) -> Result<u64, BodyError> {
    let mut p = Bytes::new(r);
    let mut seen = false;
    let mut n = 0u64;
    p.object(|p, k| match k {
        "lines" => {
            if seen {
                return Err(BodyError::Syntax("lines appears twice".into()));
            }
            seen = true;
            p.expect(b'[')?;
            p.skip_ws()?;
            if p.peek()? == Some(b']') {
                p.peeked = None;
                return Ok(());
            }
            loop {
                p.expect(b'"')?;
                let mut buf = Vec::new();
                p.string(&mut |b| {
                    if b.contains(&b'\n') || b.contains(&b'\r') {
                        return Err(BodyError::Invalid("a line holds a line break".into()));
                    }
                    if buf.len() + b.len() > max_line {
                        return Err(BodyError::TooLarge);
                    }
                    buf.extend_from_slice(b);
                    Ok(())
                })?;
                line(&buf)?;
                n += 1;
                p.skip_ws()?;
                match p.must()? {
                    b',' => continue,
                    b']' => return Ok(()),
                    _ => return Err(BodyError::Syntax("expected , or ] in lines".into())),
                }
            }
        }
        _ => p.skip_value(0),
    })?;
    if !seen {
        return Err(BodyError::Invalid("the body has no lines".into()));
    }
    Ok(n)
}

/// A small JSON value read whole (an import's `feed` settings): at most `budget` strings,
/// numbers and containers in all, each string at most 4 KiB.
fn small_value<R: Read>(
    p: &mut Bytes<R>,
    depth: usize,
    budget: &mut u32,
) -> Result<serde_json::Value, BodyError> {
    use serde_json::Value;
    if depth > MAX_DEPTH {
        return Err(BodyError::Syntax("the JSON body nests too deeply".into()));
    }
    *budget = budget
        .checked_sub(1)
        .ok_or_else(|| BodyError::Invalid("the feed settings are too large".into()))?;
    p.skip_ws()?;
    match p.must()? {
        b'"' => {
            let mut v = Vec::new();
            p.string(&mut |b| {
                if v.len() + b.len() > 4096 {
                    return Err(BodyError::Invalid("a feed setting is too long".into()));
                }
                v.extend_from_slice(b);
                Ok(())
            })?;
            Ok(Value::String(String::from_utf8_lossy(&v).into_owned()))
        }
        b'{' => {
            let mut m = serde_json::Map::new();
            p.skip_ws()?;
            if p.peek()? == Some(b'}') {
                p.peeked = None;
                return Ok(Value::Object(m));
            }
            loop {
                let k = p.key()?;
                p.expect(b':')?;
                let v = small_value(p, depth + 1, budget)?;
                m.insert(k, v);
                p.skip_ws()?;
                match p.must()? {
                    b',' => continue,
                    b'}' => return Ok(Value::Object(m)),
                    _ => return Err(BodyError::Syntax("expected , or } in the JSON body".into())),
                }
            }
        }
        b'[' => {
            let mut a = Vec::new();
            p.skip_ws()?;
            if p.peek()? == Some(b']') {
                p.peeked = None;
                return Ok(Value::Array(a));
            }
            loop {
                a.push(small_value(p, depth + 1, budget)?);
                p.skip_ws()?;
                match p.must()? {
                    b',' => continue,
                    b']' => return Ok(Value::Array(a)),
                    _ => return Err(BodyError::Syntax("expected , or ] in the JSON body".into())),
                }
            }
        }
        b't' => p.literal(b"rue").map(|_| Value::Bool(true)),
        b'f' => p.literal(b"alse").map(|_| Value::Bool(false)),
        b'n' => p.literal(b"ull").map(|_| Value::Null),
        b @ (b'-' | b'0'..=b'9') => {
            let mut t = vec![b];
            while let Some(c) = p.peek()? {
                if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                    p.peeked = None;
                    t.push(c);
                    if t.len() > 64 {
                        return Err(BodyError::Syntax("a number is too long".into()));
                    }
                } else {
                    break;
                }
            }
            serde_json::from_slice::<Value>(&t)
                .map_err(|_| BodyError::Syntax("a bad number in the JSON body".into()))
        }
        _ => Err(BodyError::Syntax(
            "an unexpected character in the JSON body".into(),
        )),
    }
}

/// What an import body held (api.md §7: a JSON export, or `{"file": …}`).
#[derive(Clone, Debug, PartialEq)]
pub enum ImportBody {
    /// A JSON export: its `feed` settings and how many entries it had.
    Export { feed: serde_json::Value, entries: u64 },
    /// `{"file": …}`: a file export or a plain list, handed on as decoded text.
    File,
}

/// One entry of a JSON export as import reads it: its `raw` line and `first_seen_at`
/// (feeds.md §4: everything else is derived again from the line).
pub struct ExportEntry<'a> {
    pub raw: &'a str,
    pub first_seen_at: Option<&'a str>,
}

/// Reads an import body as it streams: a JSON export (first key `picket_feed_export`; `feed`
/// before `entries`, else `422`) hands its settings to `on_feed` and each entry to `on_entry`;
/// `{"file": …}` hands the decoded text to `on_file`. An entry's `raw` is at most `max_line`
/// bytes and holds no line break.
pub fn parse_import<R: Read>(
    r: R,
    max_line: usize,
    on_feed: &mut dyn FnMut(&serde_json::Value) -> Result<(), BodyError>,
    on_entry: &mut dyn FnMut(ExportEntry<'_>) -> Result<(), BodyError>,
    on_file: &mut dyn FnMut(&[u8]) -> Result<(), BodyError>,
) -> Result<ImportBody, BodyError> {
    #[derive(PartialEq)]
    enum Kind {
        Unknown,
        Export,
        File,
    }
    let mut p = Bytes::new(r);
    let mut kind = Kind::Unknown;
    let mut first = true;
    let mut feed: Option<serde_json::Value> = None;
    let mut entries_seen = false;
    let mut n = 0u64;
    p.object(|p, k| {
        let was_first = std::mem::replace(&mut first, false);
        match (k, &kind) {
            ("picket_feed_export", Kind::Unknown) if was_first => {
                kind = Kind::Export;
                p.skip_ws()?;
                p.skip_value(0)
            }
            ("file", Kind::Unknown) => {
                kind = Kind::File;
                p.expect(b'"')?;
                p.string(on_file)
            }
            ("feed", Kind::Export) => {
                if feed.is_some() {
                    return Err(BodyError::Syntax("feed appears twice".into()));
                }
                let mut budget = 4096u32;
                let v = small_value(p, 0, &mut budget)?;
                if !v.is_object() {
                    return Err(BodyError::Invalid("an export's feed is an object".into()));
                }
                on_feed(&v)?;
                feed = Some(v);
                Ok(())
            }
            ("entries", Kind::Export) => {
                if feed.is_none() {
                    return Err(BodyError::Invalid(
                        "an export's entries come after its feed".into(),
                    ));
                }
                if entries_seen {
                    return Err(BodyError::Syntax("entries appears twice".into()));
                }
                entries_seen = true;
                p.expect(b'[')?;
                p.skip_ws()?;
                if p.peek()? == Some(b']') {
                    p.peeked = None;
                    return Ok(());
                }
                loop {
                    p.expect(b'{')?;
                    let mut raw: Option<Vec<u8>> = None;
                    let mut fs: Option<Vec<u8>> = None;
                    p.skip_ws()?;
                    if p.peek()? == Some(b'}') {
                        p.peeked = None;
                    } else {
                        loop {
                            let key = p.key()?;
                            p.expect(b':')?;
                            match key.as_str() {
                                "raw" => {
                                    p.expect(b'"')?;
                                    let mut v = Vec::new();
                                    p.string(&mut |b| {
                                        if b.contains(&b'\n') || b.contains(&b'\r') {
                                            return Err(BodyError::Invalid(
                                                "an entry's raw line holds a line break".into(),
                                            ));
                                        }
                                        if v.len() + b.len() > max_line {
                                            return Err(BodyError::TooLarge);
                                        }
                                        v.extend_from_slice(b);
                                        Ok(())
                                    })?;
                                    raw = Some(v);
                                }
                                "first_seen_at" => {
                                    p.skip_ws()?;
                                    if p.peek()? == Some(b'"') {
                                        p.peeked = None;
                                        let mut v = Vec::new();
                                        p.string(&mut |b| {
                                            if v.len() + b.len() > 64 {
                                                return Err(BodyError::Invalid(
                                                    "an entry's first_seen_at is too long".into(),
                                                ));
                                            }
                                            v.extend_from_slice(b);
                                            Ok(())
                                        })?;
                                        fs = Some(v);
                                    } else {
                                        p.skip_value(0)?;
                                    }
                                }
                                _ => p.skip_value(0)?,
                            }
                            p.skip_ws()?;
                            match p.must()? {
                                b',' => continue,
                                b'}' => break,
                                _ => return Err(BodyError::Syntax("expected , or } in an entry".into())),
                            }
                        }
                    }
                    let Some(raw) = raw else {
                        return Err(BodyError::Invalid("an export entry has no raw line".into()));
                    };
                    let raw = String::from_utf8_lossy(&raw);
                    let fs = fs.map(|f| String::from_utf8_lossy(&f).into_owned());
                    if let Some(f) = &fs
                        && !first_seen_ok(f)
                    {
                        // It goes into a `picket-first-seen` directive line (README §2 untrusted
                        // input: a line break would add a rule).
                        return Err(BodyError::Invalid(
                            "an entry's first_seen_at isn't an RFC 3339 date or date-time (or none)".into(),
                        ));
                    }
                    on_entry(ExportEntry {
                        raw: &raw,
                        first_seen_at: fs.as_deref(),
                    })?;
                    n += 1;
                    p.skip_ws()?;
                    match p.must()? {
                        b',' => continue,
                        b']' => return Ok(()),
                        _ => return Err(BodyError::Syntax("expected , or ] in entries".into())),
                    }
                }
            }
            (_, Kind::Unknown) if was_first => Err(BodyError::Invalid(
                "an import body is a JSON export (first key picket_feed_export) or {\"file\": …}".into(),
            )),
            _ => p.skip_value(0),
        }
    })?;
    match kind {
        Kind::Export => Ok(ImportBody::Export {
            feed: feed.ok_or_else(|| BodyError::Invalid("the export has no feed".into()))?,
            entries: n,
        }),
        Kind::File => Ok(ImportBody::File),
        Kind::Unknown => Err(BodyError::Invalid("the import body is empty".into())),
    }
}

/// True when an imported `first_seen_at` is what a `picket-first-seen` directive takes
/// (feeds.md §4): an RFC 3339 date or date-time, or `none`, with nothing around it.
pub fn first_seen_ok(v: &str) -> bool {
    v.eq_ignore_ascii_case("none")
        || (v.trim() == v
            && !v.chars().any(char::is_control)
            && picket_rules::formats::parse_rfc3339(v).is_some())
}

/// A reader that fails with `FileTooLarge` past `max` bytes (the decompressed body cap).
pub struct Capped<R> {
    inner: R,
    left: u64,
}

impl<R> Capped<R> {
    pub fn new(inner: R, max: u64) -> Self {
        Self { inner, left: max }
    }
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            // One more byte would pass the cap: probe for it.
            let mut b = [0u8; 1];
            return match self.inner.read(&mut b)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "the body is too large",
                )),
            };
        }
        let want = buf.len().min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        self.left -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn save(body: &str) -> Result<(SaveBody, Vec<u8>), BodyError> {
        let mut out = Vec::new();
        let r = parse_save(body.as_bytes(), &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        })?;
        Ok((r, out))
    }

    #[test]
    fn save_bodies() {
        let (b, c) = save(r#"{"base_version": "abcd", "content": "||a.example^\né😀\"x\"\\"}"#).unwrap();
        assert_eq!(b.base_version.as_deref(), Some("abcd"));
        assert_eq!(String::from_utf8(c).unwrap(), "||a.example^\né😀\"x\"\\");
        let (b, c) = save(
            r#" { "content" : "" , "base_version" : null , "extra": {"a": [1, 2.5e3, true, null, "s"]} } "#,
        )
        .unwrap();
        assert_eq!(b.base_version, None);
        assert!(c.is_empty());
        for bad in [
            "",
            "[]",
            r#"{"content": "x"}"#,
            r#"{"base_version": null}"#,
            r#"{"content": 1, "base_version": null}"#,
            r#"{"content": "a", "content": "b", "base_version": null}"#,
            r#"{"content": "\ud800", "base_version": null}"#,
            r#"{"content": "\x", "base_version": null}"#,
            "{\"content\": \"a\nb\", \"base_version\": null}",
            r#"{"content": "a", "base_version": null} trailing"#,
            r#"{"content": "a", "base_version": null"#,
            r#"{"content": "a", "base_version": 5}"#,
        ] {
            assert!(save(bad).is_err(), "{bad:?}");
        }
        let deep = format!(
            r#"{{"x": {}1{}, "content": "", "base_version": null}}"#,
            "[".repeat(100),
            "]".repeat(100)
        );
        assert!(save(&deep).is_err());
    }

    #[test]
    fn line_bodies() {
        let mut got = Vec::new();
        let n = parse_lines(
            br#"{"lines": ["||a.example^", "@@||b.example^", "! picket-first-seen: 2024-01-01"]}"#.as_slice(),
            1024,
            &mut |l| {
                got.push(String::from_utf8(l.to_vec()).unwrap());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(n, 3);
        assert_eq!(got[1], "@@||b.example^");
        assert!(matches!(
            parse_lines(br#"{"lines": ["a\nb"]}"#.as_slice(), 1024, &mut |_| Ok(())),
            Err(BodyError::Invalid(_))
        ));
        assert!(matches!(
            parse_lines(br#"{"lines": ["a\rb"]}"#.as_slice(), 1024, &mut |_| Ok(())),
            Err(BodyError::Invalid(_))
        ));
        assert!(matches!(
            parse_lines(br#"{"lines": ["aaaa"]}"#.as_slice(), 2, &mut |_| Ok(())),
            Err(BodyError::TooLarge)
        ));
        assert!(parse_lines(br#"{"lines": []}"#.as_slice(), 2, &mut |_| Ok(())).unwrap() == 0);
        assert!(parse_lines(br#"{}"#.as_slice(), 2, &mut |_| Ok(())).is_err());
    }

    #[test]
    fn import_bodies() {
        let mut feed = None;
        let mut entries: Vec<(String, Option<String>)> = Vec::new();
        let mut file = Vec::new();
        let body = br#"{"picket_feed_export": 1, "exported_at": "x", "feed": {"id": "f", "format": "adblock", "warn_on": ["a"]},
            "entries": [{"raw": "||a.example^", "rule_type": "dns", "first_seen_at": "2021-06-01T00:00:00Z"}, {"raw": "||b.example^", "first_seen_at": null}]}"#;
        let k = parse_import(
            &body[..],
            4096,
            &mut |f| {
                feed = Some(f.clone());
                Ok(())
            },
            &mut |e| {
                entries.push((e.raw.to_string(), e.first_seen_at.map(str::to_string)));
                Ok(())
            },
            &mut |b| {
                file.extend_from_slice(b);
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(k, ImportBody::Export { entries: 2, .. }));
        assert_eq!(feed.unwrap()["format"], "adblock");
        assert_eq!(
            entries[0],
            ("||a.example^".into(), Some("2021-06-01T00:00:00Z".into()))
        );
        assert_eq!(entries[1].1, None);
        let mut ok = |_: &serde_json::Value| Ok(());
        let mut ent = |_: ExportEntry<'_>| Ok(());
        let k = parse_import(&br#"{"file": "a\nb\n"}"#[..], 4096, &mut ok, &mut ent, &mut |b| {
            file.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(k, ImportBody::File);
        assert_eq!(
            file,
            b"a
b
"
        );
        // entries before feed, another first key, a line break in raw: refused.
        for bad in [
            &br#"{"picket_feed_export": 1, "entries": [], "feed": {}}"#[..],
            &br#"{"x": 1, "picket_feed_export": 1}"#[..],
            &br#"{"picket_feed_export": 1, "feed": {}, "entries": [{"raw": "a\nb"}]}"#[..],
            &br#"{"picket_feed_export": 1, "feed": {}, "entries": [{"first_seen_at": "x"}]}"#[..],
            // A first_seen_at that isn't a date: it would add a line to the file it makes.
            &br#"{"picket_feed_export": 1, "feed": {}, "entries": [{"raw": "||a.example^", "first_seen_at": "2021-01-01\n||x.example^"}]}"#[..],
            &br#"{"picket_feed_export": 1, "feed": {}, "entries": [{"raw": "||a.example^", "first_seen_at": "2021-01-01\r"}]}"#[..],
            &br#"{"picket_feed_export": 1, "feed": {}, "entries": [{"raw": "||a.example^", "first_seen_at": "yesterday"}]}"#[..],
            &br#"{"picket_feed_export": 1, "feed": {}, "entries": [{"raw": "||a.example^", "first_seen_at": " 2021-01-01"}]}"#[..],
        ] {
            let mut ok = |_: &serde_json::Value| Ok(());
            let mut ent = |_: ExportEntry<'_>| Ok(());
            let mut fl = |_: &[u8]| Ok(());
            assert!(
                matches!(
                    parse_import(bad, 4096, &mut ok, &mut ent, &mut fl),
                    Err(BodyError::Invalid(_))
                ),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// feeds.md §4: a directive's value is an RFC 3339 date or date-time, or `none`.
    #[test]
    fn first_seen_values() {
        for ok in [
            "2021-06-01",
            "2023-02-14T09:30:00Z",
            "2023-02-14T09:30:00+02:00",
            "none",
            "NONE",
        ] {
            assert!(first_seen_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "x",
            "2021-01-01\n||x.example^",
            "2021-01-01 ",
            "2021-13-01",
            "2021-01-01\u{2028}",
        ] {
            assert!(!first_seen_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn capped_reader() {
        let mut out = Vec::new();
        assert!(Capped::new(&b"12345"[..], 5).read_to_end(&mut out).is_ok());
        let mut out = Vec::new();
        let e = Capped::new(&b"123456"[..], 5).read_to_end(&mut out).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::FileTooLarge);
    }
}
