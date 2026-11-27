//! What core reads from a MISP warninglist `list.json` beside picket-rules' parser (feeds.md §4):
//! the list's `type`, its `list` values, and the `picket_first_seen` map of value → date. A
//! small pull reader over the bytes, bounded like the rule parser: strings of at most
//! [`MAX_STRING`] bytes, nesting of at most [`MAX_DEPTH`], one pass per question, never the
//! whole document in memory. A malformed document is an `InvalidData` error.

use std::io::{self, BufRead};

/// The longest string read (a `list` value, a date, a key).
pub const MAX_STRING: usize = 64 * 1024;
/// The deepest nesting skipped.
pub const MAX_DEPTH: u32 = 64;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// A byte reader with one byte of lookahead.
struct J<R> {
    r: R,
    peeked: Option<u8>,
}

impl<R: BufRead> J<R> {
    fn new(r: R) -> Self {
        Self { r, peeked: None }
    }

    fn peek(&mut self) -> io::Result<Option<u8>> {
        if self.peeked.is_none() {
            let mut b = [0u8; 1];
            match self.r.read(&mut b)? {
                0 => return Ok(None),
                _ => self.peeked = Some(b[0]),
            }
        }
        Ok(self.peeked)
    }

    fn next(&mut self) -> io::Result<Option<u8>> {
        let b = self.peek()?;
        self.peeked = None;
        Ok(b)
    }

    fn ws(&mut self) -> io::Result<()> {
        while let Some(b) = self.peek()? {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.peeked = None;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn expect(&mut self, c: u8) -> io::Result<()> {
        self.ws()?;
        match self.next()? {
            Some(b) if b == c => Ok(()),
            _ => Err(bad("unexpected character")),
        }
    }

    /// A string (the opening quote next), unescaped, at most [`MAX_STRING`] bytes.
    fn string(&mut self) -> io::Result<String> {
        self.ws()?;
        if self.next()? != Some(b'"') {
            return Err(bad("expected a string"));
        }
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = self.next()?.ok_or_else(|| bad("a string is cut short"))?;
            match b {
                b'"' => break,
                b'\\' => {
                    let e = self.next()?.ok_or_else(|| bad("a string is cut short"))?;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            let c = if (0xD800..0xDC00).contains(&cp) {
                                if self.next()? != Some(b'\\') || self.next()? != Some(b'u') {
                                    return Err(bad("a lone surrogate"));
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(bad("a lone surrogate"));
                                }
                                char::from_u32(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00))
                            } else {
                                char::from_u32(cp)
                            }
                            .ok_or_else(|| bad("a bad \\u escape"))?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(bad("a bad escape")),
                    }
                }
                c if c < 0x20 => return Err(bad("a control character in a string")),
                c => out.push(c),
            }
            if out.len() > MAX_STRING {
                return Err(bad("a string is too long"));
            }
        }
        String::from_utf8(out).map_err(|_| bad("a string isn't UTF-8"))
    }

    fn hex4(&mut self) -> io::Result<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.next()?.ok_or_else(|| bad("a \\u escape is cut short"))?;
            let d = (b as char).to_digit(16).ok_or_else(|| bad("a bad \\u escape"))?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    /// Skips one value of any kind.
    fn skip(&mut self, depth: u32) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(bad("nested too deeply"));
        }
        self.ws()?;
        match self.peek()? {
            Some(b'"') => {
                self.string()?;
            }
            Some(b'{') => {
                self.peeked = None;
                self.ws()?;
                if self.peek()? == Some(b'}') {
                    self.peeked = None;
                    return Ok(());
                }
                loop {
                    self.string()?;
                    self.expect(b':')?;
                    self.skip(depth + 1)?;
                    self.ws()?;
                    match self.next()? {
                        Some(b',') => continue,
                        Some(b'}') => break,
                        _ => return Err(bad("expected ',' or '}'")),
                    }
                }
            }
            Some(b'[') => {
                self.peeked = None;
                self.ws()?;
                if self.peek()? == Some(b']') {
                    self.peeked = None;
                    return Ok(());
                }
                loop {
                    self.skip(depth + 1)?;
                    self.ws()?;
                    match self.next()? {
                        Some(b',') => continue,
                        Some(b']') => break,
                        _ => return Err(bad("expected ',' or ']'")),
                    }
                }
            }
            Some(b) if b == b'-' || b.is_ascii_digit() || b.is_ascii_alphabetic() => {
                // A number or a literal: its characters, bounded.
                let mut n = 0usize;
                while let Some(c) = self.peek()? {
                    if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'+' | b'.') {
                        self.peeked = None;
                        n += 1;
                        if n > 64 {
                            return Err(bad("a number is too long"));
                        }
                    } else {
                        break;
                    }
                }
            }
            _ => return Err(bad("expected a value")),
        }
        Ok(())
    }

    /// A small value read whole: at most `budget` items, strings bounded as above.
    fn value(&mut self, depth: u32, budget: &mut u32) -> io::Result<serde_json::Value> {
        use serde_json::Value;
        if depth > MAX_DEPTH {
            return Err(bad("nested too deeply"));
        }
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| bad("the value is too large"))?;
        self.ws()?;
        match self.peek()? {
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'{') => {
                self.peeked = None;
                let mut m = serde_json::Map::new();
                self.ws()?;
                if self.peek()? == Some(b'}') {
                    self.peeked = None;
                    return Ok(Value::Object(m));
                }
                loop {
                    let k = self.string()?;
                    self.expect(b':')?;
                    let v = self.value(depth + 1, budget)?;
                    m.insert(k, v);
                    self.ws()?;
                    match self.next()? {
                        Some(b',') => continue,
                        Some(b'}') => return Ok(Value::Object(m)),
                        _ => return Err(bad("expected ',' or '}'")),
                    }
                }
            }
            Some(b'[') => {
                self.peeked = None;
                let mut a = Vec::new();
                self.ws()?;
                if self.peek()? == Some(b']') {
                    self.peeked = None;
                    return Ok(Value::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1, budget)?);
                    self.ws()?;
                    match self.next()? {
                        Some(b',') => continue,
                        Some(b']') => return Ok(Value::Array(a)),
                        _ => return Err(bad("expected ',' or ']'")),
                    }
                }
            }
            Some(_) => {
                let mut t = Vec::new();
                while let Some(c) = self.peek()? {
                    if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'+' | b'.') {
                        self.peeked = None;
                        t.push(c);
                        if t.len() > 64 {
                            return Err(bad("a literal is too long"));
                        }
                    } else {
                        break;
                    }
                }
                serde_json::from_slice(&t).map_err(|_| bad("a bad literal"))
            }
            None => Err(bad("expected a value")),
        }
    }

    /// Walks the top-level object, handing each key to `f`, which reads or skips its value.
    fn object(&mut self, mut f: impl FnMut(&mut Self, &str) -> io::Result<()>) -> io::Result<()> {
        self.expect(b'{')?;
        self.ws()?;
        if self.peek()? == Some(b'}') {
            self.peeked = None;
        } else {
            loop {
                let k = self.string()?;
                self.expect(b':')?;
                f(self, &k)?;
                self.ws()?;
                match self.next()? {
                    Some(b',') => continue,
                    Some(b'}') => break,
                    _ => return Err(bad("expected ',' or '}'")),
                }
            }
        }
        self.ws()?;
        if self.peek()?.is_some() {
            return Err(bad("data after the top-level object"));
        }
        Ok(())
    }
}

/// The list's `type` (`None` without a string `type`).
pub fn list_type<R: BufRead>(r: R) -> io::Result<Option<String>> {
    let mut j = J::new(r);
    let mut out = None;
    j.object(|j, k| {
        j.ws()?;
        if k == "type" && j.peek()? == Some(b'"') {
            out = Some(j.string()?);
            Ok(())
        } else {
            j.skip(1)
        }
    })?;
    Ok(out)
}

/// Each string of `list`, in order (non-strings are skipped), and the `type`.
pub fn values<R: BufRead>(r: R, mut f: impl FnMut(String) -> io::Result<()>) -> io::Result<Option<String>> {
    let mut j = J::new(r);
    let mut ty = None;
    j.object(|j, k| {
        j.ws()?;
        match k {
            "type" if j.peek()? == Some(b'"') => {
                ty = Some(j.string()?);
                Ok(())
            }
            "list" if j.peek()? == Some(b'[') => {
                j.next()?;
                j.ws()?;
                if j.peek()? == Some(b']') {
                    j.next()?;
                    return Ok(());
                }
                loop {
                    j.ws()?;
                    if j.peek()? == Some(b'"') {
                        f(j.string()?)?;
                    } else {
                        j.skip(2)?;
                    }
                    j.ws()?;
                    match j.next()? {
                        Some(b',') => continue,
                        Some(b']') => break,
                        _ => return Err(bad("expected ',' or ']'")),
                    }
                }
                Ok(())
            }
            _ => j.skip(1),
        }
    })?;
    Ok(ty)
}

/// Each entry of the top-level `picket_first_seen` object: (value, date text). A non-string date
/// is handed on as an empty text (a date that can't be parsed).
pub fn first_seen<R: BufRead>(r: R, mut f: impl FnMut(String, String) -> io::Result<()>) -> io::Result<()> {
    let mut j = J::new(r);
    j.object(|j, k| {
        j.ws()?;
        if k != "picket_first_seen" || j.peek()? != Some(b'{') {
            return j.skip(1);
        }
        j.next()?;
        j.ws()?;
        if j.peek()? == Some(b'}') {
            j.next()?;
            return Ok(());
        }
        loop {
            let key = j.string()?;
            j.expect(b':')?;
            j.ws()?;
            let date = if j.peek()? == Some(b'"') {
                j.string()?
            } else {
                j.skip(2)?;
                String::new()
            };
            f(key, date)?;
            j.ws()?;
            match j.next()? {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(bad("expected ',' or '}'")),
            }
        }
        Ok(())
    })
}

/// A MISP export's `picket_feed` object (the feed's settings, feeds.md §4), if it has one.
pub fn picket_feed<R: BufRead>(r: R) -> io::Result<Option<serde_json::Value>> {
    let mut j = J::new(r);
    let mut out = None;
    j.object(|j, k| {
        j.ws()?;
        if k == "picket_feed" && j.peek()? == Some(b'{') {
            let mut budget = 4096;
            out = Some(j.value(1, &mut budget)?);
            Ok(())
        } else {
            j.skip(1)
        }
    })?;
    Ok(out)
}

/// Opens a file for one of the readers above.
pub fn open(path: &std::path::Path) -> io::Result<io::BufReader<std::fs::File>> {
    Ok(io::BufReader::with_capacity(
        64 * 1024,
        std::fs::File::open(path)?,
    ))
}

/// A JSON string literal of `s` (for writing MISP lists).
pub fn quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{"description": "x", "list": ["a.example", "b.example", 3, "cé.example"],
        "name": "n", "picket_first_seen": {"a.example": "2021-06-01", "zzz": "2022-01-01", "b.example": 7},
        "type": "hostname", "nested": {"x": [1, {"y": null}]}}"#;

    #[test]
    fn reads_type_values_and_dates() {
        assert_eq!(list_type(DOC.as_bytes()).unwrap().as_deref(), Some("hostname"));
        let mut vs = Vec::new();
        let ty = values(DOC.as_bytes(), |v| {
            vs.push(v);
            Ok(())
        })
        .unwrap();
        assert_eq!(ty.as_deref(), Some("hostname"));
        assert_eq!(vs, vec!["a.example", "b.example", "cé.example"]);
        let mut ds = Vec::new();
        first_seen(DOC.as_bytes(), |k, d| {
            ds.push((k, d));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            ds,
            vec![
                ("a.example".to_string(), "2021-06-01".to_string()),
                ("zzz".to_string(), "2022-01-01".to_string()),
                ("b.example".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn refuses_bad_documents() {
        for d in [
            "",
            "[]",
            "{",
            r#"{"a": }"#,
            r#"{"a": "x"} trailing"#,
            r#"{"a": "\ud800"}"#,
        ] {
            assert!(list_type(d.as_bytes()).is_err(), "{d:?}");
        }
        let deep = format!("{{\"a\": {}{}}}", "[".repeat(100), "]".repeat(100));
        assert!(list_type(deep.as_bytes()).is_err());
        let long = format!("{{\"a\": \"{}\"}}", "x".repeat(MAX_STRING + 1));
        assert!(list_type(long.as_bytes()).is_err());
        assert_eq!(list_type(r#"{"list": []}"#.as_bytes()).unwrap(), None);
        let pf = picket_feed(
            r#"{"list": [], "picket_feed": {"id": "x", "warn_on": ["a"], "n": 1.5, "b": true}}"#.as_bytes(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(pf["id"], "x");
        assert_eq!(pf["warn_on"][0], "a");
        assert!(picket_feed(DOC.as_bytes()).unwrap().is_none());
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
    }
}
