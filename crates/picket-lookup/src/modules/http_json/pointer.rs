//! JSON Pointer (RFC 6901), parsed once from the config and evaluated on each answer.

use std::fmt;

use serde_json::Value;

/// The longest pointer text accepted.
pub const MAX_POINTER: usize = 512;
/// The most reference tokens.
pub const MAX_TOKENS: usize = 32;

/// A parsed pointer: `""` is the whole document; otherwise `/`-separated tokens with `~1` → `/`
/// and `~0` → `~`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonPointer {
    text: String,
    tokens: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PointerError {
    #[error("a JSON Pointer is empty or starts with '/'")]
    NoLeadingSlash,
    #[error("'~' must be followed by '0' or '1'")]
    BadEscape,
    #[error("pointer over {MAX_POINTER} bytes or {MAX_TOKENS} tokens")]
    TooLong,
}

impl JsonPointer {
    pub fn parse(text: &str) -> Result<Self, PointerError> {
        if text.len() > MAX_POINTER {
            return Err(PointerError::TooLong);
        }
        if text.is_empty() {
            return Ok(Self {
                text: String::new(),
                tokens: Vec::new(),
            });
        }
        let Some(rest) = text.strip_prefix('/') else {
            return Err(PointerError::NoLeadingSlash);
        };
        let mut tokens = Vec::new();
        for raw in rest.split('/') {
            if tokens.len() >= MAX_TOKENS {
                return Err(PointerError::TooLong);
            }
            let mut tok = String::with_capacity(raw.len());
            let mut chars = raw.chars();
            while let Some(c) = chars.next() {
                if c == '~' {
                    match chars.next() {
                        Some('0') => tok.push('~'),
                        Some('1') => tok.push('/'),
                        _ => return Err(PointerError::BadEscape),
                    }
                } else {
                    tok.push(c);
                }
            }
            tokens.push(tok);
        }
        Ok(Self {
            text: text.to_owned(),
            tokens,
        })
    }

    /// The value the pointer names, if any. An array index is `0` or digits without a leading
    /// zero; `-` (past the end) names nothing.
    pub fn resolve<'a>(&self, doc: &'a Value) -> Option<&'a Value> {
        let mut cur = doc;
        for tok in &self.tokens {
            cur = match cur {
                Value::Object(m) => m.get(tok)?,
                Value::Array(a) => a.get(array_index(tok)?)?,
                _ => return None,
            };
        }
        Some(cur)
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn array_index(tok: &str) -> Option<usize> {
    let b = tok.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    tok.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// RFC 6901 §5's examples.
    #[test]
    fn rfc6901_examples() {
        let doc = json!({
            "foo": ["bar", "baz"], "": 0, "a/b": 1, "c%d": 2, "e^f": 3, "g|h": 4,
            "i\\j": 5, "k\"l": 6, " ": 7, "m~n": 8
        });
        let get = |p: &str| JsonPointer::parse(p).unwrap().resolve(&doc).cloned();
        assert_eq!(get(""), Some(doc.clone()));
        assert_eq!(get("/foo"), Some(json!(["bar", "baz"])));
        assert_eq!(get("/foo/0"), Some(json!("bar")));
        assert_eq!(get("/"), Some(json!(0)));
        assert_eq!(get("/a~1b"), Some(json!(1)));
        assert_eq!(get("/c%d"), Some(json!(2)));
        assert_eq!(get("/e^f"), Some(json!(3)));
        assert_eq!(get("/g|h"), Some(json!(4)));
        assert_eq!(get("/i\\j"), Some(json!(5)));
        assert_eq!(get("/k\"l"), Some(json!(6)));
        assert_eq!(get("/ "), Some(json!(7)));
        assert_eq!(get("/m~0n"), Some(json!(8)));
    }

    #[test]
    fn misses_and_errors() {
        let doc = json!({"a": [1, 2], "n": null});
        let get = |p: &str| JsonPointer::parse(p).unwrap().resolve(&doc).cloned();
        assert_eq!(get("/a/2"), None);
        assert_eq!(get("/a/01"), None);
        assert_eq!(get("/a/+1"), None);
        assert_eq!(get("/a/-"), None);
        assert_eq!(get("/a/0/x"), None);
        assert_eq!(get("/missing"), None);
        assert_eq!(get("/n"), Some(Value::Null));
        assert_eq!(JsonPointer::parse("a"), Err(PointerError::NoLeadingSlash));
        assert_eq!(JsonPointer::parse("/a~2"), Err(PointerError::BadEscape));
        assert_eq!(JsonPointer::parse("/a~"), Err(PointerError::BadEscape));
        assert_eq!(JsonPointer::parse(&"/a".repeat(40)), Err(PointerError::TooLong));
    }
}
