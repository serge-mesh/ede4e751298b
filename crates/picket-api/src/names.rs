//! Name text in log records (api.md §5): lowercase, and every byte outside `a-z0-9-_` inside a
//! label written as `\DDD` (three decimal digits, as in RFC 1035 master files). Labels are
//! separated by `.`; the root is the empty string.

/// Encodes wire-format labels (without length bytes) as log text.
pub fn encode_labels<'a, I>(labels: I) -> String
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut out = String::new();
    let mut first = true;
    for label in labels {
        if !first {
            out.push('.');
        }
        first = false;
        push_label(&mut out, label);
    }
    out
}

/// Appends one label's log text to `out`.
pub fn push_label(out: &mut String, label: &[u8]) {
    for &b in label {
        let b = b.to_ascii_lowercase();
        if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push('\\');
            out.push(char::from(b'0' + b / 100));
            out.push(char::from(b'0' + (b / 10) % 10));
            out.push(char::from(b'0' + b % 10));
        }
    }
}

/// Decodes log text back into labels. Returns `None` for malformed escapes, empty labels or
/// labels over 63 bytes.
pub fn decode_labels(text: &str) -> Option<Vec<Vec<u8>>> {
    if text.is_empty() || text == "." {
        return Some(Vec::new());
    }
    let text = text.strip_suffix('.').unwrap_or(text);
    let bytes = text.as_bytes();
    let mut labels = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'.' {
            if cur.is_empty() || cur.len() > 63 {
                return None;
            }
            labels.push(std::mem::take(&mut cur));
            i += 1;
        } else if b == b'\\' {
            let d = bytes.get(i + 1..i + 4)?;
            if !d.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let v = u32::from(d[0] - b'0') * 100 + u32::from(d[1] - b'0') * 10 + u32::from(d[2] - b'0');
            cur.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            cur.push(b);
            i += 1;
        }
    }
    if cur.is_empty() || cur.len() > 63 {
        return None;
    }
    labels.push(cur);
    Some(labels)
}

/// True when `label`, ASCII-lowercased, holds only `a-z`, `0-9`, `-` and `_`: a name whose
/// labels are all ordinary has no unusual bytes (rules.md §3), and its AdGuard text form is the
/// name itself.
pub fn is_ordinary_label(label: &[u8]) -> bool {
    label.iter().all(|&b| {
        let b = b.to_ascii_lowercase();
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
    })
}

/// AdGuard Home's text form of a name, which patterns match against (rules.md §3 "Names with
/// unusual bytes"): the miekg/dns presentation form, ASCII-lowercased, without the trailing dot.
/// Inside a label, `.`, space, `'`, `@`, `;`, `(`, `)`, `"` and `\` get a leading `\`, and bytes
/// outside `0x20`–`0x7E` become `\DDD`. The root is the empty string.
pub fn adguard_text<'a, I>(labels: I) -> String
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut out = String::new();
    push_adguard_text(&mut out, labels);
    out
}

/// Appends a name's AdGuard text form (see [`adguard_text`]) to `out`, so a caller can reuse
/// one buffer.
pub fn push_adguard_text<'a, I>(out: &mut String, labels: I)
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut first = true;
    for label in labels {
        if !first {
            out.push('.');
        }
        first = false;
        for &b in label {
            let b = b.to_ascii_lowercase();
            match b {
                b'.' | b' ' | b'\'' | b'@' | b';' | b'(' | b')' | b'"' | b'\\' => {
                    out.push('\\');
                    out.push(b as char);
                }
                0x20..=0x7e => out.push(b as char),
                _ => {
                    out.push('\\');
                    out.push(char::from(b'0' + b / 100));
                    out.push(char::from(b'0' + (b / 10) % 10));
                    out.push(char::from(b'0' + b % 10));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let labels: Vec<&[u8]> = vec![b"Ads", b"ex ample", b"c\\m", b"x_y-1"];
        let text = encode_labels(labels);
        assert_eq!(text, "ads.ex\\032ample.c\\092m.x_y-1");
        let back = decode_labels(&text).unwrap();
        assert_eq!(
            back,
            vec![
                b"ads".to_vec(),
                b"ex ample".to_vec(),
                b"c\\m".to_vec(),
                b"x_y-1".to_vec()
            ]
        );
        assert!(decode_labels("a..b").is_none());
        assert!(decode_labels("a\\99").is_none());
        assert!(decode_labels("a\\999").is_none());
        assert_eq!(decode_labels("").unwrap().len(), 0);
    }

    #[test]
    fn adguard_text_form() {
        let l = |s: &'static [u8]| -> &'static [u8] { s };
        assert_eq!(
            adguard_text([l(b"WWW"), l(b"Example"), l(b"org")]),
            "www.example.org"
        );
        assert_eq!(adguard_text([l(b"a!b"), l(b"example")]), "a!b.example");
        assert_eq!(adguard_text([l(b"a.b"), l(b"example")]), "a\\.b.example");
        assert_eq!(adguard_text([l(b"a b\"c"), l(b"x")]), "a\\ b\\\"c.x");
        assert_eq!(adguard_text([l(b"\x00\x7f\xe9"), l(b"x")]), "\\000\\127\\233.x");
        assert_eq!(adguard_text(std::iter::empty::<&[u8]>()), "");
        assert!(is_ordinary_label(b"Ab-_9"));
        assert!(!is_ordinary_label(b"a!b"));
        assert!(!is_ordinary_label(b"a.b"));
    }
}
