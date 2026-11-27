//! The name label check (providers.md §4): the `LookupClient` passes a module only names whose
//! labels hold just letters, digits, hyphens and underscores; any other name is Unknown without a
//! call. Such names are also exactly the ones whose log text (api.md §5) and AdGuard text form
//! (rules.md §3) are the name itself.

use std::borrow::Cow;

/// The longest name in text form, without a trailing dot (RFC 1035 §3.1: 255 wire bytes).
pub const MAX_NAME: usize = 253;
/// The longest label.
pub const MAX_LABEL: usize = 63;

/// The name a module gets: ASCII-lowercased, without a trailing dot. `None` when a label is
/// empty, longer than 63 bytes or holds anything but letters, digits, `-` and `_`, when the name
/// is longer than 253 bytes, or when it is the root.
pub fn check_name(name: &str) -> Option<Cow<'_, str>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME {
        return None;
    }
    let mut upper = false;
    for label in name.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL {
            return None;
        }
        for b in label.bytes() {
            match b {
                b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {}
                b'A'..=b'Z' => upper = true,
                _ => return None,
            }
        }
    }
    Some(if upper {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_check() {
        assert_eq!(check_name("Ads.Example.com.").unwrap(), "ads.example.com");
        assert_eq!(check_name("a_b-c.d9").unwrap(), "a_b-c.d9");
        assert!(matches!(check_name("x.example"), Some(Cow::Borrowed(_))));
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "a b.c",
            "a!b.c",
            "é.example",
            "a\\.b.c",
            "*.example",
        ] {
            assert!(check_name(bad).is_none(), "{bad:?}");
        }
        assert!(check_name(&"a".repeat(63)).is_some());
        assert!(check_name(&"a".repeat(64)).is_none());
        let long = vec!["abcdefghi"; 26].join("."); // 26*10-1 = 259
        assert!(check_name(&long).is_none());
    }
}
