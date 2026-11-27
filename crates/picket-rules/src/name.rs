//! Names (rules.md §1, §3).
//!
//! Two kinds of names meet here:
//! - **Rule-text names** (host rules, hosts lines, `plain` names, the `d` of `||d^`): normalised by
//!   [`RuleName::parse`]: ASCII lowercase, one trailing dot stripped, IDN → A-labels (UTS #46 via
//!   `idna`), rejected when longer than 253 bytes or with an empty label. Picket keeps only labels of
//!   `a-z`, `0-9`, `-` and `_` as keys; anything else stays an AdGuard pattern.
//! - **Query and response-target names**: wire labels, only ASCII-lowercased and never rejected
//!   (rules.md §3 "Names with unusual bytes"). Every matching API takes them as `&[&[u8]]`, most
//!   specific label first, so a `.` byte inside a label is never a boundary.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Longest name in rule text, in bytes of its dotted form (rules.md §1).
pub const MAX_NAME_LEN: usize = 253;
/// Longest label (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

/// Why a rule-text name was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("empty name")]
    Empty,
    #[error("name longer than 253 bytes")]
    TooLong,
    #[error("empty label")]
    EmptyLabel,
    #[error("label longer than 63 bytes")]
    LabelTooLong,
    #[error("byte {0:#04x} is not allowed in a rule name")]
    BadByte(u8),
    #[error("IDN mapping failed")]
    Idna,
}

/// A normalised rule-text name (rules.md §1), stored left to right (`ads.example.org`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RuleName(String);

impl RuleName {
    /// Normalises rule text into a name: ASCII lowercase, one trailing dot stripped, IDN labels
    /// mapped to A-labels by UTS #46, then checked: 1..=253 bytes, labels of 1..=63 bytes holding
    /// only `a-z0-9-_`.
    pub fn parse(text: &str) -> Result<RuleName, NameError> {
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        let ascii = if text.is_ascii() {
            text.to_ascii_lowercase()
        } else {
            idna::domain_to_ascii(text).map_err(|_| NameError::Idna)?
        };
        check_rule_name(&ascii)?;
        Ok(RuleName(ascii))
    }

    /// Rebuilds a name from its reversed form (`org.example.ads`), as stored in `feed_entries.key`.
    pub fn from_reversed(reversed: &str) -> Result<RuleName, NameError> {
        let forward = reverse_dotted(reversed);
        check_rule_name(&forward)?;
        Ok(RuleName(forward))
    }

    /// The dotted name, left to right.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Labels left to right.
    pub fn labels(&self) -> impl DoubleEndedIterator<Item = &str> + Clone {
        self.0.split('.')
    }

    /// Number of labels.
    pub fn label_count(&self) -> usize {
        self.0.split('.').count()
    }

    /// The reversed form used as a key (`org.example.ads`, bundles.md §4).
    pub fn reversed(&self) -> String {
        reverse_dotted(&self.0)
    }

    /// True when this name equals `other` or is a subdomain of it, by whole labels.
    pub fn is_within(&self, other: &RuleName) -> bool {
        let a = self.0.as_bytes();
        let b = other.0.as_bytes();
        if a == b {
            return true;
        }
        a.len() > b.len()
            && a.ends_with(b)
            && a.len()
                .checked_sub(b.len())
                .and_then(|i| i.checked_sub(1))
                .and_then(|i| a.get(i))
                == Some(&b'.')
    }
}

impl fmt::Debug for RuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RuleName({})", self.0)
    }
}

impl fmt::Display for RuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for RuleName {
    type Error = NameError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        RuleName::parse(&s)
    }
}

impl From<RuleName> for String {
    fn from(n: RuleName) -> String {
        n.0
    }
}

/// Checks an ASCII-lowercase dotted name against the rule-name rules.
fn check_rule_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(NameError::LabelTooLong);
        }
        if let Some(&b) = label.as_bytes().iter().find(|&&b| !is_key_byte(b)) {
            return Err(NameError::BadByte(b));
        }
    }
    Ok(())
}

/// Bytes a key label may hold: the "ordinary" bytes of rules.md §3.
pub fn is_key_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
}

/// Reverses the labels of a dotted string (`ads.example.org` ↔ `org.example.ads`).
pub fn reverse_dotted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, label) in s.rsplit('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(label);
    }
    out
}

/// AdGuard's host-name check for host rules (urlfilter `ufnet.IsDomainName`, rules.md §3): labels
/// of letters, digits and inner hyphens, 1..=63 bytes; `xn--` labels at least 8 bytes; the last
/// label at least 2 bytes, starting and ending with a letter; at most 253 bytes in all.
pub fn is_adguard_host_name(name: &str) -> bool {
    if name.len() > MAX_NAME_LEN {
        return false;
    }
    let mut labels = name.split('.').peekable();
    while let Some(label) = labels.next() {
        if !adguard_label_ok(label) {
            return false;
        }
        if labels.peek().is_none() {
            let b = label.as_bytes();
            let first_ok = b.first().is_some_and(u8::is_ascii_alphabetic);
            let last_ok = b.last().is_some_and(u8::is_ascii_alphabetic);
            return b.len() >= 2 && first_ok && last_ok;
        }
    }
    false
}

fn adguard_label_ok(label: &str) -> bool {
    let b = label.as_bytes();
    if b.is_empty() || b.len() > MAX_LABEL_LEN {
        return false;
    }
    if label.starts_with("xn--") && b.len() < 8 {
        return false;
    }
    let last = b.len().saturating_sub(1);
    b.iter()
        .enumerate()
        .all(|(i, &c)| c.is_ascii_alphanumeric() || (c == b'-' && i != 0 && i != last))
}

/// golibs `netutil.ValidateHostname` as urlfilter uses it for `$dnsrewrite` targets: after IDNA
/// (Punycode only), 1..=253 bytes, labels of letters and digits with inner hyphens, the last label
/// not all digits. An ASCII name comes back as written: urlfilter keeps the value's case, compares
/// it case-sensitively (`@@…$dnsrewrite=` and AdGuard Home's CNAME-to-itself check) and answers
/// with it. A non-ASCII name comes back as its A-label form (rules.md §1).
pub fn validate_rewrite_host(name: &str) -> Option<String> {
    let ascii = if name.is_ascii() {
        name.to_string()
    } else {
        idna::domain_to_ascii(name).ok()?
    };
    if ascii.is_empty() || ascii.len() > MAX_NAME_LEN {
        return None;
    }
    let mut last = "";
    for label in ascii.split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > MAX_LABEL_LEN {
            return None;
        }
        let end = b.len().saturating_sub(1);
        let ok = b
            .iter()
            .enumerate()
            .all(|(i, &c)| c.is_ascii_alphanumeric() || (c == b'-' && i != 0 && i != end));
        if !ok {
            return None;
        }
        last = label;
    }
    if last.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(ascii)
}

/// A query or response-target name held as owned wire labels (most specific first), for callers
/// that don't already have a label slice. Labels keep every byte; matching lowercases ASCII.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct OwnedName {
    labels: Vec<Vec<u8>>,
}

impl OwnedName {
    /// Builds a name from wire labels.
    pub fn from_labels(labels: Vec<Vec<u8>>) -> OwnedName {
        OwnedName { labels }
    }

    /// Splits ordinary dotted text at every `.` (one trailing dot ignored). Only for names
    /// without `.` bytes inside labels; use [`OwnedName::from_log_text`] for escaped text.
    pub fn from_dotted(text: &str) -> OwnedName {
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() {
            return OwnedName::default();
        }
        OwnedName {
            labels: text.split('.').map(|l| l.as_bytes().to_vec()).collect(),
        }
    }

    /// Decodes the log-text form (`picket_api::names`, `\DDD` escapes).
    pub fn from_log_text(text: &str) -> Option<OwnedName> {
        picket_api::names::decode_labels(text).map(|labels| OwnedName { labels })
    }

    /// The labels as borrowed slices, for the matching APIs.
    pub fn as_labels(&self) -> Vec<&[u8]> {
        self.labels.iter().map(Vec::as_slice).collect()
    }

    /// AdGuard Home's text form (rules.md §3).
    pub fn adguard_text(&self) -> String {
        picket_api::names::adguard_text(self.labels.iter().map(Vec::as_slice))
    }
}

/// True when `labels` (most specific first) are within `name` by whole labels: equal to it or a
/// subdomain. Labels compare ASCII-case-insensitively; a label holding a `.` byte never equals one
/// of `name`'s labels, which hold none (rules.md §3).
pub fn labels_within(labels: &[&[u8]], name: &RuleName) -> bool {
    let n = name.label_count();
    if labels.len() < n {
        return false;
    }
    let tail = labels.get(labels.len().saturating_sub(n)..).unwrap_or(&[]);
    tail.iter()
        .zip(name.labels())
        .all(|(q, r)| q.eq_ignore_ascii_case(r.as_bytes()))
}

/// AdGuard's text test "domain == d or a subdomain of d" (golibs `netutil.IsSubdomain`), used by
/// patterns' `$denyallow` (rules.md §3: patterns keep the text form).
pub fn text_within(text: &str, name: &str) -> bool {
    if text == name {
        return true;
    }
    text.len() > name.len()
        && text.ends_with(name)
        && text
            .len()
            .checked_sub(name.len())
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| text.as_bytes().get(i))
            == Some(&b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises() {
        assert_eq!(RuleName::parse("Example.COM.").unwrap().as_str(), "example.com");
        assert_eq!(
            RuleName::parse("пример.рф").unwrap().as_str(),
            "xn--e1afmkfd.xn--p1ai"
        );
        assert_eq!(
            RuleName::parse("_dmarc.Example.org").unwrap().as_str(),
            "_dmarc.example.org"
        );
        assert_eq!(RuleName::parse("a..b"), Err(NameError::EmptyLabel));
        assert_eq!(RuleName::parse(""), Err(NameError::Empty));
        assert_eq!(RuleName::parse("."), Err(NameError::Empty));
        assert!(matches!(
            RuleName::parse("a*b.com"),
            Err(NameError::BadByte(b'*'))
        ));
        let long = format!("{}.com", "a.".repeat(126));
        assert_eq!(RuleName::parse(&long), Err(NameError::TooLong));
        let label = format!("{}.com", "a".repeat(64));
        assert_eq!(RuleName::parse(&label), Err(NameError::LabelTooLong));
        // UTS #46 nontransitional: ß stays a letter of its own.
        assert_eq!(RuleName::parse("faß.de").unwrap().as_str(), "xn--fa-hia.de");
        let max = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(max.len(), 253);
        assert!(RuleName::parse(&max).is_ok());
        let n = RuleName::parse("ads.example.org").unwrap();
        assert_eq!(n.reversed(), "org.example.ads");
        assert_eq!(RuleName::from_reversed("org.example.ads").unwrap(), n);
    }

    #[test]
    fn adguard_host_check() {
        assert!(is_adguard_host_name("example.org"));
        assert!(is_adguard_host_name("a-b.example.org"));
        assert!(is_adguard_host_name("xn--e1afmkfd.xn--p1ai"));
        assert!(!is_adguard_host_name("-a.example.org"));
        assert!(!is_adguard_host_name("a-.example.org"));
        assert!(!is_adguard_host_name("example.o"));
        assert!(is_adguard_host_name("example.c0m"));
        assert!(!is_adguard_host_name("example.c0"));
        assert!(!is_adguard_host_name("1.2.3.4"));
        assert!(!is_adguard_host_name("_dmarc.example.org"));
        assert!(!is_adguard_host_name("xn--a.org"));
        assert!(is_adguard_host_name("localhost"));
        assert!(!is_adguard_host_name("example.org."));
        assert!(!is_adguard_host_name("пример.рф"));
        assert!(!is_adguard_host_name(""));
    }

    #[test]
    fn label_relations() {
        let n = RuleName::parse("evil.example").unwrap();
        let q = OwnedName::from_labels(vec![b"a!b".to_vec(), b"EVIL".to_vec(), b"example".to_vec()]);
        assert!(labels_within(&q.as_labels(), &n));
        let q = OwnedName::from_labels(vec![b"evil".to_vec(), b"example!x".to_vec()]);
        assert!(!labels_within(&q.as_labels(), &n));
        let q = OwnedName::from_labels(vec![b"x.evil".to_vec(), b"example".to_vec()]);
        assert!(!labels_within(&q.as_labels(), &n));
        assert!(text_within("a.evil.example", "evil.example"));
        assert!(!text_within("aevil.example", "evil.example"));
        assert!(
            RuleName::parse("a.b.c")
                .unwrap()
                .is_within(&RuleName::parse("b.c").unwrap())
        );
        assert!(
            !RuleName::parse("ab.c")
                .unwrap()
                .is_within(&RuleName::parse("b.c").unwrap())
        );
    }

    #[test]
    fn rewrite_hosts() {
        assert_eq!(
            validate_rewrite_host("Example.ORG").as_deref(),
            Some("Example.ORG"),
            "kept as written, as urlfilter keeps it"
        );
        assert_eq!(
            validate_rewrite_host("Пример.рф").as_deref(),
            Some("xn--e1afmkfd.xn--p1ai")
        );
        assert_eq!(validate_rewrite_host("nxdomain").as_deref(), Some("nxdomain"));
        assert!(validate_rewrite_host("example.org.").is_none());
        assert!(validate_rewrite_host("a_b.org").is_none());
        assert!(validate_rewrite_host("1.2.3.4").is_none());
    }
}
