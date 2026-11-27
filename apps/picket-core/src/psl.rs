//! Registrable domains from the Public Suffix List, bundled in `data/public_suffix_list.dat`
//! (publicsuffix.org, MPL-2.0; refreshed with releases). Core never fetches it at run time, so
//! the cross-check's operator rule (core.md §8) and alert grouping (core.md §9) work offline and
//! decide the same way on every instance of a release.

use std::str::FromStr;
use std::sync::OnceLock;

use publicsuffix::{List, Psl};

const LIST_TEXT: &str = include_str!("../data/public_suffix_list.dat");

fn list() -> Option<&'static List> {
    static LIST: OnceLock<Option<List>> = OnceLock::new();
    LIST.get_or_init(|| List::from_str(LIST_TEXT).ok()).as_ref()
}

/// The bundled list read the way urlfilter reads it ([`picket_rules::psl::PublicSuffixList`]):
/// the compiler's `$denyallow` entity expansion (bundles.md §2), the reference matcher's, and the
/// public-suffix guardrail (private-section wildcards excluded there). Parsed once.
pub fn rules_list() -> &'static picket_rules::psl::PublicSuffixList {
    static LIST: OnceLock<picket_rules::psl::PublicSuffixList> = OnceLock::new();
    LIST.get_or_init(|| picket_rules::psl::PublicSuffixList::parse(LIST_TEXT))
}

/// The registrable domain of `name` (its public suffix plus one label), lowercase, without a
/// trailing dot; `None` for a name that is itself a public suffix (`co.uk`, `com`) or empty.
/// Unknown suffixes follow the list's implicit `*` rule (the last label).
pub fn registrable_domain(name: &str) -> Option<String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || n.len() > 253 {
        return None;
    }
    match list() {
        Some(l) => l
            .domain(n.as_bytes())
            .and_then(|d| std::str::from_utf8(d.as_bytes()).ok().map(str::to_string)),
        None => {
            // The bundled list always parses (a test checks it); the last two labels otherwise.
            let labels: Vec<&str> = n.split('.').collect();
            (labels.len() >= 2).then(|| labels[labels.len() - 2..].join("."))
        }
    }
}

/// Names reserved for local use that the list carries only because they sit in a delegated
/// zone: `home.arpa` (RFC 8375), the default `lanca.zones`.
const LOCAL_USE: &[&str] = &["home.arpa"];

/// True when `name` is itself a public suffix by an explicit rule of the list (`com`, `co.uk`,
/// `github.io`, `in-addr.arpa`), other than a name reserved for local use (`home.arpa`). A name
/// that is a suffix only by the implicit `*` rule (`lan`, `internal`) isn't one: nobody on the
/// internet registers under it.
pub fn is_public_suffix(name: &str) -> bool {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || LOCAL_USE.contains(&n.as_str()) {
        return false;
    }
    list()
        .and_then(|l| l.suffix(n.as_bytes()))
        .is_some_and(|s| s.is_known() && s.as_bytes() == n.as_bytes())
}

/// The key security alerts about a name group on: its registrable domain, or the full name when
/// it has none (core.md §9, Grouping).
pub fn grouping_key(name: &str) -> String {
    registrable_domain(name).unwrap_or_else(|| name.trim().trim_end_matches('.').to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_list_parses() {
        assert!(list().is_some());
    }

    #[test]
    fn public_suffixes() {
        for n in ["com", "co.uk", "github.io", "in-addr.arpa", "arpa", "Com."] {
            assert!(is_public_suffix(n), "{n}");
        }
        for n in [
            "home.arpa",
            "lan",
            "internal",
            "example.com",
            "home.example.co.uk",
            "",
        ] {
            assert!(!is_public_suffix(n), "{n}");
        }
    }

    #[test]
    fn grouping() {
        assert_eq!(grouping_key("a.b.Example.co.uk."), "example.co.uk");
        assert_eq!(grouping_key("com"), "com");
        assert_eq!(grouping_key("localhost"), "localhost");
        assert_eq!(registrable_domain("printer.lan").as_deref(), Some("printer.lan"));
    }
}
