//! The `dns` rules engine (providers.md §5 `dns` "Rules"): rules are checked in order and the
//! first whose conditions all hold decides. No rule matched: NOERROR or NXDOMAIN → Clean, any
//! other rcode → Unknown.

use picket_wire::facts::LookupFacts;
use picket_wire::types::rcode;

use super::config::{Config, EdeMatch, Rule, RuleVerdict, When};
use crate::module::Verdict;

impl When {
    /// Whether every condition set holds for these facts.
    pub fn holds(&self, f: &LookupFacts) -> bool {
        if let Some(rc) = &self.rcode
            && !rc.contains(&f.rcode)
        {
            return false;
        }
        match &self.ede {
            Some(EdeMatch::Codes(codes)) if !f.ede.iter().any(|e| codes.contains(&e.code)) => {
                return false;
            }
            Some(EdeMatch::None) if !f.ede.is_empty() => return false,
            _ => {}
        }
        if let Some(needle) = &self.ede_text
            && !f
                .ede
                .iter()
                .any(|e| contains_ignore_ascii_case(e.text.as_bytes(), needle))
        {
            return false;
        }
        if let Some(nets) = &self.answers_in
            && (f.addrs.is_empty() || !f.addrs.iter().all(|a| nets.iter().any(|n| n.contains(a))))
        {
            return false;
        }
        if let Some(suffixes) = &self.cname_suffix {
            let Some(last) = f.chain.last() else {
                return false;
            };
            if !suffixes
                .iter()
                .any(|s| last.as_name().is_at_or_below(s.as_name()))
            {
                return false;
            }
        }
        if let Some(soa) = self.soa
            && soa != f.soa
        {
            return false;
        }
        true
    }
}

/// `needle` (lowercase) occurs in `hay`, ASCII case-insensitively.
fn contains_ignore_ascii_case(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

impl Rule {
    fn verdict(&self) -> Verdict {
        match self.verdict {
            RuleVerdict::Block => Verdict::Block {
                score: self.score,
                reason: self.id.clone(),
            },
            RuleVerdict::Clean => Verdict::Clean,
            RuleVerdict::Unknown => Verdict::Unknown,
        }
    }
}

/// The verdict for an answer's facts, and the id of the rule that decided it.
pub fn decide<'c>(cfg: &'c Config, f: &LookupFacts) -> (Verdict, Option<&'c str>) {
    for r in &cfg.rules {
        if r.when.holds(f) {
            return (r.verdict(), Some(&r.id));
        }
    }
    let v = if f.rcode == rcode::NOERROR || f.rcode == rcode::NXDOMAIN {
        Verdict::Clean
    } else {
        Verdict::Unknown
    };
    (v, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_case_insensitive_contains() {
        assert!(contains_ignore_ascii_case(b"Blocked by NextDNS", b"nextdns"));
        assert!(contains_ignore_ascii_case(b"BLOCKED", b"blocked"));
        assert!(!contains_ignore_ascii_case(b"Block", b"blocked"));
        assert!(contains_ignore_ascii_case("ÉTÉ blocked".as_bytes(), b"blocked"));
        assert!(!contains_ignore_ascii_case("É".as_bytes(), "é".as_bytes()));
    }
}
