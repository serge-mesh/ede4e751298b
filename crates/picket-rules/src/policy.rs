//! `rule_policy` (feeds.md §8): which option covers a rule, so ingest keeps or drops whole rules.

use serde::{Deserialize, Serialize};

use crate::browser::parse_browser;
use crate::rule::{Rule, RuleType};

/// One `rule_policy` option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOption {
    /// Hosts lines with another address, and `$dnsrewrite` rules that return records.
    Redirects,
    /// Any rule with `$client` or `$ctag`, browser rules included.
    ClientRules,
    /// `browser` rules that do more than block a request or hide an element.
    BrowserChanges,
}

/// `drop` or `keep`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Choice {
    Drop,
    Keep,
}

/// A feed's `rule_policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RulePolicy {
    pub redirects: Choice,
    pub client_rules: Choice,
    pub browser_changes: Choice,
}

impl RulePolicy {
    /// The default for downloaded feeds: drop redirects and client rules, keep browser changes.
    pub const DOWNLOADED: RulePolicy = RulePolicy {
        redirects: Choice::Drop,
        client_rules: Choice::Drop,
        browser_changes: Choice::Keep,
    };
    /// The default for manual feeds, and the setting parity is measured with: keep everything.
    pub const KEEP_ALL: RulePolicy = RulePolicy {
        redirects: Choice::Keep,
        client_rules: Choice::Keep,
        browser_changes: Choice::Keep,
    };

    fn choice(&self, o: PolicyOption) -> Choice {
        match o {
            PolicyOption::Redirects => self.redirects,
            PolicyOption::ClientRules => self.client_rules,
            PolicyOption::BrowserChanges => self.browser_changes,
        }
    }

    /// The options set to `drop` that cover `rule`: empty when the rule is kept. A rule is never
    /// weakened into another (feeds.md §8 "Whole rules only").
    pub fn dropping(&self, rule: &Rule) -> Vec<PolicyOption> {
        covering(rule)
            .into_iter()
            .filter(|&o| self.choice(o) == Choice::Drop)
            .collect()
    }

    /// True when the rule is kept.
    pub fn keeps(&self, rule: &Rule) -> bool {
        self.dropping(rule).is_empty()
    }
}

/// Every option that covers a rule.
pub fn covering(rule: &Rule) -> Vec<PolicyOption> {
    let mut out = Vec::new();
    if rule.rule_type == RuleType::Browser || rule.kind.is_browser() {
        let b = parse_browser(&rule.key);
        if b.has_client_modifier() {
            out.push(PolicyOption::ClientRules);
        }
        if b.is_browser_change() {
            out.push(PolicyOption::BrowserChanges);
        }
        return out;
    }
    let redirect = rule.is_mapping()
        || (!rule.is_exception() && rule.spec.dnsrewrite.as_ref().is_some_and(|r| r.returns_records()));
    if redirect {
        out.push(PolicyOption::Redirects);
    }
    if rule.spec.client.is_some() || rule.spec.ctag.is_some() {
        out.push(PolicyOption::ClientRules);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Item, Line, classify_adblock_line};

    fn rule(l: &str) -> Rule {
        match classify_adblock_line(l, false) {
            Line::Items(v) => match v.into_iter().next() {
                Some(Item::Rule(r)) => r,
                o => panic!("{l}: {o:?}"),
            },
            o => panic!("{l}: {o:?}"),
        }
    }

    #[test]
    fn options() {
        use PolicyOption::*;
        assert_eq!(covering(&rule("192.0.2.10 a.example")), vec![Redirects]);
        assert_eq!(covering(&rule("0.0.0.0 a.example")), vec![]);
        assert_eq!(
            covering(&rule("||a.example^$dnsrewrite=1.2.3.4")),
            vec![Redirects]
        );
        assert_eq!(
            covering(&rule("||a.example^$dnsrewrite=other.example")),
            vec![Redirects]
        );
        assert_eq!(covering(&rule("||a.example^$dnsrewrite=NXDOMAIN;;")), vec![]);
        assert_eq!(covering(&rule("||a.example^$dnsrewrite=NOERROR;;")), vec![]);
        assert_eq!(covering(&rule("||a.example^$dnsrewrite=REFUSED;;")), vec![]);
        assert_eq!(covering(&rule("@@||a.example^$dnsrewrite=1.2.3.4")), vec![]);
        assert_eq!(covering(&rule("||a.example^$client=kid")), vec![ClientRules]);
        assert_eq!(
            covering(&rule("||a.example^$ctag=device_phone")),
            vec![ClientRules]
        );
        assert_eq!(
            covering(&rule("||a.example^$dnsrewrite=1.2.3.4,client=kid")),
            vec![Redirects, ClientRules]
        );
        assert_eq!(
            covering(&rule("||a.example^$client=kid,third-party")),
            vec![ClientRules]
        );
        assert_eq!(covering(&rule("a.example##+js(nobab)")), vec![BrowserChanges]);
        assert_eq!(covering(&rule("a.example#$#body{x:y}")), vec![BrowserChanges]);
        assert_eq!(
            covering(&rule("a.example##div:style(color: red)")),
            vec![BrowserChanges]
        );
        assert_eq!(covering(&rule("a.example#@#.ad")), vec![BrowserChanges]);
        assert_eq!(covering(&rule("@@||a.example^$script")), vec![BrowserChanges]);
        assert_eq!(
            covering(&rule("||a.example^$redirect=noop.js")),
            vec![BrowserChanges]
        );
        assert_eq!(
            covering(&rule("||a.example^$removeparam=utm")),
            vec![BrowserChanges]
        );
        assert_eq!(
            covering(&rule("||a.example^$script,badfilter")),
            vec![BrowserChanges]
        );
        assert_eq!(covering(&rule("a.example##.ad")), vec![]);
        assert_eq!(
            covering(&rule("||a.example^$dnsrewrite=NOERROR;TXT;hi")),
            vec![Redirects]
        );
        assert_eq!(covering(&rule("@@||a.example^$dnsrewrite")), vec![]);
        assert_eq!(covering(&rule("@@||a.example^$ctag=kids")), vec![ClientRules]);
        assert_eq!(
            covering(&rule("||a.example/a$redirect-rule=noop.js")),
            vec![BrowserChanges]
        );
        assert_eq!(covering(&rule("a.example#@?#.ad:has(a)")), vec![BrowserChanges]);
        assert_eq!(
            covering(&rule("a.example##^script:has-text(ad)")),
            vec![BrowserChanges]
        );
        assert_eq!(covering(&rule("||a.example/a.js$script")), vec![]);
        assert_eq!(
            covering(&rule("@@||a.example^")),
            vec![],
            "a dns exception isn't a browser change"
        );
        let p = RulePolicy::DOWNLOADED;
        assert!(!p.keeps(&rule("||a.example^$client=kid")));
        assert!(p.keeps(&rule("a.example##+js(nobab)")));
        assert!(RulePolicy::KEEP_ALL.keeps(&rule("192.0.2.10 a.example")));
        let p = RulePolicy {
            browser_changes: Choice::Drop,
            ..RulePolicy::KEEP_ALL
        };
        assert_eq!(p.dropping(&rule("a.example##+js(nobab)")), vec![BrowserChanges]);
    }
}
