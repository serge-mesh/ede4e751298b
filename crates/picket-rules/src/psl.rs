//! The public suffix list, read the way urlfilter reads it (review round 1, R3): `$denyallow`
//! entities (`tracker.*`) match `tracker.` followed by the name's public suffix, which urlfilter
//! takes from `golang.org/x/net/publicsuffix`. [`PublicSuffixList::public_suffix`] is a port of that
//! package's `PublicSuffix`, quirks included: the longest matching rule wins, `*.d` makes every
//! label below `d` a suffix, `!e.d` is an exception, a name no rule covers has its last label as
//! suffix, and `icann` reports the section of the deciding trie node (a node only implied by a
//! longer rule counts as ICANN).
//!
//! Core reads its bundled list (`apps/picket-core/data/public_suffix_list.dat`) with
//! [`PublicSuffixList::parse`]; the edge never needs it (entities are expanded at compile time,
//! [`crate::entity`]).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// One rule of the list: its text as listed (A-labels, `*.` and `!` prefixes kept) and section.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SuffixRule {
    pub rule: String,
    /// In the ICANN section (as opposed to the private one).
    #[serde(default, skip_serializing_if = "is_false")]
    pub icann: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeType {
    Normal,
    Exception,
    ParentOnly,
}

#[derive(Clone, Debug)]
struct Node {
    children: HashMap<String, usize>,
    node_type: NodeType,
    icann: bool,
    wildcard: bool,
}

impl Node {
    fn new() -> Node {
        Node {
            children: HashMap::new(),
            node_type: NodeType::ParentOnly,
            icann: true,
            wildcard: false,
        }
    }
}

/// A public suffix list (all of it, or the part an entity needs, [`crate::entity`]).
#[derive(Clone, Debug)]
pub struct PublicSuffixList {
    rules: Vec<SuffixRule>,
    nodes: Vec<Node>,
}

impl Default for PublicSuffixList {
    fn default() -> Self {
        PublicSuffixList::from_rules(Vec::new())
    }
}

impl PublicSuffixList {
    /// Reads `public_suffix_list.dat` text: rules between `===BEGIN ICANN DOMAINS===` and `===END
    /// ICANN DOMAINS===` are ICANN, the others private; `//` comments and blank lines are skipped;
    /// a rule is mapped to A-labels (UTS #46), and a line that doesn't map is skipped.
    pub fn parse(text: &str) -> PublicSuffixList {
        let mut icann = false;
        let mut rules = Vec::new();
        for line in text.lines() {
            let s = line.trim();
            if s.contains("BEGIN ICANN DOMAINS") {
                icann = true;
                continue;
            }
            if s.contains("END ICANN DOMAINS") {
                icann = false;
                continue;
            }
            if s.is_empty() || s.starts_with("//") {
                continue;
            }
            let (prefix, body) = if let Some(b) = s.strip_prefix("*.") {
                ("*.", b)
            } else if let Some(b) = s.strip_prefix('!') {
                ("!", b)
            } else {
                ("", s)
            };
            let ascii = if body.is_ascii() {
                body.to_ascii_lowercase()
            } else {
                match idna::domain_to_ascii(body) {
                    Ok(a) => a,
                    Err(_) => continue,
                }
            };
            if ascii.is_empty() || ascii.split('.').any(str::is_empty) {
                continue;
            }
            rules.push(SuffixRule {
                rule: format!("{prefix}{ascii}"),
                icann,
            });
        }
        PublicSuffixList::from_rules(rules)
    }

    /// Builds the list from rules (as [`PublicSuffixList::rules`] gives them), in order.
    pub fn from_rules(rules: Vec<SuffixRule>) -> PublicSuffixList {
        let mut nodes = vec![Node::new()];
        for r in &rules {
            let (body, nt, wildcard) = if let Some(b) = r.rule.strip_prefix("*.") {
                (b, NodeType::ParentOnly, true)
            } else if let Some(b) = r.rule.strip_prefix('!') {
                (b, NodeType::Exception, false)
            } else {
                (r.rule.as_str(), NodeType::Normal, false)
            };
            let mut n = 0usize;
            let labels: Vec<&str> = body.split('.').collect();
            for (k, label) in labels.iter().enumerate().rev() {
                let next = nodes.get(n).and_then(|node| node.children.get(*label)).copied();
                let child = match next {
                    Some(c) => c,
                    None => {
                        nodes.push(Node::new());
                        let c = nodes.len().saturating_sub(1);
                        if let Some(node) = nodes.get_mut(n) {
                            node.children.insert((*label).to_string(), c);
                        }
                        c
                    }
                };
                n = child;
                if k == 0
                    && let Some(node) = nodes.get_mut(n)
                {
                    if nt != NodeType::ParentOnly && node.node_type == NodeType::ParentOnly {
                        node.node_type = nt;
                    }
                    node.icann = node.icann && r.icann;
                    node.wildcard = node.wildcard || wildcard;
                }
            }
        }
        PublicSuffixList { rules, nodes }
    }

    /// The rules, in list order.
    pub fn rules(&self) -> &[SuffixRule] {
        &self.rules
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Heap bytes the list holds: its rules and their text, and its lookup trie (nodes, their
    /// child maps and labels), each allocation as the allocator takes it ([`crate::mem`]).
    pub fn memory_usage(&self) -> usize {
        use crate::mem::{hash_map_bytes, string_bytes, vec_bytes};
        let rules = self
            .rules
            .iter()
            .fold(vec_bytes::<SuffixRule>(self.rules.capacity()), |a, r| {
                a.saturating_add(string_bytes(&r.rule, r.rule.capacity()))
            });
        self.nodes
            .iter()
            .fold(vec_bytes::<Node>(self.nodes.capacity()), |a, n| {
                let labels = n
                    .children
                    .keys()
                    .fold(0usize, |b, k| b.saturating_add(string_bytes(k, k.capacity())));
                a.saturating_add(hash_map_bytes(&n.children))
                    .saturating_add(labels)
            })
            .saturating_add(rules)
    }

    /// Nodes of the lookup trie (the root and one per distinct label path).
    pub fn trie_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// True for an empty list.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// `golang.org/x/net/publicsuffix.PublicSuffix` on a lowercased name (dotted text, as urlfilter
    /// passes the request host): the public suffix (a suffix of `domain`) and whether the deciding
    /// rule is in the ICANN section. An IP address is its own suffix, not ICANN.
    pub fn public_suffix<'a>(&self, domain: &'a str) -> (&'a str, bool) {
        if crate::ip::parse_go_ip(domain).is_some() && !domain.contains('%') {
            return (domain, false);
        }
        let mut s = domain;
        let mut suffix = domain.len();
        let mut icann_node = false;
        let mut wildcard = false;
        let mut icann = false;
        let mut node = 0usize;
        loop {
            let dot = s.rfind('.');
            let after_dot = dot.map_or(0, |d| d.saturating_add(1));
            if wildcard {
                icann = icann_node;
                suffix = after_dot;
            }
            let Some(cur) = self.nodes.get(node) else { break };
            if cur.children.is_empty() {
                break;
            }
            let label = s.get(after_dot..).unwrap_or("");
            let Some(&f) = cur.children.get(label) else { break };
            let Some(found) = self.nodes.get(f) else { break };
            icann_node = found.icann;
            match found.node_type {
                NodeType::Normal => suffix = after_dot,
                NodeType::Exception => {
                    suffix = s.len().saturating_add(1);
                    break;
                }
                NodeType::ParentOnly => {}
            }
            wildcard = found.wildcard;
            if !wildcard {
                icann = icann_node;
            }
            node = f;
            match dot {
                None => break,
                Some(d) => s = s.get(..d).unwrap_or(""),
            }
        }
        if suffix == domain.len() {
            // No rule matched: the prevailing rule is "*".
            let start = domain.rfind('.').map_or(0, |d| d.saturating_add(1));
            return (domain.get(start..).unwrap_or(""), icann);
        }
        (domain.get(suffix.min(domain.len())..).unwrap_or(""), icann)
    }

    /// True when `name` (normalised, dotted) is a public suffix by the ICANN or private rules,
    /// private-section wildcards excluded: the compiler's guardrail (bundles.md §2).
    pub fn is_public_suffix(&self, name: &str) -> bool {
        let (ps, _) = self.public_suffix(name);
        if ps != name {
            return false;
        }
        // A private wildcard's children don't count.
        let parent = name.split_once('.').map(|(_, p)| p).unwrap_or("");
        !self
            .rules
            .iter()
            .any(|r| !r.icann && r.rule.strip_prefix("*.") == Some(parent))
            || self.rules.iter().any(|r| r.rule == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "// ===BEGIN ICANN DOMAINS===\ncom\nnet\nuk\nco.uk\n*.ck\n!www.ck\njp\nkawasaki.jp\n*.kawasaki.jp\n!city.kawasaki.jp\nрф\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n*.compute.example.com\nq.r.blogspot.com\n// ===END PRIVATE DOMAINS===\n";

    #[test]
    fn as_x_net() {
        let l = PublicSuffixList::parse(LIST);
        let ps = |d: &'static str| l.public_suffix(d);
        assert_eq!(ps("example.com"), ("com", true));
        assert_eq!(ps("a.b.example.co.uk"), ("co.uk", true));
        assert_eq!(ps("foo.co.ck"), ("co.ck", true));
        assert_eq!(ps("www.ck"), ("ck", true));
        assert_eq!(ps("a.www.ck"), ("ck", true));
        assert_eq!(ps("x.blogspot.com"), ("blogspot.com", false));
        assert_eq!(ps("blogspot.com"), ("blogspot.com", false));
        assert_eq!(ps("tracker.zzz"), ("zzz", false));
        assert_eq!(ps("a.city.kawasaki.jp"), ("kawasaki.jp", true));
        assert_eq!(ps("a.b.kawasaki.jp"), ("b.kawasaki.jp", true));
        assert_eq!(ps("x.xn--p1ai"), ("xn--p1ai", true));
        assert_eq!(ps("1.2.3.4"), ("1.2.3.4", false));
        // x/net: a node only implied by a longer rule counts as ICANN.
        assert_eq!(ps("t.r.blogspot.com"), ("blogspot.com", true));
        assert_eq!(ps("a.b.compute.example.com"), ("b.compute.example.com", false));
        assert!(l.is_public_suffix("co.uk"));
        assert!(l.is_public_suffix("blogspot.com"));
        assert!(!l.is_public_suffix("example.com"));
        assert!(
            !l.is_public_suffix("b.compute.example.com"),
            "private wildcard child"
        );
    }
}
