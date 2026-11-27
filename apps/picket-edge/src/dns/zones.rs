//! Forward zones (edge.md §6): a profile's zones, matched by longest suffix through a label
//! trie. Only the query's profile's zones count.

use std::collections::HashMap;
use std::sync::Arc;

use picket_api::edge_config::ZoneFallback;
use picket_wire::NameRef;

/// The zone a name falls in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneMatch {
    /// The forward zone's id (its key in `EdgeConfig.forward_zones`).
    pub id: Arc<str>,
    /// The upstream group the zone's names go to.
    pub group: Arc<str>,
    pub fallback: ZoneFallback,
}

#[derive(Debug, Default)]
struct Node {
    children: HashMap<Box<[u8]>, Node>,
    zone: Option<ZoneMatch>,
}

/// A label trie keyed by labels from the root down (`arpa` → `in-addr` → `168` …), lowercase.
#[derive(Debug, Default)]
pub struct ZoneTrie {
    root: Node,
    len: usize,
}

impl ZoneTrie {
    /// Adds a zone given as wire labels (most specific first, lowercase). A second zone with
    /// the same name keeps the first.
    pub fn insert(&mut self, labels: &[&[u8]], m: ZoneMatch) {
        let mut node = &mut self.root;
        for l in labels.iter().rev() {
            node = node
                .children
                .entry(l.to_ascii_lowercase().into_boxed_slice())
                .or_default();
        }
        if node.zone.is_none() {
            node.zone = Some(m);
            self.len += 1;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// The most specific zone holding `name` (lowercase wire form), the zone apex included.
    pub fn longest_match(&self, name: NameRef<'_>) -> Option<&ZoneMatch> {
        if self.len == 0 {
            return None;
        }
        // Labels most specific first; walk from the root (the last label) down.
        let mut labels: smallvec::SmallVec<[&[u8]; 16]> = name.labels().collect();
        labels.reverse();
        let mut node = &self.root;
        let mut best = node.zone.as_ref();
        for l in labels {
            match node.children.get(l) {
                Some(n) => {
                    node = n;
                    if node.zone.is_some() {
                        best = node.zone.as_ref();
                    }
                }
                None => break,
            }
        }
        best
    }

    /// True when some zone holds `name`.
    pub fn covers(&self, name: NameRef<'_>) -> bool {
        self.longest_match(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_wire::WireName;

    fn zm(id: &str) -> ZoneMatch {
        ZoneMatch {
            id: id.into(),
            group: "local".into(),
            fallback: ZoneFallback::None,
        }
    }

    fn add(t: &mut ZoneTrie, zone: &str, id: &str) {
        let w = WireName::from_text(zone).unwrap();
        let labels: Vec<&[u8]> = w.as_name().labels().collect();
        t.insert(&labels, zm(id));
    }

    #[test]
    fn longest_suffix_wins_and_apex_counts() {
        let mut t = ZoneTrie::default();
        add(&mut t, "168.192.in-addr.arpa", "lan-wide");
        add(&mut t, "1.168.192.in-addr.arpa", "lan-reverse");
        add(&mut t, "localdomain", "localdomain");
        let m = |n: &str| {
            let w = WireName::from_text(n).unwrap();
            t.longest_match(w.as_name()).map(|z| z.id.to_string())
        };
        assert_eq!(m("5.1.168.192.in-addr.arpa").as_deref(), Some("lan-reverse"));
        assert_eq!(m("5.2.168.192.in-addr.arpa").as_deref(), Some("lan-wide"));
        assert_eq!(m("localdomain").as_deref(), Some("localdomain"));
        assert_eq!(
            m("NAS.LocalDomain").as_deref(),
            Some("localdomain"),
            "names are lowercase wire"
        );
        assert_eq!(m("nas.localdomain").as_deref(), Some("localdomain"));
        assert_eq!(m("xlocaldomain"), None, "whole labels only");
        assert_eq!(m("example.com"), None);
        assert_eq!(t.len(), 3);
    }
}
