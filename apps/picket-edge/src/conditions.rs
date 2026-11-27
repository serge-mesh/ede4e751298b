//! The conditions registry (edge.md §11, api.md §3): the ongoing problems `hello` and every
//! heartbeat carry. Each change (appeared, cleared) goes to the journal and to core as a
//! `condition` record through the normal spool, so changes between snapshots reach core.
//!
//! A source that reports its whole set at once ([`Conditions::sync_kinds`]) owns its findings: a
//! condition two sources report (`unifi_conflict` for one feature, found by the helper in
//! iptables and by the edge in files, edge-unifi.md §7) holds while either reports it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use picket_api::logs::{ConditionChange, ConditionRecord, LogRecord};
use picket_api::session::Condition;
use picket_api::time::Timestamp;

use crate::logs::{LogProducer, placeholder_header};

type Key = (String, Option<String>);

/// A source of [`Conditions::sync_kinds`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// picket-edge-helper's `conditions` event (edge-firewall.md §4).
    Helper,
    /// The edge's own check of UniFi's files (edge-unifi.md §7).
    UnifiFiles,
}

/// Each synced condition's reporters, with their details.
type Claims = BTreeMap<Key, BTreeMap<Source, Option<serde_json::Value>>>;

/// The conditions holding now.
pub struct Conditions {
    map: ArcSwap<BTreeMap<Key, Condition>>,
    write: Mutex<()>,
    /// Taken before `write`, never while holding it.
    claims: Mutex<Claims>,
    logs: LogProducer,
}

impl Conditions {
    pub fn new(logs: LogProducer) -> Arc<Self> {
        Arc::new(Self {
            map: ArcSwap::from_pointee(BTreeMap::new()),
            write: Mutex::new(()),
            claims: Mutex::new(BTreeMap::new()),
            logs,
        })
    }

    /// Sets a condition. A new one gets `since` = now and an `appeared` record; one that holds
    /// already keeps its `since`, and a changed detail is reported as a new `appeared` record.
    pub fn set(&self, kind: &str, key: Option<&str>, detail: Option<serde_json::Value>) {
        let _g = self.write.lock().unwrap_or_else(|p| p.into_inner());
        let k: Key = (kind.to_owned(), key.map(str::to_owned));
        let cur = self.map.load();
        let now = Timestamp::now();
        let (since, changed) = match cur.get(&k) {
            Some(c) if c.detail == detail => return,
            Some(c) => (c.since, true),
            None => (now, false),
        };
        let mut next = BTreeMap::clone(&cur);
        next.insert(
            k,
            Condition {
                kind: kind.to_owned(),
                key: key.map(str::to_owned),
                since,
                detail: detail.clone(),
            },
        );
        self.map.store(Arc::new(next));
        tracing::warn!(
            "condition {}{} {}{}",
            kind,
            key.map(|k| format!("[{k}]")).unwrap_or_default(),
            if changed { "changed" } else { "appeared" },
            detail
                .as_ref()
                .map(|d| format!(": {}", crate::diag::cap(d)))
                .unwrap_or_default()
        );
        self.record(kind, key, ConditionChange::Appeared, detail);
    }

    /// Clears a condition if it holds.
    pub fn clear(&self, kind: &str, key: Option<&str>) {
        let _g = self.write.lock().unwrap_or_else(|p| p.into_inner());
        let k: Key = (kind.to_owned(), key.map(str::to_owned));
        let cur = self.map.load();
        if !cur.contains_key(&k) {
            return;
        }
        let mut next = BTreeMap::clone(&cur);
        next.remove(&k);
        self.map.store(Arc::new(next));
        tracing::warn!(
            "condition {}{} cleared",
            kind,
            key.map(|k| format!("[{k}]")).unwrap_or_default()
        );
        self.record(kind, key, ConditionChange::Cleared, None);
    }

    /// Sets or clears by a flag.
    pub fn set_if(&self, on: bool, kind: &str, key: Option<&str>, detail: Option<serde_json::Value>) {
        if on {
            self.set(kind, key, detail);
        } else {
            self.clear(kind, key);
        }
    }

    /// Makes `source`'s findings of `kinds` exactly `current` (a source that reports its whole
    /// set at once, such as the helper's `conditions` event, edge-firewall.md §4). A condition
    /// holds while any source reports it (the first source's detail wins) and clears when the
    /// last one stops.
    pub fn sync_kinds(
        &self,
        source: Source,
        kinds: &[&str],
        current: &[(String, Option<String>, Option<serde_json::Value>)],
    ) {
        let mut claims = self.claims.lock().unwrap_or_else(|p| p.into_inner());
        let mut touched: BTreeSet<Key> = BTreeSet::new();
        for (key, by) in claims.iter_mut() {
            if kinds.contains(&key.0.as_str())
                && by.contains_key(&source)
                && !current.iter().any(|(k, ky, _)| *k == key.0 && *ky == key.1)
            {
                by.remove(&source);
                touched.insert(key.clone());
            }
        }
        for (kind, key, detail) in current {
            if kinds.contains(&kind.as_str()) {
                let k: Key = (kind.clone(), key.clone());
                claims
                    .entry(k.clone())
                    .or_default()
                    .insert(source, detail.clone());
                touched.insert(k);
            }
        }
        for k in touched {
            let detail = claims.get(&k).and_then(|by| by.values().next().cloned());
            match detail {
                Some(d) => self.set(&k.0, k.1.as_deref(), d),
                None => {
                    claims.remove(&k);
                    self.clear(&k.0, k.1.as_deref());
                }
            }
        }
    }

    pub fn is_set(&self, kind: &str, key: Option<&str>) -> bool {
        self.map
            .load()
            .contains_key(&(kind.to_owned(), key.map(str::to_owned)))
    }

    /// Every condition holding now (for `hello` and heartbeats).
    pub fn snapshot(&self) -> Vec<Condition> {
        self.map.load().values().cloned().collect()
    }

    fn record(
        &self,
        kind: &str,
        key: Option<&str>,
        change: ConditionChange,
        detail: Option<serde_json::Value>,
    ) {
        self.logs.emit(LogRecord::Condition(ConditionRecord {
            h: placeholder_header(),
            kind: kind.to_owned(),
            key: key.map(str::to_owned),
            change,
            time: Timestamp::now(),
            detail,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_api::session::condition_kind::*;

    #[test]
    fn set_clear_and_records() {
        let (p, mut rx) = LogProducer::new("b".into(), Arc::default());
        let c = Conditions::new(p);
        c.set(SSD_UNAVAILABLE, None, Some("unmounted".into()));
        let since = c.snapshot()[0].since;
        c.set(SSD_UNAVAILABLE, None, Some("unmounted".into())); // no change, no record
        c.set(SSD_UNAVAILABLE, None, Some("low_space".into())); // detail change
        assert_eq!(c.snapshot()[0].since, since, "since stays while it holds");
        c.clear(SSD_UNAVAILABLE, None);
        c.clear(SSD_UNAVAILABLE, None); // nothing to clear
        assert!(c.snapshot().is_empty());
        let mut changes = vec![];
        while let Ok(e) = rx.rx.try_recv() {
            let v: serde_json::Value = serde_json::from_str(&e.line).unwrap();
            assert_eq!(v["t"], "condition");
            changes.push((v["change"].as_str().unwrap().to_owned(), v["detail"].clone()));
        }
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].0, "appeared");
        assert_eq!(changes[1].1, "low_space");
        assert_eq!(changes[2].0, "cleared");
    }

    #[test]
    fn sync_kinds_replaces_a_source_set() {
        let (p, _rx) = LogProducer::new("b".into(), Arc::default());
        let c = Conditions::new(p);
        c.set(UPSTREAM_DOWN, Some("cloudflare"), None);
        c.sync_kinds(
            Source::Helper,
            &[REDIRECT_MISSING, UNIFI_CONFLICT],
            &[(REDIRECT_MISSING.into(), Some("ipv4".into()), None)],
        );
        assert!(c.is_set(REDIRECT_MISSING, Some("ipv4")));
        c.sync_kinds(Source::Helper, &[REDIRECT_MISSING, UNIFI_CONFLICT], &[]);
        assert!(!c.is_set(REDIRECT_MISSING, Some("ipv4")));
        assert!(
            c.is_set(UPSTREAM_DOWN, Some("cloudflare")),
            "other kinds untouched"
        );
    }

    /// edge-unifi.md §7: the helper (iptables) and the edge (files) both report `unifi_conflict`
    /// by feature; one source's report never clears the other's finding.
    #[test]
    fn a_condition_two_sources_report_holds_while_either_does() {
        let (p, mut rx) = LogProducer::new("b".into(), Arc::default());
        let c = Conditions::new(p);
        let dnsfilter = |d: Option<&str>| {
            vec![(
                UNIFI_CONFLICT.to_owned(),
                Some("dnsfilter".to_owned()),
                d.map(serde_json::Value::from),
            )]
        };
        let shield = vec![(UNIFI_CONFLICT.to_owned(), Some("dns_shield".to_owned()), None)];
        c.sync_kinds(Source::UnifiFiles, &[UNIFI_CONFLICT], &dnsfilter(None));
        c.sync_kinds(Source::Helper, &[UNIFI_CONFLICT], &dnsfilter(None));
        c.sync_kinds(Source::Helper, &[UNIFI_CONFLICT], &[]);
        assert!(
            c.is_set(UNIFI_CONFLICT, Some("dnsfilter")),
            "the files still show it"
        );
        c.sync_kinds(Source::Helper, &[UNIFI_CONFLICT], &shield);
        c.sync_kinds(Source::UnifiFiles, &[UNIFI_CONFLICT], &[]);
        assert!(!c.is_set(UNIFI_CONFLICT, Some("dnsfilter")), "nobody reports it");
        assert!(
            c.is_set(UNIFI_CONFLICT, Some("dns_shield")),
            "the helper's own finding"
        );
        c.sync_kinds(Source::Helper, &[UNIFI_CONFLICT], &[]);
        assert!(c.snapshot().is_empty());
        let changes: Vec<String> = std::iter::from_fn(|| rx.rx.try_recv().ok())
            .map(|e| {
                let v: serde_json::Value = serde_json::from_str(&e.line).unwrap();
                format!("{} {}", v["key"].as_str().unwrap(), v["change"].as_str().unwrap())
            })
            .collect();
        assert_eq!(
            changes,
            [
                "dnsfilter appeared",
                "dns_shield appeared",
                "dnsfilter cleared",
                "dns_shield cleared"
            ],
            "one record per change, none for a second source's report"
        );
    }
}
