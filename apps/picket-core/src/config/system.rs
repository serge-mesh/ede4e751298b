//! System objects (core.md §2): created at every start when missing; editable, never deletable.
//!
//! - manual feeds `manual-allow`, `manual-block`, `manual-warn`, `lookup-exclude` (pre-loaded with
//!   `||local^`, `||lan^`, `||arpa^`, `||home.arpa^`) and `canaries` (the three NXDOMAIN rewrites);
//! - the scope bundle `lookup-exclude`; bundles `allow-common`, `block-common` and the warn bundle
//!   `warn-common`;
//! - the profile `dnssec-validator` (core.md §8) and the upstream group `cloudflare` with its
//!   upstreams (edge.md §6).

use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use picket_api::edge_config::{BypassMode, GroupStrategy, LogLevel, Profile, UpstreamProtocol};
use rusqlite::Transaction;

use super::model::*;
use super::store;

pub const DNSSEC_PROFILE: &str = "dnssec-validator";
pub const CLOUDFLARE_GROUP: &str = "cloudflare";
/// The starter profile `init` creates (not a system object: it may be deleted).
pub const DEFAULT_PROFILE: &str = "default";

pub const SYSTEM_FEEDS: &[&str] = &[
    "manual-allow",
    "manual-block",
    "manual-warn",
    "lookup-exclude",
    "canaries",
];

const SYSTEM_BUNDLES: &[(&str, BundleAction, &[&str])] = &[
    ("lookup-exclude", BundleAction::Scope, &["lookup-exclude"]),
    ("allow-common", BundleAction::Allow, &["manual-allow"]),
    ("block-common", BundleAction::Block, &["manual-block", "canaries"]),
    ("warn-common", BundleAction::Warn, &["manual-warn"]),
];

/// `lookup-exclude`'s pre-loaded file.
pub const LOOKUP_EXCLUDE_FILE: &str = "||local^\n||lan^\n||arpa^\n||home.arpa^\n";
/// `canaries`' pre-loaded file: NXDOMAIN whatever `block_response` is, because Firefox and Apple
/// treat 0.0.0.0 as a positive answer.
pub const CANARIES_FILE: &str = "||use-application-dns.net^$dnsrewrite=NXDOMAIN;;\n||mask.icloud.com^$dnsrewrite=NXDOMAIN;;\n||mask-h2.icloud.com^$dnsrewrite=NXDOMAIN;;\n";

/// The action a system bundle keeps.
pub fn system_bundle_action(id: &str) -> Option<BundleAction> {
    SYSTEM_BUNDLES.iter().find(|(b, ..)| *b == id).map(|(_, a, _)| *a)
}

/// True when `id` of `kind` is a system object (undeletable).
pub fn is_system(kind: EntityKind, id: &str) -> bool {
    match kind {
        EntityKind::Feed => SYSTEM_FEEDS.contains(&id),
        EntityKind::Bundle => system_bundle_action(id).is_some(),
        EntityKind::Profile => id == DNSSEC_PROFILE,
        EntityKind::UpstreamGroup => id == CLOUDFLARE_GROUP,
        _ => false,
    }
}

fn manual_feed(id: &str, name: &str) -> FeedDef {
    FeedDef {
        id: id.into(),
        name: name.into(),
        rule_policy: RulePolicy::default().resolved(true),
        system: true,
        ..FeedDef::default()
    }
}

fn system_feeds() -> Vec<(FeedDef, &'static str)> {
    vec![
        (manual_feed("manual-allow", "Manual allow"), ""),
        (manual_feed("manual-block", "Manual block"), ""),
        (manual_feed("manual-warn", "Manual warn"), ""),
        (
            manual_feed("lookup-exclude", "Lookup exclusions"),
            LOOKUP_EXCLUDE_FILE,
        ),
        (manual_feed("canaries", "Canaries"), CANARIES_FILE),
    ]
}

fn system_bundle(id: &str, action: BundleAction, feeds: &[&str]) -> BundleDef {
    let name = match id {
        "lookup-exclude" => "Lookup exclusions",
        "allow-common" => "Common allows",
        "block-common" => "Common blocks",
        "warn-common" => "Common warninglist",
        other => other,
    };
    BundleDef {
        id: id.into(),
        name: name.into(),
        action,
        feeds: feeds
            .iter()
            .map(|f| BundleFeed {
                feed: (*f).into(),
                rule_types: None,
                tier: None,
            })
            .collect(),
        system: true,
        ..BundleDef::default()
    }
}

/// The `dnssec-validator` profile (core.md §8): no bundles, lookup providers or forward zones,
/// `firewall.add_entries = false`, `log = off`. Its `allowed_sources` are rendered from
/// `dnssec.source_ips`, so the stored list is left empty.
pub fn dnssec_profile() -> ProfileDef {
    let mut edge = Profile {
        allowed_sources: vec![],
        upstream: CLOUDFLARE_GROUP.into(),
        log: LogLevel::Off,
        ..Profile::default()
    };
    edge.firewall.add_entries = false;
    edge.bypass.mode = BypassMode::Off;
    ProfileDef {
        id: DNSSEC_PROFILE.into(),
        name: "DNSSEC validator".into(),
        system: true,
        edge,
        alert_categories: vec![],
        alert_lookup_providers: Some(vec![]),
        ..ProfileDef::default()
    }
}

/// The starter profile `init` creates: the common allows and blocks over Cloudflare.
pub fn default_profile() -> ProfileDef {
    ProfileDef {
        id: DEFAULT_PROFILE.into(),
        name: "Default".into(),
        edge: Profile {
            allow: vec!["allow-common".into()],
            block: vec!["block-common".into()],
            upstream: CLOUDFLARE_GROUP.into(),
            ..Profile::default()
        },
        ..ProfileDef::default()
    }
}

/// The `cloudflare` group's upstreams: DoT to 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111 and
/// 2606:4700:4700::1001 on 853 (`one.one.one.one`) plus DoH to 1.1.1.1:443
/// (`cloudflare-dns.com`, `/dns-query`), all operated by `cloudflare` (edge.md §6).
pub fn cloudflare_upstreams() -> Vec<UpstreamDef> {
    let dot = |id: &str, ip: &str| UpstreamDef {
        id: id.into(),
        name: format!("Cloudflare DoT {ip}"),
        protocol: UpstreamProtocol::Dot,
        ip: ip.parse::<IpAddr>().unwrap_or(IpAddr::from([1, 1, 1, 1])),
        port: 853,
        tls_host: Some("one.one.one.one".into()),
        path: None,
        trust_store: None,
        operator: Some("cloudflare".into()),
    };
    vec![
        dot("cf-dot-1", "1.1.1.1"),
        dot("cf-dot-2", "1.0.0.1"),
        dot("cf-dot-3", "2606:4700:4700::1111"),
        dot("cf-dot-4", "2606:4700:4700::1001"),
        UpstreamDef {
            id: "cf-doh".into(),
            name: "Cloudflare DoH 1.1.1.1".into(),
            protocol: UpstreamProtocol::Doh,
            ip: IpAddr::from([1, 1, 1, 1]),
            port: 443,
            tls_host: Some("cloudflare-dns.com".into()),
            path: Some("/dns-query".into()),
            trust_store: None,
            operator: Some("cloudflare".into()),
        },
    ]
}

pub fn cloudflare_group() -> UpstreamGroupDef {
    UpstreamGroupDef {
        id: CLOUDFLARE_GROUP.into(),
        name: "Cloudflare".into(),
        upstreams: cloudflare_upstreams().into_iter().map(|u| u.id).collect(),
        strategy: GroupStrategy::Fastest,
        optimistic: true,
    }
}

/// Creates every missing system object inside `tx`. Returns what it created as
/// `(entity, id)` pairs. Manual files of new system feeds go to the blob store under
/// `data_dir`.
/// Adds the system objects `m` lacks, as [`ensure`] would create them (a restored document from
/// a release without some of them is checked with them in place).
pub fn fill_missing(m: &mut super::model::Model) {
    for (feed, _) in system_feeds() {
        m.feeds.entry(feed.id.clone()).or_insert(feed);
    }
    for (id, action, feeds) in SYSTEM_BUNDLES {
        m.bundles
            .entry(id.to_string())
            .or_insert_with(|| system_bundle(id, *action, feeds));
    }
    if !m.upstream_groups.contains_key(CLOUDFLARE_GROUP) {
        for u in cloudflare_upstreams() {
            m.upstreams.entry(u.id.clone()).or_insert(u);
        }
        m.upstream_groups
            .insert(CLOUDFLARE_GROUP.into(), cloudflare_group());
    }
    m.profiles
        .entry(DNSSEC_PROFILE.into())
        .or_insert_with(dnssec_profile);
}

pub fn ensure(tx: &Transaction<'_>, data_dir: &Path) -> Result<Vec<(EntityKind, String)>> {
    let model = store::load_model(tx)?;
    let mut created = Vec::new();
    for (feed, file) in system_feeds() {
        if !model.feeds.contains_key(&feed.id) {
            store::write_feed(tx, &feed)?;
            store::write_manual_file(tx, data_dir, &feed.id, file.as_bytes())?;
            created.push((EntityKind::Feed, feed.id.clone()));
        } else if !store::has_manual_file(tx, &feed.id)? {
            // The pre-loaded file is part of the system object: it comes back too.
            store::write_manual_file(tx, data_dir, &feed.id, file.as_bytes())?;
            super::journal::record(
                tx,
                None,
                "system",
                EntityKind::Feed,
                &feed.id,
                &serde_json::json!({"op": "update", "file": "restored", "by": "system objects at start"}),
            )?;
        }
    }
    for (id, action, feeds) in SYSTEM_BUNDLES {
        if !model.bundles.contains_key(*id) {
            store::write_bundle(tx, &system_bundle(id, *action, feeds))?;
            created.push((EntityKind::Bundle, id.to_string()));
        }
    }
    if !model.upstream_groups.contains_key(CLOUDFLARE_GROUP) {
        for u in cloudflare_upstreams() {
            if !model.upstreams.contains_key(&u.id) {
                store::write_upstream(tx, &u)?;
                created.push((EntityKind::Upstream, u.id.clone()));
            }
        }
        store::write_group(tx, &cloudflare_group())?;
        created.push((EntityKind::UpstreamGroup, CLOUDFLARE_GROUP.into()));
    }
    if !model.profiles.contains_key(DNSSEC_PROFILE) {
        store::write_profile(tx, &dnssec_profile())?;
        created.push((EntityKind::Profile, DNSSEC_PROFILE.into()));
    }
    for (kind, id) in &created {
        super::journal::record(
            tx,
            None,
            "system",
            *kind,
            id,
            &serde_json::json!({"op": "create", "by": "system objects at start"}),
        )?;
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::validate::{Severity, validate};

    #[test]
    fn system_objects_validate() {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let mut c = crate::db::open_connection(&opts, 1024).unwrap();
        let tx = c.transaction().unwrap();
        let created = ensure(&tx, d.path()).unwrap();
        assert!(created.len() > 5 + 4 + 5 + 1);
        // Idempotent.
        assert!(ensure(&tx, d.path()).unwrap().is_empty());
        let m = store::load_model(&tx).unwrap();
        let errors: Vec<_> = validate(&m)
            .into_iter()
            .filter(|i| i.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(m.bundles["block-common"].feeds.len(), 2);
        assert_eq!(m.upstream_groups[CLOUDFLARE_GROUP].upstreams.len(), 5);
        assert_eq!(m.upstreams["cf-dot-3"].ip.to_string(), "2606:4700:4700::1111");
        let lookup_exclude = store::read_manual_file(&tx, d.path(), "lookup-exclude")
            .unwrap()
            .unwrap();
        assert_eq!(lookup_exclude, LOOKUP_EXCLUDE_FILE.as_bytes());
        let canaries = store::read_manual_file(&tx, d.path(), "canaries")
            .unwrap()
            .unwrap();
        assert!(
            String::from_utf8(canaries)
                .unwrap()
                .contains("||mask-h2.icloud.com^$dnsrewrite=NXDOMAIN;;")
        );
        tx.commit().unwrap();
    }

    #[test]
    fn a_missing_preloaded_file_comes_back() {
        // core.md §2: system objects come back at every start when missing; the pre-loaded
        // files of `lookup-exclude` and `canaries` are part of them.
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let mut c = crate::db::open_connection(&opts, 1024).unwrap();
        let tx = c.transaction().unwrap();
        ensure(&tx, d.path()).unwrap();
        tx.execute(
            "DELETE FROM manual_files WHERE feed_id IN ('lookup-exclude', 'canaries')",
            [],
        )
        .unwrap();
        ensure(&tx, d.path()).unwrap();
        assert_eq!(
            store::read_manual_file(&tx, d.path(), "lookup-exclude")
                .unwrap()
                .unwrap(),
            LOOKUP_EXCLUDE_FILE.as_bytes()
        );
        assert_eq!(
            store::read_manual_file(&tx, d.path(), "canaries")
                .unwrap()
                .unwrap(),
            CANARIES_FILE.as_bytes()
        );
        // A file the admin edited is kept.
        store::write_manual_file(&tx, d.path(), "canaries", b"||x.example^\n").unwrap();
        ensure(&tx, d.path()).unwrap();
        assert_eq!(
            store::read_manual_file(&tx, d.path(), "canaries")
                .unwrap()
                .unwrap(),
            b"||x.example^\n"
        );
    }
}
