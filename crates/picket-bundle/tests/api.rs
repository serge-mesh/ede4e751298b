//! The seams other components use: shared types are `Send + Sync` (the edge swaps them with
//! `ArcSwap` and matches from many threads), `versions` and part names follow api.md §5, and a
//! reason carries what the edge logs (bundles.md §6).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use common::*;
use picket_api::logs::{BundleVersion, MatchKind};
use picket_bundle::matcher::{PartId, ReasonKey};
use picket_bundle::verdict::VerdictSet;
use picket_bundle::{Bundle, ColdCheck};
use picket_rules::matcher::BundleAction;

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn shared_types_are_send_and_sync() {
    assert_send_sync::<Bundle>();
    assert_send_sync::<VerdictSet>();
    assert_send_sync::<picket_bundle::reader::HotShard>();
    assert_send_sync::<picket_bundle::reader::ColdShard>();
    assert_send_sync::<picket_bundle::reader::IpShard>();
}

#[test]
fn reasons_and_versions() {
    let rules: Vec<String> = [
        "||ads.example^",
        "||c.example^",
        "/^banner[0-9]+\\./",
        "||1.2.3.4^",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let l = compile_and_load(BundleAction::Block, &parse_rules(&rules), 0, Tiering::Mixed);
    let head = l.bundle.head().to_string();
    match l.bundle.versions() {
        BundleVersion::Plain(h) => assert_eq!(h, picket_api::ids::short_id(&head)),
        other => panic!("{other:?}"),
    }
    let labels: Vec<&[u8]> = vec![b"x", b"ads", b"example"];
    let d = l
        .bundle
        .lookup_labels_full(&labels, &picket_rules::QueryCtx::default(), &l.pages);
    let r = d.reason.clone().unwrap();
    assert_eq!(r.kind, MatchKind::Subs);
    assert_eq!(r.key, ReasonKey::Suffix { labels: 2 });
    assert_eq!(r.key_text(&l.bundle, &labels), "ads.example");
    assert_eq!(&*r.head, head.as_str());
    assert!(matches!(r.part, PartId::Shard(_) | PartId::ColdShard(_)));
    let labels: Vec<&[u8]> = vec![b"banner7", b"example", b"net"];
    let d = l
        .bundle
        .lookup_labels_full(&labels, &picket_rules::QueryCtx::default(), &l.pages);
    let r = d.reason.unwrap();
    assert_eq!(r.kind, MatchKind::Pattern);
    assert_eq!(r.key_text(&l.bundle, &labels), "/^banner[0-9]+\\./");
    assert_eq!(r.part.key(), "segments/patterns.bin");
    let d = l
        .bundle
        .lookup_ip("1.2.3.4".parse().unwrap(), &picket_rules::QueryCtx::default());
    let r = d.reason.unwrap();
    assert_eq!((r.kind, r.key), (MatchKind::Ip, ReasonKey::Address));
    assert_eq!(r.part.key(), "ip_shards/v4/1");
    assert_eq!(d.cold, ColdCheck::NotApplicable);
}
