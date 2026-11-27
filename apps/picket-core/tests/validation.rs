//! Configuration validation rules (core.md §2 and the sections it links), through the store a
//! UI save uses: each rule refuses the save that breaks it, in either save order where two
//! entities are involved; one bad reference rejects a save; system objects can't be deleted;
//! the journal never holds a secret.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use picket_core::config::model::EntityKind;
use picket_core::config::{Actor, Op, store};
use picket_core::error::CoreError;
use serde_json::{Value, json};

struct Cfg {
    _dir: tempfile::TempDir,
    conn: rusqlite::Connection,
}

impl Cfg {
    fn new() -> Self {
        let (dir, _, _, _) = common::init_dir();
        let conn =
            picket_core::db::open_connection(&picket_core::db::DbOptions::core(dir.path()), 1024).unwrap();
        Self { _dir: dir, conn }
    }

    fn apply(&mut self, kind: EntityKind, op: Op) -> Result<store::Outcome, CoreError> {
        store::with_tx(&mut self.conn, |tx| {
            store::apply(tx, kind, op, &Actor::cli(), None)
        })
    }

    fn create(&mut self, kind: EntityKind, v: Value) -> Result<store::Outcome, CoreError> {
        self.apply(kind, Op::Create(v))
    }

    fn update(&mut self, kind: EntityKind, id: &str, v: Value) -> Result<store::Outcome, CoreError> {
        self.apply(kind, Op::Update(id.into(), v))
    }

    fn settings(&mut self, v: Value) -> Result<(), CoreError> {
        store::with_tx(&mut self.conn, |tx| {
            store::apply_settings(tx, &v, &Actor::cli(), false).map(|_| ())
        })
    }

    fn ok(&mut self, kind: EntityKind, v: Value) {
        if let Err(e) = self.create(kind, v.clone()) {
            panic!("{kind:?} {v}: {e}");
        }
    }
}

/// The refusal carries an issue with this code.
#[track_caller]
fn refused<T: std::fmt::Debug>(r: Result<T, CoreError>, code: &str) {
    match r {
        Err(CoreError::Validation(issues)) => {
            assert!(
                issues.iter().any(|i| i.code == code),
                "expected {code}, got {issues:?}"
            )
        }
        other => panic!("expected a refusal with {code}, got {other:?}"),
    }
}

/// A provider's stored listing, as a check that listed `files` stores it.
fn stored_listing(c: &Cfg, provider: &str, files: &[&str]) {
    c.conn
        .execute(
            "INSERT INTO feed_provider_state(provider_id, listing_json) VALUES (?1, ?2)
             ON CONFLICT(provider_id) DO UPDATE SET listing_json = excluded.listing_json",
            rusqlite::params![provider, json!({"files": files, "whole": true}).to_string()],
        )
        .unwrap();
}

fn bundle(id: &str, action: &str, feed: &str) -> Value {
    json!({"id": id, "name": id, "action": action, "feeds": [{"feed": feed}]})
}

fn feed(id: &str) -> Value {
    json!({"id": id, "name": id})
}

fn provider(id: &str) -> Value {
    json!({"id": id, "name": id, "module": "http_json",
           "config": {"url": "https://x/{domain}", "verdict": {"pointer": "/risk", "block_if": ">= 7"}}})
}

#[test]
fn profile_ids() {
    let mut c = Cfg::new();
    refused(
        c.create(EntityKind::Profile, json!({"id": "Kids", "name": "x"})),
        "bad_profile_id",
    );
    refused(
        c.create(EntityKind::Profile, json!({"id": "kids-full", "name": "x"})),
        "bad_profile_id",
    );
    refused(
        c.create(EntityKind::Profile, json!({"id": "a_b", "name": "x"})),
        "bad_profile_id",
    );
    c.ok(EntityKind::Profile, json!({"id": "kids", "name": "Kids"}));
    // Ids never change; renames keep them.
    assert!(matches!(
        c.update(
            EntityKind::Profile,
            "kids",
            json!({"id": "children", "name": "Kids"})
        ),
        Err(CoreError::Invalid(_))
    ));
    c.update(EntityKind::Profile, "kids", json!({"name": "Children"}))
        .unwrap();
}

#[test]
fn trial_bundles() {
    let mut c = Cfg::new();
    c.ok(EntityKind::Feed, feed("adult-feed"));
    c.ok(EntityKind::Bundle, bundle("adult", "block", "adult-feed"));
    // Not a block bundle; also in block.
    refused(
        c.create(
            EntityKind::Profile,
            json!({"id": "p", "name": "p", "trial_bundles": ["allow-common"]}),
        ),
        "trial_not_block",
    );
    refused(
        c.create(
            EntityKind::Profile,
            json!({"id": "p", "name": "p", "block": ["adult"], "trial_bundles": ["adult"]}),
        ),
        "trial_in_block",
    );
    // Another profile may still list it in block.
    c.ok(
        EntityKind::Profile,
        json!({"id": "strict", "name": "s", "block": ["adult"]}),
    );
    c.ok(
        EntityKind::Profile,
        json!({"id": "p", "name": "p", "trial_bundles": ["adult"]}),
    );

    // In the scope of the profile's sync attachment: refused.
    c.ok(EntityKind::LookupProvider, provider("lp"));
    refused(
        c.update(
            EntityKind::Profile,
            "p",
            json!({"name": "p", "trial_bundles": ["adult"],
            "lookup_providers": [{"provider": "lp", "mode": "sync", "exclude_bundles": ["adult"]}]}),
        ),
        "trial_in_sync_scope",
    );
    // An async attachment doesn't need it on the edge.
    c.update(
        EntityKind::Profile,
        "p",
        json!({"name": "p", "trial_bundles": ["adult"],
        "lookup_providers": [{"provider": "lp", "mode": "async", "exclude_bundles": ["adult"]}]}),
    )
    .unwrap();
    // Order 1: the profile attaches lp sync and trials adult; then lp's scope names adult.
    c.update(
        EntityKind::Profile,
        "p",
        json!({"name": "p", "trial_bundles": ["adult"], "lookup_providers": [{"provider": "lp", "mode": "sync"}]}),
    )
    .unwrap();
    let mut lp = provider("lp");
    lp["scope"] =
        json!({"include_bundles": [], "exclude_bundles": ["lookup-exclude", "adult"], "qtypes": ["A"]});
    refused(
        c.update(EntityKind::LookupProvider, "lp", lp.clone()),
        "trial_in_sync_scope",
    );
    // Order 2: lp's scope names adult first; then the profile trials it.
    c.update(
        EntityKind::Profile,
        "p",
        json!({"name": "p", "lookup_providers": [{"provider": "lp", "mode": "sync"}]}),
    )
    .unwrap();
    c.update(EntityKind::LookupProvider, "lp", lp).unwrap();
    refused(
        c.update(
            EntityKind::Profile,
            "p",
            json!({"name": "p", "trial_bundles": ["adult"], "lookup_providers": [{"provider": "lp", "mode": "sync"}]}),
        ),
        "trial_in_sync_scope",
    );
}

#[test]
fn mixed_group_refused() {
    let mut c = Cfg::new();
    c.ok(
        EntityKind::Upstream,
        json!({"id": "dnsmasq", "name": "d", "protocol": "udp", "ip": "127.0.0.1", "port": 53, "operator": "lan"}),
    );
    refused(
        c.create(
            EntityKind::UpstreamGroup,
            json!({"id": "g", "name": "g", "upstreams": ["dnsmasq", "cf-dot-1"]}),
        ),
        "mixed_group",
    );
    c.ok(
        EntityKind::UpstreamGroup,
        json!({"id": "local", "name": "l", "upstreams": ["dnsmasq"], "optimistic": false}),
    );
    // Changing a member's protocol later mixes the group: refused (the other order).
    refused(
        c.update(
            EntityKind::Upstream,
            "cf-dot-1",
            json!({"name": "x", "protocol": "udp", "ip": "1.1.1.1", "port": 53, "operator": "cloudflare"}),
        ),
        "plain_public",
    );
    c.ok(EntityKind::Upstream, json!({"id": "lan-dot", "name": "l", "protocol": "dot", "ip": "192.168.1.2", "port": 853, "tls_host": "dns.lan.example", "operator": "me"}));
    c.update(
        EntityKind::UpstreamGroup,
        "local",
        json!({"name": "l", "upstreams": ["dnsmasq"]}),
    )
    .unwrap();
    refused(
        c.update(
            EntityKind::UpstreamGroup,
            "local",
            json!({"name": "l", "upstreams": ["dnsmasq", "lan-dot"]}),
        ),
        "mixed_group",
    );
    // DoT/DoH need an operator.
    refused(c.create(EntityKind::Upstream, json!({"id": "q9", "name": "q", "protocol": "dot", "ip": "9.9.9.9", "port": 853, "tls_host": "dns.quad9.net"})), "operator_missing");
}

/// edge.md §6: a DoH path the edge sends as saved: absolute, RFC 3986 path characters, no dot
/// segment, query or fragment (`#x` used to be dropped on the way, a space made the config one
/// the edge couldn't apply).
#[test]
fn doh_paths_are_sent_as_saved() {
    let mut c = Cfg::new();
    let doh = |id: &str, path: &str| {
        json!({"id": id, "name": id, "protocol": "doh", "ip": "192.0.2.53", "port": 443,
               "tls_host": "dns.example", "path": path, "operator": "me"})
    };
    c.ok(EntityKind::Upstream, doh("ok", "/dns-query/v1:x@y"));
    for (i, bad) in [
        "/dns-query#x",
        "/dns query",
        "/a/../dns-query",
        "/a\\b",
        "dns-query",
    ]
    .iter()
    .enumerate()
    {
        refused(
            c.create(EntityKind::Upstream, doh(&format!("bad{i}"), bad)),
            "bad_path",
        );
    }
}

#[test]
fn managed_names_under_lanca_zones() {
    let mut c = Cfg::new();
    let fp = picket_api::ids::fingerprint_spki(b"e");
    c.ok(EntityKind::Edge, json!({"id": "e1", "name": "e1", "key": fp}));
    refused(
        c.create(
            EntityKind::Listener,
            json!({"id": "doh", "name": "doh", "proto": "doh", "bind": "192.168.1.1:9853",
            "tls": {"managed": "dns.example.com"}, "edges": ["e1"]}),
        ),
        "outside_lanca_zones",
    );
    c.ok(
        EntityKind::Listener,
        json!({"id": "doh", "name": "doh", "proto": "doh", "bind": "192.168.1.1:9853",
        "tls": {"managed": "dns.home.arpa"}, "api": true, "edges": ["e1"]}),
    );
    refused(
        c.settings(json!({"web": {"names": ["core.example.com"]}})),
        "bad_setting",
    );
    c.settings(json!({"web": {"names": ["core.home.arpa"]}})).unwrap();
    // Listener shape rules.
    refused(
        c.create(
            EntityKind::Listener,
            json!({"id": "x", "name": "x", "proto": "dns", "bind": "nope"}),
        ),
        "bad_bind",
    );
    refused(
        c.create(
            EntityKind::Listener,
            json!({"id": "y", "name": "y", "proto": "dot", "bind": "[::]:853"}),
        ),
        "tls_missing",
    );
    refused(
        c.create(
            EntityKind::Listener,
            json!({"id": "z", "name": "z", "proto": "dns", "bind": "[::]:5335", "api": true}),
        ),
        "api_not_doh",
    );
    refused(
        c.create(
            EntityKind::Listener,
            json!({"id": "w", "name": "w", "proto": "dns", "bind": "192.168.1.1:9853", "edges": ["e1"]}),
        ),
        "bind_conflict",
    );
    refused(
        c.create(
            EntityKind::Listener,
            json!({"id": "v", "name": "v", "proto": "dns", "bind": "[::]:53", "edges": ["nope"]}),
        ),
        "unknown_edge",
    );
}

#[test]
fn warn_on_names_only_warn_bundles_in_either_order() {
    let mut c = Cfg::new();
    refused(
        c.create(
            EntityKind::Feed,
            json!({"id": "f", "name": "f", "warn_on": ["block-common"]}),
        ),
        "warn_on_not_warn",
    );
    // The default for a security feed is warn-common.
    c.ok(
        EntityKind::Feed,
        json!({"id": "tif", "name": "t", "category": "security"}),
    );
    c.ok(EntityKind::Feed, feed("w2"));
    c.ok(EntityKind::Bundle, bundle("my-warn", "warn", "w2"));
    c.ok(
        EntityKind::Feed,
        json!({"id": "f", "name": "f", "warn_on": ["my-warn"]}),
    );
    // The bundle stops being a warn bundle: refused.
    refused(
        c.update(EntityKind::Bundle, "my-warn", bundle("my-warn", "block", "w2")),
        "warn_on_not_warn",
    );
}

#[test]
fn tiers_only_on_block_bundles() {
    let mut c = Cfg::new();
    c.ok(EntityKind::Feed, feed("f"));
    refused(
        c.create(
            EntityKind::Bundle,
            json!({"id": "a", "name": "a", "action": "allow", "feeds": [{"feed": "f", "tier": "cold"}]}),
        ),
        "tier_not_block",
    );
    refused(
        c.create(
            EntityKind::Bundle,
            json!({"id": "a", "name": "a", "action": "scope", "hot_max_mib": 8, "feeds": [{"feed": "f"}]}),
        ),
        "tier_not_block",
    );
    c.ok(EntityKind::Bundle, json!({"id": "b", "name": "b", "action": "block", "hot_max_mib": 8, "feeds": [{"feed": "f", "tier": "intelligent-tiering"}]}));
    refused(
        c.create(
            EntityKind::Bundle,
            json!({"id": "c", "name": "c", "action": "block", "feeds": [{"feed": "nope"}]}),
        ),
        "unknown_feed",
    );
    // System bundles keep their action.
    refused(
        c.update(
            EntityKind::Bundle,
            "block-common",
            bundle("block-common", "allow", "manual-block"),
        ),
        "system_action",
    );
}

#[test]
fn lookup_scopes() {
    let mut c = Cfg::new();
    c.ok(EntityKind::Feed, feed("f"));
    c.ok(EntityKind::Bundle, bundle("hot-block", "block", "f"));
    c.ok(
        EntityKind::Bundle,
        json!({"id": "cold", "name": "c", "action": "block", "feeds": [{"feed": "f", "tier": "cold"}]}),
    );
    let mut lp = provider("lp");
    lp["scope"] = json!({"include_bundles": ["warn-common"], "exclude_bundles": []});
    refused(c.create(EntityKind::LookupProvider, lp), "scope_warn");
    let mut lp = provider("lp");
    lp["scope"] = json!({"include_bundles": ["cold"], "exclude_bundles": []});
    refused(c.create(EntityKind::LookupProvider, lp), "scope_cold");
    // Order 2: the scope names a hot bundle, which then gets a cold part.
    let mut lp = provider("lp");
    lp["scope"] = json!({"include_bundles": ["hot-block"], "exclude_bundles": ["lookup-exclude"]});
    c.ok(EntityKind::LookupProvider, lp);
    refused(
        c.update(
            EntityKind::Bundle,
            "hot-block",
            json!({"name": "h", "action": "block", "feeds": [{"feed": "f", "tier": "cold"}]}),
        ),
        "scope_cold",
    );
    // intelligent-tiering only counts with hot_max_mib.
    c.update(
        EntityKind::Bundle,
        "hot-block",
        json!({"name": "h", "action": "block", "feeds": [{"feed": "f", "tier": "intelligent-tiering"}]}),
    )
    .unwrap();
    refused(
        c.update(EntityKind::Bundle, "hot-block", json!({"name": "h", "action": "block", "hot_max_mib": 4, "feeds": [{"feed": "f", "tier": "intelligent-tiering"}]})),
        "scope_cold",
    );
    // Attachment scopes alike.
    refused(
        c.create(EntityKind::Profile, json!({"id": "p", "name": "p", "lookup_providers": [{"provider": "lp", "mode": "async", "include_bundles": ["cold"]}]})),
        "scope_cold",
    );
    // A profile can't list scope (or warn) bundles in allow/block.
    refused(
        c.create(
            EntityKind::Profile,
            json!({"id": "p", "name": "p", "block": ["lookup-exclude"]}),
        ),
        "wrong_action",
    );
    refused(
        c.create(
            EntityKind::Profile,
            json!({"id": "p", "name": "p", "allow": ["warn-common"]}),
        ),
        "wrong_action",
    );
}

#[test]
fn unifi_redirect_rules() {
    let mut c = Cfg::new();
    let fp = picket_api::ids::fingerprint_spki(b"e");
    c.ok(EntityKind::Edge, json!({"id": "e1", "name": "e1", "key": fp}));
    refused(
        c.update(
            EntityKind::Edge,
            "e1",
            json!({"name": "e1", "key": fp, "unifi": {"redirect": {"interfaces": ["br0"]}}}),
        ),
        "redirect_needs_firewall",
    );
    let fw = json!({"interfaces": [{"name": "br0", "mode": "monitor"}]});
    refused(
        c.update(
            EntityKind::Edge,
            "e1",
            json!({"name": "e1", "key": fp, "firewall": fw, "unifi": {"redirect": {"interfaces": ["br0"]}}}),
        ),
        "redirect_listener",
    );
    c.ok(EntityKind::Listener, json!({"id": "lan-dns", "name": "dns", "proto": "dns", "bind": "[::]:5335", "interfaces": ["br0", "br2"], "edges": ["e1"]}));
    c.update(EntityKind::Edge, "e1", json!({"name": "e1", "key": fp, "firewall": fw, "unifi": {"redirect": {"interfaces": ["br0", "br2"]}}})).unwrap();
    // The listener drops an interface the redirect needs: refused (the other order).
    refused(
        c.update(EntityKind::Listener, "lan-dns", json!({"name": "dns", "proto": "dns", "bind": "[::]:5335", "interfaces": ["br0"], "edges": ["e1"]})),
        "redirect_listener",
    );
    // Debian edges have no UniFi options.
    let fp2 = picket_api::ids::fingerprint_spki(b"e2");
    refused(
        c.create(EntityKind::Edge, json!({"id": "e2", "name": "e2", "key": fp2, "platform": "debian", "firewall": fw, "unifi": {"redirect": {"interfaces": ["br0"]}}})),
        "redirect_not_unifi",
    );
}

#[test]
fn crosscheck_resolver_independence_in_either_order() {
    let mut c = Cfg::new();
    let resolver = |op: &str, ip: &str, host: &str| json!({"crosscheck": {"enabled": true, "resolver": {"protocol": "dot", "ip": ip, "tls_host": host, "operator": op}}});
    refused(
        c.settings(resolver("Cloudflare", "9.9.9.10", "dns10.quad9.net")),
        "crosscheck_operator",
    );
    refused(
        c.settings(resolver("quad9", "1.1.1.1", "dns10.quad9.net")),
        "crosscheck_ip",
    );
    refused(
        c.settings(resolver("quad9", "9.9.9.10", "x.cloudflare-dns.com")),
        "crosscheck_domain",
    );
    c.settings(resolver("quad9", "9.9.9.10", "dns10.quad9.net"))
        .unwrap();
    // Then an upstream by the same operator, IP or registrable domain is refused.
    refused(
        c.create(EntityKind::Upstream, json!({"id": "q9", "name": "q", "protocol": "dot", "ip": "9.9.9.9", "port": 853, "tls_host": "dns.quad9.net", "operator": "other"})),
        "crosscheck_domain",
    );
    refused(
        c.create(EntityKind::Upstream, json!({"id": "q9", "name": "q", "protocol": "dot", "ip": "149.112.112.112", "port": 853, "tls_host": "dns.example.net", "operator": "QUAD9"})),
        "crosscheck_operator",
    );
    refused(
        c.create(EntityKind::Upstream, json!({"id": "q9", "name": "q", "protocol": "dot", "ip": "9.9.9.10", "port": 853, "tls_host": "dns.example.net", "operator": "x"})),
        "crosscheck_ip",
    );
    c.ok(EntityKind::Upstream, json!({"id": "g", "name": "g", "protocol": "dot", "ip": "8.8.8.8", "port": 853, "tls_host": "dns.google", "operator": "google"}));
    // Enabling without a resolver is refused too.
    let mut c = Cfg::new();
    refused(
        c.settings(json!({"crosscheck": {"enabled": true}})),
        "bad_setting",
    );
}

#[test]
fn references_clients_and_settings() {
    let mut c = Cfg::new();
    // One bad reference rejects the save.
    refused(
        c.create(
            EntityKind::Client,
            json!({"name": "pc", "macs": ["aa:bb:cc:dd:ee:01"], "profile": "nope"}),
        ),
        "unknown_profile",
    );
    refused(c.create(EntityKind::Client, json!({"name": "pc"})), "no_devices");
    refused(
        c.create(EntityKind::Client, json!({"name": "pc", "macs": ["zz"]})),
        "bad_mac",
    );
    c.ok(
        EntityKind::Client,
        json!({"name": "pc", "macs": ["AA-BB-CC-DD-EE-01"], "profile": "default", "tags": ["office"]}),
    );
    refused(
        c.create(
            EntityKind::Client,
            json!({"name": "pc2", "macs": ["aa:bb:cc:dd:ee:01"]}),
        ),
        "duplicate_mac",
    );
    // allowed_sources may name clients; an unknown name is refused.
    c.ok(EntityKind::Profile, json!({"id": "adults", "name": "A", "allowed_sources": ["pc", "192.168.1.0/24", "aa:bb:cc:dd:ee:02"]}));
    refused(
        c.create(
            EntityKind::Profile,
            json!({"id": "x", "name": "x", "allowed_sources": ["nobody"]}),
        ),
        "bad_source",
    );
    // Deleting a referenced client or profile is refused.
    refused(c.apply(EntityKind::Client, Op::Delete("pc".into())), "bad_source");
    refused(
        c.apply(EntityKind::Profile, Op::Delete("default".into())),
        "unknown_profile",
    );
    refused(c.settings(json!({"default_profile": "nope"})), "unknown_profile");
    // The dnssec-validator profile stays unfiltered.
    refused(
        c.update(
            EntityKind::Profile,
            "dnssec-validator",
            json!({"name": "v", "block": ["block-common"], "log": "off", "firewall": {"add_entries": false}}),
        ),
        "validator_filtered",
    );
}

#[test]
fn system_objects_and_journal() {
    let mut c = Cfg::new();
    for (kind, id) in [
        (EntityKind::Feed, "canaries"),
        (EntityKind::Feed, "lookup-exclude"),
        (EntityKind::Bundle, "warn-common"),
        (EntityKind::Profile, "dnssec-validator"),
        (EntityKind::UpstreamGroup, "cloudflare"),
    ] {
        assert!(
            matches!(c.apply(kind, Op::Delete(id.into())), Err(CoreError::Forbidden(_))),
            "{id}"
        );
    }
    // System objects can be edited.
    c.update(EntityKind::Feed, "canaries", json!({"name": "Canaries (edited)"}))
        .unwrap();
    // Secrets never reach the journal; credential-looking config fields are masked.
    store::with_tx(&mut c.conn, |tx| {
        store::set_secret(tx, None, "am_rt", "VERY-SECRET", &Actor::cli())
    })
    .unwrap();
    let mut lp = provider("lp");
    lp["config"] = json!({"url": "https://x/{domain}", "headers": {"Authorization": "Bearer ${secret:am_rt}", "X-Token": "inline-token-123"},
                          "verdict": {"pointer": "/risk", "block_if": ">= 7"}});
    // A credential written in clear is refused (README §2 Secrets).
    refused(
        c.create(EntityKind::LookupProvider, lp.clone()),
        "literal_credential",
    );
    lp["config"]["headers"]["X-Token"] = json!("${secret:am_rt}");
    c.ok(EntityKind::LookupProvider, lp);
    let journal: Vec<String> = {
        let mut st = c.conn.prepare("SELECT diff_json FROM config_changes").unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    let all = journal.join("\n");
    assert!(!all.contains("VERY-SECRET"));
    assert!(!all.contains("inline-token-123"));
    assert!(all.contains("${secret:am_rt}"));
    // A provider save with a config change moves its cache generation on; a settings-only one keeps it.
    let m = store::load_model(&c.conn).unwrap();
    let g1 = m.lookup_providers["lp"].cache_generation.clone();
    let mut lp = provider("lp");
    lp["config"] = json!({"url": "https://x/{domain}", "headers": {"Authorization": "Bearer ${secret:am_rt}", "X-Token": "${secret:am_rt}"},
                          "verdict": {"pointer": "/risk", "block_if": ">= 7"}});
    lp["sync_timeout_ms"] = json!(200);
    c.update(EntityKind::LookupProvider, "lp", lp).unwrap();
    let g2 = store::load_model(&c.conn).unwrap().lookup_providers["lp"]
        .cache_generation
        .clone();
    assert_eq!(g1, g2);
    c.update(EntityKind::LookupProvider, "lp", provider("lp"))
        .unwrap();
    let g3 = store::load_model(&c.conn).unwrap().lookup_providers["lp"]
        .cache_generation
        .clone();
    assert_ne!(g2, g3);
}

#[test]
fn a_problem_left_by_an_older_release_doesnt_block_other_saves() {
    let mut c = Cfg::new();
    // Break the model behind the store's back (as an older release might have stored it).
    c.conn
        .execute(
            "UPDATE profiles SET body_json = json_set(body_json, '$.upstream', 'gone') WHERE id = 'default'",
            [],
        )
        .unwrap();
    // An unrelated save still goes through; one that adds a new problem doesn't.
    c.ok(EntityKind::Feed, feed("unrelated"));
    refused(
        c.create(
            EntityKind::Profile,
            json!({"id": "p2", "name": "p", "upstream": "nope"}),
        ),
        "unknown_group",
    );
}

#[test]
fn client_names_cant_look_like_sources() {
    // allowed_sources mixes ranges, MACs and client names, so a client name must be neither.
    let mut c = Cfg::new();
    for name in [
        "192.168.1.5",
        "10.0.0.0/8",
        "fd00::1",
        "aa:bb:cc:dd:ee:ff",
        "AA-BB-CC-DD-EE-FF",
        " pc",
        "pc ",
    ] {
        refused(
            c.create(
                EntityKind::Client,
                json!({"name": name, "macs": ["aa:bb:cc:dd:ee:01"]}),
            ),
            "bad_client_name",
        );
    }
    c.ok(
        EntityKind::Client,
        json!({"name": "office pc", "macs": ["aa:bb:cc:dd:ee:01"]}),
    );
}

#[test]
fn listener_limits_are_bounded() {
    let mut c = Cfg::new();
    for limits in [
        json!({"udp_payload": 8192}),
        json!({"idle_timeout_ms": 500}),
        json!({"idle_timeout_ms": 7_200_000}),
    ] {
        refused(
            c.create(
                EntityKind::Listener,
                json!({"id": "l", "name": "l", "proto": "dns", "bind": "[::]:5335", "limits": limits}),
            ),
            "range",
        );
    }
    c.ok(
        EntityKind::Listener,
        json!({"id": "l", "name": "l", "proto": "dns", "bind": "[::]:5335", "limits": {"udp_payload": 4096, "idle_timeout_ms": 3_600_000}}),
    );
}

fn a_certificate() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    rcgen::CertificateParams::new(vec!["ca.example".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .pem()
}

#[test]
fn trust_stores_must_hold_certificates() {
    let mut c = Cfg::new();
    let garbage = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n";
    let up = |ts: &str| {
        json!({"id": "q9", "name": "q", "protocol": "dot", "ip": "9.9.9.9", "port": 853,
               "tls_host": "dns.quad9.net", "operator": "quad9", "trust_store": ts})
    };
    refused(c.create(EntityKind::Upstream, up(garbage)), "bad_trust_store");
    c.ok(EntityKind::Upstream, up(&a_certificate()));
    // The resolver's trust store too.
    let resolver = |ts: &str| json!({"resolver": {"protocol": "dot", "ip": "9.9.9.9", "port": 853, "tls_host": "dns.quad9.net", "trust_store": ts}});
    refused(c.settings(resolver(garbage)), "bad_setting");
    c.settings(resolver(&a_certificate())).unwrap();
}

#[test]
fn every_upstream_names_its_operator() {
    // edge.md §6: presets fill `operator`; a custom endpoint must set it, plain ones included.
    let mut c = Cfg::new();
    let plain = |op: Option<&str>| {
        let mut v = json!({"id": "dnsmasq", "name": "d", "protocol": "udp", "ip": "127.0.0.1", "port": 53});
        if let Some(op) = op {
            v["operator"] = json!(op);
        }
        v
    };
    refused(c.create(EntityKind::Upstream, plain(None)), "operator_missing");
    refused(
        c.create(EntityKind::Upstream, plain(Some("my lan!"))),
        "bad_operator",
    );
    c.ok(EntityKind::Upstream, plain(Some("lan")));
}

#[test]
fn forward_zones_conflict_only_within_a_profile() {
    let mut c = Cfg::new();
    c.ok(EntityKind::Upstream, json!({"id": "dnsmasq", "name": "d", "protocol": "udp", "ip": "127.0.0.1", "port": 53, "operator": "lan"}));
    c.ok(EntityKind::Upstream, json!({"id": "other", "name": "o", "protocol": "udp", "ip": "192.168.1.3", "port": 53, "operator": "lan"}));
    c.ok(
        EntityKind::UpstreamGroup,
        json!({"id": "local", "name": "l", "upstreams": ["dnsmasq"]}),
    );
    c.ok(
        EntityKind::UpstreamGroup,
        json!({"id": "local2", "name": "l2", "upstreams": ["other"]}),
    );
    // Two profiles may route one zone to different groups.
    c.ok(
        EntityKind::ForwardZone,
        json!({"id": "lan-a", "zone": "lan", "group": "local"}),
    );
    c.ok(
        EntityKind::ForwardZone,
        json!({"id": "lan-b", "zone": "lan", "group": "local2"}),
    );
    c.ok(
        EntityKind::Profile,
        json!({"id": "a", "name": "a", "forward_zones": ["lan-a"]}),
    );
    c.ok(
        EntityKind::Profile,
        json!({"id": "b", "name": "b", "forward_zones": ["lan-b"]}),
    );
    // One profile can't route it twice.
    refused(
        c.create(
            EntityKind::Profile,
            json!({"id": "c", "name": "c", "forward_zones": ["lan-a", "lan-b"]}),
        ),
        "duplicate_zone",
    );
}

#[test]
fn profile_warnings() {
    let mut c = Cfg::new();
    let out = c
        .create(
            EntityKind::Profile,
            json!({"id": "nobody", "name": "n", "allowed_sources": []}),
        )
        .unwrap();
    assert!(
        out.warnings.iter().any(|w| w.code == "no_sources"),
        "{:?}",
        out.warnings
    );
    // core.md §12: custom_ip under firewall entries reaches the block page only via static_allow.
    let out = c
        .create(
            EntityKind::Profile,
            json!({"id": "page", "name": "p", "block_response": {"type": "custom_ip", "ipv4": "192.168.1.9"}}),
        )
        .unwrap();
    assert!(
        out.warnings.iter().any(|w| w.code == "custom_ip_firewall"),
        "{:?}",
        out.warnings
    );
    // The validator profile admits only core: no warning for it.
    let issues =
        picket_core::config::validate::validate(&picket_core::config::store::load_model(&c.conn).unwrap());
    assert!(
        !issues
            .iter()
            .any(|i| i.id == "dnssec-validator" && i.code == "no_sources")
    );
}

#[test]
fn bundle_rule_types() {
    let mut c = Cfg::new();
    c.ok(EntityKind::Feed, feed("f"));
    refused(
        c.create(
            EntityKind::Bundle,
            json!({"id": "b", "name": "b", "action": "block", "feeds": [{"feed": "f", "rule_types": ["dns", "dns"]}]}),
        ),
        "duplicate",
    );
    let out = c
        .create(
            EntityKind::Bundle,
            json!({"id": "s", "name": "s", "action": "scope", "feeds": [{"feed": "f", "rule_types": ["dns", "ip"]}]}),
        )
        .unwrap();
    assert!(
        out.warnings.iter().any(|w| w.code == "scope_dns_only"),
        "{:?}",
        out.warnings
    );
}

/// A feed provider body.
fn fp(id: &str, module: &str, cfg: Value) -> Value {
    json!({"id": id, "name": id, "module": module, "config": cfg})
}

#[test]
fn feed_provider_configs() {
    // security.md §4: downloads are HTTPS only; providers.md §3: each module's config.
    let mut c = Cfg::new();
    refused(
        c.create(
            EntityKind::FeedProvider,
            fp("h1", "http", json!({"url": "http://lists.example/l.txt"})),
        ),
        "bad_config",
    );
    refused(
        c.create(EntityKind::FeedProvider, fp("h2", "http", json!({}))),
        "bad_config",
    );
    refused(
        c.create(EntityKind::FeedProvider, fp("m1", "manual", json!({}))),
        "unknown_module",
    );
    refused(
        c.create(
            EntityKind::FeedProvider,
            fp("g1", "github", json!({"owner": "o"})),
        ),
        "bad_config",
    );
    refused(
        c.create(
            EntityKind::FeedProvider,
            fp("a1", "alphamountain_threat_1000", json!({"url": "ftp://x"})),
        ),
        "bad_config",
    );
    c.ok(
        EntityKind::FeedProvider,
        fp("h3", "http", json!({"url": "https://lists.example/l.txt"})),
    );
    c.ok(
        EntityKind::FeedProvider,
        fp("g2", "github", json!({"owner": "o", "repo": "r"})),
    );
    // providers.md §3: alphamountain_threat_1000 writes a plain file, so its feed's format must
    // be plain; its one file `community-threat-1000` is selected by default and becomes a feed
    // at once.
    let mut a2 = fp("a2", "alphamountain_threat_1000", json!({"min_risk_score": 7.0}));
    a2["files"] = json!([{"match": "community-threat-1000", "feed": {"format": "adblock"}}]);
    refused(
        c.create(EntityKind::FeedProvider, a2.clone()),
        "format_must_be_plain",
    );
    a2["files"] = json!([]);
    let out = c.create(EntityKind::FeedProvider, a2).unwrap();
    assert_eq!(
        out.feeds_added,
        vec!["a2"],
        "a provider of one fixed file: its id"
    );
    let m = store::load_model(&c.conn).unwrap();
    let f = &m.feeds["a2"];
    assert_eq!(f.format, picket_core::config::model::FeedFormat::Plain);
    assert_eq!(f.file.as_deref(), Some("community-threat-1000"));
    // No file name is empty or blank, whatever the module: a files entry `""` or `" "` is
    // refused as such (github paths and globs too).
    for (id, module, config) in [
        ("e1", "http", json!({"url": "https://lists.example/l.txt"})),
        ("e2", "github", json!({"owner": "o", "repo": "r"})),
        ("e3", "alphamountain_threat_1000", json!({})),
    ] {
        for blank in ["", " ", "\t "] {
            let mut p = fp(id, module, config.clone());
            p["files"] = json!([{"match": blank, "feed": {"format": "plain"}}]);
            refused(c.create(EntityKind::FeedProvider, p), "empty_file");
        }
    }
}

#[test]
fn feed_provider_rules() {
    // providers.md §2–§3, feeds.md §1, feed-scheduling.md §7.
    let mut c = Cfg::new();
    // An http provider is one URL: its one file is `response`; globs need a module that lists
    // files.
    let mut w = fp("web", "http", json!({"url": "https://lists.example/a/x.txt"}));
    w["files"] = json!([{"match": "x.txt", "feed": {"format": "plain"}}]);
    refused(c.create(EntityKind::FeedProvider, w.clone()), "bad_file");
    w["files"] = json!([{"match": "*.txt", "feed": {"format": "plain"}}]);
    refused(
        c.create(EntityKind::FeedProvider, w.clone()),
        "glob_needs_listing",
    );
    w["files"] = json!([{"match": "response"}]);
    refused(c.create(EntityKind::FeedProvider, w.clone()), "bad_feed");
    w["files"] = json!([{"match": "response", "feed": {"format": "hosts"}}]);
    let out = c.create(EntityKind::FeedProvider, w).unwrap();
    // feeds.md §1: its feed takes the provider's id and, by default, its name.
    assert_eq!(out.feeds_added, vec!["web"]);
    let m = store::load_model(&c.conn).unwrap();
    assert_eq!(m.feeds["web"].name, "web");
    assert_eq!(
        m.feeds["web"].format,
        picket_core::config::model::FeedFormat::Hosts
    );
    // A provider of several files (`github`, from its stored listing): each selected file is a
    // feed, named after the file.
    c.ok(
        EntityKind::FeedProvider,
        fp("lists", "github", json!({"owner": "o", "repo": "r"})),
    );
    stored_listing(&c, "lists", &["x.txt", "y.txt", "z.txt"]);
    // A files entry may name its feeds (as presets do): the name applies whenever a listing
    // adds the feed.
    let mut h = fp("lists", "github", json!({"owner": "o", "repo": "r"}));
    h["files"] = json!([{"match": "x.txt", "feed": {"format": "plain"}}, {"match": "y.txt", "feed": {"format": "hosts", "name": "Why list"}}]);
    let out = c.update(EntityKind::FeedProvider, "lists", h.clone()).unwrap();
    assert_eq!(out.feeds_added, vec!["lists-x", "lists-y"]);
    let m = store::load_model(&c.conn).unwrap();
    assert_eq!(m.feeds["lists-x"].name, "x.txt");
    assert_eq!(m.feeds["lists-y"].name, "Why list");
    assert_eq!(
        m.feeds["lists-y"].format,
        picket_core::config::model::FeedFormat::Hosts
    );
    // A provider can't be deleted while a feed uses it.
    let r = c.apply(EntityKind::FeedProvider, Op::Delete("lists".into()));
    assert!(matches!(r, Err(CoreError::Conflict(_))), "{r:?}");
    // A feed's provider and file never change; POST feeds makes manual feeds only.
    let r = c.update(
        EntityKind::Feed,
        "lists-x",
        json!({"name": "X", "format": "plain", "provider": "other"}),
    );
    assert!(matches!(r, Err(CoreError::Invalid(_))), "{r:?}");
    let r = c.update(
        EntityKind::Feed,
        "lists-x",
        json!({"name": "X", "format": "plain", "file": "y.txt"}),
    );
    assert!(matches!(r, Err(CoreError::Invalid(_))), "{r:?}");
    let out = c
        .update(
            EntityKind::Feed,
            "lists-x",
            json!({"name": "X", "format": "plain"}),
        )
        .unwrap();
    assert_eq!(out.entity.unwrap()["provider"], "lists", "read-only fields stay");
    let r = c.create(
        EntityKind::Feed,
        json!({"id": "f", "name": "f", "provider": "lists", "file": "z.txt"}),
    );
    assert!(matches!(r, Err(CoreError::Invalid(_))), "{r:?}");
    // Two feeds of one provider can't name one file (as stored by an older save).
    c.conn
        .execute(
            "INSERT INTO feeds(id, name, category, enabled, provider_id, file, format, format_options_json, modes_json,
                rule_policy_json, sanity_json) SELECT 'dup', name, category, enabled, provider_id, 'x2.txt', format,
                format_options_json, modes_json, rule_policy_json, sanity_json FROM feeds WHERE id = 'lists-x'",
            [],
        )
        .unwrap();
    let mut m = store::load_model(&c.conn).unwrap();
    m.feeds.get_mut("dup").unwrap().file = Some("x.txt".into());
    let issues = picket_core::config::validate::validate(&m);
    assert!(issues.iter().any(|i| i.code == "duplicate_file"), "{issues:?}");
    c.conn.execute("DELETE FROM feeds WHERE id = 'dup'", []).unwrap();
    // A provider feed's file is never empty or blank (as stored by an older save, or
    // hand-written).
    for blank in ["", "  "] {
        let mut m = store::load_model(&c.conn).unwrap();
        m.feeds.get_mut("lists-x").unwrap().file = Some(blank.into());
        let issues = picket_core::config::validate::validate(&m);
        assert!(
            issues
                .iter()
                .any(|i| i.code == "empty_file" && i.field.as_deref() == Some("file")),
            "{blank:?}: {issues:?}"
        );
    }
    // Deleting a provider feed adds its file to the provider's exclude, so it doesn't come back.
    c.apply(EntityKind::Feed, Op::Delete("lists-y".into())).unwrap();
    let m = store::load_model(&c.conn).unwrap();
    assert_eq!(m.feed_providers["lists"].exclude, vec!["y.txt"]);
    assert!(!m.feeds.contains_key("lists-y"));
    // An edit that stops selecting feeds asks first (409), then deletes them.
    let mut h2 = serde_json::to_value(&m.feed_providers["lists"]).unwrap();
    h2["files"] = json!([{"match": "y.txt", "feed": {"format": "hosts"}}]);
    let r = c.update(EntityKind::FeedProvider, "lists", h2.clone());
    assert!(
        matches!(r, Err(CoreError::Conflict(ref m)) if m.contains("lists-x")),
        "{r:?}"
    );
    let out = store::with_tx(&mut c.conn, |tx| {
        store::apply_with(
            tx,
            EntityKind::FeedProvider,
            Op::Update("lists".into(), h2.clone()),
            &Actor::cli(),
            store::SaveOpts {
                delete_unselected: true,
                ..Default::default()
            },
        )
    })
    .unwrap();
    assert_eq!(out.feeds_deleted, vec!["lists-x"]);
    assert!(out.feeds_added.is_empty(), "y.txt is still excluded");
    // Overlapping providers save with a warning naming the other: http providers of one URL (as
    // matched: scheme and host lowercase); a URL is no folder, so another under it is none.
    let out = c
        .create(
            EntityKind::FeedProvider,
            fp("web2", "http", json!({"url": "HTTPS://Lists.Example/a/x.txt"})),
        )
        .unwrap();
    assert!(
        out.warnings
            .iter()
            .any(|w| w.code == "overlap" && w.message.contains("web")),
        "{:?}",
        out.warnings
    );
    let out = c
        .create(
            EntityKind::FeedProvider,
            fp("web3", "http", json!({"url": "https://lists.example/a/x.txt/y"})),
        )
        .unwrap();
    assert!(
        !out.warnings.iter().any(|w| w.code == "overlap"),
        "{:?}",
        out.warnings
    );
    c.ok(
        EntityKind::FeedProvider,
        fp("hz1", "github", json!({"owner": "HaGeZi", "repo": "x"})),
    );
    let out = c
        .create(
            EntityKind::FeedProvider,
            fp(
                "hz2",
                "github",
                json!({"owner": "hagezi", "repo": "x", "branch": "dev"}),
            ),
        )
        .unwrap();
    assert!(
        out.warnings
            .iter()
            .any(|w| w.code == "overlap" && w.message.contains("hz1")),
        "{:?}",
        out.warnings
    );
    // sqs: the queue URL's form, its keys as secrets, one provider per queue.
    let sqs = |id: &str, url: &str, key: &str| {
        let mut p = fp(id, "http", json!({"url": "https://sqs-lists.example/l.txt"}));
        p["trigger"] = json!({"kind": "sqs", "queue_url": url, "access_key_id": key, "secret_access_key": "${secret:aws_key}"});
        p
    };
    refused(
        c.create(
            EntityKind::FeedProvider,
            sqs(
                "q1",
                "https://sqs.eu-west-1.amazonaws.com/123/x",
                "${secret:aws_id}",
            ),
        ),
        "bad_queue_url",
    );
    refused(
        c.create(
            EntityKind::FeedProvider,
            sqs(
                "q1",
                "https://sqs.eu-west-1.amazonaws.com/123456789012/lists",
                "AKIDLITERAL",
            ),
        ),
        "secret_required",
    );
    c.ok(
        EntityKind::FeedProvider,
        sqs(
            "q1",
            "https://sqs.eu-west-1.amazonaws.com/123456789012/lists",
            "${secret:aws_id}",
        ),
    );
    refused(
        c.create(
            EntityKind::FeedProvider,
            sqs(
                "q2",
                "https://sqs.eu-west-1.amazonaws.com/123456789012/lists",
                "${secret:aws_id}",
            ),
        ),
        "queue_shared",
    );
    // The cap: at most feeds.max_per_provider feeds; past it, none is created and the save says so.
    c.settings(json!({"feeds": {"max_per_provider": 2}})).unwrap();
    c.ok(
        EntityKind::FeedProvider,
        fp("many", "github", json!({"owner": "o", "repo": "many"})),
    );
    stored_listing(&c, "many", &["a.txt", "b.txt", "c.txt"]);
    let mut many = fp("many", "github", json!({"owner": "o", "repo": "many"}));
    many["files"] = json!([
        {"match": "a.txt", "feed": {"format": "plain"}},
        {"match": "b.txt", "feed": {"format": "plain"}},
        {"match": "c.txt", "feed": {"format": "plain"}}
    ]);
    let out = c.update(EntityKind::FeedProvider, "many", many).unwrap();
    assert_eq!(out.feeds_added.len(), 2);
    assert!(
        out.warnings.iter().any(|w| w.code == "feed_cap"),
        "{:?}",
        out.warnings
    );
    let skipped: String = c
        .conn
        .query_row(
            "SELECT skipped_json FROM feed_provider_state WHERE provider_id = 'many'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(skipped, "[\"c.txt\"]");
}

#[test]
fn feed_provider_triggers_take_min_interval() {
    // feed-scheduling.md: every trigger kind takes `min_interval` (default 2 min), a floor
    // between checks.
    let mut c = Cfg::new();
    let f = |trigger: Value| {
        let mut p = fp("c", "http", json!({"url": "https://x.example/l.txt"}));
        p["trigger"] = trigger;
        p
    };
    refused(
        c.create(
            EntityKind::FeedProvider,
            f(json!({"kind": "cron", "cron": "17 */6 * * *", "min_interval": "10s"})),
        ),
        "range",
    );
    refused(
        c.create(
            EntityKind::FeedProvider,
            f(json!({"kind": "cron", "cron": "nope"})),
        ),
        "bad_cron",
    );
    let out = c
        .create(
            EntityKind::FeedProvider,
            f(json!({"kind": "cron", "cron": "17 */6 * * *", "jitter": "5m", "min_interval": "5m"})),
        )
        .unwrap();
    assert_eq!(out.entity.unwrap()["trigger"]["min_interval"], "5m");
    let m = store::load_model(&c.conn).unwrap();
    assert_eq!(m.feed_providers["c"].trigger.min_interval().as_secs(), 300);
}

#[test]
fn croner_4_cron_shapes_stay_valid() {
    // jiff plan choice D1 (croner 4 → 5): a stored trigger croner 4 ran keeps validating, including
    // names outside their own field and a bare `L` in day-of-week, which croner 5 refuses alone.
    let mut c = Cfg::new();
    for (i, cron) in [
        "0 0 * * jan",
        "0 0 * mon *",
        "mon * * * *",
        "0 0 * * 1,L",
        "0 0 1 * L",
    ]
    .iter()
    .enumerate()
    {
        let mut p = fp(
            &format!("c{i}"),
            "http",
            json!({"url": "https://x.example/l.txt"}),
        );
        p["trigger"] = json!({"kind": "cron", "cron": cron});
        c.create(EntityKind::FeedProvider, p)
            .unwrap_or_else(|e| panic!("{cron}: {e:?}"));
    }
    // A bare `L` alone in day-of-week never ran under croner 4; croner 5 refuses it.
    let mut p = fp("never", "http", json!({"url": "https://x.example/l.txt"}));
    p["trigger"] = json!({"kind": "cron", "cron": "0 0 * * L"});
    refused(c.create(EntityKind::FeedProvider, p), "bad_cron");
}

#[test]
fn credentials_only_as_secret_references() {
    // README §2 Secrets, security.md §4, providers.md §2–§5: a provider config carries a
    // credential only as ${secret:name}; one written in clear is refused, so it is never stored
    // unencrypted, returned by the CRUD routes or rendered into a config object.
    let mut c = Cfg::new();
    for (id, module, cfg) in [
        (
            "g1",
            "github",
            json!({"owner": "o", "repo": "r", "token": "ghp_abcdef"}),
        ),
        (
            "h1",
            "http",
            json!({"url": "https://lists.example/l.txt", "headers": {"Authorization": "Bearer abc"}}),
        ),
        (
            "h2",
            "http",
            json!({"url": "https://lists.example/l.txt?apikey=abc"}),
        ),
        (
            "h3",
            "http",
            json!({"url": "https://user:pw@lists.example/l.txt"}),
        ),
        (
            "h4",
            "http",
            json!({"url": "https://lists.example/l.txt", "headers": {"X-Feed": "Basic dXNlcjpwYXNz"}}),
        ),
    ] {
        refused(
            c.create(EntityKind::FeedProvider, fp(id, module, cfg)),
            "literal_credential",
        );
    }
    for (id, cfg) in [
        (
            "p1",
            json!({"url": "https://x/{domain}", "headers": {"Authorization": "Bearer abc"}}),
        ),
        ("p2", json!({"url": "https://x/{domain}?api_key=abc"})),
        (
            "p3",
            json!({"url": "https://x/{domain}", "headers": {"Cookie": "sid=1"}}),
        ),
    ] {
        let mut p = provider(id);
        p["config"] = cfg;
        refused(c.create(EntityKind::LookupProvider, p), "literal_credential");
    }
    c.ok(
        EntityKind::FeedProvider,
        fp(
            "g2",
            "github",
            json!({"owner": "o", "repo": "r", "token": "${secret:gh}"}),
        ),
    );
    c.ok(
        EntityKind::FeedProvider,
        fp(
            "h5",
            "http",
            json!({"url": "https://lists.example/l.txt", "headers": {"Authorization": "Bearer ${secret:k}", "Accept": "text/plain"}}),
        ),
    );
    let mut p = provider("p4");
    p["config"] = json!({"url": "https://x/{domain}?api_key=${secret:k}", "headers": {"Authorization": "Bearer ${secret:k}"},
                         "verdict": {"pointer": "/risk", "block_if": ">= 7"}});
    c.ok(EntityKind::LookupProvider, p);
}

#[test]
fn feed_providers_reference_secrets_like_lookup_providers() {
    // A feed provider's ${secret:…} (github's token, an sqs trigger's keys) can't be deleted from
    // under it, and a missing value is a warning, as for lookup providers.
    let mut c = Cfg::new();
    for n in ["gh", "unused", "aws_id"] {
        store::with_tx(&mut c.conn, |tx| {
            store::set_secret(tx, None, n, "v", &Actor::cli())
        })
        .unwrap();
    }
    let out = c
        .create(
            EntityKind::FeedProvider,
            fp(
                "g",
                "github",
                json!({"owner": "o", "repo": "r", "token": "${secret:gh}"}),
            ),
        )
        .unwrap();
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    let r = store::with_tx(&mut c.conn, |tx| store::delete_secret(tx, "gh", &Actor::cli()));
    assert!(matches!(r, Err(CoreError::Conflict(_))), "{r:?}");
    store::with_tx(&mut c.conn, |tx| {
        store::delete_secret(tx, "unused", &Actor::cli())
    })
    .unwrap();
    let out = c
        .create(
            EntityKind::FeedProvider,
            fp(
                "g2",
                "github",
                json!({"owner": "o2", "repo": "r", "token": "${secret:nope}"}),
            ),
        )
        .unwrap();
    assert!(
        out.warnings.iter().any(|w| w.code == "secret_missing"),
        "{:?}",
        out.warnings
    );
    let mut q = fp("q", "http", json!({"url": "https://q.example/l.txt"}));
    q["trigger"] = json!({"kind": "sqs", "queue_url": "https://sqs.us-east-1.amazonaws.com/123456789012/q",
        "access_key_id": "${secret:aws_id}", "secret_access_key": "${secret:aws_key}"});
    let out = c.create(EntityKind::FeedProvider, q).unwrap();
    assert!(
        out.warnings
            .iter()
            .any(|w| w.code == "secret_missing" && w.message.contains("aws_key")),
        "{:?}",
        out.warnings
    );
    let r = store::with_tx(&mut c.conn, |tx| {
        store::delete_secret(tx, "aws_id", &Actor::cli())
    });
    assert!(
        matches!(r, Err(CoreError::Conflict(_))),
        "the trigger's keys count too: {r:?}"
    );
}

#[test]
fn every_kind_has_a_cap() {
    // README §2 Bounded: every table has an admission bound, not only edges and clients.
    let mut m = picket_core::config::Model::default();
    for i in 0..10_007 {
        let id = format!("u{i}");
        m.upstreams.insert(
            id.clone(),
            serde_json::from_value(json!({"id": id, "name": id, "protocol": "dot", "ip": "192.0.2.1",
                "port": 853, "tls_host": "dns.example", "operator": "example"}))
            .unwrap(),
        );
    }
    let issues = picket_core::config::validate::validate(&m);
    assert!(
        issues
            .iter()
            .any(|i| i.code == "too_many" && i.entity == "upstream"),
        "10,007 upstreams validate without a too_many error"
    );
    // A create past the cap is refused.
    let mut c = Cfg::new();
    let cap = picket_core::config::validate::max_entities(EntityKind::LookupProvider);
    for i in 0..cap {
        c.ok(EntityKind::LookupProvider, provider(&format!("p{i}")));
    }
    refused(
        c.create(EntityKind::LookupProvider, provider("one-more")),
        "too_many",
    );
}

#[test]
fn managed_listener_names_cannot_cover_core() {
    // A managed listener's certificate has the name and *.name (edge.md §5). An edge is
    // untrusted (README §2), so the name can't be a zone (its wildcard covers the whole zone)
    // or reach core's web.names, in either save order.
    let mut c = Cfg::new();
    let fp = picket_api::ids::fingerprint_spki(b"e");
    c.ok(EntityKind::Edge, json!({"id": "e1", "name": "e1", "key": fp}));
    let doh = |id: &str, name: &str, port: u16| {
        json!({"id": id, "name": id, "proto": "doh", "bind": format!("192.168.1.1:{port}"),
               "tls": {"managed": name}, "edges": ["e1"]})
    };
    refused(
        c.create(EntityKind::Listener, doh("zone", "home.arpa", 9001)),
        "managed_name_conflict",
    );
    c.settings(json!({"web": {"names": ["core.home.arpa"]}})).unwrap();
    refused(
        c.create(EntityKind::Listener, doh("same", "core.home.arpa", 9002)),
        "managed_name_conflict",
    );
    c.ok(EntityKind::Listener, doh("ok", "dns.home.arpa", 9003));
    // web.names under the listener's wildcard: refused second, too.
    refused(
        c.settings(json!({"web": {"names": ["core.home.arpa", "ui.dns.home.arpa"]}})),
        "managed_name_conflict",
    );
}

#[test]
fn stored_literal_credentials_are_masked_and_never_saved_again() {
    // CC1 (c): a credential an older release stored in clear never leaves through the UI API,
    // and a save of its entity that keeps it, or changes it to another literal, is refused even
    // though the problem was already there (README §2 Secrets; security.md §4).
    let mut c = Cfg::new();
    let feed_cfg = json!({"url": "https://lists.example/l.txt", "headers": {"X-Key": "${secret:k}"}});
    c.ok(EntityKind::FeedProvider, fp("h", "http", feed_cfg.clone()));
    c.ok(
        EntityKind::FeedProvider,
        fp("other", "http", json!({"url": "https://other.example/l.txt"})),
    );
    c.ok(EntityKind::LookupProvider, provider("lp"));
    let leaked_feed =
        json!({"url": "https://lists.example/l.txt?apikey=LEAKED-1", "headers": {"X-Key": "LEAKED-2"}});
    let leaked_lp =
        json!({"url": "https://x/{domain}", "headers": {"Ocp-Apim-Subscription-Key": "LEAKED-3"}});
    c.conn
        .execute(
            "UPDATE feed_providers SET config_json = ?1 WHERE id = 'h'",
            [leaked_feed.to_string()],
        )
        .unwrap();
    c.conn
        .execute(
            "UPDATE lookup_providers SET config_json = ?1 WHERE id = 'lp'",
            [leaked_lp.to_string()],
        )
        .unwrap();
    let m = store::load_model(&c.conn).unwrap();
    let mut seen = String::new();
    for kind in [EntityKind::FeedProvider, EntityKind::LookupProvider] {
        for (id, v) in store::list_values(&m, kind) {
            seen.push_str(&v.to_string());
            seen.push_str(&store::entity_for_ui(&m, kind, &id).unwrap().to_string());
        }
    }
    for leak in ["LEAKED-1", "LEAKED-2", "LEAKED-3"] {
        assert!(!seen.contains(leak), "{leak} returned: {seen}");
    }
    assert!(seen.contains("lists.example"), "{seen}");
    // A save that keeps the literal, changes it to another literal, or sends back the masked
    // copy the UI got is refused; an unrelated save passes.
    let ui_copy = store::entity_for_ui(&m, EntityKind::FeedProvider, "h").unwrap();
    let mut keep = fp("h", "http", leaked_feed.clone());
    keep["name"] = json!("renamed");
    refused(
        c.update(EntityKind::FeedProvider, "h", keep.clone()),
        "literal_credential",
    );
    keep["config"]["headers"]["X-Key"] = json!("CHANGED");
    refused(
        c.update(EntityKind::FeedProvider, "h", keep),
        "literal_credential",
    );
    refused(
        c.update(EntityKind::FeedProvider, "h", ui_copy),
        "literal_credential",
    );
    let mut lp = provider("lp");
    lp["config"] = json!({"url": "https://x/{domain}", "headers": {"Ocp-Apim-Subscription-Key": "OTHER"}});
    refused(
        c.update(EntityKind::LookupProvider, "lp", lp.clone()),
        "literal_credential",
    );
    c.update(
        EntityKind::FeedProvider,
        "other",
        json!({"name": "Other", "module": "http", "config": {"url": "https://other.example/l.txt"}}),
    )
    .unwrap();
    // Replacing the literal with a reference is accepted, and the outcome is masked too.
    lp["config"]["headers"]["Ocp-Apim-Subscription-Key"] = json!("${secret:k}");
    let out = c.update(EntityKind::LookupProvider, "lp", lp).unwrap();
    assert!(out.entity.unwrap().to_string().contains("${secret:k}"));
    let out = c
        .update(EntityKind::FeedProvider, "h", fp("h", "http", feed_cfg))
        .unwrap();
    assert!(!out.entity.unwrap().to_string().contains("LEAKED"));
    // A preset's parameters are part of the provider's config: no credential in clear there.
    let mut p = provider("lp2");
    p["preset"] = json!({"id": "x", "params": {"api_key": "LEAKED-4"}});
    refused(c.create(EntityKind::LookupProvider, p), "literal_credential");
}

/// providers.md §1, §4 (core.md §7 config schema check): a lookup provider's config is checked
/// against its module's `Config` on save, with `${secret:…}` references taking placeholder values,
/// so a refusal never quotes a secret; an unknown module is refused.
#[test]
fn lookup_provider_configs_follow_their_module_schema() {
    let mut c = Cfg::new();
    let mut p = provider("lp");
    p["config"] = json!({"url": "https://x/{domain}"});
    refused(c.create(EntityKind::LookupProvider, p.clone()), "bad_config");
    p["config"] = json!({"url": "http://x/{domain}", "verdict": {"pointer": "/risk", "block_if": ">= 7"}});
    refused(c.create(EntityKind::LookupProvider, p.clone()), "bad_config");
    p["config"] = json!({"url": "https://x/{domain}", "verdict": {"pointer": "risk", "block_if": ">= 7"}});
    refused(c.create(EntityKind::LookupProvider, p.clone()), "bad_config");
    // A dns provider's config is checked too.
    let mut d = provider("dq");
    d["module"] = json!("dns");
    d["config"] = json!({"servers": []});
    refused(c.create(EntityKind::LookupProvider, d), "bad_config");
    let mut u = provider("um");
    u["module"] = json!("nope");
    refused(c.create(EntityKind::LookupProvider, u), "unknown_module");
    // Secret references are checked with placeholders in their place.
    p["config"] = json!({"url": "https://x/{domain}", "headers": {"Authorization": "Bearer ${secret:k}"},
                         "verdict": {"pointer": "/risk", "block_if": ">= 7"}});
    c.ok(EntityKind::LookupProvider, p);
}

/// README §2 Compatibility: the previous release's shapes read in the new ones
/// (`store::upgrade_previous`). An `http` provider of a `base_url` and paths becomes one provider
/// per feed's URL (`""` and `./` one URL): the first feed (by id) keeps the provider's id, the
/// others' providers take their feeds' ids; feeds keep their ids and read `response`. A path
/// selected without a feed (past the feed cap) was never fetched: it gets no provider and is
/// reported. Two feeds of one URL keep a provider each (a save warns of the overlap). A provider
/// that selected nothing still selects nothing. alphaMountain's `""` is
/// `community-threat-1000`; any other module's `""` stays and is refused (`empty_file`). A
/// second run changes nothing.
#[test]
fn previous_release_shapes_are_upgraded() {
    use picket_core::config::model::{FeedDef, FeedFormat, FeedProviderDef, FileSelect, Model};
    let sel = |p: &str, format: &str| FileSelect {
        pattern: p.into(),
        feed: Some(json!({ "format": format })),
    };
    let provider =
        |id: &str, module: &str, config: Value, files: Vec<FileSelect>, exclude: &[&str]| FeedProviderDef {
            id: id.into(),
            name: if id == "lists" { "Lists".into() } else { id.into() },
            enabled: true,
            module: module.into(),
            config,
            files,
            exclude: exclude.iter().map(|x| x.to_string()).collect(),
            ..Default::default()
        };
    let mut m = Model::default();
    for p in [
        provider(
            "lists",
            "http",
            json!({"base_url": "https://x.example/l/", "headers": {"Accept": "text/plain"}}),
            vec![
                sel("a.txt", "hosts"),
                sel("", "plain"),
                sel("./", "plain"),
                sel("b.txt", "plain"),
                sel("c.txt", "adblock"),
            ],
            &["b*"],
        ),
        provider(
            "none",
            "http",
            json!({"base_url": "https://y.example/"}),
            vec![sel("z.txt", "plain")],
            &["z.txt"],
        ),
        provider(
            "am",
            "alphamountain_threat_1000",
            json!({}),
            vec![sel("", "plain")],
            &[""],
        ),
        provider(
            "gh",
            "github",
            json!({"owner": "o", "repo": "r"}),
            vec![sel("", "plain")],
            &[],
        ),
    ] {
        m.feed_providers.insert(p.id.clone(), p);
    }
    for (id, provider, file) in [
        ("lists", "lists", ""),
        ("lists-2", "lists", "./"),
        ("lists-a", "lists", "a.txt"),
        ("am", "am", ""),
        ("gh", "gh", ""),
    ] {
        m.feeds.insert(
            id.into(),
            FeedDef {
                id: id.into(),
                name: id.into(),
                provider: Some(provider.into()),
                file: Some(file.into()),
                format: FeedFormat::Plain,
                ..Default::default()
            },
        );
    }
    let up = store::upgrade_previous(&mut m);
    assert_eq!(
        up.splits,
        [
            ("lists-2".to_string(), "lists".to_string()),
            ("lists-a".to_string(), "lists".to_string()),
        ]
    );
    assert_eq!(
        up.dropped,
        [("lists".to_string(), vec!["https://x.example/l/c.txt".to_string()])],
        "c.txt was selected but never added: dropped, reported"
    );
    assert_eq!(up.converted, ["lists", "none"]);
    assert!(up.sqs.is_empty());
    let p = |id: &str| m.feed_providers[id].clone();
    let url = |id: &str| p(id).config["url"].as_str().unwrap().to_string();
    // The provider keeps its id for its first feed's URL (`""`: base_url), with its headers.
    assert_eq!(url("lists"), "https://x.example/l/");
    assert_eq!(
        p("lists").config,
        json!({"url": "https://x.example/l/", "headers": {"Accept": "text/plain"}})
    );
    assert_eq!(p("lists").files, [sel("response", "plain")]);
    assert!(
        p("lists").exclude.is_empty(),
        "b.txt was excluded, so it has no provider"
    );
    // `./` is the same URL, a second feed on it: its own provider (the overlap is a warning).
    assert_eq!(url("lists-2"), "https://x.example/l/");
    assert_eq!(p("lists-2").name, "Lists (./)");
    assert_eq!(url("lists-a"), "https://x.example/l/a.txt");
    assert_eq!(p("lists-a").files, [sel("response", "hosts")]);
    assert_eq!(p("lists-a").config["headers"], json!({"Accept": "text/plain"}));
    assert!(p("lists-a").enabled);
    assert!(
        !m.feed_providers.values().any(|q| {
            let u = q.config.get("url").and_then(Value::as_str);
            u == Some("https://x.example/l/c.txt") || u == Some("https://x.example/l/b.txt")
        }),
        "no provider for a path without a feed, nor for an excluded one"
    );
    // Feeds keep their ids, now each on its URL's provider, reading `response`.
    for (feed, provider) in [("lists", "lists"), ("lists-2", "lists-2"), ("lists-a", "lists-a")] {
        let f = &m.feeds[feed];
        assert_eq!(
            (f.provider.as_deref(), f.file.as_deref()),
            (Some(provider), Some("response")),
            "{feed}"
        );
    }
    // Selecting nothing stays so.
    assert_eq!(url("none"), "https://y.example/z.txt");
    assert_eq!(p("none").exclude, ["response"]);
    // alphaMountain's one file is named; github's empty one stays, refused.
    assert_eq!(p("am").files[0].pattern, "community-threat-1000");
    assert_eq!(p("am").exclude, ["community-threat-1000"]);
    assert_eq!(m.feeds["am"].file.as_deref(), Some("community-threat-1000"));
    assert_eq!(p("gh").files[0].pattern, "");
    let issues = picket_core::config::validate::validate(&m);
    let mut errors: Vec<(String, String)> = issues
        .iter()
        .filter(|i| i.severity == picket_core::config::validate::Severity::Error)
        .map(|i| (i.id.clone(), i.code.clone()))
        .collect();
    errors.sort();
    assert_eq!(
        errors,
        [
            ("gh".to_string(), "empty_file".to_string()),
            ("gh".to_string(), "empty_file".to_string())
        ],
        "{issues:?}"
    );
    assert!(
        issues.iter().any(|i| i.code == "overlap" && i.id == "lists-2"),
        "{issues:?}"
    );
    // Idempotent.
    let once = m.clone();
    assert!(store::upgrade_previous(&mut m).is_empty());
    assert_eq!(m, once);
}

/// The split's edge cases (README §2 Compatibility: what was valid stays valid and behaves the
/// same): an `sqs` provider keeps its queue alone, its split-offs on the default trigger (one
/// queue, one consumer); a split-off's name stays a valid name and its URL a valid URL however
/// long the old provider's name, `base_url` and path; its id is free among providers and the
/// other feeds; and the most providers a split can make fit the provider cap.
#[test]
fn previous_release_split_edge_cases() {
    use picket_core::config::model::{FeedDef, FeedFormat, FeedProviderDef, FileSelect, Model, Trigger};
    let feed = |id: &str, provider: &str, file: &str| FeedDef {
        id: id.into(),
        name: id.into(),
        provider: Some(provider.into()),
        file: Some(file.into()),
        format: FeedFormat::Plain,
        ..Default::default()
    };
    let old = |id: &str, name: &str, base: &str, paths: &[&str]| FeedProviderDef {
        id: id.into(),
        name: name.into(),
        enabled: true,
        module: "http".into(),
        config: json!({ "base_url": base }),
        files: paths
            .iter()
            .map(|p| FileSelect {
                pattern: p.to_string(),
                feed: Some(json!({"format": "plain"})),
            })
            .collect(),
        ..Default::default()
    };
    let mut m = Model::default();
    // sqs
    let mut q = old("q", "Q", "https://q.example/", &["a.txt", "b.txt"]);
    q.trigger = serde_json::from_value::<Trigger>(json!({"kind": "sqs",
        "queue_url": "https://sqs.eu-west-1.amazonaws.com/123456789012/lists",
        "access_key_id": "${secret:aws_id}", "secret_access_key": "${secret:aws_key}"}))
    .unwrap();
    m.feed_providers.insert("q".into(), q);
    m.feeds.insert("q-a".into(), feed("q-a", "q", "a.txt"));
    m.feeds.insert("q-b".into(), feed("q-b", "q", "b.txt"));
    // long name, base_url and paths
    let base = format!("https://long.example/{}/", "d".repeat(2000));
    let (pa, pb) = (
        format!("a{}.txt", "p".repeat(1500)),
        format!("b{}.txt", "p".repeat(1500)),
    );
    m.feed_providers.insert(
        "long".into(),
        old("long", &"N".repeat(120), &base, &[pa.as_str(), pb.as_str()]),
    );
    m.feeds.insert("long-a".into(), feed("long-a", "long", &pa));
    m.feeds.insert("long-b".into(), feed("long-b", "long", &pb));
    // a split-off's id taken by another provider
    m.feed_providers.insert(
        "c".into(),
        old("c", "C", "https://c.example/", &["x.txt", "y.txt"]),
    );
    m.feeds.insert("c-x".into(), feed("c-x", "c", "x.txt"));
    m.feeds.insert("c-y".into(), feed("c-y", "c", "y.txt"));
    m.feed_providers.insert(
        "c-y".into(),
        FeedProviderDef {
            id: "c-y".into(),
            name: "other".into(),
            module: "github".into(),
            config: json!({"owner": "o", "repo": "r"}),
            ..Default::default()
        },
    );
    let up = store::upgrade_previous(&mut m);
    assert_eq!(up.sqs, [("q".to_string(), vec!["q-b".to_string()])]);
    assert!(matches!(m.feed_providers["q"].trigger, Trigger::Sqs { .. }));
    assert!(matches!(m.feed_providers["q-b"].trigger, Trigger::Dynamic { .. }));
    let lb = &m.feed_providers["long-b"];
    assert!(
        picket_core::config::validate::is_display_name(&lb.name),
        "{}",
        lb.name
    );
    assert!(
        lb.name.starts_with("NNN") && lb.name.ends_with(".txt)"),
        "{}",
        lb.name
    );
    let url = lb.config["url"].as_str().unwrap();
    assert!(url.len() > 2048, "{}", url.len());
    assert_eq!(
        m.feeds["c-y"].provider.as_deref(),
        Some("c-y-2"),
        "free among providers"
    );
    let errors: Vec<_> = picket_core::config::validate::validate(&m)
        .into_iter()
        .filter(|i| i.severity == picket_core::config::validate::Severity::Error)
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    // The most a split can make: as many providers as the older cap allowed, all their feeds
    // each a provider of its own, within the provider cap.
    let mut big = Model::default();
    let (providers, feeds) = (256, picket_core::config::validate::max_entities(EntityKind::Feed));
    for i in 0..providers {
        let id = format!("p{i}");
        let paths: Vec<String> = (0..feeds / providers).map(|j| format!("f{j}.txt")).collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        big.feed_providers.insert(
            id.clone(),
            old(&id, &id, &format!("https://h{i}.example/"), &refs),
        );
        for p in &paths {
            let fid = format!("{id}-{}", p.trim_end_matches(".txt"));
            big.feeds.insert(fid.clone(), feed(&fid, &id, p));
        }
    }
    store::upgrade_previous(&mut big);
    assert_eq!(big.feed_providers.len(), feeds);
    assert!(
        providers + feeds <= picket_core::config::validate::max_entities(EntityKind::FeedProvider),
        "the cap covers the most a split can make"
    );
    assert!(
        !picket_core::config::validate::validate(&big)
            .iter()
            .any(|i| i.code == "too_many"),
        "the split fits"
    );
}

/// feeds.md §1: the feed of a provider of one fixed file (http, alphaMountain) takes the
/// provider's id, so a provider can't be created under another feed's id (`id_taken`), and a
/// files entry's feed name is a display name.
#[test]
fn single_file_provider_ids_and_template_names() {
    let mut c = Cfg::new();
    c.ok(
        EntityKind::Feed,
        json!({"id": "p", "name": "p", "format": "plain"}),
    );
    for (module, config) in [
        ("http", json!({"url": "https://lists.example/p.txt"})),
        ("alphamountain_threat_1000", json!({})),
    ] {
        refused(
            c.create(EntityKind::FeedProvider, fp("p", module, config)),
            "id_taken",
        );
    }
    // Excluded, there's no feed to add: no clash.
    let mut quiet = fp("p", "http", json!({"url": "https://lists.example/p.txt"}));
    quiet["exclude"] = json!(["response"]);
    c.ok(EntityKind::FeedProvider, quiet);
    let mut named = fp("n", "http", json!({"url": "https://lists.example/n.txt"}));
    named["files"] = json!([{"match": "response", "feed": {"format": "plain", "name": "x".repeat(200)}}]);
    refused(c.create(EntityKind::FeedProvider, named.clone()), "bad_feed");
    named["files"] = json!([{"match": "response", "feed": {"format": "plain", "name": "Readable"}}]);
    let out = c.create(EntityKind::FeedProvider, named).unwrap();
    assert_eq!(out.feeds_added, vec!["n"]);
    let m = store::load_model(&c.conn).unwrap();
    assert_eq!(m.feeds["n"].name, "Readable");
}
