//! Jump placement and classification on recorded-style UniFi layouts and a Debian host
//! (edge-unifi.md §4, edge-firewall.md §4 "Jump placement"; build-and-test.md §4 stimuli).

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
use picket_api::edge_config::FwMode;
use picket_api::helper::{ApplyRequest, CatchAllFinding, RedirectCheck};
use picket_edge_helper::engine::Mode;
use picket_edge_helper::iptables::{Family, Platform, TableName};

const WAN: &str = "UBIOS_LAN_WAN_USER";

fn found(i: &str, f: &str) -> CatchAllFinding {
    CatchAllFinding {
        interface: i.into(),
        found: f.into(),
    }
}

/// Picket's jumps sit together directly above `anchor` (the catch-all or its NFLOG rule).
fn assert_jumps_above(rules: &[String], anchor: &str) {
    let a = pos(rules, anchor);
    let fwd = pos(rules, "-i br0 -j PICKET-FWD");
    let mon = pos(rules, "-i br10 -j PICKET-MON");
    let mut js = [fwd, mon];
    js.sort();
    assert_eq!(js, [a - 2, a - 1], "{rules:#?}");
}

/// The conditions without `local_dst`, which only reports UniFi's local networks (here: no set,
/// so unavailable) and is no finding about the layout.
fn findings(c: &picket_api::helper::Conditions) -> picket_api::helper::Conditions {
    picket_api::helper::Conditions {
        local_dst: vec![],
        ..c.clone()
    }
}

#[test]
fn default_allow() {
    let mut g = unifi("filter-default-allow.rules");
    let r = g.apply(&lan());
    let rules = g.chain(Family::V4, WAN);
    assert_jumps_above(&rules, "UBIOS default Internal-External allow");
    // Only the enforce interface reports its catch-all.
    assert_eq!(r.conditions.fw_catch_all, vec![found("br0", "allow")]);
    assert!(r.conditions.fw_layout_unknown.is_empty());
    assert!(r.conditions.unifi_conflict.is_empty());
    assert!(r.rules_ok);
    // Idempotent: a second pass writes nothing.
    let n = g.restores();
    g.e.pass(Mode::Reassert);
    assert_eq!(g.restores(), n);
}

#[test]
fn block_all_reject_is_the_required_layout() {
    let mut g = unifi("filter-block-all-reject.rules");
    let r = g.apply(&lan());
    let rules = g.chain(Family::V4, WAN);
    // Above the Block All's NFLOG rule, so UniFi logs only what Picket leaves to it.
    assert_jumps_above(&rules, "[FIREWALL_POLICY-R-30000]");
    assert!(
        pos(&rules, "Block IoT telemetry") < pos(&rules, "PICKET-FWD"),
        "UniFi's policies run first"
    );
    assert_eq!(findings(&r.conditions), Default::default());
    assert!(r.rules_ok);
    // IPv6 uses the same layout.
    assert_jumps_above(&g.chain(Family::V6, WAN), "[FIREWALL_POLICY-R-30000]");
}

#[test]
fn block_all_with_action_block_reports_drop() {
    let mut g = unifi("filter-block-all-drop.rules");
    let r = g.apply(&lan());
    assert_jumps_above(&g.chain(Family::V4, WAN), "[FIREWALL_POLICY-D-30000]");
    assert_eq!(r.conditions.fw_catch_all, vec![found("br0", "drop")]);
}

#[test]
fn state_limited_block_all_gets_no_jump() {
    let mut g = unifi("filter-block-all-state-limited.rules");
    let r = g.apply(&lan());
    let rules = g.chain(Family::V4, WAN);
    assert!(!rules.iter().any(|x| x.contains("PICKET")), "{rules:#?}");
    assert_eq!(r.conditions.fw_catch_all, vec![found("br0", "partial")]);
    // The monitor interface's jump has no place either; fw_catch_all is for enforce ones only.
    assert_eq!(r.conditions.fw_layout_unknown, vec!["br10".to_string()]);
    assert!(!r.rules_ok);
}

#[test]
fn earlier_broad_deny_is_a_shadowed_rules_conflict() {
    let mut g = unifi("filter-earlier-broad-deny.rules");
    let r = g.apply(&lan());
    assert_eq!(r.conditions.unifi_conflict, vec!["shadowed_rules".to_string()]);
    // The broad deny stays above Picket; the catch-all is UniFi's default.
    let rules = g.chain(Family::V4, WAN);
    assert!(pos(&rules, "Block everything") < pos(&rules, "PICKET-FWD"));
    assert_eq!(r.conditions.fw_catch_all, vec![found("br0", "allow")]);
}

#[test]
fn a_deny_dnat_new_connections_pass_is_no_shadowed_rules_conflict() {
    // `! --ctstate DNAT -j REJECT`: port-forwarded new connections pass it and reach Picket's jump,
    // so it doesn't shadow everything below (the same rule AC22 applied to accepts).
    let mut g = unifi("filter-negated-dnat-deny-above.rules");
    let r = g.apply(&lan());
    assert!(
        r.conditions.unifi_conflict.is_empty(),
        "{:?}",
        r.conditions.unifi_conflict
    );
    let rules = g.chain(Family::V4, WAN);
    assert!(pos(&rules, "Block all but port forwards") < pos(&rules, "PICKET-FWD"));
    assert_eq!(r.conditions.fw_catch_all, vec![found("br0", "allow")]);
}

#[test]
fn allow_all_above_block_all() {
    let mut g = unifi("filter-allow-all-above.rules");
    let r = g.apply(&lan());
    let rules = g.chain(Family::V4, WAN);
    assert_jumps_above(&rules, "[FIREWALL_POLICY-R-30000]");
    assert!(pos(&rules, "Allow All") < pos(&rules, "PICKET-FWD"));
    assert_eq!(findings(&r.conditions), Default::default());
}

#[test]
fn object_rules_below_block_all_are_shadowed() {
    let mut g = unifi("filter-objects-below-block-all.rules");
    let r = g.apply(&lan());
    assert_eq!(r.conditions.unifi_conflict, vec!["shadowed_rules".to_string()]);
    assert_jumps_above(&g.chain(Family::V4, WAN), "[FIREWALL_POLICY-R-30000]");
}

#[test]
fn policy_landing_between_jump_and_catch_all_moves_the_jump() {
    // At start-up the surviving jump is above a policy UniFi added below it.
    let mut g = unifi("filter-policy-between-jump.rules");
    g.apply(&lan());
    let rules = g.chain(Family::V4, WAN);
    assert_jumps_above(&rules, "[FIREWALL_POLICY-R-30000]");
    assert!(pos(&rules, "Block guest gaming") < pos(&rules, "PICKET-FWD"));
    assert_eq!(rules.iter().filter(|r| r.contains("PICKET-FWD")).count(), 1);
    let _ = g.take_events();

    // Later UniFi inserts another policy between the jumps and the Block All: an ACCEPT that
    // Picket's accepts would otherwise skip. The re-assert moves the jumps and reports it.
    let mut t = g.b.table(Family::V4, TableName::Filter);
    let c = t.chains.iter_mut().find(|c| c.name == WAN).unwrap();
    let at = c
        .rules
        .iter()
        .position(|(r, _)| r.contains("[FIREWALL_POLICY-R-30000]"))
        .unwrap();
    c.rules.insert(
        at,
        (
            "-p tcp -m tcp --dport 443 -m comment --comment \"FIREWALL_POLICY 10003 Allow HTTPS\" -j ACCEPT"
                .into(),
            0,
        ),
    );
    g.b.st().tables.insert((Family::V4, TableName::Filter), t);
    g.b.advance(std::time::Duration::from_secs(2));
    let rep = g.e.pass(Mode::Reassert);
    let rules = g.chain(Family::V4, WAN);
    assert_jumps_above(&rules, "[FIREWALL_POLICY-R-30000]");
    assert!(pos(&rules, "Allow HTTPS") < pos(&rules, "PICKET-FWD"));
    assert!(
        rep.repaired.contains(&"moved4:br0".to_string()),
        "{:?}",
        rep.repaired
    );
    let ev = g.take_events().repaired.expect("rules_repaired");
    assert!(ev.missing.contains(&"moved4:br10".to_string()));
    assert!(ev.gap_ms >= 2000);
}

#[test]
fn unknown_layout_gets_no_jump() {
    let mut g = unifi("filter-unknown-layout.rules");
    let r = g.apply(&lan());
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br0".to_string(), "br10".to_string()]
    );
    let t = g.b.table(Family::V4, TableName::Filter);
    assert!(
        t.chains
            .iter()
            .filter(|c| !c.name.starts_with("PICKET"))
            .flat_map(|c| &c.rules)
            .all(|(r, _)| !r.contains("PICKET"))
    );
    assert!(!r.rules_ok);
}

#[test]
fn zone_dispatch_without_an_interface_match_is_an_unknown_layout() {
    // A dispatch on a source set, with no `-i`, sends some of every interface's traffic to the
    // External zone's chain before br0's and br10's own jumps: neither has a place.
    let mut g = env(
        Platform::Unifi,
        "filter-dispatch-without-interface.rules",
        "filter6-block-all-reject.rules",
    );
    let r = g.apply(&lan());
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br0".to_string(), "br10".to_string()]
    );
    assert!(!g.chain(Family::V4, WAN).iter().any(|x| x.contains("PICKET")));
    assert!(!r.rules_ok);
    // IPv6 has the usual layout and keeps its jumps.
    assert_jumps_above(&g.chain(Family::V6, WAN), "[FIREWALL_POLICY-R-30000]");
}

#[test]
fn a_zone_chain_rule_that_can_take_external_traffic_elsewhere_is_an_unknown_layout() {
    // edge-unifi.md §4 "Unrecognised layout": above the zone→External dispatch, br0's zone chain
    // sends one host's traffic, external destinations included, to another chain, which then
    // decides it without ever reaching Picket's jump.
    let mut g = env(
        Platform::Unifi,
        "filter-zone-chain-diverts.rules",
        "filter6-block-all-reject.rules",
    );
    let r = g.apply(&lan());
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br0".to_string(), "br10".to_string()]
    );
    assert!(!g.chain(Family::V4, WAN).iter().any(|x| x.contains("PICKET")));
    assert!(!r.rules_ok);
    assert_jumps_above(&g.chain(Family::V6, WAN), "[FIREWALL_POLICY-R-30000]");
}

/// Picket placed no jump anywhere in `f`'s filter table for these families.
fn no_jumps(g: &Env, f: Family) -> bool {
    let t = g.b.table(f, TableName::Filter);
    t.chains
        .iter()
        .filter(|c| !c.name.starts_with("PICKET"))
        .flat_map(|c| &c.rules)
        .all(|(r, _)| !r.contains("PICKET"))
}

#[test]
fn a_return_above_the_zone_dispatch_is_an_unknown_layout() {
    // edge-unifi.md §4 "Unrecognised layout", fail closed: a plain RETURN at the top of
    // UBIOS_FORWARD_IN_USER sends every interface's packets back before their zone dispatch, so
    // they would never reach Picket's jump.
    let mut g = env(
        Platform::Unifi,
        "filter-return-above-dispatch.rules",
        "filter6-block-all-reject.rules",
    );
    let r = g.apply(&lan());
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br0".to_string(), "br10".to_string()]
    );
    assert!(no_jumps(&g, Family::V4));
    assert!(!r.rules_ok);
    assert_jumps_above(&g.chain(Family::V6, WAN), "[FIREWALL_POLICY-R-30000]");
}

#[test]
fn an_accept_above_one_interfaces_dispatch_makes_only_its_layout_unknown() {
    // An ACCEPT for br10 above its dispatch lets br10's new connections out past Picket; br0's
    // traffic never matches it. A RELATED,ESTABLISHED accept above both is harmless: only new
    // connections are checked (edge-firewall.md §2).
    let mut g = env(
        Platform::Unifi,
        "filter-accept-above-dispatch.rules",
        "filter6-block-all-reject.rules",
    );
    let r = g.apply(&lan());
    assert_eq!(r.conditions.fw_layout_unknown, vec!["br10".to_string()]);
    let rules = g.chain(Family::V4, WAN);
    assert!(
        rules.iter().any(|x| x.contains("-i br0 -j PICKET-FWD")),
        "{rules:#?}"
    );
    assert!(!rules.iter().any(|x| x.contains("br10")), "{rules:#?}");
    assert!(!r.rules_ok);
}

#[test]
fn a_dnat_or_snat_state_accept_above_the_dispatch_can_take_new_connections() {
    // `--ctstate DNAT` (or SNAT) is a virtual state a NEW connection can also be in, so an ACCEPT
    // on it above the dispatch lets new connections out past Picket for every interface; only
    // INVALID, ESTABLISHED, RELATED and UNTRACKED leave NEW out (edge-unifi.md §4).
    let mut g = env(
        Platform::Unifi,
        "filter-dnat-accept-above-dispatch.rules",
        "filter6-block-all-reject.rules",
    );
    let r = g.apply(&lan());
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br0".to_string(), "br10".to_string()]
    );
    assert!(no_jumps(&g, Family::V4));
    assert!(!r.rules_ok);
}

#[test]
fn an_accept_or_return_above_the_zone_external_dispatch_is_an_unknown_layout() {
    // The second stage: in the zone chain, above the jump to the zone→External chain, an ACCEPT
    // for one host or a plain RETURN takes external traffic past Picket's jump.
    for f in [
        "filter-zone-accept-above-external.rules",
        "filter-zone-return-above-external.rules",
    ] {
        let mut g = env(Platform::Unifi, f, "filter6-block-all-reject.rules");
        let r = g.apply(&lan());
        assert_eq!(
            r.conditions.fw_layout_unknown,
            vec!["br0".to_string(), "br10".to_string()],
            "{f}"
        );
        assert!(no_jumps(&g, Family::V4), "{f}");
        assert!(!r.rules_ok, "{f}");
        assert_jumps_above(&g.chain(Family::V6, WAN), "[FIREWALL_POLICY-R-30000]");
    }
}

#[test]
fn allow_policy_below_the_block_all_leaves_it_above_picket() {
    // The Block All is no longer the last policy: like an earlier broad deny it stays above
    // Picket (edge-unifi.md §4 "Earlier policies stay above Picket, broad denies included"; a
    // UniFi block is never overridden), the catch-all is UniFi's default, and both findings are
    // reported: `fw_catch_all: allow` (no Block All last) and `shadowed_rules` (the Allow below
    // never runs, and the deny above the jump leaves Picket nothing to accept).
    let mut g = unifi("filter-allow-below-block-all.rules");
    let r = g.apply(&lan());
    let rules = g.chain(Family::V4, WAN);
    assert_jumps_above(&rules, "UBIOS default Internal-External allow");
    assert!(pos(&rules, "30000 Block All\" -j REJECT") < pos(&rules, "PICKET-FWD"));
    assert!(pos(&rules, "Allow HTTPS") < pos(&rules, "PICKET-FWD"));
    assert_eq!(r.conditions.fw_catch_all, vec![found("br0", "allow")]);
    assert_eq!(r.conditions.unifi_conflict, vec!["shadowed_rules".to_string()]);
    assert!(r.conditions.fw_layout_unknown.is_empty());
    assert!(r.rules_ok);
}

#[test]
fn chain_ending_in_return_is_not_an_allow_catch_all() {
    let mut g = unifi("filter-ends-in-return.rules");
    let r = g.apply(&lan());
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br0".to_string(), "br10".to_string()]
    );
    assert!(r.conditions.fw_catch_all.is_empty());
    assert!(!g.chain(Family::V4, WAN).iter().any(|x| x.contains("PICKET")));
}

#[test]
fn debian_forward_with_final_reject() {
    let mut g = env(
        Platform::Debian,
        "filter-debian-final-reject.rules",
        "filter-debian-final-reject.rules",
    );
    let r = g.apply(&req(&[("eth1", FwMode::Enforce)]));
    for f in [Family::V4, Family::V6] {
        let rules = g.chain(f, "FORWARD");
        assert_eq!(
            rules.last().unwrap(),
            "-j REJECT --reject-with icmp-port-unreachable"
        );
        assert_eq!(rules[rules.len() - 2], "-i eth1 -j PICKET-FWD");
    }
    assert_eq!(findings(&r.conditions), Default::default());
    assert!(r.rules_ok);
}

#[test]
fn debian_without_final_rule_reports_policy() {
    let mut g = env(
        Platform::Debian,
        "filter-debian-final-reject.rules",
        "filter-debian-final-reject.rules",
    );
    g.b.set_table(
        Family::V4,
        TableName::Filter,
        "-P FORWARD ACCEPT\n-A FORWARD -i eth0 -o eth1 -j ACCEPT\n",
    );
    let r = g.apply(&req(&[("eth1", FwMode::Enforce)]));
    assert_eq!(
        g.chain(Family::V4, "FORWARD").last().unwrap(),
        "-i eth1 -j PICKET-FWD"
    );
    assert_eq!(r.conditions.fw_catch_all, vec![found("eth1", "allow")]);
}

#[test]
fn mode_change_replaces_the_jump_and_off_removes_it() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    g.apply(&req(&[("br0", FwMode::Monitor), ("br10", FwMode::Off)]));
    let rules = g.chain(Family::V4, WAN);
    assert!(rules.iter().any(|r| r == "-i br0 -j PICKET-MON"));
    assert!(
        !rules
            .iter()
            .any(|r| r.contains("PICKET-FWD") || r.contains("br10"))
    );
    assert_eq!(
        pos(&rules, "-i br0 -j PICKET-MON") + 1,
        pos(&rules, "[FIREWALL_POLICY-R-30000]")
    );
    // No interfaces at all: no jumps; chains and sets stay.
    let r = g.apply(&req(&[]));
    assert!(!g.chain(Family::V4, WAN).iter().any(|r| r.contains("PICKET")));
    assert!(!g.chain(Family::V4, "PICKET-FWD").is_empty());
    assert!(r.rules_ok);
}

#[test]
fn dnsfilter_chain_is_a_conflict() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.set_table(Family::V4, TableName::Nat, &fx("nat-dnsfilter.rules"));
    let r = g.apply(&lan());
    assert_eq!(r.conditions.unifi_conflict, vec!["dnsfilter".to_string()]);
}

#[test]
fn over_long_rule_does_not_shift_the_jump() {
    let mut g = unifi("filter-block-all-reject.rules");
    // UniFi writes a policy whose line is over 16 KiB (a huge comment): unparsed, but it keeps its
    // position, so the jumps still land directly above the Block All's NFLOG rule.
    let mut t = g.b.table(Family::V4, TableName::Filter);
    let c = t.chains.iter_mut().find(|c| c.name == WAN).unwrap();
    let long = format!(
        "-m comment --comment \"FIREWALL_POLICY 9999 {}\" -p tcp -m tcp --dport 22 -j ACCEPT",
        "x".repeat(20_000)
    );
    c.rules.insert(0, (long, 0));
    g.b.st().tables.insert((Family::V4, TableName::Filter), t);
    let r = g.apply(&lan());
    assert!(r.rules_ok, "{r:?}");
    let rules = g.chain(Family::V4, WAN);
    assert_jumps_above(&rules, "[FIREWALL_POLICY-R-30000]");
    assert!(rules[0].len() > 16 * 1024, "the long rule is untouched and first");
    let n = g.restores();
    g.e.pass(Mode::Reassert);
    assert_eq!(g.restores(), n, "stable");
}

#[test]
fn ambiguous_zone_dispatch_is_an_unknown_layout() {
    // Some of br0's traffic is sent to the Hotspot zone: not all of it reaches the chain the jump
    // would go in, so there is no place for it. br10 is unaffected.
    let mut g = ids("filter-default-allow.rules");
    let mut t = g.b.table(Family::V4, TableName::Filter);
    t.chains
        .iter_mut()
        .find(|c| c.name == "UBIOS_FORWARD_IN_USER")
        .unwrap()
        .rules
        .insert(0, ("-i br0 -s 192.0.2.128/25 -j UBIOS_HOTSPOT_IN_USER".into(), 0));
    g.b.st().tables.insert((Family::V4, TableName::Filter), t);
    let r = g.apply(&lan());
    assert_eq!(r.conditions.fw_layout_unknown, vec!["br0".to_string()]);
    assert!(!g.chain(Family::V4, WAN).iter().any(|x| x.contains("PICKET-FWD")));
    assert!(
        g.chain(Family::V4, WAN)
            .iter()
            .any(|x| x == "-i br10 -j PICKET-MON")
    );
    // A zone chain that sends some of its traffic to a second zone→External chain.
    let mut g = ids("filter-default-allow.rules");
    let mut t = g.b.table(Family::V6, TableName::Filter);
    t.chains
        .iter_mut()
        .find(|c| c.name == "UBIOS_LAN_IN_USER")
        .unwrap()
        .rules
        .insert(
            0,
            (
                "-m set ! --match-set UBIOS_local_zoned_subnets dst -m set --match-set UBIOS_GRP_kids src -j UBIOS_HOTSPOT_WAN_USER".into(),
                0,
            ),
        );
    g.b.st().tables.insert((Family::V6, TableName::Filter), t);
    let r = g.apply(&lan());
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br0".to_string(), "br10".to_string()]
    );
    assert!(!g.chain(Family::V6, WAN).iter().any(|x| x.contains("PICKET")));
}

#[test]
fn jumps_go_above_only_the_catch_alls_own_log_rule() {
    // Another policy's log rule directly above the Block All's NFLOG rule keeps logging what it
    // logged before: Picket's jumps go between the two.
    let mut g = unifi("filter-block-all-reject.rules");
    let mut t = g.b.table(Family::V4, TableName::Filter);
    let c = t.chains.iter_mut().find(|c| c.name == WAN).unwrap();
    let at = c
        .rules
        .iter()
        .position(|(r, _)| r.contains("[FIREWALL_POLICY-R-30000]"))
        .unwrap();
    c.rules.insert(
        at,
        (
            "-p tcp -m tcp --dport 22 -m comment --comment \"FIREWALL_POLICY 10002 Log SSH\" -j NFLOG --nflog-prefix \"[FIREWALL_POLICY-A-10002]\" --nflog-group 1".into(),
            0,
        ),
    );
    g.b.st().tables.insert((Family::V4, TableName::Filter), t);
    let r = g.apply(&lan());
    assert!(r.rules_ok, "{r:?}");
    let rules = g.chain(Family::V4, WAN);
    assert_jumps_above(&rules, "[FIREWALL_POLICY-R-30000]");
    assert!(pos(&rules, "Log SSH") < pos(&rules, "PICKET-FWD"));
}

// ---- the second rendering (fixtures/unifi/id-tags) ---------------------------------------------

#[test]
fn ids_block_all_reject() {
    let mut g = ids("filter-block-all-reject.rules");
    let r = g.apply(&req(&[
        ("br0", FwMode::Enforce),
        ("br10", FwMode::Monitor),
        ("br20", FwMode::Off),
    ]));
    assert_eq!(findings(&r.conditions), Default::default());
    assert!(r.rules_ok, "{r:?}");
    for f in [Family::V4, Family::V6] {
        let rules = g.chain(f, WAN);
        // The tag is only in the comments; the NFLOG prefix names the zone pair.
        assert_jumps_above(&rules, "[LAN_WAN-R-30000]");
        assert!(pos(&rules, "[LAN_WAN-D-2]") < pos(&rules, "PICKET-FWD"));
        assert!(!rules.iter().any(|x| x.contains("br20")));
        assert!(
            !g.chain(f, "UBIOS_HOTSPOT_WAN_USER")
                .iter()
                .any(|x| x.contains("PICKET"))
        );
    }
    let n = g.restores();
    g.e.pass(Mode::Reassert);
    assert_eq!(g.restores(), n);
}

#[test]
fn ids_default_allow_and_the_hotspot_zone() {
    let mut g = ids("filter-default-allow.rules");
    let r = g.apply(&req(&[
        ("br0", FwMode::Enforce),
        ("br10", FwMode::Monitor),
        ("br20", FwMode::Enforce),
    ]));
    assert_eq!(
        r.conditions.fw_catch_all,
        vec![found("br0", "allow"), found("br20", "allow")]
    );
    assert_jumps_above(&g.chain(Family::V4, WAN), "UBIOS_DEFAULT_LAN_WAN");
    // The Guest zone has its own zone→External chain.
    let hs = g.chain(Family::V4, "UBIOS_HOTSPOT_WAN_USER");
    assert_eq!(hs[hs.len() - 2], "-i br20 -j PICKET-FWD", "{hs:#?}");
    // The WAN zone has no zone→External chain, and an interface UniFi doesn't know has no zone.
    let r = g.apply(&req(&[("eth4", FwMode::Monitor), ("br99", FwMode::Monitor)]));
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br99".to_string(), "eth4".to_string()]
    );
}

#[test]
fn ids_block_all_drop() {
    let mut g = ids("filter-block-all-drop.rules");
    let r = g.apply(&req(&[("br0", FwMode::Enforce)]));
    assert_eq!(r.conditions.fw_catch_all, vec![found("br0", "drop")]);
    let rules = g.chain(Family::V4, WAN);
    assert_eq!(
        pos(&rules, "-i br0 -j PICKET-FWD") + 1,
        pos(&rules, "[LAN_WAN-D-30000]")
    );
}

#[test]
fn ids_state_limited_block_all() {
    let mut g = ids("filter-block-all-state-limited.rules");
    let r = g.apply(&lan());
    assert_eq!(r.conditions.fw_catch_all, vec![found("br0", "partial")]);
    assert_eq!(r.conditions.fw_layout_unknown, vec!["br10".to_string()]);
    assert!(!g.chain(Family::V4, WAN).iter().any(|x| x.contains("PICKET")));
}

#[test]
fn ids_shadowed_rules_and_allow_all() {
    for f in [
        "filter-earlier-broad-deny.rules",
        "filter-object-rules-below-block-all.rules",
    ] {
        let mut g = ids(f);
        let r = g.apply(&req(&[("br0", FwMode::Enforce)]));
        assert_eq!(
            r.conditions.unifi_conflict,
            vec!["shadowed_rules".to_string()],
            "{f}"
        );
        assert!(r.conditions.fw_catch_all.is_empty(), "{f}");
        let rules = g.chain(Family::V4, WAN);
        assert_eq!(
            pos(&rules, "-i br0 -j PICKET-FWD") + 1,
            pos(&rules, "[LAN_WAN-R-30000]"),
            "{f}"
        );
    }
    let mut g = ids("filter-allow-all-above-block-all.rules");
    let r = g.apply(&req(&[("br0", FwMode::Enforce)]));
    assert_eq!(findings(&r.conditions), Default::default());
    let rules = g.chain(Family::V4, WAN);
    assert!(pos(&rules, "6731c0de00000000000000fe") < pos(&rules, "PICKET-FWD"));
}

#[test]
fn ids_policy_between_jump_and_catch_all() {
    let mut g = ids("filter-policy-between-jump-and-catch-all.rules");
    g.apply(&req(&[("br0", FwMode::Enforce)]));
    let rules = g.chain(Family::V4, WAN);
    let smtp = pos(&rules, "--dport 25");
    assert_eq!(rules[smtp + 1], "-i br0 -j PICKET-FWD", "{rules:#?}");
    assert!(rules[smtp + 2].contains("NFLOG"));
    assert_eq!(rules.iter().filter(|x| x.contains("PICKET-FWD")).count(), 1);
}

#[test]
fn ids_unknown_layout() {
    let mut g = ids("filter-unknown-layout.rules");
    let r = g.apply(&lan());
    assert_eq!(
        r.conditions.fw_layout_unknown,
        vec!["br0".to_string(), "br10".to_string()]
    );
    let t = g.b.table(Family::V4, TableName::Filter);
    assert!(
        t.chains
            .iter()
            .filter(|c| !c.name.starts_with("PICKET"))
            .flat_map(|c| &c.rules)
            .all(|(r, _)| !r.contains("PICKET"))
    );
}

#[test]
fn ids_debian_drop_policy_with_final_reject() {
    let f = "id-tags/debian-forward-reject.rules";
    let mut g = env(Platform::Debian, f, f);
    let r = g.apply(&req(&[("ens4", FwMode::Enforce)]));
    assert_eq!(findings(&r.conditions), Default::default());
    for fam in [Family::V4, Family::V6] {
        let rules = g.chain(fam, "FORWARD");
        assert_eq!(rules[rules.len() - 2], "-i ens4 -j PICKET-FWD");
        assert!(rules[rules.len() - 1].contains("REJECT"));
    }
}

fn ids_redirect(nat4: &str, nat6: &str, interfaces: &[&str], ipv6: bool, port: u16) -> Vec<String> {
    let mut g = ids("filter-block-all-reject.rules");
    g.b.set_table(Family::V4, TableName::Nat, &fx(&format!("id-tags/{nat4}")));
    g.b.set_table(Family::V6, TableName::Nat, &fx(&format!("id-tags/{nat6}")));
    let r = ApplyRequest {
        redirect: Some(RedirectCheck {
            interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
            port,
            ipv6,
        }),
        ..req(&[("br0", FwMode::Enforce)])
    };
    g.apply(&r).conditions.redirect_missing
}

#[test]
fn ids_redirect_check() {
    const P4: &str = "nat-redirect-present.rules";
    const P6: &str = "nat6-redirect-present.rules";
    assert!(ids_redirect(P4, P6, &["br0"], true, 5335).is_empty());
    // IPv6 covers only br0 in this rendering.
    assert_eq!(ids_redirect(P4, P6, &["br0", "br10"], true, 5335), vec!["ipv6"]);
    assert!(ids_redirect(P4, P6, &["br0", "br10"], false, 5335).is_empty());
    // Only br0's UDP rule is left.
    assert_eq!(
        ids_redirect("nat-redirect-missing.rules", P6, &["br0"], true, 5335),
        vec!["ipv4"]
    );
    // br0 to dnsmasq's port on the gateway; br10 to another host at the listener's port.
    for i in ["br0", "br10"] {
        assert_eq!(
            ids_redirect("nat-redirect-elsewhere.rules", P6, &[i], false, 5335),
            vec!["ipv4"],
            "{i}"
        );
    }
    // A listener on another port: neither family's rule targets it.
    assert_eq!(ids_redirect(P4, P6, &["br0"], true, 5353), vec!["ipv4", "ipv6"]);
}
