//! The helper's state machine against the fake backend (edge-firewall.md §2, §4, §5;
//! edge-unifi.md §3–§5).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use picket_api::edge_config::FwMode;
use picket_api::helper::{ApplyRequest, sets};
use picket_edge_helper::backend::{Backend, SetOp};
use picket_edge_helper::engine::{Engine, Mode, SETS};
use picket_edge_helper::fake::FakeBackend;
use picket_edge_helper::ipset::Elem;
use picket_edge_helper::iptables::layout::{DNS6, FWD, MON};
use picket_edge_helper::iptables::plan::chain_rules;
use picket_edge_helper::iptables::{ExecError, Family, Platform, TableName};
use picket_edge_helper::rules::{RULES_FILE, RulesFile, STATIC_MAX};
use picket_edge_helper::shared::Shared;
use picket_edge_helper::snapshot::{self, SNAP_FILE};

const WAN: &str = "UBIOS_LAN_WAN_USER";

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

// ---- start-up ----------------------------------------------------------------------------------

#[test]
fn startup_creates_sets_and_chains() {
    let g = unifi("filter-block-all-reject.rules");
    assert_eq!(g.b.st().created.len(), 8);
    for d in &SETS {
        let h = g.b.ipset_header(d.name).unwrap().unwrap();
        assert_eq!(h.maxelem, Some(d.maxelem));
    }
    let h = g.b.ipset_header(sets::PICKET4).unwrap().unwrap();
    assert_eq!(
        (h.type_name.as_str(), h.timeout, h.maxelem),
        ("hash:net,net", Some(300), Some(262_144))
    );
    assert_eq!(
        g.b.ipset_header(sets::PICKET_G6).unwrap().unwrap().type_name,
        "hash:ip"
    );
    assert_eq!(g.b.ipset_header(sets::STATIC4).unwrap().unwrap().timeout, None);
    for f in [Family::V4, Family::V6] {
        assert_eq!(g.chain(f, FWD), chain_rules(f, FWD));
        assert_eq!(g.chain(f, MON), chain_rules(f, MON));
    }
    assert_eq!(
        g.chain(Family::V6, FWD)[4],
        "-m set --match-set picket6 src,dst -j ACCEPT"
    );
}

#[test]
fn startup_while_disabled_creates_no_set_and_no_rule() {
    let b = Arc::new(FakeBackend::new());
    b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    let file = RulesFile {
        version: 1,
        disabled: true,
        apply: Some(lan()),
    };
    b.st()
        .files
        .insert(RULES_FILE.into(), serde_json::to_vec(&file).unwrap());
    snapshot_with(&b, &[(sets::PICKET4, Some("192.168.1.10"), "1.1.1.1", 300)]);
    let mut e = Engine::new(b.clone(), Shared::new(), Platform::Unifi);
    let rep = e.startup();
    assert!(b.st().sets.is_empty());
    assert!(b.st().restores.is_empty());
    assert!(
        !b.st().files.contains_key(SNAP_FILE),
        "the snapshot is deleted either way"
    );
    assert!(rep.conditions.helper_disabled);
    assert!(!rep.rules_ok);
    // Re-asserts while disabled repair nothing either.
    e.pass(Mode::Reassert);
    assert!(b.st().sets.is_empty());
    assert!(b.st().restores.is_empty());
}

#[test]
fn temporary_files_are_deleted_at_start() {
    let b = Arc::new(FakeBackend::new());
    b.st().files.insert("rules.json.tmp".into(), b"x".to_vec());
    b.st().files.insert("snap.json.tmp".into(), b"x".to_vec());
    Engine::new(b.clone(), Shared::new(), Platform::Debian).startup();
    assert!(b.st().files.is_empty());
}

#[test]
fn oversized_rules_json_is_not_trusted() {
    let b = Arc::new(FakeBackend::new());
    let statics: Vec<String> = (0..=STATIC_MAX)
        .map(|i| format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255))
        .collect();
    let file = RulesFile {
        version: 1,
        disabled: false,
        apply: Some(ApplyRequest {
            static_allow: statics,
            ..lan()
        }),
    };
    b.st()
        .files
        .insert(RULES_FILE.into(), serde_json::to_vec(&file).unwrap());
    let mut e = Engine::new(b.clone(), Shared::new(), Platform::Debian);
    e.startup();
    assert!(e.desired().static4.is_empty());
    assert!(b.members(sets::STATIC4).is_empty());
}

// ---- snapshot ----------------------------------------------------------------------------------

/// Writes a snapshot at the backend's current time holding these entries.
fn snapshot_with(b: &Arc<FakeBackend>, entries: &[(&'static str, Option<&str>, &str, u32)]) {
    let tmp = FakeBackend::new();
    for d in &SETS {
        tmp.ipset_create(&d.spec()).unwrap();
    }
    for (set, src, dst, t) in entries {
        let elem = match src {
            Some(s) => Elem::host_pair(ip(s), ip(dst)),
            None => Elem::ip(ip(dst)),
        };
        assert!(
            tmp.ipset_add(&[SetOp {
                set,
                elem,
                timeout: Some(*t)
            }])[0]
                .is_ok()
        );
    }
    tmp.st().wall_ms = b.st().wall_ms;
    snapshot::write(&tmp).unwrap();
    let bytes = tmp.st().files[SNAP_FILE].clone();
    b.st().files.insert(SNAP_FILE.into(), bytes);
}

fn boot(b: &Arc<FakeBackend>) -> Engine<FakeBackend> {
    let mut e = Engine::new(b.clone(), Shared::new(), Platform::Debian);
    e.startup();
    e
}

#[test]
fn snapshot_restored_after_reboot_with_elapsed_time() {
    let b = Arc::new(FakeBackend::new());
    snapshot_with(
        &b,
        &[
            (sets::PICKET4, Some("192.168.1.10"), "93.184.216.34", 300),
            (sets::PICKET_G4, None, "1.1.1.1", 100),
            (sets::PICKET6, Some("fd00::10"), "2001:db8::1", 40),
            (sets::PICKET_G6, None, "2001:db8::2", 30),
        ],
    );
    // 20 s of downtime by the clock, uptime 35 s (the larger counts), as after a reboot.
    b.st().wall_ms += 20_000;
    b.st().uptime = Some(Duration::from_secs(35));
    boot(&b);
    assert_eq!(
        b.members(sets::PICKET4),
        vec![(
            Elem::host_pair(ip("192.168.1.10"), ip("93.184.216.34")),
            Some(265)
        )]
    );
    assert_eq!(
        b.members(sets::PICKET_G4),
        vec![(Elem::ip(ip("1.1.1.1")), Some(65))]
    );
    assert_eq!(
        b.members(sets::PICKET6),
        vec![(Elem::host_pair(ip("fd00::10"), ip("2001:db8::1")), Some(5))]
    );
    assert!(
        b.members(sets::PICKET_G6).is_empty(),
        "less than 1 s left: skipped"
    );
    assert!(!b.st().files.contains_key(SNAP_FILE));
}

#[test]
fn snapshot_uses_clock_difference_when_larger_and_never_adds_time() {
    let b = Arc::new(FakeBackend::new());
    snapshot_with(&b, &[(sets::PICKET_G4, None, "1.1.1.1", 100)]);
    b.st().wall_ms += 60_000;
    b.st().uptime = Some(Duration::from_secs(10));
    boot(&b);
    assert_eq!(
        b.members(sets::PICKET_G4),
        vec![(Elem::ip(ip("1.1.1.1")), Some(40))]
    );
    let b = Arc::new(FakeBackend::new());
    snapshot_with(&b, &[(sets::PICKET_G4, None, "1.1.1.1", 100)]);
    b.st().uptime = Some(Duration::ZERO);
    boot(&b);
    assert_eq!(
        b.members(sets::PICKET_G4),
        vec![(Elem::ip(ip("1.1.1.1")), Some(100))],
        "never more than at stop"
    );
}

#[test]
fn snapshot_not_restored_when_clock_is_earlier() {
    let b = Arc::new(FakeBackend::new());
    snapshot_with(&b, &[(sets::PICKET_G4, None, "1.1.1.1", 100)]);
    b.st().wall_ms -= 5_000;
    boot(&b);
    assert!(b.members(sets::PICKET_G4).is_empty());
    assert!(!b.st().files.contains_key(SNAP_FILE));
}

#[test]
fn snapshot_not_restored_after_a_helper_restart() {
    // The kernel's sets survived (a helper restart, not a reboot): they are newer.
    let b = Arc::new(FakeBackend::new());
    for d in &SETS {
        b.ipset_create(&d.spec()).unwrap();
    }
    snapshot_with(&b, &[(sets::PICKET_G4, None, "1.1.1.1", 100)]);
    boot(&b);
    assert!(b.members(sets::PICKET_G4).is_empty());
    assert!(!b.st().files.contains_key(SNAP_FILE), "deleted either way");
}

#[test]
fn snapshot_entries_keep_ageing_while_the_restore_runs() {
    // edge-firewall.md §4 "Restore": each entry is added with what is left of its timeout when
    // it is added, so time spent restoring neither extends later entries nor brings back those
    // that ran out meanwhile. 2,000 entries are four batches; each takes 3 s here.
    let b = Arc::new(FakeBackend::new());
    let dsts: Vec<String> = (0..2000u32)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
        .collect();
    let entries: Vec<(&'static str, Option<&str>, &str, u32)> = dsts
        .iter()
        .enumerate()
        .map(|(i, d)| (sets::PICKET_G4, None, d.as_str(), if i >= 1900 { 15 } else { 30 }))
        .collect();
    snapshot_with(&b, &entries);
    b.st().wall_ms += 10_000;
    b.st().uptime = Some(Duration::from_secs(5));
    b.st().add_ctl_delay = Duration::from_secs(3);
    boot(&b);
    b.st().add_ctl_delay = Duration::ZERO;
    let m = b.members(sets::PICKET_G4);
    // 12 s after the restore began, 22 s after writing: every 30 s entry has 8 s left, whichever
    // batch it was in; the 15 s ones in the last batch had run out before it was added.
    assert_eq!(m.len(), 1900);
    assert!(m.iter().all(|(_, t)| *t == Some(8)), "{:?}", &m[1800..]);
}

#[test]
fn shutdown_writes_remaining_timeouts() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.ipset_add(&[SetOp {
        set: sets::PICKET_G4,
        elem: Elem::ip(ip("9.9.9.9")),
        timeout: Some(120),
    }]);
    g.b.advance(Duration::from_secs(20));
    g.e.shutdown();
    let snap: serde_json::Value = serde_json::from_slice(&g.b.st().files[SNAP_FILE]).unwrap();
    assert_eq!(snap["version"], 1);
    assert_eq!(snap["written_at_ms"], g.b.wall_ms());
    let g4 = snap["sets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["set"] == "picket-g4")
        .unwrap();
    assert_eq!(g4["entries"], serde_json::json!([[null, "9.9.9.9", 100]]));
}

// ---- apply ---------------------------------------------------------------------------------------

#[test]
fn apply_makes_static_and_exempt_sets_match_exactly() {
    let mut g = unifi("filter-block-all-reject.rules");
    let mut r = lan();
    r.static_allow = vec![
        "192.168.1.5".into(),
        "10.0.0.0/8".into(),
        "0.0.0.0/0".into(),
        "fd00::/8".into(),
    ];
    r.exempt = vec!["192.168.1.50/32".into()];
    let resp = g.apply(&r);
    assert!(resp.ok && resp.rules_ok, "{resp:?}");
    let s4: Vec<String> =
        g.b.members(sets::STATIC4)
            .iter()
            .map(|(e, _)| format!("{}/{}", e.ip, e.cidr.unwrap()))
            .collect();
    assert_eq!(
        s4,
        vec!["0.0.0.0/1", "10.0.0.0/8", "128.0.0.0/1", "192.168.1.5/32"]
    );
    assert_eq!(g.b.members(sets::STATIC6).len(), 1);
    assert_eq!(g.b.members(sets::EXEMPT4).len(), 1);
    // Unlisted entries are deleted.
    r.static_allow = vec!["10.0.0.0/8".into()];
    r.exempt = vec![];
    g.apply(&r);
    assert_eq!(g.b.members(sets::STATIC4).len(), 1);
    assert!(g.b.members(sets::STATIC6).is_empty());
    assert!(g.b.members(sets::EXEMPT4).is_empty());
    // Persisted in normalised form.
    let file: RulesFile = serde_json::from_slice(&g.b.st().files[RULES_FILE]).unwrap();
    assert_eq!(file.apply.unwrap().static_allow, vec!["10.0.0.0/8".to_string()]);
}

#[test]
fn invalid_apply_is_rejected_and_not_persisted() {
    let mut g = unifi("filter-block-all-reject.rules");
    let before = g.b.st().files.get(RULES_FILE).cloned();
    for bad in [
        req(&[("br0+", FwMode::Enforce)]),
        req(&[("br0 -j ACCEPT", FwMode::Enforce)]),
        ApplyRequest {
            static_allow: vec!["10.0.0.0/33".into()],
            ..lan()
        },
    ] {
        let e = g.e.apply(&bad).unwrap_err();
        assert_eq!(e.code, "invalid");
    }
    assert_eq!(g.b.st().files.get(RULES_FILE).cloned(), before);
}

#[test]
fn unlisted_jumps_are_deleted() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    // A stray jump to Picket's chain elsewhere (an older config, or by hand).
    let mut t = g.b.table(Family::V4, TableName::Filter);
    t.chains
        .iter_mut()
        .find(|c| c.name == "UBIOS_LAN_LAN_USER")
        .unwrap()
        .rules
        .insert(0, ("-i br5 -j PICKET-FWD".into(), 0));
    g.b.st().tables.insert((Family::V4, TableName::Filter), t);
    g.apply(&req(&[("br0", FwMode::Enforce)]));
    let all: Vec<String> =
        g.b.table(Family::V4, TableName::Filter)
            .chains
            .iter()
            .flat_map(|c| c.rules.iter().map(|r| r.0.clone()))
            .collect();
    assert_eq!(
        all.iter().filter(|r| r.contains("-j PICKET-")).count(),
        1,
        "{all:#?}"
    );
}

// ---- disable / enable ----------------------------------------------------------------------------

#[test]
fn disable_removes_jumps_keeps_sets_and_chains_and_survives_restart() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    let _ = g.take_events();
    let r = g.e.disable();
    assert!(r.conditions.helper_disabled && !r.rules_ok);
    assert!(!g.chain(Family::V4, WAN).iter().any(|x| x.contains("PICKET")));
    assert!(!g.chain(Family::V6, WAN).iter().any(|x| x.contains("PICKET")));
    assert_eq!(g.chain(Family::V4, FWD), chain_rules(Family::V4, FWD));
    assert_eq!(g.b.st().sets.len(), 8);
    assert!(
        g.take_events().conditions.unwrap().helper_disabled,
        "conditions sent on disable"
    );
    // A second disable sends conditions again.
    g.e.disable();
    assert!(g.take_events().conditions.is_some());
    // UniFi re-provisions: nothing is repaired; apply doesn't add jumps either.
    g.b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    g.e.pass(Mode::Reassert);
    g.apply(&lan());
    assert!(!g.chain(Family::V4, WAN).iter().any(|x| x.contains("PICKET")));
    assert!(g.take_events().repaired.is_none());
    // The flag survives a restart.
    let file: RulesFile = serde_json::from_slice(&g.b.st().files[RULES_FILE]).unwrap();
    assert!(file.disabled);
    let mut e2 = Engine::new(g.b.clone(), Shared::new(), Platform::Unifi);
    assert!(e2.startup().conditions.helper_disabled);
    // Enable re-adds the jumps (the chains came back too).
    let r = e2.enable();
    assert!(r.rules_ok && !r.conditions.helper_disabled, "{r:?}");
    assert!(
        g.chain(Family::V4, WAN)
            .iter()
            .any(|x| x == "-i br0 -j PICKET-FWD")
    );
}

#[test]
fn enable_after_disabled_boot_reports_created_sets() {
    let b = Arc::new(FakeBackend::new());
    b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    let file = RulesFile {
        version: 1,
        disabled: true,
        apply: Some(lan()),
    };
    b.st()
        .files
        .insert(RULES_FILE.into(), serde_json::to_vec(&file).unwrap());
    let shared = Shared::new();
    let m = shared.subscribe();
    let mut e = Engine::new(b.clone(), shared.clone(), Platform::Unifi);
    e.startup();
    e.enable();
    let ev = m.take().repaired.expect("rules_repaired");
    let mut sets_: Vec<String> = ev.recreated_sets.clone();
    sets_.sort();
    assert_eq!(sets_, vec!["picket-g4", "picket-g6", "picket4", "picket6"]);
}

// ---- re-assert -----------------------------------------------------------------------------------

#[test]
fn reprovisioning_is_repaired_and_reported() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    let _ = g.take_events();
    // UniFi rewrites its chains (our chains survive, the jumps are gone).
    let mut t = g.b.table(Family::V4, TableName::Filter);
    for c in &mut t.chains {
        c.rules.retain(|(r, _)| !r.contains("-j PICKET-"));
    }
    g.b.st().tables.insert((Family::V4, TableName::Filter), t);
    g.b.advance(Duration::from_millis(1500));
    let rep = g.e.pass(Mode::Reassert);
    assert!(rep.rules_ok);
    let ev = g.take_events().repaired.expect("rules_repaired");
    let mut missing = ev.missing.clone();
    missing.sort();
    assert_eq!(missing, vec!["jump4:br0", "jump4:br10"]);
    assert!(ev.recreated_sets.is_empty());
    assert_eq!(ev.gap_ms, 1500);
    assert!(g.shared.snapshot().last_repair.is_some());
}

#[test]
fn wiped_table_and_lost_set_are_recreated() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    let _ = g.take_events();
    // A full rewrite drops our chains too, and the unreferenced set is cleaned up.
    g.b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    g.b.ipset_add(&[SetOp {
        set: sets::PICKET4,
        elem: Elem::host_pair(ip("192.168.1.2"), ip("1.1.1.1")),
        timeout: Some(100),
    }]);
    g.b.destroy_behind_back(sets::PICKET4);
    g.b.advance(Duration::from_secs(2));
    g.e.pass(Mode::Reassert);
    let ev = g.take_events().repaired.expect("rules_repaired");
    assert_eq!(ev.recreated_sets, vec!["picket4".to_string()]);
    for x in [
        "set:picket4",
        "chain4:PICKET-FWD",
        "chain4:PICKET-MON",
        "jump4:br0",
    ] {
        assert!(ev.missing.contains(&x.to_string()), "{x} in {:?}", ev.missing);
    }
    assert!(g.b.members(sets::PICKET4).is_empty(), "recreated empty");
    assert_eq!(g.chain(Family::V4, FWD), chain_rules(Family::V4, FWD));
}

#[test]
fn lock_timeout_is_retried_at_the_next_reassert() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.push_restore_error(ExecError::LockTimeout);
    let r = g.apply(&lan());
    assert!(r.ok);
    assert!(!r.rules_ok);
    assert!(
        r.pending.contains(&"restore4:lock_timeout".to_string()),
        "{:?}",
        r.pending
    );
    let rep = g.e.pass(Mode::Reassert);
    assert!(rep.rules_ok, "{:?}", rep.pending);
    assert!(
        g.chain(Family::V4, WAN)
            .iter()
            .any(|x| x == "-i br0 -j PICKET-FWD")
    );
}

#[test]
fn lock_permission_error_is_not_a_timeout() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.push_restore_error(ExecError::LockPermission(
        "Fatal: can't open lock file /run/xtables.lock: Permission denied".into(),
    ));
    let r = g.apply(&lan());
    assert!(
        r.pending.contains(&"restore4:lock_permission".to_string()),
        "{:?}",
        r.pending
    );
    assert!(!r.pending.iter().any(|p| p.contains("lock_timeout")));
    assert!(
        g.shared
            .snapshot()
            .pending
            .contains(&"restore4:lock_permission".to_string())
    );
}

// ---- counters ------------------------------------------------------------------------------------

#[test]
fn reject_counters_grow_per_client_and_restart_from_zero() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    let last = chain_rules(Family::V4, FWD).len() - 1;
    g.b.set_counter(Family::V4, FWD, last, 10);
    g.b.set_counter(Family::V6, MON, chain_rules(Family::V6, MON).len() - 1, 3);
    g.e.pass(Mode::Reassert);
    let take = |g: &Env, uid| g.shared.counters.lock().unwrap().take_growth(uid);
    assert_eq!(take(&g, 1000), (10, 3));
    g.b.set_counter(Family::V4, FWD, last, 25);
    g.e.pass(Mode::Reassert);
    assert_eq!(take(&g, 1000), (15, 0));
    // The chain is rewritten (wiped by UniFi): the re-added rule counts from zero.
    g.b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    g.e.pass(Mode::Reassert);
    g.b.set_counter(Family::V4, FWD, last, 4);
    g.e.pass(Mode::Reassert);
    assert_eq!(take(&g, 1000), (4, 0));
}

#[test]
fn set_at_eighty_percent_raises_set_full() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    let _ = g.take_events();
    // Shrink picket-g4 to 10 for the test, then fill 8.
    g.b.st().sets.get_mut(sets::PICKET_G4).unwrap().maxelem = 10;
    let ops: Vec<SetOp> = (1..=8)
        .map(|i| SetOp {
            set: sets::PICKET_G4,
            elem: Elem::ip(ip(&format!("1.1.1.{i}"))),
            timeout: Some(100),
        })
        .collect();
    g.b.ipset_add(&ops);
    // The set no longer matches its definition (maxelem): the helper reports it rather than
    // replacing a referenced set.
    let rep = g.e.pass(Mode::Reassert);
    assert!(
        rep.pending
            .iter()
            .any(|p| p.starts_with("set:picket-g4:incompatible")),
        "{:?}",
        rep.pending
    );
}

#[test]
fn set_full_event_from_fill() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    let _ = g.take_events();
    let n = (sets::MAXELEM as u64 * 4).div_ceil(5) as u32; // 80 %, rounded up
    let ops: Vec<SetOp> = (0..n)
        .map(|i| SetOp {
            set: sets::PICKET_G4,
            elem: Elem::ip(std::net::Ipv4Addr::from(0x0b00_0000 + i).into()),
            timeout: Some(100),
        })
        .collect();
    g.b.ipset_add(&ops);
    g.e.pass(Mode::Reassert);
    let p = g.take_events();
    assert!(p.set_full.contains("picket-g4"), "{p:?}");
    let s = g.shared.snapshot().sets;
    assert_eq!(
        s.iter().find(|x| x.name == "picket-g4").unwrap().entries,
        n as u64
    );
    // Edge-triggered: not again while it stays high.
    g.e.pass(Mode::Reassert);
    assert!(g.take_events().set_full.is_empty());
}

// ---- redirect ------------------------------------------------------------------------------------

fn with_nat(nat4: &str, nat6: &str, ipv6: bool) -> Vec<String> {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.set_table(Family::V4, TableName::Nat, &fx(nat4));
    g.b.set_table(Family::V6, TableName::Nat, &fx(nat6));
    let mut r = lan();
    r.redirect = Some(redirect(ipv6));
    g.apply(&r).conditions.redirect_missing
}

#[test]
fn redirect_present_and_missing() {
    assert!(with_nat("nat-redirect-present.rules", "nat6-redirect-present.rules", true).is_empty());
    assert_eq!(
        with_nat("nat-redirect-missing.rules", "nat6-redirect-present.rules", true),
        vec!["ipv4"]
    );
    assert_eq!(
        with_nat("nat-redirect-present.rules", "nat6-redirect-missing.rules", true),
        vec!["ipv6"]
    );
    // With ipv6: false only IPv4 is checked.
    assert!(with_nat("nat-redirect-present.rules", "nat6-redirect-missing.rules", false).is_empty());
}

#[test]
fn redirect_aimed_elsewhere_is_missing() {
    assert_eq!(
        with_nat(
            "nat-redirect-elsewhere.rules",
            "nat6-redirect-present.rules",
            true
        ),
        vec!["ipv4"]
    );
}

#[test]
fn redirect_shadowing_in_both_directions() {
    // An earlier DNAT to another resolver shadows the correct rule: missing.
    assert_eq!(
        with_nat("nat-redirect-shadowed.rules", "nat6-redirect-present.rules", true),
        vec!["ipv4"]
    );
    // A wrong rule after the correct one is shadowed by it: present.
    assert!(
        with_nat(
            "nat-redirect-shadowing.rules",
            "nat6-redirect-present.rules",
            true
        )
        .is_empty()
    );
}

#[test]
fn redirect_source_matches_are_honoured() {
    assert_eq!(
        with_nat(
            "nat-redirect-source-limited.rules",
            "nat6-redirect-present.rules",
            true
        ),
        vec!["ipv4"]
    );
    assert!(
        with_nat(
            "nat-redirect-subnet-scoped.rules",
            "nat6-redirect-present.rules",
            true
        )
        .is_empty()
    );
    // IPv6 rules scoped to the networks' prefixes miss link-local clients (br0 holds fe80::1/64;
    // edge-unifi.md §3).
    assert_eq!(
        with_nat(
            "nat-redirect-subnet-scoped.rules",
            "nat6-redirect-subnet-scoped.rules",
            true
        ),
        vec!["ipv6"]
    );
}

#[test]
fn redirect_check_of_a_fanned_out_nat_table_is_quick() {
    // 12 chains each jumping 6 times to the next (README "Untrusted input": never stalls).
    let start = std::time::Instant::now();
    assert!(
        with_nat(
            "nat-redirect-jump-fan-out.rules",
            "nat6-redirect-present.rules",
            true
        )
        .is_empty()
    );
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
}

#[test]
fn ipv6_dns_reject_installed_with_ipv6_false() {
    let mut g = unifi("filter-block-all-reject.rules");
    // UniFi's hook chains in ip6tables.
    let mut six = fx("filter6-block-all-reject.rules");
    six.push_str("-A UBIOS_INPUT_USER_HOOK -p udp -m udp --dport 67 -j ACCEPT\n");
    g.b.set_table(Family::V6, TableName::Filter, &six);
    g.b.set_table(Family::V4, TableName::Nat, &fx("nat-redirect-present.rules"));
    let mut r = lan();
    r.redirect = Some(redirect(false));
    let resp = g.apply(&r);
    assert!(resp.rules_ok, "{resp:?}");
    assert_eq!(g.chain(Family::V6, DNS6), chain_rules(Family::V6, DNS6));
    let input = g.chain(Family::V6, "UBIOS_INPUT_USER_HOOK");
    assert_eq!(input.len(), 5);
    assert!(
        input[..4].iter().all(|x| x.ends_with("-j PICKET-DNS6")),
        "first in the hook: {input:#?}"
    );
    let fwd = g.chain(Family::V6, "UBIOS_FORWARD_USER_HOOK");
    assert_eq!(fwd.len(), 6);
    assert!(fwd.contains(&"-i br0 -p tcp -m tcp --dport 853 -j PICKET-DNS6".to_string()));
    assert!(
        !g.b.table(Family::V4, TableName::Filter)
            .chains
            .iter()
            .any(|c| c.name == DNS6)
    );
    // UniFi puts a rule first: the reject jumps move back to the top.
    let mut t = g.b.table(Family::V6, TableName::Filter);
    t.chains
        .iter_mut()
        .find(|c| c.name == "UBIOS_INPUT_USER_HOOK")
        .unwrap()
        .rules
        .insert(0, ("-j ACCEPT".into(), 0));
    g.b.st().tables.insert((Family::V6, TableName::Filter), t);
    g.e.pass(Mode::Reassert);
    let input = g.chain(Family::V6, "UBIOS_INPUT_USER_HOOK");
    assert!(
        input[..4].iter().all(|x| x.ends_with("-j PICKET-DNS6")),
        "{input:#?}"
    );
    // Back to ipv6: true: the reject and its chain go.
    r.redirect = Some(redirect(true));
    g.apply(&r);
    assert!(
        !g.b.table(Family::V6, TableName::Filter)
            .chains
            .iter()
            .any(|c| c.name == DNS6)
    );
    assert!(
        !g.chain(Family::V6, "UBIOS_INPUT_USER_HOOK")
            .iter()
            .any(|x| x.contains("PICKET"))
    );
}

#[test]
fn dns6_reject_stays_above_the_firewall_jump_on_debian() {
    // edge-firewall.md §2, §4: on a Debian FORWARD holding only its final REJECT, the IPv6 DNS
    // reject and the firewall jump are adjacent; a PICKET-FWD jump moved above them would
    // accept DNS to a granted or static destination before the reject. Re-assert repairs it.
    let b = Arc::new(FakeBackend::new());
    for f in Family::BOTH {
        b.set_table(
            f,
            TableName::Filter,
            "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A FORWARD -j REJECT\n",
        );
    }
    let shared = Shared::new();
    let events = shared.subscribe();
    let mut e = Engine::new(b.clone(), shared, Platform::Debian);
    e.startup();
    let mut r = req(&[("eth1", FwMode::Enforce)]);
    r.redirect = Some(picket_api::helper::RedirectCheck {
        interfaces: vec!["eth1".into()],
        port: 5335,
        ipv6: false,
    });
    assert!(e.apply(&r).unwrap().rules_ok);
    let fwd = b.rules(Family::V6, "FORWARD");
    assert!(fwd[..3].iter().all(|x| x.ends_with("-j PICKET-DNS6")), "{fwd:#?}");
    assert_eq!(fwd[3], "-i eth1 -j PICKET-FWD");
    let _ = events.take();
    // The firewall jump lands first, behind the helper's back.
    let mut t = b.table(Family::V6, TableName::Filter);
    let c = t.chains.iter_mut().find(|c| c.name == "FORWARD").unwrap();
    let j = c.rules.remove(3);
    c.rules.insert(0, j);
    b.st().tables.insert((Family::V6, TableName::Filter), t);
    b.advance(Duration::from_secs(2));
    let rep = e.pass(Mode::Reassert);
    assert!(rep.rules_ok, "{rep:?}");
    assert!(
        rep.repaired.contains(&"moved-dns6:eth1".to_string()),
        "{:?}",
        rep.repaired
    );
    let fwd = b.rules(Family::V6, "FORWARD");
    assert!(fwd[..3].iter().all(|x| x.ends_with("-j PICKET-DNS6")), "{fwd:#?}");
    assert_eq!(fwd[3], "-i eth1 -j PICKET-FWD");
    assert!(events.take().repaired.is_some());
}

#[test]
fn unchanged_rules_are_not_rewritten() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.apply(&lan());
    g.b.st().files.insert(RULES_FILE.into(), b"sentinel".to_vec());
    // Same rules again: no write (the sentinel stays).
    g.apply(&lan());
    assert_eq!(g.b.st().files[RULES_FILE], b"sentinel");
    g.apply(&req(&[("br0", FwMode::Enforce)]));
    assert_ne!(g.b.st().files[RULES_FILE], b"sentinel");
}

#[test]
fn nat_read_failure_is_pending_but_not_a_rules_problem() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.set_table(Family::V4, TableName::Nat, &fx("nat-redirect-present.rules"));
    g.b.set_table(Family::V6, TableName::Nat, &fx("nat6-redirect-present.rules"));
    let mut r = lan();
    r.redirect = Some(redirect(true));
    assert!(g.apply(&r).conditions.redirect_missing.is_empty());
    g.b.st().save_fail = vec![(Family::V4, TableName::Nat), (Family::V6, TableName::Nat)];
    let rep = g.e.pass(Mode::Reassert);
    assert!(rep.rules_ok, "{:?}", rep.pending);
    assert!(
        rep.pending.contains(&"nat4:exec_timeout".to_string()),
        "{:?}",
        rep.pending
    );
    // The last known redirect state holds rather than flapping.
    assert!(rep.conditions.redirect_missing.is_empty());
}

// ---- persistence, restarts and the redirect check's addresses ------------------------------------

#[test]
fn failed_rules_write_is_retried_at_each_reassert() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.st().write_fail = true;
    let r = g.apply(&lan());
    assert!(r.ok && r.rules_ok, "{r:?}");
    assert!(r.pending.contains(&"persist".to_string()), "{:?}", r.pending);
    assert!(!g.b.st().files.contains_key(RULES_FILE));
    // Still failing: still pending, and `status` says so.
    let rep = g.e.pass(Mode::Reassert);
    assert!(rep.pending.contains(&"persist".to_string()), "{:?}", rep.pending);
    assert!(rep.rules_ok, "the kernel objects are all in place");
    assert!(g.shared.snapshot().pending.contains(&"persist".to_string()));
    // The disk recovers: the next re-assert writes the file.
    g.b.st().write_fail = false;
    let rep = g.e.pass(Mode::Reassert);
    assert!(!rep.pending.iter().any(|p| p == "persist"), "{:?}", rep.pending);
    let file: RulesFile = serde_json::from_slice(&g.b.st().files[RULES_FILE]).unwrap();
    assert_eq!(file.apply.unwrap().interfaces.len(), 2);
    // A `disable` whose write fails is retried too, so the flag still survives a restart.
    g.b.st().write_fail = true;
    assert!(g.e.disable().pending.contains(&"persist".to_string()));
    g.b.st().write_fail = false;
    g.e.pass(Mode::Reassert);
    let file: RulesFile = serde_json::from_slice(&g.b.st().files[RULES_FILE]).unwrap();
    assert!(file.disabled);
}

#[test]
fn rules_json_is_applied_at_start_after_a_reboot() {
    let mut g = unifi("filter-block-all-reject.rules");
    let mut r = lan();
    r.static_allow = vec!["192.0.2.10".into(), "0.0.0.0/0".into()];
    r.exempt = vec!["fd00::5".into()];
    g.apply(&r);
    let saved = g.b.st().files[RULES_FILE].clone();
    // A reboot: UniFi's tables without Picket's chains or jumps, and no sets.
    let b = Arc::new(FakeBackend::new());
    b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    b.set_table(
        Family::V6,
        TableName::Filter,
        &fx("filter6-block-all-reject.rules"),
    );
    b.st().files.insert(RULES_FILE.into(), saved);
    let mut e = Engine::new(b.clone(), Shared::new(), Platform::Unifi);
    let rep = e.startup();
    assert!(rep.rules_ok, "{:?}", rep.pending);
    for f in [Family::V4, Family::V6] {
        let rules = b.rules(f, WAN);
        assert!(rules.contains(&"-i br0 -j PICKET-FWD".to_string()), "{rules:#?}");
        assert!(rules.contains(&"-i br10 -j PICKET-MON".to_string()));
    }
    assert_eq!(b.members(sets::STATIC4).len(), 3);
    assert_eq!(b.members(sets::EXEMPT6).len(), 1);
}

#[test]
fn lost_static_set_is_recreated_and_refilled() {
    let mut g = unifi("filter-block-all-reject.rules");
    let mut r = lan();
    r.static_allow = vec!["10.0.0.0/8".into(), "192.0.2.10".into()];
    g.apply(&r);
    let _ = g.take_events();
    g.b.destroy_behind_back(sets::STATIC4);
    g.b.advance(Duration::from_secs(2));
    g.e.pass(Mode::Reassert);
    let ev = g.take_events().repaired.expect("rules_repaired");
    assert!(ev.missing.contains(&"set:picket-static4".to_string()), "{ev:?}");
    assert!(
        ev.recreated_sets.is_empty(),
        "only timed sets are re-sent by the edge"
    );
    assert_eq!(
        g.b.members(sets::STATIC4).len(),
        2,
        "the helper refills it itself"
    );
}

#[test]
fn timed_set_first_created_after_startup_is_named_in_recreated_sets() {
    // edge-firewall.md §4 "Re-assert": a missing set is recreated empty and named in
    // `recreated_sets`, also when creating it failed at start-up, so the edge re-sends its
    // entries for it now rather than at its 10-minute reconcile.
    let b = Arc::new(FakeBackend::new());
    b.st().create_fail = vec![sets::PICKET4.into()];
    let shared = Shared::new();
    let events = shared.subscribe();
    let mut e = Engine::new(b.clone(), shared, Platform::Debian);
    let rep = e.startup();
    assert!(
        rep.pending.contains(&"set:picket4:netlink_timeout".to_string()),
        "{:?}",
        rep.pending
    );
    let _ = events.take();
    b.st().create_fail.clear();
    b.advance(Duration::from_secs(2));
    let rep = e.pass(Mode::Reassert);
    assert_eq!(rep.recreated, vec!["picket4".to_string()]);
    let ev = events.take().repaired.expect("rules_repaired");
    assert_eq!(ev.recreated_sets, vec!["picket4".to_string()]);
    // Seen in place from now on: an ordinary pass names nothing.
    assert!(e.pass(Mode::Reassert).recreated.is_empty());
}

#[test]
fn corrupt_rules_and_snapshot_files_are_survived() {
    let b = Arc::new(FakeBackend::new());
    b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    b.st().files.insert(RULES_FILE.into(), b"{not json".to_vec());
    let wall = b.st().wall_ms;
    let snap = format!(
        r#"{{"version":1,"written_at_ms":{wall},"sets":[{{"set":"picket4","entries":[["192.168.1.10","1.1.1.1",300],[null,5]]}}]}}"#
    );
    b.st().files.insert(SNAP_FILE.into(), snap.into_bytes());
    let mut e = Engine::new(b.clone(), Shared::new(), Platform::Unifi);
    let rep = e.startup();
    assert!(
        e.desired().interfaces.is_empty(),
        "no rules from a corrupt rules.json"
    );
    assert!(rep.rules_ok, "{:?}", rep.pending);
    // What parsed before the malformed entry is restored; the snapshot is deleted either way.
    assert_eq!(b.members(sets::PICKET4).len(), 1);
    assert!(!b.st().files.contains_key(SNAP_FILE));
}

#[test]
fn snapshot_leaves_out_members_picket_never_adds() {
    let mut g = unifi("filter-block-all-reject.rules");
    let wide = Elem {
        ip: ip("10.9.0.0"),
        cidr: Some(24),
        ip2: Some(ip("1.1.1.1")),
        cidr2: Some(32),
    };
    for elem in [wide, Elem::host_pair(ip("192.168.1.10"), ip("1.1.1.1"))] {
        assert!(
            g.b.ipset_add(&[SetOp {
                set: sets::PICKET4,
                elem,
                timeout: Some(100)
            }])[0]
                .is_ok()
        );
    }
    g.e.shutdown();
    let snap: serde_json::Value = serde_json::from_slice(&g.b.st().files[SNAP_FILE]).unwrap();
    let p4 = snap["sets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["set"] == "picket4")
        .unwrap();
    assert_eq!(
        p4["entries"],
        serde_json::json!([["192.168.1.10", "1.1.1.1", 100]])
    );
}

#[test]
fn disable_removes_the_ipv6_dns_reject_too() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.set_table(Family::V4, TableName::Nat, &fx("nat-redirect-present.rules"));
    let mut r = lan();
    r.redirect = Some(redirect(false));
    g.apply(&r);
    let hooks = ["UBIOS_INPUT_USER_HOOK", "UBIOS_FORWARD_USER_HOOK"];
    for h in hooks {
        assert!(
            g.chain(Family::V6, h)
                .iter()
                .any(|x| x.ends_with("-j PICKET-DNS6"))
        );
    }
    g.e.disable();
    for h in hooks {
        assert!(
            !g.chain(Family::V6, h).iter().any(|x| x.contains("PICKET")),
            "{h}"
        );
    }
    assert_eq!(
        g.chain(Family::V6, DNS6),
        chain_rules(Family::V6, DNS6),
        "the chain stays"
    );
    g.e.enable();
    for h in hooks {
        assert!(
            g.chain(Family::V6, h)
                .iter()
                .any(|x| x.ends_with("-j PICKET-DNS6"))
        );
    }
}

#[test]
fn gateway_addresses_are_cached_between_redirect_checks() {
    let mut g = unifi("filter-block-all-reject.rules");
    g.b.set_table(Family::V4, TableName::Nat, &fx("nat-redirect-present.rules"));
    g.b.set_table(Family::V6, TableName::Nat, &fx("nat6-redirect-present.rules"));
    let mut r = lan();
    r.redirect = Some(redirect(true));
    assert!(g.apply(&r).conditions.redirect_missing.is_empty());
    let reads = g.b.st().addr_reads;
    // The 2 s checks reuse the addresses for a minute.
    for _ in 0..20 {
        g.b.advance(Duration::from_secs(2));
        assert!(g.e.pass(Mode::Reassert).conditions.redirect_missing.is_empty());
    }
    assert_eq!(g.b.st().addr_reads, reads);
    g.b.advance(Duration::from_secs(25));
    g.e.pass(Mode::Reassert);
    assert_eq!(g.b.st().addr_reads, reads + 1, "re-read after a minute");
    // The gateway is renumbered and the rule follows: the stale addresses would call it
    // missing, so they are read again before the redirect is reported.
    let nat = fx("nat-redirect-present.rules").replace("192.0.2.1:", "192.0.2.254:");
    g.b.set_table(Family::V4, TableName::Nat, &nat);
    for a in g.b.st().addrs.iter_mut() {
        if a.addr == ip("192.0.2.1") {
            a.addr = ip("192.0.2.254");
        }
    }
    g.b.advance(Duration::from_secs(12));
    let rep = g.e.pass(Mode::Reassert);
    assert!(rep.conditions.redirect_missing.is_empty(), "{:?}", rep.conditions);
    assert_eq!(g.b.st().addr_reads, reads + 2);
    // A rule that is really gone doesn't make every 2 s check re-read them.
    g.b.set_table(Family::V4, TableName::Nat, &fx("nat-redirect-missing.rules"));
    for _ in 0..4 {
        g.b.advance(Duration::from_secs(2));
        assert_eq!(g.e.pass(Mode::Reassert).conditions.redirect_missing, vec!["ipv4"]);
    }
    assert_eq!(g.b.st().addr_reads, reads + 2);
}

// ---- UniFi's local networks (issue #47) ------------------------------------------------------

use picket_api::helper::{LocalDst, MAX_LOCAL_DST_NETS};
use picket_edge_helper::ipset::{SetFamily, SetType};

const LOCAL4: &str = "UBIOS_local_zoned_subnets";
const LOCAL6: &str = "UBIOS6_local_zoned_subnets";

fn net(s: &str) -> Elem {
    let (a, l) = s.split_once('/').unwrap();
    Elem::net(ip(a), l.parse().unwrap())
}

fn put(b: &FakeBackend, name: &str, t: SetType, fam: SetFamily, members: &[(&str, bool)]) {
    let m: Vec<(Elem, bool)> = members.iter().map(|(s, n)| (net(s), *n)).collect();
    b.put_set(name, t, fam, &m);
}

/// UniFi's two sets: the NAS VLAN, a routed network no gateway interface is on, IPv6.
fn local_sets(b: &FakeBackend) {
    put(
        b,
        LOCAL4,
        SetType::HashNet,
        SetFamily::Inet,
        &[
            ("192.168.20.0/24", false),
            ("10.99.0.0/16", false),
            ("192.168.1.0/24", false),
        ],
    );
    put(
        b,
        LOCAL6,
        SetType::HashNet,
        SetFamily::Inet6,
        &[("fd00:20::/64", false)],
    );
}

fn local_of<'a>(c: &'a [LocalDst], iface: &str, family: &str) -> &'a LocalDst {
    c.iter()
        .find(|l| l.interface == iface && l.family == family)
        .unwrap_or_else(|| panic!("no {iface} {family} in {c:#?}"))
}

#[test]
fn unifi_local_networks_are_reported_per_enforce_interface_and_family() {
    let mut g = unifi("filter-block-all-reject.rules");
    local_sets(&g.b);
    let r = g.apply(&lan());
    assert!(r.rules_ok, "{r:?}");
    let c = g.e.pass(Mode::Reassert).conditions.local_dst;
    let v4 = local_of(&c, "br0", "ipv4");
    assert_eq!(v4.set, LOCAL4);
    assert_eq!(v4.unavailable, None);
    assert_eq!(v4.nets, vec!["10.99.0.0/16", "192.168.1.0/24", "192.168.20.0/24"]);
    let v6 = local_of(&c, "br0", "ipv6");
    assert_eq!(
        (v6.set.as_str(), v6.nets.clone()),
        (LOCAL6, vec!["fd00:20::/64".to_string()])
    );
    // br10 monitors: nothing Picket blocks there, so nothing to exclude.
    assert_eq!(c.len(), 2, "{c:#?}");
    // The same snapshot goes out with the helper's conditions.
    assert_eq!(g.shared.snapshot().conditions.local_dst, c);
}

#[test]
fn local_network_edits_show_at_the_next_pass() {
    let mut g = unifi("filter-block-all-reject.rules");
    local_sets(&g.b);
    g.apply(&lan());
    g.take_events();
    put(
        &g.b,
        LOCAL4,
        SetType::HashNet,
        SetFamily::Inet,
        &[("192.168.30.0/24", false)],
    );
    let c = g.e.pass(Mode::Reassert).conditions.local_dst;
    assert_eq!(local_of(&c, "br0", "ipv4").nets, vec!["192.168.30.0/24"]);
    let ev = g.take_events();
    assert!(ev.conditions.is_some(), "a change is published");
}

#[test]
fn unusable_local_sets_are_reported_and_never_partly_used() {
    let big: Vec<String> = (0..=MAX_LOCAL_DST_NETS)
        .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
        .collect();
    let big: Vec<(&str, bool)> = big.iter().map(|s| (s.as_str(), false)).collect();
    type Make<'a> = Box<dyn Fn(&FakeBackend) + 'a>;
    let cases: Vec<(&str, Make<'_>)> = vec![
        (
            "nomatch",
            Box::new(|b| {
                put(
                    b,
                    LOCAL4,
                    SetType::HashNet,
                    SetFamily::Inet,
                    &[("192.168.0.0/16", false), ("192.168.20.0/24", true)],
                );
            }),
        ),
        (
            "set_type:hash:net,net",
            Box::new(|b| {
                b.put_set(
                    LOCAL4,
                    SetType::HashNetNet,
                    SetFamily::Inet,
                    &[(Elem::host_pair(ip("192.168.20.1"), ip("10.0.0.1")), false)],
                );
            }),
        ),
        (
            "family",
            Box::new(|b| {
                put(
                    b,
                    LOCAL4,
                    SetType::HashNet,
                    SetFamily::Inet6,
                    &[("fd00::/64", false)],
                )
            }),
        ),
        ("read:no_set", Box::new(|_| {})),
        (
            "too_large",
            Box::new(move |b| put(b, LOCAL4, SetType::HashNet, SetFamily::Inet, &big)),
        ),
    ];
    for (want, make) in cases {
        let mut g = unifi("filter-block-all-reject.rules");
        make(&g.b);
        g.apply(&lan());
        let c = g.e.pass(Mode::Reassert).conditions.local_dst;
        let v4 = local_of(&c, "br0", "ipv4");
        assert_eq!(v4.unavailable.as_deref(), Some(want), "{v4:?}");
        assert!(v4.nets.is_empty(), "{want}: {v4:?}");
    }
}

#[test]
fn an_unguarded_jump_into_the_external_chain_makes_local_networks_unavailable() {
    let t = format!(
        "{}-A UBIOS_LAN_IN_USER -m set --match-set UBIOS_ADDRv4_Internal dst -j {WAN}\n",
        fx("filter-block-all-reject.rules")
    );
    let mut g = env(
        Platform::Unifi,
        "filter-block-all-reject.rules",
        "filter6-block-all-reject.rules",
    );
    g.b.set_table(Family::V4, TableName::Filter, &t);
    local_sets(&g.b);
    g.apply(&lan());
    let c = g.e.pass(Mode::Reassert).conditions.local_dst;
    let v4 = local_of(&c, "br0", "ipv4");
    assert!(
        v4.unavailable
            .as_deref()
            .is_some_and(|u| u.starts_with("layout:")),
        "{v4:?}"
    );
    assert!(v4.nets.is_empty());
    // IPv6 has its own table and keeps its snapshot.
    assert_eq!(local_of(&c, "br0", "ipv6").unavailable, None);
}

#[test]
fn a_table_that_can_not_be_read_drops_that_familys_local_networks() {
    let mut g = unifi("filter-block-all-reject.rules");
    local_sets(&g.b);
    g.apply(&lan());
    assert_eq!(g.e.pass(Mode::Reassert).conditions.local_dst.len(), 2);
    g.b.st().save_fail.push((Family::V4, TableName::Filter));
    let c = g.e.pass(Mode::Reassert).conditions.local_dst;
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(c[0].family, "ipv6");
}

/// A write whose read-back fails leaves the table unknown: that family's local networks go
/// until a read succeeds again, rather than resting on the read from before the write.
#[test]
fn a_failed_read_back_after_a_write_drops_that_familys_local_networks() {
    let mut g = unifi("filter-block-all-reject.rules");
    local_sets(&g.b);
    g.apply(&lan());
    assert_eq!(g.e.pass(Mode::Reassert).conditions.local_dst.len(), 2);
    // UniFi rewrote the table without Picket's objects: the pass writes them back, and the read
    // that should verify the write fails.
    g.b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    g.b.st().fail_reads_after_restore.push(Family::V4);
    let c = g.e.pass(Mode::Reassert).conditions.local_dst;
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(c[0].family, "ipv6");
    g.b.st().save_fail.clear();
    let c = g.e.pass(Mode::Reassert).conditions.local_dst;
    assert_eq!(c.len(), 2, "back once a read succeeds: {c:#?}");
}

#[test]
fn debian_reports_no_local_networks() {
    let mut g = env(
        Platform::Debian,
        "filter-debian-final-reject.rules",
        "filter-debian-final-reject.rules",
    );
    local_sets(&g.b);
    g.apply(&lan());
    assert!(g.e.pass(Mode::Reassert).conditions.local_dst.is_empty());
}
