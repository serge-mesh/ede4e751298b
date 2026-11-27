//! Opt-in real-kernel test: `PICKET_HELPER_KERNEL_TESTS=1 cargo test -p picket-edge-helper
//! --test kernel`. It re-runs itself in a new user and network namespace (`unshare -rn`), where
//! it has `CAP_NET_ADMIN` over a private netfilter, and drives the real netlink ipset client and
//! the real `iptables-save`/`iptables-restore` through the engine. Needs the `ip_set` and
//! `xt_set` modules and an iptables (legacy or nft) on the host; skipped otherwise.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use picket_api::edge_config::FwMode;
use picket_api::helper::{ApplyRequest, DumpRequest, InterfaceMode, RedirectCheck, sets};
use picket_edge_helper::backend::{Backend, RealBackend, SetOp};
use picket_edge_helper::dump::{self, DumpStore};
use picket_edge_helper::engine::{Engine, Mode, SETS};
use picket_edge_helper::fake::FakeTable;
use picket_edge_helper::ipset::{CreateSpec, Elem, SetFamily, SetType};
use picket_edge_helper::iptables::layout::{DNS6, FWD, MON};
use picket_edge_helper::iptables::model::Table;
use picket_edge_helper::iptables::plan::{chain_rules, dns6_rules};
use picket_edge_helper::iptables::{Family, Platform, TableName};
use picket_edge_helper::shared::Shared;
use picket_edge_helper::snapshot;

const INNER: &str = "PICKET_HELPER_KERNEL_INNER";

#[test]
fn kernel() {
    if std::env::var("PICKET_HELPER_KERNEL_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: set PICKET_HELPER_KERNEL_TESTS=1 to run against the kernel");
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let st = Command::new("unshare")
        .args(["-rn"])
        .arg(&exe)
        .args(["--exact", "kernel_inner", "--nocapture", "--test-threads=1"])
        .env(INNER, "1")
        .status()
        .expect("run unshare");
    assert!(st.success(), "inner kernel test failed");
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn rules(b: &RealBackend, f: Family, chain: &str) -> Vec<String> {
    let t = Table::parse(&b.save(f, TableName::Filter).unwrap()).unwrap();
    t.chain(chain)
        .map(|c| c.rules.iter().map(|r| r.args_text().unwrap()).collect())
        .unwrap_or_default()
}

#[test]
fn kernel_inner() {
    if std::env::var(INNER).is_err() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let b = Arc::new(RealBackend::new(dir.path().to_path_buf()));
    // A Debian-like host: FORWARD ends in a REJECT.
    for f in Family::BOTH {
        b.restore(f, "*filter\n-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A FORWARD -j REJECT\nCOMMIT\n")
            .unwrap();
    }
    let shared = Shared::new();
    let mut e = Engine::new(b.clone(), shared.clone(), Platform::Debian);
    let rep = e.startup();
    assert!(rep.pending.is_empty(), "{:?}", rep.pending);
    for d in &SETS {
        let h = b.ipset_header(d.name).unwrap().expect("set created");
        assert_eq!(h.type_name, d.set_type.name());
        assert_eq!(h.maxelem, Some(d.maxelem));
        assert_eq!(h.timeout.is_some(), d.timed());
    }
    // The chains as the real iptables-save prints them match what the planner expects.
    for f in Family::BOTH {
        assert_eq!(rules(&b, f, FWD), chain_rules(f, FWD), "{f:?}");
        assert_eq!(rules(&b, f, MON), chain_rules(f, MON), "{f:?}");
    }

    let req_lo_eth9 = ApplyRequest {
        interfaces: vec![
            InterfaceMode {
                name: "lo".into(),
                mode: FwMode::Enforce,
            },
            InterfaceMode {
                name: "eth9".into(),
                mode: FwMode::Monitor,
            },
        ],
        static_allow: vec!["10.0.0.0/8".into(), "0.0.0.0/0".into(), "fd00::/8".into()],
        exempt: vec!["192.168.1.50".into()],
        redirect: None,
    };
    let r = e.apply(&req_lo_eth9).unwrap();
    assert!(r.rules_ok, "{r:?}");
    for f in Family::BOTH {
        let fwd = rules(&b, f, "FORWARD");
        let n = fwd.len();
        assert_eq!(
            fwd[n - 1],
            "-j REJECT --reject-with icmp-port-unreachable".replace(
                "icmp-port-unreachable",
                if f == Family::V4 {
                    "icmp-port-unreachable"
                } else {
                    "icmp6-port-unreachable"
                },
            )
        );
        let mut jumps = fwd[n - 3..n - 1].to_vec();
        jumps.sort();
        assert_eq!(
            jumps,
            vec![
                "-i eth9 -j PICKET-MON".to_string(),
                "-i lo -j PICKET-FWD".to_string()
            ]
        );
    }
    // Idempotent against the real tables: a second pass changes nothing and stays OK.
    let before = b.save(Family::V4, TableName::Filter).unwrap();
    let rep = e.pass(Mode::Reassert);
    assert!(rep.rules_ok && rep.repaired.is_empty(), "{rep:?}");
    let strip = |s: &str| {
        s.lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split_once("] ").map_or(l, |x| x.1).to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        strip(&b.save(Family::V4, TableName::Filter).unwrap()),
        strip(&before)
    );

    // Static set: /0 stored as its halves.
    let mut s4 = Vec::new();
    b.ipset_list(sets::STATIC4, &mut |m| {
        s4.push(format!("{}/{}", m.elem.ip, m.elem.cidr.unwrap()))
    })
    .unwrap();
    s4.sort();
    assert_eq!(s4, vec!["0.0.0.0/1", "10.0.0.0/8", "128.0.0.0/1"]);

    // ensure / list / delete over netlink, adds acting as -exist.
    let pair = Elem::host_pair(ip("192.168.1.10"), ip("93.184.216.34"));
    let ops = [
        SetOp {
            set: sets::PICKET4,
            elem: pair,
            timeout: Some(100),
        },
        SetOp {
            set: sets::PICKET4,
            elem: pair,
            timeout: Some(300),
        },
        SetOp {
            set: sets::PICKET_G6,
            elem: Elem::ip(ip("2001:db8::1")),
            timeout: Some(50),
        },
        SetOp {
            set: sets::PICKET_G4,
            elem: Elem::ip(ip("2001:db8::1")),
            timeout: Some(50),
        },
    ];
    let res = b.ipset_add(&ops);
    assert!(res[0].is_ok() && res[1].is_ok() && res[2].is_ok(), "{res:?}");
    assert!(res[3].is_err(), "family mismatch refused by the kernel");
    let mut got = Vec::new();
    b.ipset_list(sets::PICKET4, &mut |m| got.push(m)).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].elem, pair);
    let t = got[0].timeout.unwrap();
    assert!(
        (298..=300).contains(&t),
        "timeout overwritten by the second add: {t}"
    );
    b.ipset_probe().unwrap();

    // Snapshot of the real sets.
    assert!(snapshot::write(&*b).unwrap() >= 2);
    let snap = std::fs::read_to_string(dir.path().join(snapshot::SNAP_FILE)).unwrap();
    assert!(snap.contains("[\"192.168.1.10\",\"93.184.216.34\","), "{snap}");

    assert!(
        b.ipset_del(&[SetOp {
            set: sets::PICKET4,
            elem: pair,
            timeout: None
        }])[0]
            .is_ok()
    );
    assert!(
        b.ipset_del(&[SetOp {
            set: sets::PICKET4,
            elem: pair,
            timeout: None
        }])[0]
            .is_ok(),
        "absent is fine"
    );

    // A member Picket never adds (a /24 pair) is left out of a dump and deleted.
    let wide = Elem {
        ip: ip("10.9.0.0"),
        cidr: Some(24),
        ip2: Some(ip("1.1.1.1")),
        cidr2: Some(32),
    };
    let host = Elem::host_pair(ip("192.168.1.11"), ip("1.1.1.1"));
    let res = b.ipset_add(&[
        SetOp {
            set: sets::PICKET4,
            elem: wide,
            timeout: Some(100),
        },
        SetOp {
            set: sets::PICKET4,
            elem: host,
            timeout: Some(100),
        },
    ]);
    assert!(res.iter().all(|r| r.is_ok()), "{res:?}");
    let store = std::sync::Mutex::new(DumpStore::default());
    let req = DumpRequest {
        set: sets::PICKET4.into(),
        cursor: None,
        limit: 100,
    };
    let page = dump::page(&store, &*b, &req).unwrap();
    assert_eq!(page.entries.len(), 1, "{page:?}");
    assert_eq!(page.entries[0].src, Some(ip("192.168.1.11")));
    let mut left = Vec::new();
    b.ipset_list(sets::PICKET4, &mut |m| left.push(m.elem)).unwrap();
    assert_eq!(left, vec![host]);

    // The IPv6 DNS reject (redirect.ipv6: false) as the real ip6tables prints it: first in INPUT
    // and FORWARD, and stable across passes.
    let mut with_dns6 = req_lo_eth9.clone();
    with_dns6.redirect = Some(RedirectCheck {
        interfaces: vec!["eth9".into()],
        port: 5335,
        ipv6: false,
    });
    let r = e.apply(&with_dns6).unwrap();
    assert!(r.rules_ok, "{r:?}");
    assert_eq!(rules(&b, Family::V6, DNS6), chain_rules(Family::V6, DNS6));
    let input = rules(&b, Family::V6, "INPUT");
    assert_eq!(&input[..2], &dns6_rules("eth9", false)[..], "{input:#?}");
    let fwd6 = rules(&b, Family::V6, "FORWARD");
    assert_eq!(&fwd6[..3], &dns6_rules("eth9", true)[..], "{fwd6:#?}");
    assert!(
        !rules(&b, Family::V4, "INPUT")
            .iter()
            .any(|r| r.contains("PICKET"))
    );
    let before = b.save(Family::V6, TableName::Filter).unwrap();
    let rep = e.pass(Mode::Reassert);
    assert!(rep.rules_ok && rep.repaired.is_empty(), "{rep:?}");
    assert_eq!(
        strip(&b.save(Family::V6, TableName::Filter).unwrap()),
        strip(&before)
    );

    // Disable removes the jumps, the IPv6 DNS reject's included; enable puts them back.
    let r = e.disable();
    assert!(r.conditions.helper_disabled);
    assert!(
        !rules(&b, Family::V4, "FORWARD")
            .iter()
            .any(|r| r.contains("PICKET"))
    );
    assert!(
        !rules(&b, Family::V6, "INPUT")
            .iter()
            .any(|r| r.contains("PICKET"))
    );
    assert_eq!(rules(&b, Family::V4, FWD), chain_rules(Family::V4, FWD));
    let r = e.enable();
    assert!(r.rules_ok, "{r:?}");

    // The jumps removed behind the helper's back are repaired and reported.
    b.restore(Family::V4, "*filter\n-D FORWARD -i lo -j PICKET-FWD\nCOMMIT\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let rep = e.pass(Mode::Reassert);
    assert_eq!(rep.repaired, vec!["jump4:lo".to_string()]);

    unifi_layouts();
}

const WAN: &str = "UBIOS_LAN_WAN_USER";
const BLOCK_ALL_LOG: &str = "[FIREWALL_POLICY-R-30000]";

/// Feeds `text` to `iptables-restore` (or ip6tables), as bytes; `--noflush` or a full replace.
fn restore_raw(f: Family, text: &[u8], noflush: bool) -> bool {
    let cmd = if f == Family::V4 {
        "iptables-restore"
    } else {
        "ip6tables-restore"
    };
    let mut c = Command::new(cmd);
    if noflush {
        c.arg("--noflush");
    }
    let mut child = c.stdin(Stdio::piped()).spawn().expect(cmd);
    child.stdin.take().unwrap().write_all(text).unwrap();
    child.wait().unwrap().success()
}

/// A UniFi fixture as `iptables-restore` input for this family (the IPv6 rendering gets IPv6
/// sets and reject types, as ip6tables requires).
fn unifi_table(f: Family, fixture: &str) -> String {
    let mut s = common::fx(fixture);
    if f == Family::V6 {
        s = s
            .replace("UBIOS_ADDRv4_", "UBIOS_ADDRv6_")
            .replace("UBIOS_local_zoned_subnets", "UBIOS6_local_zoned_subnets")
            .replace("UBIOS_GRP_", "UBIOS6_GRP_")
            .replace("icmp-port-unreachable", "icmp6-port-unreachable")
            .replace("picket-exempt4", "picket-exempt6")
            .replace("picket-static4", "picket-static6")
            .replace("picket4 ", "picket6 ")
            .replace("picket-g4", "picket-g6");
    }
    FakeTable::from_text(&s).render("filter", false)
}

/// Picket's two jumps sit together directly above the Block All's NFLOG rule.
fn assert_jumps_above_block_all(rules: &[String]) {
    let at = |needle: &str| {
        rules
            .iter()
            .position(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not in {rules:#?}"))
    };
    let mut js = [at("-i br0 -j PICKET-FWD"), at("-i br10 -j PICKET-MON")];
    js.sort();
    let a = at(BLOCK_ALL_LOG);
    assert_eq!(js, [a - 2, a - 1], "{rules:#?}");
    assert_eq!(
        rules.iter().filter(|r| r.contains("PICKET")).count(),
        2,
        "{rules:#?}"
    );
}

/// UniFi's layouts against the real iptables (edge-unifi.md §4): placement above the Block All,
/// a policy landing between a jump and its catch-all, a surviving misplaced jump, and a stray
/// jump whose comment isn't UTF-8 — all repaired with real `-D`/`-I`.
fn unifi_layouts() {
    let dir = tempfile::tempdir().unwrap();
    let b = Arc::new(RealBackend::new(dir.path().to_path_buf()));
    for (family, names) in [
        (
            SetFamily::Inet,
            [
                "UBIOS_ADDRv4_Internal",
                "UBIOS_local_zoned_subnets",
                "UBIOS_GRP_iot",
                "UBIOS_GRP_telemetry",
                "UBIOS_GRP_gaming",
            ],
        ),
        (
            SetFamily::Inet6,
            [
                "UBIOS_ADDRv6_Internal",
                "UBIOS6_local_zoned_subnets",
                "UBIOS6_GRP_iot",
                "UBIOS6_GRP_telemetry",
                "UBIOS6_GRP_gaming",
            ],
        ),
    ] {
        for name in names {
            b.ipset_create(&CreateSpec {
                name: name.into(),
                set_type: SetType::HashNet,
                family,
                revision: 0,
                timeout: None,
                maxelem: 1024,
            })
            .unwrap();
        }
    }
    for f in Family::BOTH {
        let t = unifi_table(f, "filter-block-all-reject.rules");
        assert!(restore_raw(f, t.as_bytes(), false), "{t}");
    }
    let mut e = Engine::new(b.clone(), Shared::new(), Platform::Unifi);
    e.startup();
    let lan = ApplyRequest {
        interfaces: vec![
            InterfaceMode {
                name: "br0".into(),
                mode: FwMode::Enforce,
            },
            InterfaceMode {
                name: "br10".into(),
                mode: FwMode::Monitor,
            },
        ],
        static_allow: vec![],
        exempt: vec![],
        redirect: None,
    };
    let r = e.apply(&lan).unwrap();
    assert!(r.rules_ok, "{r:?}");
    assert_eq!(r.conditions, Default::default());
    for f in Family::BOTH {
        assert_jumps_above_block_all(&rules(&b, f, WAN));
    }
    let rep = e.pass(Mode::Reassert);
    assert!(rep.rules_ok && rep.repaired.is_empty(), "{rep:?}");

    // UniFi inserts a policy between the jumps and the Block All: the jumps move below it.
    let wan = rules(&b, Family::V4, WAN);
    let at = wan.iter().position(|r| r.contains(BLOCK_ALL_LOG)).unwrap() + 1;
    let ins = format!(
        "*filter\n-I {WAN} {at} -p tcp -m tcp --dport 443 -m comment --comment \"FIREWALL_POLICY 10003 Allow HTTPS\" -j ACCEPT\nCOMMIT\n"
    );
    assert!(restore_raw(Family::V4, ins.as_bytes(), true));
    std::thread::sleep(Duration::from_millis(20));
    let rep = e.pass(Mode::Reassert);
    assert!(rep.rules_ok, "{rep:?}");
    assert!(rep.repaired.contains(&"moved4:br0".to_string()), "{rep:?}");
    let wan = rules(&b, Family::V4, WAN);
    assert_jumps_above_block_all(&wan);
    let https = wan.iter().position(|r| r.contains("Allow HTTPS")).unwrap();
    assert!(wan[https + 1].contains("PICKET"), "{wan:#?}");

    // A re-provisioned table where a surviving jump sits above a policy added below it.
    for f in Family::BOTH {
        let t = unifi_table(f, "filter-policy-between-jump.rules");
        assert!(restore_raw(f, t.as_bytes(), false), "{t}");
    }
    let rep = e.pass(Mode::Reassert);
    assert!(rep.rules_ok, "{rep:?}");
    for f in Family::BOTH {
        let wan = rules(&b, f, WAN);
        assert_jumps_above_block_all(&wan);
        let gaming = wan
            .iter()
            .rposition(|r| r.contains("Block guest gaming"))
            .unwrap();
        let fwd = wan.iter().position(|r| r.contains("PICKET-FWD")).unwrap();
        assert!(gaming < fwd, "{f:?}: {wan:#?}");
    }

    // A stray jump to PICKET-FWD with a comment cut mid-character (not UTF-8), first in the
    // chain: deleted by its exact bytes, so nothing accepts ahead of UniFi's policies.
    let mut stray = format!("*filter\n-I {WAN} 1 -i br0 -m comment --comment \"Bl").into_bytes();
    stray.extend_from_slice(&[0xf0, 0x9f]);
    stray.extend_from_slice(b"\" -j PICKET-FWD\nCOMMIT\n");
    assert!(restore_raw(Family::V4, &stray, true));
    let rep = e.pass(Mode::Reassert);
    assert!(rep.rules_ok && rep.pending.is_empty(), "{rep:?}");
    assert_jumps_above_block_all(&rules(&b, Family::V4, WAN));

    // disable removes every jump with real -D; enable puts them back in place.
    let r = e.disable();
    assert!(r.conditions.helper_disabled);
    for f in Family::BOTH {
        assert!(!rules(&b, f, WAN).iter().any(|r| r.contains("PICKET")));
    }
    assert!(e.enable().rules_ok);
    for f in Family::BOTH {
        assert_jumps_above_block_all(&rules(&b, f, WAN));
    }
}
