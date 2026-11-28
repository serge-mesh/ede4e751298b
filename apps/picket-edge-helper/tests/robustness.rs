//! Every decoder of untrusted input survives garbage (README "Untrusted input"): the
//! iptables-save parser and what runs on it, the netlink reply decoders, the socket's request
//! decoder, `ip -j addr` and the snapshot reader, fed mutated fixtures and random bytes. The
//! `fuzz/helper` targets search the same entry points nightly; this deterministic pass runs with
//! every `cargo test`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use common::fx;
use picket_api::edge_config::FwMode;
use picket_api::helper::sets;
use picket_edge_helper::backend::Backend;
use picket_edge_helper::engine::SETS;
use picket_edge_helper::fake::FakeBackend;
use picket_edge_helper::fast::to_op;
use picket_edge_helper::ipset::proto::{self, Reply, SetHeader};
use picket_edge_helper::iptables::exec::{parse_ip_addr_json, restore_bytes, save_text};
use picket_edge_helper::iptables::layout::{self, Platform};
use picket_edge_helper::iptables::model::Table;
use picket_edge_helper::iptables::nat::redirect_present;
use picket_edge_helper::iptables::plan::{Family, Want, plan};
use picket_edge_helper::rules::Desired;
use picket_edge_helper::server::{Request, parse_request};
use picket_edge_helper::snapshot::{self, SNAP_FILE};

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// A few byte flips, insertions, deletions, duplications or truncations of `base`.
fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    const TOKENS: [&[u8]; 8] = [
        b"\"",
        b" ! ",
        b"-A ",
        b"\n",
        b"-j PICKET-FWD",
        b"\\",
        b"[",
        b"\xff",
    ];
    let mut v = base.to_vec();
    for _ in 0..1 + rng.below(8) {
        if v.is_empty() {
            v.extend_from_slice(TOKENS[rng.below(TOKENS.len())]);
            continue;
        }
        let i = rng.below(v.len());
        match rng.below(6) {
            0 => v[i] = rng.next() as u8,
            1 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                v.splice(i..i, t.iter().copied());
            }
            2 => {
                let end = (i + 1 + rng.below(32)).min(v.len());
                v.drain(i..end);
            }
            3 => {
                let end = (i + 1 + rng.below(64)).min(v.len());
                let chunk = v[i..end].to_vec();
                v.splice(i..i, chunk);
            }
            4 => v.truncate(i),
            _ => v[i] ^= 1 << rng.below(8),
        }
    }
    v
}

const TABLES: [&str; 22] = [
    "filter-allow-all-above.rules",
    "filter-negated-dnat-deny-above.rules",
    "filter-zone-chain-diverts.rules",
    "filter-allow-below-block-all.rules",
    "filter-dispatch-without-interface.rules",
    "filter-block-all-reject.rules",
    "filter-block-all-state-limited.rules",
    "filter-debian-final-reject.rules",
    "filter-ends-in-return.rules",
    "filter-objects-below-block-all.rules",
    "filter-policy-between-jump.rules",
    "filter-unknown-layout.rules",
    "nat-redirect-shadowed.rules",
    "nat-redirect-source-limited.rules",
    "nat6-redirect-present.rules",
    "nat6-redirect-subnet-scoped.rules",
    "nat-redirect-jump-fan-out.rules",
    "id-tags/filter-default-allow.rules",
    "id-tags/filter-earlier-broad-deny.rules",
    "id-tags/filter-policy-between-jump-and-catch-all.rules",
    "id-tags/nat-redirect-elsewhere.rules",
    "id-tags/nat-redirect-present.rules",
];

#[test]
fn iptables_text_and_everything_on_it() {
    let mut rng = Rng(0x5eed_0001);
    let addrs = parse_ip_addr_json(fx("ip-addr.json").as_bytes()).unwrap();
    let ifs = [
        ("br0".to_string(), FwMode::Enforce),
        ("br10".to_string(), FwMode::Monitor),
    ];
    let dns6 = ["br0".to_string()];
    for name in TABLES {
        let base = fx(name).into_bytes();
        for _ in 0..150 {
            let bytes = mutate(&mut rng, &base);
            // Lossless: whatever the bytes, a rule read back is named again exactly.
            let text = save_text(bytes.clone());
            assert_eq!(restore_bytes(&text), bytes);
            let Ok(t) = Table::parse(&text) else { continue };
            for platform in [Platform::Unifi, Platform::Debian] {
                for (family, d) in [(Family::V4, &[][..]), (Family::V6, &dns6[..])] {
                    let p = plan(
                        &t,
                        &Want {
                            family,
                            platform,
                            interfaces: &ifs,
                            dns6: d,
                            disabled: false,
                        },
                    );
                    for l in p.restore.iter().flat_map(|r| r.lines()) {
                        // Only Picket's chains are ever declared (a declaration flushes).
                        assert!(!l.starts_with(':') || l.starts_with(":PICKET-"), "{l}");
                    }
                }
                let _ = layout::place(&t, platform, "br0");
            }
            for f in [Family::V4, Family::V6] {
                let _ = redirect_present(&t, f, &["br0".to_string(), "br10".to_string()], 5335, &addrs);
            }
        }
    }
}

#[test]
fn netlink_replies() {
    let mut rng = Rng(0x5eed_0002);
    let seeds: Vec<Vec<u8>> = vec![
        proto::req_protocol().encode(1),
        proto::req_list(7, "picket4", false).encode(2),
        proto::req_add(
            7,
            "picket6",
            &picket_edge_helper::ipset::Elem::host_pair(
                "fd00::1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ),
            Some(300),
        )
        .encode(3),
    ];
    for _ in 0..3000 {
        let data = if rng.below(3) == 0 {
            let n = rng.below(512);
            rng.bytes(n)
        } else {
            let s = &seeds[rng.below(seeds.len())];
            mutate(&mut rng, s)
        };
        let Ok(replies) = proto::decode_datagram(&data) else {
            continue;
        };
        for r in replies {
            if let Reply::Ipset { attrs, .. } = r {
                let mut h = SetHeader::default();
                let _ = proto::decode_list(&attrs, &mut h, &mut |_| {});
                let _ = proto::decode_type(&attrs);
                let _ = proto::decode_protocol(&attrs);
            }
        }
    }
}

#[test]
fn socket_requests_and_ip_addr_json() {
    let mut rng = Rng(0x5eed_0003);
    let frames: [&[u8]; 4] = [
        br#"{"type":"apply","id":1,"data":{"interfaces":[{"name":"br0","mode":"enforce"}],"static":["10.0.0.0/8","::/0"],"exempt":["192.0.2.1"],"redirect":{"interfaces":["br0"],"port":5335,"ipv6":false}}}"#,
        br#"{"type":"ensure","id":2,"data":{"entries":[{"set":"picket4","src":"192.168.1.10","dst":"1.1.1.1","timeout_s":300},{"set":"picket-g6","dst":"2001:db8::1","timeout_s":0}]}}"#,
        br#"{"type":"dump","id":3,"data":{"set":"picket6","cursor":"1.4096","limit":4096}}"#,
        br#"{"type":"hello","id":4,"data":{"proto_version":1,"events":false}}"#,
    ];
    for _ in 0..3000 {
        let seed = frames[rng.below(frames.len())];
        let f = mutate(&mut rng, seed);
        match parse_request(&f) {
            Ok((_, Request::Apply(r))) => {
                assert_eq!(Desired::from_request(&r.to_request()).as_ref(), Ok(&*r));
            }
            Ok((_, Request::Ensure(r))) => {
                for e in &r.entries {
                    if let Ok(op) = to_op(e, true) {
                        assert!((1..=picket_api::helper::MAX_TIMEOUT_S).contains(&op.timeout.unwrap()));
                    }
                }
            }
            _ => {}
        }
    }
    let base = fx("ip-addr.json").into_bytes();
    for _ in 0..1000 {
        if let Ok(v) = parse_ip_addr_json(&mutate(&mut rng, &base)) {
            assert!(
                v.iter()
                    .all(|a| a.prefix <= if a.addr.is_ipv4() { 32 } else { 128 })
            );
        }
    }
}

#[test]
fn snapshot_files() {
    let mut rng = Rng(0x5eed_0004);
    let wall = FakeBackend::new().wall_ms();
    let base = format!(
        r#"{{"version":1,"written_at_ms":{wall},"sets":[{{"set":"picket4","entries":[["192.168.1.10","93.184.216.34",250],["192.168.1.11","1.1.1.1",9]]}},{{"set":"picket-g6","entries":[[null,"2001:db8::1",30]]}}]}}"#
    )
    .into_bytes();
    for _ in 0..1000 {
        let b = FakeBackend::new();
        for d in &SETS {
            b.ipset_create(&d.spec()).unwrap();
        }
        b.st().files.insert(SNAP_FILE.into(), mutate(&mut rng, &base));
        let _ = snapshot::restore(&b, &sets::TIMED);
        for s in sets::TIMED {
            for (_, t) in b.members(s) {
                // Never more than an entry had at stop, never permanent.
                assert!(t.is_some_and(|t| (1..=250).contains(&t)), "{s}: {t:?}");
            }
        }
    }
}
