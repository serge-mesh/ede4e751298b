#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

use std::sync::Arc;

use picket_api::edge_config::FwMode;
use picket_api::helper::{ApplyRequest, ApplyResponse, InterfaceMode, RedirectCheck};
use picket_edge_helper::engine::Engine;
use picket_edge_helper::fake::FakeBackend;
use picket_edge_helper::iptables::exec::parse_ip_addr_json;
use picket_edge_helper::iptables::{Family, Platform, TableName};
use picket_edge_helper::shared::{Mailbox, Pending, Shared};

pub fn fx(name: &str) -> String {
    let p = format!("{}/../../fixtures/unifi/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

pub struct Env {
    pub b: Arc<FakeBackend>,
    pub shared: Arc<Shared>,
    pub e: Engine<FakeBackend>,
    pub events: Arc<Mailbox>,
}

/// A fake gateway with these filter tables, after start-up step 1.
pub fn env(platform: Platform, f4: &str, f6: &str) -> Env {
    env_with(platform, f4, f6, "ip-addr.json")
}

/// The second rendering of the UniFi layouts (`fixtures/unifi/id-tags/`): the same layout in
/// iptables and ip6tables, and that gateway's addresses.
pub fn ids(f: &str) -> Env {
    let f = format!("id-tags/{f}");
    env_with(Platform::Unifi, &f, &f, "id-tags/ip-addr.json")
}

fn env_with(platform: Platform, f4: &str, f6: &str, addrs: &str) -> Env {
    let b = Arc::new(FakeBackend::new());
    b.set_table(Family::V4, TableName::Filter, &fx(f4));
    b.set_table(Family::V6, TableName::Filter, &fx(f6));
    b.st().addrs = parse_ip_addr_json(fx(addrs).as_bytes()).unwrap();
    let shared = Shared::new();
    let events = shared.subscribe();
    let mut e = Engine::new(b.clone(), shared.clone(), platform);
    e.startup();
    Env { b, shared, e, events }
}

pub fn unifi(f4: &str) -> Env {
    env(Platform::Unifi, f4, "filter6-block-all-reject.rules")
}

pub fn ifs(list: &[(&str, FwMode)]) -> Vec<InterfaceMode> {
    list.iter()
        .map(|(n, m)| InterfaceMode {
            name: n.to_string(),
            mode: *m,
        })
        .collect()
}

pub fn req(list: &[(&str, FwMode)]) -> ApplyRequest {
    ApplyRequest {
        interfaces: ifs(list),
        static_allow: vec![],
        exempt: vec![],
        redirect: None,
    }
}

pub fn lan() -> ApplyRequest {
    req(&[("br0", FwMode::Enforce), ("br10", FwMode::Monitor)])
}

pub fn redirect(ipv6: bool) -> RedirectCheck {
    RedirectCheck {
        interfaces: vec!["br0".into(), "br10".into()],
        port: 5335,
        ipv6,
    }
}

impl Env {
    pub fn apply(&mut self, r: &ApplyRequest) -> ApplyResponse {
        self.e.apply(r).expect("valid apply")
    }
    pub fn chain(&self, f: Family, c: &str) -> Vec<String> {
        self.b.rules(f, c)
    }
    pub fn restores(&self) -> usize {
        self.b.st().restores.len()
    }
    pub fn take_events(&self) -> Pending {
        self.events.take()
    }
}

/// Index of the first rule containing `needle`.
pub fn pos(rules: &[String], needle: &str) -> usize {
    rules
        .iter()
        .position(|r| r.contains(needle))
        .unwrap_or_else(|| panic!("{needle} not in {rules:#?}"))
}
