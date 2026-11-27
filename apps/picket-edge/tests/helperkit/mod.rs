//! The real picket-edge-helper engine and socket server in process, on its in-memory backend
//! (UniFi filter tables from the recorded fixtures), for the firewall-client tests
//! (edge-firewall.md §3–§5).

#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use picket_edge_helper::engine::{self, Cmd, Engine};
use picket_edge_helper::fake::FakeBackend;
use picket_edge_helper::fast;
use picket_edge_helper::iptables::{Family, Platform, TableName};
use picket_edge_helper::server::{self, Server, ServerConfig};
use picket_edge_helper::shared::Shared;
use tokio::sync::watch;

pub fn fx(name: &str) -> String {
    let p = format!("{}/../../fixtures/unifi/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

pub struct Helper {
    pub path: PathBuf,
    pub b: Arc<FakeBackend>,
    pub shared: Arc<Shared>,
    _dir: tempfile::TempDir,
    stop: watch::Sender<bool>,
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// A helper serving `helper.sock` in a fresh directory, accepting this process's UID as the edge.
pub fn start() -> Helper {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("helper.sock");
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
    let shared = Shared::new();
    let mut e = Engine::new(b.clone(), shared.clone(), Platform::Unifi);
    e.startup();
    let (etx, erx) = sync_channel::<Cmd>(16);
    std::thread::spawn(move || engine::run(e, erx));
    let fast = fast::spawn(b.clone(), shared.clone(), etx.clone()).expect("the fast worker starts");
    let l = server::bind(&path, None).unwrap();
    let l = tokio::net::UnixListener::from_std(l).unwrap();
    let (stop, rx) = watch::channel(false);
    let me = rustix::process::getuid().as_raw();
    let cfg = ServerConfig {
        edge_uid: Some(me),
        admin_uid: me,
        // The edge's two connections and a test's own share one UID here.
        edge_conns: 8,
        admin_conns: 8,
        ..ServerConfig::default()
    };
    let srv = Server::new(b.clone(), shared.clone(), etx, fast, cfg);
    tokio::spawn(srv.serve(l, rx));
    Helper {
        path,
        b,
        shared,
        _dir: dir,
        stop,
    }
}

impl Helper {
    /// The live members of a set as (src, dst, remaining seconds).
    pub fn members(&self, set: &str) -> Vec<(std::net::IpAddr, Option<std::net::IpAddr>, Option<u32>)> {
        self.b
            .members(set)
            .into_iter()
            .map(|(e, t)| (e.ip, e.ip2, t))
            .collect()
    }

    /// True when the set holds (src → dst) for a pair set, or dst for a global set.
    pub fn has(&self, set: &str, src: Option<&str>, dst: &str) -> bool {
        let dst: std::net::IpAddr = dst.parse().unwrap();
        self.members(set).iter().any(|(a, b, _)| match src {
            Some(s) => *a == s.parse::<std::net::IpAddr>().unwrap() && *b == Some(dst),
            None => *a == dst && b.is_none(),
        })
    }

    pub fn rules(&self, chain: &str) -> Vec<String> {
        self.b.rules(Family::V4, chain)
    }

    /// Sends one request as another client would (an entry added behind the edge's back).
    pub async fn call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        kind: &str,
        data: &Req,
    ) -> Resp {
        let mut c = picket_edge::firewall::conn::Conn::connect(&self.path, Duration::from_secs(2))
            .await
            .unwrap();
        let mut ignore = |_f: picket_api::helper::Frame| {};
        c.request(kind, data, Duration::from_secs(10), &mut ignore)
            .await
            .unwrap()
    }
}
