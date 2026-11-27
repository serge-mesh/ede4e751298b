//! The watchdog's test under descriptor exhaustion (edge.md §16 "Watchdog"): running out of
//! descriptors is the stuck state a restart cures, so it fails the test instead of being hidden.
//! The test query doesn't fall back to the in-process path when it can't get a socket (only an
//! address it can't use from here does that), and an accept loop whose accepts keep failing for
//! want of descriptors stops stamping its liveness mark. One test in its own binary: it lowers
//! `RLIMIT_NOFILE`, which every thread of the process shares.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use serde_json::json;

use picket_edge::service::{self, Options, Tuning};
use support::{MockCore, wait_until, write_edge_json};

const T: Duration = Duration::from_secs(30);
const STALE: Duration = Duration::from_secs(2);

async fn self_test_until(edge: &Arc<picket_edge::edge::Edge>, want: bool) -> bool {
    let end = std::time::Instant::now() + T;
    while std::time::Instant::now() < end {
        if picket_edge::dns::pipeline::self_test(edge).await == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn descriptor_exhaustion_fails_the_watchdog_test() {
    let core = MockCore::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let (config, data, run) = (
        tmp.path().join("dev/edge.json"),
        tmp.path().join("dev/edge"),
        tmp.path().join("dev/run"),
    );
    write_edge_json(&config, Some(&core), json!({}));
    let id = core.set_config(&json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
        "listeners": [{"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"}],
        "default_profile": "default",
        "profiles": {"default": {"upstream": "g"}},
        "upstreams": {"up1": {"protocol": "udp", "ip": "127.0.0.1", "port": 9}},
        "upstream_groups": {"g": {"upstreams": ["up1"], "strategy": "failover"}},
    }));
    let mut t = Tuning {
        platform: Some(picket_edge::paths::HostPlatform::Debian),
        clock: Some(picket_edge::clock::Clock::fixed(true)),
        update_result: Some(data.join("no-update-result.json")),
        service: Some(false),
        firmware_file: data.join("no-such-version-file"),
        ..Default::default()
    };
    t.session.backoff_min = Duration::from_millis(50);
    t.session.backoff_max = Duration::from_millis(300);
    t.firewall.socket = run.join("no-helper.sock");
    t.dns.listener_stale = STALE;
    let r = service::start(
        Options {
            config: Some(config),
            data_dir: Some(data),
            runtime_dir: run,
        },
        t,
        |_| {},
    )
    .await
    .unwrap();
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())
            && !edge.dns.listeners.local_addrs("lan-dns").is_empty())
        .await
    );
    assert!(self_test_until(&edge, true).await);
    let at = edge.dns.listeners.local_addrs("lan-dns")[0];
    // A client socket made now: connecting it later takes no descriptor.
    let client = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    // No descriptor left for anything new, whatever holes the table has.
    let saved = getrlimit(Resource::Nofile);
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(0),
            maximum: saved.maximum,
        },
    )
    .unwrap();
    let no_socket = !picket_edge::dns::pipeline::self_test(&edge).await;
    // The listener's accept now fails with EMFILE (the connection waits in the backlog).
    let connected = client.connect(&at.into());
    let mut stale = false;
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while !stale && std::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(100)).await;
        stale = edge.dns.listeners.stale_listener(STALE).is_some();
    }
    setrlimit(Resource::Nofile, saved).unwrap();
    connected.unwrap();
    assert!(
        no_socket && stale,
        "a test query with no socket failed: {no_socket}; the accept loop's mark went stale while \
         every accept failed: {stale}"
    );
    // Descriptors again: the queued connection is accepted, the mark and the test recover.
    assert!(
        wait_until(T, || edge.dns.listeners.stale_listener(STALE).is_none()).await,
        "the mark is stamped again"
    );
    assert!(self_test_until(&edge, true).await);
    drop(client);
    r.shutdown().await;
}
