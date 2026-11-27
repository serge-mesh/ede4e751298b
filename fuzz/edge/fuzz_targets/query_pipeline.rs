//! The whole query pipeline (edge.md §4, §16) on arbitrary client messages, over each transport,
//! with and without a profile named in the DoH path or DoT name, with the device's limits applied
//! by the pipeline or by the listener (`Admitted::Held`): one in-process edge with a config and a
//! bundle, no upstream reachable (every resolution fails at once), no log. A reply must never
//! exceed what the transport allows, and nothing may panic (a panic is caught per query, so this
//! asserts that none happened).
#![no_main]

use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use picket_api::logs::Proto;
use picket_edge::dns::pipeline::{self, Inbound};
use picket_edge::edge::Edge;

struct World {
    rt: tokio::runtime::Runtime,
    edge: Arc<Edge>,
    // Kept for the process's life (and reachable, so LeakSanitizer doesn't count them).
    _running: std::sync::Mutex<picket_edge::service::Running>,
    _dir: std::path::PathBuf,
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let dir = std::env::temp_dir().join(format!("picket-fuzz-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dev")).unwrap();
        std::fs::write(dir.join("dev/edge.json"), br#"{"updates_enabled": false}"#).unwrap();
        let (edge, running) = rt.block_on(async {
            let running = picket_edge::service::start(
                picket_edge::service::Options {
                    config: Some(dir.join("dev/edge.json")),
                    data_dir: Some(dir.join("dev/edge")),
                    runtime_dir: dir.join("dev/run"),
                },
                picket_edge::service::Tuning {
                    platform: Some(picket_edge::paths::HostPlatform::Debian),
                    clock: Some(picket_edge::clock::Clock::fixed(true)),
                    service: Some(false),
                    firmware_file: dir.join("none"),
                    ..Default::default()
                },
                |_| {},
            )
            .await
            .unwrap();
            let edge = Arc::clone(&running.edge);
            let cfg: picket_api::edge_config::EdgeConfig = serde_json::from_value(serde_json::json!({
                "default_profile": "default",
                "profiles": {
                    "default": {"upstream": "none", "block": ["b"], "log": "off",
                                "forward_zones": ["lan"]},
                    "strict": {"upstream": "none", "block": ["b"], "log": "off",
                               "block_response": {"type": "nxdomain"}, "allowed_sources": ["127.0.0.0/8"]},
                },
                "forward_zones": {"lan": {"zone": "lan", "group": "none"}},
                "listeners": [{"id": "x", "proto": "doh", "bind": "127.0.0.1:1", "tls": {"managed": "dns.home.arpa"}, "ips": ["192.168.1.1"]}],
                "limits": {"client_qps": 100000, "client_inflight": 4096},
            }))
            .unwrap();
            let target = picket_edge::hooks::ActivationTarget {
                object_id: "a".repeat(64),
                config_version: "a".repeat(64),
                config_hash: "b".repeat(64),
                config: Arc::new(cfg),
                config_changed: true,
                from_disk: false,
            };
            let r = picket_edge::dns::activation::DnsActivator;
            use picket_edge::hooks::Activator;
            assert_eq!(r.activate(&edge, &target).await, picket_edge::hooks::Activation::Active);
            (edge, running)
        });
        // A bundle with keys, a pattern, a rewrite, a host mapping and an IP rule.
        let text = "||ads.example^\n/trac?ker/\n||rw.example^$dnsrewrite=NOERROR;A;192.0.2.1\n||cn.example^$dnsrewrite=NOERROR;CNAME;t.example\n||203.0.113.5^";
        let pc = picket_rules::formats::ParseConfig::new(
            picket_rules::formats::Format::Adblock,
            picket_rules::formats::DomainsAs::Exact,
            jiff::Timestamp::now(),
        );
        let mut rules = vec![];
        picket_rules::formats::parse_lines(text.as_bytes(), &pc, |e| rules.push(e.rule)).unwrap();
        let action = picket_rules::matcher::BundleAction::Block;
        let compiled = picket_bundle::compile::compile_rules(&rules, &picket_bundle::compile::CompileOptions::new(action, None));
        let built = picket_bundle::compile::build(&compiled, &picket_bundle::compile::BuildOptions::new("b", action)).unwrap();
        let b = picket_bundle::compile::load_bundle(&built.head_blob.bytes, &built.blobs, None, picket_bundle::patterns::DEFAULT_BUDGET).unwrap();
        let prev = edge.active();
        let mut next = picket_edge::edge::ActiveState::clone(&prev);
        let mut ab = picket_edge::dns::filter::ActiveBundles::default();
        ab.bundles.insert("b".into(), Arc::new(b));
        next.bundles = Arc::new(ab);
        edge.active.store(Arc::new(next));
        World {
            rt,
            edge,
            _running: std::sync::Mutex::new(running),
            _dir: dir,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, msg)) = data.split_first() else {
        return;
    };
    let w = world();
    let proto = match sel & 3 {
        0 => Proto::Udp,
        1 => Proto::Tcp,
        2 => Proto::Dot,
        _ => Proto::Doh,
    };
    let named = match (sel >> 2) & 3 {
        1 => Some("strict"),
        2 => Some("nope"),
        _ => None,
    };
    let payload = if sel & 0x10 != 0 { 512 } else { 1232 };
    let client = SocketAddr::from(([127, 0, 0, 1], 5353));
    // The watchdog's internal query, or where the device's limits are applied: by the pipeline,
    // or by the listener holding the slot (DoH admits a POST before reading its body).
    let (internal, held) = match sel >> 6 {
        0 => (false, false),
        1 => (true, false),
        _ => (false, true),
    };
    let slot = if held {
        match pipeline::admit_early(&w.edge, client) {
            Ok(s) => s,
            // The listener answers it (HTTP 429): it never reaches the pipeline.
            Err(_) => return,
        }
    } else {
        None
    };
    let panics = w.edge.metrics.panics.load(Relaxed);
    let out = w.rt.block_on(pipeline::serve(
        &w.edge,
        Inbound {
            msg,
            client,
            listener: "x",
            udp_payload: payload,
            proto,
            named_profile: named,
            extension: sel & 0x20 != 0,
            internal,
            admitted: if held {
                pipeline::Admitted::Held
            } else {
                pipeline::Admitted::Here
            },
        },
    ));
    drop(slot);
    assert_eq!(
        w.edge.metrics.panics.load(Relaxed),
        panics,
        "a query task panicked"
    );
    if let Some(r) = out.reply {
        assert!(r.len() >= 12 && r.len() <= 65_535);
        if proto == Proto::Udp {
            assert!(
                r.len() <= usize::from(payload).max(512),
                "UDP reply over the limit: {}",
                r.len()
            );
        }
        assert_ne!(r[2] & 0x80, 0, "a reply has QR set");
    }
});
