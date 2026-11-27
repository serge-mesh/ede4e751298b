//! The config object as the DNS data path compiles it (api.md §4; core is untrusted as seen by
//! the edge): the runtime (profiles, clients, allowed sources, forward zones, listeners), the
//! upstream pool's configuration (trust stores parsed, plain upstreams refused to public IPs),
//! and profile choice and special names over addresses and names drawn from the input.
#![no_main]

use std::net::IpAddr;
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use picket_api::edge_config::EdgeConfig;
use picket_edge::dns::runtime::DnsRuntime;

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let (json, rest) = data.split_at(split);
    let Ok(cfg) = serde_json::from_slice::<EdgeConfig>(json) else {
        return;
    };
    let cfg = Arc::new(cfg);
    let Ok(rt) = DnsRuntime::build(Arc::clone(&cfg)) else {
        return;
    };
    let ip: IpAddr = match rest.len() {
        n if n >= 17 => IpAddr::from(<[u8; 16]>::try_from(&rest[1..17]).unwrap()),
        n if n >= 5 => IpAddr::from(<[u8; 4]>::try_from(&rest[1..5]).unwrap()),
        _ => IpAddr::from([192, 168, 1, 10]),
    };
    let mac = (rest.len() >= 23).then(|| <[u8; 6]>::try_from(&rest[17..23]).unwrap());
    let d = rt.device(ip, mac);
    let _ = rt.clients.key(&d);
    let _ = rt.clients.log_name(&d);
    let named = std::str::from_utf8(rest).ok().filter(|s| s.len() < 64);
    let _ = rt.choose(None, &d);
    let _ = rt.choose(named, &d);
    if let Some(n) = named
        && let Ok(w) = picket_wire::WireName::from_text(n)
    {
        let _ = rt.managed_answer(w.as_name());
        for p in rt.profiles.values() {
            let _ = p.zones.longest_match(w.as_name());
        }
    }
    let (logs, _rx) = picket_edge::logs::LogProducer::new("fuzz".into(), Arc::default());
    let pool = picket_edge::dns::upstream::UpstreamPool::new(
        picket_edge::metrics::Metrics::new(),
        picket_edge::conditions::Conditions::new(logs),
    );
    let _ = pool.configure(&cfg);
    for g in pool.group_ids() {
        let grp = pool.group(&g).unwrap();
        let enc = grp.upstreams.iter().filter(|u| u.encrypted()).count();
        assert!(enc == 0 || enc == grp.upstreams.len(), "mixed groups are refused");
        for u in &grp.upstreams {
            assert!(u.encrypted() || picket_edge::dns::upstream::plain_allowed(u.cfg.ip));
        }
    }
    // The same config again keeps every group's generation (its cache entries stay valid).
    let before: Vec<(String, u64)> = pool
        .group_ids()
        .into_iter()
        .map(|g| {
            let n = pool.group(&g).unwrap().generation;
            (g, n)
        })
        .collect();
    let _ = pool.configure(&cfg);
    for (g, n) in before {
        assert_eq!(
            pool.group(&g).map(|x| x.generation),
            Some(n),
            "group {g} kept its generation"
        );
    }
});
