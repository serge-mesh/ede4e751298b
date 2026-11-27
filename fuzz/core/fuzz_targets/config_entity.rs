//! UI API entity bodies (api.md §7): any JSON, decoded as each entity kind and validated with
//! the system objects around it. Decoding and validation never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::config::model::*;
use picket_core::config::validate::validate;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let mut m = Model::default();
    for u in picket_core::config::system::cloudflare_upstreams() {
        m.upstreams.insert(u.id.clone(), u);
    }
    m.upstream_groups.insert(
        "cloudflare".into(),
        picket_core::config::system::cloudflare_group(),
    );
    m.profiles.insert(
        "dnssec-validator".into(),
        picket_core::config::system::dnssec_profile(),
    );
    if let Ok(x) = serde_json::from_value::<ProfileDef>(v.clone()) {
        m.profiles.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<ClientDef>(v.clone()) {
        m.clients.push(x);
    }
    if let Ok(x) = serde_json::from_value::<ListenerDef>(v.clone()) {
        m.listeners.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<EdgeDef>(v.clone()) {
        m.edges.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<UpstreamDef>(v.clone()) {
        m.upstreams.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<FeedProviderDef>(v.clone()) {
        let _ = x.secret_refs();
        m.feed_providers.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<FeedDef>(v.clone()) {
        m.feeds.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<BundleDef>(v.clone()) {
        m.bundles.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<LookupProviderDef>(v.clone()) {
        let _ = x.secret_refs();
        m.lookup_providers.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<ForwardZoneDef>(v.clone()) {
        m.forward_zones.insert(x.id.clone(), x);
    }
    if let Ok(x) = serde_json::from_value::<UpstreamGroupDef>(v) {
        m.upstream_groups.insert(x.id.clone(), x);
    }
    let _ = validate(&m);
    if let Some(e) = m.edges.keys().next().cloned() {
        let _ = picket_core::edges::render(&m, &e, &Default::default());
    }
});
