//! Decoding the edge's session messages (api.md §3): `hello` and `heartbeat` from an untrusted
//! edge, checked for size, syntax and range before use (README §2, Untrusted input).
//!
//! A message is refused only when what core keys on is malformed (the `boot`); everything else
//! is bounded instead: lists are cut to their caps, ids that aren't ids are left out, strings
//! past their bound are cut at a character boundary, and timestamps are clamped to core's clock
//! by the caller. Map keys that become metric labels are restricted to printable text.
//!
//! Pure functions of their input: fuzzed (`fuzz/core`, `session_message`).

use std::collections::BTreeMap;

use picket_api::session::{Applied, Condition, Have, Heartbeat, Hello, InProgress, Metrics, SessionMessage};

/// Largest session message core reads (a hello with long `have` lists is a few KiB).
pub const MAX_MESSAGE: usize = 1 << 20;

/// Bounds on what one message may carry (README §2, Bounded).
pub const MAX_HAVE_IDS: usize = 8;
pub const MAX_HAVE_TARGETS: usize = 512;
pub const MAX_CONDITIONS: usize = 256;
pub const MAX_ALLOWED_BINDS: usize = 1024;
pub const MAX_FLUSH_LOOKUPS: usize = 256;
pub const MAX_UPSTREAMS: usize = 64;
pub const MAX_LOOKUP_PROVIDERS: usize = 64;
pub const MAX_COLD_BUNDLES: usize = 256;
pub const MAX_REASONS: usize = 32;
/// Listeners whose certificate's root one message may report (`cert_roots`).
pub const MAX_CERT_ROOTS: usize = 256;
const MAX_KEY: usize = 128;
const MAX_DETAIL: usize = 4096;

/// A decoded message from the edge.
#[derive(Clone, Debug, PartialEq)]
pub enum Incoming {
    Hello(Box<Hello>),
    Heartbeat(Box<Heartbeat>),
    /// A message core doesn't act on (`welcome`, `changed`, or a type a newer edge sends).
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    #[error("the message is too large")]
    TooLarge,
    #[error("the message isn't a session message")]
    Malformed,
    #[error("the message's boot id is malformed")]
    BadBoot,
}

/// Decodes and bounds one text frame.
pub fn decode(text: &str) -> Result<Incoming, MessageError> {
    if text.len() > MAX_MESSAGE {
        return Err(MessageError::TooLarge);
    }
    let msg: SessionMessage = serde_json::from_str(text).map_err(|_| MessageError::Malformed)?;
    Ok(match msg {
        SessionMessage::Hello(mut h) => {
            sanitize_hello(&mut h)?;
            Incoming::Hello(h)
        }
        SessionMessage::Heartbeat(mut hb) => {
            sanitize_heartbeat(&mut hb)?;
            Incoming::Heartbeat(hb)
        }
        _ => Incoming::Other,
    })
}

/// Cuts `s` to at most `max` bytes at a character boundary.
pub fn cut(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

fn cut_opt(s: &mut Option<String>, max: usize) {
    if let Some(v) = s {
        cut(v, max);
    }
}

/// True when `s` may become a metric label value or a map key core stores: 1–128 bytes of
/// printable text without quotes or backslashes.
pub fn is_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_KEY
        && s.bytes()
            .all(|b| (0x21..0x7f).contains(&b) && b != b'"' && b != b'\\')
}

fn ids(list: &mut Vec<String>) {
    list.retain(|i| picket_api::ids::is_object_id(i));
    list.truncate(MAX_HAVE_IDS);
}

fn id_map(m: &mut BTreeMap<String, Vec<String>>) {
    let mut out = BTreeMap::new();
    for (k, mut v) in std::mem::take(m) {
        if out.len() >= MAX_HAVE_TARGETS || !is_label(&k) {
            continue;
        }
        ids(&mut v);
        out.insert(k, v);
    }
    *m = out;
}

/// Bounds a `have` report: only well-formed object ids, at most a few per target.
pub fn sanitize_have(h: &mut Have) {
    ids(&mut h.config);
    id_map(&mut h.bundles);
    id_map(&mut h.verdict_sets);
    cut_opt(&mut h.release, 64);
    let InProgress {
        config,
        bundles,
        verdict_sets,
    } = &mut h.in_progress;
    if config
        .as_deref()
        .is_some_and(|c| !picket_api::ids::is_object_id(c))
    {
        *config = None;
    }
    id_map(bundles);
    id_map(verdict_sets);
    if h.fetched
        .as_deref()
        .is_some_and(|f| !picket_api::ids::is_object_id(f))
    {
        h.fetched = None;
    }
}

fn sanitize_conditions(list: &mut Vec<Condition>) {
    list.retain(|c| crate::logs::decode::is_kind(&c.kind));
    list.truncate(MAX_CONDITIONS);
    for c in list.iter_mut() {
        cut_opt(&mut c.key, MAX_KEY);
        if c.detail
            .as_ref()
            .is_some_and(|d| serde_json::to_vec(d).map(|b| b.len()).unwrap_or(usize::MAX) > MAX_DETAIL)
        {
            c.detail = Some(serde_json::json!({"truncated": true}));
        }
    }
    // One entry per (kind, key): a repeated one would raise and resolve the same alert twice.
    let mut seen = std::collections::BTreeSet::new();
    list.retain(|c| seen.insert((c.kind.clone(), c.key.clone())));
}

fn sanitize_applied(a: &mut Applied) {
    let id = |o: &mut Option<String>| {
        if o.as_deref().is_some_and(|i| !picket_api::ids::is_id64(i)) {
            *o = None;
        }
    };
    id(&mut a.flush_dns);
    id(&mut a.install_now);
    id(&mut a.revoked_allows);
    let mut out = BTreeMap::new();
    for (k, v) in std::mem::take(&mut a.flush_lookups) {
        if out.len() < MAX_FLUSH_LOOKUPS && is_label(&k) && picket_api::ids::is_id64(&v) {
            out.insert(k, v);
        }
    }
    a.flush_lookups = out;
}

/// `cert_roots` (api.md §3; core.md §11): listener ids that are labels, roots that are
/// certificate fingerprints, at most [`MAX_CERT_ROOTS`].
fn sanitize_cert_roots(m: &mut BTreeMap<String, String>) {
    let mut out = BTreeMap::new();
    for (k, v) in std::mem::take(m) {
        if out.len() < MAX_CERT_ROOTS && is_label(&k) && picket_api::ids::is_cert_fingerprint(&v) {
            out.insert(k, v);
        }
    }
    *m = out;
}

fn sanitize_update(u: &mut Option<picket_api::session::UpdateOutcome>) {
    if let Some(o) = u {
        if o.result_id.is_empty() || o.result_id.len() > 64 {
            *u = None;
            return;
        }
        cut(&mut o.version, 64);
    }
}

fn bounded_map<V>(m: &mut BTreeMap<String, V>, max: usize) {
    let mut out = BTreeMap::new();
    for (k, v) in std::mem::take(m) {
        if out.len() < max && is_label(&k) {
            out.insert(k, v);
        }
    }
    *m = out;
}

fn sanitize_hist(h: &mut picket_api::Histogram) {
    h.buckets.truncate(picket_api::histogram::BUCKETS);
}

/// Bounds the metrics block: map keys become metric labels.
pub fn sanitize_metrics(m: &mut Metrics) {
    sanitize_hist(&mut m.latency_us);
    bounded_map(&mut m.upstream, MAX_UPSTREAMS);
    for u in m.upstream.values_mut() {
        sanitize_hist(&mut u.rtt_ms);
        bounded_map(&mut u.invalid, MAX_REASONS);
        bounded_map(&mut u.scrubbed, MAX_REASONS);
    }
    bounded_map(&mut m.lookups, MAX_LOOKUP_PROVIDERS);
    for l in m.lookups.values_mut() {
        sanitize_hist(&mut l.call_ms);
    }
    bounded_map(&mut m.cold, MAX_COLD_BUNDLES);
}

fn check_boot(boot: &str) -> Result<(), MessageError> {
    if crate::logs::decode::is_boot_id(boot) {
        Ok(())
    } else {
        Err(MessageError::BadBoot)
    }
}

/// Bounds a `hello`; refuses one whose boot is malformed.
pub fn sanitize_hello(h: &mut Hello) -> Result<(), MessageError> {
    check_boot(&h.boot)?;
    cut(&mut h.edge_version, 64);
    cut(&mut h.arch, 32);
    cut(&mut h.os, 128);
    cut(&mut h.kernel, 128);
    cut(&mut h.platform, 32);
    // At most 128 bytes (api.md §3); a longer value is cut, so it reads as what it starts with.
    cut_opt(&mut h.firmware, 128);
    h.allowed_binds.retain(|b| b.len() <= 64);
    h.allowed_binds.truncate(MAX_ALLOWED_BINDS);
    sanitize_have(&mut h.have);
    sanitize_conditions(&mut h.conditions);
    sanitize_applied(&mut h.applied);
    sanitize_update(&mut h.update);
    sanitize_cert_roots(&mut h.cert_roots);
    Ok(())
}

/// Bounds a `heartbeat`; refuses one whose boot is malformed.
pub fn sanitize_heartbeat(hb: &mut Heartbeat) -> Result<(), MessageError> {
    check_boot(&hb.boot)?;
    sanitize_metrics(&mut hb.metrics);
    bounded_map(&mut hb.logs.dropped, MAX_REASONS);
    if let Some(v) = &hb.versions
        && crate::logs::decode::check_versions(v).is_none()
    {
        hb.versions = None;
    }
    cut_opt(&mut hb.ready_version, 64);
    sanitize_have(&mut hb.have);
    sanitize_conditions(&mut hb.conditions);
    sanitize_applied(&mut hb.applied);
    sanitize_update(&mut hb.update);
    sanitize_cert_roots(&mut hb.cert_roots);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_is_bounded_and_needs_a_boot() {
        let id = picket_api::ids::object_id(b"x");
        let mut bundles = serde_json::Map::new();
        for i in 0..600 {
            bundles.insert(
                format!("b{i}"),
                serde_json::json!([id, "not-an-id", id, id, id, id, id, id, id, id]),
            );
        }
        let msg = serde_json::json!({"type": "hello", "data": {
            "edge_version": "1.0.0", "arch": "x86_64", "boot": "7f3a91",
            "firmware": "x".repeat(300),
            "have": {"config": [id, "nope"], "bundles": bundles, "fetched": "zz"},
            "conditions": [{"kind": "memory_low", "since": "2026-11-13T10:00:00Z"},
                           {"kind": "memory_low", "since": "2026-11-13T10:00:00Z"},
                           {"kind": "Bad Kind", "since": "2026-11-13T10:00:00Z"}],
            "applied": {"flush_dns": "0123456789abcdef", "install_now": "nope"}
        }});
        let Incoming::Hello(h) = decode(&msg.to_string()).unwrap() else {
            panic!()
        };
        assert_eq!(h.firmware.as_deref().map(str::len), Some(128));
        assert_eq!(h.have.config, vec![id.clone()]);
        assert_eq!(h.have.bundles.len(), MAX_HAVE_TARGETS);
        assert!(h.have.bundles.values().all(|v| v.len() == MAX_HAVE_IDS));
        assert!(h.have.fetched.is_none());
        assert_eq!(h.conditions.len(), 1);
        assert_eq!(h.applied.flush_dns.as_deref(), Some("0123456789abcdef"));
        assert!(h.applied.install_now.is_none());

        // cert_roots (core.md §11): listener ids that are labels, roots that are certificate
        // fingerprints, bounded.
        let fp = picket_api::ids::cert_fingerprint(b"root");
        let mut roots = serde_json::Map::new();
        for i in 0..400 {
            roots.insert(format!("l{i:03}"), serde_json::json!(fp));
        }
        roots.insert("bad id".into(), serde_json::json!(fp));
        roots.insert("a-bad-root".into(), serde_json::json!("SHA256:nothex"));
        for kind in ["hello", "heartbeat"] {
            let msg = serde_json::json!({"type": kind, "data": {"boot": "7f3a91", "cert_roots": roots}});
            let got = match decode(&msg.to_string()).unwrap() {
                Incoming::Hello(h) => h.cert_roots,
                Incoming::Heartbeat(h) => h.cert_roots,
                Incoming::Other => panic!(),
            };
            assert_eq!(got.len(), MAX_CERT_ROOTS, "{kind}");
            assert!(got.values().all(|v| *v == fp), "{kind}");
            assert!(got.keys().all(|k| k.starts_with('l')), "{kind}");
        }

        let bad = serde_json::json!({"type": "hello", "data": {"boot": "has space"}});
        assert_eq!(decode(&bad.to_string()), Err(MessageError::BadBoot));
        let none = serde_json::json!({"type": "hello", "data": {}});
        assert_eq!(decode(&none.to_string()), Err(MessageError::BadBoot));
        assert_eq!(decode("{"), Err(MessageError::Malformed));
        assert_eq!(
            decode(&serde_json::json!({"type": "later", "data": {}}).to_string()),
            Ok(Incoming::Other)
        );
    }

    #[test]
    fn heartbeat_labels_are_safe() {
        let mut up = serde_json::Map::new();
        for i in 0..100 {
            up.insert(format!("u{i}"), serde_json::json!({"queries": 1}));
        }
        up.insert("bad\"label".into(), serde_json::json!({"queries": 1}));
        let reasons: serde_json::Map<String, serde_json::Value> = (0..40)
            .map(|i| (format!("r{i}"), serde_json::json!(1)))
            .chain([("bad reason".to_string(), serde_json::json!(1))])
            .collect();
        up.insert(
            "u0".into(),
            serde_json::json!({"queries": 1, "invalid": reasons, "scrubbed": reasons}),
        );
        let msg = serde_json::json!({"type": "heartbeat", "data": {
            "ts": "2026-11-13T10:00:00Z", "boot": "b1", "up_ms": 5,
            "metrics": {"upstream": up, "latency_us": {"buckets": vec![1u64; 80], "sum": 1, "count": 1}}
        }});
        let Incoming::Heartbeat(hb) = decode(&msg.to_string()).unwrap() else {
            panic!()
        };
        assert_eq!(hb.metrics.upstream.len(), MAX_UPSTREAMS);
        assert!(hb.metrics.upstream.keys().all(|k| is_label(k)));
        let u0 = &hb.metrics.upstream["u0"];
        for m in [&u0.invalid, &u0.scrubbed] {
            assert_eq!(m.len(), MAX_REASONS);
            assert!(m.keys().all(|k| is_label(k)));
        }
        assert_eq!(
            hb.metrics.latency_us.buckets.len(),
            picket_api::histogram::BUCKETS
        );
    }
}
