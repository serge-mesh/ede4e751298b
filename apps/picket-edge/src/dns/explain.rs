//! `picket-edge explain <name> [--type A] [--client IP] [--profile ID]` (edge.md §15): the full
//! ladder trace for a name with the bundle versions and the deciding rule, from the active state,
//! offline (no upstream or provider is called).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use serde_json::{Value, json};

use picket_rules::matcher::Outcome;
use picket_wire::QName;
use picket_wire::types::rtype;

use super::filter::Who;
use super::pipeline::is_local_zone;
use super::profiles::Choice;
use crate::admin::AdminError;
use crate::edge::Edge;

fn outcome_text(o: &Outcome) -> Value {
    match o {
        Outcome::None => json!("none"),
        Outcome::Exception => json!("exception"),
        Outcome::Block => json!("block"),
        Outcome::Allow => json!("allow"),
        Outcome::InScope => json!("in_scope"),
        Outcome::Rewrite(a) => json!({"rewrite": format!("{a:?}")}),
        Outcome::HostMapping(ips) => json!({"host_mapping": ips}),
    }
}

fn reason_json(b: &picket_bundle::Bundle, r: &picket_bundle::Reason, labels: &[&[u8]]) -> Value {
    json!({
        "kind": r.kind,
        "key": r.key_text(b, labels),
        "cold": r.cold,
        "part": r.part.key(),
        "head": picket_api::ids::short_id(&r.head),
        "level": r.level.map(|l| format!("{l:?}")),
    })
}

/// The `explain` admin command.
pub async fn explain(edge: Arc<Edge>, args: Value) -> Result<Value, AdminError> {
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 1024)
        .ok_or_else(|| AdminError::bad_args("explain needs a name"))?;
    let qn = QName::from_text(name).map_err(|e| AdminError::bad_args(format!("bad name: {e}")))?;
    let qtype = match args.get("type").and_then(Value::as_str) {
        None => rtype::A,
        Some(t) => picket_wire::types::rtype_from_text(&t.to_ascii_uppercase())
            .or_else(|| t.parse().ok())
            .ok_or_else(|| AdminError::bad_args(format!("unknown type {t:?}")))?,
    };
    let client: IpAddr = match args.get("client").and_then(Value::as_str) {
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(c) => c
            .parse()
            .map_err(|_| AdminError::bad_args(format!("bad client address {c:?}")))?,
    };
    let named = args.get("profile").and_then(Value::as_str);
    let active = edge.active();
    let Some(rt) = active.dns.clone() else {
        return Err(AdminError::new("not_ready", "no config is active yet"));
    };
    let src = client.to_canonical();
    let device = rt.device(src, edge.neighbours.mac_of(&src));
    let dkey = rt.clients.key(&device);
    let mut out = json!({
        "name": qn.as_name().log_text(),
        "type": picket_wire::types::TypeText(qtype).to_string(),
        "client": src,
        "device": {"key": dkey.text(), "name": rt.clients.log_name(&device)},
        "versions": active.versions.as_deref(),
    });
    // With no profile named, explain as a query without a DoH path or DoT name.
    let pid = match rt.choose(named, &device) {
        Choice::Profile(p) => p,
        Choice::Refused => {
            out["decision"] = json!("refused");
            out["why"] = json!("no profile admits the client (REFUSED, EDE 18)");
            return Ok(out);
        }
        Choice::NamedRefused => {
            out["decision"] = json!("refused");
            out["why"] = json!(
                "the named profile doesn't exist or doesn't admit the client (DoH 403, DoT REFUSED, EDE 18)"
            );
            return Ok(out);
        }
    };
    let Some(profile) = rt.profile(&pid).cloned() else {
        return Err(AdminError::internal("chosen profile missing"));
    };
    out["profile"] = json!(&*profile.id);
    let n = qn.as_name();
    if let Some(m) = rt.managed_answer(n) {
        out["decision"] = json!("local");
        out["why"] = json!(format!(
            "managed listener name of {} (answered with its IPs)",
            m.listener
        ));
        out["answers"] = json!(m.ips);
        return Ok(out);
    }
    if (is_local_zone(n)
        || (profile.cfg.private_reverse == picket_api::edge_config::PrivateReverse::Nxdomain
            && picket_wire::reverse::is_private_reverse(n)))
        && !profile.zones.covers(n)
    {
        out["decision"] = json!("local");
        out["why"] = json!("local or private-range reverse name: NXDOMAIN");
        return Ok(out);
    }
    if let Some(z) = profile.zones.longest_match(n) {
        out["decision"] = json!("forward");
        out["forward_zone"] = json!({"zone": &*z.id, "group": &*z.group, "fallback": z.fallback});
        return Ok(out);
    }
    let (names, tags): (Vec<&str>, Vec<&str>) = match rt.clients.naming_client(&device) {
        Some(c) => (vec![&*c.name], c.tags.iter().map(|t| &**t).collect()),
        None => (vec![], vec![]),
    };
    let who = Who {
        ip: src,
        names: &names,
        tags: &tags,
    };
    let labels: Vec<&[u8]> = qn.labels().collect();
    let ctx = picket_rules::QueryCtx {
        qtype,
        client_ip: Some(src),
        client_names: &names,
        client_tags: &tags,
    };
    let mut steps = vec![];
    let mut decided: Option<Value> = None;
    let allows = edge.dns.temp_allows(&edge);
    if let Some(h) = allows.find(&dkey, n) {
        let s = json!({"step": 1, "temporary_allow": h.allow_id});
        decided.get_or_insert_with(|| s.clone());
        steps.push(s);
    }
    for id in &profile.cfg.allow {
        let Some(b) = active.bundles.get(id) else {
            steps.push(json!({"step": 2, "bundle": id, "loaded": false}));
            continue;
        };
        let d = b.lookup_labels(&labels, &ctx);
        let s = json!({
            "step": 2, "bundle": id, "head": picket_api::ids::short_id(b.head()),
            "outcome": outcome_text(&d.outcome),
            "reason": d.reason.as_ref().map(|r| reason_json(b, r, &labels)),
        });
        if d.outcome == Outcome::Allow {
            decided.get_or_insert_with(|| s.clone());
        }
        steps.push(s);
    }
    for id in &profile.cfg.block {
        let Some(b) = active.bundles.get(id) else {
            steps.push(json!({"step": 3, "bundle": id, "loaded": false}));
            continue;
        };
        let mut d = b.lookup_labels(&labels, &ctx);
        let mut cold = json!(null);
        if d.cold == picket_bundle::ColdCheck::Needed {
            match active.bundles.pages.clone() {
                Some(r) => {
                    let b2 = Arc::clone(b);
                    let q2 = qn.clone();
                    if let Ok(c) = tokio::task::spawn_blocking(move || b2.lookup_cold(&q2, &*r)).await {
                        d = d.with_cold(c);
                    }
                }
                None => cold = json!("unchecked (cold part not readable)"),
            }
        }
        let s = json!({
            "step": 3, "bundle": id, "head": picket_api::ids::short_id(b.head()),
            "outcome": outcome_text(&d.outcome),
            "reason": d.reason.as_ref().map(|r| reason_json(b, r, &labels)),
            "cold": if cold.is_null() { json!(format!("{:?}", d.cold)) } else { cold },
        });
        if matches!(
            d.outcome,
            Outcome::Block | Outcome::Rewrite(_) | Outcome::HostMapping(_)
        ) {
            decided.get_or_insert_with(|| s.clone());
        }
        steps.push(s);
    }
    out["ladder"] = json!(steps);
    // Step 4: which sync lookups the name is in scope for (no call is made).
    let mut looks = vec![];
    let allowed = decided.as_ref().is_some_and(|d| d["step"] == 1 || d["step"] == 2);
    for att in &profile.sync {
        let Some(c) = edge.dns.lookups.get(&att.provider) else {
            looks.push(json!({"provider": &*att.provider, "configured": false}));
            continue;
        };
        let s = c.settings();
        let excluded = s
            .scope
            .exclude_bundles
            .iter()
            .chain(att.exclude.iter())
            .find(|b| super::filter::in_bundle(&active.bundles, b, &qn, &who, qtype));
        let included = [&s.scope.include_bundles, &att.include].iter().all(|l| {
            l.is_empty()
                || l.iter()
                    .any(|b| super::filter::in_bundle(&active.bundles, b, &qn, &who, qtype))
        });
        let qt = picket_wire::types::TypeText(qtype).to_string();
        looks.push(json!({
            "provider": &*att.provider,
            "in_scope": !allowed && excluded.is_none() && included,
            "excluded_by": excluded,
            "calls_for_type": s.scope.qtypes.iter().any(|t| t.eq_ignore_ascii_case(&qt)),
            "fail_mode": s.fail_mode,
        }));
    }
    out["lookups"] = json!(looks);
    out["decision"] = match &decided {
        Some(d) if d["step"] == 1 || d["step"] == 2 => json!("allow"),
        Some(d) => match &d["outcome"] {
            Value::String(s) if s == "block" => json!("block"),
            _ => json!("rewrite"),
        },
        None => json!("resolve"),
    };
    out["decided_by"] = decided.unwrap_or(Value::Null);
    out["upstream_group"] = json!(&*profile.group);
    Ok(out)
}
