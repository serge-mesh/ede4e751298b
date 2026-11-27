//! Attribution by replay (core.md §6 steps 1–4), for each event a rule decided (a block, a
//! rewrite, or an allow by an allow bundle or exception) and each response-phase block.
//!
//! 1. The record's `versions` give each of its profile's allow and block bundles (as the
//!    profile stood in the record's published config) the heads its parts came from
//!    ([`super::replay::BundleAt`]); a version or feed run that is gone makes the attribution
//!    `unavailable` (raising `attribution_unavailable` once per edge and bundle version): never a
//!    replay against current entries, and no self-check.
//! 2. Every rule of every feed of those bundles as it stood at those runs is checked
//!    ([`super::replay`]): keys at each suffix, patterns, rich-rule conditions (`$client` against
//!    the record's client and device, `$ctag` against that device's tags, `$dnstype`), and for a
//!    response-phase block the CNAME chain, addresses and targets of the referenced answer, else
//!    its `response`, else the preview. Scope bundles and other profiles' bundles yield no matches.
//! 3. Every match is stored with its feed, original text, line, format and role: `decisive`,
//!    `also_matched` or `overridden` (by an exception or `$badfilter`). A `truncated` or
//!    `answer_missing` record's attribution is `incomplete`.
//! 4. **Self-check:** the decisive rule's step and bundle must match the logged `reason`;
//!    a mismatch raises `attribution_mismatch`.

use std::collections::{BTreeMap, BTreeSet};

use picket_api::logs::{Decision, MatchKind, Stage, Versions};
use picket_rules::matcher::{MatchResult, Outcome, OverriddenBy, Role};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::record::Rec;
use super::replay::{self, BundleAt, CandKey, ClientCtx, PublishedConfig, ReplayCaches, Unavailable, Value};
use crate::config::model::Model;

/// What a batch's replay reads: core.db (read), the caches and the configuration model.
pub struct Env<'a> {
    pub c: &'a Connection,
    pub caches: &'a ReplayCaches,
    pub model: &'a Model,
}

/// Attribution status (storage.md §3 `attribution.status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Incomplete,
    Unavailable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Complete => "complete",
            Status::Incomplete => "incomplete",
            Status::Unavailable => "unavailable",
        }
    }
}

/// One stored match (core.md §6 step 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Match {
    /// The bundle whose feed holds the rule.
    pub bundle: String,
    pub feed: String,
    /// The rule as written in the feed.
    pub text: String,
    /// Its line in the feed (as first seen).
    pub line: Option<i64>,
    /// The feed's format.
    pub format: Option<String>,
    /// `decisive`, `also_matched`, `overridden` or (trial checks) `would_block`.
    pub role: String,
    /// What cancelled an `overridden` rule: `exception`, `badfilter` or `rewrite_exception`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// `dns` or `ip`.
    pub rule_type: String,
    /// The stage of the value it matched (`query`, `cname`, `answer_ip`, `svcb`).
    pub stage: String,
    /// The value it matched (a name as log text, or an address).
    pub value: String,
    /// The `feed_entries` row.
    #[serde(default)]
    pub entry: i64,
}

/// One record's attribution (`attribution.matches_json` holds it whole).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Attribution {
    pub matches: Vec<Match>,
    /// The ladder step and bundle replay found decisive, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisive: Option<(u8, String)>,
    /// `ok`, `mismatch` or `skipped` (core.md §6 step 4).
    #[serde(default)]
    pub self_check: String,
    /// The versions or feed runs that are gone (status `unavailable`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<UnavailableView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UnavailableView {
    pub bundle: String,
    pub head: String,
    pub reason: String,
}

impl From<&Unavailable> for UnavailableView {
    fn from(u: &Unavailable) -> Self {
        Self {
            bundle: u.bundle.clone(),
            head: u.head.clone(),
            reason: u.reason.clone(),
        }
    }
}

/// A failed self-check: (logged step, logged bundle, replayed step and bundle).
pub type Mismatch = (u8, Option<String>, Option<(u8, String)>);

/// What attributing one record did, beyond its stored row.
#[derive(Clone, Debug, Default)]
pub struct Effects {
    pub status: Option<Status>,
    pub attribution: Attribution,
    /// Versions gone: raise `attribution_unavailable` once per (edge, bundle, head).
    pub unavailable: Vec<Unavailable>,
    /// The published config is gone (`attribution_unavailable` keyed on it).
    pub config_gone: Option<String>,
    /// Self-check failed: the logged step and bundle, and what replay found.
    pub mismatch: Option<Mismatch>,
    /// `feed_hits{feed, role}` (one per feed and role per record).
    pub feed_hits: BTreeSet<(String, String)>,
    /// `bundle_key_hits`: (bundle, reversed key) of a block from a key of a cold-capable bundle.
    pub key_hit: Option<(String, String)>,
}

/// True when core attributes `r` (core.md §6): a block, rewrite or allow a rule decided (allow
/// bundle at step 2, block bundles at step 3, or an exception there: an allow the edge logs with
/// `reason.step` 3 and the exception's bundle), and each response-phase block (step 5).
pub fn wanted(r: &Rec) -> bool {
    let Some(reason) = r.reason.as_ref() else {
        return false;
    };
    if reason.bundle.is_none() {
        return false;
    }
    if matches!(
        reason.kind,
        MatchKind::TempAllow | MatchKind::Lookup | MatchKind::Forward | MatchKind::Local
    ) {
        return false;
    }
    match r.decision() {
        Some(Decision::Block) => matches!(reason.step, 3 | 5),
        Some(Decision::Rewrite) => reason.step == 3,
        Some(Decision::Allow) => matches!(reason.step, 2 | 3),
        _ => false,
    }
}

/// The record type a response value is checked with (rules.md §6: `$dnstype` matches the
/// record's type).
pub fn value_qtype(stage: Stage, v: &Value, qtype: u16) -> u16 {
    match stage {
        Stage::Query => qtype,
        Stage::Cname => 5,
        Stage::AnswerIp => match v {
            Value::Ip(ip) if picket_rules::ip::canonical_ip(*ip).is_ipv4() => 1,
            _ => 28,
        },
        Stage::Svcb => {
            if qtype == 64 || qtype == 65 {
                qtype
            } else {
                65
            }
        }
    }
}

pub fn stage_str(s: Stage) -> &'static str {
    match s {
        Stage::Query => "query",
        Stage::Cname => "cname",
        Stage::AnswerIp => "answer_ip",
        Stage::Svcb => "svcb",
    }
}

fn role_str(role: Role, decisive_here: bool) -> (String, Option<String>) {
    match role {
        Role::Decisive if decisive_here => ("decisive".into(), None),
        Role::Decisive | Role::AlsoMatched => ("also_matched".into(), None),
        Role::Overridden(by) => (
            "overridden".into(),
            Some(
                match by {
                    OverriddenBy::Exception => "exception",
                    OverriddenBy::Badfilter => "badfilter",
                    OverriddenBy::RewriteException => "rewrite_exception",
                }
                .into(),
            ),
        ),
    }
}

/// Turns one bundle's result into stored matches.
#[expect(
    clippy::too_many_arguments,
    reason = "one bundle result's context for the matches it stores"
)]
pub fn matches_of(
    env: &Env<'_>,
    bundle: &str,
    rows: &[crate::compiler::source::Row],
    res: &MatchResult,
    stage: Stage,
    value: &Value,
    role: impl Fn(Role) -> (String, Option<String>),
    out: &mut Vec<Match>,
) {
    for m in &res.matches {
        let Some(row) = rows.get(m.rule) else { continue };
        let (text, line) = replay::raw_of(env.c, row.entry_id).unwrap_or_default();
        let (role, by) = role(m.role);
        out.push(Match {
            bundle: bundle.to_string(),
            feed: row.feed.clone(),
            text,
            line,
            format: env
                .model
                .feeds
                .get(&row.feed)
                .and_then(|f| serde_json::to_value(f.format).ok())
                .and_then(|v| v.as_str().map(str::to_string)),
            role,
            by,
            rule_type: row.rule.rule_type.as_str().to_string(),
            stage: stage_str(stage).to_string(),
            value: value.text(),
            entry: row.entry_id,
        });
    }
}

/// The bundle a result decides for the ladder at `step` (rules.md §5): an allow bundle that
/// allows; a block bundle that blocks or rewrites (a response check ignores rewrites).
fn decides(res: &MatchResult, step: u8) -> bool {
    match step {
        2 => matches!(res.outcome, Outcome::Allow),
        3 => matches!(
            res.outcome,
            Outcome::Block | Outcome::Rewrite(_) | Outcome::HostMapping(_)
        ),
        // A response check blocks on a hosts line's mapping too, as the edge does (AdGuard Home
        // treats hosts lines as block rules answered in its default mode, rules.md §3 hosts
        // lines); a `$dnsrewrite` there is ignored (rules.md §5).
        _ => matches!(res.outcome, Outcome::Block | Outcome::HostMapping(_)),
    }
}

/// Resolves the record's bundles in its profile's ladder order: allow bundles (step 2), then
/// block bundles (step 3), each with how the record's versions name it.
pub fn ladder(
    env: &Env<'_>,
    cfg: &PublishedConfig,
    profile: &str,
    versions: &Versions,
) -> anyhow::Result<Vec<(u8, BundleAt)>> {
    let Some(p) = cfg.profiles.get(profile) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (step, list) in [(2u8, &p.allow), (3u8, &p.block)] {
        for b in list {
            let Some(v) = versions.bundles.get(b) else {
                continue;
            };
            out.push((step, BundleAt::resolve(env.caches, env.c, env.model, b, v)?));
        }
    }
    Ok(out)
}

/// Attributes one record (see the module docs). `None` when it isn't attributed.
pub fn attribute(env: &Env<'_>, r: &Rec) -> anyhow::Result<Option<Effects>> {
    if !wanted(r) {
        return Ok(None);
    }
    let Some(reason) = r.reason.clone() else {
        return Ok(None);
    };
    let mut fx = Effects::default();
    let Some(versions) = replay::parse_versions(&r.versions_json) else {
        fx.status = Some(Status::Unavailable);
        fx.attribution.self_check = "skipped".into();
        return Ok(Some(fx));
    };
    let cfg = env.caches.config(env.c, &r.edge, &versions.config)?;
    let Some(cfg) = cfg else {
        fx.status = Some(Status::Unavailable);
        fx.config_gone = Some(versions.config.clone());
        fx.attribution.self_check = "skipped".into();
        fx.attribution.unavailable.push(UnavailableView {
            bundle: String::new(),
            head: versions.config.clone(),
            reason: "the published config is gone".into(),
        });
        return Ok(Some(fx));
    };
    let profile = r.profile.clone().unwrap_or_default();
    let bundles = ladder(env, &cfg, &profile, &versions)?;
    let gone: Vec<Unavailable> = bundles.iter().filter_map(|(_, b)| b.unavailable()).collect();
    if !gone.is_empty() {
        fx.status = Some(Status::Unavailable);
        fx.attribution.self_check = "skipped".into();
        fx.attribution.unavailable = gone.iter().map(UnavailableView::from).collect();
        fx.unavailable = gone;
        return Ok(Some(fx));
    }
    let client = ClientCtx::of(Some(&cfg), &r.client_ip, r.device.as_deref());
    let qtype = r.qtype_num();
    let response_phase = reason.step == 5;
    // The values: the query name, and for a response-phase block the answer's.
    let mut values: Vec<(Stage, Value)> = Vec::new();
    if let Some(q) = r.qname_value() {
        values.push((Stage::Query, q));
    }
    if response_phase {
        let av = r.answer_values();
        for (s, v) in av.staged() {
            if !values.iter().any(|(_, x)| x == v) {
                values.push((s, v.clone()));
            }
        }
    }
    // The deciding value of a response-phase block.
    let deciding: Option<Value> = reason.value.as_deref().and_then(|v| match v.parse() {
        Ok(ip) => Some(Value::Ip(ip)),
        Err(_) => Value::name_from_log(v),
    });
    let mut partial = false;
    // The candidate LRU's version key: the record's version set (its BLAKE3; the text itself for
    // a partition without one).
    let vkey = if r.versions_blake3.is_empty() {
        blake3::hash(r.versions_json.as_bytes()).to_hex().to_string()
    } else {
        r.versions_blake3.clone()
    };
    // Results per (bundle index, value index).
    let mut results: BTreeMap<(usize, usize), (std::sync::Arc<replay::Candidates>, MatchResult)> =
        BTreeMap::new();
    for (bi, (_, at)) in bundles.iter().enumerate() {
        for (vi, (stage, v)) in values.iter().enumerate() {
            let key = CandKey {
                versions: vkey.clone(),
                value: v.text(),
                qtype,
                profile: profile.clone(),
                bundle: at.bundle.clone(),
            };
            let cands = replay::candidates(env.c, env.caches, at, key, v)?;
            partial |= cands.partial;
            let res = client.eval(&cands, v, value_qtype(*stage, v, qtype));
            results.insert((bi, vi), (cands, res));
        }
    }
    // The ladder: the first allow bundle that allows, else the first block bundle that blocks or
    // rewrites, on the query name; for a response-phase block, the first block bundle that
    // blocks the deciding value (after the allow bundles let it through).
    let mut decisive: Option<(usize, usize, u8)> = None;
    let query_vi = values.iter().position(|(s, _)| *s == Stage::Query);
    if response_phase {
        let dvi = deciding
            .as_ref()
            .and_then(|d| values.iter().position(|(_, v)| v == d))
            .or_else(|| {
                values.iter().enumerate().position(|(vi, (s, _))| {
                    *s != Stage::Query
                        && bundles.iter().enumerate().any(|(bi, (st, _))| {
                            *st == 3 && results.get(&(bi, vi)).is_some_and(|x| decides(&x.1, 5))
                        })
                })
            });
        if let Some(vi) = dvi {
            let allowed = bundles
                .iter()
                .enumerate()
                .any(|(bi, (st, _))| *st == 2 && results.get(&(bi, vi)).is_some_and(|x| decides(&x.1, 2)));
            if !allowed {
                decisive = bundles
                    .iter()
                    .enumerate()
                    .find(|(bi, (st, _))| {
                        *st == 3 && results.get(&(*bi, vi)).is_some_and(|x| decides(&x.1, 5))
                    })
                    .map(|(bi, _)| (bi, vi, 5));
            }
        }
    } else if let Some(vi) = query_vi {
        decisive = bundles
            .iter()
            .enumerate()
            .find(|(bi, (st, _))| results.get(&(*bi, vi)).is_some_and(|x| decides(&x.1, *st)))
            .map(|(bi, (st, _))| (bi, vi, *st));
        // Nothing decided: a block bundle whose winning rule is an exception let the name through
        // (rules.md §5 step 3; core.md §6 "an allow by … an exception"): the first such bundle
        // is decisive, as the edge logs it.
        if decisive.is_none() {
            decisive = bundles
                .iter()
                .enumerate()
                .find(|(bi, (st, _))| {
                    *st == 3
                        && results
                            .get(&(*bi, vi))
                            .is_some_and(|x| matches!(x.1.outcome, Outcome::Exception))
                })
                .map(|(bi, _)| (bi, vi, 3));
        }
    }
    let mut matches = Vec::new();
    for ((bi, vi), (cands, res)) in &results {
        let (_, at) = &bundles[*bi];
        let (stage, v) = &values[*vi];
        let here = decisive.is_some_and(|(b, x, _)| b == *bi && x == *vi);
        matches_of(
            env,
            &at.bundle,
            &cands.rows,
            res,
            *stage,
            v,
            |role| role_str(role, here),
            &mut matches,
        );
    }
    // One stored match per rule, value and bundle; decisive first.
    matches.sort_by(|a, b| {
        let rank = |m: &Match| match m.role.as_str() {
            "decisive" => 0,
            "also_matched" => 1,
            _ => 2,
        };
        rank(a).cmp(&rank(b))
    });
    matches.dedup_by(|a, b| a.entry == b.entry && a.value == b.value && a.bundle == b.bundle);
    let replayed = decisive.map(|(bi, _, st)| (st, bundles[bi].1.bundle.clone()));
    // Self-check (step 4): the decisive rule's step and bundle against the logged reason. A
    // replay cut by a cap (`partial`: rules it couldn't read) may miss the decisive rule, so it
    // is `incomplete` and skips the self-check rather than raise a mismatch only a person could
    // clear (README §2 Bounded).
    let logged = (reason.step, reason.bundle.clone());
    if partial {
        fx.attribution.self_check = "skipped".into();
    } else {
        let ok = match &replayed {
            Some((st, b)) => *st == logged.0 && Some(b) == logged.1.as_ref(),
            None => false,
        };
        fx.attribution.self_check = if ok { "ok" } else { "mismatch" }.into();
        if !ok {
            fx.mismatch = Some((logged.0, logged.1.clone(), replayed.clone()));
        }
    }
    fx.attribution.decisive = replayed;
    for m in &matches {
        if m.role == "decisive" || m.role == "also_matched" {
            fx.feed_hits.insert((m.feed.clone(), m.role.clone()));
        }
    }
    // `last_hit_at` goes to the compiled key the edge matched (the logged `reason.key`), in a
    // block bundle with hot/cold tiering (core.md §6 step 3; bundles.md §2 Tiering).
    if r.decision() == Some(Decision::Block)
        && matches!(reason.kind, MatchKind::Exact | MatchKind::Subs)
        && let (Some(b), Some(k)) = (reason.bundle.as_ref(), reason.key.as_ref())
        && env.model.bundles.get(b).is_some_and(|d| d.cold_capable())
        && let Some(Value::Name(labels)) = Value::name_from_log(k)
    {
        let rev: Vec<String> = labels
            .iter()
            .rev()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect();
        fx.key_hit = Some((b.clone(), rev.join(".")));
    }
    fx.attribution.matches = matches;
    fx.status = Some(if r.incomplete() || partial {
        Status::Incomplete
    } else {
        Status::Complete
    });
    Ok(Some(fx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_api::logs::Reason;

    fn rec(decision: &str, step: u8, bundle: Option<&str>, kind: MatchKind) -> Rec {
        Rec {
            decision: decision.into(),
            reason: Some(Reason {
                step,
                bundle: bundle.map(str::to_string),
                kind,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn which_events_are_attributed() {
        assert!(wanted(&rec("block", 3, Some("b"), MatchKind::Subs)));
        assert!(wanted(&rec("block", 5, Some("b"), MatchKind::Ip)));
        assert!(wanted(&rec("rewrite", 3, Some("b"), MatchKind::Rich)));
        assert!(wanted(&rec("allow", 2, Some("a"), MatchKind::Exact)));
        assert!(!wanted(&rec("block", 4, None, MatchKind::Lookup)));
        assert!(!wanted(&rec("allow", 1, None, MatchKind::TempAllow)));
        assert!(!wanted(&rec("allow", 6, None, MatchKind::Exact)));
        assert!(!wanted(&Rec {
            decision: "allow".into(),
            ..Default::default()
        }));
    }

    #[test]
    fn response_values_take_their_record_type() {
        let v4 = Value::Ip("192.0.2.1".parse().unwrap());
        let v6 = Value::Ip("2001:db8::1".parse().unwrap());
        let mapped = Value::Ip("::ffff:192.0.2.1".parse().unwrap());
        assert_eq!(value_qtype(Stage::AnswerIp, &v4, 28), 1);
        assert_eq!(value_qtype(Stage::AnswerIp, &v6, 1), 28);
        assert_eq!(value_qtype(Stage::AnswerIp, &mapped, 28), 1);
        assert_eq!(value_qtype(Stage::Cname, &v4, 1), 5);
        assert_eq!(value_qtype(Stage::Svcb, &v4, 64), 64);
        assert_eq!(value_qtype(Stage::Svcb, &v4, 1), 65);
        assert_eq!(value_qtype(Stage::Query, &v4, 16), 16);
    }
}
