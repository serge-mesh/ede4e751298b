//! Compile-time guardrails and alerts (bundles.md §2 "Guardrails", "Broad blocks", "Broad
//! allows"; core.md §9). Nothing is held: each finding raises an alert when new.
//!
//! - **`broad_block`** (critical, once per rule naming its feed, rule and line): a block of a whole
//!   TLD, a pattern matching most of the probe set, or an IP range of a public /8 or IPv6 /16 or
//!   more ([`picket_rules::compile::is_broad`]). **`broad_allow`** the same for an exception in a
//!   block bundle, or any rule of an allow bundle, from a downloaded feed. Both resolve when the
//!   rule leaves the bundle.
//! - **`bundle_warning`**, each when new: a block of a public suffix below the top level
//!   (private-section wildcards excluded); each cross-feed `@@` / `$badfilter` canceller, with
//!   what it was found to cancel, or "may cancel" when the bounded scan couldn't prove it
//!   ([`picket_rules::badfilter::cross_feed_cancellations_within`]); more than 10k patterns or
//!   host-IP mappings; patterns past the reference's budget or too large to build; rules whose
//!   `$denyallow` entities didn't fit the cap; a shard that can't split. Per-rule warnings resolve
//!   when the rule leaves the bundle, aggregate ones when their condition clears.
//!
//! Checks run on the entries a build reads as changed (all of them in a fresh or full build), with
//! cheap filters first so a 10M-entry feed costs little: a key is a public-suffix candidate only
//! when its name is listed in the PSL (or under one of its wildcards).

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use anyhow::Result;
use picket_rules::badfilter::{CancelKind, ScanLimits, cross_feed_cancellations_within};
use picket_rules::compile::{blocks_public_suffix_below_tld, is_broad};
use picket_rules::name::reverse_dotted;
use picket_rules::{Flags, Kind, Rule, RuleType};
use serde_json::{Value, json};

use super::build::Ctx;
use super::source::{OrderKey, Row, View};
use super::spec::Member;
use crate::alerts::{Changes, RaiseSpec, Severity};
use crate::config::model::BundleAction;
use crate::state::SharedState;

/// Findings kept per build (README §2 Bounded); past it they are counted.
pub const MAX_FINDINGS: usize = 1000;
/// Cancellers the cross-feed scan takes; past it the scan is skipped and a warning says so.
pub const MAX_CANCELLERS: usize = 20_000;
/// Rules the cross-feed scan reads besides the cancellers.
pub const MAX_RELATED: usize = 200_000;
/// Descendants read per keyed canceller with a subdomain flag.
pub const BELOW_PER_CANCELLER: usize = 1000;
/// Changed keys whose rules the scan checks against exception patterns.
pub const CHANGED_SAMPLE: usize = 2000;
/// The scan's work cap for the whole bundle (a fraction of picket-rules' default).
pub const SCAN_WORK: u64 = 500_000_000;
/// The scan's work in one heavy step (core.md §3: bounded steps; about a second of CPU).
pub const SCAN_WORK_PER_STEP: u64 = 50_000_000;
/// Cancellers one step scans.
pub const CANCELLERS_PER_STEP: usize = 1000;
/// Patterns or host-IP mappings past which a bundle warns (bundles.md §2).
pub const MANY: usize = 10_000;

/// A rule's identity (`feed_entries`), carried in per-rule alerts so the stale pass can tell
/// whether it left the bundle.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub feed: String,
    pub rule_type: String,
    pub kind: String,
    pub key: String,
    pub flags: u16,
    pub value_json: String,
}

impl Identity {
    fn of(feed: &str, rule_type: &str, kind: &str, key: &str, flags: u16, value_json: &str) -> Identity {
        Identity {
            feed: feed.into(),
            rule_type: rule_type.into(),
            kind: kind.into(),
            key: key.into(),
            flags,
            value_json: value_json.into(),
        }
    }

    fn from_row(r: &Row) -> Identity {
        Identity::of(
            &r.feed,
            r.order.rule_type,
            r.order.kind,
            &r.order.key,
            r.order.flags,
            &r.order.value_json,
        )
    }

    /// A short stable id for dedupe keys.
    pub fn short(&self) -> String {
        let s = serde_json::to_string(self).unwrap_or_default();
        picket_api::ids::object_id(s.as_bytes())[..16].to_string()
    }
}

/// One per-rule finding: raised at commit unless already open.
#[derive(Clone, Debug)]
pub struct Finding {
    pub kind: &'static str,
    pub severity: Severity,
    pub dedupe_key: String,
    pub title: String,
    pub identity: Identity,
    pub detail: Value,
}

/// What a build found; applied in its commit.
#[derive(Clone, Debug, Default)]
pub struct Findings {
    pub items: Vec<Finding>,
    pub dropped: u64,
    /// Aggregate conditions: dedupe key → the alert to raise (`None`: resolve).
    pub conditions: BTreeMap<String, Option<RaiseSpec>>,
}

impl Findings {
    fn push(&mut self, f: Finding) {
        if self.items.len() >= MAX_FINDINGS {
            self.dropped += 1;
        } else if !self.items.iter().any(|x| x.dedupe_key == f.dedupe_key) {
            self.items.push(f);
        }
    }

    /// Sets an aggregate condition for `bundle`: raised when `spec` is `Some`, resolved when not.
    pub fn condition(&mut self, key: String, spec: Option<RaiseSpec>) {
        self.conditions.insert(key, spec);
    }
}

/// Names the PSL lists explicitly, and the parents of its wildcard rules.
fn psl_candidates() -> &'static (HashSet<String>, HashSet<String>) {
    static SETS: OnceLock<(HashSet<String>, HashSet<String>)> = OnceLock::new();
    SETS.get_or_init(|| {
        let mut names = HashSet::new();
        let mut wild = HashSet::new();
        for r in crate::psl::rules_list().rules() {
            if let Some(p) = r.rule.strip_prefix("*.") {
                wild.insert(p.to_string());
            } else if !r.rule.starts_with('!') {
                names.insert(r.rule.clone());
            }
        }
        (names, wild)
    })
}

fn is_public_suffix_candidate(dotted: &str) -> bool {
    let (names, wild) = psl_candidates();
    names.contains(dotted) || dotted.split_once('.').is_some_and(|(_, p)| wild.contains(p))
}

/// Checks one entry a build reads as added (bundles.md §2 guardrails).
pub fn check_entry(
    ctx: &mut Ctx,
    m: &Member,
    rt: RuleType,
    kind: &str,
    key: &str,
    flags: u16,
    value_json: &str,
) {
    let action = ctx.spec.action;
    if !matches!(action, BundleAction::Block | BundleAction::Allow) {
        return;
    }
    let f = Flags(flags);
    let is_allow = action == BundleAction::Allow || f.intersects(Flags::ALL_ALLOW);
    if is_allow && !m.downloaded {
        return;
    }
    let k = Kind::parse(kind);
    // Cheap filters before building the rule.
    let worth = match k {
        Some(Kind::Name) => {
            let tld = !key.contains('.') && f.intersects(Flags::ALL_SUBS);
            let psl = !is_allow
                && f.intersects(Flags::ALL_BLOCK)
                && key.contains('.')
                && is_public_suffix_candidate(&reverse_dotted(key));
            tld || psl
        }
        Some(Kind::Pattern | Kind::Regex | Kind::IpLiteral | Kind::IpRange) => true,
        _ => false,
    };
    if !worth {
        return;
    }
    let Ok(rule) = Rule::from_stored(rt.as_str(), kind, key, flags, value_json) else {
        return;
    };
    let ident = Identity::of(&m.feed, rt.as_str(), kind, key, flags, value_json);
    let bundle = ctx.spec.id.clone();
    if is_broad(&rule) {
        let (kind, title) = if is_allow {
            (
                "broad_allow",
                format!("A broad allow in bundle {bundle} from feed {}", m.feed),
            )
        } else {
            (
                "broad_block",
                format!("A broad block in bundle {bundle} from feed {}", m.feed),
            )
        };
        ctx.findings.push(Finding {
            kind,
            severity: Severity::Critical,
            dedupe_key: format!("{kind}:{bundle}:{}", ident.short()),
            title,
            identity: ident.clone(),
            detail: json!({}),
        });
    }
    if !is_allow
        && blocks_public_suffix_below_tld(&rule, |n| crate::psl::rules_list().is_public_suffix(n.as_str()))
    {
        ctx.findings.push(Finding {
            kind: "bundle_warning",
            severity: Severity::Warning,
            dedupe_key: format!("bundle_warning:{bundle}:psl:{}", ident.short()),
            title: format!("Bundle {bundle} blocks a public suffix (feed {})", m.feed),
            identity: ident,
            detail: json!({"warning": "public_suffix"}),
        });
    }
}

/// The cross-feed scan of a build in progress: the bundle's cancellers (exceptions and
/// `$badfilter` rules), scanned a chunk per step (core.md §3), and the work left of the scan's
/// total budget.
pub struct CancelScan {
    cancellers: Vec<Row>,
    next: usize,
    work_left: u64,
}

/// One step of the cross-feed guardrail (bundles.md §2): each `@@` / `$badfilter` rule that
/// cancels rules of another feed of the bundle raises one `bundle_warning`. The first step reads
/// the cancellers; each later step scans [`CANCELLERS_PER_STEP`] of them against the rules they
/// can cancel (their keys, the keys above and, with a subdomain flag, below them, every pattern,
/// the IP rules when one is an IP rule, and a sample of the changed keys) within
/// [`SCAN_WORK_PER_STEP`], out of [`SCAN_WORK`] for the whole scan. A keyed or `$badfilter`
/// canceller finds what it finds in one pass; an exception pattern meets the keys its chunk reads
/// and the changed-key sample. Past the budget, the rest are reported as "may cancel", as the
/// scan does. `Ok(true)` when done.
pub async fn cancellations_step(state: &SharedState, ctx: &mut Ctx) -> Result<bool> {
    let bundle = ctx.spec.id.clone();
    let skip_key = format!("bundle_warning:{bundle}:cancel_scan");
    let Some(mut scan) = ctx.cancel.take() else {
        // The first step: what to scan.
        if ctx.spec.members.len() < 2 || !ctx.spec.compiles() {
            ctx.findings.condition(skip_key, None);
            return Ok(true);
        }
        // Nothing a cancellation depends on changed: the warnings stand as they are.
        if ctx.mode == super::build::Mode::Incremental
            && ctx.stats.changed_keys == 0
            && !ctx.touched.pattern
            && !ctx.touched.ip
        {
            return Ok(true);
        }
        let (spec, runs) = (ctx.spec.clone(), ctx.runs.clone());
        let read = state
            .db
            .read(move |c| {
                let view = View::new(&spec, &runs);
                let mut bad = 0u64;
                Ok::<_, anyhow::Error>(view.cancellers(c, MAX_CANCELLERS, &mut bad)?)
            })
            .await?;
        match read {
            Err(n) => {
                ctx.findings.condition(
                    skip_key.clone(),
                    Some(
                        RaiseSpec::new(
                            "bundle_warning",
                            Severity::Warning,
                            skip_key,
                            format!(
                                "Bundle {bundle}: cross-feed cancellations not checked (more than {n} exceptions)"
                            ),
                            json!({"bundle": bundle, "warning": "cancel_scan_skipped", "limit": n}),
                        )
                        .bundle(bundle.clone()),
                    ),
                );
                return Ok(true);
            }
            Ok(cancellers) => {
                ctx.findings.condition(skip_key, None);
                if cancellers.is_empty() {
                    return Ok(true);
                }
                ctx.cancel = Some(CancelScan {
                    cancellers,
                    next: 0,
                    work_left: SCAN_WORK,
                });
                return Ok(false);
            }
        }
    };
    let end = (scan.next + CANCELLERS_PER_STEP).min(scan.cancellers.len());
    let chunk: Vec<Row> = scan.cancellers[scan.next..end].to_vec();
    scan.next = end;
    let found = if scan.work_left == 0 {
        // The scan's budget is spent: the rest are reported unproven, as the scan does.
        chunk
            .iter()
            .map(|r| {
                let kind = if r.rule.is_badfilter() {
                    CancelKind::Badfilter
                } else if r.rule.is_rewrite() {
                    CancelKind::RewriteException
                } else {
                    CancelKind::Exception
                };
                (Identity::from_row(r), kind, 0, false, None, Vec::new())
            })
            .collect()
    } else {
        let (spec, runs, b2) = (ctx.spec.clone(), ctx.runs.clone(), bundle.clone());
        let work = scan.work_left.min(SCAN_WORK_PER_STEP);
        let (found, spent) = state
            .db
            .read(move |c| scan_chunk(c, &spec, &runs, &b2, chunk, work))
            .await?;
        scan.work_left = scan.work_left.saturating_sub(spent);
        found
    };
    for (ident, kind, count, proven, raw, sample) in found {
        let (rule, line) = raw.unwrap_or_default();
        let how = match kind {
            CancelKind::Badfilter => "$badfilter",
            CancelKind::Exception => "exception",
            CancelKind::RewriteException => "@@…$dnsrewrite",
        };
        let title = if proven {
            format!(
                "An {how} in feed {} cancels {count} rule(s) of other feeds in bundle {bundle}",
                ident.feed
            )
        } else {
            format!(
                "An {how} in feed {} may cancel rules of other feeds in bundle {bundle} (not proven within the scan's limits)",
                ident.feed
            )
        };
        ctx.findings.push(Finding {
            kind: "bundle_warning",
            severity: Severity::Warning,
            dedupe_key: format!("bundle_warning:{bundle}:cancel:{}", ident.short()),
            title,
            identity: ident,
            detail: json!({
                "warning": "cross_feed_cancellation",
                "rule": rule, "line": line, "proven": proven, "cancelled": count, "sample": sample,
            }),
        });
    }
    let done = scan.next >= scan.cancellers.len();
    if !done {
        ctx.cancel = Some(scan);
    }
    Ok(done)
}

/// What the scan found for one canceller: its identity, kind, count, whether proven, its raw
/// text and line, and a sample of what it cancels.
type Found = (
    Identity,
    CancelKind,
    u64,
    bool,
    Option<(String, Option<i64>)>,
    Vec<String>,
);

/// Scans one chunk of cancellers against the rules they can cancel, within `work`. Returns what
/// it found for the chunk's cancellers and the work spent.
fn scan_chunk(
    c: &rusqlite::Connection,
    spec: &super::spec::Spec,
    runs: &super::spec::Runs,
    bundle: &str,
    cancellers: Vec<Row>,
    work: u64,
) -> Result<(Vec<Found>, u64)> {
    let view = View::new(spec, runs);
    let mut bad = 0u64;
    let mut rows: BTreeMap<OrderKey, Row> = BTreeMap::new();
    let add = |rows: &mut BTreeMap<OrderKey, Row>, v: Vec<Row>| {
        for r in v {
            if rows.len() >= MAX_RELATED {
                break;
            }
            rows.entry(r.order.clone()).or_insert(r);
        }
    };
    let mut any_ip = false;
    for r in &cancellers {
        if let Some(k) = super::source::domain_key(&r.rule) {
            add(&mut rows, view.key_rules(c, &k, &mut bad)?);
            let mut s: &str = &k;
            while let Some(i) = s.rfind('.') {
                s = &s[..i];
                add(&mut rows, view.key_rules(c, s, &mut bad)?);
            }
            if r.rule.flags.intersects(Flags::ALL_SUBS) {
                add(&mut rows, view.below(c, &k, BELOW_PER_CANCELLER, &mut bad)?);
            }
        }
        any_ip |= matches!(r.rule.key_kind(), Kind::IpLiteral | Kind::IpRange);
    }
    if let Ok(p) = view.patterns(c, super::build::MAX_PATTERN_RULES, &mut bad)? {
        add(&mut rows, p);
    }
    if any_ip && let Ok(ips) = view.ip_rules(c, MAX_RELATED, &mut bad)? {
        add(&mut rows, ips);
    }
    // Changed keys, so new blocks meet the exception patterns.
    let changed: Vec<String> = {
        let mut st = c.prepare("SELECT key FROM bundle_build_keys WHERE bundle_id = ?1 LIMIT ?2")?;
        st.query_map(rusqlite::params![bundle, CHANGED_SAMPLE], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    for k in changed {
        add(&mut rows, view.key_rules(c, &k, &mut bad)?);
    }
    let mine: std::collections::BTreeSet<OrderKey> = cancellers.iter().map(|r| r.order.clone()).collect();
    for r in cancellers {
        rows.insert(r.order.clone(), r);
    }
    let rows: Vec<Row> = rows.into_values().collect();
    let rules: Vec<Rule> = rows.iter().map(|r| r.rule.clone()).collect();
    let feeds: Vec<&str> = rows.iter().map(|r| r.feed.as_str()).collect();
    let report = cross_feed_cancellations_within(
        &rules,
        &feeds,
        ScanLimits {
            work,
            ..ScanLimits::default()
        },
    );
    let mut found = Vec::new();
    for rep in &report.cancellers {
        let Some(row) = rows.get(rep.canceller) else {
            continue;
        };
        // Other exceptions among the related rules are their own chunk's.
        if !mine.contains(&row.order) {
            continue;
        }
        let sample: Vec<String> = rep
            .sample
            .iter()
            .filter_map(|i| rows.get(*i))
            .map(|r| {
                format!(
                    "{} ({})",
                    super::source::raw_of(c, r.entry_id)
                        .map(|x| x.0)
                        .unwrap_or_default(),
                    r.feed
                )
            })
            .collect();
        let raw = super::source::raw_of(c, row.entry_id).ok();
        found.push((
            Identity::from_row(row),
            rep.kind,
            rep.count,
            rep.proven,
            raw,
            sample,
        ));
    }
    Ok((found, report.work))
}

/// Applies a build's findings in its commit transaction: new per-rule findings and aggregate
/// conditions raise (when not open), cleared conditions resolve, and per-rule alerts of the bundle
/// whose rule left it resolve.
pub fn apply(
    tx: &rusqlite::Transaction<'_>,
    alerts: &crate::alerts::Alerts,
    bundle: &str,
    members: &[String],
    findings: &Findings,
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    for f in &findings.items {
        if crate::alerts::Alerts::is_open_in(tx, &f.dedupe_key)? {
            continue;
        }
        let (raw, line): (String, Option<i64>) = tx
            .query_row(
                "SELECT raw, line_no FROM feed_entries WHERE feed_id = ?1 AND rule_type = ?2 AND key = ?3 AND kind = ?4
                   AND flags = ?5 AND value_json = ?6 AND removed_run IS NULL LIMIT 1",
                rusqlite::params![
                    f.identity.feed,
                    f.identity.rule_type,
                    f.identity.key,
                    f.identity.kind,
                    f.identity.flags as i64,
                    f.identity.value_json
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or_default();
        let mut detail = json!({
            "bundle": bundle, "feed": f.identity.feed, "rule": raw, "line": line, "identity": f.identity,
        });
        if let (Some(d), Some(extra)) = (detail.as_object_mut(), f.detail.as_object()) {
            for (k, v) in extra {
                if !(k == "rule" && v.as_str().is_some_and(str::is_empty)) {
                    d.insert(k.clone(), v.clone());
                }
            }
        }
        let spec = RaiseSpec::new(f.kind, f.severity, f.dedupe_key.clone(), f.title.clone(), detail)
            .bundle(bundle.to_string())
            .feed(f.identity.feed.clone());
        alerts.raise_in(tx, &spec, ch)?;
    }
    for (key, spec) in &findings.conditions {
        match spec {
            Some(s) => {
                if !crate::alerts::Alerts::is_open_in(tx, key)? {
                    alerts.raise_in(tx, s, ch)?;
                }
            }
            None => {
                alerts.resolve_in(tx, key, Some(&json!({"cleared": crate::util::now_ts()})), ch)?;
            }
        }
    }
    // Per-rule alerts whose rule left the bundle.
    let open: Vec<(String, String)> = {
        let mut st = tx.prepare(
            "SELECT dedupe_key, details_json FROM alerts WHERE bundle_id = ?1 AND state = 'open'
               AND kind IN ('broad_block', 'broad_allow', 'bundle_warning')",
        )?;
        st.query_map([bundle], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (key, details) in open {
        let Ok(d) = serde_json::from_str::<Value>(&details) else {
            continue;
        };
        let Some(ident) = d
            .get("identity")
            .and_then(|i| serde_json::from_value::<Identity>(i.clone()).ok())
        else {
            continue;
        };
        let present = members.contains(&ident.feed)
            && tx
                .query_row(
                    "SELECT 1 FROM feed_entries WHERE feed_id = ?1 AND rule_type = ?2 AND key = ?3 AND kind = ?4
                       AND flags = ?5 AND value_json = ?6 AND removed_run IS NULL LIMIT 1",
                    rusqlite::params![
                        ident.feed,
                        ident.rule_type,
                        ident.key,
                        ident.kind,
                        ident.flags as i64,
                        ident.value_json
                    ],
                    |_| Ok(()),
                )
                .is_ok();
        if !present {
            alerts.resolve_in(tx, &key, Some(&json!({"rule_left_bundle": true})), ch)?;
        }
    }
    Ok(())
}

/// An aggregate `bundle_warning` condition for `bundle` (raised with `detail` when `on`).
pub fn aggregate(
    bundle: &str,
    what: &str,
    on: bool,
    title: String,
    detail: Value,
) -> (String, Option<RaiseSpec>) {
    let key = format!("bundle_warning:{bundle}:{what}");
    let spec = on.then(|| {
        RaiseSpec::new("bundle_warning", Severity::Warning, key.clone(), title, {
            let mut d = detail;
            if let Some(o) = d.as_object_mut() {
                o.insert("bundle".into(), json!(bundle));
                o.insert("warning".into(), json!(what));
            }
            d
        })
        .bundle(bundle.to_string())
    });
    (key, spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psl_candidates_include_listed_names_and_wildcard_children() {
        assert!(is_public_suffix_candidate("co.uk"));
        assert!(is_public_suffix_candidate("github.io"));
        assert!(!is_public_suffix_candidate("example.com"));
        let a = Identity::of("f", "dns", "name", "org.example", 3, "{}");
        assert_eq!(a.short(), a.clone().short());
        assert_eq!(a.short().len(), 16);
    }
}
