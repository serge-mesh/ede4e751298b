//! Compile-time guardrails and alerts (bundles.md §2 "Guardrails", "Broad blocks", "Broad
//! allows"; core.md §9). Nothing is held: each finding raises an alert when new.
//!
//! - **`broad_block`** (once per rule naming its feed, rule and line): a block of a whole TLD, a
//!   pattern matching most of the probe set, or an IP range of a public /8 or IPv6 /16 or more
//!   ([`picket_rules::compile::is_broad`]). Critical, except a manual feed's block restricted to a
//!   selected audience ([`picket_rules::compile::has_scoped_audience`]: a positive `$client` or
//!   `$ctag` alternative and no `$client` range wider than 16 addresses), a warning: a deliberate
//!   parental or device rule stays visible without taking the critical tier
//!   ([`broad_block_severity`]). Exclusion-only selectors, broad source ranges, `$dnstype` or
//!   `$denyallow` alone, and every downloaded feed's broad block (even under `client_rules: keep`)
//!   stay critical. **`broad_allow`** (critical) the same breadth for an exception in a block
//!   bundle, or any rule of an allow bundle, from a downloaded feed. Both resolve when the rule
//!   leaves the bundle. An open finding whose severity the policy now puts elsewhere (an older
//!   release's, or a re-evaluation) is reclassified in place at the next commit: one alert, its
//!   count and history kept, the change noted in its history.
//! - **`bundle_warning`** for public suffixes (#49): one per (bundle, feed) whose rules block a
//!   public suffix below the top level (private-section wildcards excluded), keyed
//!   `bundle_warning:{bundle}:public_suffix:{feed}` whatever the suffixes are. The affected rules
//!   are kept in `bundle_psl_hits` (added as builds read them, removed when their rule leaves the
//!   bundle), and the alert shows the distinct suffix count, the rule count and the first
//!   [`PSL_PREVIEW`] suffixes; `GET bundles/{id}/public-suffixes` lists them all. It is raised
//!   with the first affected suffix, its summary follows the set while open, and it resolves when
//!   the set empties (the feed leaving the bundle, or the bundle's deletion, included). Once
//!   resolved by hand it stays resolved while the set is unchanged or shrinks, and reopens when a
//!   suffix the alert hasn't shown enters (one that left and came back included), recording which.
//! - **`bundle_warning`**, each when new: each cross-feed `@@` / `$badfilter` canceller, with
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
use picket_rules::compile::{blocks_public_suffix_below_tld, has_scoped_audience, is_broad};
use picket_rules::name::reverse_dotted;
use picket_rules::{Flags, Kind, Rule, RuleType};
use rusqlite::OptionalExtension;
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

/// A rule blocking a public suffix below the top level (#49): kept in `bundle_psl_hits` at
/// commit, behind its (bundle, feed) pair's grouped warning.
#[derive(Clone, Debug)]
pub struct PslHit {
    pub suffix: String,
    pub identity: Identity,
}

/// Suffixes a grouped public-suffix warning previews (the full list: the API).
pub const PSL_PREVIEW: usize = 10;

/// The grouped public-suffix warning of `feed` in `bundle` (#49).
pub fn psl_key(bundle: &str, feed: &str) -> String {
    format!("bundle_warning:{bundle}:public_suffix:{feed}")
}

/// What a build found; applied in its commit.
#[derive(Clone, Debug, Default)]
pub struct Findings {
    pub items: Vec<Finding>,
    pub dropped: u64,
    /// Public-suffix blocks the build read, uncapped (each is one stored row, so the grouped
    /// warnings' counts stay exact).
    pub psl: Vec<PslHit>,
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
        let (kind, severity) = if is_allow {
            ("broad_allow", Severity::Critical)
        } else {
            ("broad_block", broad_block_severity(&rule, m.downloaded))
        };
        let (title, detail) = broad_text(kind, severity, &bundle, &m.feed);
        ctx.findings.push(Finding {
            kind,
            severity,
            dedupe_key: format!("{kind}:{bundle}:{}", ident.short()),
            title,
            identity: ident.clone(),
            detail,
        });
    }
    if !is_allow
        && blocks_public_suffix_below_tld(&rule, |n| crate::psl::rules_list().is_public_suffix(n.as_str()))
        && let Some(name) = rule.name()
    {
        ctx.findings.psl.push(PslHit {
            suffix: name.as_str().to_string(),
            identity: ident,
        });
    }
}

/// A broad block's severity (#67): a warning for a manual feed's rule restricted to a selected
/// audience ([`has_scoped_audience`]), critical otherwise (an unscoped rule, exclusion-only
/// selectors, a broad source range, and every downloaded feed's rule, whatever its feed policy
/// keeps). Breadth itself is [`is_broad`]'s, shared with `broad_allow`.
pub fn broad_block_severity(rule: &Rule, downloaded: bool) -> Severity {
    if !downloaded && has_scoped_audience(rule) {
        Severity::Warning
    } else {
        Severity::Critical
    }
}

/// A broad finding's title and extra detail: a scoped warning says the breadth concerns the
/// audience its `$client` / `$ctag` conditions select.
fn broad_text(kind: &str, severity: Severity, bundle: &str, feed: &str) -> (String, Value) {
    match (kind, severity) {
        ("broad_allow", _) => (
            format!("A broad allow in bundle {bundle} from feed {feed}"),
            json!({}),
        ),
        (_, Severity::Critical) => (
            format!("A broad block in bundle {bundle} from feed {feed}"),
            // `note: null` drops a scoped warning's note on a reclassification.
            json!({"scope": "everyone", "note": null}),
        ),
        _ => (
            format!("A broad block for a selected audience in bundle {bundle} from feed {feed}"),
            json!({
                "scope": "selected_audience",
                "note": "The rule blocks broadly for the clients its $client / $ctag conditions select; a name or tag can stand for many devices.",
            }),
        ),
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
    members: &[Member],
    findings: &Findings,
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    for f in &findings.items {
        if let Some(open) = open_severity(tx, &f.dedupe_key)? {
            // Already open: no new occurrence; only a broad block's severity the policy now puts
            // elsewhere changes, in place (its finding's detail carries the scope wording).
            if f.kind == "broad_block" && open != f.severity {
                alerts.reclassify_in(tx, &f.dedupe_key, f.severity, &f.title, &f.detail, ch)?;
            }
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
                if !(v.is_null() || k == "rule" && v.as_str().is_some_and(str::is_empty)) {
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
    let feeds: Vec<String> = members.iter().map(|m| m.feed.clone()).collect();
    apply_public_suffix(tx, alerts, bundle, &feeds, &findings.psl, ch)?;
    // Per-rule alerts whose rule left the bundle; open broad blocks of rules still in it take
    // the severity the policy gives them now (an older release's critical scoped block).
    let open: Vec<(String, String, String, String)> = {
        let mut st = tx.prepare(
            "SELECT dedupe_key, details_json, kind, severity FROM alerts WHERE bundle_id = ?1 AND state = 'open'
               AND kind IN ('broad_block', 'broad_allow', 'bundle_warning')",
        )?;
        st.query_map([bundle], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (key, details, kind, severity) in open {
        let Ok(d) = serde_json::from_str::<Value>(&details) else {
            continue;
        };
        let Some(ident) = d
            .get("identity")
            .and_then(|i| serde_json::from_value::<Identity>(i.clone()).ok())
        else {
            continue;
        };
        let member = members.iter().find(|m| m.feed == ident.feed);
        let present = member.is_some() && entry_present(tx, &ident);
        if !present {
            alerts.resolve_in(tx, &key, Some(&json!({"rule_left_bundle": true})), ch)?;
            continue;
        }
        if kind != "broad_block" || findings.items.iter().any(|f| f.dedupe_key == key) {
            continue;
        }
        let (Some(m), Ok(rule)) = (
            member,
            Rule::from_stored(
                &ident.rule_type,
                &ident.kind,
                &ident.key,
                ident.flags,
                &ident.value_json,
            ),
        ) else {
            continue;
        };
        let want = broad_block_severity(&rule, m.downloaded);
        if serde_json::from_value::<Severity>(Value::String(severity)).ok() != Some(want) {
            let (title, detail) = broad_text("broad_block", want, bundle, &ident.feed);
            alerts.reclassify_in(tx, &key, want, &title, &detail, ch)?;
        }
    }
    Ok(())
}

/// True when the feed still lists the rule (its current entries).
fn entry_present(tx: &rusqlite::Transaction<'_>, ident: &Identity) -> bool {
    tx.query_row(
        "SELECT 1 FROM feed_entries WHERE feed_id = ?1 AND rule_type = ?2 AND key = ?3 AND kind = ?4
           AND flags = ?5 AND value_json = ?6 AND removed_run IS NULL LIMIT 1",
        rusqlite::params![
            ident.feed,
            ident.rule_type,
            ident.key,
            ident.kind,
            i64::from(ident.flags),
            ident.value_json
        ],
        |_| Ok(()),
    )
    .is_ok()
}

/// `bundle_id`'s open alerts whose dedupe key starts with `prefix`: (dedupe key, feed).
fn open_with_prefix(
    tx: &rusqlite::Transaction<'_>,
    bundle: &str,
    prefix: &str,
) -> rusqlite::Result<Vec<(String, Option<String>)>> {
    let n = i64::try_from(prefix.chars().count()).unwrap_or(i64::MAX);
    let mut st = tx.prepare(
        "SELECT dedupe_key, feed_id FROM alerts WHERE bundle_id = ?1 AND kind = 'bundle_warning'
           AND state = 'open' AND substr(dedupe_key, 1, ?3) = ?2",
    )?;
    st.query_map(rusqlite::params![bundle, prefix, n], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })?
    .collect()
}

/// The public-suffix step of a build's commit (#49): the rules it read go into
/// `bundle_psl_hits`, rows whose rule left the bundle go, the per-rule public-suffix alerts of
/// earlier releases are superseded (resolved, their history kept), and each (bundle, feed) pair's
/// grouped warning is brought in line with its current set ([`psl_summarise`]).
fn apply_public_suffix(
    tx: &rusqlite::Transaction<'_>,
    alerts: &crate::alerts::Alerts,
    bundle: &str,
    members: &[String],
    hits: &[PslHit],
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    for h in hits {
        tx.execute(
            "INSERT OR IGNORE INTO bundle_psl_hits(bundle_id, feed_id, rule_hash, suffix, identity_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                bundle,
                h.identity.feed,
                h.identity.short(),
                h.suffix,
                serde_json::to_string(&h.identity).unwrap_or_default()
            ],
        )?;
    }
    let rows: Vec<(String, String, String)> = {
        let mut st =
            tx.prepare("SELECT feed_id, rule_hash, identity_json FROM bundle_psl_hits WHERE bundle_id = ?1")?;
        st.query_map([bundle], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut feeds: HashSet<String> = HashSet::new();
    for (feed, hash, ij) in rows {
        let present = members.contains(&feed)
            && serde_json::from_str::<Identity>(&ij).is_ok_and(|i| entry_present(tx, &i));
        if present {
            feeds.insert(feed);
        } else {
            tx.execute(
                "DELETE FROM bundle_psl_hits WHERE bundle_id = ?1 AND feed_id = ?2 AND rule_hash = ?3",
                rusqlite::params![bundle, feed, hash],
            )?;
        }
    }
    for (key, feed) in open_with_prefix(tx, bundle, &format!("bundle_warning:{bundle}:psl:"))? {
        let by = feed.as_deref().map(|f| psl_key(bundle, f));
        alerts.resolve_in(tx, &key, Some(&json!({"superseded_by": by})), ch)?;
    }
    for (_, feed) in open_with_prefix(tx, bundle, &psl_key(bundle, ""))? {
        if let Some(f) = feed {
            feeds.insert(f);
        }
    }
    let mut feeds: Vec<String> = feeds.into_iter().collect();
    feeds.sort();
    for feed in feeds {
        psl_summarise(tx, alerts, bundle, &feed, ch)?;
    }
    Ok(())
}

/// Brings one (bundle, feed) pair's grouped public-suffix warning in line with its rows (#49):
/// resolved when none are left; raised when it doesn't exist; its summary replaced while open
/// (no new occurrence or history entry); while resolved, left resolved unless a suffix it hasn't
/// shown entered, which reopens it with the added suffixes in its details.
fn psl_summarise(
    tx: &rusqlite::Transaction<'_>,
    alerts: &crate::alerts::Alerts,
    bundle: &str,
    feed: &str,
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    let key = psl_key(bundle, feed);
    // suffix, rules, shown by the alert already
    let rows: Vec<(String, i64, bool)> = {
        let mut st = tx.prepare(
            "SELECT suffix, count(*), max(alerted) FROM bundle_psl_hits WHERE bundle_id = ?1 AND feed_id = ?2
             GROUP BY suffix ORDER BY suffix",
        )?;
        st.query_map(rusqlite::params![bundle, feed], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0))
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    if rows.is_empty() {
        alerts.resolve_in(tx, &key, Some(&json!({"suffixes": 0})), ch)?;
        return Ok(());
    }
    let total = rows.len();
    let rules: i64 = rows.iter().map(|r| r.1).sum();
    let added: Vec<&str> = rows.iter().filter(|r| !r.2).map(|r| r.0.as_str()).collect();
    let all: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    let digest = picket_api::ids::object_id(all.join("\n").as_bytes())[..16].to_string();
    let detail = json!({
        "warning": "public_suffix",
        "bundle": bundle,
        "feed": feed,
        "suffixes": total,
        "rules": rules,
        "preview": all.iter().take(PSL_PREVIEW).collect::<Vec<_>>(),
        "more": total.saturating_sub(PSL_PREVIEW),
        "added": added.iter().take(PSL_PREVIEW).collect::<Vec<_>>(),
        "added_count": added.len(),
        "suffix_digest": digest,
    });
    let title = format!(
        "Bundle {bundle} blocks {total} public suffix{} (feed {feed})",
        if total == 1 { "" } else { "es" }
    );
    let current: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT state, json_extract(details_json, '$.suffix_digest') FROM alerts WHERE dedupe_key = ?1",
            [&key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let shown = match current {
        Some((state, old)) if state == "open" || added.is_empty() => {
            // Open: the summary follows the set. Resolved by hand with nothing new: it stays
            // resolved (its summary still follows, so reading it shows the current set).
            if old.as_deref() != Some(digest.as_str()) {
                alerts.update_summary_in(tx, &key, &title, &detail, ch)?;
            }
            state == "open"
        }
        // New, or resolved and a suffix it hasn't shown entered: raised (reopened).
        _ => {
            let spec = RaiseSpec::new("bundle_warning", Severity::Warning, key.clone(), title, detail)
                .bundle(bundle.to_string())
                .feed(feed.to_string());
            alerts.raise_in(tx, &spec, ch)?.is_some()
        }
    };
    if shown && !added.is_empty() {
        tx.execute(
            "UPDATE bundle_psl_hits SET alerted = 1 WHERE bundle_id = ?1 AND feed_id = ?2 AND alerted = 0",
            rusqlite::params![bundle, feed],
        )?;
    }
    Ok(())
}

/// A deleted bundle's public-suffix rows go and its grouped warnings resolve (#49).
pub fn retire_public_suffix(
    tx: &rusqlite::Transaction<'_>,
    alerts: &crate::alerts::Alerts,
    bundle: &str,
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM bundle_psl_hits WHERE bundle_id = ?1", [bundle])?;
    for prefix in [psl_key(bundle, ""), format!("bundle_warning:{bundle}:psl:")] {
        for (key, _) in open_with_prefix(tx, bundle, &prefix)? {
            alerts.resolve_in(tx, &key, Some(&json!({"bundle_deleted": true})), ch)?;
        }
    }
    Ok(())
}

/// The severity of the open alert with `dedupe_key`, if one is open.
fn open_severity(tx: &rusqlite::Transaction<'_>, dedupe_key: &str) -> rusqlite::Result<Option<Severity>> {
    let s: Option<String> = tx
        .query_row(
            "SELECT severity FROM alerts WHERE dedupe_key = ?1 AND state = 'open'",
            [dedupe_key],
            |r| r.get(0),
        )
        .optional()?;
    // An unreadable severity reads as none, so the finding takes its own.
    Ok(s.map(|s| serde_json::from_value(Value::String(s)).unwrap_or(Severity::Info)))
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

    fn rule(line: &str) -> Rule {
        match picket_rules::classify::classify_adblock_line(line, false) {
            picket_rules::classify::Line::Items(v) => match v.into_iter().next() {
                Some(picket_rules::classify::Item::Rule(r)) => r,
                o => panic!("{line}: {o:?}"),
            },
            o => panic!("{line}: {o:?}"),
        }
    }

    #[test]
    fn broad_block_severity_follows_the_feed_and_the_audience() {
        for l in [
            "$client=kids-tablet",
            "||com^$ctag=kids",
            "/./$client=kids-tablet,dnstype=A",
        ] {
            assert!(is_broad(&rule(l)), "{l}");
            assert_eq!(broad_block_severity(&rule(l), false), Severity::Warning, "{l}");
            // A downloaded feed's (kept by `client_rules: keep`) stays critical.
            assert_eq!(broad_block_severity(&rule(l), true), Severity::Critical, "{l}");
        }
        for l in [
            "$client=~kids-tablet",
            "$client=10.0.0.0/8",
            "$dnstype=A",
            "||com^",
        ] {
            assert_eq!(broad_block_severity(&rule(l), false), Severity::Critical, "{l}");
        }
    }
}
