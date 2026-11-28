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
//!   what it was found to cancel ("at least" that when the scan's candidates were cut), or "may
//!   cancel" when the bounded scan couldn't prove it
//!   ([`picket_rules::badfilter::cross_feed_cancellations_within`]); a scan that left something
//!   unchecked (`cancel_scan_incomplete`, with its reasons); more than 10k patterns or
//!   host-IP mappings; patterns past the reference's budget or too large to build; rules whose
//!   `$denyallow` entities didn't fit the cap; a shard that can't split. Per-rule warnings resolve
//!   when the rule leaves the bundle, aggregate ones when their condition clears.
//!
//! Checks run on the entries a build reads as changed (all of them in a fresh or full build), with
//! cheap filters first so a 10M-entry feed costs little: a key is a public-suffix candidate only
//! when its name is listed in the PSL (or under one of its wildcards).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::OnceLock;

use anyhow::Result;
use picket_rules::badfilter::{
    CANCELLATION_SAMPLE, CancelKind, CrossFeedReport, ScanLimits, cross_feed_cancellations_within,
    is_pattern_exception, keyed_equivalent_key,
};
use picket_rules::compile::{blocks_public_suffix_below_tld, has_scoped_audience, is_broad};
use picket_rules::name::reverse_dotted;
use picket_rules::{Flags, Kind, Rule, RuleType};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

use super::build::Ctx;
use super::source::{KeyCursor, OrderKey, Row, View};
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
/// Keys (or keyed blocks, sweeping every key) one step of the key sweep reads, at most: a page
/// that doesn't fit [`SCAN_WORK_PER_STEP`] is read again at half the size, down to
/// [`SWEEP_KEYS_MIN`].
pub const SWEEP_KEYS_PER_STEP: usize = 10_000;
/// The fewest keys a sweep step reads.
pub const SWEEP_KEYS_MIN: usize = 64;
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

/// What the cross-feed scan couldn't check, by reason (the incomplete-scan warning's `reasons`).
pub mod gap {
    /// A chunk's related rules passed [`super::MAX_RELATED`].
    pub const RELATED: &str = "related_cap";
    /// A keyed exception with a subdomain flag has more than [`super::BELOW_PER_CANCELLER`] keys
    /// below it.
    pub const BELOW: &str = "below_cap";
    /// More patterns than the scan reads.
    pub const PATTERNS: &str = "patterns_cap";
    /// More IP rules than the scan reads.
    pub const IPS: &str = "ip_cap";
    /// The scan's work budget ran out.
    pub const WORK: &str = "work";

    /// The reason in words (the warning's title).
    pub fn describe(reason: &str) -> String {
        match reason {
            RELATED => format!("more than {} related rules", super::MAX_RELATED),
            BELOW => format!(
                "more than {} keys below a subdomain-wide exception",
                super::BELOW_PER_CANCELLER
            ),
            PATTERNS => "more patterns than the scan reads".into(),
            IPS => "more IP rules than the scan reads".into(),
            WORK => "the scan's work budget ran out".into(),
            other => other.into(),
        }
    }
}

/// The incomplete-scan warning of `bundle`.
pub fn incomplete_key(bundle: &str) -> String {
    format!("bundle_warning:{bundle}:cancel_scan_incomplete")
}

/// The cross-feed scan of a build in progress: the bundle's cancellers (exceptions and
/// `$badfilter` rules), scanned a chunk per step (core.md §3), then the exception patterns
/// against the keys a page per step, and the work left of the scan's total budget.
pub struct CancelScan {
    cancellers: Vec<Row>,
    next: usize,
    work_left: u64,
    /// The exception patterns ([`is_pattern_exception`]): what their chunks found against the
    /// patterns, completed by the key sweep.
    pending: Vec<Pending>,
    /// The key sweep, once the chunks are done.
    sweep: Option<Sweep>,
    /// The sweep reads every keyed block of the bundle, not only the changed keys: an exception
    /// pattern was added in an incremental build (the keys it may cancel needn't have changed).
    all_keys: bool,
    /// The keys the scan meets cover the whole bundle (fresh and full builds; an incremental
    /// build sweeping every key, or without exception patterns): a complete scan then resolves
    /// the incomplete-scan warning, where one covering only the changed keys leaves it standing.
    covers_all: bool,
    /// What the scan couldn't check ([`gap`]).
    gaps: BTreeSet<&'static str>,
}

/// An exception pattern while the scan runs.
#[derive(Clone, Debug)]
struct Pending {
    row: Row,
    count: u64,
    /// Every rule it may cancel was checked so far (among the keys the sweep reads).
    complete: bool,
    raw: Option<(String, Option<i64>)>,
    sample: Vec<String>,
}

impl Pending {
    fn add(&mut self, count: u64, sample: Vec<String>) {
        self.count = self.count.saturating_add(count);
        for s in sample {
            if self.sample.len() >= CANCELLATION_SAMPLE {
                break;
            }
            self.sample.push(s);
        }
    }

    /// What the scan reports for it: nothing when it was found to cancel nothing in a complete
    /// scan. Its count is exact only when the sweep read every key (`whole`): a sweep of the
    /// changed keys finds what they add, so its count is a lower bound.
    fn into_found(self, whole: bool) -> Option<Found> {
        if self.count == 0 && self.complete {
            return None;
        }
        Some(Found {
            ident: Identity::from_row(&self.row),
            kind: CancelKind::Exception,
            count: self.count,
            proven: self.count > 0,
            exhaustive: self.complete && whole,
            raw: self.raw,
            sample: self.sample,
        })
    }
}

/// Where the key sweep stands.
#[derive(Clone, Debug)]
enum SweepAt {
    /// The changed keys (`bundle_build_keys`) after this one: every key in a fresh or full build.
    Changed(String),
    /// Every keyed block: the member feed (index into the view's feeds), the rule type (index
    /// into [`SWEEP_TYPES`]) and the place in its (key, id) order.
    All {
        feed: usize,
        rule_type: usize,
        cursor: KeyCursor,
    },
}

/// The key sweep: where it stands and the keys (or rows) its next step reads.
#[derive(Clone, Debug)]
struct Sweep {
    at: SweepAt,
    page: usize,
}

/// The rule types whose keyed blocks the sweep of every key reads.
const SWEEP_TYPES: [RuleType; 2] = [RuleType::Dns, RuleType::Ip];

/// One step of the cross-feed guardrail (bundles.md §2): each `@@` / `$badfilter` rule that
/// cancels rules of another feed of the bundle raises one `bundle_warning`. The first step reads
/// the cancellers; each later step scans [`CANCELLERS_PER_STEP`] of them against the rules they
/// can cancel (their keys, the keys above and, with a subdomain flag, below them, every pattern,
/// and the IP rules when one is an IP rule) within [`SCAN_WORK_PER_STEP`], out of [`SCAN_WORK`]
/// for the whole scan. An exception pattern can cancel a keyed block at any key, so it meets the
/// patterns in its chunk and then every changed key (every key in a fresh or full build, or in
/// an incremental build that added one) in a sweep of [`SWEEP_KEYS_PER_STEP`] keys a step.
///
/// What the scan couldn't check is never shown as an absence: a canceller left unchecked is
/// reported as "may cancel", one whose candidates were cut as cancelling "at least" what was
/// found, and the bundle's `cancel_scan_incomplete` warning names the reasons ([`gap`]). It
/// resolves once a scan covering the whole bundle is complete. `Ok(true)` when done.
pub async fn cancellations_step(state: &SharedState, ctx: &mut Ctx) -> Result<bool> {
    let bundle = ctx.spec.id.clone();
    let skip_key = format!("bundle_warning:{bundle}:cancel_scan");
    let Some(mut scan) = ctx.cancel.take() else {
        // The first step: what to scan.
        if ctx.spec.members.len() < 2 || !ctx.spec.compiles() {
            ctx.findings.condition(skip_key, None);
            ctx.findings.condition(incomplete_key(&bundle), None);
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
                // A skipped scan says so in its own warning.
                ctx.findings.condition(incomplete_key(&bundle), None);
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
                    ctx.findings.condition(incomplete_key(&bundle), None);
                    return Ok(true);
                }
                let incremental = ctx.mode == super::build::Mode::Incremental;
                let all_keys = incremental && ctx.touched.pattern_exception;
                let any_pattern = cancellers.iter().any(|r| is_pattern_exception(&r.rule));
                ctx.cancel = Some(CancelScan {
                    cancellers,
                    next: 0,
                    work_left: SCAN_WORK,
                    pending: Vec::new(),
                    sweep: None,
                    all_keys,
                    covers_all: !incremental || all_keys || !any_pattern,
                    gaps: BTreeSet::new(),
                });
                return Ok(false);
            }
        }
    };
    if scan.next < scan.cancellers.len() {
        let end = (scan.next + CANCELLERS_PER_STEP).min(scan.cancellers.len());
        let chunk: Vec<Row> = scan.cancellers[scan.next..end].to_vec();
        scan.next = end;
        if scan.work_left == 0 {
            // The scan's budget is spent: the rest are reported unproven, as the scan does.
            scan.gaps.insert(gap::WORK);
            for r in chunk {
                if is_pattern_exception(&r.rule) {
                    scan.pending.push(Pending {
                        row: r,
                        count: 0,
                        complete: false,
                        raw: None,
                        sample: Vec::new(),
                    });
                } else {
                    let found = Found::unchecked(&r);
                    push_found(ctx, &bundle, found);
                }
            }
        } else {
            let (spec, runs) = (ctx.spec.clone(), ctx.runs.clone());
            let work = scan.work_left.min(SCAN_WORK_PER_STEP);
            let out = state
                .db
                .read(move |c| scan_chunk(c, &spec, &runs, chunk, work))
                .await?;
            scan.work_left = scan.work_left.saturating_sub(out.spent);
            scan.gaps.extend(out.gaps);
            scan.pending.extend(out.pending);
            for f in out.found {
                push_found(ctx, &bundle, f);
            }
        }
        if scan.next < scan.cancellers.len() || !scan.pending.is_empty() {
            ctx.cancel = Some(scan);
            return Ok(false);
        }
    } else if !scan.pending.is_empty() {
        // The key sweep, a page per step.
        let sweep = scan.sweep.take().unwrap_or_else(|| Sweep {
            at: if scan.all_keys {
                SweepAt::All {
                    feed: 0,
                    rule_type: 0,
                    cursor: super::source::KEYS_START,
                }
            } else {
                SweepAt::Changed(String::new())
            },
            page: SWEEP_KEYS_PER_STEP,
        });
        if scan.work_left == 0 {
            scan.gaps.insert(gap::WORK);
            for p in &mut scan.pending {
                p.complete = false;
            }
        } else {
            let (spec, runs, b2) = (ctx.spec.clone(), ctx.runs.clone(), bundle.clone());
            let work = scan.work_left.min(SCAN_WORK_PER_STEP);
            let pats: Vec<(Rule, String)> = scan
                .pending
                .iter()
                .map(|p| (p.row.rule.clone(), p.row.feed.clone()))
                .collect();
            let input = sweep.clone();
            let out = state
                .db
                .read(move |c| sweep_step(c, &spec, &runs, &b2, &pats, &input, work))
                .await?;
            scan.work_left = scan.work_left.saturating_sub(out.spent);
            let outcome = match out.outcome {
                // Read again, smaller, while the budget allows; else keep what it proved.
                SweepOutcome::Retry { .. } if scan.work_left > 0 => None,
                SweepOutcome::Retry { hits } => Some(SweepOutcome::Done {
                    hits,
                    capped: true,
                    next: None,
                }),
                done @ SweepOutcome::Done { .. } => Some(done),
            };
            let next = match outcome {
                None => Some(Sweep {
                    at: sweep.at,
                    page: (sweep.page / 2).max(SWEEP_KEYS_MIN),
                }),
                Some(SweepOutcome::Retry { .. }) => None,
                Some(SweepOutcome::Done { hits, capped, next }) => {
                    if capped {
                        scan.gaps.insert(gap::WORK);
                        for p in &mut scan.pending {
                            p.complete = false;
                        }
                    }
                    for (p, (count, sample)) in scan.pending.iter_mut().zip(hits) {
                        p.add(count, sample);
                    }
                    next.map(|at| Sweep {
                        at,
                        page: if capped {
                            sweep.page
                        } else {
                            (sweep.page * 2).min(SWEEP_KEYS_PER_STEP)
                        },
                    })
                }
            };
            if let Some(next) = next {
                scan.sweep = Some(next);
                ctx.cancel = Some(scan);
                return Ok(false);
            }
        }
    }
    // Done: the exception patterns' findings, and whether the scan was complete.
    let whole = scan.covers_all;
    for p in std::mem::take(&mut scan.pending) {
        if let Some(f) = p.into_found(whole) {
            push_found(ctx, &bundle, f);
        }
    }
    if let Some(spec) = incomplete_condition(&bundle, &scan.gaps, scan.covers_all) {
        ctx.findings.condition(incomplete_key(&bundle), spec);
    }
    Ok(true)
}

/// The incomplete-scan warning after a scan: raised when something went unchecked, resolved when
/// a scan covering the whole bundle was complete (`Some(None)`), else left as it stands (`None`:
/// the keys it didn't meet may still hide what an earlier scan couldn't check).
fn incomplete_condition(
    bundle: &str,
    gaps: &BTreeSet<&'static str>,
    covers_all: bool,
) -> Option<Option<RaiseSpec>> {
    if gaps.is_empty() {
        return covers_all.then_some(None);
    }
    let key = incomplete_key(bundle);
    let words: Vec<String> = gaps.iter().map(|g| gap::describe(g)).collect();
    Some(Some(
        RaiseSpec::new(
            "bundle_warning",
            Severity::Warning,
            key,
            format!(
                "Bundle {bundle}: cross-feed cancellations only partly checked, so some may be unreported ({})",
                words.join("; ")
            ),
            json!({"bundle": bundle, "warning": "cancel_scan_incomplete", "reasons": gaps}),
        )
        .bundle(bundle.to_string()),
    ))
}

/// Raises one canceller's finding.
fn push_found(ctx: &mut Ctx, bundle: &str, f: Found) {
    let raw = f.raw;
    let how = match f.kind {
        CancelKind::Badfilter => "$badfilter",
        CancelKind::Exception => "exception",
        CancelKind::RewriteException => "@@…$dnsrewrite",
    };
    let (feed, count) = (&f.ident.feed, f.count);
    let title = match (f.proven, f.exhaustive) {
        (true, true) => {
            format!("An {how} in feed {feed} cancels {count} rule(s) of other feeds in bundle {bundle}")
        }
        (true, false) => format!(
            "An {how} in feed {feed} cancels at least {count} rule(s) of other feeds in bundle {bundle} (the scan couldn't check them all)"
        ),
        (false, _) => format!(
            "An {how} in feed {feed} may cancel rules of other feeds in bundle {bundle} (not proven within the scan's limits)"
        ),
    };
    let mut detail = json!({
        "warning": "cross_feed_cancellation",
        "proven": f.proven, "exhaustive": f.exhaustive, "cancelled": count, "sample": f.sample,
    });
    // Without its raw text here, the commit looks the rule and line up by identity.
    if let (Some((rule, line)), Some(d)) = (raw, detail.as_object_mut()) {
        d.insert("rule".into(), json!(rule));
        d.insert("line".into(), json!(line));
    }
    ctx.findings.push(Finding {
        kind: "bundle_warning",
        severity: Severity::Warning,
        dedupe_key: format!("bundle_warning:{bundle}:cancel:{}", f.ident.short()),
        title,
        identity: f.ident,
        detail,
    });
}

/// What the scan found for one canceller: whether it was found cancelling rules of other feeds
/// (`proven`; else it may, unchecked), how many (all of them when `exhaustive`, else at least
/// these), its raw text and line, and a sample of what it cancels.
#[derive(Clone, Debug)]
struct Found {
    ident: Identity,
    kind: CancelKind,
    count: u64,
    proven: bool,
    exhaustive: bool,
    raw: Option<(String, Option<i64>)>,
    sample: Vec<String>,
}

impl Found {
    /// A canceller the scan didn't check.
    fn unchecked(r: &Row) -> Found {
        Found {
            ident: Identity::from_row(r),
            kind: cancel_kind(&r.rule),
            count: 0,
            proven: false,
            exhaustive: false,
            raw: None,
            sample: Vec::new(),
        }
    }
}

fn cancel_kind(r: &Rule) -> CancelKind {
    if r.is_badfilter() {
        CancelKind::Badfilter
    } else if r.is_rewrite() {
        CancelKind::RewriteException
    } else {
        CancelKind::Exception
    }
}

/// The rules a report names, as alert samples: `raw (feed)`.
fn render_sample(c: &rusqlite::Connection, rows: &[&Row]) -> Vec<String> {
    rows.iter()
        .map(|r| {
            format!(
                "{} ({})",
                super::source::raw_of(c, r.entry_id)
                    .map(|x| x.0)
                    .unwrap_or_default(),
                r.feed
            )
        })
        .collect()
}

/// What one chunk's scan found: the findings of its keyed and `$badfilter` cancellers, its
/// exception patterns so far, what it couldn't check, and the work spent.
struct ChunkOut {
    found: Vec<Found>,
    pending: Vec<Pending>,
    gaps: BTreeSet<&'static str>,
    spent: u64,
}

/// Adds rows to the related set, up to [`MAX_RELATED`]; false when some didn't fit.
fn add_related(rows: &mut BTreeMap<OrderKey, Row>, v: Vec<Row>) -> bool {
    for r in v {
        if rows.len() >= MAX_RELATED && !rows.contains_key(&r.order) {
            return false;
        }
        rows.entry(r.order.clone()).or_insert(r);
    }
    true
}

/// Scans one chunk of cancellers within `work`. Keyed and `$badfilter` cancellers meet the rules
/// they can cancel (their keys, the keys above and, with a subdomain flag, below them, every
/// pattern, the IP rules when one is an IP rule); exception patterns meet the block patterns
/// here and the keyed blocks in the key sweep.
fn scan_chunk(
    c: &rusqlite::Connection,
    spec: &super::spec::Spec,
    runs: &super::spec::Runs,
    cancellers: Vec<Row>,
    work: u64,
) -> Result<ChunkOut> {
    let view = View::new(spec, runs);
    let mut bad = 0u64;
    let mut out = ChunkOut {
        found: Vec::new(),
        pending: Vec::new(),
        gaps: BTreeSet::new(),
        spent: 0,
    };
    let (pats, keyed): (Vec<Row>, Vec<Row>) = cancellers
        .into_iter()
        .partition(|r| is_pattern_exception(&r.rule));
    let patterns = view.patterns(c, super::build::MAX_PATTERN_RULES, &mut bad)?.ok();
    if patterns.is_none() {
        out.gaps.insert(gap::PATTERNS);
    }
    if !keyed.is_empty() {
        let mut rows: BTreeMap<OrderKey, Row> = BTreeMap::new();
        let mut fits = true;
        // Cancellers whose candidates were cut.
        let mut cut: HashSet<OrderKey> = HashSet::new();
        let mut ip_cancellers: Vec<OrderKey> = Vec::new();
        for r in &keyed {
            let key = super::source::domain_key(&r.rule)
                .map(|k| (k, r.rule.flags))
                .or_else(|| keyed_equivalent_key(&r.rule));
            if let Some((k, flags)) = key {
                fits &= add_related(&mut rows, view.key_rules(c, &k, &mut bad)?);
                let mut s: &str = &k;
                while let Some(i) = s.rfind('.') {
                    s = &s[..i];
                    fits &= add_related(&mut rows, view.key_rules(c, s, &mut bad)?);
                }
                if flags.intersects(Flags::ALL_SUBS) {
                    // One more than it keeps tells a full page from an omission.
                    let mut below = view.below(c, &k, BELOW_PER_CANCELLER + 1, &mut bad)?;
                    if below.len() > BELOW_PER_CANCELLER {
                        below.truncate(BELOW_PER_CANCELLER);
                        out.gaps.insert(gap::BELOW);
                        cut.insert(r.order.clone());
                    }
                    fits &= add_related(&mut rows, below);
                }
            }
            if matches!(r.rule.key_kind(), Kind::IpLiteral | Kind::IpRange) {
                ip_cancellers.push(r.order.clone());
            }
        }
        match &patterns {
            Some(p) => fits &= add_related(&mut rows, p.clone()),
            None => cut.extend(keyed.iter().map(|r| r.order.clone())),
        }
        if !ip_cancellers.is_empty() {
            match view.ip_rules(c, MAX_RELATED, &mut bad)? {
                Ok(ips) => fits &= add_related(&mut rows, ips),
                Err(_) => {
                    out.gaps.insert(gap::IPS);
                    cut.extend(ip_cancellers);
                }
            }
        }
        if !fits {
            out.gaps.insert(gap::RELATED);
            cut.extend(keyed.iter().map(|r| r.order.clone()));
        }
        let mine: BTreeSet<OrderKey> = keyed.iter().map(|r| r.order.clone()).collect();
        for r in keyed {
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
        out.spent = report.work;
        if report.capped {
            out.gaps.insert(gap::WORK);
        }
        let mut reported: HashSet<&OrderKey> = HashSet::new();
        for rep in &report.cancellers {
            let Some(row) = rows.get(rep.canceller) else {
                continue;
            };
            // Other exceptions among the related rules are their own chunk's.
            if !mine.contains(&row.order) {
                continue;
            }
            reported.insert(&row.order);
            let sample: Vec<&Row> = rep.sample.iter().filter_map(|i| rows.get(*i)).collect();
            out.found.push(Found {
                ident: Identity::from_row(row),
                kind: rep.kind,
                count: rep.count,
                proven: rep.proven,
                exhaustive: rep.proven && !report.capped && !cut.contains(&row.order),
                raw: super::source::raw_of(c, row.entry_id).ok(),
                sample: render_sample(c, &sample),
            });
        }
        // Found cancelling nothing among candidates that were cut: it may still.
        for row in rows.iter().filter(|r| mine.contains(&r.order)) {
            if cut.contains(&row.order) && !reported.contains(&row.order) {
                let mut f = Found::unchecked(row);
                f.raw = super::source::raw_of(c, row.entry_id).ok();
                out.found.push(f);
            }
        }
    }
    if !pats.is_empty() {
        // Against the block patterns (their keyed-equivalent ones included).
        let mut rows: Vec<Row> = pats.clone();
        if let Some(p) = &patterns {
            rows.extend(
                p.iter()
                    .filter(|r| !r.rule.is_exception() && !r.rule.is_badfilter())
                    .cloned(),
            );
        }
        let rules: Vec<Rule> = rows.iter().map(|r| r.rule.clone()).collect();
        let feeds: Vec<&str> = rows.iter().map(|r| r.feed.as_str()).collect();
        let report = cross_feed_cancellations_within(
            &rules,
            &feeds,
            ScanLimits {
                work: work.saturating_sub(out.spent),
                ..ScanLimits::default()
            },
        );
        out.spent = out.spent.saturating_add(report.work);
        if report.capped {
            out.gaps.insert(gap::WORK);
        }
        for (i, row) in pats.into_iter().enumerate() {
            let (count, sample) = match report.get(i) {
                Some(rep) => (
                    rep.count,
                    render_sample(
                        c,
                        &rep.sample.iter().filter_map(|j| rows.get(*j)).collect::<Vec<_>>(),
                    ),
                ),
                None => (0, Vec::new()),
            };
            let raw = super::source::raw_of(c, row.entry_id).ok();
            out.pending.push(Pending {
                row,
                count,
                complete: patterns.is_some() && !report.capped,
                raw,
                sample,
            });
        }
    }
    Ok(out)
}

/// What a sweep step came to.
enum SweepOutcome {
    /// The page didn't fit the step's work: read it again, smaller (what it proved before
    /// running out, per exception pattern, stands only when no retry can run).
    Retry { hits: Vec<(u64, Vec<String>)> },
    /// The page was scanned: per exception pattern, the blocks found and a sample of them;
    /// whether the work ran out in it (at the smallest page); and where the sweep goes on
    /// (`None`: done).
    Done {
        hits: Vec<(u64, Vec<String>)>,
        capped: bool,
        next: Option<SweepAt>,
    },
}

struct SweepOut {
    outcome: SweepOutcome,
    spent: u64,
}

/// One step of the key sweep: a page of keyed blocks against the exception patterns `pats`
/// (rule, feed), within `work`.
fn sweep_step(
    c: &rusqlite::Connection,
    spec: &super::spec::Spec,
    runs: &super::spec::Runs,
    bundle: &str,
    pats: &[(Rule, String)],
    sweep: &Sweep,
    work: u64,
) -> Result<SweepOut> {
    let view = View::new(spec, runs);
    let mut bad = 0u64;
    let is_block = |r: &Row| {
        matches!(r.rule.kind, Kind::Name | Kind::HostMapping | Kind::IpLiteral)
            && !r.rule.is_exception()
            && !r.rule.is_badfilter()
    };
    let (blocks, next): (Vec<Row>, Option<SweepAt>) = match &sweep.at {
        SweepAt::Changed(after) => {
            let keys: Vec<String> = {
                let mut st = c.prepare_cached(
                    "SELECT key FROM bundle_build_keys WHERE bundle_id = ?1 AND key > ?2 ORDER BY key LIMIT ?3",
                )?;
                st.query_map(rusqlite::params![bundle, after, sweep.page], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let mut blocks = Vec::new();
            for k in &keys {
                blocks.extend(view.key_rules(c, k, &mut bad)?.into_iter().filter(is_block));
            }
            let next = (keys.len() >= sweep.page)
                .then(|| keys.last().cloned().map(SweepAt::Changed))
                .flatten();
            (blocks, next)
        }
        SweepAt::All {
            feed,
            rule_type,
            cursor,
        } => {
            let feeds: Vec<(&str, i64)> = view.feeds().collect();
            // A feed whose own exception patterns are all there are cancels nothing of its own.
            let skip = |f: &str| pats.iter().all(|(_, pf)| pf == f);
            let (mut fi, mut ti, mut cur) = (*feed, *rule_type, cursor.clone());
            loop {
                let Some(&(f, _)) = feeds.get(fi) else {
                    break (Vec::new(), None);
                };
                let Some(rt) = SWEEP_TYPES.get(ti) else {
                    (fi, ti, cur) = (fi + 1, 0, super::source::KEYS_START);
                    continue;
                };
                if skip(f) {
                    (fi, ti, cur) = (fi + 1, 0, super::source::KEYS_START);
                    continue;
                }
                let (rows, after) = view.keyed_blocks_page(c, f, *rt, &cur, sweep.page, &mut bad)?;
                let next = match after {
                    Some(after) => SweepAt::All {
                        feed: fi,
                        rule_type: ti,
                        cursor: after,
                    },
                    None => SweepAt::All {
                        feed: fi,
                        rule_type: ti + 1,
                        cursor: super::source::KEYS_START,
                    },
                };
                break (rows.into_iter().filter(is_block).collect(), Some(next));
            }
        }
    };
    let n = pats.len();
    let mut rules: Vec<Rule> = pats.iter().map(|(r, _)| r.clone()).collect();
    let mut feeds: Vec<&str> = pats.iter().map(|(_, f)| f.as_str()).collect();
    rules.extend(blocks.iter().map(|r| r.rule.clone()));
    feeds.extend(blocks.iter().map(|r| r.feed.as_str()));
    let report = if blocks.is_empty() {
        CrossFeedReport::default()
    } else {
        cross_feed_cancellations_within(
            &rules,
            &feeds,
            ScanLimits {
                work,
                ..ScanLimits::default()
            },
        )
    };
    let mut hits = vec![(0u64, Vec::new()); n];
    for rep in &report.cancellers {
        let Some(h) = hits.get_mut(rep.canceller) else {
            continue;
        };
        let sample: Vec<&Row> = rep
            .sample
            .iter()
            .filter_map(|i| i.checked_sub(n).and_then(|b| blocks.get(b)))
            .collect();
        *h = (rep.count, render_sample(c, &sample));
    }
    if report.capped && sweep.page > SWEEP_KEYS_MIN {
        return Ok(SweepOut {
            outcome: SweepOutcome::Retry { hits },
            spent: report.work,
        });
    }
    Ok(SweepOut {
        outcome: SweepOutcome::Done {
            hits,
            capped: report.capped,
            next,
        },
        spent: report.work,
    })
}

/// Applies a build's findings in its commit transaction: new per-rule findings and aggregate
/// conditions raise (when not open), cleared conditions resolve, and per-rule alerts of the bundle
/// whose rule left it resolve.
/// Per member feed, the rule types (`dns`, `ip`) the bundle compiles from it as blocks; empty
/// for a bundle that doesn't block.
pub type PslMembers = Vec<(String, Vec<String>)>;

pub fn apply(
    tx: &rusqlite::Transaction<'_>,
    alerts: &crate::alerts::Alerts,
    bundle: &str,
    members: &[Member],
    psl_members: &[(String, Vec<String>)],
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
    apply_public_suffix(tx, alerts, bundle, psl_members, &findings.psl, ch)?;
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
    members: &[(String, Vec<String>)],
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
    // A rule replacing another for the same suffix in this build (`||co.uk^` becoming
    // `||co.uk^$important`) inherits its acknowledgement: the suffix never left, so it isn't new.
    tx.execute(
        "UPDATE bundle_psl_hits SET alerted = 1 WHERE bundle_id = ?1 AND alerted = 0 AND EXISTS (
           SELECT 1 FROM bundle_psl_hits o WHERE o.bundle_id = bundle_psl_hits.bundle_id
             AND o.feed_id = bundle_psl_hits.feed_id AND o.suffix = bundle_psl_hits.suffix AND o.alerted = 1)",
        [bundle],
    )?;
    let mut feeds: HashSet<String> = HashSet::new();
    for (feed, hash, ij) in rows {
        // Kept while the bundle still blocks with the rule: its feed is a member whose rule type
        // the bundle compiles as blocks, and the rule is still in the feed.
        let present = serde_json::from_str::<Identity>(&ij).is_ok_and(|i| {
            members
                .iter()
                .any(|(f, types)| *f == feed && types.contains(&i.rule_type))
                && entry_present(tx, &i)
        });
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
    let current: Option<(String, Option<String>, Option<i64>)> = tx
        .query_row(
            "SELECT state, json_extract(details_json, '$.suffix_digest'), json_extract(details_json, '$.rules')
             FROM alerts WHERE dedupe_key = ?1",
            [&key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let shown = match current {
        Some((state, old, old_rules)) if state == "open" || added.is_empty() => {
            // Open: the summary follows the set. Resolved by hand with nothing new: it stays
            // resolved (its summary still follows, so reading it shows the current set). A rule
            // added or removed for a suffix already listed changes only the rule count.
            if old.as_deref() != Some(digest.as_str()) || old_rules != Some(rules) {
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

    fn row(line: &str, feed: &str) -> Row {
        let rule = rule(line);
        Row {
            order: OrderKey {
                position: 0,
                line_no: 1,
                rule_type: rule.rule_type.as_str(),
                kind: rule.kind.as_str(),
                key: rule.key.clone(),
                flags: rule.flags.bits(),
                value_json: String::new(),
            },
            feed: feed.into(),
            rule,
            first_seen_at: String::new(),
            entry_id: 0,
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

    #[test]
    fn exception_patterns_report_only_what_the_scan_proved() {
        let pending = |count, complete| Pending {
            row: row("@@/^ads\\./", "b"),
            count,
            complete,
            raw: None,
            sample: Vec::new(),
        };
        assert!(pending(0, true).into_found(true).is_none(), "a complete negative");
        assert!(
            pending(0, true).into_found(false).is_none(),
            "nothing new among the changed keys"
        );
        let f = pending(0, false).into_found(true).expect("unchecked: may cancel");
        assert!(!f.proven && !f.exhaustive);
        let f = pending(3, true).into_found(false).unwrap();
        assert!(
            f.proven && !f.exhaustive,
            "the changed keys' count is a lower bound"
        );
        let f = pending(3, false).into_found(true).unwrap();
        assert!(
            f.proven && !f.exhaustive,
            "a count of a cut scan is a lower bound"
        );
        let f = pending(3, true).into_found(true).unwrap();
        assert!(f.proven && f.exhaustive);
        // Samples gather across sweep pages, bounded.
        let mut p = pending(0, true);
        for _ in 0..3 {
            p.add(2, vec!["x (a)".into(), "y (a)".into()]);
        }
        assert_eq!(p.count, 6);
        assert_eq!(p.sample.len(), CANCELLATION_SAMPLE);
    }

    #[test]
    fn the_incomplete_warning_names_its_reasons_and_resolves_only_on_whole_coverage() {
        let gaps: BTreeSet<&'static str> = [gap::BELOW, gap::WORK].into();
        let Some(Some(spec)) = incomplete_condition("b1", &gaps, false) else {
            panic!("a gap raises the warning, whatever the coverage");
        };
        assert_eq!(spec.dedupe_key, incomplete_key("b1"));
        assert_eq!(spec.details["reasons"], json!(["below_cap", "work"]));
        assert!(spec.title.contains("work budget"), "{}", spec.title);
        let none = BTreeSet::new();
        assert!(
            matches!(incomplete_condition("b1", &none, true), Some(None)),
            "a complete scan of the whole bundle resolves it"
        );
        assert!(
            incomplete_condition("b1", &none, false).is_none(),
            "a complete scan of the changed keys only leaves it standing"
        );
    }
}
