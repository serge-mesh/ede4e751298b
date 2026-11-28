//! Alerts (core.md §9), the generic engine: raise with dedupe, resolve, history, thresholds for
//! conditions, delete, listing, and the UI WebSocket broadcast.
//!
//! - **Dedupe:** the same `dedupe_key` increments `count` and `last_seen` and reopens a resolved
//!   alert. Every raise and resolve writes an `alert_history` row (README §2, Alerts).
//! - **Kept until deleted** in the UI, outside retention. The table is bounded: a new alert
//!   beyond [`MAX_PER_KIND`] for its kind or [`MAX_TOTAL`] in all is dropped and counted (repeats
//!   of existing alerts always count), an alert about an edge also beyond [`MAX_PER_EDGE_KIND`]
//!   of its kind for that edge (README §2, capped shares: one edge can't take the kind's capacity
//!   from the others), and each alert keeps at most [`MAX_HISTORY`] history rows.
//! - **In the caller's transaction:** [`Alerts::raise_in`], [`Alerts::resolve_in`],
//!   [`Alerts::condition_in`] and [`Alerts::note_in`] change alerts inside another module's
//!   writer transaction, so an alert effect commits with what caused it, in commit order, or not
//!   at all (core.md §9; README §2 Restarts). [`Alerts::committed`] then updates the open-set
//!   cache and notes the changes for the UI on the writer, and [`Alerts::announce`] logs them.
//! - **UI events:** every raise, details update, resolve and delete, and every committed change
//!   to an alert's evidence ([`Alerts::evidence_changed`]), is noted for the coalesced `alert`
//!   event (`web::events::AlertEvent`, api.md §7): one a second at most, listing each changed
//!   alert once, bounded, so a burst of raises or a bulk delete can't flood the open tabs. Each
//!   is noted on the writer right after its commit, so the notes follow commit order (an alert's
//!   latest note is its state) and a config restore's commit splits them exactly (core.md §2).
//! - **Thresholds:** [`Alerts::condition`] raises a condition alert once it has held for its
//!   kind's threshold (`alerts.thresholds.*`, defaults from core.md §9) and resolves it when it
//!   clears. The held time comes from the condition's own `since`, so it survives restarts.
//!
//! The edge kinds' raise and resolve rules live with what feeds them (`edges::status`,
//! `logs::ingest`, `edges::releases`); the feed kinds (`feed_down`, `feed_provider_down`,
//! `feed_stale`, `feed_added`, `feed_limit_reached`, `feed_provider_trigger_down`,
//! `feed_provider_listing_incomplete`, `feed_held`, `feed_rules_dropped`, `feed_redirect_added`)
//! with `feeds::check`, `feeds::sqs`,
//! `feeds::select`, `feeds::stale` and `feeds::ingest`.
//! Evidence capture, the evidence budget and `alert_evidence_full` live in
//! `logs::evidence` (`logs::evidence::start` starts a security alert's capture); the
//! attribution, wire-check, feed and sync-lookup `category_blocked` and feed `category_answered`
//! raises in `logs::analysis` and `logs::retro`; `dnssec_bogus`, `dnssec_unavailable` and `upstream_disagrees` in `dnssec`.
//! The bundle kinds: `bundle_build_failed` in `compiler`; `bundle_over_budget` in
//! `compiler::commit` (`hot_max_mib`) and `edges::publish` (an edge's budget); `bundle_warning`,
//! `broad_block` and `broad_allow` in `compiler::guard` (browser-list `bundle_warning` in
//! `lists`); `warninglist_hit` and `allow_override` in `compiler::warn`; `bundle_cold_share`
//! in `logs::cold_share` (through [`Alerts::condition_in`] and its threshold). `temporary_allow`
//! (off by default: `alerts.temporary_allow`) in `logs::ingest`, with its evidence rule.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::Db;
use crate::error::{CoreError, CoreResult};
use crate::state::UiEvents;

/// Every alert kind of core.md §9's table.
pub const KINDS: &[(&str, AlertType)] = &[
    ("dnssec_bogus", AlertType::Security),
    ("upstream_disagrees", AlertType::Security),
    ("category_answered", AlertType::Security),
    ("category_blocked", AlertType::Security),
    ("broad_allow", AlertType::Security),
    ("upstream_invalid_spike", AlertType::Security),
    ("edge_key_mismatch", AlertType::Security),
    ("feed_rules_dropped", AlertType::Security),
    ("feed_redirect_added", AlertType::Security),
    ("temporary_allow", AlertType::Security),
    ("ui_auth_failures", AlertType::Security),
    ("edge_offline", AlertType::Operational),
    ("edge_update_failed", AlertType::Operational),
    ("edge_activation_failed", AlertType::Operational),
    ("edge_listener_rejected", AlertType::Operational),
    ("edge_listener_failed", AlertType::Operational),
    ("edge_upstream_down", AlertType::Operational),
    ("edge_spool_evicting", AlertType::Operational),
    ("edge_memory_low", AlertType::Operational),
    ("edge_fw_set_full", AlertType::Operational),
    ("edge_fw_repairs", AlertType::Operational),
    ("edge_fw_drift", AlertType::Operational),
    ("edge_helper_unreachable", AlertType::Operational),
    ("edge_ssd_unavailable", AlertType::Operational),
    ("edge_crash_loop", AlertType::Operational),
    ("edge_panic", AlertType::Operational),
    ("edge_redirect_missing", AlertType::Operational),
    ("edge_unifi_conflict", AlertType::Operational),
    ("edge_fw_layout_unknown", AlertType::Operational),
    ("edge_fw_catch_all", AlertType::Operational),
    ("edge_helper_disabled", AlertType::Operational),
    ("edge_page_file_refetched", AlertType::Operational),
    ("edge_tls_version_refused", AlertType::Operational),
    ("edge_firmware_unsupported", AlertType::Operational),
    ("edge_firmware_check_failed", AlertType::Operational),
    ("release_invalid", AlertType::Operational),
    ("feed_provider_down", AlertType::Operational),
    ("feed_down", AlertType::Operational),
    ("feed_stale", AlertType::Operational),
    ("feed_added", AlertType::Operational),
    ("feed_provider_trigger_down", AlertType::Operational),
    ("feed_provider_listing_incomplete", AlertType::Operational),
    ("feed_limit_reached", AlertType::Operational),
    ("config_upgraded", AlertType::Operational),
    ("feed_held", AlertType::Operational),
    ("bundle_build_failed", AlertType::Operational),
    ("bundle_over_budget", AlertType::Operational),
    ("bundle_cold_share", AlertType::Operational),
    ("broad_block", AlertType::Operational),
    ("allow_override", AlertType::Operational),
    ("bundle_warning", AlertType::Operational),
    ("warninglist_hit", AlertType::Operational),
    ("lookup_provider_down", AlertType::Operational),
    ("lookup_self_test_failed", AlertType::Operational),
    ("dnssec_unavailable", AlertType::Operational),
    ("attribution_mismatch", AlertType::Operational),
    ("attribution_unavailable", AlertType::Operational),
    ("wire_mismatch", AlertType::Operational),
    ("core_disk_low", AlertType::Operational),
    ("alert_evidence_full", AlertType::Operational),
];

pub fn is_known_kind(kind: &str) -> bool {
    KINDS.iter().any(|(k, _)| *k == kind)
}

/// What marks a name bad for `category_answered` (core.md §7, §9): a feed's later entry
/// (retro-match) or a lookup provider's Block. One kind, one grouping for both sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnsweredBy<'a> {
    Feed(&'a str),
    Provider(&'a str),
}

/// The dedupe key of a `category_answered` alert (core.md §9 Grouping): on (feed or provider,
/// registrable domain; a name with none uses the full name).
pub fn category_answered_key(by: AnsweredBy<'_>, name: &str) -> String {
    let (kind, id) = match by {
        AnsweredBy::Feed(f) => ("feed", f),
        AnsweredBy::Provider(p) => ("provider", p),
    };
    format!("category_answered:{kind}:{id}:{}", crate::psl::grouping_key(name))
}

/// A `category_answered` alert's severity: warning for a `security` feed or provider, info
/// otherwise (as `category_blocked`, core.md §9).
pub fn category_answered_severity(security: bool) -> Severity {
    if security {
        Severity::Warning
    } else {
        Severity::Info
    }
}

/// The dedupe key of a `category_blocked` alert (core.md §9 Grouping): on (device, registrable
/// domain), the device being the record's `device`, else its client address.
pub fn category_blocked_key(device: &str, name: &str) -> String {
    format!("category_blocked:{device}:{}", crate::psl::grouping_key(name))
}

/// The dedupe key of a `temporary_allow` alert (core.md §9; the spec names none): grouped as
/// `category_blocked` (§9 Grouping), on the edge, the device (the record's `device`, else its
/// client address) and the target's registrable domain (a DNS allow) or the IP (an IP allow),
/// so a device's repeated allows of one site count on one alert.
pub fn temporary_allow_key(edge: &str, device: &str, dns: bool, target: &str) -> String {
    let target = if dns {
        crate::psl::grouping_key(target)
    } else {
        target.to_string()
    };
    format!("temporary_allow:{edge}:{device}:{target}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AlertType {
    Security,
    Operational,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AlertState {
    Open,
    Resolved,
}

fn s<T: Serialize>(v: T) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        _ => String::new(),
    }
}

fn p<T: for<'de> Deserialize<'de>>(v: String) -> rusqlite::Result<T> {
    serde_json::from_value(Value::String(v))
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

/// What to raise.
#[derive(Clone, Debug)]
pub struct RaiseSpec {
    pub kind: String,
    pub alert_type: AlertType,
    pub severity: Severity,
    pub dedupe_key: String,
    pub title: String,
    pub details: Value,
    pub edge_id: Option<String>,
    /// Whether the alert is about its edge ([`RaiseSpec::edge`]), so a new one takes a share of
    /// [`MAX_PER_EDGE_KIND`]; false for the edge a record-raised alert was seen on
    /// ([`RaiseSpec::seen_on_edge`]).
    pub edge_share: bool,
    /// This raise comes from records of several edges ([`RaiseSpec::seen_on_edges`]): the alert
    /// names no edge from now on.
    pub edge_several: bool,
    pub feed_provider_id: Option<String>,
    pub feed_id: Option<String>,
    pub bundle_id: Option<String>,
    /// How many occurrences this raise stands for (default 1): the count goes up by it. Callers
    /// that aggregate many matches of one key before raising (retro-match) pass the total, so
    /// one raise writes once instead of once per match.
    pub occurrences: u32,
}

impl RaiseSpec {
    /// A spec with the kind's type from [`KINDS`] and no target.
    pub fn new(
        kind: &str,
        severity: Severity,
        dedupe_key: impl Into<String>,
        title: impl Into<String>,
        details: Value,
    ) -> Self {
        let alert_type = KINDS
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, t)| *t)
            .unwrap_or(AlertType::Operational);
        Self {
            kind: kind.into(),
            alert_type,
            severity,
            dedupe_key: dedupe_key.into(),
            title: title.into(),
            details,
            edge_id: None,
            edge_share: false,
            edge_several: false,
            feed_provider_id: None,
            feed_id: None,
            bundle_id: None,
            occurrences: 1,
        }
    }
    /// See [`RaiseSpec::occurrences`] (at least 1).
    pub fn occurrences(mut self, n: u32) -> Self {
        self.occurrences = n.max(1);
        self
    }
    /// The edge the alert is about (an edge kind, or a per-edge key such as `wire_mismatch`'s):
    /// a new one takes a share of [`MAX_PER_EDGE_KIND`].
    pub fn edge(mut self, id: impl Into<String>) -> Self {
        self.edge_id = Some(id.into());
        self.edge_share = true;
        self
    }
    /// The edge whose record raised an alert keyed on something else (a device's or a name's
    /// security alert, core.md §9 Grouping): the record's `edge` (core.md §9 record), for the
    /// UI's edge filter and link, taking no per-edge share (the kind's alerts aren't the edge's).
    /// The alert names its edge while every record that raised it came from that edge; once a
    /// raise comes from another (or from several, [`RaiseSpec::seen_on_edges`]) it names none,
    /// for good. A raise naming no edge changes nothing.
    pub fn seen_on_edge(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        if !id.is_empty() {
            self.edge_id = Some(id);
            self.edge_share = false;
            self.edge_several = false;
        }
        self
    }
    /// [`RaiseSpec::seen_on_edge`] for a raise from the records of `edges`: one edge names it,
    /// several make the alert name none from now on, none changes nothing.
    pub fn seen_on_edges(self, edges: &[String]) -> Self {
        match edges {
            [] => self,
            [one] => self.seen_on_edge(one.clone()),
            _ => Self {
                edge_id: None,
                edge_share: false,
                edge_several: true,
                ..self
            },
        }
    }
    pub fn feed(mut self, id: impl Into<String>) -> Self {
        self.feed_id = Some(id.into());
        self
    }
    pub fn feed_provider(mut self, id: impl Into<String>) -> Self {
        self.feed_provider_id = Some(id.into());
        self
    }
    pub fn bundle(mut self, id: impl Into<String>) -> Self {
        self.bundle_id = Some(id.into());
        self
    }
}

/// An alert record (core.md §9).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Alert {
    pub id: i64,
    #[serde(rename = "type")]
    pub alert_type: AlertType,
    pub severity: Severity,
    pub kind: String,
    pub dedupe_key: String,
    pub title: String,
    /// Kind-specific detail, rendered as text only (core.md §12).
    pub details: Value,
    /// The edge the alert is about (an edge kind, or a per-edge key such as `wire_mismatch`'s), or
    /// the edge whose log records raised it (a device's or a name's security alert, core.md §9
    /// Grouping). Null when the alert has no edge (a feed, bundle or core alert), or when records
    /// from several edges raised it: those edges are then in `details` where the kind records
    /// them (`details.edges` of `dnssec_bogus` and `upstream_disagrees`).
    pub edge: Option<String>,
    pub feed_provider: Option<String>,
    pub feed: Option<String>,
    pub bundle: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub count: i64,
    pub state: AlertState,
}

/// One history row: every raise and resolve.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryEntry {
    pub at: String,
    /// `raised`, `reopened`, `repeated`, `resolved`.
    pub change: String,
    pub detail: Option<Value>,
}

/// Filters for listing (UI: type, severity, state, kind).
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct AlertFilter {
    #[serde(rename = "type")]
    pub alert_type: Option<AlertType>,
    pub severity: Option<Severity>,
    pub state: Option<AlertState>,
    pub kind: Option<String>,
    pub edge: Option<String>,
    /// Alerts about one bundle.
    pub bundle: Option<String>,
}

const ALERT_COLUMNS: &str = "id, type, severity, kind, dedupe_key, title, details_json, edge_id, feed_id, bundle_id, first_seen, last_seen, count, state, feed_provider_id";

fn row_to_alert(r: &rusqlite::Row<'_>) -> rusqlite::Result<Alert> {
    Ok(Alert {
        id: r.get(0)?,
        alert_type: p(r.get(1)?)?,
        severity: p(r.get(2)?)?,
        kind: r.get(3)?,
        dedupe_key: r.get(4)?,
        title: r.get(5)?,
        details: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or(Value::Null),
        edge: r.get(7)?,
        feed: r.get(8)?,
        bundle: r.get(9)?,
        first_seen: r.get(10)?,
        last_seen: r.get(11)?,
        count: r.get(12)?,
        state: p(r.get(13)?)?,
        feed_provider: r.get(14)?,
    })
}

/// New alerts per kind and in total (README §2, Bounded: each kind gets a capped share of the
/// table; an alert that doesn't fit is dropped and counted). Repeats of existing alerts always
/// count.
pub const MAX_PER_KIND: i64 = 10_000;
pub const MAX_TOTAL: i64 = 100_000;
/// New alerts of one kind about one edge (README §2, capped shares). An edge's alerts are keyed
/// by what it reports (activation targets, listeners, condition keys), so without a share one
/// edge could fill [`MAX_PER_KIND`] and suppress every other edge's alerts of that kind.
/// Resolved alerts count until they are deleted, as for the other caps. The spec gives no
/// number: a tenth of the kind's cap.
pub const MAX_PER_EDGE_KIND: i64 = 1_000;
/// History rows kept per alert: the first raise and the newest changes (`count` stays exact).
pub const MAX_HISTORY: usize = 1000;

/// Bounds on what one raise may store.
const MAX_TITLE: usize = 512;
const MAX_DETAILS: usize = 64 * 1024;
const MAX_KEY: usize = 1024;

/// The alerts engine.
#[derive(Clone)]
pub struct Alerts {
    db: Db,
    events: UiEvents,
    /// Dedupe keys of open alerts, so condition updates don't hit the database every heartbeat.
    open: Arc<Mutex<Option<HashSet<String>>>>,
    per_kind_cap: i64,
    total_cap: i64,
    per_edge_cap: i64,
    history_cap: usize,
    dropped: Arc<AtomicU64>,
    /// Called on the writer after a delete committed with the alerts' evidence (core.md §9):
    /// `logs::evidence` recounts its budget before its next admission.
    evidence_deleted: Arc<std::sync::OnceLock<EvidenceHook>>,
}

/// See [`Alerts::on_evidence_deleted`].
pub type EvidenceHook = Arc<dyn Fn() + Send + Sync>;

/// Alert changes made inside a caller's transaction, in order. After that transaction commits,
/// pass them to [`Alerts::committed`] (on the writer) and then [`Alerts::announce`]; if it rolls
/// back, drop them.
#[derive(Debug, Default)]
pub struct Changes {
    changed: Vec<Alert>,
    /// Kinds of new alerts dropped at a cap.
    dropped: Vec<String>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.dropped.is_empty()
    }

    /// Appends `other`'s changes (a later transaction's).
    pub fn extend(&mut self, other: Changes) {
        self.changed.extend(other.changed);
        self.dropped.extend(other.dropped);
    }
}

/// A spec checked and bounded for storage.
struct Prepared {
    title: String,
    details: String,
}

fn prepare(spec: &RaiseSpec) -> Option<Prepared> {
    if spec.dedupe_key.is_empty() || spec.dedupe_key.len() > MAX_KEY {
        return None;
    }
    let mut details = spec.details.clone();
    if serde_json::to_string(&details).map(|s| s.len()).unwrap_or(0) > MAX_DETAILS {
        details = serde_json::json!({"truncated": true});
    }
    Some(Prepared {
        title: crate::util::sanitize_for_message(&spec.title, MAX_TITLE),
        details: serde_json::to_string(&details).unwrap_or_else(|_| "null".into()),
    })
}

/// The `edge_id` and `several_edges` assignments of a repeat of `spec`'s alert (core.md §9 record
/// `edge?`), and whether they read `spec.edge_id`, bound at `param` (only then: SQLite refuses a
/// parameter the statement doesn't name). An alert about its edge (and a raise naming no
/// edge) keeps a known edge, or takes the first one named. A record-raised alert names its edge
/// while every raise came from that edge, and none from the first raise that came from another
/// or from several: `several_edges` keeps that, so a later raise from one edge doesn't name an
/// edge again.
fn edge_sets(spec: &RaiseSpec, param: &str) -> (String, bool) {
    let p = param;
    if spec.edge_several {
        ("edge_id = NULL, several_edges = 1".to_string(), false)
    } else if spec.edge_share || spec.edge_id.is_none() {
        let sets = format!("edge_id = CASE WHEN several_edges = 0 THEN coalesce(edge_id, {p}) END");
        (sets, true)
    } else {
        let same = format!("several_edges = 0 AND coalesce(edge_id, {p}) = {p}");
        let sets = format!(
            "edge_id = CASE WHEN {same} THEN {p} END, several_edges = CASE WHEN {same} THEN 0 ELSE 1 END"
        );
        (sets, true)
    }
}

impl Alerts {
    pub fn new(db: Db, events: UiEvents) -> Self {
        Self {
            db,
            events,
            open: Arc::new(Mutex::new(None)),
            per_kind_cap: MAX_PER_KIND,
            total_cap: MAX_TOTAL,
            per_edge_cap: MAX_PER_EDGE_KIND,
            history_cap: MAX_HISTORY,
            dropped: Arc::new(AtomicU64::new(0)),
            evidence_deleted: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Sets what runs (on the writer, right after the commit) when a delete removed alerts with
    /// their evidence; the first hook set stays.
    pub fn on_evidence_deleted(&self, hook: EvidenceHook) {
        let _ = self.evidence_deleted.set(hook);
    }

    /// The same engine with other caps on new alerts (tests).
    pub fn with_caps(mut self, per_kind: i64, total: i64) -> Self {
        self.per_kind_cap = per_kind;
        self.total_cap = total;
        self
    }

    /// The same engine with another per-edge share of each kind (tests).
    pub fn with_edge_cap(mut self, per_edge: i64) -> Self {
        self.per_edge_cap = per_edge;
        self
    }

    /// The same engine with another cap on history rows per alert (tests).
    pub fn with_history_cap(mut self, rows: usize) -> Self {
        self.history_cap = rows.max(2);
        self
    }

    /// New alerts dropped because their kind or the table was at its cap.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Forgets the open-alert cache after the alerts table was replaced (the config restore);
    /// call on the writer right after that commit, so the cache follows `alerts` in commit order.
    pub fn forget_open_set(&self) {
        if let Ok(mut g) = self.open.lock() {
            *g = None;
        }
    }

    /// The dedupe keys of open alerts. The cache is filled, and every later change to it made,
    /// on the writer thread right after the change commits, so it follows `alerts` in commit
    /// order: a raise and a resolve that race never leave it saying "open" for a resolved alert
    /// (or the reverse), which would suppress a condition's next raise (core.md §9).
    async fn open_set(&self) -> CoreResult<HashSet<String>> {
        if let Ok(g) = self.open.lock()
            && let Some(s) = g.as_ref()
        {
            return Ok(s.clone());
        }
        let open = self.open.clone();
        self.db
            .write(move |c| {
                let mut g = open
                    .lock()
                    .map_err(|_| CoreError::Other(anyhow::anyhow!("alert cache poisoned")))?;
                if let Some(s) = g.as_ref() {
                    return Ok(s.clone());
                }
                let mut st = c.prepare("SELECT dedupe_key FROM alerts WHERE state = 'open'")?;
                let keys = st
                    .query_map([], |r| r.get(0))?
                    .collect::<rusqlite::Result<HashSet<String>>>()?;
                *g = Some(keys.clone());
                Ok::<_, CoreError>(keys)
            })
            .await
    }

    /// Raises (or re-raises) an alert. Same `dedupe_key`: `count` + 1, `last_seen` now, state
    /// open; the title, severity and details take the latest values.
    pub async fn raise(&self, spec: RaiseSpec) -> CoreResult<Alert> {
        if prepare(&spec).is_none() {
            return Err(CoreError::Invalid(
                "an alert needs a dedupe key of at most 1024 bytes".into(),
            ));
        }
        let me = self.clone();
        let spec2 = spec.clone();
        let (alert, ch) = self
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let mut ch = Changes::default();
                let a = me.raise_in(&tx, &spec2, &mut ch)?;
                tx.commit()?;
                me.committed(&ch);
                Ok::<_, CoreError>((a, ch))
            })
            .await?;
        self.announce(ch);
        alert.ok_or_else(|| {
            CoreError::Conflict(format!(
                "alert {} dropped: too many alerts (at most {} per kind, {} per kind and edge, {} in total); delete some",
                spec.kind, self.per_kind_cap, self.per_edge_cap, self.total_cap
            ))
        })
    }

    /// [`Alerts::raise`] inside the caller's transaction `tx`. `Ok(None)` when the alert is new
    /// and its kind, its edge's share of the kind or the table is at its cap (dropped and
    /// counted), or its dedupe key is unusable.
    pub fn raise_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        spec: &RaiseSpec,
        ch: &mut Changes,
    ) -> rusqlite::Result<Option<Alert>> {
        let Some(prep) = prepare(spec) else {
            tracing::warn!(kind = %spec.kind, "alert with an unusable dedupe key ignored");
            return Ok(None);
        };
        let now = crate::util::now_ts();
        let existing: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, state FROM alerts WHERE dedupe_key = ?1",
                [&spec.dedupe_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (id, change) = match existing {
            Some((id, state)) => {
                let (sets, uses_edge) = edge_sets(spec, "?7");
                let (severity, occurrences) = (s(spec.severity), spec.occurrences.max(1));
                let mut args: Vec<&dyn rusqlite::ToSql> =
                    vec![&id, &now, &prep.title, &severity, &prep.details, &occurrences];
                if uses_edge {
                    args.push(&spec.edge_id);
                }
                tx.execute(
                    &format!(
                        "UPDATE alerts SET count = count + ?6, last_seen = ?2, state = 'open', title = ?3,
                            severity = ?4, details_json = ?5, {sets} WHERE id = ?1"
                    ),
                    args.as_slice(),
                )?;
                (id, if state == "open" { "repeated" } else { "reopened" })
            }
            None => {
                let (per_kind, total): (i64, i64) = tx.query_row(
                    "SELECT (SELECT count(*) FROM alerts WHERE kind = ?1), (SELECT count(*) FROM alerts)",
                    [&spec.kind],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let per_edge: i64 = match spec.edge_id.as_ref().filter(|_| spec.edge_share) {
                    Some(e) => tx.query_row(
                        "SELECT count(*) FROM alerts WHERE kind = ?1 AND edge_id = ?2",
                        params![spec.kind, e],
                        |r| r.get(0),
                    )?,
                    None => 0,
                };
                if per_kind >= self.per_kind_cap || total >= self.total_cap || per_edge >= self.per_edge_cap {
                    ch.dropped.push(spec.kind.clone());
                    return Ok(None);
                }
                tx.execute(
                    "INSERT INTO alerts(type, severity, kind, dedupe_key, title, details_json, edge_id, feed_id,
                        bundle_id, first_seen, last_seen, count, state, feed_provider_id, several_edges)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?12, 'open', ?11, ?13)",
                    params![
                        s(spec.alert_type),
                        s(spec.severity),
                        spec.kind,
                        spec.dedupe_key,
                        prep.title,
                        prep.details,
                        spec.edge_id,
                        spec.feed_id,
                        spec.bundle_id,
                        now,
                        spec.feed_provider_id,
                        spec.occurrences.max(1),
                        spec.edge_several
                    ],
                )?;
                (tx.last_insert_rowid(), "raised")
            }
        };
        tx.execute(
            "INSERT INTO alert_history(alert_id, at, change, detail_json) VALUES (?1, ?2, ?3, ?4)",
            params![id, now, change, prep.details],
        )?;
        trim_history(tx, id, self.history_cap)?;
        let a = tx.query_row(
            &format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1"),
            [id],
            row_to_alert,
        )?;
        ch.changed.push(a.clone());
        Ok(Some(a))
    }

    /// [`Alerts::resolve`] inside the caller's transaction `tx`.
    pub fn resolve_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        dedupe_key: &str,
        detail: Option<&Value>,
        ch: &mut Changes,
    ) -> rusqlite::Result<Option<Alert>> {
        let id: Option<i64> = tx
            .query_row(
                "SELECT id FROM alerts WHERE dedupe_key = ?1 AND state = 'open'",
                [dedupe_key],
                |r| r.get(0),
            )
            .optional()?;
        let Some(id) = id else { return Ok(None) };
        let a = resolve_in_tx(tx, id, detail)?;
        ch.changed.push(a.clone());
        Ok(Some(a))
    }

    /// True when the alert with `dedupe_key` is open, read in `tx`.
    pub fn is_open_in(tx: &rusqlite::Transaction<'_>, dedupe_key: &str) -> rusqlite::Result<bool> {
        Ok(tx
            .query_row(
                "SELECT 1 FROM alerts WHERE dedupe_key = ?1 AND state = 'open'",
                [dedupe_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// [`Alerts::condition`] inside the caller's transaction `tx` (the open state read there).
    pub fn condition_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        spec: &RaiseSpec,
        since: Option<Timestamp>,
        threshold: std::time::Duration,
        now: Timestamp,
        ch: &mut Changes,
    ) -> rusqlite::Result<bool> {
        let open = Self::is_open_in(tx, &spec.dedupe_key)?;
        match since {
            None => {
                if open {
                    self.resolve_in(
                        tx,
                        &spec.dedupe_key,
                        Some(&serde_json::json!({"cleared": crate::util::ts(&now)})),
                        ch,
                    )?;
                }
                Ok(false)
            }
            Some(since) => {
                let since = picket_api::time::clamp_to_now(since, now);
                let held = std::time::Duration::try_from(now - since).unwrap_or_default();
                if held >= threshold && !open {
                    Ok(self.raise_in(tx, spec, ch)?.is_some())
                } else {
                    Ok(open)
                }
            }
        }
    }

    /// Replaces an alert's details without raising it again (its count, state, `last_seen` and
    /// history stay), e.g. a record joining a `dnssec_bogus` alert's names (core.md §8); the
    /// change is announced like a raise. `seen_on` are the edges whose records the details now
    /// cover, applied as a raise's [`RaiseSpec::seen_on_edges`]. Details past the size bound are
    /// left as they are. Returns false when no alert has `dedupe_key`.
    pub fn update_details_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        dedupe_key: &str,
        details: &Value,
        seen_on: &[String],
        ch: &mut Changes,
    ) -> rusqlite::Result<bool> {
        let d = serde_json::to_string(details).unwrap_or_else(|_| "null".into());
        if d.len() > MAX_DETAILS {
            return Ok(false);
        }
        let seen = RaiseSpec::new("", Severity::Info, "", "", Value::Null).seen_on_edges(seen_on);
        let (sets, uses_edge) = edge_sets(&seen, "?3");
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&dedupe_key, &d];
        if uses_edge {
            args.push(&seen.edge_id);
        }
        let n = tx.execute(
            &format!("UPDATE alerts SET details_json = ?2, {sets} WHERE dedupe_key = ?1"),
            args.as_slice(),
        )?;
        if n == 0 {
            return Ok(false);
        }
        let a = tx.query_row(
            &format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE dedupe_key = ?1"),
            [dedupe_key],
            row_to_alert,
        )?;
        ch.changed.push(a);
        Ok(true)
    }

    /// Replaces an alert's title and details without raising it again (its count, state,
    /// `last_seen` and history stay), for a summary that follows a changing set (a grouped
    /// public-suffix warning's count and preview, #49); announced like a raise. Details past
    /// the size bound are left as they are. Returns false when no alert has `dedupe_key`.
    pub fn update_summary_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        dedupe_key: &str,
        title: &str,
        details: &Value,
        ch: &mut Changes,
    ) -> rusqlite::Result<bool> {
        let d = serde_json::to_string(details).unwrap_or_else(|_| "null".into());
        if d.len() > MAX_DETAILS {
            return Ok(false);
        }
        let title = crate::util::sanitize_for_message(title, MAX_TITLE);
        let n = tx.execute(
            "UPDATE alerts SET title = ?2, details_json = ?3 WHERE dedupe_key = ?1",
            params![dedupe_key, title, d],
        )?;
        if n == 0 {
            return Ok(false);
        }
        let a = tx.query_row(
            &format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE dedupe_key = ?1"),
            [dedupe_key],
            row_to_alert,
        )?;
        ch.changed.push(a);
        Ok(true)
    }

    /// Moves an open alert to another severity in place, without raising it again (its count,
    /// state, `last_seen` and history stay): its title becomes `title`, each key of `extra` is
    /// set in its details (a null removes the key), and a `reclassified` history row records the
    /// old and new severity. A rule whose severity policy changed keeps one alert (#67). Returns
    /// false when no alert with `dedupe_key` is open.
    pub fn reclassify_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        dedupe_key: &str,
        severity: Severity,
        title: &str,
        extra: &Value,
        ch: &mut Changes,
    ) -> rusqlite::Result<bool> {
        let row: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT id, severity, details_json FROM alerts WHERE dedupe_key = ?1 AND state = 'open'",
                [dedupe_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((id, from, details)) = row else {
            return Ok(false);
        };
        let mut d: Value = serde_json::from_str(&details).unwrap_or(Value::Null);
        if !d.is_object() {
            d = Value::Object(serde_json::Map::new());
        }
        if let (Some(o), Some(extra)) = (d.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                if v.is_null() {
                    o.remove(k);
                } else {
                    o.insert(k.clone(), v.clone());
                }
            }
        }
        let d = serde_json::to_string(&d).unwrap_or_else(|_| "null".into());
        let details = if d.len() > MAX_DETAILS { details } else { d };
        let title: String = title.chars().take(MAX_TITLE).collect();
        tx.execute(
            "UPDATE alerts SET severity = ?2, title = ?3, details_json = ?4 WHERE id = ?1",
            params![id, s(severity), title, details],
        )?;
        let note = serde_json::json!({"from": from, "to": s(severity)}).to_string();
        tx.execute(
            "INSERT INTO alert_history(alert_id, at, change, detail_json) VALUES (?1, ?2, 'reclassified', ?3)",
            params![id, crate::util::now_ts(), note],
        )?;
        trim_history(tx, id, self.history_cap)?;
        let a = tx.query_row(
            &format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1"),
            [id],
            row_to_alert,
        )?;
        ch.changed.push(a);
        Ok(true)
    }

    /// [`Alerts::note`] inside the caller's transaction `tx`.
    pub fn note_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        dedupe_key: &str,
        change: &str,
        detail: &Value,
    ) -> rusqlite::Result<bool> {
        let id: Option<i64> = tx
            .query_row("SELECT id FROM alerts WHERE dedupe_key = ?1", [dedupe_key], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(id) = id else { return Ok(false) };
        let d = serde_json::to_string(detail).unwrap_or_else(|_| "null".into());
        tx.execute(
            "INSERT INTO alert_history(alert_id, at, change, detail_json) VALUES (?1, ?2, ?3, ?4)",
            params![id, crate::util::now_ts(), change, d],
        )?;
        trim_history(tx, id, self.history_cap)?;
        Ok(true)
    }

    /// Brings the open-set cache up to date with changes that just committed, and notes them for
    /// the coalesced `alert` UI event. Call on the writer, right after the commit, so both follow
    /// `alerts` in commit order (module docs).
    pub fn committed(&self, ch: &Changes) {
        for a in &ch.changed {
            mark(&self.open, &a.dedupe_key, a.state == AlertState::Open);
            self.events
                .coalesced()
                .alert(crate::web::events::AlertEventItem::of(a));
        }
    }

    /// Notes the alerts whose evidence a transaction that just committed changed (records copied
    /// or counted by the backfill or live capture, `logs::evidence`; core.md §9 Evidence) for the
    /// coalesced `alert` UI event, each listed with its state now, so an open alert's view
    /// re-reads its evidence then (api.md §7). Reads at most `MAX_EVENT_ALERTS` of them (an event
    /// lists no more); the rest, and all of them when the read fails, count as unlisted
    /// (`alerts_truncated`). Call on the writer, right after the commit (as [`Alerts::committed`]).
    pub fn evidence_changed(&self, c: &rusqlite::Connection, touched: &crate::logs::evidence::Touched) {
        let ids = touched.ids();
        if ids.is_empty() {
            return;
        }
        let listed: Vec<i64> = ids
            .iter()
            .copied()
            .take(crate::web::events::MAX_EVENT_ALERTS)
            .collect();
        let read = (|| -> rusqlite::Result<Vec<crate::web::events::AlertEventItem>> {
            let mut st = c.prepare_cached(&format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1"))?;
            let mut out = Vec::new();
            for id in &listed {
                if let Some(a) = st.query_row([id], row_to_alert).optional()? {
                    out.push(crate::web::events::AlertEventItem::of(&a));
                }
            }
            Ok(out)
        })();
        let co = self.events.coalesced();
        match read {
            Ok(items) => {
                for it in items {
                    co.alert(it);
                }
                co.alerts_unlisted((ids.len() - listed.len()) as u64);
            }
            Err(e) => {
                tracing::debug!(error = %e, "cannot read the alerts whose evidence changed");
                co.alerts_unlisted(ids.len() as u64);
            }
        }
    }

    /// Logs committed changes (noted for the UI by [`Alerts::committed`]), and counts the dropped
    /// ones.
    pub fn announce(&self, ch: Changes) {
        for kind in &ch.dropped {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(kind = %kind, "alert dropped: its kind, its edge's share or the alert table is at its cap");
        }
        for a in ch.changed {
            match a.state {
                AlertState::Open => {
                    tracing::info!(kind = %a.kind, id = a.id, count = a.count, "alert raised")
                }
                AlertState::Resolved => tracing::info!(kind = %a.kind, id = a.id, "alert resolved"),
            }
        }
    }

    /// Resolves the open alert with `dedupe_key`; returns it, or `None` when none was open.
    pub async fn resolve(&self, dedupe_key: &str, detail: Option<Value>) -> CoreResult<Option<Alert>> {
        let key = dedupe_key.to_string();
        let me = self.clone();
        let (out, ch) = self
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let mut ch = Changes::default();
                let a = me.resolve_in(&tx, &key, detail.as_ref(), &mut ch)?;
                tx.commit()?;
                me.committed(&ch);
                Ok::<_, CoreError>((a, ch))
            })
            .await?;
        self.announce(ch);
        Ok(out)
    }

    /// Appends a history row to the alert with `dedupe_key`, if there is one, changing nothing
    /// else: an edge's condition changes go into its alert's history (core.md §9), while the
    /// alert itself is raised and resolved only from the snapshots.
    pub async fn note(&self, dedupe_key: &str, change: &str, detail: Value) -> CoreResult<bool> {
        let (key, change) = (dedupe_key.to_string(), change.to_string());
        let me = self.clone();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                let noted = me.note_in(&tx, &key, &change, &detail)?;
                tx.commit()?;
                Ok::<_, CoreError>(noted)
            })
            .await
    }

    /// Resolves by id (the UI's "resolve"; one-off alerts resolve by hand). An alert already
    /// resolved is noted for the UI all the same (its tabs re-read it).
    pub async fn resolve_id(&self, id: i64) -> CoreResult<Alert> {
        let open = self.open.clone();
        let events = self.events.clone();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                let state: Option<String> = tx
                    .query_row("SELECT state FROM alerts WHERE id = ?1", [id], |r| r.get(0))
                    .optional()?;
                let a = match state.as_deref() {
                    None => return Err(CoreError::NotFound(format!("no alert {id}"))),
                    Some("open") => resolve_in_tx(&tx, id, Some(&serde_json::json!({"by": "hand"})))?,
                    Some(_) => tx.query_row(
                        &format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1"),
                        [id],
                        row_to_alert,
                    )?,
                };
                tx.commit()?;
                // On the writer, right after the commit (module docs).
                mark(&open, &a.dedupe_key, false);
                events
                    .coalesced()
                    .alert(crate::web::events::AlertEventItem::of(&a));
                Ok(a)
            })
            .await
    }

    /// Feeds a condition's state: `since` is when it started holding (from the edge or the
    /// check), `None` when it doesn't hold. Raises once it has held for the kind's threshold,
    /// resolves when it clears. Returns whether the alert is open afterwards.
    pub async fn condition(
        &self,
        spec: RaiseSpec,
        since: Option<Timestamp>,
        threshold: std::time::Duration,
        now: Timestamp,
    ) -> CoreResult<bool> {
        let open = self.open_set().await?.contains(&spec.dedupe_key);
        match since {
            None => {
                if open {
                    self.resolve(
                        &spec.dedupe_key,
                        Some(serde_json::json!({"cleared": crate::util::ts(&now)})),
                    )
                    .await?;
                }
                Ok(false)
            }
            Some(since) => {
                let since = picket_api::time::clamp_to_now(since, now);
                let held = std::time::Duration::try_from(now - since).unwrap_or_default();
                if held >= threshold && !open {
                    self.raise(spec).await?;
                    Ok(true)
                } else {
                    Ok(open)
                }
            }
        }
    }

    pub async fn get(&self, id: i64) -> CoreResult<(Alert, Vec<HistoryEntry>)> {
        self.db
            .read(move |c| {
                let a = c
                    .query_row(&format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1"), [id], row_to_alert)
                    .optional()?
                    .ok_or_else(|| CoreError::NotFound(format!("no alert {id}")))?;
                let mut st = c.prepare("SELECT at, change, detail_json FROM alert_history WHERE alert_id = ?1 ORDER BY id LIMIT 1000")?;
                let h = st
                    .query_map([id], |r| {
                        Ok(HistoryEntry {
                            at: r.get(0)?,
                            change: r.get(1)?,
                            detail: r.get::<_, Option<String>>(2)?.and_then(|s| serde_json::from_str(&s).ok()),
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, CoreError>((a, h))
            })
            .await
    }

    pub async fn get_by_key(&self, dedupe_key: &str) -> CoreResult<Option<Alert>> {
        let key = dedupe_key.to_string();
        self.db
            .read(move |c| {
                Ok::<_, CoreError>(
                    c.query_row(
                        &format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE dedupe_key = ?1"),
                        [key],
                        row_to_alert,
                    )
                    .optional()?,
                )
            })
            .await
    }

    /// Lists alerts newest first (`last_seen`, then id), after the cursor.
    pub async fn list(
        &self,
        f: AlertFilter,
        after: Option<(String, i64)>,
        limit: usize,
    ) -> CoreResult<Vec<Alert>> {
        self.db
            .read(move |c| {
                let mut sql = format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE 1 = 1");
                let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
                if let Some(t) = f.alert_type {
                    args.push(Box::new(s(t)));
                    sql.push_str(&format!(" AND type = ?{}", args.len()));
                }
                if let Some(v) = f.severity {
                    args.push(Box::new(s(v)));
                    sql.push_str(&format!(" AND severity = ?{}", args.len()));
                }
                if let Some(v) = f.state {
                    args.push(Box::new(s(v)));
                    sql.push_str(&format!(" AND state = ?{}", args.len()));
                }
                if let Some(v) = f.kind {
                    args.push(Box::new(v));
                    sql.push_str(&format!(" AND kind = ?{}", args.len()));
                }
                if let Some(v) = f.edge {
                    args.push(Box::new(v));
                    sql.push_str(&format!(" AND edge_id = ?{}", args.len()));
                }
                if let Some(v) = f.bundle {
                    args.push(Box::new(v));
                    sql.push_str(&format!(" AND bundle_id = ?{}", args.len()));
                }
                if let Some((ls, id)) = after {
                    args.push(Box::new(ls));
                    let a = args.len();
                    args.push(Box::new(id));
                    let b = args.len();
                    sql.push_str(&format!(
                        " AND (last_seen < ?{a} OR (last_seen = ?{a} AND id < ?{b}))"
                    ));
                }
                args.push(Box::new(limit));
                sql.push_str(&format!(
                    " ORDER BY last_seen DESC, id DESC LIMIT ?{}",
                    args.len()
                ));
                let mut st = c.prepare(&sql)?;
                let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
                let v = st
                    .query_map(refs.as_slice(), row_to_alert)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, CoreError>(v)
            })
            .await
    }

    /// Deletes alerts with their history and evidence (single or bulk; both UI endpoints) in one
    /// transaction. The evidence rule goes in it too, and capture reads rules inside each of its
    /// transactions, so nothing is copied or counted for a deleted alert afterwards; ids are
    /// never reused (AUTOINCREMENT), so no later alert inherits anything. Returns how many.
    pub async fn delete(&self, ids: Vec<i64>) -> CoreResult<usize> {
        if ids.len() > 10_000 {
            return Err(CoreError::Invalid("delete at most 10000 alerts at once".into()));
        }
        let open = self.open.clone();
        let hook = self.evidence_deleted.clone();
        let events = self.events.clone();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                // Each deleted alert's key, kind and count (its `alert` event item).
                let mut keys = Vec::new();
                for id in &ids {
                    if let Some((k, kind, count)) = tx
                        .query_row(
                            "SELECT dedupe_key, kind, count FROM alerts WHERE id = ?1",
                            [id],
                            |r| {
                                Ok((
                                    r.get::<_, String>(0)?,
                                    r.get::<_, String>(1)?,
                                    r.get::<_, i64>(2)?,
                                ))
                            },
                        )
                        .optional()?
                    {
                        keys.push((*id, k, kind, count));
                    }
                    for t in [
                        "alert_history",
                        "alert_evidence",
                        "alert_evidence_counts",
                        "wire_examples",
                        "alert_evidence_answers",
                        "alert_evidence_rules",
                    ] {
                        tx.execute(&format!("DELETE FROM {t} WHERE alert_id = ?1"), [id])?;
                    }
                    tx.execute("DELETE FROM alerts WHERE id = ?1", [id])?;
                }
                tx.commit()?;
                // On the writer, right after the commit (module docs). Coalesced
                // (`web::events`): a bulk delete of thousands sends one event, not one each.
                for (id, k, kind, count) in &keys {
                    mark(&open, k, false);
                    events
                        .coalesced()
                        .alert(crate::web::events::AlertEventItem::deleted(
                            *id,
                            kind.clone(),
                            *count,
                        ));
                }
                if !keys.is_empty()
                    && let Some(hook) = hook.get()
                {
                    hook();
                }
                Ok::<_, CoreError>(keys.len())
            })
            .await
    }
}

/// Updates the open-set cache (when loaded); called on the writer after a commit.
fn mark(open: &Mutex<Option<HashSet<String>>>, key: &str, is_open: bool) {
    if let Ok(mut g) = open.lock()
        && let Some(s) = g.as_mut()
    {
        if is_open {
            s.insert(key.to_string());
        } else {
            s.remove(key);
        }
    }
}

/// Keeps an alert's history within `cap` rows: its first row (the raise) and the newest ones.
fn trim_history(tx: &rusqlite::Transaction<'_>, id: i64, cap: usize) -> rusqlite::Result<()> {
    let n: i64 = tx.query_row(
        "SELECT count(*) FROM alert_history WHERE alert_id = ?1",
        [id],
        |r| r.get(0),
    )?;
    if usize::try_from(n).unwrap_or(usize::MAX) <= cap {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM alert_history WHERE alert_id = ?1
           AND id > (SELECT min(id) FROM alert_history WHERE alert_id = ?1)
           AND id NOT IN (SELECT id FROM alert_history WHERE alert_id = ?1 ORDER BY id DESC LIMIT ?2)",
        params![id, i64::try_from(cap.saturating_sub(1)).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

fn resolve_in_tx(tx: &rusqlite::Transaction<'_>, id: i64, detail: Option<&Value>) -> rusqlite::Result<Alert> {
    let now = crate::util::now_ts();
    tx.execute("UPDATE alerts SET state = 'resolved' WHERE id = ?1", [id])?;
    tx.execute(
        "INSERT INTO alert_history(alert_id, at, change, detail_json) VALUES (?1, ?2, 'resolved', ?3)",
        params![id, now, detail.map(|d| d.to_string())],
    )?;
    trim_history(tx, id, MAX_HISTORY)?;
    tx.query_row(
        &format!("SELECT {ALERT_COLUMNS} FROM alerts WHERE id = ?1"),
        [id],
        row_to_alert,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> (
        tempfile::TempDir,
        Alerts,
        tokio::sync::broadcast::Receiver<crate::state::UiEvent>,
    ) {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let db = Db::open(opts).unwrap();
        let events = UiEvents::new();
        let rx = events.subscribe();
        (d, Alerts::new(db, events), rx)
    }

    #[tokio::test]
    async fn dedupe_reopen_history() {
        use crate::web::events::{AlertEvent, AlertEventItem};
        let (_d, a, mut rx) = engine();
        let spec = RaiseSpec::new(
            "feed_held",
            Severity::Warning,
            "feed_held:x",
            "Feed x held",
            serde_json::json!({"n": 1}),
        )
        .feed("x");
        let first = a.raise(spec.clone()).await.unwrap();
        assert_eq!(first.count, 1);
        assert_eq!(first.alert_type, AlertType::Operational);
        let second = a.raise(spec.clone()).await.unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(second.count, 2);
        let resolved = a.resolve("feed_held:x", None).await.unwrap().unwrap();
        assert_eq!(resolved.state, AlertState::Resolved);
        assert!(a.resolve("feed_held:x", None).await.unwrap().is_none());
        let third = a.raise(spec).await.unwrap();
        assert_eq!(third.state, AlertState::Open);
        assert_eq!(third.count, 3);
        let (_, hist) = a.get(first.id).await.unwrap();
        let changes: Vec<&str> = hist.iter().map(|h| h.change.as_str()).collect();
        assert_eq!(changes, vec!["raised", "repeated", "resolved", "reopened"]);
        // The UI's `alert` event (api.md §7) lists the alert once, as it stands after its four
        // changes (a resolve of nothing open changes nothing); it goes out coalesced, never
        // straight on the bus.
        assert_eq!(
            a.events.coalesced().take().alert,
            Some(AlertEvent {
                alerts: vec![AlertEventItem::of(&third)],
                alerts_truncated: false,
                changes: 4,
            })
        );
        let n = a.delete(vec![first.id]).await.unwrap();
        assert_eq!(n, 1);
        assert!(a.get(first.id).await.is_err());
        let ev = a.events.coalesced().take().alert.unwrap();
        assert_eq!(
            ev.alerts,
            vec![AlertEventItem::deleted(first.id, "feed_held".into(), 3)]
        );
        assert!(rx.try_recv().is_err(), "nothing sent one by one");
    }

    /// K1 (core.md §2 "It looks atomic to the user"; api.md §7): alert changes are noted for the
    /// UI on the writer, right after their commit (so notes follow commit order, and a restore's
    /// commit splits them exactly): a raise by [`Alerts::committed`] in the caller's write, a
    /// delete before its write returns (here: when the evidence hook runs on the writer).
    #[tokio::test]
    async fn changes_are_noted_on_the_writer_right_after_their_commit() {
        use crate::web::events::AlertEventItem;
        let (_d, a, _rx) = engine();
        let spec =
            RaiseSpec::new("feed_held", Severity::Warning, "feed_held:w", "held", Value::Null).feed("w");
        let me = a.clone();
        let (raised, noted) =
            a.db.write(move |c| {
                let tx = c.transaction()?;
                let mut ch = Changes::default();
                let raised = me.raise_in(&tx, &spec, &mut ch)?.unwrap();
                tx.commit()?;
                me.committed(&ch);
                Ok::<_, CoreError>((raised, me.events.coalesced().take().alert))
            })
            .await
            .unwrap();
        assert_eq!(noted.unwrap().alerts, vec![AlertEventItem::of(&raised)]);
        let seen = Arc::new(Mutex::new(None));
        let (s2, ev) = (seen.clone(), a.events.clone());
        a.on_evidence_deleted(Arc::new(move || {
            *s2.lock().unwrap() = ev.coalesced().take().alert;
        }));
        assert_eq!(a.delete(vec![raised.id]).await.unwrap(), 1);
        let noted = seen
            .lock()
            .unwrap()
            .take()
            .expect("noted before the writer's hook");
        assert_eq!(
            noted.alerts,
            vec![AlertEventItem::deleted(raised.id, "feed_held".into(), 1)]
        );
    }

    /// api.md §7, README §2 Bounded: a bulk delete (or any burst of changes) is noted for the
    /// coalesced `alert` event, never sent one event per alert: the event lists at most
    /// MAX_EVENT_ALERTS of them and counts every change.
    #[tokio::test]
    async fn a_bulk_delete_is_one_bounded_alert_event() {
        use crate::web::events::MAX_EVENT_ALERTS;
        let (_d, a, mut rx) = engine();
        let n = MAX_EVENT_ALERTS + 36;
        let mut ids = Vec::new();
        for i in 0..n {
            let spec = RaiseSpec::new(
                "feed_held",
                Severity::Warning,
                format!("feed_held:f{i}"),
                "held",
                Value::Null,
            )
            .feed(format!("f{i}"));
            ids.push(a.raise(spec).await.unwrap().id);
        }
        let raised = a.events.coalesced().take().alert.unwrap();
        assert_eq!(raised.changes, n as u64);
        assert_eq!(raised.alerts.len(), MAX_EVENT_ALERTS);
        assert!(raised.alerts_truncated);
        assert_eq!(a.delete(ids.clone()).await.unwrap(), n);
        let deleted = a.events.coalesced().take().alert.unwrap();
        assert_eq!(deleted.changes, n as u64);
        assert!(deleted.alerts_truncated);
        assert_eq!(
            deleted.alerts.iter().map(|x| x.id).collect::<Vec<_>>(),
            ids[..MAX_EVENT_ALERTS],
            "the first changed, each once"
        );
        assert!(
            deleted
                .alerts
                .iter()
                .all(|x| x.deleted && x.state.is_none() && x.kind == "feed_held" && x.count == 1)
        );
        assert!(rx.try_recv().is_err(), "nothing sent one by one");
    }

    #[tokio::test]
    async fn thresholds() {
        let (_d, a, _rx) = engine();
        let now = Timestamp::now();
        let spec = RaiseSpec::new(
            "edge_upstream_down",
            Severity::Warning,
            "edge_upstream_down:e1:cloudflare",
            "down",
            Value::Null,
        )
        .edge("e1");
        let th = std::time::Duration::from_secs(120);
        // Held 1 min: not yet.
        assert!(
            !a.condition(
                spec.clone(),
                Some(now - jiff::SignedDuration::from_secs(60)),
                th,
                now
            )
            .await
            .unwrap()
        );
        assert!(a.get_by_key(&spec.dedupe_key).await.unwrap().is_none());
        // Held 3 min: raised once, not again.
        assert!(
            a.condition(
                spec.clone(),
                Some(now - jiff::SignedDuration::from_secs(180)),
                th,
                now
            )
            .await
            .unwrap()
        );
        assert!(
            a.condition(
                spec.clone(),
                Some(now - jiff::SignedDuration::from_secs(200)),
                th,
                now
            )
            .await
            .unwrap()
        );
        assert_eq!(a.get_by_key(&spec.dedupe_key).await.unwrap().unwrap().count, 1);
        // A `since` in the future is clamped to now.
        // Cleared: resolved.
        assert!(!a.condition(spec.clone(), None, th, now).await.unwrap());
        assert_eq!(
            a.get_by_key(&spec.dedupe_key).await.unwrap().unwrap().state,
            AlertState::Resolved
        );
    }

    #[tokio::test]
    async fn listing_and_filters() {
        let (_d, a, _rx) = engine();
        for i in 0..5 {
            a.raise(RaiseSpec::new(
                "ui_auth_failures",
                Severity::Warning,
                format!("k{i}"),
                "t",
                Value::Null,
            ))
            .await
            .unwrap();
        }
        a.raise(RaiseSpec::new(
            "feed_held",
            Severity::Warning,
            "f",
            "t",
            Value::Null,
        ))
        .await
        .unwrap();
        let sec = a
            .list(
                AlertFilter {
                    alert_type: Some(AlertType::Security),
                    ..Default::default()
                },
                None,
                3,
            )
            .await
            .unwrap();
        assert_eq!(sec.len(), 3);
        let last = sec.last().unwrap();
        let rest = a
            .list(
                AlertFilter {
                    alert_type: Some(AlertType::Security),
                    ..Default::default()
                },
                Some((last.last_seen.clone(), last.id)),
                10,
            )
            .await
            .unwrap();
        assert_eq!(rest.len(), 2);
        assert!(rest.iter().all(|x| !sec.iter().any(|y| y.id == x.id)));
    }

    #[tokio::test]
    async fn new_alerts_are_capped_per_kind_and_in_total() {
        // README §2, Bounded: clients sharing a capped resource (alerts) each get a capped share;
        // an item that doesn't fit is dropped and counted.
        let (_d, a, _rx) = engine();
        let a = a.with_caps(3, 5);
        let spec = |kind: &str, key: String| RaiseSpec::new(kind, Severity::Warning, key, "t", Value::Null);
        for i in 0..3 {
            a.raise(spec("category_blocked", format!("cb:{i}")))
                .await
                .unwrap();
        }
        assert!(a.raise(spec("category_blocked", "cb:3".into())).await.is_err());
        assert_eq!(a.dropped(), 1);
        // An existing alert still counts its repeats at the cap.
        assert_eq!(
            a.raise(spec("category_blocked", "cb:0".into()))
                .await
                .unwrap()
                .count,
            2
        );
        // Another kind has its own share, until the total cap.
        a.raise(spec("feed_held", "fh:0".into())).await.unwrap();
        a.raise(spec("feed_held", "fh:1".into())).await.unwrap();
        assert!(a.raise(spec("bundle_warning", "bw:0".into())).await.is_err());
        assert_eq!(a.dropped(), 2);
        // Deleting makes room again.
        let id = a.get_by_key("cb:1").await.unwrap().unwrap().id;
        a.delete(vec![id]).await.unwrap();
        a.raise(spec("category_blocked", "cb:3".into())).await.unwrap();
    }

    #[tokio::test]
    async fn one_edge_cannot_take_another_edges_share_of_a_kind() {
        // README §2 capped shares (review A7): an edge's alerts are keyed by what it reports, so
        // one edge reporting many distinct keys must not suppress another edge's alerts.
        let (_d, a, _rx) = engine();
        let a = a.with_caps(10, 100).with_edge_cap(3);
        let spec = |edge: &str, i: usize| {
            RaiseSpec::new(
                "edge_activation_failed",
                Severity::Warning,
                format!("edge_activation_failed:{edge}:t{i}"),
                "t",
                Value::Null,
            )
            .edge(edge)
        };
        for i in 0..3 {
            a.raise(spec("e1", i)).await.unwrap();
        }
        assert!(a.raise(spec("e1", 3)).await.is_err(), "e1 is at its share");
        assert_eq!(a.dropped(), 1);
        a.raise(spec("e2", 0)).await.unwrap();
        // Repeats of an existing alert always count.
        assert_eq!(a.raise(spec("e1", 0)).await.unwrap().count, 2);
    }

    #[tokio::test]
    async fn an_alert_seen_on_several_edges_names_none() {
        // core.md §9 record `edge?`: a record-raised alert names the edge its records came from;
        // once they came from two edges it names none, and later raises from one edge don't give
        // it one (review Q7: `coalesce(edge_id, ?)` kept the first edge, or took one later).
        let (_d, a, _rx) = engine();
        let spec = |key: &str| RaiseSpec::new("category_blocked", Severity::Warning, key, "t", Value::Null);
        assert_eq!(
            a.raise(spec("k1").seen_on_edge("e1"))
                .await
                .unwrap()
                .edge
                .as_deref(),
            Some("e1")
        );
        assert_eq!(
            a.raise(spec("k1").seen_on_edge("e1"))
                .await
                .unwrap()
                .edge
                .as_deref(),
            Some("e1")
        );
        assert_eq!(a.raise(spec("k1").seen_on_edge("e2")).await.unwrap().edge, None);
        assert_eq!(a.raise(spec("k1").seen_on_edge("e1")).await.unwrap().edge, None);
        // A raise that knows no edge changes nothing.
        assert_eq!(a.raise(spec("k1")).await.unwrap().edge, None);
        assert_eq!(
            a.raise(spec("k2").seen_on_edge("e1"))
                .await
                .unwrap()
                .edge
                .as_deref(),
            Some("e1")
        );
        assert_eq!(a.raise(spec("k2")).await.unwrap().edge.as_deref(), Some("e1"));
        // Details that now cover several edges' records (a dnssec_bogus name from another edge).
        let me = a.clone();
        a.db.write(move |c| {
            let tx = c.transaction()?;
            let mut ch = Changes::default();
            let edges = ["e1".to_string(), "e2".to_string()];
            assert!(me.update_details_in(&tx, "k2", &Value::Null, &edges, &mut ch)?);
            tx.commit()?;
            Ok::<_, CoreError>(())
        })
        .await
        .unwrap();
        assert_eq!(a.raise(spec("k2").seen_on_edge("e1")).await.unwrap().edge, None);
        assert_eq!(
            a.raise(spec("k4").seen_on_edges(&["e1".into(), "e2".into()]))
                .await
                .unwrap()
                .edge,
            None
        );
        assert_eq!(a.raise(spec("k4").seen_on_edge("e1")).await.unwrap().edge, None);
        // An alert raised before any edge was known takes the first one named.
        assert_eq!(a.raise(spec("k3")).await.unwrap().edge, None);
        assert_eq!(
            a.raise(spec("k3").seen_on_edge("e3"))
                .await
                .unwrap()
                .edge
                .as_deref(),
            Some("e3")
        );
        // An alert about its edge keeps it.
        let about = || RaiseSpec::new("edge_panic", Severity::Warning, "edge_panic:e1", "t", Value::Null);
        assert_eq!(
            a.raise(about().edge("e1")).await.unwrap().edge.as_deref(),
            Some("e1")
        );
        assert_eq!(a.raise(about()).await.unwrap().edge.as_deref(), Some("e1"));
    }

    #[tokio::test]
    async fn changes_in_a_rolled_back_transaction_leave_nothing() {
        // review A6: alert effects commit with what caused them, or not at all.
        let (_d, a, _rx) = engine();
        let spec =
            RaiseSpec::new("edge_panic", Severity::Warning, "edge_panic:e1", "t", Value::Null).edge("e1");
        let me = a.clone();
        let s2 = spec.clone();
        a.db.write(move |c| {
            let tx = c.transaction()?;
            let mut ch = Changes::default();
            assert!(me.raise_in(&tx, &s2, &mut ch)?.is_some());
            drop(tx); // rolled back
            Ok::<_, CoreError>(())
        })
        .await
        .unwrap();
        assert!(a.get_by_key(&spec.dedupe_key).await.unwrap().is_none());
        let me = a.clone();
        let s2 = spec.clone();
        let ch =
            a.db.write(move |c| {
                let tx = c.transaction()?;
                let mut ch = Changes::default();
                me.raise_in(&tx, &s2, &mut ch)?;
                tx.commit()?;
                me.committed(&ch);
                Ok::<_, CoreError>(ch)
            })
            .await
            .unwrap();
        assert!(!ch.is_empty());
        a.announce(ch);
        assert!(a.get_by_key(&spec.dedupe_key).await.unwrap().is_some());
        assert!(a.open_set().await.unwrap().contains(&spec.dedupe_key));
    }

    #[tokio::test]
    async fn history_stays_bounded_for_a_busy_alert() {
        let (_d, a, _rx) = engine();
        let a = a.with_history_cap(10);
        let spec = RaiseSpec::new("category_blocked", Severity::Warning, "busy", "t", Value::Null);
        for _ in 0..30 {
            a.raise(spec.clone()).await.unwrap();
        }
        let alert = a.get_by_key("busy").await.unwrap().unwrap();
        assert_eq!(alert.count, 30, "count stays exact");
        let (_, hist) = a.get(alert.id).await.unwrap();
        assert_eq!(hist.len(), 10);
        assert_eq!(hist[0].change, "raised", "the first raise is kept");
    }

    #[tokio::test]
    async fn a_raise_and_a_resolve_that_race_leave_the_condition_cache_right() {
        // core.md §9: a condition alert resolves when its condition clears and is raised again
        // when it holds again. The open-set cache must follow commit order, whatever order the
        // callers resume in, or the next raise is suppressed.
        use std::future::Future;
        use std::task::{Context, Poll};
        let (_d, a, _rx) = engine();
        let now = Timestamp::now();
        let th = std::time::Duration::from_secs(60);
        let spec = RaiseSpec::new(
            "edge_memory_low",
            Severity::Warning,
            "edge_memory_low:e1",
            "low",
            Value::Null,
        )
        .edge("e1");
        // Load the cache.
        assert!(!a.condition(spec.clone(), None, th, now).await.unwrap());
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut raise = std::pin::pin!(a.raise(spec.clone()));
        assert!(raise.as_mut().poll(&mut cx).is_pending());
        let mut resolve = std::pin::pin!(a.resolve(&spec.dedupe_key, None));
        assert!(resolve.as_mut().poll(&mut cx).is_pending());
        // Both committed: raised, then resolved.
        assert!(a.db.ping(std::time::Duration::from_secs(5)).await);
        // The resolve's caller resumes first, the raise's last.
        assert!(
            std::future::poll_fn(|cx| match resolve.as_mut().poll(cx) {
                Poll::Ready(r) => Poll::Ready(r),
                Poll::Pending => Poll::Pending,
            })
            .await
            .unwrap()
            .is_some()
        );
        std::future::poll_fn(|cx| raise.as_mut().poll(cx)).await.unwrap();
        assert_eq!(
            a.get_by_key(&spec.dedupe_key).await.unwrap().unwrap().state,
            AlertState::Resolved
        );
        // The condition holds again: it is raised again.
        assert!(
            a.condition(
                spec.clone(),
                Some(now - jiff::SignedDuration::from_secs(120)),
                th,
                now
            )
            .await
            .unwrap()
        );
        assert_eq!(
            a.get_by_key(&spec.dedupe_key).await.unwrap().unwrap().state,
            AlertState::Open
        );
    }

    #[test]
    fn kinds_have_types() {
        assert!(is_known_kind("edge_offline"));
        assert!(!is_known_kind("nope"));
        assert_eq!(
            RaiseSpec::new("dnssec_bogus", Severity::Critical, "k", "t", Value::Null).alert_type,
            AlertType::Security
        );
    }
}
