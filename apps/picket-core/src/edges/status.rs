//! What edges report, and what core makes of it (api.md §3, core.md §4, §9, §10).
//!
//! - **`hello`:** the edge's release (`edge_boots`: the release each boot reported, so records
//!   name the release that logged them), architecture and firmware (the release offer, the
//!   firmware check), `allowed_binds` (flagged listeners), `have`, `applied`, `update` and its
//!   conditions. A hello counting more than 3 starts since the last session, or more than 3 new
//!   boots in 10 min, raises `edge_crash_loop`.
//! - **An edge that can't start a session** (#69: e.g. it refuses to run with a helper speaking
//!   another protocol, exiting before its hello, and systemd restarting it) sends core nothing:
//!   no hello, so no `edge_crash_loop` during the outage; what core shows then is `edge_offline`
//!   (no heartbeat for 5 min, below). The edge's reason waits in its spool (the
//!   `helper_protocol_mismatch` event) and reaches core with the first batch a compatible start
//!   ships: after the updater rolls a failed update back (with `update_failed` at `readiness`),
//!   or a repaired install. That start's hello counts the starts since the last session, so the
//!   refused ones can raise `edge_crash_loop` then.
//! - **`heartbeat`:** `edge_status` (last seen, versions and the versions before them,
//!   conditions, the heartbeat), metrics (`metrics.db`), convergence (`edge_named`: the first
//!   heartbeat showing each named version active; `convergence_lag_s`), pins (`have`), request
//!   acknowledgements (`applied`), the update record (`update`), and alerts.
//! - Each report is stored in one writer transaction together with its alert effects (update
//!   outcome, conditions, `edge_offline`, activations, `edge_crash_loop`,
//!   `upstream_invalid_spike`), so alerts follow the reports in commit order and a crash never
//!   separates them (core.md §9; README §2 Restarts). The edge's live copy is updated right after
//!   that commit, inside the writer. A report from a session a newer one replaced, or from a key
//!   no longer registered for the edge (checked in the transaction; api.md §1 Key change),
//!   changes nothing and ends the session.
//! - **Rates** (README §2, Bounded): a heartbeat is stored at most once per
//!   [`crate::edges::hub::HEARTBEAT_STORE_EVERY`], counted from the arrival of the last stored
//!   one (not its commit); one arriving sooner only updates the live copy.
//! - **Conditions → alerts** (core.md §9): a condition raises its alert once it has held for the
//!   kind's threshold; every hello and stored heartbeat resolves each of the edge's open
//!   condition alerts its list doesn't carry (whatever the previous report said); while the edge
//!   is offline its conditions stay as last stored (and keep counting towards their thresholds);
//!   a lost session clears nothing.
//! - **The watcher** (every 15 s): `edge_offline` (no heartbeat for 5 min, counted from core's
//!   start at the earliest; offline after 90 s), thresholds of held conditions (decided on the
//!   writer against the stored snapshot, so a heartbeat that cleared one first wins),
//!   `edge_crash_loop` resolving after 10 min with no new boot (decided in the resolving
//!   transaction, so a hello that commits first wins),
//!   `edge_fw_repairs` (more than 10 `rules_repaired` in 1 h), `edge_firmware_unsupported`
//!   against the current minimum, `edge_listener_rejected` resolving when the listener no
//!   longer asks that edge for the bind, and `edge_tls_version_refused` resolving after a day
//!   without a new refusal ([`TLS_REFUSED_QUIET`]; raised in `logs::ingest`).

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::Timestamp;
use picket_api::logs::{BundleVersion, Versions, event_kind};
use picket_api::session::{Condition, Heartbeat, Hello, UpdateOutcome};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::alerts::{AlertFilter, AlertState, Alerts, Changes, RaiseSpec, Severity};
use crate::edges::hub::{EdgeLive, HelloInfo, Registered, SessionInfo, UpdateRecord};
use crate::error::{CoreError, CoreResult};
use crate::state::{AppState, SharedState};

/// How often the watcher runs.
pub const WATCH_EVERY: Duration = Duration::from_secs(15);
/// `edge_crash_loop`: more than this many new boots (or starts in a hello) …
pub const CRASH_LOOP_BOOTS: i64 = 3;
/// … within this window; it resolves after this long with no new boot.
pub const CRASH_LOOP_WINDOW: Duration = Duration::from_secs(600);
/// `edge_fw_repairs`: more than this many `rules_repaired` events in an hour.
pub const FW_REPAIRS_PER_HOUR: i64 = 10;
/// `edge_tls_version_refused` resolves after this long without a new `tls_version_refused` event
/// for it. The edge logs a refused client at most once an hour while it keeps trying, so a day
/// without one means it stopped: updated, pointed elsewhere or gone. A day rather than a few
/// hours, so a device that tries once a day doesn't flap between open and resolved (policy
/// choice: the spec gives no number).
pub const TLS_REFUSED_QUIET: Duration = Duration::from_secs(24 * 3600);
/// `upstream_invalid_spike`: invalid upstream answers above this share of misses.
pub const INVALID_SPIKE_SHARE: f64 = 0.01;

// ---------------------------------------------------------------------------------------------
// Conditions → alerts

/// The alert a condition kind raises (core.md §9), with its severity; `None` for a kind this
/// release doesn't know (kept for display, raises nothing).
pub fn condition_alert(kind: &str) -> Option<(&'static str, Severity)> {
    use picket_api::session::condition_kind as c;
    Some(match kind {
        c::UPSTREAM_DOWN => ("edge_upstream_down", Severity::Warning),
        c::REDIRECT_MISSING => ("edge_redirect_missing", Severity::Critical),
        c::HELPER_UNREACHABLE => ("edge_helper_unreachable", Severity::Warning),
        c::UNIFI_CONFLICT => ("edge_unifi_conflict", Severity::Warning),
        c::LISTENER_FAILED => ("edge_listener_failed", Severity::Warning),
        c::SSD_UNAVAILABLE => ("edge_ssd_unavailable", Severity::Warning),
        c::MEMORY_LOW => ("edge_memory_low", Severity::Warning),
        c::FW_SET_FULL => ("edge_fw_set_full", Severity::Warning),
        c::SPOOL_EVICTING => ("edge_spool_evicting", Severity::Warning),
        c::HELPER_DISABLED => ("edge_helper_disabled", Severity::Critical),
        c::FW_LAYOUT_UNKNOWN => ("edge_fw_layout_unknown", Severity::Warning),
        c::FW_CATCH_ALL => ("edge_fw_catch_all", Severity::Critical),
        c::FW_DRIFT => ("edge_fw_drift", Severity::Warning),
        c::FIRMWARE_CHECK_FAILED => ("edge_firmware_check_failed", Severity::Warning),
        _ => return None,
    })
}

/// The dedupe key of a condition's alert: one per edge, kind and key.
pub fn condition_key(alert_kind: &str, edge: &str, key: Option<&str>) -> String {
    match key {
        Some(k) => format!("{alert_kind}:{edge}:{k}"),
        None => format!("{alert_kind}:{edge}"),
    }
}

fn condition_title(c: &Condition, name: &str) -> String {
    let key = c.key.as_deref().unwrap_or("");
    let what = match c.kind.as_str() {
        "upstream_down" => format!("every upstream of group {key} is down"),
        "redirect_missing" => {
            format!("the port-53 redirect is missing for {key}; monitor and off networks are unfiltered")
        }
        "helper_unreachable" => "picket-edge-helper is unreachable".into(),
        "unifi_conflict" => format!("a UniFi setting conflicts with Picket ({key})"),
        "listener_failed" => format!("listener {key} failed"),
        "ssd_unavailable" => "the SSD is unavailable".into(),
        "memory_low" => "memory is low".into(),
        "fw_set_full" => format!("firewall set {key} is nearly full"),
        "spool_evicting" => "the log spool is evicting records".into(),
        "helper_disabled" => "Picket's firewall rules are disabled (picket-edge-helper disable)".into(),
        "fw_layout_unknown" => format!("no place for the firewall check on {key}"),
        "fw_catch_all" => format!("{key}'s catch-all isn't a Block All policy with action Reject"),
        "fw_drift" => "kernel firewall entries differ from the edge's own".into(),
        "firmware_check_failed" => "the self-check after a firmware change failed".into(),
        other => other.to_string(),
    };
    format!("Edge {name}: {what}")
}

/// Steps for the admin, where the alert gives them (core.md §9).
fn condition_steps(
    c: &Condition,
    edge: Option<&crate::config::model::EdgeDef>,
    model: Option<&crate::config::Model>,
) -> Option<String> {
    match c.kind.as_str() {
        "redirect_missing" => {
            let family = c.key.as_deref().unwrap_or("ipv4");
            let nets = edge
                .and_then(|e| e.settings.unifi.redirect.as_ref())
                .map(|r| r.interfaces.join(", "))
                .unwrap_or_default();
            let port = model
                .zip(edge)
                .and_then(|(m, e)| {
                    m.listeners
                        .values()
                        .filter(|l| {
                            l.edges.contains(&e.id) && l.proto == picket_api::edge_config::ListenerProto::Dns
                        })
                        .find_map(|l| l.bind.parse::<SocketAddr>().ok().map(|a| a.port()))
                })
                .map(|p| p.to_string())
                .unwrap_or_else(|| "the dns listener's port".into());
            Some(format!(
                "Monitor and off networks are unfiltered until the rule is back. In the UniFi Network app: \
                 Settings → Policy Table → add a Destination NAT rule for each redirected network ({nets}), \
                 TCP and UDP port 53 → the gateway's own {family} address on that network, port {port}."
            ))
        }
        "fw_catch_all" => Some(format!(
            "Add a Block All policy with action Reject for every connection state as the catch-all of \
             {}'s zone → External chain in the UniFi Network app.",
            c.key.as_deref().unwrap_or("the network")
        )),
        _ => None,
    }
}

/// Every alert kind an edge condition raises (core.md §9).
pub const CONDITION_ALERT_KINDS: &[&str] = &[
    "edge_upstream_down",
    "edge_redirect_missing",
    "edge_helper_unreachable",
    "edge_unifi_conflict",
    "edge_listener_failed",
    "edge_ssd_unavailable",
    "edge_memory_low",
    "edge_fw_set_full",
    "edge_spool_evicting",
    "edge_helper_disabled",
    "edge_fw_layout_unknown",
    "edge_fw_catch_all",
    "edge_fw_drift",
    "edge_firmware_check_failed",
];

/// A held condition's alert: what to raise once it has held for `threshold` since `since`.
#[derive(Clone, Debug)]
pub struct ConditionAlert {
    pub spec: RaiseSpec,
    pub kind: String,
    pub key: Option<String>,
    pub since: Timestamp,
    pub threshold: Duration,
}

/// The alerts of a condition snapshot, built before the writer transaction (the model only for
/// the conditions whose alert gives steps; README §2: no full reads per heartbeat otherwise).
pub async fn condition_alerts(state: &AppState, edge: &str, list: &[Condition]) -> Vec<ConditionAlert> {
    let needs_model = list
        .iter()
        .any(|c| c.kind == picket_api::session::condition_kind::REDIRECT_MISSING);
    let model = if needs_model {
        state.config.model().await.ok()
    } else {
        None
    };
    let def = model.as_ref().and_then(|m| m.edges.get(edge));
    let name = state.edges.hub.name_of(edge).unwrap_or_else(|| edge.to_string());
    let settings = state.settings();
    let mut out = Vec::new();
    for c in list {
        let Some((kind, severity)) = condition_alert(&c.kind) else {
            continue;
        };
        let mut details = json!({"edge": edge, "condition": c.kind, "key": c.key, "since": crate::util::ts(&c.since), "detail": c.detail});
        if let Some(steps) = condition_steps(c, def, model.as_ref()) {
            details["steps"] = Value::String(steps);
        }
        let spec = RaiseSpec::new(
            kind,
            severity,
            condition_key(kind, edge, c.key.as_deref()),
            condition_title(c, &name),
            details,
        )
        .edge(edge);
        out.push(ConditionAlert {
            spec,
            kind: c.kind.clone(),
            key: c.key.clone(),
            since: c.since,
            threshold: settings.alerts.threshold(kind),
        });
    }
    out
}

/// Applies a condition snapshot (a hello or a stored heartbeat) in `tx`: each held condition
/// raises once past its threshold, and each open condition alert of the edge that `list`
/// doesn't carry resolves (core.md §9). Resolving against the open alerts, not against the
/// previous report, also clears an alert raised late by the watcher.
fn apply_snapshot_in(
    alerts: &Alerts,
    tx: &Transaction<'_>,
    edge: &str,
    specs: &[ConditionAlert],
    list: &[Condition],
    now: Timestamp,
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    for a in specs {
        alerts.condition_in(tx, &a.spec, Some(a.since), a.threshold, now, ch)?;
    }
    let carried: std::collections::HashSet<String> = list
        .iter()
        .filter_map(|c| condition_alert(&c.kind).map(|(k, _)| condition_key(k, edge, c.key.as_deref())))
        .collect();
    let kinds = serde_json::to_string(CONDITION_ALERT_KINDS).unwrap_or_else(|_| "[]".into());
    let open: Vec<String> = {
        let mut st = tx.prepare_cached(
            "SELECT dedupe_key FROM alerts WHERE edge_id = ?1 AND state = 'open'
               AND kind IN (SELECT value FROM json_each(?2))",
        )?;
        st.query_map(params![edge, kinds], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let cleared = json!({"cleared": crate::util::ts(&now)});
    for key in open.iter().filter(|k| !carried.contains(*k)) {
        alerts.resolve_in(tx, key, Some(&cleared), ch)?;
    }
    Ok(())
}

/// True while `fingerprint` is `edge`'s registered key, read in `tx`: a report from a key
/// replaced, or an edge deleted, by a commit before this one changes nothing (api.md §1).
pub(crate) fn key_holds(tx: &Transaction<'_>, edge: &str, fingerprint: &str) -> rusqlite::Result<bool> {
    Ok(tx
        .query_row(
            "SELECT 1 FROM edges WHERE id = ?1 AND key_sha256 = ?2",
            params![edge, fingerprint],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

// ---------------------------------------------------------------------------------------------
// Update outcomes (core.md §9 One-off events)

/// Replaces the edge's update record with `candidate` when its `at` is later and its
/// `result_id` differs; returns the new record then. Anything else has no alert effect.
pub fn reconcile_update(
    tx: &Transaction<'_>,
    edge: &str,
    candidate: UpdateRecord,
) -> rusqlite::Result<Option<UpdateRecord>> {
    let current: Option<UpdateRecord> = tx
        .query_row(
            "SELECT update_result_json FROM edge_status WHERE edge_id = ?1",
            [edge],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok());
    if let Some(cur) = &current {
        if cur.result_id == candidate.result_id {
            return Ok(None);
        }
        let (a, b) = (
            crate::util::parse_ts(&cur.at),
            crate::util::parse_ts(&candidate.at),
        );
        if !matches!((a, b), (Some(a), Some(b)) if b > a) {
            return Ok(None);
        }
    }
    let json = serde_json::to_string(&candidate).unwrap_or_default();
    tx.execute(
        "INSERT INTO edge_status(edge_id, update_result_json) VALUES (?1, ?2)
         ON CONFLICT(edge_id) DO UPDATE SET update_result_json = excluded.update_result_json",
        params![edge, json],
    )?;
    Ok(Some(candidate))
}

/// The update record a hello or heartbeat `update` stands for.
pub fn update_record(u: &UpdateOutcome, now: Timestamp) -> UpdateRecord {
    UpdateRecord {
        result_id: u.result_id.clone(),
        outcome: match u.outcome {
            picket_api::session::Outcome::Ok => "ok".into(),
            picket_api::session::Outcome::Failed => "failed".into(),
        },
        version: u.version.clone(),
        at: crate::util::ts(&picket_api::time::clamp_to_now(u.at, now)),
        stage: None,
    }
}

/// Raises or resolves `edge_update_failed` in `tx`, the transaction that changed the edge's
/// update record (core.md §9).
pub fn update_alert_in(
    alerts: &Alerts,
    tx: &Transaction<'_>,
    edge: &str,
    rec: &UpdateRecord,
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    let key = format!("edge_update_failed:{edge}");
    if rec.outcome == "failed" {
        let spec = RaiseSpec::new(
            "edge_update_failed",
            Severity::Warning,
            key,
            format!("Edge {edge}: the update to {} failed", crate::util::sanitize_for_message(&rec.version, 64)),
            json!({"edge": edge, "result_id": rec.result_id, "version": rec.version, "stage": rec.stage, "at": rec.at}),
        )
        .edge(edge);
        alerts.raise_in(tx, &spec, ch)?;
    } else {
        alerts.resolve_in(
            tx,
            &key,
            Some(&json!({"result_id": rec.result_id, "version": rec.version})),
            ch,
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Firmware (edge-unifi.md §1)

/// `(target, version)` from `/usr/lib/version`'s first line: the target is the first field, the
/// version the `vX.Y.Z` field (`UCGF.ipq9574.v6.0.17.…` is `UCGF`, `6.0.17`).
pub fn parse_firmware(s: &str) -> Option<(String, Vec<u64>)> {
    let s = s.trim();
    let fields: Vec<&str> = s.split('.').collect();
    let target = fields
        .first()
        .filter(|t| !t.is_empty() && t.len() <= 32)?
        .to_string();
    for (i, f) in fields.iter().enumerate().skip(1) {
        if let Some(major) = f.strip_prefix('v').and_then(|m| m.parse::<u64>().ok()) {
            let minor = fields.get(i + 1)?.parse::<u64>().ok()?;
            let patch: String = fields
                .get(i + 2)?
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            let patch = patch.parse::<u64>().ok()?;
            return Some((target, vec![major, minor, patch]));
        }
    }
    None
}

/// Why a UniFi edge's firmware is unsupported, or `None` when it is fine (core.md §9: below the
/// minimum for its target, a target with no minimum, or unreadable; never for a newer version).
pub fn firmware_problem(firmware: Option<&str>, mins: &[crate::settings::FirmwareMin]) -> Option<String> {
    let Some(fw) = firmware else {
        return Some("the firmware version can't be read".into());
    };
    let Some((target, version)) = parse_firmware(fw) else {
        return Some("the firmware version can't be read as a version".into());
    };
    let Some(min) = mins.iter().find(|m| m.target == target) else {
        return Some(format!("there is no minimum firmware for target {target}"));
    };
    let min_v = crate::settings::parse_firmware_version(&min.min)?;
    (version < min_v).then(|| format!("below the minimum {} for {target}", min.min))
}

async fn firmware_check(state: &AppState, edge: &crate::config::model::EdgeDef, hello: Option<&HelloInfo>) {
    if edge.platform != picket_api::edge_config::Platform::Unifi {
        return;
    }
    let Some(h) = hello else { return };
    let mins = state.settings().edges.effective_min_firmware();
    let problem = firmware_problem(h.firmware.as_deref(), &mins);
    let fw = h.firmware.clone().unwrap_or_default();
    let spec = RaiseSpec::new(
        "edge_firmware_unsupported",
        Severity::Warning,
        format!("edge_firmware_unsupported:{}", edge.id),
        format!(
            "Edge {}: UniFi OS {} is not supported",
            edge.name,
            crate::util::sanitize_for_message(&fw, 128)
        ),
        json!({"edge": edge.id, "firmware": h.firmware, "problem": problem}),
    )
    .edge(&edge.id);
    let since = problem.as_ref().map(|_| Timestamp::now());
    let _ = state
        .alerts
        .condition(spec, since, Duration::ZERO, Timestamp::now())
        .await;
}

// ---------------------------------------------------------------------------------------------
// Session reports

/// Upserts `edge_status` fields for `edge`.
fn upsert_status(
    tx: &Transaction<'_>,
    edge: &str,
    cols: &[(&str, &dyn rusqlite::ToSql)],
) -> rusqlite::Result<()> {
    let names: Vec<&str> = cols.iter().map(|(c, _)| *c).collect();
    let marks: Vec<String> = (2..cols.len() + 2).map(|i| format!("?{i}")).collect();
    let sets: Vec<String> = names.iter().map(|c| format!("{c} = excluded.{c}")).collect();
    let sql = format!(
        "INSERT INTO edge_status(edge_id, {}) VALUES (?1, {}) ON CONFLICT(edge_id) DO UPDATE SET {}",
        names.join(", "),
        marks.join(", "),
        sets.join(", ")
    );
    let mut params: Vec<&dyn rusqlite::ToSql> = vec![&edge];
    params.extend(cols.iter().map(|(_, v)| *v));
    tx.execute(&sql, params.as_slice())?;
    Ok(())
}

fn clamp_conditions(list: &mut [Condition], now: Timestamp) {
    for c in list.iter_mut() {
        c.since = picket_api::time::clamp_to_now(c.since, now);
    }
}

/// What a stored report changed that needs work outside the transaction.
#[derive(Default)]
struct Effects {
    update: Option<UpdateRecord>,
    rerender: bool,
    /// Revokes the edge acknowledged in this report.
    acked: crate::edges::requests::Acked,
    lags: BTreeMap<String, f64>,
    new_boot: bool,
    recent_boots: i64,
}

/// Processes a `hello` from session `sid`. Returns false when the session is no longer the
/// edge's (replaced, or its key no longer registered).
pub async fn on_hello(
    state: &SharedState,
    edge: &Registered,
    sid: u64,
    addr: SocketAddr,
    mut hello: Hello,
) -> CoreResult<bool> {
    let now = Timestamp::now();
    let now_s = crate::util::ts(&now);
    clamp_conditions(&mut hello.conditions, now);
    let prev = state.edges.hub.live(&edge.id);
    let info = HelloInfo::from_hello(
        &hello,
        prev.hello.as_ref(),
        &now_s,
        Some(crate::net::canonical_addr(addr).to_string()),
    );
    let running_changed = prev
        .hello
        .as_ref()
        .is_none_or(|p| p.edge_version != info.edge_version || p.arch != info.arch);
    let specs = condition_alerts(state, &edge.id, &hello.conditions).await;
    let hub = state.edges.hub.clone();
    let alerts = state.alerts.clone();
    let coalesced = state.events.coalesced().clone();
    let (edge_id, edge_name, fp) = (edge.id.clone(), edge.name.clone(), edge.fingerprint.clone());
    let (h, inf) = (hello.clone(), info.clone());
    let window_start =
        crate::util::ts(&(now - jiff::SignedDuration::try_from(CRASH_LOOP_WINDOW).unwrap_or_default()));
    let out = state
        .db
        .write(move |c| {
            if !hub.is_current(&edge_id, sid) {
                return Ok::<_, CoreError>(None);
            }
            let tx = c.transaction()?;
            if !key_holds(&tx, &edge_id, &fp)? {
                return Ok(None);
            }
            let mut fx = Effects::default();
            let known: Option<Option<String>> = tx
                .query_row(
                    "SELECT edge_version FROM edge_boots WHERE edge_id = ?1 AND boot = ?2",
                    params![edge_id, h.boot],
                    |r| r.get(0),
                )
                .optional()?;
            fx.new_boot = !matches!(known, Some(Some(_)));
            // The hello's boot is current (a boot first seen in spooled records may have been
            // registered as superseded); every other boot is superseded now.
            tx.execute(
                "INSERT INTO edge_boots(edge_id, boot, edge_version, first_seen) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(edge_id, boot) DO UPDATE SET edge_version = excluded.edge_version, superseded_at = NULL",
                params![edge_id, h.boot, h.edge_version, now_s],
            )?;
            tx.execute(
                "UPDATE edge_boots SET superseded_at = ?3 WHERE edge_id = ?1 AND boot <> ?2 AND superseded_at IS NULL",
                params![edge_id, h.boot, now_s],
            )?;
            fx.recent_boots = tx.query_row(
                "SELECT count(*) FROM edge_boots WHERE edge_id = ?1 AND edge_version IS NOT NULL AND first_seen >= ?2",
                params![edge_id, window_start],
                |r| r.get(0),
            )?;
            let hello_json = serde_json::to_string(&inf).unwrap_or_default();
            let conditions = serde_json::to_string(&h.conditions).unwrap_or_default();
            let addr = inf.addr.clone();
            upsert_status(
                &tx,
                &edge_id,
                &[
                    ("last_seen", &now_s),
                    ("hello_json", &hello_json),
                    ("conditions_json", &conditions),
                    ("session_addr", &addr),
                ],
            )?;
            if let Some(u) = &h.update {
                fx.update = reconcile_update(&tx, &edge_id, update_record(u, now))?;
            }
            fx.acked = crate::edges::requests::ack_revoke_list(&tx, &edge_id, h.applied.revoked_allows.as_deref())?;
            fx.rerender = fx.acked.changed;
            crate::edges::publish::end_pins(&tx, &edge_id, &h.have, &now_s)?;
            fx.lags = converge(&tx, &edge_id, None, &h.have, now)?;
            // Alert effects, in this transaction (core.md §9).
            let mut ch = Changes::default();
            if let Some(u) = &fx.update {
                update_alert_in(&alerts, &tx, &edge_id, u, &mut ch)?;
            }
            apply_snapshot_in(&alerts, &tx, &edge_id, &specs, &h.conditions, now, &mut ch)?;
            alerts.resolve_in(
                &tx,
                &format!("edge_offline:{edge_id}"),
                Some(&json!({"by": "hello"})),
                &mut ch,
            )?;
            // core.md §9 edge_crash_loop: more than 3 starts since the last session, or more
            // than 3 new boots in 10 min.
            if h.starts as i64 > CRASH_LOOP_BOOTS || (fx.new_boot && fx.recent_boots > CRASH_LOOP_BOOTS) {
                let spec = RaiseSpec::new(
                    "edge_crash_loop",
                    Severity::Critical,
                    format!("edge_crash_loop:{edge_id}"),
                    format!("Edge {edge_name} keeps restarting"),
                    json!({"edge": edge_id, "starts": h.starts, "boots_in_10_min": fx.recent_boots}),
                )
                .edge(&edge_id);
                alerts.raise_in(&tx, &spec, &mut ch)?;
            }
            tx.commit()?;
            alerts.committed(&ch);
            revoke_acked_event(&coalesced, &edge_id, fx.acked);
            let update = fx.update.clone();
            hub.update_live(&edge_id, move |l| {
                l.hello = Some(inf);
                l.last_seen = Some(now);
                l.last_seen_mono = Some(tokio::time::Instant::now());
                l.conditions = h.conditions.clone();
                l.applied = h.applied.clone();
                l.have = h.have.clone();
                if update.is_some() {
                    l.update = update;
                }
            });
            Ok(Some((fx, ch)))
        })
        .await?;
    let Some((fx, ch)) = out else { return Ok(false) };
    state.alerts.announce(ch);
    if running_changed || fx.rerender {
        state.edges.publisher.trigger(Some(&edge.id));
    }
    if let Ok(m) = state.config.model_of(crate::config::EntityKind::Edge).await
        && let Some(def) = m.edges.get(&edge.id)
    {
        firmware_check(state, def, Some(&info)).await;
    }
    store_lags(state, &edge.id, &fx.lags).await;
    served_roots(state, &edge.id, sid, &hello.cert_roots, true).await;
    edge_status_event(state, &edge.id, "hello");
    Ok(true)
}

/// Stores the roots of the certificates the edge's managed listeners serve (`cert_roots`, api.md
/// §3): core keeps trusting a previous LAN CA root until they are all the current one (core.md
/// §11, `lanca::rotation`). A failure is retried with the next report.
async fn served_roots(
    state: &SharedState,
    edge: &str,
    sid: u64,
    roots: &BTreeMap<String, String>,
    hello: bool,
) {
    if let Err(e) = crate::lanca::rotation::record_served(state, edge, sid, roots, hello).await {
        tracing::warn!(edge = %edge, error = %e, "cannot store the roots of the edge's listener certificates");
    }
}

/// An `edge_status` UI event (api.md §7; `web::events::EdgeStatusEvent`).
pub fn edge_status_event(state: &SharedState, edge: &str, event: &str) {
    let ev = crate::web::events::EdgeStatusEvent {
        edge: edge.to_string(),
        event: event.to_string(),
    };
    if let Ok(data) = serde_json::to_value(ev) {
        state.events.send("edge_status", data);
    }
}

/// Notes a `temp_allow` UI event for revokes an edge acknowledged (api.md §7; coalesced). On the
/// writer, right after the commit that stored them (`web::events` module docs).
fn revoke_acked_event(
    coalesced: &crate::web::events::Coalesced,
    edge: &str,
    acked: crate::edges::requests::Acked,
) {
    if acked.allows > 0 {
        coalesced.temp_allow(
            edge,
            crate::web::events::AllowChange::RevokeAcked(acked.allows as u64),
        );
    }
}

/// Processes a heartbeat from session `sid`, whose hello reported `boot`. Returns false when
/// the session is no longer the edge's (replaced, or its key no longer registered).
pub async fn on_heartbeat(
    state: &SharedState,
    edge: &Registered,
    sid: u64,
    boot: &str,
    mut hb: Heartbeat,
) -> CoreResult<bool> {
    // The storage interval runs from arrival (api.md §3), however long the writer takes.
    let arrived = tokio::time::Instant::now();
    if hb.boot != boot {
        tracing::warn!(edge = %edge.id, "a heartbeat with another boot than its session's hello; ignored");
        return Ok(true);
    }
    let now = Timestamp::now();
    let now_s = crate::util::ts(&now);
    hb.ts = picket_api::time::clamp_to_now(hb.ts, now);
    clamp_conditions(&mut hb.conditions, now);
    let hub = state.edges.hub.clone();
    let hb = Arc::new(hb);
    if !hub.heartbeat_due(&edge.id) {
        // README §2, Bounded: sooner than the interval after the last stored one, a heartbeat
        // only updates the live copy; the next one after the interval is stored (its running
        // totals cover this one's time, api.md §3).
        if !hub.is_current(&edge.id, sid) || !hub.pins(&edge.id, &edge.fingerprint) {
            return Ok(false);
        }
        hub.update_live(&edge.id, |l| {
            l.heartbeat = Some(hb.clone());
            l.heartbeat_at = Some(now);
            l.last_seen = Some(now);
            l.last_seen_mono = Some(tokio::time::Instant::now());
            l.conditions = hb.conditions.clone();
            l.applied = hb.applied.clone();
            l.have = hb.have.clone();
            l.versions = hb.versions.clone();
        });
        served_roots(state, &edge.id, sid, &hb.cert_roots, false).await;
        return Ok(true);
    }
    let prev = hub.live(&edge.id);
    let specs = condition_alerts(state, &edge.id, &hb.conditions).await;
    let spike = spike_decision(state, &edge.id, prev.heartbeat.as_deref(), &hb);
    let alerts = state.alerts.clone();
    let coalesced = state.events.coalesced().clone();
    let (edge_id, fp) = (edge.id.clone(), edge.fingerprint.clone());
    let hb2 = hb.clone();
    let out = state
        .db
        .write(move |c| {
            if !hub.is_current(&edge_id, sid) {
                return Ok::<_, CoreError>(None);
            }
            let tx = c.transaction()?;
            if !key_holds(&tx, &edge_id, &fp)? {
                return Ok(None);
            }
            let mut fx = Effects::default();
            let stored: Option<Option<String>> = tx
                .query_row(
                    "SELECT versions_json FROM edge_status WHERE edge_id = ?1",
                    [&edge_id],
                    |r| r.get(0),
                )
                .optional()?;
            let versions = hb2.versions.as_ref().and_then(|v| serde_json::to_string(v).ok());
            let conditions = serde_json::to_string(&hb2.conditions).unwrap_or_default();
            let heartbeat = serde_json::to_string(&*hb2).unwrap_or_default();
            upsert_status(
                &tx,
                &edge_id,
                &[
                    ("last_seen", &now_s),
                    ("versions_json", &versions),
                    ("conditions_json", &conditions),
                    ("heartbeat_json", &heartbeat),
                ],
            )?;
            if let Some(Some(old)) = stored
                && versions.as_deref().is_some_and(|v| v != old)
            {
                tx.execute(
                    "UPDATE edge_status SET previous_versions_json = ?2 WHERE edge_id = ?1",
                    params![edge_id, old],
                )?;
            }
            if let Some(u) = &hb2.update {
                fx.update = reconcile_update(&tx, &edge_id, update_record(u, now))?;
            }
            fx.acked = crate::edges::requests::ack_revoke_list(
                &tx,
                &edge_id,
                hb2.applied.revoked_allows.as_deref(),
            )?;
            fx.rerender = fx.acked.changed;
            crate::edges::publish::end_pins(&tx, &edge_id, &hb2.have, &now_s)?;
            fx.lags = converge(&tx, &edge_id, hb2.versions.as_ref(), &hb2.have, now)?;
            // Alert effects, in this transaction (core.md §9).
            let mut ch = Changes::default();
            if let Some(u) = &fx.update {
                update_alert_in(&alerts, &tx, &edge_id, u, &mut ch)?;
            }
            apply_snapshot_in(&alerts, &tx, &edge_id, &specs, &hb2.conditions, now, &mut ch)?;
            alerts.resolve_in(
                &tx,
                &format!("edge_offline:{edge_id}"),
                Some(&json!({"by": "heartbeat"})),
                &mut ch,
            )?;
            if let Some(v) = &hb2.versions {
                resolve_activations_in(&alerts, &tx, &edge_id, v, &mut ch)?;
            }
            if let Some((spec, since, threshold)) = &spike {
                alerts.condition_in(&tx, spec, *since, *threshold, now, &mut ch)?;
            }
            tx.commit()?;
            alerts.committed(&ch);
            revoke_acked_event(&coalesced, &edge_id, fx.acked);
            let update = fx.update.clone();
            hub.update_live(&edge_id, move |l| {
                l.heartbeat = Some(hb2.clone());
                l.heartbeat_at = Some(now);
                l.last_seen = Some(now);
                l.last_seen_mono = Some(tokio::time::Instant::now());
                l.conditions = hb2.conditions.clone();
                l.applied = hb2.applied.clone();
                l.have = hb2.have.clone();
                l.versions = hb2.versions.clone();
                if update.is_some() {
                    l.update = update;
                }
            });
            hub.heartbeat_stored(&edge_id, arrived);
            Ok(Some((fx, ch)))
        })
        .await?;
    let Some((fx, ch)) = out else { return Ok(false) };
    state.alerts.announce(ch);
    if fx.rerender {
        state.edges.publisher.trigger(Some(&edge.id));
    }
    // Metrics: stored as received (core.md §10).
    let ts_ms = hb.ts.as_millisecond();
    match crate::metrics::store::store_heartbeat(&state.metrics_db, &state.metrics, &edge.id, ts_ms, &hb)
        .await
    {
        Ok(0) => {}
        Ok(n) => {
            tracing::warn!(edge = %edge.id, dropped = n, "heartbeat values over the edge's series share were dropped")
        }
        Err(e) => tracing::warn!(edge = %edge.id, error = %e, "cannot store heartbeat metrics"),
    }
    store_lags(state, &edge.id, &fx.lags).await;
    fw_drift_gauges(state, &edge.id, &hb.conditions).await;
    served_roots(state, &edge.id, sid, &hb.cert_roots, false).await;
    edge_status_event(state, &edge.id, "heartbeat");
    Ok(true)
}

/// True when the config an edge reports (`versions.config`, a short or full id) is the named
/// config object without its runtime fields: an edge keeps reporting the id a config was first
/// stored under while only `bundles`, `verdict_sets`, `release`, `flush` or `revoked_allows`
/// change (edge.md §2, §13; `EdgeConfig::without_runtime_fields`), so a config object that
/// changed only its bundle heads is active once the edge runs that config.
fn same_config(tx: &Transaction<'_>, edge: &str, named: &str, reported: &str) -> rusqlite::Result<bool> {
    if reported.len() < 16 || !reported.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(false);
    }
    let body = |sql: &str, arg: &str| -> rusqlite::Result<Option<picket_api::EdgeConfig>> {
        let s: Option<String> = tx.query_row(sql, params![arg, edge], |r| r.get(0)).optional()?;
        Ok(s.and_then(|s| serde_json::from_str::<picket_api::EdgeConfig>(&s).ok()))
    };
    let Some(a) = body(
        "SELECT body_json FROM edge_configs WHERE config_id = ?1 AND edge_id = ?2",
        named,
    )?
    else {
        return Ok(false);
    };
    let Some(b) = body(
        "SELECT body_json FROM edge_configs WHERE substr(config_id, 1, length(?1)) = ?1 AND edge_id = ?2 LIMIT 1",
        reported,
    )?
    else {
        return Ok(false);
    };
    Ok(a.without_runtime_fields() == b.without_runtime_fields())
}

/// Marks the named versions a report shows active (`edge_named.active_at`) and returns, per
/// kind, `convergence_lag_s`: the largest lag of the versions core names now, a pending one
/// counting with its age so far (core.md §10).
fn converge(
    tx: &Transaction<'_>,
    edge: &str,
    versions: Option<&Versions>,
    have: &picket_api::session::Have,
    now: Timestamp,
) -> rusqlite::Result<BTreeMap<String, f64>> {
    let rows: Vec<(String, String, String, String, Option<String>)> = {
        let mut st =
            tx.prepare("SELECT kind, target, id, named_at, active_at FROM edge_named WHERE edge_id = ?1")?;
        st.query_map([edge], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    let now_s = crate::util::ts(&now);
    let mut lags: BTreeMap<String, f64> = BTreeMap::new();
    for (kind, target, id, named_at, active_at) in rows {
        let short = picket_api::ids::short_id(&id);
        let active_now = active_at.is_some() || match kind.as_str() {
            "config" => versions.is_some_and(|v| {
                v.config == short || v.config == id || same_config(tx, edge, &id, &v.config).unwrap_or(false)
            }),
            "bundle" => versions.is_some_and(
                |v| matches!(v.bundles.get(&target), Some(BundleVersion::Plain(h)) if h == short || *h == id),
            ),
            // A verdict set is active when it is the first head `have` lists for its provider.
            "verdict_set" => have.verdict_sets.get(&target).and_then(|l| l.first()) == Some(&id),
            _ => false,
        };
        let active_at = match active_at {
            Some(a) => Some(a),
            None if active_now => {
                tx.execute(
                    "UPDATE edge_named SET active_at = ?4 WHERE edge_id = ?1 AND kind = ?2 AND target = ?3",
                    params![edge, kind, target, now_s],
                )?;
                Some(now_s.clone())
            }
            None => None,
        };
        let Some(named) = crate::util::parse_ts(&named_at) else {
            continue;
        };
        let end = active_at
            .as_deref()
            .and_then(crate::util::parse_ts)
            .unwrap_or(now);
        let lag = (end - named).as_millis().max(0) as f64 / 1000.0;
        let e = lags.entry(kind).or_insert(0.0);
        *e = e.max(lag);
    }
    Ok(lags)
}

async fn store_lags(state: &AppState, edge: &str, lags: &BTreeMap<String, f64>) {
    for (kind, lag) in lags {
        state
            .metrics
            .gauge(
                &state.metrics_db,
                "convergence_lag_s",
                crate::metrics::labels(edge, &[("kind", kind)]),
                *lag,
            )
            .await;
    }
}

/// `fw_drift{edge, kind}`: the missing, unknown and longer counts while `fw_drift` holds, else 0.
async fn fw_drift_gauges(state: &AppState, edge: &str, conditions: &[Condition]) {
    let drift = conditions
        .iter()
        .find(|c| c.kind == picket_api::session::condition_kind::FW_DRIFT);
    let mut items = Vec::new();
    for kind in ["missing", "unknown", "longer"] {
        let v = drift
            .and_then(|c| c.detail.as_ref())
            .and_then(|d| d.get(kind))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        items.push((
            "fw_drift".to_string(),
            crate::metrics::labels(edge, &[("kind", kind)]),
            v,
        ));
    }
    // Stored like the other core gauges, so it can be charted (core.md §10).
    state.metrics.gauges(&state.metrics_db, items).await;
}

/// Resolves, in `tx`, the `edge_activation_failed` alerts whose head a heartbeat's `versions`
/// names in its plain form (every part active), or whose config it names (core.md §9); never
/// on a matching `head` inside the object form.
fn resolve_activations_in(
    alerts: &Alerts,
    tx: &Transaction<'_>,
    edge: &str,
    v: &Versions,
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    let open: Vec<(String, String)> = {
        let mut st = tx.prepare_cached(
            "SELECT dedupe_key, details_json FROM alerts
             WHERE kind = 'edge_activation_failed' AND edge_id = ?1 AND state = 'open'",
        )?;
        st.query_map([edge], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (key, details) in open {
        let details: Value = serde_json::from_str(&details).unwrap_or(Value::Null);
        let t = &details["target"];
        let head = t["head"].as_str().unwrap_or_default();
        let short = picket_api::ids::short_id(head);
        let active = if let Some(b) = t["bundle"].as_str() {
            matches!(v.bundles.get(b), Some(BundleVersion::Plain(h)) if !head.is_empty() && (h == short || h == head))
        } else if let Some(cfg) = t["config"].as_str() {
            let s = picket_api::ids::short_id(cfg);
            !cfg.is_empty() && (v.config == s || v.config == cfg)
        } else {
            false
        };
        if active {
            alerts.resolve_in(tx, &key, Some(&json!({"by": "heartbeat versions"})), ch)?;
        }
    }
    Ok(())
}

/// `upstream_invalid_spike` per edge: above 1 % of misses for 5 min raises; 5 min below
/// resolves (core.md §9). Measured between heartbeats of one boot.
#[derive(Default)]
pub struct SpikeTracker {
    edges: Mutex<HashMap<String, SpikeState>>,
}

/// Since when an edge has been above the spike threshold, and since when below.
type SpikeState = (Option<Timestamp>, Option<tokio::time::Instant>);

/// The `upstream_invalid_spike` effect of a heartbeat, applied in its transaction: the spec,
/// since when the share has been above the threshold (`None` to resolve), and the threshold.
/// `None` when nothing changes.
fn spike_decision(
    state: &AppState,
    edge: &str,
    prev: Option<&Heartbeat>,
    hb: &Heartbeat,
) -> Option<(RaiseSpec, Option<Timestamp>, Duration)> {
    let prev = prev.filter(|p| p.boot == hb.boot)?;
    let invalid = |h: &Heartbeat| -> u64 {
        h.metrics
            .upstream
            .values()
            .flat_map(|u| u.invalid.values())
            .fold(0u64, |a, b| a.saturating_add(*b))
    };
    let d_invalid = invalid(hb).saturating_sub(invalid(prev));
    let d_misses = hb.metrics.cache_misses.saturating_sub(prev.metrics.cache_misses);
    let above = d_invalid > 0 && (d_misses == 0 || d_invalid as f64 / d_misses as f64 > INVALID_SPIKE_SHARE);
    let threshold = state.settings().alerts.threshold("upstream_invalid_spike");
    let now = Timestamp::now();
    let mono = tokio::time::Instant::now();
    let (since, resolve) = {
        let mut m = state.edges.spikes.edges.lock().ok()?;
        if m.len() > 4096 && !m.contains_key(edge) {
            m.clear();
        }
        let e = m.entry(edge.to_string()).or_default();
        if above {
            e.1 = None;
            let since = *e.0.get_or_insert(now);
            (Some(since), false)
        } else {
            e.0 = None;
            let below = *e.1.get_or_insert(mono);
            (None, mono.saturating_duration_since(below) >= threshold)
        }
    };
    let spec = RaiseSpec::new(
        "upstream_invalid_spike",
        Severity::Warning,
        format!("upstream_invalid_spike:{edge}"),
        format!("Edge {edge}: invalid upstream answers above 1 % of misses"),
        json!({"edge": edge, "invalid": d_invalid, "misses": d_misses}),
    )
    .edge(edge);
    (since.is_some() || resolve).then_some((spec, since, threshold))
}

/// When `edge` was last seen, measured on the monotonic clock where core saw it itself
/// (README §2 Clocks); after a restart, the stored wall time (else when it was added), but no
/// earlier than core's start: an edge can't reconnect to a core that isn't running, so an outage
/// of core never counts towards `edge_offline` (core.md §9).
fn last_seen(live: &EdgeLive, created: Option<&str>, core_started: Timestamp, now: Timestamp) -> Timestamp {
    if let Some(m) = live.last_seen_mono {
        return crate::clock::held_since(Some(m), tokio::time::Instant::now(), now).unwrap_or(now);
    }
    live.last_seen
        .or_else(|| created.and_then(crate::util::parse_ts))
        .map(|t| t.max(core_started))
        .map(|t| picket_api::time::clamp_to_now(t, now))
        .unwrap_or(now)
}

/// True when `edge` is online: a hello or heartbeat within the last 90 s (core.md §4).
pub fn online(live: &EdgeLive, now: Timestamp) -> bool {
    if let Some(m) = live.last_seen_mono {
        return m.elapsed() < crate::edges::OFFLINE_AFTER;
    }
    live.last_seen.is_some_and(|t| {
        std::time::Duration::try_from(now - t).unwrap_or_default() < crate::edges::OFFLINE_AFTER
    })
}

/// The watcher (module docs), until shutdown.
pub fn spawn_watcher(state: SharedState) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(WATCH_EVERY);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                _ = t.tick() => {}
            }
            if let Err(e) = watch_once(&state).await {
                tracing::warn!(error = %e, "edge watcher failed");
            }
        }
    });
}

/// One round of the watcher (also called by tests).
pub async fn watch_once(state: &SharedState) -> CoreResult<()> {
    let model = state.config.model().await?;
    let settings = state.settings();
    let now = Timestamp::now();
    let hour_ago = crate::util::ts(&(now - jiff::SignedDuration::from_hours(1)));
    for (id, def) in &model.edges {
        let live = state.edges.hub.live(id);
        if let Err(e) = offline_tick(
            state,
            id,
            &def.name,
            def.created_at.clone(),
            settings.alerts.threshold("edge_offline"),
        )
        .await
        {
            tracing::warn!(edge = %id, error = %e, "edge_offline check failed");
        }
        // Held conditions keep counting while the edge is offline.
        if !live.conditions.is_empty()
            && let Err(e) = condition_tick(state, id, &live.conditions).await
        {
            tracing::warn!(edge = %id, error = %e, "condition threshold check failed");
        }
        let (id2, hour) = (id.clone(), hour_ago.clone());
        let repairs: i64 = state
            .db
            .read(move |c| {
                Ok::<_, CoreError>(c.query_row(
                    "SELECT count(*) FROM edge_events WHERE edge_id = ?1 AND kind = 'rules_repaired' AND at >= ?2",
                    params![id2, hour],
                    |r| r.get(0),
                )?)
            })
            .await?;
        fw_repairs_alert(state, id, &def.name, repairs).await;
        if let Err(e) = crash_loop_tick(state, id).await {
            tracing::warn!(edge = %id, error = %e, "edge_crash_loop check failed");
        }
        if let Err(e) = tls_refused_tick(state, id).await {
            tracing::warn!(edge = %id, error = %e, "edge_tls_version_refused check failed");
        }
        firmware_check(state, def, live.hello.as_ref()).await;
        resolve_listener_rejections(state, &model, id, live.hello.as_ref(), false).await;
    }
    Ok(())
}

/// Resolves `edge_crash_loop` after 10 min with no new boot (core.md §9), decided in the
/// resolving transaction: a hello that registered a new boot or raised the alert (its starts are
/// new boots too) while the watcher waited for the writer keeps it open.
async fn crash_loop_tick(state: &AppState, edge: &str) -> CoreResult<()> {
    let key = format!("edge_crash_loop:{edge}");
    // Most ticks have nothing open: no writer transaction for them (one raised after this read
    // is newer than any reason to resolve it).
    let k = key.clone();
    let open = state
        .db
        .read(move |c| {
            Ok::<_, CoreError>(
                c.query_row(
                    "SELECT 1 FROM alerts WHERE dedupe_key = ?1 AND state = 'open'",
                    [k],
                    |_| Ok(()),
                )
                .optional()?
                .is_some(),
            )
        })
        .await?;
    if !open {
        return Ok(());
    }
    let alerts = state.alerts.clone();
    let edge = edge.to_string();
    let ch = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let mut ch = Changes::default();
            let cutoff = crate::util::ts(
                &(Timestamp::now() - jiff::SignedDuration::try_from(CRASH_LOOP_WINDOW).unwrap_or_default()),
            );
            let raised: Option<String> = tx
                .query_row(
                    "SELECT last_seen FROM alerts WHERE dedupe_key = ?1 AND state = 'open'",
                    [&key],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(raised) = raised {
                let recent_boot = tx
                    .query_row(
                        "SELECT 1 FROM edge_boots WHERE edge_id = ?1 AND edge_version IS NOT NULL AND first_seen >= ?2 LIMIT 1",
                        params![edge, cutoff],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !recent_boot && raised < cutoff {
                    alerts.resolve_in(&tx, &key, Some(&json!({"by": "10 min without a new boot"})), &mut ch)?;
                }
            }
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, CoreError>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    Ok(())
}

/// Resolves the edge's `edge_tls_version_refused` alerts that went [`TLS_REFUSED_QUIET`] without
/// a new event, decided in the resolving transaction: an event that raised one again while the
/// watcher waited for the writer keeps it open. At most [`MAX_TLS_REFUSED_PER_TICK`] a tick.
async fn tls_refused_tick(state: &AppState, edge: &str) -> CoreResult<()> {
    const QUIET_SQL: &str = "SELECT dedupe_key FROM alerts
         WHERE kind = 'edge_tls_version_refused' AND edge_id = ?1 AND state = 'open' AND last_seen < ?2
         LIMIT ?3";
    let cutoff = crate::util::ts(&crate::util::window_start(Timestamp::now(), TLS_REFUSED_QUIET));
    // Most ticks have none: no writer transaction for them.
    let (e, c) = (edge.to_string(), cutoff.clone());
    let any = state
        .db
        .read(move |db| {
            Ok::<_, CoreError>(
                db.query_row(QUIET_SQL, params![e, c, 1], |_| Ok(()))
                    .optional()?
                    .is_some(),
            )
        })
        .await?;
    if !any {
        return Ok(());
    }
    let alerts = state.alerts.clone();
    let edge = edge.to_string();
    let ch = state
        .db
        .write(move |db| {
            let tx = db.transaction()?;
            let mut ch = Changes::default();
            let keys: Vec<String> = tx
                .prepare(QUIET_SQL)?
                .query_map(params![edge, cutoff, MAX_TLS_REFUSED_PER_TICK], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let hours = TLS_REFUSED_QUIET.as_secs() / 3600;
            let by = json!({"by": format!("{hours} h without a refused handshake")});
            for k in keys {
                alerts.resolve_in(&tx, &k, Some(&by), &mut ch)?;
            }
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, CoreError>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    Ok(())
}

/// Events the edge page shows: the newest of every kind but `tls_version_refused`, and the
/// newest of that kind, which an edge logs up to once per listener and device an hour.
pub const PAGE_EVENTS: i64 = 50;
pub const PAGE_TLS_REFUSALS: i64 = 20;

/// `edge_tls_version_refused` alerts resolved per edge and watcher tick (the rest wait a tick).
const MAX_TLS_REFUSED_PER_TICK: i64 = 200;

/// `edge_offline` for one edge: no heartbeat for its threshold (5 min; offline after 90 s).
/// Decided on the writer against the live copy there, so a hello or heartbeat that committed
/// first (it updates the live copy right after its commit) wins.
async fn offline_tick(
    state: &AppState,
    edge: &str,
    name: &str,
    created: Option<String>,
    threshold: Duration,
) -> CoreResult<()> {
    let hub = state.edges.hub.clone();
    let alerts = state.alerts.clone();
    let core_started = state.edges.core_started_at(Timestamp::now());
    let (edge, name) = (edge.to_string(), name.to_string());
    let ch = state
        .db
        .write(move |c| {
            let live = hub.live(&edge);
            let now = Timestamp::now();
            let seen = last_seen(&live, created.as_deref(), core_started, now);
            let offline = !online(&live, now);
            let spec = RaiseSpec::new(
                "edge_offline",
                Severity::Warning,
                format!("edge_offline:{edge}"),
                format!("Edge {name} is offline"),
                json!({"edge": edge, "last_seen": live.last_seen.map(|t| crate::util::ts(&t))}),
            )
            .edge(&edge);
            let tx = c.transaction()?;
            let mut ch = Changes::default();
            alerts.condition_in(&tx, &spec, offline.then_some(seen), threshold, now, &mut ch)?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, CoreError>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    Ok(())
}

/// Thresholds of an edge's held conditions while no report arrives (core.md §9), decided on the
/// writer against the stored snapshot: a condition a heartbeat cleared and resolved first is
/// never raised again here.
async fn condition_tick(state: &AppState, edge: &str, live: &[Condition]) -> CoreResult<()> {
    let specs = condition_alerts(state, edge, live).await;
    let alerts = state.alerts.clone();
    let edge = edge.to_string();
    let ch = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let stored: Vec<Condition> = tx
                .query_row(
                    "SELECT conditions_json FROM edge_status WHERE edge_id = ?1",
                    [&edge],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let now = Timestamp::now();
            let mut ch = Changes::default();
            for a in &specs {
                if let Some(c) = stored.iter().find(|c| c.kind == a.kind && c.key == a.key) {
                    let since = picket_api::time::clamp_to_now(c.since, now);
                    alerts.condition_in(&tx, &a.spec, Some(since), a.threshold, now, &mut ch)?;
                }
            }
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, CoreError>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    Ok(())
}

/// The `edge_fw_repairs` alert of an edge with `repairs_last_hour` repairs.
pub fn fw_repairs_spec(edge: &str, name: &str, repairs_last_hour: i64) -> RaiseSpec {
    RaiseSpec::new(
        "edge_fw_repairs",
        Severity::Warning,
        format!("edge_fw_repairs:{edge}"),
        format!("Edge {name}: Picket's firewall rules keep being repaired"),
        json!({"edge": edge, "repairs_last_hour": repairs_last_hour}),
    )
    .edge(edge)
}

/// `edge_fw_repairs`: more than 10 repairs in the last hour raises; an hour with ≤ 10 resolves.
pub async fn fw_repairs_alert(state: &AppState, edge: &str, name: &str, repairs_last_hour: i64) {
    let spec = fw_repairs_spec(edge, name, repairs_last_hour);
    let since = (repairs_last_hour > FW_REPAIRS_PER_HOUR).then(Timestamp::now);
    let _ = state
        .alerts
        .condition(spec, since, Duration::ZERO, Timestamp::now())
        .await;
}

/// Resolves `edge_listener_rejected` alerts of `edge` whose listener no longer asks the edge
/// for that bind (unassigned, or another bind), and, after a completed config activation
/// (`activated`), those whose bind the edge's `allowed_binds` now admits (core.md §9).
pub async fn resolve_listener_rejections(
    state: &AppState,
    model: &crate::config::Model,
    edge: &str,
    hello: Option<&HelloInfo>,
    after_activation: bool,
) {
    let open = state
        .alerts
        .list(
            AlertFilter {
                kind: Some("edge_listener_rejected".into()),
                edge: Some(edge.into()),
                state: Some(AlertState::Open),
                ..Default::default()
            },
            None,
            200,
        )
        .await
        .unwrap_or_default();
    for a in open {
        let listener = a.details["listener"].as_str().unwrap_or_default();
        let bind = a.details["bind"].as_str();
        let asks = model
            .listeners
            .get(listener)
            .is_some_and(|l| l.edges.iter().any(|e| e == edge) && bind.is_none_or(|b| b == l.bind));
        let admitted = after_activation
            && hello.is_some_and(|h| {
                model
                    .listeners
                    .get(listener)
                    .is_some_and(|l| h.bind_allowed(&l.bind))
            });
        if !asks || admitted {
            let _ = state
                .alerts
                .resolve(
                    &a.dedupe_key,
                    Some(json!({"by": if asks { "activation" } else { "listener changed" }})),
                )
                .await;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The UI's view of one edge

/// A listener assigned to the edge, flagged when its bind isn't in the edge's reported
/// `allowed_binds` (core.md §4).
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct ListenerFlag {
    pub id: String,
    pub bind: String,
    /// `None` until the edge's hello reported `allowed_binds`.
    pub allowed: Option<bool>,
}

/// A version core names in the edge's config object, with its convergence.
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct NamedVersion {
    pub kind: String,
    pub target: String,
    pub id: String,
    pub named_at: String,
    pub active_at: Option<String>,
    pub lag_s: f64,
}

/// One recent edge event or condition change (72 h; core.md §9).
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct EventView {
    pub at: String,
    pub kind: String,
    pub detail: Value,
}

/// An edge's live state for the UI (`GET /api/ui/v1/edges/{id}/status`).
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct EdgeStatusView {
    pub edge: String,
    pub name: String,
    pub online: bool,
    pub last_seen: Option<String>,
    pub session: Option<SessionInfo>,
    pub hello: Option<HelloInfo>,
    /// The last heartbeat as received (api.md §3).
    pub heartbeat: Option<Value>,
    pub conditions: Vec<Value>,
    /// The config core serves the edge now.
    pub config: Option<String>,
    pub config_published_at: Option<String>,
    pub missing_heads: Vec<String>,
    pub missing_verdict_sets: Vec<String>,
    pub missing_secrets: Vec<String>,
    pub release: Option<Value>,
    pub named: Vec<NamedVersion>,
    /// What the edge last reported it keeps (api.md §3 `have`).
    pub have: Value,
    /// The versions the edge reports active, and those before them.
    pub versions: Option<Value>,
    pub ready_version: Option<String>,
    pub requests: Vec<crate::edges::requests::RequestView>,
    pub update: Option<UpdateRecord>,
    pub listeners: Vec<ListenerFlag>,
    pub events: Vec<EventView>,
}

/// Builds `edge`'s status view.
pub async fn view(state: &SharedState, edge: &str) -> CoreResult<EdgeStatusView> {
    let model = state.config.model().await?;
    let def = model
        .edges
        .get(edge)
        .ok_or_else(|| CoreError::NotFound(format!("no edge {edge:?}")))?
        .clone();
    let live = state.edges.hub.live(edge);
    let now = Timestamp::now();
    let published = state.edges.publisher.current(edge);
    let (e1, applied) = (edge.to_string(), live.applied.clone());
    let offered = state.edges.releases.offer().map(|o| o.version);
    let (named, requests, events) = state
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT kind, target, id, named_at, active_at FROM edge_named WHERE edge_id = ?1 ORDER BY kind, target",
            )?;
            let named = st
                .query_map([&e1], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            // An install request for a release core no longer offers isn't rendered, so it is
            // pending no more (api.md §4: null after a different offer).
            let requests: Vec<_> = crate::edges::requests::views(c, &e1, &applied)?
                .into_iter()
                .filter(|r| r.kind != crate::edges::requests::kind::INSTALL_NOW || r.version == offered)
                .collect();
            // The newest events, of which `tls_version_refused` (up to one per listener and
            // device an hour) takes at most its own share, so the others stay in view.
            let mut events = Vec::new();
            for (sql, limit) in [
                (
                    "SELECT at, kind, detail_json FROM edge_events WHERE edge_id = ?1 AND kind <> ?2 ORDER BY at DESC LIMIT ?3",
                    PAGE_EVENTS,
                ),
                (
                    "SELECT at, kind, detail_json FROM edge_events WHERE edge_id = ?1 AND kind = ?2 ORDER BY at DESC LIMIT ?3",
                    PAGE_TLS_REFUSALS,
                ),
            ] {
                let mut st = c.prepare(sql)?;
                let rows = st.query_map(params![e1, event_kind::TLS_VERSION_REFUSED, limit], |r| {
                    Ok(EventView {
                        at: r.get(0)?,
                        kind: r.get(1)?,
                        detail: r
                            .get::<_, Option<String>>(2)?
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or(Value::Null),
                    })
                })?;
                events.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
            }
            events.sort_by(|a, b| b.at.cmp(&a.at));
            Ok::<_, CoreError>((named, requests, events))
        })
        .await?;
    let named = named
        .into_iter()
        .map(|(kind, target, id, named_at, active_at)| {
            let start = crate::util::parse_ts(&named_at).unwrap_or(now);
            let end = active_at
                .as_deref()
                .and_then(crate::util::parse_ts)
                .unwrap_or(now);
            NamedVersion {
                kind,
                target,
                id,
                named_at,
                lag_s: (end - start).as_millis().max(0) as f64 / 1000.0,
                active_at,
            }
        })
        .collect();
    let listeners = model
        .listeners
        .values()
        .filter(|l| l.edges.iter().any(|e| e == edge))
        .map(|l| ListenerFlag {
            id: l.id.clone(),
            bind: l.bind.clone(),
            allowed: live.hello.as_ref().map(|h| h.bind_allowed(&l.bind)),
        })
        .collect();
    Ok(EdgeStatusView {
        edge: edge.to_string(),
        name: def.name.clone(),
        online: online(&live, now),
        last_seen: live.last_seen.map(|t| crate::util::ts(&t)),
        session: state.edges.hub.session(edge),
        hello: live.hello.clone(),
        heartbeat: live
            .heartbeat
            .as_ref()
            .and_then(|h| serde_json::to_value(&**h).ok()),
        conditions: live
            .conditions
            .iter()
            .filter_map(|c| serde_json::to_value(c).ok())
            .collect(),
        config: published.as_ref().map(|p| p.id.clone()),
        config_published_at: published.as_ref().map(|p| p.published_at.clone()),
        missing_heads: published
            .as_ref()
            .map(|p| p.missing_heads.clone())
            .unwrap_or_default(),
        missing_verdict_sets: published
            .as_ref()
            .map(|p| p.missing_verdict_sets.clone())
            .unwrap_or_default(),
        missing_secrets: published
            .as_ref()
            .map(|p| p.missing_secrets.clone())
            .unwrap_or_default(),
        release: published
            .as_ref()
            .and_then(|p| p.config.release.as_ref())
            .and_then(|r| serde_json::to_value(r).ok()),
        named,
        have: serde_json::to_value(&live.have).unwrap_or(Value::Null),
        versions: live.versions.as_ref().and_then(|v| serde_json::to_value(v).ok()),
        ready_version: live.heartbeat.as_ref().and_then(|h| h.ready_version.clone()),
        requests,
        update: live.update.clone(),
        listeners,
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_versions() {
        assert_eq!(
            parse_firmware("UCGF.ipq9574.v6.0.17.0d2a1b3.240611.1525"),
            Some(("UCGF".into(), vec![6, 0, 17]))
        );
        assert_eq!(
            parse_firmware("UCGF.ipq9574.v6.1.0"),
            Some(("UCGF".into(), vec![6, 1, 0]))
        );
        assert!(parse_firmware("garbage").is_none());
        let mins = vec![crate::settings::FirmwareMin {
            target: "UCGF".into(),
            min: "6.0.17".into(),
        }];
        assert!(firmware_problem(Some("UCGF.ipq9574.v6.0.17.x"), &mins).is_none());
        assert!(
            firmware_problem(Some("UCGF.ipq9574.v7.0.0.x"), &mins).is_none(),
            "never for a newer version"
        );
        assert!(firmware_problem(Some("UCGF.ipq9574.v6.0.16.x"), &mins).is_some());
        assert!(
            firmware_problem(Some("UDMP.al324.v4.0.0.x"), &mins).is_some(),
            "no minimum for the target"
        );
        assert!(firmware_problem(Some("???"), &mins).is_some());
        assert!(firmware_problem(None, &mins).is_some());
    }

    #[test]
    fn condition_kinds_map_to_alerts() {
        for k in [
            "upstream_down",
            "redirect_missing",
            "helper_unreachable",
            "unifi_conflict",
            "listener_failed",
            "ssd_unavailable",
            "memory_low",
            "fw_set_full",
            "spool_evicting",
            "helper_disabled",
            "fw_layout_unknown",
            "fw_catch_all",
            "fw_drift",
            "firmware_check_failed",
        ] {
            let (alert, _) = condition_alert(k).unwrap();
            assert!(crate::alerts::is_known_kind(alert), "{alert}");
            // Every report resolves the open alerts of these kinds it doesn't carry.
            assert!(CONDITION_ALERT_KINDS.contains(&alert), "{alert}");
        }
        assert!(condition_alert("future_kind").is_none());
        assert_eq!(CONDITION_ALERT_KINDS.len(), 14);
    }
}
