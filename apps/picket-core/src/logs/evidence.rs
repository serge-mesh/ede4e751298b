//! Alert evidence (core.md §9 "Evidence"), copied from ingested records.
//!
//! - A security alert keeps full copies of its related log records, `response` included: those
//!   matching its dedup key's subject ([`EvidenceRule`]: a registrable domain, matched against
//!   the query name and, for an alert about an answer, the names and addresses in the record's
//!   answer; optionally one device, profiles or decisions), first those in the window when it is
//!   raised (the backfill), then each new one as it is analysed after ingest ([`capture_in`]),
//!   until the alert is deleted. They outlive the logs. A copy is the whole logged record
//!   ([`record_json`]: api.md §5 with its lookups, versions and EDNS, plus core's fields).
//! - **Rule and backfill together:** the rule row is made in the raising transaction
//!   ([`raise_security_with_rule_in`]) with the backfill's work: every partition's `analysis`
//!   progress (`log_progress`) at that moment. The backfill copies and counts exactly the records
//!   at or below it; live capture, inside each analysis transaction before that progress moves,
//!   takes every later record. The two never overlap, so each record is counted once, whatever
//!   copies the caps evict. The backfill runs in bounded steps (one partition window each, a
//!   light-lane job), each step's copies and its new progress in one transaction, so a restart
//!   resumes it ([`start_backfills`]; README §2 Restarts).
//! - At most `alerts.evidence_per_alert` copies per alert: half the first and half the latest
//!   (the oldest of the latest half goes when a new one comes), plus exact counts per client and
//!   per name. Each alert tracks at most [`MAX_DISTINCT`] distinct clients and names; further
//!   ones go into one "other" count (`client_other`, `name_other`), and the alert shows that its
//!   breakdown is incomplete.
//! - Each upstream answer the copies reference is copied once per alert
//!   (`alert_evidence_answers`, source `log`) and goes when no kept copy references it. A copy of
//!   a record stored with `answer_missing` is marked incomplete.
//! - **UI events:** each transaction that copies or counts records for an alert (a backfill
//!   step, an analysis batch's live capture) collects the alert in a [`Touched`], and right after
//!   its commit, on the writer, notes it for the coalesced `alert` event
//!   ([`Alerts::evidence_changed`]; api.md §7), so an open alert's view re-reads its evidence
//!   then, not only at its next raise. One note per alert per transaction: a batch's capture
//!   costs at most one listing per alert, and the event lists at most 64 (README §2 Bounded).
//! - The copies, answers, counts and `wire_mismatch` examples of all alerts share
//!   `alerts.evidence_total_mib` ([`Capture`]): every insert is charged when it is made (a count
//!   row at [`COUNT_ROW_BYTES`]), after a recount of what is stored ([`Capture::ensure_counted`]),
//!   and every eviction or delete gives its bytes back. When it is full, new records aren't
//!   copied, counts go on (new clients and names into "other"), and `alert_evidence_full` is
//!   raised (warning past 80 %, critical when full), resolved below 80 %.
//!
//! [`raise_security_with_rule_in`] (or [`raise_security_in`] then [`start`]) is the entry point
//! for any module that raises a security alert.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use super::record::{AnswerValues, Rec};
use super::replay::Value;
use crate::alerts::{Alerts, Changes, RaiseSpec, Severity};
use crate::state::{AppState, SharedState};

/// Distinct clients and names one alert counts before "other" (core.md §9).
pub const MAX_DISTINCT: i64 = 1000;
/// Bytes one count row is charged against the budget.
pub const COUNT_ROW_BYTES: u64 = 64;
/// Records one backfill step reads from a partition (rowids scanned when the rule needs each
/// record's answer; records matching its name otherwise).
const BACKFILL_STEP: i64 = 1024;
/// Partitions one rule's backfill names at most (the log window is 72 h by default; a longer
/// configured window keeps its newest hours).
const MAX_BACKFILL_HOURS: usize = 24 * 90;

/// Which records an alert's evidence copies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceRule {
    /// Records whose query name is this name or under it (the registrable domain, or the full
    /// name for a name with none).
    pub domain: String,
    /// Only this device (`category_blocked` keys on (device, domain)): the record's `device`,
    /// else its client address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Only records of these profiles (empty: any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    /// Only records with these decisions (empty: any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<String>,
    /// Also records whose answer holds a name under `domain` (its CNAME chain and HTTPS/SVCB
    /// targets, from the referenced answer, else `response`, else the preview): an alert raised
    /// for a target in the answer (`category_answered`, core.md §6 retro-match).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub answers: bool,
    /// Also records whose answer holds one of these addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
}

/// True when log-text `name` is `domain` or under it.
pub fn under(name: &str, domain: &str) -> bool {
    let n = name.trim_end_matches('.');
    let d = domain.trim_end_matches('.');
    !d.is_empty()
        && (n.eq_ignore_ascii_case(d)
            || (n.len() > d.len()
                && n.as_bytes()[n.len() - d.len() - 1] == b'.'
                && n[n.len() - d.len()..].eq_ignore_ascii_case(d)))
}

/// A record's device for grouping: its `device`, else its client address (core.md §9).
pub fn device_of(r: &Rec) -> String {
    r.device.clone().unwrap_or_else(|| r.client_ip.clone())
}

/// The text form of an address, as rules and the answered tables hold it.
fn ip_text(ip: &std::net::IpAddr) -> String {
    picket_rules::ip::canonical_ip(*ip).to_string()
}

impl EvidenceRule {
    /// The rule's lookup domain (`alert_evidence_rules.domain`): lowercase, without a final dot.
    pub fn lookup_domain(&self) -> String {
        self.domain.trim_end_matches('.').to_ascii_lowercase()
    }

    /// True when the rule looks into records' answers (names or addresses).
    pub fn needs_answers(&self) -> bool {
        self.answers || !self.ips.is_empty()
    }

    /// The device, profile and decision filters.
    fn filters(&self, r: &Rec) -> bool {
        self.device.as_ref().is_none_or(|d| *d == device_of(r))
            && (self.profiles.is_empty() || r.profile.as_ref().is_some_and(|p| self.profiles.contains(p)))
            && (self.decisions.is_empty() || self.decisions.contains(&r.decision))
    }

    /// True when `r` is one of the alert's related records (see the type's docs).
    pub fn matches(&self, r: &Rec) -> bool {
        if !self.filters(r) {
            return false;
        }
        if under(&r.qname, &self.domain) {
            return true;
        }
        self.needs_answers() && self.matches_answer(&r.answer_values())
    }

    /// The answer half of [`EvidenceRule::matches`].
    fn matches_answer(&self, av: &AnswerValues) -> bool {
        if self.answers {
            let names = av.cname.iter().chain(av.targets.iter());
            if names
                .filter(|v| matches!(v, Value::Name(_)))
                .any(|v| under(&v.text(), &self.domain))
            {
                return true;
            }
        }
        !self.ips.is_empty()
            && av.addrs.iter().any(|(v, _)| match v {
                Value::Ip(ip) => {
                    let t = ip_text(ip);
                    self.ips.iter().any(|x| {
                        x.parse::<std::net::IpAddr>()
                            .map(|a| ip_text(&a) == t)
                            .unwrap_or(false)
                    })
                }
                Value::Name(_) => false,
            })
    }
}

/// The evidence budget (core.md §9 `alerts.evidence_total_mib`) and the backfill worker's wake.
///
/// `used` holds the bytes stored, counted from the tables once before the first admission after
/// start ([`Capture::ensure_counted`], on the writer) and kept current by charging every insert
/// when it is made and releasing a delete only once its transaction has committed (an eviction's
/// bytes come back to the caller in [`Copied::freed`]), so `used` never falls below what is
/// stored, whatever rolls back; a periodic recount on the writer gives back what a rolled-back
/// insert charged.
pub struct Capture {
    /// Bytes in use.
    used: AtomicU64,
    /// `used` was counted from the tables since start (or since the last restore).
    counted: AtomicBool,
    /// A restore replaced the evidence tables: the rules' lookup columns are re-derived and
    /// the backfills of rules made before it (`restored_at`), which pointed into the logs the
    /// restore empties, dropped (core.md §2).
    restored: AtomicBool,
    restored_at: std::sync::Mutex<String>,
    /// The backfill worker runs (it was started) and its wake.
    worker: AtomicBool,
    wake: tokio::sync::Notify,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            used: AtomicU64::new(0),
            counted: AtomicBool::new(false),
            restored: AtomicBool::new(false),
            restored_at: std::sync::Mutex::new(String::new()),
            worker: AtomicBool::new(false),
            wake: tokio::sync::Notify::new(),
        }
    }
}

/// The JSON copy of a record (core.md §9 "full copies of its related log records, `response`
/// included"): the whole logged record (api.md §5) — the query-log API's record with the
/// record's `lookups` (each provider's verdict, reason and detail), its `versions` block, the
/// client's `edns` and its `response` (base64) — so provider verdicts and the versions that
/// decided survive the logs' retention.
pub fn record_json(r: &Rec) -> String {
    let mut v = serde_json::to_value(super::query::record_view(r)).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        let parsed = |s: &Option<String>| {
            s.as_deref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        };
        o.insert(
            "lookups".into(),
            parsed(&r.lookups_json).unwrap_or_else(|| serde_json::Value::Array(Vec::new())),
        );
        if let Ok(versions) = serde_json::from_str::<serde_json::Value>(&r.versions_json) {
            o.insert("versions".into(), versions);
        }
        if let Some(edns) = parsed(&r.edns_json) {
            o.insert("edns".into(), edns);
        }
        if let Some(resp) = r.response.as_ref() {
            use base64::Engine;
            o.insert(
                "response".into(),
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(resp)),
            );
        }
    }
    serde_json::to_string(&v).unwrap_or_else(|_| "{}".into())
}

/// The alerts whose evidence one transaction changed: records copied or counted (core.md §9
/// Evidence), noted for their `alert` UI event once it commits ([`Alerts::evidence_changed`]).
/// Bounded by the alerts with an evidence rule (the alert table's caps, `alerts`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Touched(BTreeSet<i64>);

impl Touched {
    pub fn add(&mut self, alert_id: i64) {
        self.0.insert(alert_id);
    }

    /// Adds `other`'s alerts (a savepoint's, once it is released).
    pub fn extend(&mut self, other: Touched) {
        self.0.extend(other.0);
    }

    pub fn ids(&self) -> &BTreeSet<i64> {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What one copy did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Copied {
    /// The record was new to the alert's evidence: counted, and copied when the budget had room
    /// (`copied`). False for a record already copied: nothing changed.
    pub counted: bool,
    pub copied: bool,
    /// The budget's change (charged less freed).
    pub bytes: i64,
    /// Bytes of older copies (and their answers) the copy evicted. The caller gives them back
    /// ([`Capture::release`]) once its transaction has committed: a rollback brings them back.
    pub freed: u64,
}

impl Capture {
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// Recounts the bytes in use from the tables. Run it on the writer (inside a write closure),
    /// so no insert or delete is in flight beside it and the count is exact.
    pub fn recount(&self, c: &Connection) -> rusqlite::Result<u64> {
        let n: i64 = c.query_row(
            "SELECT coalesce((SELECT sum(octet_length(record_json)) FROM alert_evidence), 0)
                  + coalesce((SELECT sum(octet_length(wire)) FROM alert_evidence_answers), 0)
                  + coalesce((SELECT sum(octet_length(record_json) + coalesce(octet_length(wire), 0)
                                        + coalesce(octet_length(decoded_json), 0)) FROM wire_examples), 0)
                  + coalesce((SELECT count(*) * ?1 FROM alert_evidence_counts WHERE kind IN ('client', 'name')), 0)",
            [COUNT_ROW_BYTES],
            |r| r.get(0),
        )?;
        let n = u64::try_from(n).unwrap_or(0);
        self.used.store(n, Ordering::Relaxed);
        self.counted.store(true, Ordering::SeqCst);
        Ok(n)
    }

    /// Makes `used` the stored bytes before anything is admitted: after start, an alert delete
    /// or a restore, it recounts (core.md §9: the budget holds what is already stored). After a
    /// restore it also re-derives the rules' lookup columns and drops their backfills, which
    /// named partitions the restore emptied. Call it on the writer, inside the transaction that
    /// admits (every admission in this module does).
    pub fn ensure_counted(&self, c: &Connection) -> rusqlite::Result<()> {
        if self.restored.swap(false, Ordering::SeqCst) {
            let at = self.restored_at.lock().map(|g| g.clone()).unwrap_or_default();
            if let Err(e) = normalize_rules(c, Some(&at)) {
                self.restored.store(true, Ordering::SeqCst);
                return Err(e);
            }
            self.counted.store(false, Ordering::SeqCst);
        }
        if !self.counted.load(Ordering::SeqCst) {
            normalize_rules(c, None)?;
            self.recount(c)?;
        }
        Ok(())
    }

    /// The evidence tables were replaced (a config restore, core.md §2): recount before the next
    /// admission, re-derive the rules' lookup columns and drop their backfills.
    pub fn invalidate(&self) {
        if let Ok(mut g) = self.restored_at.lock() {
            *g = crate::util::now_ts();
        }
        self.restored.store(true, Ordering::SeqCst);
        self.counted.store(false, Ordering::SeqCst);
    }

    /// Evidence was deleted outside this module (an alert deleted with its evidence): recount
    /// before the next admission.
    pub fn forget_count(&self) {
        self.counted.store(false, Ordering::SeqCst);
    }

    /// Charges `bytes` that a caller stores outside [`Capture::copy_in`] (the DNSSEC validator's
    /// DNSKEY and DS answers, the cross-check resolver's answers, `wire_mismatch` examples) to
    /// the shared budget, when it has room for them (core.md §9 `alerts.evidence_total_mib`).
    /// Returns false, charging nothing, when it hasn't: the caller then stores nothing. Call
    /// [`Capture::ensure_counted`] in the same transaction first, so the budget holds what is
    /// stored; [`Capture::release`] gives bytes back when a charged insert doesn't happen.
    pub fn charge(&self, bytes: u64, total_bytes: u64) -> bool {
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |u| {
                let after = u.saturating_add(bytes);
                (after <= total_bytes).then_some(after)
            })
            .is_ok()
    }

    /// Gives back `bytes` of the budget (a charged insert that didn't happen, or a delete).
    pub fn release(&self, bytes: u64) {
        self.used
            .update(Ordering::Relaxed, Ordering::Relaxed, |u| u.saturating_sub(bytes));
    }

    /// Stores one copy of an answer in alert `alert_id`'s evidence (`alert_evidence_answers`,
    /// `source` `log`, `validator` or `crosscheck`), charged to the budget. True when the alert
    /// holds it afterwards; false when the budget had no room (nothing stored).
    pub fn add_answer_in(
        &self,
        tx: &Transaction<'_>,
        alert_id: i64,
        answer_id: &str,
        source: &str,
        wire: &[u8],
        total_bytes: u64,
    ) -> rusqlite::Result<bool> {
        self.ensure_counted(tx)?;
        let have = tx
            .prepare_cached(
                "SELECT 1 FROM alert_evidence_answers WHERE alert_id = ?1 AND answer_id = ?2 AND source = ?3",
            )?
            .exists(params![alert_id, answer_id, source])?;
        if have {
            return Ok(true);
        }
        let bytes = wire.len() as u64;
        if !self.charge(bytes, total_bytes) {
            return Ok(false);
        }
        let n = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO alert_evidence_answers(alert_id, answer_id, source, wire)
                 SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM alerts WHERE id = ?1)",
            )?
            .execute(params![alert_id, answer_id, source, wire])?;
        if n == 0 {
            self.release(bytes);
        }
        Ok(n > 0)
    }

    /// Counts `r` once for `kind` (`client` or `name`) of alert `alert_id`: an existing row goes
    /// up; a new key gets its own row while the alert has fewer than [`MAX_DISTINCT`] and the
    /// budget has room for the row (charged before it is inserted), else it goes into
    /// `<kind>_other` (core.md §9: counts go on whatever the budget).
    fn count_in(
        &self,
        tx: &Transaction<'_>,
        alert_id: i64,
        kind: &str,
        key: &str,
        total_bytes: u64,
    ) -> rusqlite::Result<()> {
        let n = tx
            .prepare_cached(
                "UPDATE alert_evidence_counts SET count = count + 1 WHERE alert_id = ?1 AND kind = ?2 AND key = ?3",
            )?
            .execute(params![alert_id, kind, key])?;
        if n > 0 {
            return Ok(());
        }
        let distinct: i64 = tx
            .prepare_cached("SELECT count(*) FROM alert_evidence_counts WHERE alert_id = ?1 AND kind = ?2")?
            .query_row(params![alert_id, kind], |row| row.get(0))?;
        let own = distinct < MAX_DISTINCT && self.charge(COUNT_ROW_BYTES, total_bytes);
        let (k, key) = if own {
            (kind.to_string(), key.to_string())
        } else {
            (format!("{kind}_other"), String::new())
        };
        // The "other" rows (two per alert at most) are the overflow and aren't charged, so a full
        // budget never stops the counts.
        tx.prepare_cached(
            "INSERT INTO alert_evidence_counts(alert_id, kind, key, count) VALUES (?1, ?2, ?3, 1)
             ON CONFLICT(alert_id, kind, key) DO UPDATE SET count = count + 1",
        )?
        .execute(params![alert_id, k, key])?;
        Ok(())
    }

    /// Copies `r` into alert `alert_id`'s evidence inside `tx` (see the module docs): counts it
    /// once (a record already copied is neither copied nor counted again), then copies it, with
    /// its answer, when the budget has room for both, then keeps half the first and half the
    /// latest copies.
    pub fn copy_in(
        &self,
        tx: &Transaction<'_>,
        alert_id: i64,
        r: &Rec,
        per_alert: u32,
        total_bytes: u64,
    ) -> rusqlite::Result<Copied> {
        self.ensure_counted(tx)?;
        let mut out = Copied::default();
        let exists = tx
            .prepare_cached("SELECT 1 FROM alert_evidence WHERE alert_id = ?1 AND edge_id = ?2 AND boot = ?3 AND seq = ?4")?
            .exists(params![alert_id, r.edge, r.boot, r.seq])?;
        if exists {
            return Ok(out);
        }
        let before = self.used();
        out.counted = true;
        // Counts go on whatever the budget (core.md §9).
        self.count_in(tx, alert_id, "client", &device_of(r), total_bytes)?;
        self.count_in(tx, alert_id, "name", &r.qname, total_bytes)?;
        // The copy and its answer, if the budget has room for both.
        let json = record_json(r);
        let answer = match (&r.answer_id, &r.answer_wire) {
            (Some(aid), Some(w)) => {
                let have = tx
                    .prepare_cached(
                        "SELECT 1 FROM alert_evidence_answers WHERE alert_id = ?1 AND answer_id = ?2 AND source = 'log'",
                    )?
                    .exists(params![alert_id, aid])?;
                (!have).then_some((aid, w))
            }
            _ => None,
        };
        let need = json.len() as u64 + answer.map_or(0, |(_, w)| w.len() as u64);
        if self.charge(need, total_bytes) {
            tx.prepare_cached(
                "INSERT INTO alert_evidence(alert_id, edge_id, boot, seq, ts, record_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute(params![alert_id, r.edge, r.boot, r.seq, r.ts, json])?;
            out.copied = true;
            if let Some((aid, w)) = answer {
                tx.prepare_cached(
                    "INSERT INTO alert_evidence_answers(alert_id, answer_id, source, wire) VALUES (?1, ?2, 'log', ?3)",
                )?
                .execute(params![alert_id, aid, w])?;
            }
            tx.prepare_cached("UPDATE alert_evidence_rules SET copies = copies + 1 WHERE alert_id = ?1")?
                .execute([alert_id])?;
            // Half the first, half the latest: past the cap, the oldest of the latest half goes.
            let count: i64 = tx
                .prepare_cached("SELECT count(*) FROM alert_evidence WHERE alert_id = ?1")?
                .query_row([alert_id], |row| row.get(0))?;
            let cap = i64::from(per_alert.max(2));
            if count > cap {
                let half = cap / 2;
                let victim: Option<(i64, i64, Option<String>)> = tx
                    .prepare_cached(
                        "SELECT id, octet_length(record_json), json_extract(record_json, '$.answer_id') FROM alert_evidence
                         WHERE alert_id = ?1 ORDER BY ts, id LIMIT 1 OFFSET ?2",
                    )?
                    .query_row(params![alert_id, half], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })
                    .optional()?;
                if let Some((id, bytes, aid)) = victim {
                    tx.prepare_cached("DELETE FROM alert_evidence WHERE id = ?1")?
                        .execute([id])?;
                    let mut freed = u64::try_from(bytes).unwrap_or(0);
                    if let Some(aid) = aid {
                        freed = freed.saturating_add(
                            u64::try_from(drop_unreferenced_answer(tx, alert_id, &aid)?).unwrap_or(0),
                        );
                    }
                    // Given back by the caller after its commit (a rollback restores the copy).
                    out.freed = freed;
                }
            }
        }
        let after = self.used();
        out.bytes = i64::try_from(after).unwrap_or(i64::MAX)
            - i64::try_from(before).unwrap_or(i64::MAX)
            - i64::try_from(out.freed).unwrap_or(i64::MAX);
        Ok(out)
    }
}

/// Deletes alert `alert_id`'s copy of answer `aid` when no kept copy references it; returns the
/// bytes freed.
fn drop_unreferenced_answer(tx: &Transaction<'_>, alert_id: i64, aid: &str) -> rusqlite::Result<i64> {
    let used = tx
        .prepare_cached(
            "SELECT 1 FROM alert_evidence WHERE alert_id = ?1 AND json_extract(record_json, '$.answer_id') = ?2 LIMIT 1",
        )?
        .exists(params![alert_id, aid])?;
    if used {
        return Ok(0);
    }
    let bytes: i64 = tx
        .query_row(
            "SELECT coalesce(sum(octet_length(wire)), 0) FROM alert_evidence_answers WHERE alert_id = ?1 AND answer_id = ?2 AND source = 'log'",
            params![alert_id, aid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    tx.execute(
        "DELETE FROM alert_evidence_answers WHERE alert_id = ?1 AND answer_id = ?2 AND source = 'log'",
        params![alert_id, aid],
    )?;
    Ok(bytes)
}

/// A rule's backfill (`alert_evidence_rules.backfill_json`): per partition, oldest first, the
/// rowid copied through so far and the last rowid to copy (the partition's `analysis` progress
/// when the rule was made: later records are live capture's).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backfill {
    pub todo: Vec<(String, i64, i64)>,
}

/// The backfill of a rule made now, in `c`'s transaction: every partition's `analysis` progress
/// (core.db `log_progress`), the newest [`MAX_BACKFILL_HOURS`] of them.
fn backfill_now(c: &Connection) -> rusqlite::Result<Backfill> {
    let mut st = c.prepare_cached(
        "SELECT hour, value FROM log_progress WHERE kind = 'analysis' AND value > 0 ORDER BY hour DESC LIMIT ?1",
    )?;
    let mut todo: Vec<(String, i64, i64)> = st
        .query_map([MAX_BACKFILL_HOURS], |r| {
            Ok((r.get::<_, String>(0)?, 0, r.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    todo.reverse();
    Ok(Backfill { todo })
}

/// Stores alert `alert_id`'s rule with its backfill (see the module docs), in `c`'s
/// transaction, when the alert exists and has no rule yet; true when it made one.
fn insert_rule_in(c: &Connection, alert_id: i64, rule: &EvidenceRule) -> rusqlite::Result<bool> {
    let have = c
        .prepare_cached("SELECT 1 FROM alert_evidence_rules WHERE alert_id = ?1")?
        .exists([alert_id])?;
    if have {
        return Ok(false);
    }
    let bf = backfill_now(c)?;
    let bf_json = (!bf.todo.is_empty()).then(|| serde_json::to_string(&bf).unwrap_or_default());
    let j = serde_json::to_string(rule).unwrap_or_else(|_| "{}".into());
    let n = c
        .prepare_cached(
            "INSERT OR IGNORE INTO alert_evidence_rules(alert_id, rule_json, created_at, domain, answers, has_ips, backfill_json)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE EXISTS (SELECT 1 FROM alerts WHERE id = ?1)",
        )?
        .execute(params![
            alert_id,
            j,
            crate::util::now_ts(),
            rule.lookup_domain(),
            rule.answers,
            !rule.ips.is_empty(),
            bf_json
        ])?;
    Ok(n > 0)
}

/// Re-derives the rules' lookup columns from `rule_json` where they are missing (a rule stored or
/// restored without them); with `restored_at`, also drops the backfills of rules made before
/// then (after a restore: the logs they named are gone, core.md §2).
fn normalize_rules(c: &Connection, restored_at: Option<&str>) -> rusqlite::Result<()> {
    let rows: Vec<(i64, String)> = {
        let mut st = c.prepare(
            "SELECT alert_id, rule_json FROM alert_evidence_rules
             WHERE domain = '' AND answers = 0 AND has_ips = 0 LIMIT 100000",
        )?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (id, j) in rows {
        let Ok(rule) = serde_json::from_str::<EvidenceRule>(&j) else {
            continue;
        };
        c.execute(
            "UPDATE alert_evidence_rules SET domain = ?2, answers = ?3, has_ips = ?4 WHERE alert_id = ?1",
            params![id, rule.lookup_domain(), rule.answers, !rule.ips.is_empty()],
        )?;
    }
    if let Some(at) = restored_at {
        c.execute(
            "UPDATE alert_evidence_rules SET backfill_json = NULL WHERE backfill_json IS NOT NULL AND created_at <= ?1",
            [at],
        )?;
    }
    Ok(())
}

/// Raises `spec` (a security alert) in `tx` and, when the alert has no evidence rule yet, stores
/// `rule` with its backfill in the same transaction, so a stop right after the commit still
/// copies the window's records (README §2 Restarts) and capture later in `tx` already sees the
/// rule. Returns the alert's id when it made the rule: after the commit, call
/// [`wake_backfills`].
pub fn raise_security_with_rule_in(
    alerts: &Alerts,
    tx: &Transaction<'_>,
    spec: &RaiseSpec,
    rule: &EvidenceRule,
    ch: &mut Changes,
) -> rusqlite::Result<Option<i64>> {
    let Some(a) = alerts.raise_in(tx, spec, ch)? else {
        return Ok(None);
    };
    Ok(insert_rule_in(tx, a.id, rule)?.then_some(a.id))
}

/// Starts evidence capture for alert `alert_id` (a security alert just raised, new or reopened
/// with no rule yet, by a caller that used [`raise_security_in`]): stores the rule with its
/// backfill, then wakes the backfill worker (or, when none runs, backfills here). Idempotent;
/// a rule stored earlier only has its backfill resumed.
pub async fn start(state: &AppState, alert_id: i64, rule: EvidenceRule) -> anyhow::Result<()> {
    start_since(state, state.restore.generation(), alert_id, rule).await
}

/// [`start`] for an alert raised in restore generation `generation`
/// ([`crate::config::export::RestoreGate`]): after a restore it stores and copies nothing, since
/// the restored alert with that id is another one (core.md §2).
pub async fn start_since(
    state: &AppState,
    generation: u64,
    alert_id: i64,
    rule: EvidenceRule,
) -> anyhow::Result<()> {
    let gate = state.restore.clone();
    let current = state
        .db
        .write(move |c| {
            if !gate.is_current(generation) {
                return Ok(false);
            }
            insert_rule_in(c, alert_id, &rule)?;
            Ok::<_, anyhow::Error>(true)
        })
        .await?;
    if !current {
        return Ok(());
    }
    if state.analysis.capture.worker.load(Ordering::SeqCst) {
        wake_backfills(state);
        return Ok(());
    }
    run_backfill(state, generation, alert_id).await
}

/// Runs alert `alert_id`'s backfill to its end here (callers without the worker, and tests).
pub async fn run_backfill(state: &AppState, generation: u64, alert_id: i64) -> anyhow::Result<()> {
    // Bounded: each step finishes a window of one partition; a backfill names at most
    // MAX_BACKFILL_HOURS partitions of bounded size.
    while backfill_step(state, generation, alert_id).await? == Step::More {}
    Ok(())
}

/// What one backfill step did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// There is more to copy.
    More,
    /// The backfill is done (or the rule is gone).
    Done,
    /// A restore committed since `generation`: nothing was written, and the backfill this
    /// generation started is over (core.md §2).
    Stopped,
}

/// One backfill step of alert `alert_id` (see the module docs): reads one window of the first
/// partition with work left, then copies and counts its matching records and advances the work
/// in one transaction, only while no restore committed since `generation` and the work is still
/// what this step read.
pub async fn backfill_step(state: &AppState, generation: u64, alert_id: i64) -> anyhow::Result<Step> {
    let row: Option<(String, Option<String>)> = state
        .db
        .read(move |c| {
            Ok::<_, anyhow::Error>(
                c.query_row(
                    "SELECT rule_json, backfill_json FROM alert_evidence_rules WHERE alert_id = ?1",
                    [alert_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?,
            )
        })
        .await?;
    let Some((rule_json, Some(read_json))) = row else {
        return Ok(Step::Done);
    };
    let rule: Option<EvidenceRule> = serde_json::from_str(&rule_json).ok();
    let mut bf: Backfill = serde_json::from_str(&read_json).unwrap_or_default();
    let mut recs: Vec<Rec> = Vec::new();
    match (rule, bf.todo.first().cloned()) {
        (Some(rule), Some((hour_key, done, last))) => {
            let store = state.logs.writer().store().clone();
            let r2 = rule.clone();
            let (found, next) = tokio::task::spawn_blocking(move || -> anyhow::Result<(Vec<Rec>, i64)> {
                let Some(hour) = super::partition::parse_hour_key(&hour_key) else {
                    return Ok((Vec::new(), last));
                };
                // A partition retention deleted holds nothing left to copy.
                let Some(p) = store.open(&hour, false)? else {
                    return Ok((Vec::new(), last));
                };
                if r2.needs_answers() {
                    // Names and addresses in answers aren't indexed: every record of the window
                    // is read and matched here.
                    let to = done.saturating_add(BACKFILL_STEP).min(last);
                    let recs = super::record::load(
                        &p,
                        "WHERE e.rowid > ?1 AND e.rowid <= ?2 ORDER BY e.rowid",
                        &[&done, &to],
                    )?;
                    Ok((recs.into_iter().filter(|r| r2.matches(r)).collect(), to))
                } else {
                    // The name filter first, then the page: every matching record is read.
                    let d = r2.lookup_domain();
                    let like = format!(
                        "%.{}",
                        d.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
                    );
                    let recs = super::record::load(
                        &p,
                        "WHERE e.rowid > ?1 AND e.rowid <= ?2 AND (e.qname = ?3 OR e.qname LIKE ?4 ESCAPE '\\')
                         ORDER BY e.rowid LIMIT ?5",
                        &[&done, &last, &d, &like, &BACKFILL_STEP],
                    )?;
                    let next = if crate::util::sat_i64(recs.len()) >= BACKFILL_STEP {
                        recs.last().map_or(last, |r| r.rowid)
                    } else {
                        last
                    };
                    Ok((recs.into_iter().filter(|r| r2.matches(r)).collect(), next))
                }
            })
            .await??;
            recs = found;
            if next >= last {
                bf.todo.remove(0);
            } else if let Some(first) = bf.todo.first_mut() {
                first.1 = next;
            }
        }
        // A rule that doesn't parse copies nothing; no work left: done.
        _ => bf.todo.clear(),
    }
    let new_json = (!bf.todo.is_empty()).then(|| serde_json::to_string(&bf).unwrap_or_default());
    let more = new_json.is_some();
    let settings = state.settings();
    let per_alert = settings.alerts.evidence_per_alert;
    let total = u64::from(settings.alerts.evidence_total_mib) * 1024 * 1024;
    let an = state.analysis.clone();
    let gate = state.restore.clone();
    let alerts = state.alerts.clone();
    let outcome = state
        .db
        .write(move |c| {
            if !gate.is_current(generation) {
                return Ok(Step::Stopped);
            }
            let tx = c.transaction()?;
            an.capture.ensure_counted(&tx)?;
            let cur: Option<Option<String>> = tx
                .query_row(
                    "SELECT backfill_json FROM alert_evidence_rules WHERE alert_id = ?1",
                    [alert_id],
                    |r| r.get(0),
                )
                .optional()?;
            if cur.flatten().as_deref() != Some(read_json.as_str()) {
                // Another step, a delete or a restore changed the work since it was read: copy
                // nothing (keeping what ensure_counted did); the next step reads it again.
                tx.commit()?;
                return Ok(Step::More);
            }
            let mut freed = 0u64;
            let mut touched = Touched::default();
            for r in &recs {
                let copied = an.capture.copy_in(&tx, alert_id, r, per_alert, total)?;
                freed = freed.saturating_add(copied.freed);
                if copied.counted {
                    touched.add(alert_id);
                }
            }
            tx.execute(
                "UPDATE alert_evidence_rules SET backfill_json = ?2 WHERE alert_id = ?1",
                params![alert_id, new_json],
            )?;
            tx.commit()?;
            // What the copies evicted goes back to the budget only now it is gone for good.
            an.capture.release(freed);
            alerts.evidence_changed(c, &touched);
            Ok::<_, anyhow::Error>(if more { Step::More } else { Step::Done })
        })
        .await?;
    Ok(outcome)
}

/// Drops the first partition of alert `alert_id`'s backfill (a step failing there again and
/// again: README §2, a bad item never stalls the receiver).
async fn skip_backfill_partition(state: &AppState, alert_id: i64) -> anyhow::Result<()> {
    state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let cur: Option<String> = tx
                .query_row(
                    "SELECT backfill_json FROM alert_evidence_rules WHERE alert_id = ?1",
                    [alert_id],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            if let Some(j) = cur {
                let mut bf: Backfill = serde_json::from_str(&j).unwrap_or_default();
                if !bf.todo.is_empty() {
                    bf.todo.remove(0);
                }
                let new_json = (!bf.todo.is_empty()).then(|| serde_json::to_string(&bf).unwrap_or_default());
                tx.execute(
                    "UPDATE alert_evidence_rules SET backfill_json = ?2 WHERE alert_id = ?1",
                    params![alert_id, new_json],
                )?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
}

/// Wakes the backfill worker (after a commit that made rules with [`raise_security_with_rule_in`]).
pub fn wake_backfills(state: &AppState) {
    state.analysis.capture.wake.notify_one();
}

/// Starts the backfill worker once (later calls only wake it): it recounts the budget before
/// anything is admitted, then works through every rule with a backfill left, one step of each
/// in turn (so one large backfill doesn't hold up the others), each step a light-lane job, and
/// resumes what a restart interrupted (README §2 Restarts). It also hooks alert deletes, so the
/// budget is recounted after one.
pub fn start_backfills(state: &SharedState) {
    let cap = &state.analysis.capture;
    if cap.worker.swap(true, Ordering::SeqCst) {
        cap.wake.notify_one();
        return;
    }
    hook_deletes(state);
    let st = state.clone();
    tokio::spawn(async move {
        let an = st.analysis.clone();
        if let Err(e) = st
            .db
            .write(move |c| Ok::<_, anyhow::Error>(an.capture.ensure_counted(c)?))
            .await
        {
            tracing::warn!(error = %format!("{e:#}"), "cannot count the evidence budget");
        }
        let mut failures: HashMap<i64, u32> = HashMap::new();
        loop {
            let ids: Vec<i64> = match st
                .db
                .read(|c| {
                    let mut s = c.prepare(
                        "SELECT alert_id FROM alert_evidence_rules WHERE backfill_json IS NOT NULL ORDER BY alert_id LIMIT 256",
                    )?;
                    let v = s
                        .query_map([], |r| r.get::<_, i64>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok::<_, anyhow::Error>(v)
                })
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "cannot list evidence backfills");
                    Vec::new()
                }
            };
            if ids.is_empty() {
                failures.clear();
                tokio::select! {
                    _ = st.shutdown.cancelled() => return,
                    _ = st.analysis.capture.wake.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                }
                continue;
            }
            for id in ids {
                if st.shutdown.is_cancelled() {
                    return;
                }
                let generation = st.restore.generation();
                let st2 = st.clone();
                let job = st.scheduler.light.spawn(Some("evidence_backfill"), async move {
                    backfill_step(&st2, generation, id).await
                });
                let Some(job) = job else {
                    // The light lane is at its admission cap: try again shortly.
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    break;
                };
                let failed = match job.await {
                    Ok(Ok(_)) => {
                        failures.remove(&id);
                        None
                    }
                    Ok(Err(e)) => Some(format!("{e:#}")),
                    // A step that panics counts as a failure too: retried at once without a
                    // limit, it would spin on one CPU core (README §2: a bad item never stalls
                    // the receiver).
                    Err(e) => Some(format!("the step's task ended: {e}")),
                };
                if let Some(e) = failed {
                    let n = failures.entry(id).or_insert(0);
                    *n += 1;
                    tracing::warn!(error = %e, alert = id, attempt = *n, "evidence backfill step failed");
                    if *n >= 3 {
                        failures.remove(&id);
                        if let Err(e) = skip_backfill_partition(&st, id).await {
                            tracing::warn!(error = %format!("{e:#}"), alert = id, "cannot skip a failing evidence backfill partition");
                        }
                    }
                }
            }
        }
    });
}

/// Hooks alert deletes (both UI endpoints go through [`Alerts::delete`], which deletes the
/// alert's evidence and rule in its own transaction), so the budget is recounted before the next
/// admission.
fn hook_deletes(state: &AppState) {
    let an = state.analysis.clone();
    state
        .alerts
        .on_evidence_deleted(Arc::new(move || an.capture.forget_count()));
}

/// The suffixes of log-text `name` at label boundaries, the name first (lowercase).
fn suffixes(name: &str) -> Vec<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut out = Vec::new();
    let mut s = name.as_str();
    loop {
        if !s.is_empty() {
            out.push(s.to_string());
        }
        match s.find('.') {
            Some(i) => s = &s[i + 1..],
            None => break,
        }
    }
    out
}

/// The evidence rules one analysis transaction captures with (core.md §9 Evidence), read once
/// and used for each of its records ([`Capturing::record`]), so a record's capture can run on its
/// own (a savepoint per record) without reading the rules again.
pub struct Capturing {
    any: bool,
    answer_rules: bool,
    ip_rules: Vec<(i64, EvidenceRule)>,
}

impl Capturing {
    /// Reads what `tx`'s capture needs (after a recount of the budget when one is due).
    pub fn prepare(cap: &Capture, tx: &Transaction<'_>) -> rusqlite::Result<Capturing> {
        let any: bool = tx
            .prepare_cached("SELECT EXISTS (SELECT 1 FROM alert_evidence_rules)")?
            .query_row([], |r| r.get(0))?;
        if !any {
            return Ok(Capturing {
                any,
                answer_rules: false,
                ip_rules: Vec::new(),
            });
        }
        cap.ensure_counted(tx)?;
        let answer_rules: bool = tx
            .prepare_cached("SELECT EXISTS (SELECT 1 FROM alert_evidence_rules WHERE answers <> 0)")?
            .query_row([], |r| r.get(0))?;
        let ip_rules: Vec<(i64, EvidenceRule)> = {
            let mut st = tx.prepare_cached(
                "SELECT alert_id, rule_json FROM alert_evidence_rules WHERE has_ips <> 0 LIMIT 100000",
            )?;
            st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .filter_map(|(id, j)| serde_json::from_str::<EvidenceRule>(&j).ok().map(|r| (id, r)))
                .collect()
        };
        Ok(Capturing {
            any,
            answer_rules,
            ip_rules,
        })
    }

    /// Copies record `r` into the alerts whose rule it matches, inside `tx`, adding to `touched`
    /// each alert whose evidence it changed. Returns (copies made, bytes their evictions freed:
    /// the caller gives them back after its commit).
    pub fn record(
        &self,
        cap: &Capture,
        tx: &Transaction<'_>,
        r: &Rec,
        per_alert: u32,
        total_bytes: u64,
        touched: &mut Touched,
    ) -> rusqlite::Result<(usize, u64)> {
        // Domain rules are read by index for each record, so a rule made in `tx` after
        // [`Capturing::prepare`] still takes part. (The analysis prepares once its batch's
        // effects, and so its raises, are in, core.md §9; address rules come from retro-match,
        // never from inside an analysis transaction.)
        if !self.any
            && !tx
                .prepare_cached("SELECT EXISTS (SELECT 1 FROM alert_evidence_rules)")?
                .query_row([], |r| r.get::<_, bool>(0))?
        {
            return Ok((0, 0));
        }
        cap.ensure_counted(tx)?;
        let parse = |id: i64, j: String| serde_json::from_str::<EvidenceRule>(&j).ok().map(|r| (id, r));
        let mut by_domain =
            tx.prepare_cached("SELECT alert_id, rule_json FROM alert_evidence_rules WHERE domain = ?1")?;
        let mut cands: BTreeMap<i64, EvidenceRule> = BTreeMap::new();
        for s in suffixes(&r.qname) {
            for row in by_domain.query_map([&s], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, String>(1)?)))? {
                let (id, j) = row?;
                if let Some((id, rule)) = parse(id, j) {
                    cands.insert(id, rule);
                }
            }
        }
        let av = (self.answer_rules || !self.ip_rules.is_empty()).then(|| r.answer_values());
        if let Some(av) = &av {
            if self.answer_rules {
                for v in av.cname.iter().chain(av.targets.iter()) {
                    for s in suffixes(&v.text()) {
                        for row in by_domain
                            .query_map([&s], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, String>(1)?)))?
                        {
                            let (id, j) = row?;
                            if let Some((id, rule)) = parse(id, j)
                                && rule.answers
                            {
                                cands.insert(id, rule);
                            }
                        }
                    }
                }
            }
            for (id, rule) in &self.ip_rules {
                cands.entry(*id).or_insert_with(|| rule.clone());
            }
        }
        let (mut n, mut freed) = (0usize, 0u64);
        for (id, rule) in cands {
            let hit = rule.filters(r)
                && (under(&r.qname, &rule.domain)
                    || av
                        .as_ref()
                        .is_some_and(|av| rule.needs_answers() && rule.matches_answer(av)));
            if hit {
                let c = cap.copy_in(tx, id, r, per_alert, total_bytes)?;
                freed = freed.saturating_add(c.freed);
                n += usize::from(c.copied);
                if c.counted {
                    touched.add(id);
                }
            }
        }
        Ok((n, freed))
    }
}

/// Copies each of `recs` into the evidence of every alert whose rule it matches, in `tx` (live
/// capture: the analysis does it in each batch's transaction, before the batch's `analysis`
/// progress moves). Rules are read by index inside `tx`, so a rule made earlier in `tx` takes
/// part and a deleted alert's never does; each record is copied and counted at most once per
/// alert. Adds each alert whose evidence changed to `touched` (the caller notes them after its
/// commit, [`Alerts::evidence_changed`]). Returns (copies made, bytes their evictions freed: the
/// caller gives them back after its commit, [`Capture::release`]).
pub fn capture_in(
    cap: &Capture,
    tx: &Transaction<'_>,
    recs: &[&Rec],
    per_alert: u32,
    total_bytes: u64,
    touched: &mut Touched,
) -> rusqlite::Result<(usize, u64)> {
    if recs.is_empty() {
        return Ok((0, 0));
    }
    let ctx = Capturing::prepare(cap, tx)?;
    let (mut n, mut freed) = (0usize, 0u64);
    for r in recs {
        let (c, f) = ctx.record(cap, tx, r, per_alert, total_bytes, touched)?;
        n += c;
        freed = freed.saturating_add(f);
    }
    Ok((n, freed))
}

/// Raises or resolves `alert_evidence_full` from the bytes in use (core.md §9: warning past
/// 80 %, critical when full), recounted on the writer so the count is exact.
pub async fn check_budget(state: &AppState, alerts: &Alerts) -> anyhow::Result<u64> {
    hook_deletes(state);
    let an = state.analysis.clone();
    let used = state
        .db
        .write(move |c| {
            an.capture.ensure_counted(c)?;
            Ok::<_, anyhow::Error>(an.capture.recount(c)?)
        })
        .await?;
    let total = u64::from(state.settings().alerts.evidence_total_mib) * 1024 * 1024;
    let key = "alert_evidence_full";
    if used.saturating_mul(5) >= total.saturating_mul(4) {
        let full = used >= total;
        let spec = RaiseSpec::new(
            key,
            if full {
                Severity::Critical
            } else {
                Severity::Warning
            },
            key,
            if full {
                "Alert evidence is full: new records aren't copied".to_string()
            } else {
                "Alert evidence is over 80 % of alerts.evidence_total_mib".to_string()
            },
            serde_json::json!({"used_bytes": used, "total_bytes": total}),
        );
        let open = alerts.get_by_key(key).await?;
        let same = open
            .as_ref()
            .is_some_and(|a| a.state == crate::alerts::AlertState::Open && a.severity == spec.severity);
        if !same {
            alerts.raise(spec).await?;
        }
    } else {
        alerts
            .resolve(key, Some(serde_json::json!({"used_bytes": used})))
            .await?;
    }
    Ok(used)
}

/// Raises `spec` in `tx` and, for a security alert without an evidence rule yet, returns its id
/// so its evidence capture starts ([`start`]) after the commit. Prefer
/// [`raise_security_with_rule_in`], which stores the rule in the same transaction.
pub fn raise_security_in(
    alerts: &Alerts,
    tx: &Transaction<'_>,
    spec: &RaiseSpec,
    ch: &mut Changes,
) -> rusqlite::Result<Option<i64>> {
    let had_rule: bool = tx
        .query_row(
            "SELECT 1 FROM alert_evidence_rules r JOIN alerts a ON a.id = r.alert_id WHERE a.dedupe_key = ?1",
            [&spec.dedupe_key],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let a = alerts.raise_in(tx, spec, ch)?;
    Ok(a.filter(|_| !had_rule).map(|a| a.id))
}

/// The handle the rest of core uses (cheap clone).
pub type CaptureRef = Arc<Capture>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_under_a_domain() {
        assert!(under("example.com", "example.com"));
        assert!(under("a.b.Example.com", "example.com"));
        assert!(!under("badexample.com", "example.com"));
        assert!(!under("example.com.evil", "example.com"));
        assert!(!under("x", ""));
    }

    #[test]
    fn rules_match_device_profile_and_decision() {
        let r = Rec {
            qname: "ads.example.com".into(),
            client_ip: "192.0.2.7".into(),
            profile: Some("kids".into()),
            decision: "block".into(),
            ..Default::default()
        };
        let mut rule = EvidenceRule {
            domain: "example.com".into(),
            device: Some("192.0.2.7".into()),
            ..Default::default()
        };
        assert!(rule.matches(&r), "a device without a name is its address");
        rule.profiles = vec!["adults".into()];
        assert!(!rule.matches(&r));
        rule.profiles.clear();
        rule.decisions = vec!["allow".into()];
        assert!(!rule.matches(&r));
    }

    #[test]
    fn answer_rules_match_names_and_addresses_in_the_answer() {
        let r = Rec {
            qname: "front.example".into(),
            decision: "allow".into(),
            cname: vec!["cdn.bad.example".into()],
            answers: vec!["192.0.2.77".into()],
            ..Default::default()
        };
        let mut rule = EvidenceRule {
            domain: "bad.example".into(),
            ..Default::default()
        };
        assert!(!rule.matches(&r), "the query name alone isn't under bad.example");
        rule.answers = true;
        assert!(rule.matches(&r));
        let by_ip = EvidenceRule {
            domain: "other.example".into(),
            ips: vec!["::ffff:192.0.2.77".into()],
            ..Default::default()
        };
        assert!(by_ip.matches(&r), "addresses compare in canonical form");
        assert_eq!(
            suffixes("A.b.Example."),
            vec!["a.b.example", "b.example", "example"]
        );
    }
}
