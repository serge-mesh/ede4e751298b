//! `category_answered` from lookup providers' Blocks (core.md §7, §9).
//!
//! A client got a real answer (allowed, or rewritten with records: a `$dnsrewrite` that returns
//! only an rcode counts as a block) for a name a provider's Block marks bad, from any source: an
//! edge's sync lookup or late answer, or core's async lookup, retry or re-check. It fires when the
//! Block and an answer of that name both exist within the retention window, in either order,
//! checked when either arrives, for answers in profiles whose `alert_providers` include the
//! provider (a profile with `log: off` sends no answers):
//!
//! - **A Block arrives** (a new `lookup_blocks` row): this module's worker claims it
//!   (`answers_checked` 1), scans the hourly partitions in the window for real answers of the name
//!   in those profiles, raises the alert when it finds any not yet counted, and marks the Block
//!   done (2). A restart resumes claimed Blocks. The claim reads the restore generation in its own
//!   transaction, so it never claims a Block of a restored state under the generation before it
//!   (core.md §2). The alert and the mark commit only while the Block is still the one claimed,
//!   of its provider's current generation, and no restore committed since the claim
//!   (providers.md §4 Cache generation): a flush or restore during the scan deletes the Block,
//!   and Block ids are never reused, so a stale scan raises nothing and marks no other Block. A
//!   pass gives back every claim it didn't finish (an error, a rejected commit), so no Block stays
//!   claimed until a restart.
//! - **An answer arrives** ([`super::ingest`]): it is checked against the Blocks already claimed
//!   or done (`answers_checked` ≠ 0) for its name; a Block still unclaimed finds the answer in its
//!   own scan, since the answer is in its partition before the ingest's check runs.
//!
//! **Each answer counts once** (core.md §9 Dedupe; the count means occurrences): the answers a
//! provider's alert has counted for a name are kept in `lookup_answers_counted` (edge, boot,
//! seq), written in the transaction that raises the alert, by the scan and by the ingest alike.
//! Only answers not counted yet raise, and the count goes up by them: a later Block row of the
//! name (another edge's sync lookup, core's next lookup after the Block TTL) scans the same
//! answers and adds nothing; an answer the scan found and whose own ingest check runs after it,
//! or one the ingest counted while the scan that read it was still running, counts once. Per
//! (provider, name) the newest [`MAX_COUNTED`] are kept (README §2 Bounded), newest by
//! [`AnswerKey`] (time, then edge, boot and seq), the order a scan reads in too: a scan reads at
//! most the newest [`MAX_ANSWERS`], so it never meets an identity forgotten before it started. Nor
//! one forgotten while it runs: a running scan holds its answers ([`ScanHolds`]; all of them while
//! it reads, then those from its oldest answer up), and only identities older than every hold of
//! the name are forgotten until it commits, so many newer answers counted meanwhile never make
//! it count its own again. A hold yields only past [`MAX_COUNTED_HELD`]. The rest leave with the
//! log retention window, which respects the holds too ([`forget_counted_in`]): a scan reading
//! answers right at the window's edge keeps their identities until it commits, and a scan's
//! window starts only once its hold is taken, so retention never forgets an identity a scan
//! that started before it may still read.
//!
//! The alert keys on (provider, registrable domain) ([`crate::alerts::category_answered_key`]),
//! names the provider with its reason and detail, and offers the line for a one-click "add to
//! manual block feed". Evidence goes through the shared capture ([`crate::logs::evidence`]): a
//! new alert's rule (the registrable domain, the alerting profiles, real answers) is stored with
//! its backfill in the transaction that raises the alert, so a stop right after the commit still
//! copies the window's matching records; then each new one is copied as it is ingested.

use std::time::Duration;

use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::alerts::{AnsweredBy, Changes, RaiseSpec};
use crate::config::Model;
use crate::state::{AppState, SharedState};

/// Blocks checked per pass.
const BATCH: i64 = 64;
/// Answers copied per Block found (README §2 Bounded; evidence keeps at most
/// `alerts.evidence_per_alert` per alert).
pub const MAX_ANSWERS: i64 = 100;
/// Counted answers kept per (provider, name) (module docs): twice what one scan reads, so a scan
/// never meets an answer whose identity was forgotten. Policy choice.
pub const MAX_COUNTED: i64 = 2 * MAX_ANSWERS;
/// Counted answers kept per (provider, name) while running scans hold older ones (README §2
/// Bounded; module docs): past it the oldest go even so, and a scan holding them may count them
/// again. A policy choice far above what arrives while a scan runs (each partition it reads
/// waits at most two seconds for a lock).
pub const MAX_COUNTED_HELD: i64 = 50 * MAX_COUNTED;

/// A provider's Block as `lookup_blocks` holds it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BlockInfo {
    pub id: i64,
    pub provider: String,
    pub name: String,
    pub obtained_at: String,
    /// `core`, or the edge whose log carried it.
    pub source: String,
    pub reason: Option<String>,
    pub detail: Option<Value>,
}

/// One answer a client got, as evidence.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AnswerRef {
    pub edge: String,
    pub boot: String,
    pub seq: i64,
    pub ts: String,
    pub profile: Option<String>,
    pub client: Option<String>,
    pub device: Option<String>,
    pub qname: String,
}

/// The alert for a Block and the answers newly counted for its name: it stands for that many
/// occurrences (the count goes up by them, as the grouped raises of retro-match do).
pub fn spec(model: &Model, b: &BlockInfo, answers: usize) -> RaiseSpec {
    let p = model.lookup_providers.get(&b.provider);
    let security = p.is_some_and(|p| p.category == crate::config::model::Category::Security);
    let domain = crate::psl::grouping_key(&b.name);
    let pname = p.map(|p| p.name.clone()).unwrap_or_default();
    RaiseSpec::new(
        "category_answered",
        crate::alerts::category_answered_severity(security),
        crate::alerts::category_answered_key(AnsweredBy::Provider(&b.provider), &b.name),
        format!(
            "A client got an answer for {} that lookup provider {} blocks",
            b.name, b.provider
        ),
        json!({
            "by": "provider",
            "provider": b.provider,
            "provider_name": pname,
            "name": b.name,
            "domain": domain,
            "reason": b.reason,
            "detail": b.detail,
            "obtained_at": b.obtained_at,
            "block_source": b.source,
            "answers": answers,
            "add_to_manual_block": {"feed": "manual-block", "line": format!("||{domain}^")},
        }),
    )
    .occurrences(u32::try_from(answers).unwrap_or(u32::MAX))
}

/// Profiles whose answers alert on `provider`, with `log` not `off`.
pub fn alerting_profiles(model: &Model, provider: &str) -> Vec<String> {
    model
        .profiles
        .values()
        .filter(|p| p.edge.log != picket_api::edge_config::LogLevel::Off)
        .filter(|p| super::alert_providers(model, p).iter().any(|x| x == provider))
        .map(|p| p.id.clone())
        .collect()
}

/// The evidence rule of a provider's `category_answered` alert: the records of names under the
/// registrable domain, in the profiles alerting on the provider, that got real answers.
pub fn evidence_rule(model: &Model, provider: &str, name: &str) -> crate::logs::evidence::EvidenceRule {
    crate::logs::evidence::EvidenceRule {
        domain: crate::psl::grouping_key(name),
        device: None,
        profiles: alerting_profiles(model, provider),
        decisions: vec!["allow".into(), "rewrite".into()],
        ..Default::default()
    }
}

/// At start: Blocks claimed by a check that didn't finish are checked again (README §2
/// Restarts).
pub async fn recover(state: &AppState) -> anyhow::Result<()> {
    state
        .db
        .write(|c| {
            c.execute(
                "UPDATE lookup_blocks SET answers_checked = 0 WHERE answers_checked = 1",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
}

/// The worker: checks new Blocks against the answers in the window.
pub async fn run(state: SharedState) {
    loop {
        let more = match pass(&state).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "checking provider Blocks against answers failed");
                false
            }
        };
        if more {
            continue;
        }
        tokio::select! {
            _ = state.shutdown.cancelled() => return,
            _ = state.lookups.blocks_wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
    }
}

/// One answer as an alert counts it (module docs): its record's identity and time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountedAnswer<'a> {
    pub edge: &'a str,
    pub boot: &'a str,
    pub seq: i64,
    pub ts: String,
}

/// An answer's place in the order the counted answers are kept and scans read in (module docs):
/// time, then edge, boot and seq, compared as `lookup_answers_counted` sorts them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnswerKey {
    pub ts: String,
    pub edge: String,
    pub boot: String,
    pub seq: i64,
}

impl AnswerKey {
    fn of(a: &AnswerRef) -> Self {
        Self {
            ts: a.ts.clone(),
            edge: a.edge.clone(),
            boot: a.boot.clone(),
            seq: a.seq,
        }
    }
}

/// What running scans of a (provider, name) hold ([`ScanHolds::spared`]).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Spared {
    /// No scan of the name runs.
    Nothing,
    /// The identities from this answer up.
    From(AnswerKey),
    /// Every identity: a scan is still reading.
    All,
}

/// The counted answers running scans hold (module docs), per (provider, name): each scan's
/// oldest answer, or none yet while it reads. Bounded by the scans running (one at a time in the
/// worker).
#[derive(Debug, Default)]
pub struct ScanHolds {
    next: std::sync::atomic::AtomicU64,
    held: std::sync::Mutex<Held>,
}

/// Per (provider, name), each running scan's id and oldest answer (none while it reads).
type Held = std::collections::HashMap<(String, String), Vec<(u64, Option<AnswerKey>)>>;

/// A running scan's hold on its (provider, name) ([`ScanHolds::hold`]); dropping it lets go.
pub struct ScanHold {
    holds: std::sync::Arc<ScanHolds>,
    of: (String, String),
    id: u64,
}

impl ScanHolds {
    /// A scan of `name` for `provider` starts: it holds every identity until it has read.
    pub fn hold(self: &std::sync::Arc<Self>, provider: &str, name: &str) -> ScanHold {
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let of = (provider.to_string(), name.to_string());
        self.lock().entry(of.clone()).or_default().push((id, None));
        ScanHold {
            holds: self.clone(),
            of,
            id,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// What the running scans of (provider, name) hold.
    fn spared(&self, provider: &str, name: &str) -> Spared {
        let held = self.lock();
        let Some(scans) = held.get(&(provider.to_string(), name.to_string())) else {
            return Spared::Nothing;
        };
        let mut oldest: Option<&AnswerKey> = None;
        for (_, k) in scans {
            match k {
                None => return Spared::All,
                Some(k) => oldest = Some(oldest.map_or(k, |o| o.min(k))),
            }
        }
        oldest.map_or(Spared::Nothing, |k| Spared::From(k.clone()))
    }
}

impl ScanHold {
    /// The scan has read: it holds the identities from `oldest` up (none when it read nothing).
    pub fn read(&self, oldest: Option<AnswerKey>) {
        let mut held = self.holds.lock();
        let Some(scans) = held.get_mut(&self.of) else {
            return;
        };
        match oldest {
            Some(k) => {
                if let Some(s) = scans.iter_mut().find(|(id, _)| *id == self.id) {
                    s.1 = Some(k);
                }
            }
            None => {
                scans.retain(|(id, _)| *id != self.id);
                if scans.is_empty() {
                    held.remove(&self.of);
                }
            }
        }
    }
}

impl Drop for ScanHold {
    fn drop(&mut self) {
        self.read(None);
    }
}

/// Notes `answers` as counted by the provider's alert for `name`, in the transaction that raises
/// it (module docs): returns how many weren't counted yet. Past [`MAX_COUNTED`] for the name, the
/// oldest by [`AnswerKey`] are forgotten, except those a running scan holds (`holds`), up to
/// [`MAX_COUNTED_HELD`].
pub fn count_new(
    tx: &Transaction<'_>,
    provider: &str,
    name: &str,
    answers: &[CountedAnswer<'_>],
    holds: &ScanHolds,
) -> rusqlite::Result<usize> {
    let mut n = 0;
    {
        let mut st = tx.prepare_cached(
            "INSERT OR IGNORE INTO lookup_answers_counted(provider_id, name, edge_id, boot, seq, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for a in answers {
            n += st.execute(params![provider, name, a.edge, a.boot, a.seq, a.ts])?;
        }
    }
    if n > 0 {
        // The newest by AnswerKey stay (the order scan_answers reads in).
        const BEYOND: &str = "DELETE FROM lookup_answers_counted WHERE provider_id = ?1 AND name = ?2
               AND (edge_id, boot, seq) IN (SELECT edge_id, boot, seq FROM lookup_answers_counted
                 WHERE provider_id = ?1 AND name = ?2
                 ORDER BY ts DESC, edge_id DESC, boot DESC, seq DESC LIMIT -1 OFFSET ?3)";
        let spared = holds.spared(provider, name);
        match &spared {
            Spared::Nothing => {
                tx.prepare_cached(BEYOND)?
                    .execute(params![provider, name, MAX_COUNTED])?;
            }
            Spared::From(k) => {
                tx.prepare_cached(&format!(
                    "{BEYOND} AND (ts, edge_id, boot, seq) < (?4, ?5, ?6, ?7)"
                ))?
                .execute(params![
                    provider,
                    name,
                    MAX_COUNTED,
                    k.ts,
                    k.edge,
                    k.boot,
                    k.seq
                ])?;
            }
            Spared::All => {}
        }
        if spared != Spared::Nothing {
            let gone = tx
                .prepare_cached(BEYOND)?
                .execute(params![provider, name, MAX_COUNTED_HELD])?;
            if gone > 0 {
                tracing::warn!(
                    provider,
                    name,
                    gone,
                    "counted answers a running Block scan holds were forgotten (past their bound); it may count them again"
                );
            }
        }
    }
    Ok(n)
}

/// Retention of `lookup_answers_counted` (module docs): forgets the identities older than `cut`,
/// except those running scans hold: every identity of a (provider, name) whose scan still reads,
/// and from each scan's oldest answer up. Run in retention's writer transaction, where no
/// `count_new` runs beside it. Returns the rows forgotten.
pub fn forget_counted_in(tx: &Transaction<'_>, cut: &str, holds: &ScanHolds) -> rusqlite::Result<usize> {
    let held: Vec<((String, String), Spared)> = {
        let names: Vec<(String, String)> = holds.lock().keys().cloned().collect();
        names
            .into_iter()
            .map(|(p, n)| {
                let s = holds.spared(&p, &n);
                ((p, n), s)
            })
            .collect()
    };
    if held.is_empty() {
        return tx.execute("DELETE FROM lookup_answers_counted WHERE ts < ?1", [cut]);
    }
    let pairs = serde_json::to_string(
        &held
            .iter()
            .map(|((p, n), _)| [p.as_str(), n.as_str()])
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".into());
    // Unheld names first, then each held name above its hold.
    let mut n = tx.execute(
        "DELETE FROM lookup_answers_counted WHERE ts < ?1
           AND NOT EXISTS (SELECT 1 FROM json_each(?2) h
                           WHERE json_extract(h.value, '$[0]') = provider_id AND json_extract(h.value, '$[1]') = name)",
        params![cut, pairs],
    )?;
    for ((p, name), spared) in &held {
        match spared {
            Spared::All => {}
            Spared::Nothing => {
                n += tx.execute(
                    "DELETE FROM lookup_answers_counted WHERE ts < ?1 AND provider_id = ?2 AND name = ?3",
                    params![cut, p, name],
                )?;
            }
            Spared::From(k) => {
                n += tx.execute(
                    "DELETE FROM lookup_answers_counted WHERE ts < ?1 AND provider_id = ?2 AND name = ?3
                       AND (ts, edge_id, boot, seq) < (?4, ?5, ?6, ?7)",
                    params![cut, p, name, k.ts, k.edge, k.boot, k.seq],
                )?;
            }
        }
    }
    Ok(n)
}

/// One pass over unclaimed Blocks; true when more may wait.
pub async fn pass(state: &AppState) -> anyhow::Result<bool> {
    let gate = state.restore.clone();
    let (restore_generation, blocks): (u64, Vec<(BlockInfo, String, bool)>) = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            // Read on the writer, with the claim (core.md §2): a restore that committed before
            // this transaction is in it (its Blocks are claimed under its generation), and one
            // that commits after ends this pass's writes.
            let restore_generation = gate.generation();
            // A Block of a generation that is no longer its provider's is claimed and marked done
            // without a scan (providers.md §4: an old generation is never used).
            let rows: Vec<(BlockInfo, String, bool)> = {
                let mut st = tx.prepare(
                    "SELECT b.id, b.provider_id, b.name, b.obtained_at, b.source, b.reason, b.detail_json,
                            p.cache_generation IS NOT NULL AND p.cache_generation = b.generation, b.generation
                     FROM lookup_blocks b LEFT JOIN lookup_providers p ON p.id = b.provider_id
                     WHERE b.answers_checked = 0 ORDER BY b.id LIMIT ?1",
                )?;
                st.query_map([BATCH], |r| {
                    Ok((
                        BlockInfo {
                            id: r.get(0)?,
                            provider: r.get(1)?,
                            name: r.get(2)?,
                            obtained_at: r.get(3)?,
                            source: r.get(4)?,
                            reason: r.get(5)?,
                            detail: r
                                .get::<_, Option<String>>(6)?
                                .and_then(|s| serde_json::from_str(&s).ok()),
                        },
                        r.get::<_, String>(8)?,
                        r.get::<_, bool>(7)?,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            for (b, _, current) in &rows {
                tx.execute(
                    "UPDATE lookup_blocks SET answers_checked = ?2 WHERE id = ?1",
                    params![b.id, if *current { 1 } else { 2 }],
                )?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>((restore_generation, rows))
        })
        .await?;
    if blocks.is_empty() {
        return Ok(false);
    }
    let more = crate::util::sat_i64(blocks.len()) >= BATCH;
    let blocks: Vec<(BlockInfo, String)> = blocks
        .into_iter()
        .filter(|(.., c)| *c)
        .map(|(b, g, _)| (b, g))
        .collect();
    // The claims this pass hasn't finished: given back whatever ends it (module docs).
    let mut unfinished: Vec<i64> = blocks.iter().map(|(b, _)| b.id).collect();
    let checked = check_claimed(state, restore_generation, blocks, &mut unfinished).await;
    let released = !unfinished.is_empty();
    if released {
        let ids = std::mem::take(&mut unfinished);
        let r = state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                for id in &ids {
                    tx.execute(
                        "UPDATE lookup_blocks SET answers_checked = 0 WHERE id = ?1 AND answers_checked = 1",
                        [id],
                    )?;
                }
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await;
        if let Err(e) = r {
            // A restart gives them back (`recover`).
            tracing::warn!(error = %format!("{e:#}"), "giving back unfinished Block claims failed");
        }
    }
    checked?;
    Ok(more || released)
}

/// Checks the claimed Blocks one by one (module docs), removing each from `unfinished` once its
/// result is committed.
async fn check_claimed(
    state: &AppState,
    restore_generation: u64,
    blocks: Vec<(BlockInfo, String)>,
    unfinished: &mut Vec<i64>,
) -> anyhow::Result<()> {
    let model = state.lookups.model();
    let window = state.settings().retention.query_logs.as_duration();
    let store = crate::logs::LogStore::new(&state.data_dir);
    let mut new_rules = false;
    let checked = async {
        for (b, generation) in blocks {
            let profiles = alerting_profiles(&model, &b.provider);
            // Held from before the read until the result commits (module docs): no identity the
            // scan reads is forgotten meanwhile, however many newer answers are counted.
            let hold = state.lookups.scan_holds.hold(&b.provider, &b.name);
            // The window starts once the hold is taken (module docs): a retention that ran
            // before it cut below this window, and one after it spares what the hold covers.
            let since = crate::util::window_start(crate::util::now(), window);
            let answers = if profiles.is_empty() {
                Vec::new()
            } else {
                let (st, name, since) = (store.clone(), b.name.clone(), since);
                tokio::task::spawn_blocking(move || scan_answers(&st, &name, &profiles, since, MAX_ANSWERS))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))??
            };
            hold.read(answers.iter().map(AnswerKey::of).min());
            let holds = state.lookups.scan_holds.clone();
            let me = state.alerts.clone();
            let gate = state.restore.clone();
            let m2 = model.clone();
            let id = b.id;
            let (ch, made_rule, done) = state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    let mut ch = Changes::default();
                    // The Block must still be the one claimed, of its provider's current generation,
                    // with no restore since the claim (module docs); otherwise nothing is written.
                    let still: bool = gate.is_current(restore_generation)
                        && tx
                            .query_row(
                                "SELECT 1 FROM lookup_blocks b JOIN lookup_providers p
                               ON p.id = b.provider_id AND p.cache_generation = b.generation
                             WHERE b.id = ?1 AND b.generation = ?2 AND b.answers_checked = 1",
                                params![id, generation],
                                |_| Ok(()),
                            )
                            .optional()?
                            .is_some();
                    if !still {
                        return Ok::<_, anyhow::Error>((ch, false, false));
                    }
                    // Only answers this alert hasn't counted raise it (module docs).
                    let counted: Vec<CountedAnswer<'_>> = answers
                        .iter()
                        .map(|a| CountedAnswer {
                            edge: &a.edge,
                            boot: &a.boot,
                            seq: a.seq,
                            ts: a.ts.clone(),
                        })
                        .collect();
                    // Its answers go into the ledger with this transaction: its hold is done.
                    drop(hold);
                    let fresh = count_new(&tx, &b.provider, &b.name, &counted, &holds)?;
                    let mut made_rule = false;
                    if fresh > 0 {
                        // The alert's `edge` (core.md §9 record): the edge of the newest answer
                        // the scan found (a repeat keeps the edge first seen).
                        let mut spec = spec(&m2, &b, fresh);
                        if let Some(a) = answers.first() {
                            spec = spec.seen_on_edge(&a.edge);
                        }
                        let rule = evidence_rule(&m2, &b.provider, &b.name);
                        made_rule = crate::logs::evidence::raise_security_with_rule_in(
                            &me, &tx, &spec, &rule, &mut ch,
                        )?
                        .is_some();
                    }
                    tx.execute("UPDATE lookup_blocks SET answers_checked = 2 WHERE id = ?1", [id])?;
                    tx.commit()?;
                    me.committed(&ch);
                    Ok((ch, made_rule, true))
                })
                .await?;
            if done {
                unfinished.retain(|x| *x != id);
            }
            state.alerts.announce(ch);
            new_rules |= made_rule;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if new_rules {
        // The rules and their backfills are stored: the backfill worker copies the evidence.
        crate::logs::evidence::wake_backfills(state);
    }
    checked
}

/// The real answers of `name` in `profiles` since `since`, newest first by [`AnswerKey`] (the
/// order the counted answers are kept in, module docs; partitions hold the hours of their
/// records' times), at most `limit` (read-only; a partition that can't be read is skipped).
pub fn scan_answers(
    store: &crate::logs::LogStore,
    name: &str,
    profiles: &[String],
    since: jiff::Timestamp,
    limit: i64,
) -> anyhow::Result<Vec<AnswerRef>> {
    let mut out = Vec::new();
    let since_hour = crate::logs::partition::hour_start(&since);
    let mut parts = store.list()?;
    parts.reverse();
    let profiles_json = serde_json::to_string(profiles)?;
    let since_s = crate::util::ts(&since);
    for (hour, path) in parts {
        if hour < since_hour || crate::util::sat_i64(out.len()) >= limit {
            break;
        }
        let Ok(c) = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) else {
            continue;
        };
        let _ = c.busy_timeout(Duration::from_secs(2));
        let r = (|| -> rusqlite::Result<Vec<AnswerRef>> {
            let mut st = c.prepare(
                "SELECT edge_id, boot, seq, ts, profile, client_ip, device, qname
                 FROM events
                 WHERE qname = ?1 AND ts >= ?2 AND profile IN (SELECT value FROM json_each(?3))
                   AND rcode = 'NOERROR'
                   AND (decision = 'allow' OR (decision = 'rewrite' AND (coalesce(answers_json, '[]') <> '[]'
                        OR coalesce(targets_json, '[]') <> '[]' OR coalesce(cname_json, '[]') <> '[]'
                        OR response IS NOT NULL)))
                 ORDER BY ts DESC, edge_id DESC, boot DESC, seq DESC LIMIT ?4",
            )?;
            st.query_map(params![name, since_s, profiles_json, limit], |r| {
                let edge: String = r.get(0)?;
                let boot: String = r.get(1)?;
                let seq: i64 = r.get(2)?;
                let ts: String = r.get(3)?;
                let profile: Option<String> = r.get(4)?;
                let client: Option<String> = r.get(5)?;
                let device: Option<String> = r.get(6)?;
                let qname: String = r.get(7)?;
                Ok(AnswerRef {
                    edge,
                    boot,
                    seq,
                    ts,
                    profile,
                    client,
                    device,
                    qname,
                })
            })?
            .collect()
        })();
        match r {
            Ok(v) => out.extend(v),
            Err(e) => tracing::debug!(partition = %path.display(), error = %e, "skipping a partition"),
        }
    }
    out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    Ok(out)
}

/// Blocks of the providers `alerting` already claimed or checked for `name` in the window, of
/// each provider's current generation, for an answer that just arrived (module docs).
pub fn blocks_for_answer(
    c: &rusqlite::Connection,
    name: &str,
    alerting: &[String],
    since: &str,
) -> rusqlite::Result<Vec<BlockInfo>> {
    if alerting.is_empty() {
        return Ok(Vec::new());
    }
    let ids = serde_json::to_string(alerting).unwrap_or_else(|_| "[]".into());
    let mut st = c.prepare_cached(
        "SELECT b.id, b.provider_id, b.name, b.obtained_at, b.source, b.reason, b.detail_json
         FROM lookup_blocks b JOIN lookup_providers p ON p.id = b.provider_id AND p.cache_generation = b.generation
         WHERE b.name = ?1 AND b.answers_checked <> 0 AND b.obtained_at >= ?2
           AND b.provider_id IN (SELECT value FROM json_each(?3))
         ORDER BY b.obtained_at DESC LIMIT 16",
    )?;
    let rows = st
        .query_map(params![name, since, ids], |r| {
            Ok(BlockInfo {
                id: r.get(0)?,
                provider: r.get(1)?,
                name: r.get(2)?,
                obtained_at: r.get(3)?,
                source: r.get(4)?,
                reason: r.get(5)?,
                detail: r
                    .get::<_, Option<String>>(6)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    // One per provider: the latest Block names the alert.
    let mut seen = std::collections::HashSet::new();
    Ok(rows
        .into_iter()
        .filter(|b| seen.insert(b.provider.clone()))
        .collect())
}

/// True when a Block for (provider, name) obtained at `at` is already known (an edge's cache hit
/// of a Block core has checked).
pub fn known_block(c: &rusqlite::Connection, provider: &str, name: &str, at: &str) -> rusqlite::Result<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM lookup_blocks WHERE provider_id = ?1 AND name = ?2 AND obtained_at = ?3",
        params![provider, name, at],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn db() -> rusqlite::Connection {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        for step in crate::db::schema::CORE {
            c.execute_batch(step).unwrap();
        }
        c
    }

    /// Answer `seq`'s time: later with every seq, or one time for all.
    fn ts(seq: i64, same: bool) -> String {
        format!("2026-11-24T10:00:00.{:06}Z", if same { 0 } else { seq })
    }

    fn key(seq: i64) -> AnswerKey {
        AnswerKey {
            ts: ts(seq, false),
            edge: "e".into(),
            boot: "b".into(),
            seq,
        }
    }

    /// Counts answers `seqs` of ("p", "n"): how many were new.
    fn count(
        c: &mut rusqlite::Connection,
        holds: &ScanHolds,
        seqs: std::ops::RangeInclusive<i64>,
        same: bool,
    ) -> usize {
        let tss: Vec<(i64, String)> = seqs.map(|s| (s, ts(s, same))).collect();
        let answers: Vec<CountedAnswer<'_>> = tss
            .iter()
            .map(|(seq, ts)| CountedAnswer {
                edge: "e",
                boot: "b",
                seq: *seq,
                ts: ts.clone(),
            })
            .collect();
        let tx = c.transaction().unwrap();
        let n = count_new(&tx, "p", "n", &answers, holds).unwrap();
        tx.commit().unwrap();
        n
    }

    /// The seqs kept for ("p", "n"), oldest first.
    fn kept(c: &rusqlite::Connection) -> Vec<i64> {
        let mut st = c
            .prepare(
                "SELECT seq FROM lookup_answers_counted WHERE provider_id = 'p' AND name = 'n' ORDER BY seq",
            )
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    /// README §2 Bounded: with no scan running, the newest MAX_COUNTED stay.
    #[test]
    fn the_newest_are_kept_without_scans() {
        let mut c = db();
        let holds = Arc::new(ScanHolds::default());
        assert_eq!(count(&mut c, &holds, 1..=250, false), 250);
        assert_eq!(kept(&c), (51..=250).collect::<Vec<_>>());
        assert_eq!(count(&mut c, &holds, 200..=251, false), 1, "only 251 is new");
        assert_eq!(kept(&c).first(), Some(&52));
    }

    /// core.md §9 Dedupe: equal times keep the identities a scan reads first (seq, then boot and
    /// edge, descending: scan_answers' order).
    #[test]
    fn equal_times_keep_the_scan_order() {
        let mut c = db();
        let holds = Arc::new(ScanHolds::default());
        assert_eq!(count(&mut c, &holds, 1..=300, true), 300);
        assert_eq!(kept(&c), (101..=300).collect::<Vec<_>>());
    }

    /// Module docs: a scan still reading holds every identity of its name; another name's scan
    /// holds none of it; once the scan lets go the bound applies again.
    #[test]
    fn a_reading_scan_holds_every_identity_of_its_name() {
        let mut c = db();
        let holds = Arc::new(ScanHolds::default());
        let other = holds.hold("p", "other");
        let hold = holds.hold("p", "n");
        assert_eq!(count(&mut c, &holds, 1..=250, false), 250);
        assert_eq!(kept(&c).len(), 250, "nothing forgotten while the scan reads");
        drop(hold);
        assert_eq!(count(&mut c, &holds, 251..=251, false), 1);
        assert_eq!(kept(&c), (52..=251).collect::<Vec<_>>());
        drop(other);
        assert_eq!(holds.spared("p", "n"), Spared::Nothing);
        assert!(holds.lock().is_empty(), "no hold is left behind");
    }

    /// Module docs, at the boundary: a scan that read answers from 31 up holds 31 and later; 30,
    /// just below, is forgotten past the bound; with two scans the older answer holds.
    #[test]
    fn a_scan_holds_from_its_oldest_answer_up() {
        let mut c = db();
        let holds = Arc::new(ScanHolds::default());
        assert_eq!(count(&mut c, &holds, 1..=200, false), 200);
        let hold = holds.hold("p", "n");
        hold.read(Some(key(31)));
        let newer = holds.hold("p", "n");
        newer.read(Some(key(150)));
        assert_eq!(count(&mut c, &holds, 201..=260, false), 60);
        assert_eq!(kept(&c), (31..=260).collect::<Vec<_>>());
        assert_eq!(count(&mut c, &holds, 31..=31, false), 0, "31 still counts once");
        drop(hold);
        assert_eq!(count(&mut c, &holds, 261..=261, false), 1);
        assert_eq!(
            kept(&c),
            (62..=261).collect::<Vec<_>>(),
            "the later scan holds from 150 only"
        );
        drop(newer);
        // A scan that read nothing holds nothing.
        let empty = holds.hold("p", "n");
        empty.read(None);
        assert_eq!(holds.spared("p", "n"), Spared::Nothing);
    }

    /// C11 (module docs): retention's age cut spares what running scans hold: every identity of
    /// a name whose scan still reads, and from a scan's oldest answer up; other names' old
    /// identities go, and so do a name's once its scan lets go.
    #[test]
    fn retention_spares_what_running_scans_hold() {
        let mut c = db();
        let holds = Arc::new(ScanHolds::default());
        assert_eq!(count(&mut c, &holds, 1..=10, false), 10);
        {
            let tx = c.transaction().unwrap();
            for seq in 1..=3 {
                tx.execute(
                    "INSERT INTO lookup_answers_counted(provider_id, name, edge_id, boot, seq, ts)
                     VALUES ('p', 'other', 'e', 'b', ?1, ?2)",
                    params![seq, ts(seq, false)],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        // Everything up to seq 6 is past the window's edge.
        let cut = ts(7, false);
        let forget = |c: &mut rusqlite::Connection, holds: &ScanHolds| {
            let tx = c.transaction().unwrap();
            let n = forget_counted_in(&tx, &cut, holds).unwrap();
            tx.commit().unwrap();
            n
        };
        let reading = holds.hold("p", "n");
        assert_eq!(forget(&mut c, &holds), 3, "only the other name's go");
        assert_eq!(
            kept(&c),
            (1..=10).collect::<Vec<_>>(),
            "a reading scan holds them all"
        );
        reading.read(Some(key(4)));
        assert_eq!(
            forget(&mut c, &holds),
            3,
            "1 to 3, below the scan's oldest answer"
        );
        assert_eq!(kept(&c), (4..=10).collect::<Vec<_>>());
        drop(reading);
        assert_eq!(forget(&mut c, &holds), 3);
        assert_eq!(kept(&c), (7..=10).collect::<Vec<_>>());
    }

    /// README §2 Bounded: a hold yields past MAX_COUNTED_HELD.
    #[test]
    fn a_hold_yields_past_its_bound() {
        let mut c = db();
        let holds = Arc::new(ScanHolds::default());
        let _hold = holds.hold("p", "n");
        let n = MAX_COUNTED_HELD + 10;
        assert_eq!(count(&mut c, &holds, 1..=n, false), n as usize);
        assert_eq!(kept(&c), (11..=n).collect::<Vec<_>>());
    }
}
