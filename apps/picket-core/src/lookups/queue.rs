//! `lookup_queue` (core.md §7 "Queue", "Order", "Re-checks", "Execution"; storage.md §3).
//!
//! - **One row per (provider, name)**, deduplicated: the row keeps every pending need, every
//!   pending re-check deadline and who asked (bounded). `next_at` is its earliest pending deadline
//!   (or the backoff after a failed call); `class` orders the work: retries (0, answered under the
//!   provider's `fail_mode` on the edge), then async attachments (1), then re-checks (2).
//! - **Admission** ([`admit`]): a retry or async-attachment lookup is settled at once when
//!   `lookup_verdicts` holds a live entry for the name; otherwise it is queued (or merged into the
//!   row). A retry's first attempt waits until `async_timeout_ms` + 5 s after its record was
//!   ingested, so the edge's late answer arrives first. A re-check adds a deadline per `after`
//!   delay (plus a random share of `jitter`) from the answer that asked, unless the row's last
//!   pending deadline is still ahead of that answer ("later answers add none until the last one
//!   has passed"). A provider's share of the queue is capped; an item that doesn't fit is dropped
//!   and counted.
//! - **Execution** ([`process`], light lane, keyed per provider): `lookup_verdicts` is checked
//!   again before every attempt (a live entry settles a need without a call). Before every call
//!   the name must be within the scope of an asking profile's attachment and of the provider, and
//!   that profile must still attach the provider ([`super::scope::call_skip`]; core.md §7 Sources
//!   (b)); otherwise the need is dropped without a call and counted. A due re-check is also
//!   skipped when the name is in one of the asking profiles' allow bundles or forward zones, or
//!   has been blocked by the provider (current generation) since it was answered; otherwise its
//!   share of `max_per_day` is reserved in `lookup_recheck_days` before the call, and past it the
//!   re-check is dropped and counted; a re-check always calls (skipping the cache) and its result
//!   replaces the entry. A deadline is met only by a call made at or after it.
//! - **`max_per_day`** counts the calls the provider answered (made and not rejected; a failed
//!   call counts). Every lookup makes at most one call ([`picket_lookup::AsyncOptions::one_attempt`]),
//!   so each call has its own reservation, persisted before it is made (concurrent workers and a
//!   restart during the call never pass the cap); the reservation is given back when no call was
//!   made, when the provider rejected the call, and when its result is discarded (another
//!   generation, or an unsynchronised clock); a later attempt reserves again.
//! - **Generations** (providers.md §4): a result is stored only under the provider's generation
//!   in the writer's transaction; a result of an older generation (a call that spanned a flush)
//!   settles nothing: the work stays and the next attempt calls under the new generation.
//! - **Clocks** (README §2): core's calls stamp `obtained_at` with core's clock, and re-check day
//!   counts, backoffs and deadlines read it ([`super::Lookups::now`]), so nothing is called
//!   before the wall clock is synchronised: the dispatcher hands out no work until then, and the
//!   client checks again right before each call, after any wait for a slot or a token
//!   ([`picket_lookup::AsyncResult::ClockUnsynced`]: no call, no attempt used). A lookup that
//!   ends after the clock lost its synchronisation writes no deadline read from it (a retry
//!   time, a pause): a clock days ahead would park the row for days after the correction. The
//!   row stays due and goes out again once the clock is synchronised; the client's own pause and
//!   breaker, on the monotonic clock, still hold the provider back. A result that comes back on
//!   an unsynchronised clock is discarded like one of another generation.
//! - **Failures:** an error retries with exponential backoff (30 s → 1 h, ±20 % jitter) up to
//!   `async_max_attempts`, then the due work is dropped and counted. Only a call that is made and
//!   fails uses an attempt: while the breaker is open or the provider is paused after a rejection,
//!   its items wait (the dispatcher holds the provider back until then), and afterwards the
//!   client's token bucket paces the backlog.
//! - **Too old:** work due longer ago than the log retention window is dropped and counted (a
//!   re-check deadline still ahead is never old), once the wall clock is synchronised (README §2
//!   Clocks: a boot clock days ahead never discards persisted work).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::Timestamp;
use picket_lookup::{AsyncOptions, AsyncResult, ErrorKind};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore};

use super::store::{self, ProviderView};
use crate::config::Model;
use crate::config::model::LookupProviderDef;
use crate::state::{AppState, SharedState};

/// Rows one provider may hold (README §2 Bounded, capped shares). Re-check deadlines keep a row
/// per distinct answered name for up to the longest `after` delay (two days by default), so this
/// is sized for a busy household's distinct names. Policy choice: the spec gives no number.
pub const MAX_PER_PROVIDER: i64 = 200_000;
/// Rows across providers.
pub const MAX_TOTAL: i64 = 1_000_000;
/// Lookup jobs dispatched to the light lane at once (their calls are paced by each client).
pub const MAX_DISPATCHED: usize = 64;
/// Profiles and askers kept per row.
const MAX_ASKERS: usize = 16;
/// A retry's first attempt waits this long past `async_timeout_ms` (core.md §7).
pub const RETRY_GRACE: Duration = Duration::from_secs(5);
/// Backoff after a failed call: 30 s, doubling, up to 1 h, ±20 % (core.md §7).
pub const BACKOFF_MIN: Duration = Duration::from_secs(30);
pub const BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// Which first lookup a row wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NeedKind {
    /// A sync lookup that timed out, failed or was rejected (source a).
    Retry,
    /// An async attachment (source b).
    Async,
}

/// A first lookup a row wants, from `due_at` on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Need {
    pub kind: NeedKind,
    pub due_at: String,
}

/// A row's `context_json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ItemCtx {
    pub need: Option<Need>,
    /// Pending re-check deadlines (RFC 3339, sorted).
    pub rechecks: Vec<String>,
    /// The answer the pending deadlines come from (the earliest not yet re-checked).
    pub answered_at: Option<String>,
    /// Profiles whose queries asked.
    pub profiles: Vec<String>,
    /// Who asked: `edge/client`.
    pub asked: Vec<String>,
    /// After a failed or refused call: no attempt before this.
    pub retry_at: Option<String>,
    pub last_error: Option<String>,
}

impl ItemCtx {
    fn add_profile(&mut self, p: Option<&str>) {
        if let Some(p) = p
            && !self.profiles.iter().any(|x| x == p)
            && self.profiles.len() < MAX_ASKERS
        {
            self.profiles.push(p.to_string());
        }
    }

    fn add_asker(&mut self, a: Option<&str>) {
        if let Some(a) = a
            && !self.asked.iter().any(|x| x == a)
            && self.asked.len() < MAX_ASKERS
        {
            self.asked.push(a.to_string());
        }
    }

    /// Nothing left to do.
    pub fn is_empty(&self) -> bool {
        self.need.is_none() && self.rechecks.is_empty()
    }

    /// The earliest pending deadline, and the class of the work it opens: a need first (retry 0,
    /// async 1), else a re-check (2).
    pub fn schedule(&self) -> Option<(String, i64, &'static str)> {
        let need = self.need.as_ref().map(|n| {
            let (c, r) = match n.kind {
                NeedKind::Retry => (0, "retry"),
                NeedKind::Async => (1, "async"),
            };
            (n.due_at.clone(), c, r)
        });
        let re = self.rechecks.first().map(|d| (d.clone(), 2, "recheck"));
        let first = match (need, re) {
            (Some(n), Some(r)) => {
                if n.0 <= r.0 {
                    n
                } else {
                    r
                }
            }
            (Some(n), None) => n,
            (None, Some(r)) => r,
            (None, None) => return None,
        };
        let at = match &self.retry_at {
            Some(r) if *r > first.0 => r.clone(),
            _ => first.0,
        };
        Some((at, first.1, first.2))
    }
}

/// The dispatcher's state.
pub struct QueueState {
    pub wake: Notify,
    inflight: Mutex<HashSet<(String, String)>>,
    dispatched: Arc<Semaphore>,
    /// Providers held back until a monotonic instant (paused or breaker open).
    held: Mutex<HashMap<String, tokio::time::Instant>>,
    /// Approximate rows per provider (refreshed from the table, bumped by admissions).
    depths: Mutex<HashMap<String, i64>>,
}

impl Default for QueueState {
    fn default() -> Self {
        Self {
            wake: Notify::new(),
            inflight: Mutex::new(HashSet::new()),
            dispatched: Arc::new(Semaphore::new(MAX_DISPATCHED)),
            held: Mutex::new(HashMap::new()),
            depths: Mutex::new(HashMap::new()),
        }
    }
}

impl QueueState {
    /// Providers whose share of the queue is full now.
    pub fn full(&self) -> HashSet<String> {
        let d = self.depths.lock().map(|d| d.clone()).unwrap_or_default();
        let total: i64 = d.values().sum();
        if total >= MAX_TOTAL {
            return d
                .keys()
                .cloned()
                .chain(std::iter::once("*".to_string()))
                .collect();
        }
        d.into_iter()
            .filter(|(_, n)| *n >= MAX_PER_PROVIDER)
            .map(|(p, _)| p)
            .collect()
    }

    fn bump(&self, provider: &str, n: i64) {
        if let Ok(mut d) = self.depths.lock() {
            *d.entry(provider.to_string()).or_insert(0) += n;
        }
    }

    fn hold(&self, provider: &str, until: tokio::time::Instant) {
        if let Ok(mut h) = self.held.lock() {
            h.insert(provider.to_string(), until);
        }
    }

    fn held_until(&self, provider: &str) -> Option<tokio::time::Instant> {
        let mut h = self.held.lock().ok()?;
        match h.get(provider).copied() {
            Some(t) if t > tokio::time::Instant::now() => Some(t),
            Some(_) => {
                h.remove(provider);
                None
            }
            None => None,
        }
    }
}

/// What to queue.
#[derive(Clone, Debug)]
pub enum AdmitKind {
    /// A first lookup (retry or async attachment) wanted from `due_at` on.
    Need { kind: NeedKind, due_at: Timestamp },
    /// Re-checks for an answer at `answered_at`, at these deadlines.
    Recheck {
        answered_at: Timestamp,
        deadlines: Vec<Timestamp>,
    },
}

/// What admission did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// A live entry answered it: no queue item.
    Settled,
    Queued,
    /// Merged into the name's existing row.
    Merged,
    /// Nothing to add (the row already holds the work, or no deadline applies).
    Unchanged,
    /// The provider's share is full: dropped and counted.
    Full,
}

/// The re-check deadlines for an answer at `at` (each `after` delay plus a random share of
/// `jitter`).
pub fn recheck_deadlines(p: &LookupProviderDef, at: Timestamp) -> Vec<Timestamp> {
    let r = &p.settings.recheck;
    if !r.enabled {
        return Vec::new();
    }
    let jitter = r.jitter.as_secs();
    let mut v: Vec<Timestamp> = r
        .after
        .iter()
        .map(|d| {
            let j = if jitter > 0 {
                rand::random_range(0..=jitter)
            } else {
                0
            };
            picket_api::time::saturating_add(
                at,
                jiff::SignedDuration::from_secs(
                    i64::try_from(d.as_secs().saturating_add(j)).unwrap_or(i64::MAX),
                ),
            )
        })
        .collect();
    v.sort();
    v
}

fn read_row(
    tx: &rusqlite::Connection,
    provider: &str,
    name: &str,
) -> rusqlite::Result<Option<(i64, ItemCtx)>> {
    tx.query_row(
        "SELECT attempts, context_json FROM lookup_queue WHERE provider_id = ?1 AND name = ?2",
        params![provider, name],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)),
    )
    .optional()
    .map(|o| {
        o.map(|(a, c)| {
            (
                a,
                c.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
            )
        })
    })
}

/// Writes a row back: deleted when nothing is left, else with its schedule.
fn write_row(
    tx: &Transaction<'_>,
    provider: &str,
    name: &str,
    attempts: i64,
    ctx: &ItemCtx,
    now: &str,
) -> rusqlite::Result<()> {
    let Some((next_at, class, reason)) = ctx.schedule() else {
        tx.execute(
            "DELETE FROM lookup_queue WHERE provider_id = ?1 AND name = ?2",
            params![provider, name],
        )?;
        return Ok(());
    };
    let json = serde_json::to_string(ctx).unwrap_or_else(|_| "{}".into());
    tx.execute(
        "INSERT INTO lookup_queue(provider_id, name, reason, first_seen, attempts, next_at, context_json, class)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(provider_id, name) DO UPDATE SET reason = excluded.reason, attempts = excluded.attempts,
             next_at = excluded.next_at, context_json = excluded.context_json, class = excluded.class",
        params![provider, name, reason, now, attempts, next_at, json, class],
    )?;
    Ok(())
}

/// Queues work for (provider, name) inside the caller's transaction (module docs). `full`: the
/// provider's share is full (a new row is dropped; merging into an existing one still works).
#[expect(
    clippy::too_many_arguments,
    reason = "an admission's fields, written by one statement in the caller's transaction"
)]
pub fn admit(
    tx: &Transaction<'_>,
    p: &ProviderView<'_>,
    name: &str,
    kind: &AdmitKind,
    profile: Option<&str>,
    asker: Option<&str>,
    full: bool,
    now: Timestamp,
) -> rusqlite::Result<Admitted> {
    if let AdmitKind::Need { .. } = kind
        && store::live_entry(tx, p, name, now)?.is_some()
    {
        return Ok(Admitted::Settled);
    }
    let existing = read_row(tx, p.id, name)?;
    let had = existing.is_some();
    if !had && full {
        return Ok(Admitted::Full);
    }
    let (attempts, mut ctx) = existing.unwrap_or_default();
    let before = ctx.clone();
    match kind {
        AdmitKind::Need { kind, due_at } => {
            let due = crate::util::ts(due_at);
            ctx.need = Some(match ctx.need.take() {
                None => Need {
                    kind: *kind,
                    due_at: due,
                },
                Some(n) => Need {
                    // A retry outranks an async attachment; the earlier due time stands.
                    kind: if n.kind == NeedKind::Retry || *kind == NeedKind::Retry {
                        NeedKind::Retry
                    } else {
                        NeedKind::Async
                    },
                    due_at: n.due_at.min(due),
                },
            });
        }
        AdmitKind::Recheck {
            answered_at,
            deadlines,
        } => {
            let at = crate::util::ts(answered_at);
            let blocked = ctx.rechecks.last().is_some_and(|last| *last > at);
            if !blocked && !deadlines.is_empty() {
                ctx.rechecks.extend(deadlines.iter().map(crate::util::ts));
                ctx.rechecks.sort();
                ctx.rechecks.dedup();
                if ctx.answered_at.is_none() || before.rechecks.is_empty() {
                    ctx.answered_at = Some(at);
                }
            }
        }
    }
    ctx.add_profile(profile);
    ctx.add_asker(asker);
    if ctx == before {
        return Ok(Admitted::Unchanged);
    }
    if ctx.is_empty() {
        return Ok(Admitted::Unchanged);
    }
    write_row(tx, p.id, name, attempts, &ctx, &crate::util::ts(&now))?;
    Ok(if had { Admitted::Merged } else { Admitted::Queued })
}

/// At start: the approximate depths (README §2 Restarts: rows are durable; nothing else to do).
pub async fn recover(state: &AppState) -> anyhow::Result<()> {
    refresh_depths(state).await
}

async fn refresh_depths(state: &AppState) -> anyhow::Result<()> {
    let d: HashMap<String, i64> = state
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT provider_id, count(*) FROM lookup_queue GROUP BY provider_id")?;
            let m = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<rusqlite::Result<HashMap<_, _>>>()?;
            Ok::<_, anyhow::Error>(m)
        })
        .await?;
    if let Ok(mut depths) = state.lookups.queue.depths.lock() {
        *depths = d;
    }
    Ok(())
}

/// Counts admissions in the approximate depths.
pub fn note_admitted(state: &AppState, provider: &str, a: Admitted) {
    if a == Admitted::Queued {
        state.lookups.queue.bump(provider, 1);
    }
}

/// The dispatcher: hands due rows to the light lane in order (class, then due time), never two
/// jobs for one row, never a held provider's rows.
pub async fn run(state: SharedState) {
    let mut refresh = tokio::time::interval(Duration::from_secs(30));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let wait = match dispatch(&state).await {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "the lookup queue dispatcher failed; retrying");
                Duration::from_secs(5)
            }
        };
        tokio::select! {
            _ = state.shutdown.cancelled() => return,
            _ = state.lookups.queue.wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
            _ = refresh.tick() => {
                let _ = refresh_depths(&state).await;
            }
        }
    }
}

/// How often the dispatcher looks again while the wall clock isn't synchronised.
const UNSYNCED_WAIT: Duration = Duration::from_secs(5);

/// One dispatch pass; returns how long to wait before the next.
async fn dispatch(state: &SharedState) -> anyhow::Result<Duration> {
    // No call before the wall clock is synchronised (module docs, README §2 Clocks).
    if !state.clock.synced() {
        return Ok(UNSYNCED_WAIT);
    }
    let now = crate::util::ts(&state.lookups.now());
    // Held providers' rows stay out of the page, so they never crowd out the others'.
    let held: Vec<String> = state
        .lookups
        .model()
        .lookup_providers
        .keys()
        .filter(|p| state.lookups.queue.held_until(p).is_some())
        .cloned()
        .collect();
    let held_json = serde_json::to_string(&held).unwrap_or_else(|_| "[]".into());
    let (due, next): (Vec<(String, String)>, Option<String>) = state
        .db
        .read(move |c| {
            let mut st = c.prepare_cached(
                "SELECT provider_id, name FROM lookup_queue WHERE next_at <= ?1
                   AND provider_id NOT IN (SELECT value FROM json_each(?2))
                 ORDER BY class, next_at LIMIT 512",
            )?;
            let due = st
                .query_map(params![now, held_json], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let next: Option<String> = c
                .query_row(
                    "SELECT min(next_at) FROM lookup_queue WHERE next_at > ?1",
                    [&now],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            Ok::<_, anyhow::Error>((due, next))
        })
        .await?;
    let q = &state.lookups.queue;
    let mut busy = false;
    for (provider, name) in due {
        if q.held_until(&provider).is_some() {
            continue;
        }
        let key = (provider.clone(), name.clone());
        if q.inflight.lock().map(|s| s.contains(&key)).unwrap_or(true) {
            continue;
        }
        let Ok(permit) = q.dispatched.clone().try_acquire_owned() else {
            busy = true;
            break;
        };
        if let Ok(mut s) = q.inflight.lock() {
            s.insert(key.clone());
        }
        let st = state.clone();
        let lane = lane_key_of(&provider);
        let spawned = state.scheduler.light.spawn(Some(&lane), async move {
            if let Err(e) = process(&st, &key.0, &key.1).await {
                tracing::warn!(provider = %key.0, error = %format!("{e:#}"), "a lookup queue item failed");
            }
            if let Ok(mut s) = st.lookups.queue.inflight.lock() {
                s.remove(&key);
            }
            drop(permit);
            st.lookups.queue.wake.notify_one();
        });
        if spawned.is_none() {
            // The light lane is at its admission cap: the row stays queued for the next pass.
            if let Ok(mut s) = q.inflight.lock() {
                s.remove(&(provider, name));
            }
            busy = true;
            break;
        }
    }
    if busy {
        return Ok(Duration::from_secs(1));
    }
    let wait = next
        .as_deref()
        .and_then(crate::util::parse_ts)
        .map(|t| std::time::Duration::try_from(t - state.lookups.now()).unwrap_or(Duration::ZERO))
        .unwrap_or(Duration::from_secs(5));
    Ok(wait.clamp(Duration::from_millis(20), Duration::from_secs(5)))
}

fn lane_key_of(provider: &str) -> String {
    super::lane_key(provider)
}

/// The backoff before attempt `attempts + 1` (30 s doubling to 1 h, ±20 %).
pub fn backoff(attempts: i64) -> Duration {
    let exp = u32::try_from(attempts.saturating_sub(1).clamp(0, 16)).unwrap_or(16);
    let base = BACKOFF_MIN
        .saturating_mul(2u32.saturating_pow(exp))
        .min(BACKOFF_MAX);
    let f: f64 = rand::random_range(0.8..=1.2);
    base.mul_f64(f)
}

/// Why a due re-check doesn't call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecheckSkip {
    /// Skipped (allow bundle, forward zone, blocked since, out of scope, not attached).
    Skipped(&'static str),
    /// Over `max_per_day`: dropped.
    Dropped,
}

/// Decides whether a due re-check calls (module docs).
pub fn recheck_decision(
    c: &rusqlite::Connection,
    model: &Model,
    provider: &str,
    p: &LookupProviderDef,
    name: &str,
    ctx: &ItemCtx,
    today: &str,
) -> rusqlite::Result<Option<RecheckSkip>> {
    // Blocked by the provider (its current generation) since it was answered.
    if let Some(at) = &ctx.answered_at {
        let blocked: Option<i64> = c
            .query_row(
                "SELECT 1 FROM lookup_blocks b JOIN lookup_providers p
                   ON p.id = b.provider_id AND p.cache_generation = b.generation
                 WHERE b.provider_id = ?1 AND b.name = ?2 AND b.obtained_at >= ?3 LIMIT 1",
                params![provider, name, at],
                |r| r.get(0),
            )
            .optional()?;
        if blocked.is_some() {
            return Ok(Some(RecheckSkip::Skipped("blocked_since")));
        }
    }
    let mut why = "not_attached";
    let mut any = false;
    for pid in &ctx.profiles {
        let Some(prof) = model.profiles.get(pid) else {
            continue;
        };
        let Some(att) = prof.edge.lookups.iter().find(|a| a.provider == provider) else {
            continue;
        };
        if super::scope::in_forward_zone(model, prof, name) {
            why = "forward_zone";
            continue;
        }
        if prof
            .edge
            .allow
            .iter()
            .any(|b| super::scope::in_bundle(c, model, b, name).unwrap_or(false))
        {
            why = "allow_bundle";
            continue;
        }
        if !super::scope::in_scope(c, model, p, att, name)? {
            why = "out_of_scope";
            continue;
        }
        any = true;
        break;
    }
    if !any {
        return Ok(Some(RecheckSkip::Skipped(why)));
    }
    let _ = today;
    Ok(None)
}

/// Reserves one re-check call of `today`'s `max_per_day` in the writer (module docs): false when
/// the day's allowance is used up. Without a cap the call is only counted.
pub fn reserve_recheck(
    tx: &Transaction<'_>,
    provider: &str,
    max_per_day: Option<u32>,
    today: &str,
) -> rusqlite::Result<bool> {
    let n: i64 = tx
        .query_row(
            "SELECT count FROM lookup_recheck_days WHERE provider_id = ?1 AND day = ?2",
            params![provider, today],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    if max_per_day.is_some_and(|m| n >= i64::from(m)) {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO lookup_recheck_days(provider_id, day, count) VALUES (?1, ?2, 1)
         ON CONFLICT(provider_id, day) DO UPDATE SET count = count + 1",
        params![provider, today],
    )?;
    Ok(true)
}

/// Gives back a reservation of `day` for a re-check whose call doesn't count (module docs: no
/// call made, a rejection, a discarded result).
pub fn release_recheck(tx: &Transaction<'_>, provider: &str, day: &str) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE lookup_recheck_days SET count = max(count - 1, 0) WHERE provider_id = ?1 AND day = ?2",
        params![provider, day],
    )?;
    Ok(())
}

/// What one attempt did, applied to the row in the writer ([`finish`]).
#[derive(Clone, Debug, Default)]
struct Outcome {
    /// The need due before the attempt began was satisfied (settled, answered or dropped).
    clear_need_due_by: Option<String>,
    /// Deadlines at or before this are met (a call made at or after them) or dropped.
    clear_rechecks_by: Option<String>,
    attempts: Option<i64>,
    retry_at: Option<Option<String>>,
    last_error: Option<Option<String>>,
    /// A re-check reserved a share of this day's `max_per_day` but its call doesn't count: give
    /// it back.
    release_recheck: Option<String>,
}

async fn finish(state: &AppState, provider: &str, name: &str, o: Outcome) -> anyhow::Result<()> {
    let (p, n) = (provider.to_string(), name.to_string());
    let now = crate::util::ts(&state.lookups.now());
    let deleted = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if let Some(day) = &o.release_recheck {
                release_recheck(&tx, &p, day)?;
            }
            let Some((attempts, mut ctx)) = read_row(&tx, &p, &n)? else {
                tx.commit()?;
                return Ok::<_, anyhow::Error>(false);
            };
            if let Some(by) = &o.clear_need_due_by
                && ctx.need.as_ref().is_some_and(|x| x.due_at <= *by)
            {
                ctx.need = None;
            }
            if let Some(by) = &o.clear_rechecks_by {
                ctx.rechecks.retain(|d| d > by);
                if ctx.rechecks.is_empty() {
                    ctx.answered_at = None;
                }
            }
            if let Some(r) = o.retry_at.clone() {
                ctx.retry_at = r;
            }
            if let Some(e) = o.last_error.clone() {
                ctx.last_error = e;
            }
            let attempts = o.attempts.unwrap_or(attempts);
            let gone = ctx.is_empty();
            write_row(&tx, &p, &n, attempts, &ctx, &now)?;
            tx.commit()?;
            Ok(gone)
        })
        .await?;
    if deleted {
        state.lookups.queue.bump(provider, -1);
    }
    Ok(())
}

fn count(
    state: &AppState,
    items: &mut Vec<(String, crate::metrics::Labels, i64, f64)>,
    name: &str,
    l: &[(&str, &str)],
) {
    let _ = state;
    items.push((
        name.to_string(),
        crate::metrics::labels("", l),
        crate::util::now().as_millisecond(),
        1.0,
    ));
}

/// Works one row (module docs).
pub async fn process(state: &AppState, provider: &str, name: &str) -> anyhow::Result<()> {
    let model = state.lookups.model();
    let (pid, nm) = (provider.to_string(), name.to_string());
    let Some(p) = model.lookup_providers.get(provider).cloned() else {
        state
            .db
            .write(move |c| {
                c.execute(
                    "DELETE FROM lookup_queue WHERE provider_id = ?1 AND name = ?2",
                    params![pid, nm],
                )?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        return Ok(());
    };
    let Some(client) = state.lookups.client(provider) else {
        return Ok(());
    };
    // Every decision below reads the wall clock (README §2 Clocks): the row waits, unchanged,
    // and the dispatcher hands out nothing until the clock is synchronised.
    if !state.clock.synced() {
        return Ok(());
    }
    let now = state.lookups.now();
    let now_s = crate::util::ts(&now);
    let row = state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(read_row(c, &pid, &nm)?))
        .await?;
    let Some((attempts, ctx)) = row else { return Ok(()) };
    if ctx.retry_at.as_ref().is_some_and(|r| *r > now_s) {
        return Ok(());
    }
    let mut metrics = Vec::new();
    // Work due longer ago than the log retention window is dropped and counted, once the wall
    // clock can say so (README §2 Clocks).
    let window = state.settings().retention.query_logs.as_duration();
    let old = crate::util::ts(&crate::util::window_start(now, window));
    let synced = state.clock.synced();
    let stale_need = synced && ctx.need.as_ref().is_some_and(|n| n.due_at < old);
    let stale_re = synced && ctx.rechecks.iter().any(|d| *d < old);
    if stale_need || stale_re {
        if stale_need {
            count(
                state,
                &mut metrics,
                "lookup_dropped",
                &[("provider", provider), ("reason", "too_old")],
            );
        }
        if stale_re {
            count(
                state,
                &mut metrics,
                "rechecks",
                &[("provider", provider), ("result", "dropped")],
            );
        }
        state.metrics.count(&state.metrics_db, metrics).await;
        return finish(
            state,
            provider,
            name,
            Outcome {
                clear_need_due_by: stale_need.then(|| old.clone()),
                clear_rechecks_by: stale_re.then(|| old.clone()),
                ..Outcome::default()
            },
        )
        .await;
    }
    let need_due = ctx.need.as_ref().filter(|n| n.due_at <= now_s).cloned();
    let re_due = ctx.rechecks.first().is_some_and(|d| *d <= now_s);
    if need_due.is_none() && !re_due {
        return finish(state, provider, name, Outcome::default()).await;
    }
    let cache = p.settings.cache;
    let today = crate::util::day_key(&now);
    let mut recheck = false;
    // A share of today's max_per_day reserved for this re-check (given back if no call is made).
    let mut reserved: Option<String> = None;
    if re_due {
        let (m2, pid, nm, c2, p2, t2) = (
            model.clone(),
            provider.to_string(),
            name.to_string(),
            ctx.clone(),
            p.clone(),
            today.clone(),
        );
        let skip = state
            .db
            .read(move |c| Ok::<_, anyhow::Error>(recheck_decision(c, &m2, &pid, &p2, &nm, &c2, &t2)?))
            .await?;
        let skip = match skip {
            Some(s) => Some(s),
            None => {
                // Reserve the call's share of max_per_day before making it (core.md §7).
                let (pid, t2, max) = (
                    provider.to_string(),
                    today.clone(),
                    p.settings.recheck.max_per_day,
                );
                let ok = state
                    .db
                    .write(move |c| {
                        let tx = c.transaction()?;
                        let ok = reserve_recheck(&tx, &pid, max, &t2)?;
                        tx.commit()?;
                        Ok::<_, anyhow::Error>(ok)
                    })
                    .await?;
                if ok {
                    reserved = Some(today.clone());
                    None
                } else {
                    Some(RecheckSkip::Dropped)
                }
            }
        };
        match skip {
            None => recheck = true,
            Some(s) => {
                let result = match s {
                    RecheckSkip::Skipped(_) => "skipped",
                    RecheckSkip::Dropped => "dropped",
                };
                count(
                    state,
                    &mut metrics,
                    "rechecks",
                    &[("provider", provider), ("result", result)],
                );
                state
                    .metrics
                    .count(&state.metrics_db, std::mem::take(&mut metrics))
                    .await;
                finish(
                    state,
                    provider,
                    name,
                    Outcome {
                        clear_rechecks_by: Some(now_s.clone()),
                        ..Outcome::default()
                    },
                )
                .await?;
                if need_due.is_none() {
                    return Ok(());
                }
            }
        }
    }
    if !recheck && let Some(need) = &need_due {
        // Checked again before every attempt: a live entry of the provider's current generation
        // settles the need without a call; a name no asking profile's attachment (or the
        // provider) has in scope any more, or a provider no asking profile attaches, gets none.
        let (pid, nm, m2, p2, profiles) = (
            provider.to_string(),
            name.to_string(),
            model.clone(),
            p.clone(),
            ctx.profiles.clone(),
        );
        let (live, skip) = state
            .db
            .read(move |c| {
                let Some(generation) = store::current_generation(c, &pid)? else {
                    return Ok::<_, anyhow::Error>((false, None));
                };
                let pv = ProviderView {
                    id: &pid,
                    generation: &generation,
                    cache: &cache,
                };
                if store::live_entry(c, &pv, &nm, now)?.is_some() {
                    return Ok((true, None));
                }
                Ok((false, super::scope::call_skip(c, &m2, &pid, &p2, &profiles, &nm)?))
            })
            .await?;
        if live || skip.is_some() {
            if let Some(why) = skip {
                tracing::debug!(provider, why, kind = ?need.kind, "a queued lookup makes no call");
                count(
                    state,
                    &mut metrics,
                    "lookup_dropped",
                    &[("provider", provider), ("reason", why)],
                );
                state.metrics.count(&state.metrics_db, metrics).await;
            }
            return finish(
                state,
                provider,
                name,
                Outcome {
                    clear_need_due_by: Some(now_s.clone()),
                    ..Outcome::default()
                },
            )
            .await;
        }
    }
    // A client still on an older generation than the provider's row (a flush or save whose
    // reload is pending) would make a call whose result is never used: wait for the reload.
    let pid = provider.to_string();
    let row_gen = state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(store::current_generation(c, &pid)?))
        .await?;
    if row_gen.as_deref() != Some(&*client.generation()) {
        return finish(
            state,
            provider,
            name,
            Outcome {
                retry_at: Some(Some(crate::util::ts(&(now + jiff::SignedDuration::from_secs(1))))),
                release_recheck: reserved,
                ..Outcome::default()
            },
        )
        .await;
    }
    if !state.clock.synced() {
        // The clock lost its synchronisation since the start: no call (module docs; the client
        // checks again right before its call, after waiting for a slot or a token).
        return finish(
            state,
            provider,
            name,
            Outcome {
                release_recheck: reserved,
                ..Outcome::default()
            },
        )
        .await;
    }
    // The call: at most one (a generation that moves on during it ends the lookup), so the
    // reservation above stands for exactly this call. A re-check always calls and its result
    // replaces the entry.
    let call_start = crate::util::ts(&state.lookups.now());
    let out = client
        .lookup_async(
            name,
            AsyncOptions {
                skip_cache: recheck,
                one_attempt: true,
            },
        )
        .await;
    let generation = out.generation.to_string();
    let now = state.lookups.now();
    // Read after the lookup: a deadline from a clock that lost its synchronisation during it is
    // never written (module docs, Clocks).
    let synced = state.clock.synced();
    let mut o = Outcome::default();
    // The reservation is kept only for a call the provider answered (made, not rejected) whose
    // result isn't discarded (module docs).
    let mut keep_reservation = false;
    match out.result {
        AsyncResult::Answer {
            verdict,
            obtained_at,
            detail,
            storable,
            ..
        } => {
            count(state, &mut metrics, "lookup_calls", &[("provider", provider)]);
            let v = match &verdict {
                picket_lookup::StoredVerdict::Block { .. } => picket_bundle::verdict::VerdictKind::Block,
                picket_lookup::StoredVerdict::Clean => picket_bundle::verdict::VerdictKind::Clean,
                picket_lookup::StoredVerdict::Unknown => picket_bundle::verdict::VerdictKind::Unknown,
            };
            count(
                state,
                &mut metrics,
                "lookup_verdicts",
                &[("provider", provider), ("result", store::verdict_text(v))],
            );
            // Discarded: the call spanned a generation change, or the clock lost its
            // synchronisation during it (its `obtained_at` can't be trusted).
            let mut discarded = false;
            if storable {
                let (score, reason) = match &verdict {
                    picket_lookup::StoredVerdict::Block { score, reason } => {
                        (*score, Some(reason.to_string()))
                    }
                    _ => (None, None),
                };
                let (pid, nm) = (provider.to_string(), name.to_string());
                let detail = detail.map(|d| (*d).clone());
                let clock = store::RecordClock::now(
                    state.clock.synced(),
                    state.settings().retention.lookup_blocks.as_duration(),
                );
                let rec = state
                    .db
                    .write(move |c| {
                        let tx = c.transaction()?;
                        let pv = ProviderView {
                            id: &pid,
                            generation: &generation,
                            cache: &cache,
                        };
                        let r = store::record(
                            &tx,
                            &pv,
                            &store::Incoming {
                                name: &nm,
                                verdict: v,
                                score,
                                reason: reason.as_deref(),
                                detail: detail.as_ref(),
                                obtained_at: obtained_at.min(clock.now),
                                generation: &generation,
                                source: store::Source::Core,
                            },
                            &clock,
                        )?;
                        tx.commit()?;
                        Ok::<_, anyhow::Error>(r)
                    })
                    .await?;
                if rec.new_block {
                    state.lookups.blocks_wake.notify_one();
                }
                if rec.changed && v == picket_bundle::verdict::VerdictKind::Block {
                    state.lookups.sets.block_recorded(provider);
                }
                discarded = rec.wrong_generation || rec.unsynced;
                if rec.unsynced {
                    // The row stays due: the dispatcher calls again once the clock is
                    // synchronised (no wall-clock retry time is written).
                    tracing::debug!(
                        provider,
                        "a lookup result on an unsynchronised clock is discarded"
                    );
                } else if rec.wrong_generation {
                    // The call spanned a generation change (providers.md §4): its result is
                    // never used, so it settles nothing. The next attempt calls under the new
                    // generation (it waits until the client has it, above); no attempt is used.
                    o.retry_at = Some(Some(crate::util::ts(&(now + jiff::SignedDuration::from_secs(1)))));
                }
            }
            if !discarded {
                keep_reservation = true;
                if recheck {
                    count(
                        state,
                        &mut metrics,
                        "rechecks",
                        &[("provider", provider), ("result", "run")],
                    );
                    if v == picket_bundle::verdict::VerdictKind::Block {
                        count(state, &mut metrics, "recheck_blocks", &[("provider", provider)]);
                    }
                }
                o.clear_need_due_by = Some(call_start.clone());
                if recheck {
                    o.clear_rechecks_by = Some(call_start.clone());
                }
                o.attempts = Some(0);
                o.retry_at = Some(None);
                o.last_error = Some(None);
            }
            state.lookups.update_runtime(provider, |r| {
                r.paused_until = None;
                r.breaker_until = None;
            });
        }
        AsyncResult::GenerationMoved { called } => {
            // The generation moved on during the lookup: whatever it got is never used
            // (providers.md §4). The work stays; the next attempt calls under the new generation
            // with a reservation of its own. No attempt is used.
            if called {
                count(state, &mut metrics, "lookup_calls", &[("provider", provider)]);
            }
            o.retry_at = Some(Some(crate::util::ts(&(now + jiff::SignedDuration::from_secs(1)))));
        }
        AsyncResult::Cached { .. } | AsyncResult::NameCheck => {
            // Unknown without a call (a name the module may not see), or a cache tier core
            // doesn't plug in: nothing to store, nothing left to do.
            o.clear_need_due_by = Some(call_start.clone());
            if recheck {
                o.clear_rechecks_by = Some(call_start.clone());
            }
        }
        AsyncResult::Error {
            kind,
            message,
            timed_out,
        } => {
            // Made and not rejected: it counts against max_per_day.
            keep_reservation = true;
            count(state, &mut metrics, "lookup_calls", &[("provider", provider)]);
            if timed_out {
                count(state, &mut metrics, "lookup_timeouts", &[("provider", provider)]);
            } else {
                count(state, &mut metrics, "lookup_errors", &[("provider", provider)]);
            }
            let _ = kind == ErrorKind::Failed;
            let n = attempts + 1;
            if n >= i64::from(p.settings.async_max_attempts.max(1)) {
                count(
                    state,
                    &mut metrics,
                    "lookup_dropped",
                    &[("provider", provider), ("reason", "attempts")],
                );
                if recheck {
                    count(
                        state,
                        &mut metrics,
                        "rechecks",
                        &[("provider", provider), ("result", "dropped")],
                    );
                }
                o.clear_need_due_by = Some(call_start.clone());
                if recheck {
                    o.clear_rechecks_by = Some(call_start.clone());
                }
                o.attempts = Some(0);
                o.retry_at = Some(None);
            } else {
                o.attempts = Some(n);
                let d =
                    jiff::SignedDuration::try_from(backoff(n)).unwrap_or(jiff::SignedDuration::from_secs(30));
                o.retry_at = Some(Some(crate::util::ts(&(now + d))));
            }
            o.last_error = Some(Some(crate::util::sanitize_for_message(&message, 300)));
        }
        AsyncResult::Rejected { retry_after } => {
            // Not a failure: the provider is paused; the item waits. The call was made but
            // rejected: it doesn't count against max_per_day.
            count(state, &mut metrics, "lookup_calls", &[("provider", provider)]);
            count(state, &mut metrics, "lookup_rejected", &[("provider", provider)]);
            let d = retry_after
                .unwrap_or(picket_lookup::client::FIRST_PAUSE)
                .min(picket_lookup::client::MAX_PAUSE);
            let until =
                now + jiff::SignedDuration::try_from(d).unwrap_or(jiff::SignedDuration::from_secs(60));
            state
                .lookups
                .queue
                .hold(provider, tokio::time::Instant::now() + d);
            state
                .lookups
                .update_runtime(provider, |r| r.paused_until = synced.then_some(until));
            o.retry_at = Some(Some(crate::util::ts(&until)));
        }
        AsyncResult::Paused { until } => {
            let d = until.saturating_duration_since(tokio::time::Instant::now());
            let wall = now + jiff::SignedDuration::try_from(d).unwrap_or(jiff::SignedDuration::from_secs(60));
            state.lookups.queue.hold(provider, until);
            state
                .lookups
                .update_runtime(provider, |r| r.paused_until = synced.then_some(wall));
            o.retry_at = Some(Some(crate::util::ts(&wall)));
        }
        AsyncResult::BreakerOpen { until } => {
            let d = until.saturating_duration_since(tokio::time::Instant::now());
            let wall = now + jiff::SignedDuration::try_from(d).unwrap_or(jiff::SignedDuration::from_secs(30));
            state.lookups.queue.hold(provider, until);
            state
                .lookups
                .update_runtime(provider, |r| r.breaker_until = synced.then_some(wall));
            o.retry_at = Some(Some(crate::util::ts(&wall)));
        }
        AsyncResult::LimitsExhausted => {
            o.retry_at = Some(Some(crate::util::ts(&(now + jiff::SignedDuration::from_secs(1)))));
        }
        AsyncResult::ClockUnsynced => {
            // No call: the clock lost its synchronisation while the lookup waited for a slot or
            // a token. The row waits, unchanged, for a synchronised clock (module docs).
            tracing::debug!(
                provider,
                "a queued lookup makes no call on an unsynchronised clock"
            );
        }
        AsyncResult::Cancelled => {}
    }
    if !synced && matches!(o.retry_at, Some(Some(_))) {
        // The clock lost its synchronisation during the lookup: no deadline read from it is
        // written; the row stays due for once the clock is synchronised (module docs, Clocks).
        o.retry_at = None;
    }
    if !keep_reservation {
        o.release_recheck = reserved;
    }
    state.metrics.count(&state.metrics_db, metrics).await;
    finish(state, provider, name, o).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_api::edge_config::VerdictCacheSettings;

    fn db() -> (tempfile::TempDir, rusqlite::Connection) {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let c = crate::db::open_connection(&opts, 1024).unwrap();
        (d, c)
    }

    fn t(s: i64) -> Timestamp {
        Timestamp::new(1_763_700_000 + s, 0).unwrap()
    }

    /// core.md §7 Queue: a live entry settles a need at admission; needs and re-checks merge into
    /// one row per (provider, name); a retry outranks an async attachment and keeps the earlier
    /// due time; later answers add no deadlines until the last pending one has passed; a full
    /// share drops new rows only.
    #[test]
    fn admission_dedups_settles_and_keeps_deadlines() {
        let (_d, mut c) = db();
        let cache = VerdictCacheSettings::default();
        let pv = ProviderView {
            id: "q9",
            generation: "b71e4d09a2c63f58",
            cache: &cache,
        };
        let now = t(0);
        let tx = c.transaction().unwrap();
        // Async attachment, then a retry: one row, retry class, the earlier due time.
        let a = admit(
            &tx,
            &pv,
            "x.example",
            &AdmitKind::Need {
                kind: NeedKind::Async,
                due_at: t(0),
            },
            Some("kids"),
            Some("e1/10.0.0.2"),
            false,
            now,
        )
        .unwrap();
        assert_eq!(a, Admitted::Queued);
        let a = admit(
            &tx,
            &pv,
            "x.example",
            &AdmitKind::Need {
                kind: NeedKind::Retry,
                due_at: t(15),
            },
            Some("adults"),
            None,
            false,
            now,
        )
        .unwrap();
        assert_eq!(a, Admitted::Merged);
        let (reason, class, next): (String, i64, String) = tx
            .query_row(
                "SELECT reason, class, next_at FROM lookup_queue WHERE name = 'x.example'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((reason.as_str(), class), ("retry", 0));
        assert_eq!(next, crate::util::ts(&t(0)));
        // Re-checks: deadlines from the first answer; a later answer before the last deadline
        // adds none; one after it adds new ones.
        let dl = vec![t(86_400), t(172_800)];
        let a = admit(
            &tx,
            &pv,
            "y.example",
            &AdmitKind::Recheck {
                answered_at: t(0),
                deadlines: dl.clone(),
            },
            Some("kids"),
            None,
            false,
            now,
        )
        .unwrap();
        assert_eq!(a, Admitted::Queued);
        let a = admit(
            &tx,
            &pv,
            "y.example",
            &AdmitKind::Recheck {
                answered_at: t(3600),
                deadlines: vec![t(90_000), t(176_400)],
            },
            Some("kids"),
            None,
            false,
            now,
        )
        .unwrap();
        assert_eq!(a, Admitted::Unchanged);
        let (_, ctx) = read_row(&tx, "q9", "y.example").unwrap().unwrap();
        assert_eq!(ctx.rechecks, dl.iter().map(crate::util::ts).collect::<Vec<_>>());
        assert_eq!(ctx.answered_at, Some(crate::util::ts(&t(0))));
        let a = admit(
            &tx,
            &pv,
            "y.example",
            &AdmitKind::Recheck {
                answered_at: t(172_801),
                deadlines: vec![t(259_201)],
            },
            None,
            None,
            false,
            now,
        )
        .unwrap();
        assert_eq!(a, Admitted::Merged);
        // A live verdict settles a need without a row.
        tx.execute(
            "INSERT INTO lookup_verdicts(provider_id, name, verdict, obtained_at, generation, source)
             VALUES ('q9', 'z.example', 'clean', ?1, 'b71e4d09a2c63f58', 'edge-1')",
            [crate::util::ts(&now)],
        )
        .unwrap();
        let a = admit(
            &tx,
            &pv,
            "z.example",
            &AdmitKind::Need {
                kind: NeedKind::Retry,
                due_at: t(15),
            },
            None,
            None,
            false,
            now,
        )
        .unwrap();
        assert_eq!(a, Admitted::Settled);
        // A full share drops a new row, but still merges into an existing one.
        let a = admit(
            &tx,
            &pv,
            "new.example",
            &AdmitKind::Need {
                kind: NeedKind::Async,
                due_at: t(0),
            },
            None,
            None,
            true,
            now,
        )
        .unwrap();
        assert_eq!(a, Admitted::Full);
        let a = admit(
            &tx,
            &pv,
            "y.example",
            &AdmitKind::Need {
                kind: NeedKind::Async,
                due_at: t(0),
            },
            None,
            None,
            true,
            now,
        )
        .unwrap();
        assert_eq!(a, Admitted::Merged);
        tx.commit().unwrap();
    }

    #[test]
    fn schedule_orders_needs_before_rechecks_and_honours_backoff() {
        let mut ctx = ItemCtx {
            rechecks: vec![crate::util::ts(&t(100))],
            ..ItemCtx::default()
        };
        assert_eq!(ctx.schedule().unwrap().2, "recheck");
        ctx.need = Some(Need {
            kind: NeedKind::Async,
            due_at: crate::util::ts(&t(50)),
        });
        assert_eq!(ctx.schedule().unwrap(), (crate::util::ts(&t(50)), 1, "async"));
        ctx.retry_at = Some(crate::util::ts(&t(500)));
        assert_eq!(ctx.schedule().unwrap().0, crate::util::ts(&t(500)));
        ctx.need = None;
        ctx.rechecks.clear();
        assert!(ctx.schedule().is_none());
    }

    #[test]
    fn backoff_doubles_to_an_hour_with_jitter() {
        for (n, base) in [(1, 30.0), (2, 60.0), (3, 120.0), (8, 3600.0), (40, 3600.0)] {
            let d = backoff(n).as_secs_f64();
            assert!(d >= base * 0.8 - 0.01 && d <= base * 1.2 + 0.01, "{n}: {d}");
        }
    }

    #[test]
    fn deadlines_follow_after_and_jitter() {
        let mut p = LookupProviderDef::default();
        p.settings.recheck.after = vec![
            picket_api::DurationStr::hours(24),
            picket_api::DurationStr::hours(48),
        ];
        p.settings.recheck.jitter = picket_api::DurationStr::hours(1);
        let d = recheck_deadlines(&p, t(0));
        assert_eq!(d.len(), 2);
        assert!(d[0] >= t(86_400) && d[0] <= t(90_000));
        assert!(d[1] >= t(172_800) && d[1] <= t(176_400));
        p.settings.recheck.enabled = false;
        assert!(recheck_deadlines(&p, t(0)).is_empty());
    }
}
