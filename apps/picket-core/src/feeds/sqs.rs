//! The `sqs` trigger (feed-scheduling.md §7): one realtime task per enabled `sqs` feed provider
//! long-polls its AWS SQS queue (`ReceiveMessage`, `WaitTimeSeconds` 20, up to 10 messages) over
//! the SQS JSON protocol, signed with AWS Signature Version 4 (`aws-sigv4`), the credentials
//! going only to the queue's host (never across a redirect).
//!
//! - **A message is a nudge.** Its body and attributes are never parsed, stored or logged: only
//!   its id and receipt handle are read, and counts kept. The task records the nudge
//!   (`feed_provider_state.nudged_at`) in `core.db`, then deletes the batch (`DeleteMessageBatch`),
//!   so a restart loses no nudge. The provider is due at once, or when `min_interval` allows; a
//!   check clears only the nudges recorded before it started (`feeds::check`). A message id seen
//!   in the last [`RECENT_IDS`] doesn't nudge again (SQS delivers at least once).
//! - **Pacing:** while a nudge is pending or a check of the provider runs, the task doesn't poll.
//! - **Backstop:** the provider's due time (`schedule::provider_due`) checks it `backstop` after
//!   its previous check whatever the queue says.
//! - **Errors:** a failed receive, or a failed entry in a delete reply (which can come with HTTP
//!   200), is retried after 1, 2, 4 … s, up to 5 min. A nudge that can't be recorded deletes
//!   nothing: the task backs off and the messages come back after their visibility timeout.
//!   Failed deletes are retried on their own backoff without holding up receives, at most
//!   [`MAX_PENDING_DELETES`] messages for at most [`MAX_DELETE_AGE`] each. An entry SQS says
//!   can't succeed with its receipt handle (`SenderFault`, an invalid or expired handle, as a FIFO
//!   queue's become after the visibility timeout) waits for its message to come back: a message
//!   whose delete is pending takes the fresh receipt handle it comes back with and waits for the
//!   pending backoff (no delete, receive and core.db write per loop when the queue hands it back
//!   at once). Receives failing for 1 h, or deletes failing for 1 h, raise
//!   `feed_provider_trigger_down`, resolved once both succeed again: a delete streak ends only
//!   when a delete goes through with nothing left pending (or at a task's start); an entry that
//!   can't succeed counts as a failure, and one that ages out or is dropped past the cap keeps
//!   the streak. Pending deletes live in memory, so a task's start ends a delete streak (and, for
//!   another queue, a receive streak); a trigger changed away from `sqs` or a provider disabled
//!   ends the trigger state and resolves the alert ([`super::Feeds::reload`]), after the task is
//!   stopped; a stopped task (its cancellation token cancelled) writes nothing more.
//! - **A task that ends by itself** (the stored provider no longer has its trigger: an edit not
//!   reloaded yet, a deletion) removes its own entry while it still holds its generation, and
//!   [`sync`] starts a task for an entry whose task has finished, so edits A→B→A coalesced into
//!   one reload, or a delete and re-create between reloads, never leave the queue unread. When
//!   the stored trigger is already its own again, the ending task starts its successor at once
//!   (the reload that brought it back may have run while it was still registered).
//! - **FIFO queues** (`.fifo`) are accepted: the spec's queue URL allows them, and with a delete
//!   whose receipt handle expired waiting for the message's fresh one they work as nudges. S3
//!   event notifications can't target them (an AWS restriction), SNS FIFO topics and CI jobs can.
//! - The trigger's own state (`trigger_state_json`): the queue it is for, the last receive,
//!   message and error, the message count, the failing streaks and the recent message ids.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use jiff::Timestamp;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::Cause;
use crate::alerts::{Changes as AlertChanges, RaiseSpec, Severity};
use crate::config::model::Trigger;
use crate::modules::download::client::{Http, Req};
use crate::state::SharedState;

/// Message ids remembered against redelivery.
pub const RECENT_IDS: usize = 1000;
/// The longest retry delay after an error.
pub const MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// `WaitTimeSeconds` of a receive.
pub const WAIT_SECONDS: u32 = 20;
/// The largest reply read.
const MAX_REPLY: usize = 1 << 20;
/// How often a paused task looks again (a pending nudge, a running check).
const PAUSE_TICK: Duration = Duration::from_millis(500);
/// The longest a failed delete entry is retried (policy choice): by then its receipt handle may
/// have expired, and the message comes back anyway, to be ignored by id and deleted with a fresh
/// handle.
pub const MAX_DELETE_AGE: Duration = Duration::from_secs(15 * 60);
/// The most messages kept for a delete retry; the oldest go first (README §2 Bounded).
pub const MAX_PENDING_DELETES: usize = 100;
/// Entries per `DeleteMessageBatch` (SQS's limit).
pub const DELETE_BATCH: usize = 10;

/// The running long-poll tasks, by provider.
#[derive(Default)]
pub struct Tasks {
    inner: Mutex<HashMap<String, Task>>,
    /// The next task's generation: a task that ends by itself removes its own entry only while
    /// it still holds it ([`Tasks::ended`]).
    next_gen: std::sync::atomic::AtomicU64,
    /// Pauses a test set ([`Tasks::pause_once`]); always empty in core itself.
    pauses: Mutex<Vec<(PausePoint, Pause)>>,
}

/// A point where a test holds a [`sync`] or an ending task, to drive an interleaving of the two
/// deterministically (tests only: core itself never sets a pause).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PausePoint {
    /// In [`sync`], once it has read the definitions, still holding the task map's lock.
    SyncRead,
    /// In [`sync`], once it has released the task map's lock.
    SyncDone,
    /// In a task that ended by itself, before it removes its own entry.
    TaskEnding,
}

/// What a test runs at a [`PausePoint`] (it may block: an ending task runs it on a blocking
/// thread).
#[doc(hidden)]
pub type Pause = Box<dyn FnOnce() + Send>;

/// One provider's long-poll task.
struct Task {
    trigger: Trigger,
    cancel: CancellationToken,
    generation: u64,
    handle: tokio::task::JoinHandle<()>,
}

impl Tasks {
    /// True while a task polls for `provider`.
    pub fn running(&self, provider: &str) -> bool {
        self.inner
            .lock()
            .is_ok_and(|m| m.get(provider).is_some_and(|t| !t.handle.is_finished()))
    }

    /// Runs `f` once, the next time `point` is reached (tests).
    #[doc(hidden)]
    pub fn pause_once(&self, point: PausePoint, f: Pause) {
        if let Ok(mut p) = self.pauses.lock() {
            p.push((point, f));
        }
    }

    /// The pause a test set at `point`, taken.
    fn pause(&self, point: PausePoint) -> Option<Pause> {
        let mut p = self.pauses.lock().ok()?;
        let i = p.iter().position(|(q, _)| *q == point)?;
        Some(p.remove(i).1)
    }

    /// A task that ended by itself (`poll` returned without being stopped) removes its entry if
    /// it is still the registered one, so the next [`sync`] starts another.
    fn ended(&self, provider: &str, generation: u64) {
        if let Ok(mut m) = self.inner.lock()
            && m.get(provider).is_some_and(|t| t.generation == generation)
        {
            m.remove(provider);
        }
    }
}

/// Starts a task for each enabled `sqs` provider without one (or whose trigger changed, or whose
/// task ended by itself) and stops the others.
///
/// Syncs run one at a time, each reading the runtime's definitions while it holds the task map:
/// a reload and an ending task's restart ([`restart_if_back`]) can sync at once, and an older
/// sync applying what it read before a newer one would put back a task for the old trigger,
/// which ends at once (its queue isn't the stored one) and leaves no poller (feed-scheduling.md
/// §7: one task per enabled `sqs` provider). So the last sync applies the runtime's definitions
/// as they are then. Those are the newest: reloads run one at a time, each in the order it read
/// the configuration, and each loads what it read before it syncs ([`super::Feeds::reload`]).
pub fn sync(state: &SharedState) {
    let Ok(mut m) = state.feeds.sqs.inner.lock() else {
        return;
    };
    // The feeds lock is taken inside the task map's; nothing takes them the other way round.
    let wanted: HashMap<String, Trigger> = state
        .feeds
        .with(|i| {
            i.providers
                .iter()
                .filter_map(|(id, p)| {
                    let d = p.def.as_ref()?;
                    (d.enabled && matches!(d.trigger, Trigger::Sqs { .. }))
                        .then(|| (id.clone(), d.trigger.clone()))
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(pause) = state.feeds.sqs.pause(PausePoint::SyncRead) {
        pause();
    }
    m.retain(|id, t| {
        // A task that ended by itself is started again below while it is wanted.
        let keep = wanted.get(id) == Some(&t.trigger) && !t.handle.is_finished();
        if !keep {
            t.cancel.cancel();
        }
        keep
    });
    for (id, t) in wanted {
        if m.contains_key(&id) {
            continue;
        }
        let cancel = state.shutdown.child_token();
        let generation = state
            .feeds
            .sqs
            .next_gen
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (s, p, t2, c2) = (state.clone(), id.clone(), t.clone(), cancel.clone());
        let handle = tokio::spawn(async move {
            let gone = poll(s.clone(), p.clone(), t2.clone(), c2.clone()).await;
            if !c2.is_cancelled() {
                if let Some(pause) = s.feeds.sqs.pause(PausePoint::TaskEnding) {
                    let _ = tokio::task::spawn_blocking(pause).await;
                }
                s.feeds.sqs.ended(&p, generation);
                if gone {
                    restart_if_back(&s, &p, &t2).await;
                }
            }
        });
        m.insert(
            id,
            Task {
                trigger: t,
                cancel,
                generation,
                handle,
            },
        );
    }
    drop(m);
    if let Some(pause) = state.feeds.sqs.pause(PausePoint::SyncDone) {
        pause();
    }
}

/// After a task ended because the stored trigger named another queue (or none), a trigger that
/// is already this one again (an edit undone before its reload) starts a task at once: the
/// reload that brought it back may have run while the ending task was still registered. Any
/// other stored trigger waits for its own reload, which starts its task.
async fn restart_if_back(state: &SharedState, provider: &str, t: &Trigger) {
    let p = provider.to_string();
    let stored: Option<String> = state
        .db
        .read(move |c| {
            Ok::<_, anyhow::Error>(
                c.query_row(
                    "SELECT trigger_json FROM feed_providers WHERE id = ?1",
                    [&p],
                    |r| r.get(0),
                )
                .optional()?,
            )
        })
        .await
        .ok()
        .flatten();
    if stored
        .and_then(|j| serde_json::from_str::<Trigger>(&j).ok())
        .as_ref()
        == Some(t)
    {
        sync(state);
    }
}

/// The trigger's state kept in `feed_provider_state.trigger_state_json`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct TriggerState {
    /// The queue the streaks and ids are for.
    pub queue: Option<String>,
    pub last_receive_at: Option<String>,
    pub last_message_at: Option<String>,
    /// Messages received in all.
    pub messages: u64,
    pub last_error: Option<String>,
    pub last_error_at: Option<String>,
    pub receive_failing_since: Option<String>,
    pub delete_failing_since: Option<String>,
    /// The newest message ids (at most 1000).
    // The bound: RECENT_IDS (a test checks the number above).
    pub recent_ids: VecDeque<String>,
}

/// An error a reply carries, without anything the queue sent beyond its error type.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SqsError(String);

#[derive(Deserialize)]
struct ReceiveReply {
    #[serde(default, rename = "Messages")]
    messages: Vec<MessageIds>,
}

/// The two fields of a message core reads: never its body or attributes.
#[derive(Clone, Debug, Deserialize)]
pub struct MessageIds {
    #[serde(rename = "MessageId")]
    pub id: String,
    #[serde(rename = "ReceiptHandle")]
    pub receipt: String,
}

#[derive(Deserialize)]
struct DeleteReply {
    #[serde(default, rename = "Failed")]
    failed: Vec<DeleteFailed>,
}

#[derive(Deserialize)]
struct DeleteFailed {
    #[serde(rename = "Id")]
    id: String,
    #[serde(default, rename = "Code")]
    code: Option<String>,
    #[serde(default, rename = "SenderFault")]
    sender_fault: bool,
}

/// One failed entry of a `DeleteMessageBatch` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteFailure {
    /// The entry's id as sent (its index), at most 16 characters.
    pub id: String,
    /// Its error code, sanitized and short.
    pub code: String,
    /// SQS says the request was at fault (`SenderFault`).
    pub sender_fault: bool,
}

impl DeleteFailure {
    /// True when a retry of this entry can't succeed: the sender's fault, such as a receipt handle
    /// that is invalid or has expired (a FIFO queue's do after the visibility timeout). The
    /// message comes back, is ignored by id and deleted with a fresh receipt handle.
    pub fn permanent(&self) -> bool {
        self.sender_fault || self.code.to_ascii_lowercase().contains("receipthandle")
    }
}

#[derive(Deserialize)]
struct ErrorReply {
    #[serde(default, rename = "__type")]
    kind: Option<String>,
}

/// Reads a `ReceiveMessage` reply: each message's id and receipt handle (at most 10, each at
/// most 1 KiB / 8 KiB).
pub fn parse_receive(body: &[u8]) -> Result<Vec<MessageIds>, SqsError> {
    let r: ReceiveReply =
        serde_json::from_slice(body).map_err(|_| SqsError("the receive reply isn't SQS JSON".into()))?;
    Ok(r.messages
        .into_iter()
        .take(10)
        .filter(|m| {
            !m.id.is_empty() && m.id.len() <= 1024 && !m.receipt.is_empty() && m.receipt.len() <= 8192
        })
        .collect())
}

/// Reads a `DeleteMessageBatch` reply: its failed entries (at most [`DELETE_BATCH`]).
pub fn parse_delete(body: &[u8]) -> Result<Vec<DeleteFailure>, SqsError> {
    let r: DeleteReply =
        serde_json::from_slice(body).map_err(|_| SqsError("the delete reply isn't SQS JSON".into()))?;
    Ok(r.failed
        .into_iter()
        .take(DELETE_BATCH)
        .map(|f| DeleteFailure {
            id: f.id.chars().take(16).collect(),
            code: crate::util::sanitize_for_message(&f.code.unwrap_or_default(), 64),
            sender_fault: f.sender_fault,
        })
        .collect())
}

/// An error reply's type (`AccessDenied`, `QueueDoesNotExist`, …), never its message.
pub fn error_kind(body: &[u8]) -> String {
    let k = serde_json::from_slice::<ErrorReply>(body)
        .ok()
        .and_then(|e| e.kind)
        .unwrap_or_default();
    let short = k.rsplit('#').next().unwrap_or_default();
    crate::util::sanitize_for_message(short, 80)
}

/// The AWS credentials, resolved just before use.
struct Creds {
    access_key_id: String,
    secret_access_key: String,
}

/// Signs and sends one SQS JSON-protocol request (`target` like `AmazonSQS.ReceiveMessage`).
async fn call(
    http: &Http,
    region: &str,
    creds: &Creds,
    target: &str,
    body: Vec<u8>,
) -> Result<bytes::Bytes, SqsError> {
    let host = format!("sqs.{region}.amazonaws.com");
    let url_s = format!("https://{host}/");
    let url = url::Url::parse(&url_s).map_err(|_| SqsError("bad queue URL".into()))?;
    let content_type = "application/x-amz-json-1.0";
    let auth = sign(region, creds, &url_s, &host, content_type, target, &body)?;
    let mut req = Req::post(url, bytes::Bytes::from(body))
        .header("content-type", content_type)
        .and_then(|r| r.header("x-amz-target", target))
        .map_err(|e| SqsError(e.to_string()))?;
    for (k, v) in &auth {
        req = if k == "authorization" {
            req.credential(k, v)
        } else {
            req.header(k, v)
        }
        .map_err(|e| SqsError(e.to_string()))?;
    }
    let resp = http.send(req).await.map_err(|e| SqsError(e.to_string()))?;
    let status = resp.status.as_u16();
    let bytes = resp
        .bytes_limited(MAX_REPLY)
        .await
        .map_err(|e| SqsError(e.to_string()))?;
    if status != 200 {
        let kind = error_kind(&bytes);
        return Err(SqsError(if kind.is_empty() {
            format!("SQS answered HTTP {status}")
        } else {
            format!("SQS answered HTTP {status} ({kind})")
        }));
    }
    Ok(bytes)
}

/// The SigV4 headers of one request (`x-amz-date`, `authorization`): service `sqs`, the queue's
/// region, the host, content type and target signed.
fn sign(
    region: &str,
    creds: &Creds,
    url: &str,
    host: &str,
    content_type: &str,
    target: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>, SqsError> {
    let headers = [
        ("host", host),
        ("content-type", content_type),
        ("x-amz-target", target),
    ];
    sign_at(
        region,
        "sqs",
        creds,
        url,
        &headers,
        body,
        std::time::SystemTime::now(),
    )
}

/// AWS Signature Version 4 (`aws-sigv4`) of a POST at `time`: the headers to add (`x-amz-date`,
/// `authorization`).
fn sign_at(
    region: &str,
    service: &str,
    creds: &Creds,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    time: std::time::SystemTime,
) -> Result<Vec<(String, String)>, SqsError> {
    use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
    use aws_sigv4::sign::v4;
    let identity = aws_credential_types::Credentials::new(
        creds.access_key_id.clone(),
        creds.secret_access_key.clone(),
        None,
        None,
        "picket",
    )
    .into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(time)
        .settings(SigningSettings::default())
        .build()
        .map_err(|_| SqsError("cannot sign the request".into()))?
        .into();
    let req = SignableRequest::new("POST", url, headers.iter().copied(), SignableBody::Bytes(body))
        .map_err(|_| SqsError("cannot sign the request".into()))?;
    let (instr, _sig) = sign(req, &params)
        .map_err(|_| SqsError("cannot sign the request".into()))?
        .into_parts();
    Ok(instr
        .headers()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect())
}

/// One `ReceiveMessage`.
async fn receive(http: &Http, region: &str, queue: &str, creds: &Creds) -> Result<Vec<MessageIds>, SqsError> {
    let body =
        json!({"QueueUrl": queue, "MaxNumberOfMessages": 10, "WaitTimeSeconds": WAIT_SECONDS}).to_string();
    let r = call(http, region, creds, "AmazonSQS.ReceiveMessage", body.into_bytes()).await?;
    parse_receive(&r)
}

/// One `DeleteMessageBatch` of at most [`DELETE_BATCH`] messages: the entries that failed.
async fn delete(
    http: &Http,
    region: &str,
    queue: &str,
    creds: &Creds,
    msgs: &[MessageIds],
) -> Result<Vec<(MessageIds, DeleteFailure)>, SqsError> {
    let entries: Vec<serde_json::Value> = msgs
        .iter()
        .take(DELETE_BATCH)
        .enumerate()
        .map(|(i, m)| json!({"Id": i.to_string(), "ReceiptHandle": m.receipt}))
        .collect();
    let body = json!({"QueueUrl": queue, "Entries": entries}).to_string();
    let r = call(
        http,
        region,
        creds,
        "AmazonSQS.DeleteMessageBatch",
        body.into_bytes(),
    )
    .await?;
    Ok(parse_delete(&r)?
        .into_iter()
        .filter_map(|f| {
            let m = f.id.parse::<usize>().ok().and_then(|i| msgs.get(i).cloned())?;
            Some((m, f))
        })
        .collect())
}

/// What one round of deletes left.
#[derive(Default)]
struct DeleteRound {
    /// Messages whose delete is worth retrying with the same receipt handle.
    retry: Vec<MessageIds>,
    /// Messages whose delete can't succeed with this receipt handle
    /// ([`DeleteFailure::permanent`]): retried once they come back with a fresh one.
    stale: Vec<MessageIds>,
    /// What went wrong, if anything did.
    error: Option<String>,
}

/// Deletes `msgs` in batches of [`DELETE_BATCH`].
async fn delete_all(
    http: &Http,
    region: &str,
    queue: &str,
    creds: &Creds,
    msgs: &[MessageIds],
) -> DeleteRound {
    let mut round = DeleteRound::default();
    for chunk in msgs.chunks(DELETE_BATCH) {
        match delete(http, region, queue, creds, chunk).await {
            Err(e) => {
                round.retry.extend(chunk.iter().cloned());
                round.error = Some(e.to_string());
            }
            Ok(failed) => {
                for (m, f) in failed {
                    let what = if f.code.is_empty() {
                        "an entry of a delete failed".to_string()
                    } else {
                        format!("an entry of a delete failed ({})", f.code)
                    };
                    if f.permanent() {
                        round.stale.push(m);
                    } else {
                        round.retry.push(m);
                    }
                    round.error = Some(what);
                }
            }
        }
    }
    round
}

/// One message whose delete waits for a retry.
#[derive(Clone, Debug)]
struct PendingDelete {
    /// The newest receipt handle.
    msg: MessageIds,
    /// When its delete first failed.
    since: tokio::time::Instant,
    /// False when SQS said this handle can't succeed: no retry until the message comes back with
    /// a fresh one.
    usable: bool,
}

/// Deletes waiting for a retry, in memory (after a restart their messages come back and are
/// deleted then, ignored by id).
#[derive(Default)]
struct Pending {
    entries: Vec<PendingDelete>,
    failures: u32,
    next_try: Option<tokio::time::Instant>,
}

/// What a settled round of deletes means for the delete streak (feed-scheduling.md §7 Errors:
/// "resolved once both succeed again").
#[derive(Clone, Debug, PartialEq, Eq)]
enum Streak {
    /// Every delete tried went through and nothing is pending: the streak ends.
    Ended,
    /// An entry failed (one that can't succeed with its receipt handle included).
    Failing(String),
    /// Nothing that ends or starts it: deletes still pending, or an entry that aged out or was
    /// dropped past the cap without a delete going through (its message comes back and is
    /// deleted then).
    Unchanged,
}

impl Pending {
    /// The messages to retry now: those whose receipt handle may still work, once the backoff
    /// allows.
    fn due(&self, now: tokio::time::Instant) -> Vec<MessageIds> {
        if self.next_try.is_some_and(|t| t > now) {
            return vec![];
        }
        self.entries
            .iter()
            .filter(|e| e.usable)
            .map(|e| e.msg.clone())
            .collect()
    }

    /// A received message whose delete is pending takes the fresh receipt handle it came back
    /// with and stays for the pending backoff; true when it was pending.
    fn refresh(&mut self, m: &MessageIds) -> bool {
        match self.entries.iter_mut().find(|e| e.msg.id == m.id) {
            Some(e) => {
                e.msg.receipt = m.receipt.clone();
                e.usable = true;
                true
            }
            None => false,
        }
    }

    /// Takes in a round's result for the messages it tried: deleted ones leave, failed ones stay
    /// (their first failure kept), entries past [`MAX_DELETE_AGE`] or past
    /// [`MAX_PENDING_DELETES`] go; what that means for the delete streak.
    fn settle(&mut self, tried: &[MessageIds], round: &DeleteRound, now: tokio::time::Instant) -> Streak {
        let failed: std::collections::HashSet<&str> = round
            .retry
            .iter()
            .chain(&round.stale)
            .map(|m| m.id.as_str())
            .collect();
        self.entries
            .retain(|e| failed.contains(e.msg.id.as_str()) || !tried.iter().any(|t| t.id == e.msg.id));
        for (m, usable) in round
            .retry
            .iter()
            .map(|m| (m, true))
            .chain(round.stale.iter().map(|m| (m, false)))
        {
            match self.entries.iter_mut().find(|e| e.msg.id == m.id) {
                Some(e) => {
                    e.msg.receipt = m.receipt.clone();
                    e.usable = usable;
                }
                None => self.entries.push(PendingDelete {
                    msg: m.clone(),
                    since: now,
                    usable,
                }),
            }
        }
        let before = self.entries.len();
        self.entries
            .retain(|e| now.saturating_duration_since(e.since) < MAX_DELETE_AGE);
        while self.entries.len() > MAX_PENDING_DELETES {
            self.entries.remove(0);
        }
        let gone = before - self.entries.len();
        if let Some(e) = &round.error {
            self.failures = self.failures.saturating_add(1);
            self.next_try = Some(now + backoff(self.failures));
            let mut msg = e.clone();
            if !round.stale.is_empty() {
                msg.push_str("; it is deleted when its message comes back with a fresh receipt handle");
            }
            return Streak::Failing(msg);
        }
        if self.entries.is_empty() {
            self.failures = 0;
            self.next_try = None;
            // An entry that aged out or was dropped never went through: the streak stays until a
            // delete does (feed-scheduling.md §7 Errors).
            if gone == 0 {
                return Streak::Ended;
            }
        }
        Streak::Unchanged
    }
}

/// Settles a round and records what it means for the delete streak.
async fn after_deletes(
    state: &SharedState,
    provider: &str,
    queue: &str,
    cancel: &CancellationToken,
    pending: &mut Pending,
    tried: &[MessageIds],
    round: DeleteRound,
) -> Recorded {
    match pending.settle(tried, &round, tokio::time::Instant::now()) {
        Streak::Ended => record(state, provider, queue, cancel, Event::DeleteDone).await,
        Streak::Failing(msg) => record(state, provider, queue, cancel, Event::DeleteFailed(&msg)).await,
        Streak::Unchanged => Recorded::Stored,
    }
}

/// The next retry delay: 1, 2, 4 … s, up to 5 min.
pub fn backoff(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(9);
    Duration::from_secs(1u64 << exp).min(MAX_BACKOFF)
}

/// What one step of the task changes in the trigger's state.
enum Event<'a> {
    /// The task started for this queue: nothing is pending (deletes live in memory), so a delete
    /// streak ends; another queue's receive streak too.
    Start(&'a str),
    ReceiveOk,
    /// New message ids: a nudge (and a successful receive).
    Nudge(&'a [String]),
    ReceiveFailed(&'a str),
    /// Deletes went through with nothing left pending.
    DeleteDone,
    /// A delete entry failed.
    DeleteFailed(&'a str),
}

/// Whether [`record`] stored its event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recorded {
    Stored,
    /// The task was stopped, or the provider is gone or no longer this trigger: the task ends.
    Gone,
    /// The database refused it (the caller decides what that means: a nudge deletes nothing).
    Failed,
}

/// Applies an event to the stored trigger state, the nudge, and `feed_provider_trigger_down`
/// (in one transaction), unless the task was stopped (`cancel`).
async fn record(
    state: &SharedState,
    provider: &str,
    queue: &str,
    cancel: &CancellationToken,
    ev: Event<'_>,
) -> Recorded {
    let now = Timestamp::now();
    let queue = queue.to_string();
    let cancel = cancel.clone();
    let threshold = state.settings().alerts.threshold("feed_provider_trigger_down");
    let alerts = state.alerts.clone();
    let p = provider.to_string();
    let (ids, err, start): (Vec<String>, Option<String>, Option<String>) = match &ev {
        Event::Nudge(ids) => (ids.to_vec(), None, None),
        Event::ReceiveFailed(e) | Event::DeleteFailed(e) => (vec![], Some(e.to_string()), None),
        Event::DeleteDone => (vec![], None, None),
        Event::Start(q) => (vec![], None, Some(q.to_string())),
        Event::ReceiveOk => (vec![], None, None),
    };
    let nudge = matches!(ev, Event::Nudge(_));
    let kind = match ev {
        Event::Start(_) => 4,
        Event::ReceiveOk | Event::Nudge(_) => 0,
        Event::ReceiveFailed(_) => 1,
        Event::DeleteDone => 2,
        Event::DeleteFailed(_) => 3,
    };
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            // A stopped task writes nothing (its successor, or nobody, owns the state now): the
            // writer runs one transaction at a time, and whoever stops a task cancels it before
            // it ends the trigger state (`sqs::sync` before [`trigger_left`]), so a result of a
            // request still in flight never lands after that (README §2 Alerts).
            if cancel.is_cancelled() {
                return Ok::<_, anyhow::Error>(false);
            }
            // Still this provider with this queue (a trigger edit or a deletion).
            let trigger: Option<String> = tx
                .query_row("SELECT trigger_json FROM feed_providers WHERE id = ?1", [&p], |r| r.get(0))
                .optional()?;
            let mine = trigger
                .and_then(|t| serde_json::from_str::<Trigger>(&t).ok())
                .is_some_and(|t| matches!(t, Trigger::Sqs { ref queue_url, .. } if *queue_url == queue));
            if !mine {
                return Ok(false);
            }
            super::store::ensure_provider_state(&tx, &p)?;
            let cur: Option<String> = tx.query_row(
                "SELECT trigger_state_json FROM feed_provider_state WHERE provider_id = ?1",
                [&p],
                |r| r.get(0),
            )?;
            let mut st: TriggerState = cur.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            let ts = crate::util::ts(&now);
            match kind {
                0 => {
                    st.last_receive_at = Some(ts.clone());
                    st.receive_failing_since = None;
                }
                1 => {
                    st.receive_failing_since.get_or_insert(ts.clone());
                }
                2 => st.delete_failing_since = None,
                3 => {
                    st.delete_failing_since.get_or_insert(ts.clone());
                }
                _ => {
                    st.delete_failing_since = None;
                    if st.queue != start {
                        // Another queue: the old one's receive streak and ids say nothing of it.
                        st.receive_failing_since = None;
                        st.recent_ids.clear();
                        st.queue = start.clone();
                    }
                }
            }
            if let Some(e) = &err {
                st.last_error = Some(crate::util::sanitize_for_message(e, 300));
                st.last_error_at = Some(ts.clone());
            }
            if nudge {
                st.last_message_at = Some(ts.clone());
                st.messages = st.messages.saturating_add(ids.len() as u64);
                for id in &ids {
                    st.recent_ids.push_back(id.clone());
                }
                while st.recent_ids.len() > RECENT_IDS {
                    st.recent_ids.pop_front();
                }
                // The nudge is durable before the batch is deleted (feed-scheduling.md §7).
                tx.execute(
                    "UPDATE feed_provider_state SET nudged_at = ?2, due_cause = 'sqs' WHERE provider_id = ?1",
                    rusqlite::params![p, ts],
                )?;
            }
            tx.execute(
                "UPDATE feed_provider_state SET trigger_state_json = ?2 WHERE provider_id = ?1",
                rusqlite::params![p, serde_json::to_string(&st)?],
            )?;
            // Receives or deletes failing for its threshold (1 h) raise the alert; both working
            // again resolve it.
            let since = [&st.receive_failing_since, &st.delete_failing_since]
                .into_iter()
                .flatten()
                .filter_map(|s| crate::util::parse_ts(s))
                .min();
            let which: Vec<&str> = [
                st.receive_failing_since.as_ref().map(|_| "receive"),
                st.delete_failing_since.as_ref().map(|_| "delete"),
            ]
            .into_iter()
            .flatten()
            .collect();
            let spec = RaiseSpec::new(
                "feed_provider_trigger_down",
                Severity::Warning,
                format!("feed_provider_trigger_down:{p}"),
                format!("Feed provider {p}: its SQS queue can't be read"),
                json!({"failing": which, "since": since.map(|s| crate::util::ts(&s)), "last_error": st.last_error}),
            )
            .feed_provider(p.clone());
            let mut ch = AlertChanges::default();
            alerts.condition_in(&tx, &spec, since, threshold, now, &mut ch)?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok(true)
        })
        .await;
    match r {
        Ok(true) => Recorded::Stored,
        Ok(false) => Recorded::Gone,
        Err(e) => {
            tracing::warn!(provider = %provider, error = %format!("{e:#}"), "cannot record the SQS trigger's state");
            Recorded::Failed
        }
    }
}

/// The ids already seen and whether a nudge is pending.
async fn stored(state: &SharedState, provider: &str) -> (VecDeque<String>, bool) {
    let p = provider.to_string();
    state
        .db
        .read(move |c| {
            let s = super::store::load_provider_state(c, &p)?;
            let ids = s
                .trigger_state
                .and_then(|v| serde_json::from_value::<TriggerState>(v).ok())
                .map(|t| t.recent_ids)
                .unwrap_or_default();
            Ok::<_, anyhow::Error>((ids, s.nudged_at.is_some()))
        })
        .await
        .unwrap_or_default()
}

/// The credentials, resolved from their `${secret:name}` references.
async fn creds(state: &SharedState, t: &Trigger) -> Result<Creds, SqsError> {
    let Trigger::Sqs {
        access_key_id,
        secret_access_key,
        ..
    } = t
    else {
        return Err(SqsError("not an sqs trigger".into()));
    };
    let v = serde_json::json!({"a": access_key_id, "s": secret_access_key});
    let names = crate::config::model::FeedProviderDef {
        config: v.clone(),
        ..Default::default()
    }
    .secret_refs();
    let values = state
        .config
        .secret_values(names)
        .await
        .map_err(|_| SqsError("the AWS keys' secrets can't be read".into()))?;
    let r = picket_lookup::secrets::resolve(&v, &values)
        .map_err(|_| SqsError("the AWS keys' secrets have no value yet".into()))?;
    let get = |k: &str| {
        r.config
            .get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let c = Creds {
        access_key_id: get("a"),
        secret_access_key: get("s"),
    };
    if c.access_key_id.is_empty() || c.secret_access_key.is_empty() {
        return Err(SqsError("the AWS keys' secrets have no value yet".into()));
    }
    Ok(c)
}

/// One provider's long-poll loop, until it is stopped (`cancel`) or the stored provider is no
/// longer this trigger (then `true`: [`sync`] starts it again once it is wanted).
async fn poll(state: SharedState, provider: String, t: Trigger, cancel: CancellationToken) -> bool {
    let Trigger::Sqs { queue_url, .. } = &t else {
        return false;
    };
    let Some((region, _, _)) = crate::config::validate::parse_queue_url(queue_url) else {
        return false;
    };
    let mut failures = 0u32;
    let mut pending = Pending::default();
    tracing::info!(provider = %provider, "SQS trigger polling");
    if record(&state, &provider, queue_url, &cancel, Event::Start(queue_url)).await == Recorded::Gone {
        return true;
    }
    loop {
        if cancel.is_cancelled() {
            return false;
        }
        let http = match state.feeds.http(&state.settings().resolver) {
            Ok(h) => h,
            Err(_) => {
                sleep(&cancel, Duration::from_secs(5)).await;
                continue;
            }
        };
        // Deletes that failed are retried on their own backoff, without holding up receives (a
        // message whose delete keeps failing comes back and is ignored by id meanwhile).
        let tried = pending.due(tokio::time::Instant::now());
        if !tried.is_empty() {
            let round = match creds(&state, &t).await {
                Ok(c) => delete_all(&http, &region, queue_url, &c, &tried).await,
                Err(e) => DeleteRound {
                    retry: tried.clone(),
                    stale: vec![],
                    error: Some(e.to_string()),
                },
            };
            if after_deletes(&state, &provider, queue_url, &cancel, &mut pending, &tried, round).await
                == Recorded::Gone
            {
                return true;
            }
        }
        // Pacing: no poll while a nudge is pending or a check runs (feed-scheduling.md §7).
        let (mut seen, nudged) = stored(&state, &provider).await;
        if nudged || state.feeds.is_checking(&provider) {
            let tick = pending.next_try.map_or(PAUSE_TICK, |t| {
                t.saturating_duration_since(tokio::time::Instant::now())
                    .min(PAUSE_TICK)
            });
            sleep(&cancel, tick.max(Duration::from_millis(50))).await;
            continue;
        }
        let creds = match creds(&state, &t).await {
            Ok(c) => c,
            Err(e) => {
                failures += 1;
                if record(
                    &state,
                    &provider,
                    queue_url,
                    &cancel,
                    Event::ReceiveFailed(&e.to_string()),
                )
                .await
                    == Recorded::Gone
                {
                    return true;
                }
                sleep(&cancel, backoff(failures)).await;
                continue;
            }
        };
        let r = tokio::select! {
            _ = cancel.cancelled() => return false,
            r = receive(&http, &region, queue_url, &creds) => r,
        };
        match r {
            Err(e) => {
                failures += 1;
                if record(
                    &state,
                    &provider,
                    queue_url,
                    &cancel,
                    Event::ReceiveFailed(&e.to_string()),
                )
                .await
                    == Recorded::Gone
                {
                    return true;
                }
                sleep(&cancel, backoff(failures)).await;
            }
            Ok(msgs) => {
                let new: Vec<String> = msgs
                    .iter()
                    .map(|m| m.id.clone())
                    .filter(|id| !seen.contains(id))
                    .collect();
                seen.extend(new.iter().cloned());
                let stored = if new.is_empty() {
                    record(&state, &provider, queue_url, &cancel, Event::ReceiveOk).await
                } else {
                    record(&state, &provider, queue_url, &cancel, Event::Nudge(&new)).await
                };
                match stored {
                    Recorded::Gone => return true,
                    Recorded::Failed => {
                        // The nudge (or the receive) isn't durable: nothing is deleted, so the
                        // messages come back after their visibility timeout (feed-scheduling.md
                        // §7: the nudge is recorded before the batch is deleted).
                        failures += 1;
                        sleep(&cancel, backoff(failures)).await;
                        continue;
                    }
                    Recorded::Stored => failures = 0,
                }
                if !new.is_empty() {
                    tracing::info!(provider = %provider, messages = new.len(), "SQS nudge");
                    state.feeds.want_now(&provider, Cause::Sqs);
                }
                // A message whose delete is pending takes its fresh receipt handle and waits for
                // the pending backoff (feed-scheduling.md §7 Errors); the others are deleted now.
                let fresh: Vec<MessageIds> = msgs.iter().filter(|m| !pending.refresh(m)).cloned().collect();
                if !fresh.is_empty() {
                    let round = delete_all(&http, &region, queue_url, &creds, &fresh).await;
                    if after_deletes(&state, &provider, queue_url, &cancel, &mut pending, &fresh, round).await
                        == Recorded::Gone
                    {
                        return true;
                    }
                } else if !msgs.is_empty() {
                    // The queue handed back only messages whose delete is pending (a visibility
                    // timeout shorter than the backoff): the next receive waits for their retry,
                    // at most a long poll's time, so a receive and a core.db write don't loop.
                    let wait = pending
                        .next_try
                        .map_or(Duration::ZERO, |t| {
                            t.saturating_duration_since(tokio::time::Instant::now())
                        })
                        .min(Duration::from_secs(u64::from(WAIT_SECONDS)));
                    sleep(&cancel, wait).await;
                }
            }
        }
    }
}

async fn sleep(cancel: &CancellationToken, d: Duration) {
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = tokio::time::sleep(d) => {}
    }
}

/// A provider's trigger changed away from `sqs`, or the provider was disabled (another queue's
/// task records its own start): its `feed_provider_trigger_down` resolves (`by`) and the receive
/// and delete streaks end, as nothing reads the queue any more (feed-scheduling.md §7, README §2
/// Alerts). The caller stopped the task first ([`sync`]), so nothing it had in flight lands
/// after this.
pub(crate) async fn trigger_left(state: &SharedState, provider: &str, by: &'static str) {
    let alerts = state.alerts.clone();
    let p = provider.to_string();
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let cur: Option<Option<String>> = tx
                .query_row(
                    "SELECT trigger_state_json FROM feed_provider_state WHERE provider_id = ?1",
                    [&p],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(Some(j)) = cur {
                let mut st: TriggerState = serde_json::from_str(&j).unwrap_or_default();
                st.receive_failing_since = None;
                st.delete_failing_since = None;
                tx.execute(
                    "UPDATE feed_provider_state SET trigger_state_json = ?2 WHERE provider_id = ?1",
                    rusqlite::params![p, serde_json::to_string(&st)?],
                )?;
            }
            let mut ch = AlertChanges::default();
            alerts.resolve_in(
                &tx,
                &format!("feed_provider_trigger_down:{p}"),
                Some(&json!({"by": by})),
                &mut ch,
            )?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await;
    match r {
        Ok(ch) => state.alerts.announce(ch),
        Err(e) => {
            tracing::warn!(provider = %provider, error = %format!("{e:#}"), "cannot end the SQS trigger's state")
        }
    }
}

/// The SQS trigger's status for the UI (feed-scheduling.md §6): the last receive, message and
/// error.
pub fn status_of(t: Option<&serde_json::Value>) -> Option<TriggerState> {
    t.and_then(|v| serde_json::from_value::<TriggerState>(v.clone()).ok())
        .map(|mut s| {
            s.recent_ids.clear();
            s
        })
}

/// The time a nudge was recorded, if one is pending (tests).
pub fn nudged(state: &super::store::ProviderState) -> Option<Timestamp> {
    state.nudged_at
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_read_only_ids() {
        let r = parse_receive(
            br#"{"Messages": [{"MessageId": "m1", "ReceiptHandle": "r1", "Body": "{\"secret\": 1}", "MD5OfBody": "x"},
                {"MessageId": "", "ReceiptHandle": "r2"}]}"#,
        )
        .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].id.as_str(), r[0].receipt.as_str()), ("m1", "r1"));
        assert!(parse_receive(b"{}").unwrap().is_empty());
        assert!(parse_receive(b"nope").is_err());
        let f = parse_delete(br#"{"Successful": [{"Id": "0"}], "Failed": [{"Id": "1", "SenderFault": true, "Code": "ReceiptHandleIsInvalid", "Message": "x"}]}"#).unwrap();
        assert_eq!(
            f,
            vec![DeleteFailure {
                id: "1".into(),
                code: "ReceiptHandleIsInvalid".into(),
                sender_fault: true
            }]
        );
        assert!(f[0].permanent());
        let f = parse_delete(
            br#"{"Failed": [{"Id": "0", "SenderFault": false, "Code": "InternalError"},
            {"Id": "1", "Code": "ReceiptHandleIsInvalid"}]}"#,
        )
        .unwrap();
        assert!(!f[0].permanent(), "a server fault is retried");
        assert!(f[1].permanent(), "an invalid receipt handle never succeeds");
        assert_eq!(
            error_kind(br#"{"__type": "com.amazonaws.sqs#QueueDoesNotExist", "message": "acct 123"}"#),
            "QueueDoesNotExist"
        );
    }

    #[test]
    fn backoff_doubles_to_five_minutes() {
        let v: Vec<u64> = (1..=11).map(|f| backoff(f).as_secs()).collect();
        assert_eq!(v, vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300]);
    }

    #[test]
    fn requests_are_signed() {
        let c = Creds {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        };
        let h = sign(
            "eu-west-1",
            &c,
            "https://sqs.eu-west-1.amazonaws.com/",
            "sqs.eu-west-1.amazonaws.com",
            "application/x-amz-json-1.0",
            "AmazonSQS.ReceiveMessage",
            b"{}",
        )
        .unwrap();
        let auth = h.iter().find(|(k, _)| k == "authorization").unwrap().1.clone();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
            "{auth}"
        );
        assert!(auth.contains("/eu-west-1/sqs/aws4_request"), "{auth}");
        assert!(
            auth.contains("SignedHeaders=") && auth.contains("x-amz-target"),
            "{auth}"
        );
        assert!(!auth.contains("wJalrXUtnFEMI"), "the secret never travels");
        assert!(h.iter().any(|(k, _)| k == "x-amz-date"));
    }

    fn m(id: &str, rh: &str) -> MessageIds {
        MessageIds {
            id: id.into(),
            receipt: rh.into(),
        }
    }

    fn ids(p: &Pending) -> Vec<&str> {
        p.entries.iter().map(|e| e.msg.id.as_str()).collect()
    }

    /// feed-scheduling.md §7 Errors: failed deletes are kept per message (the newest receipt
    /// handle), deleted ones leave, and none stays past its age or the cap.
    #[test]
    fn pending_deletes_are_bounded() {
        let t0 = tokio::time::Instant::now();
        let mut p = Pending::default();
        let tried = vec![m("a", "ra1"), m("b", "rb1"), m("c", "rc1")];
        let round = DeleteRound {
            retry: vec![m("a", "ra1")],
            stale: vec![m("b", "rb1")],
            error: Some("x".into()),
        };
        assert!(matches!(p.settle(&tried, &round, t0), Streak::Failing(_)));
        assert_eq!(ids(&p), ["a", "b"]);
        // "a" comes back with a new receipt handle and fails again: one entry, the new handle,
        // its first failure kept.
        let round = DeleteRound {
            retry: vec![m("a", "ra2")],
            error: Some("x".into()),
            ..Default::default()
        };
        p.settle(&[m("a", "ra2")], &round, t0 + Duration::from_secs(60));
        assert_eq!(ids(&p), ["a", "b"]);
        assert_eq!(p.entries[0].msg.receipt, "ra2");
        assert_eq!(p.entries[0].since, t0);
        // Past their age they go, retried or not.
        p.settle(&[m("a", "ra2")], &round, t0 + MAX_DELETE_AGE);
        assert!(p.entries.is_empty());
        // The cap: the oldest go first.
        let many: Vec<MessageIds> = (0..MAX_PENDING_DELETES + 5)
            .map(|i| m(&format!("m{i}"), "r"))
            .collect();
        let round = DeleteRound {
            retry: many.clone(),
            error: Some("x".into()),
            ..Default::default()
        };
        p.settle(&many, &round, t0);
        assert_eq!(p.entries.len(), MAX_PENDING_DELETES);
        assert_eq!(p.entries[0].msg.id, "m5");
        // A message deleted on a later round leaves; untouched ones stay.
        p.settle(&[m("m5", "r")], &DeleteRound::default(), t0);
        assert_eq!(p.entries.len(), MAX_PENDING_DELETES - 1);
        assert_eq!(p.entries[0].msg.id, "m6");
    }

    /// Q1 (feed-scheduling.md §7 Errors, core.md §9): the delete streak ends only when deletes go
    /// through with nothing pending. An entry that can't succeed with its receipt handle is a
    /// failure and waits for a fresh handle; one that ages out (or is dropped past the cap)
    /// without a delete going through keeps the streak, so a delete that always fails reaches the
    /// alert's threshold.
    #[test]
    fn a_delete_streak_ends_only_when_a_delete_goes_through() {
        let t0 = tokio::time::Instant::now();
        let mut p = Pending::default();
        // A retryable failure: failing, retried after the backoff.
        let failed = DeleteRound {
            retry: vec![m("a", "ra1")],
            error: Some("InternalError".into()),
            ..Default::default()
        };
        assert!(matches!(
            p.settle(&[m("a", "ra1")], &failed, t0),
            Streak::Failing(_)
        ));
        assert!(p.due(t0).is_empty(), "the backoff holds the retry");
        assert_eq!(p.due(t0 + backoff(1)).len(), 1);
        // It ages out still failing: nothing pending, but the streak stays.
        let t1 = t0 + MAX_DELETE_AGE;
        assert_eq!(
            p.settle(&[m("a", "ra2")], &failed, t1),
            Streak::Failing("InternalError".into())
        );
        assert!(p.entries.is_empty());
        assert_eq!(
            p.settle(&[], &DeleteRound::default(), t1),
            Streak::Ended,
            "a round that tried nothing pending and had nothing to age"
        );
        let mut p = Pending::default();
        p.settle(&[m("a", "ra1")], &failed, t0);
        // Another message's delete goes through as "a" ages out: the streak stays.
        assert_eq!(
            p.settle(&[m("b", "rb1")], &DeleteRound::default(), t1),
            Streak::Unchanged
        );
        assert!(p.entries.is_empty());
        // An entry that can't succeed with its handle: a failure, kept without a retry until its
        // message comes back with a fresh handle; that one goes through and ends the streak.
        let mut p = Pending::default();
        let stale = DeleteRound {
            stale: vec![m("c", "rc1")],
            error: Some("an entry of a delete failed (AccessDenied)".into()),
            ..Default::default()
        };
        assert!(matches!(
            p.settle(&[m("c", "rc1")], &stale, t0),
            Streak::Failing(_)
        ));
        assert_eq!(ids(&p), ["c"]);
        assert!(
            p.due(t0 + MAX_BACKOFF).is_empty(),
            "no retry with a handle that can't succeed"
        );
        assert!(p.refresh(&m("c", "rc2")), "it came back");
        assert!(!p.refresh(&m("d", "rd1")), "not pending");
        let due = p.due(t0 + backoff(1));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].receipt, "rc2", "retried with the fresh handle");
        assert_eq!(
            p.settle(&due, &DeleteRound::default(), t0 + backoff(1)),
            Streak::Ended
        );
        assert!(p.entries.is_empty() && p.next_try.is_none() && p.failures == 0);
    }

    /// HMAC-SHA256 from `sha2`, for the independent signature below.
    fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&sha2::Sha256::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = sha2::Sha256::new();
        inner.update(k.map(|b| b ^ 0x36));
        inner.update(msg);
        let mut outer = sha2::Sha256::new();
        outer.update(k.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        outer.finalize().to_vec()
    }

    fn sha_hex(b: &[u8]) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(b))
    }

    fn at_2015() -> std::time::SystemTime {
        // 2015-08-30T12:36:00Z, the date of AWS's published SigV4 test suite.
        std::time::UNIX_EPOCH + Duration::from_secs(1_440_938_160)
    }

    fn example_creds() -> Creds {
        Creds {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        }
    }

    /// AWS's published SigV4 test suite, `post-vanilla`: `POST /` to example.amazonaws.com,
    /// service `service`, us-east-1, no body.
    #[test]
    fn sigv4_matches_the_published_post_vanilla_vector() {
        let h = sign_at(
            "us-east-1",
            "service",
            &example_creds(),
            "https://example.amazonaws.com/",
            &[("host", "example.amazonaws.com")],
            b"",
            at_2015(),
        )
        .unwrap();
        let get = |k: &str| h.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("x-amz-date"), "20150830T123600Z");
        assert_eq!(
            get("authorization"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
        );
    }

    /// An SQS request's signature, computed independently from the SigV4 algorithm (canonical
    /// request, string to sign, derived key) with HMAC-SHA256 built on `sha2`.
    #[test]
    fn sigv4_of_an_sqs_request_matches_an_independent_computation() {
        let (region, host) = ("eu-west-1", "sqs.eu-west-1.amazonaws.com");
        let (ct, target) = ("application/x-amz-json-1.0", "AmazonSQS.ReceiveMessage");
        let body = br#"{"QueueUrl":"https://sqs.eu-west-1.amazonaws.com/123456789012/q","MaxNumberOfMessages":10,"WaitTimeSeconds":20}"#;
        let h = sign_at(
            region,
            "sqs",
            &example_creds(),
            &format!("https://{host}/"),
            &[("host", host), ("content-type", ct), ("x-amz-target", target)],
            body,
            at_2015(),
        )
        .unwrap();
        let auth = h.iter().find(|(n, _)| n == "authorization").unwrap().1.clone();
        let date = "20150830T123600Z";
        let canonical = format!(
            "POST\n/\n\ncontent-type:{ct}\nhost:{host}\nx-amz-date:{date}\nx-amz-target:{target}\n\n\
             content-type;host;x-amz-date;x-amz-target\n{}",
            sha_hex(body)
        );
        let scope = format!("20150830/{region}/sqs/aws4_request");
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
            sha_hex(canonical.as_bytes())
        );
        let k = hmac(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
        let k = hmac(&k, region.as_bytes());
        let k = hmac(&k, b"sqs");
        let k = hmac(&k, b"aws4_request");
        let sig = hex::encode(hmac(&k, to_sign.as_bytes()));
        assert_eq!(
            auth,
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, \
                 SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature={sig}"
            )
        );
    }
}
