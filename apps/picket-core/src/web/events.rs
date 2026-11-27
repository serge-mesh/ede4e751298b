//! The UI WebSocket `/api/ui/v1/events` (api.md §7): `{type, data}` text frames from the UI
//! event bus. Basic auth is checked on the upgrade (`web::protect`), and the `Origin` must be
//! the page's own (`https://` + Host; `http://` with `web.tls` off), else `403`.
//!
//! **`job` events** ([`forward_jobs`]): each heavy job's start and end as the heavy lane reports
//! it, with the lane's id of that run and the fields `GET jobs` returns. Paced at most one per
//! [`JOB_EVENT_GAP`]; reports waiting to be sent are coalesced per run (a run's end stands for its
//! start not sent yet, which `coalesced` counts), never across runs, even of the same job, so
//! every run's end reaches the UI, failures included, and no end stands for another run's start.
//! At most [`MAX_PENDING_JOB_REPORTS`] wait (README §2 Bounded): past it the oldest waiting
//! start, else the oldest waiting end, is dropped, counted in the next event's `dropped`, so the
//! newest report always reaches the UI.
//!
//! **Other events** (api.md §7 names the union; the spec is silent on the new ones, so they
//! follow the `job` events' style): `restore` once a config restore has committed and core has
//! reloaded from it ([`RestoreEvent`]: every open tab resyncs); `temp_allow` when temporary
//! allows change ([`TempAllowEvent`]: allow records ingested from an edge's log, a revoke
//! requested or acknowledged by the edge, a reported expiry passed); `dnssec` when DNSSEC
//! results are stored ([`DnssecEvent`]) and `dnssec_queued` when DNSSEC validations or
//! cross-checks are queued ([`DnssecQueuedEvent`]); `lanca` when the LAN CA's roots change
//! (`lanca::rotation::LancaEvent`) and `lanca_served` when, while a previous root is kept (a
//! rotation in progress), an edge's stored report of the roots its managed listeners serve changes
//! ([`LancaServedEvent`]: an edge moved to the current root, so the UI sees a rotation progress and
//! finish without polling; `lanca` `previous_dropped` marks the end). All but `restore` and `lanca`
//! are coalesced ([`Coalesced`]): each type is sent at most once per [`COALESCE_GAP`], carrying the
//! counts since its previous event, so a burst costs one event a second (README §2 Bounded). The
//! union with every type's data is the OpenAPI schema `UiEventFrame` ([`frame_schema`]).
//!
//! **Commit order and the restore boundary** (core.md §2: a restore "looks atomic to the user").
//! A change is noted on the core.db writer right after the commit that made it (as the alert
//! open-set cache follows `alerts`), so notes come in commit order: an alert's latest note is its
//! state, and a run or a deletion committed before a restore is noted before it. The restore's
//! commit then sends every coalesced event waiting, at once, on the writer
//! ([`crate::state::UiEvents::flush_coalesced`], under the same ordering lock as the forwarder):
//! what changed before the restore goes out before its `restore` event (sent once core has
//! reloaded), and nothing from before it is merged into an event after it. The sole note not made
//! on the writer is the expiry watch's (`temp_allow` `expired`, from a read: a refetch hint
//! only). A restore costs at most one extra event of each type (README §2 Bounded: one restore
//! runs at a time).
//!
//! **`alert` and `feed_run`** (api.md §7 names both; their data is core's, in the same coalesced
//! style): a bulk delete, a provider check ingesting many feeds or many records raising alerts
//! would otherwise send one event per change to every open tab. Each event lists what changed
//! since the previous one, bounded: [`AlertEvent`] each alert once with its latest state
//! ([`MAX_EVENT_ALERTS`]), [`FeedRunEvent`] each run stored with the fields that place it
//! ([`MAX_EVENT_RUNS`]); past the bound, `*_truncated` says some went unlisted (refetch). An alert
//! is listed too when the evidence backfill or live capture changed its evidence (core.md §9
//! Evidence: `logs::evidence`), so an open alert's view re-reads its evidence then. The
//! `dnssec_queued` event covers every change to the queues `GET dnssec/queue` shows (queued,
//! joined, retried, waiting, cross-checks ended, dropped, stamped), so its view needn't poll while
//! the socket is open; stored results come as `dnssec`.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::SinkExt;
use tokio::sync::broadcast::error::RecvError;

use super::protect::origin_allowed;
use crate::settings::WebTls;
use crate::state::SharedState;

/// Concurrent UI WebSockets (bounded).
const MAX_SOCKETS: usize = 64;
static OPEN: AtomicUsize = AtomicUsize::new(0);
/// The longest one frame (or the close) may take to send: a stalled client can't hold the pump
/// (and its slot) past it, nor delay shutdown or lag handling (README §2, Bounded).
const SEND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// One UI WebSocket slot; dropping it frees the slot. It moves into the upgrade callback, which
/// axum drops without calling when the upgrade fails (the client went away before the 101 was
/// written), so a failed upgrade frees its slot too.
struct Slot;

impl Slot {
    fn acquire() -> Option<Self> {
        if OPEN.fetch_add(1, Ordering::AcqRel) >= MAX_SOCKETS {
            OPEN.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        OPEN.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Sends one frame within [`SEND_DEADLINE`]; false when it failed or timed out.
async fn send(socket: &mut WebSocket, msg: Message) -> bool {
    matches!(
        tokio::time::timeout(SEND_DEADLINE, socket.send(msg)).await,
        Ok(Ok(()))
    )
}

/// UI event streams open (or upgrading) now.
pub fn open_streams() -> usize {
    OPEN.load(Ordering::Acquire)
}

pub async fn upgrade(
    State(state): State<SharedState>,
    conn: Option<axum::Extension<super::ConnTls>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    // The scheme this connection uses; a saved web.tls change applies only at restart.
    let tls = match conn {
        Some(axum::Extension(super::ConnTls(t))) => t,
        None => state.settings().web.tls != WebTls::Off,
    };
    if !origin_allowed(origin, host, tls) {
        return (StatusCode::FORBIDDEN, "forbidden: bad Origin\n").into_response();
    }
    let Some(slot) = Slot::acquire() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "too many event streams\n").into_response();
    };
    ws.max_message_size(64 * 1024)
        .on_upgrade(move |socket| async move {
            let _slot = slot;
            pump(state, socket).await;
        })
}

async fn pump(state: SharedState, mut socket: WebSocket) {
    let mut rx = state.events.subscribe();
    let shutdown = state.shutdown.clone();
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(20));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            ev = rx.recv() => match ev {
                Ok(ev) => {
                    let Ok(text) = serde_json::to_string(&ev) else { continue };
                    if !send(&mut socket, Message::Text(text.into())).await {
                        break;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    // Too slow: tell the UI to refetch, then drop the stream; it reconnects.
                    let msg = serde_json::json!({"type": "lagged", "data": {"missed": n}}).to_string();
                    let _ = send(&mut socket, Message::Text(msg.into())).await;
                    break;
                }
                Err(RecvError::Closed) => break,
            },
            _ = ping.tick() => {
                if !send(&mut socket, Message::Ping(Vec::new().into())).await {
                    break;
                }
            }
            msg = socket.recv() => match msg {
                // The UI sends nothing but control frames; anything else is ignored.
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
        }
    }
    let _ = tokio::time::timeout(SEND_DEADLINE, socket.close()).await;
}

/// The shortest time between two `job` events (README §2 Bounded): ten a second at most.
pub const JOB_EVENT_GAP: std::time::Duration = std::time::Duration::from_millis(100);
/// Job reports that may wait for their `job` events (README §2 Bounded; policy choice): 6.4 s of
/// events at [`JOB_EVENT_GAP`].
pub const MAX_PENDING_JOB_REPORTS: usize = 64;

/// A `job` event's data (api.md §7): one heavy job's start or end, then the lanes' state as
/// `GET jobs` returns it.
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct JobEvent {
    /// `start` (its first step) or `end`.
    pub phase: &'static str,
    /// The heavy lane's id of this run: its start and end carry the same one; another run of the
    /// same job another (a newer run can start before an older one ends: core.md §3).
    pub run: u64,
    /// `kind:target`, as `heavy_running` names it.
    pub job: String,
    pub kind: String,
    pub target: String,
    /// At the end: `ok`, `failed`, or `superseded` (a newer job of its kind and target replaced
    /// it between steps); null at the start.
    pub outcome: Option<&'static str>,
    /// At the end: from its first step to its end, in milliseconds.
    pub ms: Option<u64>,
    /// Earlier reports of this run this event stands for, not sent (its start, when its end came
    /// before the start's event could be sent).
    pub coalesced: u64,
    /// Job reports dropped since the previous `job` event because at most 64 may wait (README §2
    /// Bounded), with those they stood for: when not 0, some jobs' starts or ends were never sent
    /// (refetch `GET jobs` and the runs). Every report is sent, counted in a sent event's
    /// `coalesced`, or counted here.
    // The bound: MAX_PENDING_JOB_REPORTS (a test checks the number above).
    pub dropped: u64,
    #[serde(flatten)]
    pub jobs: super::api::JobsView,
}

/// Job reports waiting for their events, oldest first: at most one start per run (its end
/// replaces it), every end, at most [`MAX_PENDING_JOB_REPORTS`] in all.
#[derive(Default)]
struct Pending {
    /// Each report with the earlier reports of its run it replaced.
    queue: std::collections::VecDeque<(crate::scheduler::JobRun, u64)>,
    /// Reports dropped past the bound since the last event.
    dropped: u64,
}

impl Pending {
    fn push(&mut self, run: crate::scheduler::JobRun) {
        // This run's start not sent yet: its end stands for it. Matched by the run, not the job: a
        // newer run of the job may have started before this one ended, and its start stays.
        let mut coalesced = 0;
        if let Some(i) = self
            .queue
            .iter()
            .position(|(r, _)| r.outcome.is_none() && r.run == run.run)
            && let Some((_, c)) = self.queue.remove(i)
        {
            coalesced = c + 1;
        }
        if self.queue.len() >= MAX_PENDING_JOB_REPORTS {
            let oldest_start = self.queue.iter().position(|(r, _)| r.outcome.is_none());
            if let Some((_, c)) = self.queue.remove(oldest_start.unwrap_or(0)) {
                // With the reports it stood for.
                self.dropped += 1 + c;
            }
        }
        self.queue.push_back((run, coalesced));
    }

    /// The oldest report, how many of its run's it replaced, and the reports dropped since the
    /// last one.
    fn pop(&mut self) -> Option<(crate::scheduler::JobRun, u64, u64)> {
        let (run, coalesced) = self.queue.pop_front()?;
        Some((run, coalesced, std::mem::take(&mut self.dropped)))
    }
}

/// Sends a `job` event for each heavy job's start and end (api.md §7), paced by
/// [`JOB_EVENT_GAP`]. The lane's observer only queues the report ([`Pending`]: never blocking
/// the worker, holding no reference to the state); a task sends them, oldest first, until
/// shutdown.
pub fn forward_jobs(state: &SharedState) {
    let slot = std::sync::Arc::new((
        std::sync::Mutex::new(Pending::default()),
        tokio::sync::Notify::new(),
    ));
    let s2 = slot.clone();
    // Job durations for `job_ms{kind}` (core.md §10): heavy jobs as they end, light jobs timed by
    // their lane.
    let metrics = state.metrics.clone();
    state.scheduler.heavy.observe(std::sync::Arc::new(move |run| {
        if let (Some(_), Some(ms)) = (run.outcome, run.ms) {
            metrics.jobs.record(&run.kind, ms);
        }
        if let Ok(mut p) = s2.0.lock() {
            p.push(run);
        }
        s2.1.notify_one();
    }));
    let metrics = state.metrics.clone();
    state
        .scheduler
        .light
        .time_jobs(std::sync::Arc::new(move |kind, ms| metrics.jobs.record(kind, ms)));
    let weak = std::sync::Arc::downgrade(state);
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        loop {
            let next = match slot.0.lock() {
                Ok(mut p) => p.pop(),
                Err(_) => return,
            };
            let Some((run, coalesced, dropped)) = next else {
                // Nothing waiting: a report queued after the look above has left a permit.
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = slot.1.notified() => continue,
                }
            };
            let Some(state) = weak.upgrade() else { return };
            let ev = JobEvent {
                phase: if run.outcome.is_some() { "end" } else { "start" },
                run: run.run,
                job: run.job,
                kind: run.kind,
                target: run.target,
                outcome: run.outcome,
                ms: run.ms,
                coalesced,
                dropped,
                jobs: super::api::jobs_view(&state),
            };
            if let Ok(data) = serde_json::to_value(&ev) {
                state.events.send("job", data);
            }
            drop(state);
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(JOB_EVENT_GAP) => {}
            }
        }
    });
}

/// A `restore` event's data (api.md §7): a config restore committed and core reloaded from it
/// (core.md §2). Every open tab refetches what it shows.
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct RestoreEvent {
    /// When the restore finished.
    pub at: String,
    /// The restore generation: one more with every restore since core started. The restore's own
    /// `PUT config/export` response carries the same value, so the tab that restored knows its
    /// event. This event goes out (after the commit) before that response, so the tab re-reads
    /// once, on whichever of the two comes first; and the generation starts again at 0 when core
    /// restarts (a tab forgets the generations it knows when this WebSocket reconnects).
    pub generation: u64,
}

/// A `temp_allow` event's data (api.md §7): temporary allows changed since the previous
/// `temp_allow` event (coalesced: at most one a second, plus one when a restore commits). Refetch `GET temp-allows` (and a
/// device's or profile's `query-summary`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct TempAllowEvent {
    /// The edges whose allows changed, at most 64.
    // The bound: MAX_EVENT_EDGES (a test checks the number above).
    pub edges: Vec<String>,
    /// More edges changed than `edges` lists.
    pub edges_truncated: bool,
    /// Allow records (`created`, `extended`, `revoked`, `expired`) stored from the edges' logs.
    pub ingested: u64,
    /// Allows whose reported expiry passed (core marks them `expired`).
    pub expired: u64,
    /// Revokes requested in the UI.
    pub revoke_requested: u64,
    /// Allows whose revoke an edge acknowledged (now `revoked`).
    pub revoke_acked: u64,
}

/// What changed about temporary allows ([`Coalesced::temp_allow`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowChange {
    Ingested(u64),
    Expired(u64),
    RevokeRequested,
    RevokeAcked(u64),
}

/// A `dnssec` event's data (api.md §7): DNSSEC validation results stored since the previous
/// `dnssec` event (coalesced: at most one a second, plus one when a restore commits). Refetch the DNSSEC queue and results.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct DnssecEvent {
    pub results: u64,
    /// By outcome: `secure`, `insecure`, `bogus`, `indeterminate`.
    pub outcomes: std::collections::BTreeMap<String, u64>,
}

/// A `dnssec_queued` event's data (api.md §7): the DNSSEC validation and cross-check queues
/// changed since the previous `dnssec_queued` event (coalesced: at most one a second, plus one when a restore commits). Refetch
/// the DNSSEC queue (`GET dnssec/queue`). Every change to what it shows sends one, except a
/// validation result stored, which sends `dnssec` instead (the item leaves the queue then), and
/// a restore, which sends `restore`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct DnssecQueuedEvent {
    /// Answers queued for validation (`dnssec_queue`, core.md §8).
    pub validation: u64,
    /// Names queued for the cross-check of unsigned answers (core.md §8 Cross-check).
    pub crosscheck: u64,
    /// Records that joined a queued validation (its records, edges, clients and groups).
    pub joined: u64,
    /// Validations rescheduled after a failed request (`attempts` moved; core.md §8 backoff).
    pub retried: u64,
    /// Validations rescheduled to wait while no edge DoH listener is reachable (core.md §8): each
    /// item's `next_at` moves 30 s on, no attempt used, so each comes again in the queue's order.
    pub waiting: u64,
    /// Cross-checks rescheduled after a failed query (core.md §8 Cross-check: 3 attempts).
    pub crosscheck_retried: u64,
    /// Cross-checks that ended (agree, disagree or no answer) and left the queue.
    pub crosscheck_ended: u64,
    /// Items dropped from either queue: older than the retention window, or queued while the
    /// cross-check is off (core.md §8).
    pub dropped: u64,
    /// Items of either queue given their times once the wall clock was synchronised (README §2
    /// Clocks).
    pub stamped: u64,
}

impl DnssecQueuedEvent {
    fn add(&mut self, o: &Self) {
        for (a, b) in [
            (&mut self.validation, o.validation),
            (&mut self.crosscheck, o.crosscheck),
            (&mut self.joined, o.joined),
            (&mut self.retried, o.retried),
            (&mut self.waiting, o.waiting),
            (&mut self.crosscheck_retried, o.crosscheck_retried),
            (&mut self.crosscheck_ended, o.crosscheck_ended),
            (&mut self.dropped, o.dropped),
            (&mut self.stamped, o.stamped),
        ] {
            *a = a.saturating_add(b);
        }
    }
}

/// A `lanca_served` event's data (api.md §7): while core keeps a previous LAN CA root (a rotation
/// in progress), edges' reports of the root each managed listener's certificate comes from
/// changed since the previous `lanca_served` event (coalesced: at most one a second, plus one when a restore commits). Refetch
/// `GET settings`: `lanca.previous[].edges` loses an edge once all its managed listeners
/// serve a certificate from the current root, and a `lanca` `previous_dropped` event follows once
/// none needs the previous root.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct LancaServedEvent {
    /// The edges whose reports changed, at most 64.
    // The bound: MAX_EVENT_EDGES (a test checks the number above).
    pub edges: Vec<String>,
    /// More edges changed than `edges` lists.
    pub edges_truncated: bool,
    /// Changed reports stored.
    pub reports: u64,
}

/// An `edge_status` event's data (api.md §7): an edge's session or live state changed.
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct EdgeStatusEvent {
    pub edge: String,
    /// `hello`, `heartbeat` or `session_ended`.
    pub event: String,
}

/// A `bundle_version` event's data (api.md §7): a bundle build ended.
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct BundleVersionEvent {
    pub bundle: String,
    /// The head it built, null when it built none.
    pub head: Option<String>,
    /// A new head was published.
    pub published: bool,
    /// The build's statistics (`GET bundles/{id}/versions` keeps them per version).
    pub stats: serde_json::Value,
}

/// A `feed_run` event's data (api.md §7): feed runs stored since the previous `feed_run` event
/// (coalesced: at most one a second, plus one when a restore commits). Refetch the feeds' and providers' statuses and runs;
/// `GET feeds/{id}/runs/{run}` has each run's counts, errors and samples. A run stored before a
/// config restore is listed in an event sent before the `restore` event, never after it.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[schemars(transform = crate::web::openapi::sent_always)]
pub struct FeedRunEvent {
    /// The runs stored, in the order they were stored, at most 64: every run of a feed, not only
    /// its latest (a manual feed's editor places each save a run read).
    // The bound: MAX_EVENT_RUNS (a test checks the number above).
    pub runs: Vec<FeedRunItem>,
    /// More runs were stored than `runs` lists: any feed's runs may have changed (an editor
    /// re-reads its feed's runs; a cached manual file is stale).
    pub runs_truncated: bool,
    /// Runs stored since the previous event, listed or not.
    pub stored: u64,
}

/// One stored feed run in a `feed_run` event: what places it (feeds.md §1 manual feeds: the
/// version and save time it read). Every field is always sent, null where it has no value.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[schemars(transform = crate::web::openapi::sent_always)]
pub struct FeedRunItem {
    pub feed: String,
    pub run: i64,
    /// `download`, `reingest`, `expire` or `import`.
    pub kind: String,
    /// `applied`, `held`, `rejected` or `expired`.
    pub status: String,
    /// The sanity gate that held or rejected it.
    pub gate: Option<String>,
    /// The file version it read.
    pub version: Option<String>,
    /// For a manual feed: the save time of the file it read; null for other feeds.
    pub saved_at: Option<String>,
    /// An applied run that reused an earlier run's entries: that run.
    pub source_run: Option<i64>,
}

/// An `alert` event's data (api.md §7): alerts raised, repeated, updated, resolved or deleted,
/// or whose evidence changed, since the previous `alert` event (coalesced: at most one a second, plus one when a restore commits).
/// Refetch the alert lists (and an alert's evidence that is shown, when `alerts` lists it not
/// deleted, or is truncated). Changes made before a config restore go out in an event sent
/// before the `restore` event, never after it.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[schemars(transform = crate::web::openapi::sent_always)]
pub struct AlertEvent {
    /// Each alert that changed, once, with its state after its latest change, in the order of
    /// their first change; at most 64.
    // The bound: MAX_EVENT_ALERTS (a test checks the number above).
    pub alerts: Vec<AlertEventItem>,
    /// More alerts changed than `alerts` lists: any alert may have changed.
    pub alerts_truncated: bool,
    /// Changes since the previous event, listed or not, one for each: a raise (new, repeated or
    /// reopened), an update of only an alert's details (more names, edges or clients joining
    /// it), a resolve (also an alert resolved again by hand that already was), a deletion, and
    /// each committed change to an alert's evidence (records copied or counted).
    pub changes: u64,
}

/// One alert in an `alert` event (`GET alerts/{id}` has the rest). Every field is always sent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[schemars(transform = crate::web::openapi::sent_always)]
pub struct AlertEventItem {
    pub id: i64,
    pub kind: String,
    /// `open` or `resolved`; null once deleted.
    pub state: Option<crate::alerts::AlertState>,
    /// Its raises so far (`Alert.count`).
    pub count: i64,
    /// Deleted: gone with its history and evidence (ids are never reused).
    pub deleted: bool,
}

impl AlertEventItem {
    /// An alert as it stands after a raise or a resolve.
    pub fn of(a: &crate::alerts::Alert) -> Self {
        Self {
            id: a.id,
            kind: a.kind.clone(),
            state: Some(a.state),
            count: a.count,
            deleted: false,
        }
    }

    /// A deleted alert, with the kind and count it had.
    pub fn deleted(id: i64, kind: String, count: i64) -> Self {
        Self {
            id,
            kind,
            state: None,
            count,
            deleted: true,
        }
    }
}

/// A `lagged` frame's data: this socket missed `missed` events (it closes next; refetch).
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct LaggedEvent {
    pub missed: u64,
}

/// The UI WebSocket's frame types and their data schemas (api.md §7 union), for the OpenAPI
/// document's `UiEventFrame`.
pub const FRAME_TYPES: &[(&str, &str)] = &[
    ("alert", "AlertEvent"),
    ("edge_status", "EdgeStatusEvent"),
    ("job", "JobEvent"),
    ("feed_run", "FeedRunEvent"),
    ("bundle_version", "BundleVersionEvent"),
    ("restore", "RestoreEvent"),
    ("temp_allow", "TempAllowEvent"),
    ("dnssec", "DnssecEvent"),
    ("dnssec_queued", "DnssecQueuedEvent"),
    ("lanca", "LancaEvent"),
    ("lanca_served", "LancaServedEvent"),
    ("lagged", "LaggedEvent"),
];

/// The `UiEventFrame` schema: `{type, data}`, one variant per [`FRAME_TYPES`] entry.
pub fn frame_schema() -> serde_json::Value {
    let variants: Vec<serde_json::Value> = FRAME_TYPES
        .iter()
        .map(|(t, s)| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "type": {"type": "string", "const": t},
                    "data": {"$ref": format!("#/components/schemas/{s}")}
                },
                "required": ["type", "data"]
            })
        })
        .collect();
    serde_json::json!({
        "description": "One UI WebSocket frame (api.md §7 `/api/ui/v1/events`): `{type, data}`. `alert`, `feed_run`, `temp_allow`, `dnssec`, `dnssec_queued` and `lanca_served` are coalesced (at most one per type a second, plus one per type when a restore commits, carrying what changed since the previous one, bounded); `lagged` comes before the socket closes for a client too slow to keep up.",
        "oneOf": variants,
        "discriminator": {"propertyName": "type"}
    })
}

/// The shortest time between two coalesced events of one type (README §2 Bounded): one a second.
pub const COALESCE_GAP: std::time::Duration = std::time::Duration::from_secs(1);
/// Edges one `temp_allow` or `lanca_served` event names at most (README §2 Bounded).
pub const MAX_EVENT_EDGES: usize = 64;
/// Alerts one `alert` event lists at most (README §2 Bounded; policy choice, as
/// [`MAX_EVENT_EDGES`]).
pub const MAX_EVENT_ALERTS: usize = 64;
/// Runs one `feed_run` event lists at most (README §2 Bounded; policy choice, as
/// [`MAX_EVENT_EDGES`]).
pub const MAX_EVENT_RUNS: usize = 64;

/// Adds `edge` to an event's bounded edge list (at most [`MAX_EVENT_EDGES`], each once).
fn note_edge(edges: &mut Vec<String>, truncated: &mut bool, edge: &str) {
    if !edges.iter().any(|x| x == edge) {
        if edges.len() < MAX_EVENT_EDGES {
            edges.push(edge.to_string());
        } else {
            *truncated = true;
        }
    }
}

/// The coalesced events taken for sending ([`Coalesced::take`], tests).
#[cfg(test)]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Taken {
    pub(crate) alert: Option<AlertEvent>,
    pub(crate) feed_run: Option<FeedRunEvent>,
    pub(crate) temp: Option<TempAllowEvent>,
    pub(crate) dnssec: Option<DnssecEvent>,
    pub(crate) dnssec_queued: Option<DnssecQueuedEvent>,
    pub(crate) lanca_served: Option<LancaServedEvent>,
}

#[cfg(test)]
impl Taken {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Coalesced UI events waiting to be sent (module docs): the counts since each type's previous
/// event, merged, so what waits is bounded whatever the burst. Changes are noted on the core.db
/// writer right after their commit, so each type's notes come in commit order.
pub struct Coalesced {
    alert: std::sync::Mutex<Option<AlertEvent>>,
    feed_run: std::sync::Mutex<Option<FeedRunEvent>>,
    temp: std::sync::Mutex<Option<TempAllowEvent>>,
    dnssec: std::sync::Mutex<Option<DnssecEvent>>,
    dnssec_queued: std::sync::Mutex<Option<DnssecQueuedEvent>>,
    lanca_served: std::sync::Mutex<Option<LancaServedEvent>>,
    /// Held across a whole take-and-send pass ([`Coalesced::send_waiting`]), so the forwarder
    /// and a restore's flush are ordered, while notes (on the core.db writer) only ever hold a
    /// slot's lock for a moment and never wait for a send.
    send_order: std::sync::Mutex<()>,
    wake: tokio::sync::Notify,
    /// Allow records arrived: the expiry watch looks again (a new allow may expire first).
    allows_ingested: tokio::sync::Notify,
    /// The shortest time between two events of a type, in milliseconds: [`COALESCE_GAP`] (tests
    /// widen it, [`Coalesced::set_gap`]).
    gap_ms: AtomicU64,
}

impl Default for Coalesced {
    fn default() -> Self {
        Self {
            alert: Default::default(),
            feed_run: Default::default(),
            temp: Default::default(),
            dnssec: Default::default(),
            dnssec_queued: Default::default(),
            lanca_served: Default::default(),
            send_order: Default::default(),
            wake: Default::default(),
            allows_ingested: Default::default(),
            gap_ms: AtomicU64::new(picket_api::duration::as_millis_u64(COALESCE_GAP)),
        }
    }
}

/// Takes the event waiting in `slot`, if any (holding the slot's lock only for the take), and
/// sends it. Called only under [`Coalesced::send_order`], so a flush ([`Coalesced::send_waiting`]
/// at a restore's commit) is ordered with the forwarder: an event taken before the flush has been
/// sent when the flush returns. True when one was sent.
fn send_slot<T: serde::Serialize>(
    slot: &std::sync::Mutex<Option<T>>,
    events: &crate::state::UiEvents,
    kind: &str,
) -> bool {
    let taken = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
    let Some(ev) = taken else { return false };
    if let Ok(data) = serde_json::to_value(ev) {
        events.send(kind, data);
    }
    true
}

impl Coalesced {
    /// Notes an alert's change (sent with the next `alert` event): listed once, with its latest
    /// state, while fewer than [`MAX_EVENT_ALERTS`] are. Notes come in commit order (module
    /// docs), so the latest is the alert's state: a raise after a deletion lists it live (a
    /// restore brought it back; ids are never reused otherwise).
    pub fn alert(&self, item: AlertEventItem) {
        {
            let mut g = self.alert.lock().unwrap_or_else(|p| p.into_inner());
            let e = g.get_or_insert_with(AlertEvent::default);
            e.changes = e.changes.saturating_add(1);
            if let Some(listed) = e.alerts.iter_mut().find(|a| a.id == item.id) {
                *listed = item;
            } else if e.alerts.len() < MAX_EVENT_ALERTS {
                e.alerts.push(item);
            } else {
                e.alerts_truncated = true;
            }
        }
        self.wake.notify_one();
    }

    /// Notes `n` alert changes that aren't listed (sent with the next `alert` event as
    /// `alerts_truncated`: any alert may have changed).
    pub fn alerts_unlisted(&self, n: u64) {
        if n == 0 {
            return;
        }
        {
            let mut g = self.alert.lock().unwrap_or_else(|p| p.into_inner());
            let e = g.get_or_insert_with(AlertEvent::default);
            e.changes = e.changes.saturating_add(n);
            e.alerts_truncated = true;
        }
        self.wake.notify_one();
    }

    /// Notes a stored feed run (sent with the next `feed_run` event): listed while fewer than
    /// [`MAX_EVENT_RUNS`] are.
    pub fn feed_run(&self, run: FeedRunItem) {
        {
            let mut g = self.feed_run.lock().unwrap_or_else(|p| p.into_inner());
            let e = g.get_or_insert_with(FeedRunEvent::default);
            e.stored = e.stored.saturating_add(1);
            if e.runs.len() < MAX_EVENT_RUNS {
                e.runs.push(run);
            } else {
                e.runs_truncated = true;
            }
        }
        self.wake.notify_one();
    }

    /// Notes a temporary-allow change on `edge` (sent with the next `temp_allow` event).
    pub fn temp_allow(&self, edge: &str, change: AllowChange) {
        {
            let mut g = self.temp.lock().unwrap_or_else(|p| p.into_inner());
            let e = g.get_or_insert_with(TempAllowEvent::default);
            note_edge(&mut e.edges, &mut e.edges_truncated, edge);
            match change {
                AllowChange::Ingested(n) => {
                    e.ingested = e.ingested.saturating_add(n);
                    self.allows_ingested.notify_one();
                }
                AllowChange::Expired(n) => e.expired = e.expired.saturating_add(n),
                AllowChange::RevokeRequested => e.revoke_requested = e.revoke_requested.saturating_add(1),
                AllowChange::RevokeAcked(n) => e.revoke_acked = e.revoke_acked.saturating_add(n),
            }
        }
        self.wake.notify_one();
    }

    /// Notes DNSSEC results stored, by outcome (sent with the next `dnssec` event).
    pub fn dnssec(&self, outcomes: &std::collections::BTreeMap<String, u64>) {
        let n: u64 = outcomes.values().sum();
        if n == 0 {
            return;
        }
        {
            let mut g = self.dnssec.lock().unwrap_or_else(|p| p.into_inner());
            let e = g.get_or_insert_with(DnssecEvent::default);
            e.results = e.results.saturating_add(n);
            for (k, v) in outcomes {
                let slot = e.outcomes.entry(k.clone()).or_insert(0);
                *slot = slot.saturating_add(*v);
            }
        }
        self.wake.notify_one();
    }

    /// Notes changes to the DNSSEC and cross-check queues, counted as in [`DnssecQueuedEvent`]
    /// (sent with the next `dnssec_queued` event); none sends nothing.
    pub fn dnssec_queued(&self, changes: &DnssecQueuedEvent) {
        if *changes == DnssecQueuedEvent::default() {
            return;
        }
        self.dnssec_queued
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_or_insert_with(DnssecQueuedEvent::default)
            .add(changes);
        self.wake.notify_one();
    }

    /// Notes that `edge`'s stored report of its managed listeners' roots changed while a previous
    /// LAN CA root is kept (sent with the next `lanca_served` event).
    pub fn lanca_served(&self, edge: &str) {
        {
            let mut g = self.lanca_served.lock().unwrap_or_else(|p| p.into_inner());
            let e = g.get_or_insert_with(LancaServedEvent::default);
            note_edge(&mut e.edges, &mut e.edges_truncated, edge);
            e.reports = e.reports.saturating_add(1);
        }
        self.wake.notify_one();
    }

    /// Sends each type's waiting event now, if any, under [`Coalesced::send_order`] (a slot's lock
    /// is held only to take its event, [`send_slot`]). True when one was sent. The forwarder calls it once per gap; a restore's
    /// commit calls it on the writer ([`crate::state::UiEvents::flush_coalesced`]), so everything
    /// noted before the restore goes out before its `restore` event (module docs).
    pub(crate) fn send_waiting(&self, events: &crate::state::UiEvents) -> bool {
        let _order = self.send_order.lock().unwrap_or_else(|p| p.into_inner());
        // Each in turn, never two slot locks at once.
        let sent = [
            send_slot(&self.alert, events, "alert"),
            send_slot(&self.feed_run, events, "feed_run"),
            send_slot(&self.temp, events, "temp_allow"),
            send_slot(&self.dnssec, events, "dnssec"),
            send_slot(&self.dnssec_queued, events, "dnssec_queued"),
            send_slot(&self.lanca_served, events, "lanca_served"),
        ];
        sent.contains(&true)
    }

    /// The shortest time between two events of a type ([`COALESCE_GAP`]).
    pub fn gap(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.gap_ms.load(Ordering::Relaxed))
    }

    /// Changes [`Coalesced::gap`] (tests: a wide gap keeps a change waiting while a restore runs);
    /// it applies from the forwarder's next wait.
    #[doc(hidden)]
    pub fn set_gap(&self, d: std::time::Duration) {
        self.gap_ms.store(
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// The events waiting, taken (tests).
    #[cfg(test)]
    pub(crate) fn take(&self) -> Taken {
        Taken {
            alert: self.alert.lock().unwrap_or_else(|p| p.into_inner()).take(),
            feed_run: self.feed_run.lock().unwrap_or_else(|p| p.into_inner()).take(),
            temp: self.temp.lock().unwrap_or_else(|p| p.into_inner()).take(),
            dnssec: self.dnssec.lock().unwrap_or_else(|p| p.into_inner()).take(),
            dnssec_queued: self
                .dnssec_queued
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take(),
            lanca_served: self.lanca_served.lock().unwrap_or_else(|p| p.into_inner()).take(),
        }
    }
}

/// Sends the coalesced events (module docs) until shutdown: whatever waits, at most one event of
/// each type per [`COALESCE_GAP`]. Also watches temporary allows' reported expiries
/// ([`watch_allow_expiry`]).
pub fn forward_coalesced(state: &SharedState) {
    let slot = state.events.coalesced().clone();
    let events = state.events.clone();
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = slot.wake.notified() => {}
            }
            while slot.send_waiting(&events) {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(slot.gap()) => {}
                }
            }
        }
    });
    watch_allow_expiry(state);
}

/// The longest the expiry watch sleeps before looking again (new allows arrive with the logs).
const EXPIRY_LOOK: std::time::Duration = std::time::Duration::from_secs(60);

/// Notes a `temp_allow` change when an allow's reported expiry passes (core marks it `expired`
/// as of then, `lookups::api::allow_state`; no record arrives for it): it sleeps until the next
/// expiry among active allows, at most [`EXPIRY_LOOK`], or until allow records arrive, then
/// counts the allows whose expiry passed since its previous look, per edge. Only a UI refresh hint, so the wall clock's
/// synchronisation doesn't gate it (README §2 Clocks covers decisions).
fn watch_allow_expiry(state: &SharedState) {
    let weak = std::sync::Arc::downgrade(state);
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        let mut since = crate::util::now_ts();
        loop {
            let Some(state) = weak.upgrade() else { return };
            let now = crate::util::now_ts();
            let from = since.clone();
            let to = now.clone();
            let r = state
                .db
                .read(move |c| {
                    let mut st = c.prepare(
                        "SELECT edge_id, count(*) FROM temp_allows
                         WHERE expires_at > ?1 AND expires_at <= ?2 AND ended_at IS NULL
                           AND revoke_requested_at IS NULL
                         GROUP BY edge_id LIMIT 1000",
                    )?;
                    let passed = st
                        .query_map(rusqlite::params![from, to], |r| {
                            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    let next: Option<String> = c.query_row(
                        "SELECT min(expires_at) FROM temp_allows
                         WHERE expires_at > ?1 AND ended_at IS NULL AND revoke_requested_at IS NULL",
                        [&to],
                        |r| r.get(0),
                    )?;
                    Ok::<_, anyhow::Error>((passed, next))
                })
                .await;
            let mut wait = EXPIRY_LOOK;
            match r {
                Ok((passed, next)) => {
                    for (edge, n) in passed {
                        state
                            .events
                            .coalesced()
                            .temp_allow(&edge, AllowChange::Expired(crate::util::nonneg(n)));
                    }
                    since = now;
                    if let Some(at) = next.and_then(|t| crate::util::parse_ts(&t)) {
                        let dt = std::time::Duration::try_from(at - crate::util::now()).unwrap_or_default();
                        // Just past the expiry, so the next look counts it.
                        wait = wait.min(dt + std::time::Duration::from_millis(50));
                    }
                }
                Err(e) => tracing::debug!(error = %format!("{e:#}"), "temporary-allow expiry watch"),
            }
            let slot = state.events.coalesced().clone();
            drop(state);
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
                _ = slot.allows_ingested.notified() => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::JobRun;

    fn run(id: u64, job: &str, outcome: Option<&'static str>) -> JobRun {
        JobRun {
            run: id,
            job: job.into(),
            kind: "k".into(),
            target: job.into(),
            outcome,
            ms: outcome.map(|_| 1),
        }
    }

    fn drain(p: &mut Pending) -> Vec<(String, Option<&'static str>, u64, u64)> {
        std::iter::from_fn(|| p.pop())
            .map(|(r, c, d)| (r.job, r.outcome, c, d))
            .collect()
    }

    /// C9 (api.md §7; README §2 Bounded): coalesced events merge their counts until sent, name
    /// each edge once and at most MAX_EVENT_EDGES of them, and a taken event starts afresh.
    #[test]
    fn coalesced_events_merge_and_stay_bounded() {
        let c = Coalesced::default();
        c.temp_allow("e1", AllowChange::Ingested(2));
        c.temp_allow("e1", AllowChange::RevokeRequested);
        c.temp_allow("e2", AllowChange::RevokeAcked(3));
        c.temp_allow("e2", AllowChange::Expired(1));
        c.dnssec(&[("secure".to_string(), 2), ("bogus".to_string(), 1)].into());
        c.dnssec(&[("secure".to_string(), 1)].into());
        c.dnssec(&Default::default());
        let Taken {
            temp: t, dnssec: d, ..
        } = c.take();
        assert_eq!(
            t,
            Some(TempAllowEvent {
                edges: vec!["e1".into(), "e2".into()],
                edges_truncated: false,
                ingested: 2,
                expired: 1,
                revoke_requested: 1,
                revoke_acked: 3,
            })
        );
        let d = d.unwrap();
        assert_eq!((d.results, d.outcomes["secure"], d.outcomes["bogus"]), (4, 3, 1));
        assert!(c.take().is_empty());
        for i in 0..MAX_EVENT_EDGES + 5 {
            c.temp_allow(&format!("e{i}"), AllowChange::Ingested(1));
        }
        let t = c.take().temp.unwrap();
        assert_eq!(t.edges.len(), MAX_EVENT_EDGES);
        assert!(t.edges_truncated);
        assert_eq!(t.ingested, (MAX_EVENT_EDGES + 5) as u64);
    }

    /// F9 (api.md §7; README §2 Bounded): `dnssec_queued` and `lanca_served` coalesce like the
    /// others: counts merge until sent, nothing queued sends nothing, each edge is named once and
    /// at most MAX_EVENT_EDGES of them, and a taken event starts afresh.
    #[test]
    fn queued_and_served_events_coalesce_and_stay_bounded() {
        let c = Coalesced::default();
        let q = |validation, crosscheck| DnssecQueuedEvent {
            validation,
            crosscheck,
            ..Default::default()
        };
        c.dnssec_queued(&q(0, 0));
        assert!(c.take().is_empty(), "nothing queued, no event");
        c.dnssec_queued(&q(3, 0));
        c.dnssec_queued(&q(1, 2));
        c.lanca_served("e1");
        c.lanca_served("e2");
        c.lanca_served("e1");
        let t = c.take();
        assert_eq!(
            t.dnssec_queued,
            Some(DnssecQueuedEvent {
                validation: 4,
                crosscheck: 2,
                ..Default::default()
            })
        );
        assert_eq!(
            t.lanca_served,
            Some(LancaServedEvent {
                edges: vec!["e1".into(), "e2".into()],
                edges_truncated: false,
                reports: 3,
            })
        );
        assert_eq!((t.temp, t.dnssec), (None, None));
        assert!(c.take().is_empty());
        for i in 0..MAX_EVENT_EDGES + 5 {
            c.lanca_served(&format!("e{i}"));
        }
        let s = c.take().lanca_served.unwrap();
        assert_eq!(s.edges.len(), MAX_EVENT_EDGES);
        assert!(s.edges_truncated);
        assert_eq!(s.reports, (MAX_EVENT_EDGES + 5) as u64);
    }

    fn alert_item(id: i64, state: crate::alerts::AlertState, count: i64) -> AlertEventItem {
        AlertEventItem {
            id,
            kind: "feed_held".into(),
            state: Some(state),
            count,
            deleted: false,
        }
    }

    fn run_item(feed: &str, run: i64, saved_at: &str) -> FeedRunItem {
        FeedRunItem {
            feed: feed.into(),
            run,
            kind: "download".into(),
            status: "applied".into(),
            gate: None,
            version: Some(format!("v{run}")),
            saved_at: Some(saved_at.into()),
            source_run: None,
        }
    }

    /// api.md §7, README §2 Bounded: `alert` events coalesce: each alert listed once with its
    /// latest state (id, kind, count, deleted: what the UI refreshes an alert's evidence by), at
    /// most MAX_EVENT_ALERTS listed past which the event says it is truncated, every change
    /// counted (unlisted ones too), and a taken event starts afresh.
    #[test]
    fn alert_events_list_each_alert_once_and_stay_bounded() {
        use crate::alerts::AlertState::{Open, Resolved};
        let c = Coalesced::default();
        c.alert(alert_item(1, Open, 1));
        c.alert(alert_item(2, Open, 1));
        c.alert(alert_item(1, Open, 2));
        c.alert(alert_item(1, Resolved, 2));
        c.alert(AlertEventItem::deleted(2, "feed_held".into(), 1));
        let t = c.take();
        assert_eq!(
            t.alert,
            Some(AlertEvent {
                alerts: vec![
                    alert_item(1, Resolved, 2),
                    AlertEventItem::deleted(2, "feed_held".into(), 1)
                ],
                alerts_truncated: false,
                changes: 5,
            })
        );
        c.alerts_unlisted(0);
        assert!(c.take().is_empty(), "no change, no event");
        c.alerts_unlisted(3);
        assert_eq!(
            c.take().alert,
            Some(AlertEvent {
                alerts: vec![],
                alerts_truncated: true,
                changes: 3,
            })
        );
        assert!(c.take().is_empty());
        for i in 0..MAX_EVENT_ALERTS as i64 + 5 {
            c.alert(alert_item(i, Open, 1));
        }
        c.alert(alert_item(0, Open, 7));
        let e = c.take().alert.unwrap();
        assert_eq!(e.alerts.len(), MAX_EVENT_ALERTS);
        assert!(e.alerts_truncated);
        assert_eq!(
            e.alerts[0],
            alert_item(0, Open, 7),
            "a listed alert still updates"
        );
        assert_eq!(e.changes, MAX_EVENT_ALERTS as u64 + 6);
    }

    /// K1 (api.md §7; core.md §2): notes come in commit order, so an alert's latest note is its
    /// state: a raise after its deletion (a restore brought it back) lists it live.
    #[test]
    fn a_raise_after_a_deletion_lists_the_alert_live() {
        use crate::alerts::AlertState::Open;
        let c = Coalesced::default();
        c.alert(AlertEventItem::deleted(2, "feed_held".into(), 1));
        c.alert(alert_item(2, Open, 2));
        assert_eq!(c.take().alert.unwrap().alerts, vec![alert_item(2, Open, 2)]);
    }

    /// K1 (core.md §2 "It looks atomic to the user"; api.md §7): a flush sends every type's
    /// waiting event at once, in the order the forwarder does, and leaves nothing waiting, so
    /// what is noted after it (after a restore's commit) goes in later events only.
    #[test]
    fn a_flush_sends_everything_waiting_and_starts_afresh() {
        use crate::alerts::AlertState::Open;
        let events = crate::state::UiEvents::new();
        let mut rx = events.subscribe();
        let c = events.coalesced();
        assert!(!c.send_waiting(&events), "nothing waiting, nothing sent");
        c.alert(AlertEventItem::deleted(7, "feed_held".into(), 1));
        c.feed_run(run_item("m", 1, "t1"));
        c.temp_allow("e1", AllowChange::RevokeRequested);
        c.dnssec(&[("secure".to_string(), 1)].into());
        c.dnssec_queued(&DnssecQueuedEvent {
            validation: 1,
            ..Default::default()
        });
        c.lanca_served("e1");
        events.flush_coalesced();
        let kinds: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|e| e.kind)
            .collect();
        assert_eq!(
            kinds,
            [
                "alert",
                "feed_run",
                "temp_allow",
                "dnssec",
                "dnssec_queued",
                "lanca_served"
            ]
        );
        assert!(c.take().is_empty(), "nothing left waiting");
        c.alert(alert_item(7, Open, 2));
        assert_eq!(c.take().alert.unwrap().alerts, vec![alert_item(7, Open, 2)]);
    }

    /// api.md §7, README §2 Bounded: `feed_run` events coalesce: every run stored is listed in
    /// order (two of one feed both, each with the version and save time it read, which a manual
    /// feed's editor places), at most MAX_EVENT_RUNS past which the event says it is truncated,
    /// every run counted.
    #[test]
    fn feed_run_events_list_each_run_and_stay_bounded() {
        let c = Coalesced::default();
        c.feed_run(run_item("m", 1, "t1"));
        c.feed_run(run_item("other", 2, "t0"));
        c.feed_run(run_item("m", 3, "t2"));
        let t = c.take();
        assert_eq!(
            t.feed_run,
            Some(FeedRunEvent {
                runs: vec![
                    run_item("m", 1, "t1"),
                    run_item("other", 2, "t0"),
                    run_item("m", 3, "t2")
                ],
                runs_truncated: false,
                stored: 3,
            })
        );
        assert!(c.take().is_empty());
        for i in 0..MAX_EVENT_RUNS as i64 + 5 {
            c.feed_run(run_item(&format!("f{i}"), i, "t"));
        }
        let e = c.take().feed_run.unwrap();
        assert_eq!(e.runs.len(), MAX_EVENT_RUNS);
        assert!(e.runs_truncated);
        assert_eq!(e.stored, MAX_EVENT_RUNS as u64 + 5);
    }

    /// api.md §7, core.md §8: every kind of queue change merges into the one `dnssec_queued`
    /// event (the UI's queue view refreshes on any), and a note of no change sends nothing.
    #[test]
    fn every_queue_change_merges_into_dnssec_queued() {
        let c = Coalesced::default();
        let one = DnssecQueuedEvent {
            validation: 1,
            crosscheck: 1,
            joined: 1,
            retried: 1,
            waiting: 1,
            crosscheck_retried: 1,
            crosscheck_ended: 1,
            dropped: 1,
            stamped: 1,
        };
        c.dnssec_queued(&DnssecQueuedEvent::default());
        assert!(c.take().is_empty());
        c.dnssec_queued(&one);
        c.dnssec_queued(&DnssecQueuedEvent {
            crosscheck_ended: 2,
            ..Default::default()
        });
        let e = c.take().dnssec_queued.unwrap();
        assert_eq!(
            e,
            DnssecQueuedEvent {
                crosscheck_ended: 3,
                ..one
            }
        );
    }

    /// R4 (api.md §7 `job` events): a run's end stands only for its own start. A newer run of
    /// the same job that started before the older one ended keeps its waiting start, so the UI
    /// never sees the job end while that run goes on.
    #[test]
    fn a_runs_end_never_stands_for_another_runs_start() {
        let mut p = Pending::default();
        p.push(run(1, "a", None));
        assert_eq!(drain(&mut p), vec![("a".into(), None, 0, 0)]);
        p.push(run(2, "a", None));
        p.push(run(1, "a", Some("ok")));
        let out: Vec<_> = std::iter::from_fn(|| p.pop())
            .map(|(r, c, d)| (r.run, r.outcome, c, d))
            .collect();
        assert_eq!(out, vec![(2, None, 0, 0), (1, Some("ok"), 0, 0)]);
        p.push(run(3, "a", None));
        p.push(run(3, "a", Some("failed")));
        assert_eq!(drain(&mut p), vec![("a".into(), Some("failed"), 1, 0)]);
    }

    /// X2 (api.md §7 `job` events): waiting reports coalesce per run only: a run's end stands
    /// for its start, every end is kept (another run of the same job's too), in order.
    #[test]
    fn reports_coalesce_per_run_and_keep_every_end() {
        let mut p = Pending::default();
        for r in [
            run(1, "a", None),
            run(1, "a", Some("ok")),
            run(2, "b", None),
            run(2, "b", Some("failed")),
            run(3, "a", None),
            run(3, "a", Some("ok")),
            run(4, "c", None),
        ] {
            p.push(r);
        }
        assert_eq!(
            drain(&mut p),
            vec![
                ("a".into(), Some("ok"), 1, 0),
                ("b".into(), Some("failed"), 1, 0),
                ("a".into(), Some("ok"), 1, 0),
                ("c".into(), None, 0, 0),
            ]
        );
    }

    /// X2 (README §2 Bounded): past the bound the oldest waiting start goes first, then the
    /// oldest end; the newest report is always kept, and the next event counts what was dropped.
    #[test]
    fn past_the_bound_the_oldest_start_then_the_oldest_end_is_dropped_and_counted() {
        let mut p = Pending::default();
        p.push(run(0, "s", None));
        for i in 0..MAX_PENDING_JOB_REPORTS - 1 {
            p.push(run(i as u64 + 1, &format!("e{i}"), Some("ok")));
        }
        p.push(run(100, "new", Some("failed")));
        assert_eq!(p.queue.len(), MAX_PENDING_JOB_REPORTS);
        assert!(p.queue.iter().all(|(r, _)| r.job != "s"), "the start went first");
        p.push(run(101, "newer", Some("ok")));
        assert_eq!(p.queue.len(), MAX_PENDING_JOB_REPORTS);
        let out = drain(&mut p);
        assert_eq!(
            out[0],
            ("e1".into(), Some("ok"), 0, 2),
            "e0 went next, both counted"
        );
        assert!(out[1..].iter().all(|o| o.3 == 0), "counted once");
        assert_eq!(out.last().unwrap().0, "newer");
    }
}
