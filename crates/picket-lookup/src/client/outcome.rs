//! What a lookup returns, on the edge (sync, edge.md §10) and on core (async, core.md §7), and
//! how the edge logs it (api.md §5 `lookups[]` items and `lookup` records).

use std::sync::Arc;
use std::time::Duration;

use picket_api::edge_config::FailMode;
use picket_api::logs::{LookupItem, LookupRecord, LookupVerdict, RecordHeader};
use picket_api::time::Timestamp;
use serde_json::Value;
use tokio::time::Instant;

use crate::module::Verdict;

/// A verdict as caches, verdict sets and outcomes hold it (the reason shared, no detail).
#[derive(Clone, Debug, PartialEq)]
pub enum StoredVerdict {
    Block { score: Option<f32>, reason: Arc<str> },
    Clean,
    Unknown,
}

impl StoredVerdict {
    pub fn log_verdict(&self) -> LookupVerdict {
        match self {
            Self::Block { .. } => LookupVerdict::Block,
            Self::Clean => LookupVerdict::Clean,
            Self::Unknown => LookupVerdict::Unknown,
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    fn score(&self) -> Option<f32> {
        match self {
            Self::Block { score, .. } => *score,
            _ => None,
        }
    }

    fn reason(&self) -> Option<String> {
        match self {
            Self::Block { reason, .. } => Some(reason.to_string()),
            _ => None,
        }
    }
}

impl From<&Verdict> for StoredVerdict {
    fn from(v: &Verdict) -> Self {
        match v {
            Verdict::Block { score, reason } => Self::Block {
                score: *score,
                reason: reason.as_str().into(),
            },
            Verdict::Clean => Self::Clean,
            Verdict::Unknown => Self::Unknown,
        }
    }
}

impl From<&StoredVerdict> for Verdict {
    fn from(v: &StoredVerdict) -> Self {
        match v {
            StoredVerdict::Block { score, reason } => Self::Block {
                score: *score,
                reason: reason.to_string(),
            },
            StoredVerdict::Clean => Self::Clean,
            StoredVerdict::Unknown => Self::Unknown,
        }
    }
}

/// Where a verdict came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The edge's RAM tier.
    Ram,
    /// The verdict set (or, on core, whatever cache tier core plugged in).
    Set,
    /// A call this lookup started.
    Call,
    /// A call already in flight for the same name (single-flight).
    Joined,
    /// The name failed the label check: Unknown without a call (providers.md §4).
    NameCheck,
}

impl Source {
    /// From a cache tier: logged with `cached: true`.
    pub fn is_cached(self) -> bool {
        matches!(self, Self::Ram | Self::Set)
    }
}

/// How a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Counts against the provider's health: a timeout, a transport error, a malformed answer,
    /// HTTP 5xx.
    Failed,
    /// Doesn't count against health: an unexpected status, a config or secret problem, a panic.
    Other,
}

/// A sync lookup's result (edge.md §10).
#[derive(Clone, Debug, PartialEq)]
pub enum SyncResult {
    Verdict {
        verdict: StoredVerdict,
        source: Source,
        /// When the provider answered; `None` only for [`Source::NameCheck`].
        obtained_at: Option<Timestamp>,
        /// The answer's detail, only on an answer the provider gave for this query.
        detail: Option<Arc<Value>>,
    },
    /// The deadline passed; the call goes on in the background (late answers: edge.md §10).
    Timeout,
    /// The call failed, or a cached error stopped the call (`cached`).
    Error {
        kind: ErrorKind,
        message: Arc<str>,
        cached: bool,
    },
    /// The call was rejected, or the provider is paused after a rejection (`paused`).
    Rejected {
        paused: bool,
    },
    BreakerOpen,
    /// `max_inflight` reached or the token bucket empty.
    LimitsExhausted,
    /// A cache-only lookup ([`crate::SyncRequest::call`] false) found no live Block.
    Miss,
}

/// A sync lookup's outcome with what the log needs.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncOutcome {
    pub result: SyncResult,
    /// The `cache_generation` the verdict was obtained under (or the current one).
    pub generation: Arc<str>,
    /// How long this lookup took.
    pub elapsed: Duration,
}

impl SyncOutcome {
    /// Whether this lookup blocks the query under `fail_mode` (edge.md §10 "Failures"): a Block
    /// always; Unknown, a timeout, an error, a rejection or pause, an open breaker and exhausted
    /// limits under `closed`; never a Clean or a cache-only miss.
    pub fn blocks(&self, fail_mode: FailMode) -> bool {
        match &self.result {
            SyncResult::Verdict { verdict, .. } => match verdict {
                StoredVerdict::Block { .. } => true,
                StoredVerdict::Clean => false,
                StoredVerdict::Unknown => fail_mode == FailMode::Closed,
            },
            SyncResult::Miss => false,
            SyncResult::Timeout
            | SyncResult::Error { .. }
            | SyncResult::Rejected { .. }
            | SyncResult::BreakerOpen
            | SyncResult::LimitsExhausted => fail_mode == FailMode::Closed,
        }
    }

    /// The `lookups[].verdict` value, also the EDE `verdict=` token (edge.md §4 EDE).
    pub fn log_verdict(&self) -> Option<LookupVerdict> {
        Some(match &self.result {
            SyncResult::Verdict { verdict, .. } => verdict.log_verdict(),
            SyncResult::Timeout => LookupVerdict::Timeout,
            SyncResult::Error { .. } | SyncResult::BreakerOpen | SyncResult::LimitsExhausted => {
                LookupVerdict::Error
            }
            SyncResult::Rejected { .. } => LookupVerdict::Rejected,
            SyncResult::Miss => return None,
        })
    }

    /// True for a failure core retries (edge.md §10): every failure but Unknown.
    pub fn retry(&self) -> bool {
        !matches!(self.result, SyncResult::Verdict { .. } | SyncResult::Miss)
    }

    /// The `lookups[]` item for this lookup (api.md §5); `None` for a cache-only miss.
    pub fn log_item(&self, provider: &str) -> Option<LookupItem> {
        let verdict = self.log_verdict()?;
        let mut item = LookupItem {
            provider: provider.to_owned(),
            verdict,
            generation: self.generation.to_string(),
            ms: u32::try_from(self.elapsed.as_millis()).unwrap_or(u32::MAX),
            retry: self.retry(),
            ..LookupItem::default()
        };
        match &self.result {
            SyncResult::Verdict {
                verdict,
                source,
                obtained_at,
                detail,
            } => {
                item.score = verdict.score();
                item.reason = verdict.reason();
                item.cached = source.is_cached();
                item.obtained_at = *obtained_at;
                if !source.is_cached() {
                    item.detail = detail.as_deref().cloned();
                }
            }
            SyncResult::Timeout => item.timed_out = true,
            SyncResult::Error { cached, .. } => item.cached = *cached,
            SyncResult::Rejected { .. } => item.rejected = Some(true),
            SyncResult::BreakerOpen | SyncResult::LimitsExhausted | SyncResult::Miss => {}
        }
        Some(item)
    }
}

/// An async lookup's result (core.md §7).
#[derive(Clone, Debug, PartialEq)]
pub enum AsyncResult {
    /// The provider answered, under the generation that is current (an answer of a call whose
    /// generation moved on is never returned: the lookup calls again, or ends with
    /// [`AsyncResult::GenerationMoved`]). Store it only when
    /// `storable`: false when the cache was emptied (flushed) after the call started
    /// (providers.md §4).
    Answer {
        verdict: StoredVerdict,
        obtained_at: Timestamp,
        detail: Option<Arc<Value>>,
        source: Source,
        storable: bool,
    },
    /// A live verdict from a cache tier.
    Cached {
        verdict: StoredVerdict,
        obtained_at: Timestamp,
        source: Source,
    },
    /// The name failed the label check: Unknown without a call.
    NameCheck,
    /// A call was made and failed (a timeout among them): it uses an attempt.
    Error {
        kind: ErrorKind,
        message: Arc<str>,
        timed_out: bool,
    },
    /// A call was made and rejected: the provider is now paused; not a failure.
    Rejected { retry_after: Option<Duration> },
    /// No call: paused after a rejection until about `until`. The item waits.
    Paused { until: Instant },
    /// No call: the breaker is open until about `until`. The item waits.
    BreakerOpen { until: Instant },
    /// No call: no inflight slot or token within `async_timeout_ms`.
    LimitsExhausted,
    /// The client was dropped.
    Cancelled,
    /// Only with [`super::AsyncOptions::one_attempt`]: the cache generation moved on during the
    /// lookup, so nothing it got is used (providers.md §4 "Cache generation"). `called`: the
    /// lookup had made its own call (not joined another's). Look up again under the new
    /// generation.
    GenerationMoved { called: bool },
    /// No call: the client's clock isn't synchronised ([`crate::Clock::synced`]), so it couldn't
    /// stamp the answer's `obtained_at` (README §2 Clocks). Checked right before the call, after
    /// any wait for a slot or a token. Look up again once it is.
    ClockUnsynced,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AsyncOutcome {
    pub result: AsyncResult,
    pub generation: Arc<str>,
    pub elapsed: Duration,
}

/// The late answer to a sync lookup that timed out (edge.md §10 "Late answers"): it is already
/// in the RAM tier; the edge logs it as a `lookup` record. Delivered once per call, with the
/// distinct tags (e.g. profile ids) of the sync lookups that timed out waiting for it.
#[derive(Clone, Debug, PartialEq)]
pub struct LateAnswer {
    /// The lookup provider id.
    pub provider: Arc<str>,
    pub name: Arc<str>,
    pub verdict: StoredVerdict,
    pub obtained_at: Timestamp,
    pub generation: Arc<str>,
    /// The call's duration.
    pub ms: u32,
    pub detail: Option<Arc<Value>>,
    pub tags: Vec<Arc<str>>,
}

impl LateAnswer {
    /// The `lookup` record (api.md §5) for one profile.
    pub fn to_record(&self, h: RecordHeader, profile: Option<String>) -> LookupRecord {
        LookupRecord {
            h,
            profile,
            // Names that pass the label check are their own log text (api.md §5).
            qname: self.name.to_string(),
            provider: self.provider.to_string(),
            verdict: self.verdict.log_verdict(),
            score: self.verdict.score(),
            reason: self.verdict.reason(),
            obtained_at: Some(self.obtained_at),
            generation: self.generation.to_string(),
            ms: self.ms,
            detail: self.detail.as_deref().cloned(),
        }
    }
}

/// Receives late answers. Called from the call's task: it must not block (the edge `try_send`s
/// to its log buffer).
pub type LateSink = Arc<dyn Fn(LateAnswer) + Send + Sync>;
