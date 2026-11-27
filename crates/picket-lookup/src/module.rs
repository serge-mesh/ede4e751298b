//! The lookup module trait and its types, exactly as providers.md §4 writes them, plus
//! [`Category`] for presets.

use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ctx::LookupCtx;

/// An [`Answer::detail`] stays under this many bytes serialised; the `LookupClient` drops one
/// that doesn't (providers.md §4 "Detail": "under 512 bytes serialised").
pub const DETAIL_MAX: usize = 512;

/// Whether a detail of `serialised_len` bytes is small enough: under [`DETAIL_MAX`].
pub fn detail_fits(serialised_len: usize) -> bool {
    serialised_len < DETAIL_MAX
}

/// A lookup module: compiled-in code that answers whether a name is bad (providers.md §4).
///
/// One module backs any number of lookup providers. The registry builds one `Module` for each
/// module and shares it: `cfg` is the calling lookup provider's `config` with secrets resolved, so
/// `self` keeps no per-provider state (per-provider state lives in [`LookupCtx::state`]).
#[async_trait::async_trait]
pub trait LookupModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn config_schema(&self) -> schemars::Schema;
    /// One lookup. The caller enforces the deadline, caching, single-flight, rate limits, pauses
    /// and breaker.
    async fn lookup(
        &self,
        ctx: &LookupCtx,
        cfg: &serde_json::Value,
        name: &str,
    ) -> Result<Answer, LookupError>;
    /// Optional: a name whose verdict is known, which core checks on a schedule to catch a
    /// provider that answers but no longer filters.
    fn self_test(&self, _cfg: &serde_json::Value) -> Option<SelfTest> {
        None
    }
    /// Optional: ready-made configs the UI offers when adding a lookup provider.
    fn presets(&self) -> Vec<Preset> {
        vec![]
    }
}

/// What a provider answered: the verdict, and what it said beyond it (under [`DETAIL_MAX`] bytes
/// serialised; `http_json` returns `None`).
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    pub verdict: Verdict,
    pub detail: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    Block { score: Option<f32>, reason: String },
    Clean,
    Unknown,
}

/// A self-test (providers.md §4 "Self-tests"): `cron` is UTC and parsed with `croner`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SelfTest {
    pub name: String,
    pub expect: Expect,
    pub cron: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Expect {
    Block,
    Clean,
}

/// Turns a preset's parameters into a full `config` and, optionally, a category.
pub type PresetBuild = fn(&serde_json::Value) -> anyhow::Result<(serde_json::Value, Option<Category>)>;

/// A ready-made config the UI offers when adding a lookup provider (providers.md §4 "Presets").
#[derive(Clone, Debug)]
pub struct Preset {
    pub id: &'static str,
    pub title: &'static str,
    pub params_schema: schemars::Schema,
    pub build: PresetBuild,
}

/// A lookup provider's category, as for feeds (feeds.md §1); default for lookup providers:
/// `security` (providers.md §4). Same values and JSON as core's feed category.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Threats.
    #[default]
    Security,
    /// Ads and tracking.
    Privacy,
    /// Both, or not known.
    Mixed,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Privacy => "privacy",
            Self::Mixed => "mixed",
        }
    }
}

/// Why a lookup produced no verdict (providers.md §4).
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    /// The provider refused the call under its own rate limit or quota (e.g. HTTP 429). Not a
    /// failure.
    #[error("rejected by the provider{}", fmt_retry_after(.retry_after))]
    Rejected { retry_after: Option<Duration> },
    /// A timeout, a transport error, a malformed answer or HTTP 5xx. Counts against the
    /// provider's health (the breaker).
    #[error("{0:#}")]
    Failed(anyhow::Error),
    /// Any other error (e.g. an unexpected HTTP status). Handled like `Failed`, but not counted
    /// against health.
    #[error("{0:#}")]
    Other(anyhow::Error),
}

fn fmt_retry_after(d: &Option<Duration>) -> String {
    match d {
        Some(d) => format!(" (retry after {} s)", d.as_secs()),
        None => String::new(),
    }
}
