//! Types the feed modules share: per-type counts, the parameters an ingest uses, run kinds and
//! statuses, and the parse summary a run keeps (storage.md §3 `feed_runs`).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::model::{DomainsAs, FeedDef, FeedFormat, Mode, Modes, PolicyOption, RulePolicy, Sanity};

/// A count per rule type (`added_json`, `removed_json`, `total_json`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TypeCounts {
    pub dns: u64,
    pub ip: u64,
    pub browser: u64,
}

impl TypeCounts {
    pub fn get(&self, t: picket_rules::RuleType) -> u64 {
        match t {
            picket_rules::RuleType::Dns => self.dns,
            picket_rules::RuleType::Ip => self.ip,
            picket_rules::RuleType::Browser => self.browser,
        }
    }

    pub fn get_mut(&mut self, t: picket_rules::RuleType) -> &mut u64 {
        match t {
            picket_rules::RuleType::Dns => &mut self.dns,
            picket_rules::RuleType::Ip => &mut self.ip,
            picket_rules::RuleType::Browser => &mut self.browser,
        }
    }

    pub fn add(&mut self, t: picket_rules::RuleType, n: u64) {
        let c = self.get_mut(t);
        *c = c.saturating_add(n);
    }

    pub fn total(&self) -> u64 {
        self.dns.saturating_add(self.ip).saturating_add(self.browser)
    }

    pub fn by_name(&self, t: &str) -> u64 {
        picket_rules::RuleType::parse(t).map(|t| self.get(t)).unwrap_or(0)
    }
}

/// What an ingest reads a blob with (feeds.md §3 "Editing a feed": a change to any of these
/// re-ingests the latest applied blob), plus the gates it was judged by.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IngestParams {
    pub format: FeedFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains_as: Option<DomainsAs>,
    pub modes: Modes,
    /// With every option filled in.
    pub rule_policy: RulePolicy,
    pub sanity: Sanity,
}

impl IngestParams {
    pub fn of(f: &FeedDef) -> Self {
        Self {
            format: f.format,
            domains_as: f.format_options.domains_as,
            modes: f.modes.clone(),
            rule_policy: f.rule_policy.resolved(f.is_manual()),
            sanity: f.sanity.clone(),
        }
    }

    /// True when a blob read with `self` and with `other` gives different entries.
    pub fn reads_differently(&self, other: &IngestParams) -> bool {
        self.format != other.format
            || self.domains_as != other.domains_as
            || self.modes != other.modes
            || self.rule_policy != other.rule_policy
    }

    pub fn mode(&self, t: picket_rules::RuleType) -> Mode {
        match t {
            picket_rules::RuleType::Dns => self.modes.dns.mode,
            picket_rules::RuleType::Ip => self.modes.ip.mode,
            picket_rules::RuleType::Browser => self.modes.browser.mode,
        }
    }

    pub fn expire_after(&self, t: picket_rules::RuleType) -> Option<std::time::Duration> {
        let spec = match t {
            picket_rules::RuleType::Dns => &self.modes.dns,
            picket_rules::RuleType::Ip => &self.modes.ip,
            picket_rules::RuleType::Browser => &self.modes.browser,
        };
        (spec.mode == Mode::Aggregate)
            .then(|| spec.expire_after.map(|d| d.as_duration()))
            .flatten()
    }

    /// The picket-rules form of the feed's `rule_policy`.
    pub fn policy(&self) -> picket_rules::policy::RulePolicy {
        let c = |o: Option<PolicyOption>| match o {
            Some(PolicyOption::Keep) => picket_rules::policy::Choice::Keep,
            _ => picket_rules::policy::Choice::Drop,
        };
        picket_rules::policy::RulePolicy {
            redirects: c(self.rule_policy.redirects),
            client_rules: c(self.rule_policy.client_rules),
            browser_changes: c(self.rule_policy.browser_changes),
        }
    }

    pub fn rules_format(&self) -> picket_rules::formats::Format {
        match self.format {
            FeedFormat::Adblock => picket_rules::formats::Format::Adblock,
            FeedFormat::Hosts => picket_rules::formats::Format::Hosts,
            FeedFormat::Plain => picket_rules::formats::Format::Plain,
            FeedFormat::MispWarninglist => picket_rules::formats::Format::MispWarninglist,
        }
    }

    pub fn rules_domains_as(&self) -> picket_rules::formats::DomainsAs {
        match self.domains_as {
            Some(DomainsAs::Subdomains) => picket_rules::formats::DomainsAs::Subdomains,
            _ => picket_rules::formats::DomainsAs::Exact,
        }
    }
}

/// What made a run (`feed_runs.kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RunKind {
    /// A download (a manual feed's save among them).
    Download,
    /// The latest applied blob read again after a `format`, `format_options`, `modes` or
    /// `rule_policy` edit (feeds.md §3, §8).
    Reingest,
    /// The hourly sweep that closed expired `aggregate` entries (feeds.md §2).
    Expire,
    /// An import merged into a provider feed (feeds.md §4): never the provider's `last`, never
    /// confirmed, compared with a download or re-ingested, and no change for the model.
    Import,
}

impl RunKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Reingest => "reingest",
            Self::Expire => "expire",
            Self::Import => "import",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "reingest" => Self::Reingest,
            "expire" => Self::Expire,
            "import" => Self::Import,
            _ => Self::Download,
        }
    }
}

/// A run's status (storage.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Applied,
    Held,
    Rejected,
    Expired,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Held => "held",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "held" => Self::Held,
            "rejected" => Self::Rejected,
            "expired" => Self::Expired,
            _ => Self::Applied,
        }
    }
}

/// What a run's parse found, kept on the run (the UI shows the first parse errors).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ParseSummary {
    pub lines: u64,
    pub rule_lines: u64,
    pub errors: u64,
    /// Rules dropped on purpose (parse warnings), by reason.
    pub warnings: BTreeMap<String, u64>,
    /// Entries the parser emitted per type, before modes and `rule_policy`.
    pub entries: TypeCounts,
    /// Distinct entries kept after modes, `rule_policy` and duplicates.
    pub kept: u64,
    /// The first parse errors: line, reason, text (cut).
    pub error_samples: Vec<ErrorSample>,
    /// Rules kept that are worth a look, by reason (`BroadBrowser`: a browser rule with no
    /// restriction whose pattern matches most requests). They are entries like any other.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub notices: BTreeMap<String, u64>,
    /// The first few of those rules: line, reason, text (cut).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notice_samples: Vec<ErrorSample>,
    /// An `adblock` list's `! Expires:` in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_secs: Option<u64>,
    /// A `misp-warninglist` file's list `type` (feeds.md §3: another type replaces the feed's
    /// entries; §4: exports and imports carry it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub misp_type: Option<String>,
    /// An import into a provider feed: the entries of types it skipped (not `aggregate`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_skipped: Option<TypeCounts>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorSample {
    pub line_no: u64,
    pub reason: String,
    pub text: String,
}

impl ErrorSample {
    fn from_parse(e: &picket_rules::formats::ErrorSample) -> Self {
        Self {
            line_no: e.line_no,
            reason: e.reason.clone(),
            text: crate::util::sanitize_for_message(&e.text, 200),
        }
    }
}

impl ParseSummary {
    pub fn from_stats(s: &picket_rules::formats::ParseStats) -> Self {
        Self {
            lines: s.lines,
            rule_lines: s.rule_lines,
            errors: s.errors,
            warnings: s.warning_reasons.clone(),
            entries: TypeCounts {
                dns: s.entries.dns,
                ip: s.entries.ip,
                browser: s.entries.browser,
            },
            kept: 0,
            error_samples: s.error_samples.iter().map(ErrorSample::from_parse).collect(),
            notices: s.notices.clone(),
            notice_samples: s.notice_samples.iter().map(ErrorSample::from_parse).collect(),
            expires_secs: s.expires_secs,
            misp_type: None,
            import_skipped: None,
        }
    }

    /// errors ÷ non-empty, non-comment lines (feeds.md §5).
    pub fn error_ratio(&self) -> f64 {
        if self.rule_lines == 0 {
            if self.errors == 0 { 0.0 } else { 1.0 }
        } else {
            self.errors as f64 / self.rule_lines as f64
        }
    }
}

/// Counts of rules `rule_policy` dropped, per option (`policy_dropped_json`).
pub type PolicyCounts = BTreeMap<String, u64>;

/// The storage name of a picket-rules policy option.
pub fn option_name(o: picket_rules::policy::PolicyOption) -> &'static str {
    match o {
        picket_rules::policy::PolicyOption::Redirects => "redirects",
        picket_rules::policy::PolicyOption::ClientRules => "client_rules",
        picket_rules::policy::PolicyOption::BrowserChanges => "browser_changes",
    }
}
