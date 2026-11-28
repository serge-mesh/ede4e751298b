//! The OpenAPI 3.1 document at `/api/ui/v1/openapi.json` (api.md §7), built with utoipa's
//! OpenAPI types. Component schemas come from `schemars` (JSON Schema 2020-12, which OpenAPI 3.1
//! uses as is), so a field's doc comment is its description — the UI's tooltip text
//! (core.md §12) — and the provider config forms use the same schemas.
//!
//! **Adding routes:** a new generic entity collection goes in `api::ENTITY_ROUTES` and appears
//! here on its own; other routes get a line in [`operations`] and their types a line in
//! [`schemas`]. A query parameter's type, its closed set of values and whether it is required
//! come from [`param_type`] and [`Op::required`]; the UI's types are generated from them.

use std::sync::OnceLock;

use schemars::JsonSchema;
use schemars::generate::{SchemaGenerator, SchemaSettings};
use serde_json::{Map, Value, json};
use utoipa::openapi::path::{HttpMethod, OperationBuilder, ParameterBuilder, ParameterIn, PathItem};
use utoipa::openapi::request_body::RequestBodyBuilder;
use utoipa::openapi::schema::{ObjectBuilder, Type};
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityRequirement, SecurityScheme};
use utoipa::openapi::{
    ComponentsBuilder, ContentBuilder, InfoBuilder, OpenApiBuilder, PathsBuilder, Ref, Required,
    ResponseBuilder,
};

use super::api::{self, ENTITY_ROUTES};

const PREFIX: &str = "/api/ui/v1";

fn schema_ref(name: &str) -> Ref {
    Ref::from_schema_name(name)
}

/// A parameter's schema (api.md §7: the UI's client is generated from the document).
#[derive(Clone, Debug, PartialEq)]
enum PType {
    Str,
    /// An integer within the bounds the handler enforces (out of them: `400`).
    Int {
        min: i64,
        max: i64,
    },
    /// A number within the bounds the handler enforces (out of them: `400`).
    Num {
        min: f64,
        max: f64,
    },
    Bool,
    /// A closed set of values.
    Enum(Vec<String>),
}

impl PType {
    fn of(values: &[&str]) -> Self {
        Self::Enum(values.iter().map(|v| (*v).to_string()).collect())
    }

    fn schema(&self) -> Value {
        match self {
            Self::Str => json!({"type": "string"}),
            Self::Int { min, max } => json!({"type": "integer", "minimum": min, "maximum": max}),
            Self::Num { min, max } => json!({"type": "number", "minimum": min, "maximum": max}),
            Self::Bool => json!({"type": "boolean"}),
            Self::Enum(v) => json!({"type": "string", "enum": v}),
        }
    }
}

/// One parameter of an operation.
struct Param {
    name: String,
    place: ParameterIn,
    desc: &'static str,
    ptype: PType,
    required: bool,
}

// `GET feed-providers/{id}/listing`'s `q` and `prefix` descriptions state the bounds.
const _: () =
    assert!(crate::feeds::api::MAX_LISTING_Q == 256 && crate::feeds::api::MAX_LISTING_PREFIX == 4096);

/// The largest `limit` an operation's handler accepts (`web::api::limit_param`), by path.
fn limit_max(path: &str) -> usize {
    match path {
        "/top" => crate::logs::query::TOP_MAX,
        "/alerts/{id}/evidence" => crate::logs::query::EVIDENCE_PAGE_MAX,
        "/logs" => crate::logs::query::MAX_LIMIT,
        "/dnssec/queue" | "/dnssec/results" => crate::dnssec::api::MAX_LIST,
        _ => api::MAX_LIMIT,
    }
}

/// A query parameter's type, by operation path (without the prefix) and name: each closed set
/// and each range is the one the handler checks, taken from the code's own lists and constants.
fn param_type(path: &str, name: &str) -> PType {
    const WINDOWS: &[&str] = &["1h", "6h", "24h", "72h"];
    const POLICY: &[&str] = &["drop", "keep"];
    match (path, name) {
        (_, "limit") => PType::Int {
            min: 1,
            max: crate::util::sat_i64(limit_max(path)),
        },
        ("/feed-providers/{id}/backtest", "days") => {
            let d = crate::feeds::api::BACKTEST_DAYS;
            PType::Int {
                min: *d.start(),
                max: *d.end(),
            }
        }
        ("/feed-providers/{id}/backtest", "k") => {
            let k = crate::feeds::api::BACKTEST_K;
            PType::Num {
                min: *k.start(),
                max: *k.end(),
            }
        }
        (_, "clear_cached_verdicts") => PType::Bool,
        (_, "window") => PType::of(WINDOWS),
        ("/alerts", "type") => PType::of(&["security", "operational"]),
        ("/alerts", "severity") => PType::of(&["info", "warning", "critical"]),
        ("/alerts", "state") => PType::of(&["open", "resolved"]),
        ("/alerts", "kind") => PType::of(&crate::alerts::KINDS.iter().map(|(k, _)| *k).collect::<Vec<_>>()),
        ("/temp-allows", "state") => PType::of(&["active", "recent", "all"]),
        ("/top", "kind") => PType::of(&["blocked", "allowed", "clients"]),
        ("/logs", "match") => PType::of(&["exact", "suffix", "substring"]),
        ("/logs", "decision") => PType::of(&["allow", "block", "rewrite", "refused", "servfail"]),
        ("/dnssec/results", "outcome") => PType::of(&["secure", "insecure", "bogus", "indeterminate"]),
        ("/feeds/{id}/entries", "rule_type") => PType::of(&["dns", "ip", "browser"]),
        ("/feed-providers/{id}/listing", "delimiter") => PType::of(&["/", ""]),
        ("/feeds/{id}/export", "as") => PType::of(&["file"]),
        ("/feeds/{id}/import", "mode") => PType::of(&["replace", "merge"]),
        ("/feeds/import" | "/feeds/{id}/import", "format") => {
            PType::of(&["adblock", "hosts", "plain", "misp-warninglist"])
        }
        ("/feeds/import" | "/feeds/{id}/import", "domains_as") => PType::of(&["exact", "subdomains"]),
        ("/feeds/import" | "/feeds/{id}/import", "category") => PType::of(&["security", "privacy", "mixed"]),
        ("/feeds/import" | "/feeds/{id}/import", "redirects" | "client_rules" | "browser_changes") => {
            PType::of(POLICY)
        }
        _ => PType::Str,
    }
}

/// One operation.
struct Op {
    method: HttpMethod,
    path: String,
    id: String,
    summary: String,
    tag: &'static str,
    body: Option<String>,
    /// (status, schema or None for no body)
    ok: (&'static str, Option<String>),
    params: Vec<Param>,
    /// Error responses documented by status, each naming its `error.code`s (api.md §2 error
    /// shape); every other error is the `default` response.
    errors: Vec<(&'static str, &'static str)>,
}

fn op(method: HttpMethod, path: &str, id: &str, summary: &str, tag: &'static str) -> Op {
    let params = path
        .split('/')
        .filter_map(|seg| seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(|name| Param {
            name: name.to_string(),
            place: ParameterIn::Path,
            desc: "",
            ptype: PType::Str,
            required: true,
        })
        .collect();
    Op {
        method,
        path: format!("{PREFIX}{path}"),
        id: id.into(),
        summary: summary.into(),
        tag,
        body: None,
        ok: ("200", None),
        params,
        errors: Vec::new(),
    }
}

impl Op {
    fn body(mut self, schema: &str) -> Self {
        self.body = Some(schema.into());
        self
    }
    fn ok(mut self, status: &'static str, schema: Option<&str>) -> Self {
        self.ok = (status, schema.map(str::to_string));
        self
    }
    /// Documents an error response: its status and what each of its `error.code`s means.
    fn err(mut self, status: &'static str, desc: &'static str) -> Self {
        self.errors.push((status, desc));
        self
    }
    fn query(mut self, name: &'static str, desc: &'static str) -> Self {
        let ptype = param_type(self.path.trim_start_matches(PREFIX), name);
        self.params.push(Param {
            name: name.to_string(),
            place: ParameterIn::Query,
            desc,
            ptype,
            required: false,
        });
        self
    }
    /// The last parameter added is required (the handler refuses a request without it).
    fn required(mut self) -> Self {
        if let Some(p) = self.params.last_mut() {
            p.required = true;
        }
        self
    }
    fn paged(self) -> Self {
        self.query("cursor", "The `next_cursor` of the previous page.")
            .query("limit", "Items per page (default 100, 1 to 500; else 400).")
    }
}

fn operations() -> Vec<Op> {
    use HttpMethod::*;
    let mut v = vec![
        op(
            Get,
            "/identity",
            "getIdentity",
            "Core's identity fingerprint and LAN CA",
            "system",
        )
        .ok("200", Some("IdentityInfo")),
        op(Get, "/settings", "getSettings", "All settings", "settings").ok("200", Some("SettingsView")),
        op(
            Put,
            "/settings",
            "putSettings",
            "Change settings: a partial nested object; null resets a key. Other lanca.zones rotate the LAN CA root with the rest of the patch, only together with lanca.rotate_from naming the current root's fingerprint (422 without it or with null; 409 lanca_root_changed when it is no longer the current root; 409 conflict while a previous root is still in use, naming the edges; 503 while core's clock isn't synchronised; 422 for names in use the new zones wouldn't cover, or any other problem; nothing changes on a refusal). The current zones, sent again, change nothing",
            "settings",
        )
        .body("SettingsPatch")
        .ok("200", Some("SettingsView"))
        .err(
            "409",
            "A LAN CA rotation was refused, by `error.code`: `lanca_root_changed`: lanca.rotate_from no longer names the current root (another change replaced it): reload GET settings and decide again. `conflict`: a previous root is still in use (the message names the edges whose managed listeners haven't reported a certificate from the current root; lanca.previous lists them): try again once lanca.can_rotate is true. Nothing changed.",
        )
        .err(
            "422",
            "`invalid` or `validation`: other lanca.zones without lanca.rotate_from (or with null), zones a LAN CA can't hold, names in use the new zones wouldn't cover, or any other problem with the patch. Nothing changed.",
        )
        .err(
            "503",
            "`unavailable`: core's wall clock isn't synchronised, so no new LAN CA root is made (lanca.clock_synced). Nothing changed.",
        ),
        op(
            Post,
            "/account/password",
            "changePassword",
            "Change the admin password (current password required)",
            "settings",
        )
        .body("PasswordChange")
        .ok("204", None),
        op(
            Get,
            "/config/issues",
            "getConfigIssues",
            "Current configuration problems, all in one page (no cursor or limit)",
            "settings",
        )
        .ok("200", Some("IssuePage")),
        op(
            Get,
            "/config/export",
            "exportConfig",
            "Export the configuration: one JSON document (core.md §2); secrets by name only (422 past 1 GiB or a part the restore wouldn't read; 409 while another export runs; 507 without room on the data disk; a download that stalls for 60 s is ended)",
            "settings",
        )
        .ok("200", Some("ExportDocument")),
        op(
            Put,
            "/config/export",
            "restoreConfig",
            "Restore an export: replaces all current data (422 for a malformed document, a bad reference or other lanca.zones; 413 past 1 GiB; 408 when the upload stalls for 60 s; 409 while another restore runs; 507 without room on the data disk). The response's generation is the one the restore's `restore` UI event carries",
            "settings",
        )
        .body("ExportDocument")
        .ok("200", Some("RestoreResult")),
        op(
            Get,
            "/config-changes",
            "listConfigChanges",
            "The change journal, newest first",
            "settings",
        )
        .paged()
        .ok("200", Some("ConfigChangePage")),
        op(
            Put,
            "/clients/order",
            "reorderClients",
            "Put the clients in a new order",
            "clients",
        )
        .body("ClientOrder")
        .ok("204", None),
        op(
            Get,
            "/secrets",
            "listSecrets",
            "Secret names (values are write-only)",
            "secrets",
        )
        .paged()
        .ok("200", Some("SecretMetaPage")),
        op(
            Put,
            "/secrets/{name}",
            "putSecret",
            "Set a secret's value",
            "secrets",
        )
        .body("SecretValue")
        .ok("200", Some("SecretMeta")),
        op(
            Delete,
            "/secrets/{name}",
            "deleteSecret",
            "Delete a secret",
            "secrets",
        )
        .ok("204", None),
        op(Get, "/edges", "listEdges", "Edges with their status", "edges")
            .paged()
            .ok("200", Some("EdgeViewPage")),
        op(Post, "/edges", "addEdge", "Add an edge by name and key", "edges")
            .body("EdgeDef")
            .ok("201", Some("Outcome")),
        op(Get, "/edges/{id}", "getEdge", "One edge", "edges").ok("200", Some("EdgeView")),
        op(
            Put,
            "/edges/{id}",
            "putEdge",
            "Replace an edge's settings (or key)",
            "edges",
        )
        .body("EdgeDef")
        .ok("200", Some("Outcome")),
        op(Delete, "/edges/{id}", "deleteEdge", "Delete an edge", "edges").ok("200", Some("Outcome")),
        op(
            Get,
            "/edges/{id}/config",
            "previewEdgeConfig",
            "The edge's config object as core would render it now",
            "edges",
        )
        .ok("200", Some("ConfigPreview")),
        op(
            Get,
            "/edges/{id}/status",
            "getEdgeStatus",
            "The edge's live state: session, last heartbeat, conditions, convergence, versions, requests",
            "edges",
        )
        .ok("200", Some("EdgeStatusView")),
        op(
            Post,
            "/edges/{id}/update",
            "updateEdge",
            "Update: install the offered release now (release.install_now)",
            "edges",
        )
        .ok("200", Some("RequestMade")),
        op(
            Post,
            "/edges/{id}/flush",
            "flushEdge",
            "Flush the edge's DNS cache, or one lookup provider's RAM tier",
            "edges",
        )
        .body("FlushRequest")
        .ok("200", Some("RequestMade")),
        op(
            Post,
            "/edges/{id}/allows/{allow}/revoke",
            "revokeAllow",
            "Revoke a temporary allow on the edge",
            "edges",
        )
        .ok("200", Some("RequestMade")),
        op(
            Get,
            "/metrics",
            "getMetrics",
            "Chart series over a window",
            "system",
        )
        .query(
            "series",
            "Series names, comma-separated (at most 32): the MetricSeries names, with map keys and .p50/.p99 as api.md §7 writes them",
        )
        .required()
        .query("window", "1h, 6h, 24h or 72h")
        .query("edge", "all (default), each, or an edge id")
        .ok("200", Some("Chart")),
        op(
            Get,
            "/edges/pending",
            "listPendingEdges",
            "Unknown keys that tried to connect",
            "edges",
        )
        .paged()
        .ok("200", Some("PendingEdgePage")),
        op(
            Post,
            "/edges/pending/{fp}/approve",
            "approvePendingEdge",
            "Approve a pending key as a new edge",
            "edges",
        )
        .body("ApproveEdge")
        .ok("201", Some("Outcome")),
        op(
            Delete,
            "/edges/pending/{fp}",
            "deletePendingEdge",
            "Forget a pending key",
            "edges",
        )
        .ok("204", None),
        op(Get, "/alerts", "listAlerts", "Alerts, newest first", "alerts")
            .query("type", "security or operational")
            .query("severity", "info, warning or critical")
            .query("state", "open or resolved")
            .query("kind", "An alert kind")
            .query("edge", "An edge id")
            .paged()
            .ok("200", Some("AlertPage")),
        op(
            Delete,
            "/alerts",
            "deleteAlerts",
            "Delete alerts in bulk",
            "alerts",
        )
        .body("AlertIds")
        .ok("200", Some("Deleted")),
        op(
            Get,
            "/alerts/{id}",
            "getAlert",
            "An alert with its history",
            "alerts",
        )
        .ok("200", Some("AlertDetail")),
        op(Delete, "/alerts/{id}", "deleteAlert", "Delete an alert", "alerts").ok("204", None),
        op(
            Post,
            "/alerts/{id}/resolve",
            "resolveAlert",
            "Resolve an alert by hand",
            "alerts",
        )
        .ok("200", Some("Alert")),
        op(Get, "/jobs", "getJobs", "Job lane depths and counters", "system").ok("200", Some("JobsView")),
        // Feed providers (providers.md §2–§3, feed-scheduling.md, api.md §7)
        op(Get, "/feed-provider-status", "listFeedProviderStatus", "Every feed provider's status", "feeds")
            .paged()
            .ok("200", Some("ProviderStatusPage")),
        op(
            Get,
            "/feed-providers/{id}/status",
            "getFeedProviderStatus",
            "A feed provider's trigger, checks, k, listing and SQS state",
            "feeds",
        )
        .ok("200", Some("ProviderStatus")),
        op(
            Post,
            "/feed-providers/{id}/check",
            "checkFeedProviderNow",
            "Check now: one check covers every enabled feed of the provider; bypasses the trigger, not min_interval",
            "feeds",
        )
        .ok("202", Some("CheckNow")),
        op(
            Get,
            "/feed-providers/{id}/listing",
            "listFeedProviderListing",
            "The provider's stored listing (or declared paths), S3 ListObjectsV2-style: the files whose path starts with prefix and, with delimiter=/, the common prefixes (folders, with their file and feed counts) of the rest; both in key order, together at most limit; or with q the files under prefix whose path holds it. Each file with whether files selects it and its feed",
            "feeds",
        )
        .query("prefix", "The files whose path starts with it (a folder: ending in /); at most 4096 bytes, else 400.")
        .query(
            "delimiter",
            "/ rolls the files past prefix up into common prefixes; left out or empty (as in S3), every file under prefix; any other value is 400.",
        )
        .query(
            "q",
            "Search instead: a substring of the path, case-insensitive (each character lowercased, Unicode), under prefix, no grouping; at most 256 characters, else 400.",
        )
        .query("cursor", "The `next_cursor` of the previous page.")
        .query(
            "limit",
            "Entries per page, folders and files together (default 100, 1 to 500; else 400).",
        )
        .ok("200", Some("ListingPage")),
        op(
            Post,
            "/feed-providers/{id}/files",
            "addFeedProviderFile",
            "Add as feed: adds the file to the provider's files (its feed follows)",
            "feeds",
        )
        .body("AddFile")
        .ok("200", Some("Outcome")),
        op(Get, "/feed-providers/{id}/checks", "listFeedProviderChecks", "The provider's checks, newest first", "feeds")
            .paged()
            .ok("200", Some("ProviderCheckViewPage")),
        op(
            Get,
            "/feed-providers/{id}/backtest",
            "backtestFeedProvider",
            "Replay the provider's recorded history with simulated checks",
            "feeds",
        )
        .query("days", "How far back in days (1–60, default 7; else 400).")
        .query("k", "One k, 0.1–50 (default: 1, 2, 3 and 5; else 400).")
        .ok("200", Some("SimResultList")),
        op(Get, "/feed-providers-review", "listFeedReview", "New feeds awaiting review (open feed_added)", "feeds")
            .ok("200", Some("ReviewItemList")),
        op(
            Post,
            "/feed-providers-add-url",
            "addFeedByUrl",
            "Add a feed by URL: a GitHub file goes to the provider of its repository and branch (created if none); any other https URL is an http provider of its own, the one whose url is that URL (scheme and host lowercase, no default port, otherwise exact) or a new one. A URL that has a feed already returns it",
            "feeds",
        )
        .body("AddUrl")
        .ok("200", Some("AddedUrl")),
        op(
            Get,
            "/download-modules",
            "listDownloadModules",
            "Download modules with their config schemas and whether they list files",
            "feeds",
        )
        .ok("200", Some("ModuleInfoList")),
        // Feeds (feeds.md, feed-scheduling.md, api.md §7)
        op(Get, "/feed-status", "listFeedStatus", "Every feed's status", "feeds")
            .paged()
            .ok("200", Some("FeedStatusPage")),
        op(Get, "/feeds/{id}/status", "getFeedStatus", "A feed's status, metrics and learned schedule; a manual feed's file version and save time (without the content) and its pending retry", "feeds")
            .ok("200", Some("FeedStatus")),
        op(Get, "/feeds/{id}/runs", "listFeedRuns", "The feed's runs, newest first", "feeds")
            .paged()
            .ok("200", Some("RunRowPage")),
        op(Get, "/feeds/{id}/runs/{run}", "getFeedRun", "One run with the rules rule_policy dropped", "feeds")
            .ok("200", Some("RunDetail")),
        op(Get, "/feeds/{id}/checks", "listFeedChecks", "The feed's checks, newest first", "feeds")
            .paged()
            .ok("200", Some("CheckViewPage")),
        op(Get, "/feeds/{id}/entries", "listFeedEntries", "The feed's current entries", "feeds")
            .query("rule_type", "dns, ip or browser.")
            .query("q", "A substring of the rule as written.")
            .paged()
            .ok("200", Some("EntryViewPage")),
        op(
            Get,
            "/feeds/{id}/policy-drops",
            "listFeedPolicyDrops",
            "Rules the feed's rule_policy dropped",
            "feeds",
        )
        .paged()
        .ok("200", Some("PolicyDropPage")),
        op(Get, "/feeds/{id}/schedule", "getFeedSchedule", "The learned schedule", "feeds").ok("200", Some("ScheduleView")),
        op(
            Get,
            "/feeds/{id}/export",
            "exportFeed",
            "Export the feed: <id>.json (settings, then each open entry as stored), or with as=file the entries as a file in the feed's format with picket-first-seen dates (a MISP list with a picket_first_seen map); streamed",
            "feeds",
        )
        .query("as", "file: the file export.")
        .ok("200", Some("FeedExport")),
        op(Get, "/feeds/{id}/export-size", "getFeedExportSize", "An export's size, the file it would make, and their limits", "feeds")
            .ok("200", Some("ExportSize")),
        op(
            Post,
            "/feeds/import",
            "importNewFeed",
            "Import a JSON export or {file} into a new manual feed; its settings come from the export (a query setting that differs is 422 naming the field), the query's for a plain list file; 409 when the id is taken, 413 past the bounds, 422 on a bad body",
            "feeds",
        )
        .query("id", "The new feed's id (default: the export's).")
        .query("name", "Its name (default: the export's).")
        .query("format", "A plain list file's format (default adblock). An export's own wins: another one is 422 (field format).")
        .query("domains_as", "A plain list's format_options.domains_as (exact or subdomains). Another than an export's: 422 (field format_options).")
        .query("category", "Its category. Another than an export's: 422 (field category).")
        .query("warn_on", "The warn bundles to check it against, comma-separated (empty: none; left out: follows the category). Another than an export's: 422 (field warn_on).")
        .query("redirects", "rule_policy.redirects, drop or keep (a manual feed's default: keep). Another than an export's: 422 (field rule_policy).")
        .query("client_rules", "rule_policy.client_rules, drop or keep (a manual feed's default: keep). Another than an export's: 422 (field rule_policy).")
        .query("browser_changes", "rule_policy.browser_changes, drop or keep (default keep). Another than an export's: 422 (field rule_policy).")
        .body("FeedImport")
        .ok("201", Some("Imported")),
        op(
            Post,
            "/feeds/{id}/import",
            "importIntoFeed",
            "Import into a manual feed (replace or merge, with base_version) or a provider feed (merge only, an import run); 422 for another format, format_options or MISP type (a MISP export included), a feed setting in the query, or replace on a provider feed",
            "feeds",
        )
        .query("mode", "replace or merge (default merge).")
        .query("base_version", "A manual feed's file version.")
        .query("format", "Optional: must be the feed's format (422, field format).")
        .query("domains_as", "Optional: must be the feed's format_options.domains_as (422, field format_options).")
        .query("category", "Optional: must be the feed's category (422, field category).")
        .query("warn_on", "Optional, comma-separated: must name the warn bundles the feed is checked against, in any order (422, field warn_on).")
        .query("redirects", "Optional, drop or keep: must be the feed's rule_policy.redirects as it applies (422, field rule_policy).")
        .query("client_rules", "Optional, drop or keep: must be the feed's rule_policy.client_rules as it applies (422, field rule_policy).")
        .query("browser_changes", "Optional, drop or keep: must be the feed's rule_policy.browser_changes as it applies (422, field rule_policy).")
        .body("FeedImport")
        .ok("200", Some("Imported")),
        op(
            Get,
            "/feeds/{id}/file",
            "getFeedFile",
            "A manual feed's file: {version, saved_at, size, content}",
            "feeds",
        )
        .ok("200", Some("FeedFile")),
        op(
            Put,
            "/feeds/{id}/file",
            "putFeedFile",
            "Save a manual feed's file (editor and upload); gzip bodies allowed; 409 on a stale base_version, 413 past the size cap, 408 when the body stalls (30 s idle, 10 min in all)",
            "feeds",
        )
        .body("FileSave")
        .ok("200", Some("SaveResult")),
        op(
            Post,
            "/feeds/{id}/file/lines",
            "appendFeedLines",
            "Append lines to a manual feed's file; 422 for a line break in a line, 413 past the size cap, 408 when the body stalls (30 s idle, 10 min in all)",
            "feeds",
        )
        .body("LinesAppend")
        .ok("200", Some("SaveResult")),
        op(Get, "/feed-presets", "listFeedPresets", "Bundled feed presets", "feeds").ok("200", Some("PresetViewList")),
        op(
            Post,
            "/feed-presets/{id}",
            "installFeedPreset",
            "Install (or restore) a preset: its feed, a manual preset's file, its bundle membership",
            "feeds",
        )
        .ok("200", Some("Installed")),

        op(Get, "/warninglists", "listWarninglists", "Warn bundles and the feeds checked against each", "feeds")
            .ok("200", Some("WarninglistList")),
        // Bundles and browser lists (bundles.md §1–§8, core.md §12)
        op(Get, "/bundle-status", "listBundleStatus", "Every bundle's build status", "bundles")
            .ok("200", Some("BundleStatusList")),
        op(
            Get,
            "/bundles/{id}/status",
            "getBundleStatus",
            "A bundle's build status, head, feed runs, stats, shards and the heads edges are named",
            "bundles",
        )
        .ok("200", Some("BundleDetail")),
        op(Get, "/bundles/{id}/versions", "listBundleVersions", "The bundle's versions, newest first", "bundles")
            .paged()
            .ok("200", Some("VersionViewPage")),
        op(
            Get,
            "/bundles/{id}/warnings",
            "listBundleWarnings",
            "The bundle's open guardrail alerts and compile-time warnings (a block bundle's on its entries; a warn or allow bundle's that it raised)",
            "bundles",
        )
        .paged()
        .ok("200", Some("BundleWarnings")),
        op(
            Get,
            "/bundles/{id}/public-suffixes",
            "listBundlePublicSuffixes",
            "The public suffixes the bundle blocks, by feed, with the rules that name each (the full list behind its grouped public_suffix alerts)",
            "bundles",
        )
        .query("feed", "Only this feed's suffixes.")
        .paged()
        .ok("200", Some("PublicSuffixes")),
        op(
            Get,
            "/bundles/{id}/public-suffixes/rules",
            "listBundlePublicSuffixRules",
            "The rules that name one public suffix the bundle blocks from one feed, a page at a time (the rest of a public-suffix item's rules, from its rules_cursor)",
            "bundles",
        )
        .query("feed", "The feed.")
        .required()
        .query("suffix", "The public suffix.")
        .required()
        .paged()
        .ok("200", Some("PublicSuffixRulePage")),
        op(
            Post,
            "/bundles/{id}/build",
            "buildBundleNow",
            "Build the bundle now (heavy lane, P0)",
            "bundles",
        )
        .ok("202", Some("BuildQueued")),
        op(
            Get,
            "/bundles/{id}/explain",
            "explainBundle",
            "How the bundle's current rules decide a name or an address (picket-rules' reference matcher)",
            "bundles",
        )
        .query("name", "A DNS name, or an address (matched as an answer address).")
        .required()
        .query("qtype", "The query type (default A).")
        .query("client_ip", "The client's address ($client).")
        .query("client", "The client entry's name ($client).")
        .query("tags", "The client entry's tags, comma-separated ($ctag).")
        .ok("200", Some("Explanation")),
        op(Get, "/browser-lists", "listBrowserLists", "Every browser list core serves, with its counts", "bundles")
            .ok("200", Some("ListViewList")),
        // The query log, attribution, trial checks and alert evidence (core.md §6, §9, §12; api.md §7)
        op(Get, "/logs", "searchLogs", "Search the query log, newest partition first (cursor pagination)", "logs")
            .query("from", "Oldest event time (RFC 3339); default the retention window's start.")
            .query("to", "Newest event time (RFC 3339); default now.")
            .query("edge", "An edge id (all or absent: every edge).")
            .query("client", "The client's address.")
            .query("device", "The device (its client name, MAC or address).")
            .query("qname", "A query name.")
            .query("match", "How qname matches: exact, suffix (default: the name and every name below it) or substring.")
            .query("decision", "allow, block, rewrite, refused or servfail.")
            .query("profile", "A profile id.")
            .query("bundle", "The deciding bundle.")
            .paged()
            .ok("200", Some("LogPage")),
        op(
            Get,
            "/logs/{id}",
            "getLogRecord",
            "One record: the reply the client got, the upstream answer, attribution with roles, lookups, trial would-blocks, versions",
            "logs",
        )
        .ok("200", Some("LogDetail")),
        op(Get, "/top", "getTop", "Top blocked names, allowed names or devices from the query log over a window", "logs")
            .query("kind", "blocked, allowed or clients.")
            .required()
            .query("window", "1h, 6h, 24h (default) or 72h, ending now; 422 past the query-log retention.")
            .query("edge", "all (default) or an edge id.")
            .query("limit", "Default 10, 1 to 100 (else 400).")
            .ok("200", Some("TopList")),
        op(Get, "/devices", "listDevices", "The devices in the logged records of the retention window", "logs")
            .ok("200", Some("DeviceList")),
        op(
            Get,
            "/query-summary",
            "getQuerySummary",
            "A device's or a profile's view over a window: queries, block rate, decisions over time, top names, temporary allows",
            "logs",
        )
        .query("device", "A device key (its client name, MAC or address).")
        .query("profile", "A profile id (instead of device).")
        .query("window", "1h, 6h, 24h (default) or 72h, ending now; 422 past the query-log retention.")
        .query("edge", "all (default) or an edge id.")
        .ok("200", Some("Summary")),
        op(Get, "/trial-results", "getTrialResults", "A trial bundle's would-blocks in one profile over a window", "logs")
            .query("profile", "The profile id.")
            .required()
            .query("bundle", "The trial bundle id.")
            .required()
            .query("window", "1h, 6h, 24h (default) or 72h, ending now; 422 past the query-log retention.")
            .query("edge", "all (default) or an edge id.")
            .ok("200", Some("TrialResults")),
        op(
            Get,
            "/alerts/{id}/evidence",
            "getAlertEvidence",
            "An alert's evidence, a page of copied records at a time, newest stored first (the order core stored them, not their event times; next_cursor leads to the copies stored before, and copies stored meanwhile come on a fresh first page), with the answers they reference and the exact total as the page was read; the first page also holds the counts per client and name, the wire_mismatch examples (each wire is a fuzz case) and the answers no copy references",
            "alerts",
        )
        .query("cursor", "The `next_cursor` of the previous page (absent: the first page, the newest copies).")
        .query("limit", "Copies per page (default 100, 1 to 500; else 400).")
        .ok("200", Some("EvidenceView")),
        // Lookups (core.md §7, §12; api.md §7)
        op(
            Get,
            "/lookup-modules",
            "listLookupModules",
            "Lookup modules with their config schemas and presets (id, title, parameter schema)",
            "lookups",
        )
        .ok("200", Some("LookupModuleInfoList")),
        op(
            Post,
            "/lookup-modules/{module}/presets/{preset}",
            "buildLookupPreset",
            "Build a preset's config from its parameters; changes nothing",
            "lookups",
        )
        .body("PresetParams")
        .ok("200", Some("LookupPresetBuilt")),
        op(
            Post,
            "/lookup-providers/{id}/flush",
            "flushLookupProvider",
            "Flush the provider on every edge and core: its cache_generation moves on",
            "lookups",
        )
        .body("Empty")
        .ok("200", Some("LookupFlushed")),
        op(
            Post,
            "/lookup-providers/{id}/test",
            "testLookupProvider",
            "Test now: run the provider's self-test on core with its committed config, once core's lookup runtime has reloaded it (a short bounded wait after a save; 409 \"provider is being reloaded\" past it; 422 when its module names no self-test)",
            "lookups",
        )
        .body("Empty")
        .ok("200", Some("SelfTestView")),
        op(
            Get,
            "/lookup-providers/{id}/status",
            "getLookupProviderStatus",
            "The provider's status on core: breaker, pause, error rate, latency, queue, verdicts, verdict set, self-test",
            "lookups",
        )
        .ok("200", Some("LookupProviderStatus")),
        op(
            Get,
            "/temp-allows",
            "listTempAllows",
            "Temporary allows across edges, newest first, with their revoke state",
            "lookups",
        )
        .query("state", "active, recent (revoked, ended or expired) or all (default).")
        .query("edge", "One edge's allows.")
        .paged()
        .ok("200", Some("TempAllowViewPage")),
        op(
            Get,
            "/browser-extension",
            "listBrowserExtensionBuilds",
            "The browser extension builds in the package, with SHA-256 sums and download paths",
            "system",
        )
        .ok("200", Some("BrowserExtensionBuilds")),
        // DNSSEC (core.md §8, §12)
        op(
            Get,
            "/dnssec/queue",
            "getDnssecQueue",
            "The DNSSEC validation backlog, earliest due first, and the cross-check queue",
            "dnssec",
        )
        .query("limit", "Items listed (default 100, 1 to 500; else 400).")
        .ok("200", Some("DnssecQueue")),
        op(
            Get,
            "/dnssec/results",
            "listDnssecResults",
            "Validation results in the retention window, newest first",
            "dnssec",
        )
        .query("outcome", "secure, insecure, bogus or indeterminate.")
        .paged()
        .ok("200", Some("DnssecResultPage")),
    ];
    for r in ENTITY_ROUTES {
        let base = format!("/{}", r.path);
        let item = format!("{base}/{{id}}");
        let tag = r.path;
        let camel = camel(r.path);
        v.push(
            op(
                Get,
                &base,
                &format!("list{camel}"),
                &format!("List {}", r.title.to_lowercase()),
                tag,
            )
            .paged()
            .ok("200", Some(&format!("{}Page", r.schema))),
        );
        v.push(
            op(
                Post,
                &base,
                &format!("create{camel}"),
                &format!("Create one of the {}", r.title.to_lowercase()),
                tag,
            )
            .body(r.schema)
            .ok("201", Some("Outcome")),
        );
        v.push(
            op(
                Get,
                &item,
                &format!("get{camel}"),
                &format!("Get one of the {}", r.title.to_lowercase()),
                tag,
            )
            .ok("200", Some(r.schema)),
        );
        let mut put = op(
            Put,
            &item,
            &format!("put{camel}"),
            &format!("Replace one of the {}", r.title.to_lowercase()),
            tag,
        )
        .body(r.schema)
        .ok("200", Some("Outcome"));
        if r.kind == crate::config::model::EntityKind::LookupProvider {
            put = put.query(
                "clear_cached_verdicts",
                "Move the cache generation on (default: when the config changed).",
            );
        }
        v.push(put);
        v.push(
            op(
                Delete,
                &item,
                &format!("delete{camel}"),
                &format!("Delete one of the {}", r.title.to_lowercase()),
                tag,
            )
            .ok("200", Some("Outcome")),
        );
    }
    v
}

fn camel(path: &str) -> String {
    path.split('-')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// A schemars transform (`#[schemars(transform = sent_always)]`) for a response type that sends
/// every field, null where it has no value: each property is required, so the UI's generated
/// type has no optional fields (api.md §7). Only for types that never skip a field (a test
/// serialises each one).
pub fn sent_always(schema: &mut schemars::Schema) {
    let Some(obj) = schema.as_object_mut() else { return };
    let keys: Vec<Value> = obj
        .get("properties")
        .and_then(Value::as_object)
        .map(|p| p.keys().cloned().map(Value::String).collect())
        .unwrap_or_default();
    if !keys.is_empty() {
        obj.insert("required".into(), Value::Array(keys));
    }
}

fn register<T: JsonSchema>(g: &mut SchemaGenerator) {
    let _ = g.subschema_for::<T>();
}

/// Every component schema, by name.
fn schemas() -> Map<String, Value> {
    use crate::config::model::*;
    let mut g = SchemaSettings::draft2020_12()
        .with(|s| {
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        })
        .into_generator();
    register::<ClientDef>(&mut g);
    register::<ListenerDef>(&mut g);
    register::<ProfileDef>(&mut g);
    register::<UpstreamDef>(&mut g);
    register::<UpstreamGroupDef>(&mut g);
    register::<ForwardZoneDef>(&mut g);
    register::<FeedProviderDef>(&mut g);
    register::<FeedDef>(&mut g);
    register::<BundleDef>(&mut g);
    register::<LookupProviderDef>(&mut g);
    register::<EdgeDef>(&mut g);
    register::<SecretMeta>(&mut g);
    register::<PendingEdge>(&mut g);
    register::<crate::settings::Settings>(&mut g);
    register::<crate::config::validate::Issue>(&mut g);
    register::<crate::config::Outcome>(&mut g);
    register::<crate::alerts::Alert>(&mut g);
    register::<api::EdgeView>(&mut g);
    register::<api::ConfigPreview>(&mut g);
    register::<api::SettingsView>(&mut g);
    register::<api::IdentityInfo>(&mut g);
    register::<api::PasswordChange>(&mut g);
    register::<api::ConfigChange>(&mut g);
    register::<api::ClientOrder>(&mut g);
    register::<api::SecretValue>(&mut g);
    register::<api::ApproveEdge>(&mut g);
    register::<api::AlertDetail>(&mut g);
    register::<api::AlertIds>(&mut g);
    register::<api::Deleted>(&mut g);
    register::<api::JobsView>(&mut g);
    // The UI WebSocket's event data (api.md §7); the union is `UiEventFrame` below.
    register::<super::events::JobEvent>(&mut g);
    register::<super::events::EdgeStatusEvent>(&mut g);
    register::<super::events::FeedRunEvent>(&mut g);
    register::<super::events::AlertEvent>(&mut g);
    register::<super::events::BundleVersionEvent>(&mut g);
    register::<super::events::RestoreEvent>(&mut g);
    register::<super::events::TempAllowEvent>(&mut g);
    register::<super::events::DnssecEvent>(&mut g);
    register::<super::events::DnssecQueuedEvent>(&mut g);
    register::<super::events::LancaServedEvent>(&mut g);
    register::<super::events::LaggedEvent>(&mut g);
    register::<crate::lanca::rotation::LancaEvent>(&mut g);
    register::<crate::edges::status::EdgeStatusView>(&mut g);
    register::<api::RequestMade>(&mut g);
    register::<api::FlushRequest>(&mut g);
    register::<crate::metrics::query::Chart>(&mut g);
    register::<crate::feeds::api::FeedStatus>(&mut g);
    register::<crate::feeds::api::CheckNow>(&mut g);
    register::<crate::feeds::store::RunRow>(&mut g);
    register::<crate::feeds::api::RunDetail>(&mut g);
    register::<crate::feeds::api::CheckView>(&mut g);
    register::<crate::feeds::api::EntryView>(&mut g);
    register::<crate::feeds::api::PolicyDrop>(&mut g);
    register::<crate::feeds::api::ScheduleView>(&mut g);
    register::<crate::feeds::schedule::learner::SimResult>(&mut g);
    register::<crate::feeds::manual::SaveResult>(&mut g);
    register::<crate::feeds::presets::PresetView>(&mut g);
    register::<crate::feeds::presets::Installed>(&mut g);
    register::<crate::feeds::api::ModuleInfo>(&mut g);
    register::<crate::feeds::api::ProviderStatus>(&mut g);
    register::<crate::feeds::api::ListingPage>(&mut g);
    register::<crate::feeds::api::AddFile>(&mut g);
    register::<crate::feeds::api::ProviderCheckView>(&mut g);
    register::<crate::feeds::api::ReviewItem>(&mut g);
    register::<crate::feeds::api::AddUrl>(&mut g);
    register::<crate::feeds::api::AddedUrl>(&mut g);
    register::<crate::feeds::transfer::Imported>(&mut g);
    register::<crate::feeds::transfer::ExportSize>(&mut g);
    register::<crate::feeds::transfer::ExportSettings>(&mut g);
    register::<crate::feeds::api::Warninglist>(&mut g);
    register::<crate::compiler::BundleStatus>(&mut g);
    register::<crate::compiler::api::BundleDetail>(&mut g);
    register::<crate::compiler::api::VersionView>(&mut g);
    register::<crate::compiler::api::BundleWarnings>(&mut g);
    register::<crate::compiler::api::PublicSuffixes>(&mut g);
    register::<crate::compiler::api::BuildQueued>(&mut g);
    register::<crate::compiler::api::Explanation>(&mut g);
    register::<crate::lists::ListView>(&mut g);
    register::<crate::logs::query::LogPage>(&mut g);
    register::<crate::logs::query::LogDetail>(&mut g);
    register::<crate::logs::query::TopList>(&mut g);
    register::<crate::logs::query::DeviceList>(&mut g);
    register::<crate::logs::query::Summary>(&mut g);
    register::<crate::logs::query::TrialResults>(&mut g);
    register::<crate::logs::query::EvidenceView>(&mut g);
    register::<crate::logs::query::EvidenceRecord>(&mut g);
    register::<crate::lookups::api::LookupModuleInfo>(&mut g);
    register::<crate::lookups::api::LookupPresetBuilt>(&mut g);
    register::<crate::lookups::api::LookupFlushed>(&mut g);
    register::<crate::lookups::api::LookupProviderStatus>(&mut g);
    register::<crate::lookups::api::TempAllowView>(&mut g);
    register::<crate::lookups::selftest::SelfTestView>(&mut g);
    register::<crate::web::browser_extension::BrowserExtensionBuilds>(&mut g);
    register::<crate::config::export::ExportDocument>(&mut g);
    register::<crate::config::export::RestoreResult>(&mut g);
    register::<crate::dnssec::api::DnssecQueue>(&mut g);
    register::<crate::dnssec::api::DnssecResultPage>(&mut g);
    let mut m = g.take_definitions(true);
    for (name, item) in [
        ("SimResultList", "SimResult"),
        ("PresetViewList", "PresetView"),
        ("ModuleInfoList", "ModuleInfo"),
        ("ReviewItemList", "ReviewItem"),
        ("WarninglistList", "Warninglist"),
        ("BundleStatusList", "BundleStatus"),
        ("ListViewList", "ListView"),
        ("LookupModuleInfoList", "LookupModuleInfo"),
    ] {
        m.insert(
            name.into(),
            json!({"type": "array", "items": {"$ref": format!("#/components/schemas/{item}")}}),
        );
    }
    let patch = settings_patch(&m);
    m.insert("SettingsPatch".into(), patch);
    m.insert(
        "FeedExport".into(),
        json!({
            "type": "object",
            "description": "A feed's JSON export (feeds.md §4): its settings, then each open entry as stored, entries last.",
            "properties": {
                "picket_feed_export": {"type": "integer", "const": 1},
                "exported_at": {"type": "string"},
                "feed": {"$ref": "#/components/schemas/ExportSettings"},
                "entries": {"type": "array", "items": {"type": "object", "properties": {
                    "raw": {"type": "string"}, "rule_type": {"type": "string"}, "kind": {"type": "string"},
                    "first_seen_at": {"type": "string"}, "last_seen_at": {"type": "string"}
                }}}
            }
        }),
    );
    m.insert(
        "FeedImport".into(),
        json!({
            "description": "A JSON export (first key picket_feed_export, feed before entries), or {\"file\": \"…\"} holding a file export or a plain list as text. The body may be gzip-compressed; up to 32 times the download size cap after decompression.",
            "oneOf": [
                {"$ref": "#/components/schemas/FeedExport"},
                {"type": "object", "properties": {"file": {"type": "string"}}, "required": ["file"]}
            ]
        }),
    );
    m.insert(
        "FeedFile".into(),
        json!({
            "type": "object",
            "description": "A manual feed's file (providers.md §3).",
            "properties": {
                "version": {"type": "string", "description": "Pass as base_version when saving an edit of it."},
                "saved_at": {"type": "string"},
                "size": {"type": "integer"},
                "content": {"type": "string", "description": "The file; bytes that aren't UTF-8 read as U+FFFD."}
            },
            "required": ["version", "saved_at", "size", "content"]
        }),
    );
    m.insert(
        "FileSave".into(),
        json!({
            "type": "object",
            "description": "A manual feed's new file. The body may be gzip-compressed (Content-Encoding: gzip).",
            "properties": {
                "content": {"type": "string", "description": "The whole file, at most the download size cap (feeds.max_download_mib) decoded."},
                "base_version": {"type": ["string", "null"], "description": "The version the content was edited from; null only while the feed has no file. Any other: 409."}
            },
            "required": ["content", "base_version"]
        }),
    );
    m.insert(
        "LinesAppend".into(),
        json!({
            "type": "object",
            "description": "Lines to append to a manual feed's file, each without a line break (else 422).",
            "properties": {"lines": {"type": "array", "items": {"type": "string"}}},
            "required": ["lines"]
        }),
    );
    m.insert("UiEventFrame".into(), super::events::frame_schema());
    m.insert("MetricSeries".into(), metric_series_schema());
    m.insert(
        "Empty".into(),
        json!({"type": "object", "description": "An empty JSON object: every mutating request carries a JSON body (core.md §12)."}),
    );
    m.insert(
        "PresetParams".into(),
        json!({"type": "object", "description": "A lookup module preset's parameters, as its params_schema describes them."}),
    );
    // Pages of each listed type.
    let mut paged: Vec<String> = ENTITY_ROUTES.iter().map(|r| r.schema.to_string()).collect();
    paged.extend(
        [
            "EdgeView",
            "PendingEdge",
            "SecretMeta",
            "Alert",
            "Issue",
            "ConfigChange",
            "FeedStatus",
            "ProviderStatus",
            "ProviderCheckView",
            "RunRow",
            "CheckView",
            "EntryView",
            "PolicyDrop",
            "VersionView",
            "TempAllowView",
            "PublicSuffixRule",
        ]
        .map(String::from),
    );
    for name in paged {
        m.insert(
            format!("{name}Page"),
            json!({
                "type": "object",
                "description": format!("A page of {name} items (cursor pagination)."),
                "properties": {
                    "items": {"type": "array", "items": {"$ref": format!("#/components/schemas/{name}")}},
                    "next_cursor": {"type": ["string", "null"], "description": "Pass as `cursor` for the next page; null on the last page."}
                },
                "required": ["items", "next_cursor"]
            }),
        );
    }
    // `GET config/issues` answers every current problem at once: it takes no cursor or limit.
    if let Some(p) = m.get_mut("IssuePage").and_then(Value::as_object_mut) {
        p.insert(
            "description".into(),
            json!("Every current configuration problem, in one page: the call takes no cursor or limit, and next_cursor is always null."),
        );
    }
    m.insert(
        "Error".into(),
        json!({
            "type": "object",
            "description": "The error shape of every UI API error (api.md §2).",
            "properties": {"error": {"type": "object", "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
                "issues": {"type": "array", "items": {"$ref": "#/components/schemas/Issue"},
                           "description": "For a refused save: the problems it would introduce."}
            }, "required": ["code", "message"]}},
            "required": ["error"]
        }),
    );
    m
}

/// The catalog of every series core records or receives (core.md §10, `metrics::HEARTBEAT_SERIES`
/// and `metrics::CORE_SERIES`): the base names `GET metrics` takes, as an enum, with each one's
/// kind and label keys under `x-picket-series`. The UI's types and its check that it renders every
/// series are generated from it.
fn metric_series_schema() -> Value {
    let all: Vec<&crate::metrics::Series> = crate::metrics::all_series().collect();
    let entry = |s: &crate::metrics::Series| {
        let kind = serde_json::to_value(s.kind).unwrap_or(Value::Null);
        let family = crate::metrics::export::family(s);
        (
            s.name.to_string(),
            json!({"kind": kind, "labels": s.labels, "family": family}),
        )
    };
    let info: Map<String, Value> = all.iter().map(|s| entry(s)).collect();
    let export_only: Map<String, Value> = crate::metrics::export::export_only().map(|s| entry(&s)).collect();
    json!({
        "type": "string",
        "description": "A series core records (core.md §10), by its base name: a heartbeat field path \
            with map keys left out (`upstream.queries`; ask `upstream.<id>.queries` for one key), or \
            core's own series name. A histogram (`histogram`, `corehistogram`) is charted as \
            `<name>.p50` or `<name>.p99`. `x-picket-series` gives each one's kind, label keys and \
            Prometheus family in `GET /metrics`; `x-picket-export-only` the families only the export \
            holds (the job lanes, `GET jobs`; each bundle's current version's statistics, `GET \
            bundles/{id}/versions`).",
        "enum": all.iter().map(|s| s.name).collect::<Vec<_>>(),
        "x-picket-series": info,
        "x-picket-export-only": export_only,
    })
}

/// Builds the document.
pub fn document() -> Value {
    let mut paths = PathsBuilder::new();
    let mut by_path: std::collections::BTreeMap<String, Vec<Op>> = Default::default();
    for o in operations() {
        by_path.entry(o.path.clone()).or_default().push(o);
    }
    for (path, ops) in by_path {
        let mut item = PathItem::builder();
        for o in ops {
            let mut b = OperationBuilder::new()
                .operation_id(Some(o.id.clone()))
                .summary(Some(o.summary.clone()))
                .tag(o.tag);
            for p in &o.params {
                let mut pb = ParameterBuilder::new()
                    .name(p.name.as_str())
                    .parameter_in(p.place.clone())
                    .schema(Some(ObjectBuilder::new().schema_type(Type::String)))
                    .required(if p.required {
                        Required::True
                    } else {
                        Required::False
                    });
                if !p.desc.is_empty() {
                    pb = pb.description(Some(p.desc));
                }
                b = b.parameter(pb);
            }
            if let Some(schema) = &o.body {
                b = b.request_body(Some(
                    RequestBodyBuilder::new()
                        .required(Some(Required::True))
                        .content(
                            "application/json",
                            ContentBuilder::new().schema(Some(schema_ref(schema))).build(),
                        )
                        .build(),
                ));
            }
            let mut ok = ResponseBuilder::new().description("Success");
            if let Some(s) = &o.ok.1 {
                ok = ok.content(
                    "application/json",
                    ContentBuilder::new().schema(Some(schema_ref(s))).build(),
                );
            }
            b = b.response(o.ok.0, ok.build());
            for (status, desc) in &o.errors {
                let r = ResponseBuilder::new()
                    .description(*desc)
                    .content(
                        "application/json",
                        ContentBuilder::new().schema(Some(schema_ref("Error"))).build(),
                    )
                    .build();
                b = b.response(*status, r);
            }
            let err = ResponseBuilder::new()
                .description("Error")
                .content(
                    "application/json",
                    ContentBuilder::new().schema(Some(schema_ref("Error"))).build(),
                )
                .build();
            b = b.response("default", err);
            item = item.operation(o.method, b.build());
        }
        paths = paths.path(path, item.build());
    }
    let components = ComponentsBuilder::new()
        .security_scheme("basic", SecurityScheme::Http(Http::new(HttpAuthScheme::Basic)))
        .build();
    let doc = OpenApiBuilder::new()
        .info(
            InfoBuilder::new()
                .title("Picket core UI API")
                .version(crate::VERSION)
                .description(Some(
                    "The UI API of picket-core (api.md §7). Basic auth (one account, `admin`); mutating requests \
                     need `X-Picket-UI: 1` and a JSON body.",
                ))
                .build(),
        )
        .paths(paths.build())
        .components(Some(components))
        .security(Some(vec![SecurityRequirement::new("basic", Vec::<String>::new())]))
        .build();
    let mut v = serde_json::to_value(doc).unwrap_or(Value::Null);
    if let Some(c) = v.get_mut("components").and_then(Value::as_object_mut) {
        c.insert("schemas".into(), Value::Object(schemas()));
    }
    // Each parameter's schema as typed above (utoipa's builder takes a plain string schema).
    let types: std::collections::BTreeMap<(String, String, String), Value> = operations()
        .into_iter()
        .flat_map(|o| {
            // The key the document uses for the method (`get`, `post`, …).
            let m = serde_json::to_value(&o.method)
                .ok()
                .and_then(|v| v.as_str().map(str::to_ascii_lowercase))
                .unwrap_or_default();
            o.params
                .into_iter()
                .map(move |p| ((o.path.clone(), m.clone(), p.name), p.ptype.schema()))
        })
        .collect();
    if let Some(paths) = v.get_mut("paths").and_then(Value::as_object_mut) {
        for (path, item) in paths.iter_mut() {
            let Some(item) = item.as_object_mut() else {
                continue;
            };
            for (method, operation) in item.iter_mut() {
                let Some(params) = operation.get_mut("parameters").and_then(Value::as_array_mut) else {
                    continue;
                };
                for p in params {
                    let name = p["name"].as_str().unwrap_or_default().to_string();
                    if let Some(s) = types.get(&(path.clone(), method.clone(), name)) {
                        p["schema"] = s.clone();
                    }
                }
            }
        }
    }
    v
}

/// The document as JSON text, built once.
pub fn document_json() -> String {
    static DOC: OnceLock<String> = OnceLock::new();
    DOC.get_or_init(|| serde_json::to_string(&document()).unwrap_or_else(|_| "{}".into()))
        .clone()
}

/// `SettingsPatch`, a `PUT settings` body as `settings::apply_patch` reads it (api.md §7): each
/// settings key (`settings::KEYS`) is its Settings schema or `null`, which resets it to the
/// default; the groups above the keys are objects of their parts, never `null` (refused). Dotted
/// keys (`"web.port"`) work too, so a group doesn't forbid other properties. `lanca.rotate_from`
/// asks for a LAN CA rotation (core.md §11).
fn settings_patch(schemas: &Map<String, Value>) -> Value {
    let resolve = |n: &Value| -> Value {
        n["$ref"]
            .as_str()
            .and_then(|r| r.strip_prefix("#/components/schemas/"))
            .and_then(|name| schemas.get(name))
            .cloned()
            .unwrap_or_else(|| n.clone())
    };
    let group = || json!({"type": "object", "properties": {}});
    let mut root = group();
    root["description"] = json!(
        "A PUT settings body: any part of Settings as a nested (or dotted) partial object, null resetting a key to its default, plus lanca.rotate_from to ask for a LAN CA rotation (core.md §11)."
    );
    let settings = resolve(&json!({"$ref": "#/components/schemas/Settings"}));
    for key in crate::settings::KEYS {
        let parts: Vec<&str> = key.split('.').collect();
        let (mut full, mut node) = (settings.clone(), &mut root);
        for (i, part) in parts.iter().enumerate() {
            let own = full["properties"][*part].clone();
            let Some(props) = node["properties"].as_object_mut() else {
                break;
            };
            if i + 1 == parts.len() {
                let mut leaf = json!({"anyOf": [own, {"type": "null"}]});
                if let Some(d) = resolve(&own).get("description") {
                    leaf["description"] = d.clone();
                }
                props.insert((*part).to_string(), leaf);
                break;
            }
            full = resolve(&own);
            let next = props.entry((*part).to_string()).or_insert_with(group);
            if let Some(d) = full.get("description") {
                next["description"] = d.clone();
            }
            node = next;
        }
    }
    root["properties"]["lanca"]["properties"]["rotate_from"] = json!({
        "type": ["string", "null"],
        "description": "With other lanca.zones: the current LAN CA root's fingerprint (lanca.fingerprint in GET settings), confirming a rotation to a new root that every device must trust again. Other zones without it, or with null (the same as leaving it out), are refused (422); a root that is no longer the current one is refused (409, error.code lanca_root_changed). Ignored when lanca.zones doesn't change."
    });
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_series_lists_every_series_with_its_kind_and_labels() {
        let d = document();
        let m = &d["components"]["schemas"]["MetricSeries"];
        let names: Vec<&str> = m["enum"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            names.len(),
            crate::metrics::HEARTBEAT_SERIES.len() + crate::metrics::CORE_SERIES.len()
        );
        for s in crate::metrics::all_series() {
            assert!(names.contains(&s.name), "{}", s.name);
            assert_eq!(
                m["x-picket-series"][s.name]["labels"],
                json!(s.labels),
                "{}",
                s.name
            );
        }
        assert_eq!(m["x-picket-series"]["lookup_call_ms"]["kind"], "corehistogram");
        assert_eq!(
            m["x-picket-series"]["feed_records"]["family"],
            "picket_feed_records"
        );
        assert_eq!(
            m["x-picket-series"]["log_records"]["family"],
            "picket_log_records_total"
        );
        assert_eq!(
            m["x-picket-export-only"]["bundle_hot_keys"]["labels"],
            json!(["bundle"])
        );
        assert_eq!(
            m["x-picket-export-only"]["metrics_dropped"]["family"],
            "picket_metrics_dropped_total"
        );
        assert_eq!(m["x-picket-series"]["upstream.rtt_ms"]["kind"], "histogram");
    }

    /// The UI's copy of this document (ui/src/api/openapi.json, ui/scripts/update-openapi.sh) lists
    /// the same series: the UI checks it renders every one, so a series added here without
    /// regenerating that copy would go unrendered silently.
    #[test]
    fn the_uis_document_lists_the_same_series() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/src/api/openapi.json");
        let ui: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            ui["components"]["schemas"]["MetricSeries"],
            document()["components"]["schemas"]["MetricSeries"],
            "run ui/scripts/update-openapi.sh"
        );
    }

    #[test]
    fn document_is_3_1_and_complete() {
        let d = document();
        assert_eq!(d["openapi"], "3.1.0");
        let paths = d["paths"].as_object().unwrap();
        for r in ENTITY_ROUTES {
            assert!(paths.contains_key(&format!("{PREFIX}/{}", r.path)), "{}", r.path);
            assert!(
                paths.contains_key(&format!("{PREFIX}/{}/{{id}}", r.path)),
                "{}",
                r.path
            );
        }
        assert!(paths.contains_key("/api/ui/v1/edges/pending/{fp}/approve"));
        for p in [
            "/api/ui/v1/feed-providers/{id}/check",
            "/api/ui/v1/feed-providers/{id}/files",
            "/api/ui/v1/feed-providers/{id}/listing",
            "/api/ui/v1/download-modules",
            "/api/ui/v1/feeds/{id}/export",
            "/api/ui/v1/feeds/import",
            "/api/ui/v1/feeds/{id}/import",
            "/api/ui/v1/feeds/{id}/file",
            "/api/ui/v1/feeds/{id}/file/lines",
            "/api/ui/v1/feed-presets",
            "/api/ui/v1/bundle-status",
            "/api/ui/v1/bundles/{id}/status",
            "/api/ui/v1/bundles/{id}/versions",
            "/api/ui/v1/bundles/{id}/warnings",
            "/api/ui/v1/bundles/{id}/public-suffixes",
            "/api/ui/v1/bundles/{id}/build",
            "/api/ui/v1/bundles/{id}/explain",
            "/api/ui/v1/browser-lists",
            "/api/ui/v1/lookup-modules",
            "/api/ui/v1/lookup-modules/{module}/presets/{preset}",
            "/api/ui/v1/lookup-providers/{id}/flush",
            "/api/ui/v1/lookup-providers/{id}/test",
            "/api/ui/v1/lookup-providers/{id}/status",
            "/api/ui/v1/temp-allows",
        ] {
            assert!(paths.contains_key(p), "{p}");
        }
        let schemas = d["components"]["schemas"].as_object().unwrap();
        for s in [
            "ProfileDef",
            "FeedDef",
            "FeedProviderDef",
            "Settings",
            "Alert",
            "Error",
            "ProfileDefPage",
            "Issue",
            "BundleDetail",
            "Explanation",
            "VersionViewPage",
        ] {
            assert!(schemas.contains_key(s), "{s}");
        }
        // Every $ref resolves.
        let text = serde_json::to_string(&d).unwrap();
        for part in text.split("\"$ref\":\"#/components/schemas/").skip(1) {
            let name = part.split('"').next().unwrap();
            assert!(schemas.contains_key(name), "dangling $ref {name}");
        }
        // Field descriptions (UI tooltips) come through.
        let p = serde_json::to_string(&schemas["ProfileDef"]).unwrap();
        assert!(p.contains("trial"), "{p}");

        // Profile lookup provider fields use consistent naming and carry descriptions.
        let profile_props = schemas["ProfileDef"]["properties"].as_object().unwrap();
        for old in ["lookups", "lookup_budget_ms", "alert_providers"] {
            assert!(!profile_props.contains_key(old), "ProfileDef still has {old}");
        }
        for field in [
            "lookup_providers",
            "sync_lookup_budget_ms",
            "alert_lookup_providers",
        ] {
            let desc = profile_props[field]["description"].as_str().unwrap_or_default();
            assert!(!desc.is_empty(), "ProfileDef.{field} missing description");
        }
        let att_props = schemas["LookupAttachment"]["properties"].as_object().unwrap();
        for field in ["provider", "mode", "include_bundles", "exclude_bundles"] {
            let desc = att_props[field]["description"].as_str().unwrap_or_default();
            assert!(!desc.is_empty(), "LookupAttachment.{field} missing description");
        }
        let mode_variants = schemas["LookupMode"]["oneOf"].as_array().unwrap();
        assert_eq!(mode_variants.len(), 2);
        for v in mode_variants {
            let desc = v["description"].as_str().unwrap_or_default();
            assert!(!desc.is_empty(), "LookupMode variant missing description: {v}");
        }
    }
}

#[cfg(test)]
mod name_tests {
    #[test]
    fn same_named_types_stay_apart() {
        let d = super::document();
        let s = &d["components"]["schemas"];
        let issue = serde_json::to_string(&s["Issue"]).unwrap();
        let alert = serde_json::to_string(&s["Alert"]).unwrap();
        // Issue.severity is error|warning; Alert.severity is info|warning|critical.
        let issue_ref = s["Issue"]["properties"]["severity"]["$ref"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let alert_ref = s["Alert"]["properties"]["severity"]["$ref"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_ne!(issue_ref, alert_ref, "{issue}\n{alert}");
    }
}

#[cfg(test)]
mod tooltip_tests {
    /// F8 (core.md §12 Rule policy controls): each rule-policy switch's description, the UI's
    /// tooltip, names the rules it covers with an example, what `keep` lets the feed do and its
    /// default (manual feeds keep all three); `browser_changes` also says it has no effect while
    /// the `browser` mode is `drop`.
    #[test]
    fn rule_policy_switches_describe_their_rules_keep_and_default() {
        let d = super::document();
        let props = &d["components"]["schemas"]["RulePolicy"]["properties"];
        for (field, covers, default) in [
            (
                "redirects",
                "$dnsrewrite",
                "Default `drop` (manual feeds: `keep`)",
            ),
            ("client_rules", "$client", "Default `drop` (manual feeds: `keep`)"),
            ("browser_changes", "+js(", "Default `keep`"),
        ] {
            let desc = props[field]["description"].as_str().unwrap_or_default();
            assert!(desc.contains(covers), "{field}: {desc}");
            assert!(desc.contains("`keep` lets the feed"), "{field}: {desc}");
            assert!(desc.contains(default), "{field}: {desc}");
        }
        let b = props["browser_changes"]["description"]
            .as_str()
            .unwrap_or_default();
        assert!(
            b.contains("No effect while the feed's `browser` mode is `drop`"),
            "{b}"
        );
        // The job event's data is documented too (api.md §7 UI WebSocket).
        let job = &d["components"]["schemas"]["JobEvent"]["properties"];
        for k in [
            "phase",
            "run",
            "job",
            "outcome",
            "ms",
            "coalesced",
            "dropped",
            "heavy_running",
            "light_depth",
        ] {
            assert!(job.get(k).is_some(), "JobEvent.{k}: {job}");
        }
    }

    /// C10 (api.md §7: the UI's client is generated from the document): query parameters carry
    /// their type, their closed set of values and whether they are required; evidence items and
    /// cross-check queue items are typed schemas; every UI event's data is in `UiEventFrame`.
    #[test]
    fn parameters_events_and_items_are_typed() {
        let d = super::document();
        let param = |path: &str, method: &str, name: &str| -> serde_json::Value {
            d["paths"][format!("/api/ui/v1{path}")][method]["parameters"]
                .as_array()
                .unwrap_or_else(|| panic!("{path}: no parameters"))
                .iter()
                .find(|p| p["name"] == name)
                .cloned()
                .unwrap_or_else(|| panic!("{path} {name}"))
        };
        let top = param("/top", "get", "kind");
        assert_eq!(top["required"], true, "{top}");
        assert_eq!(
            top["schema"]["enum"],
            serde_json::json!(["blocked", "allowed", "clients"])
        );
        let w = param("/top", "get", "window");
        assert_eq!(w["required"], false);
        assert_eq!(w["schema"]["enum"], serde_json::json!(["1h", "6h", "24h", "72h"]));
        assert_eq!(param("/top", "get", "limit")["schema"]["type"], "integer");
        assert_eq!(param("/trial-results", "get", "profile")["required"], true);
        assert_eq!(param("/metrics", "get", "series")["required"], true);
        let kinds = param("/alerts", "get", "kind");
        assert!(
            kinds["schema"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k == "category_blocked"),
            "{kinds}"
        );
        assert_eq!(
            param("/temp-allows", "get", "state")["schema"]["enum"],
            serde_json::json!(["active", "recent", "all"])
        );
        assert_eq!(
            param("/feeds/{id}/import", "post", "redirects")["schema"]["enum"],
            serde_json::json!(["drop", "keep"])
        );
        assert_eq!(param("/feeds/{id}/entries", "get", "id")["required"], true);
        assert_eq!(
            param("/lookup-providers/{id}", "put", "clear_cached_verdicts")["schema"]["type"],
            "boolean"
        );
        // Evidence paging.
        assert_eq!(
            param("/alerts/{id}/evidence", "get", "limit")["schema"]["type"],
            "integer"
        );
        param("/alerts/{id}/evidence", "get", "cursor");
        let s = &d["components"]["schemas"];
        let items = serde_json::to_string(&s["EvidenceView"]["properties"]["items"]).unwrap();
        assert!(items.contains("EvidenceRecord"), "{items}");
        for k in ["qname", "lookups", "versions", "response", "decision"] {
            assert!(
                serde_json::to_string(&s["EvidenceRecord"]).unwrap().contains(k),
                "EvidenceRecord.{k}"
            );
        }
        for k in ["next_cursor", "total"] {
            assert!(
                s["EvidenceView"]["properties"].get(k).is_some(),
                "EvidenceView.{k}"
            );
        }
        let cc = serde_json::to_string(&s["DnssecQueue"]["properties"]["crosscheck_items"]).unwrap();
        assert!(cc.contains("CrosscheckQueueItem"), "{cc}");
        // The event union.
        let frame = serde_json::to_string(&s["UiEventFrame"]).unwrap();
        for (t, data) in super::super::events::FRAME_TYPES {
            assert!(frame.contains(&format!("\"const\":\"{t}\"")), "{t}: {frame}");
            assert!(s.get(*data).is_some(), "{data}");
        }
        for t in ["restore", "temp_allow", "dnssec"] {
            assert!(frame.contains(t), "{t}");
        }
        assert!(s["TempAllowView"]["properties"]["state"].is_object());
        assert!(s["Device"]["properties"]["macs"].is_object());
    }

    /// F7 (api.md §7: the UI's client is generated from the document): every `limit` declares
    /// 1 to the maximum its handler accepts (`top` 100, the rest 500), and every numeric parameter
    /// has both bounds, none of them 0 (the handlers refuse 0).
    #[test]
    fn numeric_parameters_declare_the_bounds_core_enforces() {
        let d = super::document();
        let mut limits = 0;
        for (path, item) in d["paths"].as_object().unwrap() {
            for (method, op) in item.as_object().unwrap() {
                for p in op["parameters"].as_array().into_iter().flatten() {
                    let s = &p["schema"];
                    if s["type"] == "integer" || s["type"] == "number" {
                        assert!(s["minimum"].as_f64().unwrap() > 0.0, "{method} {path}: {p}");
                        assert!(s["maximum"].as_f64().is_some(), "{method} {path}: {p}");
                    }
                    if p["name"] == "limit" {
                        limits += 1;
                        let rel = path.trim_start_matches(super::PREFIX);
                        assert_eq!(s["type"], "integer", "{path}");
                        assert_eq!(s["minimum"], 1, "{path}");
                        assert_eq!(s["maximum"], super::limit_max(rel), "{path}");
                    }
                }
            }
        }
        assert!(limits >= 25, "{limits} limit parameters");
        let max = |path: &str| {
            d["paths"][format!("/api/ui/v1{path}")]["get"]["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == "limit")
                .unwrap()["schema"]["maximum"]
                .clone()
        };
        assert_eq!(max("/top"), 100);
        assert_eq!(max("/alerts/{id}/evidence"), 500);
        assert_eq!(max("/dnssec/queue"), 500);
        assert_eq!(max("/feeds"), 500);
        let bt = &d["paths"]["/api/ui/v1/feed-providers/{id}/backtest"]["get"]["parameters"];
        let p = |n: &str| bt.as_array().unwrap().iter().find(|p| p["name"] == n).unwrap()["schema"].clone();
        assert_eq!(
            p("days"),
            serde_json::json!({"type": "integer", "minimum": 1, "maximum": 60})
        );
        assert_eq!(
            p("k"),
            serde_json::json!({"type": "number", "minimum": 0.1, "maximum": 50.0})
        );
    }

    /// The UI follow-ups F1, F2, F4, F6, F8, F9 and F10 (api.md §7: the UI's types are generated
    /// from the document): the settings 409 names both codes; Alert.edge says what null means;
    /// LancaEvent.event is an enum and names the previous root; rotate_from is nullable; the
    /// restore response carries its generation; the new events are in the union; and no
    /// description says the LAN CA zones are fixed at init, or misdescribes the cross-check queue
    /// or the issues "page".
    #[test]
    fn followups_are_documented() {
        let d = super::document();
        let s = &d["components"]["schemas"];
        let text = |v: &serde_json::Value| serde_json::to_string(v).unwrap();
        // F1
        let put = &d["paths"]["/api/ui/v1/settings"]["put"]["responses"];
        let conflict = put["409"]["description"].as_str().unwrap_or_default();
        assert!(
            conflict.contains("`lanca_root_changed`") && conflict.contains("`conflict`"),
            "{conflict}"
        );
        assert!(put["422"].is_object() && put["503"].is_object(), "{put}");
        // F2
        let edge = s["Alert"]["properties"]["edge"]["description"]
            .as_str()
            .unwrap_or_default();
        assert!(
            edge.contains("Null when") && edge.contains("several edges") && edge.contains("details"),
            "{edge}"
        );
        // F4
        let ev = text(&s["LancaEventKind"]);
        assert!(
            ev.contains("\"rotated\"") && ev.contains("\"previous_dropped\""),
            "{ev}"
        );
        assert_eq!(
            s["LancaEvent"]["properties"]["event"]["$ref"],
            "#/components/schemas/LancaEventKind"
        );
        assert!(s["LancaEvent"]["properties"]["previous"].is_object());
        // F6
        assert_eq!(
            s["SettingsPatch"]["properties"]["lanca"]["properties"]["rotate_from"]["type"],
            serde_json::json!(["string", "null"])
        );
        // F8
        assert!(s["RestoreResult"]["properties"]["generation"].is_object());
        assert!(
            s["RestoreResult"]["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("generation"))
        );
        // F9
        let frame = text(&s["UiEventFrame"]);
        for (t, data) in [
            ("dnssec_queued", "DnssecQueuedEvent"),
            ("lanca_served", "LancaServedEvent"),
        ] {
            assert!(frame.contains(&format!("\"const\":\"{t}\"")), "{t}");
            assert!(s[data].is_object(), "{data}");
        }
        // F10
        let zones = s["LancaSettings"]["properties"]["zones"]["description"]
            .as_str()
            .unwrap_or_default();
        assert!(zones.contains("rotates"), "{zones}");
        let all = text(&d);
        assert!(
            !all.contains("may sign, set at `init`"),
            "stale LAN CA zones text"
        );
        let cc = s["CrosscheckQueueItem"]["description"]
            .as_str()
            .unwrap_or_default();
        assert!(!cc.starts_with("The queue for the UI"), "{cc}");
        assert!(cc.contains("cross-check"), "{cc}");
        let issues = s["IssuePage"]["description"].as_str().unwrap_or_default();
        assert!(issues.contains("one page"), "{issues}");
    }

    /// api.md §7 (the UI's client is generated from the document): the coalesced `alert` and
    /// `feed_run` events' data with their bounded lists, every `dnssec_queued` count, and a
    /// record's lookup detail as an object (providers.md §4), as an alert holds it.
    #[test]
    fn coalesced_events_and_lookup_detail_are_described() {
        let d = super::document();
        let s = &d["components"]["schemas"];
        let frame = serde_json::to_string(&s["UiEventFrame"]).unwrap();
        assert!(frame.contains("\"#/components/schemas/AlertEvent\""), "{frame}");
        for (schema, fields) in [
            ("AlertEvent", &["alerts", "alerts_truncated", "changes"][..]),
            ("AlertEventItem", &["id", "kind", "state", "count", "deleted"]),
            ("FeedRunEvent", &["runs", "runs_truncated", "stored"]),
            (
                "FeedRunItem",
                &[
                    "feed",
                    "run",
                    "kind",
                    "status",
                    "gate",
                    "version",
                    "saved_at",
                    "source_run",
                ],
            ),
            (
                "DnssecQueuedEvent",
                &[
                    "validation",
                    "crosscheck",
                    "joined",
                    "retried",
                    "waiting",
                    "crosscheck_retried",
                    "crosscheck_ended",
                    "dropped",
                    "stamped",
                ],
            ),
        ] {
            for f in fields {
                assert!(s[schema]["properties"][f].is_object(), "{schema}.{f}");
            }
        }
        let alerts = serde_json::to_string(&s["AlertEvent"]["properties"]["alerts"]).unwrap();
        assert!(alerts.contains("AlertEventItem"), "{alerts}");
        let runs = serde_json::to_string(&s["FeedRunEvent"]["properties"]["runs"]).unwrap();
        assert!(runs.contains("FeedRunItem"), "{runs}");
        let detail = &s["LookupView"]["properties"]["detail"];
        assert!(detail.is_object(), "{detail}");
        assert!(
            !serde_json::to_string(detail).unwrap().contains("\"string\""),
            "an object, not JSON text: {detail}"
        );
    }

    /// K3 and K4 (api.md §7: the UI's types are generated from the document): descriptions give
    /// the numbers, never a Rust doc link (`[`NAME`]`); the coalesced events' bounds and what
    /// `changes` counts are stated; the nullable fields core always sends are required; and a
    /// lookup's `detail` is an object or null, as core sends it.
    #[test]
    fn descriptions_bounds_and_required_fields_say_what_core_sends() {
        use crate::web::events::{
            COALESCE_GAP, MAX_EVENT_ALERTS, MAX_EVENT_EDGES, MAX_EVENT_RUNS, MAX_PENDING_JOB_REPORTS,
        };
        let d = super::document();
        let s = &d["components"]["schemas"];
        // No description anywhere holds a Rust doc link.
        fn links(v: &serde_json::Value, path: &str, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(m) => {
                    for (k, x) in m {
                        if k == "description"
                            && let Some(t) = x.as_str()
                            && t.contains("[`")
                        {
                            out.push(format!("{path}: {t}"));
                        }
                        links(x, &format!("{path}/{k}"), out);
                    }
                }
                serde_json::Value::Array(a) => {
                    for (i, x) in a.iter().enumerate() {
                        links(x, &format!("{path}/{i}"), out);
                    }
                }
                _ => {}
            }
        }
        let mut found = Vec::new();
        links(&d, "", &mut found);
        assert!(
            found.is_empty(),
            "Rust doc links in descriptions:\n{}",
            found.join("\n")
        );
        // A description with its doc comment's line breaks as spaces.
        let desc = |schema: &str, field: Option<&str>| {
            let v = match field {
                Some(f) => &s[schema]["properties"][f]["description"],
                None => &s[schema]["description"],
            };
            v.as_str()
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        // The bounds, as numbers.
        for (schema, field, n) in [
            ("AlertEvent", "alerts", MAX_EVENT_ALERTS),
            ("FeedRunEvent", "runs", MAX_EVENT_RUNS),
            ("TempAllowEvent", "edges", MAX_EVENT_EDGES),
            ("LancaServedEvent", "edges", MAX_EVENT_EDGES),
            ("JobEvent", "dropped", MAX_PENDING_JOB_REPORTS),
        ] {
            let t = desc(schema, Some(field));
            assert!(t.contains(&format!("at most {n}")), "{schema}.{field}: {t}");
        }
        for (schema, field, text) in [
            (
                "TriggerState",
                Some("recent_ids"),
                format!("at most {}", crate::feeds::sqs::RECENT_IDS),
            ),
            (
                "DryRun",
                Some("started_at"),
                format!("{} minutes", crate::compiler::tier::DRY_RUN_HOLD.as_secs() / 60),
            ),
            (
                "ExportDocument",
                Some("format_version"),
                format!("writes {}", crate::config::export::FORMAT_VERSION),
            ),
            (
                "RestoreResult",
                Some("warnings"),
                format!("at most {}", crate::config::export::MAX_RESTORE_WARNINGS),
            ),
            (
                "B64File",
                None,
                format!("at most {} bytes", crate::config::export::CHUNK_BYTES),
            ),
        ] {
            let t = desc(schema, field);
            assert!(t.contains(&text), "{schema}.{field:?} ({text}): {t}");
        }
        // Alert thresholds: every kind's default, as core.md §9's table gives it.
        let t = desc("AlertsSettings", Some("thresholds"));
        for (kind, _) in crate::alerts::KINDS {
            let mins = crate::settings::default_threshold(kind).as_secs() / 60;
            if mins == 0 {
                assert!(!t.contains(&format!("`{kind}`")), "{kind} fires at once: {t}");
                continue;
            }
            let at = t
                .find(&format!("`{kind}`"))
                .unwrap_or_else(|| panic!("{kind}: {t}"));
            let rest = &t[at..];
            let stated = rest[..rest.find(" min").unwrap()]
                .rsplit(' ')
                .next()
                .unwrap()
                .to_string();
            assert_eq!(stated, mins.to_string(), "{kind}: {t}");
        }
        assert_eq!(COALESCE_GAP, std::time::Duration::from_secs(1));
        for schema in [
            "AlertEvent",
            "FeedRunEvent",
            "TempAllowEvent",
            "DnssecEvent",
            "DnssecQueuedEvent",
            "LancaServedEvent",
        ] {
            let t = desc(schema, None);
            assert!(t.contains("one a second"), "{schema}: {t}");
        }
        // What `changes` counts: every note, details-only updates and re-resolving included.
        let changes = desc("AlertEvent", Some("changes"));
        for needle in ["details", "resolved again", "evidence", "deletion"] {
            assert!(
                changes.contains(needle),
                "AlertEvent.changes ({needle}): {changes}"
            );
        }
        // Nullable fields core always sends are required.
        let required = |schema: &str| -> Vec<String> {
            serde_json::from_value(s[schema]["required"].clone()).unwrap_or_default()
        };
        for (schema, fields) in [
            ("AlertEvent", &["alerts", "alerts_truncated", "changes"][..]),
            ("AlertEventItem", &["id", "kind", "state", "count", "deleted"]),
            ("FeedRunEvent", &["runs", "runs_truncated", "stored"]),
            (
                "FeedRunItem",
                &[
                    "feed",
                    "run",
                    "kind",
                    "status",
                    "gate",
                    "version",
                    "saved_at",
                    "source_run",
                ],
            ),
            ("LookupView", &["detail"]),
        ] {
            let r = required(schema);
            for f in fields {
                assert!(r.iter().any(|x| x == f), "{schema}.{f} required: {r:?}");
            }
        }
        // What `sent_always` marks required is sent: each type serialised with every optional
        // field empty holds every required key.
        let sent: [(&str, serde_json::Value); 5] = [
            (
                "AlertEvent",
                serde_json::to_value(crate::web::events::AlertEvent::default()).unwrap(),
            ),
            (
                "AlertEventItem",
                serde_json::to_value(crate::web::events::AlertEventItem::deleted(1, "k".into(), 1)).unwrap(),
            ),
            (
                "FeedRunEvent",
                serde_json::to_value(crate::web::events::FeedRunEvent::default()).unwrap(),
            ),
            (
                "FeedRunItem",
                serde_json::to_value(crate::web::events::FeedRunItem {
                    feed: "f".into(),
                    run: 1,
                    kind: "download".into(),
                    status: "applied".into(),
                    gate: None,
                    version: None,
                    saved_at: None,
                    source_run: None,
                })
                .unwrap(),
            ),
            (
                "LookupView",
                serde_json::to_value(crate::logs::query::LookupView {
                    provider: "p".into(),
                    verdict: None,
                    score: None,
                    reason: None,
                    detail: None,
                    source: "cache".into(),
                    ms: None,
                    timed_out: false,
                    retry: false,
                })
                .unwrap(),
            ),
        ];
        for (schema, v) in sent {
            for f in required(schema) {
                assert!(v.get(&f).is_some(), "{schema}.{f} is required but not sent: {v}");
            }
        }
        // AlertEventItem.state is still nullable (null once deleted), as are FeedRunItem's.
        let text = |v: &serde_json::Value| serde_json::to_string(v).unwrap();
        assert!(text(&s["AlertEventItem"]["properties"]["state"]).contains("null"));
        for f in ["gate", "version", "saved_at", "source_run"] {
            assert!(text(&s["FeedRunItem"]["properties"][f]).contains("null"), "{f}");
        }
        // A lookup's detail: an object, or null.
        assert_eq!(
            s["LookupView"]["properties"]["detail"]["type"],
            serde_json::json!(["object", "null"]),
            "{}",
            s["LookupView"]["properties"]["detail"]
        );
    }

    /// X6 (api.md §7): both import operations declare every query setting they accept and check,
    /// not only describe them.
    #[test]
    fn both_import_operations_declare_each_setting() {
        let d = super::document();
        for path in ["/api/ui/v1/feeds/import", "/api/ui/v1/feeds/{id}/import"] {
            let names: Vec<&str> = d["paths"][path]["post"]["parameters"]
                .as_array()
                .unwrap_or_else(|| panic!("{path}: no parameters"))
                .iter()
                .filter(|p| p["in"] == "query")
                .filter_map(|p| p["name"].as_str())
                .collect();
            for k in [
                "format",
                "domains_as",
                "category",
                "warn_on",
                "redirects",
                "client_rules",
                "browser_changes",
            ] {
                assert!(names.contains(&k), "{path} {k}: {names:?}");
            }
        }
    }
}

#[cfg(test)]
mod settings_patch_tests {
    use serde_json::{Value, json};

    fn admits_null(n: &Value) -> bool {
        n["type"] == "null"
            || n["type"].as_array().is_some_and(|a| a.contains(&json!("null")))
            || n["anyOf"].as_array().is_some_and(|a| a.iter().any(admits_null))
    }

    /// Follows a `#/components/schemas/…` reference.
    fn resolve<'a>(schemas: &'a Value, n: &'a Value) -> &'a Value {
        match n["$ref"]
            .as_str()
            .and_then(|r| r.strip_prefix("#/components/schemas/"))
        {
            Some(name) => &schemas[name],
            None => n,
        }
    }

    /// api.md §7 (the UI's client is generated from the document): `PUT settings` takes any part
    /// of Settings with `null` resetting a key (`{"web": {"port": null}}`), so in `SettingsPatch`
    /// every settings key admits `null` besides its own schema, and the groups above it are
    /// objects (a group isn't a key: `null` there is refused). `lanca.rotate_from` rides along.
    #[test]
    fn every_settings_key_takes_a_null_reset() {
        let d = super::document();
        let schemas = &d["components"]["schemas"];
        let patch = &schemas["SettingsPatch"];
        for key in crate::settings::KEYS {
            let (mut node, mut full) = (patch, resolve(schemas, &schemas["Settings"]));
            let parts: Vec<&str> = key.split('.').collect();
            for (i, p) in parts.iter().enumerate() {
                assert_eq!(node["type"], "object", "{key}: the group above {p}");
                node = &node["properties"][*p];
                full = resolve(schemas, &full["properties"][*p]);
                assert!(node.is_object(), "{key}: no {p} in SettingsPatch");
                assert!(full.is_object(), "{key}: no {p} in Settings");
                if i + 1 < parts.len() {
                    assert!(!admits_null(node), "{key}: the group {p} isn't nullable");
                }
            }
            assert!(admits_null(node), "{key} takes null (a reset)");
            let own = node["anyOf"]
                .as_array()
                .and_then(|a| a.iter().find(|b| b["type"] != "null"))
                .unwrap_or_else(|| panic!("{key}: {node}"));
            assert_eq!(resolve(schemas, own), full, "{key}: its value is as in Settings");
        }
        assert_eq!(
            patch["properties"]["lanca"]["properties"]["rotate_from"]["type"],
            json!(["string", "null"])
        );
    }
}
