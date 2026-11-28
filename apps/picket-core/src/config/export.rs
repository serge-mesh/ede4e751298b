//! The config export and restore (core.md §2 "Export and restore", §13; storage.md §5):
//! `GET/PUT /api/ui/v1/config/export`.
//!
//! **The document** ([`ExportDocument`], `format_version` [`FORMAT_VERSION`]): the configuration
//! (settings as stored, every entity: feed providers with their `files` and `exclude`, every
//! feed, and secrets by name only), each manual feed's file and, when it differs, its latest
//! applied run's blob, alerts with their history and evidence, the feed side
//! ([`crate::feeds::restore`]: feed check history, learned schedules with their epochs,
//! `seen_blake3` and staleness references), and the retained, redacted `config_changes`. No logs
//! or metrics. A newer release reads an older release's document: fields are only added, and
//! missing ones take their defaults (README §2 Compatibility).
//!
//! **Size and memory** (README §2 Bounded; core.md §3): a document is at most
//! [`MAX_DOCUMENT_BYTES`], a bound both sides keep: an export past it is refused with a message
//! naming what makes it large, a larger body is refused (`413`). The export also applies every
//! other bound the restore reads with as it writes (the part caps, string and depth bounds,
//! [`stream::Prescan`]): one the restore would refuse is refused (`422` naming the part), and
//! the save validation keeps the configuration well within its cap. Neither side holds the
//! document in memory: the export is written from one read transaction (a consistent snapshot)
//! into a file in `staging/` and served from there, manual files read and base64-encoded in
//! chunks; the restore spills the body into `staging/` and reads it as a stream ([`stream`]),
//! twice. One export and one restore run at a time (`409`), and neither starts, nor goes on,
//! without room on the data disk for it and a margin of its own size, within
//! [`DISK_MARGIN_FLOOR`] and [`DISK_MARGIN`] (`507`); a download or an upload that stalls for
//! [`STREAM_IDLE`] is ended, giving its slot back. A job's slot and staged file belong to its
//! work, not to the request that started it: an export's write owns them until it stops (at its
//! next chunk once its client is gone), and a restore, once the upload is in, runs in a task of
//! its own ([`run_restore`]), so a client that goes away (the UI's Cancel, a closed tab, a proxy
//! timeout) never frees a slot while its job still writes, nor cuts a committed restore short of
//! step 3. A malformed document is `422` (api.md §7).
//!
//! **A restore** replaces all current data with the document's; nothing is merged:
//!
//! 1. Checked before anything changes: the document's bounds ([`stream::prescan`]), the format
//!    version, the document's `lanca.zones` against this instance's (`422` naming the zones it
//!    needs: they stay with the LAN CA), the settings, every entity and reference (the save
//!    validation, and every provider and feed the check history names; one bad reference
//!    rejects the whole document), manual files (decoded into `staging/` as they are read) and
//!    alerts.
//! 2. One `core.db` transaction ([`crate::config::ConfigStore::replace_all`]): every table is
//!    either restored from the document, deleted (derived data, queues, verdicts, history the
//!    document doesn't hold), or kept ([`TABLES`]: core's identity, LAN CA and admin password
//!    stay, as do the edges' reported state, published configs and pins, their pending requests
//!    and temporary allows (a revoke made while an edge was offline still reaches it), and the
//!    bundle and verdict-set versions edges still run or are pinned to). Secrets: a name with a value takes
//!    it; a name without one keeps its stored value; no other stored value survives. Every lookup
//!    provider gets a new `cache_generation`. Each feed provider's and feed's `last` is cleared
//!    (first checks, due at once), feeds come back with their providers (none is added or raised
//!    again). For every bundle with an enabled downloaded member feed whose provider is enabled,
//!    the heads each edge runs are held ([`holds`]) until those members have an applied run or
//!    have failed their first check. Log partitions and `metrics.db` are emptied after the commit
//!    (a marker in the same transaction finishes that at the next start if core stops first;
//!    meanwhile log batches are answered `503`, so only pre-restore records go). A manual feed's
//!    applied blob to apply first is recorded in the same transaction (`restore_applied`), so a
//!    stop before that run finishes it at the next start, and a run the heavy queue refused is
//!    retried with that blob ([`applied_next`]); the record goes once the blob's own run is
//!    stored.
//! 3. On the writer, right after the commit, the restore generation goes up
//!    ([`RestoreGate`]) and the caches that follow the tables are dropped, so no work that began
//!    before the restore commits after it and no new work sees old state; the log analysis waits
//!    until the old partitions are emptied. The UI events coalesced so far are sent then, so the
//!    UI gets every pre-restore change before the `restore` event (`web::events`). Then the running parts reload from the restored
//!    definitions: the configuration is published (feeds, compiler, edges, lists and lookups
//!    follow it), the feeds runtime treats every feed and provider as new, and a manual feed with
//!    an applied blob in the document gets that blob applied first and keeps the saved file as
//!    its file.
//!
//! It looks atomic to the user: the old state until the transaction commits, then only the new
//! one; a failed restore changes nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::model::{
    BundleDef, ClientDef, EdgeDef, FeedDef, FeedProviderDef, ForwardZoneDef, ListenerDef, LookupProviderDef,
    Model, ProfileDef, SecretMeta, UpstreamDef, UpstreamGroupDef,
};
use super::{EntityKind, store, validate};

pub mod stream;
use crate::error::{CoreError, CoreResult};
use crate::state::SharedState;

/// This release's document format. Release N reads N−1's documents (README §2 Compatibility).
pub const FORMAT_VERSION: u32 = 1;
/// The largest document, a bound the export and the restore both keep (README §2 Bounded): an
/// export past it is refused, naming what makes it large; a larger restore body is `413`. A
/// policy choice: room for a manual feed at the default `feeds.max_download_mib` (256 MiB, a
/// third more in base64) with a differing applied blob, the default evidence budget (128 MiB)
/// and the check history and journal; both sides stream, so it costs disk in `staging/`, not
/// memory.
pub const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024 * 1024;
/// A manual file's base64 chunk, decoded (a third more encoded, under
/// [`stream::MAX_STRING_BYTES`]).
pub const CHUNK_BYTES: usize = 768 * 1024;

/// The config export document (module docs).
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct ExportDocument {
    /// The document format; this release writes 1 and reads every older one.
    // The version: FORMAT_VERSION (a test checks the number above).
    pub format_version: u32,
    #[serde(default)]
    pub exported_at: Option<String>,
    /// The release that wrote it.
    #[serde(default)]
    pub core_version: Option<String>,
    #[serde(default)]
    pub configuration: Configuration,
    /// Each manual feed's file, and its latest applied run's blob when that differs.
    #[serde(default)]
    pub manual_files: Vec<ManualFileExport>,
    /// Alerts with their history and evidence (each a row of `alerts` and its child rows).
    #[serde(default)]
    pub alerts: Vec<AlertExport>,
    /// Feed check history, learned schedules with their epochs, content hashes and staleness
    /// references (feed-scheduling.md §6, §8).
    #[serde(default)]
    #[schemars(with = "Value")]
    pub feed_state: crate::feeds::restore::FeedSide,
    /// The retained, redacted change journal.
    #[serde(default)]
    pub config_changes: Vec<Map<String, Value>>,
}

/// The configuration part.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct Configuration {
    /// The stored settings rows, by key (a key left out has its default).
    #[serde(default)]
    pub settings: BTreeMap<String, Value>,
    #[serde(default)]
    pub edges: Vec<EdgeDef>,
    #[serde(default)]
    pub listeners: Vec<ListenerDef>,
    #[serde(default)]
    pub clients: Vec<ClientDef>,
    #[serde(default)]
    pub profiles: Vec<ProfileDef>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamDef>,
    #[serde(default)]
    pub upstream_groups: Vec<UpstreamGroupDef>,
    #[serde(default)]
    pub forward_zones: Vec<ForwardZoneDef>,
    #[serde(default)]
    pub feed_providers: Vec<FeedProviderDef>,
    #[serde(default)]
    pub feeds: Vec<FeedDef>,
    #[serde(default)]
    pub bundles: Vec<BundleDef>,
    #[serde(default)]
    pub lookup_providers: Vec<LookupProviderDef>,
    /// Secrets by name only. On restore a name may carry a `value`; one without keeps the stored
    /// value of that secret.
    #[serde(default)]
    pub secrets: Vec<SecretExport>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct SecretExport {
    pub name: String,
    /// Never written by an export; a value set here is stored on restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// A file in base64: a list of chunks (each at most 786432 bytes, 768 KiB, decoded, each
/// decoding on its own); a restore also reads one string.
// The chunk size: CHUNK_BYTES (a test checks the number above).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct B64File(#[schemars(with = "B64FileSchema")] pub Vec<String>);

/// A file in base64 as a restore reads it: a list of chunks, or one string.
#[derive(JsonSchema)]
#[serde(untagged)]
#[expect(
    dead_code,
    reason = "only describes the restore format to schemars; never built"
)]
enum B64FileSchema {
    Chunks(Vec<String>),
    One(String),
}

impl<'de> Deserialize<'de> for B64File {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            One(String),
            Chunks(Vec<String>),
        }
        Ok(match Either::deserialize(d)? {
            Either::One(s) => B64File(vec![s]),
            Either::Chunks(c) => B64File(c),
        })
    }
}

impl B64File {
    /// Encodes `bytes` in chunks.
    pub fn encode(bytes: &[u8]) -> Self {
        let e = base64::engine::general_purpose::STANDARD;
        B64File(bytes.chunks(CHUNK_BYTES).map(|c| e.encode(c)).collect())
    }

    /// Decodes every chunk.
    pub fn decode(&self) -> Result<Vec<u8>> {
        let e = base64::engine::general_purpose::STANDARD;
        let mut out = Vec::new();
        for c in &self.0 {
            out.extend(e.decode(c).context("not base64")?);
        }
        Ok(out)
    }
}

/// One manual feed's file.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct ManualFileExport {
    pub feed: String,
    /// The file, base64 in chunks.
    pub file: B64File,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub saved_at: Option<String>,
    /// The latest applied run's blob, when it differs from the file (a later save was held or
    /// rejected): applied on restore while the file stays the feed's file.
    #[serde(default)]
    pub applied: Option<AppliedBlob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct AppliedBlob {
    /// The blob, base64 in chunks.
    pub file: B64File,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// One alert: its `alerts` row and its child rows, column by column (BLOBs as `{"b64": …}`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct AlertExport {
    pub alert: Map<String, Value>,
    #[serde(default)]
    pub history: Vec<Map<String, Value>>,
    #[serde(default)]
    pub evidence: Vec<Map<String, Value>>,
    #[serde(default)]
    pub evidence_counts: Vec<Map<String, Value>>,
    #[serde(default)]
    pub evidence_answers: Vec<Map<String, Value>>,
    #[serde(default)]
    pub wire_examples: Vec<Map<String, Value>>,
    #[serde(default)]
    pub evidence_rule: Option<Map<String, Value>>,
}

/// What a restore reports.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct RestoreResult {
    pub restored: bool,
    /// The restore generation this restore committed (one more with every restore since core
    /// started): the `generation` its `restore` UI event carries (api.md §7), so the tab that
    /// restored can tell its own event from another tab's. The event goes out (after the commit)
    /// before this response, so a restoring tab re-reads once, on whichever of the two comes first;
    /// and the generation starts again at 0 when core restarts, so a tab forgets the generations
    /// it knows when its UI WebSocket reconnects.
    pub generation: u64,
    /// Secrets the restored configuration names that still have no value: set them under
    /// Secrets.
    pub missing_secrets: Vec<String>,
    /// What the restore leaves for the admin, one sentence each, at most 50 (the last counts the
    /// rest): edges whose bundle heads are held until their feeds' first checks, manual feeds
    /// whose applied version runs before their saved file, feed providers that check again at
    /// once or wait (disabled, or an `sqs` trigger without its AWS keys), lookup providers
    /// starting with empty verdict caches, edges this core had that the document doesn't,
    /// settings left out or defaulted (a document from another release), and edges' configs
    /// that couldn't be rendered after the commit (core keeps trying; the restore is done all
    /// the same).
    // The bound: MAX_RESTORE_WARNINGS (a test checks the number above).
    pub warnings: Vec<String>,
}

/// What a table becomes in a restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    /// Written from the document.
    Restored,
    /// Emptied: derived data, queues, verdicts, history the document doesn't hold.
    Deleted,
    /// Left as it is (identity, admin account, the edges' own state, scratch handled elsewhere).
    Kept,
    /// Kept in part (see [`restore_in`]).
    Filtered,
}

/// Every `core.db` table and what a restore does with it. A test checks the list covers the
/// schema, so a new table needs a decision here.
pub const TABLES: &[(&str, Fate)] = &[
    ("settings", Fate::Restored),
    ("ui_account", Fate::Kept),
    ("edges", Fate::Restored),
    ("edge_pending", Fate::Deleted),
    ("listeners", Fate::Restored),
    ("listener_edges", Fate::Restored),
    ("clients", Fate::Restored),
    ("profiles", Fate::Restored),
    ("upstreams", Fate::Restored),
    ("upstream_groups", Fate::Restored),
    ("forward_zones", Fate::Restored),
    ("feed_providers", Fate::Restored),
    ("feeds", Fate::Restored),
    ("manual_files", Fate::Restored),
    ("bundles", Fate::Restored),
    ("bundle_feeds", Fate::Restored),
    ("lookup_providers", Fate::Restored),
    ("secrets", Fate::Restored),
    ("config_changes", Fate::Restored),
    ("feed_runs", Fate::Deleted),
    ("feed_entries", Fate::Deleted),
    ("feed_entry_undo", Fate::Deleted),
    ("feed_state", Fate::Restored),
    ("feed_provider_checks", Fate::Restored),
    ("feed_checks", Fate::Restored),
    ("feed_changes", Fate::Restored),
    ("warnings", Fate::Deleted),
    ("policy_drops", Fate::Deleted),
    ("bundle_keys", Fate::Deleted),
    ("bundle_shards", Fate::Deleted),
    ("bundle_key_hits", Fate::Deleted),
    ("bundle_ip_ranges", Fate::Deleted),
    ("bundle_ip_shards", Fate::Deleted),
    ("bundle_versions", Fate::Filtered),
    ("blobs", Fate::Kept),
    ("edge_status", Fate::Filtered),
    ("edge_configs", Fate::Filtered),
    ("edge_boots", Fate::Filtered),
    ("edge_events", Fate::Deleted),
    ("edge_releases", Fate::Kept),
    // The edges' pending requests (an Update, a flush, a revoke of a temporary allow made while
    // an edge was offline) and their temporary allows concern the edges, not the configuration:
    // kept for the edges the document holds (README §3: requests wait for the edge).
    ("edge_requests", Fate::Filtered),
    ("temp_allows", Fate::Filtered),
    ("alerts", Fate::Restored),
    ("alert_history", Fate::Restored),
    ("alert_evidence", Fate::Restored),
    ("alert_evidence_counts", Fate::Restored),
    ("wire_examples", Fate::Restored),
    ("alert_evidence_answers", Fate::Restored),
    ("lookup_queue", Fate::Deleted),
    ("lookup_verdicts", Fate::Deleted),
    ("lookup_blocks", Fate::Deleted),
    ("verdict_sets", Fate::Filtered),
    ("dnssec_queue", Fate::Deleted),
    ("dnssec_results", Fate::Deleted),
    ("crosscheck_queue", Fate::Deleted),
    ("crosscheck_seen", Fate::Deleted),
    ("edge_named", Fate::Filtered),
    ("edge_pins", Fate::Filtered),
    ("log_clamped", Fate::Deleted),
    ("feed_provider_state", Fate::Restored),
    // Run ids and source generations: AUTOINCREMENT keeps them increasing across the restore.
    ("feed_run_ids", Fate::Deleted),
    ("feed_runs_open", Fate::Deleted),
    ("module_pauses", Fate::Kept),
    ("feed_imports", Fate::Deleted),
    ("feed_purges", Fate::Deleted),
    ("retro_runs", Fate::Deleted),
    // Log-work progress and its metric outbox: the log partitions and metrics.db are emptied.
    ("log_progress", Fate::Deleted),
    ("retro_progress", Fate::Deleted),
    ("retro_values", Fate::Deleted),
    ("trial_pending", Fate::Deleted),
    ("metric_outbox", Fate::Deleted),
    ("alert_evidence_rules", Fate::Restored),
    // The split each bundle's builds last applied (`released_json`) stays, so a restored bundle
    // builds with it until the dry run of its restored proposal reports (bundles.md §2 Tiering);
    // compiler::tier drops the rows of bundles the restored configuration doesn't have.
    ("tier_dry_runs", Fate::Kept),
    ("bundle_builds", Fate::Deleted),
    ("bundle_build_keys", Fate::Deleted),
    ("bundle_build_ops", Fate::Deleted),
    ("bundle_version_blobs", Fate::Filtered),
    ("bundle_build_blobs", Fate::Deleted),
    ("bundle_build_fresh", Fate::Deleted),
    ("bundle_build_ip_rules", Fate::Deleted),
    ("bundle_build_ip_runs", Fate::Deleted),
    ("bundle_build_rank", Fate::Deleted),
    ("warning_rechecks", Fate::Deleted),
    ("warning_pairing", Fate::Deleted),
    ("browser_lists", Fate::Deleted),
    ("lookup_recheck_days", Fate::Deleted),
    // Change numbers only increase (lookups::store), across restores too.
    ("lookup_verdict_seq", Fate::Kept),
    // Which logged records' lookup effects were applied: goes with the queue it fed.
    ("lookup_ingested", Fate::Deleted),
    // Which answers provider alerts counted: their records leave the partitions with the restore.
    ("lookup_answers_counted", Fate::Deleted),
    ("verdict_set_state", Fate::Deleted),
    ("verdict_set_overlay", Fate::Deleted),
    ("verdict_set_blobs", Fate::Filtered),
    ("restore_holds", Fate::Filtered),
    ("restore_pending", Fate::Filtered),
    ("restore_applied", Fate::Restored),
    ("dnssec_admitted", Fate::Deleted),
    // The LAN CA stays with the instance (core.md §2), with the previous roots its edges still
    // serve certificates from and what the edges the document keeps last reported serving.
    ("lanca_roots", Fate::Kept),
    ("lanca_served", Fate::Filtered),
    // Derived from the log partitions, which a restore empties.
    ("cold_share_state", Fate::Deleted),
];

// ---------------------------------------------------------------------------------------------
// The restore generation

/// Keeps work that began before a restore from committing after it (core.md §2: "the old state
/// until it completes, then only the new one"), and runs one export and one restore at a time.
///
/// - The generation goes up on the writer, right after the restore's transaction commits
///   ([`RestoreGate::committed`]), so a write closure that runs after the commit sees the new
///   value: background work (DNSSEC validations, cross-checks, log analysis batches, evidence
///   copies, bundle builds) takes the generation when it starts and writes nothing when it
///   changed.
/// - `logs_pending`: the log partitions still hold pre-restore records until
///   [`finish_pending`] empties them; the analysis waits for that, and log batches are answered
///   `503` meanwhile (the edge keeps them in its spool and sends them again), so the partitions
///   are emptied of pre-restore records only. It is set on the core.db writer right after the
///   commit and read by the log writer before each partition write
///   ([`crate::logs::writer::LogWriter::write_unless`]), so a batch admitted before the restore
///   whose write reaches the log writer after the commit is refused there, never stored, acked
///   and then emptied (core.md §6: the ack means the records are kept). Rows the log writer
///   stored before the flag was set are pre-restore records and go with the restore.
/// - One export and one restore at a time ([`RestoreGate::begin_export`],
///   [`RestoreGate::begin_restore`]; README §2 Bounded: each stages up to [`MAX_DOCUMENT_BYTES`]
///   in `staging/`), each leaving free on the data disk a margin of its own size, within
///   [`DISK_MARGIN_FLOOR`] and [`DISK_MARGIN`], and each ended when its download or upload
///   stalls for [`STREAM_IDLE`], so a stalled one gives its slot back.
#[derive(Debug)]
pub struct RestoreGate {
    generation: std::sync::atomic::AtomicU64,
    logs_pending: Arc<std::sync::atomic::AtomicBool>,
    exporting: Arc<std::sync::atomic::AtomicBool>,
    restoring: Arc<std::sync::atomic::AtomicBool>,
    margins: std::sync::Mutex<(u64, u64)>,
    stream_idle_ms: std::sync::atomic::AtomicU64,
    /// Tests: the next restore's render of the edges' configs fails.
    fail_render: std::sync::atomic::AtomicBool,
}

/// The most free space an export or a restore leaves on the data disk besides what it writes
/// (README §2 Bounded): a policy choice, a quarter of the 2 GB at which `core_disk_low` fires
/// (core.md §9), so neither fills the disk core's databases and logs live on. A job leaves its
/// own size, between [`DISK_MARGIN_FLOOR`] and this ([`margin_for`]).
pub const DISK_MARGIN: u64 = 512 * 1024 * 1024;
/// The least free space a job leaves besides what it writes: a small export or restore (tens of
/// kilobytes) needs only this much more, not [`DISK_MARGIN`]. A policy choice.
pub const DISK_MARGIN_FLOOR: u64 = 64 * 1024 * 1024;
/// How long an export's download may go without taking its next chunk (256 KiB), or a restore's
/// upload without sending more, before it is ended (README §2 Bounded): the job's slot, its
/// staged file and its disk space are given back, so a paused download or a stalled upload
/// doesn't hold off every later export or restore (`409`). A policy choice, as long as an edge's
/// log batch may take to arrive; a download slower than about 4 KiB/s is ended.
pub const STREAM_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// The free space a job writing `bytes` into `staging/` leaves besides them, with these
/// (floor, cap): its own size within them. So a job takes at most about half the free space it
/// finds, and a small one isn't refused for want of [`DISK_MARGIN`].
pub fn margin_for(bytes: u64, (floor, cap): (u64, u64)) -> u64 {
    bytes.clamp(floor, cap.max(floor))
}

impl Default for RestoreGate {
    fn default() -> Self {
        Self {
            generation: Default::default(),
            logs_pending: Default::default(),
            exporting: Default::default(),
            restoring: Default::default(),
            margins: std::sync::Mutex::new((DISK_MARGIN_FLOOR, DISK_MARGIN)),
            stream_idle_ms: std::sync::atomic::AtomicU64::new(picket_api::duration::as_millis_u64(
                STREAM_IDLE,
            )),
            fail_render: Default::default(),
        }
    }
}

/// An export or a restore running; dropping it ends it.
#[derive(Debug)]
#[must_use = "the job runs while the slot is held"]
pub struct JobSlot(Arc<std::sync::atomic::AtomicBool>);

impl Drop for JobSlot {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

fn take_slot(flag: &Arc<std::sync::atomic::AtomicBool>) -> Option<JobSlot> {
    flag.compare_exchange(
        false,
        true,
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
    )
    .ok()
    .map(|_| JobSlot(flag.clone()))
}

impl RestoreGate {
    /// Tests: the next restore's render of the edges' configs, after its commit, fails.
    #[doc(hidden)]
    pub fn fail_next_render(&self) {
        self.fail_render.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The current generation, taken when a piece of work starts.
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// True when no restore committed since `generation` was taken. Call it inside the write
    /// closure that commits the work, so the check and the commit are ordered with the restore.
    pub fn is_current(&self, generation: u64) -> bool {
        self.generation() == generation
    }

    /// True while the log partitions still hold pre-restore records.
    pub fn logs_pending(&self) -> bool {
        self.logs_pending.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The `logs_pending` flag itself, for the log writer to read before each partition write
    /// (module docs: ordered with [`finish_pending`]'s deletes on the same thread).
    pub fn logs_pending_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.logs_pending.clone()
    }

    /// The export's slot, unless one is being written.
    pub fn begin_export(&self) -> Option<JobSlot> {
        take_slot(&self.exporting)
    }

    /// The restore's slot, unless one runs.
    pub fn begin_restore(&self) -> Option<JobSlot> {
        take_slot(&self.restoring)
    }

    /// The (floor, cap) of the free space a job leaves besides what it writes ([`margin_for`]).
    pub fn margins(&self) -> (u64, u64) {
        *self.margins.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The free space a job writing `bytes` leaves besides them ([`margin_for`]).
    pub fn margin_for(&self, bytes: u64) -> u64 {
        margin_for(bytes, self.margins())
    }

    /// Changes [`RestoreGate::margins`] (tests: a disk without room, or with little).
    #[doc(hidden)]
    pub fn set_margins(&self, floor: u64, cap: u64) {
        *self.margins.lock().unwrap_or_else(|p| p.into_inner()) = (floor, cap);
    }

    /// How long a download or an upload may stall ([`STREAM_IDLE`]).
    pub fn stream_idle(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.stream_idle_ms.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Changes [`RestoreGate::stream_idle`] (tests).
    #[doc(hidden)]
    pub fn set_stream_idle(&self, d: std::time::Duration) {
        self.stream_idle_ms.store(
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// On the writer, right after a restore commits.
    fn committed(&self) {
        self.logs_pending.store(true, std::sync::atomic::Ordering::SeqCst);
        self.generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// At start, when a restore stopped before emptying the log partitions.
    fn pending_at_start(&self) {
        self.logs_pending.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn logs_emptied(&self) {
        self.logs_pending
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------------------------
// Rows as JSON

fn row_json(r: &rusqlite::Row<'_>, cols: &[String]) -> rusqlite::Result<Map<String, Value>> {
    let mut m = Map::new();
    for (i, c) in cols.iter().enumerate() {
        let v = match r.get_ref(i)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(n) => json!(n),
            ValueRef::Real(f) => json!(f),
            ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(b) => json!({"b64": base64::engine::general_purpose::STANDARD.encode(b)}),
        };
        m.insert(c.clone(), v);
    }
    Ok(m)
}

fn rows(c: &Connection, sql: &str, p: impl rusqlite::Params) -> Result<Vec<Map<String, Value>>> {
    let mut st = c.prepare(sql)?;
    let cols: Vec<String> = st.column_names().map(|s| s.to_string()).collect();
    let out = st
        .query_map(p, |r| row_json(r, &cols))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(out)
}

/// The columns a table has in this schema.
fn columns(c: &Connection, table: &str) -> Result<BTreeSet<String>> {
    let mut st = c.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let cols = st
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    Ok(cols)
}

fn sql_value(v: &Value) -> Result<rusqlite::types::Value> {
    use rusqlite::types::Value as V;
    Ok(match v {
        Value::Null => V::Null,
        Value::Bool(b) => V::Integer(i64::from(*b)),
        Value::Number(n) => match n.as_i64() {
            Some(i) => V::Integer(i),
            None => V::Real(n.as_f64().unwrap_or(0.0)),
        },
        Value::String(s) => V::Text(s.clone()),
        Value::Object(o) if o.len() == 1 && o.contains_key("b64") => V::Blob(
            base64::engine::general_purpose::STANDARD
                .decode(o.get("b64").and_then(Value::as_str).unwrap_or(""))
                .context("a BLOB that isn't base64")?,
        ),
        other => V::Text(other.to_string()),
    })
}

/// Inserts a document row into `table`, with the columns both know (README §2 Compatibility: an
/// older document lacks newer columns, which take their defaults; unknown ones are ignored).
fn insert_row(
    tx: &Transaction<'_>,
    table: &str,
    known: &BTreeSet<String>,
    row: &Map<String, Value>,
) -> Result<()> {
    let cols: Vec<&String> = row.keys().filter(|k| known.contains(k.as_str())).collect();
    if cols.is_empty() {
        bail!("an empty {table} row");
    }
    let names: Vec<String> = cols.iter().map(|c| format!("\"{c}\"")).collect();
    let marks: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
    let values = cols
        .iter()
        .map(|c| sql_value(&row[c.as_str()]))
        .collect::<Result<Vec<_>>>()?;
    tx.execute(
        &format!(
            "INSERT INTO \"{table}\"({}) VALUES ({})",
            names.join(", "),
            marks.join(", ")
        ),
        rusqlite::params_from_iter(values),
    )
    .with_context(|| format!("a {table} row the schema refuses"))?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Export

/// Why an export can't be written.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// Past [`MAX_DOCUMENT_BYTES`]; names what made it large.
    #[error(
        "the export would be larger than {} MiB, the most a restore reads (so far manual feed files: {} MiB, alerts with their evidence: {} MiB): shrink large manual feeds or delete alerts with much evidence, then export again",
        .limit / (1024 * 1024),
        .manual / (1024 * 1024),
        .alerts / (1024 * 1024)
    )]
    TooLarge { limit: u64, manual: u64, alerts: u64 },
    /// A part past the cap the restore reads it with ([`stream::CAPS`]); names the part.
    #[error(
        "the export can't be restored: its {0}; the restore reads parts only within these bounds (README §2 Bounded)"
    )]
    Part(String),
    /// The data disk has no room left for the staged document and the margin.
    #[error(
        "the data disk has too little free space to write the export (at least {} MiB must stay free)",
        .0 / (1024 * 1024)
    )]
    Disk(u64),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<rusqlite::Error> for ExportError {
    fn from(e: rusqlite::Error) -> Self {
        ExportError::Other(e.into())
    }
}

impl From<std::io::Error> for ExportError {
    fn from(e: std::io::Error) -> Self {
        ExportError::Other(e.into())
    }
}

impl From<serde_json::Error> for ExportError {
    fn from(e: serde_json::Error) -> Self {
        ExportError::Other(e.into())
    }
}

/// A writer that counts what it wrote and refuses to pass its limit ([`MAX_DOCUMENT_BYTES`]),
/// checks what it writes as the restore will ([`stream::Prescan`]: the same part caps, string
/// and depth bounds), and stops when the data disk runs short of room ([`Room`]).
struct Bounded<W> {
    inner: W,
    n: u64,
    limit: u64,
    /// Bytes per part, for the error.
    manual: u64,
    alerts: u64,
    scan: stream::Prescan,
    /// The first bound the written bytes broke.
    refused: Option<String>,
    room: Option<Room>,
}

/// The free-space check of a job that writes into `staging/` (README §2 Bounded): every
/// [`ROOM_EVERY`] bytes, the data disk must still have the job's margin free, which grows with
/// what it wrote ([`margin_for`]).
pub struct Room {
    dir: std::path::PathBuf,
    margins: (u64, u64),
    written: u64,
    since: u64,
}

/// How often a job writing into `staging/` checks the free space.
const ROOM_EVERY: u64 = 32 * 1024 * 1024;

impl Room {
    /// `margins`: the (floor, cap) of [`margin_for`] ([`RestoreGate::margins`]).
    pub fn new(dir: &std::path::Path, margins: (u64, u64)) -> Self {
        Self {
            dir: dir.to_path_buf(),
            margins,
            written: 0,
            since: 0,
        }
    }

    /// The free space the job must leave now.
    pub fn margin(&self) -> u64 {
        margin_for(self.written, self.margins)
    }

    /// Notes `n` more bytes written; an error once the margin is reached.
    fn wrote(&mut self, n: u64) -> std::io::Result<()> {
        self.written = self.written.saturating_add(n);
        self.since += n;
        if self.since < ROOM_EVERY {
            return Ok(());
        }
        self.since = 0;
        self.check()
    }

    /// Fails when less than the margin is free (or the free space can't be read).
    pub fn check(&self) -> std::io::Result<()> {
        let free = crate::run::disk_space(&self.dir)
            .map(|(free, _)| free)
            .map_err(|e| std::io::Error::other(format!("cannot read the free space: {e:#}")))?;
        if free < self.margin() {
            return Err(std::io::Error::other(NO_ROOM));
        }
        Ok(())
    }
}

impl<W: std::io::Write> std::io::Write for Bounded<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.n + buf.len() as u64 > self.limit {
            return Err(std::io::Error::other(TOO_LARGE));
        }
        if let Err(e) = self.scan.feed(buf) {
            self.refused = Some(e);
            return Err(std::io::Error::other(REFUSED));
        }
        if let Some(r) = self.room.as_mut() {
            r.wrote(buf.len() as u64)?;
        }
        // The pre-scan saw all of `buf`: write all of it.
        self.inner.write_all(buf)?;
        self.n += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

const TOO_LARGE: &str = "the export is past its bound";
const REFUSED: &str = "the export breaks a bound of the restore";
const NO_ROOM: &str = "the data disk is short of room";

impl<W: std::io::Write> Bounded<W> {
    fn raw(&mut self, s: &str) -> Result<(), ExportError> {
        self.write_bytes(s.as_bytes())
    }

    fn write_bytes(&mut self, b: &[u8]) -> Result<(), ExportError> {
        use std::io::Write;
        self.write_all(b).map_err(|e| self.too_large(e))
    }

    fn json<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), ExportError> {
        match serde_json::to_writer(&mut *self, v) {
            Ok(()) => Ok(()),
            Err(e) if e.is_io() => Err(self.too_large(std::io::Error::other(e.to_string()))),
            Err(e) => Err(e.into()),
        }
    }

    fn too_large(&self, e: std::io::Error) -> ExportError {
        let text = e.to_string();
        if text.contains(TOO_LARGE) {
            ExportError::TooLarge {
                limit: self.limit,
                manual: self.manual,
                alerts: self.alerts,
            }
        } else if text.contains(REFUSED) {
            ExportError::Part(self.refused.clone().unwrap_or_default())
        } else if text.contains(NO_ROOM) {
            ExportError::Disk(self.room.as_ref().map_or(0, Room::margin))
        } else {
            e.into()
        }
    }
}

/// Writes a blob as a base64 chunk list, reading it from the store in chunks and checking its
/// hash; false when the blob isn't there (a concurrent change, after the snapshot was taken).
fn write_blob<W: std::io::Write>(
    out: &mut Bounded<W>,
    c: &Connection,
    data_dir: &std::path::Path,
    b3: &str,
) -> Result<bool, ExportError> {
    use std::io::Read;
    if crate::blobs::info(c, b3)?.is_none() {
        return Ok(false);
    }
    let path = crate::blobs::path(data_dir, b3)?;
    let Ok(f) = std::fs::File::open(&path) else {
        return Ok(false);
    };
    let mut f = std::io::BufReader::new(f);
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK_BYTES];
    let e = base64::engine::general_purpose::STANDARD;
    out.raw("[")?;
    let mut first = true;
    loop {
        // A whole chunk (the last may be shorter), so each chunk decodes on its own.
        let mut n = 0;
        while n < buf.len() {
            let k = f.read(&mut buf[n..])?;
            if k == 0 {
                break;
            }
            n += k;
        }
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if !first {
            out.raw(",")?;
        }
        first = false;
        let before = out.n;
        out.raw("\"")?;
        out.raw(&e.encode(&buf[..n]))?;
        out.raw("\"")?;
        out.manual += out.n - before;
        if n < buf.len() {
            break;
        }
    }
    out.raw("]")?;
    if hasher.finalize().to_hex().as_str() != b3 {
        return Err(anyhow!("blob {b3} fails its hash check").into());
    }
    Ok(true)
}

/// Writes rows of `sql` as a JSON list.
fn write_rows<W: std::io::Write>(
    out: &mut Bounded<W>,
    c: &Connection,
    sql: &str,
    p: impl rusqlite::Params,
) -> Result<(), ExportError> {
    let mut st = c.prepare_cached(sql)?;
    let cols: Vec<String> = st.column_names().map(|s| s.to_string()).collect();
    let mut rows = st.query(p)?;
    out.raw("[")?;
    let mut first = true;
    while let Some(r) = rows.next()? {
        if !first {
            out.raw(",")?;
        }
        first = false;
        out.json(&row_json(r, &cols)?)?;
    }
    out.raw("]")?;
    Ok(())
}

/// Writes the export document (core.md §2) to `w`, from one read transaction (a consistent
/// snapshot of `core.db`), part by part: nothing larger than a chunk of a file or a row is held
/// in memory. Fails with [`ExportError::TooLarge`] past [`MAX_DOCUMENT_BYTES`]. Returns the
/// bytes written.
pub fn write_export<W: std::io::Write>(
    c: &Connection,
    data_dir: &std::path::Path,
    w: W,
) -> Result<u64, ExportError> {
    write_export_within(c, data_dir, w, MAX_DOCUMENT_BYTES)
}

/// [`write_export`] with another bound (tests).
pub fn write_export_within<W: std::io::Write>(
    c: &Connection,
    data_dir: &std::path::Path,
    w: W,
    limit: u64,
) -> Result<u64, ExportError> {
    write_export_checked(c, data_dir, w, limit, None)
}

/// [`write_export`] into `staging/`, checking the free space as it writes ([`Room`]).
pub fn write_export_checked<W: std::io::Write>(
    c: &Connection,
    data_dir: &std::path::Path,
    w: W,
    limit: u64,
    room: Option<Room>,
) -> Result<u64, ExportError> {
    // One read transaction: everything below reads the same snapshot (core.md §2: one document
    // of one state), whatever commits meanwhile.
    let tx = c.unchecked_transaction()?;
    let c: &Connection = &tx;
    let mut out = Bounded {
        inner: w,
        n: 0,
        limit,
        manual: 0,
        alerts: 0,
        scan: stream::Prescan::default(),
        refused: None,
        room,
    };
    let m = store::load_model(c)?;
    let settings: BTreeMap<String, Value> = {
        let mut st = c.prepare("SELECT key, value_json FROM settings ORDER BY key")?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .filter_map(|(k, v)| serde_json::from_str::<Value>(&v).ok().map(|v| (k, v)))
            .collect()
    };
    // Entities as the UI API shows them: a credential an older release stored in clear in a
    // provider config is masked (README §2 Secrets: never in exports).
    fn masked<T: Serialize + serde::de::DeserializeOwned>(kind: EntityKind, v: &T) -> Result<T> {
        let j = store::for_ui(kind, serde_json::to_value(v)?);
        Ok(serde_json::from_value(j)?)
    }
    let configuration = Configuration {
        settings,
        edges: m.edges.values().cloned().collect(),
        listeners: m.listeners.values().cloned().collect(),
        clients: m.clients.clone(),
        profiles: m.profiles.values().cloned().collect(),
        upstreams: m.upstreams.values().cloned().collect(),
        upstream_groups: m.upstream_groups.values().cloned().collect(),
        forward_zones: m.forward_zones.values().cloned().collect(),
        feed_providers: m
            .feed_providers
            .values()
            .map(|p| masked(EntityKind::FeedProvider, p))
            .collect::<Result<_>>()?,
        feeds: m.feeds.values().cloned().collect(),
        bundles: m.bundles.values().cloned().collect(),
        lookup_providers: m
            .lookup_providers
            .values()
            .map(|p| masked(EntityKind::LookupProvider, p))
            .collect::<Result<_>>()?,
        secrets: m
            .secrets
            .keys()
            .map(|n| SecretExport {
                name: n.clone(),
                value: None,
            })
            .collect(),
    };
    out.raw(&format!("{{\"format_version\":{FORMAT_VERSION},\"exported_at\":"))?;
    out.json(&crate::util::now_ts())?;
    out.raw(",\"core_version\":")?;
    out.json(crate::VERSION)?;
    out.raw(",\"configuration\":")?;
    out.json(&configuration)?;
    drop(configuration);
    // Manual feeds' files, and each one's latest applied blob when it differs.
    out.raw(",\"manual_files\":[")?;
    let mut first = true;
    for f in m.feeds.values().filter(|f| f.is_manual()) {
        let row: Option<(String, String, String)> = c
            .query_row(
                "SELECT blob, version, saved_at FROM manual_files WHERE feed_id = ?1",
                [&f.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((blob, version, saved_at)) = row else {
            continue;
        };
        let applied: Option<(String, Option<String>, Option<String>)> = c
            .query_row(
                "SELECT blob, version, updated_at FROM feed_runs WHERE feed_id = ?1 AND status = 'applied' AND blob IS NOT NULL
                 ORDER BY id DESC LIMIT 1",
                [&f.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .filter(|(ab, _, _)| *ab != blob);
        if !first {
            out.raw(",")?;
        }
        first = false;
        out.raw("{\"feed\":")?;
        out.json(&f.id)?;
        out.raw(",\"version\":")?;
        out.json(&version)?;
        out.raw(",\"saved_at\":")?;
        out.json(&saved_at)?;
        out.raw(",\"file\":")?;
        if !write_blob(&mut out, c, data_dir, &blob)? {
            return Err(anyhow!(
                "feed {:?}'s file is missing from the blob store; export again",
                f.id
            )
            .into());
        }
        if let Some((ab, v, u)) = applied {
            out.raw(",\"applied\":{\"version\":")?;
            out.json(&v)?;
            out.raw(",\"updated_at\":")?;
            out.json(&u)?;
            out.raw(",\"file\":")?;
            if !write_blob(&mut out, c, data_dir, &ab)? {
                return Err(anyhow!(
                    "feed {:?}'s applied blob is missing from the blob store; export again",
                    f.id
                )
                .into());
            }
            out.raw("}")?;
        }
        out.raw("}")?;
    }
    // Alerts with their history and evidence, row by row.
    out.raw("],\"alerts\":[")?;
    {
        let ids: Vec<i64> = {
            let mut st = c.prepare("SELECT id FROM alerts ORDER BY id")?;
            st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
        };
        for (i, id) in ids.iter().enumerate() {
            let before = out.n;
            if i > 0 {
                out.raw(",")?;
            }
            out.raw("{\"alert\":")?;
            let alert = rows(c, "SELECT * FROM alerts WHERE id = ?1", [id])?;
            out.json(alert.first().unwrap_or(&Map::new()))?;
            for (name, table) in stream::ALERT_CHILDREN {
                out.raw(&format!(",\"{name}\":"))?;
                let order = if matches!(*table, "alert_evidence_counts" | "alert_evidence_answers") {
                    ""
                } else {
                    " ORDER BY id"
                };
                write_rows(
                    &mut out,
                    c,
                    &format!("SELECT * FROM \"{table}\" WHERE alert_id = ?1{order}"),
                    [id],
                )?;
            }
            out.raw(",\"evidence_rule\":")?;
            let rule = rows(c, "SELECT * FROM alert_evidence_rules WHERE alert_id = ?1", [id])?;
            out.json(&rule.into_iter().next())?;
            out.raw("}")?;
            out.alerts += out.n - before;
        }
    }
    // The feed side, its check history entry by entry.
    let side = crate::feeds::restore::export(c)?;
    out.raw("],\"feed_state\":{\"feeds\":")?;
    out.json(&side.feeds)?;
    out.raw(",\"providers\":")?;
    out.json(&side.providers)?;
    out.raw(",\"checks\":[")?;
    {
        let mut first = true;
        let mut failed: Option<ExportError> = None;
        crate::feeds::restore::export_checks(c, |part| {
            let r = (|| -> Result<(), ExportError> {
                if !first {
                    out.raw(",")?;
                }
                first = false;
                out.json(&part)
            })();
            if let Err(e) = r {
                failed = Some(e);
                bail!("stopped");
            }
            Ok(())
        })
        .map_err(|e| failed.take().unwrap_or(ExportError::Other(e)))?;
    }
    out.raw("]},\"config_changes\":")?;
    write_rows(&mut out, c, "SELECT * FROM config_changes ORDER BY rowid", [])?;
    out.raw("}")?;
    {
        use std::io::Write;
        out.flush()?;
    }
    drop(tx);
    Ok(out.n)
}

/// The export document in memory (tests and small documents; the UI API streams it, see
/// [`api_get`]).
pub fn export(c: &Connection, data_dir: &std::path::Path) -> Result<ExportDocument> {
    let mut buf = Vec::new();
    write_export(c, data_dir, &mut buf).map_err(|e| anyhow!("{e}"))?;
    Ok(serde_json::from_slice(&buf)?)
}

// ---------------------------------------------------------------------------------------------
// Checking a document

/// Why a document is refused.
#[derive(Debug)]
pub enum Refused {
    /// `422` with a message.
    Invalid(String),
    /// `422` with the validation issues.
    Issues(Vec<validate::Issue>),
}

impl From<Refused> for CoreError {
    fn from(r: Refused) -> Self {
        match r {
            Refused::Invalid(m) => CoreError::Invalid(m),
            Refused::Issues(i) => CoreError::Validation(i),
        }
    }
}

/// The settings a document's rows make.
fn settings_of(rows: &BTreeMap<String, Value>) -> Result<crate::settings::Settings, Refused> {
    let mut patch = Value::Object(Map::new());
    for (k, v) in rows {
        if !crate::settings::KEYS.contains(&k.as_str()) {
            continue; // another release's key
        }
        let mut cur = &mut patch;
        let parts: Vec<&str> = k.split('.').collect();
        for (i, p) in parts.iter().enumerate() {
            let Value::Object(o) = cur else { break };
            if i + 1 == parts.len() {
                o.insert((*p).to_string(), v.clone());
                break;
            }
            cur = o
                .entry((*p).to_string())
                .or_insert_with(|| Value::Object(Map::new()));
        }
    }
    let (s, _) = crate::settings::apply_patch(&crate::settings::Settings::default(), &patch, true)
        .map_err(|e| Refused::Invalid(format!("the export's settings: {e:#}")))?;
    let issues = crate::settings::validate(&s);
    if let Some(i) = issues.first() {
        return Err(Refused::Invalid(format!("the export's setting {}: {}", i.0, i.1)));
    }
    Ok(s)
}

/// Why a document with other `lanca.zones` is refused (core.md §2): they stay with the LAN CA,
/// so the instance's zones change first, by a rotation (core.md §11).
fn zones_refusal(want: &[String], have: &[String]) -> String {
    format!(
        "the export needs lanca.zones {}, and this instance's LAN CA is for {}: change lanca.zones to {} \
         under Settings first (a LAN CA rotation: a new root that every device must trust again), \
         then restore",
        want.join(","),
        have.join(","),
        want.join(",")
    )
}

/// The model a document's head holds, checked (module docs, step 1), with the providers the
/// upgrade of an older release's shapes split off ([`super::store::upgrade_previous`]). `stored`
/// names the secrets with a stored value.
pub fn check_head(
    doc: &stream::Head,
    zones: &[String],
    stored: &BTreeSet<String>,
) -> Result<(Model, super::store::Upgrade), Refused> {
    if doc.format_version == 0 || doc.format_version > FORMAT_VERSION {
        return Err(Refused::Invalid(format!(
            "an export of format {} (this release reads formats 1 to {FORMAT_VERSION})",
            doc.format_version
        )));
    }
    let cfg = &doc.configuration;
    let settings = settings_of(&cfg.settings)?;
    // lanca.zones stays with the LAN CA (core.md §2, §11); like the root's name constraints they
    // are a set, compared as the rotation and the in-transaction check compare them.
    let want = crate::lanca::normalize_zones(&settings.lanca.zones)
        .map_err(|e| Refused::Invalid(format!("{e:#}")))?;
    let have = crate::lanca::normalize_zones(zones).unwrap_or_else(|_| zones.to_vec());
    if !crate::lanca::same_zones(&want, &have) {
        return Err(Refused::Invalid(zones_refusal(&want, &have)));
    }
    let mut m = Model {
        settings,
        ..Model::default()
    };
    fn unique<T>(
        what: &str,
        list: &[T],
        id: impl Fn(&T) -> String,
        into: &mut BTreeMap<String, T>,
    ) -> Result<(), Refused>
    where
        T: Clone,
    {
        for x in list {
            let k = id(x);
            if into.insert(k.clone(), x.clone()).is_some() {
                return Err(Refused::Invalid(format!("the export holds {what} {k:?} twice")));
            }
        }
        Ok(())
    }
    unique("edge", &cfg.edges, |e| e.id.clone(), &mut m.edges)?;
    unique("listener", &cfg.listeners, |e| e.id.clone(), &mut m.listeners)?;
    unique("profile", &cfg.profiles, |e| e.id.clone(), &mut m.profiles)?;
    unique("upstream", &cfg.upstreams, |e| e.id.clone(), &mut m.upstreams)?;
    unique(
        "upstream group",
        &cfg.upstream_groups,
        |e| e.id.clone(),
        &mut m.upstream_groups,
    )?;
    unique(
        "forward zone",
        &cfg.forward_zones,
        |e| e.id.clone(),
        &mut m.forward_zones,
    )?;
    unique(
        "feed provider",
        &cfg.feed_providers,
        |e| e.id.clone(),
        &mut m.feed_providers,
    )?;
    unique("feed", &cfg.feeds, |e| e.id.clone(), &mut m.feeds)?;
    unique("bundle", &cfg.bundles, |e| e.id.clone(), &mut m.bundles)?;
    unique(
        "lookup provider",
        &cfg.lookup_providers,
        |e| e.id.clone(),
        &mut m.lookup_providers,
    )?;
    let mut clients = BTreeMap::new();
    unique("client", &cfg.clients, |c| c.name.clone(), &mut clients)?;
    m.clients = cfg.clients.clone();
    m.clients.sort_by_key(|c| c.position.unwrap_or(u32::MAX));
    for s in &cfg.secrets {
        if !validate::is_slug(&s.name) {
            return Err(Refused::Invalid(format!(
                "{:?} is not a valid secret name",
                s.name
            )));
        }
        if s.value.as_deref() == Some("") {
            return Err(Refused::Invalid(format!(
                "secret {:?} has an empty value",
                s.name
            )));
        }
        if m.secrets
            .insert(
                s.name.clone(),
                SecretMeta {
                    name: s.name.clone(),
                    has_value: s.value.is_some() || stored.contains(&s.name),
                },
            )
            .is_some()
        {
            return Err(Refused::Invalid(format!(
                "the export holds secret {:?} twice",
                s.name
            )));
        }
    }
    for kind in [
        EntityKind::Edge,
        EntityKind::Listener,
        EntityKind::Client,
        EntityKind::Profile,
        EntityKind::Upstream,
        EntityKind::UpstreamGroup,
        EntityKind::ForwardZone,
        EntityKind::FeedProvider,
        EntityKind::Feed,
        EntityKind::Bundle,
        EntityKind::LookupProvider,
        EntityKind::Secret,
    ] {
        if m.count(kind) > validate::max_entities(kind) {
            return Err(Refused::Issues(vec![validate::too_many(kind)]));
        }
    }
    // What an older release's export holds in a since-changed shape reads as the stored
    // configuration does (README §2 Compatibility).
    let upgrade = super::store::upgrade_previous(&mut m);
    // System objects a document lacks (an older release's) are created by the restore.
    super::system::fill_missing(&mut m);
    // Every reference and rule a save checks (one bad reference rejects the whole document).
    let errors: Vec<validate::Issue> = validate::validate(&m)
        .into_iter()
        .filter(|i| i.severity == validate::Severity::Error)
        .collect();
    if !errors.is_empty() {
        return Err(Refused::Issues(errors));
    }
    Ok((m, upgrade))
}

/// The model a document holds, checked with what its first pass read (module docs, step 1):
/// the head ([`check_head`]); each manual file names a manual feed of the document, once, within
/// the document's `feeds.max_download_mib`; and the feed state and check history name only
/// providers and feeds of the document (one bad reference rejects the whole document, core.md
/// §2).
pub fn check_parsed(
    head: &stream::Head,
    read: &stream::Checker,
    zones: &[String],
    stored: &BTreeSet<String>,
) -> Result<(Model, super::store::Upgrade), Refused> {
    let (m, upgrade) = check_head(head, zones, stored)?;
    let max = u64::from(m.settings.feeds.max_download_mib) * 1024 * 1024;
    let mut seen = BTreeSet::new();
    for mf in &read.manual {
        match m.feeds.get(&mf.feed) {
            Some(f) if f.is_manual() => {}
            _ => {
                return Err(Refused::Invalid(format!(
                    "the export's manual file names {:?}, which isn't a manual feed of the export",
                    mf.feed
                )));
            }
        }
        if !seen.insert(mf.feed.as_str()) {
            return Err(Refused::Invalid(format!(
                "the export holds feed {:?}'s file twice",
                mf.feed
            )));
        }
        if mf.file.size > max || mf.applied.as_ref().is_some_and(|a| a.0.size > max) {
            return Err(Refused::Invalid(format!(
                "feed {:?}: its file or applied blob is past feeds.max_download_mib",
                mf.feed
            )));
        }
    }
    for p in &head.feed_providers {
        if !m.feed_providers.contains_key(&p.provider) {
            return Err(Refused::Invalid(format!(
                "the export's feed state names an unknown feed provider {:?}",
                p.provider
            )));
        }
    }
    for f in &head.feed_feeds {
        if !m.feeds.contains_key(&f.feed) {
            return Err(Refused::Invalid(format!(
                "the export's feed state names an unknown feed {:?}",
                f.feed
            )));
        }
    }
    crate::feeds::restore::check_refs(&read.check_providers, &read.check_feeds, &m)
        .map_err(Refused::Invalid)?;
    Ok((m, upgrade))
}

// ---------------------------------------------------------------------------------------------
// Restore

/// A head an edge runs, held after a restore (core.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hold {
    pub edge: String,
    pub bundle: String,
    pub head: String,
}

/// The bundle heads each edge runs, from its reported active versions (`edge_status`), by full
/// head id.
fn running_heads(tx: &Transaction<'_>) -> Result<Vec<Hold>> {
    let mut out = Vec::new();
    let rows: Vec<(String, Option<String>, Option<String>)> = {
        let mut st = tx.prepare("SELECT edge_id, versions_json, previous_versions_json FROM edge_status")?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (edge, versions, _) in rows {
        let Some(v) = versions.and_then(|v| serde_json::from_str::<Value>(&v).ok()) else {
            continue;
        };
        let Some(bundles) = v.get("bundles").and_then(Value::as_object) else {
            continue;
        };
        for (bundle, head) in bundles {
            let short = match head {
                Value::String(s) => s.clone(),
                Value::Object(o) => o.get("head").and_then(Value::as_str).unwrap_or("").to_string(),
                _ => continue,
            };
            if short.is_empty() || short.len() > 64 || !short.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let full: Option<String> = tx
                .query_row(
                    "SELECT head_id FROM bundle_versions WHERE bundle_id = ?1 AND head_id >= ?2 AND head_id < ?2 || 'g' LIMIT 1",
                    params![bundle, short.to_ascii_lowercase()],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(head) = full {
                out.push(Hold {
                    edge: edge.clone(),
                    bundle: bundle.clone(),
                    head,
                });
            }
        }
    }
    Ok(out)
}

/// The bundles whose heads are held: those with an enabled downloaded member feed whose
/// provider is enabled.
fn held_bundles(m: &Model) -> BTreeSet<String> {
    m.bundles
        .values()
        .filter(|b| {
            b.feeds.iter().any(|bf| {
                m.feeds.get(&bf.feed).is_some_and(|f| {
                    f.enabled
                        && f.provider
                            .as_ref()
                            .and_then(|p| m.feed_providers.get(p))
                            .is_some_and(|p| p.enabled)
                })
            })
        })
        .map(|b| b.id.clone())
        .collect()
}

/// What the restore transaction did, for the steps after the commit.
#[derive(Debug, Default)]
pub struct Restored {
    pub missing_secrets: Vec<String>,
    /// [`RestoreResult::warnings`], not yet capped ([`cap_warnings`]).
    pub warnings: Vec<String>,
    /// Manual feeds whose applied blob differs from their file: (feed, blob, version, updated_at).
    pub applied: Vec<(String, String, String, String)>,
}

fn random_generation() -> String {
    crate::util::random_hex(8)
}

/// Pass 2's sink: the streamed parts into the restore's transaction.
struct Writer<'a, 'b> {
    tx: &'a Transaction<'b>,
    cols: BTreeMap<&'static str, BTreeSet<String>>,
}

impl stream::Sink for Writer<'_, '_> {
    fn decode(&self) -> bool {
        false
    }

    fn staging(&self) -> Option<&std::path::Path> {
        None
    }

    fn manual_file(&mut self, _m: stream::ManualMeta) -> Result<()> {
        Ok(())
    }

    fn alert(&mut self, row: Map<String, Value>) -> Result<()> {
        insert_row(self.tx, "alerts", &self.cols["alerts"], &row)
    }

    fn alert_row(&mut self, table: &'static str, row: Map<String, Value>) -> Result<()> {
        let cols = self.cols.get(table).ok_or_else(|| anyhow!("no table {table}"))?;
        insert_row(self.tx, table, cols, &row)
    }

    fn alert_end(&mut self) -> Result<()> {
        Ok(())
    }

    fn check(&mut self, c: crate::feeds::restore::CheckPart) -> Result<()> {
        crate::feeds::restore::restore_check_in(self.tx, &c)
    }

    fn change(&mut self, row: Map<String, Value>) -> Result<()> {
        insert_row(self.tx, "config_changes", &self.cols["config_changes"], &row)
    }
}

/// The restore transaction (module docs, step 2). The document at `doc_path` was read into
/// `head` and `manual` and [`check_parsed`] into `m`; its alerts, check history and
/// `config_changes` are read from it again here, as they are written.
pub fn restore_in(
    tx: &Transaction<'_>,
    data_dir: &std::path::Path,
    key: Option<&super::SecretsKey>,
    doc: &stream::Head,
    m: &Model,
    manual: &[stream::ManualMeta],
    doc_path: &std::path::Path,
) -> Result<Restored> {
    // lanca.zones stays with the LAN CA (core.md §2): checked again against the root core.db
    // names, so a rotation committed since step 1 can't pair the document's zones with another
    // root (core.md §11).
    if let Some(zones) = crate::lanca::rotation::current_zones(tx)?
        && !crate::lanca::same_zones(&zones, &m.settings.lanca.zones)
    {
        anyhow::bail!("{}", zones_refusal(&m.settings.lanca.zones, &zones));
    }
    let now = crate::util::now_ts();
    let mut out = Restored::default();
    // The edges this core has, for the warnings about those the document drops.
    let edges_before: Vec<(String, String)> = {
        let mut st = tx.prepare("SELECT id, name FROM edges ORDER BY name")?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    // What survives: the heads edges run, secret values named without one.
    let running = running_heads(tx)?;
    let held = held_bundles(m);
    let keep_values: Vec<(String, Vec<u8>)> = {
        let mut st = tx.prepare("SELECT name, value_enc FROM secrets")?;
        st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter(|(n, v)| {
                v.len() > 1
                    && doc
                        .configuration
                        .secrets
                        .iter()
                        .any(|s| s.name == *n && s.value.is_none())
            })
            .collect()
    };
    // Tables: delete what is restored or derived.
    let existing: BTreeSet<String> = {
        let mut st =
            tx.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")?;
        st.query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (t, fate) in TABLES {
        if !existing.contains(*t) {
            continue;
        }
        if matches!(fate, Fate::Restored | Fate::Deleted) {
            tx.execute(&format!("DELETE FROM \"{t}\""), [])?;
        }
    }
    // Filtered: the edges' own state for the edges the document keeps.
    let edges: Vec<&String> = m.edges.keys().collect();
    let in_edges = |e: &str| edges.iter().any(|x| x.as_str() == e);
    for t in [
        "edge_status",
        "edge_configs",
        "edge_boots",
        "edge_named",
        "edge_pins",
        "edge_requests",
        "temp_allows",
        "lanca_served",
    ] {
        let ids: Vec<String> = {
            let mut st = tx.prepare(&format!("SELECT DISTINCT edge_id FROM \"{t}\""))?;
            st.query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        for id in ids.iter().filter(|id| !in_edges(id)) {
            tx.execute(&format!("DELETE FROM \"{t}\" WHERE edge_id = ?1"), [id])?;
        }
    }
    // A flush of a lookup provider the document doesn't hold has nothing to flush.
    {
        let providers: Vec<&String> = m.lookup_providers.keys().collect();
        let flushes: Vec<(String, String)> = {
            let mut st =
                tx.prepare("SELECT edge_id, provider FROM edge_requests WHERE kind = 'flush_lookups'")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (e, p) in flushes.iter().filter(|(_, p)| !providers.contains(&p)) {
            tx.execute(
                "DELETE FROM edge_requests WHERE edge_id = ?1 AND kind = 'flush_lookups' AND provider = ?2",
                params![e, p],
            )?;
        }
    }
    // Bundle and verdict-set versions: those an edge runs or is pinned to stay, with their blobs.
    let pinned: Vec<(String, String, String)> = {
        let mut st = tx.prepare("SELECT kind, target, id FROM edge_pins")?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    tx.execute(
        "CREATE TEMP TABLE IF NOT EXISTS restore_keep(kind TEXT, target TEXT, id TEXT)",
        [],
    )?;
    tx.execute("DELETE FROM temp.restore_keep", [])?;
    for h in &running {
        tx.execute(
            "INSERT INTO temp.restore_keep(kind, target, id) VALUES ('bundle', ?1, ?2)",
            params![h.bundle, h.head],
        )?;
    }
    for (k, t, id) in &pinned {
        tx.execute(
            "INSERT INTO temp.restore_keep(kind, target, id) VALUES (?1, ?2, ?3)",
            params![k, t, id],
        )?;
    }
    tx.execute(
        "DELETE FROM bundle_versions WHERE NOT EXISTS (SELECT 1 FROM temp.restore_keep k
           WHERE k.kind = 'bundle' AND k.target = bundle_versions.bundle_id AND k.id = bundle_versions.head_id)",
        [],
    )?;
    tx.execute(
        "DELETE FROM bundle_version_blobs WHERE NOT EXISTS (SELECT 1 FROM bundle_versions v
           WHERE v.bundle_id = bundle_version_blobs.bundle_id AND v.head_id = bundle_version_blobs.head_id)",
        [],
    )?;
    tx.execute(
        "DELETE FROM verdict_sets WHERE NOT EXISTS (SELECT 1 FROM temp.restore_keep k
           WHERE k.kind = 'verdict_set' AND k.target = verdict_sets.provider_id AND k.id = verdict_sets.head_id)",
        [],
    )?;
    tx.execute(
        "DELETE FROM verdict_set_blobs WHERE NOT EXISTS (SELECT 1 FROM verdict_sets v
           WHERE v.provider_id = verdict_set_blobs.provider_id AND v.head_id = verdict_set_blobs.head_id)",
        [],
    )?;
    tx.execute("DROP TABLE temp.restore_keep", [])?;
    tx.execute("DELETE FROM restore_holds", [])?;
    // The configuration.
    let defaults = crate::settings::KEYS;
    for (k, v) in &doc.configuration.settings {
        if defaults.contains(&k.as_str()) {
            tx.execute(
                "INSERT INTO settings(key, value_json) VALUES (?1, ?2)",
                params![
                    k,
                    if k == "web.addresses" {
                        serde_json::to_string(&m.settings.web.addresses)?
                    } else {
                        serde_json::to_string(v)?
                    }
                ],
            )?;
        }
    }
    for e in m.edges.values() {
        store::write_edge(tx, e)?;
    }
    for l in m.listeners.values() {
        store::write_listener(tx, l)?;
    }
    for (i, c) in m.clients.iter().enumerate() {
        let mut c = c.clone();
        c.position.get_or_insert(u32::try_from(i).unwrap_or(u32::MAX));
        store::write_client(tx, &c)?;
    }
    for p in m.profiles.values() {
        store::write_profile(tx, p)?;
    }
    for u in m.upstreams.values() {
        store::write_upstream(tx, u)?;
    }
    for g in m.upstream_groups.values() {
        store::write_group(tx, g)?;
    }
    for z in m.forward_zones.values() {
        store::write_zone(tx, z)?;
    }
    for p in m.feed_providers.values() {
        store::write_feed_provider(tx, p)?;
    }
    for f in m.feeds.values() {
        store::write_feed(tx, f)?;
        crate::feeds::store::ensure_state(tx, &f.id)?;
    }
    for b in m.bundles.values() {
        store::write_bundle(tx, b)?;
    }
    // Every lookup provider gets a new cache generation (providers.md §4).
    for p in m.lookup_providers.values() {
        let mut p = p.clone();
        p.cache_generation = random_generation();
        store::write_provider(tx, &p)?;
    }
    // Secrets: by name; a value in the document is stored, a name without one keeps its stored
    // value, and no other stored value survives.
    for s in &doc.configuration.secrets {
        let sealed: Vec<u8> = match &s.value {
            Some(v) => {
                super::secrets::seal(key, &s.name, v).map_err(|e| anyhow!("secret {:?}: {e:#}", s.name))?
            }
            None => keep_values
                .iter()
                .find(|(n, _)| *n == s.name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
        };
        if sealed.len() <= 1 {
            out.missing_secrets.push(s.name.clone());
        }
        tx.execute(
            "INSERT INTO secrets(name, value_enc) VALUES (?1, ?2)",
            params![s.name, sealed],
        )?;
    }
    // Secrets the configuration references without the document naming them.
    let named: BTreeSet<&str> = doc
        .configuration
        .secrets
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    for r in m
        .lookup_providers
        .values()
        .flat_map(|p| p.secret_refs())
        .chain(m.feed_providers.values().flat_map(|p| p.secret_refs()))
    {
        if !named.contains(r.as_str()) && !out.missing_secrets.contains(&r) {
            out.missing_secrets.push(r);
        }
    }
    out.missing_secrets.sort();
    out.missing_secrets.dedup();
    // Manual files (decoded into staging/ by the first pass), and the applied blobs to apply
    // first: recorded here, so a stop before their runs finishes them at the next start.
    let max = u64::from(m.settings.feeds.max_download_mib) * 1024 * 1024;
    let put = |d: &stream::Decoded| -> Result<String> {
        let src = d
            .path
            .as_deref()
            .ok_or_else(|| anyhow!("a manual file wasn't decoded"))?;
        let size = crate::blobs::copy_in(data_dir, src, &d.b3, max)?;
        crate::blobs::register(tx, &d.b3, crate::blobs::kind::MANUAL_FILE, size)?;
        Ok(d.b3.clone())
    };
    for mf in manual {
        let b3 = put(&mf.file)?;
        let version = mf
            .version
            .clone()
            .filter(|v| v.len() <= 64)
            .unwrap_or_else(|| picket_api::ids::short_id(&b3).to_string());
        tx.execute(
            "INSERT INTO manual_files(feed_id, blob, version, saved_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                mf.feed,
                b3,
                version,
                mf.saved_at.clone().unwrap_or_else(|| now.clone())
            ],
        )?;
        if let Some((a, v, u)) = &mf.applied {
            let ab3 = put(a)?;
            if ab3 != b3 {
                let version = v
                    .clone()
                    .filter(|v| v.len() <= 64)
                    .unwrap_or_else(|| picket_api::ids::short_id(&ab3).to_string());
                let updated_at = u.clone().unwrap_or_else(|| now.clone());
                tx.execute(
                    "INSERT INTO restore_applied(feed_id, blob, version, updated_at) VALUES (?1, ?2, ?3, ?4)",
                    params![mf.feed, ab3, version, updated_at],
                )?;
                out.applied.push((mf.feed.clone(), ab3, version, updated_at));
            }
        }
    }
    // The feed side: epochs, content hashes, staleness references; every `last` cleared. The
    // check history, alerts with their history and evidence, and the journal stream from the
    // document (pass 2).
    crate::feeds::restore::restore_in(tx, &doc.feed_feeds, &doc.feed_providers)?;
    let cols: BTreeMap<&'static str, BTreeSet<String>> = [
        "alerts",
        "alert_history",
        "alert_evidence",
        "alert_evidence_counts",
        "alert_evidence_answers",
        "wire_examples",
        "alert_evidence_rules",
        "config_changes",
    ]
    .into_iter()
    .map(|t| Ok((t, columns(tx, t)?)))
    .collect::<Result<_>>()?;
    let mut writer = Writer { tx, cols };
    stream::parse(doc_path, &mut writer).map_err(|e| anyhow!(e))?;
    // Missing system objects come back (core.md §2).
    super::system::ensure(tx, data_dir)?;
    // The heads edges run, held for bundles whose downloaded feeds have no runs yet.
    let mut held_by_edge: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for h in running
        .iter()
        .filter(|h| held.contains(&h.bundle) && in_edges(&h.edge))
    {
        tx.execute(
            "INSERT OR REPLACE INTO restore_holds(edge_id, bundle_id, head_id, restored_at) VALUES (?1, ?2, ?3, ?4)",
            params![h.edge, h.bundle, h.head, now],
        )?;
        held_by_edge
            .entry(h.edge.clone())
            .or_default()
            .insert(h.bundle.clone());
    }
    out.warnings = restore_warnings(doc, m, &edges_before, &held_by_edge, &out);
    // Logs and metrics go after the commit; this marker finishes that at the next start.
    tx.execute("DELETE FROM restore_pending", [])?;
    tx.execute("INSERT INTO restore_pending(at) VALUES (?1)", [&now])?;
    super::journal::record(
        tx,
        None,
        "restore",
        EntityKind::Settings,
        "config-export",
        &json!({"op": "restore", "format_version": doc.format_version, "exported_at": doc.exported_at}),
    )?;
    Ok(out)
}

/// Most warnings a restore reports (README §2 Bounded); the last line counts the rest.
pub const MAX_RESTORE_WARNINGS: usize = 50;

/// [`RestoreResult::warnings`]: what a restore leaves for the admin (core.md §2 Export and
/// restore; api.md §7 leaves the field's content to core). The spec names the facts; the wording
/// is core's.
fn restore_warnings(
    doc: &stream::Head,
    m: &Model,
    edges_before: &[(String, String)],
    held_by_edge: &BTreeMap<String, BTreeSet<String>>,
    out: &Restored,
) -> Vec<String> {
    let q = |s: &str| crate::util::sanitize_for_message(s, 128);
    let list = |v: &mut dyn Iterator<Item = String>| {
        let all: Vec<String> = v.collect();
        let shown: Vec<String> = all.iter().take(10).map(|s| q(s)).collect();
        match all.len().saturating_sub(shown.len()) {
            0 => shown.join(", "),
            more => format!("{} and {more} more", shown.join(", ")),
        }
    };
    let mut w: Vec<String> = Vec::new();
    // Bundle heads held per edge (core.md §2).
    for (edge, bundles) in held_by_edge {
        let name = m.edges.get(edge).map_or(edge.as_str(), |e| e.name.as_str());
        w.push(format!(
            "Edge {} keeps running its current versions of {} until each one's downloaded feeds have their first run after the restore (or fail their first check).",
            q(name),
            list(&mut bundles.iter().cloned())
        ));
    }
    // Manual feeds whose applied version differs from their saved file.
    for (feed, ..) in &out.applied {
        w.push(format!(
            "Manual feed {}: its applied version from the document is applied first; then its saved file, which differs, runs.",
            q(feed)
        ));
    }
    // Feed providers: first checks at once, or waiting.
    let enabled: Vec<&FeedProviderDef> = m.feed_providers.values().filter(|p| p.enabled).collect();
    if !enabled.is_empty() {
        w.push(format!(
            "{} enabled feed provider(s) check again at once (each a first check); their feeds' bundles rebuild as the runs arrive.",
            enabled.len()
        ));
    }
    let disabled: Vec<String> = m
        .feed_providers
        .values()
        .filter(|p| {
            !p.enabled
                && m.feeds
                    .values()
                    .any(|f| f.provider.as_deref() == Some(p.id.as_str()))
        })
        .map(|p| p.id.clone())
        .collect();
    if !disabled.is_empty() {
        w.push(format!(
            "Disabled feed provider(s) {}: their feeds have no run until the provider is enabled.",
            list(&mut disabled.into_iter())
        ));
    }
    for p in enabled
        .iter()
        .filter(|p| matches!(p.trigger, super::model::Trigger::Sqs { .. }))
    {
        if p.secret_refs().iter().any(|s| out.missing_secrets.contains(s)) {
            w.push(format!(
                "Feed provider {} reads no SQS queue until its AWS keys are set under Secrets; its backstop checks go on.",
                q(&p.id)
            ));
        }
    }
    // Lookup providers: every one gets a new cache generation (providers.md §4).
    if !m.lookup_providers.is_empty() {
        w.push(format!(
            "{} lookup provider(s) start with empty verdict caches (a new cache generation): edges drop their cached verdicts, and verdict sets start from new bases.",
            m.lookup_providers.len()
        ));
    }
    // Edges this core had that the document doesn't.
    let gone: Vec<String> = edges_before
        .iter()
        .filter(|(id, _)| !m.edges.contains_key(id))
        .map(|(_, name)| name.clone())
        .collect();
    if !gone.is_empty() {
        w.push(format!(
            "Edge(s) {} aren't in the document and were removed: their sessions are refused until they are added again.",
            list(&mut gone.into_iter())
        ));
    }
    // Settings: keys this release doesn't know are left out; another release's document leaves
    // the settings it lacks at their defaults.
    let unknown: Vec<String> = doc
        .configuration
        .settings
        .keys()
        .filter(|k| !crate::settings::KEYS.contains(&k.as_str()))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        w.push(format!(
            "Setting(s) {} aren't known to this release and were left out.",
            list(&mut unknown.into_iter())
        ));
    }
    if let Some(v) = doc.core_version.as_deref().filter(|v| *v != crate::VERSION) {
        w.push(format!(
            "The document was written by release {} (this is {}): settings and fields it doesn't hold take their defaults.",
            q(v),
            crate::VERSION
        ));
    }
    w
}

/// A restore's warnings within [`MAX_RESTORE_WARNINGS`] (README §2 Bounded): past it, the last
/// line counts the rest. Applied once, when the restore reports them (after its render).
fn cap_warnings(mut w: Vec<String>) -> Vec<String> {
    if w.len() > MAX_RESTORE_WARNINGS {
        let more = w.len() - (MAX_RESTORE_WARNINGS - 1);
        w.truncate(MAX_RESTORE_WARNINGS - 1);
        w.push(format!("… and {more} more."));
    }
    w
}

/// The held heads, per edge, still in force: a bundle's holds end once each of its enabled
/// downloaded member feeds whose provider is enabled has an applied run or has failed its first
/// check (core.md §2). Ended holds are deleted.
pub fn holds(c: &Connection, m: &Model) -> rusqlite::Result<BTreeMap<String, BTreeMap<String, String>>> {
    let rows: Vec<(String, String, String, String)> = {
        let mut st = c.prepare("SELECT edge_id, bundle_id, head_id, restored_at FROM restore_holds")?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut done: BTreeMap<String, bool> = BTreeMap::new();
    for (edge, bundle, head, at) in rows {
        let finished = match done.get(&bundle) {
            Some(d) => *d,
            None => {
                let d = hold_done(c, m, &bundle, &at)?;
                done.insert(bundle.clone(), d);
                d
            }
        };
        if !finished {
            out.entry(edge).or_default().insert(bundle, head);
        }
    }
    Ok(out)
}

fn hold_done(c: &Connection, m: &Model, bundle: &str, at: &str) -> rusqlite::Result<bool> {
    let Some(b) = m.bundles.get(bundle) else {
        return Ok(true);
    };
    for bf in &b.feeds {
        let Some(f) = m.feeds.get(&bf.feed) else { continue };
        let Some(p) = f.provider.as_ref().and_then(|p| m.feed_providers.get(p)) else {
            continue;
        };
        if !f.enabled || !p.enabled {
            continue;
        }
        let applied: bool = c
            .query_row(
                "SELECT 1 FROM feed_runs WHERE feed_id = ?1 AND status = 'applied' LIMIT 1",
                [&f.id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let failed: bool = c
            .query_row(
                "SELECT 1 FROM feed_checks WHERE feed_id = ?1 AND ok = 0 AND t >= ?2
                 UNION ALL SELECT 1 FROM feed_provider_checks WHERE provider_id = ?3 AND ok = 0 AND t >= ?2 LIMIT 1",
                params![f.id, at, p.id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !applied && !failed {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Deletes the holds that ended (called as edges render).
pub fn prune_holds(
    c: &Connection,
    live: &BTreeMap<String, BTreeMap<String, String>>,
) -> rusqlite::Result<usize> {
    let rows: Vec<(String, String)> = {
        let mut st = c.prepare("SELECT edge_id, bundle_id FROM restore_holds")?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut n = 0;
    for (e, b) in rows {
        if !live.get(&e).is_some_and(|m| m.contains_key(&b)) {
            n += c.execute(
                "DELETE FROM restore_holds WHERE edge_id = ?1 AND bundle_id = ?2",
                params![e, b],
            )?;
        }
    }
    Ok(n)
}

/// Empties the log partitions and `metrics.db` a restore left (at once after it, or at the next
/// start if core stopped first).
pub async fn finish_pending(state: &SharedState) -> Result<()> {
    let pending: Option<String> = state
        .db
        .read(|c| {
            Ok::<_, anyhow::Error>(
                c.query_row("SELECT at FROM restore_pending LIMIT 1", [], |r| r.get(0))
                    .optional()?,
            )
        })
        .await?;
    let Some(at) = pending else {
        state.restore.logs_emptied();
        return Ok(());
    };
    // The analysis waits until the old partitions are gone (core.md §2: "then only the new one").
    state.restore.pending_at_start();
    let writer = state.logs.writer().clone();
    let store = writer.store().clone();
    let hours = tokio::task::spawn_blocking(move || store.list()).await??;
    for (hour, _) in hours {
        writer.delete(hour).await?;
    }
    let cache = state.metrics.series.clone();
    state
        .metrics_db
        .write(move |c| {
            let tx = c.transaction()?;
            let series: Vec<(String, String)> = {
                let mut st = tx.prepare("SELECT name, labels_json FROM series")?;
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for t in ["points", "histograms", "samples", "series"] {
                tx.execute(&format!("DELETE FROM {t}"), [])?;
            }
            tx.commit()?;
            cache.forget(
                series
                    .into_iter()
                    .map(|(n, l)| {
                        let edge = serde_json::from_str::<BTreeMap<String, String>>(&l)
                            .ok()
                            .and_then(|m| m.get("edge").cloned());
                        (n, l, edge)
                    })
                    .collect(),
            );
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    state
        .db
        .write(move |c| {
            c.execute("DELETE FROM restore_pending WHERE at = ?1", [&at])?;
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    state.restore.logs_emptied();
    tracing::info!("logs and metrics emptied after a config restore");
    Ok(())
}

/// A file in `staging/` (emptied at every start, README §2 Restarts), deleted when dropped.
pub struct Staged(pub std::path::PathBuf);

impl Staged {
    /// A new name in `staging/`.
    pub fn new(data_dir: &std::path::Path, what: &str) -> Result<Self> {
        let dir = data_dir.join("staging");
        crate::util::ensure_dir(&dir)?;
        Ok(Staged(
            dir.join(format!("{what}-{}.tmp", crate::util::random_hex(8))),
        ))
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Restores `doc` (tests and in-process callers; the UI API streams, see [`api_put`]).
pub async fn restore(
    state: &SharedState,
    doc: ExportDocument,
    actor_ip: Option<String>,
) -> CoreResult<RestoreResult> {
    let slot = state
        .restore
        .begin_restore()
        .ok_or_else(|| CoreError::Conflict(RESTORE_BUSY.into()))?;
    let file = Staged::new(&state.data_dir, "restore").map_err(CoreError::Other)?;
    let path = file.0.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let f = std::fs::File::create(&path)?;
        let mut w = std::io::BufWriter::new(f);
        serde_json::to_writer(&mut w, &doc)?;
        std::io::Write::flush(&mut w)?;
        Ok(())
    })
    .await
    .map_err(|e| CoreError::Other(anyhow!("{e}")))?
    .map_err(CoreError::Other)?;
    run_restore(state, slot, file, actor_ip).await
}

/// Restores the staged document in a task of its own that owns the restore's slot and the
/// staged file, and waits for it (module docs). A caller that goes away (the UI's request
/// dropped by a closed tab or a proxy timeout) drops only this wait: core.md §2 (a restore looks
/// atomic, "then only the new one") and README §2 Restarts need every commit followed by step 3
/// (the old logs and metrics emptied, the running parts reloaded), and the slot held until then.
async fn run_restore(
    state: &SharedState,
    slot: JobSlot,
    staged: Staged,
    actor_ip: Option<String>,
) -> CoreResult<RestoreResult> {
    let st = state.clone();
    tokio::spawn(async move {
        let out = restore_file(&st, &staged.0, actor_ip).await;
        drop(staged);
        drop(slot);
        out
    })
    .await
    .map_err(|e| CoreError::Other(anyhow!("the restore stopped: {e}")))?
}

const RESTORE_BUSY: &str = "a restore is running; try again when it ends";
const EXPORT_BUSY: &str = "an export is being written; try again when it ends";

/// What a restore may still write besides the document it spilled (`n` bytes): manual files
/// decoded into `staging/` and copied into the blob store, and the rows it inserts (README §2
/// Bounded; checked with the disk margin before the first pass).
fn restore_needs(n: u64) -> u64 {
    n.saturating_mul(3) / 2
}

/// `507`: the data disk lacks room for the job and the margin.
fn no_room(what: &str, margin: u64) -> crate::web::error::ApiError {
    crate::web::error::ApiError::new(
        axum::http::StatusCode::INSUFFICIENT_STORAGE,
        "insufficient_storage",
        format!(
            "the data disk has too little free space for the {what} (at least {} MiB must stay free besides it)",
            margin / (1024 * 1024)
        ),
    )
}

/// True when the data disk has `need` bytes free besides `margin`.
async fn has_room(dir: &std::path::Path, need: u64, margin: u64) -> bool {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || crate::run::disk_space(&dir))
        .await
        .ok()
        .and_then(Result::ok)
        .is_some_and(|(free, _)| free >= need.saturating_add(margin))
}

/// Restores the document at `path` (module docs): bounds, then the first pass and every check,
/// then one transaction with the second pass, then the reload. The caller holds the restore's
/// slot ([`RestoreGate::begin_restore`]) and runs this where nothing drops it halfway
/// ([`run_restore`]).
pub async fn restore_file(
    state: &SharedState,
    path: &std::path::Path,
    actor_ip: Option<String>,
) -> CoreResult<RestoreResult> {
    let zones = state.lanca.load().zones().to_vec();
    let stored: BTreeSet<String> = state
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT name FROM secrets WHERE length(value_enc) > 1")?;
            let v = st
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<BTreeSet<_>>>()?;
            Ok::<_, CoreError>(v)
        })
        .await?;
    // Step 1: the bounds, then the first pass (manual files decoded into staging/), then every
    // check, all before anything changes.
    let p = path.to_path_buf();
    let staging = state.data_dir.join("staging");
    let (head, read) =
        tokio::task::spawn_blocking(move || -> Result<(stream::Head, stream::Checker), String> {
            let f = std::fs::File::open(&p).map_err(|e| format!("cannot read the document: {e}"))?;
            stream::prescan(f)?;
            let mut read = stream::Checker::new(Some(staging));
            let head = stream::parse(&p, &mut read)?;
            Ok((head, read))
        })
        .await
        .map_err(|e| CoreError::Other(anyhow!("{e}")))?
        .map_err(CoreError::Invalid)?;
    let (model, upgrade) = check_parsed(&head, &read, &zones, &stored).map_err(CoreError::from)?;
    // A provider split off an older one takes its `k` (README §2 Compatibility).
    let mut head = head;
    for (new, from) in &upgrade.splits {
        if let Some(k) = head
            .feed_providers
            .iter()
            .find(|x| &x.provider == from)
            .map(|x| x.k)
        {
            head.feed_providers.push(crate::feeds::restore::ProviderPart {
                provider: new.clone(),
                listing: None,
                k,
            });
        }
    }
    let data_dir = state.data_dir.clone();
    let applied_feeds: Vec<String> = read
        .manual
        .iter()
        .filter(|f| f.applied.is_some())
        .map(|f| f.feed.clone())
        .collect();
    let st = state.clone();
    let doc_path = path.to_path_buf();
    let restored = state
        .config
        .replace_all(
            move |tx, key| {
                restore_in(tx, &data_dir, key, &head, &model, &read.manual, &doc_path)
                    .map_err(|e| CoreError::Invalid(format!("the restore was refused: {e:#}")))
            },
            move |r: &Restored| {
                // On the writer, right after the commit (module docs, step 3): no work that began
                // before the restore commits after it, and every cache that follows the tables
                // is dropped before any new work runs.
                st.restore.committed();
                // UI events noted before the commit (each on the writer, after its own) go out
                // now, before the `restore` event; later ones describe the restored state
                // (`web::events` module docs; core.md §2 "It looks atomic to the user").
                st.events.flush_coalesced();
                st.alerts.forget_open_set();
                st.analysis.caches.clear();
                st.analysis.capture.invalidate();
                st.dnssec.reset_to(st.restore.generation());
                let busy: Vec<String> = r
                    .applied
                    .iter()
                    .map(|(f, _, _, _)| f.clone())
                    .filter(|f| applied_feeds.contains(f))
                    .collect();
                st.feeds.forget_for_restore(&busy);
            },
        )
        .await?;
    // This restore's generation: it holds the restore's slot, so no other restore commits before
    // its event and response carry it.
    let generation = state.restore.generation();
    tracing::warn!(ip = ?actor_ip, generation, "the configuration was replaced by a config export");
    // The old log partitions and metrics go; the analysis resumes after (retried until done).
    if let Err(e) = finish_pending(state).await {
        tracing::warn!(error = %format!("{e:#}"), "cannot empty logs and metrics after the restore yet; retrying");
        let st = state.clone();
        tokio::spawn(async move {
            let mut wait = std::time::Duration::from_secs(5);
            loop {
                tokio::select! {
                    _ = st.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(wait) => {}
                }
                match finish_pending(&st).await {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(error = %format!("{e:#}"), "cannot empty logs and metrics after the restore yet");
                        wait = (wait * 2).min(std::time::Duration::from_secs(300));
                    }
                }
            }
        });
    }
    state.feeds.reload(state).await;
    // What upgrading an older release's shapes changed is told (README §2 Compatibility).
    super::store::announce_upgrade(&state.alerts, &upgrade).await;
    // A manual feed with an applied blob in the document gets it applied, then its file runs
    // (its saved file stays its file, core.md §2).
    submit_applied(state, &restored.applied).await;
    if let Err(e) = state.lookups.reload(state).await {
        tracing::warn!(error = %format!("{e:#}"), "cannot reload lookup providers after the restore");
    }
    let rendered = if state
        .restore
        .fail_render
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        Err(CoreError::Other(anyhow!("rendering failed (test)")))
    } else {
        state.edges.publisher.render(state, None).await
    };
    // Every open tab resyncs (api.md §7 `restore` event), whatever the render did: the restore
    // has committed.
    if let Ok(data) = serde_json::to_value(crate::web::events::RestoreEvent {
        at: crate::util::now_ts(),
        generation,
    }) {
        state.events.send("restore", data);
    }
    // The restore has committed, so it is reported as done whatever the render did (core.md §2:
    // the response carries what the restore leaves for the admin). A failed render is a warning,
    // and the publisher renders again (it retries every few seconds until a render works) while
    // the edges keep their last config (core.md §4).
    let mut warnings = restored.warnings;
    if let Err(e) = rendered {
        tracing::warn!(error = %e, "rendering the edges' configs after the restore failed; retrying");
        state.edges.publisher.trigger(None);
        let w = format!(
            "The edges' configs could not be rendered after the restore ({}); core keeps trying, and the edges keep their last config until it works.",
            crate::util::sanitize_for_message(&e.to_string(), 200)
        );
        warnings.insert(0, w);
    }
    Ok(RestoreResult {
        restored: true,
        generation,
        missing_secrets: restored.missing_secrets,
        warnings: cap_warnings(warnings),
    })
}

/// Queues the run of each manual feed's applied blob (the feed is held busy with its save
/// queued, so its file runs after).
async fn submit_applied(state: &SharedState, applied: &[(String, String, String, String)]) {
    for (feed, blob, version, updated_at) in applied {
        let f = feed.clone();
        let sgen = state
            .db
            .read(move |c| Ok::<_, anyhow::Error>(crate::feeds::store::source_gen(c, &f)?))
            .await
            .ok()
            .flatten();
        state.feeds.submit(
            state,
            feed,
            crate::feeds::ingest::Work::Download(crate::feeds::ingest::DownloadInput {
                blob: blob.clone(),
                version: version.clone(),
                updated_at: crate::util::parse_ts(updated_at).unwrap_or_else(jiff::Timestamp::now),
                downloaded_at: jiff::Timestamp::now(),
                state: json!({}),
                source_gen: sgen,
                trigger_cron: false,
            }),
        );
    }
}

/// Retries of a restored applied blob's run (each a minute after the last; README §2 Bounded):
/// past them the saved file runs without it.
pub const MAX_APPLIED_ATTEMPTS: i64 = 30;
/// The wait before an applied blob's run is tried again.
const APPLIED_RETRY: jiff::SignedDuration = jiff::SignedDuration::from_mins(1);

/// Deletes the `restore_applied` rows that are done: a run of the blob is stored (`feed_runs`
/// starts empty after a restore, so it can only be the blob's own run), the feed isn't a manual
/// feed any more, or the retries are used up.
fn prune_applied(tx: &Transaction<'_>, feed: Option<&str>) -> rusqlite::Result<()> {
    let gone: Vec<(String, i64)> = {
        let mut st = tx.prepare(
            "SELECT feed_id, attempts FROM restore_applied a WHERE (?1 IS NULL OR feed_id = ?1)
               AND (feed_id NOT IN (SELECT feed_id FROM manual_files)
                 OR EXISTS (SELECT 1 FROM feed_runs r WHERE r.feed_id = a.feed_id AND r.blob = a.blob)
                 OR attempts >= ?2)",
        )?;
        st.query_map(params![feed, MAX_APPLIED_ATTEMPTS], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    for (f, attempts) in gone {
        if attempts >= MAX_APPLIED_ATTEMPTS {
            tracing::warn!(feed = %f, attempts, "a restored applied blob's run never started; the feed's saved file runs without it");
        }
        tx.execute("DELETE FROM restore_applied WHERE feed_id = ?1", [&f])?;
    }
    Ok(())
}

/// The applied blobs a restore recorded whose runs haven't happened (a stop came first): the
/// feeds to hold busy before the feeds runtime starts ([`resume_applied`]). A row is done, and
/// deleted, once a run of its blob is stored, its feed isn't a manual feed any more, or its
/// retries are used up ([`MAX_APPLIED_ATTEMPTS`]).
pub async fn pending_applied(state: &SharedState) -> Result<Vec<(String, String, String, String)>> {
    state
        .db
        .write(|c| {
            let tx = c.transaction()?;
            prune_applied(&tx, None)?;
            let rows = {
                let mut st = tx.prepare(
                    "SELECT feed_id, blob, version, updated_at FROM restore_applied ORDER BY feed_id",
                )?;
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            tx.commit()?;
            Ok::<_, anyhow::Error>(rows)
        })
        .await
}

/// What a manual feed's run does about a restored applied blob ([`applied_next`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppliedNext {
    /// None waits: the saved file runs.
    None,
    /// Run this blob first: (blob, version, updated_at). The attempt is counted.
    Run(String, String, String),
    /// A run of the blob was refused a moment ago: try again at this time (the saved file waits).
    Wait(jiff::Timestamp),
}

/// For a manual feed's run (core.md §2: the applied blob is applied, then the saved file runs;
/// README §2 Restarts): a restored applied blob whose own run isn't stored yet runs first, so a
/// run the heavy queue refused is retried with that blob, never replaced by the saved file.
pub async fn applied_next(state: &SharedState, feed: &str) -> Result<AppliedNext> {
    let f = feed.to_string();
    state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            prune_applied(&tx, Some(&f))?;
            let row: Option<(String, String, String, Option<String>)> = tx
                .query_row(
                    "SELECT blob, version, updated_at, next_at FROM restore_applied WHERE feed_id = ?1",
                    [&f],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let now = jiff::Timestamp::now();
            let out = match row {
                None => AppliedNext::None,
                Some((_, _, _, Some(at))) if crate::util::parse_ts(&at).is_some_and(|at| at > now) => {
                    AppliedNext::Wait(crate::util::parse_ts(&at).unwrap_or(now))
                }
                Some((blob, version, updated_at, _)) => {
                    tx.execute(
                        "UPDATE restore_applied SET attempts = attempts + 1, next_at = ?2 WHERE feed_id = ?1",
                        params![f, crate::util::ts(&(now + APPLIED_RETRY))],
                    )?;
                    AppliedNext::Run(blob, version, updated_at)
                }
            };
            tx.commit()?;
            Ok::<_, anyhow::Error>(out)
        })
        .await
}

/// At start (README §2 Restarts): finishes what a restore's stop cut short. `pending` came from
/// [`pending_applied`] before the feeds runtime started, and those feeds were held busy then
/// ([`crate::feeds::Feeds::forget_for_restore`]), so each applied blob runs before its file.
pub async fn resume_applied(state: &SharedState, pending: &[(String, String, String, String)]) {
    if pending.is_empty() {
        return;
    }
    tracing::info!(
        feeds = pending.len(),
        "applying the manual feeds' blobs a config restore left"
    );
    submit_applied(state, pending).await;
}

// ---------------------------------------------------------------------------------------------
// UI API: `GET/PUT config/export`

/// `GET config/export`: the document, as a file, written from one snapshot into `staging/`
/// and streamed from there (module docs); `422` naming what makes it large past
/// [`MAX_DOCUMENT_BYTES`] or a part the restore wouldn't read ([`stream::CAPS`]); `409` while
/// another export is written or streamed; `507` when the data disk lacks room for it and its
/// margin ([`margin_for`]). A download that takes no chunk for [`STREAM_IDLE`] is ended
/// ([`export_body`]). The write owns the export's slot and staged file until it stops, at its next
/// chunk once the request is gone ([`UntilGone`]).
pub async fn api_get(
    axum::extract::State(s): axum::extract::State<SharedState>,
) -> Result<axum::response::Response, crate::web::error::ApiError> {
    use axum::response::IntoResponse;
    let slot = s.restore.begin_export().ok_or_else(|| {
        crate::web::error::ApiError::new(axum::http::StatusCode::CONFLICT, "busy", EXPORT_BUSY)
    })?;
    // Its size isn't known yet: the floor now, and a margin growing with what it writes.
    let margins = s.restore.margins();
    let margin = margin_for(0, margins);
    if !has_room(&s.data_dir, 0, margin).await {
        return Err(no_room("export", margin));
    }
    let staged = Staged::new(&s.data_dir, "export").map_err(CoreError::Other)?;
    let data_dir = s.data_dir.clone();
    // README §2 Bounded (one export at a time, each within its margin): the slot and the staged
    // file go into the write, which runs on a blocking thread whether or not this request is still
    // there; it gives them back when it ends, and ends at its next chunk once the request is gone
    // (the UI's Cancel, a closed tab), so no second export can start beside it.
    let gone = Gone::default();
    let flag = gone.flag();
    let (written, slot, staged) =
        s.db.read(move |c| {
            // Dropped after the file closes, on every way out.
            let (slot, staged) = (slot, staged);
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staged.0)
                .map_err(|e| ExportError::Other(e.into()))?;
            let mut w = std::io::BufWriter::new(UntilGone { inner: f, gone: flag });
            let room = Room::new(&data_dir, margins);
            let n = write_export_checked(c, &data_dir, &mut w, MAX_DOCUMENT_BYTES, Some(room))?;
            let f = w
                .into_inner()
                .map_err(|e| ExportError::Other(e.into_error().into()))?
                .inner;
            f.sync_all().map_err(|e| ExportError::Other(e.into()))?;
            drop(f);
            Ok::<_, ExportError>((n, slot, staged))
        })
        .await
        .map_err(|e| match e {
            ExportError::TooLarge { .. } | ExportError::Part(_) => {
                crate::web::error::ApiError::from(CoreError::Invalid(e.to_string()))
            }
            ExportError::Disk(m) => no_room("export", m),
            ExportError::Other(e) => crate::web::error::ApiError::from(CoreError::Other(e)),
        })?;
    // Opened, then unlinked: the open file streams, and nothing is left behind.
    let file = tokio::fs::File::open(&staged.0)
        .await
        .map_err(|e| CoreError::Other(e.into()))?;
    drop(staged);
    let body = export_body(file, written, slot, s.restore.stream_idle());
    let name = format!(
        "picket-config-{}.json",
        crate::util::day_key(&jiff::Timestamp::now())
    );
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/json".to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (axum::http::header::CACHE_CONTROL, "no-store".to_string()),
            (axum::http::header::CONTENT_LENGTH, written.to_string()),
        ],
        body,
    )
        .into_response())
}

/// Set when [`api_get`] ends, or is dropped because its client went away; read by [`UntilGone`]
/// (by then a finished write no longer reads it).
#[derive(Default)]
struct Gone(Arc<std::sync::atomic::AtomicBool>);

impl Gone {
    fn flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.0.clone()
    }
}

impl Drop for Gone {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The export's staged file, failing every write once the export's request is gone ([`Gone`]):
/// a cancelled export stops at its next chunk instead of writing on (README §2 Bounded).
struct UntilGone<W> {
    inner: W,
    gone: Arc<std::sync::atomic::AtomicBool>,
}

impl<W: std::io::Write> std::io::Write for UntilGone<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.gone.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::other("the export's client went away"));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The export's body (README §2 Bounded): a task holding the export's slot and the open staged
/// file reads it in chunks and hands them to the response. When the response takes no chunk for
/// `idle` (a paused or stalled download: the web server has no write timeout of its own), the
/// task ends, giving back the slot, the file and its disk space, so the next export isn't
/// refused (`409`); the response then fails short of its `Content-Length` (`len`), so the client
/// sees a failed download, never a short document.
fn export_body(
    file: tokio::fs::File,
    len: u64,
    slot: JobSlot,
    idle: std::time::Duration,
) -> axum::body::Body {
    use futures_util::StreamExt;
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(2);
    tokio::spawn(async move {
        let mut slot = Some(slot);
        let mut chunks = tokio_util::io::ReaderStream::with_capacity(file, 256 * 1024).peekable();
        while let Some(chunk) = chunks.next().await {
            let failed = chunk.is_err();
            // The slot goes back before the last chunk is handed over, so it is free by the time
            // the client has the whole document.
            if std::pin::Pin::new(&mut chunks).peek().await.is_none() {
                slot = None;
            }
            match tokio::time::timeout(idle, tx.send(chunk)).await {
                Ok(Ok(())) if !failed => {}
                // A read error (sent on), or the response is gone.
                Ok(_) => return,
                Err(_) => {
                    tracing::warn!(
                        idle_s = idle.as_secs(),
                        "a config export's download stalled; it was ended"
                    );
                    return;
                }
            }
        }
        drop(slot);
    });
    // A stream that ends before `len` bytes (the task ended it) fails instead of ending.
    let stream = futures_util::stream::unfold((rx, len), |(mut rx, left)| async move {
        match rx.recv().await {
            Some(Ok(b)) => {
                let left = left.saturating_sub(b.len() as u64);
                Some((Ok(b), (rx, left)))
            }
            Some(Err(e)) => Some((Err(e), (rx, 0))),
            None if left > 0 => Some((
                Err(std::io::Error::other("the download stalled and was ended")),
                (rx, 0),
            )),
            None => None,
        }
    });
    axum::body::Body::from_stream(stream)
}

/// `PUT config/export`: restores a document (module docs). The body streams into `staging/`
/// (`413` past [`MAX_DOCUMENT_BYTES`]; `408` when it stalls for [`STREAM_IDLE`], which gives the
/// restore's slot back); a malformed document is `422` (api.md §7); `409` while another restore
/// runs; `507` when the data disk lacks room for the document, what the restore writes besides
/// it and their margin ([`margin_for`]).
pub async fn api_put(
    axum::extract::State(s): axum::extract::State<SharedState>,
    peer: Option<axum::Extension<crate::web::protect::PeerAddr>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Body,
) -> Result<axum::Json<RestoreResult>, crate::web::error::ApiError> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let slot = s.restore.begin_restore().ok_or_else(|| {
        crate::web::error::ApiError::new(axum::http::StatusCode::CONFLICT, "busy", RESTORE_BUSY)
    })?;
    let declared = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    if declared > MAX_DOCUMENT_BYTES {
        return Err(too_large_body());
    }
    // What the job writes: the document, then what the restore writes besides it.
    let job = |n: u64| n.saturating_add(restore_needs(n));
    let idle = s.restore.stream_idle();
    let margin = s.restore.margin_for(job(declared));
    if !has_room(&s.data_dir, job(declared), margin).await {
        return Err(no_room("restore", margin));
    }
    let staged = Staged::new(&s.data_dir, "restore").map_err(CoreError::Other)?;
    let n = {
        let f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged.0)
            .await
            .map_err(|e| CoreError::Other(e.into()))?;
        let mut w = tokio::io::BufWriter::with_capacity(256 * 1024, f);
        let mut stream = body.into_data_stream();
        let mut n: u64 = 0;
        let mut checked: u64 = 0;
        loop {
            // README §2 Bounded: an upload that stalls gives the restore's slot back.
            let Ok(next) = tokio::time::timeout(idle, stream.next()).await else {
                return Err(crate::web::error::ApiError::new(
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    "timeout",
                    format!(
                        "the upload stalled for {} s; send the document again",
                        idle.as_secs()
                    ),
                ));
            };
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.map_err(|e| {
                crate::web::error::ApiError::bad_request(format!("the body was cut off: {e}"))
            })?;
            n += chunk.len() as u64;
            if n > MAX_DOCUMENT_BYTES {
                return Err(too_large_body());
            }
            if n - checked >= ROOM_EVERY {
                checked = n;
                let margin = s.restore.margin_for(job(n));
                if !has_room(&s.data_dir, 0, margin).await {
                    return Err(no_room("restore", margin));
                }
            }
            w.write_all(&chunk)
                .await
                .map_err(|e| CoreError::Other(e.into()))?;
        }
        w.flush().await.map_err(|e| CoreError::Other(e.into()))?;
        n
    };
    let margin = s.restore.margin_for(job(n));
    if !has_room(&s.data_dir, restore_needs(n), margin).await {
        return Err(no_room("restore", margin));
    }
    let ip = peer.map(|p| crate::net::canonical_ip(p.0.0.ip()).to_string());
    // From here the restore runs to its end whether or not the client stays (module docs).
    Ok(axum::Json(run_restore(&s, slot, staged, ip).await?))
}

fn too_large_body() -> crate::web::error::ApiError {
    crate::web::error::ApiError::new(
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
        format!(
            "a config export is at most {} MiB",
            MAX_DOCUMENT_BYTES / (1024 * 1024)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_has_a_fate() {
        let dir = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(dir.path());
        let mut c = crate::db::open_connection(&opts, 1024).unwrap();
        crate::db::migrate::apply(&mut c, &crate::db::migrate::CORE).unwrap();
        let mut st = c
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
            .unwrap();
        let tables: Vec<String> = st
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for t in &tables {
            assert!(
                TABLES.iter().any(|(n, _)| n == t),
                "table {t} needs a fate in config::export::TABLES"
            );
        }
    }

    /// README §2 Bounded (final check, round 3): a download that takes no chunk for the idle
    /// time is ended, giving the export's slot back, and fails rather than ending short.
    #[tokio::test]
    async fn a_stalled_download_gives_the_export_slot_back() {
        use futures_util::StreamExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc");
        std::fs::write(&path, vec![b' '; 4 << 20]).unwrap();
        let gate = RestoreGate::default();
        let slot = gate.begin_export().unwrap();
        let file = tokio::fs::File::open(&path).await.unwrap();
        let body = export_body(file, 4 << 20, slot, std::time::Duration::from_millis(200));
        let mut stream = body.into_data_stream();
        assert!(stream.next().await.unwrap().is_ok());
        assert!(gate.begin_export().is_none(), "the download holds the slot");
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        assert!(
            gate.begin_export().is_some(),
            "a stalled download gives the slot back"
        );
        let mut failed = false;
        while let Some(c) = stream.next().await {
            if c.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "the rest fails: the client sees a failed download");
        // A download that keeps up gets the whole file.
        let slot = gate.begin_export().unwrap();
        let file = tokio::fs::File::open(&path).await.unwrap();
        let body = export_body(file, 4 << 20, slot, std::time::Duration::from_millis(200));
        let got = axum::body::to_bytes(body, 8 << 20).await.unwrap();
        assert_eq!(got.len(), 4 << 20);
        assert!(gate.begin_export().is_some(), "the slot goes back when it ends");
    }

    /// README §2 Bounded (final check, round 3): a job leaves its own size free, within the
    /// floor and the cap.
    #[test]
    fn margins_follow_the_job() {
        let m = (DISK_MARGIN_FLOOR, DISK_MARGIN);
        assert_eq!(margin_for(50 * 1024, m), DISK_MARGIN_FLOOR);
        assert_eq!(margin_for(300 << 20, m), 300 << 20);
        assert_eq!(margin_for(2 << 30, m), DISK_MARGIN);
        assert_eq!(
            margin_for(0, (u64::MAX / 4, 1)),
            u64::MAX / 4,
            "a floor past the cap wins"
        );
    }

    #[test]
    fn rows_round_trip_blobs() {
        let v = json!({"b64": "AAEC"});
        assert_eq!(
            sql_value(&v).unwrap(),
            rusqlite::types::Value::Blob(vec![0, 1, 2])
        );
        assert_eq!(sql_value(&json!(3)).unwrap(), rusqlite::types::Value::Integer(3));
    }
}
