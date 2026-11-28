//! Compiled-in schemas of `core.db` and `metrics.db` (storage.md §3, §5).
//!
//! **Adding a table or column:** append a new `&str` to [`CORE`] (or [`METRICS`]); never edit a
//! released step. Each step runs once, in order, inside the file's migration transaction, and
//! `PRAGMA user_version` becomes the step count. Release N must read what N−1 stored (README §2,
//! Compatibility), so steps only add (tables, nullable or defaulted columns, indexes) or move
//! data forward.
//!
//! Timestamps are TEXT in RFC 3339 with microseconds and `Z` (`util::ts`), which sorts in time
//! order. `metrics.db` keeps `ts` as INTEGER Unix milliseconds for cheap binning.

/// `core.db` migration steps; version = index + 1.
pub const CORE: &[&str] = &[CORE_V1, CORE_V2, CORE_V3, CORE_V4, CORE_V5];

/// `metrics.db` migration steps; version = index + 1.
pub const METRICS: &[&str] = &[METRICS_V1, METRICS_V2];

const CORE_V1: &str = r#"
-- Configuration ---------------------------------------------------------------------------
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
) STRICT;

CREATE TABLE ui_account (
    name TEXT PRIMARY KEY,
    password_argon2id TEXT NOT NULL,
    changed_at TEXT NOT NULL
) STRICT;

CREATE TABLE edges (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    key_sha256 TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL,
    settings_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

-- claimed_name: the CN of the unknown key's certificate (core.md §4: "claimed name").
CREATE TABLE edge_pending (
    key_sha256 TEXT PRIMARY KEY,
    addr TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    claimed_name TEXT
) STRICT;
CREATE INDEX edge_pending_last_seen ON edge_pending(last_seen);

-- ips_json and limits_json carry the EdgeConfig listener fields of the same name (api.md §4).
CREATE TABLE listeners (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    proto TEXT NOT NULL,
    bind TEXT NOT NULL,
    interfaces_json TEXT NOT NULL DEFAULT '[]',
    tls_json TEXT,
    api INTEGER NOT NULL DEFAULT 0,
    ips_json TEXT NOT NULL DEFAULT '[]',
    limits_json TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE TABLE listener_edges (
    listener_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    PRIMARY KEY (listener_id, edge_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX listener_edges_edge ON listener_edges(edge_id);

CREATE TABLE clients (
    name TEXT PRIMARY KEY,
    position INTEGER NOT NULL,
    macs_json TEXT NOT NULL DEFAULT '[]',
    source_ips_json TEXT NOT NULL DEFAULT '[]',
    profile TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]'
) STRICT;
CREATE INDEX clients_position ON clients(position);

CREATE TABLE profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    system INTEGER NOT NULL DEFAULT 0,
    body_json TEXT NOT NULL
) STRICT;

CREATE TABLE upstreams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    tls_host TEXT,
    path TEXT,
    trust_store_pem TEXT,
    operator TEXT
) STRICT;

CREATE TABLE upstream_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    strategy TEXT NOT NULL,
    optimistic INTEGER NOT NULL,
    members_json TEXT NOT NULL
) STRICT;

CREATE TABLE forward_zones (
    id TEXT PRIMARY KEY,
    zone TEXT NOT NULL,
    group_id TEXT NOT NULL,
    fallback TEXT NOT NULL
) STRICT;

-- Feed providers (providers.md §2): configured instances of download modules.
CREATE TABLE feed_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    system INTEGER NOT NULL DEFAULT 0,
    module TEXT NOT NULL,
    config_json TEXT NOT NULL,
    trigger_json TEXT NOT NULL,
    files_json TEXT NOT NULL DEFAULT '[]',
    exclude_json TEXT NOT NULL DEFAULT '[]'
) STRICT;

-- provider_id and file are null for a manual feed (feeds.md §1); a provider's feeds name
-- distinct files.
CREATE TABLE feeds (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    provider_id TEXT,
    file TEXT,
    format TEXT NOT NULL,
    format_options_json TEXT NOT NULL,
    modes_json TEXT NOT NULL,
    rule_policy_json TEXT NOT NULL,
    sanity_json TEXT NOT NULL,
    warn_on_json TEXT
) STRICT;
CREATE UNIQUE INDEX feeds_provider_file ON feeds(provider_id, file) WHERE provider_id IS NOT NULL;

CREATE TABLE manual_files (
    feed_id TEXT PRIMARY KEY,
    blob TEXT NOT NULL,
    version TEXT NOT NULL,
    saved_at TEXT NOT NULL
) STRICT;

CREATE TABLE bundles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    system INTEGER NOT NULL DEFAULT 0,
    "action" TEXT NOT NULL,
    max_shard_keys INTEGER NOT NULL,
    hot_max_mib INTEGER
) STRICT;

-- position keeps the bundle definition's feed order.
CREATE TABLE bundle_feeds (
    bundle_id TEXT NOT NULL,
    feed_id TEXT NOT NULL,
    rule_types_json TEXT,
    tier TEXT NOT NULL DEFAULT 'hot',
    position INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bundle_id, feed_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX bundle_feeds_feed ON bundle_feeds(feed_id);

CREATE TABLE lookup_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    module TEXT NOT NULL,
    config_json TEXT NOT NULL,
    sync_timeout_ms INTEGER NOT NULL,
    async_timeout_ms INTEGER NOT NULL,
    fail_mode TEXT NOT NULL,
    retries INTEGER NOT NULL,
    recheck_json TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    cache_json TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    breaker_json TEXT NOT NULL,
    async_max_attempts INTEGER NOT NULL,
    category TEXT NOT NULL,
    cache_generation TEXT NOT NULL,
    preset_json TEXT,
    last_self_test_json TEXT
) STRICT;

-- value_enc: XChaCha20-Poly1305 when secrets.key exists, else the plain value with a marker
-- byte (config::secrets).
CREATE TABLE secrets (
    name TEXT PRIMARY KEY,
    value_enc BLOB NOT NULL
) STRICT;

CREATE TABLE config_changes (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    source_ip TEXT,
    entity TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    diff_json TEXT NOT NULL
) STRICT;
CREATE INDEX config_changes_at ON config_changes(at);

-- Feeds -------------------------------------------------------------------------------------
CREATE TABLE feed_runs (
    id INTEGER PRIMARY KEY,
    feed_id TEXT NOT NULL,
    version TEXT,
    updated_at TEXT,
    downloaded_at TEXT,
    confirmed_at TEXT,
    blob TEXT,
    status TEXT NOT NULL,
    added_json TEXT,
    removed_json TEXT,
    total_json TEXT,
    policy_dropped_json TEXT,
    error TEXT
) STRICT;
CREATE INDEX feed_runs_feed ON feed_runs(feed_id, id);

-- value_json is NOT NULL DEFAULT '' so the partial unique index holds at most one open row per
-- entry (NULLs would compare distinct).
CREATE TABLE feed_entries (
    id INTEGER PRIMARY KEY,
    feed_id TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    key TEXT NOT NULL,
    kind TEXT NOT NULL,
    flags INTEGER NOT NULL DEFAULT 0,
    value_json TEXT NOT NULL DEFAULT '',
    raw TEXT NOT NULL,
    line_no INTEGER,
    first_run INTEGER NOT NULL,
    last_seen_run INTEGER NOT NULL,
    removed_run INTEGER,
    last_seen_at TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    dropped_at TEXT,
    ip_first BLOB,
    ip_last BLOB
) STRICT;
CREATE INDEX feed_entries_lookup ON feed_entries(feed_id, rule_type, key);
CREATE UNIQUE INDEX feed_entries_open
    ON feed_entries(feed_id, rule_type, key, kind, flags, value_json) WHERE removed_run IS NULL;
CREATE INDEX feed_entries_key ON feed_entries(key);
CREATE INDEX feed_entries_ip ON feed_entries(rule_type, ip_first);
CREATE INDEX feed_entries_removed ON feed_entries(removed_run) WHERE removed_run IS NOT NULL;

CREATE TABLE feed_entry_undo (
    run_id INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    prior_json TEXT NOT NULL,
    PRIMARY KEY (run_id, entry_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE feed_state (
    feed_id TEXT PRIMARY KEY,
    last_json TEXT,
    learner_json TEXT,
    next_check_at TEXT
) STRICT;

-- One row per check of a feed provider (feed-scheduling.md §6), with what started it.
CREATE TABLE feed_provider_checks (
    id INTEGER PRIMARY KEY,
    provider_id TEXT NOT NULL,
    t TEXT NOT NULL,
    cause TEXT NOT NULL,
    duration_ms INTEGER,
    ok INTEGER NOT NULL,
    error TEXT
) STRICT;
CREATE INDEX feed_provider_checks_provider ON feed_provider_checks(provider_id, t);
CREATE INDEX feed_provider_checks_t ON feed_provider_checks(t);

CREATE TABLE feed_checks (
    id INTEGER PRIMARY KEY,
    provider_check_id INTEGER,
    feed_id TEXT NOT NULL,
    t TEXT NOT NULL,
    duration_ms INTEGER,
    method TEXT,
    ok INTEGER NOT NULL,
    changed INTEGER,
    bytes INTEGER,
    ref TEXT,
    predicted_rate REAL,
    error TEXT
) STRICT;
CREATE INDEX feed_checks_feed ON feed_checks(feed_id, t);
CREATE INDEX feed_checks_t ON feed_checks(t);

CREATE TABLE feed_changes (
    id INTEGER PRIMARY KEY,
    feed_id TEXT NOT NULL,
    check_id INTEGER,
    t_change TEXT,
    exact INTEGER,
    t_lo TEXT,
    t_seen TEXT NOT NULL,
    origin TEXT
) STRICT;
CREATE INDEX feed_changes_feed ON feed_changes(feed_id, t_seen);
CREATE INDEX feed_changes_t ON feed_changes(t_seen);

CREATE TABLE warnings (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    by_bundle_id TEXT,
    by_feed_id TEXT,
    value TEXT NOT NULL,
    feed_id TEXT,
    raw TEXT,
    bundle_id TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL
) STRICT;
CREATE INDEX warnings_bundle ON warnings(bundle_id, status);
CREATE INDEX warnings_status ON warnings(status, last_seen);

CREATE TABLE policy_drops (
    id INTEGER PRIMARY KEY,
    feed_id TEXT NOT NULL,
    option TEXT NOT NULL,
    raw TEXT NOT NULL,
    first_run INTEGER NOT NULL,
    last_seen_run INTEGER NOT NULL,
    status TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX policy_drops_rule ON policy_drops(feed_id, raw);

-- Bundles -----------------------------------------------------------------------------------
CREATE TABLE bundle_keys (
    bundle_id TEXT NOT NULL,
    part TEXT NOT NULL,
    shard INTEGER NOT NULL,
    hash128 BLOB NOT NULL,
    key TEXT NOT NULL,
    value ANY
) STRICT;
CREATE INDEX bundle_keys_shard ON bundle_keys(bundle_id, part, shard, key);
CREATE INDEX bundle_keys_key ON bundle_keys(bundle_id, key);

CREATE TABLE bundle_shards (
    bundle_id TEXT NOT NULL,
    part TEXT NOT NULL,
    shard INTEGER NOT NULL,
    prefix INTEGER,
    prefix_bits INTEGER,
    base_blake3 TEXT,
    base_seq INTEGER,
    seq INTEGER,
    overlay_bytes INTEGER,
    created_at TEXT,
    PRIMARY KEY (bundle_id, part, shard)
) STRICT, WITHOUT ROWID;

CREATE TABLE bundle_key_hits (
    bundle_id TEXT NOT NULL,
    hash128 BLOB NOT NULL,
    last_hit_at TEXT NOT NULL,
    PRIMARY KEY (bundle_id, hash128)
) STRICT, WITHOUT ROWID;

CREATE TABLE bundle_ip_ranges (
    bundle_id TEXT NOT NULL,
    ip_shard TEXT NOT NULL,
    "first" BLOB NOT NULL,
    "last" BLOB NOT NULL,
    value ANY
) STRICT;
CREATE INDEX bundle_ip_ranges_first ON bundle_ip_ranges(bundle_id, ip_shard, "first");

CREATE TABLE bundle_ip_shards (
    bundle_id TEXT NOT NULL,
    ip_shard TEXT NOT NULL,
    base_blake3 TEXT,
    base_seq INTEGER,
    seq INTEGER,
    overlay_bytes INTEGER,
    created_at TEXT,
    PRIMARY KEY (bundle_id, ip_shard)
) STRICT, WITHOUT ROWID;

CREATE TABLE bundle_versions (
    bundle_id TEXT NOT NULL,
    head_id TEXT NOT NULL,
    heads_json TEXT NOT NULL,
    feed_runs_json TEXT NOT NULL,
    definition_hash TEXT NOT NULL,
    published_at TEXT NOT NULL,
    stats_json TEXT,
    browser_list_blake3 TEXT,
    PRIMARY KEY (bundle_id, head_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX bundle_versions_published ON bundle_versions(bundle_id, published_at);

CREATE TABLE blobs (
    blake3 TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    refcount INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;
CREATE INDEX blobs_unreferenced ON blobs(refcount, created_at);

-- Edges, logs, work -------------------------------------------------------------------------
CREATE TABLE edge_status (
    edge_id TEXT PRIMARY KEY,
    last_seen TEXT,
    versions_json TEXT,
    previous_versions_json TEXT,
    conditions_json TEXT,
    heartbeat_json TEXT,
    session_addr TEXT,
    update_result_json TEXT
) STRICT;

CREATE TABLE edge_configs (
    config_id TEXT PRIMARY KEY,
    edge_id TEXT NOT NULL,
    published_at TEXT NOT NULL,
    body_json TEXT NOT NULL
) STRICT;
CREATE INDEX edge_configs_edge ON edge_configs(edge_id, published_at);

CREATE TABLE edge_boots (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    edge_version TEXT,
    first_seen TEXT NOT NULL,
    superseded_at TEXT,
    PRIMARY KEY (edge_id, boot)
) STRICT, WITHOUT ROWID;

CREATE TABLE edge_events (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    result_id TEXT,
    detail_json TEXT,
    PRIMARY KEY (edge_id, boot, seq)
) STRICT;
CREATE INDEX edge_events_at ON edge_events(at);
CREATE INDEX edge_events_edge_at ON edge_events(edge_id, at);
CREATE UNIQUE INDEX edge_events_result ON edge_events(edge_id, result_id) WHERE result_id IS NOT NULL;

CREATE TABLE edge_releases (
    version TEXT NOT NULL,
    arch TEXT NOT NULL,
    blob TEXT NOT NULL,
    minisig TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (version, arch)
) STRICT, WITHOUT ROWID;

-- provider is '' for requests that aren't per provider, so the key stays NOT NULL.
CREATE TABLE edge_requests (
    edge_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL,
    version TEXT,
    blake3 TEXT,
    requested_at TEXT NOT NULL,
    PRIMARY KEY (edge_id, kind, provider)
) STRICT, WITHOUT ROWID;

CREATE TABLE temp_allows (
    edge_id TEXT NOT NULL,
    allow_id TEXT NOT NULL,
    client TEXT,
    device TEXT,
    kind TEXT,
    target TEXT,
    created_at TEXT,
    expires_at TEXT,
    ended_at TEXT,
    revoke_requested_at TEXT,
    revoke_acked_at TEXT,
    PRIMARY KEY (edge_id, allow_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX temp_allows_ended ON temp_allows(ended_at);

-- AUTOINCREMENT: an id is never reused, so nothing kept under a deleted alert's id (evidence, a
-- capture in flight) can ever reach a new alert (core.md §9 "Kept until deleted").
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    details_json TEXT NOT NULL,
    edge_id TEXT,
    feed_provider_id TEXT,
    feed_id TEXT,
    bundle_id TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL,
    state TEXT NOT NULL,
    -- 1 once a record-raised alert was seen on more than one edge: edge_id stays null (core.md §9).
    several_edges INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX alerts_state ON alerts(state, last_seen);
CREATE INDEX alerts_kind ON alerts(kind, last_seen);
CREATE INDEX alerts_last_seen ON alerts(last_seen);

CREATE TABLE alert_history (
    id INTEGER PRIMARY KEY,
    alert_id INTEGER NOT NULL,
    at TEXT NOT NULL,
    change TEXT NOT NULL,
    detail_json TEXT
) STRICT;
CREATE INDEX alert_history_alert ON alert_history(alert_id, id);

CREATE TABLE alert_evidence (
    id INTEGER PRIMARY KEY,
    alert_id INTEGER NOT NULL,
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE INDEX alert_evidence_alert ON alert_evidence(alert_id, ts);
-- The evidence view pages an alert's copies by id, newest stored first (core.md §12).
CREATE INDEX alert_evidence_alert_id ON alert_evidence(alert_id, id);
CREATE UNIQUE INDEX alert_evidence_record ON alert_evidence(alert_id, edge_id, boot, seq);

CREATE TABLE alert_evidence_counts (
    alert_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (alert_id, kind, key)
) STRICT, WITHOUT ROWID;

CREATE TABLE wire_examples (
    id INTEGER PRIMARY KEY,
    alert_id INTEGER NOT NULL,
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    record_json TEXT NOT NULL,
    wire BLOB,
    decoded_json TEXT,
    at TEXT NOT NULL
) STRICT;
CREATE INDEX wire_examples_alert ON wire_examples(alert_id);

CREATE TABLE alert_evidence_answers (
    alert_id INTEGER NOT NULL,
    answer_id TEXT NOT NULL,
    source TEXT NOT NULL,
    wire BLOB NOT NULL,
    PRIMARY KEY (alert_id, answer_id, source)
) STRICT, WITHOUT ROWID;

CREATE TABLE lookup_queue (
    provider_id TEXT NOT NULL,
    name TEXT NOT NULL,
    reason TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at TEXT NOT NULL,
    context_json TEXT,
    PRIMARY KEY (provider_id, name)
) STRICT, WITHOUT ROWID;
CREATE INDEX lookup_queue_next ON lookup_queue(next_at);

CREATE TABLE lookup_verdicts (
    provider_id TEXT NOT NULL,
    name TEXT NOT NULL,
    verdict TEXT,
    score REAL,
    reason TEXT,
    detail_json TEXT,
    obtained_at TEXT NOT NULL,
    generation TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (provider_id, name)
) STRICT, WITHOUT ROWID;

-- id: AUTOINCREMENT, never reused, so a Block check that began before its Block was deleted (a
-- flush, a restore) can never mark or alert for another one that took its id.
CREATE TABLE lookup_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    name TEXT NOT NULL,
    obtained_at TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT,
    detail_json TEXT
) STRICT;
CREATE UNIQUE INDEX lookup_blocks_dedupe ON lookup_blocks(provider_id, name, obtained_at);
CREATE INDEX lookup_blocks_name ON lookup_blocks(name);
CREATE INDEX lookup_blocks_obtained ON lookup_blocks(obtained_at);

CREATE TABLE verdict_sets (
    provider_id TEXT NOT NULL,
    head_id TEXT NOT NULL,
    generation TEXT NOT NULL,
    published_at TEXT NOT NULL,
    PRIMARY KEY (provider_id, head_id)
) STRICT, WITHOUT ROWID;

-- kind: `answer` (a logged answer), `fallback` (core's own query) or `servfail` (an upstream
-- SERVFAIL's query, never retried); edge_id: the edge whose record admitted it (its share of the
-- queue's cap, README §2 Bounded).
CREATE TABLE dnssec_queue (
    id INTEGER PRIMARY KEY,
    answer_id TEXT,
    received_at TEXT,
    wire BLOB,
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at TEXT NOT NULL,
    context_json TEXT,
    kind TEXT NOT NULL DEFAULT 'answer',
    edge_id TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX dnssec_queue_next ON dnssec_queue(next_at);
CREATE INDEX dnssec_queue_answer ON dnssec_queue(answer_id, received_at);
CREATE INDEX dnssec_queue_name ON dnssec_queue(qname, qtype) WHERE answer_id IS NULL;
CREATE INDEX dnssec_queue_edge ON dnssec_queue(edge_id);

CREATE TABLE dnssec_results (
    id INTEGER PRIMARY KEY,
    answer_id TEXT,
    received_at TEXT,
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    at TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT
) STRICT;
CREATE INDEX dnssec_results_at ON dnssec_results(at);
CREATE INDEX dnssec_results_answer ON dnssec_results(answer_id, received_at);
CREATE INDEX dnssec_results_name ON dnssec_results(qname, qtype, at) WHERE answer_id IS NULL;

CREATE TABLE crosscheck_queue (
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    "check" TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at TEXT NOT NULL,
    context_json TEXT,
    edge_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (qname, qtype)
) STRICT, WITHOUT ROWID;
CREATE INDEX crosscheck_queue_next ON crosscheck_queue(next_at);

CREATE TABLE crosscheck_seen (
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    at TEXT NOT NULL,
    PRIMARY KEY (qname, qtype)
) STRICT, WITHOUT ROWID;
CREATE INDEX crosscheck_seen_at ON crosscheck_seen(at);
"#;

/// Edge API (api.md §2–§4, core.md §4, storage.md §4): the hello an edge's last session sent,
/// convergence tracking, pins, published-config use, and the order of temporary-allow records.
const CORE_V2: &str = r#"
-- hello_json: the last hello's release, architecture, firmware (and when it last changed),
-- allowed_binds and boot, so a restarted core renders the release offer before the edge's
-- next session (core.md §5).
ALTER TABLE edge_status ADD COLUMN hello_json TEXT;

-- last_used_at: when an edge last reported the config as active or previous (retention: the
-- query-log window after the last edge stopped using it, storage.md §4); served_seq: the order
-- in which core last served it, so a have report's `fetched` ends the pins of objects served
-- before it (storage.md §4 Pins).
ALTER TABLE edge_configs ADD COLUMN last_used_at TEXT;
ALTER TABLE edge_configs ADD COLUMN served_seq INTEGER;

-- updated_at: the event time of the last allow record applied, so a repeated or late record
-- never undoes a newer one (delivery is at-least-once, edge.md §11).
ALTER TABLE temp_allows ADD COLUMN updated_at TEXT;

-- The versions core names in each edge's config object, with when it first named each there
-- and the first heartbeat that showed it active (convergence_lag_s, core.md §10). kind is
-- config, bundle or verdict_set; target is '' for the config, else the bundle or provider id.
CREATE TABLE edge_named (
    edge_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    id TEXT NOT NULL,
    named_at TEXT NOT NULL,
    active_at TEXT,
    PRIMARY KEY (edge_id, kind, target)
) STRICT, WITHOUT ROWID;

-- Pins (storage.md §4): what an object core served an edge names (config, bundle heads,
-- verdict-set heads), kept until a have report whose `fetched` was served at or after
-- served_seq no longer lists it.
CREATE TABLE edge_pins (
    edge_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    id TEXT NOT NULL,
    served_seq INTEGER NOT NULL,
    pinned_at TEXT NOT NULL,
    PRIMARY KEY (edge_id, kind, target, id)
) STRICT, WITHOUT ROWID;
CREATE INDEX edge_pins_id ON edge_pins(kind, target, id);

CREATE INDEX edge_boots_edge ON edge_boots(edge_id, first_seen);
CREATE INDEX edge_boots_superseded ON edge_boots(superseded_at);
CREATE INDEX edge_events_kind ON edge_events(edge_id, kind, at);
CREATE INDEX edge_configs_used ON edge_configs(last_used_at);

-- Query records whose ts was clamped from a later hour (core.md §6): the hour of their first
-- attempt, as disjoint runs of seqs per boot (every q record of the boot with a seq in lo..=hi
-- whose ts is in a later hour goes to hour), so every retry goes to the same partition and
-- (edge, boot, seq) dedupes it. A capped number of runs per edge (README §2, Bounded). Kept as
-- long as that hour's partition (storage.md §4).
CREATE TABLE log_clamped (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    lo INTEGER NOT NULL,
    hi INTEGER NOT NULL,
    hour TEXT NOT NULL,
    PRIMARY KEY (edge_id, boot, lo)
) STRICT, WITHOUT ROWID;
CREATE INDEX log_clamped_hour ON log_clamped(hour);

-- An edge's temporary allows (its share of the table, README §2 Bounded).
CREATE INDEX temp_allows_edge ON temp_allows(edge_id, updated_at);

-- An edge's open condition alerts, and each edge's share of an alert kind (core.md §9; README §2
-- capped shares).
CREATE INDEX alerts_edge_state ON alerts(edge_id, state);
CREATE INDEX alerts_kind_edge ON alerts(kind, edge_id);
"#;

/// Feeds (feeds.md, feed-scheduling.md, providers.md §2–§3): the per-feed runtime state, run
/// ids that survive a crash, open runs for the start-time undo, run details, and provider
/// pauses after a rate limit.
const CORE_V3: &str = r#"
-- feed_state: the scheduler's durable state per feed. last_check_at: the last check of any
-- outcome (min_interval floor); last_ok_at: the last successful check (the start of an
-- interval change, feed-scheduling.md §3); failures / failing_since: the current streak of
-- failed checks (error backoff, feed_source_down); held_since: when the current hold began
-- (confirm_after, feeds.md §5); expires_s and last_download_at: a list's `! Expires:` and the
-- last full download (cron floor, feeds.md §5).
ALTER TABLE feed_state ADD COLUMN last_check_at TEXT;
ALTER TABLE feed_state ADD COLUMN last_ok_at TEXT;
ALTER TABLE feed_state ADD COLUMN failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE feed_state ADD COLUMN failing_since TEXT;
ALTER TABLE feed_state ADD COLUMN held_since TEXT;
ALTER TABLE feed_state ADD COLUMN expires_s INTEGER;
ALTER TABLE feed_state ADD COLUMN last_download_at TEXT;
-- source_gen: the feed's source generation, a new id from feed_run_ids (never reused) each time
-- the feed is created or its provider or provider_config changes. A check or run stores what it
-- observed only while the generation it started with is current, so a check in flight across an
-- edit or a deletion never writes the old source's state into the feed (feeds.md §3 "Editing a
-- feed"; storage.md §4).
ALTER TABLE feed_state ADD COLUMN source_gen INTEGER;
-- next_ask_at: the feed model's ask (feed-scheduling.md §5); epoch_at: when the feed last came
-- to point at another file (§4); seen_blake3: the content hash of its last download in the epoch
-- (§3); stale_ref_json: the staleness reference frozen at its last change (§8); warm_started_at:
-- when the epoch's warm start was read (§6); warm_span_at: the start of the span that warm start
-- read (its first `bootstrap` check, often before epoch_at), so rebuilds keep it (§4, §6).
ALTER TABLE feed_state ADD COLUMN next_ask_at TEXT;
ALTER TABLE feed_state ADD COLUMN epoch_at TEXT;
ALTER TABLE feed_state ADD COLUMN seen_blake3 TEXT;
ALTER TABLE feed_state ADD COLUMN stale_ref_json TEXT;
ALTER TABLE feed_state ADD COLUMN warm_started_at TEXT;
ALTER TABLE feed_state ADD COLUMN warm_span_at TEXT;
-- added_pending: a feed core created for a selected file whose `feed_added` isn't raised yet
-- (raised and cleared in one transaction, feeds.md §1).
ALTER TABLE feed_state ADD COLUMN added_pending INTEGER NOT NULL DEFAULT 0;

-- One row per feed provider (providers.md §2, feed-scheduling.md): the module's state for the
-- provider and its latest listing; next_check_at and due_cause (trigger, sqs, backstop,
-- check_now, first, edit); nudged_at: the newest SQS nudge; k: the aggressiveness; the trigger's
-- own state (sqs: last receive, message and errors, the recent message ids); source_gen as for
-- feeds; last_check_at (min_interval), last_ok_at; failing_since: the current streak of checks
-- that failed as a whole or in every file (feed_provider_down); check_started_at: the running
-- check's start (a nudge after it makes the provider due again); skipped_json: selected files
-- left without a feed past feeds.max_per_provider (feeds.md §1); list_gen: the selection
-- generation, a new id each time `module`, `config`, `files` or `exclude` changes, so a check
-- that listed for an older selection stores no provider state or listing and adds no feeds.
CREATE TABLE feed_provider_state (
    provider_id TEXT PRIMARY KEY,
    state_json TEXT,
    listing_json TEXT,
    next_check_at TEXT,
    due_cause TEXT,
    nudged_at TEXT,
    k REAL,
    trigger_state_json TEXT,
    source_gen INTEGER,
    last_check_at TEXT,
    last_ok_at TEXT,
    failing_since TEXT,
    check_started_at TEXT,
    skipped_json TEXT,
    list_gen INTEGER
) STRICT;

-- feed_runs: kind (download, reingest, expire), the ingest parameters a run used (format,
-- format_options, modes, rule_policy), the parse summary (errors and samples, warnings,
-- `! Expires:`), and the gate that held or rejected it.
ALTER TABLE feed_runs ADD COLUMN kind TEXT;
ALTER TABLE feed_runs ADD COLUMN params_json TEXT;
ALTER TABLE feed_runs ADD COLUMN parse_json TEXT;
ALTER TABLE feed_runs ADD COLUMN gate TEXT;
CREATE INDEX feed_runs_blob ON feed_runs(blob);
-- source_run: for a run that applied a held or rejected download (a confirmation or a re-gate),
-- the id that download had while it waited. The applied run takes a new id, so run ids follow
-- the order runs changed the feed's entries (replay's `first_run <= r < removed_run`,
-- storage.md §3), and the waiting row moves to it.
ALTER TABLE feed_runs ADD COLUMN source_run INTEGER;
-- policy_drops.resolved_at: when the rule left the feed; resolved rows age out like resolved
-- warnings (storage.md §4).
ALTER TABLE policy_drops ADD COLUMN resolved_at TEXT;

-- Run ids are never reused, even after a crash (AUTOINCREMENT); a run that writes entries is
-- open until its feed_runs row is final, and the start-time undo reverts open runs (feeds.md
-- §3 step 4).
CREATE TABLE feed_run_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id TEXT NOT NULL,
    at TEXT NOT NULL
) STRICT;
CREATE TABLE feed_runs_open (
    run_id INTEGER PRIMARY KEY,
    feed_id TEXT NOT NULL,
    started_at TEXT NOT NULL
) STRICT;
CREATE INDEX feed_entries_first_run ON feed_entries(first_run);
CREATE INDEX feed_entries_dropped ON feed_entries(feed_id, dropped_at)
    WHERE dropped_at IS NOT NULL AND removed_run IS NULL;
CREATE INDEX policy_drops_feed ON policy_drops(feed_id, status);
CREATE INDEX feed_changes_check ON feed_changes(check_id);
CREATE INDEX feed_checks_provider_check ON feed_checks(provider_check_id);

-- After a `RateLimited` reply no check through the module starts until `until` (providers.md §2).
CREATE TABLE module_pauses (
    module TEXT PRIMARY KEY,
    until TEXT NOT NULL
) STRICT;

-- Imports merged into provider feeds that were accepted and aren't stored as a run yet
-- (feeds.md §4): the blob of the file the import made and what it was checked against (the
-- feed's source generation; its format, format_options and MISP list type in params_json), so a
-- restart or a full heavy lane loses none, and a feed created again or edited since never takes
-- it. The import's run deletes its row in its final transaction. Ids are never reused
-- (AUTOINCREMENT), and every cleanup names (id, feed, source generation), so a queued job of a
-- deleted feed can never remove another feed's import. attempts counts the runs started and the
-- heavy lane's refusals together (the bound); refused counts the refusals alone (the reason a
-- dropped import's rejected run gives).
CREATE TABLE feed_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id TEXT NOT NULL,
    blob TEXT NOT NULL,
    source_gen INTEGER,
    params_json TEXT NOT NULL,
    at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    refused INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX feed_imports_feed ON feed_imports(feed_id, id);

-- A deleted feed's data waiting to be retired (storage.md §4): its open entries are closed under
-- run_id (an id from feed_run_ids, newer than every run of the deleted feed) and its runs move to
-- a tombstone feed id, so a feed created again with the same id starts clean while retained
-- bundle versions can still replay the old entries. Written with the feed's deletion.
CREATE TABLE feed_purges (
    feed_id TEXT PRIMARY KEY,
    run_id INTEGER NOT NULL,
    at TEXT NOT NULL
) STRICT;
"#;

/// The bundle compiler and browser lists (bundles.md §2–§8, storage.md §3–§4): each bundle's
/// build state, the work tables of a build in progress, tiering columns, per-shard bookkeeping,
/// the blobs each version names, and each version's last use (retention).
const CORE_V4: &str = r#"
-- Logs, attribution and the checks that read logged queries (core.md §6, §9; bundles.md §2) -----
-- definition_json: the members of the definition a version was built from, in bundle order, with
-- the rule types and tier taken from each, so replay reads each feed as that version took it.
ALTER TABLE bundle_versions ADD COLUMN definition_json TEXT;

-- When core first saw each applied feed run that added `dns` or `ip` entries (retro-match: an
-- entry counts for answers before it, core.md §6), and the newest run seen.
CREATE TABLE retro_runs (
    run_id INTEGER PRIMARY KEY,
    feed_id TEXT NOT NULL,
    at TEXT NOT NULL
) STRICT;
CREATE INDEX retro_runs_at ON retro_runs(at);

-- How far core's work on each hourly log partition has come (README §2 Restarts): `hour` is the
-- partition's file stem (YYYY-MM-DDTHH), `kind` names the work and `value` its progress, mostly
-- the highest `events` rowid done (rowids only grow in a partition). The progress commits in the
-- same transaction as the work's effects in this database, so a restart repeats and loses none
-- (build-and-test.md §5). Kinds: `analysis` (every record at or below it has had its analysis
-- effects: alerts, key hits, evidence capture, metrics). Partitions are never migrated
-- (storage.md §5), so this works on every log schema. Rows of a deleted partition go with it.
CREATE TABLE log_progress (
    hour TEXT NOT NULL,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL,
    PRIMARY KEY (hour, kind)
) STRICT, WITHOUT ROWID;

-- Retro-match's progress on each hourly partition (core.md §6 Retro-match; logs::retro), committed
-- with its alert effects and metrics: `seen` is the highest events rowid whose names and
-- addresses are in the hour's answered_names/answered_ips (and, after the close, matched as a
-- late record); `closed` is set once the hour closed; `run` is the newest feed run fully matched
-- against the hour; `phase` and `cursor` are the progress inside the next run (`names`, `ips`,
-- `records`, with the last name/profile, address/profile or rowid done). retro_values holds
-- the distinct answered values that run's additions hit, found in the first two phases.
CREATE TABLE retro_progress (
    hour TEXT PRIMARY KEY,
    seen INTEGER NOT NULL DEFAULT 0,
    closed INTEGER NOT NULL DEFAULT 0,
    run INTEGER NOT NULL DEFAULT 0,
    phase TEXT,
    cursor TEXT
) STRICT, WITHOUT ROWID;
CREATE TABLE retro_values (
    hour TEXT NOT NULL,
    run INTEGER NOT NULL,
    profile TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (hour, run, profile, value)
) STRICT, WITHOUT ROWID;

-- Records waiting for a trial bundle that had no built head when core first checked them
-- (core.md §6 Trial bundles): one row per partition rowid and bundle still to check, until a
-- head exists or the hour leaves the window. Bounded (logs::trial::MAX_PENDING); the `bundle`
-- index finds the rows a new head can take without reading the others.
CREATE TABLE trial_pending (
    hour TEXT NOT NULL,
    rowid_ INTEGER NOT NULL,
    bundle TEXT NOT NULL,
    PRIMARY KEY (hour, rowid_, bundle)
) STRICT, WITHOUT ROWID;
CREATE INDEX trial_pending_bundle ON trial_pending(bundle, hour, rowid_);

-- Metric increments committed with the effects that produced them (log analysis, retro-match), so
-- a restart neither repeats nor loses them; moved to metrics.db in order, which records the last
-- id applied (outbox_applied) in the same transaction as the points. bytes: items_json's size;
-- queued_at: when queued (Unix ms). Bounded by rows, bytes and age (metrics::outbox).
CREATE TABLE metric_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bytes INTEGER NOT NULL DEFAULT 0,
    queued_at INTEGER NOT NULL DEFAULT 0,
    items_json TEXT NOT NULL
) STRICT;

-- What later log records an open security alert copies as evidence (core.md §9 Evidence):
-- rule_json names the dedup key's subject (domain, device, feed or provider); copies counts
-- the records copied so far (half the first, half the latest are kept). domain, answers and
-- has_ips repeat the rule's lookup keys (the registrable domain; whether names in a record's
-- answer and its addresses match too), so capture finds a record's rules by index inside its own
-- transaction. backfill_json: the copying of the records already analysed when the rule was
-- made, still to do (null once done): `todo` lists [hour, done rowid, last rowid] per partition,
-- advanced in the same transaction as each step's copies (README §2 Restarts).
CREATE TABLE alert_evidence_rules (
    alert_id INTEGER PRIMARY KEY,
    rule_json TEXT NOT NULL,
    copies INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    domain TEXT NOT NULL DEFAULT '',
    answers INTEGER NOT NULL DEFAULT 0,
    has_ips INTEGER NOT NULL DEFAULT 0,
    backfill_json TEXT
) STRICT;
CREATE INDEX alert_evidence_rules_domain ON alert_evidence_rules(domain);
CREATE INDEX alert_evidence_rules_ips ON alert_evidence_rules(alert_id) WHERE has_ips <> 0;
CREATE INDEX alert_evidence_rules_backfill ON alert_evidence_rules(alert_id) WHERE backfill_json IS NOT NULL;

-- The tiering dry run (bundles.md §2 Tiering): per bundle, the latest replay of the log window
-- against a proposed split, and how many blocks would have come from cold. status: running, done
-- or failed; started_at: when core first saw the proposal (a split waits for its dry run until
-- then plus compiler::tier::DRY_RUN_HOLD); progress_json: a running dry run's position and
-- counts, so a restart resumes it; released_json: the proposal the bundle's builds apply (null:
-- never split, every feed hot).
CREATE TABLE tier_dry_runs (
    bundle_id TEXT PRIMARY KEY,
    definition_hash TEXT NOT NULL,
    proposed_json TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    window_from TEXT,
    window_to TEXT,
    blocks INTEGER,
    cold_blocks INTEGER,
    detail_json TEXT,
    error TEXT,
    progress_json TEXT,
    released_json TEXT
) STRICT;

-- One row per bundle the compiler has built (warn and browser-only bundles included, which
-- publish no edge version): the feed runs and definition hash the last build recorded (start
-- re-derivation, bundles.md §2 "At start"), the head it published (null: no edge bundle), its
-- status (ok, failed) and error, the stats the UI shows, and the tiering cutoffs (bundles.md §2
-- Tiering) and pattern digest the next incremental build continues from.
CREATE TABLE bundle_builds (
    bundle_id TEXT PRIMARY KEY,
    feed_runs_json TEXT NOT NULL DEFAULT '{}',
    definition_hash TEXT NOT NULL DEFAULT '',
    head_id TEXT,
    built_at TEXT,
    status TEXT NOT NULL DEFAULT 'ok',
    error TEXT,
    failed_at TEXT,
    stats_json TEXT,
    state_json TEXT
) STRICT;

-- The keys a build in progress recomputes (bundles.md §2 "Changed keys"), and what it computed
-- for them: the old and new (part, shard, value) of each key whose compiled state changes. Scratch:
-- emptied when the build ends and at start (README §2 Restarts).
CREATE TABLE bundle_build_keys (
    bundle_id TEXT NOT NULL,
    key TEXT NOT NULL,
    PRIMARY KEY (bundle_id, key)
) STRICT, WITHOUT ROWID;

CREATE TABLE bundle_build_ops (
    bundle_id TEXT NOT NULL,
    key TEXT NOT NULL,
    hash128 BLOB NOT NULL,
    old_part TEXT,
    old_shard INTEGER,
    old_value INTEGER,
    new_part TEXT,
    new_shard INTEGER,
    new_value INTEGER,
    tier TEXT,
    rank_at TEXT,
    PRIMARY KEY (bundle_id, key)
) STRICT, WITHOUT ROWID;
CREATE INDEX bundle_build_ops_new ON bundle_build_ops(bundle_id, new_part, new_shard, key);
CREATE INDEX bundle_build_ops_old ON bundle_build_ops(bundle_id, old_part, old_shard, key);

-- Tiering (bundles.md §1, §2 Tiering): a cold-eligible key's hottest feed tier (hot, cold or
-- intelligent-tiering; null for keys that always stay hot) and its rank time (the earliest
-- first_seen_at among its intelligent-tiering feeds).
ALTER TABLE bundle_keys ADD COLUMN tier TEXT;
ALTER TABLE bundle_keys ADD COLUMN rank_at TEXT;
CREATE INDEX bundle_keys_rich ON bundle_keys(bundle_id, value) WHERE (value & 256) <> 0;
CREATE INDEX bundle_keys_tier ON bundle_keys(bundle_id, tier) WHERE tier IS NOT NULL;
CREATE INDEX bundle_keys_hash_it ON bundle_keys(bundle_id, hash128) WHERE tier = 'intelligent-tiering';

-- Per-shard bookkeeping: keys, the base's in-memory and on-disk bytes on the edge, its set
-- checksum, the overlay entries its delta chain holds, and its chain length (compaction,
-- bundles.md §5; budgets, edge.md §17).
ALTER TABLE bundle_shards ADD COLUMN keys INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bundle_shards ADD COLUMN mem_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bundle_shards ADD COLUMN disk_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bundle_shards ADD COLUMN overlay_entries INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bundle_shards ADD COLUMN deltas INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bundle_ip_shards ADD COLUMN runs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bundle_ip_shards ADD COLUMN mem_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bundle_ip_shards ADD COLUMN overlay_entries INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bundle_ip_shards ADD COLUMN deltas INTEGER NOT NULL DEFAULT 0;

-- The blobs each bundle version names (its head, every base and its files, every delta and
-- segment): a blob is collected once no retained version names it (storage.md §4).
CREATE TABLE bundle_version_blobs (
    bundle_id TEXT NOT NULL,
    head_id TEXT NOT NULL,
    blake3 TEXT NOT NULL,
    PRIMARY KEY (bundle_id, head_id, blake3)
) STRICT, WITHOUT ROWID;
CREATE INDEX bundle_version_blobs_blob ON bundle_version_blobs(blake3);

-- last_used_at: when retention last saw the version in use (current, pinned, or active or
-- previous on an edge); a version no edge ran ages from when it stopped being current.
ALTER TABLE bundle_versions ADD COLUMN last_used_at TEXT;
ALTER TABLE bundle_versions ADD COLUMN superseded_at TEXT;

-- What every build reads in full besides the changed keys (bundles.md §2): a feed's rules other
-- than plain names (patterns, regexes, IP rules, `$badfilter`, host mappings, browser rules), its
-- `$dnsrewrite` and `$denyallow` entity rules (urlfilter's rewrite order and the entity cap are
-- bundle-wide), and its exceptions (cross-feed cancellations). Queries repeat each index's WHERE
-- term so SQLite uses it.
CREATE INDEX feed_entries_special ON feed_entries(feed_id, kind) WHERE kind <> 'name';
CREATE INDEX feed_entries_rewrite ON feed_entries(feed_id) WHERE instr(value_json, '"dnsrewrite"') > 0;
CREATE INDEX feed_entries_entity ON feed_entries(feed_id) WHERE instr(value_json, '"denyallow_entities"') > 0;
CREATE INDEX feed_entries_allow ON feed_entries(feed_id) WHERE (flags & 204) <> 0;

-- The blobs a build in progress wrote or names (bundles.md §2 step 6; storage.md §4): each is
-- registered in `blobs` before its file moves into the store, and retention never collects a blob
-- a row here names. Scratch like the other work tables: emptied when the build ends (its commit
-- registers what the version names) and at start, after which retention collects what no version
-- names (README §2 Restarts).
CREATE TABLE bundle_build_blobs (
    bundle_id TEXT NOT NULL,
    blake3 TEXT NOT NULL,
    PRIMARY KEY (bundle_id, blake3)
) STRICT, WITHOUT ROWID;
CREATE INDEX bundle_build_blobs_blob ON bundle_build_blobs(blake3);

-- A fresh build's keys (no published head, or one in another format), staged here until its
-- commit swaps them into bundle_keys, so readers (the next build, browser lists) never see a
-- partial table (README §2 Restarts; bundles.md §8). Scratch like the other work tables.
CREATE TABLE bundle_build_fresh (
    bundle_id TEXT NOT NULL,
    part TEXT NOT NULL,
    shard INTEGER NOT NULL,
    hash128 BLOB NOT NULL,
    key TEXT NOT NULL,
    value INTEGER NOT NULL,
    tier TEXT,
    rank_at TEXT,
    PRIMARY KEY (bundle_id, key)
) STRICT, WITHOUT ROWID;
CREATE INDEX bundle_build_fresh_shard ON bundle_build_fresh(bundle_id, part, shard, key);

-- A build's IP rules (bundles.md §2 step 4), staged so the IP pass folds them a page at a time in
-- address order (core.md §3: bounded steps): fam 0 = IPv4, 1 = IPv6; first/last as 16-byte
-- big-endian addresses of the family. Scratch like the other work tables.
CREATE TABLE bundle_build_ip_rules (
    bundle_id TEXT NOT NULL,
    fam INTEGER NOT NULL,
    "first" BLOB NOT NULL,
    "last" BLOB NOT NULL,
    entry_id INTEGER NOT NULL,
    feed_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    line_no INTEGER NOT NULL,
    rule_type TEXT NOT NULL,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    flags INTEGER NOT NULL,
    value_json TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (bundle_id, fam, "first", "last", entry_id)
) STRICT, WITHOUT ROWID;

-- The new runs of each IP shard a build changes, until its commit replaces the shard's
-- bundle_ip_ranges with them. Scratch like the other work tables.
CREATE TABLE bundle_build_ip_runs (
    bundle_id TEXT NOT NULL,
    ip_shard TEXT NOT NULL,
    "first" BLOB NOT NULL,
    "last" BLOB NOT NULL,
    value INTEGER NOT NULL,
    PRIMARY KEY (bundle_id, ip_shard, "first")
) STRICT, WITHOUT ROWID;

-- A re-rank's intelligent-tiering keys in rank order (bundles.md §2 Tiering): rkey is the rank
-- time with every byte inverted plus 0xFF, so ascending order is most recent first; ties by
-- hash. Filled and walked a page per step. Scratch like the other work tables.
CREATE TABLE bundle_build_rank (
    bundle_id TEXT NOT NULL,
    rkey BLOB NOT NULL,
    hash128 BLOB NOT NULL,
    r TEXT NOT NULL,
    PRIMARY KEY (bundle_id, rkey, hash128)
) STRICT, WITHOUT ROWID;

-- A warning's identity (bundles.md §3: warn or allow bundle, value, feed; per block bundle, so
-- two block bundles taking one feed with different rule types never clear each other's), looked
-- up for every key a check holds or clears.
CREATE INDEX warnings_entry ON warnings(value, by_bundle_id, feed_id, kind, bundle_id);
CREATE INDEX warnings_by ON warnings(by_bundle_id, status);

-- Warning re-checks still to run (bundles.md §3 "When"; README §2 Restarts): `*` (everything),
-- `by:<warn or allow bundle>`, or `block:<block bundle>` (its open warnings whose feed, pairing
-- or entry went). A row is written before its job is queued and goes when the job finishes with
-- no newer request (`seq`); at start every row runs again.
CREATE TABLE warning_rechecks (
    target TEXT PRIMARY KEY,
    seq INTEGER NOT NULL
) STRICT;

-- The `warn_on` / allow-block pairing digest the warnings were last checked against: a start
-- that finds another one re-checks everything (a change made while core was down).
CREATE TABLE warning_pairing (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    digest TEXT NOT NULL
) STRICT;

-- Browser lists (bundles.md §8): each list file core serves, with its metrics and the BLAKE3 of
-- its text (ETag).
CREATE TABLE browser_lists (
    path TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    blake3 TEXT NOT NULL,
    written_at TEXT NOT NULL,
    version TEXT NOT NULL,
    stats_json TEXT
) STRICT;

-- Async lookups (core.md §7) ------------------------------------------------------------------
-- changed_seq orders the writes to one provider's verdicts: assigned inside the writer, so in
-- commit order; the verdict-set publisher sends the rows past its head's published_seq.
ALTER TABLE lookup_verdicts ADD COLUMN changed_seq INTEGER NOT NULL DEFAULT 0;
CREATE INDEX lookup_verdicts_changed ON lookup_verdicts(provider_id, changed_seq);
CREATE INDEX lookup_verdicts_obtained ON lookup_verdicts(provider_id, obtained_at);

-- answers_checked: core has matched the Block against the answers already in the window
-- (category_answered, core.md §7); 0 until then, so a restart resumes the check.
ALTER TABLE lookup_blocks ADD COLUMN answers_checked INTEGER NOT NULL DEFAULT 0;
CREATE INDEX lookup_blocks_unchecked ON lookup_blocks(id) WHERE answers_checked = 0;

-- class orders the queue (core.md §7 Order: 0 retries, 1 async attachments, 2 re-checks);
-- context_json holds the item's pending lookup, its re-check deadlines and who asked.
ALTER TABLE lookup_queue ADD COLUMN class INTEGER NOT NULL DEFAULT 1;
CREATE INDEX lookup_queue_order ON lookup_queue(next_at, class);

-- Re-check calls per provider and UTC day, so `recheck.max_per_day` holds across restarts: each
-- call's share is reserved before it is made and given back when the call doesn't count (none
-- made, rejected, or its result discarded).
CREATE TABLE lookup_recheck_days (
    provider_id TEXT NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (provider_id, day)
) STRICT, WITHOUT ROWID;

-- Each provider's last lookup_verdicts.changed_seq: it only increases (retention deleting the
-- rows with the newest numbers never lets a later write reuse a number a verdict set published).
CREATE TABLE lookup_verdict_seq (
    provider_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL
) STRICT;

-- The cache_generation a Block was obtained under (providers.md §4: entries carry it; only the
-- provider's current one is ever read).
ALTER TABLE lookup_blocks ADD COLUMN generation TEXT NOT NULL DEFAULT '';

-- The q records whose lookup effects (re-check deadlines, answers checked against Blocks) core
-- applied, per edge and boot as seq ranges ([[first, last], …] JSON), written in the same
-- transaction as the effects, so an edge's resend after a failure applies them exactly once
-- (README §2 Restarts). Kept for the log retention window.
CREATE TABLE lookup_ingested (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    ranges_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (edge_id, boot)
) STRICT, WITHOUT ROWID;
CREATE INDEX lookup_ingested_updated ON lookup_ingested(updated_at);

-- The answers (edge, boot, seq) a provider's category_answered alert has counted for a name
-- (core.md §7, §9 Dedupe), so an answer counts once: a later Block row's scan, or the answer's
-- own ingest after a scan found it, adds it no more. The newest few hundred per (provider, name)
-- by ts, kept for the log retention window (lookups::answered).
CREATE TABLE lookup_answers_counted (
    provider_id TEXT NOT NULL,
    name TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    PRIMARY KEY (provider_id, name, edge_id, boot, seq)
) STRICT, WITHOUT ROWID;
CREATE INDEX lookup_answers_counted_ts ON lookup_answers_counted(ts);

-- Verdict sets (core.md §7, bundles.md §4–§5): what each provider's current head holds. checksum
-- is the set checksum after the chain (hex), deltas_json the head's delta list, published_seq
-- the newest lookup_verdicts.changed_seq the head includes; overlay_entries and overlay_bytes
-- what its chain costs an edge's overlay budget (edge.md §17).
CREATE TABLE verdict_set_state (
    provider_id TEXT PRIMARY KEY,
    generation TEXT NOT NULL,
    head_id TEXT NOT NULL,
    base_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    checksum TEXT NOT NULL,
    deltas_json TEXT NOT NULL,
    published_seq INTEGER NOT NULL,
    base_records INTEGER NOT NULL,
    overlay_entries INTEGER NOT NULL,
    overlay_bytes INTEGER NOT NULL,
    base_at TEXT NOT NULL,
    published_at TEXT NOT NULL
) STRICT;

-- The current head's delta chain by name hash: each name's record value as the edge's overlay
-- holds it, or null for a delete. Emptied when the base is rebuilt.
CREATE TABLE verdict_set_overlay (
    provider_id TEXT NOT NULL,
    hash BLOB NOT NULL,
    value BLOB,
    PRIMARY KEY (provider_id, hash)
) STRICT, WITHOUT ROWID;

-- The blobs each verdict-set version names (head, base, deltas): a blob is collected once no
-- retained version names it (storage.md §4). last_used_at / superseded_at as for bundle
-- versions.
CREATE TABLE verdict_set_blobs (
    provider_id TEXT NOT NULL,
    head_id TEXT NOT NULL,
    blake3 TEXT NOT NULL,
    PRIMARY KEY (provider_id, head_id, blake3)
) STRICT, WITHOUT ROWID;
CREATE INDEX verdict_set_blobs_blob ON verdict_set_blobs(blake3);
ALTER TABLE verdict_sets ADD COLUMN last_used_at TEXT;
ALTER TABLE verdict_sets ADD COLUMN superseded_at TEXT;

-- The config restore (core.md §2): the bundle heads each edge ran when it happened, which core
-- keeps naming (and keeps the files of) until the bundle's enabled downloaded member feeds have
-- applied runs or failed their first checks; and a marker that the log partitions and metrics.db
-- still need emptying (finished at the next start if core stopped first).
CREATE TABLE restore_holds (
    edge_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    head_id TEXT NOT NULL,
    restored_at TEXT NOT NULL,
    PRIMARY KEY (edge_id, bundle_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE restore_pending (
    at TEXT NOT NULL
) STRICT;
-- Manual feeds whose applied blob a restore applies before their saved file runs (core.md §2):
-- written in the restore's transaction, so a stop before that run finishes it at the next start;
-- done once a run of that blob is stored. attempts and next_at pace and bound the retries of a
-- run the heavy queue refused.
CREATE TABLE restore_applied (
    feed_id TEXT PRIMARY KEY,
    blob TEXT NOT NULL,
    version TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at TEXT
) STRICT;

-- DNSSEC admission (core.md §8): the q records admitted whose analysis hasn't marked them done
-- yet, so a batch that runs again admits, counts and joins each record once. Deleted once the
-- analysis is done with them; a key a stop left behind goes with the log retention window.
CREATE TABLE dnssec_admitted (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    PRIMARY KEY (edge_id, boot, seq)
) STRICT, WITHOUT ROWID;

-- stamped = 0: admitted while the wall clock wasn't synchronised (README §2 Clocks); first_seen
-- and next_at are set when it is, before anything decides by them (core.md §8).
ALTER TABLE dnssec_queue ADD COLUMN stamped INTEGER NOT NULL DEFAULT 1;
CREATE INDEX dnssec_queue_unstamped ON dnssec_queue(id) WHERE stamped = 0;
ALTER TABLE crosscheck_queue ADD COLUMN stamped INTEGER NOT NULL DEFAULT 1;
CREATE INDEX crosscheck_queue_unstamped ON crosscheck_queue(qname, qtype) WHERE stamped = 0;

-- The LAN CA's roots (core.md §11, security.md §2; lanca::rotation): the current one
-- (retired_at NULL; its key and certificate are lanca/ca.{key,crt}) and the previous ones core
-- still trusts until every assigned managed listener reports a certificate from the current
-- one. A rotation's row is its commit point: at start, the root staged in lanca/next-<hex>/ (the
-- hex of its fingerprint) is put in place when this row names it; every other staged root is
-- discarded.
CREATE TABLE lanca_roots (
    fingerprint TEXT PRIMARY KEY,
    cert_pem TEXT NOT NULL,
    zones_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT
) STRICT;
CREATE UNIQUE INDEX lanca_roots_current ON lanca_roots((retired_at IS NULL)) WHERE retired_at IS NULL;

-- What each edge last reported its managed listeners serve (hello and heartbeat `cert_roots`,
-- api.md §3): the root that signed each one's certificate, one row per listener holding one. A
-- previous root stays trusted, and blocks another rotation, until every assigned managed
-- listener has a row naming the current root; an offline edge's rows stay as last reported.
CREATE TABLE lanca_served (
    edge_id TEXT NOT NULL,
    listener_id TEXT NOT NULL,
    root TEXT NOT NULL,
    reported_at TEXT NOT NULL,
    PRIMARY KEY (edge_id, listener_id)
) STRICT, WITHOUT ROWID;

-- key: the compiled key a hit names (as bundle_keys.key), so retention can find hits whose key
-- left the bundle through bundle_keys_key (storage.md §4: kept while the key is in the bundle).
ALTER TABLE bundle_key_hits ADD COLUMN key TEXT;

-- unoffered_at: when retention first found no config core may still serve offering the release
-- (edges::releases; README §2, data in use); NULL while one does. Its rows go 72 h later.
ALTER TABLE edge_releases ADD COLUMN unoffered_at TEXT;

-- bundle_cold_share (core.md §9 Thresholds): per bundle with a cold part, since when its 24 h
-- cold share has been past 1 % (above_since), or back at or below it while its alert is open
-- (below_since), so the kind's threshold holds across restarts (README §2 Restarts). A row
-- goes when neither holds, or with its bundle's cold part.
CREATE TABLE cold_share_state (
    bundle_id TEXT PRIMARY KEY,
    above_since TEXT,
    below_since TEXT
) STRICT, WITHOUT ROWID;
"#;

/// Grouped public-suffix warnings (#49).
const CORE_V5: &str = r#"
-- bundle_psl_hits (compiler::guard, #49): the rules of each (bundle, feed) that block a public
-- suffix below the top level, the durable affected set behind that pair's one grouped
-- `bundle_warning` (`bundle_warning:{bundle}:public_suffix:{feed}`). A row goes when its rule
-- leaves the bundle (or the feed, or the bundle, goes). alerted: the alert has shown this rule's
-- suffix; a suffix no row of which is alerted is newly affected and reopens a resolved alert.
CREATE TABLE bundle_psl_hits (
    bundle_id TEXT NOT NULL,
    feed_id TEXT NOT NULL,
    rule_hash TEXT NOT NULL,
    suffix TEXT NOT NULL,
    identity_json TEXT NOT NULL,
    alerted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bundle_id, feed_id, rule_hash)
) STRICT, WITHOUT ROWID;
CREATE INDEX bundle_psl_hits_suffix ON bundle_psl_hits(bundle_id, feed_id, suffix);

-- Every bundle builds in full once, so its grouped warnings cover the rules already present and
-- its per-rule public-suffix alerts are superseded.
UPDATE bundle_builds SET definition_hash = '';
"#;

/// Heartbeat samples by boot (chart baselines, core.md §10).
const METRICS_V2: &str = r#"
CREATE INDEX samples_edge_boot ON samples(edge_id, boot, ts);

-- The last core.db metric_outbox id applied to points (source `core`), written in the same
-- transaction as those points, so a restart between the two databases' commits counts each
-- outbox row once.
CREATE TABLE outbox_applied (
    source TEXT PRIMARY KEY,
    last_id INTEGER NOT NULL
) STRICT;
"#;

const METRICS_V1: &str = r#"
CREATE TABLE series (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    UNIQUE (name, labels_json)
) STRICT;

-- ts: Unix milliseconds.
CREATE TABLE points (
    series_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    value REAL NOT NULL
) STRICT;
CREATE INDEX points_series_ts ON points(series_id, ts);
CREATE INDEX points_ts ON points(ts);

-- buckets: the JSON bucket array of one histogram sample (api.md §3).
CREATE TABLE histograms (
    series_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    buckets TEXT NOT NULL,
    sum REAL NOT NULL,
    count INTEGER NOT NULL
) STRICT;
CREATE INDEX histograms_series_ts ON histograms(series_id, ts);
CREATE INDEX histograms_ts ON histograms(ts);

CREATE TABLE samples (
    edge_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    boot TEXT NOT NULL,
    up_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX samples_edge_ts ON samples(edge_id, ts);
CREATE INDEX samples_ts ON samples(ts);
"#;

/// Every table `core.db` must hold after migrating (checked by tests).
pub const CORE_TABLES: &[&str] = &[
    "bundle_psl_hits",
    "settings",
    "ui_account",
    "edges",
    "edge_pending",
    "listeners",
    "listener_edges",
    "clients",
    "profiles",
    "upstreams",
    "upstream_groups",
    "forward_zones",
    "feed_providers",
    "feed_provider_state",
    "feeds",
    "manual_files",
    "bundles",
    "bundle_feeds",
    "lookup_providers",
    "secrets",
    "config_changes",
    "feed_runs",
    "feed_entries",
    "feed_entry_undo",
    "feed_state",
    "feed_provider_checks",
    "feed_checks",
    "feed_changes",
    "feed_imports",
    "warnings",
    "policy_drops",
    "bundle_keys",
    "bundle_shards",
    "bundle_key_hits",
    "bundle_ip_ranges",
    "bundle_ip_shards",
    "bundle_versions",
    "blobs",
    "edge_status",
    "edge_configs",
    "edge_boots",
    "edge_events",
    "edge_releases",
    "edge_requests",
    "temp_allows",
    "alerts",
    "alert_history",
    "alert_evidence",
    "alert_evidence_counts",
    "wire_examples",
    "alert_evidence_answers",
    "lookup_queue",
    "lookup_verdicts",
    "lookup_blocks",
    "verdict_sets",
    "dnssec_queue",
    "dnssec_results",
    "crosscheck_queue",
    "crosscheck_seen",
    "edge_named",
    "edge_pins",
    "log_clamped",
    "feed_run_ids",
    "feed_runs_open",
    "module_pauses",
    "feed_purges",
    "bundle_builds",
    "bundle_build_keys",
    "bundle_build_ops",
    "bundle_version_blobs",
    "browser_lists",
    "bundle_build_blobs",
    "bundle_build_fresh",
    "warning_rechecks",
    "warning_pairing",
    "bundle_build_ip_rules",
    "bundle_build_ip_runs",
    "bundle_build_rank",
    "lookup_recheck_days",
    "verdict_set_state",
    "verdict_set_overlay",
    "verdict_set_blobs",
    "lookup_verdict_seq",
    "lookup_ingested",
    "lookup_answers_counted",
    "restore_holds",
    "restore_pending",
    "restore_applied",
    "dnssec_admitted",
    "log_progress",
    "retro_progress",
    "retro_values",
    "trial_pending",
    "metric_outbox",
    "cold_share_state",
];

pub const METRICS_TABLES: &[&str] = &["series", "points", "histograms", "samples", "outbox_applied"];
