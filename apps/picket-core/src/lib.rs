//! picket-core: the management app (core.md). One process, one tokio runtime.
//!
//! The module tree follows core.md §1's components, one module per component, plus the foundation
//! modules every component builds on:
//!
//! | Module | Job |
//! |---|---|
//! | [`web`] | axum on the web port: UI assets, `/api/ui/v1`, the UI WebSocket, `/healthz`, protections (core.md §12) |
//! | [`edge_api`] | the edge port (mTLS): pinned-key TLS server, sessions, the `objects` bucket, logs, CSRs (api.md §1–§3) |
//! | [`scheduler`] | the realtime, light and heavy job lanes (core.md §3) |
//! | [`edges`] | registry, pending keys, sessions and live state, `EdgeConfig` publishing and convergence, requests, the bundled release, conditions → alerts (core.md §4–§5, §9) |
//! | [`logs`] | hourly partitions and log ingest; attribution by replay, unchecked cold lookups, the wire check, retro-match, trial checks, alert evidence, the query-log API (core.md §6, §9, §12) |
//! | [`metrics`] | heartbeat metrics in `metrics.db`, core's log-pipeline series, charts, the Prometheus export (core.md §10) |
//! | [`feeds`] | feed providers and their feeds: checks and downloads through download modules, triggers (SQS included), new provider feeds, schedules, staleness, ingest and diff, sanity gates, rule policy, presets, manual files, export and import (feeds.md, feed-scheduling.md) |
//! | [`modules`] | the download modules: the trait, the `build.rs` registry, `github`, `http`, `alphamountain_threat_1000` (providers.md §1–§3) |
//! | [`compiler`] | bundle builds: incremental and full shard builds, deltas, compaction, tiering, guardrails, compile-time warnings, versions, per-edge heads within budgets, retention (bundles.md §1–§7) |
//! | [`lists`] | browser lists: per bundle and per profile (pruned and full), served under `/lists/*` (bundles.md §8) |
//! | [`lookups`] | async lookups, retries and re-checks (`lookup_queue`), the verdict store, verdict sets, self-tests, `category_answered` from provider Blocks, the lookup UI endpoints (core.md §7) |
//! | [`dnssec`] | async DNSSEC validation of logged answers through an edge (hickory's validator over an adapter), fallback queries, `dnssec_queue`, coverage, `dnssec_bogus`/`dnssec_unavailable`, the cross-check of unsigned answers, the DNSSEC UI endpoints (core.md §8) |
//! | [`alerts`] | raise, dedupe, resolve, thresholds, history (core.md §9) |
//! | [`retention`] | the hourly heavy-lane P3 job (storage.md §4) |
//! | [`clock`] | wall-clock synchronisation for time decisions (README §2 Clocks) |
//! | [`lanca`] | the LAN CA (security.md §2) |
//! | [`db`] | `core.db`, `metrics.db`: one writer task and a read pool, migrations (storage.md) |
//! | [`config`] | the configuration model, validation, system objects, journal (core.md §2) |
//! | [`settings`] | typed settings with defaults (core.md §11) |
//! | [`instance`] | the data directory: `init`, the marker, `run`'s start checks (core.md §13) |
//! | [`identity`] | core's Ed25519 identity (api.md §1) |
//! | [`psl`] | registrable domains from the bundled public suffix list (core.md §8, §9) |
//! | [`cli`] | the command line (core.md §13) |

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]

pub mod alerts;
pub mod blobs;
pub mod cli;
pub mod clock;
pub mod compiler;
pub mod config;
pub mod db;
pub mod dnssec;
pub mod edge_api;
pub mod edges;
pub mod error;
pub mod feeds;
pub mod identity;
pub mod instance;
pub mod lanca;
pub mod lists;
pub mod logs;
pub mod lookups;
pub mod metrics;
pub mod modules;
pub mod net;
pub mod psl;
pub mod retention;
pub mod run;
pub mod scheduler;
pub mod settings;
pub mod state;
pub mod util;
pub mod web;

pub use error::{CoreError, ExitError};
pub use state::AppState;

/// This binary's release version: the version core offers edges (core.md §5).
pub const VERSION: &str = picket_api::VERSION;
