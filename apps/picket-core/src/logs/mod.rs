//! Query logs (core.md §6): hourly SQLite partitions, ingest, and the seams attribution,
//! retro-match, trial checks and the wire check work from.
//!
//! - [`partition`]: the partition files and their schema (never migrated).
//! - [`decode`]: `POST /v1/logs` bodies → checked records (fuzzed).
//! - [`writer`]: the one thread that writes partitions (durable before the ack).
//! - [`ingest`]: the ingest pipeline (dedupe, answers by id, `answer_missing`, unknown boots,
//!   `edge_events`, `temp_allows`, alert effects, metrics, the ack).
//! - [`LogRetention`]: deletes whole partitions past `retention.query_logs` (storage.md §4).
//! - [`analysis`]: the pass over new records after ingest (light lane, never delaying the ack):
//!   [`attribution`] by [`replay`], [`trial`] checks, unchecked [`cold`] lookups, the [`wire`]
//!   check; [`retro`]-match and hour closes; alert [`evidence`].
//! - [`record`], [`query`], [`api`]: records as read back, the query-log reads and the UI routes.

pub mod analysis;
pub mod api;
pub mod attribution;
pub mod cold;
pub mod cold_share;
pub mod decode;
pub mod evidence;
pub mod ingest;
pub mod partition;
pub mod query;
pub mod record;
pub mod replay;
pub mod retro;
pub mod trial;
pub mod wire;
pub mod writer;

pub use ingest::{Ingest, IngestError, IngestReport};
pub use partition::{LogStore, Partition};

use crate::retention::RetentionHook;
use crate::scheduler::{BoxFuture, Step};
use crate::state::AppState;

/// Deletes whole hourly partitions whose hour ended before the log retention window
/// (storage.md §4: "delete whole hourly partition files"), through the partition writer so an
/// open partition is closed first. Clock-gated like every retention delete.
pub struct LogRetention;

impl RetentionHook for LogRetention {
    fn name(&self) -> &str {
        "log_partitions"
    }

    fn step<'a>(&'a self, state: &'a AppState) -> BoxFuture<'a, anyhow::Result<Step>> {
        Box::pin(async move {
            let window = state.settings().retention.query_logs.as_duration();
            let cutoff = crate::util::window_start(jiff::Timestamp::now(), window);
            let writer = state.logs.writer().clone();
            let store = writer.store().clone();
            let list = tokio::task::spawn_blocking(move || store.list()).await??;
            for (hour, _) in list {
                // A partition holds an hour's records; it goes once that whole hour is past the
                // window (ingest drops records older than the window on arrival).
                if picket_api::time::saturating_add(hour, jiff::SignedDuration::from_hours(1)) <= cutoff {
                    writer.delete(hour).await?;
                    // The progress kept for the partition goes with it (logs::analysis,
                    // logs::retro, logs::trial).
                    analysis::forget_hour(state, hour).await?;
                    tracing::info!(hour = %hour, "log partition deleted (retention)");
                }
            }
            // Progress a stop left behind for partitions already deleted.
            analysis::prune_progress(state).await?;
            // Retro-match's record of feed runs: a run older than the window follows no
            // retained answer (core.md §6).
            let c = crate::util::ts(&picket_api::time::saturating_sub(
                cutoff,
                jiff::SignedDuration::from_hours(1),
            ));
            state
                .db
                .write(move |db| {
                    db.execute(
                        "DELETE FROM retro_runs WHERE at < ?1 AND run_id < (SELECT max(run_id) FROM retro_runs)",
                        [c],
                    )?;
                    Ok::<_, anyhow::Error>(())
                })
                .await?;
            Ok(Step::Done)
        })
    }
}
