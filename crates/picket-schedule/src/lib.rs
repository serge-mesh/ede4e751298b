//! The `dynamic` feed scheduler's model (feed-scheduling.md §4–§6), apart from core: the
//! per-feed [`learner`], the provider simulation and its [`backtest`] harness. Core
//! (`picket_core::feeds::schedule`) re-exports both modules and owns everything around them:
//! settings, storage, the checks themselves.
//!
//! A crate of its own so CI can build it optimised (`[profile.ci.package.picket-schedule]`): the
//! backtests replay 60 days of recorded feed history and are CPU-bound, minutes each without
//! optimisation against seconds with it, while core itself keeps the cheaper dev settings.

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]

pub mod backtest;
pub mod learner;

/// Warm start: how far back, and how many changes, a feed's recorded history reaches
/// (feed-scheduling.md §6). Core's GitHub provider fetches this much; the backtests replay it.
pub const HISTORY_DAYS: i64 = 60;
/// See [`HISTORY_DAYS`].
pub const HISTORY_CHANGES: usize = 20;

/// Float to `usize` with `as` semantics (core's `util::f64_to_usize`).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "float-to-int `as` saturates (NaN is 0): the intended conversion"
)]
pub(crate) fn f64_to_usize(f: f64) -> usize {
    f as usize
}
