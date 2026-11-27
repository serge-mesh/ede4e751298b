//! picket-rules: the rule model, normaliser, format parsers, classifier and AdGuard semantics
//! (rules.md, feeds.md §4–§8, bundles.md §1–§4, §6, §8).
//!
//! Core uses it to ingest feeds, compile bundles and replay queries; it is also the reference
//! semantics picket-bundle's compiled matcher must agree with ([`matcher::BundleMatcher`]).
//!
//! Module map:
//! - [`name`], [`ip`], [`flags`], [`rrtype`]: names (rule text vs wire labels), addresses, key
//!   flags and levels, DNS mnemonics.
//! - [`adguard`], [`goregex`], [`analysis`]: urlfilter's pattern model, Go → Rust regex, proofs.
//! - [`modifiers`], [`rewrite`]: `$dnstype`, `$client`, `$ctag`, `$denyallow`, `$dnsrewrite`;
//!   [`entity`], [`psl`]: `$denyallow` entities and the public suffix list they need.
//! - [`rule`]: the rule model and its storage identity; [`classify`]: rules.md §2.
//! - [`formats`], [`misp`]: streaming parsers (feeds.md §4), first-seen directives, counts.
//! - [`badfilter`], [`policy`]: `$badfilter` resolution and cross-feed cancellations; `rule_policy`.
//! - [`order`]: urlfilter's matched-rule order, which decides between rewrites.
//! - [`matcher`]: the reference matcher for one bundle (per query, or for any query as warn and
//!   allow checks need); [`compile`]: key-level helpers for the compiler (folding, subsumption with
//!   hot/cold parts, broad tests, probe set, PSL check).
//! - [`browser`]: browser-list helpers (bundles.md §8): allow conversion, exact cancellation and
//!   the names pruning checks.

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod adguard;
pub mod analysis;
pub mod badfilter;
pub mod browser;
pub mod classify;
pub mod compile;
pub mod entity;
pub mod flags;
pub mod formats;
pub mod goregex;
pub mod ip;
pub mod matcher;
pub mod mem;
pub mod misp;
pub mod modifiers;
pub mod name;
pub mod order;
pub mod policy;
pub mod psl;
pub mod rewrite;
pub mod rrtype;
pub mod rule;

pub use flags::{Flags, Level};
pub use matcher::{BundleAction, BundleMatcher, MatchResult, Outcome, Role, RuleMatch};
pub use modifiers::QueryCtx;
pub use name::{OwnedName, RuleName};
pub use rule::{Entry, Kind, Rule, RuleSpec, RuleType};
