//! picket-lookup: the lookup module trait, the module registry, the shared `LookupClient` and
//! the built-in lookup modules (providers.md §1, §4, §5). The same code runs sync lookups on the
//! edge (edge.md §10) and async lookups on core (core.md §7).
//!
//! - [`LookupModule`] and its types: the trait exactly as providers.md §4 writes it.
//! - [`LookupCtx`]: what a module gets for one lookup provider: an HTTP client, a DNS server
//!   client, per-provider state, a clock, cancellation and the call's deadline ([`ctx`]).
//! - [`Registry`]: the modules `build.rs` found under `src/modules/<id>/`
//!   ([`registry::modules`]).
//! - [`LookupClient`]: one per lookup provider: name check, RAM tier (edge), verdict-set hook,
//!   single-flight, limits, breaker, rejection pause, timeouts, late answers, metrics
//!   ([`client`]).
//! - [`selftest`]: self-test judgement and the decision logic core uses.
//! - [`cron`]: the one cron parser for self-tests and core's `cron` feed triggers.
//! - Modules: [`registry::modules::http_json`] and [`registry::modules::dns`] (with the
//!   `quad9` and `nextdns` presets).

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]

pub mod client;
pub mod cron;
pub mod ctx;
pub mod module;
pub mod name;
pub mod registry;
pub mod secrets;
pub mod selftest;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use client::{
    AsyncOptions, AsyncOutcome, AsyncResult, ClientOptions, ErrorKind, LateAnswer, LateSink, LookupClient,
    ProviderSpec, Role, SetRecord, Source, StoredVerdict, SyncOutcome, SyncRequest, SyncResult, UpdateEffect,
    VerdictSet,
};
pub use ctx::{
    Clock, ConnectionFactory, Connections, DnsClientError, DnsServer, DnsServerClient, HttpClient, HttpError,
    HttpRequest, HttpResponse, LookupCtx, SystemClock, header_names, url_for_logs,
};
pub use module::{
    Answer, Category, DETAIL_MAX, Expect, LookupError, LookupModule, Preset, PresetBuild, SelfTest, Verdict,
    detail_fits,
};
pub use name::check_name;
pub use registry::{ConfigError, Registry, modules};
pub use selftest::{SelfTestAction, SelfTestResult, SelfTestRun, SelfTestState};
