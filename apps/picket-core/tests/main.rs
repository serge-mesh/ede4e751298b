//! picket-core's integration tests, as one test binary: one link instead of one per file. Each
//! file under `tests/` is a module here (`autotests = false` in Cargo.toml); nextest still runs
//! every test in its own process.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

/// Declares each test file as a module and lists the names for the check below.
macro_rules! test_modules {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*
        const MODULES: &[&str] = &[$(stringify!($name)),*];
    };
}

test_modules!(
    bundles,
    compiler,
    config_export,
    core_extras,
    datadir,
    dnssec,
    edge_api,
    edge_e2e,
    edge_protocol,
    edge_release,
    feed_providers,
    feed_runs,
    feed_sqs,
    feed_stale,
    feed_transfer,
    feeds,
    lanca_rotation,
    lists,
    logs_analysis,
    logs_attribution,
    logs_evidence,
    logs_progress,
    logs_round2,
    logs_round3,
    logs_tier_query,
    lookups,
    lookups_e2e,
    metrics_export,
    recheck,
    retention,
    ui_followups,
    validation,
    web,
);

/// A file under `tests/` that isn't declared above would silently never build or run.
#[test]
fn every_test_file_is_declared() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests");
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .filter(|n| n != "main")
        .collect();
    files.sort();
    let mut declared: Vec<&str> = MODULES.to_vec();
    declared.sort_unstable();
    assert_eq!(files, declared, "declare each tests/*.rs in tests/main.rs");
}
