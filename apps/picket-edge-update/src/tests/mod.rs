//! Scenario tests against a temporary root and the fake system (build-and-test.md §5, rows
//! "Self-update" and "Install").

mod cli;
mod install;
mod update;

/// The calls after the first one that starts with `marker`.
pub fn after<'a>(calls: &'a [String], marker: &str) -> &'a [String] {
    let i = calls
        .iter()
        .position(|c| c.starts_with(marker))
        .unwrap_or_else(|| panic!("no call {marker:?} in {calls:#?}"));
    &calls[i + 1..]
}

/// Only the calls that change something.
pub fn mutating(calls: &[String]) -> Vec<String> {
    calls
        .iter()
        .filter(|c| c.starts_with("systemctl ") && !c.starts_with("systemctl is-"))
        .cloned()
        .collect()
}

pub fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}
