//! The path an update takes through a real process (edge.md §14 step 3): an updater runs the new
//! binary's `units` with the real, bounded runner and accepts what it prints.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

use std::path::Path;

use picket_edge_update::platform::Platform;
use picket_edge_update::system::{RealSystem, System};
use picket_edge_update::units::{UPDATE_PATH, UPDATE_SERVICE, parse_units_output};

#[test]
fn units_from_the_real_binary_pass_the_updaters_check() {
    let exe = Path::new(env!("CARGO_BIN_EXE_picket-edge-update"));
    let sys = RealSystem::default();
    for platform in [Platform::Unifi, Platform::Debian] {
        let out = sys.run_units(exe, platform).expect("units ran");
        let units = parse_units_output(&out).expect("units accepted");
        assert!(units.contains_key(UPDATE_PATH));
        let exec = format!("picket-edge-update --platform {} --data-dir ", platform.as_str());
        assert!(units[UPDATE_SERVICE].contains(&exec), "{platform:?}");
    }
}
