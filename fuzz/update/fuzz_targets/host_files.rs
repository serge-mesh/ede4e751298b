//! Host files `install` parses: `/proc/self/mountinfo` and `/usr/lib/version` (edge-unifi.md §1),
//! and `edge.json`'s directory settings, with the checks that keep them off root-owned paths.
#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use picket_edge_update::hostinfo::{
    firmware_minimums, firmware_warning, parse_mountinfo, parse_usr_lib_version, ssd_mount_usable,
};
use picket_edge_update::platform::{Layout, Platform, check_data_dir, check_dir_setting, check_ssd_dir};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mounts = parse_mountinfo(&text);
    let _ = ssd_mount_usable(&mounts, "/volume1", "/data/picket/var");
    let _ = parse_usr_lib_version(&text);
    let _ = firmware_warning(Some(&text), &firmware_minimums());
    let layout = Layout::for_platform(Platform::Unifi);
    for line in text.lines().take(4) {
        if check_dir_setting("data_dir", line).is_ok() {
            assert!(line.starts_with('/') && !line.contains(char::is_whitespace) && !line.contains('%'));
            // The edge's directories never reach a root-owned one.
            if check_data_dir(&layout, line).is_ok() {
                let d = Path::new(line);
                for root_owned in [layout.bin_dir, layout.config_dir, layout.helper_dir] {
                    let r = Path::new(root_owned);
                    assert!(!d.starts_with(r) && !r.starts_with(d), "{line}");
                }
            }
            let _ = check_ssd_dir(&layout, line, layout.default_data_dir);
        }
    }
});
