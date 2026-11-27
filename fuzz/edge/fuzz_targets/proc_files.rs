//! /proc and cgroup files behind heartbeat system fields (api.md §3).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = picket_edge::sysinfo::cpu_ms_from_stat(s, 100);
        let _ = picket_edge::sysinfo::cgroup_memory_path(s, std::path::Path::new("/sys/fs/cgroup"));
    }
});
