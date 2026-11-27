//! `bin/update-result.json`, the updater's last result, which the edge imports (edge.md §14,
//! Result and Import): `{result_id, request_id, outcome, stage?, version, at}`, `root:picket`
//! 0640, written atomically under the install directory, never under `data_dir`.

use crate::api::UpdateResult;
use crate::fsx::Dir;
use crate::system::System;

pub const NAME: &str = "update-result.json";
const MAX: u64 = 64 * 1024;

/// The last result, if there is a readable one.
pub fn read(bin: &Dir) -> Option<UpdateResult> {
    let bytes = bin.read_bounded(NAME, MAX, false).ok()?;
    parse(&bytes)
}

/// Parses a result file. Public for the fuzz target.
pub fn parse(bytes: &[u8]) -> Option<UpdateResult> {
    serde_json::from_slice(bytes).ok()
}

/// Writes the result: tmp → fsync → rename, `root:<picket gid>`, 0640.
pub fn write(bin: &Dir, sys: &dyn System, r: &UpdateResult, gid: u32) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(r).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    bin.write_atomic(sys, NAME, &bytes, 0o640, (0, gid))
}
