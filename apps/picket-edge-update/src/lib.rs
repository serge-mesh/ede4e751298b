//! picket-edge-update: the root installer and updater (edge.md §14–§15, edge-unifi.md §2,
//! security.md §3). A small oneshot with no DNS, network, TLS or async code; its normal
//! dependencies are allowlisted (build-and-test.md §4).
//!
//! # The contract with picket-edge
//!
//! picket-edge is untrusted as seen by the updater (README §2): everything it writes is checked
//! for size and syntax, opened with `O_NOFOLLOW` relative to a directory the updater opened, and
//! never written to. Paths are UniFi's; Debian's are in [`platform::Layout`].
//!
//! **The edge writes** (under `data_dir`, from `edge.json`, default `/data/picket/var`):
//! - `releases/<version>/picket-edge-<version>-<arch>.tar.gz` and `…tar.gz.minisig`: the tarball
//!   and signature as core serves them, already checked by the edge. `<arch>` is the host's
//!   (`aarch64`, `x86_64`) and must match the signature's trusted comment
//!   `picket-edge <version> <arch>`. The updater copies both (≤ 256 MiB and ≤ 64 KiB) into a
//!   root-owned directory before verifying, so the edge may delete them once the result arrives.
//! - `releases/pending.json` = `{"version": "X.Y.Z", "request_id": <string ≤ 256 bytes or
//!   null>, "rollback": true?}` (≤ 64 KiB), written tmp → rename, and only while no
//!   `pending.json` exists (`picket-edge-update.path` starts the updater on `PathExists=`). The
//!   updater deletes it when its run ends, whatever the outcome; one the edge replaced during the
//!   run (another inode), or one whose result the updater couldn't write, is left for the next
//!   run. Anything that isn't a regular file, isn't JSON or names an invalid version ends with
//!   `stage: "pending"`.
//! - `state.json` with a top-level `"ready_version"`: null from the edge's start (written before
//!   `READY=1`) until its listeners are bound, then its own version. The updater polls it for
//!   up to 120 s after restarting the edge.
//!
//! **The updater writes**:
//! - `/data/picket/bin/update-result.json` (`root:picket`, 0640, tmp → rename):
//!   `{"result_id": "<16 hex>", "request_id": <copied from pending.json>, "outcome": "ok" |
//!   "failed", "stage"?: "verify" | "units" | "readiness" | "rollback" | "locked" | "superseded"
//!   | "unpack" | "pending", "version": "X.Y.Z" (empty for an invalid pending.json),
//!   "at": "<RFC 3339, µs, Z>"}`. Each run writes at most one result, with a fresh random
//!   `result_id`; the edge imports a result whose `result_id` differs from its latest
//!   outcome's (edge.md §14, Import). A duplicate `request_id` leaves the existing result
//!   untouched.
//! - `/data/picket/bin/<version>/{picket-edge, picket-edge-helper, picket-edge-update}` and the
//!   `bin/current` symlink (relative, `<version>`), root-owned 0755; only the current and
//!   previous versions are kept.
//! - The units in `/etc/systemd/system` ([`units`]): the edge runs as
//!   `bin/current/picket-edge run --config <edge.json> --data-dir <data_dir>`, `Type=notify`; the
//!   update service as `bin/current/picket-edge-update --platform <unifi|debian> --data-dir
//!   <data_dir>`, the platform and `data_dir` its units were written for ([`cli`]).
//! - On `install` only: `<data_dir>/ssd-id` and `<ssd_dir>/.picket-ssd`, both `picket:picket`
//!   0640 holding the same 32 lowercase hex digits and a newline (edge-unifi.md §1).
//!
//! **Readiness** means: after the updater's `systemctl restart picket-edge.service` returns (at
//! `READY=1`), `state.json`'s `ready_version` becomes the new version within 120 s.

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]
#![doc(html_no_source)]

pub mod accounts;
pub mod api;
pub mod cli;
pub mod error;
pub mod fsx;
pub mod hostinfo;
pub mod install;
pub mod lock;
pub mod platform;
pub mod release;
pub mod result;
pub mod snapshot;
pub mod system;
pub mod systemd;
pub mod units;
pub mod update;

#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;

/// This binary's release version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One line to the journal (stderr under systemd).
pub fn log(msg: &str) {
    eprintln!("picket-edge-update: {msg}");
}
