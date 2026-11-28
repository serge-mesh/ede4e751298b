//! The update run (edge.md §14 steps 2–4, Lock, Interrupted update, Result).

use std::collections::BTreeMap;
use std::path::Path;

use super::{after, mode, mutating};
use crate::api::{Outcome, stage};
use crate::platform::Platform;
use crate::system::System;
use crate::testing::{Keys, Ready, TarEntry, World, release_entries};
use crate::units::{ACCOUNTS, EDGE, HELPER, UPDATE_PATH, UPDATE_SERVICE};
use crate::update::RunEnd;

/// A test case's setup step.
type Setup = Box<dyn Fn(&World)>;

/// A UniFi gateway with 1.4.0 installed.
fn installed() -> World {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    w.sys.clear_calls();
    w
}

fn result(end: RunEnd) -> crate::api::UpdateResult {
    match end {
        RunEnd::Result(r) => r,
        other => panic!("expected a result, got {other:?}"),
    }
}

fn failed(w: &World, want: &str) -> crate::api::UpdateResult {
    let r = result(w.update());
    assert_eq!(r.outcome, Outcome::Failed, "{r:?}");
    assert_eq!(r.stage.as_deref(), Some(want), "{r:?}");
    assert_eq!(w.result().as_ref(), Some(&r));
    assert!(
        !w.pending_path().exists(),
        "pending.json is deleted when the run ends"
    );
    r
}

/// Nothing changed: bin/current, units, no new version directory, no unit touched.
fn assert_unchanged(w: &World, units_before: &BTreeMap<String, Option<String>>) {
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert_eq!(w.version_dirs(), ["1.4.0"]);
    assert!(mutating(&w.sys.calls()).is_empty(), "{:?}", w.sys.calls());
    assert!(!w.snapshot_exists());
    assert!(!w.exists("/data/picket/bin/.staging"));
    for (name, text) in units_before {
        assert_eq!(&w.unit_text(name), text, "{name}");
    }
}

fn unit_texts(w: &World) -> BTreeMap<String, Option<String>> {
    [ACCOUNTS, EDGE, HELPER, UPDATE_PATH, UPDATE_SERVICE]
        .iter()
        .map(|n| (n.to_string(), w.unit_text(n)))
        .collect()
}

#[test]
fn success() {
    let w = installed();
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req-1"), false);
    let r = result(w.update());
    assert_eq!(r.outcome, Outcome::Ok);
    assert_eq!(r.stage, None);
    assert_eq!(r.version, "1.5.0");
    assert_eq!(r.request_id.as_deref(), Some("req-1"));
    assert_eq!(r.result_id.len(), 16);
    assert!(r.result_id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(r.at.ends_with('Z') && r.at.contains('.'), "{}", r.at);
    assert_eq!(w.result().as_ref(), Some(&r));
    assert_eq!(w.sys.owner_of("/data/picket/bin/update-result.json"), (0, 880));
    assert_eq!(mode(&w.real("/data/picket/bin/update-result.json")), 0o640);

    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    assert_eq!(w.version_dirs(), ["1.4.0", "1.5.0"]);
    let edge = w.real("/data/picket/bin/1.5.0/picket-edge");
    assert_eq!(std::fs::read_to_string(&edge).unwrap(), "#!picket-edge 1.5.0\n");
    assert_eq!(mode(&edge), 0o755);
    assert!(!w.snapshot_exists());
    assert!(!w.pending_path().exists());
    assert!(!w.exists("/data/picket/bin/.staging"));
    assert!(
        w.sys
            .calls()
            .contains(&"units 1.5.0 --platform unifi".to_string())
    );
    // Unit files unchanged: the helper, then the edge.
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service"
        ]
    );
    w.assert_own_service_untouched();
    // Nothing under data_dir was written but by the edge.
    let releases: Vec<_> = std::fs::read_dir(w.real("/data/picket/var/releases"))
        .unwrap()
        .collect();
    assert_eq!(releases.len(), 1, "only the edge's releases/1.5.0/ is left");

    // The next update keeps only the current and previous versions.
    w.release("1.6.0", None);
    w.pending("1.6.0", None, false);
    assert_eq!(result(w.update()).outcome, Outcome::Ok);
    assert_eq!(w.version_dirs(), ["1.5.0", "1.6.0"]);
}

#[test]
fn debian_success() {
    let w = World::new(Platform::Debian);
    w.install("1.4.0", false).unwrap();
    w.release("1.5.0", None);
    w.pending("1.5.0", None, false);
    let r = result(w.update());
    assert_eq!(r.outcome, Outcome::Ok, "{r:?}");
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    assert!(
        w.sys
            .calls()
            .contains(&"units 1.5.0 --platform debian".to_string())
    );
}

#[test]
fn nothing_pending_does_nothing() {
    let w = installed();
    assert_eq!(w.update(), RunEnd::Nothing);
    assert!(w.result().is_none());
    assert!(mutating(&w.sys.calls()).is_empty());
}

#[test]
fn already_current_is_ok() {
    let w = installed();
    w.pending("1.4.0", Some("req-9"), false);
    let r = result(w.update());
    assert_eq!(
        (r.outcome, r.stage.as_deref(), r.version.as_str()),
        (Outcome::Ok, None, "1.4.0")
    );
    assert!(mutating(&w.sys.calls()).is_empty());
    assert!(!w.pending_path().exists());
}

#[test]
fn duplicate_request_id_changes_nothing() {
    let w = installed();
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req-1"), false);
    let first = result(w.update());
    w.sys.clear_calls();
    w.release("1.6.0", None);
    w.pending("1.6.0", Some("req-1"), false);
    assert_eq!(w.update(), RunEnd::Duplicate);
    assert_eq!(w.result(), Some(first), "the existing result is left");
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    assert!(mutating(&w.sys.calls()).is_empty());
    assert!(!w.pending_path().exists());
    // A null request id is never a duplicate.
    w.pending("1.6.0", None, false);
    assert_eq!(result(w.update()).outcome, Outcome::Ok);
}

#[test]
fn superseded_unless_rollback() {
    let w = World::new(Platform::Unifi);
    w.install("1.6.0", false).unwrap();
    w.sys.clear_calls();
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("r"), false);
    let r = failed(&w, stage::SUPERSEDED);
    assert_eq!(r.version, "1.5.0");
    assert_eq!(w.current().as_deref(), Some("1.6.0"));
    assert!(mutating(&w.sys.calls()).is_empty());
    // Marked as a rollback, the older release installs.
    w.pending("1.5.0", Some("r2"), true);
    let r = result(w.update());
    assert_eq!(r.outcome, Outcome::Ok, "{r:?}");
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    assert_eq!(w.version_dirs(), ["1.5.0", "1.6.0"]);
}

#[test]
fn verify_failures_change_nothing() {
    let cases: Vec<(&str, Setup)> = vec![
        (
            "trusted comment names another version",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "picket-edge 1.5.1 x86_64",
                    &w.keys,
                );
            }),
        ),
        (
            "trusted comment names another architecture",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "picket-edge 1.5.0 aarch64",
                    &w.keys,
                );
            }),
        ),
        (
            "minisign's default trusted comment",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "timestamp:1790000000\tfile:x",
                    &w.keys,
                );
            }),
        ),
        (
            "signed by another key",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "picket-edge 1.5.0 x86_64",
                    &Keys::new(),
                );
            }),
        ),
        (
            "tarball swapped after signing",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "picket-edge 1.5.0 x86_64",
                    &w.keys,
                );
                let p = w.real("/data/picket/var/releases/1.5.0/picket-edge-1.5.0-x86_64.tar.gz");
                std::fs::write(p, crate::testing::tar_gz(&release_entries("6.6.6"))).unwrap();
            }),
        ),
        (
            "signature missing",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "picket-edge 1.5.0 x86_64",
                    &w.keys,
                );
                std::fs::remove_file(
                    w.real("/data/picket/var/releases/1.5.0/picket-edge-1.5.0-x86_64.tar.gz.minisig"),
                )
                .unwrap();
            }),
        ),
        (
            "garbage signature",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "picket-edge 1.5.0 x86_64",
                    &w.keys,
                );
                std::fs::write(
                    w.real("/data/picket/var/releases/1.5.0/picket-edge-1.5.0-x86_64.tar.gz.minisig"),
                    "untrusted comment: x\nnot base64\n",
                )
                .unwrap();
            }),
        ),
        (
            "tarball missing",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "picket-edge 1.5.0 x86_64",
                    &w.keys,
                );
                std::fs::remove_file(
                    w.real("/data/picket/var/releases/1.5.0/picket-edge-1.5.0-x86_64.tar.gz"),
                )
                .unwrap();
            }),
        ),
        (
            "no releases/<version>/ at all",
            Box::new(|w: &World| {
                std::fs::create_dir_all(w.real("/data/picket/var/releases")).unwrap();
            }),
        ),
        (
            "tarball is a symlink",
            Box::new(|w: &World| {
                w.release_raw(
                    "1.5.0",
                    &release_entries("1.5.0"),
                    "picket-edge 1.5.0 x86_64",
                    &w.keys,
                );
                let p = w.real("/data/picket/var/releases/1.5.0/picket-edge-1.5.0-x86_64.tar.gz");
                std::fs::rename(&p, w.real("/elsewhere.tar.gz")).unwrap();
                std::os::unix::fs::symlink(w.real("/elsewhere.tar.gz"), &p).unwrap();
            }),
        ),
        (
            "edge.json not root-owned: the compiled-in key",
            Box::new(|w: &World| {
                w.release("1.5.0", None);
                w.sys.set_owner("/data/picket/etc/edge.json", 880, 880);
            }),
        ),
        (
            "edge.json writable by its group: the compiled-in key",
            Box::new(|w: &World| {
                use std::os::unix::fs::PermissionsExt;
                w.release("1.5.0", None);
                std::fs::set_permissions(
                    w.real("/data/picket/etc/edge.json"),
                    std::fs::Permissions::from_mode(0o660),
                )
                .unwrap();
            }),
        ),
        (
            "config directory owned by picket: the compiled-in key",
            Box::new(|w: &World| {
                w.release("1.5.0", None);
                w.sys.set_owner("/data/picket/etc", 880, 880);
            }),
        ),
    ];
    for (what, setup) in cases {
        let w = installed();
        let before = unit_texts(&w);
        setup(&w);
        w.sys
            .st
            .borrow_mut()
            .units_out
            .insert("1.5.0".into(), World::units_json(&w.units()));
        w.pending("1.5.0", Some("req"), false);
        let r = failed(&w, stage::VERIFY);
        assert_eq!(r.version, "1.5.0", "{what}");
        assert_eq!(r.request_id.as_deref(), Some("req"), "{what}");
        assert_unchanged(&w, &before);
        assert!(
            !w.sys.calls().iter().any(|c| c.starts_with("units ")),
            "{what}: ran units"
        );
    }
}

#[test]
fn invalid_pending_is_handled_once() {
    let cases: Vec<(&str, Setup)> = vec![
        (
            "not JSON",
            Box::new(|w: &World| std::fs::write(w.pending_path(), "{nope").unwrap()),
        ),
        (
            "a path in the version",
            Box::new(|w: &World| w.pending("../1.2.3", Some("x"), false)),
        ),
        (
            "a short version",
            Box::new(|w: &World| w.pending("1.5", None, false)),
        ),
        (
            "a version that isn't a string",
            Box::new(|w: &World| std::fs::write(w.pending_path(), r#"{"version": 7}"#).unwrap()),
        ),
        (
            "a huge request id",
            Box::new(|w: &World| w.pending("1.5.0", Some(&"x".repeat(300)), false)),
        ),
        (
            "too large",
            Box::new(|w: &World| std::fs::write(w.pending_path(), vec![b' '; 70_000]).unwrap()),
        ),
        (
            "a directory",
            Box::new(|w: &World| {
                std::fs::create_dir_all(w.pending_path().join("sub")).unwrap();
                std::fs::write(w.pending_path().join("sub/f"), "x").unwrap();
            }),
        ),
        (
            "a symlink to a root file",
            Box::new(|w: &World| {
                std::os::unix::fs::symlink(w.real("/etc/passwd"), w.pending_path()).unwrap();
            }),
        ),
        (
            "a hard link",
            Box::new(|w: &World| {
                std::fs::write(w.real("/etc/other"), r#"{"version": "1.5.0"}"#).unwrap();
                std::fs::hard_link(w.real("/etc/other"), w.pending_path()).unwrap();
            }),
        ),
    ];
    for (what, setup) in cases {
        let w = installed();
        std::fs::create_dir_all(w.real("/data/picket/var/releases")).unwrap();
        setup(&w);
        let r = failed(&w, stage::PENDING);
        assert_eq!(r.version, "", "{what}");
        assert!(
            std::fs::symlink_metadata(w.pending_path()).is_err(),
            "{what}: still there"
        );
        assert!(w.real("/etc/passwd").exists());
        assert_eq!(w.current().as_deref(), Some("1.4.0"));
        // No loop: the next run finds nothing.
        assert_eq!(w.update(), RunEnd::Nothing, "{what}");
    }
}

/// A well-formed `pending.json` with a bad version still has its request id: the result carries
/// it, so the edge's request ends (edge.md §14, Result).
#[test]
fn an_invalid_version_keeps_its_request_id() {
    let w = installed();
    w.pending("../../../etc", Some("r1"), false);
    let r = failed(&w, stage::PENDING);
    assert_eq!((r.version.as_str(), r.request_id.as_deref()), ("", Some("r1")));
    assert!(mutating(&w.sys.calls()).is_empty());
    assert!(!w.exists("/data/picket/bin/.staging"));
}

#[test]
fn pending_fifo_is_not_opened() {
    let w = installed();
    std::fs::create_dir_all(w.real("/data/picket/var/releases")).unwrap();
    // std can't make a FIFO; coreutils' mkfifo is everywhere the tests run, so its absence fails.
    let made = std::process::Command::new("mkfifo")
        .arg(w.pending_path())
        .status()
        .expect("mkfifo (coreutils) runs");
    assert!(made.success(), "mkfifo failed");
    failed(&w, stage::PENDING);
    assert!(std::fs::symlink_metadata(w.pending_path()).is_err());
}

#[test]
fn releases_symlink_is_removed_not_followed() {
    let w = installed();
    std::fs::create_dir_all(w.real("/elsewhere")).unwrap();
    std::fs::write(w.real("/elsewhere/pending.json"), r#"{"version": "1.5.0"}"#).unwrap();
    std::os::unix::fs::symlink(w.real("/elsewhere"), w.real("/data/picket/var/releases")).unwrap();
    let r = result(w.update());
    assert_eq!(r.stage.as_deref(), Some(stage::PENDING));
    assert!(std::fs::symlink_metadata(w.real("/data/picket/var/releases")).is_err());
    assert!(w.real("/elsewhere/pending.json").exists());
    assert_eq!(w.update(), RunEnd::Nothing);
}

#[test]
fn unpack_failure_changes_nothing() {
    let w = installed();
    let before = unit_texts(&w);
    let mut entries = release_entries("1.5.0");
    entries.pop();
    entries.push(TarEntry::file("../escape", b"x"));
    w.release_raw("1.5.0", &entries, "picket-edge 1.5.0 x86_64", &w.keys);
    w.pending("1.5.0", None, false);
    failed(&w, stage::UNPACK);
    assert_unchanged(&w, &before);
    assert!(!w.exists("/data/picket/bin/.unpack-1.5.0"));
    assert!(!w.exists("/data/picket/escape"));
}

#[test]
fn units_output_refused_changes_nothing() {
    let mut no_update_service = World::new(Platform::Unifi).units();
    no_update_service.remove(UPDATE_SERVICE);
    let mut bad_name = World::new(Platform::Unifi).units();
    bad_name.insert("../../etc/evil.service".into(), "[Unit]\n".into());
    let outputs: Vec<(&str, Option<Vec<u8>>)> = vec![
        ("format 2", Some(br#"{"format": 2, "units": {}}"#.to_vec())),
        (
            "without the update service",
            Some(World::units_json(&no_update_service)),
        ),
        ("a bad name", Some(World::units_json(&bad_name))),
        ("not JSON", Some(b"Usage: picket-edge-update ...".to_vec())),
        ("the command failed", None),
    ];
    for (what, out) in outputs {
        let w = installed();
        let before = unit_texts(&w);
        w.release("1.5.0", None);
        match out {
            Some(o) => {
                w.sys.st.borrow_mut().units_out.insert("1.5.0".into(), o);
            }
            None => {
                w.sys.st.borrow_mut().units_out.remove("1.5.0");
            }
        }
        w.pending("1.5.0", None, false);
        failed(&w, stage::UNITS);
        assert_unchanged(&w, &before);
        assert!(!w.exists("/etc/systemd/system/evil.service"), "{what}");
    }
}

#[test]
fn readiness_timeout_rolls_back() {
    let w = installed();
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req"), false);
    let start = w.sys.st.borrow().clock;
    let r = failed(&w, stage::READINESS);
    assert_eq!(r.version, "1.5.0");
    assert!(w.sys.st.borrow().clock - start >= crate::update::READY_WAIT);
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert_eq!(
        w.version_dirs(),
        ["1.4.0"],
        "the failed version's new directory is removed"
    );
    assert!(!w.snapshot_exists());
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service",
            // Rollback: nothing added, files unchanged; reload, reenable, restart.
            "systemctl daemon-reload",
            "systemctl reenable picket-edge-helper.service",
            "systemctl reenable picket-edge-update.path",
            "systemctl reenable picket-edge.service",
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service",
            "systemctl restart picket-accounts.service",
            "systemctl restart picket-edge-update.path",
        ]
    );
    let state = std::fs::read_to_string(w.real("/data/picket/var/state.json")).unwrap();
    assert!(state.contains("\"1.4.0\""), "{state}");
    w.assert_own_service_untouched();
}

/// #69: a new edge whose helper speaks another protocol refuses to run on every start (it never
/// binds its listeners or writes `ready_version`, systemd restarting it meanwhile). The updater's
/// readiness wait never sees the new version ready, and the rollback runs as for any other
/// readiness failure.
#[test]
fn an_edge_refusing_an_incompatible_helper_never_reads_ready_and_rolls_back() {
    let w = installed();
    w.sys.st.borrow_mut().ready = Ready::Incompatible(vec!["1.5.0".into()]);
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req"), false);
    let start = w.sys.st.borrow().clock;
    let r = failed(&w, stage::READINESS);
    assert_eq!(r.version, "1.5.0");
    assert!(w.sys.st.borrow().clock - start >= crate::update::READY_WAIT);
    assert!(
        w.sys.st.borrow().refused_starts >= 10,
        "systemd kept restarting the refusing edge during the wait"
    );
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert_eq!(w.version_dirs(), ["1.4.0"]);
    let calls = mutating(&w.sys.calls());
    assert_eq!(
        calls[calls.len() - 8..],
        [
            "systemctl daemon-reload",
            "systemctl reenable picket-edge-helper.service",
            "systemctl reenable picket-edge-update.path",
            "systemctl reenable picket-edge.service",
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service",
            "systemctl restart picket-accounts.service",
            "systemctl restart picket-edge-update.path",
        ],
        "the rollback path"
    );
    // The rolled-back edge says ready again.
    let state = std::fs::read_to_string(w.real("/data/picket/var/state.json")).unwrap();
    assert!(state.contains("\"ready_version\": \"1.4.0\""), "{state}");
    w.assert_own_service_untouched();
}

#[test]
fn state_json_link_is_not_followed() {
    let w = installed();
    w.sys.st.borrow_mut().ready = Ready::Silent;
    std::fs::remove_file(w.real("/data/picket/var/state.json")).unwrap();
    std::fs::write(w.real("/elsewhere.json"), r#"{"ready_version": "1.5.0"}"#).unwrap();
    std::os::unix::fs::symlink(w.real("/elsewhere.json"), w.real("/data/picket/var/state.json")).unwrap();
    w.release("1.5.0", None);
    w.pending("1.5.0", None, false);
    failed(&w, stage::READINESS);
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
}

#[test]
fn failing_rollback_step_is_retried_then_kept_and_recovered_before_the_duplicate_check() {
    let w = installed();
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.sys.fail("systemctl reenable picket-edge.service", 4);
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req-1"), false);
    let first = failed(&w, stage::ROLLBACK);
    let reenables = w
        .sys
        .calls()
        .iter()
        .filter(|c| *c == "systemctl reenable picket-edge.service")
        .count();
    assert_eq!(reenables, 4, "one try and three retries");
    assert!(w.snapshot_exists(), "the snapshot is kept for the next run");
    // The rest of the rollback still ran.
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert_eq!(w.sys.state(EDGE), "active");

    // A stop before pending.json was deleted: the same request comes back. The next run rolls
    // back from the snapshot first, then drops the duplicate, leaving the result.
    w.sys.clear_calls();
    w.pending("1.5.0", Some("req-1"), false);
    assert_eq!(w.update(), RunEnd::Duplicate);
    let calls = w.sys.calls();
    assert!(
        calls.contains(&"systemctl reenable picket-edge.service".to_string()),
        "{calls:?}"
    );
    assert!(!calls.iter().any(|c| c.starts_with("units ")));
    assert!(!w.snapshot_exists());
    assert_eq!(w.result(), Some(first));
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert_eq!(w.version_dirs(), ["1.4.0"]);
}

#[test]
fn kept_snapshot_is_recovered_then_the_update_starts_over() {
    let w = installed();
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.sys.fail("systemctl reenable picket-edge.service", 4);
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req-1"), false);
    failed(&w, stage::ROLLBACK);
    w.sys.st.borrow_mut().ready = Ready::All;
    w.sys.clear_calls();
    w.pending("1.5.0", Some("req-2"), false);
    let r = result(w.update());
    assert_eq!(r.outcome, Outcome::Ok, "{r:?}");
    let calls = w.sys.calls();
    let recovered = calls
        .iter()
        .position(|c| c == "systemctl reenable picket-edge.service")
        .unwrap();
    let units = calls.iter().position(|c| c.starts_with("units 1.5.0")).unwrap();
    assert!(recovered < units, "recovery runs first: {calls:?}");
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
}

/// The fixture release: adds a timer and its service, removes a unit, edits the edge unit and
/// changes the path unit's [Install] section.
fn reshaped_units(w: &World) -> BTreeMap<String, String> {
    let mut u = w.units();
    u.insert(
        "picket-edge-stats.timer".into(),
        "[Timer]\nOnCalendar=hourly\n[Install]\nWantedBy=timers.target\n".into(),
    );
    u.insert(
        "picket-edge-stats.service".into(),
        "[Service]\nType=oneshot\nExecStart=/data/picket/bin/current/picket-edge stats\n".into(),
    );
    let edge = u[EDGE].replace("LimitNOFILE=65536", "LimitNOFILE=65536\nTimeoutStopSec=20");
    u.insert(EDGE.into(), edge);
    let path = u[UPDATE_PATH].replace("WantedBy=multi-user.target", "WantedBy=paths.target");
    u.insert(UPDATE_PATH.into(), path);
    u
}

fn with_old_timer(w: &World) {
    w.write_unit(
        "picket-edge-old.timer",
        "[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n",
    );
    w.sys.systemctl(&["daemon-reload"]).unwrap();
    w.sys.systemctl(&["enable", "picket-edge-old.timer"]).unwrap();
    w.sys.systemctl(&["start", "picket-edge-old.timer"]).unwrap();
    w.sys.clear_calls();
}

#[test]
fn units_added_removed_edited_and_install_sections_changed() {
    let w = installed();
    with_old_timer(&w);
    let units = reshaped_units(&w);
    w.release("1.5.0", Some(units.clone()));
    w.pending("1.5.0", None, false);
    let r = result(w.update());
    assert_eq!(r.outcome, Outcome::Ok, "{r:?}");
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl disable --now picket-edge-old.timer",
            "systemctl daemon-reload",
            "systemctl daemon-reload",
            "systemctl enable picket-edge-stats.timer",
            "systemctl reenable picket-edge-update.path",
            "systemctl reenable picket-edge.service",
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service",
            "systemctl restart picket-edge-update.path",
            "systemctl start picket-edge-stats.timer",
        ]
    );
    for (name, text) in &units {
        assert_eq!(w.unit_text(name).as_ref(), Some(text), "{name}");
    }
    assert!(!w.exists("/etc/systemd/system/picket-edge-old.timer"));
    assert_eq!(
        w.sys.links(UPDATE_PATH).into_iter().collect::<Vec<_>>(),
        ["paths.target.wants/picket-edge-update.path"]
    );
    assert!(
        w.sys.links("picket-edge-stats.service").is_empty(),
        "no [Install]: left to its timer"
    );
    assert_eq!(w.sys.state("picket-edge-stats.timer"), "active");
    w.assert_own_service_untouched();
}

#[test]
fn rollback_restores_units_byte_for_byte() {
    let w = installed();
    with_old_timer(&w);
    let before = unit_texts(&w);
    let old_timer = w.unit_text("picket-edge-old.timer");
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.release("1.5.0", Some(reshaped_units(&w)));
    w.pending("1.5.0", None, false);
    failed(&w, stage::READINESS);
    for (name, text) in &before {
        assert_eq!(&w.unit_text(name), text, "{name}");
    }
    assert_eq!(w.unit_text("picket-edge-old.timer"), old_timer);
    assert!(!w.exists("/etc/systemd/system/picket-edge-stats.timer"));
    assert!(!w.exists("/etc/systemd/system/picket-edge-stats.service"));
    assert!(w.sys.links("picket-edge-stats.timer").is_empty());
    assert_eq!(w.sys.state("picket-edge-stats.timer"), "inactive");
    assert_eq!(
        w.sys.links(UPDATE_PATH).into_iter().collect::<Vec<_>>(),
        ["multi-user.target.wants/picket-edge-update.path"]
    );
    assert_eq!(
        w.sys
            .links("picket-edge-old.timer")
            .into_iter()
            .collect::<Vec<_>>(),
        ["timers.target.wants/picket-edge-old.timer"]
    );
    assert_eq!(
        w.sys.state("picket-edge-old.timer"),
        "active",
        "a retired, active unit starts again"
    );
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    w.assert_own_service_untouched();
}

#[test]
fn failed_release_with_a_requires_on_an_inactive_unit_after_a_reboot() {
    let w = installed();
    // An enabled, running unit the release drops, and an installed, inactive one.
    w.write_unit(
        "picket-edge-aux.service",
        "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
    );
    w.write_unit("picket-edge-idle.service", "[Service]\nExecStart=/bin/true\n");
    w.sys.systemctl(&["daemon-reload"]).unwrap();
    w.sys.systemctl(&["enable", "picket-edge-aux.service"]).unwrap();
    w.sys.systemctl(&["start", "picket-edge-aux.service"]).unwrap();
    let mut units = w.units();
    units.insert(
        "picket-edge-idle.service".into(),
        "[Service]\nExecStart=/bin/true\n".into(),
    );
    let edge = units[EDGE].replace("[Unit]\n", "[Unit]\nRequires=picket-edge-idle.service\n");
    units.insert(EDGE.into(), edge);
    let path = units[UPDATE_PATH].replace("WantedBy=multi-user.target", "WantedBy=paths.target");
    units.insert(UPDATE_PATH.into(), path);
    let before = unit_texts(&w);
    w.sys.clear_calls();
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.release("1.5.0", Some(units));
    w.pending("1.5.0", None, false);
    failed(&w, stage::READINESS);
    let calls = w.sys.calls();
    // The failed edge pulled the idle unit up; the rollback stops it after the reload.
    let rollback = after(&calls, "checkpoint switched");
    let reload = rollback
        .iter()
        .position(|c| c == "systemctl daemon-reload")
        .unwrap();
    let stop = rollback
        .iter()
        .position(|c| c == "systemctl stop picket-edge-idle.service")
        .unwrap();
    assert!(reload < stop, "{rollback:?}");
    assert_eq!(w.sys.state("picket-edge-idle.service"), "inactive");
    assert_eq!(w.sys.state("picket-edge-aux.service"), "active");
    assert_eq!(w.unit_text(EDGE), before[EDGE]);
    assert_eq!(
        w.sys.links(UPDATE_PATH).into_iter().collect::<Vec<_>>(),
        ["multi-user.target.wants/picket-edge-update.path"]
    );
    // Checked again after a reboot.
    w.sys.reboot();
    assert_eq!(w.sys.state("picket-edge-idle.service"), "inactive");
    assert_eq!(w.sys.state("picket-edge-aux.service"), "active");
    assert_eq!(w.sys.state(EDGE), "active");
    assert_eq!(w.sys.state(UPDATE_PATH), "active");
}

#[test]
fn rollback_removes_an_added_unit_even_when_stopping_it_fails() {
    let w = installed();
    let mut units = w.units();
    units.insert(
        "picket-edge-extra.service".into(),
        "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n".into(),
    );
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.sys.fail("systemctl stop picket-edge-extra.service", 100);
    w.release("1.5.0", Some(units));
    w.pending("1.5.0", None, false);
    failed(&w, stage::ROLLBACK);
    assert!(!w.exists("/etc/systemd/system/picket-edge-extra.service"));
    assert!(w.sys.links("picket-edge-extra.service").is_empty());
    assert!(w.snapshot_exists());
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
}

/// An added unit that isn't running gets no stop: a stop also stops the units that require it
/// (edge.md §14 step 4). It is still disabled and deleted.
#[test]
fn rollback_stops_an_added_unit_only_if_it_is_running() {
    let w = installed();
    let mut units = w.units();
    units.insert(
        "picket-edge-oneshot.service".into(),
        "[Service]\nType=oneshot\nExecStart=/bin/true\n".into(),
    );
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.release("1.5.0", Some(units));
    w.pending("1.5.0", None, false);
    failed(&w, stage::READINESS);
    let calls = w.sys.calls();
    let rollback = after(&calls, "checkpoint switched");
    assert!(
        !rollback
            .iter()
            .any(|c| c == "systemctl stop picket-edge-oneshot.service"),
        "{rollback:?}"
    );
    assert!(
        rollback
            .iter()
            .any(|c| c == "systemctl disable picket-edge-oneshot.service"),
        "{rollback:?}"
    );
    assert!(!w.exists("/etc/systemd/system/picket-edge-oneshot.service"));
    assert!(!w.snapshot_exists());
}

#[test]
fn a_unit_that_wont_stop_fails_at_units_and_rolls_back() {
    let w = installed();
    with_old_timer(&w);
    let before = unit_texts(&w);
    w.sys.fail("systemctl disable --now picket-edge-old.timer", 1);
    w.release("1.5.0", Some(reshaped_units(&w)));
    w.pending("1.5.0", None, false);
    failed(&w, stage::UNITS);
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert_eq!(w.version_dirs(), ["1.4.0"]);
    for (name, text) in &before {
        assert_eq!(&w.unit_text(name), text, "{name}");
    }
    assert!(w.exists("/etc/systemd/system/picket-edge-old.timer"));
    assert!(!w.snapshot_exists());
}

#[test]
fn a_failed_daemon_reload_after_the_snapshot_rolls_back() {
    let w = installed();
    let before = unit_texts(&w);
    w.sys.fail("systemctl daemon-reload", 1);
    w.release("1.5.0", Some(reshaped_units(&w)));
    w.pending("1.5.0", None, false);
    failed(&w, stage::UNITS);
    for (name, text) in &before {
        assert_eq!(&w.unit_text(name), text, "{name}");
    }
    assert!(!w.exists("/etc/systemd/system/picket-edge-stats.timer"));
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
}

#[test]
fn both_update_units_change_and_its_own_service_is_never_restarted() {
    let w = installed();
    let mut units = w.units();
    let path = units[UPDATE_PATH].replace(
        "Description=Picket edge update trigger",
        "Description=Picket update trigger",
    );
    let svc = units[UPDATE_SERVICE].replace("Description=Picket edge updater", "Description=Picket updater");
    assert_ne!(svc, units[UPDATE_SERVICE]);
    units.insert(UPDATE_PATH.into(), path.clone());
    units.insert(UPDATE_SERVICE.into(), svc.clone());
    w.release("1.5.0", Some(units));
    w.pending("1.5.0", None, false);
    assert_eq!(result(w.update()).outcome, Outcome::Ok);
    assert_eq!(w.unit_text(UPDATE_PATH), Some(path));
    assert_eq!(
        w.unit_text(UPDATE_SERVICE),
        Some(svc),
        "written, applies from its next run"
    );
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl daemon-reload",
            "systemctl reenable picket-edge-update.path",
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service",
            "systemctl restart picket-edge-update.path",
        ]
    );
    w.assert_own_service_untouched();
}

/// A failed release that changed both update units gets both back byte for byte, and the
/// updater's own service is never started, stopped or restarted (edge.md §14 step 3–4).
#[test]
fn a_failed_release_that_changes_both_update_units_restores_them() {
    let w = installed();
    let before = unit_texts(&w);
    let mut units = w.units();
    let path = units[UPDATE_PATH].replace(
        "Description=Picket edge update trigger",
        "Description=Picket update trigger",
    );
    let svc = units[UPDATE_SERVICE].replace("Description=Picket edge updater", "Description=Picket updater");
    assert_ne!(svc, units[UPDATE_SERVICE]);
    units.insert(UPDATE_PATH.into(), path);
    units.insert(UPDATE_SERVICE.into(), svc);
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.release("1.5.0", Some(units));
    w.pending("1.5.0", None, false);
    failed(&w, stage::READINESS);
    assert_eq!(w.unit_text(UPDATE_PATH), before[UPDATE_PATH]);
    assert_eq!(w.unit_text(UPDATE_SERVICE), before[UPDATE_SERVICE]);
    assert_eq!(w.sys.state(UPDATE_PATH), "active");
    assert_eq!(
        w.sys.links(UPDATE_PATH).into_iter().collect::<Vec<_>>(),
        ["multi-user.target.wants/picket-edge-update.path"]
    );
    w.assert_own_service_untouched();
}

/// A unit an admin disabled stays disabled when a release changes its file; it still restarts
/// if it is running (edge.md §14 step 3).
#[test]
fn a_unit_an_admin_disabled_stays_disabled_when_its_file_changes() {
    let w = installed();
    w.sys.systemctl(&["disable", UPDATE_PATH]).unwrap();
    assert_eq!(
        w.sys.state(UPDATE_PATH),
        "active",
        "disable alone doesn't stop it"
    );
    w.sys.clear_calls();
    let mut units = w.units();
    let path = units[UPDATE_PATH].replace(
        "Description=Picket edge update trigger",
        "Description=Picket update trigger",
    );
    units.insert(UPDATE_PATH.into(), path.clone());
    w.release("1.5.0", Some(units));
    w.pending("1.5.0", None, false);
    assert_eq!(result(w.update()).outcome, Outcome::Ok);
    assert_eq!(w.unit_text(UPDATE_PATH), Some(path));
    assert!(w.sys.links(UPDATE_PATH).is_empty());
    let calls = mutating(&w.sys.calls());
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("enable") && c.ends_with(UPDATE_PATH)),
        "{calls:?}"
    );
    assert!(
        calls.contains(&format!("systemctl restart {UPDATE_PATH}")),
        "{calls:?}"
    );
}

/// An update that finds the lock held waits, and goes ahead once the holder exits (the kernel
/// releases a dead holder's `flock`; edge.md §14, Lock).
#[test]
fn an_update_waits_for_the_lock_and_proceeds_once_the_holder_exits() {
    let w = installed();
    let holder = std::fs::File::open(w.real("/data/picket/bin/.lock")).unwrap();
    holder.lock().unwrap();
    w.sys.st.borrow_mut().release_on_sleep = Some(holder);
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req"), false);
    let start = w.sys.st.borrow().clock;
    let r = result(w.update());
    assert_eq!(r.outcome, Outcome::Ok, "{r:?}");
    let waited = w.sys.st.borrow().clock - start;
    assert!(!waited.is_zero() && waited < crate::lock::LOCK_WAIT, "{waited:?}");
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
}

#[test]
fn a_masked_unit_is_never_unmasked() {
    let w = installed();
    std::fs::remove_file(w.real("/etc/systemd/system/picket-edge-update.path")).unwrap();
    std::os::unix::fs::symlink("/dev/null", w.real("/etc/systemd/system/picket-edge-update.path")).unwrap();
    w.sys.clear_calls();
    w.release("1.5.0", Some(reshaped_units(&w)));
    w.pending("1.5.0", None, false);
    assert_eq!(result(w.update()).outcome, Outcome::Ok);
    assert_eq!(
        std::fs::read_link(w.real("/etc/systemd/system/picket-edge-update.path")).unwrap(),
        Path::new("/dev/null")
    );
    assert!(
        !mutating(&w.sys.calls()).iter().any(|c| c.ends_with(UPDATE_PATH)),
        "{:?}",
        w.sys.calls()
    );
}

#[test]
fn lock_contention_times_out() {
    let w = installed();
    let before = unit_texts(&w);
    let holder = std::fs::File::open(w.real("/data/picket/bin/.lock")).unwrap();
    holder.lock().unwrap();
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req"), false);
    let start = w.sys.st.borrow().clock;
    let r = failed(&w, stage::LOCKED);
    assert_eq!(
        (r.version.as_str(), r.request_id.as_deref()),
        ("1.5.0", Some("req"))
    );
    assert!(w.sys.st.borrow().clock - start >= crate::lock::LOCK_WAIT);
    assert_unchanged(&w, &before);
}

mod interrupted {
    use super::*;

    #[test]
    fn cut_off_just_after_retiring_a_unit() {
        let w = installed();
        with_old_timer(&w);
        w.release("1.5.0", Some(reshaped_units(&w)));
        w.pending("1.5.0", Some("req"), false);
        assert_eq!(w.update_crashing("retired-unit", 1), "retired-unit");
        assert!(w.snapshot_exists());
        assert!(
            w.pending_path().exists(),
            "pending.json survives, so the path unit runs again"
        );
        assert!(w.sys.links("picket-edge-old.timer").is_empty());
        assert_eq!(w.sys.state("picket-edge-old.timer"), "inactive");
        w.sys.clear_calls();
        let r = result(w.update());
        assert_eq!(r.outcome, Outcome::Ok, "{r:?}");
        let calls = w.sys.calls();
        let units = calls.iter().position(|c| c.starts_with("units 1.5.0")).unwrap();
        let recovery = &calls[..units];
        assert!(
            recovery.contains(&"systemctl reenable picket-edge-old.timer".to_string()),
            "{recovery:?}"
        );
        assert!(
            recovery.contains(&"systemctl restart picket-edge-old.timer".to_string()),
            "{recovery:?}"
        );
        assert!(
            !w.exists("/etc/systemd/system/picket-edge-old.timer"),
            "retired again by the new run"
        );
        assert_eq!(w.current().as_deref(), Some("1.5.0"));
    }

    #[test]
    fn cut_off_after_writing_the_units_then_a_reboot() {
        let w = installed();
        // An enabled unit the admin stopped: in another boot it counts as active.
        w.sys.systemctl(&["stop", UPDATE_PATH]).unwrap();
        let before = unit_texts(&w);
        w.release("1.5.0", Some(reshaped_units(&w)));
        w.pending("1.5.0", Some("req"), false);
        w.update_crashing("units-written", 1);
        w.sys.reboot();
        w.sys.clear_calls();
        w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
        let r = failed(&w, stage::READINESS);
        assert_eq!(r.request_id.as_deref(), Some("req"));
        let calls = w.sys.calls();
        let units = calls.iter().position(|c| c.starts_with("units 1.5.0")).unwrap();
        let recovery = &calls[..units];
        assert!(
            recovery.contains(&format!("systemctl restart {UPDATE_PATH}")),
            "{recovery:?}"
        );
        assert!(
            !recovery.contains(&format!("systemctl stop {UPDATE_PATH}")),
            "restarted, never stopped: {recovery:?}"
        );
        // Nothing is stopped: the units the update added never ran in this boot, so they are
        // only disabled and removed.
        assert!(
            !recovery.iter().any(|c| c.starts_with("systemctl stop")),
            "{recovery:?}"
        );
        for added in ["picket-edge-stats.service", "picket-edge-stats.timer"] {
            assert!(
                recovery.contains(&format!("systemctl disable {added}")),
                "{recovery:?}"
            );
            assert!(!w.exists(format!("/etc/systemd/system/{added}")));
        }
        for (name, text) in &before {
            assert_eq!(&w.unit_text(name), text, "{name}");
        }
    }

    /// In the boot the snapshot was taken in, a unit recorded as enabled but not active stays
    /// stopped: only another boot counts it as active (edge.md §14, Interrupted update).
    #[test]
    fn cut_off_and_recovered_in_the_same_boot_keeps_an_idle_unit_stopped() {
        let w = installed();
        w.sys.systemctl(&["stop", UPDATE_PATH]).unwrap();
        w.release("1.5.0", Some(reshaped_units(&w)));
        w.pending("1.5.0", Some("req"), false);
        w.update_crashing("units-written", 1);
        std::fs::remove_file(w.pending_path()).unwrap();
        w.sys.clear_calls();
        assert_eq!(w.update(), RunEnd::Nothing);
        let calls = mutating(&w.sys.calls());
        assert!(
            !calls
                .iter()
                .any(|c| c.ends_with(UPDATE_PATH) && !c.contains("enable")),
            "{calls:?}"
        );
        assert_eq!(w.sys.state(UPDATE_PATH), "inactive");
        assert_eq!(
            w.sys.links(UPDATE_PATH).into_iter().collect::<Vec<_>>(),
            ["multi-user.target.wants/picket-edge-update.path"]
        );
        assert!(!w.snapshot_exists());
        assert_eq!(w.current().as_deref(), Some("1.4.0"));
    }

    #[test]
    fn cut_off_after_the_switch() {
        let w = installed();
        w.release("1.5.0", None);
        w.pending("1.5.0", None, false);
        w.update_crashing("switched", 1);
        assert_eq!(w.current().as_deref(), Some("1.5.0"));
        w.sys.clear_calls();
        w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
        failed(&w, stage::READINESS);
        assert_eq!(w.current().as_deref(), Some("1.4.0"));
        assert_eq!(w.version_dirs(), ["1.4.0"]);
    }

    #[test]
    fn cut_off_while_writing_the_snapshot() {
        let w = installed();
        w.release("1.5.0", None);
        w.pending("1.5.0", None, false);
        w.update_crashing("snapshot-before-rename", 1);
        assert!(w.exists("/data/picket/bin/.units-prev.tmp"));
        assert!(!w.snapshot_exists());
        w.sys.clear_calls();
        let r = result(w.update());
        assert_eq!(r.outcome, Outcome::Ok);
        assert!(!w.exists("/data/picket/bin/.units-prev.tmp"));
        let calls = w.sys.calls();
        let units = calls.iter().position(|c| c.starts_with("units 1.5.0")).unwrap();
        assert!(
            mutating(&calls[..units]).is_empty(),
            "nothing to roll back: {calls:?}"
        );
    }

    #[test]
    fn a_failed_snapshot_delete_after_success_never_rolls_back() {
        let w = installed();
        w.release("1.5.0", None);
        w.pending("1.5.0", None, false);
        w.sys
            .st
            .borrow_mut()
            .fail_checkpoint
            .insert("snapshot-delete".into());
        let r = result(w.update());
        assert_eq!(r.outcome, Outcome::Ok);
        assert!(w.snapshot_exists());
        w.sys.st.borrow_mut().fail_checkpoint.clear();
        w.sys.clear_calls();
        assert_eq!(w.update(), RunEnd::Nothing);
        assert!(mutating(&w.sys.calls()).is_empty(), "{:?}", w.sys.calls());
        assert!(!w.snapshot_exists());
        assert_eq!(w.current().as_deref(), Some("1.5.0"));
        assert_eq!(w.result(), Some(r));
    }

    #[test]
    fn cut_off_between_the_result_and_the_snapshot_delete() {
        let w = installed();
        w.release("1.5.0", None);
        w.pending("1.5.0", Some("req"), false);
        w.update_crashing("result-written", 1);
        let r = w.result().unwrap();
        assert_eq!(r.outcome, Outcome::Ok);
        assert!(w.snapshot_exists());
        w.sys.clear_calls();
        assert_eq!(w.update(), RunEnd::Duplicate);
        assert!(mutating(&w.sys.calls()).is_empty(), "{:?}", w.sys.calls());
        assert_eq!(w.current().as_deref(), Some("1.5.0"));
        assert_eq!(w.result(), Some(r));
    }

    #[test]
    fn an_unreadable_snapshot_fails_at_rollback() {
        let w = installed();
        std::fs::create_dir_all(w.real("/data/picket/bin/.units-prev")).unwrap();
        std::fs::write(w.real("/data/picket/bin/.units-prev/snapshot.json"), "{").unwrap();
        w.release("1.5.0", None);
        w.pending("1.5.0", Some("req"), false);
        let r = failed(&w, stage::ROLLBACK);
        assert_eq!(r.request_id.as_deref(), Some("req"));
        assert!(w.snapshot_exists(), "kept for install to clear");
        assert_eq!(w.current().as_deref(), Some("1.4.0"));
    }
}

#[test]
fn pending_replaced_during_the_run_is_left_for_the_next_run() {
    let w = installed();
    w.release("1.5.0", None);
    w.release("1.6.0", None);
    w.pending("1.5.0", Some("req-1"), false);
    w.sys.st.borrow_mut().replace_pending_at = Some((
        "snapshot-written".into(),
        r#"{"version": "1.6.0", "request_id": "req-2"}"#.into(),
    ));
    let r = result(w.update());
    assert_eq!((r.outcome, r.version.as_str()), (Outcome::Ok, "1.5.0"));
    assert!(w.pending_path().exists(), "the edge's new request survives");
    let r = result(w.update());
    assert_eq!(
        (r.outcome, r.version.as_str(), r.request_id.as_deref()),
        (Outcome::Ok, "1.6.0", Some("req-2"))
    );
    assert!(!w.pending_path().exists());
}

#[test]
fn temporary_files_are_deleted_at_start() {
    let w = installed();
    std::fs::write(w.real("/data/picket/bin/.update-result.json.tmp-00ab"), "x").unwrap();
    std::os::unix::fs::symlink("1.4.0", w.real("/data/picket/bin/.current.tmp-00cd")).unwrap();
    std::fs::create_dir_all(w.real("/data/picket/bin/.staging")).unwrap();
    std::fs::create_dir_all(w.real("/data/picket/bin/.unpack-1.5.0")).unwrap();
    std::fs::create_dir_all(w.real("/data/picket/bin/.units-prev.trash-0001/units")).unwrap();
    std::fs::write(w.real("/etc/systemd/system/.picket-edge.service.tmp-00ef"), "x").unwrap();
    std::fs::write(w.real("/etc/systemd/system/.other.tmp-1"), "x").unwrap();
    assert_eq!(w.update(), RunEnd::Nothing);
    for gone in [
        "/data/picket/bin/.update-result.json.tmp-00ab",
        "/data/picket/bin/.current.tmp-00cd",
        "/data/picket/bin/.staging",
        "/data/picket/bin/.unpack-1.5.0",
        "/data/picket/bin/.units-prev.trash-0001",
        "/etc/systemd/system/.picket-edge.service.tmp-00ef",
    ] {
        assert!(!w.exists(gone), "{gone}");
    }
    assert!(w.exists("/etc/systemd/system/.other.tmp-1"), "not ours");
    assert!(w.exists("/data/picket/bin/.lock"));
}

#[test]
fn an_invalid_edge_json_falls_back_to_the_defaults() {
    let w = installed();
    w.release("1.5.0", None);
    w.pending("1.5.0", None, false);
    std::fs::write(w.real("/data/picket/etc/edge.json"), "{ not json").unwrap();
    // The default data_dir still finds pending.json; the compiled-in key doesn't verify.
    failed(&w, stage::VERIFY);
}

/// A result the run can't write (here a directory where it goes) doesn't end the request: the run
/// keeps `pending.json`, so a later run records the outcome once the write works (edge.md §14
/// Interrupted update and Result; README §2 Restarts).
#[test]
fn a_result_that_cannot_be_written_keeps_the_request() {
    let result_path = |w: &World| w.real("/data/picket/bin/update-result.json");

    // After a completed rollback: the next run tries the update again, as after a power cut.
    let w = installed();
    w.sys.st.borrow_mut().ready = Ready::Except(vec!["1.5.0".into()]);
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req-1"), false);
    std::fs::create_dir(result_path(&w)).unwrap();
    match w.update() {
        RunEnd::Unrecorded(r) => assert_eq!(r.stage.as_deref(), Some(stage::READINESS), "{r:?}"),
        other => panic!("{other:?}"),
    }
    let writes = w
        .sys
        .calls()
        .iter()
        .filter(|c| c.starts_with("chown /data/picket/bin/update-result.json"))
        .count();
    assert_eq!(writes, 4, "one try and three retries");
    assert!(w.pending_path().exists(), "the request is kept");
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert!(!w.snapshot_exists(), "the rollback completed");
    std::fs::remove_dir(result_path(&w)).unwrap();
    let r = failed(&w, stage::READINESS);
    assert_eq!(r.request_id.as_deref(), Some("req-1"));

    // After a successful update: the next run finds it installed and records ok, touching nothing.
    let w = installed();
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req-2"), false);
    std::fs::create_dir(result_path(&w)).unwrap();
    match w.update() {
        RunEnd::Unrecorded(r) => assert_eq!(r.outcome, Outcome::Ok, "{r:?}"),
        other => panic!("{other:?}"),
    }
    assert!(w.pending_path().exists(), "the request is kept");
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    assert!(!w.snapshot_exists(), "never rolled back later");
    std::fs::remove_dir(result_path(&w)).unwrap();
    w.sys.clear_calls();
    let r = result(w.update());
    assert_eq!(
        (r.outcome, r.version.as_str(), r.request_id.as_deref()),
        (Outcome::Ok, "1.5.0", Some("req-2"))
    );
    assert!(mutating(&w.sys.calls()).is_empty(), "{:?}", w.sys.calls());
    assert!(!w.pending_path().exists());
}

/// A failed update whose restarts are slow and keep failing still ends with its result: every
/// step inside the run has its own bound, and systemd mustn't kill the run first, or the
/// rollback is cut short with no `rollback` result and the next run meets the same limit
/// (edge.md §14 step 4 and Result).
#[test]
fn a_slow_failing_run_is_not_cut_short_by_systemd() {
    let w = installed();
    // systemd's default 90 s stop plus 90 s start for every job.
    w.sys.st.borrow_mut().job_cost = std::time::Duration::from_secs(180);
    w.sys.fail("systemctl restart picket-edge-helper.service", 100);
    w.sys.fail("systemctl restart picket-edge.service", 100);
    w.release("1.5.0", None);
    w.pending("1.5.0", None, false);
    let start = w.sys.st.borrow().clock;
    failed(&w, stage::ROLLBACK);
    let took = w.sys.st.borrow().clock - start;
    assert!(took > std::time::Duration::from_secs(30 * 60), "{took:?}");
    let unit = w.unit_text(UPDATE_SERVICE).unwrap();
    let timeouts: Vec<&str> = unit
        .lines()
        .filter_map(|l| {
            l.strip_prefix("TimeoutStartSec=")
                .or_else(|| l.strip_prefix("TimeoutSec="))
                .or_else(|| l.strip_prefix("RuntimeMaxSec="))
        })
        .collect();
    assert_eq!(
        timeouts,
        ["infinity"],
        "systemd would kill a run that takes {took:?}"
    );
}
