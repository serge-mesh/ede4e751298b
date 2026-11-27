//! The command line as the binary runs it (edge.md §15; edge-unifi.md §2, `units`).

use std::path::Path;

use super::mutating;
use crate::api::{Outcome, UnitsOutput};
use crate::cli;
use crate::platform::Platform;
use crate::release::BINARIES;
use crate::testing::World;
use crate::units::{self, UPDATE_SERVICE};
use crate::update::{self, Env};

fn run(w: &World, exe_dir: Option<&Path>, args: &[&str]) -> (u8, String) {
    let mut out = Vec::new();
    let code = cli::run(&w.root, &w.sys, exe_dir, args, &mut out);
    (code, String::from_utf8(out).unwrap())
}

#[test]
fn units_prints_what_install_writes_and_changes_nothing() {
    let w = World::new(Platform::Unifi);
    w.write_edge_json(Some("/volume1/.picket"));
    let (code, out) = run(&w, None, &["units"]);
    assert_eq!(code, 0);
    let printed: UnitsOutput = serde_json::from_str(&out).unwrap();
    assert_eq!(printed.format, 1);
    assert!(w.sys.calls().is_empty(), "{:?}", w.sys.calls());
    assert!(!w.exists("/data/picket/bin"));
    // What an older updater's check accepts, and exactly what install writes.
    assert_eq!(units::parse_units_output(out.as_bytes()).unwrap(), printed.units);
    w.install("1.4.0", false).unwrap();
    for (name, text) in &printed.units {
        assert_eq!(w.unit_text(name).as_ref(), Some(text), "{name}");
    }
    assert!(printed.units[crate::units::EDGE].contains("ReadWritePaths=-/volume1\n"));
    // --platform picks the other layout.
    let (code, out) = run(&w, None, &["units", "--platform", "debian"]);
    assert_eq!(code, 0);
    assert!(out.contains("/opt/picket/bin/current/picket-edge-update --platform debian"));
}

#[test]
fn units_refuses_a_bad_edge_json() {
    let w = World::new(Platform::Unifi);
    std::fs::write(w.real("/data/picket/etc/edge.json"), "{ nope").unwrap();
    let (code, out) = run(&w, None, &["units"]);
    assert_eq!((code, out.as_str()), (1, ""));
}

#[test]
fn bad_arguments_exit_2_and_change_nothing() {
    let w = World::new(Platform::Unifi);
    for args in [
        &["bogus"][..],
        &["install", "--platform", "macos"],
        &["units", "--force"],
        &["--force"],
    ] {
        assert_eq!(run(&w, None, args), (2, String::new()), "{args:?}");
    }
    assert!(w.sys.calls().is_empty());
    assert_eq!(
        run(&w, None, &["--version"]),
        (0, format!("picket-edge-update {}\n", crate::VERSION))
    );
    assert_eq!(run(&w, None, &["--help"]), (0, cli::USAGE.to_string()));
}

#[test]
fn install_takes_the_binaries_next_to_it() {
    let w = World::new(Platform::Unifi);
    for b in BINARIES {
        std::fs::write(w.src.path().join(b), format!("#!{b} cli\n")).unwrap();
    }
    let (code, out) = run(&w, Some(w.src.path()), &["install", "--platform", "unifi"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains(&format!("picket-edge {} installed for unifi", crate::VERSION)),
        "{out}"
    );
    assert_eq!(w.current().as_deref(), Some(crate::VERSION));
    for b in BINARIES {
        assert_eq!(
            std::fs::read_to_string(w.real(format!("/data/picket/bin/{}/{b}", crate::VERSION))).unwrap(),
            format!("#!{b} cli\n")
        );
    }
    let (code, out) = run(&w, Some(w.src.path()), &["install"]);
    assert_eq!(code, 0);
    assert!(out.ends_with("(nothing to change)\n"), "{out}");
    // Without its own directory, install has nothing to copy.
    assert_eq!(run(&w, None, &["install"]).0, 1);
}

/// The update service passes the platform its units were written for, so an update works even
/// where detection would now pick the other one (a firmware that moved UniFi's udapi directory,
/// or a root filesystem without it).
#[test]
fn the_update_service_passes_its_platform() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    std::fs::remove_dir_all(w.real("/data/udapi-config")).unwrap();
    assert_eq!(Platform::detect(&w.root), Platform::Debian);
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req"), false);
    // The arguments the unit runs the updater with.
    let text = w.unit_text(UPDATE_SERVICE).unwrap();
    let exec = text.lines().find_map(|l| l.strip_prefix("ExecStart=")).unwrap();
    let args: Vec<&str> = exec.split_whitespace().skip(1).collect();
    assert_eq!(args, ["--platform", "unifi", "--data-dir", "/data/picket/var"]);
    // Detection alone looks for a Debian install, fails and leaves the request.
    assert_eq!(run(&w, None, &[]).0, 1);
    assert!(w.pending_path().exists());
    w.sys.set_active(UPDATE_SERVICE, "activating");
    let (code, _) = run(&w, None, &args);
    w.sys.set_active(UPDATE_SERVICE, "inactive");
    assert_eq!(code, 0);
    let r = w.result().unwrap();
    assert_eq!(
        (r.outcome, r.version.as_str(), r.request_id.as_deref()),
        (Outcome::Ok, "1.5.0", Some("req"))
    );
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    assert!(!w.pending_path().exists());
    w.assert_own_service_untouched();
}

#[test]
fn update_needs_root_and_an_install() {
    let w = World::new(Platform::Unifi);
    w.pending("1.5.0", None, false);
    // No install: nothing to lock or report into, and the error says what to do.
    assert_eq!(run(&w, None, &["--platform", "unifi"]).0, 1);
    let e = update::run(&Env {
        root: &w.root,
        sys: &w.sys,
        platform: Platform::Unifi,
        data_dir: None,
    })
    .unwrap_err()
    .to_string();
    assert!(e.contains("picket-edge-update install"), "{e}");
    assert!(w.pending_path().exists());
    w.install("1.4.0", false).unwrap();
    w.sys.st.borrow_mut().is_root = false;
    w.sys.clear_calls();
    assert_eq!(run(&w, None, &["--platform", "unifi"]).0, 1);
    assert!(w.result().is_none());
    assert!(w.pending_path().exists());
    assert!(mutating(&w.sys.calls()).is_empty());
}

/// With a custom `data_dir` and an `edge.json` the update can't read, the update still works in
/// the `data_dir` its path unit watches, because the unit passes it. Otherwise the run finds no
/// `pending.json`, writes no result, and the path unit starts it again and again (edge.md §14
/// Interrupted update; README §2 Bounded).
#[test]
fn the_update_service_passes_its_data_dir() {
    let w = World::new(Platform::Unifi);
    std::fs::write(
        w.real("/data/picket/etc/edge.json"),
        format!(
            "{{\"data_dir\": \"/data/picket/edge\", \"release_keys\": [\"{}\"]}}\n",
            w.keys.pub_b64
        ),
    )
    .unwrap();
    w.sys.st.borrow_mut().data_dir = "/data/picket/edge".into();
    w.install("1.4.0", false).unwrap();
    assert!(
        w.unit_text(units::UPDATE_PATH)
            .unwrap()
            .contains("PathExists=/data/picket/edge/releases/pending.json\n")
    );
    std::fs::create_dir_all(w.real("/data/picket/edge/releases")).unwrap();
    let pending = w.real("/data/picket/edge/releases/pending.json");
    std::fs::write(&pending, r#"{"version": "1.5.0", "request_id": "req"}"#).unwrap();
    std::fs::write(w.real("/data/picket/etc/edge.json"), "{ corrupt").unwrap();

    let text = w.unit_text(UPDATE_SERVICE).unwrap();
    let exec = text.lines().find_map(|l| l.strip_prefix("ExecStart=")).unwrap();
    let args: Vec<&str> = exec.split_whitespace().skip(1).collect();
    w.sys.set_active(UPDATE_SERVICE, "activating");
    let (code, _) = run(&w, None, &args);
    w.sys.set_active(UPDATE_SERVICE, "inactive");
    assert_eq!(code, 0);
    // It found the request and ended it: no release there, so stage verify.
    let r = w.result().expect("a result");
    assert_eq!(
        (r.outcome, r.stage.as_deref(), r.request_id.as_deref()),
        (Outcome::Failed, Some("verify"), Some("req"))
    );
    assert!(!pending.exists());
}

/// A result the run couldn't write fails the service (exit 1), so the journal and
/// `systemctl status` show it, and `pending.json` stays for the next run (edge.md §14).
#[test]
fn an_unwritten_result_fails_the_service_and_keeps_the_request() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    w.release("1.5.0", None);
    w.pending("1.5.0", Some("req"), false);
    std::fs::create_dir(w.real("/data/picket/bin/update-result.json")).unwrap();
    w.sys.set_active(UPDATE_SERVICE, "activating");
    let (code, _) = run(
        &w,
        None,
        &["--platform", "unifi", "--data-dir", "/data/picket/var"],
    );
    w.sys.set_active(UPDATE_SERVICE, "inactive");
    assert_eq!(code, 1);
    assert!(w.pending_path().exists());
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
}
