//! The "Core data directory" suite (build-and-test.md §5): `init` on an empty directory, each
//! allowed leftover and each case it must refuse, cut off at each step; `run` without the
//! marker; `identity`; `probe` against the same core, another core and nothing listening;
//! `passwd`; two instances side by side (core.md §13, storage.md §2).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::fs;
use std::path::Path;

use common::*;
use picket_core::identity::Identity;
use picket_core::instance::{self, INIT_FILE, INIT_STEPS, InitOptions, InitStep, MARKER};

fn init_args(dir: &Path, web: u16, edge: u16) -> Vec<String> {
    vec![
        "init".into(),
        "--data-dir".into(),
        dir.display().to_string(),
        "--web-port".into(),
        web.to_string(),
        "--edge-port".into(),
        edge.to_string(),
    ]
}

fn run_init(dir: &Path, web: u16, edge: u16) -> std::process::Output {
    let args = init_args(dir, web, edge);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_bin(&refs)
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn init_on_empty_dir_prints_password_once_and_writes_marker_last() {
    let d = tempfile::tempdir().unwrap();
    let (w, e) = free_ports();
    let o = run_init(d.path(), w, e);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let pw = fs::read_to_string(d.path().join(instance::INITIAL_PASSWORD)).unwrap();
    let pw = pw.trim();
    assert_eq!(pw.len(), 24);
    assert_eq!(stdout(&o).matches(pw).count(), 1, "printed once");
    let marker: serde_json::Value =
        serde_json::from_slice(&fs::read(d.path().join(MARKER)).unwrap()).unwrap();
    assert_eq!(marker["format"], 1);
    assert_eq!(marker["instance_id"].as_str().unwrap().len(), 32);
    assert!(marker["created_at"].as_str().is_some());
    assert!(!d.path().join(INIT_FILE).exists());
    for f in [
        "core.db",
        "metrics.db",
        "identity/core.key",
        "identity/core.crt",
        "lanca/ca.key",
        "lanca/ca.crt",
        "secrets.key",
        "logs",
        "blobs",
        "lists",
        "staging",
        "tmp",
    ] {
        assert!(d.path().join(f).exists(), "{f}");
    }
    use std::os::unix::fs::PermissionsExt;
    for f in [
        instance::INITIAL_PASSWORD,
        "identity/core.key",
        "identity/core.crt",
        "lanca/ca.key",
        "lanca/ca.crt",
        "secrets.key",
    ] {
        let m = fs::metadata(d.path().join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "{f}");
    }
    // The settings init was given.
    let c = rusqlite::Connection::open(d.path().join("core.db")).unwrap();
    let wp: String = c
        .query_row(
            "SELECT value_json FROM settings WHERE key = 'web.port'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(wp, w.to_string());
}

#[test]
fn init_into_missing_dir_creates_it() {
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("nested/core");
    let (w, e) = free_ports();
    let o = run_init(&target, w, e);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(target.join(MARKER).exists());
}

#[test]
fn allowed_leftovers() {
    // lost+found
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("lost+found")).unwrap();
    let (w, e) = free_ports();
    assert_eq!(run_init(d.path(), w, e).status.code(), Some(0));
    assert!(d.path().join("lost+found").is_dir());

    // A pre-placed identity is kept.
    let d = tempfile::tempdir().unwrap();
    let id = Identity::create(&d.path().join("identity")).unwrap();
    let o = run_init(d.path(), w, e);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stdout(&o).contains(&id.fingerprint));
    let printed = run_bin(&["identity", "--data-dir", &d.path().display().to_string()]);
    assert_eq!(stdout(&printed).trim(), id.fingerprint);

    // An empty identity/ counts as none: init fills it.
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("identity")).unwrap();
    assert_eq!(run_init(d.path(), w, e).status.code(), Some(0));
    assert!(d.path().join("identity/core.key").exists());
}

#[test]
fn refusals_name_what_they_found_and_change_nothing() {
    let (w, e) = free_ports();
    type Setup = Box<dyn Fn(&Path)>;
    let cases: Vec<(&str, Setup)> = vec![
        (
            "stray.txt",
            Box::new(|p: &Path| fs::write(p.join("stray.txt"), b"x").unwrap()),
        ),
        (
            "somedir",
            Box::new(|p: &Path| fs::create_dir(p.join("somedir")).unwrap()),
        ),
        (
            "core.db",
            Box::new(|p: &Path| fs::write(p.join("core.db"), b"not ours").unwrap()),
        ),
        (
            ".hidden",
            Box::new(|p: &Path| fs::write(p.join(".hidden"), b"x").unwrap()),
        ),
    ];
    for (name, setup) in cases {
        let d = tempfile::tempdir().unwrap();
        setup(d.path());
        let before = listing(d.path());
        let o = run_init(d.path(), w, e);
        assert_ne!(o.status.code(), Some(0), "{name}");
        assert!(stderr(&o).contains(name), "{name}: {}", stderr(&o));
        assert_eq!(listing(d.path()), before, "{name}: nothing changed");
    }
    // An unusable pre-placed identity.
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("identity")).unwrap();
    fs::write(d.path().join("identity/core.key"), b"garbage").unwrap();
    let o = run_init(d.path(), w, e);
    assert_ne!(o.status.code(), Some(0));
    assert!(stderr(&o).contains("identity"));
    assert_eq!(listing(d.path()), vec!["identity"]);
    // A complete instance (marker included) is refused.
    let d = tempfile::tempdir().unwrap();
    assert_eq!(run_init(d.path(), w, e).status.code(), Some(0));
    let before = listing(d.path());
    let core_db = fs::read(d.path().join("core.db")).unwrap();
    let o = run_init(d.path(), w, e);
    assert_ne!(o.status.code(), Some(0));
    assert!(stderr(&o).contains(MARKER));
    assert_eq!(listing(d.path()), before);
    assert_eq!(fs::read(d.path().join("core.db")).unwrap(), core_db);
}

#[test]
fn init_cut_off_at_each_step_then_restarted() {
    let (w, e) = free_ports();
    for &stop in INIT_STEPS {
        for preplaced in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let pre = preplaced.then(|| Identity::create(&d.path().join("identity")).unwrap().fingerprint);
            let opts = InitOptions {
                data_dir: d.path().to_path_buf(),
                web_port: Some(w),
                edge_port: Some(e),
                lanca_zones: None,
            };
            let r = instance::init_with_hook(&opts, &mut |s: InitStep| {
                if s == stop {
                    anyhow::bail!("simulated crash")
                } else {
                    Ok(())
                }
            });
            assert!(r.is_err(), "{stop:?}");
            assert!(
                d.path().join(INIT_FILE).exists(),
                "{stop:?}: the init file is still there"
            );
            if stop == InitStep::MarkerWritten {
                // The instance is complete: init refuses, run accepts (and drops the init file).
                let o = run_init(d.path(), w, e);
                assert_ne!(o.status.code(), Some(0));
                assert!(stderr(&o).contains(MARKER));
                let (child, port) = spawn_run(d.path());
                let fp =
                    picket_core::identity::fingerprint_from_cert_file(&d.path().join("identity")).unwrap();
                wait_for_core(port, &fp);
                kill(child);
                assert!(!d.path().join(INIT_FILE).exists());
                continue;
            }
            // No marker yet: run refuses with 78.
            let o = run_bin(&["run", "--data-dir", &d.path().display().to_string()]);
            assert_eq!(o.status.code(), Some(78), "{stop:?}: {}", stderr(&o));
            // A new init cleans up and starts over.
            let o = run_init(d.path(), w, e);
            assert_eq!(
                o.status.code(),
                Some(0),
                "{stop:?} preplaced={preplaced}: {}",
                stderr(&o)
            );
            assert!(stdout(&o).contains("interrupted init"), "{stop:?}");
            assert!(d.path().join(MARKER).exists());
            assert!(!d.path().join(INIT_FILE).exists());
            let fp = picket_core::identity::fingerprint_from_cert_file(&d.path().join("identity")).unwrap();
            if let Some(pre) = pre {
                assert_eq!(fp, pre, "{stop:?}: a pre-placed identity survives the restart");
            }
            // Nothing from the first attempt is left over: the password file matches the hash.
            let pw = fs::read_to_string(d.path().join(instance::INITIAL_PASSWORD)).unwrap();
            let c = rusqlite::Connection::open(d.path().join("core.db")).unwrap();
            let hash: String = c
                .query_row("SELECT password_argon2id FROM ui_account", [], |r| r.get(0))
                .unwrap();
            assert!(
                picket_core::web::auth::verify_password(pw.trim(), &hash),
                "{stop:?}"
            );
        }
    }
}

#[test]
fn run_without_marker_exits_78_naming_the_directory() {
    let d = tempfile::tempdir().unwrap();
    let o = run_bin(&["run", "--data-dir", &d.path().display().to_string()]);
    assert_eq!(o.status.code(), Some(78));
    assert!(
        stderr(&o).contains(&d.path().display().to_string()),
        "{}",
        stderr(&o)
    );
    // It created nothing.
    assert!(listing(d.path()).is_empty());
    // A missing directory too.
    let o = run_bin(&[
        "run",
        "--data-dir",
        &d.path().join("absent").display().to_string(),
    ]);
    assert_eq!(o.status.code(), Some(78));
    assert!(!d.path().join("absent").exists());
}

#[test]
fn newer_database_exits_78() {
    let (d, _, _, _) = init_dir();
    {
        let c = rusqlite::Connection::open(d.path().join("core.db")).unwrap();
        c.execute_batch("PRAGMA user_version = 999").unwrap();
    }
    let o = run_bin(&["run", "--data-dir", &d.path().display().to_string()]);
    assert_eq!(o.status.code(), Some(78));
    assert!(stderr(&o).contains("newer"), "{}", stderr(&o));
}

#[test]
fn newer_metrics_db_or_missing_core_db_exits_78() {
    // storage.md §5: either database newer than the binary exits 78; a marker without its
    // core.db is a broken data directory, never a reason to start empty.
    let (d, _, _, _) = init_dir();
    {
        let c = rusqlite::Connection::open(d.path().join("metrics.db")).unwrap();
        c.execute_batch("PRAGMA user_version = 999").unwrap();
    }
    let o = run_bin(&["run", "--data-dir", &d.path().display().to_string()]);
    assert_eq!(o.status.code(), Some(78));
    assert!(stderr(&o).contains("metrics.db"), "{}", stderr(&o));

    let (d, _, _, _) = init_dir();
    for f in ["core.db", "core.db-wal", "core.db-shm"] {
        let _ = fs::remove_file(d.path().join(f));
    }
    let o = run_bin(&["run", "--data-dir", &d.path().display().to_string()]);
    assert_eq!(o.status.code(), Some(78));
    assert!(stderr(&o).contains("core.db"), "{}", stderr(&o));
    assert!(!d.path().join("core.db").exists(), "run never creates a database");
}

#[test]
fn identity_probe_and_two_instances_side_by_side() {
    let (a, out_a, _, _) = init_dir();
    let (b, out_b, _, _) = init_dir();
    assert_ne!(out_a.fingerprint, out_b.fingerprint);
    let o = run_bin(&["identity", "--data-dir", &a.path().display().to_string()]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(stdout(&o).trim(), out_a.fingerprint);

    let (ca, edge_a) = spawn_run(a.path());
    let (cb, edge_b) = spawn_run(b.path());
    wait_for_core(edge_a, &out_a.fingerprint);
    wait_for_core(edge_b, &out_b.fingerprint);
    let probe = |port: u16, fp: &str| {
        run_bin(&[
            "probe",
            &format!("https://127.0.0.1:{port}"),
            "--expect-identity",
            fp,
        ])
        .status
        .code()
    };
    assert_eq!(probe(edge_a, &out_a.fingerprint), Some(0), "the same core");
    assert_eq!(probe(edge_b, &out_b.fingerprint), Some(0), "the same core");
    assert_eq!(probe(edge_a, &out_b.fingerprint), Some(3), "another core");
    assert_eq!(probe(edge_b, &out_a.fingerprint), Some(3), "another core");
    kill(ca);
    kill(cb);
    // Nothing listening.
    assert_eq!(probe(free_port(), &out_a.fingerprint), Some(4));
}

#[test]
fn passwd_sets_a_new_password_offline() {
    let (d, out, _, _) = init_dir();
    let mut child = std::process::Command::new(bin())
        .args(["passwd", "--data-dir"])
        .arg(d.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"a brand new password\n")
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(
        !d.path().join(instance::INITIAL_PASSWORD).exists(),
        "initial-password goes with the first change"
    );
    let c = rusqlite::Connection::open(d.path().join("core.db")).unwrap();
    let hash: String = c
        .query_row("SELECT password_argon2id FROM ui_account", [], |r| r.get(0))
        .unwrap();
    assert!(picket_core::web::auth::verify_password(
        "a brand new password",
        &hash
    ));
    assert!(!picket_core::web::auth::verify_password(&out.password, &hash));
    // A short password changes nothing.
    let mut child = std::process::Command::new(bin())
        .args(["passwd", "--data-dir"])
        .arg(d.path())
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"short\n").unwrap();
    assert_ne!(child.wait_with_output().unwrap().status.code(), Some(0));
    // --generate prints one.
    let o = run_bin(&[
        "passwd",
        "--data-dir",
        &d.path().display().to_string(),
        "--generate",
    ]);
    assert_eq!(o.status.code(), Some(0));
    let pw = stdout(&o).trim().to_string();
    let hash: String = c
        .query_row("SELECT password_argon2id FROM ui_account", [], |r| r.get(0))
        .unwrap();
    assert!(picket_core::web::auth::verify_password(&pw, &hash));
    // Without an instance: 78.
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        run_bin(&[
            "passwd",
            "--data-dir",
            &empty.path().display().to_string(),
            "--generate"
        ])
        .status
        .code(),
        Some(78)
    );
}

#[test]
fn edges_add_registers_an_edge() {
    let (d, _, _, _) = init_dir();
    let fp = picket_api::ids::fingerprint_spki(b"an edge key");
    let dir = d.path().display().to_string();
    let o = run_bin(&[
        "edges",
        "add",
        "--data-dir",
        &dir,
        "--name",
        "ucg-fiber",
        "--key",
        &fp,
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let id = stdout(&o).trim().to_string();
    assert!(id.starts_with("e-"));
    let c = rusqlite::Connection::open(d.path().join("core.db")).unwrap();
    let (name, key): (String, String) = c
        .query_row("SELECT name, key_sha256 FROM edges WHERE id = ?1", [&id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((name.as_str(), key.as_str()), ("ucg-fiber", fp.as_str()));
    // The same key again is refused; so is a bad key.
    assert_ne!(
        run_bin(&[
            "edges",
            "add",
            "--data-dir",
            &dir,
            "--name",
            "other",
            "--key",
            &fp
        ])
        .status
        .code(),
        Some(0)
    );
    assert_ne!(
        run_bin(&[
            "edges",
            "add",
            "--data-dir",
            &dir,
            "--name",
            "x",
            "--key",
            "SHA256:nope"
        ])
        .status
        .code(),
        Some(0)
    );
}

#[test]
fn the_binary_stops_cleanly_on_sigterm() {
    // systemd and the container entry point stop core with SIGTERM; a clean stop exits 0, so
    // `Restart=on-failure` and Docker's on-failure policy leave it stopped.
    let (d, out, _, _) = init_dir();
    let (mut child, edge) = spawn_run(d.path());
    wait_for_core(edge, &out.fingerprint);
    let killed = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let mut status = None;
    for _ in 0..200 {
        if let Some(s) = child.try_wait().unwrap() {
            status = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let Some(status) = status else {
        kill(child);
        panic!("core didn't stop within 10 s of SIGTERM");
    };
    assert_eq!(status.code(), Some(0));
    // Nothing is left listening.
    let o = run_bin(&[
        "probe",
        &format!("https://127.0.0.1:{edge}"),
        "--expect-identity",
        &out.fingerprint,
    ]);
    assert_eq!(o.status.code(), Some(4));
}

#[tokio::test(flavor = "multi_thread")]
async fn one_process_per_data_directory() {
    // A newer CLI (or a second `run`) against a live core must not migrate, clean or write under
    // it: it fails at once with 75, and changes nothing.
    let c = start_core(Some(serde_json::json!({"web": {"tls": "off"}}))).await;
    let dir = c.dir.path().display().to_string();
    let staged = c.dir.path().join("staging").join("download.part");
    fs::write(&staged, b"in progress").unwrap();
    let hash = || {
        rusqlite::Connection::open(c.dir.path().join("core.db"))
            .unwrap()
            .query_row("SELECT password_argon2id FROM ui_account", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap()
    };
    let before = hash();
    let o = run_bin(&["passwd", "--data-dir", &dir, "--generate"]);
    assert_eq!(o.status.code(), Some(75), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("another picket-core process"),
        "{}",
        stderr(&o)
    );
    assert_eq!(hash(), before);
    let key = picket_api::ids::fingerprint_spki(b"an edge key");
    let o = run_bin(&["edges", "add", "--data-dir", &dir, "--name", "e", "--key", &key]);
    assert_eq!(o.status.code(), Some(75), "{}", stderr(&o));
    let o = run_bin(&["run", "--data-dir", &dir]);
    assert_eq!(o.status.code(), Some(75), "{}", stderr(&o));
    assert!(staged.exists(), "the second run cleaned nothing");
    assert!(c.dir.path().join("initial-password").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn start_failures_a_restart_can_fix_are_not_78() {
    // core.md §13: 78 is for no marker, a failed migration, a database newer than the binary and
    // too little space. A port in use is temporary: systemd must restart core.
    let busy = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let (d, _, _, _) = init_dir();
    set_settings(d.path(), serde_json::json!({"web": {"tls": "off", "port": port}}));
    let stop = tokio_util::sync::CancellationToken::new();
    let e = picket_core::run::start(d.path(), stop.clone())
        .await
        .err()
        .unwrap();
    stop.cancel();
    assert_eq!(e.code, 1, "{}", e.message);
    assert!(e.message.contains("web port"), "{}", e.message);
}
