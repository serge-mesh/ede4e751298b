//! The self-update handoff (edge.md §14 step 1; build-and-test.md §5 "Self-update", "Edge
//! requests"): a signed test release served by the mock core is downloaded into
//! `releases/<version>/`, checked (BLAKE3 against the offer, minisign against `release_keys` with
//! the trusted comment naming that version and this architecture) and handed over in
//! `pending.json`; a release whose signature names another version is never handed over.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use picket_edge::service::{self, Options, Running, Tuning};
use support::{MockCore, wait_until, write_edge_json};

const T: Duration = Duration::from_secs(30);
const REQ: &str = "0123456789abcdef";

struct Dirs {
    _tmp: tempfile::TempDir,
    config: PathBuf,
    data: PathBuf,
    run: PathBuf,
}

fn dirs() -> Dirs {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Dirs {
        config: root.join("dev/edge.json"),
        data: root.join("dev/edge"),
        run: root.join("dev/run"),
        _tmp: tmp,
    }
}

fn tuning(d: &Dirs) -> Tuning {
    let mut t = Tuning {
        platform: Some(picket_edge::paths::HostPlatform::Debian),
        clock: Some(picket_edge::clock::Clock::fixed(true)),
        update_result: Some(d.data.join("no-update-result.json")),
        service: Some(false),
        firmware_file: d.data.join("no-such-version-file"),
        ..Default::default()
    };
    t.session.backoff_min = Duration::from_millis(50);
    t.session.backoff_max = Duration::from_millis(300);
    t.convergence.retry_min = Duration::from_millis(50);
    t.convergence.retry_max = Duration::from_millis(300);
    t.firewall.socket = d.run.join("no-helper.sock");
    t
}

struct Release {
    tarball: Vec<u8>,
    blake3: String,
    pk: String,
}

/// A tarball signed with a fresh key; the trusted comment names `signed_as`.
fn release(signed_as: &str) -> (Release, Vec<u8>) {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let tarball = b"not really a tarball, but bytes to sign".repeat(100);
    let comment = format!("picket-edge {signed_as} {}", std::env::consts::ARCH);
    let sig = minisign::sign(Some(&kp.pk), &kp.sk, &tarball[..], Some(&comment), Some("test")).unwrap();
    (
        Release {
            blake3: picket_api::ids::object_id(&tarball),
            tarball,
            pk: kp.pk.to_base64(),
        },
        sig.to_string().into_bytes(),
    )
}

fn serve(core: &MockCore, version: &str, r: &Release, sig: &[u8]) {
    let arch = std::env::consts::ARCH;
    core.with(|s| {
        s.objects.insert(
            format!("releases/{version}/picket-edge-{version}-{arch}.tar.gz"),
            r.tarball.clone(),
        );
        s.objects.insert(
            format!("releases/{version}/picket-edge-{version}-{arch}.tar.gz.minisig"),
            sig.to_vec(),
        );
    });
}

fn config(release: Value) -> Value {
    json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
        "listeners": [],
        "release": release,
    })
}

async fn start(d: &Dirs, core: &MockCore, pk: &str) -> Running {
    start_t(d, core, pk, tuning(d)).await
}

async fn start_t(d: &Dirs, core: &MockCore, pk: &str, t: Tuning) -> Running {
    write_edge_json(
        &d.config,
        Some(core),
        json!({"updates_enabled": true, "release_keys": [pk]}),
    );
    service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        t,
        |_| {},
    )
    .await
    .unwrap()
}

fn pending(d: &Dirs) -> Option<Value> {
    std::fs::read(d.data.join("releases/pending.json"))
        .ok()
        .map(|b| serde_json::from_slice(&b).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn install_now_downloads_verifies_and_hands_over_once() {
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.9");
    serve(&core, "9.9.9", &rel, &sig);
    let id = core.set_config(&config(
        json!({"auto_update": false, "version": "9.9.9", "blake3": rel.blake3,
        "install_now": {"id": REQ, "version": "9.9.9", "blake3": rel.blake3}}),
    ));
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    assert!(
        wait_until(T, || pending(&d).is_some()).await,
        "pending.json written"
    );
    let p = pending(&d).unwrap();
    assert_eq!(p["version"], "9.9.9");
    assert_eq!(p["request_id"], REQ);
    assert!(p.get("rollback").is_none());
    let arch = std::env::consts::ARCH;
    let dir = d.data.join("releases/9.9.9");
    assert_eq!(
        std::fs::read(dir.join(format!("picket-edge-9.9.9-{arch}.tar.gz"))).unwrap(),
        rel.tarball
    );
    assert_eq!(
        std::fs::read(dir.join(format!("picket-edge-9.9.9-{arch}.tar.gz.minisig"))).unwrap(),
        sig
    );
    // The id counts as applied at the handoff (edge.md §14), and goes into hello/heartbeats.
    assert!(wait_until(T, || edge.state.get().applied.install_now.as_deref() == Some(REQ)).await);
    // `picket-edge update --check` reports a pending handoff.
    let v = picket_edge::release::update_command(&edge, false).await.unwrap();
    assert_eq!(v["pending"], true);
    assert_eq!(v["offered"], "9.9.9");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_signed_for_another_version_is_never_handed_over() {
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.8");
    serve(&core, "9.9.9", &rel, &sig);
    let id = core.set_config(&config(
        json!({"auto_update": false, "version": "9.9.9", "blake3": rel.blake3,
        "install_now": {"id": REQ, "version": "9.9.9", "blake3": rel.blake3}}),
    ));
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(pending(&d).is_none(), "nothing handed over");
    assert_ne!(edge.state.get().applied.install_now.as_deref(), Some(REQ));
    assert!(
        !d.data.join("releases/9.9.9").exists(),
        "the refused download is deleted"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_update_hands_over_without_a_request_id() {
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.9");
    serve(&core, "9.9.9", &rel, &sig);
    let id = core.set_config(&config(
        json!({"auto_update": true, "version": "9.9.9", "blake3": rel.blake3}),
    ));
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    assert!(
        wait_until(T, || pending(&d).is_some()).await,
        "pending.json written"
    );
    let p = pending(&d).unwrap();
    assert_eq!(p["version"], "9.9.9");
    assert!(p["request_id"].is_null());
    r.shutdown().await;

    // A downgrade without `rollback` is never auto-installed.
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("0.0.1");
    serve(&core, "0.0.1", &rel, &sig);
    let id = core.set_config(&config(
        json!({"auto_update": true, "version": "0.0.1", "blake3": rel.blake3}),
    ));
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(pending(&d).is_none());
    r.shutdown().await;
}

fn tarball_key(version: &str) -> String {
    format!(
        "releases/{version}/picket-edge-{version}-{}.tar.gz",
        std::env::consts::ARCH
    )
}

fn gets(core: &MockCore, key: &str) -> u32 {
    core.with(|s| s.object_gets.get(key).copied().unwrap_or(0))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_auto_update_download_backs_off() {
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.9");
    serve(&core, "9.9.9", &rel, &sig);
    // The offer names other bytes: every download fails its BLAKE3 check.
    let wrong = picket_api::ids::object_id(b"other bytes");
    let id = core.set_config(&config(
        json!({"auto_update": true, "version": "9.9.9", "blake3": wrong}),
    ));
    let mut t = tuning(&d);
    t.convergence.every = Duration::from_millis(100);
    let r = start_t(&d, &core, &rel.pk, t).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    let key = tarball_key("9.9.9");
    assert!(wait_until(T, || gets(&core, &key) >= 1).await);
    // Many convergence rounds later: no second download (README §2 Bounded: retries back off).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        gets(&core, &key),
        1,
        "the failed download isn't retried every round"
    );
    assert!(pending(&d).is_none());
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_release_download_never_holds_up_convergence() {
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.9");
    serve(&core, "9.9.9", &rel, &sig);
    let key = tarball_key("9.9.9");
    core.with(|s| s.object_delays.insert(key.clone(), Duration::from_secs(6)));
    let offer = json!({"auto_update": true, "version": "9.9.9", "blake3": rel.blake3});
    let id = core.set_config(&config(offer.clone()));
    let started = std::time::Instant::now();
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the first config waited {:?} for the download",
        started.elapsed()
    );
    assert!(wait_until(T, || gets(&core, &key) >= 1).await, "download started");
    // A new config goes live while the tarball is still downloading.
    let mut c2 = config(offer);
    c2["logging"] = json!({"spool_after_s": 2});
    let id2 = core.set_config(&c2);
    core.changed(&id2);
    let t2 = std::time::Instant::now();
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id2.as_str())).await);
    assert!(
        t2.elapsed() < Duration::from_secs(2),
        "convergence waited {:?} for the download",
        t2.elapsed()
    );
    assert!(
        wait_until(T, || pending(&d).is_some()).await,
        "handed over once the download finished"
    );
    assert_eq!(gets(&core, &key), 1, "one download");
    r.shutdown().await;
}

/// `picket-edge update --install` uses the service's own handoff (edge.md §14; §2 `releases/`):
/// while the service's download runs it starts no second job, so neither job's cleanup deletes
/// the other's `releases/<version>/` mid-download, and the service's job hands the release over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cli_install_shares_the_services_handoff() {
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.9");
    serve(&core, "9.9.9", &rel, &sig);
    let key = tarball_key("9.9.9");
    core.with(|s| s.object_delays.insert(key.clone(), Duration::from_secs(2)));
    let id = core.set_config(&config(
        json!({"auto_update": false, "version": "9.9.9", "blake3": rel.blake3,
        "install_now": {"id": REQ, "version": "9.9.9", "blake3": rel.blake3}}),
    ));
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    // The service's download (for the install_now) is under way, into releases/9.9.9/.
    assert!(wait_until(T, || gets(&core, &key) == 1).await);
    let marker = d.data.join("releases/9.9.9/in-progress");
    std::fs::write(&marker, b"").unwrap();
    let v = picket_edge::release::update_command(&edge, true).await.unwrap();
    assert!(marker.exists(), "the running download's directory is kept");
    assert_eq!(gets(&core, &key), 1, "no second download");
    assert_eq!(v["handed_off"], false, "{v}");
    assert_eq!(v["reason"], "a download is in progress", "{v}");
    assert!(
        wait_until(T, || pending(&d).is_some()).await,
        "pending.json written"
    );
    assert_eq!(
        pending(&d).unwrap()["request_id"],
        REQ,
        "the service's job handed it over"
    );
    assert_eq!(gets(&core, &key), 1, "one download");
    r.shutdown().await;
}

/// `picket-edge update --install` outlives the admin command that started it (edge.md §14; the
/// admin socket cuts a command off at its timeout, edge.md §15): the download goes on and hands
/// the release over, the reply says it is still downloading, and the handoff is free afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cli_install_cut_off_by_the_admin_timeout_still_hands_over() {
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.9");
    serve(&core, "9.9.9", &rel, &sig);
    let key = tarball_key("9.9.9");
    core.with(|s| s.object_delays.insert(key.clone(), Duration::from_secs(2)));
    let id = core.set_config(&config(
        json!({"auto_update": false, "version": "9.9.9", "blake3": rel.blake3}),
    ));
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    edge.admin.set_timeout(Duration::from_millis(600));
    let reply = edge
        .admin
        .call(Arc::clone(&edge), "update", json!({"check": false}))
        .await;
    let v = reply.expect("the command answers before it is cut off");
    assert_eq!(v["handed_off"], false, "{v}");
    assert_eq!(v["downloading"], true, "{v}");
    assert!(
        wait_until(T, || pending(&d).is_some()).await,
        "the download went on and handed the release over"
    );
    assert_eq!(gets(&core, &key), 1, "one download");
    // The handoff is free again: once the updater has taken pending.json, another install runs.
    std::fs::remove_file(d.data.join("releases/pending.json")).unwrap();
    edge.admin.set_timeout(picket_edge::admin::HANDLER_TIMEOUT);
    let v = install_once_free(&edge).await;
    assert_eq!(v["handed_off"], true, "{v}");
    r.shutdown().await;
}

/// `update --install` once the running job has freed the slot (it does so right after writing
/// `pending.json`); a slot never freed stays "in progress" and fails the caller's check.
async fn install_once_free(edge: &Arc<picket_edge::edge::Edge>) -> Value {
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let v = picket_edge::release::update_command(edge, true).await.unwrap();
        if v["reason"] != "a download is in progress" || std::time::Instant::now() >= end {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The same, when the command's task is cancelled outright mid-download.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_cli_install_still_hands_over() {
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.9");
    serve(&core, "9.9.9", &rel, &sig);
    let key = tarball_key("9.9.9");
    core.with(|s| s.object_delays.insert(key.clone(), Duration::from_secs(2)));
    let id = core.set_config(&config(
        json!({"auto_update": false, "version": "9.9.9", "blake3": rel.blake3}),
    ));
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    let e = Arc::clone(&edge);
    let cli = tokio::spawn(async move { picket_edge::release::update_command(&e, true).await });
    assert!(wait_until(T, || gets(&core, &key) == 1).await, "download started");
    cli.abort();
    assert!(
        wait_until(T, || pending(&d).is_some()).await,
        "the download went on and handed the release over"
    );
    std::fs::remove_file(d.data.join("releases/pending.json")).unwrap();
    let v = install_once_free(&edge).await;
    assert_eq!(v["handed_off"], true, "nothing stays reserved: {v}");
    r.shutdown().await;
}

/// One download at a time (edge.md §14; §2 `releases/`): installs asked for at the same moment
/// (two CLI calls; a CLI call and convergence) never both start one. Each round releases two
/// threads from a spin barrier straight into the handoff's check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_installs_start_one_download() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let core = MockCore::start().await;
    let d = dirs();
    let (rel, sig) = release("9.9.9");
    serve(&core, "9.9.9", &rel, &sig);
    let key = tarball_key("9.9.9");
    let id = core.set_config(&config(
        json!({"auto_update": false, "version": "9.9.9", "blake3": rel.blake3}),
    ));
    let r = start(&d, &core, &rel.pk).await;
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    let releases = d.data.join("releases");
    for round in 0..60 {
        let before = gets(&core, &key);
        let gate = Arc::new(AtomicUsize::new(0));
        let calls: Vec<_> = (0..2)
            .map(|_| {
                let (e, gate) = (Arc::clone(&edge), Arc::clone(&gate));
                let rt = tokio::runtime::Handle::current();
                tokio::task::spawn_blocking(move || {
                    gate.fetch_add(1, Ordering::SeqCst);
                    while gate.load(Ordering::SeqCst) < 2 {
                        std::hint::spin_loop();
                    }
                    rt.block_on(picket_edge::release::update_command(&e, true))
                })
            })
            .collect();
        let mut handed = 0;
        for c in calls {
            if c.await.unwrap().is_ok_and(|v| v["handed_off"] == true) {
                handed += 1;
            }
        }
        let n = gets(&core, &key) - before;
        assert!(n <= 1, "round {round}: {n} downloads at once");
        assert_eq!(handed, 1, "round {round}: one call hands the release over");
        // The updater takes the handoff; the next round starts from nothing.
        std::fs::remove_file(releases.join("pending.json")).unwrap();
        std::fs::remove_dir_all(releases.join("9.9.9")).unwrap();
    }
    r.shutdown().await;
}
