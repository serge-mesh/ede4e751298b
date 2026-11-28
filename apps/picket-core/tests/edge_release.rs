//! The release offer (build-and-test.md §5 "Release offer"; core.md §5, edge.md §14): a signed
//! test release registered at start; an older, a newer and a current edge; Update with
//! `auto_update` off; a bundled release failing its signature.

use crate::common;

use std::io::Cursor;
use std::path::Path;

use common::edge::{FakeEdge, eventually, heartbeat, hello, send};
use jiff::Timestamp;
use picket_core::config::model::EntityKind;
use picket_core::config::{Actor, Op};
use serde_json::json;

const VERSION: &str = picket_api::VERSION;

/// Writes `<dir>/<VERSION>/picket-edge-<VERSION>-<arch>.tar.gz` and its signature, signed with
/// `sk` and the trusted comment `comment`. Returns the tarball.
fn write_release(
    dir: &Path,
    arch: &str,
    sk: &minisign::SecretKey,
    pk: &minisign::PublicKey,
    comment: &str,
) -> Vec<u8> {
    write_release_of(dir, VERSION, arch, sk, pk, comment)
}

/// [`write_release`] for `version` (its bytes differ per version).
fn write_release_of(
    dir: &Path,
    version: &str,
    arch: &str,
    sk: &minisign::SecretKey,
    pk: &minisign::PublicKey,
    comment: &str,
) -> Vec<u8> {
    let d = dir.join(version);
    std::fs::create_dir_all(&d).unwrap();
    let mut tar: Vec<u8> = version.as_bytes().to_vec();
    tar.extend((0..200_000u32).map(|i| (i % 251) as u8));
    let sig = minisign::sign(Some(pk), sk, Cursor::new(&tar), Some(comment), None).unwrap();
    let name = format!("picket-edge-{version}-{arch}.tar.gz");
    std::fs::write(d.join(&name), &tar).unwrap();
    std::fs::write(d.join(format!("{name}.minisig")), sig.to_string()).unwrap();
    tar
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_release_is_offered_per_edge_and_served() {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let rel = tempfile::tempdir().unwrap();
    let tar = write_release(
        rel.path(),
        "x86_64",
        &kp.sk,
        &kp.pk,
        &format!("picket-edge {VERSION} x86_64"),
    );
    let c = common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: rel.path().to_path_buf(),
            release_keys: vec![kp.pk.to_base64()],
            ..Default::default()
        },
    )
    .await;
    let offer = c.state.edges.releases.offer().expect("a release is offered");
    assert_eq!(offer.version, VERSION);
    let b3 = picket_api::ids::object_id(&tar);
    assert_eq!(offer.tarballs.get("x86_64"), Some(&b3));
    assert!(!offer.tarballs.contains_key("aarch64"));

    // An older edge: offered core's version, no rollback.
    let old = FakeEdge::registered(&c, "old").await;
    let mut h = hello("b1");
    h["edge_version"] = json!("0.0.1");
    let (_ws1, _) = old.session(h).await;
    assert!(eventually(|| async { old.config(None).await.2["release"]["version"] == VERSION }).await);
    let cfg = old.config(None).await.2;
    assert_eq!(cfg["release"]["blake3"], b3.as_str());
    assert_eq!(cfg["release"]["auto_update"], true);
    assert!(cfg["release"]["rollback"].is_null() || cfg["release"]["rollback"] == false);

    // A newer edge (after a core rollback): rollback.
    let newer = FakeEdge::registered(&c, "newer").await;
    let mut h = hello("b2");
    h["edge_version"] = json!("999.0.0");
    let (_ws2, _) = newer.session(h).await;
    assert!(eventually(|| async { newer.config(None).await.2["release"]["rollback"] == true }).await);

    // A current edge: offered its own version (it installs nothing).
    let cur = FakeEdge::registered(&c, "current").await;
    let (_ws3, _) = cur.session(hello("b3")).await;
    assert!(eventually(|| async { cur.config(None).await.2["release"]["version"] == VERSION }).await);

    // An edge on another architecture gets no offer.
    let arm = FakeEdge::registered(&c, "arm").await;
    let mut h = hello("b4");
    h["arch"] = json!("aarch64");
    let (_ws4, _) = arm.session(h).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(arm.config(None).await.2["release"].is_null());

    // The tarball and its signature are served (immutable, ETag = BLAKE3).
    let r = old
        .get(&format!(
            "/objects/releases/{VERSION}/picket-edge-{VERSION}-x86_64.tar.gz"
        ))
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["etag"], format!("\"{b3}\"").as_str());
    assert_eq!(r.bytes().await.unwrap().as_ref(), tar.as_slice());
    let r = old
        .get(&format!(
            "/objects/releases/{VERSION}/picket-edge-{VERSION}-x86_64.tar.gz.minisig"
        ))
        .await;
    assert_eq!(r.status(), 200);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains(&format!("picket-edge {VERSION} x86_64"))
    );
    assert_eq!(
        old.get(&format!(
            "/objects/releases/{VERSION}/picket-edge-{VERSION}-aarch64.tar.gz"
        ))
        .await
        .status(),
        404
    );

    // Update with auto_update off: install_now with the offered release's version and BLAKE3.
    let mut body = c
        .state
        .config
        .model_of(EntityKind::Edge)
        .await
        .unwrap()
        .edges
        .get(&old.id)
        .cloned()
        .map(|e| serde_json::to_value(e).unwrap())
        .unwrap();
    body["auto_update"] = json!(false);
    c.state
        .config
        .apply(
            EntityKind::Edge,
            Op::Update(old.id.clone(), body),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    let id = picket_core::edges::requests::install_now(&c.state, &old.id)
        .await
        .unwrap();
    assert!(
        eventually(|| async {
            let cfg = old.config(None).await.2;
            cfg["release"]["auto_update"] == false
                && cfg["release"]["install_now"]["id"] == id.as_str()
                && cfg["release"]["install_now"]["blake3"] == b3.as_str()
                && cfg["release"]["install_now"]["version"] == VERSION
        })
        .await
    );
    assert!(
        !c.state
            .alerts
            .get_by_key("release_invalid")
            .await
            .unwrap()
            .is_some_and(|a| a.state == picket_core::alerts::AlertState::Open)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bundled_release_failing_its_check_offers_nothing_and_alerts() {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let rel = tempfile::tempdir().unwrap();
    // Signed by another key than core's release_keys.
    write_release(
        rel.path(),
        "x86_64",
        &other.sk,
        &other.pk,
        &format!("picket-edge {VERSION} x86_64"),
    );
    // Signed by the right key, but its trusted comment names another architecture.
    write_release(
        rel.path(),
        "aarch64",
        &kp.sk,
        &kp.pk,
        &format!("picket-edge {VERSION} x86_64"),
    );
    let c = common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: rel.path().to_path_buf(),
            release_keys: vec![kp.pk.to_base64()],
            ..Default::default()
        },
    )
    .await;
    assert!(c.state.edges.releases.offer().is_none());
    let a = c
        .state
        .alerts
        .get_by_key("release_invalid")
        .await
        .unwrap()
        .expect("release_invalid");
    assert_eq!(a.state, picket_core::alerts::AlertState::Open);
    let e = FakeEdge::registered(&c, "e").await;
    let (_ws, _) = e.session(hello("b1")).await;
    assert!(e.config(None).await.2["release"].is_null());
    assert_eq!(
        e.get(&format!(
            "/objects/releases/{VERSION}/picket-edge-{VERSION}-x86_64.tar.gz"
        ))
        .await
        .status(),
        404
    );
    assert!(
        picket_core::edges::requests::install_now(&c.state, &e.id)
            .await
            .is_err()
    );

    // A release that passes its check resolves the alert.
    write_release(
        rel.path(),
        "x86_64",
        &kp.sk,
        &kp.pk,
        &format!("picket-edge {VERSION} x86_64"),
    );
    write_release(
        rel.path(),
        "aarch64",
        &kp.sk,
        &kp.pk,
        &format!("picket-edge {VERSION} aarch64"),
    );
    c.state.edges.releases.register(&c.state).await.unwrap();
    assert!(c.state.edges.releases.offer().is_some());
    let a = c
        .state
        .alerts
        .get_by_key("release_invalid")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.state, picket_core::alerts::AlertState::Resolved);
}

/// Runs one retention job to its end (heavy lane, P3).
async fn run_retention(c: &common::Core) {
    let before = c.state.scheduler.heavy.stats().completed;
    c.state.scheduler.heavy.submit(
        picket_core::scheduler::Priority::P3,
        Box::new(picket_core::retention::RetentionJob::new(c.state.clone(), false)),
    );
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    while tokio::time::Instant::now() < end {
        let s = c.state.scheduler.heavy.stats();
        if s.completed > before && s.queued == 0 && s.running.is_none() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the retention job never finished");
}

#[tokio::test(flavor = "multi_thread")]
async fn releases_nothing_offers_go_72_hours_after_they_stop_being_offered() {
    // storage.md §4 names no retention for `edge_releases` (a spec gap; every core upgrade adds
    // one, README §2 Bounded): `edges::releases::ReleaseRetention` keeps core's own release and
    // every one a config core may still serve offers, drops the others' rows 72 h after
    // retention first found nothing offering them (never from `added_at`: a core rollback's own
    // release is old), then every blob nothing names. A blob another row still names stays.
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let rel = tempfile::tempdir().unwrap();
    let tar = write_release(
        rel.path(),
        "x86_64",
        &kp.sk,
        &kp.pk,
        &format!("picket-edge {VERSION} x86_64"),
    );
    let c = common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: rel.path().to_path_buf(),
            release_keys: vec![kp.pk.to_base64()],
            ..Default::default()
        },
    )
    .await;
    c.state.clock.pin(true);
    let b3 = picket_api::ids::object_id(&tar);
    let long_ago = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(24 * 30)));
    let dir = c.state.data_dir.clone();
    let b3_core = b3.clone();
    // An earlier core's release, one whose row names the bytes of core's own, and a release blob
    // no row names (a registration replaced it).
    let (old_b3, orphan) = c
        .state
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let kind = picket_core::blobs::kind::RELEASE;
            let old = picket_core::blobs::put(&tx, &dir, kind, b"an older edge release")?;
            let orphan = picket_core::blobs::put(&tx, &dir, kind, b"a replaced edge release")?;
            for (version, blob) in [("0.0.1", &old), ("0.0.2", &b3_core)] {
                tx.execute(
                    "INSERT INTO edge_releases(version, arch, blob, minisig, added_at) VALUES (?1, 'x86_64', ?2, 'sig', ?3)",
                    rusqlite::params![version, blob, long_ago],
                )?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>((old, orphan))
        })
        .await
        .unwrap();
    let e = FakeEdge::registered(&c, "e").await;
    let (_ws, _) = e.session(hello("b1")).await;
    let path = |v: &str| format!("/objects/releases/{v}/picket-edge-{v}-x86_64.tar.gz");
    let versions = || async {
        c.state
            .db
            .read(|conn| {
                let mut st = conn.prepare("SELECT version FROM edge_releases ORDER BY version")?;
                let v = st
                    .query_map([], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
            .unwrap()
    };
    let stored = |b: &str| {
        let p = picket_core::blobs::path(&c.state.data_dir, b).unwrap();
        let (db, b) = (c.state.db.clone(), b.to_string());
        async move {
            let row = db
                .read(move |conn| picket_core::blobs::info(conn, &b))
                .await
                .unwrap();
            (row.is_some(), p.exists())
        }
    };

    let backdate = |sql: &'static str| {
        let db = c.state.db.clone();
        async move {
            let at = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(73)));
            db.write(move |conn| {
                conn.execute(sql, rusqlite::params![at, VERSION])?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap();
        }
    };

    // Nothing offers the older ones, as retention finds now: they stay (and are served) for 72 h
    // from here, however long ago core began offering its own. The blob no row names goes.
    backdate("UPDATE edge_releases SET added_at = ?1 WHERE version = ?2").await;
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(versions().await, vec!["0.0.1", "0.0.2", VERSION]);
    assert_eq!(stored(&old_b3).await, (true, true));
    assert_eq!(stored(&orphan).await, (false, false));
    assert_eq!(e.get(&path("0.0.1")).await.status(), 200);

    // 72 h after they stopped being offered, only core's own rows stay.
    backdate("UPDATE edge_releases SET unoffered_at = ?1 WHERE version <> ?2").await;
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(versions().await, vec![VERSION]);
    assert_eq!(stored(&old_b3).await, (false, false));
    assert_eq!(stored(&b3).await, (true, true), "core's own release stays");
    assert_eq!(e.get(&path("0.0.1")).await.status(), 404);
    let r = e.get(&path(VERSION)).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), tar.as_slice());
}

/// Core with the signed releases of `versions` (x86_64) in its release directory; it registers
/// its own (`VERSION`) at start.
async fn core_with_releases(versions: &[&str]) -> (common::Core, tempfile::TempDir, Vec<Vec<u8>>) {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let rel = tempfile::tempdir().unwrap();
    let tars = versions
        .iter()
        .map(|v| {
            write_release_of(
                rel.path(),
                v,
                "x86_64",
                &kp.sk,
                &kp.pk,
                &format!("picket-edge {v} x86_64"),
            )
        })
        .collect();
    let c = common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: rel.path().to_path_buf(),
            release_keys: vec![kp.pk.to_base64()],
            ..Default::default()
        },
    )
    .await;
    c.state.clock.pin(true);
    (c, rel, tars)
}

/// Sets `sql` (with `?1` the time 73 h ago) in core.db.
async fn backdate_73h(c: &common::Core, sql: &'static str) {
    let at = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(73)));
    c.state
        .db
        .write(move |conn| {
            conn.execute(sql, [at])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
}

fn release_path(v: &str) -> String {
    format!("/objects/releases/{v}/picket-edge-{v}-x86_64.tar.gz")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_a_held_config_still_offers_stays() {
    // README §2 (configuration and data still in use are kept), storage.md §4 Pins: a budget-held
    // edge keeps its whole config across a core upgrade (bundles.md §2 Budget; `edges::publish`),
    // so it still offers the previous release, `install_now` included, for as long as the hold
    // lasts; the edge downloads what its config offers (edge.md §14). That release stays while a
    // config core may still serve an edge offers it, and its 72 h run from when none does.
    const OLD: &str = "0.0.1";
    let (c, _rel, tars) = core_with_releases(&[OLD, VERSION]).await;
    // The core before the upgrade offered OLD, and the edge was asked to install it now.
    c.state
        .edges
        .releases
        .register_version(&c.state, OLD)
        .await
        .unwrap();
    let e = FakeEdge::registered(&c, "e").await;
    let (mut ws, _) = e.session(hello("b1")).await;
    picket_core::edges::requests::install_now(&c.state, &e.id)
        .await
        .unwrap();
    common::bundles::save(&c, "manual-block", "||blocked.example^\n").await;
    let head = common::bundles::build(&c, "block-common").await.unwrap();
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let held = c.state.edges.publisher.current(&e.id).unwrap();
    let offer = held.config.release.clone().unwrap();
    assert_eq!(offer.version, OLD);
    assert!(offer.install_now.is_some());
    // The edge's budget falls below the bundle it runs: its whole config holds.
    c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE bundle_versions SET stats_json = json_set(stats_json, '$.edge_mem_bytes', 20971520) WHERE head_id = ?1",
                [head],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let set_budget = |mib: u32| {
        let st = c.state.clone();
        let id = e.id.clone();
        async move {
            let m = st.config.model().await.unwrap();
            let mut def = m.edges.get(&id).unwrap().clone();
            def.settings.bundle_budget_mib = mib;
            let body = serde_json::to_value(&def).unwrap();
            st.config
                .apply(EntityKind::Edge, Op::Update(id.clone(), body), Actor::cli(), None)
                .await
                .unwrap();
        }
    };
    set_budget(16).await;
    // The upgrade: core registers its own release; the held config still offers OLD, which the
    // edge fetches.
    c.state.edges.releases.register(&c.state).await.unwrap();
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    assert_eq!(c.state.edges.publisher.current(&e.id).unwrap().id, held.id);
    let (_, etag, cfg) = e.config(None).await;
    assert_eq!(etag.as_deref(), Some(held.id.as_str()));
    assert_eq!(cfg["release"]["version"], OLD);
    assert_eq!(cfg["release"]["install_now"]["version"], OLD);

    // 73 h after core began offering its own release (a core rollback's own rows are as old),
    // the release the held config offers is still served.
    backdate_73h(&c, "UPDATE edge_releases SET added_at = ?1").await;
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    let r = e.get(&release_path(OLD)).await;
    assert_eq!(r.status(), 200, "the release the edge's held config offers");
    assert_eq!(r.bytes().await.unwrap().as_ref(), tars[0].as_slice());

    // The hold ends: the edge gets core's release. The held config stays pinned until the edge's
    // `have` releases it, and OLD with it.
    set_budget(64).await;
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let new = c.state.edges.publisher.current(&e.id).unwrap();
    assert_ne!(new.id, held.id);
    assert_eq!(new.config.release.as_ref().unwrap().version, VERSION);
    let (_, _, cfg) = e.config(None).await;
    assert_eq!(cfg["release"]["version"], VERSION);
    backdate_73h(&c, "UPDATE edge_releases SET added_at = ?1").await;
    run_retention(&c).await;
    assert_eq!(e.get(&release_path(OLD)).await.status(), 200, "pinned");
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["have"] = json!({"config": [new.id], "fetched": new.id});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    let pinned = || async {
        let (db, id) = (c.state.db.clone(), held.id.clone());
        db.read(move |conn| {
            Ok::<_, anyhow::Error>(conn.query_row(
                "SELECT count(*) FROM edge_pins WHERE kind = 'config' AND id = ?1",
                [id],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap()
    };
    assert!(eventually(|| async { pinned().await == 0 }).await);
    // Nothing offers OLD from here: it stays 72 h more, then goes.
    run_retention(&c).await;
    assert_eq!(
        e.get(&release_path(OLD)).await.status(),
        200,
        "just stopped being offered"
    );
    backdate_73h(
        &c,
        "UPDATE edge_releases SET unoffered_at = ?1 WHERE unoffered_at IS NOT NULL",
    )
    .await;
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(e.get(&release_path(OLD)).await.status(), 404);
    assert_eq!(e.get(&release_path(VERSION)).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn release_bytes_a_feed_run_also_names_are_served_and_kept() {
    // storage.md §1–§4: blobs are deduplicated by hash and keep the kind they were first
    // registered with, so a release's bytes a feed downloaded first (even a rejected run) are a
    // `download` blob. The release is served all the same (its `edge_releases` row names the
    // blob), and its blob stays while any row names it.
    const OLD: &str = "0.0.1";
    let (c, _rel, tars) = core_with_releases(&[OLD, VERSION]).await;
    // Start-up's feed runs and builds first (they register blobs and runs of their own).
    common::settled(&c).await;
    let (dir, tar) = (c.state.data_dir.clone(), tars[0].clone());
    let b3 = c
        .state
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let b3 = picket_core::blobs::put(&tx, &dir, picket_core::blobs::kind::DOWNLOAD, &tar)?;
            tx.execute(
                "INSERT INTO feed_runs(feed_id, downloaded_at, status, blob, error)
                 VALUES ('manual-block', ?2, 'rejected', ?1, 'not a list')",
                rusqlite::params![b3, picket_core::util::now_ts()],
            )?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(b3)
        })
        .await
        .unwrap();
    c.state
        .edges
        .releases
        .register_version(&c.state, OLD)
        .await
        .unwrap();
    let e = FakeEdge::registered(&c, "e").await;
    let (mut ws, _) = e.session(hello("b1")).await;
    assert!(eventually(|| async { e.config(None).await.2["release"]["version"] == OLD }).await);
    let r = e.get(&release_path(OLD)).await;
    assert_eq!(r.status(), 200, "the offered release, whatever kind its blob has");
    assert_eq!(r.bytes().await.unwrap().as_ref(), tars[0].as_slice());

    // Core moves on; 72 h later OLD's rows go, but the feed run still names the bytes.
    c.state.edges.releases.register(&c.state).await.unwrap();
    assert!(eventually(|| async { e.config(None).await.2["release"]["version"] == VERSION }).await);
    let id = c.state.edges.publisher.current(&e.id).unwrap().id.clone();
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["have"] = json!({"config": [id], "fetched": id});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    let rows = || async {
        c.state
            .db
            .read(|conn| {
                Ok::<_, anyhow::Error>(conn.query_row(
                    "SELECT count(*) FROM edge_pins WHERE kind = 'config'",
                    [],
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap()
    };
    assert!(eventually(|| async { rows().await == 1 }).await);
    run_retention(&c).await;
    backdate_73h(
        &c,
        "UPDATE edge_releases SET unoffered_at = ?1 WHERE unoffered_at IS NOT NULL",
    )
    .await;
    let b = b3.clone();
    let at = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(73)));
    c.state
        .db
        .write(move |conn| {
            conn.execute("UPDATE blobs SET created_at = ?1 WHERE blake3 = ?2", [at, b])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(e.get(&release_path(OLD)).await.status(), 404);
    let p = picket_core::blobs::path(&c.state.data_dir, &b3).unwrap();
    let b = b3.clone();
    let row = c
        .state
        .db
        .read(move |conn| picket_core::blobs::info(conn, &b))
        .await
        .unwrap();
    assert!(row.is_some() && p.exists(), "the feed run still names it");
}
