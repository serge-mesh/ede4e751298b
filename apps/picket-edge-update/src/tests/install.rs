//! `picket-edge-update install` (edge-unifi.md §2, §1; edge.md §14 Lock).

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::{mode, mutating};
use crate::accounts::SYSUSERS_CONF;
use crate::platform::Platform;
use crate::system::System;
use crate::testing::World;
use crate::units::{ACCOUNTS, EDGE, HELPER, UPDATE_PATH, UPDATE_SERVICE};

fn ssd_world() -> World {
    let w = World::new(Platform::Unifi);
    w.write_edge_json(Some("/volume1/.picket"));
    w
}

#[test]
fn fresh_unifi_install_every_step() {
    let w = ssd_world();
    let rep = w.install("1.4.0", false).unwrap();
    assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);

    // Step 2: binaries and bin/current.
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    for b in crate::release::BINARIES {
        let p = w.real(format!("/data/picket/bin/1.4.0/{b}"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), format!("#!{b} 1.4.0\n"));
        assert_eq!(mode(&p), 0o755);
        assert_eq!(w.sys.owner_of(&format!("/data/picket/bin/1.4.0/{b}")), (0, 0));
    }
    assert_eq!(mode(&w.real("/data/picket/bin")), 0o755);
    assert_eq!(mode(&w.real("/data/picket/bin/.lock")), 0o600);

    // Step 3: accounts.
    assert_eq!(
        std::fs::read_to_string(w.real("/data/picket/etc/sysusers.conf")).unwrap(),
        SYSUSERS_CONF
    );
    assert!(w.sys.calls().contains(&"systemd-sysusers".to_string()));
    crate::accounts::verify(&w.root).unwrap();

    // Step 4: directories, owners, modes.
    assert_eq!(w.sys.owner_of("/data/picket/etc"), (0, 880));
    assert_eq!(mode(&w.real("/data/picket/etc")), 0o750);
    assert_eq!(w.sys.owner_of("/data/picket/etc/edge.json"), (0, 880));
    assert_eq!(mode(&w.real("/data/picket/etc/edge.json")), 0o640);
    assert_eq!(w.sys.owner_of("/data/picket/var"), (880, 880));
    assert_eq!(mode(&w.real("/data/picket/var")), 0o750);
    assert_eq!(w.sys.owner_of("/data/picket/helper"), (881, 881));
    assert_eq!(mode(&w.real("/data/picket/helper")), 0o700);
    for d in [
        "/volume1/.picket",
        "/volume1/.picket/bundles",
        "/volume1/.picket/spool",
        "/volume1/.picket/verdicts",
    ] {
        assert_eq!(w.sys.owner_of(d), (880, 880), "{d}");
        assert_eq!(mode(&w.real(d)), 0o750, "{d}");
    }
    let marker = std::fs::read_to_string(w.real("/volume1/.picket/.picket-ssd")).unwrap();
    let id = std::fs::read_to_string(w.real("/data/picket/var/ssd-id")).unwrap();
    assert_eq!(marker, id);
    assert_eq!(marker.trim().len(), 32);
    assert_eq!(w.sys.owner_of("/volume1/.picket/.picket-ssd"), (880, 880));
    assert_eq!(w.sys.owner_of("/data/picket/var/ssd-id"), (880, 880));
    assert_eq!(mode(&w.real("/volume1/.picket/.picket-ssd")), 0o640);
    assert_eq!(mode(&w.real("/data/picket/var/ssd-id")), 0o640);

    // Step 5: units as files, the same text `units` prints.
    for (name, text) in w.units() {
        let p = w.real(format!("/etc/systemd/system/{name}"));
        assert!(std::fs::symlink_metadata(&p).unwrap().file_type().is_file());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), text);
        assert_eq!(mode(&p), 0o644);
    }
    assert!(w.unit_text(EDGE).unwrap().contains("ReadWritePaths=-/volume1\n"));
    for u in [HELPER, EDGE, UPDATE_PATH] {
        assert_eq!(
            w.sys.links(u).into_iter().collect::<Vec<_>>(),
            [format!("multi-user.target.wants/{u}")]
        );
    }
    assert!(w.sys.links(ACCOUNTS).is_empty());
    assert!(w.sys.links(UPDATE_SERVICE).is_empty());

    // Step 6: reload, enable, then start the helper, the edge, the path unit.
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl daemon-reload",
            "systemctl enable picket-edge-helper.service",
            "systemctl enable picket-edge-update.path",
            "systemctl enable picket-edge.service",
            "systemctl start picket-edge-helper.service",
            "systemctl start picket-edge.service",
            "systemctl start picket-edge-update.path",
        ]
    );
    assert_eq!(
        w.sys.state(ACCOUNTS),
        "active",
        "pulled in by the helper and edge"
    );
    assert_eq!(w.sys.state(UPDATE_SERVICE), "inactive");
    w.assert_own_service_untouched();
}

#[test]
fn second_run_changes_and_restarts_nothing() {
    let w = ssd_world();
    w.install("1.4.0", false).unwrap();
    w.sys.clear_calls();
    let rep = w.install("1.4.0", false).unwrap();
    assert!(rep.actions.is_empty(), "{:?}", rep.actions);
    assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
    assert!(mutating(&w.sys.calls()).is_empty(), "{:?}", w.sys.calls());
    assert!(!w.sys.calls().contains(&"systemd-sysusers".to_string()));
}

#[test]
fn rerun_from_bin_current_is_a_no_op() {
    // `/data/picket/bin/current/picket-edge-update install`: the source is bin/<version>/.
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    w.sys.clear_calls();
    let rep = crate::install::install(
        &w.root,
        &w.sys,
        &crate::install::InstallOptions {
            platform: None,
            force: false,
            src_dir: w.real("/data/picket/bin/1.4.0"),
            version: "1.4.0".into(),
        },
    )
    .unwrap();
    assert!(rep.actions.is_empty(), "{:?}", rep.actions);
    assert!(mutating(&w.sys.calls()).is_empty());
}

#[test]
fn repair_rewrites_deleted_and_edited_units() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    let edge = w.unit_text(EDGE).unwrap();
    std::fs::remove_file(w.real("/etc/systemd/system/picket-edge-update.path")).unwrap();
    w.write_unit(EDGE, &format!("{edge}# local edit\n"));
    w.sys.clear_calls();
    let rep = w.install("1.4.0", false).unwrap();
    assert_eq!(w.unit_text(EDGE).unwrap(), edge);
    assert!(w.unit_text(UPDATE_PATH).is_some());
    assert!(
        rep.actions
            .iter()
            .any(|a| a.contains("wrote /etc/systemd/system/picket-edge.service"))
    );
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl daemon-reload",
            "systemctl enable picket-edge-update.path",
            "systemctl reenable picket-edge.service",
            "systemctl restart picket-edge.service",
            "systemctl restart picket-edge-update.path",
        ]
    );
    w.assert_own_service_untouched();
}

/// A unit replaced by a symlink becomes a file again (units are files, so systemd loads them
/// before `/data` is mounted), and a corrupted binary is rewritten and its unit restarted
/// (edge-unifi.md §2 steps 2, 5 and 6).
#[test]
fn repair_replaces_a_symlinked_unit_and_a_corrupted_binary() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    let accounts = w.unit_text(ACCOUNTS).unwrap();
    std::fs::write(w.real("/acc.service"), &accounts).unwrap();
    std::fs::remove_file(w.real("/etc/systemd/system/picket-accounts.service")).unwrap();
    std::os::unix::fs::symlink(
        w.real("/acc.service"),
        w.real("/etc/systemd/system/picket-accounts.service"),
    )
    .unwrap();
    std::fs::write(w.real("/data/picket/bin/1.4.0/picket-edge-helper"), "corrupt").unwrap();
    w.sys.clear_calls();
    w.install("1.4.0", false).unwrap();
    let p = w.real("/etc/systemd/system/picket-accounts.service");
    assert!(std::fs::symlink_metadata(&p).unwrap().file_type().is_file());
    assert_eq!(std::fs::read_to_string(&p).unwrap(), accounts);
    assert_eq!(
        std::fs::read_to_string(w.real("/data/picket/bin/1.4.0/picket-edge-helper")).unwrap(),
        "#!picket-edge-helper 1.4.0\n"
    );
    let calls = mutating(&w.sys.calls());
    assert!(
        calls.contains(&"systemctl daemon-reload".to_string()),
        "{calls:?}"
    );
    assert!(
        calls.contains(&"systemctl restart picket-edge-helper.service".to_string()),
        "a changed binary: {calls:?}"
    );
    assert!(
        !calls.contains(&"systemctl restart picket-edge.service".to_string()),
        "{calls:?}"
    );
    w.assert_own_service_untouched();
}

/// `bin/.lock` is `root:root` 0600, whatever it was (edge.md §14, Lock).
#[test]
fn the_lock_file_is_repaired_to_root_only() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    let lock = w.real("/data/picket/bin/.lock");
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();
    w.sys.set_owner("/data/picket/bin/.lock", 880, 880);
    w.install("1.4.0", false).unwrap();
    assert_eq!(mode(&lock), 0o600);
    assert_eq!(w.sys.owner_of("/data/picket/bin/.lock"), (0, 0));
}

#[test]
fn changed_install_section_leaves_no_stale_link() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    let edge = w.unit_text(EDGE).unwrap();
    // An older version's [Install] section, enabled.
    w.write_unit(
        EDGE,
        &edge.replace("WantedBy=multi-user.target", "WantedBy=network-online.target"),
    );
    w.sys.systemctl(&["reenable", EDGE]).unwrap();
    assert_eq!(
        w.sys.links(EDGE).into_iter().collect::<Vec<_>>(),
        ["network-online.target.wants/picket-edge.service"]
    );
    w.install("1.4.0", false).unwrap();
    assert_eq!(
        w.sys.links(EDGE).into_iter().collect::<Vec<_>>(),
        ["multi-user.target.wants/picket-edge.service"]
    );
}

#[test]
fn upgrade_restarts_only_what_changed_and_keeps_two_versions() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    w.sys.clear_calls();
    w.install("1.5.0", false).unwrap();
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service"
        ]
    );
    w.install("1.6.0", false).unwrap();
    assert_eq!(w.version_dirs(), ["1.5.0", "1.6.0"]);
    w.assert_own_service_untouched();
}

#[test]
fn newer_current_refused_unless_forced() {
    let w = World::new(Platform::Unifi);
    w.install("1.6.0", false).unwrap();
    w.sys.clear_calls();
    let e = w.install("1.4.0", false).unwrap_err().to_string();
    assert!(e.contains("newer") && e.contains("--force"), "{e}");
    assert_eq!(w.current().as_deref(), Some("1.6.0"));
    assert!(mutating(&w.sys.calls()).is_empty());
    assert_eq!(w.version_dirs(), ["1.6.0"]);
    w.install("1.4.0", true).unwrap();
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert_eq!(w.version_dirs(), ["1.4.0", "1.6.0"]);
    assert!(mutating(&w.sys.calls()).contains(&"systemctl restart picket-edge.service".to_string()));
}

#[test]
fn root_and_systemd_checks_apply_even_with_force() {
    let w = World::new(Platform::Unifi);
    w.sys.st.borrow_mut().is_root = false;
    assert!(w.install("1.4.0", true).unwrap_err().to_string().contains("root"));
    w.sys.st.borrow_mut().is_root = true;
    w.sys.st.borrow_mut().booted = false;
    assert!(
        w.install("1.4.0", true)
            .unwrap_err()
            .to_string()
            .contains("systemd")
    );
    assert!(!w.exists("/data/picket/bin"));
}

#[test]
fn lock_held_by_an_update_then_its_holder_dies() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    let holder = std::fs::File::open(w.real("/data/picket/bin/.lock")).unwrap();
    holder.lock().unwrap();
    // Something to repair, which a waiting install must leave alone.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(w.real("/data/picket/bin"), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    w.sys.set_owner("/data/picket", 0, 880);
    w.sys.clear_calls();
    let before = w.sys.st.borrow().clock;
    let e = w.install("1.5.0", false).unwrap_err().to_string();
    assert!(
        e.contains("an update holds") && e.contains("nothing was changed"),
        "{e}"
    );
    assert!(w.sys.st.borrow().clock - before >= crate::lock::LOCK_WAIT);
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
    assert!(mutating(&w.sys.calls()).is_empty());
    assert!(
        !w.sys.calls().iter().any(|c| c.starts_with("chown")),
        "{:?}",
        w.sys.calls()
    );
    assert_eq!(mode(&w.real("/data/picket/bin")), 0o700);
    assert_eq!(w.version_dirs(), ["1.4.0"]);
    // The holder is killed: the kernel releases the lock.
    drop(holder);
    let rep = w.install("1.5.0", false).unwrap();
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    assert_eq!(mode(&w.real("/data/picket/bin")), 0o755);
    assert_eq!(w.sys.owner_of("/data/picket"), (0, 0));
    assert!(
        rep.actions.iter().any(|a| a == "chmod 755 /data/picket/bin"),
        "{:?}",
        rep.actions
    );
}

#[test]
fn retires_unlisted_units_but_not_core_or_masks_and_deletes_a_leftover_snapshot() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    w.write_unit(
        "picket-edge-old.timer",
        "[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n",
    );
    w.sys.systemctl(&["enable", "picket-edge-old.timer"]).unwrap();
    w.sys.set_active("picket-edge-old.timer", "active");
    w.write_unit(
        "picket-core.service",
        "[Service]\nExecStart=/usr/bin/picket-core\n",
    );
    std::os::unix::fs::symlink("/dev/null", w.real("/etc/systemd/system/picket-gone.service")).unwrap();
    std::fs::create_dir_all(w.real("/data/picket/bin/.units-prev/units")).unwrap();
    std::fs::create_dir_all(w.real("/data/picket/bin/.units-prev.tmp")).unwrap();
    w.sys.clear_calls();
    w.install("1.4.0", false).unwrap();
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl disable --now picket-edge-old.timer",
            "systemctl daemon-reload"
        ]
    );
    assert!(!w.exists("/etc/systemd/system/picket-edge-old.timer"));
    assert!(w.exists("/etc/systemd/system/picket-core.service"));
    assert!(w.exists("/etc/systemd/system/picket-gone.service"));
    assert!(!w.snapshot_exists());
    assert!(!w.exists("/data/picket/bin/.units-prev.tmp"));
}

#[test]
fn masked_unit_is_left_alone() {
    let w = World::new(Platform::Unifi);
    std::os::unix::fs::symlink("/dev/null", w.real("/etc/systemd/system/picket-edge-update.path")).unwrap();
    let rep = w.install("1.4.0", false).unwrap();
    assert!(
        rep.warnings
            .iter()
            .any(|x| x.contains("picket-edge-update.path is masked")),
        "{:?}",
        rep.warnings
    );
    assert_eq!(
        std::fs::read_link(w.real("/etc/systemd/system/picket-edge-update.path")).unwrap(),
        Path::new("/dev/null")
    );
    assert!(
        !w.sys.calls().iter().any(|c| c.starts_with("systemctl ")
            && !c.starts_with("systemctl is-")
            && c.ends_with(UPDATE_PATH))
    );
}

#[test]
fn accounts_with_other_ids_are_refused() {
    let w = World::new(Platform::Unifi);
    w.sys.st.borrow_mut().sysusers_conflict = true;
    let e = w.install("1.4.0", false).unwrap_err().to_string();
    assert!(e.contains("user picket is 1234:880"), "{e}");
    assert!(w.unit_text(EDGE).is_none());
    assert!(!w.exists("/data/picket/var"));
}

#[test]
fn model_and_firmware_warnings_carry_on() {
    let w = World::new(Platform::Unifi);
    w.sys.st.borrow_mut().model = Some("UniFi Dream Machine Pro".into());
    std::fs::write(w.real("/usr/lib/version"), "UCGF.ipq9574.v6.0.16.abc.1\n").unwrap();
    let rep = w.install("1.4.0", false).unwrap();
    assert_eq!(rep.warnings.len(), 2, "{:?}", rep.warnings);
    assert!(rep.warnings[0].contains("UniFi Dream Machine Pro"));
    assert!(rep.warnings[1].contains("below the minimum 6.0.17"));
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
}

#[test]
fn debian_install() {
    let w = World::new(Platform::Debian);
    w.sys.st.borrow_mut().model = None;
    let rep = w.install("1.4.0", false).unwrap();
    assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
    assert_eq!(rep.platform, Some(Platform::Debian));
    assert!(w.exists("/opt/picket/bin/1.4.0/picket-edge"));
    assert_eq!(w.sys.owner_of("/var/lib/picket"), (880, 880));
    assert_eq!(w.sys.owner_of("/var/lib/picket-helper"), (881, 881));
    assert_eq!(w.sys.owner_of("/etc/picket"), (0, 880));
    assert!(w.exists("/etc/picket/sysusers.conf"));
    let edge = w.unit_text(EDGE).unwrap();
    assert!(edge.contains(
        "/opt/picket/bin/current/picket-edge run --config /etc/picket/edge.json --data-dir /var/lib/picket"
    ));
    assert!(!edge.contains("OOMScoreAdjust"));
}

/// `data_dir` and `ssd_dir` belong to the edge: one that overlaps a root-owned path would hand
/// the edge `bin/`, the config or helper directory or the units, so `install` refuses it
/// before changing anything (edge.md §2, edge-unifi.md §2 step 4).
#[test]
fn data_dir_or_ssd_dir_overlapping_root_owned_paths_is_refused() {
    for (data_dir, ssd_dir) in [
        ("/data/picket/helper", None),
        ("/data/picket/bin/var", None),
        ("/data/picket/etc", None),
        ("/data", None),
        ("/etc/systemd/system/picket", None),
        ("/data/picket/var", Some("/data/picket/bin")),
        ("/volume1/.picket/var", Some("/volume1/.picket")),
        ("/data/picket/var", Some("/data/picket/var/ssd")),
    ] {
        let w = World::new(Platform::Unifi);
        let ssd = ssd_dir
            .map(|s| format!("\"{s}\""))
            .unwrap_or_else(|| "null".into());
        std::fs::write(
            w.real("/data/picket/etc/edge.json"),
            format!(
                "{{\"data_dir\": \"{data_dir}\", \"ssd_dir\": {ssd}, \"release_keys\": [\"{}\"]}}",
                w.keys.pub_b64
            ),
        )
        .unwrap();
        let e = w.install("1.4.0", false).unwrap_err().to_string();
        assert!(
            e.contains("overlaps") || e.contains("contains"),
            "{data_dir} {ssd_dir:?}: {e}"
        );
        assert!(!w.exists("/data/picket/bin"), "{data_dir}: nothing changed");
        assert!(!w.exists("/data/picket/helper"), "{data_dir}");
        assert!(w.unit_text(EDGE).is_none());
    }
}

/// A re-run repairs `bin/current` when it points anywhere but `bin/<version>`, even at a
/// directory of the same name elsewhere (edge-unifi.md §2).
#[test]
fn a_current_link_aimed_outside_bin_is_repaired() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    std::fs::create_dir_all(w.real("/elsewhere/1.4.0")).unwrap();
    let cur = w.real("/data/picket/bin/current");
    std::fs::remove_file(&cur).unwrap();
    std::os::unix::fs::symlink(w.real("/elsewhere/1.4.0"), &cur).unwrap();
    w.sys.clear_calls();
    let rep = w.install("1.4.0", false).unwrap();
    assert_eq!(w.current().as_deref(), Some("1.4.0"), "{:?}", rep.actions);
    // The running services may run other binaries: they restart.
    let calls = mutating(&w.sys.calls());
    assert!(
        calls.contains(&"systemctl restart picket-edge.service".to_string()),
        "{calls:?}"
    );
    assert_eq!(w.version_dirs(), ["1.4.0"]);
}

/// `install` never creates `edge.json`; without one it uses the defaults and says how to write
/// it (edge-unifi.md §2 step 4).
#[test]
fn a_missing_edge_json_is_not_created_and_named_in_a_warning() {
    let w = World::new(Platform::Unifi);
    std::fs::remove_file(w.real("/data/picket/etc/edge.json")).unwrap();
    let rep = w.install("1.4.0", false).unwrap();
    assert!(!w.exists("/data/picket/etc/edge.json"));
    assert_eq!(rep.warnings.len(), 1, "{:?}", rep.warnings);
    assert!(
        rep.warnings[0].contains("picket-edge setup"),
        "{:?}",
        rep.warnings
    );
    assert!(
        w.unit_text(EDGE)
            .unwrap()
            .contains("--data-dir /data/picket/var\n")
    );
    assert!(!w.unit_text(EDGE).unwrap().contains("ReadWritePaths=-"));
    assert_eq!(w.sys.state(EDGE), "active");
}

#[test]
fn edge_json_link_is_refused() {
    let w = World::new(Platform::Unifi);
    std::fs::remove_file(w.real("/data/picket/etc/edge.json")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", w.real("/data/picket/etc/edge.json")).unwrap();
    let e = w.install("1.4.0", false).unwrap_err().to_string();
    assert!(e.contains("edge.json"), "{e}");
}

mod ssd {
    use super::*;

    #[test]
    fn not_mounted_or_same_filesystem_is_skipped() {
        let w = ssd_world();
        w.sys.st.borrow_mut().mountinfo = crate::testing::DEFAULT_MOUNTINFO
            .lines()
            .take(2)
            .collect::<Vec<_>>()
            .join("\n");
        let rep = w.install("1.4.0", false).unwrap();
        assert!(
            rep.warnings
                .iter()
                .any(|x| x.contains("/volume1 isn't a mount point")),
            "{:?}",
            rep.warnings
        );
        assert!(!w.exists("/volume1/.picket"));
        assert!(!w.exists("/data/picket/var/ssd-id"));
        // The unit still lists the mount point, so a drive mounted later is visible.
        assert!(w.unit_text(EDGE).unwrap().contains("ReadWritePaths=-/volume1\n"));

        let w = World::new(Platform::Unifi);
        w.write_edge_json(Some("/data/.picket"));
        let rep = w.install("1.4.0", false).unwrap();
        assert!(
            rep.warnings.iter().any(|x| x.contains("same filesystem")),
            "{:?}",
            rep.warnings
        );
        assert!(!w.exists("/data/.picket"));
    }

    #[test]
    fn second_run_is_quiet_and_keeps_the_id() {
        let w = ssd_world();
        w.install("1.4.0", false).unwrap();
        let id = std::fs::read_to_string(w.real("/data/picket/var/ssd-id")).unwrap();
        let rep = w.install("1.4.0", false).unwrap();
        assert!(rep.actions.is_empty(), "{:?}", rep.actions);
        assert_eq!(
            std::fs::read_to_string(w.real("/data/picket/var/ssd-id")).unwrap(),
            id
        );
    }

    /// UniFi formatted the drive: a re-run makes the folder again with the same id, so the edge
    /// recognises the drive as its own (edge-unifi.md §1, §8).
    #[test]
    fn a_formatted_drive_gets_its_folder_and_the_same_id_back() {
        let w = ssd_world();
        w.install("1.4.0", false).unwrap();
        let id = std::fs::read_to_string(w.real("/data/picket/var/ssd-id")).unwrap();
        std::fs::remove_dir_all(w.real("/volume1/.picket")).unwrap();
        w.sys.clear_calls();
        let rep = w.install("1.4.0", false).unwrap();
        assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
        assert_eq!(
            std::fs::read_to_string(w.real("/volume1/.picket/.picket-ssd")).unwrap(),
            id
        );
        assert_eq!(
            std::fs::read_to_string(w.real("/data/picket/var/ssd-id")).unwrap(),
            id
        );
        for sub in ["bundles", "spool", "verdicts"] {
            assert!(w.exists(format!("/volume1/.picket/{sub}")), "{sub}");
        }
        assert!(mutating(&w.sys.calls()).is_empty(), "{:?}", w.sys.calls());
    }

    #[test]
    fn a_symlinked_marker_is_never_written_through() {
        let w = ssd_world();
        w.install("1.4.0", false).unwrap();
        std::fs::remove_file(w.real("/volume1/.picket/.picket-ssd")).unwrap();
        std::fs::write(w.real("/victim"), "keep").unwrap();
        std::os::unix::fs::symlink(w.real("/victim"), w.real("/volume1/.picket/.picket-ssd")).unwrap();
        w.sys.clear_calls();
        let rep = w.install("1.4.0", false).unwrap();
        assert_eq!(std::fs::read_to_string(w.real("/victim")).unwrap(), "keep");
        assert!(
            rep.warnings
                .iter()
                .any(|x| x.contains(".picket-ssd") && x.contains("not a regular file")),
            "{:?}",
            rep.warnings
        );
        assert!(
            !w.sys.calls().iter().any(|c| c.contains(".picket-ssd")),
            "{:?}",
            w.sys.calls()
        );
        assert_eq!(w.sys.state(EDGE), "active");
    }

    #[test]
    fn a_foreign_marker_is_left_alone() {
        let w = ssd_world();
        std::fs::create_dir_all(w.real("/volume1/.picket")).unwrap();
        w.sys.set_owner("/volume1/.picket", 880, 880);
        let foreign = "0123456789abcdef0123456789abcdef\n";
        std::fs::write(w.real("/volume1/.picket/.picket-ssd"), foreign).unwrap();
        let rep = w.install("1.4.0", false).unwrap();
        assert!(
            rep.warnings.iter().any(|x| x.contains("another id")),
            "{:?}",
            rep.warnings
        );
        assert_eq!(
            std::fs::read_to_string(w.real("/volume1/.picket/.picket-ssd")).unwrap(),
            foreign
        );
        assert_eq!(w.sys.owner_of("/volume1/.picket/.picket-ssd"), (0, 0));
    }

    #[test]
    fn links_are_never_chowned_through() {
        let w = ssd_world();
        w.install("1.4.0", false).unwrap();
        let id = std::fs::read_to_string(w.real("/data/picket/var/ssd-id")).unwrap();
        // The marker becomes a hard link to a root file; ssd-id a symlink to another.
        std::fs::write(w.real("/etc/shadow"), &id).unwrap();
        std::fs::remove_file(w.real("/volume1/.picket/.picket-ssd")).unwrap();
        std::fs::hard_link(w.real("/etc/shadow"), w.real("/volume1/.picket/.picket-ssd")).unwrap();
        w.sys.clear_calls();
        let rep = w.install("1.4.0", false).unwrap();
        assert!(
            !w.sys
                .calls()
                .iter()
                .any(|c| c.starts_with("chown /volume1/.picket/.picket-ssd")),
            "{:?}",
            w.sys.calls()
        );
        assert!(
            rep.warnings
                .iter()
                .any(|x| x.contains(".picket-ssd") && x.contains("hard link")),
            "{:?}",
            rep.warnings
        );
        assert_eq!(w.sys.owner_of("/etc/shadow"), (0, 0));
        assert_eq!(std::fs::metadata(w.real("/etc/shadow")).unwrap().nlink(), 2);

        std::fs::remove_file(w.real("/data/picket/var/ssd-id")).unwrap();
        std::os::unix::fs::symlink("/etc/shadow", w.real("/data/picket/var/ssd-id")).unwrap();
        w.sys.clear_calls();
        let rep = w.install("1.4.0", false).unwrap();
        assert!(
            !w.sys
                .calls()
                .iter()
                .any(|c| c.starts_with("chown /data/picket/var/ssd-id")),
            "{:?}",
            w.sys.calls()
        );
        assert!(
            rep.warnings
                .iter()
                .any(|x| x.contains("ssd-id") && x.contains("not a regular file")),
            "{:?}",
            rep.warnings
        );
        assert_eq!(std::fs::read_to_string(w.real("/etc/shadow")).unwrap(), id);
    }

    #[test]
    fn one_bad_entry_does_not_stop_the_install() {
        let w = ssd_world();
        std::fs::create_dir_all(w.real("/volume1/.picket")).unwrap();
        w.sys.set_owner("/volume1/.picket", 880, 880);
        std::os::unix::fs::symlink("/etc", w.real("/volume1/.picket/spool")).unwrap();
        let rep = w.install("1.4.0", false).unwrap();
        assert!(
            rep.warnings
                .iter()
                .any(|x| x.contains("spool") && x.contains("link")),
            "{:?}",
            rep.warnings
        );
        assert!(w.exists("/volume1/.picket/bundles"));
        assert!(w.exists("/volume1/.picket/verdicts"));
        assert!(w.exists("/volume1/.picket/.picket-ssd"));
        assert_eq!(w.sys.owner_of("/etc"), (0, 0));
        assert!(w.unit_text(EDGE).is_some());
        assert_eq!(w.sys.state(EDGE), "active");
    }
}

/// A run stopped after the switch (here a restart request that fails) leaves units running the
/// old binaries. The re-run still owes those restarts and makes them, then a third run is quiet
/// (edge-unifi.md §2: a re-run repairs an install; step 6; README §2 Restarts).
#[test]
fn a_rerun_makes_the_restarts_an_interrupted_install_owed() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    w.sys.fail("systemctl restart picket-edge.service", 1);
    assert!(w.install("1.5.0", false).is_err());
    assert_eq!(w.current().as_deref(), Some("1.5.0"));
    w.sys.clear_calls();
    w.install("1.5.0", false).unwrap();
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service"
        ]
    );
    w.sys.clear_calls();
    let rep = w.install("1.5.0", false).unwrap();
    assert!(rep.actions.is_empty(), "{:?}", rep.actions);
    assert!(mutating(&w.sys.calls()).is_empty(), "{:?}", w.sys.calls());

    // Stopped at step 3, after the switch: the accounts conflict, then the admin frees the IDs.
    let passwd = std::fs::read_to_string(w.real("/etc/passwd")).unwrap();
    let without_picket: String = passwd
        .lines()
        .filter(|l| !l.starts_with("picket:"))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(w.real("/etc/passwd"), &without_picket).unwrap();
    w.sys.st.borrow_mut().sysusers_conflict = true;
    w.sys.clear_calls();
    assert!(w.install("1.7.0", false).is_err());
    assert_eq!(w.current().as_deref(), Some("1.7.0"));
    std::fs::write(w.real("/etc/passwd"), &without_picket).unwrap();
    w.sys.st.borrow_mut().sysusers_conflict = false;
    w.sys.clear_calls();
    w.install("1.7.0", false).unwrap();
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl restart picket-edge-helper.service",
            "systemctl restart picket-edge.service"
        ]
    );
    w.assert_own_service_untouched();
}

/// A run stopped after writing a unit but before its reload and restart: the re-run finds the
/// file already right, and still reloads, re-enables and restarts it (edge-unifi.md §2 steps 5
/// and 6).
#[test]
fn a_rerun_reloads_and_restarts_units_an_interrupted_install_wrote() {
    let w = World::new(Platform::Unifi);
    w.install("1.4.0", false).unwrap();
    let edge = w.unit_text(EDGE).unwrap();
    // An edit an admin loaded.
    w.write_unit(EDGE, &format!("{edge}# local edit\n"));
    w.sys.systemctl(&["daemon-reload"]).unwrap();
    w.sys.fail("systemctl daemon-reload", 1);
    assert!(w.install("1.4.0", false).is_err());
    assert_eq!(w.unit_text(EDGE).unwrap(), edge);
    w.sys.clear_calls();
    w.install("1.4.0", false).unwrap();
    assert_eq!(
        mutating(&w.sys.calls()),
        [
            "systemctl daemon-reload",
            "systemctl reenable picket-edge.service",
            "systemctl restart picket-edge.service",
        ]
    );
    w.assert_own_service_untouched();
}

/// `install` copies only from a directory nobody but root can change, and never through a link,
/// so picket-edge can't swap in its own picket-edge-update for the next update to run as root
/// (security.md §3; edge-unifi.md §2).
#[test]
fn a_source_directory_others_can_change_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let install_from = |w: &World, src: &Path| {
        crate::install::install(
            &w.root,
            &w.sys,
            &crate::install::InstallOptions {
                platform: None,
                force: false,
                src_dir: src.to_path_buf(),
                version: "1.4.0".into(),
            },
        )
    };
    let w = World::new(Platform::Unifi);
    // The fake keeps owners by path; install checks the resolved one.
    let parent = std::fs::canonicalize(w.src.path()).unwrap();
    let src = parent.join("picket-edge-1.4.0");
    std::fs::create_dir(&src).unwrap();
    for b in crate::release::BINARIES {
        std::fs::write(src.join(b), format!("#!{b} 1.4.0\n")).unwrap();
    }
    let refused = |w: &World, why: &str| {
        let e = install_from(w, &src).unwrap_err().to_string();
        assert!(e.contains(why), "{e}");
        assert!(!w.exists("/data/picket/bin"), "nothing changed: {e}");
    };

    // Owned by picket (the edge's own releases/<version>/, say), or under such a directory.
    w.sys.set_owner(src.to_str().unwrap(), 880, 880);
    refused(&w, "owned by uid 880");
    w.sys.set_owner(src.to_str().unwrap(), 0, 0);
    w.sys.set_owner(parent.to_str().unwrap(), 880, 880);
    refused(&w, "owned by uid 880");
    w.sys.set_owner(parent.to_str().unwrap(), 0, 0);
    // Writable by its group.
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o775)).unwrap();
    refused(&w, "writable by group or others");
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A binary that is a link, even to the right content.
    std::fs::write(w.real("/elsewhere"), "#!picket-edge-update 1.4.0\n").unwrap();
    std::fs::remove_file(src.join("picket-edge-update")).unwrap();
    std::os::unix::fs::symlink(w.real("/elsewhere"), src.join("picket-edge-update")).unwrap();
    refused(&w, "picket-edge-update");

    // A root-only directory, under a sticky world-writable one like /tmp, is fine.
    std::fs::remove_file(src.join("picket-edge-update")).unwrap();
    std::fs::write(src.join("picket-edge-update"), "#!picket-edge-update 1.4.0\n").unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o1777)).unwrap();
    install_from(&w, &src).unwrap();
    assert_eq!(w.current().as_deref(), Some("1.4.0"));
}

/// An existing `ssd_dir` or subfolder is never chowned: install creates them only if missing,
/// and leaves one owned by anyone but picket alone, with no marker, so a UniFi folder named by
/// mistake stays as it was (edge-unifi.md §2 step 4).
#[test]
fn an_existing_ssd_folder_of_someone_else_is_left_alone() {
    use std::os::unix::fs::PermissionsExt;
    let w = ssd_world();
    std::fs::create_dir_all(w.real("/volume1/.picket/bundles")).unwrap();
    std::fs::set_permissions(w.real("/volume1/.picket"), std::fs::Permissions::from_mode(0o755)).unwrap();
    w.sys.set_owner("/volume1/.picket", 0, 0);
    w.sys.set_owner("/volume1/.picket/bundles", 0, 0);
    let rep = w.install("1.4.0", false).unwrap();
    assert!(
        rep.warnings
            .iter()
            .any(|x| x.contains("/volume1/.picket") && x.contains("owned by uid 0")),
        "{:?}",
        rep.warnings
    );
    assert_eq!(w.sys.owner_of("/volume1/.picket"), (0, 0));
    assert_eq!(mode(&w.real("/volume1/.picket")), 0o755);
    assert!(!w.exists("/volume1/.picket/.picket-ssd"));
    assert!(!w.exists("/volume1/.picket/spool"));
    assert!(
        !w.sys.calls().iter().any(|c| c.starts_with("chown /volume1")),
        "{:?}",
        w.sys.calls()
    );
    assert_eq!(w.sys.state(EDGE), "active");

    // Picket's own folder: missing subfolders are made; one owned by someone else is left alone.
    w.sys.set_owner("/volume1/.picket", 880, 880);
    w.sys.clear_calls();
    let rep = w.install("1.4.0", false).unwrap();
    assert!(
        rep.warnings
            .iter()
            .any(|x| x.contains("/volume1/.picket/bundles") && x.contains("owned by uid 0")),
        "{:?}",
        rep.warnings
    );
    assert_eq!(w.sys.owner_of("/volume1/.picket/bundles"), (0, 0));
    assert_eq!(
        mode(&w.real("/volume1/.picket")),
        0o755,
        "an existing folder keeps its mode"
    );
    for sub in ["spool", "verdicts"] {
        assert_eq!(w.sys.owner_of(&format!("/volume1/.picket/{sub}")), (880, 880));
    }
    assert!(w.exists("/volume1/.picket/.picket-ssd"));
}
