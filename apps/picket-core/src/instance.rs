//! The data directory (core.md §13, storage.md §2): `init`, the marker, and `run`'s checks.
//!
//! `init` accepts only an empty directory, or one holding nothing but `lost+found`, a
//! pre-placed `identity/`, or a `.picket-core-init` left by an interrupted `init`. Anything
//! else, a marker included, makes it exit non-zero, name what it found and change nothing. It
//! writes `.picket-core-init` first, then everything else, then the marker
//! `.picket-core-instance` (format version, instance id, creation time; temporary name, fsync,
//! rename), then deletes `.picket-core-init`. An `init` that finds `.picket-core-init` and no
//! marker deletes only what an `init` creates and starts over.
//!
//! `run` never creates an instance: without the marker it exits 78 naming the directory.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::db::{DbOptions, migrate};
use crate::error::ExitError;
use crate::identity::{self, Identity};
use crate::lanca::{self, LanCa};

pub const MARKER: &str = ".picket-core-instance";
pub const INIT_FILE: &str = ".picket-core-init";
pub const INITIAL_PASSWORD: &str = "initial-password";
pub const MARKER_FORMAT: u32 = 1;
/// The admin account's name (core.md §12).
pub const ADMIN: &str = "admin";
/// Length of the first admin password (core.md §12).
pub const PASSWORD_LEN: usize = 24;

/// Directories `init` creates (storage.md §2).
const DIRS: &[&str] = &["logs", "blobs", "lists", "lists/profiles", "staging", "tmp"];

/// Every top-level name an `init` (or its temporary files) can create.
const INIT_CREATES: &[&str] = &[
    "core.db",
    "core.db-wal",
    "core.db-shm",
    "core.db-journal",
    "metrics.db",
    "metrics.db-wal",
    "metrics.db-shm",
    "metrics.db-journal",
    INITIAL_PASSWORD,
    crate::config::secrets::SECRETS_KEY_FILE,
    lanca::LANCA_DIR,
    "logs",
    "blobs",
    "lists",
    "staging",
    "tmp",
    "pre-migration",
    MARKER,
];

/// The marker's content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub format: u32,
    pub instance_id: String,
    pub created_at: String,
    /// The release that created the instance (informational).
    #[serde(default)]
    pub created_by: String,
}

/// `.picket-core-init`'s content: whether `identity/` was pre-placed (kept on a restart).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct InitState {
    format: u32,
    started_at: String,
    identity_preplaced: bool,
}

/// `init`'s options (`--web-port`, `--edge-port`, `--lanca-zones`).
#[derive(Clone, Debug, Default)]
pub struct InitOptions {
    pub data_dir: PathBuf,
    pub web_port: Option<u16>,
    pub edge_port: Option<u16>,
    pub lanca_zones: Option<Vec<String>>,
}

/// What `init` made.
#[derive(Clone, Debug)]
pub struct InitOutcome {
    pub marker: Marker,
    /// The first admin password: printed once and written to `initial-password`.
    pub password: String,
    pub fingerprint: String,
    pub identity_preplaced: bool,
    /// True when an interrupted `init` was cleaned up first.
    pub restarted: bool,
}

/// `init`'s steps, for tests that cut it off part-way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitStep {
    InitFileWritten,
    DirsCreated,
    DatabasesCreated,
    IdentityWritten,
    LanCaWritten,
    SecretsKeyWritten,
    PasswordWritten,
    MarkerWritten,
}

pub const INIT_STEPS: &[InitStep] = &[
    InitStep::InitFileWritten,
    InitStep::DirsCreated,
    InitStep::DatabasesCreated,
    InitStep::IdentityWritten,
    InitStep::LanCaWritten,
    InitStep::SecretsKeyWritten,
    InitStep::PasswordWritten,
    InitStep::MarkerWritten,
];

fn fail(msg: impl Into<String>) -> ExitError {
    ExitError::new(1, msg)
}

/// Creates an instance.
pub fn init(opts: &InitOptions) -> Result<InitOutcome, ExitError> {
    init_with_hook(opts, &mut |_| Ok(()))
}

/// [`init`] with a hook called after each step; a hook error stops `init` there, as a crash
/// would (nothing is cleaned up).
pub fn init_with_hook(
    opts: &InitOptions,
    hook: &mut dyn FnMut(InitStep) -> Result<()>,
) -> Result<InitOutcome, ExitError> {
    let dir = &opts.data_dir;
    // Arguments first, so a bad one changes nothing.
    let mut settings = crate::settings::Settings::default();
    if let Some(p) = opts.web_port {
        settings.web.port = p;
    }
    if let Some(p) = opts.edge_port {
        settings.edge_api.port = p;
    }
    if let Some(z) = &opts.lanca_zones {
        settings.lanca.zones = lanca::normalize_zones(z).map_err(|e| fail(format!("--lanca-zones: {e}")))?;
    }
    let issues = crate::settings::validate(&settings);
    if let Some((k, m)) = issues.first() {
        return Err(fail(format!("{k}: {m}")));
    }

    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| fail(format!("cannot create {}: {e}", dir.display())))?;
        // 0750, whatever the umask (storage.md §2); an existing directory keeps its mode.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o750))
            .map_err(|e| fail(format!("cannot set the mode of {}: {e}", dir.display())))?;
    }
    if !dir.is_dir() {
        return Err(fail(format!("{} is not a directory", dir.display())));
    }
    let _lock = lock_data_dir(dir)?;

    // What's there?
    let mut entries: Vec<String> = fs::read_dir(dir)
        .map_err(|e| fail(format!("cannot read {}: {e}", dir.display())))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    if entries.iter().any(|e| e == MARKER) {
        return Err(fail(format!(
            "{} already holds a picket-core instance ({MARKER}); nothing was changed",
            dir.display()
        )));
    }
    let interrupted = entries.iter().any(|e| e == INIT_FILE);
    let prev_state: Option<InitState> = if interrupted {
        fs::read(dir.join(INIT_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    } else {
        None
    };
    let mut refused = Vec::new();
    let is_dir = |name: &str| {
        fs::symlink_metadata(dir.join(name))
            .map(|m| m.is_dir())
            .unwrap_or(false)
    };
    for e in &entries {
        let allowed = (e == "lost+found" && is_dir(e))
            || (e == identity::IDENTITY_DIR && is_dir(e))
            || e == INIT_FILE
            || (interrupted && (INIT_CREATES.contains(&e.as_str()) || is_init_temp(e)));
        if !allowed {
            refused.push(e.clone());
        }
    }
    if !refused.is_empty() {
        return Err(fail(format!(
            "{} is not empty: it holds {}; init accepts only an empty directory (or lost+found, a pre-placed \
             identity/, or an interrupted init's {INIT_FILE}); nothing was changed",
            dir.display(),
            refused
                .iter()
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    // A pre-placed identity is kept; an incomplete one is refused. After an interrupted init,
    // identity/ counts as pre-placed only if that init said so (an unreadable init file means
    // the crash came before anything else was written, so identity/ is pre-placed).
    let id_dir = identity::identity_dir(dir);
    let id_present = id_dir.is_dir()
        && fs::read_dir(&id_dir)
            .map(|mut r| r.next().is_some())
            .unwrap_or(false);
    let preplaced = match (&prev_state, id_present) {
        (_, false) => false,
        (Some(s), true) => s.identity_preplaced,
        (None, true) => true,
    };
    if preplaced {
        identity::check_preplaced(&id_dir).map_err(|e| {
            fail(format!(
                "the pre-placed {} is unusable ({e:#}); it needs core.key (Ed25519), with or without its core.crt; nothing was changed",
                id_dir.display()
            ))
        })?;
    }

    // Clean up an interrupted init: only what an init creates.
    if interrupted {
        for e in &entries {
            if INIT_CREATES.contains(&e.as_str()) || is_init_temp(e) {
                remove_any(&dir.join(e)).map_err(|err| fail(format!("cannot clean up {e}: {err:#}")))?;
            }
        }
        if id_present && !preplaced {
            remove_any(&id_dir).map_err(|err| fail(format!("cannot clean up identity/: {err:#}")))?;
        }
        let _ = crate::util::fsync_dir(dir);
    }

    let step = |hook: &mut dyn FnMut(InitStep) -> Result<()>, s: InitStep| -> Result<(), ExitError> {
        hook(s).map_err(|e| fail(format!("init stopped after {s:?}: {e:#}")))
    };
    let io = |e: anyhow::Error| fail(format!("init failed: {e:#}"));

    // 1. The init file, first.
    let state = InitState {
        format: 1,
        started_at: crate::util::now_ts(),
        identity_preplaced: preplaced,
    };
    write_durable(
        &dir.join(INIT_FILE),
        &serde_json::to_vec(&state).map_err(|e| io(e.into()))?,
    )
    .map_err(io)?;
    step(hook, InitStep::InitFileWritten)?;

    // 2. Directories.
    for d in DIRS {
        crate::util::ensure_dir(&dir.join(d)).map_err(io)?;
    }
    step(hook, InitStep::DirsCreated)?;

    // 3. Databases: schema, settings, system objects, the starter profile, the admin account.
    let password = crate::util::random_password(PASSWORD_LEN);
    let hash = crate::web::auth::hash_password(&password).map_err(io)?;
    create_databases(dir, &settings, &hash).map_err(io)?;
    step(hook, InitStep::DatabasesCreated)?;

    // 4. Identity (kept if pre-placed).
    let identity = if preplaced {
        match identity::check_preplaced(&id_dir).map_err(io)? {
            identity::Preplaced::Both => Identity::load(&id_dir).map_err(io)?,
            identity::Preplaced::KeyOnly => Identity::complete(&id_dir).map_err(io)?,
        }
    } else {
        Identity::create(&id_dir).map_err(io)?
    };
    step(hook, InitStep::IdentityWritten)?;

    // 5. LAN CA.
    let instance_id = crate::util::random_hex(16);
    LanCa::create(&lanca::lanca_dir(dir), &settings.lanca.zones, &instance_id).map_err(io)?;
    step(hook, InitStep::LanCaWritten)?;

    // 6. The secrets key (secrets are encrypted at rest by default).
    crate::config::secrets::SecretsKey::create(dir).map_err(io)?;
    step(hook, InitStep::SecretsKeyWritten)?;

    // 7. The first password's file (0600).
    crate::util::write_atomic(
        &dir.join(INITIAL_PASSWORD),
        format!("{password}\n").as_bytes(),
        0o600,
    )
    .map_err(io)?;
    step(hook, InitStep::PasswordWritten)?;

    // 8. The marker: temporary name, fsync, rename.
    let marker = Marker {
        format: MARKER_FORMAT,
        instance_id,
        created_at: crate::util::now_ts(),
        created_by: crate::VERSION.to_string(),
    };
    crate::util::write_atomic(
        &dir.join(MARKER),
        &serde_json::to_vec_pretty(&marker).map_err(|e| io(e.into()))?,
        0o640,
    )
    .map_err(io)?;
    step(hook, InitStep::MarkerWritten)?;

    // 9. Done: the init file goes.
    fs::remove_file(dir.join(INIT_FILE)).map_err(|e| io(e.into()))?;
    crate::util::fsync_dir(dir).map_err(io)?;

    Ok(InitOutcome {
        marker,
        password,
        fingerprint: identity.fingerprint,
        identity_preplaced: preplaced,
        restarted: interrupted,
    })
}

fn create_databases(dir: &Path, settings: &crate::settings::Settings, hash: &str) -> Result<()> {
    let core = DbOptions::core(dir);
    let metrics = DbOptions::metrics(dir);
    // Created empty and 0600 first, whatever the umask: SQLite gives its WAL and SHM files the
    // database file's mode (security.md §4: the argon2 hash and the configuration are private).
    for p in [&core.path, &metrics.path] {
        crate::util::write_private_new(p, b"")?;
    }
    migrate::create_fresh(&core, &migrate::CORE)?;
    migrate::create_fresh(&metrics, &migrate::METRICS)?;
    let mut conn = crate::db::open_connection(&core, 4096)?;
    let tx = conn.transaction()?;
    let rows: Vec<crate::settings::RowChange> = vec![
        ("web.port".into(), Some(serde_json::json!(settings.web.port))),
        (
            "edge_api.port".into(),
            Some(serde_json::json!(settings.edge_api.port)),
        ),
        (
            "lanca.zones".into(),
            Some(serde_json::json!(settings.lanca.zones)),
        ),
        (
            "default_profile".into(),
            Some(serde_json::json!(crate::config::system::DEFAULT_PROFILE)),
        ),
    ];
    crate::config::system::ensure(&tx, dir)?;
    crate::config::store::write_profile(&tx, &crate::config::system::default_profile())?;
    crate::settings::write_rows(&tx, &rows)?;
    tx.execute(
        "INSERT INTO ui_account(name, password_argon2id, changed_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![ADMIN, hash, crate::util::now_ts()],
    )?;
    crate::config::journal::record(
        &tx,
        None,
        "init",
        crate::config::model::EntityKind::Settings,
        "settings",
        &serde_json::json!({"op": "create", "by": "init"}),
    )?;
    tx.commit()?;
    Ok(())
}

/// Temporary files `util::write_atomic` and `VACUUM INTO` leave for names init creates.
fn is_init_temp(name: &str) -> bool {
    if let Some(inner) = name.strip_prefix('.').and_then(|n| n.strip_suffix(".tmp")) {
        return INIT_CREATES.contains(&inner)
            || inner == INIT_FILE.trim_start_matches('.')
            || inner == MARKER;
    }
    false
}

fn remove_any(p: &Path) -> Result<()> {
    let md = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if md.is_dir() {
        fs::remove_dir_all(p).with_context(|| format!("remove {}", p.display()))
    } else {
        fs::remove_file(p).with_context(|| format!("remove {}", p.display()))
    }
}

/// Creates a file with `bytes` and makes it durable (file and directory fsync).
fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let _ = fs::remove_file(path);
    crate::util::write_private_new(path, bytes)?;
    if let Some(d) = path.parent() {
        crate::util::fsync_dir(d)?;
    }
    Ok(())
}

/// An exclusive lock on the data directory, held while a command uses it (`init`, `run`,
/// `passwd`, `edges add`): two processes never migrate, clean or write one directory at once.
/// It is an `flock` on the directory itself, so no lock file is left behind, and the kernel
/// releases it when the process ends, however it ends.
#[derive(Debug)]
pub struct DataDirLock {
    _dir: fs::File,
}

/// Takes the data directory's lock, or fails at once (exit 75) when another process holds it.
pub fn lock_data_dir(dir: &Path) -> Result<DataDirLock, ExitError> {
    let f =
        fs::File::open(dir).map_err(|e| ExitError::new(1, format!("cannot open {}: {e}", dir.display())))?;
    match rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(DataDirLock { _dir: f }),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(ExitError::new(
            crate::error::EXIT_IN_USE,
            format!(
                "another picket-core process is using {} (it holds the directory's lock); stop it first; \
                 nothing was changed",
                dir.display()
            ),
        )),
        Err(e) => Err(ExitError::new(1, format!("cannot lock {}: {e}", dir.display()))),
    }
}

/// Reads the marker, if any.
pub fn read_marker(dir: &Path) -> Result<Option<Marker>> {
    match fs::read(dir.join(MARKER)) {
        Ok(b) => Ok(Some(
            serde_json::from_slice(&b).context("the marker is unreadable")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("read the marker"),
    }
}

/// `run`'s first check: the marker must be there (exit 78 otherwise, naming the directory).
pub fn require_marker(dir: &Path) -> Result<Marker, ExitError> {
    let missing = || {
        ExitError::config(format!(
            "{} holds no picket-core instance (no {MARKER}); run `picket-core init --data-dir {}` to create one, \
             or check --data-dir and that the data disk is mounted. picket-core run never creates an instance.",
            dir.display(),
            dir.display()
        ))
    };
    match read_marker(dir) {
        Ok(Some(m)) if m.format >= 1 && !m.instance_id.is_empty() => Ok(m),
        Ok(Some(_)) => Err(ExitError::config(format!(
            "{}/{MARKER} is malformed",
            dir.display()
        ))),
        Ok(None) => Err(missing()),
        Err(e) => Err(ExitError::config(format!("{}: {e:#}", dir.display()))),
    }
}

/// Start-time cleanup (README §2, Restarts): temporary files and an `init` file a crash after
/// the marker left behind.
pub fn clean_at_start(dir: &Path) -> Result<()> {
    let _ = fs::remove_file(dir.join(INIT_FILE));
    for d in ["tmp", "staging"] {
        let p = dir.join(d);
        if p.is_dir() {
            for e in fs::read_dir(&p)?.flatten() {
                let _ = remove_any(&e.path());
            }
        } else {
            crate::util::ensure_dir(&p)?;
        }
    }
    for d in DIRS {
        crate::util::ensure_dir(&dir.join(d))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(d: &Path) -> InitOptions {
        InitOptions {
            data_dir: d.to_path_buf(),
            ..Default::default()
        }
    }

    #[test]
    fn init_empty_dir() {
        let d = tempfile::tempdir().unwrap();
        let out = init(&opts(d.path())).unwrap();
        assert_eq!(out.password.len(), PASSWORD_LEN);
        assert!(!out.restarted);
        let m = require_marker(d.path()).unwrap();
        assert_eq!(m, out.marker);
        assert!(!d.path().join(INIT_FILE).exists());
        let pw = fs::read_to_string(d.path().join(INITIAL_PASSWORD)).unwrap();
        assert_eq!(pw.trim(), out.password);
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(d.path().join(INITIAL_PASSWORD))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        for f in [
            "core.db",
            "metrics.db",
            "identity/core.key",
            "lanca/ca.key",
            "secrets.key",
            "logs",
            "blobs",
            "tmp",
        ] {
            assert!(d.path().join(f).exists(), "{f}");
        }
        // security.md §4, storage.md §2: private whatever the umask.
        for (f, want) in [
            ("core.db", 0o600),
            ("metrics.db", 0o600),
            ("identity/core.key", 0o600),
            ("lanca/ca.key", 0o600),
            ("secrets.key", 0o600),
            ("logs", 0o750),
            ("tmp", 0o750),
        ] {
            let mode = fs::metadata(d.path().join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, want, "{f}");
        }
        // A second init refuses: the marker is there.
        let e = init(&opts(d.path())).unwrap_err();
        assert!(e.message.contains(MARKER), "{}", e.message);
    }

    #[test]
    fn init_creates_a_missing_directory_0750() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("new");
        init(&opts(&dir)).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[test]
    fn refusals_change_nothing() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("stray.txt"), b"x").unwrap();
        let e = init(&opts(d.path())).unwrap_err();
        assert_ne!(e.code, 0);
        assert!(e.message.contains("stray.txt"));
        let names: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn allowed_leftovers_must_be_directories() {
        // core.md §13: `lost+found` and a pre-placed `identity/` are directories; a file by
        // either name is something else, refused before anything changes.
        for name in ["identity", "lost+found"] {
            let d = tempfile::tempdir().unwrap();
            fs::write(d.path().join(name), b"x").unwrap();
            let e = init(&opts(d.path())).unwrap_err();
            assert_ne!(e.code, 0);
            assert!(e.message.contains(name), "{}", e.message);
            let names: Vec<_> = fs::read_dir(d.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names, vec![name.to_string()], "nothing changed");
        }
    }

    #[test]
    fn preplaced_key_alone_gets_a_certificate() {
        // The pin is the key's SPKI, so a deployment may pre-place just the key.
        let d = tempfile::tempdir().unwrap();
        let (id, key_pem) = Identity::generate().unwrap();
        let idir = identity::identity_dir(d.path());
        fs::create_dir(&idir).unwrap();
        fs::write(idir.join(identity::KEY_FILE), key_pem).unwrap();
        let out = init(&opts(d.path())).unwrap();
        assert!(out.identity_preplaced);
        assert_eq!(out.fingerprint, id.fingerprint);
        assert_eq!(Identity::load(&idir).unwrap().fingerprint, id.fingerprint);
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(idir.join(identity::CERT_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn preplaced_certificate_without_its_key_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let (id, _) = Identity::generate().unwrap();
        let idir = identity::identity_dir(d.path());
        fs::create_dir(&idir).unwrap();
        fs::write(idir.join(identity::CERT_FILE), &id.cert_pem).unwrap();
        let e = init(&opts(d.path())).unwrap_err();
        assert!(e.message.contains("identity"), "{}", e.message);
        let names: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "nothing changed");
    }

    #[test]
    fn no_marker_is_78() {
        let d = tempfile::tempdir().unwrap();
        let e = require_marker(d.path()).unwrap_err();
        assert_eq!(e.code, 78);
        assert!(e.message.contains(&d.path().display().to_string()));
    }
}
