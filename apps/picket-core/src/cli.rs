//! The command line (core.md §13).
//!
//! ```text
//! picket-core init [--data-dir DIR] [--web-port N] [--edge-port N] [--lanca-zones Z,…]
//! picket-core run [--data-dir DIR]
//! picket-core identity [--data-dir DIR]
//! picket-core probe URL --expect-identity SHA256:…
//! picket-core passwd [--data-dir DIR] [--generate]
//! picket-core edges add [--data-dir DIR] --name N --key SHA256:… [--platform unifi|debian]
//! ```

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};

use crate::error::ExitError;

pub const DEFAULT_DATA_DIR: &str = "/var/lib/picket-core";

#[derive(Debug, Parser)]
#[command(name = "picket-core", version, about = "Picket's management app")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, Clone, clap::Args)]
pub struct DataDir {
    /// The data directory.
    #[arg(long, env = "PICKET_CORE_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    pub data_dir: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Create an instance: identity, LAN CA, core.db, the first admin password.
    Init {
        #[command(flatten)]
        dir: DataDir,
        /// `web.port` (default 8443).
        #[arg(long)]
        web_port: Option<u16>,
        /// Additional reachable IP literals, comma-separated (default none).
        #[arg(long, value_delimiter = ',')]
        web_addresses: Option<Vec<String>>,
        /// `edge_api.port` (default 7443).
        #[arg(long)]
        edge_port: Option<u16>,
        /// `lanca.zones`, comma-separated (default home.arpa).
        #[arg(long, value_delimiter = ',')]
        lanca_zones: Option<Vec<String>>,
    },
    /// The service entry point; refuses to start without the marker.
    Run {
        #[command(flatten)]
        dir: DataDir,
        /// Tests only: bind every port to 0 instead of the configured ones (the bound addresses
        /// are in the start log line), so parallel test runs never race for a port.
        #[arg(long, hide = true)]
        any_port: bool,
    },
    /// Print core's identity fingerprint, offline.
    Identity {
        #[command(flatten)]
        dir: DataDir,
    },
    /// Connect to a core's edge port and compare its identity (exit 0 match, 3 another identity,
    /// 4 no TLS server certificate seen).
    Probe {
        /// `https://<ip>:7443`
        url: String,
        #[arg(long)]
        expect_identity: String,
    },
    /// Set a new admin password, offline (recovery). Reads it from the terminal (twice) or one
    /// line of stdin.
    Passwd {
        #[command(flatten)]
        dir: DataDir,
        /// Generate a random password and print it.
        #[arg(long)]
        generate: bool,
    },
    /// Manage edges offline.
    Edges {
        #[command(subcommand)]
        cmd: EdgesCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum EdgesCmd {
    /// Register an edge by name and key (from `picket-edge key`).
    Add {
        #[command(flatten)]
        dir: DataDir,
        #[arg(long)]
        name: String,
        #[arg(long)]
        key: String,
        #[arg(long, default_value = "unifi")]
        platform: String,
    },
}

/// Runs a command; `Ok` exits 0.
pub fn dispatch(cli: Cli) -> Result<(), ExitError> {
    match cli.cmd {
        Cmd::Init {
            dir,
            web_port,
            web_addresses,
            edge_port,
            lanca_zones,
        } => {
            let out = crate::instance::init(&crate::instance::InitOptions {
                data_dir: dir.data_dir.clone(),
                web_port,
                web_addresses,
                edge_port,
                lanca_zones,
            })?;
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "Created a picket-core instance in {}", dir.data_dir.display());
            if out.restarted {
                let _ = writeln!(o, "(an interrupted init was cleaned up first)");
            }
            let _ = writeln!(
                o,
                "Identity: {}{}",
                out.fingerprint,
                if out.identity_preplaced {
                    " (pre-placed)"
                } else {
                    ""
                }
            );
            let _ = writeln!(
                o,
                "First admin password (user admin), shown once; also in {}:",
                dir.data_dir.join(crate::instance::INITIAL_PASSWORD).display()
            );
            let _ = writeln!(o, "{}", out.password);
            Ok(())
        }
        Cmd::Run { dir, any_port } => {
            reexec_with_env(&dir.data_dir)?;
            runtime()?.block_on(crate::run::run(dir.data_dir, any_port))
        }
        Cmd::Identity { dir } => {
            let fp =
                crate::identity::fingerprint_from_cert_file(&crate::identity::identity_dir(&dir.data_dir))
                    .map_err(|e| {
                        ExitError::new(1, format!("no identity in {}: {e:#}", dir.data_dir.display()))
                    })?;
            println!("{fp}");
            Ok(())
        }
        Cmd::Probe { url, expect_identity } => {
            if picket_api::ids::parse_fingerprint(&expect_identity).is_none() {
                return Err(ExitError::new(
                    2,
                    "--expect-identity must be a SHA256:… fingerprint",
                ));
            }
            let r = runtime()?.block_on(crate::edge_api::probe(
                &url,
                &expect_identity,
                Duration::from_secs(10),
            ));
            match &r {
                crate::edge_api::ProbeResult::Match => println!("match: {expect_identity}"),
                crate::edge_api::ProbeResult::Other(fp) => eprintln!("another identity: {fp}"),
                crate::edge_api::ProbeResult::NoCert(why) => {
                    eprintln!("no TLS server certificate seen: {why}")
                }
            }
            match r.exit_code() {
                0 => Ok(()),
                c => Err(ExitError::new(c, String::new())),
            }
        }
        Cmd::Passwd { dir, generate } => passwd(&dir.data_dir, generate),
        Cmd::Edges {
            cmd:
                EdgesCmd::Add {
                    dir,
                    name,
                    key,
                    platform,
                },
        } => edges_add(&dir.data_dir, &name, &key, &platform),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, ExitError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("picket-core")
        .build()
        .map_err(|e| ExitError::new(1, format!("cannot start the runtime: {e}")))
}

/// SQLite spills to `<data_dir>/tmp` (`SQLITE_TMPDIR`) and glibc keeps two arenas
/// (`MALLOC_ARENA_MAX=2`, security.md §4). The units set both; when either is missing (a manual
/// start), `run` re-executes itself once with them set, since both are read at process start.
fn reexec_with_env(data_dir: &Path) -> Result<(), ExitError> {
    use std::os::unix::process::CommandExt;
    let tmp = data_dir.join("tmp");
    let want_tmp = tmp.to_string_lossy().into_owned();
    let tmp_ok = std::env::var("SQLITE_TMPDIR").is_ok_and(|v| v == want_tmp);
    let arena_ok = std::env::var_os("MALLOC_ARENA_MAX").is_some();
    if (tmp_ok && arena_ok) || std::env::var_os("PICKET_CORE_REEXEC").is_some() {
        return Ok(());
    }
    // Without the marker there is nothing to re-execute for: report it now.
    crate::instance::require_marker(data_dir)?;
    let exe = std::env::current_exe().map_err(|e| ExitError::new(1, format!("current_exe: {e}")))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1))
        .env("PICKET_CORE_REEXEC", "1")
        .env("SQLITE_TMPDIR", &want_tmp);
    if !arena_ok {
        cmd.env("MALLOC_ARENA_MAX", "2");
    }
    let err = cmd.exec();
    Err(ExitError::new(
        1,
        format!("cannot re-execute with SQLITE_TMPDIR set: {err}"),
    ))
}

fn read_password_tty() -> Result<String, ExitError> {
    let read_hidden = |prompt: &str| -> Result<String, ExitError> {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let stdin = std::io::stdin();
        let old = rustix::termios::tcgetattr(&stdin).ok();
        if let Some(t) = &old {
            let mut quiet = t.clone();
            quiet.local_modes.remove(rustix::termios::LocalModes::ECHO);
            let _ = rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &quiet);
        }
        let mut line = String::new();
        let r = stdin.lock().read_line(&mut line);
        if let Some(t) = &old {
            let _ = rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, t);
        }
        eprintln!();
        r.map_err(|e| ExitError::new(1, format!("read the password: {e}")))?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    };
    let a = read_hidden("New admin password: ")?;
    let b = read_hidden("Again: ")?;
    if a != b {
        return Err(ExitError::new(1, "the passwords differ; nothing was changed"));
    }
    Ok(a)
}

fn passwd(data_dir: &Path, generate: bool) -> Result<(), ExitError> {
    crate::instance::require_marker(data_dir)?;
    let _lock = crate::instance::lock_data_dir(data_dir)?;
    crate::db::migrate::migrate_databases(data_dir)?;
    let pw = if generate {
        crate::util::random_password(crate::instance::PASSWORD_LEN)
    } else if std::io::stdin().is_terminal() {
        read_password_tty()?
    } else {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| ExitError::new(1, format!("read the password: {e}")))?;
        line.trim_end_matches(['\n', '\r']).to_string()
    };
    crate::web::auth::check_new_password(&pw)
        .map_err(|e| ExitError::new(1, format!("{e}; nothing was changed")))?;
    let hash = crate::web::auth::hash_password(&pw).map_err(|e| ExitError::new(1, format!("{e:#}")))?;
    let opts = crate::db::DbOptions::core(data_dir);
    let conn = crate::db::open_connection(&opts, 2048).map_err(|e| ExitError::new(1, format!("{e:#}")))?;
    conn.execute(
        "INSERT INTO ui_account(name, password_argon2id, changed_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(name) DO UPDATE SET password_argon2id = excluded.password_argon2id, changed_at = excluded.changed_at",
        rusqlite::params![crate::instance::ADMIN, hash, crate::util::now_ts()],
    )
    .map_err(|e| ExitError::new(1, format!("cannot store the password: {e}")))?;
    let _ = conn.execute(
        "INSERT INTO config_changes(at, source_ip, entity, entity_id, diff_json) VALUES (?1, NULL, 'account', ?2, ?3)",
        rusqlite::params![crate::util::now_ts(), crate::instance::ADMIN, r#"{"op":"update","password":"<redacted>","source":"cli"}"#],
    );
    crate::web::auth::remove_initial_password(data_dir);
    if generate {
        println!("{pw}");
    } else {
        eprintln!("The admin password was changed.");
    }
    Ok(())
}

fn edges_add(data_dir: &Path, name: &str, key: &str, platform: &str) -> Result<(), ExitError> {
    crate::instance::require_marker(data_dir)?;
    let _lock = crate::instance::lock_data_dir(data_dir)?;
    crate::db::migrate::migrate_databases(data_dir)?;
    let platform: picket_api::edge_config::Platform =
        serde_json::from_value(serde_json::Value::String(platform.into()))
            .map_err(|_| ExitError::new(2, "--platform is unifi or debian"))?;
    let key = crate::edges::normalize_key(key).map_err(|e| ExitError::new(2, e.to_string()))?;
    let edge = crate::config::model::EdgeDef {
        name: name.into(),
        key: key.clone(),
        platform,
        ..Default::default()
    };
    let opts = crate::db::DbOptions::core(data_dir);
    let mut conn =
        crate::db::open_connection(&opts, 2048).map_err(|e| ExitError::new(1, format!("{e:#}")))?;
    let body = serde_json::to_value(&edge).map_err(|e| ExitError::new(1, e.to_string()))?;
    let out = crate::config::store::with_tx(&mut conn, |tx| {
        let out = crate::config::store::apply(
            tx,
            crate::config::model::EntityKind::Edge,
            crate::config::Op::Create(body),
            &crate::config::Actor::cli(),
            None,
        )?;
        tx.execute("DELETE FROM edge_pending WHERE key_sha256 = ?1", [&key])?;
        Ok(out)
    })
    .map_err(|e| ExitError::new(1, format!("cannot add the edge: {e}")))?;
    println!("{}", out.id);
    Ok(())
}
