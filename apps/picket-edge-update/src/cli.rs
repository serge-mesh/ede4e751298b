//! The command line (edge.md §15), parsed by hand to keep the dependency set minimal:
//!
//! ```text
//! picket-edge-update [--platform unifi|debian] [--data-dir <dir>]   apply the pending release (the service only)
//! picket-edge-update install [--platform unifi|debian] [--force]
//! picket-edge-update units [--platform unifi|debian]
//! ```
//!
//! `--platform` and `--data-dir` on the bare command are additions to edge.md §15:
//! `picket-edge-update.service` passes the platform and `data_dir` its units were written for,
//! so an update never re-detects the platform and works in the `data_dir` its path unit watches.
//! Detection looks for UniFi's udapi directory, which a firmware change could move; a run that
//! guessed the wrong platform couldn't find the install, end its request or report. And a run
//! that took `data_dir` from an `edge.json` it can't read (it falls back to the default) or that
//! changed since `install` would find no `pending.json`, so the path unit would start it again
//! and again.

use std::io::Write;
use std::path::Path;

use crate::fsx::Root;
use crate::install::{InstallOptions, install};
use crate::platform::{Layout, Platform, Purpose, load_settings};
use crate::system::System;
use crate::update::{self, Env, RunEnd};
use crate::{VERSION, log, units};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Update {
        platform: Option<Platform>,
        data_dir: Option<String>,
    },
    Install {
        platform: Option<Platform>,
        force: bool,
    },
    Units {
        platform: Option<Platform>,
    },
    Help,
    Version,
}

pub const USAGE: &str = "\
usage:
  picket-edge-update [--platform unifi|debian] [--data-dir <dir>]
                                                       apply the pending release; run by picket-edge-update.service only
  picket-edge-update install [--platform unifi|debian] [--force]
                                                       as root: install or repair binaries, accounts, directories and units
  picket-edge-update units [--platform unifi|debian]   print the unit files this version writes, as JSON; changes nothing
";

/// Parses the arguments after the program name.
pub fn parse<S: AsRef<str>>(args: &[S]) -> Result<Command, String> {
    let args: Vec<&str> = args.iter().map(AsRef::as_ref).collect();
    let (sub, rest) = match args.first().copied() {
        Some("-h" | "--help" | "help") => return Ok(Command::Help),
        Some("-V" | "--version") => return Ok(Command::Version),
        Some(s @ ("install" | "units")) => (Some(s), &args[1..]),
        _ => (None, &args[..]),
    };
    let mut platform = None;
    let mut data_dir = None;
    let mut force = false;
    let mut it = rest.iter();
    while let Some(&a) = it.next() {
        let value = if a == "--platform" {
            Some(*it.next().ok_or("--platform needs unifi or debian")?)
        } else {
            a.strip_prefix("--platform=")
        };
        let dir = if sub.is_none() && a == "--data-dir" {
            Some(*it.next().ok_or("--data-dir needs a directory")?)
        } else if sub.is_none() {
            a.strip_prefix("--data-dir=")
        } else {
            None
        };
        if let Some(d) = dir {
            if data_dir.is_some() {
                return Err("--data-dir given twice".into());
            }
            data_dir = Some(d.to_string());
        } else if let Some(v) = value {
            if platform.is_some() {
                return Err("--platform given twice".into());
            }
            platform = Some(
                Platform::parse(v).ok_or_else(|| format!("unknown platform {v:?}; use unifi or debian"))?,
            );
        } else if a == "--force" && sub == Some("install") {
            force = true;
        } else if sub.is_none() && !a.starts_with('-') {
            return Err(format!("unknown command {a:?}"));
        } else {
            return Err(format!("unexpected argument {a:?}"));
        }
    }
    Ok(match sub {
        Some("install") => Command::Install { platform, force },
        Some("units") => Command::Units { platform },
        _ => Command::Update { platform, data_dir },
    })
}

/// Runs a command line against a host and a root (`/` in production) and returns the exit code.
/// `exe_dir` is the directory holding this binary, where `install` finds the release's three
/// binaries.
pub fn run<S: AsRef<str>>(
    root: &Root,
    sys: &dyn System,
    exe_dir: Option<&Path>,
    args: &[S],
    out: &mut dyn Write,
) -> u8 {
    let cmd = match parse(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("picket-edge-update: {e}\n{USAGE}");
            return 2;
        }
    };
    match cmd {
        Command::Help => {
            let _ = write!(out, "{USAGE}");
            0
        }
        Command::Version => {
            let _ = writeln!(out, "picket-edge-update {VERSION}");
            0
        }
        Command::Units { platform } => {
            let layout = Layout::for_platform(platform.unwrap_or_else(|| Platform::detect(root)));
            let printed = load_settings(root, &layout, sys, Purpose::Units).and_then(|settings| {
                let json = serde_json::to_string(&units::units_output(&layout, &settings))
                    .map_err(|e| crate::error::Error::msg(e.to_string()))?;
                writeln!(out, "{json}")?;
                Ok(())
            });
            match printed {
                Ok(()) => 0,
                Err(e) => {
                    log(&e.to_string());
                    1
                }
            }
        }
        Command::Install { platform, force } => {
            let Some(src_dir) = exe_dir else {
                log("can't find this binary's directory, where install takes the binaries from");
                return 1;
            };
            let opts = InstallOptions {
                platform,
                force,
                src_dir: src_dir.to_path_buf(),
                version: VERSION.to_string(),
            };
            match install(root, sys, &opts) {
                Ok(rep) => {
                    for a in &rep.actions {
                        let _ = writeln!(out, "  {a}");
                    }
                    for w in &rep.warnings {
                        eprintln!("warning: {w}");
                    }
                    let _ = writeln!(
                        out,
                        "picket-edge {} installed for {}{}",
                        rep.version,
                        rep.platform.map(Platform::as_str).unwrap_or("?"),
                        if rep.actions.is_empty() {
                            " (nothing to change)"
                        } else {
                            ""
                        }
                    );
                    0
                }
                Err(e) => {
                    eprintln!("picket-edge-update install: {e}");
                    1
                }
            }
        }
        Command::Update { platform, data_dir } => {
            if !sys.is_root() {
                log("must run as root (by picket-edge-update.service)");
                return 1;
            }
            let env = Env {
                root,
                sys,
                platform: platform.unwrap_or_else(|| Platform::detect(root)),
                data_dir,
            };
            match update::run(&env) {
                // Every outcome the edge should see is in update-result.json; exiting 0 keeps
                // the path unit and the service out of systemd's failure handling.
                Ok(RunEnd::Nothing | RunEnd::Duplicate | RunEnd::Result(_)) => 0,
                // The result couldn't be written: pending.json is kept for a later run, and the
                // failed service shows in the journal and `systemctl status`.
                Ok(RunEnd::Unrecorded(_)) => 1,
                Err(e) => {
                    log(&e.to_string());
                    1
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        let none: [&str; 0] = [];
        assert_eq!(
            parse(&none),
            Ok(Command::Update {
                platform: None,
                data_dir: None
            })
        );
        assert_eq!(
            parse(&["--platform", "unifi"]),
            Ok(Command::Update {
                platform: Some(Platform::Unifi),
                data_dir: None
            })
        );
        assert_eq!(
            parse(&["--platform=debian"]),
            Ok(Command::Update {
                platform: Some(Platform::Debian),
                data_dir: None
            })
        );
        assert_eq!(
            parse(&["--platform", "unifi", "--data-dir", "/data/picket/var"]),
            Ok(Command::Update {
                platform: Some(Platform::Unifi),
                data_dir: Some("/data/picket/var".into())
            })
        );
        assert_eq!(
            parse(&["--data-dir=/var/lib/picket"]),
            Ok(Command::Update {
                platform: None,
                data_dir: Some("/var/lib/picket".into())
            })
        );
        assert_eq!(
            parse(&["install"]),
            Ok(Command::Install {
                platform: None,
                force: false
            })
        );
        assert_eq!(
            parse(&["install", "--force", "--platform", "debian"]),
            Ok(Command::Install {
                platform: Some(Platform::Debian),
                force: true
            })
        );
        assert_eq!(
            parse(&["units", "--platform=unifi"]),
            Ok(Command::Units {
                platform: Some(Platform::Unifi)
            })
        );
        assert_eq!(parse(&["--help"]), Ok(Command::Help));
        assert_eq!(parse(&["--version"]), Ok(Command::Version));
        for bad in [
            &["units", "--force"][..],
            &["--force"],
            &["install", "--platform"],
            &["install", "--platform", "arch"],
            &["install", "--platform", "unifi", "--platform", "debian"],
            &["--platform", "unifi", "--platform", "unifi"],
            &["update"],
            &["install", "extra"],
            &["--platform", "unifi", "install"],
            &["--data-dir"],
            &["--data-dir", "/a", "--data-dir", "/b"],
            &["install", "--data-dir", "/a"],
            &["units", "--data-dir=/a"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse(&["update"]), Err("unknown command \"update\"".into()));
    }
}
