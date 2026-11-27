//! The CLI (edge.md §15). Every subcommand takes `--config`, `--data-dir` and `--runtime-dir`
//! as `run` does, so it reaches the edge they name.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};

use crate::admin::{self, CallError};
use crate::local_config::{self, CoreUrl};
use crate::paths::{self, DataLayout, HostPlatform};
use crate::service::{self, Options};
use crate::tls::{self, CoreVerifier, Pin};
use crate::{diag, identity};

#[derive(Parser, Debug)]
#[command(name = "picket-edge", version, about = "Picket's DNS filtering edge")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Args, Debug, Clone)]
pub struct Common {
    /// edge.json (default: /data/picket/etc/edge.json on UniFi, /etc/picket/edge.json on Debian).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    /// Overrides edge.json's data_dir.
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
    /// Holds the admin socket edge.sock.
    #[arg(long, global = true, default_value = paths::DEFAULT_RUNTIME_DIR)]
    pub runtime_dir: PathBuf,
}

impl Common {
    fn options(&self) -> Options {
        Options {
            config: self.config.clone(),
            data_dir: self.data_dir.clone(),
            runtime_dir: self.runtime_dir.clone(),
        }
    }
    fn socket(&self) -> PathBuf {
        self.runtime_dir.join(paths::ADMIN_SOCKET)
    }
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Service entry point; also a development edge (pipelines.md §9).
    Run {
        #[command(flatten)]
        common: Common,
    },
    /// Pin core's key (TOFU: shows core's fingerprint, asks y/N); prints this edge's key.
    Setup {
        #[command(flatten)]
        common: Common,
        /// Core's edge API, an IP literal URL such as https://192.168.1.20:7443.
        #[arg(long)]
        core: Option<String>,
        /// Pin this key without asking (SHA256:…).
        #[arg(long)]
        core_key: Option<String>,
        /// Reissue this edge's certificate with this name (same key).
        #[arg(long)]
        name: Option<String>,
        /// Trust the key core presents without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Print this edge's key fingerprint (paste it into the core UI).
    Key {
        #[command(flatten)]
        common: Common,
    },
    /// Versions, core session, listeners, bundles, memory, spool, firewall.
    Status {
        #[command(flatten)]
        common: Common,
        /// Print the raw JSON.
        #[arg(long)]
        json: bool,
    },
    /// Full ladder trace with bundle versions and the deciding rule; works offline.
    Explain {
        #[command(flatten)]
        common: Common,
        name: String,
        #[arg(long = "type")]
        qtype: Option<String>,
        /// The client address to explain the name for.
        #[arg(long, value_name = "IP")]
        client: Option<std::net::IpAddr>,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Install the release core offers.
    Update {
        #[command(flatten)]
        common: Common,
        /// Only show what core offers.
        #[arg(long)]
        check: bool,
    },
    /// No flag: the DNS cache and every lookup RAM tier.
    FlushCache {
        #[command(flatten)]
        common: Common,
        #[arg(long)]
        dns: bool,
        /// Every RAM tier, or one provider's.
        #[arg(long, num_args = 0..=1, default_missing_value = "*", value_name = "PROVIDER")]
        lookups: Option<String>,
    },
    /// List or revoke temporary allows.
    Allows {
        #[command(flatten)]
        common: Common,
        #[command(subcommand)]
        action: Option<AllowsCmd>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AllowsCmd {
    List,
    Revoke { id: String },
}

/// The binary's entry point.
pub fn main() -> ExitCode {
    diag::init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { common } => {
            let workers = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .min(4);
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("picket-edge: can't start the runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let code = rt.block_on(service::run(common.options()));
            u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from)
        }
        other => {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("picket-edge: can't start the runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(dispatch(other)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!(
                        "picket-edge: {}",
                        diag::cap_to(format_args!("{e:#}"), diag::MAX_JOURNAL)
                    );
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn dispatch(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Run { .. } => unreachable_run(),
        Cmd::Setup {
            common,
            core,
            core_key,
            name,
            yes,
        } => {
            // Not `stdin().lock()`: that guard would be held across setup's awaits. `Stdin` locks
            // only for each read.
            let mut input = std::io::BufReader::new(std::io::stdin());
            setup(&common, core, core_key, name, yes, &mut input).await
        }
        Cmd::Key { common } => key(&common),
        Cmd::Status { common, json } => status(&common, json).await,
        Cmd::Explain {
            common,
            name,
            qtype,
            client,
            profile,
        } => {
            let v = remote(
                &common,
                "explain",
                json!({"name": name, "type": qtype, "client": client, "profile": profile}),
                "explain",
            )
            .await?;
            print_json(&v);
            Ok(())
        }
        Cmd::Update { common, check } => {
            // Shows the offered version, then asks before installing it (edge.md §14 When).
            let v = remote(&common, "update", json!({"check": true}), "update").await?;
            print_json(&v);
            if check || !v["installable"].as_bool().unwrap_or(false) {
                return Ok(());
            }
            let offered = v["offered"].as_str().unwrap_or("?").to_owned();
            // The stdin guard is a temporary: it drops before the await below.
            if !confirm(
                &format!("Install picket-edge {offered}? [y/N] "),
                &mut std::io::stdin().lock(),
            )? {
                return Ok(());
            }
            let v = remote(&common, "update", json!({"check": false}), "update").await?;
            print_json(&v);
            Ok(())
        }
        Cmd::FlushCache { common, dns, lookups } => {
            let v = remote(
                &common,
                "flush",
                json!({"dns": dns, "lookups": lookups}),
                "flush-cache",
            )
            .await?;
            let what: Vec<String> = [
                v["dns"]
                    .as_bool()
                    .unwrap_or(false)
                    .then(|| "DNS cache".to_owned()),
                v["lookups"].as_str().map(|p| {
                    if p == "*" {
                        "every lookup RAM tier".to_owned()
                    } else {
                        format!("lookup RAM tier of {p}")
                    }
                }),
            ]
            .into_iter()
            .flatten()
            .collect();
            println!("flushed: {}", what.join(", "));
            Ok(())
        }
        Cmd::Allows { common, action } => match action.unwrap_or(AllowsCmd::List) {
            AllowsCmd::List => {
                let v = remote(&common, "allows.list", json!({}), "allows").await?;
                let list = v.as_array().cloned().unwrap_or_default();
                if list.is_empty() {
                    println!("no active temporary allows");
                }
                for a in list {
                    println!(
                        "{}  {}  {}  {}  until {}",
                        a["allow_id"].as_str().unwrap_or("?"),
                        a["kind"].as_str().unwrap_or("?"),
                        a["device_name"].as_str().or(a["device"].as_str()).unwrap_or("?"),
                        a["target"].as_str().unwrap_or("?"),
                        a["expires_at"].as_str().unwrap_or("?"),
                    );
                }
                Ok(())
            }
            AllowsCmd::Revoke { id } => {
                remote(&common, "allows.revoke", json!({"id": id}), "allows revoke").await?;
                println!("revoked {id}");
                Ok(())
            }
        },
    }
}

fn unreachable_run() -> Result<()> {
    bail!("run is handled before dispatch")
}

/// Calls the running edge; a command it doesn't know is reported as not available yet.
async fn remote(common: &Common, cmd: &str, args: Value, what: &str) -> Result<Value> {
    match admin::call(&common.socket(), cmd, args).await {
        Ok(v) => Ok(v),
        Err(CallError::Remote(e)) if e.code == "unknown_command" => Err(anyhow!(
            "{what} isn't available yet: the running edge doesn't implement it"
        )),
        Err(e) => Err(anyhow!("{e}")),
    }
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn layout_for(common: &Common) -> Result<(HostPlatform, PathBuf, local_config::LocalConfig, DataLayout)> {
    let platform = HostPlatform::detect();
    let (config, local, data_dir) = service::resolve(&common.options(), platform)?;
    Ok((platform, config, local, DataLayout::new(data_dir)))
}

/// `key`: prints this edge's fingerprint, creating the identity at first use.
fn key(common: &Common) -> Result<()> {
    let (_, _, _, layout) = layout_for(common)?;
    service::ensure_data_dir(&layout.root)?;
    let id = identity::load_or_create(&layout)?;
    println!("{}", id.fingerprint);
    Ok(())
}

/// `setup` (api.md §1 First-time setup).
pub async fn setup(
    common: &Common,
    core: Option<String>,
    core_key: Option<String>,
    name: Option<String>,
    yes: bool,
    input: &mut dyn BufRead,
) -> Result<()> {
    let (_, config_path, local, layout) = layout_for(common)?;
    service::ensure_data_dir(&layout.root)?;
    let id = match &name {
        Some(n) => identity::reissue(&layout, n)?,
        None => identity::load_or_create(&layout)?,
    };
    let url = match core.as_deref() {
        Some(u) => CoreUrl::parse(u)?,
        None => local.core_url.clone().ok_or_else(|| {
            anyhow!(
                "--core https://<core IP>:7443 is needed (no core_url in {})",
                config_path.display()
            )
        })?,
    };
    let pin = match core_key {
        Some(k) => {
            if picket_api::ids::parse_fingerprint(k.trim()).is_none() {
                bail!("--core-key {k:?} isn't a SHA256:… fingerprint");
            }
            k.trim().to_owned()
        }
        None => {
            let fp = tofu_fingerprint(&url, &id).await?;
            println!("Core at {} presents key {fp}", url.text);
            if local.core_key.as_deref() == Some(fp.as_str()) {
                println!("This key is already pinned.");
            } else if local.core_key.is_some() {
                println!(
                    "WARNING: edge.json pins another key ({}).",
                    local.core_key.as_deref().unwrap_or("")
                );
            }
            if !yes && !confirm("Trust this key? [y/N] ", input)? {
                bail!("not trusted; edge.json unchanged");
            }
            fp
        }
    };
    local_config::write_core_pin(&config_path, &url, &pin)?;
    println!("Pinned core key {pin} in {}", config_path.display());
    println!("This edge's key: {}", id.fingerprint);
    println!("Add it in the core UI (Edges → Add), or approve it under Edges → Pending.");
    if admin::edge_answers(&common.socket()) {
        // edge.json is read at start.
        println!("picket-edge is running: restart it to use the new pin.");
    }
    Ok(())
}

fn confirm(prompt: &str, input: &mut dyn BufRead) -> Result<bool> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

/// Connects to core unpinned and returns the fingerprint of the key that signed the handshake:
/// recorded only once that signature verified, so a key is never taken on sight (api.md §1).
pub async fn tofu_fingerprint(url: &CoreUrl, id: &identity::Identity) -> Result<String> {
    let verifier = CoreVerifier::new(Pin::Tofu);
    let cfg = tls::client_config(id, Arc::clone(&verifier))?;
    let conn = tls::connect(url.addr, cfg, Duration::from_secs(10)).await;
    // Core may refuse our (not yet approved) client key after we verified it: the verified
    // fingerprint still stands.
    match (verifier.verified_fingerprint(), conn) {
        (Some(fp), _) => Ok(fp),
        (None, Err(e)) => Err(e).context("connecting to core"),
        (None, Ok(_)) => Err(anyhow!("core's handshake didn't prove its key")),
    }
}

/// `status`: a readable summary, or `--json`.
async fn status(common: &Common, raw: bool) -> Result<()> {
    let v = remote(common, "status", json!({}), "status").await?;
    if raw {
        print_json(&v);
        return Ok(());
    }
    let s = |p: &str| v.pointer(p).and_then(Value::as_str).unwrap_or("-").to_owned();
    let n = |p: &str| v.pointer(p).and_then(Value::as_u64);
    println!(
        "picket-edge {}  boot {}  up {}s",
        s("/edge_version"),
        s("/boot"),
        n("/up_ms").unwrap_or(0) / 1000
    );
    println!("name {}  key {}", s("/name"), s("/fingerprint"));
    println!("platform {}  firmware {}", s("/platform"), s("/firmware"));
    println!(
        "config file {}  data_dir {}  runtime_dir {}  ssd_dir {}",
        s("/paths/config"),
        s("/paths/data_dir"),
        s("/paths/runtime_dir"),
        s("/paths/ssd_dir")
    );
    println!("config {}  ready_version {}", s("/config"), s("/ready_version"));
    println!(
        "core {} ({}){}",
        s("/core/state"),
        s("/core/core_url"),
        v.pointer("/core/last_error")
            .and_then(Value::as_str)
            .map(|e| format!("  last error: {e}"))
            .unwrap_or_default()
    );
    let listeners = v
        .pointer("/listeners")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    println!("listeners {}", listeners.len());
    for l in &listeners {
        let f = |k: &str| l.get(k).and_then(Value::as_str).unwrap_or("-").to_owned();
        println!(
            "  {} {} {} {}{}",
            f("id"),
            f("proto"),
            f("bind"),
            f("state"),
            l.get("error")
                .and_then(Value::as_str)
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        );
    }
    let bundles = v
        .pointer("/bundles")
        .and_then(Value::as_object)
        .map_or(0, |m| m.len());
    println!("bundles {bundles}");
    println!(
        "memory rss {}  available {}  unit {}",
        fmt_bytes(n("/memory/rss")),
        fmt_bytes(n("/memory/mem_available")),
        fmt_bytes(n("/memory/cgroup"))
    );
    println!(
        "logs to {}  spool {} ({} segments, {} buffered)  dropped {}",
        if s("/spool/mode") == "spool" {
            "the spool"
        } else {
            "core from memory"
        },
        fmt_bytes(n("/spool/bytes")),
        n("/spool/segments").unwrap_or(0),
        n("/spool/buffered").unwrap_or(0),
        v.pointer("/spool/dropped")
            .map(Value::to_string)
            .unwrap_or_default()
    );
    println!(
        "firewall {}",
        if v.pointer("/firewall").is_none_or(Value::is_null) {
            "-".into()
        } else {
            v["firewall"].to_string()
        }
    );
    if let Some(ssd) = v.pointer("/ssd").filter(|x| !x.is_null()) {
        println!("ssd {}", ssd);
    }
    for c in v
        .pointer("/conditions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        println!(
            "condition {}{} since {}{}",
            c["kind"].as_str().unwrap_or("?"),
            c["key"].as_str().map(|k| format!("[{k}]")).unwrap_or_default(),
            c["since"].as_str().unwrap_or("?"),
            c.get("detail").map(|d| format!(": {d}")).unwrap_or_default()
        );
    }
    Ok(())
}

fn fmt_bytes(b: Option<u64>) -> String {
    match b {
        None => "-".into(),
        Some(b) if b >= 1 << 30 => format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64),
        Some(b) if b >= 1 << 20 => format!("{:.1} MiB", b as f64 / (1u64 << 20) as f64),
        Some(b) => format!("{} KiB", b / 1024),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_subcommand_with_common_flags() {
        let c = Cli::parse_from([
            "picket-edge",
            "run",
            "--config",
            "./dev/edge.json",
            "--data-dir",
            "./dev/edge",
            "--runtime-dir",
            "./dev/run",
        ]);
        let Cmd::Run { common } = c.cmd else { panic!() };
        assert_eq!(common.runtime_dir, PathBuf::from("./dev/run"));
        let c = Cli::parse_from(["picket-edge", "flush-cache", "--lookups"]);
        let Cmd::FlushCache { lookups, dns, .. } = c.cmd else {
            panic!()
        };
        assert_eq!(lookups.as_deref(), Some("*"));
        assert!(!dns);
        let c = Cli::parse_from([
            "picket-edge",
            "flush-cache",
            "--lookups",
            "am-rt",
            "--runtime-dir",
            "/tmp/r",
        ]);
        let Cmd::FlushCache { lookups, common, .. } = c.cmd else {
            panic!()
        };
        assert_eq!(lookups.as_deref(), Some("am-rt"));
        assert_eq!(common.runtime_dir, PathBuf::from("/tmp/r"));
        let c = Cli::parse_from([
            "picket-edge",
            "explain",
            "ads.example.com",
            "--type",
            "AAAA",
            "--client",
            "192.168.1.5",
            "--profile",
            "kids",
        ]);
        assert!(matches!(c.cmd, Cmd::Explain { .. }));
        let c = Cli::parse_from([
            "picket-edge",
            "setup",
            "--core",
            "https://10.0.0.2:7443",
            "--yes",
            "--name",
            "ucg",
        ]);
        assert!(matches!(c.cmd, Cmd::Setup { yes: true, .. }));
        let c = Cli::parse_from(["picket-edge", "allows", "revoke", "a-19"]);
        assert!(matches!(
            c.cmd,
            Cmd::Allows {
                action: Some(AllowsCmd::Revoke { .. }),
                ..
            }
        ));
        assert!(
            Cli::try_parse_from(["picket-edge", "explain", "x.example", "--client", "not-an-ip"]).is_err()
        );
        let c = Cli::parse_from(["picket-edge", "update", "--check"]);
        assert!(matches!(c.cmd, Cmd::Update { check: true, .. }));
        let c = Cli::parse_from(["picket-edge", "key"]);
        let Cmd::Key { common } = c.cmd else { panic!() };
        assert_eq!(common.runtime_dir, PathBuf::from("/run/picket"));
    }
}
