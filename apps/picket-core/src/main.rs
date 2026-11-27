//! picket-core's binary: see `picket_core::cli`.

use clap::Parser;

fn main() -> std::process::ExitCode {
    // Everything core creates holds the argon2 hash, configuration, secrets or logs: owner-only,
    // whatever umask the process was started with (a container, a manual start). Directories
    // get 0750 explicitly where they are created (security.md §4, storage.md §2).
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    let filter = tracing_subscriber::EnvFilter::try_from_env("PICKET_CORE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
    let cli = picket_core::cli::Cli::parse();
    match picket_core::cli::dispatch(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            if !e.message.is_empty() {
                eprintln!("picket-core: {}", e.message);
            }
            std::process::ExitCode::from(e.code)
        }
    }
}
