//! picket-edge-update (edge.md §15). See the library docs and [`cli::run`] for what each command
//! does.

use std::path::Path;
use std::process::ExitCode;

use picket_edge_update::cli;
use picket_edge_update::fsx::Root;
use picket_edge_update::system::RealSystem;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `install` copies the three binaries next to this one.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let code = cli::run(
        &Root::system(),
        &RealSystem::default(),
        exe_dir.as_deref(),
        &args,
        &mut std::io::stdout(),
    );
    ExitCode::from(code)
}
