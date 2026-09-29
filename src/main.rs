//! `tsec` — command line entry point.
//!
//! All behaviour lives in the library; this binary exists to start it and to map
//! an error onto an exit status.

use std::path::PathBuf;
use std::process::ExitCode;

use tsec::catalog::Catalog;
use tsec::config::Config;
use tsec::error::{Result, Stage};
use tsec::exec::OniuxBackend;
use tsec::provider::Registry;
use tsec::ui::theme::Theme;

/// Exit code for an error raised while presenting results.
const EXIT_DISPLAY: u8 = 1;
/// Exit code for any other error.
const EXIT_FAILURE: u8 = 2;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tsec: {e}");
            if let Some(hint) = &e.hint {
                eprintln!("  hint: {hint}");
            }
            ExitCode::from(if e.stage == Stage::Display {
                EXIT_DISPLAY
            } else {
                EXIT_FAILURE
            })
        }
    }
}

fn run() -> Result<()> {
    let cfg = Config::load_or_create()?;
    let theme = Theme::detect(cfg.general.color);
    println!("tsec {} · {}", tsec::VERSION, theme.describe());

    let root = data_root();
    let catalog = Catalog::load(&root.join("catalog/capabilities.toml"))?;
    let registry = Registry::load(&root.join("catalog/verification.json"))?
        .with_search_paths(cfg.tools.search_paths.clone());

    println!("{}", catalog.availability_summary(&registry));
    for (phase, caps) in catalog.grouped() {
        if caps.is_empty() {
            continue;
        }
        let ready = caps.iter().filter(|c| c.is_available(&registry)).count();
        println!("  {phase:<14} {ready}/{} available", caps.len());
    }

    // Report the network boundary, but do not run the full environment probe
    // here: this is a status view, and probing boots a Tor client. The probe
    // happens before the first network task in a real run.
    let backend = OniuxBackend::new(&cfg.execution.oniux_binary);
    match backend.resolve() {
        Ok(path) => println!("  {:<14} {}", "BOUNDARY", path.display()),
        Err(e) => println!("  {:<14} UNAVAILABLE — {}", "BOUNDARY", e.reason()),
    }
    Ok(())
}

/// Directory holding the catalog and verification snapshot.
///
/// `TSEC_HOME` wins when set, so a test or an alternate install can point the
/// framework at a different catalog without touching the system one.
fn data_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("TSEC_HOME") {
        return PathBuf::from(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        // target/debug/tsec → the crate root two levels up.
        if let Some(root) = exe
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
        {
            if root.join("catalog").is_dir() {
                return root.to_path_buf();
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
