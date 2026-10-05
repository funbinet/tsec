// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::PathBuf;
use std::process::ExitCode;

use tsec::catalog::{wordlist_root, Catalog};
use tsec::config::Config;
use tsec::error::{Result, Stage};
use tsec::exec::OniuxBackend;
use tsec::provider::Registry;
use tsec::ui::menu::main_menu;

const EXIT_DISPLAY: u8 = 1;
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
    let root = data_root();
    let catalog = Catalog::load(&root.join("catalog/capabilities.toml"))?;
    let registry = Registry::from_catalog(&catalog, cfg.tools.search_paths.clone());

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--status" | "-s" => {
                println!("TSEC {}", tsec::VERSION);
                println!("{}", catalog.availability_summary());
                for (phase, caps) in catalog.grouped() {
                    let ready = caps.iter().filter(|c| c.is_available()).count();
                    println!("{:<14} {ready}/{}", phase, caps.len());
                }
                let backend = OniuxBackend::new(&cfg.execution.oniux_binary);
                match backend.resolve() {
                    Ok(path) => println!("{:<14} {}", "BOUNDARY", path.display()),
                    Err(e) => println!("{:<14} UNAVAILABLE · {}", "BOUNDARY", e.reason()),
                }

                // A wordlist gap has one fix, so it is reported on its own line
                // rather than buried in a per-capability list.
                let missing = catalog.missing_wordlists();
                if !missing.is_empty() {
                    println!("{:<14} {} missing", "WORDLISTS", missing.len());
                    for name in &missing {
                        println!("               - {name}");
                    }
                    println!(
                        "               run wordlists/fetch-wordlists.sh, or set \
                         TSEC_WORDLIST_ROOT to a directory that has them"
                    );
                } else {
                    println!(
                        "{:<14} {}",
                        "WORDLISTS",
                        wordlist_root(catalog.source()).display()
                    );
                }

                // Everything else the loader noticed but did not refuse to start
                // over. An argument carrying shell syntax reaches the tool
                // verbatim, so it produces a run that looks clean and is not.
                let other: Vec<&String> = catalog
                    .advisories()
                    .iter()
                    .filter(|a| !a.contains("wordlist `"))
                    .collect();
                if !other.is_empty() {
                    println!();
                    println!(
                        "{:<14} {} (an argument that is a shell operator means an unsplit command line)",
                        "CATALOG NOTES",
                        other.len()
                    );
                    for note in other.iter().take(20) {
                        println!("               - {note}");
                    }
                    if other.len() > 20 {
                        println!("               ... and {} more", other.len() - 20);
                    }
                }
                return Ok(());
            }
            "--version" | "-v" => {
                println!("tsec v{}", tsec::VERSION);
                return Ok(());
            }
            "--help" | "-h" => {
                println!("TSEC {}", tsec::VERSION);
                println!();
                println!("Usage: tsec [OPTIONS]");
                println!();
                println!("Options:");
                println!(
                    "  -s, --status    Report capability availability and the network boundary"
                );
                println!("  -v, --version   Display version information");
                println!("  -h, --help      Display this help message");
                return Ok(());
            }
            _ => {}
        }
    }

    main_menu(&cfg, &catalog, &registry)
}

/// Where `catalog/capabilities.toml` lives.
///
/// The order matters for installed use: an explicit `TSEC_HOME` wins, then the
/// framework root an installer populated, then the build tree the binary was
/// compiled from. A path without a catalog is never chosen, so a wrong guess
/// fails as "catalog not found" instead of silently reading someone else's.
fn data_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("TSEC_HOME") {
        let dir = PathBuf::from(dir);
        if !dir.as_os_str().is_empty() {
            return dir;
        }
    }
    let system = PathBuf::from("/opt/tsec");
    if system.join("catalog").is_dir() {
        return system;
    }
    let build_tree = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if build_tree.join("catalog").is_dir() {
        return build_tree;
    }
    system
}
