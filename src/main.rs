// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::PathBuf;
use std::process::ExitCode;

use tsec::catalog::Catalog;
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
    let registry = Registry::load(&root.join("catalog/verification.json"))?
        .with_search_paths(cfg.tools.search_paths.clone());

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--status" | "-s" => {
                println!("{}", catalog.availability_summary(&registry));
                for (phase, caps) in catalog.grouped() {
                    if caps.is_empty() {
                        continue;
                    }
                    let ready = caps.iter().filter(|c| c.is_available(&registry)).count();
                    println!("  {phase:<14} {ready}/{} available", caps.len());
                }
                let backend = OniuxBackend::new(&cfg.execution.oniux_binary);
                match backend.resolve() {
                    Ok(path) => println!("  {:<14} {}", "BOUNDARY", path.display()),
                    Err(e) => println!("  {:<14} UNAVAILABLE — {}", "BOUNDARY", e.reason()),
                }
                return Ok(());
            }
            "--version" | "-v" => {
                println!("tsec v{}", tsec::VERSION);
                return Ok(());
            }
            "--help" | "-h" => {
                println!("TSEC — Tactical Security Enumeration & Compromise Framework");
                println!();
                println!("Usage: tsec [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -s, --status    Display capability availability and network boundary status");
                println!("  -v, --version   Display version information");
                println!("  -h, --help      Display this help message");
                return Ok(());
            }
            _ => {}
        }
    }

    main_menu(&cfg, &catalog, &registry)
}

fn data_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("TSEC_HOME") {
        return PathBuf::from(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
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
