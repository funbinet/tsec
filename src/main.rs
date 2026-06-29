//! TSEC — Tactical Security Enumeration & Compromise Framework.
//! Main execution loop.

mod anonymity;
mod config;
mod executor;
mod input;
mod logger;
mod parser;
mod tools;
mod ui;

use chrono::Local;
use std::path::Path;
use anyhow::Result;

use anonymity::proxy::ProxyManager;
use config::Config;
use logger::Logger;
use ui::menu::{mode_menu, outputs_menu, settings_menu, tool_menu, top_menu, MenuResult, TopMenuChoice};
use ui::theme::{
    cprintln, grey, print_error, print_info, print_success, print_warn, section_header, wait_key, white,
};

/// Saved state for restoring spoofed identity on exit.
#[derive(Clone)]
struct SpoofState {
    original_hostname: Option<String>,
    original_mac: Option<(String, String)>, // (interface, original_mac)
    anonymity_enabled: bool,
}

fn main() -> Result<()> {
    // 1. Ensure config and output dirs exist; load config.
    let mut cfg = Config::load_or_create()?;
    std::fs::create_dir_all(cfg.output_dir())?;
    std::fs::create_dir_all(cfg.log_dir())?;

    // 2. Init logger.
    let log_path = format!("{}/tsec.log", cfg.log_dir());
    let logger = Logger::open(&log_path).unwrap_or_else(|_| Logger::open("/tmp/tsec.log").unwrap());
    logger.info("Framework session started.");

    // 3. Load tool registry (zero-cost static refs).
    let categories = tools::build_registry();

    // 4. Initialize anonymity subsystem.
    let mut proxy_mgr = ProxyManager::new(
        cfg.anonymity.proxy_pool.clone(),
        cfg.anonymity.proxy_rotation_secs,
    );

    // Enable log sanitization if anonymity is on
    if cfg.anonymity.enabled && cfg.anonymity.sanitize_output {
        Logger::set_sanitize(true);
    }

    let spoof_state = std::sync::Arc::new(std::sync::Mutex::new(SpoofState {
        original_hostname: None,
        original_mac: None,
        anonymity_enabled: cfg.anonymity.enabled,
    }));

    // ── Setup Ctrl+C Handler ──────────────────────────────────────────
    let spoof_state_ctrlc = std::sync::Arc::clone(&spoof_state);
    ctrlc::set_handler(move || {
        if let Ok(logger) = Logger::open("/opt/tsec/logs/tsec.log") {
            logger.info("Caught SIGINT (Ctrl+C). Executing teardown sequence...");
            if let Ok(state) = spoof_state_ctrlc.lock() {
                cleanup_spoof(&state, &logger);
            }
            // Fix terminal if we were in the middle of crossterm
            let _ = crossterm::terminal::disable_raw_mode();
        }
        std::process::exit(1);
    }).unwrap_or(());

    // ── Tor Circuit Auto-Renewal & Async IP Fetch Thread ────────────────
    let anon_cfg_for_thread = cfg.anonymity.clone();
    std::thread::spawn(move || {
        if anon_cfg_for_thread.enabled && anon_cfg_for_thread.tor_enabled {
            let tor_mgr = anonymity::tor::TorManager::new(&anon_cfg_for_thread.tor_socks_addr);
            
            // Initial fetch so the UI shows something quickly if available
            tor_mgr.update_cached_ip();

            let mut elapsed = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                elapsed += 5;
                
                // Fetch the IP periodically
                tor_mgr.update_cached_ip();
                
                // Check if we need to forcefully renew the circuit
                if anon_cfg_for_thread.tor_renewal_secs > 0 && elapsed >= anon_cfg_for_thread.tor_renewal_secs {
                    if tor_mgr.is_running() {
                        let _ = tor_mgr.new_circuit();
                        if let Ok(logger) = Logger::open("/opt/tsec/logs/tsec.log") {
                            logger.info("Anonymity: Auto-renewed Tor circuit (rotated IP).");
                        }
                    }
                    elapsed = 0;
                }
            }
        }
    });

    if cfg.anonymity.enabled {
        logger.info("Anonymity mode: ENABLED");

        if cfg.anonymity.tor_enabled {
            let _ = std::process::Command::new("systemctl").args(&["start", "tor"]).status();
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        // MAC spoofing (requires root + macchanger)
        if cfg.anonymity.mac_spoofing {
            if anonymity::stealth::macchanger_available() {
                if let Some(iface) = anonymity::stealth::default_interface() {
                    match anonymity::stealth::spoof_mac(&iface) {
                        Ok(original) => {
                            if let Ok(mut state) = spoof_state.lock() {
                                state.original_mac = Some((iface, original));
                            }
                            logger.info("MAC address spoofed successfully.");
                        }
                        Err(e) => logger.warn(&format!("MAC spoof failed: {e}")),
                    }
                } else {
                    logger.warn("Could not detect default network interface for MAC spoofing.");
                }
            } else {
                logger.warn("macchanger not installed — skipping MAC spoof.");
            }
        }

        // Hostname spoofing
        if cfg.anonymity.hostname_spoofing {
            match anonymity::stealth::spoof_hostname() {
                Ok(original) => {
                    if let Ok(mut state) = spoof_state.lock() {
                        state.original_hostname = Some(original);
                    }
                    logger.info("Hostname spoofed successfully.");
                }
                Err(e) => logger.warn(&format!("Hostname spoof failed: {e}")),
            }
        }
    }

    // Draw the banner (with anonymity status if enabled).
    ui::theme::draw_banner_with_anon(&cfg.anonymity);

    // 5. Main interaction loop.
    loop {
        let top_choice = match top_menu() {
            Ok(c) => c,
            Err(e) => {
                logger.error(&format!("Menu error: {e}"));
                break;
            }
        };

        match top_choice {
            TopMenuChoice::Category(cat_idx) => {
                let cat = categories[cat_idx];
                // Loop at tool selection
                'tool_loop: loop {
                    match tool_menu(cat)? {
                        MenuResult::Selected(tool) | MenuResult::TimeoutOverride(tool) => {
                            // Loop at mode selection
                            loop {
                                match mode_menu(tool)? {
                                    MenuResult::Selected(mode) => {
                                        // Execute workflow.
                                        run_workflow(tool, mode, &cfg, &logger, &mut proxy_mgr)?;
                                    }
                                    MenuResult::TimeoutOverride(mode) => {
                                        // Prompt for custom timeout
                                        let theme = crate::input::hacker_theme();
                                        let t_str: String = dialoguer::Input::with_theme(&theme)
                                            .with_prompt("Custom timeout (0 = infinite)")
                                            .default(cfg.timeout_secs().to_string())
                                            .interact_text()?;
                                        let custom_t = t_str.parse::<u64>().unwrap_or(cfg.timeout_secs());
                                        let mut temp_cfg = cfg.clone();
                                        temp_cfg.general.timeout_secs = custom_t;
                                        run_workflow(tool, mode, &temp_cfg, &logger, &mut proxy_mgr)?;
                                    }
                                    MenuResult::Back => break,
                                    MenuResult::Home => break 'tool_loop,
                                    MenuResult::Exit => {
                                        if let Ok(state) = spoof_state.lock() {
                                            cleanup_spoof(&state, &logger);
                                        }
                                        std::process::exit(0);
                                    }
                                }
                            }
                        }
                        MenuResult::Back => break 'tool_loop,
                        MenuResult::Home => break 'tool_loop,
                        MenuResult::Exit => {
                            if let Ok(state) = spoof_state.lock() {
                                cleanup_spoof(&state, &logger);
                            }
                            std::process::exit(0);
                        }
                    }
                }
            }
            TopMenuChoice::Outputs => {
                let _ = outputs_menu(&cfg)?;
            }
            TopMenuChoice::Settings => {
                if let Some(new_cfg) = settings_menu(&cfg)? {
                    // Rebuild proxy manager if pool changed
                    proxy_mgr = ProxyManager::new(
                        new_cfg.anonymity.proxy_pool.clone(),
                        new_cfg.anonymity.proxy_rotation_secs,
                    );
                    cfg = new_cfg; // Update live config if user saved.
                    logger.info("Configuration updated by user.");
                }
            }
            TopMenuChoice::Exit => {
                cprintln(grey(), "\n  Exiting TSEC. \n");
                logger.info("Framework session ended normally.");
                if let Ok(state) = spoof_state.lock() {
                    cleanup_spoof(&state, &logger);
                }
                break;
            }
        }
    }

    Ok(())
}

/// Clean up spoofed MAC, hostname, and Tor on exit.
fn cleanup_spoof(state: &SpoofState, logger: &Logger) {
    if state.anonymity_enabled {
        let _ = std::process::Command::new("systemctl").args(&["stop", "tor"]).status();
        logger.info("Tor service stopped.");
    }
    if let Some(ref original) = state.original_hostname {
        if let Err(e) = anonymity::stealth::restore_hostname(original) {
            logger.warn(&format!("Failed to restore hostname: {e}"));
        } else {
            logger.info("Hostname restored.");
        }
    }
    if let Some((ref iface, ref mac)) = state.original_mac {
        if let Err(e) = anonymity::stealth::restore_mac(iface, mac) {
            logger.warn(&format!("Failed to restore MAC: {e}"));
        } else {
            logger.info("MAC address restored.");
        }
    }
}

/// The core execution workflow:
/// 1. Check dependencies.
/// 2. Collect inputs.
/// 3. Build & run command (with anonymity if enabled).
/// 4. Parse & display results.
fn run_workflow(
    tool: &tools::types::Tool,
    mode: &tools::types::Mode,
    cfg: &Config,
    logger: &Logger,
    proxy_mgr: &mut ProxyManager,
) -> Result<()> {
    section_header(&format!("{} :: {}", tool.name, mode.name));

    // 1. Dependency check.
    if !executor::check_binary(tool.binary) {
        let msg = format!("Missing dependency: `{}` is not in PATH.", tool.binary);
        logger.warn(&msg);
        print_error(&msg);
        print_info(&format!("Try: {}", executor::install_hint(tool.binary)));
        wait_key();
        return Ok(());
    }

    // 2. Collect Inputs.
    let inputs = input::collect_inputs(mode, cfg)?;

    // 3. Prepare paths & command.
    let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let out_name = format!("{}_{}_{}.{}", tool.binary, mode.name.replace(" ", "_"), ts, mode.file_ext);
    let out_path = format!("{}/{}", cfg.output_dir(), out_name);

    let cmd = executor::build_command(mode.cmd_template, &inputs, &out_path, &ts);

    println!();
    if cfg.anonymity.enabled {
        cprintln(grey(), &format!("  Exec (ANON): {}", cmd));
    } else {
        cprintln(grey(), &format!("  Exec: {}", cmd));
    }
    println!();

    // Sanitize the command before logging when anonymity is on
    if cfg.anonymity.enabled && cfg.anonymity.sanitize_output {
        logger.info(&format!("Running (anon): {}", anonymity::sanitizer::sanitize(&cmd)));
    } else {
        logger.info(&format!("Running: {}", cmd));
    }

    // 4. Execute — through anonymity layer or direct.
    let spinner = ui::spinner::Spinner::start("EXECUTING");

    let result = if cfg.anonymity.enabled {
        anonymity::wrapper::run_anonymized(&cmd, cfg.timeout_secs(), &cfg.anonymity, proxy_mgr)
    } else {
        executor::run_command(&cmd, cfg.timeout_secs())
    };

    spinner.stop();

    match result {
        Ok(exec) => {
            if exec.exit_code != 0 {
                logger.warn(&format!("Command returned non-zero ({}): {}", exec.exit_code, cmd));
                print_error(&format!("Command failed (exit {})", exec.exit_code));
                if !exec.stderr.is_empty() {
                    cprintln(white(), &exec.stderr);
                }
            } else {
                print_success(&format!("Completed in {:.1}s", exec.duration.as_secs_f32()));
                if cfg.anonymity.enabled {
                    print_info("Executed through anonymity layer.");
                }
            }

            // 5. Parse and Display Output.
            if Path::new(&out_path).exists() {
                // Sanitize the output file if anonymity is enabled
                if cfg.anonymity.enabled && cfg.anonymity.sanitize_output {
                    if let Err(e) = anonymity::sanitizer::sanitize_file(&out_path) {
                        logger.warn(&format!("Output sanitization failed: {e}"));
                    }
                }

                let raw_out = std::fs::read_to_string(&out_path).unwrap_or_default();
                let parsed = parser::parse_output(&raw_out, mode.output_format);
                ui::output::display_result(&parsed, mode.output_format, &out_path, cfg.preview_lines());
            } else {
                logger.error(&format!("Output file not created: {}", out_path));
                print_error("No output file generated by the tool.");
                // If stdout has something, show it as fallback.
                if !exec.stdout.is_empty() {
                    cprintln(grey(), "\n--- Standard Output Fallback ---");
                    println!("{}", exec.stdout);
                }
            }
        }
        Err(e) => {
            let err_msg = format!("{}", e);
            if err_msg.contains("KILL SWITCH") {
                logger.error(&err_msg);
                print_error(&err_msg);
                print_warn("Anonymity layer is DOWN. Fix the issue or disable anonymity in Settings.");
            } else {
                logger.error(&format!("Execution failed: {}", e));
                print_error(&format!("Execution error: {}", e));
            }
        }
    }

    wait_key();
    Ok(())
}

