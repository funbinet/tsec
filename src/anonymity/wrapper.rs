//! Anonymized command wrapper — the core anonymity execution engine.
//! Intercepts all tool commands and routes them through the configured
//! anonymity layers (proxychains, Tor, timing jitter, env vars).

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Result};
use rand::Rng;

use crate::anonymity::proxy::ProxyManager;
use crate::anonymity::sanitizer;
use crate::anonymity::stealth;
use crate::anonymity::tor::TorManager;
use crate::config::settings::Anonymity;
use crate::executor::{self, ExecResult};

/// Execute a command through the anonymity layer.
///
/// This is the primary entry point. It:
/// 1. Pre-flight: validates the anonymity layer is operational (kill switch).
/// 2. Injects random timing delay to defeat traffic correlation.
/// 3. Builds proxy/Tor env vars or proxychains wrapper.
/// 4. Executes the command with anonymization.
/// 5. Sanitizes output if enabled.
/// 6. Auto-rotates the proxy pool if needed.
pub fn run_anonymized(
    cmd: &str,
    timeout_secs: u64,
    config: &Anonymity,
    proxy_mgr: &mut ProxyManager,
) -> Result<ExecResult> {
    // ── 1. Pre-flight / kill switch ────────────────────────────────────
    if config.kill_switch {
        preflight_check(config, proxy_mgr)?;
    }

    // ── 2. Timing jitter ───────────────────────────────────────────────
    if config.delay_min_ms > 0 || config.delay_max_ms > 0 {
        let delay = if config.delay_max_ms > config.delay_min_ms {
            rand::thread_rng().gen_range(config.delay_min_ms..=config.delay_max_ms)
        } else {
            config.delay_min_ms
        };
        std::thread::sleep(Duration::from_millis(delay));
    }

    // ── 3. Build environment variables ─────────────────────────────────
    let mut env_vars: HashMap<String, String> = HashMap::new();

    // User-Agent rotation
    if config.user_agent_rotation {
        let ua = stealth::random_user_agent();
        env_vars.insert("USER_AGENT".to_string(), ua.to_string());
        // Some tools respect these
        env_vars.insert("HTTP_USER_AGENT".to_string(), ua.to_string());
    }

    // Proxy env vars (even when using proxychains, some tools check these)
    if config.tor_enabled {
        let tor_url = format!("socks5h://{}", config.tor_socks_addr);
        env_vars.insert("ALL_PROXY".to_string(), tor_url.clone());
        env_vars.insert("SOCKS5_PROXY".to_string(), tor_url.clone());
        env_vars.insert("http_proxy".to_string(), tor_url.clone());
        env_vars.insert("https_proxy".to_string(), tor_url);
    } else if let Some(proxy) = proxy_mgr.get_current() {
        env_vars.insert("ALL_PROXY".to_string(), proxy.to_string());
        env_vars.insert("http_proxy".to_string(), proxy.to_string());
        env_vars.insert("https_proxy".to_string(), proxy.to_string());
        if proxy.starts_with("socks") {
            env_vars.insert("SOCKS5_PROXY".to_string(), proxy.to_string());
        }
    }

    // DNS-over-HTTPS: set a flag so tools using system DNS are aware
    // (actual DoH routing is handled by proxychains or Tor)
    if config.dns_over_https {
        env_vars.insert("RES_OPTIONS".to_string(), "use-vc".to_string());
    }

    // ── 4. Smart Proxychains Bypass ────────────────────────────────────
    // Go binaries statically link their own network/DNS stack which ignores
    // libc LD_PRELOAD. Using proxychains with proxy_dns enabled causes them
    // to instantly fail DNS resolution and silently exit with 0 results.
    // Since we inject ALL_PROXY above, Go binaries will naturally route via
    // SOCKS/Tor perfectly without proxychains wrapper.
    let is_go_binary = is_static_go_tool(cmd);
    
    let final_cmd = if config.use_proxychains && !is_go_binary {
        // Wrap with proxychains-ng for transparent SOCKS routing
        format!("proxychains4 -q sh -c '{}'", cmd.replace('\'', "'\\''"))
    } else {
        cmd.to_string()
    };

    // Give visual feedback if we dynamically bypassed proxychains
    if config.use_proxychains && is_go_binary {
        if let Ok(logger) = crate::logger::Logger::open("/opt/sec/logs/sec.log") {
            logger.info(&format!("Anonymity: Bypassed proxychains for Go binary in favor of ALL_PROXY natively: {}", cmd));
        }
    }

    // ── 5. Execute ─────────────────────────────────────────────────────
    let mut result = executor::run_command_with_env(&final_cmd, timeout_secs, &env_vars)?;

    // ── 6. Sanitize output ─────────────────────────────────────────────
    if config.sanitize_output {
        result.stdout = sanitizer::sanitize(&result.stdout);
        result.stderr = sanitizer::sanitize(&result.stderr);
    }

    // ── 7. Auto-rotate proxy ───────────────────────────────────────────
    proxy_mgr.auto_rotate_if_needed();

    Ok(result)
}

/// Pre-flight check — verifies the anonymity layer is operational.
/// If the kill switch is enabled and the layer is down, bail.
fn preflight_check(config: &Anonymity, proxy_mgr: &ProxyManager) -> Result<()> {
    if config.tor_enabled {
        let tor = TorManager::new(&config.tor_socks_addr);
        if !tor.is_running() {
            bail!(
                "KILL SWITCH: Tor is not running on {}. \
                 Start the Tor service or disable anonymity.",
                config.tor_socks_addr
            );
        }
    } else if config.use_proxychains {
        // If using proxychains with no Tor, check that proxychains4 exists
        if !stealth::proxychains_available() {
            bail!(
                "KILL SWITCH: proxychains4 is not installed. \
                 Install with: sudo apt install proxychains4"
            );
        }
        // Also check that at least one proxy is configured
        if proxy_mgr.is_empty() && !config.tor_enabled {
            bail!(
                "KILL SWITCH: No proxies configured and Tor is disabled. \
                 Add proxies in Settings > Anonymity or enable Tor."
            );
        }
    }

    Ok(())
}

/// Get the operator's current public IP (bypassing proxies).
/// Used for the anonymity dashboard to show real vs masked IP.
pub fn get_real_ip() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .build()?;
    let resp = client.get("https://api.ipify.org").send()?;
    Ok(resp.text()?.trim().to_string())
}

/// Get the current masked IP through the active anonymity layer.
pub fn get_masked_ip(config: &Anonymity) -> Result<String, Box<dyn std::error::Error>> {
    if config.tor_enabled {
        let tor = TorManager::new(&config.tor_socks_addr);
        tor.get_exit_ip()
    } else {
        // Without Tor, the IP depends on proxychains config which we can't
        // easily query from Rust. Return a placeholder.
        Ok("via proxy/proxychains".to_string())
    }
}

/// Checks if a command invocation starts with a known Go binary
/// that requires proxychains to be bypassed.
fn is_static_go_tool(cmd: &str) -> bool {
    let binary = cmd.split_whitespace().next().unwrap_or("");
    let go_tools = [
        "gau", "subfinder", "httpx", "dnsx", "naabu", 
        "katana", "tlsx", "alterx", "amass", "findomain",
        "cdncheck", "cloudlist", "waybackurls", "uncover"
    ];
    go_tools.contains(&binary)
}
