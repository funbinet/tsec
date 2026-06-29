//! Configuration: load/save /opt/tsec/config/config.toml.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const CONFIG_PATH: &str = "/opt/tsec/config/config.toml";
pub const DEFAULT_OUTPUT_DIR: &str = "/opt/tsec/output";
pub const DEFAULT_LOG_DIR: &str = "/opt/tsec/logs";

/// Top-level config — serialised as TOML with [general], [api_keys], and [anonymity] sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: General,
    pub api_keys: ApiKeys,
    #[serde(default)]
    pub anonymity: Anonymity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct General {
    /// Directory where all output files are saved.
    pub output_dir: String,
    /// Directory where the log file lives.
    pub log_dir: String,
    /// Per-command timeout in seconds (default: 300).
    pub timeout_secs: u64,
    /// Number of lines shown in the output preview box.
    pub preview_lines: usize,
    /// Enable ANSI colour output.
    pub color: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeys {
    /// Shodan CLI API key.
    pub shodan: String,
    /// GitHub personal access token (for github-subdomains).
    pub github: String,
    /// Censys API ID.
    pub censys_id: String,
    /// Censys API secret.
    pub censys_secret: String,
}

/// Anonymity subsystem configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anonymity {
    /// Master toggle — when false, all anonymity features are bypassed.
    pub enabled: bool,
    /// Use Tor SOCKS5 proxy (requires `tor` service running).
    pub tor_enabled: bool,
    /// Tor SOCKS5 address (default: 127.0.0.1:9050).
    pub tor_socks_addr: String,
    /// List of proxy URLs for chaining/rotation (socks5://, http://).
    pub proxy_pool: Vec<String>,
    /// Seconds between automatic proxy rotation (0 = no rotation).
    pub proxy_rotation_secs: u64,
    /// Use proxychains-ng wrapper for transparent proxying.
    pub use_proxychains: bool,
    /// Random delay range minimum (ms) injected before each command.
    pub delay_min_ms: u64,
    /// Random delay range maximum (ms) injected before each command.
    pub delay_max_ms: u64,
    /// Rotate User-Agent header for HTTP-based tools.
    pub user_agent_rotation: bool,
    /// Use DNS-over-HTTPS (Cloudflare) instead of system resolver.
    pub dns_over_https: bool,
    /// Sanitize output files — strip private IPs, hostnames, MACs.
    pub sanitize_output: bool,
    /// Spoof MAC address (requires macchanger + root).
    pub mac_spoofing: bool,
    /// Spoof hostname for the session.
    pub hostname_spoofing: bool,
    /// Block execution if anonymity layer is down (kill switch).
    pub kill_switch: bool,
    /// Seconds between forced Tor circuit renewal (0 = let Tor decide automatically)
    #[serde(default = "default_tor_renewal")]
    pub tor_renewal_secs: u64,
}

fn default_tor_renewal() -> u64 { 0 }

impl Default for Anonymity {
    fn default() -> Self {
        Self {
            enabled: false,
            tor_enabled: false,
            tor_socks_addr: "127.0.0.1:9050".to_string(),
            proxy_pool: Vec::new(),
            proxy_rotation_secs: 300,
            use_proxychains: true,
            delay_min_ms: 500,
            delay_max_ms: 3000,
            user_agent_rotation: true,
            dns_over_https: true,
            sanitize_output: true,
            mac_spoofing: false,
            hostname_spoofing: false,
            kill_switch: true,
            tor_renewal_secs: 0,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            general: General {
                output_dir: DEFAULT_OUTPUT_DIR.to_string(),
                log_dir: DEFAULT_LOG_DIR.to_string(),
                timeout_secs: 300,
                preview_lines: 10,
                color: true,
            },
            api_keys: ApiKeys {
                shodan: String::new(),
                github: String::new(),
                censys_id: String::new(),
                censys_secret: String::new(),
            },
            anonymity: Anonymity::default(),
        }
    }
}

impl Config {
    /// Load from the default path, creating defaults if the file is absent.
    pub fn load_or_create() -> Result<Self> {
        if Path::new(CONFIG_PATH).exists() {
            let raw = std::fs::read_to_string(CONFIG_PATH)
                .with_context(|| format!("Reading {CONFIG_PATH}"))?;
            toml::from_str(&raw).with_context(|| "Parsing config.toml")
        } else {
            let cfg = Config::default();
            cfg.save()?;
            Ok(cfg)
        }
    }

    /// Persist the current config to disk.
    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(Path::new(CONFIG_PATH).parent().unwrap())?;
        let toml_str = toml::to_string_pretty(self).context("Serialising config")?;
        std::fs::write(CONFIG_PATH, toml_str).with_context(|| format!("Writing {CONFIG_PATH}"))
    }

    // ── Convenience accessors so callers can write config.output_dir ──────

    pub fn output_dir(&self) -> &str { &self.general.output_dir }
    pub fn log_dir(&self)    -> &str { &self.general.log_dir }
    pub fn timeout_secs(&self) -> u64 { self.general.timeout_secs }
    pub fn preview_lines(&self) -> usize { self.general.preview_lines }
}

