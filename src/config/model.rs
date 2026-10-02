//! Configuration model.
//!
//! Paths are discovered rather than hard-coded so the framework works from a
//! clean checkout, a system-wide install, or a user-local install without
//! source changes. Configuration is validated on load and every validation
//! failure produces an actionable message.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ExecutionErrorKind, Result, Stage, TsecError};

/// Environment variable that overrides the framework root directory.
pub const ENV_ROOT: &str = "TSEC_HOME";
/// Environment variable that overrides the configuration file path.
pub const ENV_CONFIG: &str = "TSEC_CONFIG";

/// Root-relative locations, resolved once at startup.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub output_dir: PathBuf,
    pub log_dir: PathBuf,
    pub wordlist_dir: PathBuf,
    pub tool_dir: PathBuf,
    pub script_dir: PathBuf,
}

impl Paths {
    /// Discover the framework root, honouring `TSEC_HOME`, then an existing
    /// `/opt/tsec`, then a per-user data directory.
    pub fn discover() -> Self {
        let root = std::env::var_os(ENV_ROOT)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(default_root);

        let config_file = std::env::var_os(ENV_CONFIG)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| root.join("config").join("config.toml"));

        Self {
            output_dir: root.join("output"),
            log_dir: root.join("logs"),
            wordlist_dir: root.join("wordlists"),
            tool_dir: root.join("tools"),
            script_dir: root.join("scripts"),
            root,
            config_file,
        }
    }
}

fn default_root() -> PathBuf {
    let system = PathBuf::from("/opt/tsec");
    if system.is_dir() {
        return system;
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("tsec");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("tsec");
    }
    system
}

/// Colour behaviour for the terminal interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    /// Detect terminal capability and honour `NO_COLOR`.
    #[default]
    Auto,
    /// Always emit colour, even when piped.
    Always,
    /// Never emit colour.
    Never,
}

impl ColorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ColorMode::Auto => "auto",
            ColorMode::Always => "always",
            ColorMode::Never => "never",
        }
    }
}

impl std::fmt::Display for ColorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ColorMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ColorMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        // The legacy config wrote `color = true`; an operator who upgraded in
        // place should not be met with a decode failure on startup.
        Ok(match toml::Value::deserialize(d)? {
            toml::Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "auto" => ColorMode::Auto,
                "always" => ColorMode::Always,
                "never" => ColorMode::Never,
                other => {
                    return Err(serde::de::Error::custom(format!(
                        "unknown colour mode {other:?}; expected auto, always or never"
                    )))
                }
            },
            toml::Value::Boolean(true) => ColorMode::Always,
            toml::Value::Boolean(false) => ColorMode::Never,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "color must be \"auto\", \"always\" or \"never\", found {other}"
                )))
            }
        })
    }
}

/// General presentation and storage behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    pub output_dir: PathBuf,
    pub log_dir: PathBuf,
    /// Lines of consolidated harvest shown in the terminal by default.
    pub preview_lines: usize,
    pub color: ColorMode,
    /// Keep a copy of every raw stream even when the tool wrote its own file.
    pub keep_raw: bool,
}

impl Default for General {
    fn default() -> Self {
        let paths = Paths::discover();
        Self {
            output_dir: paths.output_dir,
            log_dir: paths.log_dir,
            preview_lines: 500,
            color: ColorMode::Auto,
            keep_raw: true,
        }
    }
}

/// Execution engine behaviour.
///
/// The Oniux boundary is an *execution invariant* of this framework, not a
/// feature: every network-capable command is launched inside a private oniux
/// namespace whose only route is Tor. There is deliberately no switch to
/// disable it and no anonymity mode — the only thing an operator configures is
/// *where* the oniux binary lives. Tor itself is configured and supervised
/// entirely outside the framework; the framework only enforces that network
/// commands go through oniux.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Execution {
    /// Maximum number of tool processes running simultaneously.
    pub max_concurrency: usize,
    /// Default per-task timeout in seconds (0 = disabled / run to completion).
    pub timeout_secs: u64,
    /// Name or path of the oniux binary that provides the network boundary.
    ///
    /// Every network-capable tool is launched as `oniux <tool> <args…>`. Oniux
    /// bootstraps its own embedded Tor client, so no SOCKS endpoint is
    /// configured here — a leftover `tor_socks_proxy` from an older release is
    /// migrated away rather than honoured.
    pub oniux_binary: String,
    /// Grace period given to a child process between SIGTERM and SIGKILL.
    pub kill_grace_ms: u64,
    /// Grace period for the whole process group.
    pub group_kill_grace_ms: u64,
}

impl Default for Execution {
    fn default() -> Self {
        Self {
            max_concurrency: 6,
            timeout_secs: 0,
            oniux_binary: "oniux".to_string(),
            kill_grace_ms: 2_000,
            group_kill_grace_ms: 500,
        }
    }
}

/// Tool discovery behaviour.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Tools {
    /// Extra directories searched for provider executables, in order.
    pub search_paths: Vec<PathBuf>,
    /// Warn when a provider's installed version is older than the minimum
    /// recorded in the dependency manifest.
    pub strict_versions: bool,
}

/// Per-provider settings.
///
/// Intentionally empty. A previous release carried `proxy_overrides`, a
/// per-tool SOCKS map used to aim individual tools at different Tor circuits.
/// Oniux routes every process transparently through its own TUN interface and
/// has no endpoint to override, so the field is gone rather than left behind as
/// a switch that would do nothing. An old config file that still names it keeps
/// loading, because unknown keys are ignored rather than rejected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Providers {}

/// Framework configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: General,
    pub execution: Execution,
    pub tools: Tools,
    pub providers: Providers,
    /// Configuration schema version, for future migrations.
    pub version: u32,
}

impl Config {
    pub const SCHEMA_VERSION: u32 = 3;

    /// Load configuration from the discovered path, creating defaults when
    /// absent. Unknown keys are tolerated but reported, and a config file from
    /// an older schema with a removed section is migrated rather than fatal.
    pub fn load_or_create() -> Result<Self> {
        let paths = Paths::discover();
        let file = paths.config_file.clone();
        let mut cfg = if file.exists() {
            let raw = std::fs::read_to_string(&file).map_err(|e| {
                TsecError::new(
                    Stage::Validate,
                    ExecutionErrorKind::Io {
                        context: format!("reading {}", file.display()),
                        reason: e.to_string(),
                    },
                )
            })?;
            Self::from_toml(&raw)?
        } else {
            let cfg = Self::default();
            cfg.save()?;
            cfg
        };
        cfg.general.output_dir = expand(&cfg.general.output_dir, &paths.root);
        cfg.general.log_dir = expand(&cfg.general.log_dir, &paths.root);
        cfg.ensure_directories()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse TOML, migrating legacy keys that no longer exist.
    pub fn from_toml(raw: &str) -> Result<Self> {
        let mut value: toml::Value = toml::from_str(raw)
            .map_err(|e| TsecError::config(format!("configuration is not valid TOML: {e}")))?;

        // Legacy releases shipped an `[anonymity]` section with a SOCKS address,
        // and an `[execution]` block naming `torsocks` and a `tor_socks_proxy`.
        // All of that described a *proxy endpoint*. Oniux is not a proxy: it
        // builds its own network namespace around each process and runs an
        // embedded Tor client, so there is no endpoint to configure and no
        // anonymity state to store. The keys are therefore dropped rather than
        // translated — carrying a stale SOCKS URL into a config that no longer
        // reads it would be misleading. An old config still loads; it just
        // starts describing the boundary the operator actually has.
        if let Some(root) = value.as_table_mut() {
            root.remove("anonymity");
            root.remove("api_keys");
            if let Some(gen) = root.get_mut("general").and_then(toml::Value::as_table_mut) {
                gen.remove("timeout_secs");
            }
            if let Some(exec) = root
                .get_mut("execution")
                .and_then(toml::Value::as_table_mut)
            {
                exec.remove("torsocks_binary");
                exec.remove("tor_socks_proxy");
            }
        }

        let cfg: Config = value.try_into().map_err(|e: toml::de::Error| {
            TsecError::config(format!("configuration could not be decoded: {e}"))
        })?;
        Ok(cfg)
    }

    /// Create every directory the framework writes to.
    pub fn ensure_directories(&self) -> Result<()> {
        for dir in [&self.general.output_dir, &self.general.log_dir] {
            std::fs::create_dir_all(dir).map_err(|e| {
                TsecError::new(
                    Stage::Validate,
                    ExecutionErrorKind::Io {
                        context: format!("creating {}", dir.display()),
                        reason: e.to_string(),
                    },
                )
                .with_hint("adjust general.output_dir / general.log_dir or fix permissions")
            })?;
        }
        Ok(())
    }

    /// Reject values that would produce a broken run.
    pub fn validate(&self) -> Result<()> {
        if self.general.preview_lines == 0 {
            return Err(TsecError::config(
                "general.preview_lines must be at least 1 (the consolidated harvest is always previewed)",
            ));
        }
        if self.execution.max_concurrency == 0 {
            return Err(TsecError::config(
                "execution.max_concurrency must be at least 1",
            ));
        }
        if self.execution.max_concurrency > 64 {
            return Err(TsecError::config(
                "execution.max_concurrency above 64 will exhaust process and socket limits on most hosts",
            ));
        }
        // timeout_secs == 0 means timeout is disabled (unlimited / run to completion)
        if self.execution.oniux_binary.trim().is_empty() {
            return Err(TsecError::config(
                "execution.oniux_binary must name the oniux binary that provides the network \
                 boundary for network-capable commands",
            ));
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self
            .config_path()
            .and_then(|p| p.parent().map(Path::to_path_buf))
        {
            std::fs::create_dir_all(&parent).map_err(|e| {
                TsecError::new(
                    Stage::Append,
                    ExecutionErrorKind::Io {
                        context: format!("creating {}", parent.display()),
                        reason: e.to_string(),
                    },
                )
            })?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| TsecError::config(format!("serialising configuration: {e}")))?;
        atomic_write(
            self.config_path()
                .as_deref()
                .unwrap_or(Path::new("config.toml")),
            text.as_bytes(),
        )
    }

    /// Location this configuration was loaded from, when known.
    pub fn config_path(&self) -> Option<PathBuf> {
        std::env::var_os(ENV_CONFIG)
            .map(PathBuf::from)
            .or_else(|| Some(Paths::discover().config_file))
    }

    /// Effective timeout for a task, allowing a per-task override.
    pub fn timeout_for(&self, override_secs: Option<u64>) -> u64 {
        override_secs.unwrap_or(self.execution.timeout_secs)
    }
}

fn expand(p: &Path, root: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

/// Write a file atomically: full content to a sibling temp file, then rename.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            TsecError::new(
                Stage::Append,
                ExecutionErrorKind::Io {
                    context: format!("creating {}", parent.display()),
                    reason: e.to_string(),
                },
            )
        })?;
    }
    let tmp = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| format!("{e}."))
            .unwrap_or_default()
    ));
    std::fs::write(&tmp, bytes).map_err(|e| {
        TsecError::new(
            Stage::Append,
            ExecutionErrorKind::Io {
                context: format!("writing {}", tmp.display()),
                reason: e.to_string(),
            },
        )
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        TsecError::new(
            Stage::Append,
            ExecutionErrorKind::Io {
                context: format!("replacing {}", path.display()),
                reason: e.to_string(),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn zero_concurrency_is_rejected_with_actionable_message() {
        let mut c = Config::default();
        c.execution.max_concurrency = 0;
        let e = c.validate().unwrap_err();
        assert!(e.reason().contains("max_concurrency"));
    }

    #[test]
    fn zero_preview_lines_is_rejected() {
        let mut c = Config::default();
        c.general.preview_lines = 0;
        assert!(c.validate().unwrap_err().reason().contains("preview_lines"));
    }

    #[test]
    fn empty_oniux_binary_is_rejected() {
        let mut c = Config::default();
        c.execution.oniux_binary = "  ".into();
        let e = c.validate().unwrap_err().reason();
        assert!(e.contains("oniux_binary"), "{e}");
    }

    #[test]
    fn the_default_boundary_is_oniux() {
        assert_eq!(Config::default().execution.oniux_binary, "oniux");
    }

    #[test]
    fn default_preview_is_five_hundred_lines() {
        assert_eq!(Config::default().general.preview_lines, 500);
    }

    #[test]
    fn a_legacy_config_still_loads_but_carries_no_proxy_state() {
        // A v2 install has an anonymity section, a torsocks binary name and a
        // SOCKS endpoint. None of that describes an oniux boundary, so it is
        // dropped rather than translated; everything else must survive.
        let legacy = r#"
[general]
output_dir = "/tmp/o"
preview_lines = 42

[anonymity]
enabled = true
tor_enabled = true
tor_socks_addr = "127.0.0.1:9150"
kill_switch = true

[execution]
max_concurrency = 3
torsocks_binary = "/usr/bin/torsocks"
tor_socks_proxy = "socks5h://127.0.0.1:9150"
"#;
        let cfg = Config::from_toml(legacy).expect("legacy config parses");
        assert_eq!(cfg.general.preview_lines, 42);
        assert_eq!(cfg.execution.max_concurrency, 3);
        // The boundary falls back to the oniux default.
        assert_eq!(cfg.execution.oniux_binary, "oniux");

        let re = toml::to_string_pretty(&cfg).unwrap();
        for gone in ["anonymity", "kill_switch", "torsocks", "socks"] {
            assert!(
                !re.contains(gone),
                "{gone:?} survived into the rewritten config:\n{re}"
            );
        }
    }

    #[test]
    fn unknown_nested_tables_tolerate_partial_configs() {
        let partial = "[general]\npreview_lines = 10\n";
        let cfg = Config::from_toml(partial).unwrap();
        assert_eq!(cfg.general.preview_lines, 10);
        assert_eq!(
            cfg.execution.max_concurrency,
            Execution::default().max_concurrency
        );
    }

    #[test]
    fn malformed_toml_reports_a_config_error() {
        let e = Config::from_toml("this is not = = toml").unwrap_err();
        assert_eq!(e.kind.code(), "CONFIG_ERROR");
    }

    #[test]
    fn atomic_write_replaces_content_without_leaving_temp_files() {
        let dir = std::env::temp_dir().join(format!("tsec-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("out.txt");
        atomic_write(&f, b"first").unwrap();
        atomic_write(&f, b"second").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "second");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with("tmp"))
            .collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn colour_mode_accepts_the_legacy_boolean_form() {
        // v2 wrote `color = true`; an operator upgrading in place must not be
        // met with a decode failure on the first run of v3.
        for (raw, want) in [
            ("true", ColorMode::Always),
            ("false", ColorMode::Never),
            ("\"auto\"", ColorMode::Auto),
            ("\"always\"", ColorMode::Always),
            ("\"never\"", ColorMode::Never),
            ("\"NEVER\"", ColorMode::Never),
        ] {
            let toml = format!("[general]\ncolor = {raw}\n");
            let cfg = Config::from_toml(&toml).unwrap_or_else(|e| panic!("color = {raw}: {e}"));
            assert_eq!(cfg.general.color, want, "color = {raw}");
        }
    }

    #[test]
    fn a_nonsense_colour_mode_is_reported_not_defaulted() {
        let err = Config::from_toml("[general]\ncolor = \"chartreuse\"\n").unwrap_err();
        assert_eq!(err.kind.code(), "CONFIG_ERROR");
    }

    #[test]
    fn colour_mode_serialises_back_as_a_word() {
        // A bare enum has no table representation, so round-trip through a
        // wrapper — which is how it is actually stored in the config file.
        #[derive(Serialize, Deserialize)]
        struct Wrapper {
            color: ColorMode,
        }
        let w = Wrapper {
            color: ColorMode::Always,
        };
        let text = toml::to_string(&w).unwrap();
        assert_eq!(text.trim(), "color = \"always\"");
        assert_eq!(
            toml::from_str::<Wrapper>(&text).unwrap().color,
            ColorMode::Always
        );
    }
}
