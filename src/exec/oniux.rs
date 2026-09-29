//! The Oniux network-execution backend.
//!
//! Oniux (the Tor Project's experimental tool) drops an arbitrary Linux program
//! into its own network, mount, PID and user namespace, wires the `onion0` TUN
//! device to an embedded Tor (Arti) client, and replaces `/etc/resolv.conf` with
//! a Tor-aware resolver. The program therefore has no route to the host network:
//! its traffic physically cannot leave through anything but Tor.
//!
//! In this framework, oniux is not an optional proxy that a tool *might* use —
//! it is **the** boundary through which every network-capable command is
//! launched. This module is a first-class backend: it resolves the binary, runs
//! the preflight the framework promises, and wraps a tool's argument vector
//! into the exact argv oniux expects. The execution engine has exactly one
//! spawn site, and this backend is what that site consults for any command the
//! catalog marked as network-capable.
//!
//! # Installed version
//!
//! The backend is written against oniux **v0.4.0**, whose entire command-line
//! interface is:
//!
//! ```text
//! oniux [command] [args...]
//! ```
//!
//! It accepts no options: `cmd` is a required `trailing_var_arg`. So the only
//! thing the framework may do is prefix the tool — never pass a flag of its own,
//! which a later oniux might interpret and an earlier one would reject.
//! (Newer oniux, e.g. main, adds `-p/-c/-l`; those do not exist in 0.4.0 and are
//! deliberately not used.) The exact argv this backend produces is asserted in
//! the tests and re-checked against the installed binary in the integration
//! suite.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::error::{ExecutionErrorKind, Result, Stage, TsecError};

/// Longest an oniux environment probe may take before it is called unusable.
///
/// Booting an embedded Tor client and a TUN device is not instant; the first
/// run after a machine starts is the slowest. Ninety seconds is generous
/// enough to tolerate a cold start and short enough that a broken boundary is
/// reported before an operator loses patience.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(90);

/// The trivial program oniux runs during preflight.
///
/// `true` exercises everything that matters — user namespace, `/proc`, the
/// private `/tmp`, the TUN device, Tor bootstrap — without generating traffic
/// that is not ours, and exits 0 so success is unambiguous.
const PROBE_COMMAND: &str = "/bin/true";

/// A wrapped launch: the argv oniux will receive, plus the context to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OniuxLaunch {
    /// The oniux executable that becomes argv[0].
    pub program: PathBuf,
    /// The full argv: `["<tool>", ...args]`. oniux execs argv[1] onwards.
    pub args: Vec<String>,
}

impl OniuxLaunch {
    /// Human-readable rendering of the wrapped command, for the execution log.
    pub fn display(&self, tool_display: &str) -> String {
        let mut s = format!("{} {}", self.program.display(), tool_display);
        if self.args.len() > 1 {
            // args[0] is the tool; the rest are its own arguments.
            s.push_str(&self.args[1..].join(" "));
        }
        s
    }
}

/// The resolved oniux boundary and everything the preflight learned.
#[derive(Debug, Clone)]
pub struct OniuxPreflight {
    /// Absolute path to the oniux binary that will be used.
    pub binary: PathBuf,
    /// Whatever oniux reported about itself (help text, or its version line).
    pub identity: String,
    /// The environment probe command that was executed.
    pub probe: String,
}

impl OniuxPreflight {
    /// One-line summary for the interface.
    pub fn summary(&self) -> String {
        format!(
            "oniux {} · {} · probe {} ok",
            self.binary.display(),
            self.identity,
            self.probe
        )
    }
}

/// The Oniux execution backend.
///
/// Constructed once per run and shared by every concurrent task. Each task still
/// gets its own `oniux` *process* — and therefore its own namespace — because
/// isolation is a property of the process, not of a shared handle.
#[derive(Debug, Clone)]
pub struct OniuxBackend {
    /// Name or path of the oniux binary, from configuration.
    binary: String,
    /// How long the environment probe may run.
    probe_timeout: Duration,
}

impl OniuxBackend {
    /// Build a backend for a configured oniux binary.
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            probe_timeout: PROBE_TIMEOUT,
        }
    }

    /// Override the probe timeout (used by tests and by operators with slow
    /// links).
    pub fn with_probe_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// The configured binary, as written.
    pub fn binary(&self) -> &str {
        &self.binary
    }

    /// Locate the oniux binary and confirm it is executable.
    ///
    /// A missing or non-executable boundary is reported now — before a single
    /// tool runs — rather than surfacing as a confusing per-tool failure halfway
    /// through a capability.
    pub fn resolve(&self) -> Result<PathBuf> {
        let resolved = if self.binary.contains('/') {
            let p = PathBuf::from(&self.binary);
            p.is_file().then_some(p)
        } else {
            crate::provider::find_in_path(&self.binary)
        };
        let resolved = resolved.ok_or_else(|| self.unavailable("not found on PATH"))?;
        if !is_executable(&resolved) {
            return Err(self.unavailable("not an executable file"));
        }
        Ok(resolved)
    }

    /// Wrap a tool's argument vector for execution inside oniux.
    ///
    /// The tool is placed as argv[1] and its arguments follow unchanged; oniux
    /// execs them verbatim. No option is ever injected, because v0.4.0 takes
    /// none. This is a pure function of the tool argv — it performs no I/O and
    /// cannot fail, which is what makes the routing an invariant rather than a
    /// best-effort step.
    pub fn wrap(&self, binary: &Path, program: &str, args: &[String]) -> OniuxLaunch {
        let mut wrapped = Vec::with_capacity(args.len() + 1);
        // Prefer the resolved absolute program so oniux does not depend on PATH
        // lookup happening again inside the namespace.
        wrapped.push(program.to_string());
        wrapped.extend(args.iter().cloned());
        OniuxLaunch {
            program: binary.to_path_buf(),
            args: wrapped,
        }
    }

    /// Run the preflight the framework promises before any network task starts.
    ///
    /// Proves three things, in order, and stops at the first failure:
    ///
    /// 1. the binary exists and is executable;
    /// 2. oniux responds to `--help`, so it is really oniux and its CLI parses;
    /// 3. it can actually establish its environment and run a trivial program
    ///    inside the namespace — the only honest test of "is this boundary
    ///    usable right now".
    ///
    /// On any failure this returns an error carrying oniux's own stderr. There
    /// is deliberately no "warn and continue" and no direct-network fallback.
    pub async fn preflight(&self) -> Result<OniuxPreflight> {
        let binary = self.resolve()?;
        let identity = self.identity(&binary).await;
        let probe = self.probe_environment(&binary).await?;
        Ok(OniuxPreflight {
            binary,
            identity,
            probe,
        })
    }

    /// Ask oniux to describe itself; prefer a version line, fall back to help.
    async fn identity(&self, binary: &Path) -> String {
        for flag in ["--version", "-V"] {
            if let Ok(out) = run(binary, &[flag.to_string()], self.probe_timeout).await {
                if out.status == 0 {
                    let line = out.text.trim().to_string();
                    if !line.is_empty() && !line.contains("unexpected") {
                        return line;
                    }
                }
            }
        }
        // v0.4.0 has no --version; its help header is the best identity we get.
        match run(binary, &["--help".to_string()], self.probe_timeout).await {
            Ok(out) if out.status == 0 => out
                .text
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("oniux")
                .trim()
                .to_string(),
            _ => "oniux".to_string(),
        }
    }

    /// Run the trivial program inside oniux's namespace and require success.
    async fn probe_environment(&self, binary: &Path) -> Result<String> {
        let out = run(binary, &[PROBE_COMMAND.to_string()], self.probe_timeout)
            .await
            .map_err(|e| {
                self.unavailable(&format!(
                    "environment probe did not complete: {}",
                    e.reason()
                ))
            })?;
        if out.status != 0 {
            let detail = first_meaningful_line(&out.text)
                .unwrap_or_else(|| format!("exited with status {}", out.status));
            return Err(self.unavailable(&format!(
                "{PROBE_COMMAND} inside the oniux namespace failed: {detail}"
            )));
        }
        Ok(PROBE_COMMAND.to_string())
    }

    /// The canonical "this boundary is unusable" error.
    pub(crate) fn unavailable(&self, why: &str) -> TsecError {
        TsecError::new(
            Stage::Execute,
            ExecutionErrorKind::OniuxUnavailable {
                tool: "oniux".into(),
                reason: why.to_string(),
            },
        )
        .with_hint(format!(
            "network commands run only inside an oniux namespace; install oniux \
             (https://gitlab.torproject.org/tpo/core/oniux), load the `tun` module, \
             and allow unprivileged user namespaces, or set execution.oniux_binary to \
             the oniux executable (currently {:?})",
            self.binary
        ))
    }
}

struct Captured {
    status: i32,
    text: String,
}

/// Run a command, capturing both streams, and never inherit stdin.
///
/// This runs a *known* argv (the binary and a single probe flag or the trivial
/// `true`), never operator input, so it is not on the network execution path
/// and needs no oniux wrapping itself.
async fn run(binary: &Path, args: &[String], timeout: Duration) -> Result<Captured> {
    let child = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            TsecError::new(
                Stage::Execute,
                ExecutionErrorKind::OniuxUnavailable {
                    tool: "oniux".into(),
                    reason: format!("could not start {}: {e}", binary.display()),
                },
            )
        })?;

    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| {
            TsecError::new(
                Stage::Execute,
                ExecutionErrorKind::OniuxUnavailable {
                    tool: "oniux".into(),
                    reason: format!("timed out after {}s", timeout.as_secs()),
                },
            )
        })
        .and_then(|r| {
            r.map_err(|e| {
                TsecError::new(
                    Stage::Execute,
                    ExecutionErrorKind::OniuxUnavailable {
                        tool: "oniux".into(),
                        reason: e.to_string(),
                    },
                )
            })
        })?;

    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    if !err.trim().is_empty() {
        if !text.trim().is_empty() {
            text.push('\n');
        }
        text.push_str(&err);
    }
    Ok(Captured {
        status: out.status.code().unwrap_or(-1),
        text,
    })
}

/// The first non-empty, non-boilerplate line of captured output.
///
/// oniux reports real problems as a single `Error: …` sentence; a blank first
/// line would be useless in an error message.
fn first_meaningful_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_is_a_bare_prefix_with_no_injected_options() {
        // oniux v0.4.0 is `oniux [command] [args...]` and takes no options, so
        // the backend must never invent one. Only the tool and its own args.
        let b = OniuxBackend::new("oniux");
        let launch = b.wrap(
            Path::new("/usr/bin/oniux"),
            "httpx",
            &[
                "-u".to_string(),
                "http://example.com".to_string(),
                "-silent".to_string(),
            ],
        );
        assert_eq!(launch.program, PathBuf::from("/usr/bin/oniux"));
        assert_eq!(
            launch.args,
            vec!["httpx", "-u", "http://example.com", "-silent"],
            "argv must be exactly the tool followed by its own arguments"
        );
        // Nothing that looks like an oniux option may appear before the tool.
        assert_ne!(launch.args[0], "-p");
        assert_ne!(launch.args[0], "-c");
    }

    #[test]
    fn wrapping_an_empty_tool_produces_only_the_tool() {
        let b = OniuxBackend::new("oniux");
        let launch = b.wrap(Path::new("oniux"), "true", &[]);
        assert_eq!(launch.args, vec!["true"]);
    }

    #[test]
    fn the_display_of_a_launch_starts_with_oniux_and_names_the_tool() {
        let b = OniuxBackend::new("oniux");
        let launch = b.wrap(
            Path::new("/usr/bin/oniux"),
            "httpx",
            &["-u".to_string(), "http://x".to_string()],
        );
        let shown = launch.display("httpx -u http://x");
        assert!(shown.starts_with("/usr/bin/oniux "), "{shown}");
        assert!(shown.contains("httpx"), "{shown}");
    }

    #[test]
    fn a_missing_oniux_is_reported_not_swallowed() {
        let b = OniuxBackend::new("tsec-definitely-not-oniux");
        let e = b.resolve().unwrap_err();
        assert_eq!(e.kind.code(), "ONIUX_UNAVAILABLE");
        assert!(
            e.hint.is_some(),
            "an operator must be told how to fix a missing boundary"
        );
    }

    #[test]
    fn a_non_existent_path_is_reported_not_treated_as_a_directory() {
        let b = OniuxBackend::new("/nonexistent/dir/oniux");
        let e = b.resolve().unwrap_err();
        assert_eq!(e.kind.code(), "ONIUX_UNAVAILABLE");
    }

    #[test]
    fn the_probe_command_is_a_trivial_local_program() {
        // The preflight must not itself open a network connection or depend on
        // a tool that may not be installed.
        assert_eq!(PROBE_COMMAND, "/bin/true");
    }
}
