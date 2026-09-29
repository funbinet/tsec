//! The one authoritative execution path.
//!
//! Every command the framework runs — network-capable or not — is turned into
//! a [`Launch`] here, and there is exactly one spawn site in the whole engine
//! (in [`super::Runner::run`]) that consumes it. Centralising the decision is
//! what makes Oniux an architectural invariant rather than something each
//! capability has to remember: there is no code path that can build an argv and
//! hand it to the OS without passing through [`Launcher::plan`], and that
//! function will not produce a network command that is not wrapped.
//!
//! The order is fixed and matches the framework's lifecycle: the tool command is
//! *constructed and validated first* (by the catalog, as an argument vector
//! with no shell), and only then routed. Wrapping never rewrites, reorders or
//! "fixes" the tool's own arguments — oniux receives exactly the argv the
//! catalog produced, with the tool name in front.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::domain::command::Command;
pub use crate::domain::execution::ExecBoundary as Boundary;
use crate::error::Result;
use crate::exec::oniux::{OniuxBackend, OniuxLaunch, OniuxPreflight};

/// A fully-planned, ready-to-spawn invocation.
#[derive(Debug, Clone)]
pub struct Launch {
    /// argv[0]: the oniux binary for a network command, the tool for a local one.
    pub program: PathBuf,
    /// The argv as it will be executed.
    pub args: Vec<String>,
    /// The boundary this invocation runs behind.
    pub boundary: Boundary,
    /// The underlying *tool* command as displayed to the operator (redacted) —
    /// the thing the catalog actually asked for, before any wrapping.
    pub tool_display: String,
    /// The exact wrapped command that was executed (redacted), for the log.
    pub launched_display: String,
}

/// Builds [`Launch`]es and owns the single Oniux backend.
#[derive(Debug, Clone)]
pub struct Launcher {
    backend: OniuxBackend,
    /// Resolved oniux binary, cached after the first network command so
    /// concurrent tasks do not each re-stat PATH.
    resolved: Arc<OnceLock<PathBuf>>,
    /// Memoized preflight outcome, shared by every clone of this launcher.
    preflight: Arc<tokio::sync::OnceCell<std::result::Result<OniuxPreflight, String>>>,
}

use std::sync::Arc;

impl Launcher {
    pub fn new(backend: OniuxBackend) -> Self {
        Self {
            backend,
            resolved: Arc::new(OnceLock::new()),
            preflight: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    pub fn backend(&self) -> &OniuxBackend {
        &self.backend
    }

    /// Run the Oniux preflight and cache the resolved binary.
    ///
    /// Idempotent: the first call probes, later calls return the memoized
    /// result. [`ensure_preflight`](Self::ensure_preflight) is what the runner
    /// uses; this is the form an orchestrator calls to *report* the boundary up
    /// front rather than as a side effect of the first task.
    pub async fn preflight(&self) -> Result<OniuxPreflight> {
        self.ensure_preflight().await
    }

    /// Whether a preflight has already succeeded.
    pub fn is_preflighted(&self) -> bool {
        self.preflight.get().is_some_and(|outcome| outcome.is_ok())
    }

    /// Guarantee the boundary has been proven usable, running the preflight at
    /// most once per [`Launcher`].
    ///
    /// The engine calls this before *every* network-capable task, so the
    /// "preflight before the first network task" promise is enforced by the one
    /// code path that can spawn, not left to each caller to remember. Concurrent
    /// tasks arriving before the first probe finishes all wait on the same cell,
    /// so a capability of twenty tools still pays for exactly one probe.
    ///
    /// A failure is memoized too. Within one run the boundary is either usable or
    /// it is not, and reporting the same clear failure to every task is more
    /// useful than letting some tasks fail for a different, vaguer reason. A run
    /// that starts after the operator fixes their environment gets a fresh cell.
    pub async fn ensure_preflight(&self) -> Result<OniuxPreflight> {
        let cell = Arc::clone(&self.preflight);
        let backend = self.backend.clone();
        let outcome = cell
            .get_or_init(|| async move { backend.preflight().await.map_err(|e| e.reason()) })
            .await;
        match outcome {
            Ok(report) => {
                let _ = self.resolved.set(report.binary.clone());
                Ok(report.clone())
            }
            // Rebuilded rather than stored: the reason travels, not the error
            // object, so the cell stays `Clone`-able across concurrent waiters.
            Err(reason) => Err(self.backend.unavailable(reason)),
        }
    }

    /// Turn a validated command into a runnable launch.
    ///
    /// * A **network** command is wrapped in oniux. If the boundary cannot be
    ///   resolved the call fails with [`OniuxUnavailable`](crate::error::ExecutionErrorKind::OniuxUnavailable)
    ///   — there is no branch here that returns the unwrapped command.
    /// * A **local** command is returned as-is.
    pub fn plan(&self, cmd: &Command) -> Result<Launch> {
        let tool_display = cmd.display_redacted(cmd.sensitive_args());

        if !cmd.is_network() {
            return Ok(Launch {
                program: PathBuf::from(cmd.program()),
                args: cmd.args().to_vec(),
                boundary: Boundary::Local,
                tool_display: tool_display.clone(),
                launched_display: tool_display,
            });
        }

        // Network path: resolve oniux (cached), then wrap. A resolution failure
        // aborts here; the tool is never spawned directly.
        let binary = match self.resolved.get() {
            Some(p) => p.clone(),
            None => {
                let p = self.backend.resolve()?;
                let _ = self.resolved.set(p.clone());
                p
            }
        };
        let oniux: OniuxLaunch = self.backend.wrap(&binary, cmd.program(), cmd.args());
        let launched_display = render_launch(&oniux.program, &oniux.args, cmd);
        Ok(Launch {
            program: oniux.program,
            args: oniux.args,
            boundary: Boundary::Oniux,
            tool_display,
            launched_display,
        })
    }
}

/// Render the executed argv for the log, masking the tool's secret arguments.
///
/// `oniux_args[0]` is the tool and `oniux_args[1..]` are its arguments, so the
/// tool's own sensitive indexes line up one-for-one with the tail we redact.
fn render_launch(oniux: &Path, oniux_args: &[String], cmd: &Command) -> String {
    let mut out = crate::domain::command::quote_for_log(&oniux.to_string_lossy());
    let mask: Vec<usize> = cmd.sensitive_args().to_vec();
    for (j, a) in oniux_args.iter().enumerate() {
        out.push(' ');
        if j == 0 {
            // argv[0] of the wrapped command is the tool name itself.
            out.push_str(&crate::domain::command::quote_for_log(a));
        } else {
            let idx = j - 1;
            if mask.contains(&idx) {
                out.push_str(crate::domain::command::REDACTED);
            } else {
                out.push_str(&crate::domain::command::quote_for_log(a));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::command::Command;

    fn backend() -> OniuxBackend {
        OniuxBackend::new("/usr/bin/oniux")
    }

    #[test]
    fn a_network_command_is_planned_behind_the_oniux_boundary() {
        // Pretend oniux is at a known path so resolve() succeeds without the
        // binary being installed: point the backend at /bin/true, which *is*
        // executable, purely so the planner reaches the wrap step.
        let b = OniuxBackend::new("/bin/true");
        let l = Launcher::new(b);
        let cmd = Command::new("httpx", vec!["-u".into(), "http://x".into()]).network(true);
        let launch = l.plan(&cmd).expect("network plan");
        assert_eq!(launch.boundary, Boundary::Oniux);
        assert_eq!(launch.program, PathBuf::from("/bin/true"));
        // The wrapped argv is the oniux binary receiving the tool's own argv.
        assert_eq!(launch.args, vec!["httpx", "-u", "http://x"]);
        // The tool display is preserved verbatim for the record.
        assert_eq!(launch.tool_display, "httpx -u http://x");
    }

    #[test]
    fn a_local_command_is_planned_directly() {
        let l = Launcher::new(backend());
        let cmd = Command::new("/bin/cat", vec!["/etc/hosts".into()]).network(false);
        let launch = l.plan(&cmd).expect("local plan");
        assert_eq!(launch.boundary, Boundary::Local);
        assert_eq!(launch.program, PathBuf::from("/bin/cat"));
        assert_eq!(launch.args, vec!["/etc/hosts"]);
    }

    #[test]
    fn a_network_command_fails_rather_than_running_directly_when_oniux_is_missing() {
        let l = Launcher::new(OniuxBackend::new("tsec-not-oniux"));
        let cmd = Command::new("httpx", vec![]).network(true);
        let e = l.plan(&cmd).expect_err("must not fall back");
        assert_eq!(e.kind.code(), "ONIUX_UNAVAILABLE");
    }

    #[test]
    fn a_local_command_still_works_when_oniux_is_missing() {
        // A genuinely local tool must not be blocked by the network boundary.
        let l = Launcher::new(OniuxBackend::new("tsec-not-oniux"));
        let cmd = Command::new("/bin/true", vec![]).network(false);
        assert_eq!(l.plan(&cmd).expect("local plan").boundary, Boundary::Local);
    }

    #[test]
    fn the_executed_rendering_masks_the_tool_secrets() {
        let l = Launcher::new(OniuxBackend::new("/bin/true"));
        let cmd = Command::new(
            "nxc",
            vec!["-u".into(), "admin".into(), "-p".into(), "hunter2".into()],
        )
        .network(true)
        .mark_sensitive(3);
        let launch = l.plan(&cmd).expect("plan");
        assert!(
            !launch.launched_display.contains("hunter2"),
            "{}",
            launch.launched_display
        );
        assert!(
            launch.launched_display.contains("<redacted>"),
            "{}",
            launch.launched_display
        );
        // And the tool display hides it too.
        assert!(!launch.tool_display.contains("hunter2"));
    }

    #[test]
    fn boundary_renders_uppercase_for_reports() {
        assert_eq!(Boundary::Oniux.as_str(), "ONIUX");
        assert_eq!(Boundary::Local.as_str(), "LOCAL");
    }
}
