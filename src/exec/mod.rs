//! Serialized execution: validation, spawning, capture, harvest.
//!
//! Tasks run in declared order, each through the single launcher boundary:
//! network-capable commands are wrapped in oniux, local ones run directly.
//! Every task's output lands in its own raw evidence file, and a task that
//! fails or times out still produces evidence for the harvest.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

pub mod launch;
pub mod oniux;

pub use launch::{Boundary, Launch, Launcher};
pub use oniux::{OniuxBackend, OniuxPreflight};

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::sync::Notify;

use crate::domain::command::Command as DomainCommand;
use crate::domain::execution::{ExecutionRecord, TaskStatus};
use crate::domain::ids::TaskId;
use crate::domain::plan::RawArtifact;
use crate::error::{ExecutionErrorKind, Result, Stage, TsecError};

/// Everything the runner needs to know about a task beyond its command.
#[derive(Debug, Clone)]
pub struct TaskSpec {
    pub id: TaskId,
    pub provider: String,
    pub operation: String,
    pub label: String,
    pub timeout: Duration,
    pub artifacts: RawArtifact,
    /// Argument indexes whose values must never reach disk unredacted.
    pub sensitive_args: Vec<usize>,
}

/// The per-task context shared by every step of a single invocation.
struct TaskContext<'a> {
    spec: &'a TaskSpec,
    cmd: &'a DomainCommand,
    phase: &'a str,
    capability: &'a str,
    launched: &'a str,
    boundary: Boundary,
    started: Instant,
}

/// Runtime knobs applied to every task.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Grace period between SIGTERM and SIGKILL for a task.
    pub kill_grace: Duration,
    /// Environment additions for every child.
    pub env: Vec<(String, String)>,
    /// Working directory for children.
    ///
    /// Set to the run's own directory, never left as the operator's. A tool given
    /// a bare output filename writes it wherever it was launched, so this is what
    /// stops a run from writing its results into the repository it was started
    /// from.
    pub cwd: Option<PathBuf>,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            kill_grace: Duration::from_millis(2_000),
            env: Vec::new(),
            cwd: None,
        }
    }
}

/// Cooperative cancellation, shared between the UI and every running task.
#[derive(Debug, Clone)]
pub struct Cancellation {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl Cancellation {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// A finished task: its record plus the command text safe to show an operator.
#[derive(Debug)]
pub struct Completed {
    pub record: ExecutionRecord,
    pub rendered: String,
}

/// Runs tasks according to a schedule the caller controls.
///
/// Cheap to clone: a clone shares the launcher, and therefore the memoized
/// boundary probe, which is what lets several tasks share one preflight.
#[derive(Debug, Clone)]
pub struct Runner {
    launcher: Launcher,
    config: RunnerConfig,
}

impl Runner {
    pub fn new(launcher: Launcher, config: RunnerConfig) -> Self {
        Self { launcher, config }
    }

    /// Run the Oniux preflight once, before any network-capable task.
    pub async fn preflight(&self) -> Result<OniuxPreflight> {
        self.launcher.preflight().await
    }

    /// The launcher, so a caller can inspect the configured boundary.
    pub fn launcher(&self) -> &Launcher {
        &self.launcher
    }

    /// Record for a task a confirmed cancellation stopped before launch.
    ///
    /// The capture files are still created first: a cancelled run leaves the
    /// same two empty evidence files behind as a refused one, so the manifest
    /// never points at an artifact that does not exist.
    pub fn cancelled_before_start(
        &self,
        spec: &TaskSpec,
        cmd: &DomainCommand,
        phase: &str,
        capability: &str,
    ) -> Completed {
        let now = chrono::Utc::now();
        let rendered = cmd.display_redacted(&spec.sensitive_args);
        let _ = open_evidence(&spec.artifacts);
        Completed {
            rendered: rendered.clone(),
            record: ExecutionRecord {
                task_id: spec.id.to_string(),
                phase: phase.to_string(),
                capability: capability.to_string(),
                provider: spec.provider.clone(),
                operation: spec.operation.clone(),
                label: spec.label.clone(),
                command: rendered,
                program: cmd.program().to_string(),
                args: cmd.args_redacted(&spec.sensitive_args),
                network: cmd.network,
                boundary: boundary_of(cmd),
                launched: String::new(),
                uses_shell: cmd.uses_shell,
                started_at: now,
                finished_at: now,
                duration_ms: 0,
                status: TaskStatus::Interrupted,
                exit_code: None,
                stdout_bytes: 0,
                stderr_bytes: 0,
                raw_output: spec.artifacts.primary.clone(),
                stderr_output: Some(spec.artifacts.stderr.clone()),
                harvest_section: None,
                error_code: Some("INTERRUPTED".to_string()),
                error_message: Some("cancelled before launch".to_string()),
            },
        }
    }

    /// Run one task, capturing both streams to its own files.
    ///
    /// Always returns a record: a tool that failed or timed out still produced
    /// evidence, and that evidence belongs in the harvest.
    pub async fn run(
        &self,
        spec: &TaskSpec,
        cmd: &DomainCommand,
        phase: &str,
        capability: &str,
        cancel: &Cancellation,
    ) -> Completed {
        let started = Instant::now();

        // Evidence is opened first: whatever happens next, this task leaves two
        // capture files behind, so a refused task is still inspectable.
        let (stdout, stderr) = match open_evidence(&spec.artifacts) {
            Ok(handles) => handles,
            Err(e) => {
                return self.aborted(
                    &TaskContext {
                        spec,
                        cmd,
                        phase,
                        capability,
                        launched: "",
                        boundary: boundary_of(cmd),
                        started,
                    },
                    e,
                )
            }
        };

        // A network-capable command must be behind a *proven* boundary. The
        // probe is memoized on the launcher, so concurrent tasks still pay for
        // exactly one.
        if cmd.is_network() {
            if let Err(e) = self.launcher.ensure_preflight().await {
                return self.aborted(
                    &TaskContext {
                        spec,
                        cmd,
                        phase,
                        capability,
                        launched: "",
                        boundary: Boundary::Oniux,
                        started,
                    },
                    e,
                );
            }
        }

        // The single routing decision: plan never hands back an unwrapped
        // network argv, and this is the only place that spawns.
        let launch = match self.launcher.plan(cmd) {
            Ok(l) => l,
            Err(e) => {
                return self.aborted(
                    &TaskContext {
                        spec,
                        cmd,
                        phase,
                        capability,
                        launched: "",
                        boundary: boundary_of(cmd),
                        started,
                    },
                    e,
                )
            }
        };

        let rendered = cmd.display_redacted(&spec.sensitive_args);
        let ctx = || TaskContext {
            spec,
            cmd,
            phase,
            capability,
            launched: &launch.launched_display,
            boundary: launch.boundary,
            started,
        };

        // The one and only spawn in the engine. `program` and `args` are the
        // launcher's — for a network task, argv[0] is oniux.
        let mut command = Command::new(&launch.program);
        command
            .args(&launch.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        if let Some(dir) = &self.config.cwd {
            command.current_dir(dir);
        }
        // Point the tool's scratch space at the run's own directory, under a
        // `tmp/` beside the artifacts. Tools that unpack themselves into a
        // temporary directory — the PyInstaller-based ones do, at 99MB each —
        // otherwise leave it in the system temp, where nothing ever sweeps it:
        // 186 of those had accumulated on one host and filled a 7.7GB tmpfs,
        // which is what stopped the work mid-run. Under the run directory they
        // are swept with the run, and the path a tool does keep stays next to
        // its output instead of in a place nobody looks.
        if let Some(dir) = &self.config.cwd {
            let scratch = dir.join("tmp");
            if std::fs::create_dir_all(&scratch).is_ok() {
                command.env("TMPDIR", &scratch);
            }
        }
        for (k, v) in self.config.env.iter().chain(cmd.env_pairs()) {
            command.env(k, v);
        }
        // Own process group, so signalling the group reaches grandchildren.
        // SAFETY: setpgid is async-signal-safe and this closure allocates
        // nothing; it only reports a raw errno on failure.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                // A failure to spawn the oniux binary itself is a boundary
                // failure, not a tool failure, and must be labelled as such.
                let err = if launch.boundary == Boundary::Oniux {
                    TsecError::new(
                        Stage::Execute,
                        ExecutionErrorKind::OniuxUnavailable {
                            tool: cmd.program().to_string(),
                            reason: e.to_string(),
                        },
                    )
                    .with_hint(
                        "the oniux boundary could not be started; network tasks are never \
                         run directly on the host network",
                    )
                } else {
                    TsecError::new(
                        Stage::Execute,
                        ExecutionErrorKind::Spawn {
                            tool: cmd.program().to_string(),
                            reason: e.to_string(),
                        },
                    )
                };
                return self.aborted(&ctx(), err);
            }
        };

        let outcome = self.supervise(child, spec.timeout, cancel).await;

        // What the tool said on the way out, before the status is reduced to a
        // number. Most tools explain themselves here — an unrecognised flag, a
        // missing template, a refused connection — and that line is the only
        // thing that says which of those it was. `exited with status 2` cannot.
        let said = stderr_tail(&spec.artifacts.stderr);

        let (status, exit_code, error_code, error_message) = match outcome {
            Outcome::Exited(0) => (TaskStatus::Complete, Some(0), None, None),
            Outcome::Exited(code) => (
                TaskStatus::Failed,
                Some(code),
                Some("EXIT_STATUS".to_string()),
                Some(match said {
                    Some(line) => format!("exited {code}: {line}"),
                    None => format!("exited with status {code}"),
                }),
            ),
            Outcome::TimedOut => (
                TaskStatus::TimedOut,
                None,
                Some("TIMEOUT".to_string()),
                Some(format!(
                    "exceeded the {}s timeout and was terminated",
                    spec.timeout.as_secs()
                )),
            ),
            Outcome::Cancelled => (
                TaskStatus::Interrupted,
                None,
                Some("INTERRUPTED".to_string()),
                Some("cancelled by the operator".to_string()),
            ),
            Outcome::Signalled(sig) => (
                TaskStatus::Failed,
                None,
                Some("SIGNALLED".to_string()),
                Some(format!("terminated by signal {sig}")),
            ),
        };

        let (out_bytes, err_bytes) = file_sizes(&spec.artifacts);
        Completed {
            rendered: rendered.clone(),
            record: ExecutionRecord {
                task_id: spec.id.to_string(),
                phase: phase.to_string(),
                capability: capability.to_string(),
                provider: spec.provider.clone(),
                operation: spec.operation.clone(),
                label: spec.label.clone(),
                command: rendered,
                program: cmd.program().to_string(),
                args: cmd.args_redacted(&spec.sensitive_args),
                network: cmd.network,
                boundary: launch.boundary,
                launched: launch.launched_display.clone(),
                uses_shell: cmd.uses_shell,
                started_at: chrono::Utc::now(),
                finished_at: chrono::Utc::now(),
                duration_ms: started.elapsed().as_millis(),
                status,
                exit_code,
                stdout_bytes: out_bytes,
                stderr_bytes: err_bytes,
                raw_output: spec.artifacts.primary.clone(),
                stderr_output: Some(spec.artifacts.stderr.clone()),
                harvest_section: None,
                error_code,
                error_message,
            },
        }
    }

    /// Wait for a child, racing its exit against the timeout and cancellation.
    async fn supervise(
        &self,
        mut child: tokio::process::Child,
        timeout: Duration,
        cancel: &Cancellation,
    ) -> Outcome {
        let pid = child.id().map(|p| p as i32);
        let has_timeout = !timeout.is_zero();
        let deadline = Instant::now() + timeout;
        loop {
            // Check cancellation first so a cancel issued before the first poll
            // is never missed.
            if cancel.is_cancelled() {
                self.terminate(child, pid).await;
                return Outcome::Cancelled;
            }
            match tokio::time::timeout(POLL, child.wait()).await {
                Ok(Ok(status)) => {
                    return match status.code() {
                        Some(code) => Outcome::Exited(code),
                        None => Outcome::Signalled(signal_of(&status).unwrap_or(-1)),
                    }
                }
                Ok(Err(_)) => return Outcome::Signalled(-1),
                Err(_) => {
                    if has_timeout && Instant::now() >= deadline {
                        self.terminate(child, pid).await;
                        return Outcome::TimedOut;
                    }
                }
            }
            // Sleep, but wake the moment cancellation is requested.
            let notified = cancel.notify.notified();
            tokio::pin!(notified);
            let _ = tokio::time::timeout(POLL, notified).await;
        }
    }

    /// Stop a child politely, then forcibly, then reap it.
    async fn terminate(&self, mut child: tokio::process::Child, pid: Option<i32>) {
        if let Some(pid) = pid {
            // A negative pid addresses the whole process group, which is how a
            // tool's own children get cleaned up too.
            unsafe {
                libc::kill(-pid, libc::SIGTERM);
            }
        }
        let _ = tokio::time::timeout(self.config.kill_grace, child.wait()).await;
        if let Some(pid) = pid {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let _ = tokio::time::timeout(self.config.kill_grace, child.wait()).await;
    }

    /// A record for a task that never got as far as running.
    fn aborted(&self, ctx: &TaskContext<'_>, err: TsecError) -> Completed {
        let TaskContext {
            spec,
            cmd,
            phase,
            capability,
            launched,
            boundary,
            started,
        } = *ctx;
        let rendered = cmd.display_redacted(&spec.sensitive_args);
        let now = chrono::Utc::now();
        Completed {
            rendered: rendered.clone(),
            record: ExecutionRecord {
                task_id: spec.id.to_string(),
                phase: phase.to_string(),
                capability: capability.to_string(),
                provider: spec.provider.clone(),
                operation: spec.operation.clone(),
                label: spec.label.clone(),
                command: rendered,
                program: cmd.program().to_string(),
                args: cmd.args_redacted(&spec.sensitive_args),
                network: cmd.network,
                boundary,
                launched: launched.to_string(),
                uses_shell: cmd.uses_shell,
                started_at: now,
                finished_at: now,
                duration_ms: started.elapsed().as_millis(),
                status: TaskStatus::Failed,
                exit_code: None,
                stdout_bytes: 0,
                stderr_bytes: 0,
                raw_output: spec.artifacts.primary.clone(),
                stderr_output: Some(spec.artifacts.stderr.clone()),
                harvest_section: None,
                error_code: Some(err.kind.code().to_string()),
                error_message: Some(err.reason()),
            },
        }
    }
}

/// How often a running child is polled for exit, and how long the runner waits
/// to be woken by a cancellation request.
const POLL: Duration = Duration::from_millis(20);

enum Outcome {
    Exited(i32),
    TimedOut,
    Cancelled,
    Signalled(i32),
}

fn prepare_output(artifacts: &RawArtifact) -> Result<()> {
    for p in [&artifacts.primary, &artifacts.stderr] {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Create both capture files up front and hand back the open handles.
///
/// Called before anything that can fail, so a task the boundary refuses to
/// start still leaves two empty files behind and the manifest never points at
/// an artifact that was never created.
fn open_evidence(artifacts: &RawArtifact) -> Result<(File, File)> {
    prepare_output(artifacts)?;
    let stdout =
        File::create(&artifacts.primary).map_err(|e| io_err("opening stdout capture", &e))?;
    let stderr =
        File::create(&artifacts.stderr).map_err(|e| io_err("opening stderr capture", &e))?;
    Ok((stdout, stderr))
}

/// Which boundary a command's evidence should be attributed to.
fn boundary_of(cmd: &DomainCommand) -> Boundary {
    if cmd.is_network() {
        Boundary::Oniux
    } else {
        Boundary::Local
    }
}

fn io_err(context: &str, e: &io::Error) -> TsecError {
    TsecError::new(
        Stage::Capture,
        ExecutionErrorKind::Io {
            context: context.to_string(),
            reason: e.to_string(),
        },
    )
}

/// The most telling line a tool wrote to stderr, if it wrote one.
///
/// Scanned from the end, because the last thing a failing tool says is the one
/// about its failure; the first lines are often its banner. Progress lines are
/// skipped, since "Loaded 42 templates" explains nothing when the run then dies.
fn stderr_tail(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('['))?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let head: String = line.chars().take(200).collect();
    Some(head)
}

fn file_sizes(a: &RawArtifact) -> (usize, usize) {
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len() as usize).unwrap_or(0);
    (size(&a.primary), size(&a.stderr))
}

#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_of(_: &std::process::ExitStatus) -> Option<i32> {
    None
}

#[cfg(test)]
mod cwd_tests {
    use super::*;
    use crate::domain::command::Command;

    /// The guarantee that stops a capability run from writing into the
    /// repository it was started from: whatever a tool writes with a bare
    /// filename lands in the run's directory, because that is the directory the
    /// child is launched in.
    ///
    /// Eleven files of run output were committed once because nothing enforced
    /// this. The catalogue's `{artifacts}` placeholder routes the outputs it
    /// knows about; this covers the ones it does not.
    #[test]
    fn a_child_writes_into_the_run_directory_not_the_caller() {
        let run = std::env::temp_dir().join(format!("tsec-cwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        std::fs::create_dir_all(&run).expect("run dir");

        let spec = TaskSpec {
            id: TaskId(0),
            provider: "sh".into(),
            operation: "probe".into(),
            label: "probe".into(),
            timeout: Duration::from_secs(10),
            artifacts: RawArtifact {
                primary: run.join("probe.out"),
                stderr: run.join("probe.err"),
            },
            sensitive_args: vec![],
        };
        let runner = Runner::new(
            Launcher::new(OniuxBackend::new("/bin/true")),
            RunnerConfig {
                cwd: Some(run.clone()),
                ..RunnerConfig::default()
            },
        );
        // A tool writing a bare relative filename, exactly as most scanners do
        // when the catalogue does not name an output path.
        let cmd = Command::new(
            "/bin/sh",
            vec!["-c".into(), "printf leak > bare_output.txt".into()],
        )
        .network(false);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let done =
            rt.block_on(runner.run(&spec, &cmd, "recon", "recon.probe", &Cancellation::new()));

        assert_eq!(done.record.status, TaskStatus::Complete);
        assert!(
            run.join("bare_output.txt").is_file(),
            "the file must land in the run directory, not the caller"
        );
        let _ = std::fs::remove_dir_all(&run);
    }
}
