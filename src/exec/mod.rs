//! Process execution.
//!
//! Every external tool is spawned as an explicit program/argument vector — never
//! through a default shell — inside its own process group, so a timeout or an
//! interrupt can terminate the whole tool including anything it forked.
//!
//! Each stream is redirected straight into its own file by the child process.
//! That is deliberate: routing output through a pipe would require a reader
//! that can block the child once the pipe buffer fills, and sharing one buffer
//! across tasks would interleave bytes from concurrent tools. The kernel
//! writing to a per-task file has neither problem.
//!
//! # The network boundary
//!
//! There is exactly **one** spawn site in this module: [`Runner::run`]. It
//! never receives a raw argv. It asks the [`Launcher`] to turn the validated
//! tool command into a [`Launch`](launch::Launch), and the launcher refuses to
//! hand back a network-capable command that is not wrapped in
//! [`OniuxBackend`](oniux::OniuxBackend). So a tool cannot reach the network
//! without oniux, and cannot run at all if oniux is missing — not because a
//! capability remembered to route it, but because the only way to spawn
//! anything goes through that check.

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
///
/// These seven values are identical at every point where the runner bails out
/// early, so they travel together rather than being repeated in a long
/// argument list at each of those points.
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
///
/// A notification channel is used rather than polling so an interrupt is acted
/// on immediately instead of at the next poll tick.
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
#[derive(Debug)]
pub struct Runner {
    launcher: Launcher,
    config: RunnerConfig,
}

impl Runner {
    pub fn new(launcher: Launcher, config: RunnerConfig) -> Self {
        Self { launcher, config }
    }

    /// Run the Oniux preflight once, before any network-capable task.
    ///
    /// Proves the boundary exists, is executable and can actually establish its
    /// namespace before the first real tool asks it to. Failure here is fatal
    /// and never degrades to a direct run.
    pub async fn preflight(&self) -> Result<OniuxPreflight> {
        self.launcher.preflight().await
    }

    /// The launcher, so a caller can inspect the configured boundary.
    pub fn launcher(&self) -> &Launcher {
        &self.launcher
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

        // A network-capable command must be behind a *proven* boundary, not just
        // a resolvable one. Resolution only proves a file exists; the preflight
        // proves it can build a namespace and run something. Enforcing it here —
        // in the one function that spawns — is what makes the promise structural:
        // there is no caller who can forget, and no configuration that can turn
        // the check off. The probe is memoized on the launcher, so twenty
        // concurrent tasks still pay for exactly one.
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

        // The single routing decision. A network-capable command cannot reach
        // the OS without oniux, because this is the only spawn site and
        // `plan` never hands back an unwrapped network argv. A planning failure
        // is recorded and returned — never retried directly.
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
                        boundary: if cmd.is_network() {
                            Boundary::Oniux
                        } else {
                            Boundary::Local
                        },
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

        if let Err(e) = prepare_output(&spec.artifacts) {
            return self.aborted(&ctx(), e);
        }

        let stdout = match File::create(&spec.artifacts.primary) {
            Ok(f) => f,
            Err(e) => return self.aborted(&ctx(), io_err("opening stdout capture", &e)),
        };
        let stderr = match File::create(&spec.artifacts.stderr) {
            Ok(f) => f,
            Err(e) => return self.aborted(&ctx(), io_err("opening stderr capture", &e)),
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
                // A failure to spawn the *oniux binary itself* is a boundary
                // failure, not a tool failure, and must be labelled as such so
                // the operator does not go looking for a broken tool.
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

        // The pid is read here so a supervisor that loses track of the child can
        // still name it in the record, and so an early `None` is visible.
        let pid = child.id().map(|p| p as i32);
        debug_assert!(pid.is_some() || !spec.artifacts.primary.exists());
        let outcome = self.supervise(child, spec.timeout, cancel).await;

        let (status, exit_code, error_code, error_message) = match outcome {
            Outcome::Exited(0) => (TaskStatus::Complete, Some(0), None, None),
            Outcome::Exited(code) => (
                TaskStatus::Failed,
                Some(code),
                Some("EXIT_STATUS".to_string()),
                Some(format!("exited with status {code}")),
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
    ///
    /// Built from `tokio::time::timeout` and `Notify::notified` rather than
    /// `select!`, so the framework builds without the optional `macros` feature.
    async fn supervise(
        &self,
        mut child: tokio::process::Child,
        timeout: Duration,
        cancel: &Cancellation,
    ) -> Outcome {
        let pid = child.id().map(|p| p as i32);
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
                    if Instant::now() >= deadline {
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

fn io_err(context: &str, e: &io::Error) -> TsecError {
    TsecError::new(
        Stage::Capture,
        ExecutionErrorKind::Io {
            context: context.to_string(),
            reason: e.to_string(),
        },
    )
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
mod tests {
    use super::*;

    /// Run an async test body on a fresh runtime.
    ///
    /// The framework builds without Tokio's `macros` feature, so
    /// `#[tokio::test]` is unavailable. This is the same thing spelled out.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fut)
    }

    fn spec(dir: &std::path::Path) -> TaskSpec {
        TaskSpec {
            id: TaskId(0),
            provider: "demo".into(),
            operation: "op".into(),
            label: "demo op".into(),
            timeout: Duration::from_secs(10),
            artifacts: RawArtifact {
                primary: dir.join("out.txt"),
                stderr: dir.join("out.stderr.txt"),
            },
            sensitive_args: vec![],
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tsec-exec-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A runner whose boundary resolves to a real executable, so planning
    /// succeeds without oniux being installed on the test host.
    fn runner() -> Runner {
        Runner::new(
            Launcher::new(OniuxBackend::new("tsec-test-boundary")),
            RunnerConfig::default(),
        )
    }

    /// A local command: no network, so it runs directly and needs no boundary.
    fn local(program: &str, args: Vec<String>) -> DomainCommand {
        DomainCommand::new(program, args).network(false)
    }

    #[test]
    fn a_successful_command_is_recorded_with_its_captured_output() {
        block_on(async {
            let dir = tmp("ok");
            let s = spec(&dir);
            let cmd = local("/bin/echo", vec!["hello".into()]);
            let c = runner()
                .run(&s, &cmd, "RECON", "TEST", &Cancellation::new())
                .await;
            assert_eq!(c.record.status, TaskStatus::Complete);
            assert_eq!(c.record.exit_code, Some(0));
            let body = std::fs::read_to_string(&s.artifacts.primary).unwrap();
            assert_eq!(body.trim(), "hello");
            assert!(c.record.stdout_bytes > 0);
        });
    }

    #[test]
    fn a_failing_command_is_recorded_rather_than_dropped() {
        block_on(async {
            let dir = tmp("fail");
            let s = spec(&dir);
            let cmd = local("/bin/sh", vec!["-c".into(), "exit 3".into()]);
            let c = runner()
                .run(&s, &cmd, "RECON", "TEST", &Cancellation::new())
                .await;
            assert_eq!(c.record.status, TaskStatus::Failed);
            assert_eq!(c.record.exit_code, Some(3));
            assert_eq!(c.record.error_code.as_deref(), Some("EXIT_STATUS"));
        });
    }

    #[test]
    fn stdout_and_stderr_are_captured_to_separate_files() {
        block_on(async {
            let dir = tmp("split");
            let s = spec(&dir);
            let cmd = local(
                "/bin/sh",
                vec!["-c".into(), "echo out; echo err 1>&2".into()],
            );
            runner()
                .run(&s, &cmd, "RECON", "TEST", &Cancellation::new())
                .await;
            assert_eq!(
                std::fs::read_to_string(&s.artifacts.primary)
                    .unwrap()
                    .trim(),
                "out"
            );
            assert_eq!(
                std::fs::read_to_string(&s.artifacts.stderr).unwrap().trim(),
                "err"
            );
        });
    }

    #[test]
    fn a_missing_program_fails_with_a_spawn_error_not_a_panic() {
        block_on(async {
            let dir = tmp("missing");
            let s = spec(&dir);
            let cmd = local("/nonexistent/tsec-tool", vec![]);
            let c = runner()
                .run(&s, &cmd, "RECON", "TEST", &Cancellation::new())
                .await;
            assert_eq!(c.record.status, TaskStatus::Failed);
            assert_eq!(c.record.error_code.as_deref(), Some("SPAWN_FAILED"));
        });
    }

    #[test]
    fn a_hanging_command_is_terminated_at_its_deadline() {
        block_on(async {
            let dir = tmp("timeout");
            let mut s = spec(&dir);
            s.timeout = Duration::from_millis(300);
            let cmd = local("/bin/sleep", vec!["30".into()]);
            let c = runner()
                .run(&s, &cmd, "RECON", "TEST", &Cancellation::new())
                .await;
            assert_eq!(c.record.status, TaskStatus::TimedOut);
            assert_eq!(c.record.error_code.as_deref(), Some("TIMEOUT"));
            assert!(
                c.record.duration_ms < 5_000,
                "termination took {}ms",
                c.record.duration_ms
            );
        });
    }

    #[test]
    fn a_timeout_kills_the_whole_process_group_not_just_the_child() {
        block_on(async {
            let dir = tmp("group");
            let mut s = spec(&dir);
            s.timeout = Duration::from_millis(300);
            // The child spawns a grandchild that would outlive it if only the
            // direct child were signalled.
            let script = "sleep 25 & echo $! > /tmp/tsec-exec-grandchild.pid; wait";
            let cmd = local("/bin/sh", vec!["-c".into(), script.into()]);
            let c = runner()
                .run(&s, &cmd, "RECON", "TEST", &Cancellation::new())
                .await;
            assert_eq!(c.record.status, TaskStatus::TimedOut);

            let pid: i32 = std::fs::read_to_string("/tmp/tsec-exec-grandchild.pid")
                .expect("grandchild pid recorded")
                .trim()
                .parse()
                .unwrap();
            // Allow the signal a moment to land, then confirm it is gone.
            let mut alive = true;
            for _ in 0..50 {
                if unsafe { libc::kill(pid, 0) } != 0 {
                    alive = false;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if alive {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            assert!(!alive, "grandchild {pid} survived the group termination");
        });
    }

    #[test]
    fn cancellation_stops_a_running_task() {
        block_on(async {
            let dir = tmp("cancel");
            let s = spec(&dir);
            let cancel = Cancellation::new();
            let c2 = cancel.clone();
            let handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                c2.cancel();
            });
            let cmd = local("/bin/sleep", vec!["30".into()]);
            let c = runner().run(&s, &cmd, "RECON", "TEST", &cancel).await;
            handle.await.unwrap();
            assert_eq!(c.record.status, TaskStatus::Interrupted);
            assert_eq!(c.record.error_code.as_deref(), Some("INTERRUPTED"));
        });
    }

    #[test]
    fn sensitive_arguments_are_redacted_in_the_recorded_command() {
        block_on(async {
            let dir = tmp("redact");
            let s = spec(&dir);
            let cmd = local("/bin/echo", vec![]).arg("-n").secret("secret-value");
            let c = runner()
                .run(&s, &cmd, "RECON", "TEST", &Cancellation::new())
                .await;
            assert!(
                !c.record.command.contains("secret-value"),
                "{}",
                c.record.command
            );
            assert!(c.record.command.contains("<redacted>"));
        });
    }

    #[test]
    fn a_network_task_without_a_usable_boundary_fails_explicitly() {
        block_on(async {
            let dir = tmp("oniux-missing");
            let s = spec(&dir);
            // The boundary is genuinely absent, so planning must fail.
            let r = Runner::new(
                Launcher::new(OniuxBackend::new("tsec-no-such-oniux")),
                RunnerConfig::default(),
            );
            let cmd = DomainCommand::new("/bin/echo", vec!["hi".into()]).network(true);
            let c = r.run(&s, &cmd, "RECON", "TEST", &Cancellation::new()).await;
            // The tool never ran, and the record says why.
            assert_eq!(c.record.status, TaskStatus::Failed);
            assert_eq!(c.record.error_code.as_deref(), Some("ONIUX_UNAVAILABLE"));
            // The record still declares the task was network-capable, so an
            // operator can see the boundary was what failed.
            assert!(c.record.network);
            assert_eq!(c.record.boundary, Boundary::Oniux);
            assert!(
                !s.artifacts.primary.exists(),
                "a network command must not produce a capture without oniux"
            );
        });
    }

    #[test]
    fn a_missing_oniux_is_reported_before_any_task_runs() {
        block_on(async {
            let b = OniuxBackend::new("tsec-no-such-oniux");
            let e = b.resolve().unwrap_err();
            assert_eq!(e.kind.code(), "ONIUX_UNAVAILABLE");
            assert!(e.hint.is_some());
        });
    }

    #[test]
    fn a_local_task_runs_even_when_the_boundary_is_missing() {
        block_on(async {
            // A genuinely local command has no network capability, so a broken
            // oniux must not block it.
            let dir = tmp("local-no-boundary");
            let s = spec(&dir);
            let r = Runner::new(
                Launcher::new(OniuxBackend::new("tsec-no-such-oniux")),
                RunnerConfig::default(),
            );
            let cmd = local("/bin/echo", vec!["local".into()]);
            let c = r.run(&s, &cmd, "RECON", "TEST", &Cancellation::new()).await;
            assert_eq!(c.record.status, TaskStatus::Complete);
            assert_eq!(c.record.boundary, Boundary::Local);
        });
    }

    #[test]
    fn a_network_task_records_the_wrapped_command_it_actually_ran() {
        block_on(async {
            let dir = tmp("wrapped-record");
            let s = spec(&dir);
            // `/bin/echo` stands in for oniux so the test does not need Tor; the
            // argv is what matters.
            let r = Runner::new(
                Launcher::new(OniuxBackend::new("/bin/echo")),
                RunnerConfig::default(),
            );
            let cmd = DomainCommand::new("/bin/true", vec!["-flag".into()]).network(true);
            let c = r.run(&s, &cmd, "RECON", "TEST", &Cancellation::new()).await;
            assert_eq!(c.record.status, TaskStatus::Complete);
            assert_eq!(c.record.boundary, Boundary::Oniux);
            // The record keeps both the tool command and the wrapped one.
            assert_eq!(c.record.command, "/bin/true -flag");
            assert!(
                c.record.launched.starts_with("/bin/echo /bin/true"),
                "launched was {:?}",
                c.record.launched
            );
        });
    }

    #[test]
    fn the_wrapped_command_never_leaks_a_tool_secret() {
        block_on(async {
            let dir = tmp("wrapped-redact");
            let s = spec(&dir);
            let r = Runner::new(
                Launcher::new(OniuxBackend::new("/bin/echo")),
                RunnerConfig::default(),
            );
            let cmd = DomainCommand::new("/bin/true", vec!["-p".into(), "hunter2".into()])
                .network(true)
                .mark_sensitive(1);
            let c = r.run(&s, &cmd, "RECON", "TEST", &Cancellation::new()).await;
            assert!(
                !c.record.launched.contains("hunter2"),
                "{}",
                c.record.launched
            );
            assert!(c.record.launched.contains("<redacted>"));
        });
    }

    /// A boundary that resolves and is executable but cannot establish itself.
    ///
    /// This is the case worth testing: `resolve` succeeds, so a framework that
    /// only checked for the file would happily run the tool on the host network
    /// and report a generic "exited 1".
    fn broken_boundary(dir: &std::path::Path) -> PathBuf {
        let p = dir.join("fake-oniux-broken");
        std::fs::write(
            &p,
            "#!/bin/sh\necho 'Error: failed to set up TUN device' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn a_network_task_is_refused_when_the_boundary_resolves_but_cannot_bootstrap() {
        block_on(async {
            let dir = tmp("bad-boundary");
            let s = spec(&dir);
            let r = Runner::new(
                Launcher::new(OniuxBackend::new(
                    broken_boundary(&dir).to_string_lossy().into_owned(),
                )),
                RunnerConfig::default(),
            );
            let cmd = DomainCommand::new("/bin/echo", vec!["leaked".into()]).network(true);
            let c = r.run(&s, &cmd, "RECON", "TEST", &Cancellation::new()).await;

            // The failure is attributed to the boundary, not to the tool.
            assert_eq!(c.record.error_code.as_deref(), Some("ONIUX_UNAVAILABLE"));
            assert_eq!(c.record.boundary, Boundary::Oniux);
            assert!(
                c.record.network,
                "the record must still admit it was network work"
            );
            // And the tool did not run: oniux's own error is the only output.
            assert!(
                !s.artifacts.primary.exists(),
                "a tool must never execute on the host network because the boundary failed"
            );
        });
    }

    /// A boundary that records each environment probe it is asked to run.
    ///
    /// The log path is derived from the script's own location, because the
    /// preflight is spawned by the backend rather than by the runner and so does
    /// not inherit the runner's environment.
    fn counting_boundary(dir: &std::path::Path) -> PathBuf {
        let p = dir.join("fake-oniux-counting");
        std::fs::write(
            &p,
            r#"#!/bin/sh
if [ "$1" = /bin/true ]; then
  echo probe >> "$(dirname "$0")/probes.log"
  exit 0
fi
case "$1" in --version|-V|--help) echo "oniux 0.4.0"; exit 0;; esac
exec "$@"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn concurrent_network_tasks_share_one_boundary_probe() {
        block_on(async {
            let dir = tmp("probe-once");
            let log = dir.join("probes.log");
            let _ = std::fs::remove_file(&log);
            let r = std::sync::Arc::new(Runner::new(
                Launcher::new(OniuxBackend::new(
                    counting_boundary(&dir).to_string_lossy().into_owned(),
                )),
                RunnerConfig::default(),
            ));
            let cancel = Cancellation::new();
            let mut handles = Vec::new();
            for i in 0..5 {
                let rr = r.clone();
                let cc = cancel.clone();
                let d = dir.clone();
                handles.push(tokio::spawn(async move {
                    let s = TaskSpec {
                        id: TaskId(i),
                        provider: "demo".into(),
                        operation: "burst".into(),
                        label: "burst".into(),
                        timeout: Duration::from_secs(20),
                        artifacts: RawArtifact {
                            primary: d.join(format!("t{i}.txt")),
                            stderr: d.join(format!("t{i}.stderr.txt")),
                        },
                        sensitive_args: vec![],
                    };
                    let cmd =
                        DomainCommand::new("/bin/echo", vec![format!("task-{i}")]).network(true);
                    rr.run(&s, &cmd, "RECON", "TEST", &cc).await
                }));
            }
            for h in handles {
                let c = h.await.unwrap();
                assert_eq!(
                    c.record.status,
                    TaskStatus::Complete,
                    "{:?}",
                    c.record.error_message
                );
                assert_eq!(c.record.boundary, Boundary::Oniux);
            }
            // Five network tasks, five separate oniux processes, but the
            // expensive namespace probe is paid once.
            let probes = std::fs::read_to_string(&log).unwrap_or_default();
            assert_eq!(
                probes.lines().count(),
                1,
                "the boundary should be probed once, not once per task:\n{probes}"
            );
        });
    }

    #[test]
    fn a_persisted_execution_record_never_contains_a_secret() {
        block_on(async {
            let dir = tmp("record-redaction");
            let s = spec(&dir);
            let r = runner();
            // `nxc -u admin -p <secret> ...` — index 3 is the password.
            let cmd = local(
                "/bin/echo",
                vec![
                    "smb".into(),
                    "10.0.0.5".into(),
                    "-u".into(),
                    "admin".into(),
                    "-p".into(),
                    "hunter2".into(),
                ],
            )
            .mark_sensitive(5);
            let c = r
                .run(&s, &cmd, "LATERAL", "TEST", &Cancellation::new())
                .await;

            let json = serde_json::to_string(&c.record).unwrap();
            assert!(
                !json.contains("hunter2"),
                "secret leaked into the record: {json}"
            );
            assert!(c.record.command.contains("<redacted>"));
            assert!(!c.record.command.contains("hunter2"));
            assert_eq!(c.record.args[5], crate::domain::command::REDACTED);
            assert_eq!(c.record.args[4], "-p");
            // The argument that was not declared secret is still readable, because a
            // redacted record that hides the whole command is not much of a record.
            assert_eq!(c.record.args[3], "admin");
        });
    }

    #[test]
    fn concurrent_tasks_never_interleave_their_output() {
        block_on(async {
            let dir = tmp("concurrent");
            let cancel = Cancellation::new();
            let r = std::sync::Arc::new(runner());
            let mut handles = Vec::new();
            for i in 0..8 {
                let d = dir.clone();
                let rr = r.clone();
                let cc = cancel.clone();
                handles.push(tokio::spawn(async move {
                    let s = TaskSpec {
                        id: TaskId(i),
                        provider: "demo".into(),
                        operation: "burst".into(),
                        label: "burst".into(),
                        timeout: Duration::from_secs(20),
                        artifacts: RawArtifact {
                            primary: d.join(format!("t{i}.txt")),
                            stderr: d.join(format!("t{i}.stderr.txt")),
                        },
                        sensitive_args: vec![],
                    };
                    // 200 lines of this task's own marker, so any cross-task
                    // interleaving would show up as a foreign marker.
                    let cmd = local(
                        "/bin/sh",
                        vec![
                            "-c".into(),
                            format!("for n in $(seq 1 200); do echo T{i}-$n; done"),
                        ],
                    );
                    rr.run(&s, &cmd, "RECON", "TEST", &cc).await
                }));
            }
            for h in handles {
                let c = h.await.unwrap();
                assert_eq!(c.record.status, TaskStatus::Complete);
            }
            for i in 0..8 {
                let body = std::fs::read_to_string(dir.join(format!("t{i}.txt"))).unwrap();
                let lines: Vec<&str> = body.lines().collect();
                assert_eq!(lines.len(), 200, "task {i} lost lines");
                for (n, l) in lines.iter().enumerate() {
                    assert_eq!(
                        *l,
                        format!("T{i}-{}", n + 1),
                        "task {i} line {n} is corrupted"
                    );
                }
            }
        });
    }
}
