//! Structured execution records: the observable truth of what ran.
//!
//! Every task produces exactly one [`ExecutionRecord`]. Records are the unit
//! of persistence, correlation and display — nothing in the framework reports
//! progress or results by printing ad-hoc strings.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::ids::TaskId;

/// Terminal state of a single task execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TaskStatus {
    /// Declared but not yet started.
    Pending,
    /// Spawned, streams being captured.
    Running,
    /// Exited with status 0.
    Complete,
    /// Exited non-zero, was signalled, or could not be spawned.
    Failed,
    /// Exceeded its timeout and was terminated.
    TimedOut,
    /// Excluded from the run during preflight (missing tool, unresolved input).
    Skipped,
    /// Cancelled because the operator interrupted the run.
    Interrupted,
}

impl TaskStatus {
    /// Short marker used by the terminal renderer.
    pub fn marker(self) -> &'static str {
        match self {
            TaskStatus::Pending => "·",
            TaskStatus::Running => "»",
            TaskStatus::Complete => "✓",
            TaskStatus::Failed => "✗",
            TaskStatus::TimedOut => "⏱",
            TaskStatus::Skipped => "—",
            TaskStatus::Interrupted => "⊘",
        }
    }

    /// Capitalised label used in the interface.
    pub fn label(self) -> &'static str {
        match self {
            TaskStatus::Pending => "PENDING",
            TaskStatus::Running => "RUNNING",
            TaskStatus::Complete => "COMPLETE",
            TaskStatus::Failed => "FAILED",
            TaskStatus::TimedOut => "TIMED OUT",
            TaskStatus::Skipped => "SKIPPED",
            TaskStatus::Interrupted => "INTERRUPTED",
        }
    }

    /// Whether the task contributed evidence to the harvest.
    pub fn is_success(self) -> bool {
        matches!(self, TaskStatus::Complete)
    }
}

/// The result of attempting one task.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    /// Stable error code, present for every non-success.
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl Outcome {
    pub fn success(stdout: String, stderr: String, duration: Duration) -> Self {
        Self {
            status: TaskStatus::Complete,
            exit_code: Some(0),
            stdout,
            stderr,
            duration,
            error_code: None,
            error_message: None,
        }
    }

    pub fn failure(
        status: TaskStatus,
        code: Option<i32>,
        stdout: String,
        stderr: String,
        duration: Duration,
        error_code: &str,
        error_message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            exit_code: code,
            stdout,
            stderr,
            duration,
            error_code: Some(error_code.to_string()),
            error_message: Some(error_message.into()),
        }
    }

    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            status: TaskStatus::Skipped,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::ZERO,
            error_code: Some("SKIPPED".to_string()),
            error_message: Some(reason.into()),
        }
    }
}

/// The execution boundary a command was launched behind.
///
/// Recorded so a report can state, per tool, *how* it touched the network.
/// `Oniux` means the process ran inside a private oniux namespace whose only
/// route is Tor. `Local` means the command had no network capability and ran
/// directly. There is no third variant, and no variant that represents a
/// network command run without the boundary — that would be the bug this whole
/// design exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ExecBoundary {
    Oniux,
    Local,
}

impl ExecBoundary {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecBoundary::Oniux => "ONIUX",
            ExecBoundary::Local => "LOCAL",
        }
    }
    /// Whether this invocation opened a network connection.
    pub fn is_network(self) -> bool {
        matches!(self, ExecBoundary::Oniux)
    }
}

/// Everything the framework knows about one tool invocation, persisted verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub task_id: String,
    pub phase: String,
    pub capability: String,
    pub provider: String,
    pub operation: String,
    pub label: String,
    /// Exact command line as displayed to the operator, in original case.
    pub command: String,
    /// Program name only.
    pub program: String,
    /// Explicit argument vector, never a re-parsed string.
    ///
    /// Always redacted: arguments the task or its command declared secret are
    /// stored as `<redacted>`. This record is serialised into reports and
    /// manifests that outlive the run, so it must not be able to carry a
    /// credential.
    pub args: Vec<String>,
    /// Whether the task opened network connections.
    pub network: bool,
    /// The boundary the task was launched behind (`ONIUX` or `LOCAL`).
    pub boundary: ExecBoundary,
    /// The exact argv line that was executed, after Oniux wrapping (redacted).
    ///
    /// `command` above is the *tool* command the catalog asked for. This is what
    /// the OS actually ran, so a report shows both the intent and the enforced
    /// boundary without the operator having to reconstruct one from the other.
    pub launched: String,
    /// Whether execution required a shell.
    pub uses_shell: bool,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub duration_ms: u128,
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    /// Location of the raw evidence file.
    pub raw_output: PathBuf,
    /// Location of the captured stderr file, if it had content.
    pub stderr_output: Option<PathBuf>,
    /// Location of the parsed section inside the consolidated harvest.
    pub harvest_section: Option<PathBuf>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl ExecutionRecord {
    pub fn task(&self) -> TaskId {
        self.task_id
            .strip_prefix('T')
            .and_then(|n| n.parse::<usize>().ok())
            .map(|n| TaskId(n.saturating_sub(1)))
            .unwrap_or(TaskId(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_labels_are_capital_letters() {
        for s in [
            TaskStatus::Pending,
            TaskStatus::Running,
            TaskStatus::Complete,
            TaskStatus::Failed,
            TaskStatus::TimedOut,
            TaskStatus::Skipped,
            TaskStatus::Interrupted,
        ] {
            let l = s.label();
            assert!(
                l.chars().all(|c| !c.is_lowercase()),
                "{l} must be uppercase"
            );
        }
    }

    #[test]
    fn only_complete_counts_as_success() {
        assert!(TaskStatus::Complete.is_success());
        assert!(!TaskStatus::Failed.is_success());
        assert!(!TaskStatus::Skipped.is_success());
        assert!(!TaskStatus::TimedOut.is_success());
    }

    #[test]
    fn record_round_trips_through_json_preserving_command_case() {
        let now = Utc::now();
        let rec = ExecutionRecord {
            task_id: "T01".into(),
            phase: "RECON".into(),
            capability: "SUBDOMAIN DISCOVERY".into(),
            provider: "subfinder".into(),
            operation: "passive".into(),
            label: "Passive enumeration".into(),
            command: "subfinder -d Example.COM -silent -o x.txt".into(),
            program: "subfinder".into(),
            args: vec!["-d".into(), "Example.COM".into()],
            network: true,
            boundary: ExecBoundary::Oniux,
            launched: "oniux subfinder -d Example.COM -silent -o x.txt".into(),
            uses_shell: false,
            started_at: now,
            finished_at: now,
            duration_ms: 1234,
            status: TaskStatus::Complete,
            exit_code: Some(0),
            stdout_bytes: 10,
            stderr_bytes: 0,
            raw_output: PathBuf::from("/x"),
            stderr_output: None,
            harvest_section: None,
            error_code: None,
            error_message: None,
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("Example.COM"));
        let back: ExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.command, rec.command);
        assert_eq!(back.status, TaskStatus::Complete);
        assert_eq!(back.boundary, ExecBoundary::Oniux);
        assert!(back.boundary.is_network());
    }

    #[test]
    fn boundary_serialises_as_a_stable_uppercase_token() {
        assert_eq!(
            serde_json::to_string(&ExecBoundary::Oniux).unwrap(),
            "\"ONIUX\""
        );
        assert_eq!(
            serde_json::to_string(&ExecBoundary::Local).unwrap(),
            "\"LOCAL\""
        );
        assert!(!ExecBoundary::Local.is_network());
    }
}
