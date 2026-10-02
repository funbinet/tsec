//! Structured error taxonomy for the framework.
//!
//! Every failure mode an operator can encounter is modelled explicitly so the
//! terminal, the log and the persisted execution record can all report the
//! same, diagnosable, fact. Nothing is collapsed into a generic string.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::fmt;
use std::path::PathBuf;

/// Which stage of a capability lifecycle produced the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Input,
    Validate,
    Plan,
    ResolveTools,
    ValidateCommands,
    Execute,
    Capture,
    Parse,
    Normalize,
    Correlate,
    Append,
    Summarize,
    Display,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Input => "INPUT",
            Stage::Validate => "VALIDATE",
            Stage::Plan => "PLAN",
            Stage::ResolveTools => "RESOLVE_TOOLS",
            Stage::ValidateCommands => "VALIDATE_COMMANDS",
            Stage::Execute => "EXECUTE",
            Stage::Capture => "CAPTURE",
            Stage::Parse => "PARSE",
            Stage::Normalize => "NORMALIZE",
            Stage::Correlate => "CORRELATE",
            Stage::Append => "APPEND",
            Stage::Summarize => "SUMMARIZE",
            Stage::Display => "DISPLAY",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a single tool execution failed. Kept fine-grained on purpose: the
/// operator must be able to tell a missing binary from a bad flag from a
/// timeout without reading source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionErrorKind {
    /// The executable is not discoverable on PATH or in the configured toolchain.
    ToolNotInstalled { tool: String },
    /// The tool is present but its version does not support the requested flags.
    ToolVersionIncompatible {
        tool: String,
        found: String,
        need: String,
    },
    /// The generated command was rejected by preflight validation.
    InvalidCommand { tool: String, reason: String },
    /// Operator supplied input that failed validation.
    InvalidInput { field: String, reason: String },
    /// The tool could not be spawned (permissions, bad interpreter, …).
    Spawn { tool: String, reason: String },
    /// The process ran but exited non-zero.
    ExitStatus {
        tool: String,
        code: Option<i32>,
        stderr: String,
    },
    /// The process exceeded its allotted time and was terminated.
    Timeout { tool: String, seconds: u64 },
    /// The operator interrupted the run.
    Interrupted { tool: String },
    /// The Oniux network-execution boundary was missing or could not be
    /// established. Never a reason to fall back to a direct run.
    OniuxUnavailable { tool: String, reason: String },
    /// A network operation failed (DNS, connection refused, TLS, …).
    Network { tool: String, reason: String },
    /// A required input file was absent.
    MissingFile { path: PathBuf },
    /// Raw output could not be parsed into a structured form.
    Parser { tool: String, reason: String },
    /// Filesystem or persistence failure.
    Io { context: String, reason: String },
    /// Configuration was missing or invalid.
    Config { reason: String },
    /// The catalog itself is malformed (developer error, caught by tests).
    Catalog { reason: String },
    /// A framework bug: an invariant was violated.
    Internal { reason: String },
    /// Control-flow signal, not a failure: a nested screen asked to end the
    /// whole session (the session-wide `Esc` contract). Intercepted by the
    /// top-level menu before it can reach the operator.
    FlowExit,
}

impl ExecutionErrorKind {
    /// Stable, machine-readable discriminant persisted in execution records.
    pub fn code(&self) -> &'static str {
        match self {
            ExecutionErrorKind::ToolNotInstalled { .. } => "TOOL_NOT_INSTALLED",
            ExecutionErrorKind::ToolVersionIncompatible { .. } => "TOOL_VERSION_INCOMPATIBLE",
            ExecutionErrorKind::InvalidCommand { .. } => "INVALID_COMMAND",
            ExecutionErrorKind::InvalidInput { .. } => "INVALID_INPUT",
            ExecutionErrorKind::Spawn { .. } => "SPAWN_FAILED",
            ExecutionErrorKind::ExitStatus { .. } => "EXIT_STATUS",
            ExecutionErrorKind::Timeout { .. } => "TIMEOUT",
            ExecutionErrorKind::Interrupted { .. } => "INTERRUPTED",
            ExecutionErrorKind::OniuxUnavailable { .. } => "ONIUX_UNAVAILABLE",
            ExecutionErrorKind::Network { .. } => "NETWORK_FAILURE",
            ExecutionErrorKind::MissingFile { .. } => "MISSING_FILE",
            ExecutionErrorKind::Parser { .. } => "PARSER_FAILURE",
            ExecutionErrorKind::Io { .. } => "IO_FAILURE",
            ExecutionErrorKind::Config { .. } => "CONFIG_ERROR",
            ExecutionErrorKind::Catalog { .. } => "CATALOG_ERROR",
            ExecutionErrorKind::Internal { .. } => "INTERNAL_ERROR",
            ExecutionErrorKind::FlowExit => "FLOW_EXIT",
        }
    }
}

/// A framework error carrying the stage, the tool it concerns and a cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsecError {
    pub stage: Stage,
    pub kind: ExecutionErrorKind,
    /// Extra operator-facing remediation guidance.
    pub hint: Option<String>,
}

impl TsecError {
    pub fn new(stage: Stage, kind: ExecutionErrorKind) -> Self {
        Self {
            stage,
            kind,
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn input(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(
            Stage::Input,
            ExecutionErrorKind::InvalidInput {
                field: field.into(),
                reason: reason.into(),
            },
        )
    }

    pub fn config(reason: impl Into<String>) -> Self {
        Self::new(
            Stage::Validate,
            ExecutionErrorKind::Config {
                reason: reason.into(),
            },
        )
    }

    pub fn catalog(reason: impl Into<String>) -> Self {
        Self::new(
            Stage::Plan,
            ExecutionErrorKind::Catalog {
                reason: reason.into(),
            },
        )
    }

    pub fn io(context: impl Into<String>, err: &std::io::Error) -> Self {
        Self::new(
            Stage::Append,
            ExecutionErrorKind::Io {
                context: context.into(),
                reason: err.to_string(),
            },
        )
    }

    /// The session-wide-exit control signal (see [`ExecutionErrorKind::FlowExit`]).
    pub fn flow_exit() -> Self {
        Self::new(Stage::Display, ExecutionErrorKind::FlowExit)
    }

    /// True when this error is the session-wide-exit control signal.
    pub fn is_flow_exit(&self) -> bool {
        matches!(self.kind, ExecutionErrorKind::FlowExit)
    }

    pub fn internal(reason: impl Into<String>) -> Self {
        Self::new(
            Stage::Validate,
            ExecutionErrorKind::Internal {
                reason: reason.into(),
            },
        )
    }

    /// The concise human-facing reason, without stage decoration.
    pub fn reason(&self) -> String {
        match &self.kind {
            ExecutionErrorKind::ToolNotInstalled { tool } => {
                format!("`{tool}` is not installed or not discoverable on PATH")
            }
            ExecutionErrorKind::ToolVersionIncompatible { tool, found, need } => {
                format!("`{tool}` version `{found}` does not satisfy `{need}`")
            }
            ExecutionErrorKind::InvalidCommand { tool, reason } => {
                format!("invalid command for `{tool}`: {reason}")
            }
            ExecutionErrorKind::InvalidInput { field, reason } => {
                format!("input `{field}` is invalid: {reason}")
            }
            ExecutionErrorKind::Spawn { tool, reason } => {
                format!("could not start `{tool}`: {reason}")
            }
            ExecutionErrorKind::ExitStatus { tool, code, stderr } => match code {
                Some(c) if !stderr.trim().is_empty() => {
                    format!("`{tool}` exited with status {c}: {}", first_line(stderr))
                }
                Some(c) => format!("`{tool}` exited with status {c}"),
                None => format!("`{tool}` was terminated by a signal"),
            },
            ExecutionErrorKind::Timeout { tool, seconds } => {
                format!("`{tool}` exceeded its {seconds}s timeout and was terminated")
            }
            ExecutionErrorKind::Interrupted { tool } => format!("`{tool}` was interrupted"),
            ExecutionErrorKind::OniuxUnavailable { reason, .. } => {
                format!("Oniux network boundary unavailable: {reason}")
            }
            ExecutionErrorKind::Network { tool, reason } => {
                format!("`{tool}` could not reach the target: {reason}")
            }
            ExecutionErrorKind::MissingFile { path } => {
                format!("required file not found: {}", path.display())
            }
            ExecutionErrorKind::Parser { tool, reason } => {
                format!("could not parse `{tool}` output: {reason}")
            }
            ExecutionErrorKind::Io { context, reason } => format!("{context}: {reason}"),
            ExecutionErrorKind::Config { reason } => reason.clone(),
            ExecutionErrorKind::Catalog { reason } => reason.clone(),
            ExecutionErrorKind::Internal { reason } => reason.clone(),
            ExecutionErrorKind::FlowExit => "session ended".to_string(),
        }
    }
}

impl fmt::Display for TsecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Stage, machine-readable code and reason are all present: the stage
        // says where in the lifecycle it happened, the code says what class of
        // failure it was, and the reason says what to do about it.
        write!(
            f,
            "[{}] {}: {}",
            self.stage.as_str(),
            self.kind.code(),
            self.reason()
        )?;
        if let Some(h) = &self.hint {
            write!(f, " ({h})")?;
        }
        Ok(())
    }
}

impl std::error::Error for TsecError {}

impl From<std::io::Error> for TsecError {
    fn from(e: std::io::Error) -> Self {
        TsecError::io("filesystem error", &e)
    }
}

/// Result type used throughout the framework.
pub type Result<T> = std::result::Result<T, TsecError>;

/// First non-blank line of a stream, used to keep terminal output compact.
fn first_line(s: &str) -> String {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("no stderr")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_distinguishes_missing_binary_from_timeout() {
        let missing = TsecError::new(
            Stage::ResolveTools,
            ExecutionErrorKind::ToolNotInstalled {
                tool: "dnsx".into(),
            },
        );
        let timeout = TsecError::new(
            Stage::Execute,
            ExecutionErrorKind::Timeout {
                tool: "dnsx".into(),
                seconds: 30,
            },
        );
        assert!(missing.reason().contains("not installed"));
        assert!(timeout.reason().contains("timeout"));
        assert_ne!(missing.kind.code(), timeout.kind.code());
    }

    #[test]
    fn exit_status_reports_first_stderr_line() {
        let e = TsecError::new(
            Stage::Execute,
            ExecutionErrorKind::ExitStatus {
                tool: "nmap".into(),
                code: Some(1),
                stderr: "\nfatal: permission denied\nmore".into(),
            },
        );
        assert_eq!(
            e.reason(),
            "`nmap` exited with status 1: fatal: permission denied"
        );
    }

    #[test]
    fn signal_termination_is_not_reported_as_exit_zero() {
        let e = TsecError::new(
            Stage::Execute,
            ExecutionErrorKind::ExitStatus {
                tool: "nc".into(),
                code: None,
                stderr: String::new(),
            },
        );
        assert!(e.reason().contains("terminated by a signal"));
    }

    #[test]
    fn display_includes_stage_and_hint() {
        let e = TsecError::new(
            Stage::Execute,
            ExecutionErrorKind::OniuxUnavailable {
                tool: "httpx".into(),
                reason: "oniux not found".into(),
            },
        )
        .with_hint("install oniux or set execution.oniux_binary");
        let s = e.to_string();
        assert!(s.starts_with("["));
        assert!(s.contains("ONIUX"));
        assert!(s.contains("Oniux network boundary unavailable"));
        assert!(s.contains("install oniux"));
    }
}
