//! Run-level and capability-level reports.
//!
//! A [`CapabilityReport`] is the consolidated, human-readable harvest for one
//! capability execution. It is rendered to disk, shown in the terminal (a
//! bounded preview) and re-readable later without re-running anything.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::execution::ExecutionRecord;
use crate::domain::finding::Finding;
use crate::domain::ids::RunId;

/// Per-task contribution to a capability report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskReport {
    pub record: ExecutionRecord,
    /// Findings harvested from this task, in discovery order.
    pub findings: Vec<Finding>,
    /// Lines of raw output that were consumed.
    pub raw_lines: usize,
    /// True when the tool's structured format was understood.
    pub parsed_structurally: bool,
    /// Why parsing fell back to line mode, when it did.
    pub parse_note: Option<String>,
}

/// Consolidated harvest for one capability run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub run_id: RunId,
    pub phase: String,
    pub capability: String,
    pub capability_id: String,
    /// Operator-supplied target label used in filenames and the report header.
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub tasks: Vec<TaskReport>,
    /// Path of the human-readable consolidated harvest.
    pub harvest_path: PathBuf,
    /// Path of the machine-readable consolidated harvest.
    pub json_path: PathBuf,
    /// Directory holding raw evidence.
    pub raw_dir: PathBuf,
    /// True when the operator interrupted the run.
    pub interrupted: bool,
}

impl CapabilityReport {
    pub fn total_findings(&self) -> usize {
        self.tasks.iter().map(|t| t.findings.len()).sum()
    }

    pub fn succeeded(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.record.status.is_success())
            .count()
    }

    pub fn failed(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| {
                matches!(
                    t.record.status,
                    crate::domain::execution::TaskStatus::Failed
                        | crate::domain::execution::TaskStatus::TimedOut
                )
            })
            .count()
    }

    pub fn skipped(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.record.status == crate::domain::execution::TaskStatus::Skipped)
            .count()
    }

    /// One-line summary suitable for the terminal.
    pub fn summary_line(&self) -> String {
        format!(
            "{} TASK(S): {} COMPLETE, {} FAILED, {} SKIPPED — {} FINDING(S)",
            self.tasks.len(),
            self.succeeded(),
            self.failed(),
            self.skipped(),
            self.total_findings()
        )
    }

    /// Findings grouped by category, ordered for presentation.
    pub fn by_category(&self) -> Vec<(crate::domain::finding::Category, Vec<&Finding>)> {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<(u8, crate::domain::finding::Category), Vec<&Finding>> =
            BTreeMap::new();
        for t in &self.tasks {
            for f in &t.findings {
                map.entry((f.category.order(), f.category))
                    .or_default()
                    .push(f);
            }
        }
        map.into_iter()
            .map(|((_, category), findings)| (category, findings))
            .collect()
    }
}

/// Summary of an entire framework session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: RunId,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub capabilities: Vec<CapabilityReport>,
}

impl RunReport {
    pub fn duration_ms(&self) -> i64 {
        (self.finished_at - self.started_at).num_milliseconds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::execution::TaskStatus;
    use chrono::TimeZone;

    fn record(status: TaskStatus) -> ExecutionRecord {
        let now = Utc.with_ymd_and_hms(2026, 9, 29, 12, 0, 0).unwrap();
        ExecutionRecord {
            task_id: "T01".into(),
            phase: "RECON".into(),
            capability: "SUBDOMAIN DISCOVERY".into(),
            provider: "p".into(),
            operation: "o".into(),
            label: "l".into(),
            command: "p -o x".into(),
            program: "p".into(),
            args: vec![],
            network: false,
            boundary: crate::domain::execution::ExecBoundary::Local,
            launched: "echo smb 10.0.0.5 -u admin -p <redacted>".into(),
            uses_shell: false,
            started_at: now,
            finished_at: now,
            duration_ms: 5,
            status,
            exit_code: Some(0),
            stdout_bytes: 0,
            stderr_bytes: 0,
            raw_output: PathBuf::from("/x"),
            stderr_output: None,
            harvest_section: None,
            error_code: None,
            error_message: None,
        }
    }

    fn report(statuses: Vec<TaskStatus>) -> CapabilityReport {
        let now = Utc.with_ymd_and_hms(2026, 9, 29, 12, 0, 0).unwrap();
        CapabilityReport {
            run_id: RunId::new("20260929_120000_aa"),
            phase: "RECON".into(),
            capability: "SUBDOMAIN DISCOVERY".into(),
            capability_id: "recon.subdomain-discovery".into(),
            target: "example.com".into(),
            started_at: now,
            finished_at: now,
            tasks: statuses
                .into_iter()
                .map(|s| TaskReport {
                    record: record(s),
                    findings: vec![],
                    raw_lines: 0,
                    parsed_structurally: false,
                    parse_note: None,
                })
                .collect(),
            harvest_path: PathBuf::from("/h.txt"),
            json_path: PathBuf::from("/h.json"),
            raw_dir: PathBuf::from("/raw"),
            interrupted: false,
        }
    }

    #[test]
    fn summary_counts_every_outcome() {
        let r = report(vec![
            TaskStatus::Complete,
            TaskStatus::Failed,
            TaskStatus::Skipped,
        ]);
        let s = r.summary_line();
        assert!(s.contains("3 TASK(S)"));
        assert!(s.contains("1 COMPLETE"));
        assert!(s.contains("1 FAILED"));
        assert!(s.contains("1 SKIPPED"));
    }

    #[test]
    fn timed_out_is_counted_as_failed_not_success() {
        let r = report(vec![TaskStatus::TimedOut]);
        assert_eq!(r.failed(), 1);
        assert_eq!(r.succeeded(), 0);
    }
}
