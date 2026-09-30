//! What the operator sees after a capability has run.
//!
//! The harvest is presented as one panel titled `OUTPUTS`. It opens with how the
//! tasks actually ended and, when any of them failed, the error codes they
//! failed with — because a run where every task was refused by the boundary must
//! never read the same as a run that genuinely found nothing. Findings follow in
//! discovery order as `[CATEGORY] value`, and the panel closes with the
//! directory the full evidence was written to.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use crate::domain::execution::{ExecutionRecord, TaskStatus};
use crate::store::HarvestOutcome;
use crate::ui::panel::{self, Geometry, RawMode};
use crate::ui::theme::{Role, Theme};

/// Show the harvest of one capability run, then wait for the operator to close.
pub fn display_harvest(
    theme: &Theme,
    outcome: &HarvestOutcome,
    records: &[ExecutionRecord],
    saved_dir: &Path,
    max_preview: usize,
) -> io::Result<()> {
    let mut head = outcome_rows(outcome);
    head.extend(failure_rows(records));

    let mut tail: Vec<(String, Role)> = Vec::new();
    for note in outcome.notes.iter().take(4) {
        tail.push((note.clone(), Role::Warning));
    }
    tail.push((String::new(), Role::Muted));
    tail.push((saved_dir.display().to_string(), Role::Secondary));

    // Reserve the panel chrome and the rows already spoken for, so a long list
    // of findings scrolls rather than pushing the box off the top of the screen.
    let reserved = 6 + head.len() + tail.len();
    let limit = max_preview.min(Geometry::detect().body_rows(reserved));

    let mut rows = head;
    if outcome.findings.is_empty() {
        rows.push((
            "no findings in the captured output".to_string(),
            Role::Muted,
        ));
    } else {
        for finding in outcome.findings.iter().take(limit) {
            rows.push((
                format!("[{}] {}", finding.category.heading(), finding.value),
                Role::Foreground,
            ));
        }
        if outcome.findings.len() > limit {
            rows.push((
                format!("{} more in harvest.txt", outcome.findings.len() - limit),
                Role::Muted,
            ));
        }
    }
    rows.extend(tail);

    let _raw = RawMode::enter()?;
    let mut out = io::stdout();
    panel::draw(&mut out, theme, "OUTPUTS", &rows, true)?;
    panel::wait_close()
}

/// How the tasks ended, and how much structured output they produced.
fn outcome_rows(outcome: &HarvestOutcome) -> Vec<(String, Role)> {
    vec![(
        format!(
            "{} FINDINGS  {} TASK SECTIONS",
            outcome.findings.len(),
            outcome.sections
        ),
        Role::Muted,
    )]
}

/// The task tally and the error codes behind it.
fn failure_rows(records: &[ExecutionRecord]) -> Vec<(String, Role)> {
    let complete = records.iter().filter(|r| r.status.is_success()).count();
    let failed = records
        .iter()
        .filter(|r| matches!(r.status, TaskStatus::Failed | TaskStatus::TimedOut))
        .count();
    let interrupted = records
        .iter()
        .filter(|r| r.status == TaskStatus::Interrupted)
        .count();

    let role = if failed + interrupted > 0 {
        Role::Warning
    } else {
        Role::Muted
    };
    let mut rows = vec![(
        format!("{complete} COMPLETE  {failed} FAILED  {interrupted} INTERRUPTED"),
        role,
    )];

    let mut codes: BTreeMap<&str, usize> = BTreeMap::new();
    for record in records {
        if let Some(code) = record.error_code.as_deref() {
            *codes.entry(code).or_default() += 1;
        }
    }
    for (code, count) in codes.iter().take(4) {
        rows.push((format!("{code} x{count}"), Role::Error));
    }
    rows
}
