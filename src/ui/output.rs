// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::Path;
use crate::parser::MergedFinding;
use crate::store::HarvestOutcome;
use crate::ui::theme::{Role, Theme};

/// Display a preview of harvested findings, summary counts, and the saved artifact path.
pub fn display_harvest(theme: &Theme, outcome: &HarvestOutcome, saved_dir: &Path, max_preview: usize) {
    println!();
    display_preview(theme, &outcome.findings, max_preview);
    display_summary(theme, outcome);
    display_saved(theme, saved_dir);
}

/// Show the first `max` findings in a bordered box.
pub fn display_preview(theme: &Theme, findings: &[MergedFinding], max: usize) {
    let inner_width = 76usize;
    let border = "═".repeat(inner_width);

    println!("{}", theme.paint(Role::Border, &format!("╔{}╗", border)));
    let title = "  Harvest Findings Preview";
    let title_line = format!("║ {:<74} ║", title);
    println!("{}", theme.paint(Role::Border, &title_line));
    println!("{}", theme.paint(Role::Border, &format!("╠{}╣", border)));

    if findings.is_empty() {
        let empty_line = format!("║ {:<74} ║", "  (no findings discovered)");
        println!("{}", theme.paint(Role::Muted, &empty_line));
    } else {
        for (i, f) in findings.iter().take(max).enumerate() {
            let line = format!("{:>3}. [{}] {}", i + 1, f.category.heading(), f.value);
            let truncated = if line.chars().count() > 72 {
                let s: String = line.chars().take(69).collect();
                format!("{}...", s)
            } else {
                line
            };
            let formatted_line = format!("║ {:<74} ║", truncated);
            println!("{}", theme.paint(Role::Primary, &formatted_line));
        }

        if findings.len() > max {
            let more = format!("... {} more finding(s) in harvest.txt", findings.len() - max);
            let more_line = format!("║ {:<74} ║", more);
            println!("{}", theme.paint(Role::Muted, &more_line));
        }
    }

    println!("{}", theme.paint(Role::Border, &format!("╚{}╝", border)));
}

/// Print execution summary metrics.
pub fn display_summary(theme: &Theme, outcome: &HarvestOutcome) {
    println!();
    let label = theme.paint(Role::Success, "  [✓] Summary: ");
    let text = format!("{} findings across {} task sections", outcome.findings.len(), outcome.sections);
    println!("{}{}", label, theme.paint(Role::Foreground, &text));
}

/// Print the destination directory of saved evidence.
pub fn display_saved(theme: &Theme, path: &Path) {
    let label = theme.paint(Role::Accent, "  [~] Saved → ");
    println!("{}{}", label, theme.paint(Role::Secondary, &path.display().to_string()));
    println!();
}
