//! Formatted output display: preview box, line-numbered list, summary.

use crate::parser::ParsedOutput;
use crate::tools::types::OutputFormat;
use crate::ui::theme::{cprint, cprintln, green, grey, white, bright_green, terminal_width, pad_to};

/// Display everything after a command completes: preview, summary, saved path.
pub fn display_result(
    parsed:       &ParsedOutput,
    _fmt:         OutputFormat,
    saved_path:   &str,
    preview_lines: usize,
) {
    println!();
    display_preview(parsed, preview_lines);
    display_summary(parsed);
    display_saved(saved_path);
}

/// Show the first `max` lines in a numbered, green-bordered preview box.
pub fn display_preview(parsed: &ParsedOutput, max: usize) {
    let lines: Vec<&str> = parsed.display
        .lines()
        .take(max)
        .collect();

    if lines.is_empty() {
        cprintln(grey(), "  (no output to preview)");
        return;
    }

    let total_displayed = lines.len();
    let total_lines     = parsed.lines.len();

    let inner = terminal_width().saturating_sub(2).max(40);

    cprintln(green(), &format!("╔{}╗", "═".repeat(inner)));
    cprint(green(), "║  ");
    cprint(white(), &pad_to("Output Preview", inner.saturating_sub(4)));
    cprintln(green(), "  ║");
    cprintln(green(), &format!("╠{}╣", "═".repeat(inner)));

    let line_content_width = inner.saturating_sub(9);

    for (i, line) in lines.iter().enumerate() {
        let num = format!("{:>3}. ", i + 1);
        cprint(green(), "║  ");
        cprint(grey(), &num);
        cprint(bright_green(), &pad_to(line, line_content_width));
        cprintln(green(), "  ║");
    }

    if total_lines > total_displayed {
        let msg = format!("… {} more line{} not shown", total_lines - total_displayed,
            if total_lines - total_displayed == 1 { "" } else { "s" });
        cprint(green(), "║  ");
        cprint(grey(), &pad_to(&msg, inner.saturating_sub(4)));
        cprintln(green(), "  ║");
    }

    cprintln(green(), &format!("╚{}╝", "═".repeat(inner)));
}

/// Print the one-line summary line.
pub fn display_summary(parsed: &ParsedOutput) {
    println!();
    cprint(green(), "  [-] ");
    cprintln(white(), &parsed.summary);
}

/// Print the "Saved to:" path.
pub fn display_saved(path: &str) {
    cprint(grey(), "  [~] Saved → ");
    cprintln(bright_green(), path);
    println!();
}
