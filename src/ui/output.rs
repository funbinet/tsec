//! The `OUTPUT` document screens.
//!
//! One file — `output.txt`, written by the store — is the single source of
//! truth. The OUTPUT box is a compact summary showing the run status, finding
//! count and output path. Three controls follow: `Y` opens the full scrollable
//! viewer, `ENTER` starts a new cycle, `ESC` exits. The full viewer shows
//! every line of the output file in a scrollable box.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::io;
use std::path::Path;

use crossterm::event::KeyCode;

use crate::ui::panel;
use crate::ui::panel::{box_frame, hint_frame, Geometry, Layout, Renderer};
use crate::ui::theme::{Role, Theme};

/// The initial preview shows at most this many lines of the document.
pub const PREVIEW_LIMIT: usize = 500;

/// Largest file the viewer will hold in memory (the parser's own raw cap).
const VIEWER_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Read a document into lines, refusing anything absurdly large.
fn read_lines(path: &Path) -> io::Result<Vec<String>> {
    let file = std::fs::File::open(path)?;
    use std::io::Read;
    let mut buf = Vec::new();
    file.take(VIEWER_MAX_BYTES).read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    Ok(text.lines().map(str::to_string).collect())
}

/// Show the minimal OUTPUT screen for a finished run's document.
///
/// The OUTPUT box is a compact summary:
///   - `RUN COMPLETE`
///   - `Findings: N` (line count from the output file)
///   - `Output: /path/to/output.txt`
///
/// Controls:
///   - `Y` → open the full scrollable output viewer
///   - `ENTER` → return (start a new cycle)
///   - `ESC` → return (exit)
pub fn show_output(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    path: &Path,
    _prefix: Option<&crate::ui::panel::Frame>,
) -> io::Result<panel::CloseAction> {
    let line_count = match read_lines(path) {
        Ok(lines) => lines.len(),
        Err(_) => 0,
    };

    let rows: Vec<(String, Role)> = vec![
        ("RUN COMPLETE".to_string(), Role::Success),
        (String::new(), Role::Muted),
        (format!("Findings:        {line_count}"), Role::Foreground),
        (format!("Output:          {}", path.display()), Role::Accent),
    ];

    let panel = box_frame(theme, Layout::Form, "OUTPUT", &rows);
    renderer.freeze(&panel);

    loop {
        let frame = panel::hint_frame(
            theme,
            "-[I/K] SCROLL   -[Y] OPEN FULL   -[ENTER] NEW RUN   -[ESC] EXIT",
        );
        renderer.present(out, &frame)?;

        match panel::next_input()? {
            panel::Input::Resize => continue,
            panel::Input::ScrollUp(n) => {
                renderer.scroll_up(n);
                renderer.present(out, &frame)?;
            }
            panel::Input::ScrollDown(n) => {
                renderer.scroll_down(n);
                renderer.present(out, &frame)?;
            }
            panel::Input::Key(key) => {
                if panel::is_interrupt(&key) {
                    return Ok(panel::CloseAction::Cancel);
                }
                if renderer.handle_scroll_key(&key) {
                    renderer.present(out, &frame)?;
                    continue;
                }
                match key.code {
                    KeyCode::Up | KeyCode::Char('i') | KeyCode::Char('I') => {
                        renderer.scroll_up(2);
                        renderer.present(out, &frame)?;
                    }
                    KeyCode::Down | KeyCode::Char('k') | KeyCode::Char('K') => {
                        renderer.scroll_down(2);
                        renderer.present(out, &frame)?;
                    }
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        view_document(theme, renderer, out, "OUTPUT", path)?;
                    }
                    KeyCode::Enter => return Ok(panel::CloseAction::Accept),
                    KeyCode::Esc => return Ok(panel::CloseAction::Cancel),
                    KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Left => {
                        return Ok(panel::CloseAction::Back)
                    }
                    _ => {}
                }
            }
        }
    }
}

/// The scrollable full-file viewer: every line of `path`, full width.
pub fn view_document(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    title: &str,
    path: &Path,
) -> io::Result<()> {
    let lines = match read_lines(path) {
        Ok(lines) => lines,
        Err(e) => {
            return show_error(
                renderer,
                out,
                theme,
                &format!("cannot read {}: {e}", path.display()),
            )
        }
    };
    view_lines(theme, renderer, out, title, &lines)
}

/// The scrollable viewer over lines already in memory.
pub fn view_lines(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    title: &str,
    lines: &[String],
) -> io::Result<()> {
    let mut scroll = 0usize;
    loop {
        let g = Geometry::detect();
        // Chrome: four box rows plus the hint line.
        let visible = g.body_rows(5);
        scroll = scroll.min(lines.len().saturating_sub(visible.min(lines.len())));

        let rows: Vec<(String, Role)> = lines
            .iter()
            .skip(scroll)
            .take(visible)
            .map(|line| (line.to_string(), Role::Foreground))
            .collect();

        let mut frame = box_frame(theme, Layout::Viewer, title, &rows);
        let position = if lines.is_empty() {
            "EMPTY".to_string()
        } else {
            format!(
                "LINES {}-{} OF {}",
                scroll + 1,
                (scroll + visible).min(lines.len()),
                lines.len()
            )
        };
        frame.append(hint_frame(
            theme,
            &format!("-[I/K] SCROLL   -[J/ESC] CLOSE   {position}"),
        ));
        renderer.present(out, &frame)?;

        match panel::next_input()? {
            panel::Input::Resize => continue,
            panel::Input::ScrollUp(n) => {
                scroll = scroll.saturating_sub(n);
            }
            panel::Input::ScrollDown(n) => {
                scroll = (scroll + n).min(lines.len().saturating_sub(1));
            }
            panel::Input::Key(key) => {
                if panel::is_interrupt(&key) {
                    return Ok(());
                }
                match key.code {
                    KeyCode::Char('i') | KeyCode::Char('I') | KeyCode::Up => {
                        scroll = scroll.saturating_sub(1)
                    }
                    KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Down => {
                        scroll = (scroll + 1).min(lines.len().saturating_sub(1))
                    }
                    KeyCode::PageUp => scroll = scroll.saturating_sub(visible),
                    KeyCode::PageDown => {
                        scroll = (scroll + visible).min(lines.len().saturating_sub(1))
                    }
                    KeyCode::Char('j')
                    | KeyCode::Char('J')
                    | KeyCode::Esc
                    | KeyCode::Enter
                    | KeyCode::Left => return Ok(()),
                    _ => {}
                }
            }
        }
    }
}

/// A one-screen error notice, closed with any of the usual keys.
pub fn show_error(
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    theme: &Theme,
    message: &str,
) -> io::Result<()> {
    let mut frame = box_frame(
        theme,
        Layout::Execution,
        "ERROR",
        &[(message.to_string(), Role::Error)],
    );
    frame.append(hint_frame(theme, "-[ENTER/J/ESC] CLOSE"));
    renderer.present(out, &frame)?;
    let _ = panel::wait_close(out, renderer, &frame)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_limit_is_five_hundred_lines() {
        assert_eq!(PREVIEW_LIMIT, 500);
    }

    #[test]
    fn read_lines_reads_a_file_and_reports_missing_files() {
        let dir = std::env::temp_dir().join(format!("tsec-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("doc.txt");
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        assert_eq!(read_lines(&path).unwrap(), vec!["one", "two", "three"]);
        assert!(read_lines(&dir.join("missing.txt")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
