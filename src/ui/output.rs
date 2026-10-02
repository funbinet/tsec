//! The `OUTPUT` document screens.
//!
//! One file — `output.txt`, written by the store — is the single source of
//! truth. The preview shows its first [`PREVIEW_LIMIT`] lines inside a
//! full-width box; underneath, a small closed box names the saved file, and
//! the hint line lists exactly three operations plus `ESC`: scroll, open the
//! full viewer (`L`), close. There is no confirmation question — `L` opens
//! the viewer directly. `ESC` always closes the screen.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::io;
use std::path::Path;

use crossterm::event::KeyCode;

use crate::ui::panel;
use crate::ui::panel::{box_frame, box_frame_in, hint_frame, Geometry, Layout, Renderer};
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

/// Show the OUTPUT screen for a finished run's document.
///
/// Returns when the operator closes the screen; if they opened the full
/// viewer, the preview loop resumes underneath it first.
pub fn show_output(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    path: &Path,
    prefix: Option<&crate::ui::panel::Frame>,
) -> io::Result<()> {
    let all = match read_lines(path) {
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
    let preview: Vec<&str> = all.iter().take(PREVIEW_LIMIT).map(String::as_str).collect();
    let truncated = all.len() > preview.len();
    let mut scroll = 0usize;

    loop {
        let g = Geometry::detect();
        // Chrome: 4 preview-box rows + 4 file-box rows + 1 hint line.
        let visible = g.body_rows(4 + 4 + 1).saturating_sub(1);

        if scroll + visible > preview.len() {
            scroll = preview.len().saturating_sub(visible);
        }

        let body = visible.saturating_sub(1);
        let mut rows: Vec<(String, Role)> = preview
            .iter()
            .skip(scroll)
            .take(body)
            .map(|line| (line.to_string(), Role::Foreground))
            .collect();
        if truncated && scroll + rows.len() >= preview.len() {
            rows.push((
                format!(
                    "… {} more lines in the full output",
                    all.len() - preview.len()
                ),
                Role::Muted,
            ));
        } else if truncated {
            rows.push((
                format!("… {} of {} preview lines shown", rows.len(), preview.len()),
                Role::Muted,
            ));
        }

        let mut frame = box_frame(theme, Layout::Output, "OUTPUT", &rows);

        // The saved file, in its own closed two-row centred box.
        let file_box = box_frame_in(
            &g,
            theme,
            Layout::Form,
            "OUTPUT FILE",
            &[(path.display().to_string(), Role::Accent)],
        );
        frame.append(file_box);

        frame.append(hint_frame(
            theme,
            "-[I/K] SCROLL   -[L] OPEN FULL   -[J/ESC] CLOSE",
        ));
        if let Some(prefix) = prefix {
            let mut composed = prefix.clone();
            composed.line(String::new());
            composed.append(frame);
            renderer.present(out, &composed)?;
        } else {
            renderer.present(out, &frame)?;
        }

        match panel::next_input()? {
            panel::Input::Resize => continue,
            panel::Input::Key(key) => {
                if panel::is_interrupt(&key) {
                    return Ok(());
                }
                match key.code {
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        view_document(theme, renderer, out, "OUTPUT", path)?;
                    }
                    KeyCode::Esc | KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Left => {
                        return Ok(())
                    }
                    KeyCode::Char('i') | KeyCode::Char('I') | KeyCode::Up => {
                        scroll = scroll.saturating_sub(1)
                    }
                    KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Down => {
                        scroll = (scroll + 1).min(preview.len().saturating_sub(1))
                    }
                    KeyCode::PageUp => scroll = scroll.saturating_sub(visible),
                    KeyCode::PageDown => {
                        scroll = (scroll + visible).min(preview.len().saturating_sub(1))
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
    panel::wait_close(out, renderer, &frame)
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
