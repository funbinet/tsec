//! Structured input collection: one prompt, one line, always cancellable.
//!
//! Prompts are the documented exception to the box system — a clean
//! interactive line under the capability's title box. They run in the same
//! raw-mode, single-render-owner frame loop as every other screen, which is
//! what makes two things possible at once: the operator can walk away from a
//! field with `Esc` or `Ctrl+C` (returning to the capability menu, not
//! terminating TSEC), and a terminal resize mid-answer redraws correctly
//! instead of corrupting the line.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::io;

use crossterm::event::{KeyCode, KeyModifiers};

use crate::ui::panel::{self, Frame, Geometry, Renderer};
use crate::ui::theme::{Role, Theme};

/// One field's worth of prompt decoration.
#[derive(Debug)]
pub struct Prompt<'a> {
    /// e.g. `DOMAIN [domain]`.
    pub label: &'a str,
    /// Optional one-line help, shown muted under the value.
    pub help: Option<&'a str>,
    /// Pre-filled value; Enter on an untouched field accepts it.
    pub default: Option<&'a str>,
    /// Mask the typed characters (passwords, secrets).
    pub sensitive: bool,
    /// Validation failure from the previous attempt, shown in red.
    pub error: Option<&'a str>,
}

/// What the operator did with a prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Given(String),
    /// `Esc` or `Ctrl+C`: withdraw the capability rather than trap the operator.
    Cancelled,
}

/// Ask for one value, drawing under `above` (usually the capability box).
///
/// Returns as soon as the operator submits or withdraws; resizes and ordinary
/// keys only trigger redraws.
pub fn ask(
    out: &mut io::Stdout,
    renderer: &mut Renderer,
    theme: &Theme,
    above: Option<&Frame>,
    prompt: &Prompt<'_>,
) -> io::Result<Answer> {
    let mut buffer: Vec<char> = prompt.default.unwrap_or_default().chars().collect();
    let mut cursor = buffer.len();
    let mut shown_error: Option<String> = prompt.error.map(str::to_string);

    loop {
        let mut frame = Frame::default();
        if let Some(header) = above {
            frame.append(header.clone());
        }
        frame.append(prompt_lines(theme, prompt, &shown_error, &buffer, cursor));
        renderer.present(out, &frame)?;

        match panel::next_input()? {
            panel::Input::Resize => continue,
            panel::Input::Key(key) => {
                if panel::is_interrupt(&key) {
                    return Ok(Answer::Cancelled);
                }
                match key.code {
                    KeyCode::Enter => {
                        let value: String = buffer.iter().collect();
                        return Ok(Answer::Given(value.trim().to_string()));
                    }
                    KeyCode::Esc => return Ok(Answer::Cancelled),
                    KeyCode::Backspace => {
                        if cursor > 0 {
                            cursor -= 1;
                            buffer.remove(cursor);
                        }
                        shown_error = None;
                    }
                    KeyCode::Delete => {
                        if cursor < buffer.len() {
                            buffer.remove(cursor);
                        }
                        shown_error = None;
                    }
                    KeyCode::Left => cursor = cursor.saturating_sub(1),
                    KeyCode::Right => cursor = (cursor + 1).min(buffer.len()),
                    KeyCode::Home => cursor = 0,
                    KeyCode::End => cursor = buffer.len(),
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        buffer.clear();
                        cursor = 0;
                        shown_error = None;
                    }
                    KeyCode::Char(c)
                        if !key.modifiers.contains(KeyModifiers::CONTROL)
                            && !key.modifiers.contains(KeyModifiers::ALT) =>
                    {
                        buffer.insert(cursor, c);
                        cursor += 1;
                        shown_error = None;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// The unboxed prompt block: label line, value with a visible caret, optional
/// help and error lines, then the key hint.
fn prompt_lines(
    theme: &Theme,
    prompt: &Prompt<'_>,
    error: &Option<String>,
    buffer: &[char],
    cursor: usize,
) -> Frame {
    let g = Geometry::detect();
    let width = g.cols.saturating_sub(1);
    let mut rows: Vec<(String, Role)> = Vec::new();

    rows.push((String::new(), Role::Muted));
    rows.push((prompt.label.to_string(), Role::Accent));

    let value: String = buffer.iter().collect();
    let (value, role) = if prompt.sensitive && !value.is_empty() {
        ("*".repeat(buffer.len()), Role::Foreground)
    } else {
        (value, Role::Foreground)
    };
    // The caret is drawn as a glyph so the renderer never has to chase the
    // hardware cursor around the frame.
    let caret = "▌";
    let (before, after) = split_at_char(&value, cursor);
    rows.push((format!("{before}{caret}{after}"), role));

    if let Some(help) = prompt.help {
        rows.push((help.to_string(), Role::Muted));
    }
    if let Some(error) = error {
        rows.push((format!("! {error}"), Role::Error));
    }
    rows.push((String::new(), Role::Muted));
    rows.push(("-[ENTER] ACCEPT   -[ESC] CANCEL".to_string(), Role::Muted));

    // prompt_lines is built directly (not through box_frame) so it stays
    // unboxed, exactly as the input-form exception requires.
    let mut frame = Frame::default();
    for (text, role) in rows {
        frame.line(theme.paint(role, &panel::fit(&text, width)));
    }
    frame
}

/// Split a string at character index `at`.
fn split_at_char(text: &str, at: usize) -> (String, String) {
    let mut before = String::new();
    let mut after = String::new();
    for (index, c) in text.chars().enumerate() {
        if index < at {
            before.push(c);
        } else {
            after.push(c);
        }
    }
    (before, after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::panel::Layout;

    #[test]
    fn split_at_char_splits_on_character_boundaries() {
        assert_eq!(
            split_at_char("héllo", 2),
            ("hé".to_string(), "llo".to_string())
        );
        assert_eq!(split_at_char("", 0), (String::new(), String::new()));
        assert_eq!(split_at_char("abc", 99), ("abc".to_string(), String::new()));
    }

    #[test]
    fn prompt_lines_stay_unboxed_and_within_the_terminal() {
        let theme = Theme::plain();
        let prompt = Prompt {
            label: "DOMAIN [domain]",
            help: Some("the target you are enumerating"),
            default: Some("example.com"),
            sensitive: false,
            error: Some("not a valid domain name"),
        };
        let frame = prompt_lines(
            &theme,
            &prompt,
            &prompt.error.map(str::to_string),
            &['e'],
            1,
        );
        for line in frame.text.split("\r\n").filter(|l| !l.is_empty()) {
            assert!(
                !line.contains('│') && !line.contains('║'),
                "unboxed: {line:?}"
            );
            assert!(panel::display_width(line) <= 160, "line too wide: {line:?}");
        }
        assert!(frame.text.contains('▌'), "caret is visible");
    }

    #[test]
    fn layout_input_is_left_aligned() {
        assert!(!Layout::Input.title_centred());
        assert!(!Layout::Input.rows_centred());
    }
}
