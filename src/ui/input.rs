//! Structured input collection: one closed box per field, always cancellable.
//!
//! Each input is a closed box of two full-width rows: the title row carries
//! the input's label (centred), the content row is where the operator types
//! (centred). The box is rebuilt in place on every keystroke by the same
//! renderer that draws every other screen, so typing never scrolls, never
//! appends, never duplicates. `Enter` submits; `Esc` cancels back to the
//! capability menu — never exiting the framework from inside a form.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::io;

use crossterm::event::{KeyCode, KeyModifiers};

use crate::ui::panel;
use crate::ui::panel::{box_frame_in, centre, wrap, Frame, Geometry, Layout, Renderer};
use crate::ui::theme::{Role, Theme};

/// One field's worth of prompt decoration.
#[derive(Debug)]
pub struct Prompt<'a> {
    /// Capability name displayed as the box title.
    pub capability: &'a str,
    /// e.g. `DOMAIN [domain]` — becomes the box title row.
    pub label: &'a str,
    /// Optional one-line help, shown muted under the box.
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

/// Ask for one value: a closed two-row box — title row, typing row — drawn
/// after `above` (usually the capability's own box), plus centred help, error
/// and hint lines.
///
/// Returns as soon as the operator submits or withdraws; resizes and ordinary
/// keys only trigger in-place redraws.
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
        frame.append(input_frame(theme, prompt, &shown_error, &buffer, cursor));
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

/// The closed input box plus its centred help, error and hint lines.
fn input_frame(
    theme: &Theme,
    prompt: &Prompt<'_>,
    error: &Option<String>,
    buffer: &[char],
    cursor: usize,
) -> Frame {
    let g = Geometry::detect();
    let content = g.inner.saturating_sub(2);
    let mut frame = Frame::default();

    frame.line(String::new());

    // One closed three-part box: capability title, input label row, input row.
    let value: String = buffer.iter().collect();
    let shown = if prompt.sensitive && !value.is_empty() {
        "*".repeat(buffer.len())
    } else {
        value
    };
    let (before, after) = split_at_char(&shown, cursor);
    let value_row = format!("{before}▌{after}");
    frame.append(box_frame_in(
        &g,
        theme,
        Layout::Form,
        prompt.capability,
        &[
            (prompt.label.to_string(), Role::Primary),
            (value_row, Role::Foreground),
        ],
    ));

    if let Some(help) = prompt.help {
        for segment in wrap(help, content) {
            frame.line(theme.paint(Role::Muted, &centre(&segment, g.cols.saturating_sub(1))));
        }
    }
    if let Some(error) = error {
        for segment in wrap(&format!("! {error}"), content) {
            frame.line(theme.paint(Role::Error, &centre(&segment, g.cols.saturating_sub(1))));
        }
    }
    frame.line(theme.paint(
        Role::Muted,
        &centre("-[ENTER] ACCEPT   -[ESC] CANCEL", g.cols.saturating_sub(1)),
    ));
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
    use crate::ui::panel::{display_width, fit, Layout};

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
    fn input_frame_is_one_closed_box_with_three_sections() {
        let theme = Theme::plain();
        let prompt = Prompt {
            capability: "SUBDOMAIN DISCOVERY",
            label: "DOMAIN [domain]",
            help: Some("the target you are enumerating"),
            default: Some("example.com"),
            sensitive: false,
            error: Some("not a valid domain name"),
        };
        let frame = input_frame(
            &theme,
            &prompt,
            &prompt.error.map(str::to_string),
            &['e'],
            1,
        );

        let lines: Vec<String> = frame
            .text
            .split("\r\n")
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        assert!(lines.iter().any(|l| l.contains("SUBDOMAIN DISCOVERY")));
        assert!(lines.iter().any(|l| l.contains("DOMAIN [domain]")));
        assert!(lines.iter().any(|l| l.contains('▌')));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("-[ENTER] ACCEPT   -[ESC] CANCEL")),
            "the accept/cancel hint is present"
        );
        // The hint line is present and padded (centred): it starts with
        // spaces rather than at column zero.
        let hint = lines
            .iter()
            .find(|l| l.contains("-[ENTER] ACCEPT"))
            .expect("hint line present");
        assert!(hint.starts_with(' '), "centred hint is padded: {hint:?}");
        // Box rows never exceed terminal width.
        for line in lines.iter().filter(|l| l.contains('║')) {
            assert!(display_width(line) <= 80, "overflow: {line:?}");
        }
        assert!(!lines.iter().any(|l| l.contains('│')), "closed box only");
    }

    #[test]
    fn layout_form_is_fully_centred() {
        assert!(Layout::Form.title_centred());
        assert!(Layout::Form.rows_centred());
    }

    #[test]
    fn fit_and_centre_agree_on_painted_text() {
        let painted = "\x1b[31mred\x1b[0m";
        assert_eq!(display_width(&centre(painted, 7)), 7);
        assert_eq!(display_width(&fit(painted, 5)), 5);
    }
}
