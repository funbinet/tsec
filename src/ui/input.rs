//! Structured input collection: one unified three-part box, always cancellable.
//!
//! Every input of a capability is collected inside a single closed box with
//! three parts: the top part carries the capability's name (centred), the
//! middle part carries the input's name — e.g. `TARGET [target]` — under an
//! internal separator, and the bottom part is the typing row where the value
//! is entered around a caret glyph. Moving from one input of the same
//! capability to the next updates the middle and bottom parts in place; the
//! box never duplicates and never scrolls. `Enter` submits; `Esc` cancels back
//! to the capability menu — never exiting the framework from inside a form.
//! Help, validation errors and the key hint are drawn centred below the box:
//! they are transient explanations, not part of the box itself.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::io;

use crossterm::event::{KeyCode, KeyModifiers};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::ui::panel;
use crate::ui::panel::{centre, expand_tabs, Frame, Geometry, Layout, Renderer};
use crate::ui::theme::{Role, Theme};

/// One field's worth of prompt decoration.
#[derive(Debug)]
pub struct Prompt<'a> {
    /// e.g. `TARGET [target]` — the middle part of the box.
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

/// Ask for one value inside the capability's own unified box, whose top part
/// carries `title` (the capability's name). The box is rebuilt in place on
/// every keystroke by the same renderer that draws every other screen.
///
/// Returns as soon as the operator submits or withdraws; resizes and ordinary
/// keys only trigger in-place redraws, and `PageUp`/`PageDown` page through
/// the frozen stack above.
pub fn ask(
    out: &mut io::Stdout,
    renderer: &mut Renderer,
    theme: &Theme,
    title: &str,
    prompt: &Prompt<'_>,
) -> io::Result<Answer> {
    let mut buffer: Vec<char> = prompt.default.unwrap_or_default().chars().collect();
    let mut cursor = buffer.len();
    let mut shown_error: Option<String> = prompt.error.map(str::to_string);

    loop {
        let frame = input_box(theme, title, prompt, &shown_error, &buffer, cursor);
        renderer.present(out, &frame)?;

        match panel::next_input()? {
            panel::Input::Resize => continue,
            panel::Input::Key(key) => {
                if panel::is_interrupt(&key) {
                    return Ok(Answer::Cancelled);
                }
                if renderer.handle_scroll_key(&key) {
                    continue;
                }
                renderer.reset_scroll();
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

/// The unified three-part input box plus its centred help, error and hint
/// lines: capability title on top, the input's name in the middle, the typing
/// row at the bottom.
fn input_box(
    theme: &Theme,
    title: &str,
    prompt: &Prompt<'_>,
    error: &Option<String>,
    buffer: &[char],
    cursor: usize,
) -> Frame {
    let g = Geometry::detect();
    let inner = g.inner;
    let content = inner.saturating_sub(2);
    let mut frame = Frame::default();

    // Part 1 — the capability's name, centred under the top border.
    frame.line(theme.paint(Role::Border, &format!("╔{}╗", "═".repeat(inner))));
    let title = title.to_uppercase();
    frame.line(format!(
        "{}{}{}",
        theme.paint(Role::Border, "║ "),
        theme.paint(Role::Primary, &centre(&title, content)),
        theme.paint(Role::Border, " ║")
    ));

    // Part 2 — the input's name, under an internal double separator.
    frame.line(theme.paint(Role::Border, &format!("╠{}╣", "═".repeat(inner))));
    frame.line(format!(
        "{}{}{}",
        theme.paint(Role::Border, "║ "),
        theme.paint(Role::Accent, &centre(prompt.label, content)),
        theme.paint(Role::Border, " ║")
    ));

    // Part 3 — the typing row, under an internal thin separator. The caret is
    // a glyph so the renderer never chases the hardware cursor around the box.
    frame.line(theme.paint(Role::Border, &format!("╟{}╢", "─".repeat(inner))));
    let value: String = buffer.iter().collect();
    let shown = if prompt.sensitive && !value.is_empty() {
        "*".repeat(buffer.len())
    } else {
        value
    };
    let value_row = visible_value(&shown, cursor, content);
    frame.line(format!(
        "{}{}{}",
        theme.paint(Role::Border, "║ "),
        theme.paint(Role::Foreground, &centre(&value_row, content)),
        theme.paint(Role::Border, " ║")
    ));

    frame.line(theme.paint(Role::Border, &format!("╚{}╝", "═".repeat(inner))));

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

/// The typed value as it is shown: a window of at most `content - 1` display
/// columns around the cursor, with the caret at the cursor position. A value
/// longer than the box shows the part the operator is working on.
fn visible_value(text: &str, cursor: usize, content: usize) -> String {
    let budget = content.saturating_sub(1).max(1);
    let chars: Vec<char> = text.chars().collect();
    let cursor = cursor.min(chars.len());

    // Walk backwards from the cursor, filling the budget starting with the
    // caret itself, so the text the operator just typed always stays visible.
    let mut width = 1usize; // the caret
    let mut start = cursor;
    while start > 0 {
        let cw = UnicodeWidthChar::width(chars[start - 1]).unwrap_or(1);
        if width + cw > budget {
            break;
        }
        width += cw;
        start -= 1;
    }
    // Then forward from the cursor with whatever budget remains.
    let mut end = cursor;
    while end < chars.len() {
        let cw = UnicodeWidthChar::width(chars[end]).unwrap_or(1);
        if width + cw > budget {
            break;
        }
        width += cw;
        end += 1;
    }

    let mut out: String = chars[start..cursor].iter().collect();
    out.push('▌');
    out.extend(chars[cursor..end].iter());
    out
}

/// Wrap `text` into display lines of at most `cols` columns.
fn wrap(text: &str, cols: usize) -> Vec<String> {
    panel::wrap(&expand_tabs(text), cols)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::panel::display_width;
    use crate::ui::theme::strip_ansi;

    fn theme() -> Theme {
        Theme::plain()
    }

    #[test]
    fn the_box_has_exactly_three_parts_in_one_closed_frame() {
        let prompt = Prompt {
            label: "DOMAIN [domain]",
            help: Some("the target you are enumerating"),
            default: Some("example.com"),
            sensitive: false,
            error: Some("not a valid domain name"),
        };
        let frame = input_box(
            &theme(),
            "SUBDOMAIN DISCOVERY",
            &prompt,
            &prompt.error.map(str::to_string),
            &['e', 'x'],
            2,
        );

        let lines: Vec<String> = frame
            .text
            .split("\r\n")
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();

        // One closed box: a single top and bottom border.
        assert_eq!(
            lines.iter().filter(|l| l.contains('╔')).count(),
            1,
            "one top border"
        );
        assert_eq!(
            lines.iter().filter(|l| l.contains('╚')).count(),
            1,
            "one bottom border"
        );
        assert!(!lines.iter().any(|l| l.contains('│')), "closed box only");

        // Part 1: the capability's name. Part 2: the input's name.
        assert!(lines.iter().any(|l| l.contains("SUBDOMAIN DISCOVERY")));
        assert!(lines.iter().any(|l| l.contains("DOMAIN [domain]")));

        // Part 3: the typing row with the caret, between two separators.
        let caret = lines.iter().find(|l| l.contains('▌')).expect("caret row");
        assert!(caret.contains('║'), "the caret lives inside the box");
        assert!(
            lines.iter().any(|l| l.contains('╟')),
            "an internal thin separator separates the typing row"
        );

        // Transient lines sit below the box, centred.
        let hint = lines
            .iter()
            .find(|l| l.contains("-[ENTER] ACCEPT"))
            .expect("hint line present");
        assert!(hint.starts_with(' '), "centred hint is padded: {hint:?}");
        assert!(lines.iter().any(|l| l.contains("not a valid domain name")));

        // Box rows never exceed terminal width.
        for line in lines.iter().filter(|l| l.contains('║')) {
            assert!(display_width(line) <= 80, "overflow: {line:?}");
        }
    }

    #[test]
    fn the_typing_row_stays_one_line_for_long_values() {
        let prompt = Prompt {
            label: "PATH [path]",
            help: None,
            default: None,
            sensitive: false,
            error: None,
        };
        let long: Vec<char> = "a".repeat(400).chars().collect();
        let frame = input_box(&theme(), "T", &prompt, &None, &long, 200);
        for line in frame.text.split("\r\n").filter(|l| !l.is_empty()) {
            assert!(
                display_width(&strip_ansi(line)) <= 80,
                "overflow: {line:?}"
            );
        }
    }

    #[test]
    fn sensitive_values_are_masked_with_a_visible_caret() {
        let prompt = Prompt {
            label: "PASSWORD [password]",
            help: None,
            default: None,
            sensitive: true,
            error: None,
        };
        let buffer: Vec<char> = "hunter2".chars().collect();
        let frame = input_box(&theme(), "T", &prompt, &None, &buffer, 7);
        let lines: Vec<&str> = frame.text.split("\r\n").filter(|l| !l.is_empty()).collect();
        let value_row = lines.iter().find(|l| l.contains('▌')).unwrap();
        let plain = strip_ansi(value_row);
        assert!(plain.contains("*******▌"), "{plain:?}");
        assert!(!plain.contains("hunter2"), "secrets are never echoed");
    }

    #[test]
    fn visible_value_windows_around_the_cursor() {
        // Everything fits: prefix, caret, suffix.
        assert_eq!(visible_value("hello", 5, 20), "hello▌");
        assert_eq!(visible_value("hello", 0, 20), "▌hello");
        // A narrow box keeps the text before the cursor visible.
        let shown = visible_value("abcdefghij", 10, 6);
        assert_eq!(shown, "ghij▌");
        assert!(display_width(&shown) <= 6, "{shown:?}");
        // Mid-string cursors keep both sides around the caret.
        assert_eq!(visible_value("abcdef", 3, 20), "abc▌def");
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
        assert_eq!(UnicodeWidthStr::width(strip_ansi(painted).as_str()), 3);
    }
}
