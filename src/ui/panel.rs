//! Panel geometry: full-terminal-width boxes, layout semantics, and the
//! stacked, scrollable frame history.
//!
//! Every screen is one *full-width* box whose horizontal dimension is derived
//! from the current terminal width (`inner = cols - 2`), so the container grows
//! and shrinks with the terminal. The [`Renderer`] owns an alternate-screen
//! session and a *stack of frozen boxes*: descending into a screen freezes the
//! box above, so the main menu stays on screen beneath a phase menu, a phase
//! menu stays beneath a capability flow, and so on. A redraw paints the frozen
//! history plus the one active box — the box under construction — and never
//! duplicates a live box: regaining control after a child screen closes
//! collapses the frames added since, so the parent repaints as the single
//! active box. The hint line belongs to the active box alone. When the stack
//! outgrows the terminal, `PageUp`/`PageDown` scroll through it. The
//! operator's own terminal history (the main buffer) is never touched:
//! entering and leaving the session restores it exactly as it was. No
//! background thread ever writes.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::io::{self, Write};
use std::time::Duration;

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseEventKind,
};
use crossterm::style::ResetColor;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::ui::theme::{strip_ansi, Role, Theme};

/// Where a panel sits in the current terminal, and how wide it is.
///
/// `width` is the terminal width itself: the box spans the terminal edge to
/// edge, so `box width <= terminal width` holds for every terminal size.
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    pub cols: usize,
    pub rows: usize,
    pub width: usize,
    pub inner: usize,
}

impl Geometry {
    /// Measure the terminal, or fall back to a classic 80x24.
    ///
    /// A pty that has never been given a size reports 0x0 — common in scripts
    /// and CI — and drawing a twenty-column, three-row box from that would be
    /// technically correct and useless, so it is treated as unknown.
    pub fn detect() -> Self {
        let (cols, rows) = match terminal::size() {
            Ok((cols, rows)) if cols > 0 && rows > 0 => (cols as usize, rows as usize),
            _ => (80, 24),
        };
        Self::for_size(cols, rows)
    }

    /// Geometry for an explicit terminal size. Never wider than the terminal.
    pub fn for_size(cols: usize, rows: usize) -> Self {
        let cols = cols.max(4);
        let width = cols;
        Self {
            cols,
            rows,
            width,
            inner: width - 2,
        }
    }

    /// Body rows that fit on screen once `reserved` lines (chrome, prompts,
    /// hints) are set aside. Always at least one row: a tiny terminal shows a
    /// scrollable single row rather than an invalid box.
    pub fn body_rows(&self, reserved: usize) -> usize {
        self.rows.saturating_sub(reserved).max(1)
    }
}

/// Display width of a string in terminal columns, ignoring ANSI escapes.
pub fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(strip_ansi(text).as_str())
}

/// Replace tabs with spaces so a tab can never be measured as width zero.
pub fn expand_tabs(text: &str) -> String {
    text.replace('\t', "    ")
}

/// Truncate to `cols` display columns and pad to exactly `cols`, so every row
/// is exactly one width. ANSI sequences are stripped before measuring and are
/// never counted as visible columns.
pub fn fit(text: &str, cols: usize) -> String {
    if cols == 0 {
        return String::new();
    }
    let text = strip_ansi(&expand_tabs(text));
    let width = UnicodeWidthStr::width(text.as_str());
    if width == cols {
        return text;
    }
    if width < cols {
        return format!("{text}{}", " ".repeat(cols - width));
    }
    let mut out = String::new();
    let mut used = 0usize;
    for c in text.chars() {
        let cw = UnicodeWidthChar::width(c).unwrap_or(1);
        if used + cw > cols.saturating_sub(1) {
            break;
        }
        out.push(c);
        used += cw;
    }
    out.push('…');
    let padding = cols.saturating_sub(UnicodeWidthStr::width(out.as_str()));
    out.push_str(&" ".repeat(padding));
    out
}

/// Centre `text` inside `cols` display columns.
pub fn centre(text: &str, cols: usize) -> String {
    let text = strip_ansi(&expand_tabs(text));
    let width = UnicodeWidthStr::width(text.as_str());
    if width >= cols {
        return fit(text.as_str(), cols);
    }
    let left = (cols - width) / 2;
    format!(
        "{}{}{}",
        " ".repeat(left),
        text,
        " ".repeat(cols - width - left)
    )
}

/// Wrap `text` into display lines of at most `cols` columns.
///
/// Words are kept intact where possible; a word longer than the line is
/// hard-split, because a command line must never overflow the box.
pub fn wrap(text: &str, cols: usize) -> Vec<String> {
    let cols = cols.max(1);
    let text = strip_ansi(&expand_tabs(text));
    let mut out: Vec<String> = Vec::new();

    for paragraph in text.split('\n') {
        let mut line = String::new();
        let mut line_w = 0usize;
        let flush = |line: &mut String, line_w: &mut usize, out: &mut Vec<String>| {
            out.push(std::mem::take(line));
            *line_w = 0;
        };
        if paragraph.is_empty() {
            out.push(String::new());
            continue;
        }
        for word in paragraph.split(' ') {
            let w = UnicodeWidthStr::width(word);
            if w == 0 {
                // Consecutive spaces: keep one separator if the line has room.
                if !line.is_empty() && line_w < cols {
                    line.push(' ');
                    line_w += 1;
                }
                continue;
            }
            let needed = if line.is_empty() { w } else { line_w + 1 + w };
            if needed <= cols {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
                line_w = needed;
                continue;
            }
            if !line.is_empty() {
                flush(&mut line, &mut line_w, &mut out);
            }
            if w <= cols {
                line.push_str(word);
                line_w = w;
            } else {
                // Hard-split an over-long word across as many lines as needed.
                let mut rest: &str = word;
                loop {
                    let mut taken = String::new();
                    let mut used = 0usize;
                    for c in rest.chars() {
                        let cw = UnicodeWidthChar::width(c).unwrap_or(1);
                        if used + cw > cols {
                            break;
                        }
                        taken.push(c);
                        used += cw;
                    }
                    if taken.is_empty() {
                        break;
                    }
                    let consumed: usize = taken.chars().map(char::len_utf8).sum();
                    rest = &rest[consumed..];
                    if UnicodeWidthStr::width(rest) <= cols {
                        line.push_str(&taken);
                        line_w = used;
                        break;
                    }
                    out.push(taken);
                }
            }
        }
        if !line.is_empty() || out.is_empty() {
            out.push(line);
        }
    }
    out
}

/// How a screen arranges its content. The variants exist so one screen's
/// alignment cannot leak into another's by calling the wrong helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Selection lists: centred title, rows block-centred — every entry shares
    /// one left column and the *block* is centred, not each line.
    Menu,
    /// Input forms and closed metadata boxes: centred title, rows block-centred.
    Form,
    /// Status, guidance and errors: centred title, rows block-centred — the
    /// block sits mid-box while its entries stay aligned with each other.
    Information,
    /// Live task and processing screens: centred title, rows block-centred.
    Execution,
    /// The `OUTPUT` document: centred title, left rows.
    Output,
    /// The full-file viewer: centred title, left rows.
    Viewer,
    /// Unboxed prompt fragments, which keep the left alignment.
    Input,
}

impl Layout {
    pub fn title_centred(self) -> bool {
        !matches!(self, Layout::Input)
    }

    pub fn rows_centred(self) -> bool {
        matches!(
            self,
            Layout::Menu | Layout::Form | Layout::Information | Layout::Execution
        )
    }

    /// Menu boxes carry breathing room around their entries; form boxes stay
    /// closed and tight (title row, content row, bottom border — nothing else).
    fn padded(self) -> bool {
        matches!(self, Layout::Menu)
    }
}

/// A finished frame: the exact bytes to show, and how many lines it spans.
#[derive(Debug, Clone, Default)]
pub struct Frame {
    pub text: String,
    pub lines: u16,
}

impl Frame {
    /// Append one already-rendered line (an unboxed prompt line, a hint…).
    pub fn line(&mut self, text: impl AsRef<str>) {
        self.lines += 1;
        self.text.push_str(text.as_ref());
        self.text.push_str("\r\n");
    }

    /// Append another frame's lines to this one, keeping the total count.
    pub fn append(&mut self, other: Frame) {
        self.text.push_str(&other.text);
        self.lines += other.lines;
    }
}

/// Build one full-width box: top border, title, separator, rows, bottom border.
///
/// Menu boxes gain a blank row under the separator and above the bottom
/// border, matching the selection-screen design; every other box is exactly
/// as tall as its content.
pub fn box_frame(theme: &Theme, layout: Layout, title: &str, rows: &[(String, Role)]) -> Frame {
    box_frame_in(&Geometry::detect(), theme, layout, title, rows)
}

/// [`box_frame`] against an explicit geometry, for width-invariant tests.
pub fn box_frame_in(
    g: &Geometry,
    theme: &Theme,
    layout: Layout,
    title: &str,
    rows: &[(String, Role)],
) -> Frame {
    let mut frame = Frame::default();
    let border = "═".repeat(g.inner);
    let content = g.inner.saturating_sub(2);

    frame.line(theme.paint(Role::Border, &format!("╔{border}╗")));

    let title = title.to_uppercase();
    let title_row = if layout.title_centred() {
        centre(&title, content)
    } else {
        fit(&title, content)
    };
    frame.line(format!(
        "{}{}{}",
        theme.paint(Role::Border, "║ "),
        theme.paint(Role::Primary, &title_row),
        theme.paint(Role::Border, " ║")
    ));
    frame.line(theme.paint(Role::Border, &format!("╠{border}╣")));

    if layout.padded() {
        frame.line(format!(
            "{}{}{}",
            theme.paint(Role::Border, "║ "),
            " ".repeat(content),
            theme.paint(Role::Border, " ║")
        ));
    }

    // Block centring: wrap every row first, find the widest one, then give
    // every row the same left offset — the block sits in the middle of the
    // box while the entries stay aligned with each other on the left.
    let prepared: Vec<(String, Role)> = rows
        .iter()
        .flat_map(|(text, role)| {
            if content == 0 {
                vec![String::new()]
            } else {
                wrap(text, content)
            }
            .into_iter()
            .map(move |segment| (segment, *role))
        })
        .collect();

    let block_w = prepared
        .iter()
        .map(|(text, _)| display_width(text.trim_end()))
        .max()
        .unwrap_or(0)
        .min(content);
    let block_left = content.saturating_sub(block_w) / 2;

    for (text, role) in prepared {
        let row = if layout.rows_centred() {
            let visible = text.trim_end().to_string();
            let w = display_width(&visible);
            let right = content.saturating_sub(block_left + w);
            format!(
                "{}{}{}{}{}",
                theme.paint(Role::Border, "║ "),
                " ".repeat(block_left),
                theme.paint(role, &visible),
                " ".repeat(right),
                theme.paint(Role::Border, " ║")
            )
        } else {
            format!(
                "{}{}{}",
                theme.paint(Role::Border, "║ "),
                theme.paint(role, &fit(&text, content)),
                theme.paint(Role::Border, " ║")
            )
        };
        frame.line(row);
    }

    if layout.padded() {
        frame.line(format!(
            "{}{}{}",
            theme.paint(Role::Border, "║ "),
            " ".repeat(content),
            theme.paint(Role::Border, " ║")
        ));
    }

    frame.line(theme.paint(Role::Border, &format!("╚{border}╝")));
    frame
}

/// Unboxed lines, left aligned — for fragments under a box.
pub fn plain_frame(theme: &Theme, rows: &[(String, Role)]) -> Frame {
    let g = Geometry::detect();
    let mut frame = Frame::default();
    for (text, role) in rows {
        for segment in wrap(text, g.cols.saturating_sub(1)) {
            frame.line(theme.paint(*role, &fit(&segment, g.cols.saturating_sub(1))));
        }
    }
    frame
}

/// Split a frame's text into its lines, dropping the trailing empty segment
/// left by the final `CRLF`. Box frames never end in a blank line.
fn frame_lines(frame: &Frame) -> Vec<&str> {
    let text = frame.text.trim_end_matches("\r\n");
    if text.is_empty() {
        Vec::new()
    } else {
        text.split("\r\n").collect()
    }
}

/// Total bytes across the frozen history, for sizing the write buffer.
fn history_bytes(history: &[Frame]) -> usize {
    history.iter().map(|frame| frame.text.len()).sum()
}

/// The visible window over the frozen history plus the active frame:
/// bottom-anchored, shifted up by `scroll` lines, at most `rows` lines long.
fn window_lines<'a>(
    history: &'a [Frame],
    active: &'a Frame,
    rows: usize,
    scroll: usize,
) -> Vec<&'a str> {
    let rows = rows.max(1);
    let mut lines: Vec<&str> = history.iter().flat_map(frame_lines).collect();
    lines.extend(frame_lines(active));
    if lines.len() <= rows {
        return lines;
    }
    let end = lines.len() - scroll.min(lines.len() - rows);
    let start = end - rows;
    lines[start..end].to_vec()
}

/// The one-line key hint drawn under a box, centred and unboxed.
pub fn hint_frame(theme: &Theme, text: &str) -> Frame {
    let g = Geometry::detect();
    let mut frame = Frame::default();
    frame.line(theme.paint(Role::Muted, &centre(text, g.cols.saturating_sub(1))));
    frame
}

/// The alternate-screen render session: the single writer for the whole UI.
///
/// [`Renderer::enter`] switches to the alternate screen and hides the cursor;
/// every [`Renderer::present`] then overwrites the frame in place — cursor
/// home, the complete frame, erase-below — in one buffered write, so a redraw
/// never appends, never scrolls, never duplicates. [`Renderer::close`] (and
/// `Drop`, for error paths) returns the terminal to the main buffer with the
/// operator's prior history untouched and the cursor visible again.
#[derive(Debug)]
pub struct Renderer {
    active: bool,
    /// Boxes already left behind, in the order they were left. A frozen box is
    /// dead history: it is painted above the active box and can be scrolled
    /// through, but it can never receive input again.
    history: Vec<Frame>,
    /// Lines scrolled up from the bottom of the combined view.
    scroll: usize,
}

impl Renderer {
    /// Begin the session: raw mode, alternate screen, mouse capture, hidden cursor.
    pub fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut out = io::stdout();
        execute!(
            out,
            EnterAlternateScreen,
            EnableMouseCapture,
            cursor::Hide,
            ResetColor
        )?;
        Ok(Self {
            active: true,
            history: Vec::new(),
            scroll: 0,
        })
    }

    /// Freeze `frame` into the history: the box stays on screen above
    /// whatever comes next and becomes scrollable dead history.
    pub fn freeze(&mut self, frame: &Frame) {
        self.history.push(frame.clone());
        self.scroll = 0;
    }

    /// How many boxes are frozen.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Collapse every box frozen since `base`, including the caller's own
    /// frozen copy: a menu regaining control after its child screens close
    /// repaints itself as the one active box, never a duplicate.
    pub fn collapse_to(&mut self, base: usize) {
        self.history.truncate(base);
        self.scroll = 0;
    }

    /// Reset the scroll window to the bottom (the active box).
    pub fn reset_scroll(&mut self) {
        self.scroll = 0;
    }

    /// Scroll up by a number of lines (revealing earlier history).
    pub fn scroll_up(&mut self, lines: usize) {
        self.scroll = self.scroll.saturating_add(lines);
    }

    /// Scroll down by a number of lines (revealing newer content).
    pub fn scroll_down(&mut self, lines: usize) {
        self.scroll = self.scroll.saturating_sub(lines);
    }

    /// Current scroll offset from the bottom.
    pub fn scroll_offset(&self) -> usize {
        self.scroll
    }

    /// Apply `PageUp`/`PageDown` to the history scroll. Returns true when the
    /// key was consumed, so the caller redraws and skips its other bindings.
    /// `PageUp` looks further up the stack; `PageDown` comes back down.
    pub fn handle_scroll_key(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::PageUp => {
                let rows = Geometry::detect().rows;
                self.scroll_up(rows);
                true
            }
            KeyCode::PageDown => {
                let rows = Geometry::detect().rows;
                self.scroll_down(rows);
                true
            }
            _ => false,
        }
    }

    /// Paint the frozen history plus `frame` (the active box), in one write.
    ///
    /// The combined text is bottom-anchored: when it outgrows the terminal,
    /// the window shows the bottom of the stack — the active box — and
    /// `PageUp`/`PageDown` move the window through the history.
    pub fn present(&mut self, out: &mut io::Stdout, frame: &Frame) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        let rows = Geometry::detect().rows;
        let lines = window_lines(&self.history, frame, rows, self.scroll);
        let mut buf: Vec<u8> =
            Vec::with_capacity(frame.text.len() + history_bytes(&self.history) + 64);
        // Begin synchronized update to eliminate visual tearing and flickering.
        buf.extend_from_slice(b"\x1b[?2026h");
        // Cursor to the top-left (1, 1).
        buf.extend_from_slice(b"\x1b[H");
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                buf.extend_from_slice(b"\r\n");
            }
            buf.extend_from_slice(line.as_bytes());
            // Clear to end of line so changed text length leaves no artifacts.
            buf.extend_from_slice(b"\x1b[K");
        }
        // Only erase below if the drawn lines do not fill the entire terminal window.
        // Emitting \r\n on the bottom-most row causes the terminal to scroll up by one row.
        if lines.len() < rows {
            buf.extend_from_slice(b"\r\n\x1b[J");
        }
        // End synchronized update (atomic frame flip).
        buf.extend_from_slice(b"\x1b[?2026l");
        out.write_all(&buf)?;
        out.flush()
    }

    /// End the session, restoring the operator's terminal exactly.
    pub fn close(mut self) -> io::Result<()> {
        self.leave()?;
        Ok(())
    }

    fn leave(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let mut out = io::stdout();
        let _ = execute!(
            out,
            DisableMouseCapture,
            LeaveAlternateScreen,
            cursor::Show,
            ResetColor
        );
        let _ = terminal::disable_raw_mode();
        // Preserve all completed boxes from the session in the main terminal scrollback.
        for frame in &self.history {
            let _ = print_plain(&mut out, frame);
            let _ = out.write_all(b"\r\n");
        }
        out.flush()
    }
}

impl Drop for Renderer {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}

/// Write a finished frame after the session has closed (the exit screen):
/// a plain, one-time append to the restored main buffer.
pub fn print_plain(out: &mut io::Stdout, frame: &Frame) -> io::Result<()> {
    out.write_all(frame.text.as_bytes())?;
    out.flush()
}

/// What the terminal reported while we were waiting for an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    Key(KeyEvent),
    Resize,
    ScrollUp(usize),
    ScrollDown(usize),
}

/// The operator's decision when closing a still screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAction {
    Accept,
    Cancel,
    Back,
}

/// True for Ctrl+C, the context-sensitive interrupt key.
pub fn is_interrupt(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
}

fn is_press(key: &KeyEvent) -> bool {
    matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
}

/// Block until a key press, mouse scroll, or a resize arrives.
pub fn next_input() -> io::Result<Input> {
    loop {
        match event::read()? {
            Event::Key(key) if is_press(&key) => return Ok(Input::Key(key)),
            Event::Mouse(mouse) => match mouse.kind {
                MouseEventKind::ScrollUp => return Ok(Input::ScrollUp(3)),
                MouseEventKind::ScrollDown => return Ok(Input::ScrollDown(3)),
                _ => {}
            },
            Event::Resize(..) => return Ok(Input::Resize),
            _ => {}
        }
    }
}

/// Report a key, mouse scroll, or resize only if one is already waiting, so a caller can poll.
pub fn poll_input(timeout: Duration) -> io::Result<Option<Input>> {
    if !event::poll(timeout)? {
        return Ok(None);
    }
    Ok(match event::read()? {
        Event::Key(key) if is_press(&key) => Some(Input::Key(key)),
        Event::Mouse(mouse) => match mouse.kind {
            MouseEventKind::ScrollUp => Some(Input::ScrollUp(3)),
            MouseEventKind::ScrollDown => Some(Input::ScrollDown(3)),
            _ => None,
        },
        Event::Resize(..) => Some(Input::Resize),
        _ => None,
    })
}

/// Block until the operator closes the screen with Enter, J or Esc, or scrolls
/// through the frozen history with PageUp/PageDown/Up/Down/I/K/mouse wheel.
/// Resizes are swallowed; Ctrl+C is reported through Cancel.
pub fn wait_close(
    out: &mut io::Stdout,
    renderer: &mut Renderer,
    frame: &Frame,
) -> io::Result<CloseAction> {
    loop {
        match next_input()? {
            Input::Resize => {}
            Input::ScrollUp(n) => {
                renderer.scroll_up(n);
                renderer.present(out, frame)?;
            }
            Input::ScrollDown(n) => {
                renderer.scroll_down(n);
                renderer.present(out, frame)?;
            }
            Input::Key(key) => {
                if renderer.handle_scroll_key(&key) {
                    renderer.present(out, frame)?;
                    continue;
                }
                if is_interrupt(&key) {
                    return Ok(CloseAction::Cancel);
                }
                match key.code {
                    KeyCode::Up | KeyCode::Char('i') | KeyCode::Char('I') => {
                        renderer.scroll_up(2);
                        renderer.present(out, frame)?;
                    }
                    KeyCode::Down | KeyCode::Char('k') | KeyCode::Char('K') => {
                        renderer.scroll_down(2);
                        renderer.present(out, frame)?;
                    }
                    KeyCode::Enter => return Ok(CloseAction::Accept),
                    KeyCode::Esc => return Ok(CloseAction::Cancel),
                    KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Left => {
                        return Ok(CloseAction::Back);
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::{ColorDepth, PaletteName};

    fn theme() -> Theme {
        Theme::fixed(PaletteName::Midnight, ColorDepth::None)
    }

    #[test]
    fn fit_measures_display_width_not_byte_length() {
        assert_eq!(fit("héllo", 10), "héllo     ");
        assert_eq!(display_width(&fit("héllo", 10)), 10);
        assert!(display_width(&fit("a very long line that will not fit", 10)) <= 10);
    }

    #[test]
    fn fit_strips_ansi_before_measuring() {
        let painted = "\x1b[31mred\x1b[0m";
        assert_eq!(display_width(painted), 3);
        assert_eq!(fit(painted, 6), "red   ");
    }

    #[test]
    fn centre_places_text_midway() {
        let c = centre("MENU", 10);
        assert_eq!(display_width(&c), 10);
        assert!(c.starts_with("  "), "{c:?}");
    }

    #[test]
    fn wrap_never_exceeds_the_column_budget() {
        for text in [
            "short",
            "a much longer line that definitely needs to wrap somewhere around here",
            "supercalifragilisticexpialidociousANDTHENSOMEMORETEXT",
            "",
            "double  spaces   and\ttabs",
        ] {
            for cols in [1usize, 7, 20, 80] {
                for line in wrap(text, cols) {
                    assert!(
                        display_width(&line) <= cols,
                        "{text:?} at {cols} produced {line:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn wrap_preserves_blank_lines() {
        assert_eq!(wrap("a\n\nb", 10), vec!["a", "", "b"]);
    }

    #[test]
    fn box_frames_span_the_terminal_at_every_width() {
        for cols in [40usize, 50, 60, 80, 100, 120, 160, 200] {
            let g = Geometry::for_size(cols, 24);
            let rows = vec![
                ("RECONNAISSANCE".to_string(), Role::Foreground),
                (
                    "A long menu entry that wraps if the terminal is narrow enough to require it"
                        .to_string(),
                    Role::Highlight,
                ),
            ];
            for layout in [
                Layout::Menu,
                Layout::Form,
                Layout::Information,
                Layout::Execution,
                Layout::Output,
                Layout::Viewer,
            ] {
                let frame = box_frame_in(&g, &theme(), layout, "TSEC", &rows);
                for line in frame.text.split("\r\n").filter(|l| !l.is_empty()) {
                    assert!(
                        display_width(line) <= cols,
                        "layout {layout:?} at {cols} cols overflowed: {line:?}"
                    );
                }
                // The border itself must exactly reach the terminal width.
                let first = frame.text.split("\r\n").next().unwrap();
                assert_eq!(
                    display_width(first),
                    cols,
                    "layout {layout:?} top border at {cols}"
                );
            }
        }
    }

    #[test]
    fn a_tiny_terminal_still_produces_a_valid_box() {
        let g = Geometry::for_size(4, 3);
        let frame = box_frame_in(&g, &theme(), Layout::Menu, "TSEC", &[]);
        for line in frame.text.split("\r\n").filter(|l| !l.is_empty()) {
            assert!(display_width(line) <= 4, "{line:?}");
        }
        assert!(g.body_rows(500) >= 1, "never zero visible rows");
    }

    #[test]
    fn menu_boxes_pad_their_rows_while_form_boxes_do_not() {
        let g = Geometry::for_size(40, 24);
        let rows = vec![("DATA".to_string(), Role::Foreground)];
        let menu = box_frame_in(&g, &theme(), Layout::Menu, "T", &rows);
        let form = box_frame_in(&g, &theme(), Layout::Form, "T", &rows);
        assert!(menu.lines > form.lines, "menus breathe, forms stay closed");
    }

    /// The centring contract: entries share one left column, and that column
    /// is chosen so the block as a whole is centred in the box.
    #[test]
    fn menu_rows_share_a_left_edge_and_the_block_is_centred() {
        let g = Geometry::for_size(60, 24);
        let rows = vec![
            ("RECONNAISSANCE".to_string(), Role::Foreground),
            ("PAYLOAD".to_string(), Role::Foreground),
        ];
        let frame = box_frame_in(&g, &theme(), Layout::Menu, "TSEC", &rows);
        let body: Vec<String> = frame
            .text
            .split("\r\n")
            .filter(|l| l.contains("RECON") || l.contains("PAYLOAD"))
            .map(strip_ansi)
            .collect();
        assert_eq!(body.len(), 2);
        // Measure in display columns, not bytes: the border glyph is multi-byte.
        let first = display_width(&body[0][..body[0].find("RECONNAISSANCE").unwrap()]);
        let second = display_width(&body[1][..body[1].find("PAYLOAD").unwrap()]);
        assert_eq!(first, second, "entries aligned to one left column");

        // The block's left offset inside the content area (border prefix is
        // two display columns wide).
        let content = g.inner - 2;
        let widest = 14usize; // "RECONNAISSANCE"
        let block_left = (content.saturating_sub(widest)) / 2;
        assert_eq!(first - 2, block_left, "the block itself is centred");
    }

    #[test]
    fn layouts_pick_the_right_alignment() {
        assert!(Layout::Menu.title_centred() && Layout::Menu.rows_centred());
        assert!(Layout::Form.title_centred() && Layout::Form.rows_centred());
        assert!(Layout::Information.title_centred() && Layout::Information.rows_centred());
        assert!(Layout::Execution.title_centred() && Layout::Execution.rows_centred());
        assert!(Layout::Output.title_centred() && !Layout::Output.rows_centred());
        assert!(Layout::Viewer.title_centred() && !Layout::Viewer.rows_centred());
    }

    #[test]
    fn the_window_is_bottom_anchored_and_scrollable() {
        let mut filler = Frame::default();
        for i in 0..30 {
            filler.line(format!("FROZEN {i}"));
        }
        let history = vec![filler];
        let mut active = Frame::default();
        active.line("ACTIVE");

        // Everything fits: nothing is dropped.
        let all = window_lines(&history, &active, 40, 0);
        assert_eq!(all.len(), 31);
        assert_eq!(all[0], "FROZEN 0");
        assert_eq!(all[30], "ACTIVE");

        // A 10-row terminal shows the bottom: the active box and the last
        // frozen lines above it.
        let bottom = window_lines(&history, &active, 10, 0);
        assert_eq!(bottom.len(), 10);
        assert_eq!(bottom[9], "ACTIVE");
        assert_eq!(bottom[0], "FROZEN 21");

        // Scrolling up moves the window through the history.
        let up = window_lines(&history, &active, 10, 10);
        assert_eq!(up[0], "FROZEN 11");
        assert_eq!(up[9], "FROZEN 20");

        // The scroll never runs past the top of the stack.
        let top = window_lines(&history, &active, 10, 100);
        assert_eq!(top[0], "FROZEN 0");
        assert_eq!(top[9], "FROZEN 9");
    }

    #[test]
    fn freeze_and_collapse_keep_the_stack_well_formed() {
        let mut renderer = Renderer {
            active: true,
            history: Vec::new(),
            scroll: 0,
        };
        let g = Geometry::for_size(40, 24);
        let menu = box_frame_in(&g, &theme(), Layout::Menu, "MAIN", &[]);
        renderer.freeze(&menu);
        let base = renderer.history_len();
        let child = box_frame_in(&g, &theme(), Layout::Form, "CHILD", &[]);
        renderer.freeze(&child);
        assert_eq!(renderer.history_len(), 2);
        renderer.collapse_to(base);
        assert_eq!(renderer.history_len(), 1, "the parent copy stays frozen");
        renderer.collapse_to(0);
        assert!(renderer.history.is_empty());
    }

    #[test]
    fn a_frozen_box_reappears_above_the_active_box() {
        let g = Geometry::for_size(40, 24);
        let frozen = box_frame_in(&g, &theme(), Layout::Menu, "MAIN", &[]);
        let history = vec![frozen];
        let active = box_frame_in(&g, &theme(), Layout::Form, "CHILD", &[]);
        let lines = window_lines(&history, &active, 40, 0);
        let combined: Vec<&str> = lines.to_vec();
        assert!(combined.iter().any(|l| l.contains("MAIN")));
        assert!(combined.iter().any(|l| l.contains("CHILD")));
        let main_pos = combined.iter().position(|l| l.contains("MAIN")).unwrap();
        let child_pos = combined.iter().position(|l| l.contains("CHILD")).unwrap();
        assert!(main_pos < child_pos, "frozen boxes paint above the active box");
    }

    #[test]
    fn scroll_up_and_down_adjusts_offset() {
        let mut renderer = Renderer {
            active: true,
            history: Vec::new(),
            scroll: 0,
        };
        renderer.scroll_up(5);
        assert_eq!(renderer.scroll_offset(), 5);
        renderer.scroll_up(10);
        assert_eq!(renderer.scroll_offset(), 15);
        renderer.scroll_down(7);
        assert_eq!(renderer.scroll_offset(), 8);
        renderer.scroll_down(20);
        assert_eq!(renderer.scroll_offset(), 0);
        renderer.scroll_up(12);
        renderer.reset_scroll();
        assert_eq!(renderer.scroll_offset(), 0);
    }

    #[test]
    fn close_action_variants_are_distinct() {
        assert_ne!(CloseAction::Accept, CloseAction::Cancel);
        assert_ne!(CloseAction::Cancel, CloseAction::Back);
        assert_ne!(CloseAction::Accept, CloseAction::Back);
    }
}
