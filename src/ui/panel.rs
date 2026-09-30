//! Panel geometry and box drawing.
//!
//! One module decides what a panel looks like: a centred box, a one-word title,
//! rows of text and an optional `-[ENTER]` hint underneath. Menus, status and
//! harvest views all render through it, so they cannot drift apart, and the
//! operator sees the same shape everywhere.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::io::{self, Write};
use std::time::Duration;

use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::queue;
use crossterm::style::{Print, ResetColor};
use crossterm::terminal::{self, ClearType};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::ui::theme::{Role, Theme};

/// Where a panel sits in the current terminal, and how wide it is.
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
            Ok((cols, rows)) if cols > 0 && rows > 0 => (cols, rows),
            _ => (80, 24),
        };
        let cols = (cols as usize).max(20);
        let width = cols.saturating_sub(4).clamp(30, 68);
        Self {
            cols,
            rows: rows as usize,
            width,
            inner: width - 2,
        }
    }

    /// Left padding that centres the box.
    pub fn margin(&self) -> String {
        " ".repeat(self.cols.saturating_sub(self.width) / 2)
    }

    /// Body rows that fit on screen once `reserved` lines are set aside.
    pub fn body_rows(&self, reserved: usize) -> usize {
        self.rows.saturating_sub(reserved).max(3)
    }
}

/// Truncate to `cols` and pad to `cols`, so every row is exactly one width.
pub fn fit(text: &str, cols: usize) -> String {
    let width = UnicodeWidthStr::width(text);
    if width == cols {
        return text.to_string();
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

/// Centre `text` inside `cols` columns.
pub fn centre(text: &str, cols: usize) -> String {
    let width = UnicodeWidthStr::width(text);
    if width >= cols {
        return fit(text, cols);
    }
    let left = (cols - width) / 2;
    format!(
        "{}{}{}",
        " ".repeat(left),
        text,
        " ".repeat(cols - width - left)
    )
}

/// A finished panel: how many lines were written, so it can be erased.
#[derive(Debug, Clone, Copy)]
pub struct Drawn {
    pub lines: u16,
}

/// Draw a panel: title, rows, then the `-[ENTER]` hint when asked for.
pub fn draw(
    out: &mut io::Stdout,
    theme: &Theme,
    title: &str,
    rows: &[(String, Role)],
    hint: bool,
) -> io::Result<Drawn> {
    let g = Geometry::detect();
    let margin = g.margin();
    let border = "═".repeat(g.inner);
    let mut lines = 0u16;

    for (index, text) in [
        format!("╔{border}╗"),
        format!("║{}║", centre(&title.to_uppercase(), g.inner)),
        format!("╠{border}╣"),
    ]
    .iter()
    .enumerate()
    {
        let role = if index == 1 {
            Role::Primary
        } else {
            Role::Border
        };
        queue!(
            out,
            Print(theme.paint(role, &format!("{margin}{text}"))),
            Print("\r\n")
        )?;
        lines += 1;
    }

    let body = g.inner.saturating_sub(2);
    for (text, role) in rows {
        queue!(
            out,
            Print(theme.paint(Role::Border, &format!("{margin}║"))),
            Print(theme.paint(*role, &format!(" {} ", fit(text, body)))),
            Print(theme.paint(Role::Border, "║")),
            Print("\r\n")
        )?;
        lines += 1;
    }

    queue!(
        out,
        Print(theme.paint(Role::Border, &format!("{margin}╚{border}╝"))),
        Print("\r\n")
    )?;
    lines += 1;

    if hint {
        queue!(
            out,
            Print(theme.paint(Role::Muted, &centre(&format!("{margin}-[ENTER]"), g.cols))),
            Print("\r\n")
        )?;
        lines += 1;
    }

    out.flush()?;
    Ok(Drawn { lines })
}

/// Erase the last panel so a live screen can be redrawn in place.
pub fn erase(out: &mut io::Stdout, drawn: Drawn) -> io::Result<()> {
    queue!(
        out,
        cursor::MoveUp(drawn.lines),
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::FromCursorDown)
    )?;
    out.flush()
}

/// Terminal in raw mode with the cursor hidden; both are restored on drop.
#[derive(Debug)]
pub struct RawMode;

impl RawMode {
    pub fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut out = io::stdout();
        let _ = queue!(out, cursor::Hide);
        let _ = out.flush();
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = queue!(out, cursor::Show, ResetColor);
        let _ = out.flush();
        let _ = terminal::disable_raw_mode();
    }
}

/// True for Ctrl+C, the one key that must leave cleanly from anywhere.
pub fn is_interrupt(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
}

/// Block until the next key press or repeat, and report it.
///
/// Blocking rather than polling is deliberate: a lone `Esc` is only
/// distinguishable from the start of an escape sequence once the terminal has
/// gone quiet, and a poll loop that never lets the read time out never sees it.
pub fn next_key() -> io::Result<KeyEvent> {
    loop {
        if let Event::Key(key) = event::read()? {
            if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                return Ok(key);
            }
        }
    }
}

/// Report a key only when one is already waiting, so a caller can poll.
pub fn poll_key(timeout: Duration) -> io::Result<Option<KeyEvent>> {
    if !event::poll(timeout)? {
        return Ok(None);
    }
    Ok(match event::read()? {
        Event::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
            Some(key)
        }
        _ => None,
    })
}

/// Block until the operator closes the screen with Enter, Esc or Ctrl+C.
pub fn wait_close() -> io::Result<()> {
    loop {
        let key = next_key()?;
        if is_interrupt(&key) {
            return Ok(());
        }
        match key.code {
            KeyCode::Enter | KeyCode::Esc => return Ok(()),
            _ => {}
        }
    }
}
