//! Scrollable full-width output viewer
use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal,
};
use std::io::{self, Write};
use unicode_width::UnicodeWidthStr;

use crate::ui::theme::{terminal_width, pad_to};

pub fn view_file(path: &str) -> Result<()> {
    let fname = std::path::Path::new(path)
        .file_name().unwrap_or_default()
        .to_string_lossy().into_owned();

    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|_| "[binary or unreadable file]".into());
    
    let lines: Vec<&str> = content.lines().collect();
    
    let term_cols = terminal_width();
    let inner = term_cols.saturating_sub(2).max(40);
    
    let top = format!("╔{}╗", "═".repeat(inner));
    let bot = format!("╚{}╝", "═".repeat(inner));
    let text_cols = inner.saturating_sub(2);
    
    let title = format!("  Output: {}  ", fname);
    let title_dw = UnicodeWidthStr::width(title.as_str());
    let (lpad, rpad) = if title_dw < inner {
        let total = inner - title_dw;
        (total / 2, total - total / 2)
    } else {
        (0, 0)
    };
    let mid = format!("╠{}╣", "═".repeat(inner));

    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    let _ = execute!(stdout, cursor::Hide);

    let max_visible = 20usize;
    let mut scroll = 0usize;
    let mut prev_rows = 0u16;

    loop {
        let visible = lines.len().saturating_sub(scroll).min(max_visible);
        let end = scroll + visible;
        
        let frame_rows = (3 + visible + 1) as u16;

        if prev_rows > 0 {
            let _ = queue!(stdout,
                cursor::MoveUp(prev_rows),
                cursor::MoveToColumn(0)
            );
        }
        prev_rows = frame_rows;

        // Use Aqua for the border to distinguish from the main menu (Green)
        let _ = queue!(stdout,
            SetForegroundColor(Color::Cyan),
            Print(&top), Print("\r\n"),
            Print("║"),
            SetForegroundColor(Color::White),
            SetAttribute(Attribute::Bold),
            Print(&format!("{}{}{}", " ".repeat(lpad), pad_to(&title, title_dw.min(inner)), " ".repeat(rpad))),
            SetAttribute(Attribute::Reset),
            SetForegroundColor(Color::Cyan),
            Print("║\r\n"),
            Print(&mid), Print("\r\n")
        );

        for i in scroll..end {
            let item_text = pad_to(lines[i], text_cols);
            let _ = queue!(stdout,
                SetForegroundColor(Color::Cyan),
                Print("║ "),
                SetForegroundColor(Color::White),
                Print(&item_text),
                SetForegroundColor(Color::Cyan),
                Print(" ║\r\n")
            );
        }

        let _ = queue!(stdout,
            SetForegroundColor(Color::Cyan),
            Print(&bot), Print("\r\n"),
            ResetColor
        );
        let _ = stdout.flush();

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if scroll > 0 { scroll -= 1; }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if scroll + max_visible < lines.len() { scroll += 1; }
                    }
                    KeyCode::PageUp => {
                        scroll = scroll.saturating_sub(max_visible);
                    }
                    KeyCode::PageDown => {
                        if scroll + max_visible < lines.len() {
                            scroll = std::cmp::min(scroll + max_visible, lines.len().saturating_sub(max_visible));
                        }
                    }
                    KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => { break; }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let _ = execute!(stdout, cursor::Show, ResetColor);
                        let _ = terminal::disable_raw_mode();
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = execute!(stdout, cursor::Show, ResetColor);
    let _ = terminal::disable_raw_mode();
    Ok(())
}
