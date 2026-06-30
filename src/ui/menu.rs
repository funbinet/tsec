//! Interactive menus: top-level, tool, mode, outputs, settings.

use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal,
};
use dialoguer::{Confirm, Input};
use std::io::{self, Write};
use unicode_width::UnicodeWidthStr;

use crate::config::Config;
use crate::tools::types::{Category, Mode, Tool};
use crate::ui::theme::{
    cprintln, grey, print_box, print_info, print_success, section_header, terminal_width, wait_key,
};
use crate::input::hacker_theme;

// ── Display-width-aware padding ────────────────────────────────────────────

/// Pad or truncate `s` to exactly `target_cols` terminal display columns.
fn pad_to(s: &str, target_cols: usize) -> String {
    let w = UnicodeWidthStr::width(s);
    if w >= target_cols {
        // Truncate with ellipsis
        let mut out = String::new();
        let mut cols = 0usize;
        for c in s.chars() {
            let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(1);
            if cols + cw > target_cols.saturating_sub(1) {
                out.push('.');
                break;
            }
            out.push(c);
            cols += cw;
        }
        // Pad any remaining space
        let cur_w = UnicodeWidthStr::width(out.as_str());
        if cur_w < target_cols {
            out.push_str(&" ".repeat(target_cols - cur_w));
        }
        out
    } else {
        format!("{}{}", s, " ".repeat(target_cols - w))
    }
}

// ── Core boxed menu ────────────────────────────────────────────────────────

pub enum BoxedMenuResult {
    Selected(usize),
    TimeoutOverride(usize),
    Back,
    Home,
    Exit,
}

/// Draw a full-terminal-width box menu with a centred title and navigate with
/// arrow/j/k keys.  Returns `BoxedMenuResult`.
fn run_boxed_menu(title: &str, items: &[String]) -> Result<BoxedMenuResult> {
    let term_cols = terminal_width();

    // Total box width = term_cols (fills the whole terminal row)
    // Box chars consume 2 cols (left ║ + right ║), so inner = term_cols - 2
    let inner = term_cols.saturating_sub(2).max(40);

    let top = format!("╔{}╗", "═".repeat(inner));
    let mid = format!("╠{}╣", "═".repeat(inner));
    let bot = format!("╚{}╝", "═".repeat(inner));

    // Centred title: ║ + <spaces> + title + <spaces> + ║
    // The spaces fill `inner` columns total.
    let title_dw = UnicodeWidthStr::width(title);
    let (lpad, rpad) = if title_dw < inner {
        let total = inner - title_dw;
        (total / 2, total - total / 2)
    } else {
        (0, 0)
    };
    let title_row = format!("║{}{}{}║", " ".repeat(lpad), pad_to(title, title_dw.min(inner)), " ".repeat(rpad));

    // Item text columns:
    // Each row = ║(1) + space(1) + marker(1) + space(1) + TEXT + space(1) + ║(1)
    // = 6 fixed cols + TEXT cols = inner + 2
    // => TEXT cols = inner + 2 - 6 = inner - 4
    let text_cols = inner.saturating_sub(4);

    // ── Raw mode ───────────────────────────────────────────────────────────
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    let _ = execute!(stdout, cursor::Hide);

    let mut selected  = 0usize;
    let max_visible   = 18usize;
    let mut prev_rows = 0u16;

    let mut digit_buffer = String::new();
    let mut last_digit_time = std::time::Instant::now();

    let result = loop {
        let visible = items.len().min(max_visible);
        let start   = if selected >= max_visible { selected - max_visible + 1 } else { 0 };
        let end     = start + visible;

        // Total rows this frame: top(1) + title(1) + mid(1) + items + bot(1)
        let frame_rows = (3 + visible + 1) as u16;

        // Move cursor up to overwrite previous frame
        if prev_rows > 0 {
            let _ = queue!(stdout,
                cursor::MoveUp(prev_rows),
                cursor::MoveToColumn(0)
            );
        }
        prev_rows = frame_rows;

        // ── Draw header ────────────────────────────────────────────────────
        let _ = queue!(stdout,
            SetForegroundColor(Color::Green),
            Print(&top),  Print("\r\n"),
            Print(&title_row), Print("\r\n"),
            Print(&mid),  Print("\r\n")
        );

        // ── Draw items ─────────────────────────────────────────────────────
        for i in start..end {
            let item_text = pad_to(&items[i], text_cols);

            if i == selected {
                // Active: entire row cyan + bold
                let _ = queue!(stdout,
                    SetForegroundColor(Color::Cyan),
                    SetAttribute(Attribute::Bold),
                    Print("║ > "),
                    Print(&item_text),
                    Print(" ║"),
                    SetAttribute(Attribute::Reset),
                    Print("\r\n")
                );
            } else {
                // Inactive: dim border, green text
                let _ = queue!(stdout,
                    SetForegroundColor(Color::Rgb { r: 0, g: 220, b: 100 }),
                    Print("║ "),
                    SetForegroundColor(Color::Reset),
                    Print("  "),
                    SetForegroundColor(Color::Rgb { r: 0, g: 255, b: 80 }), // Green text instead of White
                    Print(&item_text),
                    SetForegroundColor(Color::Rgb { r: 0, g: 220, b: 100 }),
                    Print(" ║\r\n")
                );
            }
        }

        // ── Draw footer — always closes the box ────────────────────────────
        let _ = queue!(stdout,
            SetForegroundColor(Color::Rgb { r: 0, g: 220, b: 100 }),
            Print(&bot), Print("\r\n"),
            ResetColor
        );
        let _ = stdout.flush();

        // ── Key handling ───────────────────────────────────────────────────
        if crossterm::event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
                    match key.code {
                        KeyCode::Up | KeyCode::Char('u') => {
                            if selected > 0 { selected -= 1; }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if selected + 1 < items.len() { selected += 1; }
                        }
                        KeyCode::Enter | KeyCode::Right | KeyCode::Char('k') => {
                            break BoxedMenuResult::Selected(selected);
                        }
                        KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('q') | KeyCode::Char('<') => {
                            break BoxedMenuResult::Back;
                        }
                        KeyCode::Char('#') => { break BoxedMenuResult::Home; }
                        KeyCode::Char('x') => { break BoxedMenuResult::Exit; }
                        KeyCode::Char('T') | KeyCode::Char('t') => { break BoxedMenuResult::TimeoutOverride(selected); }
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            if key.kind == KeyEventKind::Press {
                                digit_buffer.push(c);
                                last_digit_time = std::time::Instant::now();
                            }
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let _ = execute!(stdout, cursor::Show, ResetColor);
                            let _ = terminal::disable_raw_mode();
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                }
            }
        } else {
            // Check digit buffer timeout
            if !digit_buffer.is_empty() && last_digit_time.elapsed() > std::time::Duration::from_millis(400) {
                if let Ok(num) = digit_buffer.parse::<usize>() {
                    if num > 0 && num <= items.len() {
                        break BoxedMenuResult::Selected(num - 1);
                    }
                }
                digit_buffer.clear();
            }
        }
    };

    let _ = execute!(stdout, cursor::Show, ResetColor);
    let _ = terminal::disable_raw_mode();
    Ok(result)
}

// ── Top-level menu ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TopMenuChoice {
    Category(usize),
    Outputs,
    Settings,
    Exit,
}

#[derive(Debug)]
pub enum MenuResult<T> {
    Selected(T),
    TimeoutOverride(T),
    Back,
    Home,
    Exit,
}

pub fn top_menu() -> Result<TopMenuChoice> {
    println!();
    let items: Vec<String> = vec![
        " [1] Reconnaissance".into(),
        " [2] Attack Surface Mapping".into(),
        " [3] Vulnerability Assessment".into(),
        " [4] Payload Development".into(),
        " [5] Privilege Escalation".into(),
        " [6] Credential Access".into(),
        " [7] Lateral Movement".into(),
        " [8] Persistence & Evasion".into(),
        " [9] Actions on Objectives".into(),
        " [10] Wireless Hacking".into(),
        " [O] Outputs".into(),
        " [*] Settings".into(),
        " [x] Exit".into(),
    ];

    match run_boxed_menu("  M A I N   M E N U  ", &items)? {
        BoxedMenuResult::Selected(0) => Ok(TopMenuChoice::Category(0)),
        BoxedMenuResult::Selected(1) => Ok(TopMenuChoice::Category(1)),
        BoxedMenuResult::Selected(2) => Ok(TopMenuChoice::Category(2)),
        BoxedMenuResult::Selected(3) => Ok(TopMenuChoice::Category(3)),
        BoxedMenuResult::Selected(4) => Ok(TopMenuChoice::Category(4)),
        BoxedMenuResult::Selected(5) => Ok(TopMenuChoice::Category(5)),
        BoxedMenuResult::Selected(6) => Ok(TopMenuChoice::Category(6)),
        BoxedMenuResult::Selected(7) => Ok(TopMenuChoice::Category(7)),
        BoxedMenuResult::Selected(8) => Ok(TopMenuChoice::Category(8)),
        BoxedMenuResult::Selected(9) => Ok(TopMenuChoice::Category(9)),
        BoxedMenuResult::Selected(10) => Ok(TopMenuChoice::Outputs),
        BoxedMenuResult::Selected(11) => Ok(TopMenuChoice::Settings),
        _ => Ok(TopMenuChoice::Exit),
    }
}

// ── Tool menu ──────────────────────────────────────────────────────────────

pub fn tool_menu(cat: &'static Category) -> Result<MenuResult<&'static Tool>> {
    println!();
    let title = format!("  {}  -  Select Tool  ", cat.name);
    let mut items: Vec<String> = cat.tools.iter().enumerate()
        .map(|(i, t)| format!(" [{}] {}", i + 1, t.name))
        .collect();
    items.push(" [#] Home".to_string());
    items.push(" [<] Back".to_string());
    items.push(" [x] Exit".to_string());

    let len = cat.tools.len();
    match run_boxed_menu(&title, &items)? {
        BoxedMenuResult::Selected(i) if i < len => Ok(MenuResult::Selected(&cat.tools[i])),
        BoxedMenuResult::Selected(i) if i == len => Ok(MenuResult::Home),
        BoxedMenuResult::Selected(i) if i == len + 1 => Ok(MenuResult::Back),
        BoxedMenuResult::Selected(_) => Ok(MenuResult::Exit),
        BoxedMenuResult::Home => Ok(MenuResult::Home),
        BoxedMenuResult::Back => Ok(MenuResult::Back),
        BoxedMenuResult::Exit => Ok(MenuResult::Exit),
        _ => Ok(MenuResult::Back),
    }
}

// ── Mode menu ──────────────────────────────────────────────────────────────

pub fn mode_menu(tool: &'static Tool) -> Result<MenuResult<&'static Mode>> {
    println!();
    let title = format!("  {}  -  Select Mode  ", tool.name);
    let mut items: Vec<String> = tool.modes.iter().enumerate()
        .map(|(i, m)| format!(" [{}] {}", i + 1, m.name))
        .collect();
    items.push(" [#] Home".to_string());
    items.push(" [<] Back".to_string());
    items.push(" [x] Exit".to_string());

    let len = tool.modes.len();
    match run_boxed_menu(&title, &items)? {
        BoxedMenuResult::Selected(i) if i < len => Ok(MenuResult::Selected(&tool.modes[i])),
        BoxedMenuResult::TimeoutOverride(i) if i < len => Ok(MenuResult::TimeoutOverride(&tool.modes[i])),
        BoxedMenuResult::Selected(i) if i == len => Ok(MenuResult::Home),
        BoxedMenuResult::Selected(i) if i == len + 1 => Ok(MenuResult::Back),
        BoxedMenuResult::Selected(_) => Ok(MenuResult::Exit),
        BoxedMenuResult::Home => Ok(MenuResult::Home),
        BoxedMenuResult::Back => Ok(MenuResult::Back),
        BoxedMenuResult::Exit => Ok(MenuResult::Exit),
        _ => Ok(MenuResult::Back),
    }
}

// ── Outputs menu ───────────────────────────────────────────────────────────

pub fn outputs_menu(config: &Config) -> Result<MenuResult<()>> {
    loop {
        println!();
        let files = collect_output_files(config.output_dir());

        if files.is_empty() {
            print_info("No output files found yet.");
            cprintln(grey(), "  Run a tool first to generate output.");
            wait_key();
            return Ok(MenuResult::Back);
        }

        let mut items: Vec<String> = files
            .iter().enumerate()
            .map(|(i, (name, size, age))| {
                format!(" [{}] {:<45} {:>8}  {}", i + 1, name, size, age)
            })
            .collect();
        items.push(" [#] Home".to_string());
        items.push(" [<] Back".to_string());
        items.push(" [x] Exit".to_string());

        let len = files.len();
        match run_boxed_menu("  Outputs  -  Browse & Manage  ", &items)? {
            BoxedMenuResult::Selected(i) if i < len => {
                let path = format!("{}/{}", config.output_dir(), files[i].0);
                match file_action_menu(&path)? {
                    MenuResult::Home => return Ok(MenuResult::Home),
                    MenuResult::Exit => return Ok(MenuResult::Exit),
                    _ => continue,
                }
            }
            BoxedMenuResult::Selected(i) if i == len => return Ok(MenuResult::Home),
            BoxedMenuResult::Selected(i) if i == len + 1 => return Ok(MenuResult::Back),
            BoxedMenuResult::Selected(_) => return Ok(MenuResult::Exit),
            BoxedMenuResult::Home => return Ok(MenuResult::Home),
            BoxedMenuResult::Back => return Ok(MenuResult::Back),
            BoxedMenuResult::Exit => return Ok(MenuResult::Exit),
            _ => return Ok(MenuResult::Back),
        }
    }
}

fn collect_output_files(dir: &str) -> Vec<(String, String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else { return vec![]; };
    let mut files: Vec<(String, u64, std::time::SystemTime)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            if !meta.is_file() { return None; }
            Some((e.file_name().to_string_lossy().into_owned(), meta.len(), meta.modified().ok()?))
        }).collect();
    files.sort_by(|a, b| b.2.cmp(&a.2));
    files.into_iter().map(|(n, s, m)| (n, human_size(s), human_age(m))).collect()
}

fn human_size(b: u64) -> String {
    if b < 1024 { format!("{} B", b) }
    else if b < 1_048_576 { format!("{:.1} KB", b as f64 / 1024.0) }
    else { format!("{:.1} MB", b as f64 / 1_048_576.0) }
}

fn human_age(mtime: std::time::SystemTime) -> String {
    let Ok(d) = std::time::SystemTime::now().duration_since(mtime) else { return "now".into(); };
    let s = d.as_secs();
    if s < 60 { "now".into() }
    else if s < 3600   { format!("{}m ago", s / 60) }
    else if s < 86400  { format!("{}h ago", s / 3600) }
    else               { format!("{}d ago", s / 86400) }
}

fn file_action_menu(path: &str) -> Result<MenuResult<()>> {
    println!();
    let fname = std::path::Path::new(path)
        .file_name().unwrap_or_default()
        .to_string_lossy().into_owned();

    let actions = vec![
        " [O] View Output".to_string(),
        " [E] Edit".to_string(),
        " [D] Delete file".to_string(),
        " [#] Home".to_string(),
        " [<] Back".to_string(),
        " [x] Exit".to_string(),
    ];

    match run_boxed_menu("  File Action  ", &actions)? {
        BoxedMenuResult::Selected(0) => { crate::ui::output_viewer::view_file(path)?; Ok(MenuResult::Selected(())) }
        BoxedMenuResult::Selected(1) => { let _ = std::process::Command::new("nano").arg(path).status(); Ok(MenuResult::Selected(())) }
        BoxedMenuResult::Selected(2) => {
            if Confirm::with_theme(&hacker_theme())
                .with_prompt(format!("Delete '{}'?", fname))
                .default(false).interact()?
            {
                std::fs::remove_file(path)?;
                print_success(&format!("Deleted: {}", fname));
                wait_key();
            }
            Ok(MenuResult::Selected(()))
        }
        BoxedMenuResult::Selected(3) => Ok(MenuResult::Home),
        BoxedMenuResult::Selected(4) => Ok(MenuResult::Back),
        BoxedMenuResult::Selected(5) => Ok(MenuResult::Exit),
        BoxedMenuResult::Home => Ok(MenuResult::Home),
        BoxedMenuResult::Back => Ok(MenuResult::Back),
        BoxedMenuResult::Exit => Ok(MenuResult::Exit),
        _ => Ok(MenuResult::Back)
    }
}

// ── Settings menu ──────────────────────────────────────────────────────────

pub fn settings_menu(config: &Config) -> Result<Option<Config>> {
    println!();
    section_header("Settings");

    let api_shodan = if config.api_keys.shodan.is_empty()    { "not set" } else { "set [OK]" };
    let api_github = if config.api_keys.github.is_empty()    { "not set" } else { "set [OK]" };
    let api_censys = if config.api_keys.censys_id.is_empty() { "not set" } else { "set [OK]" };
    let anon_status = if config.anonymity.enabled { "ON" } else { "OFF" };

    let current = [
        format!("Output dir    : {}", config.general.output_dir),
        format!("Log dir       : {}", config.general.log_dir),
        format!("Timeout       : {}s",  config.general.timeout_secs),
        format!("Preview lines : {}",   config.general.preview_lines),
        format!("Shodan API    : {}",   api_shodan),
        format!("GitHub token  : {}",   api_github),
        format!("Censys        : {}",   api_censys),
        format!("Anonymity     : {}",   anon_status),
    ];
    let refs: Vec<&str> = current.iter().map(String::as_str).collect();
    print_box("Current Settings", &refs);
    println!();

    // Settings sub-menu
    let items = vec![
        " [1] General Settings".to_string(),
        " [2] API Keys".to_string(),
        " [3] Anonymity Settings".to_string(),
        " [<] Back".to_string(),
    ];

    match run_boxed_menu("  Settings  -  Select Section  ", &items)? {
        BoxedMenuResult::Selected(0) => general_settings_menu(config),
        BoxedMenuResult::Selected(1) => api_keys_menu(config),
        BoxedMenuResult::Selected(2) => anonymity_settings_menu(config),
        _ => Ok(None),
    }
}

fn general_settings_menu(config: &Config) -> Result<Option<Config>> {
    let theme = hacker_theme();
    let mut new = config.clone();

    new.general.timeout_secs  = Input::with_theme(&theme).with_prompt("Timeout (seconds)").default(config.general.timeout_secs).interact_text()?;
    new.general.preview_lines = Input::with_theme(&theme).with_prompt("Preview lines").default(config.general.preview_lines).interact_text()?;
    new.general.output_dir    = Input::with_theme(&theme).with_prompt("Output directory").default(config.general.output_dir.clone()).interact_text()?;

    if Confirm::with_theme(&theme).with_prompt("Save settings?").default(true).interact()? {
        new.save()?;
        print_success("Settings saved to /opt/tsec/config/config.toml");
        wait_key();
        Ok(Some(new))
    } else {
        Ok(None)
    }
}

fn api_keys_menu(config: &Config) -> Result<Option<Config>> {
    let theme = hacker_theme();
    let mut new = config.clone();

    new.api_keys.shodan        = Input::with_theme(&theme).with_prompt("Shodan API key").default(config.api_keys.shodan.clone()).allow_empty(true).interact_text()?;
    new.api_keys.github        = Input::with_theme(&theme).with_prompt("GitHub token").default(config.api_keys.github.clone()).allow_empty(true).interact_text()?;
    new.api_keys.censys_id     = Input::with_theme(&theme).with_prompt("Censys ID").default(config.api_keys.censys_id.clone()).allow_empty(true).interact_text()?;
    new.api_keys.censys_secret = Input::with_theme(&theme).with_prompt("Censys secret").default(config.api_keys.censys_secret.clone()).allow_empty(true).interact_text()?;

    if Confirm::with_theme(&theme).with_prompt("Save API keys?").default(true).interact()? {
        new.save()?;
        print_success("Settings saved to /opt/tsec/config/config.toml");
        wait_key();
        Ok(Some(new))
    } else {
        Ok(None)
    }
}

fn anonymity_settings_menu(config: &Config) -> Result<Option<Config>> {
    let theme = hacker_theme();
    let mut new = config.clone();
    let anon = &config.anonymity;

    // Show current anonymity status
    println!();
    let status_lines = [
        format!("Enabled          : {}", if anon.enabled { "ON" } else { "OFF" }),
        format!("Tor              : {}", if anon.tor_enabled { "ON" } else { "OFF" }),
        format!("Tor SOCKS addr   : {}", anon.tor_socks_addr),
        format!("Proxies          : {} configured", anon.proxy_pool.len()),
        format!("Proxy rotation   : {}s", anon.proxy_rotation_secs),
        format!("ProxyChains      : {}", if anon.use_proxychains { "ON" } else { "OFF" }),
        format!("Delay range      : {}ms - {}ms", anon.delay_min_ms, anon.delay_max_ms),
        format!("User-Agent rot.  : {}", if anon.user_agent_rotation { "ON" } else { "OFF" }),
        format!("DNS-over-HTTPS   : {}", if anon.dns_over_https { "ON" } else { "OFF" }),
        format!("Output sanitize  : {}", if anon.sanitize_output { "ON" } else { "OFF" }),
        format!("MAC spoofing     : {}", if anon.mac_spoofing { "ON" } else { "OFF" }),
        format!("Hostname spoof   : {}", if anon.hostname_spoofing { "ON" } else { "OFF" }),
        format!("Kill switch      : {}", if anon.kill_switch { "ON" } else { "OFF" }),
    ];
    let refs: Vec<&str> = status_lines.iter().map(String::as_str).collect();
    print_box("Anonymity Status", &refs);
    println!();

    // Toggle prompts
    new.anonymity.enabled = Confirm::with_theme(&theme)
        .with_prompt("Enable anonymity?")
        .default(anon.enabled)
        .interact()?;

    if new.anonymity.enabled {
        new.anonymity.tor_enabled = Confirm::with_theme(&theme)
            .with_prompt("Enable Tor routing?")
            .default(anon.tor_enabled)
            .interact()?;

        if new.anonymity.tor_enabled {
            new.anonymity.tor_socks_addr = Input::with_theme(&theme)
                .with_prompt("Tor SOCKS address")
                .default(anon.tor_socks_addr.clone())
                .interact_text()?;
        }

        new.anonymity.use_proxychains = Confirm::with_theme(&theme)
            .with_prompt("Use proxychains-ng?")
            .default(anon.use_proxychains)
            .interact()?;

        // Proxy pool management
        if Confirm::with_theme(&theme).with_prompt("Edit proxy pool?").default(false).interact()? {
            println!();
            if !anon.proxy_pool.is_empty() {
                cprintln(grey(), "  Current proxies:");
                for (i, p) in anon.proxy_pool.iter().enumerate() {
                    cprintln(grey(), &format!("    [{}] {}", i + 1, p));
                }
            } else {
                cprintln(grey(), "  No proxies configured.");
            }
            println!();

            // Clear and re-enter
            new.anonymity.proxy_pool = Vec::new();
            loop {
                let proxy: String = Input::with_theme(&theme)
                    .with_prompt("Add proxy (empty to finish)")
                    .allow_empty(true)
                    .interact_text()?;
                if proxy.trim().is_empty() {
                    break;
                }
                new.anonymity.proxy_pool.push(proxy.trim().to_string());
            }
        }

        new.anonymity.proxy_rotation_secs = Input::with_theme(&theme)
            .with_prompt("Proxy rotation interval (seconds, 0=off)")
            .default(anon.proxy_rotation_secs)
            .interact_text()?;

        if new.anonymity.tor_enabled {
            new.anonymity.tor_renewal_secs = Input::with_theme(&theme)
                .with_prompt("Tor circuit renewal interval (seconds, 0=off)")
                .default(anon.tor_renewal_secs)
                .interact_text()?;
        }

        new.anonymity.delay_min_ms = Input::with_theme(&theme)
            .with_prompt("Timing delay minimum (ms)")
            .default(anon.delay_min_ms)
            .interact_text()?;

        new.anonymity.delay_max_ms = Input::with_theme(&theme)
            .with_prompt("Timing delay maximum (ms)")
            .default(anon.delay_max_ms)
            .interact_text()?;

        new.anonymity.user_agent_rotation = Confirm::with_theme(&theme)
            .with_prompt("Enable User-Agent rotation?")
            .default(anon.user_agent_rotation)
            .interact()?;

        new.anonymity.dns_over_https = Confirm::with_theme(&theme)
            .with_prompt("Enable DNS-over-HTTPS?")
            .default(anon.dns_over_https)
            .interact()?;

        new.anonymity.sanitize_output = Confirm::with_theme(&theme)
            .with_prompt("Sanitize output (strip private IPs, MACs, etc.)?")
            .default(anon.sanitize_output)
            .interact()?;

        new.anonymity.mac_spoofing = Confirm::with_theme(&theme)
            .with_prompt("Enable MAC spoofing? (requires macchanger + root)")
            .default(anon.mac_spoofing)
            .interact()?;

        new.anonymity.hostname_spoofing = Confirm::with_theme(&theme)
            .with_prompt("Enable hostname spoofing?")
            .default(anon.hostname_spoofing)
            .interact()?;

        new.anonymity.kill_switch = Confirm::with_theme(&theme)
            .with_prompt("Enable kill switch? (blocks if anon layer is down)")
            .default(anon.kill_switch)
            .interact()?;
    }

    if Confirm::with_theme(&theme).with_prompt("Save anonymity settings?").default(true).interact()? {
        new.save()?;
        print_success("Anonymity settings saved to /opt/tsec/config/config.toml");
        wait_key();
        Ok(Some(new))
    } else {
        Ok(None)
    }
}

