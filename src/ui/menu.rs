// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal,
};
use dialoguer::Input;
use unicode_width::UnicodeWidthStr;

use crate::catalog::{phase_label, Capability, Catalog};
use crate::config::Config;
use crate::domain::ids::{RunId, TaskId};
use crate::domain::input::InputValues;
use crate::domain::plan::RawArtifact;
use crate::error::{Result, TsecError};
use crate::exec::oniux::OniuxBackend;
use crate::exec::{Cancellation, Launcher, Runner, RunnerConfig, TaskSpec};
use crate::provider::Registry;
use crate::store::RunStore;
use crate::ui::output::display_harvest;
use crate::ui::spinner::Spinner;
use crate::ui::theme::{Role, Theme};

fn pad_to(s: &str, target_cols: usize) -> String {
    let w = UnicodeWidthStr::width(s);
    if w >= target_cols {
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
        let cur_w = UnicodeWidthStr::width(out.as_str());
        if cur_w < target_cols {
            out.push_str(&" ".repeat(target_cols - cur_w));
        }
        out
    } else {
        format!("{}{}", s, " ".repeat(target_cols - w))
    }
}

fn terminal_width() -> usize {
    terminal::size().map(|(w, _)| w as usize).unwrap_or(80)
}

pub fn wait_key() -> Result<()> {
    terminal::enable_raw_mode()?;
    loop {
        if crossterm::event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    break;
                }
            }
        }
    }
    terminal::disable_raw_mode()?;
    Ok(())
}

struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        let _ = execute!(stdout, cursor::Hide);
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let mut stdout = io::stdout();
        let _ = execute!(stdout, cursor::Show);
        let _ = terminal::disable_raw_mode();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxedMenuResult {
    Selected(usize),
    Back,
    Home,
    Exit,
}

pub fn run_boxed_menu(title: &str, items: &[String]) -> Result<BoxedMenuResult> {
    let _guard = RawModeGuard::enter()?;
    let mut stdout = io::stdout();

    let term_cols = terminal_width();
    let inner = term_cols.saturating_sub(2).max(40);

    let top = format!("╔{}╗", "═".repeat(inner));
    let mid = format!("╠{}╣", "═".repeat(inner));
    let bot = format!("╚{}╝", "═".repeat(inner));

    let title_dw = UnicodeWidthStr::width(title);
    let (lpad, rpad) = if title_dw < inner {
        let total = inner - title_dw;
        (total / 2, total - total / 2)
    } else {
        (0, 0)
    };
    let title_row = format!("║{}{}{}║", " ".repeat(lpad), pad_to(title, title_dw.min(inner)), " ".repeat(rpad));
    let text_cols = inner.saturating_sub(4);

    let mut selected = 0usize;
    let max_visible = 18usize;
    let mut prev_rows = 0u16;

    let mut digit_buf = String::new();
    let mut digit_last = Instant::now();

    loop {
        let visible = items.len().min(max_visible);
        let start = if selected >= max_visible {
            selected - max_visible + 1
        } else {
            0
        };
        let end = start + visible;

        let frame_rows = (3 + visible + 1) as u16;
        if prev_rows > 0 {
            let _ = queue!(stdout, cursor::MoveUp(prev_rows), cursor::MoveToColumn(0));
        }
        prev_rows = frame_rows;

        let _ = queue!(
            stdout,
            SetForegroundColor(Color::Rgb { r: 126, g: 214, b: 223 }),
            Print(&top),
            Print("\r\n"),
            Print(&title_row),
            Print("\r\n"),
            Print(&mid),
            Print("\r\n")
        );

        for (offset, item) in items[start..end].iter().enumerate() {
            let i = start + offset;
            let item_text = pad_to(item, text_cols);
            if i == selected {
                let _ = queue!(
                    stdout,
                    SetForegroundColor(Color::Cyan),
                    SetAttribute(Attribute::Bold),
                    Print("║ > "),
                    Print(&item_text),
                    Print(" ║"),
                    SetAttribute(Attribute::Reset),
                    Print("\r\n")
                );
            } else {
                let _ = queue!(
                    stdout,
                    SetForegroundColor(Color::Rgb { r: 64, g: 92, b: 108 }),
                    Print("║   "),
                    SetForegroundColor(Color::Rgb { r: 214, g: 222, b: 230 }),
                    Print(&item_text),
                    SetForegroundColor(Color::Rgb { r: 64, g: 92, b: 108 }),
                    Print(" ║\r\n")
                );
            }
        }

        let _ = queue!(
            stdout,
            SetForegroundColor(Color::Rgb { r: 126, g: 214, b: 223 }),
            Print(&bot),
            Print("\r\n"),
            ResetColor
        );
        let _ = stdout.flush();

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
                    match key.code {
                        KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('i') | KeyCode::Char('K') | KeyCode::Char('I') => {
                            selected = selected.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => {
                            if selected + 1 < items.len() {
                                selected += 1;
                            }
                        }
                        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('L') => {
                            return Ok(BoxedMenuResult::Selected(selected));
                        }
                        KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('H') => {
                            return Ok(BoxedMenuResult::Back);
                        }
                        KeyCode::Char('q') | KeyCode::Char('Q') => {
                            return Ok(BoxedMenuResult::Exit);
                        }
                        KeyCode::Home => {
                            return Ok(BoxedMenuResult::Home);
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            if digit_last.elapsed() > Duration::from_millis(700) {
                                digit_buf.clear();
                            }
                            digit_buf.push(c);
                            digit_last = Instant::now();
                            if let Ok(num) = digit_buf.parse::<usize>() {
                                if num >= 1 && num <= items.len() {
                                    selected = num - 1;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

pub fn main_menu(cfg: &Config, catalog: &Catalog, registry: &Registry) -> Result<()> {
    let theme = Theme::detect(cfg.general.color);

    loop {
        println!();
        let title = "  TSEC 3.0  -  Tactical Operations Console  ";

        let phase_display_names = [
            ("recon", "01. RECONNAISSANCE"),
            ("surface", "02. ATTACK SURFACE"),
            ("vulnerability", "03. VULNERABILITY"),
            ("payload", "04. WEAPONIZATION & PAYLOAD"),
            ("escalation", "05. PRIVILEGE ESCALATION"),
            ("credentials", "06. CREDENTIAL ACCESS"),
            ("lateral", "07. LATERAL MOVEMENT"),
            ("persistence", "08. PERSISTENCE"),
            ("objectives", "09. OBJECTIVES & EXFILTRATION"),
            ("wireless", "10. WIRELESS & RF"),
        ];

        let mut items = Vec::new();
        for (i, (slug, name)) in phase_display_names.iter().enumerate() {
            let caps = catalog.in_phase(slug);
            let available = caps.iter().filter(|c| c.is_available(registry)).count();
            items.push(format!("[{:>2}] {:<32} ({}/{} ready)", i + 1, name, available, caps.len()));
        }

        let status_idx = items.len();
        items.push(" [S] Status & Network Boundary".to_string());
        let outputs_idx = items.len();
        items.push(" [O] Outputs & Harvest Evidence".to_string());
        let exit_idx = items.len();
        items.push(" [X] Exit".to_string());

        match run_boxed_menu(title, &items)? {
            BoxedMenuResult::Selected(i) if i < 10 => {
                let slug = phase_display_names[i].0;
                phase_menu(cfg, catalog, registry, slug)?;
            }
            BoxedMenuResult::Selected(i) if i == status_idx => {
                status_menu(cfg, catalog, registry)?;
            }
            BoxedMenuResult::Selected(i) if i == outputs_idx => {
                outputs_menu(cfg)?;
            }
            BoxedMenuResult::Selected(i) if i == exit_idx => {
                println!("{}", theme.paint(Role::Muted, "\nExiting TSEC."));
                break;
            }
            BoxedMenuResult::Exit | BoxedMenuResult::Back => {
                println!("{}", theme.paint(Role::Muted, "\nExiting TSEC."));
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

fn phase_menu(
    cfg: &Config,
    catalog: &Catalog,
    registry: &Registry,
    phase: &str,
) -> Result<()> {
    let phase_title = phase_label(phase).unwrap_or(phase);

    loop {
        println!();
        let caps = catalog.in_phase(phase);
        if caps.is_empty() {
            println!("  No capabilities defined for phase {} yet.", phase_title);
            println!("  Press Enter to return...");
            let _ = wait_key();
            return Ok(());
        }

        let title = format!("  PHASE: {}  -  Select Capability  ", phase_title);
        let mut items = Vec::new();
        for (i, cap) in caps.iter().enumerate() {
            let status = if cap.is_available(registry) {
                "[READY]"
            } else {
                "[UNAVAILABLE]"
            };
            items.push(format!("[{:>2}] {:<30} {}", i + 1, cap.label, status));
        }

        let back_idx = items.len();
        items.push(" [<] Back".to_string());
        let exit_idx = items.len();
        items.push(" [x] Exit".to_string());

        match run_boxed_menu(&title, &items)? {
            BoxedMenuResult::Selected(i) if i < caps.len() => {
                execute_capability(cfg, catalog, registry, caps[i])?;
            }
            BoxedMenuResult::Selected(i) if i == back_idx => return Ok(()),
            BoxedMenuResult::Selected(i) if i == exit_idx => return Ok(()),
            BoxedMenuResult::Back | BoxedMenuResult::Exit => return Ok(()),
            _ => {}
        }
    }
}

fn execute_capability(
    cfg: &Config,
    _catalog: &Catalog,
    registry: &Registry,
    cap: &Capability,
) -> Result<()> {
    let theme = Theme::detect(cfg.general.color);
    println!();
    println!("{}", theme.paint(Role::Accent, &format!("─── {} ───", cap.label)));
    println!("{}", theme.paint(Role::Muted, &format!("Summary: {}", cap.summary)));
    println!();

    if let Some(reason) = cap.unavailable_reason(registry) {
        println!("{}", theme.paint(Role::Error, &format!("[-] Capability unavailable: {}", reason)));
        println!("{}", theme.paint(Role::Muted, "Please install the missing tools to use this capability."));
        println!();
        println!("Press Enter to return...");
        let _ = wait_key();
        return Ok(());
    }

    let mut values = InputValues::new();
    for spec in &cap.inputs {
        let mut prompt = Input::<String>::new();
        let prompt_text = format!("{} [{}]", spec.label, spec.ty.label());
        prompt = prompt.with_prompt(&prompt_text);
        if let Some(def) = &spec.default {
            prompt = prompt.default(def.to_string());
        }
        prompt = prompt.allow_empty(!spec.required);
        let raw = prompt.interact_text().map_err(|e| TsecError::internal(e.to_string()))?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            if spec.required {
                println!("{}", theme.paint(Role::Error, &format!("Input `{}` is required.", spec.key)));
                let _ = wait_key();
                return Ok(());
            }
        } else {
            let validated = spec.validate(trimmed)?;
            values.insert(&*spec.key, validated);
        }
    }

    println!();
    println!("{}", theme.paint(Role::Info, "[*] Building execution plan..."));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| TsecError::internal(format!("creating tokio runtime: {e}")))?;

    let run_id = RunId::now();
    let mut store = RunStore::open(&cfg.general.output_dir, &run_id)?;

    let launcher = Launcher::new(OniuxBackend::new(&cfg.execution.oniux_binary));
    let runner_cfg = RunnerConfig {
        kill_grace: Duration::from_millis(cfg.execution.kill_grace_ms),
        env: Vec::new(),
        cwd: None,
    };
    let runner = Runner::new(launcher, runner_cfg);
    let cancel = Cancellation::new();

    let mut task_idx = 0usize;
    let mut formats = std::collections::BTreeMap::new();

    for p in &cap.providers {
        let prog = match registry.get(&p.binary) {
            Some(pv) => match pv.resolve() {
                Some(path) => path,
                None => continue,
            },
            None => match crate::provider::find_in_path(&p.binary) {
                Some(path) => path,
                None => continue,
            },
        };

        for op in &p.operations {
            formats.insert(format!("{}/{}", p.binary, op.name), op.output);
            let cmd = op.command(&prog, &cap.inputs, &values)?;

            let safe_stem = format!("{:02}_{}_{}", task_idx + 1, p.binary, op.name.replace(' ', "_").to_lowercase());
            let raw_out = store.raw_stdout(&safe_stem);
            let raw_err = store.raw_stderr(&safe_stem);

            let spec = TaskSpec {
                id: TaskId(task_idx),
                provider: p.binary.clone(),
                operation: op.name.clone(),
                label: format!("{} ({})", op.name, p.binary),
                timeout: Duration::from_secs(cfg.execution.timeout_secs),
                artifacts: RawArtifact {
                    primary: raw_out,
                    stderr: raw_err,
                },
                sensitive_args: cmd.sensitive_args().to_vec(),
            };

            let spinner = Spinner::start(&format!("Running {} · {}...", cap.label, op.name));
            let completed = rt.block_on(runner.run(&spec, &cmd, &cap.phase, &cap.label, &cancel));
            spinner.stop();

            store.commit(completed.record)?;
            task_idx += 1;
        }
    }

    if task_idx == 0 {
        println!("{}", theme.paint(Role::Warning, "[!] No tasks were executed."));
        println!("Press Enter to return...");
        let _ = wait_key();
        return Ok(());
    }

    let outcome = store.harvest(&formats)?;
    display_harvest(&theme, &outcome, store.root(), cfg.general.preview_lines);

    println!("Press Enter to return to menu...");
    let _ = wait_key();
    Ok(())
}

fn status_menu(cfg: &Config, catalog: &Catalog, registry: &Registry) -> Result<()> {
    let theme = Theme::detect(cfg.general.color);
    println!();
    println!("{}", theme.paint(Role::Accent, "╔══════════════════════════════════════════════════════════════════════════════╗"));
    println!("{}", theme.paint(Role::Accent, "║                      TSEC 3.0 SYSTEM STATUS & BOUNDARY                       ║"));
    println!("{}", theme.paint(Role::Accent, "╚══════════════════════════════════════════════════════════════════════════════╝"));
    println!();
    println!("  Theme:   {}", theme.describe());
    println!("  Version: {}", crate::VERSION);
    println!();

    println!("  {}", theme.paint(Role::Primary, "Network Execution Boundary:"));
    let backend = OniuxBackend::new(&cfg.execution.oniux_binary);
    match backend.resolve() {
        Ok(path) => println!("    Status:   {} ({})", theme.paint(Role::Success, "RESOLVED"), path.display()),
        Err(e) => println!("    Status:   {} ({})", theme.paint(Role::Error, "UNAVAILABLE"), e.reason()),
    }
    println!();

    println!("  {}", theme.paint(Role::Primary, "Capability Availability:"));
    println!("    {}", catalog.availability_summary(registry));
    println!();

    for (slug, caps) in catalog.grouped() {
        let ready = caps.iter().filter(|c| c.is_available(registry)).count();
        let display_name = phase_label(slug).unwrap_or(slug);
        println!("    {:<16} {}/{} ready", display_name, ready, caps.len());
    }

    println!();
    println!("Press Enter to return...");
    let _ = wait_key();
    Ok(())
}

fn outputs_menu(cfg: &Config) -> Result<()> {
    let theme = Theme::detect(cfg.general.color);
    let out_dir = &cfg.general.output_dir;

    loop {
        println!();
        let entries = match std::fs::read_dir(out_dir) {
            Ok(e) => e,
            Err(_) => {
                println!("{}", theme.paint(Role::Muted, "  Output directory does not exist or is empty."));
                println!("Press Enter to return...");
                let _ = wait_key();
                return Ok(());
            }
        };

        let mut runs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.join("harvest.txt").exists())
            .collect();

        runs.sort_by(|a, b| b.cmp(a));

        if runs.is_empty() {
            println!("{}", theme.paint(Role::Muted, "  No run harvest directories found in output."));
            println!("Press Enter to return...");
            let _ = wait_key();
            return Ok(());
        }

        let mut items = Vec::new();
        for (i, r) in runs.iter().enumerate() {
            let name = r.file_name().and_then(|n| n.to_str()).unwrap_or("run");
            items.push(format!("[{:>2}] {}", i + 1, name));
        }
        let back_idx = items.len();
        items.push(" [<] Back".to_string());

        match run_boxed_menu("  Harvest Artifacts & Saved Evidence  ", &items)? {
            BoxedMenuResult::Selected(i) if i < runs.len() => {
                let harvest_path = runs[i].join("harvest.txt");
                if let Ok(content) = std::fs::read_to_string(&harvest_path) {
                    println!();
                    println!("{}", theme.paint(Role::Accent, &format!("─── {} ───", harvest_path.display())));
                    for line in content.lines().take(40) {
                        println!("  {}", line);
                    }
                    if content.lines().count() > 40 {
                        println!("{}", theme.paint(Role::Muted, &format!("  ... ({} lines total)", content.lines().count())));
                    }
                    println!();
                    println!("Press Enter to return...");
                    let _ = wait_key();
                }
            }
            BoxedMenuResult::Selected(i) if i == back_idx => return Ok(()),
            _ => return Ok(()),
        }
    }
}
