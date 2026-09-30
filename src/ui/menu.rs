//! The interactive surface: boxed menus and the capability run flow.
//!
//! Every screen is one centred box. A box holds a one-word title and the choices
//! that belong to it — never numbering, breadcrumbs or status badges. The keys
//! are fixed and identical everywhere: `I` up, `K` down, `J` back, `L` select,
//! Enter to select, Esc to close, Ctrl+C to leave cleanly. A capability whose
//! providers are missing stays visible but cannot be chosen, and says why.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossterm::event::KeyCode;
use dialoguer::Input;

use crate::catalog::{phase_label, Capability, Catalog, OutputFormat, PHASES};
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
use crate::ui::panel::{self, Geometry, RawMode};
use crate::ui::spinner::Spinner;
use crate::ui::theme::{Role, Theme};

/// One choice in a box.
#[derive(Debug, Clone)]
struct Item {
    label: String,
    /// `Some(reason)` when the row exists but cannot be chosen.
    blocked: Option<String>,
}

impl Item {
    fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            blocked: None,
        }
    }

    fn blocked_by(label: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            blocked: Some(reason.into()),
        }
    }
}

/// What the operator decided on a screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Chosen(usize),
    Back,
    Exit,
}

/// Enter the framework's top level: the ten phases, then status and outputs.
pub fn main_menu(cfg: &Config, catalog: &Catalog, registry: &Registry) -> Result<()> {
    let theme = Theme::detect(cfg.general.color);

    loop {
        let mut items: Vec<Item> = PHASES
            .iter()
            .map(|phase| Item::new(phase_label(phase).unwrap_or(phase)))
            .collect();
        let status_row = items.len();
        items.push(Item::new("STATUS"));
        let outputs_row = items.len();
        items.push(Item::new("OUTPUTS"));

        match menu(&theme, "TSEC", &items, true)? {
            Decision::Chosen(index) if index < PHASES.len() => {
                phase_menu(&theme, cfg, catalog, registry, PHASES[index])?;
            }
            Decision::Chosen(index) if index == status_row => status_screen(&theme, cfg, catalog)?,
            Decision::Chosen(index) if index == outputs_row => outputs_screen(&theme, cfg)?,
            _ => return Ok(()),
        }
    }
}

/// One phase's capabilities, drawn as a box titled with the phase name.
fn phase_menu(
    theme: &Theme,
    cfg: &Config,
    catalog: &Catalog,
    registry: &Registry,
    phase: &str,
) -> Result<()> {
    let title = phase_label(phase).unwrap_or(phase);

    loop {
        let caps = catalog.in_phase(phase);
        if caps.is_empty() {
            return show_notice(
                theme,
                title,
                &[("no capabilities in this phase".to_string(), Role::Muted)],
            );
        }

        let items: Vec<Item> = caps
            .iter()
            .map(|cap| match cap.unavailable_reason() {
                Some(reason) => Item::blocked_by(cap.label.clone(), reason),
                None => Item::new(cap.label.clone()),
            })
            .collect();

        match menu(theme, title, &items, false)? {
            Decision::Chosen(index) => run_capability(cfg, registry, caps[index])?,
            _ => return Ok(()),
        }
    }
}

/// Draw a boxed menu and read keys until the operator decides.
///
/// Rows that cannot be chosen are skipped by the cursor and explained when the
/// cursor lands on one, so a missing tool is visible rather than hidden.
fn menu(theme: &Theme, title: &str, items: &[Item], root: bool) -> Result<Decision> {
    let _raw = RawMode::enter()?;
    let mut out = io::stdout();
    let mut selected = items.iter().position(|i| i.blocked.is_none()).unwrap_or(0);
    let mut top = 0usize;
    let mut drawn: Option<panel::Drawn> = None;

    loop {
        let visible = items.len().min(Geometry::detect().body_rows(8));
        if selected < top {
            top = selected;
        } else if selected >= top + visible {
            top = selected + 1 - visible;
        }
        let end = (top + visible).min(items.len());

        let mut rows: Vec<(String, Role)> = Vec::new();
        for (index, item) in items.iter().enumerate().take(end).skip(top) {
            let marker = if index == selected { '>' } else { ' ' };
            let role = match (index == selected, item.blocked.is_some()) {
                (_, true) => Role::Muted,
                (true, false) => Role::Highlight,
                (false, false) => Role::Foreground,
            };
            rows.push((format!("{marker} {}", item.label), role));
        }
        if items.len() > visible {
            rows.push((format!("{} of {}", selected + 1, items.len()), Role::Muted));
        }
        if let Some(reason) = items.get(selected).and_then(|item| item.blocked.clone()) {
            rows.push((reason, Role::Warning));
        }

        if let Some(previous) = drawn {
            panel::erase(&mut out, previous)?;
        }
        drawn = Some(panel::draw(&mut out, theme, title, &rows, true)?);

        let key = panel::next_key()?;
        if panel::is_interrupt(&key) {
            return Ok(Decision::Exit);
        }

        match key.code {
            KeyCode::Char('i') | KeyCode::Char('I') | KeyCode::Up => {
                selected = step(items, selected, false);
            }
            KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Down => {
                selected = step(items, selected, true);
            }
            KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Left => {
                return Ok(back_or_exit(root))
            }
            KeyCode::Char('l')
            | KeyCode::Char('L')
            | KeyCode::Enter
            | KeyCode::Right
            | KeyCode::Char(' ') => {
                if items.get(selected).is_some_and(|i| i.blocked.is_none()) {
                    return Ok(Decision::Chosen(selected));
                }
            }
            KeyCode::Esc => return Ok(back_or_exit(root)),
            _ => {}
        }
    }
}

/// `J`/Esc close the current box; at the top level closing means leaving.
fn back_or_exit(root: bool) -> Decision {
    if root {
        Decision::Exit
    } else {
        Decision::Back
    }
}

/// Move the cursor, skipping rows that cannot be chosen.
fn step(items: &[Item], from: usize, forward: bool) -> usize {
    let len = items.len();
    if len == 0 {
        return 0;
    }
    let mut index = from;
    for _ in 0..len {
        index = if forward {
            (index + 1) % len
        } else if index == 0 {
            len - 1
        } else {
            index - 1
        };
        if items[index].blocked.is_none() {
            return index;
        }
    }
    from
}

/// Show a still box, then wait for the operator to close it.
fn show_notice(theme: &Theme, title: &str, rows: &[(String, Role)]) -> Result<()> {
    let _raw = RawMode::enter()?;
    let mut out = io::stdout();
    panel::draw(&mut out, theme, title, rows, true)?;
    panel::wait_close()?;
    Ok(())
}

/// The status box: version, theme, network boundary and live availability.
fn status_screen(theme: &Theme, cfg: &Config, catalog: &Catalog) -> Result<()> {
    let boundary = match OniuxBackend::new(&cfg.execution.oniux_binary).resolve() {
        Ok(path) => path.display().to_string(),
        Err(e) => format!("unavailable · {}", e.reason()),
    };
    let available = catalog
        .capabilities()
        .iter()
        .filter(|cap| cap.is_available())
        .count();

    let mut rows: Vec<(String, Role)> = vec![
        (pair("VERSION", crate::VERSION), Role::Foreground),
        (pair("THEME", &theme.describe()), Role::Foreground),
        (pair("BOUNDARY", &boundary), Role::Accent),
        (
            pair(
                "CATALOG",
                &format!("{available}/{}", catalog.capabilities().len()),
            ),
            Role::Foreground,
        ),
    ];
    for (label, caps) in catalog.grouped() {
        let ready = caps.iter().filter(|cap| cap.is_available()).count();
        rows.push((pair(label, &format!("{ready}/{}", caps.len())), Role::Muted));
    }
    rows.push((String::new(), Role::Muted));
    rows.push((catalog.source().display().to_string(), Role::Secondary));

    show_notice(theme, "STATUS", &rows)
}

/// `KEY` in a fixed column, so the box stays legible without a table.
fn pair(key: &str, value: &str) -> String {
    format!("{key:<14}{value}")
}

/// Previous runs that left a harvest behind, newest first.
fn recorded_runs(output_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(output_dir) else {
        return Vec::new();
    };
    let mut runs: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && path.join("harvest.txt").exists())
        .collect();
    runs.sort_by(|a, b| b.cmp(a));
    runs
}

/// Pick a past run and read its harvest back.
fn outputs_screen(theme: &Theme, cfg: &Config) -> Result<()> {
    loop {
        let runs = recorded_runs(&cfg.general.output_dir);
        if runs.is_empty() {
            return show_notice(
                theme,
                "OUTPUTS",
                &[("no runs recorded".to_string(), Role::Muted)],
            );
        }

        let items: Vec<Item> = runs
            .iter()
            .map(|run| {
                Item::new(
                    run.file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_else(|| run.display().to_string()),
                )
            })
            .collect();

        match menu(theme, "OUTPUTS", &items, false)? {
            Decision::Chosen(index) => view_harvest(theme, &runs[index])?,
            _ => return Ok(()),
        }
    }
}

/// Read one run's consolidated harvest back into a box.
fn view_harvest(theme: &Theme, dir: &Path) -> Result<()> {
    let path = dir.join("harvest.txt");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| TsecError::io(format!("reading {}", path.display()), &e))?;

    let limit = Geometry::detect().body_rows(8);
    let mut rows: Vec<(String, Role)> = text
        .lines()
        .take(limit)
        .map(|line| (line.to_string(), Role::Foreground))
        .collect();
    if rows.is_empty() {
        rows.push(("empty harvest".to_string(), Role::Muted));
    }
    let total = text.lines().count();
    if total > rows.len() {
        rows.push((
            format!("{} more lines in harvest.txt", total - rows.len()),
            Role::Muted,
        ));
    }

    show_notice(theme, "OUTPUTS", &rows)
}

/// The operator's answers for one capability.
enum Answers {
    Given(InputValues),
    Cancelled,
    Incomplete(String),
}

/// Ask for every declared input, validating each against its declared type.
fn collect_inputs(cap: &Capability) -> Result<Answers> {
    let mut values = InputValues::new();

    for spec in &cap.inputs {
        let prompt = format!("{} [{}]", spec.label.to_uppercase(), spec.ty.label());
        let mut input = Input::<String>::new()
            .with_prompt(prompt)
            .allow_empty(false);
        if let Some(default) = &spec.default {
            input = input.default(default.to_string());
        }

        // A prompt the operator walks away from is an answer too: it withdraws
        // the capability rather than running it with a half-filled target.
        let Ok(raw) = input.interact_text() else {
            return Ok(Answers::Cancelled);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            if spec.required {
                return Ok(Answers::Incomplete(spec.key.to_string()));
            }
            continue;
        }
        values.insert(&*spec.key, spec.validate(trimmed)?);
    }

    Ok(Answers::Given(values))
}

/// Locate a provider binary, preferring the resolved registry entry.
fn resolve_program(registry: &Registry, binary: &str) -> Option<PathBuf> {
    registry
        .get(binary)
        .and_then(|provider| provider.path.clone())
        .or_else(|| crate::provider::find_in_path(binary))
}

/// `YYYYMMDD_HHMMSS_PHASE_CAPABILITY_PROVIDER_OPERATION`, lowercased and safe.
fn artifact_stem(run: &RunId, cap: &Capability, provider: &str, operation: &str) -> String {
    let clean = |value: &str| -> String {
        value
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect()
    };
    format!(
        "{}_{}_{}_{}_{}",
        run.stamp(),
        clean(&cap.phase),
        clean(&cap.label),
        clean(provider),
        clean(operation)
    )
}

/// One provider operation, ready to run.
struct Job {
    index: usize,
    spec: TaskSpec,
    command: crate::domain::command::Command,
}

/// Execute every job, at most `execution.max_concurrency` at a time.
///
/// Concurrency is bounded by a semaphore rather than by chunking the list, so a
/// slow tool never holds back a fast one and the whole capability finishes as
/// soon as its last operation does. Results come back unordered and are sorted
/// by the caller; a task that was interrupted still returns its record, because
/// partial evidence is evidence.
fn run_jobs(
    runtime: &tokio::runtime::Runtime,
    runner: Runner,
    jobs: Vec<Job>,
    phase: &str,
    capability: &str,
    cancel: &Cancellation,
    cfg: &Config,
) -> Vec<(usize, crate::domain::execution::ExecutionRecord)> {
    let permits = Arc::new(tokio::sync::Semaphore::new(
        cfg.execution.max_concurrency.max(1),
    ));
    let runner = Arc::new(runner);

    runtime.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for job in jobs {
            let runner = runner.clone();
            let permits = permits.clone();
            let cancel = cancel.clone();
            let phase = phase.to_string();
            let capability = capability.to_string();
            set.spawn(async move {
                // The semaphore is never closed, so this cannot fail; the permit
                // lives until the task returns.
                let _permit = permits.acquire_owned().await;
                let completed = runner
                    .run(&job.spec, &job.command, &phase, &capability, &cancel)
                    .await;
                (job.index, completed.record)
            });
        }

        let mut records = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok(record) = joined {
                records.push(record);
            }
        }
        records
    })
}

/// Cancels a run when Ctrl+C arrives, and stops watching when it is dropped.
#[derive(Debug)]
struct Interrupt {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Interrupt {
    /// Watch for Ctrl+C while the caller blocks on task execution.
    fn arm(cancel: Cancellation) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                // Polling, not blocking: this thread has to notice its own stop
                // flag once the run it is watching has finished.
                match panel::poll_key(Duration::from_millis(50)) {
                    Ok(Some(key)) if panel::is_interrupt(&key) => {
                        cancel.cancel();
                        return;
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Interrupt {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Run one capability: ask, execute every provider operation, then harvest.
fn run_capability(cfg: &Config, registry: &Registry, cap: &Capability) -> Result<()> {
    let theme = Theme::detect(cfg.general.color);

    if let Some(reason) = cap.unavailable_reason() {
        return show_notice(&theme, &cap.label, &[(reason, Role::Error)]);
    }

    // Show what is about to run, then let the prompts appear underneath it.
    {
        let _raw = RawMode::enter()?;
        let mut out = io::stdout();
        panel::draw(
            &mut out,
            &theme,
            &cap.label,
            &[(cap.summary.clone(), Role::Muted)],
            false,
        )?;
    }

    let values = match collect_inputs(cap)? {
        Answers::Given(values) => values,
        Answers::Cancelled => return Ok(()),
        Answers::Incomplete(key) => {
            return show_notice(
                &theme,
                &cap.label,
                &[(format!("{key} is required"), Role::Error)],
            );
        }
    };

    let run_id = RunId::now();
    let mut store = RunStore::open(&cfg.general.output_dir, &run_id)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| TsecError::internal(format!("creating the runtime: {e}")))?;

    let launcher = Launcher::new(OniuxBackend::new(&cfg.execution.oniux_binary));
    let runner = Runner::new(
        launcher,
        RunnerConfig {
            kill_grace: Duration::from_millis(cfg.execution.kill_grace_ms),
            env: Vec::new(),
            cwd: None,
        },
    );
    let cancel = Cancellation::new();
    let mut formats: BTreeMap<String, OutputFormat> = BTreeMap::new();
    let mut jobs: Vec<Job> = Vec::new();

    for binding in &cap.providers {
        let Some(program) = resolve_program(registry, &binding.binary) else {
            continue;
        };
        for operation in &binding.operations {
            formats.insert(
                format!("{}/{}", binding.binary, operation.name),
                operation.output,
            );
            let command = operation.command(&program, &cap.inputs, &values)?;
            let stem = artifact_stem(&run_id, cap, &binding.binary, &operation.name);
            let index = jobs.len();

            jobs.push(Job {
                index,
                spec: TaskSpec {
                    id: TaskId(index),
                    provider: binding.binary.clone(),
                    operation: operation.name.clone(),
                    label: format!("{} · {}", binding.binary, operation.name),
                    timeout: Duration::from_secs(cfg.execution.timeout_secs),
                    artifacts: RawArtifact {
                        primary: store.raw_stdout(&stem),
                        stderr: store.raw_stderr(&stem),
                    },
                    sensitive_args: command.sensitive_args().to_vec(),
                },
                command,
            });
        }
    }

    if jobs.is_empty() {
        return show_notice(
            &theme,
            &cap.label,
            &[("no provider is installed".to_string(), Role::Error)],
        );
    }

    {
        let _raw = RawMode::enter()?;
        let _interrupt = Interrupt::arm(cancel.clone());
        let spinner = Spinner::start(format!("{} · {} operations", cap.label, jobs.len()));
        let records = run_jobs(&runtime, runner, jobs, &cap.phase, &cap.label, &cancel, cfg);
        spinner.stop();

        // The manifest is written in the order the catalog declared, not in the
        // order tasks happened to finish, so a run reads the same twice.
        let mut records = records;
        records.sort_by_key(|(index, _)| *index);
        for (_, record) in records {
            store.commit(record)?;
        }
    }

    let outcome = store.harvest(&formats)?;
    display_harvest(
        &theme,
        &outcome,
        store.records(),
        store.root(),
        cfg.general.preview_lines,
    )
    .map_err(|e| TsecError::io("drawing the outputs panel", &e))
}
