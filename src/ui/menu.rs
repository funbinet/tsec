//! The interactive surface: boxed menus, navigation, provider guidance and
//! the capability run flow.
//!
//! One [`Renderer`] session is open for the whole visit: every screen —
//! menus, forms, execution, processing, output, viewer — overwrites the same
//! alternate-screen frame in place, so moving the pointer repaints one box,
//! never a second copy. Escaping works by context: `Esc` cancels an input
//! back to the capability menu, asks before stopping a live run, closes
//! documents, and everywhere on a menu it closes the system through the exit
//! screen. Capability rows carry their names only — no availability junk.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::KeyCode;

use crate::catalog::{phase_label, Capability, Catalog, OutputFormat, PHASES};
use crate::config::Config;
use crate::domain::ids::{RunId, TaskId};
use crate::domain::input::InputValues;
use crate::domain::plan::RawArtifact;
use crate::error::{Result, TsecError};
use crate::exec::oniux::OniuxBackend;
use crate::exec::{Launcher, Runner, RunnerConfig, TaskSpec};
use crate::install::advise;
use crate::provider::Registry;
use crate::store::{HarvestStage, OutputHeader, RunStore};
use crate::ui::execution::{self, Job, Processing};
use crate::ui::input::{self, Answer, Prompt};
use crate::ui::output::{show_output, view_document};
use crate::ui::panel::{
    box_frame, hint_frame, is_interrupt, next_input, print_plain, wait_close, Geometry, Input,
    Layout, Renderer,
};
use crate::ui::theme::{Role, Theme};

/// One choice in a box: its name, and nothing else.
#[derive(Debug, Clone)]
struct Item {
    label: String,
}

impl Item {
    fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

/// What the operator decided on a screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Chosen(usize),
    /// `J`/`Left`: back one level (meaningless at the root, which has none).
    Back,
    /// `Esc`: leave the system through the exit screen.
    Exit,
}

/// Full uppercase name for each phase.
fn phase_display_name(slug: &str) -> &str {
    match slug {
        "recon" => "RECONNAISSANCE",
        "surface" => "ATTACK SURFACE",
        "vulnerability" => "VULNERABILITY",
        "payload" => "PAYLOAD",
        "escalation" => "PRIVILEGE ESCALATION",
        "credentials" => "CREDENTIALS",
        "lateral" => "LATERAL MOVEMENT",
        "persistence" => "PERSISTENCE & DEFENSE EVASION",
        "objectives" => "OBJECTIVES",
        "wireless" => "WIRELESS",
        _ => slug,
    }
}

/// Enter the framework's top level: the ten phases, then status and outputs.
/// The alternate-screen session lives for the whole visit; leaving it prints
/// the exit screen onto the restored main buffer.
pub fn main_menu(cfg: &Config, catalog: &Catalog, registry: &Registry) -> Result<()> {
    let theme = Theme::detect(cfg.general.color);
    let started = Instant::now();

    let mut renderer =
        Renderer::enter().map_err(|e| TsecError::io("entering the terminal session", &e))?;
    let mut out = io::stdout();
    #[allow(unused_assignments)]
    let mut exit_requested = false;

    loop {
        let mut items: Vec<Item> = PHASES
            .iter()
            .map(|phase| Item::new(phase_display_name(phase)))
            .collect();
        let status_row = items.len();
        items.push(Item::new("STATUS"));
        let outputs_row = items.len();
        items.push(Item::new("OUTPUTS"));

        match menu(
            &theme,
            &mut renderer,
            &mut out,
            "TSEC",
            &items,
            "-[I/K] MOVE   -[L/ENTER] SELECT   -[ESC] EXIT",
        )? {
            Decision::Chosen(index) if index < PHASES.len() => {
                let flow = phase_menu(
                    &theme,
                    &mut renderer,
                    &mut out,
                    cfg,
                    catalog,
                    registry,
                    PHASES[index],
                )?;
                if flow == Flow::Exit {
                    exit_requested = true;
                    break;
                }
            }
            Decision::Chosen(index) if index == status_row => {
                status_screen(&theme, &mut renderer, &mut out, cfg, catalog)?;
            }
            Decision::Chosen(index) if index == outputs_row => {
                if let Err(e) = outputs_screen(&theme, &mut renderer, &mut out, cfg) {
                    if e.is_flow_exit() {
                        exit_requested = true;
                        break;
                    }
                    return Err(e);
                }
            }
            Decision::Exit => {
                exit_requested = true;
                break;
            }
            Decision::Chosen(_) | Decision::Back => {}
        }
    }

    renderer
        .close()
        .map_err(|e| TsecError::io("restoring the terminal", &e))?;
    if exit_requested {
        exit_screen(cfg, started).map_err(|e| TsecError::io("drawing the exit screen", &e))?;
    }
    Ok(())
}

/// Whether a nested screen wants the session to end altogether.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Exit,
}

/// One phase's capabilities, drawn as a box titled with the phase name.
/// Every capability stays selectable; a missing provider opens installation
/// guidance rather than a dead end. `Esc` here closes the system.
fn phase_menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
    catalog: &Catalog,
    registry: &Registry,
    phase: &str,
) -> Result<Flow> {
    let title = phase_display_name(phase);

    loop {
        let caps = catalog.in_phase(phase);
        if caps.is_empty() {
            show_notice(
                theme,
                renderer,
                out,
                title,
                &[("no capabilities in this phase".to_string(), Role::Muted)],
            )?;
            return Ok(Flow::Continue);
        }

        let items: Vec<Item> = caps
            .iter()
            .map(|cap| Item::new(cap.label.clone()))
            .collect();

        match menu(
            theme,
            renderer,
            out,
            title,
            &items,
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
        )? {
            Decision::Chosen(index) => {
                let cap = caps[index];
                if capability_is_unavailable(cap, registry) {
                    provider_guidance(theme, renderer, out, cfg, cap, registry)?;
                } else {
                    run_capability(theme, renderer, out, cfg, registry, cap)?;
                }
            }
            Decision::Back => return Ok(Flow::Continue),
            Decision::Exit => return Ok(Flow::Exit),
        }
    }
}

/// True when no provider of the capability is installed on this host.
fn capability_is_unavailable(cap: &Capability, registry: &Registry) -> bool {
    let with_ops: Vec<_> = cap
        .providers
        .iter()
        .filter(|p| !p.operations.is_empty())
        .collect();
    if with_ops.is_empty() {
        return true;
    }
    !with_ops.iter().any(|p| {
        registry
            .get(&p.binary)
            .map(|pr| pr.installed())
            .unwrap_or(false)
            || crate::provider::find_in_path(&p.binary).is_some()
    })
}

/// Draw a boxed menu and read keys until the operator decides.
///
/// Navigation is linear and bound-clamped: every entry is reachable, and no
/// entry is silently skipped. The frame is rebuilt in place on every key, so
/// there is exactly one box on screen and the pointer moves inside it.
fn menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    title: &str,
    items: &[Item],
    hint: &str,
) -> Result<Decision> {
    if items.is_empty() {
        return Ok(Decision::Back);
    }
    let mut selected = 0usize;
    let mut top = 0usize;

    loop {
        let g = Geometry::detect();
        // Chrome: 4 box border rows + 2 internal padding blank rows + 1 hint line.
        let max_body = g.body_rows(7);
        let visible = items.len().min(max_body);

        if selected < top {
            top = selected;
        } else if selected >= top + visible {
            top = selected + 1 - visible;
        }
        let end = (top + visible).min(items.len());

        let mut rows: Vec<(String, Role)> = Vec::new();
        for (index, item) in items.iter().enumerate().take(end).skip(top) {
            let marker = if index == selected { ">" } else { " " };
            rows.push((format!("{marker} {}", item.label), Role::Foreground));
        }

        if items.len() > visible {
            rows.push((format!("{} OF {}", selected + 1, items.len()), Role::Muted));
        }

        let mut frame = box_frame(theme, Layout::Menu, title, &rows);
        frame.append(hint_frame(theme, hint));
        renderer
            .present(out, &frame)
            .map_err(|e| TsecError::io("drawing the menu", &e))?;

        match next_input().map_err(|e| TsecError::io("reading a key", &e))? {
            Input::Resize => continue,
            Input::Key(key) => {
                if is_interrupt(&key) {
                    return Ok(Decision::Exit);
                }
                match key.code {
                    KeyCode::Char('i') | KeyCode::Char('I') | KeyCode::Up => {
                        selected = selected.saturating_sub(1);
                    }
                    KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Down => {
                        selected = (selected + 1).min(items.len() - 1);
                    }
                    KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Left => {
                        return Ok(Decision::Back);
                    }
                    KeyCode::Esc => return Ok(Decision::Exit),
                    KeyCode::Char('l')
                    | KeyCode::Char('L')
                    | KeyCode::Enter
                    | KeyCode::Right
                    | KeyCode::Char(' ') => {
                        return Ok(Decision::Chosen(selected));
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Explain missing provider(s) and show verified Arch Linux installation advice.
fn provider_guidance(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
    cap: &Capability,
    registry: &Registry,
) -> Result<()> {
    let mut rows: Vec<(String, Role)> = Vec::new();
    rows.push((format!("CAPABILITY: {}", cap.label), Role::Primary));
    rows.push((String::new(), Role::Muted));

    for binding in &cap.providers {
        if binding.operations.is_empty() {
            continue;
        }
        let installed = registry
            .get(&binding.binary)
            .map(|p| p.installed())
            .unwrap_or(false)
            || crate::provider::find_in_path(&binding.binary).is_some();

        if !installed {
            rows.push((pair("REQUIRED", &binding.binary), Role::Foreground));
            rows.push((pair("STATUS", "NOT INSTALLED"), Role::Error));
            let advice = advise(&binding.binary);
            for (i, cmd) in advice.commands.iter().enumerate() {
                let key = if i == 0 { "ARCH LINUX" } else { "ALTERNATIVE" };
                rows.push((pair(key, cmd), Role::Success));
            }
            for note in &advice.notes {
                rows.push((pair("NOTE", note), Role::Muted));
            }
            rows.push((String::new(), Role::Muted));
        }
    }

    let has_network = cap
        .providers
        .iter()
        .any(|p| p.operations.iter().any(|op| op.network));
    if has_network {
        let backend = OniuxBackend::new(&cfg.execution.oniux_binary);
        if let Err(e) = backend.resolve() {
            rows.push((
                pair("BOUNDARY", &format!("UNAVAILABLE · {}", e.reason())),
                Role::Warning,
            ));
            rows.push((
                pair(
                    "NOTE",
                    "Network tasks require oniux (yay -S oniux, or ./tools.sh -recon)",
                ),
                Role::Muted,
            ));
            rows.push((String::new(), Role::Muted));
        }
    }

    rows.push((
        "Install the missing provider(s), run tools.sh for this phase, or pick another capability."
            .to_string(),
        Role::Muted,
    ));

    let mut frame = box_frame(theme, Layout::Information, "PROVIDERS NOT INSTALLED", &rows);
    frame.append(hint_frame(theme, "-[ENTER/J/ESC] RETURN"));
    renderer
        .present(out, &frame)
        .map_err(|e| TsecError::io("drawing the guidance box", &e))?;
    wait_close().map_err(|e| TsecError::io("reading a key", &e))?;
    Ok(())
}

/// The operator's answers for one capability.
enum Answers {
    Given(InputValues),
    Cancelled,
}

/// Ask for every declared input, validating each against its declared type.
///
/// The capability's own closed box — titled with its name — sits above one
/// input box per field. `Esc` on any field withdraws the whole capability
/// back to the capability menu; it never leaves the system from here.
fn collect_inputs(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cap: &Capability,
) -> Result<Answers> {
    let mut values = InputValues::new();
    let header = box_frame(theme, Layout::Form, &cap.label, &[]);

    for spec in &cap.inputs {
        let mut error: Option<String> = None;
        loop {
            let label = format!("{} [{}]", spec.label.to_uppercase(), spec.ty.label());
            let prompt = Prompt {
                label: &label,
                help: spec.help.as_deref(),
                default: spec.default.as_deref(),
                sensitive: spec.ty.is_sensitive(),
                error: error.as_deref(),
            };

            match input::ask(out, renderer, theme, Some(&header), &prompt)
                .map_err(|e| TsecError::io("drawing the input box", &e))?
            {
                Answer::Cancelled => return Ok(Answers::Cancelled),
                Answer::Given(raw) => {
                    let raw = raw.trim();
                    if raw.is_empty() && spec.default.is_none() && !spec.required {
                        break;
                    }
                    match spec.validate(raw) {
                        Ok(v) => {
                            values.insert(&*spec.key, v);
                            break;
                        }
                        Err(e) => {
                            error = Some(e.reason());
                        }
                    }
                }
            }
        }
    }

    Ok(Answers::Given(values))
}

/// Execute a capability: input collection, concurrent execution, 6-stage
/// harvest, output display and raw artifact storage.
fn run_capability(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
    registry: &Registry,
    cap: &Capability,
) -> Result<()> {
    let values = match collect_inputs(theme, renderer, out, cap)? {
        Answers::Given(values) => values,
        Answers::Cancelled => return Ok(()),
    };

    let phase_word = phase_label(&cap.phase).unwrap_or(&cap.phase);
    let run_id = RunId::for_run(phase_word, &cap.label);
    let mut store = RunStore::open(&cfg.general.output_dir, &run_id)?;

    let mut missing_providers: Vec<String> = Vec::new();
    let mut formats: BTreeMap<String, OutputFormat> = BTreeMap::new();
    let mut jobs: Vec<Job> = Vec::new();

    for binding in &cap.providers {
        if binding.operations.is_empty() {
            continue;
        }
        let Some(program) = resolve_program(registry, &binding.binary) else {
            missing_providers.push(binding.binary.clone());
            continue;
        };

        for operation in &binding.operations {
            formats.insert(
                format!("{}/{}", binding.binary, operation.name),
                operation.output,
            );
            let command = operation.command(&program, &cap.inputs, &values)?;
            let index = jobs.len();
            let stem = format!(
                "T{:02}_{}_{}",
                index + 1,
                clean_slug(&binding.binary),
                clean_slug(&operation.name)
            );

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
        return provider_guidance(theme, renderer, out, cfg, cap, registry);
    }

    let runner = Runner::new(
        Launcher::new(OniuxBackend::new(&cfg.execution.oniux_binary)),
        RunnerConfig {
            kill_grace: Duration::from_millis(cfg.execution.kill_grace_ms),
            env: Vec::new(),
            cwd: None,
        },
    );

    let outcome = execution::execute(
        theme,
        out,
        renderer,
        jobs,
        phase_word,
        &cap.label,
        runner,
        cfg.execution.max_concurrency,
    )
    .map_err(|e| TsecError::io("running the execution monitor", &e))?;

    for (_, record) in outcome.records {
        store.commit(record)?;
    }

    let header = OutputHeader {
        run_name: run_id.as_str(),
        phase: phase_word,
        capability: &cap.label,
        missing_providers: &missing_providers,
        cancelled: outcome.cancelled,
    };

    let mut processing = Processing::new(renderer, theme);
    processing
        .begin(out)
        .map_err(|e| TsecError::io("drawing processing screen", &e))?;

    let _harvest = store.harvest(
        &formats,
        &header,
        Some(&mut |stage: HarvestStage| {
            processing
                .stage_done(out, stage)
                .map_err(|e| TsecError::io("drawing processing screen", &e))
        }),
    )?;

    show_output(theme, renderer, out, &store.output_txt())
        .map_err(|e| TsecError::io("drawing output screen", &e))?;

    Ok(())
}

/// Locate a provider binary, preferring the resolved registry entry.
fn resolve_program(registry: &Registry, binary: &str) -> Option<PathBuf> {
    registry
        .get(binary)
        .and_then(|provider| provider.path.clone())
        .or_else(|| crate::provider::find_in_path(binary))
}

/// Convert arbitrary text into safe ASCII filename component.
fn clean_slug(value: &str) -> String {
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
}

/// The status box: version, theme diagnostics, network boundary and live availability.
fn status_screen(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
    catalog: &Catalog,
) -> Result<()> {
    let boundary = match OniuxBackend::new(&cfg.execution.oniux_binary).resolve() {
        Ok(path) => path.display().to_string(),
        Err(e) => format!("UNAVAILABLE · {}", e.reason()),
    };
    let available = catalog
        .capabilities()
        .iter()
        .filter(|cap| cap.is_available())
        .count();

    let mut rows: Vec<(String, Role)> = vec![(pair("VERSION", crate::VERSION), Role::Foreground)];
    for (k, v) in theme.diagnostics() {
        rows.push((pair(k, &v), Role::Foreground));
    }
    rows.push((pair("BOUNDARY", &boundary), Role::Accent));
    rows.push((
        pair(
            "CATALOG",
            &format!("{available}/{}", catalog.capabilities().len()),
        ),
        Role::Foreground,
    ));

    for (label, caps) in catalog.grouped() {
        let ready = caps.iter().filter(|cap| cap.is_available()).count();
        rows.push((pair(label, &format!("{ready}/{}", caps.len())), Role::Muted));
    }
    rows.push((String::new(), Role::Muted));
    rows.push((catalog.source().display().to_string(), Role::Secondary));

    show_notice(theme, renderer, out, "STATUS", &rows)
}

/// `KEY` in a fixed column, so the box stays legible without a table.
fn pair(key: &str, value: &str) -> String {
    format!("{key:<16}{value}")
}

/// Previous runs that left evidence behind, newest first.
fn recorded_runs(output_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(output_dir) else {
        return Vec::new();
    };
    let mut runs: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && (path.join("output.txt").exists() || path.join("manifest.json").exists())
        })
        .collect();
    runs.sort_by(|a, b| b.cmp(a));
    runs
}

/// Pick a past run and explore its normalized output, raw output, or manifest.
fn outputs_screen(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
) -> Result<()> {
    loop {
        let runs = recorded_runs(&cfg.general.output_dir);
        if runs.is_empty() {
            show_notice(
                theme,
                renderer,
                out,
                "OUTPUTS",
                &[(
                    "no runs recorded in output directory".to_string(),
                    Role::Muted,
                )],
            )?;
            return Ok(());
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

        match menu(
            theme,
            renderer,
            out,
            "OUTPUTS",
            &items,
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
        )? {
            Decision::Chosen(index) => {
                run_actions_menu(theme, renderer, out, &runs[index])?;
            }
            Decision::Back => return Ok(()),
            Decision::Exit => return Err(crate::error::TsecError::flow_exit()),
        }
    }
}

/// Actions available for a single completed run.
fn run_actions_menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    run_dir: &Path,
) -> Result<Flow> {
    let run_name = run_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "RUN ACTIONS".to_string());

    let actions = vec![
        Item::new("NORMALIZED OUTPUT"),
        Item::new("RAW EVIDENCE"),
        Item::new("RUN MANIFEST"),
    ];

    loop {
        match menu(
            theme,
            renderer,
            out,
            &run_name,
            &actions,
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
        )? {
            Decision::Chosen(0) => {
                let path = run_dir.join("output.txt");
                view_document(theme, renderer, out, "OUTPUT", &path)
                    .map_err(|e| TsecError::io("viewing output", &e))?;
            }
            Decision::Chosen(1) => {
                raw_outputs_menu(theme, renderer, out, run_dir)?;
            }
            Decision::Chosen(2) => {
                let path = run_dir.join("manifest.json");
                view_document(theme, renderer, out, "MANIFEST", &path)
                    .map_err(|e| TsecError::io("viewing manifest", &e))?;
            }
            Decision::Chosen(_) => {}
            Decision::Back => return Ok(Flow::Continue),
            Decision::Exit => return Ok(Flow::Exit),
        }
    }
}

/// Browse raw tool stdout/stderr artifacts for a run.
fn raw_outputs_menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    run_dir: &Path,
) -> Result<Flow> {
    let raw_dir = run_dir.join("raw");
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&raw_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();

    if files.is_empty() {
        show_notice(
            theme,
            renderer,
            out,
            "RAW EVIDENCE",
            &[("no raw artifacts in this run".to_string(), Role::Muted)],
        )?;
        return Ok(Flow::Continue);
    }

    let items: Vec<Item> = files
        .iter()
        .map(|f| {
            Item::new(
                f.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| f.display().to_string()),
            )
        })
        .collect();

    loop {
        match menu(
            theme,
            renderer,
            out,
            "RAW EVIDENCE",
            &items,
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
        )? {
            Decision::Chosen(index) => {
                view_document(theme, renderer, out, "RAW EVIDENCE", &files[index])
                    .map_err(|e| TsecError::io("viewing raw artifact", &e))?;
            }
            Decision::Back => return Ok(Flow::Continue),
            Decision::Exit => return Ok(Flow::Exit),
        }
    }
}

/// Show a still informational box, then wait for the operator to close it.
fn show_notice(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    title: &str,
    rows: &[(String, Role)],
) -> Result<()> {
    let mut frame = box_frame(theme, Layout::Information, title, rows);
    frame.append(hint_frame(theme, "-[ENTER/J/ESC] RETURN"));
    renderer
        .present(out, &frame)
        .map_err(|e| TsecError::io("drawing the notice", &e))?;
    wait_close().map_err(|e| TsecError::io("reading a key", &e))?;
    Ok(())
}

/// The closing screen, printed onto the restored main buffer after the
/// session ends: the TSEC title, three lines of metadata, and a goodbye.
fn exit_screen(cfg: &Config, started: Instant) -> io::Result<()> {
    let theme = Theme::detect(cfg.general.color);
    let outputs = recorded_runs(&cfg.general.output_dir).len();

    let elapsed = started.elapsed();
    let runtime = if elapsed.as_secs() >= 60 {
        format!("{}M {}S", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    } else {
        format!("{}S", elapsed.as_secs())
    };

    let rows = vec![
        (pair("OUTPUTS", &outputs.to_string()), Role::Foreground),
        (pair("RUNTIME", &runtime), Role::Foreground),
        (pair("VERSION", crate::VERSION), Role::Foreground),
        (String::new(), Role::Muted),
        (
            "BYE — STAY LOW, STAY GHOST. SEE YOU IN THE SHELL.".to_string(),
            Role::Muted,
        ),
    ];
    let frame = box_frame(&theme, Layout::Form, "TSEC", &rows);
    let mut out = io::stdout();
    out.write_all(b"\r\n")?;
    print_plain(&mut out, &frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_exit_flows_through_the_error_channel() {
        // The outputs browser reports a session-wide exit by returning it
        // through the error channel (TsecError::flow_exit), which main_menu
        // intercepts before it can reach the operator.
        let e = TsecError::flow_exit();
        assert!(e.is_flow_exit());
    }

    #[test]
    fn phase_names_are_full_uppercase_words() {
        assert_eq!(phase_display_name("recon"), "RECONNAISSANCE");
        assert_eq!(
            phase_display_name("persistence"),
            "PERSISTENCE & DEFENSE EVASION"
        );
        assert_eq!(phase_display_name("unknown"), "unknown");
    }

    #[test]
    fn exit_screen_rows_carry_the_three_metadata_lines() {
        let rows = exit_rows(3, "1M 2S", "3.0.0");
        assert!(rows[0].0.starts_with("OUTPUTS"));
        assert!(rows[1].0.starts_with("RUNTIME"));
        assert!(rows[2].0.starts_with("VERSION"));
        assert!(rows[4].0.starts_with("BYE"));
    }

    fn exit_rows(outputs: usize, runtime: &str, version: &str) -> Vec<(String, Role)> {
        vec![
            (pair("OUTPUTS", &outputs.to_string()), Role::Foreground),
            (pair("RUNTIME", runtime), Role::Foreground),
            (pair("VERSION", version), Role::Foreground),
            (String::new(), Role::Muted),
            (
                "BYE — STAY LOW, STAY GHOST. SEE YOU IN THE SHELL.".to_string(),
                Role::Muted,
            ),
        ]
    }
}
