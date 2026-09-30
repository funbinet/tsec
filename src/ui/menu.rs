//! The interactive surface: boxed menus, navigation, provider guidance and
//! the capability run flow.
//!
//! Features:
//! - Full-terminal-width boxes adapting dynamically to terminal resize.
//! - Content inside selection menus is centered; informational and status screens are left-aligned.
//! - Linear navigation with I/K (and Arrow Up/Down) that clamps within bounds without skipping any entry.
//! - Every capability in the catalog remains selectable; missing providers open verified Arch Linux installation guidance.
//! - Escapable input flow using `ui::input::ask`.
//! - Live execution monitoring via `ui::execution::execute` and 6-stage harvesting with `ui::execution::Processing`.
//! - Output presentation via `ui::output::show_output` and scrollable viewer `ui::output::view_document`.
//! - Output browser distinguishing normalized outputs, raw evidence captures, and run manifests.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
use crate::ui::panel::{self, box_frame, hint_frame, Geometry, Layout, RawMode, Renderer};
use crate::ui::theme::{Role, Theme};

/// One choice in a box.
#[derive(Debug, Clone)]
struct Item {
    label: String,
    status: Option<&'static str>,
    unavailable: bool,
}

impl Item {
    fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: None,
            unavailable: false,
        }
    }

    fn capability(label: impl Into<String>, status: &'static str, unavailable: bool) -> Self {
        Self {
            label: label.into(),
            status: Some(status),
            unavailable,
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
pub fn main_menu(cfg: &Config, catalog: &Catalog, registry: &Registry) -> Result<()> {
    let theme = Theme::detect(cfg.general.color);
    let _raw = RawMode::enter()?;
    let mut renderer = Renderer::new();
    let mut out = io::stdout();

    loop {
        let mut items: Vec<Item> = PHASES
            .iter()
            .map(|phase| Item::new(phase_display_name(phase)))
            .collect();
        let status_row = items.len();
        items.push(Item::new("STATUS"));
        let outputs_row = items.len();
        items.push(Item::new("OUTPUTS"));

        match menu(&theme, &mut renderer, &mut out, "TSEC", &items, true)? {
            Decision::Chosen(index) if index < PHASES.len() => {
                phase_menu(
                    &theme,
                    &mut renderer,
                    &mut out,
                    cfg,
                    catalog,
                    registry,
                    PHASES[index],
                )?;
            }
            Decision::Chosen(index) if index == status_row => {
                status_screen(&theme, &mut renderer, &mut out, cfg, catalog)?;
            }
            Decision::Chosen(index) if index == outputs_row => {
                outputs_screen(&theme, &mut renderer, &mut out, cfg)?;
            }
            _ => return Ok(()),
        }
    }
}

/// One phase's capabilities, drawn as a box titled with the phase name.
fn phase_menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
    catalog: &Catalog,
    registry: &Registry,
    phase: &str,
) -> Result<()> {
    let title = phase_display_name(phase);

    loop {
        let caps = catalog.in_phase(phase);
        if caps.is_empty() {
            return show_notice(
                theme,
                renderer,
                out,
                title,
                &[("no capabilities in this phase".to_string(), Role::Muted)],
            );
        }

        let items: Vec<Item> = caps
            .iter()
            .map(|cap| {
                let (status, unavailable) = capability_status(cap, registry);
                Item::capability(cap.label.clone(), status, unavailable)
            })
            .collect();

        match menu(theme, renderer, out, title, &items, false)? {
            Decision::Chosen(index) => {
                let cap = caps[index];
                let (_, unavailable) = capability_status(cap, registry);
                if unavailable {
                    provider_guidance(theme, renderer, out, cfg, cap, registry)?;
                } else {
                    run_capability(theme, renderer, out, cfg, registry, cap)?;
                }
            }
            Decision::Back | Decision::Exit => return Ok(()),
        }
    }
}

/// Determine availability status for a capability.
fn capability_status(cap: &Capability, registry: &Registry) -> (&'static str, bool) {
    let with_ops: Vec<_> = cap
        .providers
        .iter()
        .filter(|p| !p.operations.is_empty())
        .collect();
    if with_ops.is_empty() {
        return ("PROVIDER MISSING", true);
    }
    let installed = with_ops
        .iter()
        .filter(|p| {
            registry
                .get(&p.binary)
                .map(|pr| pr.installed())
                .unwrap_or(false)
                || crate::provider::find_in_path(&p.binary).is_some()
        })
        .count();
    if installed == with_ops.len() {
        ("READY", false)
    } else if installed > 0 {
        ("PARTIAL", false)
    } else {
        ("PROVIDER MISSING", true)
    }
}

/// Draw a boxed menu and read keys until the operator decides.
///
/// Navigation is linear and bound-clamped: every entry is reachable, and no
/// entry is silently skipped. Content inside the box is centered.
fn menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    title: &str,
    items: &[Item],
    root: bool,
) -> Result<Decision> {
    if items.is_empty() {
        return Ok(back_or_exit(root));
    }
    let mut selected = 0usize;
    let mut top = 0usize;

    loop {
        let g = Geometry::detect();
        // Chrome: 4 box border rows + 2 internal padding blank rows + 1 hint line
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
            let is_sel = index == selected;
            let marker = if is_sel { ">" } else { " " };
            let row_text = if let Some(status) = item.status {
                format!("{marker} {:<28} {status}", item.label)
            } else {
                format!("{marker} {}", item.label)
            };

            let role = if is_sel {
                Role::Highlight
            } else if item.unavailable {
                Role::Muted
            } else {
                Role::Foreground
            };
            rows.push((row_text, role));
        }

        if items.len() > visible {
            rows.push((format!("{} of {}", selected + 1, items.len()), Role::Muted));
        }

        let mut frame = box_frame(theme, Layout::Menu, title, &rows);
        let hint_text = if root {
            "-[I/K] MOVE   -[L/ENTER] SELECT   -[ESC] EXIT"
        } else {
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT"
        };
        frame.append(hint_frame(theme, hint_text));
        renderer.present(out, &frame)?;

        match panel::next_input()? {
            panel::Input::Resize => continue,
            panel::Input::Key(key) => {
                if panel::is_interrupt(&key) {
                    return Ok(back_or_exit(root));
                }
                match key.code {
                    KeyCode::Char('i') | KeyCode::Char('I') | KeyCode::Up => {
                        selected = selected.saturating_sub(1);
                    }
                    KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Down => {
                        selected = (selected + 1).min(items.len() - 1);
                    }
                    KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Left | KeyCode::Esc => {
                        return Ok(back_or_exit(root));
                    }
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

/// `J`/Esc close the current box; at the top level closing means leaving.
fn back_or_exit(root: bool) -> Decision {
    if root {
        Decision::Exit
    } else {
        Decision::Back
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
                    "Network tasks require oniux (paru -S oniux / yay -S oniux)",
                ),
                Role::Muted,
            ));
            rows.push((String::new(), Role::Muted));
        }
    }

    rows.push((
        "Install the missing provider(s) or select an available capability.".to_string(),
        Role::Muted,
    ));

    let mut frame = box_frame(theme, Layout::Information, "PROVIDERS NOT INSTALLED", &rows);
    frame.append(hint_frame(theme, "-[ENTER/J/ESC] RETURN"));
    renderer.present(out, &frame)?;
    panel::wait_close()?;
    Ok(())
}

/// The operator's answers for one capability.
enum Answers {
    Given(InputValues),
    Cancelled,
}

/// Ask for every declared input, validating each against its declared type.
///
/// Prompts are drawn under a clean capability title box and can be cancelled
/// with Esc or Ctrl+C at any time without terminating TSEC.
fn collect_inputs(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cap: &Capability,
) -> Result<Answers> {
    let mut values = InputValues::new();
    let header = box_frame(
        theme,
        Layout::Information,
        "CAPABILITY",
        &[(cap.label.clone(), Role::Primary)],
    );

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

            match input::ask(out, renderer, theme, Some(&header), &prompt)? {
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

    let title = format!("EXECUTION — {}", cap.label);
    let outcome = execution::execute(
        theme,
        out,
        renderer,
        &title,
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
            return show_notice(
                theme,
                renderer,
                out,
                "OUTPUTS",
                &[(
                    "no runs recorded in output directory".to_string(),
                    Role::Muted,
                )],
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

        match menu(theme, renderer, out, "OUTPUTS", &items, false)? {
            Decision::Chosen(index) => {
                run_actions_menu(theme, renderer, out, &runs[index])?;
            }
            Decision::Back | Decision::Exit => return Ok(()),
        }
    }
}

/// Actions available for a single completed run.
fn run_actions_menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    run_dir: &Path,
) -> Result<()> {
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
        match menu(theme, renderer, out, &run_name, &actions, false)? {
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
            Decision::Back | Decision::Exit => return Ok(()),
            _ => {}
        }
    }
}

/// Browse raw tool stdout/stderr artifacts for a run.
fn raw_outputs_menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    run_dir: &Path,
) -> Result<()> {
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
        return show_notice(
            theme,
            renderer,
            out,
            "RAW EVIDENCE",
            &[("no raw artifacts in this run".to_string(), Role::Muted)],
        );
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
        match menu(theme, renderer, out, "RAW EVIDENCE", &items, false)? {
            Decision::Chosen(index) => {
                view_document(theme, renderer, out, "RAW EVIDENCE", &files[index])
                    .map_err(|e| TsecError::io("viewing raw artifact", &e))?;
            }
            Decision::Back | Decision::Exit => return Ok(()),
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
    renderer.present(out, &frame)?;
    panel::wait_close()?;
    Ok(())
}
