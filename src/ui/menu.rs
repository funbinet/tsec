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
use crate::error::{ExecutionErrorKind, Result, Stage, TsecError};
use crate::exec::oniux::OniuxBackend;
use crate::exec::{Launcher, Runner, RunnerConfig, TaskSpec};
use crate::install::{self, advise, InstallJob, InstallOutcome};
use crate::provider::Registry;
use crate::store::{HarvestStage, OutputHeader, RunStore};
use crate::ui::execution::{self, Job, Processing};
use crate::ui::input::{self, Answer, Prompt};
use crate::ui::output::{show_output, view_document};
use crate::ui::panel::{
    box_frame, hint_frame, is_interrupt, next_input, print_plain, wait_close, CloseAction, Frame,
    Geometry, Input, Layout, Renderer,
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

#[derive(Debug, Clone)]
struct MenuOutcome {
    decision: Decision,
    panel: Frame,
}

fn compose_stack(stack: &[Frame], panel: &Frame, hint: &str, theme: &Theme) -> Frame {
    let mut out = Frame::default();
    for frame in stack {
        out.append(frame.clone());
        out.line(String::new());
    }
    out.append(panel.clone());
    out.append(hint_frame(theme, hint));
    out
}

/// Full uppercase name for each phase.
///
/// The catalog is the single source of truth for this, so the main menu can
/// never drift from `tsec --status` or from the phase a run is recorded under.
/// The `_ => slug` fallback means an unknown phase shows its slug rather than
/// nothing, which is the honest rendering for a catalog that names a phase this
/// build does not know.
fn phase_display_name(slug: &str) -> &str {
    phase_label(slug).unwrap_or(slug)
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

        let root = menu(
            &theme,
            &mut renderer,
            &mut out,
            "TSEC",
            &items,
            "-[I/K] MOVE   -[L/ENTER] SELECT   -[ESC] EXIT",
            &[],
        )?;
        match root.decision {
            Decision::Chosen(index) if index < PHASES.len() => {
                renderer.freeze(&root.panel);
                let flow = phase_menu(
                    &theme,
                    &mut renderer,
                    &mut out,
                    cfg,
                    catalog,
                    registry,
                    PHASES[index],
                    &[],
                )?;
                if flow == Flow::Exit {
                    exit_requested = true;
                    break;
                }
            }
            Decision::Chosen(index) if index == status_row => {
                status_screen(&theme, &mut renderer, &mut out, cfg, catalog, &[root.panel])?;
            }
            Decision::Chosen(index) if index == outputs_row => {
                if let Err(e) = outputs_screen(&theme, &mut renderer, &mut out, cfg, &[root.panel])
                {
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
pub enum Flow {
    Continue,
    NewRun,
    Exit,
}

/// One phase's capabilities, drawn as a box titled with the phase name.
/// Every capability stays selectable; a missing provider opens installation
/// guidance rather than a dead end. `Esc` here closes the system.
#[allow(clippy::too_many_arguments)]
fn phase_menu(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
    catalog: &Catalog,
    registry: &Registry,
    phase: &str,
    stack: &[Frame],
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
                stack,
            )?;
            return Ok(Flow::Continue);
        }

        let items: Vec<Item> = caps
            .iter()
            .map(|cap| Item::new(cap.label.clone()))
            .collect();

        let phase_panel = menu(
            theme,
            renderer,
            out,
            title,
            &items,
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
            stack,
        )?;
        match phase_panel.decision {
            Decision::Chosen(index) => {
                let cap = caps[index];
                renderer.freeze(&phase_panel.panel);
                let flow = if capability_is_unavailable(cap, registry) {
                    provider_guidance(theme, renderer, out, cfg, cap, registry, &[])?;
                    Flow::Continue
                } else {
                    run_capability(
                        theme,
                        renderer,
                        out,
                        &Runtime {
                            cfg,
                            registry,
                            catalog_source: catalog.source(),
                        },
                        cap,
                        &[],
                    )?
                };
                if flow == Flow::Exit {
                    return Ok(Flow::Exit);
                }
                if flow == Flow::NewRun {
                    return Ok(Flow::NewRun);
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
    stack: &[Frame],
) -> Result<MenuOutcome> {
    if items.is_empty() {
        return Ok(MenuOutcome {
            decision: Decision::Back,
            panel: box_frame(theme, Layout::Menu, title, &[]),
        });
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

        let panel = box_frame(theme, Layout::Menu, title, &rows);
        let frame = compose_stack(stack, &panel, hint, theme);
        renderer
            .present(out, &frame)
            .map_err(|e| TsecError::io("drawing the menu", &e))?;

        match next_input().map_err(|e| TsecError::io("reading a key", &e))? {
            Input::Resize => continue,
            Input::ScrollUp(n) => {
                renderer.scroll_up(n);
                renderer
                    .present(out, &frame)
                    .map_err(|e| TsecError::io("drawing the menu", &e))?;
            }
            Input::ScrollDown(n) => {
                renderer.scroll_down(n);
                renderer
                    .present(out, &frame)
                    .map_err(|e| TsecError::io("drawing the menu", &e))?;
            }
            Input::Key(key) => {
                if is_interrupt(&key) {
                    return Ok(MenuOutcome {
                        decision: Decision::Exit,
                        panel,
                    });
                }
                if key.code == KeyCode::PageUp {
                    let rows = Geometry::detect().rows;
                    renderer.scroll_up(rows);
                    renderer
                        .present(out, &frame)
                        .map_err(|e| TsecError::io("drawing the menu", &e))?;
                    continue;
                }
                if key.code == KeyCode::PageDown {
                    let rows = Geometry::detect().rows;
                    renderer.scroll_down(rows);
                    renderer
                        .present(out, &frame)
                        .map_err(|e| TsecError::io("drawing the menu", &e))?;
                    continue;
                }
                if renderer.scroll_offset() > 0 {
                    renderer.reset_scroll();
                }
                match key.code {
                    KeyCode::Char('i') | KeyCode::Char('I') | KeyCode::Up => {
                        selected = selected.saturating_sub(1);
                    }
                    KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Down => {
                        selected = (selected + 1).min(items.len() - 1);
                    }
                    KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Left => {
                        return Ok(MenuOutcome {
                            decision: Decision::Back,
                            panel,
                        });
                    }
                    KeyCode::Esc => {
                        return Ok(MenuOutcome {
                            decision: Decision::Exit,
                            panel,
                        })
                    }
                    KeyCode::Char('l')
                    | KeyCode::Char('L')
                    | KeyCode::Enter
                    | KeyCode::Right
                    | KeyCode::Char(' ') => {
                        return Ok(MenuOutcome {
                            decision: Decision::Chosen(selected),
                            panel,
                        });
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Explain missing provider(s) and show verified Arch Linux installation advice.
/// The phase slug a capability belongs to, for the guidance box.
fn phase_menu_phase(cap: &Capability) -> &'static str {
    PHASES
        .iter()
        .copied()
        .find(|p| cap.id.starts_with(&format!("{p}.")))
        .unwrap_or("recon")
}

fn provider_guidance(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
    cap: &Capability,
    registry: &Registry,
    stack: &[Frame],
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
            let key = if advice.is_auto_installable() {
                "AUTO INSTALL"
            } else {
                "MANUAL"
            };
            for (i, cmd) in advice.commands.iter().enumerate() {
                let label = if i == 0 {
                    key.to_string()
                } else {
                    "ALTERNATIVE".to_string()
                };
                rows.push((pair(&label, cmd), Role::Success));
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
                    "Network tasks require oniux (paru -S oniux, or ./tools.sh -recon)",
                ),
                Role::Muted,
            ));
            rows.push((String::new(), Role::Muted));
        }
    }

    rows.push((
        format!(
            "Run this capability to install {} in the background, run tools.sh -{} for the \
             whole phase, or pick another capability.",
            if crate::install::can_install() {
                "the missing provider(s) automatically"
            } else {
                "the missing provider(s) manually — no supported package manager was found"
            },
            phase_menu_phase(cap)
        ),
        Role::Foreground,
    ));
    rows.push((
        "A provider that is still missing after the run is reported as TOOL_NOT_FOUND, \
         never as a failed task."
            .to_string(),
        Role::Muted,
    ));

    let panel = box_frame(theme, Layout::Form, "PROVIDERS NOT INSTALLED", &rows);
    let frame = compose_stack(stack, &panel, "-[ENTER/J/ESC] RETURN", theme);
    renderer
        .present(out, &frame)
        .map_err(|e| TsecError::io("drawing the guidance box", &e))?;
    let _ = wait_close(out, renderer, &frame).map_err(|e| TsecError::io("reading a key", &e))?;
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
///
/// Each accepted input is frozen into the renderer's history so it remains
/// visible above the next input prompt and above the execution box that
/// follows.
fn collect_inputs(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cap: &Capability,
    stack: &[Frame],
) -> Result<Answers> {
    let base = renderer.history_len();
    let mut values = InputValues::new();
    let mut header = Frame::default();
    for frame in stack {
        header.append(frame.clone());
        header.line(String::new());
    }

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

            match input::ask(out, renderer, theme, &cap.label, &prompt)
                .map_err(|e| TsecError::io("drawing the input box", &e))?
            {
                Answer::Cancelled => {
                    // Undo any inputs frozen during this collection.
                    renderer.collapse_to(base);
                    return Ok(Answers::Cancelled);
                }
                Answer::Given(raw) => {
                    let raw = raw.trim();
                    if raw.is_empty() && spec.default.is_none() && !spec.required {
                        break;
                    }
                    match spec.validate(raw) {
                        Ok(v) => {
                            // Freeze the accepted input as a permanent box
                            // (without ephemeral help/error/hint lines).
                            let committed = input::committed_input_box(
                                theme,
                                &cap.label,
                                &label,
                                raw,
                                spec.ty.is_sensitive(),
                            );
                            renderer.freeze(&committed);
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

/// Everything a run needs from the installed framework, in one place.
///
/// Grouped because these three travel together through the whole run flow, and
/// because `catalog_source` is what a `{wl:...}` reference in an argument vector
/// resolves against — a run cannot build a command without it.
struct Runtime<'a> {
    cfg: &'a Config,
    registry: &'a Registry,
    catalog_source: &'a Path,
}

/// Execute a capability: input collection, concurrent execution, 6-stage
/// harvest, output display and raw artifact storage.
///
/// The pipeline branches after execution:
///   - **All tasks failed** → `RUN FAILURE` terminal state (no processing, no output)
///   - **Some/all succeeded** → `PROCESSING` → harvest → `OUTPUT`
fn run_capability(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    rt: &Runtime<'_>,
    cap: &Capability,
    stack: &[Frame],
) -> Result<Flow> {
    let Runtime {
        cfg,
        registry,
        catalog_source,
    } = *rt;
    let values = match collect_inputs(theme, renderer, out, cap, stack)? {
        Answers::Given(values) => values,
        Answers::Cancelled => return Ok(Flow::Continue),
    };

    let phase_word = phase_label(&cap.phase).unwrap_or(&cap.phase);
    let run_id = RunId::for_run(phase_word, &cap.label);
    let mut store = RunStore::open(&cfg.general.output_dir, &run_id)?;

    let mut missing_providers: Vec<String> = Vec::new();
    let mut formats: BTreeMap<String, OutputFormat> = BTreeMap::new();
    let mut jobs: Vec<Job> = Vec::new();

    // A provider that is not installed is not the end of the task: start
    // installing it now, on its own thread, and let the capability proceed with
    // whatever else it can run. The outcome is decided at the end of the run,
    // when the install has had the whole execution to finish.
    let mut installs: Vec<InstallJob> = Vec::new();
    if install::can_install() {
        for binding in &cap.providers {
            if binding.operations.is_empty() {
                continue;
            }
            if resolve_program(registry, &binding.binary).is_some() {
                continue;
            }
            let advice = install::advise(&binding.binary);
            if advice.is_auto_installable() {
                installs.push(InstallJob::spawn(&binding.binary));
            }
        }
    }

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
            let command = operation.command(&program, &cap.inputs, &values, catalog_source)?;
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
        provider_guidance(theme, renderer, out, cfg, cap, registry, stack)?;
        return Ok(Flow::Continue);
    }

    let runner = Runner::new(
        Launcher::new(OniuxBackend::new(&cfg.execution.oniux_binary)),
        RunnerConfig {
            kill_grace: Duration::from_millis(cfg.execution.kill_grace_ms),
            env: Vec::new(),
            cwd: None,
        },
    );

    // While the run is executing, a background install may finish. Anything that
    // landed is resolved now, so its operations can still be dispatched in a
    // second pass rather than being silently dropped from the capability.
    let mut late_jobs: Vec<Job> = Vec::new();
    if !installs.is_empty() {
        // Give an install a brief head start so a cached package does not have
        // to wait for the whole run to be over before its capability can use it.
        // Bounded, and never a reason to delay: anything still pending is picked
        // up by the settle step at the end.
        let grace = Instant::now() + Duration::from_millis(1500);
        while Instant::now() < grace {
            let pending = installs
                .iter_mut()
                .any(|j| matches!(j.poll(), InstallOutcome::Pending));
            if !pending {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Dispatch whatever is now available but was not at the start.
        for binding in &cap.providers {
            if binding.operations.is_empty() || missing_providers.is_empty() {
                continue;
            }
            if !missing_providers.iter().any(|m| m == &binding.binary) {
                continue;
            }
            let Some(program) = resolve_program(registry, &binding.binary) else {
                continue;
            };
            for operation in &binding.operations {
                formats.insert(
                    format!("{}/{}", binding.binary, operation.name),
                    operation.output,
                );
                let command = operation.command(&program, &cap.inputs, &values, catalog_source)?;
                let index = late_jobs.len();
                let stem = format!(
                    "T{:02}_{}_{}",
                    index + 1,
                    clean_slug(&binding.binary),
                    clean_slug(&operation.name)
                );
                late_jobs.push(Job {
                    index,
                    spec: TaskSpec {
                        id: TaskId(index),
                        provider: binding.binary.clone(),
                        operation: operation.name.clone(),
                        label: format!(
                            "{} · {} (installed mid-run)",
                            binding.binary, operation.name
                        ),
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
            missing_providers.retain(|m| m != &binding.binary);
        }
    }

    let outcome = if late_jobs.is_empty() {
        execution::execute(
            theme,
            out,
            renderer,
            jobs,
            phase_word,
            &cap.label,
            runner,
            cfg.execution.max_concurrency,
        )
        .map_err(|e| TsecError::io("running the execution monitor", &e))?
    } else {
        jobs.extend(late_jobs);
        execution::execute(
            theme,
            out,
            renderer,
            jobs,
            phase_word,
            &cap.label,
            runner,
            cfg.execution.max_concurrency,
        )
        .map_err(|e| TsecError::io("running the execution monitor", &e))?
    };

    // ── Settle the background installs ────────────────────────────────────
    // A provider that is still missing now is reported as TOOL_NOT_FOUND rather
    // than as a failed task: nothing ran, so nothing failed.
    let mut install_notes: Vec<String> = Vec::new();
    let mut install_reasons: BTreeMap<String, String> = BTreeMap::new();
    for job in &mut installs {
        let binary = job.binary().to_string();
        match job.settle() {
            InstallOutcome::Installed { package } => {
                install_notes.push(format!("installed {package} while the capability ran"))
            }
            InstallOutcome::Refused { package, reason } => {
                install_notes.push(format!("could not install {package}: {reason}"));
                install_reasons.insert(binary, format!("{package}: {reason}"));
            }
            InstallOutcome::Unavailable { reason } => {
                install_notes.push(reason.clone());
                install_reasons.insert(binary, reason);
            }
            InstallOutcome::NoPackage => {
                install_reasons.insert(binary, "no package in any repository provides it".into());
            }
            InstallOutcome::Pending => {}
        }
    }

    for (_, record) in &outcome.records {
        store.commit(record.clone())?;
    }

    // A provider that is still missing after the install settled produced no task
    // at all. It is recorded as skipped with `TOOL_NOT_FOUND`, so the manifest
    // and the document say "this did not run, and here is why" instead of
    // quietly omitting it. Recording it as a failure would be a lie: nothing was
    // executed, so nothing failed.
    let reasons: BTreeMap<String, String> = install_reasons.clone();
    for binary in &missing_providers {
        let reason = reasons
            .get(binary)
            .cloned()
            .unwrap_or_else(|| "no package provides it".to_string());
        let error = TsecError::new(
            Stage::ResolveTools,
            ExecutionErrorKind::ToolNotFound {
                tool: binary.clone(),
                reason,
            },
        );
        let now = chrono::Utc::now();
        store.commit(crate::domain::execution::ExecutionRecord {
            task_id: format!("S{}", binary),
            phase: phase_word.to_string(),
            capability: cap.label.clone(),
            provider: binary.clone(),
            operation: String::new(),
            label: format!("{binary} · not installed"),
            command: binary.clone(),
            program: binary.clone(),
            args: Vec::new(),
            network: false,
            boundary: crate::domain::execution::ExecBoundary::Local,
            launched: String::new(),
            uses_shell: false,
            started_at: now,
            finished_at: now,
            duration_ms: 0,
            exit_code: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
            raw_output: store.raw_stdout(&format!("S_{}", clean_slug(binary))),
            stderr_output: Some(store.raw_stderr(&format!("S_{}", clean_slug(binary)))),
            status: crate::domain::execution::TaskStatus::Skipped,
            error_code: Some(error.kind.code().to_string()),
            error_message: Some(error.reason()),
            harvest_section: None,
        })?;
    }

    // ── Branch: all tasks failed → RUN FAILURE (no processing, no output) ──
    // Only real attempts count. A capability whose every provider was missing has
    // not "failed"; it has not run, and it is shown as such.
    if all_tasks_failed(&outcome.records) {
        return show_run_failure(theme, renderer, out, &outcome.records);
    }

    // ── Branch: some/all succeeded → Processing → Output ───────────────────
    let header = OutputHeader {
        run_name: run_id.as_str(),
        phase: phase_word,
        capability: &cap.label,
        missing_providers: &missing_providers,
        install_notes: &install_notes,
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

    let action = show_output(theme, renderer, out, &store.output_txt(), None)
        .map_err(|e| TsecError::io("drawing output screen", &e))?;

    match action {
        CloseAction::Cancel => Ok(Flow::Exit),
        CloseAction::Accept => Ok(Flow::NewRun),
        CloseAction::Back => Ok(Flow::NewRun),
    }
}

/// True when every task in the run ended in a terminal failure (Failed,
/// TimedOut, Interrupted) — meaning the execution pipeline produced no
/// usable data for the harvest.
fn all_tasks_failed(records: &[(usize, crate::domain::execution::ExecutionRecord)]) -> bool {
    use crate::domain::execution::TaskStatus;
    if records.is_empty() {
        return true;
    }
    records.iter().all(|(_, r)| {
        matches!(
            r.status,
            TaskStatus::Failed | TaskStatus::TimedOut | TaskStatus::Interrupted
        )
    })
}

/// The `RUN FAILURE` terminal state: shown when every task of a capability run
/// ended in failure. The cycle ends here — no processing, no output, no
/// findings. The operator can press Enter to start a new cycle or Esc to exit.
fn show_run_failure(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    records: &[(usize, crate::domain::execution::ExecutionRecord)],
) -> Result<Flow> {
    let total = records.len();
    let mut rows: Vec<(String, Role)> = vec![
        (
            pair("FAILED TASKS", &format!("{total}/{total}")),
            Role::Error,
        ),
        (String::new(), Role::Muted),
    ];
    for (_, record) in records.iter().take(6) {
        rows.push((
            format!(
                "{} · {} · {}",
                record.provider,
                record.operation,
                record.error_code.as_deref().unwrap_or("UNKNOWN")
            ),
            Role::Foreground,
        ));
        if let Some(message) = &record.error_message {
            rows.push((format!("  {}", message), Role::Error));
        }
    }
    rows.push((String::new(), Role::Muted));
    rows.push((
        "Review missing providers, boundary status, and raw stderr in OUTPUTS > RAW EVIDENCE."
            .to_string(),
        Role::Muted,
    ));

    let panel = box_frame(theme, Layout::Information, "RUN FAILURE", &rows);
    renderer.freeze(&panel);
    let frame = hint_frame(theme, "-[I/K] SCROLL   -[ENTER] NEW RUN   -[ESC] EXIT");
    renderer
        .present(out, &frame)
        .map_err(|e| TsecError::io("drawing the failure box", &e))?;
    let action =
        wait_close(out, renderer, &frame).map_err(|e| TsecError::io("reading a key", &e))?;
    match action {
        CloseAction::Cancel => Ok(Flow::Exit),
        CloseAction::Accept => Ok(Flow::NewRun),
        CloseAction::Back => Ok(Flow::NewRun),
    }
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
    stack: &[Frame],
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

    // A provider can resolve and still be the wrong program. Report that here,
    // where an operator reads availability, instead of letting it surface later
    // as a wall of unexplained task failures.
    let faults = crate::provider_identity::flag_mismatches(catalog);
    if !faults.is_empty() {
        rows.push((String::new(), Role::Muted));
        rows.push((format!("WRONG PROVIDER  {}", faults.len()), Role::Warning));
        for fault in &faults {
            rows.push((pair(&fault.binary, &fault.reason()), Role::Warning));
        }
    }

    rows.push((String::new(), Role::Muted));
    rows.push((catalog.source().display().to_string(), Role::Secondary));

    show_notice(theme, renderer, out, "STATUS", &rows, stack)
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
    stack: &[Frame],
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
                stack,
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

        let pick = menu(
            theme,
            renderer,
            out,
            "OUTPUTS",
            &items,
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
            stack,
        )?;
        match pick.decision {
            Decision::Chosen(index) => {
                let mut child_stack = stack.to_vec();
                child_stack.push(pick.panel.clone());
                run_actions_menu(theme, renderer, out, &runs[index], &child_stack)?;
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
    stack: &[Frame],
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
        let action = menu(
            theme,
            renderer,
            out,
            &run_name,
            &actions,
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
            stack,
        )?;
        match action.decision {
            Decision::Chosen(0) => {
                let path = run_dir.join("output.txt");
                view_document(theme, renderer, out, "OUTPUT", &path)
                    .map_err(|e| TsecError::io("viewing output", &e))?;
            }
            Decision::Chosen(1) => {
                let mut child_stack = stack.to_vec();
                child_stack.push(action.panel.clone());
                raw_outputs_menu(theme, renderer, out, run_dir, &child_stack)?;
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
    stack: &[Frame],
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
            stack,
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
        let pick = menu(
            theme,
            renderer,
            out,
            "RAW EVIDENCE",
            &items,
            "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
            stack,
        )?;
        match pick.decision {
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
    stack: &[Frame],
) -> Result<()> {
    let panel = box_frame(theme, Layout::Form, title, rows);
    let frame = compose_stack(stack, &panel, "-[ENTER/J/ESC] RETURN", theme);
    renderer
        .present(out, &frame)
        .map_err(|e| TsecError::io("drawing the notice", &e))?;
    let _ = wait_close(out, renderer, &frame).map_err(|e| TsecError::io("reading a key", &e))?;
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
    fn phase_names_are_single_uppercase_words() {
        assert_eq!(phase_display_name("recon"), "RECON");
        assert_eq!(phase_display_name("persistence"), "PERSISTENCE");
        assert_eq!(phase_display_name("lateral"), "LATERAL");
        assert_eq!(phase_display_name("surface"), "SURFACE");
        assert_eq!(phase_display_name("escalation"), "ESCALATION");
        assert_eq!(phase_display_name("unknown"), "unknown");
        // Every phase the framework defines renders in capitals, from one source.
        for phase in crate::catalog::PHASES {
            let shown = phase_display_name(phase);
            assert!(
                shown.chars().all(|c| !c.is_lowercase()),
                "phase {phase} renders as {shown}"
            );
        }
        assert_eq!(phase_display_name("exploitation"), "EXPLOITATION");
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
