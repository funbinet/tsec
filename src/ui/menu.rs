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
                            catalog,
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

/// The FLAG SCANNING input flow, replacing the ordinary form: the flag format
/// as a plain word, then which CTF category's evidence to sweep, then which
/// run of that category — or the whole category. Returns the values that
/// satisfy the capability's declared inputs, or `None` when the operator
/// backs out.
fn flag_scan_inputs(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    cfg: &Config,
    catalog: &Catalog,
    stack: &[Frame],
) -> Result<Option<InputValues>> {
    // 1. The flag format: a plain word is enough — the braces are added here.
    let mut error_of: Option<String> = None;
    let declared = loop {
        let prompt = crate::ui::input::Prompt {
            label: "FLAG FORMAT [flag-format]",
            help: Some(
                "type the flag prefix, e.g. the challenge's own word — {…} is added for you",
            ),
            default: None,
            sensitive: false,
            error: error_of.as_deref(),
        };
        match crate::ui::input::ask(out, renderer, theme, "FLAG SCANNING", &prompt)
            .map_err(|e| TsecError::io("drawing the flag format box", &e))?
        {
            crate::ui::input::Answer::Cancelled => return Ok(None),
            crate::ui::input::Answer::Given(raw) => {
                let raw = raw.trim().to_string();
                if raw.is_empty() {
                    continue;
                }
                if let Err(e) = crate::ctf::FlagPattern::compile(&raw) {
                    error_of = Some(e.reason().to_string());
                    continue;
                }
                let committed = crate::ui::input::committed_input_box(
                    theme,
                    "FLAG SCANNING",
                    "FLAG FORMAT [flag-format]",
                    &raw,
                    false,
                );
                renderer.freeze(&committed);
                break raw;
            }
        }
    };

    // 2. The category whose runs to sweep.
    let caps: Vec<&Capability> = catalog
        .in_phase("ctf")
        .iter()
        .copied()
        .filter(|c| c.id != "ctf.flag-scanning")
        .collect();
    let items: Vec<Item> = caps.iter().map(|c| Item::new(c.label.clone())).collect();
    let pick = menu(
        theme,
        renderer,
        out,
        "FLAG SCANNING",
        &items,
        "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
        stack,
    )?;
    let index = match pick.decision {
        Decision::Back => None,
        Decision::Exit => return Err(crate::error::TsecError::flow_exit()),
        Decision::Chosen(index) => Some(index),
    };
    let Some(index) = index else {
        return Ok(None);
    };
    renderer.freeze(&pick.panel);
    let category = caps
        .get(index)
        .ok_or_else(|| TsecError::internal("category picker index out of range"))?;

    // 3. The run to sweep, or the whole category. Runs are named
    // `{stamp}_{PHASE}_{CAPABILITY}`, so a category's runs are a suffix
    // match on its cleaned label.
    let suffix = format!(
        "_CTF_CHALLENGES_{}",
        category
            .label
            .to_ascii_uppercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    );
    let runs: Vec<PathBuf> = recorded_runs(&cfg.general.output_dir)
        .into_iter()
        .filter(|run| {
            run.file_name()
                .map(|name| name.to_string_lossy().ends_with(&suffix))
                .unwrap_or(false)
        })
        .collect();
    if runs.is_empty() {
        show_notice(
            theme,
            renderer,
            out,
            "FLAG SCANNING",
            &[(
                format!(
                    "no recorded runs for {}; run that category first, then scan it",
                    category.label
                ),
                Role::Muted,
            )],
            stack,
        )?;
        return Ok(None);
    }
    let mut items: Vec<Item> = vec![Item::new("WHOLE CATEGORY (every run)")];
    items.extend(runs.iter().map(|run| {
        Item::new(
            run.file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| run.display().to_string()),
        )
    }));
    let pick = menu(
        theme,
        renderer,
        out,
        &format!("FLAG SCANNING · {}", category.label),
        &items,
        "-[I/K] MOVE   -[J] BACK   -[L/ENTER] SELECT   -[ESC] EXIT",
        stack,
    )?;
    match pick.decision {
        Decision::Back => Ok(None),
        Decision::Exit => Err(crate::error::TsecError::flow_exit()),
        Decision::Chosen(index) => {
            renderer.freeze(&pick.panel);
            let scan_dir = if index == 0 {
                cfg.general.output_dir.clone()
            } else {
                runs.get(index - 1)
                    .ok_or_else(|| TsecError::internal("run picker index out of range"))?
                    .clone()
            };
            let mut values = InputValues::new();
            values.insert("flag_format", declared);
            values.insert("scan_dir", scan_dir.display().to_string());
            Ok(Some(values))
        }
    }
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
    catalog: &'a Catalog,
}

/// The tempo a CTF run runs at, chosen once at the start. It scales every
/// operation's time budget: `Fast` hunts for the quick win, `Deep` gives a
/// slow target the patience it deserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Speed {
    Fast,
    Normal,
    Deep,
}

impl Speed {
    /// Scale one operation's time budget, never below 10 seconds: even FAST
    /// gives every tool a real attempt rather than a hair-trigger kill.
    fn scale_secs(&self, secs: u64) -> u64 {
        match self {
            Speed::Fast => (secs / 3).max(10),
            Speed::Normal => secs,
            Speed::Deep => secs.saturating_mul(2),
        }
    }
}

/// Ask the operator how hard to hunt. `Esc` withdraws the capability, like
/// every other prompt.
fn ask_speed(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    capability: &str,
) -> Result<Option<Speed>> {
    let mut error: Option<String> = None;
    loop {
        let prompt = crate::ui::input::Prompt {
            label: "SPEED [fast / normal / deep]",
            help: Some(
                "fast cuts every time budget to a third (never under 10s); \
                 deep doubles it for a patient target",
            ),
            default: Some("normal"),
            sensitive: false,
            error: error.as_deref(),
        };
        match crate::ui::input::ask(out, renderer, theme, capability, &prompt)
            .map_err(|e| TsecError::io("drawing the speed box", &e))?
        {
            crate::ui::input::Answer::Cancelled => return Ok(None),
            crate::ui::input::Answer::Given(raw) => {
                let raw = raw.trim();
                let speed = match raw.to_ascii_lowercase().as_str() {
                    "" | "normal" | "n" => Speed::Normal,
                    "fast" | "f" => Speed::Fast,
                    "deep" | "d" => Speed::Deep,
                    _ => {
                        error = Some("answer fast, normal or deep (Enter accepts normal)".into());
                        continue;
                    }
                };
                let committed = crate::ui::input::committed_input_box(
                    theme,
                    capability,
                    "SPEED [fast / normal / deep]",
                    if raw.is_empty() { "normal" } else { raw },
                    false,
                );
                renderer.freeze(&committed);
                return Ok(Some(speed));
            }
        }
    }
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
        catalog,
    } = *rt;
    // FLAG SCANNING replaces the ordinary input form with its own flow:
    // flag format, then the CTF category to sweep, then the run (or the
    // whole category) whose raw evidence to search.
    let values = if cap.id == "ctf.flag-scanning" {
        match flag_scan_inputs(theme, renderer, out, cfg, catalog, stack)? {
            Some(values) => values,
            None => return Ok(Flow::Continue),
        }
    } else {
        match collect_inputs(theme, renderer, out, cap, stack)? {
            Answers::Given(values) => values,
            Answers::Cancelled => return Ok(Flow::Continue),
        }
    };

    // A CTF run is a hunt: how long each tool is allowed to look decides how
    // long the whole hunt takes. The operator picks the tempo once, up front,
    // and every operation's time budget scales with it.
    let speed = if cap.phase == "ctf" {
        match ask_speed(theme, renderer, out, &cap.label)? {
            Some(speed) => speed,
            None => return Ok(Flow::Continue),
        }
    } else {
        Speed::Normal
    };

    let phase_word = phase_label(&cap.phase).unwrap_or(&cap.phase);

    // Every job's time budget: the operation's own `timeout` key if it
    // declared one, else the per-binary override, else the configured
    // default — with CTF runs falling back to a 300s baseline when
    // configuration leaves timeouts disabled, and the chosen speed scaling
    // whatever budget applies.
    let job_timeout = |operation: &crate::catalog::Operation, binary: &str| -> Duration {
        let secs = match operation.timeout_secs() {
            Some(secs) => secs,
            None => {
                let per_binary = cfg
                    .execution
                    .tool_timeout_secs
                    .get(binary)
                    .copied()
                    .filter(|s| *s > 0);
                match per_binary {
                    Some(secs) => secs,
                    None if cap.phase == "ctf" => 300,
                    None => cfg.execution.timeout_secs,
                }
            }
        };
        Duration::from_secs(speed.scale_secs(secs))
    };
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
            let command = operation.command(
                &program,
                &cap.inputs,
                &values,
                catalog_source,
                Some(&store.artifacts_dir()),
            )?;
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
                    timeout: job_timeout(operation, &binding.binary),
                    artifacts: RawArtifact {
                        primary: store.raw_stdout(&stem),
                        stderr: store.raw_stderr(&stem),
                    },
                    sensitive_args: command.sensitive_args().to_vec(),
                },
                command,
                stage: operation.stage(),
                confirm: operation.confirm,
                probe: operation.is_probe(),
            });
        }
    }

    if jobs.is_empty() {
        provider_guidance(theme, renderer, out, cfg, cap, registry, stack)?;
        return Ok(Flow::Continue);
    }

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
                let command = operation.command(
                    &program,
                    &cap.inputs,
                    &values,
                    catalog_source,
                    Some(&store.artifacts_dir()),
                )?;
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
                        timeout: job_timeout(operation, &binding.binary),
                        artifacts: RawArtifact {
                            primary: store.raw_stdout(&stem),
                            stderr: store.raw_stderr(&stem),
                        },
                        sensitive_args: command.sensitive_args().to_vec(),
                    },
                    command,
                    stage: operation.stage(),
                    confirm: operation.confirm,
                    probe: operation.is_probe(),
                });
            }
            missing_providers.retain(|m| m != &binding.binary);
        }
    }

    // ── Staged dispatch ───────────────────────────────────────────────────
    // Every job carries the stage its catalog operation declared: 1 baseline,
    // 2 analysis, 3 consequential. Groups run in stage order, so analysis
    // never races the baseline it reads, and consequential work never starts
    // before the evidence it acts on exists. A stage whose predecessor
    // completed nothing is withdrawn rather than run — there is nothing to
    // analyse, and a run that manufactures activity out of silence is lying.
    // The common case, every operation at stage 1, is one group and one
    // dispatch: indistinguishable from the behaviour before stages existed.
    let mut stage_of: BTreeMap<String, u8> = BTreeMap::new();
    let mut stage_groups: BTreeMap<u8, Vec<Job>> = BTreeMap::new();
    let mut probe_ops: std::collections::HashSet<String> = std::collections::HashSet::new();
    for job in jobs.into_iter().chain(late_jobs) {
        if job.probe {
            probe_ops.insert(job.spec.id.to_string());
        }
        stage_of.insert(job.spec.id.to_string(), job.stage);
        stage_groups.entry(job.stage).or_default().push(job);
    }

    // One runner per dispatch: a runner owns its launch backend and is
    // consumed by the monitor, so each stage group builds its own.
    let build_runner = || {
        Runner::new(
            Launcher::new(OniuxBackend::new(&cfg.execution.oniux_binary)),
            RunnerConfig {
                kill_grace: Duration::from_millis(cfg.execution.kill_grace_ms),
                env: Vec::new(),
                // A tool given a bare output filename writes it to its working
                // directory. Left alone that is the operator's shell — and for a
                // run started from a checkout, the checkout: scanner reports and
                // harvested hostnames end up as untracked changes in the
                // repository. Running the child inside the run's own directory
                // means anything it writes lands with the manifest that
                // describes the run.
                cwd: Some(store.root().to_path_buf()),
            },
        )
    };

    // Operations the catalog marked consequential are gated once, at the
    // point the first of them would dispatch — after the baseline evidence
    // exists, so the operator decides with the run's real context on screen.
    // A decline withdraws every gated operation, this stage and later, and
    // the run continues with everything ungated.
    let mut confirm_declined = false;
    let mut records: Vec<(usize, crate::domain::execution::ExecutionRecord)> = Vec::new();
    let mut cancelled = false;
    // Whether the previous stage completed at least one task. `None` before
    // the first stage; stage 1 always dispatches.
    let mut prior_completed = true;
    for (stage, group) in stage_groups {
        let gated_labels: Vec<String> = group
            .iter()
            .filter(|j| j.confirm)
            .map(|j| j.spec.label.clone())
            .collect();
        if !confirm_declined && !gated_labels.is_empty() {
            let scope = values.get("authorized_scope");
            confirm_declined =
                !confirm_gate(theme, renderer, out, &cap.label, &gated_labels, scope)?;
        }

        // Partition: gated operations are withdrawn when declined; everything
        // else in the group still runs.
        let (mut to_withdraw, mut to_run): (Vec<Job>, Vec<Job>) = group
            .into_iter()
            .partition(|j| confirm_declined && j.confirm);

        // A later stage whose baseline completed nothing is withdrawn whole.
        if stage > 1 && !prior_completed {
            to_withdraw.append(&mut to_run);
        }

        for job in to_withdraw {
            let declined = confirm_declined && job.confirm;
            let error = if declined {
                TsecError::new(
                    Stage::ValidateCommands,
                    ExecutionErrorKind::ConfirmationDeclined {
                        tool: job.spec.provider.clone(),
                    },
                )
            } else {
                TsecError::new(
                    Stage::ValidateCommands,
                    ExecutionErrorKind::StageWithdrawn {
                        tool: job.spec.provider.clone(),
                        reason: format!(
                            "no operation of the preceding stage completed, so there is \
                             nothing for stage {stage} to work on"
                        ),
                    },
                )
            };
            let now = chrono::Utc::now();
            records.push((
                job.index,
                crate::domain::execution::ExecutionRecord {
                    task_id: job.spec.id.to_string(),
                    phase: phase_word.to_string(),
                    capability: cap.label.clone(),
                    provider: job.spec.provider.clone(),
                    operation: job.spec.operation.clone(),
                    label: job.spec.label.clone(),
                    command: job.command.display_redacted(&job.spec.sensitive_args),
                    program: job.spec.provider.clone(),
                    args: Vec::new(),
                    network: job.command.network,
                    boundary: crate::domain::execution::ExecBoundary::Oniux,
                    launched: String::new(),
                    uses_shell: false,
                    started_at: now,
                    finished_at: now,
                    duration_ms: 0,
                    exit_code: None,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    raw_output: job.spec.artifacts.primary.clone(),
                    stderr_output: Some(job.spec.artifacts.stderr.clone()),
                    status: crate::domain::execution::TaskStatus::Skipped,
                    error_code: Some(error.kind.code().to_string()),
                    error_message: Some(error.reason()),
                    harvest_section: None,
                },
            ));
        }

        if to_run.is_empty() {
            continue;
        }

        let batch = execution::execute(
            theme,
            out,
            renderer,
            to_run,
            phase_word,
            &cap.label,
            build_runner(),
            cfg.execution.max_concurrency,
        )
        .map_err(|e| TsecError::io("running the execution monitor", &e))?;
        cancelled |= batch.cancelled;
        let mut batch = batch;
        // Probe operations are expected to exit non-zero when their premise
        // is wrong — a decoder handed non-base64, an extractor handed a
        // non-archive. That is a completed negative result, not a failure:
        // the tool ran, answered the question, and its raw output is
        // evidence like any other. Only a process-level failure to launch
        // (spawn errors carry no EXIT_STATUS) still counts as a failure.
        for (_, record) in &mut batch.records {
            if probe_ops.contains(&record.task_id)
                && record.status == crate::domain::execution::TaskStatus::Failed
                && record.error_code.as_deref() == Some("EXIT_STATUS")
            {
                record.status = crate::domain::execution::TaskStatus::Complete;
                record.error_code = Some("PROBE_NEGATIVE".to_string());
                record.error_message = record
                    .error_message
                    .as_ref()
                    .map(|m| format!("probe answer: negative ({m})"));
            }
        }
        prior_completed = batch
            .records
            .iter()
            .any(|(_, r)| r.status == crate::domain::execution::TaskStatus::Complete);
        records.extend(batch.records);
    }
    let outcome = execution::RunOutcome { records, cancelled };

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
    //
    // A CTF run never takes this branch. A hunt that came back empty-handed
    // is a result — and a hunt stopped early still carries everything the
    // finished tools found — so a CTF run always reaches the harvest and its
    // document, even when nothing completed. The honest empty case is a
    // document that says so, not a missing one.
    if !(cap.phase == "ctf") && all_tasks_failed(&outcome.records) {
        return show_run_failure(theme, renderer, out, &outcome.records);
    }

    // ── Branch: some/all succeeded → Processing → Output ───────────────────
    // What the run actually left behind. Listing the directory is the only
    // honest answer: a tool can report success having written nothing, or write
    // something and say nothing.
    let artifacts: Vec<(String, u64)> = std::fs::read_dir(store.artifacts_dir())
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| {
                    let meta = e.metadata().ok()?;
                    if !meta.is_file() {
                        return None;
                    }
                    Some((e.file_name().to_string_lossy().into_owned(), meta.len()))
                })
                .collect()
        })
        .unwrap_or_default();
    let artifacts = &artifacts;

    // Challenge context, gathered from the operator's own inputs. Declared
    // here, once, and carried into the document header and the `ctf.json`
    // sidecar so the report states what the run was for. An empty flag
    // format disables extraction rather than failing the run: not every
    // challenge family is a flag hunt, and a pattern that cannot compile is
    // reported, never silently dropped.
    let flag_pattern = if cap.phase == "ctf" {
        let declared = values.get("flag_format").trim();
        if declared.is_empty() {
            None
        } else {
            match crate::ctf::FlagPattern::compile(declared) {
                Ok(pattern) => Some(pattern),
                Err(e) => {
                    return show_pattern_refused(theme, renderer, out, &cap.label, e.reason());
                }
            }
        }
    } else {
        None
    };
    let ctf_context = if cap.phase == "ctf" {
        Some(crate::store::CtfContext {
            flag_format: values.get("flag_format"),
            objective: values.get("challenge_desc"),
            scope: values.get("authorized_scope"),
        })
    } else {
        None
    };

    let header = OutputHeader {
        run_name: run_id.as_str(),
        phase: phase_word,
        capability: &cap.label,
        missing_providers: &missing_providers,
        install_notes: &install_notes,
        cancelled: outcome.cancelled,
        artifacts,
        ctf: ctf_context,
    };

    let mut processing = Processing::new(renderer, theme);
    processing
        .begin(out)
        .map_err(|e| TsecError::io("drawing processing screen", &e))?;

    let harvest = store.harvest_with_flags(
        &formats,
        &header,
        Some(&mut |stage: HarvestStage| {
            processing
                .stage_done(out, stage)
                .map_err(|e| TsecError::io("drawing processing screen", &e))
        }),
        flag_pattern.as_ref(),
    )?;

    // The CTF sidecar: per-operation outcomes and every flag candidate with
    // its provenance, written for every CTF run — including one where the
    // pattern matched nothing, because "no candidates" is a result too.
    if cap.phase == "ctf" {
        store.write_ctf_json(&harvest, &header, &stage_of)?;
    }

    let action = show_output(theme, renderer, out, &store.output_txt(), None)
        .map_err(|e| TsecError::io("drawing output screen", &e))?;

    match action {
        CloseAction::Cancel => Ok(Flow::Exit),
        CloseAction::Accept => Ok(Flow::NewRun),
        CloseAction::Back => Ok(Flow::NewRun),
    }
}

/// The confirmation gate for consequential operations.
///
/// Drawn in the capability's own box: what is about to run, why it is
/// gated, and the scope the operator declared. `Y` dispatches the gated
/// operations; `N`, `Esc` or `Ctrl+C` declines them and the run continues
/// without them. There is no default: an operator who does nothing is not
/// counted as having consented.
fn confirm_gate(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    capability: &str,
    operations: &[String],
    scope: &str,
) -> Result<bool> {
    let mut rows: Vec<(String, Role)> = vec![
        (format!("CAPABILITY: {capability}"), Role::Primary),
        (String::new(), Role::Muted),
        (
            format!(
                "{} CONSEQUENTIAL OPERATION{} REQUIRE{} YOUR GO-AHEAD:",
                operations.len(),
                if operations.len() == 1 { "" } else { "S" },
                if operations.len() == 1 { "S" } else { "" }
            ),
            Role::Warning,
        ),
    ];
    for label in operations.iter().take(8) {
        rows.push((format!("  {label}"), Role::Foreground));
    }
    if operations.len() > 8 {
        rows.push((
            format!("  … and {} more", operations.len() - 8),
            Role::Muted,
        ));
    }
    rows.push((String::new(), Role::Muted));
    rows.push((
        "These operations go beyond observation: they may authenticate to a".to_string(),
        Role::Muted,
    ));
    rows.push((
        "target, modify challenge state, or attempt an active exploit. They".to_string(),
        Role::Muted,
    ));
    rows.push((
        "run only against the authorized scope you declared for this run.".to_string(),
        Role::Muted,
    ));
    rows.push((format!("SCOPE: {scope}"), Role::Muted));

    let mut frame = box_frame(
        theme,
        Layout::Information,
        "CONFIRM CONSEQUENTIAL OPERATIONS",
        &rows,
    );
    frame.append(hint_frame(theme, "-[Y] RUN   -[N/ESC] SKIP THEM"));
    renderer
        .present(out, &frame)
        .map_err(|e| TsecError::io("drawing the confirmation gate", &e))?;
    loop {
        match next_input()? {
            Input::Resize => {
                renderer
                    .present(out, &frame)
                    .map_err(|e| TsecError::io("drawing the confirmation gate", &e))?;
            }
            Input::ScrollUp(n) => renderer.scroll_up(n),
            Input::ScrollDown(n) => renderer.scroll_down(n),
            Input::Key(key) => {
                if is_interrupt(&key) {
                    return Ok(false);
                }
                return Ok(matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y')));
            }
        }
    }
}

/// The `FLAG FORMAT REFUSED` screen: the operator's pattern could not be
/// compiled, so extraction would either fail or match everything. The run
/// stops here rather than harvesting with a filter that cannot be trusted;
/// the reason names the exact problem to fix.
fn show_pattern_refused(
    theme: &Theme,
    renderer: &mut Renderer,
    out: &mut io::Stdout,
    capability: &str,
    reason: &str,
) -> Result<Flow> {
    let rows: Vec<(String, Role)> = vec![
        (format!("CAPABILITY: {capability}"), Role::Primary),
        (String::new(), Role::Muted),
        (
            "The flag format you entered could not be used:".to_string(),
            Role::Warning,
        ),
        (format!("  {reason}"), Role::Error),
        (String::new(), Role::Muted),
        (
            "A flag format is an extraction filter, so it has to discriminate:".to_string(),
            Role::Muted,
        ),
        (
            "shorthand like `flag{...}` or a bounded regex such as".to_string(),
            Role::Muted,
        ),
        (
            "`[A-Za-z0-9_]+@challenge\\.local`. Patterns that match the empty".to_string(),
            Role::Muted,
        ),
        (
            "string, or that match ordinary text everywhere, are refused".to_string(),
            Role::Muted,
        ),
        (
            "because they would turn every artifact into false candidates.".to_string(),
            Role::Muted,
        ),
    ];

    let mut frame = box_frame(theme, Layout::Information, "FLAG FORMAT REFUSED", &rows);
    frame.append(hint_frame(theme, "-[ENTER] BACK"));
    renderer
        .present(out, &frame)
        .map_err(|e| TsecError::io("drawing the pattern-refused box", &e))?;
    let action =
        wait_close(out, renderer, &frame).map_err(|e| TsecError::io("reading a key", &e))?;
    match action {
        CloseAction::Cancel => Ok(Flow::Exit),
        _ => Ok(Flow::Continue),
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
