//! The execution monitor and the processing-stage visualization.
//!
//! Two rules shape this module:
//!
//! * **One render owner.** Worker tasks never touch the terminal; they send
//!   [`Event`]s over a channel. This monitor is the only writer, and it draws
//!   one complete frame per tick (≈12 fps) through the shared renderer.
//! * **Every state is real.** A spinner glyph appears only while a child
//!   process is genuinely running; the instant it exits its tick, cross,
//!   timeout or cancelled marker takes its place. `Ctrl+C` asks
//!   `Stop ongoing operations? [y/N]` — default `N` means the run continues
//!   completely untouched — and only a confirmed `Y` cancels tasks, with
//!   evidence preserved and a partial manifest still written.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crossterm::event::KeyCode;

use crate::domain::command::Command;
use crate::domain::execution::{ExecutionRecord, TaskStatus};
use crate::exec::{Cancellation, Runner, TaskSpec};
use crate::store::HarvestStage;
use crate::ui::panel::{self, box_frame, hint_frame, Geometry, Layout, Renderer};
use crate::ui::spinner;
use crate::ui::theme::{Role, Theme};

// ── jobs and events ────────────────────────────────────────────────────────

/// One provider operation, ready to run.
#[derive(Debug)]
pub struct Job {
    pub index: usize,
    pub spec: TaskSpec,
    pub command: Command,
}

/// What a worker reports to the monitor. Workers render nothing themselves.
#[derive(Debug)]
pub enum Event {
    /// The task acquired its permit and its child is being launched.
    Started(usize),
    /// The task reached a terminal state.
    Finished(usize, Box<ExecutionRecord>),
    /// Every task is finished; the run is over.
    Done(Vec<(usize, ExecutionRecord)>),
}

/// What one capability run produced.
#[derive(Debug)]
pub struct RunOutcome {
    /// Records in catalog order, ready to commit.
    pub records: Vec<(usize, ExecutionRecord)>,
    /// Whether the operator confirmed a stop request.
    pub cancelled: bool,
}

// ── the monitor ────────────────────────────────────────────────────────────

struct TaskRow {
    index: usize,
    id: String,
    label: String,
    command: String,
    status: TaskStatus,
    error: Option<String>,
    started: bool,
}

impl TaskRow {
    fn new(job: &Job) -> Self {
        Self {
            index: job.index,
            id: job.spec.id.to_string(),
            label: job.spec.label.clone(),
            command: job.command.display_redacted(&job.spec.sensitive_args),
            status: TaskStatus::Pending,
            error: None,
            started: false,
        }
    }
}

/// Run every job concurrently and watch it happen.
///
/// This owns the whole execution screen: it spawns the worker thread (which
/// owns the tokio runtime), renders per-operation status while the run goes,
/// handles the stop confirmation, and returns the finished records.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    theme: &Theme,
    out: &mut io::Stdout,
    renderer: &mut Renderer,
    title: &str,
    jobs: Vec<Job>,
    phase: &str,
    capability: &str,
    runner: Runner,
    max_concurrency: usize,
) -> io::Result<RunOutcome> {
    let rows: Vec<TaskRow> = jobs.iter().map(TaskRow::new).collect();
    let total = rows.len();
    let cancel = Cancellation::new();
    let (tx, rx) = mpsc::channel::<Event>();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| io::Error::other(format!("creating the runtime: {e}")))?;

    let worker_cancel = cancel.clone();
    let worker_tx = tx.clone();
    let done_tx = tx.clone();
    let worker_phase = phase.to_string();
    let worker_capability = capability.to_string();
    let worker: JoinHandle<Vec<(usize, ExecutionRecord)>> = thread::spawn(move || {
        let records = run_jobs(
            runtime,
            runner,
            jobs,
            worker_phase,
            worker_capability,
            worker_cancel,
            max_concurrency,
            worker_tx,
        );
        // The single end-of-run signal; if this thread panics instead, the
        // monitor notices the closed channel and stops with what it has.
        let _ = done_tx.send(Event::Done(records.clone()));
        records
    });

    let mut monitor = Monitor {
        theme,
        out,
        renderer,
        title: title.to_string(),
        rows,
        rx,
        cancel,
        active: 0,
        top: 0,
        confirm: false,
        cancelled: false,
        total,
        started: Instant::now(),
        last_draw: Instant::now(),
        tick: 0,
    };
    let outcome = monitor.run()?;

    // The worker has already reported Done, so this joins a finished thread.
    let _ = worker.join();
    Ok(outcome)
}

struct Monitor<'a> {
    theme: &'a Theme,
    out: &'a mut io::Stdout,
    renderer: &'a mut Renderer,
    title: String,
    rows: Vec<TaskRow>,
    rx: Receiver<Event>,
    cancel: Cancellation,
    /// Task whose state changed most recently, kept in view.
    active: usize,
    top: usize,
    confirm: bool,
    cancelled: bool,
    total: usize,
    started: Instant,
    last_draw: Instant,
    tick: usize,
}

impl Monitor<'_> {
    fn run(&mut self) -> io::Result<RunOutcome> {
        let mut records: Vec<(usize, ExecutionRecord)> = Vec::new();
        let mut finished_run = false;

        loop {
            // 1. Drain every event the workers have queued.
            let mut dirty = false;
            while let Ok(event) = self.rx.try_recv() {
                dirty = true;
                match event {
                    Event::Started(index) => {
                        if let Some(row) = self.rows.iter_mut().find(|r| r.index == index) {
                            row.status = TaskStatus::Running;
                            row.started = true;
                        }
                        self.active = index;
                    }
                    Event::Finished(index, record) => {
                        if let Some(row) = self.rows.iter_mut().find(|r| r.index == index) {
                            row.status = record.status;
                            row.error = record.error_message.clone();
                            row.started = true;
                        }
                        self.active = index;
                        records.push((index, *record));
                    }
                    Event::Done(_) => finished_run = true,
                }
            }
            // A panicked worker closes the channel; the per-task records that
            // did arrive are still real evidence and are still returned.
            if let Err(mpsc::TryRecvError::Disconnected) = self.rx.try_recv() {
                finished_run = true;
            }

            // 2. Draw at most ~12 frames per second — enough for a living
            //    spinner, never fast enough to flicker.
            if dirty || self.last_draw.elapsed() >= spinner::TICK {
                self.draw()?;
                self.last_draw = Instant::now();
                self.tick = self.tick.wrapping_add(1);
            }

            if finished_run {
                // Final picture: every task in its terminal state.
                self.draw()?;
                records.sort_by_key(|(index, _)| *index);
                return Ok(RunOutcome {
                    records,
                    cancelled: self.cancelled,
                });
            }

            // 3. Wait for a key, a resize, or the next tick.
            let wait = spinner::TICK
                .saturating_sub(self.last_draw.elapsed())
                .max(std::time::Duration::from_millis(10));
            match panel::poll_input(wait)? {
                Some(panel::Input::Resize) => {
                    self.draw()?;
                    self.last_draw = Instant::now();
                }
                Some(panel::Input::Key(key)) => self.on_key(&key)?,
                None => {}
            }
        }
    }

    fn on_key(&mut self, key: &crossterm::event::KeyEvent) -> io::Result<()> {
        if self.confirm {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    // Stop: cancel every task, preserve the evidence already
                    // collected, and let the run finalise partially.
                    self.cancel.cancel();
                    self.cancelled = true;
                    self.confirm = false;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Enter | KeyCode::Esc => {
                    // Continue: nothing is touched — no kill, no reset, no
                    // cleared results. The run resumes exactly where it was.
                    self.confirm = false;
                }
                _ if panel::is_interrupt(key) => self.confirm = false,
                _ => {}
            }
        } else if panel::is_interrupt(key) {
            // Ask, never act. Escape during execution is deliberately inert so
            // an accidental key press cannot kill child processes.
            self.confirm = true;
        }
        self.draw()?;
        self.last_draw = Instant::now();
        Ok(())
    }

    // ── rendering ──────────────────────────────────────────────────────────

    fn draw(&mut self) -> io::Result<()> {
        let g = Geometry::detect();
        // Chrome: four border/title rows plus the hint line under the box.
        let max_body = g.body_rows(5);
        let lines = self.body_lines(g.inner.saturating_sub(2));
        let total_lines = lines.len();

        // Keep the most recently active task on screen.
        let start = lines
            .iter()
            .position(|(_, _, task)| Some(*task) == Some(self.active))
            .unwrap_or(0);
        if start < self.top {
            self.top = start;
        }
        if start >= self.top + max_body {
            self.top = start + 1 - max_body;
        }
        self.top = self.top.min(total_lines.saturating_sub(max_body));

        let window: Vec<(String, Role)> = lines
            .iter()
            .skip(self.top)
            .take(max_body)
            .map(|(text, role, _)| (text.clone(), *role))
            .collect();

        let mut frame = box_frame(self.theme, Layout::Execution, &self.title, &window);
        frame.append(hint_frame(self.theme, &self.hint()));
        self.renderer.present(self.out, &frame)
    }

    /// Every body line, tagged with the task it belongs to (usize::MAX for
    /// chrome rows), followed by the tally and the confirmation prompt.
    fn body_lines(&self, content: usize) -> Vec<(String, Role, usize)> {
        let total = self.total;
        let mut lines: Vec<(String, Role, usize)> = Vec::new();
        let none = usize::MAX;

        for row in &self.rows {
            let marker = match row.status {
                TaskStatus::Running => spinner::frame(self.tick).to_string(),
                other => other.marker().to_string(),
            };
            let status = status_label(row.status);
            let head = format!("{marker} {} {}", row.id, row.label);
            // Right-align the status word within the row, in the row's colour.
            let status_w = unicode_width::UnicodeWidthStr::width(status);
            let head = panel::fit(&head, content.saturating_sub(status_w + 1));
            lines.push((format!("{head}{status}"), role_for(row.status), row.index));

            if row.status != TaskStatus::Pending {
                lines.push((format!("  {}", row.command), Role::Secondary, row.index));
                if let Some(error) = &row.error {
                    lines.push((format!("  ! {error}"), Role::Error, row.index));
                }
            }
        }

        let running = self
            .rows
            .iter()
            .filter(|r| r.status == TaskStatus::Running)
            .count();
        let queued = self
            .rows
            .iter()
            .filter(|r| r.status == TaskStatus::Pending)
            .count();
        let finished = self.total - running - queued;
        lines.push((String::new(), Role::Muted, none));
        lines.push((
            format!(
                "{finished}/{total} FINISHED · {running} RUNNING · {queued} QUEUED · ELAPSED {}",
                elapsed(self.started)
            ),
            Role::Muted,
            none,
        ));

        if self.confirm {
            lines.push((String::new(), Role::Muted, none));
            lines.push((
                "Stop ongoing operations? [y/N]".to_string(),
                Role::Warning,
                none,
            ));
        }
        lines
    }

    fn hint(&self) -> String {
        if self.confirm {
            "-[Y] STOP OPERATIONS   -[N] CONTINUE".to_string()
        } else if self.cancelled {
            "-[STOPPING OPERATIONS]".to_string()
        } else {
            "-[CTRL+C] STOP OPERATIONS".to_string()
        }
    }
}

fn status_label(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Pending => "QUEUED",
        TaskStatus::Running => "RUNNING",
        TaskStatus::Complete => "COMPLETE",
        TaskStatus::Failed => "FAILED",
        TaskStatus::TimedOut => "TIMED OUT",
        TaskStatus::Skipped => "SKIPPED",
        TaskStatus::Interrupted => "CANCELLED",
    }
}

fn role_for(status: TaskStatus) -> Role {
    match status {
        TaskStatus::Pending => Role::Muted,
        TaskStatus::Running => Role::Primary,
        TaskStatus::Complete => Role::Success,
        TaskStatus::Failed => Role::Error,
        TaskStatus::TimedOut => Role::Warning,
        TaskStatus::Skipped => Role::Muted,
        TaskStatus::Interrupted => Role::Warning,
    }
}

fn elapsed(since: Instant) -> String {
    let secs = since.elapsed().as_secs();
    format!("{}:{:02}", secs / 60, secs % 60)
}

// ── the worker side ────────────────────────────────────────────────────────

/// Execute every job, at most `max_concurrency` at a time, reporting events.
///
/// Concurrency is bounded by a semaphore rather than by chunking the list, so
/// a slow tool never holds back a fast one. Results come back unordered and
/// are sorted by the caller; a task interrupted before it started still
/// returns its record, because partial evidence is evidence.
#[allow(clippy::too_many_arguments)]
fn run_jobs(
    runtime: tokio::runtime::Runtime,
    runner: Runner,
    jobs: Vec<Job>,
    phase: String,
    capability: String,
    cancel: Cancellation,
    max_concurrency: usize,
    tx: Sender<Event>,
) -> Vec<(usize, ExecutionRecord)> {
    let permits = Arc::new(tokio::sync::Semaphore::new(max_concurrency.max(1)));
    let runner = Arc::new(runner);

    runtime.block_on(async move {
        let mut set = tokio::task::JoinSet::new();
        for job in jobs {
            let runner = runner.clone();
            let permits = permits.clone();
            let cancel = cancel.clone();
            let phase = phase.clone();
            let capability = capability.clone();
            let tx = tx.clone();
            set.spawn(async move {
                // The semaphore is never closed, so this cannot fail; the permit
                // lives until the task returns.
                let _permit = permits.acquire_owned().await;

                // A cancelled run never launches anything new: no spawn, no
                // preflight, no network — the task records itself as cancelled
                // with its capture files already in place.
                if cancel.is_cancelled() {
                    let completed =
                        runner.cancelled_before_start(&job.spec, &job.command, &phase, &capability);
                    let record = completed.record;
                    let index = job.index;
                    let _ = tx.send(Event::Finished(index, Box::new(record.clone())));
                    return (index, record);
                }

                let _ = tx.send(Event::Started(job.index));
                let completed = runner
                    .run(&job.spec, &job.command, &phase, &capability, &cancel)
                    .await;
                let record = completed.record;
                let index = job.index;
                let _ = tx.send(Event::Finished(index, Box::new(record.clone())));
                (index, record)
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

// ── processing stages ──────────────────────────────────────────────────────

/// Draws the `PROCESSING` box while the real harvest pipeline runs.
///
/// The caller invokes [`Processing::stage_done`] from inside the store's
/// stage callback, so each tick appears exactly when the corresponding real
/// operation (parsing, normalising, deduplicating, correlating, harvesting,
/// writing) has actually finished — there is no sleep and no animation that
/// is not backed by work.
#[derive(Debug)]
pub struct Processing<'a> {
    renderer: &'a mut Renderer,
    theme: &'a Theme,
    done: usize,
    tick: usize,
}

impl<'a> Processing<'a> {
    pub fn new(renderer: &'a mut Renderer, theme: &'a Theme) -> Self {
        Self {
            renderer,
            theme,
            done: 0,
            tick: 0,
        }
    }

    /// Draw with the first stage running.
    pub fn begin(&mut self, out: &mut io::Stdout) -> io::Result<()> {
        self.draw(out)
    }

    /// Mark `stage` complete and redraw with the next stage running.
    pub fn stage_done(&mut self, out: &mut io::Stdout, stage: HarvestStage) -> io::Result<()> {
        self.done = HarvestStage::ALL
            .iter()
            .position(|s| *s == stage)
            .map(|i| i + 1)
            .unwrap_or(self.done);
        self.tick = self.tick.wrapping_add(1);
        self.draw(out)
    }

    fn draw(&mut self, out: &mut io::Stdout) -> io::Result<()> {
        let mut rows: Vec<(String, Role)> = Vec::new();
        for (index, stage) in HarvestStage::ALL.iter().enumerate() {
            let label = stage.label();
            let row = if index < self.done {
                (format!("✓ {label}"), Role::Success)
            } else if index == self.done {
                (
                    format!("{} {label}", spinner::frame(self.tick)),
                    Role::Primary,
                )
            } else {
                (format!("○ {label}"), Role::Muted)
            };
            rows.push(row);
        }
        let frame = box_frame(self.theme, Layout::Execution, "PROCESSING", &rows);
        self.renderer.present(out, &frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_labels_match_the_operator_contract() {
        assert_eq!(status_label(TaskStatus::Pending), "QUEUED");
        assert_eq!(status_label(TaskStatus::Interrupted), "CANCELLED");
        assert_eq!(status_label(TaskStatus::TimedOut), "TIMED OUT");
        assert!(status_label(TaskStatus::Failed)
            .chars()
            .all(|c| !c.is_lowercase()));
    }

    #[test]
    fn terminal_states_get_terminal_colours() {
        assert!(matches!(role_for(TaskStatus::Complete), Role::Success));
        assert!(matches!(role_for(TaskStatus::Failed), Role::Error));
        assert!(matches!(role_for(TaskStatus::Running), Role::Primary));
        assert!(matches!(role_for(TaskStatus::Pending), Role::Muted));
    }

    #[test]
    fn elapsed_formats_as_minutes_and_seconds() {
        assert!(elapsed(Instant::now()).contains(':'));
    }
}
