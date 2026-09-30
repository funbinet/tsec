//! A one-line progress indicator for the duration of a task.
//!
//! The runner is synchronous from the caller's point of view, so the animation
//! lives on its own thread and stops the moment the task ends. A task that
//! never completes never claims to have completed: the line simply keeps
//! turning until the timeout or an interrupt ends it.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::{cursor, execute};

const FRAMES: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
const TICK: Duration = Duration::from_millis(90);

/// A turning line with a label, stopped by [`Spinner::stop`] or by drop.
#[derive(Debug)]
pub struct Spinner {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Spinner {
    /// Start turning `label` until stopped.
    pub fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            let mut frame = 0usize;
            while !flag.load(Ordering::Relaxed) {
                let mut out = std::io::stdout();
                let _ = execute!(
                    out,
                    SetForegroundColor(Color::DarkGrey),
                    Print(format!("\r{} {}", FRAMES[frame % FRAMES.len()], label)),
                    ResetColor
                );
                let _ = out.flush();
                frame += 1;
                thread::sleep(TICK);
            }
            let mut out = std::io::stdout();
            let _ = execute!(
                out,
                cursor::MoveToColumn(0),
                Print(" ".repeat(label.len() + 4))
            );
            let _ = execute!(out, cursor::MoveToColumn(0), ResetColor);
            let _ = out.flush();
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    /// Stop the animation and clear the line.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.halt();
    }
}
