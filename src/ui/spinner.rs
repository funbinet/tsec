// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    width: usize,
}

impl std::fmt::Debug for Spinner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spinner")
            .field("width", &self.width)
            .finish()
    }
}

impl Spinner {
    pub fn start(msg: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let msg = msg.to_string();
        let width = msg.len() + 6;

        let handle = thread::spawn(move || {
            let mut i = 0usize;
            while !stop2.load(Ordering::Relaxed) {
                let frame = FRAMES[i % FRAMES.len()];
                print!("\r\x1b[36m{}\x1b[0m \x1b[37m{}\x1b[0m   ", frame, msg);
                let _ = io::stdout().flush();
                thread::sleep(Duration::from_millis(80));
                i += 1;
            }
        });

        Spinner {
            stop,
            handle: Some(handle),
            width,
        }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        print!("\r{}\r", " ".repeat(self.width + 4));
        let _ = io::stdout().flush();
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        print!("\r{}\r", " ".repeat(self.width + 4));
        let _ = io::stdout().flush();
    }
}
