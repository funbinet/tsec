//! Braille spinner — runs on a background thread during command execution.

use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub struct Spinner {
    stop:   Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    width:  usize, // chars to clear on stop
}

impl Spinner {
    /// Start the spinner on a background thread.  Returns immediately.
    pub fn start(msg: &str) -> Self {
        let stop   = Arc::new(AtomicBool::new(false));
        let stop2  = Arc::clone(&stop);
        let msg    = msg.to_string();
        let width  = msg.len() + 6;

        let handle = thread::spawn(move || {
            let mut i = 0usize;
            while !stop2.load(Ordering::Relaxed) {
                let frame = FRAMES[i % FRAMES.len()];
                // Cyan spinner frame + white message.
                print!("\r\x1b[36m{}\x1b[0m \x1b[37m{}\x1b[0m   ", frame, msg);
                let _ = io::stdout().flush();
                thread::sleep(Duration::from_millis(80));
                i += 1;
            }
        });

        Spinner { stop, handle: Some(handle), width }
    }

    /// Stop the spinner and erase the line.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Erase spinner line.
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
