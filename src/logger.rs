//! Append-only file logger → /opt/sec/logs/sec.log
//! Supports optional sanitization of log messages when anonymity is enabled.

use anyhow::Result;
use chrono::Local;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag: when true, all log messages are sanitized before writing.
static SANITIZE_LOGS: AtomicBool = AtomicBool::new(false);

pub struct Logger {
    path: String,
}

impl Logger {
    /// Open (or create) the log file at `path`.
    pub fn open(path: &str) -> Result<Self> {
        // Ensure the parent directory exists.
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Touch the file so it exists.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Logger { path: path.to_string() })
    }

    /// Enable or disable log sanitization (strips private IPs, hostnames, etc.).
    pub fn set_sanitize(enabled: bool) {
        SANITIZE_LOGS.store(enabled, Ordering::Relaxed);
    }

    fn write_line(&self, level: &str, msg: &str) {
        let ts = Local::now().format("%Y-%m-%dT%H:%M:%SZ");

        // Sanitize the message if anonymity mode is active.
        let clean_msg = if SANITIZE_LOGS.load(Ordering::Relaxed) {
            crate::anonymity::sanitizer::sanitize(msg)
        } else {
            msg.to_string()
        };

        let line = format!("[{ts}] [{level}] {clean_msg}\n");
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&self.path) {
            let _ = f.write_all(line.as_bytes());
        }
    }

    pub fn info(&self, msg: &str)  { self.write_line("INFO",  msg); }
    pub fn warn(&self, msg: &str)  { self.write_line("WARN",  msg); }
    pub fn error(&self, msg: &str) { self.write_line("ERROR", msg); }
}

