//! Input prompts with validation for each InputKind.

use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Input, Select, History};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::config::Config;
use crate::tools::types::{InputKind, Mode};

// ── Compiled regexes (lazy) ────────────────────────────────────────────────

fn domain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$").unwrap())
}

fn ip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$").unwrap())
}

fn ports_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[\d,\-]+$").unwrap())
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Collect every input required by `mode`, returning a map of
/// placeholder → value.  Handles the special "recent files" UI for File inputs.
pub fn collect_inputs(mode: &Mode, config: &Config) -> Result<HashMap<String, String>> {
    let mut map: HashMap<String, String> = HashMap::new();

    for kind in mode.inputs {
        let value = match kind {
            InputKind::File | InputKind::Wordlist | InputKind::Payload => prompt_file(config)?,
            other => prompt_text(*other)?,
        };
        // For duplicate kinds the last value wins (uncommon in practice).
        map.insert(kind.placeholder().to_string(), value);
    }

    Ok(map)
}

// ── Internal helpers ───────────────────────────────────────────────────────

struct FileHistory {
    max: usize,
    history: std::collections::VecDeque<String>,
    path: std::path::PathBuf,
}

impl FileHistory {
    fn new(kind: InputKind) -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let mut path = std::path::PathBuf::from(home);
        path.push(".tsec_history");
        std::fs::create_dir_all(&path).ok();
        path.push(kind.placeholder());
        
        let history = if let Ok(contents) = std::fs::read_to_string(&path) {
            contents.lines().map(|s| s.to_string()).collect()
        } else {
            std::collections::VecDeque::new()
        };
        
        Self { max: 100, history, path }
    }
}

impl History<String> for FileHistory {
    fn read(&self, pos: usize) -> Option<String> {
        self.history.get(self.history.len().saturating_sub(pos + 1)).cloned()
    }

    fn write(&mut self, val: &String) {
        if self.history.back() != Some(val) {
            // Remove previous occurrence to move to the front
            self.history.retain(|x| x != val);
            self.history.push_back(val.clone());
            if self.history.len() > self.max {
                self.history.pop_front();
            }
            let contents = self.history.iter().cloned().collect::<Vec<_>>().join("\n");
            std::fs::write(&self.path, contents).ok();
        }
    }
}

/// Prompt for a text value, validating per-kind.
fn prompt_text(kind: InputKind) -> Result<String> {
    let theme = hacker_theme();
    let label = kind.label();

    let mut history = FileHistory::new(kind);

    let value: String = match kind {
        InputKind::Domain => Input::with_theme(&theme)
            .with_prompt(label)
            .history_with(&mut history)
            .validate_with(|s: &String| {
                if domain_re().is_match(s.trim()) { Ok(()) }
                else { Err(format!("'{}' does not look like a valid domain.", s)) }
            })
            .interact_text()?,

        InputKind::Ip => Input::with_theme(&theme)
            .with_prompt(label)
            .history_with(&mut history)
            .validate_with(|s: &String| {
                if ip_re().is_match(s.trim()) { Ok(()) }
                else { Err(format!("'{}' does not look like a valid IP or CIDR.", s)) }
            })
            .interact_text()?,

        InputKind::Url => Input::with_theme(&theme)
            .with_prompt(label)
            .history_with(&mut history)
            .validate_with(|s: &String| {
                let t = s.trim();
                if t.starts_with("http://") || t.starts_with("https://") { Ok(()) }
                else { Err("URL must begin with http:// or https://".to_string()) }
            })
            .interact_text()?,

        InputKind::Ports => Input::with_theme(&theme)
            .with_prompt(label)
            .history_with(&mut history)
            .validate_with(|s: &String| {
                if ports_re().is_match(s.trim()) { Ok(()) }
                else { Err("Ports must be digits, commas, or dashes (e.g. 80,443,8000-9000)".to_string()) }
            })
            .interact_text()?,

        _ => Input::with_theme(&theme)
            .with_prompt(label)
            .history_with(&mut history)
            .validate_with(|s: &String| {
                if s.trim().is_empty() { Err("Input cannot be empty.".to_string()) }
                else { Ok(()) }
            })
            .interact_text()?,
    };

    Ok(value.trim().to_string())
}

/// Prompt for a file path, showing recent output files as quick-picks.
fn prompt_file(config: &Config) -> Result<String> {
    let theme = hacker_theme();

    // Collect recent files from the output dir, newest first.
    let mut recent: Vec<(String, std::time::SystemTime)> = std::fs::read_dir(config.output_dir())
        .unwrap_or_else(|_| {
            // If the dir doesn't exist yet just return an empty iterator stub.
            std::fs::read_dir(".").unwrap()
        })
        .filter_map(|e| {
            let e = e.ok()?;
            let meta = e.metadata().ok()?;
            if !meta.is_file() { return None; }
            Some((e.path().to_string_lossy().into_owned(), meta.modified().ok()?))
        })
        .collect();
    recent.sort_by(|a, b| b.1.cmp(&a.1));
    // Removed truncate so all files are visible

    // Build menu: recent files + manual entry option.
    let manual_label = "[ Enter path manually ]";
    let mut options: Vec<String> = recent.iter().map(|(p, _)| p.clone()).collect();
    options.push(manual_label.to_string());

    let idx = Select::with_theme(&theme)
        .with_prompt("Select input file")
        .items(&options)
        .default(options.len() - 1)   // default = manual
        .max_length(15)               // paginate
        .interact_opt()?
        .unwrap_or(options.len() - 1);

    if idx == options.len() - 1 {
        // Manual path with existence validation.
        let path: String = Input::with_theme(&theme)
            .with_prompt("File path")
            .validate_with(|s: &String| {
                if std::path::Path::new(s.trim()).exists() { Ok(()) }
                else { Err(format!("File not found: '{}'", s)) }
            })
            .interact_text()?;
        Ok(path.trim().to_string())
    } else {
        Ok(recent[idx].0.clone())
    }
}

/// Green-on-black dialoguer theme (used for text inputs, confirms, etc.)
pub fn hacker_theme() -> ColorfulTheme {
    use dialoguer::console::Style;
    ColorfulTheme {
        defaults_style:       Style::new().green(),
        prompt_style:         Style::new().white().bold(),
        prompt_prefix:        dialoguer::console::style("?".to_string()).for_stderr().green(),
        prompt_suffix:        dialoguer::console::style("⇒".to_string()).green(),
        success_prefix:       dialoguer::console::style("[OK]".to_string()).green().bold(),
        success_suffix:       dialoguer::console::style("".to_string()).green(),
        error_prefix:         dialoguer::console::style("[ERR]".to_string()).red().bold(),
        error_style:          Style::new().red().bold(),
        hint_style:           Style::new().cyan().dim(),
        values_style:         Style::new().green(),
        active_item_style:    Style::new().green().bold(),
        inactive_item_style:  Style::new().white(),
        active_item_prefix:   dialoguer::console::style("→".to_string()).green().bold(),
        inactive_item_prefix: dialoguer::console::style(" ".to_string()).white(),
        checked_item_prefix:  dialoguer::console::style("[x]".to_string()).green(),
        unchecked_item_prefix: dialoguer::console::style("[ ]".to_string()).white(),
        picked_item_prefix:   dialoguer::console::style("→".to_string()).green().bold(),
        unpicked_item_prefix: dialoguer::console::style(" ".to_string()).white(),
    }
}
