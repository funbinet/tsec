//! Output parser — converts raw command output into a structured form.

use crate::tools::types::OutputFormat;
use regex::Regex;

/// Parsed result ready for display.
#[derive(Debug, Default)]
pub struct ParsedOutput {
    /// Individual lines (for Lines / Nmap / Csv).
    pub lines: Vec<String>,
    /// Pretty-printed text ready for display (may differ from `lines` join).
    pub display: String,
    /// One-line human-readable summary ("Found 42 subdomains", "8 ports open", …).
    pub summary: String,
    /// Raw bytes of the original output (kept for fallback display).
    #[allow(dead_code)]
    pub raw: String,
}

/// Parse raw command output according to the declared format.
pub fn parse_output(raw: &str, fmt: OutputFormat) -> ParsedOutput {
    match fmt {
        OutputFormat::Lines => parse_lines(raw),
        OutputFormat::Json  => parse_json(raw),
        OutputFormat::Xml   => parse_xml(raw),
        OutputFormat::Nmap  => parse_nmap(raw),
        OutputFormat::Csv   => parse_csv(raw),
        OutputFormat::Raw   => parse_raw(raw),
    }
}

// ── Format-specific parsers ────────────────────────────────────────────────

fn parse_lines(raw: &str) -> ParsedOutput {
    let lines: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    let count = lines.len();
    ParsedOutput {
        display: lines.join("\n"),
        summary: format!("Found {} line{}", count, if count == 1 { "" } else { "s" }),
        lines,
        raw: raw.to_string(),
    }
}

fn parse_json(raw: &str) -> ParsedOutput {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) => {
            let pretty = serde_json::to_string_pretty(&v).unwrap_or_else(|_| raw.to_string());
            let count = match &v {
                serde_json::Value::Array(a) => a.len(),
                serde_json::Value::Object(o) => o.len(),
                _ => 0,
            };
            let lines: Vec<String> = pretty.lines().map(String::from).collect();
            ParsedOutput {
                display: pretty,
                summary: if count > 0 {
                    format!("{} JSON item{}", count, if count == 1 { "" } else { "s" })
                } else {
                    "JSON parsed successfully".to_string()
                },
                lines,
                raw: raw.to_string(),
            }
        }
        // If the raw output is JSONL (one JSON object per line), parse each line.
        Err(_) => {
            let valid_lines: Vec<serde_json::Value> = raw
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            if valid_lines.is_empty() {
                // Not JSON at all — fall back to plain lines.
                parse_lines(raw)
            } else {
                let count = valid_lines.len();
                let display = valid_lines
                    .iter()
                    .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("\n---\n");
                let lines: Vec<String> = display.lines().map(String::from).collect();
                ParsedOutput {
                    summary: format!("{} JSON record{}", count, if count == 1 { "" } else { "s" }),
                    display,
                    lines,
                    raw: raw.to_string(),
                }
            }
        }
    }
}

fn parse_nmap(raw: &str) -> ParsedOutput {
    // Extract open port lines: e.g. "80/tcp   open  http"
    let re = Regex::new(r"(\d+/\w+)\s+open\s+(\S+)").expect("nmap regex");
    let mut open_ports: Vec<String> = Vec::new();
    for cap in re.captures_iter(raw) {
        open_ports.push(format!("{:20} {}", &cap[1], &cap[2]));
    }

    let all_lines: Vec<String> = raw.lines().map(String::from).collect();
    let count = open_ports.len();

    ParsedOutput {
        lines: all_lines.clone(),
        display: all_lines.join("\n"),
        summary: format!("{} open port{}", count, if count == 1 { "" } else { "s" }),
        raw: raw.to_string(),
    }
}

fn parse_csv(raw: &str) -> ParsedOutput {
    let lines: Vec<String> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect();

    // Build a simple aligned table display.
    let display = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if i == 0 {
                format!("  {}", l) // header
            } else {
                format!("  {}", l)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let data_rows = lines.len().saturating_sub(1); // exclude header
    ParsedOutput {
        summary: format!("{} CSV row{}", data_rows, if data_rows == 1 { "" } else { "s" }),
        display,
        lines,
        raw: raw.to_string(),
    }
}

fn parse_xml(raw: &str) -> ParsedOutput {
    // No full XML parser — just clean up and show a line count.
    let lines: Vec<String> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect();
    let count = lines.len();
    ParsedOutput {
        display: lines.join("\n"),
        summary: format!("XML output — {} line{}", count, if count == 1 { "" } else { "s" }),
        lines,
        raw: raw.to_string(),
    }
}

fn parse_raw(raw: &str) -> ParsedOutput {
    let lines: Vec<String> = raw.lines().map(String::from).collect();
    let count = lines.len();
    ParsedOutput {
        display: raw.to_string(),
        summary: format!("{} line{} of output", count, if count == 1 { "" } else { "s" }),
        lines,
        raw: raw.to_string(),
    }
}
