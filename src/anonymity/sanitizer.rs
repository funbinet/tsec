//! Output sanitizer — strips private IPs, MAC addresses, hostnames,
//! usernames, and home directory paths from command output and files.

use regex::Regex;
use std::sync::OnceLock;

// ── Compiled regexes (lazy singletons) ─────────────────────────────────

fn private_ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:^|\b)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?:\b|$)"
        ).unwrap()
    })
}

fn mac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}"
        ).unwrap()
    })
}

fn home_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"/home/[a-zA-Z0-9_\-]+").unwrap()
    })
}

// ── Public API ─────────────────────────────────────────────────────────

/// Sanitize a string by replacing identifying information with redaction markers.
pub fn sanitize(text: &str) -> String {
    let mut result = text.to_string();

    // 1. Replace private IPv4 addresses
    result = private_ipv4_re()
        .replace_all(&result, "[REDACTED_IP]")
        .into_owned();

    // 2. Replace MAC addresses
    result = mac_re()
        .replace_all(&result, "[REDACTED_MAC]")
        .into_owned();

    // 3. Replace home directory paths
    result = home_path_re()
        .replace_all(&result, "[REDACTED_PATH]")
        .into_owned();

    // 4. Replace current system hostname
    if let Ok(hostname) = hostname::get() {
        let hn = hostname.to_string_lossy();
        if !hn.is_empty() && hn.len() > 2 {
            result = result.replace(&*hn, "[REDACTED_HOST]");
        }
    }

    // 5. Replace current username
    if let Ok(user) = std::env::var("USER") {
        if !user.is_empty() && user.len() > 2 {
            result = result.replace(&user, "[REDACTED_USER]");
        }
    } else if let Ok(user) = std::env::var("LOGNAME") {
        if !user.is_empty() && user.len() > 2 {
            result = result.replace(&user, "[REDACTED_USER]");
        }
    }

    result
}

/// Sanitize a file in place — reads, sanitizes, writes back.
pub fn sanitize_file(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let sanitized = sanitize(&content);
    std::fs::write(path, sanitized)?;
    Ok(())
}
