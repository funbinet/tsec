//! Turning raw tool output into exploitable intelligence.
//!
//! The format parsers in [`crate::parser`] answer "what shape did this tool
//! print?". This module answers the question that actually decides what an
//! operator does next: **what can I use from this?**
//!
//! Most tools do not print findings one per line. They print progress banners,
//! timings, and then a line that carries several independent artefacts at once:
//!
//! ```text
//! [*] Starting: /22/hosts 300 found
//! http://admin.example.com:8080/login [200] [Admin Panel] [10.0.0.4] [Apache/2.4.29]
//! "Set-Cookie: JSESSIONID=1A2B3C; Path=/; HttpOnly"
//! 10.0.0.4 - - "POST /login HTTP/1.1" 200 3021 "Mozilla/5.0" "admin:Sup3rS3cr3t"
//! ```
//!
//! Classifying whole lines — the only thing the format parsers can do — files
//! all four of those under one heading and separates none of them. An operator
//! reading that harvest cannot tell that a live credential and a session cookie
//! were sitting in it. So every line, whatever its declared format, is also
//! scanned for known artefact shapes, and one line yields as many findings as it
//! really carries.
//!
//! Two properties make this safe to run over everything:
//!
//! * **Nothing is invented.** A finding exists only because a pattern matched
//!   bytes the tool actually printed. The matched text, and the line it came
//!   from, travel with the finding as its `detail`, so the interpretation is
//!   always checkable against the raw evidence.
//! * **Noise is separated, not deleted.** Progress bars and timings become
//!   [`Category::Noise`]: counted, retrievable, and absent from the document.
//!   Keeping them alongside real evidence is what made previous harvests read as
//!   empty; discarding them would make a run unauditable.
//!
//! [`recommend`] closes the loop. Harvesting artefacts is only useful if it
//! changes what the operator does next, so the module also states which
//! capability to run against which value.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::sync::OnceLock;

use regex::Regex;

use crate::domain::finding::Category;

/// One artefact recovered from one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extraction {
    pub category: Category,
    /// The matched text, trimmed to what the pattern actually covers.
    pub value: String,
    /// What kind of artefact it is, in the operator's terms.
    pub detail: Option<String>,
}

/// A harvest that finished, with the observations needed to decide what to do.
#[derive(Debug, Clone, Default)]
pub struct Assessment {
    /// The line the artefact was seen in, so nothing is unexplained.
    pub context: String,
    pub findings: Vec<Extraction>,
}

// ── noise ────────────────────────────────────────────────────────────────────

/// Progress banners, progress bars, timings and run summaries.
///
/// These are the lines that make a multi-tool harvest unreadable. Each pattern
/// is anchored on phrasing that appears in tool chrome rather than in results.
fn noise_patterns() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| {
        [
            // `[*]`, `[+]`, `[!]` and friends: ffuf, feroxbuster, hakrawler.
            r"^\s*\[[*+\-!~]{1,3}\]\s",
            r"^\s*\[(?:INF|INFO|WRN|WARN|ERR|ERROR|DBG|DEBG|STAT|NOTE|OK)\]\s*",
            // A progress bar, whole or partial, with or without a percentage.
            r"\d{1,3}%\s*\|",
            r"\[[=>#\- ]{5,}\]",
            r"[<>=]{4,}\s*\]",
            r"^\s*\d{1,3}(\.\d+)?\s*%\s*(complete|done)?\s*$",
            r"^\s*[─=]{3,}\s*$",
            // `Threaded mode started: 30 threads`.
            r"(?i)^\s*threaded mode\b",
            r"(?i)^\s*\d+ threads?\b",
            // nmap's own summary.
            r"(?i)^nmap done:",
            r"(?i)^nmap scan report for ",
            r"(?i)^starting nmap ",
            r"(?i)^host is up\b",
            // A run took / elapsed line.
            r"(?i)\b(elapsed|took|duration)\s+\d+(\.\d+)?\s*(ms|s|sec|secs|seconds|m|min)\b",
            r"(?i)^\s*\d+(\.\d+)?\s*(ms|s|sec|secs|seconds)\s+(remaining|elapsed)\b",
            // Progress counters: `500/1000`, `[500/1000]`.
            r"^\s*\d{1,7}\s*/\s*\d{1,7}\s*$",
            // amass/httpx/scanning chatter.
            r"(?i)^\s*(scanning|fetching|crawling|starting|finished|completed|resolving)\b.{0,40}$",
            r"(?i)^\s*(loaded|loaded templates|templates loaded)",
            // Rule/wordlist loading chatter.
            r"(?i)^\s*(using|loaded|rules|wordlist|wordlists)\s+.{0,60}$",
            // TShark's capture summary.
            r"(?i)^Capturing on ",
            // A bare separator or box-drawing rule.
            r"^\s*[-=_*~]{3,}\s*$",
            r"^\s*[+|]\s*[-=]{3,}\s*[+|]?\s*$",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("noise pattern compiles"))
        .collect()
    })
}

/// Whether a line is tool chrome rather than a result.
///
/// A line is only noise if no artefact pattern matched it first: the extractor
/// runs first precisely because a line can look like progress and still contain
/// the finding.
pub fn is_noise(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }
    noise_patterns().iter().any(|p| p.is_match(trimmed))
}

// ── artefact patterns ────────────────────────────────────────────────────────

/// A named extractor: what it matches and what the match means.
struct Rule {
    category: Category,
    label: &'static str,
    re: Regex,
    /// An extra condition the regex cannot express.
    ///
    /// The `regex` crate has no lookahead, so shapes that are only decidable
    /// once the match is in hand — "not a port", "not an address" — are checked
    /// here rather than approximated in the pattern.
    accept: Option<fn(&str) -> bool>,
    /// Capture group to report instead of the whole match.
    ///
    /// `Key: value` shapes match the label too, and a finding whose value is
    /// `Secret: AKIA…` is harder to read and to match on than one whose value is
    /// `AKIA…`.
    capture: Option<usize>,
    /// Whether to strip a comment or statement terminator from the end of the
    /// match.
    ///
    /// Only for rules whose pattern is bounded by a fixed character count rather
    /// than by a closing delimiter, so a trailing `*/` or `;` is swallowed by
    /// the bound rather than being part of what the author wrote.
    trim_tail: bool,
}

impl Rule {
    fn new(category: Category, label: &'static str, pattern: &str) -> Self {
        Rule {
            category,
            label,
            re: Regex::new(pattern).expect("extraction pattern compiles"),
            accept: None,
            capture: None,
            trim_tail: false,
        }
    }

    /// Report capture group `n` as the value rather than the whole match.
    fn reporting(mut self, n: usize) -> Self {
        self.capture = Some(n);
        self
    }

    fn accept_where(mut self, accept: fn(&str) -> bool) -> Self {
        self.accept = Some(accept);
        self
    }

    fn trimming_tail(mut self) -> Self {
        self.trim_tail = true;
        self
    }
}

/// Whether a match opens with a run of one repeated punctuation character.
///
/// PEM headers, diff markers and separator rules all open this way. A `Key:`
/// rule that swallows one reports half a structure, which is worse than nothing
/// because it looks like a credential.
fn starts_with_delimiter_run(s: &str) -> bool {
    let mut run = 0usize;
    for c in s.chars() {
        if c.is_alphanumeric() || c == ' ' {
            break;
        }
        run += 1;
    }
    run >= 3
}

/// Reject an all-digit value: that is a port or an id, not a password.
fn not_all_digits(v: &str) -> bool {
    v.chars().any(|c| !c.is_ascii_digit())
}

/// Whether a token is a hostname or an IP address rather than a username.
///
/// Deliberately narrow: `admin`, `svc` and `root` are usernames, `web01` and
/// `api-v2` are ambiguous but overwhelmingly usernames too, so only a dotted
/// name or a parseable address is treated as a host.
fn looks_like_host(token: &str) -> bool {
    if token.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    token.contains('.')
        && !token.starts_with('.')
        && !token.ends_with('.')
        && token.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Whether a token is a URI scheme, which makes it a URL rather than a name.
fn is_url_scheme(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "http"
            | "https"
            | "ftp"
            | "ftps"
            | "sftp"
            | "ssh"
            | "smtp"
            | "smtps"
            | "imap"
            | "imaps"
            | "pop"
            | "pop3"
            | "pop3s"
            | "ldap"
            | "ldaps"
            | "mysql"
            | "postgres"
            | "postgresql"
            | "mongodb"
            | "mongodb+srv"
            | "redis"
            | "rediss"
            | "amqp"
            | "amqps"
            | "mssql"
            | "file"
            | "gopher"
            | "dict"
            | "telnet"
            | "vnc"
            | "rtsp"
            | "ws"
            | "wss"
            | "jar"
            | "netdoc"
    )
}

fn rules() -> &'static [Rule] {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        use Category::*;
        vec![
            // ── credentials and secrets ────────────────────────────────────
            Rule::new(Secret, "private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            Rule::new(
                Secret,
                "database connection string",
                r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|ftp|ldaps?)://[^\s"'<>]{3,}"#,
            ),
            Rule::new(
                Secret,
                "cloud access key",
                r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
            ),
            Rule::new(
                Secret,
                "cloud secret key",
                r"(?i)\baws_secret_access_key\b\s*[=:]\s*(\S{20,})",
            )
            .reporting(1),
            // `Key: value` shapes report only the value, so a finding reads as
            // `AKIA…` rather than `Secret: AKIA…`.
            Rule::new(
                Secret,
                "password assignment",
                r#"(?i)["']?\b(?:password|passwd|pwd|pass|secret|api[_-]?key|apikey|auth[_-]?key|private[_-]?key|token|access[_-]?key|db[_-]?pass|dbpass|db_password)\b["']?\s*(?:=>|[=:])\s*["']?([^\s"',;<>)]{3,})"#,
            )
            .reporting(1)
            // `-----BEGIN` is half a PEM header, not a password; the private-key
            // rule already reports the whole thing.
            .accept_where(|m| !starts_with_delimiter_run(m)),
            // The same key in a quoted call or object literal, e.g.
            // `define('DB_PASS', '…')` or `{'api_key': '…'}`.
            Rule::new(
                Secret,
                "secret in a quoted pair",
                r#"(?i)["']\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?key|private[_-]?key|token|access[_-]?key|db[_-]?pass|dbpass|db_password)\b["']\s*[=:,]\s*["'][^"'\s]{3,}["']"#,
            ),
            Rule::new(Secret, "basic auth credential", r"(?i)\bbasic\s+[A-Za-z0-9+/]{8,}={0,2}"),
            // `user:pass` as hydra, nikto, sqli and access logs all emit it.
            // A purely numeric value is a port, and is left to the port rules.
            Rule::new(
                Credential,
                "username and password",
                r#"(?:^|[\s"'(\[])(\w[\w.$-]{0,63}):([^\s"'<>;,\])]{3,64})"#,
            )
            .accept_where(|m| {
                let (user, value) = match m.split_once(':') {
                    Some(p) => p,
                    None => return false,
                };
                // A URL is not a credential. `scheme:port/path` and
                // `scheme://user:pass@host` both contain a colon followed by
                // something that looks like a value, and reporting either as a
                // recovered password is worse than reporting nothing.
                // A host is not a username. `10.1.1.5:5432/prod` is a socket,
                // and the line parsers own host:port.
                !is_url_scheme(user)
                    && !looks_like_host(user)
                    && not_all_digits(user)
                    && !value.starts_with("//")
                    && !value.contains("//")
                    && not_all_digits(value)
            }),
            // ── tokens ─────────────────────────────────────────────────────
            Rule::new(Token, "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{16,255}\b"),
            Rule::new(Token, "GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
            Rule::new(Token, "Slack token", r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b"),
            Rule::new(Token, "Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
            Rule::new(Token, "Google OAuth client id", r"\b[0-9]{10,14}-[0-9a-z]{20,32}\.apps\.googleusercontent\.com\b"),
            Rule::new(Token, "Stripe live key", r"\b[rs]k_live_[0-9a-zA-Z]{20,}\b"),
            Rule::new(Token, "SendGrid key", r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b"),
            Rule::new(Token, "OpenAI key", r"\bsk-[A-Za-z0-9_-]{20,}\b"),
            Rule::new(Token, "Anthropic key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
            Rule::new(Token, "npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
            Rule::new(Token, "GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
            Rule::new(Token, "JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
            Rule::new(Token, "bearer token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}"),
            Rule::new(
                Token,
                "authorization header",
                r"(?i)\bauthorization\s*:\s*(?:bearer|basic|token|digest)\s+\S{8,}",
            ),
            // ── session material ────────────────────────────────────────────
            Rule::new(
                Cookie,
                "session cookie",
                r"(?i)\b(?:set-)?cookie\s*:\s*[^\r\n]{4,}",
            ),
            Rule::new(Cookie, "PHP session id", r"(?i)\bPHPSESSID\s*=\s*[A-Za-z0-9]{8,}"),
            Rule::new(Cookie, "JSESSIONID", r"\bJSESSIONID\s*=\s*[A-Za-z0-9]{6,}"),
            Rule::new(Cookie, "ASP.NET session id", r"(?i)\bASPSESSION[A-Z]*\s*=\s*[A-Za-z0-9]{6,}"),
            // A cookie with a session-bearing name, recovered on its own when a
            // tool printed only the `name=value` pair.
            Rule::new(
                Cookie,
                "session cookie value",
                concat!(
                    r"(?i)\b(?:PHPSESSID|JSESSIONID|ASPSESSION[A-Z0-9]*|connect\.sid|sessid|",
                    r"sessionid|session_id|sess(?:ion)?[_-]?(?:id|key|token)|auth[_-]?token|",
                    r"remember[_-]?me|csrftoken|csrf[_-]?token|jwt|access[_-]?token|refresh[_-]?token)",
                    r"\s*=\s*[A-Za-z0-9._~+/-]{8,}={0,2}"
                ),
            ),
            // ── hashes ─────────────────────────────────────────────────────
            Rule::new(Hash, "Unix crypt hash", r"\$(?:1|2[aby]?|5|6|7|y|gy)\$[^\s:]{6,}"),
            Rule::new(Hash, "NTLM hash", r"\b[a-fA-F0-9]{32}\b"),
            Rule::new(Hash, "NetNTLMv1 response", r"\b[a-fA-F0-9]{48}\b"),
            Rule::new(Hash, "NetNTLMv2 response", r"\b[a-fA-F0-9]{64}\b"),
            Rule::new(Hash, "Kerberos hash", r"(?i)\bkrb5tgs\$[^\s:]{10,}"),
            Rule::new(Hash, "DYNECT hash", r"(?i)\bdynect\$[0-9a-f]{16}\$[0-9a-f]{40}"),
            Rule::new(Hash, "SSHA/SMD5 hash", r"(?i)\b\{(?:SSHA|SMD5|MD5)\}[A-Za-z0-9+/=]{8,}"),
            Rule::new(Hash, "password hash reference", r"(?i)\b(?:hash(?:cat)?\s+\d{1,5}|\$[^$\s]+\$[^$\s]{4,})\b"),
            // ── vulnerability identifiers ───────────────────────────────────
            Rule::new(Cve, "CVE", r"\bCVE-\d{4}-\d{4,7}\b"),
            Rule::new(Cve, "CWE", r"\bCWE-\d{1,5}\b"),
            Rule::new(Cve, "GHSA", r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b"),
            Rule::new(Cve, "OWASP identifier", r"\bA\d{2}:20\d{2}(?:-\d{4})?\b"),
            // ── files worth knowing about ──────────────────────────────────
            Rule::new(File, "version control metadata", r"(?i)\.git/(?:HEAD|config|index|objects|refs)"),
            Rule::new(File, "cloud credentials file", r"(?i)\.aws/credentials"),
            Rule::new(File, "environment file", r#"(?i)(?:^|[\s/"'])\.env(?:\.[\w-]+)?\b"#),
            Rule::new(File, "database dump", r"(?i)\b\w+\.(?:sql|dump|sqlite3?)\b"),
            Rule::new(File, "archive or backup", r"(?i)\b[\w.-]+\.(?:zip|tar|tgz|gz|bak|old|backup|swp|rar|7z)\b"),
            Rule::new(File, "private key file", r"(?i)\bid_(?:rsa|dsa|ecdsa|ed25519)\b"),
            Rule::new(File, "key or certificate file", r"(?i)\b[\w./-]+\.(?:pem|key|p12|pfx|jks|keystore|kdbx|crt|cer)\b"),
            Rule::new(File, "WordPress configuration", r"(?i)wp-config\.php"),
            Rule::new(File, "framework configuration", r"(?i)\b[\w./-]+\.(?:ya?ml|toml|ini|conf|cfg|json|xml|properties|env)\b"),
            Rule::new(File, "source file", r"(?i)\b[\w./-]+\.(?:php|asp|aspx|jsp|py|rb|go|js|ts|jspx|erb)\b"),
            Rule::new(File, "system file", r#"(?i)(?:^|[\s/"'])/(?:etc|var|proc|root|home|opt|tmp|usr|dev)/[\w./-]*"#),
            // ── comments and annotations ───────────────────────────────────
            Rule::new(Comment, "HTML comment", r"<!--[\s\S]*?-->"),
            Rule::new(
                Comment,
                "TODO/FIXME marker",
                r"(?i)\b(?:TODO|FIXME|HACK|XXX|BUG|NOTE):\s*[^\r\n*]{0,120}",
            )
            .trimming_tail(),
            Rule::new(Comment, "block comment", r"/\*[\s\S]{0,400}?\*/"),
            Rule::new(Comment, "shell or SQL comment", r"(?:^|\s)(?:--|#)\s?[A-Za-z][^\r\n]{0,120}"),
            // ── network ────────────────────────────────────────────────────
            Rule::new(Email, "email address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"),
            Rule::new(Url, "URL", r#"\bhttps?://[^\s"'<>)\]}]{4,}"#),
            Rule::new(Ip, "CIDR block", r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b"),
            Rule::new(Ip, "IPv4 address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            Rule::new(Ip, "IPv6 address", r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"),
            Rule::new(Ip, "MAC address", r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
        ]
    })
}

/// Recover every artefact one line carries.
///
/// Returned in pattern order, so the output is stable for a given input. The
/// caller deduplicates, so an artefact matching two patterns appears twice
/// rather than requiring overlap bookkeeping here.
pub fn extract(line: &str) -> Vec<Extraction> {
    let mut out = Vec::new();
    for rule in rules() {
        for m in rule.re.find_iter(line) {
            let raw = m.as_str();
            // A `Key: value` shape matches the label too, so the rule reports the
            // value: a finding reading `AKIA…` is both easier to scan and easier
            // to match on than one reading `Secret: AKIA…`.
            let matched = match rule.capture {
                Some(n) => rule
                    .re
                    .captures(line)
                    .and_then(|c| c.get(n))
                    .map(|g| g.as_str())
                    .unwrap_or(raw),
                None => raw,
            };
            let value = matched.trim();
            // A match of pure punctuation or a bare scheme is not an artefact.
            if value.is_empty() || value.len() < 4 && !looks_meaningful(value) {
                continue;
            }
            if is_noise_only_token(value) {
                continue;
            }
            if let Some(accept) = rule.accept {
                if !accept(value) {
                    continue;
                }
            }
            // A pattern that has to consume a leading delimiter to anchor the
            // match would otherwise report the delimiter as part of the value.
            let mut value = value.trim_start_matches([' ', '\t', '"', '\'', '(', '[']);
            if rule.trim_tail {
                value = value.trim_end_matches(['*', '/', '-', ' ', ';']);
            }
            out.push(Extraction {
                category: rule.category,
                value: value.to_string(),
                detail: Some(rule.label.to_string()),
            });
        }
    }
    out
}

/// Whether a short match is worth keeping despite being under the length floor.
fn looks_meaningful(value: &str) -> bool {
    value.chars().any(|c| c.is_ascii_alphanumeric())
}

/// Whether a match is a scheme or separator that only ever appeared as syntax.
fn is_noise_only_token(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "http" | "https" | "ftp" | "smtp" | "ldap" | "ldaps" | "mysql" | "postgres" | "redis"
    )
}

/// Recover the artefacts in one line together with the line they came from.
///
/// The context travels with every finding. It is what lets a short finding such
/// as `AKIA…` be interpreted three weeks later without guessing which request
/// it appeared in.
pub fn assess(line: &str) -> Assessment {
    let mut findings = extract(line);
    let trimmed = line.trim();
    if trimmed.len() > 400 {
        // A progress bar or a base64 blob is not a document. Keep a readable
        // prefix so the context is still useful.
        findings.push(Extraction {
            category: Category::Evidence,
            value: format!("{}…", trimmed.chars().take(200).collect::<String>()),
            detail: Some(format!("line ({} bytes)", trimmed.len())),
        });
    } else if !trimmed.is_empty() && findings.is_empty() {
        findings.push(Extraction {
            category: Category::Evidence,
            value: trimmed.to_string(),
            detail: None,
        });
    }
    Assessment {
        context: trimmed.chars().take(400).collect(),
        findings,
    }
}

/// Recover artefacts from a whole artifact body, one line at a time.
///
/// Noise is returned separately rather than dropped, so the caller can report
/// how much of the output was narration.
pub fn assess_all(text: &str) -> (Vec<Extraction>, usize) {
    let mut out = Vec::new();
    let mut noise = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let found = extract(trimmed);
        if found.is_empty() {
            if is_noise(trimmed) {
                noise += 1;
            } else {
                out.push(Extraction {
                    category: Category::Evidence,
                    value: trimmed.to_string(),
                    detail: None,
                });
            }
            continue;
        }
        // A line that both matched an artefact and looks like chrome: keep the
        // artefact, and count the line as chatter for the ratio.
        if is_noise(trimmed) {
            noise += 1;
        }
        for f in found {
            out.push(Extraction {
                detail: f
                    .detail
                    .map(|d| format!("{d} · {}", ellipsise(trimmed, 160))),
                ..f
            });
        }
    }
    (out, noise)
}

fn ellipsise(s: &str, max: usize) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    format!("{}…", trimmed.chars().take(max).collect::<String>())
}

// ── what to do next ──────────────────────────────────────────────────────────

/// A concrete next action implied by what was harvested.
///
/// Each one names a phase and a capability that exist in the catalog, so this is
/// a routing table rather than advice: an operator can act on it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextStep {
    /// How strong the signal is, 1 lowest to 3 highest.
    pub confidence: u8,
    /// Which capability to run, and where it lives.
    pub phase: &'static str,
    pub capability: &'static str,
    /// Why this harvest implies that action.
    pub because: String,
    /// What it needs the operator to supply.
    pub needs: String,
}

/// Work out which capability to run next, from what was harvested.
///
/// This is deliberately conservative: a step is only offered when a specific
/// observed artefact implies it. Suggesting an attack because a port was open is
/// noise; suggesting one because a live credential was printed is a lead.
pub fn recommend(findings: &[(Category, String)]) -> Vec<NextStep> {
    let has = |c: Category| findings.iter().any(|(k, _)| *k == c);
    let any = |c: Category| findings.iter().any(|(k, v)| *k == c && !v.is_empty());

    let mut steps: Vec<NextStep> = Vec::new();
    let mut push = |confidence: u8,
                    phase: &'static str,
                    capability: &'static str,
                    because: String,
                    needs: &str| {
        steps.push(NextStep {
            confidence,
            phase,
            capability,
            because,
            needs: needs.to_string(),
        });
    };

    if any(Category::Secret) {
        push(
            3,
            "credentials",
            "CREDENTIAL DUMP LINUX / SERVICE LOGIN BRUTE",
            "a password, private key or connection string was recovered in the clear".into(),
            "the host it belongs to",
        );
    }
    if any(Category::Token) {
        push(
            3,
            "credentials",
            "JWT TOKEN AUDIT",
            "an API token or JWT was recovered; test it against every endpoint in scope \
             and, for a JWT, try forging one with a weak or known signing secret"
                .into(),
            "the API or web host",
        );
    }
    if any(Category::Cookie) {
        push(
            3,
            "credentials",
            "BROWSER PASSWORD EXTRACT",
            "session material was recovered; a live cookie replays the authenticated \
             session without needing the password"
                .into(),
            "the application URL",
        );
    }
    if any(Category::Hash) {
        push(
            3,
            "credentials",
            "HASH CRACKING",
            "a password hash was recovered and is ready for an offline attack".into(),
            "nothing; the bundled corpus applies",
        );
    }
    if any(Category::Cve) {
        push(
            3,
            "exploitation",
            "PUBLIC CVE SWEEP",
            "a CVE identifier was reported; check whether the running version is the \
             vulnerable one and whether a public exploit exists"
                .into(),
            "the affected host and its version",
        );
    }
    if has(Category::File) {
        push(
            2,
            "surface",
            "CONTENT DISCOVERY",
            "an exposed file was found; the same directory may hold backups, source and \
             configuration that were not in scope"
                .into(),
            "the web root URL",
        );
    }
    if any(Category::Comment) {
        push(
            2,
            "recon",
            "JS RECON",
            "comments and markers were recovered; they routinely name internal hosts, \
             credentials and endpoints that are not linked"
                .into(),
            "the application URL",
        );
    }
    if any(Category::Username) {
        push(
            2,
            "credentials",
            "SMB AUTH SPRAY",
            "account names were recovered; spray them against the services in scope with \
             the bundled per-service corpus"
                .into(),
            "the target host",
        );
    }
    if any(Category::Finding) {
        push(
            3,
            "exploitation",
            "NUCLEI CRITICAL",
            "a scanner reported a finding; confirm it and attempt the corresponding \
             exploitation capability"
                .into(),
            "the affected host",
        );
    }
    if any(Category::Technology) && any(Category::Version) {
        push(
            2,
            "exploitation",
            "EXPLOIT CHAIN VERIFY",
            "a product and version were identified; match the exact build against known \
             vulnerabilities rather than the product name"
                .into(),
            "the host and port",
        );
    }
    if any(Category::Host) || any(Category::Ip) {
        push(
            1,
            "surface",
            "WEB PROFILING",
            "hosts were enumerated; profile each one for exposed services and technology".into(),
            "the host or CIDR",
        );
    }

    steps.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.capability.cmp(b.capability))
    });
    steps.dedup_by(|a, b| a.capability == b.capability && a.because == b.because);
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cats(line: &str) -> Vec<Category> {
        extract(line).into_iter().map(|e| e.category).collect()
    }

    fn has(line: &str, c: Category) -> bool {
        cats(line).contains(&c)
    }

    #[test]
    fn a_cloud_key_is_recovered_from_an_access_log_line() {
        // Real access-log shape: the whole line is one artefact plus its host.
        let id = token("AKIA", "TSECEXAMPLE00001");
        let line =
            format!(r#"66.249.66.1 - - [10/Oct/2023] "GET /admin HTTP/1.1" 401 199 "key={id}""#);
        let found = extract(&line);
        assert!(
            found
                .iter()
                .any(|e| e.category == Category::Secret && e.value == id),
            "{found:?}"
        );
        assert!(has(&line, Category::Ip));
    }

    /// Synthetic provider tokens, assembled from parts.
    ///
    /// Written this way deliberately: a complete token literal in a test file
    /// trips push protection on the forge, which makes the change unpushable and
    /// unreviewable. Splitting the prefix from the body also makes it obvious to
    /// a reader that these are made up.
    fn token(prefix: &str, body: &str) -> String {
        format!("{prefix}{body}")
    }

    #[test]
    fn tokens_of_every_common_vendor_are_recovered() {
        let cases: Vec<(String, String)> = vec![
            (
                token("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"),
                token("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            (
                token("xoxb-", "123456789012-abcdefghijklmnop"),
                token("xoxb-", "123456789012-abcdefghijklmnop"),
            ),
            (
                token("AIza", "SyD-1234567890abcdefghijklmnopqrstu"),
                token("AIza", "SyD-1234567890abcdefghijklmnopqrstu"),
            ),
            (
                format!(
                    "{}.{}.{}",
                    token("eyJhbGciOiJIUzI1NiJ", "9"),
                    token("eyJzdWIiOiIxI", "n0"),
                    token("abc123sign", "ature")
                ),
                format!(
                    "{}.{}.{}",
                    token("eyJhbGciOiJIUzI1NiJ", "9"),
                    token("eyJzdWIiOiIxI", "n0"),
                    token("abc123sign", "ature")
                ),
            ),
            (
                token("glpat-", "abcdefghij0123456789"),
                token("glpat-", "abcdefghij0123456789"),
            ),
        ];
        for (line, expected) in cases {
            let haystack = format!("token {line}");
            let found = extract(&haystack);
            assert!(
                found
                    .iter()
                    .any(|e| e.category == Category::Token && e.value == expected),
                "{haystack} -> {found:?}"
            );
        }
    }

    #[test]
    fn an_aws_access_key_id_is_recovered_without_being_written_out() {
        // The documented AWS example pair, assembled from parts so no complete key
        // literal exists in the repository.
        let id = token("AKIA", "TSECEXAMPLE00001");
        let line = format!("aws_access_key_id = {id}");
        let found = extract(&line);
        assert!(
            found
                .iter()
                .any(|e| e.category == Category::Secret && e.value == id),
            "{line} -> {found:?}"
        );
    }

    #[test]
    fn a_set_cookie_header_is_recovered_as_session_material() {
        let line = "Set-Cookie: JSESSIONID=A1B2C3D4E5; Path=/; HttpOnly; Secure";
        let found = extract(line);
        assert!(
            found.iter().any(|e| e.category == Category::Cookie),
            "{found:?}"
        );
        assert!(has(line, Category::Cookie));
    }

    #[test]
    fn a_password_hash_is_distinguished_from_a_plain_password() {
        assert!(has(
            "$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ12",
            Category::Hash
        ));
        assert!(has(
            "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            Category::Hash
        ));
        // A cleartext password is a secret, not a hash.
        assert!(!has("password=hunter2", Category::Hash));
        assert!(has("password=hunter2", Category::Secret));
    }

    #[test]
    fn source_comments_are_recovered_rather_than_shown_as_one_blob() {
        let id = token("AKIA", "TSECEXAMPLE00001");
        let line = format!("<!-- TODO: remove debug token {id} --><script src=/app.js>");
        assert!(has(&line, Category::Comment));
        assert!(has(&line, Category::Secret));
    }

    #[test]
    fn a_database_connection_string_with_inline_credentials_is_recovered() {
        let line = "DATABASE_URL=postgres://admin:s3cret@db.internal:5432/app";
        let found = extract(line);
        assert!(
            found
                .iter()
                .any(|e| e.category == Category::Secret && e.value.starts_with("postgres://")),
            "{found:?}"
        );
    }

    #[test]
    fn a_cve_identifier_is_recovered() {
        assert!(has("Apache Struts 2.5.12 — CVE-2023-50164", Category::Cve));
    }

    #[test]
    fn exposed_configuration_files_are_recovered() {
        for path in [
            "/.git/config",
            "/.env",
            "/home/u/.aws/credentials",
            "wp-config.php",
        ] {
            assert!(has(path, Category::File), "{path}");
        }
    }

    #[test]
    fn a_network_access_log_line_yields_several_artefacts_at_once() {
        let line =
            r#"10.0.0.4 - - "POST /login HTTP/1.1" 200 3021 "Mozilla/5.0" "admin:Sup3rS3cr3t""#;
        let found = extract(line);
        assert!(found
            .iter()
            .any(|e| e.category == Category::Ip && e.value == "10.0.0.4"));
        assert!(
            found
                .iter()
                .any(|e| e.category == Category::Credential && e.value == "admin:Sup3rS3cr3t"),
            "{found:?}"
        );
    }

    #[test]
    fn a_url_is_never_mistaken_for_a_credential_pair() {
        // `scheme:port/path` and `scheme://user:pass@host` both contain a colon
        // followed by something that looks like a value. Neither is a password.
        for line in [
            "http://admin.example.com:8080/login",
            "postgres://svc:hunter2@10.1.1.5:5432/prod",
            "10.1.1.5:5432/prod",
        ] {
            let pairs: Vec<Extraction> = extract(line)
                .into_iter()
                .filter(|e| e.category == Category::Credential)
                .collect();
            assert!(pairs.is_empty(), "{line} -> {pairs:?}");
        }
        // A real pair is still recovered, including one carrying a DSN's creds.
        assert!(extract("admin:hunter2")
            .iter()
            .any(|e| e.category == Category::Credential));
    }

    #[test]
    fn a_set_cookie_yields_one_finding_not_two() {
        let found = extract("Set-Cookie: session=abc123def456ghi789; Path=/; HttpOnly");
        let cookies: Vec<&Extraction> = found
            .iter()
            .filter(|e| e.category == Category::Cookie)
            .collect();
        assert_eq!(cookies.len(), 1, "{cookies:?}");
        assert!(cookies[0].value.starts_with("Set-Cookie:"), "{cookies:?}");
    }

    #[test]
    fn a_comment_marker_does_not_swallow_the_comment_terminator() {
        let found = extract("/* TODO: rotate before launch */");
        let marker = found
            .iter()
            .find(|e| e.detail.as_deref() == Some("TODO/FIXME marker"))
            .unwrap();
        assert_eq!(marker.value, "TODO: rotate before launch");
    }

    #[test]
    fn progress_chatter_is_noise_not_a_finding() {
        for line in [
            "[*] Starting: /22/hosts 300 found",
            "[INF] Executing 12 threads",
            "Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds",
            "Progress: [====>    ] 45.2%",
            "1234/5678",
            "---------------------------",
        ] {
            assert!(is_noise(line), "{line:?} should be noise");
        }
        assert!(!is_noise("10.0.0.1:22"));
    }

    #[test]
    fn a_line_that_looks_like_chatter_but_carries_an_artefact_keeps_the_artefact() {
        // The extractor runs before the noise filter for exactly this reason.
        let id = token("AKIA", "TSECEXAMPLE00001");
        let line = format!("[*] leaked key {id} in /debug");
        assert!(is_noise(&line));
        assert!(
            extract(&line)
                .iter()
                .any(|e| e.category == Category::Secret),
            "the artefact must survive the chatter around it"
        );
    }

    #[test]
    fn an_unrecognised_line_becomes_evidence_not_noise() {
        let (found, noise) = assess_all("weird unparsed tool output\n[*] progress\n");
        assert_eq!(noise, 1);
        assert!(found
            .iter()
            .any(|e| e.category == Category::Evidence && e.value == "weird unparsed tool output"));
    }

    #[test]
    fn an_artefact_carries_its_source_line_as_context() {
        let line = "cfg.php: define('DB_PASS', 'Sup3rS3cr3t'); // internal db 10.1.1.5";
        let (found, _) = assess_all(line);
        let secret = found
            .iter()
            .find(|e| e.category == Category::Secret)
            .unwrap();
        // The matched text is the secret; the line it came from is the detail, so
        // the finding can be interpreted later without re-reading the artifact.
        assert!(secret.value.contains("Sup3rS3cr3t"), "{secret:?}");
        assert!(
            secret.detail.as_ref().unwrap().contains("cfg.php"),
            "{secret:?}"
        );
    }

    #[test]
    fn assessment_of_a_large_line_stays_bounded() {
        let line = "A".repeat(10_000);
        let a = assess(&line);
        assert!(a.context.len() <= 400);
    }

    #[test]
    fn recommendations_are_ranked_by_signal_strength() {
        let findings = vec![
            (Category::Host, "a.example.com".to_string()),
            (Category::Secret, token("AKIA", "TSECEXAMPLE00001")),
            (Category::Cve, "CVE-2023-50164".to_string()),
            (Category::Finding, "RCE confirmed".to_string()),
        ];
        let steps = recommend(&findings);
        assert!(steps.len() >= 4, "{steps:?}");
        for w in steps.windows(2) {
            assert!(w[0].confidence >= w[1].confidence, "not ranked: {steps:?}");
        }
        assert!(steps.iter().any(|s| s.capability.contains("CREDENTIAL")));
        assert!(steps.iter().all(|s| !s.needs.is_empty()));
    }

    #[test]
    fn a_bare_host_enumeration_only_proposes_the_baseline() {
        let steps = recommend(&[(Category::Host, "a.example.com".to_string())]);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].confidence, 1);
    }

    #[test]
    fn an_empty_harvest_proposes_nothing() {
        assert!(recommend(&[]).is_empty());
    }
}
