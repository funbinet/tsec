//! Turning raw tool output into normalised, traceable findings.
//!
//! The pipeline is deliberately small and explicit:
//!
//! ```text
//!   raw bytes ─▶ decode ─▶ per-format parse ─▶ classify ─▶ normalise ─▶ dedupe
//! ```
//!
//! Three properties matter more than coverage:
//!
//! * **Nothing is invented.** A finding exists only because a line in the raw
//!   evidence said so. Every finding keeps the tool's own wording in `value` and
//!   points back at the artifact through [`Provenance`], so the operator can
//!   always check the interpretation against the evidence.
//! * **Unrecognised output is kept, not dropped.** A line the classifier does
//!   not understand becomes a [`Category::Evidence`] finding rather than being
//!   discarded. Silently losing a tool's output is how a framework becomes
//!   quietly untrustworthy.
//! * **Provenance is per-finding.** Two tools reporting the same host produce one
//!   deduplicated finding that lists *both* provsources, not one finding that
//!   pretends a single tool said it.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::catalog::OutputFormat;
use crate::domain::finding::{Category, Finding, Provenance};
use crate::error::{Result, TsecError};

/// Maximum bytes read from a raw artifact.
///
/// A tool that writes gigabytes to stdout is a misconfiguration, not a
/// harvest. The cap keeps the parser's memory bounded and the failure legible;
/// truncation is recorded as a finding rather than passed off as complete.
const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

/// Findings harvested from one tool invocation.
#[derive(Debug, Default, Clone)]
pub struct Harvest {
    findings: Vec<Finding>,
    truncated: bool,
    /// Non-fatal problems, e.g. a malformed JSON line that was kept as evidence.
    notes: Vec<String>,
}

impl Harvest {
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    pub fn truncated(&self) -> bool {
        self.truncated
    }
    pub fn notes(&self) -> &[String] {
        &self.notes
    }
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    fn push(&mut self, category: Category, value: impl Into<String>, detail: Option<String>) {
        let value = value.into();
        if value.trim().is_empty() {
            return;
        }
        self.findings.push(Finding {
            category,
            value,
            detail,
            provenance: Provenance::placeholder(),
            occurrences: 1,
        });
    }

    /// Attribute every finding to the invocation that produced it.
    pub fn attribute(&mut self, provenance: Provenance) {
        for f in &mut self.findings {
            f.provenance = provenance.clone();
        }
    }

    /// Record that the artifact exceeded the input cap.
    pub fn mark_truncated(&mut self) {
        self.truncated = true;
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Append another harvest's findings, keeping both provenances.
    pub fn absorb(&mut self, other: Harvest) {
        self.findings.extend(other.findings);
        self.notes.extend(other.notes);
        self.truncated |= other.truncated;
    }

    /// Collapse duplicates, keeping every distinct provenance.
    ///
    /// Order is stable and deterministic: findings come out in the order their
    /// category sorts (high signal first), then by value, then by provenance.
    /// A run that discovers the same thing twice must produce byte-identical
    /// harvest output, otherwise diffing two runs is meaningless.
    pub fn deduped(&self) -> Vec<MergedFinding> {
        let mut merged: BTreeMap<(u8, Category, String), MergedFinding> = BTreeMap::new();
        for f in &self.findings {
            let key = (f.category.order(), f.category, f.value.to_ascii_lowercase());
            match merged.get_mut(&key) {
                Some(existing) => {
                    existing.occurrences += f.occurrences;
                    if !existing.sources.contains(&f.provenance) {
                        existing.sources.push(f.provenance.clone());
                    }
                    // Keep the first spelling seen; it came from a real tool and
                    // the operator may recognise it.
                    if existing.detail.is_none() {
                        existing.detail = f.detail.clone();
                    }
                }
                None => {
                    merged.insert(
                        key,
                        MergedFinding {
                            category: f.category,
                            value: f.value.clone(),
                            detail: f.detail.clone(),
                            sources: vec![f.provenance.clone()],
                            occurrences: f.occurrences,
                        },
                    );
                }
            }
        }
        let mut out: Vec<MergedFinding> = merged.into_values().collect();
        out.sort_by(|a, b| {
            a.category.order().cmp(&b.category.order()).then_with(|| {
                a.value
                    .to_ascii_lowercase()
                    .cmp(&b.value.to_ascii_lowercase())
            })
        });
        out
    }
}

/// A deduplicated finding together with every source that reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedFinding {
    pub category: Category,
    pub value: String,
    pub detail: Option<String>,
    pub sources: Vec<Provenance>,
    pub occurrences: usize,
}

impl MergedFinding {
    /// One-line harvest entry, e.g. `PORTS  443/tcp on 10.0.0.1 (nmap, naabu)`.
    pub fn line(&self) -> String {
        let tools: Vec<&str> = {
            let mut t: Vec<&str> = self.sources.iter().map(|s| s.provider.as_str()).collect();
            t.sort_unstable();
            t.dedup();
            t
        };
        let mut line = self.value.clone();
        if let Some(d) = &self.detail {
            line.push_str(" — ");
            line.push_str(d);
        }
        line.push_str(&format!(" [{}]", tools.join(", ")));
        line
    }
}

/// Read a raw artifact and turn it into findings.
///
/// `format` is the format the catalog declared for the operation. A tool that
/// emits something else is handled by the classifier, which is why a mismatch
/// degrades to evidence rather than to an error.
pub fn parse_artifact(
    path: &Path,
    format: OutputFormat,
    provenance: Provenance,
) -> Result<Harvest> {
    let bytes = read_capped(path)?;
    let mut harvest = Harvest::default();
    if bytes.truncated {
        harvest.mark_truncated();
        harvest.note(format!(
            "artifact exceeded {MAX_INPUT_BYTES} bytes and was truncated; \
             raw evidence holds the complete output"
        ));
    }
    let text = String::from_utf8_lossy(&bytes.text).into_owned();

    match format {
        OutputFormat::Nmap => parse_nmap_xml(&text, &mut harvest),
        OutputFormat::Json => parse_jsonl(&text, &mut harvest),
        OutputFormat::Lines => parse_lines(&text, &mut harvest),
        // A tool's own format is kept verbatim. The framework has no opinion
        // about sqlmap's or nikto's layout, so the whole record is the evidence.
        OutputFormat::Raw => parse_raw(&text, &mut harvest),
    }
    harvest.attribute(provenance);
    Ok(harvest)
}

struct Capped {
    text: Vec<u8>,
    truncated: bool,
}

fn read_capped(path: &Path) -> Result<Capped> {
    use std::io::Read;
    let file = std::fs::File::open(path)
        .map_err(|e| TsecError::io(format!("opening raw evidence {}", path.display()), &e))?;
    let mut buf = Vec::new();
    let read = file
        .take(MAX_INPUT_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| TsecError::io(format!("reading raw evidence {}", path.display()), &e))?;
    let truncated = (read as u64) == MAX_INPUT_BYTES;
    Ok(Capped {
        text: buf,
        truncated,
    })
}

// ── nmap ────────────────────────────────────────────────────────────────────

/// Parse nmap's XML report into one finding per meaningful observation.
fn parse_nmap_xml(text: &str, h: &mut Harvest) {
    if !text.contains("<nmaprun") {
        // Not XML at all: keep it rather than lose the evidence.
        parse_raw(text, h);
        return;
    }
    for host in open_tags(text, "host") {
        let up = open_tags(&host.body, "status")
            .iter()
            .any(|s| s.tag.contains("state=\"up\""));
        for addr in open_tags(&host.body, "address") {
            if let Some(ip) = attr_of(&addr.tag, "addr") {
                h.push(Category::Ip, ip, Some("nmap address".into()));
            }
        }
        for name in open_tags(&host.body, "hostname") {
            if let Some(n) = attr_of(&name.tag, "name") {
                h.push(Category::Host, n, Some("nmap PTR".into()));
            }
        }
        if up {
            h.push(Category::Metadata, "host up", Some("nmap status".into()));
        }
        for port in open_tags(&host.body, "port") {
            let number = attr_of(&port.tag, "portid").unwrap_or_default();
            let protocol = attr_of(&port.tag, "protocol").unwrap_or_else(|| "tcp".into());
            if number.is_empty() {
                continue;
            }
            // A closed port is not a service; recording one per closed port would
            // bury the open ones that matter.
            if !open_tags(&port.body, "state")
                .iter()
                .any(|s| s.tag.contains("state=\"open\""))
            {
                continue;
            }
            h.push(
                Category::Port,
                format!("{number}/{protocol}"),
                Some("open".into()),
            );
            let Some(service) = open_tags(&port.body, "service").into_iter().next() else {
                continue;
            };
            if let Some(name) = attr_of(&service.tag, "name").filter(|s| !s.is_empty()) {
                h.push(
                    Category::Service,
                    name,
                    Some(format!("on {number}/{protocol}")),
                );
            }
            let product = attr_of(&service.tag, "product").filter(|p| !p.is_empty());
            if let Some(product) = product.as_deref() {
                h.push(
                    Category::Technology,
                    product,
                    Some(format!("on {number}/{protocol}")),
                );
            }
            if let Some(version) = attr_of(&service.tag, "version").filter(|s| !s.is_empty()) {
                // Attribute the version to the product that reported it, so a
                // bare "0.6" in the harvest is never ambiguous.
                let detail = match product.as_deref() {
                    Some(p) => format!("{p} on {number}/{protocol}"),
                    None => format!("on {number}/{protocol}"),
                };
                h.push(Category::Version, version, Some(detail));
            }
        }
    }
}

/// Every occurrence of `tag` in `text`, paired with its own content.
///
/// For a self-closing leaf such as `<address addr="…"/>` the returned slice is
/// empty and the caller reads attributes off the opening tag, which is why
/// [`OpenTag`] carries the tag text alongside the body. A container such as
/// `<port …>…</port>` returns its children, so the caller can look inside.
///
/// The `>`-versus-whitespace check after the name keeps `<hostname` from
/// matching a search for `<host`.
struct OpenTag {
    tag: String,
    body: String,
}

fn open_tags(text: &str, tag: &str) -> Vec<OpenTag> {
    let open = format!("<{tag}");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        let name_end = start + open.len();
        if !rest[name_end..].starts_with(|c: char| c.is_whitespace() || c == '>' || c == '/') {
            rest = &rest[name_end..];
            continue;
        }
        let Some(open_end_rel) = tag_end(&rest[name_end..]) else {
            break;
        };
        let open_end = name_end + open_end_rel;
        let head = rest[name_end..open_end].to_string();
        let (body, next) = if head.ends_with("/>") {
            (String::new(), open_end)
        } else {
            let close = format!("</{tag}>");
            match rest[open_end..].find(&close) {
                Some(rel) => (
                    rest[open_end..open_end + rel].to_string(),
                    open_end + rel + close.len(),
                ),
                None => break,
            }
        };
        out.push(OpenTag { tag: head, body });
        rest = &rest[next..];
    }
    out
}

/// Offset just past the `>` that closes an open tag, skipping quoted values.
fn tag_end(body: &str) -> Option<usize> {
    let mut quoted = false;
    for (i, c) in body.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '>' if !quoted => return Some(i + 1),
            _ => {}
        }
    }
    None
}

fn attr_of(open_tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = open_tag.find(&needle)? + needle.len();
    let end = open_tag[start..].find('"')?;
    Some(open_tag[start..start + end].to_string())
}

// ── JSON / JSONL ────────────────────────────────────────────────────────────

/// Parse newline-delimited JSON, the format nuclei and friends emit.
fn parse_jsonl(text: &str, h: &mut Harvest) {
    let mut saw_json = false;
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A tool's progress chatter on stdout is not an error; it is evidence.
        if !line.starts_with('{') && !line.starts_with('[') {
            h.push(Category::Evidence, line, Some(format!("line {}", n + 1)));
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => {
                saw_json = true;
                parse_nuclei_record(&v, h);
            }
            Err(e) => {
                h.note(format!("line {} is not valid JSON: {e}", n + 1));
                h.push(
                    Category::Evidence,
                    line,
                    Some(format!("malformed JSON, line {}", n + 1)),
                );
            }
        }
    }
    if !saw_json && !text.trim().is_empty() {
        h.note("no JSON records found; treating output as raw evidence");
        parse_raw(text, h);
    }
}

/// Pull the fields the framework understands out of a nuclei record.
fn parse_nuclei_record(v: &Value, h: &mut Harvest) {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);

    if let Some(url) = s("matched-at").or_else(|| s("url")).or_else(|| s("host")) {
        h.push(Category::Url, url.clone(), None);
        if let Some(host) = host_of(&url) {
            h.push(Category::Host, host, Some("from URL".into()));
        }
    }
    if let Some(ip) = s("ip") {
        h.push(Category::Ip, ip, None);
    }
    if let Some(port) = s("port") {
        h.push(Category::Port, port, Some("nuclei".into()));
    }
    if let Some(sev) = v.pointer("/info/severity").and_then(Value::as_str) {
        let name = v
            .pointer("/info/name")
            .and_then(Value::as_str)
            .unwrap_or("template match");
        h.push(
            Category::Finding,
            format!("{name} ({sev})"),
            Some(s("template-id").unwrap_or_default()),
        );
    }
    // A tech-detect match names the technology in `matcher-name`.
    if let Some(m) = s("matcher-name") {
        h.push(Category::Technology, m, Some("nuclei matcher".into()));
    }
    // Subdomain enumeration arrives as plain hostnames, which the line parser
    // would classify anyway; here it is explicit.
    if let Some(host) = s("host").or_else(|| s("input")) {
        if host.contains('.') && !host.contains(' ') {
            h.push(Category::Host, host, Some("nuclei host".into()));
        }
    }
}

// ── lines ───────────────────────────────────────────────────────────────────

/// Parse one-finding-per-line output.
///
/// The `lines` format is what most tools emit, but they do not agree on what a
/// line looks like. Rather than write a bespoke parser per tool, the classifier
/// recognises the shapes that actually occur and keeps anything else verbatim.
fn parse_lines(text: &str, h: &mut Harvest) {
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        classify_line(line, n + 1, h);
    }
}

/// Decide what one line of `lines` output is.
fn classify_line(line: &str, lineno: usize, h: &mut Harvest) {
    // A bracketed httpx probe: `https://h [200] [title] [ip] [Tech:1.0,Tech2]`.
    if line.contains("] [") {
        if let Some((url, rest)) = line.split_once(" [") {
            if url.starts_with("http://") || url.starts_with("https://") {
                h.push(Category::Url, url.trim(), None);
                h.push(
                    Category::Host,
                    host_of(url.trim()).unwrap_or_default(),
                    None,
                );
                for field in rest.split(" [") {
                    let field = field.trim_end_matches(']');
                    classify_bracket_field(field, h);
                }
                return;
            }
        }
    }

    // `1.2.3.4:443` — naabu, nmap, masscan.
    if let Some((addr, port)) = split_host_port(line) {
        h.push(Category::Ip, addr.clone(), Some(format!("line {lineno}")));
        h.push(Category::Port, port, Some(format!("{addr} line {lineno}")));
        return;
    }

    // A bare URL.
    if line.starts_with("http://") || line.starts_with("https://") {
        h.push(Category::Url, line, None);
        if let Some(host) = host_of(line) {
            h.push(Category::Host, host, Some("from URL".into()));
        }
        return;
    }

    // A bare IP.
    if line.parse::<std::net::IpAddr>().is_ok() {
        h.push(Category::Ip, line, None);
        return;
    }

    // A bare hostname: subfinder, amass, maigret.
    if looks_like_hostname(line) {
        h.push(Category::Host, line, None);
        return;
    }

    // An email address: theHarvester, maigret.
    if is_email(line) {
        h.push(Category::Credential, line, Some("email address".into()));
        return;
    }

    // A credential-shaped token that is not an email: `user:pass`.
    if let Some((user, pass)) = line.split_once(':') {
        if !user.is_empty() && !pass.is_empty() && !pass.contains(' ') {
            h.push(
                Category::Credential,
                format!("{user}:{pass}"),
                Some("username and password".into()),
            );
            return;
        }
    }

    h.push(Category::Evidence, line, Some(format!("line {lineno}")));
}

/// Interpret one `[...]` field of an httpx-style probe line.
fn classify_bracket_field(field: &str, h: &mut Harvest) {
    let field = field.trim();
    if field.is_empty() {
        return;
    }
    // A three-digit status code.
    if field.len() == 3 && field.bytes().all(|b| b.is_ascii_digit()) {
        h.push(Category::Http, format!("HTTP {field}"), None);
        return;
    }
    // A content length.
    if field.bytes().all(|b| b.is_ascii_digit()) {
        h.push(Category::Http, format!("{field} bytes"), None);
        return;
    }
    // A comma-separated technology list: `Python:3.14.7,SimpleHTTP:0.6`.
    if field.contains(':') && field.split(',').all(|p| p.contains(':')) {
        for part in field.split(',') {
            match part.split_once(':') {
                Some((name, version))
                    if version.chars().next().is_some_and(|c| c.is_ascii_digit()) =>
                {
                    h.push(
                        Category::Technology,
                        name,
                        Some(format!("version {version}")),
                    );
                    h.push(Category::Version, version, Some(name.to_string()));
                }
                Some((name, version)) => {
                    h.push(
                        Category::Technology,
                        name,
                        Some(format!("version {version}")),
                    );
                }
                None => h.push(Category::Technology, part, None),
            }
        }
        return;
    }
    if field.parse::<std::net::IpAddr>().is_ok() {
        h.push(Category::Ip, field, None);
        return;
    }
    // What is left is the page title, which is an HTTP observation.
    h.push(Category::Http, field, Some("title".into()));
}

// ── raw ─────────────────────────────────────────────────────────────────────

/// Keep a tool's own output verbatim, as evidence.
fn parse_raw(text: &str, h: &mut Harvest) {
    for line in text.lines() {
        let line = line.trim_end();
        if !line.trim().is_empty() {
            h.push(Category::Evidence, line, None);
        }
    }
    if h.is_empty() {
        h.note("raw output was empty");
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Split `host:port`, requiring a real port number so a URL is not mistaken.
fn split_host_port(line: &str) -> Option<(String, String)> {
    let (addr, port) = line.rsplit_once(':')?;
    if addr.is_empty() || port.is_empty() {
        return None;
    }
    let numeric = port.parse::<u16>().is_ok() && (1..=65535).contains(&port.parse::<u16>().ok()?);
    if !numeric {
        return None;
    }
    let is_addr = addr.parse::<std::net::IpAddr>().is_ok()
        || (addr.contains('.') && !addr.contains('/') && looks_like_hostname(addr));
    is_addr.then(|| (addr.to_string(), port.to_string()))
}

/// Host portion of a URL, without the scheme, port, path or credentials.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.split(['/', '?', '#']).next()?;
    // Strip any userinfo.
    let rest = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }
    // An IPv6 literal is bracketed.
    if let Some(inner) = rest.strip_prefix('[') {
        return inner.split(']').next().map(str::to_string);
    }
    rest.split(':')
        .next()
        .filter(|h| !h.is_empty())
        .map(str::to_string)
}

/// Whether a bare token is plausibly a hostname.
fn looks_like_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.contains(' ')
        && !s.contains('/')
        && !s.contains('"')
        && s.contains('.')
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

fn is_email(s: &str) -> bool {
    let Some((user, domain)) = s.split_once('@') else {
        return false;
    };
    !user.is_empty() && !user.contains(' ') && looks_like_hostname(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn prov() -> Provenance {
        Provenance {
            boundary: crate::domain::execution::ExecBoundary::Oniux,
            provider: "test".into(),
            operation: "op".into(),
            task_id: "T01".into(),
            command: "test -x".into(),
            observed_at: Utc::now(),
            artifact: PathBuf::from("/tmp/raw"),
        }
    }

    fn values(h: &Harvest, cat: Category) -> Vec<&str> {
        h.findings()
            .iter()
            .filter(|f| f.category == cat)
            .map(|f| f.value.as_str())
            .collect()
    }

    #[test]
    fn naabu_style_lines_become_a_port_and_an_ip() {
        let mut h = Harvest::default();
        parse_lines("127.0.0.1:18080\n127.0.0.1:18081\n", &mut h);
        assert_eq!(values(&h, Category::Ip), ["127.0.0.1", "127.0.0.1"]);
        assert_eq!(values(&h, Category::Port), ["18080", "18081"]);
    }

    #[test]
    fn subfinder_style_lines_become_hosts() {
        let mut h = Harvest::default();
        parse_lines("www.example.com\nmail.example.com\n", &mut h);
        assert_eq!(
            values(&h, Category::Host),
            ["www.example.com", "mail.example.com"]
        );
        assert!(h.findings().iter().all(|f| f.category != Category::Ip));
    }

    #[test]
    fn httpx_bracket_lines_are_broken_into_their_parts() {
        let mut h = Harvest::default();
        parse_lines(
            "http://127.0.0.1:18081 [200] [442] [Directory listing for /] [127.0.0.1] [Python:3.14.7,SimpleHTTP:0.6]\n",
            &mut h,
        );
        assert!(values(&h, Category::Url).contains(&"http://127.0.0.1:18081"));
        assert!(values(&h, Category::Host).contains(&"127.0.0.1"));
        assert!(values(&h, Category::Http).contains(&"HTTP 200"));
        assert_eq!(values(&h, Category::Technology), ["Python", "SimpleHTTP"]);
        assert!(values(&h, Category::Version).contains(&"3.14.7"));
    }

    #[test]
    fn an_unrecognised_line_is_kept_as_evidence_not_dropped() {
        let mut h = Harvest::default();
        parse_lines("something entirely unexpected here\n", &mut h);
        assert_eq!(
            values(&h, Category::Evidence),
            ["something entirely unexpected here"]
        );
    }

    #[test]
    fn nmap_xml_yields_ports_services_versions_and_addresses() {
        // Captured from `nmap -sV -oX` against a local listener.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.991">
<host><status state="up" reason="conn-refused"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="18080"><state state="open" reason="syn-ack"/>
<service name="http" product="SimpleHTTPServer" version="0.6" extrainfo="Python 3.14.7" method="probed" conf="10"><cpe>cpe:/a:python:simplehttpserver:0.6</cpe></service></port>
<port protocol="tcp" portid="22"><state state="closed" reason="conn-refused"/><service name="ssh"/></port>
</ports>
</host>
<runstats><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"#;
        let mut h = Harvest::default();
        parse_nmap_xml(xml, &mut h);
        assert_eq!(values(&h, Category::Ip), ["127.0.0.1"]);
        assert_eq!(values(&h, Category::Host), ["localhost"]);
        // The closed port is deliberately absent.
        assert_eq!(values(&h, Category::Port), ["18080/tcp"]);
        assert_eq!(values(&h, Category::Service), ["http"]);
        assert_eq!(values(&h, Category::Technology), ["SimpleHTTPServer"]);
        assert_eq!(values(&h, Category::Version), ["0.6"]);
    }

    #[test]
    fn nmap_xml_that_is_not_xml_falls_back_to_evidence() {
        let mut h = Harvest::default();
        parse_nmap_xml("Nmap done: 1 IP address scanned", &mut h);
        assert!(!h.is_empty());
    }

    #[test]
    fn nuclei_jsonl_yields_a_finding_with_its_severity() {
        // Shape captured from `nuclei -jsonl`.
        let line = r#"{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","severity":"info"},"matcher-name":"python","host":"127.0.0.1","port":"18081","ip":"127.0.0.1","matched-at":"http://127.0.0.1:18081"}"#;
        let mut h = Harvest::default();
        parse_jsonl(&format!("{line}\n"), &mut h);
        assert!(values(&h, Category::Finding).contains(&"Wappalyzer Technology Detection (info)"));
        assert!(values(&h, Category::Url).contains(&"http://127.0.0.1:18081"));
        assert!(values(&h, Category::Technology).contains(&"python"));
        assert_eq!(values(&h, Category::Port), ["18081"]);
    }

    #[test]
    fn a_malformed_json_line_is_kept_and_noted_rather_than_fatal() {
        let mut h = Harvest::default();
        parse_jsonl("{\"a\":1}\n{not json\n", &mut h);
        assert!(
            h.notes().iter().any(|n| n.contains("not valid JSON")),
            "{:?}",
            h.notes()
        );
        assert!(values(&h, Category::Evidence).contains(&"{not json"));
    }

    #[test]
    fn raw_output_is_preserved_line_for_line() {
        let mut h = Harvest::default();
        parse_raw("line one\n\nline two\n", &mut h);
        assert_eq!(values(&h, Category::Evidence), ["line one", "line two"]);
    }

    #[test]
    fn email_and_credential_lines_are_classified() {
        let mut h = Harvest::default();
        parse_lines("admin@example.com\nadministrator:hunter2\n", &mut h);
        assert!(values(&h, Category::Credential).contains(&"admin@example.com"));
        assert!(values(&h, Category::Credential).contains(&"administrator:hunter2"));
    }

    #[test]
    fn duplicate_findings_collapse_and_keep_every_source() {
        let mut a = Harvest::default();
        a.push(Category::Host, "WWW.Example.com", None);
        a.attribute(prov());
        let mut b = Harvest::default();
        b.push(Category::Host, "www.example.com", None);
        b.attribute(Provenance {
            provider: "other".into(),
            ..prov()
        });

        let mut combined = a;
        combined.absorb(b);
        let merged = combined.deduped();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].occurrences, 2);
        let mut tools: Vec<&str> = merged[0]
            .sources
            .iter()
            .map(|s| s.provider.as_str())
            .collect();
        tools.sort_unstable();
        assert_eq!(tools, ["other", "test"]);
        // The first spelling seen is kept, not normalised away.
        assert_eq!(merged[0].value, "WWW.Example.com");
    }

    #[test]
    fn dedup_order_is_deterministic_and_high_signal_first() {
        let mut h = Harvest::default();
        h.push(Category::Evidence, "noise", None);
        h.push(Category::Host, "b.example.com", None);
        h.push(Category::Finding, "critical issue", None);
        h.push(Category::Host, "a.example.com", None);
        let order: Vec<Category> = h.deduped().iter().map(|f| f.category).collect();
        assert_eq!(
            order,
            vec![
                Category::Finding,
                Category::Host,
                Category::Host,
                Category::Evidence
            ]
        );
        let again: Vec<Category> = h.deduped().iter().map(|f| f.category).collect();
        assert_eq!(order, again, "dedup must be stable across calls");
    }

    #[test]
    fn every_finding_carries_the_provenance_of_its_task() {
        let mut h = Harvest::default();
        parse_lines("10.0.0.1:22\n", &mut h);
        h.attribute(prov());
        assert!(h.findings().iter().all(|f| f.provenance.task_id == "T01"));
    }

    #[test]
    fn host_extraction_strips_scheme_port_path_and_credentials() {
        assert_eq!(
            host_of("https://example.com:8443/a/b?c=d").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host_of("http://user:pw@10.0.0.1:80/").as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(
            host_of("http://[2001:db8::1]:80/").as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn a_url_is_not_mistaken_for_a_host_port_pair() {
        assert!(split_host_port("http://example.com").is_none());
        assert!(split_host_port("127.0.0.1:notaport").is_none());
        assert_eq!(
            split_host_port("127.0.0.1:443"),
            Some(("127.0.0.1".into(), "443".into()))
        );
    }

    #[test]
    fn a_merged_finding_line_names_its_tools() {
        let mut a = Harvest::default();
        a.push(Category::Port, "443/tcp", Some("open".into()));
        a.attribute(Provenance {
            provider: "nmap".into(),
            ..prov()
        });
        let mut b = Harvest::default();
        b.push(Category::Port, "443/tcp", Some("open".into()));
        b.attribute(Provenance {
            provider: "naabu".into(),
            ..prov()
        });
        let mut both = a;
        both.absorb(b);
        let line = both.deduped()[0].line();
        assert!(line.contains("443/tcp"), "{line}");
        assert!(line.contains("naabu, nmap"), "{line}");
    }
}
