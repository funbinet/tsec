//! Capability input declaration, collection and validation.
//!
//! A capability declares exactly which inputs it needs, what type each one is,
//! whether it is required, and how it must look. Validation happens *before*
//! any plan is built, so a malformed value can never reach an external tool.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use regex::Regex;

use crate::error::{ExecutionErrorKind, Result, Stage, TsecError};

/// The kind of value an input carries. The type determines the prompt, the
/// validator and the placeholder available to command builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// Fully qualified domain name, e.g. `example.com`.
    Domain,
    /// A registrable domain including a public suffix, used by OSINT tools
    /// that accept company names as well as domains.
    #[serde(rename = "domain/company")]
    DomainOrCompany,
    /// IPv4 address or IPv4 CIDR block.
    #[serde(rename = "ip/cidr")]
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// Hostname, IP or URL — the general "thing to point a tool at".
    Target,
    /// A `scheme://host[:port]` URL.
    Url,
    /// A single TCP/UDP port number, 1-65535.
    Port,
    /// Port list or range, e.g. `80,443,8000-9000`.
    Ports,
    /// Path to an existing file.
    File,
    /// Path to a file or directory that need not exist yet.
    Path,
    /// Free-form single-line text.
    Text,
    /// Free-form text that must not be logged verbatim.
    Secret,
    /// Positive integer within an inclusive range.
    Integer,
    /// Boolean switch expressed as `true`/`false`.
    Flag,
    /// Account name.
    Username,
    /// Password, kept out of logs and harvest provenance.
    Password,
    /// Password hash in any supported algorithm notation.
    Hash,
    /// Network interface, e.g. `wlan0`.
    Interface,
    /// MAC / BSSID address.
    Mac,
    /// Session or workspace identifier.
    Session,
    /// Free-form list of comma separated values.
    List,
}

impl InputType {
    /// Short type name shown next to the prompt.
    pub fn label(self) -> &'static str {
        match self {
            InputType::Domain => "domain",
            InputType::DomainOrCompany => "domain/company",
            InputType::Ipv4 => "ip/cidr",
            InputType::Ipv6 => "ipv6",
            InputType::Target => "target",
            InputType::Url => "url",
            InputType::Port => "port",
            InputType::Ports => "ports",
            InputType::File => "file",
            InputType::Path => "path",
            InputType::Text => "text",
            InputType::Secret => "secret",
            InputType::Integer => "integer",
            InputType::Flag => "flag",
            InputType::Username => "username",
            InputType::Password => "password",
            InputType::Hash => "hash",
            InputType::Interface => "interface",
            InputType::Mac => "mac",
            InputType::Session => "session",
            InputType::List => "list",
        }
    }

    /// Whether values of this type must be redacted from logs and provenance.
    pub fn is_sensitive(self) -> bool {
        matches!(self, InputType::Secret | InputType::Password)
    }
}

/// An additional constraint layered on top of the base type check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationRule {
    /// Value must be one of a fixed set.
    OneOf(Vec<String>),
    /// Integer value must fall within an inclusive range.
    Range(u64, u64),
    /// Value must be a known, installed tool's supported mode.
    NonEmpty,
}

/// Declaration of a single capability input.
///
/// The strings are `Cow` rather than `&'static str` because a capability's
/// inputs are declared in `catalog/capabilities.toml`: the framework reads that
/// file at startup, so the declaration owns its strings and nothing has to be
/// leaked to satisfy a `'static` bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSpec {
    /// Stable key, also the placeholder name used by command builders.
    pub key: Cow<'static, str>,
    /// Prompt label shown to the operator.
    ///
    /// Optional in the catalog file: a capability that omits it gets the input
    /// key, which is already a human-readable word like `domain` or `target`.
    #[serde(default)]
    pub label: Cow<'static, str>,
    #[serde(rename = "type")]
    pub ty: InputType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<Cow<'static, str>>,
    #[serde(default)]
    pub help: Option<Cow<'static, str>>,
    #[serde(default)]
    pub rule: Option<ValidationRule>,
}

impl InputSpec {
    pub fn new(
        key: impl Into<Cow<'static, str>>,
        label: impl Into<Cow<'static, str>>,
        ty: InputType,
        required: bool,
    ) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            ty,
            required,
            default: None,
            help: None,
            rule: None,
        }
    }

    /// Fill in an omitted label from the key.
    pub fn normalise(mut self) -> Self {
        if self.label.is_empty() {
            self.label = self.key.clone();
        }
        self
    }

    pub fn with_default(mut self, value: impl Into<Cow<'static, str>>) -> Self {
        self.default = Some(value.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<Cow<'static, str>>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_rule(mut self, rule: ValidationRule) -> Self {
        self.rule = Some(rule);
        self
    }

    /// Validate a candidate value for this input.
    pub fn validate(&self, raw: &str) -> Result<String> {
        let value = raw.trim();
        let fail = |reason: &str| -> Result<String> {
            Err(TsecError::input(
                self.label.as_ref(),
                format!("{reason} (expected {})", self.ty.label()),
            ))
        };

        if value.is_empty() {
            if self.required {
                return fail("value is required");
            }
            return Ok(String::new());
        }

        match self.ty {
            InputType::Domain => {
                if domain_re().is_match(value) {
                    Ok(value.to_ascii_lowercase())
                } else {
                    fail("not a valid domain name")
                }
            }
            InputType::DomainOrCompany => {
                if value.contains(char::is_whitespace) || value.contains('/') {
                    return Err(TsecError::input(
                        self.label.as_ref(),
                        "must be a single token (domain or company name) without spaces or slashes",
                    ));
                }
                Ok(value.to_string())
            }
            InputType::Ipv4 => match parse_ipv4_or_cidr(value) {
                Ok(v) => Ok(v),
                Err(e) => fail(e),
            },
            InputType::Ipv6 => {
                if value.parse::<std::net::Ipv6Addr>().is_ok() {
                    Ok(value.to_string())
                } else {
                    fail("not a valid IPv6 address")
                }
            }
            InputType::Target => {
                if value.contains(' ') {
                    return fail("must be a single target (no spaces)");
                }
                if value.contains("://") {
                    if value.starts_with("http://") || value.starts_with("https://") {
                        Ok(value.to_string())
                    } else {
                        fail("URL scheme must be http or https")
                    }
                } else if value.parse::<std::net::IpAddr>().is_ok()
                    || parse_ipv4_or_cidr(value).is_ok()
                    || domain_re().is_match(value)
                {
                    Ok(value.to_string())
                } else {
                    fail("not an IP, CIDR, hostname or URL")
                }
            }
            InputType::Url => {
                if value.starts_with("http://") || value.starts_with("https://") {
                    if value.trim_end_matches('/').len() > "https://".len() {
                        Ok(value.to_string())
                    } else {
                        fail("URL has no host")
                    }
                } else {
                    fail("URL must begin with http:// or https://")
                }
            }
            InputType::Port => match value.parse::<u16>() {
                Ok(0) | Err(_) => fail("port must be between 1 and 65535"),
                Ok(_) => Ok(value.to_string()),
            },
            InputType::Ports => {
                if ports_re().is_match(value) {
                    Ok(value.to_string())
                } else {
                    fail("ports must be digits, commas, hyphens or colons, e.g. 80,443,8000-9000")
                }
            }
            InputType::File => {
                if Path::new(value).is_file() {
                    Ok(value.to_string())
                } else {
                    Err(TsecError::new(
                        Stage::Validate,
                        ExecutionErrorKind::MissingFile {
                            path: Path::new(value).to_path_buf(),
                        },
                    ))
                }
            }
            InputType::Path => Ok(value.to_string()),
            InputType::Text | InputType::Username | InputType::Session => {
                if value.chars().any(char::is_control) {
                    fail("control characters are not allowed")
                } else {
                    Ok(value.to_string())
                }
            }
            InputType::Secret | InputType::Password => {
                if value.chars().any(char::is_control) {
                    fail("control characters are not allowed")
                } else {
                    Ok(value.to_string())
                }
            }
            InputType::Hash => {
                if value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "$*.:/\\@=+-".contains(c))
                    && value.len() >= 8
                {
                    Ok(value.to_string())
                } else {
                    fail("not a recognisable password hash")
                }
            }
            InputType::Interface => {
                if interface_re().is_match(value) {
                    Ok(value.to_string())
                } else {
                    fail("not a valid interface name, e.g. wlan0 or eth0")
                }
            }
            InputType::Mac => {
                if mac_re().is_match(value) {
                    Ok(value.to_ascii_lowercase())
                } else {
                    fail("not a valid MAC address")
                }
            }
            InputType::Integer => {
                let n: u64 = value.parse().map_err(|_| {
                    TsecError::input(self.label.as_ref(), "must be a non-negative whole number")
                })?;
                if let Some(ValidationRule::Range(lo, hi)) = self.rule {
                    if n < lo || n > hi {
                        return Err(TsecError::input(
                            self.label.as_ref(),
                            format!("must be between {lo} and {hi}"),
                        ));
                    }
                }
                Ok(n.to_string())
            }
            InputType::Flag => match value.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Ok("true".into()),
                "false" | "no" | "off" | "0" => Ok("false".into()),
                _ => fail("must be true or false"),
            },
            InputType::List => {
                if value.split(',').all(|p| !p.trim().is_empty()) {
                    Ok(value
                        .split(',')
                        .map(|p| p.trim().to_string())
                        .collect::<Vec<_>>()
                        .join(","))
                } else {
                    fail("comma separated list must not contain empty entries")
                }
            }
        }
    }
}

/// Ordered, immutable set of validated input values for one capability run.
#[derive(Debug, Clone, Default)]
pub struct InputValues {
    map: BTreeMap<String, String>,
    order: Vec<String>,
}

impl InputValues {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        if !self.map.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.map.insert(key, value.into());
    }

    /// Fetch a value, or an empty string when absent.
    pub fn get(&self, key: &str) -> &str {
        self.map.get(key).map(String::as_str).unwrap_or("")
    }

    /// Fetch a value that the plan builder requires to be present.
    pub fn require(&self, key: &str) -> Result<&str> {
        let v = self.get(key);
        if v.is_empty() {
            Err(TsecError::internal(format!(
                "input `{key}` was not collected before planning"
            )))
        } else {
            Ok(v)
        }
    }

    pub fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// Values in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.order
            .iter()
            .filter_map(move |k| self.map.get_key_value(k))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Redacted rendering for logs and reports.
    pub fn redacted_pairs(&self, specs: &[InputSpec]) -> Vec<(String, String)> {
        self.order
            .iter()
            .filter_map(|k| self.map.get(k).map(|v| (k.clone(), v.clone())))
            .map(|(k, v)| {
                let sensitive = specs.iter().any(|s| s.key == k && s.ty.is_sensitive());
                if sensitive && !v.is_empty() {
                    (k, "<redacted>".to_string())
                } else {
                    (k, v)
                }
            })
            .collect()
    }
}

impl fmt::Display for InputValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rendered: Vec<String> = self
            .order
            .iter()
            .map(|k| format!("{k}={}", self.get(k)))
            .collect();
        f.write_str(&rendered.join(" "))
    }
}

fn domain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^([a-z0-9_]([a-z0-9\-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$").unwrap()
    })
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d{1,2})?$").unwrap()
    })
}

/// Validate an IPv4 address or CIDR block.
///
/// A shape-only regex is not enough: `999.1.1.1` is well formed but not a
/// routable address, and passing it to a scanner wastes the operator's time and
/// hides a typo. Octet ranges and prefix length are therefore checked properly.
fn parse_ipv4_or_cidr(value: &str) -> std::result::Result<String, &'static str> {
    let (addr, prefix) = match value.split_once('/') {
        Some((a, p)) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("not a valid IPv4 address or CIDR block");
            }
            (a, Some(p))
        }
        None => (value, None),
    };

    if !ipv4_re().is_match(value) {
        return Err("not a valid IPv4 address or CIDR block");
    }

    let octets: Vec<u16> = addr
        .split('.')
        .map(|o| o.parse::<u16>().unwrap_or(u16::MAX))
        .collect();
    if octets.len() != 4 || octets.iter().any(|o| *o > 255) {
        return Err("each address octet must be 0-255");
    }
    // A leading zero is ambiguous (octal in some resolvers) and is a typo far
    // more often than it is intentional.
    if addr.split('.').any(|o| o.len() > 1 && o.starts_with('0')) {
        return Err("address octets must not have leading zeros");
    }
    if let Some(p) = prefix {
        let n: u32 = p.parse().map_err(|_| "prefix length must be a number")?;
        if n > 32 {
            return Err("CIDR prefix length must be 0-32");
        }
    }
    Ok(value.to_string())
}

fn ports_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9,\-:]+$").unwrap())
}

fn interface_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_.:-]{0,30}$").unwrap())
}

fn mac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$").unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(ty: InputType) -> InputSpec {
        InputSpec::new("value", "Value", ty, true)
    }

    #[test]
    fn domain_validation_is_case_insensitive_and_normalised() {
        let s = spec(InputType::Domain);
        assert_eq!(s.validate("Example.COM").unwrap(), "example.com");
        assert!(s.validate("not a domain").is_err());
        assert!(s.validate("http://example.com").is_err());
    }

    #[test]
    fn ipv4_accepts_cidr_and_rejects_out_of_range_octets() {
        let s = spec(InputType::Ipv4);
        assert_eq!(s.validate("192.168.1.0/24").unwrap(), "192.168.1.0/24");
        assert!(s.validate("999.1.1.1").is_err());
    }

    #[test]
    fn port_range_is_enforced() {
        let s = spec(InputType::Port);
        assert!(s.validate("0").is_err());
        assert!(s.validate("65536").is_err());
        assert_eq!(s.validate("443").unwrap(), "443");
    }

    #[test]
    fn integer_rule_bounds_are_enforced() {
        let s = InputSpec::new("threads", "Threads", InputType::Integer, true)
            .with_rule(ValidationRule::Range(1, 500));
        assert_eq!(s.validate("50").unwrap(), "50");
        assert!(s.validate("0").is_err());
        assert!(s.validate("abc").is_err());
    }

    #[test]
    fn url_requires_http_scheme_and_host() {
        let s = spec(InputType::Url);
        assert!(s.validate("https://example.com/x").is_ok());
        assert!(s.validate("https://").is_err());
        assert!(s.validate("example.com").is_err());
    }

    #[test]
    fn list_normalises_whitespace() {
        let s = spec(InputType::List);
        assert_eq!(s.validate(" crtsh , shodan ").unwrap(), "crtsh,shodan");
        assert!(s.validate("a,,b").is_err());
    }

    #[test]
    fn secret_inputs_are_redacted_in_renderings() {
        let specs = vec![InputSpec::new(
            "password",
            "Password",
            InputType::Password,
            true,
        )];
        let mut v = InputValues::new();
        v.insert("password", "hunter2!");
        v.insert("domain", "example.com");
        let pairs = v.redacted_pairs(&specs);
        assert_eq!(pairs[0].1, "<redacted>");
        assert_eq!(pairs[1].1, "example.com");
    }

    #[test]
    fn optional_input_may_be_empty() {
        let s = InputSpec::new("note", "Note", InputType::Text, false);
        assert_eq!(s.validate("  ").unwrap(), "");
    }

    #[test]
    fn control_characters_are_rejected() {
        let s = spec(InputType::Text);
        assert!(s.validate("bad\u{7}value").is_err());
    }

    #[test]
    fn values_render_in_declaration_order() {
        let mut v = InputValues::new();
        v.insert("z", "1");
        v.insert("a", "2");
        assert_eq!(v.to_string(), "z=1 a=2");
    }
}
