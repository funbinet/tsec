//! The capability catalog.
//!
//! `catalog/capabilities.toml` is the single source of truth for what the
//! operator can do: ten phases, and inside them the capabilities an operator
//! chooses, the inputs each one needs, and the exact provider operations that
//! implement it. The loader validates all of it at startup and refuses to run
//! a catalog it cannot vouch for.
//!
//! Three rules are enforced here, not elsewhere:
//!   * a phase label is one uppercase word and a capability label exactly two;
//!   * every `{placeholder}` names a declared input, so a renamed input fails
//!     loudly instead of reaching a tool as a literal `{target}`;
//!   * an argument may not contain shell syntax, because the runtime never
//!     invokes a shell.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::command::Command;
use crate::domain::ids::CapabilityId;
use crate::domain::input::{InputSpec, InputValues};
use crate::error::{Result, TsecError};
use crate::provider::find_in_path;

/// The authoritative ten-phase model, in run order.
pub const PHASES: [&str; 10] = [
    "recon",
    "surface",
    "vulnerability",
    "payload",
    "escalation",
    "credentials",
    "lateral",
    "persistence",
    "objectives",
    "wireless",
];

/// One-word uppercase phase name for a phase slug.
pub fn phase_label(slug: &str) -> Option<&'static str> {
    Some(match slug {
        "recon" => "RECON",
        "surface" => "SURFACE",
        "vulnerability" => "VULNERABILITY",
        "payload" => "PAYLOAD",
        "escalation" => "ESCALATION",
        "credentials" => "CREDENTIALS",
        "lateral" => "LATERAL",
        "persistence" => "PERSISTENCE",
        "objectives" => "OBJECTIVES",
        "wireless" => "WIRELESS",
        _ => return None,
    })
}

/// Characters that only mean something to a shell. Nothing is ever passed to
/// one, so a template containing any of these is a catalog authoring error.
const SHELL_ONLY: &[char] = &['|', '&', ';', '<', '>', '`', '$', '(', ')'];

/// How a tool's output should be read once captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// One finding per line.
    Lines,
    /// Newline-delimited JSON.
    Json,
    /// A tool's own format, kept verbatim.
    Raw,
    /// nmap's XML report format.
    Nmap,
}

/// A single provider invocation, with its arguments fully spelled out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub name: String,
    pub args: Vec<String>,
    pub output: OutputFormat,
    /// Whether the operation touches the network and must run behind oniux.
    #[serde(default = "default_network")]
    pub network: bool,
}

fn default_network() -> bool {
    true
}

impl Operation {
    /// Render this operation as a concrete command.
    ///
    /// A placeholder occupying a whole argument is substituted as exactly one
    /// argv entry, however much whitespace the value contains; a placeholder
    /// embedded in a larger token is interpolated into that token. Values for
    /// sensitive inputs are registered on the command so the secret is masked
    /// everywhere the command is displayed, recorded or written to a report.
    pub fn command(
        &self,
        program: &Path,
        specs: &[InputSpec],
        values: &InputValues,
    ) -> Result<Command> {
        let mut args: Vec<String> = Vec::with_capacity(self.args.len());
        let mut sensitive: Vec<usize> = Vec::new();

        for token in &self.args {
            let whole = token
                .strip_prefix('{')
                .and_then(|t| t.strip_suffix('}'))
                .filter(|k| !k.is_empty() && !k.contains('{') && !k.contains('}'));

            if let Some(key) = whole {
                let spec = specs.iter().find(|s| s.key == key).ok_or_else(|| {
                    TsecError::catalog(format!(
                        "operation `{}` uses undeclared input {{{key}}}",
                        self.name
                    ))
                })?;
                if spec.ty.is_sensitive() {
                    sensitive.push(args.len());
                }
                args.push(values.get(key).to_string());
            } else {
                args.push(expand(token, specs, values, &self.name)?);
            }
        }

        let mut cmd = Command::new(program.display().to_string(), args).network(self.network);
        for i in sensitive {
            cmd = cmd.mark_sensitive(i);
        }
        Ok(cmd)
    }
}

/// Interpolate a placeholder embedded inside a larger token, e.g. `--rate={rate}`.
///
/// Three escapes are understood, because a tool's argument vector is not a shell
/// and the catalog has to be able to say exactly what a tool should receive:
/// `{{` and `}}` are literal braces, and `%{…}` is printf-style literal text
/// (curl's `%{http_code}`), copied through untouched.
fn expand(
    token: &str,
    specs: &[InputSpec],
    values: &InputValues,
    operation: &str,
) -> Result<String> {
    let bytes = token.as_bytes();
    let mut out = String::with_capacity(token.len());
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'%' if bytes.get(i + 1) == Some(&b'{') => {
                let close = token[i + 2..]
                    .find('}')
                    .map(|offset| i + 2 + offset + 1)
                    .unwrap_or(bytes.len());
                out.push_str(&token[i..close]);
                i = close;
            }
            b'{' if bytes.get(i + 1) == Some(&b'{') => {
                out.push('{');
                i += 2;
            }
            b'}' if bytes.get(i + 1) == Some(&b'}') => {
                out.push('}');
                i += 2;
            }
            b'{' => match token[i + 1..].find('}') {
                Some(offset) => {
                    let key = &token[i + 1..i + 1 + offset];
                    if !specs.iter().any(|s| s.key == key) {
                        return Err(TsecError::catalog(format!(
                            "operation `{operation}` uses undeclared input {{{key}}}"
                        )));
                    }
                    out.push_str(values.get(key));
                    i = i + 1 + offset + 1;
                }
                None => {
                    out.push('{');
                    i += 1;
                }
            },
            b'}' => {
                out.push('}');
                i += 1;
            }
            _ => {
                let ch = token[i..].chars().next().unwrap_or('?');
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }

    Ok(out)
}

/// One tool, and the operations it provides for a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderBinding {
    pub binary: String,
    #[serde(rename = "operation", default)]
    pub operations: Vec<Operation>,
}

/// One capability the operator can select.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub phase: String,
    /// Exactly two uppercase words, per the interface rules.
    pub label: String,
    pub summary: String,
    #[serde(default)]
    pub inputs: Vec<InputSpec>,
    #[serde(rename = "provider", default)]
    pub providers: Vec<ProviderBinding>,
}

impl Capability {
    pub fn capability_id(&self) -> CapabilityId {
        CapabilityId::new(self.id.clone())
    }

    /// Inputs the operator must answer before the capability can run.
    pub fn required_inputs(&self) -> impl Iterator<Item = &InputSpec> {
        self.inputs.iter().filter(|s| s.required)
    }

    /// Every provider operation the capability can dispatch, across bindings.
    pub fn all_operations(&self) -> impl Iterator<Item = (&str, &Operation)> {
        self.providers
            .iter()
            .flat_map(|p| p.operations.iter().map(move |o| (p.binary.as_str(), o)))
    }

    pub fn is_available(&self) -> bool {
        self.unavailable_reason().is_none()
    }

    /// Why this capability cannot run right now, or `None` if it can.
    ///
    /// Availability is derived from the catalog itself: a capability is
    /// available when at least one of its provider binaries resolves on the
    /// host. The reason names the missing binaries, because "unavailable" on
    /// its own tells the operator nothing.
    pub fn unavailable_reason(&self) -> Option<String> {
        let mut wanted: Vec<&str> = Vec::new();
        for p in &self.providers {
            if p.operations.is_empty() {
                continue;
            }
            if find_in_path(&p.binary).is_some() {
                return None;
            }
            wanted.push(p.binary.as_str());
        }
        if wanted.is_empty() {
            return Some(format!("`{}` declares no provider operations", self.id));
        }
        wanted.sort_unstable();
        wanted.dedup();
        Some(format!("{} not installed", wanted.join(", ")))
    }
}

/// The parsed, validated catalog file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CatalogFile {
    schema: u32,
    #[serde(rename = "capability", default)]
    capabilities: Vec<Capability>,
}

/// A loaded, validated capability catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    capabilities: Vec<Capability>,
    source: PathBuf,
}

impl Catalog {
    /// Load and validate `catalog/capabilities.toml`.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            TsecError::io(format!("reading capability catalog {}", path.display()), &e)
        })?;
        Self::from_toml(&raw, path)
    }

    /// Parse and validate catalog TOML.
    ///
    /// Validation happens at load time so a malformed catalog is a startup
    /// failure with a file and line to look at, not a surprise halfway
    /// through a capability.
    pub fn from_toml(raw: &str, source: &Path) -> Result<Self> {
        let fail = |why: String| -> TsecError {
            TsecError::catalog(format!("{}: {why}", source.display()))
        };

        let mut file: CatalogFile =
            toml::from_str(raw).map_err(|e| fail(format!("could not be parsed: {e}")))?;

        for cap in &mut file.capabilities {
            for spec in &mut cap.inputs {
                if spec.label.is_empty() {
                    spec.label = spec.key.clone();
                }
            }
        }

        if file.schema != 1 {
            return Err(fail(format!(
                "unsupported catalog schema {} (expected 1)",
                file.schema
            )));
        }

        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut per_phase: BTreeMap<&str, usize> = BTreeMap::new();
        for cap in &file.capabilities {
            let where_ = format!("capability `{}`", cap.id);

            if !seen.insert(cap.id.as_str()) {
                return Err(fail(format!("{where_} is declared twice")));
            }
            if !cap.id.starts_with(&format!("{}.", cap.phase)) {
                return Err(fail(format!(
                    "{where_} must be namespaced under its phase `{}`",
                    cap.phase
                )));
            }
            if phase_label(&cap.phase).is_none() {
                return Err(fail(format!(
                    "{where_} names phase `{}`, which is not one of the ten phases",
                    cap.phase
                )));
            }
            *per_phase.entry(cap.phase.as_str()).or_default() += 1;
            check_label(&fail, &where_, &cap.label)?;
            if cap.summary.trim().is_empty() {
                return Err(fail(format!("{where_} has no summary")));
            }

            let mut keys: BTreeSet<&str> = BTreeSet::new();
            for spec in &cap.inputs {
                if !keys.insert(spec.key.as_ref()) {
                    return Err(fail(format!(
                        "{where_} declares input `{}` twice",
                        spec.key
                    )));
                }
                if spec.required && spec.default.is_some() {
                    return Err(fail(format!(
                        "{where_} input `{}` is required yet has a default",
                        spec.key
                    )));
                }
            }

            if cap.providers.is_empty() {
                return Err(fail(format!("{where_} has no providers")));
            }
            for prov in &cap.providers {
                if prov.operations.is_empty() {
                    return Err(fail(format!(
                        "{where_} provider `{}` has no operations",
                        prov.binary
                    )));
                }
                for op in &prov.operations {
                    if op.name.trim().is_empty() {
                        return Err(fail(format!(
                            "{where_} provider `{}` has an unnamed operation",
                            prov.binary
                        )));
                    }
                    if op.args.is_empty() {
                        return Err(fail(format!(
                            "{where_} operation `{}` has no arguments",
                            op.name
                        )));
                    }
                    for token in &op.args {
                        if let Some(c) = token.chars().find(|c| SHELL_ONLY.contains(c)) {
                            return Err(fail(format!(
                                "{where_} operation `{}` argument {token:?} contains shell \
                                 syntax {c:?}; arguments are passed as a vector, never a shell",
                                op.name
                            )));
                        }
                        for key in placeholders(token) {
                            if !keys.contains(key) {
                                return Err(fail(format!(
                                    "{where_} operation `{}` uses undeclared input {{{key}}}",
                                    op.name
                                )));
                            }
                        }
                    }
                }
            }
        }

        // The framework's ten-phase model is structural: a catalog that leaves
        // a phase empty is incomplete, not extensible.
        for phase in PHASES {
            if per_phase.get(phase).copied().unwrap_or(0) == 0 {
                return Err(fail(format!(
                    "phase `{}` has no capabilities; all ten phases must be populated",
                    phase
                )));
            }
        }

        Ok(Self {
            capabilities: file.capabilities,
            source: source.to_path_buf(),
        })
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn get(&self, id: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    /// Capabilities of one phase, in catalog order.
    pub fn in_phase(&self, phase: &str) -> Vec<&Capability> {
        self.capabilities
            .iter()
            .filter(|c| c.phase == phase)
            .collect()
    }

    /// Capabilities grouped by phase, phases in framework order.
    pub fn grouped(&self) -> Vec<(&'static str, Vec<&Capability>)> {
        PHASES
            .iter()
            .map(|p| (phase_label(p).unwrap(), self.in_phase(p)))
            .collect()
    }

    /// Capabilities that cannot run on this host, with the reason.
    pub fn unavailable(&self) -> Vec<(&Capability, String)> {
        self.capabilities
            .iter()
            .filter_map(|c| c.unavailable_reason().map(|r| (c, r)))
            .collect()
    }

    /// One-line readiness summary, e.g. `160/160 available`.
    pub fn availability_summary(&self) -> String {
        let total = self.capabilities.len();
        let ready = total - self.unavailable().len();
        format!("{ready}/{total} available")
    }
}

/// Reject a label that is not exactly two uppercase words.
fn check_label<F>(fail: &F, where_: &str, label: &str) -> Result<()>
where
    F: Fn(String) -> TsecError,
{
    let words: Vec<&str> = label.split(' ').collect();
    let ok = words.len() == 2
        && words.iter().all(|w| {
            !w.is_empty()
                && w.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && w.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        });
    if ok {
        Ok(())
    } else {
        Err(fail(format!(
            "{where_} label {label:?} must be exactly two uppercase words, e.g. `PORT DISCOVERY`"
        )))
    }
}

/// Placeholder names in one argument token.
///
/// Matches the substitution rule exactly: `{{`/`}}` are literal braces and
/// `%{…}` is printf-style literal text, so neither hides nor invents a
/// placeholder.
fn placeholders(token: &str) -> Vec<&str> {
    let bytes = token.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'%' if bytes.get(i + 1) == Some(&b'{') => {
                i = token[i + 2..]
                    .find('}')
                    .map(|offset| i + 2 + offset + 1)
                    .unwrap_or(bytes.len());
            }
            b'{' if bytes.get(i + 1) == Some(&b'{') => i += 2,
            b'}' if bytes.get(i + 1) == Some(&b'}') => i += 2,
            b'{' => match token[i + 1..].find('}') {
                Some(offset) => {
                    out.push(&token[i + 1..i + 1 + offset]);
                    i = i + 1 + offset + 1;
                }
                None => i += 1,
            },
            b'}' => i += 1,
            _ => {
                i += token[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            }
        }
    }

    out
}

/// Default values declared for a capability's optional inputs.
pub fn defaults(cap: &Capability) -> BTreeMap<&str, &str> {
    cap.inputs
        .iter()
        .filter_map(|s| s.default.as_deref().map(|d| (s.key.as_ref(), d)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::command::REDACTED;
    use crate::domain::input::InputType;

    fn spec(key: &str, ty: InputType) -> InputSpec {
        InputSpec::new(key.to_string(), key.to_string(), ty, true)
    }

    /// One capability's TOML, with no `schema` line so callers can stack them.
    fn cap_toml(phase: &str, label: &str) -> String {
        format!(
            r#"
            [[capability]]
            id = "{phase}.x"
            phase = "{phase}"
            label = "{label}"
            summary = "s"
            [[capability.inputs]]
            key = "target"
            type = "target"
            required = true
            [[capability.provider]]
            binary = "nmap"
            [[capability.provider.operation]]
            name = "op"
            args = ["-sV"]
            output = "lines"
            "#
        )
    }

    /// A catalog with exactly one capability, which no phase rule can accept.
    fn one_cap(phase: &str, label: &str) -> String {
        format!("schema = 1\n{}", cap_toml(phase, label))
    }

    /// The smallest catalog the loader accepts: one capability in each phase.
    fn full_catalog() -> String {
        let mut s = String::from("schema = 1\n");
        for phase in PHASES {
            s.push_str(&cap_toml(phase, "DO THING"));
        }
        s
    }
    #[test]
    fn a_well_formed_catalog_loads() {
        let cat = Catalog::from_toml(&full_catalog(), Path::new("t.toml")).unwrap();
        assert_eq!(cat.capabilities().len(), PHASES.len());
        let cap = cat.get("surface.x").unwrap();
        assert_eq!(cap.label, "DO THING");
        assert_eq!(cap.all_operations().count(), 1);
    }

    #[test]
    fn a_doubled_brace_is_a_literal_brace() {
        let toml = full_catalog().replace(
            "args = [\"-sV\"]",
            "args = [\"-c\", \"echo {{ {target} }}\"]",
        );
        let cat = Catalog::from_toml(&toml, Path::new("t.toml")).unwrap();
        let cap = cat.get("surface.x").unwrap();
        let op = &cap.providers[0].operations[0];
        let mut values = InputValues::new();
        values.insert("target", "host");
        let cmd = op.command(Path::new("sh"), &cap.inputs, &values).unwrap();
        assert_eq!(cmd.args(), &["-c".to_string(), "echo { host }".to_string()]);
    }

    #[test]
    fn a_capability_outside_the_ten_phases_is_rejected() {
        let e =
            Catalog::from_toml(&one_cap("pwnage", "DO THING"), Path::new("t.toml")).unwrap_err();
        assert!(
            e.reason().contains("not one of the ten phases"),
            "{}",
            e.reason()
        );
    }

    #[test]
    fn an_empty_phase_is_rejected() {
        let e = Catalog::from_toml(&one_cap("recon", "DO THING"), Path::new("t.toml")).unwrap_err();
        assert!(
            e.reason().contains("all ten phases must be populated"),
            "{}",
            e.reason()
        );
    }

    #[test]
    fn the_shipped_catalog_loads_and_covers_all_ten_phases() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/capabilities.toml");
        if !path.exists() {
            return;
        }
        let cat = Catalog::load(&path).unwrap();
        for (label, caps) in cat.grouped() {
            assert_eq!(caps.len(), 16, "phase {label} must hold 16 capabilities");
            for c in caps {
                assert_eq!(c.label.split(' ').count(), 2, "{}", c.label);
            }
        }
        assert_eq!(cat.capabilities().len(), 160);
    }

    #[test]
    fn a_label_must_be_exactly_two_uppercase_words() {
        for bad in [
            "PORT",
            "PORT DISCOVERY NOW",
            "port discovery",
            "PORT  DISCOVERY",
        ] {
            let e = Catalog::from_toml(&one_cap("recon", bad), Path::new("t.toml")).unwrap_err();
            assert!(
                e.reason().contains("two uppercase words"),
                "label {bad:?} should be rejected, got {}",
                e.reason()
            );
        }
    }

    #[test]
    fn an_undeclared_placeholder_is_rejected() {
        let toml = r#"
            schema = 1
            [[capability]]
            id = "recon.x"
            phase = "recon"
            label = "DO THING"
            summary = "s"
            [[capability.inputs]]
            key = "domain"
            type = "domain"
            required = true
            [[capability.provider]]
            binary = "nmap"
            [[capability.provider.operation]]
            name = "op"
            args = ["-iL", "{hosts}"]
            output = "lines"
        "#;
        let e = Catalog::from_toml(toml, Path::new("t.toml")).unwrap_err();
        assert!(e.reason().contains("undeclared input {hosts}"));
    }

    #[test]
    fn shell_syntax_in_an_argument_is_rejected() {
        let mut toml = one_cap("recon", "DO THING");
        toml = toml.replace(
            "args = [\"-sV\"]",
            "args = [\"-oN\", \"out.txt\", \"&&\", \"echo\", \"done\"]",
        );
        let e = Catalog::from_toml(&toml, Path::new("t.toml")).unwrap_err();
        assert!(e.reason().contains("shell syntax"), "{}", e.reason());
    }

    #[test]
    fn a_placeholder_that_is_a_whole_argument_stays_one_argument() {
        let op = Operation {
            name: "op".into(),
            args: vec!["-iL".into(), "{target}".into()],
            output: OutputFormat::Lines,
            network: true,
        };
        let specs = vec![spec("target", InputType::Target)];
        let mut values = InputValues::new();
        values.insert("target", "a b c");
        let cmd = op.command(Path::new("naabu"), &specs, &values).unwrap();
        assert_eq!(cmd.args(), &["-iL".to_string(), "a b c".to_string()]);
    }

    #[test]
    fn a_sensitive_input_is_redacted_in_the_rendered_command() {
        let op = Operation {
            name: "op".into(),
            args: vec![
                "-u".into(),
                "{username}".into(),
                "-p".into(),
                "{password}".into(),
            ],
            output: OutputFormat::Raw,
            network: true,
        };
        let specs = vec![
            spec("username", InputType::Username),
            spec("password", InputType::Password),
        ];
        let mut values = InputValues::new();
        values.insert("username", "admin");
        values.insert("password", "hunter2");
        let cmd = op.command(Path::new("nxc"), &specs, &values).unwrap();
        assert_eq!(cmd.args()[3], "hunter2");
        assert_eq!(cmd.display_safe(), format!("nxc -u admin -p {REDACTED}"));
        assert!(!serde_json::to_string(&cmd.args_redacted(&[]))
            .unwrap()
            .contains("hunter2"));
    }

    #[test]
    fn a_printf_style_brace_is_a_literal_not_a_placeholder() {
        let op = Operation {
            name: "op".into(),
            args: vec!["-w".into(), "%{http_code}".into(), "{url}".into()],
            output: OutputFormat::Lines,
            network: true,
        };
        let specs = vec![spec("url", InputType::Url)];
        let mut values = InputValues::new();
        values.insert("url", "https://example.com");
        let cmd = op.command(Path::new("curl"), &specs, &values).unwrap();
        assert_eq!(
            cmd.args(),
            &[
                "-w".to_string(),
                "%{http_code}".to_string(),
                "https://example.com".to_string()
            ]
        );
    }

    #[test]
    fn an_embedded_placeholder_is_interpolated() {
        let op = Operation {
            name: "op".into(),
            args: vec!["--rate={rate}".into()],
            output: OutputFormat::Lines,
            network: false,
        };
        let specs = vec![spec("rate", InputType::Integer)];
        let mut values = InputValues::new();
        values.insert("rate", "250");
        let cmd = op.command(Path::new("naabu"), &specs, &values).unwrap();
        assert_eq!(cmd.args(), &["--rate=250".to_string()]);
    }

    #[test]
    fn network_defaults_to_true_in_the_catalog() {
        let cat = Catalog::from_toml(&full_catalog(), Path::new("t.toml")).unwrap();
        let op = &cat.get("recon.x").unwrap().providers[0].operations[0];
        assert!(op.network);
    }

    #[test]
    fn availability_reports_missing_binaries_by_name() {
        let cat = Catalog::from_toml(
            &full_catalog().replace("nmap", "tsec-no-such-tool"),
            Path::new("t.toml"),
        )
        .unwrap();
        let reason = cat.capabilities()[0].unavailable_reason().unwrap();
        assert!(reason.contains("not installed"), "{reason}");
        assert!(cat.availability_summary().starts_with("0/"));
    }

    #[test]
    fn full_catalog_helper_covers_ten_phases() {
        let cat = Catalog::from_toml(&full_catalog(), Path::new("t.toml")).unwrap();
        assert_eq!(cat.capabilities().len(), PHASES.len());
    }
}
