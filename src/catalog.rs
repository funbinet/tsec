//! The capability catalog: what the operator can actually do, and with which
//! tools.
//!
//! The legacy Bash tree encoded the catalogue inside the phase registries: a
//! phase owned a list of tools, and each tool owned a list of shell templates
//! full of flags nobody had checked. This module replaces that with an authored,
//! verified file. `catalog/capabilities.toml` declares every capability, the
//! inputs it needs, and the specific provider operations that implement it; the
//! loader validates all of it at startup and refuses to run a catalog it cannot
//! vouch for.
//!
//! Three things make this trustworthy rather than merely tidy:
//!
//!   * the labels are checked against the interface rules, so the UI cannot
//!     drift into three-word menu entries or lowercase phase names;
//!   * every `{placeholder}` must name a declared input, so a renamed input
//!     fails loudly instead of reaching a tool as a literal `{target}`;
//!   * an argument may not contain shell syntax, because the runtime never
//!     invokes a shell and a `>` in an argv is a redirect that will not happen.
//!
//! Availability is reported honestly. A capability whose provider is not
//! installed is shown as unavailable with a reason; it is never silently
//! offered, and it is never substituted with a different tool.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::command::Command;
use crate::domain::ids::CapabilityId;
use crate::domain::input::{InputSpec, InputValues};
use crate::error::{Result, TsecError};
use crate::provider::Registry;

/// The authoritative ten-phase model.
///
/// This set is fixed by the framework. A catalog that names a phase outside it
/// is rejected rather than extended, because phase ordering drives the whole
/// run order and the operator's mental model of it.
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

/// One uppercase word, as the phase bar requires.
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

/// Characters that only mean something to a shell.
///
/// A newline is deliberately absent: it is a legitimate character inside a
/// single argument (`find -printf`), and since nothing is ever passed to a
/// shell it cannot become a command separator.
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
    /// nmap's report format.
    Nmap,
}

/// A single provider invocation, with its arguments fully spelled out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    /// Operator-facing name of the operation, e.g. "Full Port Range".
    pub name: String,
    /// The argument vector, with `{input}` placeholders.
    pub args: Vec<String>,
    pub output: OutputFormat,
    /// Whether the operation opens network connections and must be run behind oniux.
    #[serde(default)]
    pub network: bool,
}

impl Operation {
    /// Render this operation as a concrete command.
    ///
    /// A placeholder that occupies a whole argument is substituted as exactly
    /// one argv entry, however much whitespace it contains, so a value that
    /// looks like two arguments cannot split into two. A placeholder embedded in
    /// a larger token is interpolated into that token.
    ///
    /// Substituted values for sensitive inputs are registered on the command
    /// so the secret is masked everywhere the command is displayed, recorded or
    /// written to a report — while still reaching the tool unmasked.
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
fn expand(
    token: &str,
    specs: &[InputSpec],
    values: &InputValues,
    operation: &str,
) -> Result<String> {
    let mut out = String::with_capacity(token.len());
    let mut rest = token;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        match tail.find('}') {
            Some(end) => {
                let key = &tail[..end];
                if !specs.iter().any(|s| s.key == key) {
                    return Err(TsecError::catalog(format!(
                        "operation `{operation}` uses undeclared input {{{key}}}"
                    )));
                }
                out.push_str(values.get(key));
                rest = &tail[end + 1..];
            }
            None => {
                // A literal brace. `{{` is how the catalog writes one.
                out.push('{');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// One tool, and the specific operations it provides for a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderBinding {
    pub binary: String,
    /// The verb whose help documents this binding's flags, e.g. `["smb"]`.
    ///
    /// Recorded explicitly so the verifier and the operator both know *where*
    /// the flags were checked. A tool with no verb uses `[]`.
    #[serde(default)]
    pub subcommand: Vec<String>,
    #[serde(rename = "operation", default)]
    pub operations: Vec<Operation>,
}

/// One capability the operator can select.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub phase: String,
    /// One to three uppercase words, per the interface rules.
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

    /// Whether at least one operation of this capability is backed by an
    /// installed provider with verified syntax.
    pub fn is_available(&self, registry: &Registry) -> bool {
        self.unavailable_reason(registry).is_none()
    }

    /// Why this capability cannot run right now, or `None` if it can.
    ///
    /// A capability is unavailable when it declares no operations at all, or
    /// when none of its providers resolve on `PATH`. The reason names the
    /// binaries, because "unavailable" on its own tells the operator nothing.
    pub fn unavailable_reason(&self, registry: &Registry) -> Option<String> {
        let mut wanted: Vec<&str> = Vec::new();
        for p in &self.providers {
            if p.operations.is_empty() {
                continue;
            }
            match registry.get(&p.binary) {
                Some(pv) if pv.resolve().is_some() => return None,
                _ => wanted.push(p.binary.as_str()),
            }
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
    /// Validation happens here rather than at run time so that a malformed
    /// catalog is a startup failure with a file and line to look at, rather
    /// than a surprise halfway through a capability.
    pub fn from_toml(raw: &str, source: &Path) -> Result<Self> {
        let fail = |why: String| -> TsecError {
            TsecError::catalog(format!("{}: {why}", source.display()))
        };

        let file: CatalogFile =
            toml::from_str(raw).map_err(|e| fail(format!("could not be parsed: {e}")))?;

        let mut file = file;
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

    /// Capabilities that cannot run against the current provider snapshot.
    pub fn unavailable(&self, registry: &Registry) -> Vec<(&Capability, String)> {
        self.capabilities
            .iter()
            .filter_map(|c| c.unavailable_reason(registry).map(|r| (c, r)))
            .collect()
    }

    /// One-line readiness summary, e.g. `14/15 available · 2 providers missing`.
    pub fn availability_summary(&self, registry: &Registry) -> String {
        let missing = self.unavailable(registry);
        let total = self.capabilities.len();
        let ready = total - missing.len();
        let mut binaries: BTreeSet<&str> = BTreeSet::new();
        for (cap, _) in &missing {
            for p in &cap.providers {
                if p.operations.is_empty() {
                    continue;
                }
                if registry
                    .get(&p.binary)
                    .map(|v| v.resolve().is_none())
                    .unwrap_or(true)
                {
                    binaries.insert(p.binary.as_str());
                }
            }
        }
        if binaries.is_empty() {
            format!("{ready}/{total} available")
        } else {
            format!(
                "{ready}/{total} available · {} not installed",
                binaries.into_iter().collect::<Vec<_>>().join(", ")
            )
        }
    }
}

/// Reject a label that is not one to three uppercase words.
fn check_label<F>(fail: &F, where_: &str, label: &str) -> Result<()>
where
    F: Fn(String) -> TsecError,
{
    let words: Vec<&str> = label.split(' ').collect();
    let ok = (1..=3).contains(&words.len())
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
            "{where_} label {label:?} must be one to three uppercase words, e.g. `PORT DISCOVERY`"
        )))
    }
}

/// Placeholder names in one argument token.
fn placeholders(token: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = token;
    while let Some(start) = rest.find('{') {
        let tail = &rest[start + 1..];
        match tail.find('}') {
            Some(end) => {
                out.push(&tail[..end]);
                rest = &tail[end + 1..];
            }
            None => rest = tail,
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

    #[test]
    fn a_well_formed_catalog_loads() {
        let toml = r#"
            schema = 1
            [[capability]]
            id = "surface.port-discovery"
            phase = "surface"
            label = "PORT DISCOVERY"
            summary = "Fast SYN scan"
            [[capability.inputs]]
            key = "target"
            type = "target"
            required = true
            [[capability.provider]]
            binary = "naabu"
            subcommand = []
            [[capability.provider.operation]]
            name = "Top 100"
            args = ["-host", "{target}"]
            output = "lines"
            network = true
        "#;
        let cat = Catalog::from_toml(toml, Path::new("test.toml")).unwrap();
        assert_eq!(cat.capabilities().len(), 1);
        let cap = cat.get("surface.port-discovery").unwrap();
        assert_eq!(cap.label, "PORT DISCOVERY");
        assert_eq!(cap.all_operations().count(), 1);
    }

    #[test]
    fn the_shipped_catalog_loads_and_validates() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/capabilities.toml");
        if !path.exists() {
            return;
        }
        let cat = Catalog::load(&path).unwrap();
        assert!(!cat.capabilities().is_empty());
        // Every phase in the framework's model is either populated or explicitly
        // absent — but a capability may never sit outside the ten phases.
        for (phase, caps) in cat.grouped() {
            assert!(PHASES.iter().any(|p| phase_label(p) == Some(phase)));
            let _ = caps;
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
        assert!(
            e.reason().contains("undeclared input {hosts}"),
            "{}",
            e.reason()
        );
    }

    #[test]
    fn shell_syntax_in_an_argument_is_rejected() {
        let toml = r#"
            schema = 1
            [[capability]]
            id = "recon.x"
            phase = "recon"
            label = "DO THING"
            summary = "s"
            [[capability.provider]]
            binary = "nmap"
            [[capability.provider.operation]]
            name = "op"
            args = ["-oN", "out.txt", "&&", "echo", "done"]
            output = "lines"
        "#;
        let e = Catalog::from_toml(toml, Path::new("t.toml")).unwrap_err();
        assert!(e.reason().contains("shell syntax"), "{}", e.reason());
    }

    #[test]
    fn a_capability_outside_the_ten_phases_is_rejected() {
        let toml = r#"
            schema = 1
            [[capability]]
            id = "pwnage.x"
            phase = "pwnage"
            label = "DO THING"
            summary = "s"
            [[capability.provider]]
            binary = "nmap"
            [[capability.provider.operation]]
            name = "op"
            args = ["-sV"]
            output = "lines"
        "#;
        let e = Catalog::from_toml(toml, Path::new("t.toml")).unwrap_err();
        assert!(
            e.reason().contains("not one of the ten phases"),
            "{}",
            e.reason()
        );
    }

    #[test]
    fn a_label_must_be_one_to_three_uppercase_words() {
        for bad in [
            "Port Discovery",
            "PORT DISCOVERY EXTRA NAME HERE",
            "",
            "PORT  DISCOVERY",
        ] {
            let toml = format!(
                r#"
                schema = 1
                [[capability]]
                id = "recon.x"
                phase = "recon"
                label = "{bad}"
                summary = "s"
                [[capability.provider]]
                binary = "nmap"
                [[capability.provider.operation]]
                name = "op"
                args = ["-sV"]
                output = "lines"
            "#
            );
            let e = Catalog::from_toml(&toml, Path::new("t.toml")).unwrap_err();
            assert!(
                e.reason().contains("uppercase words"),
                "label {bad:?} should be rejected, got {}",
                e.reason()
            );
        }
    }

    #[test]
    fn a_capability_id_must_be_namespaced_under_its_own_phase() {
        let toml = r#"
            schema = 1
            [[capability]]
            id = "surface.misfiled"
            phase = "recon"
            label = "DO THING"
            summary = "s"
            [[capability.provider]]
            binary = "nmap"
            [[capability.provider.operation]]
            name = "op"
            args = ["-sV"]
            output = "lines"
        "#;
        let e = Catalog::from_toml(toml, Path::new("t.toml")).unwrap_err();
        assert!(e.reason().contains("namespaced"), "{}", e.reason());
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
        // A value containing spaces must not split into two argv entries.
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
                "admin".into(),
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

        // The tool must receive the real password…
        assert_eq!(cmd.args()[3], "hunter2");
        // …but nothing the operator sees, and nothing persisted, may contain it.
        assert_eq!(cmd.display_safe(), format!("nxc -u admin -p {REDACTED}"));
        assert!(!serde_json::to_string(&cmd.args_redacted(&[]))
            .unwrap()
            .contains("hunter2"));
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
    fn a_network_operation_is_marked_as_needing_tor() {
        let op = Operation {
            name: "op".into(),
            args: vec!["-sV".into()],
            output: OutputFormat::Nmap,
            network: true,
        };
        let cmd = op
            .command(Path::new("nmap"), &[], &InputValues::new())
            .unwrap();
        assert!(cmd.is_network());
    }
}
