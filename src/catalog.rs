//! The capability catalog.
//!
//! `catalog/capabilities.toml` is the single source of truth for what the
//! operator can do: ten phases, and inside them the capabilities an operator
//! chooses, the inputs each one needs, and the exact provider operations that
//! implement it. The loader validates all of it at startup and refuses to run
//! a catalog it cannot vouch for.
//!
//! Rules enforced here, not elsewhere:
//!   * a phase label is one uppercase word and a capability label one to three;
//!   * every `{placeholder}` names a declared input, so a renamed input fails
//!     loudly instead of reaching a tool as a literal `{target}`;
//!   * every `{wl:...}` reference names a bundled wordlist, so no capability
//!     depends on a path that only exists on the machine it was authored on;
//!   * an argument carrying shell syntax is reported, because a shell operator
//!     pasted into an argument vector is nearly always an authoring mistake,
//!     even though the runtime would pass the bytes through harmlessly.

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
    "exploitation",
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
        "exploitation" => "EXPLOITATION",
        "wireless" => "WIRELESS",
        _ => return None,
    })
}

/// Tokens that are shell syntax and nothing else.
///
/// One of these as a whole argv entry is always an authoring mistake: no tool
/// takes `|` or `2>/dev/null` as a filename or a flag. A shell metacharacter
/// *inside* a larger token is different — a URL query string, an LDAP filter, an
/// XML payload or a SQL statement all carry them legitimately — so the whole-token
/// case is reported and the embedded case is left alone. Reporting both together
/// buried the first in 139 lines of legitimate payload syntax.
const SHELL_OPERATOR_TOKENS: &[&str] = &[
    "|",
    "||",
    "&",
    "&&",
    ";",
    ";;",
    ">",
    ">>",
    "<",
    "<<",
    "2>",
    "2>>",
    "2>&1",
    "2>/dev/null",
    "&>",
    "|&",
];

/// Prefix marking a bundled-wordlist reference inside an argument.
///
/// `{wl:ssh/passwords.txt}` resolves to the absolute path of that list inside
/// the installed `wordlists/` directory. The colon and slash are deliberately
/// outside the identifier grammar, so a wordlist reference can never collide
/// with a capability input placeholder.
const WORDLIST_PREFIX: &str = "wl:";

/// Placeholder naming the wordlist directory itself, for the capabilities whose
/// job is to report on the corpus rather than to consume one entry.
const WORDLIST_ROOT_PLACEHOLDER: &str = "{wlroot}";

/// The same, without the braces, so the substitution and validation passes can
/// talk about the key rather than the token.
const WORDLIST_ROOT_KEY: &str = "wlroot";

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

/// Root of the bundled wordlist tree.
///
/// `catalog_path` is the catalog **file**, e.g. `<root>/catalog/capabilities.toml`.
///
/// Resolution order, and why each step exists:
///
/// 1. `TSEC_WORDLIST_ROOT`, so an operator can point at one shared corpus
///    instead of keeping a copy per install.
/// 2. `<root>/wordlists`, where `<root>` is the directory holding `catalog/`.
///
/// The second step requires the catalog to sit in a directory actually named
/// `catalog`. Climbing two levels from an arbitrary path would resolve against
/// whatever happens to be two directories up, which is a path the caller did
/// not choose and this process does not own. When the name does not match, the
/// catalog's own directory's parent is used instead — which is wrong in the
/// same loud, harmless way for every caller that gets the contract right.
pub fn wordlist_root(catalog_path: &Path) -> PathBuf {
    if let Ok(custom) = std::env::var("TSEC_WORDLIST_ROOT") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let dir = catalog_path.parent();
    let install_root = dir
        .filter(|d| d.file_name().is_some_and(|n| n == "catalog"))
        .and_then(Path::parent)
        .or_else(|| dir.and_then(Path::parent));
    install_root
        .map(|root| root.join("wordlists"))
        .unwrap_or_else(|| PathBuf::from("wordlists"))
}

/// Expand one `{wl:...}` reference to the absolute path of a bundled list.
///
/// A reference that escapes the wordlist tree (`../etc/passwd`) or names a list
/// that is not present is an error naming the list, because silently continuing
/// would hand a tool a path it does not understand.
pub fn resolve_wordlist(catalog_path: &Path, rel: &str) -> Result<PathBuf> {
    let root = wordlist_root(catalog_path);

    // Reject traversal lexically, before touching the filesystem. `Path::join`
    // keeps `..` segments verbatim, so comparing the joined path would let
    // `../../../etc/passwd` through; the reference has to be normalised first.
    let mut depth: i32 = 0;
    for segment in rel.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return Err(TsecError::catalog(format!(
                        "wordlist reference `{rel}` escapes the wordlist directory"
                    )));
                }
            }
            _ => depth += 1,
        }
    }

    let joined = root.join(rel);
    if !joined.is_file() {
        return Err(TsecError::catalog(format!(
            "wordlist `{rel}` is not present under {}; run wordlists/fetch-wordlists.sh \
             or set TSEC_WORDLIST_ROOT to a directory that has it",
            root.display()
        )));
    }
    Ok(joined)
}

/// `{wl:...}` references in one argument token.
fn wordlist_refs(token: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = token.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if bytes.get(i + 1) == Some(&b'{') => {
                i = token[i + 2..]
                    .find('}')
                    .map(|o| i + 2 + o + 1)
                    .unwrap_or(bytes.len());
            }
            b'{' if bytes.get(i + 1) == Some(&b'{') => i += 2,
            b'}' if bytes.get(i + 1) == Some(&b'}') => i += 2,
            b'{' => match token[i + 1..].find('}') {
                Some(offset) => {
                    let inner = &token[i + 1..i + 1 + offset];
                    if let Some(rel) = inner.strip_prefix(WORDLIST_PREFIX) {
                        out.push(rel);
                    }
                    i = i + 1 + offset + 1;
                }
                None => i += 1,
            },
            b'}' => i += 1,
            _ => {
                i += token[i..].chars().next().map(char::len_utf8).unwrap_or(1);
            }
        }
    }
    out
}

/// Substitute every `{wl:...}` reference, and `{wlroot}`, in one argument.
///
/// A reference occupying the whole argument becomes exactly one argv entry; one
/// embedded in a larger token is interpolated into it, so
/// `-l{dl:web/common.txt}` and `-l`, `{wl:web/common.txt}` both do the obvious
/// thing.
fn expand_wordlists(token: &str, catalog_path: &Path, operation: &str) -> Result<String> {
    let refs = wordlist_refs(token);
    if refs.is_empty() && !token.contains(WORDLIST_ROOT_PLACEHOLDER) {
        return Ok(token.to_string());
    }

    let root = wordlist_root(catalog_path);

    // Walk the token once, copying text and replacing references, so an
    // embedded reference does not force the whole token through `expand`.
    let mut out = String::with_capacity(token.len());
    let bytes = token.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if bytes.get(i + 1) == Some(&b'{') => {
                let close = token[i + 2..]
                    .find('}')
                    .map(|o| i + 2 + o + 1)
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
                    let close = i + 1 + offset;
                    let inner = &token[i + 1..close];
                    if inner == WORDLIST_ROOT_KEY {
                        out.push_str(&root.display().to_string());
                    } else {
                        match inner.strip_prefix(WORDLIST_PREFIX) {
                            Some(rel) => {
                                let path = resolve_wordlist(catalog_path, rel).map_err(|e| {
                                    TsecError::catalog(format!(
                                        "operation `{operation}`: {}",
                                        e.reason()
                                    ))
                                })?;
                                out.push_str(&path.display().to_string());
                            }
                            None => {
                                out.push('{');
                                i += 1;
                                continue;
                            }
                        }
                    }
                    i = close + 1;
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

impl Operation {
    /// Render this operation as a concrete command.
    ///
    /// A placeholder occupying a whole argument is substituted as exactly one
    /// argv entry, however much whitespace the value contains; a placeholder
    /// embedded in a larger token is interpolated into that token. A
    /// `{wl:...}` reference is resolved to a bundled wordlist path, so the
    /// operator is never asked for one. Values for sensitive inputs are
    /// registered on the command so the secret is masked everywhere the command
    /// is displayed, recorded or written to a report.
    pub fn command(
        &self,
        program: &Path,
        specs: &[InputSpec],
        values: &InputValues,
        catalog_path: &Path,
    ) -> Result<Command> {
        let mut args: Vec<String> = Vec::with_capacity(self.args.len());
        let mut sensitive: Vec<usize> = Vec::new();

        for token in &self.args {
            let whole = token
                .strip_prefix('{')
                .and_then(|t| t.strip_suffix('}'))
                .filter(|k| !k.is_empty() && !k.contains('{') && !k.contains('}'));

            if let Some(key) = whole {
                if let Some(rel) = key.strip_prefix(WORDLIST_PREFIX) {
                    args.push(
                        resolve_wordlist(catalog_path, rel)
                            .map_err(|e| {
                                TsecError::catalog(format!(
                                    "operation `{}`: {}",
                                    self.name,
                                    e.reason()
                                ))
                            })?
                            .display()
                            .to_string(),
                    );
                    continue;
                }
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
                let token = expand_wordlists(token, catalog_path, &self.name)?;
                args.push(expand(&token, specs, values, &self.name)?);
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
    ///
    /// A capability whose only providers need a wordlist that is not on disk is
    /// also unavailable, and says so: an operator who picks it should learn
    /// which list to fetch, not watch a tool exit having read nothing. The
    /// bundled lists mean this only happens after a partial install or a
    /// deliberately relocated corpus.
    pub fn unavailable_reason(&self) -> Option<String> {
        let mut wanted: Vec<&str> = Vec::new();
        let mut missing_lists: Vec<&str> = Vec::new();
        let mut any_provider_ready = false;

        for p in &self.providers {
            if p.operations.is_empty() {
                continue;
            }
            for op in &p.operations {
                for token in &op.args {
                    for rel in wordlist_refs(token) {
                        if !missing_lists.contains(&rel) {
                            missing_lists.push(rel);
                        }
                    }
                }
            }
            if find_in_path(&p.binary).is_some() {
                // The binary is here. If it also needs lists that are not, the
                // capability still cannot do its job, so keep looking rather
                // than returning early.
                any_provider_ready = true;
                continue;
            }
            wanted.push(p.binary.as_str());
        }

        // Nothing declared: a capability with no provider operations at all.
        if !any_provider_ready && wanted.is_empty() {
            return Some(format!("`{}` declares no provider operations", self.id));
        }

        let mut reasons: Vec<String> = Vec::new();
        if !any_provider_ready && !wanted.is_empty() {
            let mut names = wanted.clone();
            names.sort_unstable();
            names.dedup();
            reasons.push(format!("{} not installed", names.join(", ")));
        }
        if !missing_lists.is_empty() {
            let names: BTreeSet<&str> = missing_lists.into_iter().collect();
            reasons.push(format!(
                "wordlist {} missing; run wordlists/fetch-wordlists.sh",
                names
                    .iter()
                    .map(|n| format!("`{n}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        }
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
    advisories: Vec<String>,
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
    ///
    /// Structural problems — an unknown phase, a duplicate id, an undeclared
    /// placeholder, a wordlist reference that names nothing — are errors.
    /// Judgement calls about an argument's *content* are not: shell syntax is
    /// collected into [`Catalog::advisories`] and reported by `tsec --status`,
    /// because a tool handed a stray `|` runs, returns nothing, and reads as a
    /// negative result rather than as the authoring mistake it is.
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
        let mut advisories: Vec<String> = Vec::new();
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
                    // An empty argument vector is legitimate: `id`, `env`,
                    // `printenv` and `klist` are run for what they print, and
                    // inventing a flag to satisfy a rule would change what runs.
                    for token in &op.args {
                        if SHELL_OPERATOR_TOKENS.contains(&token.as_str()) {
                            advisories.push(format!(
                                "{where_} operation `{}` passes {token:?} as an argument; no tool \
                                 takes a shell operator, so this is an unsplit command line and \
                                 the tool will run as if it were not there",
                                op.name
                            ));
                        }
                        for key in placeholders(token) {
                            if !keys.contains(key) {
                                return Err(fail(format!(
                                    "{where_} operation `{}` uses undeclared input {{{key}}}",
                                    op.name
                                )));
                            }
                        }
                        for rel in wordlist_refs(token) {
                            if rel.is_empty() {
                                return Err(fail(format!(
                                    "{where_} operation `{}` has an empty wordlist reference",
                                    op.name
                                )));
                            }
                            // Resolved now so a typo fails at startup rather
                            // than mid-capability, but absence is a warning:
                            // the operator can fetch the list and carry on,
                            // and the capability is reported as unavailable.
                            if let Err(e) = resolve_wordlist(source, rel) {
                                advisories.push(format!(
                                    "{where_} operation `{}`: {}",
                                    op.name,
                                    e.reason()
                                ));
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
            advisories,
        })
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Load-time observations that are worth reporting but not worth refusing
    /// to start over.
    ///
    /// Two kinds end up here: an argument carrying shell syntax, which reaches
    /// the tool verbatim and is usually a pasted pipeline that was never split;
    /// and a `{wl:...}` reference naming a list that is not on disk yet, which
    /// the operator can fix by running `wordlists/fetch-wordlists.sh`.
    pub fn advisories(&self) -> &[String] {
        &self.advisories
    }

    /// Wordlist references the catalog needs that are not on disk.
    ///
    /// Kept apart from the general advisories because it answers a specific
    /// question: which capabilities will report themselves unavailable, and
    /// which single command fixes it.
    pub fn missing_wordlists(&self) -> Vec<&str> {
        self.advisories
            .iter()
            .filter_map(|a| {
                a.find("wordlist `")
                    .and_then(|i| a[i + 10..].split('`').next())
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
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

    /// One-line readiness summary, e.g. `186/218 available`.
    pub fn availability_summary(&self) -> String {
        let total = self.capabilities.len();
        let ready = total - self.unavailable().len();
        format!("{ready}/{total} available")
    }
}

/// Reject a label that is not one to three uppercase words.
///
/// One word is allowed because some capabilities name a single thing
/// (`KERBEROAST`). Three is allowed because several genuinely need it
/// (`SSH KEY HARVEST`) and shortening them to satisfy a style rule loses
/// meaning the operator relies on. The rule exists so a label reads as a
/// heading in a fixed-width menu, not to enforce a vocabulary.
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
            "{where_} label {label:?} must be one to three uppercase words, e.g. \
             `PORT DISCOVERY` or `SSH KEY HARVEST`"
        )))
    }
}

/// Whether a `{...}` body names a capability input rather than something else.
///
/// Braces are common in the payloads the catalog carries: regex quantifiers
/// (`{10,}`), JSON bodies (`{"role":"admin"}`), template expressions
/// (`${{7*7}}`). Matching any of those as a placeholder would demand the
/// capability declare an input called `10,` or `"role":"admin"`. An input key
/// is an identifier — letters, digits, underscore, hyphen — so requiring that
/// shape keeps genuine references and discards payload syntax.
fn is_input_key(body: &str) -> bool {
    !body.is_empty()
        && body.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Placeholder names in one argument token.
///
/// Matches the substitution rule exactly: `{{`/`}}` are literal braces and
/// `%{…}` is printf-style literal text, so neither hides nor invents a
/// placeholder. Wordlist references are not input placeholders and are not
/// returned here; they are reported separately by [`wordlist_refs`].
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
                    let body = &token[i + 1..i + 1 + offset];
                    // `{wlroot}` is a framework placeholder for the wordlist
                    // directory, not something an operator supplies.
                    if is_input_key(body) && body != WORDLIST_ROOT_KEY {
                        out.push(body);
                    }
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

    /// A complete catalog with one operation's argv replaced, so a test can
    /// assert on a specific rejection without tripping the phase rule first.
    fn full_catalog_with_args(args: &str) -> String {
        full_catalog().replace("args = [\"-sV\"]", args)
    }

    /// Rewrite every capability label in the sample catalog.
    fn relabel(label: &str) -> String {
        format!("label = \"{label}\"")
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
        let cmd = op
            .command(Path::new("sh"), &cap.inputs, &values, Path::new("t.toml"))
            .unwrap();
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
    fn every_catalog_binary_has_a_package_mapping_in_tools_sh() {
        // `tools.sh` reads its tool list from this catalog but keeps its own
        // tool-to-package table. If the catalog gains a binary the table does not
        // know, the script silently falls back to a same-name guess — which is
        // right often enough to hide being wrong. This pins the two together.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let catalog = root.join("catalog/capabilities.toml");
        let tools = root.join("tools.sh");
        if !catalog.exists() || !tools.exists() {
            return;
        }
        let cat = Catalog::load(&catalog).unwrap();
        let script = std::fs::read_to_string(&tools).unwrap();

        let body = script
            .split("pkg_info() {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("tools.sh should define pkg_info");

        let mut mapped: Vec<String> = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            let Some((pattern, _)) = line.split_once(") echo ") else {
                continue;
            };
            mapped.extend(pattern.split('|').map(|s| s.trim().to_string()));
        }

        let mut unmapped: Vec<&str> = Vec::new();
        for cap in cat.capabilities() {
            for p in &cap.providers {
                if !mapped.contains(&p.binary) && !unmapped.contains(&p.binary.as_str()) {
                    unmapped.push(&p.binary);
                }
            }
        }
        unmapped.sort_unstable();
        assert!(
            unmapped.is_empty(),
            "tools.sh has no package mapping for {} catalog binaries: {unmapped:?}",
            unmapped.len()
        );
    }

    #[test]
    fn every_tools_sh_mapping_is_well_formed() {
        // The mapping is `arch|debian`, and both halves are needed: a missing
        // half produces a command that installs nothing and looks plausible.
        let tools = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools.sh");
        if !tools.exists() {
            return;
        }
        let script = std::fs::read_to_string(&tools).unwrap();
        let body = script
            .split("pkg_info() {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("tools.sh should define pkg_info");

        for line in body.lines() {
            let line = line.trim();
            let Some((pattern, rest)) = line.split_once(") echo ") else {
                continue;
            };
            // The `*)` arm is the deliberate same-name fallback, not a mapping.
            if pattern == "*" {
                continue;
            }
            let value = rest.trim().trim_end_matches(";;").trim();
            let value = value.trim_matches('"');
            let parts: Vec<&str> = value.split('|').collect();
            assert_eq!(
                parts.len(),
                2,
                "mapping for `{pattern}` is not `arch|debian`: {value:?}"
            );
            for part in parts {
                assert!(!part.trim().is_empty(), "`{pattern}` has an empty package");
                assert!(
                    !part.contains(['`', '$', ';', '&', '<', '>', '(', ')']),
                    "`{pattern}` package `{part}` carries shell syntax"
                );
            }
        }
    }

    #[test]
    fn the_shipped_catalog_loads_and_covers_all_ten_phases() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/capabilities.toml");
        if !path.exists() {
            return;
        }
        let cat = Catalog::load(&path).unwrap();
        // Phase membership is the invariant worth pinning. Counts are not: the
        // catalog grows, and a hardcoded total turns every capability addition
        // into a failing test that says nothing about correctness.
        for (label, caps) in cat.grouped() {
            assert!(!caps.is_empty(), "phase {label} must hold capabilities");
            for c in caps {
                assert!(
                    (1..=3).contains(&c.label.split(' ').count()),
                    "{} is not a one to three word label",
                    c.label
                );
                assert!(c.id.starts_with(&format!("{}.", c.phase)));
            }
        }
        assert_eq!(cat.grouped().len(), PHASES.len());
        assert_eq!(
            cat.capabilities().len(),
            cat.grouped().iter().map(|(_, c)| c.len()).sum::<usize>()
        );
    }

    #[test]
    fn the_shipped_catalog_names_no_missing_wordlist() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/capabilities.toml");
        if !path.exists() {
            return;
        }
        let cat = Catalog::load(&path).unwrap();
        let missing = cat.missing_wordlists();
        assert!(
            missing.is_empty(),
            "these wordlists are referenced but not on disk: {missing:?}"
        );
    }

    #[test]
    fn every_shipped_wordlist_resolves_and_is_non_empty() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("wordlists");
        if !root.is_dir() {
            return;
        }
        let catalog = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/capabilities.toml");
        let cat = Catalog::load(&catalog).unwrap();
        let mut checked = 0usize;
        for cap in cat.capabilities() {
            for (_, op) in cap.all_operations() {
                for token in &op.args {
                    for rel in wordlist_refs(token) {
                        let path = resolve_wordlist(&catalog, rel)
                            .unwrap_or_else(|e| panic!("{rel}: {}", e.reason()));
                        assert!(
                            std::fs::metadata(&path).unwrap().len() > 0,
                            "{rel} is empty"
                        );
                        assert!(path.starts_with(&root), "{rel} resolved outside {root:?}");
                        checked += 1;
                    }
                }
            }
        }
        assert!(
            checked > 0,
            "the catalog should reference bundled wordlists"
        );
    }

    #[test]
    fn a_real_capability_renders_a_real_bundled_path_into_its_command() {
        // The reference test above proves every `{wl:...}` resolves. This proves
        // the resolved path actually reaches the argument vector of a shipped
        // capability, so a wordlist-dependent attack is runnable with nothing
        // but the framework and a target.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let catalog = root.join("catalog/capabilities.toml");
        if !catalog.exists() {
            return;
        }
        let cat = Catalog::load(&catalog).unwrap();

        // `recon.subdomain-discovery` resolves its permutation and brute-force
        // corpora through `{wl:...}` and needs nothing but a domain.
        let cap = cat
            .get("recon.subdomain-discovery")
            .expect("shipped capability");
        let mut values = InputValues::new();
        values.insert("domain", "example.com");

        let mut saw_path = false;
        for (binary, op) in cap.all_operations() {
            let cmd = op
                .command(Path::new(binary), &cap.inputs, &values, &catalog)
                .unwrap_or_else(|e| panic!("{binary}/{}: {}", op.name, e.reason()));
            for arg in cmd.args() {
                if arg.starts_with("/") && arg.contains("/wordlists/") {
                    assert!(
                        std::path::Path::new(arg).is_file(),
                        "{binary}/{} rendered {arg}, which is not a file",
                        op.name
                    );
                    saw_path = true;
                }
            }
        }
        assert!(saw_path, "no operation rendered a bundled wordlist path");
    }

    #[test]
    fn a_label_must_be_one_to_three_uppercase_words() {
        for bad in [
            "PORT DISCOVERY RUNS TODAY",
            "PORT DISCOVERY AND THEN SOME",
            "port discovery",
            "PORT  DISCOVERY",
            "",
        ] {
            let toml = full_catalog().replace(r#"label = "DO THING""#, &relabel(bad));
            let e = Catalog::from_toml(&toml, Path::new("t.toml")).unwrap_err();
            assert!(
                e.reason().contains("one to three uppercase words"),
                "label {bad:?} should be rejected, got {}",
                e.reason()
            );
        }
        // One and three words are both accepted, so the rule stays a style
        // check rather than a vocabulary.
        for good in ["KERBEROAST", "PORT DISCOVERY", "SSH KEY HARVEST"] {
            let toml = full_catalog().replace(r#"label = "DO THING""#, &relabel(good));
            Catalog::from_toml(&toml, Path::new("t.toml")).unwrap();
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
    fn payload_braces_are_not_mistaken_for_input_placeholders() {
        // Regex quantifiers, JSON bodies and template expressions all carry
        // braces. None of them may be read as a demand for an input named
        // `10,` or `"role":"admin"`.
        for token in [
            "eyJ[A-Za-z0-9_-]{10,}",
            "{\"role\":\"admin\"}",
            "name=${7*7}",
            "(api_key|secret).{0,20}",
            "{}",
        ] {
            assert!(
                placeholders(token).is_empty(),
                "{token:?} should yield no placeholders, got {:?}",
                placeholders(token)
            );
        }
        // The identifiers a capability really does declare are still found.
        assert_eq!(placeholders("--rate={rate}"), vec!["rate"]);
        assert_eq!(placeholders("{target}"), vec!["target"]);
        assert_eq!(placeholders("{sudo-password}"), vec!["sudo-password"]);
    }

    #[test]
    fn shell_syntax_in_an_argument_is_reported_but_not_fatal() {
        let toml =
            full_catalog_with_args("args = [\"-oN\", \"out.txt\", \"&&\", \"echo\", \"done\"]");
        let cat = Catalog::from_toml(&toml, Path::new("t.toml"))
            .expect("a shell operator in an argument must not stop the catalog loading");
        assert!(
            cat.advisories()
                .iter()
                .any(|a| a.contains("\"&&\"") && a.contains("unsplit command line")),
            "expected an advisory naming the offending argument, got {:?}",
            cat.advisories()
        );
    }

    #[test]
    fn shell_syntax_inside_a_payload_is_left_alone() {
        // A URL query string, an LDAP filter, an XML entity and a SQL statement
        // all legitimately carry shell metacharacters. Flagging those would
        // bury the real findings under noise nobody can act on.
        for payload in [
            "https://crt.sh/?q=example.com&output=json",
            "(objectClass=*)",
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
            "select user,authentication_string from mysql.user;",
            "name=${7*7}",
        ] {
            // TOML literal strings, so a payload containing a double quote does
            // not need escaping and the test exercises the bytes verbatim.
            let args = format!("args = ['-d', '{payload}']");
            let toml = full_catalog_with_args(&args);
            let cat = Catalog::from_toml(&toml, Path::new("t.toml")).unwrap();
            assert!(
                cat.advisories().is_empty(),
                "{payload:?} should not be reported, got {:?}",
                cat.advisories()
            );
        }
    }

    #[test]
    fn an_operation_may_take_no_arguments() {
        // `id`, `env` and `printenv` are run for what they print. Rejecting an
        // empty argv would mean inventing a flag, which changes what runs.
        let toml = r#"
            schema = 1
            [[capability]]
            id = "recon.x"
            phase = "recon"
            label = "DO THING"
            summary = "s"
            [[capability.provider]]
            binary = "id"
            [[capability.provider.operation]]
            name = "Current Identity"
            args = []
            output = "lines"
        "#;
        let mut s = toml.to_string();
        for phase in PHASES.iter().filter(|p| **p != "recon") {
            s.push_str(&cap_toml(phase, "DO THING"));
        }
        let cat = Catalog::from_toml(&s, Path::new("t.toml")).unwrap();
        let op = &cat.get("recon.x").unwrap().providers[0].operations[0];
        assert!(op.args.is_empty());
    }

    #[test]
    fn a_wordlist_reference_resolves_against_the_bundled_tree() {
        let dir = std::env::temp_dir().join("tsec-wl-test");
        let catalog = dir.join("catalog/capabilities.toml");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        std::fs::create_dir_all(dir.join("wordlists/ssh")).unwrap();
        std::fs::write(dir.join("wordlists/ssh/passwords.txt"), b"root\nadmin\n").unwrap();

        let resolved = resolve_wordlist(&catalog, "ssh/passwords.txt").unwrap();
        assert_eq!(resolved, dir.join("wordlists/ssh/passwords.txt"));
        assert!(resolved.is_file());

        let op = Operation {
            name: "SSH Brute".into(),
            args: vec![
                "-t".into(),
                "ssh".into(),
                "-L".into(),
                "{rhost}".into(),
                "-P".into(),
                "{wl:ssh/passwords.txt}".into(),
            ],
            output: OutputFormat::Lines,
            network: true,
        };
        let specs = vec![spec("rhost", InputType::Target)];
        let mut values = InputValues::new();
        values.insert("rhost", "10.0.0.5");
        let cmd = op
            .command(Path::new("hydra"), &specs, &values, &catalog)
            .unwrap();
        assert_eq!(
            cmd.args()[5],
            dir.join("wordlists/ssh/passwords.txt")
                .display()
                .to_string()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_embedded_wordlist_reference_is_interpolated() {
        let dir = std::env::temp_dir().join("tsec-wl-embed");
        let catalog = dir.join("catalog/capabilities.toml");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        std::fs::create_dir_all(dir.join("wordlists/web")).unwrap();
        std::fs::write(dir.join("wordlists/web/common.txt"), b"/admin\n").unwrap();

        let op = Operation {
            name: "op".into(),
            args: vec!["-l{wl:web/common.txt}".into()],
            output: OutputFormat::Lines,
            network: true,
        };
        let cmd = op
            .command(Path::new("ffuf"), &[], &InputValues::new(), &catalog)
            .unwrap();
        assert_eq!(
            cmd.args()[0],
            format!("-l{}", dir.join("wordlists/web/common.txt").display())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wordlist_reference_outside_the_tree_is_refused() {
        let catalog = Path::new("/tmp/tsec-wl-guard/catalog/capabilities.toml");
        let e = resolve_wordlist(catalog, "../../etc/passwd").unwrap_err();
        assert!(
            e.reason().contains("escapes the wordlist directory"),
            "{}",
            e.reason()
        );
    }

    #[test]
    fn the_wordlist_root_is_derived_from_the_catalog_file() {
        // The catalogue file is `<root>/catalog/capabilities.toml`, so the corpus
        // is a sibling of `catalog/`, not two levels above whatever path the
        // caller happened to pass.
        assert_eq!(
            wordlist_root(Path::new("/opt/tsec/catalog/capabilities.toml")),
            PathBuf::from("/opt/tsec/wordlists")
        );
        // A path that is not inside a `catalog/` directory must not be climbed
        // two levels from; that would resolve against a directory the caller
        // never chose.
        assert_eq!(
            wordlist_root(Path::new("/tmp/whatever/else.toml")),
            PathBuf::from("/tmp/wordlists")
        );
        assert_eq!(
            wordlist_root(Path::new("capabilities.toml")),
            PathBuf::from("wordlists")
        );
    }

    #[test]
    fn a_missing_wordlist_names_itself() {
        let dir = std::env::temp_dir().join("tsec-wl-absent");
        let catalog = dir.join("catalog/capabilities.toml");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        let e = resolve_wordlist(&catalog, "passwords/rockyou.txt").unwrap_err();
        assert!(
            e.reason().contains("passwords/rockyou.txt")
                && e.reason().contains("fetch-wordlists.sh"),
            "{}",
            e.reason()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_capability_with_its_binary_present_is_available() {
        // Regression guard: an earlier rewrite of the availability rule kept
        // collecting reasons after finding a usable binary, and reported every
        // capability unavailable even when its tool was installed.
        let shell = find_in_path("sh").expect("a POSIX shell is always present");

        let toml = full_catalog().replace(
            "binary = \"nmap\"",
            &format!("binary = \"{}\"", shell.display()),
        );
        let cat = Catalog::from_toml(&toml, Path::new("t.toml")).unwrap();
        for cap in cat.capabilities() {
            assert!(
                cap.is_available(),
                "{} should be available: {:?}",
                cap.id,
                cap.unavailable_reason()
            );
        }
        assert!(cat
            .availability_summary()
            .starts_with(&format!("{}/", PHASES.len())));

        // A binary that does not exist is reported by name.
        let toml = full_catalog().replace("nmap", "tsec-definitely-not-installed");
        let cat = Catalog::from_toml(&toml, Path::new("t.toml")).unwrap();
        let reason = cat.capabilities()[0].unavailable_reason().unwrap();
        assert!(reason.contains("tsec-definitely-not-installed"), "{reason}");
        assert!(cat.availability_summary().starts_with("0/"));
    }

    #[test]
    fn a_capability_needing_an_absent_wordlist_reports_it_as_unavailable() {
        // Point the catalog somewhere with no wordlists at all.
        let toml = full_catalog_with_args(
            "args = [\"-w\", \"{wl:passwords/definitely-absent.txt}\", \"{target}\"]",
        );
        let cat =
            Catalog::from_toml(&toml, Path::new("/tmp/tsec-wl-none/catalog/cap.toml")).unwrap();
        let reason = cat.get("recon.x").unwrap().unavailable_reason().unwrap();
        assert!(
            reason.contains("passwords/definitely-absent.txt"),
            "{reason}"
        );
        assert!(reason.contains("fetch-wordlists.sh"), "{reason}");
        assert_eq!(
            cat.missing_wordlists(),
            vec!["passwords/definitely-absent.txt"],
            "the gap should be reported once, by name"
        );
    }

    #[test]
    fn a_wordlist_reference_is_not_also_an_input_placeholder() {
        assert!(wordlist_refs("{wl:ssh/passwords.txt}") == ["ssh/passwords.txt"]);
        assert!(wordlist_refs("-l{wl:web/common.txt}") == ["web/common.txt"]);
        assert!(wordlist_refs("%{wl:nope}").is_empty());
        assert!(placeholders("{wl:ssh/passwords.txt}").is_empty());
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
        let cmd = op
            .command(Path::new("naabu"), &specs, &values, Path::new("t.toml"))
            .unwrap();
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
        let cmd = op
            .command(Path::new("nxc"), &specs, &values, Path::new("t.toml"))
            .unwrap();
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
        let cmd = op
            .command(Path::new("curl"), &specs, &values, Path::new("t.toml"))
            .unwrap();
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
        let cmd = op
            .command(Path::new("naabu"), &specs, &values, Path::new("t.toml"))
            .unwrap();
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
