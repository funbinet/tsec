//! Provider and operation resolution.
//!
//! A *provider* is a concrete external integration. It is only ever offered to
//! the operator when the framework can prove it works: the executable resolves
//! on `PATH`, and every flag in every operation's template is documented by that
//! executable's own help output. Anything else is reported honestly as
//! unavailable with a reason, never as ready to run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ExecutionErrorKind, Result, Stage, TsecError};

/// The verification record produced by `scripts/verify_providers.py`.
#[derive(Debug, Clone, Deserialize)]
pub struct VerificationDoc {
    pub schema: u32,
    pub summary: VerificationSummary,
    pub providers: Vec<ProviderVerification>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerificationSummary {
    pub providers: usize,
    pub installed: usize,
    pub operations: usize,
    pub verified: usize,
    pub unverified: usize,
    pub suspect: usize,
}

/// How trustworthy an operation's command syntax is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperationStatus {
    /// Every flag is documented by the installed tool's own help output.
    Verified,
    /// The tool is not installed, so its syntax could not be checked.
    Unverified,
    /// The tool is installed but at least one flag is undocumented, or the
    /// template relies on shell syntax that will not survive argv construction.
    Suspect,
}

impl OperationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OperationStatus::Verified => "VERIFIED",
            OperationStatus::Unverified => "UNVERIFIED",
            OperationStatus::Suspect => "SUSPECT",
        }
    }

    /// Whether the framework will offer this operation by default.
    pub fn is_usable(self) -> bool {
        matches!(self, OperationStatus::Verified)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderVerification {
    pub binary: String,
    pub phases: Vec<String>,
    pub operation_count: usize,
    pub installed: bool,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    pub probed: bool,
    pub help_arg: Option<String>,
    pub help_sha256: Option<String>,
    pub flags: Vec<String>,
    pub help_excerpt: Option<String>,
    pub operations: Vec<OperationVerification>,
}

/// A globally unique identity for one legacy registry entry.
///
/// An operation's `index` is only unique within its (phase, tool) pair, and the
/// same binary is registered in several phases and under several tool names —
/// nuclei alone loses 62 entries to index collisions if the index is used on its
/// own. Keying on the triple keeps every operation addressable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OperationKey {
    pub phase: String,
    pub tool: String,
    pub index: usize,
}

impl OperationKey {
    pub fn new(phase: &str, tool: &str, index: usize) -> Self {
        Self {
            phase: phase.to_string(),
            tool: tool.to_string(),
            index,
        }
    }
}

impl std::fmt::Display for OperationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.phase, self.tool, self.index)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperationVerification {
    pub phase: String,
    pub tool: String,
    pub index: usize,
    pub name: String,
    pub status: String,
    pub unknown_flags: Vec<String>,
    pub shell_constructs: Vec<String>,
}

impl OperationVerification {
    pub fn key(&self) -> OperationKey {
        OperationKey::new(&self.phase, &self.tool, self.index)
    }

    pub fn status(&self) -> OperationStatus {
        match self.status.as_str() {
            "verified" => OperationStatus::Verified,
            "suspect" => OperationStatus::Suspect,
            _ => OperationStatus::Unverified,
        }
    }

    /// Operator-facing explanation of why an operation is not offered.
    pub fn blocked_reason(&self) -> Option<String> {
        match self.status() {
            OperationStatus::Verified => None,
            OperationStatus::Unverified => Some(format!(
                "`{}` is not installed, so its command syntax is unverified",
                self.tool
            )),
            OperationStatus::Suspect => {
                let mut parts: Vec<String> = Vec::new();
                if !self.unknown_flags.is_empty() {
                    parts.push(format!(
                        "undocumented flag(s): {}",
                        self.unknown_flags.join(", ")
                    ));
                }
                if !self.shell_constructs.is_empty() {
                    parts.push(format!(
                        "shell construct(s) not valid in an argv: {}",
                        self.shell_constructs.join(", ")
                    ));
                }
                Some(format!("`{}`: {}", self.tool, parts.join("; ")))
            }
        }
    }
}

/// A provider known to the framework, with its verification state.
#[derive(Debug, Clone)]
pub struct Provider {
    pub binary: String,
    pub installed: bool,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    pub probed: bool,
    pub help_arg: Option<String>,
    pub help_sha256: Option<String>,
    pub phases: Vec<String>,
    operation_count: usize,
    statuses: BTreeMap<OperationKey, OperationVerification>,
    /// Extra directories searched before `PATH`.
    search_paths: Vec<PathBuf>,
}

impl Provider {
    pub fn operations(&self) -> impl Iterator<Item = &OperationVerification> {
        self.statuses.values()
    }

    pub fn operation(&self, key: &OperationKey) -> Option<&OperationVerification> {
        self.statuses.get(key)
    }

    /// Operations that may be offered to the operator without qualification.
    pub fn verified_operations(&self) -> Vec<&OperationVerification> {
        self.operations()
            .filter(|o| o.status().is_usable())
            .collect()
    }

    /// Resolve the executable now, honouring configured search paths.
    ///
    /// The verification snapshot is a point-in-time record; a provider that was
    /// absent when the snapshot was taken may have been installed since.
    pub fn resolve(&self) -> Option<PathBuf> {
        if self.binary.contains('/') || self.binary.contains(' ') {
            let p = Path::new(&self.binary);
            return p.is_file().then(|| p.to_path_buf());
        }
        for dir in &self.search_paths {
            let cand = dir.join(&self.binary);
            if cand.is_file() {
                return Some(cand);
            }
        }
        find_in_path(&self.binary)
    }

    /// One-line readiness summary for the provider table.
    pub fn status_line(&self) -> String {
        let state = if !self.installed {
            "NOT INSTALLED"
        } else if !self.probed {
            "HELP UNREADABLE"
        } else {
            let verified = self.verified_operations().len();
            if verified == 0 {
                "NO VERIFIED SYNTAX"
            } else {
                return format!("{verified}/{} VERIFIED", self.operation_count);
            }
        };
        state.to_string()
    }
}

/// The full provider registry loaded from the verification snapshot.
#[derive(Debug, Clone)]
pub struct Registry {
    providers: Vec<Provider>,
    summary: VerificationSummary,
    source: PathBuf,
}

impl Registry {
    /// Load the committed verification snapshot.
    ///
    /// The snapshot is data, not code: it records what the maintainers actually
    /// observed on a real host. It is read at startup so a stale or hand-edited
    /// file is a startup error rather than a silent behaviour change.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            TsecError::new(
                Stage::ResolveTools,
                ExecutionErrorKind::Io {
                    context: format!("reading provider verification snapshot {}", path.display()),
                    reason: e.to_string(),
                },
            )
            .with_hint(
                "regenerate it with `python3 scripts/verify_providers.py`; the framework \
                 refuses to run unverified command syntax",
            )
        })?;
        let doc: VerificationDoc = serde_json::from_str(&raw).map_err(|e| {
            TsecError::new(
                Stage::ResolveTools,
                ExecutionErrorKind::Catalog {
                    reason: format!("provider verification snapshot is malformed: {e}"),
                },
            )
        })?;
        if doc.schema != 1 {
            return Err(TsecError::new(
                Stage::ResolveTools,
                ExecutionErrorKind::Catalog {
                    reason: format!(
                        "provider verification snapshot schema {} is not supported (expected 1)",
                        doc.schema
                    ),
                },
            ));
        }

        let mut providers = Vec::with_capacity(doc.providers.len());
        for p in doc.providers {
            let mut statuses: BTreeMap<OperationKey, OperationVerification> = BTreeMap::new();
            for op in p.operations {
                // A duplicate key means the snapshot itself is inconsistent.
                // Silently overwriting would drop operations from the very table
                // the runtime uses to decide what it may run, so it is an error.
                let key = op.key();
                if statuses.insert(key.clone(), op).is_some() {
                    return Err(TsecError::new(
                        Stage::Execute,
                        ExecutionErrorKind::Catalog {
                            reason: format!(
                                "provider `{}` lists operation {key} twice in {}",
                                p.binary,
                                path.display()
                            ),
                        },
                    ));
                }
            }
            if statuses.len() != p.operation_count {
                return Err(TsecError::new(
                    Stage::Execute,
                    ExecutionErrorKind::Catalog {
                        reason: format!(
                            "provider `{}` declares {} operations but lists {} in {}",
                            p.binary,
                            p.operation_count,
                            statuses.len(),
                            path.display()
                        ),
                    },
                ));
            }
            providers.push(Provider {
                operation_count: p.operation_count,
                binary: p.binary,
                installed: p.installed,
                path: p.path,
                version: p.version,
                probed: p.probed,
                help_arg: p.help_arg,
                help_sha256: p.help_sha256,
                phases: p.phases,
                statuses,
                search_paths: Vec::new(),
            });
        }
        Ok(Self {
            providers,
            summary: doc.summary,
            source: path.to_path_buf(),
        })
    }

    /// Add directories searched ahead of `PATH` for every provider.
    pub fn with_search_paths(mut self, paths: Vec<PathBuf>) -> Self {
        for p in &mut self.providers {
            p.search_paths = paths.clone();
        }
        self
    }

    pub fn summary(&self) -> &VerificationSummary {
        &self.summary
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn all(&self) -> &[Provider] {
        &self.providers
    }

    pub fn get(&self, binary: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.binary == binary)
    }

    pub fn in_phase(&self, phase: &str) -> Vec<&Provider> {
        self.providers
            .iter()
            .filter(|p| p.phases.iter().any(|x| x == phase))
            .collect()
    }

    /// Providers that are installed and expose at least one verified operation.
    pub fn ready(&self) -> Vec<&Provider> {
        self.providers
            .iter()
            .filter(|p| !p.verified_operations().is_empty())
            .collect()
    }

    /// How many operations in total may be offered without qualification.
    pub fn verified_operation_count(&self) -> usize {
        self.providers
            .iter()
            .map(|p| p.verified_operations().len())
            .sum()
    }
}

/// Look an executable up in `PATH` without spawning anything.
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = Path::new(name);
        return p.is_file().then(|| p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|cand| cand.is_file() && is_executable(cand))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(ops: &[(&str, &str)]) -> String {
        let operations: Vec<String> = ops
            .iter()
            .enumerate()
            .map(|(i, (status, name))| {
                format!(
                    r#"{{"phase":"recon","tool":"t","index":{i},"name":"{name}",
                        "status":"{status}","unknown_flags":[],"shell_constructs":[]}}"#
                )
            })
            .collect();
        format!(
            r#"{{"schema":1,
                 "summary":{{"providers":1,"installed":1,"operations":{n},"verified":0,
                             "unverified":0,"suspect":0}},
                 "providers":[{{"binary":"demo","phases":["recon"],"operation_count":{n},
                    "installed":true,"path":"/usr/bin/demo","version":"1.0","probed":true,
                    "help_arg":"--help","help_sha256":"ab","flags":["-o"],
                    "operations":[{ops}]}}]}}"#,
            n = ops.len(),
            ops = operations.join(",")
        )
    }

    /// Write a snapshot to a path no other test can touch.
    ///
    /// Keyed on the process id alone, every test in this module would share one
    /// file: cargo runs them on parallel threads, so one test's `load` would
    /// read a body another had just overwritten, or one still mid-write. The
    /// counter makes each scratch file private to one call.
    fn write(body: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("tsec-reg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(format!("verification-{n}.json"));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn only_verified_operations_are_offered() {
        let p = write(&snapshot(&[
            ("verified", "good"),
            ("suspect", "bad"),
            ("unverified", "absent"),
        ]));
        let reg = Registry::load(&p).unwrap();
        let demo = reg.get("demo").unwrap();
        assert_eq!(demo.operation_count, 3);
        assert_eq!(demo.verified_operations().len(), 1);
        assert_eq!(demo.verified_operations()[0].name, "good");
    }

    #[test]
    fn suspect_operations_explain_the_undocumented_flags() {
        let body = snapshot(&[("suspect", "bad")])
            .replace(r#""unknown_flags":[]"#, r#""unknown_flags":["--nope"]"#)
            .replace(r#""shell_constructs":[]"#, r#""shell_constructs":[">"]"#);
        let p = write(&body);
        let reg = Registry::load(&p).unwrap();
        let reason = reg
            .get("demo")
            .unwrap()
            .operation(&OperationKey::new("recon", "t", 0))
            .unwrap()
            .blocked_reason()
            .unwrap();
        assert!(reason.contains("--nope"), "{reason}");
        assert!(reason.contains("shell construct"), "{reason}");
    }

    #[test]
    fn unverified_operations_report_the_missing_tool() {
        let p = write(&snapshot(&[("unverified", "absent")]));
        let reg = Registry::load(&p).unwrap();
        let reason = reg
            .get("demo")
            .unwrap()
            .operation(&OperationKey::new("recon", "t", 0))
            .unwrap()
            .blocked_reason()
            .unwrap();
        assert!(reason.contains("not installed"), "{reason}");
    }

    #[test]
    fn a_missing_snapshot_is_a_startup_error_with_a_remedy() {
        let err = Registry::load(Path::new("/nonexistent/verification.json")).unwrap_err();
        assert_eq!(err.kind.code(), "IO_FAILURE");
        assert!(err.hint.as_deref().unwrap().contains("verify_providers.py"));
    }

    #[test]
    fn a_malformed_snapshot_is_rejected() {
        let p = write("{ not json");
        let err = Registry::load(&p).unwrap_err();
        assert_eq!(err.kind.code(), "CATALOG_ERROR");
    }

    #[test]
    fn an_unsupported_schema_is_rejected_rather_than_guessed() {
        let p = write(&snapshot(&[("verified", "a")]).replace(r#""schema":1"#, r#""schema":7"#));
        let err = Registry::load(&p).unwrap_err();
        assert!(err.reason().contains("schema 7"), "{}", err.reason());
    }

    #[test]
    fn path_lookup_finds_a_known_executable_and_rejects_an_unknown_one() {
        assert!(find_in_path("sh").is_some());
        assert!(find_in_path("tsec-definitely-not-installed").is_none());
    }

    #[test]
    fn only_verified_operations_are_usable() {
        // Ordering: Verified < Unverified < Suspect as declared.
        assert!(OperationStatus::Verified < OperationStatus::Unverified);
        assert!(OperationStatus::Unverified < OperationStatus::Suspect);
        assert!(OperationStatus::Verified.is_usable());
        assert!(!OperationStatus::Unverified.is_usable());
        assert!(!OperationStatus::Suspect.is_usable());
    }

    #[test]
    fn the_same_index_in_two_phases_is_two_different_operations() {
        // The legacy registry numbers operations per (phase, tool) pair, so a
        // binary registered in two phases produces two operations numbered 0.
        // Keying on the index alone silently merged them.
        let body = snapshot(&[("verified", "recon op"), ("verified", "surface op")]).replace(
            r#"{"phase":"recon","tool":"t","index":1"#,
            r#"{"phase":"surface","tool":"t","index":1"#,
        );
        let reg = Registry::load(&write(&body)).unwrap();
        let demo = reg.get("demo").unwrap();
        assert_eq!(demo.operations().count(), 2);
        let recon = demo.operation(&OperationKey::new("recon", "t", 0)).unwrap();
        let surface = demo
            .operation(&OperationKey::new("surface", "t", 1))
            .unwrap();
        assert_eq!(recon.name, "recon op");
        assert_eq!(surface.name, "surface op");
        assert!(demo
            .operation(&OperationKey::new("recon", "t", 1))
            .is_none());
    }

    #[test]
    fn a_duplicate_operation_key_is_rejected() {
        let body = snapshot(&[("verified", "a"), ("verified", "b")])
            .replace(r#""index":1"#, r#""index":0"#);
        let err = Registry::load(&write(&body)).unwrap_err();
        assert_eq!(err.kind.code(), "CATALOG_ERROR");
        assert!(err.reason().contains("twice"), "{}", err.reason());
    }

    #[test]
    fn the_shipped_snapshot_keeps_every_operation() {
        // Guards the keying change against the real file: the summary's operation
        // count must equal the number of operations actually addressable.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/verification.json");
        if !path.exists() {
            return;
        }
        let reg = Registry::load(&path).unwrap();
        let total: usize = reg.all().iter().map(|p| p.operations().count()).sum();
        assert_eq!(
            total,
            reg.summary().operations,
            "operations were lost while indexing"
        );
        assert!(total > 10_000, "snapshot looks truncated: {total}");
    }
}
