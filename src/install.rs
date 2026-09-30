//! Arch Linux installation guidance for missing providers, plus the small
//! read-only process helpers the theme adapter needs.
//!
//! The rule this module exists to enforce: **never invent a package name.**
//! A command is only offered after a local package database query actually
//! resolved it — `pacman -Si <name>` against the host's sync database, which
//! is an offline metadata read. An AUR package cannot be verified without
//! network access, and TSEC never queries the network outside the oniux
//! boundary, so for AUR-only tools the operator gets a *search* command to
//! run themselves rather than a claim that a package exists.
//!
//! Guidance is cached per binary for the life of the process: a capability
//! menu listing twelve missing providers queries each one once.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::provider::find_in_path;

/// Resolve an executable on `PATH` (or as an absolute path).
pub fn which(binary: &str) -> Option<PathBuf> {
    find_in_path(binary)
}

/// Run `program args…` with a hard timeout and capture stdout.
///
/// Returns the exit code and stdout; `None` when the program could not be
/// started at all. The child is killed if the timeout elapses, so a wedged
/// helper can never hang the interface.
pub fn run_capture(program: &str, args: &[&str], timeout_secs: u64) -> Option<(i32, String)> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        buf
    });

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    let out = reader.join().unwrap_or_default();
    match status {
        Some(status) => Some((status.code().unwrap_or(-1), out)),
        // Killed by the timeout: report failure with whatever was read.
        None => Some((-1, out)),
    }
}

/// A package resolved in the official repositories.
#[derive(Debug, Clone)]
pub struct OfficialPackage {
    pub repo: String,
    pub name: String,
    pub version: String,
    pub description: String,
}

/// What the operator should do to install a missing provider.
#[derive(Debug, Clone)]
pub struct InstallAdvice {
    pub binary: String,
    /// Set when `pacman -Si` really resolved the package.
    pub official: Option<OfficialPackage>,
    /// An AUR helper present on this host (`yay`, `paru`).
    pub helper: Option<String>,
    /// Verified install commands, ready to display.
    pub commands: Vec<String>,
    /// Honest context: where it was verified, or why nothing was.
    pub notes: Vec<String>,
}

impl InstallAdvice {
    /// Already-installed advice, for completeness of the API.
    pub fn installed(binary: &str, path: &Path) -> Self {
        Self {
            binary: binary.to_string(),
            official: None,
            helper: None,
            commands: Vec::new(),
            notes: vec![format!("already installed at {}", path.display())],
        }
    }
}

/// An AUR helper on this host, preferring `yay` then `paru`.
pub fn helper() -> Option<String> {
    ["yay", "paru"]
        .into_iter()
        .find(|h| which(h).is_some())
        .map(String::from)
}

/// Installation guidance for `binary`, cached for the process lifetime.
pub fn advise(binary: &str) -> InstallAdvice {
    static CACHE: OnceLock<Mutex<BTreeMap<String, InstallAdvice>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some(hit) = map.get(binary) {
            return hit.clone();
        }
    }

    let advice = compute(binary);

    if let Ok(mut map) = cache.lock() {
        map.insert(binary.to_string(), advice.clone());
    }
    advice
}

fn compute(binary: &str) -> InstallAdvice {
    if let Some(path) = which(binary) {
        return InstallAdvice::installed(binary, &path);
    }

    let helper = helper();
    let mut advice = InstallAdvice {
        binary: binary.to_string(),
        official: None,
        helper: helper.clone(),
        commands: Vec::new(),
        notes: Vec::new(),
    };

    if which("pacman").is_none() {
        advice.notes.push(
            "pacman was not found — package queries only work on an Arch Linux host".to_string(),
        );
        advice.notes.push(format!(
            "install {binary} from its upstream release and place it on PATH"
        ));
        return advice;
    }

    // Verified lookup: exact name, then the lowercased name, against the
    // host's local sync database. No network, no invented names.
    let mut candidates = vec![binary.to_string()];
    let lower = binary.to_lowercase();
    if lower != binary {
        candidates.push(lower);
    }
    for candidate in &candidates {
        if let Some((code, out)) = run_capture("pacman", &["-Si", candidate], 5) {
            if code == 0 {
                if let Some(pkg) = parse_pacman_info(&out) {
                    advice
                        .commands
                        .push(format!("sudo pacman -S --needed {}", pkg.name));
                    if let Some(helper) = &helper {
                        advice.commands.push(format!("{helper} -S {}", pkg.name));
                    }
                    advice.notes.push(format!(
                        "verified in the {} repository ({} {})",
                        pkg.repo, pkg.name, pkg.version
                    ));
                    advice.official = Some(pkg);
                    return advice;
                }
            }
        }
    }

    // Not official. Say so plainly and hand over a search command the operator
    // can run — TSEC will not claim an AUR package exists without verifying it,
    // and verifying would mean leaving the oniux boundary.
    advice
        .notes
        .push(format!("{binary} is not in the official Arch repositories"));
    match &helper {
        Some(helper) => advice
            .notes
            .push(format!("search the AUR:  {helper} -Ss {binary}")),
        None => advice
            .notes
            .push("no AUR helper found — install yay or paru, then search the AUR".to_string()),
    }
    advice.notes.push(format!(
        "or install {binary} from its upstream release and place it on PATH"
    ));
    advice
}

/// Parse `pacman -Si` output into a resolved package.
fn parse_pacman_info(out: &str) -> Option<OfficialPackage> {
    let mut repo = String::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut description = String::new();
    for line in out.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "Repository" => repo = value,
            "Name" => name = value,
            "Version" => version = value,
            "Description" => description = value,
            _ => {}
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(OfficialPackage {
        repo,
        name,
        version,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacman_info_output_parses_the_fields_that_matter() {
        let out = "\
Repository      : extra
Name            : nuclei
Version         : 3.3.2-1
Description     : Host discovery and vulnerability scanning
Architecture    : x86_64
";
        let pkg = parse_pacman_info(out).unwrap();
        assert_eq!(pkg.repo, "extra");
        assert_eq!(pkg.name, "nuclei");
        assert_eq!(pkg.version, "3.3.2-1");
    }

    #[test]
    fn empty_pacman_output_is_not_a_package() {
        assert!(parse_pacman_info("").is_none());
        assert!(parse_pacman_info("error: package not found\n").is_none());
    }

    #[test]
    fn guidance_for_a_missing_binary_never_invents_a_package() {
        let advice = advise("tsec-definitely-not-a-real-provider");
        assert!(advice.official.is_none());
        assert!(advice.commands.is_empty(), "{:?}", advice.commands);
        assert!(
            advice
                .notes
                .iter()
                .any(|n| n.contains("not in the official")),
            "{:?}",
            advice.notes
        );
    }

    #[test]
    fn guidance_is_cached_between_calls() {
        let a = advise("tsec-cache-probe");
        let b = advise("tsec-cache-probe");
        assert_eq!(a.notes, b.notes);
    }

    #[test]
    fn run_capture_reports_failure_for_a_missing_program() {
        assert!(run_capture("tsec-no-such-program", &[], 1).is_none());
    }

    #[test]
    fn run_capture_kills_a_hung_program() {
        let started = Instant::now();
        let result = run_capture("sleep", &["5"], 1);
        assert!(result.is_some());
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "timeout did not fire: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_known_binary_resolves_to_installed_or_a_verified_package() {
        // nmap is either installed already or in Arch's core repository.
        let advice = advise("nmap");
        assert!(
            advice.official.is_some()
                || advice.notes.iter().any(|n| n.contains("already installed")),
            "{advice:?}"
        );
        if let Some(pkg) = &advice.official {
            assert_eq!(
                advice.commands[0],
                format!("sudo pacman -S --needed {}", pkg.name)
            );
        }
    }
}
