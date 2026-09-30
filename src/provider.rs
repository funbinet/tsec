//! Provider resolution.
//!
//! A provider is an external tool named by a capability. It is only offered to
//! the operator when the executable actually resolves, honouring the configured
//! search paths ahead of `PATH`; anything else is reported honestly as
//! unavailable with the binary names, never silently offered.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::catalog::Catalog;

/// A resolved provider: a binary name and where it was found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Provider {
    pub binary: String,
    pub path: Option<PathBuf>,
}

impl Provider {
    pub fn installed(&self) -> bool {
        self.path.is_some()
    }

    pub fn status_line(&self) -> String {
        match &self.path {
            Some(p) => format!("READY — {}", p.display()),
            None => "NOT INSTALLED".to_string(),
        }
    }
}

/// Live provider availability for every binary named by the catalog.
///
/// Resolution is cached for the life of the registry so a menu redraw does not
/// re-stat `PATH` for every capability on every frame.
#[derive(Debug, Clone)]
pub struct Registry {
    providers: Vec<Provider>,
    search_paths: Vec<PathBuf>,
}

impl Registry {
    /// Build the registry from the catalog's provider bindings.
    pub fn from_catalog(catalog: &Catalog, search_paths: Vec<PathBuf>) -> Self {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut providers = Vec::new();
        for cap in catalog.capabilities() {
            for binding in &cap.providers {
                if seen.insert(binding.binary.clone()) {
                    providers.push(Provider {
                        binary: binding.binary.clone(),
                        path: None,
                    });
                }
            }
        }
        providers.sort();

        let mut reg = Self {
            providers,
            search_paths,
        };
        reg.resolve_all();
        reg
    }

    fn resolve_all(&mut self) {
        // The search paths are cloned once so the provider list can be borrowed
        // mutably while paths are resolved against them.
        let search = self.search_paths.clone();
        for p in &mut self.providers {
            p.path = resolve_in(&search, &p.binary);
        }
    }

    /// Resolve one binary, honouring search paths ahead of `PATH`.
    pub fn resolve(&self, binary: &str) -> Option<PathBuf> {
        resolve_in(&self.search_paths, binary)
    }

    pub fn get(&self, binary: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.binary == binary)
    }

    pub fn all(&self) -> &[Provider] {
        &self.providers
    }

    pub fn installed_count(&self) -> usize {
        self.providers.iter().filter(|p| p.installed()).count()
    }

    pub fn total_count(&self) -> usize {
        self.providers.len()
    }
}

/// Resolve a binary against the configured search paths, then `PATH`.
fn resolve_in(search_paths: &[PathBuf], binary: &str) -> Option<PathBuf> {
    if binary.contains('/') {
        let p = PathBuf::from(binary);
        return p.is_file().then_some(p);
    }
    for dir in search_paths {
        let cand = dir.join(binary);
        if cand.is_file() {
            return Some(cand);
        }
    }
    find_in_path(binary)
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

    #[test]
    fn path_lookup_finds_a_known_executable_and_rejects_an_unknown_one() {
        assert!(find_in_path("sh").is_some());
        assert!(find_in_path("tsec-definitely-not-installed").is_none());
    }

    #[test]
    fn search_paths_are_honoured_before_path() {
        let dir = std::env::temp_dir().join(format!("tsec-reg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tool = dir.join("tsec-fake-tool");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let dir2 = dir.clone();
        let reg = Registry {
            providers: vec![Provider {
                binary: "tsec-fake-tool".into(),
                path: None,
            }],
            search_paths: vec![dir2],
        };
        let resolved = reg.resolve("tsec-fake-tool");
        assert!(resolved.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
