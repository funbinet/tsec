//! The CTF hits engine: a purpose-built scan over raw evidence that looks
//! for everything a hunt cares about, not only flags.
//!
//! The format parsers understand tool shapes; this engine understands
//! *evidence*. One pass per raw artifact, one regex per hit class, every hit
//! deduplicated by class and value, and every hit carrying the line and
//! context it came from. A hit is an observation with provenance, never a
//! verdict — the report phrases it as one.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::Path;

use crate::domain::finding::{Category, Finding, Provenance};

/// One hunting hit: a value worth the operator's attention, its class, and
/// where in the raw evidence it was seen.
#[derive(Debug, Clone)]
pub struct Hit {
    pub category: Category,
    pub value: String,
    pub detail: String,
}

/// The stable token each hit class reports under, for `ctf.json`.
pub fn class_token(category: Category) -> &'static str {
    match category {
        Category::Hash => "HASH",
        Category::Credential => "CREDENTIAL",
        Category::Secret => "SECRET_KEY",
        Category::Endpoint => "ENDPOINT",
        Category::Cve => "CVE",
        Category::File => "SUSPICIOUS_FILE",
        Category::FlagLead | Category::FlagCandidate => "FLAG",
        Category::Token => "TOKEN",
        Category::Shell => "SHELL",
        Category::Comment => "ENCODED_BLOB",
        _ => "OTHER",
    }
}

/// What the next-steps brain says about each hit class, once hits exist.
pub fn next_step(category: Category) -> Option<&'static str> {
    match category {
        Category::Hash => Some(
            "a hash was recovered — identify its format and run CRYPTO CHALLENGES \
             with a wordlist; a cracked hash is often a password, a token, or the \
             flag body itself",
        ),
        Category::Credential => Some(
            "a credential pair surfaced — try it against every login surface the \
             run found (WEB APP SECURITY, ACTIVE DIRECTORY, PRIVILEGE ESCALATION)",
        ),
        Category::Secret => Some(
            "a private key or secret was recovered — inspect it with SCRIPTING \
             MISC (Cert Inspect, Decode Pass) and try it as an archive or \
             service key",
        ),
        Category::Shell => Some(
            "shell material was observed — check which endpoint or payload \
             produced it; an interactive foothold usually sits near the flag",
        ),
        Category::Endpoint => Some(
            "a suspicious endpoint was discovered — fetch it directly and sweep \
             its source for flags (WEB APP SECURITY, Endpoint Fetch)",
        ),
        Category::Cve => Some(
            "a CVE was named by a scanner — match it to a service version and \
             check exploit availability before deeper fuzzing",
        ),
        Category::File => Some(
            "an interesting file was recovered — run it through SCRIPTING MISC \
             (Type Identify, Archive Extract) and sweep the extraction",
        ),
        Category::Token => Some(
            "a token or key-like string surfaced — decode it, replay it against \
             the target, or feed the material to CRYPTO CHALLENGES",
        ),
        Category::FlagLead => Some(
            "the flag's vocabulary appeared without a flag shape — the flag is \
             close: run FLAG SCANNING over this run's raw evidence",
        ),
        Category::Comment => Some(
            "a long encoded blob was observed — it may be the flag in disguise; \
             run the decoding ladder in SCRIPTING MISC",
        ),
        _ => None,
    }
}

// Bounded, purposeful patterns, each anchored by vocabulary so a hit is a
// reason to look, never a verdict. Encoded blobs live under `Comment`'s
// heading because they are raw material, not yet intelligence.
fn scanners() -> &'static [(regex::Regex, Category)] {
    static SCANNERS: std::sync::OnceLock<Vec<(regex::Regex, Category)>> =
        std::sync::OnceLock::new();
    SCANNERS.get_or_init(|| {
        [
            (r"\b[0-9a-fA-F]{32}\b", Category::Hash),
            (r"\b[0-9a-fA-F]{40}\b", Category::Hash),
            (r"\b[0-9a-fA-F]{64}\b", Category::Hash),
            (r"\$\d[a-z]?\$\d{2}\$[./A-Za-z0-9]{40,}", Category::Hash),
            (r"\$NT\$[0-9a-f]{32}", Category::Hash),
            (r"(?i)user(?:name)?\s*[:=]\s*\S{3,64}", Category::Credential),
            (r"(?i)pass(?:word)?\s*[:=]\s*\S{3,64}", Category::Credential),
            (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", Category::Secret),
            (
                r"(?i)(api[_-]?key|access[_-]?token|bearer)\s*[:=]\s*\S{8,128}",
                Category::Token,
            ),
            (
                r"/bin/(?:ba|z|da|)sh\b|bash\s+-i|pty\.spawn|meterpreter|mkfifo\s",
                Category::Shell,
            ),
            (
                r#"(?i)/(?:admin|administrator|dashboard|\.git|\.env|backup|backups|uploads|config)[^\s"'<>]{0,80}"#,
                Category::Endpoint,
            ),
            (r"CVE-\d{4}-\d{4,7}", Category::Cve),
            (
                r#"(?i)[^\s"']*\.(?:pem|kdbx|kdb|p12|pfx|sql|bak|old)"#,
                Category::File,
            ),
            (r"[A-Za-z0-9+/]{48,}={0,2}", Category::Comment),
        ]
        .into_iter()
        .filter_map(|(source, category)| {
            regex::Regex::new(source)
                .ok()
                .map(|regex| (regex, category))
        })
        .collect()
    })
}

/// Scan one artifact for hits, one finding per distinct `(class, value)`.
pub fn scan(artifact: &Path, provenance: &Provenance) -> Vec<Finding> {
    let bytes = match std::fs::read(artifact) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut out: Vec<Finding> = Vec::new();
    let mut seen: std::collections::HashSet<(Category, String)> = std::collections::HashSet::new();
    for (line_no, line) in text.lines().enumerate() {
        let context: String = line.chars().take(250).collect();
        // Subresource-integrity hashes (`integrity="sha512-…"`) are the page
        // vouching for its own CDN script — not an encoded secret.
        let sri_line = line.contains("integrity=");
        for (regex, category) in scanners() {
            for m in regex.find_iter(line) {
                let value = m.as_str().to_string();
                // An SRI hash is base64-shaped but never a payload.
                if *category == Category::Comment && sri_line {
                    continue;
                }
                if !seen.insert((*category, value.clone())) {
                    continue;
                }
                out.push(Finding {
                    category: *category,
                    value,
                    detail: Some(format!("hits: line {} — context: {}", line_no + 1, context)),
                    provenance: provenance.clone(),
                    occurrences: 1,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn hash_credential_and_cve_are_hits() {
        let dir = std::env::temp_dir().join("tsec-hits");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("evidence.txt");
        std::fs::write(
            &file,
            "md5: 5d41402abc4b2a76b9719d911017c592\n\
             password=hunter2\n\
             scanner found CVE-2021-44228 here\n\
             -----BEGIN RSA PRIVATE KEY-----\n",
        )
        .unwrap();
        let hits = scan(&file, &provenance_stub());
        let classes: Vec<Category> = hits.iter().map(|h| h.category).collect();
        assert!(classes.contains(&Category::Hash));
        assert!(classes.contains(&Category::Credential));
        assert!(classes.contains(&Category::Cve));
        assert!(classes.contains(&Category::Secret));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ordinary_text_yields_no_hits() {
        let dir = std::env::temp_dir().join("tsec-hits-quiet");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("plain.txt");
        std::fs::write(&file, "the quick brown fox 2026 -- test line\n").unwrap();
        assert!(scan(&file, &provenance_stub()).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hits_deduplicate_by_class_and_value() {
        let dir = std::env::temp_dir().join("tsec-hits-dedup");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("evidence.txt");
        std::fs::write(
            &file,
            "CVE-2021-44228 again CVE-2021-44228\nCVE-2021-44228 again\n",
        )
        .unwrap();
        let hits = scan(&file, &provenance_stub());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, Category::Cve);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn provenance_stub() -> Provenance {
        Provenance {
            boundary: crate::domain::execution::ExecBoundary::Local,
            provider: "strings".into(),
            operation: "String Sweep".into(),
            task_id: "T01".into(),
            command: "strings".into(),
            observed_at: chrono::Utc::now(),
            artifact: PathBuf::from("/run/raw/x.out"),
        }
    }
}
