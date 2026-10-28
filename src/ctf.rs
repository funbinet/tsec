//! CTF support: flag-format compilation, format-aware extraction, and the
//! per-operation outcome classification the CTF report is built from.
//!
//! Two rules shape this module:
//!
//! * **A flag format is an extraction filter, not a verdict.** A string that
//!   matches the operator's pattern may sit in a banner, a test fixture, or an
//!   unrelated file. Every candidate therefore keeps its full provenance — the
//!   artifact, the line, the context around the match — and the report presents
//!   candidates as candidates.
//! * **Nothing is inferred from a zero exit code.** [`classify`] separates
//!   "the tool ran cleanly" from "the run found something" and from "a flag was
//!   recovered": a command that exits 0 with no findings is `NO_FINDINGS`, and
//!   a candidate flag is evidence of a match, not of exploitation.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::path::Path;

use regex::Regex;

use crate::domain::execution::ExecutionRecord;
use crate::domain::finding::{Category, Finding, Provenance};

/// Why a flag format was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsecPatternError {
    reason: String,
}

impl TsecPatternError {
    fn empty() -> Self {
        Self {
            reason: "flag format is empty; supply `prefix{...}` or a regex, or leave it unset \
                     to disable extraction"
                .into(),
        }
    }

    fn too_long() -> Self {
        Self {
            reason: "flag format is too long (512 character limit)".into(),
        }
    }

    fn invalid(source: &str, why: &str) -> Self {
        Self {
            reason: format!("flag format {source:?} is not a valid pattern: {why}"),
        }
    }

    fn indiscriminate(why: &str) -> Self {
        Self {
            reason: format!("flag format is too broad: {why}"),
        }
    }

    /// The human-readable reason, for prompts and reports.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// A compiled flag format, ready to scan raw evidence.
///
/// Two spellings are accepted, decided by shape rather than a mode flag:
/// * **shorthand** — `safctf{...}` or `flag{...}`: a literal prefix (no regex
///   operators), ending in `{...}`. Expanded to the escaped prefix plus a
///   bounded identifier body, so it can never match everything.
/// * **full regex** — anything carrying regex operators is compiled as
///   written, case-insensitively when it ends with `/i`.
///
/// Patterns with no discriminating power — matching the empty string, or
/// matching ordinary text everywhere — are refused: a pattern that matches
/// everything turns every artifact into thousands of false candidates.
#[derive(Debug, Clone)]
pub struct FlagPattern {
    regex: Regex,
    /// The pattern as the operator typed it, for the report and the sidecar.
    pub declared: String,
}

impl FlagPattern {
    /// Compile an operator-supplied flag format.
    pub fn compile(declared: &str) -> Result<Self, TsecPatternError> {
        let declared = declared.trim();
        if declared.is_empty() {
            return Err(TsecPatternError::empty());
        }
        if declared.len() > 512 {
            return Err(TsecPatternError::too_long());
        }

        // Case sensitivity opt-in: a trailing `/i` on a full regex.
        let (source, case_insensitive) = match declared.strip_suffix("/i") {
            Some(rest) => (rest, true),
            None => (declared, false),
        };

        let regex_source = if Self::is_shorthand(source) {
            Self::expand_shorthand(source)?
        } else {
            source.to_string()
        };

        let regex = if case_insensitive {
            regex::RegexBuilder::new(&regex_source)
                .case_insensitive(true)
                .build()
                .map_err(|e| TsecPatternError::invalid(&regex_source, &e.to_string()))?
        } else {
            Regex::new(&regex_source)
                .map_err(|e| TsecPatternError::invalid(&regex_source, &e.to_string()))?
        };
        if regex.is_match("") {
            return Err(TsecPatternError::indiscriminate(
                "the pattern matches the empty string",
            ));
        }
        // A probe of ordinary text: a real flag format is rare in it. A
        // pattern that hits four times or more would light up every artifact.
        let probe = "the quick brown fox 2026 -- test line";
        if regex.find_iter(probe).count() >= 4 {
            return Err(TsecPatternError::indiscriminate(
                "the pattern matches ordinary text everywhere; it is too broad to be a flag format",
            ));
        }

        Ok(Self {
            regex,
            declared: declared.to_string(),
        })
    }

    /// A shorthand is a literal prefix with no regex structure, ending in
    /// `{...}`. Everything else is treated as a full regex.
    fn is_shorthand(source: &str) -> bool {
        let Some(prefix) = source.strip_suffix("{...}") else {
            return false;
        };
        !prefix.is_empty()
            && !prefix.chars().any(|c| {
                matches!(
                    c,
                    '(' | ')' | '[' | ']' | '|' | '*' | '+' | '?' | '\\' | '.' | '^' | '$'
                )
            })
    }

    /// `safctf{...}` → `safctf\{[A-Za-z0-9_]{1,64}\}`.
    ///
    /// The body is bounded on purpose: an unbounded body would run over a
    /// whole artifact looking for one distant brace.
    fn expand_shorthand(source: &str) -> Result<String, TsecPatternError> {
        let body_marker = "{...}";
        let Some(prefix) = source.strip_suffix(body_marker) else {
            return Err(TsecPatternError::indiscriminate(
                "shorthand flag formats must look like `prefix{...}`",
            ));
        };
        if prefix.is_empty() {
            return Err(TsecPatternError::indiscriminate(
                "shorthand flag formats need a literal prefix before `{...}`",
            ));
        }
        let mut escaped = String::with_capacity(prefix.len() + 32);
        for ch in prefix.chars() {
            match ch {
                '{' => escaped.push_str("\\{"),
                '}' => escaped.push_str("\\}"),
                _ => escaped.push(ch),
            }
        }
        escaped.push_str("\\{[A-Za-z0-9_]{1,64}\\}");
        Ok(escaped)
    }

    /// Extract every candidate from one artifact's bytes.
    ///
    /// One finding per distinct match; a value seen again later is collapsed
    /// by the standard `(category, value)` dedup while its sightings are
    /// counted. Each finding carries its line number and a bounded context
    /// excerpt so the report can show what surrounded the match.
    pub fn extract(&self, artifact: &Path, provenance: &Provenance) -> Vec<Finding> {
        let bytes = match std::fs::read(artifact) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut out: Vec<Finding> = Vec::new();
        for (index, line) in text.lines().enumerate() {
            for hit in self.regex.find_iter(line) {
                let mut context: String = line.chars().take(250).collect();
                if line.chars().count() > 250 {
                    context.push('…');
                }
                out.push(Finding {
                    category: Category::FlagCandidate,
                    value: hit.as_str().to_string(),
                    detail: Some(format!(
                        "line {} in {} — context: {}",
                        index + 1,
                        artifact.display(),
                        context
                    )),
                    provenance: provenance.clone(),
                    occurrences: 1,
                });
            }
        }
        out
    }
}

/// How one attempted operation turned out, from the CTF report's point of
/// view. Deliberately distinct from [`crate::domain::execution::TaskStatus`],
/// which records what happened to the *process*: this classifies what the
/// *attempt* yielded. A zero exit code alone is `SUCCESS` only when the tool
/// also surfaced something; otherwise it is `NO_FINDINGS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Outcome {
    /// Completed and surfaced at least one finding.
    Success,
    /// Completed cleanly but surfaced nothing.
    NoFindings,
    /// Withdrawn before dispatch (evidence logic, scope, confirmation).
    NotApplicable,
    /// Did not run: missing tool, declined confirmation, missing input.
    Skipped,
    /// Ran and failed — a nonzero exit, a spawn error, a signal.
    ExecutionError,
    /// Ran past its time limit and was terminated.
    Timeout,
    /// Cancelled by the operator.
    Cancelled,
    /// Completed but the parser could not read the output.
    ParseError,
}

impl Outcome {
    /// The stable token used in `ctf.json` and the CTF report.
    pub fn token(self) -> &'static str {
        match self {
            Outcome::Success => "SUCCESS",
            Outcome::NoFindings => "NO_FINDINGS",
            Outcome::NotApplicable => "NOT_APPLICABLE",
            Outcome::Skipped => "SKIPPED",
            Outcome::ExecutionError => "EXECUTION_ERROR",
            Outcome::Timeout => "TIMEOUT",
            Outcome::Cancelled => "CANCELLED",
            Outcome::ParseError => "PARSE_ERROR",
        }
    }

    /// Classify one record from its status, its exit code and how many
    /// findings its artifact yielded.
    pub fn classify(record: &ExecutionRecord, findings: usize, parse_failed: bool) -> Self {
        use crate::domain::execution::TaskStatus;
        match record.status {
            TaskStatus::Skipped => Outcome::Skipped,
            TaskStatus::Interrupted => Outcome::Cancelled,
            TaskStatus::TimedOut => Outcome::Timeout,
            TaskStatus::Failed => Outcome::ExecutionError,
            TaskStatus::Complete | TaskStatus::Pending | TaskStatus::Running => {
                if parse_failed {
                    Outcome::ParseError
                } else if findings > 0 {
                    Outcome::Success
                } else {
                    Outcome::NoFindings
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn prov() -> Provenance {
        Provenance {
            boundary: crate::domain::execution::ExecBoundary::Oniux,
            provider: "strings".into(),
            operation: "String Sweep".into(),
            task_id: "T01".into(),
            command: "strings dump.bin".into(),
            observed_at: chrono::Utc::now(),
            artifact: PathBuf::from("/run/raw/strings.out"),
        }
    }

    #[test]
    fn shorthand_compiles_to_a_bounded_pattern() {
        let p = FlagPattern::compile("safctf{...}").unwrap();
        assert!(p.regex.is_match("safctf{c0ffee}"));
        // The shorthand is case-sensitive: the prefix is literal.
        assert!(!p.regex.is_match("SAFCTF{A_B}"));
        // The body is bounded: 64 characters match, 65 do not.
        assert!(p.regex.is_match(&format!("safctf{{{}}}", "a".repeat(64))));
        assert!(!p.regex.is_match(&format!("safctf{{{}}}", "a".repeat(65))));
        // The brace is literal: no match without one.
        assert!(!p.regex.is_match("safctf no braces here"));
        assert_eq!(p.declared, "safctf{...}");
        // Case-insensitive opt-in also works for shorthand spellings.
        let ci = FlagPattern::compile("safctf{...}/i").unwrap();
        assert!(ci.regex.is_match("SAFCTF{A_B}"));
    }

    #[test]
    fn a_bare_prefix_without_body_marker_is_a_regex_not_shorthand() {
        // `flag{` without the `{...}` body is regex input, and an unescaped
        // `{` is refused by the engine rather than silently mangled.
        assert!(FlagPattern::compile("flag{").is_err());
    }

    #[test]
    fn full_regex_and_case_insensitive_suffix_work() {
        let p = FlagPattern::compile(r"[A-Za-z0-9_]+@challenge\.local").unwrap();
        assert!(p.regex.is_match("user@challenge.local"));
        assert!(FlagPattern::compile(r"flag\{[a-z0-9]{4,8}\}").is_ok());

        let ci = FlagPattern::compile("FLAG[0-9]+/i").unwrap();
        assert!(ci.regex.is_match("flag12345"));
        assert!(FlagPattern::compile("flag[0-9]+")
            .unwrap()
            .regex
            .is_match("flag123"));
    }

    #[test]
    fn indiscriminate_patterns_are_refused() {
        // Matches the empty string.
        assert!(FlagPattern::compile(".*").is_err());
        assert!(FlagPattern::compile("(x)?").is_err());
        // Matches ordinary text everywhere: no discriminating power.
        assert!(FlagPattern::compile("[a-z]+").is_err());
        assert!(FlagPattern::compile("").is_err());
    }

    #[test]
    fn extract_reports_line_and_context() {
        let pattern = FlagPattern::compile("tsec{...}").unwrap();
        let dir = std::env::temp_dir().join("tsec-ctf-extract");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("evidence.txt");
        std::fs::write(
            &file,
            "noise line one\nDEBUG token=tsec{Ab_0_9xy} end of line\nlast line\n",
        )
        .unwrap();
        let hits = pattern.extract(&file, &prov());
        assert_eq!(hits.len(), 1);
        let f = &hits[0];
        assert_eq!(f.category, Category::FlagCandidate);
        assert_eq!(f.value, "tsec{Ab_0_9xy}");
        assert_eq!(f.occurrences, 1);
        let detail = f.detail.clone().unwrap();
        assert!(detail.contains("line 2"), "{detail}");
        assert!(detail.contains("token=tsec{Ab_0_9xy}"), "{detail}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_reads_only_readable_text() {
        let pattern = FlagPattern::compile("x{...}").unwrap();
        // A directory is not readable as a file; extraction yields nothing
        // rather than an error.
        let hits = pattern.extract(&PathBuf::from("/"), &prov());
        assert!(hits.is_empty());
    }

    #[test]
    fn classify_maps_status_to_outcome() {
        use crate::domain::execution::TaskStatus;
        let record = |status| ExecutionRecord {
            task_id: "T01".into(),
            phase: "ctf".into(),
            capability: "X".into(),
            provider: "t".into(),
            operation: "o".into(),
            label: "t · o".into(),
            command: "t".into(),
            program: "t".into(),
            args: vec![],
            network: false,
            boundary: crate::domain::execution::ExecBoundary::Local,
            launched: String::new(),
            uses_shell: false,
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            duration_ms: 0,
            status,
            exit_code: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
            raw_output: PathBuf::from("/run/raw/t.out"),
            stderr_output: None,
            harvest_section: None,
            error_code: None,
            error_message: None,
        };
        assert_eq!(
            Outcome::classify(&record(TaskStatus::Complete), 0, false),
            Outcome::NoFindings
        );
        assert_eq!(
            Outcome::classify(&record(TaskStatus::Complete), 3, false),
            Outcome::Success
        );
        assert_eq!(
            Outcome::classify(&record(TaskStatus::Complete), 0, true),
            Outcome::ParseError
        );
        assert_eq!(
            Outcome::classify(&record(TaskStatus::Failed), 0, false),
            Outcome::ExecutionError
        );
        assert_eq!(
            Outcome::classify(&record(TaskStatus::TimedOut), 0, false),
            Outcome::Timeout
        );
        assert_eq!(
            Outcome::classify(&record(TaskStatus::Interrupted), 0, false),
            Outcome::Cancelled
        );
        assert_eq!(
            Outcome::classify(&record(TaskStatus::Skipped), 0, false),
            Outcome::Skipped
        );
    }

    #[test]
    fn outcome_tokens_are_stable() {
        assert_eq!(Outcome::Success.token(), "SUCCESS");
        assert_eq!(Outcome::NoFindings.token(), "NO_FINDINGS");
        assert_eq!(Outcome::NotApplicable.token(), "NOT_APPLICABLE");
        assert_eq!(Outcome::Skipped.token(), "SKIPPED");
        assert_eq!(Outcome::ExecutionError.token(), "EXECUTION_ERROR");
        assert_eq!(Outcome::Timeout.token(), "TIMEOUT");
        assert_eq!(Outcome::Cancelled.token(), "CANCELLED");
        assert_eq!(Outcome::ParseError.token(), "PARSE_ERROR");
    }
}
