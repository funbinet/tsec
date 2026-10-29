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
            reason: "flag format is empty; supply the flag prefix word (e.g. the challenge's own \
                     prefix), `prefix{...}`, or a regex — or leave it unset to disable extraction"
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

/// How confident a flag-format hit is. The tier decides both the finding
/// category the hit lands in and how the report phrases it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// The operator's format with a body inside braces — `safctf{...}`. This
    /// is the real flag shape, and the match text is the flag value itself.
    Braced,
    /// A bare occurrence of the prefix, or of a term derived from it (`ctf`
    /// inside `safctf`). A lead: flags are also discussed without their
    /// braces, in comments, notes and prompts.
    Term,
    /// A generic `word{body}` flag shape with a prefix nobody declared —
    /// what an unknown-format flag looks like before anyone names it.
    FlagShaped,
}

impl MatchKind {
    /// The stable token used in `ctf.json` and the hits report.
    pub fn token(self) -> &'static str {
        match self {
            MatchKind::Braced => "BRACED",
            MatchKind::Term => "TERM",
            MatchKind::FlagShaped => "FLAG_SHAPED",
        }
    }
}

/// A compiled flag format, ready to scan raw evidence.
///
/// The operator types the *prefix* — `safctf`, not `safctf{...}`. The framework
/// builds the searches itself, in descending order of confidence:
///
/// * **braced** — `safctf{...}`: the prefix followed by a brace-bounded body.
///   A hit here is the flag value as it will be submitted, and is the tier the
///   output and report quote verbatim.
/// * **term** — the bare word, and terms derived from it (separator and
///   camelCase components, a trailing `ctf`), word-bounded. A hit means the
///   format's vocabulary is present without a flag shape around it.
/// * **flag-shaped** — `word{body}` for any word: catches a flag whose exact
///   prefix differs from what was typed.
///
/// `prefix{...}` shorthand and full regex spellings still work, decided by
/// shape rather than a mode flag. Bare-word and shorthand inputs are searched
/// case-insensitively — the operator should not have to guess the challenge's
/// letter case — while a full regex means exactly what it says unless it ends
/// in `/i`.
///
/// The indiscriminate checks — matching the empty string, matching ordinary
/// text everywhere — apply to the braced pattern only. A bare term that names
/// ordinary words is the operator's choice and lands in the low-confidence
/// tier, where its noise costs a dedup, not a verdict.
#[derive(Debug, Clone)]
pub struct FlagPattern {
    /// Compiled tiers, most confident first.
    tiers: Vec<(Regex, MatchKind)>,
    /// The pattern as the operator typed it, for the report and the sidecar.
    pub declared: String,
}

/// The brace body a bare prefix or shorthand expands to. Bounded and
/// punctuation-tolerant: real flag bodies carry digits, symbols and case, and
/// an unbounded body would run over a whole artifact looking for one distant
/// brace.
const FLAG_BODY: &str = "[A-Za-z0-9_!@#$%^&*+=?.,:;~'\\-]{1,256}";

/// The generic flag shape: any word followed by a brace-bounded body. This is
/// the net cast for flags whose prefix was never declared.
const FLAG_SHAPED: &str = "\\b[A-Za-z][A-Za-z0-9_]{1,31}\\{[^{}\\n]{4,256}\\}";

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

        let mut tiers: Vec<(Regex, MatchKind)> = Vec::new();
        let mut push = |source: String, kind: MatchKind| -> Result<(), TsecPatternError> {
            let regex = Regex::new(&source)
                .map_err(|e| TsecPatternError::invalid(&source, &e.to_string()))?;
            tiers.push((regex, kind));
            Ok(())
        };

        if Self::is_bare_word(source) {
            // A bare prefix: the framework builds every search itself,
            // case-insensitively, braced first.
            let mut braced = Self::ci(&Self::escape_literal(source));
            braced.push_str("\\{");
            braced.push_str(FLAG_BODY);
            braced.push_str("\\}");
            push(braced, MatchKind::Braced)?;
            // The bare word itself, then the terms derived from it.
            push(
                format!("\\b{}\\b", Self::ci(&Self::escape_literal(source))),
                MatchKind::Term,
            )?;
            for term in Self::derived_terms(source) {
                push(format!("\\b{}\\b", Self::ci(&term)), MatchKind::Term)?;
            }
            push(FLAG_SHAPED.into(), MatchKind::FlagShaped)?;
        } else if Self::is_shorthand(source) {
            // `prefix{...}`: the operator's own expansion, plus the word-level
            // searches a bare prefix would have had — the braces are a
            // spelling detail, not a different flag.
            let prefix = source
                .strip_suffix("{...}")
                .expect("shorthand checked by is_shorthand");
            let mut braced = Self::escape_literal(prefix);
            braced.push_str(&format!("\\{{{}\\}}", FLAG_BODY));
            if case_insensitive {
                braced = Self::ci(&braced);
            }
            push(braced, MatchKind::Braced)?;
            if Self::is_bare_word(prefix) {
                let mut term = format!("\\b{}\\b", Self::escape_literal(prefix));
                if case_insensitive {
                    term = Self::ci(&term);
                }
                push(term, MatchKind::Term)?;
                for term in Self::derived_terms(prefix) {
                    push(format!("\\b{}\\b", Self::ci(&term)), MatchKind::Term)?;
                }
            }
            push(FLAG_SHAPED.into(), MatchKind::FlagShaped)?;
        } else {
            // A full regex means what it says: one tier, exactly as written.
            let regex = if case_insensitive {
                regex::RegexBuilder::new(source)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| TsecPatternError::invalid(source, &e.to_string()))?
            } else {
                Regex::new(source).map_err(|e| TsecPatternError::invalid(source, &e.to_string()))?
            };
            tiers.push((regex, MatchKind::Braced));
        }

        // The indiscriminate checks guard the primary tier only. A braced
        // pattern that matches everything would turn every artifact into
        // thousands of verdicts; a low-confidence term that names ordinary
        // words is noise in a tier built to absorb it.
        if let Some((primary, _)) = tiers.first() {
            if primary.is_match("") {
                return Err(TsecPatternError::indiscriminate(
                    "the pattern matches the empty string",
                ));
            }
            // A probe of ordinary text: a real flag format is rare in it. A
            // pattern that hits four times or more would light up every
            // artifact with braced matches.
            let probe = "the quick brown fox 2026 -- test line";
            if primary.find_iter(probe).count() >= 4 {
                return Err(TsecPatternError::indiscriminate(
                    "the pattern matches ordinary text everywhere; it is too broad to be a \
                     flag format",
                ));
            }
        }

        Ok(Self {
            tiers,
            declared: declared.to_string(),
        })
    }

    /// A bare prefix: a literal word with no regex structure and no braces —
    /// `safctf`, `flag`, `HTB-2026`. Case, digits, underscores, hyphens and
    /// dots are allowed; everything else is regex territory.
    fn is_bare_word(source: &str) -> bool {
        !source.is_empty()
            && !source.contains('{')
            && source
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
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

    /// Terms derived from a prefix, for the word-level searches: separator
    /// and camelCase components of length ≥ 3, plus `ctf` when the prefix
    /// carries it as a tail (`safctf` → `ctf`). Deduplicated; the full prefix
    /// is added by the caller, not here.
    fn derived_terms(prefix: &str) -> Vec<String> {
        let mut terms: Vec<String> = Vec::new();
        let mut push = |t: &str| {
            if t.len() >= 3 && !terms.iter().any(|x| x == t) {
                terms.push(t.to_string());
            }
        };
        let mut component = String::new();
        let mut prev_lower_or_digit = false;
        for ch in prefix.chars() {
            if matches!(ch, '_' | '-' | '.') {
                if !component.is_empty() {
                    push(&component);
                    component.clear();
                }
                prev_lower_or_digit = false;
            } else if ch.is_uppercase() && prev_lower_or_digit {
                // A camelCase boundary: lower→upper, as in SafeCTF.
                push(&component);
                component.clear();
                component.push(ch);
                prev_lower_or_digit = false;
            } else {
                prev_lower_or_digit = ch.is_lowercase() || ch.is_numeric();
                component.push(ch);
            }
        }
        if !component.is_empty() {
            push(&component);
        }
        // The common `…ctf` tail: `safctf` is searched for as `ctf` too.
        if prefix.len() >= 5 && prefix.to_lowercase().ends_with("ctf") {
            push("ctf");
        }
        terms.retain(|t| t != prefix);
        terms
    }

    /// Lowercase-insensitive wrapper: an inline `(?i)` keeps the tier's
    /// literal pieces as written while matching any letter case.
    fn ci(source: &str) -> String {
        format!("(?i){source}")
    }

    /// Escape every regex metacharacter in a literal.
    fn escape_literal(literal: &str) -> String {
        regex::escape(literal)
    }

    /// Extract every candidate from one artifact's bytes.
    ///
    /// One finding per distinct match; a value seen again later is collapsed
    /// by the standard `(category, value)` dedup while its sightings are
    /// counted. Each finding carries its line number and a bounded context
    /// excerpt so the report can show what surrounded the match.
    ///
    /// Tiers land in different categories: a braced hit is a
    /// [`Category::FlagCandidate`] — the flag value as it would be submitted —
    /// while term and flag-shaped hits are leads under
    /// [`Category::FlagLead`]. A weaker tier's match that sits inside an
    /// already-reported braced match is skipped: the braced hit says
    /// everything the term inside it would.
    pub fn extract(&self, artifact: &Path, provenance: &Provenance) -> Vec<Finding> {
        self.extract_typed(artifact, provenance)
            .into_iter()
            .map(|hit| hit.finding)
            .collect()
    }

    /// Extract with the confidence tier attached, for the hits engine and the
    /// CTF sidecar, which phrase a braced flag and a bare mention differently.
    pub fn extract_typed(&self, artifact: &Path, provenance: &Provenance) -> Vec<FlagHit> {
        let bytes = match std::fs::read(artifact) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut hits: Vec<FlagHit> = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let mut context: String = line.chars().take(250).collect();
            if line.chars().count() > 250 {
                context.push('…');
            }
            // Braced spans already reported on this line: a term landing
            // inside one adds nothing the flag value has not already said.
            let mut braced_spans: Vec<(usize, usize)> = Vec::new();
            for (regex, kind) in &self.tiers {
                for m in regex.find_iter(line) {
                    if *kind != MatchKind::Braced
                        && braced_spans
                            .iter()
                            .any(|(s, e)| m.start() >= *s && m.end() <= *e)
                    {
                        continue;
                    }
                    if *kind == MatchKind::Braced {
                        braced_spans.push((m.start(), m.end()));
                    }
                    let category = match kind {
                        MatchKind::Braced => Category::FlagCandidate,
                        _ => Category::FlagLead,
                    };
                    hits.push(FlagHit {
                        kind: *kind,
                        finding: Finding {
                            category,
                            value: m.as_str().to_string(),
                            detail: Some(format!(
                                "{} match, line {} in {} — context: {}",
                                kind.token(),
                                index + 1,
                                artifact.display(),
                                context
                            )),
                            provenance: provenance.clone(),
                            occurrences: 1,
                        },
                    });
                }
            }
        }
        hits
    }
}

/// One flag-format hit together with the confidence tier that produced it.
#[derive(Debug, Clone)]
pub struct FlagHit {
    pub kind: MatchKind,
    pub finding: Finding,
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

    /// Whether any tier of the pattern matches `text`.
    fn hit(p: &FlagPattern, text: &str) -> bool {
        p.tiers.iter().any(|(r, _)| r.is_match(text))
    }

    /// Whether the pattern's braced tier matches `text`.
    fn braced_hit(p: &FlagPattern, text: &str) -> bool {
        p.tiers
            .iter()
            .any(|(r, k)| matches!(k, MatchKind::Braced) && r.is_match(text))
    }

    #[test]
    fn bare_prefix_compiles_bounded_braced_pattern() {
        // The operator types the prefix; the framework adds the braces.
        let p = FlagPattern::compile("safctf").unwrap();
        assert!(braced_hit(&p, "safctf{c0ffee}"));
        assert!(hit(&p, "safctf{c0ffee}"));
        assert!(hit(&p, "safctf{09x2kc249c235cg3v45554}"));
        assert!(hit(&p, "SAFCTF{A_B}"));
        assert!(hit(&p, "safctf{a.b-c_d!e}"));
        // The body is bounded: the braced tier stops at 256 characters.
        assert!(!braced_hit(&p, &format!("safctf{{{}}}", "a".repeat(257))));
        assert!(braced_hit(&p, &format!("safctf{{{}}}", "a".repeat(256))));
        // The brace is required: the bare word alone is a term-tier lead.
        assert!(hit(&p, "safctf no braces here"));
        assert_eq!(p.declared, "safctf");
    }

    #[test]
    fn bare_prefix_derives_terms() {
        let terms = FlagPattern::derived_terms("safctf");
        assert!(terms.iter().any(|t| t == "ctf"), "{terms:?}");
        let camel = FlagPattern::derived_terms("SafeCTF");
        assert!(camel.iter().any(|t| t == "Safe"), "{camel:?}");
        assert!(camel.iter().any(|t| t == "ctf"), "{camel:?}");
        let snake = FlagPattern::derived_terms("HTB_flag");
        assert!(snake.iter().any(|t| t == "HTB"), "{snake:?}");
        assert!(snake.iter().any(|t| t == "flag"), "{snake:?}");
    }

    #[test]
    fn a_bare_prefix_without_body_marker_is_a_regex_not_shorthand() {
        // `flag{` without the `{...}` body is regex input, and an unescaped
        // `{` is refused by the engine rather than silently mangled.
        assert!(FlagPattern::compile("flag{").is_err());
    }

    #[test]
    fn shorthand_still_works_and_adds_word_tiers() {
        let p = FlagPattern::compile("tsec{...}").unwrap();
        // Case-sensitive primary, exactly as the shorthand always was.
        assert!(braced_hit(&p, "tsec{Ab_0_9xy}"));
        assert!(!braced_hit(&p, "TSEC{A_B}"));
        assert_eq!(p.declared, "tsec{...}");
        // Case-insensitive opt-in widens the braced tier…
        let ci = FlagPattern::compile("tsec{...}/i").unwrap();
        assert!(braced_hit(&ci, "TSEC{A_B}"));
        // …and both spellings still search the bare prefix as a lead.
        assert!(hit(&p, "the tsec challenge"));
        assert!(hit(&ci, "the TSEC challenge"));
    }

    #[test]
    fn a_full_regex_means_exactly_what_it_says() {
        let p = FlagPattern::compile(r"[A-Za-z0-9_]+@challenge\.local").unwrap();
        assert!(hit(&p, "user@challenge.local"));
        assert!(FlagPattern::compile(r"flag\{[a-z0-9]{4,8}\}").is_ok());
        assert!(hit(
            &FlagPattern::compile("FLAG[0-9]+/i").unwrap(),
            "flag12345"
        ));
        // A full regex gets no derived terms: the operator already said what
        // to match.
        assert!(!hit(&p, "challenge.local alone"));
    }

    #[test]
    fn flag_shaped_tier_catches_an_undeclared_prefix() {
        let p = FlagPattern::compile("safctf").unwrap();
        // A different challenge's flag shape, found by the generic net.
        assert!(hit(&p, "otherctf{some_body}"));
        // But JSON braces do not light it up: a word must touch the brace.
        assert!(!hit(&p, r#"see {"role":"admin"} here"#));
    }

    #[test]
    fn braced_hits_are_candidates_terms_are_leads() {
        let p = FlagPattern::compile("safctf").unwrap();
        let dir = std::env::temp_dir().join("tsec-ctf-tiers");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("evidence.txt");
        std::fs::write(
            &file,
            "note: the safctf format this year\nreal: safctf{09x2kc} done\n",
        )
        .unwrap();
        let hits = p.extract_typed(&file, &prov());
        let braced: Vec<_> = hits
            .iter()
            .filter(|h| h.kind == MatchKind::Braced)
            .collect();
        let terms: Vec<_> = hits.iter().filter(|h| h.kind == MatchKind::Term).collect();
        assert_eq!(braced.len(), 1);
        // The flag value is reported verbatim — braces and body included.
        assert_eq!(braced[0].finding.value, "safctf{09x2kc}");
        assert_eq!(braced[0].finding.category, Category::FlagCandidate);
        // The bare mention on line 1 is a lead, and the `ctf` inside the
        // braced match on line 2 is not re-reported.
        assert!(terms
            .iter()
            .any(|h| h.finding.value == "safctf" || h.finding.value == "ctf"));
        assert!(terms
            .iter()
            .all(|h| h.finding.category == Category::FlagLead));
        assert!(!terms.iter().any(|h| h.finding.value == "safctf{09x2kc}"));
        let _ = std::fs::remove_dir_all(&dir);
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
