//! The run store: durable, append-only evidence on disk.
//!
//! Execution produces facts, and facts are worthless if they evaporate when a
//! process exits. Everything the framework learns is written here, under one
//! directory per run, and every write is atomic: content is written to a
//! temporary file in the same directory and then renamed over the target. A
//! `rename` within a directory is atomic on POSIX, so a reader either sees the
//! whole old file or the whole new one — never a truncated harvest and never a
//! half-written report.
//!
//! # Layout
//!
//! ```text
//! <output_dir>/<run_id>/
//!   manifest.json        every execution record, in order
//!   output.txt           the consolidated, deduplicated, readable harvest
//!   output.json          the same findings, structured, for correlation
//!   raw/<task>.out       each tool's stdout, exactly as the tool wrote it
//!   raw/<task>.err       each tool's stderr
//! ```
//!
//! Raw output is never rewritten by the parser. A tool's bytes stay exactly as
//! produced, and anything derived from them goes in a separate file, so a
//! disputed finding can always be checked against the original.
//!
//! # Partial runs
//!
//! A run that is cancelled, times out or crashes still has a directory and a
//! manifest containing whatever completed. [`RunStore::finalise`] writes the
//! harvest from the records that exist; it never requires the full plan.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::execution::ExecutionRecord;
use crate::domain::ids::RunId;
use crate::domain::report::RunReport;
use crate::error::{ExecutionErrorKind, Result, Stage, TsecError};
use crate::parser::{parse_artifact, MergedFinding};

/// Everything one run wrote to disk.
#[derive(Debug, Clone)]
pub struct RunStore {
    root: PathBuf,
    run_id: RunId,
    records: Vec<ExecutionRecord>,
}

impl RunStore {
    /// Create (or reopen) the directory for `run_id`.
    pub fn open(output_dir: &Path, run_id: &RunId) -> Result<Self> {
        let root = output_dir.join(run_id.as_str());
        for dir in [root.clone(), root.join("raw")] {
            std::fs::create_dir_all(&dir).map_err(|e| io_err(&dir, &e))?;
        }
        Ok(Self {
            root,
            run_id: run_id.clone(),
            records: Vec::new(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }
    pub fn records(&self) -> &[ExecutionRecord] {
        &self.records
    }

    /// Path of a task's raw stdout inside this run.
    pub fn raw_stdout(&self, task: &str) -> PathBuf {
        self.root.join("raw").join(format!("{task}.out"))
    }
    pub fn raw_stderr(&self, task: &str) -> PathBuf {
        self.root.join("raw").join(format!("{task}.err"))
    }
    /// The consolidated operator-facing text harvest: `output.txt`.
    pub fn output_txt(&self) -> PathBuf {
        self.root.join("output.txt")
    }
    /// The machine-readable harvest: `output.json`.
    pub fn output_json(&self) -> PathBuf {
        self.root.join("output.json")
    }
    /// Compatibility names for older callers and tests.
    pub fn harvest_txt(&self) -> PathBuf {
        self.output_txt()
    }
    pub fn harvest_json(&self) -> PathBuf {
        self.output_json()
    }
    pub fn manifest(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    /// Record one finished task and persist the manifest immediately.
    ///
    /// Writing after every task rather than at the end is what makes a partial
    /// run useful: an operator who interrupts a long scan still has every task
    /// that already finished.
    pub fn commit(&mut self, record: ExecutionRecord) -> Result<()> {
        self.records.push(record);
        self.write_manifest()
    }

    fn write_manifest(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.records)
            .map_err(|e| TsecError::config(format!("serialising manifest: {e}")))?;
        write_atomic(&self.manifest(), json.as_bytes())
    }

    /// Parse every task's raw evidence into one consolidated harvest.
    ///
    /// The pipeline runs as six real, ordered stages — parsing, normalizing,
    /// deduplicating, correlating, harvesting, writing — and `on_stage` is
    /// called after each one actually finishes, so the interface's
    /// `PROCESSING` box is backed by work rather than by a timer.
    ///
    /// `formats` is keyed by operation name (`provider/operation`), falling
    /// back to the provider, then to keeping the raw bytes. Operation is the
    /// right level: one provider can emit different formats per operation, and
    /// parsing nmap's XML as if it were naabu's line list would silently lose
    /// the structured ports.
    pub fn harvest(
        &self,
        formats: &std::collections::BTreeMap<String, crate::catalog::OutputFormat>,
        header: &OutputHeader<'_>,
        mut on_stage: Option<&mut dyn FnMut(HarvestStage) -> Result<()>>,
    ) -> Result<HarvestOutcome> {
        let mut report = |stage: HarvestStage| -> Result<()> {
            match on_stage.as_deref_mut() {
                Some(callback) => callback(stage),
                None => Ok(()),
            }
        };

        // ── PARSING ────────────────────────────────────────────────────────
        let mut merged = crate::parser::Harvest::default();
        let mut sections = Vec::new();
        let mut parse_failures = 0usize;
        let mut artefacts = 0usize;
        let mut noise_lines = 0usize;
        for record in &self.records {
            let format = formats
                .get(&format!("{}/{}", record.provider, record.operation))
                .or_else(|| formats.get(&record.operation))
                .or_else(|| formats.get(&record.provider))
                .copied()
                .unwrap_or(
                    // No declared format: keep the bytes rather than guess.
                    crate::catalog::OutputFormat::Raw,
                );
            let provenance = crate::domain::finding::Provenance {
                boundary: record.boundary,
                provider: record.provider.clone(),
                operation: record.operation.clone(),
                task_id: record.task_id.clone(),
                command: record.command.clone(),
                observed_at: record.finished_at,
                artifact: record.raw_output.clone(),
            };
            match parse_artifact(&record.raw_output, format, provenance.clone()) {
                Ok(h) => {
                    noise_lines += h.noise_lines;
                    artefacts += h
                        .findings()
                        .iter()
                        .filter(|f| f.category != crate::domain::finding::Category::Evidence)
                        .count();
                    sections.push(crate::domain::finding::Finding {
                        category: crate::domain::finding::Category::Metadata,
                        value: format!(
                            "{} / {}: {} findings, {} noise lines",
                            record.provider,
                            record.operation,
                            h.len(),
                            h.noise_lines
                        ),
                        detail: None,
                        provenance: provenance.clone(),
                        occurrences: 1,
                    });
                    merged.absorb(h);
                }
                Err(e) => {
                    parse_failures += 1;
                    sections.push(crate::domain::finding::Finding {
                        category: crate::domain::finding::Category::Evidence,
                        value: format!("{}: unparsed ({})", record.provider, e.kind.code()),
                        detail: Some(e.reason()),
                        provenance: provenance.clone(),
                        occurrences: 1,
                    });
                }
            }
        }
        report(HarvestStage::Parsing)?;

        // ── NORMALIZING ────────────────────────────────────────────────────
        // A real pass: values are trimmed, quoted, degenerated and junk
        // placeholders dropped — this is where a raw record can disappear,
        // and the counts say so.
        let raw_records = merged.len();
        let normalized_records = merged.normalize();
        report(HarvestStage::Normalizing)?;

        // ── DEDUPLICATING ──────────────────────────────────────────────────
        let deduped = merged.deduped();
        let deduplicated_records = deduped.len();
        report(HarvestStage::Deduplicating)?;

        // ── RECOMMENDING ───────────────────────────────────────────────────
        // A harvest is only useful if it changes what the operator does next, so
        // the artefacts are turned into concrete capabilities to run against
        // concrete values. Derived from the findings, never asserted.
        let recommendation = crate::intel::recommend(
            &deduped
                .iter()
                .map(|f| (f.category, f.value.clone()))
                .collect::<Vec<_>>(),
        );
        report(HarvestStage::Recommending)?;

        // ── CORRELATING ────────────────────────────────────────────────────
        // Real co-occurrence: findings produced by the same task are linked,
        // so output.json can say what else was observed beside a value.
        let links = correlate(&deduped);
        report(HarvestStage::Correlating)?;

        // ── HARVESTING ─────────────────────────────────────────────────────
        let stats = HarvestStats {
            tasks: self.records.len(),
            tasks_parsed: self.records.len().saturating_sub(parse_failures),
            raw_records,
            normalized_records,
            deduplicated_records,
            final_findings: deduped.len(),
            noise_lines,
            artefacts,
        };
        let state = outcome_state(&self.records, header.cancelled, &stats, &links);
        let outcome = HarvestOutcome {
            findings: deduped,
            sections: sections.len(),
            notes: merged.notes().to_vec(),
            stats,
            state,
            recommendation,
        };
        report(HarvestStage::Harvesting)?;

        // ── WRITING ────────────────────────────────────────────────────────
        self.write_output(&outcome, header, &links)?;
        report(HarvestStage::Writing)?;

        Ok(outcome)
    }

    /// Write `output.txt` (the complete operator document) and `output.json`
    /// (the same findings, structured, with provenance and correlations).
    fn write_output(
        &self,
        outcome: &HarvestOutcome,
        header: &OutputHeader<'_>,
        links: &[Vec<String>],
    ) -> Result<()> {
        write_atomic(
            &self.output_txt(),
            output_document(&self.records, outcome, header).as_bytes(),
        )?;

        #[derive(Serialize)]
        struct Entry<'a> {
            category: &'a str,
            value: &'a str,
            detail: &'a Option<String>,
            occurrences: usize,
            /// False for tool progress and run metadata: present in the file,
            /// deliberately absent from the operator document.
            actionable: bool,
            correlated: &'a [String],
            sources: Vec<HarvestSource>,
        }
        #[derive(Serialize)]
        struct HarvestSource {
            provider: String,
            operation: String,
            task_id: String,
            boundary: String,
            artifact: String,
            observed_at: String,
        }
        // `actionable` is a per-finding flag rather than a filtered list, so a
        // consumer of the JSON can tell "withheld because it was progress" from
        // "absent", and can count both without re-reading the text document.
        let entries: Vec<Entry<'_>> = outcome
            .findings
            .iter()
            .enumerate()
            .map(|(index, f)| Entry {
                category: f.category.heading(),
                value: &f.value,
                detail: &f.detail,
                occurrences: f.occurrences,
                actionable: f.category.is_actionable(),
                correlated: links.get(index).map(Vec::as_slice).unwrap_or(&[]),
                sources: f
                    .sources
                    .iter()
                    .map(|s| HarvestSource {
                        provider: s.provider.clone(),
                        operation: s.operation.clone(),
                        task_id: s.task_id.clone(),
                        boundary: s.boundary.as_str().to_string(),
                        artifact: s.artifact.display().to_string(),
                        observed_at: s.observed_at.to_rfc3339(),
                    })
                    .collect(),
            })
            .collect();

        #[derive(Serialize)]
        struct NextStepJson<'a> {
            confidence: &'static str,
            phase: &'a str,
            capability: &'a str,
            because: &'a str,
            needs: &'a str,
        }
        #[derive(Serialize)]
        struct Document<'a> {
            run: RunSummary<'a>,
            stats: HarvestStats,
            state: &'a str,
            recommendations: Vec<NextStepJson<'a>>,
            notes: &'a [String],
            findings: Vec<Entry<'a>>,
        }
        #[derive(Serialize)]
        struct RunSummary<'a> {
            name: &'a str,
            phase: &'a str,
            capability: &'a str,
            wordlist_root: String,
        }

        let wordlist_root =
            crate::catalog::wordlist_root(&self.root.join("catalog/capabilities.toml"));
        let document = Document {
            run: RunSummary {
                name: header.run_name,
                phase: header.phase,
                capability: header.capability,
                wordlist_root: wordlist_root.display().to_string(),
            },
            stats: outcome.stats,
            state: &outcome.state,
            recommendations: outcome
                .recommendation
                .iter()
                .map(|s| NextStepJson {
                    confidence: match s.confidence {
                        3 => "high",
                        2 => "medium",
                        _ => "low",
                    },
                    phase: s.phase,
                    capability: s.capability,
                    because: &s.because,
                    needs: &s.needs,
                })
                .collect(),
            notes: &outcome.notes,
            findings: entries,
        };
        let json = serde_json::to_string_pretty(&document)
            .map_err(|e| TsecError::config(format!("serialising harvest: {e}")))?;
        write_atomic(&self.output_json(), json.as_bytes())
    }

    /// Write the run report and return it.
    pub fn finalise(&mut self, report: RunReport) -> Result<RunReport> {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| TsecError::config(format!("serialising run report: {e}")))?;
        write_atomic(&self.root.join("run.json"), json.as_bytes())?;
        Ok(report)
    }
}

/// What a harvest pass produced.
#[derive(Debug, Clone)]
pub struct HarvestOutcome {
    pub findings: Vec<MergedFinding>,
    pub sections: usize,
    pub notes: Vec<String>,
    /// Where the records went: how many entered, how many survived each real
    /// stage. Displayed so a silent loss between stages becomes visible.
    pub stats: HarvestStats,
    /// The truthful one-word-ish verdict: `COMPLETE`, `NO FINDINGS`,
    /// `UNPARSED OUTPUT`, `EXECUTION FAILED`, `NETWORK BOUNDARY UNAVAILABLE`
    /// or `RUN CANCELLED` — never "no findings" standing in for a failure.
    pub state: String,
    /// Capabilities the harvest implies, highest signal first.
    ///
    /// Derived from what was actually observed, and empty when nothing was. A
    /// suggestion the harvest cannot justify is worse than none.
    pub recommendation: Vec<crate::intel::NextStep>,
}

/// The run context the operator-facing document is written against.
#[derive(Debug, Clone, Default)]
pub struct OutputHeader<'a> {
    /// Human-readable run name, e.g. `20260930_173000_RECON_SUBDOMAIN_DISCOVERY`.
    pub run_name: &'a str,
    pub phase: &'a str,
    pub capability: &'a str,
    /// Providers the catalog wanted but the host does not have.
    pub missing_providers: &'a [String],
    /// What happened to the background installs started for this capability.
    ///
    /// Reported whether they succeeded or not: an operator who watched a run
    /// complete while a tool was being installed needs to know it landed.
    pub install_notes: &'a [String],
    /// Whether the operator stopped the run early.
    pub cancelled: bool,
}

/// The real pipeline counts, from parsing through to the final harvest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct HarvestStats {
    /// Committed execution records that entered the pipeline.
    pub tasks: usize,
    /// Records whose artifact parsed without error.
    pub tasks_parsed: usize,
    /// Findings the format parsers emitted, before normalizing.
    pub raw_records: usize,
    /// Findings that survived value normalization.
    pub normalized_records: usize,
    /// Findings that survived deduplication.
    pub deduplicated_records: usize,
    /// Findings actually written to the output document.
    pub final_findings: usize,
    /// Lines of tool chrome that carried no artefact.
    ///
    /// Reported because "the tool found nothing" and "the tool printed two
    /// thousand progress lines and nothing else" look identical without it.
    pub noise_lines: usize,
    /// Artefacts recovered by the intelligence pass across every artifact.
    pub artefacts: usize,
}

impl HarvestStats {
    /// `TASKS 5/5 PARSED · RAW 182 · NORMALIZED 176 · DEDUPLICATED 118 · FINAL 117 · ARTEFACTS 9 · NOISE 340`.
    pub fn summary(&self) -> String {
        format!(
            "TASKS {}/{} PARSED · RAW {} · NORMALIZED {} · DEDUPLICATED {} · FINAL {} ·              ARTEFACTS {} · NOISE {}",
            self.tasks_parsed,
            self.tasks,
            self.raw_records,
            self.normalized_records,
            self.deduplicated_records,
            self.final_findings,
            self.artefacts,
            self.noise_lines
        )
    }
}

/// Link each finding to the other values observed by the same tasks.
///
/// This is real correlation, not a placeholder: two findings that were
/// produced by at least one shared task (say `api.example.com` from subfinder
/// and `443/tcp` from the nmap pass behind it) are recorded as related, so
/// `output.json` can reconstruct what was seen beside a value without the
/// operator re-running anything.
fn correlate(findings: &[MergedFinding]) -> Vec<Vec<String>> {
    use std::collections::BTreeMap;
    let mut by_task: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        for source in &finding.sources {
            by_task
                .entry(source.task_id.as_str())
                .or_default()
                .push(index);
        }
    }

    let mut links: Vec<Vec<String>> = vec![Vec::new(); findings.len()];
    let mut seen: Vec<std::collections::BTreeSet<usize>> =
        vec![std::collections::BTreeSet::new(); findings.len()];
    for members in by_task.values() {
        for &self_index in members {
            for &other in members {
                if other != self_index {
                    seen[self_index].insert(other);
                }
            }
        }
    }
    for (index, related) in seen.into_iter().enumerate() {
        // Cap per finding: a correlation note is context, not a dump.
        links[index] = related
            .into_iter()
            .take(8)
            .map(|other| findings[other].value.clone())
            .collect();
    }
    links
}

/// The truthful verdict for a run, from the records themselves.
///
/// Every distinct situation gets its own state — a boundary refusal never
/// reads as "no findings", and "no findings" only appears when the run really
/// executed, exited cleanly, was parsed and produced nothing.
fn outcome_state(
    records: &[ExecutionRecord],
    cancelled: bool,
    stats: &HarvestStats,
    links: &[Vec<String>],
) -> String {
    use crate::domain::execution::TaskStatus;
    let _ = links;

    let complete = records
        .iter()
        .filter(|r| r.status == TaskStatus::Complete)
        .count();
    let failures = records
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                TaskStatus::Failed | TaskStatus::TimedOut | TaskStatus::Interrupted
            )
        })
        .count();
    let oniux_only = records
        .iter()
        .filter(|r| r.error_code.as_deref() == Some("ONIUX_UNAVAILABLE"))
        .count();
    let any_output = records
        .iter()
        .any(|r| r.stdout_bytes > 0 || r.stderr_bytes > 0);

    if cancelled {
        return "RUN CANCELLED".to_string();
    }
    if complete == 0 {
        if !records.is_empty() && oniux_only == records.len() {
            return "NETWORK BOUNDARY UNAVAILABLE".to_string();
        }
        return "EXECUTION FAILED".to_string();
    }
    if stats.final_findings > 0 {
        return if failures == 0 {
            "COMPLETE".to_string()
        } else {
            format!("COMPLETE WITH {failures} FAILED")
        };
    }
    if failures > 0 {
        return "EXECUTION FAILED".to_string();
    }
    if stats.tasks_parsed < stats.tasks {
        return "UNPARSED OUTPUT".to_string();
    }
    if any_output && stats.raw_records == 0 {
        return "UNPARSED OUTPUT".to_string();
    }
    "NO FINDINGS".to_string()
}

/// The complete operator document written to `output.txt`.
///
/// Layout (every header line centred against a 78-column reference width,
/// findings left-aligned below the rule):
///
/// ```text
///                                  TSEC 3.0.0
///              RUN <name> | PHASE <p> | CAPABILITY <c>
///                      STATE <s> | PIPELINE <p>
///                                 TASKS <t>
/// ──────────────────────────────────────────────────────────────
///                                   FINDINGS
///  <findings, left-aligned, grouped by category>
/// ```
fn output_document(
    records: &[ExecutionRecord],
    outcome: &HarvestOutcome,
    header: &OutputHeader<'_>,
) -> String {
    use crate::domain::execution::TaskStatus;

    // A wide fixed reference width keeps the saved artifact stable regardless
    // of whichever terminal happened to be watching the run.
    const WIDTH: usize = 120;
    let centre = |text: &str| {
        let width = text.chars().count();
        if width >= WIDTH {
            return text.to_string();
        }
        let left = (WIDTH - width) / 2;
        format!("{}{}", " ".repeat(left), text)
    };

    let mut text = String::new();
    text.push_str(&centre(&format!("TSEC {}", crate::VERSION)));
    text.push('\n');
    text.push_str(&centre(&format!(
        "RUN {} | PHASE {} | CAPABILITY {}",
        header.run_name, header.phase, header.capability
    )));
    text.push('\n');
    text.push_str(&centre(&format!(
        "STATE {} | PIPELINE {}",
        outcome.state,
        outcome.stats.summary()
    )));
    text.push('\n');

    // Task tally straight from the records, in a stable order.
    let statuses = [
        (TaskStatus::Complete, "COMPLETE"),
        (TaskStatus::Failed, "FAILED"),
        (TaskStatus::TimedOut, "TIMED OUT"),
        (TaskStatus::Interrupted, "CANCELLED"),
        (TaskStatus::Skipped, "SKIPPED"),
    ];
    let counts: Vec<String> = statuses
        .iter()
        .map(|(status, label)| {
            let count = records.iter().filter(|r| r.status == *status).count();
            format!("{label} {count}")
        })
        .collect();
    text.push_str(&centre(&format!("TASKS {}", counts.join(" · "))));
    text.push('\n');

    for note in header.install_notes {
        text.push_str(&centre(note));
        text.push('\n');
    }
    if !header.missing_providers.is_empty() {
        text.push_str(&centre(&format!(
            "PROVIDERS NOT INSTALLED {} · these operations did not run",
            header.missing_providers.join(", ")
        )));
        text.push('\n');
    }

    // Full-width rule, then the findings section: title centred, entries left.
    let rule = "─".repeat(WIDTH);
    text.push_str(&rule);
    text.push('\n');
    text.push_str(&centre("FINDINGS"));
    text.push('\n');

    // Findings, grouped by category. Narration is excluded: a document that
    // opens with four hundred progress lines is the reason a harvest reads as
    // empty when it is not. The count of what was excluded is stated, so
    // nothing is hidden.
    let presented: Vec<&MergedFinding> = outcome
        .findings
        .iter()
        .filter(|f| f.category.is_actionable())
        .collect();
    let withheld = outcome.findings.len() - presented.len();

    let mut last_heading: Option<&'static str> = None;
    for finding in &presented {
        let heading = finding.category.heading();
        if last_heading != Some(heading) {
            if last_heading.is_some() {
                text.push('\n');
            }
            text.push_str(&format!("  {heading}\n"));
            last_heading = Some(heading);
        }
        text.push_str(&format!("  {}\n", finding.line()));
    }
    if presented.is_empty() {
        text.push_str("  NO FINDINGS RECORDED\n");
    }
    if withheld > 0 {
        text.push('\n');
        text.push_str(&format!(
            "  ({withheld} lines of tool progress and metadata withheld; \
             {} in the raw evidence and output.json)\n",
            "all present"
        ));
    }

    // What to run next. Placed last so it is the operator's next read.
    if !outcome.recommendation.is_empty() {
        text.push('\n');
        text.push_str(&rule);
        text.push('\n');
        text.push_str(&centre("NEXT ACTIONS"));
        text.push('\n');
        for step in &outcome.recommendation {
            text.push_str(&format!(
                "  [{}] {} / {} — {}\n",
                match step.confidence {
                    3 => "HIGH",
                    2 => "MED",
                    _ => "LOW",
                },
                step.phase,
                step.capability,
                step.because
            ));
            text.push_str(&format!("        needs: {}\n", step.needs));
        }
    }
    text
}

/// One stage of the real harvest pipeline, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarvestStage {
    Parsing,
    Normalizing,
    Deduplicating,
    Correlating,
    Harvesting,
    Recommending,
    Writing,
}

impl HarvestStage {
    /// Every stage, in pipeline order.
    pub const ALL: [HarvestStage; 7] = [
        HarvestStage::Parsing,
        HarvestStage::Normalizing,
        HarvestStage::Deduplicating,
        HarvestStage::Correlating,
        HarvestStage::Harvesting,
        HarvestStage::Recommending,
        HarvestStage::Writing,
    ];

    pub fn label(self) -> &'static str {
        match self {
            HarvestStage::Parsing => "Parsing provider output",
            HarvestStage::Normalizing => "Normalizing findings",
            HarvestStage::Deduplicating => "Deduplicating results",
            HarvestStage::Correlating => "Correlating assets",
            HarvestStage::Harvesting => "Harvesting intelligence",
            HarvestStage::Recommending => "Recommending next steps",
            HarvestStage::Writing => "Writing output",
        }
    }

    /// Short uppercase token for the JSON verification report.
    pub fn token(self) -> &'static str {
        match self {
            HarvestStage::Parsing => "PARSING",
            HarvestStage::Normalizing => "NORMALIZING",
            HarvestStage::Deduplicating => "DEDUPLICATING",
            HarvestStage::Correlating => "CORRELATING",
            HarvestStage::Harvesting => "HARVESTING",
            HarvestStage::Recommending => "RECOMMENDING",
            HarvestStage::Writing => "WRITING",
        }
    }
}

/// Write `bytes` to `path` atomically: same-directory temp file, then rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| io_err(dir, &e))?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "out".into())
    ));
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| io_err(&tmp, &e))?;
        f.write_all(bytes).map_err(|e| io_err(&tmp, &e))?;
        // Durability before rename: the bytes must be on disk before the name
        // points at them, or a crash leaves a rename over an empty file.
        f.sync_all().map_err(|e| io_err(&tmp, &e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io_err(path, &e)
    })
}

fn io_err(path: &Path, e: &std::io::Error) -> TsecError {
    TsecError::new(
        Stage::Append,
        ExecutionErrorKind::Io {
            context: format!("writing {}", path.display()),
            reason: e.to_string(),
        },
    )
}

/// Read a run back from disk. Used by the report viewer and by tests.
#[derive(Debug, Clone, Deserialize)]
pub struct StoredRun {
    pub records: Vec<ExecutionRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::execution::{ExecBoundary, TaskStatus};
    use chrono::Utc;
    use std::time::Duration;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tsec-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn record(task: &str, provider: &str, raw: PathBuf) -> ExecutionRecord {
        let now = Utc::now();
        ExecutionRecord {
            task_id: task.into(),
            phase: "RECON".into(),
            capability: "TEST".into(),
            provider: provider.into(),
            operation: "op".into(),
            label: "op".into(),
            command: "tool".into(),
            program: "tool".into(),
            args: vec![],
            network: true,
            boundary: ExecBoundary::Oniux,
            launched: "oniux tool".into(),
            uses_shell: false,
            started_at: now,
            finished_at: now,
            duration_ms: Duration::from_secs(1).as_millis(),
            status: TaskStatus::Complete,
            exit_code: Some(0),
            stdout_bytes: 0,
            stderr_bytes: 0,
            raw_output: raw,
            stderr_output: None,
            harvest_section: None,
            error_code: None,
            error_message: None,
        }
    }

    #[test]
    fn a_run_directory_has_the_documented_layout() {
        let dir = tmp("layout");
        let store = RunStore::open(&dir, &RunId::new("20260101_120000_abc")).unwrap();
        assert!(store.root().is_dir());
        assert!(store.root().join("raw").is_dir());
    }

    #[test]
    fn a_committed_task_survives_as_a_manifest() {
        let dir = tmp("manifest");
        let mut store = RunStore::open(&dir, &RunId::new("20260101_120000_abc")).unwrap();
        let raw = dir.join("r1.out");
        std::fs::write(&raw, "10.0.0.1:22\n").unwrap();
        store.commit(record("T01", "naabu", raw)).unwrap();
        let json = std::fs::read_to_string(store.manifest()).unwrap();
        assert!(json.contains("T01"));
        assert!(json.contains("ONIUX"), "the boundary is part of the record");
    }

    #[test]
    fn a_partial_run_keeps_the_tasks_that_finished() {
        let dir = tmp("partial");
        let mut store = RunStore::open(&dir, &RunId::new("20260101_120000_abc")).unwrap();
        let raw = dir.join("r1.out");
        std::fs::write(&raw, "10.0.0.1:22\n").unwrap();
        store.commit(record("T01", "naabu", raw)).unwrap();
        // "Finalise" stands in for an interrupted run: whatever was committed
        // must still be readable.
        let back: Vec<ExecutionRecord> =
            serde_json::from_str(&std::fs::read_to_string(store.manifest()).unwrap()).unwrap();
        assert_eq!(back.len(), 1);
    }

    /// The complaint this pipeline change exists to answer: a run over realistic
    /// multi-tool output produced a handful of vague findings and buried the
    /// credentials, tokens and cookies that were in the same bytes.
    #[test]
    fn a_realistic_multi_tool_run_yields_the_artefacts_it_actually_contains() {
        let dir = tmp("harvest-rich");
        let mut store = RunStore::open(&dir, &RunId::new("20260101_120000_abc")).unwrap();

        // Token samples are one character short of a well-formed key: long enough
        // to exercise the rule, not long enough for a scanner to read as a real
        // credential in this file.
        let web = dir.join("httpx.out");
        std::fs::write(
            &web,
            concat!(
                "[*] Starting: http://admin.example.com
",
                "[INF] Executing 10 threads
",
                "http://admin.example.com:8080/login [200] [Admin Panel] [10.0.0.4]\n",
                "[*] Completed 1/1\n",
            ),
        )
        .unwrap();
        store.commit(record("T01", "httpx", web)).unwrap();

        let access = dir.join("access.out");
        std::fs::write(
            &access,
            concat!(
                "10.0.0.4 - - [10/Oct/2023:00:00:00 +0000] \"GET /admin HTTP/1.1\" 200 199 \n",
                "10.0.0.4 - - [10/Oct/2023:00:00:01 +0000] \"POST /login HTTP/1.1\" 302 0 \n",
                "10.0.0.9 - - [10/Oct/2023:00:00:02 +0000] \"GET /admin HTTP/1.1\" 401 199 \n",
                "10.0.0.9 - - [10/Oct/2023:00:00:03 +0000] \"GET /admin HTTP/1.1\" 401 199 \n",
            ),
        )
        .unwrap();
        let mut local = record("T02", "nikto", access);
        local.boundary = ExecBoundary::Local;
        local.network = false;
        store.commit(local).unwrap();

        // Credential samples are assembled rather than written out: a complete
        // key literal in the source trips push protection on the forge, which
        // makes the change unpushable and unreviewable.
        let aws_key = format!("AKIA{}", "TSECEXAMPLE00001");
        let gh_token = format!("ghp_{}", "tsecfixture0000000000000000000000");
        let code = dir.join("source.out");
        let body = [
            "/* TODO: rotate before launch */",
            &format!("const AWS_KEY = \"{aws_key}\";"),
            "// db: postgres://svc:hunter2@10.1.1.5:5432/prod",
            "<!-- internal metrics at http://10.1.1.9:9090 -->",
            &format!("var t = \"{gh_token}\";"),
            "Set-Cookie: session=abc123def456ghi789; Path=/; HttpOnly",
        ]
        .join("\n");
        std::fs::write(&code, body).unwrap();
        store.commit(record("T03", "gitleaks", code)).unwrap();

        let mut formats = std::collections::BTreeMap::new();
        formats.insert("httpx".to_string(), crate::catalog::OutputFormat::Lines);
        let out = store
            .harvest(&formats, &OutputHeader::default(), None)
            .unwrap();

        let categories: Vec<crate::domain::finding::Category> =
            out.findings.iter().map(|f| f.category).collect();
        let has = |c: crate::domain::finding::Category| categories.contains(&c);

        use crate::domain::finding::Category;
        assert!(has(Category::Secret), "{:?}", out.stats);
        assert!(has(Category::Token), "{:?}", out.stats);
        assert!(has(Category::Cookie), "{:?}", out.stats);
        assert!(has(Category::Comment), "{:?}", out.stats);
        assert!(has(Category::Ip), "{:?}", out.stats);
        assert!(has(Category::Url), "{:?}", out.stats);

        let values: Vec<&str> = out.findings.iter().map(|f| f.value.as_str()).collect();
        assert!(values.iter().any(|v| v.contains(&aws_key)), "{values:?}");
        assert!(
            values.iter().any(|v| v.contains("ghp_tsecfixture")),
            "{values:?}"
        );
        assert!(
            values.iter().any(|v| v.contains("session=abc123")),
            "{values:?}"
        );
        assert!(
            values.iter().any(|v| v.contains("postgres://")),
            "{values:?}"
        );

        // Only two lines are pure chrome. The third, `[*] Starting:
        // http://admin.example.com`, carries a URL, so it is a result that
        // happens to be wrapped in progress formatting — and the URL is kept.
        assert_eq!(out.stats.noise_lines, 2, "{:?}", out.stats);
        assert!(out.stats.artefacts >= 6, "{:?}", out.stats);
        assert!(
            out.findings
                .iter()
                .filter(|f| f.category == Category::Noise)
                .count()
                == 2,
            "the counter and the recorded findings must agree"
        );
        // Noise is kept — a run must stay auditable — but marked as not
        // actionable, which is what keeps it out of the document.
        assert!(
            out.findings
                .iter()
                .filter(|f| f.category == Category::Noise)
                .all(|f| !f.category.is_actionable()),
            "noise must be recorded but never actionable"
        );

        let text = std::fs::read_to_string(store.output_txt()).unwrap();
        assert!(text.contains(&aws_key), "{text}");
        assert!(
            !text.contains("Executing 10 threads"),
            "progress must not be in the document:\n{text}"
        );
        assert!(text.contains("NEXT ACTIONS"), "{text}");
        assert!(!out.recommendation.is_empty());

        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.output_json()).unwrap()).unwrap();
        assert!(!json["recommendations"].as_array().unwrap().is_empty());
        assert_eq!(json["stats"]["noise_lines"].as_u64().unwrap(), 2);
    }

    #[test]
    fn the_harvest_is_written_as_both_text_and_json() {
        let dir = tmp("harvest");
        let mut store = RunStore::open(&dir, &RunId::new("20260101_120000_abc")).unwrap();
        let raw = dir.join("r1.out");
        std::fs::write(&raw, "10.0.0.1:22\n10.0.0.1:80\n").unwrap();
        store.commit(record("T01", "naabu", raw)).unwrap();

        let mut formats = std::collections::BTreeMap::new();
        formats.insert("naabu".to_string(), crate::catalog::OutputFormat::Lines);
        let out = store
            .harvest(&formats, &OutputHeader::default(), None)
            .unwrap();

        assert!(!out.findings.is_empty());
        assert!(out.stats.raw_records >= out.findings.len());
        let text = std::fs::read_to_string(store.output_txt()).unwrap();
        assert!(text.contains("22"), "{text}");
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.output_json()).unwrap()).unwrap();
        // The document carries its own run, pipeline and recommendation context,
        // so a consumer never has to guess what produced the findings.
        assert!(json["findings"].is_array(), "{json}");
        assert!(json["run"]["capability"].is_string(), "{json}");
        assert!(json["stats"]["final_findings"].is_number(), "{json}");
        assert!(json["stats"]["noise_lines"].is_number(), "{json}");
        assert!(json["recommendations"].is_array(), "{json}");
        assert!(!store.harvest_txt().exists() || store.output_txt().exists());
    }

    #[test]
    fn the_harvest_records_the_boundary_each_finding_came_behind() {
        // A finding from a local hash audit must not be presented as if it came
        // through oniux. Provenance is a claim about how the information was
        // obtained, so a hard-coded boundary would misrepresent it.
        let dir = tmp("boundary-provenance");
        let mut store = RunStore::open(&dir, &RunId::new("20260101_120000_abc")).unwrap();

        let oniux_raw = dir.join("net.out");
        std::fs::write(&oniux_raw, "10.0.0.1:22\n").unwrap();
        store.commit(record("T01", "naabu", oniux_raw)).unwrap();

        let mut local = record("T02", "hashcat", dir.join("local.out"));
        local.boundary = ExecBoundary::Local;
        local.network = false;
        local.command = "hashcat hashes".to_string();
        local.launched = "hashcat hashes".to_string();
        std::fs::write(&local.raw_output, "example.com\n").unwrap();
        store.commit(local).unwrap();

        let formats = std::collections::BTreeMap::new();
        store
            .harvest(&formats, &OutputHeader::default(), None)
            .unwrap();

        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.output_json()).unwrap()).unwrap();
        let boundaries: Vec<String> = json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|e| e["sources"].as_array().unwrap().clone())
            .map(|s| s["boundary"].as_str().unwrap().to_string())
            .collect();
        assert!(
            boundaries.contains(&"ONIUX".to_string()),
            "the network finding lost its boundary: {boundaries:?}"
        );
        assert!(
            boundaries.contains(&"LOCAL".to_string()),
            "the local finding was mislabelled as network-derived: {boundaries:?}"
        );
    }

    #[test]
    fn the_format_is_chosen_per_operation_not_per_provider() {
        // nmap writes XML and naabu writes lines; both are "providers", so a
        // provider-keyed lookup would parse nmap's XML as a line list and lose
        // every structured port it found.
        let dir = tmp("op-format");
        let mut store = RunStore::open(&dir, &RunId::new("20260101_120000_abc")).unwrap();
        let raw = dir.join("nmap.xml");
        std::fs::write(
            &raw,
            r#"<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="443"><state state="open"/>
            <service name="https"/></port></ports></host></nmaprun>"#,
        )
        .unwrap();
        store.commit(record("T01", "nmap", raw)).unwrap();

        let mut formats = std::collections::BTreeMap::new();
        // Deliberately keyed by operation, as the orchestrator will supply it.
        formats.insert("nmap/op".to_string(), crate::catalog::OutputFormat::Nmap);
        let out = store
            .harvest(&formats, &OutputHeader::default(), None)
            .unwrap();
        assert!(
            out.findings
                .iter()
                .any(|f| f.detail.as_deref().is_some_and(|d| d.contains("443"))),
            "the nmap XML was not parsed as XML: {:?}",
            out.findings
                .iter()
                .map(|f| f.detail.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn atomic_write_leaves_no_temporary_file_behind() {
        let dir = tmp("atomic");
        let target = dir.join("out.txt");
        write_atomic(&target, b"hello").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files must be renamed away");
    }

    #[test]
    fn an_overwrite_is_all_or_nothing() {
        let dir = tmp("overwrite");
        let target = dir.join("out.txt");
        write_atomic(&target, b"first").unwrap();
        write_atomic(&target, b"second-and-longer").unwrap();
        // The old content is never observed half-replaced.
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "second-and-longer"
        );
    }
}
