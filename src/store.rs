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
//!   harvest.txt          the consolidated, deduplicated, readable harvest
//!   harvest.json         the same findings, structured, for correlation
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
    pub fn harvest_txt(&self) -> PathBuf {
        self.root.join("harvest.txt")
    }
    pub fn harvest_json(&self) -> PathBuf {
        self.root.join("harvest.json")
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
    /// Tasks whose output could not be parsed are recorded as such rather than
    /// omitted, so the harvest is a faithful account of what was run — not just
    /// of what happened to be machine-readable.
    /// `formats` is keyed by operation name (`provider/operation`), falling back
    /// to the provider, then to keeping the raw bytes. Operation is the right
    /// level: one provider can emit different formats per operation, and parsing
    /// nmap's XML as if it were naabu's line list would silently lose the
    /// structured ports.
    pub fn harvest(
        &self,
        formats: &std::collections::BTreeMap<String, crate::catalog::OutputFormat>,
    ) -> Result<HarvestOutcome> {
        let mut merged = crate::parser::Harvest::default();
        let mut sections = Vec::new();

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
                    sections.push(crate::domain::finding::Finding {
                        category: crate::domain::finding::Category::Evidence,
                        value: format!("{}: {} findings", record.provider, h.len()),
                        detail: None,
                        provenance: provenance.clone(),
                        occurrences: 1,
                    });
                    merged.absorb(h);
                }
                Err(e) => sections.push(crate::domain::finding::Finding {
                    category: crate::domain::finding::Category::Evidence,
                    value: format!("{}: unparsed ({})", record.provider, e.kind.code()),
                    detail: Some(e.reason()),
                    provenance: provenance.clone(),
                    occurrences: 1,
                }),
            }
        }

        let deduped = merged.deduped();
        self.write_harvest(&deduped)?;
        Ok(HarvestOutcome {
            findings: deduped,
            sections: sections.len(),
            notes: merged.notes().to_vec(),
        })
    }

    fn write_harvest(&self, findings: &[MergedFinding]) -> Result<()> {
        let mut text = String::new();
        for f in findings {
            text.push_str(&f.line());
            text.push('\n');
        }
        write_atomic(&self.harvest_txt(), text.as_bytes())?;

        #[derive(Serialize)]
        struct Entry<'a> {
            category: &'a str,
            value: &'a str,
            detail: &'a Option<String>,
            occurrences: usize,
            sources: Vec<HarvestSource>,
        }
        #[derive(Serialize)]
        struct HarvestSource {
            provider: String,
            operation: String,
            task_id: String,
            boundary: String,
        }
        let entries: Vec<Entry<'_>> = findings
            .iter()
            .map(|f| Entry {
                category: f.category.heading(),
                value: &f.value,
                detail: &f.detail,
                occurrences: f.occurrences,
                sources: f
                    .sources
                    .iter()
                    .map(|s| HarvestSource {
                        provider: s.provider.clone(),
                        operation: s.operation.clone(),
                        task_id: s.task_id.clone(),
                        boundary: s.boundary.as_str().to_string(),
                    })
                    .collect(),
            })
            .collect();
        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| TsecError::config(format!("serialising harvest: {e}")))?;
        write_atomic(&self.harvest_json(), json.as_bytes())
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

    #[test]
    fn the_harvest_is_written_as_both_text_and_json() {
        let dir = tmp("harvest");
        let mut store = RunStore::open(&dir, &RunId::new("20260101_120000_abc")).unwrap();
        let raw = dir.join("r1.out");
        std::fs::write(&raw, "10.0.0.1:22\n10.0.0.1:80\n").unwrap();
        store.commit(record("T01", "naabu", raw)).unwrap();

        let mut formats = std::collections::BTreeMap::new();
        formats.insert("naabu".to_string(), crate::catalog::OutputFormat::Lines);
        let out = store.harvest(&formats).unwrap();

        assert!(!out.findings.is_empty());
        let text = std::fs::read_to_string(store.harvest_txt()).unwrap();
        assert!(text.contains("22"), "{text}");
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.harvest_json()).unwrap()).unwrap();
        assert!(json.is_array());
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
        store.harvest(&formats).unwrap();

        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.harvest_json()).unwrap()).unwrap();
        let boundaries: Vec<String> = json
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
        let out = store.harvest(&formats).unwrap();
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
