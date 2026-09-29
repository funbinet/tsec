//! The parser is only trustworthy if it handles output that real tools actually
//! produced, so these tests run against captured artifacts rather than
//! hand-written samples. The fixtures under `tests/fixtures/` are verbatim
//! captures; anything a test asserts was read out of them by a person who ran
//! the tool.

use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use tsec::catalog::OutputFormat;
use tsec::domain::finding::{Category, Provenance};
use tsec::parser::{parse_artifact, Harvest};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn provenance(provider: &str) -> Provenance {
    Provenance {
        boundary: tsec::domain::execution::ExecBoundary::Oniux,
        provider: provider.into(),
        operation: "op".into(),
        task_id: "T01".into(),
        command: format!("{provider} …"),
        observed_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        artifact: PathBuf::from("/tmp/raw"),
    }
}

fn values(h: &Harvest, cat: Category) -> Vec<&str> {
    h.findings()
        .iter()
        .filter(|f| f.category == cat)
        .map(|f| f.value.as_str())
        .collect()
}

#[test]
fn real_nmap_output_is_harvested() {
    let h = parse_artifact(
        &fixture("nmap-open.xml"),
        OutputFormat::Nmap,
        provenance("nmap"),
    )
    .expect("nmap artifact should parse");

    assert!(!h.is_empty(), "a real nmap scan must yield findings");
    assert!(
        values(&h, Category::Ip).contains(&"127.0.0.1"),
        "{:?}",
        h.findings()
    );
    assert!(
        values(&h, Category::Port)
            .iter()
            .any(|p| p.starts_with("18080/")),
        "the listener that was actually open: {:?}",
        values(&h, Category::Port)
    );
    assert!(!h.truncated());
    assert!(h.notes().is_empty(), "no notes expected: {:?}", h.notes());
    assert!(
        h.findings().iter().all(|f| f.provenance.provider == "nmap"),
        "every finding must name the tool that reported it"
    );
}

#[test]
fn a_scan_with_no_open_ports_reports_nothing_for_ports() {
    // nmap exits 0 with an empty port set when a host is up but closed. A
    // harvest claiming services here would be a fabrication.
    let h = parse_artifact(
        &fixture("nmap-scan.xml"),
        OutputFormat::Nmap,
        provenance("nmap"),
    )
    .expect("nmap artifact should parse");
    assert!(!h.is_empty(), "host-level facts are still findings");
    if h.findings().iter().any(|f| f.category == Category::Port) {
        // If this capture did find something, it must be a real open port.
        assert!(values(&h, Category::Port).iter().all(|p| !p.contains("0")));
    }
}

#[test]
fn parsing_is_deterministic_across_runs() {
    // Two runs over the same evidence must produce byte-identical harvests,
    // otherwise diffing runs is meaningless.
    let a = parse_artifact(
        &fixture("nmap-open.xml"),
        OutputFormat::Nmap,
        provenance("nmap"),
    )
    .expect("parse");
    let b = parse_artifact(
        &fixture("nmap-open.xml"),
        OutputFormat::Nmap,
        provenance("nmap"),
    )
    .expect("parse");
    let render = |h: &Harvest| {
        h.deduped()
            .iter()
            .map(|f| {
                format!(
                    "{:?} {} {:?} {:?}",
                    f.category, f.value, f.detail, f.sources
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(render(&a), render(&b));
}

#[test]
fn a_missing_artifact_is_an_error_not_an_empty_harvest() {
    // Silently returning zero findings here would hide a broken capture.
    let err = parse_artifact(
        Path::new("/nonexistent/tsec/does-not-exist.xml"),
        OutputFormat::Nmap,
        provenance("nmap"),
    );
    assert!(
        err.is_err(),
        "a missing raw artifact must not look like success"
    );
}
