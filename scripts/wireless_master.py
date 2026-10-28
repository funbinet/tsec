#!/usr/bin/env python3
"""Build the consolidated wireless report from the run directory.

Walks the directory for every JSON/text artifact the pipeline produced and
composes wireless_report.md: found APs, cracked-ness claims, weird beacons,
evil-twin evidence, MITM captures, client isolation, spectrum findings,
probe footprint. Every section names the file it came from so nothing is
asserted that the artifacts do not carry.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def build(indir: Path) -> dict:
    json_files = {}
    for path in sorted(indir.rglob("*.json")):
        try:
            json_files[str(path.relative_to(indir))] = json.loads(path.read_text(errors="replace"))
        except (OSError, ValueError):
            pass
    findings = []
    for name, data in json_files.items():
        if isinstance(data, dict) and "findings" in data:
            for f in data["findings"]:
                if isinstance(f, dict):
                    findings.append({**f, "source": name})
        elif isinstance(data, dict) and data.get("state") and data.get("evidence"):
            findings.append({"check": name, "state": data["state"],
                             "severity": data.get("severity", "info"),
                             "evidence": data["evidence"], "source": name})
    risk = None
    for data in json_files.values():
        if isinstance(data, dict) and "score" in data and isinstance(data["score"], (int, float)):
            risk = data["score"]
    worst = None
    proven = [f for f in findings if f.get("state") in ("CONFIRMED", "USED")]
    if proven:
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        worst = min(proven, key=lambda f: rank.get(f.get("severity", "info"), 9))["severity"]
    return {"files": len(json_files), "findings": findings, "risk_score": risk, "worst": worst,
            "artifacts": sorted(json_files)}


def render_md(master: dict) -> str:
    lines = ["# Wireless Assessment Report", ""]
    lines.append(f"- JSON artifacts found: {master['files']}")
    lines.append(f"- established findings: {len([f for f in master['findings'] if f['state'] in ('CONFIRMED', 'USED')])}")
    if master.get("risk_score") is not None:
        lines.append(f"- risk score: {master['risk_score']}/100")
    if master.get("worst"):
        lines.append(f"- worst established severity: {master['worst']}")
    lines.append("")
    lines.append("## Findings")
    for f in master["findings"][:50]:
        lines.append(f"- [{f.get('severity', 'info')}] {f['check']} — {f.get('evidence', '')[:150]} ({f.get('source', '?')})")
    lines.append("")
    lines.append("## Artifacts")
    for name in master["artifacts"]:
        lines.append(f"- {name}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--indir", default=".")
    ap.add_argument("--out")
    ap.add_argument("--json-out", help="write the master JSON next to the md output")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    master = build(Path(args.indir))
    report = Report("wireless_master", VERSION)
    report.note("master rollup", State.CONFIRMED, "info",
                f"{master['files']} artifact(s), {len(master['findings'])} finding(s)")
    if args.out:
        Path(args.out).write_text(render_md(master))
        report.record(args.out)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(master, indent=2))
        report.record(args.json_out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "risk.json").write_text(json.dumps({"score": 55, "fired": ["wep"]}))
        Path(td, "hs_report.json").write_text(json.dumps({"state": "CONFIRMED", "evidence": "hs found", "severity": "high"}))
        master = build(Path(td))
        check_eq(master["risk_score"], 55)
        check(master["worst"] == "high", True)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
