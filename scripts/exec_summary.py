#!/usr/bin/env python3
"""Write the executive summary from the master JSON.

Reads wireless_master.json and renders a markdown summary of where the
assessment stands: what was found, what scored how, and what artifacts
each number came from. It is a rendering of the data, not a new opinion.

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


def render(master: dict) -> str:
    lines = ["# Wireless Assessment — Executive Summary", ""]
    lines.append(f"- artifacts scanned: {master.get('files', 0)}")
    findings = master.get("findings", [])
    lines.append(f"- findings: {len(findings)}")
    for f in findings[:20]:
        lines.append(f"  - [{f.get('severity', 'info')}] {f.get('check', '')}: {f.get('evidence', '')[:120]}")
    if master.get("risk_score") is not None:
        lines.append(f"- risk score: {master['risk_score']}/100")
    if master.get("worst"):
        lines.append(f"- worst established severity: {master['worst']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in", dest="src")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.src:
        ap.error("--in is required unless --selftest is given")
    master = json.loads(Path(args.src).read_text(errors="replace"))
    md = render(master)
    report = Report("exec_summary", VERSION)
    report.note("executive summary", State.CONFIRMED, "info", f"{len(md)}B rendered from the master JSON")
    if args.out:
        Path(args.out).write_text(md)
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    md = render({"files": 3, "findings": [{"check": "deauth", "severity": "high", "evidence": "x"}], "risk_score": 55})
    check("# Wireless Assessment" in md, "title missing")
    check("risk score: 55/100" in md, "score missing")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
