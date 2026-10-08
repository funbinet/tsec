#!/usr/bin/env python3
"""Consolidate an exploitation chain into one report.

An exploitation assessment leaves a trail: a file per step, each with a
state, a severity and the evidence that earned them. This walks that trail
and answers the only question that matters about it -- which steps were
established, in what order, and what the chain's weakest established link
actually proves.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Finding, Report, State, check, check_eq, selftest as engine_selftest,
)

VERSION = "2.0.0"


def collect_steps(indir: Path) -> list[dict]:
    steps = []
    for path in sorted(indir.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        findings = data.get("findings")
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict) and f.get("state") and f.get("evidence"):
                    steps.append({**f, "source": path.name})
        elif data.get("state") and data.get("evidence"):
            steps.append({**data, "source": path.name})
    return steps


def chain(indir: Path) -> Report:
    report = Report("chain_report", VERSION, target=str(indir))
    steps = collect_steps(indir)
    if not steps:
        report.note("chain inputs", State.REJECTED, "info",
                    f"no findings with state and evidence found under {indir}")
        return report
    proven = [s for s in steps if s["state"] in ("CONFIRMED", "USED")]
    inferred = [s for s in steps if s["state"] in ("INFERRED", "TESTED")]
    report.note("steps established", State.CONFIRMED, "info",
                f"{len(proven)} established step(s), {len(inferred)} lead(s)",
                count=len(proven))
    for step in steps:
        state = step["state"] if step["state"] in State.MEANING else State.INFERRED
        report.add(Finding(step.get("check", "unnamed"), state,
                           step.get("severity", "info"), step.get("evidence", ""),
                           {"source": step["source"]}))
    established = report.established
    worst_estab = None
    if established:
        worst_estab = min(established, key=lambda f: f.rank)
        report.note("chain conclusion", State.CONFIRMED, worst_estab.severity,
                    f"the chain reaches {worst_estab.check}: {worst_estab.evidence[:200]}")
    else:
        report.note("chain conclusion", State.INFERRED, "info",
                    "no step was established; the chain proves nothing yet")
    report.context["steps"] = len(steps)
    report.context["established"] = len(proven)
    return report


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "a.json").write_text(json.dumps({
            "tool": "x", "findings": [
                {"check": "open port", "state": "TESTED", "severity": "info",
                 "evidence": "22/tcp answers on 10.0.0.5"},
                {"check": "credential works", "state": "CONFIRMED", "severity": "high",
                 "evidence": "ssh login as ops succeeded"},
            ]}))
        (d / "b.json").write_text(json.dumps({
            "check": "cmd exec", "state": "USED", "severity": "critical",
            "evidence": "uid=0 observed in command output"}))
        report = chain(d)
        check_eq(report.context["steps"], 3)
        check_eq(report.context["established"], 2)
        established = [f for f in report.findings if f.state in ("CONFIRMED", "USED")]
        check(any(f.check == "chain conclusion" and f.severity == "critical" for f in established),
              "chain conclusion must name the worst established step")


def selftest() -> None:
    selftest_fn()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rhost", default="", help="target the chain ran against")
    ap.add_argument("--indir", default=".", help="directory holding the step reports")
    ap.add_argument("--out", help="write the JSON report here")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    report = chain(Path(args.indir))
    if args.rhost:
        report.target = args.rhost
    from tsec_engine import emit
    emit(report, args.json, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
