#!/usr/bin/env python3
"""Roll the probe-analysis directory into the probe report.

Merges oui vendors, probe clusters and privacy scores from the analysis
directory into one reportable JSON. Missing inputs are named.

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


def rollup(dirpath: Path) -> dict:
    vendors = None
    clusters = None
    privacy = None
    for path in sorted(dirpath.rglob("*.json")):
        try:
            data = json.loads(path.read_text(errors="replace"))
        except ValueError:
            continue
        if "ouis" in data:
            vendors = data
        if "clusters" in data:
            clusters = data
        if "privacy_score" in data:
            privacy = data
    return {
        "vendors_found": vendors is not None,
        "unique_macs": vendors.get("unique_macs") if vendors else None,
        "devices": len(clusters["clusters"]) if clusters else 0,
        "probe_frames": clusters.get("frames") if clusters else 0,
        "privacy_score": privacy.get("privacy_score") if privacy else None,
    }


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
    info = rollup(Path(args.src))
    report = Report("probe_report", VERSION)
    report.note("probe rollup", State.CONFIRMED, "info",
                f"{info['probe_frames']} probe frame(s), {info['devices']} device(s), {info['unique_macs']} MAC(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "vendors.json").write_text(json.dumps({"ouis": {"AA:BB:CC": 3}, "unique_macs": 3}))
        Path(td, "clusters.json").write_text(json.dumps({"clusters": [{"mac": "m", "ssids": []}], "frames": 5}))
        Path(td, "privacy.json").write_text(json.dumps({"privacy_score": 90}))
        info = rollup(Path(td))
        check_eq(info["devices"], 1)
        check_eq(info["privacy_score"], 90)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
