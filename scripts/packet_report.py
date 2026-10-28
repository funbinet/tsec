#!/usr/bin/env python3
"""Roll frame histograms into the packet report.

Reads the analysis directory for hist.json files and merges them: total
frames, top ethertypes, the busiest second. A directory without a
histogram is reported as such.

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


def merge(dirpath: Path) -> dict:
    totals = {}
    frames = 0
    busiest = 0
    sources = 0
    for path in sorted(dirpath.rglob("*.json")):
        try:
            data = json.loads(path.read_text(errors="replace"))
        except ValueError:
            continue
        if "frames" in data and "by_ethertype" in data:
            sources += 1
            frames += data["frames"]
            busiest = max(busiest, data.get("max_per_second", 0) or 0)
            for k, v in data["by_ethertype"].items():
                totals[k] = totals.get(k, 0) + v
    return {"sources": sources, "frames": frames, "by_ethertype": totals, "busiest_pps": busiest}


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
    info = merge(Path(args.src))
    report = Report("packet_report", VERSION)
    report.note("packet rollup", State.CONFIRMED, "info",
                f"{info['frames']} frame(s) from {info['sources']} source(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "hist.json").write_text(json.dumps({"frames": 10, "by_ethertype": {"ipv4": 6, "arp": 4}, "max_per_second": 5}))
        info = merge(Path(td))
        check_eq(info["frames"], 10)
        check_eq(info["busiest_pps"], 5)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
