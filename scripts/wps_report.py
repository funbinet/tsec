#!/usr/bin/env python3
"""Roll wash output up into a WPS exposure summary.

Reads the directory for the WPS scan outputs and counts APs whose PIN is
locked or open, and the rate of WPS-no-lock APs. wash-style lines look
like "BSSID ... WPS Version:2.0 ..."; this parses those lines.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def scan(dirpath: Path) -> dict:
    total = 0
    locked = 0
    unlocked = 0
    for path in sorted(dirpath.rglob("*")):
        if not path.is_file() or path.stat().st_size == 0:
            continue
        for line in path.read_text(errors="replace").splitlines():
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line):
                continue
            total += 1
            m = re.search(r"Locked\s*[:=]\s*(\w+)", line, re.I)
            if m and m.group(1).lower() in ("yes", "true", "1"):
                locked += 1
            elif m:
                unlocked += 1
    return {"total": total, "locked": locked, "unlocked": unlocked}


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
    info = scan(Path(args.src))
    report = Report("wps_report", VERSION)
    report.note("wps exposure", State.CONFIRMED, "info",
                f"{info['total']} AP(s) found, {info['locked']} locked, {info['unlocked']} unlocked")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "wash.txt").write_text(
            "AA:BB:CC:DD:EE:FF  MyNet  WPS Version:2.0  Locked: No\n"
            "11:22:33:44:55:66  Other   WPS Version:1.0  Locked: Yes\n")
        info = scan(Path(td))
        check_eq(info["total"], 2)
        check_eq(info["locked"], 1)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
