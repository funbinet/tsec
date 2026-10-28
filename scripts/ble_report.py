#!/usr/bin/env python3
"""Roll parsed BLE devices into the BLE report.

Reads devices.json (from ble_parse) and counts named vs unnamed devices.

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


def summary(devices: list[dict]) -> dict:
    named = sum(1 for d in devices if d.get("name"))
    return {"devices": len(devices), "named": named, "unnamed": len(devices) - named}


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
    devices = json.loads(Path(args.src).read_text(errors="replace"))
    info = summary(devices)
    report = Report("ble_report", VERSION)
    report.note("ble inventory", State.CONFIRMED, "info",
                f"{info['devices']} device(s), {info['named']} named, {info['unnamed']} unnamed")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    info = summary([{"name": "a"}, {"name": ""}, {}])
    check_eq(info["named"], 1)
    check_eq(info["unnamed"], 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
