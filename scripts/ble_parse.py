#!/usr/bin/env python3
"""Extract BLE devices from a btmon HCI log.

btmon prints each HCI packet with its address and, when present, the
advertisement name. This pulls each seen address into a devices.json so
BLE findings are derived from the actual packet log, not from a capture of
a capture.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"

MAC = re.compile(r"((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})")
NAME = re.compile(r"Complete local name:\s*'([^']*)'", re.I)
ADDR = re.compile(r"addr(?:ess)?:?\s*((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", re.I)


def parse(path: Path) -> list[dict]:
    devices: dict[str, dict] = {}
    text = path.read_text(errors="replace")
    current = None
    for line in text.splitlines():
        m = ADDR.search(line)
        if m:
            current = m.group(1).upper()
            devices.setdefault(current, {"addr": current, "name": ""})
        nm = NAME.search(line)
        if nm and current:
            devices[current]["name"] = nm.group(1)
    return list(devices.values())


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
    devices = parse(Path(args.src))
    report = Report("ble_parse", VERSION)
    report.note("ble devices", State.CONFIRMED, "info", f"{len(devices)} device(s) in the btmon log")
    if args.out:
        Path(args.out).write_text(json.dumps(devices, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    log = "hci event ... addr: AA:BB:CC:11:22:33\n  Complete local name: 'Headphones'\n"
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(log)
    devices = parse(Path(f.name))
    check_eq(len(devices), 1)
    check_eq(devices[0]["name"], "Headphones")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
