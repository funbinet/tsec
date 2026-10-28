#!/usr/bin/env python3
"""Roll a paired-devices listing into a Bluetooth device report.

Reads the bluetoothctl-style devices.txt (one "Device AA:BB:... Name" per
line) and counts devices by manufacturer prefix of the address: the OUI is
the prefix, and unknown prefixes are named as such rather than guessed.

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


def parse(path: Path) -> list[dict]:
    devices = []
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r"^\s*(?:Device|device)\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s*(.*)$", line)
        if m:
            mac = m.group(1).upper()
            devices.append({"mac": mac, "name": m.group(2).strip(), "oui": mac[:8]})
    return devices


def report(devices: list[dict]) -> dict:
    ous = Counter(d["oui"] for d in devices)
    return {"devices": len(devices), "ouis": dict(ous.most_common()),
            "unnamed": sum(1 for d in devices if not d["name"])}


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
    info = report(devices)
    report = Report("bt_report", VERSION)
    report.note("bluetooth devices", State.CONFIRMED, "info",
                f"{info['devices']} device(s), {len(info['ouis'])} OUI prefix(es), {info['unnamed']} unnamed")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("Device AA:BB:CC:11:22:33 Headphones\nDevice AA:BB:CC:44:55:66 Keyboard\n")
    devices = parse(Path(f.name))
    info = report(devices)
    check_eq(info["devices"], 2)
    check_eq(info["ouis"]["AA:BB:CC"], 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
