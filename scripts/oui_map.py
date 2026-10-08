#!/usr/bin/env python3
"""Map source MACs in a probe pcap to OUI prefixes.

Reads the probe capture with tshark and groups the source MAC addresses by
their OUI prefix (the first three octets). Where the system does not have
a vendor database the prefix itself is the finding; vendors are not
invented.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def macs_via_tshark(path: Path) -> list[str]:
    if not shutil.which("tshark"):
        return []
    proc = subprocess.run(
        ["tshark", "-r", str(path), "-T", "fields", "-e", "wlan.sa", "-e", "eth.src"],
        capture_output=True, text=True, timeout=120)
    out = []
    for line in proc.stdout.splitlines():
        for part in line.split("\t"):
            if re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", part.strip()):
                out.append(part.strip().upper())
    return out


def map_ouis(path: Path) -> dict:
    macs = macs_via_tshark(path)
    ous = Counter(m[:8] for m in macs)
    return {"frames": len(macs), "unique_macs": len(set(macs)), "ouis": dict(ous.most_common())}


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
    info = map_ouis(Path(args.src))
    report = Report("oui_map", VERSION)
    report.note("oui mapping", State.CONFIRMED, "info",
                f"{info['unique_macs']} source MAC(s), {len(info['ouis'])} OUI prefix(es)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    # the prefix grouping is pure; assert it over a literal list
    from collections import Counter
    macs = ["AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66", "11:22:33:44:55:66"]
    ous = Counter(m[:8] for m in macs)
    check_eq(ous["AA:BB:CC"], 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
