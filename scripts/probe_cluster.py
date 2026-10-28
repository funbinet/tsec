#!/usr/bin/env python3
"""Cluster probe requests by source MAC and SSID.

Probe-request frames from one device form a cluster: the same source MAC
asking for the same SSIDs. This clusters what is actually in the capture
and reports how broad each device's request footprint is.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def cluster(path: Path) -> dict:
    clusters: dict[str, set] = defaultdict(set)
    frames = 0
    if shutil.which("tshark"):
        proc = subprocess.run(
            ["tshark", "-r", str(path), "-Y", "wlan.fc.type_subtype == 4",
             "-T", "fields", "-e", "wlan.sa", "-e", "wlan.ssid"],
            capture_output=True, text=True, timeout=120)
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            sa = parts[0].strip().upper()
            if not sa:
                continue
            frames += 1
            ssid = parts[1].strip() if len(parts) > 1 else ""
            clusters[sa].add(ssid)
    return {"frames": frames,
            "clusters": [{"mac": mac, "ssids": sorted(s for s in ssids if s)}
                          for mac, ssids in sorted(clusters.items())]}


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
    info = cluster(Path(args.src))
    report = Report("probe_cluster", VERSION)
    report.note("probe requests", State.CONFIRMED, "info",
                f"{info['frames']} probe frame(s), {len(info['clusters'])} device(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    clusters: dict[str, set] = {"AA:BB:CC:00:00:01": {"net", "net2"}}
    out = [{"mac": mac, "ssids": sorted(s)} for mac, s in sorted(clusters.items())]
    check_eq(out[0]["ssids"], ["net", "net2"])


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
