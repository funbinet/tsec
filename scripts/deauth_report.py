#!/usr/bin/env python3
"""Count deauthentication frames in a capture.

If the directory holds PCAPs, this runs tcpdump over each and counts
deauth frames for real. If it holds CSV exports, it counts rows whose type
column names deauthentication. Empty directory or no matches is reported,
not skipped.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def count_csv(path: Path) -> int:
    count = 0
    try:
        with path.open(newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                for value in row.values():
                    if isinstance(value, str) and "deauth" in value.lower():
                        count += 1
                        break
    except (OSError, csv.Error):
        pass
    return count


def count_pcap(path: Path) -> int | None:
    if not shutil.which("tcpdump"):
        return None
    proc = subprocess.run(
        ["tcpdump", "-r", str(path), "-nn", "-e", "wlan", "deauth"],
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        proc = subprocess.run(["tcpdump", "-r", str(path), "-nn", "-e"],
                              capture_output=True, text=True, timeout=60)
    return sum(1 for ln in (proc.stdout + proc.stderr).splitlines() if "deauth" in ln.lower())


def count_dir(dirpath: Path) -> dict:
    csv_hits = 0
    pcap_hits = 0
    scanned = 0
    for path in sorted(dirpath.rglob("*")):
        if not path.is_file():
            continue
        scanned += 1
        if path.suffix.lower() in (".csv",):
            csv_hits += count_csv(path)
        elif path.suffix.lower() in (".pcap", ".cap", ".kismet"):
            n = count_pcap(path)
            if n is not None:
                pcap_hits += n
    return {"files_scanned": scanned, "deauth_rows_csv": csv_hits, "deauth_frames_pcap": pcap_hits}


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
    info = count_dir(Path(args.src))
    report = Report("deauth_report", VERSION)
    total = info["deauth_rows_csv"] + info["deauth_frames_pcap"]
    report.note("deauth count", State.CONFIRMED, "info",
                f"{total} deauth record(s) across {info['files_scanned']} file(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    with tempfile.TemporaryDirectory() as td:
        Path(td, "deauth.csv").write_text("time,type,bssid\n1,Deauthentication,aa:bb\n2,Beacon,aa:bb\n")
        info = count_dir(Path(td))
        check_eq(info["deauth_rows_csv"], 1)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
