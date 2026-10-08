#!/usr/bin/env python3
"""Report WEP-capture exposure: IV count per BSSID.

Reads the WEP capture directory for CSV rows mentioning WEP and counts IVs
per BSSID. A small IV count means the capture proves little; a large one
makes the WEP weakness concrete.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def collect(dirpath: Path) -> dict:
    ivs = Counter()
    wep_rows = 0
    for path in sorted(dirpath.rglob("*.csv")):
        try:
            with path.open(newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    low = {k.strip().lower(): (v or "") for k, v in row.items() if k}
                    if "wep" in " ".join(low.values()).lower():
                        wep_rows += 1
                        bssid = low.get("bssid") or low.get("mac") or "unknown"
                        ivs[bssid] += 1
        except (OSError, csv.Error):
            continue
    return {"wep_rows": wep_rows, "ivs_per_bssid": dict(ivs.most_common())}


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
    info = collect(Path(args.src))
    report = Report("wep_report", VERSION)
    report.note("wep exposure", State.CONFIRMED, "info",
                f"{info['wep_rows']} WEP row(s), {len(info['ivs_per_bssid'])} BSSID(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "wep.csv").write_text("bssid,enc\nAA:BB:CC:DD:EE:FF,WEP\nAA:BB:CC:DD:EE:FF,WEP\n")
        info = collect(Path(td))
        check_eq(info["wep_rows"], 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
