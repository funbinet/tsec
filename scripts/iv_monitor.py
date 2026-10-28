#!/usr/bin/env python3
"""Count IVs per BSSID in a WEP capture CSV.

If the capture repeats the same BSSID with IVs, the report must show how
many IVs were captured per radio, because WEP's weakness is IV volume.

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


def count(path: Path) -> dict:
    ivs = Counter()
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            low = {k.strip().lower(): (v or "") for k, v in row.items() if k}
            bssid = low.get("bssid") or low.get("mac") or low.get("ap") or "unknown"
            ivs[bssid] += 1
    return {"total_ivs": sum(ivs.values()), "ivs_per_bssid": dict(ivs.most_common())}


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
    info = count(Path(args.src))
    report = Report("iv_monitor", VERSION)
    report.note("iv volume", State.CONFIRMED, "info",
                f"{info['total_ivs']} IV(s), {len(info['ivs_per_bssid'])} BSSID(s)")
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write("bssid,iv\nAA:BB:CC:DD:EE:FF,112233\nAA:BB:CC:DD:EE:FF,445566\n")
    info = count(Path(f.name))
    check_eq(info["total_ivs"], 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
