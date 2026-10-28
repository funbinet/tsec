#!/usr/bin/env python3
"""Roll the AP inventory up into channel and channel-width findings.

Reads ap_inventory.csv (the deduplicated inventory) and reports how many
APs sit on each channel, which channel is the most crowded, and what
fraction of the APs are on the crowded 1/6/11 set that dominates 2.4GHz.

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


def rollup(path: Path) -> dict:
    channels = Counter()
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            ch = (row.get("channel") or "").strip()
            if ch:
                channels[ch] += 1
    crowded = sum(v for k, v in channels.items() if k in ("1", "6", "11"))
    total = sum(channels.values())
    return {
        "channels": dict(channels.most_common()),
        "busiest": channels.most_common(1)[0] if channels else None,
        "on_1_6_11": crowded,
        "on_1_6_11_ratio": round(crowded / total, 2) if total else None,
        "total": total,
    }


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
    info = rollup(Path(args.src))
    report = Report("ap_report", VERSION)
    report.note("channel rollup", State.CONFIRMED, "info",
                f"{info['total']} APs, busiest channel {info['busiest']}")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    sample = "bssid,ssid,channel,frames,best_signal\nAA,net,6,2,-40\nBB,net2,6,1,-60\nCC,net3,11,1,-70\n"
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write(sample)
    info = rollup(Path(f.name))
    check_eq(info["busiest"], ("6", 2))
    check_eq(info["on_1_6_11_ratio"], 1.0)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
