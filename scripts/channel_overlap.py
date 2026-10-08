#!/usr/bin/env python3
"""Measure channel overlap in a 2.4GHz survey.

Reads a channel survey CSV (channel per row) and counts how many APs sit on
each channel and which channels are within half a channel-width of each
other -- the channels that actually collide.

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


def survey(path: Path) -> dict:
    channels = Counter()
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            low = {k.strip().lower(): (v or "") for k, v in row.items() if k}
            raw = low.get("channel") or low.get("ch") or ""
            try:
                channels[int(float(raw))] += 1
            except ValueError:
                continue
    overlaps = []
    chans = sorted(channels)
    for i, a in enumerate(chans):
        for b in chans[i + 1 :]:
            if b - a < 5:
                overlaps.append((a, b))
    return {"channels": dict(channels.most_common()), "overlapping_pairs": overlaps, "distinct": len(chans)}


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
    info = survey(Path(args.src))
    report = Report("channel_overlap", VERSION)
    report.note("channel overlap", State.CONFIRMED, "info",
                f"{info['distinct']} channel(s), {len(info['overlapping_pairs'])} overlapping pair(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write("channel\n1\n1\n6\n7\n11\n")
    info = survey(Path(f.name))
    check_eq(info["distinct"], 4)
    check_eq(info["overlapping_pairs"], [(6, 7), (7, 11)])


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
