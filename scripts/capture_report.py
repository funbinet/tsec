#!/usr/bin/env python3
"""Summarize a capture by type, channel and encryption.

Reads the structured AP list produced by kismet_parse and counts it: how
many APs per channel, per type, and the signal range. Totals and averages
are computed over the rows that actually exist, never padded.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def summarize(aps: list[dict]) -> dict:
    types = Counter(a.get("type", "Unknown") for a in aps)
    channels = Counter(str(a.get("channel", "")) for a in aps if a.get("channel"))
    signals = []
    for a in aps:
        try:
            signals.append(float(str(a.get("signal", "")).split()[0]))
        except (ValueError, IndexError):
            continue
    return {
        "aps": len(aps),
        "by_type": dict(types),
        "by_channel": dict(sorted(channels.items(), key=lambda kv: kv[1], reverse=True)),
        "signal_mean": round(sum(signals) / len(signals), 1) if signals else None,
        "signal_min": min(signals) if signals else None,
        "signal_max": max(signals) if signals else None,
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
    aps = json.loads(Path(args.src).read_text(errors="replace"))
    summary = summarize(aps)
    report = Report("capture_report", VERSION)
    report.note("capture summarized", State.CONFIRMED, "info",
                f"{summary['aps']} APs, {len(summary['by_channel'])} channel(s) in use, "
                f"mean signal {summary['signal_mean']}")
    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    summary = summarize([
        {"type": "AP", "channel": "6", "signal": "-42"},
        {"type": "AP", "channel": "6", "signal": "-50"},
        {"type": "Client", "channel": "11", "signal": "-70"},
    ])
    check_eq(summary["aps"], 3)
    check_eq(summary["by_type"]["AP"], 2)
    check_eq(summary["signal_max"], -42.0)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
