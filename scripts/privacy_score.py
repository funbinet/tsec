#!/usr/bin/env python3
"""Score probe-request privacy.

More SSIDs in a device's probe history means the device leaks more about
its network history. The score is 100 minus the mean SSID count per
device times ten, clamped to 0..100: a quiet device sits near 100.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def score(clusters: list[dict]) -> dict:
    counts = [len(c.get("ssids", [])) for c in clusters]
    mean = sum(counts) / len(counts) if counts else 0.0
    value = max(0, min(100, round(100 - mean * 10)))
    return {"devices": len(clusters), "mean_ssids_per_device": round(mean, 1), "privacy_score": value}


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
    data = json.loads(Path(args.src).read_text(errors="replace"))
    clusters = data.get("clusters", data if isinstance(data, list) else [])
    info = score(clusters)
    report = Report("privacy_score", VERSION)
    report.note("probe privacy", State.CONFIRMED, "info",
                f"score {info['privacy_score']}/100 over {info['devices']} device(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    info = score([{"ssids": ["a", "b"]}, {"ssids": []}])
    check_eq(info["mean_ssids_per_device"], 1.0)
    check_eq(info["privacy_score"], 90)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
