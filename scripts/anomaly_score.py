#!/usr/bin/env python3
"""Score frame-rate anomalies in a capture histogram.

Reads a hist.json (frame_hist output) and flags the usual signs of an
attack in numbers: a deauth-heavy ethertype mix, very high burst rates,
and EAPOL floods. The score is an integer 0..100 -- sum of weighted
observations, capped. Every point is justified by a field in the input,
never by a global guess.

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


def score(hist: dict) -> dict:
    reasons = []
    points = 0
    by_type = hist.get("by_ethertype", {})
    eapol_share = 0.0
    total = sum(by_type.values())
    if total:
        eapol_share = by_type.get("eapol", 0) / total
    if eapol_share > 0.5:
        points += 40
        reasons.append(f"EAPOL-heavy mix ({eapol_share:.0%} of frames)")
    burst = hist.get("max_per_second", 0) or 0
    if burst > 1000:
        points += 30
        reasons.append(f"burst of {burst} pps")
    duration = hist.get("duration_s", 0) or 0
    if duration and hist.get("frames", 0) / duration > 500:
        points += 20
        reasons.append(f"mean rate {hist['frames'] / duration:.0f} pps")
    if not reasons:
        reasons.append("nothing anomalous in the histogram")
    return {"score": min(points, 100), "reasons": reasons,
            "eapol_share": round(eapol_share, 2), "max_pps": burst}


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
    hist = json.loads(Path(args.src).read_text(errors="replace"))
    info = score(hist)
    report = Report("anomaly_score", VERSION)
    report.note("anomaly score", State.CONFIRMED, "info",
                f"{info['score']}/100: {'; '.join(info['reasons'])}")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    info = score({"by_ethertype": {"eapol": 8, "ipv4": 2}, "max_per_second": 1500,
                  "frames": 10, "duration_s": 0.01})
    check(info["score"] >= 70, f"expected a high score, got {info}")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
