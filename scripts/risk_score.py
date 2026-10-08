#!/usr/bin/env python3
"""Score the wireless findings file.

Reads a plain-text findings file and scores the usual classes of finding
by the weight they carry: exposed credentials, unencrypted management
frames, weak ciphers, default SSIDs, isolation failures. Each class only
fires when the corresponding line exists in the file.

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

WEIGHTS = {
    "credential": 30, "deauth": 15, "wep": 25, "wps": 20, "evil-twin": 25,
    "no pmf": 10, "default ssid": 5, "open network": 15, "isolate fail": 15,
}


def score(lines: list[str]) -> dict:
    text = "\n".join(lines).lower()
    hits = {k: v for k, v in WEIGHTS.items() if k in text}
    return {"score": min(sum(hits.values()), 100), "fired": sorted(hits)}


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
    lines = Path(args.src).read_text(errors="replace").splitlines()
    info = score(lines)
    report = Report("risk_score", VERSION)
    report.note("risk score", State.CONFIRMED, "info",
                f"{info['score']}/100 from {len(info['fired'])} class(es)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    info = score(["credential captured on rogue AP", "wep iv count high"])
    check_eq(info["score"], 55)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
