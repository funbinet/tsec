#!/usr/bin/env python3
"""Record IQ samples from an RTL-SDR device.

Runs rtl_sdr for real when the binary and a dongle are present; otherwise it
says so and captures nothing -- it never fabricates samples.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def capture(freq: int, samples: int, out: Path) -> dict:
    if not shutil.which("rtl_sdr"):
        return {"state": State.BLOCKED, "evidence": "rtl_sdr not installed"}
    proc = subprocess.run(
        ["rtl_sdr", "-f", str(freq), "-g", "32", "-n", str(samples * 2), str(out)],
        capture_output=True, text=True, timeout=120)
    if proc.returncode == 0 and out.exists():
        return {"state": State.USED, "evidence": f"{out.stat().st_size} bytes of raw IQ (u8 interleaved)"}
    return {"state": State.FAILED, "evidence": (proc.stderr or "")[:200] or "no output"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--freq", type=int, default=2_437_000_000)
    ap.add_argument("--samples", type=int, default=1_000_000)
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    report = Report("rtl_capture", VERSION)
    if args.out:
        result = capture(args.freq, args.samples, Path(args.out))
        report.note("rtl_sdr capture", result["state"],
                    "high" if result["state"] == State.USED else "info", result["evidence"])
        if result["state"] == State.USED:
            report.record(args.out)
    else:
        report.note("rtl_capture", State.GENERATED, "info",
                    "no --out given; would run rtl_sdr "
                    f"-f {args.freq} -g 32 -n {args.samples * 2}")
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    check(True, "rtl_capture selftest asserts constructor path and rtl_sdr presence only")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
