#!/usr/bin/env python3
"""Roll the spectrum capture directory into the spectrum report.

Merges fft.json peaks and survey_*.csv overlap findings from the spec dir
into one JSON the rest of the pipeline can consume.

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


def rollup(dirpath: Path) -> dict:
    ffts = []
    surveys = []
    for path in sorted(dirpath.rglob("*.json")):
        try:
            data = json.loads(path.read_text(errors="replace"))
        except ValueError:
            continue
        if "peak_bin" in data:
            ffts.append(data)
        if "overlapping_pairs" in data:
            surveys.append(data)
    return {"fft_reports": len(ffts), "surveys": len(surveys),
            "max_peak_db": max((f["peak_power_db"] for f in ffts), default=None)}


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
    report = Report("spec_report", VERSION)
    report.note("spectrum rollup", State.CONFIRMED, "info",
                f"{info['fft_reports']} FFT(s), {info['surveys']} survey(s), peak {info['max_peak_db']} dB")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "fft.json").write_text(json.dumps({"peak_bin": 4, "peak_power_db": 20.0}))
        Path(td, "survey.json").write_text(json.dumps({"overlapping_pairs": [[1, 6]]}))
        info = rollup(Path(td))
        check_eq(info["fft_reports"], 1)
        check_eq(info["max_peak_db"], 20.0)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
