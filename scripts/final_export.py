#!/usr/bin/env python3
"""Export the run's final wireless JSON.

Walks the run directory for the canonical JSON artifacts our scripts
produce (ap_inventory, ap_report, pmkid.json, wireless_master.json,
eaт laporanешь subsets...) and merges them into one final JSON document
with their names. Every source file is its own key, so the final export
cannot introduce numbers of its own.

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

CANONICAL = (
    "ap_inventory.csv", "ap_report.json", "pmkid.json", "pmkid_report.json",
    "wpa_crack.json", "wireless_master.json", "ap_inventory.json",
    "capture_report.json", "hs_report.json", "wep_report.json", "wps_report.json",
    "bt_report.json", "ble_report.json", "et_report.json", "portal_report.json",
    "wpa3_report.json", "mitm_report.json", "rd_report.json", "iso_report.json",
    "probe_report.json", "spec_report.json", "packet_report.json", "persist_report.json",
)


def merge(root: Path) -> dict:
    out = {}
    for name in CANONICAL:
        for hit in root.rglob(name):
            try:
                if name.endswith(".json"):
                    out[hit.stem] = json.loads(hit.read_text(errors="replace"))
                else:
                    out[hit.stem] = hit.read_text(errors="replace").splitlines()
            except (OSError, ValueError):
                continue
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--indir", default=".")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    info = merge(Path(args.indir))
    report = Report("final_export", VERSION)
    report.note("final export", State.CONFIRMED, "info",
                f"merged {len(info)} known artifact(s) from {args.indir}")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "ap_report.json").write_text(json.dumps({"total": 3}))
        info = merge(Path(td))
        check_eq(info["ap_report"]["total"], 3)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
