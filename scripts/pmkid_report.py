#!/usr/bin/env python3
"""Roll parsed PMKID records up by access point.

Reads pmkid.json (the structured output of pmkid_parse) and counts records
per MAC_AP, so the report names the APs a real capture produced.

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


def rollup(records: list[dict]) -> dict:
    per_ap = Counter(r.get("mac_ap", "") for r in records)
    return {
        "total": len(records),
        "per_ap": dict(per_ap.most_common()),
        "pmkid_lines": sum(1 for r in records if r.get("type") == "PMKID"),
        "eapol_lines": sum(1 for r in records if r.get("type") == "EAPOL"),
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
    records = json.loads(Path(args.src).read_text(errors="replace"))
    info = rollup(records)
    report = Report("pmkid_report", VERSION)
    report.note("rollup", State.CONFIRMED, "info", f"{info['total']} records across {len(info['per_ap'])} AP(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    info = rollup([{"mac_ap": "aa", "type": "EAPOL"}, {"mac_ap": "aa", "type": "PMKID"}, {"mac_ap": "bb", "type": "EAPOL"}])
    check_eq(info["per_ap"]["aa"], 2)
    check_eq(info["eapol_lines"], 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
