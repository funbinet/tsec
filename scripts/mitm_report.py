#!/usr/bin/env python3
"""Roll extracted pcap credentials into a MITM report.

Reads creds.json (pcap_creds output) and counts credentials by type.
A credential the parser did not recognise is named, not assumed.

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


def rollup(found: list[dict]) -> dict:
    by_kind = Counter(f.get("kind", "unknown") for f in found)
    return {"total": len(found), "by_kind": dict(by_kind.most_common())}


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
    found = json.loads(Path(args.src).read_text(errors="replace"))
    info = rollup(found)
    report = Report("mitm_report", VERSION)
    report.note("mitm credentials", State.CONFIRMED, "info",
                f"{info['total']} credential(s), kinds: {info['by_kind']}")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    info = rollup([{"kind": "basic"}, {"kind": "basic"}, {"kind": "password"}])
    check_eq(info["by_kind"]["basic"], 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
