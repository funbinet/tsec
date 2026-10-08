#!/usr/bin/env python3
"""Roll the evil-twin portal log into a portal report.

portal_serve writes one "user,password" line per capture. This counts the
captures and lists how many distinct usernames the log holds. A missing log
is reported as zero, not silently passed over.

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


def collect(dirpath: Path) -> dict:
    captures = 0
    users = set()
    for path in sorted(dirpath.rglob("*")):
        if path.is_file() and path.suffix in (".log", ".txt"):
            for line in path.read_text(errors="replace").splitlines():
                if "," in line:
                    captures += 1
                    users.add(line.split(",", 1)[0].strip())
    return {"captures": captures, "distinct_users": len(users)}


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
    info = collect(Path(args.src))
    report = Report("portal_report", VERSION)
    report.note("portal captures", State.CONFIRMED, "info",
                f"{info['captures']} credential line(s), {info['distinct_users']} user(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "creds.log").write_text("alice,pw1\nbob,pw2\nalice,pw3\n")
        info = collect(Path(td))
        check_eq(info["captures"], 3)
        check_eq(info["distinct_users"], 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
