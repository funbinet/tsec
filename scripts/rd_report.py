#!/usr/bin/env python3
"""Roll the responder-directory into the rogue-device report.

Reads the rd/ artifact directory for the captures and logs of a rogue-AP
as we set them up -- creds.txt, victims list, pcap captures -- and names
what was actually collected.

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


def inventory(dirpath: Path) -> dict:
    files = [p for p in sorted(dirpath.rglob("*")) if p.is_file()]
    return {
        "files": [p.name for p in files],
        "creds_count": sum(1 for p in files if p.name == "creds.txt"
                            and p.stat().st_size),
        "pcaps": [p.name for p in files if p.suffix in (".pcap", ".cap")],
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
    info = inventory(Path(args.src))
    report = Report("rd_report", VERSION)
    report.note("rogue-device artifacts", State.CONFIRMED, "info",
                f"{len(info['files'])} file(s), creds.txt present={bool(info['creds_count'])}, {len(info['pcaps'])} pcap(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "creds.txt").write_text("u,p\n")
        Path(td, "run.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        info = inventory(Path(td))
        check_eq(info["creds_count"], 1)
        check_eq(len(info["pcaps"]), 1)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
