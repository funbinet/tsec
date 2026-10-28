#!/usr/bin/env python3
"""Report the client-isolation test directory.

Looks at the artifacts of a client-isolation test (portal logs, arp
captures, Nmap outputs) and names what evidence exists to judge whether
two clients on the same AP can reach each other.

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
    names = [p.name for p in sorted(dirpath.rglob("*")) if p.is_file()]
    return {"files": names, "has_nmap": any("nmap" in n for n in names),
            "has_pcap": any(n.endswith((".pcap", ".cap")) for n in names)}


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
    report = Report("iso_report", VERSION)
    report.note("isolation evidence", State.CONFIRMED, "info",
                f"{len(info['files'])} file(s), nmap={info['has_nmap']}, pcap={info['has_pcap']}")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "nmap_out.txt").write_text("up\n")
        Path(td, "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        info = inventory(Path(td))
        check(info["has_nmap"] and info["has_pcap"], True)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
