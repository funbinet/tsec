#!/usr/bin/env python3
"""Check the evil-twin artifact directory end to end.

A working evil twin needs hostapd.conf, dnsmasq.conf, and a portal log
not necessarily -- but the report must name which pieces exist so the
operator does not claim the twin worked on missing parts.

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
    present = {p.name: p.stat().st_size for p in sorted(dirpath.rglob("*")) if p.is_file()}
    required = {"hostapd.conf": "hostapd.conf", "dnsmasq.conf": "dnsmasq.conf"}
    missing = [v for v in required.values() if v not in present]
    return {"files": present, "missing": missing, "ready": not missing}


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
    report = Report("et_report", VERSION)
    report.note("evil-twin artifacts", State.CONFIRMED, "info",
                f"{len(info['files'])} file(s); ready={info['ready']}; missing: {info['missing'] or 'none'}")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "hostapd.conf").write_text("ssid=x\n")
        Path(td, "dnsmasq.conf").write_text("no-resolv\n")
        info = inventory(Path(td))
        check(info["ready"], "all files present must be ready")
        Path(td, "dnsmasq.conf").unlink()
        info = inventory(Path(td))
        check_eq(info["missing"], ["dnsmasq.conf"])


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
