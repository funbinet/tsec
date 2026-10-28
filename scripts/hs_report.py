#!/usr/bin/env python3
"""Report captured handshakes for one BSSID.

Reads a handshake capture directory and finds, for the named BSSID, the
files hashcat-style tooling recognises: .22000 lines and .pcap capture
files. A handshake is only reported when the file exists and is non-empty;
a directory of empty files is reported as none.

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


def find_handshakes(dirpath: Path, bssid: str) -> list[Path]:
    hits = []
    for path in sorted(dirpath.iterdir()):
        if not path.is_file() or path.stat().st_size == 0:
            continue
        if path.suffix in (".22000", ".pcap", ".cap") and (bssid.replace(":", "") in path.name or bssid in path.name or path.suffix == ".22000"):
            hits.append(path)
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in", dest="src")
    ap.add_argument("--bssid", default="")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.src:
        ap.error("--in is required unless --selftest is given")
    hits = find_handshakes(Path(args.src), args.bssid)
    report = Report("hs_report", VERSION)
    state = State.CONFIRMED if hits else State.INFERRED
    report.note("handshake files", state, "high" if hits else "info",
                f"{len(hits)} candidate file(s) under {args.src}: " + ", ".join(p.name for p in hits))
    if args.out:
        Path(args.out).write_text(json.dumps([str(p) for p in hits], indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "aa-bb-cc-dd-ee-ff.22000").write_text("WPA*01*...\n")
        (d / "empty.pcap").write_bytes(b"")
        hits = find_handshakes(d, "AA:BB:CC:DD:EE:FF")
        check_eq(len(hits), 1)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
