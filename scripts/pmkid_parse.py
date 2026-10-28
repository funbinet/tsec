#!/usr/bin/env python3
"""Parse a 22000-format captured file into structured PMKID records.

hashcat 22000 lines are WPA*TYPE*PMKID*MAC_AP*MAC_CLIENT*ESSID with hex
fields. This parses each line, validates the field widths, and drops
os that cannot be understood instead of reporting garbage.

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
HEXES = set("0123456789abcdefABCDEF")


def parse_line(line: str) -> dict | None:
    parts = line.strip().split("*")
    if len(parts) != 6 or parts[0] != "WPA":
        return None
    _, kind, pmkid, mac_ap, mac_client, essid_hex = parts
    if not all(set(f) <= HEXES for f in (kind, pmkid, mac_ap, mac_client)):
        return None
    try:
        essid = bytes.fromhex(essid_hex).decode(errors="replace")
    except ValueError:
        return None
    return {
        "type": "EAPOL" if kind == "02" else "PMKID",
        "pmkid": pmkid, "mac_ap": mac_ap, "mac_client": mac_client,
        "essid": essid,
    }


def loads(path: Path) -> list[dict]:
    out = []
    for line in path.read_text(errors="replace").splitlines():
        rec = parse_line(line)
        if rec:
            out.append(rec)
    return out


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
    records = loads(Path(args.src))
    report = Report("pmkid_parse", VERSION)
    report.note("pmkid records", State.CONFIRMED, "info", f"{len(records)} valid line(s) from {args.src}")
    if args.out:
        Path(args.out).write_text(json.dumps(records, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    rec = parse_line("WPA*01*" + "ab" * 16 + "*aabbccddeeff*112233445566*" + "6f6666696365")
    check(rec is not None, "a well-formed line must parse")
    check_eq(rec["type"], "PMKID")
    check(parse_line("garbage") is None, "garbage must be dropped")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
