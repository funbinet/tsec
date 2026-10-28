#!/usr/bin/env python3
"""Turn a Kismet device CSV into structured AP data.

Kismet logs can be exported as CSV; the column layout depends on what was
exported, so this locates the fields by name (bssid, ssid, channel,
signal, type) rather than by fixed position, and skips rows it cannot
parse rather than inventing values for them.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Finding, Report, State, check, check_eq, selftest as engine_selftest,
)

VERSION = "2.0.0"


def load(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = csv.DictReader(text.splitlines())
    aps = []
    for row in rows:
        lowered = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
        bssid = first(lowered, ("bssid", "bss_id", "mac", "mac_addr", "station mac"))
        if not bssid or ":" not in bssid:
            continue
        aps.append({
            "bssid": bssid,
            "ssid": first(lowered, ("ssid", "essid", "network name")),
            "channel": first(lowered, ("channel", "ch")),
            "signal": first(lowered, ("signal", "rssi", "signal/noise", "power")),
            "type": first(lowered, ("type", "device type", "phyname")) or "Unknown",
        })
    return aps


def first(row: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        if row.get(key):
            return row[key]
    return ""


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
    report = Report("kismet_parse", VERSION)
    try:
        aps = load(Path(args.src))
    except OSError as exc:
        report.note("input", State.UNREACHABLE, "info", str(exc))
        _finish(report, args)
        return 0
    report.note("aps parsed", State.CONFIRMED, "info",
                f"{len(aps)} access point(s) parsed from {args.src}")
    if args.out:
        Path(args.out).write_text(json.dumps(aps, indent=2))
        report.record(args.out)
    _finish(report, args)
    return 0


def _finish(report, args) -> None:
    from tsec_engine import emit
    emit(report, args.json, None)


def selftest_fn() -> None:
    import tempfile
    sample = "BSSID,SSID,Channel,Signal,Type\n" \
             "AA:BB:CC:DD:EE:FF,Office,6,-42,AP\n" \
             "11:22:33:44:55:66,Home,11,-70,AP\n"
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write(sample)
        path = f.name
    aps = load(Path(path))
    check_eq(len(aps), 2)
    check_eq(aps[0]["ssid"], "Office")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
