#!/usr/bin/env python3
"""Deduplicate an AP capture CSV into an inventory.

A capture CSV repeats each AP once per appearance; the inventory keeps one
row per BSSID with the first SSID seen, the channel, the number of frames
captured, and the strongest signal observed. Rows without a BSSID are
dropped, never guessed.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def inventory(path: Path) -> list[dict]:
    seen: dict[str, dict] = {}
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            low = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
            bssid = low.get("bssid") or low.get("bss_id") or low.get("mac") or ""
            if ":" not in bssid:
                continue
            entry = seen.setdefault(bssid, {
                "bssid": bssid,
                "ssid": low.get("ssid") or low.get("essid") or "",
                "channel": low.get("channel") or low.get("ch") or "",
                "frames": 0, "best_signal": None,
            })
            entry["frames"] += 1
            sig = low.get("signal") or low.get("rssi") or low.get("power") or ""
            try:
                value = float(sig.split()[0])
                entry["best_signal"] = max(entry["best_signal"] if entry["best_signal"] is not None else value, value)
            except (ValueError, IndexError):
                pass
    return sorted(seen.values(), key=lambda e: e["bssid"])


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
    report = Report("ap_inventory", VERSION)
    aps = inventory(Path(args.src))
    report.note("inventory built", State.CONFIRMED, "info", f"{len(aps)} unique AP(s) from {args.src}")
    if args.out:
        Path(args.out).write_text(_render_csv(aps))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def _render_csv(aps: list[dict]) -> str:
    import io
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["bssid", "ssid", "channel", "frames", "best_signal"])
    writer.writeheader()
    writer.writerows(aps)
    return buf.getvalue()


def selftest_fn() -> None:
    import tempfile
    sample = "BSSID,SSID,Channel,Signal\nAA:BB:CC:DD:EE:FF,Office,6,-42\nAA:BB:CC:DD:EE:FF,Office,6,-48\n11:22:33:44:55:66,Home,11,-70\n"
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write(sample)
    aps = inventory(Path(f.name))
    check_eq(len(aps), 2)
    check_eq(aps[0]["frames"] + aps[1]["frames"], 3)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
