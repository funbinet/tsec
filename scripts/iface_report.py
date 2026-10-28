#!/usr/bin/env python3
"""Report one interface's real state.

Runs `ip link show` and `ip -d link show` for the interface and parses
what comes back: state, flags, MTU, and whether it is in monitor mode.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def iface_state(iface: str) -> dict:
    proc = subprocess.run(["ip", "-d", "link", "show", iface],
                          capture_output=True, text=True, timeout=20)
    if proc.returncode != 0:
        return {"found": False, "detail": proc.stderr.strip()[:200]}
    text = proc.stdout
    state = re.search(r"state\s+(\w+)", text)
    mtu = re.search(r"mtu\s+(\d+)", text)
    monitor = "monitor" in text.lower()
    return {"found": True, "state": state.group(1) if state else None,
            "mtu": int(mtu.group(1)) if mtu else None, "monitor": monitor,
            "mac": (re.search(r"link/\w+\s+([0-9a-f:]+)", text) or [None, None])[1]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iface")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.iface:
        ap.error("--iface is required unless --selftest is given")
    info = iface_state(args.iface)
    report = Report("iface_report", VERSION, target=args.iface)
    if info["found"]:
        report.note("interface", State.CONFIRMED, "info",
                    f"{args.iface}: {info['state']}, mtu {info['mtu']}, monitor={info['monitor']}")
    else:
        report.note("interface", State.UNREACHABLE, "info", info["detail"])
    if args.out:
        Path(args.out).write_text(json_to_str(info))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def json_to_str(info: dict) -> str:
    import json
    return json.dumps(info, indent=2)


def selftest_fn() -> None:
    info = iface_state("lo")
    check(info["found"], "loopback must exist")
    check(info["state"] == "UNKNOWN" or info["state"] == "UP", f"unexpected {info}")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
