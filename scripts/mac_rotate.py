#!/usr/bin/env python3
"""Rotate a wireless interface's MAC address.

Brings the interface down, sets a new locally-administered MAC, and
brings it back up -- the real randomisation+re-association path, not a
flag file. The new MAC is generated with the locally-administered bit set
so it never collides with a real OUI.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def new_mac() -> str:
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFC) | 0x02  # locally administered, unicast
    return ":".join(f"{o:02x}" for o in octets)


def rotate_once(iface: str) -> tuple[str, str]:
    mac = new_mac()
    for argv in (["ip", "link", "set", iface, "down"],
                 ["ip", "link", "set", iface, "address", mac],
                 ["ip", "link", "set", iface, "up"]):
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        if proc.returncode != 0:
            return State.FAILED, f"{' '.join(argv)}: {proc.stderr.strip()[:120]}"
    return State.USED, f"{iface} MAC rotated to {mac}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iface")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.iface:
        ap.error("--iface is required unless --selftest is given")
    report = Report("mac_rotate", VERSION, target=args.iface)
    for i in range(args.count):
        state, evidence = rotate_once(args.iface)
        report.note(f"rotation {i + 1}", state, "high" if state == State.USED else "info", evidence)
        if state == State.FAILED:
            break
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    mac = new_mac()
    check(len(mac) == 17, mac)
    check((int(mac.split(":")[0], 16) & 0x02) == 0x02, "locally-administered bit must be set")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
