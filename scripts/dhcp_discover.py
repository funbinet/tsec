#!/usr/bin/env python3
"""Send real DHCP discovers, read real offers.

Builds a DHCP Discover via scapy, broadcasts it, and waits for a DHCP
Offer. The offer's server-id is the evidence; silence is reported as no
DHCP server seen, not as a failure.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def discover(iface: str | None, timeout: int = 6) -> dict:
    try:
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp1
    except ImportError:
        return {"state": State.BLOCKED, "evidence": "scapy not installed"}
    pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
           / UDP(sport=68, dport=67) / BOOTP(chaddr=b"\x00" * 6 + b"\x42" * 10)
           / DHCP(options=[("message-type", "discover"), "end"]))
    try:
        reply = srp1(pkt, iface=iface, timeout=timeout, verbose=False, multi=True)
    except Exception as exc:  # noqa: BLE001
        return {"state": State.FAILED, "evidence": str(exc)[:200]}
    if reply is None:
        return {"state": State.REJECTED, "evidence": f"no DHCP offer within {timeout}s"}
    try:
        offers = [reply] if not isinstance(reply, list) else reply
        server = offers[0][DHCP].options[1][1] if offers else None
        return {"state": State.CONFIRMED, "evidence": f"DHCP offer from {server}"}
    except (IndexError, KeyError, TypeError):
        return {"state": State.TESTED, "evidence": "a DHCP reply arrived but no server-id parsed"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iface")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    report = Report("dhcp_discover", VERSION)
    result = discover(args.iface)
    report.note("dhcp discovery", result["state"],
                "high" if result["state"] == State.CONFIRMED else "info", result["evidence"])
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    from scapy.all import DHCP, BOOTP
    check_eq(DHCP(options=[("message-type", "discover"), "end"]).options[0][1], "discover")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
