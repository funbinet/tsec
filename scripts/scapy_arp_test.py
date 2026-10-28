#!/usr/bin/env python3
"""Probe the network for a MAC with a real ARP request.

Sends an ARP who-has for the target and parses the first is-at reply:
that reply is the evidence, and a timeout is the honest negative.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def probe(target: str, iface: str | None, timeout: int = 3) -> tuple[str, str]:
    try:
        from scapy.all import ARP, Ether, srp1
    except ImportError:
        return State.BLOCKED, "scapy not installed"
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    try:
        reply = srp1(pkt, iface=iface, timeout=timeout, verbose=False)
    except Exception as exc:  # noqa: BLE001
        return State.FAILED, str(exc)[:200]
    if reply is None:
        return State.REJECTED, f"no ARP reply for {target} within {timeout}s"
    return State.CONFIRMED, f"{target} is at {reply[Ether].src if reply.haslayer(Ether) else reply.psrc}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iface")
    ap.add_argument("--target")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.target:
        ap.error("--target is required unless --selftest is given")
    report = Report("scapy_arp_test", VERSION, target=args.target)
    state, evidence = probe(args.target, args.iface)
    report.note("arp probe", state, "high" if state == State.CONFIRMED else "info", evidence)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    from scapy.all import ARP, Ether
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.0.2.1")
    check_eq(pkt[ARP].pdst, "192.0.2.1")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
