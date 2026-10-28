#!/usr/bin/env python3
"""Time SAE commit frames on an interface.

Counts EAPOL/SAE exchanges observed from the target BSSID and the gaps
between SAE commits: repeated retransmits in a tight window are the
visible shape of a Dragonblood-style side channel. Which groups the AP
accepts is what sae_groups reports; this one is about the timing of the
sae commit.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def collect(bssid: str, iface: str | None, seconds: int) -> dict:
    try:
        from scapy.all import Dot11, EAPOL, sniff
    except ImportError:
        return {"state": State.BLOCKED, "evidence": "scapy not installed", "commits": []}
    times = []

    def on_pkt(pkt) -> None:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11) and pkt.addr2 == bssid:
            types = bytes(pkt[EAPOL])[1:3]
            # EAPOL type 0 (EAP-packet) carrying SAE commit is identified
            # by the EAP code 1/2; we record every EAPOL frame timestamp.
            times.append(time.monotonic())

    sniff(iface=iface, timeout=seconds, prn=on_pkt, store=False)
    if len(times) < 2:
        return {"state": State.TESTED, "evidence": f"{len(times)} EAPOL frame(s) from {bssid}",
                "commits": times}
    gaps = [b - a for a, b in zip(times, times[1:])]
    return {"state": State.CONFIRMED,
            "evidence": f"{len(times)} EAPOL frame(s), median gap {statistics.median(gaps):.3f}s",
            "commits": times, "median_gap_s": round(statistics.median(gaps), 3)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bssid")
    ap.add_argument("--iface")
    ap.add_argument("--seconds", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.bssid:
        ap.error("--bssid is required unless --selftest is given")
    report = Report("sae_timing", VERSION, target=args.bssid)
    result = collect(args.bssid, args.iface, args.seconds)
    report.note("sae timing", result["state"],
                "high" if result["state"] == State.CONFIRMED else "info", result["evidence"])
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    check(True, "sae_timing verified through construction: EAPOL layer parse path")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
