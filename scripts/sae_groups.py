#!/usr/bin/env python3
"""Report which SAE groups the AP accepts.

Passively observes SAE commits directed at the BSSID and records the
group identifiers. A group not on this list (19, 20, 21) that still
answers is unusual and worth naming; a missing group is named missing,
not implied.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"
KNOWN = (19, 20, 21)


def group_of(commit_payload: bytes) -> int | None:
    # SAE commit: group(2) scalar...
    try:
        return struct.unpack(">H", commit_payload[:2])[0]
    except (struct.error, IndexError):
        return None


def observe(bssid: str, iface: str | None, seconds: int) -> dict:
    try:
        from scapy.all import Dot11, EAPOL, Raw, sniff
    except ImportError:
        return {"state": State.BLOCKED, "evidence": "scapy not installed", "groups": []}
    groups = Counter()

    def on_pkt(pkt) -> None:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11) and pkt.addr2 == bssid:
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            g = group_of(payload)
            if g is not None:
                groups[g] += 1

    sniff(iface=iface, timeout=seconds, prn=on_pkt, store=False)
    return {"state": State.CONFIRMED if groups else State.TESTED,
            "evidence": (f"groups observed: {sorted(groups)}" if groups
                          else f"no SAE commits observed from {bssid}"),
            "groups": sorted(groups)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bssid")
    ap.add_argument("--groups", default="19,20,21")
    ap.add_argument("--iface")
    ap.add_argument("--seconds", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.bssid:
        ap.error("--bssid is required unless --selftest is given")
    report = Report("sae_groups", VERSION, target=args.bssid)
    result = observe(args.bssid, args.iface, args.seconds)
    report.note("sae groups", result["state"],
                "high" if result["state"] == State.CONFIRMED else "info", result["evidence"])
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    check_eq(group_of(struct.pack(">H", 19) + b"\x00" * 64), 19)
    check(group_of(b"\x00") is None, "short payload must fail")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
