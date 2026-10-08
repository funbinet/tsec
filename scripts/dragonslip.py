#!/usr/bin/env python3
"""Look for Dragonblood-style SAE scalar anomalies passively.

The Dragonslip class of bug shows up as SAE commit frames whose scalar
field sits outside the expected range for the advertised group. This
passively watches the target BSSID's SAE commits and reports the
anomalous ones it sees. It does not inject: passive observation only, so
a negative is an absence of evidence and is stated as such.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"

EXPECTED = {19: (32, 64), 20: (48, 96), 21: (66, 132)}  # scalar byte-length bounds


def anomaly(commit_payload: bytes) -> bool:
    if len(commit_payload) < 2:
        return False
    group = struct.unpack(">H", commit_payload[:2])[0]
    bounds = EXPECTED.get(group)
    if bounds is None:
        return True  # unknown group is itself anomalous
    scalar_len = len(commit_payload) - 2
    return not (bounds[0] <= scalar_len <= bounds[1])


def watch(bssid: str, iface: str | None, seconds: int) -> dict:
    try:
        from scapy.all import Dot11, EAPOL, Raw, sniff
    except ImportError:
        return {"state": State.BLOCKED, "evidence": "scapy not installed", "anomalies": 0}
    anomalies = 0
    seen = 0

    def on_pkt(pkt) -> None:
        nonlocal anomalies, seen
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11) and pkt.addr2 == bssid:
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            seen += 1
            if anomaly(payload):
                anomalies += 1

    sniff(iface=iface, timeout=seconds, prn=on_pkt, store=False)
    return {"state": State.CONFIRMED if anomalies else State.TESTED,
            "evidence": f"{seen} SAE commit(s) from {bssid}, {anomalies} anomalous scalar(s)",
            "anomalies": anomalies, "seen": seen}


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
    report = Report("dragonslip", VERSION, target=args.bssid)
    result = watch(args.bssid, args.iface, args.seconds)
    report.note("dragonslip scalar check", result["state"],
                "high" if result["state"] == State.CONFIRMED else "info", result["evidence"])
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    check(anomaly(struct.pack(">H", 19) + b"\x00" * 8), "short scalar must be anomalous")
    check(not anomaly(struct.pack(">H", 19) + b"\x00" * 48), "valid-length scalar must pass")
    check(anomaly(struct.pack(">H", 99) + b"\x00" * 48), "unknown group must be anomalous")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
