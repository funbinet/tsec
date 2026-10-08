#!/usr/bin/env python3
"""Check whether a BSSID's beacon advertises PMF.

Parses the RSN information element in a real beacon/probe response from
the target BSSID and reads the MFPC/MFPR bits -- protected management
frames required/capable are the difference between a deauth working and
not working on a properly configured AP.

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

RSN_IE = 48


def pmf_flags(rsn_ie: bytes) -> dict | None:
    # RSN IE body: version(2) group_cipher(4) pairwise_count(2) pairwise(4N)
    # akm_count(2) akm(4N) rsn_capabilities(2)
    try:
        if len(rsn_ie) < 2 + 4 + 2 + 4 + 2 + 4 + 2:
            return None
        offset = 2
        offset += 4  # group cipher
        pc = struct.unpack("<H", rsn_ie[offset : offset + 2])[0]
        offset += 2 + pc * 4
        ac = struct.unpack("<H", rsn_ie[offset : offset + 2])[0]
        offset += 2 + ac * 4
        caps = struct.unpack("<H", rsn_ie[offset : offset + 2])[0]
        return {"mfpc": bool(caps & 0x80), "mfpr": bool(caps & 0x40)}
    except (IndexError, struct.error):
        return None


def sniff_one(bssid: str, iface: str | None, timeout: int = 8) -> dict:
    try:
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
    except ImportError:
        return {"state": State.BLOCKED, "evidence": "scapy not installed"}
    seen: list[dict] = []

    def on_pkt(pkt) -> None:
        if pkt.haslayer(Dot11Elt) and pkt.addr2 == bssid:
            for elt in pkt[Dot11Elt]:
                if elt.ID == RSN_IE and bytes(elt.info):
                    seen.append(pmf_flags(bytes(elt.info)) or {})
                    return

    sniff(iface=iface, timeout=timeout, prn=on_pkt, store=False)
    if seen:
        flags = seen[0]
        return {"state": State.CONFIRMED,
                "evidence": f"MFPC={flags.get('mfpc')} MFPR={flags.get('mfpr')}"}
    return {"state": State.TESTED, "evidence": f"no RSN IE from {bssid} within {timeout}s"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bssid")
    ap.add_argument("--iface")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.bssid:
        ap.error("--bssid is required unless --selftest is given")
    report = Report("pmf_probe", VERSION, target=args.bssid)
    result = sniff_one(args.bssid, args.iface)
    report.note("pmf flags", result["state"],
                "high" if result["state"] == State.CONFIRMED else "info", result["evidence"])
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    # one pairwise cipher, one AKM, caps 0xC0 -> MFPC+MFPR both set
    body = struct.pack("<H", 1) + b"\x00" * 4 + struct.pack("<H", 1) + b"\x00" * 4 + struct.pack("<H", 1) + b"\x00" * 4 + struct.pack("<H", 0xC0)
    flags = pmf_flags(body)
    check(flags == {"mfpc": True, "mfpr": True}, f"got {flags}")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
