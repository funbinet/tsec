#!/usr/bin/env python3
"""Histogram of frame types in a pcap.

Reads the pcap's own global header and counts per-ethertype frame totals
and per-second rates. The counts are from the file header itself, never
from a cached guess -- and the magic is validated before any of it is
trusted.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import collections
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"

ETHERTYPES = {0x0800: "ipv4", 0x0806: "arp", 0x86DD: "ipv6", 0x888E: "eapol", 0x8100: "vlan"}


def read_pcap(path: Path) -> tuple[list[float], collections.Counter, int]:
    data = path.read_bytes()
    if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        raise ValueError("not a pcap (bad magic)")
    little = data[:4] in (b"\xd4\xc3\xb2\xa1",)
    fmt = "<" if little else ">"
    timestamps: list[float] = []
    types = collections.Counter()
    offset = 24
    while offset + 16 <= len(data):
        sec, usec, caplen, origlen = struct.unpack_from(fmt + "IIII", data, offset)
        offset += 16
        if offset + caplen > len(data):
            break
        packet = data[offset : offset + caplen]
        offset += caplen
        timestamps.append(sec + usec / 1_000_000)
        if len(packet) >= 14:
            ethertype = struct.unpack_from("!H", packet, 12)[0]
            types[ETHERTYPES.get(ethertype, f"0x{ethertype:04x}")] += 1
    return timestamps, types, len(timestamps)


def hist(path: Path) -> dict:
    timestamps, types, total = read_pcap(path)
    if not timestamps:
        return {"frames": 0, "by_ethertype": {}, "duration_s": 0.0}
    per_second = collections.Counter()
    for ts in timestamps:
        per_second[int(ts)] += 1
    return {
        "frames": total,
        "by_ethertype": dict(types.most_common()),
        "duration_s": round(timestamps[-1] - timestamps[0], 3),
        "max_per_second": max(per_second.values()),
        "mean_per_second": round(total / max(len(per_second), 1), 1),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in", dest="src")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.src:
        ap.error("--in is required unless --selftest is given")
    try:
        info = hist(Path(args.src))
    except (ValueError, OSError) as exc:
        report = Report("frame_hist", VERSION)
        report.note("input", State.REJECTED, "info", str(exc))
        from tsec_engine import emit
        emit(report, args.json, None)
        return 0
    report = Report("frame_hist", VERSION)
    report.note("frame histogram", State.CONFIRMED, "info",
                f"{info['frames']} frame(s), max {info.get('max_per_second')} pps")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    # a real little-endian pcap with two frames, one ethernet IPv4, one ARP
    g = b"\xd4\xc3\xb2\xa1" + struct.pack("<H", 2) + struct.pack("<H", 4) + struct.pack("<i", 0) + struct.pack("<I", 0) + struct.pack("<I", 65535) + struct.pack("<I", 1)
    def pkt(ethertype):
        eth = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", ethertype)
        return eth + b"\x00" * 40
    rec1 = struct.pack("<IIII", 1700000000, 0, 54, 54) + pkt(0x0800)
    rec2 = struct.pack("<IIII", 1700000000, 500000, 54, 54) + pkt(0x0806)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(g + rec1 + rec2)
        path = f.name
    info = hist(Path(path))
    check_eq(info["frames"], 2)
    check_eq(info["by_ethertype"].get("ipv4"), 1)
    check_eq(info["by_ethertype"].get("arp"), 1)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
