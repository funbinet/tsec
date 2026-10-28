#!/usr/bin/env python3
"""Generate a hostapd.conf for the evil-twin surface.

Writes a real hostapd configuration with the requested SSID and channel.
The same file works as-is under hostapd for a controlled lab AP; the check
is that its keys parse as hostapd directives.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def render(ssid: str, channel: int, interface: str = "wlan0", open_network: bool = True) -> str:
    if not ssid:
        raise ValueError("ssid is empty")
    lines = [
        f"interface={interface}",
        "driver=nl80211",
        f"ssid={ssid}",
        f"channel={channel}",
        "hw_mode=g",
        "wmm_enabled=1",
        "macaddr_acl=0",
        "ignore_broadcast_ssid=0",
    ]
    if open_network:
        lines.append("auth_algs=1")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ssid")
    ap.add_argument("--channel", type=int, default=6)
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.ssid:
        ap.error("--ssid is required unless --selftest is given")
    conf = render(args.ssid, args.channel)
    report = Report("hostapd_gen", VERSION)
    report.note("hostapd.conf", State.GENERATED, "info",
                f"ssid {args.ssid!r} on channel {args.channel} ({len(conf)}B)")
    if args.out:
        Path(args.out).write_text(conf)
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    conf = render("TSEC-TEST", 11)
    check("ssid=TSEC-TEST" in conf, "ssid missing")
    check("channel=11" in conf, "channel missing")
    try:
        render("", 6)
        check(False, "empty ssid must be refused")
    except ValueError:
        pass


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
