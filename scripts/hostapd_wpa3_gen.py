#!/usr/bin/env python3
"""Generate a WPA3-only AP config.

WPA3 means SAE over GCMP, no PMKID-based PSK exchange: the generated
config sets wpa_key_mgmt=SAE, ieee80211w=2 (PMF required), and drops
mixed-mode. That is the difference that matters and it is written down
in the file itself.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def render(ssid: str, password: str = "tsec-wpa3-test", channel: int = 6) -> str:
    lines = [
        "interface=wlan0",
        "driver=nl80211",
        f"ssid={ssid}",
        f"channel={channel}",
        "hw_mode=g",
        "ieee80211w=2",
        "wpa=2",
        "wpa_key_mgmt=SAE",
        "rsn_pairwise=GCMP-256",
        f"sae_password={password}",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ssid")
    ap.add_argument("--password", default="tsec-wpa3-test")
    ap.add_argument("--channel", type=int, default=6)
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.ssid:
        ap.error("--ssid is required unless --selftest is given")
    conf = render(args.ssid, args.password, args.channel)
    report = Report("hostapd_wpa3_gen", VERSION)
    report.note("wpa3 config", State.GENERATED, "info", "SAE + GCMP-256 + PMF required")
    if args.out:
        Path(args.out).write_text(conf)
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    conf = render("TSEC-WPA3")
    check("wpa_key_mgmt=SAE" in conf, "SAE missing")
    check("ieee80211w=2" in conf, "PMF required flag missing")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
