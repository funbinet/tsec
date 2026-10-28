#!/usr/bin/env python3
"""Generate a dnsmasq.conf for the lab AP.

Real dnsmasq directives: a DHCP range, binding to the AP interface, and
not touching the host's DNS unless told to.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def render(dhcp_range: str, interface: str = "wlan0", gateway: str | None = None) -> str:
    parts = [p.strip() for p in dhcp_range.replace(" ", "").split(",")]
    if len(parts) != 2:
        raise ValueError(f"dhcp range must be start,end, got {dhcp_range!r}")
    lines = [
        f"interface={interface}",
        "bind-interfaces",
        f"dhcp-range={parts[0]},{parts[1]},12h",
        "dhcp-option=3" + (f",{gateway}" if gateway else ""),
        "dhcp-option=6" + (f",{gateway}" if gateway else ""),
        "server=0.0.0.0",
        "no-resolv",
        "log-queries",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dhcp-range", default="10.0.0.10,10.0.0.100")
    ap.add_argument("--gateway")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    conf = render(args.dhcp_range, gateway=args.gateway)
    report = Report("dnsmasq_gen", VERSION)
    report.note("dnsmasq.conf", State.GENERATED, "info", f"dhcp range {args.dhcp_range}")
    if args.out:
        Path(args.out).write_text(conf)
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    conf = render("10.0.0.10,10.0.0.100", gateway="10.0.0.1")
    check("dhcp-range=10.0.0.10,10.0.0.100,12h" in conf, "range missing")
    check("dhcp-option=3,10.0.0.1" in conf, "gateway option missing")
    try:
        render("bogus")
        check(False, "a bogus range must be refused")
    except ValueError:
        pass


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
