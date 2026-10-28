#!/usr/bin/env python3
"""Validate a WPS PIN's checksum digit.

WPS PINs are eight digits: seven serial digits plus a checksum digit.
The checksum is the standard WPS algorithm: sum the odd-position digits
weighted by three, add the even ones, complement against ten. A PIN that
fails it cannot be one the enrollee was handed.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def check_digit(serial7: str) -> int:
    odd = sum(int(d) for d in serial7[::2])   # positions 1,3,5,7
    even = sum(int(d) for d in serial7[1::2])  # positions 2,4,6
    return (10 - ((3 * odd + even) % 10)) % 10


def valid(pin: str) -> bool:
    if len(pin) != 8 or not pin.isdigit():
        return False
    return int(pin[-1]) == check_digit(pin[:7])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pin")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.pin:
        ap.error("--pin is required unless --selftest is given")
    ok = valid(args.pin)
    report = Report("pin_check", VERSION)
    report.note("pin checksum", State.CONFIRMED, "info",
                f"{args.pin}: checksum digit {'valid' if ok else 'invalid'}")
    from tsec_engine import emit
    emit(report, args.json, args.out and None)
    return 0 if ok else 1


def selftest_fn() -> None:
    check_eq(check_digit("1234567"), 0)
    check(valid("12345670"), "12345670 must validate")
    check(not valid("12345671"), "12345671 must not validate")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
