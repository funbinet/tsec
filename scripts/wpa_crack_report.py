#!/usr/bin/env python3
"""Count the parts of a WPA capture that a cracker needs.

hashcat 22000 lines for WPA have four message types. This counts them and
the distinct APs/clients so the report states what the capture actually
contains -- rather than claiming the password is recoverable.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def analyze(path: Path) -> dict:
    kinds = Counter()
    aps = set()
    clients = set()
    for line in path.read_text(errors="replace").splitlines():
        parts = line.strip().split("*")
        if len(parts) != 6 or parts[0] != "WPA":
            continue
        kinds[parts[1]] += 1
        aps.add(parts[3])
        clients.add(parts[4])
    return {"lines": sum(kinds.values()), "by_type": dict(kinds),
            "distinct_aps": len(aps), "distinct_clients": len(clients)}


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
    info = analyze(Path(args.src))
    report = Report("wpa_crack_report", VERSION)
    report.note("capture composition", State.CONFIRMED, "info",
                f"{info['lines']} line(s), {info['distinct_aps']} AP(s), {info['distinct_clients']} client(s)")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    text = ("WPA*01*" + "ab" * 16 + "*aabbccddeeff*112233445566*6f6666696365\n") * 2 \
        + "WPA*02*" + "ab" * 16 + "*aabbccddeeff*112233445566*6f6666696365\n"
    with tempfile.NamedTemporaryFile("w", suffix=".22000", delete=False) as f:
        f.write(text)
    info = analyze(Path(f.name))
    check_eq(info["lines"], 3)
    check_eq(info["distinct_aps"], 1)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
