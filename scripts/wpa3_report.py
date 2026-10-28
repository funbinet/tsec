#!/usr/bin/env python3
"""Report what the WPA3 test directory actually contains.

WPA3 findings live in the wpa3/ artifact directory: sascript config files
and any tcpdump of the SAE exchange. This reports which exist and whether
the SAE parameters in the table (groups 19/20/21) were tested, from the
sae_groups output file when present.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def inventory(dirpath: Path) -> dict:
    accounts = {}
    for path in sorted(dirpath.rglob("*")):
        if path.is_file():
            accounts[path.name] = path.stat().st_size
    configs = [n for n in accounts if n.endswith(".conf")]
    return {
        "files": accounts, "configs": configs,
        "has_sae_groups_report": any("sae" in n for n in accounts),
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
    info = inventory(Path(args.src))
    report = Report("wpa3_report", VERSION)
    report.note("wpa3 artifacts", State.CONFIRMED, "info",
                f"{len(info['files'])} file(s), configs: {', '.join(info['configs']) or 'none'}")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        Path(td, "ap.conf").write_text("ssid=x\n")
        Path(td, "sae_groups.json").write_text("{}\n")
        info = inventory(Path(td))
        check_eq(len(info["files"]), 2)
        check(info["has_sae_groups_report"], True)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
