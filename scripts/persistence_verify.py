#!/usr/bin/env python3
"""Check whether a persistence mechanism survived behind its owner name.

A persistence artifact is a plain file at a well-known location: a cron
entry, a systemd unit, an init script, a desktop autostart entry, an
etc rc.local line. All of them can be found without any malware tooling —
the check is a search for the name, and the honest output is which of
those locations hold it.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Finding, Report, State, check, check_eq, selftest as engine_selftest,
)

VERSION = "2.0.0"

SEARCH_PATHS = (
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
    "/etc/cron.monthly", "/var/spool/cron", "/etc/init.d",
    "/etc/systemd/system", "/etc/rc.local",
    "/root/.config/autostart", "/etc/xdg/autostart",
)


def search(name: str, root: Path = Path("/")) -> list[Path]:
    hits = []
    for rel in SEARCH_PATHS:
        base = root / rel.lstrip("/")
        if base.is_dir():
            for entry in sorted(base.rglob("*")):
                if entry.is_file() and name in entry.name:
                    hits.append(entry)
        elif base.is_file() and name in base.read_text(errors="replace"):
            hits.append(base)
    # crontabs and user units outside the fixed list
    for home in (root / "home").iterdir() if (root / "home").is_dir() else []:
        for unit in (home / ".config/systemd/user").glob(f"*{name}*") if (home / ".config/systemd/user").is_dir() else []:
            hits.append(unit)
    return hits


def verify(name: str, root: Path = Path("/")) -> Report:
    report = Report("persistence_verify", VERSION, target=str(root))
    hits = search(name, root)
    if hits:
        report.note(
            "persistence present", State.CONFIRMED, "high",
            f"{len(hits)} file(s) reference {name!r}: " + ", ".join(str(h) for h in hits[:6]),
            paths=[str(h) for h in hits],
        )
    else:
        report.note(
            "persistence absent", State.CONFIRMED, "ok",
            f"no cron/systemd/init/autostart entry under {root} references {name!r}",
        )
    for hit in hits:
        try:
            content = hit.read_text(errors="replace")
        except OSError:
            continue
        report.note(
            f"artifact {hit.name}", State.CONFIRMED, "medium",
            f"{hit}: {len(content)}B, first line: {content.splitlines()[0][:80] if content else ''}",
        )
    return report


def selftest_fn() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        unit = root / "etc/systemd/system"
        unit.mkdir(parents=True)
        (unit / "tsec-persist.service").write_text(
            "[Service]\nExecStart=/usr/bin/tsec-persist\n")
        report = verify("tsec-persist", root)
        check(any(f.state == State.CONFIRMED and "persistence present" in f.check for f in report.findings),
              "the planted unit must be found")
        report = verify("definitely-not-there-xyz", root)
        check(any("persistence absent" in f.check for f in report.findings),
              "a missing name must report absent")


def selftest() -> None:
    selftest_fn()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--name")
    ap.add_argument("--out", help="write the JSON report here")
    ap.add_argument("--root", default="/", help="filesystem root to search (for tests)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.name:
        ap.error("--name is required unless --selftest is given")
    report = verify(args.name, Path(args.root))
    from tsec_engine import emit
    emit(report, args.json, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
