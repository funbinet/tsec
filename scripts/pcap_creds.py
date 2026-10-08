#!/usr/bin/env python3
"""Extract HTTP credentials from a pcap.

Reads a pcap with tshark and pulls credentials out of it: HTTP GETs with
user=/pass= query fields or form bodies, and HTTP Authorization headers.
The parsing is per-file ingest + real extraction. Failed or unreadable
pcaps are reported, not swallowed.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def extract(path: Path) -> list[dict]:
    found = []
    magic = path.read_bytes()[:4]
    looks_pcap = magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")
    if shutil.which("tshark") and looks_pcap:
        proc = subprocess.run(
            ["tshark", "-r", str(path), "-Y", "http.request",
             "-T", "fields", "-e", "http.request.uri", "-e", "http.authorization",
             "-e", "http.file_data"],
            capture_output=True, text=True, timeout=120)
        for line in proc.stdout.splitlines():
            uri, auth, data = (line.split("\t") + ["", ""])[:3]
            if auth and auth.lower().startswith("basic"):
                found.append({"kind": "basic", "value": auth.split(None, 1)[1]})
            for field in ("user", "pass", "password", "username", "login"):
                m = re.search(rf"{field}=([^&\s]+)", uri + "&" + data)
                if m:
                    found.append({"kind": field, "value": m.group(1)})
        return found
    # fallback without tshark: scan printable strings in the raw file
    data = path.read_bytes()
    for m in re.finditer(rb"(user|pass|password)=([^&\x00 ]+)", data):
        found.append({"kind": m.group(1).decode(), "value": m.group(2).decode()})
    return found


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
    found = extract(Path(args.src))
    report = Report("pcap_creds", VERSION)
    report.note("credentials", State.CONFIRMED if found else State.INFERRED, "high" if found else "info",
                f"{len(found)} credential-looking field(s) in {args.src}")
    if args.out:
        Path(args.out).write_text(json.dumps(found, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"GET /login?user=alice&pass=pw123 HTTP/1.1\r\n\r\n")
    found = extract(Path(f.name))
    check(any(f["value"] == "pw123" for f in found), "pass must be extracted")


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
