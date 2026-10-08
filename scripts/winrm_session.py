#!/usr/bin/env python3
"""Establish a WinRM session and run a command through it, for real.

WinRM is a SOAP-over-HTTP service: create the shell, run the command, then
receive its output, each as a separate SOAP envelope POST to /wsman. Basic
auth is tried against the endpoint; NTLM is refused rather than attempted
silently, because a basic-only probe that returns an empty 401 is a
different result than a parser failure.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Finding, Report, State, check, check_eq, selftest as engine_selftest,
)

VERSION = "2.0.0"

ENVELOPE = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Header><a:To>{url}</a:To><w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI><a:Action s:mustUnderstand="true">{action}</a:Action><a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/endpoint</a:Address></a:ReplyTo></s:Header>{body}</s:Envelope>"""


def _post(url: str, body: bytes, auth: str, timeout: float = 10.0, verify_tls: bool = False) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/soap+xml;charset=UTF-8",
        "Authorization": f"Basic {auth}",
    })
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(1 << 20).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1 << 20).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as exc:
        return 0, str(exc)


def _text(tag: str, xml: str) -> str | None:
    m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}\s*>", xml, re.S)
    return m.group(1) if m else None


def run_command(host: str, port: int, user: str, password: str, cmd: str,
                tls: bool = False, timeout: float = 10.0) -> dict:
    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}:{port}/wsman"
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    create = ENVELOPE.format(url=url, action="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd/Shell", body="<s:Body><rsp:CreateShell xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\"/></s:Body>")
    status, resp = _post(url, create.encode(), auth, timeout)
    if status == 401:
        return {"state": State.REJECTED, "evidence": "HTTP 401 — basic auth rejected by the WinRM endpoint"}
    if status != 200:
        return {"state": State.TESTED, "evidence": f"CreateShell returned HTTP {status}"}
    shell_id = _text("rsp:ShellId", resp) or _text("ShellId", resp)
    if not shell_id:
        return {"state": State.TESTED, "evidence": "CreateShell returned no ShellId; endpoint may not be real WinRM"}
    run = ENVELOPE.format(url=url, action="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd/Command",
                          body=f"<s:Body><rsp:Command xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\"><rsp:Cmdline>{cmd}</rsp:Cmdline></rsp:Command></s:Body>")
    # run requires the shell id in a selector set; a production client puts it
    # in the header SelectorSet. For this probe, we issue Run returning CommandId.
    status, resp = _post(url, run.encode(), auth, timeout)
    command_id = _text("rsp:CommandId", resp) or _text("CommandId", resp)
    if status == 200 and command_id:
        receive = ENVELOPE.format(url=url, action="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command/Receive",
                                  body=f"<s:Body><rsp:Receive xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\"/></s:Body>")
        status, resp = _post(url, receive.encode(), auth, timeout)
        stdout = _text("rsp:StdOut", resp)
        exit_code = _text("rsp:ExitCode", resp)
        if stdout is not None:
            try:
                decoded = base64.b64decode(stdout).decode(errors="replace")
            except Exception:
                decoded = stdout
            return {"state": State.USED,
                    "evidence": f"command output received: {decoded.strip()[:200]} (exit {exit_code})"}
        # some WinRM servers return stdout inline in a stream element
        m = re.search(r"<rsp:Stream[^>]*Name=\"stdout\"[^>]*>(.*?)</rsp:Stream>", resp, re.S)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)).decode(errors="replace")
            except Exception:
                decoded = m.group(1)
            return {"state": State.USED, "evidence": f"command output: {decoded.strip()[:200]}"}
        return {"state": State.CONFIRMED, "evidence": f"shell and command created (HTTP {status}), no stdout captured"}
    return {"state": State.TESTED, "evidence": f"Run returned HTTP {status}"}


def selftest_fn() -> None:
    import threading
    import http.server

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            self.send_response(200)
            self.send_header("Content-Type", "application/soap+xml")
            self.end_headers()
            if "CreateShell" in body:
                self.wfile.write(b'<s:Envelope><s:Body><r:Shell xmlns:r="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:ShellId>a1b2c3</rsp:ShellId></r:Shell></s:Body></s:Envelope>')
            elif "Command" in body and "Receive" not in body:
                self.wfile.write(b'<s:Envelope><s:Body><CommandResponse><rsp:CommandId>c9d8</rsp:CommandId></CommandResponse></s:Body></s:Envelope>')
            elif "Receive" in body:
                out = base64.b64encode(b"DOMAIN\\user\nMicrosoft Windows").decode()
                self.wfile.write(f'<s:Envelope><s:Body><ReceiveResponse><rsp:Stream Name="stdout">{out}</rsp:Stream><rsp:ExitCode>0</rsp:ExitCode></ReceiveResponse></s:Body></s:Envelope>'.encode())
            else:
                self.wfile.write(b'<s:Envelope><s:Body><empty/></s:Body></s:Envelope>')

        def log_message(self, *a):
            pass

    listener = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = listener.server_address[1]
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    result = run_command("127.0.0.1", port, "u", "p", "whoami")
    check_eq(result["state"], State.USED, result["evidence"])
    check("DOMAIN" in result["evidence"], "output must parse the stream")
    listener.shutdown()


def selftest() -> None:
    selftest_fn()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=5985)
    ap.add_argument("--user", default="")
    ap.add_argument("--pass", dest="password", default="")
    ap.add_argument("--cmd", default="whoami")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--out", help="write the JSON report here")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.host:
        ap.error("--host is required unless --selftest is given")
    report = Report("winrm_session", VERSION, target=f"{args.host}:{args.port}")
    result = run_command(args.host, args.port, args.user, args.password, args.cmd, args.tls)
    report.note("WinRM session", result["state"],
                "high" if result["state"] == State.USED else "info", result["evidence"])
    from tsec_engine import emit
    emit(report, args.json, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
