#!/usr/bin/env python3
"""Probe a WebLogic server's T3 protocol by performing its real handshake.

T3 has a peculiar greeting: the client announces its version and the server
answers HELO or fails. A T3 endpoint is a Remote JNDI surface -- the same one
used to carry a serialized payload. Confirming it is the handshake, not any
part of the payload path.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Finding, Report, State, check, check_eq, selftest as engine_selftest,
)

VERSION = "2.0.0"
GREETING = (
    "t3 12.2.1\n"
    "AS:255\n"
    "HL:19\n"
    "MS:10000000\n"
    "PU:t3://{host}:{port}\n"
    "\n"
)


def probe(host: str, port: int, timeout: float = 6.0) -> tuple[str, str]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return State.UNREACHABLE, f"no route to {host}:{port}: {exc}"
    try:
        sock.settimeout(timeout)
        sock.sendall(GREETING.format(host=host, port=port).encode())
        reply = sock.recv(4096)
        if reply.startswith(b"HELO"):
            server = reply.split(b"\n", 1)[0].decode(errors="replace").strip()
            return State.CONFIRMED, f"T3 endpoint confirmed: {server}"
        if reply.startswith(b"ERR"):
            return State.CONFIRMED, f"server rejected the greeting as T3-invalid: {reply[:60]!r}"
        if reply:
            return State.TESTED, f"port answered {reply[:40]!r}, not a T3 shape"
        return State.TESTED, "port answered with nothing"
    except (socket.timeout, OSError) as exc:
        return State.FAILED, f"probe failed: {exc}"
    finally:
        sock.close()


def selftest_fn() -> None:
    import threading
    # A real T3-shaped server on loopback: read the greeting, answer HELO.
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        conn, _ = listener.accept()
        try:
            data = conn.recv(2048)
            assert data.startswith(b"t3 "), f"greeting wrong: {data[:40]!r}"
            conn.sendall(b"HELO:10.3.6\nAS:2048\nHL:19\nMS:10000000\nPU:t3://x\n\n")
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state, evidence = probe("127.0.0.1", port)
    check_eq(state, State.CONFIRMED, evidence)
    # a closed port must be unreachable
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    state, _ = probe("127.0.0.1", closed_port)
    check_eq(state, State.UNREACHABLE)


def selftest() -> None:
    selftest_fn()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=7001)
    ap.add_argument("--out", help="write the JSON report here")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.host:
        ap.error("--host is required unless --selftest is given")
    report = Report("t3_probe", VERSION, target=f"{args.host}:{args.port}")
    state, evidence = probe(args.host, args.port)
    report.note("T3 handshake", state,
                "high" if state == State.CONFIRMED else "info", evidence)
    from tsec_engine import emit
    emit(report, args.json, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
