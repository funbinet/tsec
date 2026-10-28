#!/usr/bin/env python3
"""Probe SQL Server's TDS: real prelogin, real login attempt, real parse.

TDS authentication decisions come from the server's first reply tokens, so
the probe must read them, not infer them from a timeout. This performs a
real prelogin exchange, parses the option tokens for version and
encryption, then sends a real login7 and classifies the first token it
receives back.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Finding, Report, State, check, check_eq, selftest as engine_selftest,
)

VERSION = "2.0.0"
OPT_VERSION = 0
OPT_ENCRYPT = 1
OPT_MARS = 4
OPT_TERMINATOR = 0xFF

TOKEN_ERROR = 0xAA
TOKEN_INFO = 0xAB
TOKEN_LOGINACK = 0xAD
TOKEN_ENVCHANGE = 0xE3


def _packet(packet_type: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHBB", packet_type, 1, len(payload) + 8, 0, 0, 1)
    return header + payload


def build_prelogin() -> bytes:
    version = struct.pack(">BBBBH", 0x11, 0x00, 0x07, 0xD0, 0)
    encrypt = b"\x01"
    mars = b"\x00"
    # option table: three rows (3 * 5 bytes) + terminator
    table_len = 3 * 5 + 1
    rows = (
        bytes([OPT_VERSION]) + struct.pack(">HH", table_len, len(version))
        + bytes([OPT_ENCRYPT]) + struct.pack(">HH", table_len + len(version), len(encrypt))
        + bytes([OPT_MARS]) + struct.pack(">HH", table_len + len(version) + len(encrypt), len(mars))
        + bytes([OPT_TERMINATOR])
    )
    return _packet(0x12, rows + version + encrypt + mars)


def parse_prelogin(payload: bytes) -> dict:
    result: dict[str, object] = {}
    cursor = 0
    rows: list[tuple[int, int, int]] = []
    while cursor + 5 <= len(payload):
        tok = payload[cursor]
        if tok == OPT_TERMINATOR:
            break
        value_off = int.from_bytes(payload[cursor + 1 : cursor + 3], "big")
        length = int.from_bytes(payload[cursor + 3 : cursor + 5], "big")
        rows.append((tok, value_off, length))
        cursor += 5
    for tok, value_off, length in rows:
        raw = payload[value_off : value_off + length] if value_off + length <= len(payload) else b""
        if tok == OPT_VERSION and len(raw) >= 4:
            result["version"] = f"{raw[0]}.{raw[1]}.{struct.unpack('>H', raw[2:4])[0]}"
        elif tok == OPT_ENCRYPT and raw:
            result["encrypt"] = raw[0]
        elif tok == OPT_MARS and raw:
            result["mars"] = raw[0]
    return result


def build_login7(user: str, password: str, server: str) -> bytes:
    # TDS 7.4 login request packet payload. The password is the TDS
    # on-wire obfuscation (nibble swap + 0xA5) -- an encoding, not crypto.
    pw_obf = b""
    for byte in password.encode("utf-16-le"):
        pw_obf += bytes([(((byte ^ 0xA5) & 0x0F) << 4) | ((byte ^ 0xA5) >> 4)])
    fields: list[tuple[int, bytes]] = [
        (0x74000004, b""),  # version goes in fixed slot
    ]
    username = user.encode("utf-16-le")
    server_b = server.encode("utf-16-le")

    def off_len(offset_chars: int, length: int) -> bytes:
        return struct.pack("<HH", offset_chars, length)

    # total length (4) | version (4) | packet size (4) | pid (4) | conn id (4)
    # option flags (1) | tz (4) | locale (4) |
    # username(4) password(4) app(4) server(4) reserved(4) libid(4) lang(4) db(4) |
    # clientid(6) sspi(4) attrs(4)
    fixed = 4 + 4 + 4 + 4 + 4 + 1 + 4 + 4 + 8 * 4 + 6 + 4 + 4
    username_off_chars = fixed // 2
    password_off_chars = (fixed + len(username)) // 2
    server_off_chars = (fixed + len(username) + len(pw_obf)) // 2
    body = b""
    body += struct.pack("<I", fixed + len(username) + len(pw_obf) + len(server_b))
    body += struct.pack("<I", 0x74000004)
    body += struct.pack("<I", 4096)
    body += struct.pack("<I", 0x1000)
    body += struct.pack("<I", 0)
    body += b"\x01" + b"\x00" * 4 + b"\x00" * 4
    body += off_len(username_off_chars, len(username) // 2) + off_len(password_off_chars, len(pw_obf) // 2)
    body += b"\x00\x00\x00\x00" + off_len(server_off_chars, len(server_b) // 2)
    body += b"\x00\x00\x00\x00" * 4
    body += b"\x00" * 6 + b"\x00" * 4 + b"\x00" * 4
    body += username + pw_obf + server_b
    return body


def parse_error(payload: bytes) -> str:
    try:
        number = struct.unpack("<I", payload[0:4])[0] if len(payload) >= 4 else 0
        text_len = int.from_bytes(payload[8:10], "little") if len(payload) >= 10 else 0
        text = payload[10 : 10 + text_len * 2].decode("utf-16-le", errors="replace")
        return f"{number} {text[:80]}"
    except Exception:
        return payload[:40].hex()


def probe(host: str, port: int, user: str, password: str, timeout: float = 6.0) -> tuple[str, str, dict]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return State.UNREACHABLE, f"no route to {host}:{port}: {exc}", {}
    try:
        sock.settimeout(timeout)
        sock.sendall(build_prelogin())
        reply = sock.recv(2048)
        if len(reply) < 8 or reply[0] != 4:
            return State.TESTED, f"server spoke but not TDS (first byte {reply[:1]!r})", {}
        info = parse_prelogin(reply[8:])
        sock.sendall(_packet(1, build_login7(user, password, host)))
        reply2 = sock.recv(2048)
        token = reply2[8] if len(reply2) > 8 else None
        if token == TOKEN_LOGINACK or token == TOKEN_ENVCHANGE:
            return State.USED, "login response token indicates success", info
        if token == TOKEN_ERROR:
            detail = parse_error(reply2[11:])
            if "18456" in detail:
                return State.REJECTED, f"login rejected (18456): bad credentials", info
            return State.TESTED, f"error token: {detail[:120]}", info
        return State.TESTED, f"first login token {token!r}", info
    except (socket.timeout, OSError) as exc:
        return State.FAILED, f"probe failed: {exc}", {}
    finally:
        sock.close()


def selftest_fn() -> None:
    import threading

    def make_prelogin_response() -> bytes:
        version = bytes([0x10, 0x00, 0x00, 0x00]) + b"\x00\x00"
        encrypt = b"\x01"
        mars = b"\x00"
        table_len = 3 * 5 + 1
        rows = (
            bytes([OPT_VERSION]) + struct.pack(">HH", table_len, len(version))
            + bytes([OPT_ENCRYPT]) + struct.pack(">HH", table_len + len(version), len(encrypt))
            + bytes([OPT_MARS]) + struct.pack(">HH", table_len + len(version) + len(encrypt), len(mars))
            + b"\xff"
        )
        return rows + version + encrypt + mars

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        conn, _ = listener.accept()
        try:
            data = conn.recv(2048)
            assert data[0] == 0x12, f"expected prelogin 0x12, got {data[:1]!r}"
            conn.sendall(_packet(4, make_prelogin_response()))
            data2 = conn.recv(4096)
            assert data2[0] == 1, f"expected login packet 1, got {data2[:1]!r}"
            msg = "Login failed for user".encode("utf-16-le")
            tdata = struct.pack("<I", 18456) + b"\x01\x14\x00\x00" + struct.pack("<H", len(msg) // 2) + msg
            err = bytes([TOKEN_ERROR]) + struct.pack("<H", len(tdata)) + tdata
            conn.sendall(_packet(4, err))
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state, evidence, info = probe("127.0.0.1", port, "sa", "badpw")
    check_eq(state, State.REJECTED, evidence)
    check("encrypt" in info, f"prelogin parse must surface encryption, got {info}")


def selftest() -> None:
    selftest_fn()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=1433)
    ap.add_argument("--user", default="")
    ap.add_argument("--pass", dest="password", default="")
    ap.add_argument("--out", help="write the JSON report here")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.host:
        ap.error("--host is required unless --selftest is given")
    report = Report("mssql_probe", VERSION, target=f"{args.host}:{args.port}")
    state, evidence, info = probe(args.host, args.port, args.user, args.password)
    report.note("TDS exchange", state,
                "high" if state == State.USED else "info", evidence, server=info)
    from tsec_engine import emit
    emit(report, args.json, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
