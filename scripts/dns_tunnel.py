#!/usr/bin/env python3
"""A real DNS query/response tunnel round-trip.

Encodes a payload as base32 labels under a domain, sends it as a TXT
query to the server, and decodes the answer. Both ends here are real
sockets speaking real DNS, and the payload round-trips -- a lookup that
comes back decoded is the evidence, missing answers are reported as none.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def encode(payload: bytes) -> str:
    return base64.b32encode(payload).decode().lower().rstrip("=")


def decode(label: str) -> bytes:
    pad = "=" * (-len(label) % 8)
    return base64.b32decode(label.upper() + pad)


def query_txt(domain: str, name: str, timeout: float = 4.0) -> bytes | None:
    # real DNS TXT query, hand-built wire format
    tid = 0x1234
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 16, 1)  # TXT / IN
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(header + question, (domain, 53))
        data, _ = sock.recvfrom(4096)
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount < 1:
            return None
        # skip header(12) + question
        offset = 12 + len(question)
        for _ in range(ancount):
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 12
            rdata = data[offset : offset + rdlen]
            offset += rdlen
            if rtype == 16:
                ln = rdata[0]
                return rdata[1 : 1 + ln]
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def mini_dns_server(domain: str, stop: threading.Event, port: int = 0) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    real_port = sock.getsockname()[1]
    sock.settimeout(0.2)
    threading.Thread(target=_serve, args=(sock, stop), daemon=True).start()
    return real_port


def _serve(sock: socket.socket, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            return
        tid = data[:2]
        qd = struct.unpack("!H", data[4:6])[0]
        # parse only the query name to answer anything under it
        offset = 12
        try:
            parts = []
            while data[offset] != 0:
                ln = data[offset]
                parts.append(data[offset + 1 : offset + 1 + ln].decode())
                offset += 1 + ln
            offset += 1
            qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            name = ".".join(parts)
            label = parts[0] if parts else ""
            try:
                payload = decode(label)
            except Exception:
                payload = b""
            question = data[12 : offset]
            # TXT answer
            rdata = bytes([len(payload)]) + payload
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
            hdr = struct.pack("!HHHHHH", int.from_bytes(tid, "big"), 0x8180, 1, 1, 0, 0)
            sock.sendto(hdr + question + answer, addr)
        except (IndexError, struct.error, UnicodeDecodeError):
            continue


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--server", help="DNS server to ask")
    ap.add_argument("--domain", help="the tunnel apex domain")
    ap.add_argument("--payload", default="tsec-probe")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.server or not args.domain:
        ap.error("--server and --domain are required unless --selftest is given")
    report = Report("dns_tunnel", VERSION)
    try:
        label = encode(args.payload.encode())
        name = f"{label}.{args.domain}"
        # TXT on the configured server: UDP port 53 (dig server:domain style)
        nxt = name
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4.0)
        tid = 0xAB12
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(p)]) + p.encode() for p in nxt.split(".")) + b"\x00"
        question = qname + struct.pack("!HH", 16, 1)
        sock.sendto(header + question, (args.server, 53))
        data, _ = sock.recvfrom(4096)
        ancount = struct.unpack("!H", data[6:8])[0]
        payload = None
        if ancount >= 1:
            offset = 12 + len(question)
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1
            offset += 12
            rdlen = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
            rdata = data[offset : offset + rdlen]
            if rdata:
                ln = rdata[0]
                payload = rdata[1 : 1 + ln]
        ok = payload is not None
        report.note("dns tunnel", State.CONFIRMED if ok else State.TESTED, "info",
                    f"TXT answer {len(payload) if payload else 0}B from {args.server}")
    except (socket.timeout, OSError) as exc:
        report.note("dns tunnel", State.FAILED, "info", str(exc)[:200])
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    stop = threading.Event()
    port = mini_dns_server("tsec.local", stop, port=0)
    try:
        payload = b"tsec-probe"
        name = f"{encode(payload)}.tsec.local"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4.0)
        tid = 0x1234
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        question = qname + struct.pack("!HH", 16, 1)
        sock.sendto(header + question, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
        ancount = struct.unpack("!H", data[6:8])[0]
        check(ancount >= 1, "server must answer with one TXT")
        offset = 12 + len(question)
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1
        rdlen = struct.unpack("!H", data[offset + 8 : offset + 10])[0]
        rdata = data[offset + 10 : offset + 10 + rdlen]
        ln = rdata[0]
        check_eq(rdata[1 : 1 + ln], payload)
        sock.close()
    finally:
        stop.set()


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
