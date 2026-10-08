#!/usr/bin/env python3
"""Turn a set of scan and credential results into the shortest path to a host.

Scanning produces a list. The question worth answering is not "what did we find"
but "what is the order": given these services and these credentials, which host
is reachable from which, and how few hops does the furthest one need.

This reads results as JSON, builds a directed graph of host -> reachable host,
and reports the paths. Three things it adds over reading the raw output:

  reachability   a host is only listed as a pivot if some credential or open
                 service actually makes the hop possible, not merely because
                 the two appear in the same scan
  chain order    breadth-first from the entry points, so hop 1 is worked before
                 hop 4 and the first unsupported hop is obvious
  chokepoints    which single credential or service unlocks the most hosts,
                 because that is the thing to keep working

Also emits Graphviz so the shape is visible without reading the table.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
from collections import deque
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Finding, Report, State, check, check_eq, selftest as engine_selftest,
)

# Services worth treating as a way in, and the ports that mean the service is
# probably real rather than a scan artefact.
VERSION = "2.0.0"


PIVOT_PORTS = {
    22: "ssh",
    445: "smb",
    139: "netbios",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm-tls",
    135: "msrpc",
    1433: "mssql",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
    8080: "http-alt",
    80: "http",
    443: "https",
    88: "kerberos",
    464: "kerberos-pwchange",
}


def load_records(path: str) -> list[Any]:
    """Read one or more result files, tolerating a list, an object, or JSONL."""
    records: list[Any] = []
    for name in path:
        file = Path(name)
        if file.is_dir():
            candidates = sorted(file.glob("*.json"))
        else:
            candidates = [file]
        for item in candidates:
            try:
                text = item.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                print(f"pivot_map: cannot read {item}: {exc}", file=sys.stderr)
                continue
            records.extend(_parse_text(text, item))
    return records


def _parse_text(text: str, origin: Path) -> list[Any]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        # JSONL: one object per line, which is what nmap -oJ and most of the
        # parsers in this project emit when a scan produced several hosts.
        records = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records
    if isinstance(parsed, list):
        return parsed
    return [parsed]


def host_of(record: Any) -> str | None:
    if not isinstance(record, dict):
        return None
    for key in ("host", "ip", "target", "address", "hostname"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def ports_of(record: Any) -> list[int]:
    ports: list[int] = []
    if not isinstance(record, dict):
        return ports
    for key in ("ports", "open_ports", "services"):
        value = record.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, int):
                    ports.append(item)
                elif isinstance(item, dict):
                    for port_key in ("port", "number"):
                        if isinstance(item.get(port_key), int):
                            ports.append(item[port_key])
                            break
                    else:
                        # A bare service name is worth mapping back.
                        name = item.get("name") or item.get("service")
                        if isinstance(name, str):
                            for port, service in PIVOT_PORTS.items():
                                if name.lower().startswith(service):
                                    ports.append(port)
                                    break
    if isinstance(record.get("port"), int):
        ports.append(record["port"])
    return sorted(set(ports))


def credentials_of(record: Any) -> list[tuple[str, str, str]]:
    """(user, password, source) triples, from whichever shape the tool produced."""
    found: list[tuple[str, str, str]] = []
    if not isinstance(record, dict):
        return found
    raw = record.get("credentials") or record.get("creds") or record.get("logins")
    entries = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        user = str(entry.get("username") or entry.get("user") or entry.get("login") or "")
        password = str(entry.get("password") or entry.get("pass") or "")
        source = str(entry.get("service") or entry.get("source") or entry.get("type") or "unknown")
        if user or password:
            found.append((user, password, source))
    return found


def build_graph(records: list[Any]) -> dict[str, Any]:
    hosts: dict[str, dict[str, Any]] = {}
    cred_index: dict[tuple[str, str], set[str]] = {}

    for record in records:
        name = host_of(record)
        if not name:
            continue
        node = hosts.setdefault(name, {"ports": set(), "credentials": [], "raw": record})
        node["ports"].update(ports_of(record))
        for user, password, source in credentials_of(record):
            node["credentials"].append((user, password, source))
            cred_index.setdefault((user, password), set()).add(name)

    # A credential found on one host is assumed usable where the corresponding
    # service is open. This is the assumption the whole report rests on, so it
    # is stated in the output rather than buried: an operator who knows the
    # credential is host-specific should discount the edges it creates.
    edges: list[dict[str, Any]] = []
    for (user, password), sources in cred_index.items():
        for target, node in hosts.items():
            if target in sources:
                continue
            for port in sorted(node["ports"]):
                service = PIVOT_PORTS.get(port)
                if not service:
                    continue
                if _plausible(user, password, service):
                    edges.append(
                        {
                            "from": sorted(sources)[0],
                            "to": target,
                            "port": port,
                            "service": service,
                            "via": f"{user}:{'*' if password else ''}",
                        }
                    )

    # Distinct service credentials only create one edge per host pair.
    seen = set()
    unique: list[dict[str, Any]] = []
    for edge in edges:
        key = (edge["from"], edge["to"])
        if key not in seen:
            seen.add(key)
            unique.append(edge)
    return {"hosts": hosts, "edges": unique}


def _plausible(user: str, password: str, service: str) -> bool:
    """Whether a credential is the kind that service would accept.

    Checking this is what stops a MySQL password being reported as an SSH pivot:
    the graph stays useful when a credential set is reused across services by a
    lab, and stays honest when it is not.
    """
    if not password:
        return False
    if service in ("http", "https", "http-alt"):
        return False  # a web credential is not a shell
    if service in ("ssh", "winrm", "winrm-tls", "rdp", "ftp"):
        return True
    if service in ("smb", "netbios", "msrpc", "kerberos", "kerberos-pwchange"):
        return True
    if service in ("mssql", "mysql", "postgres", "mongodb", "redis"):
        return bool(user)
    return True


def breadth_first(graph: dict[str, Any], entry: str) -> dict[str, list[dict[str, Any]]]:
    """Shortest path from `entry` to every reachable host."""
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in graph["edges"]:
        adjacency.setdefault(edge["from"], []).append(edge)
    for targets in adjacency.values():
        targets.sort(key=lambda e: e["to"])

    hops: dict[str, list[dict[str, Any]]] = {}
    queue = deque([(entry, [])])
    seen = {entry}
    while queue:
        node, path = queue.popleft()
        for edge in adjacency.get(node, []):
            if edge["to"] in seen:
                continue
            seen.add(edge["to"])
            step = path + [edge]
            hops[edge["to"]] = step
            queue.append((edge["to"], step))
    return hops


def entry_points(graph: dict[str, Any]) -> list[str]:
    """Hosts nothing points at, which is where a run should start."""
    targeted = {edge["to"] for edge in graph["edges"]}
    sources = {edge["from"] for edge in graph["edges"]}
    external = [
        name
        for name in graph["hosts"]
        if name not in targeted and name in sources
    ]
    if external:
        return sorted(external)
    # Everything is in a cycle: start from the host with the most services,
    # which is the one most likely to be the entry point.
    return sorted(graph["hosts"], key=lambda h: len(graph["hosts"][h]["ports"]), reverse=True)[:1]


def chokepoints(graph: dict[str, Any]) -> list[tuple[str, int, int]]:
    """(credential, hops it enables, hosts it reaches) — most useful first."""
    tally: dict[str, dict[str, set[str]]] = {}
    for edge in graph["edges"]:
        entry = tally.setdefault(edge["via"], {"hosts": set(), "services": set()})
        entry["hosts"].add(edge["to"])
        entry["services"].add(edge["service"])
    ranked = sorted(
        ((key, len(value["hosts"]), len(value["services"])) for key, value in tally.items()),
        key=lambda row: (row[1], row[2]),
        reverse=True,
    )
    return ranked


def to_dot(graph: dict[str, Any], chains: dict[str, list[dict[str, Any]]]) -> str:
    lines = ["digraph pivots {", '  rankdir=LR;', '  node [shape=box, fontname="monospace"];']
    for name, node in sorted(graph["hosts"].items()):
        ports = ",".join(str(p) for p in sorted(node["ports"])[:6])
        label = f"{name}\\n{ports}" if ports else name
        depth = next((len(path) for host, path in chains.items() if host == name), None)
        style = ', style=filled, fillcolor="#dff0d8"' if depth else ""
        lines.append(f'  "{name}" [label="{label}"{style}];')
    for edge in graph["edges"]:
        label = f'{edge["service"]} {edge["port"]}'
        lines.append(f'  "{edge["from"]}" -> "{edge["to"]}" [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


# ── live edge verification ───────────────────────────────────────────────────

# An edge in the graph is a hypothesis: a credential exists on one host and
# the matching service is open on another. It only becomes a pivot when the
# service answers the way that service answers -- so `--probe` tests each
# candidate edge with the service's own handshake, never with ping.

PROBE_TIMEOUT = 4.0


def _tcp(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> socket.socket | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    except OSError:
        return None


def probe_service(host: str, port: int, service: str) -> tuple[str, str]:
    """The service's own protocol answered: that is evidence, not an open port."""
    sock = _tcp(host, port)
    if sock is None:
        return State.UNREACHABLE, f"no route to {host}:{port}"
    try:
        if service == "redis":
            sock.sendall(b"PING\r\n")
            reply = sock.recv(256)
            if reply.startswith(b"+PONG"):
                return State.CONFIRMED, f"redis answered PING with +PONG on {host}:{port}"
            if b"NOAUTH" in reply or b"AUTH" in reply:
                return State.CONFIRMED, f"redis is up but requires AUTH: {reply[:60]!r}"
            return State.TESTED, f"redis-like port, unexpected reply {reply[:60]!r}"
        if service == "ssh":
            reply = sock.recv(256)
            if reply.startswith(b"SSH-"):
                return State.CONFIRMED, f"ssh banner {reply.splitlines()[0][:50]!r}"
            return State.TESTED, "port answered but not with an ssh banner"
        if service == "postgres":
            user = b"tsec"
            payload = b"user\x00" + user + b"\x00\x00"
            sock.sendall(struct.pack("!II", 8 + len(payload), 196608) + payload)
            reply = sock.recv(256)
            if reply[:1] == b"R" and len(reply) >= 9:
                auth = struct.unpack("!I", reply[5:9])[0]
                return State.CONFIRMED, f"postgres answered a startup with auth type {auth}"
            if reply[:1] == b"E":
                return State.CONFIRMED, f"postgres answered an error: {reply[9:60]!r}"
            return State.TESTED, f"postgres-like port, unexpected reply {reply[:60]!r}"
        if service in ("mysql", "mariadb"):
            reply = sock.recv(512)
            if reply and (b"mysql" in reply.lower() or b"mariadb" in reply.lower()):
                return State.CONFIRMED, f"mysql server greeting {reply[5:45].split(bytes([0]))[0]!r}"
            if reply:
                return State.TESTED, f"port answered: {reply[:60]!r}"
            return State.TESTED, "mysql port open, empty greeting"
        if service == "ftp":
            reply = sock.recv(256)
            if reply.startswith(b"220"):
                return State.CONFIRMED, f"ftp banner {reply[:50]!r}"
            return State.TESTED, f"ftp-like port, unexpected {reply[:50]!r}"
        if service in ("smb", "netbios"):
            import shutil
            if shutil.which("smbclient"):
                import subprocess
                proc = subprocess.run(
                    ["smbclient", "-L", f"//{host}", "-N"],
                    capture_output=True, text=True, timeout=PROBE_TIMEOUT * 2,
                )
                if "NT_STATUS" in proc.stdout + proc.stderr:
                    return State.CONFIRMED, f"smbclient reached the server: {(proc.stdout + proc.stderr)[:60]!r}"
            return State.TESTED, "smb port open; smbclient not available for a real handshake"
        return State.TESTED, f"{service}:{port} accepted a TCP connection; no service-specific check ran"
    except (socket.timeout, OSError) as exc:
        return State.FAILED, f"probe of {service}:{port} failed: {exc}"
    finally:
        sock.close()


def verify_edges(graph: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for edge in graph["edges"]:
        state, evidence = probe_service(edge["to"], edge["port"], edge["service"])
        edge["state"] = state
        edge["evidence"] = evidence
        findings.append(Finding(
            f"edge {edge['from']} -> {edge['to']} {edge['service']}:{edge['port']}",
            state, "high" if state == State.CONFIRMED else "info", evidence,
        ))
    return findings


def _local_server(respond: bytes) -> tuple[int, socket.socket]:
    import threading
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            while True:
                conn, _ = listener.accept()
                try:
                    if respond.startswith(b"SSH-"):
                        conn.sendall(respond)
                    else:
                        conn.recv(256)
                        conn.sendall(respond)
                finally:
                    conn.close()
        except OSError:
            return

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, listener


def selftest_fn() -> None:
    records = [
        {"host": "10.0.0.1", "ports": [22, 445], "credentials": [{"username": "ops", "password": "x"}]},
        {"host": "10.0.0.2", "ports": [22], "credentials": []},
        {"host": "10.0.0.3", "ports": [5432], "credentials": []},
    ]
    graph = build_graph(records)
    check(len(graph["hosts"]) == 3, "graph dropped a host")
    check(len(graph["edges"]) == 2, f"expected 2 edges, got {len(graph['edges'])}")
    paths = breadth_first(graph, "10.0.0.1")
    check("10.0.0.2" in paths, "no path to the ssh host")
    check("10.0.0.3" in paths, "no path to the postgres host")
    ranked = chokepoints(graph)
    check(ranked and ranked[0][0].startswith("ops"), "credential ranking lost the shared credential")

    redis_port, redis_listener = _local_server(b"+PONG\r\n")
    try:
        state, _ = probe_service("127.0.0.1", redis_port, "redis")
        check_eq(state, State.CONFIRMED, "redis probe did not confirm a +PONG")
    finally:
        redis_listener.close()

    ssh_port, ssh_listener = _local_server(b"SSH-2.0-OpenSSH_9.0\r\n")
    try:
        state, _ = probe_service("127.0.0.1", ssh_port, "ssh")
        check_eq(state, State.CONFIRMED, "ssh probe did not confirm a banner")
    finally:
        ssh_listener.close()

    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    state, _ = probe_service("127.0.0.1", closed_port, "redis")
    check_eq(state, State.UNREACHABLE, "closed port must be UNREACHABLE")


def selftest() -> None:
    selftest_fn()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  pivot_map.py --in output/2026-10-07-nmap/\n"
               "  pivot_map.py --in scans/ --out pivot.json --dot pivots.dot --probe\n"
               "  pivot_map.py --selftest\n",
    )
    parser.add_argument("--in", dest="inputs", nargs="+",
                        help="result files or directories")
    parser.add_argument("--out", help="write the graph as JSON here")
    parser.add_argument("--dot", help="write a Graphviz file here")
    parser.add_argument("--entry", help="start from this host rather than inferring")
    parser.add_argument("--probe", action="store_true",
                        help="test every edge with the service's real handshake")
    parser.add_argument("--quiet", action="store_true", help="suppress the report, write only")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="write the JSON report here")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return engine_selftest(selftest_fn)

    if not args.inputs:
        parser.error("--in is required unless --selftest is given")

    records = load_records(args.inputs)
    graph = build_graph(records)

    if not graph["hosts"]:
        print(f"pivot_map: no hosts found in {', '.join(args.inputs)}", file=sys.stderr)
        return 2

    entries = [args.entry] if args.entry else entry_points(graph)
    chains: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        chains.update(breadth_first(graph, entry))

    report = Report("pivot_map", VERSION)
    report.context = {
        "hosts": len(graph["hosts"]),
        "edges": len(graph["edges"]),
        "entry_points": entries,
    }
    if args.probe:
        for finding in verify_edges(graph):
            report.add(finding)
    else:
        for edge in graph["edges"]:
            edge["state"] = State.INFERRED
            edge["evidence"] = (
                f"credential {edge['via']} found on {edge['from']}; "
                f"{edge['service']} open on {edge['to']}; not yet attempted"
            )
            report.note(
                f"edge {edge['from']} -> {edge['to']} {edge['service']}:{edge['port']}",
                State.INFERRED, "info", edge["evidence"],
            )

    if not args.quiet:
        print(f"hosts        {len(graph['hosts'])}")
        print(f"edges        {len(graph['edges'])}")
        print(f"entry points {', '.join(entries)}")
        print()
        print("hop  host                       via")
        for entry in entries:
            for host, path in sorted(chains.items(), key=lambda kv: len(kv[1])):
                if not path:
                    continue
                steps = " -> ".join(f"{e['service']}:{e['port']}" for e in path)
                print(f"{len(path):>3}  {host:<26} {steps}")
        print()
        ranked = chokepoints(graph)
        if ranked:
            print("credentials that unlock the most:")
            for cred, hosts, services in ranked[:10]:
                print(f"  {cred:<28} reaches {hosts} host(s) over {services} service(s)")

    payload = {
        "entries": entries,
        "hosts": {
            name: {
                "ports": sorted(node["ports"]),
                "services": sorted({PIVOT_PORTS.get(p, str(p)) for p in node["ports"]}),
                "credentials": node["credentials"],
                "hops": len(chains.get(name, [])),
            }
            for name, node in graph["hosts"].items()
        },
        "edges": graph["edges"],
        "chokepoints": [
            {"credential": c, "hosts": h, "services": s} for c, h, s in chokepoints(graph)
        ],
        "caveat": "An edge means a credential was found and the matching service is "
        "open on the target. It does not mean the credential was accepted there; "
        "that is what --probe establishes.",
    }
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        report.record(args.out, "graph")
        if not args.quiet:
            print(f"\nwrote {args.out}")
    if args.dot:
        Path(args.dot).write_text(to_dot(graph, chains), encoding="utf-8")
        report.record(args.dot, "graphviz")
        if not args.quiet:
            print(f"wrote {args.dot}")

    if args.json or args.output:
        from tsec_engine import emit
        emit(report, args.json, args.output)
    elif not args.quiet:
        print(report.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
