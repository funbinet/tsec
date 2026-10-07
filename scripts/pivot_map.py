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
import sys
from collections import deque
from pathlib import Path
from typing import Any

# Services worth treating as a way in, and the ports that mean the service is
# probably real rather than a scan artefact.
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  pivot_map.py --in output/2026-10-07-nmap/*.json\n"
               "  pivot_map.py --in scans/ --out pivot.json --dot pivots.dot\n",
    )
    parser.add_argument(
        "--in",
        dest="inputs",
        nargs="+",
        required=True,
        help="result files or directories",
    )
    parser.add_argument("--out", help="write the graph as JSON here")
    parser.add_argument("--dot", help="write a Graphviz file here")
    parser.add_argument("--entry", help="start from this host rather than inferring")
    parser.add_argument("--quiet", action="store_true", help="suppress the report, write only")
    args = parser.parse_args(argv)

    records = load_records(args.inputs)
    graph = build_graph(records)

    if not graph["hosts"]:
        print(f"pivot_map: no hosts found in {', '.join(args.inputs)}", file=sys.stderr)
        return 2

    entries = [args.entry] if args.entry else entry_points(graph)
    chains: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        chains.update(breadth_first(graph, entry))

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
                steps = " -> ".join(
                    f"{e['service']}:{e['port']}" for e in path
                )
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
        "open on the target. It does not mean the credential was accepted there.",
    }
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"\nwrote {args.out}")
    if args.dot:
        Path(args.dot).write_text(to_dot(graph, chains), encoding="utf-8")
        if not args.quiet:
            print(f"wrote {args.dot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
