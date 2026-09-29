#!/usr/bin/env python3
"""Migrate the legacy TSEC tool registry into a JSON inventory.

The legacy `src/tools/phase*.rs` files are the authoritative record of which
tools TSEC drives and which operations exist for them. The Rust rewrite exposes
*capabilities* to operators and *providers* underneath, but it must not lose
any of that coverage. This script converts the Rust literals into
`catalog/inventory.json`, which the runtime loads as read-only reference data.

The legacy files are regular Rust struct literals, so a brace-tracking scanner
is exact and far more robust than trying to shell out to a Rust parser.

Usage:  python3 scripts/migrate_inventory.py [--check]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEGACY = ROOT / "src" / "tools"
OUTPUT = ROOT / "catalog" / "inventory.json"

# Phase id, legacy category name, and the single-word operator label.
PHASES = [
    ("recon", "Reconnaissance", "RECON", "phase01_reconnaissance.rs"),
    ("surface", "Attack Surface Mapping", "SURFACE", "phase02_attack_surface.rs"),
    ("vulnerability", "Vulnerability Assessment", "VULNERABILITY", "phase03_vulnerability.rs"),
    ("payload", "Payload Development", "PAYLOAD", "phase04_payload.rs"),
    ("escalation", "Privilege Escalation", "ESCALATION", "phase05_privesc.rs"),
    ("credentials", "Credential Access", "CREDENTIALS", "phase06_credentials.rs"),
    ("lateral", "Lateral Movement", "LATERAL", "phase07_lateral.rs"),
    ("persistence", "Persistence & Evasion", "PERSISTENCE", "phase08_persistence.rs"),
    ("objectives", "Actions on Objectives", "OBJECTIVES", "phase09_objectives.rs"),
    ("wireless", "Wireless Hacking", "WIRELESS", "phase10_wireless.rs"),
]

# Placeholder -> input kind, derived from the legacy `InputKind` enum.
BUILTIN_INPUTS = {
    "Domain": "domain",
    "Ip": "ip",
    "Url": "url",
    "File": "file",
    "Ports": "ports",
    "Target": "target",
    "Username": "username",
    "Password": "password",
    "Interface": "interface",
    "Hash": "hash",
    "Wordlist": "wordlist",
    "Payload": "payload",
    "Session": "session",
    "Lhost": "lhost",
    "Lport": "lport",
}

STRING_RE = re.compile(r'r#"(.*?)"#|r"(.*?)"|"((?:\\.|[^"\\])*)"', re.S)
INPUT_RE = re.compile(r'InputKind::([A-Za-z]+)|InputKind::Custom\(\s*"((?:\\.|[^"\\])*)"\s*,\s*"((?:\\.|[^"\\])*)"\s*\)', re.S)


def unescape(value: str) -> str:
    return (
        value.replace('\\"', '"')
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\\\", "\\")
    )


def split_top_level(text: str) -> list[str]:
    """Split a body on commas that are not inside brackets or string literals."""
    out, depth, buf, in_str, in_raw, escape = [], 0, [], False, False, False
    for ch in text:
        if in_str:
            buf.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if in_raw:
            buf.append(ch)
            if ch == '"':
                in_raw = False
            continue
        if ch == '"':
            in_str = True
            buf.append(ch)
            continue
        if text.startswith('r#"', len(buf) and 0 or 0) and len(buf) == 0 and ch == 'r':
            # handled below via explicit prefix detection
            pass
        if ch == "#" and buf and buf[-1] == "r":
            in_raw = True
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def find_blocks(text: str, header: str) -> list[tuple[int, int, str]]:
    """Yield (start, end, body) for every `header { ... }` literal."""
    blocks = []
    for m in re.finditer(re.escape(header) + r"\s*\{", text):
        start = m.end()
        depth = 1
        i = start
        in_str = in_raw = escape = False
        while i < len(text) and depth > 0:
            ch = text[i]
            if in_raw:
                if ch == '"':
                    in_raw = False
                i += 1
                continue
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                i += 1
                continue
            if ch == '"':
                in_str = True
            elif ch == "r" and text[i : i + 2] == 'r#':
                in_raw = True
                i += 2
                continue
            elif ch == "r" and text[i : i + 1] == "r" and i + 1 < len(text) and text[i + 1] == '"':
                in_raw = True
                i += 1
                continue
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        blocks.append((m.start(), i + 1, text[start:i]))
    return blocks


def field(body: str, name: str) -> str | None:
    m = re.search(rf"\b{name}\s*:\s*(.*?)(?=,\s*\n\s*\w+\s*:|\Z)", body, re.S)
    return m.group(1).strip() if m else None


def parse_string(raw: str) -> str:
    raw = raw.strip().rstrip(",")
    m = STRING_RE.match(raw)
    if not m:
        return ""
    return unescape(next(g for g in m.groups() if g is not None))


def parse_inputs(raw: str | None) -> list[dict]:
    inputs: list[dict] = []
    if not raw:
        return inputs
    for m in INPUT_RE.finditer(raw):
        if m.group(1):
            kind = m.group(1)
            inputs.append({"kind": kind.lower(), "placeholder": BUILTIN_INPUTS.get(kind, kind.lower())})
        else:
            label, ph = unescape(m.group(2)), unescape(m.group(3))
            inputs.append({"kind": "custom", "label": label, "placeholder": ph})
    return inputs


def parse_mode(body: str) -> dict | None:
    name = field(body, "name")
    template = field(body, "cmd_template")
    if not name or not template:
        return None
    fmt = field(body, "output_format") or "Raw"
    ext = field(body, "file_ext")
    return {
        "name": parse_string(name),
        "template": parse_string(template),
        "inputs": parse_inputs(field(body, "inputs")),
        "output_format": fmt.rsplit("::", 1)[-1].strip().lower(),
        "file_ext": parse_string(ext) if ext else "txt",
    }


def parse_tool(body: str) -> dict | None:
    name = field(body, "name")
    binary = field(body, "binary")
    if not name or not binary:
        return None
    modes = [parse_mode(b) for _, _, b in find_blocks(body, "Mode")]
    return {
        "name": parse_string(name),
        "binary": parse_string(binary),
        "description": parse_string(field(body, "description") or '""'),
        "operations": [m for m in modes if m],
    }


def build() -> dict:
    phases = []
    totals = {"tools": 0, "operations": 0}
    for phase_id, legacy_name, label, filename in PHASES:
        path = LEGACY / filename
        if not path.exists():
            print(f"error: missing legacy phase file {path}", file=sys.stderr)
            sys.exit(2)
        text = path.read_text(encoding="utf-8")
        tools = [parse_tool(b) for _, _, b in find_blocks(text, "Tool")]
        tools = [t for t in tools if t]
        totals["tools"] += len(tools)
        totals["operations"] += sum(len(t["operations"]) for t in tools)
        phases.append(
            {
                "id": phase_id,
                "label": label,
                "legacy_name": legacy_name,
                "tools": tools,
            }
        )
        print(f"  {label:<14} {len(tools):>3} tool(s)  {sum(len(t['operations']) for t in tools):>4} operation(s)")
    return {"schema": 1, "generated_by": "scripts/migrate_inventory.py", "phases": phases, "totals": totals}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if the committed inventory is stale")
    args = ap.parse_args()

    print("Extracting legacy tool inventory:")
    data = build()
    print(f"Total: {data['totals']['tools']} tool(s), {data['totals']['operations']} operation(s)")

    rendered = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    if args.check:
        if not OUTPUT.exists():
            print(f"error: {OUTPUT} does not exist", file=sys.stderr)
            return 1
        if OUTPUT.read_text(encoding="utf-8") != rendered:
            print(f"error: {OUTPUT} is stale; re-run scripts/migrate_inventory.py", file=sys.stderr)
            return 1
        print("inventory is up to date")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
