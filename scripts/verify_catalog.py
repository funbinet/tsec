#!/usr/bin/env python3
"""Verify the capability catalog against real provider help output.

The catalog is the only place the framework decides what a command looks like,
so it is checked as strictly as the legacy registry was — with one important
difference: this file is *authored*, not mined, and every entry in it must pass.

Checks performed, per capability:
  * the label is one to three uppercase words, as the interface requires
  * every `{placeholder}` used in an operation is a declared input
  * every input type is one the framework understands
  * required inputs have no default and optional inputs do
  * no argument contains shell syntax that an argument vector cannot express
  * every flag is documented by that provider's own help output
  * the provider binary is one the framework knows about

Exit status is non-zero if any check fails, so this is usable as a gate.

Usage:  python3 scripts/verify_catalog.py [--quiet]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify_providers import HELP_ARGS, capture_help, parse_flags, resolve, strip_ansi  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog" / "capabilities.toml"
INVENTORY = ROOT / "catalog" / "inventory.json"

INPUT_TYPES = {
    "domain", "domain/company", "ip/cidr", "ipv6", "target", "url", "port",
    "ports", "file", "path", "text", "secret", "integer", "flag", "username",
    "password", "hash", "interface", "mac", "session", "list",
}

SHELL_CHARS = set("|&;<>`$()\n")
PLACEHOLDER_RE = re.compile(r"\{([a-z0-9_]+)\}")
LABEL_RE = re.compile(r"^[A-Z][A-Z0-9]*(?: [A-Z][A-Z0-9]*){0,2}$")


class Problems:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, where: str, message: str) -> None:
        self.items.append(f"{where}: {message}")

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self):
        return iter(self.items)


def flag_tokens(args: list[str]) -> list[str]:
    """Flags in an argv, ignoring flag *values*."""
    out = []
    skip_next = False
    for tok in args:
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-") and len(tok) > 1:
            out.append(tok.split("=")[0])
            # A long flag written as `--flag value` consumes the value.
            if tok.startswith("--") and "=" not in tok:
                skip_next = True
    return out


def flag_known(flag: str, known: set[str]) -> bool:
    if flag in known:
        return True
    if not flag.startswith("--") and len(flag) > 2 and all(f"-{c}" in known for c in flag[1:]):
        return True
    if not flag.startswith("--"):
        tail = flag[1:]
        if 1 <= len(tail) <= 2 and any(k.startswith(flag) and len(k) - len(flag) <= 2 for k in known):
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not CATALOG.exists():
        print(f"error: {CATALOG} missing", file=sys.stderr)
        return 2

    data = tomllib.loads(CATALOG.read_text(encoding="utf-8"))
    if data.get("schema") != 1:
        print(f"error: unsupported catalog schema {data.get('schema')!r}", file=sys.stderr)
        return 2

    known_binaries: set[str] = set()
    if INVENTORY.exists():
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        for phase in inventory["phases"]:
            for tool in phase["tools"]:
                known_binaries.add(tool["binary"])

    problems = Problems()
    help_cache: dict[str, set[str] | None] = {}
    stats = {
        "capabilities": 0,
        "providers": 0,
        "operations": 0,
        "flags": 0,
        "unknown_flags": 0,
        "unprobeable": 0,
    }

    for cap in data.get("capability", []):
        cid = cap.get("id", "<missing id>")
        stats["capabilities"] += 1
        where = f"capability {cid}"

        label = cap.get("label", "")
        if not LABEL_RE.match(label):
            problems.add(where, f"label {label!r} must be 1-3 uppercase words")
        if not cap.get("summary"):
            problems.add(where, "summary is required")
        if not cap.get("phase"):
            problems.add(where, "phase is required")

        declared: dict[str, dict] = {}
        for spec in cap.get("inputs", []):
            key = spec.get("key")
            if not key:
                problems.add(where, "an input has no key")
                continue
            if key in declared:
                problems.add(where, f"input {key!r} declared twice")
            declared[key] = spec
            if spec.get("type") not in INPUT_TYPES:
                problems.add(where, f"input {key!r} has unknown type {spec.get('type')!r}")
            if spec.get("required") and "default" in spec:
                problems.add(where, f"required input {key!r} must not have a default")
            if not spec.get("required") and "default" not in spec and not spec.get("help"):
                problems.add(where, f"optional input {key!r} needs a default or help text")

        providers = cap.get("provider", [])
        if not providers:
            problems.add(where, "no provider is listed")
        for prov in providers:
            stats["providers"] += 1
            binary = prov.get("binary", "<missing binary>")
            pwhere = f"{where} / {binary}"
            if known_binaries and binary not in known_binaries:
                problems.add(pwhere, "binary is not in the extracted tool inventory")

            if "subcommand" not in prov:
                problems.add(pwhere, "subcommand is required (use [] when the tool has no verb)")
            subcommand = prov.get("subcommand", [])
            if not isinstance(subcommand, list) or not all(isinstance(x, str) for x in subcommand):
                problems.add(pwhere, "subcommand must be a list of strings")
                subcommand = []
            resolved = resolve(binary, subcommand)
            if resolved:
                if binary not in help_cache:
                    hout, _ = capture_help(resolved, subcommand)
                    help_cache[binary] = set(parse_flags(strip_ansi(hout))) if hout.strip() else None
                known = help_cache[binary]
            else:
                known = None

            if known is None:
                stats["unprobeable"] += 1
                if resolved:
                    problems.add(pwhere, "installed but its help output could not be read")
                continue

            ops = prov.get("operation", [])
            if not ops:
                problems.add(pwhere, "no operations declared")
            for op in ops:
                stats["operations"] += 1
                owhere = f"{pwhere} / {op.get('name', '<unnamed>')}"
                argv = op.get("args", [])
                if not argv:
                    problems.add(owhere, "has no arguments")
                    continue
                if not op.get("output"):
                    problems.add(owhere, "output format is required")
                for tok in argv:
                    bad = SHELL_CHARS & set(tok)
                    if bad:
                        problems.add(
                            owhere,
                            f"argument {tok!r} contains shell syntax {''.join(sorted(bad))!r}; "
                            "an argument vector cannot express it",
                        )
                    for ph in PLACEHOLDER_RE.findall(tok):
                        if ph not in declared:
                            problems.add(owhere, f"uses undeclared input {{{ph}}}")
                for flag in flag_tokens(argv):
                    stats["flags"] += 1
                    if not flag_known(flag, known):
                        stats["unknown_flags"] += 1
                        problems.add(owhere, f"flag {flag!r} is not in the tool's help output")

    # Duplicate capability ids would make the UI ambiguous.
    ids = [c.get("id") for c in data.get("capability", [])]
    for dup in {i for i in ids if ids.count(i) > 1}:
        problems.add(f"capability {dup}", "duplicate id")

    if not args.quiet:
        print(
            f"{stats['capabilities']} capability(ies), {stats['providers']} provider binding(s), "
            f"{stats['operations']} operation(s), {stats['flags']} flag(s) checked "
            f"({stats['unknown_flags']} unknown, {stats['unprobeable']} provider(s) not installed)"
        )

    if problems:
        print(f"\n{len(problems)} problem(s):\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    if not args.quiet:
        print("catalog verified: every flag is documented by its provider")
    return 0


if __name__ == "__main__":
    sys.exit(main())
