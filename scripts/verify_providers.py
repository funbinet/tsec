#!/usr/bin/env python3
"""Verify every provider's command syntax against its installed help output.

The framework must never invent a flag. For each provider binary recorded in
`catalog/inventory.json` this script:

  1. resolves the executable on `PATH` (extra search directories optional),
  2. records the installed version string,
  3. captures `--help` under a hard timeout and with no stdin,
  4. derives the set of flags that help actually documents,
  5. checks every legacy operation's flags against that set, and
  6. writes `catalog/verification.json`.

Operations are marked:
  verified   - every flag in the template is documented by the tool's help
  unverified - the tool is not installed, so its syntax could not be checked
  suspect    - the tool is installed but at least one flag is undocumented

Nothing is ever executed against a real target: only `--version`/`--help` are
run, never an operation template.

Usage:  python3 scripts/verify_providers.py [--include-uninstalled]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "catalog" / "inventory.json"
OUTPUT = ROOT / "catalog" / "verification.json"

HELP_TIMEOUT = 8
VERSION_TIMEOUT = 15

# Tools print their flags under different flags. sqlmap, for example, only
# lists them under `-hh`; `-h` prints a banner with no option table at all, and
# curl's `--help` prints only a category index unless asked for everything.
HELP_ARGS = [
    ["--help"],
    ["-help"],
    ["-hh"],
    ["-h"],
    ["--usage"],
    ["-?"],
    ["--help", "all"],
    ["help", "all"],
    ["--help", "full"],
    ["--help", "long"],
]

# Some help output is paginated or colourised; strip it before hashing so the
# recorded help fingerprint is stable across terminals.
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# Tools that ignore --help, block on stdin, or start a long-lived service.
# They are recorded as installed but never probed, because probing them would
# be unsafe or meaningless rather than merely slow.
UNPROBEABLE = {
    "nc",
    "ncat",
    "netcat",
    "msfconsole",
    "msfvenom",
    "teamserver",
    "sliver-server",
    "evil-winrm",
    "proxychains",
    "proxychains4",
    "meterpreter",
    "empire",
    "wfuzz",  # long interactive fuzzing controller; probed via -h only
}

# Long-running C2/server binaries that are safe to version but not to --help.
HELP_SUPPRESSED = {"donut", "havoc", "mythic-cli", "bettercap", "hostapd-wpe"}

FLAG_RE = re.compile(r"(?<![\w-])(-{1,2}[A-Za-z][A-Za-z0-9_.-]*)")
PLACEHOLDER_RE = re.compile(r"\{([a-z0-9_]+)\}")


def resolve(binary: str, search_paths: list[str]) -> str | None:
    if "/" in binary or "\\" in binary or " " in binary:
        p = pathlib.Path(binary)
        return str(p.resolve()) if p.is_file() and os.access(p, os.X_OK) else None
    for d in search_paths:
        cand = pathlib.Path(d) / binary
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which(binary)


def run(argv: list[str], timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env={**os.environ, "TERM": "dumb", "NO_COLOR": "1", "PAGER": "cat", "LINES": "100"},
        )
    except subprocess.TimeoutExpired:
        return 124, ""
    except (OSError, ValueError) as exc:
        return 127, f"{type(exc).__name__}: {exc}"
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def capture_help(path: str, prefix: list[str] | None = None) -> tuple[str, str | None]:
    """Return (help text, argv that produced it) for the richest help output.

    Richness is measured by how many distinct flags the text documents, not by
    length: sqlmap's `--help` banner is long but lists almost no options, while
    its `-hh` prints the full table, and curl's `--help` prints only a category
    index while `curl --help all` prints every option.

    `prefix` puts a subcommand in front of the help flag, which is the only way
    to see the options of a tool that keeps them under a verb — `nxc smb --help`
    documents `-u`, while plain `nxc --help` does not.
    """
    best, best_arg, best_score = "", None, -1
    for argv in HELP_ARGS:
        cmd = [*(prefix or []), *argv]
        _, out = run([path, *cmd], HELP_TIMEOUT)
        out = strip_ansi(out)
        score = len(parse_flags(out))
        if score > best_score:
            best, best_arg, best_score = out, " ".join(cmd), score
    return best, best_arg


def parse_flags(help_text: str) -> list[str]:
    return sorted({m.group(1) for m in FLAG_RE.finditer(help_text)})


def template_flags(template: str) -> tuple[list[str], list[str]]:
    """Split a template into its literal flags and placeholders.

    Shell metacharacters, redirections and pipes are reported separately: they
    are rewritten into explicit argument vectors at run time, and a template
    that relies on them is a legacy defect, not a missing flag.
    """
    filled = PLACEHOLDER_RE.sub("PLACEHOLDER", template)
    tokens = filled.split()
    flags, suspicious = [], []
    for tok in tokens:
        if tok in {"|", "||", "&&", ";", ">", ">>", "<", "2>", "2>&1", "&"}:
            suspicious.append(tok)
            continue
        if "|" in tok or ">" in tok or "<" in tok:
            suspicious.append(tok)
            continue
        if tok.startswith("-") and tok != "-":
            flags.append(tok.split("=")[0])
    return flags, suspicious


def flag_known(flag: str, known: set[str]) -> bool:
    if flag in known:
        return True
    # A clustered short flag such as -abc is legal if the help lists each part.
    if not flag.startswith("--") and len(flag) > 2 and all(f"-{c}" in known for c in flag[1:]):
        return True
    # Several tools document only the long form of a short option (`-oN` with
    # no bare `-o`). Accept a short flag that prefixes a documented one, but
    # only for a one- or two-character remainder so `-o` does not silently
    # match `-old-style-input`.
    if not flag.startswith("--"):
        tail = flag[1:]
        if 1 <= len(tail) <= 2 and any(k.startswith(flag) and len(k) - len(flag) <= 2 for k in known):
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--search-path", action="append", default=[], help="extra directory to search (repeatable)")
    ap.add_argument("--include-uninstalled", action="store_true", help="list every provider, not just installed ones")
    args = ap.parse_args()

    if not INVENTORY.exists():
        print(f"error: {INVENTORY} missing; run scripts/migrate_inventory.py first", file=sys.stderr)
        return 2

    inv = json.loads(INVENTORY.read_text(encoding="utf-8"))

    # Group operations by provider binary across every phase.
    ops_by_binary: dict[str, list[dict]] = {}
    for phase in inv["phases"]:
        for tool in phase["tools"]:
            entry = ops_by_binary.setdefault(tool["binary"], {"phases": [], "operations": []})
            if phase["id"] not in entry["phases"]:
                entry["phases"].append(phase["id"])
            for i, op in enumerate(tool["operations"]):
                entry["operations"].append({"phase": phase["id"], "tool": tool["name"], "index": i, **op})

    search_paths = [str(p) for p in args.search_path] + [str(p) for p in inv.get("search_paths", [])]
    print(f"Verifying {len(ops_by_binary)} provider(s)…\n")

    providers = []
    counts = {"verified": 0, "unverified": 0, "suspect": 0}

    for binary in sorted(ops_by_binary):
        info = ops_by_binary[binary]
        path = resolve(binary, search_paths)
        rec = {
            "binary": binary,
            "phases": info["phases"],
            "operation_count": len(info["operations"]),
            "installed": path is not None,
            "path": path,
            "version": None,
            "probed": False,
            "help_sha256": None,
            "flags": [],
            "operations": [],
        }

        if path is None:
            for op in info["operations"]:
                rec["operations"].append({"phase": op["phase"], "tool": op["tool"], "index": op["index"], "name": op["name"], "status": "unverified", "unknown_flags": [], "shell_constructs": []})
            counts["unverified"] += len(info["operations"])
            providers.append(rec)
            if args.include_uninstalled:
                print(f"  [absent]    {binary:<22} {len(info['operations']):>4} operation(s) unverified")
            continue

        base = pathlib.Path(path).name
        if base in UNPROBEABLE:
            _, out = run([path, "--version"], VERSION_TIMEOUT)
            rec["version"] = out.strip().splitlines()[0][:200] if out.strip() else None
        elif base in HELP_SUPPRESSED:
            _, out = run([path, "--version"], VERSION_TIMEOUT)
            rec["version"] = out.strip().splitlines()[0][:200] if out.strip() else None
        else:
            _, out = run([path, "--version"], VERSION_TIMEOUT)
            vtext = strip_ansi(out).strip()
            if vtext:
                rec["version"] = vtext.splitlines()[0][:200]
            hout, harg = capture_help(path)
            # argparse-based tools reject unknown verbs and print their usage
            # synopsis instead. That synopsis is the tool documenting its own
            # short options, so it is admissible evidence too.
            usage_flags = parse_flags(vtext)
            if hout.strip():
                rec["probed"] = True
                rec["help_arg"] = harg
                rec["help_sha256"] = hashlib.sha256(hout.encode()).hexdigest()
                rec["flags"] = sorted(set(parse_flags(hout)) | set(usage_flags))
                rec["help_excerpt"] = "\n".join(hout.splitlines()[:40])
            elif usage_flags:
                rec["probed"] = True
                rec["help_arg"] = "--version (usage synopsis)"
                rec["help_sha256"] = hashlib.sha256(vtext.encode()).hexdigest()
                rec["flags"] = sorted(usage_flags)
                rec["help_excerpt"] = "\n".join(vtext.splitlines()[:40])
            else:
                rec["probed"] = False

        known = set(rec["flags"])
        for op in info["operations"]:
            flags, shell = template_flags(op["template"])
            if not rec["probed"]:
                status = "unverified"
                unknown = []
            else:
                unknown = sorted({f for f in flags if not flag_known(f, known)})
                # A template that relies on a shell is not something the runtime
                # can execute: an argument vector has no pipes or redirections.
                # Recording such a template as `verified` would let the provider
                # layer offer a command that cannot be run as written, so shell
                # syntax makes an operation suspect on its own.
                if unknown or shell:
                    status = "suspect"
                else:
                    status = "verified"
            counts[status] += 1
            rec["operations"].append(
                {
                    "phase": op["phase"],
                    "tool": op["tool"],
                    "index": op["index"],
                    "name": op["name"],
                    "status": status,
                    "unknown_flags": unknown,
                    "shell_constructs": sorted(set(shell)),
                }
            )

        tally = {s: sum(1 for o in rec["operations"] if o["status"] == s) for s in counts}
        providers.append(rec)
        if args.include_uninstalled or not rec["installed"]:
            print(f"  [{'probed ' if rec['probed'] else 'no-help'}] {binary:<22} v{tally['verified']:>4} / ?{tally['unverified']:>4} / !{tally['suspect']:>4}")

    total = sum(counts.values())
    doc = {
        "schema": 1,
        "generated_by": "scripts/verify_providers.py",
        "summary": {
            "providers": len(providers),
            "installed": sum(1 for p in providers if p["installed"]),
            "operations": total,
            "verified": counts["verified"],
            "unverified": counts["unverified"],
            "suspect": counts["suspect"],
        },
        "providers": providers,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    s = doc["summary"]
    print(
        f"\n{s['installed']}/{s['providers']} provider(s) installed · "
        f"{s['verified']} verified, {s['unverified']} unverified, {s['suspect']} suspect "
        f"(of {s['operations']} operation(s))"
    )
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
