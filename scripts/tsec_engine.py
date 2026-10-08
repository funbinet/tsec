"""Shared engine primitives for the TSEC script suite.

Every script in `scripts/` reports the same way and is judged by the same
states, so that one can be read as input to another and so a finding means the
same thing wherever it came from. This module is that contract:

  Finding        one claim, with a state, a severity and the evidence for it
  State          inferred < tested < confirmed < used, and what each may say
  Evidence       why a state was reached, never asserted without one
  Renderer       the same report as JSON for machines and text for people
  Artifacts      files a run produced, hashed and listed
  Workspace      a temporary directory that cleans itself up

The state ladder is the part worth arguing for. A capability that finds an open
port and a password has established two facts, not one that it can log in: the
port is open and the password exists. That is `INFERRED`. Establishing that the
credential is accepted is `TESTED`. Establishing what was done with the session
is `CONFIRMED`. Having actually used the session for the purpose is `USED`.
Collapsing these is how a scanner ends up reporting a pivot that was never made,
so each state carries a fixed sentence about what it does and does not prove.

Standard library only. No imports from the sibling scripts, so any one of them
runs on its own.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

SUITE = "tsec"
# Bumped when a report's shape changes in a way a consumer would notice.
REPORT_SCHEMA = 3


class State:
    """What a claim is backed by. Ordered; never skipped when reporting."""

    INFERRED = "INFERRED"
    TESTED = "TESTED"
    CONFIRMED = "CONFIRMED"
    USED = "USED"
    BLOCKED = "BLOCKED"
    REJECTED = "REJECTED"
    GENERATED = "GENERATED"
    UNREACHABLE = "UNREACHABLE"
    FAILED = "FAILED"

    ORDER = {
        INFERRED: 0, TESTED: 1, CONFIRMED: 2, USED: 3,
        GENERATED: 1, BLOCKED: 4, REJECTED: 2, UNREACHABLE: 5, FAILED: 6,
    }

    #: What each state is entitled to claim. Rendered verbatim, because the whole
    #: point is that a reader is never left guessing how strong a result is.
    MEANING = {
        INFERRED: "read from an input; not tested against anything",
        TESTED: "attempted and the attempt was observed; outcome not established",
        CONFIRMED: "the thing was established by direct observation",
        USED: "established by actually doing it, with the result observed",
        GENERATED: "built and measured; nothing has run it",
        BLOCKED: "attempted; a control or environment stopped it",
        REJECTED: "attempted; the target declined it",
        UNREACHABLE: "no route to the target",
        FAILED: "the attempt errored; the reason is in the evidence",
    }

    MARK = {
        USED: "+", CONFIRMED: "+", TESTED: "~", GENERATED: "o", INFERRED: "?",
        REJECTED: "-", BLOCKED: "x", UNREACHABLE: "x", FAILED: "!",
    }


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}

#: The only states that may set a headline. `TESTED` says an attempt was
#: observed, not that it worked, and `INFERRED` says nothing was attempted at
#: all -- so neither can be the worst *established* finding. Ranking on the
#: state order alone instead is how a scan reports "critical: lateral movement
#: possible" off an open port and a password it never tried.
PROVEN = frozenset({State.CONFIRMED, State.USED})


@dataclass
class Finding:
    """One claim, with what backs it."""

    check: str
    state: str = State.INFERRED
    severity: str = "info"
    evidence: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    artifact: str | None = None

    def __post_init__(self) -> None:
        if not self.evidence:
            # An unevidenced claim is the failure this whole module exists to
            # prevent, so it is refused at construction rather than rendered.
            raise ValueError(
                f"finding {self.check!r} is {self.state} with no evidence; "
                f"a state that cannot be substantiated is not a finding"
            )
        if self.state not in State.MEANING:
            raise ValueError(f"unknown state {self.state!r}")

    @property
    def rank(self) -> tuple[int, int]:
        return (SEVERITY_ORDER.get(self.severity, 9), State.ORDER.get(self.state, 9))

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "check": self.check,
            "state": self.state,
            "means": State.MEANING[self.state],
            "severity": self.severity,
            "evidence": self.evidence,
        }
        if self.detail:
            out["detail"] = self.detail
        if self.artifact:
            out["artifact"] = self.artifact
        return out


def worst(findings: Iterable[Finding]) -> str:
    """The most serious severity among findings that were actually established.

    Only `TESTED`-or-better counts. An `INFERRED` critical is a lead, not a
    result, and letting it set the headline is how a scan reports a critical
    finding it never confirmed.
    """
    established = [f for f in findings if f.state in PROVEN]
    if not established:
        return "info"
    return min(established, key=lambda f: f.rank).severity.lower()


# ── output normalisation ─────────────────────────────────────────────────────

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL = {chr(c) for c in range(0, 0x20) if c not in (9, 10)} | {chr(0x7F)}

# Lines that are a tool describing itself rather than reporting a result. These
# are the shapes that turned six real findings into a screenful of chrome.
_NOISE = re.compile(
    r"""^(?:
          [\s_=~^*#.-]*\[?(?:INF|WRN|ERR|FTL|DBG|TTI|VER|NOT)\]?[\s:.-]   # log levels
        | (?:\s*\|?\s*)?(?:Usage|USAGE|SYNOPSIS|DESCRIPTION|OPTIONS|FLAGS)\b
        | (?:\s*\|?\s*)?[A-Z][a-z]+ (?:Version|version)[:\s]
        | (?:\s*\|?\s*)?(?:Copyright|License|Licence|Written by|Author)[:\s(]
        | (?:\s*\|?\s*)?(?:This program|This tool|Examples?:|See also)
        | [-=_*~]{3,}                                                 # rules
        | (?:\s*\|?\s*)?(?:unknown|unsupported|invalid|no such|not found|error:)[\s:]
        | Installing|Successfully|Welcome to|Downloading|Fetching|Resolving
        | \d+%\s+done|Progress
    )""",
    re.VERBOSE | re.IGNORECASE,
)


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def clean_line(line: str) -> str:
    """One line, free of escape sequences and terminal control bytes."""
    out = strip_ansi(line)
    return "".join(c for c in out if c not in _CONTROL).strip()


def is_noise(line: str) -> bool:
    """Whether a line is the tool talking about itself rather than a result."""
    text = clean_line(line)
    if not text:
        return True
    if len(set(text)) <= 2 and len(text) > 6:
        return True  # a bar or a rule
    return bool(_NOISE.match(text))


def normalise(raw: str, keep_noise: bool = False) -> list[str]:
    """Output as reportable lines: no escapes, no chrome, no blank runs."""
    seen_blank = False
    out: list[str] = []
    for line in raw.splitlines():
        text = clean_line(line)
        if not text:
            seen_blank = False
            continue
        if not keep_noise and is_noise(text):
            continue
        out.append(text)
        seen_blank = False
    del seen_blank
    return out


# ── artifacts ────────────────────────────────────────────────────────────────

@dataclass
class Artifact:
    path: str
    size: int
    sha256: str
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        out = {"path": self.path, "size": self.size, "sha256": self.sha256}
        if self.note:
            out["note"] = self.note
        return out


def record(path: str | Path, note: str = "") -> Artifact:
    p = Path(path)
    data = p.read_bytes()
    return Artifact(str(p), len(data), hashlib.sha256(data).hexdigest(), note)


# ── workspace ────────────────────────────────────────────────────────────────

class Workspace:
    """A scratch directory that removes itself.

    Tools that unpack themselves leave 99MB per invocation in the system temp,
    and nothing sweeps it. Handing each run its own directory and removing it at
    the end is the difference between scratch space and a filled filesystem.

    `keep=True` retains it, for when the artifacts are the point.
    """

    def __init__(self, prefix: str = "tsec-", keep: bool = False, parent: str | Path | None = None) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix=prefix, dir=str(parent) if parent else None))
        self.keep = keep

    def path(self, *parts: str) -> Path:
        target = self.dir.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def cleanup(self) -> None:
        if self.keep:
            return
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self) -> "Workspace":
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()


# ── wordlists ────────────────────────────────────────────────────────────────

WORDLIST_DIRS = (
    "/usr/share/wordlists", "/usr/share/seclists", "/usr/share/dict",
    "wordlists", os.path.expanduser("~/wordlists"),
)


def discover_wordlists(explicit: str | None = None, cap: int = 500_000) -> list[bytes]:
    """Candidate secrets, shortest first.

    Shortest first is the useful order: a key is weak by being short, so
    `abc` is found before a twelve-character entry that is also in the list. The
    cap bounds memory rather than correctness -- a run that exhausts the cap has
    said so rather than quietly testing less than it claims.
    """
    if explicit:
        return _read(Path(explicit), cap)
    found: list[bytes] = []
    for base in WORDLIST_DIRS:
        root = Path(base)
        if root.is_dir():
            found.extend(_read_dir(root, cap - len(found)))
            if len(found) >= cap:
                break
    if not found:
        return [b"", b"secret", b"password", b"changeme", b"test", b"admin"]
    out, seen = [], set()
    for candidate in sorted(set(found), key=len):
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out


def _read(path: Path, cap: int) -> list[bytes]:
    try:
        return _read_dir(path, cap, single=True)
    except OSError:
        return []


#: Suffixes that mean "a list of candidate secrets". A bare suffix match is not
#: enough: a wordlist directory also holds SHA-256 manifests, .rule files for
#: hashcat and base64 blobs, and reading those as wordlists fills the candidate
#: list with single punctuation characters that sort first and crowd out the
#: actual words. The longest candidate is what makes the report readable, so
#: polluting the front of the list destroys the ordering that makes it useful.
LIST_SUFFIXES = frozenset({".txt", ".lst", ".dic", ".csv", ".list", ".wordlist"})
LIST_NAME_HINTS = ("secret", "password", "passwd", "credential", "cred", "wordlist", "common")
#: Never a wordlist, whatever the name suggests. `fetch-wordlists.sh` matches the
#: hint and reading a shell script as candidate secrets puts `#!/bin/sh` in the
#: candidate list, where it sorts to the front and is tried first.
NOT_A_LIST = frozenset({
    ".sh", ".py", ".rb", ".pl", ".ps1", ".bat", ".cmd", ".psm1", ".js", ".ts",
    ".md", ".json", ".toml", ".yaml", ".yml", ".xml", ".html", ".htm",
    ".sha256", ".sha1", ".sha512", ".md5", ".rule", ".pyc", ".so", ".zip", ".gz",
    ".exe", ".bin", ".png", ".jpg", ".gz", ".xz", ".7z", ".lock", ".log",
})


def _is_wordlist(path: Path) -> bool:
    if path.suffix.lower() in NOT_A_LIST:
        return False
    if path.suffix.lower() in LIST_SUFFIXES:
        return True
    name = path.name.lower()
    return any(hint in name for hint in LIST_NAME_HINTS)


def _read_dir(root: Path, cap: int, single: bool = False) -> list[bytes]:
    out: list[bytes] = []
    try:
        items = [root] if single else sorted(root.rglob("*"))
    except OSError:
        return out
    for item in items:
        if len(out) >= cap:
            break
        if not item.is_file() or (not single and not _is_wordlist(item)):
            continue
        try:
            if item.stat().st_size > 200 * 1024 * 1024:
                continue
            raw = item.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue  # binary, whatever it is called
        for line in raw.splitlines():
            line = line.strip()
            if line:
                out.append(line)
        del single
        single = True  # an explicitly named file is taken whole
    return out[:cap]


# ── running things ───────────────────────────────────────────────────────────

def which(*names: str) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


@dataclass
class Ran:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def lines(self, keep_noise: bool = False) -> list[str]:
        return normalise(self.stdout, keep_noise)

    def why(self, limit: int = 160) -> str:
        """Why it failed, in terms someone can act on."""
        if self.timed_out:
            return f"timed out after {self.seconds:.1f}s"
        tail = [l for l in normalise(self.stderr) if l]
        return (tail[-1] if tail else f"exit {self.returncode}")[:limit]


def run(argv: list[str], timeout: float = 60.0, stdin: str | None = None,
        env: dict[str, str] | None = None, cwd: str | Path | None = None) -> Ran:
    """Run a command with a real timeout and both streams captured.

    A missing binary is reported as such rather than as an exception, because
    "not installed" and "ran and failed" are different answers and the caller
    needs to tell them apart.
    """
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
            env={**os.environ, **(env or {})},
            cwd=str(cwd) if cwd else None,
        )
    except FileNotFoundError:
        return Ran(argv, 127, "", f"{argv[0]}: not installed", 0.0)
    except subprocess.TimeoutExpired as exc:
        return Ran(
            argv, 124,
            exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            time.monotonic() - started, timed_out=True,
        )
    except OSError as exc:
        return Ran(argv, 126, "", f"{argv[0]}: {exc}", time.monotonic() - started)
    return Ran(
        argv, proc.returncode, proc.stdout or "", proc.stderr or "",
        time.monotonic() - started,
    )


# ── report ───────────────────────────────────────────────────────────────────

@dataclass
class Report:
    tool: str
    version: str
    target: str = ""
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    started: float = field(default_factory=time.time)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def note(self, check: str, state: str, severity: str, evidence: str, **detail: Any) -> Finding:
        return self.add(Finding(check, state, severity, evidence, dict(detail)))

    def record(self, path: str | Path, note: str = "") -> Artifact:
        art = record(path, note)
        self.artifacts.append(art)
        return art

    @property
    def established(self) -> list[Finding]:
        """Findings with something behind them. Everything else is a lead."""
        return [f for f in self.findings if f.state in PROVEN]

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "schema": REPORT_SCHEMA,
            "target": self.target,
            "seconds": round(time.time() - self.started, 2),
            "worst_established_severity": worst(self.findings),
            "counts": self.counts(),
            "context": self.context,
            "findings": [f.as_dict() for f in sorted(self.findings, key=lambda f: f.rank)],
            "artifacts": [a.as_dict() for a in self.artifacts],
        }

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for f in self.findings:
            tally[f.state] = tally.get(f.state, 0) + 1
        return dict(sorted(tally.items()))

    def render(self, width: int = 100) -> str:
        lines = [f"{SUITE} {self.tool} {self.version}" + (f"  target {self.target}" if self.target else "")]
        counts = self.counts()
        if counts:
            lines.append("  " + "  ".join(f"{k.lower()}={v}" for k, v in counts.items()))
        if self.findings:
            lines.append("")
            for f in sorted(self.findings, key=lambda f: f.rank):
                mark = State.MARK.get(f.state, "?")
                lines.append(f"[{mark}] {f.severity.upper():<8} {f.state:<11} {f.check}")
                for piece in _wrap(f.evidence, width - 26):
                    lines.append(f"      {piece}")
        for art in self.artifacts:
            lines.append(f"  artifact {art.path} ({art.size}B, sha256 {art.sha256[:16]})")
        return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = str(text).split(), [], ""
    for word in words:
        if current and len(current) + len(word) + 1 > max(width, 20):
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def emit(report: Report, as_json: bool, path: str | None = None) -> None:
    """Write the report, in both shapes, to wherever the caller asked."""
    payload = json.dumps(report.as_dict(), indent=2)
    if path:
        Path(path).write_text(payload + "\n", encoding="utf-8")
        print(f"wrote {path}", file=sys.stderr)
    print(payload if as_json else report.render())


# ── selftest ─────────────────────────────────────────────────────────────────

class SelfTestError(AssertionError):
    pass


def check(condition: object, message: str) -> None:
    if not condition:
        raise SelfTestError(message)


def check_eq(got: object, want: object, message: str = "") -> None:
    if got != want:
        raise SelfTestError(f"{message or 'mismatch'}: got {got!r}, want {want!r}")


def selftest(fn) -> int:
    """Run a script's own checks. Returns a shell exit status.

    Each script exposes `--selftest`, so the whole suite is checkable in one
    command and nothing has to be pointed at a live target to find out whether
    the script still works.
    """
    try:
        fn()
    except SelfTestError as exc:
        print(f"selftest FAILED: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"selftest ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"{fn.__module__ or 'script'} selftest ok")
    return 0

def run_selftests() -> int:
    """Every script in this directory that exposes a `selftest` function.

    One command checks the suite, so a script cannot quietly stop working: the
    suite is checked in the same way it is shipped, rather than each script
    being trusted because it ran once.
    """
    import importlib.util

    here = Path(__file__).resolve().parent
    passed, failed = [], []
    for path in sorted(here.glob("*.py")):
        if path.name.startswith("_") or path.name == Path(__file__).name:
            continue
        try:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001
            failed.append((path.name, f"import failed: {type(exc).__name__}: {exc}"))
            continue
        fn = getattr(module, "selftest", None)
        if fn is None:
            continue
        try:
            fn()
            passed.append(path.name)
        except Exception as exc:  # noqa: BLE001
            failed.append((path.name, f"{type(exc).__name__}: {exc}"))

    for name in passed:
        print(f"  ok    {name}")
    for name, why in failed:
        print(f"  FAIL  {name}: {why}")
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run_selftests())
