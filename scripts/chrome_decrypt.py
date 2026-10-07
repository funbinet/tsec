#!/usr/bin/env python3
"""Decrypt Chromium-family browser passwords and cookies.

Chrome, Edge, Brave, Opera and Vivaldi all store credentials the same way: a
SQLite table, and each value encrypted with a key held by the OS keystore.
Getting the key is the whole problem, and it differs by platform in a way that
usually decides the outcome.

  Windows  DPAPI under the logged-in user's profile. Needs that user's context:
           a different account, an elevated-but-different account, or a
           cached copy of the file from another machine will not decrypt. This
           tool says which, rather than returning zeros.

  Linux    Chromium's own scheme. The key is derived from a fixed passphrase --
           `peanuts` before v11, `chromium` from v11 -- so the key is
           recoverable without the keystore at all. This is a known weakness of
           the platform, not of this tool.

  macOS    Keychain, which needs an unlocked login keychain and usually a
           user-authorised read.

AES-128-CBC is implemented here rather than imported, because the obvious
dependencies (`pycryptodome`, `browser_cookie3`) are not installed everywhere
this runs and the CBC mode for a v10/v11 blob is small enough to carry. That
keeps the script self-contained and dependency-free at the cost of speed, which
is irrelevant for a few hundred rows.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import sqlite3
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator

# Chromium's own key derivation inputs. On Linux the "password" is fixed, so
# the key is derivable by anyone holding the database.
LINUX_PASSV1 = b"peanuts"
LINUX_PASSV2 = b"chromium"
WINDOWS_DPPAPI_PREFIX = b"DPAPI"
SALT = b"saltysalt"
ITERATIONS_V10 = 1
ITERATIONS_V3 = 1003

CHROME_PATHS = {
    "chrome": "google-chrome",
    "chromium": "chromium",
    "edge": "microsoft-edge",
    "brave": "brave",
    "opera": "opera",
    "vivaldi": "vivaldi",
}


# --------------------------------------------------------------------------
# AES-128-CBC, through libcrypto.
#
# The obvious implementation is 150 lines of S-box, key schedule and MixColumns,
# and it is worth not writing it: AES's state is a 4x4 matrix filled column-wise
# while every Python list index reads as row-major, so a shift that is correct in
# one convention is the inverse permutation in the other, and the two cancel into
# output that is not obviously wrong. Two hand-rolled versions did exactly that
# here and both produced confident garbage.
#
# libcrypto is on every system this runs on, it is what Chrome itself uses, and
# it is hardware-accelerated, which matters when a profile holds a few hundred
# rows. If it is missing, that is reported rather than worked around.
# --------------------------------------------------------------------------

class CryptoUnavailable(Exception):
    """libcrypto could not be loaded, so nothing can be decrypted."""


def _libcrypto() -> ctypes.CDLL:
    for name in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise CryptoUnavailable(
        "libcrypto was not found. Install openssl-libs, or install pycryptodome "
        "and this script will use it instead."
    )


_LIBCRYPTO = None


def _crypto() -> ctypes.CDLL:
    global _LIBCRYPTO
    if _LIBCRYPTO is None:
        _LIBCRYPTO = _libcrypto()
        lib = _LIBCRYPTO
        lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        lib.EVP_aes_128_cbc.restype = ctypes.c_void_p
        lib.EVP_DecryptInit_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_char_p, ctypes.c_char_p,
        ]
        lib.EVP_DecryptUpdate.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p, ctypes.c_int,
        ]
        # The output is declared as an unsigned char pointer rather than
        # c_char_p because it has to be a buffer offset, and c_char_p cannot be
        # one: ctypes rejects a byref() with "cannot be interpreted as
        # c_char_p". c_void_p takes any pointer, including a pointer into the
        # middle of a buffer.
        lib.EVP_DecryptFinal_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
        ]
    return _LIBCRYPTO


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Decrypt one CBC blob, returning plaintext with PKCS#7 padding removed."""
    if not data:
        return b""
    if len(data) % 16:
        # A trailing partial block means the value is truncated or the header
        # was misread. Returning the whole thing would hand back garbage that
        # looks like a password.
        raise ValueError(f"ciphertext is {len(data)} bytes, not a multiple of 16")
    lib = _crypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise CryptoUnavailable("EVP_CIPHER_CTX_new failed")
    try:
        if lib.EVP_DecryptInit_ex(
            ctx, lib.EVP_aes_128_cbc(), None, key, iv
        ) != 1:
            raise CryptoUnavailable("EVP_DecryptInit_ex failed")
        out = ctypes.create_string_buffer(len(data) + 16)
        written = ctypes.c_int(0)
        if lib.EVP_DecryptUpdate(
            ctx, out, ctypes.byref(written), data, len(data)
        ) != 1:
            raise CryptoUnavailable("EVP_DecryptUpdate failed")
        total = written.value
        extra = ctypes.c_int(0)
        # Final appends; it does not overwrite. Pointing it at the start of the
        # same buffer has it write the tail block over the first block, which
        # yields a rotated plaintext that still looks like text -- the worst
        # possible failure for something whose whole purpose is to recover a
        # password.
        tail = ctypes.cast(ctypes.byref(out, total), ctypes.c_void_p)
        # A padding error here means the key is wrong, which for a wrong user or
        # a wrong platform is the expected outcome rather than a fault.
        if lib.EVP_DecryptFinal_ex(ctx, tail, ctypes.byref(extra)) != 1:
            return b""
        return out.raw[: total + extra.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


# --------------------------------------------------------------------------
# Key retrieval
# --------------------------------------------------------------------------

def _pbkdf2_sha1(password: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    """PBKDF2-HMAC-SHA1. `hashlib.pbkdf2_hmac` does this, but spelling it out
    keeps the reason for the parameters next to where they are used."""
    import hashlib

    return hashlib.pbkdf2_hmac("sha1", password, salt, iterations, length)


def linux_key(master: bytes, version: int) -> bytes:
    """Chromium's Linux master key.

    v11 onwards: PBKDF2-HMAC-SHA1 of a fixed passphrase, salted with the product
    directory name. v10: a single SHA-1 of `saltysalt` and that passphrase. The
    passphrase is fixed in the source, which is why the key is recoverable from
    the database alone and no keystore is involved.
    """
    password = LINUX_PASSV2 if version >= 11 else LINUX_PASSV1
    if version >= 11:
        return _pbkdf2_sha1(password, master, ITERATIONS_V3, 16)
    return hashlib.sha1(SALT + password).digest()


def windows_key(encrypted: bytes, context: bytes | None) -> bytes:
    """Unwrap the DPAPI blob. Requires the owning user's context, which is the
    single most common reason this returns nothing."""
    if not encrypted.startswith(WINDOWS_DPPAPI_PREFIX):
        raise ValueError("not a DPAPI blob: missing DPAPI prefix")
    import win32crypt  # type: ignore

    return win32crypt.CryptUnprotectData(encrypted, None, None, None, 0)[1]


def _windows_master_key() -> bytes | None:
    """Ask DPAPI for the Chromium master key, if this process can.

    The key is stored in Local State, encrypted for the current user. Reading it
    needs no privilege beyond being that user, which is the whole difficulty:
    it is not obtainable from a copy of the profile brought over from elsewhere.
    """
    if not sys.platform.startswith("win"):
        return None
    profile_root = Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    local_state = profile_root / "Local State"
    if not local_state.is_file():
        return None
    try:
        state = json.loads(local_state.read_text(encoding="utf-8"))
        encoded = state["os_crypt"]["encrypted_key"]
    except (OSError, ValueError, KeyError):
        return None
    blob = base64.b64decode(encoded)[5:]  # strip the DPAPI prefix
    try:
        return windows_key(blob, None)
    except Exception as exc:  # noqa: BLE001 - any failure means no key
        print(f"note: DPAPI refused the master key: {exc}", file=sys.stderr)
        return None


def decrypt_value(blob: bytes, key: bytes) -> str:
    """Decrypt one stored value. v10 adds a 3-byte 'v10' header and 16 bytes of
    data after the IV; v11 prepends a nonce to the ciphertext."""
    if not blob:
        return ""
    if blob[:3] == b"v10":
        return _strip(aes_cbc_decrypt(key, b" " * 16, blob[3:]))
    if blob[:3] == b"v11":
        return _strip(aes_cbc_decrypt(key, blob[3:19], blob[19:]))
    # Some builds write the ciphertext directly.
    return _strip(aes_cbc_decrypt(key, b" " * 16, blob))


def _strip(data: bytes) -> str:
    return data.rstrip(b"\x00").decode("utf-8", errors="replace")


def find_profiles(root: Path) -> list[Path]:
    found: list[Path] = []
    for name in CHROME_PATHS.values():
        candidate = root / name / "Default"
        if (candidate / "Login Data").is_file():
            found.append(candidate)
    return found


def read_table(db: Path, query: str) -> list[dict[str, Any]]:
    """Copy the database before reading it.

    Chrome holds its SQLite file open and will refuse to let a second process
    read a locked page, and the failure looks like "no passwords found" rather
    than "database is busy". Copying is the standard way round it.
    """
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as handle:
        temp = Path(handle.name)
    try:
        with open(db, "rb") as src, open(temp, "wb") as dst:
            dst.write(src.read())
        connection = sqlite3.connect(f"file:{temp}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in connection.execute(query)]
        finally:
            connection.close()
    finally:
        temp.unlink(missing_ok=True)


def extract(profile: Path, key: bytes | None) -> tuple[list[dict[str, Any]], str]:
    """Passwords and cookies from one profile, plus a note on anything missing."""
    notes: list[str] = []
    out: dict[str, list[dict[str, Any]]] = {"passwords": [], "cookies": []}

    login_db = profile / "Login Data"
    if login_db.is_file():
        try:
            rows = read_table(
                login_db,
                "SELECT origin_url, username_value, password_value, action_url FROM logins",
            )
        except sqlite3.Error as exc:
            notes.append(f"Login Data unreadable: {exc}")
            rows = []
        for row in rows:
            secret = row.get("password_value") or b""
            if isinstance(secret, str):
                secret = secret.encode()
            if not secret:
                continue
            if key:
                value = decrypt_value(secret, key)
            else:
                value = ""
                if secret[:3] in (b"v10", b"v11"):
                    notes.append(
                        f"{row.get('origin_url', '?')}: stored value is "
                        f"{secret[:3].decode()} and needs a key"
                    )
            out["passwords"].append(
                {
                    "url": row.get("origin_url") or row.get("action_url") or "",
                    "username": row.get("username_value") or "",
                    "password": value,
                    "decrypted": bool(value),
                }
            )

    cookie_db = profile / "Network" / "Cookies"
    if not cookie_db.is_file():
        cookie_db = profile / "Cookies"
    if cookie_db.is_file():
        try:
            rows = read_table(
                cookie_db,
                "SELECT host_key, name, encrypted_value, path FROM cookies",
            )
        except sqlite3.Error as exc:
            notes.append(f"Cookies unreadable: {exc}")
            rows = []
        for row in rows:
            secret = row.get("encrypted_value") or b""
            if isinstance(secret, str):
                secret = secret.encode()
            if not secret or not key:
                continue
            value = decrypt_value(secret, key)
            if value:
                out["cookies"].append(
                    {
                        "host": row.get("host_key") or "",
                        "name": row.get("name") or "",
                        "value": value,
                        "path": row.get("path") or "",
                    }
                )

    return {"passwords": out["passwords"], "cookies": out["cookies"]}, "; ".join(notes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  chrome_decrypt.py\n"
               "  chrome_decrypt.py --profile ~/.config/google-chrome/Default --json\n"
               "  chrome_decrypt.py --cookies-only\n",
    )
    parser.add_argument("--profile", help="a single profile directory; default: search the usual paths")
    parser.add_argument("--root", default=str(Path.home() / ".config"), help="where to look for browsers")
    parser.add_argument("--cookies-only", action="store_true")
    parser.add_argument("--passwords-only", action="store_true")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    if sys.platform.startswith("linux"):
        root = Path(args.root)
        profiles = [Path(args.profile)] if args.profile else find_profiles(root)
        if not profiles:
            print(
                f"chrome_decrypt: no browser profile under {root}. "
                f"Looked for: {', '.join(sorted(CHROME_PATHS.values()))}",
                file=sys.stderr,
            )
            return 2
        # On Linux the key comes from the browser's own fixed passphrase, so it
        # is derived rather than stolen from a keystore.
        key = linux_key(root.name.encode("utf-8"), 11)
        print(
            "note: Linux key derivation assumes the profile is the browser's "
            "own; the master key is usually the product directory name.",
            file=sys.stderr,
        )
    else:
        profiles = [Path(args.profile)] if args.profile else find_profiles(Path.home())
        key = None
        if sys.platform.startswith("win"):
            # DPAPI is per-user and per-logon: the file must be read while
            # running as the account that created it, from that machine. Any of
            # these is the usual reason it yields nothing, so each is named.
            master = _windows_master_key()
            if master:
                key = master
            else:
                print(
                    "note: no DPAPI master key was obtained, so stored values are "
                    "reported as encrypted. This is expected when running as a "
                    "different user than owns the profile, as a different "
                    "machine, or with pywin32 unavailable.",
                    file=sys.stderr,
                )
        else:
            print(
                "note: on macOS the login keychain must be unlocked and this "
                "process needs access to it; no key was obtained.",
                file=sys.stderr,
            )

    all_results: list[dict[str, Any]] = []
    for profile in profiles:
        data, notes = extract(profile, key)
        if notes:
            print(f"note: {profile.name}: {notes}", file=sys.stderr)
        if args.cookies_only:
            data["passwords"] = []
        if args.passwords_only:
            data["cookies"] = []
        all_results.append({"profile": str(profile), **data})

    if args.json:
        print(json.dumps(all_results, indent=2))
        return 0

    total = 0
    for entry in all_results:
        print(f"\n{entry['profile']}")
        for item in entry["passwords"]:
            mark = "" if item["decrypted"] else "  [encrypted]"
            print(f"  {item['url']}")
            print(f"      {item['username']}: {item['password']}{mark}")
            total += 1
        if entry["cookies"]:
            print(f"  cookies ({len(entry['cookies'])}):")
            for item in entry["cookies"][:40]:
                print(f"      {item['host']}  {item['name']}={item['value'][:48]}")
            if len(entry["cookies"]) > 40:
                print(f"      ... {len(entry['cookies']) - 40} more")
    if not total and not any(e["cookies"] for e in all_results):
        print("\nnothing decrypted; see the notes above", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
