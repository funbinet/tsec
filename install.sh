#!/usr/bin/env bash
# TSEC 3.0 installer
# Copyright (c) funbinet. All rights reserved.
# Part of TSEC terminal cybersecurity operations platform by funbinet.
#
# Installs:
#   /usr/bin/tsec                     the framework binary
#   /opt/tsec/catalog/capabilities.toml   the operational surface
#   /opt/tsec/wordlists/             the bundled wordlist corpus
#   /opt/tsec/{config,output,logs,...}    the runtime workspace

set -e

ROOT="${TSEC_ROOT:-/opt/tsec}"

# 1. Require root, or re-enter through sudo, before doing anything.
if [ "$EUID" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

echo "TSEC 3.0 installer"
echo ""

# 2. Find cargo — look in the real user's home even when running through sudo.
find_cargo() {
    if [ -n "$SUDO_USER" ]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        local cargo_bin="$user_home/.cargo/bin"
        if [ -f "$cargo_bin/cargo" ]; then
            export PATH="$cargo_bin:$PATH"
            echo "[ok] cargo found at $cargo_bin"
            return 0
        fi
    fi
    if command -v cargo &> /dev/null; then
        echo "[ok] cargo found in PATH"
        return 0
    fi
    return 1
}

if ! find_cargo; then
    echo "[!] cargo (Rust) is not installed or not in PATH."
    echo "    Install it with:"
    echo "      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "    then open a new terminal and run this installer again."
    exit 1
fi

# 3. Compile as the invoking user, so the build tree is not left root-owned.
echo "[..] compiling in release mode"
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    sudo -u "$SUDO_USER" env PATH="$USER_HOME/.cargo/bin:$PATH" cargo build --release
else
    cargo build --release
fi

if [ ! -f target/release/tsec ]; then
    echo "[!] build failed: target/release/tsec is missing"
    exit 1
fi

# 4. Install the binary.
echo "[..] installing /usr/bin/tsec"
install -m 0755 -o root -g root target/release/tsec /usr/bin/tsec

# 5. Install the catalog and the wordlist corpus, then create the workspace.
#
# The binary looks for catalog/capabilities.toml in TSEC_HOME, then in
# $ROOT, then in the directory it was built from. Installing it here is what
# makes `tsec` work from any directory on this machine, without TSEC_HOME.
echo "[..] installing the catalog to $ROOT/catalog"
install -d -m 0755 "$ROOT/catalog"
install -m 0644 catalog/capabilities.toml "$ROOT/catalog/capabilities.toml"

echo "[..] creating the workspace at $ROOT"
mkdir -p "$ROOT"/{config,output,logs,scripts,tools}

# The wordlists are part of the product, not an optional extra: the catalog
# resolves `{wl:...}` against this directory, and an empty one leaves every
# capability that needs a corpus unable to run. Copy the shipped lists and the
# manifest, then fetch the four too large for a git repository.
echo "[..] installing the wordlist corpus to $ROOT/wordlists"
mkdir -p "$ROOT/wordlists"
cp -R wordlists/. "$ROOT/wordlists/"
if [ -x "$ROOT/wordlists/fetch-wordlists.sh" ]; then
    chmod +x "$ROOT/wordlists"/fetch-wordlists.sh "$ROOT/wordlists"/verify-wordlists.sh
    # A missing large list is reported, never fatal: the install succeeds and the
    # capability that needs it is marked unavailable by name.
    "$ROOT/wordlists/fetch-wordlists.sh" || true
fi

if [ -n "$SUDO_USER" ]; then
    chown -R "$SUDO_USER:$SUDO_USER" "$ROOT"
fi

# 6. Install and check the network-execution boundary.
#
# oniux is not a provider tool: it is the boundary every network-capable command
# is launched through. TSEC has no proxy configuration and no switch that turns
# the boundary off, so a missing or broken oniux means no network capability can
# run at all. Install it if we can; otherwise say so plainly.
echo ""
echo "[..] checking the oniux network boundary"

# Detect stale Cargo-installed oniux that may be outdated or broken.
detect_stale_cargo_oniux() {
    local cargo_oniux
    if [ -n "$SUDO_USER" ]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        cargo_oniux="$user_home/.cargo/bin/oniux"
    else
        cargo_oniux="$HOME/.cargo/bin/oniux"
    fi
    if [ -f "$cargo_oniux" ]; then
        echo "[!] found Cargo-installed oniux at $cargo_oniux"
        echo "    if it is outdated, remove it with: cargo uninstall oniux"
    fi
}

install_oniux() {
    # Try AUR helpers, but verify the package exists first.
    if command -v paru >/dev/null 2>&1; then
        if paru -Si oniux >/dev/null 2>&1; then
            paru -S --needed --noconfirm oniux && return 0
        else
            echo "[!] oniux not found in AUR via paru"
        fi
    elif command -v yay >/dev/null 2>&1; then
        if yay -Si oniux >/dev/null 2>&1; then
            yay -S --needed --noconfirm oniux && return 0
        else
            echo "[!] oniux not found in AUR via yay"
        fi
    fi
    return 1
}

if command -v oniux >/dev/null 2>&1; then
    echo "[ok] oniux found at $(command -v oniux)"
else
    detect_stale_cargo_oniux
    if install_oniux; then
        echo "[ok] oniux installed"
    else
        echo "[!] oniux was not installed automatically. Install it with one of:"
        echo "      paru -S oniux"
        echo "      cargo install --git https://gitlab.torproject.org/tpo/core/oniux oniux"
        echo "    Until then, every network capability will report the boundary unavailable."
    fi
fi

# The TUN device oniux creates inside its namespace.
if [ ! -e /dev/net/tun ]; then
    if modprobe tun 2>/dev/null; then
        echo "[ok] loaded the tun module"
    else
        echo "[!] could not load the tun module: run 'sudo modprobe tun'"
    fi
fi

# oniux builds its network namespace from unprivileged user namespaces, which
# some distributions restrict.
if [ -r /proc/sys/kernel/unprivileged_userns_clone ] \
   && [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != "1" ]; then
    echo "[!] kernel.unprivileged_userns_clone=0 — oniux cannot create namespaces."
    echo "    Set it to 1 to let the boundary work."
fi

# Prove the boundary rather than assume it.
if command -v oniux >/dev/null 2>&1; then
    ONIUX_PATH=$(command -v oniux)
    echo "[..] verifying oniux runtime at $ONIUX_PATH"
    if oniux /bin/true >/dev/null 2>&1; then
        echo "[ok] the boundary works: oniux /bin/true exited zero"
    else
        echo "[!] 'oniux /bin/true' failed. Network capabilities will refuse to run."
        echo "    Diagnose with: oniux /bin/true"
    fi
fi

echo ""
echo "[ok] installation complete"
echo "     run 'tsec' to start, or 'tsec --status' to see availability per phase"
