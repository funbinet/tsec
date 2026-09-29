#!/usr/bin/env bash
# TSEC Installer v2.0.0

set -e

# 1. Require root or prompt for sudo FIRST
if [ "$EUID" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

echo -e "\033[32m╔═══════════════════════════════════════════════════════════════╗\033[0m"
echo -e "\033[32m║  \033[1;32mTSEC  \033[0m \033[37mInstaller        \033[0m                                     \033[32m║\033[0m"
echo -e "\033[32m╚═══════════════════════════════════════════════════════════════╝\033[0m"
echo ""


# 2. Find cargo — look in the real user's home even when running as root
find_cargo() {
    # If invoked via sudo, check that user's .cargo/bin first
    if [ -n "$SUDO_USER" ]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        local cargo_bin="$user_home/.cargo/bin"
        if [ -f "$cargo_bin/cargo" ]; then
            export PATH="$cargo_bin:$PATH"
            echo -e "\033[32m[OK]\033[0m Found cargo at $cargo_bin"
            return 0
        fi
    fi
    # Fall back to checking current PATH
    if command -v cargo &> /dev/null; then
        echo -e "\033[32m[OK]\033[0m Found cargo in PATH"
        return 0
    fi
    return 1
}

if ! find_cargo; then
    echo -e "\033[31m[x] ERROR: Cargo (Rust) is not installed or not in PATH.\033[0m"
    echo "Please install Rust via rustup:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "Then open a new terminal and run this installer again."
    exit 1
fi

# 3. Compile project as the invoking user (avoids root-owned target/ files)
echo -e "\033[36m[i]\033[0m Compiling TSEC in release mode..."
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    sudo -u "$SUDO_USER" env PATH="$USER_HOME/.cargo/bin:$PATH" cargo build --release
else
    cargo build --release
fi

if [ ! -f "target/release/tsec" ]; then
    echo -e "\033[31m[x] ERROR: Build failed — cannot find target/release/tsec.\033[0m"
    exit 1
fi

# 4. Install binary
echo -e "\033[36m[i]\033[0m Installing binary to /usr/bin/tsec..."
cp -f target/release/tsec /usr/bin/tsec
chmod +x /usr/bin/tsec

# 5. Create workspace directories
echo -e "\033[36m[i]\033[0m Creating workspace at /opt/tsec/..."
mkdir -p /opt/tsec/output /opt/tsec/logs /opt/tsec/config /opt/tsec/wordlists /opt/tsec/scripts /opt/tsec/configs /opt/tsec/tools /opt/tsec/projects

if [ -n "$SUDO_USER" ]; then
    chown -R "$SUDO_USER:$SUDO_USER" /opt/tsec
fi

# 6. Install the network-execution boundary
#
# oniux is not a provider tool: it is the boundary every network-capable command
# is launched through. TSEC has no proxy configuration and no in-framework
# switch, so a missing or broken oniux means no network capability can run at
# all. Install it here, or let the operator do it, but never silently skip it.
echo ""
echo -e "\033[36m[i]\033[0m Checking the oniux network boundary..."

install_oniux() {
    if command -v paru >/dev/null 2>&1; then
        paru -S --needed oniux && return $?
    elif command -v yay >/dev/null 2>&1; then
        yay -S --needed oniux && return $?
    fi
    return 1
}

if command -v oniux >/dev/null 2>&1; then
    echo -e "\033[32m[OK]\033[0m oniux found at $(command -v oniux)"
elif install_oniux; then
    echo -e "\033[32m[OK]\033[0m oniux installed"
else
    echo -e "\033[33m[!]\033[0m oniux was not installed automatically."
    echo -e "    Install it with one of:"
    echo -e "      paru -S oniux          # Arch / AUR"
    echo -e "      cargo install --git https://gitlab.torproject.org/tpo/core/oniux --tag v0.4.0 oniux"
    echo -e "    Network capabilities will report the boundary as unavailable until you do."
fi

# The TUN device oniux creates inside its namespace; without the module it
# cannot establish its network at all.
if [ ! -e /dev/net/tun ]; then
    modprobe tun 2>/dev/null && echo -e "\033[32m[OK]\033[0m loaded the tun module" \
        || echo -e "\033[33m[!]\033[0m could not load the tun module: run 'sudo modprobe tun'."
fi

# oniux builds its own network namespace with unprivileged user namespaces.
# Some distributions disable them; oniux then cannot isolate anything.
if [ -r /proc/sys/kernel/unprivileged_userns_clone ] \
   && [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != "1" ]; then
    echo -e "\033[33m[!]\033[0m kernel.unprivileged_userns_clone=0 — oniux cannot create"
    echo -e "    namespaces. Set it to 1 to let the boundary work."
fi

echo ""
echo -e "\033[32m[OK] Installation Complete!\033[0m"
echo -e "Run \033[1;32mtsec\033[0m from anywhere to launch the framework."
echo -e "Network capabilities run as 'oniux <tool> ...'. Check the boundary with: oniux /bin/true"
