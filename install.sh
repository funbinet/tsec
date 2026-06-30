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

echo ""
echo -e "\033[32m[OK] Installation Complete!\033[0m"
echo -e "Run \033[1;32mtsec\033[0m from anywhere to launch the framework."
