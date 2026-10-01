#!/usr/bin/env bash
# ==============================================================================
# TSEC 3.0 Tool Dependency Resolver & Installer
# Copyright (c) funbinet. All rights reserved.
# Part of TSEC terminal cybersecurity operations platform by funbinet.
#
# The tool list for each phase is read straight from catalog/capabilities.toml
# (the same catalog the TUI executes), so this script can never drift from
# what the framework actually runs.
#
# Usage:
#   ./tools.sh -recon            # resolve & install tools for RECONNAISSANCE
#   ./tools.sh -surface          # ... ATTACK SURFACE
#   ./tools.sh -vulnerability    # ... VULNERABILITY
#   ./tools.sh -payload          # ... PAYLOAD
#   ./tools.sh -escalation       # ... PRIVILEGE ESCALATION
#   ./tools.sh -credentials      # ... CREDENTIALS
#   ./tools.sh -lateral          # ... LATERAL MOVEMENT
#   ./tools.sh -persistence      # ... PERSISTENCE & DEFENSE EVASION
#   ./tools.sh -objectives       # ... OBJECTIVES
#   ./tools.sh -wireless         # ... WIRELESS
#   ./tools.sh -all              # every phase
#   ./tools.sh -recon -c         # check only; never install
# ==============================================================================

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/go/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:$PATH"

CATALOG="catalog/capabilities.toml"
CHECK_ONLY=false

IS_ARCH=false
IS_KALI=false
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
        *arch*|*omarchy*) IS_ARCH=true ;;
        *kali*|*debian*|*ubuntu*) IS_KALI=true ;;
    esac
fi

check_tool() {
    local bin="$1"
    command -v "$bin" >/dev/null 2>&1 && return 0
    for p in "$HOME/.cargo/bin/$bin" "$HOME/.local/bin/$bin" "$HOME/go/bin/$bin" \
             "/usr/local/bin/$bin" "/usr/bin/$bin" "/sbin/$bin" "/usr/sbin/$bin"; do
        [ -x "$p" ] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Tool -> package mapping: "tool|arch package|kali package".
# Anything not listed falls back to a same-name package guess plus a
# yay/apt search command, so every tool always gets usable guidance.
# ---------------------------------------------------------------------------
pkg_info() {
    local tool="$1"
    case "$tool" in
        amass) echo "amass|amass" ;;
        arp-scan) echo "arp-scan|arp-scan" ;;
        asnmap) echo "asnmap|asnmap" ;;
        assetfinder) echo "assetfinder|assetfinder" ;;
        aws) echo "aws-cli|awscli" ;;
        b2sum|base64|cat|cksum|dd|diff|du|find|grep|id|ip|stat|sort|split|tee|touch|truncate|wc) echo "coreutils|coreutils" ;;
        capsh) echo "libcap|libcap2-bin" ;;
        chisel) echo "chisel|chisel" ;;
        cloud_enum) echo "cloud-enum|cloud-enum" ;;
        ctfr) echo "ctfr-git|ctfr" ;;
        curl) echo "curl|curl" ;;
        dig|host) echo "bind|dnsutils" ;;
        docker) echo "docker|docker.io" ;;
        enum4linux-ng) echo "enum4linux-ng|enum4linux-ng" ;;
        exiftool) echo "perl-image-exiftool|libimage-exiftool-perl" ;;
        ffuf) echo "ffuf|ffuf" ;;
        file) echo "file|file" ;;
        freeradius-wpe) echo "freeradius-wpe|freeradius-wpe" ;;
        git) echo "git|git" ;;
        gitleaks) echo "gitleaks|gitleaks" ;;
        hashcat) echo "hashcat|hashcat" ;;
        httpx) echo "httpx|httpx-toolkit" ;;
        impacket-*) echo "impacket|python3-impacket" ;;
        john) echo "john|john" ;;
        jq) echo "jq|jq" ;;
        masscan) echo "masscan|masscan" ;;
        mat2) echo "mat2|mat2" ;;
        msfconsole|msfvenom) echo "metasploit|metasploit-framework" ;;
        ncat) echo "nmap|ncat" ;;
        nmap) echo "nmap|nmap" ;;
        objdump|readelf|strings) echo "binutils|binutils" ;;
        openssl) echo "openssl|openssl" ;;
        pdfinfo) echo "poppler|poppler-utils" ;;
        php) echo "php|php" ;;
        proxychains4) echo "proxychains-ng|proxychains4" ;;
        python3) echo "python|python3" ;;
        rustscan) echo "rustscan|rustscan" ;;
        samdump2) echo "chntpw|chntpw" ;;
        searchsploit) echo "exploitdb|exploitdb" ;;
        shodan) echo "python-shodan|shodan" ;;
        smbclient) echo "smbclient|smbclient" ;;
        snmpwalk) echo "net-snmp|snmp" ;;
        socat) echo "socat|socat" ;;
        sqlite3) echo "sqlite|sqlite3" ;;
        ssh) echo "openssh|openssh-client" ;;
        strace) echo "strace|strace" ;;
        testssl.sh) echo "testssl.sh|testssl.sh" ;;
        theharvester) echo "theharvester|theharvester" ;;
        traceroute) echo "traceroute|traceroute" ;;
        upx) echo "upx-ucl|upx-ucl" ;;
        wget) echo "wget|wget" ;;
        whois) echo "whois|whois" ;;
        xxd) echo "xxd|xxd" ;;
        yara) echo "yara|yara" ;;
        zip) echo "zip|zip" ;;
        7z) echo "p7zip|p7zip-full" ;;
        *) echo "$tool|$tool" ;;
    esac
}

# Guidance when an automated install fails or check-only is set.
manual_commands() {
    local tool="$1"
    local info arch_pkg kali_pkg
    info=$(pkg_info "$tool")
    arch_pkg="${info%%|*}"
    kali_pkg="${info##*|}"

    echo "    Arch Linux : sudo pacman -S $arch_pkg"
    echo "                 (if not found: yay -Ss $arch_pkg)"
    echo "    Kali Linux : sudo apt update && sudo apt install -y $kali_pkg"
    echo "                 (if not found: apt search $kali_pkg)"
}

try_install() {
    local tool="$1"
    local info arch_pkg kali_pkg
    info=$(pkg_info "$tool")
    arch_pkg="${info%%|*}"
    kali_pkg="${info##*|}"

    # oniux: built from source (crates.io has only a placeholder release).
    if [ "$tool" = "oniux" ]; then
        echo -e "    ${CYAN}[..] installing oniux from source (gitlab.torproject.org)...${RESET}"
        local tmp
        tmp=$(mktemp -d)
        if git -q clone --depth 1 --branch v0.13.0 \
             https://gitlab.torproject.org/tpo/core/oniux "$tmp/oniux" 2>/dev/null &&
           (cd "$tmp/oniux" && cargo build --release >/dev/null 2>&1) &&
           install -Dm755 "$tmp/oniux/target/release/oniux" "$HOME/.local/bin/oniux" 2>/dev/null; then
            rm -rf "$tmp"
            return 0
        fi
        rm -rf "$tmp"
        echo "    Arch Linux : yay -S oniux"
        echo "                 (or: cargo install --git https://gitlab.torproject.org/tpo/core/oniux oniux)"
        echo "    Kali Linux : cargo install --git https://gitlab.torproject.org/tpo/core/oniux oniux"
        return 1
    fi

    if [ "$IS_ARCH" = true ]; then
        if command -v pacman >/dev/null 2>&1 &&
           sudo -n pacman -S --noconfirm --needed "$arch_pkg" >/dev/null 2>&1; then
            return 0
        fi
        if command -v yay >/dev/null 2>&1 &&
           yay -S --noconfirm --needed "$arch_pkg" >/dev/null 2>&1; then
            return 0
        fi
    elif [ "$IS_KALI" = true ]; then
        if command -v apt-get >/dev/null 2>&1 &&
           sudo -n apt-get install -y "$kali_pkg" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Extract the unique provider binaries for a phase from the TOML catalog.
tools_for_phase() {
    local phase="$1"
    python3 - "$CATALOG" "$phase" <<'PY'
import sys, re

path, phase = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
text = open(path, encoding="utf-8").read()

cap_re = re.compile(r"^\[\[capability\]\](.*?)^(?=\[\[capability\]\]|\Z)", re.S | re.M)
bin_re = re.compile(r"^binary\s*=\s*'([^']+)'", re.M)
phase_re = re.compile(r"^phase\s*=\s*'([^']+)'", re.M)

bins = []
for block in cap_re.finditer(text):
    body = block.group(1)
    m = phase_re.search(body)
    if phase in ("", "all") or (m and m.group(1) == phase):
        for bm in bin_re.finditer(body):
            b = bm.group(1)
            if b not in bins:
                bins.append(b)
print(" ".join(bins))
PY
}

resolve_phase() {
    local phase="$1"
    local phase_names="recon surface vulnerability payload escalation credentials lateral persistence objectives wireless"

    if [ ! -f "$CATALOG" ]; then
        # Allow running from anywhere: fall back to the script's directory.
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        CATALOG="$script_dir/$CATALOG"
    fi
    if [ ! -f "$CATALOG" ]; then
        echo -e "${RED}catalog not found: catalog/capabilities.toml${RESET}"
        exit 1
    fi
    if [ "$phase" != "all" ] && ! [[ " $phase_names " == *" $phase "* ]]; then
        echo -e "${RED}Unknown phase: $phase${RESET}"
        echo "Valid phases: $phase_names, all"
        exit 1
    fi

    local tools
    tools=$(tools_for_phase "$phase")
    if [ -z "$tools" ]; then
        echo -e "${RED}no tools found for phase: $phase${RESET}"
        exit 1
    fi

    local total
    total=$(wc -w <<<"$tools")
    echo -e "${BOLD}${CYAN}=== TSEC tool resolver: ${phase^^} ($total tools) ===${RESET}"

    local installed=0 missing=0
    local missing_tools=()
    for tool in $tools; do
        if check_tool "$tool"; then
            printf "  ${GREEN}OK ${RESET} %s\n" "$tool"
            installed=$((installed + 1))
        else
            printf "  ${RED}-- ${RESET} %s (missing)\n" "$tool"
            missing=$((missing + 1))
            missing_tools+=("$tool")
        fi
    done

    echo ""
    echo -e "${BOLD}Summary: ${installed} installed, ${missing} missing${RESET}"

    if [ "$missing" -eq 0 ]; then
        echo -e "${GREEN}All tools for phase ${phase} are ready.${RESET}"
        return 0
    fi

    if [ "$CHECK_ONLY" = true ]; then
        echo ""
        echo -e "${BOLD}${YELLOW}Missing tools - installation commands:${RESET}"
        echo "----------------------------------------------------------------"
        for tool in "${missing_tools[@]}"; do
            echo -e "${BOLD}$tool${RESET}"
            manual_commands "$tool"
        done
        echo "----------------------------------------------------------------"
        return 1
    fi

    echo ""
    echo -e "${BOLD}Attempting automated installation of missing tools...${RESET}"
    local still_missing=()
    for tool in "${missing_tools[@]}"; do
        echo -e "Installing ${BOLD}$tool${RESET}..."
        if try_install "$tool" && check_tool "$tool"; then
            echo -e "  ${GREEN}OK installed $tool${RESET}"
        else
            echo -e "  ${YELLOW}! could not install automatically${RESET}"
            still_missing+=("$tool")
        fi
    done

    if [ "${#still_missing[@]}" -gt 0 ]; then
        echo ""
        echo -e "${BOLD}${YELLOW}Manual installation commands for remaining tools:${RESET}"
        echo "----------------------------------------------------------------"
        for tool in "${still_missing[@]}"; do
            echo -e "${BOLD}$tool${RESET}"
            manual_commands "$tool"
        done
        echo "----------------------------------------------------------------"
    else
        echo -e "${GREEN}All missing tools were successfully installed.${RESET}"
    fi
}

usage() {
    echo -e "${BOLD}TSEC 3.0 tool dependency manager${RESET}"
    echo "Usage: $0 [-<phase> ...] [-c]"
    echo ""
    echo "Phases:"
    echo "  -recon           Reconnaissance"
    echo "  -surface         Attack Surface"
    echo "  -vulnerability   Vulnerability"
    echo "  -payload         Payload"
    echo "  -escalation      Privilege Escalation"
    echo "  -credentials     Credentials"
    echo "  -lateral         Lateral Movement"
    echo "  -persistence     Persistence & Defense Evasion"
    echo "  -objectives      Objectives"
    echo "  -wireless        Wireless"
    echo "  -all             Every phase"
    echo ""
    echo "Options:"
    echo "  -c               Check only: report missing tools and their"
    echo "                   Arch + Kali install commands; install nothing"
    exit 0
}

main() {
    [ $# -eq 0 ] && usage

    local phases=()
    for arg in "$@"; do
        case "$arg" in
            -c|--check) CHECK_ONLY=true ;;
            -h|--help) usage ;;
            -*) phases+=("$(echo "$arg" | sed 's/^--*//')") ;;
            *)  phases+=("$arg") ;;
        esac
    done
    [ ${#phases[@]} -eq 0 ] && usage

    local rc=0
    for phase in "${phases[@]}"; do
        resolve_phase "$phase" || rc=1
        echo ""
    done
    exit "$rc"
}

main "$@"
