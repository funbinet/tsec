#!/usr/bin/env bash
# ==============================================================================
# TSEC wordlist fetcher
# Copyright (c) funbinet. All rights reserved.
# Part of TSEC terminal cybersecurity operations platform by funbinet.
#
# Downloads the wordlists that are too large to live in a git repository.
# Everything else is already committed under wordlists/, so a fresh clone can run
# every capability except the ones listed as `fetch` here.
#
# Usage:
#   ./fetch-wordlists.sh              # download every missing `fetch` list
#   ./fetch-wordlists.sh --check      # report which are missing, download nothing
#   ./fetch-wordlists.sh --force      # re-download even if already present
#   TSEC_WORDLIST_ROOT=/path ./fetch-wordlists.sh
#
# Exit status is non-zero if any list is still missing afterwards, so this is
# safe to call from CI or from an install script.
# ==============================================================================

set -uo pipefail

BOLD="\033[1m"; GREEN="\033[0;32m"; RED="\033[0;31m"
YELLOW="\033[0;33m"; CYAN="\033[0;36m"; DIM="\033[2m"; RESET="\033[0m"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Manifest paths are repository relative, so the root is the repository, not
# this directory. TSEC_WORDLIST_ROOT overrides it for a relocated install.
ROOT="${TSEC_WORDLIST_ROOT:-$(cd "$HERE/.." && pwd)}"
MANIFEST="$HERE/MANIFEST.tsv"

CHECK_ONLY=false
FORCE=false

usage() {
    cat <<EOF
${BOLD}TSEC wordlist fetcher${RESET}

Usage: $0 [--check] [--force]

  --check   Report which large wordlists are missing. Download nothing.
  --force   Re-download lists that are already present.
  -h, --help
            Show this help.

Wordlist root: $ROOT
Override with TSEC_WORDLIST_ROOT.
EOF
}
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=true ;;
        --force) FORCE=true ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [ ! -f "$MANIFEST" ]; then
    echo -e "${RED}manifest not found: $MANIFEST${RESET}" >&2
    exit 1
fi

fetch_one() {
    local rel="$1" url="$2" want="$3" dest="$ROOT/$1" tmp

    if [ -s "$dest" ] && [ "$FORCE" = false ]; then
        if [ "$want" != "-" ] && [ -n "$want" ]; then
            local have
            have=$(sha256sum "$dest" | awk '{print $1}')
            if [ "$have" != "$want" ]; then
                echo -e "  ${YELLOW}~${RESET} $(basename "$rel") ${DIM}(checksum differs, re-fetching)${RESET}"
                FORCE_LOCAL=true
            else
                echo -e "  ${GREEN}OK${RESET} $(basename "$rel") ${DIM}(present)${RESET}"
                return 0
            fi
        else
            echo -e "  ${GREEN}OK${RESET} $(basename "$rel") ${DIM}(present)${RESET}"
            return 0
        fi
    fi

    if [ "$CHECK_ONLY" = true ]; then
        echo -e "  ${RED}--${RESET} $(basename "$rel") ${DIM}(missing)${RESET}"
        return 1
    fi

    mkdir -p "$(dirname "$dest")"
    tmp="$dest.part"
    echo -e "  ${CYAN}>>${RESET} $(basename "$rel") ${DIM}(downloading)${RESET}"
    if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 \
              -o "$tmp" "$url"; then
        rm -f "$tmp"
        echo -e "  ${RED}!!${RESET} $(basename "$rel") ${DIM}download failed${RESET}"
        return 1
    fi

    if [ "$want" != "-" ] && [ -n "$want" ]; then
        local got
        got=$(sha256sum "$tmp" | awk '{print $1}')
        if [ "$got" != "$want" ]; then
            rm -f "$tmp"
            echo -e "  ${RED}!!${RESET} $(basename "$rel") ${DIM}sha256 mismatch${RESET}"
            echo "      expected $want"
            echo "      got      $got"
            return 1
        fi
    fi

    mv "$tmp" "$dest"
    echo -e "  ${GREEN}OK${RESET} $(basename "$rel") ${DIM}$(wc -l <"$dest" | tr -d ' ') lines${RESET}"
    return 0
}

echo -e "${BOLD}${CYAN}=== TSEC wordlist fetcher ===${RESET}"
echo -e "${DIM}root: $ROOT${RESET}"
echo ""

missing=0
total=0

while IFS=$'\t' read -r rel tier sha url note; do
    case "$rel" in ''|\#*) continue ;; esac
    [ "$tier" != "fetch" ] && continue
    total=$((total + 1))
    fetch_one "$rel" "$url" "$sha" || missing=$((missing + 1))
done < "$MANIFEST"

echo ""
if [ "$total" -eq 0 ]; then
    echo -e "${GREEN}No large wordlists declared in the manifest.${RESET}"
elif [ "$missing" -eq 0 ]; then
    echo -e "${GREEN}All $total large wordlists are present.${RESET}"
    exit 0
else
    if [ "$CHECK_ONLY" = true ]; then
        echo -e "${YELLOW}$missing of $total large wordlists are not downloaded.${RESET}"
        echo -e "${DIM}Run $0 to fetch them.${RESET}"
    else
        echo -e "${RED}$missing of $total large wordlists could not be fetched.${RESET}"
        echo -e "${DIM}Check network access, then re-run $0.${RESET}"
    fi
    exit 1
fi
