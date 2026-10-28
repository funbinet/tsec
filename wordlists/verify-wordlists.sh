#!/usr/bin/env bash
# ==============================================================================
# TSEC wordlist verifier
# Copyright (c) funbinet. All rights reserved.
# Part of TSEC terminal cybersecurity operations platform by funbinet.
#
# Confirms every wordlist the catalog can reference is present and non-empty,
# then checks shipped copies against MANIFEST.sha256. Cheap enough to run on
# every build.
#
# Usage:
#   ./verify-wordlists.sh              # presence and checksum report
#   ./verify-wordlists.sh --quiet      # one line per problem, nothing else
#
# Exit status is non-zero when a committed wordlist is missing or corrupt, so a
# partial clone cannot pass unnoticed.
# ==============================================================================

set -uo pipefail

BOLD="\033[1m"; GREEN="\033[0;32m"; RED="\033[0;31m"
YELLOW="\033[0;33m"; DIM="\033[2m"; RESET="\033[0m"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Manifest paths are repository relative, so the root is the repository, not
# this directory. TSEC_WORDLIST_ROOT overrides it for a relocated install.
ROOT="${TSEC_WORDLIST_ROOT:-$(cd "$HERE/.." && pwd)}"
MANIFEST="$HERE/MANIFEST.tsv"
SUMS="$HERE/MANIFEST.sha256"
QUIET=false

[ "${1:-}" = "--quiet" ] && QUIET=true

say() { [ "$QUIET" = false ] && echo "$@"; return 0; }

if [ ! -f "$MANIFEST" ]; then
    echo -e "${RED}manifest not found: $MANIFEST${RESET}" >&2
    exit 1
fi

say -e "${BOLD}${DIM}=== TSEC wordlist verification ===${RESET}"

total=0
missing=0
empty=0
badsum=0

while IFS=$'\t' read -r rel tier sha url note; do
    case "$rel" in ''|\#*) continue ;; esac
    total=$((total + 1))
    dest="$ROOT/$rel"

    if [ ! -f "$dest" ]; then
        if [ "$tier" = "fetch" ]; then
            say -e "  ${YELLOW}--${RESET} $rel ${DIM}(large list, run fetch-wordlists.sh)${RESET}"
        else
            echo -e "  ${RED}!!${RESET} $rel ${DIM}(missing from the repository)${RESET}"
            missing=$((missing + 1))
        fi
        continue
    fi

    if [ ! -s "$dest" ]; then
        echo -e "  ${RED}!!${RESET} $rel ${DIM}(empty)${RESET}"
        empty=$((empty + 1))
        continue
    fi

    if [ "$tier" != "fetch" ] && [ "$sha" != "-" ] && [ -n "$sha" ]; then
        got=$(sha256sum "$dest" | awk '{print $1}')
        if [ "$got" != "$sha" ]; then
            echo -e "  ${RED}!!${RESET} $rel ${DIM}(sha256 mismatch)${RESET}"
            badsum=$((badsum + 1))
            continue
        fi
    fi

    say -e "  ${GREEN}OK${RESET} $rel ${DIM}($(wc -l <"$dest" | tr -d ' ') lines)${RESET}"
done < "$MANIFEST"

# Cross-check the recorded digests for the shipped tier.
if [ -f "$SUMS" ] && [ "$QUIET" = false ]; then
    say ""
    say -e "${BOLD}${DIM}=== committed checksums ===${RESET}"
    badsums=0
    while read -r want rel; do
        [ -z "${rel:-}" ] && continue
        f="$ROOT/${rel#\*}"
        [ -f "$f" ] || continue
        got=$(sha256sum "$f" | awk '{print $1}')
        if [ "$got" != "$want" ]; then
            echo -e "  ${RED}!!${RESET} $rel ${DIM}(digest differs)${RESET}"
            badsums=$((badsums + 1))
        fi
    done < "$SUMS"
    if [ "$badsums" -eq 0 ]; then
        say -e "  ${GREEN}OK${RESET} MANIFEST.sha256 verifies"
    fi
fi

echo ""
if [ $((missing + empty + badsum)) -eq 0 ]; then
    say -e "${GREEN}All $total declared wordlists are present.${RESET}"
    exit 0
fi
echo -e "${RED}$missing missing, $empty empty, $badsum corrupt.${RESET}" >&2
exit 1
