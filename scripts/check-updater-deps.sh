#!/bin/sh
# CI check (build-and-test.md §4, "Updater dependencies"): every normal dependency of
# picket-edge-update must be listed in dist/updater-deps-allowlist.json, so no DNS, network, TLS
# or async code reaches the root installer (security.md §3).
#
# Usage: scripts/check-updater-deps.sh [extra cargo tree flags]
# Checks every target (`--target all`), so a dependency gated on aarch64, the gateway's
# architecture, is seen from an x86_64 runner; pass `--target <triple>` to check one instead.
# Needs only cargo, sed, sort and grep. The allowlist keeps one "crate": "why" entry per line.
set -eu

cd "$(dirname "$0")/.."
allowlist=dist/updater-deps-allowlist.json
if [ ! -f "$allowlist" ]; then
    echo "check-updater-deps: $allowlist is missing" >&2
    exit 1
fi

allowed=$(sed -n 's/^ *"\([A-Za-z0-9][A-Za-z0-9_.-]*\)": *".*",\{0,1\} *$/\1/p' "$allowlist" | sort -u)
if [ -z "$allowed" ]; then
    echo "check-updater-deps: no crates found in $allowlist" >&2
    exit 1
fi

target="--target all"
for arg in "$@"; do
    case "$arg" in
        --target | --target=*) target="" ;;
    esac
done
# $target is unquoted on purpose: it is two words, or none.
# shellcheck disable=SC2086
tree=$(cargo tree -p picket-edge-update -e normal --prefix none --locked $target "$@")
deps=$(printf '%s\n' "$tree" | sed -n 's/^\([A-Za-z0-9][A-Za-z0-9_-]*\) v[0-9].*/\1/p' | sort -u)
if [ -z "$deps" ]; then
    echo "check-updater-deps: cargo tree listed no crates" >&2
    exit 1
fi

bad=""
for dep in $deps; do
    if ! printf '%s\n' "$allowed" | grep -qx -- "$dep"; then
        bad="$bad $dep"
    fi
done

if [ -n "$bad" ]; then
    echo "check-updater-deps: picket-edge-update depends on crates outside $allowlist:" >&2
    for dep in $bad; do
        echo "  $dep" >&2
        printf '%s\n' "$tree" | grep -E "^$dep v" | head -n 1 | sed 's/^/    /' >&2
    done
    echo "Remove the dependency, or add it to the allowlist with a reason if it is JSON, minisign or tar.gz plumbing." >&2
    exit 1
fi

count=$(printf '%s\n' "$deps" | wc -l | tr -d ' ')
echo "check-updater-deps: all $count normal dependencies of picket-edge-update (${target:-$*}) are allowlisted"
