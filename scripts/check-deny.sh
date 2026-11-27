#!/bin/sh
# CI check (security.md §6, build-and-test.md §4): cargo deny over the whole workspace with every
# feature: RustSec advisories, licences, bans (duplicates, wildcards, ring) and sources, as
# configured in deny.toml at the repository root.
#
# Usage: scripts/check-deny.sh [advisories|bans|licenses|sources ...]
# With no arguments it runs every check. Needs cargo-deny (CI pins the version it installs:
# CARGO_DENY_VERSION in .github/workflows/ci.yml). The advisory check fetches the RustSec database
# into $CARGO_HOME/advisory-dbs.
set -eu

cd "$(dirname "$0")/.."

if ! cargo deny --version >/dev/null 2>&1; then
    echo "check-deny: cargo-deny is missing; install it with" >&2
    echo "  cargo install cargo-deny --version 0.22.1 --locked" >&2
    exit 1
fi
if [ ! -f deny.toml ]; then
    echo "check-deny: deny.toml is missing" >&2
    exit 1
fi

exec cargo deny --all-features --locked check "$@"
