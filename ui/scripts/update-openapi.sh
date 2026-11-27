#!/usr/bin/env bash
# Regenerates ui/src/api/openapi.json and ui/src/api/schema.d.ts from a picket-core build.
#
# It runs a throwaway core instance as the current user (no root, no edits to core):
#   init --data-dir <tmp> on high ports, run, fetch /api/ui/v1/openapi.json with the first
#   admin password, stop it, then run openapi-typescript.
#
# Usage: ui/scripts/update-openapi.sh [path/to/picket-core]
#   Without an argument it builds picket-core with cargo (debug) into target-ui-openapi/.
#   PICKET_CORE_WEB_PORT / PICKET_CORE_EDGE_PORT override the ports (default 18943 / 18944).
#   Alternatively: PICKET_CORE_URL=https://host:port PICKET_CORE_PASSWORD=… fetches from a
#   running core instead of starting one.
set -euo pipefail

ui_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd "$ui_dir/.." && pwd)"
out_json="$ui_dir/src/api/openapi.json"

fetch() { # url password
  # --insecure: the only cores this talks to are a throwaway one it starts on 127.0.0.1 (its web
  # certificate is self-issued at first start, before any LAN CA trust exists) with a one-time
  # password, or one named by PICKET_CORE_URL on purpose. Never point it at a core across a network.
  curl --fail --silent --show-error --insecure --max-time 30 \
    --user "admin:$2" "$1/api/ui/v1/openapi.json" -o "$out_json.tmp"
}

if [[ -n "${PICKET_CORE_URL:-}" ]]; then
  fetch "$PICKET_CORE_URL" "${PICKET_CORE_PASSWORD:?set PICKET_CORE_PASSWORD}"
else
  core_bin="${1:-}"
  if [[ -z "$core_bin" ]]; then
    (cd "$repo_dir" && CARGO_TARGET_DIR="$repo_dir/target-ui-openapi" cargo build -p picket-core --bin picket-core)
    core_bin="$repo_dir/target-ui-openapi/debug/picket-core"
  fi
  web_port="${PICKET_CORE_WEB_PORT:-18943}"
  edge_port="${PICKET_CORE_EDGE_PORT:-18944}"
  tmp="$(mktemp -d)"
  core_pid=""
  cleanup() {
    if [[ -n "$core_pid" ]]; then kill "$core_pid" 2>/dev/null || true; wait "$core_pid" 2>/dev/null || true; fi
    rm -rf "$tmp"
  }
  trap cleanup EXIT
  "$core_bin" init --data-dir "$tmp/data" --web-port "$web_port" --edge-port "$edge_port" >/dev/null
  "$core_bin" run --data-dir "$tmp/data" >"$tmp/core.log" 2>&1 &
  core_pid=$!
  password="$(cat "$tmp/data/initial-password")"
  for _ in $(seq 1 60); do
    if fetch "https://127.0.0.1:$web_port" "$password" 2>/dev/null; then break; fi
    if ! kill -0 "$core_pid" 2>/dev/null; then cat "$tmp/core.log" >&2; exit 1; fi
    sleep 0.5
  done
  [[ -s "$out_json.tmp" ]] || { echo "could not fetch the OpenAPI document" >&2; cat "$tmp/core.log" >&2; exit 1; }
fi

# Pretty-print with sorted keys so diffs stay readable.
node -e '
const fs = require("fs");
const sort = (v) => Array.isArray(v) ? v.map(sort) : v && typeof v === "object"
  ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sort(v[k])])) : v;
const doc = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
fs.writeFileSync(process.argv[2], JSON.stringify(sort(doc), null, 2) + "\n");
' "$out_json.tmp" "$out_json"
rm -f "$out_json.tmp"

cd "$ui_dir"
npx --no-install openapi-typescript src/api/openapi.json -o src/api/schema.d.ts --default-non-nullable false
echo "updated $out_json and src/api/schema.d.ts"
