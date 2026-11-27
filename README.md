# Picket

A self-hosted DNS filtering system: **picket-edge** on the UniFi Cloud Gateway Fiber, with
**picket-edge-helper** and **picket-edge-update** beside it; **picket-core**, the management
app; and **picket-browser-extension**.

## Layout

| Path | What |
|---|---|
| `crates/picket-wire` | DNS on hickory-proto: query checks, answer scrub and facts, cache-hit serving, reply and query writers |
| `crates/picket-rules` | Normalisation, format parsers, rule classifier, AdGuard semantics |
| `crates/picket-bundle` | Bundle format writer (core) and reader/matcher (edge) |
| `crates/picket-lookup` | Lookup module trait, `LookupClient`, built-in lookup modules (`src/modules/<id>/`) |
| `crates/picket-api` | Serde types for every interface |
| `apps/picket-edge` | The edge service and CLI |
| `apps/picket-edge-helper` | The ipset/iptables helper |
| `apps/picket-edge-update` | The root installer and updater |
| `apps/picket-core` | The management app (embeds `ui/dist`) |
| `ui/` | React + Vite web UI |
| `extension/` | Browser extension (Brave, Firefox) |
| `dist/` | systemd units, firmware minimums, updater dependency allowlist, Docker file |
| `fixtures/` | Recorded feeds, upstream answers, golden bundles |
| `build-support/` | Code the build scripts share (module registry scan, release public keys) |

## Building

```sh
cargo build --workspace          # toolchain pinned in rust-toolchain.toml
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

No `unsafe` code: `unsafe_code = "forbid"` applies workspace-wide.

### Release public keys

Release minisign public keys are environment-specific and are not committed to this repository.
Supply them at build time when building release binaries:

- `PICKET_RELEASE_PUB`: one or more minisign public keys (base64 key lines, comma/whitespace
  separated, or `.pub` file text); in CI, set from the `RELEASE_PUB` Actions variable.
- `PICKET_RELEASE_PUB_FILE`: path to a minisign `.pub` file (absolute or relative to the workspace
  root).
- `PICKET_REQUIRE_RELEASE_KEYS=1`: fail the build if no keys were supplied (use in release jobs).

When unset, binaries compile with no default release keys and fail closed unless keys are provided
at runtime (`release_keys` in `edge.json` on edges).

## CI

`.github/workflows/ci.yml` runs fmt, clippy and tests, and builds the UI and the extension, on
GitHub Actions (`ubuntu-latest`). The spec's VM integration, binfmt, golden-bundle-on-aarch64,
Valgrind budget, release, signing, image-rebuild and firmware-canary pipelines are not wired up
here yet.

CodeQL scans Rust, JavaScript/TypeScript and GitHub Actions on PRs, pushes to `main` and weekly.
Dependency review rejects newly introduced high/critical vulnerabilities on PRs. Dependabot
opens weekly update PRs for Cargo (including fuzz workspaces), npm, Actions and the Docker base
image; those PRs run the same CI. See [CI security](docs/ci-security.md) for coverage and the
repository settings needed for Dependabot alerts and security updates.
