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
GitHub Actions (`ubuntu-latest`). Rust checks run independently from four test jobs: core unit
tests, two groups of core integration tests, and the remaining workspace. Integration targets
are discovered from Cargo metadata and balanced using approximate durations in
`scripts/ci-core-test-seconds.json`; new targets get a default estimate and are included
automatically. Core doctests run separately; the remaining workspace job includes its doctests.

To reproduce a test job locally:

```sh
python3 scripts/ci-rust-tests.py core-integration-1  # also: core-unit, core-integration-2, workspace
cargo test --profile ci --package picket-core --doc --locked
```

The `ci` test profile optimises the rules, bundle and wire crates. Application crates keep dev
optimisation settings; debug assertions and overflow checks stay enabled. Native jobs share
compiled objects through `sccache`; Cargo download archives have one
writer on `main`. They cache neither complete `target` directories nor toolchains. The ARM job
uses a pruned dependency cache. Cache keys follow compiler/dependency inputs rather than commit
SHAs. Compatible finished compilations can be reused across jobs; simultaneous cold misses
can still compile the same dependency. Tool binaries are downloaded at pinned versions and
verified against pinned SHA-256 sums.

UI lint/build, two UI test shards, extension packaging, and the two browser projects run
independently. The UI typecheck runs once in the build job; each browser uses two workers.
PRs run only the components and CodeQL languages selected by their changed files; pushes to
`main` run all components. The combined `rust`, `ui`, `extension-browsers` and `CodeQL` checks
fail if a selected job fails or change selection fails, and allow intentionally unselected jobs.

The spec's VM integration, binfmt, golden-bundle-on-aarch64,
Valgrind budget, release, signing, image-rebuild and firmware-canary pipelines are not wired up
here yet.

CodeQL scans affected languages on PRs, and all three languages on `main`, weekly and manual runs.
Dependency review rejects newly introduced high/critical vulnerabilities on PRs. Dependabot
checks for version updates daily at staggered times for Cargo (including fuzz workspaces), npm,
Actions and the Docker base image, with at most two open version-update PRs per ecosystem.
Minor/patch and major groups are separate; security updates remain alert-driven. Dependabot's
Rust test matrix runs at most two lanes concurrently; other PRs can run all four.
See [CI security](docs/ci-security.md) for coverage and the
repository settings needed for Dependabot alerts and security updates.
