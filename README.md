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
| `crates/picket-schedule` | The `dynamic` feed scheduler's learner and its backtests (core re-exports them) |
| `apps/picket-edge` | The edge service and CLI |
| `apps/picket-edge-helper` | The ipset/iptables helper |
| `apps/picket-edge-update` | The root installer and updater |
| `apps/picket-core` | The management app (embeds `ui/dist`) |
| `ui/` | React + Vite web UI |
| `extension/` | Browser extension (Brave, Firefox) |
| `dist/` | systemd units, firmware minimums, updater dependency allowlist, Docker file |
| `fixtures/` | Recorded feeds, upstream answers, golden bundles |
| `build-support/` | Code the build scripts share (module registry scan, release public keys) |

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:196d5f5916d57c51f79d036bd79a8134898f9c4b85c6eea566af02bb785ba08a -->

## Reaching Core through a container or WSL port forward

When a container port is published on a host IP, or Windows forwards a port to Core in WSL,
initialize Core with the IP clients use, for example:

```sh
picket-core init --data-dir /path/to/data --web-addresses 192.168.1.50,fd00::50
```

Publish or forward the host port to Core's configured web port (8443 by default). The external
port may differ. For an existing instance, set `web.addresses` under Settings → Web and access.
Use exact IP literals without brackets, ports or CIDR prefixes. Core still accepts its own IPs
and configured DNS names; this setting does not change binding, client allowlists, outbound source
IPs or DNS registration.

With managed TLS, Core includes declared RFC1918 and ULA addresses in its LAN CA certificate.
Install and trust the LAN CA root on each client before accessing the forwarded HTTPS address;
fetch `/lanca/ca.pem` from a trusted connection or the optional plain HTTP lists port and verify
it through a trusted channel. Other IP addresses are accepted as Host but cannot be included in
the managed certificate: use a suitable file certificate or a configured DNS name for verified
HTTPS. `web.names` must remain DNS names under `lanca.zones`.

## Building

<!-- /coderabbit-ai-generated:v1 -->

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

## Existing installs

There are no existing installs yet, so renaming a config or schema field (in `edge.json`, other
stored config or state, or the `picket-api` types) doesn't need a migration or compatibility
handling for previously stored data. Revisit this once there are real deployments.

## CI

`.github/workflows/ci.yml` runs on GitHub Actions. Its first job, **Changes and lint**, picks the
jobs a change needs from the paths it touches (`dorny/paths-filter`: a PR's diff against its
base; on `main`, the diff since the commit before the push; changing `ci.yml` picks every job)
and runs the cheap checks before anything long starts: typos (`_typos.toml`) and, when workflows
change, zizmor (`.github/zizmor.yml`). Weekly runs pick every job but the fuzz CodeQL scan, which
runs monthly. Manual runs (**Actions → ci → Run workflow**) pick every job, or one group: `rust`,
`edge`, `deny`, `fuzz`, `ui`, `extension`, `codeql` or `codeql-fuzz`.

| Job | Runs when | What |
|---|---|---|
| Rust (x86_64) | Rust sources, manifests, fixtures, toolchain | rustfmt (also over the lookup modules, which `cargo fmt` doesn't reach), updater dependency allowlist, clippy, `cargo doc` (broken links fail; links to private items are allowed), cargo-nextest over the workspace except the edge side, doctests |
| Edge tests (arm64) | the edge apps or the crates they link | the edge side's tests (`EDGE_PACKAGES` in `ci.yml`), natively on `ubuntu-24.04-arm`, where the edge ships |
| Edge aarch64 cross-build | same | `scripts/check-edge-aarch64.sh` (zig, glibc floor 2.41); on PRs, a warning (never a failure) when an edge binary grows more than 2 % against `main` |
| cargo deny | manifests, `Cargo.lock`, `deny.toml` | advisories, licences, bans, sources |
| Fuzz workspaces | `fuzz/` | rustfmt and `cargo check --locked --all-targets` in each `fuzz/*` workspace |
| UI | `ui/` | lint, typecheck, build, tests |
| Extension | `extension/` | build, lint, tests, reproducible packages, Chromium and Firefox tests in the Playwright image |
| Review dependency changes | PRs changing manifests, lockfiles or workflows | rejects new high/critical vulnerabilities |
| CodeQL (rust, javascript-typescript) | pushes to `main` changing that language; weekly; manual | `security-extended`, `fuzz/` excluded (`.github/codeql/codeql-config.yml`); not on PRs |
| CodeQL (rust, fuzz workspaces) | monthly; manual | the harness code in `fuzz/` only, under its own category (`.github/codeql/codeql-fuzz-config.yml`) |
| CI | always | the one check to require: fails if change selection failed or a picked job didn't pass |

A PR's new push cancels its older run; every push to `main` runs to completion (one concurrency
group per commit), so routing by diff never skips a merge. Jobs run on GitHub's free runners for
public repositories, sized to the work: the router, the `CI` gate, dependency review and the
SonarQube sync on `ubuntu-slim` (1 CPU, 15-minute job cap, no Rust toolchain), builds and tests
on `ubuntu-latest` (4 CPUs), and the edge tests on `ubuntu-24.04-arm`. The cross-build stays alongside the
arm64 tests so the edge checks still work where only x86_64 runners exist.

To run the Rust checks locally:

```sh
cargo clippy --profile ci --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings -A rustdoc::private_intra_doc_links" cargo doc --profile ci --workspace --no-deps --locked
cargo nextest run --profile ci --cargo-profile ci --workspace --locked
cargo test --profile ci --workspace --doc --locked
```

`picket-core`'s integration tests build as one test binary (`tests/main.rs` declares each file);
nextest runs each test in its own process and kills one still running after 5 minutes
(`.config/nextest.toml`). The `ci` profile optimises the rules, bundle and wire crates, and
`picket-schedule` is built at opt-level 3 in every dev build (its backtests are CPU-bound);
application crates keep dev settings, and debug assertions and overflow checks stay on.
`Swatinem/rust-cache` restores dependencies' build output from `main`'s last run (only `main`
saves). Tool binaries are downloaded at pinned versions and checked against pinned SHA-256 sums
(`scripts/install-ci-tool.sh`).

The arm64 job covers the spec's golden-bundle reads on aarch64 natively (the `binfmt` runner
would run them under QEMU). The spec's VM integration, UniFi userland smoke test, Valgrind
budget, release, signing, image-rebuild and firmware-canary pipelines are not wired up here yet.

SonarQube Cloud findings (vulnerabilities, bugs, and code smells) are synced into GitHub Code
Scanning via `.github/workflows/sonar-sarif.yml`. `.github/workflows/rustsec-advisories.yml`
checks RustSec advisories daily for the root and every fuzz lockfile and opens an issue (or
comments on the open one) when one fails. Dependabot checks for version updates weekly, at
staggered times on Mondays, for Cargo (including fuzz workspaces), npm, Actions and the Docker
base image, waits 3 days after a release before proposing it, and opens at most two
version-update PRs per ecosystem. Minor/patch and major groups are separate; security updates
remain alert-driven and skip the schedule and the wait.
See [CI security](docs/ci-security.md) for coverage and the
repository settings needed for Dependabot alerts and security updates.
