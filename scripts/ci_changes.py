#!/usr/bin/env python3
"""Select CI components and CodeQL languages from a PR's complete Git diff."""

import os
from pathlib import PurePosixPath
import subprocess


COMPONENTS = ("rust", "edge", "deny", "ui", "extension", "codeql_rust", "codeql_js", "codeql_actions")


def classify(paths):
    selected = dict.fromkeys(COMPONENTS, False)
    for path in paths:
        name = PurePosixPath(path).name
        suffix = PurePosixPath(path).suffix.lower()
        if suffix in {".md", ".rst", ".adoc"}:
            continue
        # Changes to the selectors themselves must exercise every selected check.
        if path in {"scripts/ci_changes.py", "scripts/test_ci_changes.py"}:
            return dict.fromkeys(COMPONENTS, True)
        if path == ".github/workflows/codeql.yml":
            selected.update(codeql_rust=True, codeql_js=True, codeql_actions=True)
        if path == ".github/workflows/ci.yml" or path.startswith(".github/actions/"):
            selected.update(rust=True, edge=True, deny=True, ui=True, extension=True)
        if path.startswith((".github/workflows/", ".github/actions/")) and suffix in {".yml", ".yaml"}:
            selected["codeql_actions"] = True
        rust = suffix == ".rs" or name in {"Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml"}
        # Crate data, templates and local fixtures can be embedded by Rust builds.
        if rust or path.startswith((".cargo/", "apps/", "crates/", "build-support/", "fuzz/")):
            selected.update(rust=True, edge=True, deny=True, codeql_rust=True)
        if path.startswith(("fixtures/", "dist/")) or name in {"clippy.toml", "rustfmt.toml"} or path in {
            "scripts/ci-rust-tests.py", "scripts/ci-core-test-seconds.json", "scripts/check-updater-deps.sh"
        }:
            selected.update(rust=True, edge=True)
        if path in {"deny.toml", "scripts/check-deny.sh"}:
            selected["deny"] = True
        if path == "scripts/check-edge-aarch64.sh":
            selected["edge"] = True
        if path == "scripts/install-ci-tool.sh":
            selected.update(edge=True, deny=True)
        if path.startswith("ui/"):
            selected["ui"] = True
        # picket-core's openapi.rs unit test reads the UI's copy of the API document.
        if path == "ui/src/api/openapi.json":
            selected["rust"] = True
        if path.startswith("extension/"):
            selected["extension"] = True
        if path == ".node-version":
            selected.update(ui=True, extension=True, codeql_js=True)
        if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"} or name in {
            "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"
        }:
            selected["codeql_js"] = True
    return selected


def main():
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        base, head = os.environ["BASE_SHA"], os.environ["HEAD_SHA"]
        # No rename detection: removing Rust and adding a document must still scan Rust.
        # The NUL-separated diff handles spaces/newlines and has no API pagination cap.
        output = subprocess.check_output([
            "git", "diff", "--name-only", "--no-renames", "-z", f"{base}...{head}", "--"
        ])
        selected = classify(p.decode("utf-8", errors="surrogateescape") for p in output.split(b"\0") if p)
    else:
        selected = dict.fromkeys(COMPONENTS, True)
    output = "".join(f"{name}={str(value).lower()}\n" for name, value in selected.items())
    print(output, end="")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(output)


if __name__ == "__main__":
    main()
