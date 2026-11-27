#!/usr/bin/env python3
"""Run one CI test suite; discover integration targets from Cargo, including new ones."""

import argparse
import json
from pathlib import Path
import shlex
import subprocess


SUITES = ("core-unit", "core-integration-1", "core-integration-2", "workspace")
ROOT = Path(__file__).resolve().parent.parent


def integration_groups(targets):
    # Approximate seconds from the existing local workspace run (2026-11-27). Keep the
    # slower targets apart; unmeasured/new targets still run, with a 10-second estimate.
    durations = json.loads((ROOT / "scripts/ci-core-test-seconds.json").read_text())
    groups = [[], []]
    totals = [0, 0]
    for target in sorted(targets, key=lambda t: (-durations.get(t, 10), t)):
        shard = min(range(2), key=lambda i: (totals[i], len(groups[i]), i))
        groups[shard].append(target)
        totals[shard] += durations.get(target, 10)
    return [sorted(group) for group in groups]


def test_args(suite, metadata):
    if suite == "workspace":
        return ["--workspace", "--exclude", "picket-core"]
    if suite == "core-unit":
        return ["--package", "picket-core", "--lib", "--bins"]

    core = next(p for p in metadata["packages"] if p["name"] == "picket-core")
    targets = [t["name"] for t in core["targets"] if "test" in t["kind"]]
    shard = int(suite.rsplit("-", 1)[1]) - 1
    selected = integration_groups(targets)[shard]
    if not selected:
        raise ValueError(f"{suite}: no integration targets selected")
    return ["--package", "picket-core", *[a for t in selected for a in ("--test", t)]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=SUITES)
    parser.add_argument("--no-run", action="store_true", help="compile before saving the cache")
    parser.add_argument("--dry-run", action="store_true", help="print the selected Cargo command")
    args = parser.parse_args()
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"], cwd=ROOT
        )
    )
    command = ["cargo", "test", "--profile", "ci", "--locked", "--no-fail-fast", *test_args(args.suite, metadata)]
    if args.no_run:
        command.append("--no-run")
    print(shlex.join(command), flush=True)
    if not args.dry_run:
        return subprocess.call(command, cwd=ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
