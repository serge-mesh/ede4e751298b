#!/usr/bin/env python3
"""Unit tests for scripts/sonarcloud-to-sarif.py."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

SCRIPT_PATH = pathlib.Path(__file__).resolve().parent / "sonarcloud-to-sarif.py"
SPEC = importlib.util.spec_from_file_location("sonarcloud_to_sarif", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load module spec from {SCRIPT_PATH}")
mod = importlib.util.module_from_spec(SPEC)
sys.modules["sonarcloud_to_sarif"] = mod
SPEC.loader.exec_module(mod)


SAMPLE_SHA = "00968da03031748aa5fc9da16a1c4010de485359"
PROJECT_KEY = "serge-mesh_ede4e751298b"


class ParseCheckRunUrlTests(unittest.TestCase):
    def test_parses_branch_url(self) -> None:
        target = mod.parse_check_run_url(
            f"https://sonarcloud.io/dashboard?id={PROJECT_KEY}&branch=main",
            SAMPLE_SHA,
            expected_project_key=PROJECT_KEY,
        )
        self.assertEqual(
            target,
            mod.SyncTarget(
                project_key=PROJECT_KEY,
                kind="branch",
                value="main",
                ref="refs/heads/main",
                sha=SAMPLE_SHA,
            ),
        )

    def test_parses_pull_request_url(self) -> None:
        target = mod.parse_check_run_url(
            f"https://sonarcloud.io/dashboard?id={PROJECT_KEY}&pullRequest=27",
            SAMPLE_SHA,
            expected_project_key=PROJECT_KEY,
        )
        self.assertEqual(
            target,
            mod.SyncTarget(
                project_key=PROJECT_KEY,
                kind="pull_request",
                value="27",
                ref="refs/pull/27/head",
                sha=SAMPLE_SHA,
            ),
        )

    def test_rejects_unexpected_host_or_project(self) -> None:
        self.assertIsNone(
            mod.parse_check_run_url(
                f"http://sonarcloud.io/dashboard?id={PROJECT_KEY}&branch=main",
                SAMPLE_SHA,
                expected_project_key=PROJECT_KEY,
            )
        )
        self.assertIsNone(
            mod.parse_check_run_url(
                f"https://evil.example/dashboard?id={PROJECT_KEY}&branch=main",
                SAMPLE_SHA,
                expected_project_key=PROJECT_KEY,
            )
        )
        self.assertIsNone(
            mod.parse_check_run_url(
                "https://sonarcloud.io/dashboard?id=other_project&branch=main",
                SAMPLE_SHA,
                expected_project_key=PROJECT_KEY,
            )
        )


class VerifyTargetShaTests(unittest.TestCase):
    def test_retries_until_sha_matches(self) -> None:
        target = mod.SyncTarget(
            project_key=PROJECT_KEY,
            kind="branch",
            value="main",
            ref="refs/heads/main",
            sha=SAMPLE_SHA,
        )
        responses = [
            {"branches": [{"name": "main", "commit": {"sha": "1" * 40}}]},
            {"branches": [{"name": "main", "commit": {"sha": SAMPLE_SHA}}]},
        ]
        calls = {"count": 0}

        def fake_fetch(_path: str, _params: dict[str, str], token: str | None = None) -> dict:
            resp = responses[calls["count"]]
            calls["count"] += 1
            return resp

        matched, reason = mod.verify_target_sha(
            target,
            max_attempts=3,
            sleep_seconds=0,
            fetcher=fake_fetch,
            sleeper=lambda _: None,
        )
        self.assertTrue(matched)
        self.assertEqual(reason, "matched")
        self.assertEqual(calls["count"], 2)

    def test_skips_when_pr_missing(self) -> None:
        target = mod.SyncTarget(
            project_key=PROJECT_KEY,
            kind="pull_request",
            value="99",
            ref="refs/pull/99/head",
            sha=SAMPLE_SHA,
        )
        matched, _ = mod.verify_target_sha(
            target,
            max_attempts=2,
            sleep_seconds=0,
            fetcher=lambda _p, _q, token=None: {"pullRequests": []},
            sleeper=lambda _: None,
        )
        self.assertFalse(matched)


class FetchOpenIssuesTests(unittest.TestCase):
    def test_paginates_and_merges_rules(self) -> None:
        target = mod.SyncTarget(
            project_key=PROJECT_KEY,
            kind="branch",
            value="main",
            ref="refs/heads/main",
            sha=SAMPLE_SHA,
        )
        pages = {
            "1": {
                "total": 2,
                "issues": [{"key": "k1", "rule": "r1"}],
                "rules": [{"key": "r1", "name": "Rule 1"}],
            },
            "2": {
                "total": 2,
                "issues": [{"key": "k2", "rule": "r2"}],
                "rules": [{"key": "r2", "name": "Rule 2"}],
            },
        }

        def fake_fetch(_path: str, params: dict[str, str], token: str | None = None) -> dict:
            return pages[params["p"]]

        issues, rules = mod.fetch_open_issues(target, fetcher=fake_fetch)
        self.assertEqual([i["key"] for i in issues], ["k1", "k2"])
        self.assertEqual(set(rules.keys()), {"r1", "r2"})


class BuildSarifTests(unittest.TestCase):
    def test_maps_vulnerabilities_bugs_smells_flows_and_duplicate_hashes(self) -> None:
        target = mod.SyncTarget(
            project_key=PROJECT_KEY,
            kind="branch",
            value="main",
            ref="refs/heads/main",
            sha=SAMPLE_SHA,
        )
        issues = [
            {
                "key": "issue-2",
                "rule": "githubactions:S8482",
                "severity": "BLOCKER",
                "type": "VULNERABILITY",
                "component": f"{PROJECT_KEY}:.github/workflows/ci.yml",
                "line": 112,
                "hash": "samehash",
                "textRange": {"startLine": 112, "endLine": 112, "startOffset": 12, "endOffset": 50},
                "message": "Avoid executing downloaded artifacts.",
                "tags": ["cwe"],
                "organization": "serge-mesh",
                "impacts": [{"softwareQuality": "SECURITY", "severity": "HIGH"}],
            },
            {
                "key": "issue-1",
                "rule": "githubactions:S8482",
                "severity": "BLOCKER",
                "type": "VULNERABILITY",
                "component": f"{PROJECT_KEY}:.github/workflows/ci.yml",
                "line": 49,
                "hash": "samehash",
                "textRange": {"startLine": 49, "endLine": 49, "startOffset": 12, "endOffset": 50},
                "message": "Avoid executing downloaded artifacts.",
                "tags": ["cwe"],
                "organization": "serge-mesh",
                "impacts": [{"softwareQuality": "SECURITY", "severity": "HIGH"}],
            },
            {
                "key": "issue-bug",
                "rule": "rust:S7493",
                "severity": "MAJOR",
                "type": "BUG",
                "component": f"{PROJECT_KEY}:apps/picket-core/src/main.rs",
                "line": 234,
                "hash": "bughash",
                "textRange": {"startLine": 234, "endLine": 234, "startOffset": 36, "endOffset": 59},
                "flows": [
                    {
                        "locations": [
                            {
                                "component": f"{PROJECT_KEY}:apps/picket-core/src/main.rs",
                                "textRange": {
                                    "startLine": 127,
                                    "endLine": 127,
                                    "startOffset": 17,
                                    "endOffset": 22,
                                },
                                "msg": "this is an asynchronous context",
                            }
                        ]
                    }
                ],
                "message": "Use an async file API.",
                "tags": ["async"],
                "organization": "serge-mesh",
                "impacts": [{"softwareQuality": "RELIABILITY", "severity": "HIGH"}],
            },
            {
                "key": "issue-smell",
                "rule": "typescript:S7773",
                "severity": "MINOR",
                "type": "CODE_SMELL",
                "component": f"{PROJECT_KEY}:ui/src/app.tsx",
                "line": 10,
                "message": "Prefer Number.parseInt.",
                "tags": ["es2015", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9"],
                "organization": "serge-mesh",
                "impacts": [{"softwareQuality": "MAINTAINABILITY", "severity": "LOW"}],
            },
            {
                "key": "project-level-no-file",
                "rule": "common:S9999",
                "severity": "MINOR",
                "type": "CODE_SMELL",
                "component": PROJECT_KEY,
                "message": "Project-level issue without file path",
                "organization": "serge-mesh",
            },
        ]
        rules = {
            "githubactions:S8482": {
                "key": "githubactions:S8482",
                "name": "Avoid executing downloaded artifacts without verification",
                "lang": "githubactions",
                "langName": "GitHub Actions",
            },
            "rust:S7493": {
                "key": "rust:S7493",
                "name": "Blocking operations should not be used in async contexts",
                "lang": "rust",
                "langName": "Rust",
            },
            "typescript:S7773": {
                "key": "typescript:S7773",
                "name": "Use Number methods",
                "lang": "ts",
                "langName": "TypeScript",
            },
        }

        sarif = mod.build_sarif(target, issues, rules)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "SonarQube Cloud")

        sarif_rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(set(sarif_rules.keys()), {"githubactions:S8482", "rust:S7493", "typescript:S7773"})
        self.assertEqual(sarif_rules["githubactions:S8482"]["properties"]["security-severity"], "9.5")
        self.assertNotIn("security-severity", sarif_rules["rust:S7493"]["properties"])
        self.assertNotIn("security-severity", sarif_rules["typescript:S7773"]["properties"])
        self.assertLessEqual(len(sarif_rules["typescript:S7773"]["properties"]["tags"]), 10)

        results = run["results"]
        self.assertEqual(len(results), 4)

        # Sorted deterministically by line: line 49 comes before line 112 and gets unique, stable fingerprints.
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 49)
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startColumn"], 13)
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["endColumn"], 51)
        self.assertEqual(
            results[0]["partialFingerprints"]["primaryLocationLineHash"], "samehash:issue-1"
        )
        self.assertEqual(results[1]["locations"][0]["physicalLocation"]["region"]["startLine"], 112)
        self.assertEqual(
            results[1]["partialFingerprints"]["primaryLocationLineHash"], "samehash:issue-2"
        )
        self.assertEqual(results[0]["level"], "error")

        # Resolving/removing issue-1 must not change issue-2's fingerprint.
        after_resolve = mod.build_sarif(
            target, [i for i in issues if i["key"] != "issue-1"], rules
        )
        remaining_s8482 = [
            r for r in after_resolve["runs"][0]["results"] if r["ruleId"] == "githubactions:S8482"
        ]
        self.assertEqual(len(remaining_s8482), 1)
        self.assertEqual(
            remaining_s8482[0]["partialFingerprints"]["primaryLocationLineHash"],
            "samehash:issue-2",
        )

        bug_result = results[2]
        self.assertEqual(bug_result["level"], "warning")
        self.assertEqual(len(bug_result["relatedLocations"]), 1)
        self.assertEqual(
            bug_result["relatedLocations"][0]["physicalLocation"]["region"]["startLine"], 127
        )

        smell_result = results[3]
        self.assertEqual(smell_result["level"], "note")
        self.assertTrue(
            smell_result["partialFingerprints"]["primaryLocationLineHash"].endswith(":issue-smell")
        )

    def test_empty_issues_still_produces_valid_sarif(self) -> None:
        target = mod.SyncTarget(
            project_key=PROJECT_KEY,
            kind="pull_request",
            value="14",
            ref="refs/pull/14/head",
            sha=SAMPLE_SHA,
        )
        sarif = mod.build_sarif(target, [], {})
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])


if __name__ == "__main__":
    unittest.main()
