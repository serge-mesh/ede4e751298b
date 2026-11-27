import unittest

from ci_changes import COMPONENTS, classify


class ChangeSelection(unittest.TestCase):
    def test_docs_need_no_language_or_component_runner(self):
        for paths in (["README.md"], ["docs/security.md"], ["ui/README.md", "extension/README.md"]):
            self.assertFalse(any(classify(paths).values()))

    def test_ui_does_not_request_rust_or_browsers(self):
        selection = classify(["ui/src/app.tsx", "ui/package-lock.json"])
        self.assertEqual({k for k, v in selection.items() if v}, {"ui", "codeql_js"})

    def test_extension_needs_browser_and_javascript_checks(self):
        selection = classify(["extension/test/browser/blocks.spec.ts"])
        self.assertEqual({k for k, v in selection.items() if v}, {"extension", "codeql_js"})

    def test_rust_sources_and_all_workspace_lockfiles(self):
        for path in ("apps/picket-core/src/lib.rs", "build-support/release_keys.rs", "fuzz/helper/Cargo.lock", ".cargo/config.toml"):
            with self.subTest(path=path):
                self.assertEqual({k for k, v in classify([path]).items() if v}, {"rust", "edge", "deny", "codeql_rust"})

    def test_embedded_data_and_crate_fixtures_select_rust(self):
        for path in ("apps/picket-core/data/feed-presets.json", "apps/picket-core/data/public_suffix_list.dat",
                     "crates/picket-wire/tests/fixtures/response.bin", "build-support/templates/config.json"):
            with self.subTest(path=path):
                self.assertTrue(classify([path])["rust"])
                self.assertTrue(classify([path])["codeql_rust"])

    def test_scan_configuration_and_selector_fail_closed(self):
        self.assertTrue(all(classify(["scripts/ci_changes.py"]).values()))
        selection = classify([".github/workflows/codeql.yml"])
        self.assertTrue(all(selection[k] for k in ("codeql_rust", "codeql_js", "codeql_actions")))

    def test_deleted_and_added_paths_are_combined(self):
        selection = classify(["crates/old/src/lib.rs", "docs/renamed.md"])
        self.assertTrue(selection["codeql_rust"])
        self.assertEqual(set(selection), set(COMPONENTS))

    def test_node_and_workflow_changes_select_their_checks(self):
        self.assertTrue(classify([".node-version"])["extension"])
        self.assertTrue(classify([".github/workflows/ci.yml"])["rust"])
        self.assertTrue(classify([".github/workflows/ci.yml"])["codeql_actions"])


if __name__ == "__main__":
    unittest.main()
