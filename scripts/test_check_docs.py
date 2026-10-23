import copy
import json
import tempfile
import unittest
from pathlib import Path

from check_docs import check, local_targets, validate_registry


def registry():
    ref = "a" * 40
    return {
        "schemaVersion": "1.0", "reviewedAt": "2026-10-24",
        "status": "design_research", "integrationStatus": "not_implemented",
        "updatePolicy": "manual_review_only", "vendoredContent": False,
        "capabilityStage": "S0",
        "upstreams": [{
            "id": "demo", "repository": "example/demo", "reviewedCommit": ref,
            "url": "https://github.com/example/demo",
            "licenseDeclared": "MIT", "boundary": "reference only",
            "licenseEvidenceUrl": f"https://github.com/example/demo/blob/{ref}/LICENSE",
            "decision": "reference", "integrationStatus": "not_implemented",
            "requiredValidation": ["permission boundary"],
            "observedCommitDate": "2026-10-23T00:00:00Z",
        }],
    }


class DocumentationChecks(unittest.TestCase):
    def test_relative_assets_checked_and_external_examples_ignored(self):
        content = ('[doc](docs/PRD.md#scope) ![image](docs/banner.svg) '
                   '[external](https://example.com) <img src="docs/picture.svg">\n'
                   '```text\n[example](not-a-real-file.md)\n```\n')
        self.assertEqual(list(local_targets(content)), ["docs/PRD.md", "docs/banner.svg", "docs/picture.svg"])

    def test_valid_pinned_registry(self):
        self.assertEqual(validate_registry(registry()), [])

    def test_floating_license_and_duplicate_id_fail(self):
        data = registry()
        data["upstreams"][0]["licenseEvidenceUrl"] = "https://github.com/example/demo/blob/main/LICENSE"
        data["upstreams"].append(copy.deepcopy(data["upstreams"][0]))
        errors = validate_registry(data)
        self.assertTrue(any("license evidence" in error for error in errors))
        self.assertTrue(any("duplicate" in error for error in errors))

    def test_fake_integration_and_future_reference_fail(self):
        data = registry()
        data["upstreams"][0]["integrationStatus"] = "implemented"
        data["upstreams"][0]["observedCommitDate"] = "2027-01-01T00:00:00Z"
        errors = validate_registry(data)
        self.assertTrue(any("cannot claim" in error for error in errors))
        self.assertTrue(any("exceeds" in error for error in errors))

    def test_malformed_input_is_reported(self):
        self.assertTrue(validate_registry([]))
        data = registry()
        data["reviewedAt"] = "not-a-date"
        data["upstreams"] = [None]
        self.assertGreaterEqual(len(validate_registry(data)), 2)

    def test_missing_and_outside_paths_fail_without_fetching_urls(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "docs/research").mkdir(parents=True)
            (root / "docs/research/upstreams.json").write_text(json.dumps(registry()), encoding="utf-8")
            (root / "README.md").write_text(
                "[missing](missing.md) [outside](../outside.md) [remote](https://example.com)",
                encoding="utf-8",
            )
            errors, _, count = check(root)
            self.assertEqual(count, 1)
            self.assertTrue(any("local target missing.md" in error for error in errors))
            self.assertTrue(any("local target ../outside.md" in error for error in errors))
            self.assertFalse(any("example.com" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
