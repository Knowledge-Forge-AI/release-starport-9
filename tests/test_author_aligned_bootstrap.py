"""Current author-aligned LIVE1 selector and historical proof boundaries."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from rs9.operator import BOOTSTRAP


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL = ROOT / "bootstrap/pre-rs9/theme-forge-live1/manifest.json"
CURRENT = ROOT / BOOTSTRAP
EXPECTATIONS = ROOT / "operators/live1/expectations.json"
CANDIDATE = ROOT / "operators/live1/candidate-manifest.json"
LEGACY_NEBULAR_APPROVAL = ROOT / "operators/tf-pypi/theme-forge-nebular-fusion-artifacts.json"


class AuthorAlignedBootstrapTests(unittest.TestCase):
    def test_current_selector_uses_versioned_manifest_and_live_commits(self):
        self.assertEqual(BOOTSTRAP, "bootstrap/pre-rs9/theme-forge-live1/manifest-author-aligned.json")
        historical = json.loads(HISTORICAL.read_bytes())
        current = json.loads(CURRENT.read_bytes())
        expectations = json.loads(EXPECTATIONS.read_bytes())
        self.assertEqual(len(current["projects"]), 4)

        historical_by_repo = {row["repository"]: row for row in historical["projects"]}
        expectations_by_repo = {row["repository"]: row for row in expectations["projects"]}
        for row in current["projects"]:
            with self.subTest(repository=row["repository"]):
                old = historical_by_repo[row["repository"]]
                expected = expectations_by_repo[row["repository"]]
                normalized = copy.deepcopy(row)
                normalized["tag_commit"] = old["tag_commit"]
                self.assertEqual(normalized, old)
                self.assertEqual(row["tag_commit"], expected["commit"])
                self.assertNotEqual(row["tag_commit"], old["tag_commit"])
                self.assertEqual(row["tag_tree"], old["tag_tree"])
                self.assertEqual(row["release_id"], old["release_id"])

    def test_historical_manifest_and_candidate_proof_remain_bound(self):
        historical_digest = hashlib.sha256(HISTORICAL.read_bytes()).hexdigest()
        candidate = json.loads(CANDIDATE.read_bytes())
        self.assertEqual(candidate["bootstrap_manifest_sha256"], historical_digest)
        self.assertNotEqual(hashlib.sha256(CURRENT.read_bytes()).hexdigest(), historical_digest)
        self.assertEqual(CURRENT.name, "manifest-author-aligned.json")

    def test_legacy_nebular_approval_remains_explicitly_historical(self):
        historical = json.loads(HISTORICAL.read_bytes())
        current = json.loads(CURRENT.read_bytes())
        approval = json.loads(LEGACY_NEBULAR_APPROVAL.read_bytes())
        historical_row = next(
            row for row in historical["projects"]
            if row["repository"] == "Knowledge-Forge-AI/theme-forge-nebular-fusion"
        )
        current_row = next(
            row for row in current["projects"]
            if row["repository"] == "Knowledge-Forge-AI/theme-forge-nebular-fusion"
        )
        self.assertEqual(
            approval["authentication"]["bootstrap_sha256"],
            hashlib.sha256(HISTORICAL.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            approval["authentication"]["nebular"]["tag_commit"],
            historical_row["tag_commit"],
        )
        self.assertNotEqual(
            approval["authentication"]["nebular"]["tag_commit"],
            current_row["tag_commit"],
        )


if __name__ == "__main__":
    unittest.main()
