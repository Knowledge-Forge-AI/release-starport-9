"""Diagnostic graph independence cannot alter the original qualification gates."""
import json
from pathlib import Path
import subprocess
import unittest

from tests.test_workflow_static import _parse_yaml

ROOT = Path(__file__).resolve().parents[1]


class ScopedGraphTests(unittest.TestCase):
    def test_q_jobs_are_transitively_independent_of_runtime(self):
        jobs = _parse_yaml((ROOT / ".github/workflows/rs9-candidate-tests.yml").read_text())["jobs"]
        def ancestors(name, seen=None):
            seen = set() if seen is None else seen
            for dependency in jobs[name].get("needs", []):
                if dependency not in seen:
                    seen.add(dependency); ancestors(dependency, seen)
            return seen
        for name in ("native", "pages", "observe"):
            self.assertTrue({"nix", "nix-proot"}.isdisjoint(ancestors(name)))
        self.assertIn("nix", ancestors("summary"))
        self.assertNotIn("nix-proot", ancestors("summary"))

    def test_original_lanes_jobs_and_gates_are_preserved_against_public_parent(self):
        parent = json.loads((ROOT / "operators/live1/candidate-manifest.json").read_bytes())["parent"]
        result = subprocess.run(["git", "-C", str(ROOT), "show", parent + ":operators/live1/hosted-lanes.json"],
                                capture_output=True)
        if result.returncode:
            self.skipTest("public parent object absent in shallow hosted checkout")
        original = json.loads(result.stdout)
        current = json.loads((ROOT / "operators/live1/hosted-lanes.json").read_bytes())
        self.assertEqual(current["lanes"], original["lanes"])
        self.assertEqual(current["required_jobs"], original["required_jobs"])
        self.assertEqual(current["experiment_jobs"], ["nix-proot"])
        self.assertTrue(all(row["qualification_authority"] is False for row in current["experiments"]))
