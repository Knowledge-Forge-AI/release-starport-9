"""Preserve the graph with only the explicitly authorized RPM gate migration."""
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
        migrated = 0
        for row in original['lanes']:
            if row['lane'] == 'rpm' and 'rpm-rpmlint-clean' in row['required_gates']:
                row['required_gates'] = [
                    'rpm-lint-policy-accepted' if name == 'rpm-rpmlint-clean' else name
                    for name in row['required_gates']]
                migrated += 1
        self.assertIn(migrated, (0, 2))  # zero after this exact candidate is adopted
        added = {'rpm-client-preparation', 'rpm-derivation-record', 'rpm-manifest-record', 'rpm-policy-custody'}
        normalized = json.loads(json.dumps(current))
        for row in normalized['lanes']:
            if row['lane'] == 'rpm':
                self.assertTrue(added.issubset(row['required_gates']))
                row['required_gates'] = [g for g in row['required_gates'] if g not in added]
        self.assertEqual(sum('rpm-lint-policy-accepted' in row.get('required_gates',[]) for row in current['lanes']), 2)
        for row in original['lanes']:
            if row['lane'] == 'rpm':
                row['required_gates'] = [g for g in row['required_gates'] if g not in added]
        self.assertEqual(normalized["lanes"], original["lanes"])
        self.assertEqual(current["required_jobs"], original["required_jobs"])
        self.assertEqual(current["experiment_jobs"], ["nix-proot"])
        self.assertTrue(all(row["qualification_authority"] is False for row in current["experiments"]))
