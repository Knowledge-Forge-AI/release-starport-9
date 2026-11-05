"""Current ARM workflow and architecture policy; pure source and parser checks."""
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION, distribution_paths
from rs9.hosted_contract import load_hosted_lanes, generate_matrix_outputs
from rs9.errors import ContractError
from rs9.planner import _packaging_policy

ROOT = Path(__file__).resolve().parents[1]


class ArchArmIntegrationContractTests(unittest.TestCase):
    def test_original_x64_constructor_precedes_arm_importer(self):
        text = (ROOT / distribution_paths(CURRENT_GENERATION)[0]).read_text()
        arm = text.split("  native-arm:\n", 1)[1].split("  pages:\n", 1)[0]
        self.assertIn("needs: [config, authenticate, pins, native]", arm)
        self.assertIn("runs-on: ubuntu-24.04-arm", arm)
        self.assertIn("timeout-minutes: 90", arm)
        self.assertIn("actions: read", arm)
        self.assertNotIn("environment:", arm)
        self.assertNotIn("secrets.", arm)
        self.assertNotIn("sudo ", arm)
        self.assertNotIn("apt-get", arm)
        self.assertIn("'pacman' --system 'aarch64-linux'", arm)
        self.assertIn("needs: [config, authenticate, pins, native, native-arm]", text)
        self.assertIn("needs: [config, unit, authenticate, pins, nix, native, native-arm, pages]", text)

    def test_arm_cannot_race_x64_in_parallel_native_matrix(self):
        current = load_hosted_lanes(ROOT, generation=CURRENT_GENERATION)
        parallel = json.loads(generate_matrix_outputs(current)["matrix_native"])["include"]
        pairs = {(r["lane"], r["system"]) for r in parallel}
        self.assertIn(("pacman", "x86_64-linux"), pairs)
        self.assertNotIn(("pacman", "aarch64-linux"), pairs)
        rows = [r for r in current["lanes"] if (r["lane"], r["system"]) == ("pacman", "aarch64-linux")]
        self.assertEqual(len(rows), 1)
        self.assertTrue({"pacman-canonical-any-reuse", "pacman-sdk-cleanup"} <= set(rows[0]["required_gates"]))

    def test_each_arm_source_contract_mutation_refused(self):
        path = distribution_paths(CURRENT_GENERATION)[1]
        original = json.loads((ROOT / path).read_bytes())
        for change in ("runner", "timeout_minutes", "system", "module", "custody_required", "required_gates", "duplicate"):
            with self.subTest(field=change), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for relative in (distribution_paths()[1], path):
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((ROOT / relative).read_bytes())
                doc = copy.deepcopy(original)
                row = next(r for r in doc["lanes"] if (r["lane"], r["system"]) == ("pacman", "aarch64-linux"))
                if change == "duplicate":
                    doc["lanes"].append(copy.deepcopy(row))
                elif change == "required_gates":
                    row[change].remove("pacman-canonical-any-reuse")
                else:
                    row[change] = {"runner":"ubuntu-24.04", "timeout_minutes":180,
                                   "system":"any", "module":"rs9.hosted_deb", "custody_required":False}[change]
                (root / path).write_text(json.dumps(doc))
                with self.assertRaises(ContractError) as error:
                    load_hosted_lanes(root, generation=CURRENT_GENERATION)
                self.assertEqual(error.exception.code, "LANES_POLICY")

    def test_current_planner_binds_exact_authenticated_generation(self):
        capture = object()
        intent = {"project":{"id":"theme-forge-nebular-fusion"}}
        with patch("rs9.current_generation.bind_native_build_generation") as bind:
            policy = _packaging_policy(capture, intent, "pacman", generation=CURRENT_GENERATION)
        bind.assert_called_once_with(capture, intent, generation=CURRENT_GENERATION)
        self.assertEqual(policy["qualified_architectures"], ["aarch64", "x86_64"])
        with patch("rs9.current_generation.bind_native_build_generation", side_effect=ContractError("NATIVE_GENERATION_BINDING","wrong source")):
            with self.assertRaises(ContractError):
                _packaging_policy(capture, intent, "pacman", generation=CURRENT_GENERATION)

    def test_historical_policy_does_not_gain_arm(self):
        for product in ("theme-forge-nebular-fusion", "theme-forge-stellar-burst"):
            with patch("rs9.current_generation.bind_native_build_generation") as bind:
                policy = _packaging_policy(object(), {"project":{"id":product}}, "pacman", generation=HISTORICAL_GENERATION)
            bind.assert_not_called()
            self.assertEqual(policy["qualified_architectures"], ["x86_64"])
        for invalid in (None, "current", "../current", {}):
            with self.assertRaises(ContractError):
                _packaging_policy(object(), {"project":{"id":"theme-forge-nebular-fusion"}}, "pacman", generation=invalid)
