"""Current080-specific fail-closed policy checks.

These tests deliberately stop at the pure policy/caller seams.  They do not
construct a native RPM, claim caller capability, or replace the authenticated
source contracts with a test double.
"""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT
if str(SOURCE_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT / "src"))

from rs9 import current080_rpm_keyfree as keyfree  # noqa: E402
from rs9 import current080_rpm_keyfree_job as job  # noqa: E402
from rs9 import rpm_lint_policy  # noqa: E402
from rs9.current_generation import CURRENT_GENERATION  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.release_core import digest  # noqa: E402
from rs9.scratch import canonical  # noqa: E402


POLICY_PATH = ROOT / "operators/theme-forge-current-202610/rpm-lint-policy-nebular080.json"
PROJECT = "theme-forge-nebular-fusion"
SYSTEMS = ("x86_64-linux", "aarch64-linux")
MISSING = rpm_lint_policy.MISSING_EVIDENCE_PREDICATES


def _active_policy() -> dict:
    return rpm_lint_policy.load_policy(
        generation=CURRENT_GENERATION,
        policy_variant="current080",
    )


def _rule_rows(policy: dict, system: str):
    rules = policy["projects"][PROJECT]["exceptions"]
    for code, entries in rules.items():
        if code == "files-duplicated-waste":
            continue
        for path, rule in entries.items():
            yield code, path, rule, rule["systems"][system]


def _minimal_inventory(path: str, pin: dict) -> dict:
    mode = int(pin["mode"], 8)
    row = {
        "path": path,
        "type": "file",
        "mode": mode,
        "size": 1,
        "sha256": pin["sha256"],
        "owner": "root",
        "group": "root",
        "inode": 1,
        "device": 1,
        "flags": 0,
    }
    expected = {
        "path": path,
        "type": "file",
        "mode": mode,
        "size": 1,
        "sha256": pin["sha256"],
        "shebang": "#!" + pin["shebang"],
        "input_member": pin["input_member"],
        "input_archive_sha256": pin["asset_sha256"],
        "origin": "release",
    }
    return {"files": {path: row}, "expected": {path: expected}, "wrappers": {}}


def _record(code: str, path: str, pin: dict) -> dict:
    mode = pin["mode"]
    return {
        "code": code,
        "path": path,
        "mode": mode,
        "interpreter": pin["shebang"],
    }


class Current080RpmPolicySpecificTests(unittest.TestCase):
    def test_keyfree_path_refuses_selected_candidate_for_both_systems(self):
        active = _active_policy()
        for system in SYSTEMS:
            with self.subTest(system=system):
                request = job.request_for_system(system)
                with self.assertRaisesRegex(ContractError, "KEYFREE_POLICY"):
                    job._load_policy(SOURCE_ROOT, request)
                with self.assertRaisesRegex(ContractError, "KEYFREE_POLICY"):
                    keyfree._validate_builder_policy(active, request)

    def test_current080_caller_rules_and_declarations_fail_or_prove_at_script_seam(self):
        policy = _active_policy()
        for system in SYSTEMS:
            asset = next(
                row["sha256"]
                for row in policy["projects"][PROJECT]["authenticated_inputs"]["assets"]
                if system.removesuffix("-linux") + "-unknown-linux-gnu" in row["name"]
            )
            inputs = {
                "project_id": PROJECT,
                "version": "0.8.0",
                "system": system,
                "arch": system.removesuffix("-linux"),
                "asset_sha256": asset,
            }
            for code, path, rule, pin in _rule_rows(policy, system):
                with self.subTest(system=system, path=path):
                    inventory = _minimal_inventory(path, pin)
                    record = _record(code, path, pin)
                    proof, reason = rpm_lint_policy._script_proof(
                        record, rule, inventory, inputs
                    )
                    if rule["intent"] == "typescript-declaration-data":
                        self.assertIsNotNone(proof)
                        self.assertIsNone(reason)
                    else:
                        self.assertIsNone(proof)
                        self.assertIn(reason, MISSING)

                        forged = copy.deepcopy(inventory)
                        forged["caller_evidence"] = {
                            "schema": "rs9.nebular-caller-sources.v1",
                            "status": "available",
                            "tag_name": "v0.8.0",
                            "files": {},
                        }
                        proof, reason = rpm_lint_policy._script_proof(
                            record, rule, forged, inputs
                        )
                        self.assertIsNone(proof)
                        self.assertIn(reason, MISSING)

    def test_forged_authorized_policy_and_wrong_variant_refuse(self):
        active = _active_policy()
        mutated = copy.deepcopy(active)
        mutated["projects"][PROJECT]["inventory_bindings"]["x86_64-linux"][
            "source_inventory_sha256"
        ] = "0" * 64
        with self.assertRaises(ContractError):
            rpm_lint_policy._validate_policy(
                mutated,
                generation=CURRENT_GENERATION,
                policy_variant="current080",
            )
        result = rpm_lint_policy.evaluate_policy(
            {}, {}, {"project_id": PROJECT, "version": "0.8.0", "arch": "x86_64", "system": "x86_64-linux"},
            policy=mutated,
            generation=CURRENT_GENERATION,
            policy_variant="current080",
        )
        self.assertFalse(result["accepted"])
        self.assertEqual(result["blockers"], ["malformed-or-unavailable-policy-evidence"])
        with self.assertRaises(ContractError):
            rpm_lint_policy._validate_policy(
                active,
                generation=CURRENT_GENERATION,
                policy_variant="current071",
            )

    def test_empty_selected_inventory_is_not_accepted_or_diagnostic_only(self):
        result = rpm_lint_policy.evaluate_policy(
            {}, {}, {"project_id": PROJECT, "version": "0.8.0", "arch": "x86_64", "system": "x86_64-linux"},
            policy=_active_policy(),
            generation=CURRENT_GENERATION,
            policy_variant="current080",
        )
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "blocked")
        self.assertIn("missing-findings-summary", result["blockers"])
        self.assertNotIn("current-generation-diagnostic-only", result["blockers"])

    def test_fixed080_policy_context_selects_current080_for_both_architectures(self):
        """Structural selector proof only; this does not authenticate a release."""
        policy = _active_policy()
        policy_sha = digest(canonical(policy))
        self.assertEqual(policy_sha, "18beff59e710b79c5ea21eed9831010fd144cdab57e20db0e5a9e9efb7ceacb4")
        for system in SYSTEMS:
            rows = {}
            for product, entry in policy["projects"].items():
                auth = entry["authenticated_inputs"]
                if "asset_sha256" in auth:
                    asset_sha = auth["asset_sha256"]
                    closure_sha = auth.get("closure_sha256")
                else:
                    triple = system.removesuffix("-linux") + "-unknown-linux-gnu"
                    asset_sha = next(row["sha256"] for row in auth["assets"] if triple in row["name"])
                    closure_sha = auth.get("closure_sha256")
                arch = "noarch" if entry["allowed_architectures"] == ["noarch"] else system.removesuffix("-linux")
                rows[product] = {
                    "product": product,
                    "version": entry["version"],
                    "system": system,
                    "architecture": arch,
                    "policy_sha256": policy_sha,
                    "inputs": {
                        "project_id": product,
                        "version": entry["version"],
                        "system": system,
                        "arch": arch,
                        "asset_sha256": asset_sha,
                        "closure_sha256": closure_sha,
                        "payload_manifest_sha256": entry["inventory_bindings"][system]["payload_manifest_sha256"],
                    },
                }
            receipt = {"system": system, "details": {"rpm_lint_policy": rows}}
            self.assertEqual(
                rpm_lint_policy.policy_variant_for_evaluations(SOURCE_ROOT, receipt),
                "current080",
            )


if __name__ == "__main__":
    unittest.main()
