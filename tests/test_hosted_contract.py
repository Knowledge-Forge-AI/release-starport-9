"""Unit and contract tests for RS9 hosted lane contract and authentication projections."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.hosted_contract import (
    POLICY_BLOCKERS,
    REQUIRED_GATES,
    REQUIRED_LANES,
    REQUIRED_RECEIPT_FILES,
    REQUIRED_RECEIPTS,
    SCHEMA_HOSTED_LANES,
    canonical_release_auth_projection,
    compute_auth_sha256,
    generate_matrix_outputs,
    load_hosted_lanes,
    validate_execution_context,
    validate_execution_result,
)
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]


class HostedContractTests(unittest.TestCase):
    def test_required_receipts_inventory_is_exact_sixteen(self):
        self.assertEqual(len(REQUIRED_RECEIPTS), 16)
        lanes = [lane for lane, _ in REQUIRED_RECEIPTS]
        self.assertEqual(lanes.count("authenticate"), 1)
        self.assertEqual(lanes.count("pins"), 1)
        self.assertEqual(lanes.count("wheels"), 3)
        self.assertEqual(lanes.count("nix"), 3)
        self.assertEqual(lanes.count("pacman"), 1)
        self.assertEqual(lanes.count("rpm"), 2)
        self.assertEqual(lanes.count("deb"), 2)
        self.assertEqual(lanes.count("pages"), 1)
        self.assertEqual(lanes.count("observe"), 1)
        self.assertEqual(lanes.count("foundation3"), 1)

        self.assertEqual(len(REQUIRED_RECEIPT_FILES), 16)
        for lane, system in REQUIRED_RECEIPTS:
            self.assertIn(f"{lane}-{system}.json", REQUIRED_RECEIPT_FILES)

    def test_load_hosted_lanes_validates_schema(self):
        lanes_doc = load_hosted_lanes(ROOT)
        self.assertEqual(lanes_doc.get("schema"), SCHEMA_HOSTED_LANES)
        self.assertFalse(lanes_doc.get("production_enabled"))
        lanes = lanes_doc.get("lanes", [])
        self.assertTrue(len(lanes) >= 16)

        # Check required lanes are present
        lane_names = {l["lane"] for l in lanes}
        for req in REQUIRED_LANES:
            self.assertIn(req, lane_names)

    def test_generate_matrix_outputs_partitions(self):
        lanes_doc = load_hosted_lanes(ROOT)
        matrices = generate_matrix_outputs(lanes_doc)
        for key in ("matrix_wheels", "matrix_nix", "matrix_native", "matrix_candidate", "matrix_experiments", "lanes"):
            self.assertIn(key, matrices)
            parsed = json.loads(matrices[key])
            self.assertIsInstance(parsed, (dict, list))

        wheels = json.loads(matrices["matrix_wheels"])["include"]
        self.assertEqual(len(wheels), 3)
        self.assertEqual({w["system"] for w in wheels}, {"aarch64-darwin", "x86_64-linux", "aarch64-linux"})

        nix = json.loads(matrices["matrix_nix"])["include"]
        self.assertEqual(len(nix), 3)

        native = json.loads(matrices["matrix_native"])["include"]
        self.assertEqual(len(native), 5)
        native_lanes = {n["lane"] for n in native}
        self.assertEqual(native_lanes, {"pacman", "rpm", "deb"})

        experiments = json.loads(matrices["matrix_experiments"])["include"]
        self.assertEqual(len(experiments), 2)
        self.assertEqual({e["system"] for e in experiments}, {"x86_64-linux", "aarch64-linux"})
        for e in experiments:
            self.assertEqual(e["lane"], "nix-proot")
            self.assertTrue(e["artifact_name"].startswith("experiment-nix-proot-"))

    def test_experiment_rows_are_source_declared_diagnostic_only(self):
        doc = json.loads((ROOT / "operators/live1/hosted-lanes.json").read_bytes())
        rows = doc["experiments"]
        self.assertEqual({r["system"] for r in rows}, {"x86_64-linux", "aarch64-linux"})
        self.assertEqual(doc["experiment_jobs"], ["nix-proot"])
        for row in rows:
            self.assertIs(row["qualification_authority"], False)
            self.assertEqual(row["experiment_gates"], row["required_gates"])
            self.assertEqual(len(set(row["required_gates"])), 9)
            self.assertIn("proot-in-guest-offline", row["required_gates"])
        # Experiments never join the required graph or the production lane set.
        self.assertTrue(set(doc["experiment_jobs"]).isdisjoint(doc["required_jobs"]))
        self.assertTrue({r["lane"] for r in rows}.isdisjoint({r["lane"] for r in doc["lanes"]}))

    def test_validate_hosted_experiment_diagnostic_contract(self):
        from rs9.hosted_contract import validate_hosted_experiment_diagnostic, SCHEMA_HOSTED_EXPERIMENT_DIAGNOSTIC
        valid_receipt = {
            "schema": SCHEMA_HOSTED_EXPERIMENT_DIAGNOSTIC,
            "lane": "nix-proot",
            "system": "x86_64-linux",
            "production_enabled": False,
            "publication_authority": False,
            "qualification_authority": False,
            "application_qualified": False,
            "mandatory_gates_satisfied": False,
            "network": {
                "runtime_offline_status": "pass",
            },
            "gates": [
                {"name": "proot-in-guest-offline", "status": "pass", "runtime_offline_status": "pass"},
                {"name": "proot-pinned-derivation", "status": "pass"},
            ],
        }
        self.assertEqual(validate_hosted_experiment_diagnostic(valid_receipt), valid_receipt)

        # A pass gate without the explicit in-guest denial field is not offline proof
        implicit = dict(valid_receipt, gates=[{"name": "proot-in-guest-offline", "status": "pass"}])
        with self.assertRaises(ContractError):
            validate_hosted_experiment_diagnostic(implicit)

        # A failed or not-run gate cannot back a pass either, whatever field it carries
        for status in ("fail", "not-run"):
            contradictory = dict(valid_receipt, gates=[
                {"name": "proot-in-guest-offline", "status": status, "runtime_offline_status": "pass"}])
            with self.assertRaises(ContractError):
                validate_hosted_experiment_diagnostic(contradictory)

        # Rejects qualification_authority = True
        bad_auth = dict(valid_receipt, qualification_authority=True)
        with self.assertRaises(ContractError):
            validate_hosted_experiment_diagnostic(bad_auth)

        # Rejects production_enabled = True
        bad_prod = dict(valid_receipt, production_enabled=True)
        with self.assertRaises(ContractError):
            validate_hosted_experiment_diagnostic(bad_prod)

        # Rejects pass-by-absence-of-error for runtime_offline_status
        fake_offline = {
            **valid_receipt,
            "network": {"runtime_offline_status": "pass"},
            "gates": [{"name": "proot-pinned-derivation", "status": "pass"}],  # missing proot-in-guest-offline pass
        }
        with self.assertRaises(ContractError):
            validate_hosted_experiment_diagnostic(fake_offline)

    def test_canonical_release_auth_projection_strips_ephemeral_fields(self):
        auth_run_1 = {
            "schema": "rs9.candidate-authentication.v1alpha1",
            "checkout_binding": "hosted:abc123",
            "trust_root": "hosted-candidate-unattested",
            "observed_at": "2026-10-03T12:00:00+00:00",
            "production_enabled": False,
            "receipts": [
                {
                    "url": "https://api.github.com/repos/org/repo/releases",
                    "final_url": "https://cdn.github.com/redirect1?token=temp1",
                    "status": 200,
                    "size": 1024,
                    "sha256": "1" * 64,
                    "collected_at": "2026-10-03T12:00:01+00:00",
                }
            ],
            "projects": [
                {
                    "project": "theme-forge-stellar-loom",
                    "release_record_sha256": "2" * 64,
                    "profile_result_sha256": "3" * 64,
                }
            ],
        }

        auth_run_2 = {
            "schema": "rs9.candidate-authentication.v1alpha1",
            "checkout_binding": "hosted:abc123",
            "trust_root": "hosted-candidate-unattested",
            "observed_at": "2026-10-03T18:45:22+00:00",  # Different timestamp
            "production_enabled": False,
            "receipts": [
                {
                    "url": "https://api.github.com/repos/org/repo/releases",
                    "final_url": "https://cdn.github.com/redirect2?token=temp2",  # Different redirect
                    "status": 200,
                    "size": 1024,
                    "sha256": "1" * 64,
                    "collected_at": "2026-10-03T18:45:23+00:00",  # Different timestamp
                }
            ],
            "projects": [
                {
                    "project": "theme-forge-stellar-loom",
                    "release_record_sha256": "2" * 64,
                    "profile_result_sha256": "3" * 64,
                }
            ],
        }

        proj_1 = canonical_release_auth_projection(auth_run_1)
        proj_2 = canonical_release_auth_projection(auth_run_2)

        # Both projections are identical
        self.assertEqual(proj_1, proj_2)
        self.assertNotIn("observed_at", proj_1)
        self.assertNotIn("collected_at", proj_1["receipts"][0])
        self.assertNotIn("final_url", proj_1["receipts"][0])

        sha_1 = compute_auth_sha256(proj_1)
        sha_2 = compute_auth_sha256(proj_2)
        self.assertEqual(sha_1, sha_2)

    def test_shared_execution_interface_validation(self):
        valid_context = {
            "repository": ROOT,
            "scratch": Path("/tmp"),
            "captures": [],
            "client": None,
            "binding": {"source_commit": "1" * 40},
            "system": "x86_64-linux",
            "inputs": None,
            "pins": {},
            "authentication_sha256": "a" * 64,
            "phase": "candidate",
        }
        validate_execution_context(valid_context)

        # Invalid context rejects non-Path
        with self.assertRaises(ContractError):
            validate_execution_context({"repository": "/tmp", "scratch": Path("/tmp"), "system": "x86"})

        valid_result = {
            "gates": [{"name": "test-gate", "status": "pass"}],
            "artifacts": [Path("/tmp/art1.json")],
            "details": {"info": "ok"},
        }
        self.assertEqual(validate_execution_result(valid_result), valid_result)

        # Invalid result rejects bad gates
        with self.assertRaises(ContractError):
            validate_execution_result({"gates": [{"name": "bad", "status": "unknown"}], "artifacts": [], "details": {}})

    def test_policy_blockers_separated(self):
        self.assertIn("no-production-authority-in-hosted-candidate", POLICY_BLOCKERS)
        self.assertIn("publication-disabled-by-tenant-policy", POLICY_BLOCKERS)
        self.assertIn("manager-attended-disposition-required", POLICY_BLOCKERS)


if __name__ == "__main__":
    unittest.main()
