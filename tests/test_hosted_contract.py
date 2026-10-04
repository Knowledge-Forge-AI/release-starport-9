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
        for key in ("matrix_wheels", "matrix_nix", "matrix_native", "matrix_candidate", "lanes"):
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
