"""Separate witnessed construction from downstream durable boundaries."""
from pathlib import Path
import tempfile
import unittest

from rs9.hosted_packaging import rpm_stage_gates, verify_construction_witness
from rs9.release_core import digest


PRODUCTS = ["theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion"]


class RpmStageGateTests(unittest.TestCase):
    def test_each_post_construction_boundary_keeps_construction_gate(self):
        for index, (code, gate) in enumerate((("RPM_DERIVATION_RECORD", "rpm-derivation-record"),
                                            ("RPM_MANIFEST_RECORD", "rpm-manifest-record"),
                                            ("RPM_POLICY_CUSTODY", "rpm-policy-custody"))):
            stages = ["derivation", "manifest", "custody"]
            completed = {stage: set(PRODUCTS) if i < index else set(PRODUCTS[1:])
                         for i,stage in enumerate(stages)}
            with self.subTest(code=code):
                rows = {r["name"]: r for r in rpm_stage_gates(PRODUCTS, set(PRODUCTS), completed,
                                                            {PRODUCTS[0]: {"code": code}})}
                self.assertEqual(rows["rpm-package-build"]["status"], "pass")
                self.assertEqual(rows[gate]["status"], "fail")
                self.assertEqual(rows[gate]["product_codes"], {PRODUCTS[0]: code})

    def test_typed_exception_never_grants_construction(self):
        for code in ("RPM_DERIVATION_RECORD", "RPM_MANIFEST_RECORD", "RPM_POLICY_CUSTODY", "BUILD_FAILED"):
            rows = rpm_stage_gates(PRODUCTS, set(), {}, {PRODUCTS[0]: {"code": code}})
            self.assertEqual(rows[0]["status"], "fail")

    def test_existing_package_and_incomplete_or_changed_witness_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "test.rpm"; package.write_bytes(b"package")
            self.assertFalse(verify_construction_witness(None, package, PRODUCTS[0]))
            witness = {"schema": "rs9.rpm-construction-witness.v1", "package_sha256": digest(b"package"),
                       "package_size": 7, "spec_sha256": digest(b"spec"),
                       "rpmbuild_receipt": {"executed": True, "tool": "rpmbuild", "exit_code": 0,
                                            "command_sha256": digest(b"rpmbuild-command"),
                                            "stdout_sha256": digest(b"built"), "stderr_sha256": digest(b"")},
                       "rpm_identity": {"name": PRODUCTS[0], "version": "0.6.1", "release": "1.fc43", "arch": "x86_64"},
                       "rpm_payload_digest": {"payload_digest_algo": "sha256", "payload_digest": digest(b"payload")}}
            self.assertTrue(verify_construction_witness(witness, package, PRODUCTS[0]))
            witness["rpmbuild_receipt"]["executed"] = False
            self.assertFalse(verify_construction_witness(witness, package, PRODUCTS[0]))
            witness["rpmbuild_receipt"]["executed"] = True
            package.write_bytes(b"replacement")
            self.assertFalse(verify_construction_witness(witness, package, PRODUCTS[0]))
