"""System-WebKit builder and publisher joins use one explicit runtime profile."""
from __future__ import annotations

import copy
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from rs9 import tf_pypi_nebular070_publish as publish
from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
from rs9.tf_pypi_nebular_successor import authenticate_gate1_capture, build_gate1_candidates
from rs9.wheel_nebular_successor import SYSTEM_WEBKIT_PROFILE
from tests.test_nebular070_gate1_roundtrip import _prepare_fixture
from tests import test_tf_pypi_nebular070_publish as legacy


class SystemWebKitPublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name)
        cls.repository, cls.evidence, _, cls.binding = _prepare_fixture(cls.base / "fixture")
        authenticated = authenticate_gate1_capture(
            cls.repository, cls.evidence, release_binding=cls.binding,
            approved_bootstrap_sha256=cls.binding["expected"]["bootstrap_sha256"],
        )
        cls.candidates = cls.base / "system"
        cls.receipt = build_gate1_candidates(
            authenticated, cls.candidates, rs9_source_commit=legacy.CANDIDATE_COMMIT,
            rs9_source_tree=legacy.CANDIDATE_TREE, candidate_profile=SYSTEM_WEBKIT_PROFILE,
        )
        wheels = sorted([
            {"target": publish.TARGET_BY_SYSTEM[row["system"]], **row["wheel"]}
            for row in cls.receipt["rows"]
        ], key=lambda row: row["target"])
        fixture = types.SimpleNamespace(
            candidate_receipt=cls.receipt,
            candidate_receipt_sha=sha256(canonical(cls.receipt)),
            expected_artifacts={"record_sha256": sha256(canonical(wheels))},
            profile_sha=cls.receipt["profile_result_sha256"],
            matrix_receipt_sha="a" * 64,
        )
        cls.pin, cls.approval = legacy.Nebular070PublisherSeamTests._build_pin_and_approval.__func__(fixture)
        cls.pin["description"] = SYSTEM_WEBKIT_PROFILE.description_path
        cls.pin["linux_runtime_profile"] = publish.SYSTEM_WEBKIT_RUNTIME_PROFILE
        cls.approval["linux_runtime_profile"] = publish.SYSTEM_WEBKIT_RUNTIME_PROFILE
        cls.approval["set_sha256"] = publish.compute_set_sha256(cls.approval)
        cls.approval["admission_sha256"] = publish.compute_admission_sha256(cls.approval)
        cls.pin["admission_sha256"] = cls.approval["admission_sha256"]

    def test_three_system_wheels_verify_with_explicit_approval(self):
        from rs9.tf_pypi_consumer import _nebular_candidate_row
        publish._cross_check_pin_and_approval(self.pin, self.approval)
        for record in self.approval["files"]:
            with self.subTest(target=record["target"]):
                _nebular_candidate_row(self.receipt, record["target"])
                path = self.candidates / record["system"] / record["filename"]
                actual = publish.inspect_candidate_wheel(
                    path, file_record=record, approval=self.approval,
                )
                self.assertEqual(actual["sha256"], record["sha256"])

    def test_runtime_selection_is_bound_by_set_digest_and_rejects_stage_a(self):
        publish.validate_pin(self.pin)
        publish.validate_approval(self.approval)
        without_marker = copy.deepcopy(self.approval)
        without_marker.pop("linux_runtime_profile")
        self.assertNotEqual(publish.compute_set_sha256(without_marker), self.approval["set_sha256"])
        for value in (None, [], {}, "manylinux"):
            bad = {**self.approval, "linux_runtime_profile": value}
            with self.subTest(value=value), self.assertRaises(AdmissionError):
                publish.validate_approval(bad)
        bad = {**self.approval, "manylinux_stage_a_sha256": "b" * 64}
        with self.assertRaises(AdmissionError):
            publish.validate_approval(bad)
        bad_pin = {**self.pin}
        bad_pin.pop("linux_runtime_profile")
        bad_pin["description"] = str(publish.DESCRIPTION_PATH)
        with self.assertRaises(AdmissionError):
            publish._cross_check_pin_and_approval(bad_pin, self.approval)

    def test_system_wheel_cannot_be_reclassified_as_portable(self):
        record = self.approval["files"][1]
        path = self.candidates / record["system"] / record["filename"]
        for approval, stage_a in (
            ({key: value for key, value in self.approval.items() if key != "linux_runtime_profile"}, None),
            (self.approval, "b" * 64),
        ):
            with self.subTest(stage_a=stage_a), self.assertRaises(AdmissionError):
                publish.inspect_candidate_wheel(
                    path, file_record=record, approval=approval,
                    manylinux_stage_a_digest=stage_a,
                )

    def test_external_artifacts_require_only_inputs_for_explicit_system(self):
        api = self.base / "system-api"
        api.mkdir()
        capture = {
            "repository": "Knowledge-Forge-AI/release-starport-9", "run_id": 55,
            "head_branch": "main", "qualification_source_commit": "1" * 40,
            "artifacts": {},
        }
        row = {
            "id": 56, "name": publish.PUBLIC_INPUTS_ARTIFACT, "size_in_bytes": 123,
            "expired": False,
            "archive_download_url":
                "https://api.github.com/repos/Knowledge-Forge-AI/release-starport-9/actions/artifacts/56/zip",
            "workflow_run": {"id": 55, "head_branch": "main", "head_sha": "1" * 40},
            "digest": "sha256:" + "2" * 64,
        }
        (api / "artifacts.json").write_bytes(canonical({"artifacts": [row]}))
        result = publish.validate_public_external_artifact_metadata(
            api, capture=capture, approval=self.approval,
        )
        self.assertEqual(set(result), {publish.PUBLIC_INPUTS_ARTIFACT})
        with self.assertRaises(AdmissionError):
            publish.validate_public_external_artifact_metadata(api, capture=capture)
        for names in (
            [publish.PUBLIC_INPUTS_ARTIFACT, publish.MANYLINUX_ADMISSION_ARTIFACT],
            [publish.PUBLIC_INPUTS_ARTIFACT, publish.PUBLIC_INPUTS_ARTIFACT],
        ):
            with self.subTest(names=names), self.assertRaises(AdmissionError):
                publish.validate_public_external_artifact_metadata(
                    api, capture=capture, approval=self.approval, names=names,
                )
        row["workflow_run"]["head_sha"] = "3" * 40
        (api / "artifacts.json").write_bytes(canonical({"artifacts": [row]}))
        with self.assertRaises(AdmissionError):
            publish.validate_public_external_artifact_metadata(
                api, capture=capture, approval=self.approval,
            )

    def test_resume_routes_portability_arguments_from_explicit_approval(self):
        workflow = publish.publication_resume_job_text()
        self.assertIn("runtime_profile=", workflow)
        self.assertIn("if: steps.resolve_qual.outputs.runtime_profile == 'manylinux'", workflow)
        self.assertIn('if not _system_runtime_profile(load_approval(Path("publisher-authority"))):', workflow)
        self.assertIn("approval=load_approval(pub)", workflow)
        for name, next_name in (
            ("Verify artifact integrity and select only missing files",
             "Re-verify staged upload artifacts against approval before upload"),
            ("Re-verify staged upload artifacts against approval before upload",
             "Publish package distribution to PyPI"),
        ):
            block = workflow.split("- name: " + name, 1)[1].split("- name: " + next_name, 1)[0]
            self.assertIn("PORTABILITY_ARGS=()", block)
            self.assertIn('"${PORTABILITY_ARGS[@]}"', block)
            self.assertEqual(block.count("--tf-producer-commit"), 1)
            self.assertEqual(block.count("--manylinux-admission"), 1)

    def test_system_matrix_requires_both_floor_receipts_before_reading_primary_results(self):
        from rs9.tf_pypi_hosted import NEBULAR070_EXPECTED_ARTIFACT_SCHEMA, admit_nebular070_matrix
        wheels = sorted([
            {"target": publish.TARGET_BY_SYSTEM[row["system"]], **row["wheel"]}
            for row in self.receipt["rows"]
        ], key=lambda row: row["target"])
        expected = {
            "schema": NEBULAR070_EXPECTED_ARTIFACT_SCHEMA,
            "candidate_rs9_source": self.receipt.get("candidate_rs9_source"),
            "wheels": wheels, "record_sha256": sha256(canonical(wheels)),
        }
        for floors in (None, {}, {"linux-x64-gnu": {}}):
            with self.subTest(floors=floors), self.assertRaisesRegex(
                AdmissionError, "NEBULAR_MATRIX_FLOOR_RECEIPTS",
            ):
                admit_nebular070_matrix(
                    self.receipt, expected, self.base,
                    candidate_receipt_sha256=sha256(canonical(self.receipt)),
                    expected_commit=legacy.CANDIDATE_COMMIT, expected_tree=legacy.CANDIDATE_TREE,
                    profile_sha256=self.receipt["profile_result_sha256"], run_id="55", run_attempt="1",
                    system_floor_receipts=floors,
                )

    def _build(self, output, **kwargs):
        descriptor = {
            "system_webkit": {
                "schema": publish.SYSTEM_WEBKIT_INPUT_SCHEMA,
                "origin_kind": "public-in-run",
                "profile_id": SYSTEM_WEBKIT_PROFILE.profile_id,
            },
            "release_binding": self.binding,
            "release_binding_sha256": sha256(canonical(self.binding)),
        }
        def git_output(root, args, code):
            if args == ["rev-parse", "--verify", "HEAD^{commit}"]:
                return legacy.CANDIDATE_COMMIT
            if args == ["rev-parse", "--verify", "HEAD^{tree}"]:
                return legacy.CANDIDATE_TREE
            if args == ["status", "--porcelain", "--untracked-files=all"]:
                return ""
            raise AssertionError(args)
        with patch.object(publish, "_git_output", git_output), patch.object(
            publish, "materialize_qualification_evidence", return_value=descriptor,
        ):
            return publish.build_candidates_bundle(
                output, expected_commit=legacy.CANDIDATE_COMMIT,
                repository=self.repository, evidence_dir=self.evidence,
                qualification_inputs=descriptor, require_clean=True, **kwargs,
            )

    def test_bundle_propagates_system_profile_through_receipt_validation(self):
        output = self.base / "bundle"
        self._build(output)
        import json
        receipt = json.loads((output / "candidate_receipt.json").read_bytes())
        self.assertEqual(receipt["profile"]["profile_id"], SYSTEM_WEBKIT_PROFILE.profile_id)
        self.assertEqual(receipt["readme"]["path"], SYSTEM_WEBKIT_PROFILE.description_path)
        self.assertFalse((output / "payload_portability.json").exists())
        self.assertEqual(
            [row["wheel"]["tag"] for row in receipt["rows"]],
            ["py3-none-macosx_13_0_arm64", "py3-none-linux_aarch64", "py3-none-linux_x86_64"],
        )

    def test_system_bundle_rejects_portability_arguments_before_output(self):
        options = (
            {"require_manylinux": True},
            {"payload_portability": self.base / "stage-a.json"},
            {"tf_producer_source": {"commit": "1" * 40, "tree": "2" * 40}},
        )
        for index, kwargs in enumerate(options):
            output = self.base / f"rejected-{index}"
            with self.subTest(kwargs=kwargs), self.assertRaises(AdmissionError):
                self._build(output, **kwargs)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
