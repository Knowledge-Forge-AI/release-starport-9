"""Current public-native provenance direct-lineage contract tests."""
from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import rs9.nebular_lineage as lineage
from rs9.errors import ContractError
from rs9.operator import release_bindings, validate_release_binding
from rs9.release_core import ReleaseCapture, digest
from rs9.scratch import canonical


PUBLIC_PROVENANCE = Path(
    "/Users/Shared/agent-scratch/r/triad-20261029-003307-recovery2/"
    "state/rs9-public-pypi-inputs2/candidate/evidence/public-release/assets/PROVENANCE.json"
)
FIXTURE = Path(__file__).parent / "fixtures" / "public-native-provenance-v1.json"
PUBLIC_PROVENANCE_SHA256 = "535951387716f3100eaab33c8ee28b3d0794cd3a755c2b23f0071c3f5f88e92d"
CURRENT_PROVENANCE = {
    "path": "PROVENANCE.json",
    "commit_field": "releaseCommit",
    "tree_field": "testedTree",
}
INTAKE_PROVENANCE = {
    "path": "PYPI-INTAKE-PROVENANCE.json",
    "commit_field": "releaseCommit",
    "tree_field": "testedTree",
}


def _fixture_data() -> dict:
    return json.loads(FIXTURE.read_bytes())


def _provenance_bytes() -> bytes:
    if PUBLIC_PROVENANCE.is_file():
        raw = PUBLIC_PROVENANCE.read_bytes()
        if digest(raw) != PUBLIC_PROVENANCE_SHA256:
            raise AssertionError("held public provenance bytes changed")
        return raw
    return canonical(_fixture_data()["provenance"])


class Nebular070NativeDirectLineageTests(unittest.TestCase):
    def _capture_and_binding(
        self,
        *,
        document=None,
        record=None,
        provenance=None,
        provenance_path="PROVENANCE.json",
        selector=None,
    ):
        fixture = _fixture_data()
        record = copy.deepcopy(record or fixture["capture"]["record"])
        raw = provenance if provenance is not None else _provenance_bytes()
        if document is not None:
            raw = canonical(document)
        root = Path(tempfile.mkdtemp(prefix="nebular070-direct-lineage-"))
        self.addCleanup(shutil.rmtree, root, True)
        capture = ReleaseCapture(
            record,
            {}, {}, {}, {}, {provenance_path: raw}, root,
        )
        binding = release_bindings("0.7.0")
        binding.update({
            "status": "ready",
            "expected": {
                "repository_id": 1358643872,
                "release_id": 426333162,
                "tag_commit": "cadb40c4972f68f314096ff60fbcfb4da950c161",
                "tag_tree": "27c643b6375c2aafde314799c4f08e844c14992c",
                "bootstrap_sha256": "c" * 64,
                "expectations_sha256": "d" * 64,
            },
            "provenance": copy.deepcopy(selector or {
                **CURRENT_PROVENANCE,
                "path": provenance_path,
            }),
        })
        return capture, binding

    def _verify(self, capture, binding):
        metadata = {
            "id": 426333162,
            "tag_name": "v0.7.0",
            "draft": False,
            "prerelease": False,
        }
        tree = {"sha": binding["expected"]["tag_tree"], "truncated": False}
        with patch.object(lineage, "authenticated_record_hash", return_value="e" * 64), \
                patch.object(lineage, "authenticated_release_metadata", return_value=metadata), \
                patch.object(lineage, "authenticated_tree", return_value=tree):
            return lineage.verify_direct_release_lineage(capture, binding)

    def test_actual_flat_public_provenance_roundtrips_through_release_capture(self):
        capture, binding = self._capture_and_binding()
        validate_release_binding(binding)
        facts = self._verify(capture, binding)
        document = json.loads(capture.evidence_bytes["PROVENANCE.json"])
        self.assertEqual(facts["mode"], "direct-tag-provenance-equality")
        self.assertEqual(facts["provenance_source_kind"], "asset")
        self.assertEqual(facts["provenance_schema"], document["schema"])
        self.assertEqual(facts["tested_commit"], document["testedCommit"])
        self.assertEqual(facts["native_ci_run"], 40792039041)
        self.assertEqual(facts["native_ci_attempt"], 1)
        self.assertEqual(facts["source_ci_run"], 40792040378)
        self.assertEqual(facts["provenance_commit_field"], "releaseCommit")
        self.assertEqual(facts["provenance_tree_field"], "testedTree")

    def test_operator_accepts_only_the_known_flat_selector(self):
        _capture, binding = self._capture_and_binding()
        self.assertEqual(validate_release_binding(binding)["provenance"], CURRENT_PROVENANCE)
        intake_capture, intake_binding = self._capture_and_binding(
            provenance_path=INTAKE_PROVENANCE["path"],
            selector=INTAKE_PROVENANCE,
        )
        self.assertEqual(validate_release_binding(intake_binding)["provenance"], INTAKE_PROVENANCE)
        self.assertEqual(self._verify(intake_capture, intake_binding)["provenance_path"], INTAKE_PROVENANCE["path"])
        with self.assertRaises(ContractError):
            validate_release_binding({
                **binding,
                "provenance": {
                    **CURRENT_PROVENANCE,
                    "tree_field": "tagTree",
                },
            })

    def test_intake_selector_is_fixed_and_legacy_default_is_unchanged(self):
        self.assertEqual(
            release_bindings("0.7.0")["provenance"],
            {"path": "PROVENANCE.json", "commit_field": "tagCommit", "tree_field": "tagTree"},
        )
        _capture, binding = self._capture_and_binding(
            provenance_path=INTAKE_PROVENANCE["path"],
            selector=INTAKE_PROVENANCE,
        )
        invalid_selectors = (
            {**INTAKE_PROVENANCE, "path": "arbitrary.json"},
            {**INTAKE_PROVENANCE, "tree_field": "tagTree"},
            {**INTAKE_PROVENANCE, "extra": "not-allowed"},
            {"path": INTAKE_PROVENANCE["path"], "commit_field": "tagCommit", "tree_field": "tagTree"},
        )
        for selector in invalid_selectors:
            with self.subTest(selector=selector):
                with self.assertRaises(ContractError):
                    validate_release_binding({**binding, "provenance": selector})

    def test_current_document_cannot_be_selected_through_legacy_schema(self):
        capture, binding = self._capture_and_binding(
            selector={"path": "PROVENANCE.json", "commit_field": "tagCommit", "tree_field": "tagTree"},
        )
        validate_release_binding(binding)
        with self.assertRaises(ContractError):
            self._verify(capture, binding)

    def test_flat_provenance_identity_and_schema_mismatches_refuse(self):
        fixture = _fixture_data()
        original = fixture["provenance"]
        cases = (
            ("release-id", lambda d: d.update(release=426333163)),
            ("repository", lambda d: d.update(repository="other/repository")),
            ("version", lambda d: d.update(version="0.7.1")),
            ("commit", lambda d: d.update(releaseCommit="0" * 40)),
            ("tree", lambda d: d.update(testedTree="1" * 40)),
            ("schema", lambda d: d.update(schema="unknown.schema.v1")),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                document = copy.deepcopy(original)
                mutate(document)
                capture, binding = self._capture_and_binding(document=document)
                with self.assertRaises(ContractError):
                    self._verify(capture, binding)

    def test_authenticated_capture_binding_identity_mismatches_refuse(self):
        for field, value in (("release_id", 426333163), ("repository", "other/repository"),
                             ("tag_commit", "0" * 40), ("tag_tree", "1" * 40)):
            with self.subTest(field=field):
                capture, binding = self._capture_and_binding()
                if field == "repository":
                    binding[field] = value
                else:
                    binding["expected"][field] = value
                with self.assertRaises(ContractError):
                    self._verify(capture, binding)

    def test_flat_provenance_rejects_noninteger_or_nonpositive_ci_identity(self):
        fixture = _fixture_data()
        for field, value in (("nativeCiRun", True), ("nativeCiAttempt", 0), ("sourceCiRun", "40792040378")):
            with self.subTest(field=field):
                document = copy.deepcopy(fixture["provenance"])
                document[field] = value
                capture, binding = self._capture_and_binding(document=document)
                with self.assertRaises(ContractError):
                    self._verify(capture, binding)

    def test_flat_selector_cannot_mix_legacy_identity_fields(self):
        capture, binding = self._capture_and_binding()
        binding["provenance"] = {
            "path": "PROVENANCE.json",
            "commit_field": "releaseCommit",
            "tree_field": "tagTree",
        }
        with self.assertRaises(ContractError):
            self._verify(capture, binding)


if __name__ == "__main__":
    unittest.main()
