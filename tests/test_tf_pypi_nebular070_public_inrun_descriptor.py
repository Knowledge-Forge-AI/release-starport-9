"""Focused phase-contract tests for the v1 public-in-run input descriptor."""
from __future__ import annotations

import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
from rs9.tf_pypi_nebular070_publish import (
    QUALIFICATION_INPUT_PHASE_PREP,
    QUALIFICATION_INPUT_PHASE_PUBLICATION,
    QUALIFICATION_INPUTS_SCHEMA,
    PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND,
    PUBLIC_INRUN_MANYLINUX_SCHEMA,
    validate_qualification_inputs_descriptor,
    materialize_manylinux_inputs,
    workflow_070_qualify_jobs_text,
)


class PublicInRunDescriptorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=".public-inrun-", dir=Path.cwd()))
        (self.root / "bootstrap/pre-rs9/theme-forge-nebular-0.7.0").mkdir(parents=True)
        (self.root / "operators/tf-pypi/nebular-0.7.0").mkdir(parents=True)
        (self.root / "operators/tf-pypi").mkdir(parents=True, exist_ok=True)
        (self.root / "evidence").mkdir()
        (self.root / "raw-release").mkdir()

        bootstrap = b"bootstrap\n"
        expectations = b"expectations\n"
        (self.root / "bootstrap/pre-rs9/theme-forge-nebular-0.7.0/manifest.json").write_bytes(bootstrap)
        (self.root / "operators/tf-pypi/nebular-0.7.0/expectations.json").write_bytes(expectations)
        binding = {
            "schema": "rs9.nebular-release-binding.v1alpha1",
            "release": "0.7.0",
            "application_version": "0.7.0",
            "distribution_version": "0.7.0",
            "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
            "tag": "v0.7.0",
            "bootstrap_path": "bootstrap/pre-rs9/theme-forge-nebular-0.7.0/manifest.json",
            "expectations_path": "operators/tf-pypi/nebular-0.7.0/expectations.json",
            "profile_path": "operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-gate1.json",
            "status": "ready",
            "lineage": {
                "mode": "direct-tag-provenance-equality",
                "requires_historical_author_rewrite": False,
            },
            "provenance": {
                "path": "PROVENANCE.json",
                "commit_field": "tagCommit",
                "tree_field": "tagTree",
            },
            "expected": {
                "repository_id": 1,
                "release_id": 2,
                "tag_commit": "a" * 40,
                "tag_tree": "b" * 40,
                "bootstrap_sha256": sha256(bootstrap),
                "expectations_sha256": sha256(expectations),
            },
        }

        evidence: dict[str, dict[str, object]] = {}
        required = (
            "api/release.json",
            "api/repository.json",
            "api/ref.json",
            "api/commit.json",
            "api/tree.json",
            "assets/SHA256SUMS",
            "assets/PROVENANCE.json",
            "npm/metadata.json",
            "npm/package.tgz",
            "source/LICENSE",
            "source/NOTICE",
        )
        for rel in required:
            data = (rel + "\n").encode()
            path = self.root / "evidence" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            evidence[rel] = {"path": rel, "size": len(data), "sha256": sha256(data)}

        stage_a_rel = "manylinux/stage-a.json"
        stage_b_rel = "manylinux/stage-b.json"
        stage_a = b"stage-a\n"
        stage_b = b"stage-b\n"
        for rel, data in ((stage_a_rel, stage_a), (stage_b_rel, stage_b)):
            path = self.root / "evidence" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            evidence[rel] = {"path": rel, "size": len(data), "sha256": sha256(data)}
        self.stage_b_entry = evidence.pop(stage_b_rel)

        def file_entry(path: str = "artifact.bin") -> dict[str, object]:
            return {"path": path, "size": 1, "sha256": "c" * 64}

        raw_targets: dict[str, object] = {}
        for target in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"):
            raw_targets[target] = {
                "schema": "rs9.tf-pypi-nebular070-raw-release-handoff.v1",
                "target": target,
                "record": file_entry("release.json"),
                "readme": file_entry("README.md"),
                "legal_files": {
                    "LICENSE": file_entry("LICENSE"),
                    "NOTICE": file_entry("NOTICE"),
                    "COMMERCIAL-LICENSE.md": file_entry("COMMERCIAL-LICENSE.md"),
                },
                "payload": file_entry("payload.tgz"),
                "manifest": file_entry("manifest.json"),
                "provenance": file_entry("PROVENANCE.json"),
                "native_consumer": {
                    target: {
                        "qualification": file_entry("qualification.json"),
                        "smoke": {
                            "raw-archive": {
                                "run": file_entry("raw-run.json"),
                                "receipt": file_entry("raw-receipt.json"),
                            },
                            "npm-package": {
                                "run": file_entry("npm-run.json"),
                                "receipt": file_entry("npm-receipt.json"),
                            },
                        },
                    }
                },
            }

        self.descriptor = {
            "schema": QUALIFICATION_INPUTS_SCHEMA,
            "project": "theme-forge-nebular-fusion",
            "version": "0.7.0",
            "distribution_version": "0.7.0",
            "workflow": "rs9-tfnf-pypi-publish.yml",
            "status": "ready",
            "upstream_origin": {
                "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
                "tag": "v0.7.0",
                "release_url": "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/tag/v0.7.0",
                "api_release_url": "https://api.github.com/repos/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/tags/v0.7.0",
            },
            "release_binding": binding,
            "release_binding_sha256": sha256(canonical(binding)),
            "evidence": {"source_root": "evidence", "files": evidence},
            "raw_release": {"source_root": "raw-release", "targets": raw_targets},
            "manylinux": {
                "schema": PUBLIC_INRUN_MANYLINUX_SCHEMA,
                "origin_kind": PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND,
                "tf_producer_source": {"commit": "d" * 40, "tree": "e" * 40},
                "stage_a": evidence[stage_a_rel].copy(),
            },
        }

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _validate(self, doc: dict, phase: str) -> dict:
        return validate_qualification_inputs_descriptor(
            doc, repository=self.root, phase=phase
        )

    def _legacy_with_stage_b(self) -> dict:
        legacy = copy.deepcopy(self.descriptor)
        legacy["evidence"]["files"]["manylinux/stage-b.json"] = self.stage_b_entry.copy()
        legacy["manylinux"]["stage_b"] = self.stage_b_entry.copy()
        legacy["manylinux"].pop("schema")
        legacy["manylinux"].pop("origin_kind")
        return legacy

    def test_preparation_roundtrip_is_stage_a_only_and_workflow_is_explicit(self) -> None:
        validated = self._validate(self.descriptor, QUALIFICATION_INPUT_PHASE_PREP)
        self.assertEqual(
            set(validated["manylinux"]),
            {"schema", "origin_kind", "stage_a", "tf_producer_source"},
        )
        materialized = materialize_manylinux_inputs(
            self.descriptor,
            self.root / "materialized-prep",
            repository=self.root,
            phase=QUALIFICATION_INPUT_PHASE_PREP,
        )
        self.assertIn("stage_a", materialized)
        self.assertNotIn("stage_b", materialized)
        workflow = workflow_070_qualify_jobs_text()
        self.assertIn("--phase qualification-prep", workflow)
        self.assertIn("--phase publication", workflow)

    def test_legacy_v1_with_precomputed_stage_b_is_phase_insensitive(self) -> None:
        legacy = self._legacy_with_stage_b()
        for phase, evidence_name in (
            (QUALIFICATION_INPUT_PHASE_PREP, "materialized-legacy-prep"),
            (QUALIFICATION_INPUT_PHASE_PUBLICATION, "materialized-legacy-publication"),
        ):
            with self.subTest(phase=phase):
                validated = self._validate(legacy, phase)
                self.assertEqual(
                    set(validated["manylinux"]),
                    {"stage_a", "stage_b", "tf_producer_source"},
                )
                materialized = materialize_manylinux_inputs(
                    legacy,
                    self.root / evidence_name,
                    repository=self.root,
                    phase=phase,
                )
                self.assertIn("stage_b", materialized)

    def test_unversioned_stage_a_only_cannot_opt_into_phase_route(self) -> None:
        legacy = copy.deepcopy(self.descriptor)
        legacy["manylinux"].pop("schema")
        legacy["manylinux"].pop("origin_kind")
        with self.assertRaises(AdmissionError) as ctx:
            self._validate(legacy, QUALIFICATION_INPUT_PHASE_PREP)
        self.assertEqual(ctx.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_MANYLINUX")

    def test_publication_roundtrip_requires_actual_stage_b(self) -> None:
        with self.assertRaises(AdmissionError) as ctx:
            self._validate(self.descriptor, QUALIFICATION_INPUT_PHASE_PUBLICATION)
        self.assertEqual(ctx.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_MANYLINUX")

        final_doc = copy.deepcopy(self.descriptor)
        final_doc["evidence"]["files"]["manylinux/stage-b.json"] = self.stage_b_entry.copy()
        final_doc["manylinux"]["stage_b"] = self.stage_b_entry.copy()
        validated = self._validate(final_doc, QUALIFICATION_INPUT_PHASE_PUBLICATION)
        self.assertEqual(
            set(validated["manylinux"]),
            {"schema", "origin_kind", "stage_a", "stage_b", "tf_producer_source"},
        )
        materialized = materialize_manylinux_inputs(
            final_doc,
            self.root / "materialized-final",
            repository=self.root,
            phase=QUALIFICATION_INPUT_PHASE_PUBLICATION,
        )
        self.assertIn("stage_b", materialized)

    def test_early_or_unbound_inputs_fail_closed(self) -> None:
        early = copy.deepcopy(self.descriptor)
        early["manylinux"]["stage_b"] = self.stage_b_entry.copy()
        with self.assertRaises(AdmissionError) as ctx_early:
            self._validate(early, QUALIFICATION_INPUT_PHASE_PREP)
        self.assertEqual(ctx_early.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_STAGE_B_EARLY")

        for label, mutate in (
            ("absent-stage-a", lambda doc: doc["manylinux"].pop("stage_a")),
            ("wrong-source", lambda doc: doc["manylinux"]["tf_producer_source"].update(commit="bad")),
            (
                "stale-stage-a",
                lambda doc: doc["evidence"]["files"]["manylinux/stage-a.json"].update(sha256="f" * 64),
            ),
        ):
            with self.subTest(label=label):
                bad = copy.deepcopy(self.descriptor)
                mutate(bad)
                with self.assertRaises(AdmissionError) as ctx_bad:
                    self._validate(bad, QUALIFICATION_INPUT_PHASE_PREP)
                self.assertIn(ctx_bad.exception.code, {
                    "TF_PYPI_QUALIFICATION_INPUTS_MANYLINUX",
                    "TF_PYPI_QUALIFICATION_INPUTS_EVIDENCE",
                })

        with self.assertRaises(AdmissionError) as ctx_phase:
            self._validate(self.descriptor, "resume")
        self.assertEqual(ctx_phase.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_PHASE")


if __name__ == "__main__":
    unittest.main()
