"""Focused tests for the explicit public-in-run evidence-root transport."""
from __future__ import annotations

import copy
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_tf_pypi_nebular070_public_inrun_descriptor import (
    PublicInRunDescriptorTests,
)
import rs9.tf_pypi_nebular070_publish as publish
from rs9.tf_pypi_archive import AdmissionError, canonical
from rs9.tf_pypi_nebular070_publish import (
    CANDIDATE_BUNDLE_ARTIFACT,
    QUALIFICATION_INPUT_PHASE_PREP,
    MANYLINUX_ADMISSION_ARTIFACT,
    MANYLINUX_STAGE_A_MEMBER,
    build_candidates_bundle,
    materialize_manylinux_inputs,
    parser,
    _validate_optional_inrun_transport,
)


class PublicInRunRootTests(PublicInRunDescriptorTests):
    """Exercise the transport seam against the existing descriptor fixture."""

    def _external_inputs(self) -> Path:
        external = Path(
            tempfile.mkdtemp(prefix=".public-inrun-root-", dir=self.root.parent)
        )
        shutil.copytree(self.root / "evidence", external / "evidence")
        shutil.copytree(self.root / "raw-release", external / "raw-release")
        return external

    def test_external_public_inrun_root_materializes_exact_bytes(self) -> None:
        external = self._external_inputs()
        try:
            destination = self.root / "materialized-external"
            result = materialize_manylinux_inputs(
                self.descriptor,
                destination,
                repository=self.root,
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=external,
            )
            stage_a = destination / "manylinux/stage-a.json"
            self.assertEqual(Path(result["stage_a"]), stage_a.resolve())
            self.assertEqual(
                stage_a.read_bytes(),
                (external / "evidence/manylinux/stage-a.json").read_bytes(),
            )
            self.assertEqual(
                (self.root / "bootstrap/pre-rs9/theme-forge-nebular-0.7.0/manifest.json").read_bytes(),
                b"bootstrap\n",
            )

            final_doc = copy.deepcopy(self.descriptor)
            final_doc["evidence"]["files"]["manylinux/stage-b.json"] = self.stage_b_entry.copy()
            final_doc["manylinux"]["stage_b"] = self.stage_b_entry.copy()
            final_destination = self.root / "materialized-external-final"
            final_result = materialize_manylinux_inputs(
                final_doc,
                final_destination,
                repository=self.root,
                phase="publication",
                inrun_root=external,
            )
            self.assertEqual(
                Path(final_result["stage_b"]),
                (final_destination / "manylinux/stage-b.json").resolve(),
            )
        finally:
            shutil.rmtree(external, ignore_errors=True)

    def test_legacy_descriptor_cannot_select_external_root(self) -> None:
        external = self._external_inputs()
        try:
            with self.assertRaises(AdmissionError) as ctx:
                materialize_manylinux_inputs(
                    self._legacy_with_stage_b(),
                    self.root / "materialized-legacy-external",
                    repository=self.root,
                    phase=QUALIFICATION_INPUT_PHASE_PREP,
                    inrun_root=external,
                )
            self.assertEqual(ctx.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_ROOT")
        finally:
            shutil.rmtree(external, ignore_errors=True)

    def test_external_root_must_be_outside_checkout_and_not_symlink(self) -> None:
        inside = self.root / "evidence"
        with self.assertRaises(AdmissionError) as ctx_inside:
            materialize_manylinux_inputs(
                self.descriptor,
                self.root / "materialized-inside",
                repository=self.root,
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=inside,
            )
        self.assertEqual(ctx_inside.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_ROOT")

        external = self._external_inputs()
        link = external.parent / (external.name + "-link")
        link.symlink_to(external, target_is_directory=True)
        try:
            with self.assertRaises(AdmissionError) as ctx_link:
                materialize_manylinux_inputs(
                    self.descriptor,
                    self.root / "materialized-link",
                    repository=self.root,
                    phase=QUALIFICATION_INPUT_PHASE_PREP,
                    inrun_root=link,
                )
            self.assertEqual(ctx_link.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_ROOT")
        finally:
            link.unlink(missing_ok=True)
            shutil.rmtree(external, ignore_errors=True)

    def test_external_digest_join_is_still_descriptor_bound(self) -> None:
        external = self._external_inputs()
        try:
            bad = copy.deepcopy(self.descriptor)
            bad["evidence"]["files"]["manylinux/stage-a.json"]["sha256"] = "f" * 64
            with self.assertRaises(AdmissionError) as ctx:
                materialize_manylinux_inputs(
                    bad,
                    self.root / "materialized-bad-digest",
                    repository=self.root,
                    phase=QUALIFICATION_INPUT_PHASE_PREP,
                    inrun_root=external,
                )
            self.assertIn(
                ctx.exception.code,
                {
                    "TF_PYPI_QUALIFICATION_INPUTS_MANYLINUX",
                    "TF_PYPI_QUALIFICATION_INPUTS_EVIDENCE",
                },
            )
        finally:
            shutil.rmtree(external, ignore_errors=True)

    def test_require_clean_still_rejects_dirty_checkout_before_transport(self) -> None:
        git_root = Path(
            tempfile.mkdtemp(prefix=".public-inrun-git-", dir=self.root.parent)
        )
        external = self._external_inputs()
        env_names = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE")
        saved = {name: os.environ.pop(name, None) for name in env_names}
        try:
            (git_root / "README").write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=git_root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=git_root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=git_root, check=True)
            subprocess.run(["git", "add", "README"], cwd=git_root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=git_root, check=True)
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=git_root, text=True
            ).strip()
            (git_root / "dirty").write_text("untracked\n", encoding="utf-8")
            with self.assertRaises(AdmissionError) as ctx:
                build_candidates_bundle(
                    git_root / "out",
                    expected_commit=commit,
                    repository=git_root,
                    evidence_dir=git_root / "evidence",
                    qualification_inputs=self.descriptor,
                    require_clean=True,
                    inrun_root=external,
                )
            self.assertEqual(ctx.exception.code, "TF_PYPI_HOSTED_WORKTREE_DIRTY")
        finally:
            for name, value in saved.items():
                if value is not None:
                    os.environ[name] = value
            shutil.rmtree(git_root, ignore_errors=True)
            shutil.rmtree(external, ignore_errors=True)

    def test_cli_and_downstream_consumers_require_explicit_transport_pair(self) -> None:
        for operation, required in (
            (
                "materialize-manylinux-inputs",
                ["--qualification-inputs", "descriptor.json", "--evidence", "evidence"],
            ),
            (
                "build-candidates",
                ["--output", "out", "--expected-commit", "a" * 40],
            ),
            (
                "qualify-native",
                [
                    "--target", "linux-x64-gnu", "--bundle", "bundle", "--work", "work",
                    "--output", "result", "--expected-commit", "a" * 40,
                    "--run-id", "1", "--run-attempt", "1",
                ],
            ),
            (
                "admit-matrix",
                [
                    "--bundle", "bundle", "--receipts-dir", "receipts", "--output", "matrix",
                    "--expected-commit", "a" * 40, "--run-id", "1", "--run-attempt", "1",
                ],
            ),
            (
                "prepare-resume",
                ["--api-dir", "api", "--archives-dir", "archives", "--output", "resume"],
            ),
            (
                "select-missing",
                ["--candidate-receipt", "candidate", "--expected-artifacts", "expected", "--receipts-dir", "receipts"],
            ),
            ("verify-upload", []),
        ):
            parsed = parser().parse_args([operation, *required, "--inrun-root", "/explicit/root"])
            self.assertEqual(parsed.inrun_root, Path("/explicit/root"))

        external = self._external_inputs()
        try:
            with self.assertRaises(AdmissionError) as ctx:
                _validate_optional_inrun_transport(
                    self._legacy_with_stage_b(),
                    repository=self.root,
                    inrun_root=external,
                    phase="publication",
                )
            self.assertEqual(ctx.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_ROOT")
        finally:
            shutil.rmtree(external, ignore_errors=True)

    def test_prepare_resume_uses_explicit_external_descriptor_path(self) -> None:
        external = self._external_inputs()
        descriptor_path = external / "qualification-inputs.json"
        descriptor_path.write_bytes(canonical(self.descriptor))
        output = self.root / "resume-explicit"
        stage_bytes = canonical(
            {
                "schema": "rs9.nebular070-payload-portability-input.v2",
                "record": {
                    "tf_producer_source": self.descriptor["manylinux"]["tf_producer_source"],
                },
                "bodies": {},
            }
        )
        approval = {
            "manylinux_stage_a_sha256": "a" * 64,
            "files": [],
            "qualification": {
                "candidate_source_commit": "b" * 40,
                "candidate_source_tree": "c" * 40,
            },
        }
        capture = {"run_id": "1"}
        extracted = {
            CANDIDATE_BUNDLE_ARTIFACT: {
                "candidate_receipt.json": b"{}",
                "expected_artifacts.json": b"{}",
                MANYLINUX_STAGE_A_MEMBER: stage_bytes,
            },
            MANYLINUX_ADMISSION_ARTIFACT: {},
        }
        seen: dict[str, object] = {}
        real_loader = publish.load_qualification_inputs_descriptor

        class StopAfterDescriptor(Exception):
            pass

        def tracking_loader(path=None, **kwargs):
            seen["path"] = path
            seen.update(kwargs)
            return real_loader(path, **kwargs)

        def stop_payload(*args, **kwargs):
            raise StopAfterDescriptor()

        try:
            with mock.patch.object(publish, "load_pin", return_value={}), \
                    mock.patch.object(publish, "load_approval", return_value=approval), \
                    mock.patch.object(publish, "load_qualification_capture", return_value=capture), \
                    mock.patch.object(publish, "_cross_check_pin_and_approval", return_value=({}, approval)), \
                    mock.patch.object(publish, "validate_api_metadata"), \
                    mock.patch.object(publish, "validate_archives", return_value=extracted), \
                    mock.patch.object(publish, "load_qualification_inputs_descriptor", side_effect=tracking_loader), \
                    mock.patch.object(publish, "load_payload_portability_bundle", side_effect=stop_payload):
                with self.assertRaises(StopAfterDescriptor):
                    publish.prepare_resume(
                        self.root / "api",
                        self.root / "archives",
                        output,
                        publisher_dir=self.root,
                        qualification_dir=self.root,
                        qualification_inputs=descriptor_path,
                        inrun_root=external,
                    )
            self.assertEqual(seen["path"], descriptor_path)
            self.assertEqual(seen["repository"], self.root)
            self.assertEqual(seen["inrun_root"], external)
        finally:
            shutil.rmtree(external, ignore_errors=True)

    def test_prepare_resume_public_descriptor_without_explicit_root_refuses(self) -> None:
        external = self._external_inputs()
        descriptor_path = external / "qualification-inputs.json"
        descriptor_path.write_bytes(canonical(self.descriptor))
        stage_bytes = canonical(
            {
                "schema": "rs9.nebular070-payload-portability-input.v2",
                "record": {
                    "tf_producer_source": self.descriptor["manylinux"]["tf_producer_source"],
                },
                "bodies": {},
            }
        )
        approval = {
            "manylinux_stage_a_sha256": "a" * 64,
            "files": [],
            "qualification": {
                "candidate_source_commit": "b" * 40,
                "candidate_source_tree": "c" * 40,
            },
        }
        extracted = {
            CANDIDATE_BUNDLE_ARTIFACT: {
                "candidate_receipt.json": b"{}",
                "expected_artifacts.json": b"{}",
                MANYLINUX_STAGE_A_MEMBER: stage_bytes,
            },
            MANYLINUX_ADMISSION_ARTIFACT: {},
        }
        try:
            with mock.patch.object(publish, "load_pin", return_value={}), \
                    mock.patch.object(publish, "load_approval", return_value=approval), \
                    mock.patch.object(publish, "load_qualification_capture", return_value={"run_id": "1"}), \
                    mock.patch.object(publish, "_cross_check_pin_and_approval", return_value=({}, approval)), \
                    mock.patch.object(publish, "validate_api_metadata"), \
                    mock.patch.object(publish, "validate_archives", return_value=extracted), \
                    mock.patch.object(publish, "load_payload_portability_bundle"):
                with self.assertRaises(AdmissionError) as ctx:
                    publish.prepare_resume(
                        self.root / "api",
                        self.root / "archives",
                        self.root / "resume-no-root",
                        publisher_dir=self.root,
                        qualification_dir=self.root,
                        qualification_inputs=descriptor_path,
                    )
            self.assertEqual(ctx.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_ROOT")
        finally:
            shutil.rmtree(external, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
