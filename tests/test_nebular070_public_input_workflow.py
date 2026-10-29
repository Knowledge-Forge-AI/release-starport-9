"""Focused tests for the held public-input workflow wiring."""

from __future__ import annotations

import io
import json
import hashlib
from pathlib import Path
import stat
import tempfile
from types import ModuleType
import unittest
import zipfile
from unittest.mock import patch

from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_nebular070_publish import (
    MANYLINUX_ADMISSION_ARTIFACT,
    MANYLINUX_ADMISSION_MEMBERS,
    MANYLINUX_ADMISSION_MEMBER,
    QUALIFY_BRANCH,
    DEFAULT_GITHUB_REPOSITORY,
    BOOKWORM_DISPLAY_TOOL_PACKAGES,
    DISPLAY_TOOL_COMMANDS,
    UBUNTU_DISPLAY_TOOL_PACKAGES,
    PUBLIC_INPUTS_ARTIFACT,
    PUBLIC_INPUTS_DESCRIPTOR,
    PUBLIC_INPUTS_PREPARATION_RECEIPT,
    PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR,
    PUBLIC_STAGE_A_OUTPUT,
    PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND,
    PUBLIC_INRUN_MANYLINUX_SCHEMA,
    _public_stage_a_output_from_descriptor,
    _load_public_stage_a_adapter,
    _read_public_descriptor_bind_output,
    _resume_stage_b_member_path,
    build_candidates_bundle,
    extract_public_external_artifact,
    prepare_public_inputs_070,
    publication_resume_job_text,
    validate_public_external_artifact_metadata,
    workflow_070_jobs_text,
)


def _zip_bytes(files: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, body in files.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, body)
        if symlink is not None:
            info = zipfile.ZipInfo(symlink)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"target")
    return buf.getvalue()


class Nebular070PublicInputWorkflowTests(unittest.TestCase):
    def test_stage_a_loader_preserves_module_assembler_and_binder_exports(self):
        adapter = ModuleType("rs9.nebular070_public_stagea_files")

        def assemble_stage_a_files(**_kwargs):
            return {}

        def bind_descriptor_phase(**_kwargs):
            return {}

        adapter.assemble_stage_a_files = assemble_stage_a_files
        adapter.bind_descriptor_phase = bind_descriptor_phase
        with patch(
            "rs9.tf_pypi_nebular070_publish.importlib.import_module",
            return_value=adapter,
        ):
            loaded = _load_public_stage_a_adapter()
        self.assertIs(loaded, adapter)
        self.assertIs(loaded.assemble_stage_a_files, assemble_stage_a_files)
        self.assertIs(loaded.bind_descriptor_phase, bind_descriptor_phase)

    def test_stage_a_bind_result_keeps_evidence_and_artifact_path_domains_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            old = json.dumps(
                {"evidence": {"source_root": "evidence/public-release"}},
                sort_keys=True,
            ).encode()
            new = b"{\"status\":\"ready\"}\n"
            payload = b"payload"
            (root / PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR).write_bytes(old)
            descriptor_path = root / PUBLIC_INPUTS_DESCRIPTOR
            descriptor_path.write_bytes(new)
            payload_path = root / PUBLIC_STAGE_A_OUTPUT / "payload-portability.json"
            payload_path.parent.mkdir(parents=True)
            payload_path.write_bytes(payload)
            result = {
                "schema": "rs9.nebular070-public-descriptor-bind.v1",
                "status": "pass",
                "phase": "qualification-prep",
                "role": "stage_a",
                "old_descriptor_sha256": hashlib.sha256(old).hexdigest(),
                "new_descriptor_sha256": hashlib.sha256(new).hexdigest(),
                "stage_file": {
                    "path": "generated-stage-a/payload-portability.json",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
            }
            binding = _read_public_descriptor_bind_output(
                root,
                descriptor_path,
                f"{PUBLIC_STAGE_A_OUTPUT}/payload-portability.json",
                result,
            )
            self.assertEqual(
                binding["stage_file"]["path"],
                "generated-stage-a/payload-portability.json",
            )
            self.assertEqual(
                binding["stage_artifact_path"],
                f"{PUBLIC_STAGE_A_OUTPUT}/payload-portability.json",
            )

    def test_prepare_job_is_reachable_without_skipped_reject_dependency(self):
        text = workflow_070_jobs_text()
        prepare = text.split("  prepare_public_inputs_070:\n", 1)[1].split(
            "  build_verify_070:", 1
        )[0]
        self.assertNotIn("\n    needs:", prepare)

    def test_public_input_upload_keeps_hidden_transport_and_build_uses_descriptor_stage_a(self):
        text = workflow_070_jobs_text()
        public_upload = text.split(
            "      - name: Upload 0.7.0 public inputs\n", 1
        )[1].split("\n  build_verify_070:", 1)[0]
        self.assertIn("include-hidden-files: true", public_upload)
        self.assertIn(
            "path: '${{ runner.temp }}/tfnf-070-public-inputs/'", public_upload
        )
        self.assertEqual(text.count("include-hidden-files: true"), 1)

        build = text.split("  build_verify_070:\n", 1)[1].split(
            "\n  native_consumer_070_darwin_arm64:", 1
        )[0]
        self.assertNotIn("--payload-portability", build)
        self.assertIn("--require-manylinux", build)
        self.assertIn(
            "--tf-producer-commit 79c67bb70d800701b4b0cdbb9caa9be2bbc7c2ff",
            build,
        )
        self.assertIn(
            "--tf-producer-tree e663c9cf15144578a17d3cd501cf031ac83a7e0e",
            build,
        )

    def test_descriptor_stage_a_default_and_source_override_guard_remain_closed(self):
        descriptor = {
            "manylinux": {
                "schema": PUBLIC_INRUN_MANYLINUX_SCHEMA,
                "origin_kind": PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND,
                "stage_a": {"path": "generated-stage-a/payload-portability.json"},
            }
        }
        self.assertEqual(
            _public_stage_a_output_from_descriptor(descriptor), "generated-stage-a"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            evidence = root / "evidence"
            evidence.mkdir()
            wrong = root / "wrong-payload-portability.json"
            wrong.write_bytes(b"{}")
            with (
                patch(
                    "rs9.tf_pypi_nebular070_publish.repo_root",
                    return_value=root,
                ),
                patch(
                    "rs9.tf_pypi_nebular070_publish._git_output",
                    return_value="a" * 40,
                ),
                patch(
                    "rs9.tf_pypi_nebular070_publish.materialize_qualification_evidence",
                    return_value=descriptor,
                ),
            ):
                with self.assertRaises(AdmissionError) as ctx:
                    build_candidates_bundle(
                        root / "bundle",
                        expected_commit="a" * 40,
                        evidence_dir=evidence,
                        payload_portability=wrong,
                        tf_producer_source={"commit": "c" * 40, "tree": "d" * 40},
                        require_manylinux=True,
                    )
            self.assertEqual(ctx.exception.code, "TF_PYPI_MANYLINUX_INPUT")

    def test_stage_b_resume_layout_matches_prepare_resume_materialization(self):
        resume = Path("resume")
        self.assertEqual(
            _resume_stage_b_member_path(resume, MANYLINUX_ADMISSION_MEMBER),
            resume / MANYLINUX_ADMISSION_MEMBER,
        )
        for member in sorted(MANYLINUX_ADMISSION_MEMBERS - {MANYLINUX_ADMISSION_MEMBER}):
            self.assertEqual(
                _resume_stage_b_member_path(resume, member),
                resume / "manylinux-consumers" / member,
            )
        with self.assertRaises(AdmissionError):
            _resume_stage_b_member_path(resume, "unexpected.json")

    def test_external_artifact_metadata_accepts_only_authenticated_source_branches(self):
        for branch in ("main", QUALIFY_BRANCH):
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                run_id = 123
                head_sha = "a" * 40
                stage_id = 9001
                public_id = 9002
                stage_size = 17
                public_size = 19
                stage_url = (
                    f"https://api.github.com/repos/{DEFAULT_GITHUB_REPOSITORY}/"
                    f"actions/artifacts/{stage_id}/zip"
                )
                public_url = (
                    f"https://api.github.com/repos/{DEFAULT_GITHUB_REPOSITORY}/"
                    f"actions/artifacts/{public_id}/zip"
                )
                stage_sha = "b" * 64
                capture = {
                    "repository": DEFAULT_GITHUB_REPOSITORY,
                    "run_id": run_id,
                    "head_branch": branch,
                    "qualification_source_commit": head_sha,
                    "artifacts": {
                        MANYLINUX_ADMISSION_ARTIFACT: {
                            "id": stage_id,
                            "size_in_bytes": stage_size,
                            "archive_download_url": stage_url,
                            "archive_sha256": stage_sha,
                        }
                    },
                }
                (root / "artifacts.json").write_text(
                    json.dumps(
                        {
                            "artifacts": [
                                {
                                    "name": PUBLIC_INPUTS_ARTIFACT,
                                    "id": public_id,
                                    "size_in_bytes": public_size,
                                    "archive_download_url": public_url,
                                    "expired": False,
                                    "workflow_run": {
                                        "id": run_id,
                                        "head_sha": head_sha,
                                        "head_branch": branch,
                                    },
                                },
                                {
                                    "name": MANYLINUX_ADMISSION_ARTIFACT,
                                    "id": stage_id,
                                    "size_in_bytes": stage_size,
                                    "archive_download_url": stage_url,
                                    "archive_sha256": f"sha256:{stage_sha}",
                                    "expired": False,
                                    "workflow_run": {
                                        "id": run_id,
                                        "head_sha": head_sha,
                                        "head_branch": branch,
                                    },
                                },
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                rows = validate_public_external_artifact_metadata(root, capture=capture)
                self.assertEqual(rows[MANYLINUX_ADMISSION_ARTIFACT]["id"], stage_id)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            capture = {
                "repository": DEFAULT_GITHUB_REPOSITORY,
                "run_id": 123,
                "head_branch": "feature/not-allowed",
                "qualification_source_commit": "a" * 40,
                "artifacts": {},
            }
            (root / "artifacts.json").write_text('{"artifacts": []}', encoding="utf-8")
            with self.assertRaises(AdmissionError):
                validate_public_external_artifact_metadata(root, capture=capture)

    def test_workflow_has_held_transport_external_roots_and_floor_jobs(self):
        text = workflow_070_jobs_text()
        self.assertIn("prepare-public-inputs-070", text)
        self.assertIn("tfnf-070-public-inputs/qualification-inputs-prep.json", text)
        self.assertIn("--inrun-root", text)
        self.assertIn("Extract and bind held public input roots", text)
        self.assertIn("Verify external Stage-B and Stage-A bindings", text)
        self.assertIn("assemble-stage-b", text)
        self.assertIn("--cap-add=SYS_ADMIN", text)
        self.assertNotIn("options: --privileged", text)
        self.assertIn("Native consumer 0.7.0 (linux-arm64-gnu floor)", text)
        self.assertIn("Native consumer 0.7.0 (linux-x64-gnu floor)", text)
        self.assertIn("--consumer-host-role newer", text)

    def test_workflow_declares_minimal_display_tool_policy(self):
        text = workflow_070_jobs_text()
        self.assertEqual(text.count("- name: Install minimal Ubuntu display tools"), 2)
        self.assertEqual(text.count("- name: Verify Ubuntu display tool class"), 2)
        self.assertEqual(text.count("- name: Verify Bookworm display tool class"), 2)
        self.assertEqual(text.count("platform=ubuntu-runner"), 2)
        self.assertEqual(text.count("platform=debian-bookworm-floor"), 2)
        self.assertEqual(text.count("options: --init --cap-add=SYS_ADMIN"), 2)
        self.assertNotIn("options: --privileged", text)
        self.assertNotIn("not approved for dispatch", text)
        for package in BOOKWORM_DISPLAY_TOOL_PACKAGES:
            self.assertEqual(text.count(package), 2)
        for package in UBUNTU_DISPLAY_TOOL_PACKAGES:
            self.assertGreaterEqual(text.count(package), 4)
        for tool in DISPLAY_TOOL_COMMANDS:
            self.assertGreaterEqual(text.count(f"command -v \"$tool\""), 4)
        self.assertIn(
            "test \"$(dpkg-query -W -f='${Version}' xvfb)\" = \"2:21.1.7-3+deb12u13\"",
            text,
        )
        self.assertIn(
            "test \"$(dpkg-query -W -f='${Version}' xauth)\" = \"1:1.1.2-1\"",
            text,
        )
        self.assertIn(
            "test \"$(dpkg-query -W -f='${Version}' dbus-x11)\" = \"1.14.10-1~deb12u1\"",
            text,
        )

    def test_stage_b_archive_requires_the_closed_five_member_set(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            archive = root / "stage-b.zip"
            archive.write_bytes(
                _zip_bytes({name: b"{}" for name in sorted(MANYLINUX_ADMISSION_MEMBERS)})
            )
            out = root / "out"
            result = extract_public_external_artifact(
                archive,
                out,
                artifact_name=MANYLINUX_ADMISSION_ARTIFACT,
            )
            self.assertEqual(result["artifact"], MANYLINUX_ADMISSION_ARTIFACT)
            self.assertEqual(set(result["members"]), set(MANYLINUX_ADMISSION_MEMBERS))

    def test_public_input_archive_preserves_six_hidden_tfsb_members(self):
        hidden = {
            "docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-dark.toml",
            "docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-light.toml",
            "docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand-package.toml",
            "docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand.toml",
            "docs/examples/v0.4/brand-system/core-minimal/.tfsb/companions/GUIDANCE.md",
            "docs/examples/v0.4/brand-system/core-minimal/.tfsb/project.toml",
        }
        files = {
            PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR: b"{}",
            PUBLIC_INPUTS_DESCRIPTOR: b"{}",
            "fetch-receipt.json": b"{}",
            PUBLIC_INPUTS_PREPARATION_RECEIPT: b"{}",
            f"{PUBLIC_STAGE_A_OUTPUT}/payload-portability.json": b"{}",
            f"{PUBLIC_STAGE_A_OUTPUT}/stage-a-receipt.json": b"{}",
        }
        files.update({name: b"fixture" for name in hidden})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            archive = root / "public-inputs.zip"
            archive.write_bytes(_zip_bytes(files))
            result = extract_public_external_artifact(
                archive,
                root / "out",
                artifact_name=PUBLIC_INPUTS_ARTIFACT,
            )
            self.assertTrue(hidden.issubset(set(result["members"])))

    def test_external_archive_rejects_symlinks_and_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            for data in (
                _zip_bytes({PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR: b"{}",
                            PUBLIC_INPUTS_DESCRIPTOR: b"{}", "fetch-receipt.json": b"{}",
                            PUBLIC_INPUTS_PREPARATION_RECEIPT: b"{}",
                            f"{PUBLIC_STAGE_A_OUTPUT}/payload-portability.json": b"{}",
                            f"{PUBLIC_STAGE_A_OUTPUT}/stage-a-receipt.json": b"{}"},
                           symlink="escape"),
                _zip_bytes({"../escape": b"x"}),
            ):
                archive = root / "bad.zip"
                archive.write_bytes(data)
                with self.assertRaises(AdmissionError):
                    extract_public_external_artifact(
                        archive,
                        root / "out",
                        artifact_name=PUBLIC_INPUTS_ARTIFACT,
                    )
                if (root / "out").exists():
                    for child in (root / "out").rglob("*"):
                        if child.is_file() or child.is_symlink():
                            child.unlink()
                    for child in sorted((root / "out").rglob("*"), reverse=True):
                        if child.is_dir():
                            child.rmdir()
                    (root / "out").rmdir()

    def test_absolute_manifest_is_not_accepted_by_held_preparation(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(AdmissionError) as ctx:
                prepare_public_inputs_070(
                    Path(temp) / "tracked-manifest.json",
                    Path(temp) / "out",
                    repository=Path(__file__).resolve().parents[1],
                    rs9_source={"commit": "a" * 40, "tree": "b" * 40},
                    tf_producer_source={"commit": "c" * 40, "tree": "d" * 40},
                )
            self.assertIn("PUBLIC_INPUTS_MANIFEST", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
