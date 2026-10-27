"""Focused tests for the attended Burst publication resume boundary."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Iterator
import unittest
import zipfile

import yaml

from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
from rs9.tf_pypi_resume import (
    AGGREGATE_SET_SHA256,
    PROJECT,
    QUALIFICATION_COMMIT,
    QUALIFICATION_RUN_ID,
    _ARTIFACTS,
    _PREREQUISITES,
    _PUBLISH_FAILED_STEP,
    _PUBLISH_JOB,
    _PUBLISH_READBACK_STEP,
    _PUBLISH_UPLOAD_STEP,
    load_capture,
    materialize,
    validate_api_metadata,
    validate_archive,
    validate_publisher,
    workflow_text,
)


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "operators/tf-pypi/theme-forge-stellar-burst-0.7.0-qualification.json"


@contextlib.contextmanager
def _tempdir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp).resolve()


def _jobs_fixture(capture):
    jobs = []
    for index, name in enumerate(_PREREQUISITES, start=1):
        jobs.append({
            "id": 121938317231 + index,
            "run_id": int(capture["run_id"]),
            "run_attempt": int(capture["run_attempt"]),
            "head_branch": "main",
            "head_sha": capture["head"],
            "status": "completed",
            "conclusion": "success",
            "name": name,
            "steps": [{"name": "completed prerequisite", "status": "completed", "conclusion": "success"}],
        })
    jobs.append({
        "id": 121938587340,
        "run_id": int(capture["run_id"]),
        "run_attempt": int(capture["run_attempt"]),
        "head_branch": "main",
        "head_sha": capture["head"],
        "status": "completed",
        "conclusion": "failure",
        "name": _PUBLISH_JOB,
        "steps": [
            {"name": "Set up job", "status": "completed", "conclusion": "success"},
            {"name": _PUBLISH_FAILED_STEP, "status": "completed", "conclusion": "failure"},
            {"name": _PUBLISH_UPLOAD_STEP, "status": "completed", "conclusion": "skipped"},
            {"name": _PUBLISH_READBACK_STEP, "status": "completed", "conclusion": "skipped"},
            {"name": "Complete job", "status": "completed", "conclusion": "success"},
        ],
    })
    return {"total_count": len(jobs), "jobs": jobs}


class ResumeTests(unittest.TestCase):
    def test_capture_binds_original_first_attempt_and_all_four_artifacts(self):
        capture = load_capture(CAPTURE)
        self.assertEqual(capture["project"], PROJECT)
        self.assertEqual(capture["head"], QUALIFICATION_COMMIT)
        self.assertEqual(capture["run_id"], QUALIFICATION_RUN_ID)
        self.assertEqual(capture["run_attempt"], "1")
        self.assertEqual(capture["aggregate_set_sha256"], AGGREGATE_SET_SHA256)
        self.assertEqual({row["name"] for row in capture["artifacts"]}, set(_ARTIFACTS))

    def test_capture_rejects_attempt_two_or_wrong_head(self):
        capture = json.loads(CAPTURE.read_text())
        with _tempdir() as root:
            path = root / CAPTURE.name
            capture["run_attempt"] = "2"
            path.write_bytes(canonical(capture))
            with self.assertRaises(AdmissionError) as error:
                load_capture(path)
            self.assertEqual(error.exception.code, "TF_PYPI_RESUME_CAPTURE_RUN")

    def test_archive_validator_checks_outer_and_member_digests(self):
        body = b"receipt"
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            member = zipfile.ZipInfo("result.json")
            member.external_attr = 0o100644 << 16
            archive.writestr(member, body)
        raw = stream.getvalue()
        row = {
            "size": len(raw),
            "sha256": sha256(raw),
            "members": [{"name": "result.json", "bytes": len(body), "sha256": sha256(body)}],
        }
        self.assertEqual(validate_archive(raw, row), {"result.json": body})
        with self.assertRaises(AdmissionError) as error:
            validate_archive(raw[:-1] + bytes([raw[-1] ^ 1]), row)
        self.assertEqual(error.exception.code, "TF_PYPI_RESUME_ARCHIVE_DIGEST")

    def test_api_metadata_requires_exact_run_and_artifact_identity(self):
        capture = load_capture(CAPTURE)
        with _tempdir() as root:
            metadata = root
            (metadata / "run.json").write_bytes(canonical({
                "name": "RS9 theme-forge-stellar-burst publish / burst070-publish-20261027-0043-root1",
                "id": int(capture["run_id"]),
                "run_attempt": int(capture["run_attempt"]),
                "head_sha": capture["head"],
                "status": "completed",
                "conclusion": "failure",
                "head_branch": "main",
                "path": ".github/workflows/rs9-tfsb-pypi-publish.yml",
                "event": "workflow_dispatch",
                "repository": {"full_name": capture["repository"], "id": capture["repository_id"]},
                "head_repository": {"full_name": capture["repository"], "id": capture["repository_id"]},
                "head_commit": {"id": capture["head"], "tree_id": "f847046ec9ec503d9b2370f517ffe6c66d2d4200"},
            }))
            (metadata / "jobs.json").write_bytes(canonical(_jobs_fixture(capture)))
            for row in capture["artifacts"]:
                value = {
                    "id": row["id"],
                    "name": row["name"],
                    "size_in_bytes": row["size"],
                    "digest": "sha256:" + row["sha256"],
                    "expired": False,
                    "workflow_run": row["workflow_run"],
                }
                (metadata / f"{row['id']}.json").write_bytes(canonical(value))
            self.assertTrue(validate_api_metadata(capture, metadata))
            run = json.loads((metadata / "run.json").read_text())
            run["conclusion"] = "success"
            (metadata / "run.json").write_bytes(canonical(run))
            with self.assertRaises(AdmissionError) as error:
                validate_api_metadata(capture, metadata)
            self.assertEqual(error.exception.code, "TF_PYPI_RESUME_METADATA_RUN")
            run["conclusion"] = "failure"
            (metadata / "run.json").write_bytes(canonical(run))
            tampered = json.loads((metadata / "12701155653.json").read_text())
            tampered["workflow_run"]["id"] = 40427947586
            (metadata / "12701155653.json").write_bytes(canonical(tampered))
            with self.assertRaises(AdmissionError) as error:
                validate_api_metadata(capture, metadata)
            self.assertEqual(error.exception.code, "TF_PYPI_RESUME_METADATA_LINEAGE")
            tampered["workflow_run"]["id"] = int(capture["run_id"])
            (metadata / "12701155653.json").write_bytes(canonical(tampered))
            run = json.loads((metadata / "run.json").read_text())
            run["run_attempt"] = 2
            (metadata / "run.json").write_bytes(canonical(run))
            with self.assertRaises(AdmissionError) as error:
                validate_api_metadata(capture, metadata)
            self.assertEqual(error.exception.code, "TF_PYPI_RESUME_METADATA_RUN")

    def test_api_metadata_rejects_prerequisite_failure_or_upload_attempt(self):
        capture = load_capture(CAPTURE)
        with _tempdir() as root:
            metadata = root
            (metadata / "run.json").write_bytes(canonical({
                "id": int(capture["run_id"]),
                "run_attempt": int(capture["run_attempt"]),
                "head_sha": capture["head"],
                "status": "completed",
                "conclusion": "failure",
                "head_branch": "main",
                "path": ".github/workflows/rs9-tfsb-pypi-publish.yml",
                "event": "workflow_dispatch",
                "repository": {"full_name": capture["repository"], "id": capture["repository_id"]},
                "head_repository": {"full_name": capture["repository"], "id": capture["repository_id"]},
            }))
            for row in capture["artifacts"]:
                (metadata / f"{row['id']}.json").write_bytes(canonical({
                    "id": row["id"],
                    "name": row["name"],
                    "size_in_bytes": row["size"],
                    "digest": "sha256:" + row["sha256"],
                    "expired": False,
                    "workflow_run": row["workflow_run"],
                }))
            jobs = _jobs_fixture(capture)
            jobs["jobs"][0]["conclusion"] = "failure"
            (metadata / "jobs.json").write_bytes(canonical(jobs))
            with self.assertRaises(AdmissionError) as error:
                validate_api_metadata(capture, metadata)
            self.assertEqual(error.exception.code, "TF_PYPI_RESUME_METADATA_JOBS")
            jobs = _jobs_fixture(capture)
            jobs["jobs"][-1]["steps"][2]["conclusion"] = "success"
            (metadata / "jobs.json").write_bytes(canonical(jobs))
            with self.assertRaises(AdmissionError) as error:
                validate_api_metadata(capture, metadata)
            self.assertEqual(error.exception.code, "TF_PYPI_RESUME_METADATA_JOBS")
            jobs = _jobs_fixture(capture)
            jobs["jobs"][-1]["steps"][-1]["conclusion"] = "failure"
            (metadata / "jobs.json").write_bytes(canonical(jobs))
            with self.assertRaises(AdmissionError) as error:
                validate_api_metadata(capture, metadata)
            self.assertEqual(error.exception.code, "TF_PYPI_RESUME_METADATA_JOBS")
            jobs = _jobs_fixture(capture)
            jobs["jobs"][0]["run_attempt"] = 2
            (metadata / "jobs.json").write_bytes(canonical(jobs))
            with self.assertRaises(AdmissionError) as error:
                validate_api_metadata(capture, metadata)
            self.assertEqual(error.exception.code, "TF_PYPI_RESUME_METADATA_JOBS")

    def test_promoted_burst_metadata_is_three_platform_and_publication_admitted(self):
        pin = json.loads((ROOT / "operators/tf-pypi/theme-forge-stellar-burst-0.7.0.json").read_text())
        self.assertEqual(pin["source_status"], "READY")
        self.assertEqual(pin["qualified_platforms"], ["darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"])
        aggregate = json.loads((ROOT / "operators/tf-pypi/theme-forge-stellar-burst-0.7.0-artifacts.json").read_text())
        self.assertEqual(aggregate["schema"], "rs9.tf-pypi-candidate-aggregate.v1")
        self.assertEqual(aggregate["project"], PROJECT)
        self.assertEqual(aggregate["version"], "0.7.0")
        self.assertTrue(aggregate["publication_admitted"])
        self.assertEqual(aggregate["set_sha256"], AGGREGATE_SET_SHA256)
        self.assertEqual({row["target"] for row in aggregate["files"] if row["target"]}, set(pin["qualified_platforms"]))

    def test_materialize_writes_only_dist_and_three_receipt_targets(self):
        capture = load_capture(CAPTURE)
        archives = {
            "pypi-artifacts": {
                name: name.encode("ascii")
                for name in _ARTIFACTS["pypi-artifacts"]["members"]
            },
            "native-consumer-theme-forge-stellar-burst-linux-arm64-gnu": {"result.json": b"arm"},
            "native-consumer-theme-forge-stellar-burst-darwin-arm64": {"result.json": b"darwin"},
            "native-consumer-theme-forge-stellar-burst-linux-x64-gnu": {"result.json": b"x64"},
        }
        with _tempdir() as root:
            result = materialize(capture, archives, root / "resume", publisher_revision="f" * 40)
            self.assertEqual(
                {path.name for path in result["dist"].iterdir()},
                set(archives["pypi-artifacts"]),
            )
            self.assertEqual(
                {path.name for path in result["receipts"].iterdir()},
                {"darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"},
            )
            self.assertFalse(result["lineage"]["publication_admitted"])
            self.assertEqual(result["lineage"]["publisher_revision"], "f" * 40)

    def test_workflow_is_attended_resume_and_keeps_qualification_source_separate(self):
        document = yaml.safe_load(workflow_text())
        job = document["jobs"]["publish"]
        text = workflow_text()
        trigger = document.get("on", document.get(True))
        self.assertEqual(trigger, {"workflow_dispatch": {"inputs": {
            "dispatch_id": {
                "description": "Attended resume correlation; not publication authority",
                "required": True,
                "type": "string",
            }
        }}})
        self.assertEqual(len(job["needs"]) if "needs" in job else 0, 0)
        self.assertIn("path: qualification-source", text)
        self.assertIn(QUALIFICATION_COMMIT, text)
        self.assertIn(QUALIFICATION_RUN_ID, text)
        self.assertIn(f"attempts/1/jobs?per_page=100", text)
        self.assertIn('> "remote-metadata/jobs.json"', text)
        self.assertIn("actions/artifacts/$artifact_id/zip", text)
        self.assertIn("pypa/gh-action-pypi-publish@", text)
        self.assertNotIn("tf_pypi_publish build", text)
        self.assertNotIn("tf_pypi_hosted qualify", text)
        self.assertNotIn("tf_pypi_hosted admit", text)

    def test_resume_qualification_source_uses_relative_pythonpath(self):
        with _tempdir() as root:
            qualification_source = root / "qualification-source"
            shutil.copytree(ROOT / "src", qualification_source / "src")
            command = ["python3", "-B", "-c", "import rs9.tf_pypi_publish"]
            environment = os.environ.copy()
            environment["PYTHONPATH"] = "$GITHUB_WORKSPACE/qualification-source/src"
            literal = subprocess.run(
                command,
                cwd=qualification_source,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(literal.returncode, 0)
            self.assertIn("ModuleNotFoundError", literal.stderr)
            environment["PYTHONPATH"] = "src"
            relative = subprocess.run(
                command,
                cwd=qualification_source,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(relative.returncode, 0, relative.stderr)

    def test_publisher_revision_requires_original_head_ancestor(self):
        with self.assertRaises(AdmissionError) as error:
            validate_publisher(ROOT, "0" * 40)
        self.assertEqual(error.exception.code, "TF_PYPI_RESUME_PUBLISHER_REVISION")


if __name__ == "__main__":
    unittest.main()
