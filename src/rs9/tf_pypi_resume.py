"""Attended, publication-only resume for the Burst 0.7.0 PyPI candidate.

This module admits only the four artifacts captured from the successful first
qualification attempt.  It never builds, qualifies, or uploads.  It changes
only fresh qualification-checkout metadata, never its source code or Git
history.  The workflow uses this module from the current
publisher checkout, then invokes the unchanged publication helpers from a
separate checkout at the original qualification commit.
"""

import argparse
import io
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import zipfile

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_model import load_pin, strict_json


PROJECT = "theme-forge-stellar-burst"
VERSION = "0.7.0"
REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
REPOSITORY_ID = 1402549560
QUALIFICATION_RUN_ID = "40427947585"
QUALIFICATION_RUN_ATTEMPT = "1"
QUALIFICATION_COMMIT = "e35ed6dfbe38f601db9b329c34331a170580372a"
QUALIFICATION_SOURCE_HASHES = {
    "src/rs9/tf_pypi_publish.py": "f9356ede72ec4df89a60e50d069c48373144efb3054d42b0ebbfdac87b6d0eed",
    "src/rs9/tf_pypi_hosted.py": "1d871566a6d8475ebd3209e22d3c30a49959d3c328338d152c8e7ee75ed52bff",
}
AGGREGATE_SET_SHA256 = "a88e0b211bd025b8bbab2e5f79fbdf6bde1e1fe61aaf4ef5fdeb0e63e1de31f3"

_ARTIFACTS = {
    "native-consumer-theme-forge-stellar-burst-linux-arm64-gnu": {
        "id": 12701155653,
        "size": 1819,
        "sha256": "cd06d7cb503aac58e29bb04a7b256edf49acf4934313b642d069c1b8258ff6bf",
        "members": {
            "result.json": {
                "bytes": 12122,
                "sha256": "0862cc1b6697db0f8ae2306ed52db58683948848f5c0e00e46ede7eedb1565cb",
            }
        },
        "target": "linux-arm64-gnu",
    },
    "pypi-artifacts": {
        "id": 12700482027,
        "size": 3977146,
        "sha256": "3a4cf61340708207d0296eecb37739fd808bc157c4c356767df0caa0646c4023",
        "members": {
            "theme_forge_stellar_burst-0.7.0-py3-none-macosx_13_0_arm64.whl": {
                "bytes": 4890808,
                "sha256": "df7bde863f94f6130fd0fe49af2ca85f9d2cffbfc3369226054120c095402e86",
            },
            "theme_forge_stellar_burst-0.7.0-py3-none-manylinux_2_33_aarch64.whl": {
                "bytes": 4910808,
                "sha256": "f9d6377697290a986112dff569058d9ec8c8730a2bea8395c38f2ee57e547636",
            },
            "theme_forge_stellar_burst-0.7.0-py3-none-manylinux_2_33_x86_64.whl": {
                "bytes": 4864702,
                "sha256": "b1ee52d8cb55788aeb53d6e94daceeccb8d53f092794af3e20ba115d39f4f16c",
            },
            "theme_forge_stellar_burst-0.7.0.tar.gz": {
                "bytes": 1228913,
                "sha256": "eeb0636584d586b375c909c26f52984995cb650755e5961e4f8ae2445ec40807",
            },
        },
        "target": None,
    },
    "native-consumer-theme-forge-stellar-burst-darwin-arm64": {
        "id": 12700432813,
        "size": 1816,
        "sha256": "37c07abdfdcbab55e08a775a054fdff5cffdf6fc68ced53bb346f51fbd75f638",
        "members": {
            "result.json": {
                "bytes": 12103,
                "sha256": "dbaf47f93be21c6e8b0850f3906e29dfa460c4ff979db1a26b62909a46553437",
            }
        },
        "target": "darwin-arm64",
    },
    "native-consumer-theme-forge-stellar-burst-linux-x64-gnu": {
        "id": 12700053808,
        "size": 1818,
        "sha256": "6f3b90fae04bbc0d1730638b9b122866c4b71fd3bf573e425769326f4cc1a506",
        "members": {
            "result.json": {
                "bytes": 12111,
                "sha256": "03a2a2e08fa91a57830974782df15aaebeb77124ec67c88b228a580d70f6b034",
            }
        },
        "target": "linux-x64-gnu",
    },
}

_PREREQUISITES = [
    "Build and Verify Candidate Artifacts",
    "Native Linux ARM64 GNU installed consumer",
    "Native macOS ARM64 installed consumer",
    "Native Linux x86_64 GNU installed consumer",
    "Three-host qualification gate",
]
_PUBLISH_JOB = "Trusted Publishing to PyPI"
_PUBLISH_FAILED_STEP = "Verify artifact integrity and select only missing files"
_PUBLISH_UPLOAD_STEP = "Publish package distributions to PyPI"
_PUBLISH_READBACK_STEP = "Read back published PyPI state"
_EXPECTED_JOB_NAMES = set(_PREREQUISITES) | {_PUBLISH_JOB}
_CAPTURE_KEYS = {
    "schema", "project", "version", "repository", "repository_id", "run_id",
    "run_attempt", "head", "aggregate_set_sha256", "artifacts",
    "successful_prerequisites",
}


def _require(condition, code):
    if not condition:
        fail("RESUME_" + code)


def _hex(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def _git_head(root):
    try:
        result = subprocess.run(
            ["git", "-C", str(Path(root).absolute()), "rev-parse", "HEAD"],
            capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        fail("RESUME_GIT")
    _require(result.returncode == 0, "GIT")
    value = result.stdout.decode("ascii", "replace").strip()
    _require(re.fullmatch(r"[0-9a-f]{40}", value) is not None, "GIT")
    return value


def _is_ancestor(root, ancestor, descendant):
    try:
        result = subprocess.run(
            ["git", "-C", str(Path(root).absolute()), "merge-base", "--is-ancestor", ancestor, descendant],
            capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        fail("RESUME_LINEAGE")
    _require(result.returncode == 0, "LINEAGE")


def _git_blob(root, revision, relative):
    try:
        result = subprocess.run(
            ["git", "-C", str(Path(root).absolute()), "show", f"{revision}:{relative}"],
            capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        fail("RESUME_SOURCE")
    _require(result.returncode == 0, "SOURCE")
    return result.stdout


def validate_publisher(root, publisher_revision):
    """Bind the current workflow checkout and prove the old head is its ancestor."""
    _require(_hex(publisher_revision, 40), "PUBLISHER_REVISION")
    _require(_git_head(root) == publisher_revision, "PUBLISHER_REVISION")
    _is_ancestor(root, QUALIFICATION_COMMIT, publisher_revision)
    return publisher_revision


def load_capture(path):
    """Load the immutable four-artifact first-attempt capture record."""
    value = strict_json(physical_bytes(path, limit=1024 * 1024))
    _require(isinstance(value, dict) and set(value) == _CAPTURE_KEYS, "CAPTURE_SCHEMA")
    _require(value["schema"] == "rs9.tf-pypi-publication-resume.v1", "CAPTURE_SCHEMA")
    _require(value["project"] == PROJECT and value["version"] == VERSION, "CAPTURE_PRODUCT")
    _require(value["repository"] == REPOSITORY and value["repository_id"] == REPOSITORY_ID, "CAPTURE_REPOSITORY")
    _require(value["run_id"] == QUALIFICATION_RUN_ID and value["run_attempt"] == QUALIFICATION_RUN_ATTEMPT, "CAPTURE_RUN")
    _require(value["head"] == QUALIFICATION_COMMIT, "CAPTURE_HEAD")
    _require(value["aggregate_set_sha256"] == AGGREGATE_SET_SHA256, "CAPTURE_AGGREGATE")
    _require(value["successful_prerequisites"] == _PREREQUISITES, "CAPTURE_PREREQUISITES")
    rows = value["artifacts"]
    _require(isinstance(rows, list) and len(rows) == len(_ARTIFACTS), "CAPTURE_ARTIFACTS")
    seen = set()
    for row in rows:
        _require(isinstance(row, dict) and set(row) == {"id", "name", "size", "sha256", "members", "workflow_run"}, "CAPTURE_ARTIFACT")
        name = row["name"]
        _require(name in _ARTIFACTS and name not in seen, "CAPTURE_ARTIFACT")
        seen.add(name)
        expected = _ARTIFACTS[name]
        _require(row["id"] == expected["id"] and row["size"] == expected["size"] and row["sha256"] == expected["sha256"], "CAPTURE_ARTIFACT")
        _require(isinstance(row["members"], list), "CAPTURE_MEMBERS")
        expected_members = expected["members"]
        _require(len(row["members"]) == len(expected_members), "CAPTURE_MEMBERS")
        member_seen = set()
        for member in row["members"]:
            _require(isinstance(member, dict) and set(member) == {"name", "bytes", "sha256"}, "CAPTURE_MEMBER")
            member_name = member["name"]
            _require(member_name in expected_members and member_name not in member_seen, "CAPTURE_MEMBER")
            member_seen.add(member_name)
            _require(member == {"name": member_name, **expected_members[member_name]}, "CAPTURE_MEMBER")
        _require(row["workflow_run"] == {
            "id": int(QUALIFICATION_RUN_ID),
            "head_sha": QUALIFICATION_COMMIT,
            "repository_id": REPOSITORY_ID,
            "head_repository_id": REPOSITORY_ID,
        }, "CAPTURE_LINEAGE")
    _require(seen == set(_ARTIFACTS), "CAPTURE_ARTIFACTS")
    return value


def validate_api_metadata(capture, metadata_dir):
    """Validate GitHub API artifact records before accepting archive bytes."""
    metadata_dir = Path(metadata_dir)
    _require(not metadata_dir.is_symlink() and metadata_dir.is_dir(), "METADATA_DIR")
    expected_names = {str(row["id"]) + ".json" for row in capture["artifacts"]} | {"run.json", "jobs.json"}
    _require({p.name for p in metadata_dir.iterdir()} == expected_names, "METADATA_INVENTORY")
    actual_run = strict_json(physical_bytes(metadata_dir / "run.json", limit=1024 * 1024))
    _require(
        isinstance(actual_run, dict)
        and actual_run.get("id") == int(capture["run_id"])
        and actual_run.get("run_attempt") == int(capture["run_attempt"])
        and actual_run.get("head_sha") == capture["head"]
        and actual_run.get("status") == "completed"
        and actual_run.get("conclusion") == "failure"
        and actual_run.get("head_branch") == "main"
        and actual_run.get("path") == ".github/workflows/rs9-tfsb-pypi-publish.yml"
        and actual_run.get("event") == "workflow_dispatch"
        and isinstance(actual_run.get("repository"), dict)
        and actual_run["repository"].get("full_name") == REPOSITORY
        and actual_run["repository"].get("id") == REPOSITORY_ID,
        "METADATA_RUN",
    )
    actual_head_repository = actual_run.get("head_repository")
    _require(
        isinstance(actual_head_repository, dict)
        and actual_head_repository.get("full_name") == REPOSITORY
        and actual_head_repository.get("id") == REPOSITORY_ID,
        "METADATA_RUN",
    )
    jobs = strict_json(physical_bytes(metadata_dir / "jobs.json", limit=8 * 1024 * 1024))
    _validate_jobs(capture, jobs)
    for row in capture["artifacts"]:
        actual = strict_json(physical_bytes(metadata_dir / f"{row['id']}.json", limit=1024 * 1024))
        _require(isinstance(actual, dict), "METADATA_SCHEMA")
        _require(actual.get("id") == row["id"] and actual.get("name") == row["name"], "METADATA_IDENTITY")
        _require(actual.get("size_in_bytes") == row["size"], "METADATA_SIZE")
        _require(actual.get("digest") == "sha256:" + row["sha256"] and actual.get("expired") is False, "METADATA_DIGEST")
        run = actual.get("workflow_run")
        _require(isinstance(run, dict), "METADATA_LINEAGE")
        for key, expected in row["workflow_run"].items():
            _require(run.get(key) == expected, "METADATA_LINEAGE")
    return True


def _validate_jobs(capture, value):
    """Bind the exact first-attempt prerequisite and pre-upload failure shape."""
    _require(
        isinstance(value, dict)
        and value.get("total_count") == len(_EXPECTED_JOB_NAMES)
        and isinstance(value.get("jobs"), list)
        and len(value["jobs"]) == len(_EXPECTED_JOB_NAMES),
        "METADATA_JOBS",
    )
    jobs = value["jobs"]
    names = [job.get("name") for job in jobs if isinstance(job, dict)]
    _require(len(names) == len(set(names)) == len(_EXPECTED_JOB_NAMES), "METADATA_JOBS")
    _require(set(names) == _EXPECTED_JOB_NAMES, "METADATA_JOBS")
    for job in jobs:
        _require(
            isinstance(job, dict)
            and job.get("run_id") == int(capture["run_id"])
            and job.get("run_attempt") == int(capture["run_attempt"])
            and job.get("head_sha") == capture["head"]
            and job.get("head_branch") == "main"
            and job.get("status") == "completed",
            "METADATA_JOBS",
        )
        if job["name"] in _PREREQUISITES:
            _require(job.get("conclusion") == "success", "METADATA_JOBS")
            continue
        _require(job["name"] == _PUBLISH_JOB and job.get("conclusion") == "failure", "METADATA_JOBS")
        steps = job.get("steps")
        _require(isinstance(steps, list), "METADATA_JOBS")
        step_names = [step.get("name") for step in steps if isinstance(step, dict)]
        _require(len(step_names) == len(set(step_names)), "METADATA_JOBS")
        by_name = {step["name"]: step for step in steps if isinstance(step, dict) and "name" in step}
        for name in (_PUBLISH_FAILED_STEP, _PUBLISH_UPLOAD_STEP, _PUBLISH_READBACK_STEP):
            _require(
                name in by_name
                and by_name[name].get("status") == "completed",
                "METADATA_JOBS",
            )
        _require(by_name[_PUBLISH_FAILED_STEP].get("conclusion") == "failure", "METADATA_JOBS")
        _require(by_name[_PUBLISH_UPLOAD_STEP].get("conclusion") == "skipped", "METADATA_JOBS")
        _require(by_name[_PUBLISH_READBACK_STEP].get("conclusion") == "skipped", "METADATA_JOBS")
        failed_steps = [step for step in steps if step.get("conclusion") == "failure"]
        skipped_steps = [step for step in steps if step.get("conclusion") == "skipped"]
        _require(
            len(failed_steps) == 1 and failed_steps[0].get("name") == _PUBLISH_FAILED_STEP,
            "METADATA_JOBS",
        )
        _require(
            {step.get("name") for step in skipped_steps}
            == {_PUBLISH_UPLOAD_STEP, _PUBLISH_READBACK_STEP},
            "METADATA_JOBS",
        )


def validate_archive(data, row):
    """Validate one raw Actions archive and return its exact member bytes."""
    _require(isinstance(data, (bytes, bytearray)), "ARCHIVE_TYPE")
    _require(len(data) == row["size"] and sha256(data) == row["sha256"], "ARCHIVE_DIGEST")
    expected = {member["name"]: member for member in row["members"]}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            _require(len(infos) == len(expected), "ARCHIVE_MEMBERS")
            names = [info.filename for info in infos]
            _require(set(names) == set(expected) and len({name.casefold() for name in names}) == len(names), "ARCHIVE_NAMES")
            output = {}
            for info in infos:
                _require(info.orig_filename == info.filename and "\x00" not in info.filename, "ARCHIVE_NAME")
                mode = info.external_attr >> 16
                _require(not info.is_dir() and not info.flag_bits & 1 and stat.S_IFMT(mode) == stat.S_IFREG and not mode & 0o7000, "ARCHIVE_TYPE")
                member = expected[info.filename]
                _require(info.file_size == member["bytes"], "ARCHIVE_MEMBER_SIZE")
                with archive.open(info) as stream:
                    body = stream.read(member["bytes"] + 1)
                    _require(len(body) == member["bytes"] and not stream.read(1), "ARCHIVE_MEMBER_SIZE")
                _require(sha256(body) == member["sha256"], "ARCHIVE_MEMBER_DIGEST")
                output[info.filename] = body
            return output
    except AdmissionError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        fail("RESUME_ARCHIVE")


def validate_archives(capture, archive_dir):
    """Validate exactly the captured raw archives, with no surplus files."""
    archive_dir = Path(archive_dir)
    _require(not archive_dir.is_symlink() and archive_dir.is_dir(), "ARCHIVE_DIR")
    expected_paths = {str(row["id"]) + ".zip" for row in capture["artifacts"]}
    _require({p.name for p in archive_dir.iterdir()} == expected_paths, "ARCHIVE_INVENTORY")
    result = {}
    for row in capture["artifacts"]:
        result[row["name"]] = validate_archive(
            physical_bytes(archive_dir / f"{row['id']}.zip", limit=32 * 1024**2), row,
        )
    return result


def _write_new(path, data):
    path = Path(path)
    _require(not path.exists() and not path.is_symlink(), "OUTPUT")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def materialize(capture, archives, output, publisher_revision=None):
    """Materialize only the approved distribution and native receipt layout."""
    _require(isinstance(archives, dict) and set(archives) == set(_ARTIFACTS), "ARCHIVE_INVENTORY")
    output = Path(output).absolute()
    _require(not output.exists() and not output.is_symlink(), "OUTPUT")
    output.mkdir(mode=0o700)
    dist = output / "dist"
    receipts = output / "receipts"
    dist.mkdir(mode=0o700)
    receipts.mkdir(mode=0o700)
    pypi = archives["pypi-artifacts"]
    _require(set(pypi) == set(_ARTIFACTS["pypi-artifacts"]["members"]), "DIST_INVENTORY")
    for name, body in pypi.items():
        _write_new(dist / name, body)
    target_names = {row["target"] for row in _ARTIFACTS.values() if row["target"] is not None}
    for name, row in _ARTIFACTS.items():
        if row["target"] is None:
            continue
        members = archives[name]
        _require(set(members) == {"result.json"}, "RECEIPT_INVENTORY")
        target = row["target"]
        target_dir = receipts / target
        target_dir.mkdir(mode=0o700)
        _write_new(target_dir / "result.json", members["result.json"])
    _require({p.name for p in receipts.iterdir()} == target_names, "RECEIPT_INVENTORY")
    lineage = {
        "schema": "rs9.tf-pypi-publication-resume-lineage.v1",
        "project": PROJECT,
        "version": VERSION,
        "qualification_commit": capture["head"],
        "qualification_run_id": capture["run_id"],
        "qualification_run_attempt": capture["run_attempt"],
        "aggregate_set_sha256": capture["aggregate_set_sha256"],
        "publication_admitted": False,
    }
    if publisher_revision is not None:
        _require(_hex(publisher_revision, 40), "PUBLISHER_REVISION")
        lineage["publisher_revision"] = publisher_revision
    _write_new(output / "qualification-lineage.json", canonical(lineage))
    return {"dist": dist, "receipts": receipts, "lineage": lineage}


def prepare(capture_path, metadata_dir, archive_dir, output, publisher_root, publisher_revision):
    """Validate the captured inputs, current publisher checkout, and materialize them."""
    capture = load_capture(capture_path)
    validate_publisher(publisher_root, publisher_revision)
    validate_api_metadata(capture, metadata_dir)
    archives = validate_archives(capture, archive_dir)
    result = materialize(capture, archives, output, publisher_revision=publisher_revision)
    result["publisher_revision"] = publisher_revision
    return result


def stage_metadata(pin_path, approval_path, qualification_source, publisher_root, publisher_revision):
    """Copy only promoted pin/approval metadata into a fresh e35 checkout."""
    validate_publisher(publisher_root, publisher_revision)
    qualification_source = Path(qualification_source).absolute()
    _require(not qualification_source.is_symlink() and qualification_source.is_dir(), "QUALIFICATION_SOURCE")
    _require(_git_head(qualification_source) == QUALIFICATION_COMMIT, "QUALIFICATION_SOURCE")
    for relative, expected in QUALIFICATION_SOURCE_HASHES.items():
        _require(sha256(_git_blob(qualification_source, QUALIFICATION_COMMIT, relative)) == expected, "QUALIFICATION_SOURCE")
        _require(sha256(physical_bytes(qualification_source / relative)) == expected, "QUALIFICATION_SOURCE")
    pin_path = Path(pin_path)
    approval_path = Path(approval_path)
    _require(pin_path.name == f"{PROJECT}-{VERSION}.json", "PIN_PATH")
    _require(approval_path.name == f"{PROJECT}-{VERSION}-artifacts.json", "APPROVAL_PATH")
    pin = load_pin(PROJECT, pin_path)
    _require(pin.get("source_status") == "READY" and pin.get("qualified_platforms") == [
        "darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu",
    ], "PIN_NOT_READY")
    approval = strict_json(physical_bytes(approval_path, limit=1024 * 1024))
    _require(isinstance(approval, dict) and approval.get("schema") == "rs9.tf-pypi-candidate-aggregate.v1", "APPROVAL_SCHEMA")
    _require(approval.get("project") == PROJECT and approval.get("version") == VERSION, "APPROVAL_IDENTITY")
    _require(approval.get("publication_admitted") is True, "APPROVAL_NOT_ADMITTED")
    pin_destination = qualification_source / "operators/tf-pypi" / pin_path.name
    approval_destination = qualification_source / "operators/tf-pypi" / approval_path.name
    for destination in (pin_destination, approval_destination):
        _require(
            not any(parent.is_symlink() for parent in (destination, *destination.parents))
            and destination.parent.is_dir(),
            "QUALIFICATION_METADATA",
        )
    shutil.copyfile(pin_path, pin_destination)
    shutil.copyfile(approval_path, approval_destination)
    return {
        "qualification_commit": QUALIFICATION_COMMIT,
        "publisher_revision": publisher_revision,
        "pin": pin_destination.relative_to(qualification_source).as_posix(),
        "approval": approval_destination.relative_to(qualification_source).as_posix(),
        "pin_sha256": sha256(physical_bytes(pin_destination)),
        "approval_sha256": sha256(physical_bytes(approval_destination)),
    }


def workflow_text():
    """Render the attended Burst-only publication resume workflow."""
    artifact_ids = " ".join(str(_ARTIFACTS[name]["id"]) for name in _ARTIFACTS)
    return f"""name: RS9 {PROJECT} PyPI Publication Resume
run-name: 'RS9 {PROJECT} publication resume / ${{{{ inputs.dispatch_id }}}}'

on:
  workflow_dispatch:
    inputs:
      dispatch_id:
        description: 'Attended resume correlation; not publication authority'
        required: true
        type: string

permissions:
  contents: read
  actions: read

concurrency:
  group: rs9-tfsb-pypi-publication-resume-${{{{ github.ref }}}}
  cancel-in-progress: false

jobs:
  publish:
    if: github.ref == 'refs/heads/main'
    name: Attended Burst 0.7.0 PyPI publication resume
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    environment:
      name: pypi
      url: https://pypi.org/p/{PROJECT}
    permissions:
      id-token: write
      contents: read
      actions: read
    steps:
      - name: Checkout current publisher authority
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          fetch-depth: 0
          persist-credentials: false

      - name: Checkout original qualification source
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '{QUALIFICATION_COMMIT}'
          path: qualification-source
          persist-credentials: false

      - name: Set up Python 3.13
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'

      - name: Verify source lineage and original helper hashes
        env:
          PYTHONPATH: src
          PUBLISHER_REVISION: '${{{{ github.sha }}}}'
        run: |
          set -euo pipefail
          python3 -B -m rs9.tf_pypi_resume verify-source \\
            --publisher-root "$GITHUB_WORKSPACE" \\
            --publisher-revision "$PUBLISHER_REVISION" \\
            --qualification-source "$GITHUB_WORKSPACE/qualification-source"

      - name: Read exact first-attempt artifact metadata and archives
        env:
          GH_TOKEN: '${{{{ github.token }}}}'
        run: |
          set -euo pipefail
          mkdir -p remote-metadata archives
          gh api --header 'X-GitHub-Api-Version: 2022-11-28' \\
            "/repos/{REPOSITORY}/actions/runs/{QUALIFICATION_RUN_ID}" \\
            > "remote-metadata/run.json"
          gh api --header 'X-GitHub-Api-Version: 2022-11-28' \\
            "/repos/{REPOSITORY}/actions/runs/{QUALIFICATION_RUN_ID}/attempts/{QUALIFICATION_RUN_ATTEMPT}/jobs?per_page=100" \\
            > "remote-metadata/jobs.json"
          for artifact_id in {artifact_ids}; do
            gh api --header 'X-GitHub-Api-Version: 2022-11-28' \\
              "/repos/{REPOSITORY}/actions/artifacts/$artifact_id" \\
              > "remote-metadata/$artifact_id.json"
            gh api --header 'X-GitHub-Api-Version: 2022-11-28' \\
              "/repos/{REPOSITORY}/actions/artifacts/$artifact_id/zip" \\
              > "archives/$artifact_id.zip"
          done

      - name: Validate original archives and materialize the held candidate
        env:
          PYTHONPATH: src
          PUBLISHER_REVISION: '${{{{ github.sha }}}}'
        run: |
          set -euo pipefail
          python3 -B -m rs9.tf_pypi_resume prepare \\
            --capture operators/tf-pypi/{PROJECT}-0.7.0-qualification.json \\
            --metadata-dir remote-metadata --archive-dir archives --output resume \\
            --publisher-root "$GITHUB_WORKSPACE" \\
            --publisher-revision "$PUBLISHER_REVISION"

      - name: Stage promoted metadata into the original qualification checkout
        env:
          PYTHONPATH: src
          PUBLISHER_REVISION: '${{{{ github.sha }}}}'
        run: |
          set -euo pipefail
          python3 -B -m rs9.tf_pypi_resume stage-metadata \\
            --pin operators/tf-pypi/{PROJECT}-0.7.0.json \\
            --approval operators/tf-pypi/{PROJECT}-0.7.0-artifacts.json \\
            --qualification-source qualification-source \\
            --publisher-root "$GITHUB_WORKSPACE" \\
            --publisher-revision "$PUBLISHER_REVISION"

      - name: Verify approved candidate and select only missing files
        id: missing
        env:
          PYTHONPATH: src
          QUALIFY_COMMIT: '{QUALIFICATION_COMMIT}'
          QUALIFY_RUN_ID: '{QUALIFICATION_RUN_ID}'
          QUALIFY_RUN_ATTEMPT: '{QUALIFICATION_RUN_ATTEMPT}'
        run: |
          set -euo pipefail
          python3 -B -m rs9.tf_pypi_publish select-missing \\
            --project {PROJECT} \\
            --pin operators/tf-pypi/{PROJECT}-0.7.0.json \\
            --dist "$GITHUB_WORKSPACE/resume/dist" \\
            --upload-dir "$GITHUB_WORKSPACE/resume/upload" \\
            --receipts "$GITHUB_WORKSPACE/resume/receipts" \\
            --expected-commit "$QUALIFY_COMMIT" \\
            --run-id "$QUALIFY_RUN_ID" \\
            --run-attempt "$QUALIFY_RUN_ATTEMPT" >> "$GITHUB_OUTPUT"
        working-directory: qualification-source

      - name: Publish package distributions to PyPI
        if: steps.missing.outputs.upload == 'true'
        uses: pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e
        with:
          packages-dir: resume/upload/

      - name: Read back exact PyPI state
        env:
          PYTHONPATH: src
        run: |
          set -euo pipefail
          python3 -B -m rs9.tf_pypi_publish readback \\
            --project {PROJECT} \\
            --pin operators/tf-pypi/{PROJECT}-0.7.0.json \\
            --dist "$GITHUB_WORKSPACE/resume/dist"
        working-directory: qualification-source
"""


def resume_job_text():
    """Render the Burst resume job for the registered publisher workflow."""
    marker = "jobs:\n  publish:\n"
    standalone = workflow_text()
    if marker not in standalone:
        fail("RESUME_WORKFLOW")
    _, body = standalone.split(marker, 1)
    body = "  publication_resume:\n" + body
    old_if = "    if: github.ref == 'refs/heads/main'\n"
    new_if = (
        "    if: github.ref == 'refs/heads/main' && "
        "github.event_name == 'workflow_dispatch' && inputs.mode == 'resume'\n"
    )
    if old_if not in body:
        fail("RESUME_WORKFLOW")
    return body.replace(old_if, new_if, 1).rstrip()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="operation", required=True)
    source = sub.add_parser("verify-source")
    source.add_argument("--publisher-root", type=Path, required=True)
    source.add_argument("--publisher-revision", required=True)
    source.add_argument("--qualification-source", type=Path, required=True)
    prepare_cmd = sub.add_parser("prepare")
    prepare_cmd.add_argument("--capture", type=Path, required=True)
    prepare_cmd.add_argument("--metadata-dir", type=Path, required=True)
    prepare_cmd.add_argument("--archive-dir", type=Path, required=True)
    prepare_cmd.add_argument("--output", type=Path, required=True)
    prepare_cmd.add_argument("--publisher-root", type=Path, required=True)
    prepare_cmd.add_argument("--publisher-revision", required=True)
    stage = sub.add_parser("stage-metadata")
    stage.add_argument("--pin", type=Path, required=True)
    stage.add_argument("--approval", type=Path, required=True)
    stage.add_argument("--qualification-source", type=Path, required=True)
    stage.add_argument("--publisher-root", type=Path, required=True)
    stage.add_argument("--publisher-revision", required=True)
    sub.add_parser("workflow")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.operation == "verify-source":
            validate_publisher(args.publisher_root, args.publisher_revision)
            qualification_source = Path(args.qualification_source)
            _require(_git_head(qualification_source) == QUALIFICATION_COMMIT, "QUALIFICATION_SOURCE")
            for relative, expected in QUALIFICATION_SOURCE_HASHES.items():
                _require(sha256(_git_blob(qualification_source, QUALIFICATION_COMMIT, relative)) == expected, "QUALIFICATION_SOURCE")
                _require(sha256(physical_bytes(qualification_source / relative)) == expected, "QUALIFICATION_SOURCE")
            return 0
        if args.operation == "prepare":
            result = prepare(args.capture, args.metadata_dir, args.archive_dir, args.output, args.publisher_root, args.publisher_revision)
            print(json.dumps({"status": "prepared", "publisher_revision": result["publisher_revision"], "qualification_commit": QUALIFICATION_COMMIT}, sort_keys=True))
            return 0
        if args.operation == "stage-metadata":
            result = stage_metadata(args.pin, args.approval, args.qualification_source, args.publisher_root, args.publisher_revision)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.operation == "workflow":
            print(workflow_text(), end="")
            return 0
        return 1
    except AdmissionError as error:
        print(error.code, file=sys.stderr)
        return 1
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        print("TF_PYPI_RESUME_OPERATION_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
