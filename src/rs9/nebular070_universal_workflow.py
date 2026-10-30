"""Universal-mode jobs derived from the approved native runner definitions.

Only the distribution inputs and their admission commands change. Runner
images, native package classes, permissions, actions and limits stay owned by
the existing 0.7.0 workflow definitions.
"""
from __future__ import annotations

import re
import textwrap

from rs9 import tf_pypi_nebular070_publish as legacy


QUALIFY_MODE = "universal-qualify"
PUBLISH_MODE = "universal-publish"
PREFIX = "tfnf-070-universal-"
JOB_IDS = (
    "prepare_public_inputs_070", "build_verify_070",
    "native_consumer_070_darwin_arm64", "native_consumer_070_linux_arm64_gnu",
    "native_consumer_070_linux_x64_gnu", "native_consumer_070_linux_arm64_gnu_floor",
    "native_consumer_070_linux_x64_gnu_floor", "qualification_gate_070",
)


def _split_jobs(text: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?m)^  ([a-z][a-z0-9_]*):[ ]*$", text))
    result = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        if match[1] in result:
            raise ValueError("Duplicate workflow job")
        result[match[1]] = text[match.start():end]
    return result


def _replace_step(job: str, name: str, replacement: str) -> str:
    pattern = r"(?ms)^      - name: " + re.escape(name) + r"\n.*?(?=^      - name: |\Z)"
    result, count = re.subn(pattern, lambda _match: replacement, job)
    if count != 1:
        raise ValueError("Reviewed workflow step changed or is ambiguous")
    return result


def _shell_step(name: str, script: str) -> str:
    return (
        "      - name: " + name + "\n"
        "        env:\n          PYTHONPATH: src\n          PYTHONDONTWRITEBYTECODE: '1'\n"
        "        run: |\n"
        + textwrap.indent(textwrap.dedent(script).strip() + "\n", "          ") + "\n"
    )


def _system_profile(job: str) -> str:
    pattern = r'(?m)^([ ]*)if "system_webkit" in descriptor:$'
    def require(match):
        indent = match[1]
        return (indent + 'if "system_webkit" not in descriptor or "manylinux" in descriptor:\n'
                + indent + '    raise SystemExit("universal launcher requires system WebKit inputs")\n'
                + match[0])
    result, count = re.subn(pattern, require, job)
    if count != 1:
        raise ValueError("Reviewed runtime selector changed or is ambiguous")
    return result


def _native_job(job: str) -> str:
    job = _system_profile(job) if "linux_runtime_profile" in job else job
    job = job.replace("rs9.tf_pypi_nebular070_publish qualify-native",
                      "rs9.tf_pypi_nebular070_universal qualify-native")
    job = job.replace("rs9.tf_pypi_nebular070_publish check-system-webkit-missing",
                      "rs9.tf_pypi_nebular070_universal check-system-webkit-missing")
    lines = [line for line in job.splitlines()
             if not line.lstrip().startswith("--consumer-capture-output ")]
    for index, line in enumerate(lines[:-1]):
        if line.endswith("\\") and not lines[index + 1].strip():
            lines[index] = line[:-1].rstrip()
    return "\n".join(lines) + "\n\n"


def qualify_jobs_text() -> str:
    original = _split_jobs(legacy.workflow_070_qualify_jobs_text())
    jobs = []
    for job_id in JOB_IDS:
        job = original[job_id]
        old = "inputs.mode == 'qualify'"
        if job.count(old) != 1:
            raise ValueError("Reviewed qualification condition changed")
        job = job.replace(old, "inputs.mode == '" + QUALIFY_MODE + "'")
        job, count = re.subn(
            r"\(github.ref == 'refs/heads/main' \|\| github.ref == 'refs/heads/[^']+'\)",
            "github.ref == 'refs/heads/main'", job)
        if count != 1:
            raise ValueError("Reviewed qualification ref condition changed")
        for old_id in JOB_IDS:
            job = re.sub(r"\b" + re.escape(old_id) + r"\b", "universal_" + old_id, job)
        job = job.replace("tfnf-070-", PREFIX)
        job = job.replace("    name: Native consumer 0.7.0", "    name: Universal installed consumer 0.7.0")
        if job_id == "prepare_public_inputs_070":
            job = job.replace("    name: " + legacy.PREPARE_PUBLIC_INPUTS_070_JOB_NAME,
                              "    name: Prepare Nebular 0.7.0 universal launcher inputs")
        elif job_id == "build_verify_070":
            job = job.replace("    name: " + legacy.BUILD_VERIFY_070_JOB_NAME,
                              "    name: Build and Verify Nebular 0.7.0 Universal Launcher")
            job = _replace_step(job, "Validate explicit 0.7.0 runtime profile", "")
            job = _replace_step(job, "Build and verify 0.7.0 candidate bundle", _shell_step(
                "Build and verify one universal launcher wheel", r'''
                set -euo pipefail
                "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.tf_pypi_nebular070_universal build-bundle \
                  --qualification-inputs "${{ runner.temp }}/tfnf-070-universal-public-inputs/qualification-inputs-prep.json" \
                  --inrun-root "${{ runner.temp }}/tfnf-070-universal-public-inputs" \
                  --output "${{ runner.temp }}/tfnf-070-universal-bundle" \
                  --expected-commit "${{ github.sha }}" \
                  --require-clean
                '''))
        elif job_id.startswith("native_consumer_"):
            job = _native_job(job)
        elif job_id == "qualification_gate_070":
            job = job.replace("    name: " + legacy.QUALIFICATION_GATE_070_JOB_NAME,
                              "    name: Universal installed qualification matrix 0.7.0")
            job = _replace_step(job, "Admit complete 3-platform 0.7.0 qualification matrix", _shell_step(
                "Validate all five universal installed consumer lanes", r'''
                set -euo pipefail
                "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.tf_pypi_nebular070_universal admit-matrix \
                  --bundle "${{ runner.temp }}/tfnf-070-universal-bundle" \
                  --qualification-inputs "${{ runner.temp }}/tfnf-070-universal-public-inputs/qualification-inputs-prep.json" \
                  --inrun-root "${{ runner.temp }}/tfnf-070-universal-public-inputs" \
                  --receipts-dir "${{ runner.temp }}/tfnf-070-universal-receipts" \
                  --floor-receipts "${{ runner.temp }}/tfnf-070-universal-floor-receipts" \
                  --work "${{ runner.temp }}/tfnf-070-universal-matrix-work" \
                  --output "${{ runner.temp }}/tfnf-070-universal-matrix/matrix_receipt.json" \
                  --expected-commit "${{ github.sha }}" \
                  --run-id "${{ github.run_id }}" \
                  --run-attempt "${{ github.run_attempt }}"
                '''))
            for name in (
                "Validate explicit 0.7.0 runtime profile for matrix", "Verify floor consumer receipts",
                "Assemble authenticated 0.7.0 Stage-B admission input",
                "Verify system-WebKit matrix has no manylinux admission",
                "Upload 0.7.0 manylinux admission input",
            ):
                job = _replace_step(job, name, "")
        jobs.append(job.rstrip() + "\n")
    return "\n" + "\n".join(jobs) + dispatch_guard_text()


def validate_workflow_dispatch(release: str, mode: str) -> dict:
    if release not in {"0.6.1", "0.7.0"}:
        legacy.fail("WORKFLOW_RELEASE")
    if (release, mode) not in {("0.6.1", "qualify"), ("0.6.1", "publish"),
                              ("0.7.0", QUALIFY_MODE), ("0.7.0", PUBLISH_MODE)}:
        legacy.fail("WORKFLOW_MODE_UNSUPPORTED")
    return {"release": release, "mode": mode}


def dispatch_guard_text() -> str:
    return r'''
  reject_unsupported_dispatch:
    if: github.event_name == 'workflow_dispatch' && !((inputs.release == '0.6.1' && (inputs.mode == 'qualify' || inputs.mode == 'publish')) || (inputs.release == '0.7.0' && (inputs.mode == 'universal-qualify' || inputs.mode == 'universal-publish')))
    name: Reject unsupported release and mode combination
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      contents: read
    steps:
      - name: Reject unsupported distribution route
        run: exit 1
'''


def publication_job_text() -> str:
    """Use the registered trusted-publisher identity and existing OIDC action."""
    return r'''
  universal_publication_070:
    if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'universal-publish'
    name: Attended Nebular 0.7.0 universal PyPI publication
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    concurrency:
      group: rs9-tfnf-pypi-publish-main
      cancel-in-progress: false
    environment:
      name: pypi
      url: https://pypi.org/p/theme-forge-nebular-fusion
    permissions:
      id-token: write
      contents: read
      actions: read
    steps:
      - name: Checkout publisher authority commit
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{ github.sha }}'
          path: publisher-authority
          fetch-depth: 0
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'

      - name: Resolve pinned universal qualification commit
        id: resolve_qual
        run: |
          "${{ steps.setup_python.outputs.python-path }}" -I -B - <<'PY' >> "$GITHUB_OUTPUT"
          import json, os, re, stat
          from pathlib import Path
          def unique(pairs):
              value = {}
              for key, item in pairs:
                  if key in value:
                      raise ValueError
                  value[key] = item
              return value
          def frame(info):
              return (info.st_dev, info.st_ino, info.st_size, info.st_mode,
                      info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink)
          path = Path("publisher-authority/operators/tf-pypi/nebular-fusion-0.7.0-universal-publication.json")
          try:
              for parent in path.parents:
                  if not stat.S_ISDIR(parent.lstat().st_mode):
                      raise ValueError
              fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
              with os.fdopen(fd, "rb") as stream:
                  before = os.fstat(stream.fileno())
                  if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 * 1024:
                      raise ValueError
                  raw = stream.read(1024 * 1024 + 1)
                  if (len(raw) != before.st_size or frame(before) != frame(os.fstat(stream.fileno()))
                          or frame(before) != frame(path.lstat())):
                      raise ValueError
              value = json.loads(raw, object_pairs_hook=unique)
              source, run = value["source"], value["run"]
              if (value["schema"] != "rs9.nebular070-universal-publication.v1"
                      or value["repository"] != "Knowledge-Forge-AI/release-starport-9"
                      or value["workflow"] != "rs9-tfnf-pypi-publish.yml"
                      or not isinstance(source, dict) or set(source) != {"commit", "tree"}
                      or any(type(item) is not str or not re.fullmatch(r"[0-9a-f]{40}", item) for item in source.values())
                      or not isinstance(run, dict) or set(run) != {"id", "attempt"}
                      or type(run["id"]) is not str or not re.fullmatch(r"[1-9][0-9]{0,19}", run["id"])
                      or run["attempt"] != "1"):
                  raise ValueError
          except (OSError, ValueError, TypeError, KeyError):
              raise SystemExit("NEBULAR_UNIVERSAL_AUTHORITY_COORDINATES")
          print("qualification_commit=" + source["commit"])
          print("qualification_run_id=" + run["id"])
          PY

      - name: Checkout exact qualified source commit
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{ steps.resolve_qual.outputs.qualification_commit }}'
          path: qualification-source
          persist-credentials: false

      - name: Fetch exact universal qualification custody
        env:
          GH_TOKEN: ${{ github.token }}
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{ steps.setup_python.outputs.python-path }}" -B - <<'PY'
          import os, subprocess
          from pathlib import Path
          from rs9.nebular070_universal_publication import load_authority
          authority = load_authority(Path("publisher-authority"))
          root = Path(os.environ["RUNNER_TEMP"]) / "tfnf-070-universal-custody"
          api, archives = root / "api", root / "archives"
          api.mkdir(parents=True, mode=0o700)
          archives.mkdir(mode=0o700)
          repo, run = authority["repository"], authority["run"]["id"]
          def fetch(path, endpoint):
              with path.open("xb") as stream:
                  subprocess.run(["gh", "api", "--header", "X-GitHub-Api-Version: 2022-11-28", endpoint],
                                 stdin=subprocess.DEVNULL, stdout=stream, check=True, timeout=300)
          fetch(api / "run.json", f"/repos/{repo}/actions/runs/{run}")
          fetch(api / "artifacts.json", f"/repos/{repo}/actions/runs/{run}/artifacts?per_page=100")
          fetch(api / "jobs.json", f"/repos/{repo}/actions/runs/{run}/jobs?filter=all&per_page=100")
          for name, spec in authority["artifacts"].items():
              fetch(archives / (name + ".zip"), f"/repos/{repo}/actions/artifacts/{spec['id']}/zip")
          PY

      - name: Admit one wheel and select only an absent distribution
        id: missing
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{ github.token }}
          RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED: ${{ vars.RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED }}
        run: |
          "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.nebular070_universal_publication select-missing \
            --publisher-dir publisher-authority --qualification-dir qualification-source \
            --api-dir "${{ runner.temp }}/tfnf-070-universal-custody/api" \
            --archives-dir "${{ runner.temp }}/tfnf-070-universal-custody/archives" \
            --work "${{ runner.temp }}/tfnf-070-universal-publication" \
            --upload-dir "${{ github.workspace }}/tfnf-070-universal-upload" \
            --attempt-marker "${{ runner.temp }}/tfnf-070-universal-upload-attempt.json" \
            --publisher-revision "${{ github.sha }}" >> "$GITHUB_OUTPUT"

      - name: Reverify universal upload bytes and admission
        if: steps.missing.outputs.upload == 'true'
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{ github.token }}
          RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED: ${{ vars.RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED }}
        run: |
          "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.nebular070_universal_publication verify-upload \
            --publisher-dir publisher-authority --qualification-dir qualification-source \
            --api-dir "${{ runner.temp }}/tfnf-070-universal-custody/api" \
            --archives-dir "${{ runner.temp }}/tfnf-070-universal-custody/archives" \
            --work "${{ runner.temp }}/tfnf-070-universal-publication" \
            --upload-dir "${{ github.workspace }}/tfnf-070-universal-upload" \
            --attempt-marker "${{ runner.temp }}/tfnf-070-universal-upload-attempt.json" \
            --publisher-revision "${{ github.sha }}"

      - name: Publish universal launcher distribution to PyPI
        if: steps.missing.outputs.upload == 'true'
        uses: pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e
        with:
          packages-dir: tfnf-070-universal-upload/
          verify-metadata: true
          print-hash: true
          skip-existing: false
          attestations: false

      - name: Read back exact universal PyPI bytes and metadata
        if: always() && (steps.missing.outputs.upload == 'true' || steps.missing.outputs.state == 'published-exact')
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.nebular070_universal_publication readback \
            --publisher-dir publisher-authority --qualification-dir qualification-source \
            --api-dir "${{ runner.temp }}/tfnf-070-universal-custody/api" \
            --archives-dir "${{ runner.temp }}/tfnf-070-universal-custody/archives" \
            --work "${{ runner.temp }}/tfnf-070-universal-publication" \
            --publisher-revision "${{ github.sha }}"
'''
