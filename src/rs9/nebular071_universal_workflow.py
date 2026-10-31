"""Universal-mode jobs derived from the approved native runner definitions.

Only the distribution inputs and their admission commands change. Runner
images, native package classes, permissions, actions and limits stay owned by
the existing 0.7.1 workflow definitions.
"""
from __future__ import annotations

import re
import textwrap

from rs9 import tf_pypi_nebular071_publish as legacy
from rs9 import nebular071_universal_profile as profile


QUALIFY_MODE = profile.QUALIFY_MODE
PUBLISH_MODE = profile.PUBLISH_MODE
PREFIX = "tfnf-071-universal-"
JOB_IDS = (
    "prepare_public_inputs_071", "build_verify_071",
    "native_consumer_071_darwin_arm64", "native_consumer_071_linux_arm64_gnu",
    "native_consumer_071_linux_x64_gnu", "native_consumer_071_linux_arm64_gnu_floor",
    "native_consumer_071_linux_x64_gnu_floor", "qualification_gate_071",
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


def _replace_exact(text: str, old: str, new: str, *, count: int = 1) -> str:
    if text.count(old) != count:
        raise ValueError("Reviewed workflow text changed or is ambiguous")
    return text.replace(old, new, count)


def _shell_step(name: str, script: str, *, extra_env: dict[str, str] | None = None) -> str:
    env_lines = [
        "          PYTHONPATH: src\n",
        "          PYTHONDONTWRITEBYTECODE: '1'\n",
    ]
    for key, value in (extra_env or {}).items():
        env_lines.append(f"          {key}: {value}\n")
    return (
        "      - name: " + name + "\n"
        "        env:\n" + "".join(env_lines)
        + "        run: |\n"
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
    job = _replace_exact(
        job,
        "rs9.tf_pypi_nebular071_publish qualify-native",
        "rs9.tf_pypi_nebular071_universal qualify-native",
        count=1,
    )
    if "rs9.tf_pypi_nebular071_publish check-system-webkit-missing" in job:
        job = _replace_exact(
            job,
            "rs9.tf_pypi_nebular071_publish check-system-webkit-missing",
            "rs9.tf_pypi_nebular071_universal check-system-webkit-missing",
            count=1,
        )
    if "QUALIFICATION_INPUTS:" in job:
        job = _replace_exact(
            job,
            "          )\n\n          descriptor = load_qualification_inputs_descriptor(\n",
            "          )\n"
            "          from rs9.nebular071_product_capture import load_held_product_capture\n"
            '          product_capture = load_held_product_capture(Path(os.environ["INRUN_ROOT"]))\n\n'
            "          descriptor = load_qualification_inputs_descriptor(\n",
            count=1,
        )
        job = _replace_exact(
            job,
            '              inrun_root=Path(os.environ["INRUN_ROOT"]),\n',
            '              inrun_root=Path(os.environ["INRUN_ROOT"]),\n'
            "              product_capture=product_capture,\n",
            count=1,
        )
    lines = [line for line in job.splitlines()
             if not line.lstrip().startswith("--consumer-capture-output ")]
    for index, line in enumerate(lines[:-1]):
        if line.endswith("\\") and not lines[index + 1].strip():
            lines[index] = line[:-1].rstrip()
    return "\n".join(lines) + "\n\n"


def qualify_jobs_text() -> str:
    original = _split_jobs(legacy.workflow_071_qualify_jobs_text())
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
        job = job.replace("tfnf-071-", PREFIX)
        job = job.replace("    name: Native consumer 0.7.1", "    name: Universal installed consumer 0.7.1")
        if job_id == "prepare_public_inputs_071":
            job = job.replace("    name: " + legacy.PREPARE_PUBLIC_INPUTS_071_JOB_NAME,
                              "    name: Prepare Nebular 0.7.1 universal launcher inputs")
            job = _replace_step(job, "Prepare held 0.7.1 public inputs", _shell_step(
                "Prepare held Nebular 0.7.1 system-WebKit inputs", r'''
                set -euo pipefail
                "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.tf_pypi_nebular071_publish prepare-public-inputs-071 \
                  --manifest operators/tf-pypi/theme-forge-nebular-fusion-0.7.1-public-inputs.json \
                  --output "${{ runner.temp }}/tfnf-071-universal-public-inputs" \
                  --repository "$GITHUB_WORKSPACE" \
                  --stage-a-spec stage-a-files.json \
                  --rs9-commit "${{ github.sha }}" \
                  --rs9-tree "$(git rev-parse --verify 'HEAD^{tree}')"
                ''', extra_env={"RS9_GITHUB_READ_TOKEN": "${{ github.token }}"}))
        elif job_id == "build_verify_071":
            job = job.replace("    name: " + legacy.BUILD_VERIFY_071_JOB_NAME,
                              "    name: Build and Verify Nebular 0.7.1 Universal Launcher")
            job = _replace_step(job, "Validate explicit 0.7.1 runtime profile", "")
            job = _replace_step(job, "Build and verify 0.7.1 candidate bundle", _shell_step(
                "Build and verify one universal launcher wheel", r'''
                set -euo pipefail
                "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.tf_pypi_nebular071_universal build-bundle \
                  --qualification-inputs "${{ runner.temp }}/tfnf-071-universal-public-inputs/qualification-inputs-prep.json" \
                  --inrun-root "${{ runner.temp }}/tfnf-071-universal-public-inputs" \
                  --output "${{ runner.temp }}/tfnf-071-universal-bundle" \
                  --expected-commit "${{ github.sha }}" \
                  --require-clean
                '''))
        elif job_id.startswith("native_consumer_"):
            job = _native_job(job)
        elif job_id == "qualification_gate_071":
            job = job.replace("    name: " + legacy.QUALIFICATION_GATE_071_JOB_NAME,
                              "    name: Universal installed qualification matrix 0.7.1")
            job = _replace_step(job, "Admit complete 3-platform 0.7.1 qualification matrix", _shell_step(
                "Validate all five universal installed consumer lanes", r'''
                set -euo pipefail
                "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.tf_pypi_nebular071_universal admit-matrix \
                  --bundle "${{ runner.temp }}/tfnf-071-universal-bundle" \
                  --qualification-inputs "${{ runner.temp }}/tfnf-071-universal-public-inputs/qualification-inputs-prep.json" \
                  --inrun-root "${{ runner.temp }}/tfnf-071-universal-public-inputs" \
                  --receipts-dir "${{ runner.temp }}/tfnf-071-universal-receipts" \
                  --floor-receipts "${{ runner.temp }}/tfnf-071-universal-floor-receipts" \
                  --work "${{ runner.temp }}/tfnf-071-universal-matrix-work" \
                  --output "${{ runner.temp }}/tfnf-071-universal-matrix/matrix_receipt.json" \
                  --expected-commit "${{ github.sha }}" \
                  --run-id "${{ github.run_id }}" \
                  --run-attempt "${{ github.run_attempt }}"
                '''))
            for name in (
                "Validate explicit 0.7.1 runtime profile for matrix", "Verify floor consumer receipts",
                "Assemble authenticated 0.7.1 Stage-B admission input",
                "Verify system-WebKit matrix has no manylinux admission",
                "Upload 0.7.1 manylinux admission input",
            ):
                job = _replace_step(job, name, "")
        jobs.append(job.rstrip() + "\n")
    return "\n" + "\n".join(jobs) + dispatch_guard_text()


def _rendered_jobs(document: str) -> dict[str, str]:
    """Return jobs from a complete document without trusting API-supplied YAML."""
    marker = "\njobs:\n"
    if document.count(marker) != 1:
        raise ValueError("Workflow jobs section changed or is ambiguous")
    return _split_jobs(document.partition(marker)[2])


def rendered_qualification_job_ids(document: str) -> tuple[str, ...]:
    """Derive the universal qualification set from the rendered workflow."""
    jobs = _rendered_jobs(document)
    result = tuple(sorted(
        job_id for job_id in jobs
        if job_id.startswith("universal_") and job_id != "universal_publication_071"
    ))
    if not result or any(not job_id.startswith("universal_") for job_id in result):
        raise ValueError("Rendered 071 qualification jobs are incomplete")
    return result


def complete_workflow_text() -> str:
    """Compose the registered workflow from legacy jobs and the isolated 071 route."""
    from rs9 import tf_pypi_nebular as historical

    document = historical.workflow_text()
    jobs = _rendered_jobs(document)
    retained = [job_id for job_id in jobs if not (
        job_id.startswith("universal_") or job_id == "reject_unsupported_dispatch"
    )]
    if set(retained) != {"build_verify", "native_consumer", "publish"}:
        raise ValueError("Historical workflow job boundary changed")
    header = document.partition("\njobs:\n")[0]
    historical_version = ".".join(("0", "7", "0"))
    header = header.replace("- " + historical_version, "- 0.7.1")
    header = header.replace("universal-qualify", QUALIFY_MODE)
    header = header.replace("universal-publish", PUBLISH_MODE)
    body = "\n".join(jobs[job_id].rstrip() for job_id in retained)
    result = header + "\njobs:\n" + body + qualify_jobs_text() + publication_job_text()
    if (historical_version in result
            or "universal-qualify-071" in result
            or "universal-publish-071" in result):
        raise ValueError("071 workflow retained a historical universal coordinate")
    if len(_rendered_jobs(result)) != 13:
        raise ValueError("071 workflow did not retain the approved legacy/071 job set")
    return result


def validate_workflow_dispatch(release: str, mode: str) -> dict:
    if release not in {"0.6.1", "0.7.1"}:
        legacy.fail("WORKFLOW_RELEASE")
    if (release, mode) not in {
        ("0.6.1", "qualify"), ("0.6.1", "publish"),
        ("0.7.1", QUALIFY_MODE), ("0.7.1", PUBLISH_MODE),
    }:
        legacy.fail("WORKFLOW_MODE_UNSUPPORTED")
    return {"release": release, "mode": mode}


def dispatch_guard_text() -> str:
    return r'''
  reject_unsupported_dispatch:
    if: github.event_name == 'workflow_dispatch' && !((inputs.release == '0.6.1' && (inputs.mode == 'qualify' || inputs.mode == 'publish')) || (inputs.release == '0.7.1' && (inputs.mode == '__071_QUALIFY_MODE__' || inputs.mode == '__071_PUBLISH_MODE__')))
    name: Reject unsupported release and mode combination
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      contents: read
    steps:
      - name: Reject unsupported distribution route
        run: exit 1
'''.replace("__071_QUALIFY_MODE__", QUALIFY_MODE).replace("__071_PUBLISH_MODE__", PUBLISH_MODE)


def publication_job_text() -> str:
    """Use the registered trusted-publisher identity and existing OIDC action."""
    return r'''
  universal_publication_071:
    if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.1' && inputs.mode == '__071_PUBLISH_MODE__'
    name: Attended Nebular 0.7.1 universal PyPI publication
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
          path = Path("publisher-authority/operators/tf-pypi/nebular-fusion-0.7.1-universal-publication.json")
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
              if (value["schema"] != "rs9.nebular071-universal-publication.v1"
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
          from rs9.nebular071_universal_publication import load_authority
          authority = load_authority(Path("publisher-authority"))
          root = Path(os.environ["RUNNER_TEMP"]) / "tfnf-071-universal-custody"
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
          "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.nebular071_universal_publication select-missing \
            --publisher-dir publisher-authority --qualification-dir qualification-source \
            --api-dir "${{ runner.temp }}/tfnf-071-universal-custody/api" \
            --archives-dir "${{ runner.temp }}/tfnf-071-universal-custody/archives" \
            --work "${{ runner.temp }}/tfnf-071-universal-publication" \
            --upload-dir "${{ github.workspace }}/tfnf-071-universal-upload" \
            --attempt-marker "${{ runner.temp }}/tfnf-071-universal-upload-attempt.json" \
            --publisher-revision "${{ github.sha }}" >> "$GITHUB_OUTPUT"

      - name: Reverify universal upload bytes and admission
        if: steps.missing.outputs.upload == 'true'
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{ github.token }}
          RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED: ${{ vars.RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED }}
        run: |
          "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.nebular071_universal_publication verify-upload \
            --publisher-dir publisher-authority --qualification-dir qualification-source \
            --api-dir "${{ runner.temp }}/tfnf-071-universal-custody/api" \
            --archives-dir "${{ runner.temp }}/tfnf-071-universal-custody/archives" \
            --work "${{ runner.temp }}/tfnf-071-universal-publication" \
            --upload-dir "${{ github.workspace }}/tfnf-071-universal-upload" \
            --attempt-marker "${{ runner.temp }}/tfnf-071-universal-upload-attempt.json" \
            --publisher-revision "${{ github.sha }}"

      - name: Publish universal launcher distribution to PyPI
        if: steps.missing.outputs.upload == 'true'
        uses: pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e
        with:
          packages-dir: tfnf-071-universal-upload/
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
          "${{ steps.setup_python.outputs.python-path }}" -B -m rs9.nebular071_universal_publication readback \
            --publisher-dir publisher-authority --qualification-dir qualification-source \
            --api-dir "${{ runner.temp }}/tfnf-071-universal-custody/api" \
            --archives-dir "${{ runner.temp }}/tfnf-071-universal-custody/archives" \
            --work "${{ runner.temp }}/tfnf-071-universal-publication" \
            --publisher-revision "${{ github.sha }}"
'''.replace("__071_PUBLISH_MODE__", PUBLISH_MODE)
