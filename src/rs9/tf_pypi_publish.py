"""Source-owned future publication contract for Theme Forge PyPI adapters.

Parent will materialize workflows only for READY products.
The CLI verifies approved files and prepares upload directories; GitHub alone owns uploads.
Only the explicit future build command may download pinned source inputs.
"""
import argparse
import io
from pathlib import Path
import shutil
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes
from rs9.tf_pypi_backend import build_aggregate
from rs9.tf_pypi_closure import DEPENDENCIES, admit_dependency, load_dependencies
from rs9.tf_pypi_hosted import admit_matrix
from rs9.tf_pypi_intake import NoRedirect, download
from rs9.tf_pypi_model import PRODUCTS, intake, load_pin, strict_json, validate_pin
from rs9.tf_pypi_remote import PublicReader, exact_state
from rs9.tf_pypi_verify import verify_aggregate


def dependency_url(dep_pin):
    """Return the exact pinned npm registry tarball URL."""
    name, asset = dep_pin["name"], dep_pin["asset"]
    return f"https://registry.npmjs.org/{name}/-/{asset}"


def fetch_dependency(dep_pin, *, opener=None):
    """Fetch and admit an exact pinned dependency tarball without npm."""
    opener = opener or build_opener(ProxyHandler({}), NoRedirect())
    if not isinstance(dep_pin, dict):
        fail("DEPENDENCY_URL")
    name = dep_pin.get("name")
    asset = dep_pin.get("asset")
    if not isinstance(name, str) or not isinstance(asset, str):
        fail("DEPENDENCY_URL")
    if "/" in asset or not asset.endswith(".tgz") or any(p in ("", ".", "..") for p in asset.split("/")):
        fail("DEPENDENCY_URL")
    if any(p in ("", ".", "..") for p in name.split("/")):
        fail("DEPENDENCY_URL")
    url = dependency_url(dep_pin)
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org"
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.query or parsed.fragment or any(p in (".", "..") for p in parsed.path.split("/"))):
        fail("DEPENDENCY_URL")
    try:
        with opener.open(Request(url, headers={"User-Agent": "RS9-TF-PyPI/1"}), timeout=30) as response:
            if response.status != 200 or response.geturl() != url:
                fail("REMOTE_UNKNOWN")
            body = response.read(dep_pin["size"] + 1)
            admit_dependency(dep_pin, body)
            return body
    except AdmissionError:
        raise
    except HTTPError as error:
        code, actual = error.code, error.geturl()
        error.close()
        if code == 404 and actual == url:
            fail("ASSET_ABSENT")
        fail("REMOTE_UNKNOWN")
    except (URLError, OSError, ValueError):
        fail("REMOTE_UNKNOWN")


def fetch_dependencies(directory=None, *, opener=None):
    """Fetch all pinned dependencies verified via closure DEPENDENCIES."""
    result = {}
    for dep in DEPENDENCIES:
        body = fetch_dependency(dep, opener=opener)
        result[dep["asset"]] = body
        if directory is not None:
            dir_path = Path(directory)
            dir_path.mkdir(parents=True, exist_ok=True)
            with (dir_path / dep["asset"]).open("xb") as stream:
                stream.write(body)
    return result


def approval_path(pin):
    """Return the path to the operator-approved artifacts manifest."""
    if isinstance(pin, str):
        pin = load_pin(pin)
    else:
        validate_pin(pin)
    root = Path(__file__).resolve().parents[2]
    return root / "operators/tf-pypi" / f"{pin['project']}-{pin['distribution_version']}-artifacts.json"


def load_approval(pin):
    """Load the approved candidate artifacts manifest."""
    if isinstance(pin, str):
        pin = load_pin(pin)
    else:
        validate_pin(pin)
    path = approval_path(pin)
    if not path.is_file():
        fail("APPROVAL_ABSENT")
    data = physical_bytes(path)
    return strict_json(data)


def verify_approved(pin, dist):
    """Verify local dist directory exactly matches the committed approved aggregate."""
    if isinstance(pin, str):
        pin = load_pin(pin)
    else:
        validate_pin(pin)
    if pin.get("source_status") != "READY":
        fail("SOURCE_NOT_READY")
    approved = load_approval(pin)
    actual = verify_aggregate(pin, dist)
    if actual != approved and {**actual, "publication_admitted": True} != approved:
        fail("APPROVAL_MISMATCH")
    return approved


def build(pin, output=Path("dist"), inputs=None, opener=None):
    """Build candidate distribution aggregate with deterministic cross-target builder."""
    if isinstance(pin, str):
        pin = load_pin(pin)
    else:
        validate_pin(pin)
    output = Path(output)
    if inputs is not None:
        inputs = Path(inputs)
        data, _ = intake(pin, inputs / pin["asset"])
        if pin["project"] == "theme-forge-stellar-burst":
            dependencies = load_dependencies(inputs)
        else:
            dependencies = None
    else:
        data = download(pin, opener=opener)
        if pin["project"] == "theme-forge-stellar-burst":
            dependencies = {dep["asset"]: fetch_dependency(dep, opener=opener) for dep in DEPENDENCIES}
        else:
            dependencies = None
    build_aggregate(pin, data, output, dependencies=dependencies)
    return verify_aggregate(pin, output)


def select_missing(
    pin,
    dist=Path("dist"),
    upload_dir=Path("upload"),
    receipts=None,
    expected_commit=None,
    run_id=None,
    run_attempt=None,
    get=None,
):
    """Verify local approved dist, admit three-host matrix, check exact remote state, and copy only missing files."""
    if isinstance(pin, str):
        pin = load_pin(pin)
    else:
        validate_pin(pin)
    if pin.get("source_status") != "READY":
        fail("SOURCE_NOT_READY")
    if pin.get("qualified_platforms") != pin.get("candidate_platforms"):
        fail("PLATFORM_UNQUALIFIED")
    approved = verify_approved(pin, dist)
    if approved.get("publication_admitted") is not True:
        fail("PUBLICATION_NOT_ADMITTED")
    if receipts is None:
        fail("HOSTED_MATRIX_RECEIPTS")
    admit_matrix(pin, dist, receipts, expected_commit, run_id, run_attempt)

    dist = Path(dist)
    upload_dir = Path(upload_dir)

    if upload_dir.is_symlink():
        fail("UPLOAD_DIR")
    if upload_dir.exists():
        if not upload_dir.is_dir() or any(upload_dir.iterdir()):
            fail("UPLOAD_DIR")

    local = {}
    for record in approved["files"]:
        filename = record["filename"]
        local[filename] = physical_bytes(dist / filename)

    state_info = exact_state(pin, local, get=get)
    state = state_info.get("state")
    missing = state_info.get("missing", [])

    if state in ("unknown", "conflict"):
        fail(f"REMOTE_{state.upper()}")
    if state not in ("published-exact", "incomplete", "absent", "version-absent"):
        fail("REMOTE_UNKNOWN")

    approved_names = {record["filename"] for record in approved["files"]}
    if missing:
        upload_dir.mkdir(parents=True, exist_ok=True)
    for filename in missing:
        if filename not in approved_names:
            fail("UNAPPROVED_FILE")
        dest = upload_dir / filename
        if dest.exists() or dest.is_symlink():
            fail("UPLOAD_DIR")
        with dest.open("xb") as stream:
            stream.write(local[filename])

    return {"upload": bool(missing), "state": state, "missing": missing}


def readback(pin, dist=Path("dist"), get=None):
    """Read back remote PyPI state against approved candidate aggregate; must be published-exact."""
    if isinstance(pin, str):
        pin = load_pin(pin)
    else:
        validate_pin(pin)
    approved = verify_approved(pin, dist)
    dist = Path(dist)
    local = {record["filename"]: physical_bytes(dist / record["filename"]) for record in approved["files"]}

    state_info = exact_state(pin, local, get=get)
    state = state_info.get("state")
    if state == "published-exact":
        return {
            "project": pin["project"],
            "version": pin["distribution_version"],
            "upstream_version": pin["version"],
            "state": "published-exact",
        }
    fail(f"READBACK_{(state or 'unknown').upper().replace('-', '_')}")


def _native_qualify_job(job_id, job_name, runner, project, target, sandbox=False):
    qualify_prefix = (
        "/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \\\n            "
        if sandbox else ""
    )
    return f"""  {job_id}:
    name: {job_name}
    needs: [build_verify]
    runs-on: {runner}
    timeout-minutes: 20
    permissions:
      contents: read
    steps:
      - name: Checkout exact source
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false
      - name: Set up Python 3.13
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'
      - name: Set up Node 22
        uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38
        with:
          node-version: '22'
          package-manager-cache: false
      - name: Download the same run's verified distributions
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: pypi-artifacts
          path: dist/
      - name: Test exact wheel and sdist with networking denied
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFY_COMMIT: '${{{{ github.sha }}}}'
          QUALIFY_RUN_ID: '${{{{ github.run_id }}}}'
          QUALIFY_RUN_ATTEMPT: '${{{{ github.run_attempt }}}}'
        shell: bash
        run: |
          set -euo pipefail
          PHYSICAL_TMP="$(python3 -c 'import os,tempfile; print(os.path.realpath(tempfile.gettempdir()))')"
          export TMPDIR="$PHYSICAL_TMP" TMP="$PHYSICAL_TMP" TEMP="$PHYSICAL_TMP"
          PHYSICAL_RUNNER_TEMP="$(python3 -c 'import os; print(os.path.realpath(os.environ["RUNNER_TEMP"]))')"
          mkdir -p "$PHYSICAL_RUNNER_TEMP/tf-consumer-report"
          {qualify_prefix}python3 -B -m rs9.tf_pypi_hosted qualify --project {project} \\
            --target {target} \\
            --dist "$GITHUB_WORKSPACE/dist" --work "$PHYSICAL_RUNNER_TEMP/tf-consumer" \\
            --report "$PHYSICAL_RUNNER_TEMP/tf-consumer-report/result.json" \\
            --expected-commit "$QUALIFY_COMMIT" \\
            --run-id "$QUALIFY_RUN_ID" --run-attempt "$QUALIFY_RUN_ATTEMPT"
      - name: Preserve native consumer result
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: native-consumer-{project}-{target}
          path: '${{{{ runner.temp }}}}/tf-consumer-report/'
          retention-days: 14
          if-no-files-found: error"""


def _receipt_download_steps(project):
    return f"""      - name: Download darwin-arm64 consumer receipt
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: native-consumer-{project}-darwin-arm64
          path: receipts/darwin-arm64/
      - name: Download linux-arm64-gnu consumer receipt
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: native-consumer-{project}-linux-arm64-gnu
          path: receipts/linux-arm64-gnu/
      - name: Download linux-x64-gnu consumer receipt
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: native-consumer-{project}-linux-x64-gnu
          path: receipts/linux-x64-gnu/"""


def workflow_text(pin):
    """Generate exact registered GitHub Actions publish workflow text for a product pin."""
    if isinstance(pin, str):
        pin = load_pin(pin)
    else:
        validate_pin(pin)
    project = pin["project"]
    workflow_name = pin["workflow"]
    concurrency_group = workflow_name[:-4] if workflow_name.endswith(".yml") else workflow_name
    darwin_job = _native_qualify_job(
        "native_darwin_arm64", "Native macOS ARM64 installed consumer",
        "macos-15", project, "darwin-arm64", sandbox=True,
    )
    linux_arm_job = _native_qualify_job(
        "native_linux_arm64", "Native Linux ARM64 GNU installed consumer",
        "ubuntu-24.04-arm", project, "linux-arm64-gnu", sandbox=False,
    )
    linux_x64_job = _native_qualify_job(
        "native_linux_x64", "Native Linux x86_64 GNU installed consumer",
        "ubuntu-24.04", project, "linux-x64-gnu", sandbox=False,
    )
    receipt_downloads = _receipt_download_steps(project)

    return f"""name: RS9 {project} PyPI Publish
run-name: 'RS9 {project} ${{{{ inputs.mode }}}} / ${{{{ inputs.dispatch_id }}}}'

on:
  push:
    branches: [rs9-tf-pypi-hostqual1]
  workflow_dispatch:
    inputs:
      mode:
        description: 'Execution mode'
        required: true
        type: choice
        options:
          - qualify
          - publish
        default: qualify
      dispatch_id:
        description: 'Unique attended intent correlation; not publication authority'
        required: false
        type: string

permissions:
  contents: read

concurrency:
  group: {concurrency_group}-${{{{ github.ref }}}}
  cancel-in-progress: false

jobs:
  build_verify:
    if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/rs9-tf-pypi-hostqual1'
    name: Build and Verify Candidate Artifacts
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - name: Checkout repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Build and verify package distributions
        env:
          PYTHONPATH: src
        run: python3 -B -m rs9.tf_pypi_publish build --project {project} --output dist

      - name: Stage verified artifacts
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: pypi-artifacts
          path: dist/
          retention-days: 1
          if-no-files-found: error

{darwin_job}

{linux_arm_job}

{linux_x64_job}

  qualification_gate:
    name: Three-host qualification gate
    needs: [build_verify, native_darwin_arm64, native_linux_arm64, native_linux_x64]
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - name: Checkout exact source
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false
      - name: Download staged artifacts
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: pypi-artifacts
          path: dist/
{receipt_downloads}
      - name: Admit three-host native matrix receipts
        env:
          PYTHONPATH: src
          QUALIFY_COMMIT: '${{{{ github.sha }}}}'
          QUALIFY_RUN_ID: '${{{{ github.run_id }}}}'
          QUALIFY_RUN_ATTEMPT: '${{{{ github.run_attempt }}}}'
        run: python3 -B -m rs9.tf_pypi_hosted admit --project {project} --dist dist --receipts receipts --expected-commit "$QUALIFY_COMMIT" --run-id "$QUALIFY_RUN_ID" --run-attempt "$QUALIFY_RUN_ATTEMPT"

  publish:
    if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.mode == 'publish'
    name: Trusted Publishing to PyPI
    needs: [build_verify, native_darwin_arm64, native_linux_arm64, native_linux_x64, qualification_gate]
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    environment:
      name: pypi
      url: https://pypi.org/p/{project}
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Download staged artifacts
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: pypi-artifacts
          path: dist/
{receipt_downloads}

      - name: Verify artifact integrity and select only missing files
        id: missing
        env:
          PYTHONPATH: src
          QUALIFY_COMMIT: '${{{{ github.sha }}}}'
          QUALIFY_RUN_ID: '${{{{ github.run_id }}}}'
          QUALIFY_RUN_ATTEMPT: '${{{{ github.run_attempt }}}}'
        run: python3 -B -m rs9.tf_pypi_publish select-missing --project {project} --dist dist --upload-dir upload --receipts receipts --expected-commit "$QUALIFY_COMMIT" --run-id "$QUALIFY_RUN_ID" --run-attempt "$QUALIFY_RUN_ATTEMPT" >> "$GITHUB_OUTPUT"

      - name: Publish package distributions to PyPI
        if: steps.missing.outputs.upload == 'true'
        uses: pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e
        with:
          packages-dir: upload/

      - name: Read back published PyPI state
        env:
          PYTHONPATH: src
        run: python3 -B -m rs9.tf_pypi_publish readback --project {project} --dist dist
"""


def parser():
    """Build CLI parser for tf_pypi_publish operations."""
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="operation", required=True)

    build_cmd = sub.add_parser("build")
    build_cmd.add_argument("--project", choices=sorted(PRODUCTS), required=True)
    build_cmd.add_argument("--output", type=Path, default=Path("dist"))
    build_cmd.add_argument("--inputs", type=Path, default=None)

    missing_cmd = sub.add_parser("select-missing")
    missing_cmd.add_argument("--project", choices=sorted(PRODUCTS), required=True)
    missing_cmd.add_argument("--dist", type=Path, default=Path("dist"))
    missing_cmd.add_argument("--upload-dir", type=Path, default=Path("upload"))
    missing_cmd.add_argument("--receipts", type=Path, required=True)
    missing_cmd.add_argument("--expected-commit", required=True)
    missing_cmd.add_argument("--run-id", default="1")
    missing_cmd.add_argument("--run-attempt", default="1")

    readback_cmd = sub.add_parser("readback")
    readback_cmd.add_argument("--project", choices=sorted(PRODUCTS), required=True)
    readback_cmd.add_argument("--dist", type=Path, default=Path("dist"))

    workflow_cmd = sub.add_parser("workflow")
    workflow_cmd.add_argument("--project", choices=sorted(PRODUCTS), required=True)

    return result


def main(argv=None, *, get=None, opener=None):
    """Run CLI dispatch with strict admission error handling."""
    args = parser().parse_args(argv)
    try:
        pin = load_pin(args.project)
        op = args.operation
        if op == "build":
            result = build(pin, output=args.output, inputs=args.inputs, opener=opener)
            sys.stdout.buffer.write(canonical(result))
            return 0
        if op == "select-missing":
            res = select_missing(
                pin,
                dist=args.dist,
                upload_dir=args.upload_dir,
                receipts=args.receipts,
                expected_commit=args.expected_commit,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                get=get,
            )
            sys.stdout.write(f"upload={'true' if res['upload'] else 'false'}\nstate={res['state']}\n")
            return 0
        if op == "readback":
            res = readback(pin, dist=args.dist, get=get)
            sys.stdout.write(f"state={res['state']}\n")
            return 0
        if op == "workflow":
            sys.stdout.write(workflow_text(pin))
            return 0
        return 1
    except AdmissionError as error:
        sys.stderr.write(error.code + "\n")
        return 1
    except (OSError, ValueError, KeyError, RuntimeError):
        sys.stderr.write("TF_PYPI_OPERATION_FAILED\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
