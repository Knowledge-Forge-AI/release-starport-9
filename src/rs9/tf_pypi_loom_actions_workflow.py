"""Qualification-only workflow using unchanged hosted job renderers."""
import argparse
import re

from .tf_pypi_publish import _native_qualify_job, _receipt_download_steps

PROJECT = "theme-forge-stellar-loom"
SELECTOR = " --pin operators/tf-pypi/theme-forge-stellar-loom-0.5.0.json"


TOOLING_REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
EXECUTION_REPOSITORY = "Knowledge-Forge-AI/theme-forge-stellar-loom"


def loom_execution(text, rs9_commit):
    """Bind tooling identity separately from the Loom execution/token scope."""
    checkout = "          ref: '${{ github.sha }}'"
    if text.count(checkout) != 5 or text.count("QUALIFY_COMMIT: '${{ github.sha }}'") != 4:
        raise ValueError("qualification renderer checkout/commit contract changed")
    text = text.replace(checkout, f"          repository: {TOOLING_REPOSITORY}\n          ref: '{rs9_commit}'")
    text = text.replace("QUALIFY_COMMIT: '${{ github.sha }}'", f"QUALIFY_COMMIT: '{rs9_commit}'")
    for job in ("build_verify", "native_darwin_arm64", "native_linux_arm64", "native_linux_x64", "qualification_gate"):
        header = f"  {job}:\n"
        if text.count(header) != 1:
            raise ValueError("qualification renderer job contract changed")
        text = text.replace(header, header + "    if: ${{ github.repository == '" + EXECUTION_REPOSITORY + "' }}\n")
    return ("# rs9-loom-actions-qualification-v1\n"
            f"# Tooling repository: {TOOLING_REPOSITORY}; commit: {rs9_commit}\n"
            f"# Execution/token repository: {EXECUTION_REPOSITORY}; publication: false\n" + text)


def workflow_text(rs9_commit):
    if not isinstance(rs9_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", rs9_commit):
        raise ValueError("--rs9-commit requires an accepted full lowercase 40-character RS9 commit")
    jobs = [
        _native_qualify_job("native_darwin_arm64", "Native macOS ARM64 installed consumer", "macos-15", PROJECT, "darwin-arm64", sandbox=True, selector=SELECTOR),
        _native_qualify_job("native_linux_arm64", "Native Linux ARM64 GNU installed consumer", "ubuntu-24.04-arm", PROJECT, "linux-arm64-gnu", selector=SELECTOR),
        _native_qualify_job("native_linux_x64", "Native Linux x86_64 GNU installed consumer", "ubuntu-24.04", PROJECT, "linux-x64-gnu", selector=SELECTOR),
    ]
    return loom_execution(f"""name: RS9 Loom 0.5.0 Actions Artifact Qualification
run-name: 'Loom 0.5.0 qualification / ${{{{ inputs.dispatch_id }}}}'
on:
  workflow_dispatch:
    inputs:
      dispatch_id:
        description: 'Attended intent correlation; not publication authority'
        required: true
        type: string
permissions:
  contents: read
concurrency:
  group: rs9-tfsl-actions-qualify-${{{{ github.ref }}}}
  cancel-in-progress: false
jobs:
  build_verify:
    name: Admit exact upstream CI artifact and build distributions
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions:
      contents: read
      actions: read
    steps:
      - name: Checkout exact RS9 source
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false
      - name: Set up Python 3.13
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'
      - name: Admit reviewed upstream artifact into local inputs
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          GH_TOKEN: '${{{{ github.token }}}}'
        run: python3 -B -m rs9.tf_pypi_loom_actions_intake --output transport
      - name: Build using maintained local input API
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: python3 -B -m rs9.tf_pypi_publish build --project {PROJECT}{SELECTOR} --inputs transport/inputs --output dist
      - name: Retain transport evidence independently
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: upstream-transport-evidence
          path: transport/
          retention-days: 14
          if-no-files-found: error
      - name: Stage verified distributions
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: pypi-artifacts
          path: dist/
          retention-days: 14
          if-no-files-found: error

{chr(10).join(jobs)}

  qualification_gate:
    name: Three-host qualification gate
    needs: [build_verify, native_darwin_arm64, native_linux_arm64, native_linux_x64]
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - name: Checkout exact RS9 source
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false
      - name: Download staged artifacts
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: pypi-artifacts
          path: dist/
{_receipt_download_steps(PROJECT)}
      - name: Admit three-host native matrix receipts
        env:
          PYTHONPATH: src
          QUALIFY_COMMIT: '${{{{ github.sha }}}}'
          QUALIFY_RUN_ID: '${{{{ github.run_id }}}}'
          QUALIFY_RUN_ATTEMPT: '${{{{ github.run_attempt }}}}'
        run: python3 -B -m rs9.tf_pypi_hosted admit --project {PROJECT}{SELECTOR} --dist dist --receipts receipts --expected-commit "$QUALIFY_COMMIT" --run-id "$QUALIFY_RUN_ID" --run-attempt "$QUALIFY_RUN_ATTEMPT" > matrix-result.json
      - name: Retain native matrix admission
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: native-matrix-admission
          path: matrix-result.json
          retention-days: 14
          if-no-files-found: error
""", rs9_commit)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rs9-commit", required=True, help="Accepted public RS9 tooling commit (full lowercase SHA); not the Loom caller SHA")
    args = parser.parse_args(argv)
    try:
        text = workflow_text(args.rs9_commit)
    except ValueError as exc:
        parser.error(str(exc))
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
