# Nebular 0.7.0 Publisher Runtime Wiring Evaluation

## 1. Executive Summary

This evaluation documents the runtime wiring repairs and post-review revisions across the additive Theme Forge Nebular Fusion `0.7.0` PyPI publisher seam (`src/rs9/tf_pypi_nebular070_publish.py`, `src/rs9/tf_pypi_nebular.py`, `.github/workflows/rs9-tfnf-pypi-publish.yml`, and their test suites).

All three confirmed runtime wiring defects (`R2`, `R3`, `R4`) and all independent work-review findings (`F1`–`F6`) are resolved and verified end-to-end, and the withdrawn `R1` syntax finding is backed by direct subprocess execution coverage under the selected Python 3.13.12 runtime:

1. **R1 (Withdrawn — Verified via Subprocess Execution)**:
   - The `Resolve pinned qualification commit from publisher authority` step in `publication_resume_job_text()` uses PEP 701 nested double quotes inside an f-string (`f"qualification_commit={cap[\"qualification_source_commit\"]}"`).
   - Both the repository's selected Python 3.13.12 interpreter and the workflow's `actions/setup-python` (`python-version: '3.13'`) support PEP 701 natively.
   - `tests/test_tf_pypi_nebular070_publish.py` (`test_r1_rendered_resume_python_resolver_executes_under_selected_python313`) extracts the rendered shell/Python snippet from `publication_resume_job_text()` and executes it in a `bash` subprocess under Python 3.13.12, verifying exit code `0` and exact `GITHUB_OUTPUT` emission.

2. **R2 (Repaired — `build_verify_070` / `build-candidates` Qualification-Inputs & Evidence Wiring)**:
   - Defined the closed operator qualification-inputs descriptor contract (`QUALIFICATION_INPUTS_SCHEMA = "rs9.tf-pypi-nebular070-qualification-inputs.v1"`, default path `operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-qualification-inputs.json`).
   - Updated `workflow_070_qualify_jobs_text()` and `.github/workflows/rs9-tfnf-pypi-publish.yml` so `build_verify_070` passes `--qualification-inputs operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-qualification-inputs.json` and `--evidence "${{ runner.temp }}/tfnf-070-evidence"` to `python -B -m rs9.tf_pypi_nebular070_publish build-candidates`.
   - When the descriptor is absent or its `status` is `"pending"`, `build-candidates` fails closed immediately with `TF_PYPI_RELEASE_INPUTS_PENDING` before any Gate 1 or consumer work.
   - When a ready descriptor is provided, `materialize_qualification_evidence()` enforces repository-relative containment on `evidence.source_root` (`_resolve_repo_contained_dir`), verifies every declared evidence file against its exact byte size and SHA-256 digest (rejecting symlinks, path traversal, extra files, or digest mismatches with `TF_PYPI_QUALIFICATION_INPUTS_DIGEST` / `TF_PYPI_QUALIFICATION_INPUTS_EVIDENCE` and cleaning up partial staging directories on error), verifies the release binding and bootstrap/expectations digests, authenticates the Gate 1 capture, and emits the exact 5-file candidate bundle (`candidate_receipt.json`, `expected_artifacts.json`, and 3 wheels under `dist/`).

3. **R3 (Repaired — `native_consumer_070_*` / `qualify-native` Target-Bound Raw-Release Handoff)**:
   - Updated `workflow_070_qualify_jobs_text()` and `.github/workflows/rs9-tfnf-pypi-publish.yml` so all three native consumer jobs (`darwin-arm64`, `linux-arm64-gnu`, `linux-x64-gnu`) pass `--qualification-inputs operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-qualification-inputs.json` and `--raw-release "${{ runner.temp }}/tfnf-070-raw-release-<target>/raw_release.json"`.
   - Removed the unvalidated `bundle / "raw_release.json"` fallback in `load_raw_release_handoff()` and added `_validate_bundle_file_set()` so any extra or missing file in `tfnf-070-candidate-bundle` fails closed with `TF_PYPI_BUNDLE_FILE_SET`.
   - `materialize_raw_release_handoff()`, `validate_raw_release_handoff_binding()`, and `_verify_handoff_matches_descriptor()` enforce closed schema keys (`RAW_RELEASE_HANDOFF_SCHEMA = "rs9.tf-pypi-nebular070-raw-release-handoff.v1"`), physical file size and SHA-256 verification for every descriptor (`record`, `readme`, `legal_files`, `provenance`, `payload`, `manifest`, and `native_consumer[target]`'s `qualification` and `smoke["raw-archive"|"npm-package"]["run"|"receipt"]`), entry-for-entry comparison against `descriptor["raw_release"]["targets"][target]` (even when a pre-existing `--raw-release` file is supplied on disk), and cryptographic join against `candidate_receipt.json` and `expected_artifacts.json`.
   - Missing handoffs or descriptors fail with `TF_PYPI_RAW_RELEASE_HANDOFF_PENDING`, digest mismatches (including self-consistent tampering against the descriptor) fail with `TF_PYPI_RAW_RELEASE_HANDOFF_DIGEST`, and mixed-target or cross-candidate handoffs fail with `TF_PYPI_RAW_RELEASE_HANDOFF_BINDING`.

4. **R4 (Repaired — `check_prior_publish_runs` 0.7.0 Qualification Run Recognition)**:
   - Updated `check_prior_publish_runs()` in both `src/rs9/tf_pypi_nebular070_publish.py` and `src/rs9/tf_pypi_nebular.py` to recognize any completed `0.7.0` qualification run where all 5 `QUALIFY_070_JOB_NAMES` jobs are present and completed, at least one `QUALIFY_070_JOB_NAMES` job executed (`conclusion != "skipped"`), and every non-qualification job on that workflow run was `"skipped"` (including completed qualification runs where `build_verify_070` or a native consumer job failed and downstream qualification jobs were skipped).
   - Preserved fail-closed rejection (`TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED`) for any prior `0.7.0` resume run where the upload step ran, failed, was in progress, or is missing/incomplete, any partial or in-progress `0.7.0` qualification job set (fewer than 5 qualification jobs or any job not `"completed"`), any all-skipped/guard-only run, any mixed active `0.6.1` + `0.7.0` job set, or any unknown job name.

---

## 2. Root Design Decisions: Per-Job Descriptor Materialization & Byte Provenance

1. **Per-Job Descriptor Materialization vs. Separate Workflow Artifact**:
   - The frozen Gate 2 artifact capture contract (`REQUIRED_CAPTURE_ARTIFACTS`) admits exactly 5 workflow artifacts (`tfnf-070-candidate-bundle`, the 3 `tfnf-070-qualification-<target>` artifacts, and `tfnf-070-matrix-receipt`), and `tfnf-070-candidate-bundle` is locked to 5 exact files (`candidate_receipt.json`, `expected_artifacts.json`, and the 3 wheels under `dist/`).
   - Rather than adding a 6th workflow artifact or mutating out-of-scope Gate 2 capture schemas, `build_verify_070` and the three `native_consumer_070_*` jobs all read the same versioned operator descriptor (`operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-qualification-inputs.json`) from the pinned qualification checkout (`${{ github.sha }}` on `rs9/nebular-pypi-qualify`) and materialize digest-verified inputs into job-local `${{ runner.temp }}` staging directories.
2. **Repository-Contained Byte Provenance (`evidence.source_root` and `raw_release.source_root`)**:
   - Because hosted qualification jobs execute with `contents: read` and network isolation against the qualification branch checkout, both `evidence.source_root` and `raw_release.source_root` in `validate_qualification_inputs_descriptor()` are strictly constrained to repository-relative, symlink-free directories contained within `repo_root` (`_validate_repo_relative_dir_spec` and `_resolve_repo_contained_dir`). Absolute paths, `..` traversal, symlinks, and duplicate per-target `root` keys inside `raw_release.targets[target]` are rejected fail-closed (`TF_PYPI_QUALIFICATION_INPUTS_EVIDENCE` / `TF_PYPI_QUALIFICATION_INPUTS_RAW_RELEASE`).
   - When an operator prepares the `rs9/nebular-pypi-qualify` branch for a real `v0.7.0` qualification run, the authenticated upstream release evidence and per-target raw-release inputs reside under those repository-relative directories in the qualification checkout and are verified by exact byte size and SHA-256 before Gate 1 or native consumer execution.

---

## 3. Verification Commands and Results

All verification was executed against the repository's selected Python 3.13.12 interpreter (`/nix/store/556f8qa70vw60a2isqy2wb77r5ljs9yl-python3-3.13.12-env/bin/python3.13`) with `PYTHONPATH=src` and native `unittest`:

```bash
PYTHONPATH=src /nix/store/556f8qa70vw60a2isqy2wb77r5ljs9yl-python3-3.13.12-env/bin/python3.13 -m unittest -v \
  tests.test_tf_pypi_nebular070_publish \
  tests.test_tf_pypi_nebular \
  tests.test_nebular070_gate1 \
  tests.test_nebular070_gate1_roundtrip \
  tests.test_tf_pypi_nebular070_gate2 \
  tests.test_tf_pypi_nebular_successor \
  tests.test_wheel_nebular_successor \
  tests.test_tf_pypi_successor_release \
  tests.test_nebular_host_state \
  tests.test_nebular_legal_boundary \
  tests.test_nebular_lineage \
  tests.test_nebular_callers \
  tests.test_tf_pypi_workflow
```

- **Result**: `Ran 168 tests` across the 13 focused Nebular/workflow test modules — `OK` (`0` failures, `0` errors).
- **Workflow Generator Byte-Parity & Static Checks**:
  - `workflow_text("0.7.0") == workflow_text("0.6.1") == Path(".github/workflows/rs9-tfnf-pypi-publish.yml").read_text(encoding="utf-8")`.
  - Static AST contract check (`ast.parse(..., feature_version=(3, 12))`, stdlib/`rs9.*`-only imports, and zero `.extract`/`.extractall` calls across `tf_pypi_nebular.py`, `nebular_host_state.py`, and `tf_pypi_nebular070_publish.py`) passed.
- **`actionlint` Availability**:
  - Checked `command -v actionlint` and standard host/Nix profile paths; `actionlint` is not installed in this local environment and was not downloaded per task constraints.

---

## 4. Python Language Profile Assessment & Structural Exception Record

Per the repository's Python language profile thresholds:

| Module | Baseline Lines (`HEAD`) | Current Total Lines | Embedded Workflow YAML Lines | Handwritten Python Logic Lines (Baseline -> Current) | Max Function Length |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `src/rs9/tf_pypi_nebular070_publish.py` | 3,388 | 4,437 | ~491 (`workflow_070_qualify_jobs_text`, `publication_resume_job_text`) | ~2,913 -> ~3,946 (`+1,033` across checkpoint; `+556` in runtime-wiring/handoff repair) | `validate_raw_release_handoff_binding` (209 lines), `validate_qualification_inputs_descriptor` (142 lines) |
| `src/rs9/tf_pypi_nebular.py` | 3,270 | 3,317 | ~260 (`workflow_text`) | ~3,010 -> ~3,057 (`+47`) | `check_prior_publish_runs` (102 lines) |

- **Legacy / Ownership Boundary Exception**:
  - Both modules are existing single-file publisher seams in the baseline checkpoint, and this task's write ownership is strictly bounded to the 6 listed paths (`src/rs9/tf_pypi_nebular070_publish.py`, `src/rs9/tf_pypi_nebular.py`, `.github/workflows/rs9-tfnf-pypi-publish.yml`, `tests/test_tf_pypi_nebular070_publish.py`, `tests/test_tf_pypi_nebular.py`, and `docs/evaluations/nebular070-publisher-runtime-wiring.md`). Splitting either module into new package files would violate the 6-path ownership constraint and existing caller imports.
- **Rollback Plan**:
  - Because this stage is a non-publishing source checkpoint with no external side effects, rollback consists of declining the checkpoint or reverting the 6 owned paths to the baseline tree.
- **Follow-Up Decomposition Boundary**:
  - In a future structural cleanup phase with broader file ownership, `src/rs9/tf_pypi_nebular070_publish.py` can be decomposed into dedicated internal submodules (`_nebular070_models.py` for pin/approval/capture/inputs schema validation, `_nebular070_handoff.py` for evidence and raw-release materialization, `_nebular070_remote.py` for PyPI state/readback/prior-run guards, and `_nebular070_workflow.py` for YAML rendering) while re-exporting the public surface from `rs9.tf_pypi_nebular070_publish`.

---

## 5. Scope Limits and Pending Operator Inputs

- **No Real v0.7.0 Release Inputs or Publication Admission in This Phase**:
  - `operators/tf-pypi/theme-forge-nebular-fusion-0.7.0.json`, `operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-qualification-inputs.json`, `operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-artifacts.json`, and `operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-qualification.json` remain absent from the committed repository (`load_pin` -> `TF_PYPI_PIN_ABSENT`, `build-candidates` -> `TF_PYPI_RELEASE_INPUTS_PENDING`, `qualify-native` -> `TF_PYPI_RAW_RELEASE_HANDOFF_PENDING`) until an operator captures real upstream `v0.7.0` release assets and hosted 3-platform qualification evidence.
- **Controlled Local Consumer Driver vs. Hosted Qualification**:
  - The end-to-end `qualify-native` CLI tests in `tests/test_tf_pypi_nebular070_publish.py` exercise the real `qualify_nebular070` -> `consume_nebular_candidate` call chain, real `make_real_user_state_snapshotter` and `_nebular_process_snapshot` observers, and real subprocess execution of the wheel's embedded `theme_forge_nebular_fusion.launcher` and `rs9.materialize` payload materializer using synthetic fixture archives and a controlled local subprocess driver. They prove runtime wiring and contract enforcement, not hosted 3-platform release qualification.
