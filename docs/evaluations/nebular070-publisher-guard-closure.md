# RS9 Nebular 0.7.0 PyPI Publisher Guard Closure Evaluation

## 1. Executive Summary and Scope

This evaluation documents the bounded closure of two fail-closed guard gaps and one non-blocking handoff relative-path binding review in the additive Nebular `0.7.0` three-wheel PyPI publisher seam (`src/rs9/tf_pypi_nebular070_publish.py`) and its unit/contract test suite (`tests/test_tf_pypi_nebular070_publish.py`).

- **Repository state**: `HEAD` `e0fecf795aa7c05dd05ca66f4b76e6acf1c7b14e`, descending from public base `6790d53fb8f4157015fd127744ccd69b366367e9`.
- **Touched paths (exact 3-file scope)**:
  1. `src/rs9/tf_pypi_nebular070_publish.py`
  2. `tests/test_tf_pypi_nebular070_publish.py`
  3. `docs/evaluations/nebular070-publisher-guard-closure.md`
- **Untouched invariants**:
  - `.github/workflows/rs9-tfnf-pypi-publish.yml` is unchanged and remains byte-identical to `workflow_text("0.7.0")` and `workflow_text("0.6.1")`.
  - Committed repository release inputs and pins (`operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-gate1.json`, `operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-qualification-inputs.json`, `operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-artifacts.json`, and `operators/tf-pypi/theme-forge-nebular-fusion-0.7.0.json`) remain in their unfabricated pending/unadmitted state (`publication_admitted: false`).
  - No live network, GitHub Actions, or PyPI calls are performed.

---

## 2. Gap 1 Closure: Mandatory Operator-Handoff Descriptor on All `build-candidates` Paths

### Problem Analysis

Previously, `build_candidates_bundle` materialized and validated the `0.7.0` operator `qualification-inputs` descriptor (`rs9.tf-pypi-nebular070-qualification-inputs.v1`) only when `qualification_inputs` (or `RS9_TFNF070_QUALIFICATION_INPUTS`) was explicitly supplied. When omitted:

1. `descriptor` remained `None`.
2. Any caller supplying a `"status": "ready"` `release_binding` alongside `evidence_dir` (or `RS9_TFNF070_EVIDENCE_DIR`) bypassed `materialize_qualification_evidence(...)` and `descriptor["release_binding_sha256"]` verification.

Although the generated workflow (`build_verify_070`) always passed `--qualification-inputs operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-qualification-inputs.json`, direct API or CLI `build-candidates` callers omitting `--qualification-inputs` could build bundles without verifying the operator-handoff byte-custody contract.

### Implemented Fix

In `build_candidates_bundle` (`src/rs9/tf_pypi_nebular070_publish.py`):

1. **Mandatory evidence target directory**: `eff_evidence` resolves from `evidence_dir` or `RS9_TFNF070_EVIDENCE_DIR`; if `None`, `build_candidates_bundle` fails closed with `TF_PYPI_RELEASE_INPUTS_PENDING`.
2. **Unconditional descriptor validation and evidence materialization/verification**: `descriptor = materialize_qualification_evidence(qualification_inputs, eff_evidence, repository=root)` runs unconditionally before inspecting `release_binding`:
   - `Mapping` inputs validate via `validate_qualification_inputs_descriptor`; path or `None` inputs resolve explicit `path`, `RS9_TFNF070_QUALIFICATION_INPUTS`, or default `qualification_inputs_path(root)`, failing closed with `TF_PYPI_RELEASE_INPUTS_PENDING` when absent or `"status": "pending"`.
   - Every file in `eff_evidence` is materialized from `descriptor["evidence"]["source_root"]` or verified against `descriptor["evidence"]["files"]` for exact file-set, size, and SHA-256 digest equality (`TF_PYPI_QUALIFICATION_INPUTS_EVIDENCE` / `TF_PYPI_QUALIFICATION_INPUTS_DIGEST`).
3. **Unconditional `release_binding_sha256` binding**:
   - When `release_binding` is omitted and `RS9_TFNF070_RELEASE_BINDING` is unset, `raw_binding` defaults to `descriptor["release_binding"]`.
   - When `release_binding` is provided explicitly or via `RS9_TFNF070_RELEASE_BINDING`, it is validated via `validate_release_binding` and unconditionally checked against `descriptor["release_binding_sha256"]` (`TF_PYPI_QUALIFICATION_INPUTS_BINDING`).

---

## 3. Gap 2 Closure: Fail-Closed Prior-Run History Normalization and DAG Validation

### Problem Analysis

Prior to this change, `check_prior_publish_runs` (invoked by `select_missing` before PyPI upload staging) had several permissive assumptions when inspecting GitHub Actions history:

- `run.get("status") in (None, "completed")` allowed missing or `None` run status.
- Optional `run.get("inputs")` was not validated when empty `{}` or when contradicting the run title.
- Run-level metadata fields (`workflow_id`, `path`, `event`, `head_branch`, `head_sha`, `run_attempt`, `status`, `conclusion`, `repository`, `head_repository`) were not strictly validated.
- Non-empty arbitrary strings for job `conclusion` passed on qualify jobs.
- Missing non-qualify jobs in a 10-job workflow run could look like skipped non-qualify jobs because only `qualify_070_jobs` cardinality (`len == 5`) was checked.
- In `publish_jobs`, `step.get("status") in (None, "completed")` accepted `status: None` if `conclusion == "skipped"`.
- `"resume" not in display_title` was unanchored and rejected a legitimate `0.7.0` `qualify` run whose `dispatch_id` contained `"resume"`, while not anchoring the header before `" /"`.
- The 5-job `0.7.0` `qualify` dependency DAG (`Build and Verify Nebular 0.7.0 Candidate Bundle` -> 3 `Native consumer 0.7.0 (<target>)` jobs -> `Qualification matrix gate 0.7.0`) was not checked for topological conclusion consistency.

### Implemented Root Design and REST Normalization

1. **Environment and pagination guards**:
   - Non-empty `RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED` or `GITHUB_RUN_ATTEMPT != "1"` fails closed with `TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED`.
   - `GITHUB_REPOSITORY` must equal `DEFAULT_GITHUB_REPOSITORY` (`Knowledge-Forge-AI/release-starport-9`).
   - `GITHUB_RUN_ID` must match `^[1-9][0-9]*$` whenever set, and is mandatory when `GITHUB_ACTIONS == "true"`.
   - `_fetch_paginated_github_list` enforces consistent non-negative integer `total_count` across pages and requires `len(items) == total_count` on termination.

2. **Run-level envelope validation**:
   For every prior run in `workflow_runs` (`rid != current_run_id` after verifying positive unique integer `id`):
   - `workflow_id`: positive `int`, identical across all runs returned for the workflow.
   - `event == "workflow_dispatch"`, `head_branch == "main"`, and 40-hex lowercase `head_sha`.
   - `path`: normalized by `_normalize_workflow_run_path` to `.github/workflows/rs9-tfnf-pypi-publish.yml`. GitHub's primary REST API documentation illustrates `.github/workflows/<file>@main`; `_normalize_workflow_run_path` accepts bare `.github/workflows/rs9-tfnf-pypi-publish.yml`, `@main`, `@refs/heads/main`, and (as an intentional defensive normalization extension bound to the verified run commit) `@<head_sha>`, rejecting any other workflow path or ref.
   - `run_attempt`: positive `int` (`>= 1`).
   - `status == "completed"` and `conclusion in {"success", "failure", "cancelled", "timed_out"}`.
   - `repository` and `head_repository` (when present and non-null): mapping with `full_name == DEFAULT_GITHUB_REPOSITORY`.

3. **Title and optional `inputs` normalization (`_parse_prior_run_title_and_inputs`)**:
   - Current workflow `run-name` is `"RS9 theme-forge-nebular-fusion ${{ inputs.release || '0.6.1' }} ${{ inputs.mode || 'qualify' }} / ${{ inputs.dispatch_id }}"`.
   - `_parse_prior_run_title_and_inputs` rejects leading whitespace (`raw_title != raw_title.lstrip()`) and splits on `" /"` (`head, sep, dispatch_tail = raw_title.partition(" /")`), requiring `sep == " /"` and `head.split(" ") == ["RS9", PROJECT, release_tok, mode_tok]` where `validate_workflow_dispatch(release_tok, mode_tok)` succeeds. Because `dispatch_id` is optional (`required: false`), `dispatch_tail` may be `""` (trimmed `" /"`) or `" "` (untrimmed `" / "`) when `dispatch_id` is omitted; when `dispatch_id` is provided, `dispatch_tail` must equal `" " + dispatch_id` with no leading/trailing whitespace on `dispatch_id`. Mode extraction is anchored before `" /"`, so a `dispatch_id` containing `"resume"` in a `0.7.0` `qualify` run is classified as `("0.7.0", "qualify")`.
   - Historical `0.6.1` run titles (`"RS9 theme-forge-nebular-fusion PyPI Publish"` and `"RS9 theme-forge-nebular-fusion <qualify|publish> / <id>"`) set `is_historical_061 = True`.
   - Standard GitHub REST API workflow-run payloads do not populate `inputs`, so `inputs` is optional when absent or `None`; if present, it must be a non-empty mapping whose `release` and `mode` pass `validate_workflow_dispatch` and match the parsed title release and mode.

4. **Per-attempt job and step envelope validation (`_validate_prior_run_jobs_by_attempt`, `_validate_prior_run_jobs_map`)**:
   - Because `/actions/runs/<id>/jobs?filter=all` returns jobs across all attempts `1..run["run_attempt"]`, `_validate_prior_run_jobs_by_attempt` groups jobs by `job["run_attempt"]`, requiring every attempt `1..run["run_attempt"]` to be present.
   - Every job must have a positive integer `id` (unique across the run), `run_id == run["id"]`, `run_attempt == attempt_idx`, `head_sha == run["head_sha"]`, a unique name within its attempt in `ALL_KNOWN_WORKFLOW_JOB_NAMES`, `status == "completed"`, and `conclusion in {"success", "failure", "cancelled", "skipped", "timed_out"}`.
   - When `"steps"` is present, every step must have non-empty string `name`, `status == "completed"`, and `conclusion in VALID_WORKFLOW_JOB_CONCLUSIONS`. If the job has `conclusion == "skipped"`, every step must also have `conclusion == "skipped"`.

5. **Route-specific job-set and DAG validation**:
   - **Current `0.7.0` `qualify` (`_validate_070_qualify_prior_run`)**:
     - Validated for every attempt `1..run["run_attempt"]` (checking `run["conclusion"]` parity on `attempt_idx == run["run_attempt"]`).
     - Requires all 10 `ALL_KNOWN_WORKFLOW_JOB_NAMES` present on every attempt, with all 5 non-qualify jobs `"skipped"`.
     - Validates the 5-job `qualify` DAG (`ACTIVE_FAILURE_CONCLUSIONS = {"failure", "cancelled", "timed_out"}`):
       - **Build failed**: `build` in `ACTIVE_FAILURE_CONCLUSIONS`, all 3 `native` jobs `"skipped"`, `matrix` `"skipped"`, and (final attempt) `run["conclusion"]` in `ACTIVE_FAILURE_CONCLUSIONS`.
       - **Native failed**: `build == "success"`, all 3 `native` jobs in `{"success"} | ACTIVE_FAILURE_CONCLUSIONS` with `>= 1` in `ACTIVE_FAILURE_CONCLUSIONS`, `matrix == "skipped"`, and (final attempt) `run["conclusion"]` in `ACTIVE_FAILURE_CONCLUSIONS`.
       - **Matrix failed**: `build == "success"`, all 3 `native` jobs `"success"`, `matrix` in `ACTIVE_FAILURE_CONCLUSIONS`, and (final attempt) `run["conclusion"]` in `ACTIVE_FAILURE_CONCLUSIONS`.
       - **All succeeded**: `build == "success"`, all 3 `native` jobs `"success"`, `matrix == "success"`, and (final attempt) `run["conclusion"] == "success"`.
   - **Prior `0.7.0` `resume` (`_validate_070_resume_prior_run`)**:
     - Requires `run["run_attempt"] == 1`, all 10 `ALL_KNOWN_WORKFLOW_JOB_NAMES` present, and all 9 non-resume jobs `"completed"` + `"skipped"`.
     - Requires `Attended Nebular 0.7.0 PyPI publication resume` to have `status == "completed"`, `conclusion in ACTIVE_FAILURE_CONCLUSIONS`, `run["conclusion"] in ACTIVE_FAILURE_CONCLUSIONS`, and a non-empty `steps` list containing `"Publish package distribution to PyPI"` with `status == "completed"` and `conclusion == "skipped"`.
   - **Legacy `0.6.1` (`_validate_061_legacy_prior_run`)**:
     - Validated across `1..run["run_attempt"]`. Admits either the 10-job combined workflow (all 7 `0.7.0` jobs `"completed"` + `"skipped"`) or, when `is_historical_061` is true, the 3-job legacy workflow (`LEGACY_061_JOB_NAMES`), enforcing the 3-job `0.6.1` DAG and final-attempt run conclusion consistency.

---

## 4. Non-Blocking Handoff Path-Semantics Review and Tightening

In `validate_qualification_inputs_descriptor`, `descriptor["raw_release"]["source_root"]` is a normalized repository-relative directory, and every file entry under `descriptor["raw_release"]["targets"][target]` has a normalized relative `path` (and optional `name == basename(path)`). When `materialize_raw_release_handoff` stages `files/` from `root / source_root`, it preserves `rel_src` under `stage_dir`.

`_verify_handoff_file_entry_matches_descriptor` and `_verify_handoff_matches_descriptor` enforce both `(size, sha256)` (`TF_PYPI_RAW_RELEASE_HANDOFF_DIGEST`) and exact `(path, name)` equality (`TF_PYPI_RAW_RELEASE_HANDOFF_BINDING`) across all 13 file-digest entries (`record`, `readme`, `provenance`, `payload`, `manifest`, 3 `legal_files`, `native_consumer[target]["qualification"]`, and 4 `smoke` entries), plus exact key-set equality on `raw_release["native_consumer"]` and `raw_release["native_consumer"][target]`.

---

## 5. Genuine API vs. Controlled Fixtures and Verification Summary

- **Genuine API execution**: All production functions in `src/rs9/tf_pypi_nebular070_publish.py` (`build_candidates_bundle`, `materialize_qualification_evidence`, `materialize_raw_release_handoff`, `validate_raw_release_handoff_binding`, `check_prior_publish_runs`, `select_missing`, `verify_upload_dir`, `readback`, `qualify_native_target`, `main`, and `admit_nebular070_matrix` via `main(["admit-matrix", ...])`) execute directly without mocking internal validation logic.
- **Controlled test seams**:
  - `check_prior_publish_runs` and `select_missing` receive complete GitHub REST API run and job envelopes (including job `id`, `run_id`, `run_attempt`, and `head_sha`) via `api_get` and PyPI JSON/wheel payloads via `get`.
  - Local `qualify-native` CLI tests use `_controlled_native_consumer_driver` to exercise the real `qualify_nebular070` -> `consume_nebular_candidate` pipeline offline without host network or root namespace privileges.
- **Verification commands and results**:
  - Selected Python 3.13.12 (`PYTHONPATH=src python3.13 -m unittest -v ...` across all 13 Nebular/workflow test modules): **169 tests across 13 modules pass**.
  - AST and workflow parity verification: all 4 core Nebular publisher/consumer Python modules parse cleanly under Python 3.13.12 `ast.parse`, and `workflow_text("0.7.0") == workflow_text("0.6.1")` matches `.github/workflows/rs9-tfnf-pypi-publish.yml` byte-for-byte.

---

## 6. Remaining Limits, Liveness Boundaries, and Rollback

- **Withheld live inputs**: Real `0.7.0` upstream release artifacts, qualification run captures, and publication admission pins remain intentionally withheld (`status: "pending"`, `publication_admitted: false`) until an authorized operator qualification run is executed.
- **Intentional fail-closed liveness boundaries and operator recovery**:
  - **Prior `0.7.0` `resume` re-runs (`run_attempt >= 2`)**: While `0.7.0` `qualify` and `0.6.1` legacy runs support `run_attempt >= 2` by validating every attempt `1..run["run_attempt"]` returned by `filter=all`, any prior `0.7.0` `resume` run with `run_attempt >= 2` is refused (`TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED`) because re-running a publication job is forbidden by policy.
  - **Workflow-guarded unsupported dispatches (`0.7.0 publish`, `0.6.1 resume`)**: `_parse_prior_run_title_and_inputs` enforces `validate_workflow_dispatch`, so a completed mis-dispatch where only `Reject unsupported release and mode combination` ran and failed still fails closed in `check_prior_publish_runs`. If an operator accidentally triggers an unsupported `(release, mode)` dispatch on `main`, recovery requires verifying that only the dispatch-guard job ran and deleting that rejected workflow run record (`gh api -X DELETE /repos/Knowledge-Forge-AI/release-starport-9/actions/runs/<run_id>`) before dispatching `0.7.0` `resume`.
- **Rollback**: Reverting `src/rs9/tf_pypi_nebular070_publish.py` and `tests/test_tf_pypi_nebular070_publish.py` and removing `docs/evaluations/nebular070-publisher-guard-closure.md` restores the prior candidate snapshot cleanly.
