# RS9 Nebular 0.7.0 Prior-Run Step-Profile Guard Closure Evaluation

## 1. Scope and Baseline

Bounded prior-run step-profile validation repair in the Theme Forge Nebular Fusion `0.7.0` PyPI publisher (`src/rs9/tf_pypi_nebular070_publish.py`) and its unit test suite (`tests/test_tf_pypi_nebular070_publish.py`).

- **Baseline**: `HEAD` `b2013a429dcb08aeeb3b374f08a5267db15aa1bc` (tree `e4bb9d672084ead789b6ba4ab2f6ca0280bfb2f7`).
- **Touched paths (exact 3-file scope)**:
  1. `src/rs9/tf_pypi_nebular070_publish.py` (`552bfa861c9dd4f8437df5598fae7a8be51196084af4a484fce0cb09c12c3b4f` -> `87ac4cfee0c60d0eb46d7a6ae0c89723b88f3a9691c55e3a0bbee5a81fb6eb8d`)
  2. `tests/test_tf_pypi_nebular070_publish.py` (`7f3fec51b3e710e9f045e69dc84a76a1a0ec65c351efbf85e59815c74abc606e` -> proposal `010f3429eb587f4e8092f78fc716f84f9710dbad4388416b9bca6e5e0bf6ad3c` -> post-review `045fe1e0a5acbac5beff0d40e792650a54bb1d3857dd6cf86f926513004fcca9`)
  3. `docs/evaluations/nebular070-prior-step-profile-closure.md`
- **Untouched invariants**: `.github/workflows/rs9-tfnf-pypi-publish.yml` (`98e51826ab03f3fc1bd1438a3d92bb67caef88c5147f34aa188a1df6491b415a`) matches `workflow_text("0.7.0")` and `workflow_text("0.6.1")` byte-for-byte. All other sources, dependencies, runner policies, and historical evaluations are untouched.

## 2. Exact Guard Gap

Previously, `_validate_prior_run_jobs_map` checked step shape when `"steps"` was present (`isinstance(step, dict)`, non-empty `name`, `status == "completed"`, `conclusion in VALID_WORKFLOW_JOB_CONCLUSIONS`, and `conclusion == "skipped"` when the job was `"skipped"`), while `_validate_070_resume_prior_run` required `"Publish package distribution to PyPI"` to be `"skipped"` on prior failed `0.7.0` `resume` runs. Two gaps remained:

1. **Unconstrained active step names**: Known `0.7.0` or legacy `0.6.1` jobs could record arbitrary active (`conclusion != "skipped"`) step names — such as an injected upload/execution step in a qualification job, or an unexpected active upload step alongside a skipped canonical publish step in a resume job — without failing `TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED`.
2. **Omitted or empty steps on active `0.7.0` jobs**: Non-resume active `0.7.0` jobs passed even when `"steps"` was omitted or `steps == []`.

## 3. Profile Rules and Explicit Limits

1. **Maintained 10-job profile map (`WORKFLOW_STEP_PROFILES`)**:
   - Maps all 10 `ALL_KNOWN_WORKFLOW_JOB_NAMES` to ordered `(step_name, is_action)` tuples across the 7 current `0.7.0` jobs (`CURRENT_070_PROFILE_JOB_NAMES`: `Reject unsupported release and mode combination`, `Build and Verify Nebular 0.7.0 Candidate Bundle`, the 3 `Native consumer 0.7.0 (<target>)` jobs, `Qualification matrix gate 0.7.0`, and `Attended Nebular 0.7.0 PyPI publication resume`) and 3 legacy `0.6.1` jobs (`LEGACY_061_JOB_NAMES`: `Build and Verify Native Darwin Wheel`, `Native macOS ARM64 installed consumer and Scenario A`, and `Trusted Publishing to PyPI`).
2. **Runner and action post-step allowance (`WORKFLOW_STEP_PROFILE_ALLOWED_NAMES`)**:
   - Permits declared `step_name` values, runner-owned `"Set up job"` and `"Complete job"`, and `"Post <step_name>"` **only** for declared `uses:` steps (`is_action is True`). `run:` steps (`is_action is False`) may not produce `"Post <step_name>"` records.
3. **Presence and conclusion checks (`_validate_prior_run_job_steps`)**:
   - **Current active `0.7.0` jobs**: When `job_name in CURRENT_070_PROFILE_JOB_NAMES` and `job_conclusion != "skipped"`, `"steps"` must be a non-empty `list`; omitted or empty step lists fail with `TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED`.
   - **Skipped jobs (`job_conclusion == "skipped"`)**: May omit `"steps"` or supply `steps == []`; any supplied steps must have `conclusion == "skipped"`.
   - **Unknown skipped vs. active steps**: An unknown step with `conclusion == "skipped"` is explicit non-execution and is accepted. Any step with `conclusion != "skipped"` whose `name` is not in `WORKFLOW_STEP_PROFILE_ALLOWED_NAMES[job_name]` fails with `TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED`.
   - **Historical `0.6.1` compatibility**: Jobs in `LEGACY_061_JOB_NAMES` may omit `"steps"` or supply `steps == []`, while any supplied active step names are verified against `WORKFLOW_STEP_PROFILE_ALLOWED_NAMES[job_name]`.
   - Existing run-envelope, per-attempt job-binding, DAG, release-binding, and qualification-inputs descriptor guards remain intact.
4. **Scope limits**:
   - `WORKFLOW_STEP_PROFILES` is a bounded, maintained profile aligned with the current `0.7.0` generator and maintained `0.6.1` job definitions; it does not claim full historical step completeness, inspect remote workflow YAML blobs, or add a YAML parser dependency.
   - This snapshot remains subject to final root verification before publisher acceptance.

## 4. Verification and Review Sequence

```bash
PYTHONPATH=src python3.13 -m unittest -v \
  tests.test_tf_pypi_nebular070_publish tests.test_tf_pypi_nebular \
  tests.test_nebular070_gate1 tests.test_nebular070_gate1_roundtrip \
  tests.test_tf_pypi_nebular070_gate2 tests.test_tf_pypi_nebular_successor \
  tests.test_wheel_nebular_successor tests.test_tf_pypi_successor_release \
  tests.test_nebular_host_state tests.test_nebular_legal_boundary \
  tests.test_nebular_lineage tests.test_nebular_callers tests.test_tf_pypi_workflow
```

- **Tests**: `170` tests across `13` modules pass (`OK`) under Python `3.13.12` (`PEP 701` valid), including `test_prior_step_profiles_match_generated_jobs_and_reject_unknown_active_steps` (`0.7.0`/`0.6.1` `(step_name, is_action)` parity; positive runner/post, omitted/empty/populated `0.6.1`, omitted/empty skipped `0.7.0`, and unknown skipped steps; negative unknown active `0.7.0` qualify/resume/legacy `0.6.1` steps, fabricated `Post <name>` on a `run:` step, and omitted/empty `steps` on active `0.7.0`) and `_fill_current_profile_steps` across fixtures (enabled in negative loop except `resume-missing-steps`).
- **Static & workflow checks**: Python `3.13.12` `ast.parse` passes on both modified files; `.github/workflows/rs9-tfnf-pypi-publish.yml` remains exact (`98e51826ab03f3fc1bd1438a3d92bb67caef88c5147f34aa188a1df6491b415a`).
- **Review sequence**: Root accepted the design after isolated postimage testing (`170/13`). `produce` authenticated the proposal postimages and verified `170/13`; dispatcher-owned Opus `post_work` review confirmed the module guard (`87ac4cfee0c60d0eb46d7a6ae0c89723b88f3a9691c55e3a0bbee5a81fb6eb8d`) and raised 5 advisory test/doc findings; `revise_close` applied those fixes and re-verified `170/13` with no second independent review.

## 5. Rollback

Restore `src/rs9/tf_pypi_nebular070_publish.py` (`552bfa861c9dd4f8437df5598fae7a8be51196084af4a484fce0cb09c12c3b4f`) and `tests/test_tf_pypi_nebular070_publish.py` (`7f3fec51b3e710e9f045e69dc84a76a1a0ec65c351efbf85e59815c74abc606e`) to `HEAD` (`b2013a429dcb08aeeb3b374f08a5267db15aa1bc`) and remove `docs/evaluations/nebular070-prior-step-profile-closure.md`.
