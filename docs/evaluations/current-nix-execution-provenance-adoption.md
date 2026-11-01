# Current 0.7.1 Linux Nix Caller and Execution-Source Provenance Join

## Status

Owner approved this bounded current Linux Nix test-environment and execution-source policy on November 1, 2026, including one ordinary main-push native campaign. The selected caller and fail-closed custody join are adopted in source; required hosted native and application qualification remains pending. This source adoption does not establish native, FHS or causal proof.

## Empirical Baseline (`305cdaec66de9e34f855753581fcca30adab477d`, Run `41273757874`)

In hosted run `41273757874` (attempt `1` on commit `305cdaec66de9e34f855753581fcca30adab477d`, tree `79b0a2201be98037fe5e00ce7a3bf57114bba29b`), `rpm2`, `deb2`, `pacman`, `nix-aarch64-darwin`, and Pages passed, while both Linux Nix lanes failed during `application_smoke` after ~213 seconds (`213311 ms` on `aarch64-linux` scenario `B`, artifact `13070234275`; `213169 ms` on `x86_64-linux` scenario `C`, artifact `13070616319`). In both lanes:

- Finalization completed (`status: "complete"`, `phase: "complete"`, `spawned: true`, `exitObserved: true`, `applicationReceiptObservation: "absent-at-read"`, `applicationReceiptCopy: "not-attempted"`).
- `source_profile` bound the unmodified `nebular071` closure (`f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a`, tree `6e3561855f6ee0093fb709488ad976b69bf501d2`, `native-rc-smoke.mjs` SHA-256 `874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69`, `30732` bytes).
- Both `XDG_DATA_DIRS` and `FONTCONFIG_FILE` were `true` at `wrapper_entry` and `false` at `first_spawn`.
- Replay remained suppressed (`not-run`, `original-harness-not-passed`), and no root cause was proven.

## Caller Selection and Shared Forwarding Route

The call route is `src/rs9/hosted_nix.py:_verify_final_nebular_runtime` -> `src/rs9/hosted_smoke.py:verify_nebular_runtime` -> `src/rs9/application_smoke_diagnostic.py:execute_application_smoke`:

1. `_verify_final_nebular_runtime` computes `current_linux_observation = _current_linux_initial_observation_enabled(generation, system, prepared)` and passes `current_nix_environment_transform=current_linux_observation` alongside `diagnostic_initial_observation=current_linux_observation`.
2. Selection occurs **only** when `generation == "theme-forge-current-202610"`, `system in {"x86_64-linux", "aarch64-linux"}`, and `prepared` carries authenticated current `capture` and `fixture_capture` bindings.
3. `verify_nebular_runtime` and `execute_application_smoke` default `current_nix_environment_transform: bool = False`, reject non-boolean values fail-closed (`ContractError("APPLICATION_SMOKE", ...)`), and leave historical `0.7.0`, `aarch64-darwin`, container/RPM/DEB/pacman/wheel callers, and default untransformed smoke calls untouched.

## Fail-Closed Provenance Contract (`rs9.current-nix-execution-source-provenance.v1`)

When `current_nix_environment_transform` (or `diagnostic_current_nix_environment_transform`) is active, `_attempt` and `_scenario_run_projection` evaluate and bind `execution_source` under schema `"rs9.current-nix-execution-source-provenance.v1"`:

- **Required for `"status": "verified"` on a passing scenario:**
  - Readable, untruncated `initial-observation.json` with zero `observer-fault`, `stream-fault`, and `write-failure` counts, `"status": "completed"`, and all four completion phase events (`candidate/exited`, `receipt/finalized`, `run-record/finalized`, `run-smoke/returned`) without failure phase events.
  - Exact `nebular071` `source_profile` (`harness_sha256` `874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69` and seven-module closure digests).
  - Exact `execution_transform` carrier (`schema` `"rs9.current-nix-smoke-environment-transform.v1"`, `transform_id` `"current071-nix-inherited-xdg-fontconfig-v1"`, `upstream_sha256` `874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69` / `30732` bytes, `executed_derived_sha256` `15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f` / `30772` bytes, `restored_env_keys` `["XDG_DATA_DIRS", "FONTCONFIG_FILE"]`, `modified_from_upstream: true`, `non_admitting: true`, `fhs_origin_proven: false`, `native_qualified: false`, `causal_attribution_proven: false`).
  - Boolean-only two-key `environment_presence` with `XDG_DATA_DIRS: true` and `FONTCONFIG_FILE: true` at both `wrapper_entry` and `first_spawn` (never raw values or paths).
- **Successful custody projection:** Transformed passing scenarios return `{"scenario", "receipt_sha256", "executable_sha256", "execution_source"}`, carried by `verify_nebular_runtime` into `nix-output-receipt.json` under `native_smoke.scenarios`, while `source_bindings` preserves the upstream `nebular071` hashes. Untransformed passing scenarios retain the exact three-key projection `{"scenario", "receipt_sha256", "executable_sha256"}`.
- **Failure handling and replay suppression:** If process/receipt execution passes (`exit_code: 0`) but provenance verification fails, `_bind_attempt_execution_source` fails the attempt closed with `cause: "execution-source-unverified"` and `reason_token: "execution-source-unverified"`. If the application itself fails, original failure `cause` and `reason_token` are preserved alongside `initial_run.execution_source` (or a compact `omitted: "diagnostic-size-cap"` marker after larger optional fields are shed at the 60 KiB cap), and transformed attempts never execute cross-attempt `run_replay` reruns (`not-run` with `original-harness-not-passed` when finalization is clean, or `original-cleanup-unproven` otherwise).

## Non-Claims and Rollback

 Provenance metadata (`non_admitting: true`, `fhs_origin_proven: false`, `native_qualified: false`, `causal_attribution_proven: false`) is non-admitting diagnostic custody, not FHS, causal, or native qualification authority. To roll back, remove `tests/test_current_nix_execution_provenance.py` and this evaluation note, and revert the `current_nix_environment_transform` forwarding and `execution_source` join in `src/rs9/hosted_nix.py`, `src/rs9/hosted_smoke.py`, `src/rs9/application_smoke_diagnostic.py`, `tests/test_hosted_nix.py`, and `tests/test_hosted_smoke.py`.
