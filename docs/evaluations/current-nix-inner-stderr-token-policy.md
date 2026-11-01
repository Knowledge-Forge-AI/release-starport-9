# Proposed Current-Linux-Nix Inner-Stderr Closed-Token Policy (`rs9.current-nix-inner-stderr-tokens.v1`)

## Status and Authority Boundary

- **Policy status**: `ADOPTED-NATIVE-QUALIFICATION-PENDING` (operator approval on 2026-11-01).
- **Authority**: The operator adopted this bounded diagnostic policy and authorized one ordinary main-push native campaign plus up to two independently reviewed corrective successors within unchanged approved limits. Run `41312396215` consumed the earlier separate campaign grant. New diagnostic classes, dependencies, runner/environment/permission, timeout, controller, signing or gate changes require separate authorization.

## Hosted Baseline Evidence and Non-Claims

In hosted workflow `RS9 Native Qualification` (`run_id`: `41312396215`, commit `8b16e65e05760db290fa078947fd9cc85ef05ad4`, tree `ae9f78722eafa9d4b9913ffa4091f25f1387957f`):

1. `unit_and_non_native_verification` failed on a test-only module-level replacement of the shared GPG-discovery helper in `tests/test_current_nix_environment_binding.py`. That unit fix is separately accepted in the PR39 draft baseline (`tests/test_current_nix_environment_binding.py`) and is preserved unchanged.
2. Both Linux Nix `application_smoke` lanes failed after ~213 seconds (`aarch64-linux` Scenario `B`, artifact `13086207737`, `213245 ms`; `x86_64-linux` Scenario `C`, artifact `13085858492`, `213320 ms`) despite derived harness `15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f` (`30772` bytes) and restored `XDG_DATA_DIRS: true` and `FONTCONFIG_FILE: true` at both `wrapper_entry` and `first_spawn`.
3. Both lanes recorded `inner_stderr_diagnostic` with `bytes: 512`, `lines: 5`, `complete: true`, `utf8_valid: true`, `withheld_reason: null`, `tokens: []`, and `tokens_omitted: 0` (`sha256` `6b757c284e206135be86f5499047c58d8b50e293b9fb673570a24232110ba626` on `aarch64-linux`; `8f346d618452ab3f84645d3743007406e2d597b21b8faa8be25e747c711b32ee` on `x86_64-linux`).
4. **Explicit non-claims**:
   - The actual raw 512-byte / five-line inner stderr text is **not** retained or available.
   - Outer `dbus-daemon-error` (`2`) and `no-such-file-marker` (`target_basename: "unknown"`) do **not** prove an actual missing program or root cause.
   - The 11 proposed marker classes are conditional literal grammar for future bounded observation, not claimed upstream log content.
   - `WEBKIT_DISABLE_COMPOSITING_MODE` and `WEBKIT_DISABLE_DMABUF_RENDERER` are already allowed upstream; no additional environment keys or gate weakenings are proposed.
   - Receipt-finalization and source-provenance validators remain unchanged; this proposal does not diagnose why a receipt was not written.

## Closed-Token Envelope Contract

- **Opt-in reader (`src/rs9/smoke_stream_tokens.py`)**: `read_inner_stderr(directory, platform, scenario, *, current_nix_tokens=False)` reads the held `O_NOFOLLOW` descriptor snapshot once (`<= 64 KiB`). Only when `current_nix_tokens is True` and `withheld_reason is None` does it attach `current_nix_tokens` computed from that same held `raw` byte snapshot:
  - `schema`: `"rs9.current-nix-inner-stderr-tokens.v1"`
  - `tokens`: sorted unique matched literals (`<= 8` via `MAX_TOKENS`)
  - `tokens_omitted`: `len(matched) - len(tokens)` (`>= 0`)
  - `non_admitting`: `True`
  - `native_qualified`: `False`
  - `causal_attribution_proven`: `False`
- **11-class closed vocabulary (`CURRENT_NIX_INNER_TOKEN_RULES`)**:
  - Same-line `dbus` + failure phrase: `dbus-config-read-failed`, `dbus-service-activation-failed`, `dbus-program-exec-failed`, `dbus-address-connect-failed`.
  - Non-causal reference markers: `dbus-machine-id-reference`, `portal-desktop-reference`, `portal-settings-reference`, `webkit-webprocess-reference`, `webkit-networkprocess-reference`, `sandbox-helper-reference`, `gsettings-schema-reference`.
  - No raw lines, paths, target basenames, PIDs, or environment values are emitted.
- **Caller scoping**: `collect_failure_diagnostics` passes `current_nix_tokens=True` only on the Linux `_CATEGORY_BINDINGS` branch when `current071 is True` (`initial_observation.get("profile") == CURRENT071_REPLAY_PROGRESS_PROFILE`). `current071_problems` alone, Darwin, historical `0.7.0`, and default callers omit `current_nix_tokens`.
- **Validation and 60 KiB shedding**:
  - `validate_inner_stream_tokens` preserves valid `current_nix_tokens` idempotently when `complete is True and withheld_reason is None`, drops invalid or ineligible `current_nix_tokens` while preserving the validated 10-key base record, and still refuses malformed base records or extra base keys.
  - In `src/rs9/application_smoke_diagnostic.py`, `_retain_failure` sheds `initial_run["inner_stderr_diagnostic"]["current_nix_tokens"]` first if the canonical diagnostic exceeds `MAX_DIAGNOSTIC` (`60 KiB`).

## Verification, Remaining Qualification, and Rollback

- **Verification**: Parent checks passed: 75 independent invariants; 236 candidate tests; 236 plus 48 repository-only tests; zero failures, errors, skips or forbidden native/signing calls. Full-suite discovery found 3,522 tests with zero import errors and no test bodies executed, using four fixed read-only Git metadata fixtures.
- **Remaining qualification**: Required current native gates and source/custody/caller/client joins must pass before production publication; this policy itself grants no qualification.
- **Rollback**: Restore `src/rs9/smoke_stream_tokens.py` and `src/rs9/application_smoke_diagnostic.py` to baseline and remove `tests/test_current_nix_inner_stderr_tokens.py` and `docs/evaluations/current-nix-inner-stderr-token-policy.md`.
