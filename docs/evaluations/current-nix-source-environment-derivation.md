# Current 0.7.1 Nix Smoke Environment Source Derivation

## Status

Owner approved this bounded execution-transform policy on November 1, 2026. The authenticated current 0.7.1 Linux Nix caller selects it explicitly; shared defaults, historical 0.7.0, Darwin and other packaging callers remain untransformed. The carrier stays non-admitting. Required hosted native and application qualification remains pending.

## Provenance and Exact Transform Identity

The transform operates only on the authenticated upstream `tools/native-rc-smoke.mjs` entry module from `Knowledge-Forge-AI/theme-forge-nebular-fusion` (`AGPL-3.0-or-later`, retained at `tests/fixtures/current071-native-rc-smoke.mjs.txt`):

- **Upstream commit:** `f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a` (`v0.7.1`)
- **Upstream tree:** `6e3561855f6ee0093fb709488ad976b69bf501d2`
- **Upstream `tools/native-rc-smoke.mjs` SHA-256:** `874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69` (`30732` bytes, Git blob `cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f`)
- **Single anchor:** `"export const SMOKE_INHERITED_ENV_KEYS = Object.freeze([\n"`
- **Exact insertion:** `"  \"XDG_DATA_DIRS\",\n  \"FONTCONFIG_FILE\",\n"` (`40` UTF-8 bytes immediately after the anchor)
- **Derived `native-rc-smoke.mjs` SHA-256:** `15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f` (`30772` bytes)

All other keys stripped by `buildSmokeEnvironment` (`LD_LIBRARY_PATH`, `GIO_EXTRA_MODULES`, `GDK_PIXBUF_MODULE_FILE`, `GSETTINGS_SCHEMA_DIR`, credentials, and ambient caller state) remain uninherited, and WebKit/software-GL environment assignments remain unchanged.

## Authentication and In-Memory Loader Seam

1. `src/rs9/replay_progress_wrapper.mjs` authenticates the unmodified seven-file `CURRENT071_PROFILE` closure and `package.json` support pin on disk before any derivation is attempted.
2. Only when `--rs9-current-nix-environment-transform current071-nix-inherited-xdg-fontconfig-v1` is paired with `--rs9-initial-observation-kind initial-observation` on an authorized current-Linux target (`linux-arm64` scenario `B`, `linux-x64` scenarios `C` and `C-signal`) does the wrapper invoke `deriveCurrentNixSmokeModule` in `src/rs9/current_nix_smoke_environment.mjs`.
3. `deriveCurrentNixSmokeModule` requires an explicit validated target context (`transformId`, `nebular071` profile, and allowed Linux platform/scenario), re-verifies the `30732`-byte upstream buffer (length, SHA-256, and Git blob), verifies a single anchor occurrence, produces the `30772`-byte buffer, and verifies its `15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f` digest; `replay_progress_wrapper.mjs` independently re-checks the derived byte length and SHA-256 before ESM loader hooks are installed.
4. `installAuthenticatedLoader` serves the derived bytes only in memory for the `native-rc-smoke.mjs` entry URL. The on-disk checkout and `SMOKE_SOURCE_READBACKS` / `CURRENT071_REPLAY_PROGRESS_PROFILE` pins remain untouched.

## Separate Closed Provenance Carrier

When the transform is active, `initial-observation.json` retains `source_profile.harness_sha256` at the original upstream digest (`874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69`) and emits a separate closed `execution_transform` object validated by both `validateCurrentNixEnvironmentCarrier` and `_read_initial_observation`:

- `schema`: `"rs9.current-nix-smoke-environment-transform.v1"`
- `transform_id`: `"current071-nix-inherited-xdg-fontconfig-v1"`
- `mode`: `"execution-transform-and-observation"`
- `target_module`: `"native-rc-smoke.mjs"`
- `upstream_sha256` / `upstream_bytes`: `874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69` / `30732`
- `executed_derived_sha256` / `executed_derived_bytes`: `15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f` / `30772`
- `restored_env_keys`: `["XDG_DATA_DIRS", "FONTCONFIG_FILE"]`
- `modified_from_upstream`: `true`
- `non_admitting`: `true`
- `fhs_origin_proven`: `false`
- `native_qualified`: `false`
- `causal_attribution_proven`: `false`

Default initial observation (`expected_execution_transform=False`) rejects any `execution_transform` carrier; opt-in transform execution (`expected_execution_transform=True`) requires the exact closed carrier above.

## Non-Claims and Rollback

- **No causal or native qualification claim:** In run `41269854155` (attempt `1` on source commit `8f75dea53843c883748382d843a95a5fe21cb577`, tree `2053c04910de0ea92448f1015543f86fc02ebe02`), both `aarch64-linux` (scenario `B`) and `x86_64-linux` (scenario `C`) failure summaries record `XDG_DATA_DIRS` and `FONTCONFIG_FILE` present at `wrapper_entry` and absent at `first_spawn`, alongside cause `dbus-session-failure`, harness problem categories `application-bound-killed`, `application-exit-nonzero`, and `receipt-not-written` (plus `derived-asset-not-written` on `x86_64-linux`), and replay `not-run` (`original-cleanup-unproven`). Restoring those two keys is an experimental hypothesis seam, not proof of failure cause, FHS-origin provenance, or native release qualification.
- **Rollback:** Remove `src/rs9/current_nix_smoke_environment.mjs`, `tests/test_current_nix_smoke_environment.mjs`, `tests/test_current_nix_environment_binding.py`, `tests/fixtures/current071-native-rc-smoke.mjs.txt`, and this note, and revert the optional transform hooks in `src/rs9/replay_progress_wrapper.mjs` and `src/rs9/application_smoke_diagnostic.py`.
