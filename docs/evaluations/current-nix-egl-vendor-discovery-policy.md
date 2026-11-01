# Policy Proposal: Optional Fixed EGL Guest Metadata in Nix FHS Discovery

## Status

- **Disposition:** OWNER-APPROVED-SOURCE-POLICY (hosted qualification pending)
- **Flags:** productionReady=false, nativeQualified=false (source policy adoption does not establish native or production qualification).
- **Authorization:** The owner approved this exact six-path metadata policy and one fresh current-distribution campaign on November 1, 2026. The previous three-campaign allowance remains fully consumed; this is one additional campaign, not a reset or retry allowance. Earlier logging, guard, observer and Python approvals remain valid. No signing or publication authority is added.

## Context

In current RS9 run `41349769055` at commit `41a95122171540ede3d27d2631064aad9348a9f2` (tree `3fc7ccd06ef25cca5ae27892f6248e7a43ffe2ab`), `authenticate`, `config`, `native`, `pages`, `pins`, `unit`, and `nix` (`aarch64-darwin`) passed, while both Linux Nix lanes (`x86_64-linux` artifact `13101356593`, `aarch64-linux` artifact `13101102461`) failed in `APPLICATION_SMOKE` with the same bounded 512-byte, 5-line inner stderr (`observedFatal: "EGL_BAD_PARAMETER while creating default display"`, `additionalMesaOrLibGLDebugLinesObserved: false`). Separately, public `P` run `41350364796` at commit `0be1ef1fa4ca7e7269dbcc120c167ce78bd7a8ad` (projection root `0e755ab9fc910a14517f9f74991394dffbd2c01daa3f548f47d92c8612d4ab52`) qualified all three GUI platforms and four scenarios (`A`, `B`, `C`, `C-signal`) using the same product and native assets on different Nix/FHS/display paths. Upstream `libglvnd` ICD enumeration documentation notes `/usr/share/glvnd/egl_vendor.d/50_mesa.json` as an example Mesa registration path while using compiled `sysconfdir`/`datadir` defaults unless overridden. Whether the RS9 Linux FHS guest exposes the expected GLVND/Mesa vendor and library links remains unobserved, and the runtime cause remains unproven.

## Decision

### 1. Fixed Guest IDs and Read Footprint

When explicitly opted in on current-generation Linux lanes, the existing single Node FS discovery process (`30s` timeout, no second subprocess, no new tool or dependency) observes at most eight fixed guest paths in order, represented in output only by closed fixed IDs:

| Fixed ID | Fixed Guest Path |
| --- | --- |
| `usr-share-mesa` | `/usr/share/glvnd/egl_vendor.d/50_mesa.json` |
| `etc-mesa` | `/etc/glvnd/egl_vendor.d/50_mesa.json` |
| `usr-lib-egl` | `/usr/lib/libEGL.so.1` |
| `usr-lib64-egl` | `/usr/lib64/libEGL.so.1` |
| `usr-lib-mesa` | `/usr/lib/libEGL_mesa.so.0` |
| `usr-lib64-mesa` | `/usr/lib64/libEGL_mesa.so.0` |
| `usr-lib-swrast` | `/usr/lib/dri/swrast_dri.so` |
| `usr-lib64-swrast` | `/usr/lib64/dri/swrast_dri.so` |

- **Maximum syscall footprint:** At most `8` `lstat` calls (`1` per fixed path) and at most `8` `readlink` calls (`fs.readlinkSync(path, {encoding: 'buffer'})`, `1` per leaf symlink).
- **Prohibited operations:** No leaf symlink follow (`stat`/`realpath`), no directory enumeration (`readdir`), no file open or content read (`open`/`read`/`readFile`), no JSON parsing, no ELF/library hashing, no driver loading, no display creation, and no request-supplied path list. Prefer no JSON contents over speculative broader probes.
- **Preserved baseline source:** `NODE_FS_SOURCE` (`sha256=72f295144b4a4c547b1e0f8e2282ab78d0b59201bd90fae6a1ebe05aa258ab39`) is preserved byte-for-byte. `NODE_FS_EGL_METADATA_SOURCE` (`sha256=572279120edb1854972972e170b55532e7ff6bca0e890aa671d5813507bff806`) is built at import via three exact-anchor insertions using only the already-bound `fs`, `path`, `STORE_PATH`, and `Buffer` bindings (no `require` or `process` calls).

### 2. Placement, Provenance, and Closed Schema (`rs9.nix-fhs-egl-guest-metadata.v1`)

- **Provenance (`script_sha256`):** Default and non-`True` calls execute and hash `NODE_FS_SOURCE`. Opt-in (`current_linux_egl_metadata=True`) calls execute and hash `NODE_FS_EGL_METADATA_SOURCE` across both passing and failing custody records.
- **Record placement:** Node attaches `egl_metadata` to the outer observation object on `"pass"` and `"partial"` emissions. Python strips `egl_metadata` before running the unchanged `_validate_observation(result)` check and stores validated `egl_metadata` as a top-level field on the custody record (`record["egl_metadata"]`, outside `record["result"]`). Default and non-`True` calls never emit or retain `egl_metadata`.
- **Observed entry shapes (`status == "observed"`):** `entries` must contain exactly the eight fixed IDs, each matching one closed shape:
  - `{"status": "present", "kind": "regular" | "directory" | "other"}`
  - `{"status": "present", "kind": "symlink", "target_class": "public-nix-store" | "fixed-guest-path" | "other"}`
  - `{"status": "bounded" | "error", "kind": "symlink", "target_class": "unavailable"}`
  - `{"status": "missing" | "inaccessible" | "error"}`
- **Error and UTF-8 target classification:**
  - `lstat` `ENOENT` maps to `"missing"`; `EACCES` and `EPERM` map to `"inaccessible"` (never claiming absence on access failure); all other `lstat` errors (including `ELOOP` and `ENOTDIR` on intermediate components) map to `{"status": "error"}`.
  - If `lstat` reports a symlink and `readlinkSync(guestPath, {encoding: 'buffer'})` throws, the entry is `{"status": "error", "kind": "symlink", "target_class": "unavailable"}`.
  - Raw symlink target bytes are checked on the `Buffer` before classification: the buffer must be non-empty, `<= 4096` bytes, contain no NUL (`0x00`), and decode as valid UTF-8 whose UTF-8 re-encoding equals the raw buffer. Otherwise the entry is `{"status": "bounded", "kind": "symlink", "target_class": "unavailable"}` and the buffer is discarded.
  - Valid UTF-8 targets containing any `..` segment classify as `"other"`. Otherwise lexical resolution (`path.posix.resolve(path.posix.dirname(guestPath), target)`) classifies matches to `STORE_PATH` as `"public-nix-store"`, matches to one of the 8 fixed guest paths as `"fixed-guest-path"`, and everything else as `"other"`. Raw target strings, guest paths, errno text, and stat numbers (`dev`, `ino`, `mode`, `uid`, `gid`, `size`, timestamps) are discarded immediately.

### 3. Closed Omission and Unavailability Reason Mapping

When `status` is `"omitted"` or `"unavailable"`, the object has the closed shape `{"schema": "rs9.nix-fhs-egl-guest-metadata.v1", "status": ..., "reason": ...}`:

| Record / Execution Path | Authority | `egl_metadata.status` | `egl_metadata.reason` |
| --- | --- | --- | --- |
| Node stdout JSON with `egl_metadata` exceeds `4 MiB` (`_MAX_OUTPUT_BYTES`); EGL block shed before record drop | Node | `"omitted"` | `"output-bound"` |
| Unexpected exception inside Node `observeEglEntries` / `attachEglMetadata` during `"pass"`/`"partial"` emission | Node | `"unavailable"` | `"observation-failed"` |
| Python `_write_record` canonical JSON with `"observed"` `egl_metadata` exceeds `64 KiB` (`_MAX_CUSTODY_BYTES`); EGL block shed before halving `records`/`samples` | Python only | `"omitted"` | `"custody-bound"` |
| Python `diagnostic_bytes` raises `ContractError` (`reason: "diagnostic-custody-withheld"`) | Python only | `"omitted"` | `"custody-withheld"` |
| Python `_write_record` catches `(OSError, ContractError)` and returns in-memory `"diagnostic-output-unavailable"` dict (never written) | Python only | `"unavailable"` | `"output-unavailable"` |
| Subprocess exits `0` with empty `stderr` and valid `"pass"`/`"partial"` `result`, but JSON lacks `"egl_metadata"` | Python only | `"unavailable"` | `"not-returned"` |
| Subprocess exits `0` with empty `stderr` and valid `"pass"`/`"partial"` `result`, but `"egl_metadata"` fails `_validated_egl` (including any forged Python-only reason sent from Node) | Python only | `"unavailable"` | `"validation-failed"` |
| `_validate_observation(result)` succeeds, but `result["status"] == "fail"` (including empty stdout `empty-observation` or Node `"fail"` even with a forged well-formed `egl_metadata`, which Python ignores), `exit_code != 0`, or `stderr` is non-empty | Python only | `"unavailable"` | `"discovery-failed"` |
| `_discovery_request(facts)` fails before subprocess launch (`invalid-source-bound-facts`) or subprocess/stream/JSON/`_validate_observation` raises (`bounded-observation-unavailable`) | Python only | `"unavailable"` | `"discovery-unavailable"` |

### 4. Bounds, Shedding Order, and Caller Eligibility

- **Bounds and shedding order:** The 30-second subprocess timeout, 4 MiB stdout cap, and 64 KiB custody cap are unchanged. On stdout pressure (`> 4 MiB`), `shedEglForOutput` replaces `egl_metadata` with `omitted/output-bound` first; only if the payload still exceeds 4 MiB does the existing record-dropping fallback run. On custody pressure (`> 64 KiB`), `_shed_egl_metadata` replaces an `observed` `egl_metadata` block with `omitted/custody-bound` first; only if the canonical record still exceeds 64 KiB does the existing `records`-then-`samples` halving loop run. Under the contract's literal shedding order, when old `records` alone exceed 4 MiB on stdout or 64 KiB in custody, `egl_metadata` is shed first (`omitted/output-bound` or `omitted/custody-bound`) and is not re-attached after `records` are dropped or halved, even though the truncated payload would then have room for the metadata. Because the retained `omitted/custody-bound` marker occupies ~95 bytes in the outer record, a payload within ~95 bytes of a halving step boundary can take one extra halving step to stay within 64 KiB.
- **Caller eligibility and predicate basis:** `record_fhs_gui_discovery` accepts keyword-only `current_linux_egl_metadata: bool = False` and enables the variant only when `current_linux_egl_metadata is True`. In `src/rs9/hosted_nix.py`, discovery runs at lines 444-447 (pre-patch line 441) before `prepare_smoke` at line 466 (pre-patch line 461), when `prepared` is still `None`. Moving discovery after `prepare_smoke` would alter existing call ordering and failure custody if store archive readback or `prepare_smoke` failed. Accordingly, `hosted_nix.py` extracts the generation/system clause of `_current_linux_initial_observation_enabled` into `_current_linux_lane(generation, system)` (`generation == CURRENT_GENERATION and system in {"x86_64-linux", "aarch64-linux"}`), shared with `_current_linux_initial_observation_enabled` and `_nix_application_environment`. At lines 444-447, current-generation authentication rests on `prepare_input` (line 354, pre-patch line 351) and `bind_catalog_product` (line 170, pre-patch line 167), which verify in-process `ReleaseCapture` proof (`authenticated_record_hash`) and bind all four current-generation release captures to `nix/theme-forge-current-202610-products.json` before any Nix build or FHS discovery runs, rather than on `prepare_smoke`. The owner must explicitly accept `prepare_input` / `bind_catalog_product` as the eligibility basis for this call site.
- **Test scope note:** `_execute_nix_success_fixture` in `tests/test_hosted_nix.py` patches `prepare_input`, so its lane matrix tests generation/system routing at the `execute` call site rather than `prepare_input` binding; `tests/test_current_nix_egl_vendor_discovery.py` separately verifies that unpatched `prepare_input` and `bind_catalog_product` refuse incomplete capture sets (`NIX_CAPTURE`), unauthenticated captures lacking fresh in-process byte authentication (`RELEASE_CAPTURE`), and authenticated captures with mismatched catalog coordinates (`NIX_CATALOG_BINDING`) before `record_fhs_gui_discovery` is reached.

## Consequences, Disclosures, Rollback, and Native Acceptance Plan

- **Mandatory disclosures:**
  1. The OS kernel resolves intermediate directory symlinks when accessing `/usr/...` and `/etc/...` before inspecting the leaf; leaf `lstat`/`readlink` is not physical intermediate-component sealing.
  2. Symlink target classification is purely lexical (`path.posix.resolve` without `..`).
  3. Presence of a symlink (`status: "present", kind: "symlink"`) does not prove that its target exists, is readable, or is valid.
  4. Fixed guest path presence or absence does not prove `libglvnd` compiled search prefixes, actual vendor JSON parsing, driver selection, ELF loadability, or the causal root of `EGL_BAD_PARAMETER`.
- **What would make this proposal wrong:** If the owner requires `prepare_smoke` capture authentication prior to EGL metadata opt-in (requiring discovery to move after `prepare_smoke`), or if `libglvnd` in the pinned Nixpkgs closure searches only store-specific compiled directories rather than `/usr/share/glvnd`/`/etc/glvnd`.
- **Rollback:** Revert the adopting six-file policy change through the ordinary PR route and verify the prior source behavior. Preparation already proved exact reversal/restoration and deletion of the two newly added files, followed by byte-identical forward reconstruction in an isolated tree. Rollback does not authorize a hosted retry.
- **Native acceptance plan:** After normal PR adoption, use the one authorized ordinary-main-push current-distribution campaign. Verify native custody joins and fixed-ID metadata on both Linux systems; preserve Darwin behavior and every required gate. No duplicate dispatch or corrective retry is authorized.
