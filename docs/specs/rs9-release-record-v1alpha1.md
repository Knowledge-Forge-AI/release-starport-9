# Release record and generic capture v1alpha1

Status: implemented specification in `src/rs9/release_core.py`, `src/rs9/records.py`, `src/rs9/command_policies.py`, and `src/rs9/npm_commands.py`. Separates generic release capture from tenant evidence profiles. Pure standard-library implementation; no external dependencies. Record hashes bind canonical JSON bytes; they do not establish signatures or authority.

## Overview

The generic release core (`rs9.release_core`) provides cryptographically authenticated ingestion of public GitHub releases without executing tenant code or guessing artifact filenames. It accepts a strict selection document, verifies raw bytes against GitHub metadata, tree blobs, and checksums, and produces an in-process `ReleaseCapture` container whose identity is bound by `rs9.release-record.v1alpha1`.

## Selection contract (`rs9.release-selection.v1alpha1`)

A selection document instructs `release_core` which assets and source files to capture and verify:

```json
{
  "schema": "rs9.release-selection.v1alpha1",
  "repository": "Owner/Repo",
  "tag": "v1.0.0",
  "prerelease": "reject",
  "checksums": "SHA256SUMS-1.0.0.txt",
  "payload_assets": [
    {
      "id": "linux-x64",
      "name": "app-1.0.0-x86_64.tar.gz",
      "format": "tar.gz",
      "platforms": ["x86_64-linux"],
      "command_policy": "native-executable",
      "commands": {"app": "bin/app"},
      "launchers": {"app": "bin/launcher"},
      "checksum_covered": true
    }
  ],
  "evidence_assets": [
    {
      "role": "wrapper",
      "name": "app-1.0.0.tgz",
      "checksum_covered": false
    }
  ],
  "source_paths": [
    "LICENSE",
    "package.json"
  ],
  "limits": {
    "asset_bytes": 1073741824,
    "capture_bytes": 2147483648,
    "source_bytes": 16777216,
    "members": 20000,
    "member_bytes": 268435456,
    "archive_bytes": 1073741824,
    "ratio": 1000
  }
}
```

### Selection rules

1. `repository`: Mandatory POSIX-safe repository identifier (`Owner/Repo`).
2. `tag`: Strict Git tag name without control characters, whitespace, traversal (`..`), or unsafe characters (`~^:?*[`).
3. `prerelease`: Must be `"allow"` or `"reject"`. Draft releases are always rejected by `release_core`.
4. `checksums`: Basename of the SHA256SUMS asset. Must be covered by release assets.
5. `payload_assets`: Nonempty list of tar.gz archives providing executable payloads. Each entry must have unique `id`, unique `name`, valid platforms, mapped commands, and optional `command_policy`.
6. `evidence_assets`: Supporting non-payload assets (e.g. npm tarballs, provenance documents, notices). Each has a unique `role` slug.
7. `source_paths`: Unique, relative POSIX paths to be captured from the tagged Git tree.
8. `limits`: Optional dictionary that may only **narrow** core default limits.
9. `command_policy`: Optional additive field on payload assets (`"native-executable"` or `"npm-package-bin"`, defaulting to `"native-executable"`). Closed validation is enforced by `rs9.command_policies`. Unknown policies are refused; `evaluate_profile` refuses profile/policy disagreement. If `"npm-package-bin"` is specified, declaring native launchers is rejected.

## Release record schema (`rs9.release-record.v1alpha1`)

The release record emitted by `authenticate_release` contains the complete audit identity of the captured release:

| Field | Type | Description |
|---|---|---|
| `schema` | string | Exact schema string `"rs9.release-record.v1alpha1"` |
| `selection_sha256` | string | 64-character hex SHA-256 of the canonical selection document |
| `repository` | table | Numeric GitHub `id` (positive int) and `full_name` (`Owner/Repo`) |
| `release` | table | Numeric GitHub `id`, `tag`, `draft` (always `false`), and `prerelease` (bool) |
| `tag` | table | Resolved `commit` SHA, `tree` SHA, `tag_objects` (annotated tag chain), and `target_basis` (`"sha-match"` or `"tag-ref"`) |
| `assets` | list | List of all captured assets with `name`, `github_asset_id`, `size`, `sha256`, `role`, and `checksum_covered` |
| `payloads` | list | Payload-specific entries with `id`, `platforms`, `command_policy` (`"native-executable"` or `"npm-package-bin"`), archive `root`, `commands` (mapping each command name to its record `{path, sha256, size, mode}`), `launchers`, `payload_manifest_sha256`, and `member_count` |
| `source_files` | list | Captured Git blobs with `path`, `blob` (SHA-1), `sha256`, and `size` |
| `limits` | table | Effective byte limits applied during capture and authentication |
| `source_times` | table | Optional immutable UTC timestamps from GitHub (`created_at`, `published_at`) |

## Sealed in-process `ReleaseCapture` and anti-forgery design

`authenticate_release` produces an in-memory `ReleaseCapture` container:
- Holds actual physical file descriptors, payload bytes, decoded manifests, and source maps.
- Possesses a private sentinel `_proof` created exclusively by `authenticate_release`.
- `authenticated_record_hash(capture)` validates the sealed sentinel and ensures that the in-memory record has not been mutated since authentication.
- When profile evaluation runs (`evaluate_profile`), it verifies that the captured payload `command_policy` matches the profile expectation (`"npm-package-bin"` for `npm-package-archive.v1alpha1` and `"native-executable"` for native/desktop profiles); any policy mismatch raises `ContractError("EVIDENCE_PROFILE")`.
- The profile result hash is registered directly into `capture._profile_results`.
- Planner validation strictly checks that `record_sha256(profile_result) in capture._profile_results`.

**Persisted audit limit**: Serialized JSON records are historical audit files, not capabilities. A persisted JSON release record cannot pass `authenticated_record_hash`, nor can a serialized profile result be injected without fresh in-process evaluation. Reauthorizing gates requires physical captured bytes and fresh in-process reauthentication.

## Archive inspection, hardlink rejection, and command policy layering

In `src/rs9/archives.py`, tar hard links (`member.islnk()` or `member.type in (tarfile.LNKTYPE, "1", b"1")`) are unconditionally rejected fail-safe before member visitors execute. This eliminates silent inspection gaps where unvisited link entries reference visited files, prevents unbounded memory retention tracking link maps, and ensures strict byte accounting.

Generic archive inspection records four physical properties for every mapped command: `{path, sha256, size, mode}`. Mode is an integer masked to `0o777`; size is the regular member byte count. These fields and payload `command_policy` extend v1alpha1 additively: downstream consumers do not close payload/command row keys. Legacy desktop shadow records retain their path/hash projection.

Execution policy delegation is managed by closed RS9 modules:
1. `rs9.command_policies`: Validates closed policy choices (`"native-executable"` vs `"npm-package-bin"`). Unknown policies are rejected; `evaluate_profile` separately rejects profile/policy disagreement.
2. For `"native-executable"`, commands and launchers must be regular files and executable (`mode & 0o111`).
3. For `"npm-package-bin"`, `rs9.npm_commands` validates declarative bin agreement with `package/package.json` (`validate_ecosystem_name`, safe relative POSIX paths) and verifies that each declared command has a valid UTF-8 Node shebang (`#!/usr/bin/env node`) on its bounded first line (`node_script_shape`). Direct capture also validates bins and shebangs.
4. RS9 wrappers invoke Node explicitly (`node-explicit`), safely accommodating observed upstream packages where bins are published with mode `0644` (such as Stellar Burst 0.6.1) without compromising strict native executable contracts (`0755` / `mode & 0o111`).
5. Undeclared package bins in `package.json` are recorded in profile results (`undeclared_bins`) but not exposed as commands.

## What would make this wrong

1. **Trust boundary**: Trusting unauthenticated remote assertions, client verdicts, or publisher signatures without hashing raw downloaded bytes against independent checksums and tree blobs.
2. **Timestamps limitation**: Relying on volatile API or collection timestamps for ordering or security checks; immutable upstream timestamps are recorded for audit purposes only and cannot prove temporal freshness on untrusted transport.
3. **Persisted audit limit**: Allowing saved JSON files to reauthorize publication gates, bypassing fresh in-process byte possession and sentinel validation.
4. **Hardlink tolerance**: Permitting archive hard links that allow uninspected archive entries to alias inspected binaries.
5. **Truncated source trees**: Accepting partial or truncated Git trees from the GitHub API.

## Local Links

- [ADR 0004: Ingestion core and evidence profiles](../adr/0004-ingestion-core-and-evidence-profiles.md)
- [ADR 0003: Authenticated ingestion and shadow adapters](../adr/0003-authenticated-ingestion-and-shadow-adapters.md)
- [Specification: Ingestion record v1alpha1](rs9-ingestion-record-v1alpha1.md)
- [Specification: Configuration v1alpha1](rs9-config-v1alpha1.md)
- [Specification: Publication plan v1alpha1](rs9-publication-plan-v1alpha1.md)
- [Architecture overview](../architecture.md)

Profile results use `rs9.evidence-profile-result.v1alpha1`, identifying the closed versioned profile and binding `release_record_sha256`, `intent_sha256`, and profile-owned `sections`. In-process result registration is a trusted-code boundary against accidental JSON substitution, not isolation from arbitrary Python code.
