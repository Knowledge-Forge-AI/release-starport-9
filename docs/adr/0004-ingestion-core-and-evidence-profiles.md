# ADR 0004: Ingestion core and evidence profiles

Status: decided; implemented in `rs9.release_core` and `rs9.records`. Replaces the composite Foundation 2 ingestion approach with generic release capture and closed evidence profiles. No live publication or publisher claims authorized.

## Context

Foundation 2 bound release authentication directly to Nebular's Tauri-desktop layout in `rs9.ingestion`. While that proved end-to-end byte authentication against a real release, it conflated generic GitHub release mechanics (repository verification, annotated tag chains, tree blobs, asset checksums) with tenant-specific artifact inspection and legal evidence reconciliation.

Several critical architectural issues emerged from that prototype:
1. **Archive hardlink hazards**: Tar archives can legally contain hard links. If members are inspected by visitors, hard links could allow uninspected paths to share inodes with inspected files, introduce silent inspection gaps, create memory-retention issues while tracking link maps across large archives, and corrupt uncompressed size accounting.
2. **Replay vulnerability of serialized records**: Storing an authentication result as a JSON document creates a risk that callers treat the JSON file as an authorization token. A saved JSON record is an audit log of past observation, not an active cryptographic capability.
3. **Tenant artifact guessing**: Ingesting releases by guessing filenames or executing tenant-provided scripts violates RS9's declarative design and invites arbitrary code execution.
4. **Tenant licensing conflicts**: Upstream projects may exhibit internal licensing discrepancies (such as Nebular's npm package declaring `AGPL-3.0-or-later OR Commercial` while Git source and release archives declare `AGPL-3.0-or-later`). RS9 cannot invent resolution for such legal conflicts.

## Decision

### 1. Canonical generic release core (`rs9.release_core`)

Extract reusable, bounded release capture and byte authentication into `src/rs9/release_core.py`:
- **Selection contract (`rs9.release-selection.v1alpha1`)**: Explicit repository (`Owner/Repo`), Git tag, prerelease policy (`allow` or `reject`), checksums asset name, payload asset list, evidence asset list, source file paths, and optional bounded limits.
- **Release record contract (`rs9.release-record.v1alpha1`)**: Cryptographically binds the numeric GitHub repository ID, numeric release ID, tag object chain, resolved commit SHA, tree SHA, regular source file blobs (recomputed `blob <len>\0<data>` SHA-1), release asset sizes and GitHub SHA-256 digests, independent SHA256SUMS verification for every covered asset, archive root names, command paths, launcher paths, and canonical archive payload manifest hashes.
- **Strict byte limits**: Enforces positive bounded limits (`DEFAULT_LIMITS`: 1 GB asset size, 2 GB total capture, 16 MB source files, 20,000 archive members, 256 MB member size, 1 GB decompressed archive, 1000:1 compression ratio). Tenant configurations may only narrow these bounds.

### 2. Unconditional archive hardlink rejection

In `src/rs9/archives.py`, tar hard links (`member.islnk()` or `member.type in (tarfile.LNKTYPE, "1", b"1")`) are unconditionally rejected fail-safe with `ContractError("UNSAFE_LINK", "Archive hard links forbidden")` before any member visitor runs.

Because all supported archive profiles inspect members, rejecting hard links completely avoids:
- Silent inspection gaps where unvisited link entries reference visited files;
- Unbounded memory retention from storing hardlink inode targets;
- Ambiguous decompressed size accounting across linked archive members.

Safe relative symlinks within the archive root remain supported. Archive manifests and hash calculations for archives without hard links are preserved identically.

### 3. Closed RS9 evidence profiles

Tenant evidence inspection is separated from the generic core into explicit, closed profiles:
- `tauri-desktop-archive.v1alpha1`: Inspects bundled Linux and macOS desktop archives, extracting ELF binaries, shared library dependencies, desktop entries, and tagged PNG icon assets.
- `npm-package-archive.v1alpha1`: Inspects published npm package tarballs, package manifest metadata, and legal evidence wrappers.

Arbitrary tenant profile code, arbitrary shell hooks, and heuristic filename guessing are prohibited. Stellar renderers are explicitly excluded.

### 4. Declarative `[evidence]` schema amendment in `releases.toml`

The `releases.toml` configuration format (`rs9.releases.v1alpha1`) is amended to support an `[evidence]` table:
- `checksums`: Exact basename or version template (e.g. `SHA256SUMS-{version}.txt`).
- `profile`: Closed profile identifier (`tauri-desktop-archive.v1alpha1` or `npm-package-archive.v1alpha1`).
- `assets`: Nonempty list of tables specifying exact `{role, name}` bindings with `{version}` templating.

**Explicit behavioral rule**: The `[evidence]` table is optional for configuration normalization and validation (`rs9.contract validate` and `normalize`), but **REQUIRED** for release authentication (`rs9.release_core.authenticate_release`). A release configuration lacking `[evidence]` can be normalized as planning intent but cannot be authenticated into a `ReleaseCapture`.

### 5. In-process `ReleaseCapture` container and sealed authentication

`authenticate_release` returns a transient in-process `ReleaseCapture` instance holding:
- `record`: The canonical `rs9.release-record.v1alpha1` dictionary;
- `archives`: Mapped paths to authenticated archive payloads;
- `source`: Tagged source file contents;
- `manifests`: Decoded archive manifests;
- `metadata`: Per-asset size and SHA-256 mappings;
- `payloads`: Raw bytes of evidence payloads;
- `root`: Confined scratch directory containing physical files;
- `_proof`: A private sealed sentinel ensuring in-process instantiation.

`authenticated_record_hash(capture)` verifies the private sentinel proof and checks that the canonical record hash matches `capture._record_hash`. Downstream profile results evaluated via `evaluate_profile` register their SHA-256 in `capture._profile_results`. This trusted-code mechanism rejects substituted JSON records: persisted JSON files represent historical audit records, not capabilities. Persisted audit JSON cannot reauthorize publication gates and requires offline reauthentication and fresh re-evaluation before a new plan can proceed. Record hashes bind canonical JSON bytes; they do not establish signatures or authority.

### 6. Verification and live reauthentication evidence

Read-only genericity and byte-compatibility evidence is recorded in the [Foundation 3 candidate](../foundation3-candidate.md).

### 7. Unresolved Nebular license conflict

The genuine license discrepancy in Nebular 0.6.1 between the published npm package (`AGPL-3.0-or-later OR Commercial`) and the repository source/archives (`AGPL-3.0-or-later`) remains open and unresolved. RS9 faithfully records both observations without inventing an artificial resolution. Live publication remains blocked until tenant authorities resolve the discrepancy.

## Consequences

- Ingestion core is reusable across all tenants without importing tenant-specific heuristics.
- Security posture is hardened against link-based archive attacks and serialized token replay attacks.
- Release authentication requires real in-process bytes, preventing synthetic or forged JSON records from bypassing publication gates.
- No live compatibility or publisher claims are made without captured and independently authenticated bytes.

## Local Links

- [ADR 0003: Authenticated ingestion and shadow adapters](0003-authenticated-ingestion-and-shadow-adapters.md)
- [ADR 0005: Publication state, planner, and receipts](0005-publication-state-planner-and-receipts.md)
- [Specification: Release record v1alpha1](../specs/rs9-release-record-v1alpha1.md)
- [Specification: Ingestion record v1alpha1](../specs/rs9-ingestion-record-v1alpha1.md)
- [Specification: Configuration v1alpha1](../specs/rs9-config-v1alpha1.md)
- [Architecture overview](../architecture.md)
