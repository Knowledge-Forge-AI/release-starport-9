# Authenticated input record v1alpha1

Status: implemented candidate for the Nebular shadow profile, updated for Foundation 3. Canonical JSON uses sorted keys, two-space indentation, UTF-8, LF and a final newline. Record hashes bind canonical JSON bytes; they do not establish signatures or authority. The captured HTTP receipt is separate scratch evidence.

## Relationship to release core (`rs9.release-record.v1alpha1`)

In Foundation 2, `rs9.ingestion.v1alpha1` captured both GitHub release metadata and Nebular-specific desktop/license evidence in a single composite record. In Foundation 3:
- Generic release selection, GitHub API capture, and byte verification are extracted into `rs9.release_core` and specified by [rs9-release-record-v1alpha1](rs9-release-record-v1alpha1.md).
- Profile-specific evidence (desktop integration, ELF dependencies, legal wrapper evidence) evaluates via `rs9.profiles.evaluate_profile` on top of generic capture and registers in `capture._profile_results`.
- `rs9.ingestion.v1alpha1` remains supported for backward compatibility with the Nebular 0.6.1 shadow projection.

## Schema allowlist (`rs9.ingestion.v1alpha1`)

`rs9.ingestion.v1alpha1` has this explicit output field allowlist:

| Field | Bound evidence |
|---|---|
| `repository` | Exact full name and numeric GitHub repository id |
| `release` | Numeric release id, selected tag, draft/prerelease state |
| `tag` | Resolved commit/tree, annotated tag object chain, target comparison basis |
| `assets` | Tenant asset id/name/platforms, GitHub asset id, size/SHA256, archive root, commands/launchers, manifest hash and member count |
| `evidence_assets` | Checksums, provenance, SPDX, notices and npm wrapper asset identities/digests |
| `source_files` | Tagged path, recomputed Git blob SHA1, SHA256 and byte length |
| `payload_license_copies` | Exact project license path, source relationship and agreeing byte hash |
| `license` | Exact declarations, reconciliation status and syntax-only limitation |
| `npm_support` | Wrapper identity, digest, GitHub attachment parity, registry integrity agreement, legal-file hashes and safe payload manifest binding |
| `icon` | Tagged source relationship, commit/hash and derived square hicolor size |
| `limits` | Freshness, self-asserted provenance and acceptance limitations |

## Verification and capture rules

Asset presence is exact and unambiguous. Each uploaded required asset needs a GitHub `sha256:` digest. Downloaded bytes must match size and digest; authenticated SHA256SUMS must independently agree for every non-self selected asset. SHA256SUMS uses strict lowercase hexadecimal, two spaces and unique filenames. Drafts fail; prereleases follow tenant policy. Lightweight and bounded annotated tags are supported. Branch-valued release targets use the resolved tag as authority; SHA-valued targets must agree. A truncated recursive source tree fails closed.

Tagged source files must be regular Git blobs, with locally recomputed blob identities matching the captured tree. Current project license copies at the archive root (or app Resources directory) must match their tagged source bytes. Publisher provenance assertions are cross-checked where present, without claiming independent signer authentication.

### Archive inspection and hardlink rejection

Tar hard links (`member.islnk()` or `member.type in (tarfile.LNKTYPE, "1", b"1")`) are unconditionally rejected with `ContractError("UNSAFE_LINK", "Archive hard links forbidden")` before any member visitor runs. Disallowing hard links prevents silent inspection gaps where linked members could bypass validation, eliminates memory retention overhead from inode graphs, and ensures strict byte accounting.

### Legal evidence and license status

The supporting npm wrapper is hash-equal to its GitHub attachment, agrees with registry SHA-512 integrity, and is safety-inspected through the same archive code. It is legal evidence, not a package input for packaging adapters.

The Nebular 0.6.1 npm package contains a genuine license conflict: the published `package.json` declares `AGPL-3.0-or-later OR Commercial`, while tagged repository source files and tarball license copies declare `AGPL-3.0-or-later`. This conflict remains **unresolved**; RS9 records both observed declarations without inventing an artificial legal resolution. Live compatibility cannot be claimed without captured bytes.

### Sealed in-process `ReleaseCapture` requirement

A persisted JSON ingestion record is an audit document, not an executable capability. Evaluating the `release.authenticated` gate requires an in-process `ReleaseCapture` container holding the actual captured bytes and archive handles. Offline reauthentication from physical captured bytes is strictly required before any new plan can proceed.

Parent live verification confirmed that both Nebular and Stellar passed real reauthentication from captured bytes. Nebular ingestion, dependencies, and recipes remained identical, with `normalized_sha` being the only delta. Scanner manifests proved byte-identical across 3 payloads with zero hardlinks.

## What would make this wrong

1. **Trust boundary**: Trusting remote assertions, publisher provenance, or third-party registry metadata without hashing raw downloaded bytes against independent checksums and tree blobs.
2. **Timestamps limitation**: Relying on collection or release timestamps to establish freshness on untrusted networks; timestamps cannot prove absence of replay attacks.
3. **Persisted audit limit**: Allowing saved JSON ingestion records to reauthorize publication gates without in-process byte verification.
4. **Permitting archive hard links**: Allowing hard links allows uninspected archive paths to alias inspected binaries.
5. **Resolving tenant license conflicts artificially**: Silently selecting a license interpretation without tenant legal authority.

## Local Links

- [ADR 0004: Ingestion core and evidence profiles](../adr/0004-ingestion-core-and-evidence-profiles.md)
- [ADR 0003: Authenticated ingestion and shadow adapters](../adr/0003-authenticated-ingestion-and-shadow-adapters.md)
- [Specification: Release record v1alpha1](rs9-release-record-v1alpha1.md)
- [Specification: Configuration v1alpha1](rs9-config-v1alpha1.md)
- [Architecture overview](../architecture.md)
