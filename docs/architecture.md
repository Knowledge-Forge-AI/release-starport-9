# Release Starport 9 architecture

Status: intended architecture with provisional validation/normalization, captured-byte authentication, Nebular shadow rendering, and Foundation 3 publication control plane (observation derivation, evidence-bound gates, pure planner, revision allocator, mutation attempts, confirmed receipts, and retry engine). Live package publication remains unimplemented; no publisher claims are made. See the [Foundation 2 candidate](foundation2-candidate.md) and Foundation 3 specifications.

## Role

Release Starport 9 (RS9) is a publication control plane. It begins from an authoritative public project release and carries that release into downstream registries, package repositories, projection repositories, and upstream packaging contribution workflows.

The source project remains authoritative for application source, application versioning, Git tags, GitHub Releases, and the release assets it declares authoritative.

RS9 is authoritative for shared publication machinery.

## Core control plane flow

A normal RS9-managed release flows through the following deterministic stages:

```text
source project
  -> reviewed source commit
  -> version/tag
  -> authoritative GitHub Release and assets
  -> RS9 release ingestion core (rs9.release_core)
  -> profile evidence capture (rs9.profiles: tauri-desktop-archive, npm-package-archive)
  -> in-process ReleaseCapture container (sealed authenticated_record_hash)
  -> destination observation (rs9.observation: observe / validate_observation)
  -> evidence-bound safety gates (rs9.gates: gate / derive_gates / check_gates)
  -> pure publication planner & revision allocator (rs9.planner: adapter_output / plan)
  -> mutation attempt execution auditing (rs9.publication: mutation_attempt)
  -> verified post-readback & confirmed receipt (rs9.publication: publication_receipt)
  -> deterministic retry evaluation (rs9.publication: next_action / check_precondition)
```

RS9 must not silently rebuild or mutate an upstream release artifact when the publication contract requires byte identity. When an ecosystem necessarily creates a new packaging artifact, RS9 binds that artifact to the exact authoritative upstream inputs and records the transformation.

## Standard adapters

The planned standard publication roster is:

- npm
- PyPI
- Nix
- Homebrew
- pacman
- DNF/RPM
- APT

Go modules and other ecosystems can be supported project-by-project without becoming mandatory parts of the standard roster. Stellar renderers are explicitly not supported.

## Publication modes

### Direct

In direct mode, RS9 publishes to a registry or repository under RS9 control. Examples include hosted APT/DNF/pacman repositories and, where authentication models permit, package registries.

### Projection

RS9 generates and maintains downstream repository surfaces (e.g. Homebrew tap, one AUR repo per package) from canonical publication inputs. Projection mode binds base commits, allowed file paths, and component boundaries.

### Contribution

RS9 prepares and maintains changes against an external repository (e.g. nixpkgs, Homebrew upstream). **Contribution PR state is kept strictly separate from destination exact state**: opening or updating a PR does not satisfy destination readback until the package is merged and observed live.

## Control plane invariants

1. **Pure records never publish**: All control plane records (`Record` dicts) are pure, immutable canonical JSON structures. Records hash raw bytes, not signatures or ambient authority. Planning, gating, revision allocation, and retry evaluation are pure mathematical functions evaluated at an explicit RFC3339 UTC timestamp (`evaluated_at`), free of ambient clock calls, network I/O, or filesystem mutations.
2. **Generic ingestion core and closed profiles**:
   - `src/rs9/release_core.py` handles canonical generic selection, download bounds, tree blobs, asset digests, SHA256SUMS cross-validation, and archive safety checks.
   - Profile-specific capture is restricted to closed RS9 profiles: `tauri-desktop-archive.v1alpha1` and `npm-package-archive.v1alpha1`. No arbitrary tenant code or filename guessing is permitted.
   - Archive hard links are unconditionally rejected fail-safe before visitors run, eliminating silent inspection gaps and memory retention hazards.
3. **Sealed in-process `ReleaseCapture` and anti-forgery**: The `release.authenticated` gate requires an active in-process `ReleaseCapture` instance holding physical byte handles and verified by `authenticated_record_hash`. Downstream profile evaluations register in `capture._profile_results`. Stored JSON records are historical audit logs and cannot reauthorize publication.
4. **Canonical observation derivation**: `rs9.observation.observe` derives one of six lowercase states: `unknown`, `unreachable`, `absent`, `exact`, `incomplete`, `conflict`. Readback requires explicit auth, transport, presence, components, content identity, and level. Unknown errors are never inferred as absent. No actual destination readback adapter or publisher exists.
5. **Mandatory known gates**: Gate evaluation (`check_gates`) enforces mandatory stable gate IDs (`release.authenticated`, `license.authority`, `package.render`) across five lowercase statuses (`pass`, `fail`, `not-run`, `not-applicable`, `deferred`). External trust/platform/destination IDs are policy-specific hash-bound evidence managed by operators.
6. **Planner precedence**:
   - Stale/future readback before exact noop (`defer-readback`);
   - Conflict before gates (`block-conflict`);
   - Exact no-op before gates (`noop`): performs zero writes and does not constitute acceptance;
   - All unresolved gates `block-gate`;
   - Absent yields `publish-intent`;
   - Safe repair yields `repair-intent`; otherwise `block`.
   - If allocated revision != output revision, blocks on `allocated-revision-requires-render`.
7. **Revision-independent semantic identity**: Desired adapter output binds `rs9.semantic-content-identity.v1alpha1` (artifact payload hashes + explicit configuration input hash mapping, excluding packaging revisions), while separately binding revisioned rendered files. `adapter_outputs_from_shadow` wires the actual renderer and normalized semantic inputs.
8. **Named versioned safe-repair contract**: Repair of an incomplete destination requires `rs9.safe-repair.v1alpha1` (`restore-missing-components`). Policy must select the same ID (`repair["id"] == policy["repair_contract"]`), and only missing components may be restored when aggregate semantic identity matches.
9. **Mutation attempts and confirmed receipts**:
   - `mutation_attempt` records `transport_outcome` (`not_attempted`, `confirmed`, `ambiguous`, `failed`) with sanitized roles, request tracking, and separate bounded log hashes.
   - `publication_receipt` confirms final states (`already-exact`, `published`, `conflict`, `incomplete`, `not-attempted`, `unconfirmed`).
   - A `published` receipt strictly requires an actual confirmed or ambiguous attempt AND an exact post-readback observation ordered after the attempt via response remote sequence/ID or documented timestamp fallback.
10. **The nine retry MUST rules**: Evaluated through `check_precondition` and `next_action`. Mandatory re-read after any actual transport, temporal ordering (`observed_at > max(finished_at)`), exact state yields `noop`, changed observation hash triggers `replan-required`, conflicts permanently block (`block-conflict`), and replay validates the full receipt graph.

## Tenant model

Projects are tenants of RS9, not owners of RS9's shared machinery. Project-specific facts and publication intent live under `<project-root>/.rs9/`. RS9 owns the parsers, schemas, adapters, policy, verification logic, and destination mechanics.

Theme Forge is the first migration tenant. The genuine license discrepancy in Nebular 0.6.1 (`AGPL-3.0-or-later OR Commercial` in npm package.json vs `AGPL-3.0-or-later` in source/archives) remains **unresolved**; RS9 faithfully records observed declarations without claiming live compatibility or inventing legal resolutions.

Read-only genericity and byte-compatibility evidence is recorded in the [Foundation 3 candidate](foundation3-candidate.md).

## Hosted publication domain

The intended canonical hosted publication origin is:

```text
https://rs9.knowledge-forge.ai/
```

`https://packages.knowledge-forge.ai/` is a convenience redirect preserving path and query. Public client configuration should prefer a stable custom domain rather than binding clients to a GitHub repository name or GitHub Pages project path.

## Trust and signing

RS9 reuses a deliberate, bounded signing authority where multiple package-manager repositories are intentionally governed by the same publication trust root. Private signing material must never be committed to RS9, tenant repositories, projection repositories, evidence archives, or public Pages artifacts. Production signing keys remain separate from qualification fixture keys.

## Licensing boundary

RS9's license applies to RS9 infrastructure and RS9-authored material. It does not relicense tenant projects or their release payloads. Adapters and generated package metadata must preserve the licensing identity of the software being distributed.

## Local Links

- [ADR 0001: Tenant contract v1alpha1](adr/0001-tenant-contract-v1alpha1.md)
- [ADR 0002: GitHub Release as sole ingestion authority](adr/0002-github-release-sole-ingestion-authority.md)
- [ADR 0003: Authenticated ingestion and shadow adapters](adr/0003-authenticated-ingestion-and-shadow-adapters.md)
- [ADR 0004: Ingestion core and evidence profiles](adr/0004-ingestion-core-and-evidence-profiles.md)
- [ADR 0005: Publication state, planner, and receipts](adr/0005-publication-state-planner-and-receipts.md)
- [Specification: Release record v1alpha1](specs/rs9-release-record-v1alpha1.md)
- [Specification: Destination observation v1alpha1](specs/rs9-destination-observation-v1alpha1.md)
- [Specification: Publication plan v1alpha1](specs/rs9-publication-plan-v1alpha1.md)
- [Specification: Publication receipt v1alpha1](specs/rs9-publication-receipt-v1alpha1.md)
- [Specification: Retry and idempotence v1alpha1](specs/rs9-retry-idempotence-v1alpha1.md)
- [Adapter and destination boundary](architecture/adapter-destination-model.md)
- [Migration map](architecture/migration-map.md)
