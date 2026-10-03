# Publication plan and semantic identity v1alpha1

Status: implemented specification in `src/rs9/planner.py` and `src/rs9/records.py`. Defines revision-independent semantic content identity, adapter outputs, pure publication planning, and deterministic revision allocation. Record hashes bind canonical JSON bytes; they do not establish signatures or authority.

LIVE1 retains plan/adapter-output v1alpha1 shapes but requires an explicitly
migrated [destination policy v1alpha2](rs9-live1-policy-receipt-v1alpha2.md).
The v1alpha1 policy description below is historical. Current adapter-owned gates
cannot be waived; serialized plans are audit evidence and require fresh planning
before real transport.

## Overview

The RS9 publication planner (`rs9.planner`) is a pure functional control plane component. Given normalized tenant intent, an authenticated in-process `ReleaseCapture`, profile results, an adapter output manifest, qualification gates, destination policy, and a destination observation, it deterministically computes a plan with an immutable hash identity (`rs9.publication-plan.v1alpha1`).

The planner executes zero network I/O and does not access ambient clocks (evaluating
strictly against an explicit RFC3339 UTC `evaluated_at`). It rechecks local captured
bytes and configuration authority before producing canonical records. A pre-RS9
exception requires an approved exact bootstrap capability; normal future releases
require captured tagged `.rs9/` inputs. Serialized configuration claims cannot
replace those checks.

## Semantic content identity (`rs9.semantic-content-identity.v1alpha1`)

To distinguish genuine upstream payload changes from packaging rebuilds (e.g. bumping Arch `pkgrel` or RPM `Release`), RS9 binds payload content to a revision-independent semantic identity:

```json
{
  "schema": "rs9.semantic-content-identity.v1alpha1",
  "project_id": "theme-forge-nebular-fusion",
  "version": "0.6.1",
  "target_id": "nebular-pacman",
  "adapter": "pacman",
  "artifact_payload_hashes": {
    "app-0.6.1-x86_64.tar.gz": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "configuration_identity": {
    "semantic-inputs": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  }
}
```

- Binds payload hashes and an explicit semantic configuration input hash mapping. No recipe rewriting or filename/field heuristics hide a packaging revision.
- Exact artifact hashes (e.g. `PKGBUILD`, `.spec`) are separately revision-specific and bound in `rs9.adapter-output.v1alpha1`.
- `adapter_outputs_from_shadow` wires the actual shadow renderer and normalized semantic target inputs excluding the allocated revision.

## Adapter output schema (`rs9.adapter-output.v1alpha1`)

Constructed via `rs9.planner.adapter_output`:
- `destination`: Destination dictionary (`id`, `adapter`, `mode`).
- `subject`: Subject dictionary (`package`, `version`, `revision`).
- `implementation`: Renderer identifier and version.
- `source_version`: Adapter implementation source version. Future executors must supply an authoritative deployment version or source revision; the current shadow helper identifies this candidate generation.
- `semantic_identity`: Complete `rs9.semantic-content-identity.v1alpha1` record.
- `content_identity_sha256`: SHA-256 of the semantic identity.
- `artifacts`: List of rendered artifact entries (`path`, `size`, `sha256`).
- `source_manifest`: Renderer manifest and its SHA-256 digest.
- `repair_contract`: Optional named versioned `rs9.safe-repair.v1alpha1` record.
- `revision_scheme`: Ecosystem scheme (`none`, `pkgrel`, `rpm-release`, `apt-revision`).

## Destination policy schema (`rs9.destination-policy.v1alpha1`)

Constructed via `rs9.planner.destination_policy`:
- `enabled`: Boolean controlling destination enablement.
- `max_observation_age_seconds`: Bounded maximum age for valid observations (default 300s).
- `required_gates`: List of mandatory gate IDs.
- `allow_not_applicable`: Allowed not-applicable gate IDs.
- `external_evidence`: Mapping of gate ID to valid external SHA-256 hashes.
- `repair_contract`: Expected repair contract ID.
- `immutable_versions`: Boolean enforcing registry immutability.
- `revision_floor`, `pinned_revision`, `base_commit`, `allowed_paths`.

## Plan evaluation rules (`plan`)

The pure function `plan(...)` evaluates outcomes in this strict precedence:

0. **Disabled destination**: An explicitly disabled policy produces `block`.
1. **Stale/future readback before exact noop**: If observation age exceeds `policy["max_observation_age_seconds"]` or is in the future relative to `evaluated_at`, or state is `unknown` or `unreachable`, outcome is `defer-readback`.
2. **Conflict before gates**: If observation state is `conflict`, or revision allocation basis is `immutable-conflict` or `pinned-conflict`, outcome is `block-conflict`.
3. **Exact no-op before gates**: If observation state is `exact`, outcome is `noop`. Exact no-op before gates executes zero writes and does not constitute acceptance or authorization of new packaging artifacts.
4. **All unresolved gates block-gate**: If any required gate is missing, unbound, failed, not-run, or deferred, outcome is `block-gate`.
5. **Absent state**: If observation state is `absent`, outcome is `publish-intent`.
6. **Safe repair**: If observation state is `incomplete` and satisfies the named safe-repair contract, outcome is `repair-intent`.
7. **Default block**: If an incomplete observation lacks a qualifying repair contract, outcome is `block` (`safe-repair-contract-required`).
8. **Revision re-render guard**: If outcome is `publish-intent` or `repair-intent` and allocated revision != `output["subject"]["revision"]`, outcome is `block` (`allocated-revision-requires-render`).
9. **Projection and contribution guards**: Projection mode validates `base_commit` readback parity and `allowed_paths` boundaries; contribution mode blocks on `upstream-pr-open`.

## Qualification and provenance bindings

The required gate IDs always include `release.authenticated`, `license.authority`, and `package.render`. Every gate has a stable ID, scope, reason, blocker and sorted evidence hashes, with status `pass`, `fail`, `not-run`, `not-applicable`, or `deferred`. A passing string without evidence is rejected. Release evidence binds the sealed capture; package evidence binds the output source manifest, whose qualification must be complete. Profile evaluation binds both the release-record hash and `intent_sha256`; changing normalized intent requires reevaluation.

Agreement among license declarations is insufficient to resolve licensing authority. A license pass also needs scoped `tenant-license-authority` evidence explicitly bound by operator policy. An unresolved tenant marker or observed declaration conflict blocks even when such evidence is supplied. Tenant configuration cannot assert legal resolution. Signature/trust, build/install/runtime, and destination-specific requirements are additional policy gate IDs; external hashes are operator-supplied evidence references, not independently verified attestations. Not-applicable status requires a reason and explicit policy permission.

Plans bind tenant/project/release and immutable commit/tree, authenticated release/profile/legacy-ingestion hashes, normalized/config input hashes, adapter implementation/source version, desired artifact manifest, gate-set hash, destination policy, observation hash and full observation, selected outcome, and revision-allocation inputs/results. The planner verifies these input relationships before selecting an outcome.

A destination reader must reconstruct the **same semantic identity contract** from authoritative remote metadata. If the destination exposes only artifact checksums and cannot establish the semantic input hashes, it cannot prove exact semantic identity and must remain incomplete/unknown. Revision reuse does not make recipes at different revisions byte-identical.

## Safe repair contract (`rs9.safe-repair.v1alpha1`)

Created via `safe_repair_contract(contract_id, adapter, allowed_components)`:
- Declares operation `restore-missing-components`.
- **Dual agreement requirement**: The adapter output repair contract must match `policy["repair_contract"]` by ID and adapter.
- Only missing components may be restored, all missing components must be within `allowed_components`, and readback content identity must match desired identity. Overwrite of existing differing components is strictly forbidden.

## Revision allocation (`allocate_revision`)

Computes integer package revisions without ambient state. Carries both input parameters and output results (`revision`, `basis`). Bases include: `unrevisioned`, `pinned`, `reuse-exact`, `next-after-observed`, `first`, `immutable-conflict`, and `pinned-conflict`, and `reuse-exact-readback`.

## What would make this wrong

1. **Trust boundary**: Accepting unauthenticated serialized JSON plans or profiles without fresh in-process `ReleaseCapture` and sentinel validation.
2. **Timestamps limitation**: Relying on uncalibrated timestamps for ordering; observations with timestamps in the future or older than policy bounds must trigger `defer-readback`.
3. **Persisted audit limit**: Treating an audit-persisted plan as an ongoing execution capability without re-checking destination observation freshness and gate validity.
4. **Authorizing repair without dual agreement**: Permitting repairs when adapter output and destination policy repair contract IDs disagree.

## Local Links

- [ADR 0005: Publication state, planner, and receipts](../adr/0005-publication-state-planner-and-receipts.md)
- [Specification: Destination observation v1alpha1](rs9-destination-observation-v1alpha1.md)
- [Specification: Publication receipt v1alpha1](rs9-publication-receipt-v1alpha1.md)
- [Specification: Retry and idempotence v1alpha1](rs9-retry-idempotence-v1alpha1.md)
- [Adapter and destination boundary](../architecture/adapter-destination-model.md)
- [Architecture overview](../architecture.md)
