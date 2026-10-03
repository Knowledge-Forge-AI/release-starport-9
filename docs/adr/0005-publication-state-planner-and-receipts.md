# ADR 0005: Publication state, planner, and receipts

Status: decided; implemented in `rs9.records`, `rs9.gates`, `rs9.observation`, `rs9.planner`, and `rs9.publication`. Establishes the Foundation 3 publication control plane. No live publication or publisher claims authorized.

## Context

Prior foundations focused on declarative intent normalization (Foundation 1) and authenticated shadow recipe generation in scratch workspaces (Foundation 2). Foundation 3 addresses the publication control plane: observing destination state, evaluating safety gates, computing publication plans, allocating packaging revisions, executing mutation attempts, issuing verifiable receipts, and handling retries idempotently.

Publishing to package ecosystems presents severe hazards:
1. **Accidental overwrite and registry immutability**: Many package registries (such as npm and PyPI) permanently forbid re-uploading an existing version with different content. Blind retries or uncontrolled publishing can corrupt destination state or permanently break an ecosystem release stream.
2. **Ambient side-effects in planning**: Coupling planning logic with live network requests or system clocks creates non-deterministic plans that cannot be audited or verified offline.
3. **Forged or unconfirmed receipts**: Claiming a release is published based solely on transport success or process exit codes is unsafe; registries frequently fail asynchronously, index updates can be delayed, and network timeouts can leave publication state ambiguous.
4. **Conflating PR submission with publication**: In projection or upstream contribution workflows, opening a pull request is not equivalent to package publication.

## Decision

### 1. Pure records never publish

All data structures in the publication control plane are represented as canonical dictionary records (`rs9.records.Record`). They are serialized as deterministic canonical JSON (sorted keys, two-space indentation, UTF-8, LF endings) and authenticated via SHA-256 digests. Record hashes bind canonical JSON bytes; they do not establish signatures or authority.

Planning functions, gate evaluations, revision allocation, and retry calculations are pure mathematical functions:
- They evaluate against explicit RFC3339 UTC timestamps (`evaluated_at`).
- They perform zero network I/O, zero filesystem writes, and zero process spawning.
- They have no ambient authority.

### 2. Revision-independent semantic content identity

To prevent ecosystem revision numbers (such as Arch Linux `pkgrel` or RPM `Release`) from artificially altering the identity of identical upstream payloads, RS9 introduces a contractually versioned semantic content identity (`rs9.semantic-content-identity.v1alpha1`):
- Created via `build_semantic_content_identity(project_id, version, target_id, adapter, artifact_payload_hashes, configuration_identity)` and hashed via `semantic_identity_sha256`.
- Binds `artifact_payload_hashes` (mapping POSIX relative path to SHA-256 digest) and explicit semantic configuration input hash mapping (`configuration_identity`). No recipe rewriting or filename/field heuristics hide a packaging revision.
- Exact rendered recipe artifact hashes (e.g. `PKGBUILD`, `.spec`, `.nix`) are separately revision-specific and bound in `rs9.adapter-output.v1alpha1`.
- `adapter_outputs_from_shadow` wires the actual shadow renderer and normalized semantic target inputs excluding the allocated revision.

### 3. Destination observation and subject binding

Destination state is observed and validated via `rs9.observation.observe` and `rs9.observation.validate_observation` (`rs9.destination-observation.v1alpha1`):
- Derives one of six mutually exclusive lowercase states: `unknown`, `unreachable`, `absent`, `exact`, `incomplete`, `conflict`.
- Requires an explicit readback dictionary: `authenticated` (boolean), `transport` (`ok`, `unknown`, `unreachable`), `presence` (`absent`, `present`, `unknown`), `components` (hash mapping), `content_identity_sha256`, and readback `level` (`none`, `metadata`, `content`, `full`).
- **Unknown errors are never inferred as absent**: If transport fails or presence is unknown, state is derived as `unreachable` or `unknown`. An absent readback with present components or content identity raises `ContractError("OBSERVATION_CONTRADICTION", ...)`.
- Binds explicit `source` (`synthetic-fixture`, `adapter-readback`, `live-read`), `observed_at`, `remote` identifiers (`etag`, `commit`, `revision`, `sequence`, `registry_id`), `revisions` list, `diagnostics` list, and optional upstream `contribution` status (`pr_id`, `state`).
- **No actual destination readback adapter or publisher exists**: Live network execution and destination clients remain outside current scope.

### 4. Evidence-bound safety gates

Gate derivation and verification (`rs9.gates.gate`, `derive_gates`, `check_gates`) produce `rs9.qualification-gate.v1alpha1` records across five lowercase statuses: `pass`, `fail`, `not-run`, `not-applicable`, `deferred`.

Mandatory known gate IDs:
- `release.authenticated`: Strictly bound to `authenticated_record_hash(capture)` with scope `release`. Requires an in-process `ReleaseCapture` holding private sentinel proof; serialized JSON records cannot reauthorize.
- `license.authority`: Bound to `record_sha256(profile)` with scope `tenant`. Evaluates tenant license reconciliation; defers or fails if license status is unresolved or conflict (as in Nebular 0.6.1).
- `package.render`: Bound to `output["source_manifest_sha256"]` with scope `adapter`. Passes only if the render manifest verdict is qualified with no blockers.

External trust, platform, or destination gate IDs are policy-specific hash-bound evidence managed under operator responsibility and verified through `policy["external_evidence"]`.

### 5. Pure planner logic and execution ordering

`rs9.planner.plan` produces an immutable `rs9.publication-plan.v1alpha1` record. Evaluation adheres to this strict precedence:

1. **Stale/future readback before exact noop**: If `observed_at` is in the future relative to `evaluated_at` or exceeds `policy["max_observation_age_seconds"]`, or if state is `unknown` or `unreachable`, the outcome is `defer-readback`.
2. **Conflict before gates**: If observation state is `conflict`, or revision allocation yields `immutable-conflict` or `pinned-conflict`, the outcome is `block-conflict`.
3. **Exact no-op before gates**: If observation state is `exact`, the outcome is `noop`. Exact no-op before gates performs zero writes and does not constitute acceptance or authorization of new packaging artifacts.
4. **All unresolved gates block-gate**: If any required gate is missing, unbound, failed, not-run, or deferred, the outcome is `block-gate`.
5. **Absent state**: If observation state is `absent`, outcome is `publish-intent`.
6. **Safe repair**: If observation state is `incomplete` and satisfies the named versioned safe-repair contract, outcome is `repair-intent`.
7. **Default block**: If an incomplete observation lacks a qualifying repair contract, outcome is `block` (`safe-repair-contract-required`).
8. **Revision re-render guard**: If outcome is `publish-intent` or `repair-intent` and the allocated revision differs from `output["subject"]["revision"]`, outcome is `block` (`allocated-revision-requires-render`).
9. **Projection and contribution checks**: Projection mode enforces `policy["base_commit"]` readback parity and `policy["allowed_paths"]` containment; contribution mode blocks on `upstream-pr-open`.

### 6. Named versioned safe-repair contract

Repair of an `incomplete` destination requires `rs9.planner.safe_repair_contract(contract_id, adapter, allowed_components)` (`rs9.safe-repair.v1alpha1`):
- Explicitly declares operation `restore-missing-components` over bounded allowed component paths.
- **Dual agreement requirement**: The output repair contract must match `policy["repair_contract"]` by ID and adapter.
- Only missing components may be restored, all missing components must be within `allowed_components`, and readback content identity must match the desired content identity. Overwrite of existing differing components is strictly forbidden.

### 7. Pure revision allocation (`allocate_revision`)

`allocate_revision(scheme, revisions, content_identity, *, floor=1, pinned=None, immutable=True)` computes deterministic revision decisions:
- Supported schemes: `none`, `pkgrel`, `rpm-release`, `apt-revision`.
- Carries both input parameters and output results (`revision`, `basis`).
- Output bases include `unrevisioned`, `pinned`, `reuse-exact`, `next-after-observed`, `first`, `immutable-conflict`, and `pinned-conflict`.

### 8. Mutation attempts and confirmed receipts

Execution lifecycle tracking in `rs9.publication`:
- **Mutation attempt (`rs9.mutation-attempt.v1alpha1`)**: Created via `mutation_attempt(plan, ...)`. Captures `executor_role` (`operator`, `ci-publisher`, `synthetic-test`), `started_at`, `finished_at`, `transport_outcome` (`not_attempted`, `confirmed`, `ambiguous`, `failed`), optional `request_identity`, `response_remote`, and bounded separate `log_reference` (`sha256`, `size`). Only mutating plans (`publish-intent`, `repair-intent`) can record attempted transport.
- **Publication receipt (`rs9.publication-receipt.v1alpha1`)**: Created via `publication_receipt(plan, attempts, post_observation)`.
  - Supported final states: `already-exact`, `published`, `conflict`, `incomplete`, `not-attempted`, `unconfirmed`. All non-success final states are fully supported.
  - An `already-exact` receipt is issued for `noop` plans with zero attempts.
  - A `published` receipt **strictly requires** an actual confirmed or ambiguous attempt (`transport_outcome != "not_attempted"`) AND an exact post-readback observation ordered after the attempt via response remote sequence/identity or documented timestamp fallback (`_ordered_after`). No `not_attempted` attempt can ever yield a published receipt.

### 9. Original nine retry MUST rules

`check_precondition` and `next_action` enforce the nine mandatory retry rules:
1. **MUST re-read after any actual transport**: Following any attempt where transport was attempted, a fresh observation is strictly required before any subsequent action.
2. **MUST enforce temporal ordering**: The fresh observation timestamp must be strictly later than attempt completion (`observed_at > max(finished_at)`) and within `max_observation_age_seconds`. Future or stale observations return `reread-required`.
3. **MUST check plan preconditions**: `check_precondition` verifies observation hash and remote parameters against plan inputs; drifts return `stale-plan`.
4. **MUST return noop on exact state**: If the fresh observation confirms `exact` destination state, `next_action` returns `noop`, executing zero duplicate mutations.
5. **MUST replan on destination drift**: If remote revisions, sequence numbers, or observation hashes change, `next_action` returns `replan-required`.
6. **MUST block permanently on conflict**: If fresh observation reveals a `conflict` state, `next_action` returns `block-conflict`. Conflicting destinations must never be retried automatically.
7. **MUST defer when status is unavailable**: If destination observation state is `unreachable` or `unknown`, `next_action` returns `reread-required`.
8. **MUST isolate contribution PR state**: Opening or updating an upstream PR does not constitute destination readback; exact destination availability governs completion.
9. **MUST validate receipt replay graph**: Replaying a receipt validates the entire receipt graph against `publication_receipt(plan, receipt["attempts"], receipt["post_observation"])`.

## Consequences

- The publication control plane is completely deterministic, replay-safe, and auditable.
- Unsafe uppercase actions, duplicate classes, and unconfirmed receipt claims are eliminated.
- Destructive overwrites and registry immutability conflicts are blocked fail-safe before mutation.
- Pull request workflows and destination package availability remain strictly decoupled.

## Local Links

- [ADR 0004: Ingestion core and evidence profiles](0004-ingestion-core-and-evidence-profiles.md)
- [Specification: Destination observation v1alpha1](../specs/rs9-destination-observation-v1alpha1.md)
- [Specification: Publication plan v1alpha1](../specs/rs9-publication-plan-v1alpha1.md)
- [Specification: Publication receipt v1alpha1](../specs/rs9-publication-receipt-v1alpha1.md)
- [Specification: Retry and idempotence v1alpha1](../specs/rs9-retry-idempotence-v1alpha1.md)
- [Adapter and destination boundary](../architecture/adapter-destination-model.md)
- [Architecture overview](../architecture.md)
