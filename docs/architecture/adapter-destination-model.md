# Adapter and destination boundary

Status: contract design with executable intent validation, Nebular shadow renderer candidate, and Foundation 3 publication control plane (observation derivation, pure planner, revision allocator, receipts, and retry engine). Live package builders, publishers, signers, projection writers, and contribution clients remain deferred; no live mutations are authorized. No actual destination readback adapter or publisher exists.

## Inputs and ownership

The publication adapter consumes normalized tenant facts, an authenticated in-process `ReleaseCapture` (repository, tag, commit, assets, SHA256SUMS, archive manifests, license evidence), qualified operator destination policy, and destination observation state (readback hashes, remote IDs, semantic content identity).

Adapters must not discover alternate upstreams or silently rebuild release bytes.

- **Core owns**: Release authentication (`rs9.release_core`), canonical records (`rs9.records`), native payload identity, observation state derivation (`rs9.observation`), safety gates (`rs9.gates`), pure publication planning (`rs9.planner`), revision allocation, and confirmed receipts (`rs9.publication`). Records hash raw bytes, not signatures or ambient authority.
- **Adapters own**: Packaging artifact construction, rendering manifests, ecosystem-specific readback parsing, and install/verification logic.
- **Destinations own**: Repository topology, shared indexes, origin, retention, trust binding, and remote revision tracking. Credentials live in operator facilities and are absent from interpreted tenant schemas.

## Modes and results

| Mode | Intended effect | Required readback verification |
|---|---|---|
| `direct` | Registry publication or atomic hosted-repository generation | Exact package payload hashes and registry metadata, or authenticated signed index and installed payload. |
| `projection` | Controlled updates to downstream repos (e.g. Homebrew tap, AUR) | Generated file tree, upstream base commit, allowed relative paths, commit/PR identity, and merged/current tree readback. |
| `contribution` | Reviewed packaging proposal in external repositories (e.g. nixpkgs) | Source/build policy, branch/PR identity, upstream review outcome, and verified repository availability. **Contribution PR state is separate from destination exact state.** |

A projection can travel by pull request without becoming contribution mode: the distinction is whether RS9 governs the generated projection repository or proposes changes to an external ecosystem-maintained package.

## Destination observation and subject binding

Destination state is observed and validated via `rs9.observation.observe` and `validate_observation` (`rs9.destination-observation.v1alpha1`):
1. `unreachable`: Endpoint unreachable (DNS, timeout, connection failure).
2. `unknown`: Ambiguous or unparseable destination response.
3. `absent`: Authenticated check confirms the package version definitely does not exist. Unknown errors are never inferred as absent.
4. `exact`: Authenticated readback confirms all expected files, hashes, and aggregate desired semantic content identity match completely.
5. `incomplete`: Destination contains a partial or broken release.
6. `conflict`: Destination version exists with differing payload hashes or configuration.

**Subject mismatch input error**: If the observed destination ID, target ID, adapter, or version disagrees with the expected subject, `ContractError("SUBJECT_MISMATCH", ...)` is raised immediately.

**Independent verification**: Caller-asserted verdicts are never accepted alone; readback payload hashes are independently checked against expected component hashes.

## Semantic content identity and revision allocation

To prevent packaging revision bumps (e.g. Arch `pkgrel` or RPM `Release`) from breaking byte equivalence, RS9 uses `rs9.semantic-content-identity.v1alpha1`:
- Contains artifact payload hashes and explicit configuration input hash mapping;
- Strictly excludes ecosystem packaging revision numbers;
- Evaluates identically on both desired output manifests and destination observations.

Actual rendered recipe files (`PKGBUILD`, `.spec`, `.nix`) are separately bound in `rs9.adapter-output.v1alpha1`. `adapter_outputs_from_shadow` wires the actual shadow renderer and normalized semantic target inputs excluding the allocated revision.

**Revision allocation (`allocate_revision`)**:
- Desired revision unoccupied: returns desired revision.
- Desired revision occupied with identical semantic identity: returns desired revision (`reuse-exact`).
- Desired revision occupied with differing content on immutable registry: returns `None` with basis `immutable-conflict`.
- Mutable ecosystems: allocates next positive integer (`next-after-observed` or `first`).
- If allocated revision != output revision on mutating plans, the planner blocks on `allocated-revision-requires-render`.

## Repair and publication state

- **Planner precedence**:
  1. Stale/future readback before exact noop (`defer-readback`);
  2. Conflict before gates (`block-conflict`);
  3. Exact no-op before gates (`noop`): performs zero writes and does not imply acceptance;
  4. All unresolved gates `block-gate`;
  5. Absent yields `publish-intent`;
  6. Safe repair yields `repair-intent`; otherwise `block`.
- **Named versioned safe-repair contract**: An `incomplete` destination can be repaired only when matching `rs9.safe-repair.v1alpha1` (`restore-missing-components`). Policy must select the same ID (`repair["id"] == policy["repair_contract"]`), and only missing components may be restored when aggregate semantic identity matches. Overwriting existing components is prohibited.
- **Publication attempts and receipts**:
  - `mutation_attempt` records `transport_outcome` (`not_attempted`, `confirmed`, `ambiguous`, `failed`) with sanitized roles, request tracking, and separate bounded log hashes.
  - `publication_receipt` confirms final states (`already-exact`, `published`, `conflict`, `incomplete`, `not-attempted`, `unconfirmed`).
  - A `published` receipt strictly requires an actual confirmed or ambiguous attempt AND an exact post-readback observation ordered after the attempt via response remote sequence/ID or documented timestamp fallback.
- **The nine retry MUST rules**:
  - Retries require a fresh re-read strictly after attempt completion (`observed_at > max(finished_at)`);
  - Preconditions are verified against the fresh observation;
  - Confirmed exact destinations trigger `noop` without duplicate action;
  - Shifted remote revisions trigger `replan-required`;
  - Conflicting destinations are blocked permanently (`block-conflict`);
  - Blind retries and automatic timeout repetitions are prohibited;
  - Receipt replay validates the full receipt graph.

## Local Links

- [ADR 0004: Ingestion core and evidence profiles](../adr/0004-ingestion-core-and-evidence-profiles.md)
- [ADR 0005: Publication state, planner, and receipts](../adr/0005-publication-state-planner-and-receipts.md)
- [Specification: Destination observation v1alpha1](../specs/rs9-destination-observation-v1alpha1.md)
- [Specification: Publication plan v1alpha1](../specs/rs9-publication-plan-v1alpha1.md)
- [Specification: Publication receipt v1alpha1](../specs/rs9-publication-receipt-v1alpha1.md)
- [Specification: Retry and idempotence v1alpha1](../specs/rs9-retry-idempotence-v1alpha1.md)
- [Architecture overview](../architecture.md)
