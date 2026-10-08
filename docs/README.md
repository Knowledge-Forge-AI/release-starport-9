# RS9 documentation

Release Starport 9 is organized around stable, evidence-bound contracts across its ingestion, rendering, and publication control planes.

Theme Forge LIVE1 is pending / not live. See the [candidate disposition](live1-candidate.md),
[source inventory](live1-inventory.md) and [attended preparation runbook](../operators/live1/RUNBOOK.md).

- [CONT2 hosted candidate source](live1-hosted-candidate.md) — Source-defined lanes, custody and attended handoff.
- [CONT9 native-client source candidate](live1-native-client-cont9.md) — Lint/trust diagnostics, installed Nebular verification and pending run-8 handoff.
- [ADR 0007](adr/0007-hosted-candidate-lane-contract.md) — Hosted qualification authority.
- [Hosted artifact set v1alpha2](specs/rs9-hosted-artifact-set-v1alpha2.md) — Exact logical and archive custody.

## Architecture and governance

- [Architecture](architecture.md) — Control-plane responsibilities, publication modes, and trust boundaries.
- [Project contract](project-contract.md) — The declarative `.rs9/*.toml` tenant interface.
- [Adapter and destination boundary](architecture/adapter-destination-model.md) — Routing, destination observation, and repair contracts.
- [Migration map](architecture/migration-map.md) — Staged adoption surfaces, rollback strategies, and unresolved migration gates.
- [Theme Forge extraction inventory](architecture/theme-forge-extraction-inventory.md) — Observed facts extracted from first tenant.
- [Nebular shadow projection](architecture/nebular-shadow-projection.md) — Shadow package rendering for Nebular 0.6.1.
- [Install navigation](install/README.md) — Routes to current authorities.

## Architecture Decision Records (ADRs)

- [ADR 0001: Tenant contract v1alpha1](adr/0001-tenant-contract-v1alpha1.md) — Declarative project configuration under `.rs9/`.
- [ADR 0002: GitHub Release as sole ingestion authority](adr/0002-github-release-sole-ingestion-authority.md) — Rejection of speculative sources and ambient credentials.
- [ADR 0003: Authenticated ingestion and shadow adapters](adr/0003-authenticated-ingestion-and-shadow-adapters.md) — Bounded byte capture and deferred shadow adapters.
- [ADR 0004: Ingestion core and evidence profiles](adr/0004-ingestion-core-and-evidence-profiles.md) — Generic release capture, closed profiles, hardlink rejection, and in-process `ReleaseCapture`.
- [ADR 0005: Publication state, planner, and receipts](adr/0005-publication-state-planner-and-receipts.md) — Pure planner, observation derivation, evidence gates, revision allocation, receipts, and nine retry MUST rules.
- [ADR 0006: LIVE1 gates and bootstrap](adr/0006-live-publisher-gates-and-bootstrap-tenants.md) — Mandatory adapter gates, reviewed local verifier authority and exact-generation configuration.

## Implemented specifications

- [Configuration v1alpha1](specs/rs9-config-v1alpha1.md) — Validator and normalizer contract, including the `[evidence]` schema amendment.
- [Release record v1alpha1](specs/rs9-release-record-v1alpha1.md) — Generic release selection, capture, and cryptographic identity.
- [Ingestion record v1alpha1](specs/rs9-ingestion-record-v1alpha1.md) — Authenticated input record for Nebular shadow profile.
- [Dependency evidence v1alpha1](specs/rs9-dependency-evidence-v1alpha1.md) — ELF dependencies, SONAMEs, interpreters, and package mapping.
- [Destination observation v1alpha1](specs/rs9-destination-observation-v1alpha1.md) — Derived destination states, subject binding, and readback verification.
- [Publication plan v1alpha1](specs/rs9-publication-plan-v1alpha1.md) — Pure planner actions, revision allocation, and semantic content identity.
- [Publication receipt v1alpha1](specs/rs9-publication-receipt-v1alpha1.md) — Execution attempt records and confirmed post-readback receipts.
- [Retry and idempotence v1alpha1](specs/rs9-retry-idempotence-v1alpha1.md) — Deterministic retry evaluation and the nine retry MUST rules.
- [LIVE1 policy and receipt v1alpha2](specs/rs9-live1-policy-receipt-v1alpha2.md) — Explicit migration and live-read authority.
- [Qualification record v1alpha1](specs/rs9-qualification-record-v1alpha1.md) — Executed local verifier boundary; imported verdicts grant no authority.
- [Bootstrap tenant v1alpha1](specs/rs9-bootstrap-tenant-v1alpha1.md) — Reviewed exception for these four releases only.

## Foundation qualification records

- [Foundation 1 disposition and qualification](foundation1-candidate.md) — Initial extraction and normalization qualification.
- [Foundation 2 candidate](foundation2-candidate.md) — Authenticated Nebular ingestion and shadow package adapters.
- [Foundation 2 qualification](foundation2-qualification.md) — Containerized build and install qualification receipts.
- [Foundation 2 inventory](foundation2-inventory.md) — File and test delta inventory.

Ecosystem-specific operator and adapter documentation will be added as individual publication channels are qualified and adopted.

- [CONT10 native-client repairs](live1-native-client-cont10.md) — Public APT modes, RPM lint custody, pacman trust classification and bounded preparation diagnostics.
