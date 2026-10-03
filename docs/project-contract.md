# RS9 project contract

A project opts into Release Starport 9 with declarative configuration under:

```text
<project-root>/.rs9/
```

The project repository owns these configuration files. RS9 owns their schemas and interpretation.

## Design rules

The contract should stay:

- declarative rather than executable;
- reviewable in the source project;
- stable across RS9 implementation changes;
- explicit about authoritative release assets and evidence bindings;
- explicit about which publication adapters are enabled;
- free of long-lived credentials and private signing material; and
- narrow enough that ecosystem mechanics remain in RS9.

Arbitrary shell hooks are not part of the contract. When a project needs behavior that is broadly useful, prefer adding a reusable RS9 adapter capability and representing the project's choice declaratively.

## Intended file layout

```text
.rs9/
  project.toml
  releases.toml
  npm.toml
  pypi.toml
  nix.toml
  homebrew.toml
  pacman.toml
  dnf.toml
  apt.toml
```

Only applicable files need to exist.

## Responsibility split

### Project configuration may describe

- canonical project identity and source repository;
- release/version conventions;
- authoritative GitHub Release assets and platform mappings;
- declarative `[evidence]` selections (checksums template, profile, and explicit `{role, name}` asset tables);
- expected executable names;
- explicitly selected release-owned launchers, summary and desktop/icon facts;
- project license identity and authoritative license location;
- package names for individual ecosystems;
- supported operating systems and architectures;
- adapter enablement; and
- destination-specific names or metadata that are genuinely project facts.

### RS9 owns

- generic release capture and byte authentication (`rs9.release_core`);
- archive member inspection and fail-safe hardlink rejection (`rs9.archives`);
- destination state observation and readback verification (`rs9.observation`);
- evidence-bound safety gate evaluation (`rs9.gates`);
- pure publication planning and action determination (`rs9.planner`);
- revision allocation for mutable and immutable destinations;
- registry/repository API mechanics and execution attempt auditing;
- confirmed publication receipts and remote proof verification (`rs9.publication`);
- deterministic retry evaluation enforcing the nine retry MUST rules;
- trusted-publishing and signing integrations;
- package construction implementation;
- reproducibility and provenance machinery;
- clean-install validation;
- repository index construction;
- Pages publication; and
- projection-repository updates and upstream pull-request workflows.

Records hash raw bytes, not signatures or ambient authority. Sealed in-process `ReleaseCapture` containers and anti-forgery sentinels ensure that persisted audit JSON cannot reauthorize publication gates without fresh in-process byte verification.

## Schema versioning

Every RS9 configuration file carries an explicit schema version. RS9 rejects unsupported or ambiguous configuration rather than guessing.

The [v1alpha1 specification](specs/rs9-config-v1alpha1.md) implements a strict validator and normalizer. It promises no stable compatibility or production publication. Only selected adapter files are needed; the caller can explicitly select a project root below a monorepo root. License paths are relative to the declared release repository at the resolved tag commit.

The Foundation 3 amendment introduces the `[evidence]` table in `releases.toml`: optional for pure intent normalization, but strictly required for release authentication.

## Local Links

- [ADR 0001: Tenant contract v1alpha1](adr/0001-tenant-contract-v1alpha1.md)
- [ADR 0004: Ingestion core and evidence profiles](adr/0004-ingestion-core-and-evidence-profiles.md)
- [ADR 0005: Publication state, planner, and receipts](adr/0005-publication-state-planner-and-receipts.md)
- [Specification: Configuration v1alpha1](specs/rs9-config-v1alpha1.md)
- [Specification: Release record v1alpha1](specs/rs9-release-record-v1alpha1.md)
- [Specification: Destination observation v1alpha1](specs/rs9-destination-observation-v1alpha1.md)
- [Specification: Publication plan v1alpha1](specs/rs9-publication-plan-v1alpha1.md)
- [Specification: Publication receipt v1alpha1](specs/rs9-publication-receipt-v1alpha1.md)
- [Specification: Retry and idempotence v1alpha1](specs/rs9-retry-idempotence-v1alpha1.md)
- [Architecture overview](architecture.md)
