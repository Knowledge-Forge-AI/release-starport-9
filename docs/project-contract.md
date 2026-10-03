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
- explicit about authoritative release assets;
- explicit about which publication adapters are enabled;
- free of long-lived credentials and private signing material; and
- narrow enough that ecosystem mechanics remain in RS9.

Arbitrary shell hooks are not part of the default contract. When a project needs behavior that is broadly useful, prefer adding a reusable RS9 adapter capability and representing the project's choice declaratively.

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
- expected executable names;
- project license identity and authoritative license location;
- package names for individual ecosystems;
- supported operating systems and architectures;
- adapter enablement; and
- destination-specific names or metadata that are genuinely project facts.

### RS9 should own

- registry/repository API mechanics;
- trusted-publishing and signing integrations;
- package construction implementation;
- reproducibility and provenance machinery;
- clean-install validation;
- signature and tamper testing;
- repository index construction;
- Pages publication;
- projection-repository updates;
- upstream pull-request workflows; and
- publication readback/idempotence policy.

## Schema versioning

Every RS9 configuration file should eventually carry or inherit an explicit schema version. RS9 must reject unsupported or ambiguous configuration rather than guessing.

The concrete TOML schemas are intentionally deferred until the first Theme Forge migration slice can derive them from real publication requirements.
