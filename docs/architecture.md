# Release Starport 9 architecture

Status: intended architecture. The foundation currently validates and normalizes
configuration only; publication and release authentication remain unimplemented.

## Role

Release Starport 9 (RS9) is a publication control plane. It begins from an authoritative public project release and carries that release into downstream registries, package repositories, projection repositories, and upstream packaging contribution workflows.

The source project remains authoritative for application source, application versioning, Git tags, GitHub Releases, and the release assets it declares authoritative.

RS9 is authoritative for shared publication machinery.

## Core boundary

A normal RS9-managed release should flow as:

```text
source project
  -> reviewed source commit
  -> version/tag
  -> authoritative GitHub Release and assets
  -> RS9 release ingestion
  -> release/authenticity checks
  -> ecosystem adapters
  -> qualification
  -> publication/projection/upstream contribution
  -> publication provenance and readback
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

Go modules and other ecosystems can be supported project-by-project without becoming mandatory parts of the standard roster.

## Publication modes

### Direct

In the intended direct mode, RS9 publishes to a registry or repository under RS9 control.

Examples include hosted APT/DNF/pacman repositories and, where authentication models permit, package registries.

### Projection

RS9 generates another repository or maintained downstream surface from its canonical publication inputs.

The existing Homebrew tap is expected to become a projection rather than an independent source of publication logic. AUR's one-repository-per-package model is another natural projection target.

### Contribution

RS9 prepares and maintains changes against an external repository, including opening or updating pull requests when that ecosystem requires upstream review.

Examples may include nixpkgs, Homebrew upstream repositories, and distribution package repositories.

## Tenant model

Projects are tenants of RS9, not owners of RS9's shared machinery.

Project-specific facts and publication intent live under `<project-root>/.rs9/`. RS9 owns the parsers, schemas, adapters, policy, verification logic, and destination mechanics.

Theme Forge is the first migration tenant. Its current Nix, pacman, DNF/RPM, AUR-readiness, APT, and Homebrew work will be used to extract reusable RS9 infrastructure without changing the authority of existing Theme Forge releases.

The provisional extraction treats each independent release stream as a project.
Theme Forge groups four such projects; a family label has no publication
authority. A selected project root can lie below a build monorepo root, while
its declared repository remains the release authority. Shared keys, hosted
repositories, flake and tap are operator/RS9 destinations, not a single tenant's
configuration.

The foundation validates [v1alpha1 configuration](specs/rs9-config-v1alpha1.md)
and normalizes intent only. See the [inventory](architecture/theme-forge-extraction-inventory.md),
[adapter/destination model](architecture/adapter-destination-model.md) and
[migration map](architecture/migration-map.md) for evidence and unimplemented gates.

## Hosted publication domain

The intended canonical hosted publication origin is:

```text
https://rs9.knowledge-forge.ai/
```

`https://packages.knowledge-forge.ai/` is a convenience redirect preserving path and query.

Public client configuration should prefer a stable custom domain rather than binding clients to a GitHub repository name or GitHub Pages project path.

## Trust and signing

RS9 should reuse a deliberate, bounded signing authority where multiple package-manager repositories are intentionally governed by the same publication trust root, while respecting ecosystems that provide their own trusted-publishing identity systems.

Private signing material must not be committed to RS9, tenant repositories, projection repositories, evidence archives, or public Pages artifacts.

Validation should use fixture or ephemeral keys where production signing is not required.

## Licensing boundary

RS9's license applies to RS9 infrastructure and RS9-authored material. It does not relicense tenant projects or their release payloads.

Adapters and generated package metadata must preserve the licensing identity of the software being distributed.
