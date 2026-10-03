# Release Starport 9

**Release Starport 9 (RS9)** is Knowledge Forge AI's publication-infrastructure hub for software releases.

Projects remain responsible for producing authoritative public GitHub releases. RS9 consumes those releases, verifies their identity and provenance, and handles downstream packaging and publication across supported ecosystems.

The short name and prospective CLI name are **`rs9`**.

## Mission

RS9 exists to centralize publication machinery that would otherwise be duplicated across projects:

- release discovery and authentication;
- package-manager and registry adapters;
- deterministic package generation;
- signing and trust bootstrap;
- provenance and publication receipts;
- clean-install and tamper/fail-closed qualification;
- hosted package-repository generation;
- downstream repository projections; and
- contribution workflows such as opening or updating upstream packaging pull requests.

A project's normal publication boundary should eventually be:

```text
project CI
  -> version/tag
  -> authoritative GitHub Release + release assets
  -> RS9
  -> downstream registries, repositories, projections, and upstream PRs
```

## Planned publication roster

The standard RS9 roster is:

- npm
- PyPI
- Nix
- Homebrew
- pacman / Arch Linux
- DNF / RPM
- APT / Debian and Ubuntu

Official ecosystem repositories such as nixpkgs, Homebrew repositories, distro repositories, or AUR repositories may require their own repository topology or contribution workflow. RS9 treats those as publication destinations rather than separate sources of truth.

Go-module publication is intentionally project-dependent and is not part of the mandatory standard roster.

## Project configuration

Projects opt into RS9 through declarative configuration under:

```text
<project-root>/.rs9/
```

The intended model is a small set of TOML files, for example:

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

Only relevant adapters need configuration. Project configuration should describe project-specific facts and publication intent; ecosystem mechanics belong in RS9 rather than arbitrary executable project hooks.

## Publication modes

RS9 supports three broad publication modes:

1. **Direct publication** — publish to a registry or RS9-hosted repository.
2. **Projection publication** — generate and update ecosystem-specific repositories such as a Homebrew tap or AUR package repository.
3. **Contribution publication** — generate a downstream change and open/update a pull request to an external packaging repository.

Repository sprawl may therefore exist where an ecosystem requires it, while publication authority and machinery remain centralized in RS9.

## Hosted package domain

The canonical package-serving hostname is intended to be:

```text
rs9.knowledge-forge.ai
```

`packages.knowledge-forge.ai` is a convenience redirect to the corresponding RS9 path.

## Licensing boundary

RS9 itself is licensed under the GNU Affero General Public License v3.0 or later unless a file states otherwise.

**That license covers RS9's own publication infrastructure, generators, adapters, templates, verification tooling, documentation, and other RS9-authored material. It does not relicense the projects or release artifacts that RS9 packages, mirrors, verifies, or publishes.**

Every distributed project remains governed by the licensing and notice terms of its own authoritative source repository and release artifacts.

See [LICENSE](LICENSE), [NOTICE](NOTICE), [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [CLA.md](CLA.md).
