# Theme Forge publication extraction

Status: research inventory for a provisional RS9 foundation. No tooling is moved
from a tenant repository, no production publication is changed, and no adapter
implementation is imported. Facts are observations, not release authentication.

## Sources and observations

Private distribution authority: `theme-forge-stellar-burst`,
`tools/distribution/` and its nested generated `theme-forge-packages/` projection.
At entry, the local branch was 18 commits ahead of its remote-tracking ref and
had additional working-copy changes. The generator/workflow/bootstrap state is
partly unpublished. The private and nested release locks have SHA256
`567b91e43e9e3d871d19f96abbaa4c593de0f0c99029d56f3fd903b5635b29cc`.
Current workflow bytes include the pinned Nix installer and still invoke GUI
version checks. A pin alone does not prove hosted validation is repaired.

The fresh public audit inspected
[hosted run 37079040848](https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/37079040848)
at the hotfix: Linux Nebular checks report a bubblewrap UID-map denial; macOS
reports a Tao abort while running the native GUI version check. A display flag
describes the tenant check requirement; it does not fix Linux namespace policy
or establish a replacement qualification harness. Those remain separate gates.

APT: `tools/distribution-apt/` is untracked staged candidate authority, with 14
patches and an explicit fold-in map. Its docs describe private qualification;
that qualification was not rerun here. No live DIST1 APT integration is assumed.
The candidate's matrix SHA256 is
`b239018d67711059dd3cb6fcf54fcc79c4c47905db2b225f6720036aa36e998f`.

The extracted fact fixture records source repository, revision context, path,
working-copy state and SHA256 for every surface tuple. It is authored from actual
lock/recipe/matrix bytes, not a verbatim third-party import or a second hand copy
of example configuration. Public remote readback is recorded separately in the
[candidate handoff](../foundation1-candidate.md).

| Product | Observed version | Distribution input | Commands |
|---|---|---|---|
| Stellar Burst | 0.6.1 | npm registry tarball | `tfsb`, `tfsb-studio-service` |
| Stellar Loom | 0.4.0 | npm registry tarball | `tfsl`, `tfsl-batch` |
| Solar Sail | 0.2.1 | npm registry tarball | `tfss` |
| Nebular Fusion | 0.6.1 | three GitHub native archive URLs | `tfnf` |

The first three inputs use lock cache names distinct from their observed GitHub
asset names. Fresh public release API reads found corresponding
`knowledge-forge-ai-<product>-<version>.tgz` assets at all three current tags;
API-reported digests match the lock. This resolves availability uncertainty,
but does not replace downloaded-byte authentication and release-lineage checks.
Nebular supplies aarch64 Darwin and aarch64/x86_64 Linux archives.
The executable example targets Nebular only. All four products remain research
inputs for the family-wide migration.

## Classification

Each row identifies its primary owner. Secondary responsibilities are stated
explicitly; a source's current location does not determine future ownership.

| Concern and current evidence | Classification | Extracted responsibility |
|---|---|---|
| TF `tfsb66b/publication_releases.py`; APGR release workflow: tag/asset readback | RS9 shared core; tenant fact | Core resolves explicit release/tag/commit, rejects drafts, authenticates assets and lineage; tenant declares repository/tag/prerelease intent. |
| DIST1 `release-lock.json`, asset size/digest and executable hash | RS9 shared core | Generated ingestion record binds immutable inputs, not durable tenant-authored hashes. Registry-sourced inputs are historical migration evidence. |
| PKGBUILD/spec/formula/npm names; Nebular AUR `-bin` | Tenant/project fact; ecosystem-owned policy | Tenant names packages; adapter validates ecosystem syntax; destination defines reservation/topology policy. |
| `pkgrel`, RPM Release and APT revision | RS9 shared core; ecosystem-owned policy | Publication state allocates revisions without changing tenant application version; version ordering remains adapter-specific. |
| Raw archives and APT architecture matrix | Tenant/project fact; RS9 destination/projection | Tenant declares asset platform coverage; destination serves a subset; adapter maps labels and represents architecture-independent payloads once. |
| `rawArchives.*.executablePath`, npm wrappers | Tenant/project fact | Assets map declared commands to archive-relative paths. Runtime-specific wrapper rendering belongs to adapters. |
| `templates/{pacman,rpm,nix,aur}`; APT build tools; tap formulas | RS9 adapter | Render packages/recipes from authenticated normalized input. No recipes are rendered in this phase. |
| `!strip`, disabled RPM strip, `dontStrip`/`dontPatchELF`, FHS wrapper and installed hashes | RS9 shared core; RS9 adapter | Core native payload identity invariant, adapter packaging mechanics and explicit transformation records. Contribution policy can require source builds; that is a separately qualified channel. |
| Public key and `KEY-METADATA.json` | Credential/operator configuration; RS9 destination/projection | Operator controls private authority and rotation; destination binds public trust. Current primary fingerprint `7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF`, subkey `C021E00EE3D37C459B0E1CB3199F8028126E8A8C`; public metadata only. |
| `verify-public-key-bootstrap.mjs`, multi-subkey/rotation fixtures | RS9 shared core | Reject fixture trust in production, verify signing-capable binding/expiry/attribution and deliberate rotations. Deferred implementation. |
| `verify-signatures.sh`, hosted tamper fixtures, APT verifier | RS9 shared core; RS9 adapter | Core fail-closed qualification, ecosystem-specific signatures and tamper cases. APT signs indexes, not individual debs. |
| Pinned Arch/Fedora clients; APT clean clients/install/purge | RS9 shared core; tenant fact | Harness owns isolated install/uninstall and readback; tenant declares command expectations/display requirements. No harness implemented here. |
| `publication-provenance.json`, hosted gate receipt, projection binding/Merkle rules | RS9 shared core | Bind input/config/tool/recipe/output/qualification identity. Source schemes are evidence; new RS9 receipt contracts need independent design. |
| `publish.yml` aggregate full replacement of Pages tree | RS9 destination/projection | Static repositories/site generation and deployment belong to destination orchestration. APT requires previous-generation retention before changing indexes. |
| TF npm local token helper; APGR PyPI OIDC and npm guidance | Credential/operator configuration; ecosystem-owned policy | Bind registry publisher per package/workflow. npm provenance repository compatibility and PyPI caller claims need independent qualification. |
| Shared `homebrew-tap/Formula/` and APGR formula | RS9 destination/projection; RS9 adapter; ecosystem-owned policy | Keep Homebrew repository shape; generate only tenant-owned formulas through reviewed projection changes. Keep unrelated families intact. |
| `aur/*` staged recipes | RS9 destination/projection; ecosystem-owned policy; credential/operator configuration | One repository per package, operator AUR account/SSH authority. Current recipes do not prove accepted AUR publication. |
| Official distro/nixpkgs/Homebrew contributions | Ecosystem-owned policy; RS9 destination/projection | PR/review/source-build/maintainer requirements govern contribution mode. No automatic equivalence to direct binary packages. |
| Signing secrets, registry tokens, GitHub environments | Credential/operator configuration | Operator owns secret stores, environment approvals and least privilege. Tenant config owns neither values nor credential lookup names. |
| APGR exact-match no-op; TF npm refuses existing version and verifies sha256/sha1/sha512 | RS9 shared core | Adopt explicit observed states: absent, already exact, conflicting, incomplete. No retry of mutations without authenticated readback. |
| `verify-hosted-validation-gate.mjs` | RS9 shared core | Qualify the candidate inputs before unsealing production signing authority. Configuration validation alone is insufficient. |
| `scan-distribution-privacy.mjs`, receipt-output rules | RS9 shared core | Sanitize durable evidence, exclude private operational paths/data, keep private material out of source and receipts. |
| DIST1 freeze manifest, pending-key bootstrap marker, projection tarball/schema names | Historical evidence / not migrated | Preserve as rollback/evidence; do not make DIST1 identifiers the RS9 public contract. |
| Nebular desktop entry/icons under distribution templates | Tenant/project fact | Tenant must own/authorize desktop artifacts before packaging. Generic icon-source fields would conceal missing authority; deferred. |
| Node >=22; dependency lock and Nix dependency authority | Tenant/project fact; RS9 adapter | Runtime floor is tenant fact; adapter derives vendored closure and ecosystem hashes from authenticated release inputs, recording state. |
| APT Ubuntu 26.04, Debian 13 exclusion, target-specific shlibdeps | RS9 destination/projection; RS9 adapter; ecosystem-owned policy | Suite support/qualification belongs to destination; dependencies derive per architecture, not by translating RPM lists. |
| Nix GUI check in headless sandbox; container CLI checks | Tenant/project fact; RS9 adapter | Display requirement belongs to check intent. Byte identity may qualify payload preservation but does not replace display-capable launch evidence. |
| Distro AGPL expression vs Nebular npm `OR Commercial` | Tenant/project fact | Tenant resolves authoritative license identity. RS9 has no payload license default; syntax acceptance does not resolve legal authority. |
| Tap `test do` fixtures and `tfsl-batch` stdin behavior | Tenant/project fact; RS9 adapter | Complex fixture/stdin checks require a later declarative contract; do not invent `--help` support. |
| TF/APGR checksum and attestation assets | Tenant/project fact; RS9 shared core | Future declarations select evidence; core verifies identity, digests and signer policy. Deferred schema support. |
| APT archive-keyring package | RS9 destination/projection | Destination-owned trust artifact, not a Theme Forge tenant release. Initial trust remains out of band. |

## Migration gaps

Monorepo build authority versus per-product release authority; authenticated
byte readback for npm-sourced release assets; Nebular license discrepancy; current key branding
and UID domain; stale tap version docs; unpublished private generator bytes;
unrepaired hosted qualification; Burst native architecture restrictions; registry
OIDC/provenance compatibility; live github.io URLs without a custom domain;
desktop/icon authority; stdin smoke contracts; APT generation retention and native
amd64 hosted qualification. These are gates/evidence, not reasons to rebuild or
alter released application bytes.

The proposal's AUR Burst `any` assertion is superseded by current recipe bytes:
`x86_64 aarch64`. Loom and Sail are `any`; pacman Burst currently serves only
x86_64, RPM serves both native Linux architectures.
