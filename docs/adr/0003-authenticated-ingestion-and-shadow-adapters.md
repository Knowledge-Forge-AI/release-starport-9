# ADR 0003: authenticated input records and deferred shadow adapters

Status: Foundation 2 terminal source candidate; pre-final reviewed with findings.
Terminal amendments have scoped verification and no additional review. No live
publication or migration adoption is authorized by this decision.

## Context

Foundation 1 normalized intent without authenticating releases or rendering
recipes. Nebular Fusion 0.6.1 supplies three public raw archives, tagged source
license/icon material, publisher evidence and an existing distribution reference.
A recorded digest or a JSON field claiming authentication cannot establish
freshness, publisher identity or package acceptance.

## Decision

Keep public HTTPS collection separate from deterministic authentication over
captured bytes. Bind repository/tag/commit/tree, API asset identities, byte sizes,
GitHub digests, SHA256SUMS, tagged Git blobs, safe archive manifests, native
commands, optional upstream launchers and payload license copies. Reject truncated
trees, duplicate assets, unsafe archive structures and inconsistent evidence.
Publisher provenance is consistency evidence; signatures/attestations remain
unevaluated. Neither ingestion identity nor fixtures contain an assurance flag.

The renderer requires an in-process byte-authentication result and rechecks raw
bytes. It always emits a deferred shadow verdict. A saved record is not an
acceptance capability. Fresh collection, reconciled license authority, provider
mapping proof and package/install qualification remain separate gates.

Derive Linux evidence from every released ELF object and executable shebang
member. Record interpreters, needed SONAMEs, loader search paths, symbol floors,
bundled providers, script engine declarations and unresolved behavior. RS9 owns
distro package mappings and desktop integration dependencies. Tenant runtime
facts contain no distro names.

Extend v1alpha1 only with optional summary, desktop command/categories, an explicit
tagged-repository PNG selection, and per-asset upstream launcher selections.
Include an optional unresolved license marker so normalized consumers can see
the known tenant authority conflict; it cannot assert resolution or acceptance.
Derive icon dimensions from authenticated bytes. Add operator destination
`profile = "aur"`; generic projection mode alone does not select AUR layout.
Every amendment has positive/adverse validation and normalized evidence.

Render whole payload trees with preservation controls, local desktop text and
hash-bound source downloads. Nix uses mandatory Linux FHS wrapping and no GUI
build-time check; pacman/AUR disable stripping/debug/purge/zipman transformations;
RPM disables payload-altering brp steps and verifies sources in `%prep`. Private
SONAME filtering excludes corresponding generated requirements and providers
together. Publication, signing, builders in RS9 source and live projection writers
remain outside this slice. The qualification harness is scratch-only.

## Consequences

The genuine npm artifact license conflict remains unresolved. Source and tagged
payload licenses agree on AGPL-3.0-or-later; the published wrapper declares
AGPL-3.0-or-later OR Commercial. Exact-string reconciliation does not validate
SPDX list membership or interpret commercial licensing. RS9's own license remains
separate. This phase supplies source and evidence for review, not migration
acceptance.

Python remains standard-library-only, with Python 3.11 as the compatibility floor.
Bounded protocol traversal functions are a scoped structural exception for this
first slice: procedural parsing makes offsets, limits and failure paths auditable;
adverse tests and both live architectures constrain it. No generic plugin/parser
framework is introduced. Before broader tenancy, split profile-specific capture
and legal evidence selection from the reusable core. Rollback is removal of the
new shadow modules and optional facts; live distribution remains unchanged.

See the [candidate disposition](../foundation2-candidate.md),
[record specification](../specs/rs9-ingestion-record-v1alpha1.md),
[dependency model](../specs/rs9-dependency-evidence-v1alpha1.md) and
[Nebular design](../architecture/nebular-shadow-projection.md).
