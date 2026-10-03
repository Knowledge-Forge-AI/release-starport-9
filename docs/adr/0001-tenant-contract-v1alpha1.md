# ADR 0001: provisional tenant contract

Status: implemented provisionally; no compatibility promise or production use.

Foundation 2 adds optional summary/desktop/tagged icon facts and per-asset
release-owned launcher selections, plus explicit operator AUR profile selection.
The validator still performs no network or execution. Separate modules now
authenticate captured bytes and render deferred shadow candidates. See
[ADR 0003](0003-authenticated-ingestion-and-shadow-adapters.md) for the amendment;
the original Foundation 1 boundary described below remains historical context.

## Context

Theme Forge distribution joins four independently versioned products in one
signed repository and Nix flake. npm artifacts are built in a monorepo, while
the distribution lock names separate release repositories. A tap already holds
Theme Forge and APGR. Shared destinations cannot belong to a single tenant.

## Decision

One selected project root contains one `.rs9` directory, one release repository,
and one version stream. `project.repository` names release authority, not
necessarily the source/build monorepo. A family label groups documentation only.
The selected root may be a subdirectory in a monorepo. A caller selects it
explicitly; RS9 does not recursively discover projects or infer authority from
directory names. License paths remain relative to the root of the declared
release repository at its resolved tag commit. A tag such as `tool-v{version}`
permits prefixes. Independent streams need independently selected configurations.

Require `project.toml` and `releases.toml`; require only selected adapter files.
Every file has its own `rs9.<kind>.v1alpha1` schema. Unknown files, keys and
versions fail. Project files express facts and intent; operator-owned
destinations bind adapter, mode and served platforms. Exactly three modes exist:
direct (including registries), projection, contribution.

The implementation validates relationships and emits deterministic JSON. It
does not authenticate releases, execute checks, render packages, sign, publish,
or authorize a destination. Current Nebular mappings demonstrate this boundary.
Invented MIT npm/PyPI inputs demonstrate independent payload licensing.

Smoke checks are argv arrays, with declared command names and explicit display
requirements. Neither shell hooks nor scripts are supported. Checks awaiting a
display-capable harness must remain pending; skipping a GUI check must not be
represented as a successful launch qualification.

License expression and tagged-repository-relative license files are mandatory.
The interpreter preserves the expression exactly; no RS9 license default exists.
Syntax checking is not license-list or legal validation: `AGPL-3.0-or-later OR
Commercial` passes syntax, but remains an unresolved tenant-authority issue.
Non-NFC expressions are rejected to preserve exact expression bytes in output.
RS9 examples retain RS9's existing license. No automatic relicensing on copying
and no new permissive exception is claimed. A steward exception remains deferred.

Digests and packaging revisions belong to ingestion/publication state, not
tenant configuration. Raw config SHA256 evidence is separate from normalized
semantics: repeated identical input yields identical complete output, while
format-only edits change evidence hashes but preserve semantics.

For `any` assets, a target has one architecture-independent payload per
destination, indexed for selected served CPUs. pacman/RPM/APT map it to
`any`/`noarch`/`all`; they do not clone the package for each architecture. For
concrete assets, intersect source coverage, package restrictions and destination
platforms before ecosystem mapping. Empty intersections fail.

## Consequences and limits

Only naming, asset selection and routing intent are executable adapter contracts.
Dependency derivation, Nix FHS wrappers/aliases, desktop files/icons, package
metadata and revision policies require a later shadow adapter. APT illustrates
routing to a staged candidate, not live integration. Public trust metadata and
credential references are deferred to an operator contract; no names or values
are accepted in tenant files.

Promotion to a stable version requires a qualified migration and a reviewed
compatibility policy. A tenant with multiple version streams tied to one
indivisible release, conflicting per-artifact license terms, or unrepresentable
asset selection may require a successor schema. Fail rather than guess.
