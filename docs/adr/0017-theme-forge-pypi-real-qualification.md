# ADR 0017: authenticated Theme Forge Python adapter qualification

Status: source candidate for dispatcher pre-final checkpoint; no publication authority.

## Context and proposal disposition

This successor continues the uncommitted SOURCE1 candidate; SOURCE1 remains
terminal BLOCKED/RC2. All six manager-supplied archives are readable in this stage.
The exact 23,115-byte proposal, SHA-256
`b92bc2a1cb2f573d451df2fea1b39f6c9ac03c78367be71f01a65d71f916616d`,
is **amended**. Original task scope, proposal bytes and review findings remain
distinct. Every advisory finding is dispositioned in
`evidence/tf-pypi/realqual2-plan-disposition.json`; no stage deltas were supplied.

## Decision

Build Python wrappers around unchanged Node releases with external Node.js >=22.
No npm installation, lifecycle script, install-time or import-time download is
used. Admission checks exact size/hash, inner identities, bins and hostile archive
members. Only a benign leading ./ in bin declarations is normalized for comparison.
Burst's exact three authenticated dependency trees are mounted deterministically
inside its private payload/node_modules. Their identities, legal files and indirect
runtime needs are checked. The supplied task/manifest and prior loader evidence
bind dependency digests; the original AUR PKGBUILD was not supplied or freshly read.

Burst keeps only its target .node file in each wheel. Original source/dependency
archives remain unchanged in its sdist. The source-bound transform records every
omission and dependency digest. Inspection confirms the loader selects one addon
without requiring foreign binaries. All four selection paths and Windows/musl
refusal are simulated; only Darwin ARM64 is actually loaded and executed.

Burst's Darwin ARM64 tag is macosx_13_0_arm64, derived from LC_BUILD_VERSION.
Darwin x64 declares macOS 15; Linux ARM64/x64 reference GLIBC 2.33. None of those
foreign binaries was executed. All four compiled get-api-version functions return
8; the manifests' Node-API 10 fields describe the build runtime. Registration
symbols alone do not establish the requested API. See the official
[Node-API matrix](https://nodejs.org/api/n-api.html#node-api-version-matrix).

Only Darwin ARM64 is qualified. Loom/Sail use macosx_11_0_arm64 (the architecture
baseline), rather than an unqualified universal tag. All wheels set Root-Is-Purelib
false. The launcher checks the actual Node platform/architecture and Linux glibc.
PEP 517 builds refuse unqualified hosts. Explicit cross-target dist builds can
reproduce already-qualified artifacts in CI; they do not qualify CI's host.

The wrapper floor is Python >=3.9, tested through complete lifecycles on 3.9.6 and
3.13.12. Intermediate minors are inferred, not directly tested. This floor applies
to the installed launchers and the sdist's empty private rs9 namespace; the RS9
application retains its existing Python policy. ZIP_STORED and fixed stored-DEFLATE
gzip produce byte-identical builds across those interpreters. Wheel RECORD,
METADATA/PKG-INFO, entrypoints, licenses, helpers and payload agree with the sdist.
RS9's own AGPL license/notice is included separately; Burst's composite expression
also includes dependency MIT and BSD-3-Clause terms. Upstream legal bytes are unchanged.

The enforced provider sandbox denies literal-IP TCP with permission errors and
DNS for Python and Node. The harness checks that boundary before installation;
--no-index alone is not isolation. Nested sandbox-exec is refused and is not
claimed as successful. Real probes compile bundled themes and a positive batch;
Burst imports/builds/checks/bundles an SVG directory through native snapshots and
completes a Studio initialize/shutdown/exit session. Missing, old, non-executable
and wrong-platform Node runtimes fail before upstream execution.

Only qualified products receive their exact registered workflows. Both jobs
checkout github.sha so code and committed artifact pins come from the same
immutable run commit. Dispatch-only/main-only jobs use the existing four APGR
action SHAs. Only the publishing job receives id-token write in environment pypi.
Build and publish verify the complete approved set. Remote reconciliation checks
names/version/files/sizes/hashes/yanked state and downloaded bytes. Unknown or
conflict refuses selection; an exact subset selects only missing approved files.
Post-upload readback must be exact. No local command uploads or dispatches.

## Consequences, verification and deferrals

READY is bounded local product qualification, subject to independent dispatcher
review and closeout. It is not source adoption or publication approval. The
verification record preserves real receipts, independent legacy baseline results,
remaining historical failures and unrun hosted checks. The cumulative candidate
manifest is refreshed; historical E1/AUTH1 bindings remain unchanged.

Use isolated venvs. Command names match upstream npm/AUR names, so root/system pip
can overwrite another installation and PATH ordering can shadow one. Dynamic
coexistence checks cover all three products, disjoint RECORDs, uninstall behavior
and preserved apgr/tfnf sentinels. No adapter installs those two commands.

Python profile: Orange for authorized packaging/backend contracts. The source-bound
stdlib native parser is a bounded callable-size exception backed by adverse and
real-byte tests. Unscoped fallback imports and silent broad exception handling
were removed. Further parser decomposition is a maintenance follow-up. Rollback
restores only successor paths; APGR and upstream assets need no rollback.
Permitted temporary storage is used because configured shared scratch is outside
the sandbox's writable roots. Durable sanitized receipts live in this repository.

## What would make this wrong

A changed input hash, missing indirect dependency/license, native load failure,
unreviewed transform, reproducibility mismatch, unsupported sdist host, or unrepaired
candidate-only regression invalidates the affected qualification. Simulated foreign
selection is not foreign runtime proof. A byte-exact hosted qualify run, independent
post-closeout review, verified adoption and operator publisher readback remain
publication gates; provider transport success cannot substitute for them.
