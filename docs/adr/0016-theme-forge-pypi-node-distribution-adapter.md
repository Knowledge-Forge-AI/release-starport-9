# ADR 0016: offline Node-release adapters for first-wave PyPI candidates

Status: accepted for SOURCE1 local candidate; superseded in part by ADR 0017 for REALQUAL2. SOURCE1 remains terminal BLOCKED/RC2.

## Context

The three frozen releases are npm tarballs, not Python distributions. The task
requires truthful metadata, usable entrypoints, offline reconstruction and
platform qualification before any publisher workflow. The bound planner
proposal is 23,016 bytes with SHA-256
`b9079daa57bed2b390a713822dc133c5fa55cb8c2261475d4e86dc35a14230d1`.
Its independent advisory review identified artifact custody, license-path,
native-platform and workflow inventory gaps.

Fresh public asset downloads failed DNS resolution in this stage's restricted
shell; the web reader could not retrieve their binary bytes. No exact release
tarball is present in the isolated clone. Existing candidate evidence is not
sufficient to qualify this new adapter.

## Decision

Proposal disposition: **amend**. Preserve the original three-product scope and
frozen releases. Implement a stdlib local adapter and provider-free checks for
dependency-free Loom/Sail. Keep all three verdicts BLOCKED, emit no Burst
distribution and enable no publishing workflow. This is an incomplete product
qualification result, not a replacement of the requested scope or a claim that
any upstream release cannot be wrapped.

The sdist carries the immutable release tarball and the offline in-tree backend.
It describes an adapter source distribution, not a rebuild of upstream TypeScript
or native source. All License-File paths are identical relative to the sdist root
and wheel .dist-info/licenses. PKG-INFO equals METADATA byte-for-byte. Metadata
version 2.4 provides the required PEP 639 fields; Python >=3.13 is provisional for
local fixtures only, pending a qualified interpreter matrix before publication.
No new Python dependency, package-manager policy
or lockfile is introduced. The backend uses a private in-tree `rs9` helper
package so the original repository's absolute-import hygiene contract remains
valid without installing RS9 as a build dependency.

The planned edits to `docs/README.md` and `docs/live1-pypi.md` are superseded by
the new standalone first-wave guide. Both existing documents are consumed by
historical approval pins; they remain byte-identical to the base. The new guide
explicitly supersedes the old publisher table and sdist stance without changing
the existing operator or its approvals.

The backend refuses all runtime npm closures and native/platform-limited payloads.
Burst stays entirely withheld pending exact-byte closure/license and native
qualification. There is no foreign-prebuild retention/pruning decision embedded
in a shipping artifact, and no unsupported-host Burst sdist fallback.

## Plan-review disposition

| Finding | Disposition and resulting behavior |
| --- | --- |
| 1: exact workflow-list tests | Accepted. No product is qualified, so no workflow is added; both existing inventory tests remain valid and unmodified. New tests enforce no tfnf or first-wave publisher and pin APGR workflow bytes. |
| 2: cross-host archive identity | Accepted. Compare full member identities, metadata and modes; store wheel members without compression for reproducible wheel bytes. Same-host sdist rebuild checks exact wheel bytes; outer sdist bytes remain separately hashed. |
| 3: PEP 639 relative legal paths | Accepted. LICENSE/NOTICE/optional COMMERCIAL-LICENSE.md exist at sdist root and the same paths below wheel .dist-info/licenses. |
| 4: digest alone is insufficient approval | Accepted. Candidate manifests never grant publication admission. Future workflows require committed filename/logical pins and a reviewed same-commit main qualify run in addition to the operator digest. No publish selector is exposed. |
| 5: foreign native members | Accepted as an unresolved production blocker. No Burst wheel/sdist; candidate retention precedent is not adopted as proof. |
| 6: stricter libc-only policy | Accepted clarification. This is proposed local policy, not the PEP 600 portability definition; no such tag is emitted. Prior matching-digest records are not fresh proof. |
| 7: Darwin offline isolation | Accepted. Receipts say not-run unless actual Linux isolation was explicitly exercised. |
| 8: readback unknown/conditional execution | Accepted. Unknown local remote-state command exits nonzero; future post-publish readback must be publish-only and fail closed. No readback workflow is enabled. |
| 9: Python floor/action pin | Amended. Candidate Python floor >=3.13; no setup-python action is added, and 3.10 is unclaimed. |
| 10: Burst sdist unsupported-host fallback | Accepted by withholding Burst sdist entirely. |

There were no dispatcher-observed stage deltas before production. During
implementation, unavailable fresh intake changed the achievable qualification
boundary. The requested original outcome remains first-wave real distributions;
this candidate intentionally reports the unresolved part rather than inventing
successful release-byte results.

## Verification and consequences

Synthetic fixtures cover offline build, wheel/sdist custody, metadata/licenses,
malicious archives, identity/hash/size drift, entrypoints, dependency/native
refusal, Node prerequisites, unsupported consumer hosts and remote state. Real
pip/Node fixture lifecycle checks verify the adapter mechanism only. Optional
live tests and CLI checks require exact supplied release bytes. Detailed observed
results and changed-file inventory are retained in
`evidence/tf-pypi/first3-source1-verification.json`.

APGR's publisher, pins, journals and existing assets remain outside the patch.
No external write, workflow dispatch, account step, version bump, stage, commit
or push is permitted or performed. The dispatcher supplied an independent
pre-final advisory review. The terminal producer applies the disposition below;
no additional review was requested.

## Work-review disposition at closeout

Terminal disposition: **amend**, retaining all products as BLOCKED. The product
qualification phase remains incomplete; this is not merge-ready or publish-ready.

| Finding | Disposition and terminal evidence |
| --- | --- |
| 1: real release bytes unavailable | Accepted as a blocker. Fresh public GETs for all three products again failed DNS. `closeout-intake.json` captures reproducible commands and sanitized error classes/codes. No manifest or functional feasibility claim is inferred from prior receipts. Networked-host intake remains required. |
| 2: red gates and unsupported failure attribution | Accepted as an unresolved admission blocker. Eleven selected tests report identical three failures/six errors on candidate and a fresh HEAD archive. The two APGR CLI tests pass in both; the prior discrepancy remains unexplained. Read-only committed-delta comparison matches the historical manifest, but the live inventory test fails with these additions. Closed source inventories expand as well. No historical approvals, controller bindings or APGR pins are refreshed. This narrow baseline control supersedes the earlier unsupported attribution, not the gate requirement. |
| 3: undeclared static metadata | Accepted for Summary, Classifier and Project-URL: now explicit in `[project]`, with complete mapped-field/entrypoint regression checks. README content type is now explicit rather than inferred from `.md`. The backend refuses altered static metadata/README. `Requires-External` has no standardized PEP 621 key; it remains backend metadata derived from the pinned Node prerequisite, not an invalid `dynamic` key. See the official [pyproject specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/) and [core metadata specification](https://packaging.python.org/en/latest/specifications/core-metadata/). |
| 4: Python floor chosen from test host | Accepted as a shipping blocker. Keep >=3.13 provisional for this prototype; do not invent untested compatibility or upload frozen metadata. Select the final floor from a qualified interpreter matrix before unblocking. |
| 5: symlinked temporary-directory ancestors | Accepted and corrected at the trusted backend location. Resolve the already imported backend's own path before reading its helpers/pins; retain strict descriptor-relative no-follow reads for untrusted assets. A separate-process aliased import now rebuilds the exact wheel with Python network access denied. This tests a frontend path alias, not every frontend. |
| 6: universal wheel installs on unsupported Windows | Accepted as a shipping blocker. Local pure-payload wheels are explicitly unshippable prototypes. Qualify a portable launcher or restrict artifact tags and sdist builds before READY; no untested platform tag is invented. |
| 7: RS9 adapter notice omitted | Accepted and corrected. A separate RS9-NOTICE preserves RS9 copyright and AGPL terms in sdist root and wheel licenses, with matching License-File metadata; upstream legal bytes are unchanged. |
| 8: npm/npx token heuristic | Accepted limitation. Retained only as a conservative admission heuristic; it can false-refuse and cannot prove closure or absence of downloads. Real-byte closure scanning and network-denied smoke remain mandatory before READY. |

The three new backend regressions reproduced missing static declarations,
aliased-path refusal and acceptance of modified static metadata before fixes.
The final focused suite passes 58 tests and skips three unavailable real-input
tests. Full-suite results remain historical evidence, not a new terminal pass.

Python profile: Orange for authorized packaging/backend and executable-launcher
contracts. Stdlib modules are decomposed by intake, build, validation, runtime
and remote observation. Compatibility and adverse-input tests support the
decision. Rollback removes only the new tf-pypi source/tests/pins/docs; it does
not require changing prior releases
or APGR operation.

## What would make this wrong

Fresh bytes may reveal different package facts, hidden runtime dependencies,
missing legal files, command behavior requiring other resources, or an upstream
runtime contract the adapter cannot support. Such results keep that product
BLOCKED. A genuine portable Burst design may be feasible after direct native
inspection; this ADR does not conclude otherwise. Any shipping change requires
fresh platform evidence and a separate reviewed workflow implementation.
