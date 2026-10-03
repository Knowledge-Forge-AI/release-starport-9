# Foundation 2 Nebular shadow candidate

Status: terminal implementation/testing source candidate. Dispatcher pre-final
review completed with advisory findings; terminal disposition is amend.
Live package acceptance and migration remain deferred. The provider performed
no staging, commit, push or public write; dispatcher finalization is separate.

## Original task scope

Implement the first Foundation 1 packaging slice for Nebular Fusion 0.6.1: fresh
GitHub Release ingestion, source/license/runtime/desktop evidence, Nix/pacman/RPM
and AUR shadow recipes, deterministic text goldens and feasible disposable
qualification. Preserve upstream bytes and existing live publication surfaces.
Only RS9 source, tests, small evidence fixtures and documentation belong in the
candidate. No npm/PyPI/Homebrew/APT adapter, signing, publisher, secrets, external
repository change, DNS/Pages deployment or next migration phase is included.

## Bound proposal disposition: amend

The original planner proposal remains distinct from the task and this candidate.
Its dispatcher binding is 35,874 bytes, SHA256
`1ff5f95a13338013a180011cb70de5f3f5780d44ae7754f8b0d0a71370aa3fb8`,
`plan-material.md`, schema `agent-phase-plan-material-v1`. Disposition: **amend**.
The plan review outcome was `reviewed_with_findings` (advisory), not acceptance.
No stage delta was recorded before production. The producer dispositions are:

| Finding | Applied disposition |
|---|---|
| 1: JSON authentication status cannot grant acceptance | Remove assurance from record identity; require in-process byte authentication and always defer render acceptance |
| 2: RPM private AutoReq/AutoProv mismatch | Scoped matching requirement/provider exclusions for bundled SONAMEs; neither broad AutoProv-off nor orphan private requirements |
| 3: rpmbuild does not verify source hashes | Render explicit raw/desktop/icon `%prep` checksums |
| 4: tagged license vs payload copies | Require byte equality for project LICENSE/NOTICE in every archive |
| 5: sidecar may use an interpreter | Scan all ELF and executable shebang members; record engine constraints and unresolved runtime behavior |
| 6: recursive tree may be truncated | Reject truncated/malformed tree evidence |
| 7: volatile API metadata destabilizes identity | Explicit ingestion output allowlist; timestamps/receipts stay outside identity |
| 8: tenant icon size is derived | Remove size field; derive square hicolor dimensions from tagged PNG bytes |
| 9: SPDX syntax is not membership validation | Exact declaration comparison; retain explicit list-membership limitation |
| 10: external Nix evaluation/launch safety | No external code in parent comparison; qualifier disables IFD; bounded display smoke cannot imply sidecar readiness |
| 11: navigation/status docs omitted | Update architecture, project-contract and install index alongside planned docs |
| 12: generic projection is not AUR | Add explicit operator `profile = "aur"` restricted to pacman projection |

The implementation uses cohesive `fetch`, `github`, `ingestion`, `archives`,
`elf`, `dependencies`, `scratch`, `render`, `compare` and `shadow` modules instead
of the proposal's larger renderer module inventory. Distro maps remain outside
tenant facts. This is a stdlib first-tenant profile, not a new packaging framework.

## Observed stage deltas

Fresh captured bytes independently reproduced all three raw and executable
digests, release/tag/tree identities and tagged source blobs. The real npm
tarball contains the license conflict; the provisional discrepancy remains open.
Archives contain an upstream `tfnf` shim, so the proposed dangling-reference-link
claim is withdrawn. An explicit optional `assets.launchers` amendment preserves
that shim without replacing the native command hash mapping.

The Linux native sidecar is ELF, with C++ symbol requirements; packaged Loom
scripts require Node 22. The whole released tree also contains a native Node
addon. Full-payload evidence replaces the main-executable-only dependency picture.
Tagged PNG authority is selected for Linux desktop integration. Darwin app icons
remain authenticated archive content preserved with the app bundle. Additional
reference PNG sizes are not imported.

The first container pass found `.SRCINFO` architecture-field ordering and an
icon-theme dependency defect. Both were corrected before repeated qualification.
Observed Arch compiler providers are split `libgcc` and `libstdc++`; the mapping
was amended. GLIBC and Node floors are explicit package constraints. Fedora lint
preferences for automatic library Requires do not override this task's explicit
evidence-to-package mapping; official distro contributions remain out of scope.

The initial parent environment could not resolve GitHub DNS or access Docker/Nix
daemon sockets. Admitted APGR leaf workers could collect/qualify within their
authority. Public RS9 main was observed at Foundation 1; public reference main
remained `062a931f4b5e44ad43c88363efd81ab8d92602df` through final remote audit.
Exact Git identities are evidence, not enforced current-state gates. Untracked
`.serena/**` remains excluded and preserved.

## Evidence and qualification boundary

- [Ingestion/authentication specification](specs/rs9-ingestion-record-v1alpha1.md)
  and [record](../tests/fixtures/nebular-0.6.1/ingestion.json).
- [License, dependency, desktop/icon and adapter design](architecture/nebular-shadow-projection.md).
- [Both Linux dependency records](../tests/fixtures/nebular-0.6.1/dependency-evidence.json).
- [Render manifest and goldens](../tests/golden/shadow/nebular-0.6.1/README.md).
- [Structured reference comparison](../tests/fixtures/nebular-0.6.1/comparison.json),
  with material differences and unclassified/stale-difference tests.
- [File byte comparison](../tests/fixtures/nebular-0.6.1/reference-byte-comparison.json)
  and source-tree/blob reauthentication of the captured reference.
- [Build/install qualification](foundation2-qualification.md), with environment
  labels, tested recipe hashes, unresolved checks and retained receipt hashes.
- [Contract amendments](specs/rs9-config-v1alpha1.md) and
  [ADR 0003](adr/0003-authenticated-ingestion-and-shadow-adapters.md).

The full Foundation 1 suite remains required. Offline adverse tests cover digest,
asset count/state, draft/prerelease, checksum, source/provenance/license mismatch,
archive paths/links/special members/limits, ELF bounds, dependency evidence,
contract fields, per-adapter values, output confinement, render determinism and
comparison completeness. The opt-in live test reauthenticates actual captured
bytes and reproduces committed records and golden recipes. Skipping it supplies
only offline evidence. Hygiene checks cover bounded UTF-8 product content, secrets,
private paths and binary magic; portability, links and whitespace are final gates.

The producer integrated run passed 135 unittest tests, including the original Foundation 1
tests and both opt-in captured-live tests. Python 3.13.12 was available; Python
3.11 was not executed. The exact-candidate qualification receipt binds final
portability, link, whitespace and hygiene checks outside the product tree.

## Internal worker disposition

Worker use: **used**, through the selected temporary APGR controller only.
Requested Gemini profile was `gemini-3.8-flash-high`; effective model/effort was
not observed. Workers were bounded leaves with explicit disjoint write ownership.
No worker output satisfies a dispatcher checkpoint.

| Bounded task | Parent disposition |
|---|---|
| Archive core | Failed before edits: provider rejected a tool-schema enum; cleanup proven; parent implemented directly |
| ELF core | Accepted after parent tests and bounds corrections; cleanup proven |
| Fresh live collection | Accepted for captured bytes/receipts, followed by independent parent authentication; cleanup proven |
| Shadow contract | Accepted after integration/adverse tests and launcher/category corrections; cleanup proven |
| Qualification attempt 1 | Partial/preliminary; cleanup proven before replacement |
| Qualification attempt 2 | Partial: built-payload evidence accepted; unsupported full-qualification claims rejected; cleanup proven |
| Public remote audit | Accepted read-only observations; cleanup proven |
| Terminal comparison correction attempt | Cancelled after bounded wait and progress investigation with no edits; cleanup proven; parent implemented directly |

The producer corrections preceded its candidate freeze. The external scratch candidate
inventory binds exact changed paths, blob/SHA256 identities and the candidate
tree without staging. Final verification results and exact inventory are returned
to the dispatcher. This report intentionally does not embed its own candidate
tree hash, which would create a self-reference.

## Review and handoff

The dispatcher owns exactly two checkpoints: post-planning and pre-final. The
first finding set is dispositioned above. The pre-final result is
**reviewed_with_findings (advisory)** for the bound producer candidate. The
independent reviewer inspected the 72-path candidate read-only and ran no tests;
the reviewer could not mechanically recompute its tree. This is an advisory
source review, not package acceptance.

The closeout stage envelope authorizes the terminal dispositioner to amend the
candidate and verify changed bytes, superseding the earlier task-scoped
reporting-only closeout rule. Terminal amendments receive no additional review.
No reviewer was selected or invoked by the producer or terminal dispositioner.
The terminal inventory and scoped qualification receipt bind the resulting
bytes separately from the reviewed producer tree.

| Pre-final finding | Terminal disposition |
|---|---|
| 1: hard-coded comparison names, paths and fallback license | Amend comparison extraction and add material recipe-drift tests; distinguish concrete Nix derivation names |
| 2: desktop file-open/WM/category behavior changes | Amend classification to reference-only behavior pending evidence; retain material parity gap without claiming argument support |
| 3: captured reference semantics not mechanically checked | Amend static reference extraction and captured-byte comparison tests; no external recipe execution |
| 4: Nebular-specific ingestion profile | Defer generic/profile split until before a second tenant, as required by ADR 0003; this candidate is the first-tenant profile |
| 5: normalized license lacks unresolved marker | Amend contract, example and normalization with optional unresolved-only status; retain explicit rendering blocker and provisional recipe strings |
| Minor: hard-linked scan members | Defer broader hard-link visitor handling; the authenticated Nebular raw inputs contain no hard-linked members |
| Minor: Linux Nix name has no version | Retain existing shadow recipe bytes, expose concrete derivation identity in comparison, and defer naming-policy change |
| Minor: Python 3.11 execution | Retain the documented compatibility floor as unexecuted; terminal verification uses available Python 3.13 |

Terminal verification reauthenticates the retained captured bytes, not fresh
network metadata. A closeout remote audit failed at DNS resolution. No new
package build/install, provider query, GUI launch or independent review is
claimed. Recipe/desktop identity checks preserve the exact scope of earlier
qualification; manifest/normalization identity is separately refreshed.

Manager adoption, if separately accepted, must bind the exact reviewed tree and
stage only the [inventory's RS9 paths](foundation2-inventory.md). Exclude `.serena/**`, scratch, downloaded
archives, icons, generated package binaries, bytecode and worker operational
metadata. Recommended commit message:

```text
Add authenticated Nebular ingestion and shadow package adapters

Bind Nebular 0.6.1 release inputs and Linux runtime evidence, add minimal
desktop and upstream launcher facts, and render deterministic shadow
Nix, pacman, RPM and AUR recipes with classified reference comparison.
Keep tenant license reconciliation and migration acceptance deferred.
```

Do not migrate a live tenant on this candidate alone. Resolve the tenant license
conflict and runtime/provider/install gates first. A later broader family shadow
or publication-state/provenance phase requires a separate assignment and is not
started here.
