# Theme Forge LIVE1 implementation candidate

This document describes the preceding accepted partial source checkpoint. The current
[real-candidate continuation](live1-real-candidate-continuation.md) records the latest
source changes, fresh failed authentication, current observations and remaining blockers.

Status: **partial implementation; pending / not live; production operator not ready**.
No production signing, publication, secret change, Git publication or upstream
release/tag mutation was performed by the provider. The dispatcher pre-final review
returned advisory findings. [Terminal corrections and scoped verification](live1-closeout.md)
amend this partial candidate; the LIVE1 implementation/testing outcome is blocked.
LIVE1 cannot be completed by accepting this source candidate alone.

## Scope and proposal disposition

Original scope remains the current releases of Stellar Burst 0.6.1, Stellar Loom
0.4.0, Solar Sail 0.2.1 and Nebular Fusion 0.6.1, with PyPI, RS9 Nix, pacman,
DNF/RPM and APT preparation and qualification. npm/Homebrew are read-only observation
targets; the legacy generator and private DIST1/APT evidence remain read-only.
No APGR mutation belongs to this cycle.

Disposition of the bound proposal: **amend**. Its binding is 39,144 bytes, SHA-256
`00d91c4285a04d6510110cd37e0c0da7937917e901483c1360bbcd2148387473`.
The original task, proposal and advisory findings are distinct inputs. This candidate
retains the task's unfinished obligations; its partial delivery does not replace
them with a narrower task. No stage deltas were recorded before this work.
Foundation 3 is already accepted. The dispatcher removed brittle current-state Git
identity prerequisites; this stage uses semantic checks. A future attended mutation
still requires its own exact independently reviewed commit/tree.

| Finding | Disposition and observed result |
|---|---|
| H1: Nix exposure/evidence cycle | Amend: flake package/app/overlay outputs remain hidden. Qualification must precede a separate reviewed exposure change. Builders source bounded files rather than the whole checkout. Cross-platform evidence remains not-run. |
| H2: repeated signatures destroy exactness | Amend: retain signed objects once, with signed/unsigned hashes and issuer evidence; restart reuses retained bytes and carries current objects into deployment. Persistent store/tamper tests pass. Real signers, readers and durable production snapshot custody remain incomplete. |
| H3: undefined observation identity | Amend: npm/Homebrew forced observe-only; metadata/digest reads do not imply exact. Licensing is included in the intended observation contract; Nebular npm's historical declaration is a conflict. Exact live identity readers/contracts remain unfinished; no eight-pair noop claim. |
| M1: self-asserted qualification | Amend: reviewed local verifier rerun is the explicit trust root; actual verifier module, artifacts and full qualification hash are bound. Imported verdicts/hash-only evidence fail. Real adapter verifier suites remain unfinished. |
| M2: observation expires during approval | Amend operator contract: observe, plan and check freshness after approval in the same protected job. PyPI serial and Pages timestamp fallback are explicit. Production workflows are withheld pending implementation. |
| M3: native tools transform bytes | Amend: recipe tests enforce no strip/debug/build-id/shebang rewriting. Installed-byte/native-client proof remains not-run. Different Fedora dependency closures require separately qualified family destinations, not a shared assumed-compatible RPM. |
| M4: duplicate Nebular config authority | Amend: LIVE1 loader uses only the exact bootstrap; example configuration remains illustrative and is never merged. |
| M5: closed schema changes | Amend: destination policy and receipt become v1alpha2; explicit migration and fresh planning required. Legacy tauri profile stays v1alpha1; repository-authoritative profile is v1alpha2. |
| L1: Foundation 3 adoption naming | Accept correction: Foundation 3 is already accepted; future adoption concerns this LIVE1 candidate. |
| L2: homemade pacman/RPM indices | Accept: prefer native repo-add/createrepo_c in pinned environments with determinism checks. Those repository builders remain unimplemented. |
| L3: Xvfb/GPU coverage limit | Accept: software/Xvfb smoke does not qualify every host GPU/EGL driver path. Documented in runtime materialization design. |
| L4: composite Burst license | Accept: new downstream metadata remains literal AGPL-3.0-or-later. Preserve authenticated dependency notices separately; no composite-expression adoption. |

## Release evidence

Producer-stage public GitHub connector reads matched all repository ids, release ids, tag
commits/trees and reported primary asset digests. Tagged license files, package
metadata, Burst lockfile and Nebular verifier source were reread. All four releases
report `immutable=false`, and no tagged `.rs9/` exists. See the complete
[metadata matrix](../evidence/live1/release-metadata.json) and independent
[hard-stop expectations](../operators/live1/expectations.json).
Fresh [Homebrew formula metadata](../evidence/live1/homebrew-metadata.json) is
retained separately; formula observations do not authenticate downloaded payloads.

**Payload bytes were not downloaded/authenticated in this stage.** Shell public
transport could not resolve hosts; the connector rejects binary downloads. These
are metadata observations, not authenticated ingestion records. No release-record,
wheel or native-package hash is invented from those observations. Fresh byte
authentication must precede every real candidate and eventual mutation.

| Project | Version/tag | Release id | Reported primary payload SHA-256 |
|---|---|---|---|
| Stellar Burst | 0.6.1 / v0.6.1 | 399542205 | 53ef41a3de3335e042f2c4b1d299b1155b64bfc6556a84baf6a62cb28bcca209 |
| Stellar Loom | 0.4.0 / v0.4.0 | 399542451 | 4550314d9a6eb9a016c8637eb2a0a98e9a410210ad6546642dfce31c7402c9ec |
| Solar Sail | 0.2.1 / v0.2.1 | 399542664 | ebc4f21d1e61dbc0ac4e87ce81f7ecec4f97d7c15562356e429d4c1a4e9aa5a0 |
| Nebular Darwin arm64 | 0.6.1 / v0.6.1 | 400494635 | e5ab9c5ce5dd7fb02274b11b223db9db7ac1f3b2167334ee2f322abd3c8ec4be |
| Nebular Linux arm64 | Same | Same | 5d59a1dfb6b5cec5edced1b098eba7b79e4f77a0dd2a0ab815caa8992b17497f |
| Nebular Linux x86_64 | Same | Same | d6060f74d6e55ec3a096ac01a1ebadc8b8b1d89a9a51475cd52207b465ca434d |

## Implemented candidate and remaining channel obligations

The exact-generation bootstrap binds config hashes without placing derived release
hashes in ordinary config. The operator requires an independently reviewed bootstrap
hash. Normal future ingestion has no example/bootstrap fallback. Source/tree
mutation after authentication is rejected. See the
[bootstrap contract](specs/rs9-bootstrap-tenant-v1alpha1.md).

| Surface | Implemented and verified locally | Still required before publication |
|---|---|---|
| Foundation 3 gate boundary | Mandatory adapter gates; render verdict/hash spoof refusal; executed verifier binding; observe-only behavior; synthetic confirmation cannot say published; persisted attempts cannot authorize new transport | Real independently reviewed per-adapter verifier suites and platform matrices |
| PyPI | Deterministic standard-library wheel builder, full command inventory, AGPL metadata/legal files, RECORD, Node >=22 exec launchers; fixture double-build and pip --no-index --no-deps install/run/uninstall; bounded JSON/file reader | Actual release integration, Burst dependency staging and ABI floors, Nebular materializer/wheel integration, real platform tags/install/native smoke, current name/ownership and OIDC setup. Native Nebular wheels are withheld; no sdist is emitted. |
| Nix | Candidate metadata/build templates, stable names, pure evaluation proves no public outputs; generic mode-restoring materializer with tamper/concurrency tests | Pinned nixpkgs lock, authenticated inputs/dependency staging, packaged materializer, complete Linux FHS closure on both architectures, actual raw/store/materialized smoke, build/check/run/profile/offline qualification and separate exposure review |
| pacman | Authenticated-capture recipe renderer stages local release inputs, preserves binaries and emits desktop/icon integration; x86_64 restriction | Native makepkg build, derived dependencies/revision floor, repo-add database, package/DB signatures, clean clients and tamper tests |
| DNF/RPM | Both-architecture unsigned spec renderer disables binary rewriting and binds release input hashes | Native rpmbuild/rpmsign, per-Fedora-family dependencies and installed-byte checks, createrepo_c, retained signed RPM identity, clean clients and tamper tests |
| APT | Bounded DEB control parser; deterministic resolute pool/dists/Packages/gzip/xz/Release/by-hash; retained signature interface; structural validation explicitly does not authenticate signatures | Recipe rendering withheld with APT_RECIPE_UNQUALIFIED. Real Ubuntu 26.04 builds and dependency derivation, live Date/freshness policy, both metadata signatures, installed-byte/desktop/runtime checks, clean clients and tamper tests. No supported Debian 13 claim. |
| Hosted storage/Pages | Immutable signed-object retention, conservative carry-forward deployment assembly, inventory/public-tree scanner | Real native signature verification, production public key capture, signing custody, complete repo trees, exact signed readers, durable snapshots, Pages/domain/TLS verification and deployment transport |
| npm/Homebrew | Observe-only policy and conflict behavior; current Homebrew formula metadata observed | Explicit full observation identity, authenticated current registry/formula payloads and actual plans. Nebular npm historical license conflict is retained. No mutation permitted. |

The native package renderer is a candidate recipe interface, not a qualified build
runner. Burst recipes remain withheld until authenticated dependency staging is
integrated. Native Nebular Nix construction throws until its unproven runtime
integration is complete. The wheel builder's `can_publish` is false.

## Readiness, gate matrix and planning

Current PyPI availability/ownership is **unknown**; planning-stage 404 observations
are historical and do not reserve a name. Current Pages administration and DNS/TLS
could not be verified through the available read interfaces. A metadata-only local
signing-key listing failed; private-key custody is unknown, and no private material
was read. The Linux container engine was unavailable; native distro tools were
absent; Nix daemon access was denied. Pure Nix evaluation was available.

[Readiness](../operators/live1/readiness.json), the
[mandatory gate matrix](../evidence/live1/gate-matrix.json) and the
[28-pair preparation matrix](../evidence/live1/publication-preparation.json) record
these states. There are **zero real qualification records, zero actual LIVE1
Foundation 3 plans and zero publication receipts**. The preparation matrix is
deliberately not a publication-plan record: desired authenticated artifacts and
destination identities do not exist yet. Unknown must never be converted to absent.

## Verification and pre-final inspection

Producer-stage verification: 295 unittest cases, 290 passed, five live-capture cases skipped
because authenticated capture directories were unavailable. This includes retained
Foundation tests, fresh fail-closed contracts, actual synthetic wheel pip
install/run/uninstall, signed-store tamper/retention, bounded APT indices and pure
Nix output withholding. No fixture result is a Theme Forge qualification verdict.
The expected negative-test AMBIGUOUS_COVERAGE diagnostic is not a suite failure.

Parent inspection removed asserted authentication, fixture-derived production hashes,
guessed FHS dependencies, fallback command guesses and incomplete native launch
integration from worker submissions. Four Gemini leaf assignments were used with
disjoint scopes; replacements followed proven cleanup and explicit partial-work
adoption. Parent reran relied-on tests. Internal work is not a dispatcher checkpoint.
Terminal verification selected 203 cases covering the amended boundaries: 200
passed and three live Nebular cases skipped. The full producer suite was not rerun.
The [closeout disposition](live1-closeout.md) records exact checks and deferred gates.
The [inventory](live1-inventory.md) excludes unrelated `.serena/` state and temporary
fixture artifacts. No dependency, lockfile or package-metadata change was introduced.

## Required continuation and rollback

The [runbook](../operators/live1/RUNBOOK.md) provides an attended authentication
operator and exact setup packets. It is a preparation handoff; production commands
intentionally stop. Complete the real candidates, verifiers, readers and transports,
then independently review a production-ready operator. Preserve the original scope
through those remaining steps. Final closeout verifies actual native/readback
evidence; do not infer readiness from these unit tests.

After future publication, rollback reuses a retained previous signed public tree,
keeps required pool/by-hash objects and existing trust, uses an attended PyPI yank
where necessary and a reviewed Nix revert. Pages workflow artifact expiry is not a
rollback storage contract. Documentation becomes live only through a separately
reviewed readback-bound update. Legacy, npm and Homebrew surfaces remain untouched.

APGR v0.13.0 preparation is limited to the [onboarding note](apgr-v0.13.0-readiness.md).
