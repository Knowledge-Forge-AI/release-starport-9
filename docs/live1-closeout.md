# Theme Forge LIVE1 terminal disposition

Disposition: amend

Rationale: retain the reviewed preparation work and correct its unsafe or overstated
boundaries. Accept the candidate only as a partial implementation checkpoint.
The original LIVE1 implementation/testing scope remains incomplete; production
publication and a ready attended publisher are blocked.

The dispatcher-bound input was HEAD `cbceaf816b17bd0f931b98eb5b8c1c55cda46bce`,
tree `0fb63c86e15d3e2cc9afeeee5f24031bd4c1effa`. These identify the reviewed input,
not a prerequisite recreated from historical task prose. Terminal source changes
amend that input; the refreshed [candidate inventory](../operators/live1/candidate-manifest.json)
binds the resulting files. The supplied independent review remains the pre-final
checkpoint. No additional substantive review was requested or performed.

## Work-review dispositions

| Supplied finding | Terminal disposition |
|---|---|
| Scope: most publication handoff items missing | Accept. Preserve the unfinished scope; report blocked rather than publication-ready or LIVE1-complete. |
| 1 HIGH: PyPI file 404 becomes absent | Amend. Only a 404 on the exact requested metadata URL can imply absence. File-download errors and mismatched error URLs remain unknown; regression proves planner defer-readback. |
| 2 HIGH: Pages secret-key and directory bypass | Amend. Sensitive path components have no extension exception. Public keys require a complete supported OpenPGP packet stream without secret-key packets; malformed/trailing data fails. Package/index suffixes require documented directories. Real key trust and signature qualification remain separate pending gates. |
| 3 MED: License-File prefix | Amend. Metadata uses paths relative to dist-info/licenses; fixture wheels retain legal files there. |
| 4 MED: Debian recipe cannot build | Supersede the incomplete recipe with APT_RECIPE_UNQUALIFIED refusal for both intended architectures. Actual Ubuntu 26.04 recipe/build/dependency qualification is deferred. The renderer creates no APT candidate output. |
| 5 MED: future-release config requirement unused | Amend. Normal ingestion and planning enforce captured tagged config/hash binding or an approved exact bootstrap capability. Shadow diagnostics are explicit and cannot bypass planning. Bootstrap config is rechecked during planning and before network capture. |
| 6 MED: signature generations and issuer trust | Amend. Each generation has an immutable path manifest over shared content-addressed objects. First retention binds claimed and verified issuer; reopened records recheck issuer and configured trust. Production defaults pin the established primary fingerprint and any verified subkey. Fixture validators are not real signature evidence. |
| 7 MED: unsafe archive writes, lock/hash bypass, cache cleanup | Amend. Validate complete archive types/targets/ancestry before extraction; reject writes through symlink parents, malformed/pending digests and flock failures. Confined read-only cache cleanup propagates failures. Actual released sidecar/native proof remains deferred. |
| 8 LOW-MED: unchecked bootstrap inputs and expectations | Amend. All config inventories and project identifiers are checked before requests/evidence paths. Expectations bind immutable state, tagged config absence, timestamp, tree truncation and asset IDs. Attended checkout rejects ignored inputs. |
| LOW: APT scope, Date, Installed-Size and structural validator | Amend scope to Ubuntu 26.04 resolute; use control Installed-Size; return explicit signature_authenticated=false. Fixed fixture Date remains deferred as a production freshness policy and cannot authorize publication. |
| LOW: wheel inventory and metadata body | Amend. RECORD and archive inventories agree in both directions; header parsing stops before description text. |
| LOW: qualification approval timing | Amend specification. Independently approve the complete post-execution record hash before policy allowlisting, then observe/plan. Restart or changed hash needs fresh execution/approval. Production approval orchestration is pending. |
| LOW: CI runtime assumption | Amend. Candidate workflow selects Node 22 through a pinned setup action. Hosted execution is pending externally. |

Prior producer additions/modifications are retained within their documented partial
scope. APT recipe availability is superseded as above. Nix outputs stay unexposed,
Nebular construction stays withheld, publication commands remain disabled, and
npm/Homebrew remain observe-only. Legacy distribution and APGR source are unchanged.
Unrelated local state and `.serena/` are preserved.

## Qualification evidence

Qualification evidence: the terminal command in
[closeout-verification.json](../evidence/live1/closeout-verification.json) ran 203
scoped unittest cases: 200 passed, three live Nebular capture cases skipped because
authenticated capture directories were unavailable. The selected tests exercise
changed ingestion/planning/operator boundaries, Pages, wheels, native recipe
refusals, APT indices, retained signatures, materialization and shadow compatibility.
Fixture wheel tests install/run/uninstall locally with pip --no-index --no-deps.
Nix evidence is limited to output withholding and fixture mechanics, not real
build/install/native smoke. `git diff --check` passed; operator status reported
production_enabled=false and publication=blocked.

Four bounded Gemini implementation workers applied supplied findings in disjoint
scopes; all cleanup was proven. Parent integration tightened packet framing,
cache cleanup and reopened-store trust, and superseded the unqualified Debian
recipe. Parent reran the combined scoped checks against the terminal source bytes.
Worker output did not satisfy a dispatcher review checkpoint. No full repository
or release gate was run. Hosted CI remains pending externally.

## Remaining handoff and rollback

Unresolved concerns: no authenticated release payloads, real wheel/native package
artifacts, real qualification records, actual Foundation 3 plans or publication
receipts exist. Complete Linux FHS closure on both architectures and Darwin
released-verifier/native smoke are pending. PyPI availability/ownership/OIDC,
Pages/DNS/TLS and production signing custody are unknown or unattested. Signed
pacman/RPM/APT readers, production transports and attended approval orchestration
are unfinished. The fixed APT fixture Date is not a live freshness contract.

The [generation matrix and channel status](live1-candidate.md), exact bootstrap
manifest/config hashes, [mandatory gate matrix](../evidence/live1/gate-matrix.json),
pending [preparation matrix](../evidence/live1/publication-preparation.json),
[attended preparation runbook](../operators/live1/RUNBOOK.md) and
[APGR v0.13.0 onboarding note](apgr-v0.13.0-readiness.md) remain the handoff.
The preparation matrix is not a set of real publication plans. Metadata observations
from the producer stage are retained as historical evidence; closeout did not
repeat live destination or release observations.

Rollback remains prospective: retain complete prior signed public trees and required
pool/by-hash objects, restore a selected generation atomically under existing trust,
use an attended PyPI yank and reviewed Nix output revert where necessary. No live
rollback was executed. Documentation remains pending/not-live until a separately
reviewed update binds exact manager-provided readback. Provider-local work did not
stage, commit, push, publish or mutate secrets. The dispatcher owns Git finalization
and any publication/archive outcome.
