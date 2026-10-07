# CONT9 native-client source candidate

Status: source implementation/testing candidate, independently reviewed with
advisory findings and amended at terminal closeout; external manager disposition
remains required. FULL LIVE1 remains
unqualified. Production, publication and candidate-adoption readiness remain
false. No adoption, hosted run, commit, push or destination mutation occurred in
this phase.

## Proposal disposition and evidence

Disposition: **amend** the bound 20,194-byte proposal with SHA-256
`6673fcf5b89067b617a198ee959991a5bb0086373783de99dbaf422c35219738`.
The original task scope remains RPM lint collection, APT positive-control
diagnosis/trust qualification, installed Nebular verification and supporting
destination reporting. The proposal and advisory findings do not replace it.
The cumulative implementation-stage product delta is retained.

The selected run-7 manager records were readable during implementation. They
confirm lint exit 64 without message text, APT refresh failures without a causal
receipt, and Nebular's smoke-stage FileNotFoundError without a filename. The
source filesystem mismatch is reproduced by a regression; it does not identify
the exact missing run-7 resource. Existing retained package files were inspected
read-only before considering downloads; no new downloads were needed.

The six advisory findings were handled as follows:

1. The extracted archive control runs on the host with no guest subprocess
   prefix. It is labelled `host-control` and never qualifies the installed client.
2. Released verifier modules execute from authenticated read-only source. The
   harness receives a guest-local checkout copy whose authenticated source bytes
   are checked before and after smoke; the original source is also rechecked.
3. Inventory, source readback, released verifier and application smoke run as
   UID/GID 65534 in the disconnected client. The explicit output directory has
   that ownership and mode 0755, independent of the producer's umask.
4. Tamper qualification receives the matching positive control explicitly,
   bound to family, image, platform, product and setup identity. RPM lint failure
   leaves DNF trust qualification blocked upstream.
5. RPM build success means package construction plus supported identity and
   requires queries completed. Lint is a separate gate. Version receipts never
   replace the actual failing lint receipt. Session headers/config paths are
   parsed and sanitized.
6. Evidence was inspected before choosing repairs. Neither an APT cause nor an
   RPM policy exception was invented from missing native output.

## Terminal work-review disposition

Disposition: **amend** the reviewed candidate. The three medium findings and
the grouped low findings are accepted and corrected:

1. Tamper classifiers now receive the client family. Representative APT, pacman
   and DNF wording has regression coverage, including package-signature rejection
   at install for pacman/DNF. Matching positive controls and causal stage checks
   remain required; unclassified refusals never earn credit. These fixtures do
   not establish the wording or results of a native hosted run.
2. Request parsing, unexpected guest exceptions and diagnostic-file failures
   produce bounded failure output when the output directory is writable. A
   diagnostic failure preserves the primary failure. Host output errors retain
   the guest command's exit code and stream hashes, including crashes that cannot
   write output.
3. Application process failure, timeout and an actually missing receipt have
   separate reasons and stream hashes. Process failures no longer invent a
   missing-resource location.
4. Candidate lint requires exactly one package and one spec. Unknown
   rpmlint-prefixed lines fail parsing. Evidence-limit failures retain package
   and spec identities for quarantine. APT command diagnostics share the primary
   refresh setup digest and architecture label.

These terminal amendments did not receive another independent review. Their
verification is recorded below and in the source verification record; external
manager acceptance must account for this terminal revision.

## Implemented boundaries

[RPM lint collection](../src/rs9/rpm_lint.py) retains per-product package/spec
identities, supported payload-hash readback, tool/version receipts, output hashes
and sizes, grouped severity/code counts, bounded sanitized samples and parse
completeness. Empty, malformed, inconsistent or nonzero lint results fail closed;
warnings preserve the tool's exit semantics. Formatting was checked against
[upstream rpmlint](https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/lint.py).
Lint-failed package bytes remain in local candidate quarantine and are excluded
from unsigned custody, Pages, indexing, signing and disconnected DNF clients.
The spec and JSON diagnostics are retained separately for each product. No
metadata repair, filter or authenticated-byte mutation is justified yet.

[APT diagnostics](../src/rs9/apt_diagnostics.py) retain command stage, exit code,
output hashes, bounded reason categories, setup identity and public fingerprint.
Guest probes check key/index hashes, actual readability and ancestor modes as
root and `_apt`, public signature verification and tool versions. A failed
diagnostic rerun cannot replace the original failure. Public/private key modes
have not been changed without a demonstrated native cause. Tamper rows retain
raw receipt hashes but earn credit only with the same successful untampered
configure/refresh/install/query control and a causally relevant rejection.
Failed controls produce `not-run`, not trust passes. Historical records remain
unchanged; xz handling and parser bounds are preserved.

[Nebular's container boundary](../src/rs9/hosted_container_smoke.py) uses explicit
read-only source/probe mounts and one writable output mount. All runtime reads
and verifier commands occur in the installed client's filesystem. Expected
manifest, scanner, source bindings, native hashes and scenario receipts remain
checked. The host accepts only bounded regular JSON output using no-follow
opens, validates its request/family/system/user bindings and records missing
resources by class and logical location. There is no Docker socket, host-root
mount, privileged container or host-extracted qualification substitute.
Uninstall and post-remove inventory execute after a successful install even if
smoke fails; cleanup status is separate from the primary failure.

Destination summaries expose the eight successful npm/Homebrew observations and
their planner noops independently. Pages TLS failure remains unknown and the
aggregate readback gate remains blocked. The
[endpoint diagnostic note](live1-pages-endpoint-diagnostic.md) is read-only.
Required Linux Nix lanes remain intact. PRoot remains diagnostic-only: guest
MAIN mapping, signal behavior and WebKit/application compatibility are open
questions, separate from these source repairs.

## Verification and limits

Tests exercise structured RPM findings and sanitation, explicit APT positive
controls and tamper causes, cleanup after smoke failure, and per-destination
reporting. The Nebular regression uses disjoint host/guest trees and real child
Python/Node filesystem work through a fixture transport; it does not mock away
all runtime reads. Wheel and Darwin Nix regressions preserve their host behavior.
Fixture transport, fake package tools and simulated executed receipts are
source-regression evidence only.

The full unittest suite runs with ResourceWarning as an error under process-local
umasks 022 and 077. Counts, skipped native boundaries and candidate checks are
recorded in [the verification record](../evidence/live1/cont9-source-verification.json).
Native RPM tools are absent and the provider sandbox cannot access the Docker
daemon. Real rpmlint findings, APT's refresh cause, both Linux architectures'
installed qualification and Nebular's native client lifecycle therefore remain
pending. Darwin's offline-isolation limitation, required Linux Nix userns gates
and diagnostic-only PRoot results are carried forward. Internal Gemini work was
integrated and amended by the parent; it is not a dispatcher review checkpoint.

## One future hosted-run-8 handoff

CONT9R1 repairs the adoption scratch boundary described below. Retained ignored
root scratch may remain during the attended handoff; it never enters source custody.

After disposition of the independently reviewed candidate and terminal amendments,
the external manager must explicitly accept the exact
source tree, parent and cumulative [candidate manifest](../operators/live1/candidate-manifest.json)
for partial-diagnostic source adoption. The readiness flag is not an acceptance
mechanism. The existing external attestation scheme remains required.

The prepared [run-8 operator](../operators/live1/run-hosted8.py) is **not executed**
in this phase. The future attended operator must:

1. Bind reviewed parent/tree/manifest digest and external manager scope; inspect
   the real index and preserve unrelated work. Supply a matching external
   attestation and digest.
2. Create an existing empty physical packet directory, with logs, attestation
   and result ZIP outside it. Existing custody must never be overwritten.
3. Adopt only reviewed source, make one commit and one fast-forward push using
   the existing shared adoption implementation, and collect only its new
   push-triggered run bound to the commit and not-before time.
4. Record every required job/artifact and separately scoped experiments. Do not
   rerun run 7, retry adoption or automatically retry any hosted job.
5. Print only `LOG`, `RC`, `MANAGER_PACKET`, `UPLOAD`; keep full streams in files.
   The small result ZIP contains selected bounded manager/summary, native-client,
   destination, experiment and diagnostic JSON
   with selection hashes and excludes large package bytes.

Invocation shape (placeholders must be replaced with the manager's accepted
bindings and an already-created empty packet directory):

```text
python3 operators/live1/run-hosted8.py --reviewed-parent PARENT --reviewed-tree TREE
  --manifest-sha256 DIGEST --manager-attestation ATTESTATION
  --manager-attestation-sha256 ATTESTATION_DIGEST --output EMPTY_PACKET
```

The dispatcher owns Git finalization. The independent work review is complete;
terminal amendments and their task-scoped verification are reported for manager
disposition. There is
no authorization for production signing/packages, PyPI, Pages deployment,
npm/Homebrew mutation or Theme Forge release/tag changes.

## CONT9R1 adoption scratch boundary

Disposition: **amend** the bound 15,457-byte proposal with SHA-256
`b4f3eec6b50547bbe0d68988cbc35bd52ce55765a36ff7d0e829ba33a8d89762`.
The original scope is M1's ignored-scratch adoption repair, cumulative source
qualification and the future diagnostic run-8 handoff. The proposal and advisory
plan-review findings do not expand or replace that scope. No stage deltas were
reported at entry. All 29 inherited path hashes and modes matched the kit;
CONT9's native implementation and its 14 terminal amendment paths are retained.

The adoption boundary permits untracked, actually ignored root `.scratch/**`
outside reviewed custody. It rejects root scratch in manifest files, changed or
deleted paths and tracked files, including tracked deletions. Unignored scratch
still stops adoption. Git's ignored listing collapses ignored directories,
avoiding a scratch-content inventory while preserving existing
`.serena`, pytest and Python cache behavior. Scratch bytes and modes are retained.
Parent, tree, manifest, readiness and external attestation checks remain intact.

The ignore rule is anchored as `/.scratch/` because nested source such as
`src/fixture_pkg/.scratch/nested.py` must remain visible to Git's product delta
and staging. The former unanchored rule could cause inventory disagreement or
late staging failure. Nested `.scratch` paths are source, not an operational
exception.

The advisory findings are dispositioned as follows:

1. Regenerate the cumulative manifest before full discovery; write results
   without a self-referential manifest digest, regenerate again and reverify.
2. Compare index entries and staged paths. Git's stat refresh may rewrite index
   bytes without changing staged content, so byte identity is not claimed.
3. Direct scratch-custody tests assert `ADOPTION_SCRATCH`; full adoption tests
   allow earlier inventory failures and require a stop before mutation.
4. The run-8 subprocess seam is module-local. Real Git and inventory reads remain
   active; text output is adapted to the operator's binary log. A failing fixture
   collection correctly yields RC 2 after the local fixture adoption.
5. Use the proposed directory listing and expand ambiguous directories through
   literal positive pathspecs outside root scratch and recognized cache paths.
   This preserves the existing per-file cache policy even when Git collapses
   a newly ignored directory containing only Python cache files. A Git trace
   confirmed that merely
   excluding scratch by pathspec still walks its files; directory collapse avoids
   that traversal. The scratch exception applies only to ignored root entries.
6. The anchored-rule rationale above describes the actual disagreement and late
   staging risk, rather than claiming that adoption could silently succeed.
7. The manager kit, reproduction, prior review and closeout were readable and
   inspected; all inherited path metadata matched before edits.
8. The live-checkout index regression is read-only, uses staged content, and skips
   when the public parent object is absent in a shallow checkout.
9. Real-Git regressions skip clearly on Git older than 2.32 and isolate Git
   configuration, identity, hooks and inherited repository/index overrides.

[The CONT9R1 verification record](../evidence/live1/cont9r1-adoption-scratch-verification.json)
records implementation-stage results and native/environment skips separately.
Disposable Git fixtures exercise real inventory, pre-mutation checks and local
commits, including run-hosted8 through shared adoption with an existing empty
packet and matching external attestation. Fetch, push and hosted collection are
intercepted at the explicit fixture boundary. No public or real-checkout adoption
occurs. Source tests confer no native qualification.

The dispatcher pre-final checkpoint reviewed M1 and the complete cumulative
candidate, including CONT9's terminal amendments, with advisory findings.
Closeout amends three findings: accepted tampered content is a failure even
without a valid positive control; ambiguous ignored directories preserve the
per-file cache policy while unrelated ignored files still stop adoption; and
an unavailable RPM or spec digest cannot replace a lint failure and its receipt
hashes. Positive-control rejection credit still requires matching successful
untampered controls. Regression fixtures cover all three corrections.

The older nested `.serena` policy disagreement is deferred: inventory permits
it but adoption rejects it. It fails closed and does not affect the root-scratch
repair. These terminal amendments receive task-scoped verification and no
additional independent review; external manager acceptance remains required
before using the invocation above. Readiness stays false; RPM
lint findings, the APT refresh cause, Linux client runtime/lifecycle and Pages TLS
remain pending. Required Linux Nix lanes and diagnostic-only PRoot are unchanged.
