# CONT12 hosted-run-10 RPM source repair

## Scope and proposal disposition

Disposition: **amend** the bound 23,443-byte proposal, SHA-256
`eebca710c2e59c742dae89e1090783e271196500dfc3a32945ed83d202bc7938`.
The original task authorizes portable test scratch, the accepted RPM durable
record boundary, exact candidate preservation predicates, complete diagnostic
custody, source verification and an attended run-11 handoff. The proposal and
advisory review findings remain evidence separate from that authority.
The dispatcher owns the two independent review checkpoints and Git publication.
No reviewer, source adoption, signing, workflow rerun or remote write is executed
by this source phase.

Run 10 (`37802815634`) remains **NOT QUALIFIED / HOSTED_GATES**. Its unit job ran
1,457 tests with one error and 17 skips. The hard-coded scratch write caused
that error; this phase does not characterize the historical unit job as green.
APT amd64 and arm64 retain their 41 recorded passing gates each, including the
untampered positive control for the local InRelease/NODATA negative. Pacman
retains its 40 passing gates. Config, authentication, pins, three wheels and
Darwin Nix passed; Darwin wheel offline isolation remains NOT-RUN. Four npm and
four Homebrew exact observations and eight planner noops remain historical facts.
The manager verified the selected packet objects and receipts, but did not
independently download omitted large packages.

## Durable evidence and complete custody

The integration test writes all three diagnostics inside its existing owned
TemporaryDirectory. It keeps canonical, pretty JSON and blocked-policy custody
assertions. Guarded platform discovery and adverse-input path strings remain
tests. Local execution is Darwin; an ordinary Linux execution without
`/private/tmp` requires an available Linux runtime and is reported separately.

Raw rpmlint bytes, counts, complete errors, stream hashes and exit identity are
retained. Candidate policy acceptance is distinct from raw cleanliness and
official Fedora admission. A typed durable projection binds the exact retained
raw evidence; optional absent diagnostic text follows its explicit field
contract. Generic record string validation and diagnostic scanners remain
unchanged. Boundary failures retain logical field, rule and stage diagnostics;
a downstream serialization failure has no fabricated tool cause.
Replaying the former raw embedding through the real accepted-policy derivation
constructor rejects `$.evidence.rpmlint.findings[1].message` under `INVALID_STRING`
for Burst, Loom and Solar Sail. The retained Nebular proxy rejects index 14.
Neither replay identifies the unretained native run-10 CLI traceback field.

Compact policy summaries bind ordered bounded evidence chunks. Reconstruction
must authenticate product, version, system, asset, evaluation hash, order and
count against the artifact manifest. Missing, swapped, changed, duplicated,
surplus or cross-system chunks fail. Legitimate package-member paths receive a
typed representation; host paths and credential-containing strings do not.
Evaluation data is never truncated to fit the diagnostic cap. Collection,
summary, Foundation 3, Pages and the manager text ZIP consume the same evidence.
Historical receipts remain subject to their existing source and required-gate
checks.

## Nebular policy limits

The authorization covers exactly eight private members in Nebular 0.6.1 and
the complete 128 duplicate groups, separately bound to each Linux release asset.
No glob, public launcher, new script, tool filter or broad error-code exemption
is authorized. Member bytes, type, mode, ownership, non-ghost identity and
authenticated input mapping must agree with actual RPM inventory. The two
`.d.ts` members require declaration-data and non-exposure predicates. The six
other members require authenticated maintained caller/loader contracts.

The pinned archive fetch is unavailable in the source sandbox. Local retained
metadata does not establish those caller contracts. Missing predicates therefore
remain individually blocked; binary string literals or invented node wrappers
are insufficient. Unversioned `nodejs` Requires cannot use a builder Node
version as proof of client resolution. Client image identity and installed
nodejs RPM query evidence, the authenticated loom engine floor and the real
installed-client hosted check remain necessary. The current pipeline cannot
supply that proof: preservation inventory never receives
`client_runtime_evidence`, the policy has no `client_image` pin, and the DNF
client is provisioned only after policy acceptance. This circular prerequisite
keeps the six rules blocked even if authenticated caller contracts become
available. No dependency change is made.

Duplicate waste uses equality of complete authenticated and actual group sets,
with actual inode semantics. Its closed possible-total set derives from those
same groups: 3,128,775; 3,129,379; 3,335,535; 3,336,139 bytes. It is neither a
range nor an arbitrary historical allowlist. Every duplicate copy remains.

The all-four RPM gate is preserved. **Any blocked Nebular rule prevents DNF,
signing, tamper qualification and Pages RPM custody for every product.** A
diagnostic run can check repaired derivations and complete custody while still
remaining unqualified. Manager review must weigh that limited result before
authorizing run 11. Source tests do not establish native DNF qualification.

## Verification and attended handoff

The [verification record](../evidence/live1/cont12-hosted10-rpm-policy-verification.json)
records observed source checks and unresolved checks. The cumulative
[candidate manifest](../operators/live1/candidate-manifest.json) binds all changed
paths relative to public parent `ce0c428331f61336530088d328e1b537fea287fb`.
Full LIVE1 and published Linux Nix readiness remain false. Linux Nix
`NIX_FHS_USERNS`, experimental PRoot and unknown Pages TLS remain out of scope.
Pages assembly cannot succeed while RPM custody is missing.
The pre-final producer verification record reports both process-local umasks,
022 and 077, passing the full cumulative suite with ResourceWarning treated as
an error: 1,499 discovered tests, 1,489 run and 14
reported skips. Five skips are individual tests; eight are tests in four skipped
classes; one unavailable GPG class excludes ten tests from the run count.
The portable custody integration test runs in both suites. An ordinary Linux
runtime without `/private/tmp` is unavailable locally, and native package tools
and GnuPG remain external verification limits.

Terminal closeout repeats only focused source regressions and reporting checks;
it does not independently repeat the producer's full-suite observations. The
verification record distinguishes that evidence from fresh closeout checks.

The terminal return supplies final tree and manifest bindings after reporting
corrections. The canonical dispatch ZIP and receipt are dispatcher closeout
outputs; the producer does not issue a replacement checkpoint or attestation.

The [run-11 operator](../operators/live1/run-hosted11.py) is prepared for attended
execution **after manager acceptance**. Bind acceptance to the final tree and
manifest SHA-256 and provide the existing external partial-diagnostic manager
attestation. Precreate the required empty physical packet directory; keep
attestation, full-stream logs and upload outside it. Readiness flags remain false.

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 operators/live1/run-hosted11.py \
  --reviewed-parent ce0c428331f61336530088d328e1b537fea287fb \
  --reviewed-tree "$RS9_ACCEPTED_TREE" \
  --manifest-sha256 "$RS9_ACCEPTED_MANIFEST_SHA256" \
  --manager-attestation "$RS9_MANAGER_ATTESTATION" \
  --manager-attestation-sha256 "$RS9_MANAGER_ATTESTATION_SHA256" \
  --output "$RS9_EMPTY_PACKET_DIRECTORY"
```

The shared backend preserves ignored root `.scratch/`, Serena, unrelated paths
and the real index; it stages only reviewed paths, makes one normal nonempty
commit and fast-forward push, and collects one new push-triggered workflow bound
to that commit and the original adoption not-before timestamp. Interrupted
collection requires its original commit/run/time bindings with `--collect-only`.
No automatic rerun, force push, empty commit or old-workflow replay is allowed.
Full stdout/stderr go to files and terminal output contains bounded paths.

Native signed query, fixture signatures, createrepo, installed clients, trust
negatives and positive controls remain real hosted gates. Production signing,
publishing, registries, Pages deployment, release/tag changes and production
receipts remain unauthorized. Dispatcher closeout is reporting-only; a terminal
product amendment requires renewed manager review.

## Work-review disposition and deferred product findings

The dispatcher pre-final work review returned **reviewed_with_findings**. Terminal
disposition is **amend** for reporting corrections; executable source, policy and
tests retain the reviewed bytes. WP1, the typed WP2 record boundary, bounded WP4
custody and the external manager-attestation handoff are accepted within their
source-test limits. WP3 remains partial and fails closed. Manager acceptance of
the final reporting-amended tree is still required before adoption or run 11.

1. **Accepted; product correction deferred:** the Node/client proof prerequisite
   is circular and lacks a client-image policy pin. Both this pipeline gap and
   missing authenticated callers block the six private script rules. Manager
   review must choose a bounded proof-provisioning change before expecting DNF.
2. **Accepted; product correction deferred:** synthetic JSON-pointer contracts
   do not establish Nebular's maintained invocation through
   `tfsb-studio-service` and `sidecar-payload/manifest.json`. The generic archive
   projection also hard-codes Nebular's loom engine-floor path. Actual caller
   structure support and fresh authenticated-input/RPM preservation checks are
   incomplete; source fixtures do not qualify those predicates.
3. **Accepted; product correction deferred:** `missing_evidence` lists
   `caller-content-unproven`, while the proof emits
   `caller-content-or-identity-unproven`. The mismatch fails closed but needs
   alignment in a manager-reviewed product change.
4. **Accepted; product correction deferred:** derivation, manifest and policy
   custody failures currently fail the aggregate `rpm-package-build` gate and
   use `blocked-by:rpm-package-build` despite retained construction identities.
   Per-product substage/field/rule evidence is authoritative for diagnosis;
   aggregate attribution and gate tests need a manager-reviewed correction.
5. **Accepted; consumer hardening deferred:** the durable lint reference binds
   retained raw evidence by construction. Production consumers do not invoke
   `validate_durable_lint` or independently compare derivation raw-evidence
   hash/size with the selected raw diagnostic. Focused tests verify construction
   and validator behavior, not that missing production check.
6. **Accepted; consumer hardening deferred:** current-builder receipts emit
   chunk summaries, and downgrade attempts with chunk markers fail. The consumer
   still permits marker-free inline historical evaluations with a source-policy
   hash; requiring summaries for this builder source remains deferred.

No product fix was made after the work review and no additional substantive
review was obtained. Run 11, if the manager accepts this limited handoff, can
observe repaired records and complete diagnostics. Under the current pipeline
it cannot qualify DNF, signed RPM custody or RPM Pages assembly for any product.
All readiness and production-authority flags remain false.
