# CONT13 RPM repository repair candidate

## Scope and proposal disposition

Proposal disposition: **amend** the dispatcher-bound 17,553-byte proposal,
SHA-256 `fc6e57aed495da93d0f60f1e344185e927cac78e2e588d28109fc1038b6ff947`.
The original task authorizes source repairs for RPM writer ownership, noarch
build reproducibility, and completed-stage reporting, plus source verification
and an attended run-12 operator. Proposal bytes and plan-review findings are
separate evidence; neither expands that scope. No stage delta was recorded
before implementation. The dispatcher owns independent review and publication.

Run 11 (`37847967104`) remains **NOT QUALIFIED / HOSTED_GATES**. Its accepted
candidate preservation evaluations and package-signature probes do not establish
DNF lifecycle qualification. Raw rpmlint remains failed. Historical receipts and
the narrow preservation policy remain unchanged.

## Plan-review findings

1. Accept: `CLIENT_IMAGE_DRIFT` and `CLIENT_IMAGE_IDENTITY` continue to fail
   `rpm-client-preparation`, with `client-image-verification` as the cause.
2. Accept: writer identity changes apply to RPM operations; the shared pacman
   tool runner retains its existing behavior.
3. Amend: use one validated authenticated release date authority. RPM's
   changelog-derived midnight clamp must agree with the captured wrapper
   timestamps; preserving those payload bytes is a requirement. Effective
   controls are verified by a tool receipt, not inferred from argv alone.
4. Accept: evaluate pinned RPM 6.0.2 `--target noarch`, together with SRPM
   architecture/platform and flags, before claiming convergence.
5. Accept: permission-denied controls are guarded for root's DAC override;
   distinct-owner tests run only with the necessary authority.
6. Accept: the kit is directly readable in this stage. Derived references must
   bind the actual supplied unsigned RPMs; inaccessible evidence is reported
   explicitly rather than fabricated.
7. Accept: package-signing and repository-metadata are distinct causal substages
   of `rpm-repository-indexing`; no nonexistent signing gate is introduced.

Parent integration also amends the proposal to set the metadata creator's umask
inside its container, preserve probe records when a secondary diagnostic write
fails, and keep signing-probe read failures separate from unsigned-custody
verification. The verification artifact retains the pre-final work-stage
snapshot separately from the terminal closeout checks.

## Evidence and preserved boundaries

The supplied four unsigned Loom/Sail RPMs have equal compressed payloads within
each product pair. Their differing main-header tags are 1006, 1007, 1094, 1122
and 1146. This is binary-header inspection, with no installation or signature
authentication claim. The manager's manifest and CRC verification remains
attributed to the manager. The original hosted filesystem owner, mode and errno
were not captured. The supplied controlled POSIX ownership replay is separate
evidence, not an original hosted stat observation or Docker integration test.

Noarch custody continues to require equality of complete package bytes for the
same filename. Different package bytes, duplicate lane bundles and wrong
architectures remain blocking. Fixture signing operates on separate copies.
Public repository files require 0644 and directories 0755; private signing
homes and stores retain their existing permissions.

APT, pacman, wheel, Darwin Nix and destination readback paths are outside the
repair scope. Linux Nix `NIX_FHS_USERNS`, experimental PRoot, Darwin wheel offline
isolation and unknown Pages TLS remain unresolved under their existing gates.
Current Theme Forge releases remain the ingestion authority.

## Pinned RPM source contract

RPM 6.0.2's [build time and host implementation](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/build/build.cc)
uses `_buildhost` and checks `_buildtime` before the enabled
`SOURCE_DATE_EPOCH` fallback for build time. The candidate binds both timestamp
inputs to the same validated epoch; macro readback establishes the supplied
inputs, while native header equality remains pending. Its
changelog rule subtracts the noon rounding to obtain midnight when setting an
otherwise absent epoch. These controls declare reproducibility metadata; they
do not report the physical builder hostname.

The [package writer](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/build/pack.cc)
derives the cookie from build host/time and carries the source package identity
into the binary package. The
[spec finalizer](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/build/parseSpec.cc)
reads `optflags` and target platform macros into metadata. The
[file packer](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/build/files.cc)
supports `build_mtime_policy clamp_to_source_date_epoch` for source and binary
file timestamps. Its legacy clamp macro is a deprecated compatibility path.
These source contracts support candidate input controls; cross-lane whole-file
equality still requires native proof.

## Work-review disposition and terminal amendment

Disposition: **amend** the reviewed source candidate. The dispatcher owns final
binding and manager disposition of these terminal bytes; no additional
independent review is implied.

1. Retain `_buildtime`: the pinned source cited above explicitly consumes it.
   The source contract supports the control; a macro echo alone does not prove
   the built header's value.
2. Cross-system convergence remains unproven. Both lanes retain noarch SRPM
   digests in construction witnesses, manifests and derivation evidence, plus
   unsigned source-RPM copies. Run 12 must compare those digests, closure and
   spec inputs, complete binary bytes and any remaining header delta.
3. Distinct-owner filesystem proof remains pending because this host lacks
   the required root authority. Same-writer permission failures and positive
   controls do not establish container integration.
4. Amend custody reporting: absent or unreadable bundle bytes leave the
   unchanged-custody check `not-run`; an observed hash mismatch still fails.
   The original failed operation and secondary verification cause are retained.
5. Retain existing gate mapping: custody-bundle and fixture-preparation are
   prerequisites of repository indexing, so their failure blocks that gate.
   Their exact causal substages are preserved; no metadata-tool execution or
   signing success is inferred.
6. Amend diagnostics to name `createrepo_c` behind the exact owned umask
   wrapper in family and Pages paths. Real command receipts retain original
   stdout/stderr hashes, including later host signature-write errors.

The terminal corrections change diagnostics and evidence status only. They do
not modify noarch build inputs, custody comparison, payloads or release policy.
Focused regressions reproduce the previous missing-bundle and tool-name errors,
exercise actual unreadable custody files, and keep real custody mutation failed.
Final unit discovery also exposed an archive-time-dependent test fixture error:
the two-architecture Burst test could select the other build's archive hash.
Its fixture policy now scans only the current build, with deliberately distinct
gzip timestamps. Runtime packaging and production lint policy are unchanged.
Terminal full unit discovery under each of umasks 022 and 077 ran 1,603 tests,
with 1,587 successes, 17 skip events, zero errors/failures and no ResourceWarning.
The initial 077 fixture failure and deterministic reproduction remain recorded.

## Verification and attended handoff

Implementation evidence is recorded in
[CONT13 verification](../evidence/live1/cont13-verification.json).
The cumulative [candidate inventory](../operators/live1/candidate-manifest.json)
binds source bytes without modifying the real index. Readiness, production and
publication flags remain false. Native cross-platform RPM equality, DNF
installation of those exact identities and trust/tamper positive controls must
be observed in one new attended hosted run after manager acceptance.

Use the [run-12 operator](../operators/live1/run-hosted12.py) only with external
manager acceptance binding the reviewed parent, source tree and manifest digest.
An existing empty physical packet directory is required; logs and upload stay
outside it. The shared adoption path explicitly stages reviewed paths, makes
one normal commit and fast-forward push, and collects the new push-triggered
workflow using its original not-before timestamp. Interrupted collection uses
the same commit/run/time bindings. No failure is rerun automatically.

```sh
rtk proxy env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 operators/live1/run-hosted12.py \
  --reviewed-parent "$RS9_ACCEPTED_PARENT" \
  --reviewed-tree "$RS9_ACCEPTED_TREE" \
  --manifest-sha256 "$RS9_ACCEPTED_MANIFEST_SHA256" \
  --manager-attestation "$RS9_MANAGER_ATTESTATION" \
  --manager-attestation-sha256 "$RS9_MANAGER_ATTESTATION_SHA256" \
  --output "$RS9_EMPTY_PACKET_DIRECTORY"
```

This source stage does not execute the operator. Pages deployment, production
signing/publication, registry writes and upstream release/tag changes remain
outside its authority. This closeout includes the terminal amendments described
above and requires explicit manager disposition of its final binding.
