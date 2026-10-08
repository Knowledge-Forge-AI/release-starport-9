# CONT10 hosted-run-8 source repairs

## Scope and disposition

Disposition: **amend** the bound proposal (19,669 bytes, SHA-256
`89dd2b304635e1db6f90d2f40f3de54abfd3fedbeed1f3250c161eae74129a6b`).
The original scope remains explicit public APT output modes, lossless RPM lint
failure handling, pacman wrong-key classification and bounded Debian preparation
diagnostics. Proposal text and advisory findings do not replace task scope.
No stage deltas were reported on implementation entry. The dispatcher owns both
independent checkpoints. Its pre-final review accepted all seven required lenses
with five advisory findings; the terminal closeout amends the reviewed candidate
under the dispatcher's correction authority. No additional review is obtained.

The supplied run-8 evidence kit was read, including manager disposition,
packet, summary, selected canonical receipts, diagnostic objects, controlled
reproductions and excerpt provenance. All 12 selected evidence identities in
the provenance record were checked against their local bytes. Run 8 remains
not-qualified (`HOSTED_GATES`); its adoption and collection are not repeated.
The retained RPM evidence contains no actual lint finding stream. The Debian
amd64 receipt proves only an environment `TOOL_TIMEOUT`, with no responsible
preparation substage. Neither a transient outage nor a package regression is
inferred.

## Advisory findings

1. Pacman matching lowercases the complete stream and validates a full 40-hex
   fingerprint. Both upper- and lowercase exact samples are covered. The kit's
   actual corrupt-signature sample reports an invalid signature, not an unknown
   issuer. The proposed corrupted-fingerprint inference and identity-set design
   are superseded by the observed closed diagnostic family. No fixture primary
   or subkey set is compared, so uppercase-set and omitted-subkey mismatches do
   not arise. Generic unknown-trust text, lookup text alone and malformed tokens
   earn no wrong-key credit.
2. Causal RPM diagnostic custody is kept outside the limited error-detail
   sanitizer. Preparation gate details are sanitized and numeric timing fields
   are typed. Secondary diagnostic failures annotate the original causal error.
3. Preparation recorders are optional for existing wheel, pacman and Pages
   callers; tool-facts failures retain their container-tool substage. No
   preparation deadline is increased and no retries are introduced.
4. Root `.serena/` and ignored root `.scratch/` retain the established inventory
   and adoption behavior. No operational tree is deleted or rewritten.
5. Real `CommandReceipt.command` drives RPM diagnostics. Probe failure cannot
   replace causal lint evidence. The baseline masking failure is reproduced
   from read-only parent source without modifying Git state.
6. Public directory creation and readback cover all parents within the public
   root, including by-hash, tamper rewrites and the second Pages staging APT tree.
   Private stores and signing material retain their existing defaults.
7. Evidence-kit access resolved the planner's missing-source limitation before
   source repair. Actual unknown-key and invalid-signature samples are replayed;
   no unseen lint codes or historical timeout substage are invented.

## Implemented contracts

Public APT regular files are 0644 and repository-owned directories are 0755,
independent of process umask. Pool files, indexes, compressed indexes, by-hash
objects and signed public outputs retain their exact bytes. Assembled public
Pages APT projections are read back. Private signed-object storage and fixture
keys remain private. Confinement rejects links and touches no ancestors outside
the public root. Native `_apt` readability and untampered refresh/install remain
requirements for the next hosted validation; a host mode readback cannot qualify
the client.

RPM lint failures preserve command exit and output identities, package/spec
identities, parsed findings and completeness. Optional probes and diagnostic
filesystem failures cannot replace the lint cause. Product failures accumulate;
construction and lint qualification remain separate. Rejected RPMs stay
quarantined outside publishable custody. Actual native lint qualification is
pending because the run-8 stream was not retained.

Pacman's specific unknown-key diagnostic precedes the generic PGP-corruption
summary. Plain invalid-signature diagnostics stay `SIGNATURE_REJECTED`; wrong-key
requires `KEY_MISMATCH`. Network, permissions and missing packages never qualify
trust negatives. Negative credit still requires the matching successful,
executed configure/refresh/install/query control bound to image, platform,
product and setup. Accepted tampering fails even without a positive control.

Container preparation retains tool, substage, elapsed/deadline and stream digests
at pull, inspect, release probe, image provisioning/commit and tool-facts
boundaries. Original sanitized error details survive environment/setup failures.
Phase-owned release, provisioning and preparation-tool containers have exact
names and cleanup deadlines capped at 30 seconds. Cleanup failure annotates the
original timeout. No host settings change or preparation deadline increase is
introduced.

## Verification and deferrals

Implementation-stage and terminal source results are recorded in the
[verification record](../evidence/live1/cont10-hosted8-repair-verification.json).
Full logs remain in ignored task scratch. Process-local umasks 022 and 077 use
ResourceWarning as an error. These are offline source regressions and fixture
transports, not actual native package qualification. Provider closeout reruns the
task-required cumulative source qualification after the terminal corrections.

Each terminal cumulative pass discovers 1,373 cases: 1,350 pass, 13 skip individually and
ten are unavailable in one skipped signing class. `unittest` starts 1,363 cases
and records 14 skip events. There are zero failures or errors under either
umask. The unavailable cases require GnuPG, live captures, official Nix archives
or unsupported host filesystem operations. Direct success counting avoids
treating a skipped class as an executed test. The initial implementation import-path
attempts and one terminal long-temporary-path attempt are retained as
nonqualifying harness evidence. The terminal runner uses the inherited shorter
platform temporary directory for the existing Unix-socket test.

The public-output comparison loads parent source read-only and confirms all 20
pool/index/compressed/by-hash/signed fixture files have identical bytes and hashes
under both umasks. Python parsing, changed-file compilation, workflow/static
contracts, credential scans, 267 relative links and `git diff --check` pass.
Workflow, source pins, signing fixture, guest-smoke, observation and readiness
sources remain unchanged. Live remote verification was unavailable due to DNS;
local HEAD and cached remote main match the parent. The attended operator must
perform its normal live remote preflight.

The dispatcher pre-final reviewer accepted public modes/private-store isolation,
RPM diagnostic custody, wrong-key classification, original positive controls,
timeout attribution, the non-production boundary and adoption/scratch contracts.
The reviewer could not read the supplied evidence kit and did not run tests or
recompute bindings. Provider closeout verified the bound candidate and the prior
tested-source inventory before amendment. Review evidence is distinct from
provider-local source tests and pending hosted native qualification.

## Terminal advisory disposition

Disposition: **amend** the reviewed cumulative candidate. The terminal correction
scope is limited to the following findings and their regressions:

- A: RPM construction credit requires the retained causal package SHA-256.
  Missing package identity fails the construction gate while preserving every
  lint failure. A missing optional spec or a later input removal does not erase
  an already retained package identity.
- B: Cleanup uses copies of the runner wrapper chain for a local deadline capped
  at 30 seconds. An unset original timeout is supported. Nested cleanup and
  ordinary preparation keep their original deadlines and receipt sinks.
- C: All four public-mode failure messages are constant text with bounded
  substage/reason details. Full mode reports are excluded from exception messages.
- D: Index construction delegates directory creation to the confined public
  writer. A linked `dists` component is rejected before creating anything outside
  the public root, and outside bytes and modes remain unchanged.
- E: A collect-only regression uses the real post-commit inventory and local
  fixture Git tree. Reviewed continuation succeeds; unreviewed source drift stops
  before collection. The original time, commit identity and operational-state
  preservation remain enforced. No live hosted collection is executed.

Focused feedback ran 170 tests with two skips and no failures or errors. The
pre-correction regressions reproduced A-D; E confirmed the existing behavior.
Both terminal cumulative runs passed under process-local umasks 022 and 077
with ResourceWarning as an error. Static checks and final inventory readback are
recorded in the verification record. Full logs and nonqualifying reproductions
remain in a new ignored closeout scratch directory; prior scratch and caches
retain their bytes and modes. The final tree and manifest digest are supplied in
the terminal handoff to avoid self-referential evidence. Dispatcher finalization
remains separate from these provider-local actions.

Run 8's four ordinary pacman clients, installed Nebular verifier/closure/smoke,
Burst released-loader proof, authentication, three wheel jobs and Darwin Nix
remain proven historical results. Darwin wheel offline isolation remains
unsupported/not-run. npm and Homebrew retain four exact observations and four
noops each; PyPI has four authoritative absent observations. Pages TLS remains
unknown. Required Linux Nix A stays required and unqualified
(`NIX_FHS_USERNS`, uid-map-denied); PRoot B stays experimental and cannot satisfy A
or publication. Linux Nix redesign and Pages TLS remediation are deferred.

## Prepared attended run-9 handoff

The [run-9 operator](../operators/live1/run-hosted9.py) is prepared and **not
executed**. The [cumulative manifest](../operators/live1/candidate-manifest.json)
is relative to parent `ab4b01d612ad2e2645ab649fc5fcf1e5c5d851eb`. Readiness,
production and publication flags remain false. The external manager must accept
the exact parent, final cumulative tree and manifest digest using the existing
external attestation contract. This document grants no adoption authority.

After manager review, an attended operator must supply an existing empty physical
packet directory in the configured manager outbox. Attestation, full stdout and
stderr log, wrapper metadata and selected result ZIP stay outside that packet.
Only the manifest's reviewed changed paths may be staged; ignored root scratch
is preserved and excluded, and unrelated product drift stops adoption. Shared
adoption performs one normal commit and fast-forward push, then collects one new
push-triggered workflow bound to the resulting commit and post-push time.
No automatic rerun or adoption retry is permitted.

```text
python3 operators/live1/run-hosted9.py --reviewed-parent PARENT --reviewed-tree TREE
  --manifest-sha256 DIGEST --manager-attestation ATTESTATION
  --manager-attestation-sha256 ATTESTATION_DIGEST --output EMPTY_PACKET
```

If collection alone needs continuation, use a fresh existing empty physical
packet directory with the same reviewed bindings and external attestation. Pass
`--collect-only --commit COMMIT --run-id RUN --not-before ORIGINAL_TIME_Z`, taking
the exact identities and time from the original manager packet. Continuation
never repeats source adoption or chooses a new time. All jobs, artifacts,
summaries and selected bounded diagnostics are retained even when qualification
fails. Terminal output is restricted to `LOG=`, `RC=`, `MANAGER_PACKET=` and
`UPLOAD=`. Native preparation, RPM lint and public-mode diagnostics are included
in the bounded result selection. No production signing, publishing, deployment,
DNS changes, replacement Theme Forge release or workflow mutation is authorized.
