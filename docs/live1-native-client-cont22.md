# LIVE1 CONT22: original APT smoke and experimental PRoot diagnostics

Status: terminal amended source checkpoint after dispatcher pre-final review. Hosted run 20
remains NOT QUALIFIED / HOSTED_GATES. No hosted run 21, native replay, release
change, promotion, or publication is authorized by this checkpoint.

## Scope and proposal disposition

The original task covers causal first-failure APT smoke evidence and fail-closed
PRoot signal, WebKit/bwrap and smoke diagnostics for existing released payloads.
The bound planner proposal is **amended**, rather than substituted for that scope.
Proposal identity: 19,827 bytes, SHA256
`34f91478e51118ecfd06e2f7a3fe30a45de5f7ece66fb4a6e910e2cd48ec746f`.
At the producer boundary, no incoming stage deltas were recorded. The closer
accepts all fifteen cumulative product paths, with six amended after review.
The Git index and unrelated local state are preserved.

The eight advisory plan-review findings are dispositioned as follows:

1. Accept: authenticate the packet and inspect both outer/nested ZIPs before
   instrumentation. Compare fixed released messages offline. No fixed candidate
   matched either original APT stderr digest. Raw logs and smoke work directories
   are absent from the selected archives.
2. Amend: diagnostics run only after a failed original outcome is fixed. Each
   observation is exception-isolated, and only its two diagnostic fields may be
   added. The new passing control exercises the shared executor per system;
   incumbent consumer tests supply separate source-level regression evidence.
3. Amend: `validate_smoke_observation(raw, *, system=None)` supports idempotent
   reprojection. Host calls supply the bound system, never guest system text.
   A swapped scenario becomes unknown with a persistent binding-mismatch marker.
4. Defer: omit optional package-query growth. The existing required query and
   probe pass rules stay byte-identical. Both original probes were unavailable;
   their stdout hashes support comparison but do not expose package versions.
5. Accept: compare PRoot and APT hashes without assuming common causality. Keep
   timing/concurrency/cleanup races as untested hypotheses, not flakiness.
6. Amend/defer: report existing failed WebKit predicates only. No helper-control
   token becomes evidence of an application bwrap spawn. ELF/API-call inspection
   is deferred because released bulk binaries are omitted; imports would not
   prove calls, and absence would not exclude dynamic lookup. Host AppArmor/userns
   restriction remains a hypothesis.
7. Amend: retain observed PRoot SIGTERM-ignore and survival as observations.
   Neither these nor an upstream citation identify the exact forwarding failure.
   The sudo relay/monitor/PTY path remains unresolved; group delivery is separate.
8. Accept: added diagnostics have no native run evidence in this stage. They can
   yield new observations only if the manager separately authorizes a future run.

## Evidence-proven observations

The input verifier authenticated 173 selected run-20 records, 18 manifests and
149 physically present manifest-selected objects. All 323 omitted objects remain
unverified. Both original outer ZIPs and nested selected ZIPs pass CRC checks.
Run 19 is historical comparison, not a retry. The fetched released smoke script
and snapshot helper at the pinned commit match the selected source hashes and
sizes; Git blob identities were independently recomputed.

| Original context | Scenario | Exit | Elapsed | Stderr | Receipt |
| --- | --- | --- | --- | --- | --- |
| Run20 standalone APT x64 | C | 1 | 6147 ms | 97 bytes, hash 74321a… | missing |
| Run20 standalone APT arm64 | B | 1 | 5888 ms | 97 bytes, hash a7562a… | missing |
| Run20 PRoot x64 | C | 1 | 3413 ms | hash 3155a7… | not retained in original probe |
| Run20 PRoot arm64 | B | 1 | 3268 ms | hash 3155a7… | not retained in original probe |

APT stdout is empty; PRoot stdout is nonempty. Their differing stream identities
weigh against equating the failures. Run20 standalone x64 and Pages APT have equal
smoke context hashes and equal required dpkg-query stdout hashes, but different
runtime image digests. Version drift within the queried set is not demonstrated.
Run19 standalone APT passed both architectures while Pages APT failed; run20
reversed those contexts. This establishes neither flakiness nor a packaging
regression.

The released script writes its run receipt at the end, after its inner catch and
scratch cleanup. Inner caught failures normally reach that write and stdout;
uncaught setup, cleanup, or persistence failures can bypass both. The exact
upstream stage cannot be established from a stderr digest. Missing receipt is an
observation, not an independently proved producer defect. No deterministic
source-owned harness repair is established.

PRoot retains genuine guest SIGTERM with host status 255, independently of the
passing deliberate-exit-255 control. Both outer deliveries target sudo, have no
guest handler marker, and leave three observed layers alive before forced group
cleanup. The PRoot layer has SIGTERM marked ignored. Group controls observe the
handler and no survivors. WebKit has one web process and no bwrap parent; its
NoNewPrivs=1/Seccomp=2 flags match the confounded baseline. The standalone bwrap
control fails on both architectures, with distinct observations:

| System | Helper exit | Existing diagnostic token | Stderr SHA256 |
| --- | --- | --- | --- |
| x86_64-linux | 1 | unclassified | `72c3b399fde2c46a921f589c0ffaf501a5a8e08d14f66c9719506e6d8e9e70ac` |
| aarch64-linux | 1 | no-such-file | `343bc964ed6df3c607e03e0ab769f346121faeeb376fa922db99abb7d80f0613` |

The aarch64 helper's missing-file classification supports a distinct path or
loader hypothesis. The missing object and exact helper cause are not established
from retained hashes. Neither helper observation proves an application sandbox
request or explains the original WebKit failure.

## Source changes and validation

The original argv, subprocess policy, timeout, environment, receipt read, cause,
reason and gate decision remain unchanged. Failure diagnostics add closed stderr
tokens and a descriptor-based inventory of at most 32 entries. Only four bound
artifact kinds are represented; neither contents nor unknown names leave the
process. Empty, oversized, invalid UTF-8, control-bearing, incomplete, unterminated
or private streams yield no tokens. A complete stream without a trailing newline
is withheld as `unterminated`; this does not establish truncation. At most eight
closed tokens leave the process, with `tokens_omitted` reporting any overflow.
Projected diagnostics retain the reported stderr hash/length and host system.
In container lanes, the tokens and original smoke stderr identity are
guest-asserted; their binding establishes self-consistency. The host command
receipt hashes Docker's stderr, which is a separate stream and does not
authenticate the guest token classification. These observations cannot
authenticate or synthesize a missing receipt.

The privacy filter withholds any stream containing a user-home path. Host-runner
wheel and PRoot stderr containing such paths will therefore yield `private` and
no tokens. Diagnostic yield in those lanes is limited; this checkpoint does not
relax the filter or claim observations from a future native run.

PRoot adds a bounded signal-observation summary, standalone-helper stderr tokens,
existing WebKit predicate failures, and the original smoke observation. No signal
status mapping, kill authority, guest bind, sandbox override or launch change is
introduced. Exact verification counts and preservation digests are recorded in
`evidence/live1/cont22-verification.json`. New tests supplement the unchanged seven
incumbent disjoint-filesystem methods and existing negative controls.

Python structure decision: retain the smallest hooks in the legacy hosted and
PRoot modules; place closed projections in two bounded diagnostic modules. These
serve the existing diagnostic responsibility. The inherited large modules are
not broadly refactored. Rollback removes these additive fields and their hooks;
it requires no payload, dependency, protocol or publication migration.

## Preserved boundaries and deferrals

The run20 positive matrix remains historical evidence: DNF 50/50 per Linux
architecture, pacman 40/40, Pages 112/112, Linux wheels 26/26 per architecture,
Darwin Nix 12/12, foundation3/authentication/pins/core tests pass. It was not
natively re-executed here. Standalone APT remains 39 passed/2 failed per
architecture. Required Linux Nix remains NIX_FHS_USERNS with downstream gates
not-run. Experimental PRoot remains six passing/three failing gates, with
application_qualified=false and qualification_authority=false; it is not an
isolation boundary. The full pinned D-Bus policy and alias removal are preserved.

All readiness/publication flags remain false, foundation3 retains sixteen blocked
plans and zero production receipts, and both promotion restrictions remain exact:
`linux-wheel-production-promotion-compatibility-unproven` and
`rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified`. Raw rpmlint
nonzero remains distinct from narrow policy acceptance. The recorded live Pages
origin is unknown with TLS verification code 62; it is not absent.

## Independent review and terminal amendments

The dispatcher supplied a cumulative independent pre-final review with six
advisory findings and no blockers. The closer's disposition is **amend**:

1. Accept and narrow: rename the passing control to the shared executor per
   system, remove the unused family label, and qualify consumer coverage above.
2. Accept: document container tokens as guest-asserted self-consistency evidence.
3. Amend: classify a complete stream without a newline as `unterminated`.
4. Amend: report and validate a bounded omitted-token count; test overflow and
   hostile counts without changing the eight-token limit.
5. Accept: record the helper observations separately by architecture and keep
   the aarch64 missing-file hypothesis distinct from application causality.
6. Accept limitation: preserve privacy withholding and disclose reduced yield
   for host-runner paths; add an explicit synthetic runner-path control.

Post-review modifications affect this document, `src/rs9/smoke_stream_tokens.py`,
`tests/test_smoke_stream_tokens.py`, `tests/test_cont22_diagnostics.py`, and the
verification record and candidate manifest. Terminal amendments receive no
additional independent review; task-scoped final verification is recorded in
`evidence/live1/cont22-verification.json`. No reviewer was selected or invoked
by the closer. Native causal proof and any run21 decision remain deferred to
the manager after canonical dispatch readback. Git finalization and archive
outcomes belong to the dispatcher.
