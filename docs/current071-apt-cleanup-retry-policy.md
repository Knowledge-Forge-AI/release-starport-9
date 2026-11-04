# Current 0.7.1 APT bounded whole-call cleanup

Status: source policy specification. This document authorizes no activation,
native campaign, capacity fallback or slot use. Separate owner-adoption and
original native qualification receipts establish activation and acceptance.
A repeated cleanup failure stops the campaign; no blind successor is allowed.

## Evidence and limitation

Original R41889464519 at a920ce158e17a1bb51d892e515309caeb196ceee
failed ARM64 APT Scenario B. The closed record reports all 12 application steps
passing, exactly one harness-cleanup-failed problem, and ENOTEMPTY from the
builtin-retry observer. This does not establish a fully qualified application,
the scratch writer, or whether native retry eligibility was satisfied.

A controlled Node 22.23.3 fixture creates one ordinary late child between child
traversal and final directory removal. The prior builtin maxRetries 3 rule
leaves that child and throws ENOTEMPTY after five rmdir calls. A second whole
rmSync call re-enumerates the child and removes the fixture. The proposed
wrapper passes that same real-filesystem test. This reproduces a contributing
mechanism; it does not reproduce the actual native writer.

The inspected Node 22.22.1 and 22.23.4 synchronous rimraf sources enumerate
children once and retry rmdir without another enumeration:
- https://github.com/nodejs/node/blob/v22.22.1/lib/internal/fs/rimraf.js
- https://github.com/nodejs/node/blob/v22.23.4/lib/internal/fs/rimraf.js

No Node pin or runtime installation change is proposed. Local fixture tests use
22.23.3; the native-host receipt reports22.23.4 and the APT Burst loader reports
22.22.1. The exact interpreter executing the failed Nebular harness remains
unestablished by those separate observations.

## Exact behavior

The unchanged authenticated 30,732-byte harness and its complete source closure
remain fixed. Current Linux APT contexts remain ARM64 B and AMD64 C/C-signal,
which use the same scratch cleanup call and finalizer. Historical, Darwin and
other-family routes retain their existing execution paths.

Only the first matching original scratch cleanup is eligible for rewalk.
Eligibility requires exactly the original two option keys, a canonical
absolute nebular-rc-smoke-* basename directly under the existing temp parent,
a nonsymlink directory owned by the current UID, mode 0700, and safe integer
device/inode metadata.

The wrapper makes at most four whole rmSync calls, passing the identical
recursive=true/force=true options object and receiver. Builtin retry options
are not added. Only ENOTEMPTY permits another call. Between calls it waits
100, 200, 300 ms using standard Node Atomics.wait, then checks the same eligible
device/inode again. Lost eligibility, replacement, unavailable metadata,
another error code or exhaustion immediately rethrows the applicable original
cleanup error. If the root vanishes at recheck, the prior ENOTEMPTY still fails the gate even
if removal was achieved. No final error is swallowed. The total scheduled wait is at
most 600 ms; traversal duration remains governed by the unchanged outer timeout.

This narrows the a920 builtin retry class: EBUSY, EMFILE, ENFILE and EPERM now
fail immediately rather than receiving builtin retries; only ENOTEMPTY permits
another whole call. Synchronous Atomics waits can delay JS signal handlers by
at most 600 ms scheduled sleep, in addition to traversal time.

The observation predicate stays byte-identical to its predecessor. It still
observes retry-ineligible errors, preserves one closed final errno marker and
does not expose paths or contents. A passing run emits no failure outcome and does not show whether a rewalk was used;
acceptance alone does not prove causal efficacy or writer quiescence.
A new failure-only fixed label reports
ineligible, identity-lost-after-1..3, exhausted-4, nonretryable-after-1..4 or
unclassified. These closed outcomes distinguish initial eligibility, lost
identity and exhausted calls without retaining actual UID/inode/mode values. A failed application body remains failed
even if cleanup later succeeds. No additional process kill, generic cleanup
sweep, environment variable, dependency, permission or signing access is added.

Metadata checks are pre-call observations, not an atomic ownership or process
quiescence proof. A short-lived writer outside the launch-root process census
may finish and allow cleanup to pass; a continuing writer may still exhaust
the bound. This gate-semantics tradeoff requires owner disposition. The change
is not a finding that such an escaped writer caused the native failure.

## Identity, validation and rollback

The current policy becomes
rs9.runner-policy.current071-apt-cleanup-rewalk.v1alpha1;
execution mode is reviewed-test-execution-bounded-rewalk, and observer ID is
current071-apt-cleanup-rm-sync-rewalk-v1. Current plans reject both prior IDs,
modes and policy identities. The emitter always writes the current ID.
Current records use schema rs9.current071-cleanup-observation.v1alpha2 with
one rewalk_outcome field; no-cleanup-error and withheld records set it to null.
Historical observation-only and builtin-retry IDs retain v1alpha1 and the exact
old11-key shape. Validation preserves both historical IDs on every valid or
withheld path. Standalone diagnostics remain non-admitting;
original native admission separately binds source, builder, jobs and receipts.

Tests cover actual late-child traversal, maximum calls, original option and
return/error identity, first-call scope, non-ENOTEMPTY refusal, device/inode and
eligibility changes, historical fixed points, source refusal and retained
application failures. Inert fixtures and the controlled local filesystem test
do not establish Linux GUI or native qualification.

No package metadata, locks, dependency or license closure changes. Supply-chain
impact is limited to existing standard Node APIs. The original source and
package pins, workflows, outer timeout, signing scope and trust identity remain.
Rollback restores the previous four files. A source rollback does not turn a
failed native receipt into success.
