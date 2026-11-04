# Current 0.7.1 APT bounded scratch-cleanup policy

Status: prepared source; activation and a corrective native campaign require the
owner's separate decision. The observation-only predecessor remains the policy
of historical source and receipts.

Native evidence: original run 41876976476 at f24cce56c6335eec55559809fe3a3b3fa61b2194
failed the ARM64 Debian Nebular client gate. Its existing closed observer emitted
one ENOTEMPTY cleanup marker. The scratch writer, its lifetime, and whether all
application checks passed are not established. The same run also had a Mac
runner-allocation failure; that does not make this a capacity-only failure.

## Exact behavior

The unchanged authenticated 0.7.1 harness is executed by the existing wrapper in
current Linux APT contexts: ARM64 Scenario B and AMD64 Scenarios C/C-signal.
The original 30,732-byte harness, complete closure authentication, source and
package pins, application checks, process checks, and outer timeout remain fixed.

For the first matching cleanup call only, the wrapper supplies Node rmSync with
recursive=true, force=true, maxRetries=3 and retryDelay=100. Eligibility requires
exactly the original two option keys, a canonical absolute scratch basename
nebular-rc-smoke-* directly under the existing temporary directory, and a
non-symlink directory owned by the current UID with mode 0700.

Node's own recursive removal retries EBUSY, EMFILE, ENFILE, ENOTEMPTY and EPERM,
with linear backoff. Three retries schedule 100 + 200 + 300 milliseconds for
each exhausted internal retry chain. This is not a total cleanup wall-time
bound or a claim that the whole tree has only four removal calls. The existing
outer timeout remains authoritative. No custom retry loop is introduced.

All other calls retain the original options and return/error identity. A final
error still propagates through the unchanged harness finalizer and required
failure gate; existing closed errno observation remains. A body failure stays a
failure even if cleanup succeeds. There is no error suppression, process kill
addition, follow-up deletion sweep, new path, permission grant or key access.

The plan's policy identity becomes
rs9.runner-policy.current071-apt-cleanup-bounded-retry.v1alpha1 and its execution
mode becomes reviewed-test-execution-bounded-cleanup. The diagnostic observer ID becomes
current071-apt-cleanup-rm-sync-retry-v1. Its schema and closed fields remain
unchanged; it reports final-error observation, not retry counts. Historical
inputs bearing current071-apt-cleanup-rm-sync-v1 retain that ID on every valid
or withheld validation path, including binding mismatches and incomplete
streams. Their validation output equals the predecessor's output; no
validator relabels them as retry evidence. The current execution plan requires
the new ID and wrapper byte identity, and the emitter always writes the new ID.
A standalone diagnostic record is non-admitting and does not prove a policy
executed: original native admission separately binds the R source, builder and
all required job/receipt identities.

The predecessor observation predicate is byte-for-byte unchanged. The stricter
directory/UID/mode/options checks gate only retries, so an observed but
retry-ineligible failure still emits its original closed errno marker.

Metadata checks are pre-call observations; this is not an atomic path-ownership
or writer-quiescence proof. The already authenticated harness owns the fresh
directory. Repeated filesystem churn may still fail and must stop the campaign.

## Alternatives and evidence

A blind capacity retry is outside the current grant and would not address the
observed non-capacity failure. Suppressing ENOTEMPTY would weaken the gate.
Adding a process killer or GUI storage redesign lacks a demonstrated writer
cause. Node's existing bounded retry facility is the smallest source candidate.

The same cleanup call and finalizer serve all three existing Linux APT
contexts, so the candidate applies one uniform fresh-scratch rule to them.
This includes AMD64 C/C-signal even though the observed failure was ARM64 B.
It may allow a short-lived writer outside the launch-root process census to
finish and then pass cleanup. The writer is unproved; this is an explicit gate
semantics tradeoff for owner disposition, not proof of process quiescence.

Local fixture tests use Node 22.23.3. The hosted workflow selects major 22 rather
than a patch version; the disposable client image/tool resolver may also select
a different Node 22. The exact Node version inside the failed ARM64 client is
not established by the retained closed receipt. Neither pin nor tool changes
are proposed. Only documented option forwarding is claimed; retries may reduce
transient failures, but native efficacy and traversal behavior are unproved.
No assumption of a particular internal JS or native recursive-removal
implementation is used to accept a gate.

No runtime or test dependencies, versions, package metadata, lockfiles, workflow
permissions, environment, signing scope or timing limits change. License and
supply-chain impact: no new input; the existing Node test/runtime tooling is
used. Runtime/packaging impact is confined to the authenticated test wrapper.

Local tests cover exact option forwarding, ineligible paths and metadata, return
and exhausted-error identity, final-error marker behavior, authenticated harness
execution, unchanged source refusal and retained failed body checks. Inert
fixtures do not prove Linux GUI or native acceptance. A fresh required native
campaign is still necessary after adoption.

Rollback: restore the prior module and tests and remove this policy document
and the new retry test. This patch changes no upstream source pin. Never reinterpret an
old failed receipt as passed. No production artifact or trust identity changes.

Reference: https://nodejs.org/docs/latest-v22.x/api/fs.html#fsrmsyncpath-options
