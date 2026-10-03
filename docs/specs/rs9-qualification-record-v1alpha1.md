# Qualification record v1alpha1

Status: implemented capability boundary; real adapter verifier suites pending.

`rs9.qualification-record.v1alpha1` binds a gate, release-record hash, adapter,
semantic content identity, source-manifest hash, exact artifact inventory,
verifier id/source hash, bounded environment, OS/architecture and command receipts.
Each command receipt carries an id, observed exit status and stdout/stderr hashes.
Raw logs, private paths, credentials and caller payloads are excluded.

`execute_qualification` accepts trusted reviewed local verifier code. It checks
the actual verifier module hash, rehashes candidate files before and after running
the verifier and registers an in-process capability on the authenticated capture.
The verifier must independently assert its real boundary: double render, build,
protocol/runtime behavior, installed-byte inventory or signature/tamper checks.
Its command receipts are an audit summary of those assertions, not a generic
exit-zero acceptance rule. Verifier source and resulting record hash need separate
review; arbitrary caller-selected code is not a production verifier.

The policy must separately allowlist the full qualification record hash. Gates
also bind profile/source evidence and candidate scope. Imported JSON, a hash-only
policy entry, a changed record or changed artifact cannot replace the capability.
CI verdict imports are unsupported. Future CI evidence needs a separately designed
attestation trust root binding workflow source, run identity, environment and
candidate bytes; this candidate makes no such claim.

The adapter minimum gate registry is in `src/rs9/adapter_gates.py`. Policy may add
obligations and cannot remove/waive adapter requirements. Platform matrices and
independent verifiers must be reviewed before a publisher can enable.

Full record approval follows execution: stdout/stderr hashes are known only after
the verifier completes. An independent attended approver must approve the exact
resulting record hash and its source/environment/artifact binding before a policy
may allowlist it. Keep that execution capability in the operator process, then
re-observe and plan after approval. Restarting requires a fresh execution; any
changed record hash requires fresh approval. Approval orchestration is pending;
these APIs alone do not implement an attended production workflow.
