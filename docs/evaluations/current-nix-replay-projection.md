# Linux Nix replay receipt category projection

Status: private diagnostic-only proposal against source from `2dd458a`.
No native execution or qualification is established by this proposal.

## Observed failure and scope

The retained artifacts for public run `41008667708` show the original current
Linux attempts timing out at approximately 240 seconds: B on aarch64-linux,
C on x86_64-linux, both without a receipt. Their optional replays completed
with failed receipts and D-Bus-related log categories, while their problem
codes were withheld and no safe receipt category projection was available.
The original command already uses the validated co-rooted pinned session-bus
argv. Default-PATH boundary probe failures are controls and do not justify
changing that production argv. This proposal changes no D-Bus command,
payload, timeout, required gate, replay equivalence rule or policy.

## Diagnostic correction

`run_replay` accepts optional `system=None` and forwards it to `_attempt`.
The retained-failure caller supplies its actual system context. The existing
projector independently accepts only its closed Linux system/platform/scenario
bindings; context is not guessed from a platform string. Omitted or mixed
contexts produce no additional observation, preserving the historical default.

After a replay outcome is fixed, a failed replay may project the already-read
receipt using the existing `project_problem_categories` enum/count classifier.
Only its receipt byte count/hash and bounded problem counts/categories are
retained under `replay.harness_problem_categories`:

```json
{
  "origin": "diagnostic-replay",
  "receipt": {"bytes": 123, "sha256": "<receipt digest>"},
  "problems": {
    "total": 1, "scanned": 1,
    "categories": [{"category": "receipt-not-written", "count": 1}],
    "unrecognized": 0, "non_string": 0, "omitted": 0, "unavailable": 0
  }
}
```

The original projector's original-attempt schema/stage is deliberately not
copied onto replay evidence. No raw problem strings, paths, process IDs,
nonce values, environment, stdout or stderr are added. Recognized private
suffixes become closed categories; unknown strings become an unrecognized
count; non-string entries become a non-string count. Projection faults remain
optional and cannot replace the original failure. The new optional field is
removed first if it would exceed the existing diagnostic byte bound.

A replay that passes remains `replay-passed` under an overall failed gate;
`replay_equivalent_to_original` remains false. Original cause, mandatory attempt,
child sequence, command and timeout behavior are unchanged. The original smoke
observation remains separate from the retained optional replay diagnostic.

## Verification

Five new pure tests use controlled child and receipt seams to cover both
current Linux tuples, exact pinned session-bus forwarding, original/replay
240-second outer budgets, existing 180000-ms replay harness budget, one replay
only, privacy injection, receipt digest binding, historical omitted context,
mixed context refusal, optional projection faults, byte-bound fallback, and
passing replay without gate promotion. The new tests fail against the source
preimage and pass against the candidate.

The candidate passes **83 focused tests**: the five new cases, existing
application smoke diagnostics, and existing stream-token/projection tests.
Network entry points are blocked by the private runner. Tests execute no
released application or native payload. Source/preimage hashes, exact argv,
test logs and a unified patch are retained in the private review packet.

## Remaining limitations

This correction provides a sanitized replay receipt observation, not a cause
for the original timeout or qualification of current packages. The earlier
run's missing raw problem details cannot be reconstructed from withheld codes.
A fresh authorized hosted run would be needed to observe the new categories.

The optional progress observer remains unavailable for current 0.7 source:
its legacy harness and snapshot hash pins differ from the fixed current
published source hashes. Read-only checks confirmed the wrapper exists and
selection returns unavailable. No observer source hash was widened and no
new progress evidence is claimed. Native products, D-Bus behavior and their
qualification remain outside this proposal.
