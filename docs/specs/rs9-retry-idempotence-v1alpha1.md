# Retry and idempotence specification v1alpha1

Status: implemented specification in `src/rs9/publication.py`. Defines deterministic retry evaluation, idempotence guarantees, and the original nine retry MUST rules. Record hashes bind canonical JSON bytes; they do not establish signatures or authority.

## Overview

In distributed release publication, failures are frequently ambiguous: network connections drop mid-transfer, gateways time out before returning receipts, and registries may experience indexing latency. RS9 prevents duplicate publications, race conditions, and corrupted repository states through two pure control plane functions:
- `rs9.publication.check_precondition(plan, observation, *, evaluated_at)`: Validates observation freshness and identity against plan preconditions. Returns `"ready"`, `"stale-plan"`, or `"reread-required"`.
- `rs9.publication.next_action(plan, attempts, latest_observation, *, evaluated_at, receipt=None)`: Evaluates the execution attempt history and current destination observation to determine the exact next step without ambient side-effects.

## Required publisher rules

Future publishers MUST follow these nine rules:

1. Observe authenticated destination state before **every** mutation.
2. Bind mutation to the exact observed identity/etag/revision where the destination supports a precondition. Otherwise the adapter must document its race limit; a timestamp cannot substitute for a compare-and-swap.
3. After ambiguous transport failure, reread before retry. RS9 also requires reread after confirmed or failed attempted transport. Local timestamp freshness currently governs retry ordering; remote sequence/response bindings strengthen receipt ordering.
4. Exact authenticated readback becomes noop success with no duplicate publication. Replay validates the complete receipt graph and merges its attempts into retry history, even if the caller omits them. A supplied observation must be newer than the receipt's post-observation, or be that identical observation; older or same-time contradictory observations require reread. A fresher non-exact observation requires replanning or blocks on conflict.
5. Conflict blocks automatic retry and never becomes republishable work.
6. Partial/incomplete state requires a named adapter-specific repair contract explicitly selected by destination policy, or blocks. Only contract-listed missing components can be restored; mismatched existing content cannot be repaired automatically.
7. Never overwrite an immutable registry version. Observed incompatible content blocks even if a transport previously failed.
8. Projection repositories require both an observed base commit and component-bounded allowed paths. A changed observation hash or remote identity requires a new plan.
9. Contribution mode tracks upstream PR state separately from direct publication. Open or merged PR status does not prove exact package readback.

`check_precondition` rejects stale/future observations and returns `stale-plan` when the observation hash changes, including a refreshed observation timestamp. `next_action` requires reread after attempted transport, returns noop only for fresh exact readback, and requires replanning before another mutation on non-exact state. A planner or retry result authorizes no network action in this phase; future executors must enforce these rules at their real mutation boundary.

Contribution policy currently blocks an open PR. Merged or closed PR handling does not yet define whether to wait for publication readback or authorize a distinct contribution. Such a plan is not sufficient authorization to create another PR; a future contribution executor must define and qualify that transition first.

## Deterministic next action outcomes

| Outcome | Meaning | Next step |
|---|---|---|
| `noop` | Destination already in exact desired state | Issuance of `already-exact` receipt; zero side effects |
| `publish-intent` | Destination absent and preconditions verified | Execute transport attempt |
| `repair-intent` | Destination incomplete and safe-repair contract satisfied | Execute repair attempt |
| `reread-required` | Observation stale, in future, transport unread, or unreachable | Capture fresh destination observation |
| `replan-required` | Observation drifted from plan preconditions or prior attempts executed | Re-evaluate `rs9.planner.plan` against fresh observation |
| `block-conflict` | Irreconcilable content or revision conflict at destination | Halt workflow and alert operator |
| `block` | Incomplete state without valid repair contract or policy disablement | Halt execution fail-safe |

## What would make this wrong

1. **Trust boundary**: Retrying an operation based on client-side transport errors without verifying actual destination state via post-readback.
2. **Timestamps limitation**: Allowing out-of-order execution when clocks drift; timestamps are checked against bounded windows and attempts must strictly precede observations.
3. **Persisted audit limit**: Assuming cached retry outcomes remain valid over time without checking current destination observation hashes.
4. **Retrying on conflict**: Force-pushing or re-uploading against an immutable destination in `conflict` state.

## Local Links

- [ADR 0005: Publication state, planner, and receipts](../adr/0005-publication-state-planner-and-receipts.md)
- [Specification: Destination observation v1alpha1](rs9-destination-observation-v1alpha1.md)
- [Specification: Publication plan v1alpha1](rs9-publication-plan-v1alpha1.md)
- [Specification: Publication receipt v1alpha1](rs9-publication-receipt-v1alpha1.md)
- [Adapter and destination boundary](../architecture/adapter-destination-model.md)
- [Architecture overview](../architecture.md)
