# Publication receipt and mutation attempt v1alpha1

Status: implemented specification in `src/rs9/publication.py` and `src/rs9/records.py`. Defines execution attempt auditing, verifiable receipt generation, and cryptographic readback confirmation. Record hashes bind canonical JSON bytes; they do not establish signatures or authority. No actual destination readback adapter or publisher exists.

## Overview

Release Starport 9 draws a fundamental distinction between attempting a publication operation and confirming its completion. Network responses, client-side HTTP success codes, and process exit statuses only prove that an attempt occurred. A confirmed publication receipt is issued **only after** an explicit post-readback observation proves that the remote destination is in the exact desired state.

## Mutation attempt schema (`rs9.mutation-attempt.v1alpha1`)

An attempt record documents a single execution event created via `rs9.publication.mutation_attempt`:

```json
{
  "schema": "rs9.mutation-attempt.v1alpha1",
  "plan_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "executor_role": "ci-publisher",
  "request_identity": "req-98721",
  "started_at": "2026-10-03T11:41:00Z",
  "finished_at": "2026-10-03T11:41:05Z",
  "transport_outcome": "confirmed",
  "response_remote": {
    "sequence": 143
  },
  "log_reference": {
    "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "size": 4096
  }
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `schema` | string | Exact schema string `"rs9.mutation-attempt.v1alpha1"` |
| `plan_sha256` | string | 64-character hex SHA-256 of the bound plan record |
| `executor_role` | string | Closed enum: `operator`, `ci-publisher`, `synthetic-test` |
| `request_identity` | string/null | Optional sanitized idempotence/request tracking string |
| `started_at` | string | Explicit RFC3339 UTC timestamp (must be `>= plan.evaluated_at`) |
| `finished_at` | string | Explicit RFC3339 UTC timestamp (must be `>= started_at`) |
| `transport_outcome` | string | Closed enum: `not_attempted`, `confirmed`, `ambiguous`, `failed` |
| `response_remote` | table | Optional destination response identifiers (`etag`, `commit`, `revision`, `sequence`, `registry_id`) |
| `log_reference` | table/null | Optional separate bounded execution log reference: `{sha256, size}` (max 1 MB) |

Only mutating plan intents (`publish-intent`, `repair-intent`) are permitted to record attempted transport (`transport_outcome != "not_attempted"`). Non-mutating plans attempting transport are rejected with `ContractError("ATTEMPT_POLICY", ...)`.

## Publication receipt schema (`rs9.publication-receipt.v1alpha1`)

Constructed via `rs9.publication.publication_receipt`:

```json
{
  "schema": "rs9.publication-receipt.v1alpha1",
  "plan_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "attempts": [ ... ],
  "attempt_sha256s": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
  "post_observation": { ... },
  "post_observation_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "readback_proof": {
    "basis": "remote-sequence",
    "remote": {
      "sequence": 143
    }
  },
  "final_state": "published"
}
```

### Supported final states

The receipt contract fully supports all non-success and terminal states:
- `already-exact`: Issued when the plan outcome was `noop`, post-readback observation is `exact`, and zero mutation attempts were executed.
- `published`: Confirms successful publication. Strictly requires an actual confirmed or ambiguous attempt AND an exact post-readback observation ordered after the attempt.
- `conflict`: Post-readback observation is in `conflict` state.
- `incomplete`: Post-readback observation is in `incomplete` state.
- `not-attempted`: Zero actual transport attempts were executed on a non-noop plan.
- `unconfirmed`: Transport was attempted but post-readback failed to confirm exact desired state, or post-readback could not be ordered after the attempt.

## Readback ordering and proof hierarchy

`_ordered_after` determines whether a post-readback observation occurred strictly after an execution attempt:
1. **Remote sequence proof**: When remote systems return an atomic integer sequence, `post.remote.sequence >= response.sequence`, with a response sequence newer than the planned observation when known, establishes ordering (`basis: "remote-sequence"`).
2. **Response identifier proof**: When the response provides `etag`, `revision`, or `commit`, equality with `post.remote` and a change from the planned observation establishes ordering (`basis: "response-<key>"`).
3. **Documented timestamp fallback**: When the destination provides no sequential or cryptographic remote proof, `post.observed_at > max(finished_at)` serves as fallback (`basis: "timestamp-fallback"`).

All supplied ordering identifiers must be corroborated. A supplied sequence without a reader sequence, an identifier missing from or contradicting readback, or a response identifier unchanged from the planned observation leaves the receipt `unconfirmed`. These cases cannot fall back to timestamps, even when another supplied identifier agrees. A `registry_id` alone identifies a registry object and is not ordering proof.

Receipt replay retains the bound attempts as retry history. It rejects an observation older than the receipt's post-observation and a different observation at the same timestamp. The identical fresh exact post-observation can be reused for `noop`; a newer observation is evaluated against the recorded attempts and current state.

## What would make this wrong

1. **Trust boundary**: Issuing a `published` receipt based solely on transport response codes without independent post-readback hash verification; trusting `not_attempted` attempts to grant success.
2. **Timestamps limitation**: Relying on wall-clock timestamps when remote sequences or ETags are available; timestamp fallbacks cannot prevent concurrent write races.
3. **Persisted audit limit**: Treating historical receipts as ongoing proofs of repository availability without validating that current destination observations remain exact.
4. **Duplicate and forged attempts**: Accepting mismatched `plan_sha256` or duplicate attempts within a receipt graph.

## Local Links

- [ADR 0005: Publication state, planner, and receipts](../adr/0005-publication-state-planner-and-receipts.md)
- [Specification: Destination observation v1alpha1](rs9-destination-observation-v1alpha1.md)
- [Specification: Publication plan v1alpha1](rs9-publication-plan-v1alpha1.md)
- [Specification: Retry and idempotence v1alpha1](rs9-retry-idempotence-v1alpha1.md)
- [Adapter and destination boundary](../architecture/adapter-destination-model.md)
- [Architecture overview](../architecture.md)
