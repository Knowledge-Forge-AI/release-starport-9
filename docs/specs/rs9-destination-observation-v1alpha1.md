# Destination observation record v1alpha1

Status: implemented specification in `src/rs9/observation.py` and `src/rs9/records.py`. Defines destination state observation, subject binding, and component hash comparison. Record hashes bind canonical JSON bytes; they do not establish signatures or authority. No actual destination readback adapter or publisher exists.

## Overview

Release Starport 9 requires observing remote destination state before planning or executing any publication action. Destination observation is not an inferred ping or passive HTTP status check; it is an active, evidence-bound state derivation process that compares observed remote component hashes and aggregate content identities against desired outputs.

## Schema (`rs9.destination-observation.v1alpha1`)

Observations are created via `rs9.observation.observe` and validated via `rs9.observation.validate_observation`:

```json
{
  "schema": "rs9.destination-observation.v1alpha1",
  "destination": {
    "id": "theme-forge-pacman",
    "adapter": "pacman",
    "mode": "projection"
  },
  "subject": {
    "package": "theme-forge-nebular-fusion",
    "version": "0.6.1",
    "revision": 1
  },
  "desired_identity_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "expected_components": {
    "PKGBUILD": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "theme-forge-nebular-fusion.desktop": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "state": "exact",
  "readback": {
    "authenticated": true,
    "transport": "ok",
    "presence": "present",
    "components": {
      "PKGBUILD": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "theme-forge-nebular-fusion.desktop": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    },
    "content_identity_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "level": "full"
  },
  "source": "synthetic-fixture",
  "reader": {"id": "synthetic-fixture", "version": "v1alpha1"},
  "observed_at": "2026-10-03T12:00:00Z",
  "remote": {
    "etag": "\"33a64df551425fcc55e4d42a148795d9f25f89d4\"",
    "sequence": 142
  },
  "revisions": [
    {
      "revision": 1,
      "content_identity_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "complete": true
    }
  ],
  "diagnostics": [],
  "contribution": null
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `schema` | string | Exact schema string `"rs9.destination-observation.v1alpha1"` |
| `destination` | table | Closed dictionary with `id`, `adapter`, and `mode` (`direct`, `projection`, `contribution`) |
| `subject` | table | Closed dictionary with `package`, `version`, and nullable `revision` |
| `desired_identity_sha256` | string | 64-character hex SHA-256 of desired semantic content identity |
| `expected_components` | table | Map of relative POSIX component paths to expected SHA-256 hashes |
| `state` | string | Derived state: `unknown`, `unreachable`, `absent`, `exact`, `incomplete`, `conflict` |
| `readback` | table | Explicit readback details: `authenticated`, `transport`, `presence`, `components`, `content_identity_sha256`, `level` |
| `source` | string | Closed enum: `synthetic-fixture`, `adapter-readback`, `live-read` |
| `reader` | table | Source adapter implementation ID/version; required for real readers |
| `observed_at` | string | Explicit RFC3339 UTC timestamp ending in `Z` with real calendar date |
| `remote` | table | Optional destination proofs: `etag`, `commit`, `revision`, `sequence`, `registry_id` |
| `revisions` | list | Observed revision entries: `revision`, `content_identity_sha256`, `complete` |
| `diagnostics` | list | Bounded list of `{code, message}` diagnostics (max 16 entries) |
| `contribution` | table/null | Optional upstream PR tracking: `{pr_id, state}` (`open`, `merged`, `closed`) |

## State classification logic

Classification derives one of six mutually exclusive lowercase states:
1. `unreachable`: `readback["transport"] == "unreachable"`.
2. `unknown`: `readback["transport"] == "unknown"` or `not readback["authenticated"]` or `readback["presence"] == "unknown"` or readback level is `none`.
3. `absent`: `readback["presence"] == "absent"`. **Unknown errors are never inferred as absent**. An absent readback must have empty `components` and `content_identity_sha256 == None`; presence of components in absent readback raises `ContractError("OBSERVATION_CONTRADICTION", ...)`.
4. `conflict`: Destination content identity differs from desired identity, or any observed component hash differs from expected components.
5. `incomplete`: Readback level is not `"content"` or `"full"`, content identity is missing, or observed components are a partial subset of expected components.
6. `exact`: All expected components match observed components bit-for-bit, content identity matches `desired_identity_sha256`, and readback level is `"content"` or `"full"`.

## Verification invariants

1. **Subject binding**: `validate_observation` checks destination, subject, expected components, and desired identity against expected parameters; any mismatch raises `ContractError("SUBJECT_MISMATCH", ...)`.
2. **Canonical rebuild**: Rebuilding the observation from its fields must reproduce the record bit-for-bit, preventing forged state verdicts.
3. **No ambient authorities**: Clocks and networks are decoupled; the record reflects a point-in-time snapshot at `observed_at`.

## What would make this wrong

1. **Trust boundary**: Accepting unauthenticated or caller-asserted verdicts without independent component hash mapping and content identity verification.
2. **Timestamps limitation**: Relying on local or remote wall clocks to infer release sequence; clocks drift and timestamps alone cannot prevent race conditions without remote sequence/revision IDs.
3. **Persisted audit limit**: Treating an observation record as a permanent or ongoing capability; observations age and must be re-read if older than `policy["max_observation_age_seconds"]`.
4. **Inferred absence**: Conflating transport failures (`unreachable`, `unknown`) with package absence (`absent`).

## Local Links

- [ADR 0005: Publication state, planner, and receipts](../adr/0005-publication-state-planner-and-receipts.md)
- [Specification: Publication plan v1alpha1](rs9-publication-plan-v1alpha1.md)
- [Specification: Publication receipt v1alpha1](rs9-publication-receipt-v1alpha1.md)
- [Specification: Retry and idempotence v1alpha1](rs9-retry-idempotence-v1alpha1.md)
- [Adapter and destination boundary](../architecture/adapter-destination-model.md)
- [Architecture overview](../architecture.md)

The observation producer owns authentication of transport and remote metadata. `authenticated: true` is a recorded assertion from that producer; a hash of the record is not a signature or a proof that a network request occurred. Synthetic fixtures are labeled by `source`; real readers must supply implementation/version custody through the `reader` field. The planner binds the adapter implementation/source version in its output manifest.
