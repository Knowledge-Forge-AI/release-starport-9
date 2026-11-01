# Default-production SignedStore identity admission and persisted proof markers

Status: prepared-unused candidate source only. No signing, native execution,
source promotion, CI campaign, or publication authority is established by this
change.

## Defect and admission boundary

In default-production mode (`trust_config is None`), `SignedStore` previously
had three related gaps in `src/rs9/signed_store.py`:

1. `_validate_trust()` required `PRODUCTION_PRIMARY_FINGERPRINT`
   (`7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF`) but checked
   `PRODUCTION_SIGNING_SUBKEY` (`C021E00EE3D37C459B0E1CB3199F8028126E8A8C`)
   only when `subkey is not None`, and fell back to caller `evidence`
   (`signing_subkey` / `subkey_id`) when the validator omitted a subkey.
   Because the primary key is the offline certification identity and not the CI
   signing subkey, production admission must require both full pins from the
   validator result alone.
2. Short-circuit `or` evaluation across `primary_key_id` /
   `primary_fingerprint` and `signing_subkey` / `subkey_id` ignored `None`,
   empty, or conflicting secondary alias values when the first alias was
   present, while `retain()` required `"primary_key_id"` in `valid_result`
   rather than accepting `"primary_fingerprint"` in default-production mode.
3. `_load_manifest()` validated persisted record evidence through
   `_validate_trust()` without requiring `verified_primary_key` and
   `verified_signing_subkey` markers written from the validator result on first
   retain or checking their consistency with persisted identity aliases.

## Implemented repair

- **Validator-only dual-pin admission (`_check_production_pin_group`,
  `_validate_production_trust`)**: When effective `trust_config` is `None`,
  `valid_result` must supply both a primary key identifier (`primary_key_id` or
  `primary_fingerprint`) matching `PRODUCTION_PRIMARY_FINGERPRINT` and a
  signing subkey identifier (`signing_subkey` or `subkey_id`) matching
  `PRODUCTION_SIGNING_SUBKEY`. Caller `evidence` never fills a missing
  validator identity. Missing, `None`, empty, whitespace, wrong,
  primary-as-subkey, subkey-as-primary, short-key suffix, and conflicting alias
  values fail closed (`VERIFICATION_FAILED` at the `retain()` pre-gate when
  both primary key aliases are absent from `valid_result`, and
  `UNPINNED_TRUST` for all other missing/invalid/conflicting production pin
  checks). Existing full-fingerprint spacing, case, and `0x` prefix
  normalization in `_matches_pin()` is preserved, and consistent aliases/markers
  are compared as full fingerprints in those supported forms.
- **Caller claim consistency**: Contradictory caller production identity claims
  (`primary_key_id`, `primary_fingerprint`, `verified_primary_key`,
  `signing_subkey`, `subkey_id`, `verified_signing_subkey`, `verified_issuer`)
  are rejected on `retain()` with `UNPINNED_TRUST` rather than persisting
  records that would fail reopening or replay. Caller non-identity evidence is
  preserved unchanged.
- **Fail-closed persisted marker verification and residual boundaries
  (`_validate_persisted_trust`)**: On default-production manifest load (store
  initialization, `get`, `assemble_deployment`, `verify_store_integrity`, and
  `retain` replay reload), persisted `evidence` must contain both
  `verified_primary_key` and `verified_signing_subkey`, each matching the
  approved production pin and consistent with all present persisted
  primary/subkey fields and aliases. Legacy primary-only records and legacy
  caller-only-subkey records lacking `verified_signing_subkey` fail closed with
  `UNPINNED_TRUST` without rewriting, migrating, deleting, or re-signing store
  files. Pre-repair caller-only-subkey records where caller `evidence` also
  supplied a matching `verified_signing_subkey` marker remain
  schema-indistinguishable without a schema change (persisted markers enforce
  the store's admission contract, not external cryptographic proof against
  forged local store bytes). Per-call synthetic `trust_config` overrides on
  `retain()` follow synthetic admission (`effective_trust is not None`) while
  `_load_manifest()` validates against `self.trust_config` (requiring matching
  synthetic `trust_config` on reopen).
- **Synthetic trust and immutable replay preservation**: All explicit synthetic
  `trust_config` forms (`dict` with `allowed_keys`-only, explicit synthetic
  subkeys, `set`/`list`/`tuple`, and absent synthetic subkey), the synthetic
  `retain()` requirement that `valid_result` include `"primary_key_id"`
  (`VERIFICATION_FAILED` when absent), and retain-once immutable replay (no
  validator invocation or re-signing on replay) remain unchanged. Public APIs,
  schemas, constructor flags, and `get` / `assemble_deployment` contracts are
  unchanged.

Equivalent full-fingerprint formats are accepted at first admission and on
reopen. Immutable replay still compares supplied evidence field values exactly.
If a validator overwrote a caller's differently formatted value on the same
key, re-supplying that original representation returns OBJECT_CONFLICT. Replays
using the retained canonical claim or the matching nonidentity evidence keep
the existing immutable behavior; no validator runs on replay.

## Verification and AST profile

The parent ran the integrated source under Python 3.13.12 with isolation,
bytecode disabled and standard-library-only imports. The 193 collected tests
include the unchanged 24 signed-store cases, nine production admission cases,
and 160 surrounding record, scratch, generation, candidate, Pages and APT
cases. There were 191 passes, two intentionally excluded native GPG fixture
cases, no failures/errors, and no duplicate test IDs. Native-fixture discovery
was explicitly disabled for this source-only run, with an additional subprocess
tripwire recording zero actual GPG launches.

Six normalized alias/caller combinations survive retain and reopen; supported
normalized persisted proof markers reopen without mutation. Missing/wrong
validator pins and inconsistent identities still fail closed. Immutable replay
does not call the validator. The original synthetic admission guard and generic
fingerprint matcher are preserved.

The three production-specific helpers have respectively 10/8/6 statement
nodes, cyclomatic complexity 7/8/4 and 5/4/0 local bindings. The cohesive flat
production test module has 457 physical lines under a bounded 475-line parent
structural exception; all 16 named callables stay within 26 statement nodes,
15 local bindings and cyclomatic complexity 5. Existing legacy module size and
complexity remain separate from this narrow source correction. These are
standard-library AST measurements, not a configured-linter claim.

This source evidence does not qualify native signing, deployed stores,
production keys, or package publication. Legacy caller-supplied markers remain
schema-indistinguishable as described above.

## Rollback

Discard this unused candidate delta by restoring `src/rs9/signed_store.py` and
removing `tests/test_signed_store_production_pins.py` and
`docs/evaluations/production-store-identity-admission.md`.
