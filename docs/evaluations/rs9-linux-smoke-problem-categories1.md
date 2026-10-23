# RS9 Linux smoke: original-harness problem categories

## Status

Accepted source change after root QA and independent review. The changed test
modules passed 41 tests, and the adjacent application, Pages, hosted-container
and Nix/PRoot diagnostic modules passed 73 tests. Independent text-only Opus
review accepted the exact source candidate. The first adjacent invocation had
a test-import path error; the corrected invocation passed with unchanged
source. No native Nix/PRoot application run or new hosted observation was made.

The three new broad-exception lint warnings are retained deliberately: optional
diagnostic failures must preserve the original smoke outcome and must not log
private exception text. Other new test lint findings were corrected. Root owns
Git finalization, candidate inventory refresh and hosted observation. The
candidate manifest is untouched by this six-owner source change. No production,
publication, sandbox or original-gate authority changes.

## 1. Context

When the original application smoke fails, `application_smoke_diagnostic._attempt`
reads the original `<platform>-<scenario>.run.json` exactly once, with a
no-follow bounded descriptor read. It fixes the original outcome and only then
calls the optional diagnostics, which work from the record already read.
`smoke_stream_tokens` already had a closed mapping from harness problem strings
to categories (`PROBLEM_CATEGORIES`). That mapping drops variable suffixes, but
it was only reachable through the Darwin ScenarioA `harness_run_record`
projection. As a result, Linux x86_64 ScenarioC/C-signal and aarch64 ScenarioB
failures carried only `process-nonzero`, `receipt-failed`, `unclassified` and
withheld problem codes.

## 2. Change

### 2.1 Changed owners

| Owner | Change |
|---|---|
| `src/rs9/smoke_stream_tokens.py` | Pure refactor: the problem-classification loop moves out of `project_run_record` into `_classify_problems`. New producer `project_problem_categories`, new validator `validate_problem_categories` with private helpers, and an independent `try` in `collect_failure_diagnostics` behind the new keyword-only `system=None`. |
| `src/rs9/application_smoke_diagnostic.py` | `_attempt` takes keyword `system=None` and forwards it. `harness_problem_categories` is added to the diagnostic copy whitelist. `execute_application_smoke` passes its own `system` to the original attempt only. |
| `src/rs9/pages_smoke_diagnostic.py` | `validate_smoke_observation` consumes the field for the two Linux systems, inside a `try`. It carries the identity forward only when the field binds positively. |
| `tests/test_smoke_stream_tokens.py` | New class `LinuxProblemCategoryTests`. |
| `tests/test_cont22_diagnostics.py` | New class `LinuxProblemCategoryFlowTests`. |
| this document | New. |

No other file changed. There are no new modules, dependencies or
configuration, and no change to runner policy or the host.

### 2.2 Envelope `harness_problem_categories`

This field is versioned separately from the Darwin `harness_run_record` and
does not replace it. A positive envelope has exactly these keys:

```json
{
  "schema": "rs9.original-smoke-problem-categories.v1alpha1",
  "stage": "original-harness-problem-categories",
  "system": "x86_64-linux | aarch64-linux",
  "scenario": "C | C-signal (x86_64-linux) | B (aarch64-linux)",
  "receipt": {"bytes": "<int 1..1 MiB>", "sha256": "<64 lowercase hex>"},
  "problems": {
    "total": "<int | null>", "scanned": "<int>",
    "categories": [{"category": "<existing PROBLEM_CATEGORIES value>", "count": "<int >= 1>"}],
    "unrecognized": "<int>", "non_string": "<int>", "omitted": "<int>", "unavailable": "0 | 1"
  }
}
```

The single failure representation is exactly
`{"schema", "stage", "withheld_reason"}`. `withheld_reason` is either
`invalid-observation` (structural) or `binding-mismatch` (binding). It carries
no system, receipt, counts, categories or exception text. If the field is
absent, it stays absent.

### 2.3 Producer

`project_problem_categories(record, identity, *, system, platform, scenario)`
emits an envelope only when all of these hold:

- `(system, platform, scenario)` is one of `(x86_64-linux, linux-x64, C)`,
  `(x86_64-linux, linux-x64, C-signal)` or `(aarch64-linux, linux-arm64, B)`.
- `record` is the already-parsed dict.
- `identity` is the same-read descriptor summary (`fields["receipt"]`), with
  `present is True`, an exact-`int` byte length in `(0, 1 MiB]`, and a
  lowercase SHA-256.

`execute_application_smoke` is the caller that supplies `system`. The
`platform` derivation in that function sends every unknown system to
`linux-x64`, so the producer never infers a system from the platform.
Requiring the full triple rejects that fallback.

Only `bytes` and `sha256` are copied into the envelope. The producer does not
reopen any path, run a harness, read logs or widen the inventory. Counting
uses `_classify_problems`: the same `MAX_PROBLEMS` (64) prefix, the same
exact/suffix/prefix order and the same unknown and non-string accounting that
`project_run_record` uses. It adds no vocabulary, literal form or fallback
classifier. `omitted = total - scanned`. When the problem container is not a
list (`total: null`, `unavailable: 1`), `omitted` is 0.

If the receipt is missing, invalid, oversize, corrupt or not a dict, there is
no record, so the field is absent. The producer runs in its own `try` after
the Darwin block, so the Darwin key set and order do not change.

### 2.4 Consumer

`validate_smoke_observation(raw, system=...)` calls
`validate_problem_categories` only when `system` is `x86_64-linux` or
`aarch64-linux`. Checks run in this order:

1. If the raw field is absent, it stays absent.
2. An exact withheld shape is idempotent. If the observation mismatch flag is
   set, it becomes `binding-mismatch`.
3. A structural failure gives `invalid-observation`, or `binding-mismatch`
   when the observation is mismatched. Structural checks cover:
   - exact key sets at every level;
   - schema and stage;
   - a Linux system with a scenario allowed for that system;
   - a receipt that is exactly `{bytes, sha256}`;
   - exact non-`bool` `int` counts;
   - `unavailable ∈ {0,1}`;
   - when `unavailable == 1`: `total` is null and every other count is 0, with no categories;
   - when `unavailable == 0`: `scanned == min(total, 64)` and `omitted == total - scanned`;
   - a strictly ascending, duplicate-free category list drawn only from existing values, with each count between 1 and `scanned`;
   - `sum(counts) + unrecognized + non_string == scanned`.
4. A binding failure gives `binding-mismatch`. Binding checks cover:
   - the observation mismatch flag;
   - envelope system or scenario differing from the observation;
   - the observation receipt not being one of the two accepted shapes, or its
     identity differing from the envelope. The accepted shapes are the
     first-pass descriptor summary (`present is True`, keys within the
     summary set) and a prior positive projection (exactly `{bytes, sha256}`);
   - `receipt_error` being `receipt-missing`, `-invalid`, `-oversize` or
     `-corrupt`;
   - the inventory check below.
5. Otherwise the result is a closed copy of the envelope. Only in this case
   does the observation also gain a top-level `receipt: {bytes, sha256}`.

**Inventory check.** A positive category binding requires validated inventory status
`observed` or `limit-exceeded` with exactly one listed `run.json` row that is
regular, not a symlink, and whose `bytes` match the envelope. Missing,
malformed, unavailable, duplicate or mismatched inventory, and a limited
listing without that row, give `binding-mismatch`. A row outside a bounded
window is unknown, not proof of absence or a positive binding. A valid unique
row remains usable in a `limit-exceeded` listing. The inventory supplies no
SHA-256; its evidence is length/type corroboration only.

**Why the top-level `receipt` key.** `validate_smoke_observation` runs again on
its own output: on the host in `hosted_container_smoke._accept_container_output`,
in `retain_host_smoke_diagnostic`, and in `hosted_deb` and `nix_proot`. The
earlier output had no `receipt`, so a later pass would have nothing to bind
against. The key is added only on a positive binding, and it holds identity
only, with no status or codes. That keeps the projection a fixed point. When
the field is absent or withheld, no key is added, so existing outputs
(including the exact-equality `cont22-input-evidence.json` records) do not
change.

**Fault containment.** If the validator raises, the consumer `try` gives the
withheld shape when a raw field was present, and leaves the field absent
otherwise. No exception text is kept, and the original `APPLICATION_SMOKE`
error is never replaced.

Darwin consumers (`harness_run_record`, `inner_stderr_diagnostic`) are
unchanged. With `system=None` the Linux field is ignored and dropped; it is
absent, not a mismatch. Every current Linux caller passes a system.

## 3. Preserved behavior and privacy

The following are unchanged:

- the gate outcome: `cause`, `reason_token`, `failed`, raw exit code and
  signal, `receipt_error`, `problem_codes`;
- argv, environment, timeout, subprocess and cleanup policy;
- `MAX_DIAGNOSTIC` and diagnostic ordering;
- whole-stream withholding: private, incomplete, invalid, oversize,
  unterminated and control-byte streams.

Classification happens only after the outcome is fixed. It adds no replay, no
reopening of the receipt or stream, no new signal channel, no outer-255
mapping, no sandbox waiver and no qualifying effect. Raw problem strings,
paths, values and exception text never leave as categories or tokens.

**Extras path.** With `diagnostic_extras` on `x86_64-linux`, `_retain_failure`
stores the producer `fields`, including this field, as `initial_run`.
`initial_run` is not validated there. The field consumes the existing 60 KiB `MAX_DIAGNOSTIC` budget. If including
it would exceed that budget, `_retain_failure` omits only this new field from
the serialized `initial_run` and serializes again. It does not mutate the
original fields or their smoke observation. If the original diagnostic still
exceeds the unchanged cap, its existing `APPLICATION_SMOKE` bound refusal
remains. No replay, deadline, cap or original failure outcome is added or
changed by this fallback.

## 4. Evidence limits

- A category is a closed label. It carries no problem text, and no count,
  category or digest implies success, authentication or qualification.
- The receipt digest is a consistency check, not authentication.
  - On the first, in-guest pass it is compared with the descriptor identity
    from the original same-read.
  - On host passes, the top-level `receipt`, the envelope `receipt` and the
    inventory length all come from the same untrusted `result.json`. Host-side
    binding is therefore self-consistency only.
- `evidence_inventory` rows contain only `{kind, bytes, regular, symlink}`, so
  inventory corroborates length and file type, never the SHA-256.
- An unavailable or absent inventory, or a limited listing without `run.json`,
  cannot positively bind the category envelope; the result is withheld.
- Only the first `MAX_PROBLEMS` entries are classified. `omitted` reports the
  rest without describing them.

## 5. Authored tests and root execution

`tests/test_smoke_stream_tokens.py::LinuxProblemCategoryTests`:

- `test_producer_selects_only_linux_bindings_and_reduces_private_suffixes`
- `test_producer_requires_same_read_identity_and_dict_record`
- `test_unknown_near_match_multiline_and_non_string_forms`
- `test_empty_list_is_distinct_from_unavailable_problems`
- `test_scan_overflow_reports_omitted_and_ignores_items_past_window`
- `test_validator_fixed_point_and_withheld_idempotence`
- `test_validator_rejects_structural_forgeries_as_invalid_observation`
- `test_validator_binding_receipt_and_inventory`
- `test_collect_failure_diagnostics_emits_categories_only_for_bound_linux`

`tests/test_cont22_diagnostics.py::LinuxProblemCategoryFlowTests`:

- `test_linux_categories_flow_from_original_read_through_reprojection_and_retention`
- `test_classification_never_changes_original_outcome_or_masks_failure`
- `test_absent_optional_field_and_unreadable_receipt_add_no_keys`
- `test_wrong_system_withholds_and_non_linux_consumers_ignore_field`
- `test_diagnostic_extras_initial_run_keeps_bounded_field_without_masking`
- `test_host_boundary_retains_matching_field_and_withholds_swapped_scenario`
- `test_missing_or_uncorroborated_inventory_never_retains_positive_categories`
- `test_optional_category_growth_cannot_mask_original_at_diagnostic_cap`

All existing tests and assertions in both files are unchanged. The host-boundary
test reuses the existing `DisjointFilesystemTests` fixture, which needs `node`,
like the existing `HostBoundaryTests`. No skip, filter or suppression was
added.

The dispatcher authoring stages did not execute these tests. Root subsequently
ran both changed modules (41 passed) and adjacent diagnostic modules (73 passed).

## 6. What would make this wrong

- An unseen consumer requires an exact key set for a Linux
  `smoke_observation` and rejects the two added keys. A search of `src`
  found none.
- The `_classify_problems` refactor changes Darwin output. The existing exact
  Darwin `harness_run_record` assertions passed in the root checks.
- A host re-projection receives an observation whose `receipt` was rewritten
  between passes. It would then show `binding-mismatch`, which is the intended
  nonqualifying result, not a positive binding.

## Parent correction before QA

Read-only parent review identified that the initial source candidate accepted
missing/unavailable/outside-window inventory as a positive binding, contrary
to the request. That fallback is now fail-closed, with unit and consumer-flow
regressions authored. Review also identified that optional category growth
could push an otherwise bounded extras diagnostic over its existing cap;
the new-field-only omission and exact-cap/legacy-overflow controls are authored.
The pre-correction six-owner bodies/hashes are retained in the parent evidence
packet outside this repository. These corrections are not test evidence;
root QA and independent review subsequently accepted the resulting candidate.
