# Foundation 3 terminal candidate

Status: amended closeout candidate for manager disposition after the dispatcher-owned pre-final review. Foundation 2 remains accepted as an RS9 source/shadow foundation. This candidate implements shared state/provenance contracts and performs no live destination mutation. No publisher, signing, migration or publication acceptance is claimed.

## Terminal disposition and delta

Disposition: **amend**. The reviewed candidate and cumulative prior-stage changes are retained with the two receipt corrections below. This is an authorized terminal revision; the resulting bytes did not receive another independent review. Dispatcher Git and archive finalization remain separate from provider-local verification and this adoption recommendation.

| Pre-final finding | Terminal disposition |
|---|---|
| Receipt replay ignores receipt attempts and post-observation | Corrected. Replay merges receipt attempts with caller history. An older observation, or different observation at the receipt timestamp, requires reread. Identical fresh exact readback yields noop; fresher absence requires replanning and conflict blocks. |
| Supplied remote proof can fall back to timestamps | Corrected. Missing reader sequence, missing/mismatched response identifiers, and identifiers unchanged from pre-plan state fail closed. All supplied ordering identifiers must agree, even when sequence proof exists. Timestamp fallback applies only without supplied ordering proof. |
| Mandatory adapter gates and package qualification authority | Deferred before any real publisher. Only three gates are unconditionally required today; platform/build/install/runtime and trust/signature requirements depend on explicit operator policy. A source manifest's qualified verdict is a bound input, not independent qualification evidence. Future executors require adapter-declared mandatory gates and an authoritative qualification producer. |
| Desktop profile carries Nebular-specific license expectations | Deferred before a second Tauri tenant. The current profile requires commercial-license evidence and AGPL notice declarations. Its generic-looking name does not establish applicability to another desktop project. The separately selected package profile handles the Stellar probe. |
| Merged/closed contribution state can yield a new intent | Deferred before a contribution executor. Only open PRs currently block. Merged/closed state requires explicit qualified transition rules before creating another contribution; a planner intent alone cannot authorize a duplicate PR. |

The exact terminal delta from the reviewed candidate is six paths:

- `src/rs9/publication.py`: receipt history/readback ordering corrections.
- `tests/test_publication.py`: four regression tests covering omitted history, stale/contradictory readback, ambiguous receipts, new attempts, and missing/unchanged/conflicting remote proof.
- `docs/specs/rs9-retry-idempotence-v1alpha1.md`: replay semantics and contribution limitation.
- `docs/specs/rs9-publication-receipt-v1alpha1.md`: fail-closed proof and replay semantics.
- `docs/foundation3-candidate.md`: terminal disposition, verification and deferrals.
- `docs/foundation3-inventory.md`: terminal inventory status; the 52 product paths are unchanged.

Fresh closeout verification used Python 3.13.12. The new tests first reproduced the defects (11 failing subcases across four tests); all 12 publication tests then passed. The complete retained/new suite passed **201 tests with no skips**, with both retained public captures enabled. The same 201 tests passed over a physical 133-file product copy without Git from a foreign working directory; the ephemeral copy was cleaned. These runs exercise the terminal implementation and reauthenticate the earlier Nebular/Stellar captured bytes. They are not new live HTTP probes. Final report-only edits receive hygiene, inventory, whitespace and local-link verification separately.

Python 3.11 was absent on PATH and at both standard Homebrew binary locations; it was not run. No new worker or substantive reviewer was invoked during closeout. The fixes remained local because they concern one state machine. Temporary portability resources used the sandbox-permitted system temporary directory and were cleaned; no new persistent scratch or worker archive content was created. RTK commands worked, although its gain tracking database could not be opened in this sandbox; filtering/tracking statistics are not qualification evidence.

Python profile level: **Orange** under APG fallback counts. `publication.py` has 158 physical lines; `_ordered_after` has 24 owned statements, complexity 15 and 10 branches; `next_action` has 29 statements, complexity 18 and 10 branches. The narrow correctness fix preserves API/schema shape and standard-library `unittest` policy. Adverse regression tests and the required suite qualify this bounded choice. A manager can reject the six-path terminal amendment independently of the prior candidate; broader state-machine decomposition remains outside this closeout.

Recommend adoption only as a **state/provenance foundation with the explicit deferrals above**. Nebular license authority remains unresolved and blocking. Real publishers, signing, destination mutation, independent package/platform qualification, and the next Theme Forge family shadow were not implemented. No staging, commit, push or downstream write was performed by the closeout provider.

## Scope and entry evidence

The live checkout contains the adopted Foundation 2 ingestion/shadow implementation and matches `origin/main`. The only entry-local operator state was `.serena/**`, which was preserved. Public RS9 readback also identified the adopted main commit and tree. Prior prose identities were used as evidence, without introducing a current-state hash gate. No stage deltas were supplied before production.

The original Foundation 3 scope remains A–M: reusable ingestion with separate profiles; safe archive inspection; destination observations; pure planning, retry and provenance; evidence-bound qualification; synthetic destination tests; read-only release probes; contract documentation and hygiene. Stellar Burst is a genericity probe and has no renderer in this phase.

## Pre-final proposal and review disposition

Proposal disposition: **amend**. The exact dispatcher-bound proposal is 26,956 bytes with SHA-256 `4eae1bcaee06d7f508111f9eaa69c457ea0902be1f4a0c535ee4696e86b42d2a`. Its original bytes, the original task, and advisory review findings remain separate authorities/evidence; this report does not replace them.

The core/profile split, pure destination planner, evidence gates and provenance records were retained. The amendments are:

- Hard links are rejected unconditionally before visitors, rather than resolved. This closes inspection/accounting ambiguity without retaining aliased bytes. Existing safe symlink behavior and non-hardlink manifests remain compatible.
- Semantic identity binds payload hashes and explicit normalized semantic input hashes independently of allocated packaging revision. Actual rendered artifact hashes remain revision-specific. Destination readers must reconstruct this same semantic contract; artifact checksums alone cannot prove it.
- Observations are closed records with explicit authenticated transport, presence, components, content identity, reader implementation/version, source/time, remote identifiers and completeness. Forged states or subject bindings are rejected. Stale/future observations defer before exact noop.
- Passing gates bind evidence to release/profile/output and scoped operator inputs. License declaration agreement alone does not resolve authority. Observed conflicts and unresolved tenant markers remain blockers.
- Repair requires a versioned adapter contract defining allowed missing components and a matching operator policy. Allocation carries explicit input/output; a changed revision blocks pending rerender.
- Attempts and receipts use canonical mappings. Actual confirmed or ambiguous transport plus matching exact post-readback and ordering proof can produce `published`; attempts alone cannot. Persisted JSON is an audit graph, not a fresh authorization capability.
- Synthetic observation/gate fixtures are in standard-library test helpers rather than a separate JSON fixture tree. All retained tests remain under `unittest`; no dependencies or runner policy changed.

Advisory review findings were addressed as follows:

| Finding | Disposition and evidence |
|---|---|
| Revision-independent identity unspecified | Addressed by explicit semantic hash contract and real shadow revision-1/revision-2 equality tests; payload changes alter identity. |
| Offline fixtures cannot prove Nebular compatibility | Executed fresh captured-byte reauthentication, retained ingestion/dependency/recipe comparisons, and old/new scanner comparison over all three payloads. |
| Hard-link target memory cap | Superseded by fail-safe rejection before visitors; no hard-link target retention. |
| Executor/reader clock ordering | Receipt prefers response-bound sequence/etag/revision/commit proof and documents timestamp fallback; stale/future retry observations fail closed. |
| Subject mismatch and shared capture proof | Mismatches are contract errors. Both real releases replay through the same capture/authentication core; separate profiles evaluate authenticated bytes. |
| Evidence requirement changes v1alpha1 behavior | Explicitly documented: evidence table remains optional for validation/normalization, required for tenant authentication. |
| Persisted-plan re-verification limit | Documented sealed capture and fresh profile evaluation requirements; audit JSON cannot reauthorize release gates. |

## Resulting behavior

Generic release selection/capture/authentication has no project-name or filename-profile heuristics. RS9-owned versioned desktop and package profiles hold Cargo/Tauri/npm, payload-license, provenance and command expectations. No arbitrary tenant hooks execute.

Destination outcomes are `noop`, `publish-intent`, `repair-intent`, `block`, `block-conflict`, `defer-readback`, and `block-gate`. No planner outcome reports publication success. Retry requires readback after attempted transport and replanning after observation drift. Projection constraints bind base commit and allowed paths; contribution PR state remains separate from publication readback.

The source/npm license conflict for Nebular 0.6.1 remains unresolved. The live Nebular plan is `block-gate`. Package/render, provider, build/install/runtime, trust/signature and destination policy qualification remain required according to adapter/operator policy.

## Pre-final verification reported by the producer

Default interpreter: Python 3.13.12. The complete retained Foundation 1 + Foundation 2 suite and new tests passed: **197 tests**, with both live evidence inputs enabled and no skips. The same 197 tests passed in a physical copied product tree without Git, launched from a foreign working directory. Python 3.11 was unavailable on PATH and in the checked standard Homebrew locations; that interpreter run was not executed.

The suite covers deterministic plans/receipts, archive hard-link adverse cases, two independently selected profiles through the shared capture core, stale/conflict/ambiguous retries, duplicate/replayed requests, partial fanout, safe repair contracts, revision allocation/rerender, projection/contribution constraints, and the unresolved Nebular blocker. Source hygiene checks validate bounded text, binary magic, private paths/secrets, and standard-library-only imports. `git diff --check`, changed-file whitespace and all local links passed. A broader whitespace scan found pre-existing whitespace in unchanged `CLA.md`; its bytes match the baseline and were preserved.

Read-only public capture authenticated:

- Nebular release 0.6.1: release ID `400494635`; commit `49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e`; tree `203a80b33fc94c776c9c184f8cac4f1609cb0f2b`. All three original scanner manifests are byte-identical and contain zero hard-link members. Retained ingestion/dependency records and recipe bytes are unchanged; the render manifest changes only `inputs.normalized_sha256`.
- Stellar Burst release 0.6.1: release ID `399542205`; commit `a3e89683f92b8240c800ed303c866e7b12aa3277`; tree `158bd6d03b21d747385fb25f49e6e148d62043c8`. Main asset ID `599265851`, size `644313`, SHA-256 `53ef41a3de3335e042f2c4b1d299b1155b64bfc6556a84baf6a62cb28bcca209`. Required NOTICE and provenance checksum coverage was observed and verified. No Stellar registry query or renderer was added.

The parent transport was unavailable; one admitted worker captured public bytes, which the parent independently reauthenticated. Worker prose was not used as acceptance evidence. Transport capture was replayed through the generic core for both releases using the actual captured bytes. The probe proves selection/core genericity; it does not onboard a second tenant renderer or qualify installation/runtime behavior.

## Worker and archive hygiene

Gemini workers were used for bounded archive, publication, documentation and capture work. Publication prototypes were dispositioned partial and replaced/integrated after proven cleanup; parent tests establish the final candidate. Internal worker results do not satisfy dispatcher checkpoints.

All six admitted worker jobs reached terminal cleanup. The exact worker artifact subtree contains only regular files/directories, with zero symlinks or other special files. A workspace-relative capture staging directory was required by the worker facade; after cleanup, regular captured bytes were relocated outside the checkout. This was a narrow scratch-path exception caused by sandbox/facade restrictions. No payload binary, scratch, cache, worker metadata or `.serena/**` is part of the product inventory. Worker custody/result records remain intact.

## Deferrals and adoption recommendation

Live publication/signing, destination writes, registries, packaging PRs, complete pinned-provider/build/install/runtime qualification and the Nebular licensing resolution remain deferred. Observation producer authentication and external qualification evidence are trusted input boundaries; record hashes are not signatures. Timestamp fallback cannot replace destination preconditions against races.

The pre-final recommendation was adoption only as a **state/provenance foundation**, after dispatcher disposition of the checkpoint. The terminal section above records the subsequent authorized six-path amendment and remaining concerns. The separately assigned Theme Forge family shadow remains the preferred next phase; it was not started.

See the [exact changed-file inventory](foundation3-inventory.md), [core/profile ADR](adr/0004-ingestion-core-and-evidence-profiles.md), and [state/provenance ADR](adr/0005-publication-state-planner-and-receipts.md).
