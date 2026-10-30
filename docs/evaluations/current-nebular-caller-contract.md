# Current Nebular caller contract

Status: bounded static source implementation; native qualification and publication
remain held.

## Exact current selection

The new contract is separate from the historical 0.6.1 caller contracts. It
selects repository `Knowledge-Forge-AI/theme-forge-nebular-fusion`, repository ID
`1358643872`, release ID `426333162`, tag `v0.7.0`, commit
`cadb40c4972f68f314096ff60fbcfb4da950c161`, and tree
`27c643b6375c2aafde314799c4f08e844c14992c`.

`current_contract_for_capture` requires an actual in-process authenticated
release, the unchanged authenticated tree and release metadata, and both exact
current Linux release asset IDs, sizes and SHA-256 values. It does not select by
version alone. The source-owned JSON contract is bounded and pinned to SHA-256
`db10b939421dc56d4011dcb3a52a659f0c0e8f73e33439cd88173e3b85fe90a8`.
Changing its fields, source pins or whitespace requires a deliberate source
update and review.

Current source collection authenticates 21 tagged source files against their
Git blobs, SHA-256 and sizes. These comprise the historical 19 path names with
their independently measured current bytes, plus the current Linux resource-root
and Solar payload-authentication modules. Of the historical path set, 13 files
changed bytes and six remain identical. The eight observed member-role literal
relationships remain valid in the exact current source.

The collector returns the existing caller-source audit schema in a
JSON-compatible dictionary carrying a private in-process capture binding. Its
source result is sealed; verification rechecks the live authenticated capture
and unchanged result. Serializing that dictionary does not persist the binding.
Plain JSON, mutated copies and mixed historical/current identities cannot grant
current caller acceptance.

Historical `TAG_NAME`, commit/tree constants, forward-correction identities,
source inventories, runtime pins, floor hash, default function calls and result
schemas remain authoritative for their original releases. The historical
`_reviewed_tag_identity` helper was not broadened to accept 0.7.0.

## Current byte contracts

The data derives from actual authenticated current release custody, without
executing a payload:

- Linux ARM64 asset `687086522`, SHA-256
  `eb15e92e2c6c893748612c3e1e3910acbc57e8e990a4d4d1c89f958e330ce17c`.
- Linux x64 asset `687086740`, SHA-256
  `4a4035797ac591854e362404d32e8acc38f79ccdccf7696b31f24060f0b55c27`.
- Both manifests identify `tfsb.studio-sidecar-distribution`, schemaVersion `1`,
  runtimeKind `node-runtime-payload-v1`, and entrypoint
  `dist/service-protocol/server-cli.js`.
- Each manifest binds exactly 350 sidecar file rows. Verification checks exact
  manifest bytes and the complete expected file set, SHA-256, size and mode
  preservation. Current caller-member, application and runtime hashes are
  additionally pinned to the independently observed release members.
- The embedded runtime is declared as Node `22.23.3` in both manifests and
  matching tagged runtime authority. Its bytes retain SHA-256
  `d09e299258c24f7cdf6f5d5ec185e3a56512b27a697113735dac909f1cac7b8d`
  (ARM64, 122,179,336 bytes) and
  `fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48`
  (x64, 124,827,920 bytes), mode `0755`. No version probe was run.
- The current Loom floor member remains
  `loom-payload/package.json`, but now has SHA-256
  `168b43aba5a8966b0caee78d441f4bb63787889bb2895120e44f505194b3236c`,
  size 1,822 bytes, pointer `/engines/node`, value `>=22`.

`release_runtime_floor(..., capture=current_capture)` admits only the exact
current authenticated release and an exact current archive, then requires the
current entry's member/hash/pointer. Omitting `capture` retains the historical
floor contract. This does not silently reinterpret the historical RPM policy.
Current Loom caller checks retain the existing `nodejs >= 22` preservation-policy
requirement; they make no system Node execution claim.

Producer lineage coordinates inside native manifests remain producer inputs.
They are not relabelled as the public tag commit, and no historical forward-fix
proof or source-equivalence claim is substituted for the current identity.

## Verification

Focused static suite:

```sh
PYTHONPATH=src python3 -m unittest \
  tests.test_nebular_callers tests.test_rpm_lint_policy
```

Result: 45 tests passed. The caller suite includes all ten unchanged historical
tests and eleven current tests. Current tests cover the exact selector and asset
inventory, real core authentication in controlled fixtures, both platform role
sets, contract tampering, missing/mutated source, JSON capability refusal,
wrong/mixed identities, floor/runtime/member mismatches and historical floor
preservation. Controlled fixtures explicitly substitute their own source/asset
bytes; they do not claim native qualification.

Separate static resulting-state evaluation used the real sealed current source
and published archive custody: source collection was available, all 16 role
checks across both Linux architectures passed, and both current floor checks
returned `>= 22`. All 16 corresponding plain-JSON caller evidence substitutions
were refused. No network write, native invocation, install, build, signing,
workflow dispatch or publication occurred. `git diff --check` passed for the
owned changes.

## Held integration and smoke-support patch scope

Current RPM integration remains a separate slice. `rpm_lint_policy.py` and its
historical policy data still bind old versions and preservation inventories.
`build_rpm.py` and `rpm_client_runtime.py` call the historical default floor API;
their current route must pass the authenticated current capture and a reviewed
current policy entry. No change to these files or RPM policy occurred here.

The observed `unknown-tag-closure` originates in
`src/rs9/hosted_smoke.py::_reviewed_verifier_support`. Its `VERIFIER_SUPPORT` and
`VERIFIER_SUPPORT_TREES` tables contain the historical and forward-corrected
0.6.1 identities, excluding the exact 0.7.0 commit/tree above. The precise
minimal patch scope for that blocker is:

1. Add the exact current commit to both tables, binding support
   `("package.json",)` and the exact current tree. Preserve unknown-commit and
   wrong-tree refusal. Do not introduce a version or ambient-checkout fallback.
2. Extend `tests/test_sidecar_harness_closure.py` with current commit/tree,
   missing/tampered/nonregular support and unknown/mixed identity cases.
3. Establish the actual current verifier closure and import preflight before
   hosted use. Current `tools/platform-targets.mjs` reads root `package.json`
   at import time; `prepare_smoke` already collects bounded tagged `tools/`
   files and explicitly selected support through `tagged_files`. Current
   `sidecar-common.mjs` and `native-rc-smoke.mjs` import sibling tool modules.
   A table update alone is not evidence of successful import or execution.

These are the minimal files for the observed selector rejection, not a claim
that later payload/GUI/runtime gates will pass. `nebular070_smoke_support.py`
is a separate transported-support authority and does not own this rejecting
table; it was not changed or treated as a shortcut.

## Smoke source closure extension

This later evaluation supersedes the unknown-tag-closure deferral above. The
initial caller source/data/tests and their 45-test evidence were preserved;
the initial report bytes were retained before appending this section.

Additional source scope: `src/rs9/hosted_smoke.py` and
`tests/test_sidecar_harness_closure.py`. All historical `VERIFIER_SUPPORT` and
`VERIFIER_SUPPORT_TREES` entries remain intact. The new entry selects only the
exact authenticated current Nebular commit/tree already identified above.
Unknown commits, wrong trees, mixed generation identities and unauthenticated
current capture dictionaries remain refused.

The current import-time closure is closed and byte-pinned:

- Three roots: `tools/sidecar-common.mjs`, `tools/sidecar-verify.mjs` and
  `tools/native-rc-smoke.mjs`.
- Ten transitive modules: `build-inputs.mjs`, `build-settings.mjs`,
  `candidate-provenance.mjs`, `darwin-linkage-validator.mjs`, `fs-snapshot.mjs`,
  `native-launcher.mjs`, `native-rc-package.mjs`, `native-runtime.mjs`,
  `node-runtime-authority.mjs` and `platform-targets.mjs`, all under `tools/`.
- Root `package.json`, read by `platform-targets.mjs` at import time.
- Fourteen exact current Burst fixture files under
  `docs/examples/v0.4/brand-system/core-minimal/`.

The source dependency graph was derived from actual current tagged bytes and
checked against the maintained constants. It has no external package imports
in its import-time graph. Eight additional sibling modules and the current
fixture closure were obtained with bounded exact-commit public GETs, beyond the
source files already authenticated during caller preparation. Every collected
member matched its authenticated tree's Git blob and independently recorded
SHA-256/size. Nebular source/support totals 398,177 bytes; the fixture totals
9,174 bytes. No ambient checkout, installed npm package or historical source
closure was substituted.

Current preparation and readback require both real in-process captures. Burst
fixture identity is repository ID `1342490027`, release ID `424873797`, tag
`v0.7.0`, commit `3edb9d2c40dd19a2b7d97d9309bc210e7fed711c`, tree
`4be1551c49b15dff788d07ed1fb00ddcd8839a76`. Each of the 28 source records must
have the exact path, role, producer commit, blob, SHA-256 and size. The actual
staged file set must match exactly; missing, extra, changed and nonregular
members are rejected. Recomputing a changed member's supplied record cannot
replace its reviewed pin. The importer path must remain the reviewed
`source/tools` directory, and the current generation marker cannot be changed
or dropped to select a historical readback path.

### Fresh extension evidence

```sh
PYTHONPATH=src python3 -m unittest \
  tests.test_nebular_callers tests.test_rpm_lint_policy \
  tests.test_sidecar_harness_closure tests.test_hosted_smoke
```

Result: 83 checks passed. This includes all prior caller/RPM-policy tests,
historical closure behavior, controlled current core captures, the maintained
non-native ESM import gate, cross-generation producer and role refusals,
missing/extra source records and files, changed support with recomputed record
digests, importer redirection, lost live captures and nonregular support.

Separate resulting-state validation used the actual current source and fixture
custody through `prepare_smoke`, strict source readback and the maintained
`verifier_import_preflight`. The 28-member closure passed its 13-module import
preflight using the system Node tool, version `22.22.2`. Ten actual-custody
negative controls were refused before `_run_verifier` could run: missing/extra
records, missing capture, cross-generation marker, wrong fixture producer,
redirected importer, changed producer record, extra staged source, missing
support, and changed support with recomputed record hashes.

The system tool imported verifier JavaScript only. The embedded Node 22.23.3
runtime, GUI and released application were not executed. Function-time dynamic
loading, distribution verification, installed caller behavior and application
smoke acceptance are outside this import-only evidence. No dependency, runner
policy, workflow, signing or publication change occurred. Scoped
`git diff --check` passed. Private source inventories, GET receipts, import graph,
actual validation results and a fresh hash manifest remain retained for review.

### Remaining integration

The `unknown-tag-closure` selector blocker is addressed for this exact current
source tree. Current RPM policy and its floor callsites remain held exactly as
described earlier: a separate reviewed current preservation policy and capture
wiring are still required in `rpm_lint_policy.py`/policy data, `build_rpm.py` and
`rpm_client_runtime.py`. Full hosted native builds, installation, payload
verification, GUI/caller positive and negative execution, and publication gates
remain unqualified by this source closure result.

## External review corrections

The first independent review returned REVISE with four local blockers. The
resulting-state corrections address each without changing historical constants,
default release selection, dependencies, runner policy, workflows or package
metadata:

- **B1, path compatibility:** preflight again resolves source/tools before
  readback. Current checks compare the canonical importer against canonical
  `source/tools`. Symlinked ancestors such as macOS `/var` or `/tmp` are allowed;
  source-root aliases and descendant aliases remain refused. Committed
  historical and current regressions use unresolved paths beneath a symlinked
  ancestor; current source-root and descendant aliases still fail.
- **B2, copying bindings:** deepcopy allocates the evidence dictionary without
  its constructor and preserves `_capture`, `_capture_hash`, `_seal` and `_proof`
  verbatim. Copying neither authenticates nor rebinds. A non-identity capture
  mutation followed by deepcopy succeeds as a copy operation and is then
  refused by verification.
- **B3, generation isolation:** historical caller verification refuses version
  `0.7.0` and either current Linux asset hash carried by inputs, inventory or
  member pin. These refusal hashes are fixed constants; the historical route
  does not read the current JSON contract. Regression coverage pairs real
  historical source evidence with current-shaped inputs.
- **B4, classified failure:** current smoke capture binding maps missing,
  unreadable and malformed contract failures (`OSError`/`ValueError`) to
  `SIDECAR_HARNESS_IMPORT` with `current-capture-binding`.

Related corrections parse current floor archives from the already-hashed
in-memory bytes, classify malformed floor capture bindings, delay current
`source-bindings.json` until readback passes, guard malformed record/tag/row
shapes, and use a distinct `mixed-generation` diagnostic. Committed tests bind
the three shared caller/smoke tool pins and current asset refusal hashes to the
reviewed data. Adapter member hashes must directly equal their authenticated
tagged adapter source hashes; coherent substituted member/inventory values do
not bypass that relationship.

The current JSON configuration route is **checkout-only**. It resolves
`operators/theme-forge-current-202610/nebular-callers.json` relative to this
source checkout. This slice does not claim that route works from the universal
wheel or an installed Python package. No wheel/package data was added.

`CURRENT070_VERIFIER_IMPORTS` documents the reviewed import-time graph and is
checked for internal consistency. It is not a JavaScript parser and does not
itself prove that source code obeys that graph. Enforcement comes from the exact
member-byte pins, closed source-set readback, live capture identities and the
maintained import-only preflight. Function-time loading remains outside this
evidence.

### Fresh review-correction verification

The same focused command listed above passed **93 checks**. The fixture-based
unit tests deliberately substitute synthetic source/asset pins and synthetic
adapter member/source joins. Those tests establish boundary behavior, not
qualification of public native artifacts. The committed real-data consistency
test separately compares the unchanged reviewed JSON with smoke pins, asset
constants and adapter relationships without substituting those data tables.

Fresh private actual-custody evaluation, distinct from synthetic unit evidence,
reauthenticated the retained public capture and measured sources: all 16 caller
role checks, both current floor checks and 16 plain-JSON refusals passed. The
actual 28-member smoke closure again passed ten before-import negative controls
and the maintained import-only preflight using system Node `22.22.2`. No
embedded Node, GUI or released application execution occurred. Previous
evaluation artifacts remain retained; fresh source hashes and results are
recorded separately for the second independent review. Scoped
`git diff --check` passed.

Current RPM preservation policy/floor callsite wiring and full hosted native
qualification remain held as described above. These corrections establish no
publication completion.
