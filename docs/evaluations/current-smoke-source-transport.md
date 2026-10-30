# Current container smoke source transport

Status: bounded source transport integration evaluated; native qualification and
publication remain held. Base: accepted source commit `8251969`.

## Boundary correction

The current parent preparation retains real live Nebular and Burst captures.
`verify_source_readback` and `export_current_source_readback` still require those
captures and exact current identities. Serialized prepared dictionaries, including
guest dictionaries with a source-only proof, cannot pass these parent gates.

The fixed current 28-file/producer/role/hash checks now live in a pure verifier.
It reads only the closed source file set using bounded, regular-file, no-follow
reads. Expectations remain source-owned in `hosted_smoke.py`; no release capture
is reconstructed from JSON and no caller configuration JSON is needed in the
guest.

After parent live authentication and readback, export emits a closed bounded
`rs9.current-smoke-source-readback.v1` envelope. It contains the exact generation,
fixed Nebular/fixture producers, importer `tools`, closed source records and
their digest. Its authority block explicitly states:

```json
{
  "scope": "source-readback-only",
  "release_authentication": false,
  "configuration_authority": false,
  "profile_authority": false,
  "publication_authority": false
}
```

The guest explicitly validates the envelope against fixed code expectations and
physical source files before creating an internal source-readback-only proof.
Import preflight accepts that proof only through the explicit container source
path. The proof is not a `ReleaseCapture` and cannot satisfy release,
configuration or profile APIs. Plain serialized prepared dictionaries do not
receive this treatment automatically.

## Request, wrapper and acceptance bindings

Current requests include the envelope in their canonical request bytes and SHA.
The parent passes the exact expected request SHA in the guest invocation. Current
guest request validation requires that digest, canonical bytes and the closed
request schema before source verification or import. Removing the envelope does
not permit a current invocation to select the historical transport path.

The guest preserves UID validation and verifies the exact two source-owned
wrapper files, their hashes and content. Request substitutions are refused
before import. Source and input mounts remain read-only; only the existing
output mount is writable.

Current output includes the envelope digest. Before dispatch and again before
acceptance, the parent rechecks its original live prepared object, the exact
stored request bytes and input file, exported envelope, expected member data and
wrapper files. Acceptance also compares the output envelope digest and retains
the existing receipt, sidecar, scenario sequence and scenario hash checks.

Historical request/output shapes and the default guest invocation are unchanged.
Nix and PRoot continue using live parent preparation and require no serialization
API.

## Two filesystem roles

Imported verifier modules remain rooted in the original read-only guest source
tree. The released harness still receives its separate writable checkout for
fixture work. Checkout readback rebases both `source` and `tools` to that copy;
it does not change the original importer roots or reuse their path-bound proof
for a different root. Current source records and fixed file hashes are checked
before and after the existing runtime/scenario path, preserving fixture and
state assertions.

## Observed verification

```sh
PYTHONPATH=src:tests python3 -m unittest \
  tests.test_current_smoke_source_transport \
  tests.test_sidecar_harness_closure tests.test_hosted_container_smoke \
  tests.test_hosted_smoke tests.test_nebular_callers tests.test_rpm_lint_policy
```

Result: **114 focused checks passed**. Seven new source-only fixture tests cover
real JSON serialization/deserialization, explicit guest source proof creation,
parent live-capture refusal, release/configuration/profile authority refusal,
missing/extra/duplicate/hash/role/producer/importer/symlink envelope substitutions,
request and wrapper substitutions before dispatch/import, checkout root
rebasing, output digest substitution and scenario/receipt substitution. Existing
historical container and scenario assertions remain passing. The new current
fixtures substitute controlled source/asset pins; they do not qualify released
native packages.

A separate actual-custody check reauthenticated the retained published captures,
prepared the exact 28 public source files with real fixed expectations, exported
the canonical current request and validated its JSON in a separate Python
process. No pin table was replaced in that check. Guest source verification
passed without loading the checkout-only caller JSON. Five attempted authority
escapes were refused: both parent live-auth gates and release, configuration and
profile APIs. The original parent live object and exact request/envelope were
then rechecked successfully.

No Docker, Nix, installed product, GUI, embedded Node or released JavaScript was
executed by the actual-custody transport check. Existing non-native fixture
tests exercise the maintained harness with synthetic source only. Scoped
`git diff --check` passed. Exact resulting file hashes and private check results
are retained separately for independent review.

## Remaining limitations

This is source transport/readback evidence, not release authentication by an
envelope and not installed-client qualification. Real mount isolation, effective
UID, disconnected runtime execution, GUI/caller behavior, cleanup and resulting
native package acceptance still require public hosted qualification. No
dependency, runner-policy, workflow, installed-state or publication change was
made. No universal-wheel/package data was added; parent live caller selection
retains its existing checkout-only configuration route.

## Review correction evidence

The narrow first external review's two questions were investigated without
loosening the closed source or checkout file set. The real
`application_smoke_diagnostic._command` supplies the checked checkout as an
input and supplies the scratch evidence directory separately. Its actual
`execute_application_smoke` orchestration contains no live-capture gate.
The tagged `native-rc-smoke.mjs` creates a temporary smoke directory, then
`prepareFixtures` copies the maintained checkout fixture into
`smokeDir/fixtures`; `copyProject` and `deriveProject` modify only those copies.
The checkout is not the fixture output directory.

An additional pure run imported only the actual published `prepareFixtures`
export under the system Node runtime, using all 28 fixed source members and
the published fixture bytes. Scenario A completed. B, C and C-signal correctly
refused this host's case-insensitive filesystem before copying their projects.
The original source and separate checkout inventories were identical before
and after all four attempts, and closed readback passed. This is bounded
filesystem evidence; successful B/C fixture preparation on a case-sensitive
filesystem and native execution remain unqualified. No arbitrary checkout
extra files or symlinks are permitted.

A committed test now calls the real `verify_nebular_runtime` with the
serialized/deserialized guest proof and runtime-member manifest. Only
`_run_verifier` and the application scenario subprocess seam are controlled.
The real preflight checks the read-only wrapper bytes, original source/tools
URIs and source CWD; the real runtime verifier consumes expected members
without a capture; the real application orchestration validates controlled
receipt bytes for C and C-signal. Changing the preflight wrapper bytes refuses
before either child seam. These tests use synthetic unit pins and static
runtime bytes; the separate actual-custody helper run uses the fixed published
source pins. Neither constitutes native qualification.

The shared pure expectations again enforce the fixed import-table/closure
self-consistency assertion. This assertion does not independently parse or
enforce every documented import edge. Guest proofs refuse dictionaries that
also contain either live-capture key. The default guest invocation now has an
explicit current-request refusal regression. Failure outputs preserve the
guest code and safe details when the envelope digest is absent or exact;
successful outputs still require the exact digest.

Result after corrections: **116 focused checks passed** using the same six
test modules listed above. The prior reviewed postimages are retained intact;
fresh delta hashes, before/after inventories, helper results and a read-only
copy of `application_smoke_diagnostic.py` are retained for the next independent
review. No source change to that orchestration module was required.
