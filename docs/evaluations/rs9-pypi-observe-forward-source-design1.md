# RS9 PyPI observe lane: forward-only source correction

## Status

Accepted as the implementation contract for the bounded S1a work. This is a design only. No source, test, configuration, approval,
manifest, workflow or receipt is changed by this document. Implementation,
tests and hosted qualification belong to later, separately reviewed stages.

## 1. Context and cause

The hosted observe lane (`src/rs9/hosted_observe.py`) records one PyPI
observation per product. All four products currently classify as `conflict`
with the diagnostic `conflict-ownership-unattested`. A retained observation
receipt produced from the current source shows the mechanism exactly:

- `hosted_observe.execute` calls `read_pypi_project(project, version)`
  (`hosted_observe.py:310`). `version` is the application (upstream) version
  from the intent: Burst `0.6.1`, Loom `0.4.0`, Solar `0.2.1`, Nebular
  `0.6.1`.
- The call passes no expected file map. `_normalize_reader_target`
  (`readers.py:84-92`) synthesizes `desired_identity = "0" * 64` and
  `expected_hashes = {<project-name>: "0" * 64}`.
- PyPI has a release at every one of those application versions. The receipt
  records two files each (one Darwin wheel and one sdist) for the three
  first-wave projects and one Darwin wheel for Nebular. `read_pypi_project`
  (`readers.py:249-273`) builds the real filename-to-SHA-256 map. That map
  cannot equal the synthetic one-entry map, so the reader emits a
  metadata-level readback with `content_identity_sha256: null`.
- `classify_observation` (`observation.py:44`) classifies the observed
  filenames, none of which is in the expected map, as `conflict`.

The conflict is therefore produced by the observer's own construction. It is
not a remote byte conflict, and it says nothing about ownership. Two facts are
wrong in the current call:

1. **Subject.** For the first wave, the approved PyPI distribution is not the
   application version. `src/rs9/tf_pypi_model.py:15-19` maps
   `0.6.1 → 0.6.1.post1`, `0.4.0 → 0.4.0.post1` and `0.2.1 → 0.2.1.post1`. The
   older application-version releases coexist on PyPI and are not observation
   targets.
2. **Expectations.** No approved file set, size, digest or byte check is
   supplied, so no answer other than `conflict` or `unknown` is reachable.

An earlier read-only registry audit, recorded outside this repository, found
that each first-wave `.post1` release lists exactly the four files of its
committed approval, and Nebular `0.6.1` its one file. The match covered
filename, size and SHA-256. That audit is prior context. It is not an
observation made by this design or by the lane, and no fresh registry read
was made while preparing this document.

The Nebular distribution that is currently published and immutable is `0.6.1`,
one Darwin ARM64 wheel (`operators/tf-pypi/theme-forge-nebular-fusion-artifacts.json`).
The successor `0.6.1.post1` (`src/rs9/tf_pypi_nebular_successor.py`,
`src/rs9/wheel_nebular_successor.py`) is an unpublished candidate:
`can_publish`, `publication_admitted` and `manylinux_proven` are all false,
and its Linux admission is unresolved. The observe lane must not switch to it,
and its absence from PyPI must never be reported as a remote conflict.

## 2. Four separate facts

The correction keeps four facts separate. No one of them implies another.

| Fact | Established by | Does not establish |
|---|---|---|
| **Byte exactness** | Every remote file of the exact distribution version equals the committed approved filename, size and SHA-256 set. Downloaded bytes hash to the approved digests. Nothing is missing, surplus, duplicated or yanked. | Source lineage, ownership, or authority to upload. |
| **Source lineage** | The approved bytes embed historical commit identities. Those identities are bound to the current authenticated release by four things together: an equal tree, exact pins in the historical manifest, an authenticated release-asset byte binding, and an explicit, reviewed historical-to-current record. | That the current commit object built the bytes, or who uploaded them. |
| **Observed publication** | One authenticated live read, made at a single point in time inside the run that reports it. | That the release persists afterwards (it could be yanked or deleted later). Earlier audits are context only. |
| **Ownership authority** | Out of band only: the project owner and the PyPI Trusted Publisher binding, confirmed by the operator. | Nothing from PyPI JSON or byte equality can establish it. In this lane ownership is always `unattested`, even when the observation is `exact`. |

Exact bytes never grant upload authority. The projection introduced here
exposes no upload operation. Nothing in `tf_pypi_publish.py`, the workflows,
or the admission records consumes it.

## 3. Minimal owners

| Path | Change |
|---|---|
| `config/forward/pypi-observe/v1alpha1/projection.json` (new) | A closed, canonical record with four rows. `src/rs9/pypi_observe.py` pins its reviewed digest as a constant, in the same way `FORWARD_RECORD_SHA256` pins the Nebular lineage record. |
| `src/rs9/pypi_observe.py` (new) | Record validation; typed `PypiProjection`, constructed only inside the module, following the token pattern of `ForwardLineageProof`; the observer-only first-wave lineage binding; reuse of Nebular lineage; parsing of embedded provenance. |
| `src/rs9/tf_pypi_remote.py` | Behavior-preserving extractions plus one new observer function, `approved_state` (§5.1). `PublicReader`, `project_state` and `exact_state` keep their signatures and results. |
| `src/rs9/readers.py` | New `read_pypi_distribution(projection, *, fetch=None)` and `READERS["pypi-distribution"] = "v1alpha1"`; a bounded fetch adapter that keeps closed TLS and transport tokens. `read_pypi_project`, `read_pypi` and the string-target zero synthesis are unchanged, because `src/rs9/hosted_foundation3.py:271` and existing tests use them. |
| `src/rs9/hosted_observe.py` | Builds the projection per capture; replaces line 310; removes the `read_pypi_project` import; for PyPI, `readback_satisfied` becomes `state == "exact"`; each PyPI row carries projection facts, `ownership` and `upload_authority` in the separately validated hosted-row envelope. The closed destination observation remains unchanged. |
| `tests/test_pypi_observe.py` (new) | Record, trust-input, lineage and provenance tests. |
| `tests/test_tf_pypi_remote.py` | Tests for `approved_state`. The existing tests stay unchanged. |
| `tests/test_readers.py` | `read_pypi_distribution` and fetch-adapter tests. |
| `tests/test_hosted_observe.py` | Updated wiring and semantics (§8.6). |

The following stay unchanged:

- **Records and approvals:** the first-wave pins (`operators/tf-pypi/<project>.json`) and every `operators/tf-pypi/*-artifacts.json`.
- **Bootstrap and expectations:** both bootstrap manifests and `operators/live1/expectations.json`.
- **Nebular lineage:** `config/forward/theme-forge-nebular-fusion/v0.6.1-lineage/reconciliation.json` and `src/rs9/nebular_lineage.py`.
- **Lane contracts:** `operators/live1/hosted-lanes.json` and the gate names.
- **Other surfaces:** workflows, dependencies, versions, admission flags, and every historical receipt.

**Nebular closure digest.** Adding to `tf_pypi_remote.py` changes the
`closure_files_sha256` that `tf_pypi_nebular.py:1918` reports, because the
module is in that import closure. Nothing committed compares against that
value; its test only asserts the format (`tests/test_tf_pypi_nebular.py:1867`).
The approval's `verifier_closure.records_sha256` hashes upstream Nebular
source rows, not RS9 source, so it is unaffected.

## 4. Projection record and trust inputs

### 4.1 Record schema

Every field is required and the record is closed. Rows are sorted by
`project`, and the file bytes must equal their own canonical serialization.

```text
schema: "rs9.pypi-observe-projection.v1alpha1"
reason: "observer-only application-to-distribution projection;
         grants no upload, ownership or lineage authority outside this lane"
historical_manifest: {path: "bootstrap/pre-rs9/theme-forge-live1/manifest.json", sha256}
current_manifest:    {path: "bootstrap/pre-rs9/theme-forge-live1/manifest-author-aligned.json", sha256}
rows: exactly four, one per product
  project
  application:   {repository, repository_id, release_id, tag, version}
  distribution:  {name, version,
                  kind: "tf-npm-aggregate" | "nebular-native-wheel",
                  approval_path, approval_sha256, set_sha256}
  lineage:       {basis: "observer-equal-tree" | "nebular-forward-lineage",
                  tree_relation_basis: "reviewed-record",
                  current: {commit, tree}, historical: {commit, tree}}
  binding_asset: {name, github_asset_id, size, sha256}
  intake:        {pin_path, pin_sha256}   (tf-npm-aggregate only; null for Nebular)
```

**`set_sha256` differs by kind.** Each value is recomputed with that kind's own
existing rule:

- `tf-npm-aggregate`: `sha256(canonical(files))`, as in `tf_pypi_verify.py:211`.
- `nebular-native-wheel`: `compute_set_sha256(doc)` (`tf_pypi_nebular.py:152-159`),
  which is the digest of the canonical document without `publication_admitted`
  and `set_sha256`.

**Desired identity.** Each row has a desired identity:
`sha256(canonical({"schema": "rs9.pypi-distribution-identity.v1alpha1", project,
application_version, distribution: {name, version}, approval_sha256,
set_sha256, files: {filename: sha256}}))`. Here `files` is the approved
filename-to-digest map.

**Supersession.** The record is never followed automatically. Any of these
changes needs a new reviewed record version and a new pinned digest in the
module:

- a new admitted distribution, such as a future `.post2`;
- publication of Nebular `0.6.1.post1`;
- a change to any approval byte.

The lane observes only what the pinned record names. It does not search for a
later version.

### 4.2 Identity table

This table was reconciled against the retained receipt reconciliation, and it
matches the current repository sources. Those sources are the pins, both
manifests, `operators/live1/expectations.json`, the approvals and
`nebular_lineage.py`. The digests of the approvals, pins and observer sources
recorded at the time of the receipt equal their bytes at this revision.

| Product | Release ID | Historical → current commit | Shared tree | Binding asset (ID / size) | Distribution |
|---|---|---|---|---|---|
| Stellar Burst | 399542205 | `a3e89683…` → `9f0bb67a…` | `158bd6d0…` | npm tgz 599265851 / 644313 | `0.6.1.post1` |
| Stellar Loom | 399542451 | `d6f3cc45…` → `85e42645…` | `9388e305…` | npm tgz 599266537 / 273462 | `0.4.0.post1` |
| Solar Sail | 399542664 | `68e3f95a…` → `17883c16…` | `35a865bd…` | npm tgz 599267369 / 110658 | `0.2.1.post1` |
| Nebular Fusion | 400494635 | `49e2c491…` → `75bc4125…` | `203a80b3…` | Darwin app archive 601953438 / 47079690 | `0.6.1` |

The record carries the full 40- and 64-character values.

### 4.3 Validation

All validation runs offline, before any network read. Any failure raises a
`ContractError` with one of the codes below, and no observation is emitted.
`hosted_observe.read_destination` already re-raises a `ContractError` as a
lane failure. A broken trust input is a lane error, never a remote conflict.

**`PYPI_PROJECTION_RECORD`:**
- the record bytes are canonical and match the pinned digest;
- the fields are closed and there are exactly four rows;
- the paths are safe and relative.

**`PYPI_PROJECTION_SCOPE`:**
- the intent project and the application version select exactly one row;
- Nebular selects only distribution `0.6.1` with kind `nebular-native-wheel`;
- a request for the successor version, or for any version not named in the record, is refused.

**`PYPI_PROJECTION_CAPTURE`:**
- `authenticated_record_hash(capture)` succeeds, which proves a fresh in-process `ReleaseCapture`;
- the repository full name and ID, the release ID and tag, and the tag commit and tree equal `application` and `lineage.current`;
- `authenticated_tree(capture)` returns `sha == lineage.current.tree` with `truncated is False`;
- `binding_asset` equals exactly one row of `capture.record["assets"]` and its `capture.asset_metadata` entry, matched by name, `github_asset_id`, size and SHA-256.

**`PYPI_PROJECTION_LINEAGE`, every row:**
- both manifest digests match the record;
- the historical manifest row has `tag_commit == lineage.historical.commit` and `tag_tree == lineage.historical.tree`;
- the current manifest row has `tag_commit == lineage.current.commit`, with the same tag, release ID and tree;
- the commits differ and the trees are equal.

**`PYPI_PROJECTION_LINEAGE`, first wave:**
- `pin.source_commit == lineage.historical.commit`;
- `pin.asset`, `pin.size` and `pin.sha256` equal `binding_asset`.

**`PYPI_PROJECTION_LINEAGE`, Nebular:**
- `select_forward_lineage_proof(repository, capture, intent)` returns a proof, and `verify_forward_lineage_proof` succeeds;
- the proof facts equal `profile["sections"]["forward_lineage"]`;
- the proof's commits and tree equal the row;
- in the approval's `authentication.nebular`: `tag_commit` and `tag_tree` equal `lineage.historical`, and the repository and tag equal `application`;
- `authentication.bootstrap_sha256` equals the historical manifest digest;
- `authentication.stellar_fixture` agrees with the historical Burst row (consistency only);
- `payload_asset` (`github_asset_id`, name, size and SHA-256) equals `binding_asset` and appears in the lineage proof's asset inventory. The comparison uses `github_asset_id`, never `payload_asset.id`, which is the platform label `darwin-arm64`.

**`PYPI_PROJECTION_APPROVAL`:**
- the approval and pin bytes match the recorded digests;
- **first wave:**
  - `validate_pin(pin)` passes and `pin.source_status` is ready;
  - a closed aggregate check passes: schema `rs9.tf-pypi-candidate-aggregate.v1`, version is `pin.distribution_version`, `upstream_version` is `pin.version`, targets are `TARGETS`, and `publication_admitted is True`;
  - the recomputed `set_sha256` matches;
- **Nebular:** `validate_approval_schema` passes, `publication_admitted is True` and `builder_can_publish is False`.

**Equal trees are never enough on their own.** The asset byte binding and the
exact historical-manifest pins are always required as well.

**Import isolation.** `pypi_observe.py` imports `tf_pypi_nebular` lazily, only
inside the Nebular branch. That keeps `rs9.candidate`, `rs9.operator` and
`rs9.hosted_commands` out of the import graph of `rs9.readers`. `readers.py`
imports `pypi_observe` and `tf_pypi_remote` inside `read_pypi_distribution`,
matching its existing in-function imports. Neither `tf_pypi_remote` nor its
`tf_pypi_*` dependencies import `readers`, so no cycle is introduced.

The lazy import still ties every Nebular observation to the full import graph
of `tf_pypi_nebular`, which is large, for only two pure functions
(`validate_approval_schema` and `compute_set_sha256`). This is accepted for S1b
because copying them would create a second schema authority. If that import
cost or coupling proves material, a later behavior-preserving change may move
the two functions into a small module that `tf_pypi_nebular` re-exports. The
observer must never hold a private copy.

**What a projection grants.** The result is a `PypiProjection`. It exposes
only public facts and its desired identity. Holding one grants nothing outside
`read_pypi_distribution`. It is not merged into a destination observation,
readback, diagnostic or publication receipt.

### 4.4 Hosted-row envelope

The PyPI row emitted by `hosted_observe` is a separately validated, closed
hosted-row envelope. Its fields are `project`, `adapter`, `mode`,
`observation`, `projection_facts`, `ownership` and `upload_authority`. The
`observation` field is the unchanged `rs9.destination-observation.v1alpha1`
record produced by `observation.observe`; its closed `readback`, `diagnostics`
and serialized observation keys are not extended. `projection_facts` is the
public serialized projection and desired identity from §4.1, without a capture
object, authentication token, raw file body or upload operation. `ownership` is
a closed object whose state is exactly `unattested`, and `upload_authority` is
exactly `false`. Unknown or arbitrary keys in this envelope fail closed.

## 5. Remote contract

### 5.1 Reuse in `tf_pypi_remote.py`

The extractions below are behavior-preserving. Existing callers keep their
results, and their check order is unchanged:

- `_project_state_for(project, dv, get)` holds the body of `project_state`. `project_state(pin, get)` keeps `validate_pin` and delegates to it.
- `_version_rows_for(project, dv, get)` holds the body of `_version_rows`, which delegates to it.
- `_checked_row(row, approved)` takes the checks of `_verified_file` in their existing order: filename in the set; `yanked is False`; `size` is an int; `(size, digests.sha256)` equals the approved pair; `_public_url(url, {"files.pythonhosted.org"})`. `approved` maps each filename to `(size, sha256)`. `_verified_file` builds that map from its local bytes, calls `_checked_row`, and keeps its own byte comparison.

**Carrying the cause without changing the legacy exception.** The existing
helpers collapse every cause into one code: `_verified_file` and `_version_rows`
raise `REMOTE_CONFLICT` for all conflicts, and `project_state` returns a bare
"conflict" for both a project name mismatch and a normalized version collision.
The per-cause codes in §6 cannot be derived from those results. The extracted
helpers therefore report a closed cause token alongside the state.

The implementation uses a private `_ObserverAdmissionError` subclass in
`tf_pypi_remote.py` only. It calls the existing `AdmissionError` initializer
with the same sanitized code and stores `cause` from the closed set below. It
does not override `.code`, `__str__` or `__repr__`; the inherited code-only
surface remains unchanged, and the cause is never serialized or copied from a
URL, response, exception text or payload. Only the new observer helpers may
construct this subclass.

- `_project_state_for` returns `(state, cause)`. The causes are
  `project-name-mismatch`, `version-normalization-collision`,
  `metadata-schema`, `project-absent`, `version-absent` and `transport`.
- `_version_rows_for` and `_checked_row` raise `_ObserverAdmissionError` with
  the existing code and a closed `cause` attribute. The causes are
  `version-identity-mismatch`, `surplus-file`, `file-yanked`,
  `file-changed`, `metadata-schema` and `file-host`.

The legacy wrappers ignore the cause. `project_state` returns only the state;
`_version_rows` and `_verified_file` preserve the same `AdmissionError` code,
check order and observable failure behavior. Their results, codes and check
order are unchanged, and the regression tests in §8.4 assert this. Only
`approved_state` reads the cause. The wrappers may re-raise the private
subclass because it is still an `AdmissionError`; its inherited string and
representation remain identical. They must not expose or serialize `cause`.
For the observer, `metadata-schema` (a row that is not an object, or a
missing or ill-typed `yanked`, `size` or `digests` field) maps to `unknown`,
not `conflict`. The legacy publish-time result for those rows is unchanged.

New function:

```text
approved_state(project, distribution_version, approved, fetch) -> dict
  approved: {filename: (size, sha256)} from the validated projection
  fetch(url, limit) -> bytes: returns only a complete body of at most limit
      bytes; it may read at most limit + 1 to detect an overrun, then raises
      the private AdmissionError with REMOTE_ABSENT only for a 404 at the exact
      requested URL and REMOTE_UNKNOWN otherwise
  returns {"state", "code", "observed": {filename: sha256}, "missing": [...],
           "bodies": {filename: bytes} only when state == "published-exact"}
```

`approved_state` runs these steps in order:

1. **Project and version state.**
   - Run `_project_state_for` with a JSON getter bounded to 32 MiB.
   - This covers name equality, collision of normalized versions, presence of the exact `dv` key, and the probe of the version URL.
   - It never reads `info.version` (the latest release), so there is no fallback to the latest version.
   - The application-version release and the `.post1` release coexist without colliding: `_normalize_version` keeps `0.6.1` and `0.6.1.post1` distinct.
2. **Exact version endpoint.**
   - Run `_version_rows_for`.
   - `info.name` and `info.version` must equal the request.
   - The `urls` list must be non-empty.
   - If the project listing named the version but the version endpoint
     returns 404, the remote is inconsistent. The result is `unknown`, never
     `absent`.
3. **Per-file metadata.**
   - Run `_checked_row` on every row before any download.
   - Duplicate filenames are a conflict.
4. **Download.**
   - Each file is read with `limit = approved size`. The size bound is per file. This replaces the fixed 32 MiB `PublicReader` cap, which the 46,792,720-byte Nebular wheel exceeds.
   - The adapter may read at most `limit + 1` bytes to detect an overrun, but it returns only a complete body of at most `limit` bytes. A body that exceeds the approved bound is a bounded transport failure with the closed `limit` token and maps to `unknown`; it is never treated as downloaded content or as a byte conflict.
   - A complete body of the approved length with a different SHA-256 is a conflict (`pypi-bytes-differ`). A complete body shorter than the approved size is also a conflict when EOF or a shorter `Content-Length` proves that the bounded body is complete. A short transfer relative to its declared `Content-Length`, an incomplete response, or a protocol failure is `unknown`.
5. **Completeness.**
   - Approved files that are not listed remotely produce `incomplete`, with their names in `missing`.

**Nebular semantics.** `tf_pypi_nebular.NebularPublicReader`,
`tf_pypi_nebular.project_state` and `tf_pypi_nebular.exact_state`
(`tf_pypi_nebular.py:1404-1512`) already provide an approved-size file bound,
but with publication-guard semantics: a present project without `VERSION` is a
`conflict`, and there is no probe of the version URL. That is the right choice
for deciding whether to upload, because an unexplained state there must stop
the upload. It is the wrong choice for an observer, which must not label
absence as conflict. `approved_state` therefore applies the first-wave
semantics to all four rows: a missing version gives `version-absent`. The
Nebular functions are neither superseded nor called by the observer; they
remain the publish-time contract. The observer reuses only `_public_url`,
`_normalize_version` and the extracted first-wave checks.

### 5.2 Fetch adapter in `readers.py`

`read_pypi_distribution` constructs a per-call adapter that implements
`fetch(url, limit)`.

**Request discipline.** It uses the same rules as `readers._get`:
- HTTPS only;
- fixed host sets: `pypi.org` for JSON and `files.pythonhosted.org` for files;
- no proxy, no redirect, credential scan and a 20-second timeout.

**Failure tokens.** Before raising, the adapter appends one closed token to
its own list:

| Failure | Token |
|---|---|
| HTTP error | `http-<status>` |
| TLS failure | `tls-<classify_tls_error(error)>`, with `extract_tls_verify_code` kept as a bounded integer |
| timeout | `timeout` |
| redirect | `redirect` |
| URL outside authority | `url-authority` |
| response over its bound | `limit` |
| credential found in the URL | `credential-scan` |
| `http.client.HTTPException`, including `IncompleteRead` and a bad status line | `protocol` |
| response not complete (below) | `incomplete-body` |
| other `URLError` or `OSError` | `transport` |

`HTTPException` is not an `OSError`, and `PublicReader` does not catch it
today. The adapter catches it explicitly. `readers._reader_failure` already
classifies it separately, and the adapter follows that precedent.

**Complete response and size bound.** `http.client` returns short data from
`read(n)` without raising when the connection closes early. The adapter
decides completeness mechanically and never returns an over-bound body:

- if `Content-Length` is present and no greater than `limit`, exactly that many
  bytes must be read and one further read must return no data; a declared length
  below `limit` is a complete short body and may be compared by `approved_state`;
- if `Content-Length` is absent, the adapter reads until end of stream within
  `limit + 1` bytes; an EOF body at or below `limit` is complete and may be
  compared, including when it is short;
- if the declared length is greater than `limit`, or `limit + 1` bytes are
  observed, the adapter records the closed `limit` token and raises
  `REMOTE_UNKNOWN`; the body is not returned and the observer reports
  `unknown`;
- if a declared transfer ends before its declared length, the adapter records
  `incomplete-body` and raises `REMOTE_UNKNOWN`; a protocol exception follows
  the same unknown path.

Anything else is `incomplete-body`, which becomes `unknown`. This preserves a
conflict only for a complete bounded body whose size or SHA-256 differs from
the approved pair.

**Two kinds of `ContractError`.** The adapter and `read_pypi_distribution`
keep them apart:

- Request-discipline failures raised while reading (URL authority, redirect,
  limit, credential scan) become tokens and then `unknown`, as above.
- Trust-input failures (every `PYPI_PROJECTION_*` code, including
  `PYPI_PROJECTION_PROVENANCE`, which is raised after a download) are never
  caught by the reader. They propagate to `hosted_observe.read_destination`,
  which re-raises them as a lane failure. The existing readers catch
  `ContractError` into a diagnostic. `read_pypi_distribution` must not copy
  that broad `except` around its trust-input steps.

**What it raises.** After recording the token, the adapter raises the existing
`AdmissionError` codes (`REMOTE_ABSENT` or `REMOTE_UNKNOWN`). `REMOTE_ABSENT`
is raised only for a 404 whose error URL equals the requested URL; a 404 at
any other URL is `REMOTE_UNKNOWN`. The existing single-argument `get(url)`
injection used by `project_state` and `exact_state` is untouched.

**Diagnostics.** `read_pypi_distribution` turns the first token into a
diagnostic. The text of the exception and of the response is never retained,
which matches `_reader_failure`.

### 5.3 Embedded provenance

Exactness requires the provenance check. It runs only on bytes already
verified against the approved digests, and it checks the historical records
the bytes were built from. It does not run current-source builders.
`tf_pypi_publish.verify_approved` and `tf_pypi_nebular.inspect_candidate` are
excluded deliberately: they rebuild with today's backend and need local
distribution files. Once SHA-256 equality is proven they add nothing about the
remote, and they would tie the observation of immutable bytes to today's
builder code.

**First-wave wheel** (built by `tf_pypi_backend.py:108-111, 142-168`). A
bounded ZIP read must find:
- in `METADATA`, `Name` and `Version` equal to the distribution;
- `Project-URL: Source` ending in `/tree/<lineage.historical.commit>`;
- `Project-URL: Release` ending in `/releases/tag/<application.tag>`;
- `rs9-tf-transform.json` with `target_key` in `TARGETS`, matching the wheel's platform tag, and `source_sha256 == pin.sha256 == binding_asset.sha256`;
- for Burst, `dependencies` equals `{dep.asset: dep.sha256}` over the pin's dependency entries; for Loom and Solar, whose pins list no dependencies, `dependencies` is exactly `{}`.

**First-wave sdist** (`tf_pypi_backend.py:234-243`). A bounded tar read must
find:
- `upstream/<pin.asset>`, with bytes whose size and SHA-256 equal `binding_asset`;
- `_rs9_build/rs9/pins.json`, whose bytes equal `canonical(build_pin(pin))`. `build_pin` (`tf_pypi_model.py:90-92`) is a pure projection of the pinned pin bytes.

**Nebular wheel** (`tf_pypi_nebular.py:788-806`). The member table must equal
`approval.members`. `_rs9/provenance.json` must have:
- the expected `schema`, `product_id`, `distribution_name`, `version` and `wheel_tag`;
- `release_record_sha256` equal to the historical value in `approval.authentication.nebular`. It is compared with that approval value, never with the current capture's record hash;
- `payload_archive_sha256 == binding_asset.sha256`;
- `manifest_sha256 == approval.payload_asset.payload_manifest_sha256`;
- `helper_source_sha256 == approval.embedded_helpers`;
- `fixture_only`, `candidate_only` and `can_publish` all `false`.

**A provenance failure is a lane error.** If provenance fails on bytes whose
digests match the approval, the trust inputs contradict each other. The result
is a `PYPI_PROJECTION_PROVENANCE` contract error, not a remote conflict.

## 6. Outcome taxonomy

`read_pypi_distribution` maps each outcome onto the states in `observation.py`,
reported under the reader `{"id": "pypi-distribution", "version": "v1alpha1"}`.
The subject is `{package: distribution.name, version: distribution.version}`;
the application version appears only in the projection facts.

| Remote outcome | State | Readback | Diagnostic code |
|---|---|---|---|
| exact set, bytes and provenance verified | `exact` | `level: full`, components = approved map, identity = desired identity | `pypi-distribution-exact` |
| project 404 at the exact URL | `absent` | `presence: absent`, no components, identity null | `pypi-project-absent` |
| version 404, project present | `absent` | as above | `pypi-distribution-version-absent` |
| approved file not listed | `incomplete` | the listed matching components, **identity null** | `pypi-file-missing` |
| surplus file, changed size or digest, yanked, duplicate, wrong info/wrong version/version collision, or a complete bounded body whose size or SHA-256 differs from the approved pair, project-listing name mismatch, wrong version-endpoint `info.name` or `info.version`, normalized version collision | `conflict` | observed components plus a conflict identity | one closed code each: `pypi-surplus-file`, `pypi-file-changed`, `pypi-file-yanked`, `pypi-duplicate-file`, `pypi-bytes-differ`, `pypi-project-name-mismatch`, `pypi-version-identity-mismatch`, `pypi-version-normalization-collision` |
| non-404 HTTP, 404 at a different URL, TLS, timeout, transport, `HTTPException`, incomplete or short declared transfer, body over the approved bound, redirect, oversize JSON, JSON or per-file schema failure, foreign file host, file 404, version 404 after the project listed the version | `unknown` | `transport: unknown` | `pypi-transport-unknown`, `pypi-tls-<token>`, `pypi-protocol`, `pypi-incomplete-body`, `pypi-limit`, `pypi-metadata-schema`, `pypi-file-host-unknown`, `pypi-version-inconsistent` |

**Rules behind the table:**

- **`incomplete` carries a null identity.** Otherwise `observation.py:42` would turn a missing file into `conflict`.
- **The conflict identity is computed, not a sentinel.** It is `sha256(canonical({"conflict": code, "observed": observed}))`. This digest cannot equal the desired identity, which has a different schema, so no `"f" * 64` sentinel is needed. When an approved name is observed with a different digest, the observed digest appears in `components`.
- **Unknown is never absence.** `unknown` is never satisfied and never reported as `absent`.
- **Absent is never conflict.** `absent` is never satisfied for these four rows, because each one binds an admitted, published distribution. It is still reported as `absent`, with its own diagnostic code.
- **Ownership is not a state input.** It never affects any state.

## 7. Lineage reconciliation

The source histories were reconciled by correcting author metadata. Each
product's release commit changed while its tree did not. The approved,
published distribution bytes embed the historical commits. The current
authenticated captures carry the current ones. The repository already records
both sides:

- `bootstrap/pre-rs9/theme-forge-live1/manifest.json` is byte-identical and holds the historical commits.
- `manifest-author-aligned.json`, which `src/rs9/operator.py:19` selects, holds the current commits with the same trees, release IDs and assets.

**Nebular.** Nebular reuses `src/rs9/nebular_lineage.py` without change. Its
proof binds the current capture (`75bc4125…`) to the historical commit
(`49e2c491…`) through:

- the reviewed record `config/forward/theme-forge-nebular-fusion/v0.6.1-lineage/reconciliation.json`;
- the thirteen-asset authenticated inventory;
- the publisher assertions in the reviewed `PROVENANCE.json` asset.

Its `tree_relation_basis` is `reviewed-record`.

**First wave.** The first-wave rows use an observer-only equal-tree binding.
It follows the field discipline of the Nebular proof, with these limits:

- It is not a `ForwardLineageProof`. It is never passed to profiles, candidates or operator code, and it changes no authentication or bootstrap authority.
- It records `tree_relation_basis: "reviewed-record"`. The historical tree comes from the committed historical manifest. The historical commit object is not read live, so this binding is not a live verification of the old commit.
- The first-wave products have no reviewed `PROVENANCE.json` asset that could carry publisher assertions. In its place the binding uses the authenticated npm release tarball, whose bytes must equal the pin's `asset`, `size` and `sha256`. The pin's `source_commit` must equal the historical manifest commit, and the published wheels and sdists must embed that same commit and asset digest (§5.3).

**What stays untouched.** Old approvals, pins and manifest bytes are never
changed. Nothing is rebuilt or republished. The current Nebular `0.6.1` record
is observed only as that historical distribution. The successor kernel and
adapter are a separate, unpublished candidate that this lane does not
reference.

**An evidence recommendation not adopted.** The retained reconciliation
suggests observing Nebular at `0.6.1.post1`. This design does not adopt that
suggestion. That version is not published or admitted, so observing it would
turn a candidate's absence into a lane failure for the published distribution.
Switching the lane to the successor requires a new projection record version
after the successor is admitted and published (§4.1).

## 8. Test matrix

All tests run offline. They use injected `fetch` callables and authenticated
fixtures, and they make no registry mutation.

### 8.1 Record and scope (`tests/test_pypi_observe.py`)

- **Static reconciliation.** The committed record is checked against the real pins, approvals, both manifests and the lineage record, with no network and no capture.
- **Record failures:** altered bytes, non-canonical bytes, an extra or missing field, a missing row, or a fifth row.
- **Scope refusals:** a Nebular `0.6.1.post1` request, an unknown project, an application version that does not select a row, or a kind that does not match the product.

### 8.2 Capture and lineage

**Capture fixtures.** These are real `ReleaseCapture` objects. First wave:
`tests.shadow_fixtures.fixture_evidence` plus `authenticate_release`. Nebular:
the `NebularLineageTests` fixture. As in the existing tests, only
module-internal pins are patched.

**Each of these must be refused:**
- a capture whose tag commit equals the historical commit;
- a different tree, a truncated tree, or a different release ID;
- a different asset digest, ID or size;
- an object that only looks like a capture;
- a record changed after authentication.

**Lineage failures:**
- drift in a manifest digest;
- equal commits, or unequal trees;
- `pin.source_commit` not equal to the historical commit;
- equal trees without the asset binding, which must be refused.

**Nebular-specific refusals:**
- no lineage proof;
- profile `forward_lineage` facts that disagree with the proof;
- drift in the approval's `tag_commit`;
- a payload asset missing from the inventory.

### 8.3 Approval

- **Refused:** an aggregate with `publication_admitted: false` (including the older `<project>-artifacts.json` sets), a `set_sha256` mismatch, an approval digest mismatch, or a Nebular `set_sha256` recomputed with the first-wave formula.

### 8.4 Remote state (`tests/test_tf_pypi_remote.py`, `tests/test_readers.py`)

- **Exact:** the full approved set, verified bytes.
- **Absent:** a project 404 and a version 404.
- **Unknown:** HTTP 500 and 403; a 404 whose error URL differs from the requested URL; `URLError`; `SSLCertVerificationError`, keeping the `pypi-tls-certificate-verify-failed` token and the verify code; timeout; redirect; oversize JSON; schema damage, including a file row with a missing or non-boolean `yanked` or a non-integer `size`; a foreign file host; a file 404; a project listing that names the version while the version endpoint returns 404.
- **Incomplete transfer is unknown, never conflict:** `http.client.IncompleteRead` and another `HTTPException` (bad status line); a body shorter than its declared `Content-Length` with no exception; or a connection that ends before the declared length.
- **Complete short bodies are conflicts:** a bounded body shorter than the approved size is `pypi-bytes-differ` when EOF or a shorter declared `Content-Length` proves the response is complete. A body that reaches `limit + 1`, a declared length over `limit`, or any other over-bound response is `unknown` with the closed `limit` token and is never compared as downloaded content.
- **Coexistence without fallback:**
  - The project lists both `0.6.1` (two files) and `0.6.1.post1`. Only the `.post1` files are read, and the latest release is never consulted.
  - Only `0.6.1` exists, so a `.post1` request returns `absent` and is never compared with the `0.6.1` files.
  - A normalized version collision is a conflict.
- **Conflict, one test per closed code:** a project listing with a different `info.name`; wrong version-endpoint `info.name` or `info.version`; a surplus file; a changed size or digest; a yanked file; a duplicate file; a complete bounded body shorter than approved, or of the approved length with different content. An over-bound body is covered by the unknown `limit` case above.
- **Incomplete:** one approved file not listed, with a null identity.
- **Unchanged regressions:** every existing `project_state` and `exact_state` test passes unchanged, including the publish-time Nebular tests. New tests drive `project_state`, `_version_rows` and `_verified_file` through each extracted cause and assert their legacy result or `AdmissionError` code is exactly what it is today.
- **Cause-carrier compatibility:** the private observer exception exposes only one enumerated cause to `approved_state`; its inherited `.code`, string and representation remain code-only, and no raw URL, response, exception text or body reaches the cause or diagnostics.
- **Trust-input propagation:** a `PYPI_PROJECTION_*` error, including a `PYPI_PROJECTION_PROVENANCE` error raised after a successful download, propagates out of `read_pypi_distribution` and is not turned into a diagnostic. A request-discipline `ContractError` (URL authority, redirect, limit) becomes an `unknown` diagnostic.

### 8.5 Provenance

- **Required:** the historical-commit `Source` URL.
- **Each raises `PYPI_PROJECTION_PROVENANCE`, not `conflict`:** drift in the transform's `source_sha256` or `target_key`; drift in the sdist `upstream/` bytes; drift in `pins.json`.
- **Nebular:** provenance must carry the historical `release_record_sha256`. Substituting the current capture's hash is refused. Drift in members or helpers is refused.
- **Live proof:** the minted observation passes `has_live_proof`.

### 8.6 Hosted wiring (`tests/test_hosted_observe.py`)

- PyPI `absent` is no longer satisfied. This inverts `tests/test_hosted_observe.py:178`.
- Four exact rows make `destinations.pypi.satisfied` true.
- The closed hosted-row envelope carries `ownership` with state `"unattested"` and `upload_authority` set to `false`. These facts are not fields in the destination observation or its readback. `publication_receipts` stays empty.
- `absent` stays distinct in `destinations.pypi.states` and in the diagnostics. The aggregate gate reason string keeps its existing value, which already names both causes (`identity-conflict-or-required-target-absent`).
- A static check confirms that `hosted_observe` no longer imports `read_pypi_project`.
- A subprocess check confirms that importing `rs9.readers` loads neither `rs9.candidate` nor `rs9.tf_pypi_nebular`.
- Gate outcome. Today `readback-byte-comparison` is `fail`, because every PyPI row is a `conflict` (`hosted_observe.py:403-404, 428`). After the change, with four exact PyPI rows and Pages `unknown`, it is `not-run` only if no npm or Homebrew row is a conflict; any such conflict keeps it `fail`. Tests cover both cases.
- The 17 existing patches of `rs9.hosted_observe.read_pypi_project` (most return `{"state": "absent"}`) move to the new seam. Their expected gate outcomes are updated deliberately, never loosened.

## 9. Staged order

Root owns every stage.

| Slice | Work | Acceptance |
|---|---|---|
| **S1a (first slice)** | The `tf_pypi_remote` extractions with cause tokens, `approved_state`, and the private bytes-returning fetch adapter in `readers.py`, with the §8.4 remote-state tests other than trust-input propagation. No projection record, public `read_pypi_distribution`, reader registration, provenance parser or hosted wiring yet: tests pass approved maps and inject `fetch` directly. | All tests offline with injected `fetch`; no network and no registry mutation; existing remote and Nebular tests unchanged and passing; legacy-result regression tests pass. The adapter returns only complete bodies at or below the bound and uses closed failures for overrun/incomplete transport. |
| **S1b** | The projection record, `pypi_observe.py`, `read_pypi_distribution`, and the §8.1–§8.3 and §8.5 tests plus the trust-input propagation tests. | All tests offline with authenticated fixtures and injected `fetch`; static reconciliation of the committed record passes; the import-isolation subprocess check passes. |
| **S2** | Wire up `hosted_observe` (§3) and update `tests/test_hosted_observe.py` (§8.6). | The hosted-observe suite passes with the new semantics, validates the closed hosted-row envelope, and confirms the unchanged closed destination-observation schema. |
| **S3** | Root runs the local suite and arranges an independent review. | Review findings are dispositioned. |
| **S4** | One hosted run of the observe lane on the new source. | `details.destinations.pypi` reports four `exact` rows with ownership `unattested`. That run is the live read. |
| **Later (optional)** | Make `_normalize_reader_target` refuse PyPI string targets that come without explicit expectations. | A separate change. |

**S1a implementation handoff and test seam.** The four S1a owners are exactly
`src/rs9/tf_pypi_remote.py`, `src/rs9/readers.py`,
`tests/test_tf_pypi_remote.py` and `tests/test_readers.py`. The only new reader
seam is an injected `fetch(url, limit) -> bytes` callable. It returns only a
complete body at or below `limit`; it may read `limit + 1` bytes internally to
detect an overrun, then raises the private cause-carrying
`AdmissionError` with a closed failure token. No registry or network access is
allowed in S1a, and no projection, provenance, hosted-observe or public reader
registration is added until S1b.

The bounded S1a command is:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest -v \
  tests.test_tf_pypi_remote tests.test_readers
```

The command runs through the repository RTK shell proxy and uses injected
response fakes only. Its acceptance includes the unchanged legacy remote and
Nebular tests plus exact/short-complete/conflict, over-bound/limit-unknown,
incomplete-declared-transfer, protocol, and URL-authority cases.

**S4 does not qualify the whole hosted run.** While Pages stays `unknown`,
`readback-byte-comparison` cannot reach `pass`, whatever PyPI reports
(`hosted_observe.py:403-429`). The run downloads about 70 MB, the sum of the
approved sizes for all four distributions, which is a cost to accept or bound
in S4 planning.

## 10. Remaining gates

- **Implementation (root):** S1a, S1b and S2, the local suite, and independent review.
- **Live observation:** S4. Until it runs, nothing here states that the `.post1` releases are observed by the lane.
- **Ownership:** the project owner and the Trusted Publisher stay operator-attested outside this lane. Nothing here changes that.
- **Independent hosted failures stay open:**
  - Nix user namespaces;
  - experimental PRoot;
  - Pages TLS.
  They are not addressed here, and unchanged campaigns are not rerun.
- **Nebular successor:** publication of `0.6.1.post1` and its Linux admission stay unresolved and out of scope.

## 11. What would make this design wrong

- The published first-wave wheels do not embed the historical commit in `Project-URL: Source`, or the sdists do not carry `upstream/<asset>` and `pins.json`.
- PyPI serves files from a host other than `files.pythonhosted.org`, or drops the per-file `yanked`, `size` or `digests` fields.
- The current authenticated release assets differ from the pins. Capture would already fail in `assert_release_expectations`, so the lane would report a capture error rather than a PyPI state.
- The Nebular wheel's `_rs9/provenance.json` fields differ from the contract that `inspect_candidate` checks.
- A committed comparator exists for the reported Nebular closure digest.
- PyPI's per-version JSON lists files that are not under `releases[<version>]`, or the reverse.
- PyPI removes the `releases` key from the project JSON. Upstream already documents it as deprecated. Every row would then be `unknown`, which fails safe but blocks S4 until the project-level step reads another listing.
- The committed pins changed after the first-wave sdists were built. The `pins.json` check compares the sdist member with `canonical(build_pin(pin))` from the current pin bytes, so it assumes those bytes are the ones used at build time. The pin digest in the projection record pins today's bytes; it does not prove they are the build-time bytes.

## 12. Discrepancies reported, not repaired

The approval `operators/tf-pypi/theme-forge-nebular-fusion-artifacts.json`
says `publication_admitted: true` (with `builder_can_publish: false`). Two
documents say `false`:

- `docs/live1-pypi.md:74`
- `docs/tf-pypi-nebular.md:3`

The observer validates the approval file, the source that binds it. This
design edits neither the approval nor the documents. Reconciling the documents
is a separate documentation change.
