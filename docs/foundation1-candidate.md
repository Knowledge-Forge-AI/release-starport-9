# FOUNDATION1 disposition and qualification

Status: terminal provider disposition after independent pre-final work review.
Closeout corrections and qualification are recorded below. Git finalization and
publication status belong to the dispatcher result, not this repository record.

## Scope and proposal disposition

Original scope: extract Theme Forge/APGR/tap publication ownership from actual
authority, implement the smallest useful RS9 foundation, and preserve all live
publication paths. Only RS9 product files may change. No external repository
mutation, package publication, credentials, DNS, Pages, staging, commit or push.

Proposal disposition: **amend** the exact bound proposal (37,857 bytes, SHA256
`c4c45b6edd0c4c10b943664b24387bec459d6584bc2fcb89a4597ce2edf86fbc`).
The original task remains authoritative; proposal bytes and advisory findings
are separately dispositioned here. Retain the provisional contract/core boundary
but narrow executable examples/parity to Nebular's actual native inputs. Research
facts still cover all four Theme Forge release streams. Dependency, desktop,
trust and publisher schemas are deferred, not guessed. No tenant code or verbatim
release lock is imported. NOTICE and all governance documents remain unchanged.

## Producer-stage entry audit and evidence

RS9 entered on `main`, local HEAD and origin-tracking main both at
`ad3235b1c7c3cb9b9b1684b973cb6e2ae19b3620`. A fresh parent GitHub branch API read
and the worker's remote query confirm public main at that revision. The parent's
SSH remote query failed because DNS was unavailable in its sandbox; that failure
did not trigger fallback to another runtime. Revision identities are evidence,
not enforced head prerequisites.

Pre-existing `.serena/` operational metadata is preserved and excluded from the
product inventory. It is not added to `.gitignore`. The observed prior stage had
no product delta. This work stage introduces only the inventory below.

Fresh public audit observed `theme-forge-packages` main at `062a931f…`, tap main
at `b8b695b…`; private distribution remains at a local revision 18 commits ahead
of its stale origin-tracking ref plus additional working changes. APT remains a
staged/untracked 14-patch candidate. No source/projection state was repaired here.

Parent connector reads confirm all four current releases are non-draft and
non-prerelease: Burst 0.6.1, Loom 0.4.0, Sail 0.2.1, Nebular 0.6.1. The first
three attach prefixed npm tarballs whose API-reported digests match the lock;
Nebular's three raw archive names/digests also match. Actual downloads, signer
authentication and release/tag lineage are not qualified by those API reads.
The public lock's fetched bytes match private/nested lock SHA256. The Nebular
Homebrew formula tuple is separately bound to fetched formula bytes.

## Advisory plan-review findings

| Finding | Disposition and resulting candidate |
|---|---|
| 1: npm provenance/repository collision | Amend. Confirmed documented compatibility requirement; ADR 0002 removes any assumption that central `--provenance` succeeds. Production identity route remains deferred pending qualification. PyPI reusable-publisher limitation is separately sourced. |
| 2: unittest importability | Accept. `tests/__init__.py` included; tests use stdlib unittest. Writer pytest tests were converted, with no dependency added. |
| 3: untracked Serena metadata | Amend. Preserve and exclude from product inventory; do not require porcelain to be empty or silently ignore the metadata. |
| 4: NOTICE/example relicensing assertion | Amend. NOTICE unchanged; no automatic change of example licensing on copying. RS9-authored examples retain existing terms; permissive per-file exception deferred to steward. Missing-license behavior belongs in spec/ADR. |
| 5: monorepo config placement | Amend. Explicitly selected project subroots allowed; declared release repo/version stream remains authority; prefixed tags supported. |
| 6: `any` intersection | Amend. Single independent package label per native destination with concrete eligibility; tests cover pacman/RPM/APT and empty intersection. Mixed independent/concrete native package inputs fail. |
| 7: license file base/authentication | Amend. Relative to declared release repository root at resolved tag commit. Validator checks syntax only; future ingestion authenticates bytes and reconciles payload licensing. |
| 8: circular oracle/import provenance | Amend. Reduced authored facts extracted from actual lock/recipes/APT matrix and fetched tap formula, with per-tuple repository/revision/path/SHA256. Configs are independently authored; no code/template/full lock import. |
| 9: APT/SPDX/next phase details | Accept. APT labeled candidate, syntax-only `Commercial` acceptance explicit, next shadow phase narrowed to Nebular. |

Observed research deltas amend carried-forward assertions: current GitHub
tarball availability is confirmed at the metadata level; AUR Burst targets
x86_64/aarch64, not `any`; APT changed-index publication is guarded pending
authenticated generation retention. GUI display intent is insufficient to repair
Linux FHS namespace constraints. None is silently converted into a live fix.

## Candidate artifacts and qualification

- [Extraction/classification inventory](architecture/theme-forge-extraction-inventory.md)
- [Contract decision](adr/0001-tenant-contract-v1alpha1.md),
  [release authority decision](adr/0002-github-release-sole-ingestion-authority.md)
  and [implemented specification](specs/rs9-config-v1alpha1.md)
- [Adapter/destination boundary](architecture/adapter-destination-model.md)
- [First tenant example](../examples/theme-forge/theme-forge-nebular-fusion/.rs9/project.toml)
  and [source-bound facts](../tests/fixtures/theme-forge-observed-facts.json)
- [Migration/rollback map](architecture/migration-map.md) and
  [installation navigation](install/README.md)

Historical work-stage qualification on Python 3.13.12:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
32 tests: OK
```

Tests include negative configuration cases, type/schema/path/credential rejection
(including decoded TOML escapes), CLI validation, deterministic
same-input output, reordered-semantic versus raw-hash behavior, six Nebular
destination tuples, all four release metadata/lock comparisons, MIT preservation,
exact input hashes and golden output, source import hygiene and unchanged
governance bytes. Both Nebular and synthetic registry examples pass real CLI
validation with destination checks; two subprocess normalization runs for each
are byte-identical. The oracle's APT facts describe candidate bytes, not live
publication. API metadata facts are offline observations, not integrated release
authentication tests.

Product secret-pattern/private-key/private-path scan: zero matches. Standard
library/RS9 imports only; no dependency/metadata/lockfile change. No generated
cache artifacts. Git whitespace check and explicit new-file whitespace scan pass.
LICENSE, COMMERCIAL-LICENSE, CLA, NOTICE and CONTRIBUTING match existing HEAD
bytes. Docs distinguish intended architecture from implemented normalization.
Python 3.11 is the intended minimum; only the available 3.13 interpreter was run.

Python profile: Orange for bounded syntax/path-validation branching; the parent
split writer monoliths into project/release/adapter/destination responsibilities
and one shared routing calculation. APG fallback source counts: 14 modules,
largest 278 physical lines, largest callable 32 statement nodes. Explicit
fail-closed checks are retained with adverse tests. Rollback is removal of this
unpublished foundation; no production compatibility changes exist.

Two Gemini facility jobs were admitted for read-only audit and disjoint source
implementation. Both completed with proven cleanup. Their outputs were adopted
as partial evidence/work and corrected by the parent; neither is a dispatcher
checkpoint. Requested worker profile was Gemini; effective model telemetry was
not independently observed. No external reviewer was invoked.

## Terminal disposition of the reviewed candidate

Disposition: amend

Rationale: retain the reviewed validation-only foundation and all prior product
deltas. Apply bounded corrections to tenant validation, normalization, portable
hygiene and durable evidence. The advisory review found no blocking defect and
did not authorize production publication. Preserve `.serena/` operational
metadata without adding it to the product inventory or changing its bytes.

| Work-review finding | Terminal disposition |
|---|---|
| 1: handoff status becomes stale | Amend. Replace transient staging/pending language with this durable disposition record. Dispatcher result owns final Git/publication status. |
| 2: governance test and product scan need Git | Amend. Product scan uses explicit product roots; the ongoing test checks the documented licensing boundary. Baseline byte preservation is phase evidence below, not an ongoing HEAD-relative restriction. |
| 3: credential-like command identifiers | Amend. Permit declared asset command keys such as `gh-auth` and `tokenizer`; continue screening raw/decoded token and private-key patterns, including decoded keys. Other credential-like field names still fail. |
| 4: tenant-local duplicate destination/package names | Amend. Reject in adapter validation without requiring destination definitions. Cross-destination validation remains defensive. |
| 5: target asset references exceed effective platforms | Amend. Emit only contributing selected assets per target; retain the complete top-level release asset inventory. Assets spanning several platforms remain one reference. |
| 6: inconsistent missing-key codes | Amend. Required fields/tables consistently use `MISSING_REQUIRED_KEY`; malformed present types remain `INVALID_TYPE`. Add representative cases across tenant/adapter/destination tables. |
| 7: license golden proves packaging agreement only | Accept with explicit deferral. Label test/example/golden agreement provisional; FOUNDATION2 must resolve tagged tenant/payload terms and npm's `OR Commercial` discrepancy. Do not invent a license authority finding. |
| 8: native npm tarball with narrower pacman serving untested | Amend. Add a synthetic Burst-shaped normalization test, covering one native npm tarball's multi-platform eligibility and x86_64-only pacman serving. It is not authenticated Burst parity or archive-file selection. |
| 9: ADR context, subprocess cwd, NFC, exit range, metadata | Amend ADR Context, use absolute subprocess source path and reject non-NFC check arguments/expectations. Defer exit/signal-domain limits to the future runner; document the current integer-only rule. Preserve operational metadata; dispatcher selects phase paths. |

No additional substantive review was requested or obtained. These terminal
corrections were inspected and verified by the provider; they do not create
another independent dispatcher review checkpoint.

## Closeout qualification

Qualification evidence: on Python 3.13.12, the final foundation command passes:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
39 tests: OK
```

Before source corrections, the focused regression tests reproduced the reviewed
command-name, local ambiguity, target asset, missing-code and check NFC defects.
After corrections, all 39 tests pass, including adverse inputs, decoded-key
credential rejection, Nebular golden/input-digest parity, provisional packaging
agreement, MIT preservation and the native npm tarball shape. Nebular example
and golden bytes did not need to change.

Additional closeout checks actually run:

- Real CLI validation with destinations for Nebular and the synthetic registry
  fixture; two fresh subprocess normalizations for each agree byte-for-byte
  with the in-process result.
- Copy the product files to a temporary source archive without `.git`, then run
  the three hygiene tests and subprocess CLI test from a foreign working
  directory: four targeted tests pass.
- Compare all five governance files with the phase baseline using read-only
  `git show HEAD:<path>`: identical bytes. No ongoing test imposes that baseline.
- Rehash the 19 unique local Theme Forge research-source files bound in the
  fact fixture: all match, none missing. This confirms source-byte extraction,
  not release authentication or the fetched public tap/API observations.
- Product token/private-key/private-path screening and standard-library-only
  imports pass through the hygiene tests. No generated cache artifacts remain.
- `rtk git diff --check`, explicit new-file whitespace, product inventory and
  local Markdown-link checks pass; 48 product paths match the inventory below.

The closeout local audit still observes the phase baseline HEAD and the expected
product delta. A remote `git ls-remote origin refs/heads/main` attempt failed
because GitHub DNS was unavailable in the sandbox; public-head observations
above remain historical producer evidence. RTK commands execute, but its gain
tracking database is unavailable in this sandbox. No runtime fallback was used.

Unresolved concerns: release authenticity and downloaded bytes, authoritative
Nebular licensing and `--version` stdout, public tap/API binding refresh,
runner exit/signal semantics, and the migration gates below remain deferred.
Python 3.11 compatibility was not executed; the available interpreter is 3.13.
No package build, signing, install/uninstall, hosted validation or publication
was run or claimed. The terminal correction has no automatic independent review.

Deferred: actual release authentication; package construction and complete
metadata/dependency/desktop parity; GUI/namespace-capable qualification; signing
and rotation; receipts and publisher OIDC routes; registry/projection/contribution
operations; APT retention/native hosted acceptance; domain migration; example
license exception. Current publication surfaces stay operational and authoritative.

Recommended commit message:

```text
Extract provisional RS9 tenant contract from Theme Forge publication

Add declarative validation and deterministic normalization, source-bound
Theme Forge facts, Nebular and synthetic fixtures, architecture decisions,
migration gates and installation navigation. No publication is implemented.

Verify 39 contract, parity and hygiene tests, CLI determinism, source
bindings, archive portability and unchanged governance bytes.
```

Next bounded phase: `RS9-FOUNDATION2-NEBULAR-PROJECTION-SHADOW1`, as described
in the migration map. Authenticate first-tenant inputs and close dependency,
desktop/license gaps before accepting any generated recipe. No signing or live
cutover belongs to that recommendation.

## Exact product changed-file inventory

The following 48-path list excludes preserved operational metadata; all paths are
repository-relative. Existing product modifications are limited to README.md,
docs/README.md, docs/architecture.md and docs/project-contract.md. Other listed
files are new.

- `.gitignore`
- `README.md`
- `docs/README.md`
- `docs/adr/0001-tenant-contract-v1alpha1.md`
- `docs/adr/0002-github-release-sole-ingestion-authority.md`
- `docs/architecture.md`
- `docs/architecture/adapter-destination-model.md`
- `docs/architecture/migration-map.md`
- `docs/architecture/theme-forge-extraction-inventory.md`
- `docs/foundation1-candidate.md`
- `docs/install/README.md`
- `docs/project-contract.md`
- `docs/specs/rs9-config-v1alpha1.md`
- `examples/README.md`
- `examples/destinations.example.toml`
- `examples/theme-forge/theme-forge-nebular-fusion/.rs9/apt.toml`
- `examples/theme-forge/theme-forge-nebular-fusion/.rs9/dnf.toml`
- `examples/theme-forge/theme-forge-nebular-fusion/.rs9/homebrew.toml`
- `examples/theme-forge/theme-forge-nebular-fusion/.rs9/nix.toml`
- `examples/theme-forge/theme-forge-nebular-fusion/.rs9/pacman.toml`
- `examples/theme-forge/theme-forge-nebular-fusion/.rs9/project.toml`
- `examples/theme-forge/theme-forge-nebular-fusion/.rs9/releases.toml`
- `src/rs9/__init__.py`
- `src/rs9/adapters.py`
- `src/rs9/constants.py`
- `src/rs9/contract.py`
- `src/rs9/cross_validator.py`
- `src/rs9/destinations.py`
- `src/rs9/errors.py`
- `src/rs9/fields.py`
- `src/rs9/normalizer.py`
- `src/rs9/project.py`
- `src/rs9/releases.py`
- `src/rs9/security.py`
- `src/rs9/spdx.py`
- `src/rs9/validator.py`
- `tests/__init__.py`
- `tests/fixtures/synthetic-mit-tool/.rs9/npm.toml`
- `tests/fixtures/synthetic-mit-tool/.rs9/project.toml`
- `tests/fixtures/synthetic-mit-tool/.rs9/pypi.toml`
- `tests/fixtures/synthetic-mit-tool/.rs9/releases.toml`
- `tests/fixtures/theme-forge-observed-facts.json`
- `tests/golden/theme-forge-nebular-fusion.normalized.json`
- `tests/test_closeout_regressions.py`
- `tests/test_contract.py`
- `tests/test_fail_closed.py`
- `tests/test_hygiene.py`
- `tests/test_theme_forge_parity.py`
