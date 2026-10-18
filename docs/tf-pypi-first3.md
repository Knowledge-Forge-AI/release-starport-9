# First-wave Theme Forge Python adapters

This REALQUAL2 source candidate received dispatcher work review and closeout
corrections. Source adoption remains BLOCKED by the historical admission gates
recorded below. SOURCE1 remains terminal BLOCKED/RC2. The provider made no commit,
push, upload, workflow dispatch, account action, upstream asset modification or
version change. APGR's separate publisher, pins, journal and Go ownership are
preserved. Dispatcher finalization is reported separately.

| Product | Version | Local verdict | Wheel platform | Registered workflow |
| --- | --- | --- | --- | --- |
| theme-forge-stellar-burst | 0.6.1 | READY, Darwin ARM64 only | macosx_13_0_arm64 | rs9-tfsb-pypi-publish.yml |
| theme-forge-stellar-loom | 0.4.0 | READY, Darwin ARM64 only | macosx_11_0_arm64 | rs9-tfsl-pypi-publish.yml |
| theme-forge-solar-sail | 0.2.1 | READY, Darwin ARM64 only | macosx_11_0_arm64 | rs9-tfss-pypi-publish.yml |

READY describes the bounded product evidence, not source adoption or upload
permission. See [ADR 0017](adr/0017-theme-forge-pypi-real-qualification.md),
[plan disposition](../evidence/tf-pypi/realqual2-plan-disposition.json) and
[verification](../evidence/tf-pypi/realqual2-verification.json). SOURCE1 receipts
are retained unchanged. Historical admission failures remain separately recorded.
The final correction receipt is
[closeout verification](../evidence/tf-pypi/realqual2-closeout.json).

## Runtime and installation

These distributions wrap frozen Node CLI releases. Install Node.js >=22 separately;
pip installation and Python import never download Node or npm packages. Host
qualification used Node v22.22.2 on macOS ARM64. Python >=3.9 is declared; 3.9.6
and 3.13.12 passed complete wheel/sdist lifecycles. Intermediate minors are inferred,
not directly tested. This does not change the RS9 application's Python policy.

Use a dedicated virtual environment and trusted local distributions:

```sh
python3 -m venv theme-forge-env
theme-forge-env/bin/python -m pip install --no-index --no-deps /approved/path/to/package.whl
```

Burst installs tfsb/tfsb-studio-service; Loom installs tfsl/tfsl-batch; Sail installs
tfss. No package installs apgr or tfnf. Names match upstream npm/AUR commands:
root/system pip can overwrite another installation, and PATH ordering can shadow
it. Use a dedicated venv and explicit bin paths. Uninstall removes the package and
launchers, leaving user-created application outputs and separately installed Node.

Only Darwin ARM64 wheels and host-restricted sdists are approved. Foreign native
headers and all four loader selections were checked; Linux ARM64/x64 and Darwin
x64 binaries were not executed. No Windows or musl input was supplied. Loom/Sail
are platform-constrained despite having no npm runtime dependencies. No artifact
claims py3-none-any. macOS versions below the actual qualification host were not
separately executed; tags reflect binary deployment requirements or ARM64 baseline.
The loader's static string heuristic is an admission check, not proof that native
pruning is safe on an unexecuted platform. Foreign native runtime qualification
remains deferred; no foreign artifact pins or publishing workflows are approved.

## Reproduce qualification

Use the manager's read-only authenticated inputs. Set TF_INPUTS to that directory
and TF_DIST/TF_WORK to fresh task-owned locations; keep receipts outside TF_DIST.
Do not substitute network copies or rewrite the inputs during this phase.

```sh
PYTHONPATH=src python3 -B -m rs9.tf_pypi_workflow intake --project theme-forge-stellar-burst --inputs "$TF_INPUTS"
PYTHONPATH=src python3 -B -m rs9.tf_pypi_workflow build --project theme-forge-stellar-burst --inputs "$TF_INPUTS" --output "$TF_DIST"
PYTHONPATH=src python3 -B -m rs9.tf_pypi_workflow verify --project theme-forge-stellar-burst --dist "$TF_DIST"
PYTHONPATH=src python3 -B -m rs9.tf_pypi_workflow consumer --project theme-forge-stellar-burst --dist "$TF_DIST" --work "$TF_WORK"
RS9_TF_PYPI_REQUIRE_LIVE=1 RS9_TF_PYPI_INPUTS="$TF_INPUTS" PYTHONPATH=src python3 -B -m unittest discover -s tests -p 'test_tf_pypi_*.py' -q
```

Substitute each exact project name to qualify it independently. Consumer tests
require enforced network denial, including permission-denied Python/Node literal-IP
TCP and failed DNS probes. An unrestricted shell deliberately fails that gate;
--no-index alone does not prove runtime isolation.
All real-input tests use RS9_TF_PYPI_INPUTS; RS9_TF_PYPI_REQUIRE_LIVE makes absent
inputs fail. A configured but unavailable directory also fails. The live suite
builds each product against its actual committed artifact approval, so changes
to embedded backend helpers, pins or legal files cannot silently stale the pins.

Sdists retain original release tarballs and Burst's three dependency tarballs.
Their in-tree backend needs no Python build dependencies. Wheel/sdist metadata,
legal paths, helper bytes and complete payload agree; RECORD is bidirectional and
native omissions are source-bound. Repeated builds and sdist-built wheels must
match byte-for-byte. Per-project artifact manifests bind filenames, sizes, SHA-256
and logical identities. A digest alone does not grant approval.

## Attended publication after independent adoption

These are future operator steps. Do not publish from this uncommitted candidate.

1. Complete dispatcher closeout and independent review of the exact final patch
   and source tree, including closer edits. Verify adoption into the canonical
   checkout. Repair candidate-only regressions and disposition historical admission
   limitations without silently refreshing E1/AUTH1 approvals. Publish reviewed
   source/workflows through the operator-owned GitHub process.
2. Read back every pending PyPI publisher: Knowledge-Forge-AI/release-starport-9,
   environment pypi, and exactly its registered workflow above. APGR separately
   uses rs9-pypi-publish.yml for agentic-praxis-grimoire v0.13.0. Confirm environment
   protections without altering APGR publishing. For an existing PyPI project,
   independently confirm authorized ownership and its active Trusted Publisher
   in the authenticated UI before authorizing publish mode. Public package JSON
   and byte readback cannot establish ownership, even for identical artifacts.
3. Per product, initially Sail then Loom then Burst, dispatch qualify from reviewed
   main. Both jobs bind code and committed pins to github.sha. The Ubuntu job uses
   an explicit cross-target builder to reproduce Darwin ARM64 artifacts; no hosted
   byte-exact rebuild has been observed here, so successful qualify is mandatory.
   Never edit pins merely to accept a CI mismatch.
4. Inspect artifacts against committed filename/size/hash/logical pins and local
   receipts. Select the same reviewed commit for attended publish mode, then review
   that product's pypi environment deployment. Only the publish job receives OIDC.
   There is no token fallback or local upload command.
5. Exact absent state selects all approved files; published-exact selects none;
   an exact subset selects only missing files. Extra, changed, yanked, renamed or
   wrong-version files conflict. Malformed data, redirects, transport uncertainty
   refuse publication. published-exact establishes artifact identity only; the
   workflow cannot authenticate project ownership and does not enforce the manual
   ownership prerequisite. Do not authorize publishing while ownership remains
   unknown. Do not delete files or bump frozen versions to evade reconciliation.
6. Require exact post-upload readback. Unknown/eventual-consistency results fail
   closed and require a new attended reconciliation decision. Confirm project owner
   and active Trusted Publisher in the UI, then retain sanitized receipts through
   a later reviewed evidence change.

Each independently qualified product may use its existing pending publisher even
though this first wave is macOS ARM64 only. Local workflows/artifacts create no
PyPI project. A successful project creation converts that project's pending
publisher; it does not qualify any other project or platform.

## Nebular second batch

theme-forge-nebular-fusion remains deferred with no workflow, upload or pending
record mutation. After a first-wave upload has exact readback and owner-confirmed
pending-to-active conversion, the operator may use the freed slot for
rs9-tfnf-pypi-publish.yml under the same repository and pypi environment. A separate
authenticated-input qualification and independent review must precede that workflow
and upload. Never delete an existing pending record merely to make space.

## ADMISSION3 checkpoint recovery

ADMISSION3 is a separate admission/inventory recovery phase. The combined
REALQUAL2 closeout remains BLOCKED. Synthetic E1 tests now use separate frozen
controller copies; the development checkout remains inadmissible as an E1
controller. Hygiene permits only the two exact historical review ZIPs and scans
their bounded text members. This does not make the frozen text-only inventory or
AUTH1 complete-snapshot controller admissible. See ADR 0018 and the ADMISSION3
verification and review evidence for exact remaining failure IDs.

ADMISSION3 also bounds wheel-member reads before ZIP CRC validation. A forged
declared member size previously allowed oversized DEFLATE output before refusal.
The verifier now limits each actual read; the public error remains unchanged.
This tool is outside the embedded backend and launcher, and fresh builds must
still match the unchanged approved artifacts. The fix and its regression require
review with the rest of the terminal amendment.

The Ubuntu workflow eligibility check uses the download branch with authenticated
retained bytes and forbids subprocess and network execution. It reproduces the
committed Darwin artifacts using the builder's explicit `darwin-arm64` target.
The fixture's Linux platform patches do not exercise host selection because this
target bypasses `host_key()`. It establishes host-independent download-branch
byte reproduction only. A hosted download, Python 3.12 execution, Linux native
qualification and Darwin runtime qualification remain unobserved by this check.
The static Python 3.12 grammar and stdlib call-site audit covers only
`src/rs9/tf_pypi_*.py`. It excludes `rs9/__init__.py` and the non-TF modules imported
by package initialization; full workflow import compatibility on Python 3.12
remains unverified. Within the audited TF sources, archive readers inspect members
without using `extract` or `extractall`, so extraction-filter defaults are not
relied upon. A same-commit hosted qualify run remains pending with the operator.

Checkpoint patches and sanitized full test logs are bounded source evidence.
Patch scope and replay preconditions are stated in the inventory report. Before
applying the zero-context patch with `--unidiff-zero`, verify every listed
`entry_sha256` against a physical regular preimage and require absence for every
null preimage. These checks are mandatory: zero-context application does not
verify surrounding lines. After replay, verify every result hash and mode.
Derived manifest and evidence controls are supplied as files rather than
recursive patch payloads. In the verification report, retained-log `sha256`
values bind the sanitized source logs; `raw_log_sha256` binds the scratch-only
originals. The inventory and candidate manifest cannot include their own final
digests recursively: their complete final hash/mode rows remain in the external
task-scratch sidecar, and are also reported in the terminal dispatcher handoff.
Those two rows are an explicit source-owned hash-list limitation; scratch is not
adoption authority. The managed sandbox cannot write the operator outbox.
Terminal edits without a second independent review remain review-required.
