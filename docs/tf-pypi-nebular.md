# Nebular Fusion Native Darwin PyPI Publisher

Status: source candidate prepared for dispatcher pre-final checkpoint; `publication_admitted` remains `false` in `operators/tf-pypi/theme-forge-nebular-fusion-artifacts.json`. No Git commit, push, PyPI upload, or hosted workflow dispatch was performed in this phase.

| Field | Value |
| --- | --- |
| Project / Distribution | `theme-forge-nebular-fusion` |
| Version | `0.6.1` |
| Registered Workflow | `.github/workflows/rs9-tfnf-pypi-publish.yml` |
| Trusted Publisher Environment | `pypi` (`Knowledge-Forge-AI/release-starport-9`) |
| Approved Artifact | `theme_forge_nebular_fusion-0.6.1-py3-none-macosx_13_0_arm64.whl` (wheel-only; no sdist) |
| Wheel Size | `46,792,720` bytes (`53,207,280` bytes headroom below PyPI 100 MB default limit) |
| Wheel SHA-256 | `7f38708f9e82216b27165769785b378f5b17480a8a7a594f07adf6273e737c20` |
| Logical SHA-256 | `58ab244a0dabdf797dbe4c1d02b43c0d9082656ce7a7222c8c07b016b230cab6` |
| Approval `set_sha256` | `5b306dfabae76d597263ea2ddd563d7d11211b252eba910eca45672a0a939284` |
| `Requires-Python` | `>=3.10` |
| Console Script | `tfnf` (`theme_forge_nebular_fusion.launcher:main_tfnf`) |
| License Expression | `AGPL-3.0-or-later` (`LICENSE` and `NOTICE` in `.dist-info/licenses/`; `COMMERCIAL-LICENSE.md` not shipped in wheel) |

See [ADR 0019](adr/0019-nebular-native-pypi-publisher.md) for architectural decisions and the superseded preliminary `>=3.9` candidate record (`7d2bcbee182e496fa6221e1b2dad75e7899373aba7801f17a16a838f843ae82c`).

## Runtime and installation

The Darwin ARM64 wheel encapsulates the exact authenticated release archive (`theme-forge-nebular-fusion-v0.6.1-aarch64-apple-darwin.app.tar.gz`, 1,656 members, manifest SHA-256 `41d9eaa1b7930efe1edaa33a600491bd9073da42f27445983fd4da88596995ba`) together with the five unchanged reviewed RS9 runtime helpers (`archives.py`, `errors.py`, `materialize.py`, `scratch.py`, `security.py`) under `theme_forge_nebular_fusion/_isolated/rs9/`.

Install into a dedicated Python `>=3.10` virtual environment on macOS 13.0+ ARM64:

```sh
python3 -m venv nebular-env
nebular-env/bin/python -m pip install --no-index --no-deps /approved/path/to/theme_forge_nebular_fusion-0.6.1-py3-none-macosx_13_0_arm64.whl
```

On first invocation of `nebular-env/bin/tfnf`, the launcher verifies the embedded archive SHA-256 and member manifest and materializes the application bundle into a locked user runtime cache directory (`$THEME_FORGE_CACHE_DIR` when set, or the user cache directory). `pip uninstall -y theme-forge-nebular-fusion` removes all 17 wheel members and the `tfnf` entry point from the virtual environment; the materialized runtime cache persists outside the virtual environment by design and can be removed separately when no longer needed.

## Reproduce offline build and native consumer qualification

Set `NEBULAR_CAPTURE`, `STELLAR_CAPTURE`, and `VERIFIER_CLOSURE` to the read-only authenticated input directories, and set `TFNF_DIST` and `TFNF_WORK` to fresh empty directories:

```sh
PYTHONPATH=src python3 -B -m rs9.tf_pypi_nebular build \
  --nebular-capture "$NEBULAR_CAPTURE" \
  --stellar-capture "$STELLAR_CAPTURE" \
  --closure "$VERIFIER_CLOSURE" \
  --output "$TFNF_DIST" \
  --scratch "$TFNF_WORK/build-scratch"

/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)(allow process-exec (with no-sandbox) (literal "/bin/ps"))' \
  env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m rs9.tf_pypi_nebular qualify \
  --dist "$TFNF_DIST" \
  --work "$TFNF_WORK/consumer" \
  --nebular-capture "$NEBULAR_CAPTURE" \
  --stellar-capture "$STELLAR_CAPTURE" \
  --closure "$VERIFIER_CLOSURE" \
  --python39 /usr/bin/python3 \
  --report "$TFNF_WORK/consumer-report.json" \
  --expected-commit "$(git rev-parse HEAD)"
```

`qualify` enforces:
1. Source commit and worktree binding (`source_tree_state`): verifies `HEAD` equals `--expected-commit`, records `worktree_clean`, `status_porcelain_sha256`, `product_files_sha256` (5 Nebular product files), `closure_files_count` and `closure_files_sha256` (all 84 files in the transitive `src/rs9/*.py` import closure plus product, bootstrap, and release-expectations manifests), and `serena_excluded_from_dirty_check: true` (operator-local `.serena/` IDE metadata is preserved untouched and ignored by the worktree dirty check), and fails closed (`TF_PYPI_HOSTED_WORKTREE_DIRTY`) when `--require-clean` is passed on a dirty checkout. Pre-commit local qualification runs (`worktree_clean: false`) attest to the exact candidate overlay via `product_files_sha256` and `closure_files_sha256`, whereas hosted `native_consumer` enforces `--require-clean` against the committed tree.
2. Active Darwin seatbelt network denial for both Python (`s.connect(('1.1.1.1', 443))` -> `EPERM`/`EACCES` and `socket.getaddrinfo('registry.npmjs.org', 443)` -> host libc `socket.gaierror` `EAI_*` in `{EAI_NONAME, EAI_AGAIN, EAI_FAIL, EAI_NODATA}`) and Node (literal-IP TCP `1.1.1.1:443` and DNS `registry.npmjs.org` independently verified as denied via `TCP:` / `DNS:` tokens) with only the narrow `/bin/ps` process-table exception required by upstream `native-rc-smoke.mjs` (`ps -ax -o pid=,command=`).
3. `ps` resolution on the harness `PATH` to root-owned, non-symlink `/bin/ps` (`uid == 0`, `mode in (0o4755, 0o0755)`, SHA-256 recorded for audit rather than pinned across macOS minor OS updates), probed via `ps -p <self-pid> -o pid=,comm=` with exact first-token PID matching on a single output line and without retaining raw process output.
4. Exact 63-target persistent-state snapshots (`7` Library bases × `3` application names × `3` suffixes) beneath the real operator home directory before and after execution without enumerating shared `~/Library/*` parent directories; any existing descendant subpaths are SHA-256-hashed (`sha256:...`) and only `public_summary` aggregates are written to `host-state-before.json` / `host-state-after.json`.
5. Real Python 3.9 (`3.9.6`) pre-installation refusal of the `>=3.10` wheel with zero virtual-environment mutation.
6. Offline virtual-environment install, `tfnf --version` (`0.6.1`), released sidecar verification (`tools/sidecar-verify.mjs`, 8 checks), released Darwin Scenario A (`tools/native-rc-smoke.mjs` against the authenticated `theme-forge-stellar-burst` `v0.6.1` fixture), and clean `pip uninstall` verification.

## Attended hosted qualification and publication runbook

1. **Hosted qualification (`mode=qualify`)**:
   - Push the reviewed candidate to `rs9-tfnf-pypi-hostqual1` or dispatch `rs9-tfnf-pypi-publish.yml` with `mode=qualify` on `main` after operator adoption.
   - `build_verify` (`macos-15`, Python 3.13) rebuilds the wheel from fresh authenticated GitHub release captures (using `RS9_GITHUB_READ_TOKEN`) and verifies exact byte parity against `operators/tf-pypi/theme-forge-nebular-fusion-artifacts.json` (`publication_admitted` may remain `false` during `qualify`).
   - `native_consumer` (`macos-15`, Python 3.13, Node 22) downloads the same run's wheel artifact to `${{ runner.temp }}/tfnf-dist` (outside `$GITHUB_WORKSPACE` so the checkout stays clean), prepares fresh authenticated captures and verifier source closure outside network denial, and executes `rs9.tf_pypi_nebular qualify --dist "$PHYSICAL_RUNNER_TEMP/tfnf-dist" --require-clean` under `/usr/bin/sandbox-exec`.
   - Confirm that the `publish` job is skipped during `qualify` and that no OIDC token is requested.

2. **Promotion and attended publication (`mode=publish`)**:
   - After independent review of hosted qualification receipts and operator verification of the pending PyPI Trusted Publisher (`theme-forge-nebular-fusion`, owner `Knowledge-Forge-AI`, repository `release-starport-9`, workflow `rs9-tfnf-pypi-publish.yml`, environment `pypi`), flip `"publication_admitted": true` in `operators/tf-pypi/theme-forge-nebular-fusion-artifacts.json` (`set_sha256` remains `5b306dfabae76d597263ea2ddd563d7d11211b252eba910eca45672a0a939284`).
   - Dispatch `rs9-tfnf-pypi-publish.yml` on `main` with `mode=publish`.
   - In `publish` (`ubuntu-24.04`, `environment: pypi`, `permissions: {id-token: write, contents: read, actions: read}`), `select-missing` requires `publication_admitted == true`, enforces repeat-upload guards (`--attempt-marker` intra-job exclusive file lock, `GITHUB_RUN_ATTEMPT != '1'` job-rerun refusal, `vars.RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED` durable environment/repository variable guard, and a mandatory paginated GitHub Actions prior-run check `check_prior_publish_runs` using `RS9_GITHUB_READ_TOKEN: ${{ github.token }}` over `?branch=main&event=workflow_dispatch&per_page=100` and `?filter=all&per_page=100` requiring every unreviewed prior run to include the `Trusted Publishing to PyPI` job and mapping any unexpected client or assertion failure fail-closed to `TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED` before staging), checks remote PyPI state (`absent` stages the single wheel; `published-exact` skips upload; `conflict` or `unknown` aborts), `verify-upload` re-verifies the staged file immediately prior to `pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e`, and `readback` polls `(0, 15, 30, 60, 120, 180)` seconds in-job without ever re-invoking upload.
   - If `readback` exhausts its 6 attempts (`TF_PYPI_READBACK_ABSENT` / `TF_PYPI_READBACK_UNKNOWN`), the workflow exits non-zero with `disposition=unconfirmed-no-redispatch-before-independent-readback`. Set `RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED=1` if holding the environment and never re-dispatch `publish` before independently reading back remote PyPI state. If a prior `publish` workflow run failed or was cancelled before uploading (`Publish package distribution to PyPI` did not execute or `Trusted Publishing to PyPI` was cancelled with empty steps), the operator must independently read back `https://pypi.org/pypi/theme-forge-nebular-fusion/json` and the GitHub Actions run logs; once zero upload is proven, record that audited run ID in `REVIEWED_SAFE_PRIOR_RUN_IDS` in `src/rs9/tf_pypi_nebular.py` via a reviewed commit before re-dispatching.
