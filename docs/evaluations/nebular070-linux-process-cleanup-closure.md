# RS9 Nebular 0.7.0 Linux Process-Group Cleanup Closure

## 1. Scope and Baseline

- **Baseline**: `HEAD` `4f8ad21f751fb362e6e515c1516330f81fd5e96a` (tree `c0afc6d470155b520bce429dea46c22fcf7ca168`), PR `#14` source (`170` Darwin tests passing; legacy `0.6.1` API compatible).
- **Linux baseline**: Source CI `40485852569` and `main` `40447676708` had the same two Linux unit failures in `tests.test_tf_pypi_nebular070_gate2`: Gate 1 -> Gate 2 `COMMAND_CONTRACT` (`require_clean`) and timeout `cleanup_known == False`. Required Linux Nix gates fail `NIX_FHS_USERNS` (`uid-map-denied`); PRoot is excluded from `required_jobs` (no Nix/unit waiver).
- **Touched paths (5-file scope)**:
  1. `src/rs9/tf_pypi_consumer.py` (`e34ef4b328c68ff3bb4340e2e0b0a351f6505fadb01e83c6b3d7060e500aa3a0`, `76,933` B)
  2. `tests/test_tf_pypi_nebular070_gate2.py` (`e479aabe1f9e3381314e93077a15c32ef5209b9c790af9ec2175d23e95906772`, `87,676` B)
  3. `docs/evaluations/nebular070-linux-process-cleanup-closure.md`
  4. `docs/evaluations/nebular070-nix-userns-policy-proposal.md` (`13a0145ce93691c1558a7d59a4c05c15d73ada4d3195d0fcf8affe72dc72aad0`, `4,398` B; inert)
  5. `docs/evaluations/nebular070-nix-userns-policy-proposal.patch` (`137b4877502a9f53aabc85287c78bf2effcf1c20bd0d2c47d32c51ef828ed846`, `13,487` B; inert)
- **Invariants**: `.github/workflows/rs9-candidate-tests.yml` (`0b5582b18bcb561257239d9fa6512e9c8b8852d4d46ddd21b343a01abdc1cab7`) and `.github/workflows/rs9-tfnf-pypi-publish.yml` are unchanged; neither `.github/scripts/rs9-linux-userns-apparmor-guard.sh` nor `tests/test_linux_userns_apparmor_guard.py` is materialized; no other source, lock, workflow, or policy files changed.

## 2. Process-Group Cleanup Gap and Bounded Fix

- **Gap**: In `_nebular_run` (`start_new_session=True`, `1 MiB` cap), on leader reap (`code is not None`) and pipe EOF (`not streams`), the loop exited early: (1) `break` fired as soon as `post_exit_deadline = now + _NEBULAR_DRAIN_GRACE` was armed (`SIGTERM` sent if `_nebular_group_exists(child.pid)` held), before `post_exit_deadline`/`cleanup_deadline` elapsed; (2) in `kill_sent`, a second `break` after `child.wait(...)` bypassed `post_exit_deadline`; (3) with `not streams`, `selector.select(wait_for)` did not sleep, so a signalled Linux group member briefly observable via `os.killpg(child.pid, 0)` left `cleanup_known = False`.
- **Bounded fix (`src/rs9/tf_pypi_consumer.py`)**:
  1. Break on `code is not None and not streams` only when `post_exit_deadline is not None and now >= post_exit_deadline and (cleanup_deadline is None or now >= cleanup_deadline)`.
  2. Remove the second `break` after `child.wait(...)` so the next turn arms `post_exit_deadline`.
  3. When `not streams and not events`, sleep `wait_for` (`<= 0.05`s before `post_exit_deadline`; floored at `1 ms` / `~500` wakeups per `0.5`s once `post_exit_deadline` passes while `cleanup_deadline` is pending).
- **Admission impact & limits**:
  - Callers (`install`, `require_clean`, `uninstall`) reject `forced_cleanup == True`, and line `893` sets `forced_cleanup = True` if `_nebular_group_exists(child.pid)` holds at leader exit. Waiting out the deadlines fixes `cleanup_known == False` on already-rejected forced runs (explaining the Linux timeout unit failure) and adds `>= 0.5`s per clean probe without changing any production admission outcome.
  - `NEBULAR_COMMAND_CONTRACT` has `>= 5` non-cleanup triggers (`1440-1460`), and the Ubuntu container probe ran only flood/timeout probes; thus the hosted Linux `Gate 1 -> Gate 2` `COMMAND_CONTRACT` failure is unattributed and **not** claimed closed (hosted Linux unit CI decides).
  - Pre-existing at `HEAD` (follow-up outside minimal fix): if a leader ignores `SIGTERM` past `deadline` (`code is None`), lines `889-890` call `request_termination` each turn and line `875` resets `cleanup_deadline`, preventing `escalate()` (`895`) from firing; thus `kill_sent` (`920-931`, no dedicated unit test) is reachable only via `output_limit_exceeded`.
- **Contracts**: `_NEBULAR_TERMINATION_GRACE`/`_NEBULAR_DRAIN_GRACE` (`0.5`s) are unchanged. `cleanup_known` requires **observed group absence** (`os.killpg(child.pid, 0)` raising `ESRCH`); live, zombie/unreaped, and `PermissionError`/non-`ESRCH` `OSError` remain `False`. Stream/artifact caps, session/PID checks, and command/hash/`require_clean` contracts are preserved (Python `Red` `1,532`-line module: smallest bugfix, no new responsibility/refactor).

## 3. Test Coverage and Qualification Limits

- **Test (`tests/test_tf_pypi_nebular070_gate2.py`)**: `test_leader_exit_waits_for_group_observation_and_fails_closed_on_retained_group` verifies after leader exit + pipe EOF: (1) group remains until `SIGTERM`/`SIGKILL` (`len(signals) >= 2`) complete across deadlines then disappears (`cleanup_known is True`); (2) retained group stays `False`; (3) `os.killpg` `PermissionError` stays `False`. Real `Popen` flood + timeout and Gate 1 -> Gate 2 tests pass on Darwin; no `RS9_GATE2_FIXTURE_SOURCE_ROOT` override exists in committed tests.
- **Limits**: Prior checks passed 3 Gate 2 tests on Darwin (`Python 3.13.12`) and 2 Linux probes (flood + timeout) in an approved Ubuntu image (`Python 3.12.3`) with `0` orphans and no retained container. Neither proves GitHub-hosted Linux VM PID 1 / subreaper behavior or closes the unattributed `Gate 1 -> Gate 2` `COMMAND_CONTRACT` failure.

## 4. Inert Required-Linux-Nix Runner Proposal

- **Guard & trade-off (`nebular070-nix-userns-policy-proposal.md`/`.patch`, inert)**: Requires `GITHUB_ACTIONS=true`, `RUNNER_OS=Linux`, `RUNNER_ENVIRONMENT=github-hosted`, and `GITHUB_REPOSITORY=Knowledge-Forge-AI/release-starport-9` (rejecting persistent/self-hosted/unknown contexts before host calls). Wraps only Linux `nix` rows inside `Execute non-production nix lane` (`if: ${{ !cancelled() }}`) via `.github/scripts/rs9-linux-userns-apparmor-guard.sh` (`100755`); Darwin keeps the byte-identical direct command; PRoot, unit, publication, permissions, and Nix pins/packages are unchanged. GitHub-hosted runner users already have passwordless `sudo`, so the delta is exposing unprivileged-userns kernel attack surface (`kernel.apparmor_restrict_unprivileged_userns=0`) to lane code for the step duration on a single-tenant ephemeral VM.
- **Lifecycle & proof**: Reads exact `0`/`1` sysctl, sets/verifies temporary `0` only from `1`, runs the quoted command preserving failure status, and restores + verifies original on `EXIT`/`INT`/`TERM` (restoring `0` if mutated from `0`; missing/unknown/unrestored fails closed). Foreground children may defer `TERM`, `sudo -n sysctl` has no separate timeout beyond job timeout, and `SIGKILL` is untrappable; disposable VM teardown is final containment. `git apply --check`, `bash -n`, `11` stub guard tests, and `test_hosted_diagnostics`/`test_workflow_static`/`test_scoped_workflow_graph` (`34` refcopy tests) pass with zero host calls; UID-map correlation is not proof. Bash profile is `Orange` (single owner), pending **explicit user approval**; Nix gates remain mandatory without waiver.

## 5. Verification, Review Sequence, and Rollback

- **Suite & review**: `PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3.13 -m unittest -v` across the `13` Nebular/workflow modules passes `171` tests (`OK`, `PEP 701` valid, `ast.parse` clean on both modified Python files, before/after metadata hashes unchanged, `0` leaked processes). `produce` had one dispatcher-owned Opus `post_work` review; `revise_close` amended the evaluation/proposal docs and inert patch and checkpoints without a second review.
- **Ownership & rollback**: Root owns acceptance, any owner query on the Nix proposal, public commit/PR `#14` CI, and 3-wheel qualification/publication (APGR `v0.1.4` `Jaca` open; AUR deferred). Rollback restores `src/rs9/tf_pypi_consumer.py` and `tests/test_tf_pypi_nebular070_gate2.py` to `HEAD` and removes this evaluation doc; inert policy files stay unapplied pending owner decision.
