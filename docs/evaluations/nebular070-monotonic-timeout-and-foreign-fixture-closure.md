# RS9 Nebular 0.7.0 Monotonic Timeout and Foreign-Fixture Path Closure

## 1. Scope, Baseline, and Prior Checkpoint

- **Baseline**: Public PR `#14` `HEAD` `4f8ad21f751fb362e6e515c1516330f81fd5e96a` (tree `c0afc6d470155b520bce429dea46c22fcf7ca168`; `170` Darwin tests passing; `0.6.1` API compatible).
- **Prior checkpoint**: All three worker drains closed (`uncertain_cleanup: false`). Its Opus review accepted the narrow cleanup-reporting fix (`cleanup_known` after leader reap + pipe EOF) and doc/patch amendments, identifying two gaps:
  1. Non-monotonic termination deadline in `_nebular_run`: a `SIGTERM`-ignoring leader reset `cleanup_deadline` each turn, postponing `escalate()` (`SIGKILL`) forever.
  2. Hosted Linux `Gate 1 -> Gate 2` `TF_PYPI_NEBULAR_COMMAND_CONTRACT` (`require_clean`) unit failure, unattributed by flood/timeout probes.
- **Owned 6-path scope**:
  1. `src/rs9/tf_pypi_consumer.py`: `1d4b6f8e...` (`76,092` B) -> prior `e34ef4b3...` (`76,933` B) -> final `5dc920c9f2535b505fe18e3dea06a116d4e441c4b6719a6f15217098b5d32df0` (`77,181` B, `1,537` lines).
  2. `tests/test_tf_pypi_nebular070_gate2.py`: `4d2d472a...` (`84,972` B) -> prior `e479aabe...` (`87,676` B) -> proposal 2 base `80ce8788...` (`91,318` B) + patch `a29a34b7...` (`1,560` B) -> final `a38bd1ae4027439404ec23d1955f50c7ffc326241404ce4458b8c1ab18878ea0` (`91,337` B, `1,686` lines).
  3. `docs/evaluations/nebular070-linux-process-cleanup-closure.md` (`dc156f7b5da658a353323e29834c95f42ba16713ddfb373d8d91d2bfcd7f8fea`, `7,973` B; historical/inert, byte-identical).
  4. `docs/evaluations/nebular070-nix-userns-policy-proposal.md` (`13a0145ce93691c1558a7d59a4c05c15d73ada4d3195d0fcf8affe72dc72aad0`, `4,398` B; inert, byte-identical).
  5. `docs/evaluations/nebular070-nix-userns-policy-proposal.patch` (`137b4877502a9f53aabc85287c78bf2effcf1c20bd0d2c47d32c51ef828ed846`, `13,487` B; inert, byte-identical).
  6. `docs/evaluations/nebular070-monotonic-timeout-and-foreign-fixture-closure.md` (this closure).
- **Invariants**: `.github/workflows/rs9-candidate-tests.yml` (`0b5582b18bcb561257239d9fa6512e9c8b8852d4d46ddd21b343a01abdc1cab7`) and `.github/workflows/rs9-tfnf-pypi-publish.yml` (`98e51826ab03f3fc1bd1438a3d92bb67caef88c5147f34aa188a1df6491b415a`) are unchanged; no guard script/test materialized; no dependency, lock, workflow, native build, policy activation, or git/CI publication.

## 2. Monotonic Termination Grace Deadline Fix

- **Production (`src/rs9/tf_pypi_consumer.py:254-256, 872-936`)**:
  - Layers on the EOF/group-observation fix (`post_exit_deadline`/`cleanup_deadline` wait before EOF break, single `kill_sent` exit path, and `wait_for` sleep when `not streams and not events`).
  - Adds `_nebular_grace_deadline(current, now)` (`current if current is not None else now + _NEBULAR_TERMINATION_GRACE`) in `request_termination`, retaining the **first** termination deadline across recurring timeout/output checks so `escalate()` (`SIGKILL` + post-`SIGKILL` observation window) fires after `0.5`s.
  - Constants (`0.5`s graces), caps (`1 MiB`/`64 MiB`), `start_new_session=True`, PID checks, `forced_cleanup` rejection, and `cleanup_known` observed-absence semantics (`os.killpg(child.pid, 0)` `ESRCH`) are unchanged; the `>= 0.5`s clean-probe delay and `~1 ms` cleanup polling (`~500` wakeups/0.5s) remain documented tradeoffs.
- **Tests (`tests/test_tf_pypi_nebular070_gate2.py:922-1001`)**:
  1. `test_termination_grace_deadline_is_not_postponed_by_repeated_checks`: Deterministic first-deadline state check (`_nebular_grace_deadline(first_deadline, repeated_now) == first_deadline`; not a substitute for real loop coverage).
  2. `test_term_ignoring_leader_reaches_sigkill_and_exact_group_is_absent`: Real child (`timeout=1`) ignores `SIGTERM`, prints `PID:PGID`, and sleeps `30`s. Private `runner=capture_runner` captures `Popen` in `try/finally`, binds printed `leader_pid == captured_child.pid == group_id`, and asserts `timed_out`, `forced_cleanup`, `signal == SIGKILL`, `cleanup_known`, `duration_ms < 5000` (behavioral vs `30`s sleep, not an outer hard timeout), and `os.killpg(group_id, 0)` `ESRCH`. Fallback signals in `finally` only while `poll() is None` with verified leader PGID, never signaling a reaped/absent group.

## 3. Foreign-Fixture `--path` Platform-Guard Fix

- **Root cause & fix (`tests/test_tf_pypi_nebular070_gate2.py:1282-1286, 1557-1580`)**:
  - `NebularGate1ToGate2Fixture` builds `self.handoffs` in exact order `("darwin-arm64", "linux-x64-gnu")` (two cases, not three).
  - `fixture_runner(self, target)` previously bypassed `_platform_check()` only for `target.startswith("linux") and "--path"`. Hosted Ubuntu hit `darwin-arm64` first: `--version` succeeded, `--path` exited `1` at the real Darwin platform guard, and `require_clean(path_probe)` (`1437-1441`) failed with `TF_PYPI_NEBULAR_COMMAND_CONTRACT`.
  - `fixture_runner` now applies its **existing** temporary `_platform_check()` bypass to `--path` for every synthetic target (`if "--path" in [str(value) for value in argv]:`) with a host-neutral non-qualifying docstring. Production launcher guards, non-fixture admission, `require_clean`, wheel materialization, hashes, and native checks are unchanged.

## 4. Supporting Packets, Reconciliation, and Qualification Boundaries

- **Monotonic packets (`RS9-NEBULAR070-MONOTONIC-TIMEOUT-PROPOSAL1` & `PROPOSAL2`)**: Proposal 1 passed `4/4` focused cases (`8.291s`); Proposal 2 passed `2/2` focused cases (`2.025s`; raw logs in packets).
- **Linux `--path` diagnostics (`Diagnostic 1` & `RS9-NEBULAR070-LINUX-PATH-PROBE-DIAGNOSTIC3`)**: Diagnostic 1 stopped before `--path` because immutable Ubuntu image6 (Python `3.12.3`) lacks `pip` (no dependency added). Diagnostic 3 used a private stdlib materializer (`read_wheel`) for the locally generated Darwin fixture wheel (`18` members/modes) on image6 (`--network none`, read-only rootfs; container absent verified). Original helper on `darwin-arm64` `--path`: `returncode=1`, `cleanup_known=True`, `forced_cleanup=False`, `timed_out=False`, `platform-guard` stderr (triggering consumer `require_clean` `TF_PYPI_NEBULAR_COMMAND_CONTRACT`). Host-neutral helper: `returncode=0`, clean state, empty stderr (`native` probe not invoked). Proves the isolated synthetic cross-host `--path` mechanism with the production guard unchanged, **not** `pip install`, full fixture, native, or hosted CI qualification; fresh GitHub-hosted Linux unit CI remains pending.
- **Reconciliation (`RS9-NEBULAR070-POSTIMAGE-RECONCILIATION-DIAGNOSTIC4`)**: Reconciled wrong prospective digest `cbb5faa6...` (extra closing `"""` on opening docstring line; stopped before tests): base `80ce8788...` (`91,318` B) + patch `a29a34b7...` (`1,560` B) yields `91,337` B / `a38bd1ae...`.
- **Actual Mac full suite (`RS9-NEBULAR070-FINAL-PROBE-FIXES-PREP1`) & review**: Base `4f8ad21f...` with only these two tracked changes (`5dc920c9...`, `a38bd1ae...`) and no staged changes passed **`173` tests across `13` modules in `49.143s` (`OK`)** under pinned Python `3.13.12` (`300`s, `5 MB`/`10 MB` caps, owned-group runner; `result.json` `d023f63ab1a6b73b4cc4b29b580fd3ce7d02c948e44724ef9695c7556641cf2a`), reused after verifying exact hashes and `ast.parse`. One dispatcher-owned `post_work` review found zero blocking defects; `revise_close` amended this closure and kept the five frozen files unchanged (no second review).

## 5. Inert Nix Policy, Python Profile, and Rollback

- **Inert Nix proposal (`RS9-NEBULAR070-NIX-USERNS-POLICY-OWNER-READY1`)**: Remains **inert** pending owner decision in root; root owns later activation. Frozen patch `137b4877...` keeps one workflow step name/`if`, branches Linux guard (`875855d2...`) vs Darwin direct inside `run`, and passed `git apply --check`, `bash -n`, and `34` reference tests (`11` stub guard + `5` hosted diagnostics + `16` workflow static + `2` scoped graph; no second Opus review covered those workflow/test corrections). Tradeoff: disposable GitHub-hosted Linux only, temporary unprivileged-userns surface, verified restore on normal exit/handled signals, foreground-child signal deferral, `sudo -n sysctl` bounded only by enclosing job, VM teardown on `SIGKILL`/job timeout; no Nix gate waiver.
- **Python profile & rollback**: Bounded `Red` legacy size exception (`1,537`/`1,686` lines) for smallest cohesive bug fixes; decomposition deferred. Root owns final acceptance, source promotion/fresh public Linux CI, and 3-wheel publication (`APGR v0.1.4` `Jaca` S1 open; AUR deferred). Phase rollback restores the two tracked files and removes this closure doc while keeping the three historical/inert files.
