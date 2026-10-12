# LIVE1 CONT21: experimental build staging and original Pages smoke diagnostics

## Status and authority

Source-only terminal candidate. Run 19 remains **NOT QUALIFIED / HOSTED_GATES**.
No hosted run 20, package rebuild, new release, adoption replay, commit, push,
publication, deployment, Pages/DNS change, or host security change is authorized
by this candidate. The dispatcher owns Git finalization and the canonical receipt.

The dispatcher-bound producer tree
`46e6956fed6523b8c272d9d1f51185837cf2b421` is **amended** after its advisory
cumulative pre-final review. All 17 supplied cumulative product paths are
accepted within the source-only scope. Earlier proposal and plan-review custody
remain in `evidence/live1/cont21-input-evidence.json`; closeout findings and
verification are in `evidence/live1/cont21-verification.json`.

The evidence verifier passed: 167 selected records, 18 manifests, 143 present
objects rehashed, and 323 omitted objects. The independent upload is identical
to the inner operator ZIP. Omitted bulk binaries are not independently
authenticated by this packet. The original PRoot artifact ZIPs and separately
retained run-18 evaluations were inspected without changing them.

The preceding manager observed remote-main parity. The initial shell check
failed at GitHub DNS resolution. A later read-only GitHub connector GET of
`branches/main` confirmed parity with the local CONT20 commit and tree before
pre-final handoff. It does not retrospectively make the initial check successful.
Live local semantic checks established `main`, the CONT20 source, and preserved
unrelated local state. No historical commit identity was recreated as a gate.

## Experimental Nix source repair

CONT20 introduced `builtins.readFile ../src/rs9/nix_proot_dbus_pin.py`, while
`hosted_nix.prepare_input` stages only `flake.nix` and `nix/`. A test runs that
actual staging boundary, shows the referenced file absent, then stages exactly
the fixed pin file and verifies every upward Nix source reference resolves.
This demonstrates a source staging defect. It does not reconstruct run 19's
stderr or prove that this was its sole cause.

The experiment now stages the exact single-line, bounded physical pin file.
Malformed grammar, altered digest, missing input, symlinks, and mismatched staged
evaluator inputs fail before Nix execution. The actual staged flake and experiment
expression are bound to repository hashes. The full D-Bus main policy and digest
`206f009ddcf909422f3651c687b4623a5780fb7486c6d650e5332f57c00d6be1`
remain unchanged. The optional legacy `/etc/dbus-1/session.conf` remains absent;
it never aliases the main file. No Nix expression or release bytes are changed.

The shared Nix command helper gains an optional failure callback. Production
callers do not opt in; tests preserve their exact existing error projection.
Only experiment metadata/build calls opt in. The callback observes the captured
original stream once, never replays the producer, and cannot overwrite the code,
exit status, substage, or stream hashes. Diagnostic write failures preserve the
original failure. Success creates no failure record.

`diagnostics/nix-build-failure.json` is an exclusive, no-follow 0600 record of the
first producer failure. A bounded closed classifier distinguishes evaluator
path/attribute/assertion patterns, builder failure, fixed-output hash failure,
fetch failure, permission/sandbox observations, conflicts, and unknown or invalid
streams. It stores no prose or arbitrary paths. Only the fixed source-relative
pin path and fixed guest-root derivation name can be projected. Secret-bearing,
truncated, malformed, absent, and empty streams withhold causal fields as
appropriate. Full captured stream hashes remain evidence of bytes, not causes.

The guest-root synthetic `sha256sum -c` builder control is classified as
`builder-failed` with its fixed derivation name, distinct from the staging defect.
That alone
does not prove a pin mismatch. The actual Linux build, store-file availability,
full policy digest check, and subsequent runtime behavior remain untested.
Local Nix reports 2.31.5; the lane pins 2.31.2. Source-pinned local evaluation is
unavailable, and no store import, evaluator-cache mutation, or diagnostic replay
was performed in this stage.

Closeout calibrates the plain-text missing-file and builder-exit formats against
[Nix 2.31.2 file operations](https://github.com/NixOS/nix/blob/2.31.2/src/libutil/file-system.cc),
[builder error construction](https://github.com/NixOS/nix/blob/2.31.2/src/libstore/unix/build/derivation-builder.cc),
and [process status formatting](https://github.com/NixOS/nix/blob/2.31.2/src/libutil/unix/processes.cc).
The tests use messages derived from those sources, not captured run-19 stderr.
Dependency failures stay unknown; conflicting, colored, incomplete, or
secret-bearing streams withhold causal projection. This establishes parser
coverage for those formats, not source-pinned evaluation or builder success.

Both original run-19 experiment records stop at `NIX_EXECUTION`, `nix-build`,
exit 1, with empty stdout and stderr digests only. Their nine failed gate rows
are early-stop consequences. There is no run-19 D-Bus acceptance, signal,
WebKit, or offline application evidence. Run 18 reached four passing/five failing
runtime gates and observed recursive legacy inclusion, with causality still
explicitly unproven. PRoot remains neither an isolation boundary nor application
qualification. No signal-status synthesis is introduced.

## Assembled Pages APT observation gap

Run 19 standalone DEB amd64 passes 41/41. Pages passes 110/112; the only failures
are Nebular's APT smoke client gate and aggregate APT gate. Signed repository
trust, refresh, install/query, cleanup/inventory, other APT products, and Pages
DNF/pacman controls pass. No package or trust repair is demonstrated.

The actual boundary is `hosted_deb.execute_pages` through `_pages_client_tests`
and `client_cycle`, then `verify_container_nebular`, `guest_main`,
`verify_nebular_runtime`, and `execute_application_smoke`. The task-named
`hosted_pages.py` and `hosted_native_client.py` do not exist in this repository.

The original smoke uses `subprocess.run` with the existing argv, a 240-second
timeout per scenario, `xvfb-run -a dbus-run-session -- node`, a fresh disconnected
container as uid 65534, and `HOME=/tmp`. The immutable authenticated source and
installed runtime are verified before smoke. APT provisioning uses floating
archive dependency versions over a source-pinned base image. Dependency-version,
display/session state, and complete smoke stream text are absent from run 19.

The candidate retains a closed observation of that original attempt through the
guest result, host diagnostic, and client failure projection. No raw excerpts,
retry, fixture substitution, or success conversion are introduced. The
family-specific `application-smoke-failure-<family>.json` is an exclusive,
no-follow 0600 record; missing counts/hashes stay unknown and writer failure
cannot mask the unsuccessful smoke. It intentionally retains only the first
failure per family in a lane scratch; later failures cannot overwrite it and
still fail their original gates. Inventory
counters are labeled with the actual last inventory stage: successful install
followed by cleanup ordinarily leaves `post-remove`, while earlier failure can
leave `pre-install`. Counters do not diagnose the smoke process.

A separate bounded read-only, disconnected, disposable image probe records the
immutable image ID and strictly parsed versions of GTK, WebKit/JavaScriptCore,
libc, Python, Xvfb, and D-Bus packages when available. It disables image pulling
and uses no package-manager mutation. Closeout gives the disposable probe a
unique name and always attempts bounded removal of that exact container,
including after a timeout. Cleanup remains explicitly unconfirmed if removal
fails or if automatic removal cannot be independently confirmed. Probe receipts are excluded from gate
execution accounting and occur outside both inventories. Malformed, incomplete,
or unavailable probe data never changes qualification. Request, source-record,
and installed-manifest hashes bind the deterministic smoke context.

Return code, exit status, and signal describe the outer process only. Deliberate
255 and 143 remain exit codes; negative return codes identify an outer signal.
A null signal proves nothing about inner D-Bus/PRoot signal propagation.
Diagnostic observation and any separately labeled existing wheel replay do not
alter the original unsuccessful gate result.

The shared application-smoke diagnostic projection also affects wheel, DEB,
RPM, and pacman failure details: signal deaths now use `process-signal`, absent
values are omitted, and scenario, cause, and elapsed time are included. These
are diagnostic serialization changes; the original subprocess, gate outcome,
and retry policy are unchanged. Complete original observations travel separately
from the bounded error-details projection.

The recorded run-19 runner facts match across the two APT lanes. Retained
runtime-root, sidecar binary/manifest, expected manifest, mismatch counts,
successful released verifier and import-preflight identities also match.
Provisioned image and setup hashes differ across lanes and runs 18/19. These
observations establish neither version drift nor nondeterminism. The cause stays
unobserved; this candidate makes no speculative smoke harness repair.

## Verification and handoff

`evidence/live1/cont21-verification.json` records the observed source checks,
warning-as-error runs under umasks 022 and 077, incumbent test preservation,
worker disposition, and limitations. The candidate manifest inventories the
complete product source while excluding itself and preserved operational state.
Terminal tree, manifest digest, and exact changed-file count are returned in the
bounded dispatcher candidate summary, avoiding a self-referential tree record.

Before pre-final review, both full source suites passed with warnings treated as errors under umasks
022 and 077: 2,053 tests reported each, zero failures/errors, 22 skips, and no
unraisable exceptions. The source/test inventory digest matches across both
runs. These are runner counters: a class-level skip is reported separately from
tests actually executed. The seven incumbent `DisjointFilesystemTests` remain
in the suite with unchanged method ASTs. Source tests
can validate custody, failure propagation, adversarial parsing, and control
behavior; they cannot qualify an omitted release binary or native application.
Both dispatcher-owned reviews are advisory with findings. Closeout accepts the
staging repair with native verification deferred, adds the source-derived Nix
format controls, repairs probe cleanup and the null inventory-stage fallback,
and connects the Pages family control through the real host output validator
and diagnostic writer over scripted guest receipts. The connected controls
preserve exactly the original failing gates and one attempt; the passing
control creates no failure record. This is source orchestration evidence, not
Docker execution or installed-application qualification. The signing-dependent
assembled-tree test remains skipped in the recorded producer runs.

These source/test corrections, this handoff, verification evidence, and the
candidate inventory were edited after pre-final review. No further independent
review was requested or obtained. Terminal warning-as-error verification is
limited to the affected Nix, smoke, installed-client, and source-custody tests
under umasks 022 and 077: 517 affected source tests per umask, zero failures or
errors, two expected skips, followed by 13 inventory/readiness/hygiene tests per
umask with no failures, errors, or skips. The complete source suite was not
rerun after these edits. Exact terminal counts and skips are in the verification record. Native
Nix evaluation/build, D-Bus acceptance/signals, WebKit/offline application checks,
and native Pages Nebular smoke remain unrun locally.

Required Linux Nix remains `NIX_FHS_USERNS` / `uid-map-denied` on both systems,
with dependent gates not run. Public HTTPS remains certificate hostname failure
62, state unknown. Raw rpmlint remains exit 64, and the RPM preservation and
Linux-wheel production compatibility restrictions remain promotion blockers.
Foundation3 keeps 16 blocked plans and zero production receipts. All production,
publication, full qualification, and published Linux Nix readiness flags remain
false. The manager decides whether to authorize subsequent native execution
after reviewing the canonical dispatcher ZIP and receipt.
