# CONT18: guest D-Bus closure and wheel regression diagnostics

Status: terminal source amendment; hosted qualification pending. Existing
Theme Forge generation only. No release, adoption, workflow run or publication
occurred in this stage. The dispatcher owns finalization and the canonical archive.

## Evidence and proposal disposition

The manager evidence verifier passed before evidence interpretation: 18
manifests, 148 retained objects and 172 selected records verified. The 323
omitted objects have not been independently reverified. The complete hosted
summary, exact manager packet, both PRoot evaluations, x86 wheel diagnostic
and run-15 wheel baseline were parsed and inspected. Run 16 remains
`NOT QUALIFIED / HOSTED_GATES`; its previous adoption is complete and must
not be repeated.

Proposal disposition: **amend**. This dispositions the exact 19,693-byte
proposal with SHA256
`4da89666921ac342465fa5db43ec924066575ca67c4f366e55ad8b10bec47ec7`.
The task scope remains independent of the proposal and advisory review.
No stage deltas were recorded before implementation. The amendments are:

- F1: wheel diagnostics and any one diagnostic replay are explicit options
  selected only by the x86 Linux wheel lifecycle. Shared Nix, PRoot, container
  and wheel-client callers retain their existing behavior and timeout.
- F2: retain the existing prohibition on raw process output. Closed causal
  categories, validated problem tokens and stream identities supply evidence;
  raw excerpts and an opportunistic package query are omitted.
- F3 and F4: do not introduce a forwarder with a detached group whose cleanup
  depends on a killable supervisor or a parent-death signal. Single-target
  signal delivery and signal-death status remain independent failures.
  Process-group control does not establish wrapper forwarding.
- F5: D-Bus relative includes resolve from the guest configuration filename,
  rather than the real store target. Required includes and exact daemon
  resolution must be observed; missing or malformed config stays a failure.
- F6: the first failing scenario ends the qualification loop. If C fails,
  C-signal is not executed. One fresh diagnostic replay is labeled
  replay-reproduced, replay-passed or replay-not-run; it cannot establish a
  deterministic cause or turn the original failure into a pass. Malformed
  receipts must become bounded contract failures.

## Preserved qualification and packaging

Run-16 evidence records RPM/DNF 50/50 per architecture, APT 41/41 per
architecture, pacman 40/40, assembled Pages 112/112, Foundation3 2/2,
Darwin Nix 12/12, Darwin and ARM64 Linux wheel lifecycle success, and all
16 BLOCK publication plans with zero production receipts. npm/Homebrew
retain eight exact reads/noops; PyPI versions remain absent.

Raw rpmlint exit 64, RPM preservation restrictions and Linux wheel promotion
blockers remain recorded independently. Production FHS Nix gates, package
recipes, release bytes, wheel builder and tags, Nix pins, revision, workflows
and publication contracts are unchanged.

Both required Linux Nix systems still fail `NIX_FHS_USERNS`. PRoot is a
diagnostic compatibility experiment, never required-Nix qualification or
network isolation. Application qualification and qualification authority
remain false. The complete required lane set remains in force.

## Track A: D-Bus guest configuration

Both run-16 PRoot experiments identify `dbus-run-session`, actual exit 127,
and missing guest `/etc/dbus-1/session.conf`. That causal path is retained;
no next helper failure may be treated as success.

The candidate supplies the pinned store-backed session config through one
guest-root symlink, with a build-time existence check and facts schema v3.
The closed `/etc` gate requires the exact singleton directory and store
target. One fixed audit source checks daemon resolution, transitive includes,
listen/auth settings and service-directory declarations in the real guest;
fixtures execute the same source. Unsafe files, missing required includes,
unreadable present directories and traversal limits fail explicitly. The
cached nixpkgs NAR hash matches the pin; the installed Linux config and its
includes remain native-unproven. The bare-name released smoke argv is retained.
Host `/etc`, `/usr`, the whole store, credentials and ambient GUI sockets
must not be bound. No authenticated release payload or TLS/WebKit sandbox
behavior changes are authorized.

The installed pinned session configuration and its exact transitive includes
have not been observed on Linux. The audit fixtures establish guest-relative
include handling but do not reproduce the complete installed configuration.
SELinux-root-relative include semantics remain unverified; the current guest
exposes no `/sys/fs/selinux` and skips conditional SELinux includes. Do not
extend that filesystem policy without repairing and testing those semantics.
Per-stage `config_identity` values are expected static facts; only the shared
guest audit supplies observed file hashes and daemon/config resolution.

The official [dbus-run-session manual](https://dbus.freedesktop.org/doc/dbus-run-session.1.html)
also documents explicit config and daemon arguments. Their availability does
not prove pinned package layout or native execution. Native hosted readback
must recheck display, D-Bus, observer, released main/sidecar, loader, shebangs,
application smoke, offline denial and WebKit bwrap descendants after repair.

## Track B: signal and wait-status boundary

Run 16 distinguishes deliberate exit 255 from guest signal death. The raw
outer SIGTERM fails to invoke the guest handler; process-group delivery
succeeds and leaves zero observed orphan tracees. Neither observation proves
safe forwarding for the original wrapper. The existing framed wait evidence,
bounded waits, exact created-group cleanup and explicit orphan failures stay
in place. No 255-to-signal mapping is introduced.

The proposed detached-group forwarder has unresolved cleanup and ownership
risks under supervisor SIGKILL and escaped descendants. PRoot source access
and native substrate behavior must be verified before selecting a repair.
Until that is established, keep the diagnostic failure explicit and keep
required-Nix qualification blocked. The original passing paths are not
placed under a new supervisor.

## Track C: unresolved x86 wheel regression

Run 15 passed the original x86 wheel lifecycle. Run 16 failed Nebular
`APPLICATION_SMOKE` with exit 1, nonempty stdout identity and empty stderr;
Burst native loading and other wheel lifecycles passed. Run-16 source changes
did not change the wheel builder. The retained hashes cannot identify the
scenario or causal process output. No artifact corruption, missing library
or transient cause is assumed.

The candidate diagnostics preserve scenario, process exit/signal status,
bounded receipt identity even on process failure, validated problem tokens,
safe stream categories and retained-log failures. Every original gate attempt,
including x86 with diagnostics enabled, keeps the legacy `subprocess.run`,
240-second timeout and `xvfb-run -a dbus-run-session --` argv. A passing original
attempt starts no diagnostic replay. Only the replay adds the Xvfb error-file
option, caps captured streams and kills its created process group on completion,
timeout or output overflow. Escaped descendants are not claimed absent. No raw
logs, credentials or runner paths enter
retained evidence. Corrupt, oversized or unsafe receipts and logs remain
observable failures. Nonzero exit and timeout never become passes.

One targeted probe is available for a future attended run 17: replay only the
first failed x86 wheel smoke scenario once, in a fresh evidence directory,
using the same released script, prefix, environment and application timeout,
with a separate error file and the explicitly different replay supervisor.
The replay is not equivalent to the original gate and cannot distinguish a
regression resolution from an effect of instrumentation. Unsupported Xvfb
error-file options may introduce a replay-only failure. The original
gate remains failed even if the replay passes. If the regression does not
reproduce, its cause remains unresolved. Native provider proof is still owed.

Closed categories and validated problem tokens can still withhold the cause:
free-form receipt problems become `withheld-token`, and unmatched output is
`unclassified`. The diagnostic explicitly records `cause_withheld_or_unresolved`;
`process-nonzero` alone is not a causal explanation. Released problem-format
compatibility is unverified. A cause withheld or unresolved is an expected
possible run-17 outcome, not permission to publish raw logs or weaken the gate.

Replay cleanup permission denial is recorded separately from raw child status.
The supervisor attempts its bounded child wait even after group-signal EPERM;
a reap timeout is `process-reap-timeout`, distinct from the application deadline.
Cleanup failures cannot produce `replay-passed`. Under the privileged Linux
prefix, successful reaping and absence of remaining group members are still
native-unproven; a failed cleanup remains a diagnostic failure and requires
exact owned-resource disposition before any subsequent execution.

## Track D: Pages attended read-only remediation

The launcher's fresh GET-only readback records the exact public CNAME
`rs9.knowledge-forge.ai` to `knowledge-forge-ai.github.io`. Pages API settings
are unavailable. Hosted origin observation remains unknown after certificate
hostname verification code 62. No current Pages association or certificate
SAN is inferred from DNS.

An authorized operator should inspect the repository Pages custom-domain
association and certificate state in the attended UI, compare public CNAME
and origin routing, and inspect the currently served certificate with normal
hostname verification. Record public findings and any missing permission.
Any proposed configuration repair needs separate authorization. This stage
changes no DNS, Cloudflare or Pages setting, uploads no candidate, bypasses
no certificate check and requests no credential. API unavailability does
not block independent source repair.

## Verification and manager handoff

Verification records belong in
[cont18-verification.json](../evidence/live1/cont18-verification.json).
The candidate inventory belongs in
[candidate-manifest.json](../operators/live1/candidate-manifest.json).
Full source suites are required under umasks 022 and 077 with ResourceWarning
as error, plus focused changed-boundary tests, safe file/mode and credential
checks, exact inventory, import guards and `git diff --check`.

Producer verification on Darwin/Python 3.13.12 passed under both umasks:
1,873 discovered methods, 1,842 passed and 31 skipped per suite, with zero
failures, errors or ResourceWarning messages. The runner reports 1,863 tests
and 22 skip records because class-level skips cover multiple methods. Focused
PRoot checks ran 156 tests (155 passed, one Darwin skip); wheel/operator/hygiene
checks ran 57 tests, all passed. Guarded collection started no subprocess or
origin request. All 282 Python files and the exact guest source compiled;
Nix syntax parsing passed. These are source and disposable-process results,
not hosted PRoot or released Linux wheel proof.

The initial scratch runner omitted the repository import root; that harness
failure was corrected before both accepted full-suite runs. Existing source
modes remain owner-readable without group/world write or special bits. The
Git index byte digest drifted during work, with cause unproven; staged entries
still match HEAD and no explicit staging, commit or push occurred. Optional
Git refreshes were disabled for remaining checks. No further producer source changed after those
accepted producer suites; terminal amendments and fresh closeout verification
are recorded below.

The dispatcher pre-final independent cumulative review returned advisory
findings. Terminal disposition: **amend**. Work-review F1 is corrected by keeping
the original x86 gate on the legacy process/argv path; F2 by preserving child
status and attempting a bounded wait after group-signal permission denial; F3
by explicit withheld/unresolved cause reporting; F5 by removing the unused
replay parameter. F4's exact installed-config and SELinux fidelity remains
deferred to native readback under the existing closed guest filesystem policy.

Closeout amended source/test paths are `src/rs9/application_smoke_diagnostic.py`,
`tests/test_application_smoke_diagnostic.py` and `tests/test_hosted_smoke.py`.
It also updated this handoff, `evidence/live1/cont18-verification.json` and the
candidate manifest. These terminal revisions receive no further independent
review under the dispatcher contract. Fresh closeout checks and counts are
recorded separately from the producer evidence in the verification record.
The canonical APGR ZIP and receipt remain dispatcher finalization outputs;
no provider-local archive is represented as canonical.

Fresh closeout verification on Darwin/Python 3.13.12 passed under umasks 022
and 077 with ResourceWarning as error: 1,878 discovered methods, 1,847 passed
and 31 skipped per suite; the runner reports 1,868 tests and 22 skip records.
Both runs have zero failures, errors or ResourceWarnings. Focused changed
boundaries passed 179 tests; the diagnostic suite passed 25 tests. Compilation
of 282 Python files and the fixed guest source, guarded collection of 1,878
methods, Nix parsing, 310 relative links, 498-file credential/mode checks and
`git diff --check` passed. The closeout index snapshot is unchanged and staged
entries match HEAD. These checks establish source and disposable-process
behavior only. Report and inventory metadata were refreshed afterward.

For one possible future nonproduction hosted run 17, the manager must accept
the final tree, manifest SHA256 and partial-diagnostic attestation. Use the
existing attended contract through
[run-hosted17.py](../operators/live1/run-hosted17.py); do not invoke it in this
stage. Preserve all required lanes, both PRoot experiments, wheel diagnostics,
config audit, signal/wait/orphan records, package receipts and origin evidence.
Stop for manager disposition after collection. Never repeat run-16 adoption.

`candidate_adoption_ready`, `full_live1_qualification`,
`published_linux_nix_ready`, `production_enabled` and `publication_authority`
remain false. The known blockers are required Linux Nix userns, native PRoot
application and signal semantics, unresolved x86 wheel smoke, origin TLS
hostname verification, and the preserved RPM/Linux wheel promotion limits.
