# CONT19: bounded PRoot D-Bus and signal diagnostics

Status: terminal source closeout, disposition **amend**. The dispatcher supplied
an independent cumulative review with no blockers and five advisory findings.
Native qualification remains pending. This stage did not adopt source, run a hosted workflow, commit,
push, publish, change Pages settings, or change DNS.

## Scope, inputs and proposal disposition

Proposal disposition: **amend**, against the bound 15,666-byte proposal SHA256
`4d56c4f2bc276f1edf45377f5fe9a38c69e6fec6e8a60aa544599105d402623a`.
The original assignment remains authoritative. No stage deltas were recorded
before implementation. The plan review was advisory, with no blocking findings.
All seven findings were addressed: session-independent descendant observation;
traceback continuation and separate PRoot advisories; verified evidence before
interpretation and no uncited message templates; explicit stream truncation,
address withholding and owned-child reaping; captured signal stderr; independent
socket controls; and serialized credential scanning with physical packet readback.
These responses do not satisfy the dispatcher pre-final review checkpoint.

The manager verifier succeeded before interpretation: 171 selected records,
18 manifests and 147 included selected objects verified. The 323 omitted objects
were not independently rehashed. Complete PRoot documents for both Linux systems,
the hosted summary, manager packet, first-failure summary and continuation were
loaded. [Input provenance](../evidence/live1/cont19-input-evidence.json) records
their identities and the limits of source inspection.

## D-Bus: observed boundary and next causal readback

Run 17 proves the pinned config and daemon identities on both architectures.
The same 3,561-byte config has SHA256
`206f009ddcf909422f3651c687b4623a5780fb7486c6d650e5332f57c00d6be1`.
The audit records a root include of `/etc/dbus-1/session.conf` resolving back to
that same config. This is an observed self-include, not proof of what the daemon
reported. The audit traversal skips visited paths; its pass does not establish
native acceptance of cyclic includes. A separate include-structure diagnostic
now states that distinction without changing the historical identity audit.

The earliest failed positive control remains pinned `dbus-run-session --`
followed by pinned Python with `-I -S -B -c` and the socket observer, at guest cwd
`/tmp`. Xvfb alone passes. Each architecture has raw exit 127 and complete
149-byte stderr, with architecture-specific hashes. The retained packet does
not contain those stderr bytes. Their content was neither reconstructed nor
inferred from a digest. The exact failure remains unclassified.

The outer invocation uses `sudo -n`, an offline network namespace, privilege
drop and empty environment before the existing pinned PRoot prefix. Guest stdout
and stderr remain separate files. The guest stderr can contain output from more
than one process, so a prefix is recorded as an observation rather than proof of
which executable wrote it.

Failed original launch receipts now retain closed stderr diagnostics with stage,
argv identity, raw status, byte count, SHA256, completeness, prefix observations
and errno tokens. Invalid, truncated, conflicting or mixed causal streams cannot
identify a cause. Excerpts require valid text, a closed safe format, privacy
redaction and scans of both raw text and final serialized output. Unknown D-Bus
messages are withheld because pinned message templates could not be inspected.
This is an explicit evidence limitation, not a guessed classification.

After a failed D-Bus-only control, nine bounded controls distinguish executable
startup, path and abstract socket binding, daemon startup with its default versus
explicit config, cwd dependence, session orchestration and the original target.
Each has a 15-second outer deadline; daemon startup has a five-second address
deadline and bounded exact-child termination/reaping. Address bytes stay local.
Daemon stderr frames include an explicit truncation flag and raw waitpid status;
frames with duplicate, unknown or contradictory fields are rejected. PID/start-time
survivor checks are read-only and grant no signal authority. Missing lifecycle
readback remains unobserved. Control results cannot qualify main, WebKit or smoke.
The added `daemon-minimal` arm creates and removes a private temporary config with
no includes, EXTERNAL authentication, one Unix listener and a deny-only policy.
It starts no application client and never replaces `/etc/dbus-1/session.conf`.
Its config SHA and command binding are retained. A successful minimal control
contrasted with failed original controls would narrow the boundary to config-dependent
startup; it would not prove that the self-include caused the original message.
An empty `/proc/comm` daemon list is explicitly unobserved and cannot establish
that no daemon spawned.

The [official run-session manual](https://dbus.freedesktop.org/doc/dbus-run-session.1.html)
documents internal-error exit 127, target exit propagation and explicit daemon/config
options. The [daemon manual](https://dbus.freedesktop.org/doc/dbus-daemon.1.html)
documents nofork, address output and include semantics. These references are not
an authenticated copy of pinned 1.14.10 source. The pinned Nixpkgs recipe was
read back and hash-matched to CONT18; fetching the pinned upstream archive/source
was unavailable. No message template or native causal claim rests on recollection.
No guest config, binding, derivation or pin was changed. Removing the self-include
is deferred until actual daemon evidence and reviewed correction support it.

## Signals and wait attribution

Raw deliberate exits 0, 7, 42 and 255 remain separate from actual signal death.
The guest framed wait arm remains non-authenticating diagnostic evidence, with
source/run/argv binding and no status mapping. Invalid or missing frames cannot
create a collapse attribution. Only a valid observed SIGTERM wait paired with
raw 255 receives the observed-collapse token; it remains a failed gate.

The external probe still targets the exact outer Popen process. The separately
signaled owned process-group control never qualifies that target. New read-only
descendant observations cross sudo session changes and bind PID identity by
kernel start time before delivery and survival readback. Missing masks are
unknown, not false. Names, command lines and exception text do not enter receipts.
Signal stderr uses an anonymous host-owned file, monitored against a 4,096-byte
bound. Timeout and truncation cannot create a complete causal receipt.

A Linux-only native-prefix self-SIGTERM arm records the same offline-prefix
status without PRoot; it cannot repair or qualify the PRoot result. Upstream
[PRoot v5.4.0 event.c](https://github.com/proot-me/proot/blob/v5.4.0/src/tracee/event.c#L264)
shows default ignored terminating signals and exit-status updates only for normal
tracee exit. This supports investigation of the planner hypotheses, but the tagged
file was not authenticated against the recursive pinned source hash and does not
prove the hosted wrapper's responsible layer. No supervisor or forwarder was added.

## Preserved results and authorization

Run 17 remains NOT QUALIFIED. Required Linux Nix fails `NIX_FHS_USERNS` on both
architectures; its dependent required gates remain not-run. PRoot remains
experimental diagnostic-fail. Main and WebKit remain unobserved; no bwrap or
WebKit sandbox policy was weakened. Released native/sidecar bytes are unchanged.
The x86 Linux wheel passed in run 17; its prior regression was not reopened.
RPM/DNF 50/50 per architecture, APT 41/41 per architecture, pacman 40/40,
assembled Pages 112/112, Foundation3 2/2, Darwin Nix and all wheel lanes remain
the manager's green observations. Raw rpmlint exit 64 is still distinct from
candidate-preservation exceptions. Both production-promotion blockers remain.

The optional [Pages readback](../evidence/live1/cont19-pages-readback.json) confirms
the intended CNAME and unavailable Pages-settings access. It does not supersede
run-17 direct TLS hostname verification failure 62. The assembled candidate is
unpublished. Pages follow-up has separate authorization.

The next hosted readback is `launch_chain.stages[*].stderr_diagnostic`,
`dbus_config_include_structure`, `dbus_decomposition`, and the signal stage's
native-prefix, observed-layer, survival and bounded stderr details on both systems.
Manager alone may authorize one later nonproduction run 18 after source review.
The run-18 shim preserves the shared external-attestation contract and was not
invoked. All five readiness/publication flags remain false.

## Verification and review boundary

[Verification](../evidence/live1/cont19-verification.json) records producer source
tests, warning policy, hygiene and preservation checks. Synthetic receipts and
disposable local child-process tests do not constitute Linux PRoot qualification.
Native Linux daemon, ptrace, wrapper delivery and released application execution
were not performed here. Initial broad runs exposed stale manifest metadata,
a private-path fixture and two expected duplicate-ZIP fixture warnings. Metadata
and fixtures were corrected; the warnings are now asserted explicitly without
weakening the runner's warning policy or changing packaging behavior.

The reviewed producer's complete suites succeeded under umasks 022 and 077 with warnings as
errors: each discovered 1,928 methods and reported 1,918 runner tests, 22 skip
records, zero failures, zero errors and zero unraisable exceptions. The focused
adversarial suite reported 78 tests with one Linux-only skip. Compilation covered
291 Python files and seven fixed guest sources without writing bytecode. The
credential scan covered all 511 candidate files. The index, 491 unrelated tracked
files, 166 existing operational files, tracked modes and Nix/pin files were
preserved; `git diff --check` passed. A final correction also makes exit-zero
session controls with missing observation frames unobserved. Only documentation,
verification metadata and inventory are finalized after these full source suites.

Two bounded Gemini workers were used, both with proven cleanup. Parent integration
amended their stderr and process observation code for privacy, completeness and
PID identity checks. Python profile decision: Orange for bounded diagnostic
process management and legacy-module edits; new logic is isolated, with adverse
and disposable-process tests. Rollback removes optional diagnostic modules and
their call sites; the original qualification contracts and pins remain intact.

The dispatcher owns review checkpoints and finalization. The supplied pre-final
review found no blockers and five advisories. Closeout disposition is **amend**:

1. Address the causal-readback limitation with the temporary no-include daemon
   control recommended by the review. Exact pinned message recognition remains
   deferred: neither the archive nor tagged source was accessible, and the original
   149-byte stderr is absent from the selected packet. No message was guessed.
2. Name simultaneous default/explicit control failures as
   `default-and-explicit-daemon-controls-failed`, without implying config specificity.
3. Treat an empty daemon identity list as unobserved, retaining the `/proc/comm`
   identification limit and no-absence-proof marker.
4. Settle observed descendant exits for at most 0.9 seconds before forced cleanup;
   label that observation phase and make incomplete or unreadable survival records
   unobserved. The later owned-group cleanup remains separate.
5. Defer authentic native timeout, interruption and signal qualification to a later
   manager-authorized Linux run. Synthetic frames and disposable local children
   remain source evidence only.

Post-review amendments are `src/rs9/nix_proot.py`,
`src/rs9/nix_proot_dbus_probe.py`, `src/rs9/nix_proot_layers.py`, their two changed
test modules, this report, verification metadata and the candidate manifest.
No further substantive review was obtained, as required by the closeout envelope.
Final source verification and preservation results are recorded in the verification
JSON; the terminal tree and manifest digest are returned by read-only calculation.
All twenty cumulative product additions/modifications are accepted with these
amendments. Operational metadata and unrelated work remain outside the disposition.

Terminal closeout verification repeated the full suites on the amended source
under umasks 022 and 077, with warnings as errors. Each discovered 1,933 methods,
ran 1,923 tests, and recorded 1,902 passes, 21 individual skips and one class-skip
record (ten methods), with no failures, errors or unraisable exceptions. The
focused adversarial suite ran 83 tests: 82 passed and one Linux-only test skipped.
Nine inventory/readiness tests passed. Compilation covered 291 Python files and
seven fixed guest sources; credential scanning covered all 511 candidate files.
The real index, 491 unrelated tracked paths, 204 preexisting operational entries,
modes and Nix/pin files were preserved. Only this report, verification metadata
and the manifest were finalized after the complete suites, followed by final
read-only inventory, credential and whitespace checks. No native qualification
was performed and no substantive re-review followed the terminal amendments.
