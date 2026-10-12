# CONT20: guest D-Bus legacy-include repair

Status: source candidate amended after the dispatcher pre-final review. Live daemon
acceptance and native application qualification remain unproven. PRoot remains
experimental and has no isolation or qualification authority.

## Scope and proposal disposition

The original task authorizes a source repair of the guest configuration topology,
retention of native diagnostics and signal failures, and source verification.
It does not authorize a hosted workflow, source adoption, release or publication.

Proposal disposition: **amend**. The exact bound proposal is 15,043 bytes, SHA256
`01c2ce46d865adabda65d1507e10a6b1694fef7c466def4364ca857263866e78`.
The original scope remains authoritative. The dispatcher recorded no stage
deltas before implementation. Its independent plan review was advisory.

| Plan-review finding | Disposition in this candidate |
| --- | --- |
| 1. Genuine absent `/etc` includes must remain allowed | Amend: absent standard legacy targets and absent closure includes are recorded; present targets must remain in the closure. Ancestor realpath cycle detection is deliberately stricter than a string-only check. |
| 2. Expected baseline failures mask repaired stages | Amend: baseline receipts remain visible with `gate_relevant: false`; first failure uses the pinned stages and audits. |
| 3. Pin the daemon as well as session config | Accept: the supported session argv specifies both pinned executables and the exact store main file. |
| 4. PRoot smoke option and default-lane preservation | Accept with conditions: only the experimental caller supplies the optional session argv; Linux and Darwin defaults have golden tests. The caller contract comment is updated. Released tools that create their own bus remain an open native question. |
| 5. Safe D-Bus excerpts, including daemon frames | Accept with conditions: every retained line has a recognized prefix, printable ASCII, bounded length, privacy redaction and raw/excerpt/serialized credential scans. Alias comparison must use observed redacted text and length rather than PID-dependent hashes. |
| 6. New digest pin and architecture equality | Amend: this is a new source-verification byte pin, shared by Nix and Python. Both complete architecture records show identical bytes and digest. Dependency/release pins remain intact. |
| 7. Separate alias runtime and bounded control budget | Accept: only two diagnostic arms receive the alias bind; the gate runtime and `guest_bindings()` are unchanged. Twelve controls each have a 15-second timeout; 180 seconds is their summed command-timeout allowance, not an overall deadline. Survivor polling adds up to about one second per daemon arm. |
| 8. Optional direct tracer signal attribution | Defer: no additional signal attempt or supervisor repair. Existing native masks and outer/group controls are retained. |
| 9. Runtime path and audit-test assumptions | Accept: diagnostics record the store main alongside the legacy default candidate; tests enforce absence rather than the old singleton alias. |
| 10. Verify manager evidence first | Accept: the verifier passed before interpretation or implementation. |

The dispatcher owns both independent checkpoints. Internal Gemini findings are
integration evidence only. Its cumulative pre-final review reported five advisory
findings and no blockers. Closeout amends the documentation and source comments;
executable behavior and the reviewed repair remain unchanged. No additional
substantive review was obtained after these terminal amendments.

| Work-review finding | Terminal disposition |
| --- | --- |
| 1. Removing CONT18's alias re-exposes run 16's default-config failure | Amend: the ADR and this document explicitly identify the earlier fix and expected original-baseline, `main_baseline` and application-spawned default-bus failures. |
| 2. Built-in default path is inferred, not pinned-build proof | Amend: source comments and this document label the inference; requiring default-config failure can under-report hypothesis support. |
| 3. Timeout sum is not an overall deadline | Amend: describe twelve separate 15-second timeouts plus survivor polling; keep the existing diagnostic budget unchanged. |
| 4. SELinux include modeling differs from daemon semantics | Defer: document the heuristic and config-relative resolution limitation below. Current guest has no `/sys`; native acceptance remains unproven. |
| 5. Fresh public-main match could not be established | Defer: closeout retried read-only public-main lookup and again observed DNS resolution failure. Only local tracking parity and the manager's earlier external check are available. |

## Evidence and resulting behavior

The manager verifier confirmed 171 selected records, 18 manifests and 147 retained
objects. The 323 omitted objects were not reauthenticated. Complete architecture
evaluations, the hosted summary/packet, manager instructions and original nested
selection ZIP were inspected. [Input evidence](../evidence/live1/cont20-input-evidence.json)
records sanitized identities and original stream lengths/digests. No raw 95-byte
daemon or 149-byte session stderr was found in the selected packet. Their native
content remains unknown; no text was reconstructed from a hash.

The recipe leaves `/etc/dbus-1` genuinely absent. A build-time digest check and
the guest audit require the original 3,561-byte main config, SHA256
`206f009ddcf909422f3651c687b4623a5780fb7486c6d650e5332f57c00d6be1`.
`nix_proot_dbus_pin.py` is the sole pin owner; Nix reads that fixed assignment and
Python embeds it in the fixed guest source. No application policy is rewritten.

CONT18 added the singleton alias to address run 16's missing legacy session file.
Leaving that file absent deliberately re-exposes that failure for built-in-default
callers, including `baseline-original-*`, `main_baseline`, and buses started by
the released app itself when they use the built-in default. Original baseline
receipts have `gate_relevant: false`;
their expected failure in a future run 19 is neither a new regression nor new
causal evidence. Explicit pinned sessions are the repaired path. The compiled
default location is inferred from run-16/18 behavior; pinned build flags have not
been checked, and the default-dependent hypothesis label can under-report support.

Pinned observations, launch controls and the experimental smoke select:

```text
<store>/bin/dbus-run-session
--dbus-daemon=<store>/bin/dbus-daemon
--config-file=<store>/share/dbus-1/session.conf
-- <original-command>
```

All three paths must have the same canonical validated store root. The legacy
directory/file, dangling links and `/etc` ancestor links fail closed. The main
file must be regular, unsymlinked, bounded, inside the closure and digest exact.
The audit rejects recursive includes, closure escapes, malformed XML and entity
declarations, while preserving standard DOCTYPE and optional include semantics.
It records policy counts/classes without arbitrary policy attribute contents.
Duplicate sibling includes are allowed; traversal remains bounded.

The audit's SELinux condition uses directory presence at `/sys/fs/selinux`,
whereas the daemon asks libselinux. It also resolves `selinux_root_relative`
targets from the config directory rather than the SELinux policy root. These
are source-model limitations, deferred for the current guest without `/sys`.
The audit does not prove those semantics match the pinned daemon or qualify a
guest with SELinux exposed; live full-policy daemon acceptance remains required.

This follows the separation between main configuration and local overrides in
the [D-Bus daemon manual](https://dbus.freedesktop.org/doc/dbus-daemon.1.html).
The [upstream session template](https://sources.debian.org/src/dbus/1.16.2-2/bus/session.conf.in/)
is explanatory context; the run-18 digest establishes fixture identity. Neither
source proves acceptance by the pinned native daemon in the repaired guest.

Controls run even when the repaired pinned launch succeeds. They retain versions,
socket binding, compiled default, full store main, deny-only minimal config,
session cwd variants, and isolated daemon/session legacy-alias reproductions.
The minimal config remains diagnostic-only and never enters application argv.
The alias reproduction label requires complete streams and a safely observed
circular-inclusion token; failure statuses alone are insufficient. Missing or contrary evidence
remains blocking/unobserved. Excerpts and circular-inclusion tokens require actual
safe observed bytes; a recognized prefix is attribution evidence, not writer
authentication. A source fixture or mock pass is not live daemon acceptance.

## Signal and preserved blockers

Signal implementation is unchanged. Deliberate 255 remains distinct from the
guest wait record `signaled/15` with outer 255. No status remapping, privileged
helper or new signal target is introduced. Run 18 records PRoot's SIGTERM ignored
mask, a missing handler observation for the outer target, and a passing separate
process-group control. This supports retaining an architectural limitation; it
does not establish every forwarding layer's internal behavior.

The nine PRoot gates and all readiness/publication flags remain unchanged and
false where required. WebKit main-process readback remains unobserved, bwrap is
red and sandboxing stays enabled. Both mandatory Linux Nix lanes still fail
`NIX_FHS_USERNS`; PRoot cannot substitute for them. Direct Pages HTTPS still has
the independent certificate hostname failure code 62, and readback comparison
remains not-run. Wheel promotion and raw RPM lint exceptions remain blockers.

Run-18 passing results are preserved: RPM/DNF 50 per architecture, APT 41 each,
pacman 40, assembled Pages 112, Foundation3 2 with 16 blocked plans and no
production receipts, Linux wheels 26 each, Darwin Nix and source/config/auth/pins.
No new native results are claimed. Packaging, workflows, package metadata,
archives, manifests, runner policy, Pages configuration and release pins are
outside this change. The source-candidate inventory alone is regenerated.

## Verification and deferrals

[Verification evidence](../evidence/live1/cont20-verification.json) retains the
producer's warning-as-error source tests under umasks 022 and 077, compilation,
credential scans and Nix parse/pin evaluation. Those recorded full runs report
1,997 successes, 2,018 runner tests and 22 skip records each; the producer focused
suite reports 346 successes and one Linux-only skip. Producer compilation covers
295 Python files and nine fixed guest sources. These totals are producer evidence,
not closeout reruns of the full suite.

After the review, closeout ran the affected D-Bus, signal, runtime and smoke tests
under both umasks with warnings as errors: 332 successes, 333 runner tests and
one Linux-only skip each, with zero failures, errors or unraisable exceptions.
Closeout compiled all 20 scoped Python source/test files and nine fixed guest
sources without bytecode. Digest-authenticated comparison confirms executable
source ASTs are unchanged from the reviewed candidate; only two source comments
changed. Inventory, readiness, hygiene, credential and index checks qualify the
resulting documentation/evidence/inventory bytes; the metadata suite reports
13 successes under each umask. No native Linux build or live
D-Bus/application acceptance was run; those remain separately authorized work.
New guest-audit helpers are bounded below
51 statement nodes; large pre-existing owners retain the narrow-scope exception.
The configured shared scratch root is outside this sandbox's writable roots;
task-owned test state uses an allowed temporary directory. Existing `.scratch`,
`.serena`, the real index and unrelated state are preserved. The final tree and
inventory SHA are reported in the terminal handoff to avoid a self-hash cycle.

Python profile: Orange for security-sensitive config/argv validation and bounded
changes to existing large runtime/smoke owners. No new responsibility is added to
those legacy owners; the new command helper is separate. The fixture suite is
cohesive and bounded. Nix profile: Yellow for the verification pin and guest-root
change; parsing and pin-expression evaluation do not prove a Linux build. Rollback
is removal of this source delta through a later authorized change; no live state
or released bytes require restoration.

Remaining native questions for a separately authorized run 19:

- Does the pinned daemon accept the full store policy, and do both session cwd
  arms publish/connect to a real bus while the legacy override stays absent?
- Can the isolated alias reproduce the original 95/149-byte failures, and what
  scanner-approved text is actually observed? A contradictory arm blocks claims.
- Does the unmodified application reach WebKit, or fail at bwrap/userns or a
  separately spawned default D-Bus session? Does GIO require a machine-id?
- Does the x86 smoke signal scenario expose the existing PRoot boundary after
  D-Bus starts? Outer/group delivery and deliberate 255 must remain independent.
- Fresh public-main readback was unavailable because DNS resolution failed;
  the local tracking ref matches the parent, and the manager's prior check is
  retained as evidence only.

Run 18 must not be repeated or re-adopted. This candidate is not authorization
for run 19, source adoption, a new release or publication.
