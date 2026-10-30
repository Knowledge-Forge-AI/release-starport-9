# Current optional replay progress observer

Status: private source proposal, requiring independent review before adoption or
native execution. The qualifying original attempt and all native qualification
claims remain unchanged.

## Closed current source selection

The historical two-file observer profile and default path retain their existing
constants and behavior. A separate current profile is selected only after the
existing current live/source-proof readback gate accepts the exact source
identity. A plain serialized prepared object cannot select it.

The source-owned current identity is Nebular tag v0.7.0, commit
`cadb40c4972f68f314096ff60fbcfb4da950c161`, tree
`27c643b6375c2aafde314799c4f08e844c14992c`. Its seven reachable ESM modules
are native-rc-smoke, fs-snapshot, native-launcher, native-rc-package,
native-runtime, candidate-provenance and platform-targets. Their pins include
Git blob ID, SHA256 and byte length. The separate package.json support file is
1833 bytes, blob `161ee788b7a8660916e2b6fbbebbac0de4a87f42`, SHA256
`15d3f118dfdc0014129fc37d63533a6a02cf355fdb89961a215eca77e95b7cd2`.
Its parsed version must equal 0.7.0.

The wrapper independently refuses changed profile ID, commit/tree, entry,
closure member set, duplicate entries, module/support hash, blob, length or
package version before import. The seven modules plus support total eight
files and 228179 bytes. The existing eight-file, 4-MiB member, 8-MiB aggregate,
32-event and 16-KiB progress bounds are unchanged. Support bytes count against
those file/byte bounds.

ESM imports execute only already-held authenticated bytes through the existing
closed loader. Only during module import, the source-known package.json read receives
its already-held authenticated bytes with the same Buffer/UTF8 behavior; other
filesystem reads pass through. The override is restored immediately after import, before runSmoke; runtime reads retain their normal options and behavior. The loader admits no extra ESM module. Source
root aliases, final-file symlinks and nonregular members refuse. Source-side
readback retains the complete current source/fixture closure requirements.

## Diagnostic hooks and trust

The optional replay keeps the original runSmoke export, source bytes, launch
args, environment, app payload and harness timeout. The current hooks map to
the exact tagged candidate spawn and exact evidence receipt/report writes.
They return the same child/write result and preserve stream bytes. A current
candidate-launch event requires the numeric-child identity condition used by
the tagged harness, without retaining its value.

A read-only wrapper around that child's existing stderr `emit` method recognizes only the
fixed compiled line for the active scenario: `TFSB Studio release smoke
scenario <B|C|C-signal> active`. This line is printed after the real main webview
is built and immediately before release_smoke::start. A match emits only
`application / release-smoke-active`. A transient bounded tail handles chunk
splits. Unknown lines, private suffixes and arbitrary text produce no marker
event or retained text. Observation faults cannot alter the released stream
path. No `data` listener is added and flow mode, listener count and pipe backpressure are unchanged. The original emit method is restored after replay.

A missing marker remains unobserved, including when it falls beyond the 64-KiB stderr window; it is never proof that the application failed to reach release smoke.

Progress remains optional replay evidence. A failed original stays failed even
if replay progress or a later replay passes. Existing
replay_equivalent_to_original=false remains in place. The profile/progress
objects grant no release, bootstrap, publication or native qualification
capability. No original command, deadline, cleanup policy or gate was changed.

## Verification and limits

**70 focused observer tests passed**: ten new current-profile/hook cases plus the
maintained historical observer and application diagnostic tests. They cover
real core authentication with synthetic source fixtures, wrong identity and
missing/extra/changed source refusal, sealed module/support/blob/version refusal,
exact spawn/write hook semantics, split marker handling, unknown marker omission,
late-attached and never-drained pipe behavior, import-only support-read scope, B/C/C-signal markers, unchanged captured streams/source bytes, and current replay command/gate
integration using controlled child seams. Synthetic unit pins do not qualify
published packages.

A separate actual-custody check freshly authenticated the retained published
Nebular/Burst captures, prepared the current 28-file source closure, selected
the real profile without replacing pins, and ran the wrapper against the
published seven-module closure plus package support. It observed import-start,
imported, run-smoke-enter and source-only error at an empty candidate directory.
No candidate process could launch: that directory contains no executable.
Source readback passed afterward, and the profile failed the release-capability
API. Only stream hashes and closed progress enums were retained. This proves
profile/import compatibility, not GUI startup or a fix for Linux Nix timeouts.

The immutable GitHub commit/tree and all selected blob/length/SHA256 joins,
actual source fixture custody, exact commands, logs and resulting file hashes
are retained in the private review packet. No native/container/CI execution or
shared adoption was performed. Independent review is required before using
this proposal in an authorized hosted qualification run.

The original 240-second timeout still lacks a finalized inner application log.
This optional replay marker cannot fill that original boundary or prove that
the replay's D-Bus category caused the original timeout. A separate design-only
read-only process-role sampler is retained privately; it is not implemented.
