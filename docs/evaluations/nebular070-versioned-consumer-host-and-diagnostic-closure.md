# Nebular 0.7 versioned consumer, host observation and wheel diagnostic closure

## Changes

The generic Gate 1 path is unchanged when no Stage-A context is supplied.
When a validated, non-fixture Stage-A object is supplied, the native consumer
joins its version, schema, claim, construction status, producer and executing
RS9 sources, source snapshot, targets and 24 receipt-body keys. Only after that
does it accept manylinux 2.36 wheel tags and construction rows. The same digest
then has to appear in the native qualification and matrix receipts. Expected
wheels and candidate rows that carry construction fields without applicable
Linux Stage-A context are refused. Darwin keeps its existing tag and metadata.

`qualify-native` and `admit-matrix` both load Stage-A from the bundle through
the authenticated qualification-inputs descriptor. The loader reads the member
once with a bounded, stable physical read. It compares the exact length and
full SHA-256 with `manylinux.stage_a`, then parses and validates those same
bytes with the maintained envelope and portability validator. The workflow
generator and checked-in workflow add only the matrix `--qualification-inputs`
argument. No permissions, runners or dependencies change.

`nebular070_pip.py` authenticates the existing MIT pip 25.0.1 closure at a
fixed mounted root: 438 regular files, 4958315 bytes, and a 148305-byte manifest
pinned by SHA-256. The inventory never follows links, and membership and hashes
must match exactly. With the seam enabled, a `pip --python <venv> --version`
bootstrap check runs first. Install and uninstall then run the authenticated
pip runner under the venv interpreter. Nothing is installed or resolved at
runtime. When the seam is absent, the existing `-I -B -m pip` path is unchanged.
The seam is reachable through `qualify_nebular070` but is not yet wired into
the CLI or workflow. The measured embedded import closure is 100 files.
Files are authenticated one at a time and then executed by path, so the
mounted pip root must stay immutable between the check and its use. Wiring
the seam into the CLI or workflow must establish that.

`nebular070_host_observation.py` observes the current Linux host directly. It
checks the machine, the observer ELF through `/proc/<observer-pid>/exe`, the
loader, Python and platform libc, `ldd`, and the loader version, against a
floor of glibc 2.36 and a newer host above 2.36. Output files are no-follow
mode-0600 regular files. They are created through a temporary file and an
exclusive link, and rollback removes only an output whose full stat identity
still matches. Probe runners injected by tests are marked synthetic and cannot
be written as actual evidence.

After the original application smoke fails, Linux wheel clients enable the
existing non-qualifying boundary probes. They retain the smoke diagnostic only
if it is a regular file whose stamp changed. Failures, gates, timeouts and
cleanup behave as before.

## Review findings and disposition

- Captured-byte gap (an earlier independent review): the Stage-A loader could
  validate bytes other than the descriptor capture. Fixed upstream of this
  checkpoint. The red run had 2 failing tests (10 negative subcases) and the
  green run had 2 passing tests. The green receipt reuses the red receipt's
  schema label; its return code is 0.
- Host banner ambiguity (this checkpoint): version parsing treated package
  revisions such as `2.39-0ubuntu8.4` as a second version. On Ubuntu-style
  hosts that refused the `ldd` and loader banners before any capture. Version
  candidates are now standalone `major.minor` tokens, and two distinct
  standalone versions are still refused. Two regression tests were added. The
  Ubuntu subcase failed before the fix and passes after it.
- Shared smoke-diagnostic path: if both client families fail, the second
  overwrites the first family's smoke sidecar. The per-family lifecycle
  diagnostics still record each failure, and custody de-duplicates paths.
  Accepted as a diagnostic limit.
- Test temporary paths (closing review): two output tests created their
  directories under the repository root, and the race tests relied on a
  physical `TMPDIR`. The writer refuses symlinked ancestry, such as macOS
  `/var`. All of these tests now resolve a system temporary directory.
- Superseded timing: an earlier report of 29 tests in 32.370 s disagreed with
  its own receipt. The 214-test proof below replaces it.

## Verification and limits

The root resulting-state proof ran 214 tests in 49.588 s with return code 0,
no source drift and a clean diff check. It covers the twelve integrated files
before this checkpoint's host fix. After the fix, Python 3.13.12 ran the
affected tests under the pinned bounded helper with source bookends and no
drift: all 14 host-observation tests passed, and the 2 static workflow and
closure contract tests passed.
The test temp-path change was re-run the same way: all 14 host-observation
tests passed.

All of these tests are synthetic or local behavioral checks. No actual host
observation, native build, container, Nix run, hosted dispatch or portability
qualification was performed. The full publisher uses Python 3.12+ syntax and
has not run on Bookworm Python 3.11.

## Still pending

Actual native builds, Stage-A and Stage-B capture, CPU checks, and floor and
newer host observations. Real consumer and matrix runs, staged-wheel custody,
fresh public CI and registry gates. The current required Linux Nix B/C
application smoke still times out before producing any receipt, with cleanup
status unknown. That failure is unqualified and outside this slice.

## Rollback

Revert this change set. Generic consumers and matrices without Stage-A context
return to the previous behavior. Historical receipts are not modified.

Root revision: refuse banner microversions and attached word suffixes; distro revisions and punctuation remain valid. All 15 host tests and 2 affected contract checks passed.
