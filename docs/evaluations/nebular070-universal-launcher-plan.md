# Nebular 0.7.0 universal Python launcher

Status: implementation authorized; publication requires fresh hosted qualification.

## Decision and boundary

Publish one `py3-none-any` wheel for `theme-forge-nebular-fusion==0.7.0`.
The wheel contains Python source, reviewed materializer helpers, manifests and
license information. `tfnf install-runtime` explicitly retrieves the matching
native release asset and verifies its pinned size and SHA256 before extraction.
Ordinary launch never downloads. There are no pip installation hooks or automatic
OS package operations.

Supported runtimes remain macOS 13+ ARM64 and glibc 2.36+ Linux ARM64/AMD64.
Linux requires host WebKitGTK 4.1. Help and version reporting need no native
runtime. Missing runtime or platform prerequisites produce a bounded actionable
error. Existing cache-root overrides and the materializer's verified atomic
cache layout remain supported.

The owner selected this route because PyPI rejects the generic Linux tags used
by the previously qualified thin wheels. Merely changing their tags would not
establish manylinux compatibility. Bundled portable Linux wheels and direct
GitHub wheel installation were considered; neither is the selected PyPI route.

## Provenance and dependencies

The runtime input table pins three existing GitHub assets, their member-manifest
identities and launcher paths. Their native qualification is recorded by
[run 40948818287](https://github.com/Knowledge-Forge-AI/release-starport-9/actions/runs/40948818287).
That result qualifies the native payloads, not the new universal package.
The new package and its installed launcher require their own qualification.

No third-party dependency or dependency version change is proposed. The
implementation uses the Python standard library and the unchanged reviewed
materializer closure. The package retains `AGPL-3.0-or-later`, its license files
and Python `>=3.10` requirement. Native third-party notices stay with the
unchanged runtime assets. Packaging must verify that every wheel member is
source or text data and that no native archive or executable is embedded.

Downloads use fixed official HTTPS URLs, verified TLS, a closed redirect-host
set, exact byte limits, a monotonic acceptance budget, streaming SHA256 and atomic cache
commit. Invalid downloads never become extraction inputs. Exceptions and
receipts must not expose signed URLs, headers, credentials or local paths.
Cache reuse must make no network request. Filesystem operations retain the
existing nofollow, regular-file, ownership and locking boundaries.

The new product downloader uses a 15-minute acceptance budget and a maximum
10-second timeout for each network operation. Elapsed-time checks run between
streaming reads; resolver and in-flight syscall behavior are not an absolute
wall-clock guarantee. This changes product download behavior only. Existing
CI and test-runner limits remain fixed. Closed failure codes provide specific
certificate-trust, connection, integrity and cache-recovery guidance. Public
exceptions are raised outside catch suites so their cause/context chains do
not retain transport exception payloads.

The Python wheel retains the packaging repository's license and notice files
for its launcher and materializer source. The separately downloaded native
assets retain their application licenses and third-party notices. Both use
AGPL-3.0-or-later. The former platform-wheel README and legal staging are not
inputs to this package's metadata; the universal description is source-bound.

## Implementation units

1. **Runtime and wheel.** Add cohesive launcher/download modules and a
   deterministic wheel builder. Generate manifest resources from the exact
   pinned native archives; preserve existing extraction and launcher semantics.
   Synthetic tests cover platform and prerequisite failures, explicit setup,
   offline launch, corruption, concurrent cache use, redirect/size/deadline
   failures, privacy and deterministic packaging. Keep legacy wheel builders
   and profiles intact.
2. **Hosted qualification and publication contract.** Add explicit universal
   modes to the existing registered workflow filename. Use an honest universal
   consumer adapter rather than impersonating the three-native-wheel profiles.
   Retain the five native environments and existing runner/dependency classes.
   Extend closed workflow-history validation for the new modes, preserving
   unknown-job and prior-upload refusal. Test the release/mode routing table,
   generated workflow parity and the changed source/admission boundary.
3. **Native qualification.** Run the exact candidate from genuine `main`.
   Install the single wheel, exercise explicit download and offline reuse,
   validate missing prerequisites before extraction, and run the existing
   required installed application scenarios on all five native consumers.
   Local synthetic evidence cannot satisfy these checks.
4. **Publication.** Capture successful main-run APIs, artifact identities and
   all required receipts. A separate metadata-only successor authorizes exactly
   one wheel. Verify source lineage, index eligibility and an empty 0.7.0 file
   set before trusted publication. Read back exactly the approved filename,
   size, hash, license and description afterward.

Each unit is reviewed before promotion. Required checks, timeout values,
dependency classes and runner permissions are not weakened. Python 3.10 syntax
and standard-library compatibility are checked without silently adding a new
runner policy.

## Migration and rollback

The old three-wheel authority remains unpublished. The universal publisher
must prevent platform-wheel shadowing of the same version, and old native
publication modes must not upload 0.7.0 after this cutover. Existing historical
records and earlier release behavior remain auditable.

Before upload, source commits can be reverted without changing public package
files. After upload, registry artifacts remain immutable; a correction requires
a separately authorized release identity. This work does not close APGR 0.14,
change the Jaca handoff, publish to AUR or alter native runtime assets.
