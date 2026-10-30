# Nebular 0.7.0 universal Python distribution

Status: implementation candidate. This document grants no publication authority.

The Python distribution contains one `py3-none-any` wheel. It ships Python
launcher code, the three authenticated native member tables, runtime download
pins, and licensing documents. It does not embed native executables or Linux
WebKit libraries. The package requires Python 3.10 or later and declares
`AGPL-3.0-or-later`.

`python3 -m pip install theme-forge-nebular-fusion` installs the launcher.
The user explicitly runs `tfnf install-runtime` to download the selected native
archive from the official GitHub release. The launcher checks its exact size,
SHA-256 digest, and member table before materialization. Ordinary launch never
downloads. Linux setup checks for WebKitGTK 4.1 before downloading and provides
installation guidance when it is unavailable. It does not install system
packages. The native payload retains its own licenses and notices.

## Qualification

The `universal-qualify` mode of `rs9-tfnf-pypi-publish.yml` runs only from the
repository's genuine `main` branch. It constructs one deterministic wheel and
qualifies that wheel on five matching public native lanes:

| Lane | Host | Required installed behavior |
| --- | --- | --- |
| Darwin ARM64 | macOS runner | Scenario A and authenticated installed executable |
| Linux ARM64 newer | Ubuntu ARM64 runner | Host WebKit, installed smoke, and lifecycle guards |
| Linux AMD64 newer | Ubuntu AMD64 runner | Host WebKit, installed smoke, and lifecycle guards |
| Linux ARM64 floor | Bookworm ARM64 container on native runner | Missing-WebKit refusal, then positive installed smoke |
| Linux AMD64 floor | Bookworm AMD64 container on native runner | Missing-WebKit refusal, then positive installed smoke |

Existing runner images, package classes, container capability, actions,
permissions, and job timeouts remain the source of runner policy. Tests and
archive inspection on an operator's workstation are not native qualification.

Each positive lane installs the actual wheel offline into a new virtual
environment. It proves a cold ordinary-launch refusal, performs the explicit
verified runtime setup, and verifies cached reuse under network denial. Normal
version, path, and application probes retain the existing network-denial,
process-group, orphan, persistent-user-state, and uninstall guards. Only the
explicit positive setup command has network access within that guarded run.

Each Bookworm lane also installs the actual wheel before the approved WebKit
packages are installed. It observes the library's genuine absence, checks help
and version, checks ordinary cold-launch refusal, and checks that explicit setup
reports missing WebKit before attempting a download. These negative probes
remain under network denial and must not create a runtime cache.

The matrix reader requires all five positive receipts and both negative
receipts. It reauthenticates the three native archives and their original input
proofs, including the Darwin evidence, rather than trusting receipt summaries.
All wheel, runtime, source, run, host, and GUI identities must join. Universal
receipts use their own schema and distribution identity; historical platform
wheel receipts cannot stand in for them. Linux installed preflight uses its
explicit universal distribution domain.

## Publication custody

Publication uses a qualified source commit Q and a later publisher commit P.
P may differ from Q only in the exact universal-publication authority JSON.
Both checkouts must be clean, Q must be an ancestor of P, and the actual Q tree
must equal the captured qualification tree. Executable publication code comes
from Q.

The ready authority must bind the successful qualification run, the actual run,
jobs and artifacts API captures, and all eight retained artifact ZIPs. ZIP
identities and every extracted member are checked before use. The eight
artifacts are public inputs, the one-wheel bundle, the five native lane
receipts, and the matrix receipt. The publisher revalidates the installed
receipts and reauthenticates the native input bytes before staging the wheel.
Neither a builder receipt nor a successful individual lane authorizes upload.

The `universal-publish` mode retains the registered workflow filename,
`pypi` environment, and pinned trusted-publishing action. The Python verifier
does not upload. An absent distribution may stage exactly the approved wheel
after the full prior-run and exclusive attempt-marker guards pass. An existing
exact distribution is a read-only outcome. A surplus file, changed digest,
yanked file, ambiguous history, or unknown remote state refuses upload.
Immediately before upload, the source lineage, custody, and exact staged bytes
must be checked again. Readback requires the same bytes, license expression,
Python requirement, and Python-specific description.

Historical publication readers retain their closed domains. New universal
history records are validated explicitly without filtering them from the run
list or treating unknown jobs, steps, or possible prior uploads as harmless.

## Remaining acceptance

The integrated implementation still requires accepted independent review,
resulting-state verification, and the public native qualification run.
Publication authority can be prepared only from that run's actual API
captures and artifact bytes. Until those gates pass, the package is not admitted
for publication.
