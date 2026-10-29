# Nebular 0.7.0 system WebKit wheel profile

Status: source candidate; public native qualification and PyPI publication pending.

The selected Python distribution contains three wheels: macOS ARM64, Linux
ARM64 and Linux AMD64. The Linux wheels use the existing native release
archives and the host's WebKitGTK 4.1 runtime. They carry generic Linux tags;
they do not claim manylinux compatibility. This removes the private WebKit
runtime closure that made the previous Linux candidates exceed PyPI's default
per-file limit. The macOS wheel continues to use the platform WebKit framework.

The explicit profile is `nebular-fusion-0.7.0-system-webkitgtk-4.1-v1`.
Its package description documents Python installation and the distro runtime
packages. Normal Linux `tfnf` launch checks `libwebkit2gtk-4.1.so.0` in an
isolated Python child with a five-second timeout before extracting the
application. A missing runtime produces installation guidance and exit status
1. The launcher does not install system packages. Help, version and path
commands retain their existing behavior.

The public input manifest pins the new metadata archive by release asset ID,
size and SHA-256, alongside the exact original native payloads and npm wrapper.
The metadata is a transport input, not a native qualification receipt. Linux
inputs describe the authenticated archive members, protocol and smoke-support
closure; they contain no invented previous consumer pass. The original public
native provenance binds the thin payloads to the released product commit and
tree. Existing release assets and the captured payload checksums are preserved.

Qualification uses matching public GitHub-hosted native runners. Linux runs
the actual installed Python entrypoint through a derived version of the
authenticated product harness, retaining its GUI, sidecar, signal, process,
cleanup and user-state checks. The derived harness records both its source
identity and its transformation. It uses the same authenticated content cache
as the installed consumer and records the application's own output streams.

The matrix requires macOS ARM64 and both Linux architectures on newer Ubuntu
and the Debian Bookworm floor. Each floor first proves a real missing-runtime
refusal, then installs its distro runtime and performs positive qualification.
Source, run, wheel, payload, host and provider identities must agree throughout.
No local archive checks or synthetic tests establish native acceptance.

The portable/manylinux profile remains separately selectable. Its launcher
bytes are retained exactly, including the historical successor release.
System-profile evidence and portable runtime admission cannot be mixed.

Publication remains a separate attended resume after the full native matrix
passes. The retained matrix includes both floor observations and negative
receipts. Operator metadata binds the exact three qualified wheel files and
the current source before any PyPI upload.
