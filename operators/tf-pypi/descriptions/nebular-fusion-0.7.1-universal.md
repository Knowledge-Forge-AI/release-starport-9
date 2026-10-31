# Theme Forge Nebular Fusion 0.7.1

Theme Forge Nebular Fusion is a desktop workbench for reviewing, inspecting,
and managing Theme Forge brand systems and artifacts. The workbench provides
Brand / System, Vector / Graphics, Starlight Theme, and Application Theme
destinations. Open a theme example or profile, edit it, compile the current
draft, save the document, and inspect the resulting preview. Starlight Theme
and Application Theme previews provide light/dark and desktop/mobile views;
the workbench keeps the last valid preview visible when a new compilation has
diagnostics.

The Python distribution is a small universal launcher for the native desktop
application. One wheel supports Apple Silicon macOS and GNU/Linux on ARM64 and
AMD64; the native payload is selected for the running host.

## Install and use

Install the universal launcher with Python's standard package installer:

```console
$ python3 -m pip install --upgrade theme-forge-nebular-fusion==0.7.1
$ tfnf --version
theme-forge-nebular-fusion 0.7.1
$ tfnf --help
Usage: tfnf [--version|--help|--path] [application args...]
       tfnf install-runtime [--json]
```

Runtime setup is explicit. Run `tfnf install-runtime` before the first normal
launch, or use `tfnf install-runtime --json` for JSON setup details. Use
`tfnf --path` to verify the installed runtime and print the
authenticated GUI executable path without launching it. A normal `tfnf`
invocation verifies the selected payload immediately before launching the GUI
and forwards application arguments. Unsupported hosts are not supported; setup
does not download a runtime for a different architecture.

## Supported hosts and system WebKit

The supported targets are Apple Silicon macOS 13 or later, GNU/Linux ARM64
with glibc 2.36 or later, and GNU/Linux AMD64 with glibc 2.36 or later. The
Linux system-WebKit build also requires GLIBCXX 3.4.30. Windows, Intel macOS,
musl Linux, and other libc environments are not supported by this release.

Linux uses the host's WebKitGTK 4.1 runtime rather than a bundled or manylinux
WebKit. The required shared library is `libwebkit2gtk-4.1.so.0`; on Debian or
Ubuntu the maintained setup guidance is:

```console
$ sudo apt install libwebkit2gtk-4.1-0
```

The launcher checks for WebKitGTK 4.1 during Linux runtime setup and normal
launch. If the system runtime is unavailable, it reports the prerequisite and
does not start the application.

## Verified native runtime download

`tfnf install-runtime` selects the current host's pinned native archive from
the v0.7.1 GitHub release. See the release page:

<https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/tag/v0.7.1>

The wheel carries the exact target asset name, byte size, and SHA-256 digest.
Before committing an archive to the local runtime cache, the launcher requires
HTTPS/TLS, checks the exact release URL and archive size, verifies the complete
SHA-256 digest, and permits only the authenticated GitHub release-asset
redirect host. A failed or changed download is rejected; it is never used as a
native payload.

## Payload and release notes

Before use, the launcher checks the selected runtime manifest and payload
identity, including executable paths and file hashes. Changed or missing
payload files are rejected rather than launched.

The Darwin application archive is ad-hoc signed. It is not Developer ID signed
and no notarization claim is made. Do not bypass Gatekeeper or remove
quarantine as an installation workaround.

## License and source

The community license is **AGPL-3.0-or-later**. Preserve `LICENSE`, `NOTICE`,
and `COMMERCIAL-LICENSE.md` when conveying the package; the commercial-license
document describes optional proprietary terms and does not replace the AGPL
community license.

Source: <https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion>

Packaging source: <https://github.com/Knowledge-Forge-AI/release-starport-9>
