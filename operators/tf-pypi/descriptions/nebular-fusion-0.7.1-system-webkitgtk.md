# Theme Forge Nebular Fusion 0.7.1 — system-WebKit runtime

Theme Forge Nebular Fusion is a desktop workbench for reviewing, inspecting,
and managing Theme Forge brand systems and artifacts. Its workbench provides
Brand / System, Vector / Graphics, Starlight Theme, and Application Theme
destinations. Theme profiles can be opened or edited, compiled, saved, and
inspected in Starlight and Application Theme previews with light/dark and
desktop/mobile views.

This Python distribution uses a small universal launcher with separately
authenticated native archives for Apple Silicon macOS and GNU/Linux ARM64 and
AMD64. Install it with Python's standard package installer:

```console
$ python3 -m pip install --upgrade theme-forge-nebular-fusion==0.7.1
$ tfnf install-runtime
$ tfnf --version
theme-forge-nebular-fusion 0.7.1
```

Use `tfnf --help` for the supported commands, `tfnf install-runtime --json`
for JSON setup details, and `tfnf --path` to print the authenticated GUI
executable path without launching it. Normal `tfnf [application args...]`
launches only after the selected payload and manifest have been checked.

## Supported targets and host runtime

The supported targets are macOS 13 or later on Apple Silicon, GNU/Linux ARM64
with glibc 2.36 or later, and GNU/Linux AMD64 with glibc 2.36 or later. This
system-WebKit build also requires GLIBCXX 3.4.30. It makes no manylinux or
private bundled-WebKit claim.

GNU/Linux requires the host WebKitGTK 4.1 shared library
`libwebkit2gtk-4.1.so.0`. On Debian or Ubuntu, use the maintained package
guidance:

```console
$ sudo apt install libwebkit2gtk-4.1-0
```

The launcher checks WebKitGTK during Linux runtime setup and normal launch. If
host WebKit is unavailable, it reports the prerequisite and does not start the
application; the launcher does not install system packages itself.

## Verified native runtime download

`tfnf install-runtime` selects one target archive from the v0.7.1 GitHub
release. See the release page:

<https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/tag/v0.7.1>

The wheel embeds the selected archive's exact name, byte size, and SHA-256
digest. HTTPS/TLS, the canonical release URL, archive length, complete digest,
and the permitted GitHub release-asset redirect are checked before the archive
is committed to the local cache. A failed or changed archive is rejected.

## License and source

The community license is **AGPL-3.0-or-later**. Preserve `LICENSE`, `NOTICE`,
and `COMMERCIAL-LICENSE.md`; the commercial-license document describes optional
proprietary terms and does not replace the AGPL community license.

Source: <https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion>

Packaging source: <https://github.com/Knowledge-Forge-AI/release-starport-9>
