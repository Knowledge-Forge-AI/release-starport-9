# Theme Forge Nebular Fusion

Theme Forge Nebular Fusion 0.7.0 is a native desktop workbench for reviewing,
inspecting, and managing Theme Forge brand systems and artifacts. This Python
distribution provides the authenticated native application through Python 3
and pip; it is not a Python reimplementation and it does not compile a
replacement application at install or first launch.

The wheel contains a small offline launcher, the selected native payload, its
complete authenticated manifest, and the isolated materialization helpers.
The launcher verifies those inputs before it resolves the captured application
launcher. It does not download application content, check out source, invoke a
compiler, or fall back to a foreign architecture.

## Install and use

Use Python 3.10 or newer. A virtual environment is recommended for an
application installation:

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python3 -m pip install theme-forge-nebular-fusion==0.7.0
$ tfnf --version
theme-forge-nebular-fusion 0.7.0
$ tfnf
```

For an offline wheel-only installation, select the wheel whose target tag
matches the host and disable index, dependency, and source-distribution
fallback:

```console
$ python3 -m pip install --no-index --no-deps --only-binary=:all: \
    ./theme_forge_nebular_fusion-0.7.0-<target>.whl
$ tfnf --help
```

The package is intended to be installed as a native application wheel. A
source distribution, source build, compiler fallback, or downloaded runtime
is not part of this delivery profile. Remove the installed wheel with pip when
it is no longer wanted:

```console
$ python3 -m pip uninstall theme-forge-nebular-fusion
```

## Wheel targets and Linux compatibility

The 0.7.0 wheel set has exactly these target tags:

| Host target | Wheel tag |
| --- | --- |
| Apple Silicon macOS 13 or newer | `macosx_13_0_arm64` |
| Linux ARM64 | `manylinux_2_36_aarch64` |
| Linux AMD64/x86_64 | `manylinux_2_36_x86_64` |

The Linux profile requires GNU glibc 2.36 or newer and a libstdc++ symbol
floor of `GLIBCXX_3.4.30`. Linux publication requires the corresponding
manylinux qualification and installed-wheel consumer checks. The wheels do
not claim musllinux or universal `any` compatibility; an unsupported libc or
architecture fails closed.

Linux wheels carry the selected private user-space GTK3, WebKitGTK 4.1, and
JavaScriptCoreGTK 4.1 runtime projection used by the native application,
along with its authenticated supporting libraries. They do not install host
packages and do not promise to link against an unrelated host GTK/WebKit
installation. The bundled user-space runtime does not provide a display
server, compositor, session bus, GPU, DRM device, graphics driver, or other
host desktop facility.

## Commands and launch behavior

The installed command is `tfnf`:

```console
$ tfnf --version
theme-forge-nebular-fusion 0.7.0
$ tfnf --help
Usage: tfnf [--version|--help|--path] [application args...]
$ tfnf --path
/absolute/path/to/the/authenticated/gui
```

`--version` and `--help` are local diagnostic queries. `--path` performs the
platform, archive, manifest, and executable-path checks, materializes the
authenticated payload if necessary, and prints the canonical GUI path without
launching it. A normal `tfnf [application args...]` invocation performs the
same checks and then executes the manifest-selected shell launcher with the
application arguments.

The Python launcher uses `os.execv` for that final handoff, so the Python
entry process is replaced by the authenticated launcher. This distribution
does not claim the npm wrapper's separate child-process signal-forwarding or
fixed termination-escalation behavior. Process and signal handling after the
handoff belongs to the selected native launcher.

## Integrity and fail-closed checks

Before use, the launcher checks the captured operating-system family and CPU,
requires GNU glibc on Linux, verifies the embedded payload archive SHA-256,
and validates the authenticated manifest. Materialization then checks the
complete archive and extracted tree, including:

- a bounded manifest and complete member inventory;
- package version, OS, CPU, payload-root, and executable-path identity;
- relative path containment with no empty, `.`, `..`, backslash, NUL, or
  traversal segment;
- regular files, directories, and contained relative symlinks only;
- declared member types, sizes, SHA-256 values, modes, and symlink targets;
- no duplicate, missing, unexpected, special, or escaping members; and
- an executable regular file at the authenticated launcher path.

The cache and payload are rechecked when an existing materialization is
reused. Changes to the wheel, archive, manifest, cache tree, symlinks, or
resolved executable cause refusal rather than an alternate-path launch.

## Cache and offline operation

The materialized runtime is content-addressed by the authenticated manifest
digest and stored outside the virtual environment. Set
`THEME_FORGE_CACHE_DIR` to a dedicated non-empty absolute directory when a
custom location is needed. An empty or relative value is rejected. Otherwise,
an absolute `XDG_CACHE_HOME` selects
`$XDG_CACHE_HOME/rs9/theme-forge-nebular-fusion`; macOS falls back to
`~/Library/Caches/rs9/theme-forge-nebular-fusion`, and Linux falls back to
`~/.cache/rs9/theme-forge-nebular-fusion`. Empty or relative
`XDG_CACHE_HOME` values are ignored.

The cache root and staged entries are created with restrictive `0700`
permissions, protected by a per-manifest lock, and verified before reuse. It
may be removed separately when the application is not running. No first-launch
network access or host-package installation is required.

## Desktop requirements

Provide the host facilities expected by a native desktop application: a
working X11 or Wayland display, session/DBus environment where applicable,
and a compatible graphics stack with the required GPU, DRM, and driver
access. These facilities are intentionally outside the wheel. The package
does not claim to create a display server, provide a compositor, or bundle a
host GPU driver.

On macOS, the qualified profile is Apple Silicon on macOS 13 or newer. The
developer app is ad-hoc signed, not Developer ID signed, and not notarized.
No Gatekeeper bypass, quarantine removal, or installation workaround is
provided or recommended.

## License

Theme Forge Nebular Fusion and this Python distribution are offered under
**AGPL-3.0-or-later**. Review and preserve the distributed `LICENSE` and
`NOTICE` files when using or conveying the package.

For a packaging issue, include the wheel filename and the output of
`python3 -m pip show theme-forge-nebular-fusion` and `tfnf --version`. Do not
include credentials, tokens, private keys, or private release evidence in a
bug report.
