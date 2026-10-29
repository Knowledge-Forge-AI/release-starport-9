# Theme Forge Nebular Fusion

Theme Forge Nebular Fusion 0.7.0 is a native desktop workbench for reviewing,
inspecting, and managing Theme Forge brand systems and artifacts. Install
the native application with Python 3 and pip, then open it with `tfnf`.
The package includes the application and an offline launcher.

## Install and use

Use Python 3.10 or newer. A virtual environment is recommended:

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python3 -m pip install theme-forge-nebular-fusion==0.7.0
$ tfnf --version
theme-forge-nebular-fusion 0.7.0
$ tfnf
```

For an offline wheel-only installation, select the wheel matching the host:

```console
$ python3 -m pip install --no-index --no-deps --only-binary=:all: \
    ./theme_forge_nebular_fusion-0.7.0-<target>.whl
$ tfnf --help
```

The package has no source-build, compiler, network, or bundled-runtime
fallback. Remove it with `python3 -m pip uninstall theme-forge-nebular-fusion`.

## Supported targets and host runtime

This profile has three target families:

| Host target | Wheel tag | Requirement |
| --- | --- | --- |
| Apple Silicon macOS | `macosx_13_0_arm64` | macOS 13 or newer |
| Linux ARM64 | `linux_aarch64` | GNU glibc 2.36+, GLIBCXX_3.4.30+ |
| Linux AMD64/x86_64 | `linux_x86_64` | GNU glibc 2.36+, GLIBCXX_3.4.30+ |

Linux uses the system's WebKitGTK 4.1 runtime. A desktop installation may
already provide it; if `tfnf` reports that it is unavailable, install the
runtime for your distribution and launch `tfnf` again:

| Distribution | Install WebKitGTK 4.1 |
| --- | --- |
| Debian / Ubuntu | `sudo apt install libwebkit2gtk-4.1-0` |
| Fedora | `sudo dnf install webkit2gtk4.1` |
| Arch Linux | `sudo pacman -S webkit2gtk-4.1` |

WebKitGTK 4.0 and 6.0 use different library interfaces and do not replace 4.1.
The launch check runs offline, before extracting or starting the application.
It never installs system packages. Provide a working graphical desktop,
session bus, and graphics drivers as you would for other native applications.
On macOS, the application uses the system WebKit framework.

The `--help` and `--version` queries remain available without loading the
runtime. `--path` performs the existing archive and executable checks and
prints the resolved GUI path without starting the application.

The Linux tags are generic and make no manylinux, musllinux, or universal
compatibility claim. Darwin keeps its native payload and macOS 13 floor; the
WebKitGTK preflight is Linux-only.

## Offline integrity and cache behavior

The launcher verifies the embedded archive, authenticated manifest, extracted
members, and exact executable paths before handoff. It does not check out
source or use an alternate path. Materialized content is stored in the
content-addressed cache selected by `THEME_FORGE_CACHE_DIR`, then
`XDG_CACHE_HOME`, or the platform default. Custom cache paths must be
absolute and non-empty. No first-launch network access is required.

## License

Theme Forge Nebular Fusion and this Python distribution are offered under
**AGPL-3.0-or-later**. Preserve the distributed `LICENSE` and `NOTICE` files
when using or conveying the package.
