# Theme Forge Nebular Fusion

Theme Forge Nebular Fusion 0.8.0 is a native desktop application distributed
to Python users through a small `py3-none-any` launcher package. The package
provides the `tfnf` console command. It does not bundle the native GUI or a
WebKit runtime.

Use the installation commands below when the matching 0.8.0 package and
native release are available from their distribution channels.

## What is included

The 0.8.0 application brings together:

- paired-v2 profile authoring with editable briefs, Solar Sail and Stellar
  Loom previews, candidate packet exchange and review, application drafts,
  and explicit save/reopen workflows;
- six application appearance families, each with light and dark variants;
- System, Light, and Dark appearance controls, independent light/dark family
  pairs, saved preferences, reset, and bundled fallback appearances; and
- a native desktop GUI launched only after the selected runtime has been
  downloaded, verified, and materialized.

The Python package supplies the launcher and runtime setup boundary. The
application itself is a native package selected for the host platform.

## Install

When 0.8.0 is available, install the Python launcher with Python 3.11 or
newer:

```console
$ python3 -m pip install theme-forge-nebular-fusion==0.8.0
$ tfnf --version
theme-forge-nebular-fusion 0.8.0
```

Installing the Python package does not download the native GUI. Download and
verify the host runtime explicitly, then launch:

```console
$ tfnf install-runtime
$ tfnf
```

`install-runtime` uses the package's 0.8.0 runtime index and fetches the
matching archive from the Theme Forge Nebular Fusion GitHub release service.
The fetcher checks the pinned archive name, size, SHA-256, HTTPS origin, and
permitted release-asset redirect before committing the archive to the local
runtime cache. Ordinary `tfnf` invocation never performs the first download
implicitly.

For a machine-readable installation receipt, use:

```console
$ tfnf install-runtime --json
```

The command reports the selected target, archive and manifest digests, byte
count, whether the archive was downloaded, and the verified redirect hosts.

## Supported hosts and system runtime

The launcher accepts only these consumer environments:

| Host | Launcher target | Consumer requirement |
| --- | --- | --- |
| Apple Silicon macOS | `darwin-arm64` | macOS 13.3 or newer |
| ARM64 Linux | `linux-arm64-gnu` | GNU libc 2.36 or newer and WebKitGTK 4.1 |
| AMD64 Linux | `linux-x64-gnu` | GNU libc 2.36 or newer and WebKitGTK 4.1 |

Linux uses the host's WebKitGTK 4.1. It is not bundled into this Python
package. For Debian or Ubuntu, install the runtime package named by the
launcher:

```console
$ sudo apt install libwebkit2gtk-4.1-0
```

Other distributions should use their own WebKitGTK 4.1 runtime package. The
launcher performs a short WebKit preflight before Linux installation and
before a normal Linux launch. `tfnf --path` is a non-launching path query and
does not require that preflight.

musl, Windows, unsupported CPU architectures, and older platform floors fail
closed. This package does not make a manylinux or bundled-WebKit claim.

## Command reference

```console
$ tfnf --version
$ tfnf --help
$ tfnf install-runtime
$ tfnf install-runtime --json
$ tfnf --path
$ tfnf [application arguments]
```

- `--version` prints the launcher version.
- `--help` prints the launcher usage.
- `install-runtime` performs the explicit, verified native download and
  materialization. Its only supported option is `--json`.
- `--path` prints the authenticated GUI executable path without launching it.
- Other arguments are forwarded to the authenticated native GUI after runtime
  verification.

Each launch verifies the selected runtime manifest and payload before
selecting the native executable.

## Runtime cache and removal

Set `THEME_FORGE_CACHE_DIR` to an absolute directory when you want an
explicit, isolated cache location:

```console
$ export THEME_FORGE_CACHE_DIR=/absolute/path/to/tfnf-runtime
$ tfnf install-runtime
```

Without that variable, the launcher uses `$XDG_CACHE_HOME/rs9/theme-forge-nebular-fusion`
when `XDG_CACHE_HOME` is absolute, `~/Library/Caches/rs9/theme-forge-nebular-fusion`
on macOS, or `~/.cache/rs9/theme-forge-nebular-fusion` on Linux.

To remove the Python launcher:

```console
$ python3 -m pip uninstall theme-forge-nebular-fusion
```

The downloaded native archive is cached separately and is not removed by
uninstall. There is no runtime-removal command; remove only the exact custom
cache directory you selected, or the product cache directory for your
platform, using your operating system's normal file-management tools.

## Troubleshooting

- `TFNF_RUNTIME_MISSING`: run `tfnf install-runtime` before launching.
- `TFNF_RUNTIME_WEBKIT`: install the system WebKitGTK 4.1 runtime package,
  then retry the command.
- `TFNF_RUNTIME_PLATFORM`: confirm Apple Silicon macOS 13.3+, or Linux
  ARM64/AMD64 with GNU libc 2.36+.
- `TFNF_RUNTIME_CACHE`: choose a new absolute `THEME_FORGE_CACHE_DIR` and run
  `tfnf install-runtime` again. The launcher refuses changed, unreadable,
  linked, or otherwise unsafe cache entries.
- `TFNF_RUNTIME_DOWNLOAD`, `TFNF_RUNTIME_TLS`, or
  `TFNF_RUNTIME_REDIRECT`: check the connection and proxy trust, then retry.
  The launcher accepts only the pinned GitHub release-asset route; it does
  not accept an arbitrary download URL.

If `tfnf --path` succeeds, it prints the selected authenticated GUI path
without starting the application. This is useful for diagnosing target
selection separately from GUI startup.

## Native archives and macOS notice

The matching native release uses these target archive names:

```text
theme-forge-nebular-fusion-v0.8.0-aarch64-apple-darwin.app.tar.gz
theme-forge-nebular-fusion-v0.8.0-aarch64-unknown-linux-gnu.tar.gz
theme-forge-nebular-fusion-v0.8.0-x86_64-unknown-linux-gnu.tar.gz
```

The current project disclosure states that the developer app is not Developer
ID signed or notarized. Do not infer signing or notarization from package
availability. Do not bypass Gatekeeper or remove quarantine as an installation
workaround.

## License

Theme Forge Nebular Fusion is offered under **AGPL-3.0-or-later**. Review and
preserve `LICENSE`, `NOTICE`, and `COMMERCIAL-LICENSE.md` when conveying the
package. Those files describe the applicable software and commercial terms.

## Source and release links

- [Theme Forge Nebular Fusion source](https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion)
- [Theme Forge Nebular Fusion releases](https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases)
- [RS9 packaging source](https://github.com/Knowledge-Forge-AI/release-starport-9)
