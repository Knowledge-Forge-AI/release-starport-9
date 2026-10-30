# Theme Forge Nebular Fusion

Theme Forge Nebular Fusion 0.7.0 is a native desktop workbench for reviewing,
inspecting and managing Theme Forge brand systems and artifacts. Install its
Python launcher with pip, install the matching native runtime once, then open
the application with `tfnf`.

## Install and use

Use Python 3.10 or newer. A virtual environment is recommended:

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python3 -m pip install theme-forge-nebular-fusion==0.7.0
$ tfnf install-runtime
$ tfnf
```

The small Python wheel works across the supported targets. The explicit setup
command downloads only the runtime for the current host, about 47–55 MB, from
the project's GitHub release. It checks the pinned archive size, SHA256 and
member manifest before extraction. Repeating setup reuses a valid saved archive
without downloading it again.

Pip does not download the native runtime or install OS packages. Ordinary
`tfnf` launch never downloads: if setup is missing, it reports the setup command.
Once setup is complete, launch uses the verified local cache offline.

```console
$ tfnf --version
theme-forge-nebular-fusion 0.7.0
$ tfnf --help
$ tfnf --path
```

Help and version queries work without the native runtime. After setup,
`--path` checks the saved runtime and prints the resolved GUI executable path.

## Supported hosts and WebKit

| Host | Runtime requirement |
| --- | --- |
| Apple Silicon macOS | macOS 13 or newer |
| Linux ARM64 | GNU glibc 2.36+, GLIBCXX_3.4.30+ |
| Linux AMD64/x86_64 | GNU glibc 2.36+, GLIBCXX_3.4.30+ |

Provide a working graphical desktop, session bus and graphics drivers as for
other native applications. macOS uses the system WebKit framework.

Linux uses the host's WebKitGTK 4.1 runtime. If setup or launch reports that
WebKitGTK 4.1 is unavailable, install your distribution's runtime package first.
On Debian and Ubuntu:

```console
$ sudo apt install libwebkit2gtk-4.1-0
$ tfnf install-runtime
```

WebKitGTK 4.0 and 6.0 have different library interfaces and do not replace 4.1.
The prerequisite check does not install system packages.

## Integrity and cache behavior

Runtime setup accepts only fixed official release assets with the identities
carried by this package. Invalid or incomplete downloads never become extraction
inputs. The launcher checks the archive, manifest, extracted members and exact
executable paths before handoff. It does not check out source, compile code or
select a fallback application.

Runtime archives and materialized files use the cache selected by
`THEME_FORGE_CACHE_DIR`, then `XDG_CACHE_HOME`, or the platform default. Custom
cache paths must be absolute and non-empty. Runtime setup requires network
access only when a verified archive is not already saved.

Setup allows a 15-minute download acceptance budget, with a 10-second timeout
for individual network operations. If it expires, check the connection and
retry `tfnf install-runtime`. A certificate-verification error requires fixing
Python's trusted certificates or your proxy's trust configuration before retrying.

Setup can repair a corrupt or unreadable archive that you own. If it reports
an unsafe cache, choose a new absolute directory and repeat setup:

```console
$ export THEME_FORGE_CACHE_DIR="$HOME/.cache/nebular-fusion-runtime"
$ tfnf install-runtime
```

Use the same cache setting for later launches.

Remove the Python launcher with
`python3 -m pip uninstall theme-forge-nebular-fusion`. Its versioned runtime
cache remains available for reuse.

## License

Theme Forge Nebular Fusion and this Python distribution are offered under
**AGPL-3.0-or-later**. Preserve the distributed `LICENSE` and `NOTICE` files when
using or conveying the package. The Python launcher and downloaded application
each include their applicable license and notice files. Native runtime assets
retain their distributed third-party notices.
