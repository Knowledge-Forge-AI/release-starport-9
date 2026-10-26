# Theme Forge Nebular Fusion

Theme Forge Nebular Fusion is the Python distribution of the Nebular Fusion
desktop application. The upstream application release and this Python
distribution are version **0.7.0**. This Gate1 profile packages the
authenticated upstream application payload byte-for-byte and provides an
offline Python 3/pip launcher.

## What this package contains

The wheel contains the released native application archive, its authenticated
archive manifest, and a small isolated materialization runtime. The runtime
extracts the archive into a private cache, checks the archive and manifest
digests, checks every extracted member against the manifest, and then resolves
the exact captured application launcher. It does not download application
content or execute a guessed path.

The console command is `tfnf`. The command forwards ordinary arguments to the
captured application launcher. The diagnostic options are available before
materialization:

```console
$ tfnf --version
theme-forge-nebular-fusion 0.7.0
$ tfnf --help
Usage: tfnf [--version|--help|--path] [application args...]
```

After the archive has passed platform, manifest, and executable-path checks,
`tfnf --path` prints the absolute path of the captured GUI executable. This is
useful for integrations that need to inspect the resolved application without
starting it.

## Installation and use

Install the wheel with Python 3.10 or newer and pip:

```console
$ python3 -m pip install theme-forge-nebular-fusion==0.7.0
$ tfnf
```

For an offline, wheel-only installation, provide a local wheel and disable
index, dependency, and source-distribution fallback:

```console
$ python3 -m pip install --no-index --no-deps --only-binary=:all: ./theme_forge_nebular_fusion-0.7.0-<platform>.whl
```

This successor publishes no source distribution and does not fall back to a
source build. The wheel must be selected for the host platform before
installation. Remove it with pip when it is no longer needed:

```console
$ python3 -m pip uninstall theme-forge-nebular-fusion
```

Use a virtual environment when installing an application for a project:

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python3 -m pip install theme-forge-nebular-fusion==0.7.0
$ tfnf --path
```

The cache location can be selected with `THEME_FORGE_CACHE_DIR`. When it is
unset, macOS uses `~/Library/Caches/rs9/theme-forge-nebular-fusion` and Linux
uses `$XDG_CACHE_HOME/rs9/theme-forge-nebular-fusion` or
`~/.cache/rs9/theme-forge-nebular-fusion`. The cache is content-addressed by
the authenticated manifest and is safe to remove when the application is not
running. The selected cache directory is created with mode `0700`; set
`THEME_FORGE_CACHE_DIR` to a dedicated absolute directory. Empty or relative
values are rejected for that variable, and empty or relative `XDG_CACHE_HOME`
values are ignored.

## Supported wheel targets

The Gate1 profile covers Apple Silicon macOS, Linux arm64, and Linux amd64.
Linux wheels use truthful generic `linux_aarch64` or `linux_x86_64` tags and do
not claim `manylinux`, `musllinux`, or universal compatibility. The current
runtime policy names glibc **2.36** and GLIBCXX **3.4.30** as conservative
provider floors for both Linux architectures; the embedded ELF/provider
closure remains a separate qualification input. Only separately qualified
release rows may be installed from a public index. Linux hosts also need the
system GTK and WebKitGTK runtime libraries required by the native application;
the wheel does not bundle or install those system libraries.

The Darwin payload and every `Contents/MacOS` Mach-O executable must agree on
an actual macOS deployment floor of **13.0**. The wheel tag and the embedded
`Info.plist` are not sufficient by themselves; Gate1 records the cross-check
against each native executable.

## Offline and reproducible behavior

The launcher is offline after installation. It verifies the embedded payload
archive and manifest before materializing anything. Extraction rejects unsafe
paths, privileged modes, hard links, escaping links, duplicate members, and
manifest mismatches. The materialized launcher and GUI executable are selected
from authenticated release metadata and are checked for executable regular
files before use.

The wheel's `_rs9/provenance.json` records the declared PEP 639 license
expression `AGPL-3.0-or-later`, the required `LICENSE` and `NOTICE` files, an
optional `COMMERCIAL-LICENSE.md` companion when that authenticated source file
is present, the Markdown project description path and digest, the upstream
release identity, the payload and manifest digests, the profile and floor
evidence, and the source hashes of the isolated helper modules. These
provenance fields are separate from the PEP 639 headers in `METADATA`. Gate1
is a candidate-only profile: source closure, Linux provider qualification, and
publication admission remain false or pending until their separate evidence
is authenticated.

Archive, manifest, platform, and executable-path checks run immediately before
materialization. `tfnf --path` reports the resolved GUI path without launching
the application. Do not rename, replace, or mutate the wheel, cache archive,
manifest, or resolved executable between those checks and use; changes made by
another process after resolution are outside this package's guarantee.

## License

The declared distribution license is **AGPL-3.0-or-later**. If the
authenticated upstream release includes `COMMERCIAL-LICENSE.md`, that file is
preserved as an optional companion for readers who need the upstream
commercial terms; it does not change the distribution's declared metadata
expression.

## Reporting problems

When reporting a packaging problem, include the output of `python3 -m pip
show theme-forge-nebular-fusion`, the wheel filename, and the result of
`tfnf --version`. Do not include tokens, private keys, personal credentials,
or private release evidence in an issue report.
