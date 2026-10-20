# Theme Forge: Stellar Burst (`theme-forge-stellar-burst`)

- **PyPI distribution version:** `0.6.1.post1`
- **Upstream release version:** `0.6.1`
- **Upstream npm package:** `@knowledge-forge-ai/theme-forge-stellar-burst`
- **Upstream source commit:** `a3e89683f92b8240c800ed303c866e7b12aa3277`
- **Upstream release tag:** [v0.6.1](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/releases/tag/v0.6.1)
- **Console script entrypoints:** `tfsb`, `tfsb-studio-service`
- **SPDX license expression:** `AGPL-3.0-or-later AND MIT AND BSD-3-Clause`
- **Python requirement:** `>=3.9`
- **External runtime requirement:** `Node.js >=22` (`Requires-External: nodejs (>=22)`)

---

## Overview

Theme Forge Stellar Burst (TFSB) is a deterministic declarative SVG compiler, transactional installer, and lifecycle drift checker, packaged with its JSON-RPC 2.0 studio service (`tfsb-studio-service`) as the `theme-forge-stellar-burst` Python distribution (`0.6.1.post1`). It turns a bounded, safe subset of SVG into human-editable TOML, compiles canonical standards-compliant SVGs, distributes assets to configured project destinations, and manages upstream asset updates safely without silently overwriting human changes.

```text
SVG bundle
   ↓ import
.tfsb TOML + companions
   ↓ build / install / check
reconcile / diff / fmt / bundle / preview
```

### Why TFSB

Raw SVG is XML: verbose, error-prone to edit by hand, noisy in pull request diffs, and vulnerable to accidental corruption or drift across different application directories. TFSB brings software-engineering discipline to vector asset pipelines:

- **Human-editable TOML:** Vector graphics are structured in clean, readable TOML rather than unwieldy XML markup.
- **Single source of truth:** `.tfsb` is canonical project state. Change a color, gradient, or dimension once in TOML, then rebuild and reinstall across your entire repository.
- **Interoperable output:** Generated output remains standards-compliant SVG with deterministic attribute ordering, clean formatting, and no proprietary runtime dependencies.
- **Companion integrity:** Opaque brand and legal companion documents (`README.md`, `LICENSE`, `NOTICE`, `COPYING`, `COPYRIGHT`) travel byte-for-byte alongside vector assets without being mutated or executed.
- **Safe reconciliation:** Upstream revisions reconcile against paired-checkpoint provenance so manual edits are never silently clobbered.

### Release Scope and Capabilities

The `.post1` PEP 440 post-release suffix identifies the first Python packaging revision of the immutable upstream `0.6.1` release. Version `0.6.1` is a patch successor of `0.6.0`, which follows the [0.5.0 release](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/releases/tag/v0.5.0) and historical [0.4.0 release notes](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/blob/a3e89683f92b8240c800ed303c866e7b12aa3277/docs/releases/v0.4.0.md). Related Theme Forge products are independently versioned: [Stellar Loom](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom), [Nebular Fusion](https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion), and [Terminal Nova](https://github.com/Knowledge-Forge-AI/starlight-theme-terminal-nova).

Since `0.5.0`, Stellar Burst includes the closed `./scene/v1` upstream Node.js library export and `tfsb scene` commands for accessible vector scenes, deterministic SVG compilation, layout, labels, and bounded SVG import; see the upstream [Scene contract](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/blob/a3e89683f92b8240c800ed303c866e7b12aa3277/protocol/tfsb-scene-v1/README.md) and [import contract](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/blob/a3e89683f92b8240c800ed303c866e7b12aa3277/protocol/tfsb-scene-v1/import-svg.md). Existing `0.4` asset, installation, and drift contracts remain supported.

This release distributes SVG only. Clips, masks, embedded or external resource ingestion, and distributed PNG output remain deferred. Raster capability is reported unavailable without a separately qualified renderer; no renderer is silently downloaded. `nova-social` is an SVG source artifact, with no promise of social-platform image compatibility.

---

## Wheel Targets and Requirements

Platform wheels and host-targeted source-distribution (`sdist`) builds support three POSIX environments:

| Target Key | Operating System & Architecture | PEP 425 Wheel Tag | Minimum C Library / OS Floor | Retained Native Addon Prebuild |
| :--- | :--- | :--- | :--- | :--- |
| `darwin-arm64` | macOS Apple Silicon (`arm64`) | `py3-none-macosx_13_0_arm64` | macOS 13.0+ | `native/directory-snapshot/prebuilds/darwin-arm64/native-addon-posix-openat-v1.node` |
| `linux-arm64-gnu` | Linux ARM64 (`aarch64`, GNU libc) | `py3-none-manylinux_2_33_aarch64` | `glibc >= 2.33` | `native/directory-snapshot/prebuilds/linux-arm64-gnu/native-addon-posix-openat-v1.node` |
| `linux-x64-gnu` | Linux AMD64 (`x86_64`, GNU libc) | `py3-none-manylinux_2_33_x86_64` | `glibc >= 2.33` | `native/directory-snapshot/prebuilds/linux-x64-gnu/native-addon-posix-openat-v1.node` |

### Distribution Filenames

- `theme_forge_stellar_burst-0.6.1.post1-py3-none-macosx_13_0_arm64.whl`
- `theme_forge_stellar_burst-0.6.1.post1-py3-none-manylinux_2_33_aarch64.whl`
- `theme_forge_stellar_burst-0.6.1.post1-py3-none-manylinux_2_33_x86_64.whl`
- `theme_forge_stellar_burst-0.6.1.post1.tar.gz`

---

## Prerequisites

1. **Python `>=3.9`** with `pip`.
2. **Node.js `>=22`** (`v22.0.0` or newer) matching the wheel's target operating system, CPU architecture, and (on Linux) GNU `libc` (`glibc >= 2.33`).

Verify both runtimes before installation:

```sh
python3 --version
node --version
```

---

## Installation and Upgrade

Standard installation from PyPI downloads the distribution over the network:

```sh
python3 -m pip install "theme-forge-stellar-burst==0.6.1.post1"
```

Upgrade an existing installation to `0.6.1.post1`:

```sh
python3 -m pip install --upgrade "theme-forge-stellar-burst==0.6.1.post1"
```

### Offline Installation from Local Artifacts

All upstream JavaScript modules (`dist/`), the target-matched POSIX `openat` native directory-snapshot addon, and the three runtime npm dependencies (`@xmldom/xmldom@0.9.12`, `fflate@0.8.3`, `smol-toml@1.8.0`) are bundled inside the distribution. The Python packaging adapter and launcher never invoke `npm`, `npx`, or `corepack`.

To install offline from a local directory (`./dist`) containing the prebuilt wheel or `.tar.gz` sdist without network access:

```sh
python3 -m pip install --no-index --no-deps --find-links ./dist "theme-forge-stellar-burst==0.6.1.post1"
```

`--no-deps` is safe because `theme-forge-stellar-burst` declares zero Python package dependencies and `build-system.requires = []`. When building a wheel from `theme_forge_stellar_burst-0.6.1.post1.tar.gz`, the bundled offline PEP 517 backend (`rs9.tf_pypi_backend` under `_rs9_build/`) selects the current host target (`darwin-arm64`, `linux-arm64-gnu`, or `linux-x64-gnu`) via `host_key()`, refuses unsupported build hosts (such as `darwin-x64` or non-glibc Linux), and rejects any PEP 517 `config_settings`.

---

## Node.js Resolution and Launcher Diagnostics

At runtime, the console-script wrapper (`theme_forge_stellar_burst.launcher`) locates the Node.js executable in the following order:

1. **`THEME_FORGE_NODE_BIN` environment variable:** If set and non-empty, the launcher uses that path directly without falling back to `PATH`.
2. **`PATH` lookup:** Otherwise, the launcher resolves `node` on `PATH`.

To bind execution to a specific Node.js `>=22` binary:

```sh
export THEME_FORGE_NODE_BIN="/opt/node-v22/bin/node"
tfsb --version
```

### Runtime Verification and Failure Codes

Before handing off execution with `os.execv`, the launcher verifies:

1. The host `os.name` is `"posix"` and the packaged JavaScript entrypoint exists on disk.
2. `<node> --version` reports a major version `>=22`.
3. A subprocess check of Node's `process.platform`, `process.arch`, and `process.report.getReport().header.glibcVersionRuntime` matches the wheel's `PLATFORM_KEY` (`darwin-arm64`, `linux-arm64-gnu`, or `linux-x64-gnu`) and, on Linux, confirms GNU `libc` meets `MIN_GLIBC` (`2.33`). Note that the macOS `13.0` deployment floor is enforced by the wheel tag (`macosx_13_0_arm64`) rather than a runtime macOS version probe.

If any check fails, the launcher exits with status `1` and writes a single line to `stderr` in the fixed format:

```text
<TOKEN>: Node.js >=22 and an intact supported POSIX installation are required.
```

| Diagnostic Token | Triggering Conditions |
| :--- | :--- |
| `TF_PYPI_NODE_REQUIRED` | Non-POSIX host, missing packaged entrypoint file, `node` not found on `PATH`, `THEME_FORGE_NODE_BIN` missing or non-executable, `--version` query failure, or detected Node.js major version older than `22`. |
| `TF_PYPI_NODE_PLATFORM` | Node's reported `process.platform`/`process.arch` does not match the wheel's `PLATFORM_KEY` (for example, running an `x64` Node.js binary under Rosetta 2 on `darwin-arm64`), Linux runtime is non-glibc (such as musl), or Linux runtime `glibc` is older than `2.33`. |

The installed Python package (`theme_forge_stellar_burst`) ships an empty `__init__.py` and exposes no Python library API; installing via `pip` provides the `tfsb` and `tfsb-studio-service` console scripts on `PATH`.

---

## Project Configuration and Asset Model

### New-Project Quick Start

1. **Import** an archive of vector assets into your project:

   ```sh
   tfsb import brand-assets.zip --root . --companion README.md --record-provenance
   ```

2. **Configure** target destinations in `.tfsb/project.toml`.
3. **Build** canonical SVGs into the build directory:

   ```sh
   tfsb build
   ```

4. **Install** compiled SVGs to configured project locations:

   ```sh
   tfsb install
   ```

5. **Verify** that sources, builds, and installed files are synchronized:

   ```sh
   tfsb check
   ```

6. **Inspect** all managed assets, companion documents, and configured destinations:

   ```sh
   tfsb list
   ```

7. **Preview** your asset collection in a static offline visual gallery:

   ```sh
   tfsb preview
   ```

### Project Configuration (`.tfsb/project.toml`)

```toml
schema_version = 1
name = "My Application Brand"

[build]
directory = "brand/dist"

[[install]]
asset = "favicon"
destinations = [
  "public/favicon.svg",
  "docs/src/assets/brand/favicon.svg",
]
```

> **Build directory vs. install destinations:**
> - The **build directory** (`brand/dist`) is a TFSB-owned directory that may be wholesale generated and replaced. Protected source trees (`src`, `docs`, `test`) are intentionally forbidden as `build.directory` to prevent accidental deletion of source code.
> - An **install destination** is an individual configured file copy inside the project. Install destinations may live inside source or application trees (such as `docs/src/assets/brand/` or `public/`), provided they do not overlap `.tfsb` or the build directory.

### Optional Bundle Companion Documents

When an archive carries legal, licensing, or brand guidance documents, pass `--companion <path>` during import:

```sh
tfsb import brand-assets.zip --root . --companion README.md --record-provenance
```

Then configure the companion installation in `.tfsb/project.toml`:

```toml
[[companion]]
file = "README.md"
destinations = [
  "README-BRAND.md",
]
```

### Asset Configuration (`.tfsb/assets/favicon.toml`)

```toml
schema_version = 1
id = "favicon"
filename = "favicon.svg"

[canvas]
width = 64
height = 64
view_box = "0 0 64 64"
shape_rendering = "geometricPrecision"

[accessibility]
title = "Application Favicon"
title_id = "app-favicon-title"
description = "Application brand favicon."
description_id = "app-favicon-desc"

[[definitions.linear_gradients]]
id = "brand-gradient"
x1 = 22
y1 = 21
x2 = 42
y2 = 43
units = "userSpaceOnUse"
stops = [
  { offset = 0, color = "#FF8A3D" },
  { offset = 1, color = "#8B5CF6" },
]

[[elements]]
type = "path"
id = "center-mark"
fill = "url(#brand-gradient)"
fill_fallback = "#FF8A3D"
d = "M32 20 C33 26.5 36 29.5 44 32 C36 34.5 33 37.5 32 44 C31 37.5 28 34.5 20 32 C28 29.5 31 26.5 32 20Z"
```

For additional format and lifecycle examples in the upstream repository, see the [v0.1 assets](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/blob/a3e89683f92b8240c800ed303c866e7b12aa3277/docs/examples/v0.1/README.md) and [v0.2 lifecycle examples](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/blob/a3e89683f92b8240c800ed303c866e7b12aa3277/docs/examples/v0.2/README.md).

### Directory Import with Source Maps (`.tfsb-source-map.toml`)

In addition to ZIP archives, `tfsb import` can ingest a directory tree using a declarative TOML source map (`--source-map <map.toml>`) and a named collection (`--collection <id>`):

```toml
schema_version = 1
source_root = "."

[[collection]]
id = "icons"
name = "Icons"
root = "."
identity = "basename"
prefix = ""
include_paths = ["icon.svg"]
include_trees = []
exclude_paths = []
exclude_trees = []
```

Example directory import, build, check, and bundle sequence:

```sh
tfsb import ./source \
  --source-map ./source/.tfsb-source-map.toml \
  --collection icons \
  --normalize exact-common \
  --root ./project \
  --json

tfsb build --root ./project
tfsb check --root ./project --json
tfsb bundle --output qualified.zip --root ./project --json
```

---

## Updating, Migration, and Normalization

### Reconciling Upstream Revisions

When upstream designers supply a revised ZIP archive, reconcile incoming updates against canonical state and paired provenance checkpoints:

```sh
# 1. Inspect planned changes safely (read-only by default)
tfsb reconcile revised-brand-assets.zip

# 2. Apply planned changes transactionally
tfsb reconcile revised-brand-assets.zip --apply
```

- **Read-only by default:** `tfsb reconcile` analyzes differences without writing to disk.
- **Human canonical edits are never overwritten silently:** Canonical modifications made since the last import or reconcile are detected and preserved.
- **Omissions never delete:** If an asset in your project is omitted from the new archive, it is preserved as an accepted absence (tombstone) rather than silently deleted.
- **Conflicts need exact per-record authority:** When upstream changes conflict with local canonical edits, exact flags (`--resolve <id>=archive|canonical`, `--rename <from>=<to>`, `--remove <id>`) are required to authorize the change.
- **Renames and removals are explicit:** All renames and removals require operator confirmation.

### Schema-1 to Schema-2 Migration and Normalization

Stellar Burst supports explicit schema-1 to schema-2 migration and normalization for supported common SVG sources:

```sh
# Read-only: exit 2 when a complete valid migration is available
tfsb migrate --check
tfsb migrate --check --json

# Transactionally replace one homogeneous schema-1 tree with schema 2
tfsb migrate
tfsb migrate --json
```

Migration reparses the complete proposed tree and requires every schema-1 and schema-2 canonical SVG output to be byte-identical. Companions and an existing build receipt are left untouched; the receipt naturally reports source drift until the next explicit build.

Noncanonical common-v0.3 sources require explicit normalization authority:

```sh
tfsb import source.zip --root . \
  --normalize exact-common \
  --normalization-map normalization-map.toml \
  --record-provenance

tfsb reconcile revised.zip --dry-run \
  --normalize exact-common \
  --normalization-map normalization-map.toml
```

Canonical direct schema-2 input remains direct and needs no normalization flag. The map is required only where source accessibility intent cannot be derived safely. Reconciliation of changed normalized source accepts only the stored policy identity or a formatting-equivalent map with the same canonical digest; unavailable or semantically changed authority blocks the operation.

### Upgrading a v0.1 Project

- **Bootstrap provenance:** A matching archive can bootstrap provenance with `reconcile ... --apply` to generate `.tfsb/provenance.json`.
- **Mismatching archive:** A mismatching archive requires explicit decisions (`--resolve`, `--rename`, `--remove`).
- **Build receipts:** Valid v2 build receipts remain accepted as build ownership evidence for `check`, `build`, and `install`.
- **Upgrade to v3 receipt:** Run `tfsb build` once to emit v3 policy evidence before using `diff --build`.
- **Preview directory:** `.tfsb-preview` is generated state and should be added to `.gitignore`.

---

## Portable Bundles, Inspection, and Automation

### Portable Bundles

Export your canonical project into a portable, reproducible ZIP bundle:

```sh
# Export complete canonical assets and companions
tfsb bundle --output release/brand-assets.zip

# Import into a clean project preserving declared asset IDs and names
tfsb import release/brand-assets.zip --manifest --root ../fresh-copy
```

- **Deterministic store-only ZIPs:** Bundle archives use level 0 compression, fixed timestamps, and canonical header sorting for byte-stable hashes across environments.
- **Exact manifest verification:** The bundle includes `tfsb-manifest.json` containing cryptographic SHA-256 digests and asset identifiers.
- **Identity preservation:** Importing with `--manifest` restores declared asset IDs and file names instead of guessing from basenames.
- **No policy transport:** Bundles transport only canonical artwork and companion documents; installation destinations and provenance history remain private to each repository.

### Inspection, Diffing, Formatting, and Preview

```sh
# Compare canonical state against paired provenance checkpoint
tfsb diff

# Compare canonical state against an external archive
tfsb diff --archive revised.zip

# Compare canonical state against build outputs (requires v3 receipt)
tfsb diff --build

# Compare canonical state against installed destinations
tfsb diff --install

# Check canonical TOML formatting without writing
tfsb fmt --check

# Format canonical TOML files deterministically
tfsb fmt

# Render an offline HTML preview gallery
tfsb preview

# Emit machine-readable output for automation
tfsb check --json
```

### Automation and Machine Results

Commands supporting `--json` (`check`, `list`, `migrate`, `reconcile`, `diff`, `bundle`, `fmt`, `preview`) emit a single envelope matching JSON schema version 1 with deterministic key sorting:

- **Exit code `0`:** Clean / success.
- **Exit code `1`:** Invalid / failed operation.
- **Exit code `2`:** Valid drift / conflict state.

---

## Safety Limits

TFSB enforces a defense-in-depth safety architecture:

- **Local archives only:** Processes only local archives or directories provided by the operator; no arbitrary network access.
- **Fail-closed SVG subset:** Supports a safe declarative subset (paths, groups, linear gradients, use references, accessibility tags). Scripts, CSS `<style>` blocks, external resources, foreign objects, and unparsed XML fail closed.
- **No scripts or executable companions:** Scripts (`.js`, `.ts`, `.py`, `.sh`) and executable companion files are rejected immediately.
- **Explicit normalization only:** `exact-common` performs a closed set of typed operations. It never repairs arbitrary IDs, CSS, external references, or unsafe/unsupported content.
- **Path and symlink confinement:** Absolute paths, `..` traversal, and symlink traversals fail closed across all read, write, build, and install operations.
- **Exact companion allowlist:** Only text documentation (`*.md`, `*.markdown`, `*.txt`) and well-known legal documents (`LICENSE`, `NOTICE`, `COPYING`, `COPYRIGHT`) are permitted as companions.
- **Quantitative bounds:** Maximum 1,024 archive entries, maximum 128 selected/mutating SVG assets, 8 MiB per selected entry, 32 MiB selected aggregate, and 128 MiB raw archive size.
- **Curated scope:** TFSB is designed for bounded, curated brand and application icon sets rather than full external icon warehouses.

---

## Studio Service Protocol (`tfsb-studio-service`)

The `tfsb-studio-service` console script (`dist/service-protocol/server-cli.js`) runs a newline-delimited **JSON-RPC 2.0** server over standard input (`stdin`) and standard output (`stdout`). It speaks the JSON-RPC 2.0 lifecycle protocol over stdio rather than taking `--help` or `--version` CLI flags.

### Lifecycle Handshake (`initialize` -> `initialized` -> `shutdown` -> `exit`)

1. **`initialize` request (`id: 1`):** Client sends protocol negotiation parameters (`protocol: "tfsb.studio"`, `minVersion: "1.0"`, `maxVersion: "1.2"`). Server responds with `result.selectedVersion`, `result.sessionNonce`, and `result.server.version` (`"0.6.1"`).
2. **`initialized` notification:** Client echoes `params.sessionNonce` to activate the session.
3. **`shutdown` request (`id: 2`):** Client requests an orderly shutdown using `params.sessionNonce`. Server replies with `"result": null`.
4. **`exit` notification:** Client sends `{"jsonrpc": "2.0", "method": "exit", "params": {}}` and the server exits with status `0`.

### Example Session from Python (`subprocess`)

```python
import json
import subprocess

proc = subprocess.Popen(
    ["tfsb-studio-service"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

init_req = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocol": "tfsb.studio",
        "minVersion": "1.0",
        "maxVersion": "1.2",
        "client": {"name": "example-client", "version": "1.0.0"},
        "capabilities": {"progress": False, "cancellation": False},
    },
}
proc.stdin.write(json.dumps(init_req) + "\n")
proc.stdin.flush()

init_resp = json.loads(proc.stdout.readline())
nonce = init_resp["result"]["sessionNonce"]

proc.stdin.write(json.dumps({
    "jsonrpc": "2.0",
    "method": "initialized",
    "params": {"sessionNonce": nonce},
}) + "\n")
proc.stdin.write(json.dumps({
    "jsonrpc": "2.0",
    "id": 2,
    "method": "shutdown",
    "params": {"sessionNonce": nonce},
}) + "\n")
proc.stdin.flush()

shutdown_resp = json.loads(proc.stdout.readline())

proc.stdin.write(json.dumps({
    "jsonrpc": "2.0",
    "method": "exit",
    "params": {},
}) + "\n")
proc.stdin.close()
rc = proc.wait(timeout=10)
assert rc == 0
```

---

## Package Layout, Native Addon, and Bundled Dependencies

When installed into a Python environment, `theme-forge-stellar-burst` unpacks under `site-packages/theme_forge_stellar_burst/` and `site-packages/theme_forge_stellar_burst-0.6.1.post1.dist-info/`:

```text
theme_forge_stellar_burst/
  __init__.py
  launcher.py
  payload/
    package/
      package.json
      LICENSE
      NOTICE
      COMMERCIAL-LICENSE.md
      dist/
        cli.js
        directory-snapshot-native.js
        service-protocol/
          server-cli.js
        ...
      native/
        directory-snapshot/
          prebuilds/
            <target>/
              native-addon-posix-openat-v1.node
      node_modules/
        @xmldom/xmldom/
        fflate/
        smol-toml/
theme_forge_stellar_burst-0.6.1.post1.dist-info/
  METADATA
  WHEEL
  RECORD
  entry_points.txt
  rs9-tf-transform.json
  licenses/
    LICENSE
    NOTICE
    COMMERCIAL-LICENSE.md
    RS9-LICENSE
    RS9-NOTICE
    node_modules/@xmldom/xmldom/LICENSE
    node_modules/fflate/LICENSE
    node_modules/smol-toml/LICENSE
```

### Native Addon Selection (`native-addon-posix-openat-v1.node`)

Stellar Burst uses a compiled Node-API addon (`native-addon-posix-openat-v1.node`) for POSIX `openat` directory snapshots, loaded by `dist/directory-snapshot-native.js` (`loadDirectorySnapshotNative`). The upstream `0.6.1` release archive ships four prebuilt binaries (`darwin-arm64`, `darwin-x64`, `linux-arm64-gnu`, and `linux-x64-gnu`). During wheel construction:

- The one prebuild matching the wheel's target (`native/directory-snapshot/prebuilds/<target>/native-addon-posix-openat-v1.node`) is retained inside `theme_forge_stellar_burst/payload/package/`.
- The other three prebuilds are omitted from the wheel and recorded in `theme_forge_stellar_burst-0.6.1.post1.dist-info/rs9-tf-transform.json`.
- The source distribution (`theme_forge_stellar_burst-0.6.1.post1.tar.gz`) embeds the complete unmodified upstream tarball and all three dependency tarballs under `upstream/`.

### Bundled Runtime Dependency Closure

The following runtime npm dependencies are bundled under `theme_forge_stellar_burst/payload/package/node_modules/`:

| Package | Version | License |
| :--- | :--- | :--- |
| `@xmldom/xmldom` | `0.9.12` | `MIT` |
| `fflate` | `0.8.3` | `MIT` |
| `smol-toml` | `1.8.0` | `BSD-3-Clause` |

---

## Licensing and Legal Notices

The combined distribution is governed by the SPDX license expression:

```text
AGPL-3.0-or-later AND MIT AND BSD-3-Clause
```

- **Upstream payload (`@knowledge-forge-ai/theme-forge-stellar-burst`):** Licensed under the GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`). Copyright and attribution details are provided in `NOTICE`. Commercial licenses are available for proprietary integration, closed-source distribution, OEM bundling, or organizations requiring custom licensing terms, and do not restrict permitted AGPL use (inquiries: `lair001@gmail.com`; see `COMMERCIAL-LICENSE.md`).
- **RS9 Python packaging adapter (`theme_forge_stellar_burst/launcher.py` and `_rs9_build/rs9/*`):** Licensed under `AGPL-3.0-or-later` (`RS9-LICENSE` and `RS9-NOTICE`).
- **Bundled third-party npm dependencies:** `@xmldom/xmldom` (`0.9.12`, `MIT`), `fflate` (`0.8.3`, `MIT`), and `smol-toml` (`1.8.0`, `BSD-3-Clause`), with their respective `LICENSE` files included under `.dist-info/licenses/node_modules/<pkg>/LICENSE` and in the sdist root.

### Upstream Repository References

- **Source:** `https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/tree/a3e89683f92b8240c800ed303c866e7b12aa3277`
- **Release:** `https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/releases/tag/v0.6.1`
