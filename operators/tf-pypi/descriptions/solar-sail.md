# Theme Forge: Solar Sail (`theme-forge-solar-sail`)

- **PyPI distribution version:** `0.2.1.post1`
- **Upstream release version:** `0.2.1`
- **Upstream npm package:** `@knowledge-forge-ai/theme-forge-solar-sail`
- **Upstream source commit:** `68e3f95a27cf1681aabb1fccb55e8b78d23b5fa0`
- **Upstream release tag:** [v0.2.1](https://github.com/Knowledge-Forge-AI/theme-forge-solar-sail/releases/tag/v0.2.1)
- **Console script entrypoint:** `tfss`
- **SPDX license expression:** `AGPL-3.0-or-later`
- **Python requirement:** `>=3.9`
- **External runtime requirement:** `Node.js >=22` (`Requires-External: nodejs (>=22)`)

---

## Overview

Theme Forge Solar Sail is a deterministic theme compiler, library, and `tfss` CLI for Tailwind CSS v4 and shadcn/ui application theming (`tfss.theme-v1`), packaged as the `theme-forge-solar-sail` Python distribution (`0.2.1.post1`). It serves as the application-theming sibling engine to Theme Forge Stellar Loom.

The `.post1` PEP 440 post-release suffix identifies the first Python packaging revision of the immutable upstream `0.2.1` release (`@knowledge-forge-ai/theme-forge-solar-sail` `0.2.1`, a patch successor of `0.2.0`).

Theme Forge Solar Sail translates declarative theme specifications (`tfss.theme-v1`) into:

- **Tailwind CSS v4 `@theme inline` configuration:** Emits clean CSS theme variables directly compatible with Tailwind v4's stylesheet-first engine.
- **shadcn/ui semantic roles:** Maps tokens to standard component roles (`background`, `foreground`, `card`, `popover`, `primary`, `secondary`, `muted`, `accent`, `destructive`, `border`, `input`, `ring`, plus optional `chart1`–`chart5` and canonical `sidebar*` tokens).
- **Light and dark theme support:** Emits scoped `:root` and `.dark` / `@custom-variant dark (&:is(.dark *))` styles.
- **Radius progression:** Defines full radius scales from `--radius-sm` through `--radius-4xl`.
- **Actionable diagnostics:** Verifies color contrast ratios against background tokens and reports contrast diagnostics.
- **Standalone distribution packages:** Generates self-contained packages in TypeScript (`--language typescript`) or zero-build JavaScript (`--language javascript`) that require zero runtime dependencies on Solar Sail or any external service.
- **Dependency-free upstream payload:** Solar Sail has zero third-party npm dependencies and zero native binary addons.

---

## Wheel Targets and Requirements

Platform wheels and host-targeted source-distribution (`sdist`) builds support three POSIX environments:

| Target Key | Operating System & Architecture | PEP 425 Wheel Tag | Minimum C Library / OS Floor |
| :--- | :--- | :--- | :--- |
| `darwin-arm64` | macOS Apple Silicon (`arm64`) | `py3-none-macosx_11_0_arm64` | macOS 11.0+ |
| `linux-arm64-gnu` | Linux ARM64 (`aarch64`, GNU libc) | `py3-none-manylinux_2_28_aarch64` | `glibc >= 2.28` |
| `linux-x64-gnu` | Linux AMD64 (`x86_64`, GNU libc) | `py3-none-manylinux_2_28_x86_64` | `glibc >= 2.28` |

### Distribution Filenames

- `theme_forge_solar_sail-0.2.1.post1-py3-none-macosx_11_0_arm64.whl`
- `theme_forge_solar_sail-0.2.1.post1-py3-none-manylinux_2_28_aarch64.whl`
- `theme_forge_solar_sail-0.2.1.post1-py3-none-manylinux_2_28_x86_64.whl`
- `theme_forge_solar_sail-0.2.1.post1.tar.gz`

---

## Prerequisites

1. **Python `>=3.9`** with `pip`.
2. **Node.js `>=22`** (`v22.0.0` or newer) matching the wheel's target operating system, CPU architecture, and (on Linux) GNU `libc` (`glibc >= 2.28`).

Verify both runtimes before installation:

```sh
python3 --version
node --version
```

---

## Installation and Upgrade

Standard installation from PyPI downloads the distribution over the network:

```sh
python3 -m pip install "theme-forge-solar-sail==0.2.1.post1"
```

Upgrade an existing installation to `0.2.1.post1`:

```sh
python3 -m pip install --upgrade "theme-forge-solar-sail==0.2.1.post1"
```

### Offline Installation from Local Artifacts

The entire upstream release payload is bundled inside the wheel and sdist. The Python packaging adapter and launcher never invoke `npm`, `npx`, or `corepack`.

To install offline from a local directory (`./dist`) containing the prebuilt wheel or `.tar.gz` sdist without network access:

```sh
python3 -m pip install --no-index --no-deps --find-links ./dist "theme-forge-solar-sail==0.2.1.post1"
```

`--no-deps` is safe because `theme-forge-solar-sail` declares zero Python package dependencies and `build-system.requires = []`. When building a wheel from `theme_forge_solar_sail-0.2.1.post1.tar.gz`, the bundled offline PEP 517 backend (`rs9.tf_pypi_backend` under `_rs9_build/`) selects the current host target (`darwin-arm64`, `linux-arm64-gnu`, or `linux-x64-gnu`) via `host_key()`, refuses unsupported build hosts (such as `darwin-x64` or non-glibc Linux), and rejects any PEP 517 `config_settings`.

---

## Node.js Resolution and Launcher Diagnostics

At runtime, the console-script wrapper (`theme_forge_solar_sail.launcher`) locates the Node.js executable in the following order:

1. **`THEME_FORGE_NODE_BIN` environment variable:** If set and non-empty, the launcher uses that path directly without falling back to `PATH`.
2. **`PATH` lookup:** Otherwise, the launcher resolves `node` on `PATH`.

To bind execution to a specific Node.js `>=22` binary:

```sh
export THEME_FORGE_NODE_BIN="/opt/node-v22/bin/node"
tfss --version
```

### Runtime Verification and Failure Codes

Before handing off execution with `os.execv`, the launcher verifies:

1. The host `os.name` is `"posix"` and the packaged JavaScript entrypoint exists on disk.
2. `<node> --version` reports a major version `>=22`.
3. A subprocess check of Node's `process.platform`, `process.arch`, and `process.report.getReport().header.glibcVersionRuntime` matches the wheel's `PLATFORM_KEY` (`darwin-arm64`, `linux-arm64-gnu`, or `linux-x64-gnu`) and, on Linux, confirms GNU `libc` meets `MIN_GLIBC` (`2.28`). Note that the macOS `11.0` deployment floor is enforced by the wheel tag (`macosx_11_0_arm64`) rather than a runtime macOS version probe.

If any check fails, the launcher exits with status `1` and writes a single line to `stderr` in the fixed format:

```text
<TOKEN>: Node.js >=22 and an intact supported POSIX installation are required.
```

| Diagnostic Token | Triggering Conditions |
| :--- | :--- |
| `TF_PYPI_NODE_REQUIRED` | Non-POSIX host, missing packaged entrypoint file, `node` not found on `PATH`, `THEME_FORGE_NODE_BIN` missing or non-executable, `--version` query failure, or detected Node.js major version older than `22`. |
| `TF_PYPI_NODE_PLATFORM` | Node's reported `process.platform`/`process.arch` does not match the wheel's `PLATFORM_KEY` (for example, running an `x64` Node.js binary under Rosetta 2 on `darwin-arm64`), Linux runtime is non-glibc (such as musl), or Linux runtime `glibc` is older than `2.28`. |

The installed Python package (`theme_forge_solar_sail`) ships an empty `__init__.py` and exposes no Python library API; installing via `pip` provides the `tfss` console script on `PATH`.

---

## Command-Line Interface (`tfss`)

The `tfss` CLI (`bin/tfss.js` -> `dist/cli.js`) provides three subcommands plus `--help` and `--version`:

```text
tfss validate <theme.json> [--fail-on-diagnostics] [--json]
tfss compile <theme.json> --out <file|dir> [--overwrite] [--fail-on-diagnostics] [--json]
tfss generate <theme.json> --package <package.json> --out <dir> [--language typescript|javascript] [--fail-on-diagnostics] [--json]
tfss --help | -h
tfss --version | -v
```

### 1. Validate a Theme Specification (`tfss validate`)

Validates theme specification schema conformance, required color roles, and color contrast diagnostics (`--out` and `--overwrite` are not supported on `validate`):

```sh
tfss validate path/to/theme.json
tfss validate path/to/theme.json --fail-on-diagnostics
tfss validate path/to/theme.json --json
```

In `--json` mode, `validate` emits `{"status": "success", "command": "validate", "valid": true, "errors": [], "diagnostics": [...]}` on `stdout`.

### 2. Compile to a Standalone Stylesheet (`tfss compile`)

Compiles a theme specification into a standalone Tailwind CSS v4 and shadcn/ui stylesheet (`--out <destination>` is required):

```sh
# Write directly to a .css file path
tfss compile path/to/theme.json --out ./dist/theme-compiled.css

# Or pass a directory path to write <dir>/theme.css
tfss compile path/to/theme.json --out ./dist/styles

# Replace an existing CSS file and return the compilation descriptor in JSON on stdout
tfss compile path/to/theme.json --out ./dist/styles --overwrite --json
```

**Output and descriptor contract:**

- **Destination path resolution:** If `--out <destination>` ends with `.css`, `tfss compile` writes the stylesheet directly to that CSS file path. Otherwise, it resolves `<destination>/theme.css` inside the target directory.
- **Descriptor output:** `tfss compile` writes only the compiled CSS file to disk; it does **not** write a separate `theme.descriptor.json` file. When invoked with `--json`, `tfss compile` returns the compilation descriptor and SHA-256 output digest in the structured `stdout` result (`{"status": "success", "command": "compile", "outputFile": "...", "outputDigest": "...", "descriptor": {...}}`).

### 3. Generate an Installable Theme Package (`tfss generate`)

Generates a self-contained npm theme package with manifest, stylesheet, types, and provenance (`--package <file>` and a directory `--out <dir>` are both required):

```sh
tfss generate path/to/theme.json \
  --package path/to/package-metadata.json \
  --out ./packages/my-app-theme \
  --language typescript \
  --json
```

Options for `generate`:

- `--package <file>`: Path to package metadata JSON (`name`, `version`, `description`, `license`).
- `--out <dir>`: Destination directory (must be absent or empty; `--overwrite` is forbidden for `generate`).
- `--language <typescript|javascript>`: Target integration language (default: `javascript`).
- `--fail-on-diagnostics`: Fail when contrast diagnostics are present.
- `--json`: Emit structured JSON status (`{"status": "success", "command": "generate", "outDir": "...", "filesWritten": [...], "descriptor": {...}, "provenance": {...}}`).

### Locating Bundled Example Files on Disk

The installed wheel unpacks upstream example files under `<site-packages>/theme_forge_solar_sail/payload/package/examples/`, including `examples/forge-console.theme.json`, `examples/forge-console.profile.json`, `examples/flexoki.profile.json`, and `examples/package-metadata.json`. Because `theme_forge_solar_sail` has no Python library API, locating `theme_forge_solar_sail.__file__` in a helper snippet only resolves the installed payload directory on disk to pass to the `tfss` CLI:

```sh
SPEC_PATH="$(python3 -c 'import pathlib, theme_forge_solar_sail as m; print(pathlib.Path(m.__file__).parent / "payload/package/examples/forge-console.theme.json")')"

tfss validate "$SPEC_PATH" --json
tfss compile "$SPEC_PATH" --json --out ./theme.css
```

Example invocation from Python using `subprocess`:

```python
import json
from pathlib import Path
import subprocess
import tempfile
import theme_forge_solar_sail

spec_path = (
    Path(theme_forge_solar_sail.__file__).parent
    / "payload/package/examples/forge-console.theme.json"
)

validate_res = subprocess.run(
    ["tfss", "validate", str(spec_path), "--json"],
    capture_output=True,
    text=True,
    check=True,
)
assert json.loads(validate_res.stdout)["status"] == "success"

with tempfile.TemporaryDirectory() as tmp:
    css_file = Path(tmp) / "theme.css"
    compile_res = subprocess.run(
        ["tfss", "compile", str(spec_path), "--json", "--out", str(css_file)],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(compile_res.stdout)
    assert payload["status"] == "success"
    assert "descriptor" in payload
    assert "--" in css_file.read_text(encoding="utf-8")
```

---

## Package Architecture, Language Modes, and Backend Boundaries

Generated theme packages are self-contained:

- **TypeScript mode (`--language typescript`):** Emits `src/index.ts`, `tsconfig.json`, and a `build` script (`tsc`) configured to compile into `dist/` when run. Generation does not run that build.
- **JavaScript mode (`--language javascript`):** Emits zero-build `index.js` and `index.d.ts` entry points.
- **Zero consumer runtime coupling:** Neither mode requires Solar Sail, Nebular Fusion, or repository-internal packages at consumer runtime.

### Boundaries and Limitations

- **Theme backend only:** Solar Sail is a deterministic theme backend and compiler. It generates CSS tokens, radius scales, and package envelopes; it does not generate arbitrary React/TSX application code or UI component implementations.
- **Tailwind v4 first:** Output stylesheets target Tailwind CSS v4 `@theme inline` and standard CSS custom properties.
- **Filesystem safety:** Package generation requires the target directory to be absent or completely empty to prevent accidental overwrites.

---

## `tfss.theme-v1` Validation and Compatibility Contract

`tfss.theme-v1` is a closed semantic schema. Unknown top-level, palette-mode, surface, typography, and color-role fields fail validation. The supported optional roles are `chart1`–`chart5` and the canonical `sidebar*` roles in `ColorTokens`; these must occur in both `light` and `dark` modes. Arbitrary custom roles, aliases such as `sidebar-background`, spacing, tracking, and shadow fields require an explicit adapter and are not silently dropped. Chart tokens map `chart1`–`chart5` to `--chart-1`–`--chart-5` and `--color-chart-1`–`--color-chart-5`.

### Color, Font, and Length Grammar

- **Supported color subset:** Hex (`3`, `4`, `6`, or `8` digits), numeric `rgb()`, `hsl()`, and `oklch()` functions, and bounded standalone CSS variable references (`var(--x)`) with supported color fallbacks. Declaration escapes, comments, invalid components, and nonfinite numbers fail. RGB channels, saturation/lightness, and alpha are range-checked; finite hue angles and nonnegative OKLCH chroma have no additional magnitude cap. Gamut conversion and hue normalization are not performed.
- **Unsupported indirection and contrast:** Nested color indirection (such as `hsl(var(--x))` or `rgb(var(--x))`) and font indirection (such as `var(--font-geist-sans), sans-serif`) are unsupported and must be resolved in an explicit adapter before validation. Alpha and non-hex colors report `UNEVALUATED_CONTRAST`, which is not an accessibility pass.
- **Fonts and lengths:** Font stacks support quoted names and ordinary multiword names. Radius and border values use the validator's nonnegative CSS length subset; executable expressions are unsupported.

### Input Parsing and Data Boundaries

- **Byte parser (`parseThemeJson(bytesOrText)`):** Rejects duplicate decoded keys, malformed UTF-8, BOM, and unsafe JSON within a `1 MiB` / depth-`20` bound. CLI input uses this boundary.
- **Object validation:** Rejects accessors without evaluating getters, hidden/symbol properties, custom prototypes, cycles, and nonfinite numbers, returning owned, deeply frozen theme data.
- **Identity-bearing spelling and control handling:** Validated token spelling, including ordinary surrounding spaces, is identity-bearing; equal visual appearance does not imply an equal digest. CSS token strings and description/author fields reject C0, DEL, and C1 control characters before trimming. Human CLI output escapes terminal controls (`\uXXXX`); `--json` mode preserves data meaning via standard JSON escaping. Generated README descriptions encode Markdown punctuation and leading whitespace as text.

---

## Upstream Node.js API, Mapping Coverage, and Source Provenance

> **Upstream Node.js / npm interface notice:** Installing `theme-forge-solar-sail` via `pip` installs the `tfss` CLI and does not expose a Python import API or globally register the npm package for Node.js imports. The programmatic interfaces below apply when importing `@knowledge-forge-ai/theme-forge-solar-sail` in a Node.js / TypeScript project.

```typescript
import {
  bindSourceProfile,
  compileTheme,
  generateThemePackage,
  validateThemeSpecification,
  type ThemeSpecification,
} from "@knowledge-forge-ai/theme-forge-solar-sail";

// Direct validation and compilation
const validation = validateThemeSpecification(themeSpec);
const compiled = compileTheme(themeSpec);

// Byte-bound paired-profile mapping and package generation
const bound = bindSourceProfile(profileBytes, { expectedSha256 });
const { specification, report } = bound.mapToSolarSail();
// Inspect and disposition report.entries before adoption (unsupported != consumed)
const generated = generateThemePackage({
  themeSpec: specification,
  metadata: { name: "@example/application-theme", version: "1.0.0" },
  language: "typescript",
});
```

### Mapping Reports and Provenance Rules

- **Report dispositions:** Reports retain source paths, target paths where mapped, values, and reasons for `consumed`, `unsupported`, `target-specific`, `overridden`, `normalized`, and `degraded` dispositions. No color conversion is claimed. Solar surface overrides win over shared values explicitly; reading width and Loom/syntax intent remain visible as unsupported or another target's intent. Unknown Solar-specific override leaves require the report API; the bare mapper rejects them.
- **Leaf counting and legacy helpers:** `summary.totalLeaves` counts report entries (including synthetic defaults) rather than unique source leaves; disposition entries individually. `mapToSyntaxPalette()` is a legacy value projection without a coverage report.
- **Exported error constructors:** `FilesystemSafetyError` is exported from the package root; `StaleProvenanceError` identifies itself by `Error.name` and carries expected/actual hashes. `writeCssFile` is CLI-internal.
- **Source profile hashing and transformations:** `bindSourceProfile` verifies SHA-256 against the exact input bytes and freezes the profile deeply. `normalizedSha256` hashes canonical paired JSON and is separate from the raw source byte digest. `transform` validates a new profile, binds its canonical serialized bytes, and retains the prior raw hash as `parentSourceSha256`. Serializing `canonicalizeJson(transformed.profile)` reproduces those transformed source bytes. Embedded `sha256` or `sourceProfileSha256` fields inside a profile are rejected as unknown authority; for Stellar Loom, pass `sourceProfileSha256` from `bound.mapToStellarLoom(baseCatalog)` explicitly to `compileThemeCatalog(catalog, { sourceProfileSha256 })`.

---

## Identity and Determinism Domains

| Identity | Exact v1 Meaning |
| :--- | :--- |
| **Profile source hash** | SHA-256 of exact verified source bytes; whitespace matters. |
| **Normalized profile hash** | SHA-256 of recursively `localeCompare("en")` key-sorted, two-space JSON with one trailing LF. Arrays retain order. |
| **Compiler input digest** | SHA-256 of that canonical JSON encoding of the validated Solar theme, including any caller-supplied source hash. |
| **Compiler output digest** | SHA-256 of exact generated CSS bytes. |
| **Descriptor inventory digest** | SHA-256 of canonical `{ inputDigest, outputDigest, name, version }`. |
| **Package inventory digest** | SHA-256 of `tfss.package-inventory-v1\n` followed by compact `JSON.stringify` of path/size/hash records sorted with `localeCompare("en")`. |
| **Provenance hash** | SHA-256 of the emitted `provenance.json` bytes (excluding `provenance.json` itself from its file inventory to avoid a cycle). |
| **Generation invocation digest** | Domain-prefixed canonical `tfss.generation-invocation-v1`: validated theme, effective metadata/defaults, language, and compiler name/version. |

`describeGenerationInvocation(options)` returns the complete direct-generator invocation plus every generated file's size and hash, including provenance, naming the descriptor and package inventory domains separately. Destination and overwrite policy are execution inputs rather than content inputs; package metadata and language are content inputs. Equal complete direct invocations under a qualified compiler and runtime produce equal emitted source-package bytes (without claiming cross-runtime locale equivalence or subsequent npm archive reproducibility).

---

## Structured CLI Failures and Filesystem Contract

### CLI Error Taxonomy

In `--json` mode, each invocation emits one JSON object on `stdout`. Failures emit `status: "error"`, `command`, `code`, `message`, and validation details where relevant, and exit with code `1`. Stable failure codes are:

- `ARGUMENT_ERROR`
- `PARSE_ERROR`
- `VALIDATION_ERROR`
- `UNSUPPORTED_INTENT`
- `DIAGNOSTIC_FAILURE`
- `FILESYSTEM_SAFETY_ERROR`
- `IO_ERROR`
- `INTERNAL_ERROR`

Warnings and info diagnostics are nonfatal by default; `--fail-on-diagnostics` fails on contrast warnings or `UNEVALUATED_CONTRAST` before writing any output.

### Filesystem Safety and Rollback Semantics

Package generation (`tfss generate`) accepts only absent or empty destination directories. It rejects path traversal, absolute or member separator ambiguity, case/Unicode collisions, file/directory prefix conflicts, symlink destinations or ancestors (including system alias symlinks; use physical paths), and nonempty destinations. Package names never determine filesystem destinations.

Cooperating writers reserve an empty directory exclusively, and every file uses exclusive creation. On I/O failure, rollback verifies identity and removes only unchanged entries created by that invocation, preserving prior empty directories and reporting any cleanup failure rather than hiding it. Package files become visible incrementally (not crash-atomic publication); if a crash leaves partial files and the reservation marker, inspect and remove only the abandoned invocation's owned state before retrying. Parent directories must remain trusted and stable during the operation. For `tfss compile`, `--overwrite` stages and checks a regular-file replacement; without `--overwrite`, existing files are preserved.

---

## Paired Profile v2 Checkpoint

Paired Profile v2 (`tf-paired-profile-v2`) defines neutral semantic groups and separately named target adapters while maintaining existing paired v1 functions and historical identities. V2 requires explicit version migration, source-byte binding, and capability reports; it is not a silent replacement for v1, and unsupported intent remains visible.

- **Cross-target mapping rules:** Loom pixel geometry does not imply `rem`/`em` conversion, and font families require explicit font-ID bindings. Code and syntax mapping is part of the report, while Solar component, sidebar, and chart vocabulary stays in target-only overrides. Complete invocations bind base inputs, final configuration, generation options, and compiler identity.
- **Additive v2 Node.js root exports:** `validatePairedProfileV2`, `bindSourceProfileV2`, `canonicalizeProfileV2`, `migrateV1ToV2`, `migrateV2ToV1`, `applyRecipe`, `classifyProfileError`, `ERROR_CODES`, and schema/adapter constants. Migrations and recipes take raw source bytes rather than parsed objects. Bound profiles expose `mapToSolarSail()` and `mapToStellarLoom(explicitInputs)` (returning catalog, syntax, and a single source-leaf capability report). V2 does not extend the `tfss` CLI or Studio file-open contract.
- **V2 provenance and validation:** Distinguishes `source-bytes`, `transformed` (canonical bytes created by a bound transformation), and `serialized-profile`. Group applicability states adapter capability independently of supplied leaves, and generated-default counts include only defaults surviving source projection and explicit overrides. Validation preserves authored color spelling and returns a detached frozen object without freezing caller data.

---

## Package Layout

When installed into a Python environment, `theme-forge-solar-sail` unpacks under `site-packages/theme_forge_solar_sail/` and `site-packages/theme_forge_solar_sail-0.2.1.post1.dist-info/`:

```text
theme_forge_solar_sail/
  __init__.py
  launcher.py
  payload/
    package/
      package.json
      LICENSE
      NOTICE
      COMMERCIAL-LICENSE.md
      bin/
        tfss.js
      dist/
        cli.js
        compiler.js
        emitter.js
        identity.js
        index.js
        input.js
        legal.js
        profile.js
        types.js
        validator.js
        writer.js
        paired-v2/
          ...
      examples/
        flexoki.profile.json
        forge-console.profile.json
        forge-console.theme.json
        package-metadata.json
theme_forge_solar_sail-0.2.1.post1.dist-info/
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
```

---

## Licensing and Legal Notices

The distribution is governed by the SPDX license expression:

```text
AGPL-3.0-or-later
```

- **Upstream payload (`@knowledge-forge-ai/theme-forge-solar-sail`):** Licensed under the GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`), with attribution in `NOTICE` and separate commercial licensing details in `COMMERCIAL-LICENSE.md`.
- **RS9 Python packaging adapter (`theme_forge_solar_sail/launcher.py` and `_rs9_build/rs9/*`):** Licensed under `AGPL-3.0-or-later` (`RS9-LICENSE` and `RS9-NOTICE`).

### Upstream Repository References

- **Source:** `https://github.com/Knowledge-Forge-AI/theme-forge-solar-sail/tree/68e3f95a27cf1681aabb1fccb55e8b78d23b5fa0`
- **Release:** `https://github.com/Knowledge-Forge-AI/theme-forge-solar-sail/releases/tag/v0.2.1`
