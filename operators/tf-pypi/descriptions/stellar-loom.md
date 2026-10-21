# Theme Forge: Stellar Loom (`theme-forge-stellar-loom`)

- **PyPI distribution version:** `0.4.0.post1`
- **Upstream release version:** `0.4.0`
- **Upstream npm package:** `@knowledge-forge-ai/theme-forge-stellar-loom`
- **Upstream source commit:** `d6f3cc457ee68224cef06e9599c9d2401057c618`
- **Upstream release tag:** [v0.4.0](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom/releases/tag/v0.4.0)
- **Console script entrypoints:** `tfsl`, `tfsl-batch`
- **SPDX license expression:** `AGPL-3.0-or-later`
- **Python requirement:** `>=3.9`
- **External runtime requirement:** `Node.js >=22` (`Requires-External: nodejs (>=22)`)

---

## Overview

Theme Forge Stellar Loom (TFSL) is a Starlight theme-builder backend, library, and CLI (`tfsl`, `tfsl-batch`), packaged as the `theme-forge-stellar-loom` Python distribution (`0.4.0.post1`). It compiles typed, versioned theme specifications into canonical, deterministic CSS custom properties, theme descriptors, and standalone Starlight plugin packages for documentation sites (`starlight-v0.42`, demonstrated with Astro `7.3.1` and `@astrojs/starlight@0.42.0`).

The `.post1` PEP 440 post-release suffix identifies the first Python packaging revision of the immutable upstream `0.4.0` release. Version `0.4.0` includes reading layout presets (`--reading-layout`), distribution-safe TypeScript emission (`--language typescript`), Expressive Code syntax styling derivation, and book-chrome navigation.

Key properties:

- **Versioned theme schemas:** Supports both `tfsl.theme-v1` and the closed `tfsl.theme-v2` / catalog domain.
- **Zero-dependency core:** Compiles using Node.js built-in modules (`node:crypto`, `node:fs/promises`, `node:path`) with zero third-party npm dependencies and zero native binary addons.
- **Deterministic compilation:** Produces byte-identical CSS and SHA-256 digests across environments.
- **Deterministic contrast diagnostics:** Computes WCAG 2.2 AA relative luminance and contrast ratios for body text, links, and inline code across light and dark modes.
- **Filesystem safety:** Prevents CSS injection, refuses symlink destination roots and dangling intermediate symlinks, requires empty or absent destination directories for package generation, requires `--overwrite` for existing v1 compilation outputs, protects manually edited CSS by verifying existing descriptor output digests, and detects input/output collisions.

---

## Wheel Targets and Requirements

Platform wheels and host-targeted source-distribution (`sdist`) builds support three POSIX environments:

| Target Key | Operating System & Architecture | PEP 425 Wheel Tag | Minimum C Library / OS Floor |
| :--- | :--- | :--- | :--- |
| `darwin-arm64` | macOS Apple Silicon (`arm64`) | `py3-none-macosx_11_0_arm64` | macOS 11.0+ |
| `linux-arm64-gnu` | Linux ARM64 (`aarch64`, GNU libc) | `py3-none-manylinux_2_28_aarch64` | `glibc >= 2.28` |
| `linux-x64-gnu` | Linux AMD64 (`x86_64`, GNU libc) | `py3-none-manylinux_2_28_x86_64` | `glibc >= 2.28` |

### Distribution Filenames

- `theme_forge_stellar_loom-0.4.0.post1-py3-none-macosx_11_0_arm64.whl`
- `theme_forge_stellar_loom-0.4.0.post1-py3-none-manylinux_2_28_aarch64.whl`
- `theme_forge_stellar_loom-0.4.0.post1-py3-none-manylinux_2_28_x86_64.whl`
- `theme_forge_stellar_loom-0.4.0.post1.tar.gz`

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
python3 -m pip install "theme-forge-stellar-loom==0.4.0.post1"
```

Upgrade an existing installation to `0.4.0.post1`:

```sh
python3 -m pip install --upgrade "theme-forge-stellar-loom==0.4.0.post1"
```

### Offline Installation from Local Artifacts

The entire upstream release payload is bundled inside the wheel and sdist. The Python packaging adapter and launcher never invoke `npm`, `npx`, or `corepack`.

To install offline from a local directory (`./dist`) containing the prebuilt wheel or `.tar.gz` sdist without network access:

```sh
python3 -m pip install --no-index --no-deps --find-links ./dist "theme-forge-stellar-loom==0.4.0.post1"
```

`--no-deps` is safe because `theme-forge-stellar-loom` declares zero Python package dependencies and `build-system.requires = []`. When building a wheel from `theme_forge_stellar_loom-0.4.0.post1.tar.gz`, the bundled offline PEP 517 backend (`rs9.tf_pypi_backend` under `_rs9_build/`) selects the current host target (`darwin-arm64`, `linux-arm64-gnu`, or `linux-x64-gnu`) via `host_key()`, refuses unsupported build hosts (such as `darwin-x64` or non-glibc Linux), and rejects any PEP 517 `config_settings`.

---

## Node.js Resolution and Launcher Diagnostics

At runtime, the console-script wrapper (`theme_forge_stellar_loom.launcher`) locates the Node.js executable in the following order:

1. **`THEME_FORGE_NODE_BIN` environment variable:** If set and non-empty, the launcher uses that path directly without falling back to `PATH`.
2. **`PATH` lookup:** Otherwise, the launcher resolves `node` on `PATH`.

To bind execution to a specific Node.js `>=22` binary:

```sh
export THEME_FORGE_NODE_BIN="/opt/node-v22/bin/node"
tfsl --version
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

The installed Python package (`theme_forge_stellar_loom`) ships an empty `__init__.py` and exposes no Python library API; installing via `pip` provides the `tfsl` and `tfsl-batch` console scripts on `PATH`.

---

## Theme v2 and Catalog

`tfsl.theme-v2` is a separate closed domain alongside supported `tfsl.theme-v1` validation, canonical bytes, generated packages, and strict exchange compatibility. First-party capability fixtures in `examples/` include `loom-black-core.theme.json`, `loom-flexoki-core.theme.json`, and `loom-celestia-core.theme.json` (plus v1 examples such as `stellar-cyan.theme.json` and `amber-forge.theme.json`).

The library `compileTheme`, CLI `validate`/`compile`/`generate`, and batch `compile`/`validate` discriminate automatically by `schemaVersion`. V2 compilation returns an ordered `styles` map and a v2 descriptor; `css` (batch `compiledCss`) is its ordered concatenation for display rather than a structural browser preview. V2 CLI `compile` writes the fixed five stylesheet files and descriptor to an absent or empty directory and does not support `--overwrite`:

```sh
tfsl validate examples/loom-black-core.theme.json
tfsl compile examples/loom-black-core.theme.json --out compiled
tfsl generate examples/loom-black-core.theme.json --package metadata.json --out theme-package
```

Use `--accent <declared-id>` to select another complete light/dark variant. The emitted v2 stylesheet order is:

1. `styles/layers.css`
2. `styles/tokens.css`
3. `styles/base.css`
4. `styles/accent.css`
5. `styles/overrides.css`

The layer declaration places `starlight` before `tfsl`, then orders Loom's `tokens`, `base`, `accent`, and `overrides` sublayers. Unlayered consumer custom CSS follows defaults and wins under ordinary CSS cascade rules. Documented override selectors include `:root`, `.sl-markdown-content a:focus-visible`, and `::selection`.

### Catalog Capabilities and Boundaries

The catalog supports finite `Hero`, `PageTitle`, `Pagination`, and `Sidebar` choices, responsive navigation, and bounded syntax/frame/diff presentation. Consumer components and supported Expressive Code values retain precedence. Catalog specifications include a closed `catalog` object; core specifications without that object retain their separate, smaller contract. Unknown structures fail closed.

Header and PageFrame replacements, generated code tabs, virtual data modules, and font-provider conversion remain deferred. Public Starlight search, theme, language, and supporting controls retain their normal behavior.

### Font Records and Materialization

Font records use logical IDs, face metadata, a SHA-256 digest, and license/notice identities; the theme specification contains no file paths or URLs. In the CLI, pass `--font-root <selected-directory> --font-ids <comma-separated-ids>` (or in the upstream Node.js API, call `materializeFontResources(root, declarations, selectedIds)` and pass the returned map as `fontResources` to `generateThemePackageV2`).

Only fixed `<id>.woff` or `<id>.woff2` leaf files are read: at most 8 resources, 4 MiB each, and 16 MiB total, rejecting symlinks, path traversal, and digest mismatches. Generated font filenames are fixed ordinals. Core byte-pipeline fixtures use non-rendering test bytes; actual font rendering and third-party font licensing require catalog qualification, and system fonts make no promise of pixel-identical cross-OS rendering.

### Exchange Compatibility

The legacy v1 exchange verifier requires the exact producer version (`compilerVersion`). V2 semantic compatibility is independent of package SemVer: producer package version is recorded as provenance rather than a compatibility gate, and exchange v2 recompiles locally and requires exact bound output and inventory equality. Explicit v1 import creates a fresh unadopted v2 candidate linked to the historical packet without mutating historical bytes. V2 CLI output is structured JSON even when `--json` is omitted.

---

## Command-Line Interface (`tfsl` and `tfsl-batch`)

### `tfsl` Usage

```sh
# Validate a theme specification and inspect contrast diagnostics
tfsl validate ./examples/stellar-cyan.theme.json

# Fail validation if contrast warnings exist
tfsl validate ./examples/stellar-cyan.theme.json --strict-contrast

# Compile to custom CSS and descriptor in an output directory
tfsl compile ./examples/stellar-cyan.theme.json --out ./dist/theme

# Re-compile a v1 theme into an existing directory (verifies existing descriptor and unedited theme.css)
tfsl compile ./examples/stellar-cyan.theme.json --out ./dist/theme --overwrite

# Output parseable JSON diagnostics without progress prose
tfsl compile ./examples/stellar-cyan.theme.json --out ./dist/theme --json

# Generate an installable Starlight theme package
tfsl generate ./examples/stellar-cyan.theme.json --package ./pkg-meta.json --out ./dist/cyan-package

# Generate an installable package with the approved page-title-frame template
tfsl generate ./examples/amber-forge.theme.json --package ./pkg-meta.json --out ./dist/amber-package --template page-title-frame

# Emit a TypeScript Starlight theme package
tfsl generate ./examples/amber-forge.theme.json --package ./pkg-meta.json --out ./dist/amber-ts-package --language typescript

# Show help or version
tfsl --help
tfsl --version
```

> **Note on `--out`:** For `tfsl compile`, `--out <output-dir>` always specifies an **output directory** (writing `<output-dir>/theme.css` and `theme.descriptor.json` for `tfsl.theme-v1`, or the five `styles/*.css` files and descriptor for `tfsl.theme-v2`).

### Locating Bundled Example Files on Disk

The installed wheel unpacks upstream example specifications under `<site-packages>/theme_forge_stellar_loom/payload/package/examples/`, including `examples/amber-forge.theme.json`. Because `theme_forge_stellar_loom` has no Python library API, locating `theme_forge_stellar_loom.__file__` in a one-liner only resolves the installed payload directory on disk for CLI invocation:

```sh
SPEC_PATH="$(python3 -c 'import pathlib, theme_forge_stellar_loom as m; print(pathlib.Path(m.__file__).parent / "payload/package/examples/amber-forge.theme.json")')"

tfsl validate "$SPEC_PATH" --json
tfsl compile "$SPEC_PATH" --json --out ./out-dir
```

### Batch IPC Runner (`tfsl-batch`)

The `tfsl-batch` console script (`bin/tfsl-batch.js`) runs the batch IPC processor over `stdin` and `stdout`. It reads a JSON request payload from `stdin` and writes a JSON response payload to `stdout`. If `stdin` is empty, `tfsl-batch` exits with status `1` and emits a JSON error response with code `EMPTY_INPUT`.

Request payload (`stdin`):

```json
{
  "action": "compile",
  "specification": {
    "...": "contents of a *.theme.json specification object"
  }
}
```

Response payload (`stdout` on success, exit code `0`):

```json
{
  "status": "success",
  "compiledCss": ":root {\n  --...\n}\n"
}
```

Example `tfsl-batch` invocation from Python using `subprocess`:

```python
import json
from pathlib import Path
import subprocess
import theme_forge_stellar_loom

spec_path = (
    Path(theme_forge_stellar_loom.__file__).parent
    / "payload/package/examples/amber-forge.theme.json"
)
specification = json.loads(spec_path.read_text(encoding="utf-8"))

request = json.dumps({
    "action": "compile",
    "specification": specification,
}).encode("utf-8")

result = subprocess.run(
    ["tfsl-batch"],
    input=request,
    capture_output=True,
    check=True,
)
response = json.loads(result.stdout)
assert response["status"] == "success"
assert "--" in response["compiledCss"]
```

---

## Theme Data Contract (`tfsl.theme-v1`), Dimensions, and Exit Codes

Stellar Loom validates untrusted JSON data strictly. Top-level plain objects must inherit from `Object.prototype` or `null` to defend against prototype pollution (`INVALID_PROTOTYPE`).

### `tfsl.theme-v1` Fields and Version Grammar

- **`schemaVersion`**: `"tfsl.theme-v1"`.
- **`adapter`**: `"starlight-v0.42"`.
- **`name`**: Alphanumeric identifier (`^[a-zA-Z0-9_-]{1,64}$`).
- **`version`**: Strict SemVer 2.0.0 without leading zeroes in major/minor/patch segments (`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-...)?$`).
- **`$schema`** (optional): Non-executing editor metadata string; excluded from canonical semantic hashing and never dereferenced.
- **`colors`**: Object containing `dark` and `light` palettes. Each palette must specify 7-character `#rrggbb` hex colors for:
  - `accent`: `base`, `low`, `high`.
  - `neutrals`: `bg`, `bgNav`, `bgSidebar`, `bgInlineCode`, `bgAccent`, `text`, `textAccent`, `textInvert`, `hairline`, `hairlineLight`, `hairlineShade`.
  - `grays`: `gray1` through `gray7`.
- **`typography`**:
  - `bodyFont`: `"system-sans"` | `"system-serif"` | `"system-mono"`.
  - `codeFont`: `"system-mono"` | `"system-code"`.
  - `baseFontSize` (optional): Bounded dimension string.
  - `lineHeight` (optional): Unitless number in `[1.0, 3.0]`.
- **`layout`**:
  - `contentWidth`: Bounded dimension string.
  - `sidebarWidth`: Bounded dimension string.

### Per-Unit Dimension Bounds

| Role | `px` | `rem` | `em` | `ch` |
| :--- | :---: | :---: | :---: | :---: |
| **`layout.contentWidth`** | `[320, 3840]` | `[20, 240]` | `[20, 240]` | `[30, 200]` |
| **`layout.sidebarWidth`** | `[160, 600]` | `[10, 40]` | `[10, 40]` | `[15, 60]` |
| **`typography.baseFontSize`** | `[10, 36]` | `[0.625, 2.25]` | `[0.625, 2.25]` | `[1, 4]` |

Spelling is canonically normalized within each unit (for example, `048.00rem` -> `48rem`, `019.0px` -> `19px`). Units are not conflated across unit types.

### Exit Codes and CLI Behavior

| Code | Category | Meaning & Triggers |
| :---: | :--- | :--- |
| `0` | Success | Command completed successfully (`validate`, `compile`, `generate`, `--help`, `--version`). |
| `1` | Theme Specification Error | Schema validation failure, missing or unreadable input file, or contrast threshold failure under `--strict-contrast`. |
| `2` | Syntax / Invocation Error | Unknown options, missing option arguments, duplicate options, surplus operands, specifying `--overwrite` on `generate` (or v2 `compile`), or `--out` with a leading hyphen. |
| `3` | Filesystem Safety or I/O Failure | Non-empty target directory without `--overwrite` (for v1 `compile`), non-empty target directory (for `generate` or v2 `compile`), symlink target or traversal refusal, non-regular target (FIFO/socket), unmanaged manual edits to `theme.css` without matching descriptor, input/output collision, or staging/publication write failure. |

---

## Upstream Node.js Library API, Exports, and Protocol Schemas

> **Upstream Node.js / npm interface notice:** Installing `theme-forge-stellar-loom` via `pip` provides the `tfsl` and `tfsl-batch` CLI commands and does not expose a Python module API or globally register the npm package for Node.js imports. The programmatic exports below apply when importing `@knowledge-forge-ai/theme-forge-stellar-loom` in a Node.js / TypeScript project.

```typescript
import {
  validateTheme,              // Alias to validateThemeSpecification
  validateThemeSpecification,
  ValidationError,
  compileTheme,
  canonicalizeTheme,          // Alias to canonicalizeSpecification
  canonicalizeSpecification,
  generateThemeDescriptor,
  computeSha256,
  analyzeThemeContrast,
  calculateContrastRatio,
  calculateRelativeLuminance,
  ContrastError,
  generateThemePackage,
  writeThemePackage,
} from "@knowledge-forge-ai/theme-forge-stellar-loom";

const spec = validateTheme(inputJson);
const { canonicalObject, canonicalJson, inputDigest } = canonicalizeTheme(spec);
const diagnostics = analyzeThemeContrast(canonicalObject);

const { css, descriptor, outputDigest, diagnostics: compDiagnostics } = compileTheme(spec, {
  strictContrast: false,
});

const packageResult = generateThemePackage({
  themeSpec: spec,
  metadata: {
    name: "starlight-theme-stellar-cyan",
    version: "0.1.0",
    description: "Stellar Cyan Starlight theme plugin",
    template: "page-title-frame",
  },
  strictContrast: false,
});

const writeResult = await writeThemePackage(packageResult, "./dist/my-theme-package");
```

### Upstream Package Subpath Exports

- `.` (`@knowledge-forge-ai/theme-forge-stellar-loom`): Core compiler, validator, generator (`generateThemePackage`, `generateThemePackageCatalog`, `generateThemePackageV2`, `materializeFontResources`), design exchange, and contrast diagnostics.
- `./batch` (`@knowledge-forge-ai/theme-forge-stellar-loom/batch`): Batch IPC runner (`runBatch`, `processBatchRequest`).
- `./cli` (`@knowledge-forge-ai/theme-forge-stellar-loom/cli`): Programmatic CLI invocation (`runCli`, `CLI_HELP`).
- `./protocol/*`: JSON schemas, inventory, and canonical protocol example packets.

### Portable Theme Evidence Protocol v1

Shipped under `protocol/tfsl-theme-evidence-v1/`:

- `brief.schema.json`: Schema for `tfsl.theme-brief` (version 1)
- `candidate.schema.json`: Schema for `tfsl.theme-candidate` (version 1)
- `review.schema.json`: Schema for `tfsl.theme-review` (version 1)
- `visual-evidence.schema.json`: Schema for `tfsl.theme-visual-evidence` (version 1)
- `inventory.json`: Protocol inventory manifest
- `negative-corpus.json`: Closed negative test corpus
- `examples/`: Integrity-bound canonical packet examples (`brief`, `candidate-a`, `candidate-b`, `review`)

---

## Generated Starlight Integration, Code Presentation, and Paired Profiles

### Starlight Plugin Integration

Each emitted theme package is a standalone Starlight plugin conforming to `@astrojs/starlight@0.42.0`:

```javascript
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import themePlugin from "starlight-theme-stellar-cyan";

export default defineConfig({
  integrations: [
    starlight({
      title: "Docs",
      plugins: [themePlugin()],
      // Consumer customCss automatically takes precedence over theme defaults:
      customCss: ["./src/styles/custom.css"],
    }),
  ],
});
```

- **CSS cascade:** Injects `${packageName}/styles/theme.css` before existing entries in `config.customCss`, ensuring consumer CSS rules take precedence.
- **Idempotence:** Repeated hook invocations do not duplicate stylesheet registrations.
- **Component overrides:** When generated with `--template page-title-frame`, registers `components.PageTitle` only if the consumer has not configured a custom `PageTitle` component.

### Code Presentation and Syntax Palette Integration

The `syntaxPalette` specification pairs syntax highlighting tokens with Expressive Code frame chrome:

- **`syntax`**: Light and dark hex color mappings for 11 syntax roles (`keyword`, `string`, `number`, `constant`, `function`, `type`, `variable`, `comment`, `punctuation`, `tag`, `attribute`).
- **`chrome`**: Light and dark role mappings for 8 frame surfaces (`background`, `foreground`, `border`, `focus`, `tabBarBackground`, `activeTabBackground`, `activeTabIndicator`, `copyButtonForeground`). Every chrome role must be defined symmetrically in both dark and light modes; asymmetric definitions fail closed with `[SYNTAX_PALETTE_VALIDATION_ERROR]`.
- **`tabs`**: Tabbed presentation settings (such as `activeIndicator: "bottom"`). When `syntaxPalette` is supplied to `generateThemePackageCatalog`, `styles/tabs.css` is emitted and wired so `--sl-tab-color-border` maps to `chrome[mode].activeTabIndicator` with a 2px tablist bottom border.
- **`frame`**: Frame style (`"editor"`, `"terminal"`, or `"plain"`).
- **Expressive Code contrast normalization:** Expressive Code enforces a minimum syntax contrast ratio of `5.5:1` (`minSyntaxHighlightingColorContrast: 5.5`), preserving exact hex colors at `>= 5.5:1` and adjusting luminance when raw contrast is lower.

### TypeScript Authoring and Book Chrome Layouts

- **TypeScript mode (`--language typescript`):** Emits typed sources (`src/index.ts`, `src/navigation.ts`, `src/middleware.ts`) and `tsconfig.json` with `build: "tsc"` and `prepare: "tsc"` scripts mapping package exports to `./dist/` artifacts (`./dist/index.js`, `./dist/index.d.ts`, `./dist/navigation.js`, `./dist/navigation.d.ts`), matching JavaScript package CSS and browser rendering byte-for-byte.
- **Book Chrome reading layouts (`bookChrome`):** Supports `bookChrome: true`, `bookChrome: false`, or a granular `BookChromeConfig` (`chapterNavigation`, `chapterProgress`, `keyboardShortcuts`). Arrow-key listeners bail out when `e.defaultPrevented` is set, when focus is in an editable input (`<input>`, `<select>`, `<textarea>`, `isContentEditable`), or when focus is inside `[role="tab"]`, `[role="tablist"]`, `.expressive-code`, `<pre>`, `<code>`, open `<dialog>`, or horizontally scrollable containers. All rules reside under `@layer tfsl.overrides` and `.tfsl-book-chrome` with zero `!important` declarations, and normalize into `provenance.bookChrome`.

### Consumer Override Precedence and Digest Boundaries

1. **Leaf options:** Consumer Expressive Code options (such as `styleOverrides.frames.editorBackground`) deep-merge over theme defaults.
2. **Array replacement:** Consumer array properties (such as `themes: ["github-light"]`) replace theme defaults rather than concatenating.
3. **Unlayered custom CSS:** Consumer `customCss` loads after theme stylesheets in unlayered space, overriding `@layer tfsl` rules.
4. **`PageTitle` precedence:** Consumer `components.PageTitle` bypasses theme frame wrappers.
5. **Expressive Code disablement:** Setting `expressiveCode: false` disables Expressive Code rendering and falls back to standard Markdown `<pre><code>`.

**Output digest boundaries:** `cssOutputDigest` covers purely CSS-derived output (`styles/tokens.css`, `styles/base.css`, `styles/layers.css`, `styles/accent.css`, `styles/overrides.css`, `styles/tabs.css`), whereas `provenance.inventoryDigest` covers the full generated package file tree including runtime JS/TS `ecDefaults.styleOverrides`.

### Paired Profiles (`tf-paired-profile-v1` and `v2`) and Compatibility Limits

- **Paired Profile v1 (`tf-paired-profile-v1`):** Stellar Loom and Solar Sail compile shared design profiles (such as `flexoki.profile.json`) with identical canonical SHA-256 profile digests and independent `targetOverrides.loom` vs `targetOverrides.solarSail` sections.
- **Paired Profile v2 checkpoint:** Defines neutral semantic groups and separately named target adapters while preserving v1 functions. V2 requires explicit version migration, source-byte binding, capability reports, and explicit `baseCatalog`, `token-set`, primary/secondary family, default accent, and family-to-font-ID bindings. Loom pixel geometry does not imply `rem`/`em` conversion, and relative lengths and alpha colors remain visible unsupported effects.
- **Core adapter qualification limits:** Core browser qualification covers screen media on sidebar-bearing documentation pages; Starlight `0.42.0` has unlayered sidebar-less content-width and print rules that can take precedence over Loom layers. Installed packages validate catalog/template data and recompile bound exchange output; they do not read TypeScript source or provide tamper detection.

---

## Package Layout

When installed into a Python environment, `theme-forge-stellar-loom` unpacks under `site-packages/theme_forge_stellar_loom/` and `site-packages/theme_forge_stellar_loom-0.4.0.post1.dist-info/`:

```text
theme_forge_stellar_loom/
  __init__.py
  launcher.py
  payload/
    package/
      package.json
      LICENSE
      NOTICE
      COMMERCIAL-LICENSE.md
      bin/
        tfsl.js
        tfsl-batch.js
      examples/
        amber-forge.theme.json
        loom-black-core.theme.json
        loom-flexoki-core.theme.json
        loom-celestia-core.theme.json
        stellar-cyan.theme.json
      protocol/
        tfsl-theme-evidence-v1/
          ...
theme_forge_stellar_loom-0.4.0.post1.dist-info/
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

- **Upstream payload (`@knowledge-forge-ai/theme-forge-stellar-loom`):** Licensed under the GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`), with attribution in `NOTICE` and separate commercial licensing details in `COMMERCIAL-LICENSE.md`.
- **RS9 Python packaging adapter (`theme_forge_stellar_loom/launcher.py` and `_rs9_build/rs9/*`):** Licensed under `AGPL-3.0-or-later` (`RS9-LICENSE` and `RS9-NOTICE`).

### Upstream Repository References

- **Source:** `https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom/tree/d6f3cc457ee68224cef06e9599c9d2401057c618`
- **Release:** `https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom/releases/tag/v0.4.0`
