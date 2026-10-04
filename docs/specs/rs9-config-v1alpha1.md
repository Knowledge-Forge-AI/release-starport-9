# RS9 configuration v1alpha1

Status: implemented validation/normalization subset. No publication capability.
Python 3.11+ standard library only; no install or dependency metadata required.

## Files and authority

The caller explicitly selects a project root containing `.rs9/`. Required:
`project.toml`, `releases.toml`. Optional: `npm.toml`, `pypi.toml`, `nix.toml`,
`homebrew.toml`, `pacman.toml`, `dnf.toml`, `apt.toml`. Other entries, directories
and symlinks fail. A selected root may be below a monorepo root; no implicit
recursive discovery occurs. Tenant ownership and licensing are independent of
RS9's schema ownership. See [ADR 0001](../adr/0001-tenant-contract-v1alpha1.md).

Every file requires `schema = "rs9.<file-stem>.v1alpha1"`. Unknown keys fail at
every table. Types are checked, including rejection of booleans as integers.
Identifiers use lowercase alphanumeric slugs with internal hyphens. Lists of
identities/references must be unique. Relative paths are POSIX paths without
absolute roots, empty components, `.`/`..`, backslashes or control characters.
Paths and asset/command basenames must already be NFC so normalization does not
change archive lookup identities. Raw TOML and decoded values are both screened
for credential patterns, including decoded keys. Credential-like field names
fail, except declared command identifiers in asset command maps; names such as
`gh-auth` are allowed there. Token/private-key patterns still fail in those names
and their path values.

## project.toml

| Table | Required fields | Optional fields |
|---|---|---|
| `project` | `id`, `name`, `repository` (`Owner/Repo`) | `family`, `summary` |
| `license` | `expression`, `source = "tagged-repository"`, nonempty `files` | `status = "unresolved"` |
| `desktop` (optional table) | `command`, `categories`, `icon` | none |
| `runtime` (optional table) | `kind` (`native`, `node`, `python`) | `constraint` |
| `commands` (array of tables) | unique `name`, `interface` (`cli`, `gui`) | none |
| `checks` (array of tables) | unique `id`, `argv`, `requires-display` | `expect-exit` (default 0), `expect-stdout-contains` |

`project.summary` is an optional single NFC line (1..160 characters) with no control characters or credential patterns.

`desktop` is an optional table with `command` (must name a declared GUI command), `categories` (nonempty unique list of allowlisted freedesktop categories containing at least one main category: `Development`, `Graphics`, `Utility`, `Office`, `Network`, `AudioVideo`, `Audio`, `Video`, `Game`, `Education`, `Science`, `Settings`, `System`, plus additional `IDE` allowed with `Development`; `Audio`/`Video` require `AudioVideo`), and `icon` table (`source = "tagged-repository"`, safe relative POSIX `path` ending in `.png`). There is no `icon.size` field; dimensions are derived from authenticated IHDR bytes. Normalized desktop sorts categories and emits a deep stable dictionary.

License files are relative to the declared release repository root at the tag's
resolved commit. No files are fetched by the validator. Expression grammar is
syntax-only: identifiers, `AND`, `OR`, `WITH`, parentheses. It does not validate
the SPDX license list; `Commercial` is syntactically accepted. Expression
presence is mandatory and exact text is preserved (non-NFC text fails).

For `tauri-desktop-archive.v1alpha1` and `tauri-desktop-archive.v1alpha2`,
`license.files` is the nonempty, duplicate-free list of legal copies required in
every native payload and installed by downstream renderers. Each copy must match
the corresponding tagged source bytes exactly. Nebular 0.6.1 requires `LICENSE`
and `NOTICE`, at the Linux archive root or Darwin `Contents/Resources/`.
Tagged `COMMERCIAL-LICENSE.md` is broader licensing authority evidence selected
independently by `TAURI_SOURCES`; it is not required inside the native payload.
Do not add authority-only files to this payload list. For
`npm-package-archive.v1alpha1`, `license.files` selects tagged source evidence;
the desktop payload-copy rule does not apply to that profile.

Optional `license.status = "unresolved"` preserves a known authority conflict in
normalized intent. The expression then records a provisional source declaration,
not a reconciled payload license. Nebular needs this because its tagged community
declaration conflicts with the authenticated npm artifact. Tenant intent owns
this unresolved marker; ingestion separately records observed declarations.
Only `"unresolved"` is accepted: the field cannot assert legal resolution or
grant acceptance. Omission means declaration only, not proven consistency.
Normalization preserves the marker deterministically. Render manifests expose
`license_intent_status` and retain a `tenant-license-unresolved` blocker even if
the currently inspected declarations agree. Recipe license strings remain
provisional shadow metadata until tenant authority resolves the conflict.

Checks are nonempty argv arrays starting with a declared command. They are never
executed here. Arguments and output expectations must already be NFC so
normalization preserves their operational meaning. Output expectations can use
`{version}`; no other placeholders. `expect-exit` accepts integers without an
execution-domain range check; runner-specific exit/signal semantics are deferred.
There are no shell, hook, script, credential, digest or revision fields.

## releases.toml

`[release]`: `tag` with exactly one `{version}` and `prerelease = "reject"` or
`"allow"`. Drafts are always rejected by ingestion. Tags may have prefixes.

`[[assets]]`: unique `id`, unique `name` template (exactly one `{version}`),
`format` (`tar.gz`, `npm-tarball`, `wheel`, `sdist`), `platforms`, and `commands`
(table of declared command names to safe archive-relative paths; may be empty).
Asset names are basenames, not URLs or paths. The only platform vocabulary is
`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`, or exactly
`["any"]`. Ambiguous overlapping assets for the same command fail.

Optional `launchers` maps an asset command to an upstream archive-owned shim.
It must be nonempty when present, name only this asset's mapped commands and use
the same safe relative-path rules. It is a selection of authenticated payload
bytes, not an executable hook. Normalization preserves the map deterministically.
Ingestion requires executable regular nonlink files for both native command and
selected launcher. Nebular's released `tfnf` shim supplies headless version/path
behavior while `commands.tfnf` continues to identify the native GUI bytes.

Resolved version, tag and asset names must remain safe. Version resolution
accepts a numeric dotted version with an optional semver-style suffix; version
validation does not implement ecosystem version ordering.

### Evidence table amendment `[evidence]`

Foundation 3 introduces an optional schema amendment table `[evidence]` to `releases.toml`:
- `checksums`: Safe basename template containing `{version}` or an exact basename identifying the authoritative SHA256SUMS file (e.g. `"SHA256SUMS-{version}.txt"`).
- `profile`: Closed profile identifier, restricted to `"tauri-desktop-archive.v1alpha1"`, `"tauri-desktop-archive.v1alpha2"` or `"npm-package-archive.v1alpha1"`. No filename guessing or arbitrary tenant code is supported. No Stellar renderers exist or are supported.
- `assets`: Nonempty list of tables specifying exact `{role, name}` bindings where `role` is a sanitized slug (e.g. `"checksums"`, `"wrapper"`) and `name` is a safe basename template with `{version}`.

**Explicit behavioral rule**:
The `[evidence]` table is **optional** in the configuration schema for `rs9.contract validate` and `normalize`, allowing pure planning manifests to be generated without evidence declarations. However, it is **required** for release authentication (`rs9.release_core.authenticate_release`). Attempting to authenticate a release whose configuration omits `[evidence]` fails closed.

## Adapter intent files

All seven adapters use the same deliberately limited shape:

```toml
schema = "rs9.pacman.v1alpha1"

[[packages]]
id = "main"
name = "example-tool"
assets = ["linux-x64"]
# optional platforms = ["x86_64-linux"]

[[publish]]
package = "main"
destination = "example-pacman"
```

Every package names nonempty known assets. Optional platform restrictions must
fit source coverage. Names receive a bounded ecosystem syntax check, not a
reservation or availability check. npm supports scoped names and requires
`npm-tarball` assets. PyPI requires wheels/sdists. AUR naming is expressed by a
separate pacman package intent referencing an AUR destination. Duplicate
package/destination pairs fail. Unsupported dependency/build/signing fields fail.
Multiple intents with different IDs naming the same package in one destination
also fail as ambiguous during tenant-only validation. Resolved release tags are checked again after version
substitution.

## Destination subset

An operator-supplied file outside `.rs9/` has
`schema = "rs9.destinations.v1alpha1"` and `[[destinations]]`:

- unique `id`, matching `adapter`, `mode` (`direct`, `projection`, `contribution`);
- nonempty concrete canonical `platforms` (never `any`);
- `status` (`illustrative`, `candidate`, `live`), descriptive only;
- optional HTTPS `base-url` without credentials, query or fragment;
- optional `repository` (`Owner/Repo`);
- optional `profile = "aur"` only for pacman projection destinations (propagated to normalized targets).

This is routing validation, not a production destination registry. No trust,
secrets, credential references, suites or authentication are interpreted yet.
With destinations supplied, unknown references, mismatched adapters and empty
platform intersections fail. pacman/DNF/APT require Linux. Without destinations,
`validate` checks tenant-local relationships only.

`any` denotes one architecture-independent payload, eligible for each selected
destination platform. pacman maps it to `any`, RPM to `noarch`, APT to `all`.
Those labels remain singletons; concrete eligibility remains explicit in
`effective-platforms`. Concrete Linux maps x86_64/aarch64 to pacman/RPM
x86_64/aarch64 and APT amd64/arm64. Nix uses canonical platform names. Other
architecture-independent targets retain canonical eligibility. Concrete npm CPU
labels map to x64/arm64; Homebrew maps aarch64 to arm64. PyPI retains canonical
platforms because full wheel-tag interpretation is deferred.

## Normalized output and rejection

`python3 -m rs9.contract normalize PROJECT --destinations FILE --version V`
emits `rs9.normalized-tenant.v1alpha1` JSON: tenant semantics, resolved release
tag/assets, contributing asset references, target names/modes/platforms, destination
status/routing and ecosystem architecture labels.
Each target's `assets` includes only package-selected assets covering at least
one effective platform (or an `any` asset). The top-level asset inventory retains
all declared release assets. An asset spanning several platforms remains one
reference; this subset does not select files within an archive.
Raw input SHA256 records form a separate evidence section. Keys and entity lists
are deterministically ordered; argv order is preserved. UTF-8, NFC strings,
two-space indentation, LF and final newline are canonical.

Identical bytes and arguments produce identical complete output. Formatting or
table-order changes preserve semantic output while necessarily changing raw
input hashes. The result is a planning manifest, not an authenticated release
lock, publication receipt or successful qualification claim.

Errors expose stable codes without echoing untrusted values. Missing/unknown
files or keys, schema/type errors, malformed templates, unsafe paths,
ambiguity, unknown references, inappropriate asset formats and credential
patterns fail. Secret-pattern screening is defense in depth, not proof that an
arbitrary string cannot conceal a secret; strict field allowlists remain primary.
Missing required fields/tables use `MISSING_REQUIRED_KEY`; present fields of the
wrong type use `INVALID_TYPE`. A present unsupported schema uses
`SCHEMA_MISMATCH`. Invalid check text normalization uses `NON_NFC_STRING`.

## Deferred contract questions

Authenticating checksum/signature assets; license reconciliation;
dependencies derived per target architecture; Nix wrappers/aliases;
complex stdin/fixture smoke checks; signing rotation; receipt schemas; npm/PyPI
OIDC claims; complete ecosystem naming/version policy; contribution source-build
rules. These are not invented fields in v1alpha1.

Changing release authority, multiple coupled version streams or license terms
per payload may require a successor schema. See the
[migration gates](../architecture/migration-map.md).

## What would make this wrong

1. **Trust boundary**: Trusting tenant configuration declarations or planning manifests as authorization to publish without independent byte authentication via `ReleaseCapture`.
2. **Timestamps limitation**: Relying on configuration or file modification timestamps to infer release sequence or freshness; timestamps cannot secure untrusted transport.
3. **Persisted audit limit**: Treating persisted normalized configuration JSON as an active capability rather than a static planning intent record.
4. **Guessing filenames or interpreting arbitrary tenant scripts**: Attempting to dynamically infer release assets or executing arbitrary tenant code instead of enforcing declarative `[evidence]` bindings.
5. **Inventing unsupported profiles or renderers**: Adding unverified profiles or Stellar renderers without specification and qualification.
6. **Ignoring credential patterns in field values or keys**: Permitting API keys, private keys, or credentials to be committed to tenant configuration.
7. **Silently ignoring non-NFC Unicode strings**: Allowing non-NFC strings to alter archive lookup semantics or bypass path safety checks.

## Local Links

- [ADR 0001: Tenant contract v1alpha1](../adr/0001-tenant-contract-v1alpha1.md)
- [ADR 0002: GitHub Release as sole ingestion authority](../adr/0002-github-release-sole-ingestion-authority.md)
- [ADR 0003: Authenticated ingestion and shadow adapters](../adr/0003-authenticated-ingestion-and-shadow-adapters.md)
- [ADR 0004: Ingestion core and evidence profiles](../adr/0004-ingestion-core-and-evidence-profiles.md)
- [Specification: Release record v1alpha1](rs9-release-record-v1alpha1.md)
- [Specification: Ingestion record v1alpha1](rs9-ingestion-record-v1alpha1.md)
- [Project contract](../project-contract.md)
- [Architecture overview](../architecture.md)
