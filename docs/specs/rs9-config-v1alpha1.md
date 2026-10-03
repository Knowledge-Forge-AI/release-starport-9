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
| `project` | `id`, `name`, `repository` (`Owner/Repo`) | `family` |
| `license` | `expression`, `source = "tagged-repository"`, nonempty `files` | none |
| `runtime` (optional table) | `kind` (`native`, `node`, `python`) | `constraint` |
| `commands` (array of tables) | unique `name`, `interface` (`cli`, `gui`) | none |
| `checks` (array of tables) | unique `id`, `argv`, `requires-display` | `expect-exit` (default 0), `expect-stdout-contains` |

License files are relative to the declared release repository root at the tag's
resolved commit. No files are fetched by the validator. Expression grammar is
syntax-only: identifiers, `AND`, `OR`, `WITH`, parentheses. It does not validate
the SPDX license list; `Commercial` is syntactically accepted. Expression
presence is mandatory and exact text is preserved (non-NFC text fails).

Checks are nonempty argv arrays starting with a declared command. They are never
executed here. Arguments and output expectations must already be NFC so
normalization preserves their operational meaning. Output expectations can use
`{version}`; no other placeholders. `expect-exit` accepts integers without an
execution-domain range check; runner-specific exit/signal semantics are deferred.
There are no shell, hook, script, credential, digest, revision or desktop fields.

## releases.toml

`[release]`: `tag` with exactly one `{version}` and `prerelease = "reject"` or
`"allow"`. Drafts are always rejected by future ingestion. Tags may have prefixes.

`[[assets]]`: unique `id`, unique `name` template (exactly one `{version}`),
`format` (`tar.gz`, `npm-tarball`, `wheel`, `sdist`), `platforms`, and `commands`
(table of declared command names to safe archive-relative paths; may be empty).
Asset names are basenames, not URLs or paths. The only platform vocabulary is
`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`, or exactly
`["any"]`. Ambiguous overlapping assets for the same command fail.

Resolved version, tag and asset names must remain safe. Version resolution
accepts a numeric dotted version with an optional semver-style suffix; version
validation does not implement ecosystem version ordering.

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
- optional `repository` (`Owner/Repo`).

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

Authenticating checksum/signature assets; license reconciliation; desktop/icon
ownership; dependencies derived per target architecture; Nix wrappers/aliases;
complex stdin/fixture smoke checks; signing rotation; receipt schemas; npm/PyPI
OIDC claims; complete ecosystem naming/version policy; contribution source-build
rules. These are not invented fields in v1alpha1.

Changing release authority, multiple coupled version streams or license terms
per payload may require a successor schema. See the
[migration gates](../architecture/migration-map.md).
