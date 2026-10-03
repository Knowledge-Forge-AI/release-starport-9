# Nebular 0.6.1 shadow projection

Status: Foundation 2 terminal source candidate. Shadow acceptance is deferred. This
document describes RS9 source and small test goldens; no destination is updated.

## Input and license authority

The freshly captured GitHub release is `Knowledge-Forge-AI/theme-forge-nebular-fusion`
`v0.6.1`, release id 400494635. Its lightweight tag resolves to commit
`49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e`, tree
`203a80b33fc94c776c9c184f8cac4f1609cb0f2b`; draft/prerelease are false. All three
raw archives reproduce the API and SHA256SUMS digests. The integrated inspection
recomputed native executable hashes:

| Platform | Executable SHA256 |
|---|---|
| aarch64-darwin | `663c60a675165287e3157a279988bcd4bce556cf3c2a69d4bfd5ab937f60d867` |
| aarch64-linux | `5c182d28c02f2d6ea09ed130625ef899a8d0fe4ca080df775d72cdd6cd43b743` |
| x86_64-linux | `6efc9c12ff9148f9e20763c620b7abb1712c614fc796b1577e01913488c658e0` |

Tagged root LICENSE contains AGPL v3 text. NOTICE declares AGPL-3.0-or-later and
COMMERCIAL-LICENSE describes a separate commercial offer. Tagged package.json and
Cargo.toml declare AGPL-3.0-or-later. Project LICENSE/NOTICE copies in all three
archives are byte-equal to tagged authority. The published npm wrapper's actual
package.json and registry metadata both declare
`AGPL-3.0-or-later OR Commercial`. Its tarball is byte-equal to the GitHub wrapper
asset and agrees with registry integrity. This is an artifact conflict, not only
a registry label discrepancy. The example and normalized output explicitly carry
`license.status = "unresolved"`; their expression remains a provisional tagged
community declaration. Every render manifest preserves this unresolved marker
and its blocker, independently of the ingestion declaration comparison;
RS9 neither rewrites it nor invents the legal meaning of Commercial. SPDX list
membership remains unvalidated. Tenant reconciliation blocks acceptance.

Evidence: [ingestion record](../../tests/fixtures/nebular-0.6.1/ingestion.json) and
[collection observations](../../tests/fixtures/nebular-0.6.1/live-observations.json).
Publisher provenance/SPDX/notices are bound, but signatures and attestations are
not evaluated. Collection observations are supporting evidence, not verdicts.

## Runtime and launcher findings

Each Linux payload contains three ELF objects: the main GTK/WebKit GUI, the
native `tfsb-studio-service`, and a platform-specific directory-snapshot Node
addon. The native sidecar adds libstdc++ requirements. Both platforms require
GLIBC 2.34, GLIBCXX 3.4.21 and CXXABI 1.3.9. Interpreters are the standard
architecture-specific GNU loaders. No ELF RPATH/RUNPATH is present and no private
SONAME provider is inferred. Arm64 directly adds cairo-gobject and pango; x86_64
directly names its loader in the GUI's NEEDED list.

Both archives also contain a shell `bin/tfnf` shim and Loom Node scripts with
packaged `engines.node = ">=22"`. The shim provides headless version/path output
and resolves symlinks before launching the adjacent native GUI. It is present
and executable, so the plan's possible dangling-reference-launcher finding is
withdrawn. The optional asset `launchers` map selects it explicitly while the
primary `commands` map continues to bind the native executable hash. Darwin
selects the release-owned Resources shim. Full resource/sidecar readiness remains
separate from printing version metadata.

Evidence: [both-platform dependency model](../../tests/fixtures/nebular-0.6.1/dependency-evidence.json).
Candidate Arch/Fedora/Nix mappings cover GTK3, WebKit 4.1, JavaScriptCore, libsoup3,
GLib, cairo, pixbuf, dbus, GNU C/C++ runtime and the script interpreters. Current
Arch queries identify split `libgcc`/`libstdc++` providers. Provider proof and
runtime smoke limitations are recorded in [qualification](../foundation2-qualification.md).

| Reference dependency difference | Classification |
|---|---|
| gtk3/WebKit/GLib/cairo/dbus naming | Equivalent ecosystem names where providers agree |
| libsoup3, pixbuf, GNU runtime and Node | Released object/script requirements; explicit closure candidates added |
| pango on x86_64 | No direct released object requirement; GTK/transitive use remains possible |
| openssl/zlib | No direct released object requirement; redundancy and transitive runtime use remain unresolved |
| compiler library package naming | Arch split provider correction; Fedora/Nix mapping remains ecosystem-owned |
| hicolor-icon-theme | Adapter-owned desktop integration dependency, identified by Arch lint |

No release bytes are changed to accommodate those mappings.

## Desktop and icon authority

Neither Linux raw archive contains a desktop entry or icon PNG outside bundled
dependencies. Tagged Tauri configuration supplies product name, the observed
short description and DeveloperTool category. RS9's explicit example selects
`Development` and renders only Type, Name, Comment, Exec, Icon, Terminal and
Categories. The reference's MIME associations, `%U`, WM class and additional
categories remain reference-only behavior pending evidence. File/URL argument
support and launcher/window matching were not tested, so their omission is a
material unresolved parity gap, not an accepted behavior normalization.
The generic name also lacks tenant facts. Desktop bytes are deterministic RS9
metadata from the declarative configuration.

The explicit tagged selection `src-tauri/icons/icon.png` is a verified Git blob,
256px square PNG, SHA256
`2d65e8c69a675b6c939ac11757c6a47a123f63b3f83b6d58305aaf7231aca160`.
It is byte-identical to the reference 256px icon. The other reference sizes have
no selected tagged authority and are excluded. Dimensions are derived from PNG
IHDR bytes; there is no tenant-authored size or derived release digest.

These are RS9-authored stand-in tenant facts, not a claim that the tenant adopted
the example. The selection relationship is bound to the release repository's
resolved tagged commit.

## Adapter design and comparison

The stdlib renderer consumes normalized intent and an in-process authentication
result, derives fresh dependency evidence and writes exclusively into an existing
empty physical output root. It renders Nix for three declared systems, direct
pacman for x86_64, RPM for both Linux architectures, and explicit AUR profile
`theme-forge-nebular-fusion-bin` for both. Public Linux launcher paths and package
family names are retained; concrete Nix derivation names are compared separately.
The whole payload, including hidden files, sidecar, resources
and notices, is copied with byte-preservation controls. AUR provides/conflicts
retain the project identity, with a versioned provides declaration.

Package-source URLs are build-time fixed-hash inputs; no install or runtime
network fetch is rendered. Nix uses a Linux FHS wrapper with no fallback that
would skip the ELF interpreter environment. Darwin preserves the app bundle.
RPM checks raw archive, local desktop and tagged icon hashes before unpacking;
strip/shebang/brp transformations are disabled. Private bundled SONAME filters
remove matching requirements and provides together when needed.

The public reference remained at `062a931f4b5e44ad43c88363efd81ab8d92602df`
in fresh remote audits. No unpublished DIST1 R2 work is consumed. Static source
inspection avoids executing external Bash/Nix on the parent. Source/blob hashes,
32 classified field differences and material flags are in the
[reference facts](../../tests/fixtures/nebular-0.6.1/reference-facts.json) and
[comparison](../../tests/fixtures/nebular-0.6.1/comparison.json).
The [byte comparison](../../tests/fixtures/nebular-0.6.1/reference-byte-comparison.json)
binds every reference/projected recipe and desktop digest; the selected tagged
256px icon is identical to the reference icon. Captured reference blobs are
verified against the observed commit's complete recursive tree.
Static first-tenant parsers re-derive reference and shadow names, architectures,
dependency declarations, provides/conflicts, desktop fields and recipe paths.
Mutation tests check material drift; unknown Nix license attributes fail closed.
Concrete Nix names are reported per system: Linux FHS outputs are `tfnf` in both
recipes, while Darwin changes from the reference family pname to the shadow
`theme-forge-nebular-fusion-payload`. That naming difference is an unresolved
material blocker. RPM-managed license copy basenames are derived from `%license`;
the concrete versioned license directory remains package-manager-owned and
requires installed-tree readback. These constrained static grammars do not
evaluate recipes or establish installed package behavior.
Unchanged identities are tested separately; every differing field must have a
non-stale classification. Built package payload readback confirms shadow content
identity for pacman/RPM and Darwin Nix. Installed-tree/reference-package readback
remains incomplete; the comparison does not claim that reference
packages necessarily changed executable bytes.

Two renders are byte-identical. The
[golden manifest](../../tests/golden/shadow/nebular-0.6.1/render-manifest.json)
binds all nine text outputs and input hashes. Goldens are test evidence, not
publication state. Build/install outcomes and unavailable architectures remain
accurately bounded in the qualification report.
