# Foundation 2 shadow qualification

Status: partial qualification. Shadow acceptance and migration remain deferred.
The parent checked retained logs and manifests rather than accepting worker
summary verdicts. No package was signed or published. No Git mutation occurred.

## Terminal verification boundary

The dispatcher pre-final review returned advisory findings and executed no tests.
Closeout amends comparison evidence and adds an explicit unresolved-license
marker to normalized intent and render manifests. Package recipe and desktop
bytes are retained. Terminal scoped verification reauthenticates captured release
inputs, checks double-render identity and recipe identity, and runs affected
contract/comparison tests plus the task-required final suite, portability and
product hygiene checks. The exact results are recorded in the terminal handoff.
These checks do not rerun the package builds/install observations below or repair
their environment, provider, installed-tree or runtime limitations. Closeout
fresh remote audit failed at DNS resolution; captured-byte reauthentication
does not claim collection freshness. No additional review is obtained.

## Executed checks

| Target | Observed result | Environment and limits |
|---|---|---|
| Nix aarch64-darwin | Build, upstream shim version/path and payload readback passed; altered source hash rejected | Native Darwin arm64; ambient Nix channel; IFD disabled |
| Nix aarch64-linux / x86_64-linux | Both derivations instantiated with IFD disabled | Builds/install unavailable without Linux Nix builder |
| pacman x86_64 | Package built; dependency-checked install/uninstall with network disabled; launcher, desktop, icon and license readback | Disposable Arch x86_64 container, emulated on arm64 host |
| AUR x86_64 | Package built; `makepkg --printsrcinfo` exactly matched golden `.SRCINFO`; source verification passed | Same disposable Arch environment; separate AUR install not executed |
| AUR aarch64 | Architecture-specific `makepkg --verifysource` passed | Source check only; no arm64 Arch package build/install |
| RPM x86_64 / aarch64 | Both packages built and installed without dependency bypass under network isolation; launcher/integration readback and uninstall passed | Fedora 43 disposable containers; x86_64 emulated, arm64 in Linux VM |
| RPM altered asset | One-byte Source0 corruption rejected by rendered `%prep` checksum | `rpmbuild -bp` failed before extraction |
| RS9 altered/unsafe inputs | Offline adverse tests and live reauthentication passed | Fixture negatives are distinguished from real release evidence |

The package builds used pre-staged authenticated assets and the selected tagged
icon. Arch builds used `makepkg --nodeps`; the later install used `pacman -U`
with dependency checks. RPM installs used `rpm -ivh` without `--nodeps`. Container
runtime dependencies were provisioned before `--network none` install checks.
There were no package install scriptlets. System icon/MIME cache hooks ran normally.
Uninstall readback confirmed payload-directory and launcher removal; complete
desktop/icon/license residue readback was not executed.

## Payload identity and recipe binding

Parent verification compared authenticated archive manifests with retained built
package/store manifests, including dotfiles, sidecars and native addons:

| Payload | Regular files and symlinks | Content/link identity | Modes |
|---|---:|---|---|
| pacman x86_64 | 1,371 | Identical | Identical |
| RPM x86_64 | 1,371 | Identical | Identical |
| RPM aarch64 | 1,371 | Identical | Identical |
| Nix Darwin app bundle | 1,316 | Identical | Write bits removed by Nix store |

These are built-payload manifests. Full installed-tree manifests and installed
native-executable hashes were not collected. Headless `tfnf --version` reports
upstream shim metadata; it does not exercise the GUI executable or sidecar.
Directory modes are outside these regular-file/symlink comparisons.

All nine executed recipe/desktop files are byte-identical to the final goldens.
The qualification render manifest differs from the final manifest because
normalized input and evidence metadata hashes evolved. The parent verified this
bridge file by file; no executed recipe changed. Exact recipe, manifest, harness,
log and payload-manifest digests are in the small
[parent readback record](../tests/fixtures/nebular-0.6.1/qualification-readback.json).
Full logs, harness and payload manifests remain in scratch `qualification-final/`.

## Provider and lint results

Arch `pacman -F` and Fedora x86_64 `dnf repoquery` returned providers for every
observed system SONAME. Arch confirms split `libgcc`/`libstdc++` providers.
Fedora arm64 queries returned **no providers** because the harness used an
incorrect capability glob. Their log is retained as unsuccessful evidence.
Nix attribute evaluation passed, but SONAME file-provider proof was not executed.
Mapping qualification therefore remains incomplete; committed dependency records
keep mappings explicitly unqualified. GLIBC >= 2.34 and Node >= 22 are rendered
from released object/script evidence.

`namcap PKGBUILD` reported architecture-literal and missing-maintainer warnings.
Package-level namcap and standalone `desktop-file-validate` were not executed.
RPM lint was executed and did **not** pass cleanly: each architecture reported
15 errors and 138 warnings. The same diagnostic families occurred on both:

| Diagnostic family | Disposition |
|---|---|
| Explicit library dependencies (5 errors) | Intentional task-required evidence-to-Fedora mappings; not official Fedora contribution policy |
| Non-executable scripts (6), env-script interpreter (2) | Upstream released modes/shebangs preserved; changing them would violate payload identity |
| Duplicate payload waste (1 error), duplicate-file warnings | Upstream bundled files preserved; no deduplication |
| Missing changelog identity (1 error) | Operator identity excluded from deterministic shadow recipe |
| Unstripped binaries, hidden files, PIE suggestion | Upstream payload preserved without fixup |
| Missing manual/docs/check section, desktop launcher warning | Packaging convention limitations; installed shim readback succeeded |
| Crypto policy and gethostbyname warnings | Upstream binary behavior; runtime/distro-policy qualification unresolved |

These classifications explain retention; they do not convert lint errors into
a passing official-repository gate. RPM Requires/Provides completeness and
reference package installed-manifest comparison remain unqualified.

## Reproducibility and remaining gates

The second harness referenced locally provisioned container images; immutable
base-image provenance and repository snapshot identities were not retained in
that harness. It is disposable-environment evidence, not a reproducible pinned
container qualification. Nix used an ambient `25.11pre-git` channel rather than
the planned reference commit. Its claimed content hash was hardcoded in the
harness, so the parent rejects that hash as independent verification.

A bounded display launch was reported as a three-second timeout, but its command
and stdout/stderr were not retained by this harness. No GUI, resource-resolution,
Node module-resolution or sidecar-readiness proof is claimed. No hosted/native
x86_64, signature, AUR publication or live client qualification was performed.
The makepkg altered-asset negative was not executed; RS9, RPM and Nix digest
negatives supply distinct recorded evidence.

The source-tag license declarations support `AGPL-3.0-or-later`; the authenticated
published npm wrapper declares `AGPL-3.0-or-later OR Commercial`. This conflict
remains an acceptance blocker independent of build success. Resolve it through
tenant authority, then complete provider, pinned-environment, installed-tree and
runtime qualification before any migration.

## Worker disposition and cleanup

Qualification attempt 1 is preliminary only. After its cleanup was proven, the
parent adopted observations and corrected SRCINFO ordering, icon-theme mapping,
Arch compiler providers and runtime version floors. Attempt 2 used the corrected
recipe bytes. Its disposition is **partial** because the limitations above remain.
The parent made no third qualification attempt or hidden provider fallback.

The retained cleanup receipt shows successful removal of the three owned local
builder images. Docker commands used `--rm`. APGR reports provider-process and
transport cleanup proven. A separate global daemon inventory was not recorded;
no claim is made that unrelated daemon resources changed or were audited.
