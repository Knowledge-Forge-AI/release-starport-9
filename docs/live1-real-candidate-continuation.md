# Theme Forge real-candidate continuation

Status: **blocked partial source candidate; adoption disabled; not production ready**.
This is the terminal amended source candidate for RS9-LIVE1-THEME-FORGE-CONT1-REAL-CANDIDATES1.
The dispatcher supplied the independent work review, which found material source defects
and confirmed that the real generation is incomplete. Closeout corrections have no
automatic independent review. Internal workers and provider tests do not satisfy a
dispatcher review checkpoint. No provider-local Git publication, release mutation,
production signing, destination mutation or secret provisioning occurred.

The original objective remains a complete generation from Burst 0.6.1, Loom 0.4.0,
Sail 0.2.1 and Nebular 0.6.1. This partial result does not reduce that objective.
The bound 27,235-byte proposal, SHA-256
`3efb00e8cebf4778588c0170eeedaf9dbea28df57e8d36413499db3f7a407df7`, is **amended**.
[Disposition](../evidence/live1/continuation-proposal-disposition.json) distinguishes
the original scope, proposal, advisory findings and observed source changes.

## Real evidence and blockers

Fresh authentication was attempted through the release capture pipeline and stopped
with FETCH_FAILED. Shell DNS could not resolve GitHub, release CDN, PyPI, npm or RS9
Pages. Historical metadata and manager hashes were not reused as authenticated bytes.
[Environment](../evidence/live1/environment.json) retains booleans and output hashes,
without host paths or usernames. Download/build scratch remains outside source.

Docker's engine and the Nix daemon were inaccessible. Native Linux packaging tools
were absent. GPG fixture-key generation could not start an agent in this sandbox.
Consequently there are **zero authenticated releases, zero real downstream artifacts,
zero real qualification records, zero Foundation 3 publication plans and zero receipts**.

| Output | Source candidate | Real qualification |
|---|---|---|
| CLI wheels | Authenticated archive/profile binding, lock-pinned offline dependencies, dependency notices, Node >=22 launchers, deterministic builds and venv lifecycle/parity helpers | Not-run; no downloaded releases |
| Nebular Darwin wheel | Archive-preserving arm64 builder, tag floor of macOS 11, unchanged reviewed materializer/helper bytes embedded, exact launcher binding | Not-run; released verifier and scenario-A remain unqualified |
| Nebular Linux wheels | Withheld pending a truthful accepted compatibility policy and complete ABI/system closure | Not-run; no manylinux promise inferred from a glibc floor |
| Nix | Existing unexposed candidate definitions retained | No nixpkgs lock, complete FHS closure, native smoke or supported exposed outputs |
| pacman/RPM/DEB | Native-tool CLI package drivers and exact archive staging; architecture-independent CLI packages use any/noarch/all | Not-run; native Nebular dependency derivation explicitly withheld |
| Signed repositories | Ephemeral fixture signer, pinned-issuer exact-index/object readback contract; RPM metadata requests gzip and no database | No real native repository, clean client or fixture tamper qualification |
| Pages | Strict apt/rpm/pacman/keys/docs prefixes, explicit root docs, supplied exact inventory, collision/CNAME checks and privacy scan | No qualified repository objects or public tree candidate; real binary packet-scan compatibility remains unqualified |

The native drivers remain unqualified interfaces. They do not constitute clean-client,
installed-byte, reproducibility or fixture-trust evidence. In particular, running
dpkg-shlibdeps against the released shell launcher cannot prove the GUI and mandatory
sidecar closure; the Debian native path refuses it. RPM 6 signing/header identity and
real rpmlint findings remain untested. Architecture-specific npm dependencies remain
withheld from architecture-independent CLI outputs.

## Destination observations and planning

[Destination matrix](../evidence/live1/continuation-destinations.json) contains current
read-only attempts: four PyPI names, four npm projects, public repository HTTP paths,
Git main and Pages administration. Fourteen observations are unknown because transport
failed. Four Homebrew observations are not-run because a fresh immutable tap reference
and candidate payload authority are unavailable. No name was reserved or uploaded.

PyPI metadata URL 404 may establish absence; file-download 404 remains unknown. An
unauthenticated Pages administration 404 may conceal access and remains unknown.
Git ref and formula metadata do not establish downstream artifact identity. npm exact
readback now downloads the tarball, verifies sha512, and compares packaged metadata;
its mutation policy remains observe-only. Signed repository exactness requires the
pinned primary/subkey issuer, a reviewed index parser and every exact object byte.

[Gate matrix](../evidence/live1/gate-matrix.json) and
[plan availability](../evidence/live1/continuation-plan-availability.json) retain
all 36 proposed product/destination pairs. Every real platform gate remains not-run;
authentication is blocked. There are no artifact hashes from which to generate real
Foundation 3 plans. Provider and hosted diagnostic passes never satisfy attended gates.

## Hosted workflow and manager boundary

The [candidate workflow](../.github/workflows/rs9-candidate-tests.yml) now triggers on
main pushes and runs read-only authentication and CLI wheel diagnostics on Darwin arm64,
Linux x86_64 and Linux arm64. Actions are pinned. GitHub's contents-read workflow identity
is confined to GET requests at api.github.com; redirects, assets and raw source never
receive that credential. Rate limits and transport errors fail closed.

**This workflow is incomplete and deliberately fails qualification.** Native packages,
Nix, Pages, released Nebular sidecar/scenario-A and clean-client/signature/tamper lanes
still have explicit unmet prerequisites. Distro container digests, Arch snapshot,
nixpkgs revision and maintainer are unresolved in
[targets](../operators/live1/targets.json); no floating container or nixpkgs substitute
was installed. The workflow uploads bounded diagnostic receipts, hashes and manifests,
not duplicate release payloads. It has no production environment, publishing command,
production secrets, deployment permission or OIDC publishing permission.

The [attended adoption operator](../operators/live1/adopt-and-qualify.py) checks a
manager-reviewed complete inventory/tree and parent, stages only inventory paths,
commits and fast-forward pushes main, waits within a bound for the new push run at
that commit, then collects every job/step conclusion and digest-checked receipts.
It stops for manager disposition. Its manifest currently has candidate_adoption_ready
false, so **it refuses this partial candidate before any Git mutation**. Its source and
receipt-boundary tests do not claim full attended adoption or hosted execution proof.

Before future production publication, an attended rebuild must reproduce the exact
hosted candidate artifact hashes, or exact artifact bytes must be retained in durable
reviewed custody. One-day diagnostic artifact retention is not publication custody.
RPM production signing changes container bytes: verify payload/header identity with
the actual pinned RPM version and record final signed SHA-256 and exact readback.

The separate [signing preflight](../operators/live1/signing-preflight.py) inspects key
availability markers and compares an in-memory public export against an independently
reviewed public-key hash. It prints fingerprints/booleans only, never signs, exports
private material or handles a passphrase. Listing local secret availability does not
prove passphrase usability. Production fingerprints remain unchanged.

## Verification and deferral

Work-stage verification ran 435 unittest cases: 428 passed and seven skipped. Five skips
require authenticated live captures; two require an available fixture GPG agent.
After the terminal helper correction, 26 targeted tests ran: 25 passed and one fixture
GPG case skipped. Missing-tool tests use an explicit seam on every host, including
Linux hosted runners. Synthetic repository construction now lives exclusively in tests.
Fixture wheel installation, execution and uninstall are source regression evidence,
not Theme Forge release qualification. The expected AMBIGUOUS_COVERAGE negative-test
diagnostic is not a suite failure. [Verification](../evidence/live1/continuation-verification.json)
records log hashes and the source-only limits. No dependencies, package metadata or
test-runner policy were changed. Materialize and its embedded helper source files
remain unchanged; archive/profile checks were tightened in the new wrapper builders.

Four bounded Gemini workers supplied source with disjoint ownership. All completed
with proven cleanup and were dispositioned partial after parent amendments. The
provider reran integrated tests. This is not independent review.

Closeout accepted the work-review findings and amended the source interfaces without
claiming an adoptable generation. The per-finding disposition and terminal delta are in
[closeout evidence](../evidence/live1/continuation-closeout.json). Pacman source staging
now populates makepkg's srcdir before --noextract. The existing APT engine indexes CLI
Architecture: all packages in both binary-amd64 and binary-arm64; native dependency
qualification remains withheld. Node requirements are explicitly reviewed policy,
separate from builder execution. Architecture-independent native payload rejection now
covers ELF, PE, 32/64-bit and fat Mach-O, and native library names.

All wheel verifiers use the same strict bidirectional RECORD implementation. Lifecycle
verification compares the full venv inventory, including bytes/types/modes and empty
directories, and isolates and reports Nebular's cache after pip uninstall.
Linux diagnostic commands use network namespaces and setpriv to return to the non-root
runner identity. Darwin offline execution remains not-run because proxies do not prove
isolation. tfsl-batch uses empty input only; the studio-service probe is withheld pending
a supported released scenario. Product/command diagnostic failures are retained without
inventing supported flags. Summary/readback requires all 13 workflow lane/system receipts
and compares summary outcomes to their contents. Configuration blockers derive from the
target declaration; pin or exposure settings never prove an implemented Nix harness.

Pages assembly rejects source collisions and mismatched CNAME and requires a supplied
inventory before writing. Explicit discovery mode remains non-authoritative. Legacy
root/asset/repository namespaces are rejected. The conservative OpenPGP packet scan is
unchanged: possible real RPM/XZ false positives remain deferred until real artifacts can
be tested. npm readback compares normalized bin metadata with authenticated tarball bytes,
following the [npm normalization implementation](https://github.com/npm/npm-normalize-package-bin/blob/v3.0.1/lib/index.js).
PyPI project conflicts use observed metadata hashes rather than invented semantic
identities; duplicate registry rows stay unknown. The signing runbook specifies the
exact public export command behind its reviewed digest and requires attended review of
UID/certification changes.

After all runtime/test source amendments, closeout ran the complete unittest suite:
470 tests, 463 passed, seven prerequisite skips, zero failures/errors. The skips still
require five authenticated live captures and two available fixture-GPG agents. Subsequent
report/evidence/inventory edits receive terminal hygiene, diff and inventory checks;
they introduce no runtime source changes. Three additional bounded Gemini workers
completed with proven cleanup; their output was parent-amended and dispositioned partial.
Their requested model was observed in admission evidence; effective provider model was
not independently reported. No additional substantive review was requested. Hosted
qualification remains externally pending and was not executed during closeout.

Production remains blocked on fresh byte authentication, complete real builds,
platform/client/trust qualification, truthful Linux wheels, pinned Nix/distro inputs,
real Foundation 3 records/plans, hosted results, name/owner/publisher attestations,
license authority, Pages/DNS/TLS administration, durable artifact custody and attended
production signing/readback. APGR readiness is documented separately; APGR was untouched.
