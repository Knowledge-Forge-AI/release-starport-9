# LIVE1 hosted candidate source

Status: CONT2 non-production source candidate following the dispatcher advisory pre-final review.
Closeout amendments are recorded in the source evidence; manager disposition and adoption remain pending.
No authenticated release capture, package build, hosted PASS, destination publication or production receipt is claimed by the provider.

The immutable generation is Stellar Burst 0.6.1, Stellar Loom 0.4.0, Solar Sail 0.2.1 and Nebular Fusion 0.6.1. The pre-RS9 bootstrap remains migration authority. No upstream version or release is changed.

## Execution and custody

[The source contract](../operators/live1/hosted-lanes.json) defines 16 required lane/system receipts and artifact sets. It drives workflow matrices and both aggregate and operator completeness validation. Config, source tests and summary are also required jobs. [The workflow](../.github/workflows/rs9-candidate-tests.yml) triggers on main pushes and manual dispatch, uses pinned action commits, read-only contents permission and credential-free checkout. It has no production environment, secret reference, OIDC permission, deployment or publication operation.

| Lane | Actual hosted work | Retained custody |
|---|---|---|
| authenticate | Fresh tag, source, checksums, provenance and asset authentication | Canonical release projection and command implementation bindings |
| pins | Resolve platform image digests once and validate source nixpkgs identities | Exact run pin record |
| wheels, three systems | Double build, strict RECORD, venv install/supported probes/uninstall and full inventory comparison | Exact wheels, hash manifests and lifecycle evidence |
| Nix, three systems | Authenticated payload/lock closure input, pinned nixpkgs, all four builds, flake check, command readback and native runtime verification | Actual drvPath/outPath/narHash/narSize receipts |
| pacman x86_64 | Real makepkg/repo-add, unsigned custody, fixture-signed copies, disconnected clients and tamper tests | Exact unsigned package objects and bounded evidence |
| RPM Fedora 43 x86_64/aarch64 | Real rpmbuild/rpmlint, dependency readback, fixture header signing, signed metadata, clients and tamper | Unsigned RPM objects and separate fixture-signed identities |
| APT Ubuntu 26.04 amd64/arm64 | Real dpkg-deb/dpkg-shlibdeps, all-architecture dual indexes, signed Release/InRelease, clients and tamper | Exact deb objects and repositories bound by hashes |
| Pages | Rebuild fixture repositories from custody, strict namespace/CNAME, format-aware privacy scan and assembled-tree client tests | Exact public tree/Merkle root, with an indexed split fallback |
| observe | Read-only PyPI, npm, Homebrew and Pages readback | Observations, including truthful unknown states |
| Foundation 3 | Rehash/reverify exact custody in-process, generate disabled plans; CI verdicts remain an annex | Qualification records, disabled plans and missing-input reasons |

Build and qualification run in one job per system. The tested files are the retained files; fixture signing uses separate copies. APT architecture-all and RPM noarch copies must agree byte-for-byte across lanes before Pages assembly. Conflicts block aggregation. Production signing later changes RPM headers and requires a new post-sign identity and readback. Fixture-signed objects are marked test-only.

Each set contains a v1alpha2 manifest binding source commit, workflow/contract/builder hashes, canonical release-ingestion hash, event/ref/attempt, runner/tool facts, package hashes and receipt hashes. Aggregation rejects mixed source, release, run or inventory. The summary is bounded to 16 MiB. Upload retention is 90 days, subject to repository/organization limits; the manager packet records actual artifact IDs, outer SHA-256 digests and expiration times. A future publisher must use actions:read and the reviewed run ID, download retained artifacts, verify outer digests and rehash their logical inventories. It must not silently rebuild qualified bytes.

## Qualification limits and first-run outcome

The first run is expected to be **not-qualified**, even if all executable lanes succeed:
- Container digests and the version-bound Nix installer checksum are resolved once during preparation because provider DNS is unavailable. Their provenance is run-resolved; the summary refuses to call that source-reproducible. Commit reviewed run pins before a manager-acceptable qualification.
- Linux Nebular wheels use honest generic linux_x86_64/linux_aarch64 candidate tags. Manylinux remains refused, and every production builder path still withholds Linux wheels. Their promotion policy requires manager disposition; a future publisher must refuse them while pending.
- Command declarations are researched against maintained upstream source and bound to exact authenticated released implementation bytes during the hosted run. Missing implementation guards or unavailable released smoke fixtures fail required command gates.
- Homebrew metadata-only or unreachable readback stays incomplete/unknown; no noop is fabricated.

The summary reports lanes_executed_ok separately from qualification_verdict and blocking_reasons. No hosted PASS record is checked into source. A failed hosted lane is repair input and is never automatically rerun.

## Runtime behavior

Supported command declarations live in [command-contracts.json](../operators/live1/command-contracts.json). Burst/Loom/Sail version behavior is permitted only after implementation binding. Studio service validation uses initialize/initialized/shutdown/exit NDJSON, and tfsl-batch retains empty stdin, exit 1, EMPTY_INPUT. Nebular metadata uses its released launcher; its sidecar verifier and application-aware scenarios come from authenticated tagged blobs. Darwin scenario A and Linux platform scenarios inspect the installed/materialized runtime, not a GUI probe in a build sandbox.

Provisioning can use the network. Linux runtime uses nonroot network namespaces or Docker --network none, with an actual negative connectivity check. Wheel and Nix probes restore a filtered HOME/PATH/cache environment after privilege dropping, so sudo environment reset cannot redirect materialization into the root cache. Capture and Actions credentials are excluded from application and pip environments. Wheels also qualify on the pinned Ubuntu 26.04 and Fedora 43 clients. Darwin lifecycle and application checks run, but Darwin offline is explicitly not-run:darwin-offline-isolation-unsupported. Proxy variables are not an offline proof.

Pages uses only apt/, rpm/, pacman/, keys/, docs/ and CNAME, with CNAME exactly rs9.knowledge-forge.ai. Fixture public keys use rs9-candidate-fixture-NONPRODUCTION names and metadata; production key paths are refused for fixture mode. The index records every tree object and the Merkle root. Trees up to 2 GiB are uploaded whole. Larger trees use an indexed split: metadata and newly fixture-signed RPM objects remain in the Pages artifact; unchanged APT/pacman package objects remain in family custody and are re-bound by their exact hash.

Assembled Pages client tests cover amd64/x86_64 APT, DNF and pacman, including package, index, signature and wrong-key rejection. The arm64 APT and aarch64 RPM family lanes qualify their own repositories; installation from the final assembled arm64 Pages repositories remains deferred. No assembled arm64 client result is claimed.

## Attended handoff

Use [the runbook](../operators/live1/RUNBOOK.md) after the dispatcher finishes review. The operator authenticates exact manager-reviewed inventory/tree/manifest, requires current remote main to equal the reviewed parent, stages only reviewed paths including deletions, commits normally and fast-forward pushes. It finds the new push run for that commit, refuses reruns/non-main runs, waits with a bound, and stores all jobs/steps, artifact identities, summary bytes and validation reasons before returning.

The operator stops on failure or timeout. The manager packet retains all summary-reported blockers even when validation stops at its first error; reported diagnostics confer no qualification authority. An explicit collect command can resume read-only collection into another empty outbox directory. No production publication, key access, npm/Homebrew mutation, Pages deployment or production receipt is performed.
