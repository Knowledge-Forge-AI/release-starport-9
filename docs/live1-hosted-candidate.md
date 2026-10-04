# LIVE1 hosted candidate source

Status: REPAIR1 non-production candidate source following the hosted repair amendments.
Proposal disposition: amend. Bound proposal SHA `e55cb8ab059b22ed799c3504cb67185d318317b9fc7e35706324971bd55e301d`; all plan-review corrections are retained.
Dispatcher work-review findings were dispositioned at closeout. Terminal corrections are recorded in the source repair evidence and have no subsequent independent review; exact terminal bindings require manager disposition.
First hosted run 37166638590 failed due to primary source defects; a second hosted run has not been performed, downstream cascades are untouched, and no hosted green qualification is claimed.
No fresh full release capture, hosted PASS, destination publication or production receipt is claimed. Local synthetic package and installed-wheel tests establish source contracts; real hosted package lanes remain mandatory integration.

The immutable generation is Stellar Burst 0.6.1, Stellar Loom 0.4.0, Solar Sail 0.2.1 and Nebular Fusion 0.6.1. The pre-RS9 bootstrap remains migration authority. No upstream version or release is changed.

## Execution and custody

[The source contract](../operators/live1/hosted-lanes.json) defines 16 required lane/system receipts and artifact sets. It drives workflow matrices and both aggregate and operator completeness validation. Config, source tests and summary are also required jobs. [The workflow](../.github/workflows/rs9-candidate-tests.yml) triggers on main pushes and manual dispatch, uses pinned action commits, read-only contents permission and credential-free checkout. It has no production environment, secret reference, OIDC permission, deployment or publication operation.

| Lane | Actual hosted work | Retained custody |
|---|---|---|
| authenticate | Fresh tag, source, checksums, provenance, asset authentication, command policy validation, and command report retention on success and failure | Canonical release projection, command implementation bindings, and bounded `command-report.json` |
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

## Observed bytes and command report

The [command report](../evidence/live1/hosted-repair-command-report.json) records every declared command and launcher from retained release bytes. All six payload sizes and hashes match the reviewed current-generation expectations. These bytes establish command semantics; a fresh complete API/source capture remains hosted work.

| Project | Declared commands | Regular member mode | Reviewed execution contract |
|---|---|---|---|
| Burst 0.6.1 | `tfsb`, `tfsb-studio-service` | `0644` | Exact package bin targets and Node shebangs; explicit Node wrappers |
| Loom 0.4.0 | `tfsl`, `tfsl-batch` | `0755` | Exact package bin targets and Node shebangs |
| Sail 0.2.1 | `tfss` | `0755` | Exact package bin target and Node shebang |
| Nebular 0.6.1 | Native `tfnf` executable and release launcher in each of three archives | `0755` | Regular executable members; shell launcher shebangs |

Generic archive command inspection records now bind `path`, `sha256`, `size`, and `mode`. Payload `command_policy` (`native-executable` and `npm-package-bin`) is additive in `v1alpha1`. `rs9.release_core` delegates closed policy validation to `rs9.command_policies`. `rs9.npm_commands` owns declarative bin agreement and Node shebang verification on the bounded first line (`node_script_shape`), and direct release capture also validates bins and shebangs. Unknown policies or native profile downgrades are refused; package bins cannot declare native launchers. RS9 wrappers invoke Node explicitly (`node-explicit`), allowing Stellar Burst's observed 0644 mode without compromising native executable enforcement. Undeclared bins are recorded in profile results (`undeclared_bins`) but not exposed.

The hosted pipeline retains `command-report.json` on success and failure whenever scratch capture directories exist. Reports and command rows explicitly record `bytes_authenticated` and `basis`: completed generation authentication is distinguished from captured-archive inspection, including digest failures. Retained-payload inspection in the source evidence binds sizes/hashes but does not claim full generation authentication. `execution_error_detail` is closed and sanitized (allows spaces; forbids absolute paths and secrets).

## Hermetic testing, Pages fixtures, and resource management

Hermetic Pages sibling tests always run. Tests patch synthetic `sign_rpm` for both real GPG and fake runners. Production checks stay strict: `production_enabled: false` remains mandatory, and custom files supplying production key paths (`keys/rs9.asc`, `keys/rs9-archive-keyring.gpg`) are strictly rejected with `FIXTURE_KEY_PATH`. The exact NONPRODUCTION fixture inventory is maintained:
- `keys/rs9-candidate-fixture-NONPRODUCTION.asc`
- `keys/rs9-candidate-fixture-NONPRODUCTION.gpg`
- `keys/KEY-METADATA.json` (`purpose: "NON-PRODUCTION CANDIDATE TEST ONLY"`)

The test inventory binds fixture-owned public armor independently of the assembler helper, so assembler byte drift fails with `TAMPER_DETECTED`. Tampered candidate files also fail exact inventory verification. In `src/rs9/pages.py`, format-aware `zstd` decoding joins feeder threads with timeout, kills and reaps child processes on limit or exit timeout, and closes stdin/stdout to avoid resource leaks or ResourceWarnings.

## Qualification limits and environment reality

The qualification verdict remains **not-qualified** and hosted PASS is not claimed:
- **First hosted run**: Run 37166638590 failed due to primary source defects; a second hosted run has not been performed, downstream cascades are untouched, and no hosted green qualification is claimed.
- **Local environment**: The local execution environment is Darwin with Python 3.13; no Python 3.12 or GnuPG usable was observed locally. Minimal scratch symlink PATH reruns serve strictly as tool-isolation checks, not Ubuntu equivalence.
- **Stock Ubuntu 24.04 environment**: A stock ubuntu-24.04 source unit assumes Python 3.12, Node 22, and GnuPG are present, and the unit suite must work without Docker, Nix, Arch/RPM builders, or zstd. Real hosted package lanes remain mandatory integration.
- **Run-resolved inputs**: Container digests and Nix installer checksums resolved during preparation prevent source-reproducibility qualification until committed as reviewed pins.
- **Linux wheel policy**: Linux Nebular wheels use generic `linux_x86_64`/`linux_aarch64` candidate tags; manylinux remains refused and production paths remain withheld pending manager disposition.
- **Homebrew observations**: Readbacks remain incomplete/unknown when unreachable; no noop is fabricated.
- **Verification**: Counts and scoped skips are recorded in [source repair evidence](../evidence/live1/hosted-repair-verification.json).

The summary reports `lanes_executed_ok` separately from `qualification_verdict` and `blocking_reasons`. A failed hosted lane is repair input and is never automatically rerun.

## Runtime behavior

Supported command declarations live in [command-contracts.json](../operators/live1/command-contracts.json). Burst/Loom/Sail version behavior is permitted only after implementation binding. Studio service validation uses initialize/initialized/shutdown/exit NDJSON, and tfsl-batch retains empty stdin, exit 1, EMPTY_INPUT. Nebular metadata uses its released launcher; its sidecar verifier and application-aware scenarios come from authenticated tagged blobs. Darwin scenario A and Linux platform scenarios inspect the installed/materialized runtime, not a GUI probe in a build sandbox.

Provisioning can use the network. Linux runtime uses nonroot network namespaces or Docker --network none, with an actual negative connectivity check. Wheel and Nix probes restore a filtered HOME/PATH/cache environment after privilege dropping, so sudo environment reset cannot redirect materialization into the root cache. Capture and Actions credentials are excluded from application and pip environments. Wheels also qualify on the pinned Ubuntu 26.04 and Fedora 43 clients. Darwin lifecycle and application checks run, but Darwin offline is explicitly not-run:darwin-offline-isolation-unsupported. Proxy variables are not an offline proof.

Pages uses only apt/, rpm/, pacman/, keys/, docs/ and CNAME, with CNAME exactly rs9.knowledge-forge.ai. Fixture public keys use rs9-candidate-fixture-NONPRODUCTION names and metadata; production key paths are refused for fixture mode. The index records every tree object and the Merkle root. Trees up to 2 GiB are uploaded whole. Larger trees use an indexed split: metadata and newly fixture-signed RPM objects remain in the Pages artifact; unchanged APT/pacman package objects remain in family custody and are re-bound by their exact hash.

Assembled Pages client tests cover amd64/x86_64 APT, DNF and pacman, including package, index, signature and wrong-key rejection. The arm64 APT and aarch64 RPM family lanes qualify their own repositories; installation from the final assembled arm64 Pages repositories remains deferred. No assembled arm64 client result is claimed.

## Attended handoff

Use [the runbook](../operators/live1/RUNBOOK.md) after the dispatcher finishes review. The operator authenticates exact manager-reviewed inventory/tree/manifest, requires current remote main to equal the reviewed parent `2095e9d84295e09e4f1d4fc517fe0d5006478803`, stages only reviewed paths including deletions, commits with `--commit-message "Repair hosted command authentication and hermetic source contracts"`, and fast-forward pushes. It finds the new push run for that commit, refuses reruns/non-main runs, waits with a bound, and stores all jobs/steps, artifact identities, summary bytes and validation reasons before returning.

The collection step uses the v2 collector (`rs9.collect_candidate`), preserving packet artifacts and summary blockers before validation; legacy `validate_receipts` is not used. The operator stops on failure or timeout. The manager packet retains all summary-reported blockers even when validation stops at its first error; reported diagnostics confer no qualification authority. An explicit collect command can resume read-only collection into another empty outbox directory. No production publication, key access, npm/Homebrew mutation, Pages deployment or production receipt is performed.
