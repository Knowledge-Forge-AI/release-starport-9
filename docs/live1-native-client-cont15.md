# CONT15: DNF diagnostics and gzip RPM metadata

## Status and scope

Run 13 remains **NOT QUALIFIED / HOSTED_GATES**. CONT15 is a source repair
candidate for one attended nonproduction run 14. It does not adopt source,
trigger a workflow, publish, deploy, sign production objects or change releases.
All readiness, production and publication flags remain false.

The manager kit was read before implementation. Its offline verifier reproduces
167 selected records, 18 retained artifact manifests, 143 included objects,
16 receipt hashes, eight accepted preservation policies and 80 reconstructing
chunks. Reference RPMs, old receipts and private logs stay outside product custody.
The four retained binary/SRPM noarch pairs remain whole-byte equal across both
architectures; no source timestamp, macro, OPTFLAGS or finished header is repaired
again. Raw rpmlint remains failed, exit 64.

## Bound proposal disposition

**Disposition: amend.** The original task scope remains the three authorized
repairs plus source verification and the attended handoff. The bound proposal
is identified separately by schema `agent-phase-plan-material-v1`, size 18,125
bytes and SHA-256
`9a53e5df75ec70cd304f5eaf48131b40a6c2c1bbdd1bda9d2e361e215624a056`.
No stage deltas were recorded at entry. Internal workers supply implementation
evidence; the dispatcher owns both independent review checkpoints.

The proposal's inaccessible-kit premise is superseded by the actual successful
manager/evidence read. Versioned width/rendering facts use the manager's exact
DNF5 source observations and blob identities: `2198a23b6474e531e34d69a5deeab82f0f6f49c6`
and `dda913ec5ea871ba826a33139439e508a35cba76`. Re-fetching those two pages
was unavailable in this session. DNF5 5.2.18.0 key-import grammar was independently
read in its [context source](https://github.com/rpm-software-management/dnf5/blob/5.2.18.0/dnf5/context.cpp).
Core-inclusive gzip semantics were read in the
[upstream argument parser](https://github.com/rpm-software-management/createrepo_c/blob/master/src/cmd_parser.c)
and [maintained manual](https://man.archlinux.org/man/extra/createrepo_c/createrepo_c.8.en).
The kit does not retain a measured createrepo version; none is invented.

| Plan-review finding | Disposition |
| --- | --- |
| Direct builder uses architecture directories | Amend: explicit expected relative package inventory per call site. |
| Preserve actual wrong-key successes | Amend: both run-13 wrong-key display streams are required replay cases. |
| Fatal summaries embed a progress reason | Amend: assign line roles and compare the summary reason once. |
| Exact failed package path | Amend: require the exact failed download location and bind it to the sole candidate source; basename alone earns no credit. |
| Environment readback does not prove rendering | Accept: native complete run-14 output is still required. |
| Signature mutation proof was underchecked | Amend: require the repomd boundary, armor framing and changed packet offset/length. |
| Resolved createrepo executable | Amend: shared argv accepts the resolved binary; finished output still must verify. |
| Real metadata coverage skipped by default | Amend: execute the external run-13 references in producer verification and disclose the default skip. |
| Parser locale binding | Amend: require exact presentation/locale and matching command identity. |

## DNF evidence contracts

The guest command uses `FORCE_COLUMNS=512`, `LC_ALL=C`, `LANG=C`, supported
`DNF5_FORCE_INTERACTIVE=0`, assumeyes and disabled color. The version is measured
and must remain DNF5 5.2.18.0. Positive and negative controls bind presentation,
strict configuration, sole enabled repository, public key, image and command
identity. APT and pacman retain their existing command/setup contracts.

512 columns is a bounded setting, not proof that arbitrary messages cannot be
clipped. Qualification consumes the same executed install's full bounded
streams. It requires complete calculated and expected SHA-256 values matching
the retained tampered/control objects, the exact package location, failed
install, successful untampered refresh, candidate absence and matching positive
control. Missing/ambiguous hashes, unknown algorithms and environmental failures
remain blocking. Both historical short run-13 display samples remain unqualified.

Repository failure parsing distinguishes initial expected-key import from the
terminal fatal signature cause. It preserves intermediate KEY_MISMATCH evidence
and checks the fatal repository/base URI and imported fixture key. Second or
unexpected repositories/keys, contradictory summaries, incomplete records and
environmental failures remain blocking across complete streams, including beyond
64 KiB. Index, signature and wrong-key mutation proofs remain distinct.

Run-13 display fixtures are explicitly sanitized samples. Controlled URI
substitutions support parser tests; their bytes are never represented as original
command-stream hashes or new native qualification.

## Metadata and Pages contracts

Every candidate createrepo path uses the shared core-inclusive
`--general-compress-type gz`, `--no-database` and SHA-256 options. Finished
repomd references, the physical object set, gzip magic, compressed/open sizes
and hashes, bounded decompression and package/content linkage verify before
metadata signing or readiness claims. The direct builder's architecture-relative
locations and native/Pages `Packages/` locations use explicit inventory binding.
The direct builder retains the resolved `createrepo_c` executable. An installation
exposing only the legacy `createrepo` name is an unavailable prerequisite; an
ambiguous version string does not establish the supported compression option.

No zstd suffix exemption, recompression, metadata omission or payload/header
rewrite is introduced. The actual retained run-13 metadata demonstrates a
generator/scanner format mismatch independently of the unknown historical first
Pages rejection path. That original path remains unknown.

Pages rejects disallowed paths with the original error code, causal substage and
a bounded safe public relative path or SHA-256 token. Completed custody equality,
APT staging, per-architecture RPM metadata, pacman metadata, inventory and assembly
remain recorded when a later stage fails. Package privacy scans, public modes,
unsigned/signed custody and assembled client gates retain their separate status.

## Verification and limitations

The [CONT15 verification record](../evidence/live1/cont15-verification.json)
records producer-stage tests, source identities, exact counts, skips and static
checks. Both ResourceWarning-as-error runs, under process-local umasks 022 and
077, discovered 1,708 methods, ran 1,698 and passed 1,678. Each recorded 20
method skips and one class skip covering ten methods, with zero failures,
errors or ResourceWarnings. The focused run passed 182 of 186 with four skips;
the explicit external run-13 metadata regression passed without skips. Its
default skip remains visible in ordinary discovery. Final review and verification
belong to dispatcher closeout. Native
DNF5/RPM/createrepo and hosted clients are not substituted with receipt doubles.

Required Linux Nix/PRoot, Pages TLS, Darwin wheel offline isolation and Linux
wheel production compatibility remain separate limitations. Run-13 APT 41/41
per architecture, pacman 40/40, ordinary DNF clients, both wrong-key negatives,
noarch byte equality, preservation acceptance, wheel/config/authenticate/pins
and Darwin Nix successes remain historical evidence, not newly executed results.

## Attended run-14 handoff

The [cumulative candidate manifest](../operators/live1/candidate-manifest.json)
binds product bytes and changed paths. The
[run-14 operator](../operators/live1/run-hosted14.py) requires an externally
attested accepted tree/manifest with parent
`80b42ab10ece5f333b7c57dc3a43ebc4a631eaa7`, partial-diagnostic scope and false
qualification/production/publication flags. That parent is the intended next
handoff baseline, not an additional source-stage hash gate.

After dispatcher closeout and manager acceptance, the repository operator creates
one existing empty physical packet directory. Logs, operator metadata and upload
ZIP stay outside it. Redirect wrapper output to a file; its only terminal fields
are `LOG`, `RC`, `MANAGER_PACKET`, `UPLOAD`.

```sh
rtk proxy env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 operators/live1/run-hosted14.py \
  --reviewed-parent "$RS9_ACCEPTED_PARENT" \
  --reviewed-tree "$RS9_ACCEPTED_TREE" \
  --manifest-sha256 "$RS9_ACCEPTED_MANIFEST_SHA256" \
  --manager-attestation "$RS9_MANAGER_ATTESTATION" \
  --manager-attestation-sha256 "$RS9_MANAGER_ATTESTATION_SHA256" \
  --output "$RS9_EMPTY_PACKET_DIRECTORY" > "$RS9_WRAPPER_OUTPUT" 2>&1
```

The backend makes one normal commit/fast-forward push and collects the new
push-triggered run, all jobs/artifacts/summary. It preserves ignored scratch,
Serena and the real index. Collection continuation uses a new existing empty
packet directory, the accepted bindings, `--collect-only`, exact commit/run ID
and the **original** `--not-before` timestamp. It performs collection without
a workflow rerun. This dispatch does not invoke adoption or run 14.
