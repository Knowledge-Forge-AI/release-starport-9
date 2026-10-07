# Attended Theme Forge LIVE1 preparation and future publication contract

Status: **CONT8R2 partial diagnostic source candidate; native run 7 pending; production disabled**.

CONT8R1 is retained partial work, including all 35 inherited paths and twelve
terminal corrections. Its terminal tree was not independently rereviewed.
CONT8R2 prepares a separate reviewed source handoff for non-production B–E
native diagnostics and a pinned candidate-only PRoot experiment. The existing
required Linux Nix lanes remain authoritative for the full verdict. Their failure
means not-qualified; absent or failed evidence is never an allowed-pass alias.
The dispatcher owns both review checkpoints and finalization. Source providers
never stage, commit, push, run hosted Actions, or select a reviewer.

See [scoped source evidence](../../evidence/live1/cont8r2-scoped-qualification-verification.json)
and the [Linux runtime ADR](../../docs/adr/0008-nix-linux-runtime-without-user-namespaces.md).
The [inherited evidence](../../evidence/live1/cont8r1-evidence-led-repair-verification.json)
is historical repair input, not hosted run-7 evidence.

`rs9.operator` publication commands remain disabled. Burst is architecture-specific in wheels, pacman, RPM and APT; its complete foreign prebuild inventory is retained. Installed released-loader proofs are required in every Burst runtime lane. Production Linux wheel compatibility remains unproved. No product is omitted to obtain a qualified verdict.

## Environment and qualification realities

- **Local environment**: The local execution environment is Darwin with Python 3.13; no
  Python 3.12 or GnuPG usable was observed locally. Minimal scratch symlink PATH reruns serve
  strictly as tool-isolation checks, not Ubuntu equivalence.
- **Stock Ubuntu 24.04 environment**: A stock ubuntu-24.04 source unit assumes Python 3.12,
  Node 22, and GnuPG are present, and the unit suite must work without Docker, Nix, Arch/RPM builders, or zstd.
  Real hosted package lanes remain mandatory integration.
- **Verification**: Source checks and scoped skips are recorded in the repair verification evidence.
- **Corroboration states**: npm comparison records `blocked` when an unrelated profile failure prevents comparison, and preserves `pass` when a later failure follows completed npm checks. Overall authentication still requires every selected profile to pass. Any closeout amendment requires manager disposition of the exact terminal delta.
- **Registry availability**: Hosted run 3 passed exact version `0.6.1` packument/tarball transport. Fresh authentication must retain any new `NPM_IDENTITY` or HTTP failure as evidence; never substitute `latest`, another version or registry, or retry failed hosted jobs automatically.

## Partial diagnostic adoption and attended run 7

The manifest and operator readiness share a closed `readiness` block:
`source_adoption_scope=partial-diagnostic`, known unqualified Linux Nix A lanes,
`full_live1_qualification=false`, `published_linux_nix_ready=false`,
`production_enabled=false`, and `publication_authority=false`. The source
adoption Boolean means eligibility for one attended diagnostic adoption after
source checks, exact independent review and manager disposition. It does not
approve packages or publication. A's unresolved runtime no longer withholds
B–E native collection. This candidate keeps both source readiness Booleans false.
The manager can authorize the exact terminal source through an external
attestation without flipping either Boolean or changing any manifest row.
This is a source review condition; A remains a required qualification gate.

The dispatcher review covers its bound pre-closeout candidate. Terminal
amendments are listed in the source verification record and have scoped tests;
they have no subsequent independent review. The manager must disposition that
exact delta and the terminal tree/digest before issuing the attestation. The
provider does not create acceptance evidence or authorize adoption.

The manager writes a physical JSON file outside the checkout, at most 16 KiB,
with exactly these fields and the accepted terminal bindings:

~~~json
{
  "schema": "rs9.manager-source-adoption-attestation.v1alpha1",
  "decision": "accept",
  "source_adoption_scope": "partial-diagnostic",
  "reviewed_parent": "<accepted parent commit>",
  "reviewed_tree": "<accepted cumulative terminal tree>",
  "manifest_sha256": "<accepted terminal manifest digest>",
  "full_live1_qualification": false,
  "production_enabled": false,
  "publication_authority": false
}
~~~

Supply its SHA-256 as a separate attended input. This digest binds bytes; it is
not a signature or proof of the manager's identity. Missing, duplicate, extra,
changed, symlinked, in-checkout or publication-authorizing records fail before
Git actions. The wrapper and shared adopter check the record, and the adopter
checks it again immediately before staging. Readiness metadata remains unchanged.

The [operator](run-hosted7.py) was prepared, not executed. After exact manager
acceptance, supply the reviewed parent, cumulative terminal tree, manifest digest
and a new empty physical result directory:

~~~sh
rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 operators/live1/run-hosted7.py \
  --reviewed-parent "$RS9_ACCEPTED_PARENT" \
  --reviewed-tree "$RS9_ACCEPTED_TREE" \
  --manifest-sha256 "$RS9_ACCEPTED_MANIFEST_SHA256" \
  --manager-attestation "$RS9_MANAGER_ATTESTATION" \
  --manager-attestation-sha256 "$RS9_MANAGER_ATTESTATION_SHA256" \
  --output "$RS9_RUN7_PACKET_DIR"
~~~

The operator checks main, current remote parent, clean index, complete inventory
and cumulative `changed_paths`. It stages exactly that set, rechecks the resulting
tree and normal commit parent, makes one fast-forward push, and collects a NEW
run for that commit with `event=push` and attempt 1. It stops after collecting
terminal jobs, artifacts and summary. No automatic retry/rerun, dispatch,
publication, Pages deployment, production signing, registry or tap writes occur.
Its exclusive combined log stays in a file; output is `LOG=`, `RC=` and
`MANAGER_PACKET=`. RC=2 is not a pass; inspect the packet classification and
per-lane evidence.

Native package/observe jobs retain their independent authenticated-input graph.
The separate `nix-proot` job has declared experiment artifacts and no authority
over the original required gates. It does not cancel B–E or join summary's needs.
An experiment artifact is optional only for a skipped experiment job and must
be custody/provenance verified when present. A failed experiment leaves its own
fail/not-run receipt; no execution step uses continue-on-error to produce green.
A passing experiment cannot qualify the unchanged buildFHSEnv recipe.

`diagnostic_scope` is saved before qualification errors. Source-bound summary
receipts and individually authenticated artifacts retain pass/fail/missing states
for every required lane, even if another artifact cannot be collected. The packet
classifies A-only failure, A plus other gate failures, B–E failure, collection
failure and timeout distinctly. Full qualification still requires every original
required job, step and gate plus exact artifact custody. Experimental job failure
is recorded separately from that verdict; workflow failure remains observable.
RPM 6 signed-query transcripts, native APT/DNF/Arch inventory baselines and full
install/probe/remove cleanliness, and all application runtime results are owed
to run 7. Source unit tests are not those native results.

## Collection recovery and retained historical operators

The historical `run-hosted5.py` and `run-hosted6.py` remain for audit only.
Do not invoke them.
The run-6 wrapper supplies its source `PYTHONPATH` and disables child bytecode writes.
It preserves existing logs and never advertises a stale packet after preflight failure.
Collection defaults to two hours, with a six-hour maximum. Event, branch, attempt
and creation timestamp are checked; at most 60 seconds of clock skew is allowed
and recorded. No rerun or dispatch endpoint is invoked.

The v2 collector retains every job and step, streams every artifact with byte/time bounds, verifies each outer digest, extracts safely, and rehashes candidate custody manifests. One artifact failure does not suppress attempts to collect the remaining artifacts. Extracted summaries are retained in full; the packet contains bounded identities, reported blockers and validation reasons. Production promotion blockers remain mandatory on Linux wheels but are separate from candidate qualification blockers.

If collection times out, resume **read-only collection** explicitly in a different empty outbox directory, using the original push boundary as `RS9_PUSH_BOUNDARY` (ISO8601Z):

~~~sh
rtk proxy env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 operators/live1/adopt-and-qualify.py collect \
  --commit "$RS9_ADOPTED_COMMIT" --run-id "$RS9_RUN_ID" --not-before "$RS9_PUSH_BOUNDARY" \
  --output "$RS9_PACKET_DIR" > "$RS9_PACKET_DIR.operator.log" 2>&1
RS9_OPERATOR_STATUS=$?
rtk proxy printf 'LOG=%s\nRC=%s\nMANAGER_PACKET=%s\n' "$RS9_PACKET_DIR.operator.log" "$RS9_OPERATOR_STATUS" "$RS9_PACKET_DIR/manager-packet.json"
~~~

Neither operator publishes, deploys, production-signs, mutates npm/Homebrew or emits production receipts. The released Theme Forge generation is unchanged. Preparation source pins have no floating fallback. Linux wheel compatibility remains an explicit production promotion limit. The manifest binds its public parent and mechanically checks the complete cumulative changed-path set before staging exactly that reviewed set.

The signing-preflight.py operator takes an independently reviewed public-export
SHA-256. It inspects existing local-key availability and public bytes only; it never
exports secrets, signs or handles a passphrase. It was not run by this provider.
The pinned digest is specifically the SHA-256 of the binary stdout from
`gpg --batch --export 7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF` with no export
options. Local UID/certification changes may change these public export bytes
without changing the fingerprints. Capture and review the digest using the same
public keyring/export command; a mismatch must stop preflight. Do not silently
refresh the approved digest or reinterpret it as an export-minimal digest.

## Review-bound preparation

The dispatcher owns candidate adoption and Git publication. After independent
review/adoption, use the resulting reviewed commit/tree; do not substitute hashes
from historical task prose. The operator requires main, those exact identities,
no tracked changes and no unreviewed untracked or ignored files except preserved
`.serena/`. Use the documented bytecode-disabled environment in a dedicated reviewed
checkout; This older authentication operator retains its own stricter checkout rules.
It never updates product source or publication documentation.

From the reviewed repository, inspect status:

```sh
rtk proxy env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m rs9.operator status
```

Prepare an empty caller-owned physical evidence directory outside the repository,
through the configured scratch workflow. Independently compare the approved raw
bootstrap SHA-256 with the inventory. Then run fresh authentication on an attended
host with public GitHub binary-download access:

```sh
rtk proxy env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m rs9.operator authenticate \
  --reviewed-commit "$RS9_REVIEWED_COMMIT" \
  --reviewed-tree "$RS9_REVIEWED_TREE" \
  --approved-bootstrap-sha256 "$RS9_APPROVED_BOOTSTRAP_SHA256" \
  --evidence "$RS9_EVIDENCE_DIR"
```

Authenticate each release/tag/source blob, checksums, provenance and selected asset
bytes. Compare all four captures against expectations. Any mismatch stops the
generation. A failed capture leaves evidence for diagnosis; use a new empty evidence
root after resolving the failure. Never weaken bounds or modify an upstream release
to force a match. Successful authentication does not authorize publication.

Complete the [remaining implementation/qualification](../../docs/live1-candidate.md)
before considering the production packets below ready. Qualify branch/PR code with
Nix outputs unexposed; bind builder files, artifacts, drvPaths, verifier source and
environment, not the entire checkout tree. After evidence is reviewed, expose Nix
outputs in a separate reviewed change and obtain Git/raw/evaluation readback.
APT recipe generation currently stops with APT_RECIPE_UNQUALIFIED. Complete the
Ubuntu 26.04 build runner and dependency derivation before that lane can proceed.

## Exact manager setup packets, pending independent readiness

1. In the RS9 GitHub repository, configure protected environments `pypi`,
   `rs9-production-signing` and `github-pages`, required manager approval and main
   deployment restriction. A future production workflow must be reviewed/pinned,
   narrowly permissioned and bound to the approved candidate inventory.
2. Audit custody of the **existing** primary fingerprint
   `7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF` and signing subkey
   `C021E00EE3D37C459B0E1CB3199F8028126E8A8C`. Compare public-key metadata only.
   Do not create a new production key. Prefer attended local gpg-agent custody when
   available; otherwise the manager may provision existing material from its secret
   store into a protected signing environment after an explicit custody decision.
   No key export, secret provisioning, passphrase command or credential value belongs
   in this packet. Pin an independently captured public key and verify every issuer.
3. In GitHub Settings / Pages, select GitHub Actions as source, set custom domain
   `rs9.knowledge-forge.ai`, verify DNS and certificate issuance and enforce HTTPS.
   Independently check canonical TLS and path/query behavior. Verify the operator-owned
   `packages.knowledge-forge.ai` redirect read-only; contact its operator if wrong.
   Current readiness is unknown. Stop hosted lanes until exact checks pass.
4. Observe each preferred PyPI name immediately before setup. Absence does not
   establish ownership. For each authorized name, create a PyPI pending publisher
   with owner `Knowledge-Forge-AI`, repository `release-starport-9`, workflow filename
   `rs9-pypi-publish.yml`, environment `pypi`. Record manager ownership/setup
   attestations without credentials. No production PyPI workflow currently exists;
   install it only after independent readiness review. Pending publishers do not
   reserve names. Use OIDC Trusted Publishing; no token is required by this design.

## Required future live operator behavior

The completed operator must authenticate current releases again; compare reviewed
unsigned package bytes; run independently approved per-platform build/install/run/
uninstall/verifier/signature/tamper gates; observe every pair; and record actual
Foundation 3 plans. It must require the reviewed source commit/tree at execution,
never consume serialized publish-intent as authority, and stop on conflict,
incomplete/unknown state except a separately bound safe-repair contract.

Protected approval happens **before** destination re-observation, planning and
freshness/precondition checking in the same mutation job. Bind all attempts to that
fresh plan. PyPI resulting serials must be corroborated by JSON/file readback;
where no resulting serial is available, document timestamp fallback. Pages normally
requires fresh exact signed-object readback after the attempt with timestamp
fallback; a deployment success status does not prove package publication.

Use deliberate order: retained signed package objects first; deterministic indexes
from exactly those objects; index signatures retained once; whole public tree scan
and clean signature verification; then atomic Pages deployment/readback. Build
pacman and RPM metadata with native repo-add/createrepo_c in pinned environments.
Do not re-sign exact objects on restart. RPM signing changes container bytes:
verify unchanged release payload and bind both unsigned and final signed hashes.
Keep per-Fedora-family dependency qualification separate when requirements differ.

Before a full-site deploy, carry forward every exact live signed object, including
pool/by-hash objects required by current clients. Retain signed manifests/objects
and previous deployment snapshots in durable protected storage, independently of
short-lived Actions/Pages artifact retention. The candidate SignedStore supplies
local storage mechanics; production retention/transport is still unimplemented.

Select a distinct reviewed snapshot identifier with `SignedStore(root,
generation=snapshot_id)`. Its immutable manifest is stored under
`generations/<snapshot_id>/manifest.json`; content-addressed objects remain shared.
Use `for_generation(previous_snapshot_id)` to retrieve a previous exact tree and
explicitly carry required objects into the new snapshot. Different generations may
retain different InRelease or repository DB signatures at the same public path;
the same generation cannot overwrite them. Production defaults pin the established
primary fingerprint and verified signing subkey when supplied. Synthetic trust
configuration is fixture evidence only. Reopening a store rechecks retained issuer
and trust binding; no real GPG verifier or production custody is supplied here.

The candidate APT layout uses `dists/resolute/` for Ubuntu 26.04, matching the
[Ubuntu release identity](https://releases.ubuntu.com/26.04/). Its structural validator
does not authenticate signatures. The deterministic fixture Date is not a live
freshness policy; publication must bind a reviewed generation timestamp and qualify
client freshness and signature behavior before enabling the lane.

Publish PyPI last, one product at a time, after current name/version observation and
all required wheel gates. Emit no misleading native sdist. Each upload is followed
by exact JSON plus every file's downloaded hash/semantic provenance readback.
Partial uploads are incomplete, not successful; repair requires an explicit
reviewed contract limited to missing files. Never overwrite immutable artifacts.

Rerun every destination reader and planner after publication: exact must become
noop. Observe-only npm/Homebrew never receive a transport. Their identity contract
must include authoritative version, commands, payload and licensing. The Nebular
npm metadata conflict must be recorded as block-conflict without blocking unrelated
downstream lanes. This candidate has no real replay/noop evidence.

## Rollback and documentation

Retain exact signed previous public trees before mutation. Restore their objects and
indexes atomically while preserving existing trust and client-required by-hash/pool
objects. Remove a faulty repository from serving when safe restoration is unavailable.
PyPI rollback is an attended yank; an immutable version cannot be reused. Nix
rollback is a reviewed output revert. No rollback is executed in this stage.

Published receipts require exact readback. README/install pages remain pending until
a separately reviewed update binds manager-provided exact readback. Runtime
publication must never rewrite unreviewed product source. Keep legacy distribution,
private evidence, npm and Homebrew unchanged until LIVE1 acceptance.
