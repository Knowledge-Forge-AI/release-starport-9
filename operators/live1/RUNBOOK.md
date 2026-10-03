# Attended Theme Forge LIVE1 preparation and future publication contract

Status: **not ready for production publication**. `rs9.operator` supports status
and fresh release authentication only. `publish-pages` and `publish-pypi` stop with
PUBLICATION_NOT_READY. Manual environment setup cannot complete the missing package,
qualification, reader and transport implementations.

The latest [real-candidate continuation](../../docs/live1-real-candidate-continuation.md)
is also **not ready for source adoption**. The candidate manifest refuses adoption
while real artifacts/platform qualification are missing. The separate attended
adopt-and-qualify.py operator accepts a reviewed parent/tree/manifest digest and an
empty external output directory; it has no production publication path. Do not run
it against this blocked candidate. Complete qualification and obtain manager review
before changing candidate_adoption_ready. Future hosted receipt hashes must be matched
by an attended rebuild or exact bytes held in reviewed durable custody before production.

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
checkout; ignored interpreter files are also refused.
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
