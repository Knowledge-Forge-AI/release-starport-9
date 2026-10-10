# CONT14 DNF contracts and noarch header repair candidate

## Status, scope and terminal disposition

Disposition: **amend** the dispatcher-bound producer candidate, tree
`abc671d3b565feb472605008813a350e62f6412b`, after its independent pre-final
review. The terminal corrections below remain within the authorized DNF state,
trust and noarch repair scope. They receive task-scoped verification, without
another substantive review. The dispatcher owns Git finalization; external
manager acceptance must bind the amended terminal tree and manifest before the
attended run-13 handoff can execute.

Run 12, Actions run `37863203077`, attempt 1, remains **NOT QUALIFIED /
HOSTED_GATES**. Its source is `980d868445eca001c2aacc2d88d9f63a563307d5`, tree
`3fef7f9e5bfc6fad1bdd964c41f7f4b30f10e3ae`. It was not rerun. These identities
attribute historical evidence; the implementation uses live semantic checks.

The evidence kit became readable during implementation. Both supplied read-only
verification scripts passed. Their header replay confirms equal SRPM bytes for
Loom and Solar Sail, equal compressed binary payloads, and binary main-header
delta `[1122]` only. Replay neither installs a package nor proves native success.
The retained checksum sample abbreviates the calculated digest; signature and
wrong-key refresh messages were not retained. This candidate does not invent
those missing run-12 messages or an effective run-12 skip configuration.

## Advisory findings and amendments

### Independent pre-final findings: terminal disposition

- **F1, amended:** parse the actual DNF5 5.2.18.0 main/repository banners from
  [the versioned source](https://github.com/rpm-software-management/dnf5/blob/5.2.18.0/dnf5/main.cpp).
  Bare options retain an unreadable value, distinct from an empty string;
  unreadable required values, duplicate sections/options and unsupported banners
  fail closed. Receipt fixtures use the source grammar, including disabled repos
  and optional unreadable values. This is source-contract evidence, not a native
  client observation.
- **F2, amended:** the rendered Pages `rpm/rs9.repo` explicitly sets
  `skip_if_unavailable=False`, retaining both GPG checks. Its production renderer
  is covered directly, alongside strict hosted-client invocation tests.
- **F3, amended:** recognize only the exact `Bad PGP signature: <diagnostic>`
  suffix form at the repomd boundary, with full-stream environmental vetoes
  preserved. Remove the unsupported `Public key is not installed` token. Bare
  signature strings and misleading network/permission/configuration failures
  still confer no trust credit.
- **F4, amended:** retain `SIGNATURE_REJECTED` as the observed boundary category,
  while qualifying a provenance-verified index mutation as `INDEX_CORRUPT`.
  This category derives from exact mutation custody plus rejection, not an
  invented client message. Missing index provenance fails.
- **F5, amended:** wrong-key mutation verification uses the isolated fixture's
  pinned verifier to establish a valid replacement signature under a different
  public issuer. Qualification binds the original key to the positive-control
  identity and requires that issuer proof. Same-key, absent verifier, invalid
  signature and inconsistent issuer controls fail. Local doubles exercise the
  contract; real fixture cryptography and DNF rejection remain hosted evidence.
- **F6, deferred native evidence:** retain the noarch spec-local control and
  mandatory finished-header readback. The parse/reparse model remains synthetic;
  native RPM 6.0.2 is unavailable here. Neither that model nor source tracing
  establishes cross-architecture final RPM equality.

### Producer-stage amendments retained

1. Accept index provenance: verify that only `repomd.xml` changes, retaining
   signature and all other member identities. Index and bad-signature negatives
   both reach the repomd signature boundary; their distinct mutation records
   identify the cause. Wrong-key remains a separate category.
2. Amend removal: disable every repository explicitly on DNF removal. Strict
   synchronization applies to refresh/install; uninstall no longer loads the
   candidate repository. The package absence query remains mandatory.
3. Accept locale pinning: DNF client execution sets `LC_ALL=C` and `LANG=C`.
   Exact English RPM absence grammar is a native assumption to check in run 13.
   `DNF5_FORCE_COLUMNS=512` retains complete future checksum diagnostics.
4. Amend the gate contract: `rpm-noarch-header-readback` is required on both
   RPM lanes. Missing witnesses, missing readback and unbound identities fail.
   Its failure does not suppress otherwise available DNF evidence collection.
   The scoped workflow-graph regression allows this precise RPM-only addition;
   all other lane/job/gate contracts remain compared with the public parent.
5. Accept scope confinement: preserving tampered acceptance after a subsequent
   exception changes DNF only. APT and pacman qualification paths are preserved.
6. Accept comment hygiene: the new spec control adds no macro-bearing comment.
   Raw rpmlint findings and accepted preservation policy remain independent.
7. Amend probing: check candidate cache state before and after config-only
   probes. Dump main/repository configuration with strict candidate-only argv;
   avoid metadata-loading repo-list operations before the intended refresh.

The inventory worker supplied useful parser plumbing but initially selected
incorrect state roots. The parent rejected those roots and rebuilt the policy
and replay from the exact six observations. Noarch worker output was adopted
with header/type/binding and test amendments. The operator worker was adopted
with a scoped message and test cleanup. All three workers have proven terminal
cleanup. Internal results are not dispatcher review checkpoints.

## Inventory classification and readback

The DNF-only policy classifies regular files strictly below
`usr/lib/sysimage/libdnf5` and `usr/lib/sysimage/rpm` as package-manager state.
Patterns use exact component boundaries and `\Z`. They reject traversal,
backslash variants, empty components and newline lookalikes without normalizing
input. Root directory entries, symlinks, special files and nearby unrelated
files remain visible. Existing byte-lossless transport, validation, modes,
collision checks, bounds and no-follow scanning remain in force.

The labeled synthetic replay changes exactly these six files:

```text
usr/lib/sysimage/libdnf5/system.toml
usr/lib/sysimage/libdnf5/transaction_history.sqlite
usr/lib/sysimage/libdnf5/transaction_history.sqlite-shm
usr/lib/sysimage/libdnf5/transaction_history.sqlite-wal
usr/lib/sysimage/rpm/rpmdb.sqlite
usr/lib/sysimage/rpm/rpmdb.sqlite-shm
```

The previous policy detects six modified, zero added and zero removed paths;
the new policy detects zero differences. Real temporary-tree controls retain
unrelated payload leftovers, state symlinks and directory mode changes. Tests
also cover legacy state paths, foreign families and package-policy rejection of
payload members beneath state roots. No rpmdb/history bytes are reset or copied
back. Each client records classification roots, pattern digest and pre/post
excluded-file counters. Uninstall, inventory cleanliness and container cleanup
remain separate receipts. Historical rows are unchanged.

## Strict DNF synchronization and causal negatives

The sole enabled candidate repository explicitly sets
`skip_if_unavailable=False`, `gpgcheck=1` and `repo_gpgcheck=1` in configuration
and authoritative CLI overrides, including Pages consumers. DNF5 documents
distribution overrides of the skip option and command-line
[configuration precedence](https://dnf5.readthedocs.io/en/latest/dnf5.8.html).
Run-12 silent disabling is a supported hypothesis, not a measured setting.

The prepared client supplies bounded tool-version and configuration receipts,
key-file digest, public fixture fingerprint, repository ID/local URI, client
image identity and platform. Probes require the strict effective options,
running-container immutable image readback (including Pages' mutable tag),
candidate-only enabled repository set and empty candidate cache before/after.
Positive controls bind that normalized identity. Unsupported, oversized,
non-UTF-8 or ambiguous probes confer no qualification. A synthetic unexecuted
command seam is explicitly unavailable.

Package mutation qualifies only at failed install with the complete
[librepo checksum diagnostic](https://github.com/rpm-software-management/librepo/blob/master/librepo/downloader.c),
candidate context, verified original/tampered digests and proven absence.
The full suffix is a primary-source contract for future receipts; it is not
attributed to the abbreviated run-12 sample. Metadata, signature and wrong-key
negatives require failed strict refresh at the intended authentication boundary,
failed install and exact absence. A successful refresh is a bypass failure.
Any accepted tampered install/query fails even without a positive control.

DNF-only classification preserves causal repomd errors ahead of downstream
package-not-found, after full-stream network/permission/configuration vetoes.
Bare signature/checksum text earns no credit. Bad signature, missing/wrong key,
corrupted index, unavailable source, missing package and permission/configuration
failures remain distinct. Index corruption is authenticated through its
unchanged detached signature, with mutation provenance recording the boundary.

The bad-signature mutation changes the final decoded signature-packet byte,
preserving armor layout and recomputing CRC24. All four mutations verify exact
file/mode custody. Every DNF stage retains bounded sanitized stdout/stderr
samples, original stream hashes/sizes, execution and truncation indicators.
Decisions consume full bounded CommandReceipt bytes, including output beyond
preview limits. Mutation bytes, private keys and private paths are withheld.

Parent integration additionally binds actual running-container image readback
for Pages, where the caller uses a mutable tag. A regression changes the image
behind the same tag and rejects the mismatched positive control. Full discovery
was repeated after this source amendment; earlier successful discovery remains
recorded as intermediate evidence.

## Noarch finalization context and finished bytes

RPM 6.0.2's [spec parser](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/build/parseSpec.cc)
recursively parses after BuildArch selection (lines 1161–1190), then finalizes
the returned spec (1341–1347). Finalization expands `optflags` and writes tag
1122 (1272–1304). Its
[target configuration](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/lib/rpmrc.cc)
replaces architecture-specific optflags during target setup (1493–1506,
1567–1590). These are source observations; the precise hosted overwrite was
not instrumented, and the rpmbuild outer target loop was not independently
traced in this stage.

Only pure-JS noarch Loom/Sail specs define `%global optflags %{nil}` in the
spec prelude, so the definition is evaluated during each parse. Existing CLI
controls remain, labeled `rpm-cli-context`. Synthetic parse/reparse tests
model configuration replacement and restart; native Burst/Nebular render
golden digests remain unchanged. No built RPM header is rewritten.

Read-only finished binary/SRPM parsing requires the intended architecture,
authenticated epoch, declared buildhost and strictly absent or empty OPTFLAGS.
Wrong types, whitespace flags and malformed headers fail. Records retain
buildtime/buildhost and cookie/OPTFLAGS/platform/SOURCEPKGID tag digests,
compressed payload hashes and package/SRPM/spec/closure identities. The mandatory
lane gate binds both Loom/Sail readbacks to their construction witnesses.
Authenticated source timestamps/modes, buildhost declaration, `-ba`, closure,
source identity and payload preservation are retained.

Pages still rejects any same-name noarch whole-byte conflict. Equal payloads
are diagnostic only. SRPM equality, payload equality and complete binary
equality remain separate checks; real x86_64/aarch64 convergence is hosted-only.

## Verification and unresolved native evidence

[CONT14 verification](../evidence/live1/cont14-verification.json) records focused
regressions, full discovery under umasks 022/077 with ResourceWarning as error,
exact run/pass/test-skip/class-skip/failure/error counts, original failure-log
digests and immutable source/test/log identities. Checks include Python
parse/compile, relative Markdown links, credential/private-path scanning and
`git diff --check`. Receipt/model tests are synthetic; adoption and collector
backend integrations exercise real temporary Git/filesystem behavior. The kit
replays inspect original unsigned reference bytes. No provider Docker access
was acquired and no native DNF/RPM experiment was substituted.

Producer-stage discovery ran **1,642 tests under each umask**: 1,624 passed
test methods, 18 test skips, one class skip (19 skip events), zero failures and
zero errors. ResourceWarning was treated as an error. Focused regression runs
covered 333 tests before the image amendment and 180 afterward. Original Pages
custody replay rejects both run-12 noarch pairs despite equal compressed
payloads, with delta `[1122]` and unchanged reference bytes. All static checks
pass; the report preserves the initial discovery failures and their disposition.

After independent review and the terminal F1–F5 amendments, fresh focused
regressions ran **207 tests**: 201 passed, six test skips, zero failures/errors.
Terminal full discovery with the supplied run-12 references ran **1,646 tests
under each umask**: 1,628 passed test methods, 18 test skips, one class skip
(19 skip events), zero failures/errors,
with ResourceWarning as error. Source/test identities stayed unchanged during
both runs. New banner, causal-category and issuer controls are synthetic receipt
contracts. Existing real temporary Git/filesystem adoption and collector backend
integrations remain included. The closeout record separates these terminal
measurements from retained producer-stage evidence and preserves reproduction
and test-driver failure logs. No native DNF/RPM pass is inferred.

Run 12's APT 41 gates on each architecture, pacman 40, eight npm/Homebrew
observations/no-ops, wheels, Darwin Nix and authentication gains are preserved.
RPM repository creation/signature/ownership gains and all eight accepted
preservation policies remain intact; raw rpmlint remains FAIL, exit 64.
Loom/Sail source equality and binary payload equality remain distinct gains.
Release generation remains Burst 0.6.1, Loom 0.4.0, Solar Sail 0.2.1 and Nebular
0.6.1; infrastructure licensing does not replace tenant licenses.

Fresh native DNF identity grammar, exact absence grammar, complete checksum
output, strict signature/wrong-key rejection and final noarch equality remain
unavailable here. Required Linux Nix lanes, no-userns, diagnostic PRoot, Pages
TLS and wheel limitations retain their separate status. Production signing,
registry mutation, deployment, upstream rebuild/retag and readiness flips
remain outside this candidate.

## Attended run-13 handoff

The [exact candidate manifest](../operators/live1/candidate-manifest.json) binds
all changed product paths and bytes. Source-adoption/readiness, production and
publication flags remain false. Independent pre-final review covered the bound
producer candidate against the historical parent; the terminal findings
disposition above identifies subsequent source amendments and their evidence.
External manager acceptance must cover the amended terminal binding. No further
substantive review was requested in closeout.

An external manager supplies an attestation matching the closed
`rs9.manager-source-adoption-attestation.v1alpha1` schema: decision `accept`,
scope `partial-diagnostic`, exact `reviewed_parent`, `reviewed_tree` and
`manifest_sha256`, with qualification/production/publication false. The attended
attestation digest is a byte binding, not an independent identity signature.
The operator validates it before invoking the shared adoption backend.

Create one existing empty physical packet directory. Set the following variables
from the manager-accepted terminal binding and external attestation. Logs,
metadata and result ZIP are siblings outside the packet directory.

```sh
rtk proxy env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 operators/live1/run-hosted13.py \
  --reviewed-parent "$RS9_ACCEPTED_PARENT" \
  --reviewed-tree "$RS9_ACCEPTED_TREE" \
  --manifest-sha256 "$RS9_ACCEPTED_MANIFEST_SHA256" \
  --manager-attestation "$RS9_MANAGER_ATTESTATION" \
  --manager-attestation-sha256 "$RS9_MANAGER_ATTESTATION_SHA256" \
  --output "$RS9_EMPTY_PACKET_DIRECTORY"
```

The backend preserves ignored scratch/operational caches and the initial index,
stages only reviewed changes, makes one normal commit and fast-forward push,
waits for a fresh push-triggered workflow of that new commit, collects every
job/step/artifact/summary, and stops. It rejects stale runs. If collection is
interrupted, use a new empty physical packet directory and the same reviewed
binding/attestation, adding `--collect-only --commit "$RS9_RUN13_COMMIT"
--run-id "$RS9_RUN13_RUN_ID" --not-before "$RS9_ORIGINAL_NOT_BEFORE"`. Preserve
the original timestamp; resume performs read-only collection without a rerun.

Run 13 must compare both lanes' SRPM/spec/closure digests, finished headers,
compressed payloads and complete noarch bytes; inspect DNF effective identities,
all four causal negatives per architecture and inventory policy/counters.
The operator was prepared and tested, not executed. This handoff authorizes no
production receipt, deployment, registry write or automatic rerun.
