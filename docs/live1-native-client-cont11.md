# CONT11 hosted-run-9 APT and RPM source candidate

## Scope and proposal disposition

Disposition: **amend** the bound 17,725-byte proposal, SHA-256
`278b05a44c7f2ae0e527216122d4c1b94a46bfee0703ebd4541980b549a9b85c`.
The original task authorizes the controlled local APT invalid-envelope repair,
RPM metadata corrections, three narrowly proved payload-preservation classes,
an explicit future lint-gate migration, source tests and an attended run-10
handoff. Proposal text and advisory findings remain separate from that scope.
The dispatcher supplied the producer candidate and an advisory pre-final review.
Closeout amends that candidate for the accepted findings and verifies the terminal
bytes. No further substantive review is requested; terminal amendments do not
receive an automatic independent review.

The manager disposition and retained run-9 records are data. Run 9 remains
not-qualified (`HOSTED_GATES`) and is neither rerun nor relabeled. In particular,
Nebular's retained list contains only eight of fifteen errors. Its complete
group counts do not identify omitted paths and cannot authorize exceptions.
Original samples and diagnostic stream hashes remain historical evidence.

## APT qualification contract

The new invalid signed envelope category applies only to a controlled local
`file:` repository's `resolute InRelease` at the refresh stage. A bare `NODATA`,
HTTP response, captive portal, wrong source or stage, successful command, mixed
environment failure, or arbitrary nonzero exit earns no signature-negative
credit. Permission, DNS, network, missing tools, bad source configuration and
missing packages retain their failure categories.

Qualification also requires a matching executed positive control, successful
configuration, refresh rejection, failed installation and non-installation
query. The signature mutation must change exactly one armored signature byte
in each expected file, retain the same length, and leave the rest of the
repository byte-identical. Network-none configuration and an actual runtime
socket-denial probe are separate required facts. Future per-stream diagnostics
retain bounded sanitized line shapes and completeness information. A controlled
five-line refresh stdout reconstruction matches the retained digest on both
architectures, including the `[1041 B]` progress lines. Its classification is
tested with the retained stderr digest. The original raw stdout artifact is
absent, and this source reproduction does not establish native APT qualification.

## RPM raw result and preservation policy

RPM packaging changelog entries derive their UTC date from authenticated release
publication metadata, use the reviewed reserved packaging identity and exact
package version/revision, and describe RS9 repackaging. They do not invent
Theme Forge history or use implicit current time. The entry explicitly identifies
upstream publication as its date basis and contains no distribution macro.
Redundant named Nebular
library requirements may be removed only with generated SONAME/capability
coverage; runtime/interpreter requirements and normal dependency generation
remain enforced. Burst's exact foreign-prebuild exclusions are preserved.
The removed named requirements are exactly `dbus-libs`, `glib2`, `libgcc`,
`libstdc++` and `libsoup3`, when derived only from DT_NEEDED. Missing generated
capabilities still stop the builder before lint or repository indexing.

Complete errors take priority over bounded warning samples. The raw tool
result retains exit code, errors, warnings, existing filtered findings, effective
tool/configuration identity and stream digests. Unknown, malformed, incomplete,
count-mismatched or failed tool execution remains blocking. The three authorized
preservation classes require exact current project/version/platform and
authenticated input/member identities, bytes, modes, link types, shebangs,
invocation and interpreter proof. Duplicate waste requires complete group
membership and expected waste, including declared license copies.
Mixed-prefix duplicate groups retain all possible rpmlint representative totals;
the raw total must be possible for the exact preserved groups and equal the
policy's declared waste. A different legitimate total still requires manager
disposition. No arbitrary aggregate or sorted-member approximation qualifies.
The policy file participates in builder provenance, retained evaluations are
checked against its canonical digest, and declared wrappers and shebangs are
enforced. Malformed observation or serialization data produces a blocked result.

The future required gate is `rpm-lint-policy-accepted`. Historical
`rpm-rpmlint-clean` receipts receive no alias and cannot satisfy it. Builder,
hosted receipts, collector and summary retain separate raw and policy results.
Foundation3 inventories and adapters retain their independent verification and
publication boundaries. Pages custody remains unavailable when required RPM
candidates are blocked; no TLS workaround or deployment is authorized.
Policy exceptions retain the production promotion blocker
`rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified`.
Policy acceptance does not claim raw cleanliness or official Fedora admission.
The source policy leaves Nebular explicitly incomplete and blocking. A fresh run
must retain its complete error members and duplicate groups for manager
disposition; a warning sample or aggregate count cannot extend its exceptions.

The packaging references are the [RPM spec/changelog manual](https://rpm.org/docs/4.20.x/manual/spec.html),
[RPM dependency generators](https://rpm.org/docs/6.0.x/manual/dependency_generators.html),
[RPM 6 ELF attribute rules](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.0-release/fileattrs/elf.attr)
and [rpmlint 2.8 duplicate accounting](https://github.com/rpm-software-management/rpmlint/blob/2.8.0/rpmlint/checks/DuplicatesCheck.py).
Its [package reader](https://github.com/rpm-software-management/rpmlint/blob/2.8.0/rpmlint/pkg.py)
uses `FILERDEVS` and `FILEINODES` for hardlink accounting; inventory queries use
those same headers.
RPM 6's referenced ELF rules cover matching shared libraries regardless of
executable mode. Runtime capability readback remains mandatory; source inspection
alone does not establish a native package's generated dependencies.

## Verification and remaining authority

Observed source results and plan-review dispositions are in the
[verification record](../evidence/live1/cont11-hosted9-rpm-apt-verification.json).
Full discovery is required under process-local umasks 022 and 077 with
`PYTHONPATH=src`, bytecode disabled and ResourceWarning treated as an error.
Discovered, run, directly passed, individual skips and class-skipped cases are
reported separately. Native package tools and provider Docker execution are
unavailable here; controlled fixtures do not qualify signing, installation or
runtime behavior. The hosted run owns those claims.

The cumulative [candidate manifest](../operators/live1/candidate-manifest.json)
binds the entire phase delta relative to the committed parent. Real index,
ignored root scratch, Serena and unrelated work are preserved. Full readiness,
production and publication flags remain false. Required Linux Nix A failures,
experimental PRoot, unknown Pages TLS, absent PyPI publications and Darwin
wheel offline isolation not-run remain unchanged qualification boundaries.
Recorded green pacman, APT normal/control, wheel jobs, Darwin Nix, authentication,
pins and npm/Homebrew observations are preserved historical results.

## Attended hosted-run-10 handoff

The [run-10 operator](../operators/live1/run-hosted10.py) is prepared, not executed.
After manager acceptance, supply the exact parent, terminal tree and manifest
digest plus an external manager attestation for partial-diagnostic adoption.
Precreate the required existing empty physical packet directory in the
configured manager outbox; keep attestation, logs and upload outside it.

```sh
python3 operators/live1/run-hosted10.py \
  --reviewed-parent dbf94dd5e506987a9316baaef837a38dd88e1f48 \
  --reviewed-tree "$RS9_ACCEPTED_TREE" \
  --manifest-sha256 "$RS9_ACCEPTED_MANIFEST_SHA256" \
  --manager-attestation "$RS9_MANAGER_ATTESTATION" \
  --manager-attestation-sha256 "$RS9_MANAGER_ATTESTATION_SHA256" \
  --output "$RS9_EXISTING_EMPTY_PACKET"
```

The shared adoption implementation stages only reviewed product paths, makes
one normal commit and fast-forward push, and collects one new push event bound
to that commit and the original not-before timestamp. A bound collect-only
continuation preserves that timestamp and performs no adoption. No rerun API,
failed-job retry, production publication or new release is allowed. The wrapper
saves stdout/stderr to its external log and prints only bounded `LOG`, `RC`,
`MANAGER_PACKET` and `UPLOAD` paths. The package-free upload retains manager
summary, raw lint and policy diagnostics, both APT positive/negative receipt
sets and observations. Large packages retain separate custody. Stop for manager
disposition after collection.

## CONT11R1 machine-stream repair

CONT11 is retained as recovery input. CONT11R1 repairs complete-stream consumption
without altering release assets or the incomplete, blocking Nebular policy. The
controlled kit reproduction establishes the source defect; it is not native RPM
execution or evidence of actual release inventory sizes.

`CommandReceipt.stdout_text` and `stderr_text` remain 65,536-byte display previews.
Acceptance reads complete raw bytes, checks the protocol byte limit, then decodes
strictly. RPM dump and inode/flag streams use UTF-8 with a 16 MiB limit each, at
most 20,000 members, newline framing and exact set equality. The digest-algorithm
record has a 64-byte limit and must be exactly `8` followed by a newline. RPM
requires/provides use strictly decoded ASCII with a 1 MiB limit each; surrounding
spaces retain the prior trimming behavior, while empty records, controls and
unterminated streams fail. RPM signature readback uses a 4 KiB, single-record
limit. Rpmlint uses complete strict UTF-8 within its 512 KiB limit; warning sample
caps do not limit error accounting or acceptance input. APT envelope qualification
checks both full strict UTF-8 streams within the combined 1 MiB bound.
Rpmlint tool and installed-package identities use one strictly decoded ASCII
record within a 1 KiB limit. Trailing whitespace, extra records, missing framing,
stderr and malformed identities block policy acceptance while preserving raw lint.

Late corruption, duplicates, missing attributes, invalid encodings, excessive
streams and incomplete final records remain failures. Inventory failures retain
the causal query receipt separately from raw lint evidence. The bounded inventory
diagnostic records query identities, exit status, byte lengths, stream hashes and
record counts without member paths or raw lines. Dependency-coverage diagnostics
sample at most 32 records per list and retain complete counts and list hashes;
the actual coverage decision still uses every record.
Rejected inode member paths retain the attribute-query receipt and reason.
Runner execution failures retain their original error code and any supplied
stream hashes; a missing query receipt is never replaced by the preceding lint
receipt. Stderr query failures report the stderr byte count.

The [CONT11R1 verification record](../evidence/live1/cont11r1-rpm-inventory-stream-verification.json)
dispositions the bound proposal and advisory findings separately from the original
scope. The cumulative manifest covers the full delta against the public parent,
including the 18 CONT11 terminal amendments. Dispatcher cumulative pre-final
review returned advisory findings. Terminal closeout amended the identity and
causal-diagnostic findings, with exact path hashes disclosed in the manager
packet. These terminal amendments have not received another independent review
and require manager disposition. The existing inventory-failure build-gate
classification is retained; native dump-format qualification remains pending.

The attended run-10 contract above remains prepared and unexecuted. Manager
attestation binds the exact reviewed parent, tree and manifest digest externally,
with every readiness and publication flag false in reviewed source. The caller
creates the existing empty physical packet directory; logs and attestation stay
outside it. Adoption performs one fast-forward push and collects one new
push-triggered run. Collect-only continuation retains the original timestamp,
commit and run; no adoption replay or automatic rerun is authorized. Native RPM
signing/DNF and full LIVE1 qualification remain pending.
