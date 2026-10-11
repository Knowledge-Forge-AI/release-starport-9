# CONT16: hosted evidence consumers and Pages transport diagnostics

## Status and scope

Run 14 remains **NOT QUALIFIED / HOSTED_GATES**. Its successful native-package
and assembled-Pages receipts are retained. CONT16 repairs source consumers and
transport diagnostics; it does not rebuild those packages, repeat adoption, or
authorize publication. All source readiness, production and publication flags
remain false. The required Linux Nix namespace gates, Darwin wheel offline
isolation and Linux wheel production compatibility remain open obligations.

The manager packet was read directly. Its verifier confirmed 170 selection
records, 18 artifact manifests, 146 included manifest-selected objects and 16
canonical receipt hashes. Both uploaded diagnostic ZIPs represent the same run.
Large package bytes were omitted from the kit and were not independently
reverified locally. Historical native results are not fresh local execution.
The kit's standalone TLS replay requires an unavailable optional cryptography
module; no dependency was installed. Current regression tests exercise genuine
local TLS failures using the available OpenSSL tool and MemoryBIO.

## Bound proposal disposition

**Disposition: amend.** Original task scope, proposal bytes and review findings
remain separate. The proposal is `agent-phase-plan-material-v1`, 15,283 bytes,
SHA-256 `f2a23a730155e99c7ee1d27b2f1b6d1f915a8e7986c90c14e72cd1d3f6272e17`.
No stage deltas were recorded at entry. Live entry checks found `main`, an
unchanged index and no divergence from the remote tracking branch. Historical
Git identities are evidence, rather than an additional producer hash gate.
The existing dispatcher owns the two independent review checkpoints; internal
worker evidence supplies no independent checkpoint.

| Plan-review finding | Amendment |
| --- | --- |
| Pages bundle basenames would become fixture copies | Use unsigned bundle provenance for binary architecture checks. |
| Architecture helper alias sets differ | Preserve and test each helper's existing accepted and rejected names. |
| Promotion omission and malformed policy were underspecified | Retain conservative restrictions and separately record causal policy errors. |
| RPM evidence has a separate path selector | Apply the shared role contract to that consumer as well. |
| Operator placement changes builder identity; schema rename risks compatibility | Keep shared operator code under `operators/live1` and retain per-run metadata schemas. |
| Origin diagnostic needs bounded standard HTTP handling | Use the standard HTTP client, verified TLS and bounded stage diagnostics. |
| RPM type parsing could read a large payload | Read bounded lead/signature/main headers for role verification. |
| Producer source location must be exact | Pin the retained `lane-work/unsigned-source` producer location. |
| Evidence was only read through a worker | Read original manifests, receipts, excerpts and controlled replays directly; run the packet hash verifier. |

## Consumer contracts

Source RPMs remain hash-bound reproducibility evidence. Binary packages, source
evidence and fixture-signed copies have distinct roles. Source and fixture-only
inputs cannot satisfy the four-product binary presence or platform architecture
requirements. Actual RPM type must agree with producer role; a declaration
cannot authorize a wrong-architecture binary. Historical role inference is a
diagnostic compatibility path and never upgrades historical publication authority.
Pages retains its public inventory and whole-file noarch equality requirement.

The RPM header source marker and lead determine package type. Source `ARCH`
metadata is not used as an installable platform: historical RPM versions can
record the build architecture in that field, as the
[upstream source-architecture discussion](https://github.com/rpm-software-management/rpm/issues/2601)
records. Header types follow the [RPM tag contract](https://rpm.org/docs/4.20.x/manual/tags.html).
Every source object must match exactly one current reproducibility declaration
by name, size and hash; malformed, orphaned and missing source bindings fail.

Summary validations retain independently valid promotion restrictions when
another check fails and record each causal validation error. Raw rpmlint remains
failed, exit 64; accepted preservation policies remain separate from raw-clean
or official Fedora admission claims.

Native package formats map explicitly to canonical publication adapters:
Debian to APT, RPM to DNF, and pacman to pacman. Destination identity, revision
schemes and mandatory repository gates remain in force. Foundation3 uses fresh
in-process qualification and records disabled or blocked plans. It preserves
completed records and a bounded product/adapter/substage cause on later failure.
Hosted success strings provide no in-process or publication authority.
Normalized intent targets supply the existing configured destination IDs and
semantic target identity. Canonical adapter normalization does not invent or
rename those configured destinations.

## Pages transport boundary

TLS classification inspects native SSL types before unwrapping actual transport
wrappers. Diagnostic output uses bounded classes and numeric verification codes,
without arbitrary exception text or local trust-store paths. The local
self-signed reproduction proves a classifier defect and does not establish the
live certificate's cause.

The fixed-origin diagnostic targets `rs9.knowledge-forge.ai` with ordinary
certificate and hostname verification. DNS, TCP, TLS, HTTP, redirect and object
comparison remain distinct. Failed access remains unknown; it does not establish
absence. Diagnostic results never become observation or publication authority.
There is no weaker TLS retry, alternate origin, deployment or settings mutation.
DNS uses a bounded, killed-and-reaped resolver child; TCP, TLS and HTTP use
bounded timeouts, and object bodies have both size and deadline bounds. The
diagnostic is a separate single request from the existing Pages observation.
GitHub Pages settings metadata was not requested in this phase; no repository
settings or configured-domain state is inferred from unavailable access.

## Verification and handoff

The [verification record](../evidence/live1/cont16-verification.json) records
producer-stage and terminal integration and static checks, including separate
method and class skips. The original dispatcher pre-final work review returned
`reviewed_with_findings` with advisory observations; it ran no tests and did not
independently recompute identity. Closeout amends those reviewed bytes and records
the terminal verification separately. No additional substantive review is obtained.
Before that review, both process-local umasks, 022 and 077, passed the full unittest suite with
ResourceWarnings treated as errors: 1,750 passed, 20 individual skips and one
class skip covering 10 methods, with no ResourceWarnings. The complete sixteen
product/adapter paths use current package-bound RPM raw evidence, typed policy
references and fresh in-process verification; all plans remain disabled.
All 267 candidate Python files parse and compile without writing bytecode.

Terminal amendments patch the fixed-origin diagnostic in observation unit-test
setup, retain unknown-role objects with a bounded failing receipt, and preserve
the unsigned candidate role of quarantine copies. Fixture copies now undergo
lane architecture checks while remaining insufficient for candidate presence.
Tests replay both exact run-14 custody path sets with typed synthetic bytes and
compare roles and historical promotions; this does not reverify omitted package
bytes. TLS diagnostics use general failure wording for handshake/protocol/EOF
classes. The run-15 operator retains mode 100644 and its documented `python3`
invocation. Terminal suite results and every finding disposition are recorded
in the verification record; original producer results remain distinguishable.
Both terminal full-suite passes, under umasks 022 and 077, report 1,754 passed,
20 individual skips and one class skip covering 10 methods, with no
ResourceWarnings. The workflow/operator checks report 29 passed. Final source
inventory, parse/compile, privacy, relative-link and whitespace checks qualify
the terminal source bytes; full hosted qualification and run-15 acceptance remain
pending externally.

Exact candidate tree and manifest hash are returned separately to avoid circular
hash bindings inside the inventory itself.

After manager acceptance, use the [run-15 operator](../operators/live1/run-hosted15.py)
and [shared attended contract](../operators/live1/attended_run.py). The
[candidate manifest](../operators/live1/candidate-manifest.json) binds exact
reviewed changed paths. An external manager attestation must bind its unchanged
tree and manifest hash with partial-diagnostic scope and false qualification,
production and publication flags. No post-review readiness edits are needed.

The attended procedure creates a fresh empty physical packet directory outside
the repository before invocation. Logs, metadata, wrapper output and the small
result ZIP stay beside that directory. For example, after acceptance:

```sh
RS9_EMPTY_PACKET_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/RS9-CONT16-HOSTED15.XXXXXX")
RS9_WRAPPER_OUTPUT="${RS9_EMPTY_PACKET_DIRECTORY}.wrapper.log"
rtk proxy env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 operators/live1/run-hosted15.py \
  --reviewed-parent "$RS9_ACCEPTED_PARENT" \
  --reviewed-tree "$RS9_ACCEPTED_TREE" \
  --manifest-sha256 "$RS9_ACCEPTED_MANIFEST_SHA256" \
  --manager-attestation "$RS9_MANAGER_ATTESTATION" \
  --manager-attestation-sha256 "$RS9_MANAGER_ATTESTATION_SHA256" \
  --output "$RS9_EMPTY_PACKET_DIRECTORY" > "$RS9_WRAPPER_OUTPUT" 2>&1
```

The backend adopts only reviewed paths, makes one normal commit and fast-forward
push, binds the single fresh push workflow to that commit, retains jobs,
artifacts and diagnostics, and stops. Collection continuation requires its exact
commit/run and original timestamp in another existing empty packet directory;
it does not rerun the workflow. This dispatch performs none of these actions.
