# Optional public ZIP relay and distribution input verifier

Status: PREPARE ONLY. No relay release or asset exists as a result of this work.
Nothing was published, activated, signed, installed, deployed, or submitted to CI.
The prior qualifier revision and its seal remain preserved.

## Scope and original authority

This revision adds an optional ZIP transport and a read-only verifier facade.
The default `actions` ZIP transport and historical workflow selection remain
unchanged. `public-release-relay` is accepted only with
`theme-forge-current-202610`; unknown modes fail closed.

The relay supplies bytes only. Live ORIGINAL RS9 Actions run, job, step and
artifact metadata remain authoritative. The collector retains its existing
metadata GET path and all source, tree, workflow, run, attempt, event, ref,
artifact, receipt, gate, custody and adoption checks. The original ZIP digest
must come from fresh original Actions artifact metadata. A saved packet, relay
release name, relay-only checksum, successful workflow conclusion, or matching
extracted files cannot replace those checks.

## Reserved relay naming and exact set

The only relay repository is the public
`Knowledge-Forge-AI/theme-forge-packages` repository. Naming is closed:

- Tag: `rs9-current-distribution-<40hex-source-commit>-run-<original-run-id>-attempt-1`.
- Asset: `rs9-artifact-<original-artifact-id>-<original-artifact-name>.zip`.

A later, separately authorized operator would upload the ORIGINAL downloaded
ZIP bytes unchanged. This revision contains no uploader or release creator.
No rezipping or recompression is permitted: the ZIP stream must hash to the
ORIGINAL live Actions `sha256:` digest. Even a ZIP with identical extracted files
is refused if its original bytes differ.

The relay release must be public, non-draft and non-prerelease. Its asset names
and identities must form exactly the selected original artifact set. Extra
assets, duplicate assets, missing assets, mismatched names, expired original
artifacts, missing original digests, missing or mismatched relay digests, and
noncanonical download URLs are refused. Reserved tags cannot contain unrelated
assets such as supplemental README or checksum files.

## Anonymous bounded transfer

Relay release metadata uses a fixed anonymous GitHub API GET with redirects
disabled and a 1 MiB response limit. Asset URLs are constructed from the fixed
repository and naming rules. Requests send only the fixed User-Agent and Accept
headers, without Authorization, cookies, proxy inheritance or ambient tokens.
The production transport is explicit and typed; it never uses the collector's
fixture `runner` seam as a binary-download fallback.

ZIP transfer uses an exclusive physical output file and 64 KiB chunks, with
2 GiB per-artifact and 8 GiB cumulative limits, a 120-second transfer deadline,
a 20-second socket timeout, and at most three redirects. Redirects permit only
HTTPS on GitHub and its existing release CDN hosts. GitHub paths remain bound
to the fixed release asset. Initial URLs have no query; transient CDN query keys
are limited to the source-owned signed-download key set. Downgrades, userinfo,
fragments, arbitrary hosts, arbitrary query keys and changed release paths fail.
Rejected transfers close responses and remove only their newly created ZIP.

Signed redirect URLs remain transient and are never stored in collection
packets, manifests or transport receipts. The existing safe ZIP extraction,
expanded-byte limits, physical object checks and custody validation remain in
place after the original ZIP digest is verified.

## Strict verifier API

`qualified_distribution_inputs(SourceBoundConfiguration(...), output,
zip_transport="actions")` accepts a closed configuration containing the source
repository Path, exact source commit/tree, original run ID, timezone-aware push
boundary, workflow/contract/builder/configuration hashes and release-ingestion
hash. Generation, scope, repository authority, workflow path, push/main/attempt-1
admission and the selected required lanes are fixed by source. The existing
collector's empty physical manager-outbox output boundary remains applicable.

The facade recomputes local source provenance and performs a fresh collection.
It accepts no saved manager packet as input. The computed packet must have
validation pass with no reasons, the exact current-distribution classification,
current-distribution qualification true, and historical full qualification and
published readiness false. It then calls the original summary validator again,
requiring qualified/adoptable/no blockers and exact caller-bound provenance.
The physical bounded summary must remain unchanged through revalidation.

Actual summary `production_promotion_blockers` must be empty and
`production_promotion_blocked` false. Every physical lane receipt is joined back
to the validated summary and manifest, and `promotion_restrictions` is recomputed
for every selected lane. Any token or error prohibits import. There is no blanket
exemption for preserved RPM lint findings, accepted findings, or policy labels.
The current RPM policy source check is repeated; the missing or diagnostic-only
blocked current policy still rejects real admission. Any later policy admission
is a separate owner decision.

Existing byte-role verification checks physical custody, including RPM lead and
typed header roles and source reproducibility bindings. Only explicit installable
`binary-package` rows from the deb/rpm/pacman producer lanes enter the returned
input list. Source RPMs and fixture-signed copies remain evidence and are excluded.
Unknown products, stale version filenames, missing required products, wrong
architectures, and conflicting complete noarch/all bytes are refused. Existing
architecture and cross-lane byte-consistency helpers are reused. Identical
architecture-independent inputs retain all source origins while deduplicating
by exact identity.

The result contains relative custody origins and validated Nix output metadata.
It grants no signing, production, publication, deployment or attended authority:
`production_enabled`, `publication_authority`, `attended_gates_satisfied`,
`signing_authority`, `full_live1_qualification` and `published_linux_nix_ready`
remain false. These boundaries are preserved, not relabeled into permission.
No public packages-repository Nix qualification derives from this verifier.

## Verification and held integration

145 focused Python tests passed, including 20 new transport/verifier tests and
the retained qualifier, collector, summary, role, capture and command regressions.
Tests use standard-library mocked GETs and synthetic ZIP/RPM/archive fixtures.
Real RPM role checks reject source bytes disguised as binaries and mismatched
headers. Tests also reject recompression, digest/set changes, transfer bounds,
unsafe redirects, forged green packet flags, promotion restrictions, and real
current RPM-policy holds. An isolated result-constructor fixture checks false
authority flags; it is not an end-to-end qualification claim.

A source AST comparison confirms that collector metadata and validation/adoption
logic are unchanged after accounting for the explicit ZIP seam and CLI option.
Both existing workflow files and the selected contract remain byte-identical to
the prior qualifier revision. No new dependency, test runner, installer, signing
service or deployment capability is introduced.

No live relay integration or positive real input admission is claimed. Held:
operator approval and creation of an exact original-byte relay; availability of
fresh unexpired original metadata; real source-bound Git/hosted identities;
current caller/smoke/RPM integration; current RPM policy admission; and public
native qualification. The relay CDN query contract and first real transfer must
be checked during a separately authorized read-only integration. The original
metadata reader has not been replaced by a new anonymous fallback in this slice.
