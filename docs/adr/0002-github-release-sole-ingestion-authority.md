# ADR 0002: GitHub Release ingestion authority

Status: architecture decision; authentication and publication not implemented.

## Context

Current Theme Forge distro inputs combine GitHub native release archives and npm
tarballs. A release lock records digests, but that alone does not authenticate
the publisher or release lineage. RS9 needs one ingestion authority while
preserving tenant artifact bytes and each registry's publisher identity rules.

## Decision

RS9 ingestion begins with an explicitly selected public GitHub Release tag in
the declared repository. Resolve the tag to its commit and record release and
asset identities, raw digests, sizes and any authenticated checksum/attestation
evidence. Drafts fail; prereleases follow explicit tenant policy. A Latest label
is not release authority. A digest alone authenticates content consistency, not
the right publisher or release lineage.

npm/PyPI are downstream destinations. The three npm-sourced Theme Forge distro
inputs must be attached to an authoritative GitHub Release and independently
authenticated. Fresh API reads found current Burst/Loom/Sail tarballs and
lock-matching reported digests; downloaded-byte and release-lineage verification
remain future ingestion gates. The lock filename is a cache name, distinct from
the observed GitHub asset name. The normalizer performs no remote assertion.

Tenant license files are fetched from the declared repository at the resolved
tag commit, hashed and bound to the ingestion record. The eventual packager must
also reconcile payload notices/licenses. Missing or conflicting authority blocks
publication. This validator checks paths only; it does not claim those files
exist or cover the payload.

## npm provenance finding

npm requires the package's public `repository` metadata to match the repository
used for provenance. Trusted publishing automatically creates provenance for
eligible packages. Thus an RS9-hosted publishing workflow cannot assume it can
publish an unchanged tarball naming the tenant repository. These are ecosystem
constraints, separate from RS9's desired control-plane ownership. See
[npm provenance prerequisites](https://docs.npmjs.com/generating-provenance-statements/)
and [trusted publishers](https://docs.npmjs.com/trusted-publishers/).

No approach is chosen for production in this phase. Prefer qualifying a
tenant-side caller of pinned RS9 reusable machinery while keeping artifact bytes
unchanged. Verify the exact caller/reusable-workflow OIDC claims, registry
authorization and attestation identity in a bounded registry qualification;
do not infer them from workflow location. Alternative token/no-provenance
operation needs an explicit operator security decision. Rewriting repository
metadata creates a new artifact and requires an explicit transformation contract,
new digest/provenance and tenant approval; it is outside this phase.

PyPI identity must be independently checked against its own trusted-publisher
policy. Its current [troubleshooting documentation](https://docs.pypi.org/trusted-publishers/troubleshooting/)
states that reusable workflows cannot be registered as the trusted-publisher
workflow. Do not assume registering RS9 reusable code will work; qualify a
tenant-owned publishing job and the supported identity route separately.
npm behavior is not evidence of PyPI behavior. No registry tokens,
trusted publishers or production environments are configured here.

## Consequences

Keep current npm machinery operational. Future exact-match registry readback
must compare registry tarball bytes with the authoritative asset, and reject
same-version mismatch or incomplete state. A qualified identity route is a hard
precondition, not a promise that adding `--provenance` will work.
