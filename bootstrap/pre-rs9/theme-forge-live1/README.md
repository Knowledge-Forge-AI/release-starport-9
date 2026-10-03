# One-time Theme Forge LIVE1 bootstrap

Status: candidate configuration; release bytes and downstream gates pending.

This RS9-owned manifest applies only to Burst 0.6.1, Loom 0.4.0, Sail 0.2.1 and
Nebular 0.6.1. Their tagged trees predate `.rs9/`. No upstream release, tag or
repository is changed by this exception. Future releases require normal
project-owned, release-bound `.rs9/` configuration or another reviewed exception.

`manifest.json` binds each repository/tag/release/commit/tree/version and the
canonical configuration inventory hash. The per-project `intent.json` and
`channels.json` are the single LIVE1 authority; the Nebular files under `examples/`
remain illustrative and are not combined with these configurations.

Expected release asset hashes are in the attended operator's expectation record.
Authenticated derived hashes belong in ingestion evidence, not ordinary tenant
config. The [bootstrap specification](../../../docs/specs/rs9-bootstrap-tenant-v1alpha1.md)
defines hash computation and refusal rules. Exact file hashes appear in the
[candidate inventory](../../../operators/live1/candidate-manifest.json).
